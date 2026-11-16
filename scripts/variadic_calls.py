#!/usr/bin/env python3
"""
Call sites of the variadic API in the target's own programs (tests, examples), for the API harness.

A variadic function (`bool scan(const char *sentence, const char *format, ...)`) has no signature
for the arguments after the fixed ones, so scripts/api_harness.py cannot build a call from the model
alone, and the recorder of seed_harvest.py cannot wrap it. The target's own callers show how it is
meant to be called: with which format, and with objects of which types and sizes behind it. This
script reads them from the source, without running anything:

    variadic_calls.py run [--out workspace/reports/variadic_calls.json]        (analysis image)

  1. the functions: the model's API entry points (workspace/reports/phase0_model.json) that are
     variadic (`seed_harvest.is_variadic`: a signature ending in `...`, or a last formal named
     `__va_params`), not `static`;
  2. the sources: every source the build compiled (workspace/reports/build_capture.json) that
     belongs to no library unit, that is, the sources of the executables (tests, examples, tools),
     read from the work tree (workspace/work) when their text names one of the functions. Each is
     parsed with `clang -fsyntax-only -Xclang -ast-dump=json` and the preprocessing flags of its
     own compile, plus the run snapshot's include options (scripts/target_env.py), so the headers
     of the test framework are found. clang writes the AST to a temporary file in the workspace;
     an AST above MAX_AST_BYTES is refused unread, and the harvest stops starting clang once its
     total budget (HARVEST_BUDGET_S) is spent, counting the sources it left out;
  3. the call sites: every `CallExpr` of one of the functions. The rule that names the format: it
     is the LAST FIXED PARAMETER, and it must be declared `const char *`; a function whose
     prototype does not fit is skipped with the reason. A call site is kept only when
       - the format argument is a string literal, and
       - every argument after it is the address of a variable or of a member (`&x`, `&s.f`: an
         object of the type declared there) or an array passed by name (`char value[80]` -> an
         object of type `char[80]`), of a type that can be written again without a pointer in it.
     Anything else (a pointer variable, a value, a cast, the address of one array element, an
     unnamed type, a variable-length array, a node clang could not type) makes the call site
     unusable, with the reason: the size of the object behind the argument is not known, and a
     harness that guessed it would report overflows the target does not have;
  4. per usable call site: the format, the type of each object and how it is passed (`addr` or
     `array`), and the string literals among the other fixed arguments (the data a seed can start
     from).

The report groups the call sites by (function, format, objects): one `case` each, with the literal
data of its sites. api_harness.py turns each case into a dispatch case (kind `variadic`) and
seed_harvest.py write turns the literal data into seeds for it. `api_harness.generate` runs the
harvest itself when the report is missing or was made from another model (`ensure`), so a harness
generation never works from stale call sites; run it by hand to look at the report first.

No call site is a status, never a failure: the function then stays in the sidecar's `api_skipped`.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from framac_common import VA_PARAMS, atomic_write_json, load_json_optional, utc_now  # noqa: E402
from seed_harvest import _QUALIFIERS_RE, CAPTURE_JSON, MODEL_JSON, is_variadic, split_signature  # noqa: E402

SCHEMA_VERSION = 1
REPORT_JSON = Path("workspace/reports/variadic_calls.json")
WORK_DIR = Path("workspace/work")

CLANG_TIMEOUT_S = 300  # one source
# The whole harvest. It runs inside harness generation (`api_harness.generate` -> `ensure`), so it
# must not hold Phase 0 up: 64 sources at 300 s each is over 5 hours. 900 s is three times the limit
# of one source and far more than a test suite of ordinary size needs (minmea run-1: one source, a few
# seconds); the sources it leaves out are counted in `sources.over_budget`, never a failure.
HARVEST_BUDGET_S = 900
# clang's JSON AST of one source, refused above this size without being read. The dump repeats the
# whole of every header the source includes (a few tens of MB for a test file that includes the C
# library's headers: an estimate, not measured on this host), and `json.load` builds a Python tree
# several times the size of its text, so 128 MiB keeps the peak around 1 GB in the analysis image.
# The size is checked once clang has finished (stdout goes to a file, not a pipe): stopping clang
# while it writes would need a Popen loop in place of the injectable `runner`, and the file is on the
# run's disk, not in memory.
MAX_AST_BYTES = 128 * 1024 * 1024
MAX_SOURCES = 64  # sources parsed (each names a variadic API function)
MAX_CASES_PER_FUNCTION = 256  # distinct (format, objects) kept per function
MAX_DATA_PER_CASE = 64  # distinct literal data kept per case
MAX_LITERAL_BYTES = 65536  # one string literal
MAX_SKIPPED_PER_FUNCTION = 100  # unusable call sites listed per function (all are counted)
MAX_CALLERS_PER_CASE = 8

_SIMPLE_ESCAPES = {
    "n": 10,
    "t": 9,
    "r": 13,
    "a": 7,
    "b": 8,
    "f": 12,
    "v": 11,
    "\\": 92,
    '"': 34,
    "'": 39,
    "?": 63,
}
_BASE_TYPE_RE = re.compile(r"^[A-Za-z_]\w*(?: [A-Za-z_]\w*)*$")
_ARRAY_TYPE_RE = re.compile(r"^(?P<elem>[^\[\]]+?)\s*(?P<dims>(?:\[\d+\])+)$")
_TRANSPARENT_CASTS = {"NoOp"}
_VARIABLE_DECLS = {"VarDecl", "ParmVarDecl"}


# ---------------------------------------------------------------------------------------------------
# 1. Reading clang's AST
# ---------------------------------------------------------------------------------------------------


def decode_literal(value: Any) -> bytes | None:
    """
    The bytes of a narrow string literal as clang's JSON AST spells it (`"\\"a\\\\n\\""`: the source
    form, quotes included), without the terminating NUL. None for a wide or UTF literal, or a
    spelling this does not understand.
    """
    if not isinstance(value, str) or len(value) < 2 or value[0] != '"' or value[-1] != '"':
        return None
    body = value[1:-1]
    out = bytearray()
    i = 0
    while i < len(body):
        ch = body[i]
        if ch != "\\":
            try:
                out += ch.encode("latin-1")
            except UnicodeEncodeError:
                out += ch.encode("utf-8")
            i += 1
            continue
        i += 1
        if i >= len(body):
            return None
        esc = body[i]
        if esc in _SIMPLE_ESCAPES:
            out.append(_SIMPLE_ESCAPES[esc])
            i += 1
        elif esc in "01234567":
            j = i
            while j < len(body) and j < i + 3 and body[j] in "01234567":
                j += 1
            code = int(body[i:j], 8)
            if code > 255:
                return None
            out.append(code)
            i = j
        elif esc == "x":
            j = i + 1
            while j < len(body) and body[j] in "0123456789abcdefABCDEF":
                j += 1
            if j == i + 1 or int(body[i + 1 : j], 16) > 255:
                return None
            out.append(int(body[i + 1 : j], 16))
            i = j
        else:
            return None
        if len(out) > MAX_LITERAL_BYTES:
            return None
    return bytes(out)


def _inner(node: dict) -> list[dict]:
    return [n for n in node.get("inner") or [] if isinstance(n, dict)]


def _unwrap(node: dict, casts: set[str]) -> dict:
    """`node` without the parentheses and the implicit casts of `casts` around it."""
    while True:
        kind = node.get("kind")
        inner = _inner(node)
        if kind == "ParenExpr" and len(inner) == 1:
            node = inner[0]
        elif kind == "ImplicitCastExpr" and node.get("castKind") in casts and len(inner) == 1:
            node = inner[0]
        else:
            return node


def _string_literal(node: dict) -> bytes | None:
    """The bytes of an argument that is a string literal (through the decay and qualification casts)."""
    n = _unwrap(node, {"NoOp", "ArrayToPointerDecay", "BitCast"})
    return decode_literal(n.get("value")) if n.get("kind") == "StringLiteral" else None


def prototype(qual_type: str) -> tuple[list[str], bool] | None:
    """
    (fixed parameter types, variadic) of a function type as clang prints it
    (`bool (const char *, const char *, ...)`); None when it is not a plain function type (one that
    returns a function pointer prints its own parameters in the middle).
    """
    t = " ".join((qual_type or "").split())
    if not t.endswith(")"):
        return None
    depth = 0
    start = -1
    for i in range(len(t) - 1, -1, -1):
        depth += t[i] == ")"
        depth -= t[i] == "("
        if depth == 0:
            start = i
            break
    if start <= 0 or t[start - 1] == ")":
        return None
    params: list[str] = []
    cur, depth = "", 0
    for ch in t[start + 1 : -1]:
        if ch == "," and depth == 0:
            params.append(cur.strip())
            cur = ""
            continue
        depth += ch in "(["
        depth -= ch in ")]"
        cur += ch
    if cur.strip():
        params.append(cur.strip())
    variadic = bool(params) and params[-1] == "..."
    if variadic:
        params = params[:-1]
    if params == ["void"]:
        params = []
    return params, variadic


def is_format_type(t: str) -> bool:
    """Whether a parameter type is `const char *` (qualifiers on the pointer itself do not count)."""
    t = " ".join(t.split())
    if t.count("*") != 1:
        return False
    pointee = t[: t.index("*")]
    if not re.search(r"\bconst\b", pointee):
        return False
    return " ".join(_QUALIFIERS_RE.sub(" ", pointee).split()) == "char"


def object_type(type_node: Any) -> tuple[str | None, str]:
    """
    (the type of an object as the harness can declare it, why not). Typedefs are resolved when clang
    resolved them (a typedef of the test's own file is not visible in the harness); top-level
    qualifiers are dropped (the harness zeroes the object). A type with a pointer in its spelling,
    an unnamed type, a function type, or an array without constant dimensions has no such spelling.
    """
    if not isinstance(type_node, dict):
        return None, "no type"
    why = "no type"
    for key in ("desugaredQualType", "qualType"):
        raw = type_node.get(key)
        if not isinstance(raw, str) or not raw.strip():
            continue
        t = " ".join(_QUALIFIERS_RE.sub(" ", raw).split())
        if "unnamed" in t or "anonymous" in t:
            why = f"an unnamed type ({' '.join(raw.split())})"
            continue
        if "*" in t or "(" in t:
            return None, f"type {t!r} holds a pointer: an object of it cannot be built from the call site alone"
        m = _ARRAY_TYPE_RE.match(t)
        elem = m.group("elem").strip() if m else t
        if ("[" in t and not m) or not _BASE_TYPE_RE.match(elem):
            return None, f"type {t!r} has no constant size the harness can write"
        return (f"{elem}{m.group('dims')}" if m else elem), ""
    return None, why


def _object(node: dict) -> tuple[dict | None, str]:
    """The declared object an lvalue expression names (a variable or a member), else why not."""
    kind = node.get("kind")
    if kind == "DeclRefExpr":
        ref = node.get("referencedDecl")
        if isinstance(ref, dict) and ref.get("kind") in _VARIABLE_DECLS:
            return node, ""
        return None, "not a variable"
    if kind == "MemberExpr":
        return node, ""
    if kind == "ArraySubscriptExpr":
        return None, "one element of an array: the object the callee may write is the array, not the element"
    return None, f"a {kind} expression"


def vararg(node: dict) -> tuple[dict[str, str] | None, str]:
    """
    One argument after the fixed ones: ({type, pass}, why not). `pass` is `addr` (`&object`) or
    `array` (an array object passed by name).
    """
    n = _unwrap(node, _TRANSPARENT_CASTS)
    kind = n.get("kind")
    inner = _inner(n)
    how = ""
    target: dict | None = None
    why = ""
    if kind == "ImplicitCastExpr" and len(inner) == 1:
        cast = n.get("castKind")
        base = _unwrap(inner[0], _TRANSPARENT_CASTS)
        if cast == "ArrayToPointerDecay":
            if base.get("kind") == "StringLiteral":
                return None, "a string literal"
            how = "array"
            target, why = _object(base)
        elif cast == "LValueToRValue":
            t = str((base.get("type") or {}).get("qualType") or "?")
            what = "a pointer variable" if "*" in t else "a value"
            return None, f"{what} of type {t!r}: not the address of a declared object"
        else:
            return None, f"an implicit {cast} conversion"
    elif kind == "UnaryOperator" and n.get("opcode") == "&" and len(inner) == 1:
        how = "addr"
        target, why = _object(_unwrap(inner[0], _TRANSPARENT_CASTS))
    else:
        return None, f"a {kind} expression: not the address of a declared object"
    if target is None:
        return None, why
    ctype, why = object_type(target.get("type"))
    if ctype is None:
        return None, why
    if how == "array" and "[" not in ctype:
        return None, f"type {ctype!r} is not an array"
    return {"type": ctype, "pass": how}, ""


def _callee(call: dict) -> dict | None:
    inner = _inner(call)
    if not inner:
        return None
    n = _unwrap(inner[0], {"FunctionToPointerDecay", "NoOp"})
    ref = n.get("referencedDecl") if n.get("kind") == "DeclRefExpr" else None
    return ref if isinstance(ref, dict) and ref.get("kind") == "FunctionDecl" else None


def call_sites(tree: dict, wanted: dict[str, int]) -> tuple[list[dict], list[dict]]:
    """
    The call sites of the functions `wanted` (name -> number of fixed parameters, per the model) in
    a clang JSON AST: (usable sites, unusable ones with `why`). A usable site:
    {function, caller, format (the literal's bytes, as latin-1 text), format_param, varargs:
    [{type, pass}], data: {fixed parameter index: hex of a string literal passed there}}.
    """
    sites: list[dict] = []
    skipped: list[dict] = []
    stack: list[tuple[dict, str | None]] = [(tree, None)]
    while stack:
        node, fn = stack.pop()
        kind = node.get("kind")
        if kind == "FunctionDecl" and isinstance(node.get("name"), str):
            fn = node["name"]
        if kind == "CallExpr":
            ref = _callee(node)
            name = ref.get("name") if ref else None
            if isinstance(name, str) and name in wanted:
                site, why = _site(node, ref or {}, wanted[name])
                if site is not None:
                    sites.append({"function": name, "caller": fn, **site})
                else:
                    skipped.append({"function": name, "caller": fn, "why": why})
        stack.extend((n, fn) for n in reversed(_inner(node)))
    return sites, skipped


def _site(call: dict, ref: dict, model_fixed: int) -> tuple[dict | None, str]:
    if call.get("containsErrors"):
        return None, "clang could not type the call"
    proto = prototype(str((ref.get("type") or {}).get("qualType") or ""))
    if proto is None or not proto[1]:
        return None, "the function is not declared variadic where it is called"
    fixed, _ = proto
    if len(fixed) != model_fixed:
        return None, f"declared with {len(fixed)} fixed parameters where it is called, {model_fixed} in the model"
    if not fixed or not is_format_type(fixed[-1]):
        return None, "the last fixed parameter is not `const char *`: no format to fix"
    args = _inner(call)[1:]
    if len(args) < len(fixed):
        return None, "fewer arguments than fixed parameters"
    fmt_at = len(fixed) - 1
    fmt = _string_literal(args[fmt_at])
    if fmt is None:
        return None, "the format is not a string literal"
    varargs: list[dict[str, str]] = []
    for j, arg in enumerate(args[len(fixed) :]):
        if arg.get("containsErrors"):
            return None, f"variable argument {j}: clang could not type it"
        got, why = vararg(arg)
        if got is None:
            return None, f"variable argument {j}: {why}"
        varargs.append(got)
    data: dict[str, str] = {}
    for i, arg in enumerate(args[:fmt_at]):
        lit = _string_literal(arg)
        if lit is not None:
            data[str(i)] = lit.split(b"\0", 1)[0].hex()
    return {"format": fmt.decode("latin-1"), "format_param": fmt_at, "varargs": varargs, "data": data}, ""


# ---------------------------------------------------------------------------------------------------
# 2. The functions and the sources
# ---------------------------------------------------------------------------------------------------


def fixed_parameters(signature: str, formals: Any) -> int | None:
    """The number of fixed parameters of a variadic model function (its `__va_params` formal is not one)."""
    parts = split_signature(signature)
    if parts is None:
        return None
    n = len(parts[1])
    if not parts[2] and isinstance(formals, list) and formals:
        last = formals[-1]
        if (last.get("name") if isinstance(last, dict) else last) == VA_PARAMS:
            n -= 1
    return n if n >= 0 else None


def variadic_api(model: dict) -> dict[str, dict[str, Any]]:
    """The variadic API entry points of the model: name -> {key, fixed, file}."""
    functions = model.get("functions") or {}
    embedded: set[str] = {
        e
        for u in (model.get("units") or {}).values()
        if isinstance(u, dict) and not u.get("test")
        for e in u.get("embedded_api") or []
    }
    out: dict[str, dict[str, Any]] = {}
    for fid in sorted({*(model.get("entry_points") or []), *embedded}):
        rec = functions.get(fid)
        if not isinstance(rec, dict) or rec.get("static"):
            continue
        name = str(rec.get("name") or str(fid).split("#")[-1])
        sig = str(rec.get("signature") or "")
        if name == "main" or name in out or not is_variadic(sig, rec.get("formals")):
            continue
        fixed = fixed_parameters(sig, rec.get("formals"))
        if fixed is not None:
            out[name] = {"key": fid, "fixed": fixed, "file": rec.get("file")}
    return out


def caller_sources(capture: dict) -> tuple[list[dict], int]:
    """
    The compiles of the target's own programs: (one compile record per source that belongs to no
    library unit, the number of library sources left out). A source inside the tree only.
    """
    library: set[str] = set()
    for unit in (capture.get("units") or {}).values():
        if isinstance(unit, dict) and unit.get("kind") != "executable":
            library |= {str(f) for f in unit.get("files") or []}
    seen: set[str] = set()
    out: list[dict] = []
    left_out = 0
    for c in capture.get("compiles") or []:
        src = c.get("source") if isinstance(c, dict) else None
        if not isinstance(src, str) or src in seen:
            continue
        seen.add(src)
        if src in library:
            left_out += 1
        elif not src.startswith("/") and ".." not in Path(src).parts:
            out.append(c)
    return sorted(out, key=lambda c: str(c["source"])), left_out


def clang_argv(exe: str, source: Path, compile_rec: dict, work: Path) -> list[str]:
    """The AST dump command of one source: its compile's preprocessing flags, then the snapshot's."""
    import build_capture as bc
    from target_env import with_include_flags

    flags = bc.absolute_flags([str(f) for f in compile_rec.get("flags") or []], work.resolve().as_posix())
    flags += [str(f) for f in compile_rec.get("system_flags") or []]
    cpp = with_include_flags(shlex.join(flags))
    return [exe, "-fsyntax-only", "-w", "-x", "c", *shlex.split(cpp), "-Xclang", "-ast-dump=json", str(source)]


def _mentions(path: Path, names: set[str]) -> bool:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return any(re.search(rf"\b{re.escape(n)}\b", text) for n in names)


# ---------------------------------------------------------------------------------------------------
# 3. The report
# ---------------------------------------------------------------------------------------------------


def group_cases(sites: list[dict]) -> list[dict]:
    """The usable sites of one function as cases: one per (format, objects), in first-seen order."""
    cases: dict[str, dict] = {}
    for s in sites:
        key = json.dumps([s["format"], s["varargs"]], sort_keys=True)
        case = cases.get(key)
        if case is None:
            if len(cases) >= MAX_CASES_PER_FUNCTION:
                continue
            case = cases[key] = {
                "format": s["format"],
                "format_param": s["format_param"],
                "varargs": s["varargs"],
                "sites": 0,
                "callers": [],
                "data": [],
            }
        case["sites"] += 1
        where = f"{s.get('source')}:{s.get('caller') or '?'}"
        if where not in case["callers"] and len(case["callers"]) < MAX_CALLERS_PER_CASE:
            case["callers"].append(where)
        if s.get("data") and s["data"] not in case["data"] and len(case["data"]) < MAX_DATA_PER_CASE:
            case["data"].append(s["data"])
    return list(cases.values())


def read_ast(argv: list[str], timeout: float, runner: Callable[..., Any], tmp_dir: Path | None) -> tuple[Any, Any, str]:
    """
    (clang's JSON AST of one source, the finished process, why there is none). `runner` is called
    like `subprocess.run`, with `stdout` a binary temporary file it must write the AST to; the file
    is removed on every path. An AST above MAX_AST_BYTES is refused without being read. Raises what
    the runner raises (OSError, subprocess.TimeoutExpired) and ValueError for an AST that is no JSON.
    """
    with tempfile.TemporaryFile(prefix=".variadic_ast_", dir=tmp_dir) as ast:
        proc = runner(argv, stdout=ast, stderr=subprocess.PIPE, text=True, timeout=timeout, check=False)
        ast.flush()
        size = os.fstat(ast.fileno()).st_size
        if size > MAX_AST_BYTES:
            why = f"clang's AST is {size} bytes, above the cap of {MAX_AST_BYTES} (MAX_AST_BYTES): not read"
            return None, proc, why
        ast.seek(0)
        return json.load(ast), proc, ""


def harvest(
    model: Any,
    capture: Any,
    work: Path = WORK_DIR,
    clang: str | None = None,
    runner: Callable[..., Any] = subprocess.run,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """
    The report (see the module docstring); `runner` runs clang and `clock` measures the budget
    (tests replace both). clang's AST goes to a temporary file in the parent of `work` (the
    workspace, on the run's disk).
    """
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "status": "error",
        "model_generated_at": model.get("generated_at") if isinstance(model, dict) else None,
        "functions": {},
        "sources": {
            "scanned": [],
            "library": 0,
            "not_calling": 0,
            "missing": [],
            "failed": {},
            "over_cap": 0,
            "over_budget": 0,
        },
        "warnings": [],
    }
    if not isinstance(model, dict) or model.get("status") != "ok":
        report["status"] = "no_model"
        return report
    api = variadic_api(model)
    if not api:
        report["status"] = "no_variadic_api"
        return report
    for name, info in api.items():
        report["functions"][name] = {
            "key": info["key"],
            "fixed": info["fixed"],
            "sites": 0,
            "unusable": 0,
            "cases": [],
            "skipped": [],
        }
    if not isinstance(capture, dict) or capture.get("status") != "ok":
        report["status"] = "no_capture"
        return report
    exe = clang or shutil.which("clang")
    if not exe:
        report["status"] = "no_clang"
        return report
    compiles, report["sources"]["library"] = caller_sources(capture)
    wanted = {name: int(info["fixed"]) for name, info in api.items()}
    usable: dict[str, list[dict]] = {name: [] for name in api}
    unusable: dict[str, int] = {name: 0 for name in api}
    src_info = report["sources"]
    tmp_dir = work.parent if work.parent.is_dir() else None
    deadline = clock() + HARVEST_BUDGET_S
    for c in compiles:
        src = str(c["source"])
        path = work / src
        if not path.is_file():
            src_info["missing"].append(src)
            continue
        if not _mentions(path, set(api)):
            src_info["not_calling"] += 1
            continue
        if len(src_info["scanned"]) + len(src_info["failed"]) >= MAX_SOURCES:
            src_info["over_cap"] += 1
            continue
        left = deadline - clock()
        if left <= 0:
            src_info["over_budget"] += 1
            continue
        limit = min(float(CLANG_TIMEOUT_S), left)
        try:
            argv = clang_argv(exe, path, c, work)
            tree, proc, why = read_ast(argv, limit, runner, tmp_dir)
        except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
            reason = f"{type(exc).__name__}: {str(exc)[:200]}"
            if isinstance(exc, subprocess.TimeoutExpired) and limit < CLANG_TIMEOUT_S:
                reason += f" (cut to the {limit:.0f} s left of the harvest budget, HARVEST_BUDGET_S)"
            src_info["failed"][src] = reason
            continue
        if tree is None:
            src_info["failed"][src] = why
            continue
        if not isinstance(tree, dict):
            src_info["failed"][src] = "clang's AST is not an object"
            continue
        if getattr(proc, "returncode", 0) != 0:
            first = (getattr(proc, "stderr", "") or "").strip().splitlines()[:1]
            report["warnings"].append(
                f"{src}: clang reported errors ({first[0][:200] if first else 'no message'}): "
                "call sites it could not type are unusable"
            )
        src_info["scanned"].append(src)
        sites, skipped = call_sites(tree, wanted)
        del tree
        for s in sites:
            usable[s["function"]].append({**s, "source": src})
        for s in skipped:
            unusable[s["function"]] += 1
            listed = report["functions"][s["function"]]["skipped"]
            if len(listed) < MAX_SKIPPED_PER_FUNCTION:
                listed.append({"source": src, "caller": s.get("caller"), "why": s["why"]})
    if src_info["over_budget"]:
        report["warnings"].append(
            f"{src_info['over_budget']} source(s) naming a variadic function left unparsed: the harvest's "
            f"budget of {HARVEST_BUDGET_S} s (HARVEST_BUDGET_S) was spent; the cases come from the others"
        )
    for name in api:
        entry = report["functions"][name]
        entry["sites"] = len(usable[name]) + unusable[name]
        entry["unusable"] = unusable[name]
        entry["cases"] = group_cases(usable[name])
    report["status"] = "ok"
    return report


def run(out: Path = REPORT_JSON, model_path: Path = MODEL_JSON, capture_path: Path = CAPTURE_JSON) -> dict[str, Any]:
    """Harvest and write the report; a failure is recorded in it, never raised."""
    model = load_json_optional(model_path, None)
    try:
        report = harvest(model, load_json_optional(capture_path, None))
    except Exception as exc:  # noqa: BLE001 - recorded as a status: call sites never stop the pipeline
        report = {
            "schema_version": SCHEMA_VERSION,
            "generated_at": utc_now(),
            "status": "error",
            "model_generated_at": model.get("generated_at") if isinstance(model, dict) else None,
            "error": f"{type(exc).__name__}: {exc}",
            "functions": {},
            "warnings": [],
        }
    from validate_artifacts import schema_warning

    problem = schema_warning("variadic_calls", report)
    if problem:
        report["warnings"] = [*(report.get("warnings") or []), problem]
    out.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(out, report)
    return report


def load_cases(path: Path = REPORT_JSON) -> dict[str, list[dict]]:
    """Function name -> its harvested cases, from the report ({} without one)."""
    report = load_json_optional(path, None)
    functions = report.get("functions") if isinstance(report, dict) else None
    out: dict[str, list[dict]] = {}
    for name, entry in (functions or {}).items() if isinstance(functions, dict) else []:
        cases = entry.get("cases") if isinstance(entry, dict) else None
        if isinstance(cases, list):
            out[str(name)] = [c for c in cases if isinstance(c, dict)]
    return out


def ensure(
    path: Path = REPORT_JSON, model_path: Path = MODEL_JSON, capture_path: Path = CAPTURE_JSON
) -> dict[str, list[dict]]:
    """
    The harvested cases, harvesting first when the report is missing, did not complete, or was made
    from another model than the one on disk. Never raises: without call sites the variadic
    functions stay skipped.
    """
    try:
        report = load_json_optional(path, None)
        model = load_json_optional(model_path, None)
        stamp = model.get("generated_at") if isinstance(model, dict) else None
        fresh = (
            isinstance(report, dict)
            and report.get("status") in ("ok", "no_variadic_api")
            and report.get("model_generated_at") == stamp
        )
        if not fresh:
            run(path, model_path, capture_path)
        return load_cases(path)
    except Exception as exc:  # noqa: BLE001 - call sites are an improvement, never a requirement
        print(f"variadic_calls: no call sites ({type(exc).__name__}: {exc})", file=sys.stderr)
        return {}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Call sites of the variadic API in the target's own programs.")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="Harvest the call sites and write the report")
    r.add_argument("--out", type=Path, default=REPORT_JSON)
    a = p.parse_args(argv)
    report = run(a.out)
    summary = {
        "status": report.get("status"),
        "error": report.get("error"),
        "scanned": (report.get("sources") or {}).get("scanned"),
        "functions": {
            name: {"sites": e.get("sites"), "unusable": e.get("unusable"), "cases": len(e.get("cases") or [])}
            for name, e in (report.get("functions") or {}).items()
        },
    }
    print(json.dumps(summary, indent=1))
    return 1 if report.get("status") == "error" else 0


if __name__ == "__main__":
    sys.exit(main())
