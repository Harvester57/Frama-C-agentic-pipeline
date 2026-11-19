"""
The macro context a target compiles in, read from `gcc -E -dD` of one of its own compiles.

Two readers share it:

- scripts/stub_check.py: the macros the target defines before it includes a library header
  (`scan_preprocessed`, `select_context`), so each probe sees the header as the target does (pcre2.h and
  PCRE2_CODE_UNIT_WIDTH on nginx run-3);
- scripts/generate_harness.py, and stub_check.py again: the target's feature-test and configuration macros
  (`scan_feature_macros`, `select_feature_macros`, `feature_macros_of`), those its command line and its
  own files define before the compile first enters a system header and that a system header tests in a
  conditional. glibc's <features.h> reads `_GNU_SOURCE` and `_FILE_OFFSET_BITS` once, at the first system
  header; a harness that includes <stdint.h> before the target's config header (nginx defines
  `_GNU_SOURCE` in src/os/unix/ngx_linux_config.h), or a compile that force-includes fc_compat_types.h
  (the E-ACSL frontend, Eva), enters it first, and `struct in6_pktinfo` stays undeclared. They are
  given as `-D` flags (`macro_flag`): on the command line they precede every system header, whatever
  is force-included. Include guards and macros no system header tests are never carried.

The compile is preprocessed with its own flags in the target's tree (`preprocess_command`), with the
run snapshot's system and generated include directories, so the scan sees what the build saw.
"""

from __future__ import annotations

import json
import re
import shlex
import shutil
import subprocess
from collections.abc import Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from pathlib import Path
from typing import Any

import target_env

# `gcc -E -dD` of one compile: its timeout, and how many compiles one derivation preprocesses at most.
PREPROCESS_TIMEOUT_S = 120
MAX_FEATURE_COMPILES = 256
# A `differing` record names at most this many sources; `(undefined)` stands for a compile without the macro.
MAX_LISTED = 20
UNDEFINED = "(undefined)"
_LINEMARKER_RE = re.compile(r'^#\s+\d+\s+"((?:[^"\\]|\\.)*)"((?:\s+\d+)*)\s*$')
_DEFINE_LINE_RE = re.compile(r"^#define\s+([A-Za-z_]\w*)")
_UNDEF_LINE_RE = re.compile(r"^#undef\s+([A-Za-z_]\w*)")
_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
_C_COMMENT_RE = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)
_DIRECTIVE_RE = re.compile(r"^\s*#\s*([a-z]+)\b(.*)$", re.MULTILINE)
_GUARD_TEST_RE = re.compile(r"^\s*(?:!\s*defined\s*\(?\s*)?([A-Za-z_]\w*)\s*\)?\s*$")
# The directives that test a macro (`defined X`, `X == 64`, `#ifdef X`).
_CONDITIONALS = frozenset({"if", "ifdef", "ifndef", "elif", "elifdef", "elifndef"})
# A `-D` value later stages cannot carry: they split and re-join flag strings (generate_harness.py's DAG
# flags) and e-acsl-gcc splits its flag values on spaces (eacsl_toolchain.normalize_passthrough).
_UNSAFE_VALUE_RE = re.compile(r"[\s\"'\\]")
_PSEUDO_FILES = frozenset({"", "<built-in>", "<command-line>"})


def under(path: str, root: str | None) -> bool:
    """Whether `path` is `root` or below it (`/`-separated strings)."""
    if not root:
        return False
    root = root.rstrip("/")
    return path == root or path.startswith(root + "/")


def _unescape_marker(path: str) -> str:
    return re.sub(r"\\(.)", r"\1", path)


def is_abs_path(path: str) -> bool:
    """An absolute path as gcc prints it: POSIX, or a Windows drive path (host tests)."""
    return path.startswith("/") or bool(re.match(r"^[A-Za-z]:[/\\]", path))


def _read(path: str, cwd: Path | None = None) -> str | None:
    p = Path(path) if cwd is None or is_abs_path(path) else cwd / path
    try:
        return _C_COMMENT_RE.sub(" ", p.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return None


# ---------------------------------------------------------------------------
# The macros the target defines before it includes one header (stub_check.py's include context)
# ---------------------------------------------------------------------------


def scan_preprocessed(text: str, include: str, tree: str, generated: str | None) -> dict:
    """
    Walk the `gcc -E -dD` output of one compile until it leaves the first file it enters whose path ends
    in `/<include>` outside `tree`. {entered: that path or None, defines: {name: `#define` line} the
    target's command line and its own files (not system headers, except the build's generated headers
    under `generated`) left defined before entering it, closure: the files entered while it was open,
    itself first}. A later redefinition by a system header or an `#undef` removes a name.
    """
    suffix = "/" + include.strip("/")
    stack: list[tuple[str, bool]] = []
    defines: dict[str, str] = {}
    entered: str | None = None
    depth = 0
    closure: list[str] = []
    for line in text.splitlines():
        if not line.startswith("#"):
            continue
        m = _LINEMARKER_RE.match(line)
        if m:
            path = _unescape_marker(m.group(1))
            flags = m.group(2).split()
            system = "3" in flags
            if "1" in flags:
                stack.append((path, system))
                if entered is None and path.endswith(suffix) and not under(path, tree):
                    entered, depth = path, len(stack)
                    closure.append(path)
                elif entered is not None and path not in closure:
                    closure.append(path)
            elif "2" in flags:
                if stack:
                    stack.pop()
                if entered is not None and len(stack) < depth:
                    break
                if stack:
                    stack[-1] = (path, system)
                else:
                    stack.append((path, system))
            elif stack:
                stack[-1] = (path, system)
            else:
                stack.append((path, system))
            continue
        if entered is not None:
            continue
        cur, system = stack[-1] if stack else ("", False)
        target = cur != "<built-in>" and (not system or under(cur, generated))
        d = _DEFINE_LINE_RE.match(line)
        if d:
            if target:
                defines[d.group(1)] = line.rstrip()
            else:
                defines.pop(d.group(1), None)
            continue
        u = _UNDEF_LINE_RE.match(line)
        if u:
            defines.pop(u.group(1), None)
    return {"entered": entered, "defines": defines, "closure": closure}


def include_guard(text: str) -> str | None:
    """The include guard of a header (comments removed): its first directive tests X, its second defines X."""
    directives = _DIRECTIVE_RE.findall(text)[:2]
    if len(directives) < 2:
        return None
    (kind1, arg1), (kind2, arg2) = directives
    test = arg1.strip() if kind1 == "ifndef" else (arg1 if kind1 == "if" and "!" in arg1 else None)
    m = _GUARD_TEST_RE.match(test or "")
    if m is None or kind2 != "define":
        return None
    defined = arg2.split()
    return m.group(1) if defined and defined[0] == m.group(1) else None


def macro_body(line: str) -> str:
    """The replacement list of a `#define` line, parameters left out."""
    rest = _DEFINE_LINE_RE.sub("", line, count=1)
    if rest.startswith("("):
        rest = rest.split(")", 1)[1] if ")" in rest else ""
    return rest


def _with_bodies(keep: set[str], defines: dict[str, str], guards: set[str]) -> set[str]:
    """`keep` and, transitively, the macros of `defines` a kept macro's body names; never a guard."""
    todo = sorted(keep)
    while todo:
        for ident in _IDENT_RE.findall(macro_body(defines[todo.pop()])):
            if ident in defines and ident not in keep and ident not in guards:
                keep.add(ident)
                todo.append(ident)
    return keep


def select_context(scan: dict, snapshot_root: str | None, cwd: Path | None = None) -> list[str]:
    """
    The `#define` lines of `scan` (scan_preprocessed) the header reads: the macros named in the header
    and in the target-package headers it entered (under the snapshot's `root/`), then, transitively, the
    target's macros a kept macro's body names; never one of their include guards. Sorted by name.
    """
    defines: dict[str, str] = scan.get("defines") or {}
    entered = scan.get("entered")
    if not entered or not defines:
        return []
    files = [entered, *(f for f in (scan.get("closure") or [])[1:] if under(f, snapshot_root))]
    names: set[str] = set()
    guards: set[str] = set()
    for f in files:
        text = _read(f, cwd)
        if text is None:
            continue
        names |= set(_IDENT_RE.findall(text))
        guard = include_guard(text)
        if guard:
            guards.add(guard)
    keep = _with_bodies({n for n in defines if n in names and n not in guards}, defines, guards)
    return [defines[n] for n in sorted(keep)]


# ---------------------------------------------------------------------------
# The target's feature-test macros: defined before its first system header, tested by a system header
# ---------------------------------------------------------------------------


def scan_feature_macros(text: str, tree: str, generated: str | None) -> dict:
    """
    Walk the `gcc -E -dD` output of one compile. {first_system: the first system header the target's
    own files enter (stdc-predef.h and other files the command line enters do not count; the build's
    generated headers under `generated` are the target's), defines: {name: `#define` line} the command
    line and the target's files left defined before it, later: the target's own `#define`s after it
    (last one wins, an `#undef` removes it; a source that includes <stdint.h> before the target's config
    header, as nginx's generated ngx_event_quic_bpf_code.c does, defines `_GNU_SOURCE` only there),
    target_files: every file of the target the compile enters, system_files: every system header it
    enters}. `tree` is accepted for symmetry with `scan_preprocessed`: a file is the target's by its line
    marker (not a system header), not by its path.
    """
    del tree
    stack: list[tuple[str, bool]] = []
    defines: dict[str, str] = {}
    later: dict[str, str] = {}
    first: str | None = None
    target_files: list[str] = []
    system_files: list[str] = []
    seen_system: set[str] = set()
    for line in text.splitlines():
        if not line.startswith("#"):
            continue
        m = _LINEMARKER_RE.match(line)
        if m:
            path = _unescape_marker(m.group(1))
            flags = m.group(2).split()
            system = "3" in flags and not under(path, generated)
            if "1" in flags:
                parent = stack[-1][0] if stack else ""
                stack.append((path, system))
                if system:
                    if path not in seen_system:
                        seen_system.add(path)
                        system_files.append(path)
                    if first is None and parent not in _PSEUDO_FILES:
                        first = path
                elif path not in target_files:
                    target_files.append(path)
            elif "2" in flags:
                if stack:
                    stack.pop()
                if stack:
                    stack[-1] = (path, system)
                else:
                    stack.append((path, system))
            elif stack:
                stack[-1] = (path, system)
            else:
                stack.append((path, system))
            continue
        cur, system = stack[-1] if stack else ("", False)
        target = cur != "<built-in>" and not system
        table = defines if first is None else later
        d = _DEFINE_LINE_RE.match(line)
        if d:
            if target:
                table[d.group(1)] = line.rstrip()
            else:
                table.pop(d.group(1), None)
            continue
        u = _UNDEF_LINE_RE.match(line)
        if u:
            table.pop(u.group(1), None)
    return {
        "first_system": first,
        "defines": defines,
        "later": later,
        "target_files": target_files,
        "system_files": system_files,
    }


@lru_cache(maxsize=4096)
def _tested_names(path: str) -> frozenset[str]:
    """The identifiers a header's conditional directives test (`#if`, `#ifdef`, `#elif`, ...)."""
    text = _read(path)
    if text is None:
        return frozenset()
    text = text.replace("\\\n", " ")
    return frozenset(
        ident for kind, arg in _DIRECTIVE_RE.findall(text) if kind in _CONDITIONALS for ident in _IDENT_RE.findall(arg)
    )


def select_feature_macros(scan: dict, cwd: Path | None = None, late: bool = False) -> dict[str, str]:
    """
    {name: `#define` line} of `scan` (scan_feature_macros) that a system header the compile entered tests
    in a conditional, then, transitively, the target's macros a kept macro's body names; never the include
    guard of one of the target's files. Sorted by name; empty when the compile entered no system header.
    With `late`, the same of the macros the target defines only after its first system header (`later`).
    """
    early: dict[str, str] = scan.get("defines") or {}
    defines = {n: line for n, line in (scan.get("later") or {}).items() if n not in early} if late else early
    if not scan.get("first_system") or not defines:
        return {}
    tested: set[str] = set()
    for f in scan.get("system_files") or []:
        tested |= _tested_names(f)
    guards: set[str] = set()
    for f in scan.get("target_files") or []:
        text = _read(f, cwd)
        guard = include_guard(text) if text is not None else None
        if guard:
            guards.add(guard)
    keep = _with_bodies({n for n in defines if n in tested and n not in guards}, defines, guards)
    return {n: defines[n].rstrip() for n in sorted(keep)}


def macro_flag(line: str) -> str | None:
    """
    The `-D` flag that defines the macro of a `#define` line identically (`-DNAME=` for an empty body,
    so the target's own `#define` stays an identical redefinition), or None when no flag string can carry
    it: a function-like macro, or a body with whitespace, quotes or backslashes.
    """
    m = _DEFINE_LINE_RE.match(line.strip())
    if not m:
        return None
    rest = line.strip()[m.end() :]
    if rest.startswith("("):
        return None
    body = rest.strip()
    if _UNSAFE_VALUE_RE.search(body):
        return None
    return f"-D{m.group(1)}={body}"


def flag_definitions(tokens: Sequence[str]) -> dict[str, str]:
    """{name: the token that defines or undefines it last} of the `-D`/`-U` flags in `tokens`."""
    out: dict[str, str] = {}
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in ("-D", "-U") and i + 1 < len(tokens):
            tok, i = tok + tokens[i + 1], i + 1
        if tok.startswith(("-D", "-U")) and len(tok) > 2:
            m = _IDENT_RE.match(tok[2:])
            if m:
                out[m.group(0)] = tok
        i += 1
    return out


def agrees(given: str, line: str) -> bool:
    """
    Whether the flag `given` (`-DX`, `-DX=v`, `-UX`) defines X as the `#define` line does. A valueless
    `-DX` only asks for X to be defined: it agrees with an empty body or `1`.
    """
    if not given.startswith("-D"):
        return False
    body = macro_body(line).strip()
    name_value = given[2:]
    if "=" not in name_value:
        return body in ("", "1")
    return name_value.split("=", 1)[1].strip() == body


def merge_feature_macros(cppflags_tokens: Sequence[str], macros: dict[str, str]) -> dict[str, Any]:
    """
    How `macros` ({name: `#define` line}) join flags that may define some already: {flags: the `-D`
    flags to add, given: the names the flags already define identically, conflicts: [{macro, given,
    derived}] the flags define otherwise (or undefine; the given flag is kept), not_carried: [{macro,
    line, why}] no flag can spell}.
    """
    have = flag_definitions(list(cppflags_tokens))
    out: dict[str, Any] = {"flags": [], "given": [], "conflicts": [], "not_carried": []}
    for name, line in sorted(macros.items()):
        if name in have:
            if agrees(have[name], line):
                out["given"].append(name)
            else:
                out["conflicts"].append({"macro": name, "given": have[name], "derived": line})
            continue
        flag = macro_flag(line)
        if flag is None:
            function_like = _DEFINE_LINE_RE.sub("", line.strip(), count=1).startswith("(")
            why = (
                "a function-like macro"
                if function_like
                else "its value has whitespace, quotes or backslashes, which the flag strings cannot carry"
            )
            out["not_carried"].append({"macro": name, "line": line, "why": why})
        else:
            out["flags"].append(flag)
    return out


# ---------------------------------------------------------------------------
# Preprocessing the target's own compiles
# ---------------------------------------------------------------------------


def context_tree(dag: dict, capture: dict) -> Path | None:
    """The target's tree to preprocess in: the DAG's `target_dir` (the work tree), else the capture's trees."""
    scratch = capture.get("scratch") if isinstance(capture.get("scratch"), dict) else {}
    for cand in (dag.get("target_dir"), (scratch or {}).get("tree"), capture.get("target")):
        if isinstance(cand, str) and cand and Path(cand).is_dir():
            return Path(cand)
    return None


def preprocess_command(compile_rec: dict, tree: Path, snapshot: Path | None) -> list[str] | None:
    """
    `gcc -E -dD` of one compile in the analysis image, with the compile's own flags (project paths made
    absolute in `tree`), its system include directories and force-included system files read from the
    snapshot, and the build's generated headers. None when the source is in neither the tree nor the
    snapshot's generated files.
    """
    import build_capture as bc  # lazily: heavy, and only needed when a compile is preprocessed

    source = str(compile_rec["source"])
    src = tree / source
    if not src.is_file() and snapshot is not None:
        src = snapshot / target_env.GENERATED_REL / source
    if not src.is_file():
        return None
    root = (snapshot / "root").as_posix() if snapshot else None
    system = [str(t) for t in compile_rec.get("system_flags") or []]
    forced: list[str] = []
    for i, tok in enumerate(system[:-1]):
        if tok in ("-include", "-imacros") and is_abs_path(system[i + 1]):
            copy = f"{root}{system[i + 1]}" if root else system[i + 1]
            forced += [tok, copy if Path(copy).is_file() else system[i + 1]]
    return [
        "gcc",
        "-E",
        "-dD",
        *bc.absolute_flags([str(t) for t in compile_rec.get("flags") or []], tree.as_posix()),
        *target_env.include_flags(root, system),
        *target_env.generated_include_flags(snapshot),
        *forced,
        src.as_posix(),
    ]


def run_preprocessor(cmd: list[str], cwd: Path, timeout: int) -> tuple[int, str]:
    """(exit code, stdout then stderr) of `cmd`; 127 when the compiler is missing, 124 on a timeout."""
    if shutil.which(cmd[0]) is None:
        return 127, f"{cmd[0]}: not found"
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {timeout} s"
    except OSError as exc:
        return 127, str(exc)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _first_error(out: str) -> str:
    for line in out.splitlines():
        if "error" in line.lower():
            return line.strip()[:300]
    return ""


_CACHE: dict[str, dict[str, Any]] = {}


def clear_cache() -> None:
    """Forget the derivations of this process (tests)."""
    _CACHE.clear()
    _tested_names.cache_clear()


def _one_compile(c: dict, tree: Path, snapshot: Path | None, generated: str | None) -> dict[str, Any]:
    cmd = preprocess_command(c, tree, snapshot)
    if cmd is None:
        return {"source": c["source"], "error": "source not found in the tree"}
    rc, out = run_preprocessor(cmd, tree, PREPROCESS_TIMEOUT_S)
    if rc != 0:
        return {"source": c["source"], "error": _first_error(out) or f"gcc exited {rc}"}
    scan = scan_feature_macros(out, tree.as_posix(), generated)
    return {
        "source": c["source"],
        "command": shlex.join(cmd),
        "macros": select_feature_macros(scan, tree),
        "late": select_feature_macros(scan, tree, late=True),
    }


def feature_macros_of(compiles: Iterable[dict], tree: Path | None) -> dict[str, Any]:
    """
    The feature-test macros the target sets in every one of `compiles` (build_capture.json records):
    {compiles: the sources preprocessed, command: the first one's, macros: {name: `#define` line} that a
    system header tests, that one compile at least defines before its first system header, and that
    every preprocessed compile defines identically (before or after it: `late` lists the sources that
    define it only after their first system header, whose system headers the flag changes), differing:
    [{macro, values: {line or `(undefined)`: count}, compiles: {source: line or null} of the sources
    off the most common value}] the others, failed: [{source, error}]}. Empty `macros` when no compile
    could be preprocessed (no tree, no gcc). Each compile is preprocessed once per process.
    """
    recs = sorted(
        {json.dumps(c, sort_keys=True): c for c in compiles if isinstance(c, dict) and c.get("source")}.values(),
        key=lambda c: (str(c["source"]), str(c.get("object") or "")),
    )
    if not recs or tree is None:
        return {"compiles": [], "macros": {}, "differing": [], "failed": []}
    snapshot = target_env.snapshot_dir()
    generated = (snapshot / target_env.GENERATED_REL).as_posix() if snapshot else None
    todo = recs[:MAX_FEATURE_COMPILES]
    keys = {id(c): json.dumps([tree.as_posix(), str(snapshot), c], sort_keys=True) for c in todo}
    missing = [c for c in todo if keys[id(c)] not in _CACHE]
    if missing:
        with ThreadPoolExecutor(max_workers=max(1, min(8, len(missing)))) as pool:
            fresh = list(pool.map(lambda c: _one_compile(c, tree, snapshot, generated), missing))
            for c, res in zip(missing, fresh, strict=True):
                _CACHE[keys[id(c)]] = res
    results = [_CACHE[keys[id(c)]] for c in todo]
    ok = [r for r in results if "macros" in r]
    failed = [{"source": r["source"], "error": r["error"]} for r in results if "error" in r]
    if len(recs) > len(todo):
        failed.append({"source": f"{len(recs) - len(todo)} more", "error": f"over {MAX_FEATURE_COMPILES} compiles"})
    names = sorted({n for r in ok for n in r["macros"]})
    macros: dict[str, str] = {}
    late: dict[str, list[str]] = {}
    differing: list[dict[str, Any]] = []
    for n in names:
        lines = {r["source"]: r["macros"].get(n) or (r.get("late") or {}).get(n) for r in ok}
        values = set(lines.values())
        if len(values) == 1 and None not in values:
            macros[n] = next(iter(values)) or ""
            after = [r["source"] for r in ok if n not in r["macros"]]
            if after:
                late[n] = after
            continue
        counts: dict[str, int] = {}
        for v in lines.values():
            counts[v or UNDEFINED] = counts.get(v or UNDEFINED, 0) + 1
        common = max(sorted(counts), key=lambda v: (counts[v], v != UNDEFINED))
        off = {s: v for s, v in lines.items() if (v or UNDEFINED) != common}
        differing.append({"macro": n, "values": counts, "compiles": dict(list(off.items())[:MAX_LISTED])})
    out: dict[str, Any] = {
        "compiles": [r["source"] for r in ok],
        "macros": macros,
        "differing": differing,
        "failed": failed,
    }
    if late:
        out["late"] = late
    if ok:
        out["command"] = ok[0]["command"]
    return out


def compiles_of_sources(capture: dict, sources: Iterable[str], tree_prefixes: Sequence[str] = ()) -> list[dict]:
    """
    The capture's compiles of `sources` (run-relative, `workspace/work/...`, tree-relative or under one
    of `tree_prefixes`), matched on the compile's tree-relative `source`.
    """
    prefixes = [p.rstrip("/") + "/" for p in (*tree_prefixes, "workspace/work") if p]
    wanted: set[str] = set()
    for s in sources:
        rel = str(s).strip().replace("\\", "/")
        while rel.startswith("./"):
            rel = rel[2:]
        for p in prefixes:
            if rel.startswith(p):
                rel = rel[len(p) :]
                break
        wanted.add(rel)
    return [c for c in capture.get("compiles") or [] if isinstance(c, dict) and str(c.get("source")) in wanted]
