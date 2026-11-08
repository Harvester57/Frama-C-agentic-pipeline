#!/usr/bin/env python3
"""
Writes the call-graph DAG (workspace/reports/callgraph_dag.json) from the Phase 0 model
(workspace/reports/phase0_model.json, scripts/phase0_model.py) and the build capture
(workspace/reports/build_capture.json, scripts/build_capture.py). Stdlib only.

- **Functions:** every function a non-test link unit compiles, under its real name (`file#name` when
  the name collides), with Frama-C's direct and indirect edges, bottom-up topological waves (Wave 0:
  leaves) and recursion cycles.
- **Per-function facts, all from the model:** lines, storage, loops and cyclomatic complexity; from the
  signature, the parameters, pointer parameters, pointer result and variadic; from the external calls,
  allocation and formatting; the indirect call sites; trust (scripts/trust.py). From the source lines
  of each definition, backward gotos, `container_of`, volatile and inline assembly. From these, the WP
  blockers and notes, and the termination obligation (Layer 2).
- **Modules:** the build's link units (`unit_view`, step I5b), libraries first: their sources plus the
  sources of the project libraries they link, the build's flags, their API entry points. Units too
  large for one Eva run are split into sub-modules (scripts/unit_split.py, step I8).
- **Path modules:** the sources partitioned by directory (`path_module`), the granularity harness
  sub-modules have always had. They are kept under `lexer_modules`, the key's name from when a token
  lexer drew them, with `unit_of_lexer_module`. A harness named after one is a sub-module of its unit
  (scripts/module_map.py).
- **Tiers:** per function from trust and structure, per module the most demanding (scripts/tiers.py).

Without a successful model there is no DAG: Phase 0 stops, and the parent agent asks for a build
recipe (`needs_build_recipe`, docs/phase0-implementation-plan.md).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent))

import tiers  # noqa: E402
import unit_split  # noqa: E402
from framac_common import is_pipeline_output_dir  # noqa: E402

DYNAMIC_ALLOC_CALLEES = {
    "malloc",
    "calloc",
    "realloc",
    "free",
    "aligned_alloc",
    "strdup",
    "strndup",
    "alloca",
    "__builtin_alloca",
}

FORMAT_OR_WRITE_CALLEES = {
    "snprintf",
    "vsnprintf",
    "sprintf",
    "vsprintf",
    "memcpy",
    "memmove",
    "strncpy",
    "strlcpy",
    "strncat",
    "strlcat",
}

HARNESS_ENTRYPOINT_NAMES = frozenset(
    {
        "LLVMFuzzerTestOneInput",
        "LLVMFuzzerInitialize",
        "eva_main",
    }
)

# The formal Frama-C gives a variadic definition's `...`.
VA_PARAMS = "__va_params"

DEFAULT_MODEL = Path("workspace/reports/phase0_model.json")
CAPTURE_NAME = "build_capture.json"

# phase0_model.py's fact sources -> the ledger's callgraph_source values.
MODEL_SOURCES = {"frama-c-kernel": "frama_c", "gcc-callgraph-info": "gcc_callgraph"}


def compute_topological_waves(
    functions: dict[str, dict],
    call_edges: dict[str, set[str]],
) -> tuple[list[list[str]], list[list[str]]]:
    """
    Compute exact Strongly Connected Components (Tarjan's algorithm) and
    bottom-up Topological Waves:
      Wave 0: Leaf project functions (call 0 other project functions)
      Wave k: Functions whose internal callees are all in Waves 0..k-1
    """
    all_fns = sorted(functions.keys())
    all_fn_set = set(all_fns)
    internal_callees: dict[str, set[str]] = {
        fn: {c for c in call_edges.get(fn, set()) if c in all_fn_set and c != fn} for fn in all_fns
    }

    # 1. Tarjan's SCC algorithm to detect mutual and self recursion accurately
    index = 0
    indices: dict[str, int] = {}
    lowlink: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    sccs: list[list[str]] = []

    def strongconnect(node: str) -> None:
        nonlocal index
        indices[node] = index
        lowlink[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)

        for succ in sorted(internal_callees[node]):
            if succ not in indices:
                strongconnect(succ)
                lowlink[node] = min(lowlink[node], lowlink[succ])
            elif succ in on_stack:
                lowlink[node] = min(lowlink[node], indices[succ])

        if lowlink[node] == indices[node]:
            scc: list[str] = []
            while True:
                w = stack.pop()
                on_stack.remove(w)
                scc.append(w)
                if w == node:
                    break
            sccs.append(sorted(scc))

    for fn in all_fns:
        if fn not in indices:
            strongconnect(fn)

    cycles: list[list[str]] = []
    for scc in sccs:
        if len(scc) > 1:
            cycles.append(scc)
        elif len(scc) == 1 and functions[scc[0]].get("self_recursive"):
            cycles.append(scc)

    # 2. Bottom-up wave scheduling
    remaining = set(all_fns)
    waves: list[list[str]] = []

    while remaining:
        current_wave = sorted(fn for fn in remaining if len(internal_callees[fn] & remaining) == 0)
        if current_wave:
            waves.append(current_wave)
            remaining -= set(current_wave)
        else:
            # Break mutual recursion cycle using a leaf SCC among remaining nodes
            rem_sccs = [scc for scc in sccs if set(scc).issubset(remaining) and len(scc) > 1]
            if rem_sccs:
                # Pick SCC that has no edges to any other remaining SCC
                chosen_scc = None
                for scc in rem_sccs:
                    scc_set = set(scc)
                    outside_deps = set()
                    for m in scc:
                        outside_deps |= (internal_callees[m] & remaining) - scc_set
                    if not outside_deps:
                        chosen_scc = scc
                        break
                picked_group = chosen_scc or rem_sccs[0]
                waves.append(picked_group)
                remaining -= set(picked_group)
            else:
                picked = sorted(
                    remaining,
                    key=lambda f: (len(internal_callees[f] & remaining), f),
                )[0]
                waves.append([picked])
                remaining.remove(picked)

    return waves, cycles


_SKIPPED_WALK_DIRS = frozenset({"build", "CMakeFiles", "__pycache__"})


def find_pipeline_output_dirs(target_dir: Path) -> list[str]:
    """Target-relative directories that hold pipeline output (a run directory copied into the target)."""
    found: list[str] = []
    for root, dirs, _ in os.walk(target_dir):
        kept: list[str] = []
        for d in dirs:
            if is_pipeline_output_dir(Path(root) / d):
                found.append((Path(root) / d).relative_to(target_dir).as_posix())
            elif not d.startswith(".") and d not in _SKIPPED_WALK_DIRS:
                kept.append(d)
        dirs[:] = kept
    return sorted(found)


def _load_json(path: Path, what: str) -> tuple[dict | None, str | None]:
    if not path.is_file():
        return None, f"{path} not found ({what})"
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return None, f"{path} unreadable: {exc}"
    if not isinstance(doc, dict) or doc.get("status") != "ok":
        return None, f"{path} status {doc.get('status') if isinstance(doc, dict) else None!r}"
    return doc, None


def load_model(path: Path) -> tuple[dict | None, str | None]:
    """The Phase 0 model when it exists and succeeded, else (None, why not)."""
    return _load_json(path, "run the build capture and phase0_model.py run first")


def load_capture(path: Path) -> tuple[dict | None, str | None]:
    """The build capture when it exists and succeeded, else (None, why not)."""
    return _load_json(path, "the build capture's report")


def _model_key_of(model_fns: dict[str, dict]) -> dict[str, str]:
    """DAG keys for model ids (`file#name`): the plain name when it is unique, else the id."""
    names: dict[str, int] = defaultdict(int)
    for rec in model_fns.values():
        names[rec["name"]] += 1
    return {fid: (rec["name"] if names[rec["name"]] == 1 else fid) for fid, rec in model_fns.items()}


# ---------------------------------------------------------------------------------------------------
# Per-function facts from the model
# ---------------------------------------------------------------------------------------------------

# Canonical types of the dump (typedefs unrolled, qualifiers dropped): `unsigned char *`, `unsigned long`.
_BYTE_POINTEES = frozenset({"char", "unsigned char", "signed char", "void"})
_INTEGER_WORDS = frozenset({"char", "short", "int", "long", "unsigned", "signed"})
# `int (*)(int)`, not a pointer to an array (`long (*)[16]`).
_FN_POINTER_RE = re.compile(r"\(\s*\*[^()]*\)\s*\(")
_ARRAY_RE = re.compile(r"\[[^\]]*\]")


def split_signature(signature: str) -> tuple[str, list[str], bool]:
    """
    The dump's canonical signature `ret(arg1,arg2[,...])` as (return type, argument types, variadic).
    `(void)` and an unspecified list `()` both give no arguments.
    """
    sig = (signature or "").strip()
    if not sig.endswith(")"):
        return sig, [], False
    depth, open_idx = 0, -1
    for i in range(len(sig) - 1, -1, -1):
        if sig[i] == ")":
            depth += 1
        elif sig[i] == "(":
            depth -= 1
            if depth == 0:
                open_idx = i
                break
    if open_idx < 0:
        return sig, [], False
    args: list[str] = []
    cur, depth = "", 0
    for ch in sig[open_idx + 1 : -1]:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            args.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        args.append(cur.strip())
    variadic = bool(args) and args[-1] == "..."
    if variadic:
        args = args[:-1]
    if args == ["void"]:
        args = []
    return sig[:open_idx].strip(), args, variadic


def signature_facts(m: dict) -> dict:
    """
    What the signature says about a function: its parameter types, pointer parameters (const or not,
    from the dump's `formals`), whether it takes a bounded input buffer (a const pointer plus an
    integer) or writes one (a writable byte pointer plus an integer), its pointer result and whether it
    is variadic. A function pointer parameter is not a pointer parameter. Without `formals` (a model
    from before dump schema 3) a pointer's constness is unknown: it counts as a pointer parameter, and
    no buffer direction is inferred.
    """
    ret, args, variadic = split_signature(str(m.get("signature") or ""))
    formals = m.get("formals") if isinstance(m.get("formals"), list) else None
    if formals and args and str((formals[-1] or {}).get("name")) == VA_PARAMS:
        # Frama-C's variadic translation: `f(int n, ...)` is defined as `f(int n, void * const *__va_params)`.
        formals, args, variadic = formals[:-1], args[:-1], True
    kinds = [str((f or {}).get("kind") or "") for f in formals] if formals and len(formals) == len(args) else None
    const_ptr = mutable_ptr = byte_in = byte_out = integers = 0
    for i, arg in enumerate(args):
        if _FN_POINTER_RE.search(arg):
            continue
        if "*" in arg or "[" in arg:
            pointee = " ".join(_ARRAY_RE.sub(" ", arg).replace("*", " ").split())
            # A byte buffer is one level of indirection to bytes: `char **` is a pointer to pointers.
            byte = pointee in _BYTE_POINTEES and arg.count("*") + arg.count("[") == 1
            if kinds is None:
                mutable_ptr += 1  # constness unknown (a dump before schema 3): no buffer direction
            elif kinds[i] == "const_pointer":
                const_ptr += 1
                byte_in += byte
            else:
                mutable_ptr += 1
                byte_out += byte
        elif arg.split() and set(arg.split()) <= _INTEGER_WORDS and arg != "char":
            integers += 1
    return {
        "params": args,
        "is_variadic": variadic,
        "returns_pointer": "*" in ret,
        "const_ptr_params": const_ptr,
        "mutable_ptr_params": mutable_ptr,
        "takes_bounded_buffer": (const_ptr > 0 or byte_in > 0) and integers > 0,
        "writes_bounded_buffer": byte_out > 0 and integers > 0,
    }


def call_facts(m: dict, indirect_exprs: list[str]) -> dict:
    """What the calls say: externals called (allocation, formatting or bounded copies) and indirect call sites."""
    external = sorted({str(c) for c in m.get("external_calls") or [] if c})
    return {
        "external_callees": external,
        "has_dynamic_alloc": bool(set(external) & DYNAMIC_ALLOC_CALLEES),
        "uses_format_or_write": bool(set(external) & FORMAT_OR_WRITE_CALLEES),
        "indirect_calls": indirect_exprs,
    }


# Source tokens that make a function a WP shell: a volatile access or inline assembly.
VOLATILE_OR_ASM_TOKENS = frozenset({"volatile", "__volatile", "__volatile__", "asm", "__asm", "__asm__"})
# Words followed by `:` that are not statement labels, and words `goto` cannot name.
_NOT_LABELS = frozenset({"default", "case", "goto", "return", "break", "continue", "else", "do"})
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def source_facts(text: str) -> dict[str, bool]:
    """
    WP blockers in a function's source text (its definition's lines in the model): a backward goto
    (a loop WP cannot attach an invariant to), `container_of` (a cast from a member back to its
    struct), and a volatile access or inline assembly. These are the rules of the token lexer the
    DAG used before step I10a, applied to the model's line span of the function; the kernel AST
    cannot give them, as `container_of` is a macro and Frama-C adds gotos of its own. Comments and
    string literals are skipped; code inside macros the function calls is not seen.
    """
    from acsl_ast import AcslError, tokenize_c_acsl

    out = {"has_backward_goto": False, "has_container_of": False, "has_volatile_or_asm": False}
    try:
        tokens = [t for t in tokenize_c_acsl(text) if t.kind in ("c_token", "string")]
    except AcslError:
        return out
    start = next((i for i, t in enumerate(tokens) if t.text == "{"), None)
    if start is None:
        return out
    body = tokens[start:]
    labels: dict[str, int] = {}
    gotos: list[tuple[str, int]] = []
    for i, tok in enumerate(body):
        t = tok.text
        if t in VOLATILE_OR_ASM_TOKENS:
            out["has_volatile_or_asm"] = True
        elif t == "container_of":
            out["has_container_of"] = True
        elif t == "goto" and i + 1 < len(body) and _IDENT_RE.match(body[i + 1].text):
            gotos.append((body[i + 1].text, i))
        elif (
            _IDENT_RE.match(t)
            and t not in _NOT_LABELS
            and i + 1 < len(body)
            and body[i + 1].text == ":"
            and body[i - 1].text in (";", "{", "}", ":")
        ):
            labels.setdefault(t, i)
    out["has_backward_goto"] = any(label in labels and labels[label] < at for label, at in gotos)
    return out


class SourceLines:
    """Lines of the project files under `root`, read once each; a missing file gives no text."""

    def __init__(self, root: Path | None) -> None:
        self.root = root
        self._lines: dict[str, list[str] | None] = {}

    def span(self, rel: str, first: int, last: int) -> str | None:
        if self.root is None or first <= 0:
            return None
        if PurePosixPath(rel).is_absolute() or ".." in PurePosixPath(rel).parts:
            return None
        if rel not in self._lines:
            try:
                path = self.root / rel
                self._lines[rel] = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except (OSError, ValueError):
                self._lines[rel] = None
        lines = self._lines[rel]
        if lines is None:
            return None
        return "\n".join(lines[first - 1 : max(first, last)])


def wp_facts(name: str, rec: dict) -> dict:
    """
    WP blockers (a harness entry point, a variadic definition, a backward goto, heap allocation,
    `container_of`, a volatile access or inline assembly: the function goes to the unverifiable
    shell), notes for the prover, and the verifiability class. Recursion is noted once the cycles
    are known.
    """
    blockers: list[str] = []
    notes: list[str] = []
    if name in HARNESS_ENTRYPOINT_NAMES:
        blockers.append("fuzz_or_eva_harness_entrypoint")
        notes.append("fuzz/Eva harness entrypoint: verified dynamically by E-ACSL + LibFuzzer and Eva, not WP")
    if rec["is_variadic"]:
        blockers.append("internal_variadic")
        notes.append("internal variadic function: Frama-C WP does not support variadic function specifications")
    if rec.get("has_backward_goto"):
        blockers.append("irreducible_goto")
    if rec["has_dynamic_alloc"]:
        blockers.append("dynamic_allocation")
    if rec.get("has_container_of"):
        blockers.append("container_of")
    if rec.get("has_volatile_or_asm"):
        blockers.append("volatile_or_asm")
    if rec["indirect_calls"]:
        notes.append(f"indirect call(s) {rec['indirect_calls']} require '//@ calls <targets>;'")
    if blockers:
        verifiability = "shell_unverifiable_wp"
    elif rec["indirect_calls"]:
        verifiability = "needs_calls_annotation"
    else:
        verifiability = "core_provable"
    return {"wp_blockers": blockers, "wp_notes": notes, "verifiability": verifiability}


def termination_properties(rec: dict) -> list[dict]:
    """
    Layer 2 (termination): a loop variant per loop, else a decreasing measure for recursion. Layers 3-6
    come from the structured threat model (scripts/security_props.py, step I9).
    """
    if rec.get("has_loops"):
        return [
            {
                "layer": 2,
                "category": "Termination / Anti-DoS",
                "template": "loop variant",
                "reason": f"Function contains {rec.get('loop_count')} loop(s) requiring strict decreasing loop variant proofs.",
            }
        ]
    if rec.get("is_recursive"):
        return [
            {
                "layer": 2,
                "category": "Termination / Anti-DoS",
                "template": "decreases",
                "reason": "Recursive function requires a strict decreasing measure.",
            }
        ]
    return []


# ---------------------------------------------------------------------------------------------------
# Path modules and flags
# ---------------------------------------------------------------------------------------------------


def path_module(rel_path: str) -> str:
    """A source's path module: `src/<dir>/...` -> `<dir>`, `src/f.c` -> `f`, `<dir>/...` -> `<dir>`, `f.c` -> `f`."""
    p = PurePosixPath(rel_path)
    parts = p.parts
    if len(parts) >= 2 and parts[0] == "src":
        return parts[1] if len(parts) > 2 else p.stem
    if len(parts) >= 2:
        return parts[0]
    return p.stem


_DIR_FLAGS = ("-I", "-isystem", "-iquote", "-idirafter")
_FORCE_INCLUDE_FLAGS = ("-include", "-imacros")


def _rooted(path: str, root: str) -> str:
    """A project-relative path made relative to the run directory (`root` is the DAG's target directory)."""
    if not root or path.startswith("/") or path.startswith(root.rstrip("/") + "/"):
        return path
    path = path[2:] if path.startswith("./") else path
    return root.rstrip("/") if path in ("", ".") else f"{root.rstrip('/')}/{path}"


def unit_cppflags(unit_flags: list[str], include_dirs: list[str], root: str = "") -> tuple[list[str], list[str]]:
    """
    A unit's compile flags, one token each, and its force-included files (`-include f` / `-imacros f`,
    which take two tokens and so are kept apart). Flags are the build's own (`-I inc` joined to `-Iinc`;
    `-isystem`/`-iquote`/`-idirafter` directories as `-I`), then `-I` for `include_dirs`: the directories
    of the unit's sources and of the project headers they include, which the compiler finds next to the
    including file but a harness elsewhere does not. The model's paths are relative to the project root;
    with `root` (the DAG's target directory, e.g. `workspace/work`) relative directories and files are
    made relative to the run directory.
    """
    out: list[str] = []
    forced: list[str] = []
    tokens = [str(t) for t in unit_flags]
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        nxt = tokens[i + 1] if i + 1 < len(tokens) else None
        if tok in _FORCE_INCLUDE_FLAGS and nxt is not None:
            forced.append(_rooted(nxt, root))
            i += 2
            continue
        if tok in _DIR_FLAGS and nxt is not None:
            tok = "-I" + _rooted(nxt, root)
            i += 1
        elif tok in ("-D", "-U") and nxt is not None:
            tok += nxt
            i += 1
        else:
            for opt in _DIR_FLAGS:
                if tok.startswith(opt) and len(tok) > len(opt):
                    tok = "-I" + _rooted(tok[len(opt) :], root)
                    break
        if tok not in out:
            out.append(tok)
        i += 1
    for d in include_dirs:
        flag = "-I" + _rooted(d, root)
        if flag not in out:
            out.append(flag)
    return out, list(dict.fromkeys(forced))


def include_dirs(sources: list[str], capture: dict | None) -> list[str]:
    """
    Project directories a harness of these sources needs on its include path: each source's directory,
    then the directories of the project headers it includes (the capture's `cc -M` dependency lists).
    """
    headers: dict[str, set[str]] = defaultdict(set)
    for c in (capture or {}).get("compiles") or []:
        if isinstance(c, dict) and c.get("source"):
            headers[str(c["source"])] |= {str(h) for h in c.get("headers") or [] if h}
    out: list[str] = []
    for src in sources:
        for d in [
            PurePosixPath(src).parent.as_posix(),
            *(PurePosixPath(h).parent.as_posix() for h in sorted(headers[src])),
        ]:
            d = "" if d == "." else d
            if d not in out:
                out.append(d)
    return out


# ---------------------------------------------------------------------------------------------------
# The DAG from the Phase 0 model, path modules as modules (docs/phase0-implementation-plan.md step I5a)
# ---------------------------------------------------------------------------------------------------


def _path_module_records(functions: dict[str, dict], files: dict[str, str], flags_of: dict[str, list[str]]) -> dict:
    """
    One record per path module: its sources and functions, the sources its functions' callees need
    (`required_sources`: its own files except those defining `main` or a harness entry point, plus the
    files of the project functions its own definitions reach in other modules, through header
    functions), its flags (those of the units compiling those sources) and its entry points
    (non-static functions no other function of the module calls).
    """
    members: dict[str, list[str]] = defaultdict(list)
    for key, rec in functions.items():
        members[rec["lexer_module"]].append(key)
    own_files: dict[str, list[str]] = defaultdict(list)
    for f, m in sorted(files.items()):
        own_files[m].append(f)
    main_files = {
        r["file"] for r in functions.values() if r.get("name") == "main" or r.get("name") in HARNESS_ENTRYPOINT_NAMES
    }

    modules: dict[str, dict] = {}
    for name in sorted(set(own_files) | set(members)):
        fns = sorted(members.get(name, []))
        fn_set = set(fns)
        mod_files = set(own_files.get(name, []))
        effective = (mod_files - main_files) or mod_files
        # From the module's own definitions, through header functions (inline wrappers) to what they call:
        # a header function shared by the unit is assigned to one module, and must not pull in every
        # file its callers' modules need.
        start = [k for k in fns if not functions[k]["header"]]
        closure, work = set(start), list(start)
        while work:
            for callee in functions[work.pop()].get("internal_callees") or []:
                if callee not in closure:
                    closure.add(callee)
                    work.append(callee)
        cross = sorted(
            k
            for k in closure - fn_set
            if not functions[k]["header"]
            and functions[k]["file"] not in mod_files
            and functions[k]["file"] not in main_files
            and functions[k].get("name") != "main"
            and functions[k].get("name") not in HARNESS_ENTRYPOINT_NAMES
        )
        required = sorted(effective | {functions[k]["file"] for k in cross if functions[k]["file"].endswith(".c")})
        flags: list[str] = []
        for src in required:
            flags += [f for f in flags_of.get(src) or [] if f not in flags]
        roots = [k for k in fns if not set(functions[k]["internal_callers"]) & fn_set]
        modules[name] = {
            "module": name,
            "files": sorted(mod_files),
            "required_sources": required,
            "cross_module_callees": cross,
            "external_callees": sorted({c for k in fns for c in functions[k]["external_callees"]}),
            "cppflags": flags,
            "function_count": len(fns),
            "functions": fns,
            "provable_functions": [k for k in fns if functions[k]["verifiability"] != "shell_unverifiable_wp"],
            "shell_unverifiable_functions": [
                k for k in fns if functions[k]["verifiability"] == "shell_unverifiable_wp"
            ],
            "candidate_entry_points": [k for k in roots if not functions[k]["is_static"]] or roots or fns[:1],
        }
    return modules


def model_view(model: dict, capture: dict | None = None, root: str = "", sources: SourceLines | None = None) -> dict:
    """
    The DAG of the Phase 0 model (scripts/phase0_model.py) with path modules as its modules:

    - functions are the model's (every function a non-test link unit compiles, under its real name),
      with their facts (see the module docstring), and the source WP blockers (`source_facts`) when
      `sources` can read the function's lines;
    - `internal_callees` are the model's edges, direct and indirect (type-matched function pointers,
      thread starts, callbacks), so waves, the WP scheduler and the hypothesis audit see them; the
      indirect ones are also listed in `indirect_callees`;
    - a function's path module (`lexer_module`, and `module` in this view) is its file's, and a header
      function's is the one owning most of the sources of the units compiling it;
    - `macro_aliases` maps each alias the model found to the DAG keys of its functions;
    - header functions are marked `header`, and `reached` when an entry point of the build calls them;
    - functions of a unit on the GCC fallback carry `callgraph_fallback` (Frama-C's first error);
    - each function carries the model's `trust` (scripts/trust.py), and the DAG the model's `trust` block.
    """
    model_fns: dict[str, dict] = model.get("functions") or {}
    units: dict[str, dict] = model.get("units") or {}
    aliases: dict[str, dict] = model.get("macro_aliases") or {}
    key_of = _model_key_of(model_fns)
    fallback_error = {
        n: (u.get("parse") or {}).get("error") or "Frama-C could not parse this unit"
        for n, u in units.items()
        if (u.get("parse") or {}).get("status") == "gcc_fallback"
    }

    # The partition: every source of a non-test unit, and every function's .c file.
    file_module: dict[str, str] = {}
    for u in units.values():
        if not u.get("test"):
            for f in u.get("files") or []:
                file_module.setdefault(str(f), path_module(str(f)))
    for m in model_fns.values():
        if str(m["file"]).endswith(".c"):
            file_module.setdefault(str(m["file"]), path_module(str(m["file"])))

    def module_of(rec: dict) -> str:
        if rec["file"] in file_module:
            return file_module[rec["file"]]
        votes: dict[str, int] = defaultdict(int)
        for unit in rec.get("units") or []:
            for src in (units.get(unit) or {}).get("files") or []:
                if src in file_module:
                    votes[file_module[src]] += 1
        if votes:
            return sorted(votes.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
        return Path(rec["file"]).parent.name or Path(rec["file"]).stem

    # Each source's flags: those of the first non-test unit compiling it (libraries first).
    order = sorted(
        (n for n, u in units.items() if not u.get("test")),
        key=lambda n: (_UNIT_KIND_ORDER.get(units[n].get("kind") or "", 2), n),
    )
    flags_of: dict[str, list[str]] = {}
    for n in order:
        files = [str(f) for f in units[n].get("files") or []]
        flags = unit_cppflags(list(units[n].get("cppflags") or []), include_dirs(files, capture), root)[0]
        for f in files:
            flags_of.setdefault(f, flags)

    succ: dict[str, set[str]] = defaultdict(set)
    indirect: dict[str, set[str]] = defaultdict(set)
    for e in model.get("edges") or []:
        caller, callee = key_of.get(e.get("caller")), key_of.get(e.get("callee"))
        if caller and callee:
            succ[caller].add(callee)
            if e.get("kind") == "indirect":
                indirect[caller].add(callee)
    site_exprs: dict[str, list[str]] = defaultdict(list)
    for site in model.get("indirect_sites") or []:
        expr = str(site.get("expr") or "")
        if expr and expr not in site_exprs[str(site.get("caller"))]:
            site_exprs[str(site.get("caller"))].append(expr)

    functions: dict[str, dict] = {}
    for fid, m in sorted(model_fns.items()):
        key = key_of[fid]
        source = MODEL_SOURCES.get(m.get("source") or "", "frama_c")
        loops = int(m.get("loops") or 0)
        mod = module_of(m)
        rec: dict = {
            "name": m["name"],
            "file": m["file"],
            "module": mod,
            "lexer_module": mod,
            "line": m.get("line") or 0,
            "end_line": m.get("end_line") or m.get("line") or 0,
            "loc": m.get("lines") or 0,
            "is_static": bool(m.get("static")),
            "has_loops": loops > 0,
            "loop_count": loops,
            **signature_facts(m),
            **call_facts(m, site_exprs.get(fid, [])),
            "internal_callees": sorted(succ[key] - {key}),
            "indirect_callees": sorted(indirect[key] - {key}),
            "self_recursive": key in succ[key],
            "callgraph_source": source,
            "units": list(m.get("units") or []),
            "header": bool(m.get("header")),
        }
        text = sources.span(str(m["file"]), int(rec["line"]), int(rec["end_line"])) if sources else None
        if text is not None:
            rec.update(source_facts(text))
        rec.update(wp_facts(m["name"], rec))
        errors = sorted({fallback_error[u] for u in m.get("units") or [] if u in fallback_error})
        if errors:
            rec["callgraph_fallback"] = errors[0]
            if all(u in fallback_error for u in m.get("units") or []):
                # No unit compiling it parses: Eva and WP cannot run on it (unit_view decides by the
                # function's home unit instead).
                rec["eva_wp_blocked"] = fallback_blocked_reason(errors[0])
        if m.get("cyclomatic") is not None:
            rec["cyclomatic"] = m["cyclomatic"]
        if isinstance(m.get("trust"), dict):
            rec["trust"] = m["trust"]  # step I7 (scripts/trust.py)
        functions[key] = rec

    waves, cycles = compute_topological_waves(functions, succ)
    in_cycle = {f for c in cycles for f in c}
    for idx, wave in enumerate(waves):
        for key in wave:
            rec = functions[key]
            rec["wave"] = idx
            rec["is_recursive"] = key in in_cycle
            if rec["is_recursive"]:
                rec["wp_notes"].append("recursive function requires 'decreases <measure>;'")
            rec["security_properties"] = termination_properties(rec)
    callers: dict[str, set[str]] = defaultdict(set)
    for caller, callees in succ.items():
        for callee in callees - {caller}:
            callers[callee].add(caller)
    for key, rec in functions.items():
        rec["internal_callers"] = sorted(callers[key])

    # Header functions get a ledger unit only when an entry point of the build reaches them.
    reached: set[str] = set()
    work = [key_of[e] for e in model.get("entry_points") or [] if e in key_of]
    while work:
        cur = work.pop()
        if cur not in reached:
            reached.add(cur)
            work.extend(succ[cur] - reached)
    for key, rec in functions.items():
        if rec["header"]:
            rec["reached"] = key in reached

    alias_keys = {
        alias: sorted(key_of[i] for i in rec.get("ids") or [] if i in key_of) for alias, rec in sorted(aliases.items())
    }
    by_name: dict[str, list[str]] = defaultdict(list)
    for m in model_fns.values():
        by_name[m["name"]].append(m["file"])
    return {
        "callgraph_source": "frama_c",
        "total_c_files": len({r["file"] for r in functions.values() if r["file"].endswith(".c")}),
        "total_functions": len(functions),
        "total_waves": len(waves),
        "name_collisions": [{"function": n, "files": sorted(f)} for n, f in sorted(by_name.items()) if len(f) > 1],
        "macro_aliases": {a: k for a, k in alias_keys.items() if k},
        "warnings": [
            f"unit {u}: Frama-C could not parse it, its call graph comes from GCC (-fcallgraph-info): {err}"
            for u, err in sorted(fallback_error.items())
        ],
        "modules": _path_module_records(functions, file_module, flags_of),
        "waves": [{"wave": i, "count": len(w), "functions": w} for i, w in enumerate(waves)],
        "recursion_cycles": cycles,
        "functions": functions,
        "model": {
            "generated_at": model.get("generated_at"),
            "functions": len(model_fns),
            "gcc_fallback_units": sorted(fallback_error),
        },
        **({"trust": model["trust"]} if isinstance(model.get("trust"), dict) else {}),
    }


# ---------------------------------------------------------------------------------------------------
# Link units as modules (docs/phase0-implementation-plan.md step I5b)
# ---------------------------------------------------------------------------------------------------

_UNIT_KIND_ORDER = {"static_lib": 0, "shared_lib": 1}
_RESERVED_MODULE_NAMES = frozenset({"tune", "tune-base"})


def fallback_blocked_reason(error: str) -> str:
    """Why Eva and WP cannot run on a function of a unit Frama-C could not parse (its first error)."""
    return f"Frama-C cannot parse its link unit, so Eva and WP cannot run on it: {error[:200]}"


def block_fallback_units(dag: dict) -> dict:
    """
    A link unit on the GCC fallback (Frama-C could not parse it): fuzzing runs with the sanitizers,
    since E-ACSL needs the Frama-C parse, and Eva and WP are blocked. Its record, its path modules'
    and its clusters' (the records its harnesses run under) get `run_eva` and `run_wp_full` false and
    `fuzz_engine: sanitizers`. Its functions carry the reason in `eva_wp_blocked`.
    """
    modules: dict[str, dict] = dag.get("modules") or {}
    fallback = {name: str(rec["callgraph_fallback"]) for name, rec in modules.items() if rec.get("callgraph_fallback")}
    if not fallback:
        return dag
    unit_of_path = dag.get("unit_of_lexer_module") or {}
    records = [modules[n] for n in fallback]
    records += [rec for m, rec in (dag.get("lexer_modules") or {}).items() if unit_of_path.get(m) in fallback]
    records += [rec for rec in (dag.get("submodules") or {}).values() if rec.get("unit") in fallback]
    for rec in records:
        if isinstance(rec, dict):
            rec.update(run_eva=False, run_wp_full=False, fuzz_engine="sanitizers")
    for name, error in sorted(fallback.items()):
        dag.setdefault("warnings", []).append(
            f"module {name}: on the GCC fallback, fuzzed with the sanitizers; Eva and WP are blocked"
        )
        for key in modules[name].get("functions") or []:
            rec = (dag.get("functions") or {}).get(key)
            if isinstance(rec, dict):
                rec["eva_wp_blocked"] = fallback_blocked_reason(error)
    return dag


def unit_module_name(unit: str) -> str:
    """A link artifact as a module name usable in Make targets and file names: `lib/libkv.a` -> `libkv_a`."""
    name = "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in Path(unit).name).strip("_") or "unit"
    return name if name not in _RESERVED_MODULE_NAMES else f"{name}_unit"


def unit_view(dag: dict, model: dict, root: str = "", capture: dict | None = None) -> dict:
    """
    The model's DAG (`model_view`) with the build's link units as its modules (step I5b):

    - one module per non-test link unit, libraries first: its own sources plus those of the project
      libraries it links (`required_sources`), its compile flags (`unit_cppflags`), its API entry points
      (exported functions, `main` for an executable, and an executable's embedded API), `concurrent`;
    - a source file belongs to the first unit that compiles it, a header function to the first unit
      it is compiled into;
    - each function keeps its path module (`lexer_module`); the path modules are kept under
      `lexer_modules`, and `unit_of_lexer_module` maps each to the unit holding most of its functions.
      Harnesses stay per path module as sub-modules of a unit (their sidecar's `unit`;
      scripts/module_map.py).

    Tiers and run flags are set afterwards, by scripts/tiers.py.
    """
    units = {n: u for n, u in (model.get("units") or {}).items() if not u.get("test")}
    if not units:
        return dag
    order = sorted(units, key=lambda u: (_UNIT_KIND_ORDER.get(units[u].get("kind") or "", 2), u))
    names: dict[str, str] = {}
    for u in order:
        base = unit_module_name(u)
        name, n = base, 2
        while name in names.values():
            name, n = f"{base}_{n}", n + 1
        names[u] = name
    unit_of_file: dict[str, str] = {}
    for u in order:
        for f in units[u].get("files") or []:
            unit_of_file.setdefault(f, u)

    path_modules: dict[str, dict] = dag.get("modules") or {}
    functions: dict[str, dict] = dag.get("functions") or {}
    model_fns: dict[str, dict] = model.get("functions") or {}
    key_of = _model_key_of(model_fns)

    def home(rec: dict) -> str | None:
        if rec["file"] in unit_of_file:
            return unit_of_file[rec["file"]]
        compiled_in = [u for u in order if u in set(rec.get("units") or [])]
        return compiled_in[0] if compiled_in else None

    members: dict[str, list[str]] = defaultdict(list)
    path_votes: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for key, rec in functions.items():
        path_mod = str(rec.get("lexer_module") or "")
        u = home(rec)
        if u is None:
            continue  # stays in its path module (kept below)
        # Eva and WP run per unit: the home unit's parse decides (block_fallback_units sets it back).
        rec.pop("eva_wp_blocked", None)
        rec["module"] = names[u]
        members[u].append(key)
        if path_mod:
            path_votes[path_mod][names[u]] += 1

    modules: dict[str, dict] = {}
    folded: list[str] = []
    for u in order:
        rec = units[u]
        name = names[u]
        sources, seen, stack = list(rec.get("files") or []), {u}, list(rec.get("links") or [])
        while stack:
            lk = stack.pop()
            if lk in seen or lk not in units:
                continue
            seen.add(lk)
            sources += [f for f in units[lk].get("files") or [] if f not in sources]
            stack += units[lk].get("links") or []
        fns = sorted(members.get(u, []))
        if not fns:
            # Every source belongs to an earlier unit (x509-parser's .so builds its .a's files).
            folded.append(f"unit {u}: compiles only sources of an earlier unit, analysed there")
            continue
        fn_set = set(fns)
        api = [*(rec.get("entry_points") or []), *(rec.get("embedded_api") or [])]
        entries = [k for k in dict.fromkeys(key_of[e] for e in api if e in key_of) if k in fn_set]
        flags, forced = unit_cppflags(list(rec.get("cppflags") or []), include_dirs(sources, capture), root)
        modules[name] = {
            "module": name,
            "unit": u,
            "kind": rec.get("kind"),
            "concurrent": bool(rec.get("concurrent")),
            **(
                {"callgraph_fallback": (rec.get("parse") or {}).get("error") or "Frama-C could not parse this unit"}
                if (rec.get("parse") or {}).get("status") == "gcc_fallback"
                else {}
            ),
            "files": sorted(f for f in sources if unit_of_file.get(f) == u),
            "required_sources": sources,
            "cross_module_callees": sorted(
                {c for k in fns for c in functions[k].get("internal_callees") or [] if c not in fn_set}
            ),
            "external_callees": sorted({c for k in fns for c in functions[k].get("external_callees") or []}),
            "cppflags": flags,
            "force_includes": forced,
            "function_count": len(fns),
            "functions": fns,
            "provable_functions": [k for k in fns if functions[k].get("verifiability") != "shell_unverifiable_wp"],
            "shell_unverifiable_functions": [
                k for k in fns if functions[k].get("verifiability") == "shell_unverifiable_wp"
            ],
            "candidate_entry_points": entries or [k for k in fns if not functions[k].get("is_static")],
            "lexer_modules": sorted({functions[k]["lexer_module"] for k in fns if functions[k].get("lexer_module")}),
            # Step I7: the threat model's status for the unit, and each entry point's trust.
            "threat_model": (rec.get("trust") or {}).get("threat_model"),
            "entry_trust": {
                k: {t: functions[k]["trust"].get(t) for t in ("value", "source", "boundary")}
                for k in (entries or [])
                if isinstance(functions[k].get("trust"), dict)
            },
        }
    # Functions no unit compiles (none in a successful model) keep their path module.
    for key, rec in functions.items():
        if rec["module"] not in modules:
            base_mod = dict(path_modules.get(rec["module"]) or {"module": rec["module"]})
            mod = modules.setdefault(rec["module"], {**base_mod, "functions": [], "lexer_modules": [rec["module"]]})
            mod["functions"] = sorted({*mod["functions"], key})
            mod["function_count"] = len(mod["functions"])

    return {
        **dag,
        "module_kind": "link_unit",
        "warnings": [*(dag.get("warnings") or []), *folded],
        "modules": modules,
        "lexer_modules": path_modules,
        "unit_of_lexer_module": {
            m: sorted(v.items(), key=lambda kv: (-kv[1], kv[0]))[0][0] for m, v in sorted(path_votes.items())
        },
    }


def _run_root(target_dir: Path) -> str:
    """The target directory as later stages name it: relative to the run directory inside the container."""
    root = target_dir.as_posix()
    return root[len("/framac-run/") :] if root.startswith("/framac-run/") else root


def build_dag(
    target_dir: Path,
    model: dict,
    capture: dict | None = None,
    units: bool = True,
    split_max_functions: int = unit_split.MAX_FUNCTIONS,
    split_max_lines: int = unit_split.MAX_LINES,
) -> dict:
    """The DAG of `model` over the project tree `target_dir` (the run's workspace/work overlay)."""
    target_dir = target_dir.resolve()
    root = _run_root(target_dir)
    view = model_view(model, capture, root, SourceLines(target_dir))
    view = {"target_dir": str(target_dir), **view}
    view["warnings"] = [
        f"skipped pipeline output directory inside the target: {rel} (move run results out of the target tree)"
        for rel in find_pipeline_output_dirs(target_dir)
    ] + view["warnings"]
    if units:
        view = unit_view(view, model, root=root, capture=capture)
    # Step I8: tiers per function from trust, then oversized units split into sub-modules.
    tiers.apply(view)
    view = unit_split.apply(view, split_max_functions, split_max_lines)
    # The plan's decision for a unit Frama-C cannot parse: sanitizer fuzzing, Eva and WP blocked.
    return block_fallback_units(view) if units else view


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Write the call-graph DAG and topological waves from the Phase 0 model."
    )
    parser.add_argument("--target", type=Path, required=True, help="Project tree (the run's workspace/work overlay)")
    parser.add_argument("--out", type=Path, required=True, help="Output JSON path for the DAG")
    parser.add_argument(
        "--model",
        type=Path,
        default=DEFAULT_MODEL,
        help=f"Phase 0 model (scripts/phase0_model.py) giving the functions and edges (default {DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--capture",
        type=Path,
        default=None,
        help=f"Build capture (scripts/build_capture.py) giving the headers each source includes "
        f"(default: {CAPTURE_NAME} next to the model)",
    )
    parser.add_argument(
        "--split-max-functions",
        type=int,
        default=unit_split.MAX_FUNCTIONS,
        help=f"Split a link unit with more functions than this (default {unit_split.MAX_FUNCTIONS})",
    )
    parser.add_argument(
        "--split-max-lines",
        type=int,
        default=unit_split.MAX_LINES,
        help=f"Split a link unit with more lines of function bodies than this (default {unit_split.MAX_LINES})",
    )
    parser.add_argument(
        "--held-modules",
        action="store_true",
        help="Keep the path modules as the modules instead of the build's link units (step I5a's view)",
    )
    args = parser.parse_args()

    model, why = load_model(args.model)
    if model is None:
        print(
            f"error: no Phase 0 model: {why}. Phase 0 stops here: the target must build (needs_build_recipe) "
            "and Frama-C must parse at least one of its units (no_unit_parsed).",
            file=sys.stderr,
        )
        return 2
    capture, capture_note = load_capture(args.capture or args.model.parent / CAPTURE_NAME)
    dag = build_dag(
        args.target,
        model,
        capture,
        units=not args.held_modules,
        split_max_functions=args.split_max_functions,
        split_max_lines=args.split_max_lines,
    )
    if capture_note:
        note = f"build capture not used, harness include directories are the sources' only: {capture_note}"
        dag["warnings"] = [*dag.get("warnings", []), note]
        print(f"warning: {note}", file=sys.stderr)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(dag, indent=2) + "\n", encoding="utf-8")

    summary = {
        "out": str(args.out),
        "callgraph_source": dag["callgraph_source"],
        "total_c_files": dag["total_c_files"],
        "total_functions": dag["total_functions"],
        "total_waves": dag["total_waves"],
        "modules": {k: v.get("tier") for k, v in dag["modules"].items()},
        "gcc_fallback_units": dag["model"]["gcc_fallback_units"],
    }
    if dag.get("submodules"):
        summary["submodules"] = {k: v["tier"] for k, v in dag["submodules"].items()}
    if isinstance(dag.get("tiers"), dict):
        summary["tiers"] = dag["tiers"].get("functions") or dag["tiers"].get("source")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
