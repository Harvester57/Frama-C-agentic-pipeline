#!/usr/bin/env python3
"""
Phase 0 harness reachability gate (stdlib only).

A module harness that calls one entry point leaves the rest of the module's API
unexercised: Phase 1 never fuzzes it, Phase 2 marks it dead ("harness gap"), and
Phase 3 breakers cannot reach it. This gate measures, before any fuzzing, which of
each module's entry points (`candidate_entry_points` in the call-graph DAG) the
harness reaches statically:

  roots    = DAG functions the harness file names, directly or through a header
             macro (e.g. a `for_each` iterator) or a header `static inline` wrapper
  reached  = roots plus their transitive in-repo callees (`internal_callees`)

An entry point the harness does not reach fails the gate unless the sidecar
records why it cannot be harnessed (`reach_exempt`, written by the `exempt`
subcommand), by its DAG key or by its plain name when no other DAG function has
it (the static and the dynamic gate match alike). Static reach over-approximates (a call behind an impossible branch
counts); Phase 1/2 measure the dynamic reach.

With link units as DAG modules (step I5b, scripts/module_map.py), a harness that is a
sub-module of a unit answers for the unit's entry points in its scope (its lexer
module's functions), with callees followed across the whole unit. The unit itself
gets a row only for its Tier 1/2 entry points that lie in no harness module's scope
(or all of them when it has no harness): each is a gap unless its lexer module (or
the unit) is exempt in reach_exempt_modules.json, or a sidecar of the unit exempts it.

A target fuzz module (`tf_<id>`, sidecar `target_fuzzer`: a harness around the target's own libFuzzer
fuzz function) is additive: it answers for no entry point and never stands for its unit, which still
needs its own harness or exemptions. Its row fails only when its fuzzer source is missing
(`target_fuzzer_source_missing`) or names no DAG function (`target_fuzzer_reaches_nothing`).

Subcommands:
  check   [--module M]... [--out FILE]   gate every harnessed module (exit 1 on a gap)
  exempt  --module M [--function F]... --reason R
          record an accepted gap: entry points (in the module's sidecar), or a whole
          module that needs no harness (in reach_exempt_modules.json). Once the gate has run, it
          re-records the gate rows the exemption can change (`gate` in the output), so the module's
          targets need no `reach-gate` in between.
  dynamic [--module M]...                 dynamic reach (step I6, after `coverage-<mod>`): an entry
          point of the gate that the module's corpus never executed (workspace/reports/coverage)
          reopens the gate for that module (exit 1). The rows go to harness_reach_dynamic.json with
          the harness digest, and `check` keeps such a gap failing until the harness changes or the
          entry point is exempted; exit 2 when a module has no usable coverage report, or one with
          inputs it never replayed (`inputs.not_replayed`: its gaps are only a lower bound). Such a
          module is listed under `unmeasured`, and a gate an earlier dynamic run failed is re-checked.

A sidecar whose automatic prelude left identifiers unresolved (`prelude_status: unresolved`) fails
`check` (`harness_prelude_unresolved: <symbols>`): generate_harness.py wrote that harness and then failed.

Exit code 0 when the gate passes, 1 when a module has an unexempted gap, 2 on
usage/IO problems.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import phase0_gates  # noqa: E402
from acsl_ast import AcslSyntaxError, tokenize_c_acsl  # noqa: E402
from framac_common import (  # noqa: E402
    ArtifactError,
    atomic_write_json,
    load_json_optional,
    load_json_strict,
    run_lock,
    utc_now,
)
from generate_harness import (  # noqa: E402
    DISPATCH_SKIP_FN,
    TARGET_EMBEDDED_PREFIX,
    _include_dirs_from_cppflags,
    _strip_c_comments,
)
from module_map import ModuleMap, load_sidecars  # noqa: E402

DEFAULT_DAG = Path("workspace/reports/callgraph_dag.json")
DEFAULT_HARNESS_DIR = Path("workspace/harnesses")
DEFAULT_OUT = Path("workspace/reports/harness_reach.json")
# Not named harness_*.json, so the sidecar glob never reads it as a module.
MODULE_EXEMPT_FILE = "reach_exempt_modules.json"
# Tiers Phase 0 must harness (framac-slice Step 4); a Tier 3 module without a harness is by design.
HARNESSED_TIER_PREFIXES = ("Tier 1A", "Tier 1B", "Tier 2")
_IDENT_RE = re.compile(r"\b([A-Za-z_]\w*)\b")
_DEFINE_RE = re.compile(r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)(.*)$")
_HEADER_SUFFIXES = (".h", ".hh", ".hpp", ".inc")


def _logical_lines(text: str) -> list[str]:
    """Join backslash-continued lines so a multi-line #define is one line."""
    return text.replace("\\\r\n", " ").replace("\\\n", " ").splitlines()


def header_macro_functions(include_dirs: list[Path], fn_names: set[str]) -> dict[str, set[str]]:
    """
    Map each function-naming macro defined in the headers of `include_dirs` (top level of
    each directory) to the DAG functions its body names, following macro-to-macro uses.
    """
    raw: dict[str, set[str]] = {}
    for inc_dir in include_dirs:
        if not inc_dir.is_dir():
            continue
        for hdr in sorted(inc_dir.iterdir()):
            if not hdr.is_file() or hdr.suffix not in _HEADER_SUFFIXES:
                continue
            try:
                text = _strip_c_comments(hdr.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
            for line in _logical_lines(text):
                m = _DEFINE_RE.match(line)
                if m:
                    raw.setdefault(m.group(1), set()).update(_IDENT_RE.findall(m.group(2)))
    resolved: dict[str, set[str]] = {}

    def _resolve(name: str, stack: frozenset[str]) -> set[str]:
        if name in resolved:
            return resolved[name]
        out: set[str] = set()
        for ident in raw.get(name, set()):
            if ident in fn_names:
                out.add(ident)
            elif ident in raw and ident not in stack:
                out |= _resolve(ident, stack | {ident})
        resolved[name] = out
        return out

    return {name: fns for name in raw if (fns := _resolve(name, frozenset({name})))}


def _functions_by_name(dag: dict[str, Any]) -> dict[str, list[tuple[str, dict[str, Any]]]]:
    """Index DAG function records, as (DAG key, record), by plain name and by DAG key.

    A colliding name is keyed `file#name` in the DAG, and the model's edges name it by that key.
    """
    by_name: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for key, rec in (dag.get("functions") or {}).items():
        if isinstance(rec, dict):
            name = str(rec.get("name") or key)
            by_name.setdefault(name, []).append((key, rec))
            if key != name:
                by_name.setdefault(key, []).append((key, rec))
    return by_name


def exemption_matcher(exempt: dict[str, str], functions: dict[str, Any]) -> Callable[[str], str | None]:
    """
    How both gates find an entry point's exemption: `match(entry)` is the recorded reason, or None.
    An exemption names the entry point by its DAG key (`name`, or `file#name` when the name collides),
    or by its plain name when exactly one DAG function has that name.
    """
    counts: dict[str, int] = {}
    for key, rec in functions.items():
        name = str(rec.get("name") or key) if isinstance(rec, dict) else str(key)
        counts[name] = counts.get(name, 0) + 1

    def match(entry: str) -> str | None:
        if entry in exempt:
            return exempt[entry]
        rec = functions.get(entry)
        plain = str(rec.get("name") or "") if isinstance(rec, dict) else ""
        plain = plain or entry.rpartition("#")[2]
        if plain != entry and plain in exempt and counts.get(plain, 0) == 1:
            return exempt[plain]
        return None

    return match


def dag_macro_aliases(dag: dict[str, Any]) -> dict[str, set[str]]:
    """The model's macro aliases (alias -> DAG keys of the functions it expands to)."""
    raw = dag.get("macro_aliases") or {}
    if not isinstance(raw, dict):
        return {}
    out: dict[str, set[str]] = {}
    for alias, keys in raw.items():
        vals = [keys] if isinstance(keys, str) else keys if isinstance(keys, list) else []
        if found := {str(k) for k in vals if isinstance(k, str)}:
            out[str(alias)] = found
    return out


def _callees_from_clang_ast(tree: dict) -> set[str]:
    """Extract referenced function names from Clang JSON AST."""
    callees: set[str] = set()
    stack = [tree]
    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            continue
        kind = node.get("kind")
        if kind == "DeclRefExpr":
            ref = node.get("referencedDecl")
            if isinstance(ref, dict) and ref.get("kind") == "FunctionDecl":
                name = ref.get("name")
                if isinstance(name, str) and name:
                    callees.add(name)
            elif isinstance(node.get("name"), str):
                callees.add(node["name"])
        elif kind == "CallExpr":
            callee_decl = node.get("calleeDecl")
            if isinstance(callee_decl, dict) and callee_decl.get("name"):
                callees.add(callee_decl["name"])
        inner = node.get("inner")
        if isinstance(inner, list):
            stack.extend(n for n in reversed(inner) if isinstance(n, dict))
    return callees


def _callees_from_clang(harness_path: Path, cppflags: str) -> set[str] | None:
    clang = shutil.which("clang")
    if not clang or not harness_path.is_file():
        return None
    from target_env import with_include_flags

    argv = [
        clang,
        "-fsyntax-only",
        "-w",
        "-x",
        "c",
        *shlex.split(with_include_flags(cppflags)),
        "-Xclang",
        "-ast-dump=json",
        str(harness_path),
    ]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=120, check=False)
        tree = json.loads(proc.stdout or "")
        return _callees_from_clang_ast(tree) if isinstance(tree, dict) else None
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None


def harness_roots(
    harness_text: str,
    fn_names: set[str],
    macros: dict[str, set[str]],
    harness_path: Path | None = None,
    cppflags: str = "-I.",
) -> set[str]:
    """DAG functions the harness names directly or through a header macro (inline wrappers are DAG functions)."""
    roots: set[str] = set()
    ast_callees = _callees_from_clang(harness_path, cppflags) if harness_path else None
    idents = ast_callees if ast_callees is not None else _used_identifiers(harness_text)
    for ident in idents:
        if ident in fn_names:
            roots.add(ident)
        roots |= macros.get(ident, set())
    return roots


# Words that can stand right before an expression: an identifier after one of them is a use, not a declared name.
_EXPR_KEYWORDS = frozenset({"return", "else", "do", "case", "sizeof", "goto"})
_TAG_KEYWORDS = frozenset({"struct", "union", "enum"})
_PP_IF_RE = re.compile(r"^#\s*(if|ifdef|ifndef|elif|else|endif)\b\s*(.*)$", re.DOTALL)
_PP_DEFINE_BODY_RE = re.compile(r"^#\s*define\s+[A-Za-z_]\w*(?:\([^)]*\))?(.*)$", re.DOTALL)


def _used_identifiers(text: str) -> set[str]:
    """
    Identifiers the C text uses as a value or a call: not the ones it only declares, and not text that
    is never compiled as code. Naming a function is not calling it, so these do not count:

    - string and character literals, comments, and the body of `#if 0`;
    - a member (`s.hash`, `p->hash`) and a tag (`struct stat`);
    - a declared name: a prototype or a definition at file scope, and inside a body an identifier
      that follows a type (`int hash = 0;`, `char *stat;`, `int f(int);`), with the later uses of
      such a variable or parameter.

    A function passed as a value (`register_cb(on_msg)`, `cb = on_msg;`) counts. Text the tokenizer
    cannot read falls back to every identifier outside comments, as before.
    """
    try:
        tokens = [t for t in tokenize_c_acsl(text) if t.kind not in ("whitespace", "c_comment")]
    except AcslSyntaxError:
        return set(_IDENT_RE.findall(_strip_c_comments(text)))
    used: set[str] = set()
    variables: set[str] = set()
    depth = 0
    dead: list[bool] = []  # one entry per open #if: whether its current branch is `#if 0`
    for i, tok in enumerate(tokens):
        if tok.kind == "pp_directive":
            m = _PP_IF_RE.match(tok.text)
            if m:
                word, rest = m.group(1), _strip_c_comments(m.group(2)).strip()
                if word in ("if", "ifdef", "ifndef"):
                    dead.append(word == "if" and rest == "0")
                elif word in ("elif", "else") and dead:
                    dead[-1] = False
                elif word == "endif" and dead:
                    dead.pop()
            elif not any(dead) and (body := _PP_DEFINE_BODY_RE.match(tok.text)):
                used.update(_IDENT_RE.findall(_strip_c_comments(body.group(1))))
            continue
        if any(dead) or tok.kind != "c_token":
            continue
        if tok.text == "{":
            depth += 1
        elif tok.text == "}":
            depth = max(0, depth - 1)
        if not _IDENT_RE.fullmatch(tok.text):
            continue
        prev = tokens[i - 1] if i else None
        prev_text = prev.text if prev is not None and prev.kind == "c_token" else ""
        before = tokens[i - 2].text if i > 1 and tokens[i - 2].kind == "c_token" else ""
        if prev_text == "." or (prev_text == ">" and before == "-") or prev_text in _TAG_KEYWORDS:
            continue
        after_type = bool(_IDENT_RE.fullmatch(prev_text)) and prev_text not in _EXPR_KEYWORDS
        nxt = tokens[i + 1].text if i + 1 < len(tokens) else ""
        if prev_text == "*" and _IDENT_RE.fullmatch(before) and before not in _EXPR_KEYWORDS:
            after_type = nxt != "("  # `char *name;` declares; `n * f(x)` calls
        if after_type and nxt != "(":
            variables.add(tok.text)  # a variable or a parameter of that name hides the function
        if tok.text in variables:
            continue
        if depth == 0:
            # File scope: only an initializer uses a function (`static cb_t cb = on_msg;`).
            if prev_text in ("=", "&"):
                used.add(tok.text)
        elif not after_type:
            used.add(tok.text)
    return used


def callee_closure(roots: set[str], by_name: dict[str, list[tuple[str, dict[str, Any]]]], module: str) -> set[str]:
    """Transitive in-repo callees of `roots`, as names and DAG keys.

    A colliding plain name resolves to its record in `module` first; a `file#name` key to its record.
    """
    reached: set[str] = set()
    work = sorted(roots)
    while work:
        name = work.pop()
        if name in reached:
            continue
        reached.add(name)
        recs = by_name.get(name) or []
        same_mod = [kr for kr in recs if kr[1].get("module") == module]
        for key, rec in same_mod or recs:
            plain = str(rec.get("name") or key)
            # The plain name stands for this record only when no other record shares it.
            idents = (key, plain) if len(by_name.get(plain) or []) == 1 else (key,)
            work.extend(i for i in idents if i not in reached)
            work.extend(c for c in rec.get("internal_callees") or [] if c not in reached)
    return reached


def built_entries(entries: list[str], functions: dict[str, Any]) -> list[str]:
    """
    `entries` without the functions the real build does not define (`model_only` in the DAG: nettle's
    getopt under Frama-C's libc). No harness built with glibc can reach them, so none answers for them.
    """
    return [e for e in entries if not (functions.get(e) or {}).get("model_only")]


def check_module(
    module: str,
    dag: dict[str, Any],
    sidecar: dict[str, Any],
    harness_text: str,
    include_dirs: list[Path],
    mm: ModuleMap | None = None,
    run_dir: Path = Path("."),
) -> dict[str, Any]:
    """
    The gate row of one harness module. A target fuzz module (sidecar `target_fuzzer`) wraps the
    target's own fuzz function: its roots also come from the fuzzer source, it answers for no entry
    point (its unit still needs its own harness, `check_unit`), and it fails when it reaches no DAG
    function at all.
    """
    by_name = _functions_by_name(dag)
    fn_names = set(by_name)
    unit = mm.unit_of(module) if mm is not None else module
    mod_info = (dag.get("modules") or {}).get(module) or {}
    tier = mod_info.get("tier")
    target_fuzzer = sidecar.get("target_fuzzer")
    fuzzer_text: str | None = None
    src: Path | None = None
    tf_row: dict[str, Any] = {}
    if isinstance(target_fuzzer, dict):
        src = phase0_gates.target_fuzzer_source(run_dir, sidecar)
        try:
            fuzzer_text = src.read_text(encoding="utf-8", errors="replace") if src is not None else None
        except OSError:
            fuzzer_text = None
        tf_row = {
            "module": module,
            "tier": mm.tier_of(module) if mm is not None else tier,
            "harness_file": sidecar.get("harness_file"),
            "target_fuzzer": str(target_fuzzer.get("id") or ""),
        }
        if unit != module:
            tf_row["unit"] = unit
        if fuzzer_text is None:
            return {**tf_row, "passed": False, "error": "target_fuzzer_source_missing"}
    if fuzzer_text is not None:
        mod_fns: list[str] = []
        entries: list[str] = []
        tier = tf_row["tier"]
    elif mm is not None and unit != module:
        # A sub-module of a link unit: the unit's entry points in its scope, callees across the unit.
        mod_fns = mm.scope_functions(module)
        entries = mm.scope_entry_points(module)
        tier = mm.tier_of(module)
    else:
        mod_fns = [f for f in mod_info.get("functions") or [] if isinstance(f, str)]
        entries = [f for f in mod_info.get("candidate_entry_points") or [] if isinstance(f, str)]
        if not entries:
            entries = [f for f in mod_fns if not any(r.get("is_static") for _, r in by_name.get(f) or [])]
    entries = built_entries(entries, dag.get("functions") or {})

    macros = header_macro_functions(include_dirs, fn_names)
    for alias, keys in dag_macro_aliases(dag).items():
        macros[alias] = macros.get(alias, set()) | keys
    h_file = sidecar.get("harness_file")
    harness_path = run_dir / h_file if h_file else None
    cppflags = str(sidecar.get("cppflags") or "-I.")
    roots = harness_roots(harness_text, fn_names, macros, harness_path=harness_path, cppflags=cppflags)
    if fuzzer_text is not None:
        roots |= harness_roots(fuzzer_text, fn_names, macros, harness_path=src, cppflags=cppflags)
        if not roots:
            return {**tf_row, "roots": [], "passed": False, "error": "target_fuzzer_reaches_nothing"}
    reached = callee_closure(roots, by_name, unit)

    exempt_raw = sidecar.get("reach_exempt")
    exempt = {str(k): str(v) for k, v in exempt_raw.items()} if isinstance(exempt_raw, dict) else {}
    match = exemption_matcher(exempt, dag.get("functions") or {})
    unreached = sorted(f for f in entries if f not in reached)
    exempted = {f: why for f in unreached if (why := match(f)) is not None}
    gaps = [f for f in unreached if f not in exempted]
    row: dict[str, Any] = {
        "module": module,
        "tier": tier,
        "harness_file": sidecar.get("harness_file"),
        "entry_points": len(entries),
        "entry_points_reached": len(entries) - len(unreached),
        "functions": len(mod_fns),
        "functions_reached": sum(1 for f in mod_fns if f in reached),
        "roots": sorted(roots & set(mod_fns)) + sorted(roots - set(mod_fns)),
        "unreached_entry_points": unreached,
        "exempt": exempted,
        "gaps": gaps,
        "passed": not gaps,
    }
    if unit != module:
        row["unit"] = unit
    if fuzzer_text is not None:
        row["target_fuzzer"] = tf_row["target_fuzzer"]
    return row


def _harness_path(sidecar: dict[str, Any], sidecar_path: Path) -> Path:
    declared = sidecar.get("harness_file")
    if isinstance(declared, str) and Path(declared).is_file():
        return Path(declared)
    return sidecar_path.with_suffix(".c")


def _prelude_failure(sidecar: dict[str, Any]) -> str | None:
    """
    Why the harness generation failed, or None. generate_harness.py writes the harness and its sidecar
    before it raises on identifiers the automatic prelude could not resolve (QCBOR run-4): such a harness
    does not compile, so it fails the gate instead of passing on its names.
    """
    if sidecar.get("prelude_status") != "unresolved":
        return None
    symbols = [str(s) for s in sidecar.get("prelude_unresolved") or [] if s]
    return "harness_prelude_unresolved: " + (", ".join(symbols) or "unknown identifiers")


def _is_harnessed_tier(tier: Any) -> bool:
    return str(tier or "").startswith(HARNESSED_TIER_PREFIXES)


def check_unit(
    unit: str,
    mm: ModuleMap,
    harness_modules: list[str],
    module_exempt: dict[str, Any],
) -> dict[str, Any] | None:
    """
    The gate row of a link unit for its Tier 1/2 entry points outside every harness module's scope
    (all of them without a harness), or None when it has nothing to answer for: a unit-named harness
    covers the whole unit, and Tier 3 code without a harness is deferred by design.
    """
    info = mm.modules.get(unit) or {}
    tier = info.get("tier")
    if not harness_modules and unit in module_exempt and _is_harnessed_tier(tier):
        return {"module": unit, "tier": tier, "passed": True, "exempt": str(module_exempt[unit])}
    if unit in harness_modules:
        return None
    covered: set[str] = set()
    for h in harness_modules:
        covered.update(mm.scope_functions(h))
    entries = built_entries([e for e in info.get("candidate_entry_points") or [] if isinstance(e, str)], mm.functions)
    lexer_of = {e: str((mm.functions.get(e) or {}).get("lexer_module") or "") for e in entries}

    def fn_tier(e: str) -> Any:
        rec = mm.functions.get(e) or {}
        return rec.get("tier") or (mm.lexer_modules.get(lexer_of[e]) or {}).get("tier") or tier

    unharnessed = [e for e in entries if e not in covered and _is_harnessed_tier(fn_tier(e))]
    if not entries and not harness_modules and _is_harnessed_tier(tier):
        # No API entry point to place: the whole unit needs a harness or an exemption, as a module did.
        lexers = [str(m) for m in info.get("lexer_modules") or []]
        if lexers and all(m in module_exempt for m in lexers):
            return {"module": unit, "tier": tier, "passed": True, "exempt": _exempt_note(lexers, module_exempt)}
        return {"module": unit, "tier": tier, "passed": False, "error": "no_harness"}
    if not unharnessed:
        return None
    # The unit's name exempts it unless it also names one of the DAG's lexer modules (tweetnacl's
    # executable `main` holds the lexer module `main`): that key then exempts that lexer module only.
    unit_key = unit in module_exempt and (not harness_modules or unit not in mm.lexer_modules)
    sidecar_exempt: dict[str, str] = {}
    for h in harness_modules:
        raw = (mm.sidecars.get(h) or {}).get("reach_exempt")
        if isinstance(raw, dict):
            for fn, why in raw.items():
                sidecar_exempt.setdefault(str(fn), str(why))
    match = exemption_matcher(sidecar_exempt, mm.functions)
    exempt: dict[str, str] = {}
    for e in unharnessed:
        if lexer_of[e] in module_exempt:
            exempt[e] = f"module {lexer_of[e]}: {module_exempt[lexer_of[e]]}"
        elif unit_key:
            exempt[e] = f"unit {unit}: {module_exempt[unit]}"
        elif (why := match(e)) is not None:
            exempt[e] = why
    gaps = [e for e in unharnessed if e not in exempt]
    if not harness_modules:
        if gaps:
            return {
                "module": unit,
                "tier": tier,
                "passed": False,
                "error": "no_harness",
                "unharnessed_entry_points": unharnessed,
                "gaps": gaps,
            }
        lexers = sorted({lexer_of[e] for e in unharnessed})
        return {"module": unit, "tier": tier, "passed": True, "exempt": _exempt_note(lexers, module_exempt, unit)}
    return {
        "module": unit,
        "tier": tier,
        "harness_modules": harness_modules,
        "entry_points": len(entries),
        "unharnessed_entry_points": unharnessed,
        "exempt": exempt,
        "gaps": gaps,
        "passed": not gaps,
    }


def _exempt_note(lexers: list[str], module_exempt: dict[str, Any], unit: str | None = None) -> str:
    """Why a unit without a harness passes: the exemptions of the lexer modules holding its entry points."""
    parts = [f"{m}: {module_exempt[m]}" for m in lexers if m in module_exempt]
    if unit is not None and len(parts) < len(lexers):
        parts.append(f"{unit}: {module_exempt.get(unit, 'sidecar exemptions')}")
    return "every entry point is in an exempt module (" + "; ".join(parts) + ")"


def run_check(
    dag_path: Path, harness_dir: Path, modules: list[str] | None, run_dir: Path = Path(".")
) -> dict[str, Any]:
    dag = load_json_strict(dag_path)
    if not isinstance(dag, dict):
        raise ValueError(f"{dag_path}: not a call-graph DAG object")
    dag_modules = dag.get("modules") or {}
    wanted = set(modules or [])
    module_exempt = load_json_optional(harness_dir / MODULE_EXEMPT_FILE, {})
    module_exempt = module_exempt if isinstance(module_exempt, dict) else {}
    mm = ModuleMap(dag, load_sidecars(harness_dir))
    link_units = mm.units_are_link_units
    results: list[dict[str, Any]] = []
    harnessed: set[str] = set()
    for sidecar_path in sorted(harness_dir.glob("harness_*.json")):
        sidecar = load_json_optional(sidecar_path, {})
        if not isinstance(sidecar, dict):
            continue
        module = str(sidecar.get("module") or sidecar_path.stem[len("harness_") :])
        # A target fuzz module is never a DAG module: it is gated under the unit its sidecar names, and
        # it is additive, so it never stands for its unit's entry points (`check_unit` ignores it).
        tf = isinstance(sidecar.get("target_fuzzer"), dict)
        if not tf:
            harnessed.add(module)
        if wanted and module not in wanted:
            continue
        if (mm.unit_of(module) if link_units or tf else module) not in dag_modules:
            results.append({"module": module, "passed": True, "skipped": "module_not_in_dag"})
            continue
        if (failed := _prelude_failure(sidecar)) is not None:
            results.append({"module": module, "tier": mm.tier_of(module), "passed": False, "error": failed})
            continue
        harness_file = _harness_path(sidecar, sidecar_path)
        try:
            harness_text = harness_file.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            results.append({"module": module, "passed": False, "error": f"harness_unreadable: {exc}"})
            continue
        include_dirs = _include_dirs_from_cppflags(str(sidecar.get("cppflags") or ""))
        results.append(
            check_module(
                module, dag, sidecar, harness_text, include_dirs, mm=mm if link_units or tf else None, run_dir=run_dir
            )
        )
    if link_units:
        for unit in sorted(dag_modules):
            if wanted and unit not in wanted:
                continue
            subs = sorted(h for h in harnessed if mm.unit_of(h) == unit)
            row = check_unit(unit, mm, subs, module_exempt)
            if row is not None:
                results.append(row)
        return _report(dag_path, results)
    for module, info in sorted(dag_modules.items()):
        if module in harnessed or (wanted and module not in wanted) or not isinstance(info, dict):
            continue
        if not str(info.get("tier") or "").startswith(HARNESSED_TIER_PREFIXES):
            continue
        if module in module_exempt:
            results.append(
                {"module": module, "tier": info.get("tier"), "passed": True, "exempt": str(module_exempt[module])}
            )
        else:
            results.append({"module": module, "tier": info.get("tier"), "passed": False, "error": "no_harness"})
    return _report(dag_path, results)


def _report(dag_path: Path, results: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "generated_at": utc_now(),
        "dag": str(dag_path).replace("\\", "/"),
        "passed": all(r.get("passed") for r in results),
        "modules": results,
    }


def record_exempt(
    harness_dir: Path, module: str, function: str | None, reason: str, dag_path: Path | None = None
) -> dict[str, Any]:
    """
    Record an exemption: a whole module (a lexer module or link unit name) without `function`, else
    one entry point in the module's sidecar. A link unit without a harness of its own records an entry
    point it leaves unharnessed in the sidecar of its first sub-module (read from `dag_path`).
    """
    if function is None:
        path = harness_dir / MODULE_EXEMPT_FILE
        exempt_modules = load_json_optional(path, {})
        exempt_modules = dict(exempt_modules) if isinstance(exempt_modules, dict) else {}
        exempt_modules[module] = reason
        harness_dir.mkdir(parents=True, exist_ok=True)
        atomic_write_json(path, dict(sorted(exempt_modules.items())))
        return {"module": module, "function": None, "reason": reason}
    sidecar_path = harness_dir / f"harness_{module}.json"
    if not sidecar_path.is_file() and dag_path is not None and dag_path.is_file():
        mm = ModuleMap(load_json_strict(dag_path), load_sidecars(harness_dir))
        # Not a target fuzz module: the unit's gate never reads its exemptions (`run_check`).
        subs = [s for s in mm.submodules(module) if not isinstance(mm.sidecars[s].get("target_fuzzer"), dict)]
        stand_in = module if module in subs else (subs[0] if subs else None)
        if stand_in:
            sidecar_path = harness_dir / f"harness_{stand_in}.json"
    sidecar = load_json_strict(sidecar_path)
    if not isinstance(sidecar, dict):
        raise ValueError(f"{sidecar_path}: not a harness sidecar object")
    exempt = sidecar.get("reach_exempt")
    exempt = dict(exempt) if isinstance(exempt, dict) else {}
    exempt[function] = reason
    sidecar["reach_exempt"] = dict(sorted(exempt.items()))
    from generate_harness import write_sidecar

    write_sidecar(sidecar_path, sidecar)  # checks the sidecar's schema (R5)
    return {"module": module, "function": function, "reason": reason, "reach_exempt": sidecar["reach_exempt"]}


def regate_after_exempt(run_dir: Path, dag_path: Path, harness_dir: Path, module: str) -> dict[str, Any]:
    """
    Re-record the reach gate rows an exemption can change, as `check` would: the module's own row, its
    unit's and its sub-modules' (the sidecar that took the exemption changed its digest), and every row
    the gate holds as failed (a module-wide exemption can clear rows of other names). A dynamic gap is
    kept only while it is not exempted (`apply_dynamic`). Without this, `coverage-<mod>` stopped at the
    stale row and `reach-dynamic-<mod>`, which depends on it, never ran to replace it (ptf-original
    run-2). Nothing is recorded before the gate's first run, and a check that cannot run leaves the rows
    as they were: the exemption itself is already stored.
    """
    reach = phase0_gates.load_gates(run_dir).get("reach")
    prior = reach.get("modules") if isinstance(reach, dict) else None
    if not isinstance(prior, dict):
        return {"rechecked": [], "note": "the reach gate has not run yet"}
    try:
        report = run_check(dag_path, harness_dir, None, run_dir=run_dir)
        dag = load_json_strict(dag_path)
        mm = ModuleMap(dag if isinstance(dag, dict) else {}, load_sidecars(harness_dir))
        affected = {module, mm.unit_of(module), *mm.submodules(module)}
    except (ArtifactError, OSError, ValueError, KeyError) as exc:
        return {"rechecked": [], "note": f"gate not re-checked ({exc}): run `{phase0_gates.HOW_TO_RUN['reach']}`"}
    affected |= {str(m) for m, r in prior.items() if not (isinstance(r, dict) and r.get("passed"))}
    report["modules"] = [r for r in report["modules"] if r.get("module") in affected]
    apply_dynamic(report, run_dir / DEFAULT_DYNAMIC_OUT, harness_dir, run_dir, dag=dag if isinstance(dag, dict) else {})
    phase0_gates.record_reach(run_dir, report, partial=True, dag_path=dag_path)
    failing = {
        str(r["module"]): r.get("error") or f"entry points not reached: {', '.join(r.get('gaps') or [])}"
        for r in report["modules"]
        if not r.get("passed")
    }
    out: dict[str, Any] = {"rechecked": sorted(str(r["module"]) for r in report["modules"])}
    if failing:
        out["still_failing"] = dict(sorted(failing.items()))
    return out


DEFAULT_DYNAMIC_OUT = Path("workspace/reports/harness_reach_dynamic.json")
COVERAGE_DIR = Path("workspace/reports/coverage")
FUZZ_DIR = Path("workspace/reports/fuzz")
DEFAULT_FUZZ_DIR = FUZZ_DIR
DEFAULT_HARNESSES = DEFAULT_HARNESS_DIR
_COVERAGE_OK = ("ok", "partial")
_UNKNOWN_FAILURE_FNS = frozenset({"", "unknown", "unknown_function"})
# Harness code: a failure here happened before or around the call of an entry point, never in one.
_HARNESS_FAILURE_FNS = frozenset({"LLVMFuzzerTestOneInput", "main", DISPATCH_SKIP_FN})
# E-ACSL wraps a function that has a contract in `__gen_e_acsl_<fn>`: it checks the preconditions (and
# evaluates `\old`), calls `<fn>`, then checks the postconditions. Callers call the wrapper. The
# runtime names a contract failure by the source name (`.fct = "<fn>"`, kind Precondition or
# Postcondition); a crash inside the wrapper itself shows the wrapper's name.
_EACSL_WRAPPER_PREFIX = "__gen_e_acsl_"
# A frame of a sanitizer or libFuzzer stack (run_eacsl_fuzz._STACK_FRAME_RE), for C function names
# only: `in fuzzer::Fuzzer::...` is not the function `fuzzer`.
_STACK_FRAME_RE = re.compile(
    r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+(?P<function>[A-Za-z_]\w*)(?![\w:])(?:\s+(?P<file>[^\s():]+):\d+)?"
)
_CRASH_NOTES_MAX = 20


def _module_entries(module: str, dag: dict[str, Any], mm: ModuleMap) -> list[str]:
    """
    The entry points the reach gate holds a harness module to (as `check_module` does): for a sub-module,
    its unit's entry points within its scope (`ModuleMap.scope_entry_points`); for a unit, its DAG
    `candidate_entry_points`, else its non-static functions. All are DAG keys: the plain name, or
    `file#name` when the name collides. A target fuzz module (sidecar `target_fuzzer`) answers for none.
    """
    if isinstance((mm.sidecars.get(module) or {}).get("target_fuzzer"), dict):
        return []
    if mm.units_are_link_units and mm.unit_of(module) != module:
        return built_entries(mm.scope_entry_points(module), dag.get("functions") or {})
    info = (dag.get("modules") or {}).get(module) or {}
    entries = [f for f in info.get("candidate_entry_points") or [] if isinstance(f, str)]
    if not entries:
        by_name = _functions_by_name(dag)
        fns = [f for f in info.get("functions") or [] if isinstance(f, str)]
        entries = [f for f in fns if not any(r.get("is_static") for _, r in by_name.get(f) or [])]
    return built_entries(entries, dag.get("functions") or {})


def _executions(coverage: dict[str, Any]) -> dict[str, list[tuple[str, int]]]:
    """Function name -> [(file, executions)] of a coverage report."""
    out: dict[str, list[tuple[str, int]]] = {}
    for row in coverage.get("functions") or []:
        if isinstance(row, dict) and isinstance(row.get("function"), str):
            out.setdefault(row["function"], []).append((str(row.get("file") or ""), int(row.get("executions") or 0)))
    return out


def _entry_executions(key: str, dag: dict[str, Any], runs: dict[str, list[tuple[str, int]]]) -> int | None:
    """Executions of a DAG function in the coverage report, or None when the report does not list it."""
    rec = (dag.get("functions") or {}).get(key) or {}
    name = str(rec.get("name") or key.rpartition("#")[2])
    rows = runs.get(name)
    if not rows:
        return None
    file_ = str(rec.get("file") or (key.partition("#")[0] if "#" in key else "")).replace("\\", "/")
    if file_ and len(rows) > 1:
        rows = [r for r in rows if r[0].replace("\\", "/").endswith(file_)] or rows
    return sum(n for _, n in rows)


def _normalize_failure_fn(raw: object) -> str:
    """The source name a failure function stands for ("" when unknown); harness names stay as they are."""
    if not isinstance(raw, str):
        return ""
    name = raw.strip().removeprefix(_EACSL_WRAPPER_PREFIX)
    return "" if name in _UNKNOWN_FAILURE_FNS else name


def _is_harness_function(name: str) -> bool:
    return name in _HARNESS_FAILURE_FNS or name.startswith(TARGET_EMBEDDED_PREFIX)


def _artifact_failure(art: dict[str, Any], frames: list[tuple[str, str]]) -> tuple[str, str, bool, bool]:
    """
    (function, file, in_harness, before_body) of an artifact's failure (its own, else the sanitizer
    replay's attribution). `function` is the source name, "" when unknown. `in_harness`: the failure is
    in the harness's own code (`LLVMFuzzerTestOneInput`, the runtime skip helper, an embedded target
    fuzzer hook, or a `harness_*` file), so no entry point was running. `before_body`: the failure may be
    in the E-ACSL wrapper of `function` before it called the body: a Precondition; any other failure
    but a Postcondition reported in `__gen_e_acsl_<function>`; or one reported under the source name
    (the wrapper's own RTE checks, e.g. `\\initialized` of a formal before the call, carry
    `.fct = "<function>"`) while the replay's stack (`frames`) holds the wrapper and no frame of the
    body. The wrapper's checks before the call cannot be told from those after it, so none counts.
    """
    raw = art.get("failure")
    if not isinstance(raw, dict):
        attr = art.get("attribution")
        raw = attr.get("failure") if isinstance(attr, dict) else None
    if not isinstance(raw, dict):
        return "", "", False, False
    raw_fn = str(raw.get("function") or "").strip()
    file_ = str(raw.get("file") or "")
    kind = str(raw.get("kind") or "").strip().lower()
    in_harness = _is_harness_function(raw_fn) or Path(file_.replace("\\", "/")).name.startswith("harness_")
    fn = _normalize_failure_fn(raw_fn)
    on_stack = {f for f, _ in frames}
    in_wrapper = raw_fn.startswith(_EACSL_WRAPPER_PREFIX) or (
        bool(fn) and _EACSL_WRAPPER_PREFIX + fn in on_stack and fn not in on_stack
    )
    before_body = kind == "precondition" or (in_wrapper and kind != "postcondition")
    return fn, file_, in_harness, before_body


def _artifact_frames(art: dict[str, Any]) -> list[tuple[str, str]]:
    """
    (function, file) of every stack frame the artifact's replay printed: the `frames` a campaign records
    (run_eacsl_fuzz.stack_frames), else those in `replay_log_tail` (reports written before `frames`;
    the tail keeps the last 3000 characters, so inner frames may be missing). Names stay exact: a
    `__gen_e_acsl_<fn>` frame is E-ACSL's wrapper, which proves its caller ran, not `<fn>`.
    """
    frames = art.get("frames")
    if isinstance(frames, list) and frames:
        return [
            (f["function"], str(f.get("file") or ""))
            for f in frames
            if isinstance(f, dict) and isinstance(f.get("function"), str)
        ]
    tail = art.get("replay_log_tail")
    if not isinstance(tail, str):
        return []
    return [(m.group("function"), m.group("file") or "") for m in _STACK_FRAME_RE.finditer(tail)]


def _fn_matches_entry(
    fn_name: str,
    fn_file: str,
    ep: str,
    module: str,
    dag: dict[str, Any],
    by_name: dict[str, list[tuple[str, dict[str, Any]]]],
) -> bool:
    if not fn_name:
        return False
    if fn_name == ep:
        return True
    functions = dag.get("functions") or {}
    rec = functions.get(ep) or {}
    ep_plain = str(rec.get("name") or ep.rpartition("#")[2])
    if fn_name != ep_plain:
        return False
    defs = by_name.get(ep_plain) or []
    if len(defs) <= 1:
        return True
    ep_file = str(rec.get("file") or (ep.partition("#")[0] if "#" in ep else "")).replace("\\", "/")
    norm_file = fn_file.replace("\\", "/") if fn_file and fn_file != "unknown" else ""
    if norm_file and ep_file:
        return norm_file.endswith(ep_file) or ep_file.endswith(norm_file)
    return [k for k, r in defs if r.get("module") == module] == [ep]


def _entry_callee_closure(
    ep: str,
    module: str,
    dag: dict[str, Any],
    by_name: dict[str, list[tuple[str, dict[str, Any]]]],
) -> tuple[set[str], set[str]]:
    """Transitive DAG keys and function names reachable from `ep` across direct and indirect callee edges."""
    functions = dag.get("functions") or {}
    reached_keys: set[str] = set()
    reached_names: set[str] = set()
    work: list[str] = [ep]
    while work:
        cur = work.pop()
        if cur in reached_keys:
            continue
        if isinstance(functions.get(cur), dict):
            recs = [(cur, functions[cur])]
        else:
            all_recs = by_name.get(cur) or []
            same_mod = [kr for kr in all_recs if kr[1].get("module") == module]
            recs = same_mod or all_recs
            if not recs:
                reached_names.add(cur)
                continue
        for key, rec in recs:
            if key in reached_keys:
                continue
            reached_keys.add(key)
            plain = str(rec.get("name") or key.rpartition("#")[2])
            reached_names.add(key)
            reached_names.add(plain)
            for edge_field in ("internal_callees", "callees", "indirect_callees"):
                for callee in rec.get(edge_field) or []:
                    if isinstance(callee, str) and callee not in reached_keys:
                        work.append(callee)
    return reached_keys, reached_names


def _candidate_roots(*paths: Path | None) -> list[Path]:
    roots: list[Path] = []
    seen: set[str] = set()
    for base in (Path("."), *paths):
        if base is None:
            continue
        cur = Path(base)
        for cand in (cur, cur.parent, cur.parent.parent, cur.parent.parent.parent):
            key = str(cand)
            if key not in seen:
                seen.add(key)
                roots.append(cand)
    return roots


def _artifact_first_byte(raw_path: object, roots: list[Path]) -> int | None:
    if not isinstance(raw_path, str) or not raw_path.strip():
        return None
    rel = Path(raw_path.strip())
    candidates = [rel] if rel.is_absolute() else [rel, *(r / rel for r in roots)]
    for cand in candidates:
        if not cand.is_file():
            continue
        try:
            with cand.open("rb") as fh:
                first = fh.read(1)
            return first[0] if first else None
        except OSError:
            continue
    return None


def _reproducible_fuzz_artifacts(fuzz_report: dict[str, Any]) -> list[dict[str, Any]]:
    raw_list: list[Any] = []
    top = fuzz_report.get("artifacts")
    if isinstance(top, list) and top:
        raw_list.extend(top)
    elif isinstance(fuzz_report.get("engines"), dict):
        for eng_val in fuzz_report["engines"].values():
            if isinstance(eng_val, dict) and isinstance(eng_val.get("artifacts"), list):
                raw_list.extend(eng_val["artifacts"])
    out: list[dict[str, Any]] = []
    for art in raw_list:
        # Only a replay that reproduced the crash: a missing or null verdict (not replayed) is not one.
        if not isinstance(art, dict) or art.get("reproducible") is not True:
            continue
        kind = art.get("kind")
        if isinstance(kind, str) and kind and kind not in ("crash", "leak"):
            continue
        out.append(art)
    return out


def _single_case_target(case: dict[str, Any]) -> str:
    if case.get("kind") != "single":
        return ""
    for field in ("entry", "function"):
        val = case.get(field)
        if isinstance(val, str) and val.strip():
            return val.strip()
    calls = case.get("calls")
    if isinstance(calls, list) and len(calls) == 1 and isinstance(calls[0], str) and calls[0].strip():
        return calls[0].strip()
    return ""


def _case_count(raw: object) -> int | None:
    """A dispatch case count as the sidecar and the fuzz report record it; None for no dispatch."""
    return raw if isinstance(raw, int) and not isinstance(raw, bool) and raw > 0 else None


def _artifact_identity_problem(
    art: dict[str, Any],
    stamped_report: bool,
    legacy_problem: str | None,
    harness_digest: str | None,
    n_cases: int | None,
    first_byte: int | None,
) -> str | None:
    """
    Why a crash artifact cannot speak for the current harness, or None. A stamped artifact must carry
    the current `harness_digest` and `dispatch_case_count` (run_eacsl_fuzz.stamp_harness_identity).
    Its own count only explains the mismatch: the case its first byte selected then and selects now.
    An artifact without them counts only in a report written before the fields existed and after the
    harness last changed (`legacy_problem` is None).
    """
    if "harness_digest" in art and "dispatch_case_count" in art:
        found_n = _case_count(art.get("dispatch_case_count"))
        if found_n != n_cases:

            def _under(n: int | None) -> str:
                if n is None:
                    return "a harness without dispatch cases"
                case = f", case {first_byte % n}" if first_byte is not None else ""
                return f"{n} dispatch cases{case}"

            return f"found under {_under(found_n)}; the harness now has {_under(n_cases)}"
        if harness_digest is None or art.get("harness_digest") != harness_digest:
            return "found under another harness (harness_digest differs)"
        return None
    if stamped_report:
        return "carried over from an earlier campaign without a harness digest"
    return legacy_problem


def _in_closure(
    fn: str, fn_file: str, closure: tuple[set[str], set[str]], module: str, dag: dict[str, Any], by_name: dict
) -> bool:
    keys, names = closure
    return any(_fn_matches_entry(fn, fn_file, k, module, dag, by_name) for k in keys) or (
        fn in names and not by_name.get(fn)
    )


def _crashed_entry_points(
    module: str,
    candidates: list[str],
    dag: dict[str, Any],
    sidecar: dict[str, Any],
    fuzz_dir: Path | None,
    roots: list[Path],
    *,
    harness_digest: str | None = None,
    harness_file: Path | None = None,
) -> tuple[list[str], list[str]]:
    """
    The `candidates` that reproducible crashes of the module's fuzz report prove executed under the
    current harness, and notes on the crashes that proved nothing (for the dynamic row's `crash_notes`).

    Only an artifact found under the current harness (`_artifact_identity_problem`) counts. It proves an
    entry point ran when:

    - a frame of its replay's stack is the entry point (`_artifact_frames`; exact names);
    - its failure is in the entry point itself, after the body started (not an E-ACSL precondition or
      wrapper failure, `_artifact_failure`);
    - its input selects a `single` dispatch case of the entry point (first byte modulo the current case
      count) and the failure is in the entry's callee closure but in none of the case's init helpers'
      closures (they run before the entry), or the failure is unknown and the case has no init helper.
      A `custom` or `sequence` case calls several functions in an order the sidecar does not record, so
      only the first two kinds of evidence credit it.

    A failure in the harness's own code (`LLVMFuzzerTestOneInput`, a `harness_*` file) credits nothing.
    """
    if not candidates or fuzz_dir is None:
        return [], []
    report_path = Path(fuzz_dir) / f"{module}.json"
    try:
        fuzz_report = load_json_optional(report_path, None)
    except (ArtifactError, OSError, ValueError):
        return [], []
    if not isinstance(fuzz_report, dict):
        return [], []
    artifacts = _reproducible_fuzz_artifacts(fuzz_report)
    if not artifacts:
        return [], []

    by_name = _functions_by_name(dag)
    n_cases = _case_count(sidecar.get("dispatch_case_count"))
    raw_cases = sidecar.get("api_cases")
    api_cases = raw_cases if isinstance(raw_cases, list) and n_cases else []
    stamped_report = "harness_digest" in fuzz_report
    legacy_problem: str | None = None
    if not stamped_report:
        try:
            if harness_file is None or report_path.stat().st_mtime <= Path(harness_file).stat().st_mtime:
                legacy_problem = "the fuzz report has no harness digest and is older than the harness"
        except OSError:
            legacy_problem = "the fuzz report has no harness digest and the harness file cannot be read"

    closures: dict[str, tuple[set[str], set[str]]] = {}

    def closure(fn: str) -> tuple[set[str], set[str]]:
        if fn not in closures:
            closures[fn] = _entry_callee_closure(fn, module, dag, by_name)
        return closures[fn]

    proven: set[str] = set()
    notes: list[str] = []
    for art in artifacts:
        if len(proven) == len(candidates):
            break
        raw_path = art.get("artifact") or art.get("path")
        name = Path(str(raw_path)).name if raw_path else "artifact"
        first_byte = _artifact_first_byte(raw_path, roots)
        problem = _artifact_identity_problem(
            art, stamped_report, legacy_problem, harness_digest, n_cases, first_byte
        )
        if problem:
            notes.append(f"{name}: not used ({problem})")
            continue
        frames = _artifact_frames(art)
        fn, fn_file, in_harness, before_body = _artifact_failure(art, frames)
        credited = False
        for ep in candidates:
            if ep in proven:
                continue
            in_body = bool(fn) and not in_harness and not before_body
            if any(_fn_matches_entry(f, f_file, ep, module, dag, by_name) for f, f_file in frames) or (
                in_body and _fn_matches_entry(fn, fn_file, ep, module, dag, by_name)
            ):
                proven.add(ep)
                credited = True
        if in_harness or not api_cases or first_byte is None or n_cases is None:
            continue
        idx = first_byte % n_cases
        case = api_cases[idx] if idx < len(api_cases) and isinstance(api_cases[idx], dict) else {}
        kind = str(case.get("kind") or "")
        if kind in ("custom", "sequence"):
            if credited or (fn and any(_fn_matches_entry(fn, fn_file, e, module, dag, by_name) for e in proven)):
                continue  # this crash, or another, proved the entry point it shows: nothing unexplained
            where = f"in {fn}" if fn else "at an unknown location"
            notes.append(
                f"{name}: {kind} case {idx} crashed {where}; a {kind} case is credited only for a failure "
                "in the entry point itself or a frame of it"
            )
            continue
        target = _single_case_target(case)
        case_ep = next((e for e in candidates if _fn_matches_entry(target, "", e, module, dag, by_name)), None)
        if case_ep is None or case_ep in proven:
            continue
        ep = case_ep
        inits = [i.get("fn") if isinstance(i, dict) else i for i in case.get("inits") or []]
        init_fns = [i for i in inits if isinstance(i, str) and i]
        if not fn:
            if not init_fns:
                proven.add(ep)
            continue
        if _fn_matches_entry(fn, fn_file, ep, module, dag, by_name) or not _in_closure(
            fn, fn_file, closure(ep), module, dag, by_name
        ):
            continue  # in the entry itself only before its body ran (handled above), or outside it
        shared = [i for i in init_fns if _in_closure(fn, fn_file, closure(i), module, dag, by_name)]
        if shared:
            notes.append(
                f"{name}: single case {idx} ({target}) crashed in {fn}, which its init helper "
                f"{', '.join(shared)} also reaches"
            )
            continue
        proven.add(ep)
    if len(notes) > _CRASH_NOTES_MAX:
        notes = [*notes[:_CRASH_NOTES_MAX], f"... and {len(notes) - _CRASH_NOTES_MAX} more"]
    return sorted(proven), notes


def _load_module_sidecar(module: str, mm: ModuleMap, harnesses_dir: Path | None) -> dict[str, Any]:
    if harnesses_dir is not None:
        try:
            loaded = load_json_optional(Path(harnesses_dir) / f"harness_{module}.json", None)
        except (ArtifactError, OSError, ValueError):
            loaded = None
        if isinstance(loaded, dict):
            return loaded
    in_map = mm.sidecars.get(module)
    if isinstance(in_map, dict) and in_map:
        return in_map
    try:
        fallback = load_json_optional(DEFAULT_HARNESS_DIR / f"harness_{module}.json", None)
    except (ArtifactError, OSError, ValueError):
        fallback = None
    return fallback if isinstance(fallback, dict) else {}


def check_dynamic(
    module: str,
    dag: dict[str, Any],
    mm: ModuleMap,
    coverage: dict[str, Any],
    fuzz_dir: Path | None = None,
    harnesses_dir: Path | None = None,
    *,
    harness_dir: Path | None = None,
    static_gaps: set[str] | list[str] | None = None,
) -> dict[str, Any]:
    """
    The dynamic reach row of a harness module: its gate entry points the corpus never executed, minus
    those its sidecar exempts or that reproducible fuzz crashes of the current harness already proved
    executed (`_crashed_entry_points`; `crash_notes` says why the others proved nothing). An entry point
    the coverage build does not list (a header inline function no translation unit instantiated) counts
    as never executed unless proven by a fuzz crash.
    """
    resolved_hdir = harnesses_dir if harnesses_dir is not None else harness_dir
    sidecar = _load_module_sidecar(module, mm, resolved_hdir)
    raw = sidecar.get("reach_exempt")
    exempt = {str(k): str(v) for k, v in raw.items()} if isinstance(raw, dict) else {}
    match = exemption_matcher(exempt, dag.get("functions") or {})
    static_gap_set = set(static_gaps) if static_gaps is not None else set()
    runs = _executions(coverage)
    executed: dict[str, int] = {}
    unexecuted: list[str] = []
    for e in _module_entries(module, dag, mm):
        n = _entry_executions(e, dag, runs) or 0
        executed[e] = n
        if not n and match(e) is None:
            unexecuted.append(e)
    crash_candidates = [e for e in unexecuted if e not in static_gap_set]
    hdir = Path(resolved_hdir or DEFAULT_HARNESS_DIR)
    # The run directory the harness directory lives in: the campaign stamps phase0_gates' digest of it.
    run_dir = hdir.parent.parent if hdir.parts[-2:] == tuple(Path(DEFAULT_HARNESS_DIR).parts) else Path(".")
    crashed, crash_notes = _crashed_entry_points(
        module,
        crash_candidates,
        dag,
        sidecar,
        fuzz_dir,
        _candidate_roots(fuzz_dir, hdir),
        harness_digest=phase0_gates.harness_digest(run_dir, module, ignore_exempt=True),
        harness_file=hdir / f"harness_{module}.c",
    )
    crashed_set = set(crashed)
    never = [e for e in unexecuted if e not in crashed_set]
    row: dict[str, Any] = {
        "module": module,
        "mode": "dynamic",
        "coverage_status": coverage.get("status"),
        "corpus_inputs": (coverage.get("inputs") or {}).get("replayed"),
        "entry_points": len(executed),
        "entry_points_executed": sum(1 for n in executed.values() if n) + len(crashed),
        "crashed_entry_points": crashed,
        "executions": dict(sorted(executed.items())),
        "gaps": never,
        "passed": not never,
    }
    if crash_notes and never:
        # Why the crashes of the fuzz report did not close these gaps.
        row["crash_notes"] = crash_notes
    if failed_inputs := _input_count(coverage, "failed"):
        # Every input was replayed and only these crashed (crash candidates already): the reach stands.
        row["failed_inputs"] = failed_inputs
    return row


def _input_count(coverage: dict[str, Any], key: str) -> int:
    """`inputs.<key>` of a coverage report (total, replayed, failed, not_replayed), 0 when absent."""
    inputs = coverage.get("inputs")
    try:
        return max(0, int((inputs or {}).get(key) or 0)) if isinstance(inputs, dict) else 0
    except (TypeError, ValueError):
        return 0


def partial_coverage_reason(coverage: dict[str, Any]) -> str | None:
    """
    Why a coverage report cannot decide the dynamic gate, or None. Inputs the replay never ran
    (`inputs.not_replayed`) make every gap a lower bound (QCBOR run-4: 1,971 of 2,240 inputs not replayed,
    76 "gaps"), so the module is unmeasured, not failed.
    """
    missing = _input_count(coverage, "not_replayed")
    if not missing:
        return None
    total = _input_count(coverage, "total")
    return f"partial coverage: {missing} of {total or '?'} inputs not replayed"


def _static_gaps_by_module(dag_path: Path) -> dict[str, set[str]]:
    try:
        static_doc = load_json_optional(dag_path.parent / "harness_reach.json", None)
    except (ArtifactError, OSError, ValueError):
        return {}
    if not isinstance(static_doc, dict) or not isinstance(static_doc.get("modules"), list):
        return {}
    out: dict[str, set[str]] = {}
    for row in static_doc["modules"]:
        if not isinstance(row, dict) or str(row.get("error") or "").startswith("dynamic:"):
            continue
        mod = row.get("module")
        gaps = row.get("gaps")
        if isinstance(mod, str) and isinstance(gaps, list) and gaps:
            out[mod] = {g for g in gaps if isinstance(g, str)}
    return out


def run_dynamic(
    dag_path: Path,
    harness_dir: Path = DEFAULT_HARNESS_DIR,
    modules: list[str] | None = None,
    coverage_dir: Path = COVERAGE_DIR,
    fuzz_dir: Path | None = None,
    *,
    harnesses_dir: Path | None = None,
) -> dict[str, Any]:
    resolved_hdir = harnesses_dir if harnesses_dir is not None else harness_dir
    dag = load_json_strict(dag_path)
    if not isinstance(dag, dict):
        raise ValueError(f"{dag_path}: not a call-graph DAG object")
    mm = ModuleMap(dag, load_sidecars(resolved_hdir))
    static_gaps = _static_gaps_by_module(dag_path)
    rows: list[dict[str, Any]] = []
    for module in modules or sorted(mm.sidecars):
        cov = load_json_optional(coverage_dir / f"{module}.json", None)
        if not isinstance(cov, dict) or cov.get("status") not in _COVERAGE_OK:
            status = cov.get("status") if isinstance(cov, dict) else "missing"
            rows.append({"module": module, "mode": "dynamic", "passed": None, "error": f"no coverage ({status})"})
            continue
        row = check_dynamic(
            module,
            dag,
            mm,
            cov,
            fuzz_dir=fuzz_dir,
            harnesses_dir=resolved_hdir,
            static_gaps=static_gaps.get(module),
        )
        if (reason := partial_coverage_reason(cov)) is not None:
            # Keep what was measured for the reader; the gaps are only a lower bound and decide nothing.
            row.update(passed=None, error=reason, gaps_lower_bound=row.pop("gaps"))
        rows.append(row)
    crashed_total = sum(len(r.get("crashed_entry_points") or []) for r in rows if r.get("passed") is not None)
    return {
        "generated_at": utc_now(),
        "dag": str(dag_path).replace("\\", "/"),
        "entry_points_crashed": crashed_total,
        "modules": rows,
    }


def record_dynamic(
    run_dir: Path,
    report: dict[str, Any],
    out: Path,
    dag_path: Path | None = None,
    harness_dir: Path | None = None,
) -> None:
    """
    Merge the rows into the dynamic report (with each module's harness digest) and reopen the reach
    gate of every module with a gap. A module without a gap, or unmeasured now, gets the gate the static
    check gives it: its row from an earlier dynamic run is dropped, and a gate an earlier dynamic run
    failed is checked again (`_restore_static_gate`).
    """
    from validate_artifacts import schema_warning

    measured = {
        # Without `reach_exempt`: an exemption recorded later is not a repaired harness (`apply_dynamic`).
        row["module"]: {
            **row,
            "harness_digest": phase0_gates.harness_digest(run_dir, row["module"], ignore_exempt=True),
        }
        for row in report["modules"]
        if row.get("passed") is not None
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    # Make runs one `dynamic --module <m>` per module in parallel: merge under the lock, or the last
    # writer drops the rows the others stored (cryptolib r2v lost `sa`).
    with run_lock("harness_reach_dynamic", run_dir):
        prior = load_json_optional(out, {})
        by_module = dict((prior or {}).get("modules") or {}) if isinstance(prior, dict) else {}
        unmeasured = dict((prior or {}).get("unmeasured") or {}) if isinstance(prior, dict) else {}
        for row in report["modules"]:
            if row.get("passed") is None:
                unmeasured[row["module"]] = str(row.get("error") or "no coverage")
                # A row an earlier run measured would keep its gaps failing at `check` (apply_dynamic).
                by_module.pop(row["module"], None)
            else:
                unmeasured.pop(row["module"], None)
                by_module[row["module"]] = measured[row["module"]]
        crashed_total = sum(len(m.get("crashed_entry_points") or []) for m in by_module.values() if isinstance(m, dict))
        doc: dict[str, Any] = {
            "generated_at": report["generated_at"],
            "entry_points_crashed": crashed_total,
            "modules": dict(sorted(by_module.items())),
        }
        if unmeasured:
            doc["unmeasured"] = dict(sorted(unmeasured.items()))
        problem = schema_warning("harness_reach_dynamic", doc)  # R5: recorded, `validate_artifacts run-dir` fails on it
        if problem:
            doc["warnings"] = [problem]
        atomic_write_json(out, doc)
    failed = [r for r in report["modules"] if r.get("passed") is False]
    if failed:
        rows = [{**r, "error": DYNAMIC_GAP_ERROR} for r in failed]
        phase0_gates.record_reach(run_dir, {"modules": rows}, partial=True, dag_path=dag_path)
    cleared = [str(r["module"]) for r in report["modules"] if r.get("passed") is not False]
    _restore_static_gate(run_dir, cleared, out, dag_path, harness_dir)


DYNAMIC_GAP_ERROR = phase0_gates.DYNAMIC_GAP_ERROR


def _restore_static_gate(
    run_dir: Path, modules: list[str], dynamic_path: Path, dag_path: Path | None, harness_dir: Path | None
) -> None:
    """
    Re-run the static check for each of `modules` whose reach gate an earlier dynamic run failed: the
    corpus now executes every entry point, or the new measurement cannot decide (unmeasured), so the
    old dynamic failure no longer stands. Without this, a module that moved from failed to unmeasured
    kept the stale failure until someone re-ran `reach-gate` by hand.
    """
    reach = phase0_gates.load_gates(run_dir).get("reach")
    rows = reach.get("modules") if isinstance(reach, dict) else None
    if not isinstance(rows, dict):
        return
    stale = [m for m in modules if str((rows.get(m) or {}).get("error") or "").startswith("dynamic:")]
    if not stale:
        return
    dag_file = Path(dag_path) if dag_path is not None else run_dir / DEFAULT_DAG
    hdir = Path(harness_dir) if harness_dir is not None else run_dir / DEFAULT_HARNESS_DIR
    try:
        report = run_check(dag_file, hdir, stale, run_dir=run_dir)
        dag = load_json_strict(dag_file)
    except (ArtifactError, OSError, ValueError):
        return  # no DAG to check against: the failure stays until `reach-gate` runs
    report["modules"] = [r for r in report["modules"] if r.get("module") in stale]
    apply_dynamic(report, dynamic_path, hdir, run_dir, dag=dag if isinstance(dag, dict) else {})
    phase0_gates.record_reach(run_dir, report, partial=True, dag_path=dag_file)


def apply_dynamic(
    report: dict[str, Any],
    dynamic_path: Path,
    harness_dir: Path,
    run_dir: Path,
    dag: dict[str, Any] | None = None,
) -> None:
    """
    Keep a dynamic gap failing at the static check while the harness is the one coverage measured (same
    digest) and the entry point is not exempted since: a repaired harness or an exemption clears it.
    Exemptions match as in the static check (`exemption_matcher`), against `dag` (default: the
    report's own DAG).
    """
    dyn = load_json_optional(dynamic_path, {})
    rows = dyn.get("modules") if isinstance(dyn, dict) else None
    if not isinstance(rows, dict):
        return
    if dag is None:
        loaded = load_json_optional(Path(str(report.get("dag") or DEFAULT_DAG)), {})
        dag = loaded if isinstance(loaded, dict) else {}
    functions = dag.get("functions") or {}
    for row in report["modules"]:
        d = rows.get(row.get("module"))
        if not isinstance(d, dict) or not d.get("gaps") or not row.get("passed"):
            continue
        # The row's digest leaves `reach_exempt` out, so an exemption clears only the gaps it names. A
        # row written before that (digest of the whole sidecar) still matches while nothing changed.
        name = str(row["module"])
        current = (
            phase0_gates.harness_digest(run_dir, name, ignore_exempt=True),
            phase0_gates.harness_digest(run_dir, name),
        )
        if d.get("harness_digest") not in current:
            continue
        sidecar = load_json_optional(harness_dir / f"harness_{row['module']}.json", {})
        raw = sidecar.get("reach_exempt") if isinstance(sidecar, dict) else None
        exempt = {str(k): str(v) for k, v in raw.items()} if isinstance(raw, dict) else {}
        match = exemption_matcher(exempt, functions)
        gaps = [g for g in d["gaps"] if match(g) is None]
        if gaps:
            row.update(passed=False, gaps=gaps, error=DYNAMIC_GAP_ERROR)
    report["passed"] = all(r.get("passed") for r in report["modules"])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Phase 0 harness reachability gate.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_check = sub.add_parser("check", help="Gate every harnessed module against its DAG entry points")
    p_check.add_argument("--dag", type=Path, default=DEFAULT_DAG)
    p_check.add_argument("--harness-dir", "--harnesses", dest="harness_dir", type=Path, default=DEFAULT_HARNESS_DIR)
    p_check.add_argument("--module", action="append", default=[], help="Limit to this module (repeatable)")
    p_check.add_argument("--out", type=Path, default=DEFAULT_OUT, help="Report path ('-' for stdout only)")
    p_ex = sub.add_parser("exempt", help="Record why an entry point cannot be harnessed")
    p_ex.add_argument("--harness-dir", "--harnesses", dest="harness_dir", type=Path, default=DEFAULT_HARNESS_DIR)
    p_ex.add_argument("--dag", type=Path, default=DEFAULT_DAG, help="To place a link unit's exemption")
    p_ex.add_argument("--module", required=True)
    p_ex.add_argument(
        "--function",
        action="append",
        default=[],
        help="Entry point to exempt (repeatable, one reason for all); omit to exempt a module without a harness",
    )
    p_ex.add_argument("--reason", required=True)
    p_dyn = sub.add_parser("dynamic", help="Reopen the gate for entry points the corpus never executed")
    p_dyn.add_argument("--dag", type=Path, default=DEFAULT_DAG)
    p_dyn.add_argument("--harness-dir", "--harnesses", dest="harness_dir", type=Path, default=DEFAULT_HARNESS_DIR)
    p_dyn.add_argument("--coverage-dir", type=Path, default=COVERAGE_DIR)
    p_dyn.add_argument("--fuzz-dir", type=Path, default=FUZZ_DIR)
    p_dyn.add_argument("--module", action="append", default=[], help="Harness module (repeatable; default all)")
    p_dyn.add_argument("--out", type=Path, default=DEFAULT_DYNAMIC_OUT)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.cmd == "dynamic":
            dyn = run_dynamic(args.dag, args.harness_dir, args.module, args.coverage_dir, fuzz_dir=args.fuzz_dir)
            record_dynamic(Path("."), dyn, args.out, dag_path=args.dag, harness_dir=args.harness_dir)
            print(json.dumps(dyn, indent=2))
            if any(r.get("passed") is None for r in dyn["modules"]):
                return 2
            return 0 if all(r.get("passed") for r in dyn["modules"]) else 1
        if args.cmd == "exempt":
            if not args.reason.strip():
                raise ValueError("--reason must not be empty")
            recorded: dict[str, Any] = {}
            for fn in args.function or [None]:
                recorded = record_exempt(args.harness_dir, args.module, fn, args.reason.strip(), args.dag)
            if len(args.function) > 1:
                recorded["function"] = list(args.function)
            # The gate reads recorded rows, and the sidecar just changed: re-record them here, so no
            # target stops at a stale row until someone runs `reach-gate`.
            recorded["gate"] = regate_after_exempt(Path("."), args.dag, args.harness_dir, args.module)
            print(json.dumps(recorded, indent=2))
            return 0
        report = run_check(args.dag, args.harness_dir, args.module)
        apply_dynamic(report, DEFAULT_DYNAMIC_OUT, args.harness_dir, Path("."))
    except (ArtifactError, OSError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        return 2
    if str(args.out) != "-":
        args.out.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(args.out, report)
        # The gate stamp the Make recipes check (phase0_gates.py), with the digest of the DAG checked
        # against, so a DAG rebuilt afterwards fails the gate; `--out -` is a dry look.
        phase0_gates.record_reach(Path("."), report, partial=bool(args.module), dag_path=args.dag)
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
