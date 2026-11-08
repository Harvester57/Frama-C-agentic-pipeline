#!/usr/bin/env python3
"""
Drives Frama-C Eva + RTE on a module slice, parses the resulting property status
table (alarms.csv) into Valid (Green), Unknown (Orange), Invalid (Red), Dead
(unreachable under the harness) and Assumed ("Considered valid") buckets,
extracts the surviving 'Unknown' functions for Phase 3 (/framac-wp), and emits SARIF.
A failed Frama-C run is reported as status "analysis_error", never as zero alarms.

Inside a run directory, a report with status "ok" is cached (scripts/cache.py, namespace `eva`)
under the toolchain, the Eva command line (with the output directory factored out, so the same
analysis is one entry wherever it writes) and the content of every source and header it includes;
an identical later run restores the report, alarms.csv, red_alarms.csv, eva.log, slice.sarif,
flows.log, flamegraph.txt and nonterm.log instead of re-running Eva (the .sav is not cached).

Every run also writes flamegraph.txt (-eva-flamegraph, render it with `pipeline_make.py run
flamegraph-<mod>` or scripts/eva_flamegraph.py when a run is slow) and runs the nonterm plug-in
(-nonterm -nonterm-log), whose warnings land in the report as `nonterm`. The report's
`repair_hints` field ports upstream make-wrapper's log patterns (recursive call without assigns,
called function with neither code nor specification) into pipeline actions.

Tuning comes in two forms, both recorded in the report: `--eva-option name=value`, allowlisted by
eva_options.py, and `--loop-unroll file#function#ordinal=N`, which analyses a scratch mirror of the
sources (eva_loops.py) and maps its paths back, so workspace/work is never touched.

Inside a run directory with a Phase 0 gate stamp (workspace/reports/phase0_gates.json), a run for
`--module M` first checks M's reach gate (phase0_gates.py check --module M --need reach) and refuses
to run, exit 1 and no report, when M failed it or its harness or the DAG changed since: guidance-mode
runs never analyse a harness the gate stopped, as the Make recipes never do.

After a successful run, read and write sets are taken from the saved session in a separate
Frama-C process (`-load framac.sav -deps -inout -input -out-external -cg`), so they can neither
change Eva's status nor its timing. The report carries them as `flows`, by kernel function name:
hints about this harness, used for the provers' briefs (function_facts.py), never a verdict.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import subprocess
import sys
import time
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path

_KERNEL_ERR_RE = re.compile(
    r"^(?:\[kernel[^\]]*\]|[^:\n]+:\d+:).*?(?:user error|syntax error|fatal error|error:|unbound logic|invalid).*$",
    re.IGNORECASE | re.MULTILINE,
)


def extract_error_summary(log_text: str, max_lines: int = 20) -> list[str]:
    """Extract concise kernel/preprocessor error lines from a Frama-C log."""
    matches = [m.group(0).strip() for m in _KERNEL_ERR_RE.finditer(log_text or "")]
    if matches:
        return matches[:max_lines]
    tail = [line.strip() for line in (log_text or "").splitlines() if line.strip()]
    return tail[-max_lines:]


sys.path.insert(0, str(Path(__file__).resolve().parent))

import cache  # noqa: E402
import phase0_gates  # noqa: E402
from eva_loops import LoopRef, parse_loop_ref, prepare_mirror, strip_mirror  # noqa: E402
from eva_options import extra_domains as option_domains  # noqa: E402
from eva_options import framac_args, options_problem, parse_option  # noqa: E402
from framac_common import (  # noqa: E402
    STATUS_ASSUMED,
    STATUS_DEAD,
    STATUS_INVALID,
    STATUS_INVALID_UNDER_HYP,
    STATUS_NEVER_TRIED,
    STATUS_UNKNOWN,
    STATUS_VALID,
    STATUS_VALID_UNDER_HYP,
    ArtifactError,
    augment_framac_cppflags,
    failure_reason,
    normalize_flag_args,
    read_report_csv,
    scan_undeclared_functions,
)
from resources import CLASSES  # noqa: E402

BASE_DOMAINS = ("cvalue", "equality", "symbolic-locations", "octagon", "gauges")
DEFAULT_AUTO_LOOP_UNROLL = 32
_DOMAIN_RE = re.compile(r"^[a-z][a-z0-9_-]*$")
_C_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)
_PTR_FUNC_DEF_RE = re.compile(
    r"\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*\{",
)
_FUNC_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_FN_PTR_INIT_RE = re.compile(
    r"\(\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\([^;={}]+?\)\s*=\s*&?\s*([A-Za-z_][A-Za-z0-9_]*)\s*;"
)
_BASE_ALLOCATORS = frozenset({"malloc", "calloc", "realloc"})
_MAX_WRAPPER_BODY_LINES = 25


def detect_alloc_wrappers(sources: Iterable[str | Path]) -> list[str]:
    """
    Scan slice C sources for small pointer-returning wrapper functions around `malloc`, `calloc`, or
    `realloc` (including 1-hop static function-pointer tables like `__ares_malloc = default_malloc`).
    Listing these in `-eva-alloc-functions` lets Frama-C Eva's `by_stack` allocation builtin create
    distinct dynamic bases at each wrapper's caller site rather than funneling all allocations through
    the wrapper's single call site.
    """
    fn_bodies: dict[str, set[str]] = {}
    fn_ptr_targets: dict[str, str] = {}
    for src in sources:
        path = Path(src)
        if not path.is_file():
            continue
        try:
            text = _C_COMMENT_RE.sub(" ", path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        for m_ptr in _FN_PTR_INIT_RE.finditer(text):
            fn_ptr_targets[m_ptr.group(1)] = m_ptr.group(2)
        for m_fn in _PTR_FUNC_DEF_RE.finditer(text):
            name = m_fn.group(1)
            if name in _BASE_ALLOCATORS or name in ("if", "while", "for", "switch"):
                continue
            line_start = text.rfind("\n", 0, m_fn.start()) + 1
            prefix = text[line_start : m_fn.start()].strip()
            if prefix and not all(tok.isidentifier() for tok in prefix.split()):
                continue
            brace_start = m_fn.end() - 1
            depth = 0
            end_idx = len(text)
            for idx in range(brace_start, len(text)):
                ch = text[idx]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        end_idx = idx
                        break
            body = text[brace_start + 1 : end_idx]
            if body.count("\n") > _MAX_WRAPPER_BODY_LINES:
                continue
            callees = {c for c in _FUNC_CALL_RE.findall(body) if c != name}
            fn_bodies.setdefault(name, set()).update(callees)

    resolved_bodies: dict[str, set[str]] = {}
    for name, callees in fn_bodies.items():
        expanded = set(callees)
        for callee in list(callees):
            if callee in fn_ptr_targets:
                expanded.add(fn_ptr_targets[callee])
        resolved_bodies[name] = expanded

    known_allocs = set(_BASE_ALLOCATORS)
    wrappers: set[str] = set()
    changed = True
    while changed:
        changed = False
        for name, callees in resolved_bodies.items():
            if name not in wrappers and (callees & known_allocs):
                wrappers.add(name)
                known_allocs.add(name)
                changed = True
    return sorted(wrappers)


# Report files restored from the cache; the .sav is never cached.
_CACHED_OUTPUTS = {
    "alarms.csv": "csv_file",
    "red_alarms.csv": None,
    "eva.log": "log_file",
    "slice.sarif": "sarif_file",
    "flows.log": None,
    "flows.cg.dot": None,
    "flamegraph.txt": "flamegraph_file",
    "nonterm.log": "nonterm_log_file",
}
# The flows step reads a saved session. It decides nothing but hints, so a slow machine loses
# those hints at worst (`flows.status`), and the limit is well above what it takes on real modules.
FLOWS_TIMEOUT_S = 600
_FROM_SECTION_RE = re.compile(
    r"^\[from\] ====== DEPENDENCIES COMPUTED ======$(.*?)^\[from\] ====== END OF DEPENDENCIES ======$",
    re.MULTILINE | re.DOTALL,
)
_FROM_FUNCTION_RE = re.compile(r"^\[from\] Function (\S+?):\s*$")
_FROM_ENTRY_RE = re.compile(r"^(.+?) FROM (.*)$")
_INOUT_HEADER_RE = re.compile(r"^\[inout\] (Out \(external\)|Inputs|InOut \(internal\)) for function (\S+?):\s*$")
_INOUT_SUBSECTIONS = {
    "Operational inputs:": "operational_inputs",
    "Operational inputs on termination:": "operational_inputs_on_termination",
    "Sure outputs:": "sure_outputs",
}
_INOUT_FIELDS = {"Out (external)": "out_external", "Inputs": "inputs"}
_DOT_NODE_RE = re.compile(r'"(?P<id>[^"]+)"\s*\[[^\]]*?label="(?P<label>[^"]+)"', re.DOTALL)
_DOT_EDGE_RE = re.compile(r'"(?P<src>[^"]+)"\s*->\s*"(?P<dst>[^"]+)"')


def split_locations(text: str) -> list[str]:
    """Split Frama-C's `a; b{.x; .y}; c[0..3]` at top-level semicolons, dropping `\\nothing`."""
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    quote = False
    prev = ""
    for ch in text:
        if ch == '"' and prev != "\\":
            quote = not quote
        elif not quote and ch == "{":
            depth += 1
        elif not quote and ch == "}":
            depth = max(0, depth - 1)
        if ch == ";" and depth == 0 and not quote:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
        prev = ch
    parts.append("".join(current))
    cleaned = (" ".join(part.split()) for part in parts)
    return [part for part in cleaned if part and part != "\\nothing"]


def parse_deps_log(log_text: str) -> dict[str, dict]:
    """
    `-deps` output by function: `writes` ({loc, from, and_self}), `result_from`, and whether the
    function has no effects. A continuation line's indent gives how much of the previous
    location it shares (`r.len` then `   .buf[0..4]` is `r.buf[0..4]`).
    """
    out: dict[str, dict] = {}
    section = _FROM_SECTION_RE.search(log_text or "")
    if not section:
        return out
    current: dict | None = None
    entry: dict | None = None
    previous_loc = ""
    pending_loc: str | None = None
    pending_from: list[str] = []

    def _close_entry() -> None:
        nonlocal entry, pending_from
        if entry is None:
            pending_from = []
            return
        text = " ".join(pending_from)
        entry["and_self"] = "(and SELF)" in text
        entry["from"] = split_locations(text.replace("(and SELF)", ""))
        if current is not None:
            if entry["loc"] == "\\result":
                current["result_from"] = entry["from"]
            else:
                current["writes"].append(entry)
        entry, pending_from = None, []

    for line in section.group(1).splitlines():
        m_fn = _FROM_FUNCTION_RE.match(line)
        if m_fn:
            _close_entry()
            current = {"writes": [], "result_from": None, "no_effects": False, "non_terminating": False}
            out[m_fn.group(1)] = current
            previous_loc = ""
            continue
        if current is None or not line.strip():
            continue
        stripped = line.strip()
        if "NO EFFECTS" in stripped:
            _close_entry()
            current["no_effects"] = True
            current["non_terminating"] = "NON TERMINATING" in stripped
            continue
        # A list wraps after a semicolon; any other line without FROM is a location of its own,
        # whose FROM comes on the next line.
        if entry is not None and pending_from and pending_from[-1].rstrip().endswith(";"):
            pending_from.append(stripped)
            continue
        if stripped.startswith("FROM ") and pending_loc is not None:
            entry, pending_loc = {"loc": pending_loc}, None
            pending_from = [stripped[len("FROM ") :]]
            continue
        _close_entry()
        indent = len(line) - len(line.lstrip())
        m_entry = _FROM_ENTRY_RE.match(stripped)
        loc = m_entry.group(1) if m_entry else stripped
        if loc.startswith((".", "[")) and previous_loc:
            loc = previous_loc[: max(0, indent - 2)] + loc
        previous_loc = loc
        if m_entry:
            entry = {"loc": loc}
            pending_from = [m_entry.group(2)]
        else:
            pending_loc = loc
    _close_entry()
    return out


def parse_inout_log(log_text: str) -> dict[str, dict]:
    """`-inout -input -out-external` output by function, each section a list of locations."""
    out: dict[str, dict] = {}
    field: str | None = None
    function: str | None = None
    buffers: dict[tuple[str, str], list[str]] = {}
    for line in (log_text or "").splitlines():
        m_head = _INOUT_HEADER_RE.match(line)
        if m_head:
            function = m_head.group(2)
            field = _INOUT_FIELDS.get(m_head.group(1))
            continue
        if line.startswith("["):
            function, field = None, None
            continue
        if function is None:
            continue
        stripped = line.strip()
        if stripped in _INOUT_SUBSECTIONS:
            field = _INOUT_SUBSECTIONS[stripped]
        elif stripped and field:
            buffers.setdefault((function, field), []).append(stripped)
    for (fn, name), lines in buffers.items():
        out.setdefault(fn, {})[name] = split_locations(" ".join(lines))
    return out


def parse_callgraph_dot(dot_text: str) -> dict[str, list[str]]:
    """Caller -> callees from the Callgraph plug-in's dot file, by function name."""
    labels = {m.group("id"): m.group("label") for m in _DOT_NODE_RE.finditer(dot_text or "")}
    edges: dict[str, set[str]] = defaultdict(set)
    for m in _DOT_EDGE_RE.finditer(dot_text or ""):
        src, dst = labels.get(m.group("src")), labels.get(m.group("dst"))
        if src and dst:
            edges[src].add(dst)
    return {caller: sorted(callees) for caller, callees in sorted(edges.items())}


def collect_flows(sav_path: Path, out_dir: Path, timeout: int = FLOWS_TIMEOUT_S) -> dict:
    """Read and write sets, and Eva-resolved call targets, from a saved Eva session (see module docstring)."""
    log_path = out_dir / "flows.log"
    dot_path = out_dir / "flows.cg.dot"
    cmd = [
        "frama-c",
        "-no-unicode",
        "-load",
        str(sav_path),
        "-deps",
        "-inout",
        "-input",
        "-out-external",
        "-cg",
        str(dot_path),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "reason": f"exceeded {timeout} s", "by_function": {}, "call_edges": {}}
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        return {"status": "failed", "reason": str(exc), "by_function": {}, "call_edges": {}}
    log_text = (proc.stdout or "") + "\n" + (proc.stderr or "")
    log_path.write_text(log_text, encoding="utf-8")
    deps = parse_deps_log(log_text)
    inout = parse_inout_log(log_text)
    if proc.returncode != 0 and not deps:
        return {
            "status": "failed",
            "reason": f"frama-c exited with {proc.returncode}",
            "by_function": {},
            "call_edges": {},
        }
    by_function = {name: {**deps.get(name, {}), **inout.get(name, {})} for name in sorted(set(deps) | set(inout))}
    dot_text = dot_path.read_text(encoding="utf-8", errors="replace") if dot_path.is_file() else ""
    return {"status": "ok", "reason": None, "by_function": by_function, "call_edges": parse_callgraph_dot(dot_text)}


def eva_domains(extra_domains: list[str] | str | None = None, precision: int | None = None) -> str:
    """`-eva-domains` value: the base domains plus extra ones (e.g. `taint`), deduplicated."""
    if isinstance(extra_domains, str):
        extra_domains = extra_domains.split(",")
    if precision is not None and precision < 2:
        domains = ["cvalue"]
    elif precision == 2:
        domains = ["cvalue", "equality", "symbolic-locations"]
    else:
        domains = list(BASE_DOMAINS)
    for raw in extra_domains or []:
        dom = raw.strip()
        if not dom:
            continue
        if not _DOMAIN_RE.match(dom):
            raise ValueError(f"invalid Eva domain name {dom!r}")
        if dom not in domains:
            domains.append(dom)
    return ",".join(domains)


def run_eva_on_slice(
    sources: list[str],
    main_fn: str,
    out_dir: Path,
    machdep: str = "gcc_x86_64",
    cppflags: str = "-I.",
    slevel: int = 100,
    mlevel: int = 0,
    warn_invalid_pointer: bool = True,
    warn_unsigned: bool = True,
    warn_unsigned_downcast: bool = True,
    timeout: int | None = None,
    extra_domains: list[str] | str | None = None,
    allow_incomplete_recursion_specs: bool = False,
    use_cache: bool = True,
    eva_options: dict | None = None,
    loop_unroll: Iterable[LoopRef] | None = None,
    mirror_root: str | None = None,
) -> dict:
    """
    `eva_options` are allowlisted tuning values; `loop_unroll` analyses a mirror of the sources at
    `mirror_root` instead (default: under `out_dir`), with those loops annotated.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    options = dict(eva_options or {})
    problem = options_problem(options)
    if problem:
        raise ValueError(problem)
    csv_path = out_dir / "alarms.csv"
    red_csv = out_dir / "red_alarms.csv"
    sav_path = out_dir / "framac.sav"
    sarif_path = out_dir / "slice.sarif"
    # A report left over from an earlier run must never be read as this run's result.
    for stale in (
        csv_path,
        red_csv,
        sav_path,
        sarif_path,
        out_dir / "flows.log",
        out_dir / "flows.cg.dot",
        out_dir / "flamegraph.txt",
        out_dir / "nonterm.log",
    ):
        if stale.exists():
            stale.unlink()

    original_flags = shlex.split(augment_framac_cppflags(cppflags))
    # Over the sources as given, before any mirror: runs of one analysis must agree on it.
    input_digest = _input_digest(sources, original_flags)
    eff_sources, eff_cppflags = list(sources), cppflags
    applied: list[LoopRef] = []
    dropped: list[LoopRef] = []
    path_root: str | None = None
    refs = sorted(set(loop_unroll or []))
    if refs:
        root = mirror_root or (out_dir / "mirror").as_posix()
        mirror = prepare_mirror(root, sources, cppflags, original_flags, refs)
        if mirror is None or not mirror.applied:
            # Nothing to annotate: this is the plain analysis, and the cache already knows it.
            dropped = refs
        else:
            eff_sources, eff_cppflags, path_root = mirror.sources, mirror.cppflags, mirror.root
            applied, dropped = mirror.applied, mirror.dropped
    cmd, reduced_checks = _eva_command(
        eff_sources,
        main_fn,
        out_dir,
        machdep,
        eff_cppflags,
        slevel,
        warn_invalid_pointer,
        warn_unsigned,
        warn_unsigned_downcast,
        extra_domains,
        mlevel=mlevel,
        allow_incomplete_recursion_specs=allow_incomplete_recursion_specs,
        eva_options=options,
    )

    def _finalize(res: dict) -> dict:
        # Never cached: these describe this invocation, and the digest is taken fresh each time.
        res["sources"] = list(sources)
        res["eva_options"] = res.get("eva_options") or options
        res["loop_unroll"] = [ref.to_json() for ref in applied]
        res["loop_unroll_dropped"] = [ref.to_json() for ref in dropped]
        res["input_digest"] = input_digest
        return res

    def _run() -> dict:
        budget_s = float(timeout) if timeout is not None and timeout > 0 else None
        started_all = time.monotonic()

        def _remaining(default_s: int = 300) -> int | None:
            if budget_s is None:
                return None
            rem = int(budget_s - (time.monotonic() - started_all))
            return rem if rem >= 30 else default_s

        can_timeout_fallback = (
            budget_s is not None and budget_s >= 120 and options.get("precision") is None and not options.get("domains")
        )

        cur_allow_rec = allow_incomplete_recursion_specs
        cur_cmd, cur_reduced = cmd, reduced_checks
        res = _execute_eva(cur_cmd, eff_sources, main_fn, out_dir, cur_reduced, timeout, path_root=path_root)

        # Auto-retry when Frama-C aborts on a recursive call or indirect callback cycle without an ACSL assigns clause.
        if (
            res["status"] == "analysis_error"
            and not cur_allow_rec
            and _is_missing_assigns_error(out_dir / "eva.log", res.get("error_summary") or [])
        ):
            cur_allow_rec = True
            cur_cmd, cur_reduced = _eva_command(
                eff_sources,
                main_fn,
                out_dir,
                machdep,
                eff_cppflags,
                slevel,
                warn_invalid_pointer,
                warn_unsigned,
                warn_unsigned_downcast,
                extra_domains,
                mlevel=mlevel,
                allow_incomplete_recursion_specs=True,
                eva_options=options,
            )
            res = _execute_eva(
                cur_cmd,
                eff_sources,
                main_fn,
                out_dir,
                cur_reduced,
                _remaining(int(budget_s or 300)),
                path_root=path_root,
            )
            res["auto_recursion_fallback"] = True

        # Fast cvalue fallback when the default 5-domain base run times out.
        if res["status"] == "analysis_timeout" and can_timeout_fallback:
            fb_budget = min(900, max(120, int((budget_s or 600) // 4)))
            for tier_name, fb_opts in _timeout_fallback_tiers(slevel, options):
                fb_cmd, fb_reduced = _eva_command(
                    eff_sources,
                    main_fn,
                    out_dir,
                    machdep,
                    eff_cppflags,
                    slevel,
                    warn_invalid_pointer,
                    warn_unsigned,
                    warn_unsigned_downcast,
                    extra_domains,
                    mlevel=mlevel,
                    allow_incomplete_recursion_specs=cur_allow_rec,
                    eva_options=fb_opts,
                )
                fb_res = _execute_eva(fb_cmd, eff_sources, main_fn, out_dir, fb_reduced, fb_budget, path_root=path_root)
                if (
                    fb_res["status"] == "analysis_error"
                    and not cur_allow_rec
                    and _is_missing_assigns_error(out_dir / "eva.log", fb_res.get("error_summary") or [])
                ):
                    cur_allow_rec = True
                    fb_cmd, fb_reduced = _eva_command(
                        eff_sources,
                        main_fn,
                        out_dir,
                        machdep,
                        eff_cppflags,
                        slevel,
                        warn_invalid_pointer,
                        warn_unsigned,
                        warn_unsigned_downcast,
                        extra_domains,
                        mlevel=mlevel,
                        allow_incomplete_recursion_specs=True,
                        eva_options=fb_opts,
                    )
                    fb_res = _execute_eva(
                        fb_cmd, eff_sources, main_fn, out_dir, fb_reduced, fb_budget, path_root=path_root
                    )
                    fb_res["auto_recursion_fallback"] = True
                if fb_res["status"] == "ok":
                    fb_res["eva_options"] = fb_opts
                    fb_res["timeout_fallback"] = tier_name
                    return fb_res
                res = fb_res
        return res

    if not use_cache:
        res = _run()
        res["cache"] = {"hit": False, "key": None}
        return _finalize(res)

    def _restore_map(entry: cache.Entry) -> dict[str, Path]:
        return {name: out_dir / name for name in _CACHED_OUTPUTS}

    def _on_restore(result: dict, entry: cache.Entry) -> dict:
        # Path fields always name this run's files; the .sav is not part of a cache entry.
        restored = entry.meta.get("files") or {}
        for name, field in _CACHED_OUTPUTS.items():
            if field:
                result[field] = str(out_dir / name) if name in restored else None
        result["sav_file"] = None
        return result

    # The output files are not part of the analysis: the same analysis is one entry wherever it writes.
    outputs_in_cmd = {
        str(out_dir / name): f"<out>/{name}"
        for name in ("alarms.csv", "red_alarms.csv", "framac.sav", "flamegraph.txt", "nonterm.log")
    }
    # The nonterm log is passed with its append prefix, so mask that spelling too.
    outputs_in_cmd[f"a:{out_dir / 'nonterm.log'}"] = "<out>/nonterm.log"
    material = {
        "kind": "eva",
        "command": [outputs_in_cmd.get(token, token) for token in cmd],
        "sources": list(eff_sources),
    }
    return _finalize(
        cache.memoize(
            "eva",
            material,
            sources=eff_sources,
            dep_flags=shlex.split(augment_framac_cppflags(eff_cppflags)),
            build=_run,
            outputs=lambda res: {name: out_dir / name for name in _CACHED_OUTPUTS},
            ok=lambda res: res.get("status") == "ok",
            restore_map=_restore_map,
            on_restore=_on_restore,
        )
    )


def _input_digest(sources: list[str], flags: list[str]) -> str | None:
    """One digest for the sources and every header they include; None when it cannot be computed."""
    manifest = cache.dependency_manifest(sources, flags)
    if manifest is None:
        return None
    blob = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


# Upstream make-wrapper log patterns (docs/upstream/sources/make_wrapper_tips.md), ported as
# structured repair hints in the report.
_RE_MISSING_SPEC_RE = re.compile(r"Neither code nor (specification|[^ ]+ assigns clause) for function ([^,]+),")
_RE_RECURSIVE_CALL_RE = re.compile(r"detected recursive call")
_NONTERM_WARN_RE = re.compile(
    r"^\[nonterm:[a-z-]+\] (?P<loc>[^:\n]+:\d+): Warning:\s*\n?\s*(?P<msg>[^\n]+)(?:\n\s+stack: (?P<stack>[^\n]+))?",
    re.MULTILINE,
)


def extract_repair_hints(log_text: str) -> list[dict]:
    """
    Repair hints from Frama-C log patterns ported from upstream make-wrapper
    (docs/upstream/sources/make_wrapper_tips.md): recursive calls without an assigns clause,
    and called functions with neither code nor a specification.
    """
    hints: list[dict] = []
    for m in _RE_MISSING_SPEC_RE.finditer(log_text or ""):
        kind, fname = m.group(1), m.group(2).strip()
        if kind == "specification":
            action = (
                f"add the file defining {fname!r} to the module sources (locate it via "
                "build_callgraph_dag.py's function index), or add a stub/contract in "
                "templates/acsl/external_stubs.h"
            )
        else:
            action = (
                f"add an ACSL assigns clause for {fname!r}, or enable the recursion fallback "
                "(pipeline_make.py params set --module <mod> --eva-recursion-fallback)"
            )
        hints.append({"pattern": "missing_spec", "function": fname, "spec_kind": kind, "action": action})
    if _RE_RECURSIVE_CALL_RE.search(log_text or ""):
        hints.append(
            {
                "pattern": "recursive_call",
                "function": None,
                "action": (
                    "patch, stub or add an ACSL assigns specification to the recursive call, or enable "
                    "the recursion fallback (pipeline_make.py params set --module <mod> --eva-recursion-fallback)"
                ),
            }
        )
    return hints


def parse_nonterm_log(log_text: str) -> list[dict]:
    """Non-terminating loops/statements reported by the nonterm plug-in (-nonterm-log)."""
    return [
        {
            "location": m.group("loc"),
            "message": m.group("msg").strip(),
            "stack": (m.group("stack") or "").strip() or None,
        }
        for m in _NONTERM_WARN_RE.finditer(log_text or "")
    ]


def _is_missing_assigns_error(log_path: Path, error_summary: list[str]) -> bool:
    """Whether Frama-C Eva aborted due to a recursive call / callback cycle lacking an ACSL assigns clause."""
    if any("assigns:missing" in line or "without assigns clause" in line for line in error_summary):
        return True
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.is_file() else ""
    except OSError:
        return False
    return "[eva:assigns:missing]" in text or "without assigns clause" in text


def _timeout_fallback_tiers(slevel: int, base_options: dict) -> list[tuple[str, dict]]:
    """
    Fast cvalue-only fallback configurations when the default 5-domain base run exceeds its wall-clock budget.
    Tier 1 preserves per-callstack allocation (`by_stack`) and `split-return=auto`; Tier 2 drops to `precision=0`
    and `alloc-builtin=imprecise` if Tier 1 also times out.
    """
    tier1 = {
        **base_options,
        "precision": 1,
        "slevel": min(max(10, slevel), 20),
        "split-return": base_options.get("split-return", "auto"),
        "widening-delay": 1,
        "widening-period": 1,
        "remove-redundant-alarms": True,
    }
    tier2 = {
        **base_options,
        "precision": 0,
        "slevel": min(max(5, slevel), 10),
        "auto-loop-unroll": 2,
        "split-return": base_options.get("split-return", "auto"),
        "alloc-builtin": "imprecise",
        "widening-delay": 1,
        "widening-period": 1,
        "remove-redundant-alarms": True,
    }
    return [("cvalue_fast", tier1), ("cvalue_imprecise_alloc", tier2)]


def _eva_command(
    sources: list[str],
    main_fn: str,
    out_dir: Path,
    machdep: str,
    cppflags: str,
    slevel: int,
    warn_invalid_pointer: bool,
    warn_unsigned: bool,
    warn_unsigned_downcast: bool,
    extra_domains: list[str] | str | None,
    mlevel: int = 0,
    allow_incomplete_recursion_specs: bool = False,
    eva_options: dict | None = None,
) -> tuple[list[str], list[str]]:
    if mlevel < 0:
        raise ValueError(f"mlevel must be >= 0 (got {mlevel})")
    options = dict(eva_options or {})
    if "alloc-functions" not in options:
        detected_allocs = detect_alloc_wrappers(sources)
        if detected_allocs:
            options["alloc-functions"] = detected_allocs
    precision = options.get("precision")
    eff_precision = precision if isinstance(precision, int) and not isinstance(precision, bool) else None
    # These two always appear on the command line; an option only changes their value.
    slevel = options.pop("slevel", slevel)
    default_unroll = 0 if (eff_precision is not None and eff_precision < 2) else DEFAULT_AUTO_LOOP_UNROLL
    auto_loop_unroll = options.pop("auto-loop-unroll", default_unroll)
    domains = list(extra_domains.split(",") if isinstance(extra_domains, str) else (extra_domains or []))
    domains += option_domains(options)
    csv_path = out_dir / "alarms.csv"
    red_csv = out_dir / "red_alarms.csv"
    sav_path = out_dir / "framac.sav"
    cmd = [
        "frama-c",
        "-pp-annot",
        "-no-unicode",
        "-machdep",
        machdep,
        "-warn-signed-overflow",
        "-warn-signed-downcast",
        "-warn-left-shift-negative",
        "-warn-right-shift-negative",
        "-warn-pointer-downcast",
    ]
    reduced_checks: list[str] = []
    if warn_invalid_pointer:
        cmd.append("-warn-invalid-pointer")
    else:
        reduced_checks.append("-no-warn-invalid-pointer")
    if warn_unsigned:
        cmd.append("-warn-unsigned-overflow")
        if warn_unsigned_downcast:
            cmd.append("-warn-unsigned-downcast")
        else:
            reduced_checks.append("-no-warn-unsigned-downcast")
    else:
        reduced_checks.extend(["-no-warn-unsigned-overflow", "-no-warn-unsigned-downcast"])

    effective_cppflags = augment_framac_cppflags(cppflags)
    cmd.extend(
        [
            f"-cpp-extra-args={effective_cppflags}",
            *sources,
            "-main",
            main_fn,
            "-rte",
            "-then",
            "-eva",
            "-eva-domains",
            eva_domains(domains, precision=eff_precision),
            "-eva-slevel",
            str(slevel),
            "-eva-auto-loop-unroll",
            str(auto_loop_unroll),
            *framac_args(options),
            "-eva-report-red-statuses",
            str(red_csv),
            # Perf profile of the run; render it with scripts/eva_flamegraph.py when a run is slow.
            "-eva-flamegraph",
            str(out_dir / "flamegraph.txt"),
            "-then",
            "-metrics",
            "-metrics-eva-cover",
            "-then",
            "-report",
            "-report-csv",
            str(csv_path),
            "-save",
            str(sav_path),
            # Non-termination analysis on the saved AST (upstream analysis.mk runs it the same way);
            # its warnings are parsed into the report's `nonterm` field.
            "-then",
            "-nonterm",
            "-nonterm-log",
            f"a:{out_dir / 'nonterm.log'}",
        ]
    )
    if mlevel > 0:
        insert_at = cmd.index("-then", cmd.index("-eva"))
        cmd[insert_at:insert_at] = ["-eva-mlevel", str(mlevel)]
    if allow_incomplete_recursion_specs:
        # A recursive call with no ACSL assigns clause aborts Eva with a deferred
        # "warning as error assigns:missing". Downgrading the key keeps the analysis
        # going with the kernel-inferred (incomplete) assigns; recorded as a reduced
        # check because the recursion boundary is then interpreted unsoundly.
        # Insert inside the Eva option group (before the next -then), not after -save.
        insert_at = cmd.index("-then", cmd.index("-eva"))
        cmd[insert_at:insert_at] = ["-eva-warn-key", "assigns:missing=warning"]
        reduced_checks.append("-eva-warn-key assigns:missing=warning (recursive calls use kernel-inferred assigns)")
    return cmd, reduced_checks


def read_report_rows(csv_path: Path, path_root: str | None = None) -> list[dict]:
    """The report's property rows, with a mirror's path prefix removed (see eva_loops.py)."""
    rows = read_report_csv(csv_path)
    if path_root:
        for row in rows:
            row["directory"] = strip_mirror(row["directory"], path_root)
    return rows


def summarize_rows(rows: list[dict]) -> dict:
    """The report's status buckets and counts for a list of property rows."""
    alarms_by_status: dict[str, list[dict]] = {
        "Valid": [],
        "Unknown": [],
        "Invalid": [],
        "Dead": [],
        "Assumed": [],
        "Other": [],
    }
    unknown_by_function: dict[str, list[dict]] = defaultdict(list)
    functions_with_properties: set[str] = set()
    functions_with_properties_by_file: set[tuple[str, str, str]] = set()

    for row in rows:
        st = row["status"]
        entry = {
            "directory": row["directory"],
            "file": row["file"],
            "function": row["function"],
            "line": row["line"],
            "kind": row["kind"],
            "status": row["status_raw"],
            "status_bucket": st,
            "annotation": row["property"],
        }
        if row["function"]:
            functions_with_properties.add(row["function"])
            functions_with_properties_by_file.add((row["directory"], row["file"], row["function"]))
        if st in (STATUS_VALID, STATUS_VALID_UNDER_HYP):
            alarms_by_status["Valid"].append(entry)
        elif st in (STATUS_UNKNOWN, STATUS_NEVER_TRIED):
            alarms_by_status["Unknown"].append(entry)
            if row["function"]:
                unknown_by_function[row["function"]].append(entry)
        elif st in (STATUS_INVALID, STATUS_INVALID_UNDER_HYP):
            entry["under_hypotheses"] = st == STATUS_INVALID_UNDER_HYP
            if row.get("tuning_run"):
                entry["tuning_run"] = row["tuning_run"]
            alarms_by_status["Invalid"].append(entry)
        elif st == STATUS_DEAD:
            # Unreachable from eva_main under this harness: neither a bug nor a proof.
            alarms_by_status["Dead"].append(entry)
        elif st == STATUS_ASSUMED:
            # "Considered valid": an assumption (libc/stub spec), recorded, never counted as proven.
            alarms_by_status["Assumed"].append(entry)
        else:
            alarms_by_status["Other"].append(entry)

    total_checked = len(alarms_by_status["Valid"]) + len(alarms_by_status["Unknown"]) + len(alarms_by_status["Invalid"])
    discharged_pct = round(100.0 * len(alarms_by_status["Valid"]) / total_checked, 2) if total_checked > 0 else 0.0
    return {
        "total_properties": total_checked,
        "valid_count": len(alarms_by_status["Valid"]),
        "unknown_count": len(alarms_by_status["Unknown"]),
        "invalid_count": len(alarms_by_status["Invalid"]),
        "dead_count": len(alarms_by_status["Dead"]),
        "assumed_count": len(alarms_by_status["Assumed"]),
        # Inconsistent or unrecognized statuses: neither proof nor alarm, so ingest never credits them.
        "other_count": len(alarms_by_status["Other"]),
        "discharged_percentage": discharged_pct,
        "surviving_unknown_functions": sorted(unknown_by_function.keys()),
        "unknown_obligations_by_function": dict(unknown_by_function),
        "functions_with_properties": sorted(functions_with_properties),
        "functions_with_properties_by_file": [
            {"directory": d, "file": f, "function": fn} for d, f, fn in sorted(functions_with_properties_by_file)
        ],
        "invalid_alarms": alarms_by_status["Invalid"],
        "dead_alarms": alarms_by_status["Dead"],
        "assumed_properties": alarms_by_status["Assumed"],
        "other_properties": alarms_by_status["Other"],
    }


def _execute_eva(
    cmd: list[str],
    sources: list[str],
    main_fn: str,
    out_dir: Path,
    reduced_checks: list[str],
    timeout: int | None,
    path_root: str | None = None,
) -> dict:
    csv_path = out_dir / "alarms.csv"
    sav_path = out_dir / "framac.sav"
    sarif_path = out_dir / "slice.sarif"
    log_path = out_dir / "eva.log"

    started = time.monotonic()
    timed_out = False
    returncode: int | None
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        returncode, stdout, stderr = proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        timed_out, returncode = True, None
        stdout = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
    elapsed_s = round(time.monotonic() - started, 1)
    combined_log = stdout + "\n" + stderr
    log_path.write_text(combined_log, encoding="utf-8")

    flows: dict = {"status": "not_run", "reason": "no saved session", "by_function": {}, "call_edges": {}}
    # Generate SARIF from saved state if sav_path was produced
    if sav_path.exists() and not timed_out:
        flows = collect_flows(sav_path, out_dir)
        sarif_cmd = [
            "frama-c",
            "-load",
            str(sav_path),
            "-mdr-gen",
            "sarif",
            "-mdr-no-print-libc",
            "-mdr-out",
            str(sarif_path),
        ]
        subprocess.run(sarif_cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        if path_root and sarif_path.exists():
            # Findings must name the real sources, not the scratch mirror they were analysed in.
            sarif_text = sarif_path.read_text(encoding="utf-8", errors="replace")
            sarif_path.write_text(sarif_text.replace(f"{path_root}/", ""), encoding="utf-8")

    rows = read_report_rows(csv_path, path_root) if csv_path.exists() else []
    summary = summarize_rows(rows)

    flamegraph_path = out_dir / "flamegraph.txt"
    nonterm_log_path = out_dir / "nonterm.log"
    try:
        nonterm_text = (
            nonterm_log_path.read_text(encoding="utf-8", errors="replace") if nonterm_log_path.is_file() else ""
        )
    except OSError:
        nonterm_text = ""

    # A failed Frama-C run or a missing report must never look like "0 alarms".
    reason = None
    if timed_out:
        status = "analysis_timeout"
        error_summary = [f"Frama-C Eva exceeded the {timeout} s wall-clock limit"] + extract_error_summary(
            combined_log
        )[-5:]
    else:
        status = "ok" if returncode == 0 and csv_path.exists() else "analysis_error"
        error_summary = extract_error_summary(combined_log) if status != "ok" else []
        if status == "analysis_error":
            reason = failure_reason(returncode, False)
            if not error_summary:  # a SIGKILL leaves no log line behind
                error_summary = [f"Frama-C Eva produced no report ({reason}, exit code {returncode})"]

    return {
        "status": status,
        "reason": reason,
        "returncode": returncode,
        "error_summary": error_summary,
        # Non-empty means Frama-C invented `int f()` prototypes: fix the stubs before trusting results.
        "undeclared_functions": scan_undeclared_functions(combined_log),
        "main_fn": main_fn,
        "sources": list(sources),
        **summary,
        "mirror_root": path_root,
        "elapsed_s": elapsed_s,
        "reduced_checks": reduced_checks,
        "flows": flows,
        "sarif_file": str(sarif_path) if sarif_path.exists() else None,
        "csv_file": str(csv_path) if csv_path.exists() else None,
        "sav_file": str(sav_path) if sav_path.exists() else None,
        "log_file": str(log_path),
        "flamegraph_file": str(flamegraph_path) if flamegraph_path.exists() else None,
        "nonterm_log_file": str(nonterm_log_path) if nonterm_log_path.exists() else None,
        "nonterm": parse_nonterm_log(nonterm_text),
        "repair_hints": extract_repair_hints(combined_log),
    }


EVA_GATE_NEED = ("reach",)


def phase0_gate_reasons(module: str, run_dir: Path = Path(".")) -> list[str]:
    """
    Why the Phase 0 gate stops an Eva run of `module` (the reach gate, as the Make Eva recipes check
    it), or [] when it passes or the run directory has no gate stamp (a scratch copy, guidance mode).
    """
    if not module or not (run_dir / phase0_gates.GATES_JSON).is_file():
        return []
    try:
        return phase0_gates.check(run_dir, module, EVA_GATE_NEED)
    except (ArtifactError, OSError, ValueError) as exc:
        return [f"cannot read {phase0_gates.GATES_JSON}: {exc}"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Frama-C Eva + RTE on a module slice.")
    parser.add_argument("--sources", nargs="+", required=True)
    parser.add_argument("--main", required=True, help="Entry function name (e.g. eva_main)")
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--machdep", default="gcc_x86_64")
    parser.add_argument("--cppflags", default="-I.")
    parser.add_argument("--slevel", type=int, default=100)
    parser.add_argument(
        "--mlevel",
        type=int,
        default=0,
        help="Maximum dynamic allocation calls per callstack returning fresh bases (-eva-mlevel, default: 0).",
    )
    parser.add_argument("--module", default="")
    parser.add_argument("--out-json", type=Path, required=True)
    parser.add_argument(
        "--no-warn-invalid-pointer",
        action="store_true",
        help="Disable -warn-invalid-pointer (recorded in reduced_checks).",
    )
    parser.add_argument(
        "--no-warn-unsigned",
        action="store_true",
        help="Disable -warn-unsigned-overflow and -warn-unsigned-downcast (recorded in reduced_checks).",
    )
    parser.add_argument(
        "--no-warn-unsigned-downcast",
        action="store_true",
        help="Disable -warn-unsigned-downcast only (C11 modulo narrowing; recorded in reduced_checks).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Wall-clock limit in seconds (0: none; default: the eva job class limit); "
        "exceeding it yields status analysis_timeout.",
    )
    parser.add_argument(
        "--extra-domains",
        default="",
        help="Comma-separated Eva domains appended to -eva-domains (e.g. 'taint').",
    )
    parser.add_argument(
        "--allow-incomplete-recursion-specs",
        action="store_true",
        help=(
            "Downgrade the deferred 'assigns:missing' error for recursive calls without an "
            "ACSL assigns clause to a warning and continue (recorded in reduced_checks)."
        ),
    )
    parser.add_argument(
        "--eva-option",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="Allowlisted Eva tuning option (see eva_options.py), for example slevel=1000. Repeatable.",
    )
    parser.add_argument(
        "--loop-unroll",
        action="append",
        default=[],
        metavar="FILE#FUNCTION#ORDINAL=N",
        help="Unroll this loop N times, on a scratch mirror of the sources. Repeatable.",
    )
    parser.add_argument(
        "--mirror-root",
        default=None,
        help="Where --loop-unroll writes its mirror (default: under --out-dir).",
    )
    raw = list(argv) if argv is not None else sys.argv[1:]
    args = parser.parse_args(normalize_flag_args(raw, ("--cppflags",)))
    timeout = CLASSES["eva"].wall_timeout_s if args.timeout is None else args.timeout
    try:
        eva_domains(args.extra_domains)
        options = dict(parse_option(text) for text in args.eva_option)
        loop_unroll = [parse_loop_ref(text) for text in args.loop_unroll]
    except ValueError as exc:
        parser.error(str(exc))
    if args.mlevel < 0:
        parser.error("--mlevel must be >= 0")
    gate = phase0_gate_reasons(args.module)
    if gate:
        print(json.dumps({"status": "gate_failed", "module": args.module, "reasons": gate}, indent=2))
        for reason in gate:
            print(f"phase0 gate: {reason}", file=sys.stderr)
        return 1

    res = run_eva_on_slice(
        sources=args.sources,
        main_fn=args.main,
        out_dir=args.out_dir,
        machdep=args.machdep,
        cppflags=args.cppflags,
        slevel=args.slevel,
        mlevel=args.mlevel,
        warn_invalid_pointer=not args.no_warn_invalid_pointer,
        warn_unsigned=not args.no_warn_unsigned,
        warn_unsigned_downcast=not args.no_warn_unsigned_downcast,
        timeout=timeout or None,
        extra_domains=args.extra_domains,
        allow_incomplete_recursion_specs=args.allow_incomplete_recursion_specs,
        eva_options=options,
        loop_unroll=loop_unroll,
        mirror_root=args.mirror_root,
    )
    res["module"] = args.module
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "status": res["status"],
                "reason": res.get("reason"),
                "error_summary": res["error_summary"],
                "undeclared_functions": res["undeclared_functions"],
                "valid_count": res["valid_count"],
                "unknown_count": res["unknown_count"],
                "invalid_count": res["invalid_count"],
                "dead_count": res["dead_count"],
                "assumed_count": res["assumed_count"],
                "discharged_percentage": res["discharged_percentage"],
                "surviving_unknown_functions": res["surviving_unknown_functions"],
            },
            indent=2,
        )
    )
    return 0 if res["status"] == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
