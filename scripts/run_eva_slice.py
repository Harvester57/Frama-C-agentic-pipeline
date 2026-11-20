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

A run writes flamegraph.txt (-eva-flamegraph, render it with `pipeline_make.py run
flamegraph-<mod>` or scripts/eva_flamegraph.py when a run is slow) unless called with
--no-flamegraph, as tuning rungs and loop trials are. The cost follows the profile's size: +7% wall
time on libmnl `attr` (6.8 MB), within noise on QCBOR run-4 (1.1 MB), and QCBOR run-5's base run
wrote 2.5 GB; only the module's base and plain runs have their profile read. Eva writes one line per
analysed call; the run folds identical stacks into one line (eva_flamegraph.fold_flamegraph) before
the file is read, cached or copied. Every run also runs
the nonterm plug-in (-nonterm -nonterm-log), whose warnings land in the report as `nonterm`. The report's
`repair_hints` field ports upstream make-wrapper's log patterns (recursive call without assigns,
called function with neither code nor specification) into pipeline actions.

Tuning comes in two forms, both recorded in the report: `--eva-option name=value`, allowlisted by
eva_options.py, and `--loop-unroll file#function#ordinal=N`, which analyses a scratch mirror of the
sources (eva_loops.py) and maps its paths back, so workspace/work is never touched.

Inside a run directory with a Phase 0 gate stamp (workspace/reports/phase0_gates.json), a run for
`--module M` first checks M's reach gate (phase0_gates.py check --module M --need reach) and refuses
to run, exit 1 and no report, when M failed it or its harness or the DAG changed since: guidance-mode
runs never analyse a harness the gate stopped, as the Make recipes never do. The report's top-level
`harness_digest` (phase0_gates.harness_digest(run_dir, M, ignore_exempt=True), None without a harness)
names the harness it stands for, on a cache hit too; wp_scheduler.py refresh compares it with the
current one.

After a successful run, read and write sets are taken from the saved session in a separate
Frama-C process (`-load framac.sav -deps -inout -input -out-external -cg`), so they can neither
change Eva's status nor its timing. The report carries them as `flows`, by kernel function name:
hints about this harness, used for the provers' briefs (function_facts.py), never a verdict.

MetAcsl security properties (scripts/security_props.py, docs/guides/security-properties.md):
`--security-props PATH|none` (default: $FRAMAC_SECURITY_PROPS, else workspace/reports/security_props.json
when it exists) names the run's security_props.json. When its `meta_engines` holds `eva`, the run
writes the module's meta file (the properties with an instance in a function of this parse) to
security_meta/security_meta_<module>.c next to that file, adds it and the sources its properties
need to the parse, and puts `-meta -meta-checks -meta-warn-key unknown-func=inactive -then-last
-set-project-as-default` before `-rte`: every later stage, the saved session included, then works on
MetAcsl's project. The generated annotations are `check`s, so a violated one never stops the
analysis. Their rows leave the status buckets above and are reported under `security_props`, named
after their property and sorted by where they sit: `instances` (the ledger units' functions),
`unplanned_instances` (a target function security_props.json does not list) and `outside_instances`
(harness code). When Frama-C fails with the properties loaded, the run is done again without them and
`security_props.error` says so. Without `eva` in `meta_engines` nothing changes: same command, same report.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import re
import shlex
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cache  # noqa: E402
import phase0_gates  # noqa: E402
import unit_split  # noqa: E402
from eva_flamegraph import cost_profile, fold_flamegraph  # noqa: E402
from eva_loops import LoopRef, parse_loop_ref, prepare_mirror, strip_mirror  # noqa: E402
from eva_options import extra_domains as option_domains  # noqa: E402
from eva_options import framac_args, options_problem, parse_option  # noqa: E402
from framac_common import (  # noqa: E402
    _KERNEL_ERROR_HINT_RE,
    STATUS_ASSUMED,
    STATUS_DEAD,
    STATUS_INVALID,
    STATUS_INVALID_UNDER_HYP,
    STATUS_NEVER_TRIED,
    STATUS_UNKNOWN,
    STATUS_VALID,
    STATUS_VALID_UNDER_HYP,
    ArtifactError,
    atomic_write_json,
    augment_framac_cppflags,
    bound_flow_location,
    failure_reason,
    fold_messages,
    missing_spec_messages,
    normalize_flag_args,
    parse_missing_spec,
    read_report_csv,
    resolve_flows,
    scan_undeclared_functions,
    spill_large_flows,
    stub_repair_action,
)
from patterns import DOMAIN_RE, KERNEL_RENAME_RE  # noqa: E402
from resources import CLASSES  # noqa: E402

_KERNEL_ERR_RE = re.compile(
    r"^(?:\[kernel[^\]]*\]|[^:\n]+:\d+:).*?(?:user error|syntax error|fatal error|error:|unbound logic|invalid).*$",
    re.IGNORECASE | re.MULTILINE,
)


def extract_error_summary(log_text: str, max_lines: int = 20) -> list[str]:
    """Extract concise kernel/preprocessor error lines from a Frama-C log."""
    messages = fold_messages(log_text or "")
    seen: set[str] = set()
    matches: list[str] = []
    for m in messages:
        if (m.plugin in ("kernel", "cpp") and _KERNEL_ERROR_HINT_RE.search(m.folded)) or _KERNEL_ERR_RE.search(
            m.folded
        ):
            if m.folded not in seen:
                seen.add(m.folded)
                matches.append(m.folded)
    if matches:
        return matches[:max_lines]
    tail = [line.strip() for line in (log_text or "").splitlines() if line.strip()]
    return tail[-max_lines:]


BASE_DOMAINS = ("cvalue", "equality", "symbolic-locations", "octagon", "gauges")
DEFAULT_AUTO_LOOP_UNROLL = 32
_DOMAIN_RE = DOMAIN_RE
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
    writes_by_loc: dict[str, dict] = {}
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
        and_self = "(and SELF)" in text
        from_locs = list(dict.fromkeys(bound_flow_location(x) for x in split_locations(text.replace("(and SELF)", ""))))
        if current is not None:
            if entry["loc"] == "\\result":
                if current["result_from"] is None:
                    current["result_from"] = from_locs
                else:
                    current["result_from"] = list(dict.fromkeys([*current["result_from"], *from_locs]))
            else:
                loc = bound_flow_location(entry["loc"])
                existing = writes_by_loc.get(loc)
                if existing is None:
                    rec = {"loc": loc, "and_self": and_self, "from": from_locs}
                    writes_by_loc[loc] = rec
                    current["writes"].append(rec)
                else:
                    existing["and_self"] = bool(existing.get("and_self")) or and_self
                    existing["from"] = list(dict.fromkeys([*(existing.get("from") or []), *from_locs]))
        entry, pending_from = None, []

    for line in section.group(1).splitlines():
        m_fn = _FROM_FUNCTION_RE.match(line)
        if m_fn:
            _close_entry()
            current = {"writes": [], "result_from": None, "no_effects": False, "non_terminating": False}
            writes_by_loc = {}
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
        out.setdefault(fn, {})[name] = list(
            dict.fromkeys(bound_flow_location(x) for x in split_locations(" ".join(lines)))
        )
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
    domains: list[str]
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
        if not _DOMAIN_RE.fullmatch(dom):
            raise ValueError(f"invalid Eva domain name {dom!r}")
        if dom not in domains:
            domains.append(dom)
    return ",".join(domains)


# ---------------------------------------------------------------------------
# MetAcsl security properties (module docstring; docs/guides/security-properties.md)
# ---------------------------------------------------------------------------

SECURITY_PROPS_ENV = "FRAMAC_SECURITY_PROPS"
DEFAULT_SECURITY_PROPS = Path("workspace/reports/security_props.json")
SECURITY_META_DIR = "security_meta"
META_ENGINE = "eva"
# What goes between `-main <fn>` and `-rte` when the properties are loaded.
#   -meta-checks: the generated annotations are `check`s. The default `assert`/`requires` stops Eva at
#     the first violated instance, so one violation the harness induces (a protected function it calls
#     directly) would turn everything behind it Dead.
#   -then-last -set-project-as-default: MetAcsl writes its annotations into a copy of the project. A
#     plain `-then` goes back to the original one (Eva would never see the annotations), and the saved
#     session would hold the original as its current project, so the flows and SARIF steps that load it
#     would run Eva again on it. Made the default, MetAcsl's project is what every later stage and the
#     saved session use.
META_STAGE = (
    "-meta",
    "-meta-checks",
    "-meta-warn-key",
    "unknown-func=inactive",
    "-then-last",
    "-set-project-as-default",
)
META_BUCKETS = ("valid", "unknown", "invalid", "dead", "assumed", "other")
# The rows a reader has to look at, in the order they are listed; the others are only counted.
META_OPEN_BUCKETS = ("invalid", "other", "unknown")
META_OPEN_ROWS_MAX = 2000
# The part of the report's `security_props` that does not depend on the rows (load_security_meta).
META_STATIC_KEYS = (
    "props",
    "meta_file",
    "properties",
    "line_names",
    "extra_sources",
    "skipped",
    "classes",
    "planned",
    "decided",
    "functions",
    "outside_functions",
    "roots",
)
# A generated precondition keeps its name in the report: `L4_auth_required_login: meta: auth_ok != 0`.
_META_NAMED_RE = re.compile(r"^\s*([A-Za-z_]\w*)\s*[:,]\s*meta\s*[:,]\s*")
_META_FILE_UNSAFE_RE = re.compile(r"[^A-Za-z0-9_.+-]")


def resolve_security_props(spec: str | None) -> str | None:
    """
    The security_props.json a run reads, as run_wp_function.resolve_security_meta picks it: `spec`
    (`none`/`off`: no file), else $FRAMAC_SECURITY_PROPS, else workspace/reports/security_props.json
    when it exists. None: no file.
    """
    if spec is not None and spec.strip().lower() in ("none", "off", ""):
        return None
    if spec:
        return spec
    path = Path(os.environ.get(SECURITY_PROPS_ENV) or DEFAULT_SECURITY_PROPS)
    return path.as_posix() if path.is_file() else None


def _posix(path: str | Path) -> str:
    return posixpath.normpath(str(path).replace("\\", "/"))


def _same_file(a: str, b: str) -> bool:
    """Whether two normalized paths name one file, one of them possibly from further up (a/b/x.c, b/x.c)."""
    return a == b or a.endswith("/" + b) or b.endswith("/" + a)


def _row_path(row: dict) -> str:
    directory = str(row.get("directory") or "").replace("\\", "/").rstrip("/")
    file = str(row.get("file") or "").replace("\\", "/")
    if not file:
        return ""
    return _posix(f"{directory}/{file}" if directory and directory != "." and not file.startswith("/") else file)


def _props_function_ids(doc: dict) -> set[str]:
    """Every `file#name` id security_props.json knows: obligations, frame, instances, decided functions."""
    ids = {str(fid) for fid in doc.get("obligations") or {}}
    ids |= {str(f.get("function")) for f in doc.get("frame") or [] if isinstance(f, dict) and f.get("function")}
    for prop in doc.get("properties") or []:
        if not isinstance(prop, dict):
            continue
        ids |= {str(i) for i in prop.get("instances") or []}
        ids |= {str(d.get("function")) for d in prop.get("decided") or [] if isinstance(d, dict) and d.get("function")}
    return {fid for fid in ids if "#" in fid}


def _module_functions(doc: dict, paths: Iterable[str]) -> tuple[set[str], list[str], set[str]]:
    """
    The function ids of security_props.json that the files of one parse define: (ids, work roots, the
    paths that matched). A path matches the id file that is its longest suffix
    (`workspace/work/src/x.c` -> `src/x.c`), and what is left of the path is a work root.
    """
    by_file: dict[str, set[str]] = defaultdict(set)
    for fid in _props_function_ids(doc):
        by_file[_posix(fid.rpartition("#")[0])].add(fid)
    ids: set[str] = set()
    roots: set[str] = set()
    matched: set[str] = set()
    for path in paths:
        found = [file for file in by_file if path == file or path.endswith("/" + file)]
        if not found:
            continue
        best = max(found, key=len)
        ids |= by_file[best]
        roots.add(path[: len(path) - len(best)])
        matched.add(path)
    return ids, sorted(roots), matched


def _defined_functions(path: str) -> set[str]:
    """The functions a C file defines; empty when it cannot be read."""
    from acsl_ast import locate_all_definition_spans  # noqa: PLC0415

    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        return set(locate_all_definition_spans(text, path))
    except (OSError, ValueError, RuntimeError):
        return set()


def _write_if_changed(path: Path, text: str) -> None:
    """Atomic, and a no-op when the file already holds `text`: runs of one module share the file."""
    try:
        if path.is_file() and path.read_text(encoding="utf-8") == text:
            return
    except (OSError, ValueError):
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    # A name of its own: two containers writing the same file can have the same pid.
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp_", suffix=".c")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        os.replace(tmp, path)
    finally:
        Path(tmp).unlink(missing_ok=True)


def load_security_meta(props_path: str, sources: list[str], flags: list[str], module: str, main_fn: str) -> dict | None:
    """
    What a run loads from security_props.json. None when the file does not turn MetAcsl on for Eva
    (`meta_engines` without `eva`): the run is then exactly the run without the option. Otherwise the
    static part of the report's `security_props`:

      {props, error, properties: []}            the file cannot be read;
      {props, properties: [], meta_file: None}   no property has an instance in this parse;
      {props, meta_file, properties, line_names, extra_sources, classes, planned, decided, functions,
       outside_functions, roots[, skipped]}      the module meta file was written and is to be parsed.

    Only the properties security_props.for_engine keeps for Eva are considered; the names it left
    out are listed under `not_for_engine` (absent when there are none).

    The module's functions are those security_props.json knows in the sources and in every file they
    include (the dependency manifest: a harness that `#include`s the target source lists only itself).
    A property whose `sources` (the file defining a global it names) is neither in the parse nor under
    a work root is left out and listed under `skipped`: MetAcsl could not type it.
    The meta file's directory is named after its text, so runs that load different properties (shards
    under different defines, a rung started before security_props.json changed) never share a file.
    """
    import security_props  # noqa: PLC0415

    path = Path(props_path)
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {"props": path.as_posix(), "error": f"unreadable: {exc}", "properties": []}
    if not isinstance(doc, dict) or META_ENGINE not in security_props.meta_engines(doc):
        return None
    # A property whose `engines` leave Eva out (a monotonic invariant: Eva does not evaluate
    # \at(x, Before)) never reaches the meta file, nor the planned instances and classes below.
    listed = [p for p in doc.get("properties") or [] if isinstance(p, dict)]
    doc = security_props.for_engine({**doc, "properties": listed}, META_ENGINE)
    not_for_engine = sorted(
        {str(p.get("name")) for p in listed} - {str(p.get("name")) for p in doc.get("properties") or []}
    )
    manifest = cache.dependency_manifest(sources, flags)
    source_paths = [_posix(s) for s in sources]
    paths = sorted({_posix(dep) for dep, _ in manifest} | set(source_paths)) if manifest else source_paths
    ids, roots, matched = _module_functions(doc, paths)
    nothing: dict = {
        "props": path.as_posix(),
        "properties": [],
        "meta_file": None,
        **({"not_for_engine": not_for_engine} if not_for_engine else {}),
    }
    if not ids:
        return nothing

    kept: list[dict] = []
    extra: list[str] = []
    skipped: list[dict] = []
    for prop in doc.get("properties") or []:
        if not isinstance(prop, dict):
            continue
        wanted = not prop.get("code") and bool(set(prop.get("instances") or []) & ids)
        missing = None
        found: list[str] = []
        for src in (prop.get("sources") or []) if wanted else []:
            rel = _posix(str(src))
            if any(_same_file(p, rel) for p in paths):
                continue  # already parsed, as a source or through an #include
            cand = next((f"{root}{rel}" for root in roots if Path(f"{root}{rel}").is_file()), None)
            if cand is None:
                missing = rel
                break
            found.append(cand)
        if missing is not None:
            skipped.append(
                {
                    "property": str(prop.get("name")),
                    "reason": f"its source {missing} is neither in this parse nor under {', '.join(roots) or '.'}",
                }
            )
            continue
        extra += [f for f in found if f not in extra]
        kept.append(prop)
    built = security_props.module_meta_file_text({**doc, "properties": kept}, functions=ids)
    if built is None:
        return {**nothing, **({"skipped": skipped} if skipped else {})}
    text, names, _ = built
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
    stem = _META_FILE_UNSAFE_RE.sub("_", module or "") or "slice"
    meta_file = path.parent / SECURITY_META_DIR / digest / f"security_meta_{stem}.c"
    _write_if_changed(meta_file, text)

    selected = [p for p in kept if str(p.get("name")) in names]
    functions: dict[str, list[str]] = defaultdict(list)
    for fid in sorted(ids):
        functions[fid.rpartition("#")[2]].append(fid)
    # Harness code: what the sources outside the target's work tree define, and the entry function.
    outside = {main_fn}
    for src in source_paths:
        if src not in matched and not any(root and src.startswith(root) for root in roots):
            outside |= _defined_functions(src)
    return {
        "props": path.as_posix(),
        "meta_file": meta_file.as_posix(),
        "properties": list(names),
        "line_names": {str(line): name for line, name in security_props.meta_line_names(text).items()},
        "extra_sources": extra,
        **({"skipped": skipped} if skipped else {}),
        **({"not_for_engine": not_for_engine} if not_for_engine else {}),
        "classes": {str(p["name"]): str(p.get("obligation_class") or "") for p in selected},
        "planned": {str(p["name"]): sorted(set(p.get("instances") or []) & ids) for p in selected},
        "decided": {
            str(p["name"]): found_ids
            for p in selected
            if (
                found_ids := sorted(
                    {str(d.get("function")) for d in p.get("decided") or [] if isinstance(d, dict)} & ids
                )
            )
        },
        "functions": dict(functions),
        "outside_functions": sorted(outside - set(functions)),
        "roots": roots,
    }


def _meta_row_name(row: dict, section: dict) -> tuple[str | None, bool] | None:
    """(property, whether the row sits in the meta file) of a row MetAcsl generated; None for any other row."""
    meta_file = section.get("meta_file")
    if not meta_file:
        return None
    text = str(row.get("property") if "property" in row else row.get("annotation") or "")
    m = _META_NAMED_RE.match(text)
    named = m.group(1) if m and m.group(1) in (section.get("properties") or []) else None
    path = _row_path(row)
    if path and _same_file(path, _posix(meta_file)):
        return (section.get("line_names") or {}).get(str(row.get("line"))) or named, True
    return (named, False) if named else None


def is_meta_row(row: dict, section: dict | None) -> bool:
    """Whether a report row is an annotation MetAcsl generated from the properties `section` loaded."""
    return isinstance(section, dict) and _meta_row_name(row, section) is not None


def split_meta_rows(rows: Iterable[dict], section: dict | None) -> tuple[list[dict], list[dict]]:
    """(the other rows, MetAcsl's rows), each in report order."""
    plain: list[dict] = []
    meta: list[dict] = []
    for row in rows:
        (meta if is_meta_row(row, section) else plain).append(row)
    return plain, meta


def _meta_bucket(status: str) -> str:
    if status in (STATUS_VALID, STATUS_VALID_UNDER_HYP):
        return "valid"
    if status in (STATUS_UNKNOWN, STATUS_NEVER_TRIED):
        return "unknown"
    if status in (STATUS_INVALID, STATUS_INVALID_UNDER_HYP):
        return "invalid"
    if status == STATUS_DEAD:
        return "dead"
    return "assumed" if status == STATUS_ASSUMED else "other"


def _meta_row_place(name: str | None, row: dict, in_meta_file: bool, section: dict) -> tuple[str, str, list[str]]:
    """
    Where one MetAcsl row belongs: (role, function id or name, candidate ids).

      instance   in a function security_props.json lists as an instance of the property: a ledger unit;
      decided    in a function whose instance the model decided (no unit waits for it);
      unplanned  in a target function that is not an instance: the model and MetAcsl disagree;
      ambiguous  in a function several files define under one name (the kernel renames the copies `f_0`
                 and a row in the meta file does not say which one it is): no instance is credited;
      outside    harness code, or a row no property names.

    A generated assertion sits in the meta file and only names its function. A generated precondition
    is reported at each call site, in the caller's own file.
    """
    functions = section.get("functions") or {}
    fn = str(row.get("function") or "")
    cands = list(functions.get(fn) or [])
    renamed = False
    if not cands:
        m = KERNEL_RENAME_RE.fullmatch(fn)
        if m and functions.get(m.group(1)):
            cands, renamed = list(functions[m.group(1)]), True
    path = _row_path(row)
    if not in_meta_file:
        here = [fid for fid in cands if _same_file(path, _posix(fid.rpartition("#")[0]))]
        cands = [max(here, key=len)] if here else []
        renamed = False
    if name is None or not fn:
        return "outside", fn, []
    if not cands:
        in_target = any(root and path.startswith(root) for root in section.get("roots") or [])
        if fn in (section.get("outside_functions") or []) or not (in_meta_file or in_target):
            return "outside", fn, []
        return "unplanned", fn, []
    planned = set((section.get("planned") or {}).get(name) or [])
    if len(cands) > 1 or renamed:
        return ("ambiguous", fn, cands) if planned & set(cands) else ("unplanned", fn, cands)
    fid = cands[0]
    if fid in planned:
        return "instance", fid, cands
    if fid in ((section.get("decided") or {}).get(name) or []):
        return "decided", fid, cands
    return "unplanned", fid, cands


def security_section(meta_rows: Iterable[dict], section: dict) -> dict:
    """
    The report's `security_props` from MetAcsl's rows and the static part load_security_meta returned:

      instances            one entry per planned instance in this parse (property, class, instance,
                           function) with its rows counted per status; all zeros when MetAcsl generated
                           nothing there (decided statically, or not instantiated);
      unplanned_instances  the same counts for target functions that are not instances;
      outside_instances    and for harness code: a violation the harness induces is listed, never filed;
      open_rows            the Invalid, unclassified and Unknown rows themselves, named
                           (`<property>: meta: <predicate>`), at most META_OPEN_ROWS_MAX of them;
      counts               all of MetAcsl's rows per status.

    The consolidated row of a generated precondition (in the meta file, kind `precondition`) is left
    out: its call sites have rows of their own, in the callers.
    """
    out = {key: section[key] for key in META_STATIC_KEYS if key in section}
    # Not a cache input (_meta_digest): the meta file's text already differs without those properties.
    if section.get("not_for_engine"):
        out["not_for_engine"] = section["not_for_engine"]
    classes = section.get("classes") or {}

    def zero() -> dict:
        return dict.fromkeys(META_BUCKETS, 0)

    instances = {(name, fid): zero() for name, fids in sorted((section.get("planned") or {}).items()) for fid in fids}
    unplanned: dict[tuple[str, str], dict] = {}
    outside: dict[tuple[str, str], dict] = {}
    totals = zero()
    open_rows: list[dict] = []
    for row in meta_rows:
        info = _meta_row_name(row, section)
        if info is None:
            continue
        name, in_meta_file = info
        if in_meta_file and str(row.get("kind") or "") == "precondition":
            continue
        bucket = _meta_bucket(str(row.get("status") or ""))
        role, where, cands = _meta_row_place(name, row, in_meta_file, section)
        totals[bucket] += 1
        if role == "decided":
            continue
        if role == "instance":
            instances[(str(name), where)][bucket] += 1
        elif role == "ambiguous":
            # Not known to be this instance's row: counted as unclassified on each candidate.
            for fid in cands:
                if (str(name), fid) in instances:
                    instances[(str(name), fid)]["other"] += 1
        elif role == "unplanned":
            unplanned.setdefault((str(name), where), zero())[bucket] += 1
        else:
            outside.setdefault((str(name or ""), where), zero())[bucket] += 1
        if bucket in META_OPEN_BUCKETS or role == "ambiguous":
            text = str(row.get("property") if "property" in row else row.get("annotation") or "")
            open_rows.append(
                {
                    "property": name,
                    "role": role,
                    "instance": where if role == "instance" else None,
                    **({"candidates": cands} if role == "ambiguous" else {}),
                    "directory": row.get("directory"),
                    "file": row.get("file"),
                    "line": row.get("line"),
                    "function": row.get("function"),
                    "kind": row.get("kind"),
                    "status": row.get("status_raw"),
                    "status_bucket": bucket,
                    "annotation": text if not name or _META_NAMED_RE.match(text) else f"{name}: meta: {text}",
                    **({"tuning_run": row["tuning_run"]} if row.get("tuning_run") else {}),
                }
            )
    order = {bucket: i for i, bucket in enumerate(META_OPEN_BUCKETS)}
    open_rows.sort(
        key=lambda r: (
            order.get(r["status_bucket"], len(order)),
            str(r["property"] or ""),
            str(r["function"] or ""),
            int(r["line"] or 0),
            r["annotation"],
        )
    )
    out["instances"] = [
        {
            "property": name,
            "class": classes.get(name, ""),
            "instance": fid,
            "function": fid.rpartition("#")[2],
            **counts,
        }
        for (name, fid), counts in sorted(instances.items())
    ]
    out["unplanned_instances"] = [
        {"property": name, "function": where, **counts} for (name, where), counts in sorted(unplanned.items())
    ]
    out["outside_instances"] = [
        {"property": name or None, "function": where, **counts} for (name, where), counts in sorted(outside.items())
    ]
    out["open_rows"] = open_rows[:META_OPEN_ROWS_MAX]
    if len(open_rows) > META_OPEN_ROWS_MAX:
        out["open_rows_truncated"] = len(open_rows) - META_OPEN_ROWS_MAX
    out["counts"] = totals
    return out


def summarize_report(rows: list[dict], section: dict | None = None) -> dict:
    """
    summarize_rows for a run that may have loaded security properties: MetAcsl's rows leave the status
    buckets (they are no RTE obligation of their function) and are reported under `security_props`.
    `section` is the run's own `security_props` (or its static part); without a meta file in it this is
    summarize_rows. Every writer of a module report goes through here (eva_tuning.py finish and
    eva_shards.py merge through summarize_runs), so the section always describes the rows the report
    was built from.
    """
    if not isinstance(section, dict) or not section.get("meta_file"):
        return summarize_rows(rows)
    plain, meta = split_meta_rows(rows, section)
    out = summarize_rows(plain)
    out["security_props"] = security_section(meta, section)
    return out


def summarize_runs(rows: list[dict], sections: Iterable[object]) -> dict:
    """
    summarize_report for rows put together from several runs of one module (eva_shards.py merge,
    eva_tuning.py finish), given each run's `security_props`. The runs must have loaded the same meta
    file; when one ran without the properties (its MetAcsl stage failed) or with others, no instance
    gets a status from the merge: MetAcsl's rows are dropped and `security_props.error` says why.
    """
    found = [s for s in sections if isinstance(s, dict)]
    loaded = [s for s in found if s.get("meta_file")]
    failed = next((s for s in found if s.get("error")), None)
    if not loaded:
        out = summarize_rows(rows)
        if found:
            out["security_props"] = dict(failed or found[0])
        return out
    files = sorted({str(s["meta_file"]) for s in loaded})
    if failed is None and len(files) == 1 and len(loaded) == len(found):
        return summarize_report(rows, loaded[0])
    plain = rows
    for section in loaded:
        plain, _ = split_meta_rows(plain, section)
    out = summarize_rows(plain)
    why = (
        f"one of the runs ran without the properties ({failed['error']})"
        if failed is not None
        else "the runs did not load the same meta file (" + ", ".join(files) + ")"
    )
    out["security_props"] = {
        "props": loaded[0].get("props"),
        "error": f"{why}: no property status for this module",
        "properties": [],
    }
    return out


def _meta_digest(section: dict) -> str:
    """Digest of what decides how MetAcsl's rows are filed (the meta file's own text is a cache input)."""
    blob = json.dumps({k: section.get(k) for k in META_STATIC_KEYS}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


def _keep_meta_failed_log(out_dir: Path) -> str | None:
    """Move the log of the run that failed with the properties loaded aside (eva.meta_failed.log)."""
    log = out_dir / "eva.log"
    kept = out_dir / "eva.meta_failed.log"
    try:
        if log.is_file():
            os.replace(log, kept)
            return str(kept)
    except OSError:
        pass
    return None


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
    timeout_fallback: bool = True,
    flamegraph: bool = True,
    security_props: str | None = None,
    module: str = "",
    dag_path: Path | str | None = None,
) -> dict:
    """
    `eva_options` are allowlisted tuning values; `loop_unroll` analyses a mirror of the sources at
    `mirror_root` instead (default: under `out_dir`), with those loops annotated. `timeout_fallback`
    False keeps a timeout a timeout (tuning trials: a less precise fallback result cannot help there).
    `flamegraph` False leaves out -eva-flamegraph (tuning trials: nobody reads their profile).
    `security_props` is the security_props.json to load MetAcsl properties from (resolve_security_props
    gives a command line's default; None: none), `module` names the meta file written for them and
    enables the address-flow soundness gate (`dag_path`, default `workspace/reports/callgraph_dag.json`
    when it exists) for `address_flow` unit-split clusters.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    options = dict(eva_options or {})
    problem = options_problem(options)
    if problem:
        raise ValueError(problem)
    resolved_dag: Path | str | None = dag_path
    if resolved_dag is None and module and DEFAULT_DAG_PATH.is_file():
        resolved_dag = DEFAULT_DAG_PATH
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
        out_dir / "flamegraph.timed_out.txt",
        out_dir / "nonterm.log",
        out_dir / "eva.timed_out.log",
    ):
        if stale.exists():
            stale.unlink()

    original_flags = shlex.split(augment_framac_cppflags(cppflags))
    # The MetAcsl properties this run loads: `meta` is what the report says about them whatever
    # happens, `active` is set when a meta file is to be parsed (the command and the cache key change).
    meta = (
        load_security_meta(security_props, list(sources), original_flags, module, main_fn) if security_props else None
    )
    active = meta if meta and meta.get("meta_file") else None
    meta_inputs: list[str] = [*active["extra_sources"], active["meta_file"]] if active else []
    # Over the sources as given, before any mirror: runs of one analysis must agree on it.
    input_digest = _input_digest([*sources, *meta_inputs] if active else sources, original_flags)
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

    def _command(
        loaded: dict | None, allow_rec: bool, opts: dict, with_flamegraph: bool
    ) -> tuple[list[str], list[str]]:
        return _eva_command(
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
            allow_incomplete_recursion_specs=allow_rec,
            eva_options=opts,
            flamegraph=with_flamegraph,
            **({"security_meta": loaded} if loaded else {}),
        )

    cmd, reduced_checks = _command(active, allow_incomplete_recursion_specs, options, flamegraph)

    def _finalize(res: dict) -> dict:
        # Never cached: these describe this invocation, and the digest is taken fresh each time.
        res["sources"] = list(sources)
        res["eva_options"] = res.get("eva_options") or options
        res["loop_unroll"] = [ref.to_json() for ref in applied]
        res["loop_unroll_dropped"] = [ref.to_json() for ref in dropped]
        res["input_digest"] = input_digest
        if meta is not None and "security_props" not in res:
            # Asked for, and no meta file was parsed (unreadable file, no property for this module).
            res["security_props"] = dict(meta)
        return res

    def _run() -> dict:
        res = _attempt(active)
        if active and res["status"] == "analysis_error" and res.get("reason") not in _NON_RETRYABLE_REASONS:
            # Frama-C failed with the properties loaded (a property MetAcsl cannot type aborts it):
            # the module still gets its RTE result, from the run without them, and the report says so.
            failed_log = _keep_meta_failed_log(out_dir)
            errors = list(res.get("error_summary") or [])[:5]
            for name in ("alarms.csv", "red_alarms.csv", "framac.sav", "slice.sarif", "flows.log", "flows.cg.dot"):
                (out_dir / name).unlink(missing_ok=True)
            res = _attempt(None)
            res["security_props"] = {
                "props": active["props"],
                "error": "Frama-C failed with the security properties loaded; this is the run without them",
                "error_summary": errors,
                "failed_log": failed_log,
                "failed_meta_file": active["meta_file"],
                "properties": [],
            }
        return res

    def _attempt(loaded: dict | None) -> dict:
        budget_s = float(timeout) if timeout is not None and timeout > 0 else None
        started_all = time.monotonic()

        def _remaining(default_s: int = 300) -> int | None:
            if budget_s is None:
                return None
            rem = int(budget_s - (time.monotonic() - started_all))
            return rem if rem >= 30 else default_s

        can_timeout_fallback = (
            timeout_fallback
            and budget_s is not None
            and budget_s >= 120
            and options.get("precision") is None
            and not options.get("domains")
        )

        def _exec(run_cmd: list[str], run_reduced: list[str], run_timeout: int | None) -> dict:
            # Every run (base, recursion retry, fallback tier) fails on a contract without \from
            # or an address-flow cluster gap (missing project body / missing project global).
            out = _execute_eva(
                run_cmd,
                eff_sources,
                main_fn,
                out_dir,
                run_reduced,
                run_timeout,
                path_root=path_root,
                **({"security_meta": loaded} if loaded else {}),
            )
            out = reject_stub_from_defects(out, out_dir)
            if module and resolved_dag is not None:
                gate_sources = [*sources, *(loaded.get("extra_sources") or [])] if loaded else list(sources)
                out = reject_address_flow_gaps(out, out_dir, module, resolved_dag, gate_sources)
            return out

        cur_allow_rec = allow_incomplete_recursion_specs
        cur_cmd, cur_reduced = (
            (cmd, reduced_checks)
            if loaded is active
            else _command(loaded, allow_incomplete_recursion_specs, options, flamegraph)
        )
        started = time.monotonic()
        res = _exec(cur_cmd, cur_reduced, timeout)
        first_s = round(time.monotonic() - started, 1)

        # Auto-retry when Frama-C aborts on a recursive call or indirect callback cycle without an ACSL
        # assigns clause, and on nothing else under the same warning key.
        if (
            res["status"] == "analysis_error"
            and not cur_allow_rec
            and res.get("reason") not in _NON_RETRYABLE_REASONS
            and _recursion_retry_applies(out_dir / "eva.log")
        ):
            cur_allow_rec = True
            cur_cmd, cur_reduced = _command(loaded, True, options, flamegraph)
            res = _exec(cur_cmd, cur_reduced, _remaining(int(budget_s or 300)))
            res["auto_recursion_fallback"] = True
            # elapsed_s stays the retry's; this is the wall time the aborted first attempt took of the
            # budget (what _remaining() subtracted). Cached with the result like the marker above.
            res[RECURSION_FIRST_ATTEMPT_FIELD] = first_s

        # Fast cvalue fallback when the default 5-domain base run times out. Preserve both eva.log
        # and any non-empty 5-domain flamegraph.txt so cost_profile and eva_shards.py plan from the
        # true 5-domain profile instead of a 900 s cvalue fallback.
        timed_out_profile = res.get("cost_profile")
        if res["status"] == "analysis_timeout" and can_timeout_fallback:
            timed_out = res
            _keep_timed_out_log(timed_out, out_dir)
            kept_fg = _keep_timed_out_flamegraph(out_dir)
            fb_flamegraph = flamegraph and kept_fg is None
            fb_budget = min(900, max(120, int((budget_s or 600) // 4)))
            tried: list[dict] = []
            for tier_name, fb_opts in _timeout_fallback_tiers(slevel, options):
                fb_cmd, fb_reduced = _command(loaded, cur_allow_rec, fb_opts, fb_flamegraph)
                fb_started = time.monotonic()
                fb_res = _exec(fb_cmd, fb_reduced, fb_budget)
                fb_first_s = round(time.monotonic() - fb_started, 1)
                if (
                    fb_res["status"] == "analysis_error"
                    and not cur_allow_rec
                    and fb_res.get("reason") not in _NON_RETRYABLE_REASONS
                    and _recursion_retry_applies(out_dir / "eva.log")
                ):
                    cur_allow_rec = True
                    fb_cmd, fb_reduced = _command(loaded, True, fb_opts, fb_flamegraph)
                    fb_res = _exec(fb_cmd, fb_reduced, fb_budget)
                    fb_res["auto_recursion_fallback"] = True
                    fb_res[RECURSION_FIRST_ATTEMPT_FIELD] = fb_first_s
                if fb_res["status"] == "ok":
                    if timed_out.get("auto_recursion_fallback") and not fb_res.get("auto_recursion_fallback"):
                        # The tiers started downgraded because the timed-out run had retried: the
                        # result keeps that marker and the first attempt it lost, so a tuning plan
                        # reading it propagates the downgrade (pipeline_make._plan_tuning).
                        fb_res["auto_recursion_fallback"] = True
                        if RECURSION_FIRST_ATTEMPT_FIELD in timed_out:
                            fb_res[RECURSION_FIRST_ATTEMPT_FIELD] = timed_out[RECURSION_FIRST_ATTEMPT_FIELD]
                    fb_res["eva_options"] = fb_opts
                    fb_res["timeout_fallback"] = tier_name
                    own = cost_profile(out_dir / "flamegraph.txt") if kept_fg is None else None
                    _restore_timed_out_flamegraph(kept_fg, out_dir, fb_res)
                    profile = timed_out_profile or ({"run": "fallback", **own} if own else None)
                    if profile:
                        fb_res["cost_profile"] = profile
                    return fb_res
                tried.append({"tier": tier_name, "status": fb_res["status"], "elapsed_s": fb_res.get("elapsed_s")})
            # No tier completed: the result is the timed-out run's, which names the limit it hit.
            res = _with_failed_fallbacks(timed_out, tried, fb_budget)
            _restore_timed_out_flamegraph(kept_fg, out_dir, res)
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
        if module and resolved_dag is not None:
            gate_sources = [*sources, *(active.get("extra_sources") or [])] if active else list(sources)
            result = reject_address_flow_gaps(result, out_dir, module, resolved_dag, gate_sources)
        return result

    # The output files are not part of the analysis: the same analysis is one entry wherever it writes.
    outputs_in_cmd = {
        str(out_dir / name): f"<out>/{name}"
        for name in ("alarms.csv", "red_alarms.csv", "framac.sav", "flamegraph.txt", "nonterm.log")
    }
    # The nonterm log is passed with its append prefix, so mask that spelling too.
    outputs_in_cmd[f"a:{out_dir / 'nonterm.log'}"] = "<out>/nonterm.log"
    # With properties loaded, the meta file and the sources its properties need are inputs like any
    # other: the meta file's text is in the dependency manifest, so a changed property is a new key, and
    # so is turning the engine on or off (the command differs).
    cache_sources = [*eff_sources, *meta_inputs]
    material = {
        "kind": "eva",
        "command": [outputs_in_cmd.get(token, token) for token in cmd],
        "sources": cache_sources,
        # A fallback tier's result is cached under the command that timed out: never reuse it where
        # the fallback is off. Only added when off, so existing entries keep their keys.
        **({} if timeout_fallback else {"timeout_fallback": False}),
        # How the rows are filed (instances, decided functions) comes from security_props.json, not
        # from the meta file: only added with properties loaded, so existing entries keep their keys.
        **({"security_props": _meta_digest(active)} if active else {}),
    }
    return _finalize(
        cache.memoize(
            "eva",
            material,
            sources=cache_sources,
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
    and called functions with neither code nor a specification; plus contract assigns clauses
    without \\from (`stub_missing_from`).
    """
    hints: list[dict] = []
    specs = missing_spec_messages(log_text or "")
    if not specs and "Neither code nor" in (log_text or ""):
        specs = parse_missing_spec(log_text or "")
    for spec in specs:
        if spec.benign:
            continue
        fname = spec.function
        if not fname:
            continue
        if "specification" in spec.missing:
            action = (
                f"add the file defining {fname!r} to the module sources (locate it via "
                f"build_callgraph_dag.py's function index), or, for an external function, {stub_repair_action(fname)}"
            )
            spec_kind = "specification"
        else:
            action = (
                f"add an ACSL assigns clause for {fname!r}, or enable the recursion fallback "
                "(pipeline_make.py params set --module <mod> --eva-recursion-fallback)"
            )
            spec_kind = "assigns"
        hints.append({"pattern": "missing_spec", "function": fname, "spec_kind": spec_kind, "action": action})
    for entry in missing_assigns_messages(log_text or ""):
        if entry["kind"] != "stub_from":
            continue
        hints.append(
            {
                "pattern": "stub_missing_from",
                "function": entry["function"],
                "location": entry["location"],
                "action": (
                    f"write the \\from of '{entry['clause']}' in the contract at {entry['location']} (the run's "
                    "stub overlay workspace/stubs/, or the shipped stub it comes from), for example "
                    "`assigns *p \\from p, *q;` or `\\from \\nothing` when nothing is read; the recursion "
                    "fallback does not cover this"
                ),
            }
        )
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


# Eva's `assigns:missing` key (an error unless downgraded) covers two defects with different fixes, in
# the messages Frama-C 34.0~beta prints (captured in tests/fixtures/eva_assigns/):
#   [eva:assigns:missing] b.c:5: User Error:
#     Recursive call to depth without assigns clause.            <- recursion or a callback cycle
#   [eva:assigns:missing] stub.h:4: User Error:
#     no \from part for clause 'assigns *p;'.                    <- a contract (a stub) without \from
# Only the first is what the recursion fallback is for. The second makes Eva assume `\from \nothing`
# ("probably incorrect"): it is a defect in the contract, fixed by writing the \from.
_ASSIGNS_MISSING_RE = re.compile(
    r"^\[eva:assigns:missing\] (?P<loc>\S+?:\d+): (?:User Error|Warning|Error):"
    r"(?P<head>[^\n]*)\n?(?P<body>(?:[ \t]+[^\n]*(?:\n|$))*)",
    re.MULTILINE,
)
_RECURSIVE_NO_ASSIGNS_RE = re.compile(r"Recursive call to (?P<fn>[A-Za-z_]\w*) without assigns clause")
_NO_FROM_RE = re.compile(r"no \\from part for clause '(?P<clause>[^']*)'")
_USING_SPEC_RE = re.compile(r"^\[eva\] using specification for function (?P<fn>[A-Za-z_]\w*)[ \t]*$", re.MULTILINE)
_DECL_NAME_RE = re.compile(r"\b(?P<fn>[A-Za-z_]\w*)\s*\(")
_NOT_A_DECL_NAME = frozenset({"__attribute__", "__attribute", "__declspec", "__asm__", "__asm", "asm", "typeof"})
RECURSION_REDUCED_CHECK = "-eva-warn-key assigns:missing=warning (recursive calls use kernel-inferred assigns)"
# Report field: seconds the first attempt took before it aborted on the recursion and was retried with
# the downgrade (set with `auto_recursion_fallback`; `elapsed_s` is the retry's alone).
RECURSION_FIRST_ATTEMPT_FIELD = "auto_recursion_fallback_first_attempt_s"


def _strip_attributes(text: str) -> str:
    """`text` without `__attribute__((...))` groups (balanced parentheses)."""
    out: list[str] = []
    i = 0
    while i < len(text):
        m = re.compile(r"__attribute__\s*\(").match(text, i)
        if not m:
            out.append(text[i])
            i += 1
            continue
        depth, j = 0, m.end() - 1
        while j < len(text):
            depth += {"(": 1, ")": -1}.get(text[j], 0)
            j += 1
            if depth == 0:
                break
        i = j
    return "".join(out)


def _declared_after_contract(path: str, line: int) -> str | None:
    """The function declared right after the ACSL contract holding `path`:`line`, when the file is readable."""
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, ValueError):
        return None
    start = max(line - 1, 0)
    if start < len(lines) and lines[start].lstrip().startswith("//@"):
        # A line contract: the declaration follows its last `//@` line.
        while start < len(lines) and lines[start].lstrip().startswith("//@"):
            start += 1
        after = "\n".join(lines[start:])
    else:
        rest = "\n".join(lines[start:])
        end = rest.find("*/")
        if end < 0:
            return None
        after = rest[end + 2 :]
    decl = re.split(r"[;{]", after, maxsplit=1)[0]
    decl = re.sub(r"/\*.*?\*/|//[^\n]*", " ", _strip_attributes(decl), flags=re.S)
    for m in _DECL_NAME_RE.finditer(decl):
        if m.group("fn") not in _NOT_A_DECL_NAME:
            return m.group("fn")
    return None


def _spec_function_before(log_text: str, start: int) -> str | None:
    """
    The function Eva announced (`using specification for function f`) right before the message at
    `start`, with nothing but other `[eva:assigns...]` messages in between; None otherwise (never a guess).
    """
    found = None
    for m in _USING_SPEC_RE.finditer(log_text, 0, start):
        found = m
    if found is None:
        return None
    between = log_text[found.end() : start]
    if any(ln and not ln[0].isspace() and not ln.startswith("[eva:assigns") for ln in between.splitlines()):
        return None
    return found.group("fn")


def missing_assigns_messages(log_text: str) -> list[dict]:
    """
    Every `[eva:assigns:missing]` message of an Eva log (as an error or, downgraded, as a warning), one
    entry per location: `kind` is `recursion` (a recursive call or callback cycle without an assigns
    clause; `function` is the callee), `stub_from` (an assigns clause without \\from in a contract;
    `function` is the declared function when it can be told, `clause` the clause) or `other`.
    """
    entries: list[dict] = []
    seen: set[tuple] = set()
    for m in _ASSIGNS_MISSING_RE.finditer(log_text or ""):
        loc = m.group("loc")
        text = " ".join((m.group("head") + "\n" + m.group("body")).split())
        rec = _RECURSIVE_NO_ASSIGNS_RE.search(text)
        no_from = _NO_FROM_RE.search(text)
        if rec:
            entry = {"kind": "recursion", "location": loc, "function": rec.group("fn"), "clause": None}
        elif no_from:
            path, _, line = loc.rpartition(":")
            fn = _declared_after_contract(path, int(line)) or _spec_function_before(log_text, m.start())
            entry = {"kind": "stub_from", "location": loc, "function": fn, "clause": no_from.group("clause")}
        else:
            entry = {"kind": "other", "location": loc, "function": None, "clause": None}
        entry["message"] = text
        key = (entry["kind"], loc, entry["function"], entry["clause"])
        if key not in seen:
            seen.add(key)
            entries.append(entry)
    return entries


def _read_log(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""
    except OSError:
        return ""


def _recursion_retry_applies(log_path: Path) -> bool:
    """
    Whether an aborted Eva run is the case the recursion fallback is for: every `assigns:missing`
    message is a recursive call or callback cycle without an assigns clause. A contract without \\from
    (or a message this does not know) is not retried: the downgrade would hide it.
    """
    entries = missing_assigns_messages(_read_log(log_path))
    return bool(entries) and all(e["kind"] == "recursion" for e in entries)


def stub_from_defect_message(entry: dict) -> str:
    """The error line for one contract assigns clause without \\from."""
    who = f"stub contract of {entry['function']}" if entry.get("function") else "stub contract"
    return (
        f"{who} at {entry['location']} lacks \\from for '{entry['clause']}': add a \\from clause "
        "(Eva would assume \\from \\nothing, which it calls probably incorrect)"
    )


def reject_stub_from_defects(res: dict, out_dir: Path) -> dict:
    """
    Turn a run whose log shows a contract assigns clause without \\from into an `analysis_error` that
    names the function and the clause, whatever `-eva-warn-key assigns:missing` was: the recursion
    downgrade (automatic or --allow-incomplete-recursion-specs) must not hide it under a recursion label.
    A timed-out run keeps its status; its error summary names the defect too.
    """
    log_text = _read_log(Path(res.get("log_file") or out_dir / "eva.log"))
    entries = missing_assigns_messages(log_text)
    defects = [e for e in entries if e["kind"] == "stub_from"]
    if not defects:
        return res
    lines = [stub_from_defect_message(e) for e in defects]
    recursive = sorted({e["function"] for e in entries if e["kind"] == "recursion"})
    if recursive:
        lines.append(
            "Eva also reports recursive calls without an assigns clause ("
            + ", ".join(recursive)
            + "); the recursion fallback applies to them once every \\from is written"
        )
    res["stub_assigns_without_from"] = [{k: e[k] for k in ("function", "location", "clause")} for e in defects]
    if res.get("status") in ("ok", "analysis_error"):
        res["status"] = "analysis_error"
        res["reason"] = "stub_assigns_without_from"
    res["error_summary"] = (lines + [x for x in res.get("error_summary") or [] if x not in lines])[:20]
    return res


DEFAULT_DAG_PATH = Path("workspace/reports/callgraph_dag.json")
_FLOW_BASE_IDENT_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)")
_NON_RETRYABLE_REASONS = frozenset(
    {"stub_assigns_without_from", "address_flow_missing_body", "address_flow_missing_global"}
)


def _normalize_source_path(path: str, mirror_root: str | None = None) -> str:
    """Normalize a slice source path to a repo-relative POSIX path."""
    p = str(path or "").replace("\\", "/").strip()
    if not p:
        return ""
    p = posixpath.normpath(p)
    prefixes: list[str] = []
    if mirror_root:
        root = posixpath.normpath(str(mirror_root).replace("\\", "/").strip()).rstrip("/")
        if root and root != ".":
            prefixes.append(root + "/")
    prefixes.extend(("/framac-run/", "/target/", "workspace/work/", "./"))
    changed = True
    while changed:
        changed = False
        for prefix in prefixes:
            if p.startswith(prefix):
                p = p[len(prefix) :]
                changed = True
    if "/workspace/work/" in p:
        p = p.split("/workspace/work/", 1)[1]
    p = p.lstrip("/")
    return "" if p == "." else p


def _flow_read_identifiers(res: dict) -> set[str]:
    """Base variable identifiers read in Eva's `-inout` report for `main_fn` (or all functions if absent)."""
    flows = res.get("flows")
    if isinstance(flows, dict) and "by_function" not in flows and flows.get("flows_file"):
        flows = resolve_flows(flows)
    by_function = flows.get("by_function") if isinstance(flows, dict) else None
    if not isinstance(by_function, dict) or not by_function:
        return set()
    main_fn = str(res.get("main_fn") or "eva_main")
    main_entry = by_function.get(main_fn)
    entries = (
        [main_entry]
        if isinstance(main_entry, dict)
        else [entry for entry in by_function.values() if isinstance(entry, dict)]
    )
    idents: set[str] = set()
    for entry in entries:
        for field in ("inputs", "operational_inputs", "operational_inputs_on_termination"):
            locs = entry.get(field)
            if not isinstance(locs, list):
                continue
            for loc in locs:
                if not isinstance(loc, str):
                    continue
                m = _FLOW_BASE_IDENT_RE.match(loc)
                if m:
                    idents.add(m.group(1))
    return idents


def reject_address_flow_gaps(
    res: dict,
    out_dir: Path,
    module: str,
    dag_path: Path | str | None,
    sources: list[str],
) -> dict:
    """
    Soundness gate for `address_flow` unit-split clusters (correction plan step C6):
    fail loudly when Eva calls a project function without a body or reads a non-static project
    global whose defining `.c` file was omitted from `sources`. Active only when `module` is a DAG
    submodule with `reach == "address_flow"`.
    """
    if not module or dag_path is None:
        return res
    path = Path(dag_path)
    if not path.is_file():
        return res
    try:
        dag = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return res
    if not isinstance(dag, dict):
        return res
    submodules = dag.get("submodules")
    if not isinstance(submodules, dict):
        return res
    sub = submodules.get(module)
    if not isinstance(sub, dict) or sub.get("reach") != unit_split.REACH_FLOW:
        return res

    lines: list[str] = []

    # 1. Missing project function bodies (Eva's `Neither code nor ...` on unit / linked_modules functions).
    unit = str(sub.get("unit") or "")
    _, closure_keys = unit_split.unit_closure_keys(dag, unit) if unit else ([], [])
    raw_functions = dag.get("functions")
    functions: dict = raw_functions if isinstance(raw_functions, dict) else {}
    project_fns: dict[str, list[tuple[str, dict]]] = {}
    for key in closure_keys:
        rec = functions.get(key)
        if not isinstance(rec, dict) or rec.get("is_static"):
            continue
        fname = str(rec.get("name") or key.rpartition("#")[2] or key)
        if fname:
            project_fns.setdefault(fname, []).append((key, rec))

    log_text = _read_log(Path(res.get("log_file") or out_dir / "eva.log"))
    seen_specs: dict[str, list[str]] = {}
    for spec in missing_spec_messages(log_text):
        if spec.benign or not spec.function or spec.function not in project_fns:
            continue
        bucket = seen_specs.setdefault(spec.function, [])
        for kind in spec.missing or ("specification",):
            if kind not in bucket:
                bucket.append(kind)

    missing_bodies: list[dict] = []
    for fname in sorted(seen_specs):
        entries = project_fns[fname]
        keys = sorted({k for k, _ in entries})
        files = sorted(
            {
                f
                for _, rec in entries
                for f in (unit_split._defining_c_files(rec) or ([str(rec["file"])] if rec.get("file") else []))
                if f
            }
        )
        missing = seen_specs[fname]
        missing_bodies.append({"function": fname, "keys": keys, "files": files, "missing": missing})
        where = f" (defined in {', '.join(files)})" if files else ""
        lines.append(
            f"address-flow cluster {module!r}: project function {fname!r}{where} has no body in Eva "
            f"(missing {', '.join(missing)}); add its defining source to the slice or fix address_flow reach"
        )

    # 2. Missing non-static project globals read by Eva without their defining `.c` file compiled.
    read_idents = _flow_read_identifiers(res)
    mirror_root = res.get("mirror_root") if isinstance(res.get("mirror_root"), str) else None
    norm_sources = {norm for s in sources if (norm := _normalize_source_path(s, mirror_root=mirror_root))}
    global_vars = dag.get("global_variables")
    globals_by_name: dict[str, list[tuple[str, list[str]]]] = {}
    if isinstance(global_vars, dict) and read_idents:
        for gid, grec in global_vars.items():
            if not isinstance(grec, dict) or grec.get("static"):
                continue
            def_files = [norm for f in unit_split._defining_c_files(grec) if (norm := _normalize_source_path(f))]
            if not def_files:
                continue
            gname = str(grec.get("name") or str(gid).rpartition("#")[2] or gid)
            if gname:
                globals_by_name.setdefault(gname, []).append((str(gid), def_files))

    missing_globals: list[dict] = []
    for gname in sorted(read_idents):
        g_entries = globals_by_name.get(gname)
        if not g_entries:
            continue
        all_def_files = sorted({f for _, dfs in g_entries for f in dfs})
        if any(f in norm_sources for f in all_def_files):
            continue
        ids = sorted({gid for gid, _ in g_entries})
        missing_globals.append({"global": gname, "ids": ids, "files": all_def_files})
        lines.append(
            f"address-flow cluster {module!r}: project global {gname!r} (defined in {', '.join(all_def_files)}) "
            "is read in Eva without its defining source compiled (extern globals are silently zero-initialized); "
            "add its defining source to the slice or fix address_flow reach"
        )

    if not missing_bodies and not missing_globals:
        return res
    if missing_bodies:
        res["missing_project_bodies"] = missing_bodies
    if missing_globals:
        res["missing_project_globals"] = missing_globals
    if res.get("status") == "ok":
        res["status"] = "analysis_error"
        res["reason"] = "address_flow_missing_body" if missing_bodies else "address_flow_missing_global"
    res["error_summary"] = (lines + [x for x in res.get("error_summary") or [] if x not in lines])[:20]
    return res


def _keep_timed_out_log(res: dict, out_dir: Path) -> None:
    """Move a timed-out run's eva.log aside (eva.timed_out.log) before a fallback run reuses the name."""
    log = out_dir / "eva.log"
    kept = out_dir / "eva.timed_out.log"
    try:
        if log.is_file():
            os.replace(log, kept)
            res["log_file"] = str(kept)
    except OSError:
        pass


def _keep_timed_out_flamegraph(out_dir: Path) -> Path | None:
    """Move a timed-out 5-domain run's non-empty flamegraph.txt aside before cvalue fallbacks run."""
    fg = out_dir / "flamegraph.txt"
    kept = out_dir / "flamegraph.timed_out.txt"
    try:
        if fg.is_file() and fg.stat().st_size > 0:
            os.replace(fg, kept)
            return kept
    except OSError:
        pass
    return None


def _restore_timed_out_flamegraph(kept: Path | None, out_dir: Path, res: dict) -> None:
    """Restore the timed-out 5-domain flamegraph.txt so shard planning reads the 5-domain profile."""
    if kept is None:
        return
    fg = out_dir / "flamegraph.txt"
    try:
        if kept.is_file():
            os.replace(kept, fg)
            res["flamegraph_file"] = str(fg)
    except OSError:
        pass


def _with_failed_fallbacks(timed_out: dict, tried: list[dict], fb_budget: int) -> dict:
    """
    The timed-out run's result when no fallback tier completed: its own limit stays in the first
    error line, and the tiers tried are named after it (each had `fb_budget` seconds).
    """
    res = dict(timed_out)
    if tried:
        res["timeout_fallback_tried"] = tried
        names = ", ".join(f"{t['tier']} ({t['status']})" for t in tried)
        res["error_summary"] = [
            *(timed_out.get("error_summary") or [])[:1],
            f"no fallback tier completed (each limited to {fb_budget} s): {names}",
            *(timed_out.get("error_summary") or [])[1:],
        ]
    return res


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
    flamegraph: bool = True,
    security_meta: dict | None = None,
) -> tuple[list[str], list[str]]:
    """
    `security_meta` (load_security_meta, with a `meta_file`) adds the sources its properties need and
    the meta file after `sources`, and META_STAGE before `-rte`; without it the command is unchanged.
    """
    if mlevel < 0:
        raise ValueError(f"mlevel must be >= 0 (got {mlevel})")
    meta_file = (security_meta or {}).get("meta_file")
    if meta_file:
        sources = [*sources, *((security_meta or {}).get("extra_sources") or [])]
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
            *([str(meta_file)] if meta_file else []),
            "-main",
            main_fn,
            *(META_STAGE if meta_file else ()),
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
            *(["-eva-flamegraph", str(out_dir / "flamegraph.txt")] if flamegraph else []),
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
        # check because the recursion boundary is then interpreted unsoundly. The same
        # key also covers contracts without \from: reject_stub_from_defects fails those.
        # Insert inside the Eva option group (before the next -then), not after -save.
        insert_at = cmd.index("-then", cmd.index("-eva"))
        cmd[insert_at:insert_at] = ["-eva-warn-key", "assigns:missing=warning"]
        reduced_checks.append(RECURSION_REDUCED_CHECK)
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
    security_meta: dict | None = None,
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
    summary = summarize_report(rows, security_meta)

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

    # One line per distinct stack instead of one per analysed call, before anything reads, caches or
    # copies it (eva_flamegraph.fold_flamegraph: lossless for every reader).
    if flamegraph_path.is_file():
        fold_flamegraph(flamegraph_path)
    # Where a run that hit its time limit spent that time (eva_flamegraph.cost_profile), the limit it hit
    # and how long it ran: a fallback tier's report keeps this profile, and Eva shard planning floors
    # the timed-out run's time to these, not to whatever the module's limit is by then.
    profile = cost_profile(flamegraph_path) if timed_out else None
    return {
        **(
            {"cost_profile": {"run": "timed_out", "timeout_s": timeout, "elapsed_s": elapsed_s, **profile}}
            if profile
            else {}
        ),
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
            "ACSL assigns clause to a warning and continue (recorded in reduced_checks). A contract "
            "assigns clause without \\from still fails the run (reason stub_assigns_without_from)."
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
        "--no-timeout-fallback",
        action="store_true",
        help="On a timeout, do not retry with the faster, less precise cvalue tiers (tuning rungs).",
    )
    parser.add_argument(
        "--no-flamegraph",
        action="store_true",
        help="Do not write flamegraph.txt (-eva-flamegraph): tuning rungs, whose profile nobody reads.",
    )
    parser.add_argument(
        "--mirror-root",
        default=None,
        help="Where --loop-unroll writes its mirror (default: under --out-dir).",
    )
    parser.add_argument(
        "--security-props",
        default=None,
        metavar="PATH|none",
        help=(
            "security_props.json to load MetAcsl properties from, when its meta_engines holds eva "
            f"(default: ${SECURITY_PROPS_ENV}, else {DEFAULT_SECURITY_PROPS.as_posix()} when it exists; `none`: never)."
        ),
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

    # The harness this report stands for, taken before the run (a cache hit included: the restored
    # result describes these sources, so it gets the stamp of the harness that is current now).
    harness = phase0_gates.harness_digest(Path("."), args.module, ignore_exempt=True) if args.module else None
    props = resolve_security_props(args.security_props)
    # Only pass security_props when a file exists; pass module whenever set so address-flow
    # soundness checks run inside _exec before the cache decides whether to store the entry.
    extra_slice_kwargs: dict = {}
    if props:
        extra_slice_kwargs["security_props"] = props
    if props or args.module:
        extra_slice_kwargs["module"] = args.module
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
        timeout_fallback=not args.no_timeout_fallback,
        flamegraph=not args.no_flamegraph,
        **extra_slice_kwargs,
    )
    if args.module and DEFAULT_DAG_PATH.is_file():
        sec = res.get("security_props")
        extra_sources = list(sec.get("extra_sources") or []) if isinstance(sec, dict) else []
        res = reject_address_flow_gaps(
            res, args.out_dir, args.module, DEFAULT_DAG_PATH, [*args.sources, *extra_sources]
        )
    res["module"] = args.module
    res["harness_digest"] = harness
    disk_res = spill_large_flows(res, args.out_dir / "flows.json", report_path=args.out_json)
    atomic_write_json(args.out_json, disk_res)
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
                **({"timeout_fallback": res["timeout_fallback"]} if res.get("timeout_fallback") else {}),
                **({"cost_profile": res["cost_profile"]} if res.get("cost_profile") else {}),
                **(
                    {"missing_project_bodies": res["missing_project_bodies"]}
                    if res.get("missing_project_bodies")
                    else {}
                ),
                **(
                    {"missing_project_globals": res["missing_project_globals"]}
                    if res.get("missing_project_globals")
                    else {}
                ),
                **(
                    {
                        "security_props": {
                            key: res["security_props"][key]
                            for key in ("properties", "error", "skipped", "counts")
                            if key in res["security_props"]
                        }
                    }
                    if isinstance(res.get("security_props"), dict)
                    else {}
                ),
            },
            indent=2,
        )
    )
    return 0 if res["status"] == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
