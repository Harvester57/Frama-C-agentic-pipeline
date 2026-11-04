#!/usr/bin/env python3
"""
Drives Frama-C Eva + RTE on a module slice, parses the resulting property status
table (alarms.csv) into Valid (Green), Unknown (Orange), Invalid (Red), Dead
(unreachable under the harness) and Assumed ("Considered valid") buckets,
extracts the surviving 'Unknown' functions for Phase 3 (/framac-wp), and emits SARIF.
A failed Frama-C run is reported as status "analysis_error", never as zero alarms.

Inside a run directory, a report with status "ok" is cached (scripts/cache.py, namespace `eva`)
under the toolchain, the Eva command line, the output directory and the content of every source
and header it includes; an identical later run restores the report, alarms.csv, red_alarms.csv,
eva.log, slice.sarif and flows.log instead of re-running Eva (the .sav is not cached).

After a successful run, read and write sets are taken from the saved session in a separate
Frama-C process (`-load framac.sav -deps -inout -input -out-external -cg`), so they can neither
change Eva's status nor its timing. The report carries them as `flows`, by kernel function name:
hints about this harness, used for the provers' briefs (function_facts.py), never a verdict.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
import sys
from collections import defaultdict
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
from framac_common import (  # noqa: E402
    STATUS_ASSUMED,
    STATUS_DEAD,
    STATUS_INVALID,
    STATUS_INVALID_UNDER_HYP,
    STATUS_NEVER_TRIED,
    STATUS_UNKNOWN,
    STATUS_VALID,
    STATUS_VALID_UNDER_HYP,
    augment_framac_cppflags,
    failure_reason,
    normalize_flag_args,
    read_report_csv,
    scan_undeclared_functions,
)
from resources import CLASSES  # noqa: E402

BASE_DOMAINS = ("cvalue", "equality", "symbolic-locations", "octagon", "gauges")
_DOMAIN_RE = re.compile(r"^[a-z][a-z0-9_-]*$")
# Report files restored from the cache; the .sav is never cached.
_CACHED_OUTPUTS = {
    "alarms.csv": "csv_file",
    "red_alarms.csv": None,
    "eva.log": "log_file",
    "slice.sarif": "sarif_file",
    "flows.log": None,
    "flows.cg.dot": None,
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


def eva_domains(extra_domains: list[str] | str | None = None) -> str:
    """`-eva-domains` value: the base domains plus extra ones (e.g. `taint`), deduplicated."""
    if isinstance(extra_domains, str):
        extra_domains = extra_domains.split(",")
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
) -> dict:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "alarms.csv"
    red_csv = out_dir / "red_alarms.csv"
    sav_path = out_dir / "framac.sav"
    sarif_path = out_dir / "slice.sarif"
    # A report left over from an earlier run must never be read as this run's result.
    for stale in (csv_path, red_csv, sav_path, sarif_path, out_dir / "flows.log", out_dir / "flows.cg.dot"):
        if stale.exists():
            stale.unlink()

    cmd, reduced_checks = _eva_command(
        sources,
        main_fn,
        out_dir,
        machdep,
        cppflags,
        slevel,
        warn_invalid_pointer,
        warn_unsigned,
        warn_unsigned_downcast,
        extra_domains,
        mlevel=mlevel,
        allow_incomplete_recursion_specs=allow_incomplete_recursion_specs,
    )

    def _run() -> dict:
        return _execute_eva(cmd, sources, main_fn, out_dir, reduced_checks, timeout)

    if not use_cache:
        res = _run()
        res["cache"] = {"hit": False, "key": None}
        return res

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

    material = {"kind": "eva", "command": cmd, "sources": list(sources), "out_dir": out_dir.as_posix()}
    return cache.memoize(
        "eva",
        material,
        sources=sources,
        dep_flags=shlex.split(augment_framac_cppflags(cppflags)),
        build=_run,
        outputs=lambda res: {name: out_dir / name for name in _CACHED_OUTPUTS},
        ok=lambda res: res.get("status") == "ok",
        restore_map=_restore_map,
        on_restore=_on_restore,
    )


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
) -> tuple[list[str], list[str]]:
    if mlevel < 0:
        raise ValueError(f"mlevel must be >= 0 (got {mlevel})")
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
            eva_domains(extra_domains),
            "-eva-slevel",
            str(slevel),
            "-eva-auto-loop-unroll",
            "32",
            "-eva-report-red-statuses",
            str(red_csv),
            "-then",
            "-metrics",
            "-metrics-eva-cover",
            "-then",
            "-report",
            "-report-csv",
            str(csv_path),
            "-save",
            str(sav_path),
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


def _execute_eva(
    cmd: list[str],
    sources: list[str],
    main_fn: str,
    out_dir: Path,
    reduced_checks: list[str],
    timeout: int | None,
) -> dict:
    csv_path = out_dir / "alarms.csv"
    sav_path = out_dir / "framac.sav"
    sarif_path = out_dir / "slice.sarif"
    log_path = out_dir / "eva.log"

    timed_out = False
    returncode: int | None
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        returncode, stdout, stderr = proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        timed_out, returncode = True, None
        stdout = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
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

    if csv_path.exists():
        for row in read_report_csv(csv_path):
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
        "total_properties": total_checked,
        "valid_count": len(alarms_by_status["Valid"]),
        "unknown_count": len(alarms_by_status["Unknown"]),
        "invalid_count": len(alarms_by_status["Invalid"]),
        "dead_count": len(alarms_by_status["Dead"]),
        "assumed_count": len(alarms_by_status["Assumed"]),
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
        "reduced_checks": reduced_checks,
        "flows": flows,
        "sarif_file": str(sarif_path) if sarif_path.exists() else None,
        "csv_file": str(csv_path) if csv_path.exists() else None,
        "sav_file": str(sav_path) if sav_path.exists() else None,
        "log_file": str(log_path),
    }


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
    raw = list(argv) if argv is not None else sys.argv[1:]
    args = parser.parse_args(normalize_flag_args(raw, ("--cppflags",)))
    timeout = CLASSES["eva"].wall_timeout_s if args.timeout is None else args.timeout
    try:
        eva_domains(args.extra_domains)
    except ValueError as exc:
        parser.error(str(exc))
    if args.mlevel < 0:
        parser.error("--mlevel must be >= 0")

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
