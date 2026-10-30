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
eva.log and slice.sarif instead of re-running Eva (the .sav is not cached).
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
}


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
    warn_invalid_pointer: bool = True,
    warn_unsigned: bool = True,
    warn_unsigned_downcast: bool = True,
    timeout: int | None = None,
    extra_domains: list[str] | str | None = None,
    use_cache: bool = True,
) -> dict:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "alarms.csv"
    red_csv = out_dir / "red_alarms.csv"
    sav_path = out_dir / "framac.sav"
    sarif_path = out_dir / "slice.sarif"
    # A report left over from an earlier run must never be read as this run's result.
    for stale in (csv_path, red_csv, sav_path, sarif_path):
        if stale.exists():
            stale.unlink()

    cmd, reduced_checks = _eva_command(
        sources, main_fn, out_dir, machdep, cppflags, slevel, warn_invalid_pointer, warn_unsigned,
        warn_unsigned_downcast, extra_domains,
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
) -> tuple[list[str], list[str]]:
    csv_path = out_dir / "alarms.csv"
    red_csv = out_dir / "red_alarms.csv"
    sav_path = out_dir / "framac.sav"
    cmd = [
        "frama-c",
        "-pp-annot",
        "-no-unicode",
        "-machdep", machdep,
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
    cmd.extend([
        f"-cpp-extra-args={effective_cppflags}",
        *sources,
        "-main", main_fn,
        "-rte",
        "-then", "-eva",
        "-eva-domains", eva_domains(extra_domains),
        "-eva-slevel", str(slevel),
        "-eva-auto-loop-unroll", "32",
        "-eva-report-red-statuses", str(red_csv),
        "-then", "-metrics", "-metrics-eva-cover",
        "-then", "-report", "-report-csv", str(csv_path),
        "-save", str(sav_path),
    ])
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

    # Generate SARIF from saved state if sav_path was produced
    if sav_path.exists() and not timed_out:
        sarif_cmd = [
            "frama-c",
            "-load", str(sav_path),
            "-mdr-gen", "sarif",
            "-mdr-no-print-libc",
            "-mdr-out", str(sarif_path),
        ]
        subprocess.run(sarif_cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")

    alarms_by_status: dict[str, list[dict]] = {
        "Valid": [], "Unknown": [], "Invalid": [], "Dead": [], "Assumed": [], "Other": [],
    }
    unknown_by_function: dict[str, list[dict]] = defaultdict(list)
    functions_with_properties = set()

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

    total_checked = (
        len(alarms_by_status["Valid"])
        + len(alarms_by_status["Unknown"])
        + len(alarms_by_status["Invalid"])
    )
    discharged_pct = (
        round(100.0 * len(alarms_by_status["Valid"]) / total_checked, 2)
        if total_checked > 0
        else 0.0
    )

    # A failed Frama-C run or a missing report must never look like "0 alarms".
    reason = None
    if timed_out:
        status = "analysis_timeout"
        error_summary = [f"Frama-C Eva exceeded the {timeout} s wall-clock limit"] + extract_error_summary(combined_log)[-5:]
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
        "invalid_alarms": alarms_by_status["Invalid"],
        "dead_alarms": alarms_by_status["Dead"],
        "assumed_properties": alarms_by_status["Assumed"],
        "reduced_checks": reduced_checks,
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
    args = parser.parse_args(argv)
    timeout = CLASSES["eva"].wall_timeout_s if args.timeout is None else args.timeout
    try:
        eva_domains(args.extra_domains)
    except ValueError as exc:
        parser.error(str(exc))

    res = run_eva_on_slice(
        sources=args.sources,
        main_fn=args.main,
        out_dir=args.out_dir,
        machdep=args.machdep,
        cppflags=args.cppflags,
        slevel=args.slevel,
        warn_invalid_pointer=not args.no_warn_invalid_pointer,
        warn_unsigned=not args.no_warn_unsigned,
        warn_unsigned_downcast=not args.no_warn_unsigned_downcast,
        timeout=timeout or None,
        extra_domains=args.extra_domains,
    )
    res["module"] = args.module
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
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
    }, indent=2))
    return 0 if res["status"] == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
