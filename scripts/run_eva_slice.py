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
an identical later run restores the report, alarms.csv, red_alarms.csv, eva.log and slice.sarif
instead of re-running Eva (the .sav is not cached).

Tuning comes in two forms, both recorded in the report: `--eva-option name=value`, allowlisted by
eva_options.py, and `--loop-unroll file#function#ordinal=N`, which analyses a scratch mirror of the
sources (eva_loops.py) and maps its paths back, so workspace/work is never touched.
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
    for stale in (csv_path, red_csv, sav_path, sarif_path):
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
        res["eva_options"] = options
        res["loop_unroll"] = [ref.to_json() for ref in applied]
        res["loop_unroll_dropped"] = [ref.to_json() for ref in dropped]
        res["input_digest"] = input_digest
        return res

    def _run() -> dict:
        return _execute_eva(cmd, eff_sources, main_fn, out_dir, reduced_checks, timeout, path_root=path_root)

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
    outputs_in_cmd = {str(out_dir / name): f"<out>/{name}" for name in ("alarms.csv", "red_alarms.csv", "framac.sav")}
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
    # These two always appear on the command line; an option only changes their value.
    slevel = options.pop("slevel", slevel)
    auto_loop_unroll = options.pop("auto-loop-unroll", DEFAULT_AUTO_LOOP_UNROLL)
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
            eva_domains(domains),
            "-eva-slevel",
            str(slevel),
            "-eva-auto-loop-unroll",
            str(auto_loop_unroll),
            *framac_args(options),
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

    # Generate SARIF from saved state if sav_path was produced
    if sav_path.exists() and not timed_out:
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
