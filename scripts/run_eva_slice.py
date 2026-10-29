#!/usr/bin/env python3
"""
Drives Frama-C Eva + RTE on a module slice, parses the resulting property status
table (alarms.csv) into Valid (Green), Unknown (Orange), Invalid (Red), Dead
(unreachable under the harness) and Assumed ("Considered valid") buckets,
extracts the surviving 'Unknown' functions for Phase 3 (/framac-wp), and emits SARIF.
A failed Frama-C run is reported as status "analysis_error", never as zero alarms.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from framac_common import (  # noqa: E402
    STATUS_ASSUMED,
    STATUS_DEAD,
    STATUS_INVALID,
    STATUS_INVALID_UNDER_HYP,
    STATUS_NEVER_TRIED,
    STATUS_UNKNOWN,
    STATUS_VALID,
    STATUS_VALID_UNDER_HYP,
    read_report_csv,
)


def run_eva_on_slice(
    sources: list[str],
    main_fn: str,
    out_dir: Path,
    machdep: str = "gcc_x86_64",
    cppflags: str = "-I.",
    slevel: int = 100,
    warn_invalid_pointer: bool = True,
    warn_unsigned: bool = True,
) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "alarms.csv"
    red_csv = out_dir / "red_alarms.csv"
    sav_path = out_dir / "framac.sav"
    sarif_path = out_dir / "slice.sarif"
    log_path = out_dir / "eva.log"

    cmd = [
        "frama-c",
        "-pp-annot",
        "-no-unicode",
        "-machdep", machdep,
        "-warn-signed-overflow",
        "-warn-signed-downcast",
        "-warn-invalid-shift",
        "-warn-pointer-downcast",
    ]
    reduced_checks: list[str] = []
    if warn_invalid_pointer:
        cmd.append("-warn-invalid-pointer")
    else:
        reduced_checks.append("-no-warn-invalid-pointer")
    if warn_unsigned:
        cmd.extend(["-warn-unsigned-overflow", "-warn-unsigned-downcast"])
    else:
        reduced_checks.extend(["-no-warn-unsigned-overflow", "-no-warn-unsigned-downcast"])

    cmd.extend([
        f"-cpp-extra-args={cppflags}",
        *sources,
        "-main", main_fn,
        "-rte",
        "-then", "-eva",
        "-eva-domains", "cvalue,equality,symbolic-locations,octagon,gauges",
        "-eva-slevel", str(slevel),
        "-eva-auto-loop-unroll", "32",
        "-eva-report-red-statuses", str(red_csv),
        "-then", "-metrics", "-metrics-eva-cover",
        "-then", "-report", "-report-csv", str(csv_path),
        "-save", str(sav_path),
    ])

    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    log_path.write_text((proc.stdout or "") + "\n" + (proc.stderr or ""), encoding="utf-8")

    # Generate SARIF from saved state if sav_path was produced
    if sav_path.exists():
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
    status = "ok" if proc.returncode == 0 and csv_path.exists() else "analysis_error"

    return {
        "status": status,
        "returncode": proc.returncode,
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


def main() -> int:
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
    args = parser.parse_args()

    res = run_eva_on_slice(
        sources=args.sources,
        main_fn=args.main,
        out_dir=args.out_dir,
        machdep=args.machdep,
        cppflags=args.cppflags,
        slevel=args.slevel,
        warn_invalid_pointer=not args.no_warn_invalid_pointer,
        warn_unsigned=not args.no_warn_unsigned,
    )
    res["module"] = args.module
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": res["status"],
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
