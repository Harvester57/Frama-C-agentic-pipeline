#!/usr/bin/env python3
"""
Split link units too large for one Eva run into sub-modules (docs/phase0-implementation-plan.md step I8).
Stdlib only.

    unit_split.py show [--dag workspace/reports/callgraph_dag.json] [--max-functions N] [--max-lines N]

A unit is split when it has more than MAX_FUNCTIONS functions or MAX_LINES lines of function bodies
(calibrated on CryptoLib's and QCBOR's Eva times, see the plan's I8 notes). Clustering is anchored on
the unit's API entry points:

  1. each entry point starts a cluster: the functions of the unit it reaches in the call graph
     (direct and indirect edges);
  2. two clusters merge when they overlap above OVERLAP (shared functions over the smaller
     cluster's size), the most overlapping pair first, whatever the merged size: code two entry
     points mostly share is analysed once (an entry point whose whole reach lies inside another's
     joins it);
  3. clusters smaller than MIN_FUNCTIONS (getters, setters, one-call wrappers) are packed, within
     MAX_FUNCTIONS, into the cluster they share most functions with, else one whose anchors are
     in the same source file, else another small cluster, else the smallest cluster, so a unit does
     not get a harness per getter;
  4. functions no entry point reaches belong to no cluster (no harness reaches them either).

A single entry point whose own reach exceeds MAX_FUNCTIONS stays one cluster: Eva starts from the
entry point and needs all of it.

The clusters become the unit's sub-modules (scripts/module_map.py), in the DAG's `submodules` map:

    submodules.<name> = {module, unit, kind: "cluster", anchors (its entry points),
                         candidate_entry_points, functions, function_count, lines, files, tier ...}

named `<unit>__<file stem>` after the source file holding most of its anchors. A harness module named
after one (`--unit <unit>` in its sidecar) runs under its unit's sources and flags; its scope at the
reachability gate is the cluster's functions, its tier the highest of theirs. The unit's record gets
`split` (the reason, the thresholds, its sub-modules, the unclustered functions), and the DAG gets
`unit_split` (thresholds and one row per unit, split or not).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, deque
from pathlib import Path, PurePosixPath
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import tiers  # noqa: E402

# Calibrated in step I8 (plan notes): Eva on a harness reaching ~100-200 functions finishes in 1-4
# minutes on the benchmark, far inside the 30-minute cap; a whole CryptoLib unit does not.
MAX_FUNCTIONS = 150
MAX_LINES = 5000
OVERLAP = 0.5
MIN_FUNCTIONS = 10
_NAME_JUNK = re.compile(r"[^A-Za-z0-9_]+")


def fn_lines(rec: dict) -> int:
    loc = rec.get("loc")
    if isinstance(loc, int) and loc > 0:
        return loc
    start, end = rec.get("line"), rec.get("end_line")
    if isinstance(start, int) and isinstance(end, int) and end >= start:
        return end - start + 1
    return 0


def unit_size(functions: dict[str, dict], keys: list[str]) -> tuple[int, int]:
    """(functions, lines) of a set of DAG keys."""
    return len(keys), sum(fn_lines(functions.get(k) or {}) for k in keys)


def reach(functions: dict[str, dict], start: str, within: set[str]) -> set[str]:
    seen = {start}
    queue = deque([start])
    while queue:
        cur = queue.popleft()
        for callee in (functions.get(cur) or {}).get("internal_callees") or []:
            if callee in within and callee not in seen:
                seen.add(callee)
                queue.append(callee)
    return seen


def _overlap(a: set[str], b: set[str]) -> float:
    small = min(len(a), len(b))
    return len(a & b) / small if small else 0.0


def cluster(
    functions: dict[str, dict],
    keys: list[str],
    entries: list[str],
    max_functions: int = MAX_FUNCTIONS,
    overlap: float = OVERLAP,
    min_functions: int = MIN_FUNCTIONS,
) -> list[dict[str, Any]]:
    """Clusters [{anchors, functions}] of one unit, deterministic (see the module docstring)."""
    within = set(keys)
    clusters: list[dict[str, Any]] = []
    for e in dict.fromkeys(e for e in entries if e in within):
        clusters.append({"anchors": [e], "functions": reach(functions, e, within)})

    def fits(a: dict, b: dict) -> bool:
        fa, fb = a["functions"], b["functions"]
        return fa <= fb or fb <= fa or len(fa | fb) <= max_functions

    def merge(i: int, j: int) -> None:
        a, b = clusters[i], clusters[j]
        a["anchors"] = a["anchors"] + b["anchors"]
        a["functions"] = a["functions"] | b["functions"]
        del clusters[j]

    # Step 2: overlap merging, the most overlapping pair first (ties: earlier clusters first).
    while True:
        best: tuple[float, int, int] | None = None
        for i in range(len(clusters)):
            for j in range(i + 1, len(clusters)):
                ov = _overlap(clusters[i]["functions"], clusters[j]["functions"])
                if ov > overlap and (best is None or ov > best[0]):
                    best = (ov, i, j)
        if best is None:
            break
        merge(best[1], best[2])

    # Step 3: pack small clusters.
    def file_of(c: dict) -> str:
        files = Counter(str((functions.get(a) or {}).get("file") or "") for a in c["anchors"])
        return sorted(files.items(), key=lambda kv: (-kv[1], kv[0]))[0][0] if files else ""

    stuck: set[str] = set()  # first anchors of small clusters nothing can take
    while len(clusters) > 1:
        small = [
            i for i, c in enumerate(clusters) if len(c["functions"]) < min_functions and c["anchors"][0] not in stuck
        ]
        if not small:
            break
        i = min(small, key=lambda k: (len(clusters[k]["functions"]), clusters[k]["anchors"][0]))
        c = clusters[i]
        options = []
        for j, other in enumerate(clusters):
            if j == i or not fits(c, other):
                continue
            shared = len(c["functions"] & other["functions"])
            same_file = file_of(c) == file_of(other)
            other_small = len(other["functions"]) < min_functions
            # Most shared functions, then the same file, then another small cluster, then the smallest.
            options.append(((-shared, not same_file, not other_small, len(other["functions"]), j), j))
        if not options:
            stuck.add(c["anchors"][0])
            continue
        j = min(options)[1]
        a, b = (j, i) if j < i else (i, j)
        merge(a, b)
    return clusters


def _name(unit: str, c: dict, functions: dict[str, dict], taken: set[str]) -> str:
    stems = Counter(PurePosixPath(str((functions.get(a) or {}).get("file") or "x")).stem for a in c["anchors"])
    stem = sorted(stems.items(), key=lambda kv: (-kv[1], kv[0]))[0][0] if stems else "part"
    base = f"{unit}__{_NAME_JUNK.sub('_', stem).strip('_') or 'part'}"[:120]
    name, n = base, 2
    while name in taken:
        name, n = f"{base}_{n}", n + 1
    taken.add(name)
    return name


def apply(
    dag: dict,
    max_functions: int = MAX_FUNCTIONS,
    max_lines: int = MAX_LINES,
    overlap: float = OVERLAP,
    min_functions: int = MIN_FUNCTIONS,
) -> dict:
    """Split the DAG's oversized link units (in place, and returned). Only link-unit DAGs are split."""
    functions: dict[str, dict] = dag.get("functions") or {}
    modules: dict[str, dict] = dag.get("modules") or {}
    rows: dict[str, dict] = {}
    submodules: dict[str, dict] = {}
    if dag.get("module_kind") == "link_unit":
        taken = set(modules) | set(dag.get("lexer_modules") or {})
        for unit, rec in sorted(modules.items()):
            keys = [k for k in rec.get("functions") or [] if k in functions]
            n_fns, n_lines = unit_size(functions, keys)
            row: dict[str, Any] = {"functions": n_fns, "lines": n_lines, "split": False}
            rows[unit] = row
            if n_fns <= max_functions and n_lines <= max_lines:
                continue
            entries = [e for e in rec.get("candidate_entry_points") or [] if e in functions]
            clusters = cluster(functions, keys, entries, max_functions, overlap, min_functions)
            if len(clusters) < 2:
                row["note"] = "above the threshold, but its entry points form a single cluster"
                continue
            names = []
            covered: set[str] = set()
            for c in clusters:
                name = _name(unit, c, functions, taken)
                fns = sorted(c["functions"])
                covered |= c["functions"]
                c_fns, c_lines = unit_size(functions, fns)
                submodules[name] = {
                    "module": name,
                    "unit": unit,
                    "kind": "cluster",
                    "anchors": c["anchors"],
                    "candidate_entry_points": c["anchors"],
                    "functions": fns,
                    "function_count": c_fns,
                    "lines": c_lines,
                    "files": sorted({str(functions[k].get("file")) for k in fns if functions[k].get("file")}),
                    **tiers.module_fields(functions, fns, rec.get("tier")),
                }
                names.append(name)
            unclustered = sorted(set(keys) - covered)
            why = []
            if n_fns > max_functions:
                why.append(f"{n_fns} functions > {max_functions}")
            if n_lines > max_lines:
                why.append(f"{n_lines} lines > {max_lines}")
            rec["split"] = {"reason": ", ".join(why), "submodules": names, "unclustered": unclustered}
            row.update(split=True, submodules=len(names), unclustered=len(unclustered))
    dag["submodules"] = submodules
    dag["unit_split"] = {
        "max_functions": max_functions,
        "max_lines": max_lines,
        "overlap": overlap,
        "min_functions": min_functions,
        "units": rows,
    }
    return dag


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0] if __doc__ else None)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("show", help="Print the clusters of the DAG's units (does not write the DAG)")
    s.add_argument("--dag", type=Path, default=Path("workspace/reports/callgraph_dag.json"))
    s.add_argument("--max-functions", type=int, default=MAX_FUNCTIONS)
    s.add_argument("--max-lines", type=int, default=MAX_LINES)
    s.add_argument("--overlap", type=float, default=OVERLAP)
    s.add_argument("--min-functions", type=int, default=MIN_FUNCTIONS)
    a = p.parse_args(argv)
    try:
        dag = json.loads(a.dag.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"error: {a.dag}: {exc}", file=sys.stderr)
        return 2
    for rec in (dag.get("modules") or {}).values():
        if isinstance(rec, dict):
            rec.pop("split", None)
    apply(dag, a.max_functions, a.max_lines, a.overlap, a.min_functions)
    out = {
        "unit_split": dag["unit_split"],
        "submodules": {
            n: {k: s[k] for k in ("unit", "function_count", "lines", "tier")} | {"anchors": len(s["anchors"])}
            for n, s in dag["submodules"].items()
        },
    }
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
