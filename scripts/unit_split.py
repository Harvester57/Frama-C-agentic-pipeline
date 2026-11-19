#!/usr/bin/env python3
"""
Split link units too large for one Eva run into sub-modules (docs/plans/archive/phase0-implementation-plan.md step I8;
the address-flow reach: docs/plans/unit-split-address-flow.md). Stdlib only.

    unit_split.py show [--dag workspace/reports/callgraph_dag.json] [--max-functions N] [--max-lines N]

A unit is split when its entry points reach more than MAX_FUNCTIONS functions or MAX_LINES lines of
function bodies (what one harness driving its whole API gives Eva; calibrated on CryptoLib's and
QCBOR's Eva times, see the plan's I8 notes). Clustering is anchored on the unit's API entry points:

  1. each entry point starts a cluster: the functions of the unit it reaches (`reach` below);
  2. two clusters merge when they overlap above OVERLAP (shared functions over the smaller
     cluster's size), the most overlapping pair first, and only when the merged cluster still fits
     MAX_FUNCTIONS and MAX_LINES: code two entry points mostly share is analysed once (an entry
     point whose whole reach lies inside another's joins it), but no merge makes a cluster that
     the split's own calibration says one Eva run cannot take;
  3. clusters smaller than MIN_FUNCTIONS (getters, setters, one-call wrappers) are packed, within
     the same limits, into the cluster they share most functions with, else one whose anchors are
     in the same source file, else another small cluster, else the smallest cluster, so a unit does
     not get a harness per getter;
  4. functions no entry point reaches belong to no cluster (no harness reaches them either).

A single entry point whose own reach exceeds the limits stays one cluster: Eva starts from the
entry point and needs all of it. Such a cluster is marked `over_limit` (the reason), and no other
cluster is merged or packed into it.

Reach. With the model's address-flow facts (every function of the unit has `address_refs`; the DAG
has `global_variables` with their initializers; phase0_dump.ml schema 6), a cluster's reach is the
*address-flow reach* of its anchors, computed to a fixpoint:

  - a reached function's direct callees (every edge that is not only an indirect site's type match:
    direct calls, and callbacks a function passes to the library, `callback-arg` / `thread-spawn`);
  - the addresses a reached function takes (`address_refs`) and the globals it names (`global_refs`),
    then, through the initializers of those globals, the functions and globals they name
    (`init_functions`, `init_globals`, transitively): the pool of function addresses the cluster's
    executions can hold;
  - at an indirect call site of a reached function, the type-matched candidates
    (`indirect_callees`) whose address is in that pool.

A generated harness never forges a function pointer (a function pointer in a struct it builds stays
NULL, a callback parameter is a stub of its own: scripts/api_harness.py), and Eva starts from the
globals' initializers, so a function pointer the cluster's code can call holds an address taken in
reached code or in the initializer of a global that code reads. A type-matched candidate whose
address is only taken elsewhere is unreachable from the cluster's harness, by fuzzing or by Eva.
Without those facts (an older model), the reach is the call graph's, over every edge.

The clusters become the unit's sub-modules (scripts/module_map.py), in the DAG's `submodules` map:

    submodules.<name> = {module, unit, kind: "cluster", reach, anchors (its entry points),
                         candidate_entry_points, functions, function_count, lines, files, tier ...,
                         [over_limit], [globals, build_sources, link_stubs]}

named `<unit>__<file stem>` after the source file holding most of its anchors. A harness module named
after one (`--unit <unit>` in its sidecar) runs under its unit's flags; its scope at the reachability
gate is the cluster's functions, its tier the highest of theirs. With the address-flow reach, a cluster
also lists the globals it reads (`globals`), the sources its builds compile (`build_sources`: the .c
files defining its functions and those globals) and what those files name that is defined outside
them (`link_stubs`: `functions`, linked as stubs that abort when called, and `globals`, defined
zero-initialized). Neither kind is reachable from the cluster's harness, by the reach above. The
unit's record gets `split` (the reason, the thresholds, its sub-modules, the unclustered functions),
and the DAG gets `unit_split` (thresholds and one row per unit, split or not).
"""

from __future__ import annotations

import argparse
import heapq
import json
import re
import sys
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import tiers  # noqa: E402

# Calibrated in step I8 (plan notes): the slowest benchmark harnesses cost Eva about 2 s per reached
# function (QCBOR's spiffy decode, 102 functions, 205 s) and 0.05 s per line; a harness driving all of
# CryptoLib's API (231 reached functions, 12.7k lines) converges in 61 s. These limits keep a unit's
# Eva run at half the 30-minute cap at the worst observed rate.
MAX_FUNCTIONS = 400
MAX_LINES = 15000
OVERLAP = 0.5
MIN_FUNCTIONS = 10
REACH_FLOW = "address_flow"
REACH_CALLS = "call_graph"
_NAME_JUNK = re.compile(r"[^A-Za-z0-9_]+")


def fn_lines(rec: dict) -> int:
    loc = rec.get("loc")
    if isinstance(loc, int) and loc > 0:
        return loc
    start, end = rec.get("line"), rec.get("end_line")
    if isinstance(start, int) and isinstance(end, int) and end >= start:
        return end - start + 1
    return 0


def unit_size(functions: dict[str, dict], keys: list[str] | set[str]) -> tuple[int, int]:
    """(functions, lines) of a set of DAG keys."""
    return len(keys), sum(fn_lines(functions.get(k) or {}) for k in keys)


def reach(functions: dict[str, dict], start: str, within: set[str]) -> set[str]:
    """The call graph's reach of `start` within `within`, over every edge (direct and indirect)."""
    seen = {start}
    queue = [start]
    while queue:
        cur = queue.pop()
        for callee in (functions.get(cur) or {}).get("internal_callees") or []:
            if callee in within and callee not in seen:
                seen.add(callee)
                queue.append(callee)
    return seen


def has_flow_facts(functions: dict[str, dict], keys: list[str]) -> bool:
    """Whether every function of `keys` carries the model's address-flow facts (schema 6 dumps)."""
    return bool(keys) and all(isinstance((functions.get(k) or {}).get("address_refs"), list) for k in keys)


def flow_reach(
    functions: dict[str, dict], global_vars: dict[str, dict], starts: list[str], within: set[str]
) -> tuple[set[str], set[str]]:
    """
    The address-flow reach of `starts` within `within` (module docstring): the functions reached and
    the globals they name, with those the globals' initializers name.
    """
    reached: set[str] = set()
    pool: set[str] = set()  # function addresses the reached code and data hold
    globs: set[str] = set()
    with_sites: list[str] = []  # reached functions with indirect callees
    work = [s for s in starts if s in within]
    gwork: list[str] = []
    while work:
        while work:
            f = work.pop()
            if f in reached:
                continue
            reached.add(f)
            rec = functions.get(f) or {}
            indirect = set(rec.get("indirect_callees") or [])
            for c in rec.get("internal_callees") or []:
                if c in within and c not in reached and c not in indirect:
                    work.append(c)
            pool.update(rec.get("address_refs") or [])
            for g in rec.get("global_refs") or []:
                if g not in globs:
                    globs.add(g)
                    gwork.append(g)
            if indirect:
                with_sites.append(f)
            while gwork:
                grec = global_vars.get(gwork.pop()) or {}
                pool.update(grec.get("init_functions") or [])
                for g2 in grec.get("init_globals") or []:
                    if g2 not in globs:
                        globs.add(g2)
                        gwork.append(g2)
        for f in with_sites:
            for c in (functions.get(f) or {}).get("indirect_callees") or []:
                if c in pool and c in within and c not in reached:
                    work.append(c)
    return reached, globs


class _Reacher:
    """Reach of a set of anchors within a unit: address-flow when `flow`, else over every call edge."""

    def __init__(self, functions: dict[str, dict], within: set[str], global_vars: dict[str, dict], flow: bool):
        self.functions, self.within, self.global_vars, self.flow = functions, within, global_vars, flow

    def __call__(self, anchors: list[str]) -> tuple[set[str], set[str]]:
        if self.flow:
            return flow_reach(self.functions, self.global_vars, anchors, self.within)
        out: set[str] = set()
        for a in anchors:
            if a not in out:
                out |= reach(self.functions, a, self.within)
        return out, set()


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
    max_lines: int = MAX_LINES,
    global_vars: dict[str, dict] | None = None,
    flow: bool | None = None,
) -> list[dict[str, Any]]:
    """
    Clusters [{anchors, functions, globals}] of one unit, deterministic (see the module docstring).
    `flow` None: the address-flow reach when every function of `keys` has its facts.
    """
    within = set(keys)
    if flow is None:
        flow = has_flow_facts(functions, keys)
    reacher = _Reacher(functions, within, global_vars or {}, flow)
    clusters: dict[int, dict[str, Any]] = {}  # creation order -> cluster (merged ones keep the lower)
    for seq, e in enumerate(dict.fromkeys(e for e in entries if e in within)):
        fs, gs = reacher([e])
        clusters[seq] = {"anchors": [e], "functions": fs, "globals": gs, "version": 0}

    def fits(fs: set[str]) -> bool:
        n, lines = unit_size(functions, fs)
        return n <= max_functions and lines <= max_lines

    def merged(a: dict, b: dict) -> tuple[set[str], set[str]]:
        fa, fb = a["functions"], b["functions"]
        if fa <= fb and a["anchors"][0] in fb:
            return fb, b["globals"]  # a's anchor is reached from b: the closure is b's
        if fb <= fa and b["anchors"][0] in fa:
            return fa, a["globals"]
        return reacher(a["anchors"] + b["anchors"])

    def merge(i: int, j: int, fs: set[str], gs: set[str]) -> None:
        a, b = clusters[i], clusters.pop(j)
        a.update(anchors=a["anchors"] + b["anchors"], functions=fs, globals=gs, version=a["version"] + 1)

    # Step 2: overlap merging, the most overlapping pair first (ties: earlier clusters first), within
    # the limits. A pair whose merge does not fit stays apart; it is tried again only after one of
    # the two has changed.
    heap: list[tuple[float, int, int, int, int]] = []

    def push_pairs(i: int) -> None:
        a = clusters[i]
        for j, b in clusters.items():
            if j == i:
                continue
            ov = _overlap(a["functions"], b["functions"])
            if ov > overlap:
                lo, hi = (i, j) if i < j else (j, i)
                heapq.heappush(heap, (-ov, lo, hi, clusters[lo]["version"], clusters[hi]["version"]))

    for i in sorted(clusters):
        a = clusters[i]
        for j in sorted(clusters):
            if j > i:
                ov = _overlap(a["functions"], clusters[j]["functions"])
                if ov > overlap:
                    heapq.heappush(heap, (-ov, i, j, 0, 0))
    while heap:
        _neg, i, j, vi, vj = heapq.heappop(heap)
        if i not in clusters or j not in clusters or clusters[i]["version"] != vi or clusters[j]["version"] != vj:
            continue
        a, b = clusters[i], clusters[j]
        if not (fits(a["functions"] | b["functions"])):
            continue  # the closure holds the union: it cannot fit either
        fs, gs = merged(a, b)
        if not fits(fs):
            continue
        merge(i, j, fs, gs)
        push_pairs(i)

    # Step 3: pack small clusters, within the limits.
    def file_of(c: dict) -> str:
        files = Counter(str((functions.get(a) or {}).get("file") or "") for a in c["anchors"])
        return sorted(files.items(), key=lambda kv: (-kv[1], kv[0]))[0][0] if files else ""

    stuck: set[str] = set()  # first anchors of small clusters nothing can take
    while len(clusters) > 1:
        small = [i for i, c in clusters.items() if len(c["functions"]) < min_functions and c["anchors"][0] not in stuck]
        if not small:
            break
        i = min(small, key=lambda k: (len(clusters[k]["functions"]), clusters[k]["anchors"][0]))
        c = clusters[i]
        options = []
        for j, other in clusters.items():
            if j == i or not fits(c["functions"] | other["functions"]):
                continue
            shared = len(c["functions"] & other["functions"])
            same_file = file_of(c) == file_of(other)
            other_small = len(other["functions"]) < min_functions
            # Most shared functions, then the same file, then another small cluster, then the smallest.
            options.append(((-shared, not same_file, not other_small, len(other["functions"]), j), j))
        target = None
        for _key, j in sorted(options):
            fs, gs = merged(c, clusters[j]) if j > i else merged(clusters[j], c)
            if fits(fs):
                target = (j, fs, gs)
                break
        if target is None:
            stuck.add(c["anchors"][0])
            continue
        j, fs, gs = target
        lo, hi = (j, i) if j < i else (i, j)
        merge(lo, hi, fs, gs)
    return [{k: c[k] for k in ("anchors", "functions", "globals")} for _seq, c in sorted(clusters.items())]


def _name(unit: str, c: dict, functions: dict[str, dict], taken: set[str]) -> str:
    stems = Counter(PurePosixPath(str((functions.get(a) or {}).get("file") or "x")).stem for a in c["anchors"])
    stem = sorted(stems.items(), key=lambda kv: (-kv[1], kv[0]))[0][0] if stems else "part"
    base = f"{unit}__{_NAME_JUNK.sub('_', stem).strip('_') or 'part'}"[:120]
    name, n = base, 2
    while name in taken:
        name, n = f"{base}_{n}", n + 1
    taken.add(name)
    return name


def _over_limit(n_fns: int, n_lines: int, max_functions: int, max_lines: int) -> str:
    why = []
    if n_fns > max_functions:
        why.append(f"{n_fns} functions > {max_functions}")
    if n_lines > max_lines:
        why.append(f"{n_lines} lines > {max_lines}")
    return ", ".join(why)


def build_plan(
    functions: dict[str, dict], global_vars: dict[str, dict], unit_keys: list[str], fns: set[str], globs: set[str]
) -> dict[str, Any]:
    """
    What a cluster's builds compile and link (address-flow reach only): `build_sources`, the .c files
    defining its functions and the globals it reads; `link_stubs`, the functions and globals of the
    unit those files name (calls, addresses, globals, initializers) without defining them. By the
    reach, none of them is reachable from the cluster's harness: a reached function's file and a
    read global's file are compiled.
    """
    files = {str(functions[k]["file"]) for k in fns if str(functions[k].get("file") or "").endswith(".c")}
    files |= {
        str(global_vars[g]["file"]) for g in globs if str((global_vars.get(g) or {}).get("file") or "").endswith(".c")
    }
    in_files = [k for k in unit_keys if str(functions[k].get("file") or "") in files]
    defined = set(in_files) | {k for k in unit_keys if functions[k].get("header")}
    unit_set = set(unit_keys)
    named: set[str] = set()
    named_globals: set[str] = set()
    for k in in_files:
        rec = functions[k]
        indirect = set(rec.get("indirect_callees") or [])
        named.update(c for c in rec.get("internal_callees") or [] if c not in indirect)
        named.update(rec.get("address_refs") or [])
        named_globals.update(rec.get("global_refs") or [])
    file_globals = {g for g, r in global_vars.items() if str(r.get("file") or "") in files}
    for g in file_globals:
        named.update(global_vars[g].get("init_functions") or [])
        named_globals.update(global_vars[g].get("init_globals") or [])
    stub_fns = sorted(k for k in named - defined if k in unit_set and not functions[k].get("is_static"))
    stub_globals = sorted(
        g for g in named_globals - file_globals if g in global_vars and not global_vars[g].get("static")
    )
    return {
        "build_sources": sorted(files),
        "link_stubs": {"functions": stub_fns, "globals": stub_globals},
    }


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
    global_vars: dict[str, dict] = dag.get("global_variables") or {}
    rows: dict[str, dict] = {}
    submodules: dict[str, dict] = {}
    if dag.get("module_kind") == "link_unit":
        taken = set(modules) | set(dag.get("lexer_modules") or {})
        for unit, rec in sorted(modules.items()):
            keys = [k for k in rec.get("functions") or [] if k in functions]
            entries = [e for e in rec.get("candidate_entry_points") or [] if e in functions]
            flow = has_flow_facts(functions, keys)
            # The size a whole-unit harness gives Eva: what the entry points reach (all without any).
            within = set(keys)
            reacher = _Reacher(functions, within, global_vars, flow)
            reached = reacher([e for e in entries if e in within])[0] if entries else set(keys)
            n_fns, n_lines = unit_size(functions, reached)
            row: dict[str, Any] = {
                "functions": len(keys),
                "reached": n_fns,
                "lines": n_lines,
                "split": False,
                "reach": REACH_FLOW if flow else REACH_CALLS,
            }
            rows[unit] = row
            if n_fns <= max_functions and n_lines <= max_lines:
                continue
            clusters = cluster(
                functions, keys, entries, max_functions, overlap, min_functions, max_lines, global_vars, flow
            )
            if len(clusters) < 2:
                row["note"] = "above the threshold, but its entry points form a single cluster"
                continue
            names = []
            covered: set[str] = set()
            over: list[str] = []
            for c in clusters:
                name = _name(unit, c, functions, taken)
                fns = sorted(c["functions"])
                covered |= c["functions"]
                c_fns, c_lines = unit_size(functions, fns)
                sub: dict[str, Any] = {
                    "module": name,
                    "unit": unit,
                    "kind": "cluster",
                    "reach": REACH_FLOW if flow else REACH_CALLS,
                    "anchors": c["anchors"],
                    "candidate_entry_points": c["anchors"],
                    "functions": fns,
                    "function_count": c_fns,
                    "lines": c_lines,
                    "files": sorted({str(functions[k].get("file")) for k in fns if functions[k].get("file")}),
                    **tiers.module_fields(functions, fns, rec.get("tier")),
                }
                limit = _over_limit(c_fns, c_lines, max_functions, max_lines)
                if limit:
                    sub["over_limit"] = limit
                    over.append(name)
                if flow:
                    sub["globals"] = sorted(c["globals"])
                    sub.update(build_plan(functions, global_vars, keys, c["functions"], c["globals"]))
                submodules[name] = sub
                names.append(name)
            unclustered = sorted(set(keys) - covered)
            why = []
            if n_fns > max_functions:
                why.append(f"{n_fns} reached functions > {max_functions}")
            if n_lines > max_lines:
                why.append(f"{n_lines} lines > {max_lines}")
            rec["split"] = {"reason": ", ".join(why), "submodules": names, "unclustered": unclustered}
            if over:
                rec["split"]["over_limit"] = over
            row.update(split=True, submodules=len(names), unclustered=len(unclustered), over_limit=len(over))
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
    shown = ("unit", "function_count", "lines", "tier", "over_limit")
    out = {
        "unit_split": dag["unit_split"],
        "submodules": {
            n: {k: s[k] for k in shown if k in s}
            | {"anchors": len(s["anchors"])}
            | ({"build_sources": len(s["build_sources"])} if "build_sources" in s else {})
            for n, s in dag["submodules"].items()
        },
    }
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
