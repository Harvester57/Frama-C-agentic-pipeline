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
from collections.abc import Iterable
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


def _defining_c_files(rec: dict | None) -> list[str]:
    """The .c translation unit(s) compiling a function or global (direct `.c` file or `compiled_in`)."""
    if not isinstance(rec, dict):
        return []
    file = str(rec.get("file") or "")
    if file.endswith(".c"):
        return [file]
    return [str(f) for f in rec.get("compiled_in") or [] if str(f).endswith(".c")]


def unit_closure_modules(dag: dict, unit: str) -> list[str]:
    """`unit` plus every project module it transitively links (`linked_modules`)."""
    modules: dict[str, dict] = dag.get("modules") or {}
    if unit not in modules:
        return []
    order: list[str] = []
    seen: set[str] = set()
    stack = [unit]
    while stack:
        cur = stack.pop(0)
        if cur in seen or cur not in modules:
            continue
        seen.add(cur)
        order.append(cur)
        for lk in modules[cur].get("linked_modules") or []:
            if isinstance(lk, str) and lk not in seen and lk in modules:
                stack.append(lk)
    return order


def unit_closure_keys(dag: dict, unit: str) -> tuple[list[str], list[str]]:
    """(own_keys, all_keys): functions of `unit`, and functions of `unit` plus its linked modules."""
    functions: dict[str, dict] = dag.get("functions") or {}
    modules: dict[str, dict] = dag.get("modules") or {}
    rec = modules.get(unit) or {}
    own = [k for k in rec.get("functions") or [] if k in functions]
    seen = set(own)
    all_keys = list(own)
    for mod in unit_closure_modules(dag, unit)[1:]:
        for k in (modules.get(mod) or {}).get("functions") or []:
            if k in functions and k not in seen:
                seen.add(k)
                all_keys.append(k)
    return own, all_keys


def has_flow_facts(functions: dict[str, dict], keys: list[str]) -> bool:
    """Whether every function of `keys` carries the model's address-flow facts (schema 6 dumps)."""
    return bool(keys) and all(isinstance((functions.get(k) or {}).get("address_refs"), list) for k in keys)


def flow_reach(
    functions: dict[str, dict],
    global_vars: dict[str, dict],
    starts: list[str],
    within: set[str],
    extra_globals: Iterable[str] | None = None,
    *,
    include_constructors: bool = True,
) -> tuple[set[str], set[str]]:
    """
    The address-flow reach of `starts` within `within` (module docstring): the functions reached and
    the globals they name, with those the globals' initializers name.

    - Direct calls (everything in `internal_callees` outside `indirect_callees`) are always followed.
    - Function-body `address_refs` are followed unconditionally (decision D1(b): structurally covers
      callbacks stored in locals/structs passed to external libraries and function-pointer casts).
    - Global initializers (`init_functions`) feed the signature-filtered `pool`, except callbacks
      whose signature matches no indirect site in `within` (external-library tables such as nginx's
      `signals[]` -> `sigaction`, or cast targets), which are followed directly.
    - When `include_constructors` is True, any `__attribute__((constructor))` function in `within`
      compiled by a `.c` file of a reached function or global joins the reach to a fixpoint.
    """
    reached: set[str] = set()
    pool: set[str] = set()  # function addresses the reached code and data hold
    globs: set[str] = set()
    with_sites: list[str] = []  # reached functions with indirect callees
    all_indirect: set[str] = {c for k in within for c in (functions.get(k) or {}).get("indirect_callees") or []}
    ctors_by_file: dict[str, list[str]] = {}
    if include_constructors:
        for k in within:
            rec = functions.get(k)
            if isinstance(rec, dict) and rec.get("constructor"):
                for cf in _defining_c_files(rec):
                    ctors_by_file.setdefault(cf, []).append(k)

    work = [s for s in starts if s in within]
    gwork: list[str] = []
    if extra_globals:
        for g in extra_globals:
            if g in global_vars and g not in globs:
                globs.add(g)
                gwork.append(g)

    def _enqueue_file_ctors(rec: dict | None) -> None:
        if not ctors_by_file:
            return
        for cf in _defining_c_files(rec):
            for ctor in ctors_by_file.get(cf) or ():
                if ctor not in reached:
                    work.append(ctor)

    while work or gwork:
        while work:
            f = work.pop()
            if f in reached:
                continue
            reached.add(f)
            rec = functions.get(f) or {}
            _enqueue_file_ctors(rec)
            indirect = set(rec.get("indirect_callees") or [])
            for c in rec.get("internal_callees") or []:
                if c in within and c not in reached and c not in indirect:
                    work.append(c)
            for a in rec.get("address_refs") or []:
                pool.add(a)
                if a in within and a not in reached:
                    work.append(a)
            for g in rec.get("global_refs") or []:
                if g not in globs:
                    globs.add(g)
                    gwork.append(g)
            if indirect:
                with_sites.append(f)
        while gwork:
            grec = global_vars.get(gwork.pop()) or {}
            _enqueue_file_ctors(grec)
            for fn in grec.get("init_functions") or []:
                pool.add(fn)
                if fn in within and fn not in reached and fn not in all_indirect:
                    work.append(fn)
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
    closure_keys: list[str] | None = None,
) -> list[dict[str, Any]]:
    """
    Clusters [{anchors, functions, globals, all_functions}] of one unit, deterministic (see the
    module docstring). `flow` None: the address-flow reach when every function of `closure_keys`
    (default `keys`) has its facts. When `closure_keys` includes linked libraries, reach runs over
    the full link closure while cluster membership and limits stay on `keys` (`own_set`).
    """
    own_set = set(keys)
    all_keys = list(closure_keys) if closure_keys is not None else list(keys)
    within_all = set(all_keys) | own_set
    if flow is None:
        flow = has_flow_facts(functions, all_keys)
    gv = global_vars or {}
    reacher = _Reacher(functions, within_all if flow else own_set, gv, flow)
    clusters: dict[int, dict[str, Any]] = {}  # creation order -> cluster (merged ones keep the lower)
    own_entries = list(dict.fromkeys(e for e in entries if e in own_set))
    for seq, e in enumerate(own_entries):
        all_fs, gs = reacher([e])
        clusters[seq] = {
            "anchors": [e],
            "functions": all_fs & own_set,
            "all_functions": all_fs,
            "globals": gs,
            "version": 0,
        }

    def fits(fs: set[str]) -> bool:
        n, lines = unit_size(functions, fs)
        return n <= max_functions and lines <= max_lines

    def merged(a: dict, b: dict) -> tuple[set[str], set[str]]:
        fa, fb = a["all_functions"], b["all_functions"]
        if fa <= fb and a["anchors"][0] in fb:
            return fb, b["globals"]  # a's anchor is reached from b: the closure is b's
        if fb <= fa and b["anchors"][0] in fa:
            return fa, a["globals"]
        return reacher(a["anchors"] + b["anchors"])

    def merge(i: int, j: int, all_fs: set[str], gs: set[str]) -> None:
        a, b = clusters[i], clusters.pop(j)
        a.update(
            anchors=a["anchors"] + b["anchors"],
            functions=all_fs & own_set,
            all_functions=all_fs,
            globals=gs,
            version=a["version"] + 1,
        )

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
        if not fits(a["functions"] | b["functions"]):
            continue  # the closure holds the union: it cannot fit either
        all_fs, gs = merged(a, b)
        if not fits(all_fs & own_set):
            continue
        merge(i, j, all_fs, gs)
        push_pairs(i)

    # Step 2b (decision D3): rescue producer-consumer splits that drop unit-reachable callbacks into
    # `unclustered` (e.g. one cluster reads a global table with `cb`, another calls `cb`'s signature),
    # merging within the limits.
    if flow and len(clusters) > 1 and own_entries:
        unit_reached = reacher(own_entries)[0] & own_set
        while len(clusters) > 1:
            covered = set().union(*(c["functions"] for c in clusters.values()))
            lost = unit_reached - covered
            if not lost:
                break
            producers: dict[int, set[str]] = {}
            consumers: dict[int, set[str]] = {}
            for cid, c in clusters.items():
                prod: set[str] = set()
                cons: set[str] = set()
                for fk in c["all_functions"]:
                    rec = functions.get(fk) or {}
                    prod.update(rec.get("address_refs") or [])
                    cons.update(rec.get("indirect_callees") or [])
                for gk in c["globals"]:
                    prod.update((gv.get(gk) or {}).get("init_functions") or [])
                producers[cid] = prod & lost
                consumers[cid] = cons & lost
            best: tuple[tuple[int, int, int, int], int, int, set[str], set[str]] | None = None
            seen_pairs: set[tuple[int, int]] = set()
            for f in sorted(lost):
                p_ids = [cid for cid, p in producers.items() if f in p]
                c_ids = [cid for cid, cs in consumers.items() if f in cs]
                for pi in p_ids:
                    for ci in c_ids:
                        if pi == ci:
                            continue
                        lo, hi = (pi, ci) if pi < ci else (ci, pi)
                        if (lo, hi) in seen_pairs:
                            continue
                        seen_pairs.add((lo, hi))
                        a, b = clusters[lo], clusters[hi]
                        if not fits(a["functions"] | b["functions"]):
                            continue
                        all_fs, gs = merged(a, b)
                        own_fs = all_fs & own_set
                        rescued = len(own_fs & lost)
                        if rescued == 0 or not fits(own_fs):
                            continue
                        score = (-rescued, len(own_fs), lo, hi)
                        if best is None or score < best[0]:
                            best = (score, lo, hi, all_fs, gs)
            if best is None:
                break
            _, lo, hi, all_fs, gs = best
            merge(lo, hi, all_fs, gs)

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
            all_fs, gs = merged(c, clusters[j]) if j > i else merged(clusters[j], c)
            if fits(all_fs & own_set):
                target = (j, all_fs, gs)
                break
        if target is None:
            stuck.add(c["anchors"][0])
            continue
        j, all_fs, gs = target
        lo, hi = (j, i) if j < i else (i, j)
        merge(lo, hi, all_fs, gs)
    return [
        {k: c[k] for k in ("anchors", "functions", "globals", "all_functions")} for _seq, c in sorted(clusters.items())
    ]


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


def link_stubs_for_files(
    functions: dict[str, dict],
    global_vars: dict[str, dict],
    all_keys: list[str],
    files: set[str],
    reached_fns: Iterable[str] = (),
    reached_globals: Iterable[str] = (),
) -> dict[str, list[str]]:
    """
    The functions and globals of the unit's link closure (`all_keys`) that `files` name (direct calls,
    `address_refs`, `global_refs`, and global initializers) without defining them. Reached functions
    and reached globals are never listed.
    """
    all_set = set(all_keys)
    in_files = [k for k in all_keys if set(_defining_c_files(functions.get(k))) & files]
    # Header `static inline` functions called by `.c` files in `files` are compiled into those
    # translation units too, so their `global_refs` and non-header callees create link relocations.
    compiled_fns: set[str] = set(in_files)
    hwork = list(in_files)
    while hwork:
        k = hwork.pop()
        rec = functions.get(k) or {}
        indirect = set(rec.get("indirect_callees") or [])
        cands = [c for c in rec.get("internal_callees") or [] if c not in indirect]
        cands.extend(rec.get("address_refs") or [])
        for c in cands:
            if c in all_set and c not in compiled_fns and (functions.get(c) or {}).get("header"):
                compiled_fns.add(c)
                hwork.append(c)
    defined = compiled_fns | {k for k in all_keys if (functions.get(k) or {}).get("header")} | set(reached_fns)
    named: set[str] = set()
    named_globals: set[str] = set()
    for k in compiled_fns:
        rec = functions[k]
        indirect = set(rec.get("indirect_callees") or [])
        named.update(c for c in rec.get("internal_callees") or [] if c not in indirect)
        named.update(rec.get("address_refs") or [])
        named_globals.update(rec.get("global_refs") or [])
    file_globals = {g for g, r in global_vars.items() if set(_defining_c_files(r)) & files}
    for g in file_globals:
        named.update((global_vars[g] or {}).get("init_functions") or [])
        named_globals.update((global_vars[g] or {}).get("init_globals") or [])
    defined_globals = file_globals | set(reached_globals)
    stub_fns = sorted(k for k in named - defined if k in all_set and not (functions.get(k) or {}).get("is_static"))
    stub_globals = sorted(
        g for g in named_globals - defined_globals if g in global_vars and not (global_vars[g] or {}).get("static")
    )
    return {"functions": stub_fns, "globals": stub_globals}


def build_plan(
    functions: dict[str, dict],
    global_vars: dict[str, dict],
    unit_keys: list[str],
    fns: set[str],
    globs: set[str],
    closure_keys: list[str] | None = None,
) -> dict[str, Any]:
    """
    What a cluster's builds compile and link (address-flow reach only): `build_sources`, the .c files
    defining its reached functions (including reached linked-library functions and `.inc`/header
    definitions via `compiled_in`) and the globals it reads; `link_stubs`, the functions and globals
    of the unit's link closure those files name (calls, addresses, globals, initializers) without
    defining them. Reached functions and reached globals are never listed in `link_stubs`.
    """
    all_keys = list(closure_keys) if closure_keys is not None else list(unit_keys)
    files: set[str] = set()
    for k in fns:
        if k in functions:
            files.update(_defining_c_files(functions[k]))
    for g in globs:
        files.update(_defining_c_files(global_vars.get(g)))
    return {
        "build_sources": sorted(files),
        "link_stubs": link_stubs_for_files(functions, global_vars, all_keys, files, fns, globs),
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
            keys, all_keys = unit_closure_keys(dag, unit)
            entries = [e for e in rec.get("candidate_entry_points") or [] if e in functions]
            closure_mods = unit_closure_modules(dag, unit)
            flow = has_flow_facts(functions, all_keys) and not any(
                (modules.get(m) or {}).get("callgraph_fallback") for m in closure_mods
            )
            # The size a whole-unit harness gives Eva: what the entry points reach (all without any).
            own_set = set(keys)
            within = set(all_keys) if flow else own_set
            reacher = _Reacher(functions, within, global_vars, flow)
            reached = (reacher([e for e in entries if e in own_set])[0] & own_set) if entries else set(keys)
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
                functions,
                keys,
                entries,
                max_functions,
                overlap,
                min_functions,
                max_lines,
                global_vars,
                flow,
                closure_keys=all_keys,
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
                    sub.update(
                        build_plan(
                            functions,
                            global_vars,
                            keys,
                            c["all_functions"],
                            c["globals"],
                            closure_keys=all_keys,
                        )
                    )
                submodules[name] = sub
                names.append(name)
            unclustered = sorted(set(keys) - covered)
            cross_unclustered = sorted(reached - covered) if flow else []
            why = []
            if n_fns > max_functions:
                why.append(f"{n_fns} reached functions > {max_functions}")
            if n_lines > max_lines:
                why.append(f"{n_lines} lines > {max_lines}")
            rec["split"] = {"reason": ", ".join(why), "submodules": names, "unclustered": unclustered}
            if cross_unclustered:
                rec["split"]["cross_cluster_unclustered"] = cross_unclustered
                dag.setdefault("warnings", []).append(
                    f"unit {unit}: {len(cross_unclustered)} unit-reachable callback(s) dropped into unclustered "
                    f"because producer and consumer clusters exceeded the split limits ({', '.join(cross_unclustered[:5])})"
                )
            if not flow:
                dag.setdefault("warnings", []).append(
                    f"unit {unit}: split used call_graph reach (missing dump-schema-6 address-flow facts); "
                    "re-run phase0_model.py to narrow clusters"
                )
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
