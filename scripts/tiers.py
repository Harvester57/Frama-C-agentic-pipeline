#!/usr/bin/env python3
"""
Risk tiers per function and per module (docs/phase0-implementation-plan.md step I8). Stdlib only.

    tiers.py summary [--dag workspace/reports/callgraph_dag.json]

Before I8 a module took one tier from the lexer's look at all its functions together, and every function
inherited it. Now each function gets its own tier from its trust (scripts/trust.py, step I7) and its
structure, and a module takes the most demanding tier among its functions:

  - **untrusted path**: a function is on an untrusted path when it is untrusted itself, when the threat
    model's `trusted_callers` overrode an untrusted mark on it (attacker data still reaches it, through
    callers that check it), or when an untrusted function reaches it in the call graph (direct and
    indirect edges). The library API is untrusted by default (I7), so a library's internal helpers
    are on an untrusted path through the API that calls them;
  - **Tier 3** (deferred under the quick profile): no untrusted path; or scalar glue on one: no loop,
    no pointer parameter, pointer return or pointer cast, no indirect call, no allocation or
    recursion, not variadic, at most one decision (cyclomatic complexity <= SCALAR_MAX_CYCLOMATIC),
    and either off the trust boundary or without parameters (an exported getter or init function:
    attacker data reaches a boundary function only through its parameters);
  - **Tier 2**: on an untrusted path, and allocates on the heap or is recursive;
  - **Tier 1B**: on an untrusted path and writes a bounded output buffer it does not read from
    (an emitter), or formats into one;
  - **Tier 1A**: any other function on an untrusted path (parsers, validators, the boundary itself).

The plan's wording is "untrusted and complex -> 1A/1B; heap or recursive and untrusted -> 2; no
untrusted path -> 3". Heap and recursion are tested first because Tier 2's route (fuzzing, Eva, WP on
the non-allocating validators) is the one WP can follow on such code; "complex" is read as "not an
internal scalar helper", the only untrusted-path code put in Tier 3.

Each function records `tier`, `tier_reasons` and `untrusted_path`; each module (link unit, lexer module,
split sub-module) records `tier`, `recommended_strategy`, the run flags of that tier (`run_eacsl_fuzz`,
`run_eva`, `run_wp_full`), `tier_counts` and `deferred_profiles` (["quick"] for Tier 3). A module with
no function keeps its tier. The lexer's tier of a module stays under `lexer_tier`.

Without trust in the DAG (no Phase 0 model, or a model from before I7) nothing changes: the lexer's
tiers stay, and the DAG's `tiers.source` says so.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, deque
from pathlib import Path
from typing import Any

TIER_1A = "Tier 1A (Untrusted Binary / Network Parser)"
TIER_1B = "Tier 1B (Structured Packet / Log Emitter)"
TIER_2 = "Tier 2 (Recursive Heap / Tree Parser)"
TIER_3 = "Tier 3 (Internal State / Glue Module)"
# Most to least demanding (build_callgraph_dag._TIER_RANK uses the same order).
TIER_ORDER = (TIER_1A, TIER_1B, TIER_2, TIER_3)
_PREFIXES = ("Tier 1A", "Tier 1B", "Tier 2", "Tier 3")

SCALAR_MAX_CYCLOMATIC = 2
# The profiles under which a tier's modules are not run (no fuzzing, no Eva) and its ledger units deferred.
DEFERRED_PROFILES: dict[str, list[str]] = {"Tier 3": ["quick"]}

# The route of each tier (the slice skill's tier table); the run flags are those of the lexer's
# classify_module_tier, so a module keeps its phases when its tier stays the same.
ROUTE: dict[str, dict[str, Any]] = {
    TIER_1A: {
        "recommended_strategy": "RTE + E-ACSL + LibFuzzer -> Module Eva -> Full Wavefront WP + Security Contracts",
        "run_wp_full": True,
        "run_eva": True,
        "run_eacsl_fuzz": True,
    },
    TIER_1B: {
        "recommended_strategy": "RTE + Module Eva -> Full Wavefront WP + Layer 5 Output Sanitization & Bounds Contracts",
        "run_wp_full": True,
        "run_eva": True,
        "run_eacsl_fuzz": True,
    },
    TIER_2: {
        "recommended_strategy": "RTE + E-ACSL + LibFuzzer + WP/Eva on post-parse validator functions",
        "run_wp_full": False,
        "run_eva": True,
        "run_eacsl_fuzz": True,
    },
    TIER_3: {
        "recommended_strategy": "Targeted RTE + Eva on entry points; on-demand WP for high-risk helpers",
        "run_wp_full": False,
        "run_eva": True,
        "run_eacsl_fuzz": False,
    },
}


def tier_rank(tier: str | None) -> int:
    """0 for Tier 1A (most demanding) to 3 for Tier 3; 4 for anything else."""
    for idx, prefix in enumerate(_PREFIXES):
        if (tier or "").startswith(prefix):
            return idx
    return len(_PREFIXES)


def highest(tiers: list[str]) -> str | None:
    """The most demanding of `tiers` (None for none)."""
    known = [t for t in tiers if tier_rank(t) < len(_PREFIXES)]
    return min(known, key=tier_rank) if known else None


def deferred_profiles(tier: str | None) -> list[str]:
    for prefix, profiles in DEFERRED_PROFILES.items():
        if (tier or "").startswith(prefix):
            return list(profiles)
    return []


def is_deferred(tier: str | None, profile: str | None) -> bool:
    """Whether a module (or ledger unit) of `tier` is deferred under `profile` (Tier 3 under quick)."""
    return bool(profile) and profile in deferred_profiles(tier)


def has_trust(dag: dict) -> bool:
    return any(isinstance((f or {}).get("trust"), dict) for f in (dag.get("functions") or {}).values())


def untrusted_path(functions: dict[str, dict]) -> dict[str, str]:
    """DAG key -> why it is on an untrusted path, for every function that is."""
    why: dict[str, str] = {}
    queue: deque[str] = deque()
    for key, rec in sorted(functions.items()):
        trust: dict = rec["trust"] if isinstance(rec.get("trust"), dict) else {}
        if trust.get("value") == "untrusted":
            why[key] = f"untrusted ({trust.get('source') or 'unknown'})"
        elif trust.get("overridden"):
            why[key] = "trusted callers only, but attacker data reaches it (threat model)"
        else:
            continue
        queue.append(key)
    while queue:
        cur = queue.popleft()
        for callee in functions[cur].get("internal_callees") or []:
            if callee in functions and callee not in why:
                why[callee] = f"reached from {cur}"
                queue.append(callee)
    return why


def _ptr_params(rec: dict) -> int:
    return int(rec.get("const_ptr_params") or 0) + int(rec.get("mutable_ptr_params") or 0)


def has_params(rec: dict) -> bool:
    params = rec.get("params")
    if isinstance(params, list):
        return bool(params)
    return str(params or "").strip() not in ("", "void")


def is_scalar_helper(rec: dict) -> bool:
    """
    Straight-line scalar glue: what the only untrusted-path Tier 3 functions look like. A function on
    the trust boundary qualifies only without parameters (an exported getter or init): attacker data
    reaches a boundary function through its parameters.
    """
    trust: dict = rec["trust"] if isinstance(rec.get("trust"), dict) else {}
    cyclomatic = rec.get("cyclomatic")
    return (
        not (trust.get("boundary") and has_params(rec))
        and not rec.get("has_loops")
        and not rec.get("macro_loops")
        and _ptr_params(rec) == 0
        and not rec.get("returns_pointer")
        and not rec.get("has_pointer_cast")
        and not rec.get("indirect_calls")
        and not rec.get("is_variadic")
        and not rec.get("has_dynamic_alloc")
        and not rec.get("is_recursive")
        and isinstance(cyclomatic, int)
        and cyclomatic <= SCALAR_MAX_CYCLOMATIC
    )


def function_tier(rec: dict, path_reason: str | None) -> tuple[str, list[str]]:
    """(tier, reasons) of one DAG function record; `path_reason` is None when no untrusted path reaches it."""
    if path_reason is None:
        why = ["no untrusted path: neither untrusted nor reached from an untrusted function"]
        if rec.get("header") and rec.get("reached") is False:
            # Public static inline API is untrusted only when the threat model lists it (step I7).
            why.append("header function no entry point of the build reaches")
        return TIER_3, why
    if rec.get("has_dynamic_alloc") or rec.get("is_recursive"):
        what = " and ".join(
            w for w, on in (("heap", rec.get("has_dynamic_alloc")), ("recursive", rec.get("is_recursive"))) if on
        )
        return TIER_2, [path_reason, f"{what} on an untrusted path"]
    if is_scalar_helper(rec):
        what = "internal scalar helper" if has_params(rec) else "scalar glue without parameters"
        return TIER_3, [
            path_reason,
            f"{what}: no loop, no pointer, cyclomatic {rec.get('cyclomatic')} <= {SCALAR_MAX_CYCLOMATIC}",
        ]
    writes = bool(rec.get("writes_bounded_buffer"))
    if writes and (rec.get("uses_format_or_write") or not rec.get("takes_bounded_buffer")):
        return TIER_1B, [path_reason, "writes a bounded output buffer (emitter)"]
    shape = []
    if rec.get("has_loops") or rec.get("macro_loops"):
        shape.append("loops")
    if _ptr_params(rec):
        shape.append("pointer parameters")
    if isinstance(rec.get("cyclomatic"), int):
        shape.append(f"cyclomatic {rec['cyclomatic']}")
    return TIER_1A, [
        path_reason,
        "reads or walks attacker-reachable data" + (f" ({', '.join(shape)})" if shape else ""),
    ]


def module_fields(functions: dict[str, dict], keys: list[str], fallback: str | None = None) -> dict[str, Any]:
    """A module's tier, route, run flags, tier counts and deferred profiles from its functions' tiers."""
    tiers = [str(functions[k].get("tier")) for k in keys if k in functions and functions[k].get("tier")]
    tier = highest(tiers) or fallback or TIER_3
    route = ROUTE.get(tier) or ROUTE[TIER_3]
    counts = Counter(t.split(" (")[0] for t in tiers)
    return {
        "tier": tier,
        **route,
        "tier_counts": {p: counts[p] for p in _PREFIXES if counts.get(p)},
        "deferred_profiles": deferred_profiles(tier),
    }


def _retier_modules(functions: dict[str, dict], modules: dict[str, dict], member_of: Any) -> None:
    for name, mod in modules.items():
        if not isinstance(mod, dict):
            continue
        keys = member_of(name, mod)
        if not keys:
            continue
        mod.setdefault("lexer_tier", mod.get("tier"))
        mod.update(module_fields(functions, keys, mod.get("tier")))


def apply(dag: dict) -> dict:
    """Set per-function and per-module tiers in `dag` (in place, and returned). See the module docstring."""
    functions: dict[str, dict] = dag.get("functions") or {}
    if not functions or not has_trust(dag):
        dag["tiers"] = {"source": "lexer", "note": "no trust in the DAG (step I7): the lexer's module tiers are kept"}
        return dag
    path = untrusted_path(functions)
    for key, rec in functions.items():
        rec.setdefault("lexer_tier", rec.get("tier"))
        tier, reasons = function_tier(rec, path.get(key))
        rec["tier"] = tier
        rec["tier_reasons"] = reasons
        rec["untrusted_path"] = key in path

    _retier_modules(functions, dag.get("modules") or {}, lambda _n, m: list(m.get("functions") or []))
    lexer_modules = dag.get("lexer_modules")
    if isinstance(lexer_modules, dict) and dag.get("module_kind") == "link_unit":
        by_lexer: dict[str, list[str]] = {}
        for key, rec in functions.items():
            if rec.get("lexer_module"):
                by_lexer.setdefault(str(rec["lexer_module"]), []).append(key)
        _retier_modules(functions, lexer_modules, lambda n, _m: by_lexer.get(n, []))
    _retier_modules(functions, dag.get("submodules") or {}, lambda _n, m: list(m.get("functions") or []))

    counts = Counter(str(r["tier"]).split(" (")[0] for r in functions.values())
    dag["tiers"] = {
        "source": "trust",
        "functions": {p: counts[p] for p in _PREFIXES},
        "untrusted_path": len(path),
        "tier3_no_untrusted_path": sum(1 for k in functions if k not in path),
        "tier3_unreached_header": sum(
            1 for k, r in functions.items() if k not in path and r.get("header") and r.get("reached") is False
        ),
        "tier3_scalar_helpers": sum(
            1 for k, r in functions.items() if k in path and str(r["tier"]).startswith("Tier 3")
        ),
        "deferred_profiles": DEFERRED_PROFILES,
        "scalar_max_cyclomatic": SCALAR_MAX_CYCLOMATIC,
    }
    return dag


def summary(dag: dict) -> dict[str, Any]:
    """The DAG's tiers: totals, each module's tier and counts, and the Tier 3 functions with their reason."""
    functions: dict[str, dict] = dag.get("functions") or {}

    def mods(records: dict) -> dict[str, Any]:
        return {
            n: {"tier": m.get("tier"), "lexer_tier": m.get("lexer_tier"), "tier_counts": m.get("tier_counts")}
            for n, m in sorted((records or {}).items())
            if isinstance(m, dict)
        }

    return {
        "tiers": dag.get("tiers"),
        "modules": mods(dag.get("modules") or {}),
        "lexer_modules": mods(dag.get("lexer_modules") or {}) if dag.get("module_kind") == "link_unit" else {},
        "submodules": mods(dag.get("submodules") or {}),
        "tier3": {
            k: (r.get("tier_reasons") or [""])[-1]
            for k, r in sorted(functions.items())
            if str(r.get("tier") or "").startswith("Tier 3")
        },
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0] if __doc__ else None)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("summary", help="Print the DAG's tiers and the Tier 3 functions with their reason")
    s.add_argument("--dag", type=Path, default=Path("workspace/reports/callgraph_dag.json"))
    a = p.parse_args(argv)
    try:
        dag = json.loads(a.dag.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"error: {a.dag}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary(dag), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
