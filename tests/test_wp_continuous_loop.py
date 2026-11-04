"""Comprehensive E2E and integration tests for the Continuous Reactive Sliding-Window Loop.

Covers Requirements R1 through R5 across a 4-tier systematic methodology:
- Tier 1: Feature Coverage (R1 speculative, R2 gating & splice, R3 step & eager, R4 sizing, R5 waves)
- Tier 2: Boundary & Corner Cases (CPUs 31/32 & 63/64, empty queues, SCC cycles, header conflicts)
- Tier 3: Cross-Feature Combinations (speculative + step, gating + eager merge, parallel rechecks)
- Tier 4: Real-World Workload Scenarios (multi-module sliding-window pipeline simulation)
"""

from __future__ import annotations

import inspect
import sys
from pathlib import Path

import pytest

# Ensure scripts/ and tests/ are accessible for imports
TESTS_DIR = Path(__file__).resolve().parent
ROOT_DIR = TESTS_DIR.parent
SCRIPTS_DIR = ROOT_DIR / "scripts"

for p in (str(SCRIPTS_DIR), str(TESTS_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

import acsl_ast  # noqa: E402
import ledger  # noqa: E402
import resources as R  # noqa: E402
import wp_scheduler as S  # noqa: E402
from test_wp_scheduler import Sim, tasks, units  # noqa: E402

TIER1 = "Tier 1A (Untrusted Binary / Network Parser)"

# Feature capability probes for progressive testability across M1-M4
_HAS_M1_SPLICE = hasattr(acsl_ast, "splice_architect_header")
_HAS_M2_SPECULATIVE = hasattr(S, "callee_has_contract") or (
    hasattr(getattr(S, "_compute_deps", None), "__code__")
    and "has_function_contract" in S._compute_deps.__code__.co_names
)
_HAS_M2_GATING = hasattr(S, "_gate_blockers") and "task" in inspect.signature(S._gate_blockers).parameters
_HAS_M3_STEP = hasattr(S, "cmd_step")
_HAS_M4_RESOURCES = R.recommend(pool=R.Budget(128, 512_000, "t"))["max_agents"] == 64


@pytest.fixture
def sim(run_dir, monkeypatch):
    """Synthetic run directory fixture leveraging Sim harness."""
    return Sim(run_dir, monkeypatch)


def _splice_architect_header(*args, **kwargs) -> str:
    fn = getattr(acsl_ast, "splice_architect_header")  # noqa: B009
    return str(fn(*args, **kwargs))


def _cmd_step(*args, **kwargs) -> dict:
    fn = getattr(S, "cmd_step")  # noqa: B009
    return dict(fn(*args, **kwargs))


def ready() -> list[str]:
    raw = [r["task"] for r in S.cmd_status()["ready"]]
    res = list(raw)
    for t in raw:
        if t.startswith("prove:"):
            res.append(t[len("prove:") :])
    return res


# ============================================================================
# TIER 1: Feature Coverage (Requirements R1 through R5)
# ============================================================================


@pytest.mark.xfail(
    not _HAS_M2_SPECULATIVE,
    reason="Pending M2: speculative contract-first dispatch in _compute_deps",
    strict=False,
)
def test_tier1_r1_speculative_dispatch_callee_has_contract_before_body_proven(sim):
    """R1: Caller proceeds as soon as callee has a contract in workspace/work/."""
    sim.build(
        {
            "callee": ("src/m/callee.c", "m", []),
            "caller": ("src/m/caller.c", "m", ["callee"]),
        }
    )
    # Write a pre-existing function contract for callee in workspace/work/
    hdr = sim.run_dir / "workspace/work/src/m/callee.h"
    hdr.parent.mkdir(parents=True, exist_ok=True)
    hdr.write_text(
        "/*@ requires x >= 0; assigns \\nothing; ensures \\result >= x; */\nint callee(int x);\n", encoding="utf-8"
    )

    c_file = sim.run_dir / "workspace/work/src/m/caller.c"
    c_file.parent.mkdir(parents=True, exist_ok=True)
    c_file.write_text("int caller(int x) { return callee(x) + 1; }\n", encoding="utf-8")

    out = S.cmd_init()
    assert out["ok"] is True

    # Under speculative dispatch, prove:caller does NOT wait for prove:callee body proof
    caller_task = tasks()["prove:src/m/caller.c#caller"]
    assert "prove:src/m/callee.c#callee" not in caller_task.get("deps", [])
    assert "src/m/caller.c#caller" in ready()


@pytest.mark.xfail(
    not _HAS_M2_SPECULATIVE,
    reason="Pending M2: Option A for static callees without contract in _compute_deps",
    strict=False,
)
def test_tier1_r1_option_a_caller_waits_for_static_callee_without_contract(sim):
    """R1: Caller waits for internal static callee when the callee has no contract at all (Option A)."""
    sim.build(
        {
            "static_callee": ("src/m/m.c", "m", []),
            "caller": ("src/m/m.c", "m", ["static_callee"]),
        }
    )
    # Both in same file, but static_callee has NO contract in workspace/work/
    src = sim.run_dir / "workspace/work/src/m/m.c"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text(
        "static int static_callee(int x) { return x * 2; }\nint caller(int x) { return static_callee(x); }\n",
        encoding="utf-8",
    )

    out = S.cmd_init()
    assert out["ok"] is True

    # Option A: Caller MUST depend on static_callee because no contract exists
    caller_task = tasks()["prove:src/m/m.c#caller"]
    assert "prove:src/m/m.c#static_callee" in caller_task.get("deps", [])
    assert "src/m/m.c#caller" not in ready()
    assert "src/m/m.c#static_callee" in ready()


@pytest.mark.xfail(
    not _HAS_M2_SPECULATIVE,
    reason="Pending M2: caller unblocking upon callee contract merge",
    strict=False,
)
def test_tier1_r1_option_a_caller_unblocks_when_static_callee_acquires_contract(sim):
    """R1: Caller unblocks as soon as static callee produces or acquires a contract."""
    sim.build(
        {
            "static_callee": ("src/m/m.c", "m", []),
            "caller": ("src/m/m.c", "m", ["static_callee"]),
        }
    )
    S.cmd_init()
    assert "src/m/m.c#caller" not in ready()

    # Finish static callee with all_proven and merge it
    nxt = S.cmd_next("auto", prepare=True)
    aid = nxt["tasks"][0]["agent_id"]
    sim.finish(aid, "static_callee", "src/m/m.c")

    # Caller must now be ready
    assert "src/m/m.c#caller" in ready()


def test_tier1_r1_reconciliation_rechecks_speculative_caller_on_callee_contract_change(sim):
    """R1: Reconciliation soundly queues recheck when merged callee contract changes."""
    sim.build(
        {
            "callee": ("src/m/callee.c", "m", []),
            "caller": ("src/m/caller.c", "m", ["callee"]),
        }
    )
    S.cmd_init()
    # Callee is dispatched and finishes
    nxt1 = S.cmd_next("auto", prepare=True)
    aid_callee = nxt1["tasks"][0]["agent_id"]
    sim.finish(aid_callee, "callee", "src/m/callee.c")

    # Caller is dispatched and finishes
    nxt2 = S.cmd_next("auto", prepare=True)
    aid_caller = nxt2["tasks"][0]["agent_id"]
    sim.finish(aid_caller, "caller", "src/m/caller.c")

    # Now a negotiation or update modifies callee's contract
    sim.prover("aid-callee-2", "callee", "src/m/callee.c")
    # Simulate callee contract change queueing recheck for caller
    with S.run_lock("ledger"):
        state = S.load_schedule()
        rechecks = S._queue_rechecks_for(
            state, state["tasks"]["prove:src/m/callee.c#callee"], "callee contract modified"
        )
        S.save_schedule(state)

    assert len(rechecks) >= 1
    assert any("caller" in r for r in rechecks)


@pytest.mark.xfail(
    not _HAS_M2_GATING,
    reason="Pending M2: fine-grained gating by call cone in _gate_blockers",
    strict=False,
)
def test_tier1_r2_fine_grained_gate_blocks_only_affected_call_cone(sim):
    """R2: Verify task gates only functions in its call cone; safe functions remain unblocked."""
    sim.build(
        {
            "safe_fn": ("src/m/safe.c", "m", []),
            "vuln_fn": ("src/m/vuln.c", "m", []),
            "caller_of_vuln": ("src/m/caller.c", "m", ["vuln_fn"]),
        }
    )
    # Inject Eva candidate only in vuln_fn
    sim.eva_candidate("m", "src/m/vuln.c", "vuln_fn")
    out = S.cmd_init()
    assert out["ok"] is True

    ready_tasks = ready()
    # safe_fn is outside the call cone of vuln_fn -> ready
    assert "src/m/safe.c#safe_fn" in ready_tasks
    # vuln_fn and its caller are gated
    assert "src/m/vuln.c#vuln_fn" not in ready_tasks
    assert "src/m/caller.c#caller_of_vuln" not in ready_tasks


@pytest.mark.xfail(
    not _HAS_M2_GATING,
    reason="Pending M2: leaf/static functions run in parallel with arch:module",
    strict=False,
)
def test_tier1_r2_leaf_and_static_functions_run_in_parallel_with_module_architect(sim):
    """R2: Leaf and internal static functions that do not touch module headers run in parallel with arch:m."""
    sim.build(
        {
            "leaf_internal": ("src/m/internal.c", "m", []),
            "public_api": ("src/m/public.c", "m", []),
        },
        modules={"m": {"header": "src/m/m.h"}},
    )
    # Create module header prototype only for public_api
    hdr = sim.run_dir / "workspace/work/src/m/m.h"
    hdr.parent.mkdir(parents=True, exist_ok=True)
    hdr.write_text("int public_api(void);\n", encoding="utf-8")

    out = S.cmd_init()
    assert out["ok"] is True

    # leaf_internal does not touch header -> does not depend on arch:m
    leaf_task = tasks()["prove:src/m/internal.c#leaf_internal"]
    assert "arch:m" not in leaf_task.get("deps", [])
    assert "src/m/internal.c#leaf_internal" in ready()


@pytest.mark.xfail(
    not _HAS_M1_SPLICE,
    reason="Pending M1: tolerant header splice in acsl_ast.splice_architect_header",
    strict=False,
)
def test_tier1_r2_tolerant_architect_header_merge_per_declaration_splice():
    """R2: Per-declaration splice merges concurrent non-overlapping header modifications cleanly."""
    base_text = "#ifndef M_H\n#define M_H\n\nint parse_magic(void);\n\nint parse_payload(int len);\n\n#endif\n"
    # Architect modifies parse_magic and adds predicate P1
    agent_text = (
        "#ifndef M_H\n#define M_H\n\n"
        "/*@ predicate P1(int x) = x > 0; */\n\n"
        "/*@ assigns \\nothing; ensures \\result == 42; */\n"
        "int parse_magic(void);\n\n"
        "int parse_payload(int len);\n\n"
        "#endif\n"
    )
    # Concurrently, a prover modified parse_payload and added predicate P2
    current_text = (
        "#ifndef M_H\n#define M_H\n\n"
        "/*@ predicate P2(int y) = y >= 0; */\n\n"
        "int parse_magic(void);\n\n"
        "/*@ requires len > 0; assigns \\nothing; */\n"
        "int parse_payload(int len);\n\n"
        "#endif\n"
    )

    spliced = _splice_architect_header(
        base_text=base_text,
        agent_text=agent_text,
        current_text=current_text,
        path="src/m/m.h",
    )

    assert "predicate P1" in spliced
    assert "predicate P2" in spliced
    assert "ensures \\result == 42;" in spliced
    assert "requires len > 0;" in spliced
    # Baseline C tokens preserved identically
    assert acsl_ast.verify_acsl_only(base_text, spliced) == []


@pytest.mark.xfail(
    not _HAS_M3_STEP,
    reason="Pending M3: atomic cmd_step command implementation in wp_scheduler",
    strict=False,
)
def test_tier1_r3_atomic_step_command_completes_merges_and_dispatches(sim):
    """R3: cmd_step atomically executes complete + merge-pending + next in one call."""
    sim.build(
        {
            "f1": ("src/m/f1.c", "m", []),
            "f2": ("src/m/f2.c", "m", []),
        }
    )
    S.cmd_init()
    # Prepare agent for f1
    prep = S.cmd_next(slots="1", prepare=True)
    aid = prep["tasks"][0]["agent_id"]

    sim.prover(aid, "f1", "src/m/f1.c", status="all_proven")

    # Atomic step: complete f1, eagerly merge it, and dispatch f2
    res = _cmd_step(complete_ids=[aid], slots="auto", prepare=True)

    assert res["ok"] is True
    assert any(c.get("agent_id") == aid for c in res["completed"])
    assert any(m.get("agent_id") == aid for m in res["merge_pending"].get("merged", []))
    assert any(t["task"] in ("src/m/f2.c#f2", "prove:src/m/f2.c#f2") for t in res["next"].get("tasks", []))
    assert not res["errors"]


@pytest.mark.xfail(
    not _HAS_M3_STEP,
    reason="Pending M3: eager merge when caller waits on queued callee",
    strict=False,
)
def test_tier1_r3_eager_merge_triggered_when_caller_waits_on_queued_callee(sim):
    """R3: cmd_merge_pending triggers eagerly when a caller is waiting on a queued callee."""
    sim.build(
        {
            "callee": ("src/m/callee.c", "m", []),
            "caller": ("src/m/caller.c", "m", ["callee"]),
        }
    )
    S.cmd_init()
    nxt = S.cmd_next("auto", prepare=True)
    aid = nxt["tasks"][0]["agent_id"]
    sim.prover(aid, "callee", "src/m/callee.c", status="all_proven")
    assert S.cmd_complete(aid)["action"] == "queued_for_merge"

    # Merge pending without force: should merge eagerly because caller waits on it
    out = S.cmd_merge_pending(force=False)
    assert any(m["agent_id"] == aid for m in out["merged"])


@pytest.mark.xfail(
    not _HAS_M3_STEP,
    reason="Pending M3: eager merge when no merge is in flight",
    strict=False,
)
def test_tier1_r3_eager_merge_triggered_when_no_merge_in_flight(sim):
    """R3: cmd_merge_pending merges eagerly when no other merge is currently in flight."""
    sim.build({"f1": ("src/m/f1.c", "m", [])})
    S.cmd_init()
    nxt = S.cmd_next("auto", prepare=True)
    aid = nxt["tasks"][0]["agent_id"]
    sim.prover(aid, "f1", "src/m/f1.c", status="all_proven")
    S.cmd_complete(aid)

    # Queue size is 1 (< MERGE_BATCH_TRIGGER=4), but no merge in flight -> merges immediately
    out = S.cmd_merge_pending(force=False)
    assert any(m["agent_id"] == aid for m in out["merged"])


@pytest.mark.xfail(
    not _HAS_M4_RESOURCES,
    reason="Pending M4: recommend() cap scaling for pools >= 32 and >= 64 CPUs",
    strict=False,
)
def test_tier1_r4_resource_scaling_agent_cap_for_large_pools():
    """R4: recommend() agent caps scale to 32 on >= 32 CPUs and 64 on >= 64 CPUs."""
    assert R.recommend(pool=R.Budget(16, 64_000, "t"))["max_agents"] == 16
    assert R.recommend(pool=R.Budget(32, 128_000, "t"))["max_agents"] == 32
    assert R.recommend(pool=R.Budget(64, 256_000, "t"))["max_agents"] == 64
    assert R.recommend(pool=R.Budget(128, 512_000, "t"))["max_agents"] == 64


@pytest.mark.xfail(
    not _HAS_M4_RESOURCES,
    reason="Pending M4: nominal_grant wp max_cpus scaling to 16 for pool >= 32 CPUs",
    strict=False,
)
def test_tier1_r4_resource_scaling_wp_max_cpus():
    """R4: CLASSES['wp'] nominal grant scales up to 16 CPUs when pool >= 32 CPUs."""
    small_grant = R.nominal_grant(R.CLASSES["wp"], R.Budget(16, 64_000, "t"))
    large_grant = R.nominal_grant(R.CLASSES["wp"], R.Budget(32, 128_000, "t"))
    assert small_grant["cpus"] == 8
    assert large_grant["cpus"] == 16


@pytest.mark.xfail(
    not _HAS_M4_RESOURCES,
    reason="Pending M4: nominal_grant guardrail max_cpus scaling to 4 for pool >= 32 CPUs",
    strict=False,
)
def test_tier1_r4_resource_scaling_guardrail_max_cpus():
    """R4: CLASSES['guardrail'] nominal grant scales up to 4 CPUs when pool >= 32 CPUs."""
    small_grant = R.nominal_grant(R.CLASSES["guardrail"], R.Budget(8, 32_000, "t"))
    large_grant = R.nominal_grant(R.CLASSES["guardrail"], R.Budget(32, 64_000, "t"))
    assert small_grant["cpus"] == 2
    assert large_grant["cpus"] == 4


def test_tier1_r4_fixed_limits_invariance():
    """R4: Fixed per-process limits remain invariant across any machine pool size."""
    for cpus in (4, 16, 32, 64, 128):
        rec = R.recommend(pool=R.Budget(cpus, cpus * 4000, "t"))
        assert rec["fixed_limits"]["wp_memlimit_mb"] == 1000
        assert rec["fixed_limits"]["fuzz_rss_limit_mb"] == 2048


def test_tier1_r5_waves_mode_fallback_preserves_barriers(sim, monkeypatch):
    """R5: FRAMAC_SCHEDULER=waves preserves strict barriers between waves."""
    monkeypatch.setenv("FRAMAC_SCHEDULER", "waves")
    sim.build(
        {
            "leaf1": ("src/m/w0.c", "m", []),
            "caller1": ("src/m/w1.c", "m", ["leaf1"]),
        }
    )
    S.cmd_init()
    # Wave 0 must be completed before Wave 1 can be ready
    assert "prove:src/m/w0.c#leaf1" in ready()
    assert "prove:src/m/w1.c#caller1" not in ready()


def test_tier1_r5_continuous_sliding_window_ignores_wave_barriers(sim, monkeypatch):
    """R5: Default sliding-window mode dispatches tasks reactively without wave barriers."""
    monkeypatch.delenv("FRAMAC_SCHEDULER", raising=False)
    sim.build(
        {
            "indep1": ("src/m/w0.c", "m", []),
            "indep2": ("src/m/w1.c", "m", []),
        }
    )
    S.cmd_init()
    # Both independent tasks are ready concurrently regardless of wave assignment
    r = ready()
    assert "prove:src/m/w0.c#indep1" in r
    assert "prove:src/m/w1.c#indep2" in r


# ============================================================================
# TIER 2: Boundary & Corner Cases
# ============================================================================


@pytest.mark.xfail(
    not _HAS_M4_RESOURCES,
    reason="Pending M4: pool size boundary 31 vs 32 CPUs scaling",
    strict=False,
)
def test_tier2_boundary_cpu_pool_31_vs_32():
    """Boundary transition between 31 and 32 CPUs."""
    pool_31 = R.Budget(31, 128_000, "t")
    pool_32 = R.Budget(32, 128_000, "t")

    assert R.recommend(pool=pool_31)["max_agents"] == 16
    assert R.recommend(pool=pool_32)["max_agents"] == 32

    assert R.nominal_grant(R.CLASSES["wp"], pool_31)["cpus"] == 8
    assert R.nominal_grant(R.CLASSES["wp"], pool_32)["cpus"] == 16

    assert R.nominal_grant(R.CLASSES["guardrail"], pool_31)["cpus"] == 2
    assert R.nominal_grant(R.CLASSES["guardrail"], pool_32)["cpus"] == 4


@pytest.mark.xfail(
    not _HAS_M4_RESOURCES,
    reason="Pending M4: pool size boundary 63 vs 64 CPUs scaling",
    strict=False,
)
def test_tier2_boundary_cpu_pool_63_vs_64():
    """Boundary transition between 63 and 64 CPUs."""
    pool_63 = R.Budget(63, 256_000, "t")
    pool_64 = R.Budget(64, 256_000, "t")

    assert R.recommend(pool=pool_63)["max_agents"] == 32
    assert R.recommend(pool=pool_64)["max_agents"] == 64


@pytest.mark.xfail(
    not _HAS_M3_STEP,
    reason="Pending M3: empty cmd_step handling",
    strict=False,
)
def test_tier2_empty_step_command(sim):
    """Corner case: cmd_step with empty complete list and zero tasks returns clean schema."""
    sim.build({})
    S.cmd_init()
    res = _cmd_step(complete_ids=[], slots="auto")
    assert res["ok"] is True
    assert res["completed"] == []
    assert res["errors"] == []


def test_tier2_empty_merge_pending(sim):
    """Corner case: cmd_merge_pending with zero queued provers returns cleanly."""
    sim.build({"f": ("src/m/f.c", "m", [])})
    S.cmd_init()
    out = S.cmd_merge_pending()
    assert out["ok"] is True
    assert out["merged"] == []
    assert out["failed"] == []


@pytest.mark.xfail(
    not _HAS_M3_STEP,
    reason="Pending M3: cmd_step with slots=0",
    strict=False,
)
def test_tier2_zero_slots_step(sim):
    """Corner case: cmd_step with slots=0 performs complete and merge but picks zero next tasks."""
    sim.build({"f": ("src/m/f.c", "m", [])})
    S.cmd_init()
    res = _cmd_step(complete_ids=[], slots="0")
    assert res["ok"] is True
    assert res["next"]["tasks"] == []


def test_tier2_mutual_recursion_scc_tarjan_decoupled_from_pruned_deps(sim):
    """Corner case: Mutual recursion cycle (f <-> g) preserved by Tarjan call graph SCCs."""
    sim.build(
        {
            "even": ("src/m/even.c", "m", ["odd"]),
            "odd": ("src/m/odd.c", "m", ["even"]),
        }
    )
    S.cmd_init()
    t = tasks()
    even_t = t["prove:src/m/even.c#even"]
    odd_t = t["prove:src/m/odd.c#odd"]

    # Mutual recursion members share an SCC identifier
    assert even_t.get("scc") is not None
    assert even_t["scc"] == odd_t.get("scc")
    # Both become ready together
    assert "prove:src/m/even.c#even" in ready()
    assert "prove:src/m/odd.c#odd" in ready()


def test_tier2_self_recursion_edge(sim):
    """Corner case: Self-recursive function (f -> f) does not self-deadlock."""
    sim.build({"self_fn": ("src/m/self.c", "m", ["self_fn"])})
    S.cmd_init()
    t = tasks()["prove:src/m/self.c#self_fn"]
    # Self recursion must not add itself to deps
    assert "prove:src/m/self.c#self_fn" not in t.get("deps", [])
    assert "prove:src/m/self.c#self_fn" in ready()


@pytest.mark.xfail(
    not _HAS_M1_SPLICE,
    reason="Pending M1: disjoint multi-declaration splicing in splice_architect_header",
    strict=False,
)
def test_tier2_disjoint_header_splice_multiple_declarations():
    """Corner case: Multiple disjoint function contracts and predicates spliced concurrently."""
    base_text = "int fa(int x);\nint fb(int y);\nint fc(int z);\n"
    agent_text = (
        "/*@ predicate Pa(int x) = x > 0; */\n"
        "/*@ assigns \\nothing; ensures \\result >= 0; */\n"
        "int fa(int x);\n"
        "int fb(int y);\n"
        "int fc(int z);\n"
    )
    current_text = (
        "int fa(int x);\n"
        "/*@ predicate Pb(int y) = y != 0; */\n"
        "/*@ requires y > 0; assigns \\nothing; */\n"
        "int fb(int y);\n"
        "int fc(int z);\n"
    )

    spliced = _splice_architect_header(
        base_text=base_text,
        agent_text=agent_text,
        current_text=current_text,
        path="src/m/hdr.h",
    )
    assert "predicate Pa" in spliced
    assert "predicate Pb" in spliced
    assert "ensures \\result >= 0;" in spliced
    assert "requires y > 0;" in spliced
    assert "int fc(int z);" in spliced


@pytest.mark.xfail(
    not _HAS_M1_SPLICE,
    reason="Pending M1: ScopeViolationError on conflicting header modifications",
    strict=False,
)
def test_tier2_conflicting_header_splice_raises_scope_violation():
    """Corner case: Conflicting contract edits on the same prototype raise ScopeViolationError."""
    base_text = "int parse(int x);\n"
    agent_text = "/*@ requires x > 0; */\nint parse(int x);\n"
    current_text = "/*@ requires x > 100; */\nint parse(int x);\n"

    with pytest.raises(acsl_ast.ScopeViolationError) as exc_info:
        _splice_architect_header(
            base_text=base_text,
            agent_text=agent_text,
            current_text=current_text,
            path="src/m/hdr.h",
        )
    assert "parse" in str(exc_info.value)


@pytest.mark.xfail(
    not _HAS_M1_SPLICE,
    reason="Pending M1: predicate deduplication in splice_architect_header",
    strict=False,
)
def test_tier2_identical_concurrent_predicate_deduplication():
    """Corner case: Identical concurrent top-level ACSL predicates are merged without error."""
    base_text = "int parse(int x);\n"
    agent_text = "/*@ predicate Valid(int x) = x >= 0; */\nint parse(int x);\n"
    current_text = "/*@ predicate Valid(int x) = x >= 0; */\nint parse(int x);\n"

    spliced = _splice_architect_header(
        base_text=base_text,
        agent_text=agent_text,
        current_text=current_text,
        path="src/m/hdr.h",
    )
    # Deduplication ensures exactly one declaration remains
    assert spliced.count("predicate Valid") == 1


# ============================================================================
# TIER 3: Cross-Feature Combinations
# ============================================================================


@pytest.mark.xfail(
    not (_HAS_M2_SPECULATIVE and _HAS_M3_STEP),
    reason="Pending M2/M3: speculative dispatch combined with atomic step",
    strict=False,
)
def test_tier3_speculative_dispatch_with_atomic_step(sim):
    """Interaction: cmd_step completion immediately dispatches speculatively ready callers."""
    sim.build(
        {
            "unrelated": ("src/m/unrelated.c", "m", []),
            "callee": ("src/m/callee.c", "m", []),
            "caller": ("src/m/caller.c", "m", ["callee"]),
        }
    )
    # Callee already has a contract in header
    hdr = sim.run_dir / "workspace/work/src/m/callee.h"
    hdr.parent.mkdir(parents=True, exist_ok=True)
    hdr.write_text("/*@ assigns \\nothing; */\nint callee(void);\n", encoding="utf-8")

    S.cmd_init()
    # unrelated runs and finishes
    prep = S.cmd_next(slots="1", prepare=True)
    aid = prep["tasks"][0]["agent_id"]
    sim.prover(aid, "unrelated", "src/m/unrelated.c")

    # In one atomic step: unrelated completes, caller is speculatively ready and dispatched
    step_out = _cmd_step(complete_ids=[aid], slots="auto", prepare=True)

    assert step_out["ok"] is True
    dispatched = [t["task"] for t in step_out["next"]["tasks"]]
    assert any(t in ("src/m/caller.c#caller", "prove:src/m/caller.c#caller") for t in dispatched)


@pytest.mark.xfail(
    not (_HAS_M2_GATING and _HAS_M3_STEP),
    reason="Pending M2/M3: fine-grained gating combined with eager merge",
    strict=False,
)
def test_tier3_fine_grained_gating_with_eager_merge(sim):
    """Interaction: Eager merge unblocks waiting callers while unrelated functions remain gated."""
    sim.build(
        {
            "vuln_fn": ("src/m/vuln.c", "m", []),
            "leaf_a": ("src/m/leaf_a.c", "m", []),
            "caller_b": ("src/m/caller_b.c", "m", ["leaf_a"]),
        }
    )
    sim.eva_candidate("m", "src/m/vuln.c", "vuln_fn")
    S.cmd_init()

    # leaf_a finishes and enters merge queue
    nxt = S.cmd_next("auto", prepare=True)
    aid_leaf = [t["agent_id"] for t in nxt["tasks"] if "leaf_a" in t["task"]][0]
    sim.prover(aid_leaf, "leaf_a", "src/m/leaf_a.c")
    S.cmd_complete(aid_leaf)

    # Eager merge triggered because caller_b is waiting
    merge_out = S.cmd_merge_pending(force=False)
    assert any(m["agent_id"] == aid_leaf for m in merge_out["merged"])

    # caller_b is now ready, while vuln_fn is still properly gated
    r = ready()
    assert "src/m/caller_b.c#caller_b" in r
    assert "src/m/vuln.c#vuln_fn" not in r


def test_tier3_concurrent_rechecks_with_eager_merge(sim):
    """Interaction: Parallel rechecks during batch merge respect ledger -> merge lock order."""
    sim.build(
        {
            "callee": ("src/m/callee.c", "m", []),
            "caller1": ("src/m/c1.c", "m", ["callee"]),
            "caller2": ("src/m/c2.c", "m", ["callee"]),
        }
    )
    S.cmd_init()
    # Dispatch and finish callee
    nxt1 = S.cmd_next("auto", prepare=True)
    aid_callee = nxt1["tasks"][0]["agent_id"]
    sim.finish(aid_callee, "callee", "src/m/callee.c")

    # Dispatch and finish callers
    nxt2 = S.cmd_next("auto", prepare=True)
    for t in nxt2["tasks"]:
        sim.finish(t["agent_id"], t["function"], t["file"], force=True)

    # Callee contract change triggers rechecks for both callers
    sim.prover("aid-callee-2", "callee", "src/m/callee.c")
    with S.run_lock("ledger"):
        state = S.load_schedule()
        rechecks = S._queue_rechecks_for(
            state, state["tasks"]["prove:src/m/callee.c#callee"], "callee contract modified"
        )
        S.save_schedule(state)

    assert len(rechecks) >= 2
    out: dict = {"errors": [], "rechecks": {}}
    S._run_rechecks("m", out)

    assert "caller1" in sim.recheck_calls
    assert "caller2" in sim.recheck_calls


# ============================================================================
# TIER 4: Real-World Workload Scenarios
# ============================================================================


@pytest.mark.xfail(
    not (_HAS_M2_SPECULATIVE and _HAS_M3_STEP and _HAS_M4_RESOURCES),
    reason="Pending M2/M3/M4: full reactive sliding-window loop orchestration",
    strict=False,
)
def test_tier4_end_to_end_sliding_window_simulation(sim):
    """Tier 4: Realistic multi-module sliding-window verification pipeline execution.

    Simulates:
    - Module protocol: proto_parse (public), proto_crc (static callee), proto_dispatch (candidate)
    - Module crypto: crypto_decrypt (calls proto_parse), crypto_kdf (leaf)
    - Reactive loop driven entirely by cmd_step until all ledger units transition to done.
    """
    sim.build(
        {
            "proto_crc": ("src/proto/proto.c", "proto", []),
            "proto_parse": ("src/proto/proto.c", "proto", ["proto_crc"]),
            "proto_dispatch": ("src/proto/dispatch.c", "proto", ["proto_parse"]),
            "crypto_kdf": ("src/crypto/kdf.c", "crypto", []),
            "crypto_decrypt": ("src/crypto/decrypt.c", "crypto", ["proto_parse"]),
        },
        modules={
            "proto": {"header": "src/proto/proto.h"},
            "crypto": {"header": "src/crypto/crypto.h"},
        },
    )

    # proto_parse has public prototype contract in header
    hdr = sim.run_dir / "workspace/work/src/proto/proto.h"
    hdr.parent.mkdir(parents=True, exist_ok=True)
    hdr.write_text("/*@ assigns \\nothing; */\nint proto_parse(int len);\n", encoding="utf-8")

    # Eva candidate in proto_dispatch
    sim.eva_candidate("proto", "src/proto/dispatch.c", "proto_dispatch")

    init_res = S.cmd_init()
    assert init_res["ok"] is True

    running_agents: dict[str, dict] = {}  # agent_id -> task_info
    iteration = 0
    max_iterations = 20

    # Reactive continuous loop driver
    while iteration < max_iterations:
        iteration += 1

        # Simulate completions for all running agents
        completed_ids = []
        for aid, t_info in list(running_agents.items()):
            if t_info["kind"] == "prove":
                sim.prover(aid, t_info["function"], t_info["file"], status="all_proven")
            elif t_info["kind"] == "arch":
                sim.architect(aid, t_info["header"])
            elif t_info["kind"] == "verify":
                fp = t_info.get("candidate_fingerprint") or t_info.get("fingerprint")
                out_path = sim.run_dir / f"agents/{aid}/scratch/result.json"
                out_path.parent.mkdir(parents=True, exist_ok=True)
                ledger.cmd_scaffold_verifier(fp, "needs_validation", aid, out_path=out_path)
            completed_ids.append(aid)
        running_agents.clear()

        # Step: complete finished agents, eager merge, and pull next ready tasks
        step_out = _cmd_step(complete_ids=completed_ids, slots="auto", prepare=True)

        assert step_out["ok"] is True, f"Step failed at iteration {iteration}: {step_out['errors']}"

        new_tasks = step_out["next"].get("tasks", [])
        for t in new_tasks:
            if t["kind"] in ("prove", "arch", "verify"):
                running_agents[t["agent_id"]] = t

        # Stop condition: no running agents and no tasks left to dispatch
        if not running_agents and not new_tasks:
            break

    # Verification: all coverage units must be proven/done
    cov_units = units()
    for cid, u in cov_units.items():
        if "proto_dispatch" in cid:
            # Gated candidate remains accounted for
            continue
        assert u["status"] in ("covered", "done"), f"Unit {cid} was stranded in status {u['status']}"
