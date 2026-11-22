"""Unit tests for scripts/crash_triage.py (P5 crash clustering, probe selection, circuit breaker)."""

from __future__ import annotations

import copy
import random
from typing import Any

import pytest

import crash_triage
import resources
import wp_scheduler

pytestmark = pytest.mark.unit


def _fp(fn: str, kind: str = "mem_access", idx: int = 0) -> str:
    return f"src/sudoers.c#{fn}::{kind}::{idx:010x}"


def _cand(
    fn: str,
    *,
    idx: int = 0,
    module: str = "sudoers",
    kind: str = "ubsan_runtime_error",
    alarm_kind: str = "mem_access",
    predicate: str = "rte: mem_access: member access within null pointer of type 'struct sudo_user'",
    input_bytes: int | None = 2,
    entry: str | None = None,
    dispatch_case: int | str | None = None,
    status: str | None = "unverified",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "fingerprint": _fp(fn, alarm_kind, idx),
        "module": module,
        "kind": kind,
        "alarm_kind": alarm_kind,
        "predicate": predicate,
        "location": {"file": "src/sudoers.c", "line": 10 + idx, "function": fn},
    }
    if status is not None:
        data["status"] = status
    if input_bytes is not None:
        data["input_bytes"] = input_bytes
    if entry is not None:
        data["entry"] = entry
    if dispatch_case is not None:
        data["dispatch_case"] = dispatch_case
    if extra:
        data.update(extra)
    return data


# ---------------------------------------------------------------------------
# 1. Feature flag: verifier_breaker_enabled
# ---------------------------------------------------------------------------


def test_verifier_breaker_enabled_default_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(crash_triage.VERIFIER_BREAKER_ENV, raising=False)
    assert crash_triage.verifier_breaker_enabled() is True


@pytest.mark.parametrize(
    "value", ["", "   ", "on", "ON", "On", "1", "true", "TRUE", "  true  ", " 1 ", "yes", "YES", " yes ", "enabled"]
)
def test_verifier_breaker_enabled_truthy_values(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv(crash_triage.VERIFIER_BREAKER_ENV, value)
    assert crash_triage.verifier_breaker_enabled() is True


@pytest.mark.parametrize("value", ["off", "OFF", "0", "false", "FALSE", "no", "NO", "  off  "])
def test_verifier_breaker_enabled_falsy_values(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv(crash_triage.VERIFIER_BREAKER_ENV, value)
    assert crash_triage.verifier_breaker_enabled() is False


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, True),
        ("", True),
        ("off", False),
        ("0", False),
        ("false", False),
        ("no", False),
        ("on", True),
        ("1", True),
        ("true", True),
        ("yes", True),
        ("YES", True),
        (" yes ", True),
    ],
)
def test_wp_scheduler_fuzz_explore_judge_delegates_to_resources(
    monkeypatch: pytest.MonkeyPatch, value: str | None, expected: bool
) -> None:
    if value is None:
        monkeypatch.delenv("FRAMAC_FUZZ_EXPLORE_JUDGE", raising=False)
    else:
        monkeypatch.setenv("FRAMAC_FUZZ_EXPLORE_JUDGE", value)
    assert wp_scheduler._fuzz_explore_judge_enabled() is expected
    assert wp_scheduler._fuzz_explore_judge_enabled() is resources.fuzz_explore_judge_enabled()


# ---------------------------------------------------------------------------
# 2. failure_family classification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("candidate", "expected"),
    [
        (
            {
                "kind": "ubsan_runtime_error",
                "alarm_kind": "mem_access",
                "predicate": "rte: mem_access: member access within null pointer of type 'struct sudo_user'",
            },
            "ubsan:null_member_access",
        ),
        (
            {
                "fingerprint": _fp("parse", "mem_access", 1),
                "property": {
                    "kind": "mem_access",
                    "predicate": "rte: mem_access: member access within null pointer of type 'struct ctx'",
                },
                "observations": [
                    {
                        "fingerprint": _fp("parse", "mem_access", 1),
                        "origin": "fuzz",
                        "engine": "ubsan",
                        "kind": "ubsan_runtime_error",
                        "message": "member access within null pointer of type 'struct ctx'",
                        "tool_output": "out.log",
                        "reproducer": "crash-1",
                    }
                ],
            },
            "ubsan:null_member_access",
        ),
        (
            {
                "kind": "ubsan_runtime_error",
                "alarm_kind": "mem_access",
                "predicate": "rte: mem_access: load of null pointer of type 'int'",
            },
            "ubsan:null_pointer",
        ),
        (
            {
                "kind": "ubsan_runtime_error",
                "alarm_kind": "index_bound",
                "predicate": "rte: index_bound: index N out of bounds for type 'char[64]'",
            },
            "ubsan:index_oob",
        ),
        (
            {
                "kind": "ubsan_runtime_error",
                "alarm_kind": "signed_overflow",
                "predicate": "rte: signed_overflow: signed integer overflow: N + N cannot be represented in type 'int'",
            },
            "ubsan:signed_overflow",
        ),
        (
            {
                "kind": "ubsan_segv",
                "alarm_kind": "mem_access",
                "message": "UndefinedBehaviorSanitizer: SEGV on unknown address 0x000000000000",
            },
            "ubsan:segv_null",
        ),
        (
            {
                "kind": "asan_attempting_free_on_address_which_was_not_malloc_ed",
                "alarm_kind": "freeable",
                "predicate": "rte: freeable: AddressSanitizer: attempting free on address which was not malloc()-ed",
            },
            "asan:non_malloc_free",
        ),
        (
            {
                "kind": "asan_attempting_double_free",
                "alarm_kind": "freeable",
                "predicate": "rte: freeable: AddressSanitizer: attempting double-free",
            },
            "asan:double_free",
        ),
        (
            {
                "kind": "asan_stack_buffer_overflow",
                "alarm_kind": "mem_access",
                "file": "workspace/harnesses/harness_sudoers.c",
                "function": "LLVMFuzzerTestOneInput",
                "predicate": "rte: mem_access: AddressSanitizer: stack-buffer-overflow (READ)",
            },
            "asan:stack_oob_harness",
        ),
        (
            {
                "kind": "asan_stack_buffer_overflow",
                "alarm_kind": "mem_access",
                "file": "src/parser.c",
                "function": "parse_rule",
                "predicate": "rte: mem_access: AddressSanitizer: stack-buffer-overflow (WRITE)",
            },
            "asan:stack_oob",
        ),
        (
            {
                "kind": "asan_heap_buffer_overflow",
                "alarm_kind": "mem_access",
                "predicate": "rte: mem_access: AddressSanitizer: heap-buffer-overflow (READ)",
            },
            "asan:heap_oob",
        ),
        (
            {
                "kind": "asan_heap_use_after_free",
                "alarm_kind": "dangling_pointer",
                "predicate": "rte: dangling_pointer: AddressSanitizer: heap-use-after-free (READ)",
            },
            "asan:use_after_free",
        ),
        (
            {
                "kind": "lsan_direct_leak",
                "alarm_kind": "memory_leak",
                "predicate": "memory_leak: LeakSanitizer: direct leak allocated in make_buf",
            },
            "lsan:direct_leak",
        ),
        (
            {
                "kind": "lsan_indirect_leak",
                "alarm_kind": "memory_leak",
                "predicate": "memory_leak: LeakSanitizer: indirect leak allocated in alloc_node",
            },
            "lsan:indirect_leak",
        ),
        (
            {
                "kind": "assertion",
                "alarm_kind": "mem_access",
                "predicate": r"\valid_read(p + i)",
            },
            "eacsl:mem_access",
        ),
        (
            {
                "kind": "eacsl_runtime_error",
                "alarm_kind": "mem_access",
                "predicate": "rte: mem_access: Use of invalid address in foo",
            },
            "eacsl:mem_access",
        ),
        (
            {
                "kind": "eacsl_format_error",
                "predicate": "Format error: invalid directive",
            },
            "eacsl:format_error",
        ),
        (
            {
                "kind": "toolchain_artifact",
                "summary": "error while loading shared libraries: libsudo_util.so: cannot open shared object file",
            },
            "toolchain:startup",
        ),
        (
            {
                "summary": "FRAMAC_LINK_STUB_CALLED: sudo_fatalx",
            },
            "toolchain:link_stub",
        ),
        (
            {
                "kind": "asan_requested_allocation_size",
                "predicate": "AddressSanitizer: requested allocation size exceeds maximum supported size",
            },
            "toolchain:resource_limit",
        ),
        (
            {
                "summary": "Process terminated with SIGABRT",
            },
            "signal:sigabrt",
        ),
        (
            {},
            "unknown:crash",
        ),
    ],
)
def test_failure_family_classifications(candidate: dict[str, Any], expected: str) -> None:
    snap = copy.deepcopy(candidate)
    assert crash_triage.failure_family(candidate) == expected
    assert candidate == snap


# ---------------------------------------------------------------------------
# 3. cluster_candidates
# ---------------------------------------------------------------------------


def test_cluster_candidates_sudo_38_null_deref_burst_and_determinism() -> None:
    # 38 distinct functions in module `sudoers` all hitting NULL member access through one entry.
    burst = [
        _cand(
            f"sudo_fn_{i:02d}",
            idx=i,
            module="sudoers",
            entry="sudoers_policy_open",
            input_bytes=2 + (i % 7),
        )
        for i in range(38)
    ]
    # Add two smaller clusters to verify deterministic cross-cluster ordering.
    heap_cluster = [
        _cand(
            f"heap_fn_{i}",
            idx=100 + i,
            module="sudoers",
            entry="sudoers_policy_open",
            kind="asan_heap_buffer_overflow",
            alarm_kind="mem_access",
            predicate="rte: mem_access: AddressSanitizer: heap-buffer-overflow (READ)",
            input_bytes=16 + i,
        )
        for i in range(4)
    ]
    free_cluster = [
        _cand(
            f"free_fn_{i}",
            idx=200 + i,
            module="sudoers",
            dispatch_case=3,
            kind="asan_attempting_free_on_address_which_was_not_malloc_ed",
            alarm_kind="freeable",
            predicate="rte: freeable: AddressSanitizer: attempting free on address which was not malloc()-ed",
            input_bytes=1 + i,
        )
        for i in range(4)
    ]
    # Already-verified candidate must be excluded from clustering.
    verified_cand = _cand("already_done", idx=999, status="verified", entry="sudoers_policy_open")

    all_cands = burst + heap_cluster + free_cluster + [verified_cand]
    shuffled = list(all_cands)
    random.Random(42).shuffle(shuffled)

    clusters_a = crash_triage.cluster_candidates(all_cands, lambda c: str(c.get("module") or "unknown"))
    clusters_b = crash_triage.cluster_candidates(shuffled, lambda c: str(c.get("module") or "unknown"))

    assert list(clusters_a.keys()) == list(clusters_b.keys())
    assert list(clusters_a.keys()) == [
        "sudoers::sudoers_policy_open::ubsan:null_member_access",
        "sudoers::case_3::asan:non_malloc_free",
        "sudoers::sudoers_policy_open::asan:heap_oob",
    ]
    # Burst cluster holds all 38 fingerprints; verified_cand excluded.
    assert len(clusters_a["sudoers::sudoers_policy_open::ubsan:null_member_access"]) == 38
    assert sum(len(v) for v in clusters_a.values()) == 38 + 4 + 4

    # Both 4-element clusters tie on size; free_cluster has smallest input_bytes=1 < 16 so comes first.
    for key in clusters_a:
        fps_a = [c["fingerprint"] for c in clusters_a[key]]
        fps_b = [c["fingerprint"] for c in clusters_b[key]]
        assert fps_a == fps_b

    # Within the 38-burst cluster, candidates are sorted by (input_bytes asc, fingerprint asc).
    burst_members = clusters_a["sudoers::sudoers_policy_open::ubsan:null_member_access"]
    keys = [(c["input_bytes"], c["fingerprint"]) for c in burst_members]
    assert keys == sorted(keys)


def test_cluster_candidates_missing_input_bytes_and_default_case() -> None:
    c_unknown = _cand("fn_a", idx=1, input_bytes=None)
    c_small = _cand("fn_b", idx=2, input_bytes=0)
    c_art = _cand("fn_c", idx=3, input_bytes=None, extra={"artifact": {"size_bytes": 5}})

    clusters = crash_triage.cluster_candidates([c_unknown, c_art, c_small], lambda c: str(c["module"]))
    assert list(clusters.keys()) == ["sudoers::default::ubsan:null_member_access"]
    ordered_fps = [c["fingerprint"] for c in clusters["sudoers::default::ubsan:null_member_access"]]
    assert ordered_fps == [c_small["fingerprint"], c_art["fingerprint"], c_unknown["fingerprint"]]


def test_cluster_candidates_tie_breaks_by_smallest_fingerprint() -> None:
    c_hi = _cand("z_fn", idx=1, dispatch_case=1, input_bytes=4)
    c_lo = _cand("a_fn", idx=2, dispatch_case=2, input_bytes=4)

    clusters = crash_triage.cluster_candidates([c_hi, c_lo], lambda c: str(c["module"]))
    assert list(clusters.keys()) == [
        "sudoers::case_2::ubsan:null_member_access",
        "sudoers::case_1::ubsan:null_member_access",
    ]


# ---------------------------------------------------------------------------
# 4. select_probe_batch
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("count", [1, 2, 3])
def test_select_probe_batch_small_module_passthrough_zero_delay(count: int) -> None:
    cands = [
        _cand(
            f"fn_{i}",
            idx=i,
            kind="asan_heap_buffer_overflow",
            predicate="rte: mem_access: AddressSanitizer: heap-buffer-overflow (READ)",
            input_bytes=32 + i,
        )
        for i in range(count)
    ]
    selected = crash_triage.select_probe_batch(cands, [])
    assert len(selected) == count
    assert set(selected) == {c["fingerprint"] for c in cands}


def test_select_probe_batch_prioritizes_tiny_null_free_harness_stack_and_distinct_families() -> None:
    # Large non-harness heap OOB cluster (10 candidates, 64+ bytes)
    heap_cands = [
        _cand(
            f"heap_{i}",
            idx=i,
            kind="asan_heap_buffer_overflow",
            predicate="rte: mem_access: AddressSanitizer: heap-buffer-overflow (READ)",
            input_bytes=64 + i,
        )
        for i in range(10)
    ]
    # Smaller 2-byte non-malloc free cluster (3 candidates) — high-signal broken harness!
    free_cands = [
        _cand(
            f"free_{i}",
            idx=100 + i,
            kind="asan_attempting_free_on_address_which_was_not_malloc_ed",
            alarm_kind="freeable",
            predicate="rte: freeable: AddressSanitizer: attempting free on address which was not malloc()-ed",
            input_bytes=2 + i,
        )
        for i in range(3)
    ]
    # Larger 1-byte NULL-deref cluster (5 candidates) — high-signal broken harness!
    null_cands = [
        _cand(
            f"null_{i}",
            idx=200 + i,
            kind="ubsan_runtime_error",
            alarm_kind="mem_access",
            predicate="rte: mem_access: member access within null pointer of type 'struct env'",
            input_bytes=1 + i,
        )
        for i in range(5)
    ]

    all_cands = heap_cands + free_cands + null_cands
    probes = crash_triage.select_probe_batch(all_cands, [], fanout_threshold=3, max_probes=2)

    assert len(probes) == 2
    # Probe #1: largest high-signal (<=4B + NULL) cluster, smallest input (1B)
    assert probes[0] == null_cands[0]["fingerprint"]
    # Probe #2: second distinct high-signal family (<=4B + non_malloc_free), smallest input (2B)
    assert probes[1] == free_cands[0]["fingerprint"]


def test_select_probe_batch_harness_stack_oob_prioritized_over_target_heap_oob() -> None:
    heap_cands = [
        _cand(
            f"heap_{i}",
            idx=i,
            kind="asan_heap_buffer_overflow",
            predicate="rte: mem_access: AddressSanitizer: heap-buffer-overflow (READ)",
            input_bytes=80 + i,
        )
        for i in range(8)
    ]
    harness_stack = [
        _cand(
            f"h_oob_{i}",
            idx=50 + i,
            kind="asan_stack_buffer_overflow",
            predicate="rte: mem_access: AddressSanitizer: stack-buffer-overflow in harness_sudoers.c",
            input_bytes=12 + i,
        )
        for i in range(2)
    ]

    probes = crash_triage.select_probe_batch(heap_cands + harness_stack, [])
    assert probes == [harness_stack[0]["fingerprint"], heap_cands[0]["fingerprint"]]


def test_select_probe_batch_single_family_burst_selects_two_probes() -> None:
    # All 38 candidates share a single failure family: must still select max_probes=2 so breaker can trip at 2/2.
    burst = [_cand(f"fn_{i:02d}", idx=i, input_bytes=1 + i) for i in range(38)]
    probes = crash_triage.select_probe_batch(burst, [], fanout_threshold=3, max_probes=2)
    assert probes == [burst[0]["fingerprint"], burst[1]["fingerprint"]]


def test_select_probe_batch_tracks_active_and_done_probes_and_releases_on_clear() -> None:
    null_cands = [_cand(f"null_{i}", idx=i, input_bytes=2 + i) for i in range(5)]
    heap_cands = [
        _cand(
            f"heap_{i}",
            idx=50 + i,
            kind="asan_heap_buffer_overflow",
            predicate="rte: mem_access: AddressSanitizer: heap-buffer-overflow (READ)",
            input_bytes=40 + i,
        )
        for i in range(4)
    ]
    all_cands = null_cands + heap_cands

    # Step 1: 0 active, 0 done -> selects 2 probes (1 null, 1 heap).
    p0 = crash_triage.select_probe_batch(all_cands, [])
    assert p0 == [null_cands[0]["fingerprint"], heap_cands[0]["fingerprint"]]

    # Step 2: probe #1 is running -> only 1 probe slot left, picks distinct family (heap_0).
    p1 = crash_triage.select_probe_batch(
        all_cands,
        [{"fingerprint": null_cands[0]["fingerprint"], "state": "running"}],
    )
    assert p1 == [heap_cands[0]["fingerprint"]]

    # Step 3: both probes running -> 0 slots left, wait!
    p2 = crash_triage.select_probe_batch(
        all_cands,
        [
            {"fingerprint": null_cands[0]["fingerprint"], "state": "running"},
            {"fingerprint": heap_cands[0]["fingerprint"], "state": "running"},
        ],
    )
    assert p2 == []

    # Step 4: probe #1 completed as harness_induced, probe #2 still running -> wait!
    p3 = crash_triage.select_probe_batch(
        all_cands,
        [
            {"fingerprint": null_cands[0]["fingerprint"], "state": "done", "outcome": "harness_induced"},
            {"fingerprint": heap_cands[0]["fingerprint"], "state": "running"},
        ],
    )
    assert p3 == []

    # Step 5a: probe #2 completes as confirmed -> 1/2 harness_induced does NOT trip -> release all 7 remaining!
    released = crash_triage.select_probe_batch(
        all_cands,
        [
            {"fingerprint": null_cands[0]["fingerprint"], "verdict": "rejected", "rejection_class": "harness_induced"},
            {"fingerprint": heap_cands[0]["fingerprint"], "verdict": "confirmed"},
        ],
    )
    expected_remaining = {c["fingerprint"] for c in all_cands} - {
        null_cands[0]["fingerprint"],
        heap_cands[0]["fingerprint"],
    }
    assert len(released) == 7
    assert set(released) == expected_remaining

    # Step 5b: if instead probe #2 also comes back harness_induced (2/2) -> breaker tripped -> return []!
    halted = crash_triage.select_probe_batch(
        all_cands,
        [
            {"fingerprint": null_cands[0]["fingerprint"], "outcome": "harness_induced"},
            {"fingerprint": heap_cands[0]["fingerprint"], "outcome": "harness_induced"},
        ],
    )
    assert halted == []


def test_select_probe_batch_four_candidate_module_stays_gated_after_first_completion() -> None:
    # Regression check: 4 candidates > fanout_threshold=3. After probe #1 finishes and leaves
    # module_candidates (leaving 3 unverified) while probe #2 is still running, do NOT fall back
    # to the <= 3 passthrough and prematurely release candidates #3 and #4!
    cands = [_cand(f"fn_{i}", idx=i, input_bytes=2 + i) for i in range(4)]
    remaining_three = cands[1:]
    verdicts = [
        {"fingerprint": cands[0]["fingerprint"], "outcome": "harness_induced"},
        {"fingerprint": cands[1]["fingerprint"], "state": "running"},
    ]
    assert crash_triage.select_probe_batch(remaining_three, verdicts, fanout_threshold=3, max_probes=2) == []


# ---------------------------------------------------------------------------
# 5. evaluate_circuit_breaker
# ---------------------------------------------------------------------------


def test_circuit_breaker_trips_at_2_of_2_and_2_of_3() -> None:
    two_of_two = crash_triage.evaluate_circuit_breaker(
        [
            {"fingerprint": _fp("a", idx=1), "outcome": "harness_induced"},
            {"fingerprint": _fp("b", idx=2), "verdict": "rejected", "rejection_class": "harness_induced"},
        ]
    )
    assert two_of_two["tripped"] is True
    assert two_of_two["harness_induced"] == 2
    assert two_of_two["verified"] == 2
    assert two_of_two["ratio"] == pytest.approx(1.0)
    assert "tripped" in two_of_two["reason"]

    two_of_three = crash_triage.evaluate_circuit_breaker(
        [
            {"fingerprint": _fp("a", idx=1), "outcome": "harness_induced"},
            {"fingerprint": _fp("b", idx=2), "verdict": "confirmed"},
            {
                "fingerprint": _fp("c", idx=3),
                "decision": "rejected",
                "record": {"verdict": "rejected", "rejection_class": "harness_induced"},
            },
        ]
    )
    assert two_of_three["tripped"] is True
    assert two_of_three["harness_induced"] == 2
    assert two_of_three["verified"] == 3
    assert two_of_three["ratio"] == pytest.approx(2 / 3)


def test_circuit_breaker_does_not_trip_on_low_ratio_or_real_bugs() -> None:
    # 1/2 harness_induced -> False
    one_of_two = crash_triage.evaluate_circuit_breaker(
        [
            {"outcome": "harness_induced"},
            {"outcome": "confirmed"},
        ]
    )
    assert one_of_two["tripped"] is False
    assert one_of_two["harness_induced"] == 1
    assert one_of_two["verified"] == 2
    assert one_of_two["ratio"] == pytest.approx(0.5)

    # 1/3 harness_induced -> False
    one_of_three = crash_triage.evaluate_circuit_breaker(
        [
            {"outcome": "harness_induced"},
            {"outcome": "confirmed"},
            {"outcome": "needs_validation"},
        ]
    )
    assert one_of_three["tripped"] is False
    assert one_of_three["harness_induced"] == 1
    assert one_of_three["verified"] == 3

    # 0/2 -> False
    zero_of_two = crash_triage.evaluate_circuit_breaker(
        [
            {"verdict": "rejected", "rejection_class": "dead_code"},
            {"verdict": "needs_validation"},
        ]
    )
    assert zero_of_two["tripped"] is False
    assert zero_of_two["harness_induced"] == 0
    assert zero_of_two["verified"] == 2

    # 2/2 confirmed real bugs -> False
    two_confirmed = crash_triage.evaluate_circuit_breaker(
        [
            {"verdict": "confirmed"},
            {"verdict": "confirmed"},
        ]
    )
    assert two_confirmed["tripped"] is False
    assert two_confirmed["harness_induced"] == 0
    assert two_confirmed["verified"] == 2

    # 2/4 harness_induced (ratio 0.5 < 2/3) -> False
    two_of_four = crash_triage.evaluate_circuit_breaker(
        [
            {"outcome": "harness_induced"},
            {"outcome": "harness_induced"},
            {"outcome": "confirmed"},
            {"outcome": "confirmed"},
        ]
    )
    assert two_of_four["tripped"] is False
    assert two_of_four["harness_induced"] == 2
    assert two_of_four["verified"] == 4
    assert two_of_four["ratio"] == pytest.approx(0.5)


def test_circuit_breaker_ignores_pending_running_and_blocked_entries() -> None:
    res = crash_triage.evaluate_circuit_breaker(
        [
            {"fingerprint": _fp("a", idx=1), "state": "pending", "outcome": None},
            {"fingerprint": _fp("b", idx=2), "state": "running", "outcome": None},
            {"fingerprint": _fp("c", idx=3), "status": "active"},
            {"fingerprint": _fp("d", idx=4), "state": "blocked", "outcome": "ingest_failed"},
            {"fingerprint": _fp("e", idx=5), "state": "skipped", "outcome": "candidate"},
            {"fingerprint": _fp("f", idx=6), "state": "done", "outcome": "harness_induced"},
            {"fingerprint": _fp("g", idx=7), "state": "done", "outcome": "harness_induced"},
        ]
    )
    assert res["tripped"] is True
    assert res["harness_induced"] == 2
    assert res["verified"] == 2
    assert res["ratio"] == pytest.approx(1.0)


def test_circuit_breaker_empty_and_custom_thresholds() -> None:
    empty = crash_triage.evaluate_circuit_breaker([])
    assert empty["tripped"] is False
    assert empty["harness_induced"] == 0
    assert empty["verified"] == 0
    assert empty["ratio"] == 0.0

    # Custom min_harness_induced=3, min_ratio=0.75
    verdicts = [
        {"outcome": "harness_induced"},
        {"outcome": "harness_induced"},
        {"outcome": "harness_induced"},
        {"outcome": "confirmed"},
    ]
    assert (
        crash_triage.evaluate_circuit_breaker(verdicts[:2], min_harness_induced=3, min_ratio=0.75)["tripped"] is False
    )
    assert crash_triage.evaluate_circuit_breaker(verdicts, min_harness_induced=3, min_ratio=0.75)["tripped"] is True
    assert (
        crash_triage.evaluate_circuit_breaker(
            [*verdicts, {"outcome": "confirmed"}], min_harness_induced=3, min_ratio=0.75
        )["tripped"]
        is False
    )
