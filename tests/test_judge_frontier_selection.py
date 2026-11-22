"""Unit tests for W1-D two-tier coverage-frontier E-ACSL judge selection, speed-aware Tier 2
expansion, per-case `not_judged_by_case` accounting, `FRAMAC_JUDGE_FRONTIER=off` rollback,
and `schemas/judge_report.schema.json` validation.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

import minischema
import run_eacsl_fuzz as R
import sandbox_exec
from generate_harness import _build_invocations
from sandbox_exec import SandboxResult

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parent.parent
JUDGE_REPORT_SCHEMA = REPO_ROOT / "schemas" / "judge_report.schema.json"


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now


def _write_dispatch_harness(tmp_path: Path, n_cases: int) -> Path:
    cases = [f"/* case {i} */ (void)fuzz_buf;" for i in range(n_cases)]
    _, fuzz = _build_invocations("f", "dispatch", dispatch_cases=cases)
    path = tmp_path / "harness_mod.c"
    path.write_text(
        "#include <stddef.h>\n#include <stdint.h>\n#include <stdlib.h>\n"
        "/* runtime dispatch case skip */\n"
        "static inline int framac_fuzz_skip_case(unsigned int c) {\n"
        '    const char *only_env = getenv("FRAMAC_FUZZ_ONLY_CASE"); (void)only_env;\n'
        "    return (int)(c == 9999U);\n"
        "}\n"
        "#ifndef FRAMAC_FUZZ_REJECT\n#define FRAMAC_FUZZ_REJECT() ((void)0)\n#endif\n"
        f"int run(uint8_t *fuzz_buf, size_t fuzz_len) {{\n    {fuzz}\n    return 0;\n}}\n",
        encoding="utf-8",
    )
    return path


def _make_build_json(
    tmp_path: Path,
    *,
    module: str = "mod",
    sources: list[str] | None = None,
    with_san: bool = True,
    with_eacsl: bool = True,
) -> tuple[Path, Path | None, Path | None]:
    san_bin: Path | None = None
    eacsl_bin: Path | None = None
    if with_san:
        san_bin = tmp_path / f"fuzz_{module}.san"
        san_bin.write_bytes(b"#!/bin/sh\nexit 0\n")
    if with_eacsl:
        eacsl_bin = tmp_path / f"fuzz_{module}.e-acsl"
        eacsl_bin.write_bytes(b"#!/bin/sh\nexit 0\n")
    doc: dict[str, Any] = {
        "mode": "build",
        "module": module,
        "status": "built",
        "engine_used": "eacsl" if with_eacsl else "sanitizers",
        "binary": str(eacsl_bin or san_bin),
        "sources": list(sources or []),
        "binaries": {
            "sanitizers": str(san_bin) if san_bin else None,
            "eacsl": str(eacsl_bin) if eacsl_bin else None,
        },
        "compile": {
            "returncode": 0,
            "binary": str(eacsl_bin or san_bin),
            "engine": "eacsl" if with_eacsl else "sanitizers",
        },
    }
    if with_san:
        doc["sanitizer_compile"] = {"returncode": 0, "binary": str(san_bin), "engine": "sanitizers"}
    bpath = tmp_path / f"{module}.build.json"
    bpath.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return bpath, san_bin, eacsl_bin


def test_frontier_100_percent_selected_with_40k_unmerged_files(tmp_path: Path) -> None:
    """When 40,000 unmerged grown files exist alongside a 2,500-file frontier, 100% of the
    frontier is selected in Tier 1 ahead of unmerged mutations (and all 42,500 stay on disk).
    """
    corpus = tmp_path / "corpus"
    corpus.mkdir()

    frontier_names: set[str] = set()
    for i in range(2500):
        name = f"fr_{i:05d}"
        frontier_names.add(name)
        (corpus / name).write_bytes(b"F")

    for i in range(40000):
        (corpus / f"unmerged_{i:05d}").write_bytes(b"U")

    sel = R.select_judge_inputs(
        corpus,
        cap=R.JUDGE_CORPUS_CAP_BY_PROFILE["standard"],
        n_cases=None,
        frontier_names=frontier_names,
        frontier_cap=R.JUDGE_FRONTIER_CAP_BY_PROFILE["standard"],
    )

    assert sel["grown_total"] == 42500
    assert sel["frontier_total"] == 2500
    assert sel["frontier_selected"] == 2500
    assert sel["grown_selected"] == 2500
    assert sel["not_judged_cap"] == 40000

    selected_names = {p.name for p in sel["selected"]}
    assert frontier_names.issubset(selected_names)
    assert len(selected_names & frontier_names) == 2500
    # Remaining 40,000 non-frontier files remain in tier2_pool and untouched on disk.
    assert len(sel["tier2_pool"]) == 40000
    assert sum(1 for p in corpus.iterdir() if p.is_file()) == 42500


def test_not_judged_by_case_accounting_and_tier1_priority(tmp_path: Path) -> None:
    """Cases whose grown inputs are all selected have `not_judged_by_case.get(k, 0) == 0`,
    while capped cases accurately report their remaining unjudged counts.
    """
    corpus = tmp_path / "corpus"
    corpus.mkdir()

    frontier_names: set[str] = set()
    # Cases 0 and 1: 4 files each, all in frontier -> 0 unjudged.
    for c in (0, 1):
        for i in range(4):
            name = f"f_c{c}_{i}"
            frontier_names.add(name)
            (corpus / name).write_bytes(bytes([c, i]))
    # Case 2: 2 frontier + 10 overflow (cap=12 leaves 2 Tier 2 slots for overflow across cases 2 & 3 -> 1 each).
    for i in range(2):
        name = f"f_c2_{i}"
        frontier_names.add(name)
        (corpus / name).write_bytes(bytes([2, i]))
    for i in range(10):
        (corpus / f"ov_c2_{i:02d}").write_bytes(bytes([2, 100 + i]))
    # Case 3: 0 frontier + 8 overflow.
    for i in range(8):
        (corpus / f"ov_c3_{i:02d}").write_bytes(bytes([3, 100 + i]))
    # Case 4: 3 files, smoke-skipped -> all 3 counted in not_judged_by_case["4"].
    for i in range(3):
        (corpus / f"sm_c4_{i}").write_bytes(bytes([4, i]))

    sel = R.select_judge_inputs(
        corpus,
        cap=12,
        n_cases=5,
        selector="identity",
        smoke_skipped=[4],
        frontier_names=frontier_names,
        frontier_cap=50,
    )

    assert sel["frontier_total"] == 10
    assert sel["frontier_selected"] == 10
    assert sel["grown_selected"] == 12  # 10 frontier + 2 Tier 2 (1 from case 2, 1 from case 3)
    assert sel["not_judged_cap"] == 16  # 9 from case 2 + 7 from case 3
    assert sel["not_judged_smoke"] == 3

    nj_by_case = sel["not_judged_by_case"]
    assert nj_by_case.get("0", 0) == 0
    assert nj_by_case.get("1", 0) == 0
    assert nj_by_case["2"] == 9
    assert nj_by_case["3"] == 7
    assert nj_by_case["4"] == 3
    assert sum(nj_by_case.values()) == sel["not_judged_cap"] + sel["not_judged_smoke"]

    # Tier 1 frontier files appear strictly before Tier 2 overflow files in selection order.
    selected_names = [p.name for p in sel["selected"]]
    assert set(selected_names[:10]) == frontier_names
    assert set(selected_names[10:]).isdisjoint(frontier_names)


def test_discover_judge_frontier_readonly_merge_and_floor_hash_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`discover_judge_frontier` runs read-only `-merge=1` into scratch, keeps `corpus_dir`
    unmodified (not in `writable`), and matches both SHA-1 and `floor_*` filenames.
    """
    san_bin = tmp_path / "fuzz_mod.san"
    san_bin.write_bytes(b"san")
    corpus = tmp_path / "corpus"
    corpus.mkdir()

    sha1_name = "a" * 40
    (corpus / sha1_name).write_bytes(b"\x00direct-match")
    floor_payload = b"\x01floor-unit-payload"
    (corpus / "floor_c1_deadbeef00112233").write_bytes(floor_payload)
    (corpus / "non_frontier_extra").write_bytes(b"\x02extra-mutation")

    seen_calls: list[tuple[list[str], list[Path]]] = []

    def fake_sandbox(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        seen_calls.append((list(cmd), [Path(w) for w in writable]))
        assert "-merge=1" in cmd
        assert timeout_s == R.JUDGE_MERGE_TIMEOUT_S
        # corpus_dir must NOT be writable.
        assert corpus.resolve() not in [Path(w).resolve() for w in writable]
        merge_dst = Path(cmd[-2])
        # libFuzzer writes SHA-1 named copies into merge_dst.
        (merge_dst / sha1_name).write_bytes(b"\x00direct-match")
        floor_sha1 = hashlib.sha1(floor_payload).hexdigest()
        (merge_dst / floor_sha1).write_bytes(floor_payload)
        return SandboxResult(returncode=0, stdout="", stderr="MERGE-OUTER: done\n", timed_out=False, sandbox="fake")

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_sandbox)
    frontier = R.discover_judge_frontier(san_bin, corpus)
    assert len(seen_calls) == 1
    assert frontier == {sha1_name, "floor_c1_deadbeef00112233"}
    # Original corpus is completely untouched (all 3 files intact).
    assert sorted(p.name for p in corpus.iterdir()) == sorted(
        [sha1_name, "floor_c1_deadbeef00112233", "non_frontier_extra"]
    )

    # Timeout or non-zero exit falls back cleanly to None.
    monkeypatch.setattr(
        sandbox_exec,
        "run_sandboxed",
        lambda *a, **kw: SandboxResult(returncode=1, stdout="", stderr="timeout", timed_out=True, sandbox="fake"),
    )
    assert R.discover_judge_frontier(san_bin, corpus) is None

    # SandboxUnavailable falls back cleanly to None.
    def raise_sbx(*_a, **_kw):
        raise sandbox_exec.SandboxUnavailable("no sandbox")

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", raise_sbx)
    assert R.discover_judge_frontier(san_bin, corpus) is None


def test_compute_tier2_expansion_qcbor_and_hard_cap() -> None:
    """Speed-aware Tier 2 expansion matches QCBOR throughput (119.5 inputs/s -> ~120 s budget)
    and enforces the 16,384 grown-input hard cap while keeping slow modules unexpanded.
    """
    # QCBOR run-1: 1,177 mandatory, 2,591 frontier, 39,697 overflow, 119.5 inputs/s, 120 s target.
    extra_qcbor = R.compute_tier2_expansion(
        already_selected_total=1177 + 2591,
        already_selected_grown=2591,
        mandatory_count=1177,
        available_overflow=39697,
        inputs_per_s=119.5,
        target_replay_s=120,
        hard_cap=R.JUDGE_TIER2_HARD_CAP,
    )
    # 119.5 * 120 = 14,340 total -> 13,163 grown -> 10,572 additional Tier 2 overflow inputs.
    assert extra_qcbor == 10572
    assert 2591 + extra_qcbor <= R.JUDGE_TIER2_HARD_CAP

    # Very fast module (500 inputs/s * 120 s = 60,000) is hard-capped at 16,384 grown inputs.
    extra_fast = R.compute_tier2_expansion(
        already_selected_total=100 + 2000,
        already_selected_grown=2000,
        mandatory_count=100,
        available_overflow=50000,
        inputs_per_s=500.0,
        target_replay_s=120,
        hard_cap=R.JUDGE_TIER2_HARD_CAP,
    )
    assert 2000 + extra_fast == R.JUDGE_TIER2_HARD_CAP

    # Slow module (5 inputs/s * 120 s = 600 <= already selected 2,591) adds 0 extra overflow.
    extra_slow = R.compute_tier2_expansion(
        already_selected_total=100 + 2591,
        already_selected_grown=2591,
        mandatory_count=100,
        available_overflow=30000,
        inputs_per_s=5.0,
        target_replay_s=120,
        hard_cap=R.JUDGE_TIER2_HARD_CAP,
    )
    assert extra_slow == 0


def test_run_judge_two_tier_discovery_and_speed_aware_expansion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End-to-end `run_judge` runs `-merge=1` on `.san`, selects 100% of the frontier, expands
    Tier 2 based on first-batch throughput, updates `not_judged_by_case`, and validates schema.
    """
    clock = FakeClock()
    monkeypatch.setattr(R.time, "monotonic", clock.monotonic)
    monkeypatch.delenv(R.JUDGE_FRONTIER_ENV, raising=False)

    harness = _write_dispatch_harness(tmp_path, 4)
    bjson, _san, _eacsl = _make_build_json(tmp_path, module="fastmod", sources=[str(harness)])
    corpus = tmp_path / "corpus"
    corpus.mkdir()

    # 30 frontier files across cases 0..3 + 170 non-frontier overflow files (200 total > cap=20).
    frontier_names: set[str] = set()
    for i in range(30):
        name = f"fr_{i:03d}"
        frontier_names.add(name)
        (corpus / name).write_bytes(bytes([i % 4, i]))
    for i in range(170):
        (corpus / f"ov_{i:03d}").write_bytes(bytes([i % 4, 50 + (i % 200)]))

    merge_invoked = 0
    judged_names: list[str] = []

    def fake_sandbox(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        nonlocal merge_invoked
        if "-merge=1" in cmd:
            merge_invoked += 1
            merge_dst = Path(cmd[-2])
            for fn in frontier_names:
                (merge_dst / fn).write_bytes((corpus / fn).read_bytes())
            return SandboxResult(returncode=0, stdout="", stderr="MERGE-OUTER\n", timed_out=False, sandbox="fake")

        inputs_in_cmd = [Path(a) for a in cmd[1:] if not a.startswith("-")]
        # Simulate fast replay: ~100 inputs/s (0.01 s per input).
        clock.now += 0.01 * len(inputs_in_cmd)
        lines: list[str] = []
        for p in inputs_in_cmd:
            judged_names.append(p.name)
            lines.append(f"Running: {p.resolve()}")
            lines.append(f"Executed {p.resolve()} in 1 ms")
        return SandboxResult(returncode=0, stdout="", stderr="\n".join(lines), timed_out=False, sandbox="fake")

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_sandbox)

    # Initial cap=20, frontier_cap=50, target_replay_s=1 -> 100 inputs/s * 1 s = 100 total grown!
    rep = R.run_judge(
        "fastmod",
        bjson,
        corpus,
        profile="standard",
        max_corpus_inputs=20,
        frontier_cap=50,
        target_replay_s=1,
        batch_size=10,
    )

    assert merge_invoked == 1
    assert rep["status"] == "clean"
    assert rep["frontier_total"] == 30
    assert rep["frontier_judged"] == 30
    assert rep["inputs"]["frontier_total"] == 30
    assert rep["inputs"]["frontier_judged"] == 30
    # Expanded from 30 (frontier only) up to 100 grown inputs (30 frontier + 70 Tier 2 overflow).
    assert rep["inputs"]["grown_selected"] == 100
    assert rep["inputs"]["judged"] == 100
    assert rep["inputs"]["not_judged_breakdown"]["cap"] == 100
    assert rep["not_judged"] == 100
    assert sum(rep["not_judged_by_case"].values()) == 100
    assert rep["inputs"]["not_judged_by_case"] == rep["not_judged_by_case"]
    # 100% of frontier judged, and frontier ran before expanded Tier 2 overflow.
    assert frontier_names.issubset(set(judged_names))
    assert set(judged_names[:30]) == frontier_names

    judge_schema = minischema.load_schema(JUDGE_REPORT_SCHEMA)
    assert minischema.validate(rep, judge_schema) == []


def test_judge_frontier_env_rollback_off(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Setting `FRAMAC_JUDGE_FRONTIER=off` disables `-merge=1` frontier discovery and Tier 2
    expansion, restoring single-tier case-stratified SHA-256 selection up to `cap`.
    """
    assert R.judge_frontier_enabled({}) is True
    assert R.judge_frontier_enabled({R.JUDGE_FRONTIER_ENV: "on"}) is True
    for off_val in ("off", "OFF", "0", "false", "no"):
        assert R.judge_frontier_enabled({R.JUDGE_FRONTIER_ENV: off_val}) is False

    clock = FakeClock()
    monkeypatch.setattr(R.time, "monotonic", clock.monotonic)
    monkeypatch.setenv(R.JUDGE_FRONTIER_ENV, "off")

    harness = _write_dispatch_harness(tmp_path, 3)
    bjson, _san, _eacsl = _make_build_json(tmp_path, module="rbmod", sources=[str(harness)])
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    for i in range(60):
        (corpus / f"u_{i:03d}").write_bytes(bytes([i % 3, i]))

    merge_seen = False

    def fake_sandbox(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        nonlocal merge_seen
        if "-merge=1" in cmd:
            merge_seen = True
        inputs_in_cmd = [Path(a) for a in cmd[1:] if not a.startswith("-")]
        clock.now += 0.005 * len(inputs_in_cmd)
        lines = [f"Running: {p.resolve()}\nExecuted {p.resolve()} in 1 ms" for p in inputs_in_cmd]
        return SandboxResult(returncode=0, stdout="", stderr="\n".join(lines), timed_out=False, sandbox="fake")

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_sandbox)
    rep = R.run_judge(
        "rbmod", bjson, corpus, profile="standard", max_corpus_inputs=15, target_replay_s=60, batch_size=5
    )

    assert merge_seen is False
    assert rep["frontier_total"] == 0
    assert rep["frontier_judged"] == 0
    assert rep["inputs"]["grown_selected"] == 15
    assert rep["inputs"]["judged"] == 15
    assert rep["not_judged"] == 45
    assert rep["not_judged_by_case"] == {"0": 15, "1": 15, "2": 15}
    assert minischema.validate(rep, minischema.load_schema(JUDGE_REPORT_SCHEMA)) == []


def test_judge_report_schema_backward_compatible_and_rejects_bad_types() -> None:
    """`judge_report.schema.json` accepts both legacy reports without W1-D fields and new reports
    with them, while rejecting malformed values for `frontier_total`, `frontier_judged`, and
    `not_judged_by_case`.
    """
    schema = minischema.load_schema(JUDGE_REPORT_SCHEMA)
    base: dict[str, Any] = {
        "schema_version": 1,
        "mode": "judge",
        "module": "mod",
        "generated_at": "2026-11-22T00:00:00Z",
        "discovering_step": "judge",
        "engine_used": "eacsl",
        "profile": "standard",
        "status": "clean",
        "binary": "fuzz_mod.e-acsl",
        "corpus_cap": 2048,
        "inputs": {
            "total": 100,
            "mandatory": 10,
            "grown_total": 90,
            "grown_selected": 90,
            "selected": 100,
            "judged": 100,
            "passed": 100,
            "failed": 0,
            "not_judged": 0,
            "not_judged_breakdown": {"cap": 0, "timeout": 0, "blinded": 0, "smoke_skipped": 0, "error": 0},
        },
        "not_judged": 0,
        "artifacts": [],
        "batch_state_only": [],
        "cross_engine_links": [],
        "smoke_skipped_cases": [],
        "blinded_cases": [],
        "partial_blinded": False,
        "telemetry": {
            "judge_s": 1.0,
            "batch_s": 1.0,
            "confirm_s": 0.0,
            "inputs_per_s": 100.0,
            "batches_run": 2,
            "fresh_confirmations": 0,
        },
    }
    # Legacy shape without W1-D optional fields still validates.
    assert minischema.validate(base, schema) == []

    # With W1-D optional fields validates cleanly.
    with_new = json.loads(json.dumps(base))
    with_new["frontier_total"] = 2591
    with_new["frontier_judged"] = 2591
    with_new["not_judged_by_case"] = {"2": 15, "5": 3}
    with_new["inputs"]["frontier_total"] = 2591
    with_new["inputs"]["frontier_judged"] = 2591
    with_new["inputs"]["not_judged_by_case"] = {"2": 15, "5": 3}
    assert minischema.validate(with_new, schema) == []

    # Negative frontier_total or invalid not_judged_by_case entry is rejected.
    bad1 = json.loads(json.dumps(with_new))
    bad1["frontier_total"] = -1
    assert minischema.validate(bad1, schema)

    bad2 = json.loads(json.dumps(with_new))
    bad2["not_judged_by_case"] = {"0": -5}
    assert minischema.validate(bad2, schema)

    bad3 = json.loads(json.dumps(with_new))
    bad3["inputs"]["not_judged_by_case"] = {"0": "five"}
    assert minischema.validate(bad3, schema)
