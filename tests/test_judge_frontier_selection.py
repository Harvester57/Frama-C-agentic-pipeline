"""Unit tests for W1-D two-tier coverage-frontier E-ACSL judge selection, speed-aware Tier 2
expansion, per-case `not_judged_by_case` accounting, `FRAMAC_JUDGE_FRONTIER=off` rollback,
and `schemas/judge_report.schema.json` validation.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

import minischema
import run_eacsl_fuzz as R
import sandbox_exec
from generate_harness import _build_invocations
from sandbox_exec import SandboxResult

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


@pytest.mark.unit
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


@pytest.mark.unit
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


@pytest.mark.unit
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


@pytest.mark.unit
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


@pytest.mark.unit
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


@pytest.mark.unit
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


@pytest.mark.unit
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

    # frontier_status and frontier_merge validate cleanly and reject malformed values.
    for valid_status in (
        "ok",
        "provided",
        "disabled",
        "below_cap",
        "no_san_binary",
        "skipped",
        "timed_out",
        "no_files",
        "sandbox_unavailable",
        "rc=1",
        "rc=-9",
    ):
        doc_ok = json.loads(json.dumps(with_new))
        doc_ok["frontier_status"] = valid_status
        doc_ok["frontier_merge"] = {
            "status": valid_status,
            "returncode": 0 if valid_status == "ok" else 1,
            "timed_out": valid_status == "timed_out",
            "timeout_s": 202,
            "elapsed_s": 12.34,
            "stage_s": 1.5,
            "staged_locally": True,
            "corpus_files": 60467,
            "merged_files": 4847 if valid_status == "ok" else 0,
            "matched_files": 4847 if valid_status == "ok" else 0,
            "stderr_tail": "MERGE-OUTER: done\n",
            "reason": None,
        }
        assert minischema.validate(doc_ok, schema) == []

    bad_status = json.loads(json.dumps(with_new))
    bad_status["frontier_status"] = "bogus_status"
    assert minischema.validate(bad_status, schema)

    bad_merge = json.loads(json.dumps(with_new))
    bad_merge["frontier_merge"] = {"status": "timed_out", "timeout_s": -5}
    assert minischema.validate(bad_merge, schema)


@pytest.mark.unit
def test_compute_judge_merge_timeout_scales_with_corpus_and_respects_budget() -> None:
    """`-merge=1` wall limit keeps the 30 s floor for small corpora, scales linearly for large
    corpora (e.g. 60,467 files -> 202 s), and respects both the hard cap and judge budget share.
    """
    assert R.compute_judge_merge_timeout(0) == R.JUDGE_MERGE_TIMEOUT_S
    assert R.compute_judge_merge_timeout(3) == R.JUDGE_MERGE_TIMEOUT_S
    assert R.compute_judge_merge_timeout(9000) == R.JUDGE_MERGE_TIMEOUT_S
    assert R.compute_judge_merge_timeout(15000) == 50
    assert R.compute_judge_merge_timeout(60467) == 202
    assert R.compute_judge_merge_timeout(60467, max_time_s=1800) == 202
    assert R.compute_judge_merge_timeout(120000, max_time_s=1800) == R.JUDGE_MERGE_MAX_TIMEOUT_S
    assert R.compute_judge_merge_timeout(60467, max_time_s=300) == 100
    assert R.compute_judge_merge_timeout(60467, max_time_s=60) == 20


@pytest.mark.unit
def test_filesystem_type_and_slow_mount_detection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`_filesystem_type_for_path` picks the longest matching mount point from mountinfo
    (decoding octal escapes) and `_is_slow_mount` flags 9p/fuse/drvfs/virtiofs mounts only.
    """
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(
        "\n".join(
            [
                "618 456 0:93 / / rw,relatime - overlay overlay rw",
                "625 618 0:114 / /tmp rw,nosuid - tmpfs tmpfs rw",
                "627 618 0:71 /Users/dev/run /framac-run rw,noatime - 9p C:\\134 rw,aname=drvfs;path=C:\\",
                "628 618 0:72 /share /mnt/win\\040share ro - drvfs D: ro",
                "629 618 0:73 /mac /mnt/mac rw - fuse.grpcfuse grpcfuse rw",
                "630 618 0:74 /v /mnt/virt rw - virtiofs virtiofs rw",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(R.os.path, "realpath", lambda p: Path(p).as_posix())

    assert R._filesystem_type_for_path(Path("/tmp/judge_frontier"), mountinfo_path=mountinfo) == "tmpfs"
    assert R._is_slow_mount(Path("/tmp/judge_frontier"), mountinfo_path=mountinfo) is False

    assert R._filesystem_type_for_path(Path("/var/scratch/work"), mountinfo_path=mountinfo) == "overlay"
    assert R._is_slow_mount(Path("/var/scratch/work"), mountinfo_path=mountinfo) is False

    assert R._filesystem_type_for_path(Path("/framac-run/workspace/corpus/mod"), mountinfo_path=mountinfo) == "9p"
    assert R._is_slow_mount(Path("/framac-run/workspace/corpus/mod"), mountinfo_path=mountinfo) is True

    assert R._filesystem_type_for_path(Path("/mnt/win share/corpus"), mountinfo_path=mountinfo) == "drvfs"
    assert R._is_slow_mount(Path("/mnt/win share/corpus"), mountinfo_path=mountinfo) is True

    assert R._filesystem_type_for_path(Path("/mnt/mac/corpus"), mountinfo_path=mountinfo) == "fuse.grpcfuse"
    assert R._is_slow_mount(Path("/mnt/mac/corpus"), mountinfo_path=mountinfo) is True

    assert R._filesystem_type_for_path(Path("/mnt/virt/corpus"), mountinfo_path=mountinfo) == "virtiofs"
    assert R._is_slow_mount(Path("/mnt/virt/corpus"), mountinfo_path=mountinfo) is True

    assert R._filesystem_type_for_path(Path("/any"), mountinfo_path=tmp_path / "missing") is None
    assert R._is_slow_mount(Path("/any"), mountinfo_path=tmp_path / "missing") is False


@pytest.mark.unit
def test_discover_judge_frontier_detailed_statuses_and_stderr_tail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`discover_judge_frontier_detailed` classifies every failure mode (`timed_out`, `rc=N`,
    `no_files`, `sandbox_unavailable`) and captures the stderr tail bounded to 2000 bytes.
    """
    san_bin = tmp_path / "fuzz_mod.san"
    san_bin.write_bytes(b"san")
    corpus = tmp_path / "corpus"

    # Missing directory -> no_files without invoking sandbox.
    sandbox_called = False

    def fail_if_called(*_a: Any, **_kw: Any) -> SandboxResult:
        nonlocal sandbox_called
        sandbox_called = True
        return SandboxResult(returncode=0, stdout="", stderr="", timed_out=False, sandbox="fake")

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fail_if_called)
    r_missing = R.discover_judge_frontier_detailed(san_bin, corpus)
    assert r_missing.status == "no_files"
    assert r_missing.frontier_names is None
    assert sandbox_called is False

    # Empty directory -> no_files without invoking sandbox.
    corpus.mkdir()
    r_empty = R.discover_judge_frontier_detailed(san_bin, corpus)
    assert r_empty.status == "no_files"
    assert r_empty.corpus_files == 0
    assert sandbox_called is False

    (corpus / "u1").write_bytes(b"\x01hello")
    (corpus / "u2").write_bytes(b"\x02world")

    # Timeout -> timed_out (even when returncode is -9), with stderr tail capped at 2000 bytes.
    long_err = "X" * 3000 + "TAIL_MARKER_TIMEOUT"
    monkeypatch.setattr(
        sandbox_exec,
        "run_sandboxed",
        lambda *a, **kw: SandboxResult(returncode=-9, stdout="", stderr=long_err, timed_out=True, sandbox="fake"),
    )
    r_to = R.discover_judge_frontier_detailed(san_bin, corpus)
    assert r_to.status == "timed_out"
    assert r_to.timed_out is True
    assert r_to.returncode == -9
    assert r_to.frontier_names is None
    assert len(r_to.stderr_tail) == R.JUDGE_MERGE_STDERR_TAIL_BYTES
    assert r_to.stderr_tail.endswith("TAIL_MARKER_TIMEOUT")

    # Non-zero exit -> rc=<N>.
    monkeypatch.setattr(
        sandbox_exec,
        "run_sandboxed",
        lambda *a, **kw: SandboxResult(
            returncode=77, stdout="", stderr="ERROR: libFuzzer merge rc 77\n", timed_out=False, sandbox="fake"
        ),
    )
    r_rc = R.discover_judge_frontier_detailed(san_bin, corpus)
    assert r_rc.status == "rc=77"
    assert r_rc.returncode == 77
    assert r_rc.timed_out is False
    assert "rc 77" in r_rc.stderr_tail

    # Clean exit but 0 merged files -> no_files.
    monkeypatch.setattr(
        sandbox_exec,
        "run_sandboxed",
        lambda *a, **kw: SandboxResult(
            returncode=0, stdout="", stderr="MERGE-OUTER: 0 files\n", timed_out=False, sandbox="fake"
        ),
    )
    r_zero = R.discover_judge_frontier_detailed(san_bin, corpus)
    assert r_zero.status == "no_files"
    assert r_zero.merged_files == 0

    # Clean exit with merged file whose content matches nothing in corpus -> no_files.
    def write_unmatched(cmd: list[str], *_a: Any, **_kw: Any) -> SandboxResult:
        merge_dst = Path(cmd[-2])
        (merge_dst / ("f" * 40)).write_bytes(b"completely different payload")
        return SandboxResult(returncode=0, stdout="", stderr="MERGE-OUTER: 1 file\n", timed_out=False, sandbox="fake")

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", write_unmatched)
    r_unmatched = R.discover_judge_frontier_detailed(san_bin, corpus)
    assert r_unmatched.status == "no_files"
    assert r_unmatched.merged_files == 1
    assert r_unmatched.matched_files == 0

    # SandboxUnavailable -> sandbox_unavailable with reason.
    def raise_sbx(*_a: Any, **_kw: Any) -> SandboxResult:
        raise sandbox_exec.SandboxUnavailable("not posix")

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", raise_sbx)
    r_sbx = R.discover_judge_frontier_detailed(san_bin, corpus)
    assert r_sbx.status == "sandbox_unavailable"
    assert r_sbx.reason == "not posix"


@pytest.mark.unit
def test_discover_judge_frontier_stages_locally_on_slow_mount_and_matches_floor_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When `corpus_dir` sits on a slow mount (e.g. 9p `/framac-run`) and scratch is local,
    `discover_judge_frontier_detailed` stages files in parallel into local scratch, runs
    `-merge=1` against the staged directory (not `corpus_dir`), and resolves `floor_*` names
    via the in-memory digest map without re-reading `corpus_dir`.
    """
    san_bin = tmp_path / "fuzz_mod.san"
    san_bin.write_bytes(b"san")
    corpus = tmp_path / "slow_corpus"
    corpus.mkdir()
    scratch = tmp_path / "local_scratch"
    scratch.mkdir()

    sha1_name = "b" * 40
    (corpus / sha1_name).write_bytes(b"\x00sha1-unit")
    floor_bytes = b"\x01floor-unit-bytes"
    (corpus / "floor_c1_aabbccdd").write_bytes(floor_bytes)
    (corpus / "extra_non_frontier").write_bytes(b"\x02ignored")

    def fake_is_slow(path: Path, **_kw: Any) -> bool:
        return Path(path).resolve() == corpus.resolve()

    monkeypatch.setattr(R, "_is_slow_mount", fake_is_slow)

    seen_src: list[Path] = []

    def fake_sandbox(cmd: list[str], writable: list[Path], timeout_s: int, **_kw: Any) -> SandboxResult:
        merge_dst = Path(cmd[-2])
        merge_src = Path(cmd[-1])
        seen_src.append(merge_src)
        # Must run against staged local copy inside scratch, NOT corpus_dir.
        assert merge_src.resolve() != corpus.resolve()
        assert merge_src.resolve().parent == scratch.resolve()
        assert corpus.resolve() not in [Path(w).resolve() for w in writable]
        # Verify staged copy has all 3 files intact.
        assert sorted(p.name for p in merge_src.iterdir()) == sorted(
            [sha1_name, "floor_c1_aabbccdd", "extra_non_frontier"]
        )
        (merge_dst / sha1_name).write_bytes(b"\x00sha1-unit")
        (merge_dst / hashlib.sha1(floor_bytes).hexdigest()).write_bytes(floor_bytes)
        return SandboxResult(
            returncode=0, stdout="", stderr="MERGE-OUTER: 2 new files\n", timed_out=False, sandbox="fake"
        )

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_sandbox)

    res = R.discover_judge_frontier_detailed(san_bin, corpus, scratch_dir=scratch)
    assert len(seen_src) == 1
    assert res.status == "ok"
    assert res.staged_locally is True
    assert res.stage_s >= 0.0
    assert res.corpus_files == 3
    assert res.merged_files == 2
    assert res.matched_files == 2
    assert res.frontier_names == {sha1_name, "floor_c1_aabbccdd"}
    assert sorted(p.name for p in corpus.iterdir()) == sorted([sha1_name, "floor_c1_aabbccdd", "extra_non_frontier"])


@pytest.mark.unit
def test_discover_judge_frontier_stage_byte_cap_falls_back_cleanly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If local staging exceeds the byte cap, it cleans up partial files and falls back to
    running `-merge=1` directly against `corpus_dir` while recording why staging was skipped.
    """
    san_bin = tmp_path / "fuzz_mod.san"
    san_bin.write_bytes(b"san")
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "u1").write_bytes(b"A" * 2048)
    (corpus / "u2").write_bytes(b"B" * 2048)

    orig_stage = R._stage_corpus_for_merge

    def tiny_cap_stage(dest_dir: Path, entries: Any, **_kw: Any) -> Any:
        return orig_stage(dest_dir, entries, max_bytes=1024, min_free_bytes=0, max_workers=2)

    monkeypatch.setattr(R, "_stage_corpus_for_merge", tiny_cap_stage)

    seen_src: list[Path] = []

    def fake_sandbox(cmd: list[str], *_a: Any, **_kw: Any) -> SandboxResult:
        merge_dst = Path(cmd[-2])
        merge_src = Path(cmd[-1])
        seen_src.append(merge_src)
        (merge_dst / "u1").write_bytes(b"A" * 2048)
        return SandboxResult(
            returncode=0, stdout="", stderr="MERGE-OUTER: 1 new file\n", timed_out=False, sandbox="fake"
        )

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_sandbox)
    res = R.discover_judge_frontier_detailed(san_bin, corpus, stage_locally=True)
    assert seen_src == [corpus.resolve()]
    assert res.status == "ok"
    assert res.staged_locally is False
    assert res.frontier_names == {"u1"}
    assert res.reason is not None and "cap" in res.reason


@pytest.mark.unit
def test_run_judge_records_frontier_status_merge_info_diagnostic_hints_and_stderr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`run_judge` never leaves `frontier_total: 0` unexplained: timeout, missing `.san`,
    below-cap, disabled, and ok paths all record `frontier_status`, `frontier_merge` (when
    attempted), `diagnostic_hints` (on fallback), and stderr logs, all schema-valid.
    """
    clock = FakeClock()
    monkeypatch.setattr(R.time, "monotonic", clock.monotonic)
    monkeypatch.delenv(R.JUDGE_FRONTIER_ENV, raising=False)
    schema = minischema.load_schema(JUDGE_REPORT_SCHEMA)

    harness = _write_dispatch_harness(tmp_path, 4)
    bjson, _san, _eacsl = _make_build_json(tmp_path, module="jmod", sources=[str(harness)])
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    for i in range(40):
        (corpus / f"u_{i:03d}").write_bytes(bytes([i % 4, i]))

    def _run_batches(cmd: list[str], *_a: Any, **_kw: Any) -> SandboxResult:
        if "-merge=1" in cmd:
            clock.now += 30.5
            return SandboxResult(
                returncode=-9,
                stdout="",
                stderr="MERGE-INNER: slow corpus on 9p\n",
                timed_out=True,
                sandbox="fake",
            )
        inputs_in_cmd = [Path(a) for a in cmd[1:] if not a.startswith("-")]
        clock.now += 0.01 * len(inputs_in_cmd)
        lines = [f"Running: {p.resolve()}\nExecuted {p.resolve()} in 1 ms" for p in inputs_in_cmd]
        return SandboxResult(returncode=0, stdout="", stderr="\n".join(lines), timed_out=False, sandbox="fake")

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", _run_batches)

    # 1. Timeout during -merge=1 -> frontier_status == "timed_out", diagnostic_hints + stderr populated.
    rep_to = R.run_judge("jmod", bjson, corpus, profile="standard", max_corpus_inputs=10, batch_size=5)
    err_to = capsys.readouterr().err
    assert rep_to["frontier_total"] == 0
    assert rep_to["frontier_status"] == "timed_out"
    assert rep_to["frontier_merge"]["status"] == "timed_out"
    assert rep_to["frontier_merge"]["timed_out"] is True
    assert rep_to["frontier_merge"]["corpus_files"] == 40
    assert "slow corpus on 9p" in rep_to["frontier_merge"]["stderr_tail"]
    assert rep_to["diagnostic_hints"]
    assert "timed_out" in rep_to["diagnostic_hints"][0]
    assert "[judge] jmod:" in err_to and "timed_out" in err_to
    assert minischema.validate(rep_to, schema) == []

    # 2. Missing .san binary when grown > cap -> frontier_status == "no_san_binary".
    bjson_no_san, _, _ = _make_build_json(tmp_path, module="nosan", sources=[str(harness)], with_san=False)
    rep_nosan = R.run_judge("nosan", bjson_no_san, corpus, profile="standard", max_corpus_inputs=10, batch_size=5)
    err_nosan = capsys.readouterr().err
    assert rep_nosan["frontier_total"] == 0
    assert rep_nosan["frontier_status"] == "no_san_binary"
    assert rep_nosan["frontier_merge"]["status"] == "no_san_binary"
    assert rep_nosan["diagnostic_hints"]
    assert "no_san_binary" in err_nosan or "sanitizer binary unavailable" in err_nosan
    assert minischema.validate(rep_nosan, schema) == []

    # 3. Grown corpus <= cap -> frontier_status == "below_cap", no frontier_merge or hint.
    rep_below = R.run_judge("jmod", bjson, corpus, profile="standard", max_corpus_inputs=100, batch_size=10)
    assert rep_below["frontier_status"] == "below_cap"
    assert "frontier_merge" not in rep_below
    assert "diagnostic_hints" not in rep_below
    assert minischema.validate(rep_below, schema) == []

    # 4. Explicit frontier_names -> frontier_status == "provided".
    rep_prov = R.run_judge(
        "jmod", bjson, corpus, profile="standard", max_corpus_inputs=10, frontier_names={"u_000", "u_001"}, batch_size=5
    )
    assert rep_prov["frontier_status"] == "provided"
    assert rep_prov["frontier_total"] == 2
    assert minischema.validate(rep_prov, schema) == []

    # 5. Disabled via env -> frontier_status == "disabled".
    monkeypatch.setenv(R.JUDGE_FRONTIER_ENV, "off")
    rep_off = R.run_judge("jmod", bjson, corpus, profile="standard", max_corpus_inputs=10, batch_size=5)
    assert rep_off["frontier_status"] == "disabled"
    assert "frontier_merge" not in rep_off
    assert minischema.validate(rep_off, schema) == []


_DOCKER_MERGE_HARNESS = r"""
#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    if (data[0] == 1 && data[1] == 0x7f) {
        int64_t x = (-9223372036854775807LL - 1LL);
        volatile int64_t y = -x;
        (void)y;
    }
    volatile int acc = 0;
    switch (data[0] % 8) {
    case 0: acc += 1; break;
    case 1: acc += 2; break;
    case 2: acc += 3; break;
    case 3: acc += 4; break;
    case 4: acc += 5; break;
    case 5: acc += 6; break;
    case 6: acc += 7; break;
    default: acc += 8; break;
    }
    return acc == 999999 ? 1 : 0;
}
"""

_DOCKER_MERGE_DRIVER = """import json, subprocess, sys
from pathlib import Path

sys.path.insert(0, "/opt/framac-pipeline/scripts")
import run_eacsl_fuzz as R

work = Path("/w")
src = work / "harness.c"
san_bin = work / "fuzz_merge.san"
subprocess.run(
    ["clang", "-O1", "-g", "-fsanitize=fuzzer,address,undefined", "-fno-sanitize-recover=all", str(src), "-o", str(san_bin)],
    check=True,
)
corpus = work / "corpus"
corpus.mkdir(exist_ok=True)
for i in range(60):
    (corpus / f"floor_c{i % 8}_{i:03d}").write_bytes(bytes([i % 8, i & 0x3F, 0xAA]))
# Include a real UBSan crashing input in the corpus to verify -merge=1 still succeeds cleanly.
(corpus / "floor_c1_crash").write_bytes(bytes([1, 0x7F, 0x00]))

res_ok = R.discover_judge_frontier_detailed(san_bin, corpus, stage_locally=True)
out = {
    "ok": res_ok.to_report_dict(),
    "frontier_names": sorted(res_ok.frontier_names or []),
    "corpus_intact_count": len(list(corpus.iterdir())),
}
(work / "report.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
"""


@pytest.mark.integration
@pytest.mark.slow
def test_docker_discover_judge_frontier_local_staging_with_real_libfuzzer(tmp_path: Path) -> None:
    """Real Clang LibFuzzer `-merge=1` inside `framac-analysis:latest` with local corpus staging:
    verifies `status == "ok"`, `staged_locally is True`, `floor_*` filename matching, and clean
    handling of a UBSan-crashing unit in the corpus while keeping `corpus_dir` unmodified.
    """
    from conftest import ANALYSIS_IMAGE, require_docker_images

    require_docker_images(ANALYSIS_IMAGE)
    (tmp_path / "harness.c").write_text(_DOCKER_MERGE_HARNESS, encoding="utf-8", newline="\n")
    (tmp_path / "driver.py").write_text(_DOCKER_MERGE_DRIVER, encoding="utf-8", newline="\n")
    proc = subprocess.run(
        [
            "docker", "run", "--rm", "--init", "--network", "none",
            "--cpus", "2", "--memory", "2g",
            "--label", os.environ.get("FPI_DOCKER_LABEL", "framac.test=test_judge_frontier_selection"),
            "-v", f"{tmp_path}:/w",
            "-v", f"{REPO_ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
            "-v", f"{REPO_ROOT / 'templates'}:/opt/framac-pipeline/templates:ro",
            "-v", f"{REPO_ROOT / 'schemas'}:/opt/framac-pipeline/schemas:ro",
            "--entrypoint", "python3", ANALYSIS_IMAGE, "/w/driver.py",
        ],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120, check=False,
    )  # fmt: skip
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    data = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    ok = data["ok"]
    assert ok["status"] == "ok", ok
    assert ok["staged_locally"] is True, ok
    assert ok["corpus_files"] == 61, ok
    assert ok["matched_files"] >= 4, ok
    assert ok["merged_files"] == ok["matched_files"], ok
    assert "MERGE-OUTER" in ok["stderr_tail"], ok
    assert all(name.startswith("floor_c") for name in data["frontier_names"])
    assert data["corpus_intact_count"] == 61
