"""Remediation step R9: benchmark stages, the baseline merge per replay, D6 (seeded corpus) and D7 (manifest)."""

import json
from pathlib import Path

import pytest

import benchmark
import benchmark_seeded as bs
from conftest import PHASE0_FIXTURES


def _replay(target: str, outcome: str, gate: str | None = "confirmed") -> dict:
    return {
        "target": target,
        "module": "decode",
        "engine": "eacsl",
        "required": True,
        "outcome": outcome,
        "gate": gate if outcome != "not_run" else None,
    }


def _bug(*replays: dict) -> dict:
    spec = {"replays": [{k: r[k] for k in ("target", "module", "engine", "required")} for r in replays]}
    outcomes = {(r["target"], r["module"], r["engine"]): r for r in replays if r["outcome"] != "not_run"}
    return benchmark.decide_bug(spec, outcomes)


def _run(run_id: str, bugs: dict) -> dict:
    return {
        "run_id": run_id,
        "targets": {},
        "recall": benchmark.recall_block(bugs),
        "totals": {},
    }


# ---------------------------------------------------------------------------
# Baseline merge
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_merge_runs_keeps_both_targets_replays():
    # qcbor-dev alone, then qcbor-master alone: the merged bug holds both replays and is decided over both.
    dev_only = _bug(_replay("qcbor-dev", "reproduced"), _replay("qcbor-master", "not_run"))
    master_only = _bug(_replay("qcbor-dev", "not_run"), _replay("qcbor-master", "reproduced"))
    assert dev_only["status"] == "retained" and dev_only["partial"] is True
    merged = benchmark.merge_runs([_run("r-dev", {"QCBOR-02": dev_only}), _run("r-master", {"QCBOR-02": master_only})])
    bug = merged["recall"]["bugs"]["QCBOR-02"]
    assert {r["target"]: r["outcome"] for r in bug["replays"]} == {
        "qcbor-dev": "reproduced",
        "qcbor-master": "reproduced",
    }
    assert bug["status"] == "retained" and bug["partial"] is False
    assert merged["recall"]["retained"] == 1


@pytest.mark.unit
def test_merge_runs_a_later_replay_replaces_the_earlier_one():
    both = _bug(_replay("qcbor-dev", "reproduced"), _replay("qcbor-master", "reproduced"))
    lost_on_master = _bug(_replay("qcbor-dev", "not_run"), _replay("qcbor-master", "not_reproduced"))
    merged = benchmark.merge_runs([_run("a", {"Q": both}), _run("b", {"Q": lost_on_master})])
    bug = merged["recall"]["bugs"]["Q"]
    assert bug["status"] == "lost" and bug["reason"].startswith("qcbor-master/")
    assert {r["target"]: r["outcome"] for r in bug["replays"]}["qcbor-dev"] == "reproduced"
    # A later run that ran nothing for the bug leaves it as it was.
    untouched = benchmark.merge_runs([_run("a", {"Q": both}), _run("b", {"Q": _bug(_replay("qcbor-dev", "not_run"))})])
    assert untouched["recall"]["bugs"]["Q"] == both


# ---------------------------------------------------------------------------
# Stages
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_stage_list_runs_coverage_and_reach_dynamic_before_ingest():
    stages = benchmark.post_phase0_stages(run_fuzz=True, replays=True)
    names = [s[0] for s in stages]
    assert names == ["build", "fuzz", "eva", "coverage", "replay", "ingest", "gate", "queue"]
    assert dict((n, c) for n, c, _ in stages)["coverage"].endswith("pipeline_make.py run coverage reach-dynamic")
    assert [s[0] for s in benchmark.post_phase0_stages(run_fuzz=False, replays=False)] == [
        "build",
        "eva",
        "coverage",
        "ingest",
        "queue",
    ]
    seeded = [name for name, _ in bs.POST_STAGES]
    assert seeded.index("coverage") < seeded.index("ingest")
    assert dict(bs.POST_STAGES)["coverage"].endswith("pipeline_make.py run coverage reach-dynamic")


def _target() -> dict:
    return {
        "id": "t",
        "set": "comparison",
        "url": "https://example.invalid/t.git",
        "revision": "0" * 40,
        "repo_name": "t",
        "checkout": "t",
        "build": {"command": "make"},
        "scope": ["src"],
        "modules": [{"name": "m", "harness": {}}],
    }


@pytest.mark.unit
@pytest.mark.parametrize(
    ("capture", "runs_phase0"),
    [
        ({"status": "needs_build_recipe", "first_error": "boom"}, False),
        ({"status": "ok", "model": {"status": "failed", "error": "no unit parsed"}}, False),
        ({"status": "ok", "model": {"status": "ok"}}, True),
    ],
)
def test_a_failed_capture_or_model_stops_the_target(tmp_path, monkeypatch, capture, runs_phase0):
    started: list[str] = []

    def fake_stage(name, command, *args, **kwargs):
        started.append(name)
        return {"rc": 0, "wall_s": 0.0, "cpu_s": 0.0}

    monkeypatch.setattr(benchmark, "run_capture", lambda *a, **k: dict(capture))
    monkeypatch.setattr(benchmark, "run_stage", fake_stage)
    monkeypatch.setattr(benchmark, "collect_target_metrics", lambda run_dir, target, notes: {"problems": notes})
    entry = benchmark.run_target(
        _target(), {"bugs": []}, tmp_path, "r", run_fuzz=False, fuzz_budget=None, eva_timeout=None
    )
    if runs_phase0:
        # bench/phase0.json is absent in this fake, so Phase 0 reads as failed and nothing follows it.
        assert started == ["phase0"]
    else:
        assert started == [] and entry["status"] == "failed"
        assert any(p.startswith(("capture:", "model:")) for p in entry["problems"])


@pytest.mark.unit
def test_phase0_runs_the_post_stages_only_after_a_passing_phase0(tmp_path, monkeypatch):
    started: list[str] = []

    def fake_stage(name, command, mount, run_dir, *args, **kwargs):
        started.append(name)
        if name == "phase0":
            benchmark.write_json(run_dir / benchmark.BENCH_SUBDIR / "phase0.json", {"ok": True})
        return {"rc": 0, "wall_s": 0.0, "cpu_s": 0.0}

    monkeypatch.setattr(benchmark, "run_capture", lambda *a, **k: {"status": "ok", "model": {"status": "ok"}})
    monkeypatch.setattr(benchmark, "run_stage", fake_stage)
    monkeypatch.setattr(benchmark, "collect_target_metrics", lambda run_dir, target, notes: {"problems": notes})
    benchmark.run_target(_target(), {"bugs": []}, tmp_path, "r", run_fuzz=True, fuzz_budget=None, eva_timeout=None)
    assert started == ["phase0", "build", "fuzz", "eva", "coverage", "ingest", "queue"]


@pytest.mark.unit
def test_inner_phase0_steps_leave_the_phase0_checkpoint_to_build_check():
    # R1: Phase 0 is recorded by `pipeline_make.py build-check`, not by the benchmarks' Phase 0 steps.
    for module in (benchmark, bs):
        source = Path(str(module.__file__)).read_text(encoding="utf-8")
        assert '"save-phase"' not in source and "checkpoint_phase0" not in source


# ---------------------------------------------------------------------------
# D6 and D7
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_seeded_corpus_is_the_fixture_copy_and_the_scorer_accepts_it(tmp_path):
    assert bs.CORPUS == PHASE0_FIXTURES / "seeded"
    projects = bs.projects_in(bs.CORPUS)
    assert len(projects) == 8
    for proj in projects:
        truth = json.loads((proj / "truth.json").read_text(encoding="utf-8"))
        # Every bug found by a fuzz artifact at its site and no decoy fired: the scorer reads each truth.
        artifacts = [
            {"failure": {"file": b["file"], "function": b["function"], "line": b.get("line"), "kind": "x"}}
            for b in truth.get("bugs") or []
        ]
        run = tmp_path / proj.name
        (run / "workspace" / "reports" / "fuzz").mkdir(parents=True)
        (run / "workspace" / "reports" / "fuzz" / "m.json").write_text(
            json.dumps({"status": "ok", "artifacts": artifacts}), encoding="utf-8"
        )
        score = bs.score(run, truth)
        assert score["bugs"] and all(b["found"] for b in score["bugs"].values()), proj.name
        assert not any(d["fired"] for d in score["decoys"].values()), proj.name
    s08 = json.loads((bs.CORPUS / "s08_wellformed_input" / "truth.json").read_text(encoding="utf-8"))
    assert "trust" in s08


@pytest.mark.unit
def test_manifest_has_no_compile_commands():
    manifest = benchmark.load_manifest(benchmark.DEFAULT_MANIFEST)
    assert benchmark.validate_manifest(manifest) == []
    for target in manifest["targets"]:
        assert "compile_commands" not in target
        assert all("compile_commands" not in a["path"] for a in target.get("assets") or [])
        assert "compile_commands" not in benchmark.target_spec(target, manifest, fuzz_budget=None, eva_timeout=None)
    assert not (benchmark.ASSETS_DIR / "cryptolib" / "compile_commands.json").exists()
