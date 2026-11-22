"""Unit tests for conditional `smoke` and `judge` stage wiring in benchmark.py and benchmark_seeded.py."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import benchmark
import benchmark_seeded as bs
import harness_smoke
import resources

pytestmark = pytest.mark.unit


def _set_flags(monkeypatch: pytest.MonkeyPatch, smoke: str | None, judge: str | None) -> None:
    if smoke is None:
        monkeypatch.delenv("FRAMAC_HARNESS_SMOKE", raising=False)
    else:
        monkeypatch.setenv("FRAMAC_HARNESS_SMOKE", smoke)
    if judge is None:
        monkeypatch.delenv("FRAMAC_FUZZ_EXPLORE_JUDGE", raising=False)
    else:
        monkeypatch.setenv("FRAMAC_FUZZ_EXPLORE_JUDGE", judge)


class TestBenchmarkPostPhase0Stages:
    @pytest.mark.parametrize(
        ("smoke", "judge", "expected"),
        [
            (None, None, ["build", "smoke", "fuzz", "judge", "eva", "coverage", "replay", "ingest", "gate", "queue"]),
            ("off", "off", ["build", "fuzz", "eva", "coverage", "replay", "ingest", "gate", "queue"]),
            ("on", "off", ["build", "smoke", "fuzz", "eva", "coverage", "replay", "ingest", "gate", "queue"]),
            ("off", "on", ["build", "fuzz", "judge", "eva", "coverage", "replay", "ingest", "gate", "queue"]),
            ("on", "on", ["build", "smoke", "fuzz", "judge", "eva", "coverage", "replay", "ingest", "gate", "queue"]),
        ],
    )
    def test_four_flag_combinations_with_fuzz_and_replays(
        self,
        monkeypatch: pytest.MonkeyPatch,
        smoke: str | None,
        judge: str | None,
        expected: list[str],
    ) -> None:
        _set_flags(monkeypatch, smoke, judge)
        stages = benchmark.post_phase0_stages(run_fuzz=True, replays=True)
        assert [name for name, _, _ in stages] == expected
        by_name = {name: (cmd, cls) for name, cmd, cls in stages}
        assert by_name["build"] == (f"{bs.PM} build-check", None)
        assert by_name["fuzz"] == (f"{bs.PM} run fuzz", None)
        assert by_name["eva"] == (f"{bs.PM} run eva", None)
        if "smoke" in by_name:
            assert by_name["smoke"] == (f"{bs.PM} run smoke", None)
        if "judge" in by_name:
            assert by_name["judge"] == (f"{bs.PM} run judge", None)

    @pytest.mark.parametrize(
        ("smoke", "judge", "expected"),
        [
            ("off", "off", ["build", "eva", "coverage", "ingest", "queue"]),
            ("on", "off", ["build", "smoke", "eva", "coverage", "ingest", "queue"]),
            ("off", "on", ["build", "eva", "coverage", "ingest", "queue"]),
            ("on", "on", ["build", "smoke", "eva", "coverage", "ingest", "queue"]),
        ],
    )
    def test_no_fuzz_keeps_smoke_for_eva_and_omits_judge(
        self,
        monkeypatch: pytest.MonkeyPatch,
        smoke: str,
        judge: str,
        expected: list[str],
    ) -> None:
        _set_flags(monkeypatch, smoke, judge)
        stages = benchmark.post_phase0_stages(run_fuzz=False, replays=False)
        assert [name for name, _, _ in stages] == expected

    def test_respects_module_helper_seams(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_flags(monkeypatch, None, None)
        monkeypatch.setattr(harness_smoke, "harness_smoke_enabled", lambda: True)
        monkeypatch.setattr(resources, "fuzz_explore_judge_enabled", lambda: True)
        stages = benchmark.post_phase0_stages(run_fuzz=True, replays=False)
        assert [name for name, _, _ in stages] == [
            "build",
            "smoke",
            "fuzz",
            "judge",
            "eva",
            "coverage",
            "ingest",
            "queue",
        ]


class TestBenchmarkSeededStages:
    @pytest.mark.parametrize(
        ("smoke", "judge", "expected_post"),
        [
            (None, None, ["build", "smoke", "fuzz", "judge", "eva", "coverage", "ingest"]),
            ("off", "off", ["build", "fuzz", "eva", "coverage", "ingest"]),
            ("on", "off", ["build", "smoke", "fuzz", "eva", "coverage", "ingest"]),
            ("off", "on", ["build", "fuzz", "judge", "eva", "coverage", "ingest"]),
            ("on", "on", ["build", "smoke", "fuzz", "judge", "eva", "coverage", "ingest"]),
        ],
    )
    def test_four_flag_combinations(
        self,
        monkeypatch: pytest.MonkeyPatch,
        smoke: str | None,
        judge: str | None,
        expected_post: list[str],
    ) -> None:
        _set_flags(monkeypatch, smoke, judge)
        post = bs.post_stages()
        assert [name for name, _ in post] == expected_post
        if smoke == "off" and judge == "off":
            assert post == list(bs.POST_STAGES)

        plan = bs.stage_plan(Path("s04_force_include"), 45)
        assert [name for name, _, _ in plan] == ["phase0", *expected_post]
        by_name = {name: (cmd, cls) for name, cmd, cls in plan}
        assert by_name["build"] == (f"{bs.PM} build-check", None)
        if "smoke" in by_name:
            assert by_name["smoke"] == (f"{bs.PM} run smoke", None)
        if "judge" in by_name:
            assert by_name["judge"] == (f"{bs.PM} run judge", None)

    def test_respects_module_helper_seams(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_flags(monkeypatch, None, None)
        monkeypatch.setattr(harness_smoke, "harness_smoke_enabled", lambda: True)
        monkeypatch.setattr(resources, "fuzz_explore_judge_enabled", lambda: True)
        plan = bs.stage_plan(Path("s01_macro_fn"), 30)
        assert [name for name, _, _ in plan] == [
            "phase0",
            "build",
            "smoke",
            "fuzz",
            "judge",
            "eva",
            "coverage",
            "ingest",
        ]


class TestStageExecutionAndEnvForwarding:
    def test_run_stage_forwards_flags_when_enabled_and_preserves_off_default(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        captured_envs: list[dict[str, str]] = []

        class _Proc:
            returncode = 0

        def fake_run(argv: list[str], *, env: dict[str, str], **_: Any) -> _Proc:
            captured_envs.append(dict(env))
            return _Proc()

        monkeypatch.setattr(benchmark, "_is_windows", lambda: False)
        monkeypatch.setattr(benchmark.subprocess, "run", fake_run)

        _set_flags(monkeypatch, None, None)
        benchmark.run_stage("build", f"{bs.PM} build-check", tmp_path, tmp_path, "repo")
        assert "FRAMAC_HARNESS_SMOKE" not in captured_envs[-1]
        assert "FRAMAC_FUZZ_EXPLORE_JUDGE" not in captured_envs[-1]

        _set_flags(monkeypatch, "1", "yes")
        benchmark.run_stage("smoke", f"{bs.PM} run smoke", tmp_path, tmp_path, "repo")
        assert captured_envs[-1]["FRAMAC_HARNESS_SMOKE"] == "1"
        assert captured_envs[-1]["FRAMAC_FUZZ_EXPLORE_JUDGE"] == "yes"

        # If helpers are patched to True while env vars say off, run_stage forwards "on".
        _set_flags(monkeypatch, "off", "off")
        monkeypatch.setattr(harness_smoke, "harness_smoke_enabled", lambda: True)
        monkeypatch.setattr(resources, "fuzz_explore_judge_enabled", lambda: True)
        benchmark.run_stage("judge", f"{bs.PM} run judge", tmp_path, tmp_path, "repo")
        assert captured_envs[-1]["FRAMAC_HARNESS_SMOKE"] == "on"
        assert captured_envs[-1]["FRAMAC_FUZZ_EXPLORE_JUDGE"] == "on"

        # Symmetrically, if helpers are patched to False while env vars are unset, run_stage forwards "off".
        _set_flags(monkeypatch, None, None)
        monkeypatch.setattr(harness_smoke, "harness_smoke_enabled", lambda: False)
        monkeypatch.setattr(resources, "fuzz_explore_judge_enabled", lambda: False)
        benchmark.run_stage("build", f"{bs.PM} build-check", tmp_path, tmp_path, "repo")
        assert captured_envs[-1]["FRAMAC_HARNESS_SMOKE"] == "off"
        assert captured_envs[-1]["FRAMAC_FUZZ_EXPLORE_JUDGE"] == "off"

    def test_run_target_executes_smoke_and_judge_when_enabled(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _set_flags(monkeypatch, "on", "on")
        started: list[tuple[str, str]] = []

        def fake_stage(
            name: str,
            command: str,
            mount: Path,
            run_dir: Path,
            *args: Any,
            **kwargs: Any,
        ) -> dict[str, Any]:
            started.append((name, command))
            if name == "phase0":
                benchmark.write_json(run_dir / benchmark.BENCH_SUBDIR / "phase0.json", {"ok": True})
            return {"rc": 0, "wall_s": 0.0, "cpu_s": 0.0}

        monkeypatch.setattr(benchmark, "run_capture", lambda *a, **k: {"status": "ok", "model": {"status": "ok"}})
        monkeypatch.setattr(benchmark, "run_stage", fake_stage)
        monkeypatch.setattr(benchmark, "collect_target_metrics", lambda run_dir, target, notes: {"problems": notes})

        target = {
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
        benchmark.run_target(target, {"bugs": []}, tmp_path, "r-on", run_fuzz=True, fuzz_budget=None, eva_timeout=None)
        assert [name for name, _ in started] == [
            "phase0",
            "build",
            "smoke",
            "fuzz",
            "judge",
            "eva",
            "coverage",
            "ingest",
            "queue",
        ]

    def test_run_project_executes_smoke_and_judge_when_enabled(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _set_flags(monkeypatch, "on", "on")
        proj = tmp_path / "proj" / "s01_demo"
        proj.mkdir(parents=True)
        (proj / "truth.json").write_text(
            json.dumps({"mechanism": "demo", "build": "make", "bugs": [], "decoys": []}),
            encoding="utf-8",
        )
        started: list[str] = []

        def fake_stage(name: str, command: str, *args: Any, **kwargs: Any) -> dict[str, Any]:
            started.append(name)
            return {"rc": 0, "wall_s": 0.0, "cpu_s": 0.0}

        monkeypatch.setattr(benchmark, "run_capture", lambda *a, **k: {"status": "ok", "model": {"status": "ok"}})
        monkeypatch.setattr(benchmark, "run_stage", fake_stage)

        bs.run_project(proj, tmp_path / "work", "seeded-on", 30)
        assert started == ["phase0", "build", "smoke", "fuzz", "judge", "eva", "coverage", "ingest"]


class TestJudgeArtifactAccounting:
    def test_seeded_collect_findings_reads_judge_artifacts_when_present(self, tmp_path: Path) -> None:
        run_dir = tmp_path / "run-1"
        judge_dir = run_dir / "workspace" / "reports" / "judge"
        judge_dir.mkdir(parents=True)
        (judge_dir / "libm_a.json").write_text(
            json.dumps(
                {
                    "status": "crash_found",
                    "artifacts": [
                        {
                            "fingerprint": "src/a.c#bug_fn::mem_access::0123456789",
                            "failure": {
                                "file": "workspace/work/src/a.c",
                                "function": "bug_fn",
                                "line": 42,
                                "kind": "mem_access",
                            },
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        found = bs.collect_findings(run_dir)
        assert len(found["fuzz_hits"]) == 1
        assert found["fuzz_hits"][0]["function"] == "bug_fn"
        assert found["fuzz_hits"][0]["line"] == 42

    def test_annotate_replays_counts_judge_artifacts_as_campaign_found(self, tmp_path: Path) -> None:
        reports = tmp_path / "workspace" / "reports"
        (reports / "eva").mkdir(parents=True)
        (reports / "fuzz").mkdir(parents=True)
        (reports / "judge").mkdir(parents=True)
        (reports / "eva" / "m.json").write_text(json.dumps({"status": "ok"}), encoding="utf-8")
        (reports / "fuzz" / "m.json").write_text(json.dumps({"artifacts": []}), encoding="utf-8")
        (reports / "judge" / "m.json").write_text(
            json.dumps({"artifacts": [{"fingerprint": "a.c#f::shift::0123456789"}]}),
            encoding="utf-8",
        )
        spec = {
            "replays": [
                {"bug": "B", "engine": "eacsl", "file": "a.c", "function": "f", "alarm_kind": "shift", "lines": [10]}
            ]
        }
        doc = benchmark.annotate_replays({"results": [{"bug": "B", "engine": "eacsl", "module": "m"}]}, spec, tmp_path)
        assert doc["results"][0]["found_by_campaign"] is True
