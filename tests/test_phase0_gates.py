"""
Phase 0 gates enforced (plan step I1): the reach gate and build-check record
workspace/reports/phase0_gates.json, the Make recipes that consume harnesses check it first, and
the benchmark records its manifest exemptions before the gate runs.
"""

import json
import re
from pathlib import Path

import pytest

import benchmark
import harness_reach
import phase0_gates
import pipeline_make
import validate_artifacts
from test_harness_reach import _run_dir, _write_harness

ROOT = Path(__file__).resolve().parent.parent
PIPELINE_MK = ROOT / "templates" / "pipeline.mk"


def _reach(run: Path, hdir: Path, *extra: str) -> int:
    return harness_reach.main(
        ["check", "--harness-dir", str(hdir), "--out", str(run / harness_reach.DEFAULT_OUT), *extra]
    )


@pytest.mark.unit
def test_a_missing_stamp_fails_with_how_to_run_the_gates(tmp_path):
    reasons = phase0_gates.check(tmp_path, "api")
    assert len(reasons) == 2
    assert "harness_reach.py check" in reasons[0] and "build-check" in reasons[1]


@pytest.mark.unit
def test_reach_gate_records_the_stamp_and_follows_exemptions_and_harness_changes(tmp_path, monkeypatch):
    run = _run_dir(tmp_path, monkeypatch)
    hdir = _write_harness(run, "rec_parse(fuzz_buf, fuzz_len);")
    harness_reach.record_exempt(hdir, "tools", None, "example programs")
    assert _reach(run, hdir) == 1
    reasons = phase0_gates.check(run, "api", ("reach",))
    assert reasons and "rec_print" in reasons[0] and "rec_put" in reasons[0]

    for fn in ("rec_put", "rec_print"):
        harness_reach.record_exempt(hdir, "api", fn, "pinned harness")
    assert _reach(run, hdir) == 0
    assert phase0_gates.check(run, "api", ("reach",)) == []
    assert phase0_gates.check(run, None, ("reach",)) == []

    # A harness regenerated after the gate ran fails it until the gate runs again.
    (hdir / "harness_api.c").write_text("/* regenerated */\n", encoding="utf-8")
    assert "changed after the reach gate ran" in phase0_gates.check(run, "api", ("reach",))[0]


@pytest.mark.unit
def test_a_partial_reach_check_updates_only_its_modules(tmp_path, monkeypatch):
    run = _run_dir(tmp_path, monkeypatch)
    hdir = _write_harness(run, "rec_parse(fuzz_buf, fuzz_len); rec_put(fuzz_buf, fuzz_len, 0); rec_print(0, 0);")
    assert _reach(run, hdir) == 1  # tools has no harness
    assert _reach(run, hdir, "--module", "api") == 0
    gates = phase0_gates.load_gates(run)["reach"]
    assert gates["modules"]["api"]["passed"] is True
    assert gates["modules"]["tools"]["passed"] is False and gates["passed"] is False
    assert phase0_gates.check(run, "api", ("reach",)) == []
    assert "tools" in phase0_gates.check(run, None, ("reach",))[0]


@pytest.mark.unit
def test_build_check_gate_covers_fuzzed_modules_only(tmp_path):
    phase0_gates.record_build_check(
        tmp_path,
        {
            "ok": False,
            "modules": {
                "cfg": {"ok": True, "status": "eacsl"},
                "log": {"ok": False, "status": "eacsl_fallback", "first_error": "x.h:1: User Error"},
            },
        },
    )
    assert phase0_gates.check(tmp_path, "cfg", ("build_check",)) == []
    assert phase0_gates.check(tmp_path, "eva_only", ("build_check",)) == []  # not fuzzed
    reason = phase0_gates.check(tmp_path, "log", ("build_check",))[0]
    assert "eacsl_fallback" in reason and "User Error" in reason
    assert "log" in phase0_gates.check(tmp_path, None, ("build_check",))[0]


@pytest.mark.unit
def test_cli_exit_codes(tmp_path, capsys):
    assert phase0_gates.main(["check", "--run-dir", str(tmp_path), "--module", "m"]) == 1
    assert "phase0 gate:" in capsys.readouterr().err
    phase0_gates.record_build_check(tmp_path, {"ok": True, "modules": {"m": {"ok": True, "status": "eacsl"}}})
    assert phase0_gates.main(["check", "--run-dir", str(tmp_path), "--module", "m", "--need", "build_check"]) == 0
    with pytest.raises(SystemExit):
        phase0_gates.main(["check", "--run-dir", str(tmp_path), "--need", "bogus"])


def _recipe(text: str, target_line: str) -> list[str]:
    body = text.split(target_line + "\n", 1)[1]
    return [line for line in body.splitlines() if line.startswith("\t")][:2]


@pytest.mark.unit
@pytest.mark.parametrize(
    ("target_line", "need"),
    [
        ("$(BUILD_TARGETS): build-%:", "reach"),
        ("$(FUZZ_TARGETS): fuzz-%: selftest build-%", "reach,build_check"),
        ("$(COVERAGE_TARGETS): coverage-%:", "reach"),
        ("$(EVA_TARGETS): eva-%:", "reach"),
        ("$(EVA_BASE_TARGETS): evabase-%:", "reach"),
        ("$(EVA_TUNE_TARGETS): evatune-%:", "reach"),
    ],
)
def test_every_harness_consuming_recipe_checks_its_gate_first(target_line, need):
    first = _recipe(PIPELINE_MK.read_text(encoding="utf-8"), target_line)[0]
    assert first == f"\t$(GATE) --module $* --need {need}"


@pytest.mark.unit
def test_seed_runs_the_reach_gate_and_wp_queue_needs_both():
    text = PIPELINE_MK.read_text(encoding="utf-8")
    assert re.search(r"^seed: reach-gate$", text, re.MULTILINE)
    assert "harness_reach.py check" in _recipe(text, "reach-gate:")[0]
    assert _recipe(text, "wp-queue: ingest facts")[0] == "\t$(GATE) --need reach,build_check"
    assert "\t$$(GATE) --module $(1) --need reach" in text  # the Eva tuning rungs
    assert "reach-gate" in pipeline_make.STAGE_OF_TARGET


@pytest.mark.unit
def test_stamp_validation():
    ok = {
        "reach": {"passed": False, "modules": {"a": {"passed": True}, "b": {"passed": False}}},
        "build_check": {"ok": True, "modules": {"a": {"ok": True}}},
    }
    assert not validate_artifacts.validate_phase0_gates(ok)
    assert validate_artifacts.validate_phase0_gates({"reach": {"passed": True, "modules": {"b": {"passed": False}}}})
    assert validate_artifacts.validate_phase0_gates({"build_check": {"ok": "yes", "modules": {}}})
    assert validate_artifacts.validate_phase0_gates([])


@pytest.mark.unit
def test_benchmark_records_manifest_exemptions_before_the_gate(tmp_path, monkeypatch):
    run = _run_dir(tmp_path, monkeypatch)
    hdir = _write_harness(run, "rec_parse(fuzz_buf, fuzz_len);")
    spec = {
        "reach_exempt_modules": {"tools": "example programs"},
        "modules": [{"name": "api", "reach_gaps_accepted": "pinned recall harness"}],
    }
    assert benchmark.apply_reach_exemptions(spec, hdir) == {"modules_exempted": 1, "functions_exempted": 2}
    report = harness_reach.run_check(run / "workspace/reports/callgraph_dag.json", hdir, None)
    assert report["passed"] is True
    api = next(m for m in report["modules"] if m["module"] == "api")
    assert api["exempt"] == {"rec_print": "pinned recall harness", "rec_put": "pinned recall harness"}


@pytest.mark.unit
def test_manifest_exemptions_reach_the_container_spec():
    manifest = benchmark.load_manifest()
    assert not benchmark.validate_manifest(manifest)
    for target in manifest["targets"]:
        spec = benchmark.target_spec(target, manifest, fuzz_budget=None, eva_timeout=None)
        assert spec["reach_exempt_modules"] == (target.get("reach_exempt_modules") or {})
        names = {m["name"] for m in target["modules"]}
        for module in spec["modules"]:
            assert module["reach_gaps_accepted"] == next(
                m.get("reach_gaps_accepted") for m in target["modules"] if m["name"] == module["name"]
            )
        # An exempted module is never one the benchmark harnesses.
        assert not set(spec["reach_exempt_modules"]) & names, target["id"]
        for module in target["modules"]:
            if (module.get("params") or {}).get("fuzz_engine") == "sanitizers":
                assert module.get("fuzz_engine_reason"), (target["id"], module["name"])
    x509 = next(t for t in manifest["targets"] if t["id"] == "x509-parser")
    assert json.dumps(x509).count('"fuzz_engine": "sanitizers"') == 4
