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
from test_harness_reach import _run_dir, _unit_run, _write_harness

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
def test_reach_stamp_is_per_harness_module_with_link_units(tmp_path, monkeypatch):
    # Sub-modules are stamped under their own names; the unit's row (an unharnessed API entry point)
    # fails the whole-run check without blocking a sub-module's own recipes.
    harnesses = {"decode": "dec_run(); dec_peek();", "encode": "enc_run();"}
    _, hdir = _unit_run(tmp_path, monkeypatch, harnesses, exempt={"kvtool": "cli", "kvdemo": "ex"})
    assert _reach(tmp_path, hdir) == 1
    gates = phase0_gates.load_gates(tmp_path)["reach"]["modules"]
    assert gates["decode"]["passed"] and gates["decode"]["harness_digest"]
    assert not gates["libkv_a"]["passed"] and gates["libkv_a"]["harness_digest"] is None
    assert phase0_gates.check(tmp_path, "decode", ("reach",)) == []
    assert "libkv_a" in phase0_gates.check(tmp_path, None, ("reach",))[0]
    assert "u_len" in phase0_gates.check(tmp_path, "libkv_a", ("reach",))[0]


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
def test_the_whole_run_gate_refuses_stale_and_unchecked_modules(tmp_path, monkeypatch, capsys):
    run = _run_dir(tmp_path, monkeypatch)
    hdir = _write_harness(run, "rec_parse(fuzz_buf, fuzz_len); rec_put(fuzz_buf, fuzz_len, 0); rec_print(0, 0);")
    harness_reach.record_exempt(hdir, "tools", None, "example programs")
    assert _reach(run, hdir) == 0
    assert phase0_gates.check(run, None, ("reach",), ["api"]) == []
    # A harness the reach check never saw (added after it ran) fails wp-queue's whole-run check.
    assert "reach: late not checked" in phase0_gates.check(run, None, ("reach",), ["api", "late"])[0]
    # So does a harness changed since the check, which only the per-module check used to notice.
    (hdir / "harness_api.c").write_text("/* regenerated */\n", encoding="utf-8")
    assert "harness of api changed" in phase0_gates.check(run, None, ("reach",))[0]

    # Build-check covers the fuzzed modules the plan names; one it never built fails the run.
    phase0_gates.record_build_check(run, {"ok": True, "modules": {"api": {"ok": True, "status": "eacsl"}}})
    assert phase0_gates.check(run, None, ("build_check",), fuzzed_expected=["api"]) == []
    reasons = phase0_gates.check(run, None, ("build_check",), fuzzed_expected=["api", "late"])
    assert reasons == [f"build_check: late not checked; run `{phase0_gates.HOW_TO_RUN['build_check']}` again"]
    argv = ["check", "--run-dir", str(run), "--need", "build_check", "--modules", "api", "--fuzzed", "api late"]
    assert phase0_gates.main(argv) == 1
    assert phase0_gates.main(["check", "--run-dir", str(run), "--need", "build_check", "--fuzzed", "api"]) == 0
    with pytest.raises(SystemExit):
        phase0_gates.main(["check", "--run-dir", str(run), "--module", "api", "--fuzzed", "api"])
    capsys.readouterr()


@pytest.mark.unit
def test_wp_scheduler_init_refuses_a_failed_gate(tmp_path, monkeypatch, capsys):
    import wp_scheduler

    monkeypatch.chdir(tmp_path)
    assert wp_scheduler.main(["init"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["error"] == "Phase 0 gate" and any("has not run" in r for r in out["reasons"])


def _build_report(run: Path, module: str, engine: str, returncode: int = 0) -> None:
    path = run / "workspace" / "build" / f"{module}.build.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"engine_used": engine, "compile": {"returncode": returncode}}), encoding="utf-8")


@pytest.mark.unit
def test_build_gate_judges_the_build_the_campaign_will_use(tmp_path):
    # build-check saw an intermittent E-ACSL fallback; Make rebuilt the module (a prerequisite of
    # fuzz-<mod>) before the gate ran, this time with E-ACSL: the campaign uses that build.
    phase0_gates.record_build_check(
        tmp_path,
        {"ok": False, "modules": {"crypto": {"ok": False, "status": "eacsl_fallback", "fuzz_engine": "auto"}}},
    )
    _build_report(tmp_path, "crypto", "eacsl")
    assert phase0_gates.check(tmp_path, "crypto", ("build_check",)) == []
    assert phase0_gates.check(tmp_path, None, ("build_check",)) == []
    # The other way round: a passed stamp, then a rebuild that fell back.
    _build_report(tmp_path, "crypto", "sanitizers")
    phase0_gates.record_build_check(
        tmp_path, {"ok": True, "modules": {"crypto": {"ok": True, "status": "eacsl", "fuzz_engine": "auto"}}}
    )
    assert "eacsl_fallback" in phase0_gates.check(tmp_path, "crypto", ("build_check",))[0]
    # Sanitizers as the recorded choice pass; a failed compile never does.
    phase0_gates.record_build_check(
        tmp_path,
        {"ok": True, "modules": {"crypto": {"ok": True, "status": "sanitizers_chosen", "fuzz_engine": "sanitizers"}}},
    )
    assert phase0_gates.check(tmp_path, "crypto", ("build_check",)) == []
    _build_report(tmp_path, "crypto", "sanitizers", returncode=1)
    assert "build_failed" in phase0_gates.check(tmp_path, "crypto", ("build_check",))[0]


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
    assert re.search(r"^seed: reach-gate security-props$", text, re.MULTILINE)
    assert "harness_reach.py check" in _recipe(text, "reach-gate:")[0]
    assert _recipe(text, "wp-queue: ingest facts")[0] == (
        '\t$(GATE) --need reach,build_check --modules "$(MODULES)" --fuzzed "$(FUZZ_MODULES)"'
    )
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
    # Nothing to fuzz passes; no module in the plan at all fails with its error.
    assert not validate_artifacts.validate_phase0_gates({"build_check": {"ok": True, "modules": {}}})
    assert not validate_artifacts.validate_phase0_gates(
        {"build_check": {"ok": False, "modules": {}, "error": "no module in the plan"}}
    )
    assert validate_artifacts.validate_phase0_gates({"build_check": {"ok": False, "modules": {}}})
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


@pytest.mark.unit
def test_harness_digest_covers_a_target_fuzz_modules_fuzzer_source(tmp_path):
    hdir = tmp_path / "workspace/harnesses"
    hdir.mkdir(parents=True)
    src = tmp_path / "workspace/work/fuzz/fuzz_kv.c"
    src.parent.mkdir(parents=True)
    src.write_text("int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { return 0; }\n")
    (hdir / "harness_tf_fuzz_kv.c").write_text("int wrapper;\n")
    sidecar = {
        "module": "tf_fuzz_kv",
        "target_fuzzer": {"id": "fuzz_kv", "source": "fuzz/fuzz_kv.c", "initialize": False},
    }
    (hdir / "harness_tf_fuzz_kv.json").write_text(json.dumps(sidecar))
    # Resolved like a sidecar source: the run directory first, then the work tree.
    assert phase0_gates.target_fuzzer_source(tmp_path, sidecar) == src
    before = phase0_gates.harness_digest(tmp_path, "tf_fuzz_kv")
    src.write_text("int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { return 1; }\n")
    after = phase0_gates.harness_digest(tmp_path, "tf_fuzz_kv")
    assert before is not None and after is not None and before != after
    src.unlink()
    assert phase0_gates.harness_digest(tmp_path, "tf_fuzz_kv") not in (before, after, None)
    # A harness without `target_fuzzer` digests its own two files only, as before.
    (hdir / "harness_api.json").write_text("{}")
    import hashlib

    assert phase0_gates.harness_digest(tmp_path, "api") == hashlib.sha256(b".json{}").hexdigest()
