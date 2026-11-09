"""
Eva tuning wall time (QCBOR run-5): a ladder no rung can finish is not searched, a rung that times out
stays a timeout (no less precise fallback), the timeout message names the limit the run hit, and each
rung leases memory from its own measured peak.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

import eva_options as eo
import eva_tuning as et
import pipeline_make as pm
import resources as R
import run_eva_slice
from test_eva_tuning import ACSL, _base_report, _csv_row, _finish_args, _mk, _record_for, _write_trial
from test_pipeline_make import _make_run

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# 1. Skip a ladder no rung can finish
# ---------------------------------------------------------------------------


def test_the_ladder_is_skipped_when_even_the_cheapest_rung_would_reach_its_limit():
    cap = eo.TRIAL_TIMEOUT_CEILING_S
    # QCBOR run-5: a 6,964 s base run against the 7,200 s rung limit.
    reason = eo.tuning_skip_reason(6963.6, eo.trial_timeout(6963.6))
    assert reason is not None and "6964 s" in reason and f"{cap} s rung limit" in reason
    assert f"--eva-timeout {int(6963.6 * eo.TUNING_SKIP_MARGIN) + 1}" in reason
    edge = cap / eo.TUNING_SKIP_MARGIN
    assert eo.tuning_skip_reason(edge, cap) is not None
    assert eo.tuning_skip_reason(edge - 1, cap) is None
    # Fast modules, and runs without a measured time, are always tuned.
    assert eo.tuning_skip_reason(100.0, eo.trial_timeout(100.0)) is None
    assert eo.tuning_skip_reason(None, cap) is None and eo.tuning_skip_reason(0, cap) is None
    assert eo.tuning_skip_reason(5000.0, None) is None


def test_an_explicit_module_timeout_is_the_limit_the_reason_names():
    reason = eo.tuning_skip_reason(900.0, 1000, module_timeout=1000)
    assert reason is not None and "module's eva_timeout" in reason
    assert eo.tuning_skip_reason(900.0, 20000, module_timeout=20000) is None


def test_a_slow_base_run_gets_no_rungs_and_a_plan_warning(tmp_path):
    run = _make_run(tmp_path)
    _base_report(run, elapsed_s=6963.6)
    res = pm.generate(run, templates_dir=ACSL)
    text = (run / pm.MODULES_MK).read_text(encoding="utf-8")
    assert "EVA_TUNE_RUNGS_snmp :=\n" in text
    skip_line = next(line for line in text.splitlines() if line.startswith("EVA_TUNE_SKIP_snmp :="))
    assert "ladder skipped" in skip_line and "6964 s" in skip_line
    assert any(w.startswith("snmp: Eva tuning: ladder skipped") for w in res["warnings"])
    assert pm.build_plan(run).modules["snmp"].to_json()["tune_skip"].startswith("ladder skipped")


def test_a_raised_module_timeout_gives_the_rungs_back(tmp_path):
    run = _make_run(tmp_path)
    _base_report(run, elapsed_s=6963.6)
    pm.params_set(run, "snmp", eva_timeout=9000)
    text = _mk(run)
    assert f"EVA_TUNE_RUNGS_snmp := {' '.join(eo.RUNG_NAMES)}\n" in text
    assert "EVA_TUNE_SKIP_snmp :=\n" in text and "EVA_TUNE_TIMEOUT_snmp := 9000\n" in text


def test_a_current_recorded_decision_still_replays_after_a_slow_base_run(tmp_path):
    run = _make_run(tmp_path)
    _base_report(run, elapsed_s=6963.6)
    pm.record_eva_tuning(run, "snmp", _record_for(run, "snmp", rung="unroll"))
    text = _mk(run)
    assert "EVA_REPLAY_snmp := 1\n" in text and "EVA_TUNE_SKIP_snmp :=\n" in text
    assert "EVA_TUNE_RUNGS_snmp := unroll" in text


def test_finish_with_skip_search_reports_the_base_run_and_searches_nothing(tune_run, capsys, monkeypatch):
    _write_trial(tune_run, "m", "base", [_csv_row(1), _csv_row(2)], elapsed_s=6963.6)

    def no_trial(*args, **kwargs):
        raise AssertionError("a skipped ladder runs no loop trial")

    monkeypatch.setattr(et, "run_eva_on_slice", no_trial)
    args = _finish_args(tune_run, [])
    assert et.main([*args, "--skip-search", "ladder skipped: too slow"]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["tuning"] == {"mode": "skipped", "reason": "ladder skipped: too slow"}
    report = json.loads((tune_run / "workspace/reports/eva/m.json").read_text(encoding="utf-8"))
    assert report["status"] == "ok" and report["elapsed_s"] == 6963.6, "the base run's own report"
    assert report["entry_reached"] is True and report["tuning"]["mode"] == "skipped"
    assert "eva_tuned" not in pm.load_params(tune_run)["modules"].get("m", {}), "nothing is recorded"


@pytest.fixture
def tune_run(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "workspace/build").mkdir(parents=True)
    return tmp_path


# ---------------------------------------------------------------------------
# 1. No fallback inside tuning, and a timeout message that names the right limit
# ---------------------------------------------------------------------------


def _timing_out(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fallback_ok: bool = False) -> list[int | None]:
    """_execute_eva stand-in: the first run times out at its limit, fallbacks time out or complete."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(run_eva_slice, "_input_digest", lambda sources, flags: "d")
    limits: list[int | None] = []

    def fake_execute(cmd, sources, main_fn, out_dir, reduced_checks, timeout, path_root=None):
        limits.append(timeout)
        (Path(out_dir) / "eva.log").write_text(f"log of run {len(limits)}\n", encoding="utf-8")
        if len(limits) > 1 and fallback_ok:
            return {"status": "ok", "sources": sources, "reduced_checks": [], "elapsed_s": 50.0}
        return {
            "status": "analysis_timeout",
            "error_summary": [f"Frama-C Eva exceeded the {timeout} s wall-clock limit", "last log line"],
            "sources": sources,
            "reduced_checks": [],
            "elapsed_s": float(timeout or 0),
            "log_file": str(Path(out_dir) / "eva.log"),
            "cost_profile": {"run": "timed_out", "self": [{"function": "M", "share": 0.5}], "inclusive": []},
        }

    monkeypatch.setattr(run_eva_slice, "_execute_eva", fake_execute)
    return limits


def test_a_tuning_trial_that_times_out_stays_a_timeout(tmp_path, monkeypatch):
    limits = _timing_out(tmp_path, monkeypatch, fallback_ok=True)
    res = run_eva_slice.run_eva_on_slice(
        ["a.c"], "eva_main", tmp_path / "out", timeout=7200, use_cache=False, timeout_fallback=False
    )
    assert limits == [7200], "no fallback tier runs"
    assert res["status"] == "analysis_timeout" and "timeout_fallback" not in res
    assert res["error_summary"][0] == "Frama-C Eva exceeded the 7200 s wall-clock limit"


def test_when_no_fallback_tier_completes_the_report_names_the_runs_own_limit(tmp_path, monkeypatch):
    limits = _timing_out(tmp_path, monkeypatch)
    out = tmp_path / "out"
    res = run_eva_slice.run_eva_on_slice(["a.c"], "eva_main", out, timeout=7200, use_cache=False)
    assert limits == [7200, 900, 900]
    assert res["status"] == "analysis_timeout"
    assert res["error_summary"][0] == "Frama-C Eva exceeded the 7200 s wall-clock limit"
    assert res["error_summary"][1].startswith("no fallback tier completed (each limited to 900 s): cvalue_fast")
    assert res["elapsed_s"] == 7200.0
    assert [t["tier"] for t in res["timeout_fallback_tried"]] == ["cvalue_fast", "cvalue_imprecise_alloc"]
    assert res["cost_profile"]["self"][0]["function"] == "M"
    # The timed-out run's own log is kept beside the last fallback's.
    assert res["log_file"] == str(out / "eva.timed_out.log")
    assert (out / "eva.timed_out.log").read_text(encoding="utf-8") == "log of run 1\n"


def test_a_base_run_still_falls_back(tmp_path, monkeypatch):
    limits = _timing_out(tmp_path, monkeypatch, fallback_ok=True)
    res = run_eva_slice.run_eva_on_slice(["a.c"], "eva_main", tmp_path / "out", timeout=7200, use_cache=False)
    assert limits == [7200, 900] and res["status"] == "ok" and res["timeout_fallback"] == "cvalue_fast"


def test_a_cached_fallback_result_never_answers_a_run_without_fallback(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(run_eva_slice, "_input_digest", lambda sources, flags: "d")
    materials: list[dict] = []

    def fake_memoize(ns, material, **kwargs):
        materials.append(material)
        return {"status": "ok"}

    monkeypatch.setattr(run_eva_slice.cache, "memoize", fake_memoize)
    for fallback in (True, False):
        run_eva_slice.run_eva_on_slice(["a.c"], "eva_main", Path("out"), timeout_fallback=fallback)
    assert "timeout_fallback" not in materials[0], "existing cache entries keep their keys"
    assert materials[1] == {**materials[0], "timeout_fallback": False}


def test_the_cli_turns_the_fallback_off(tmp_path, monkeypatch):
    seen: dict = {}

    def fake_run(**kwargs):
        seen.update(kwargs)
        return {
            "status": "ok",
            "error_summary": [],
            "undeclared_functions": [],
            **{k: 0 for k in ("valid_count", "unknown_count", "invalid_count", "dead_count", "assumed_count")},
            "discharged_percentage": 0.0,
            "surviving_unknown_functions": [],
        }

    monkeypatch.setattr(run_eva_slice, "run_eva_on_slice", fake_run)
    base = [
        "--sources",
        "a.c",
        "--main",
        "eva_main",
        "--out-dir",
        str(tmp_path),
        "--out-json",
        str(tmp_path / "r.json"),
    ]
    assert run_eva_slice.main([*base, "--no-timeout-fallback"]) == 0
    assert seen["timeout_fallback"] is False
    assert run_eva_slice.main(base) == 0
    assert seen["timeout_fallback"] is True


def test_loop_trials_run_without_the_fallback(tune_run, monkeypatch):
    seen: dict = {}

    def fake_run(**kwargs):
        seen.update(kwargs)
        return {"status": "analysis_timeout"}

    monkeypatch.setattr(et, "run_eva_on_slice", fake_run)
    args = et.argparse.Namespace(
        sources=["a.c"],
        main="eva_main",
        cppflags="-I.",
        slevel=100,
        mlevel=0,
        timeout=600,
        extra_domains="",
        allow_incomplete_recursion_specs=False,
        no_warn_unsigned_downcast=True,
        module="m",
        entry_fn=None,
        report_dir=str(tune_run / "r"),
        work_dir=str(tune_run / "w"),
    )
    et.Tuner(args).run_trial("loop-f-0", {}, [])
    assert seen["timeout_fallback"] is False


# ---------------------------------------------------------------------------
# 2. One resource-history key per rung
# ---------------------------------------------------------------------------


def test_a_rung_leases_from_its_own_peak_once_measured_and_from_the_module_before(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    # QCBOR run-5: the base run peaked at 12.6 GB, the relational rung at 4.7 GB.
    R.write_history(run, {"class": "eva", "key": "libqcbor_a", "peak_mb": 12630, "oom_killed": False})
    # First run of a rung: no record of its own, so the module's largest peak (never the class default).
    assert R.history_estimate(run, "eva", "libqcbor_a:slevel") == 15788
    R.write_history(run, {"class": "eva", "key": "libqcbor_a:relational", "peak_mb": 4761, "oom_killed": False})
    assert R.history_estimate(run, "eva", "libqcbor_a:relational") == 5952
    # Another rung still has no peak of its own: the largest of the module's, base run included.
    assert R.history_estimate(run, "eva", "libqcbor_a:values") == 15788
    # The base run and eva-<mod> keep their own key, untouched by the rungs' smaller peaks.
    assert R.history_estimate(run, "eva", "libqcbor_a") == 15788
    # A module never measured has no estimate: the class default applies, as for any first run.
    assert R.history_estimate(run, "eva", "other:slevel") is None


def test_the_rung_rule_has_its_own_key_and_no_fallback():
    text = (REPO / "templates/pipeline.mk").read_text(encoding="utf-8")
    rule = text[text.index("define EVA_RUNG_RULE") : text.index("endef", text.index("define EVA_RUNG_RULE"))]
    assert "--key $(1):$(2)" in rule and "--no-timeout-fallback" in rule
    finish = text[text.index("eva_finish_cmd =") : text.index("--out-json", text.index("eva_finish_cmd ="))]
    assert "--skip-search $(EVA_TUNE_SKIP_$(1))" in finish


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("make") is None, reason="GNU make not available")
def test_make_dry_run_of_a_skipped_ladder_and_rung_keys(tmp_path):
    run = _make_run(tmp_path)
    scripts = f"S={(REPO / 'scripts').as_posix()}"

    def make(*args):
        proc = subprocess.run(
            ["make", "-f", pm.MAKEFILE, scripts, "-n", *args], cwd=run, capture_output=True, text=True, check=False
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        return proc.stdout.replace("\\n", " ")

    _base_report(run)
    pm.generate(run, templates_dir=ACSL)
    out = make("evatune-snmp")
    assert "--key snmp:slevel" in out and "--no-timeout-fallback" in out and "--skip-search" not in out

    _base_report(run, elapsed_s=6963.6)
    pm.generate(run, templates_dir=ACSL)
    out = make("evatune-snmp")
    assert "run_eva_slice.py" not in out and "eva_tuning.py finish" in out
    assert "--skip-search 'ladder skipped: the base run took 6964 s" in out


# ---------------------------------------------------------------------------
# 3. The flamegraph only where its profile is read
# ---------------------------------------------------------------------------


def _command(**kwargs) -> list[str]:
    cmd, _ = run_eva_slice._eva_command(
        ["a.c"], "eva_main", Path("out"), "gcc_x86_64", "-I.", 100, True, True, True, None, **kwargs
    )
    return cmd


def test_the_flamegraph_is_on_by_default_and_off_on_request():
    assert "-eva-flamegraph" in _command()
    cmd = _command(flamegraph=False)
    assert "-eva-flamegraph" not in cmd and not any("flamegraph" in token for token in cmd)
    # Nothing else changes: the analysis, hence its statuses, is the same.
    on = _command()
    i = on.index("-eva-flamegraph")
    assert on[:i] + on[i + 2 :] == cmd


def test_a_run_without_flamegraph_passes_no_flag_to_frama_c(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(run_eva_slice, "_input_digest", lambda sources, flags: "d")
    seen: list[list[str]] = []

    def fake_execute(cmd, sources, main_fn, out_dir, reduced_checks, timeout, path_root=None):
        seen.append(cmd)
        return {"status": "ok", "sources": sources, "reduced_checks": []}

    monkeypatch.setattr(run_eva_slice, "_execute_eva", fake_execute)
    run_eva_slice.run_eva_on_slice(["a.c"], "eva_main", tmp_path / "o", use_cache=False, flamegraph=False)
    run_eva_slice.run_eva_on_slice(["a.c"], "eva_main", tmp_path / "o", use_cache=False)
    assert "-eva-flamegraph" not in seen[0] and "-eva-flamegraph" in seen[1]


def test_rungs_and_loop_trials_write_no_flamegraph(tune_run, monkeypatch):
    text = (REPO / "templates/pipeline.mk").read_text(encoding="utf-8")
    rule = text[text.index("define EVA_RUNG_RULE") : text.index("endef", text.index("define EVA_RUNG_RULE"))]
    assert "--no-flamegraph" in rule
    base_rule = text[text.index("$(EVA_BASE_TARGETS): evabase-%:") : text.index("define EVA_RUNG_RULE")]
    assert "--no-flamegraph" not in base_rule, "the base run keeps its profile"
    seen: dict = {}
    monkeypatch.setattr(et, "run_eva_on_slice", lambda **kwargs: seen.update(kwargs) or {"status": "ok"})
    args = et.argparse.Namespace(
        sources=["a.c"],
        main="eva_main",
        cppflags="-I.",
        slevel=100,
        mlevel=0,
        timeout=600,
        extra_domains="",
        allow_incomplete_recursion_specs=False,
        no_warn_unsigned_downcast=True,
        module="m",
        entry_fn=None,
        report_dir=str(tune_run / "r"),
        work_dir=str(tune_run / "w"),
    )
    et.Tuner(args).run_trial("loop-f-0", {}, [])
    assert seen["flamegraph"] is False


def test_the_cli_turns_the_flamegraph_off(tmp_path, monkeypatch):
    seen: dict = {}

    def fake_run(**kwargs):
        seen.update(kwargs)
        return {
            "status": "ok",
            "error_summary": [],
            "undeclared_functions": [],
            **{k: 0 for k in ("valid_count", "unknown_count", "invalid_count", "dead_count", "assumed_count")},
            "discharged_percentage": 0.0,
            "surviving_unknown_functions": [],
        }

    monkeypatch.setattr(run_eva_slice, "run_eva_on_slice", fake_run)
    base = [
        "--sources",
        "a.c",
        "--main",
        "eva_main",
        "--out-dir",
        str(tmp_path),
        "--out-json",
        str(tmp_path / "r.json"),
    ]
    assert run_eva_slice.main([*base, "--no-flamegraph"]) == 0 and seen["flamegraph"] is False
    assert run_eva_slice.main(base) == 0 and seen["flamegraph"] is True


def test_a_report_resting_on_a_rung_publishes_the_base_runs_flamegraph(tmp_path):
    base_fg = tmp_path / "tune/base/flamegraph.txt"
    base_fg.parent.mkdir(parents=True)
    base_fg.write_text("eva_main 3\n", encoding="utf-8")
    dest = tmp_path / "eva/flamegraph.txt"
    et.publish_flamegraph({"flamegraph_file": None}, dest, {"flamegraph_file": base_fg.as_posix()})
    assert dest.read_text(encoding="utf-8") == "eva_main 3\n"
    rung_fg = tmp_path / "tune/slevel/flamegraph.txt"
    rung_fg.parent.mkdir(parents=True)
    rung_fg.write_text("eva_main 9\n", encoding="utf-8")
    et.publish_flamegraph({"flamegraph_file": rung_fg.as_posix()}, dest, {"flamegraph_file": base_fg.as_posix()})
    assert dest.read_text(encoding="utf-8") == "eva_main 9\n", "a run's own profile comes first"
    et.publish_flamegraph({"flamegraph_file": None}, dest, {"flamegraph_file": None})
    assert not dest.exists()


def test_the_cost_profile_reads_a_large_file_line_by_line(tmp_path, monkeypatch):
    import eva_flamegraph

    path = tmp_path / "flamegraph.txt"
    path.write_text("eva_main;f 3\neva_main;g 1\n" * 1000, encoding="utf-8")
    monkeypatch.setattr(Path, "read_text", lambda *a, **k: (_ for _ in ()).throw(AssertionError("whole file read")))
    profile = eva_flamegraph.cost_profile(path)
    assert profile is not None and profile["self"][0] == {"function": "f", "share": 0.75}
