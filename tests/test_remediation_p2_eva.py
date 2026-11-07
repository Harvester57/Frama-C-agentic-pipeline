"""Remediation P2 (docs/remediation-plan.md): M2, Eva tuning is never lost; M3, one alarm kind per property."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

import eva_options as eo
import eva_tuning as et
import pipeline_make as pm
from fingerprint import (
    detect_predicate_alarm_kind,
    leading_alarm_kind,
    make_fingerprint,
    normalize_kind,
    normalize_predicate,
)
from test_eva_tuning import _base_report, _csv_row, _finish_args, _mk, _record, _write_trial
from test_pipeline_make import FakeMake, _make_run

REPO = Path(__file__).resolve().parent.parent
ACSL = "/opt/framac-pipeline/templates"
MK = (REPO / "templates" / "pipeline.mk").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# M3: fuzz and Eva fingerprint the same property alike
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_fuzz_and_eva_hits_on_the_same_property_share_a_fingerprint():
    # E-ACSL reports the label apart (`mem_access`, run_eacsl_fuzz.py takes it as alarm_kind) and the
    # predicate without it; Eva's annotation keeps the label. `shift` is an identifier, not the kind.
    fuzz = make_fingerprint("workspace/work/src/a.c", "f", "mem_access", r"\valid_read(p + shift)")
    eva = make_fingerprint("src/a.c", "f", "mem_access", r"mem_access: \valid_read(p + shift)")
    eva_assertion = make_fingerprint("src/a.c", "f", "Assertion", r"assert rte: mem_access: \valid_read(p + shift);")
    assert fuzz == eva == eva_assertion
    assert fuzz.startswith("src/a.c#f::mem_access::")

    fuzz = make_fingerprint("src/a.c", "g", "index_bound", "index < 16")
    eva = make_fingerprint("src/a.c", "g", "Assertion", "index_bound: index < 16")
    assert fuzz == eva and "::index_bound::" in fuzz


@pytest.mark.unit
def test_the_label_wins_then_the_kind_then_a_label_inside_the_predicate():
    assert normalize_kind("index_bound", r"mem_access: \valid(p)") == "mem_access"
    assert normalize_kind("mem_access", r"\valid_read(p + shift)") == "mem_access"
    assert normalize_kind("Assertion", "rte/pointer_value: \\object_pointer(p)") == "ptr_value"
    assert normalize_kind("assertion", "assert rte: shift: 0 <= n < 32") == "shift"
    assert normalize_kind("", r"E-ACSL rte/index_bound i < 8") == "index_bound"


@pytest.mark.unit
def test_identifiers_named_like_alarm_kinds_are_not_kinds():
    assert normalize_kind("assertion", r"\valid(p + index + shift)") == "assertion"
    assert normalize_kind("", "x < overlap") == "property"
    assert detect_predicate_alarm_kind("c ? shift : 0") == ""
    assert detect_predicate_alarm_kind("a::shift") == ""
    assert leading_alarm_kind("shift_count: n < 32") == ""
    assert leading_alarm_kind("rte/shift: n < 32") == "shift"
    # The label never reaches the hash, whichever side kept it.
    assert normalize_predicate(r"mem_access: \valid_read(p + shift)") == normalize_predicate(r"\valid_read(p+shift)")


@pytest.mark.unit
def test_fingerprints_that_were_already_right_did_not_move():
    # Pinned from the previous implementation: only kinds read from identifiers changed.
    assert make_fingerprint("src/ber.c", "ber_len", "mem_access", r"\valid_read(buf+i)") == (
        "src/ber.c#ber_len::mem_access::5f9277855c"
    )
    assert make_fingerprint("src/parser/parser.c", "parse_record", "assertion", "rte/index_bound: i < 8.") == (
        "src/parser/parser.c#parse_record::index_bound::6614fa2ecf"
    )
    assert make_fingerprint("src/x.c", "f", "", r"\valid(p)") == "src/x.c#f::property::6cb4981e0d"


# ---------------------------------------------------------------------------
# M2: modules.mk, warnings and run order
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_a_current_decision_makes_eva_replay_the_tuning(tmp_path):
    run = _make_run(tmp_path)
    _base_report(run)
    pm.record_eva_tuning(run, "snmp", _record(run))
    text = _mk(run)
    assert "EVA_REPLAY_snmp := 1\n" in text and "EVA_REPLAY_cfg :=\n" in text
    plan = pm.build_plan(run, templates_dir=ACSL)
    assert plan.modules["snmp"].eva_replay is True
    assert not [w for w in plan.warnings if "Eva tuning" in w]
    assert pm._node_deps("eva-snmp", plan) == ["evabase-snmp"]
    assert pm._node_deps("eva-cfg", plan) == []


@pytest.mark.unit
def test_a_stale_decision_is_a_visible_warning_in_gen_and_run(tmp_path):
    run = _make_run(tmp_path)
    _base_report(run)
    pm.record_eva_tuning(run, "snmp", _record(run))
    pm.params_set(run, "snmp", eva_slevel=250)  # other settings: the decision no longer applies

    out = pm.generate(run, templates_dir=ACSL)
    text = (run / pm.MODULES_MK).read_text(encoding="utf-8")
    assert "EVA_REPLAY_snmp :=\n" in text and "EVA_OPTIONS_snmp :=\n" in text
    top = [w for w in out["warnings"] if w.startswith("snmp: Eva tuning:")]
    assert len(top) == 1 and "stale" in top[0] and "base options" in top[0]
    assert any("stale" in w for w in out["modules"]["snmp"]["warnings"])

    rc, summary = pm.run_targets(["eva-snmp"], run, jobs=1, make_runner=FakeMake(), templates_dir=ACSL)
    assert rc == 0 and any(w.startswith("snmp: Eva tuning:") and "stale" in w for w in summary["warnings"])


@pytest.mark.unit
def test_a_decision_on_other_sources_warns_that_it_is_not_replayed(tmp_path):
    run = _make_run(tmp_path)
    _base_report(run)
    pm.record_eva_tuning(run, "snmp", _record(run, input_digest="older"))
    out = pm.generate(run, templates_dir=ACSL)
    assert not out["modules"]["snmp"]["eva_replay"]
    assert any("cannot be replayed" in w for w in out["warnings"] if w.startswith("snmp: "))


@pytest.mark.unit
def test_flamegraph_renders_after_eva_and_eva_tune_and_never_runs_eva():
    assert pm.STAGE_OF_TARGET["flamegraph"] > pm.STAGE_OF_TARGET["eva-tune"] > pm.STAGE_OF_TARGET["eva"]
    assert pm._stage("flamegraph-snmp") == pm._stage("flamegraph")
    assert "$(FLAMEGRAPH_TARGETS): flamegraph-%:\n" in MK
    assert "flamegraph-%: eva-%" not in MK
    assert "workspace/eva/$*/flamegraph.txt not found" in MK


@pytest.mark.unit
def test_eva_and_eva_tune_share_the_finish_command():
    assert "$(if $(EVA_REPLAY_$*),$(call eva_finish_cmd,$*) --replay-only,$(call eva_plain_cmd,$*))" in MK
    assert "eva-$(m): evabase-$(m) $(foreach r,$(EVA_TUNE_RUNGS_$(m)),evarung-$(m)--$(r))" in MK
    tune_recipe = MK.split("$(EVA_TUNE_TARGETS): evatune-%:", 1)[1].split("\n\n", 1)[0]
    assert "$(call eva_finish_cmd,$*)" in tune_recipe and "--replay-only" not in tune_recipe
    assert "--flamegraph-out workspace/eva/$(1)/flamegraph.txt" in MK


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("make") is None, reason="GNU make not available")
def test_make_dry_run_replays_the_tuning_for_eva_and_module(tmp_path):
    run = _make_run(tmp_path)
    _base_report(run)
    pm.record_eva_tuning(run, "snmp", _record(run))
    pm.generate(run, templates_dir=ACSL)
    proc = subprocess.run(
        ["make", "-f", pm.MAKEFILE, f"S={(REPO / 'scripts').as_posix()}", "-n", "module-snmp", "eva-cfg"],
        cwd=run,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = proc.stdout.replace("\\\n", " ")
    assert "--out-json workspace/reports/eva-tuning/snmp/base.json" in out
    assert "eva_tuning.py finish --module snmp" in out and "--replay-only" in out
    assert "--out-dir workspace/eva/snmp " not in out, "no single run of the selected options"
    assert "run_eva_slice.py --module cfg" in out and "eva_tuning.py finish --module cfg" not in out


# ---------------------------------------------------------------------------
# M2: finish --replay-only and the flamegraph of the reported run
# ---------------------------------------------------------------------------


@pytest.fixture
def tune_run(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "workspace/build").mkdir(parents=True)
    return tmp_path


def _report(run_dir: Path) -> dict:
    return json.loads((run_dir / "workspace/reports/eva/m.json").read_text(encoding="utf-8"))


def _trials(run_dir: Path) -> None:
    base = _write_trial(run_dir, "m", "base", [_csv_row(1), _csv_row(2)])
    (base / "flamegraph.txt").write_text("base 1\n", encoding="utf-8")
    slevel = _write_trial(
        run_dir,
        "m",
        "slevel",
        [_csv_row(1, "Valid"), _csv_row(2)],
        eva_options={"slevel": 1000},
        flamegraph_file=(run_dir / "workspace/eva/m/tune/slevel/flamegraph.txt").as_posix(),
    )
    (slevel / "flamegraph.txt").write_text("slevel 1\n", encoding="utf-8")
    _write_trial(run_dir, "m", "history", [_csv_row(1), _csv_row(2, "Valid")], eva_options={"partition-history": 1})


@pytest.mark.unit
def test_replay_only_gives_the_report_eva_tune_gives(tune_run, capsys):
    _trials(tune_run)
    flame = ["--flamegraph-out", "workspace/eva/m/flamegraph.txt"]
    assert et.main(_finish_args(tune_run, ["slevel", "history"]) + flame) == 0
    tuned = _report(tune_run)
    assert tuned["tuning"]["mode"] == "ladder" and tuned["unknown_count"] == 0
    # The report rests on the selected run: its flamegraph is the one flamegraph-<mod> renders.
    assert (tune_run / "workspace/eva/m/flamegraph.txt").read_text(encoding="utf-8") == "slevel 1\n"
    record = pm.load_params(tune_run)["modules"]["m"]["eva_tuned"]

    assert et.main(_finish_args(tune_run, eo.recorded_rungs(record)) + flame) == 0
    via_eva_tune = _report(tune_run)
    assert et.main([*_finish_args(tune_run, eo.recorded_rungs(record)), *flame, "--replay-only"]) == 0
    via_eva = _report(tune_run)
    capsys.readouterr()
    assert via_eva == via_eva_tune and via_eva["tuning"]["mode"] == "replay" and via_eva["unknown_count"] == 0
    assert pm.load_params(tune_run)["modules"]["m"]["eva_tuned"] == record


@pytest.mark.unit
def test_replay_only_on_a_stale_decision_gives_the_base_report_and_records_nothing(tune_run, capsys):
    _trials(tune_run)
    flame = ["--flamegraph-out", "workspace/eva/m/flamegraph.txt"]
    assert et.main(_finish_args(tune_run, ["slevel", "history"]) + flame) == 0
    record = pm.load_params(tune_run)["modules"]["m"]["eva_tuned"]

    args = _finish_args(tune_run, eo.recorded_rungs(record), digest="other-settings") + flame + ["--replay-only"]
    assert et.main(args) == 0
    capsys.readouterr()
    report = _report(tune_run)
    assert report["tuning"]["mode"] == "skipped" and "eva-tune" in report["tuning"]["reason"]
    assert report["eva_options"] == {} and report["csv_file"].endswith("tune/base/alarms.csv"), "the base run alone"
    assert pm.load_params(tune_run)["modules"]["m"]["eva_tuned"] == record, "a replay never re-records"
    # The base run named no flamegraph: a stale one from the tuned run must not be rendered for it.
    assert not (tune_run / "workspace/eva/m/flamegraph.txt").exists()


@pytest.mark.unit
def test_publish_flamegraph_copies_and_clears(tmp_path):
    src = tmp_path / "tune/base/flamegraph.txt"
    src.parent.mkdir(parents=True)
    src.write_text("main 3\n", encoding="utf-8")
    dest = tmp_path / "eva/flamegraph.txt"
    et.publish_flamegraph({"flamegraph_file": src.as_posix()}, dest)
    assert dest.read_text(encoding="utf-8") == "main 3\n"
    et.publish_flamegraph({"flamegraph_file": None}, dest)
    assert not dest.exists()
    et.publish_flamegraph({"flamegraph_file": src.as_posix()}, None)
    assert not dest.exists()
