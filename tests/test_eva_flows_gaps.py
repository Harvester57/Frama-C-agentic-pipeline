"""Large Eva reports, the gaps left after the flows spill (F4): tuning reports spill their flows, Eva-report
readers take the Eva size cap, a missing side file fails facts generation, a `flows_file` pointer stays
inside the run directory, and the shard merge keeps a `sure_outputs` list only later shards report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import pytest

import eva_shards as es
import eva_tuning as et
import framac_common as fc
import function_facts as ff
import pipeline_make as pm
from conftest import write_json
from test_eva_tuning import _base_report, _csv_row, _finish_args, _mk, _write_trial
from test_pipeline_make import _make_run

BIG_PAD = 65 * 1024 * 1024  # above load_json_optional's default 64 MiB cap


def _big_flows(n: int = 12) -> dict:
    return {
        "status": "ok",
        "reason": None,
        "by_function": {
            "f": {
                "writes": [{"loc": f"arr[{k}]", "and_self": False, "from": [f"src_{k}"]} for k in range(n)],
                "inputs": [f"src_{k}" for k in range(n)],
            }
        },
        "call_edges": {},
    }


# ---------------------------------------------------------------------------
# (a) eva_tuning.py spills the flows of the reports it writes
# ---------------------------------------------------------------------------


def _tuner_args(run: Path) -> argparse.Namespace:
    return argparse.Namespace(
        module="m",
        sources=["a.c"],
        main="eva_main",
        entry_fn="parse",
        cppflags="-I.",
        slevel=100,
        mlevel=0,
        extra_domains="",
        allow_incomplete_recursion_specs=False,
        no_warn_unsigned_downcast=False,
        timeout=None,
        report_dir=f"{pm.TUNE_REPORT_DIR}/m",
        work_dir="workspace/eva/m/tune",
        run_dir=run,
    )


def test_a_loop_trial_report_spills_large_flows(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(fc, "FLOWS_INLINE_MAX_BYTES", 256)
    monkeypatch.setattr(et, "run_eva_on_slice", lambda **kw: {"status": "ok", "flows": _big_flows()})
    run = et.Tuner(_tuner_args(tmp_path)).run_trial("loops", {}, [])
    assert "by_function" in run.report["flows"], "the in-memory report keeps its flows"
    on_disk = json.loads((tmp_path / pm.TUNE_REPORT_DIR / "m" / "loops.json").read_text(encoding="utf-8"))
    ref = on_disk["flows"]["flows_file"]
    assert "by_function" not in on_disk["flows"]
    assert ref == "workspace/eva/m/tune/loops/flows.json"
    assert json.loads((tmp_path / ref).read_text(encoding="utf-8")) == _big_flows()


def test_the_module_report_selected_from_a_trial_spills_its_flows(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(fc, "FLOWS_INLINE_MAX_BYTES", 256)
    (tmp_path / "workspace/build").mkdir(parents=True)
    _write_trial(tmp_path, "m", "base", [_csv_row(1), _csv_row(2)])
    rows = [_csv_row(1, "Valid"), _csv_row(2, "Valid")]
    _write_trial(tmp_path, "m", "slevel", rows, eva_options={"slevel": 1000}, flows=_big_flows())
    assert et.main(_finish_args(tmp_path, ["slevel"])) == 0
    capsys.readouterr()
    report_path = tmp_path / "workspace/reports/eva/m.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["tuning"]["selected"] == "slevel"
    assert "by_function" not in report["flows"]
    assert fc.resolve_flows(report["flows"], report_path=report_path) == _big_flows()
    assert [p.name for p in report_path.parent.glob("*.json")] == ["m.json"]


def test_a_spilled_trial_report_is_republished_with_its_flows(tmp_path, monkeypatch, capsys):
    # The base run (run_eva_slice.py) spilled its flows next to its trial directory; the module report
    # written from it gets a side file of its own, not a pointer into a trial's work directory.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(fc, "FLOWS_INLINE_MAX_BYTES", 256)
    (tmp_path / "workspace/build").mkdir(parents=True)
    write_json(tmp_path / "workspace/eva/m/tune/base/flows.json", _big_flows())
    pointer = {"status": "ok", "reason": None, "flows_file": "workspace/eva/m/tune/base/flows.json"}
    _write_trial(tmp_path, "m", "base", [_csv_row(1, "Valid")], flows=pointer)
    assert et.main(_finish_args(tmp_path, [])) == 0
    capsys.readouterr()
    report_path = tmp_path / "workspace/reports/eva/m.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["flows"]["flows_file"] == "workspace/eva/m/flows.json"
    assert fc.resolve_flows(report["flows"], report_path=report_path) == _big_flows()


# ---------------------------------------------------------------------------
# (b) Eva report readers take the Eva cap
# ---------------------------------------------------------------------------


def _pad_report(path: Path, **fields: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(fields)[:-1] + ', "pad": "')
        f.write("x" * BIG_PAD)
        f.write('"}\n')


@pytest.mark.slow
def test_read_trial_reads_a_report_above_64_mib(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_trial(tmp_path, "m", "base", [_csv_row(1)])
    path = tmp_path / pm.TUNE_REPORT_DIR / "m" / "base.json"
    report = json.loads(path.read_text(encoding="utf-8"))
    _pad_report(path, **report)
    run = et.Tuner(_tuner_args(tmp_path)).read_trial("base")
    assert run.report.get("status") == "ok", run.report.get("reason")


@pytest.mark.slow
def test_tuning_is_planned_from_a_base_report_above_64_mib(tmp_path):
    run = _make_run(tmp_path)
    _base_report(run)
    path = run / pm.TUNE_REPORT_DIR / "snmp" / "base.json"
    _pad_report(path, **json.loads(path.read_text(encoding="utf-8")))
    text = _mk(run)
    assert "EVA_TUNE_RUNGS_snmp :=\n" not in text
    assert "artifact exceeds" not in json.dumps(pm.generate(run))


@pytest.mark.slow
def test_the_run_summary_reads_the_status_of_a_large_report(tmp_path):
    path = tmp_path / "big.json"
    report = {"status": "analysis_timeout", "module": "m", "nested": {"status": "ok"}}
    fc.atomic_write_json(path, {**report, "pad": "x" * (9 * 1024 * 1024)})
    assert pm._report_brief(path) == {"report_status": "analysis_timeout"}


def test_ingest_refuses_an_eva_report_above_the_eva_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(pm, "EVA_REPORT_MAX_BYTES", 64)
    write_json(tmp_path / pm.REPORT_DIRS["eva"] / "m.json", {"status": "ok", "pad": "x" * 200})
    pending, _, bad = pm._pending_reports(tmp_path, "eva", "m", {})
    assert pending == [] and "exceeds" in bad[0]["error"]


# ---------------------------------------------------------------------------
# (c) a missing or unreadable side file fails facts generation, naming the file
# ---------------------------------------------------------------------------


def _report_with_pointer(run: Path, ref: str) -> Path:
    path = run / "workspace/reports/eva/m.json"
    write_json(path, {"status": "ok", "flows": {"status": "ok", "reason": None, "flows_file": ref}})
    return path


def test_resolve_flows_strict_raises_on_a_missing_side_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    report = _report_with_pointer(tmp_path, "workspace/eva/m/flows.json")
    flows = json.loads(report.read_text(encoding="utf-8"))["flows"]
    with pytest.raises(fc.ArtifactError, match="workspace/eva/m/flows.json"):
        fc.resolve_flows(flows, report_path=report, strict=True)
    # Lenient readers (the shard merge) still get a failed flows dict.
    lenient = fc.resolve_flows(flows, report_path=report)
    assert lenient is not None and lenient["status"] == "failed"


def test_resolve_flows_strict_raises_on_an_unreadable_side_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    side = tmp_path / "workspace/eva/m/flows.json"
    side.parent.mkdir(parents=True)
    side.write_text("{not json", encoding="utf-8")
    report = _report_with_pointer(tmp_path, "workspace/eva/m/flows.json")
    flows = json.loads(report.read_text(encoding="utf-8"))["flows"]
    with pytest.raises(fc.ArtifactError, match="flows.json"):
        fc.resolve_flows(flows, report_path=report, strict=True)


def test_facts_generation_fails_visibly_on_a_missing_side_file(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    report = _report_with_pointer(tmp_path, "workspace/eva/m/flows.json")
    out = tmp_path / "workspace/reports/facts/m.json"
    write_json(out, {"schema": ff.FACTS_SCHEMA, "module": "m", "status": "ok", "functions": {"m.c#f": {}}})
    with pytest.raises(fc.ArtifactError, match="workspace/eva/m/flows.json"):
        ff.generate("m", ["m.c"], "-I.", report, out)
    rc = ff.main(["--module", "m", "--sources", "m.c", "--eva-report", str(report), "--out-json", str(out)])
    printed = capsys.readouterr().out
    assert rc == 1 and "workspace/eva/m/flows.json" in printed
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["status"] == "failed" and doc["functions"] == {}, "no facts of an earlier run are left behind"
    assert "workspace/eva/m/flows.json" in doc["eva"]["reason"]


# ---------------------------------------------------------------------------
# (d) flows_file stays inside the run directory
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ref", ["../outside/flows.json", "workspace/../../outside/flows.json", "ABSOLUTE"])
def test_a_flows_file_outside_the_run_directory_is_refused(tmp_path, monkeypatch, ref):
    run = tmp_path / "run"
    run.mkdir()
    monkeypatch.chdir(run)
    outside = tmp_path / "outside" / "flows.json"
    write_json(outside, _big_flows())
    if ref == "ABSOLUTE":
        ref = outside.as_posix()
    report = _report_with_pointer(run, ref)
    flows = json.loads(report.read_text(encoding="utf-8"))["flows"]
    resolved = fc.resolve_flows(flows, report_path=report)
    assert resolved is not None and resolved["status"] == "failed" and resolved["by_function"] == {}
    assert "run-relative" in resolved["reason"]
    with pytest.raises(fc.ArtifactError, match="run-relative"):
        fc.resolve_flows(flows, report_path=report, strict=True)


def test_a_run_relative_flows_file_resolves(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    write_json(tmp_path / "workspace/eva/m/flows.json", _big_flows())
    report = _report_with_pointer(tmp_path, "workspace/eva/m/flows.json")
    flows = json.loads(report.read_text(encoding="utf-8"))["flows"]
    assert fc.resolve_flows(flows, report_path=report, strict=True) == _big_flows()


def test_spill_keeps_flows_inline_when_the_side_file_would_be_outside_the_run(tmp_path, monkeypatch):
    run = tmp_path / "run"
    run.mkdir()
    monkeypatch.chdir(run)
    monkeypatch.setattr(fc, "FLOWS_INLINE_MAX_BYTES", 256)
    report = {"status": "ok", "module": "m", "flows": _big_flows()}
    out = fc.spill_large_flows(report, tmp_path / "elsewhere" / "flows.json", report_path=run / "workspace/r.json")
    assert out["flows"] == _big_flows()
    assert not (tmp_path / "elsewhere" / "flows.json").exists()


# ---------------------------------------------------------------------------
# (e) the shard merge: sure outputs only later shards report
# ---------------------------------------------------------------------------


def test_sure_outputs_reported_only_by_a_later_shard_are_kept():
    a = {"status": "ok", "by_function": {"f": {"inputs": ["x"]}}, "call_edges": {}}
    b = {"status": "ok", "by_function": {"f": {"inputs": ["y"], "sure_outputs": ["r"]}}, "call_edges": {}}
    c = {"status": "ok", "by_function": {"f": {"sure_outputs": ["r", "s"]}}, "call_edges": {}}
    merged = es.merge_flows([a, b, c])["by_function"]["f"]
    assert merged["sure_outputs"] == ["r"], "intersection over the shards that report sure outputs"
    assert merged["inputs"] == ["x", "y"]
