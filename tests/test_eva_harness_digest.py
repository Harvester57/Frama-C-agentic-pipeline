"""Eva reports name the harness they stand for (`harness_digest`): run_eva_slice.py, the shard merge and
eva_tuning.py finish. wp_scheduler.py refresh compares it with the current harness."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import eva_shards as es
import eva_tuning as et
import phase0_gates
import run_eva_slice as res_mod
from conftest import write_json
from test_eva_shards import _merge, _row, _shard
from test_eva_tuning import _csv_row, _finish_args, _write_trial


def _harness(run: Path, module: str = "m", body: str = "void eva_main(void) {}\n", exempt: list | None = None) -> str:
    hdir = run / phase0_gates.HARNESS_DIR
    hdir.mkdir(parents=True, exist_ok=True)
    (hdir / f"harness_{module}.c").write_text(body, encoding="utf-8")
    write_json(hdir / f"harness_{module}.json", {"module": module, "reach_exempt": exempt or []})
    digest = phase0_gates.harness_digest(run, module, ignore_exempt=True)
    assert digest
    return digest


def _fake_eva(**extra: Any) -> dict:
    return {
        "status": "ok",
        "reason": None,
        "error_summary": [],
        "undeclared_functions": [],
        "valid_count": 1,
        "unknown_count": 0,
        "invalid_count": 0,
        "dead_count": 0,
        "assumed_count": 0,
        "discharged_percentage": 100.0,
        "surviving_unknown_functions": [],
        **extra,
    }


def _run_slice(run: Path) -> dict:
    out = run / "workspace/reports/eva/m.json"
    argv = ["--module", "m", "--sources", "a.c", "--main", "eva_main"]
    rc = res_mod.main([*argv, "--out-dir", str(run / "workspace/eva/m"), "--out-json", str(out)])
    assert rc == 0
    return json.loads(out.read_text(encoding="utf-8"))


def test_run_eva_slice_stamps_the_current_harness_digest_even_on_a_cache_hit(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(res_mod, "phase0_gate_reasons", lambda module: [])
    first = _harness(tmp_path)
    monkeypatch.setattr(res_mod, "run_eva_on_slice", lambda **kw: _fake_eva(cache={"hit": False, "key": "k"}))
    assert _run_slice(tmp_path)["harness_digest"] == first

    # A cache hit restores a report that may carry an older stamp: the field names the harness now.
    second = _harness(tmp_path, body="void eva_main(void) { int x = 0; }\n")
    assert second != first
    stale = _fake_eva(cache={"hit": True, "key": "k"}, harness_digest=first)
    monkeypatch.setattr(res_mod, "run_eva_on_slice", lambda **kw: dict(stale))
    assert _run_slice(tmp_path)["harness_digest"] == second

    # The exemption list is not the harness: the reach rows' ignore_exempt digest.
    _harness(tmp_path, body="void eva_main(void) { int x = 0; }\n", exempt=[{"function": "f", "reason": "r"}])
    assert _run_slice(tmp_path)["harness_digest"] == second
    capsys.readouterr()


def test_run_eva_slice_without_a_harness_stamps_none(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(res_mod, "phase0_gate_reasons", lambda module: [])
    monkeypatch.setattr(res_mod, "run_eva_on_slice", lambda **kw: _fake_eva())
    report = _run_slice(tmp_path)
    capsys.readouterr()
    assert "harness_digest" in report and report["harness_digest"] is None


def test_the_shard_merge_copies_an_agreed_harness_digest_and_input_digest(tmp_path, capsys):
    _shard(tmp_path, 0, [_row(1, "Valid")], {"parse": 5}, harness_digest="H", input_digest="same")
    _shard(tmp_path, 1, [_row(1, "Valid")], {"parse": 5}, harness_digest="H", input_digest="same")
    rc, report = _merge(tmp_path)
    capsys.readouterr()
    assert rc == 0 and report["harness_digest"] == "H"
    assert report["input_digest"] == "same"


def test_the_shard_merge_keeps_a_combined_input_digest_when_shards_differ(tmp_path, capsys):
    _shard(tmp_path, 0, [_row(1, "Valid")], {"parse": 5}, harness_digest="H")
    _shard(tmp_path, 1, [_row(1, "Valid")], {"parse": 5}, harness_digest="H")
    rc, report = _merge(tmp_path)
    capsys.readouterr()
    assert rc == 0 and report["input_digest"] not in (None, "d0", "d1")


def test_shards_run_on_different_harnesses_are_refused(tmp_path, capsys):
    _shard(tmp_path, 0, [_row(1, "Valid")], {"parse": 5}, harness_digest="H1")
    _shard(tmp_path, 1, [_row(1, "Valid")], {"parse": 5}, harness_digest="H2")
    rc, report = _merge(tmp_path)
    capsys.readouterr()
    assert rc == 1 and report["status"] == "analysis_error"
    assert "harness" in report["reason"]
    assert report.get("harness_digest") is None


def test_a_shard_without_a_stamp_beside_a_stamped_one_is_refused(tmp_path, capsys):
    _shard(tmp_path, 0, [_row(1, "Valid")], {"parse": 5}, harness_digest="H1")
    _shard(tmp_path, 1, [_row(1, "Valid")], {"parse": 5})
    rc, report = _merge(tmp_path)
    capsys.readouterr()
    assert rc == 1 and "harness" in report["reason"]


def test_finish_stamps_the_harness_the_base_run_used(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "workspace/build").mkdir(parents=True)
    _write_trial(tmp_path, "m", "base", [_csv_row(1), _csv_row(2)], harness_digest="H-base")
    _write_trial(tmp_path, "m", "slevel", [_csv_row(1, "Valid"), _csv_row(2, "Valid")], eva_options={"slevel": 1000})
    assert et.main(_finish_args(tmp_path, ["slevel"])) == 0
    capsys.readouterr()
    report = json.loads((tmp_path / "workspace/reports/eva/m.json").read_text(encoding="utf-8"))
    assert report["tuning"]["selected"] == "slevel"
    assert report["harness_digest"] == "H-base"


def _age(path: Path, when: float) -> None:
    os.utime(path, (when, when))


def _harness_at(run: Path, when: float) -> str:
    current = _harness(run)
    for suffix in (".c", ".json"):
        _age(run / phase0_gates.HARNESS_DIR / f"harness_m{suffix}", when)
    return current


def test_finish_without_a_stamped_base_stamps_the_current_harness(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "workspace/build").mkdir(parents=True)
    current = _harness_at(tmp_path, 1_000_000)
    _write_trial(tmp_path, "m", "base", [_csv_row(1, "Valid")])
    _age(tmp_path / "workspace/reports/eva-tuning/m/base.json", 2_000_000)
    assert et.main(_finish_args(tmp_path, [])) == 0
    capsys.readouterr()
    report = json.loads((tmp_path / "workspace/reports/eva/m.json").read_text(encoding="utf-8"))
    assert report["harness_digest"] == current


def test_finish_on_an_unstamped_base_older_than_the_harness_does_not_pass_for_the_current_harness(
    tmp_path, monkeypatch, capsys
):
    """A base run from before a harness repair, decided again today: the new report is not fresh evidence."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "workspace/build").mkdir(parents=True)
    current = _harness_at(tmp_path, 2_000_000)
    _write_trial(tmp_path, "m", "base", [_csv_row(1, "Valid")])
    _age(tmp_path / "workspace/reports/eva-tuning/m/base.json", 1_000_000)
    assert et.main(_finish_args(tmp_path, [])) == 0
    capsys.readouterr()
    report = json.loads((tmp_path / "workspace/reports/eva/m.json").read_text(encoding="utf-8"))
    assert report["harness_digest"] == phase0_gates.HARNESS_DIGEST_UNKNOWN != current


def test_the_merge_of_unstamped_shards_stands_for_the_harness_only_when_they_are_newer(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    current = _harness_at(tmp_path, 2_000_000)
    for i in (0, 1):
        _shard(tmp_path, i, [_row(1, "Valid")], {"parse": 5})
        _age(tmp_path / es.SHARD_DIR / "m" / f"shard{i}.json", 3_000_000)
    rc, report = _merge(tmp_path)
    assert rc == 0 and report["harness_digest"] == current

    # One shard report predates the harness (run-6: shards of the 181-case harness merged again later).
    _age(tmp_path / es.SHARD_DIR / "m" / "shard1.json", 1_000_000)
    rc, report = _merge(tmp_path)
    capsys.readouterr()
    assert rc == 0 and report["harness_digest"] == phase0_gates.HARNESS_DIGEST_UNKNOWN


def test_a_derived_digest_is_none_without_a_harness_and_unknown_without_inputs(tmp_path):
    assert phase0_gates.derived_harness_digest(tmp_path, "m", [tmp_path / "x.json"]) is None
    _harness(tmp_path)
    assert phase0_gates.derived_harness_digest(tmp_path, "m", []) == phase0_gates.HARNESS_DIGEST_UNKNOWN
    assert phase0_gates.derived_harness_digest(tmp_path, "m", [tmp_path / "missing.json"]) == "unknown"
