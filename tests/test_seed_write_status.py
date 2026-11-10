"""Seed and fuzz-asset writes record their outcome, and the fuzz report carries it as `seeds` (K1)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

import fuzz_assets as fa
import run_eacsl_fuzz as R
import seed_harvest as sh

pytestmark = pytest.mark.unit

HARNESS = """\
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    uint8_t *fuzz_buf = bounded_buf;
    size_t fuzz_len = size;
    /* Invoke target module entry point */
    (void)kv_load((const uint8_t *)fuzz_buf, (size_t)fuzz_len);
    return 0;
}
"""


def _harness(run: Path, module: str) -> None:
    hdir = run / "workspace" / "harnesses"
    hdir.mkdir(parents=True, exist_ok=True)
    (hdir / f"harness_{module}.json").write_text(json.dumps({"module": module}), encoding="utf-8")
    (hdir / f"harness_{module}.c").write_text(HARNESS, encoding="utf-8")


def _records(run: Path) -> None:
    rec = run / "workspace" / "seed_records"
    rec.mkdir(parents=True, exist_ok=True)
    call = {"fn": "kv_load", "args": {"0": [["b", 0, "0102"]], "1": [["i", 0, "0200000000000000"]]}}
    (rec / "calls.jsonl").write_text(json.dumps(call) + "\n", encoding="utf-8")


def _status(run: Path, writer: str, module: str) -> dict:
    return json.loads((run / "workspace" / "reports" / "seed_status" / writer / f"{module}.json").read_text("utf-8"))


# --- seed_harvest.py write ------------------------------------------------------------------------------


def test_seed_write_records_skipped_without_records(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _harness(tmp_path, "m")
    assert sh.main(["write", "--module", "m", "--module", "ghost"]) == 0
    st = _status(tmp_path, "seed_harvest", "m")
    assert st["status"] == "skipped" and "record has not run" in st["reason"] and st["inputs"] == 0
    ghost = _status(tmp_path, "seed_harvest", "ghost")
    assert ghost["status"] == "skipped" and "no harness sidecar" in ghost["reason"]
    assert json.loads(capsys.readouterr().out)["modules"]["m"]["status"] == "skipped"


def test_seed_write_failure_is_recorded_per_module_and_exits_1(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _records(tmp_path)
    _harness(tmp_path, "bad")
    _harness(tmp_path, "good")
    real = sh.write_module

    def flaky(module, *a, **k):
        if module == "bad":
            raise OSError(28, "No space left on device")
        return real(module, *a, **k)

    monkeypatch.setattr(sh, "write_module", flaky)
    assert sh.main(["write"]) == 1
    bad = _status(tmp_path, "seed_harvest", "bad")
    assert bad["status"] == "failed" and "No space left on device" in bad["reason"]
    assert "workspace/seeds/bad/ may hold part" in bad["reason"]
    good = _status(tmp_path, "seed_harvest", "good")
    assert good["status"] == "ok" and good["inputs"] == 1 and "reason" not in good
    out = json.loads(capsys.readouterr().out)["modules"]
    assert out["bad"]["status"] == "failed" and out["good"] == {"seeds": 1, "dropped_too_large": 0, "status": "ok"}


def test_unreadable_records_fail_every_selected_module(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _harness(tmp_path, "m")
    (tmp_path / "workspace" / "seed_records" / "files" / "not_a_file").mkdir(parents=True)
    out = sh.write([])
    assert "cannot read workspace/seed_records" in out["error"]
    assert _status(tmp_path, "seed_harvest", "m")["status"] == "failed"


def test_status_is_never_written_outside_the_status_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sh.record_write_status("seed_harvest", "../evil", "ok")
    sh.record_write_status("other_writer", "m", "ok")
    sh.record_write_status("seed_harvest", "m", "great")
    assert not (tmp_path / "workspace").exists()


# --- fuzz_assets.py write -------------------------------------------------------------------------------


def test_fuzz_assets_write_without_report_is_skipped(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _harness(tmp_path, "m")
    assert fa.main(["write", "--module", "m"]) == 0
    st = _status(tmp_path, "fuzz_assets", "m")
    assert st["status"] == "skipped" and "discover has not run" in st["reason"] and st["inputs"] == 0


def test_fuzz_assets_malformed_report_fails_and_exits_1(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _harness(tmp_path, "m")
    (tmp_path / "workspace" / "reports").mkdir(parents=True, exist_ok=True)
    (tmp_path / "workspace" / "reports" / "fuzz_assets.json").write_text("{not json", encoding="utf-8")
    assert fa.main(["write", "--module", "m"]) == 1
    st = _status(tmp_path, "fuzz_assets", "m")
    assert st["status"] == "failed" and "cannot read workspace/reports/fuzz_assets.json" in st["reason"]


def test_fuzz_assets_write_module_exception_is_recorded(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _harness(tmp_path, "m")

    def boom(*a, **k):
        raise PermissionError("denied")

    monkeypatch.setattr(fa, "write_module", boom)
    assert fa.main(["write"]) == 1
    st = _status(tmp_path, "fuzz_assets", "m")
    assert st["status"] == "failed" and st["reason"].startswith("PermissionError: denied")
    assert "workspace/imported_corpus/m/" in st["reason"]


# --- the fuzz report's `seeds` field --------------------------------------------------------------------


def test_seeds_field_combines_both_writers(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert sh.seeds_report_field("m", extra_corpus=False)["status"] == "skipped"
    assert sh.seeds_report_field(None, extra_corpus=True)["status"] == "skipped"

    missing = sh.seeds_report_field("m", extra_corpus=True)
    assert missing["status"] == "failed" and "did not run" in missing["reason"]
    assert set(missing["writers"]) == {"seed_harvest", "fuzz_assets"}

    sh.record_write_status("seed_harvest", "m", "ok", inputs=3)
    sh.record_write_status("fuzz_assets", "m", "skipped", "no corpus mapped", inputs=0)
    field = sh.seeds_report_field("m", extra_corpus=True)
    assert field["status"] == "ok" and "reason" not in field
    assert field["writers"]["seed_harvest"]["inputs"] == 3
    assert field["writers"]["fuzz_assets"]["reason"] == "no corpus mapped"

    sh.record_write_status("seed_harvest", "m", "skipped", "no records")
    field = sh.seeds_report_field("m", extra_corpus=True)
    assert field["status"] == "skipped" and field["reason"] == "seed_harvest: no records; fuzz_assets: no corpus mapped"

    sh.record_write_status("fuzz_assets", "m", "failed", "OSError: disk full")
    field = sh.seeds_report_field("m", extra_corpus=True)
    assert field == {**field, "status": "failed", "reason": "fuzz_assets: OSError: disk full"}

    sh.write_status_path("seed_harvest", "m").write_text("{oops", encoding="utf-8")
    field = sh.seeds_report_field("m", extra_corpus=True)
    assert field["status"] == "failed" and "unreadable status" in field["writers"]["seed_harvest"]["reason"]


def _argv(tmp_path: Path, *extra: str) -> list[str]:
    return [
        "run_eacsl_fuzz.py",
        "campaign",
        "--module",
        "m",
        "--sources",
        "mod.c",
        "--out-bin",
        str(tmp_path / "fuzz_m"),
        "--corpus-dir",
        str(tmp_path / "corpus"),
        "--artifacts-dir",
        str(tmp_path / "artifacts"),
        "--out-json",
        str(tmp_path / "out.json"),
        *extra,
    ]


def test_campaign_report_carries_the_seeds_field(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    sh.record_write_status("seed_harvest", "m", "failed", "OSError: disk full")
    sh.record_write_status("fuzz_assets", "m", "ok", inputs=2)
    monkeypatch.setattr(R, "_run_campaign_mode", lambda args: {"mode": "campaign", "status": "clean"})
    monkeypatch.setattr(sys, "argv", _argv(tmp_path, "--extra-corpus", "workspace/seeds/m"))
    assert R.main() == 0
    report = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    assert report["seeds"]["status"] == "failed" and report["seeds"]["reason"] == "seed_harvest: OSError: disk full"
    assert report["seeds"]["writers"]["fuzz_assets"]["inputs"] == 2


def test_campaign_report_without_extra_corpus_skips_seeds(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    def unavailable(args):
        raise R.SandboxUnavailable("no sandbox")

    monkeypatch.setattr(R, "_run_campaign_mode", unavailable)
    monkeypatch.setattr(sys, "argv", _argv(tmp_path))
    assert R.main() == 3
    report = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    assert report["status"] == "sandbox_unavailable" and report["seeds"]["status"] == "skipped"
