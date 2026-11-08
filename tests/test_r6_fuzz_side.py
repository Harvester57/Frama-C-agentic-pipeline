"""Remediation step R6: coverage of snapshot headers, the replay fallback spec, the campaign gate."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

import phase0_gates
import pipeline_make as pm
import run_eacsl_fuzz as R
from framac_common import atomic_write_json as write_json
from test_pipeline_make import _unit_run

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Defect 10: snapshot headers are not target code
# ---------------------------------------------------------------------------


def _fn(name: str, filename: str, count: int = 1) -> dict:
    return {"name": name, "count": count, "filenames": [filename], "regions": [[1, 1, 2, 2, count, 0, 0, 0]]}


def test_snapshot_headers_count_as_external_code():
    summary = R.summarize_coverage_export(
        {
            "data": [
                {
                    "functions": [
                        _fn("parse", "/framac-run/workspace/work/src/p.c"),
                        _fn("gcry_inline", "/framac-run/workspace/snapshot/root/usr/include/gcrypt.h"),
                        _fn("rel_inline", "workspace/snapshot/root/usr/local/include/z.h"),
                        _fn("other_mount", "/elsewhere/run/workspace/snapshot/root/usr/include/y.h"),
                    ]
                }
            ]
        }
    )
    assert [f["function"] for f in summary["functions"]] == ["parse"]
    assert summary["excluded_functions"] == {"external": 3}


def test_a_target_directory_named_snapshot_stays_target_code():
    assert R._coverage_file_role("/framac-run/workspace/work/snapshot/root.c") == "target"
    assert R._coverage_file_role("/framac-run/workspace/snapshot/root/usr/include/a.h") == "external"


# ---------------------------------------------------------------------------
# Defect 8, fallback path: the spec follows the candidate's file and function
# ---------------------------------------------------------------------------


def _split_unit_run(tmp_path: Path) -> Path:
    run = _unit_run(tmp_path)
    dag = json.loads((run / pm.DAG_JSON).read_text(encoding="utf-8"))
    dag["functions"] = {
        "dec_run": {"name": "dec_run", "file": "src/decode.c", "module": "libkv_a", "lexer_module": "decode"},
        "enc_run": {"name": "enc_run", "file": "src/encode.c", "module": "libkv_a", "lexer_module": "encode"},
    }
    dag["modules"]["libkv_a"]["functions"] = ["dec_run", "enc_run"]
    write_json(run / pm.DAG_JSON, dag)
    return run


def test_fallback_spec_builds_the_sub_module_holding_the_candidates_function(tmp_path, monkeypatch):
    run = _split_unit_run(tmp_path)
    monkeypatch.chdir(run)
    hdir = Path(pm.HARNESS_DIR)
    assert R._sidecar_build_spec("libkv_a", hdir, "src/encode.c", "enc_run")["harness_module"] == "encode"
    assert R._sidecar_build_spec("libkv_a", hdir, "src/decode.c", "dec_run")["harness_module"] == "decode"
    # Without a location, the unit's first sub-module, as before.
    assert R._sidecar_build_spec("libkv_a", hdir)["harness_module"] == "decode"


def test_replay_spec_without_pipeline_make_passes_the_location_to_the_fallback(tmp_path, monkeypatch):
    run = _split_unit_run(tmp_path)
    monkeypatch.chdir(run)
    monkeypatch.setitem(sys.modules, "pipeline_make", None)  # `import pipeline_make` raises ImportError
    spec = R.replay_build_spec("libkv_a", Path(pm.HARNESS_DIR), "src/encode.c", "enc_run")
    assert spec["harness_module"] == "encode"
    assert spec["sources"] == ["src/encode.c", "workspace/harnesses/harness_encode.c"]


# ---------------------------------------------------------------------------
# Guidance mode: `campaign` checks the Phase 0 gate first
# ---------------------------------------------------------------------------


def _campaign_argv(tmp_path: Path, module: str = "m") -> list[str]:
    return [
        "campaign",
        "--module",
        module,
        "--sources",
        "harness_m.c",
        "--out-bin",
        str(tmp_path / "fuzz_m"),
        "--corpus-dir",
        str(tmp_path / "corpus"),
        "--artifacts-dir",
        str(tmp_path / "crashes"),
        "--out-json",
        str(tmp_path / "out" / "m.json"),
    ]


def _no_campaign(*_args, **_kwargs):
    raise AssertionError("the campaign ran despite the gate")


def test_campaign_is_refused_when_the_gate_failed(tmp_path, monkeypatch, capsys):
    write_json(
        tmp_path / phase0_gates.GATES_JSON,
        {"reach": {"passed": False, "modules": {"m": {"passed": False, "gaps": ["api_open"], "error": None}}}},
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(R, "_run_campaign_mode", _no_campaign)
    assert R.main(_campaign_argv(tmp_path)) == 1
    out = capsys.readouterr()
    assert json.loads(out.out)["status"] == "gate_failed"
    assert "entry points not reached: api_open" in out.err
    assert not (tmp_path / "out" / "m.json").exists()


def test_campaign_is_refused_for_a_module_the_gate_never_checked(tmp_path):
    write_json(tmp_path / phase0_gates.GATES_JSON, {"reach": {"passed": True, "modules": {}}})
    reasons = R.campaign_gate_reasons(tmp_path, "m")
    assert any("module m was not checked" in r for r in reasons)
    # build-check never ran either: the campaign needs it too.
    assert any(r.startswith("build_check has not run") for r in reasons)


def test_campaign_runs_when_the_gate_passed(tmp_path, monkeypatch):
    (tmp_path / phase0_gates.HARNESS_DIR).mkdir(parents=True)
    (tmp_path / phase0_gates.HARNESS_DIR / "harness_m.c").write_text("int h;\n", encoding="utf-8")
    digest = phase0_gates.harness_digest(tmp_path, "m")
    write_json(
        tmp_path / phase0_gates.GATES_JSON,
        {
            "reach": {"passed": True, "modules": {"m": {"passed": True, "harness_digest": digest}}},
            "build_check": {"ok": True, "modules": {"m": {"ok": True, "status": "eacsl"}}},
        },
    )
    assert R.campaign_gate_reasons(tmp_path, "m") == []
    monkeypatch.chdir(tmp_path)
    ran: list[str] = []

    def fake_campaign(args):
        ran.append(args.module)
        return {"mode": "campaign", "module": args.module, "status": "ok", "artifacts": []}

    monkeypatch.setattr(R, "_run_campaign_mode", fake_campaign)
    monkeypatch.setattr(R, "_summary", lambda res: res)
    assert R.main(_campaign_argv(tmp_path)) == 0
    assert ran == ["m"]


def test_campaign_without_a_stamp_or_module_is_not_gated(tmp_path):
    assert R.campaign_gate_reasons(tmp_path, "m") == []
    write_json(tmp_path / phase0_gates.GATES_JSON, {"reach": {"passed": False, "modules": {}}})
    assert R.campaign_gate_reasons(tmp_path, "") == []
