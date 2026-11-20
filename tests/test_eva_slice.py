"""Tests for run_eva_slice: missing spec repair hints, error summary, and address-flow soundness gate."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import run_eva_slice as E
import unit_split


@pytest.mark.unit
def test_extract_repair_hints_missing_spec_all_forms() -> None:
    log = (
        "[kernel] Neither code nor specification for function ext_fn,\n"
        "[kernel] Neither code nor explicit assigns for function rec_fn,\n"
        "[kernel:annot:missing-spec] a.c:10: Warning:\n"
        "  Neither code nor explicit exits, assigns and terminates for function\n"
        "  wrapped_fn, generating default clauses.\n"
        "[kernel] Neither code nor explicit exits and terminates for function benign_fn,\n"
    )
    hints = E.extract_repair_hints(log)
    by_fn = {h.get("function"): h for h in hints if h.get("pattern") == "missing_spec"}

    assert "ext_fn" in by_fn and by_fn["ext_fn"]["spec_kind"] == "specification"
    assert "rec_fn" in by_fn and by_fn["rec_fn"]["spec_kind"] == "assigns"
    assert "wrapped_fn" in by_fn and by_fn["wrapped_fn"]["spec_kind"] == "assigns"
    assert "benign_fn" not in by_fn


@pytest.mark.unit
def test_extract_error_summary_two_line_kernel_errors() -> None:
    log = (
        "[kernel:annot-error] foo.c:42: Warning:\n"
        "  unbound logic variable val.\n"
        "[kernel] user error: syntax error\n" + "\n".join(f"unrelated tail line {i}" for i in range(50))
    )
    summary = E.extract_error_summary(log, max_lines=5)
    assert len(summary) >= 2
    assert any("foo.c:42" in s and "unbound logic variable val" in s for s in summary)


def _write_address_flow_dag(path: Path) -> Path:
    dag = {
        "module_kind": "link_unit",
        "modules": {
            "prog": {
                "module": "prog",
                "functions": ["api_a", "unit_helper", "src/other.c#close"],
                "linked_modules": ["libcore_a"],
            },
            "libcore_a": {
                "module": "libcore_a",
                "functions": ["lib_compute"],
                "linked_modules": [],
            },
            "unrelated_exe": {
                "module": "unrelated_exe",
                "functions": ["other_app_fn"],
                "linked_modules": [],
            },
        },
        "submodules": {
            "prog__a": {
                "module": "prog__a",
                "unit": "prog",
                "kind": "cluster",
                "reach": unit_split.REACH_FLOW,
                "functions": ["api_a"],
            },
            "prog__cg": {
                "module": "prog__cg",
                "unit": "prog",
                "kind": "cluster",
                "reach": unit_split.REACH_CALLS,
                "functions": ["api_a"],
            },
        },
        "functions": {
            "api_a": {"name": "api_a", "file": "src/a.c", "is_static": False},
            "unit_helper": {"name": "unit_helper", "file": "src/helper.c", "is_static": False},
            "src/other.c#close": {"name": "close", "file": "src/other.c", "is_static": True},
            "lib_compute": {"name": "lib_compute", "file": "lib/core.c", "is_static": False},
            "other_app_fn": {"name": "other_app_fn", "file": "other/app.c", "is_static": False},
        },
        "global_variables": {
            "src/cfg.c#g_cfg": {
                "name": "g_cfg",
                "file": "src/cfg.c",
                "static": False,
                "init_functions": [],
                "init_globals": [],
            },
            "src/table.inc#g_tbl": {
                "name": "g_tbl",
                "file": "src/table.inc",
                "static": False,
                "compiled_in": ["src/table.c"],
                "init_functions": [],
                "init_globals": [],
            },
            "src/a.c#g_present": {
                "name": "g_present",
                "file": "src/a.c",
                "static": False,
                "init_functions": [],
                "init_globals": [],
            },
            "src/secret.c#g_static_only": {
                "name": "g_static_only",
                "file": "src/secret.c",
                "static": True,
                "init_functions": [],
                "init_globals": [],
            },
            "src/orphan.inc#g_no_tu": {
                "name": "g_no_tu",
                "file": "src/orphan.inc",
                "static": False,
                "compiled_in": [],
                "init_functions": [],
                "init_globals": [],
            },
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dag), encoding="utf-8")
    return path


def _ok_result(out_dir: Path, *, log_text: str = "", flows: dict | None = None, mirror_root: str | None = None) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / "eva.log"
    log_path.write_text(log_text, encoding="utf-8")
    return {
        "status": "ok",
        "reason": None,
        "error_summary": [],
        "undeclared_functions": [],
        "main_fn": "eva_main",
        "valid_count": 5,
        "unknown_count": 0,
        "invalid_count": 0,
        "dead_count": 0,
        "assumed_count": 0,
        "discharged_percentage": 100.0,
        "surviving_unknown_functions": [],
        "log_file": str(log_path),
        "mirror_root": mirror_root,
        "flows": flows or {"status": "ok", "reason": None, "by_function": {}, "call_edges": {}},
    }


@pytest.mark.unit
def test_address_flow_gate_ignores_external_libc_and_benign_missing_specs(tmp_path: Path) -> None:
    dag = _write_address_flow_dag(tmp_path / "dag.json")
    out_dir = tmp_path / "eva"
    log = (
        "[kernel:annot:missing-spec] src/a.c:12: Warning:\n"
        "  Neither code nor specification for function strlen, generating default assigns.\n"
        "[kernel:annot:missing-spec] src/a.c:15: Warning:\n"
        "  Neither code nor specification for function close, generating default assigns.\n"
        "[kernel:annot:missing-spec] src/a.c:18: Warning:\n"
        "  Neither code nor explicit exits and terminates for function unit_helper, generating default clauses.\n"
        "[kernel:annot:missing-spec] src/a.c:21: Warning:\n"
        "  Neither code nor specification for function other_app_fn, generating default assigns.\n"
    )
    res = _ok_result(out_dir, log_text=log)
    got = E.reject_address_flow_gaps(res, out_dir, "prog__a", dag, ["workspace/work/src/a.c"])
    assert got["status"] == "ok"
    assert got["reason"] is None
    assert "missing_project_bodies" not in got
    assert "missing_project_globals" not in got
    assert got["error_summary"] == []


@pytest.mark.unit
@pytest.mark.parametrize(
    ("fn_name", "expected_file"),
    [
        ("unit_helper", "src/helper.c"),
        ("lib_compute", "lib/core.c"),
    ],
)
def test_address_flow_gate_rejects_missing_project_body_in_unit_or_linked_module(
    tmp_path: Path, fn_name: str, expected_file: str
) -> None:
    dag = _write_address_flow_dag(tmp_path / "dag.json")
    out_dir = tmp_path / "eva"
    log = (
        f"[kernel:annot:missing-spec] src/a.c:10: Warning:\n"
        f"  Neither code nor specification for function {fn_name},\n"
        f"  generating default exits, assigns and terminates.\n"
    )
    res = _ok_result(out_dir, log_text=log)
    got = E.reject_address_flow_gaps(res, out_dir, "prog__a", dag, ["workspace/work/src/a.c"])
    assert got["status"] == "analysis_error"
    assert got["reason"] == "address_flow_missing_body"
    assert got["missing_project_bodies"] == [
        {"function": fn_name, "keys": [fn_name], "files": [expected_file], "missing": ["specification"]}
    ]
    assert got["error_summary"]
    assert fn_name in got["error_summary"][0] and expected_file in got["error_summary"][0]


@pytest.mark.unit
def test_address_flow_gate_rejects_omitted_project_globals_including_inc_compiled_in(tmp_path: Path) -> None:
    dag = _write_address_flow_dag(tmp_path / "dag.json")
    out_dir = tmp_path / "eva"
    flows = {
        "status": "ok",
        "reason": None,
        "by_function": {
            "eva_main": {
                "inputs": ["g_cfg.magic", "g_present", "<string literal>", "g_static_only", "g_no_tu"],
                "operational_inputs": ["g_tbl[0..3].cb"],
                "operational_inputs_on_termination": ["__fc_stdout"],
            }
        },
        "call_edges": {},
    }
    res = _ok_result(out_dir, flows=flows)
    got = E.reject_address_flow_gaps(res, out_dir, "prog__a", dag, ["workspace/work/src/a.c"])
    assert got["status"] == "analysis_error"
    assert got["reason"] == "address_flow_missing_global"
    assert got["missing_project_globals"] == [
        {"global": "g_cfg", "ids": ["src/cfg.c#g_cfg"], "files": ["src/cfg.c"]},
        {"global": "g_tbl", "ids": ["src/table.inc#g_tbl"], "files": ["src/table.c"]},
    ]
    assert len(got["error_summary"]) == 2
    assert any("g_cfg" in line and "src/cfg.c" in line for line in got["error_summary"])
    assert any("g_tbl" in line and "src/table.c" in line for line in got["error_summary"])


@pytest.mark.unit
@pytest.mark.parametrize(
    ("sources", "mirror_root"),
    [
        (["src/a.c", "src/cfg.c", "src/table.c"], None),
        (["/framac-run/workspace/work/src/a.c", "/target/src/cfg.c", "./src/table.c"], None),
        (["/tmp/m/workspace/work/src/a.c", "/tmp/m/src/cfg.c", "workspace/work/src/table.c"], "/tmp/m"),
    ],
)
def test_address_flow_gate_accepts_compiled_project_globals_under_normalized_paths(
    tmp_path: Path, sources: list[str], mirror_root: str | None
) -> None:
    dag = _write_address_flow_dag(tmp_path / "dag.json")
    out_dir = tmp_path / "eva"
    flows = {
        "status": "ok",
        "reason": None,
        "by_function": {
            "eva_main": {
                "inputs": ["g_cfg.magic", "g_present"],
                "operational_inputs": ["g_tbl{.cb; .len}"],
                "operational_inputs_on_termination": ["g_cfg[0]"],
            }
        },
        "call_edges": {},
    }
    res = _ok_result(out_dir, flows=flows, mirror_root=mirror_root)
    got = E.reject_address_flow_gaps(res, out_dir, "prog__a", dag, sources)
    assert got["status"] == "ok"
    assert got["reason"] is None
    assert "missing_project_globals" not in got


@pytest.mark.unit
def test_address_flow_gate_falls_back_to_all_functions_when_main_absent_and_preserves_precedence(
    tmp_path: Path,
) -> None:
    dag = _write_address_flow_dag(tmp_path / "dag.json")
    out_dir = tmp_path / "eva"
    log = "[kernel] Neither code nor specification for function lib_compute, generating default assigns.\n"
    flows = {
        "status": "ok",
        "reason": None,
        "by_function": {
            "api_a": {
                "operational_inputs_on_termination": ["g_cfg[0]"],
            }
        },
        "call_edges": {},
    }
    res = _ok_result(out_dir, log_text=log, flows=flows)
    res["error_summary"] = [f"existing error {i}" for i in range(25)]
    got = E.reject_address_flow_gaps(res, out_dir, "prog__a", dag, ["workspace/work/src/a.c"])
    assert got["status"] == "analysis_error"
    assert got["reason"] == "address_flow_missing_body"
    assert [b["function"] for b in got["missing_project_bodies"]] == ["lib_compute"]
    assert [g["global"] for g in got["missing_project_globals"]] == ["g_cfg"]
    assert len(got["error_summary"]) == 20
    assert "lib_compute" in got["error_summary"][0]
    assert "g_cfg" in got["error_summary"][1]


@pytest.mark.unit
@pytest.mark.parametrize("module_name", ["prog__cg", "prog", "unknown_mod", ""])
def test_address_flow_gate_leaves_non_address_flow_modules_untouched(tmp_path: Path, module_name: str) -> None:
    dag = _write_address_flow_dag(tmp_path / "dag.json")
    out_dir = tmp_path / "eva"
    log = "[kernel] Neither code nor specification for function lib_compute, generating default assigns.\n"
    flows = {
        "status": "ok",
        "reason": None,
        "by_function": {"eva_main": {"inputs": ["g_cfg", "g_tbl"]}},
        "call_edges": {},
    }
    res = _ok_result(out_dir, log_text=log, flows=flows)
    got = E.reject_address_flow_gaps(res, out_dir, module_name, dag, ["workspace/work/src/a.c"])
    assert got["status"] == "ok"
    assert got["reason"] is None
    assert "missing_project_bodies" not in got
    assert "missing_project_globals" not in got
    assert got["error_summary"] == []


@pytest.mark.unit
def test_address_flow_gate_preserves_existing_timeout_or_error_reason(tmp_path: Path) -> None:
    dag = _write_address_flow_dag(tmp_path / "dag.json")
    out_dir = tmp_path / "eva"
    log = "[kernel] Neither code nor specification for function lib_compute, generating default assigns.\n"
    res = _ok_result(out_dir, log_text=log)
    res["status"] = "analysis_timeout"
    res["reason"] = "timeout"
    got = E.reject_address_flow_gaps(res, out_dir, "prog__a", dag, ["workspace/work/src/a.c"])
    assert got["status"] == "analysis_timeout"
    assert got["reason"] == "timeout"
    assert [b["function"] for b in got["missing_project_bodies"]] == ["lib_compute"]


@pytest.mark.unit
def test_run_eva_on_slice_enforces_address_flow_gate_and_does_not_cache_downgraded_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FRAMAC_IMAGE_ID", "sha256:test-image")
    monkeypatch.delenv("FRAMAC_CACHE", raising=False)
    monkeypatch.delenv("FRAMAC_CACHE_MODE", raising=False)
    monkeypatch.delenv("FRAMAC_SHARED_CACHE_DIR", raising=False)
    (tmp_path / "run-metadata.json").write_text("{}\n", encoding="utf-8")
    src = tmp_path / "workspace" / "work" / "src" / "a.c"
    src.parent.mkdir(parents=True)
    src.write_text("int api_a(void) { return 0; }\n", encoding="utf-8")
    _write_address_flow_dag(tmp_path / "workspace" / "reports" / "callgraph_dag.json")

    calls: list[list[str]] = []

    def fake_execute(cmd, sources, main_fn, out_dir, reduced_checks, timeout, path_root=None, security_meta=None):
        calls.append(list(cmd))
        log = "[kernel] Neither code nor specification for function lib_compute, generating default assigns.\n"
        return _ok_result(out_dir, log_text=log)

    monkeypatch.setattr(E, "_execute_eva", fake_execute)
    monkeypatch.setattr(E, "_input_digest", lambda sources, flags: "d")
    monkeypatch.setattr(
        E.cache, "dependency_manifest", lambda sources, flags, runner=None: [("workspace/work/src/a.c", "h1")]
    )

    out_dir = tmp_path / "workspace" / "eva" / "prog__a"
    first = E.run_eva_on_slice(["workspace/work/src/a.c"], "eva_main", out_dir, module="prog__a")
    assert first["status"] == "analysis_error"
    assert first["reason"] == "address_flow_missing_body"
    assert first["cache"]["hit"] is False
    assert first["cache"]["key"] is not None

    # Because the gate rejected the run inside _exec, ok() returned False and nothing was cached.
    second = E.run_eva_on_slice(["workspace/work/src/a.c"], "eva_main", out_dir, module="prog__a")
    assert second["status"] == "analysis_error"
    assert second["cache"]["hit"] is False
    assert len(calls) == 2


@pytest.mark.unit
def test_main_enforces_address_flow_gate_and_exits_nonzero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_address_flow_dag(tmp_path / "workspace" / "reports" / "callgraph_dag.json")
    out_dir = tmp_path / "workspace" / "eva" / "prog__a"
    out_json = tmp_path / "workspace" / "reports" / "eva" / "prog__a.json"
    flows = {
        "status": "ok",
        "reason": None,
        "by_function": {"eva_main": {"inputs": ["g_tbl.cb"]}},
        "call_edges": {},
    }

    monkeypatch.setattr(E, "phase0_gate_reasons", lambda module: [])
    monkeypatch.setattr(E, "run_eva_on_slice", lambda **kw: _ok_result(out_dir, flows=flows))

    rc = E.main(
        [
            "--module",
            "prog__a",
            "--sources",
            "workspace/work/src/a.c",
            "--main",
            "eva_main",
            "--out-dir",
            str(out_dir),
            "--out-json",
            str(out_json),
        ]
    )
    assert rc == 1
    stdout_doc = json.loads(capsys.readouterr().out)
    disk_doc = json.loads(out_json.read_text(encoding="utf-8"))
    assert stdout_doc["status"] == "analysis_error"
    assert stdout_doc["reason"] == "address_flow_missing_global"
    assert stdout_doc["missing_project_globals"][0]["global"] == "g_tbl"
    assert disk_doc["status"] == "analysis_error"
    assert disk_doc["reason"] == "address_flow_missing_global"
    assert disk_doc["missing_project_globals"][0]["files"] == ["src/table.c"]
