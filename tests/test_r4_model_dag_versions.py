"""
Remediation step R4 (docs/phase0-remediation-plan.md): model, DAG and versions. `no_unit_parsed` in the
checkpoint, GCC paths resolved against the compile's directory, the model's version 2 and
`model_features`, the DAG's feature warnings and `schema_version`, and the report's fallback section.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

import build_callgraph_dag as bcd
import checkpoint
import generate_report as gr
import phase0_model as pm

pytestmark = pytest.mark.unit

TREE = "/framac-scratch/tree"


# ---------------------------------------------------------------------------------------------------
# no_unit_parsed in the checkpoint
# ---------------------------------------------------------------------------------------------------


def _unparsable_capture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    tree = tmp_path / "tree"
    (tree / "src").mkdir(parents=True)
    (tree / "src" / "a.c").write_text("int f(void) { return 0; }\n", encoding="utf-8")
    capture = {
        "status": "ok",
        "scratch": {"tree": str(tree)},
        "compiles": [{"source": "src/a.c", "object": "a.o", "flags": [], "system_flags": []}],
        "units": {
            "liba.a": {"kind": "static_lib", "test": False, "objects": ["a.o"], "files": ["src/a.c"], "links": []}
        },
    }
    cap = tmp_path / "cap.json"
    cap.write_text(json.dumps(capture), encoding="utf-8")
    monkeypatch.setattr(pm, "compile_dump_module", lambda *a, **k: (tmp_path / "dump.cmxs", ""))
    monkeypatch.setattr(pm, "macro_aliases", lambda *a, **k: [])
    monkeypatch.setattr(
        pm,
        "framac_parse",
        lambda *a, **k: {"status": "parse_failed", "error": "src/a.c:1: syntax error", "seconds": 0.1},
    )
    monkeypatch.setattr(
        pm,
        "gcc_callgraph",
        lambda *a, **k: {"status": "ok", "errors": [], "functions": {}, "edges": [], "indirect": []},
    )
    return cap


def test_no_unit_parsed_blocks_the_checkpoint_and_a_resume_shows_the_unit_errors(tmp_path, monkeypatch, capsys):
    cap = _unparsable_capture(tmp_path, monkeypatch)
    state = tmp_path / "state"
    checkpoint.cmd_init(state, "/target", "verify")
    capsys.readouterr()
    out = tmp_path / "model.json"
    rc = pm.main(["run", "--capture", str(cap), "--out", str(out), "--no-broker", "--state", str(state)])
    assert rc == pm.NO_UNIT_PARSED_RC
    progress = json.loads((state / "progress.json").read_text(encoding="utf-8"))
    assert progress["status"] == "no_unit_parsed" and progress["phase_done"] == -1
    blocked = progress["blocked"]
    assert blocked["resume_at"] == "phase0_model.py run"
    assert blocked["units"] == {"liba.a": "src/a.c:1: syntax error"}
    assert blocked["report"] == str(out)
    capsys.readouterr()

    # The resume reads the checkpoint: it shows the status, where it restarts and each unit's error.
    checkpoint.cmd_load(state)
    err = capsys.readouterr().err
    assert "no_unit_parsed" in err and "phase0_model.py run" in err and "liba.a: src/a.c:1: syntax error" in err

    # A model that parses clears the status; phase_done is still the step's to advance.
    pm.record_checkpoint(state, {"status": "ok"}, out)
    progress = json.loads((state / "progress.json").read_text(encoding="utf-8"))
    assert progress["status"] == "running" and "blocked" not in progress and progress["phase_done"] == -1


def test_an_empty_state_leaves_the_checkpoint_alone(tmp_path, monkeypatch):
    cap = _unparsable_capture(tmp_path, monkeypatch)
    monkeypatch.chdir(tmp_path)
    rc = pm.main(["run", "--capture", str(cap), "--out", str(tmp_path / "m.json"), "--no-broker", "--state", ""])
    assert rc == pm.NO_UNIT_PARSED_RC and not (tmp_path / "state").exists()


def test_the_build_capture_block_names_its_step():
    assert checkpoint.BLOCKING_STEPS["needs_build_recipe"] == "build_capture.py run"
    assert checkpoint.blocked_lines({"status": "running"}) == []


# ---------------------------------------------------------------------------------------------------
# GCC paths from a subdirectory compile
# ---------------------------------------------------------------------------------------------------


def test_gcc_paths_resolve_against_the_compile_directory_then_the_tree(tmp_path):
    # Compiled from src/ with -I../include: GCC prints the header relative to src/.
    ci = (
        'node: { title: "nest_sum" label: "nest_sum\\n/framac-scratch/tree/src/nest.c:4:5" }\n'
        'node: { title: "clamp" label: "clamp\\n../include/api.h:12:19" }\n'
        'node: { title: "local" label: "local\\nnest_util.h:3:1" }\n'
        'edge: { sourcename: "nest_sum" targetname: "clamp" }\n'
    )
    seen: dict = {}

    def fake_run(cmd, **kw):
        seen["cwd"] = kw.get("cwd")
        Path(f"{cmd[cmd.index('-dumpbase') + 1]}.ci").write_text(ci, encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    job = {
        "key": "k",
        "compiles": [{"source": "src/nest.c", "cwd": "src", "arguments": ["cc", "-I../include", "-c", "nest.c"],
                      "flags": ["-I", "include"], "system_flags": []}],
    }  # fmt: skip
    g = pm.gcc_callgraph(job, TREE, None, tmp_path, runner=fake_run)
    assert seen["cwd"] == f"{TREE}/src"
    assert set(g["functions"]) == {"src/nest.c#nest_sum", "include/api.h#clamp", "src/nest_util.h#local"}
    assert ("src/nest.c#nest_sum", "include/api.h#clamp", "clamp") in g["edges"]


def test_tree_rel_prefers_an_existing_file_and_falls_back_to_the_tree(tmp_path):
    tree = tmp_path.as_posix()
    (tmp_path / "include").mkdir()
    (tmp_path / "include" / "api.h").write_text("", encoding="utf-8")
    sub = f"{tree}/src"
    # Relative to the compile's directory, outside the tree: the tree resolves it.
    assert pm.tree_rel("include/api.h", tree, sub) == "include/api.h"
    assert pm.tree_rel("../include/api.h", tree, sub) == "include/api.h"
    assert pm.tree_rel("../../elsewhere.h", tree, sub) is None
    assert pm.tree_rel("x.h", tree) == "x.h"


def test_macro_alias_line_markers_resolve_against_the_compile_directory():
    text = '# 1 "../include/api.h"\n#define crypto_hash crypto_hash_tweet\n'
    assert pm.parse_defines(text, TREE, f"{TREE}/src") == [
        {"alias": "crypto_hash", "value": "crypto_hash_tweet", "file": "include/api.h"}
    ]
    # Without the directory the path leaves the tree, and the define is not the project's.
    assert pm.parse_defines(text, TREE) == []


# ---------------------------------------------------------------------------------------------------
# Versions: model_features and the DAG
# ---------------------------------------------------------------------------------------------------


def _model_fn(file: str, name: str, **kw: object) -> dict:
    rec = {
        "file": file,
        "name": name,
        "line": 1,
        "end_line": 3,
        "lines": 3,
        "static": False,
        "inline": False,
        "header": False,
        "signature": "int(void *, unsigned long)",
        "loops": 0,
        "cyclomatic": 1,
        "address_taken": False,
        "source": "frama-c-kernel",
        "units": ["liba.a"],
    }
    rec.update(kw)
    return rec


def _v1_model() -> dict:
    """A model from before steps I7 and I9: no external calls, formals, writes, trust or kernel names."""
    return {
        "schema_version": 1,
        "status": "ok",
        "units": {"liba.a": {"kind": "static_lib", "test": False, "files": ["src/a.c"], "links": [],
                             "parse": {"status": "ok"}, "concurrent": False, "entry_points": ["src/a.c#grow"]}},
        "functions": {"src/a.c#grow": _model_fn("src/a.c", "grow")},
        "edges": [],
        "entry_points": ["src/a.c#grow"],
    }  # fmt: skip


def _v2_model() -> dict:
    model = _v1_model()
    model["schema_version"] = pm.SCHEMA_VERSION
    model["functions"]["src/a.c#grow"].update(
        external_calls=["malloc"],
        kernel_names={"liba.a": "grow"},
        formals=[{"name": "p", "kind": "pointer"}, {"name": "n", "kind": "value"}],
        writes={"pointer": 1, "params": ["p"], "globals": []},
        trust={"value": "untrusted", "source": "default", "sources": ["default"], "boundary": True, "reasons": []},
    )
    return model


def test_model_schema_version_is_2_and_both_versions_validate():
    assert pm.SCHEMA_VERSION == 2
    base = {"generated_at": "t", "status": "error", "capture": "c", "warnings": []}
    assert not pm.validate_model({**base, "schema_version": 2})
    assert not pm.validate_model({**base, "schema_version": 1})
    assert pm.validate_model({**base, "schema_version": 3})


def test_model_features_read_a_version_1_model_by_its_fields():
    assert pm.missing_features(_v1_model()) == [
        "external_calls",
        "formals",
        "writes",
        "trust",
        "kernel_names",
        "param_sizes",
    ]
    old = _v1_model()
    old["functions"]["src/a.c#grow"].update(
        external_calls=[], kernel_names={}, param_sizes={"0": {"min": 1, "max": 1, "sites": 1}}
    )
    old["trust"] = {"threat_model": {"status": "no_threat_model"}}
    assert pm.missing_features(old) == ["formals", "writes"]
    # A GCC-fallback function never has formals or writes: it does not count for them.
    old["functions"]["src/b.c#gcc"] = _model_fn("src/b.c", "gcc", source="gcc-callgraph-info", formals=[])
    assert pm.missing_features(old) == ["formals", "writes"]


def test_model_features_of_a_version_2_model_and_of_no_model():
    feats = pm.model_features(_v2_model())
    assert set(feats) == set(pm.MODEL_FEATURES) and all(feats.values())
    untrusted = _v2_model()
    del untrusted["functions"]["src/a.c#grow"]["trust"]
    assert pm.missing_features(untrusted) == ["trust"]
    assert pm.missing_features(None) == list(pm.MODEL_FEATURES)
    assert pm.missing_features({"schema_version": 2, "functions": {}}) == list(pm.MODEL_FEATURES)


def test_a_model_without_external_calls_gives_a_dag_warning_instead_of_silently_dropping_facts(tmp_path):
    dag = bcd.build_dag(tmp_path, _v1_model())
    warnings = [w for w in dag["warnings"] if w.startswith("model (schema_version 1)")]
    assert any("dynamic_allocation" in w and "Tier 2" in w and "format/write" in w for w in warnings)
    assert dag["model"]["schema_version"] == 1
    assert dag["model"]["missing_features"][0] == "external_calls"
    grow = dag["functions"]["grow"]
    assert grow["has_dynamic_alloc"] is False  # unknown, not known false: the warning says so

    current = bcd.build_dag(tmp_path, _v2_model())
    assert not [w for w in current["warnings"] if w.startswith("model (")]
    assert current["model"]["missing_features"] == []
    assert "dynamic_allocation" in current["functions"]["grow"]["wp_blockers"]


def test_the_dag_records_its_schema_version_and_drops_unread_module_fields(tmp_path):
    dag = bcd.build_dag(tmp_path, _v2_model())
    assert dag["schema_version"] == bcd.DAG_SCHEMA_VERSION
    mod = dag["modules"]["liba_a"]
    assert "provable_functions" not in mod and "shell_unverifiable_functions" not in mod
    assert not {"cross_module_callees", "entry_trust"} & set(mod)
    assert "indirect_callees" not in dag["functions"]["grow"]
    # A DAG that never went through block_fallback_units (held modules) has no version.
    assert "schema_version" not in bcd.build_dag(tmp_path, _v2_model(), units=False)
    assert bcd.block_fallback_units({"modules": {}})["schema_version"] == bcd.DAG_SCHEMA_VERSION


# ---------------------------------------------------------------------------------------------------
# The report: fallback units and the old classes
# ---------------------------------------------------------------------------------------------------


def _fallback_model() -> dict:
    return {
        "units": {
            "liba.a": {"kind": "static_lib", "test": False, "parse": {"status": "ok"}},
            "libb.a": {"kind": "static_lib", "test": False,
                       "parse": {"status": "gcc_fallback", "error": "src/b.c:3: syntax error | bad"}},
            "tests": {"kind": "executable", "test": True, "parse": {"status": "skipped_test"}},
        },
        "functions": {
            "src/a.c#fa": {"file": "src/a.c", "name": "fa", "units": ["liba.a"]},
            "src/b.c#fb": {"file": "src/b.c", "name": "fb", "units": ["libb.a"]},
            "src/b.c#gb": {"file": "src/b.c", "name": "gb", "units": ["libb.a"]},
        },
    }  # fmt: skip


def _unit(function: str, cls: str, status: str, reason: str | None) -> dict:
    return {
        "coverage_id": f"src/b.c#{function}:{cls}",
        "file": "src/b.c",
        "function": function,
        "module": "libb_a",
        "obligation_class": cls,
        "status": status,
        "assumptions": [],
        "evidence": [],
        "unresolved": [reason] if reason else [],
    }


def test_the_report_lists_a_fallback_unit_with_its_error_and_what_was_deferred():
    ledger = [
        _unit("fb", "rte", "deferred", "callgraph_fallback: Frama-C cannot parse its link unit"),
        _unit("gb", "rte", "deferred", "callgraph_fallback: Frama-C cannot parse its link unit"),
        _unit("fb", "l2_termination", "deferred", "callgraph_fallback: Frama-C cannot parse its link unit"),
        _unit("gb", "l3_frame", "deferred", "tier3_not_scheduled: x"),
    ]
    lines = gr.fallback_lines(_fallback_model(), ledger)
    text = "\n".join(lines)
    assert lines[0] == "### Phase 0 parse"
    row = next(line for line in lines if line.startswith("| `libb.a`"))
    assert "src/b.c:3: syntax error \\| bad" in row and "| 2 |" in row
    assert "1 `l2_termination`, 2 `rte`" in row and "l3_frame" not in row
    assert "liba.a" not in text and "Alias" not in text


def test_the_report_has_no_parse_section_without_a_fallback_and_summarizes_alias():
    model = _fallback_model()
    model["units"]["libb.a"]["parse"] = {"status": "ok"}
    assert gr.fallback_lines(model, []) == []
    assert gr.fallback_lines(None, []) == []
    model["alias"] = {"enabled": True, "module": "ok", "sites": {"alias": 3, "no_targets": 1}, "dropped_candidates": 5}
    text = "\n".join(gr.fallback_lines(model, []))
    assert "Alias narrowing" in text and "3 alias, 1 no_targets" in text and "5 type-match" in text


def test_the_report_renders_the_fallback_section_next_to_the_trust_table():
    meta: dict[str, Any] = {
        "run_id": "r1",
        "repo": "x",
        "target": "/target",
        "run_status": "complete",
        "incomplete_reason": None,
        "source_ref": {"vcs": "git", "commit": None},
        "profile": "standard",
        "scope_paths": [],
        "budget": None,
        "sandbox": {"outer": "docker", "inner": "none"},
        "prior_runs": [],
    }
    ledger = [_unit("fb", "rte", "deferred", "callgraph_fallback: Frama-C cannot parse its link unit")]
    data = {
        "meta": meta,
        "ledger": ledger,
        "findings": [],
        "candidates": [],
        "run_dir": None,
        "model": _fallback_model(),
    }
    report = gr.render_report(data)
    assert "### Phase 0 parse" in report and "`libb.a`" in report
    assert report.index("### Phase 0 parse") < report.index("## 2. Summary")


def test_the_report_drops_the_pre_i9_classes():
    assert not {"l4_auth", "l5_output", "l6_secret"} & set(gr.CLASSES)
    assert {"l4_auth_state", "l4_auth_required", "l5_sanitized", "l6_wiped", "l6_no_leak"} <= set(gr.CLASSES)
