"""Phase 0 never treats pipeline run output kept inside a target as target source."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import workspace_overlay
from build_callgraph_dag import build_dag, find_pipeline_output_dirs
from framac_common import PIPELINE_OUTPUT_MARKERS, is_pipeline_output_dir

API_H = "int api_parse(const unsigned char *buf, unsigned int len);\n"
API_C = '#include "api.h"\nint api_parse(const unsigned char *buf, unsigned int len) { return len > 0 ? buf[0] : 0; }\n'
# An annotated copy of the header, as a previous run's overlay would hold it.
OLD_H = "/*@ requires len < 4; */\nint api_parse(const unsigned char *buf, unsigned int len);\n"


def _target_with_results(tmp_path: Path, marker: str) -> Path:
    target = tmp_path / "target"
    (target / "include").mkdir(parents=True)
    (target / "src").mkdir()
    (target / "include" / "api.h").write_text(API_H, encoding="utf-8")
    (target / "src" / "api.c").write_text(API_C, encoding="utf-8")
    results = target / "run-1-results"
    old_work = results / "workspace" / "work"
    (old_work / "include").mkdir(parents=True)
    (old_work / "src").mkdir()
    (old_work / "include" / "api.h").write_text(OLD_H, encoding="utf-8")
    (old_work / "src" / "api.c").write_text(API_C, encoding="utf-8")
    (old_work / "src" / "harness_old.c").write_text("int old_harness(void) { return 0; }\n", encoding="utf-8")
    marker_dir = results / "workspace" if marker == "overlay_meta.json" else results
    (marker_dir / marker).write_text("{}", encoding="utf-8")
    return target


@pytest.mark.parametrize("marker", PIPELINE_OUTPUT_MARKERS)
def test_marker_identifies_pipeline_output(tmp_path, marker):
    (tmp_path / marker).write_text("{}", encoding="utf-8")
    assert is_pipeline_output_dir(tmp_path)
    assert not is_pipeline_output_dir(tmp_path / "missing")


@pytest.mark.parametrize("marker", PIPELINE_OUTPUT_MARKERS)
def test_dag_skips_results_folder_and_warns(tmp_path, marker):
    target = _target_with_results(tmp_path, marker)
    dag = build_dag(target)
    files = {rec["file"] for rec in dag["functions"].values()}
    assert files == {"src/api.c"}
    assert "old_harness" not in dag["functions"]
    for mod in dag["modules"].values():
        assert not any("run-1-results" in flag for flag in mod.get("cppflags") or [])
    skipped = "run-1-results" if marker != "overlay_meta.json" else "run-1-results/workspace"
    assert find_pipeline_output_dirs(target) == [skipped]
    assert any(skipped in w and "pipeline output" in w for w in dag["warnings"])


def test_overlay_does_not_copy_results_folder(tmp_path):
    target = _target_with_results(tmp_path, "run-metadata.json")
    overlay = tmp_path / "run" / "workspace"
    meta = workspace_overlay.init_overlay(target, overlay)
    assert meta["skipped_pipeline_output"] == ["run-1-results"]
    assert meta["copied_count"] == 2
    assert not (overlay / "work" / "run-1-results").exists()
    assert not (overlay / "baseline" / "run-1-results").exists()
    assert json.loads((overlay / "overlay_meta.json").read_text(encoding="utf-8"))["skipped_pipeline_output"] == [
        "run-1-results"
    ]
    # Resuming on the same target still works: skipped files never enter the stale-baseline check.
    workspace_overlay.init_overlay(target, overlay)
