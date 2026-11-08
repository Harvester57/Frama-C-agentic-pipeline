"""R5 follow-up: the Phase 0 producers record their own schema problems as warnings."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import harness_reach as hr
from validate_artifacts import SCHEMA_WARNING_PREFIX, recorded_schema_warnings

pytestmark = pytest.mark.unit


def _schema_warnings(path: Path) -> list[str]:
    return recorded_schema_warnings(json.loads(path.read_text(encoding="utf-8")))


def test_dynamic_reach_report_records_a_schema_problem(tmp_path: Path) -> None:
    out = tmp_path / "workspace/reports/harness_reach_dynamic.json"
    row = {"module": "m", "mode": "dynamic", "entry_points": 1, "entry_points_executed": 1}
    row |= {"executions": {"f": 3}, "gaps": [], "passed": True}
    good = {"generated_at": "2026-11-08T00:00:00+00:00", "modules": [row]}
    hr.record_dynamic(tmp_path, good, out)
    assert _schema_warnings(out) == []
    bad = {"generated_at": "2026-11-08T00:00:00+00:00", "modules": [{**row, "gaps": "f"}]}
    hr.record_dynamic(tmp_path, bad, out)
    warnings = _schema_warnings(out)
    assert len(warnings) == 1 and warnings[0].startswith(SCHEMA_WARNING_PREFIX)


def test_an_exemption_rewrites_the_sidecar_through_its_schema_check(tmp_path: Path) -> None:
    harnesses = tmp_path / "harnesses"
    harnesses.mkdir()
    sidecar = harnesses / "harness_m.json"
    sidecar.write_text(json.dumps({"module": "m"}), encoding="utf-8")  # lacks the generator's fields
    hr.record_exempt(harnesses, "m", "f", "OS entropy")
    data = json.loads(sidecar.read_text(encoding="utf-8"))
    assert data["reach_exempt"] == {"f": "OS entropy"}
    assert recorded_schema_warnings(data)
