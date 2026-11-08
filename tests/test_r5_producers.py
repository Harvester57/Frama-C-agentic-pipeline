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


def test_a_module_without_usable_coverage_is_recorded_as_unmeasured_until_it_is_measured(tmp_path: Path) -> None:
    # oscs-qlz (r2v): every input crashed, so the corpus stayed empty and the report said nothing.
    out = tmp_path / "workspace/reports/harness_reach_dynamic.json"
    lost = {"module": "m", "mode": "dynamic", "passed": None, "error": "no coverage (no_inputs)"}
    hr.record_dynamic(tmp_path, {"generated_at": "2026-11-08T00:00:00+00:00", "modules": [lost]}, out)
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["modules"] == {} and doc["unmeasured"] == {"m": "no coverage (no_inputs)"}
    assert _schema_warnings(out) == []
    row = {"module": "m", "mode": "dynamic", "entry_points": 1, "entry_points_executed": 1}
    row |= {"executions": {"f": 3}, "gaps": [], "passed": True}
    hr.record_dynamic(tmp_path, {"generated_at": "2026-11-08T00:00:01+00:00", "modules": [row]}, out)
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert "unmeasured" not in doc and doc["modules"]["m"]["passed"] is True


_RECORD_ONE = """
import sys
sys.path[:0] = [sys.argv[1]]
from pathlib import Path
import harness_reach as hr
run_dir, module = Path(sys.argv[2]), sys.argv[3]
passed = module.endswith(("0", "2", "4", "6"))
row = {"module": module, "mode": "dynamic", "entry_points": 1, "entry_points_executed": int(passed)}
row |= {"executions": {"f": int(passed)}, "gaps": [] if passed else ["f"], "passed": passed}
hr.record_dynamic(run_dir, {"generated_at": "2026-11-08T00:00:00+00:00", "modules": [row]},
                  run_dir / "workspace/reports/harness_reach_dynamic.json")
"""


def test_parallel_dynamic_checks_keep_every_modules_row(tmp_path: Path) -> None:
    # cryptolib (r2v): Make ran reach-dynamic-<m> in parallel and the report lost `sa`'s row.
    import subprocess
    import sys

    scripts = str(Path(hr.__file__).resolve().parent)
    modules = [f"m{i}" for i in range(8)]
    procs = [
        subprocess.Popen([sys.executable, "-c", _RECORD_ONE, scripts, str(tmp_path), m], cwd=tmp_path) for m in modules
    ]
    assert all(p.wait(timeout=120) == 0 for p in procs)
    doc = json.loads((tmp_path / "workspace/reports/harness_reach_dynamic.json").read_text(encoding="utf-8"))
    assert sorted(doc["modules"]) == modules
    gates = json.loads((tmp_path / "workspace/reports/phase0_gates.json").read_text(encoding="utf-8"))
    assert sorted(gates["reach"]["modules"]) == ["m1", "m3", "m5", "m7"]  # the failed ones reopen the gate


def test_an_exemption_rewrites_the_sidecar_through_its_schema_check(tmp_path: Path) -> None:
    harnesses = tmp_path / "harnesses"
    harnesses.mkdir()
    sidecar = harnesses / "harness_m.json"
    sidecar.write_text(json.dumps({"module": "m"}), encoding="utf-8")  # lacks the generator's fields
    hr.record_exempt(harnesses, "m", "f", "OS entropy")
    data = json.loads(sidecar.read_text(encoding="utf-8"))
    assert data["reach_exempt"] == {"f": "OS entropy"}
    assert recorded_schema_warnings(data)
