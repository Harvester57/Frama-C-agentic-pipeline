"""Unit tests for P3 smoke gate enforcement in scripts/phase0_gates.py."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import phase0_gates
import validate_artifacts

pytestmark = pytest.mark.unit


def _write_harness(run_dir: Path, module: str, body: str = "int LLVMFuzzerTestOneInput(void) { return 0; }\n") -> str:
    hdir = run_dir / "workspace" / "harnesses"
    hdir.mkdir(parents=True, exist_ok=True)
    sidecar = {"module": module, "entry_style": "dispatch", "dispatch_case_count": 4, "sources": ["src/a.c"]}
    (hdir / f"harness_{module}.json").write_text(json.dumps(sidecar, indent=2), encoding="utf-8")
    (hdir / f"harness_{module}.c").write_text(body, encoding="utf-8")
    digest = phase0_gates.harness_digest(run_dir, module, ignore_exempt=True)
    assert digest is not None
    return digest


def _smoke_report(
    module: str,
    digest: str | None,
    *,
    status: str = "ok",
    startup_ok: bool = True,
    quarantined_cases: list[int] | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    q = sorted(quarantined_cases or [])
    return {
        "schema_version": 1,
        "generated_at": "2026-11-22T12:00:00Z",
        "module": module,
        "harness_digest": digest,
        "entry_style": "dispatch",
        "dispatch_case_count": 4,
        "status": status,
        "startup": {
            "ok": startup_ok,
            "engines_checked": ["sanitizers"],
            "failing_engine": None if startup_ok else "sanitizers",
            "reason": reason,
            "stack_trace": None,
            "results": {},
        },
        "quarantined_cases": q,
        "candidate_warning_cases": [],
        "skip_cases_env": ",".join(str(c) for c in q),
        "case_results": [],
        "wall_s": 0.12,
    }


def test_record_smoke_stores_fields_and_merges_modules(tmp_path: Path) -> None:
    d_a = _write_harness(tmp_path, "mod_a")
    d_b = _write_harness(tmp_path, "mod_b")

    phase0_gates.record_smoke(tmp_path, "mod_a", _smoke_report("mod_a", d_a, status="ok", startup_ok=True))
    phase0_gates.record_smoke(
        tmp_path,
        "mod_b",
        _smoke_report("mod_b", d_b, status="degraded", startup_ok=True, quarantined_cases=[3, 1]),
    )

    gates = phase0_gates.load_gates(tmp_path)
    smoke = gates["smoke"]
    assert smoke["ok"] is True
    assert set(smoke["modules"]) == {"mod_a", "mod_b"}

    row_a = smoke["modules"]["mod_a"]
    assert row_a["ok"] is True
    assert row_a["status"] == "ok"
    assert row_a["startup_ok"] is True
    assert row_a["harness_digest"] == d_a
    assert row_a["quarantined_cases"] == []
    assert row_a["timestamp"]

    row_b = smoke["modules"]["mod_b"]
    assert row_b["ok"] is True
    assert row_b["status"] == "degraded"
    assert row_b["startup_ok"] is True
    assert row_b["harness_digest"] == d_b
    assert row_b["quarantined_cases"] == [1, 3]
    assert row_b["skip_cases_env"] == "1,3"
    assert row_b["timestamp"]

    # Stamp remains valid under validate_artifacts.validate_phase0_gates.
    assert not validate_artifacts.validate_phase0_gates(gates)


def test_check_smoke_missing_section_and_missing_module(tmp_path: Path) -> None:
    _write_harness(tmp_path, "mod_a")
    reasons = phase0_gates.check(tmp_path, "mod_a", need=["smoke"])
    assert len(reasons) == 1
    assert "smoke has not run" in reasons[0]

    d_a = _write_harness(tmp_path, "mod_a")
    phase0_gates.record_smoke(tmp_path, "mod_a", _smoke_report("mod_a", d_a))
    reasons_b = phase0_gates.check(tmp_path, "mod_b", need=["smoke"])
    assert len(reasons_b) == 1
    assert "mod_b was not checked" in reasons_b[0]


def test_check_smoke_ok_passes_cleanly(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    d_a = _write_harness(tmp_path, "mod_a")
    phase0_gates.record_smoke(tmp_path, "mod_a", _smoke_report("mod_a", d_a, status="ok", startup_ok=True))

    warnings_out: list[str] = []
    reasons = phase0_gates.check(tmp_path, "mod_a", need=["smoke"], warnings_out=warnings_out)
    assert reasons == []
    assert warnings_out == []
    assert capsys.readouterr().err == ""


def test_check_smoke_degraded_passes_with_warning_listing_quarantined_cases(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    d_a = _write_harness(tmp_path, "mod_a")
    phase0_gates.record_smoke(
        tmp_path,
        "mod_a",
        _smoke_report("mod_a", d_a, status="degraded", startup_ok=True, quarantined_cases=[0, 2]),
    )

    warnings_out: list[str] = []
    reasons = phase0_gates.check(tmp_path, "mod_a", need=["smoke"], warnings_out=warnings_out)
    assert reasons == []
    assert len(warnings_out) == 1
    assert "degraded" in warnings_out[0]
    assert "mod_a" in warnings_out[0]
    assert "[0, 2]" in warnings_out[0]

    # When warnings_out is omitted, check() prints the warning directly to stderr.
    reasons_stderr = phase0_gates.check(tmp_path, "mod_a", need=["smoke"])
    assert reasons_stderr == []
    err = capsys.readouterr().err
    assert "phase0 gate warning:" in err
    assert "[0, 2]" in err


@pytest.mark.parametrize(
    ("status", "startup_ok", "reason", "expected_substr"),
    [
        ("startup_error", False, "libfoo.so: cannot open shared object file", "startup_error"),
        ("failed", True, "all dispatch cases quarantined", "failed"),
        ("ok", False, "binary aborted during startup", "startup_error"),
        ("degraded", False, "eacsl startup aborted", "startup_error"),
    ],
)
def test_check_smoke_fails_on_bad_status_or_startup_false(
    tmp_path: Path,
    status: str,
    startup_ok: bool,
    reason: str,
    expected_substr: str,
) -> None:
    d_a = _write_harness(tmp_path, "mod_a")
    phase0_gates.record_smoke(
        tmp_path,
        "mod_a",
        _smoke_report("mod_a", d_a, status=status, startup_ok=startup_ok, reason=reason),
    )

    reasons = phase0_gates.check(tmp_path, "mod_a", need=["smoke"])
    assert len(reasons) == 1
    assert "mod_a" in reasons[0]
    assert expected_substr in reasons[0]
    assert reason in reasons[0]


def test_check_smoke_fails_on_stale_harness_digest(tmp_path: Path) -> None:
    d_a = _write_harness(tmp_path, "mod_a")
    phase0_gates.record_smoke(tmp_path, "mod_a", _smoke_report("mod_a", d_a, status="ok", startup_ok=True))
    assert phase0_gates.check(tmp_path, "mod_a", need=["smoke"]) == []

    # Modifying harness_<mod>.c changes the digest and makes the smoke stamp stale.
    (tmp_path / "workspace" / "harnesses" / "harness_mod_a.c").write_text(
        "int LLVMFuzzerTestOneInput(void) { return 1; }\n", encoding="utf-8"
    )
    reasons = phase0_gates.check(tmp_path, "mod_a", need=["smoke"])
    assert len(reasons) == 1
    assert "stale harness_digest" in reasons[0]
    assert "mod_a" in reasons[0]

    # Modifying harness_<mod>.json (non-exempt fields) also invalidates the digest.
    d_new = phase0_gates.harness_digest(tmp_path, "mod_a", ignore_exempt=True)
    phase0_gates.record_smoke(tmp_path, "mod_a", _smoke_report("mod_a", d_new, status="ok", startup_ok=True))
    assert phase0_gates.check(tmp_path, "mod_a", need=["smoke"]) == []

    sidecar_path = tmp_path / "workspace" / "harnesses" / "harness_mod_a.json"
    sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
    sidecar["dispatch_case_count"] = 8
    sidecar_path.write_text(json.dumps(sidecar), encoding="utf-8")
    reasons_json = phase0_gates.check(tmp_path, "mod_a", need=["smoke"])
    assert len(reasons_json) == 1
    assert "stale harness_digest" in reasons_json[0]


def test_check_without_smoke_in_need_is_100_percent_backwards_compatible(tmp_path: Path) -> None:
    d_a = _write_harness(tmp_path, "mod_a")
    phase0_gates.record_reach(tmp_path, {"modules": [{"module": "mod_a", "passed": True, "gaps": []}]})
    phase0_gates.record_build_check(tmp_path, {"ok": True, "modules": {"mod_a": {"ok": True, "status": "eacsl"}}})

    # Even with no smoke section at all, default check(run_dir, "mod_a") passes.
    assert phase0_gates.check(tmp_path, "mod_a") == []

    # Even with a FAILED smoke record, checks that do not request "smoke" still pass.
    phase0_gates.record_smoke(
        tmp_path,
        "mod_a",
        _smoke_report("mod_a", d_a, status="startup_error", startup_ok=False, reason="loader error"),
    )
    assert phase0_gates.check(tmp_path, "mod_a") == []
    assert phase0_gates.check(tmp_path, "mod_a", need=("reach", "build_check")) == []
    assert phase0_gates.check(tmp_path, None, need=("reach", "build_check")) == []

    # Requesting "smoke" catches the failure.
    assert phase0_gates.check(tmp_path, "mod_a", need=["reach", "build_check", "smoke"]) != []


def test_cli_record_smoke_and_check_smoke(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    d_a = _write_harness(tmp_path, "mod_a")
    report_path = tmp_path / "workspace" / "reports" / "smoke" / "mod_a.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(_smoke_report("mod_a", d_a, status="degraded", startup_ok=True, quarantined_cases=[2])),
        encoding="utf-8",
    )

    rc_rec = phase0_gates.main(
        ["record-smoke", "--run-dir", str(tmp_path), "--module", "mod_a", "--report", str(report_path)]
    )
    assert rc_rec == 0
    rec_out = json.loads(capsys.readouterr().out)
    assert rec_out["ok"] is True
    assert rec_out["module"] == "mod_a"
    assert rec_out["smoke"]["status"] == "degraded"
    assert rec_out["smoke"]["quarantined_cases"] == [2]

    rc_chk = phase0_gates.main(["check", "--run-dir", str(tmp_path), "--module", "mod_a", "--need", "smoke"])
    assert rc_chk == 0
    cap = capsys.readouterr()
    chk_out = json.loads(cap.out)
    assert chk_out["ok"] is True
    assert chk_out["reasons"] == []
    assert len(chk_out["warnings"]) == 1
    assert "[2]" in chk_out["warnings"][0]
    assert "phase0 gate warning:" in cap.err

    # Recording a failed smoke report succeeds (rc=0) and causes `check --need smoke` to fail (rc=1).
    report_path.write_text(
        json.dumps(_smoke_report("mod_a", d_a, status="startup_error", startup_ok=False, reason="missing symbol")),
        encoding="utf-8",
    )
    assert (
        phase0_gates.main(
            ["record-smoke", "--run-dir", str(tmp_path), "--module", "mod_a", "--report", str(report_path)]
        )
        == 0
    )
    rec_fail = json.loads(capsys.readouterr().out)
    assert rec_fail["ok"] is False

    assert phase0_gates.main(["check", "--run-dir", str(tmp_path), "--module", "mod_a", "--need", "smoke"]) == 1
    cap_fail = capsys.readouterr()
    chk_fail = json.loads(cap_fail.out)
    assert chk_fail["ok"] is False
    assert any("startup_error" in r for r in chk_fail["reasons"])
    assert "phase0 gate:" in cap_fail.err


def test_cli_record_smoke_missing_report_returns_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc = phase0_gates.main(
        [
            "record-smoke",
            "--run-dir",
            str(tmp_path),
            "--module",
            "mod_a",
            "--report",
            str(tmp_path / "nonexistent.json"),
        ]
    )
    assert rc == 1
    cap = capsys.readouterr()
    out = json.loads(cap.out)
    assert out["ok"] is False
    assert "cannot record smoke report" in out["error"]
    assert "phase0 gate:" in cap.err


def test_whole_run_smoke_check_enforces_fuzzed_expected(tmp_path: Path) -> None:
    d_a = _write_harness(tmp_path, "mod_a")
    phase0_gates.record_smoke(tmp_path, "mod_a", _smoke_report("mod_a", d_a, status="ok", startup_ok=True))

    assert phase0_gates.check(tmp_path, None, need=["smoke"], fuzzed_expected=["mod_a"]) == []
    reasons = phase0_gates.check(tmp_path, None, need=["smoke"], fuzzed_expected=["mod_a", "mod_b"])
    assert len(reasons) == 1
    assert "mod_b not checked" in reasons[0]
