"""Unit and mock-runner tests for Wave 1 Track 2B: per-case health probe in harness_smoke.py."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import harness_smoke as HS
import minischema
import sandbox_exec
from sandbox_exec import SandboxResult

pytestmark = pytest.mark.unit

_PROBE_SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "smoke_probe.schema.json"
_PROBE_SCHEMA = minischema.load_schema(_PROBE_SCHEMA_PATH)

_LOG_NULL_MEMBER_UBSAN = """\
Running: {probe_path}
src/ctx.c:42:12: runtime error: member access within null pointer of type 'struct ctx_t'
    #0 0x55551000 in ctx_process src/ctx.c:42:12
    #1 0x55551100 in LLVMFuzzerTestOneInput workspace/harnesses/harness_demo.c:180:5
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior src/ctx.c:42:12
"""


def _write_sidecar(
    tmp_path: Path,
    module: str,
    *,
    dispatch_case_count: int = 4,
    api_cases: list[dict[str, Any]] | None = None,
) -> Path:
    hdir = tmp_path / "workspace" / "harnesses"
    hdir.mkdir(parents=True, exist_ok=True)
    sidecar: dict[str, Any] = {
        "module": module,
        "harness_file": f"workspace/harnesses/harness_{module}.c",
        "sources": ["src/demo.c"],
        "cppflags": "-I.",
        "entry_fn": "fuzz_entry",
        "entry_style": "dispatch",
        "dispatch_case_count": dispatch_case_count,
        "dispatch_cases": [f"case_{k}();" for k in range(dispatch_case_count)],
        "dispatch_selector": "identity",
    }
    if api_cases is not None:
        sidecar["api_cases"] = api_cases
    sidecar_path = hdir / f"harness_{module}.json"
    sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")
    (hdir / f"harness_{module}.c").write_text("/* synthetic harness */\n", encoding="utf-8")
    return sidecar_path


def _make_fake_bin(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\x7fELFfake")
    return path


def _extract_probe_paths(argv: list[str]) -> list[Path]:
    return [Path(a) for a in argv[1:] if not a.startswith("-")]


# ---------------------------------------------------------------------------
# Feature flag tests (Contract 2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "val,expected",
    [
        (None, False),
        ("", False),
        ("off", False),
        ("0", False),
        ("false", False),
        ("no", False),
        ("on", True),
        ("ON", True),
        (" 1 ", True),
        ("true", True),
        ("True", True),
        ("yes", True),
        ("YES", True),
    ],
)
def test_harness_probe_enabled_flag(monkeypatch, val, expected):
    if val is None:
        monkeypatch.delenv("FRAMAC_HARNESS_PROBE", raising=False)
    else:
        monkeypatch.setenv("FRAMAC_HARNESS_PROBE", val)
    assert HS.harness_probe_enabled() is expected


# ---------------------------------------------------------------------------
# Schema validation tests (Contract 1 + probe summary block)
# ---------------------------------------------------------------------------


def test_smoke_probe_schema_validates_contract1_and_summary():
    telemetry = {
        "schema_version": 1,
        "cases": {
            "0": {"runs": 64, "init_fail": 0, "ret_kind": "i64", "unique_overflow": False, "unique_vals": [0, 14]},
            "7": {"runs": 64, "init_fail": 0, "ret_kind": "i64", "unique_overflow": False, "unique_vals": [27]},
            "12": {"runs": 64, "init_fail": 64, "ret_kind": "void", "unique_overflow": False, "unique_vals": []},
        },
    }
    assert minischema.validate(telemetry, _PROBE_SCHEMA) == []

    summary = {
        "enabled": True,
        "probe_secs": 5,
        "summary_counts": {
            "never_reached": 1,
            "init_always_fails": 1,
            "constant_return": 1,
            "low_samples": 1,
            "healthy": 2,
        },
        "flagged_cases": [
            {
                "case": 7,
                "entry": "src/api.c::get_in_map",
                "status": "constant_return",
                "runs": 64,
                "init_fail": 0,
                "ret_kind": "i64",
                "constant_value": 27,
            },
            {
                "case": 12,
                "entry": None,
                "status": "init_always_fails",
                "runs": 64,
                "init_fail": 64,
                "ret_kind": "void",
                "constant_value": None,
            },
        ],
    }
    assert minischema.validate(summary, _PROBE_SCHEMA) == []

    bad_telemetry = {
        "schema_version": 1,
        "cases": {
            "0": {
                "runs": 10,
                "init_fail": 0,
                "ret_kind": "float",
                "unique_overflow": False,
                "unique_vals": [],
            }
        },
    }
    assert minischema.validate(bad_telemetry, _PROBE_SCHEMA)

    too_many_vals = {
        "schema_version": 1,
        "cases": {
            "0": {
                "runs": 10,
                "init_fail": 0,
                "ret_kind": "i64",
                "unique_overflow": True,
                "unique_vals": list(range(9)),
            }
        },
    }
    assert minischema.validate(too_many_vals, _PROBE_SCHEMA)

    bad_flagged_status = {
        **summary,
        "flagged_cases": [
            {
                "case": 0,
                "entry": "ok_fn",
                "status": "healthy",
                "runs": 64,
                "init_fail": 0,
                "ret_kind": "i64",
                "constant_value": None,
            }
        ],
    }
    assert minischema.validate(bad_flagged_status, _PROBE_SCHEMA)


# ---------------------------------------------------------------------------
# Pure classification tests: classify_probe_cases()
# ---------------------------------------------------------------------------


def test_classify_probe_cases_all_five_states_and_unique_overflow():
    probe_data = {
        "schema_version": 1,
        "cases": {
            # case 0: omitted -> never_reached
            # case 1: init_fail == runs -> init_always_fails
            "1": {"runs": 64, "init_fail": 64, "ret_kind": "void", "unique_overflow": False, "unique_vals": []},
            # case 2: runs >= 20, i64, single unique value -> constant_return (27)
            "2": {"runs": 64, "init_fail": 0, "ret_kind": "i64", "unique_overflow": False, "unique_vals": [27]},
            # case 3: runs >= 20, ptr, single unique value (0 = NULL) -> constant_return (0)
            "3": {"runs": 20, "init_fail": 0, "ret_kind": "ptr", "unique_overflow": False, "unique_vals": [0]},
            # case 4: 0 < runs < 20 and len(unique_vals) <= 1 -> low_samples
            "4": {"runs": 19, "init_fail": 0, "ret_kind": "i64", "unique_overflow": False, "unique_vals": [27]},
            # case 5: multiple unique_vals -> healthy
            "5": {"runs": 64, "init_fail": 0, "ret_kind": "i64", "unique_overflow": False, "unique_vals": [0, 14]},
            # case 6: unique_overflow=True -> healthy even if unique_vals has 8 entries (or 1)
            "6": {
                "runs": 64,
                "init_fail": 0,
                "ret_kind": "i64",
                "unique_overflow": True,
                "unique_vals": [0, 1, 2, 3, 4, 5, 6, 7],
            },
            # case 7: void with runs >= 20 and init_fail < runs -> healthy
            "7": {"runs": 30, "init_fail": 2, "ret_kind": "void", "unique_overflow": False, "unique_vals": []},
            # case 8: quarantined -> excluded from counts and flagged_cases
            "8": {"runs": 0, "init_fail": 0, "ret_kind": "void", "unique_overflow": False, "unique_vals": []},
            # case 9: unique_overflow=True with len(unique_vals)==1 -> still healthy (not constant_return)
            "9": {"runs": 50, "init_fail": 0, "ret_kind": "i64", "unique_overflow": True, "unique_vals": [1]},
        },
    }
    entry_map = {
        0: "src/a.c::unreached_fn",
        1: "src/a.c::bad_init_fn",
        2: "src/a.c::const_err_fn",
        3: "src/a.c::null_ptr_fn",
        4: "src/a.c::under_sampled_fn",
        5: "src/a.c::healthy_multi_fn",
        6: "src/a.c::healthy_overflow_fn",
        7: "src/a.c::healthy_void_fn",
        8: "src/a.c::quarantined_fn",
        9: "src/a.c::overflow_single_fn",
    }

    result = HS.classify_probe_cases(
        probe_data,
        n_cases=10,
        quarantined_cases=[8],
        entry_map=entry_map,
    )

    assert result["case_classifications"] == {
        0: "never_reached",
        1: "init_always_fails",
        2: "constant_return",
        3: "constant_return",
        4: "low_samples",
        5: "healthy",
        6: "healthy",
        7: "healthy",
        9: "healthy",
    }
    assert result["summary_counts"] == {
        "never_reached": 1,
        "init_always_fails": 1,
        "constant_return": 2,
        "low_samples": 1,
        "healthy": 4,
    }
    assert result["flagged_cases"] == [
        {
            "case": 0,
            "entry": "src/a.c::unreached_fn",
            "status": "never_reached",
            "runs": 0,
            "init_fail": 0,
            "ret_kind": "void",
            "constant_value": None,
        },
        {
            "case": 1,
            "entry": "src/a.c::bad_init_fn",
            "status": "init_always_fails",
            "runs": 64,
            "init_fail": 64,
            "ret_kind": "void",
            "constant_value": None,
        },
        {
            "case": 2,
            "entry": "src/a.c::const_err_fn",
            "status": "constant_return",
            "runs": 64,
            "init_fail": 0,
            "ret_kind": "i64",
            "constant_value": 27,
        },
        {
            "case": 3,
            "entry": "src/a.c::null_ptr_fn",
            "status": "constant_return",
            "runs": 20,
            "init_fail": 0,
            "ret_kind": "ptr",
            "constant_value": 0,
        },
    ]

    summary = {
        "enabled": True,
        "probe_secs": 5,
        "summary_counts": result["summary_counts"],
        "flagged_cases": result["flagged_cases"],
    }
    assert minischema.validate(summary, _PROBE_SCHEMA) == []


# ---------------------------------------------------------------------------
# End-to-end mock-runner tests: run_smoke() with FRAMAC_HARNESS_PROBE off vs on
# ---------------------------------------------------------------------------


def test_run_smoke_probe_off_skips_probe_and_omits_block(tmp_path, monkeypatch):
    monkeypatch.delenv("FRAMAC_HARNESS_PROBE", raising=False)
    sidecar = _write_sidecar(tmp_path, "mod_probe_off", dispatch_case_count=3)
    san_bin = _make_fake_bin(tmp_path / "fuzz_mod_probe_off.san")
    out_json = tmp_path / "smoke_off.json"
    probe_env_seen: list[str] = []

    def fake_run(argv, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        if extra_env and "FRAMAC_PROBE_OUT" in extra_env:
            probe_env_seen.append(extra_env["FRAMAC_PROBE_OUT"])
        return SandboxResult(returncode=0, stdout="", stderr="", timed_out=False, sandbox="rlimits", command=list(argv))

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_run)
    report, rc = HS.run_smoke(
        module="mod_probe_off",
        sidecar_path=sidecar,
        out_json=out_json,
        san_bin=san_bin,
    )

    assert rc == 0
    assert report["status"] == "ok"
    assert "probe" not in report
    assert probe_env_seen == []


def test_run_smoke_probe_on_skips_quarantined_and_keeps_exit_code(tmp_path, monkeypatch):
    monkeypatch.setenv("FRAMAC_HARNESS_PROBE", "on")
    api_cases = [
        {"selector": 0, "kind": "single", "calls": ["api_ok"], "slots": [], "rest": None, "entry": "src/a.c::api_ok"},
        {
            "selector": 1,
            "kind": "single",
            "calls": ["ctx_process"],
            "slots": [],
            "rest": None,
            "entry": "src/ctx.c::ctx_process",
        },
        {
            "selector": 2,
            "kind": "single",
            "calls": ["get_in_map"],
            "slots": [],
            "rest": None,
            "entry": "src/map.c::get_in_map",
        },
        {
            "selector": 3,
            "kind": "single",
            "calls": ["bad_init"],
            "slots": [],
            "rest": None,
            "entry": "src/init.c::bad_init",
        },
    ]
    sidecar = _write_sidecar(tmp_path, "mod_probe_on", dispatch_case_count=4, api_cases=api_cases)
    san_bin = _make_fake_bin(tmp_path / "fuzz_mod_probe_on.san")
    seeds_dir = tmp_path / "seeds"
    seeds_dir.mkdir()
    (seeds_dir / "seed_0").write_bytes(b"\x00hello")
    (seeds_dir / "seed_1_quarantined").write_bytes(b"\x01boom")
    out_json = tmp_path / "smoke_on.json"

    probe_invocations: list[tuple[list[str], dict[str, str]]] = []

    def fake_run(argv, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        env = dict(extra_env or {})
        if "FRAMAC_PROBE_OUT" in env:
            probe_invocations.append((list(argv), env))
            probe_out = Path(env["FRAMAC_PROBE_OUT"])
            telemetry = {
                "schema_version": 1,
                "cases": {
                    "0": {
                        "runs": 64,
                        "init_fail": 0,
                        "ret_kind": "i64",
                        "unique_overflow": False,
                        "unique_vals": [0, 14],
                    },
                    "2": {
                        "runs": 64,
                        "init_fail": 0,
                        "ret_kind": "i64",
                        "unique_overflow": False,
                        "unique_vals": [27],
                    },
                    "3": {
                        "runs": 64,
                        "init_fail": 64,
                        "ret_kind": "void",
                        "unique_overflow": False,
                        "unique_vals": [],
                    },
                },
            }
            probe_out.write_text(json.dumps(telemetry), encoding="utf-8")
            return SandboxResult(
                returncode=0, stdout="", stderr="", timed_out=False, sandbox="rlimits", command=list(argv)
            )

        for p in _extract_probe_paths(argv):
            raw = p.read_bytes()
            if not raw or raw == b"\xff":
                continue
            if raw[0] == 1 and len(raw) == 1:
                return SandboxResult(
                    returncode=1,
                    stdout="",
                    stderr=_LOG_NULL_MEMBER_UBSAN.format(probe_path=p),
                    timed_out=False,
                    sandbox="rlimits",
                    command=list(argv),
                )
        return SandboxResult(returncode=0, stdout="", stderr="", timed_out=False, sandbox="rlimits", command=list(argv))

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_run)
    report, rc = HS.run_smoke(
        module="mod_probe_on",
        sidecar_path=sidecar,
        out_json=out_json,
        san_bin=san_bin,
        seeds_dir=seeds_dir,
    )

    assert rc == 0
    assert report["status"] == "degraded"
    assert report["quarantined_cases"] == [1]
    assert report["skip_cases_env"] == "1"

    assert len(probe_invocations) == 1
    probe_argv, probe_env = probe_invocations[0]
    assert "-max_total_time=5" in probe_argv
    assert "-ignore_crashes=1" in probe_argv
    assert probe_env.get("FRAMAC_FUZZ_SKIP_CASES") == "1"

    assert "probe" in report
    probe = report["probe"]
    assert minischema.validate(probe, _PROBE_SCHEMA) == []
    assert probe["enabled"] is True
    assert probe["probe_secs"] == 5
    assert probe["summary_counts"] == {
        "never_reached": 0,
        "init_always_fails": 1,
        "constant_return": 1,
        "low_samples": 0,
        "healthy": 1,
    }
    flagged_by_case = {item["case"]: item for item in probe["flagged_cases"]}
    assert set(flagged_by_case) == {2, 3}
    assert flagged_by_case[2]["status"] == "constant_return"
    assert flagged_by_case[2]["constant_value"] == 27
    assert flagged_by_case[2]["entry"] == "src/map.c::get_in_map"
    assert flagged_by_case[3]["status"] == "init_always_fails"
    assert flagged_by_case[3]["constant_value"] is None


def test_cli_probe_secs_flag_overrides_env_default(tmp_path, monkeypatch):
    monkeypatch.delenv("FRAMAC_HARNESS_PROBE", raising=False)
    sidecar = _write_sidecar(tmp_path, "mod_cli_probe", dispatch_case_count=2)
    san_bin = _make_fake_bin(tmp_path / "fuzz_mod_cli_probe.san")
    out_json = tmp_path / "smoke_cli.json"
    seen_probe_args: list[list[str]] = []

    def fake_run(argv, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        if extra_env and "FRAMAC_PROBE_OUT" in extra_env:
            seen_probe_args.append(list(argv))
            Path(extra_env["FRAMAC_PROBE_OUT"]).write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "cases": {
                            "0": {
                                "runs": 30,
                                "init_fail": 0,
                                "ret_kind": "i64",
                                "unique_overflow": False,
                                "unique_vals": [1],
                            },
                            "1": {
                                "runs": 30,
                                "init_fail": 0,
                                "ret_kind": "i64",
                                "unique_overflow": False,
                                "unique_vals": [0, 1],
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )
        return SandboxResult(returncode=0, stdout="", stderr="", timed_out=False, sandbox="rlimits", command=list(argv))

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_run)
    rc = HS.main(
        [
            "run",
            "--module",
            "mod_cli_probe",
            "--san-bin",
            str(san_bin),
            "--sidecar",
            str(sidecar),
            "--out-json",
            str(out_json),
            "--probe-secs",
            "3",
        ]
    )

    assert rc == 0
    assert len(seen_probe_args) == 1
    assert "-max_total_time=3" in seen_probe_args[0]
    report = json.loads(out_json.read_text(encoding="utf-8"))
    assert report["status"] == "ok"
    assert report["probe"]["probe_secs"] == 3
    assert report["probe"]["summary_counts"]["constant_return"] == 1
    assert report["probe"]["summary_counts"]["healthy"] == 1
    assert minischema.validate(report["probe"], _PROBE_SCHEMA) == []
