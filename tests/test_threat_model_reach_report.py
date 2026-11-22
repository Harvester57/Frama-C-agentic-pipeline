"""
W1-E (docs/plans/phase1-qcbor-lessons-plan.md): Threat-Model Coverage Gap Summary.

Self-contained unit tests modeled on the real QCBOR run-1 data shapes (`phase0_model.json`,
`callgraph_dag.json`, `harness_libqcbor_a.json`, `coverage/libqcbor_a.json`) with no runtime
dependency on `~`. Verifies:
  1. `harness_reach.check_dynamic` / `dynamic` computes `threat_model_coverage` (`input_sources_total`,
     `executed`, `unexecuted_total`, `auto_exempt_by_reason`, `untrusted_files` sorted ascending by
     `pct` with `< 50%` `below_threshold` flagging).
  2. `schemas/harness_reach_dynamic.schema.json` accepts both new and legacy reports and rejects
     malformed `threat_model_coverage` payloads via `validate_artifacts.validate_dynamic_reach`.
  3. `generate_report.py` (`threat_model_coverage_lines`, `fuzz_reach_lines`, `render_report`)
     renders a concise "Threat-Model Coverage Gaps" section iff `auto_exempt_by_reason` is non-empty
     or any untrusted `.c` file is `< 50%` covered.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import generate_report
import harness_reach
from validate_artifacts import validate_dynamic_reach

pytestmark = pytest.mark.unit


def _tm_entry_trust(name: str) -> dict[str, Any]:
    return {
        "value": "untrusted",
        "source": "threat_model",
        "sources": ["threat_model", "default"],
        "boundary": True,
        "reasons": ["threat-model input source (entry)", f"API of libqcbor.a ({name})"],
        "input_role": "entry",
    }


def _call_graph_untrusted() -> dict[str, Any]:
    return {
        "value": "untrusted",
        "source": "call_graph",
        "sources": ["call_graph"],
        "boundary": False,
        "reasons": ["on the input path"],
    }


def _trusted_trust() -> dict[str, Any]:
    return {
        "value": "trusted",
        "source": "threat_model",
        "sources": [],
        "boundary": False,
        "reasons": ["threat model: trusted callers only"],
    }


def _build_qcbor_like_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    number_decode_covered: int = 176,
    number_decode_total: int = 821,
    include_auto_exempt: bool = True,
    not_replayed: int = 0,
) -> Path:
    """
    Create a self-contained QCBOR run-1-shaped run directory under `tmp_path` with:
      - `src/qcbor_number_decode.c` at 176/821 regions (21.4% by default) and `QCBORDecode_ProcessBigNumber`
        plus 12 `szLabel`-exempt functions, 3 `BigNumberBuf`-exempt functions, and 2 `MantissaBuffer`-exempt
        functions.
      - `src/qcbor_main_encode.c` (194/358 = 54.2%), including `QCBOREncode_EncodeHead` which is in
        `api_auto_exempt` yet executed transitively (1200x), so it must NOT appear in `auto_exempt_by_reason`.
      - `src/qcbor_main_decode.c` (624/757 = 82.4%).
      - `src/qcbor_err_to_str.c` (216/216 = 100.0%).
      - `src/trusted_internal.c` (10/100 = 10.0%, all functions `trusted` -> excluded from `untrusted_files`).
      - `inc/qcbor/UsefulBuf.h` header inline (0/4 -> `.h` excluded from `untrusted_files`).
    """
    run = tmp_path / "qcbor-run"
    reports = run / "workspace" / "reports"
    cov_dir = reports / "coverage"
    hdir = run / "workspace" / "harnesses"
    cov_dir.mkdir(parents=True)
    hdir.mkdir(parents=True)
    monkeypatch.chdir(run)

    szlabel_fns = [f"QCBORDecode_GetItemInMapSZ_{i:02d}" for i in range(12)]
    bignum_fns = [
        "QCBORDecode_GetTBigNumber",
        "QCBORDecode_GetTBigNumberInMapN",
        "QCBORDecode_ProcessBigNumber",
    ]
    mantissa_fns = [
        "QCBORDecode_GetTBigFloatBigMantissa",
        "QCBORDecode_GetTDecimalFractionBigMantissa",
    ]
    executed_entries: list[tuple[str, str, int, int, int]] = [
        # (file, name, execs, reg_cov, reg_tot)
        ("src/qcbor_number_decode.c", "QCBORDecode_GetDoubleConvertAll", 1965, number_decode_covered, 200),
        ("src/qcbor_main_encode.c", "QCBOREncode_AddInt64", 288, 120, 200),
        ("src/qcbor_main_encode.c", "QCBOREncode_EncodeHead", 1200, 74, 158),
        ("src/qcbor_main_decode.c", "QCBORDecode_Init", 42039, 300, 357),
        ("src/qcbor_main_decode.c", "QCBORDecode_GetNext", 49329, 324, 400),
        ("src/qcbor_err_to_str.c", "qcbor_err_to_str", 420, 216, 216),
    ]

    dag_functions: dict[str, Any] = {}
    model_functions: dict[str, Any] = {}
    cov_functions: list[dict[str, Any]] = []
    entry_names: list[str] = []

    for fpath, fname, execs, rcov, rtot in executed_entries:
        entry_names.append(fname)
        dag_functions[fname] = {
            "name": fname,
            "file": fpath,
            "module": "libqcbor_a",
            "is_static": False,
            "header": False,
            "internal_callees": [],
        }
        model_functions[f"{fpath}#{fname}"] = {
            "name": fname,
            "file": fpath,
            "units": ["libqcbor.a"],
            "trust": _tm_entry_trust(fname),
        }
        cov_functions.append(
            {
                "function": fname,
                "file": fpath,
                "line": 10,
                "executions": execs,
                "regions": {"covered": rcov, "total": rtot},
            }
        )

    # Distribute remaining regions of src/qcbor_number_decode.c across the unexecuted functions so
    # total regions equal `number_decode_total` (821 by default -> 176/821 = 21.4%).
    unexec_number_fns = [*szlabel_fns, *bignum_fns, *mantissa_fns]
    rem_total = max(0, number_decode_total - 200)
    base_reg, extra_reg = divmod(rem_total, len(unexec_number_fns))

    auto_exempt: dict[str, str] = {}
    if include_auto_exempt:
        auto_exempt["QCBOREncode_EncodeHead"] = "trusted parameter Buffer has no instance"

    for idx, fname in enumerate(unexec_number_fns):
        entry_names.append(fname)
        rtot = base_reg + (1 if idx < extra_reg else 0)
        ex_count = 0 if include_auto_exempt else 15
        rcov = 0 if include_auto_exempt else rtot
        dag_functions[fname] = {
            "name": fname,
            "file": "src/qcbor_number_decode.c",
            "module": "libqcbor_a",
            "is_static": False,
            "header": False,
            "internal_callees": [],
        }
        model_functions[f"src/qcbor_number_decode.c#{fname}"] = {
            "name": fname,
            "file": "src/qcbor_number_decode.c",
            "units": ["libqcbor.a"],
            "trust": _tm_entry_trust(fname),
        }
        cov_functions.append(
            {
                "function": fname,
                "file": "src/qcbor_number_decode.c",
                "line": 100 + idx * 10,
                "executions": ex_count,
                "regions": {"covered": rcov, "total": rtot},
            }
        )
        if include_auto_exempt:
            if fname in szlabel_fns:
                auto_exempt[fname] = "trusted parameter szLabel has no instance"
            elif fname in bignum_fns:
                auto_exempt[fname] = "trusted parameter BigNumberBuf has no instance"
            else:
                auto_exempt[fname] = "trusted parameter MantissaBuffer has no instance"

    # Non-entry internal helper in src/qcbor_number_decode.c (untrusted via call_graph, 0 execs).
    model_functions["src/qcbor_number_decode.c#QCBORDecode_BigNumberCopyPlusOne"] = {
        "name": "QCBORDecode_BigNumberCopyPlusOne",
        "file": "src/qcbor_number_decode.c",
        "units": ["libqcbor.a"],
        "trust": _call_graph_untrusted(),
    }
    cov_functions.append(
        {
            "function": "QCBORDecode_BigNumberCopyPlusOne",
            "file": "src/qcbor_number_decode.c",
            "line": 500,
            "executions": 0 if include_auto_exempt else 5,
            "regions": {"covered": 0, "total": 0},
        }
    )

    # Trusted-only .c file (should be excluded from untrusted_files even with low coverage).
    model_functions["src/trusted_internal.c#Internal_SelfTest"] = {
        "name": "Internal_SelfTest",
        "file": "src/trusted_internal.c",
        "units": ["libqcbor.a"],
        "trust": _trusted_trust(),
    }
    cov_functions.append(
        {
            "function": "Internal_SelfTest",
            "file": "src/trusted_internal.c",
            "line": 20,
            "executions": 0,
            "regions": {"covered": 10, "total": 100},
        }
    )

    # Header inline function (should be excluded from untrusted_files because it is a .h file).
    model_functions["inc/qcbor/UsefulBuf.h#UsefulBuf_IsNULL"] = {
        "name": "UsefulBuf_IsNULL",
        "file": "inc/qcbor/UsefulBuf.h",
        "units": ["libqcbor.a"],
        "trust": _call_graph_untrusted(),
    }
    cov_functions.append(
        {
            "function": "UsefulBuf_IsNULL",
            "file": "inc/qcbor/UsefulBuf.h",
            "line": 2127,
            "executions": 0,
            "regions": {"covered": 0, "total": 4},
        }
    )

    # Separate test-unit function (must not leak into libqcbor_a counts).
    model_functions["test/run_tests.c#RunTestsQCBOR"] = {
        "name": "RunTestsQCBOR",
        "file": "test/run_tests.c",
        "units": ["qcbortest"],
        "trust": _tm_entry_trust("RunTestsQCBOR"),
    }

    dag = {
        "module_kind": "link_unit",
        "modules": {
            "libqcbor_a": {
                "unit": "libqcbor.a",
                "tier": "Tier 1A",
                "functions": sorted(dag_functions),
                "candidate_entry_points": sorted(entry_names),
            }
        },
        "functions": dag_functions,
    }
    (reports / "callgraph_dag.json").write_text(json.dumps(dag, indent=2), encoding="utf-8")

    model = {
        "units": {
            "libqcbor.a": {
                "kind": "static_lib",
                "test": False,
                "files": [
                    "src/qcbor_number_decode.c",
                    "src/qcbor_main_encode.c",
                    "src/qcbor_main_decode.c",
                    "src/qcbor_err_to_str.c",
                    "src/trusted_internal.c",
                ],
                "trust": {"threat_model": "ok"},
            },
            "qcbortest": {"kind": "executable", "test": True, "files": ["test/run_tests.c"]},
        },
        "functions": model_functions,
        "trust": {"threat_model": {"status": "ok"}},
    }
    (reports / "phase0_model.json").write_text(json.dumps(model, indent=2), encoding="utf-8")

    harness_c = hdir / "harness_libqcbor_a.c"
    calls = "\n".join(f"  {fn}();" for fn in sorted(entry_names))
    harness_c.write_text(f"int LLVMFuzzerTestOneInput(void) {{\n{calls}\n  return 0;\n}}\n", encoding="utf-8")

    sidecar: dict[str, Any] = {
        "module": "libqcbor_a",
        "unit": "libqcbor.a",
        "harness_file": "workspace/harnesses/harness_libqcbor_a.c",
        "sources": [
            "src/qcbor_number_decode.c",
            "src/qcbor_main_encode.c",
            "src/qcbor_main_decode.c",
            "src/qcbor_err_to_str.c",
        ],
        "cppflags": "-I.",
        "entry_style": "dispatch",
        "reach_exempt": {},
    }
    if include_auto_exempt:
        sidecar["api_auto_exempt"] = auto_exempt
    (hdir / "harness_libqcbor_a.json").write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

    total_reg_cov = sum(int(r["regions"]["covered"]) for r in cov_functions)
    total_reg_all = sum(int(r["regions"]["total"]) for r in cov_functions)
    cov_report = {
        "mode": "coverage",
        "module": "libqcbor_a",
        "status": "ok",
        "inputs": {"total": 43465, "replayed": 43465 - not_replayed, "failed": 0, "not_replayed": not_replayed},
        "totals": {
            "functions": {
                "total": len(cov_functions),
                "reached": sum(1 for r in cov_functions if r["executions"] > 0),
            },
            "regions": {"total": total_reg_all, "covered": total_reg_cov},
        },
        "functions": cov_functions,
    }
    (cov_dir / "libqcbor_a.json").write_text(json.dumps(cov_report, indent=2), encoding="utf-8")
    return run


def _minimal_report_data(run: Path) -> dict[str, Any]:
    return {
        "run_dir": run,
        "meta": {
            "run_id": "run-1",
            "repo": "QCBOR",
            "run_status": "complete",
            "target": "/target",
            "source_ref": {"vcs": "git", "commit": "47df2bc4240d", "dirty": False},
            "profile": "standard",
            "scope_paths": [],
            "budget": 21600,
            "sandbox": {"outer": "docker", "inner": "sandbox_exec"},
            "prior_runs": [],
        },
        "ledger": [],
        "findings": [],
        "candidates": [],
        "coverage": generate_report.load_coverage_reports(run),
    }


def test_qcbor_fixture_populates_threat_model_coverage_and_renders_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    run = _build_qcbor_like_run(tmp_path, monkeypatch)

    rc = harness_reach.main(["dynamic", "--module", "libqcbor_a"])
    assert rc == 0

    dyn_path = run / "workspace" / "reports" / "harness_reach_dynamic.json"
    doc = json.loads(dyn_path.read_text(encoding="utf-8"))
    assert "warnings" not in doc
    assert validate_dynamic_reach(doc) == []

    row = doc["modules"]["libqcbor_a"]
    assert row["passed"] is True
    assert row["gaps"] == []

    tm = row["threat_model_coverage"]
    # 6 executed input sources + 17 unexecuted (12 szLabel + 3 BigNumberBuf + 2 MantissaBuffer) = 23 total
    assert tm["input_sources_total"] == 23
    assert tm["executed"] == 6
    assert tm["unexecuted_total"] == 17

    by_reason = tm["auto_exempt_by_reason"]
    # QCBOREncode_EncodeHead was executed 1200x so its Buffer reason is excluded from unexecuted gaps.
    assert "trusted parameter Buffer has no instance" not in by_reason
    assert list(by_reason.keys()) == [
        "trusted parameter szLabel has no instance",
        "trusted parameter BigNumberBuf has no instance",
        "trusted parameter MantissaBuffer has no instance",
    ]
    assert by_reason["trusted parameter szLabel has no instance"]["count"] == 12
    assert len(by_reason["trusted parameter szLabel has no instance"]["functions"]) == 10
    assert by_reason["trusted parameter BigNumberBuf has no instance"] == {
        "count": 3,
        "functions": [
            "QCBORDecode_GetTBigNumber",
            "QCBORDecode_GetTBigNumberInMapN",
            "QCBORDecode_ProcessBigNumber",
        ],
    }
    assert by_reason["trusted parameter MantissaBuffer has no instance"] == {
        "count": 2,
        "functions": [
            "QCBORDecode_GetTBigFloatBigMantissa",
            "QCBORDecode_GetTDecimalFractionBigMantissa",
        ],
    }

    untrusted_files = tm["untrusted_files"]
    # Sorted ascending by pct; excludes trusted_internal.c and UsefulBuf.h.
    assert [f["file"] for f in untrusted_files] == [
        "src/qcbor_number_decode.c",
        "src/qcbor_main_encode.c",
        "src/qcbor_main_decode.c",
        "src/qcbor_err_to_str.c",
    ]
    num_dec = untrusted_files[0]
    assert num_dec["covered"] == 176
    assert num_dec["total"] == 821
    assert num_dec["pct"] == 21.4
    assert num_dec["below_threshold"] is True
    assert "QCBORDecode_ProcessBigNumber" in num_dec["zero_exec_functions"]
    assert "QCBORDecode_BigNumberCopyPlusOne" in num_dec["zero_exec_functions"]
    assert len(num_dec["zero_exec_functions"]) == 18

    assert untrusted_files[1]["pct"] == 54.2
    assert untrusted_files[1]["below_threshold"] is False
    assert untrusted_files[2]["pct"] == 82.4
    assert untrusted_files[2]["below_threshold"] is False
    assert untrusted_files[3]["pct"] == 100.0
    assert untrusted_files[3]["below_threshold"] is False

    # Verify Markdown rendering in threat_model_coverage_lines, fuzz_reach_lines, and full REPORT.md.
    tm_md = "\n".join(generate_report.threat_model_coverage_lines(run))
    assert "### Threat-Model Coverage Gaps" in tm_md
    assert "6 / 23 threat-model input sources executed (17 unexecuted)" in tm_md
    assert "| `libqcbor_a` | `src/qcbor_number_decode.c` | 176 / 821 | 21.4% |" in tm_md
    assert "src/qcbor_main_encode.c" not in tm_md
    assert "src/trusted_internal.c" not in tm_md
    assert "| `libqcbor_a` | `trusted parameter szLabel has no instance` | 12 |" in tm_md
    assert "| `libqcbor_a` | `trusted parameter BigNumberBuf has no instance` | 3 |" in tm_md
    assert "`QCBORDecode_ProcessBigNumber`" in tm_md
    assert "| `libqcbor_a` | `trusted parameter MantissaBuffer has no instance` | 2 |" in tm_md

    fuzz_md = "\n".join(generate_report.fuzz_reach_lines(generate_report.load_coverage_reports(run), run_dir=run))
    assert "### Threat-Model Coverage Gaps" in fuzz_md
    assert "src/qcbor_number_decode.c" in fuzz_md

    report_md = generate_report.render_report(_minimal_report_data(run))
    assert report_md.count("### Threat-Model Coverage Gaps") == 1
    assert "21.4%" in report_md
    assert "trusted parameter BigNumberBuf has no instance" in report_md


def test_no_gap_table_when_all_files_above_threshold_and_no_auto_exempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    run = _build_qcbor_like_run(
        tmp_path,
        monkeypatch,
        number_decode_covered=180,
        number_decode_total=821,
        include_auto_exempt=False,
    )
    assert harness_reach.main(["dynamic", "--module", "libqcbor_a"]) == 0

    doc = json.loads((run / "workspace/reports/harness_reach_dynamic.json").read_text(encoding="utf-8"))
    assert validate_dynamic_reach(doc) == []
    tm = doc["modules"]["libqcbor_a"]["threat_model_coverage"]
    assert tm["input_sources_total"] == 23
    assert tm["executed"] == 23
    assert tm["unexecuted_total"] == 0
    assert tm["auto_exempt_by_reason"] == {}
    assert all(f["below_threshold"] is False for f in tm["untrusted_files"])

    # No auto-exemptions and all untrusted .c files >= 50%: table must be omitted.
    assert generate_report.threat_model_coverage_lines(run) == []
    report_md = generate_report.render_report(_minimal_report_data(run))
    assert "### Threat-Model Coverage Gaps" not in report_md


def test_only_low_coverage_file_renders_file_table_without_auto_exempt_table(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    run = _build_qcbor_like_run(
        tmp_path,
        monkeypatch,
        number_decode_covered=40,
        number_decode_total=200,
        include_auto_exempt=False,
    )
    assert harness_reach.main(["dynamic", "--module", "libqcbor_a"]) == 0
    doc = json.loads((run / "workspace/reports/harness_reach_dynamic.json").read_text(encoding="utf-8"))
    assert validate_dynamic_reach(doc) == []

    tm_md = "\n".join(generate_report.threat_model_coverage_lines(run))
    assert "### Threat-Model Coverage Gaps" in tm_md
    assert "**Low-coverage untrusted source files (< 50% regions):**" in tm_md
    assert "src/qcbor_number_decode.c" in tm_md
    assert "20.0%" in tm_md
    assert "**Auto-exempt unexecuted functions by reason:**" not in tm_md


def test_only_auto_exempt_renders_reason_table_without_low_file_table(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    # Give src/qcbor_number_decode.c >= 50% coverage (150/200) while keeping auto_exempt unexecuted functions.
    run = _build_qcbor_like_run(
        tmp_path,
        monkeypatch,
        number_decode_covered=150,
        number_decode_total=200,
        include_auto_exempt=True,
    )
    assert harness_reach.main(["dynamic", "--module", "libqcbor_a"]) == 0
    doc = json.loads((run / "workspace/reports/harness_reach_dynamic.json").read_text(encoding="utf-8"))
    assert validate_dynamic_reach(doc) == []
    assert all(
        f["below_threshold"] is False for f in doc["modules"]["libqcbor_a"]["threat_model_coverage"]["untrusted_files"]
    )

    tm_md = "\n".join(generate_report.threat_model_coverage_lines(run))
    assert "### Threat-Model Coverage Gaps" in tm_md
    assert "**Low-coverage untrusted source files (< 50% regions):**" not in tm_md
    assert "**Auto-exempt unexecuted functions by reason:**" in tm_md
    assert "trusted parameter szLabel has no instance" in tm_md


def test_schema_backward_compatibility_and_validation_rejections():
    legacy_doc = {
        "generated_at": "2026-11-22T22:17:26Z",
        "entry_points_crashed": 0,
        "modules": {
            "libqcbor_a": {
                "module": "libqcbor_a",
                "mode": "dynamic",
                "coverage_status": "ok",
                "corpus_inputs": 100,
                "entry_points": 2,
                "entry_points_executed": 2,
                "crashed_entry_points": [],
                "executions": {"a": 1, "b": 2},
                "gaps": [],
                "passed": True,
                "harness_digest": "0" * 64,
            }
        },
    }
    assert validate_dynamic_reach(legacy_doc) == []
    assert generate_report.threat_model_coverage_lines(dynamic_doc=legacy_doc) == []

    # Missing required field in threat_model_coverage must fail validation.
    bad_missing = json.loads(json.dumps(legacy_doc))
    bad_missing["modules"]["libqcbor_a"]["threat_model_coverage"] = {
        "input_sources_total": 1,
        "executed": 1,
        "unexecuted_total": 0,
        "auto_exempt_by_reason": {},
    }
    assert validate_dynamic_reach(bad_missing)

    # pct > 100 must fail validation.
    bad_pct = json.loads(json.dumps(legacy_doc))
    bad_pct["modules"]["libqcbor_a"]["threat_model_coverage"] = {
        "input_sources_total": 1,
        "executed": 1,
        "unexecuted_total": 0,
        "auto_exempt_by_reason": {},
        "untrusted_files": [
            {
                "file": "src/a.c",
                "covered": 10,
                "total": 10,
                "pct": 105.0,
                "zero_exec_functions": [],
                "below_threshold": False,
            }
        ],
    }
    assert validate_dynamic_reach(bad_pct)

    # Zero count in auto_exempt_by_reason must fail validation.
    bad_count = json.loads(json.dumps(legacy_doc))
    bad_count["modules"]["libqcbor_a"]["threat_model_coverage"] = {
        "input_sources_total": 1,
        "executed": 1,
        "unexecuted_total": 0,
        "auto_exempt_by_reason": {"trusted parameter x has no instance": {"count": 0, "functions": []}},
        "untrusted_files": [],
    }
    assert validate_dynamic_reach(bad_count)


def test_partial_coverage_drops_threat_model_coverage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    run = _build_qcbor_like_run(tmp_path, monkeypatch, not_replayed=50)
    # Exit code 2 because coverage was partial (unmeasured).
    assert harness_reach.main(["dynamic", "--module", "libqcbor_a"]) == 2
    doc = json.loads((run / "workspace/reports/harness_reach_dynamic.json").read_text(encoding="utf-8"))
    assert validate_dynamic_reach(doc) == []
    assert "libqcbor_a" in doc["unmeasured"]
    assert "libqcbor_a" not in doc["modules"]


def test_submodule_scopes_threat_model_coverage_to_its_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    run = _build_qcbor_like_run(tmp_path, monkeypatch)
    dag = json.loads((run / "workspace/reports/callgraph_dag.json").read_text(encoding="utf-8"))
    model = json.loads((run / "workspace/reports/phase0_model.json").read_text(encoding="utf-8"))
    cov = json.loads((run / "workspace/reports/coverage/libqcbor_a.json").read_text(encoding="utf-8"))
    sub_sidecar = {
        "module": "qcbor_enc",
        "unit": "libqcbor_a",
        "scope_files": ["src/qcbor_main_encode.c"],
        "api_auto_exempt": {
            "QCBORDecode_ProcessBigNumber": "trusted parameter BigNumberBuf has no instance",
            "QCBOREncode_AddInt64": "trusted parameter Buf has no instance",
        },
    }
    mm = harness_reach.ModuleMap(dag, {"qcbor_enc": sub_sidecar})
    runs = harness_reach._executions(cov)
    res = harness_reach._threat_model_coverage("qcbor_enc", dag, mm, model, sub_sidecar, cov, runs)
    tm = res["threat_model_coverage"]
    assert tm["input_sources_total"] == 2
    assert tm["executed"] == 2
    assert tm["unexecuted_total"] == 0
    assert tm["auto_exempt_by_reason"] == {}
    assert [f["file"] for f in tm["untrusted_files"]] == ["src/qcbor_main_encode.c"]
