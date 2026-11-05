"""`--no-warn-unsigned` is limited to the lines a prover declares as deliberate wraps."""

from __future__ import annotations

import copy
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import run_wp_function as W  # noqa: E402
import workspace_overlay as WO  # noqa: E402

SOURCE = """int f(unsigned char c, unsigned *out) {
  unsigned d = (unsigned)c - 32u;
  unsigned e = (unsigned)c - 16u;
  *out = d + e;
  return 0;
}
"""
# The same code after ACSL merges above and inside the function: code doesn't move among code lines.
MERGED = """/*@ requires \\valid(out);
    assigns *out; */
int f(unsigned char c, unsigned *out) {
  unsigned d = (unsigned)c - 32u;
  //@ assert ok: \\true;
  unsigned e = (unsigned)c - 16u;
  *out = d + e;
  return 0;
}
"""


def _proof(status: str = "all_proven", **kw) -> dict:
    return {
        "status": status,
        "function": "f",
        "total_goals": 10,
        "proven_count": 10,
        "unproven_count": 0,
        "unproven_goals": [],
        "unproven_by_bucket": {"step_c_rte_obligation": []},
        "by_obligation_class": {"rte": {"proven": 10, "proven_under_hyp": 0, "unproven": 0}},
        "soundness": {"ok": True, "reduced_checks": ["-warn-unsigned-overflow / -warn-unsigned-downcast OFF"]},
        "next_synthesis_focus": "complete",
        **kw,
    }


def _goal(line: int, status: str = "Unknown", kind: str = "unsigned_overflow", file: str = "m.c") -> dict:
    return {"file": file, "function": "f", "line": line, "kind": kind, "status": status, "annotation": f"p{line}"}


@pytest.fixture
def source(tmp_path: Path) -> Path:
    path = tmp_path / "m.c"
    path.write_text(SOURCE, encoding="utf-8")
    return path


def _check(monkeypatch, source: Path, unproven=(), under_hyp=(), check_status="unproven_goals_remain", **kw):
    calls = []

    def fake(c_file, fn_name, out_dir, **options):
        calls.append(options)
        return {
            "status": check_status,
            "reason": "timeout" if check_status == "analysis_error" else None,
            "unproven_goals": list(unproven),
            "proven_under_hyp_goals": [],
            "partially_proven_goals": list(under_hyp),
        }

    monkeypatch.setattr(W, "run_wp_on_function", fake)
    res = W.check_declared_wraps(kw.pop("proof", None) or _proof(), source, "f", source.parent, **kw)
    return res, calls


def test_the_check_is_a_second_run_with_overflow_checks_on_and_no_retries(monkeypatch, source) -> None:
    _, calls = _check(monkeypatch, source, wp_model="Typed+ref+int", cache_dir="off")
    assert len(calls) == 1
    options = calls[0]
    assert options["unsigned_reduced"] is False
    assert options["warn_unsigned_downcast"] is False, "aligned with the parent's default re-check"
    assert options["prop"] == "unsigned_overflow"
    assert options["retry_bitwise"] is False and options["retry_tail"] is False
    assert options["ignore_prover_budget"] is True, "one prover iteration, not two"
    assert options["wp_model"] == "Typed+ref+int" and options["cache_dir"] == "off"


def test_declared_lines_are_recorded_and_the_proof_stands(monkeypatch, source) -> None:
    res, _ = _check(monkeypatch, source, unproven=[_goal(2)], wrap_lines=[2])
    assert res["status"] == "all_proven" and res["unproven_count"] == 0
    wraps = res["unsigned_wraps"]
    assert wraps["status"] == "ok" and wraps["undeclared"] == []
    assert wraps["declared"] == [{"line": 2, "code_line": 1, "annotations": ["p2"]}]
    assert wraps["declared_code_lines"] == [1]
    assert any("declared deliberate wraps at L2" in item for item in res["soundness"]["reduced_checks"])
    assert any("OFF" in item for item in res["soundness"]["reduced_checks"]), "the parent still infers the flag"


def test_an_undeclared_unproven_goal_leaves_the_function_unproven(monkeypatch, source) -> None:
    res, _ = _check(monkeypatch, source, unproven=[_goal(2), _goal(3)], wrap_lines=[2])
    assert res["status"] == "unproven_goals_remain"
    assert res["unproven_count"] == 1 and res["total_goals"] == 11
    assert res["by_obligation_class"]["rte"]["unproven"] == 1, "the ledger's rte unit must not be credited"
    assert res["next_synthesis_focus"] == "step_c_rte_obligation"
    assert [g["line"] for g in res["unproven_goals"]] == [3]
    assert res["unproven_by_bucket"]["step_c_rte_obligation"][0]["undeclared_unsigned_wrap"] is True
    assert res["unsigned_wraps"]["status"] == "undeclared"
    assert res["unsigned_wraps"]["undeclared"][0]["line"] == 3
    assert any("line(s) 3" in hint for hint in res["diagnostic_hints"])


def test_no_declaration_means_no_wrap_is_allowed(monkeypatch, source) -> None:
    res, _ = _check(monkeypatch, source, unproven=[_goal(2)])
    assert res["status"] == "unproven_goals_remain" and res["unsigned_wraps"]["declared"] == []


def test_a_goal_only_partially_proven_does_not_clear_an_undeclared_line(monkeypatch, source) -> None:
    # WP assumes the wrap's assertion for what follows, so this "proof" may rest on a false hypothesis.
    res, _ = _check(monkeypatch, source, unproven=[_goal(2)], under_hyp=[_goal(3, "Partially proven")], wrap_lines=[2])
    assert res["status"] == "unproven_goals_remain"
    assert res["unsigned_wraps"]["undeclared"][0]["status"] == "Partially proven"


def test_proved_goals_and_other_kinds_are_left_alone(monkeypatch, source) -> None:
    res, _ = _check(
        monkeypatch,
        source,
        unproven=[_goal(4, kind="mem_access")],  # judged by the proof run, not here
        under_hyp=[_goal(4, "Partially proven", kind="user assertion")],
    )
    assert res["status"] == "all_proven" and res["unsigned_wraps"]["status"] == "ok"


def test_a_goal_in_another_file_is_never_covered_by_a_declaration(monkeypatch, source) -> None:
    res, _ = _check(monkeypatch, source, unproven=[_goal(2, file="other.h")], wrap_lines=[2])
    assert res["status"] == "unproven_goals_remain"


def test_declared_positions_survive_acsl_merges(monkeypatch, source) -> None:
    first, _ = _check(monkeypatch, source, unproven=[_goal(2)], wrap_lines=[2])
    positions = first["unsigned_wraps"]["declared_code_lines"]
    source.write_text(MERGED, encoding="utf-8")
    # The same code line is now file line 4: a parent re-check on the merged tree still matches it,
    # while the line below, which was never declared, still fails.
    again, _ = _check(monkeypatch, source, unproven=[_goal(4)], wrap_code_lines=positions)
    assert again["status"] == "all_proven"
    assert again["unsigned_wraps"]["declared"] == [{"line": 4, "code_line": 1, "annotations": ["p4"]}]
    other, _ = _check(monkeypatch, source, unproven=[_goal(6)], wrap_code_lines=positions)
    assert other["status"] == "unproven_goals_remain"


def test_declarations_nothing_needed_are_reported_not_recorded(monkeypatch, source) -> None:
    res, _ = _check(monkeypatch, source, wrap_lines=[2, 99])
    wraps = res["unsigned_wraps"]
    assert wraps["declared_code_lines"] == [] and wraps["unused_code_lines"] == [1] and wraps["unknown_lines"] == [99]
    assert len(res["soundness"]["reduced_checks"]) == 1


def test_a_failed_check_proves_nothing(monkeypatch, source) -> None:
    res, _ = _check(monkeypatch, source, check_status="analysis_error", wrap_lines=[2])
    assert res["status"] == "analysis_error" and res["reason"] == "timeout"
    assert res["next_synthesis_focus"] == "analysis_error_rerun_required"
    assert res["unsigned_wraps"] == {"status": "check_failed", "check_status": "analysis_error"}


@pytest.mark.parametrize(
    "proof",
    [
        _proof("analysis_error"),
        _proof("acsl_syntax_error"),
        _proof("wp_aborted"),
        _proof("all_proven", budget_exhausted=True),
    ],
)
def test_no_check_when_the_proof_run_decided_nothing(monkeypatch, source, proof) -> None:
    res, calls = _check(monkeypatch, source, proof=copy.deepcopy(proof))
    assert calls == [] and "unsigned_wraps" not in res


# ---------------------------------------------------------------------------
# The command line
# ---------------------------------------------------------------------------


def _main(monkeypatch, tmp_path: Path, *extra: str) -> tuple[int, dict, list]:
    source = tmp_path / "m.c"
    source.write_text(SOURCE, encoding="utf-8")
    runs: list[dict] = []

    def fake(c_file, fn_name, out_dir, **options):
        runs.append(options)
        if options.get("prop") == "unsigned_overflow":
            return {"status": "unproven_goals_remain", "unproven_goals": [_goal(2)], "proven_under_hyp_goals": []}
        return _proof()

    monkeypatch.setattr(W, "run_wp_on_function", fake)
    out = tmp_path / "r.json"
    args = ["--file", str(source), "--function", "f", "--out-dir", str(tmp_path / "wp"), "--out-json", str(out), *extra]
    return W.main(args), json.loads(out.read_text(encoding="utf-8")), runs


def test_main_records_declarations_in_the_report(monkeypatch, tmp_path: Path) -> None:
    rc, report, runs = _main(monkeypatch, tmp_path, "--no-warn-unsigned", "--wrap-lines", "2")
    assert rc == 0 and len(runs) == 2
    assert runs[0]["unsigned_reduced"] is True
    assert report["status"] == "all_proven" and report["unsigned_wraps"]["declared_code_lines"] == [1]


def test_main_without_declarations_fails_the_function(monkeypatch, tmp_path: Path) -> None:
    _, report, _ = _main(monkeypatch, tmp_path, "--no-warn-unsigned")
    assert report["status"] == "unproven_goals_remain"


@pytest.mark.parametrize("extra", [("--no-warn-unsigned-downcast",), ("--no-warn-unsigned", "--prop", "x")])
def test_main_runs_no_check_without_the_opt_out_or_on_a_partial_run(monkeypatch, tmp_path: Path, extra) -> None:
    _, report, runs = _main(monkeypatch, tmp_path, *extra)
    assert len(runs) == 1 and "unsigned_wraps" not in report


def test_main_rejects_declarations_without_the_opt_out(monkeypatch, tmp_path: Path, capsys) -> None:
    with pytest.raises(SystemExit):
        _main(monkeypatch, tmp_path, "--wrap-lines", "2")
    assert "only apply with --no-warn-unsigned" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# The parent follows the declaration
# ---------------------------------------------------------------------------


def test_parent_flags_carry_the_declared_positions(tmp_path: Path) -> None:
    scratch = tmp_path / "agents" / "prove-f" / "scratch"
    scratch.mkdir(parents=True)
    report = {
        "function": "f",
        "soundness": {"reduced_checks": ["-warn-unsigned-overflow / -warn-unsigned-downcast OFF"]},
        "unsigned_wraps": {"declared_code_lines": [1, 4]},
    }
    (scratch / "wp_f.json").write_text(json.dumps(report), encoding="utf-8")
    flags = WO.infer_prover_wp_flags(tmp_path, agent_id="prove-f", c_file="m.c", function="f")
    assert flags == ["--no-warn-unsigned", "--wrap-code-lines=1,4"]


def test_parent_flags_from_the_ledger_evidence_carry_them_too(tmp_path: Path) -> None:
    reports = tmp_path / "workspace" / "reports" / "wp-old"
    reports.mkdir(parents=True)
    report = {
        "function": "f",
        "soundness": {"reduced_checks": ["-warn-unsigned-overflow / -warn-unsigned-downcast OFF"]},
        "unsigned_wraps": {"declared_code_lines": [2]},
    }
    (reports / "f.json").write_text(json.dumps(report), encoding="utf-8")
    unit = {
        "function": "f",
        "file": "m.c",
        "assumptions": [
            {
                "description": "WP run with reduced RTE check flags: -warn-unsigned-overflow / -warn-unsigned-downcast OFF."
            }
        ],
        "evidence": [{"phase": "wp", "tool_output": "workspace/reports/wp-old/f.json"}],
    }
    (tmp_path / "coverage-ledger.json").write_text(json.dumps([unit]), encoding="utf-8")
    flags = WO.infer_prover_wp_flags(tmp_path, c_file="m.c", function="f")
    assert flags == ["--no-warn-unsigned", "--wrap-code-lines=2"]


def test_declared_flags_never_leak_into_the_default_flags(tmp_path: Path) -> None:
    assert WO.infer_prover_wp_flags(tmp_path, function="f") == ["--no-warn-unsigned-downcast"]


# ---------------------------------------------------------------------------
# The WP semantics this design rests on
# ---------------------------------------------------------------------------

needs_framac = pytest.mark.skipif(shutil.which("frama-c") is None, reason="needs Frama-C (inside the image)")

PROBE = r"""/*@ requires \valid(out);
    assigns *out; */
int f(unsigned char c, unsigned *out) {
  unsigned d = (unsigned)c - 32u;
  //@ assert later: c >= 32;
  unsigned e = (unsigned)c - 16u;
  *out = d + e;
  return 0;
}
"""


def _real(tmp_path: Path, name: str, **kw) -> dict:
    return W.run_wp_on_function(
        tmp_path / "w.c",
        "f",
        tmp_path / name,
        provers="alt-ergo,z3",
        timeout=5,
        retry_bitwise=False,
        retry_tail=False,
        cache_dir="off",
        **kw,
    )


@needs_framac
def test_real_a_wrap_supports_later_goals_only_with_the_checks_on(tmp_path: Path) -> None:
    (tmp_path / "w.c").write_text(PROBE, encoding="utf-8")
    on = _real(tmp_path, "on", warn_unsigned_downcast=False, prop="later,unsigned_overflow")
    assert any(g["annotation"] == "c >= 32" for g in on["partially_proven_goals"]), "the wrap's assertion proves it"
    off = _real(tmp_path, "off", unsigned_reduced=True)
    assert any(g["annotation"] == "c >= 32" for g in off["unproven_goals"]), "nothing does, with the checks off"


@needs_framac
def test_real_second_wrap_is_caught_though_it_looks_proved_below_the_declared_one(tmp_path: Path, capsys) -> None:
    (tmp_path / "w.c").write_text(PROBE.replace("  //@ assert later: c >= 32;\n", ""), encoding="utf-8")
    out = tmp_path / "r.json"
    base = [
        "--file",
        str(tmp_path / "w.c"),
        "--function",
        "f",
        "--out-dir",
        str(tmp_path / "wp"),
        "--out-json",
        str(out),
    ]
    options = [
        "--provers",
        "alt-ergo,z3",
        "--timeout",
        "5",
        "--no-retry-bitwise",
        "--no-retry-tail",
        "--cache-dir",
        "off",
    ]
    W.main([*base, *options, "--no-warn-unsigned", "--wrap-lines", "4"])
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["status"] == "unproven_goals_remain"
    undeclared = report["unsigned_wraps"]["undeclared"]
    assert any(g["status"] == "Partially proven" and "- 16u" in g["annotation"] for g in undeclared)
    # Declaring the deliberate lines is what clears it, and they end up in the report.
    W.main([*base, *options, "--no-warn-unsigned", "--wrap-lines", "4,5,6"])
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["status"] == "all_proven", report["unsigned_wraps"]
    assert {entry["line"] for entry in report["unsigned_wraps"]["declared"]} == {4, 5, 6}
