"""
A passing verdict must state what it covered: the should-pass and should-fail cases for the
limits recorded by run_wp_function.py and run_eacsl_fuzz.py and enforced by ledger.py and
validate_artifacts.py.

The `needs_framac` cases run the real tools (skipped without Frama-C, e.g. outside the image).
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import run_eacsl_fuzz as R
import run_wp_function as W
from acsl_ast import find_named_clause, is_trivial_predicate
from conftest import evidence, unit
from framac_common import wp_limits_problem
from generate_report import verdict_limits_section
from run_eacsl_fuzz import derive_eacsl_diagnostic_hints, parse_guardrail_reach
from validate_artifacts import validate_ledger

needs_framac = pytest.mark.skipif(shutil.which("frama-c") is None, reason="Frama-C not available")


@pytest.mark.parametrize(
    "predicate",
    [
        "\\true",
        "1",
        "(\\true)",
        "*o == *o",
        "p->x == p->x",
        "1 == 1",
        "0 <= 1",
        "x <= x",
        "\\valid(o) ==> \\true",
        "x > 0 ==> x > 0",
        "\\false ==> x == 1",
        "x > 0 <==> x > 0",
        "x > 0 || \\true",
        "\\true && 1 == 1",
    ],
)
def test_trivial_predicates(predicate):
    assert is_trivial_predicate(predicate)


@pytest.mark.parametrize(
    "predicate",
    [
        "\\false",
        "0",
        "*o != 10",
        "x != x",
        "x < x",
        "1 == 2",
        "x == y",
        "0 <= x <= 5",
        "x > 0 ==> y > 0",
        "x > 0 <==> y > 0",
        "x > 0 && \\true",
        "\\true ==> x > 0",
        "no_crlf_or_nul(out, \\result)",
        "\\forall integer i",
        "f(1 == 1)",
    ],
)
def test_real_predicates_are_not_trivial(predicate):
    assert not is_trivial_predicate(predicate)


def test_find_named_clause_reads_multiline_acsl():
    source = "/*@ requires r: x > 0;\n  @ ensures L5_a:\n  @   \\result == 1;\n  @ ensures L5_b: \\true; */"
    assert find_named_clause(source, "L5_a") == "\\result == 1"
    assert find_named_clause(source, "L5_b") == "\\true"
    assert find_named_clause(source, "L5_abc") is None


DOOMED_REQUIRES = "[wp] [Failed] (Doomed) typed_g2_wp_smoke_default_requires (Qed)\n  Smoke Tests:     0 / 2\n"
DOOMED_BEHAVIOR = "[wp] [Failed] (Doomed) typed_f_wp_smoke_b_requires (Qed)\n  Smoke Tests:     1 / 3\n"
# Correct defensive code: `if (p == 0)` under `requires \valid(p)`.
DOOMED_DEFENSIVE = (
    "[wp] [Failed] (Doomed) typed_f_wp_smoke_dead_code_s4 (Qed)\n"
    "[wp] [Failed] (Doomed) typed_log_err_wp_smoke_dead_call_s3 (Qed)\n"
    "  Smoke Tests:     2 / 8\n"
)


def test_doomed_requires_is_contradictory():
    assert W.classify_vacuity_log(DOOMED_REQUIRES)["status"] == "contradictory"
    assert W.classify_vacuity_log(DOOMED_BEHAVIOR)["doomed"] == ["b"]


def test_dead_defensive_code_is_counted_but_not_contradictory():
    res = W.classify_vacuity_log(DOOMED_DEFENSIVE)
    assert res["status"] == "consistent" and res["dead_goals"] == 2


def test_smoke_pass_without_a_result_is_inconclusive():
    assert W.classify_vacuity_log("[kernel] user error", returncode=1)["status"] == "inconclusive"
    assert W.classify_vacuity_log("no summary line", returncode=0)["status"] == "inconclusive"


def test_missing_spec_is_unsound_but_explicit_exits_message_is_benign():
    bad = "[kernel:annot:missing-spec] a.c:2: Warning: \n  Neither code nor specification for function set_shared, generating default\n"
    good = "[kernel:annot:missing-spec] string.h:170: Warning: \n  Neither code nor explicit exits and terminates for function memset,\n"
    assert not W.scan_wp_log_soundness(bad)["ok"]
    assert W.scan_wp_log_soundness(good)["ok"]


def _report(**kw):
    res = {
        "status": "all_proven",
        "soundness": {"ok": True, "tier_a_aborts": [], "tier_b_unsound": []},
        "layer_goals": [],
        "wp_log_tail": "",
    }
    res.update(kw)
    return res


def test_contradictory_contract_fails_the_proof():
    res = W.apply_verdict_limits(
        _report(), Path("a.c"), {"status": "contradictory", "doomed": ["default"], "dead_goals": 0}
    )
    assert res["status"] == "unsound_proof"
    assert not res["soundness"]["ok"]
    assert any("contradictory" in h or "Vacuous" in h for h in res["diagnostic_hints"])


def test_consistent_contract_keeps_the_proof():
    res = W.apply_verdict_limits(_report(), Path("a.c"), {"status": "consistent", "doomed": [], "dead_goals": 0})
    assert res["status"] == "all_proven"
    assert wp_limits_problem(res["limits"]) is None


def test_missing_spec_callees_are_listed():
    msg = "Neither code nor specification for function set_shared, generating default"
    res = W.apply_verdict_limits(_report(soundness={"ok": False, "tier_b_unsound": [msg]}), Path("a.c"), None)
    assert res["limits"]["missing_spec_callees"] == ["set_shared"]


@pytest.mark.parametrize(
    "limits", [None, {}, {"vacuity": {"status": "not_run"}}, {"vacuity": {"status": "contradictory"}}]
)
def test_limits_that_do_not_allow_credit(limits):
    assert wp_limits_problem(limits)


@pytest.mark.parametrize("status", ["consistent", "inconclusive"])
def test_limits_that_allow_credit(status):
    assert wp_limits_problem({"vacuity": {"status": status}}) is None


def test_layer_class_needs_one_real_clause(tmp_path):
    c = tmp_path / "a.c"
    c.write_text(
        "/*@ ensures L5_empty: \\true; ensures L5_real: *o != 10; ensures L6_empty: 1 == 1; */\n", encoding="utf-8"
    )
    goals = [
        {"file": str(c), "kind": "postcondition", "annotation": "L5_empty", "obligation_class": "l5_output"},
        {"file": str(c), "kind": "postcondition", "annotation": "L5_real", "obligation_class": "l5_output"},
        {"file": str(c), "kind": "postcondition", "annotation": "L6_empty", "obligation_class": "l6_secret"},
    ]
    limits = W.layer_clause_limits(goals, c)
    assert limits["classes_without_real_clause"] == ["l6_secret"]
    assert limits["trivial_layer_clauses"] == ["L5_empty", "L6_empty"]


def test_unreadable_layer_clause_stays_credited_and_is_reported(tmp_path):
    goals = [{"file": "gone.h", "kind": "postcondition", "annotation": "L5_x", "obligation_class": "l5_output"}]
    limits = W.layer_clause_limits(goals, tmp_path / "missing.c")
    assert limits["unchecked_layer_clauses"] == ["L5_x"]
    assert limits["classes_without_real_clause"] == []


COVERAGE = """INFO: Seed: 1
Assertion failed at a.c:3
COVERAGE:
UNCOVERED_FUNC: hits: 0 edges: 0/3 LLVMFuzzerInitialize fuzz_init.c:22
COVERED_FUNC: hits: 2 edges: 4/8 LLVMFuzzerTestOneInput a.c:939
COVERED_FUNC: hits: 2 edges: 1/1 __gen_e_acsl_target_ok a.c:987
UNCOVERED_FUNC: hits: 0 edges: 0/1 __gen_e_acsl_target_never a.c:988
stat::number_of_executed_units: 3
stat::peak_rss_mb: 40
"""


def test_guardrail_reach_counts_the_eacsl_wrapper():
    reach, rest = parse_guardrail_reach(COVERAGE, ["target_ok", "target_never", "inlined"])
    assert reach["measured"] and reach["executed_inputs"] == 3
    assert reach["functions"] == {"target_ok": 2, "target_never": 0, "inlined": None}
    assert reach["unreached"] == ["target_never"]
    assert "COVERED_FUNC" not in rest and "Assertion failed at a.c:3" in rest


def test_guardrail_reach_unmeasured_without_coverage_lines():
    reach, _ = parse_guardrail_reach("INFO: Seed: 1\n", ["f"])
    assert not reach["measured"] and reach["unreached"] == []


def test_guardrail_pass_on_unreached_function_says_so():
    res = {"status": "passed_dynamic_oracle", "reach": {"unreached": ["target_never"]}}
    assert "target_never" in derive_eacsl_diagnostic_hints(res)[0]
    assert derive_eacsl_diagnostic_hints({"status": "passed_dynamic_oracle", "reach": {"unreached": []}}) == []


def test_report_section_names_what_verdicts_did_not_establish():
    limits = {
        "vacuity": {"status": "inconclusive"},
        "dynamic_oracle": {"exercised": False},
        "trivial_layer_clauses": ["L5_empty"],
        "unchecked_layer_clauses": ["L6_gone"],
    }
    credited = {"file": "a.c", "function": "f", "evidence": [{"phase": "wp", "details": {"limits": limits}}]}
    text = "\n".join(verdict_limits_section([credited]))
    assert "no guardrail input reached the function (1): `a.c#f`" in text
    assert "inconclusive (1)" in text
    assert "`a.c#f (L5_empty)`" in text and "`a.c#f (L6_gone)`" in text
    assert verdict_limits_section([{"file": "a.c", "function": "f", "evidence": []}]) == []


def test_validator_rejects_discharging_wp_evidence_without_limits():
    base = evidence(phase="wp", result="wp_proven", tool_output=None)
    bare = unit("a.c", "f", "rte", status="covered", evidence=[base])
    assert any("records no verdict limits" in e for e in validate_ledger([bare]))
    contradictory = {**base, "details": {"limits": {"vacuity": {"status": "contradictory"}}}}
    assert any("did not pass" in e for e in validate_ledger([{**bare, "evidence": [contradictory]}]))
    consistent = {**base, "details": {"limits": {"vacuity": {"status": "consistent"}}}}
    assert list(validate_ledger([{**bare, "evidence": [consistent]}])) == []


CASES = {
    # (function, source, expected status, expected vacuity)
    "contradictory": (
        "f",
        "int buf[4];\n/*@ requires a: n > 0; requires b: n < 0; assigns buf[0 .. 3]; */\nvoid f(int n){ buf[n + 10] = 1; }\n",
        "unsound_proof",
        "contradictory",
    ),
    "contradictory_predicate": (
        "f",
        "int buf[4];\n/*@ predicate never(integer n) = n > 0 && n < 0; */\n/*@ requires a: never(n); assigns buf[0 .. 3]; */\nvoid f(int n){ buf[n + 10] = 1; }\n",
        "unsound_proof",
        "contradictory",
    ),
    "defensive_branch": (
        "f",
        "/*@ requires \\valid(p); assigns *p; */\nint f(int *p){ if (p == 0) return -1; *p = 1; return 0; }\n",
        "all_proven",
        "consistent",
    ),
    "unreachable_assert": (
        "f",
        "/*@ requires 0 <= k <= 1; assigns \\nothing; ensures \\result >= 0; */\nint f(int k){ switch (k) { case 0: return 1; case 1: return 2; default: /*@ assert unreachable_branch: \\false; */ return 0; } }\n",
        "all_proven",
        "consistent",
    ),
    "spec_less_callee": (
        "f",
        "int shared;\nvoid set_shared(int v);\n/*@ assigns shared; ensures shared == 0; */\nvoid f(void){ shared = 0; set_shared(7); }\n",
        "unsound_proof",
        "not_run",
    ),
    "specified_callee": (
        "f",
        "int shared;\n/*@ assigns \\nothing; */ void noop(int v);\n/*@ assigns shared; ensures shared == 0; */\nvoid f(void){ shared = 0; noop(7); }\n",
        "all_proven",
        "consistent",
    ),
}


def _run(tmp_path: Path, name: str, fn: str, source: str) -> dict:
    os.chdir(tmp_path)  # Frama-C and Why3 write next to the working directory
    c = tmp_path / f"{name}.c"
    c.write_text(source, encoding="utf-8")
    out = tmp_path / f"{name}.json"
    assert (
        W.main(
            [
                "--file",
                str(c),
                "--function",
                fn,
                "--out-dir",
                str(tmp_path / name),
                "--out-json",
                str(out),
                "--ignore-prover-budget",
                "--cache-dir",
                "off",
            ]
        )
        == 0
    )
    return json.loads(out.read_text(encoding="utf-8"))


@needs_framac
@pytest.mark.parametrize("name", sorted(CASES))
def test_real_wp_verdicts(tmp_path, name):
    fn, source, status, vacuity = CASES[name]
    res = _run(tmp_path, name, fn, source)
    assert res["status"] == status, res.get("wp_log_tail")
    assert res["limits"]["vacuity"]["status"] == vacuity


@needs_framac
@pytest.mark.parametrize(
    "fn,call,status,hits",
    [
        ("target_violated", "if (size >= 4) (void)target_violated(copy, (int)size);", "rejected_overconstrained", None),
        ("target_ok", "if (size >= 4) (void)target_ok(copy, 12345);", "passed_dynamic_oracle", 2),
        ("target_never", "if (size == 99999) (void)target_never(copy, 1);", "passed_dynamic_oracle", 0),
    ],
)
def test_real_guardrail_reports_reach(tmp_path, fn, call, status, hits):
    os.chdir(tmp_path)
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "a").write_bytes(b"AAAA")
    (corpus / "b").write_bytes(b"BBBBBB")
    c = tmp_path / "g.c"
    c.write_text(
        "#include <stddef.h>\n#include <stdint.h>\n#include <stdlib.h>\n#include <string.h>\n"
        f"/*@ requires ok: n == 12345; */\nstatic int {fn}(const uint8_t *p, int n) {{ return p[0] + n; }}\n"
        "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
        "  uint8_t *copy = (uint8_t *)malloc(size > 0 ? size : 1U);\n"
        "  if (copy == NULL) return 0;\n"
        "  if (size > 0) memcpy(copy, data, size);\n"
        f"  {call}\n  free(copy);\n  return 0;\n}}\n",
        encoding="utf-8",
    )
    out = tmp_path / "guard.json"
    argv = ["guardrail", "--sources", str(c), "--functions", fn, "--out-bin", str(tmp_path / "bin")]
    argv += ["--corpus-dir", str(corpus), "--extra-runs", "0", "--no-cache", "--out-json", str(out)]
    assert R.main(argv) == 0
    res = json.loads(out.read_text(encoding="utf-8"))
    assert res["status"] == status
    if hits is not None:
        assert res["reach"]["measured"] and res["reach"]["functions"][fn] == hits
        assert res["reach"]["unreached"] == ([fn] if hits == 0 else [])


@needs_framac
def test_real_trivial_layer_clause_is_flagged(tmp_path):
    res = _run(
        tmp_path,
        "trivial",
        "f",
        "/*@ requires \\valid(o); assigns *o; ensures L5_no_crlf: \\true; */\nvoid f(char *o){ *o = '\\n'; }\n",
    )
    assert res["status"] == "all_proven"
    assert res["limits"]["classes_without_real_clause"] == []


@needs_framac
def test_real_layer_clause_is_credited(tmp_path):
    res = _run(
        tmp_path,
        "real",
        "f",
        "/*@ requires \\valid(o); assigns *o; ensures L5_no_crlf: *o != 10; */\nvoid f(char *o){ *o = 1; }\n",
    )
    assert res["status"] == "all_proven"
    assert res["limits"]["classes_without_real_clause"] == []
