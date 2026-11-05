from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from benchmark_briefs import (
    DEFAULT_SAMPLE,
    added_entry_preconditions,
    defined_functions,
    is_candidate,
    judge_sample,
    load_sample,
    missing_annotations,
    outcome_rates,
    paired_comparison,
    prepare,
    render_task,
    resolve_sample,
    select_sample,
    static_oracle,
    summarize_arm,
)

PROGRAM = """/*@
requires n >= 0;
*/
void foo(int n) {
  int x = n;
  int y = 0;
  while (x > 0) {
    y = y + 1;
    x = x - 1;
  }
  //@ assert(y == n);
}
"""

ANSWER = """/*@
requires n >= 0;
assigns \\nothing;
*/
void foo(int n) {
  int x = n;
  int y = 0;
  /*@ loop invariant x + y == n;
      loop invariant x >= 0;
      loop assigns x, y;
      loop variant x; */
  while (x > 0) {
    y = y + 1;
    x = x - 1;
  }
  //@ assert(y == n);
}
"""


def make_dataset(root: Path) -> Path:
    for corpus in ("autobench", "live24", "live25"):
        (root / corpus).mkdir(parents=True)
    for i in range(6):
        (root / "autobench" / f"{i}.c").write_text(PROGRAM.replace("foo", f"foo{i}"), encoding="utf-8")
        (root / "live24" / f"12345_STUDENT{i}.c").write_text(PROGRAM.replace("foo", f"bar{i}"), encoding="utf-8")
        (root / "live25" / f"case{i}.c").write_text(PROGRAM.replace("foo", f"baz{i}"), encoding="utf-8")
    return root


@pytest.mark.unit
class TestSampling:
    def test_candidate_needs_an_assert_and_a_loop(self):
        assert is_candidate(PROGRAM)
        assert not is_candidate("int main(){ //@ assert 1 == 1;\n return 0; }\n")
        assert not is_candidate("void f(){ while(1){} }\n")
        assert not is_candidate("// assert in a plain comment\nvoid f(){ while(1){} }\n")
        assert not is_candidate("/*@ assert \\true; */ void f(){ /* while */ }\n")

    def test_selection_is_independent_of_file_names_and_location(self, tmp_path):
        from benchmark_briefs import scan_dataset

        first = select_sample(scan_dataset(make_dataset(tmp_path / "a")), 3, "salt")
        moved = make_dataset(tmp_path / "somewhere" / "else")
        for path in sorted((moved / "live24").glob("*.c")):
            path.rename(path.with_name("renamed_" + path.name))
        assert select_sample(scan_dataset(moved), 3, "salt") == first
        assert len(first) == 9

    def test_salt_changes_the_choice(self, tmp_path):
        from benchmark_briefs import scan_dataset

        programs = scan_dataset(make_dataset(tmp_path))
        assert select_sample(programs, 2, "one") != select_sample(programs, 2, "two")

    def test_sample_records_no_file_name(self, tmp_path):
        from benchmark_briefs import scan_dataset

        chosen = select_sample(scan_dataset(make_dataset(tmp_path)), 3, "salt")
        assert all(set(row) == {"id", "corpus", "sha256", "lines"} for row in chosen)
        assert "STUDENT" not in json.dumps(chosen)

    def test_shipped_sample_has_digests_only(self):
        sample = load_sample()
        assert len(sample["programs"]) == 30
        text = DEFAULT_SAMPLE.read_text(encoding="utf-8")
        assert not re.search(r"\.c\b(?!\w)", text.replace("docs/benchmark.md", ""))
        assert "BL.EN" not in text
        for row in sample["programs"]:
            assert set(row) == {"id", "corpus", "sha256", "lines"}
            assert re.fullmatch(r"[0-9a-f]{64}", row["sha256"])

    def test_resolve_finds_moved_content_and_reports_what_is_gone(self, tmp_path):
        from benchmark_briefs import scan_dataset

        dataset = make_dataset(tmp_path)
        chosen = select_sample(scan_dataset(dataset), 1, "salt")
        sample = {"programs": [*chosen, {"id": "s-gone", "corpus": "live25", "sha256": "0" * 64, "lines": 1}]}
        resolved, missing = resolve_sample(sample, dataset)
        assert len(resolved) == len(chosen)
        assert missing == ["s-gone"]


@pytest.mark.unit
class TestStaticOracle:
    def test_annotations_only_answer_passes(self):
        assert static_oracle(PROGRAM, ANSWER) == []

    def test_changed_c_code_is_refused(self):
        changed = ANSWER.replace("y = y + 1;", "y = y + 2;")
        assert any("non-ACSL" in p for p in static_oracle(PROGRAM, changed))

    def test_deleting_the_assert_is_refused(self):
        changed = ANSWER.replace("//@ assert(y == n);", "")
        problems = static_oracle(PROGRAM, changed)
        assert any("annotations removed" in p and "assert(y==n)" in p for p in problems)

    def test_weakening_the_assert_is_refused(self):
        changed = ANSWER.replace("//@ assert(y == n);", "//@ assert(y >= 0);")
        assert any("annotations removed" in p for p in static_oracle(PROGRAM, changed))

    def test_deleting_the_original_requires_is_refused(self):
        changed = ANSWER.replace("requires n >= 0;", "")
        assert any("requires" in p for p in static_oracle(PROGRAM, changed))

    @pytest.mark.parametrize(
        "bad",
        ["//@ admit y == n;", "/*@ axiomatic A { axiom a: \\true; } */", "/*@ requires \\false; */"],
    )
    def test_unsound_constructs_are_refused(self, bad):
        assert static_oracle(PROGRAM, bad + "\n" + ANSWER)

    def test_merging_new_clauses_into_an_existing_block_keeps_the_original(self):
        assert missing_annotations(PROGRAM, ANSWER) == []

    def test_whitespace_changes_do_not_count_as_removal(self):
        assert missing_annotations(PROGRAM, ANSWER.replace("assert(y == n)", "assert( y==n )")) == []


@pytest.mark.unit
class TestEntryPreconditions:
    def test_new_value_precondition_on_an_entry_function_is_flagged(self):
        answer = ANSWER.replace("requires n >= 0;", "requires n >= 0;\nrequires n == 5;")
        assert added_entry_preconditions(PROGRAM, answer) == ["foo: n==5"]

    def test_memory_shape_precondition_is_allowed(self):
        program = "void f(int *p) {\n  while (*p > 0) { *p = *p - 1; }\n  //@ assert *p <= 0;\n}\n"
        answer = "/*@ requires \\valid(p); */\n" + program
        assert added_entry_preconditions(program, answer) == []

    def test_precondition_on_a_called_function_is_allowed(self):
        program = (
            "int g(int x) { return x; }\nint main(void) {\n  int r = g(1);\n  //@ assert r == 1;\n  return r;\n}\n"
        )
        answer = program.replace(
            "int g(int x)", "/*@ requires x == 1; assigns \\nothing; ensures \\result == x; */\nint g(int x)"
        )
        assert added_entry_preconditions(program, answer) == []

    def test_original_precondition_is_not_new(self):
        assert added_entry_preconditions(PROGRAM, ANSWER) == []

    def test_brace_inside_a_contract_does_not_end_it(self):
        # One program of the sample has a set in its contract; splitting at the first brace broke it.
        program = (
            "/*@ requires n \\in {1, 2}; */\nvoid f(int n) {\n  while (n > 0) { n = n - 1; }\n  //@ assert n <= 0;\n}\n"
        )
        answer = program.replace("{1, 2};", "{1, 2};\n    requires n == 1;")
        assert added_entry_preconditions(program, program) == []
        assert added_entry_preconditions(program, answer) == ["f: n==1"]

    def test_defined_functions_lists_only_definitions(self):
        assert defined_functions("int a(void);\nint b(void) { return 0; }\n") == ["b"]


def wp(status="all_proven", total=3, proven=3, unproven=0, log="") -> dict:
    return {
        "status": status,
        "total_goals": total,
        "proven_count": proven,
        "proven_under_hyp_count": 0,
        "unproven_count": unproven,
        "wp_log_tail": log,
    }


@pytest.mark.unit
class TestJudgeSample:
    def test_all_proven_is_proved(self):
        result = judge_sample([], [wp(), wp()], [])
        assert result["outcome"] == "proved"
        assert result["goals_total"] == 6

    def test_static_refusal_outranks_everything(self):
        assert judge_sample(["C changed"], [wp()], [])["outcome"] == "oracle_rejected"

    def test_added_precondition_makes_the_proof_conditional(self):
        assert judge_sample([], [wp()], ["f: n==5"])["outcome"] == "proved_conditional"

    def test_unproven_goal_is_not_proved(self):
        assert judge_sample([], [wp("unproven_goals_remain", 3, 2, 1)], [])["outcome"] == "not_proved"

    def test_goals_lost_to_the_time_limit_are_undecided(self):
        result = judge_sample(
            [], [wp("unproven_goals_remain", 3, 2, 1, "[wp] Proved goals: 2 / 3\n  Timeout: 1\n")], []
        )
        assert result["outcome"] == "timeout"

    def test_timeout_does_not_excuse_other_unproven_goals(self):
        result = judge_sample([], [wp("unproven_goals_remain", 4, 1, 3, "  Timeout: 1\n")], [])
        assert result["outcome"] == "not_proved"

    def test_a_soundness_rejection_is_not_proved(self):
        assert judge_sample([], [wp("unsound_proof", 3, 3, 0)], [])["outcome"] == "not_proved"

    def test_a_tool_failure_is_undecided(self):
        assert judge_sample([], [wp(), wp("analysis_error", 0, 0, 0)], [])["outcome"] == "tool_failure"

    def test_no_function_is_a_tool_failure(self):
        assert judge_sample([], [], [])["outcome"] == "tool_failure"


def samples(*outcomes: str) -> dict:
    return {f"s{i}": {"outcome": o, "corpus": "autobench"} for i, o in enumerate(outcomes)}


@pytest.mark.unit
class TestRates:
    def test_two_ways(self):
        rates = outcome_rates(samples("proved", "not_proved", "timeout", "tool_failure"))
        assert rates["over_decided"] == 0.5
        assert rates["strict"] == 0.25

    def test_conditional_proof_is_not_a_pass(self):
        assert outcome_rates(samples("proved_conditional"))["passed"] == 0

    def test_missing_answer_counts_only_against_the_strict_rate(self):
        rates = outcome_rates(samples("proved", "not_answered"))
        assert rates["over_decided"] == 1.0
        assert rates["strict"] == 0.5

    def test_arm_summary_reports_usage_only_from_what_was_reported(self):
        rows = samples("proved", "not_proved")
        rows["s0"]["usage"] = {"input_tokens": 10, "output_tokens": 2, "iterations": 1}
        arm = summarize_arm(rows, ["s-gone"])
        assert arm["usage"]["samples_reporting"] == 1
        assert arm["usage"]["input"] == 10
        assert arm["missing_programs"] == ["s-gone"]
        assert arm["by_corpus"]["autobench"]["passed"] == 1

    def test_paired_comparison_counts_programs_not_totals(self):
        a = {"samples": samples("proved", "proved", "not_proved", "not_proved")}
        b = {"samples": samples("proved", "not_proved", "proved", "not_proved")}
        pair = paired_comparison(a, b)
        assert pair["both_proved"] == 1
        assert pair["neither_proved"] == 1
        assert pair["only_first_proved"] == ["s1"]
        assert pair["only_second_proved"] == ["s2"]


@pytest.mark.unit
class TestPrepare:
    def test_task_carries_the_brief_and_the_program(self):
        task = render_task("Prove {function_name} as {agent_id}.", "s-1", "int x;")
        assert "every function in the program" in task
        assert "sample-s-1" in task
        assert "int x;" in task
        assert "{function_name}" not in task

    def test_prepared_tree_has_no_dataset_file_name(self, tmp_path):
        from benchmark_briefs import scan_dataset

        dataset = make_dataset(tmp_path / "data")
        chosen = select_sample(scan_dataset(dataset), 2, "salt")
        sample_path = tmp_path / "sample.json"
        sample_path.write_text(json.dumps({"programs": chosen}), encoding="utf-8")
        brief = tmp_path / "brief.md"
        brief.write_text("Brief for {function_name}.", encoding="utf-8")
        out = tmp_path / "out"
        plan = prepare(dataset, out, {"a": brief}, sample_path)
        assert plan["arms"] == ["a"]
        assert len(plan["programs"]) == 6
        names = [p.name for p in out.rglob("*")]
        assert not any("STUDENT" in name for name in names)
        assert "STUDENT" not in (out / "plan.json").read_text(encoding="utf-8")
        first = plan["programs"][0]["id"]
        assert (out / "samples" / first / "input.c").is_file()
        assert (
            (out / "arms" / "a" / first / "task.md").read_text(encoding="utf-8").startswith("Brief for every function")
        )
