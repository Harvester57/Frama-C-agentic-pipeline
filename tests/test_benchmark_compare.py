from __future__ import annotations

import copy
import json

import pytest

from benchmark_compare import (
    SCHEMA_VERSION,
    Comparison,
    IncomparableError,
    Tolerances,
    compare_runs,
    main,
    rate_block,
    render_text,
)


def eva_block(**over) -> dict:
    block: dict = {
        "status": "ok",
        "reason": None,
        "valid": 90,
        "unknown": 10,
        "invalid": 0,
        "dead": 5,
        "assumed": 20,
        "total": 100,
        "invalid_ids": [],
        "reduced_checks": [],
        "undeclared_functions": [],
        "coverage": {
            "functions_analyzed": 10,
            "functions_total": 10,
            "statements_reached": 200,
            "statements_total": 200,
        },
    }
    block.update(over)
    return block


def bug_entry(status: str = "retained", fingerprint: str = "a.c#f::shift::0123456789", reason=None) -> dict:
    return {
        "status": status,
        "reason": reason,
        "replays": [
            {
                "target": "t",
                "module": "m",
                "engine": "sanitizers",
                "required": True,
                "outcome": "reproduced" if status == "retained" else "not_reproduced",
                "observed": {"fingerprint": fingerprint},
            },
            {
                "target": "t",
                "module": "m",
                "engine": "eacsl",
                "required": False,
                "outcome": "reproduced",
                "observed": {"fingerprint": "a.c#f::shift::9876543210"},
            },
        ],
    }


def make_run() -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": "base",
        "machine": {"cpus": 12, "mem_mb": 24000},
        "toolchain": {"frama-c": "34.0"},
        "limits": {"wp_memlimit_mb": 1000, "fuzz_rss_limit_mb": 2048},
        "pipeline": {"content_digest": "abc"},
        "recall": {"bugs": {"BUG-1": bug_entry(), "BUG-2": bug_entry()}},
        "targets": {
            "t": {
                "revision": "r1",
                "harness_digest": "h1",
                "status": "ok",
                "problems": [],
                "wall_s": 100.0,
                "cpu_s": 200.0,
                "dag": {"functions": 10, "waves": 3, "name_collisions": 0, "recursion_cycles": 0},
                "modules": {
                    "m": {
                        "build": {"status": "built", "engine": "eacsl"},
                        "fuzz": {"status": "clean"},
                        "eva": eva_block(),
                    }
                },
                "functions_with_unknown": ["a.c#f", "a.c#g"],
                "prover_tasks": {"count": 2},
                "units": {
                    "covered": ["a.c#h::rte", "a.c#i::rte"],
                    "candidate": [],
                    "by_wave": {"0": rate_block(2, 2, 0)},
                },
                "candidates": {"unverified": 0, "fingerprints": {"eva": [], "fuzz": []}},
            }
        },
    }


def rows(result: Comparison, severity: str, area: str | None = None) -> list:
    return [d for d in result.diffs if d.severity == severity and (area is None or d.area == area)]


def mutate(mutator) -> Comparison:
    base = make_run()
    cur = copy.deepcopy(base)
    mutator(cur)
    return compare_runs(base, cur)


def mod_eva(run: dict) -> dict:
    return run["targets"]["t"]["modules"]["m"]["eva"]


@pytest.mark.unit
class TestRateBlock:
    def test_undecided_lowers_only_the_strict_rate(self):
        block = rate_block(3, 1, 1)
        assert block["over_decided"] == 0.75
        assert block["strict"] == 0.6

    def test_nothing_decided_has_no_rate_rather_than_zero(self):
        assert rate_block(0, 0, 2)["over_decided"] is None
        assert rate_block(0, 0, 2)["strict"] == 0.0
        assert rate_block(0, 0, 0)["strict"] is None


@pytest.mark.unit
class TestRecall:
    def test_identical_runs_have_no_failure(self):
        base = make_run()
        result = compare_runs(base, copy.deepcopy(base))
        assert not result.failed()
        assert rows(result, "regression") == []
        assert rows(result, "warning") == []

    def test_lost_bug_is_a_primary_regression(self):
        result = mutate(
            lambda r: r["recall"]["bugs"].__setitem__("BUG-1", bug_entry("lost", reason="mismatch at line 3"))
        )
        assert result.failed()
        lost = rows(result, "regression", "recall")
        assert [d.subject for d in lost] == ["BUG-1"]
        assert lost[0].primary and "LOST" in lost[0].message and "mismatch at line 3" in lost[0].message

    def test_tool_failure_on_a_recall_bug_counts_as_lost(self):
        result = mutate(
            lambda r: r["recall"]["bugs"].__setitem__("BUG-1", bug_entry("undecided", reason="build failed"))
        )
        assert result.failed()
        assert rows(result, "regression", "recall")[0].primary

    def test_bug_not_selected_is_not_a_loss(self):
        result = mutate(lambda r: r["recall"]["bugs"].pop("BUG-2"))
        assert not result.failed()
        assert [d.subject for d in rows(result, "not_compared", "recall")] == ["BUG-2"]

    def test_bug_not_selected_fails_when_all_are_required(self):
        base = make_run()
        cur = copy.deepcopy(base)
        cur["recall"]["bugs"].pop("BUG-2")
        assert compare_runs(base, cur, require_all=True).failed()

    def test_bad_baseline_cannot_excuse_a_lost_bug(self):
        base = make_run()
        base["recall"]["bugs"]["BUG-1"] = bug_entry("lost")
        cur = copy.deepcopy(base)
        result = compare_runs(base, cur)
        assert result.failed()
        assert "still not retained" in rows(result, "regression", "recall")[0].message

    def test_recovered_bug_is_an_improvement(self):
        base = make_run()
        base["recall"]["bugs"]["BUG-1"] = bug_entry("lost")
        cur = make_run()
        result = compare_runs(base, cur)
        assert not result.failed()
        assert [d.subject for d in rows(result, "improvement", "recall")] == ["BUG-1"]

    def test_changed_fingerprint_warns_but_keeps_the_bug(self):
        result = mutate(
            lambda r: r["recall"]["bugs"].__setitem__("BUG-1", bug_entry(fingerprint="a.c#f::shift::aaaaaaaaaa"))
        )
        assert not result.failed()
        assert "fingerprint changed" in rows(result, "warning", "recall")[0].message

    def test_informational_engine_change_warns_only(self):
        def lose_informational(r):
            r["recall"]["bugs"]["BUG-1"]["replays"][1]["outcome"] = "not_reproduced"

        result = mutate(lose_informational)
        assert not result.failed()
        assert "informational engine" in rows(result, "warning", "recall")[0].message


@pytest.mark.unit
class TestEvaAtBugSites:
    def with_site(self, status: str) -> dict:
        run = make_run()
        run["recall"]["bugs"]["BUG-1"]["replays"][0]["eva_site"] = status
        return run

    def test_eva_going_quiet_on_a_real_bug_warns_even_if_counts_improved(self):
        base = self.with_site("unknown")
        cur = self.with_site("not_flagged")
        mod_eva(cur).update(unknown=8, valid=92)
        result = compare_runs(base, cur)
        assert "no longer flags" in rows(result, "warning", "recall")[0].message

    def test_analysis_failure_at_the_site_also_warns(self):
        result = compare_runs(self.with_site("invalid"), self.with_site("no_analysis"))
        assert rows(result, "warning", "recall")

    def test_unknown_to_invalid_is_no_loss(self):
        assert rows(compare_runs(self.with_site("unknown"), self.with_site("invalid")), "warning", "recall") == []


@pytest.mark.unit
class TestEvaCounts:
    def test_fewer_unknowns_with_same_coverage_is_an_improvement(self):
        result = mutate(lambda r: mod_eva(r).update(unknown=8, valid=92))
        assert [d.area for d in rows(result, "improvement")] == ["eva"]
        assert not result.failed()

    @pytest.mark.parametrize(
        ("change", "fragment"),
        [
            ({"unknown": 8, "valid": 80, "total": 88}, "properties checked fell"),
            ({"unknown": 8, "valid": 92, "dead": 9}, "Dead rose"),
            ({"unknown": 8, "valid": 92, "assumed": 25}, "Considered valid rose"),
            ({"unknown": 8, "valid": 92, "reduced_checks": ["-no-warn-unsigned-downcast"]}, "checks weakened"),
            (
                {
                    "unknown": 8,
                    "valid": 92,
                    "coverage": {"functions_analyzed": 9, "statements_reached": 200},
                },
                "functions analyzed fell",
            ),
        ],
    )
    def test_fewer_unknowns_that_coverage_loss_could_explain_is_not_a_gain(self, change, fragment):
        result = mutate(lambda r: mod_eva(r).update(change))
        assert rows(result, "improvement", "eva") == []
        warnings = rows(result, "warning", "eva")
        assert warnings and fragment in warnings[0].message

    def test_more_unknowns_on_the_same_properties_is_a_regression(self):
        result = mutate(lambda r: mod_eva(r).update(unknown=11, valid=89))
        assert result.failed()
        assert rows(result, "regression", "eva")

    def test_more_unknowns_because_more_code_was_analyzed_is_not_a_regression(self):
        result = mutate(lambda r: mod_eva(r).update(unknown=12, valid=98, total=110))
        assert rows(result, "regression", "eva") == []
        assert rows(result, "changed", "eva")

    def test_counts_have_zero_tolerance(self):
        assert mutate(lambda r: mod_eva(r).update(unknown=9, valid=91)).diffs

    def test_analysis_failure_is_a_regression_and_skips_the_counts(self):
        result = mutate(lambda r: mod_eva(r).update(status="analysis_timeout", reason="wall-clock", unknown=0))
        regressions = rows(result, "regression", "eva")
        assert len(regressions) == 1 and "no longer completes" in regressions[0].message

    def test_analysis_recovery_is_an_improvement(self):
        base = make_run()
        mod_eva(base).update(status="analysis_error")
        result = compare_runs(base, make_run())
        assert [d.area for d in rows(result, "improvement")] == ["eva"]

    def test_analysis_failing_on_both_sides_is_flagged(self):
        base = make_run()
        mod_eva(base).update(status="analysis_error")
        cur = copy.deepcopy(base)
        assert "either run" in rows(compare_runs(base, cur), "warning", "eva")[0].message

    def test_vanished_invalid_alarm_is_a_warning(self):
        base = make_run()
        mod_eva(base).update(invalid=1, invalid_ids=["a.c#f::separation::x"], total=101)
        cur = make_run()
        mod_eva(cur).update(total=101)
        message = " ".join(d.message for d in rows(compare_runs(base, cur), "warning", "eva"))
        assert "no longer reported" in message

    def test_new_invalid_alarm_is_a_warning(self):
        result = mutate(lambda r: mod_eva(r).update(invalid=1, total=101, invalid_ids=["a.c#f::shift::y"]))
        assert "candidate to verify" in " ".join(d.message for d in rows(result, "warning", "eva"))


@pytest.mark.unit
class TestProverTasks:
    def test_new_function_with_unknown_is_a_regression(self):
        result = mutate(lambda r: r["targets"]["t"]["functions_with_unknown"].append("a.c#new"))
        assert "a.c#new" in rows(result, "regression", "prover_tasks")[0].message

    def test_new_function_with_unknown_is_not_a_regression_when_more_code_ran(self):
        def more(r):
            r["targets"]["t"]["functions_with_unknown"].append("a.c#new")
            mod_eva(r).update(total=120, valid=110)

        result = mutate(more)
        assert rows(result, "regression", "prover_tasks") == []
        assert rows(result, "changed", "prover_tasks")

    def test_fewer_prover_tasks_is_an_improvement(self):
        result = mutate(lambda r: r["targets"]["t"]["functions_with_unknown"].remove("a.c#g"))
        assert rows(result, "improvement", "prover_tasks")

    def test_fewer_prover_tasks_with_coverage_loss_is_not_a_gain(self):
        def gain(r):
            r["targets"]["t"]["functions_with_unknown"].remove("a.c#g")
            mod_eva(r).update(unknown=8, valid=80, total=88)

        result = mutate(gain)
        assert rows(result, "improvement", "prover_tasks") == []
        assert rows(result, "warning", "prover_tasks")

    def test_swapped_functions_are_only_changed(self):
        def swap(r):
            r["targets"]["t"]["functions_with_unknown"] = ["a.c#f", "a.c#new"]

        assert rows(mutate(swap), "changed", "prover_tasks")

    def test_function_with_unknown_but_no_ledger_unit_warns(self):
        result = mutate(lambda r: r["targets"]["t"].update(functions_with_unknown_no_unit=["a.c#hidden"]))
        assert "a.c#hidden" in rows(result, "warning", "prover_tasks")[0].message

    def test_closing_a_ledger_gap_is_an_improvement(self):
        base = make_run()
        base["targets"]["t"]["functions_with_unknown_no_unit"] = ["a.c#hidden"]
        result = compare_runs(base, make_run())
        assert "now have a ledger unit" in rows(result, "improvement", "prover_tasks")[0].message

    def test_a_unit_covered_over_an_unknown_is_a_regression(self):
        result = mutate(lambda r: r["targets"]["t"].update(covered_with_unknown=["a.c#f"]))
        assert "a.c#f" in rows(result, "regression", "units")[0].message
        base = make_run()
        base["targets"]["t"]["covered_with_unknown"] = ["a.c#f"]
        assert rows(compare_runs(base, make_run()), "improvement", "units")


@pytest.mark.unit
class TestUnits:
    def test_lost_proof_is_a_regression(self):
        result = mutate(lambda r: r["targets"]["t"]["units"]["covered"].remove("a.c#h::rte"))
        assert "a.c#h::rte" in rows(result, "regression", "units")[0].message

    def test_covered_unit_turned_candidate_by_a_campaign_only_warns(self):
        def flag(r):
            r["targets"]["t"]["units"]["covered"].remove("a.c#h::rte")
            r["targets"]["t"]["units"]["candidate"].append("a.c#h::rte")

        result = mutate(flag)
        assert rows(result, "regression", "units") == []
        assert "now a candidate" in rows(result, "warning", "units")[0].message

    def test_newly_covered_unit_is_an_improvement(self):
        result = mutate(lambda r: r["targets"]["t"]["units"]["covered"].append("a.c#f::rte"))
        assert rows(result, "improvement", "units")

    def test_wave_rate_change_is_reported_with_both_rates_kept(self):
        result = mutate(lambda r: r["targets"]["t"]["units"]["by_wave"].__setitem__("0", rate_block(3, 1, 0)))
        info = rows(result, "info", "units")
        assert info and "50.0% -> 75.0%" in info[0].message


@pytest.mark.unit
class TestComparability:
    def test_other_schema_version_is_refused(self):
        base = make_run()
        cur = copy.deepcopy(base)
        cur["schema_version"] = SCHEMA_VERSION + 1
        with pytest.raises(IncomparableError):
            compare_runs(base, cur)

    def test_foreign_file_is_refused(self):
        with pytest.raises(IncomparableError):
            compare_runs(make_run(), {"unrelated": True})

    def test_other_revision_is_not_compared_at_all(self):
        def move(r):
            r["targets"]["t"]["revision"] = "r2"
            mod_eva(r).update(unknown=99)

        result = mutate(move)
        assert not result.failed()
        assert rows(result, "not_compared", "target")
        assert rows(result, "regression", "eva") == []

    def test_changed_harness_warns_that_counts_are_not_like_for_like(self):
        result = mutate(lambda r: r["targets"]["t"].update(harness_digest="h2"))
        assert "like for like" in rows(result, "warning", "target")[0].message

    def test_changed_limit_warns_and_changed_toolchain_informs(self):
        def drift(r):
            r["limits"]["wp_memlimit_mb"] = 2000
            r["toolchain"]["frama-c"] = "35.0"

        result = mutate(drift)
        assert "result-deciding" in rows(result, "warning", "limits")[0].message
        assert rows(result, "info", "toolchain")

    def test_target_on_one_side_is_not_compared(self):
        base = make_run()
        cur = copy.deepcopy(base)
        cur["targets"]["other"] = copy.deepcopy(cur["targets"]["t"])
        del cur["targets"]["t"]
        result = compare_runs(base, cur)
        assert not result.failed()
        assert {d.subject for d in rows(result, "not_compared", "target")} == {"t", "other"}


@pytest.mark.unit
class TestTiming:
    def test_slower_beyond_tolerance_warns_and_never_fails(self):
        result = mutate(lambda r: r["targets"]["t"].update(wall_s=400.0))
        assert not result.failed()
        assert "wall-clock" in rows(result, "warning", "time")[0].message

    def test_slower_within_tolerance_is_silent(self):
        result = mutate(lambda r: r["targets"]["t"].update(wall_s=120.0))
        assert not [d for d in result.diffs if d.area == "time"]

    def test_small_absolute_change_is_silent_even_at_a_high_ratio(self):
        base = make_run()
        base["targets"]["t"]["wall_s"] = 1.0
        cur = copy.deepcopy(base)
        cur["targets"]["t"]["wall_s"] = 5.0
        assert not [d for d in compare_runs(base, cur).diffs if d.area == "time"]

    def test_other_machine_only_informs(self):
        def elsewhere(r):
            r["machine"] = {"cpus": 64, "mem_mb": 256000}
            r["targets"]["t"]["wall_s"] = 400.0

        result = mutate(elsewhere)
        assert rows(result, "warning", "time") == []
        assert "machines differ" in rows(result, "info", "time")[0].message

    def test_custom_tolerance_applies(self):
        base = make_run()
        cur = copy.deepcopy(base)
        cur["targets"]["t"]["wall_s"] = 120.0
        result = compare_runs(base, cur, Tolerances(time_ratio=1.1, time_min_delta_s=5))
        assert rows(result, "warning", "time")


@pytest.mark.unit
class TestToolingAndCandidates:
    def test_build_failure_is_a_regression(self):
        result = mutate(lambda r: r["targets"]["t"]["modules"]["m"]["build"].update(status="compile_error"))
        assert rows(result, "regression", "build")

    def test_engine_fallback_warns(self):
        result = mutate(lambda r: r["targets"]["t"]["modules"]["m"]["build"].update(engine="sanitizers"))
        assert "engine changed" in rows(result, "warning", "build")[0].message

    def test_weaker_runtime_checks_warn(self):
        result = mutate(
            lambda r: r["targets"]["t"]["modules"]["m"]["build"].update(reduced_checks=["-no-rte-initialized"])
        )
        assert "weakened" in rows(result, "warning", "build")[0].message

    def test_campaign_tool_failure_is_a_regression(self):
        result = mutate(lambda r: r["targets"]["t"]["modules"]["m"]["fuzz"].update(status="compile_error"))
        assert rows(result, "regression", "fuzz")

    def test_campaign_aborting_without_an_input_warns_but_does_not_fail(self):
        result = mutate(lambda r: r["targets"]["t"]["modules"]["m"]["fuzz"].update(status="fuzzer_error"))
        assert not result.failed()
        assert "without leaving a crash input" in rows(result, "warning", "fuzz")[0].message

    def test_campaign_finding_something_is_not_scored(self):
        result = mutate(lambda r: r["targets"]["t"]["modules"]["m"]["fuzz"].update(status="crash_found"))
        assert not result.failed()
        assert rows(result, "info", "fuzz")

    def test_run_without_campaigns_does_not_read_as_campaigns_failing(self):
        base = make_run()
        base["selection"] = {"fuzz": True}
        cur = copy.deepcopy(base)
        cur["selection"] = {"fuzz": False}
        cur["targets"]["t"]["modules"]["m"]["fuzz"] = {"status": "not_run"}
        cur["targets"]["t"]["wall_s"] = 10.0
        result = compare_runs(base, cur)
        assert not result.failed()
        assert rows(result, "regression", "fuzz") == []
        assert [d.subject for d in rows(result, "not_compared", "time")] == ["t"]

    def test_campaign_that_produced_no_report_is_still_a_regression(self):
        base = make_run()
        base["selection"] = {"fuzz": True}
        cur = copy.deepcopy(base)
        cur["targets"]["t"]["modules"]["m"]["fuzz"] = {"status": "not_run"}
        assert rows(compare_runs(base, cur), "regression", "fuzz")

    def test_new_eva_candidate_warns_new_fuzz_candidate_informs(self):
        def add(r):
            r["targets"]["t"]["candidates"]["fingerprints"] = {"eva": ["a.c#f::x::1"], "fuzz": ["a.c#g::y::2"]}

        result = mutate(add)
        assert "eva candidates" in rows(result, "warning", "candidates")[0].message
        assert any("fuzz candidates" in d.message for d in rows(result, "info", "candidates"))

    def test_lost_module_warns(self):
        result = mutate(lambda r: r["targets"]["t"]["modules"].pop("m"))
        assert "only in the baseline" in rows(result, "warning", "modules")[0].message

    def test_target_status_regression(self):
        result = mutate(lambda r: r["targets"]["t"].update(status="failed", problems=["phase0 rc=1"]))
        assert "phase0 rc=1" in rows(result, "regression", "target")[0].message


@pytest.mark.unit
class TestBriefsControlArm:
    def with_samples(self, outcome: str) -> dict:
        run = make_run()
        run["briefs"] = {"samples": {"s-1": {"outcome": outcome}}}
        return run

    def test_proved_to_not_proved_is_a_regression(self):
        assert compare_runs(self.with_samples("proved"), self.with_samples("not_proved")).failed()

    def test_gain_is_an_improvement(self):
        result = compare_runs(self.with_samples("not_proved"), self.with_samples("proved"))
        assert rows(result, "improvement", "briefs")

    def test_one_sided_is_not_compared(self):
        assert rows(compare_runs(make_run(), self.with_samples("proved")), "not_compared", "briefs")


@pytest.mark.unit
class TestOutput:
    def test_recall_regression_is_printed_first(self):
        base = make_run()
        cur = copy.deepcopy(base)
        cur["recall"]["bugs"]["BUG-1"] = bug_entry("lost")
        mod_eva(cur).update(unknown=20, valid=80)
        text = render_text(compare_runs(base, cur))
        assert text.startswith("RECALL REGRESSION")
        assert text.index("BUG-1") < text.index("[eva]")

    def test_info_rows_are_hidden_unless_verbose(self):
        result = mutate(lambda r: r["toolchain"].update({"frama-c": "35.0"}))
        assert "[toolchain]" not in render_text(result)
        assert "[toolchain]" in render_text(result, verbose=True)

    def test_json_form_has_counts_and_recall_flag(self):
        result = mutate(lambda r: r["recall"]["bugs"].__setitem__("BUG-1", bug_entry("lost")))
        doc = result.to_json()
        assert doc["recall_regression"] is True
        assert doc["counts"]["regression"] >= 1


@pytest.mark.unit
class TestCli:
    def write(self, tmp_path, name: str, run: dict):
        path = tmp_path / name
        path.write_text(json.dumps(run), encoding="utf-8")
        return str(path)

    def test_exit_codes(self, tmp_path, capsys):
        base = make_run()
        same = self.write(tmp_path, "same.json", base)
        assert main([same, same]) == 0

        lost = copy.deepcopy(base)
        lost["recall"]["bugs"]["BUG-1"] = bug_entry("lost")
        assert main([same, self.write(tmp_path, "lost.json", lost)]) == 1
        assert "BUG-1" in capsys.readouterr().out

    def test_fail_on_warning(self, tmp_path):
        base = make_run()
        warned = copy.deepcopy(base)
        warned["targets"]["t"]["harness_digest"] = "h2"
        args = [self.write(tmp_path, "a.json", base), self.write(tmp_path, "b.json", warned)]
        assert main(args) == 0
        assert main([*args, "--fail-on", "warning"]) == 1

    def test_unreadable_or_foreign_input_exits_2(self, tmp_path):
        good = self.write(tmp_path, "good.json", make_run())
        bad = tmp_path / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        assert main([good, str(bad)]) == 2
        assert main([good, self.write(tmp_path, "foreign.json", {"x": 1})]) == 2
        assert main([good, str(tmp_path / "missing.json")]) == 2

    def test_json_output_file(self, tmp_path):
        good = self.write(tmp_path, "good.json", make_run())
        out = tmp_path / "diff.json"
        assert main([good, good, "--json", str(out)]) == 0
        assert json.loads(out.read_text(encoding="utf-8"))["recall_regression"] is False
