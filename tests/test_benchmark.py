from __future__ import annotations

import copy
import json
import subprocess
from pathlib import Path

import pytest

import benchmark
from benchmark import (
    BenchmarkError,
    annotate_replays,
    assert_no_host_paths,
    classify_replay,
    content_digest,
    decide_bug,
    eva_site_status,
    fetch_targets,
    harness_digest,
    in_scope_file,
    load_manifest,
    merge_runs,
    recall_block,
    replay_outcomes,
    scrub_host_paths,
    select_targets,
    summarize_candidates,
    summarize_eva,
    summarize_fuzz,
    summarize_phase3,
    summarize_queue,
    summarize_units,
    unit_bucket,
    validate_manifest,
    validate_run,
    verifier_result,
    wrapper_argv,
)
from run_eacsl_fuzz import DEFAULT_PER_INPUT_TIMEOUT_S
from validate_artifacts import validate_agent_result

EXPECTED = {"file": "minmea.c", "function": "f", "alarm_kind": "signed_overflow", "lines": [10, 20]}


def artifact(**over) -> dict:
    base = {
        "reproducible": True,
        "timed_out": False,
        "returncode": 77,
        "failure": {"file": "workspace/work/minmea.c", "line": 10, "function": "f", "alarm_kind": "signed_overflow"},
    }
    base.update(over)
    return base


@pytest.mark.unit
class TestClassifyReplay:
    def test_expected_site_is_reproduced(self):
        assert classify_replay(artifact(), EXPECTED) == ("reproduced", None)

    def test_any_recorded_line_counts(self):
        failure = {"file": "minmea.c", "line": 20, "function": "f", "alarm_kind": "signed_overflow"}
        assert classify_replay(artifact(failure=failure), EXPECTED)[0] == "reproduced"

    def test_earlier_false_alarm_is_not_a_reproduction(self):
        # What E-ACSL with -rte-initialized does on the minmea inputs: it stops at \initialized(&endptr).
        failure = {
            "file": "workspace/work/minmea.c",
            "line": 224,
            "function": "minmea_scan",
            "alarm_kind": None,
            "kind": "e_acsl_rte",
        }
        outcome, reason = classify_replay(artifact(failure=failure), EXPECTED)
        assert outcome == "mismatch"
        assert "minmea_scan" in str(reason)

    def test_other_line_of_the_right_function_is_a_mismatch(self):
        failure = {"file": "minmea.c", "line": 99, "function": "f", "alarm_kind": "signed_overflow"}
        outcome, reason = classify_replay(artifact(failure=failure), EXPECTED)
        assert outcome == "mismatch" and "99" in str(reason)

    def test_clean_run_is_not_reproduced(self):
        outcome, _ = classify_replay(artifact(reproducible=False, returncode=0, failure=None), EXPECTED)
        assert outcome == "not_reproduced"

    def test_crash_without_a_parsed_report_is_a_mismatch(self):
        assert classify_replay(artifact(failure=None), EXPECTED)[0] == "mismatch"

    def test_timeout_and_missing_result_are_tool_failures(self):
        assert classify_replay(artifact(timed_out=True), EXPECTED)[0] == "tool_failure"
        assert classify_replay(None, EXPECTED)[0] == "tool_failure"


def unit(cid="a.c#f::rte", status="planned", wave=0, cls="rte", evidence=()) -> dict:
    return {
        "coverage_id": cid,
        "status": status,
        "wave": wave,
        "obligation_class": cls,
        "evidence": [{"phase": p, "result": r} for p, r in evidence],
    }


@pytest.mark.unit
class TestUnits:
    @pytest.mark.parametrize(
        ("status", "evidence", "bucket"),
        [
            ("covered", [("eva", "eva_all_valid")], "proved"),
            ("candidate", [("fuzz", "fuzz_failure")], "not_proved"),
            ("deferred", [], "excluded"),
            ("out_of_scope", [], "excluded"),
            ("planned", [("eva", "eva_unknown")], "not_proved"),
            ("planned", [("eva", "eva_analysis_error")], "tool_failure"),
            ("planned", [("eva", "eva_dead")], "not_reached"),
            ("planned", [("eva", "eva_no_properties")], "not_reached"),
            ("planned", [("fuzz", "fuzz_clean")], "not_attempted"),
            ("planned", [], "not_attempted"),
            ("blocked", [("wp", "wp_unproven")], "not_proved"),
            ("blocked", [("wp", "wp_analysis_error")], "tool_failure"),
            ("blocked", [], "not_proved"),
            ("planned", [("eva", "eva_analysis_error"), ("wp", "wp_unproven")], "not_proved"),
        ],
    )
    def test_buckets(self, status, evidence, bucket):
        assert unit_bucket(unit(status=status, evidence=evidence)) == bucket

    def test_rates_per_wave_keep_both_denominators(self):
        ledger = [
            unit("a.c#a::rte", "covered", 0, evidence=[("eva", "eva_all_valid")]),
            unit("a.c#b::rte", "planned", 0, evidence=[("eva", "eva_unknown")]),
            unit("a.c#c::rte", "planned", 0, evidence=[("eva", "eva_analysis_error")]),
            unit("a.c#d::rte", "covered", 1, evidence=[("eva", "eva_all_valid")]),
            unit("a.c#e::rte", "deferred", 1),
            unit("a.c#f::l2_termination", "planned", 1, cls="l2_termination"),
        ]
        summary = summarize_units(ledger)
        wave0 = summary["by_wave"]["0"]
        assert wave0["over_decided"] == 0.5
        assert wave0["strict"] == pytest.approx(0.3333)
        assert summary["by_wave"]["1"]["strict"] == 1.0
        assert summary["by_wave"]["1"]["not_attempted"] == 1
        assert summary["excluded"] == 1
        assert summary["total"]["tool_failure"] == 1
        assert summary["covered"] == ["a.c#a::rte", "a.c#d::rte"]
        assert "l2_termination" in summary["by_class"]

    def test_unknown_wave_has_its_own_row(self):
        assert "none" in summarize_units([unit(wave=None, evidence=[("eva", "eva_unknown")])])["by_wave"]


def bug_spec() -> dict:
    return {
        "id": "BUG",
        "replays": [
            {"target": "t1", "module": "m", "engine": "sanitizers", "required": True},
            {"target": "t2", "module": "m", "engine": "sanitizers", "required": True},
            {"target": "t1", "module": "m", "engine": "eacsl", "required": False},
        ],
    }


def record(outcome="reproduced", gate="confirmed", reason=None) -> dict:
    return {"outcome": outcome, "gate": gate, "reason": reason, "observed": {"fingerprint": "fp"}}


@pytest.mark.unit
class TestDecideBug:
    def test_retained_needs_every_required_replay_and_the_gate(self):
        outcomes = {("t1", "m", "sanitizers"): record(), ("t2", "m", "sanitizers"): record()}
        result = decide_bug(bug_spec(), outcomes)
        assert result["status"] == "retained"
        assert result["partial"] is False

    def test_nothing_selected_is_not_run(self):
        assert decide_bug(bug_spec(), {})["status"] == "not_run"

    def test_one_selected_revision_is_marked_partial(self):
        result = decide_bug(bug_spec(), {("t1", "m", "sanitizers"): record()})
        assert result["status"] == "retained"
        assert result["partial"] is True

    def test_informational_engine_never_decides(self):
        outcomes = {
            ("t1", "m", "sanitizers"): record(),
            ("t2", "m", "sanitizers"): record(),
            ("t1", "m", "eacsl"): record("not_reproduced", gate=None),
        }
        assert decide_bug(bug_spec(), outcomes)["status"] == "retained"

    def test_mismatch_is_lost_with_the_reason(self):
        outcomes = {
            ("t1", "m", "sanitizers"): record("mismatch", reason="failed at x.c:1"),
            ("t2", "m", "sanitizers"): record(),
        }
        result = decide_bug(bug_spec(), outcomes)
        assert result["status"] == "lost"
        assert "x.c:1" in result["reason"]

    def test_tool_failure_is_undecided(self):
        outcomes = {
            ("t1", "m", "sanitizers"): record("tool_failure", reason="compile_error"),
            ("t2", "m", "sanitizers"): record(),
        }
        assert decide_bug(bug_spec(), outcomes)["status"] == "undecided"

    def test_decided_loss_outranks_a_tool_failure(self):
        outcomes = {
            ("t1", "m", "sanitizers"): record("tool_failure"),
            ("t2", "m", "sanitizers"): record("not_reproduced"),
        }
        assert decide_bug(bug_spec(), outcomes)["status"] == "lost"

    def test_filtered_at_ingestion_is_lost_even_though_it_reproduced(self):
        outcomes = {("t1", "m", "sanitizers"): record(gate="filtered_at_ingest"), ("t2", "m", "sanitizers"): record()}
        result = decide_bug(bug_spec(), outcomes)
        assert result["status"] == "lost"
        assert "filtered_at_ingest" in result["reason"]

    def test_gate_rejection_is_lost(self):
        outcomes = {("t1", "m", "sanitizers"): record(gate="rejected"), ("t2", "m", "sanitizers"): record()}
        assert decide_bug(bug_spec(), outcomes)["status"] == "lost"


@pytest.mark.unit
def test_replay_outcomes_join_only_required_replays_to_the_gate():
    replay_doc = {
        "results": [
            {"bug": "B", "module": "m", "engine": "sanitizers", "required": True, "outcome": "reproduced"},
            {"bug": "B", "module": "m", "engine": "eacsl", "required": False, "outcome": "reproduced"},
        ]
    }
    gate_doc = {"results": {"B": {"gate": "confirmed"}}}
    joined = replay_outcomes("t", replay_doc, gate_doc)["B"]
    assert joined[("t", "m", "sanitizers")]["gate"] == "confirmed"
    assert joined[("t", "m", "eacsl")]["gate"] is None


@pytest.mark.unit
def test_recall_block_counts_not_run_outside_both_rates():
    block = recall_block(
        {
            "A": {"status": "retained"},
            "B": {"status": "lost"},
            "C": {"status": "undecided"},
            "D": {"status": "not_run"},
        }
    )
    assert block["expected"] == 4
    assert block["retained"] == 1
    assert block["rates"]["over_decided"] == 0.5
    assert block["rates"]["strict"] == pytest.approx(0.3333)
    assert block["not_run"] == ["D"]


def eva_report(**over) -> dict:
    report = {
        "status": "ok",
        "valid_count": 3,
        "unknown_count": 4,
        "invalid_count": 1,
        "dead_count": 2,
        "assumed_count": 1,
        "total_properties": 8,
        "discharged_percentage": 37.5,
        "reduced_checks": [],
        "undeclared_functions": [],
        "unknown_obligations_by_function": {
            "parse": [{"directory": "workspace/work", "file": "src/a.c", "kind": "mem_access"}],
            "inner": [{"directory": "workspace/work", "file": "src/a.c", "kind": "signed_overflow"}],
            "strtol": [{"directory": "FRAMAC_SHARE/libc", "file": "stdlib.h", "kind": "precondition"}],
            "eva_main": [{"directory": "workspace/harnesses", "file": "harness_m.c", "kind": "initialization"}],
            "tool": [{"directory": "workspace/work", "file": "tools/b.c", "kind": "mem_access"}],
        },
        "invalid_alarms": [{"file": "src/a.c", "function": "parse", "kind": "shift", "annotation": "x < 32"}],
    }
    report.update(over)
    return report


@pytest.mark.unit
class TestSummarizeEva:
    def test_only_in_scope_target_code_costs_a_prover_task(self):
        block = summarize_eva(eva_report(), {"src/a.c#parse", "src/a.c#inner"}, ["src"])
        assert block["functions_with_unknown"] == ["src/a.c#inner", "src/a.c#parse"]
        assert set(block["other_functions_with_unknown"]) == {"strtol", "eva_main", "tool"}
        assert block["unknown_by_kind"]["mem_access"] == 2

    def test_static_renamed_for_another_translation_unit_counts_once(self):
        row = {"directory": "workspace/work", "file": "src/a.h", "kind": "mem_access"}
        report = eva_report(
            unknown_obligations_by_function={"inl": [row], "inl_0": [row], "real_2": [row]},
            functions_with_properties=["inl", "inl_0", "real_2"],
        )
        block = summarize_eva(report, set(), ["src"])
        assert block["functions_with_unknown"] == ["src/a.h#inl", "src/a.h#real_2"]

    def test_only_renamed_copies_analysed_map_to_the_ledger_unit(self):
        # A header static inline whose analysed copies were all renamed (`inl_0`): the ledger has `inl`.
        row = {"directory": "workspace/work", "file": "src/a.h", "kind": "mem_access"}
        report = eva_report(unknown_obligations_by_function={"inl_0": [row], "real_2": [row]})
        block = summarize_eva(report, {"src/a.h#inl", "src/a.h#real_2"}, ["src"])
        assert block["functions_with_unknown"] == ["src/a.h#inl", "src/a.h#real_2"]
        assert block["functions_with_unknown_no_unit"] == []

    def test_function_without_a_ledger_unit_is_reported_apart(self):
        # The x509-parser case: Eva reaches code whose functions the DAG never listed.
        block = summarize_eva(eva_report(), {"src/a.c#parse"}, ["src"])
        assert block["functions_with_unknown_no_unit"] == ["src/a.c#inner"]
        assert "src/a.c#inner" in block["functions_with_unknown"]

    def test_failed_analysis_has_no_counts(self):
        block = summarize_eva({"status": "analysis_timeout", "reason": None, "error_summary": ["limit"]}, set())
        assert block["status"] == "analysis_timeout"
        assert "unknown" not in block

    def test_invalid_alarms_are_identified_without_line_numbers(self):
        block = summarize_eva(eva_report(), set(), ["src"])
        assert len(block["invalid_ids"]) == 1
        assert block["invalid_ids"][0].startswith("src/a.c#parse::shift::")

    def test_coverage_is_read_from_the_log(self, tmp_path):
        (tmp_path / "eva.log").write_text(
            "  20 functions analyzed (out of 21): 95% coverage.\n  In these functions, 772 statements reached (out of 797): 97% coverage.\n",
            encoding="utf-8",
        )
        block = summarize_eva(eva_report(log_file="eva.log"), set(), ["src"], tmp_path)
        assert block["coverage"] == {
            "functions_analyzed": 20,
            "functions_total": 21,
            "statements_reached": 772,
            "statements_total": 797,
        }


@pytest.mark.unit
class TestEvaSiteStatus:
    def report(self, **over) -> dict:
        row = {"directory": "workspace/work", "file": "a.c", "function": "f", "line": "10", "kind": "shift"}
        base = {
            "status": "ok",
            "invalid_alarms": [],
            "dead_alarms": [],
            "unknown_obligations_by_function": {"f": [row]},
        }
        base.update(over)
        return base

    def test_unknown_at_the_recorded_line(self):
        assert eva_site_status(self.report(), "a.c", "f", [10]) == "unknown"

    def test_any_other_line_of_the_function_does_not_count(self):
        assert eva_site_status(self.report(), "a.c", "f", [11]) == "not_flagged"

    def test_same_named_function_in_another_file_does_not_count(self):
        assert eva_site_status(self.report(), "b.c", "f", [10]) == "not_flagged"

    def test_invalid_outranks_unknown(self):
        invalid = [{"directory": "workspace/work", "file": "a.c", "function": "f", "line": 10}]
        assert eva_site_status(self.report(invalid_alarms=invalid), "a.c", "f", [10]) == "invalid"

    def test_dead_code_is_not_flagged_as_a_bug(self):
        dead = [{"directory": "workspace/work", "file": "a.c", "function": "f", "line": 10}]
        report = self.report(dead_alarms=dead, unknown_obligations_by_function={})
        assert eva_site_status(report, "a.c", "f", [10]) == "dead"

    def test_no_analysis(self):
        assert eva_site_status(None, "a.c", "f", [10]) == "no_analysis"
        assert eva_site_status({"status": "analysis_error"}, "a.c", "f", [10]) == "no_analysis"


@pytest.mark.unit
def test_annotate_replays_adds_what_other_phases_saw(tmp_path):
    reports = tmp_path / "workspace" / "reports"
    (reports / "eva").mkdir(parents=True)
    (reports / "fuzz").mkdir(parents=True)
    row = {"directory": "workspace/work", "file": "a.c", "function": "f", "line": 10}
    (reports / "eva" / "m.json").write_text(
        json.dumps({"status": "ok", "unknown_obligations_by_function": {"f": [row]}}), encoding="utf-8"
    )
    (reports / "fuzz" / "m.json").write_text(
        json.dumps({"artifacts": [{"fingerprint": "a.c#f::shift::0123456789"}, {"fingerprint": None}]}),
        encoding="utf-8",
    )
    spec = {
        "replays": [
            {"bug": "B", "engine": "eacsl", "file": "a.c", "function": "f", "alarm_kind": "shift", "lines": [10]}
        ]
    }
    doc = annotate_replays({"results": [{"bug": "B", "engine": "eacsl", "module": "m"}]}, spec, tmp_path)
    assert doc["results"][0]["eva_site"] == "unknown"
    assert doc["results"][0]["found_by_campaign"] is True


@pytest.mark.unit
def test_in_scope_file_handles_files_directories_and_no_scope():
    assert in_scope_file("src/a.c", ["src"])
    assert in_scope_file("src/a.c", ["src/"])
    assert in_scope_file("a.c", ["a.c"])
    assert not in_scope_file("srcfoo/a.c", ["src"])
    assert in_scope_file("anything.c", [])


@pytest.mark.unit
class TestSmallSummaries:
    def test_fuzz_stub_reads_as_not_run(self):
        assert summarize_fuzz({"stub": True, "status": "not_run", "reason": "excluded"}) == {
            "status": "not_run",
            "reason": "excluded",
        }
        assert summarize_fuzz(None) is None

    def test_fuzz_collects_fingerprints_once(self):
        block = summarize_fuzz(
            {"status": "crash_found", "artifacts": [{"fingerprint": "x"}, {"fingerprint": "x"}, {"fingerprint": None}]}
        )
        assert block is not None
        assert block["fingerprints"] == ["x"]
        assert block["artifacts"] == 3

    def test_candidates_from_benchmark_replays_are_their_own_source(self):
        block = summarize_candidates(
            [
                {
                    "fingerprint": "a",
                    "origin": "fuzz",
                    "status": "verified",
                    "tool_outputs": ["workspace/reports/fuzz/bench-replay-m-eacsl.json"],
                },
                {
                    "fingerprint": "b",
                    "origin": "fuzz",
                    "status": "unverified",
                    "tool_outputs": ["workspace/reports/fuzz/m.json"],
                },
                {
                    "fingerprint": "c",
                    "origin": "eva",
                    "status": "unverified",
                    "tool_outputs": ["workspace/reports/eva/m.json"],
                },
            ]
        )
        assert block["fingerprints"] == {"eva": ["c"], "fuzz": ["b"], "replay": ["a"]}
        assert block["unverified"] == 2

    def test_queue_counts_only_pending_prover_tasks(self):
        queue = {
            "queue": [
                {"state": "pending", "wave": 0, "file": "a.c", "function": "f"},
                {"state": "pending", "wave": 1, "file": "a.c", "function": "g"},
                {"state": "skipped", "wave": 1, "file": "a.c", "function": "h"},
            ]
        }
        block = summarize_queue(queue)
        assert block["count"] == 2
        assert block["by_wave"] == {"0": 1, "1": 1}
        assert summarize_queue(None)["count"] == 0


@pytest.mark.unit
class TestPhase3:
    def setup_run(self, tmp_path: Path, tasks: dict) -> Path:
        (tmp_path / "state" / "resource-history" / "wp").mkdir(parents=True)
        (tmp_path / "workspace" / "reports" / "wp").mkdir(parents=True)
        (tmp_path / "state" / "wp_schedule.json").write_text(json.dumps({"tasks": tasks}), encoding="utf-8")
        return tmp_path

    def test_stalls_and_rates_two_ways(self, tmp_path):
        tasks = {
            "a": {"kind": "prove", "state": "done", "outcome": "merged", "wave": 0, "dispatches": 1},
            "b": {
                "kind": "prove",
                "state": "blocked",
                "outcome": "stalled_after_k_retries",
                "wave": 0,
                "dispatches": 2,
            },
            "c": {"kind": "prove", "state": "pending", "outcome": None, "wave": 1, "dispatches": 0},
            "d": {"kind": "prove", "state": "skipped", "outcome": "no_open_units", "wave": 1, "dispatches": 0},
            "e": {"kind": "breaker", "state": "done", "outcome": "clean"},
            "f": {"kind": "prove", "state": "skipped", "outcome": "candidate", "wave": 1, "dispatches": 0},
        }
        block = summarize_phase3(self.setup_run(tmp_path, tasks))
        assert block["stalls"] == 1
        assert block["function_rate"]["over_decided"] == 0.5
        assert block["function_rate"]["strict"] == pytest.approx(0.3333)
        assert block["function_rate_by_wave"]["1"]["undecided"] == 1
        assert block["dispatches"] == 3
        assert block["breakers"] == {"clean": 1}

    def test_tokens_only_when_the_host_reports_them(self, tmp_path):
        run = self.setup_run(tmp_path, {})
        assert summarize_phase3(run)["tokens"] is None
        usage = {"agents": {"p": {"input_tokens": 10, "output_tokens": 5, "iterations": 3}}}
        block = summarize_phase3(run, usage)
        assert block["tokens"] == {"input": 10, "output": 5, "source": "host"}
        assert block["iterations_host_reported"] == 3


@pytest.mark.unit
class TestManifest:
    def test_shipped_manifest_is_valid(self):
        assert validate_manifest(load_manifest()) == []

    def test_every_listed_bug_of_the_report_is_in_the_recall_set(self):
        index = (Path(benchmark.PIPELINE_ROOT) / "docs" / "bugs-found" / "README.md").read_text(encoding="utf-8")
        for bug in load_manifest()["bugs"]:
            assert f"`{bug['id']}`" in index
        assert len(load_manifest()["bugs"]) == 7

    def test_recorded_revisions_are_the_reported_ones(self):
        index = (Path(benchmark.PIPELINE_ROOT) / "docs" / "bugs-found" / "README.md").read_text(encoding="utf-8")
        for target in load_manifest()["targets"]:
            if target["set"] == "recall":
                assert target["revision"] in index

    def test_wrong_digest_is_found(self):
        manifest = copy.deepcopy(load_manifest())
        manifest["bugs"][0]["input_sha256"] = "0" * 64
        assert any("input_sha256" in p for p in validate_manifest(manifest))

    def test_dangling_module_is_found(self):
        manifest = copy.deepcopy(load_manifest())
        manifest["bugs"][0]["replays"][0]["module"] = "nope"
        assert any("unknown module" in p for p in validate_manifest(manifest))

    def test_bug_without_required_replay_is_found(self):
        manifest = copy.deepcopy(load_manifest())
        for replay in manifest["bugs"][0]["replays"]:
            replay["required"] = False
        assert any("no required replay" in p for p in validate_manifest(manifest))

    def test_missing_asset_is_found(self):
        manifest = copy.deepcopy(load_manifest())
        manifest["targets"][1]["assets"][0]["path"] = "missing/file.h"
        assert any("missing asset" in p for p in validate_manifest(manifest))

    def test_selection(self):
        manifest = load_manifest()
        assert {t["set"] for t in select_targets(manifest, ["recall"])} == {"recall"}
        assert len(select_targets(manifest)) == len(manifest["targets"])
        assert [t["id"] for t in select_targets(manifest, ["recall"], ["minmea"])] == ["minmea"]
        with pytest.raises(BenchmarkError):
            select_targets(manifest, ["all"], ["nope"])

    def test_harness_digest_follows_what_the_benchmark_decides(self):
        manifest = copy.deepcopy(load_manifest())
        target = manifest["targets"][0]
        before = harness_digest(target, manifest)
        assert harness_digest(target, manifest) == before
        target["modules"][0]["params"] = {"eva_slevel": 1}
        assert harness_digest(target, manifest) != before

    def test_replay_timeout_is_the_tools_own(self):
        assert benchmark.PER_INPUT_TIMEOUT_S == DEFAULT_PER_INPUT_TIMEOUT_S

    def test_content_digest_ignores_line_endings_and_caches(self, tmp_path):
        (tmp_path / "scripts" / "__pycache__").mkdir(parents=True)
        (tmp_path / "scripts" / "a.py").write_bytes(b"x\n")
        first = content_digest(tmp_path, ["scripts"])
        (tmp_path / "scripts" / "a.py").write_bytes(b"x\r\n")
        (tmp_path / "scripts" / "__pycache__" / "a.pyc").write_bytes(b"junk")
        assert content_digest(tmp_path, ["scripts"]) == first
        (tmp_path / "scripts" / "a.py").write_bytes(b"y\n")
        assert content_digest(tmp_path, ["scripts"]) != first


@pytest.mark.unit
class TestHostPaths:
    @pytest.mark.parametrize("value", [r"C:\Users\me\x", "/home/me/x", "/Users/me/x"])
    def test_host_paths_are_refused(self, value):
        with pytest.raises(BenchmarkError):
            assert_no_host_paths({"a": [{"b": value}]})

    def test_container_paths_are_fine(self):
        assert_no_host_paths({"a": "/framac-run/workspace/work/a.c", "b": ["workspace/reports"]})

    def test_scrub(self):
        out = scrub_host_paths({"a": [r"see C:\w\runs\x and C:/w/runs/y"]}, [(r"C:\w", "<work>")])
        assert out == {"a": ["see <work>\\runs\\x and <work>/runs/y"]}


def run_doc(run_id: str, targets: dict, bugs: dict) -> dict:
    return {
        "schema_version": 1,
        "run_id": run_id,
        "created_at": "now",
        "pipeline": {"commit": run_id},
        "toolchain": {},
        "machine": {},
        "limits": {},
        "targets": targets,
        "recall": recall_block(bugs),
        "briefs": None,
        "totals": {},
    }


@pytest.mark.unit
def test_merge_runs_keeps_later_targets_and_decided_bugs():
    first = run_doc(
        "r1",
        {"a": {"wall_s": 1, "cpu_s": 1}, "b": {"wall_s": 2, "cpu_s": 2}},
        {"X": {"status": "retained"}, "Y": {"status": "not_run"}},
    )
    second = run_doc("r2", {"b": {"wall_s": 5, "cpu_s": 5}}, {"X": {"status": "not_run"}, "Y": {"status": "retained"}})
    merged = merge_runs([first, second])
    assert merged["targets"]["b"]["wall_s"] == 5
    assert merged["targets"]["a"]["wall_s"] == 1
    assert merged["recall"]["retained"] == 2
    assert merged["recall"]["not_run"] == []
    assert merged["totals"]["wall_s"] == 6
    assert merged["run_id"] == "r2"


@pytest.mark.unit
class TestSummaryOutput:
    def run(self) -> dict:
        bugs: dict[str, dict] = {
            "A": {"status": "retained", "replays": [{"required": True, "fingerprint_as_recorded": True}]},
            "B": {"status": "retained", "replays": [{"required": True, "fingerprint_as_recorded": False}]},
            "C": {"status": "not_run", "replays": []},
        }
        target = {
            "status": "ok",
            "functions_with_unknown_count": 2,
            "functions_with_unknown_no_unit": ["a.c#hidden"],
            "prover_tasks": {"count": 1},
            "units": {"total": {"passed": 1, "over_decided": 0.5, "strict": 0.25}},
            "wall_s": 1,
            "cpu_s": 2,
            "modules": {
                "good": {
                    "eva": {
                        "status": "ok",
                        "valid": 9,
                        "unknown": 8,
                        "invalid": 7,
                        "dead": 6,
                        "functions_with_unknown_count": 2,
                    }
                },
                "bad": {"eva": {"status": "analysis_timeout"}},
            },
        }
        return {
            "run_id": "r",
            "toolchain": {"frama-c": "34"},
            "totals": {"wall_s": 1, "cpu_s": 2},
            "recall": recall_block(bugs),
            "targets": {"t": target},
            "selection": {"targets_not_run": {"u": "fetch failed: x"}},
        }

    def test_says_what_was_kept_measured_and_not_run(self, capsys):
        benchmark.print_summary(self.run())
        out = capsys.readouterr().out
        assert "2/3 retained" in out
        assert "not run ['C']" in out
        assert "Valid 9, Unknown 8, Invalid 7, Dead 6" in out
        assert "Eva analysis_timeout" in out
        assert "no ledger unit" in out
        assert "u: NOT RUN (fetch failed: x)" in out

    def test_names_bugs_whose_fingerprint_drifted_from_the_report(self, capsys):
        benchmark.print_summary(self.run())
        assert "docs/bugs-found records: B" in capsys.readouterr().out


@pytest.mark.unit
class TestWrapperArgv:
    def test_posix_keeps_the_shared_cache_off(self, monkeypatch, tmp_path):
        monkeypatch.setattr(benchmark, "_is_windows", lambda: False)
        argv = wrapper_argv(tmp_path, tmp_path, "r", cls="eva", packages="p q")
        assert argv[0] == "bash"
        assert argv[argv.index("--cache-dir") + 1] == "off"
        assert argv[argv.index("--class") + 1] == "eva"
        assert argv[argv.index("--target-packages") + 1] == "p q"

    def test_windows_uses_powershell_with_the_cache_off(self, monkeypatch, tmp_path):
        monkeypatch.setattr(benchmark, "_is_windows", lambda: True)
        monkeypatch.setattr(benchmark.shutil, "which", lambda name: f"C:/bin/{name}.exe" if name == "pwsh" else None)
        argv = wrapper_argv(tmp_path, tmp_path, "r", image="framac-pipeline:r")
        assert "framac-docker.ps1" in argv[5]
        assert argv[argv.index("-CacheDir") + 1] == "off"
        assert argv[argv.index("-Image") + 1] == "framac-pipeline:r"

    def test_nothing_sizes_a_container(self, monkeypatch, tmp_path):
        monkeypatch.setattr(benchmark, "_is_windows", lambda: False)
        argv = wrapper_argv(tmp_path, tmp_path, "r")
        assert not {"--cpus", "--memory", "--pids-limit", "-j"} & set(argv)


@pytest.mark.unit
def test_harness_arguments_keep_leading_dash_values_bound():
    module = {
        "name": "m",
        "harness": {
            "sources": ["a.c"],
            "header": "a.h",
            "entry_fn": "f",
            "cppflags": "-I. -DX=1",
            "ldflags": "-lm",
            "call_expr": "f();",
            "null_terminate": True,
            "extra_includes": ["b.h"],
        },
    }
    argv = benchmark._harness_argv(module)
    assert "--cppflags=-I. -DX=1" in argv
    assert "--ldflags=-lm" in argv
    assert "--call-expr=f();" in argv
    assert "--null-terminate" in argv
    assert argv[argv.index("--extra-include") + 1] == "b.h"
    assert "--include-source" not in argv


@pytest.mark.unit
def test_mechanical_verifier_result_passes_the_agent_result_contract(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    input_path = Path("workspace/crashes/m/crash-x")
    input_path.parent.mkdir(parents=True)
    input_path.write_bytes(b"abc")
    item = {
        "bug": "MINMEA-01",
        "module": "m",
        "title": "Title",
        "alarm_kind": "signed_overflow",
        "reachability": "untrusted_surface",
        "severity": "medium",
        "verdict": {
            "description": "d",
            "root_cause": "r",
            "intended_behavior": "i",
            "severity_rationale": "s",
            "remediation_summary": "rs",
            "remediation_invariant": "ri",
        },
    }
    replay = {
        "engine": "sanitizers",
        "observed": {
            "file": "a.c",
            "line": 3,
            "function": "f",
            "alarm_kind": "signed_overflow",
            "predicate": "rte: signed_overflow: x",
            "fingerprint": "a.c#f::signed_overflow::0123456789",
        },
    }
    candidate = {"linked_units": ["a.c#f::rte"]}
    result = verifier_result(item, replay, candidate, {"entry_fn": "f"}, "workspace/reports/fuzz/r.json", input_path)
    assert result["agent_id"] == "bench-gate-minmea-01"
    assert list(validate_agent_result(result)) == []
    assert result["record"]["reproducers"][0]["size_bytes"] == 3


def _git(path: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "commit.gpgsign=false", *args], cwd=path, check=True, capture_output=True, text=True
    ).stdout.strip()


@pytest.mark.unit
class TestFetch:
    def make_repo(self, tmp_path: Path) -> tuple[Path, str]:
        repo = tmp_path / "upstream"
        (repo / "one").mkdir(parents=True)
        (repo / "two").mkdir()
        _git(repo, "init", "-q")
        _git(repo, "config", "user.email", "t@example.com")
        _git(repo, "config", "user.name", "t")
        _git(repo, "config", "core.autocrlf", "false")
        (repo / "one" / "a.c").write_bytes(b"int a;\r\n")  # CRLF must survive byte for byte
        (repo / "two" / "b.c").write_text("int b;\n", encoding="utf-8")
        _git(repo, "add", ".")
        _git(repo, "commit", "-q", "-m", "x")
        return repo, _git(repo, "rev-parse", "HEAD")

    def test_checkout_is_pinned_sparse_and_byte_exact(self, tmp_path):
        repo, rev = self.make_repo(tmp_path)
        base = {"url": repo.as_uri(), "revision": rev, "checkout": "co"}
        targets = [{**base, "id": "one", "subdir": "one"}, {**base, "id": "two", "subdir": "two"}]
        manifest = {"targets": targets}
        work = tmp_path / "work"
        assert fetch_targets(targets[:1], work, manifest) == {}
        co = work / "targets" / "co"
        assert _git(co, "rev-parse", "HEAD") == rev
        assert (co / "one" / "a.c").read_bytes() == b"int a;\r\n"
        # The other target of the manifest stays available, so selecting one never drops another's files.
        assert (co / "two" / "b.c").is_file()
        assert fetch_targets(targets, work, manifest) == {}

    def test_unknown_revision_is_reported_per_target(self, tmp_path):
        repo, _rev = self.make_repo(tmp_path)
        target = {"id": "x", "url": repo.as_uri(), "revision": "f" * 40, "checkout": "co"}
        problems = fetch_targets([target], tmp_path / "work", {"targets": [target]})
        assert "x" in problems


@pytest.mark.unit
class TestRunSchema:
    def minimal_run(self) -> dict:
        rate = {"passed": 0, "failed": 0, "undecided": 0, "over_decided": None, "strict": None}
        return {
            "schema_version": 1,
            "run_id": "r",
            "created_at": "now",
            "mode": "deterministic",
            "pipeline": {"commit": None, "dirty": None, "content_digest": "0" * 64},
            "toolchain": {},
            "machine": {},
            "limits": {"wp_memlimit_mb": 1000, "fuzz_rss_limit_mb": 2048, "replay_per_input_timeout_s": 10},
            "selection": {},
            "targets": {
                "t": {
                    "set": "recall",
                    "revision": "a" * 40,
                    "harness_digest": "b" * 64,
                    "status": "ok",
                    "problems": [],
                    "stages": {},
                    "wall_s": 1.0,
                    "cpu_s": 1.0,
                    "dag": {},
                    "modules": {"m": {"eva": {"status": "ok"}, "fuzz": None, "build": None}},
                    "functions_with_unknown": [],
                    "functions_with_unknown_count": 0,
                    "functions_with_unknown_no_unit": [],
                    "prover_tasks": {},
                    "units": {"total": rate, "by_wave": {"0": rate}, "by_class": {}, "covered": [], "candidate": []},
                    "candidates": {},
                }
            },
            "recall": {
                "expected": 0,
                "retained": 0,
                "lost": [],
                "undecided": [],
                "not_run": [],
                "rates": rate,
                "bugs": {},
            },
            "briefs": None,
            "totals": {"wall_s": 1.0, "cpu_s": 1.0},
        }

    def test_valid_run_passes(self):
        assert validate_run(self.minimal_run()) == []

    def test_missing_metric_is_refused(self):
        run = self.minimal_run()
        del run["targets"]["t"]["units"]["by_wave"]
        assert any("by_wave" in p for p in validate_run(run))

    def test_wrong_status_is_refused(self):
        run = self.minimal_run()
        run["recall"]["bugs"]["B"] = {"status": "maybe", "replays": []}
        assert validate_run(run)


@pytest.mark.unit
def test_modules_without_harness_ignores_excluded_units():
    ledger = [
        {**unit("a.c#a::rte", "planned", evidence=[("eva", "eva_unknown")]), "module": "covered"},
        {**unit("b.c#b::rte", "planned"), "module": "forgotten"},
        {**unit("c.c#c::rte", "deferred"), "module": "tier3"},
    ]
    assert benchmark.modules_without_harness(ledger, {"modules": [{"name": "covered"}]}) == ["forgotten"]


@pytest.mark.unit
def test_wave_with_only_excluded_units_has_no_row():
    assert summarize_units([unit(status="deferred", wave=7)])["by_wave"] == {}
