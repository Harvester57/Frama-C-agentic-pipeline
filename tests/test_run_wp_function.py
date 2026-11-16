"""Tests for run_wp_function: vacuity classification, proven goals backstop, missing spec detection, message folding."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

import run_wp_function as W

CSV_HEADER = "directory\tfile\tfunction\tline\tkind\tstatus\tproperty\n"


# ---------------------------------------------------------------------------
# Feature A2: Vacuity Log Classification
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_vacuity_doomed_requires_arbitrary_model_prefix() -> None:
    # Model: bytes
    log_bytes = "[wp] [Failed] (Doomed) bytes_doomed_wp_smoke_default_requires (Qed)\n  Smoke Tests: 0 / 1\n"
    res = W.classify_vacuity_log(log_bytes)
    assert res["status"] == "contradictory"
    assert res["doomed"] == ["default"]

    # Model: hoare
    log_hoare = "[wp] [Failed] (Doomed) hoare_fn_wp_smoke_b1_requires (Alt-Ergo)\n  Smoke Tests: 1 / 2\n"
    res = W.classify_vacuity_log(log_hoare)
    assert res["status"] == "contradictory"
    assert res["doomed"] == ["b1"]

    # Model: typed_caveat
    log_caveat = "[wp] [Failed] (Doomed) typed_caveat_fn_wp_smoke_my_clause_requires (Qed)\n  Smoke Tests: 0 / 2\n"
    res = W.classify_vacuity_log(log_caveat)
    assert res["status"] == "contradictory"
    assert res["doomed"] == ["my_clause"]


@pytest.mark.unit
def test_vacuity_doomed_dead_goals_arbitrary_model_and_local_init() -> None:
    # Dead code under bytes model
    log_dead_bytes = "[wp] [Failed] (Doomed) bytes_fn_wp_smoke_dead_code_s4 (Qed)\n  Smoke Tests: 1 / 2\n"
    res = W.classify_vacuity_log(log_dead_bytes)
    assert res["status"] == "consistent"
    assert res["dead_goals"] == 1

    # Dead local init under typed model
    log_local_init = "[wp] [Failed] (Doomed) typed_fn_wp_smoke_dead_local_init_s1 (Qed)\n  Smoke Tests: 2 / 3\n"
    res = W.classify_vacuity_log(log_local_init)
    assert res["status"] == "consistent"
    assert res["dead_goals"] == 1


@pytest.mark.unit
def test_vacuity_fails_closed_when_smoke_k_less_than_n_and_no_goals_recognised() -> None:
    # Smoke tests failed (0/2) but no doomed requires or dead goals in log
    log_unrecognised_fail = "[wp] 2 goals scheduled\n  Smoke Tests: 0 / 2\n"
    res = W.classify_vacuity_log(log_unrecognised_fail, returncode=0)
    assert res["status"] == "inconclusive"
    assert "without recognised doomed goals" in res.get("reason", "")

    # Smoke tests failed (1/3) with no doomed requires or dead goals
    log_partial_fail = "[wp] 3 goals scheduled\n  Smoke Tests: 1 / 3\n"
    res = W.classify_vacuity_log(log_partial_fail, returncode=0)
    assert res["status"] == "inconclusive"


@pytest.mark.unit
def test_vacuity_consistent_when_smoke_k_equals_n() -> None:
    log_clean = "[wp] 3 goals scheduled\n  Smoke Tests: 3 / 3\n"
    res = W.classify_vacuity_log(log_clean, returncode=0)
    assert res["status"] == "consistent"
    assert res["doomed"] == []
    assert res["dead_goals"] == 0


@pytest.mark.unit
def test_vacuity_fails_closed_on_malformed_smoke_summary() -> None:
    log_malformed = "[wp] Smoke Tests: invalid / format\n"
    res = W.classify_vacuity_log(log_malformed, returncode=0)
    assert res["status"] == "inconclusive"
    assert "malformed" in res.get("reason", "")


@pytest.mark.unit
def test_vacuity_fails_closed_on_invalid_smoke_ratio_bounds() -> None:
    # k > n
    res_exceed = W.classify_vacuity_log("Smoke Tests: 2 / 1\n", returncode=0)
    assert res_exceed["status"] == "inconclusive"
    assert res_exceed["reason"] == "invalid smoke test counts (2/1)"

    # n == 0
    res_zero = W.classify_vacuity_log("Smoke Tests: 0 / 0\n", returncode=0)
    assert res_zero["status"] == "inconclusive"
    assert res_zero["reason"] == "invalid smoke test counts (0/0)"

    # n == 0 with k > 0
    res_div_zero = W.classify_vacuity_log("Smoke Tests: 1 / 0\n", returncode=0)
    assert res_div_zero["status"] == "inconclusive"
    assert res_div_zero["reason"] == "invalid smoke test counts (1/0)"


@pytest.mark.unit
def test_vacuity_fails_closed_on_unexplained_failed_smoke_tests() -> None:
    # 2 failures, only 1 dead goal -> 1 unexplained failure
    log_unexplained = (
        "[wp] [Failed] (Doomed) typed_f_wp_smoke_dead_code_s1 (Qed)\n"
        "Smoke Tests: 1 / 3\n"
    )
    res = W.classify_vacuity_log(log_unexplained, returncode=0)
    assert res["status"] == "inconclusive"
    assert res["reason"] == "smoke test failure (1/3) without recognised doomed goals"
    assert res["dead_goals"] == 1


@pytest.mark.unit
def test_vacuity_consistent_when_all_failures_explained_by_dead_goals() -> None:
    # 2 failures, exactly 2 dead goals -> 0 unexplained failures
    log_explained = (
        "[wp] [Failed] (Doomed) typed_f_wp_smoke_dead_code_s4 (Qed)\n"
        "[wp] [Failed] (Doomed) typed_log_err_wp_smoke_dead_call_s3 (Qed)\n"
        "  Smoke Tests:     6 / 8\n"
    )
    res = W.classify_vacuity_log(log_explained, returncode=0)
    assert res["status"] == "consistent"
    assert res["dead_goals"] == 2
    assert res["doomed"] == []


# ---------------------------------------------------------------------------
# Feature A3: WP Proven Goals Backstop
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_wp_backstop_report_csv_present_without_proved_goals_returns_unproven(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out_dir = tmp_path / "wp"
    out_dir.mkdir()
    c_file = tmp_path / "f.c"
    c_file.write_text("int f(int x) { return x; }\n", encoding="utf-8")

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if "-wp" in cmd and "-report-csv" in cmd:
            csv_path = Path(cmd[cmd.index("-report-csv") + 1])
            csv_path.write_text(CSV_HEADER + ".\tf.c\tf\t1\trte: mem_access\tValid\tx\n", encoding="utf-8")
            # Log missing 'Proved goals:' line!
            return subprocess.CompletedProcess(cmd, 0, stdout="[wp] 1 goal scheduled\n", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(W.subprocess, "run", fake_run)
    res = W.run_wp_on_function(c_file, "f", out_dir, retry_bitwise=False)
    assert res["status"] == "unproven_goals_remain"


@pytest.mark.unit
def test_wp_backstop_report_csv_present_with_zero_goals_proved_returns_unproven(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out_dir = tmp_path / "wp"
    out_dir.mkdir()
    c_file = tmp_path / "f.c"
    c_file.write_text("int f(int x) { return x; }\n", encoding="utf-8")

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if "-wp" in cmd and "-report-csv" in cmd:
            csv_path = Path(cmd[cmd.index("-report-csv") + 1])
            csv_path.write_text(CSV_HEADER + ".\tf.c\tf\t1\trte: mem_access\tValid\tx\n", encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout="[wp] Proved goals:    0 / 0\n", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(W.subprocess, "run", fake_run)
    res = W.run_wp_on_function(c_file, "f", out_dir, retry_bitwise=False)
    assert res["status"] == "unproven_goals_remain"


@pytest.mark.unit
def test_wp_backstop_degenerated_goal_waiver_requires_proved_goals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out_dir = tmp_path / "wp"
    out_dir.mkdir()
    c_file = tmp_path / "f.c"
    c_file.write_text("int f(int (*fp)(void)) { return fp(); }\n", encoding="utf-8")

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if "-wp" in cmd and "-report-csv" in cmd:
            csv_path = Path(cmd[cmd.index("-report-csv") + 1])
            csv_path.write_text(
                CSV_HEADER + ".\tf.c\tf\t1\tpointer_value\tUnknown\t\\valid_function(fp)\n",
                encoding="utf-8",
            )
            stdout = "[wp] [Timeout] typed_f_assert_rte_pointer_value (Qed) (Degenerated)\n"
            return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(W.subprocess, "run", fake_run)
    res = W.run_wp_on_function(c_file, "f", out_dir, retry_bitwise=False)
    assert res["status"] == "unproven_goals_remain"


@pytest.mark.unit
def test_wp_backstop_valid_proved_goals_returns_all_proven(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out_dir = tmp_path / "wp"
    out_dir.mkdir()
    c_file = tmp_path / "f.c"
    c_file.write_text("int f(int x) { return x; }\n", encoding="utf-8")

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if "-wp" in cmd and "-report-csv" in cmd:
            csv_path = Path(cmd[cmd.index("-report-csv") + 1])
            csv_path.write_text(CSV_HEADER + ".\tf.c\tf\t1\trte: mem_access\tValid\tx\n", encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout="[wp] Proved goals:    1 / 1\n", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(W.subprocess, "run", fake_run)
    res = W.run_wp_on_function(c_file, "f", out_dir, retry_bitwise=False)
    assert res["status"] == "all_proven"


# ---------------------------------------------------------------------------
# Feature A1: Missing Spec Detection
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_missing_spec_soundness_detection_variants() -> None:
    bad_spec = (
        "[kernel:annot:missing-spec] a.c:2: Warning:\n"
        "  Neither code nor specification for function ext_fn, generating default exits, assigns and terminates.\n"
    )
    bad_assigns = (
        "[kernel:annot:missing-spec] a.c:2: Warning:\n"
        "  Neither code nor explicit assigns for function set_shared, generating default clauses.\n"
    )
    bad_mixed = (
        "[kernel:annot:missing-spec] a.c:2: Warning:\n"
        "  Neither code nor explicit exits, assigns and terminates for function set_shared, generating default clauses.\n"
    )
    bad_unrec = (
        "[kernel:annot:missing-spec] a.c:2: Warning:\n"
        "  Neither code nor foo for function weird_fn, generating default clauses.\n"
    )

    assert W.scan_wp_log_soundness(bad_spec)["ok"] is False
    assert W.scan_wp_log_soundness(bad_assigns)["ok"] is False
    assert W.scan_wp_log_soundness(bad_mixed)["ok"] is False
    assert W.scan_wp_log_soundness(bad_unrec)["ok"] is False

    # Benign exits/terminates must remain sound
    good_both = (
        "[kernel:annot:missing-spec] string.h:170: Warning:\n"
        "  Neither code nor explicit exits and terminates for function memset, generating default clauses.\n"
    )
    good_term = (
        "[kernel:annot:missing-spec] string.h:170: Warning:\n"
        "  Neither code nor explicit terminates for function bar, generating default clauses.\n"
    )
    good_exits = (
        "[kernel:annot:missing-spec] string.h:170: Warning:\n"
        "  Neither code nor explicit exits for function baz, generating default clauses.\n"
    )

    assert W.scan_wp_log_soundness(good_both)["ok"] is True
    assert W.scan_wp_log_soundness(good_term)["ok"] is True
    assert W.scan_wp_log_soundness(good_exits)["ok"] is True


@pytest.mark.unit
def test_missing_spec_multiline_extraction_and_limits() -> None:
    wrapped = (
        "[kernel:annot:missing-spec] a.c:2: Warning:\n"
        "  Neither code nor explicit exits, assigns and terminates for function\n"
        "  only_ensures, generating default clauses.\n"
    )
    soundness = W.scan_wp_log_soundness(wrapped)
    assert soundness["ok"] is False

    res: dict[str, object] = {"soundness": soundness, "layer_goals": [], "wp_log_tail": wrapped}
    limits_res = W.apply_verdict_limits(res, Path("a.c"), None)
    assert limits_res["limits"]["missing_spec_callees"] == ["only_ensures"]

    hints = W.derive_wp_diagnostic_hints(res, wrapped)
    assert any("only_ensures" in h for h in hints)


# ---------------------------------------------------------------------------
# Feature B4: Frama-C Message Folding
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_missing_assigns_two_line_macro_loop_folding() -> None:
    stdout_2line = (
        "[wp] macro_test.c:3: Warning:\n"
        "  Missing assigns clause (assigns 'everything' instead)\n"
    )
    soundness = W.scan_wp_log_soundness(stdout_2line)
    assert any("macro_test.c:3" in msg for msg in soundness["tier_b_unsound"])


# ---------------------------------------------------------------------------
# Tier 1: per-goal solver cost and verdict kind
# ---------------------------------------------------------------------------

# Entries in the shape `-wp-report-json` wrote in framac-analysis:latest (Frama-C 34, 2026-11-16).
_COST_REPORT_ENTRIES: list[dict] = [
    {
        "goal": "typed_f_ensures_fast_false",
        "property": "f_ensures_fast_false",
        "file": "/w/probe.c",
        "line": 3,
        "function": "f",
        "smoke": False,
        "passed": False,
        "verdict": "unknown",
        "provers": [{"prover": "qed", "time": 0.000584, "success": 0}, {"prover": "CVC5:1.1.2", "time": 0, "success": 0}],
        "unknown": 1,
    },
    {
        "goal": "typed_f_assert_fermat3",
        "property": "f_assert_fermat3",
        "function": "f",
        "smoke": False,
        "passed": False,
        "verdict": "timeout",
        "provers": [{"prover": "qed", "time": 0, "success": 0}, {"prover": "Alt-Ergo:2.4.3", "time": 0, "success": 0}],
        "timeout": 1,
        "cached": 3,
    },
    {
        "goal": "typed_f_loop_invariant_preserved",
        "property": "f_loop_invariant",
        "function": "f",
        "smoke": False,
        "passed": True,
        "verdict": "valid",
        "provers": [{"prover": "qed", "time": 0.00461, "success": 0}, {"prover": "Alt-Ergo:2.4.3", "time": 0.0171, "success": 1}],
        "proved": 1,
    },
    {
        "goal": "typed_f_assert_rte_mem_access",
        "property": "f_assert_rte_mem_access",
        "function": "f",
        "smoke": False,
        "passed": True,
        "verdict": "valid",
        "provers": [{"prover": "qed", "time": 0.00336, "success": 0}, {"prover": "Z3:4.13.3", "time": 2.5, "success": 1}],
        "proved": 1,
    },
    {  # cached: its time is the run that filled the cache, never this one
        "goal": "typed_f_ensures_cached",
        "property": "f_ensures_cached",
        "function": "f",
        "smoke": False,
        "passed": True,
        "verdict": "valid",
        "provers": [{"prover": "CVC5:1.1.2", "time": 9.0, "success": 1}],
        "proved": 1,
        "cached": 1,
    },
    {  # proved by Qed alone in no measurable time
        "goal": "typed_f_assigns",
        "property": "f_assigns",
        "function": "f",
        "smoke": False,
        "passed": True,
        "verdict": "valid",
        "provers": [{"prover": "qed", "time": 0, "success": 1}],
        "proved": 1,
    },
]


@pytest.mark.unit
def test_goal_costs_from_report_reads_verdict_provers_and_cached() -> None:
    unproven, slowest = W.goal_costs_from_report(_COST_REPORT_ENTRIES, "f")
    assert unproven == [
        {
            "goal": "typed_f_ensures_fast_false",
            "property": "f_ensures_fast_false",
            "verdict_kind": "unknown",
            "provers": ["CVC5"],
            "time_ms": None,  # WP 34 writes a 0 placeholder for an unproved goal
            "cached": False,
        },
        {
            "goal": "typed_f_assert_fermat3",
            "property": "f_assert_fermat3",
            "verdict_kind": "timeout",
            "provers": ["Alt-Ergo"],
            "time_ms": None,
            "cached": True,
        },
    ]
    # Highest first; the cached 9 s goal and the 0 s Qed goal are left out.
    assert slowest == [
        {"goal": "typed_f_assert_rte_mem_access", "prover": "Z3", "time_ms": 2500},
        {"goal": "typed_f_loop_invariant_preserved", "prover": "Alt-Ergo", "time_ms": 17},
    ]


@pytest.mark.unit
def test_goal_costs_from_report_fails_closed() -> None:
    entries: list[dict] = [
        {"goal": "typed_f_smoke", "smoke": True, "passed": False, "verdict": "unknown"},
        {"goal": "typed_g_post", "function": "g", "passed": False, "verdict": "timeout"},
        {"goal": "not a goal name", "passed": False, "verdict": "timeout"},
        {"property": "no_goal", "passed": False, "verdict": "timeout"},
        {"goal": "typed_f_odd_verdict", "function": "f", "passed": False, "verdict": "computing"},
        {"goal": "typed_f_no_passed", "function": "f", "verdict": "timeout"},
        {"goal": "typed_f_bad_provers", "function": "f", "passed": False, "verdict": "stepout", "provers": "Alt-Ergo"},
        {"goal": "typed_f_bad_time", "function": "f", "passed": True, "verdict": "valid",
         "provers": [{"prover": "Z3", "time": "12", "success": 1}, {"prover": "CVC5", "time": True, "success": 1}]},
        {"goal": "typed_f_measured", "function": "f", "passed": False, "verdict": "failed",
         "provers": [{"prover": "Z3:4.13.3", "time": 0.25, "success": 0}], "cached": True},
    ]
    unproven, slowest = W.goal_costs_from_report(entries, "f")
    assert unproven == [
        {"goal": "typed_f_bad_provers", "property": None, "verdict_kind": "stepout", "provers": [], "time_ms": None, "cached": False},
        # A positive time is a measurement and is kept; `cached: true` (a bool, not WP's count) is not read as cached.
        {"goal": "typed_f_measured", "property": None, "verdict_kind": "failed", "provers": ["Z3"], "time_ms": 250, "cached": False},
    ]
    assert slowest == []


@pytest.mark.unit
def test_slowest_proved_goals_keeps_five() -> None:
    entries = [
        {"goal": f"typed_f_g{i}", "function": "f", "passed": True, "verdict": "valid",
         "provers": [{"prover": "Alt-Ergo:2.4.3", "time": i / 10, "success": 1}]}
        for i in range(1, 9)
    ]
    _, slowest = W.goal_costs_from_report(entries, "f")
    assert [g["goal"] for g in slowest] == ["typed_f_g8", "typed_f_g7", "typed_f_g6", "typed_f_g5", "typed_f_g4"]
    assert slowest[0]["time_ms"] == 800


@pytest.mark.unit
def test_parse_wp_report_json_rejects_non_lists() -> None:
    assert W.parse_wp_report_json("not json") is None
    assert W.parse_wp_report_json('{"goal": "x"}') is None
    assert W.parse_wp_report_json('[{"goal": "x"}, 3, "y"]') == [{"goal": "x"}]


@pytest.mark.unit
@pytest.mark.parametrize(
    ("line", "kind", "provers", "cached"),
    [
        ("[wp] [Timeout] typed_f_post (Qed 0.60ms) (Alt-Ergo)", "timeout", ["Alt-Ergo"], False),
        ("[wp] [Unknown] typed_f_post (Qed 2ms) (CVC5)", "unknown", ["CVC5"], False),
        ("[wp] [Unknown] typed_f_post (Z3)", "unknown", ["Z3"], False),
        ("[wp] [Timeout] typed_f_post (CVC5) (Cached)", "timeout", ["CVC5"], True),
        ("[wp] [Unknown] typed_f_post (Qed 2ms) (CVC5) (Cached) (Model)", "unknown", ["CVC5"], True),
        ("[wp] [Timeout] typed_f_post (Qed 0.59ms) (CVC5) (No Model)", "timeout", ["CVC5"], False),
        ("[wp] [Timeout] typed_f_assert_rte_pointer_value (Qed) (Degenerated)", "timeout", [], False),
        ("[wp] [Stepout] typed_f_post (Qed 0.56ms) (Alt-Ergo)", "stepout", ["Alt-Ergo"], False),
        ("[wp] [Failed] typed_f_post (Alt-Ergo)", "failed", ["Alt-Ergo"], False),
        # A tail that is not only parenthesised tags: the goal and verdict stay, nothing else is guessed.
        ("[wp] [Timeout] typed_f_post (Alt-Ergo) trailing text (Cached)", "timeout", [], False),
    ],
)
def test_goal_costs_from_log_tag_forms(line: str, kind: str, provers: list[str], cached: bool) -> None:
    costs = W.goal_costs_from_log(line + "\n")
    assert len(costs) == 1
    goal = "typed_f_assert_rte_pointer_value" if "pointer_value" in line else "typed_f_post"
    assert costs[0] == {
        "goal": goal,
        "property": None,
        "verdict_kind": kind,
        "provers": provers,
        "time_ms": None,
        "cached": cached,
    }


@pytest.mark.unit
def test_goal_costs_from_log_skips_unmatched_lines_and_duplicates() -> None:
    log = (
        "[wp] 7 goals scheduled\n"
        "[wp] [Valid] typed_f_assigns (Qed)\n"
        "[wp] [Incorrect] typed_f_odd (Alt-Ergo)\n"
        "[wp] [Timeout]typed_f_nospace (Alt-Ergo)\n"
        "  [wp] [Timeout] typed_f_indented (Alt-Ergo)\n"
        "[wp] [Stepout] typed_f_post (Alt-Ergo)\n"
        "[wp] [Stepout] typed_f_post (Alt-Ergo)\n"
        "[wp] Proved goals:   11 / 13\n"
    )
    costs = W.goal_costs_from_log(log)
    assert [c["goal"] for c in costs] == ["typed_f_post"]


@pytest.mark.unit
def test_collect_goal_costs_prefers_the_json_report(tmp_path: Path) -> None:
    log = "[wp] [Timeout] typed_f_only_in_log (Alt-Ergo)\n"
    report = tmp_path / "wp_f_goals.json"
    unproven, slowest, source = W.collect_goal_costs(report, log, "f")
    assert (source, [c["goal"] for c in unproven], slowest) == ("log", ["typed_f_only_in_log"], [])

    report.write_text(json.dumps(_COST_REPORT_ENTRIES), encoding="utf-8")
    unproven, slowest, source = W.collect_goal_costs(report, log, "f")
    assert source == "report_json"
    assert [c["goal"] for c in unproven] == ["typed_f_ensures_fast_false", "typed_f_assert_fermat3"]
    assert len(slowest) == 2

    report.write_text("truncated [", encoding="utf-8")
    assert W.collect_goal_costs(report, log, "f")[2] == "log"
    assert W.collect_goal_costs(tmp_path / "missing.json", "", "f") == ([], [], None)


def _cost(goal: str, kind: str, time_ms: int | None = None, cached: bool = False) -> dict:
    return {"goal": goal, "property": None, "verdict_kind": kind, "provers": ["Z3"], "time_ms": time_ms, "cached": cached}


def _cost_res(costs: list[dict], provers: list[str] | None = None, **extra: object) -> dict:
    res: dict = {
        "status": "unproven_goals_remain",
        "unproven_goal_costs": costs,
        "wp_timeout_s": 10,
        "wp_provers": provers if provers is not None else ["alt-ergo", "z3", "cvc5"],
        "soundness": {"ok": True, "tier_a_aborts": [], "tier_b_unsound": [], "assumed_function_pointer_goals": []},
    }
    res.update(extra)
    return res


@pytest.mark.unit
def test_goal_cost_hint_fast_unknown() -> None:
    hints = W.goal_cost_hints(_cost_res([_cost("typed_f_a", "unknown"), _cost("typed_f_b", "unknown", time_ms=4000)]))
    assert len(hints) == 1
    assert "probably false or missing a fact" in hints[0]
    assert "--prop <clause> --dump-goal" in hints[0]
    assert "`typed_f_a`, `typed_f_b`" in hints[0]


@pytest.mark.unit
def test_goal_cost_hint_unknown_threshold_is_a_fraction_of_the_timeout() -> None:
    slow = [_cost("typed_f_a", "unknown", time_ms=6000)]  # over half of the 10 s timeout
    assert W.goal_cost_hints(_cost_res(slow)) == []
    # The same time under a 20 s timeout is well under it.
    assert len(W.goal_cost_hints(_cost_res(slow, wp_timeout_s=20))) == 1
    # A cached time is never used: the verdict alone decides.
    assert len(W.goal_cost_hints(_cost_res([_cost("typed_f_a", "unknown", time_ms=9000, cached=True)]))) == 1


@pytest.mark.unit
def test_goal_cost_hint_unknown_needs_every_goal() -> None:
    mixed = [_cost("typed_f_a", "unknown"), _cost("typed_f_b", "timeout")]
    assert W.goal_cost_hints(_cost_res(mixed)) == []
    assert W.goal_cost_hints(_cost_res(mixed, provers=["z3"])) == []
    # Not on a counter-example run, where an Unknown with a model outranks a Timeout.
    assert W.goal_cost_hints(_cost_res([_cost("typed_f_a", "unknown")], counter_examples=True)) == []
    # Nothing without the run's timeout or without goals.
    assert W.goal_cost_hints(_cost_res([_cost("typed_f_a", "unknown")], wp_timeout_s=None)) == []
    assert W.goal_cost_hints(_cost_res([])) == []


@pytest.mark.unit
def test_goal_cost_hint_timeout_only_with_a_single_prover() -> None:
    costs = [_cost("typed_f_a", "timeout"), _cost("typed_f_b", "stepout")]
    # Several provers: the merged Timeout does not say what the others answered.
    assert W.goal_cost_hints(_cost_res(costs)) == []
    hints = W.goal_cost_hints(_cost_res(costs, provers=["alt-ergo"]))
    assert len(hints) == 1
    assert "may be true and too large" in hints[0]
    assert "isolate it" in hints[0].lower()
    # A measured Timeout well below the limit contradicts itself: no hint.
    early = [_cost("typed_f_a", "timeout", time_ms=2000)]
    assert W.goal_cost_hints(_cost_res(early, provers=["alt-ergo"])) == []
    assert len(W.goal_cost_hints(_cost_res(early, provers=["alt-ergo"], wp_timeout_s=2))) == 1


@pytest.mark.unit
def test_goal_cost_hints_leave_out_assumed_degenerated_goals() -> None:
    costs = [_cost("typed_f_assert_rte_pointer_value", "timeout"), _cost("typed_f_a", "unknown")]
    res = _cost_res(costs)
    res["soundness"]["assumed_function_pointer_goals"] = ["typed_f_assert_rte_pointer_value"]
    hints = W.goal_cost_hints(res)
    assert len(hints) == 1 and "pointer_value" not in hints[0]


@pytest.mark.unit
def test_goal_costs_flag_off_removes_the_hints(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    res = _cost_res([_cost("typed_f_a", "unknown")], unproven_goals=[], unproven_by_bucket={})
    monkeypatch.delenv(W.GOAL_COSTS_ENV, raising=False)
    on = W.derive_wp_diagnostic_hints(res, "", kb_dir=tmp_path / "kb")
    assert any("probably false or missing a fact" in h for h in on)
    monkeypatch.setenv(W.GOAL_COSTS_ENV, "off")
    off = W.derive_wp_diagnostic_hints(res, "", kb_dir=tmp_path / "kb")
    assert not any("probably false or missing a fact" in h for h in off)
    assert res["unproven_goal_costs"]  # the fields stay


@pytest.mark.unit
def test_run_wp_on_function_reports_goal_costs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out_dir = tmp_path / "wp"
    out_dir.mkdir()
    c_file = tmp_path / "f.c"
    c_file.write_text("int f(int x) { return x; }\n", encoding="utf-8")
    stale = out_dir / "wp_f_goals.json"
    stale.write_text(
        json.dumps([{"goal": "typed_f_stale", "function": "f", "passed": False, "verdict": "timeout"}]), encoding="utf-8"
    )
    seen: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if "-wp" in cmd and "-report-csv" in cmd:
            seen.append(cmd)
            Path(cmd[cmd.index("-report-csv") + 1]).write_text(
                CSV_HEADER + ".\tf.c\tf\t1\tpostcondition\tUnknown\tfast_false: \\result > 50\n", encoding="utf-8"
            )
            Path(cmd[cmd.index("-wp-report-json") + 1]).write_text(json.dumps(_COST_REPORT_ENTRIES[:1]), encoding="utf-8")
            stdout = "[wp] [Unknown] typed_f_ensures_fast_false (Qed 0.58ms) (CVC5)\n[wp] Proved goals:    0 / 1\n"
            return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(W.subprocess, "run", fake_run)
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(W.GOAL_COSTS_ENV, raising=False)
    res = W.run_wp_on_function(
        c_file, "f", out_dir, timeout=8, retry_bitwise=False, retry_tail=False, retry_cast_probe=False, retry_bytes=False
    )
    assert seen and seen[0][seen[0].index("-wp-report-json") + 1] == str(stale)
    assert res["status"] == "unproven_goals_remain"
    assert res["goal_costs_source"] == "report_json"
    assert [c["goal"] for c in res["unproven_goal_costs"]] == ["typed_f_ensures_fast_false"]
    assert res["slowest_proved_goals"] == []
    assert res["wp_timeout_s"] == 8
    assert any("probably false or missing a fact" in h for h in res["diagnostic_hints"])
