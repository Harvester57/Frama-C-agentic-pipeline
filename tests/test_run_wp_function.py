"""Tests for run_wp_function: vacuity classification, proven goals backstop, missing spec detection, message folding."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
from pathlib import Path

import pytest

import run_wp_function as W

CSV_HEADER = "directory\tfile\tfunction\tline\tkind\tstatus\tproperty\n"


@pytest.mark.unit
def test_a_loop_invariant_is_no_termination_goal() -> None:
    # "invariant" contains "variant": only a variant or a decreases clause belongs to l2_termination.
    assert W.goal_obligation_class({"kind": "loop invariant", "annotation": "0 <= i <= n"}) == "rte"
    assert W.goal_obligation_class({"kind": "precondition", "annotation": "L4_invariants: len <= cap"}) == "rte"
    assert W.goal_obligation_class({"kind": "loop variant", "annotation": "n - i"}) == "l2_termination"
    assert W.goal_obligation_class({"kind": "variant", "annotation": "decreases n"}) == "l2_termination"


@pytest.mark.unit
@pytest.mark.parametrize(
    ("kind", "annotation", "expected"),
    [
        # Predicate clauses whose label/body contains "decreases" or "variant" are rte, never l2_termination.
        ("postcondition", "decreases_len: \\result < len", "rte"),
        ("postcondition", "ensures decreases_len: \\result < len", "rte"),
        ("postcondition", "variant_ok: \\result >= 0", "rte"),
        ("precondition", "decreases: len > 0", "rte"),
        ("precondition", "decreases_bound: len > 0", "rte"),
        ("precondition of step", "decreases_arg: n > 0", "rte"),
        ("loop invariant", "0 <= i <= n", "rte"),
        ("loop invariant", "decreases_rem: rem <= n - i", "rte"),
        ("user assertion", "decreases_step: next < cur", "rte"),
        ("signed_overflow", "variant + 1 <= 2147483647", "rte"),
        # Frama-C emits `termination clause` (`terminates \true;`) on loop-free functions too.
        ("termination clause", "\\true", "rte"),
        # Genuine termination report kinds map to l2_termination.
        ("loop variant", "n - i", "l2_termination"),
        ("loop_variant", "n - i", "l2_termination"),
        ("variant", "n - i", "l2_termination"),
        ("decreases", "n", "l2_termination"),
        ("decreases clause", "n", "l2_termination"),
        # Unlabeled / synthetic assertion predicates (ledger proof_gap/fault_hypothesis) only match leading keywords.
        ("", "loop variant n - i", "l2_termination"),
        ("", "decreases n", "l2_termination"),
        ("", "decreases_len: \\result < len", "rte"),
        ("assertion", "loop variant n - i", "l2_termination"),
        ("assertion", "decreases n", "l2_termination"),
        ("assertion", "decreases: x < y", "rte"),
    ],
)
def test_goal_obligation_class_termination_matches_kind_not_predicate_label(
    kind: str, annotation: str, expected: str
) -> None:
    assert W.goal_obligation_class({"kind": kind, "annotation": annotation}) == expected


@pytest.mark.unit
def test_degenerated_pointer_value_goal_with_warnings_is_listed() -> None:
    # WP prints `(Degenerated, 2 warnings)` for a second function-pointer call of the same function.
    log = (
        "[wp] [Timeout] typed_send_msg_assert_rte_pointer_value_2 (Qed 2ms) (Alt-Ergo) (Degenerated)\n"
        "[wp] [Timeout] typed_send_msg_assert_rte_pointer_value_4 (Qed 5ms) (Alt-Ergo) (Degenerated, 2 warnings)\n"
        "[wp] [Timeout] typed_send_msg_assert_rte_pointer_value_6 (Qed 5ms) (Alt-Ergo) (2 warnings)\n"
    )
    assert [m.group(1) for m in W._FPV_DEGEN_RE.finditer(log)] == [
        "typed_send_msg_assert_rte_pointer_value_2",
        "typed_send_msg_assert_rte_pointer_value_4",
    ]


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
            "file": "/w/probe.c",
            "line": 3,
            "verdict_kind": "unknown",
            "provers": ["CVC5"],
            "time_ms": None,  # WP 34 writes a 0 placeholder for an unproved goal
            "cached": False,
        },
        {
            "goal": "typed_f_assert_fermat3",
            "property": "f_assert_fermat3",
            "file": None,  # an entry without a location keeps the goal, with no place to pair it by
            "line": None,
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
        {"goal": "typed_f_bad_provers", "function": "f", "passed": False, "verdict": "stepout", "provers": "Alt-Ergo",
         "file": 7, "line": "12"},
        {"goal": "typed_f_bad_time", "function": "f", "passed": True, "verdict": "valid",
         "provers": [{"prover": "Z3", "time": "12", "success": 1}, {"prover": "CVC5", "time": True, "success": 1}]},
        {"goal": "typed_f_measured", "function": "f", "passed": False, "verdict": "failed",
         "provers": [{"prover": "Z3:4.13.3", "time": 0.25, "success": 0}], "cached": True},
    ]
    unproven, slowest = W.goal_costs_from_report(entries, "f")
    assert unproven == [
        # A file that is not a string and a line that is not a number are dropped, not guessed.
        {"goal": "typed_f_bad_provers", "property": None, "file": None, "line": None, "verdict_kind": "stepout",
         "provers": [], "time_ms": None, "cached": False},
        # A positive time is a measurement and is kept; `cached: true` (a bool, not WP's count) is not read as cached.
        {"goal": "typed_f_measured", "property": None, "file": None, "line": None, "verdict_kind": "failed",
         "provers": ["Z3"], "time_ms": 250, "cached": False},
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
        "file": None,
        "line": None,
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
    stale = out_dir / "wp_f.wp-report-json"
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
    # spec_kb and mutation_check read every `wp_*.json` / `*.json` there as a WP result object.
    assert not [p.name for p in out_dir.glob("*.json")]


# Real Frama-C 34.0~beta `-wp-status` output captured in framac-analysis:latest (2026-11-20).
_REAL_WP_STATUS_FAST_UNKNOWN = """\
[wp] 2 goals scheduled
[wp] [Timeout] typed_fast_unknown_ensures_fast_false (Qed 0.77ms) (Alt-Ergo)
[wp] Proved goals:    3 / 4
  Terminating:     1
  Unreachable:     1
  Qed:             1 (0.39ms)
  Timeout:         1
------------------------------------------------------------
  Function fast_unknown
------------------------------------------------------------

Goal Post-condition 'fast_false' in 'fast_unknown':
Assume {
  Type: is_sint32(fast_unknown_0).
  (* Pre-condition *)
  Have: (0 <= fast_unknown_0) /\\ (fast_unknown_0 <= 100).
}
Prove: 51 <= fast_unknown_0.
Prover Alt-Ergo 2.4.3 returns Timeout (Qed:0.77ms) (3s)
Prover CVC5 1.1.2 returns Unknown (Qed:0.77ms)
Prover Z3 4.13.3 returns Timeout (Qed:0.77ms) (3s)

------------------------------------------------------------
[report] Computing properties status...
"""

_REAL_WP_STATUS_SAME_LINE_MULTI = """\
[wp] 4 goals scheduled
[wp] [Timeout] typed_multi_loop_invariant_bad_inv_preserved (Qed 5ms) (Alt-Ergo)
[wp] [Timeout] typed_multi_assert_rte_signed_overflow (Qed 4ms) (Alt-Ergo)
[wp] [Timeout] typed_multi_assert_rte_signed_overflow_2 (Qed 4ms) (Alt-Ergo)
[wp] [Timeout] typed_multi_assert_rte_signed_overflow_4 (Qed 5ms) (Alt-Ergo)
[wp] Proved goals:    0 / 4
  Timeout:           4
------------------------------------------------------------
  Function multi
------------------------------------------------------------

Goal Preservation of Invariant 'bad_inv' ("/tmp/multi.c", line 9):
Prove: x_2 = 7.
Prover Alt-Ergo 2.4.3 returns Timeout (Qed:5ms) (2s)
Prover CVC5 1.1.2 returns Timeout (Qed:5ms) (2s)
Prover Z3 4.13.3 returns Timeout (Qed:5ms) (2s)

------------------------------------------------------------
------------------------------------------------------------
  Function multi
------------------------------------------------------------

Goal Assertion 'rte,signed_overflow' ("/tmp/multi.c", line 14):
Prove: (-2147483648) <= (x * x_1).
Prover Alt-Ergo 2.4.3 returns Timeout (Qed:4ms) (2s)
Prover CVC5 1.1.2 returns Unknown (Qed:4ms)
Prover Z3 4.13.3 returns Timeout (Qed:4ms) (2s)

------------------------------------------------------------
------------------------------------------------------------
  Function multi
------------------------------------------------------------

Goal Assertion 'rte,signed_overflow' ("/tmp/multi.c", line 14):
Prove: x_2 <= 2147483647.
Prover Alt-Ergo 2.4.3 returns Timeout (Qed:4ms) (2s)
Prover CVC5 1.1.2 returns Unknown (Qed:4ms)
Prover Z3 4.13.3 returns Timeout (Qed:4ms) (2s)

------------------------------------------------------------
------------------------------------------------------------
  Function multi
------------------------------------------------------------

Goal Assertion 'rte,signed_overflow' ("/tmp/multi.c", line 14):
Prove: x_4 <= 2147483647.
Prover Alt-Ergo 2.4.3 returns Timeout (Qed:5ms) (2s)
Prover CVC5 1.1.2 returns Timeout (Qed:5ms) (2s)
Prover Z3 4.13.3 returns Timeout (Qed:5ms) (2s)

------------------------------------------------------------
"""

_REAL_WP_STATUS_STEPOUT_SPLIT_CACHED = """\
[wp] 2 goals scheduled
[wp] [Stepout] typed_edge_terminates_part1 (Qed 0.72ms) (Alt-Ergo) (Cached)
[wp] [Stepout] typed_edge_terminates_part2 (Qed 0.86ms) (Alt-Ergo) (Cached)
[wp] Proved goals:    0 / 2
------------------------------------------------------------
  Function edge
------------------------------------------------------------

Goal Termination-condition (generated by Frama-C kernel from "/tmp/edge.c", lines 4-7) in 'edge' (1/2):
Prove: false.
Prover Alt-Ergo 2.4.3 returns Step limit (Qed:0.72ms) (50)
Prover CVC5 1.1.2 returns Step limit (Qed:0.72ms) (50)
Prover Z3 4.13.3 returns Step limit (Qed:0.72ms) (50)

------------------------------------------------------------
------------------------------------------------------------
  Function edge
------------------------------------------------------------

Goal Termination-condition (generated by Frama-C kernel from "/tmp/edge.c", lines 4-7) in 'edge' (2/2):
Prove: false.
Prover Alt-Ergo 2.4.3 returns Step limit (Qed:0.86ms) (50) (cached)
Prover CVC5 1.1.2 returns Step limit (Qed:0.86ms) (50) (cached)
Prover Z3 4.13.3 returns Step limit (Qed:0.86ms) (50) (cached)

------------------------------------------------------------
"""


@pytest.mark.unit
def test_parse_wp_status_per_prover_real_framac34_output(tmp_path: Path) -> None:
    # 1. Single pending goal with CVC5 Unknown masked by Alt-Ergo/Z3 Timeout.
    parsed = W.parse_wp_status_per_prover(_REAL_WP_STATUS_FAST_UNKNOWN, fn_name="fast_unknown")
    assert parsed == {
        "typed_fast_unknown_ensures_fast_false": {
            "Alt-Ergo": {"verdict": "timeout", "time_ms": 3000, "cached": False},
            "CVC5": {"verdict": "unknown", "time_ms": None, "cached": False},
            "Z3": {"verdict": "timeout", "time_ms": 3000, "cached": False},
        }
    }

    # 2. Same-line identical RTE headers aligned in Wpo.iter order with -wp-report-json.
    multi_report = tmp_path / "multi.wp-report-json"
    multi_entries = [
        {
            "goal": "typed_multi_loop_invariant_bad_inv_preserved",
            "property": "multi_loop_invariant_bad_inv",
            "file": "/tmp/multi.c",
            "line": 9,
            "function": "multi",
            "smoke": False,
            "passed": False,
            "verdict": "timeout",
            "provers": [{"prover": "Alt-Ergo:2.4.3", "time": 0, "success": 0}],
        },
        {
            "goal": "typed_multi_assert_rte_signed_overflow",
            "property": "multi_assert_rte_signed_overflow",
            "file": "/tmp/multi.c",
            "line": 14,
            "function": "multi",
            "smoke": False,
            "passed": False,
            "verdict": "timeout",
            "provers": [{"prover": "Alt-Ergo:2.4.3", "time": 0, "success": 0}],
        },
        {
            "goal": "typed_multi_assert_rte_signed_overflow_2",
            "property": "multi_assert_rte_signed_overflow_2",
            "file": "/tmp/multi.c",
            "line": 14,
            "function": "multi",
            "smoke": False,
            "passed": False,
            "verdict": "timeout",
            "provers": [{"prover": "Alt-Ergo:2.4.3", "time": 0, "success": 0}],
        },
        {
            "goal": "typed_multi_assert_rte_signed_overflow_4",
            "property": "multi_assert_rte_signed_overflow_4",
            "file": "/tmp/multi.c",
            "line": 14,
            "function": "multi",
            "smoke": False,
            "passed": False,
            "verdict": "timeout",
            "provers": [{"prover": "Alt-Ergo:2.4.3", "time": 0, "success": 0}],
        },
    ]
    multi_report.write_text(json.dumps(multi_entries), encoding="utf-8")
    unproven, _, source = W.collect_goal_costs(multi_report, _REAL_WP_STATUS_SAME_LINE_MULTI, "multi")
    assert source == "report_json"
    by_goal = {c["goal"]: c for c in unproven}
    assert by_goal["typed_multi_loop_invariant_bad_inv_preserved"]["per_prover_verdicts"] == {
        "Alt-Ergo": "timeout",
        "CVC5": "timeout",
        "Z3": "timeout",
    }
    assert by_goal["typed_multi_assert_rte_signed_overflow"]["per_prover_verdicts"] == {
        "Alt-Ergo": "timeout",
        "CVC5": "unknown",
        "Z3": "timeout",
    }
    assert by_goal["typed_multi_assert_rte_signed_overflow_2"]["per_prover_verdicts"] == {
        "Alt-Ergo": "timeout",
        "CVC5": "unknown",
        "Z3": "timeout",
    }
    assert by_goal["typed_multi_assert_rte_signed_overflow_4"]["per_prover_verdicts"] == {
        "Alt-Ergo": "timeout",
        "CVC5": "timeout",
        "Z3": "timeout",
    }
    assert by_goal["typed_multi_assert_rte_signed_overflow_4"]["per_prover_time_ms"] == {
        "Alt-Ergo": 2000,
        "CVC5": 2000,
        "Z3": 2000,
    }

    # 3. Split termination parts (1/2) / (2/2) with Step limit and (cached).
    parsed_step = W.parse_wp_status_per_prover(_REAL_WP_STATUS_STEPOUT_SPLIT_CACHED, fn_name="edge")
    assert parsed_step["typed_edge_terminates_part1"] == {
        "Alt-Ergo": {"verdict": "stepout", "time_ms": None, "cached": False},
        "CVC5": {"verdict": "stepout", "time_ms": None, "cached": False},
        "Z3": {"verdict": "stepout", "time_ms": None, "cached": False},
    }
    assert parsed_step["typed_edge_terminates_part2"]["Alt-Ergo"]["cached"] is True


@pytest.mark.unit
def test_parse_wp_status_per_prover_handles_par_reordering_and_fails_closed() -> None:
    # Under -wp-par > 1, a fast goal can finish on the console before a slower goal, while -wp-status
    # prints goals in Wpo.iter order. Pass 2 peeling matches both uniquely by label and verdict.
    reordered_log = """\
[wp] [Unknown] typed_order_test_check_g2_fast (Qed 0.87ms) (CVC5)
[wp] [Timeout] typed_order_test_check_g1_slow (Qed 0.80ms) (Alt-Ergo)
[wp] Proved goals:    0 / 2
------------------------------------------------------------
  Function order_test
------------------------------------------------------------

Goal Check 'g1_slow' ("/tmp/order2.c", line 3):
Prove: false.
Prover Alt-Ergo 2.4.3 returns Timeout (Qed:0.80ms) (3s)
Prover CVC5 1.1.2 returns Timeout (Qed:0.80ms) (3s)
Prover Z3 4.13.3 returns Unknown (Qed:0.80ms)

------------------------------------------------------------
------------------------------------------------------------
  Function order_test
------------------------------------------------------------

Goal Check 'g2_fast' ("/tmp/order2.c", line 4):
Prove: false.
Prover Alt-Ergo 2.4.3 returns Unknown (Qed:0.87ms)
Prover CVC5 1.1.2 returns Unknown (Qed:0.87ms)
Prover Z3 4.13.3 returns Unknown (Qed:0.87ms)

------------------------------------------------------------
"""
    parsed = W.parse_wp_status_per_prover(reordered_log, fn_name="order_test")
    assert {p: v["verdict"] for p, v in parsed["typed_order_test_check_g1_slow"].items()} == {
        "Alt-Ergo": "timeout",
        "CVC5": "timeout",
        "Z3": "unknown",
    }
    assert {p: v["verdict"] for p, v in parsed["typed_order_test_check_g2_fast"].items()} == {
        "Alt-Ergo": "unknown",
        "CVC5": "unknown",
        "Z3": "unknown",
    }

    # Ambiguous mismatch: 2 identical same-line RTE blocks with disagreeing verdicts against 3 log goals -> fail closed.
    ambiguous_log = """\
[wp] [Timeout] typed_f_assert_rte_signed_overflow (Alt-Ergo)
[wp] [Timeout] typed_f_assert_rte_signed_overflow_2 (Alt-Ergo)
[wp] [Timeout] typed_f_assert_rte_signed_overflow_3 (Alt-Ergo)
------------------------------------------------------------
  Function f
------------------------------------------------------------

Goal Assertion 'rte,signed_overflow' ("/tmp/f.c", line 5):
Prover Alt-Ergo 2.4.3 returns Timeout (2s)
Prover CVC5 1.1.2 returns Unknown

------------------------------------------------------------
------------------------------------------------------------
  Function f
------------------------------------------------------------

Goal Assertion 'rte,signed_overflow' ("/tmp/f.c", line 5):
Prover Alt-Ergo 2.4.3 returns Timeout (2s)
Prover CVC5 1.1.2 returns Timeout (2s)

------------------------------------------------------------
"""
    assert W.parse_wp_status_per_prover(ambiguous_log, fn_name="f") == {}


@pytest.mark.unit
def test_goal_cost_hints_multi_prover_with_per_prover_verdicts() -> None:
    # 1. All 3 configured provers genuinely timed out or stepped out -> fires multi-prover "too large" hint.
    all_timed_out = [
        {
            **_cost("typed_f_a", "timeout"),
            "per_prover_verdicts": {"Alt-Ergo": "timeout", "CVC5": "timeout", "Z3": "timeout"},
            "per_prover_time_ms": {"Alt-Ergo": 10000, "CVC5": 10000, "Z3": 10000},
        },
        {
            **_cost("typed_f_b", "stepout"),
            "per_prover_verdicts": {"Alt-Ergo": "stepout", "CVC5": "stepout", "Z3": "stepout"},
        },
    ]
    hints = W.goal_cost_hints(_cost_res(all_timed_out))
    assert len(hints) == 1
    assert "all configured provers (alt-ergo, z3, cvc5, 10s limit)" in hints[0]
    assert "may be true and too large" in hints[0]

    # 2. Fast Unknown from CVC5 masked by Alt-Ergo/Z3 Timeout -> must NOT fire "too large" hint.
    masked_unknown = [
        {
            **_cost("typed_f_fast_false", "timeout"),
            "per_prover_verdicts": {"Alt-Ergo": "timeout", "CVC5": "unknown", "Z3": "timeout"},
            "per_prover_time_ms": {"Alt-Ergo": 10000, "Z3": 10000},
        }
    ]
    assert W.goal_cost_hints(_cost_res(masked_unknown)) == []

    # 3. Missing one configured prover in per_prover_verdicts -> fail closed (no timeout hint).
    incomplete = [
        {
            **_cost("typed_f_a", "timeout"),
            "per_prover_verdicts": {"Alt-Ergo": "timeout", "Z3": "timeout"},
        }
    ]
    assert W.goal_cost_hints(_cost_res(incomplete)) == []

    # 4. Measured per-prover timeout well below the 10s limit -> fail closed (no timeout hint).
    early_timeout = [
        {
            **_cost("typed_f_a", "timeout"),
            "per_prover_verdicts": {"Alt-Ergo": "timeout", "CVC5": "timeout", "Z3": "timeout"},
            "per_prover_time_ms": {"Alt-Ergo": 10000, "CVC5": 2000, "Z3": 10000},
        }
    ]
    assert W.goal_cost_hints(_cost_res(early_timeout)) == []

    # 5. Every prover returned Unknown -> still fires the "got Unknown, not Timeout" hint.
    all_unknown = [
        {
            **_cost("typed_f_a", "unknown"),
            "per_prover_verdicts": {"Alt-Ergo": "unknown", "CVC5": "unknown", "Z3": "unknown"},
        }
    ]
    u_hints = W.goal_cost_hints(_cost_res(all_unknown))
    assert len(u_hints) == 1 and "probably false or missing a fact" in u_hints[0]


@pytest.mark.unit
def test_run_wp_on_function_passes_wp_status_except_dump_goal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out_dir = tmp_path / "wp"
    c_file = tmp_path / "probe.c"
    c_file.write_text("int fast_unknown(int x) { return x; }\n", encoding="utf-8")
    seen: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if "-wp" in cmd and "-report-csv" in cmd:
            seen.append(list(cmd))
            Path(cmd[cmd.index("-report-csv") + 1]).write_text(
                CSV_HEADER + ".\tprobe.c\tfast_unknown\t3\tpostcondition\tUnknown\tfast_false: \\result > 50\n",
                encoding="utf-8",
            )
            Path(cmd[cmd.index("-wp-report-json") + 1]).write_text(
                json.dumps(
                    [
                        {
                            "goal": "typed_fast_unknown_ensures_fast_false",
                            "property": "fast_unknown_ensures_fast_false",
                            "file": "/tmp/probe.c",
                            "line": 3,
                            "function": "fast_unknown",
                            "smoke": False,
                            "passed": False,
                            "verdict": "timeout",
                            "provers": [{"prover": "Alt-Ergo:2.4.3", "time": 0, "success": 0}],
                        }
                    ]
                ),
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(cmd, 0, stdout=_REAL_WP_STATUS_FAST_UNKNOWN, stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(W.subprocess, "run", fake_run)
    monkeypatch.chdir(tmp_path)
    res = W.run_wp_on_function(
        c_file,
        "fast_unknown",
        out_dir,
        timeout=3,
        cache_dir="off",
        retry_bitwise=False,
        retry_tail=False,
        retry_cast_probe=False,
        retry_bytes=False,
    )
    assert "-wp-status" in seen[0]
    assert res["unproven_goal_costs"][0]["per_prover_verdicts"] == {
        "Alt-Ergo": "timeout",
        "CVC5": "unknown",
        "Z3": "timeout",
    }
    assert not any("too large" in h for h in res["diagnostic_hints"])

    # With dump_goal=True, -wp-print -wp-no-qed is passed without -wp-status (so Valid goals still print).
    W.run_wp_on_function(
        c_file,
        "fast_unknown",
        out_dir,
        timeout=3,
        dump_goal=True,
        cache_dir="off",
        retry_bitwise=False,
        retry_tail=False,
        retry_cast_probe=False,
        retry_bytes=False,
    )
    assert "-wp-print" in seen[1] and "-wp-no-qed" in seen[1] and "-wp-status" not in seen[1]


# ---------------------------------------------------------------------------
# Exclusive `--out-dir` lock
# ---------------------------------------------------------------------------


def _write_lock(out_dir: Path, owner: dict[str, object], age_s: float | None = None) -> Path:
    lock_dir = out_dir / W.OUT_DIR_LOCK_NAME
    lock_dir.mkdir(parents=True, exist_ok=True)
    owner_file = lock_dir / "owner.json"
    owner_file.write_text(json.dumps(owner) + "\n", encoding="utf-8")
    if age_s is not None:
        old = time.time() - age_s
        os.utime(owner_file, (old, old))
        os.utime(lock_dir, (old, old))
    return lock_dir


@pytest.mark.unit
def test_out_dir_lock_refuses_concurrent_live_holder_without_clobbering_reports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    out_dir = tmp_path / "wp"
    out_dir.mkdir()
    c_file = tmp_path / "f.c"
    c_file.write_text("int f(int x) { return x; }\n", encoding="utf-8")

    # Pre-existing artifacts that a refused concurrent call must leave completely untouched.
    existing_csv = out_dir / "wp_f.csv"
    existing_log = out_dir / "wp_f.log"
    existing_json = out_dir / "wp_f.json"
    existing_csv.write_text("KEEP_CSV\n", encoding="utf-8")
    existing_log.write_text("KEEP_LOG\n", encoding="utf-8")
    existing_json.write_text('{"keep": true}\n', encoding="utf-8")

    owner = {
        "pid": os.getpid(),
        "host": socket.gethostname(),
        "started_at": "2026-11-20T10:00:00+00:00",
        "function": "minmea_check",
    }
    lock_dir = _write_lock(out_dir, owner)

    called = False

    def fail_if_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal called
        called = True
        raise AssertionError(f"subprocess.run should not be called while locked: {cmd}")

    monkeypatch.setattr(W.subprocess, "run", fail_if_run)

    res = W.run_wp_on_function(c_file, "f", out_dir, cache_dir="off", retry_bitwise=False)
    assert not called
    assert res["status"] == "analysis_error"
    assert res["reason"] == "out_dir_locked"
    assert str(out_dir) in res["error_summary"][0]
    assert str(os.getpid()) in res["error_summary"][0]
    assert res["lock_owner"]["pid"] == os.getpid()
    assert any("--out-dir" in h for h in res["diagnostic_hints"])
    assert existing_csv.read_text(encoding="utf-8") == "KEEP_CSV\n"
    assert existing_log.read_text(encoding="utf-8") == "KEEP_LOG\n"
    assert existing_json.read_text(encoding="utf-8") == '{"keep": true}\n'
    assert lock_dir.is_dir()

    rc = W.main(
        [
            "--file",
            str(c_file),
            "--function",
            "f",
            "--out-dir",
            str(out_dir),
            "--out-json",
            str(existing_json),
            "--cache-dir",
            "off",
            "--security-props",
            "none",
        ]
    )
    captured = capsys.readouterr()
    assert rc != 0
    assert not called
    summary = json.loads(captured.out)
    assert summary["status"] == "analysis_error"
    assert summary["reason"] == "out_dir_locked"
    assert summary["lock_owner"]["pid"] == os.getpid()
    assert str(out_dir) in captured.err and str(os.getpid()) in captured.err
    assert existing_csv.read_text(encoding="utf-8") == "KEEP_CSV\n"
    assert existing_log.read_text(encoding="utf-8") == "KEEP_LOG\n"
    assert existing_json.read_text(encoding="utf-8") == '{"keep": true}\n'
    assert lock_dir.is_dir()


@pytest.mark.unit
def test_out_dir_lock_reclaims_stale_dead_pid_and_expired_remote_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    c_file = tmp_path / "f.c"
    c_file.write_text("int f(int x) { return x; }\n", encoding="utf-8")

    def fake_ok(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if "-wp" in cmd and "-report-csv" in cmd:
            Path(cmd[cmd.index("-report-csv") + 1]).write_text(
                CSV_HEADER + ".\tf.c\tf\t1\trte: mem_access\tValid\tx\n", encoding="utf-8"
            )
            return subprocess.CompletedProcess(cmd, 0, stdout="[wp] Proved goals:    1 / 1\n", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(W.subprocess, "run", fake_ok)

    # 1. Dead PID on the same host -> reclaimed immediately even if lock is brand new.
    out_dead = tmp_path / "wp_dead"
    _write_lock(
        out_dead,
        {"pid": 999_999, "host": socket.gethostname(), "started_at": "2026-11-20T10:00:00+00:00", "function": "old"},
    )
    monkeypatch.setattr(W, "_pid_is_alive", lambda pid: False if pid == 999_999 else True)
    res_dead = W.run_wp_on_function(c_file, "f", out_dead, cache_dir="off", retry_bitwise=False)
    assert res_dead["status"] == "all_proven"
    assert not (out_dead / W.OUT_DIR_LOCK_NAME).exists()

    # 2. Remote container host whose lock is older than the stale threshold -> reclaimed.
    monkeypatch.setenv(W.OUT_DIR_LOCK_STALE_ENV, "5")
    out_old_remote = tmp_path / "wp_old_remote"
    _write_lock(
        out_old_remote,
        {"pid": 7, "host": "dead-container-1234", "started_at": "2026-11-20T09:00:00+00:00", "function": "old"},
        age_s=60.0,
    )
    res_old = W.run_wp_on_function(c_file, "f", out_old_remote, cache_dir="off", retry_bitwise=False)
    assert res_old["status"] == "all_proven"
    assert not (out_old_remote / W.OUT_DIR_LOCK_NAME).exists()

    # 3. Remote container host with a fresh lock -> refused (different PID namespace, do not kill by local PID check).
    out_live_remote = tmp_path / "wp_live_remote"
    _write_lock(
        out_live_remote,
        {"pid": 999_999, "host": "live-container-5678", "started_at": "2026-11-20T10:00:00+00:00", "function": "live"},
    )
    res_live = W.run_wp_on_function(c_file, "f", out_live_remote, cache_dir="off", retry_bitwise=False)
    assert res_live["status"] == "analysis_error"
    assert res_live["reason"] == "out_dir_locked"
    assert (out_live_remote / W.OUT_DIR_LOCK_NAME).is_dir()


@pytest.mark.unit
def test_out_dir_lock_allows_nested_retries_and_releases_on_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out_dir = tmp_path / "wp"
    c_file = tmp_path / "f.c"
    c_file.write_text("unsigned int f(unsigned int x) { return x << 1; }\n", encoding="utf-8")
    lock_dir = out_dir / W.OUT_DIR_LOCK_NAME

    calls: list[str] = []

    def fake_retry_then_pass(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        # Lock must be held throughout every outer and nested WP invocation.
        assert lock_dir.is_dir() and (lock_dir / "owner.json").is_file()
        model = cmd[cmd.index("-wp-model") + 1] if "-wp-model" in cmd else ""
        calls.append(model)
        if "-report-csv" in cmd:
            csv_path = Path(cmd[cmd.index("-report-csv") + 1])
            if model == "Typed":
                csv_path.write_text(
                    CSV_HEADER + ".\tf.c\tf\t1\trte: shift\tUnknown\t(x << 1) <= 4294967295\n",
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess(
                    cmd,
                    0,
                    stdout="[wp] [Timeout] typed_f_assert_rte_shift (Alt-Ergo)\n[wp] Proved goals:    0 / 1\n",
                    stderr="",
                )
            csv_path.write_text(
                CSV_HEADER + ".\tf.c\tf\t1\trte: shift\tValid\t(x << 1) <= 4294967295\n",
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(cmd, 0, stdout="[wp] Proved goals:    1 / 1\n", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(W.subprocess, "run", fake_retry_then_pass)
    res = W.run_wp_on_function(
        c_file, "f", out_dir, cache_dir="off", retry_bitwise=True, retry_tail=False, retry_cast_probe=False
    )
    assert calls == ["Typed", "Typed+ref+int"]
    assert res["status"] == "all_proven"
    assert res["bitwise_retry"]["triggered"] is True
    assert not lock_dir.exists()
    assert str(out_dir.resolve()) not in W._HELD_OUT_DIR_LOCKS

    # Exception inside a run must still release the lock cleanly so the next call succeeds.
    def fake_boom(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert lock_dir.is_dir()
        raise RuntimeError("simulated crash inside subprocess")

    monkeypatch.setattr(W.subprocess, "run", fake_boom)
    with pytest.raises(RuntimeError, match="simulated crash"):
        W.run_wp_on_function(c_file, "f", out_dir, cache_dir="off", retry_bitwise=False)
    assert not lock_dir.exists()
    assert str(out_dir.resolve()) not in W._HELD_OUT_DIR_LOCKS

    # A subsequent run on the same out_dir acquires the lock without error.
    monkeypatch.setattr(W.subprocess, "run", fake_retry_then_pass)
    res2 = W.run_wp_on_function(
        c_file, "f", out_dir, cache_dir="off", retry_bitwise=True, retry_tail=False, retry_cast_probe=False
    )
    assert res2["status"] == "all_proven"
    assert not lock_dir.exists()


# ---------------------------------------------------------------------------
# Timed-out / omitted loop variants and recursion variants (Frama-C 34)
# ---------------------------------------------------------------------------

# Real Frama-C 34.0~beta -report-csv output on a loop whose `loop variant` times out while all
# other properties prove: Frama-C emits `termination clause | Partially proven` and omits the
# `loop variant` row completely.
_REAL_VARIANT_TIMEOUT_CSV = (
    "directory\tfile\tline\tfunction\tproperty kind\tstatus\tproperty\n"
    "/tmp/probe\tonly_variant_timeout.c\t6\twalk_bad\tpostcondition\tValid\t\\false\n"
    "/tmp/probe\tonly_variant_timeout.c\t6\twalk_bad\ttermination clause\tPartially proven\t\\true\n"
    "/tmp/probe\tonly_variant_timeout.c\t6\twalk_bad\tassigns clause\tValid\tassigns \\nothing;\n"
    "/tmp/probe\tonly_variant_timeout.c\t9\twalk_bad\tloop invariant\tValid\t0 <= i <= n\n"
    "/tmp/probe\tonly_variant_timeout.c\t10\twalk_bad\tloop invariant\tValid\t0 <= acc <= 255\n"
    "/tmp/probe\tonly_variant_timeout.c\t11\twalk_bad\tassigns clause\tValid\tassigns i, acc;\n"
    "/tmp/probe\tonly_variant_timeout.c\t14\twalk_bad\tmem_access\tValid\t\\valid_read(s + i)\n"
    "/tmp/probe\tonly_variant_timeout.c\t14\twalk_bad\tpointer_value\tValid\t\\null == s + i || \\object_pointer(s + i)\n"
    "/tmp/probe\tonly_variant_timeout.c\t15\twalk_bad\tmem_access\tValid\t\\valid_read(s + i)\n"
    "/tmp/probe\tonly_variant_timeout.c\t15\twalk_bad\tpointer_value\tValid\t\\null == s + i || \\object_pointer(s + i)\n"
    "/tmp/probe\tonly_variant_timeout.c\t16\twalk_bad\tsigned_overflow\tValid\ti + 1 <= 2147483647\n"
)

_REAL_VARIANT_TIMEOUT_REPORT_JSON: list[dict[str, object]] = [
    {
        "goal": "typed_walk_bad_assigns",
        "property": "walk_bad_assigns",
        "file": "/tmp/probe/only_variant_timeout.c",
        "line": 6,
        "function": "walk_bad",
        "smoke": False,
        "passed": True,
        "verdict": "valid",
        "provers": [{"prover": "qed", "time": 0, "success": 1}],
        "proved": 1,
    },
    {
        "goal": "typed_walk_bad_loop_variant_positive",
        "property": "walk_bad_loop_variant",
        "file": "/tmp/probe/only_variant_timeout.c",
        "line": 12,
        "function": "walk_bad",
        "smoke": False,
        "passed": False,
        "verdict": "timeout",
        "provers": [
            {"prover": "qed", "time": 0.00529, "success": 0},
            {"prover": "Alt-Ergo:2.4.3", "time": 0, "success": 0},
        ],
        "timeout": 1,
    },
    {
        "goal": "typed_walk_bad_loop_variant_decrease",
        "property": "walk_bad_loop_variant",
        "file": "/tmp/probe/only_variant_timeout.c",
        "line": 12,
        "function": "walk_bad",
        "smoke": False,
        "passed": False,
        "verdict": "timeout",
        "provers": [
            {"prover": "qed", "time": 0.005, "success": 0},
            {"prover": "Alt-Ergo:2.4.3", "time": 0, "success": 0},
        ],
        "timeout": 1,
    },
]

_REAL_VARIANT_TIMEOUT_LOG = (
    "[wp] 13 goals scheduled\n"
    "[wp] [Timeout] typed_walk_bad_loop_variant_decrease (Qed 5ms) (Alt-Ergo)\n"
    "[wp] [Timeout] typed_walk_bad_loop_variant_positive (Qed 5ms) (Alt-Ergo)\n"
    "[wp] Proved goals:   13 / 15\n"
    "  Qed:               8 (2ms-1ms-5ms)\n"
    "  Timeout:           2\n"
)


@pytest.mark.unit
def test_timed_out_loop_variant_is_surfaced_from_report_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out_dir = tmp_path / "wp"
    c_file = tmp_path / "only_variant_timeout.c"
    c_file.write_text("int walk_bad(const unsigned char *s, int n) { return 0; }\n", encoding="utf-8")

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if "-wp" in cmd and "-report-csv" in cmd:
            Path(cmd[cmd.index("-report-csv") + 1]).write_text(_REAL_VARIANT_TIMEOUT_CSV, encoding="utf-8")
            Path(cmd[cmd.index("-wp-report-json") + 1]).write_text(
                json.dumps(_REAL_VARIANT_TIMEOUT_REPORT_JSON), encoding="utf-8"
            )
            return subprocess.CompletedProcess(cmd, 0, stdout=_REAL_VARIANT_TIMEOUT_LOG, stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(W.subprocess, "run", fake_run)
    monkeypatch.chdir(tmp_path)
    res = W.run_wp_on_function(
        c_file, "walk_bad", out_dir, cache_dir="off", retry_bitwise=False, retry_tail=False, retry_cast_probe=False
    )
    assert res["status"] == "unproven_goals_remain"
    assert res["unproven_count"] == 1
    assert res["proven_count"] == 11
    assert res["total_goals"] == 12
    assert res["proven_count"] < res["total_goals"]
    assert len(res["unproven_goals"]) == 1
    goal = res["unproven_goals"][0]
    assert goal["kind"] == "loop variant"
    assert goal["status"] == "Timeout"
    assert goal["line"] == 12
    assert goal["obligation_class"] == "l2_termination"
    assert goal["diagnostic_bucket"] == "step_b_loop_invariant"
    assert set(goal["wp_goals"]) == {"typed_walk_bad_loop_variant_positive", "typed_walk_bad_loop_variant_decrease"}
    assert len(res["unproven_by_bucket"]["step_b_loop_invariant"]) == 1
    assert res["by_obligation_class"]["l2_termination"]["unproven"] == 1
    assert res["next_synthesis_focus"] == "step_b_loop_invariant"
    assert any("fix progress for" in h for h in res["diagnostic_hints"])
    assert not any("dynamic allocation" in h.lower() for h in res["diagnostic_hints"])


@pytest.mark.unit
def test_timed_out_loop_variant_log_fallback_without_report_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out_dir = tmp_path / "wp"
    c_file = tmp_path / "minmea.c"
    c_file.write_text("int minmea_checksum(const char *sentence) { return 0; }\n", encoding="utf-8")
    csv_text = (
        "directory\tfile\tline\tfunction\tproperty kind\tstatus\tproperty\n"
        ".\tminmea.c\t10\tminmea_checksum\ttermination clause\tPartially proven\t\\true\n"
        ".\tminmea.c\t10\tminmea_checksum\tassigns clause\tValid\tassigns \\nothing;\n"
    )
    log_text = (
        "[wp] 26 goals scheduled\n"
        "[wp] [Timeout] typed_minmea_checksum_loop_variant_positive_part1 (Qed 4ms) (Alt-Ergo)\n"
        "[wp] [Timeout] typed_minmea_checksum_loop_variant_positive_part2 (Qed 4ms) (Alt-Ergo)\n"
        "[wp] Proved goals:   24 / 26\n"
        "  Timeout:           2\n"
    )

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if "-wp" in cmd and "-report-csv" in cmd:
            Path(cmd[cmd.index("-report-csv") + 1]).write_text(csv_text, encoding="utf-8")
            # Deliberately do not write `-wp-report-json` to exercise the log fallback.
            return subprocess.CompletedProcess(cmd, 0, stdout=log_text, stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(W.subprocess, "run", fake_run)
    monkeypatch.chdir(tmp_path)
    res = W.run_wp_on_function(
        c_file,
        "minmea_checksum",
        out_dir,
        cache_dir="off",
        retry_bitwise=False,
        retry_tail=False,
        retry_cast_probe=False,
    )
    assert res["status"] == "unproven_goals_remain"
    assert res["unproven_count"] == 1
    assert res["proven_count"] == 2 and res["total_goals"] == 3
    assert res["unproven_goals"][0]["kind"] == "loop variant"
    assert res["unproven_goals"][0]["obligation_class"] == "l2_termination"
    assert res["by_obligation_class"]["l2_termination"]["unproven"] == 1
    assert res["next_synthesis_focus"] == "step_b_loop_invariant"
    assert any("fix progress for" in h for h in res["diagnostic_hints"])


@pytest.mark.unit
def test_timed_out_recursion_variant_and_mixed_unproven_variant_are_surfaced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    c_file = tmp_path / "var.c"
    c_file.write_text("int rec_bad(int n) { return n; }\n", encoding="utf-8")

    # Subcase A: real Frama-C 34 recursion variant (`decreases`) timeout with no CSV row.
    rec_csv = (
        "directory\tfile\tline\tfunction\tproperty kind\tstatus\tproperty\n"
        "/tmp/p\tvar.c\t45\trec_bad\ttermination clause\tPartially proven\t\\true\n"
        "/tmp/p\tvar.c\t45\trec_bad\tassigns clause\tValid\tassigns \\nothing;\n"
    )
    rec_json = [
        {
            "goal": "typed_rec_bad_variant",
            "property": "rec_bad_variant",
            "file": "/tmp/p/var.c",
            "line": 42,
            "function": "rec_bad",
            "smoke": False,
            "passed": False,
            "verdict": "timeout",
            "provers": [{"prover": "Alt-Ergo:2.4.3", "time": 0, "success": 0}],
            "timeout": 1,
        }
    ]
    rec_log = (
        "[wp] [Timeout] typed_rec_bad_variant (Qed 0.92ms) (Alt-Ergo)\n[wp] Proved goals:    9 / 10\n  Timeout: 1\n"
    )

    def fake_rec(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if "-report-csv" in cmd:
            Path(cmd[cmd.index("-report-csv") + 1]).write_text(rec_csv, encoding="utf-8")
            Path(cmd[cmd.index("-wp-report-json") + 1]).write_text(json.dumps(rec_json), encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout=rec_log, stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(W.subprocess, "run", fake_rec)
    monkeypatch.chdir(tmp_path)
    res_rec = W.run_wp_on_function(
        c_file, "rec_bad", tmp_path / "wp_rec", cache_dir="off", retry_bitwise=False, retry_tail=False
    )
    assert res_rec["status"] == "unproven_goals_remain"
    assert res_rec["unproven_count"] == 1
    assert res_rec["proven_count"] == 2 and res_rec["total_goals"] == 3
    assert res_rec["unproven_goals"][0]["kind"] == "decreases"
    assert res_rec["unproven_goals"][0]["obligation_class"] == "l2_termination"
    assert res_rec["by_obligation_class"]["l2_termination"]["unproven"] == 1
    assert res_rec["next_synthesis_focus"] == "step_b_loop_invariant"

    # Subcase B: CSV also has an Unknown loop invariant AND an omitted loop variant timeout.
    mix_csv = (
        "directory\tfile\tline\tfunction\tproperty kind\tstatus\tproperty\n"
        "/tmp/p\tvar.c\t5\twalk\tloop invariant\tUnknown\t0 <= acc <= n\n"
        "/tmp/p\tvar.c\t3\twalk\ttermination clause\tPartially proven\t\\true\n"
    )
    mix_json = [
        {
            "goal": "typed_walk_loop_invariant_preserved",
            "property": "walk_loop_invariant",
            "file": "/tmp/p/var.c",
            "line": 5,
            "function": "walk",
            "smoke": False,
            "passed": False,
            "verdict": "timeout",
            "provers": [{"prover": "Alt-Ergo:2.4.3", "time": 0, "success": 0}],
            "timeout": 1,
        },
        {
            "goal": "typed_walk_loop_variant_positive",
            "property": "walk_loop_variant",
            "file": "/tmp/p/var.c",
            "line": 6,
            "function": "walk",
            "smoke": False,
            "passed": False,
            "verdict": "timeout",
            "provers": [{"prover": "Alt-Ergo:2.4.3", "time": 0, "success": 0}],
            "timeout": 1,
        },
    ]
    mix_log = (
        "[wp] [Timeout] typed_walk_loop_invariant_preserved (Alt-Ergo)\n"
        "[wp] [Timeout] typed_walk_loop_variant_positive (Alt-Ergo)\n"
        "[wp] Proved goals:    7 / 9\n  Timeout: 2\n"
    )

    def fake_mix(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if "-report-csv" in cmd:
            Path(cmd[cmd.index("-report-csv") + 1]).write_text(mix_csv, encoding="utf-8")
            Path(cmd[cmd.index("-wp-report-json") + 1]).write_text(json.dumps(mix_json), encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout=mix_log, stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(W.subprocess, "run", fake_mix)
    res_mix = W.run_wp_on_function(
        c_file, "walk", tmp_path / "wp_mix", cache_dir="off", retry_bitwise=False, retry_tail=False
    )
    assert res_mix["status"] == "unproven_goals_remain"
    assert res_mix["unproven_count"] == 2
    assert {g["kind"] for g in res_mix["unproven_goals"]} == {"loop invariant", "loop variant"}
    assert res_mix["by_obligation_class"]["l2_termination"]["unproven"] == 1


@pytest.mark.unit
def test_partially_proven_under_hypotheses_stays_all_proven_when_all_vcs_proved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out_dir = tmp_path / "wp"
    c_file = tmp_path / "clean.c"
    c_file.write_text("int clean(int n) { return n; }\n", encoding="utf-8")
    csv_text = (
        "directory\tfile\tline\tfunction\tproperty kind\tstatus\tproperty\n"
        ".\tclean.c\t1\tclean\ttermination clause\tPartially proven\t\\true\n"
        ".\tclean.c\t1\tclean\tassigns clause\tPartially proven\tassigns \\nothing;\n"
        ".\tclean.c\t2\tclean\tpostcondition\tValid\t\\result == n\n"
    )

    def fake_clean(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if "-report-csv" in cmd:
            Path(cmd[cmd.index("-report-csv") + 1]).write_text(csv_text, encoding="utf-8")
            Path(cmd[cmd.index("-wp-report-json") + 1]).write_text("[]", encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout="[wp] Proved goals:    4 / 4\n", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(W.subprocess, "run", fake_clean)
    monkeypatch.chdir(tmp_path)
    res = W.run_wp_on_function(c_file, "clean", out_dir, cache_dir="off", retry_bitwise=False, retry_tail=False)
    assert res["status"] == "all_proven"
    assert res["unproven_count"] == 0
    assert res["unproven_goals"] == []
    assert res["proven_count"] == res["total_goals"] == 3


@pytest.mark.unit
def test_parse_partial_wp_log_verdicts_empty_and_non_wp_returns_none() -> None:
    assert W.parse_partial_wp_log_verdicts("") is None
    assert (
        W.parse_partial_wp_log_verdicts("[kernel] Parsing foo.c (with preprocessing)\n[wp] Running WP plugin...\n")
        is None
    )


@pytest.mark.unit
def test_parse_partial_wp_log_verdicts_framac34_and_goal_colon_formats() -> None:
    log = "\n".join(
        [
            "[kernel] Parsing modbus.c (with preprocessing)",
            "[wp] Running WP plugin...",
            "[wp] 540 goals scheduled",
            "[wp] [Qed] Goal typed_recv_ensures_1 : Valid (1ms)",
            "[wp] [Alt-Ergo 2.4.3] Goal typed_recv_assert_2 : Valid (14ms) (Cached)",
            "[wp] [Valid] typed_recv_assert_3 (Qed 2ms)",
            "[wp] [Proved] typed_recv_assert_4 (Z3) (Cached)",
            # First prover times out, second prover proves the same goal -> counts once as proved.
            "[wp] [Alt-Ergo 2.4.3] Goal typed_recv_assert_upgraded : Timeout (2s)",
            "[wp] [Z3 4.13.3] Goal typed_recv_assert_upgraded : Valid (12ms)",
            # Cached and uncached timeouts plus Stepout / Step limit and duplicates.
            "[wp] [Timeout] typed_recv_assert_to1 (Qed 3ms) (Alt-Ergo) (Cached)",
            "[wp] [Timeout] typed_recv_assert_to1 (Qed 3ms) (Alt-Ergo)",
            "[wp] [Stepout] typed_recv_assert_step1 (Qed 2ms) (Alt-Ergo)",
            "[wp] [Step limit] typed_recv_assert_step2 (Alt-Ergo) (Cached)",
            "[wp] [Unknown] typed_recv_assert_unk1 (Qed 1ms) (CVC5) (Cached) (Model)",
            "[wp] [Failed] typed_recv_assert_fail1 (Alt-Ergo)",
            "[wp] [Alt-Ergo 2.4.3] Goal typed_recv_assert_invalid : Invalid (5ms)",
            "[wp] [Cache] updated:10",
        ]
    )
    partial = W.parse_partial_wp_log_verdicts(log)
    assert partial is not None
    assert partial["incomplete"] is True
    assert partial["scheduled_vcs"] == 540
    assert partial["proved_vcs"] == 5
    assert partial["timed_out_vcs"] == 3
    assert partial["unknown_vcs"] == 1
    assert partial["failed_vcs"] == 2
    assert partial["completed_vcs"] == 11
    assert partial["cached_vcs"] == 5
    assert partial["cached_timed_out_vcs"] == 2
    assert partial["timed_out_goals"] == [
        "typed_recv_assert_to1",
        "typed_recv_assert_step1",
        "typed_recv_assert_step2",
    ]
    assert partial["unknown_goals"] == ["typed_recv_assert_unk1"]
    assert partial["failed_goals"] == ["typed_recv_assert_fail1", "typed_recv_assert_invalid"]


@pytest.mark.unit
def test_parse_partial_wp_log_verdicts_caps_goal_lists_and_handles_scheduled_only() -> None:
    lines = ["[wp] 100 goals scheduled"]
    lines += [f"[wp] [Timeout] typed_f_to_{i} (Alt-Ergo) (Cached)" for i in range(35)]
    partial = W.parse_partial_wp_log_verdicts("\n".join(lines))
    assert partial is not None
    assert partial["timed_out_vcs"] == 35
    assert partial["cached_timed_out_vcs"] == 35
    assert len(partial["timed_out_goals"]) == 25
    assert partial["timed_out_goals"][0] == "typed_f_to_0"
    assert partial["timed_out_goals"][-1] == "typed_f_to_24"

    sched_only = W.parse_partial_wp_log_verdicts("[wp] 42 goals scheduled\n")
    assert sched_only is not None
    assert sched_only["scheduled_vcs"] == 42
    assert sched_only["completed_vcs"] == 0
    assert sched_only["incomplete"] is True

    # WP summary emitted just before kill during -report-csv recovers proved_vcs.
    late_kill = W.parse_partial_wp_log_verdicts(
        "[wp] 22 goals scheduled\n[wp] [Timeout] typed_f_slow (Alt-Ergo) (Cached)\n[wp] Proved goals:   23 / 24\n"
    )
    assert late_kill is not None
    assert late_kill["scheduled_vcs"] == 24
    assert late_kill["proved_vcs"] == 23
    assert late_kill["timed_out_vcs"] == 1
    assert late_kill["completed_vcs"] == 24


@pytest.mark.unit
def test_run_wp_on_function_timeout_expired_attaches_partial_verdicts_without_crediting_goals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out_dir = tmp_path / "wp"
    c_file = tmp_path / "recv.c"
    c_file.write_text("int recv_msg(int n) { return n; }\n", encoding="utf-8")
    partial_stdout = (
        "[wp] Running WP plugin...\n"
        "[wp] 540 goals scheduled\n"
        "[wp] [Valid] typed_recv_msg_assert_ok (Qed 1ms)\n"
        "[wp] [Timeout] typed_recv_msg_assert_a (Qed 3ms) (Alt-Ergo) (Cached)\n"
        "[wp] [Timeout] typed_recv_msg_assert_b (Qed 4ms) (Alt-Ergo) (Cached)\n"
        "[wp] [Unknown] typed_recv_msg_assert_c (CVC5)\n"
    )

    def fake_timeout(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        raw_timeout = kwargs.get("timeout")
        timeout_s = float(raw_timeout) if isinstance(raw_timeout, (int, float)) else 10.0
        raise subprocess.TimeoutExpired(cmd, timeout_s, output=partial_stdout.encode("utf-8"))

    monkeypatch.setattr(W.subprocess, "run", fake_timeout)
    monkeypatch.chdir(tmp_path)
    res = W.run_wp_on_function(
        c_file, "recv_msg", out_dir, cache_dir="off", wall_timeout=10, retry_bitwise=False, retry_tail=False
    )
    assert res["status"] == "analysis_error"
    assert res["reason"] == "timeout"
    assert res["total_goals"] == 0
    assert res["proven_count"] == 0
    assert res["proven_under_hyp_count"] == 0
    assert res["unproven_count"] == 0
    pv = res.get("partial_verdicts")
    assert isinstance(pv, dict)
    assert pv["incomplete"] is True
    assert pv["scheduled_vcs"] == 540
    assert pv["completed_vcs"] == 4
    assert pv["proved_vcs"] == 1
    assert pv["timed_out_vcs"] == 2
    assert pv["cached_timed_out_vcs"] == 2
    assert pv["unknown_vcs"] == 1
    assert pv["timed_out_goals"] == ["typed_recv_msg_assert_a", "typed_recv_msg_assert_b"]
    assert any("4/540 VCs" in h and "2 timed out (2 cached)" in h and "--timeout" in h for h in res["diagnostic_hints"])

    # Also verify CLI main() surfaces partial_verdicts in stdout JSON summary and --out-json.
    out_json = tmp_path / "wp_recv_msg.json"
    buf_out: list[str] = []
    monkeypatch.setattr("builtins.print", lambda *a, **kw: buf_out.append(" ".join(str(x) for x in a)))
    rc = W.main(
        [
            "--file",
            str(c_file),
            "--function",
            "recv_msg",
            "--out-dir",
            str(out_dir),
            "--out-json",
            str(out_json),
            "--cache-dir",
            "off",
            "--wall-timeout",
            "10",
        ]
    )
    assert rc == 0
    summary = json.loads(buf_out[-1])
    assert summary["status"] == "analysis_error"
    assert summary["partial_verdicts"]["scheduled_vcs"] == 540
    assert json.loads(out_json.read_text(encoding="utf-8"))["partial_verdicts"]["cached_timed_out_vcs"] == 2


@pytest.mark.unit
def test_run_wp_on_function_oom_before_wp_omits_partial_verdicts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out_dir = tmp_path / "wp"
    c_file = tmp_path / "oom.c"
    c_file.write_text("int oom_fn(int n) { return n; }\n", encoding="utf-8")

    def fake_oom(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, -9, stdout="[kernel] Parsing oom.c\n", stderr="")

    monkeypatch.setattr(W.subprocess, "run", fake_oom)
    monkeypatch.chdir(tmp_path)
    res = W.run_wp_on_function(c_file, "oom_fn", out_dir, cache_dir="off", retry_bitwise=False, retry_tail=False)
    assert res["status"] == "analysis_error"
    assert res["reason"] == "oom_killed"
    assert "partial_verdicts" not in res
    assert any("Frama-C WP terminated before producing a report" in h for h in res["diagnostic_hints"])
