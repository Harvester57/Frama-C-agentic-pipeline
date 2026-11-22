"""Empirical Challenger 1 stress tests for Milestone M3.

Tests WP parser hardening:
1. classify_vacuity_log in scripts/run_wp_function.py
2. run_wp_on_function proven goals backstop
3. _kernel_error_line in scripts/loop_seeds.py
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import loop_seeds as ls
import run_wp_function as W

CSV_HEADER = "emitter\tfile\tfunction\tline\tkind\tstatus\tproperty\n"


# ===========================================================================
# 1. Stress Tests: classify_vacuity_log
# ===========================================================================


@pytest.mark.unit
def test_vacuity_prover_models_doomed_requires() -> None:
    """Varied prover memory models with doomed requires must return contradictory."""
    models = ["raw_", "bytes_", "hoare_", "typed_caveat_", "typed_", "custom_model_v2_"]
    clauses = ["default", "r1", "pre_condition_2", "tag_requires"]
    for m in models:
        for c in clauses:
            log = f"[wp] [Failed] (Doomed) {m}fn_wp_smoke_{c}_requires (Qed)\nSmoke Tests: 0 / 1\n"
            res = W.classify_vacuity_log(log)
            assert res["status"] == "contradictory", f"Model {m} clause {c} failed: {res}"
            assert c in res["doomed"]


@pytest.mark.unit
def test_vacuity_prover_models_dead_goals() -> None:
    """Varied prover memory models with dead code goals."""
    models = ["raw_", "bytes_", "hoare_", "typed_caveat_", "typed_"]
    kinds = ["dead_code_s1", "dead_call_s2", "dead_loop_s3", "dead_local_init_s4"]
    for m in models:
        for k in kinds:
            log = f"[wp] [Failed] (Doomed) {m}fn_wp_smoke_{k} (Qed)\nSmoke Tests: 0 / 1\n"
            res = W.classify_vacuity_log(log)
            assert res["dead_goals"] == 1, f"Model {m} kind {k} failed: {res}"


@pytest.mark.unit
def test_vacuity_k_less_than_n_without_dead_goals_fails_closed() -> None:
    """When k < n and dead goals list is empty, must fail closed to inconclusive."""
    log = "[wp] [Timeout] typed_f_contract (Alt-Ergo)\nSmoke Tests: 1 / 3\n"
    res = W.classify_vacuity_log(log)
    assert res["status"] == "inconclusive"
    assert "without recognised doomed goals" in res["reason"]


@pytest.mark.unit
def test_vacuity_k_less_than_n_with_fewer_dead_goals_than_failures_xfail() -> None:
    """Stress test: k < n and dead goals are fewer than total failures (n - k > len(dead)).

    Example: n=3, k=1 -> 2 failures occurred. Only 1 dead goal is recognized.
    1 failure remains completely unexplained.
    Current implementation bug: returns 'consistent' because `not dead` evaluates to False.
    Safe behavior: must fail closed to inconclusive.
    """
    log = "[wp] [Failed] (Doomed) typed_f_wp_smoke_dead_code_s1 (Qed)\nSmoke Tests: 1 / 3\n"
    res = W.classify_vacuity_log(log)
    assert res["status"] == "inconclusive", (
        f"Unsound fail-open: returned {res['status']!r} despite unexplained failed smoke test!"
    )


@pytest.mark.unit
def test_vacuity_malformed_smoke_ratios_xfail() -> None:
    """Stress test malformed and impossible smoke test ratios."""
    # k > n: 2 / 1 is impossible
    res_impossible = W.classify_vacuity_log("Smoke Tests: 2 / 1\n")
    assert res_impossible["status"] == "inconclusive", f"Impossible ratio 2/1 returned: {res_impossible}"

    # 0 / 0: zero smoke tests run
    res_zero = W.classify_vacuity_log("Smoke Tests: 0 / 0\n")
    assert res_zero["status"] == "inconclusive", f"Zero ratio 0/0 returned: {res_zero}"


@pytest.mark.unit
def test_vacuity_malformed_smoke_summaries_non_numeric() -> None:
    """Stress test non-numeric malformed smoke test summaries."""
    non_numeric_cases = [
        "Smoke Tests: invalid",
        "Smoke Tests: 1",
        "Smoke Tests: / 2",
        "Smoke Tests: k / n",
        "Smoke Tests: -1 / 2",
    ]
    for snippet in non_numeric_cases:
        res = W.classify_vacuity_log(snippet)
        assert res["status"] == "inconclusive", f"Expected inconclusive for {snippet!r}, got {res}"


@pytest.mark.unit
def test_vacuity_multiline_logs() -> None:
    """Multiline noisy logs with warnings, errors, and solver outputs."""
    log = (
        "[kernel] Parsing test.c (with preprocessing)\n"
        "[kernel:annot-error] test.c:5: Warning: some warning\n"
        "[wp] 3 goals scheduled\n"
        "[wp] [Failed] (Doomed) typed_f_wp_smoke_r_requires (Alt-Ergo 0.05s)\n"
        "[wp] [Passed] typed_f_wp_smoke_dead_code_s1 (Qed)\n"
        "[wp] Proved goals: 1 / 3\n"
        "   Smoke Tests: 0 / 2\n"
    )
    res = W.classify_vacuity_log(log)
    assert res["status"] == "contradictory"
    assert "r" in res["doomed"]


# ===========================================================================
# 2. Stress Tests: run_wp_on_function proven goals backstop
# ===========================================================================


@pytest.mark.unit
def test_wp_backstop_report_csv_statuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test various CSV goal status permutations against the backstop."""
    out_dir = tmp_path / "wp"
    out_dir.mkdir()
    c_file = tmp_path / "f.c"
    c_file.write_text("int f(int x) { return x; }\n", encoding="utf-8")

    def run_with(csv_rows: list[str], stdout: str, returncode: int = 0) -> dict:
        def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            if "-wp" in cmd and "-report-csv" in cmd:
                csv_path = Path(cmd[cmd.index("-report-csv") + 1])
                csv_content = CSV_HEADER + "".join(csv_rows)
                csv_path.write_text(csv_content, encoding="utf-8")
                return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        monkeypatch.setattr(W.subprocess, "run", fake_run)
        return W.run_wp_on_function(c_file, "f", out_dir, retry_bitwise=False)

    # 1. Valid goals proved: 2/2 -> all_proven
    rows_valid = [
        ".\tf.c\tf\t1\trte: mem_access\tValid\tx\n",
        ".\tf.c\tf\t2\tpostcondition\tValid\tx > 0\n",
    ]
    res = run_with(rows_valid, "[wp] Proved goals: 2 / 2\n")
    assert res["status"] == "all_proven"

    # 2. Missing 'Proved goals:' line -> unproven_goals_remain
    res = run_with(rows_valid, "[wp] 2 goals scheduled\n")
    assert res["status"] == "unproven_goals_remain"

    # 3. Proved goals 0 / 0 -> unproven_goals_remain
    res = run_with(rows_valid, "[wp] Proved goals: 0 / 0\n")
    assert res["status"] == "unproven_goals_remain"

    # 4. Proved goals 1 / 2 (vc_proved < vc_total) -> unproven_goals_remain
    res = run_with(rows_valid, "[wp] Proved goals: 1 / 2\n")
    assert res["status"] == "unproven_goals_remain"

    # 5. Proved goals 2 / 2 BUT Timeout: 1 -> unproven_goals_remain
    res = run_with(rows_valid, "[wp] Proved goals: 2 / 2\n[wp] Timeout: 1\n")
    assert res["status"] == "unproven_goals_remain"

    # 6. Returncode != 0 -> unproven_goals_remain
    res = run_with(rows_valid, "[wp] Proved goals: 2 / 2\n", returncode=1)
    assert res["status"] == "unproven_goals_remain"

    # 7. Empty CSV (total_goals == 0) -> unproven_goals_remain
    res = run_with([], "[wp] Proved goals: 2 / 2\n")
    assert res["status"] == "unproven_goals_remain"

    # 8. CSV has unproven goal (Unknown) even if Proved goals claims 2 / 2
    rows_unproven = [
        ".\tf.c\tf\t1\trte: mem_access\tValid\tx\n",
        ".\tf.c\tf\t2\tpostcondition\tUnknown\tx > 0\n",
    ]
    res = run_with(rows_unproven, "[wp] Proved goals: 2 / 2\n")
    assert res["status"] == "unproven_goals_remain"


@pytest.mark.unit
def test_wp_backstop_degenerated_goal_waiver(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Stress test Degenerated-goal waiver interactions with the backstop."""
    out_dir = tmp_path / "wp"
    out_dir.mkdir()
    c_file = tmp_path / "f.c"
    c_file.write_text("int f(int (*fp)(void)) { return fp(); }\n", encoding="utf-8")

    def run_degen(stdout: str) -> dict:
        def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            if "-wp" in cmd and "-report-csv" in cmd:
                csv_path = Path(cmd[cmd.index("-report-csv") + 1])
                csv_content = CSV_HEADER + ".\tf.c\tf\t1\tpointer_value\tUnknown\t\\valid_function(fp)\n"
                csv_path.write_text(csv_content, encoding="utf-8")
                return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        monkeypatch.setattr(W.subprocess, "run", fake_run)
        return W.run_wp_on_function(c_file, "f", out_dir, retry_bitwise=False)

    # Degenerated waiver with no Proved goals line -> unproven_goals_remain
    stdout_no_proved = "[wp] [Timeout] typed_f_assert_rte_pointer_value (Qed) (Degenerated)\n"
    res = run_degen(stdout_no_proved)
    assert res["status"] == "unproven_goals_remain"

    # Degenerated waiver with Proved goals: 0 / 1 -> unproven_goals_remain
    stdout_zero_proved = (
        "[wp] [Timeout] typed_f_assert_rte_pointer_value (Qed) (Degenerated)\n[wp] Proved goals: 0 / 1\n"
    )
    res = run_degen(stdout_zero_proved)
    assert res["status"] == "unproven_goals_remain"

    # Degenerated waiver with Proved goals: 1 / 1 -> all_proven
    stdout_proved = "[wp] [Timeout] typed_f_assert_rte_pointer_value (Qed) (Degenerated)\n[wp] Proved goals: 1 / 1\n"
    res = run_degen(stdout_proved)
    assert res["status"] == "all_proven"


# ===========================================================================
# 3. Stress Tests: _kernel_error_line in scripts/loop_seeds.py
# ===========================================================================


@pytest.mark.unit
def test_kernel_error_line_suffix_overlap_rejected() -> None:
    """Filenames that share a suffix with the query filename must be rejected."""
    overlaps = [
        "[kernel] not_sum.c:9: User Error: boom",
        "[kernel] prefix_sum.c:9: User Error: boom",
        "[kernel] other-sum.c:9: User Error: boom",
        "[kernel] badsum.c:9: User Error: boom",
        "[kernel] a.sum.c:9: User Error: boom",
    ]
    for msg in overlaps:
        result = {"syntax_check": {"errors": [msg]}}
        assert ls._kernel_error_line(result, "sum.c") is None, f"Suffix overlap not rejected: {msg}"


@pytest.mark.unit
def test_kernel_error_line_bare_filename_accepted() -> None:
    """Bare filename matching works correctly."""
    result = {"syntax_check": {"errors": ["[kernel] sum.c:9: User Error: boom"]}}
    assert ls._kernel_error_line(result, "sum.c") == 9


@pytest.mark.unit
def test_kernel_error_line_path_prefixing_bug_reproduction() -> None:
    """Path-prefixed filenames must extract the correct line number.

    Current implementation bug: regex (?<![\\w./-]) includes '/' in the negative lookbehind.
    When a filename is preceded by a directory (e.g. dir/sum.c or ./sum.c), the preceding
    character is '/', causing the match to fail and returning None.
    """
    path_cases = [
        ("[kernel] dir/sum.c:9: User Error: boom", "sum.c", 9),
        ("[kernel] ./sum.c:9: User Error: boom", "sum.c", 9),
        ("[kernel] /abs/path/sum.c:9: User Error: boom", "sum.c", 9),
        ("[kernel] workspace/work/sum.c:9: error", "sum.c", 9),
    ]
    for msg, query, expected in path_cases:
        result = {"syntax_check": {"errors": [msg]}}
        actual = ls._kernel_error_line(result, query)
        assert actual == expected, f"Failed on path-prefixed message: {msg!r} -> expected {expected}, got {actual}"
