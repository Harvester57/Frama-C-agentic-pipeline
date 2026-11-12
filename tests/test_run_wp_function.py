"""Tests for run_wp_function: vacuity classification, proven goals backstop, missing spec detection, message folding."""

from __future__ import annotations

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
