"""Empirical Challenger 2 stress tests for Milestone M3.

Tests Eva parser, stub check, and loop annotation hardening:
1. scripts/run_eva_slice.py: missing spec detection across all variants and error summary extraction.
2. scripts/stub_check.py: check_eva handling of -report-csv rows, ok vs short calls, STATUS_DEAD, uncarried log warnings, missing CSV.
3. scripts/eva_loops.py: multi-line loop annotations with leading @, multiple clauses, comments, indentation, nested loops.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import eva_loops
import framac_common as fc
import run_eva_slice as E
import stub_check
from eva_loops import LoopRef

pytestmark = pytest.mark.unit

_CSV_HEADER = ("directory", "file", "line", "function", "property kind", "status", "property")
_HASH_PROTO = "int ml_hash(unsigned char const *data, size_t len, unsigned char out[32])"
_SUM_PROTO = "int ml_sum(char const *s, size_t n)"
_ID_PROTO = "int ml_id(int x)"
_VALID_DATA = r"valid_data: len > 0 ==> \valid_read(data + (0 .. len - 1))"
_VALID_OUT = r"valid_out: \valid(out + (0 .. 31))"
_VALID_S = r"valid_s: \valid_read(s + (0 .. n - 1))"
_EVA_DONE = "[eva] done for function fc_stub_smoke_main\n"


def _smoke_sigs():
    parsed = [stub_check.parse_proto(p) for p in (_HASH_PROTO, _SUM_PROTO, _ID_PROTO)]
    sigs = [s for s in parsed if s is not None]
    assert len(sigs) == len(parsed)
    _, lines_of = stub_check.smoke_source("mylib.h", sigs)
    line = {where: n for n, where in lines_of.items()}
    return sigs, line, lines_of


def _csv(rows) -> str:
    return "".join("\t".join(str(c) for c in row) + "\n" for row in (_CSV_HEADER, *rows))


def _call_row(line, caller, callee, status, prop, file="fc_stub_smoke.c"):
    return (".", file, line, caller, f"precondition of {callee}", status, prop)


def _run_eva_mock(monkeypatch, tmp_path, sigs, rows, log=_EVA_DONE, write_csv=True, rc=0):
    seen: dict = {}

    def fake_run(cmd, cwd, timeout=0, env=None):
        seen["cmd"] = cmd
        if write_csv:
            target = Path(cwd) / cmd[cmd.index("-report-csv") + 1]
            target.write_text(_csv(rows), encoding="utf-8", newline="")
        return rc, log

    monkeypatch.setattr(stub_check, "_run", fake_run)
    res = stub_check.check_eva("mylib.h", sigs, tmp_path)
    return res, seen


# ===========================================================================
# 1. Stress Tests: run_eva_slice.py (Missing Spec & Error Summary)
# ===========================================================================


def test_missing_spec_variants_generator() -> None:
    """Generate all combinatorial variants of missing spec clauses and verify classification."""
    cases = [
        # (clause_text, expected_spec_kind, is_benign)
        ("specification", "specification", False),
        ("explicit assigns", "assigns", False),
        ("explicit exits", None, True),
        ("explicit terminates", None, True),
        ("explicit exits and terminates", None, True),
        ("explicit terminates and exits", None, True),
        ("explicit exits, assigns and terminates", "assigns", False),
        ("explicit assigns and terminates", "assigns", False),
        ("explicit exits and assigns", "assigns", False),
        ("explicit assigns, exits and terminates", "assigns", False),
        ("explicit terminates, assigns and exits", "assigns", False),
    ]

    for clause, exp_kind, exp_benign in cases:
        msg = f"[kernel:annot:missing-spec] test.c:1: Warning: Neither code nor {clause} for function fn_{exp_kind or 'benign'}, generating default clauses."
        specs = fc.parse_missing_spec(msg)
        assert len(specs) == 1, f"Failed to parse: {msg}"
        spec = specs[0]
        assert spec.benign == exp_benign, f"Benign mismatch for {clause}: got {spec.benign}, expected {exp_benign}"

        hints = E.extract_repair_hints(msg)
        if exp_benign:
            assert len(hints) == 0, f"Benign clause {clause} should yield no hints, got: {hints}"
        else:
            assert len(hints) == 1, f"Expected 1 hint for {clause}, got {hints}"
            assert hints[0]["pattern"] == "missing_spec"
            assert hints[0]["spec_kind"] == exp_kind
            assert hints[0]["function"] == f"fn_{exp_kind}"


def test_missing_spec_multiline_and_wrapped_formats() -> None:
    """Stress test multi-line, indented, and differently punctuated missing spec logs."""
    log = (
        "[kernel:annot:missing-spec] a.c:15: Warning:\n"
        "  Neither code nor explicit exits, assigns and terminates for function\n"
        "  wrapped_fn, generating default clauses.\n"
        "[kernel] b.c:20: Warning:\n"
        "  Neither code nor specification for function\n"
        "  multi_spec_fn;\n"
        "[kernel] Neither code nor explicit assigns for function flat_fn,\n"
        "[kernel:annot:missing-spec] c.c:30: Warning: Neither code nor explicit exits and terminates for function benign_wrapped_fn, generating default clauses.\n"
    )
    hints = E.extract_repair_hints(log)
    by_fn = {h["function"]: h for h in hints if h.get("pattern") == "missing_spec"}

    assert "wrapped_fn" in by_fn
    assert by_fn["wrapped_fn"]["spec_kind"] == "assigns"

    assert "multi_spec_fn" in by_fn
    assert by_fn["multi_spec_fn"]["spec_kind"] == "specification"

    assert "flat_fn" in by_fn
    assert by_fn["flat_fn"]["spec_kind"] == "assigns"

    assert "benign_wrapped_fn" not in by_fn


def test_missing_spec_unrecognised_wording_fails_closed() -> None:
    """Unrecognised clause wording under 'Neither code nor' must fail closed (benign=False)."""
    unrec_log = "[kernel] Neither code nor arbitrary_future_clause for function weird_fn, generating default clauses."
    specs = fc.parse_missing_spec(unrec_log)
    assert len(specs) == 1
    assert specs[0].benign is False

    hints = E.extract_repair_hints(unrec_log)
    assert len(hints) == 1
    assert hints[0]["function"] == "weird_fn"
    assert hints[0]["spec_kind"] == "assigns"


def test_error_summary_extraction_kernel_and_compiler_variants() -> None:
    """Stress test extract_error_summary on diverse single and multi-line diagnostics."""
    log = (
        "[kernel] user error: syntax error at token 'x'\n"
        "[kernel:annot-error] foo.c:42: Warning:\n"
        "  unbound logic variable val.\n"
        "bar.c:12:5: error: unknown type name 'size_t'\n"
        "baz.c:1:2: error: stray '\u2018' in program\n"
        "[kernel] fatal error: out of memory\n" + "\n".join(f"normal log line {i}" for i in range(100))
    )
    summary = E.extract_error_summary(log, max_lines=10)
    assert len(summary) == 5
    assert any("syntax error" in s for s in summary)
    assert any("foo.c:42" in s and "unbound logic variable" in s for s in summary)
    assert any("bar.c:12:5" in s and "size_t" in s for s in summary)
    assert any("baz.c:1:2" in s for s in summary)
    assert any("fatal error" in s for s in summary)


def test_error_summary_deduplication_and_limit() -> None:
    """Duplicate diagnostics must be deduplicated and max_lines respected."""
    dup_lines = ["[kernel] user error: duplicate error line\n" for _ in range(30)]
    log = "".join(dup_lines)
    summary = E.extract_error_summary(log, max_lines=5)
    assert len(summary) == 1


def test_error_summary_fallback_on_clean_or_unmatched_log() -> None:
    """When no kernel error matches, extract_error_summary falls back to tail lines."""
    log = "\n".join(f"info line {i}" for i in range(50))
    summary = E.extract_error_summary(log, max_lines=3)
    assert summary == ["info line 47", "info line 48", "info line 49"]

    empty_summary = E.extract_error_summary("", max_lines=5)
    assert empty_summary == []


def test_error_summary_preprocessed_file_extension() -> None:
    """Preprocessor error on a .i preprocessed file must be captured via the _KERNEL_ERR_RE branch."""
    log = "foo.i:12:3: error: expected ';' before '}' token\n"
    summary = E.extract_error_summary(log, max_lines=5)
    assert len(summary) == 1
    assert "foo.i:12:3" in summary[0]


def test_missing_spec_mixed_plugin_and_raw_dropped_behavior() -> None:
    """Adversarial case: When log mixes [kernel] plugin lines and raw lines without [plugin].

    Because missing_spec_messages requires m.plugin != '', a raw line without [plugin]
    is omitted from missing_spec_messages. Then, because specs is non-empty (it found the
    [kernel] line), the fallback 'if not specs:' does not run, dropping the raw line.
    """
    log = (
        "[kernel] Neither code nor explicit exits and terminates for function benign_fn\n"
        "Neither code nor explicit assigns for function raw_fn\n"
    )
    hints = E.extract_repair_hints(log)
    # Document empirical behavior: raw_fn is dropped because benign_fn populated specs
    assert len(hints) == 0
    # In contrast, when the raw line is alone, 'if not specs:' activates and catches it:
    alone_hints = E.extract_repair_hints("Neither code nor explicit assigns for function raw_fn\n")
    assert len(alone_hints) == 1
    assert alone_hints[0]["function"] == "raw_fn"


# ===========================================================================
# 2. Stress Tests: stub_check.py (check_eva Handling of CSV and Log Alarms)
# ===========================================================================


def test_check_eva_valid_vs_invalid_statuses(monkeypatch, tmp_path) -> None:
    """Verify check_eva property status matrix across ok and short calls."""
    sigs, line, _ = _smoke_sigs()

    # Matrix:
    # ml_hash: ok has Valid, short has Invalid -> passed
    # ml_sum: ok has Valid under hyp, short has Unknown -> passed
    # ml_id: only ok call, Valid -> passed
    rows = [
        _call_row(line["ml_hash", "ok"], "fc_smoke_ok_ml_hash", "ml_hash", "Valid", _VALID_DATA),
        _call_row(line["ml_hash", "ok"], "fc_smoke_ok_ml_hash", "ml_hash", "Valid", _VALID_OUT),
        _call_row(line["ml_hash", "short"], "fc_smoke_short_ml_hash", "ml_hash", "Invalid", _VALID_DATA),
        _call_row(line["ml_hash", "short"], "fc_smoke_short_ml_hash", "ml_hash", "Valid", _VALID_OUT),
        _call_row(line["ml_sum", "ok"], "fc_smoke_ok_ml_sum", "ml_sum", "Valid under hyp", _VALID_S),
        _call_row(line["ml_sum", "short"], "fc_smoke_short_ml_sum", "ml_sum", "Unknown", _VALID_S),
        _call_row(line["ml_id", "ok"], "fc_smoke_ok_ml_id", "ml_id", "Valid", "x == x"),
    ]
    res, _ = _run_eva_mock(monkeypatch, tmp_path, sigs, rows)
    assert res["status"] == "ok"
    assert res["functions"]["ml_hash"]["status"] == "passed"
    assert res["functions"]["ml_sum"]["status"] == "passed"
    assert res["functions"]["ml_id"]["status"] == "passed"


def test_check_eva_valid_call_alarm_precedence(monkeypatch, tmp_path) -> None:
    """If an ok call triggers an alarm, status must be valid_call_alarm even if short caught."""
    sigs, line, _ = _smoke_sigs()
    rows = [
        _call_row(line["ml_hash", "ok"], "fc_smoke_ok_ml_hash", "ml_hash", "Unknown", _VALID_DATA),
        _call_row(line["ml_hash", "short"], "fc_smoke_short_ml_hash", "ml_hash", "Invalid", _VALID_DATA),
    ]
    res, _ = _run_eva_mock(monkeypatch, tmp_path, sigs, rows)
    assert res["functions"]["ml_hash"]["status"] == "valid_call_alarm"
    assert len(res["functions"]["ml_hash"]["valid_call_alarms"]) == 1


def test_check_eva_dead_short_call_is_too_weak(monkeypatch, tmp_path) -> None:
    """STATUS_DEAD on a short call does NOT count as catching the error; status must be too_weak."""
    sigs, line, _ = _smoke_sigs()
    rows = [
        _call_row(line["ml_hash", "ok"], "fc_smoke_ok_ml_hash", "ml_hash", "Valid", _VALID_DATA),
        _call_row(line["ml_hash", "ok"], "fc_smoke_ok_ml_hash", "ml_hash", "Valid", _VALID_OUT),
        _call_row(line["ml_hash", "short"], "fc_smoke_short_ml_hash", "ml_hash", "Dead", _VALID_DATA),
        _call_row(line["ml_hash", "short"], "fc_smoke_short_ml_hash", "ml_hash", "Dead", _VALID_OUT),
    ]
    res, _ = _run_eva_mock(monkeypatch, tmp_path, sigs, rows)
    assert res["functions"]["ml_hash"]["status"] == "too_weak"
    assert res["functions"]["ml_hash"]["short_call_alarms"] == []


def test_check_eva_missing_csv_fails_closed(monkeypatch, tmp_path) -> None:
    """If CSV report file is not produced, check_eva must fail closed with error status."""
    sigs, _, _ = _smoke_sigs()
    res, _ = _run_eva_mock(monkeypatch, tmp_path, sigs, [], write_csv=False)
    assert res["status"] == "error"
    assert "no Eva report CSV produced" in res["reason"]


def test_check_eva_nonzero_exit_fails_closed(monkeypatch, tmp_path) -> None:
    """If Frama-C exits non-zero, check_eva must return error status."""
    sigs, _, _ = _smoke_sigs()
    res, _ = _run_eva_mock(monkeypatch, tmp_path, sigs, [], rc=1, log="[kernel] user error: boom\n")
    assert res["status"] == "error"
    assert "boom" in res["reason"]


def test_check_eva_uncarried_log_warning_fallback(monkeypatch, tmp_path) -> None:
    """Log warnings uncarried by CSV must be parsed and tagged as (Eva log only)."""
    sigs, line, _ = _smoke_sigs()
    log = (
        f"[eva:alarm] fc_stub_smoke.c:{line['ml_sum', 'ok']}: Warning: \n"
        "  function ml_sum, behavior default: precondition 'uncarried_pred' got status unknown.\n" + _EVA_DONE
    )
    # CSV has valid call as Valid, so CSV alone would pass
    rows = [
        _call_row(line["ml_sum", "ok"], "fc_smoke_ok_ml_sum", "ml_sum", "Valid", _VALID_S),
        _call_row(line["ml_sum", "short"], "fc_smoke_short_ml_sum", "ml_sum", "Unknown", _VALID_S),
    ]
    res, _ = _run_eva_mock(monkeypatch, tmp_path, sigs, rows, log=log)
    rec = res["functions"]["ml_sum"]
    assert rec["status"] == "valid_call_alarm"
    assert any("uncarried_pred" in a and "(Eva log only)" in a for a in rec["valid_call_alarms"])


def test_check_eva_foreign_csv_rows_filtered(monkeypatch, tmp_path) -> None:
    """CSV rows from other files or libc callees on the same line must be ignored."""
    sigs, line, _ = _smoke_sigs()
    rows = [
        # Foreign file (header)
        (".", "mylib.h", 10, "ml_hash", "precondition", "Unknown", "foreign_prop"),
        # Callee mismatch on the same smoke call line (e.g. libc helper call)
        _call_row(line["ml_hash", "ok"], "fc_smoke_ok_ml_hash", "memcpy", "Unknown", "valid_memcpy"),
        # Correct calls
        _call_row(line["ml_hash", "ok"], "fc_smoke_ok_ml_hash", "ml_hash", "Valid", _VALID_DATA),
        _call_row(line["ml_hash", "ok"], "fc_smoke_ok_ml_hash", "ml_hash", "Valid", _VALID_OUT),
        _call_row(line["ml_hash", "short"], "fc_smoke_short_ml_hash", "ml_hash", "Invalid", _VALID_DATA),
        _call_row(line["ml_hash", "short"], "fc_smoke_short_ml_hash", "ml_hash", "Valid", _VALID_OUT),
    ]
    res, _ = _run_eva_mock(monkeypatch, tmp_path, [sigs[0]], rows)
    assert res["functions"]["ml_hash"]["status"] == "passed"
    assert res["functions"]["ml_hash"]["valid_call_alarms"] == []


def test_check_eva_empty_csv_handling(monkeypatch, tmp_path) -> None:
    """A 0-byte CSV file produces 0 rows, resulting in too_weak for functions with short calls."""
    sigs, _, _ = _smoke_sigs()
    seen: dict = {}

    def fake_run(cmd, cwd, timeout=0, env=None):
        seen["cmd"] = cmd
        target = Path(cwd) / cmd[cmd.index("-report-csv") + 1]
        target.write_text("", encoding="utf-8")
        return 0, _EVA_DONE

    monkeypatch.setattr(stub_check, "_run", fake_run)
    res = stub_check.check_eva("mylib.h", sigs, tmp_path)
    assert res["status"] == "ok"
    assert res["functions"]["ml_hash"]["status"] == "too_weak"


# ===========================================================================
# 3. Stress Tests: eva_loops.py (Loop Annotations & Unroll Merging)
# ===========================================================================


def test_eva_loops_multiline_leading_at_clauses() -> None:
    """Stress test multi-line loop annotations with leading @, tabs, spaces, and multiple clauses."""
    source = (
        "void f(int n) {\n"
        "  /*@\n"
        "    @ loop invariant 0 <= i;\n"
        "    @ loop variant n - i;\n"
        "    @ loop assigns i;\n"
        "    @*/\n"
        "  for (int i = 0; i < n; i++) {}\n"
        "}\n"
    )
    refs = [LoopRef("a.c", "f", 0, 16)]
    annotated, applied, dropped = eva_loops.annotate_source(source, refs)
    assert applied == refs and dropped == []
    # Exactly one /*@ block must be present
    assert annotated.count("/*@") == 1
    assert "loop unroll 16;" in annotated
    assert "loop invariant 0 <= i;" in annotated
    assert "loop variant n - i;" in annotated


def test_eva_loops_crlf_and_multiple_at() -> None:
    """Stress test CRLF line endings and multiple consecutive @ characters."""
    source = (
        "void f(int n) {\r\n"
        "  /*@\r\n"
        "    @@@ loop invariant 0 <= i;\r\n"
        "    @@@*/\r\n"
        "  for (int i = 0; i < n; i++) {}\r\n"
        "}\r\n"
    )
    refs = [LoopRef("a.c", "f", 0, 8)]
    annotated, applied, dropped = eva_loops.annotate_source(source, refs)
    assert applied == refs and dropped == []
    assert annotated.count("/*@") == 1
    assert "loop unroll 8;" in annotated


def test_eva_loops_for_behavior_syntax() -> None:
    """Loop annotations with 'for <behavior>:' syntax."""
    source = (
        "void f(int n) {\n"
        "  /*@\n"
        "    @ for default, special:\n"
        "    @ loop invariant 0 <= i;\n"
        "    @*/\n"
        "  while (n > 0) { n--; }\n"
        "}\n"
    )
    refs = [LoopRef("a.c", "f", 0, 4)]
    annotated, applied, dropped = eva_loops.annotate_source(source, refs)
    assert applied == refs and dropped == []
    assert annotated.count("/*@") == 1
    assert "loop unroll 4;" in annotated


def test_eva_loops_nested_loops_simultaneous_annotation() -> None:
    """Stress test deeply nested loops: outer, middle, inner annotated simultaneously."""
    source = (
        "void nested(int a, int b, int c) {\n"
        "  /*@\n"
        "    @ loop invariant 0 <= i;\n"
        "    @*/\n"
        "  for (int i = 0; i < a; i++) {\n"
        "    /*@\n"
        "      @ loop invariant 0 <= j;\n"
        "      @*/\n"
        "    for (int j = 0; j < b; j++) {\n"
        "      int k = 0;\n"
        "      do {\n"
        "        k++;\n"
        "      } while (k < c);\n"
        "    }\n"
        "  }\n"
        "}\n"
    )
    refs = [
        LoopRef("a.c", "nested", 0, 2),
        LoopRef("a.c", "nested", 1, 4),
        LoopRef("a.c", "nested", 2, 8),
    ]
    annotated, applied, dropped = eva_loops.annotate_source(source, refs)
    assert applied == refs and dropped == []
    # Loop 0 and 1 had existing /*@, loop 2 was unannotated
    assert annotated.count("/*@") == 3
    assert "loop unroll 2;" in annotated
    assert "loop unroll 4;" in annotated
    assert "loop unroll 8;" in annotated


def test_eva_loops_comments_interspersed() -> None:
    """Comments before and between ACSL annotations and loop keywords."""
    source = (
        "void f(int n) {\n"
        "  /* Outer C comment */\n"
        "  /*@\n"
        "    @ loop invariant 0 <= i;\n"
        "    @*/\n"
        "  /* Intervening C comment */\n"
        "  for (int i = 0; i < n; i++) {}\n"
        "}\n"
    )
    refs = [LoopRef("a.c", "f", 0, 32)]
    annotated, applied, dropped = eva_loops.annotate_source(source, refs)
    assert applied == refs and dropped == []
    assert annotated.count("/*@") == 1
    assert "loop unroll 32;" in annotated


def test_eva_loops_single_line_acsl_continuation() -> None:
    """Consecutive single-line //@ comments."""
    source = (
        "void f(int n) {\n"
        "  //@ loop invariant 0 <= i;\n"
        "  //@ loop variant n - i;\n"
        "  for (int i = 0; i < n; i++) {}\n"
        "}\n"
    )
    refs = [LoopRef("a.c", "f", 0, 8)]
    annotated, applied, dropped = eva_loops.annotate_source(source, refs)
    assert applied == refs and dropped == []
    assert "loop unroll 8;" in annotated


def test_eva_loops_preexisting_multiline_unroll_detected() -> None:
    """Pre-existing multi-line loop unroll annotation must be detected and dropped."""
    source = "void f(int n) {\n  /*@\n    @ loop\n    @   unroll 16;\n    @*/\n  for (int i = 0; i < n; i++) {}\n}\n"
    refs = [LoopRef("a.c", "f", 0, 32)]
    annotated, applied, dropped = eva_loops.annotate_source(source, refs)
    assert applied == []
    assert dropped == refs
    assert annotated == source


def test_eva_loops_infinite_loops_and_labels() -> None:
    """Stress test for(;;), while(1), and labels preceding loop annotations."""
    source = (
        "void f(void) {\n"
        "  top_label:\n"
        "  /*@\n"
        "    @ loop invariant 1;\n"
        "    @*/\n"
        "  for (;;) {\n"
        "    break;\n"
        "  }\n"
        "  /*@\n"
        "    @ loop invariant 1;\n"
        "    @*/\n"
        "  while (1) {\n"
        "    break;\n"
        "  }\n"
        "}\n"
    )
    refs = [LoopRef("a.c", "f", 0, 4), LoopRef("a.c", "f", 1, 8)]
    annotated, applied, dropped = eva_loops.annotate_source(source, refs)
    assert applied == refs and dropped == []
    assert annotated.count("/*@") == 2
    assert "loop unroll 4;" in annotated
    assert "loop unroll 8;" in annotated
