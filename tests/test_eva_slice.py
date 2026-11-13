"""Tests for run_eva_slice: missing spec repair hints and error summary extraction."""

from __future__ import annotations

import pytest

import run_eva_slice as E


@pytest.mark.unit
def test_extract_repair_hints_missing_spec_all_forms() -> None:
    log = (
        "[kernel] Neither code nor specification for function ext_fn,\n"
        "[kernel] Neither code nor explicit assigns for function rec_fn,\n"
        "[kernel:annot:missing-spec] a.c:10: Warning:\n"
        "  Neither code nor explicit exits, assigns and terminates for function\n"
        "  wrapped_fn, generating default clauses.\n"
        "[kernel] Neither code nor explicit exits and terminates for function benign_fn,\n"
    )
    hints = E.extract_repair_hints(log)
    by_fn = {h.get("function"): h for h in hints if h.get("pattern") == "missing_spec"}

    assert "ext_fn" in by_fn and by_fn["ext_fn"]["spec_kind"] == "specification"
    assert "rec_fn" in by_fn and by_fn["rec_fn"]["spec_kind"] == "assigns"
    assert "wrapped_fn" in by_fn and by_fn["wrapped_fn"]["spec_kind"] == "assigns"
    assert "benign_fn" not in by_fn


@pytest.mark.unit
def test_extract_error_summary_two_line_kernel_errors() -> None:
    log = (
        "[kernel:annot-error] foo.c:42: Warning:\n"
        "  unbound logic variable val.\n"
        "[kernel] user error: syntax error\n"
        + "\n".join(f"unrelated tail line {i}" for i in range(50))
    )
    summary = E.extract_error_summary(log, max_lines=5)
    assert len(summary) >= 2
    assert any("foo.c:42" in s and "unbound logic variable val" in s for s in summary)
