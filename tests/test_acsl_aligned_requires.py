"""An agent-added `requires \\aligned(...)` is refused: WP implements `\\aligned` under no memory model.

QCBOR run-6 (2026-11-15): the merged `UsefulOutBuf_Reset` contract carried `requires \\aligned(...)`; WP
prints `\\aligned not yet implemented` and every caller's precondition goal stays Unknown (Degenerated).
"""

from __future__ import annotations

import pytest

from acsl_ast import AcslError, find_unsound_acsl_keywords, splice_prover_changes, tokenize_c_acsl, verify_acsl_only

SRC_C = """#include <stdint.h>
int load(const uint32_t *p) {
    return (int)*p;
}
"""

FN = "int load(const uint32_t *p) {"


def _with(contract: str, base: str = SRC_C) -> str:
    return base.replace(FN, contract + FN)


@pytest.mark.parametrize(
    "contract",
    [
        "/*@ requires \\valid_read(p);\n    requires \\aligned(p, 4); */\n",
        "/*@ requires al: \\aligned (p, 4) && \\valid_read(p); */\n",
        "/*@ behavior b:\n      assumes p != \\null;\n      requires \\aligned(p, 4); */\n",
        "//@ requires \\aligned(p, 4);\n",
    ],
    ids=["second-clause", "labelled-conjunct", "behavior-level", "line-annotation"],
)
def test_an_added_aligned_requires_is_refused(contract: str) -> None:
    errors = verify_acsl_only(SRC_C, _with(contract), path="m.c")
    assert any("\\aligned" in e and "boundary_assumptions" in e for e in errors), errors


def test_the_splice_refuses_it_too() -> None:
    with pytest.raises(AcslError, match=r"boundary_assumptions"):
        splice_prover_changes(SRC_C, _with("/*@ requires \\aligned(p, 4); */\n"), SRC_C, "load", path="m.c")


@pytest.mark.parametrize(
    "contract",
    [
        "/*@ ensures \\aligned(\\result, 4); */\n",
        "/*@ requires \\valid_read(p); */\n",
        "/*@ requires aligned_ok: \\valid_read(p); */\n",
    ],
    ids=["ensures", "no-aligned", "label-named-aligned"],
)
def test_other_clauses_are_not_refused(contract: str) -> None:
    assert verify_acsl_only(SRC_C, _with(contract), path="m.c") == []


def test_an_aligned_requires_of_the_baseline_is_not_the_agents() -> None:
    baseline = _with("/*@ requires \\aligned(p, 4); */\n")
    # The agent extends the target's own block: the block is new text, the \aligned clause is not.
    agent = baseline.replace("requires \\aligned(p, 4); */", "requires \\aligned(p, 4);\n    assigns \\nothing; */")
    assert verify_acsl_only(baseline, agent, path="m.c") == []


def test_the_standalone_keyword_scan_is_unchanged() -> None:
    tokens = tokenize_c_acsl(_with("/*@ requires \\aligned(p, 4); */\n"))
    assert find_unsound_acsl_keywords(tokens) == []
