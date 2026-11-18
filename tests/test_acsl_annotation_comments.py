"""
Text the Frama-C kernel does not read inside an ACSL annotation must not count as a clause, and text
it does read must not be hidden: `//` comments, a nested `//@` (a comment, except in ghost code), `@`
(white space) and literals, in `acsl_ast.iter_clauses` and every check built on it.

libmodbus run-1 (2026-11-18): `negotiate-modbus_tcp_build_request_basis-2` merged an `assigns` clause
whose required location `ctx_tcp->t_id` stood only in a `//` comment, and the frame check counted it.

The kernel's side is recorded in `tests/fixtures/acsl_kernel_comments/` (inputs, the logs
framac-analysis:latest printed for them, and `scenario.sh` with the commands).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from acsl_ast import (  # noqa: E402
    SHAPE_SAFETY_ONLY,
    _acsl_comment_body,
    check_frame_preserved,
    contract_shape,
    entry_requires_violations,
    extract_frame_clauses,
    find_named_clause,
    find_unsound_acsl_keywords,
    function_contract_text,
    is_trivial_predicate,
    iter_clauses,
    mask_comments_and_literals,
    tokenize_c_acsl,
    verify_acsl_only,
)

KERNEL_COMMENT_FIXTURES = ROOT / "tests" / "fixtures" / "acsl_kernel_comments"
RUN1_NEGOTIATE_PATCH = (
    ROOT / "tests" / "fixtures" / "libmodbus_run1_contracts" / "negotiate_modbus_tcp_build_request_basis_2.patch"
)
T_ID_SKELETON = {
    "status": "ok",
    "separated": [],
    "assigns": [
        {"loc": "ctx_tcp->t_id", "from": [], "clause": "assigns ctx_tcp->t_id \\from \\nothing;", "source": "ast"}
    ],
}
REAL_T_ID = "((modbus_tcp_t *)ctx->backend_data)->t_id"


def _clauses(text: str) -> list[tuple[str, str, str]]:
    return [(kind, label, " ".join(pred.split())) for kind, label, pred, _span in iter_clauses(text)]


def _run1_contract() -> str:
    """The annotation the run-1 negotiator added, as its patch has it."""
    added = [line[1:] for line in RUN1_NEGOTIATE_PATCH.read_text(encoding="utf-8").splitlines() if line[:1] == "+"]
    contract = "\n".join(line for line in added if not line.startswith("++"))
    assert contract.startswith("/*@") and contract.endswith("@*/")
    return contract


# ---------------------------------------------------------------------------
# The run-1 regression and its controls
# ---------------------------------------------------------------------------


def test_run1_location_in_a_comment_is_not_an_assigns_location() -> None:
    contract = _run1_contract()
    assert "->t_id // , ctx_tcp->t_id ," in contract
    t_id = [a for a in extract_frame_clauses(contract)["assigns"] if any("t_id" in loc for loc in a["locs"])]
    assert t_id == [{"locs": [REAL_T_ID], "from": ["\\nothing"], "from_nothing": True}]
    errors = check_frame_preserved(T_ID_SKELETON, contract, path="src/modbus-tcp.c")
    assert len(errors) == 1 and "ctx_tcp->t_id" in errors[0]


def test_run1_clause_without_its_annotation_delimiters() -> None:
    bare = f"assigns t_id_frame: {REAL_T_ID} // , ctx_tcp->t_id ,\n    \\from \\nothing;"
    assert extract_frame_clauses(bare)["assigns"] == [
        {"locs": [REAL_T_ID], "from": ["\\nothing"], "from_nothing": True}
    ]
    assert check_frame_preserved(T_ID_SKELETON, bare)


def test_the_same_location_written_for_real_is_found() -> None:
    real = f"/*@ assigns t_id_frame: {REAL_T_ID} , ctx_tcp->t_id\n  @     \\from \\nothing;\n  @*/"
    assert extract_frame_clauses(real)["assigns"] == [
        {"locs": [REAL_T_ID, "ctx_tcp->t_id"], "from": ["\\nothing"], "from_nothing": True}
    ]
    assert check_frame_preserved(T_ID_SKELETON, real) == []


def test_a_trailing_comment_after_a_complete_clause_changes_nothing() -> None:
    plain = "/*@ requires a > 0;\n    assigns *out \\from len;\n    ensures done: \\result == 0;\n*/"
    commented = (
        "/*@ requires a > 0; // the caller checks it\n"
        "    assigns *out \\from len; // frame\n"
        "    ensures done: \\result == 0; // , \\old(x)\n"
        "*/"
    )
    expected = [("requires", "", "a > 0"), ("assigns", "", "*out \\from len"), ("ensures", "done", "\\result == 0")]
    assert _clauses(plain) == expected
    assert _clauses(commented) == expected
    assert extract_frame_clauses(commented) == extract_frame_clauses(plain)


# ---------------------------------------------------------------------------
# A comment must not forge what a check requires
# ---------------------------------------------------------------------------


def test_a_separated_clause_in_a_comment_or_a_literal_is_not_a_separated_clause() -> None:
    skeleton = {
        "status": "ok",
        "separated": [{"roots": ["buf", "out"], "clause": "requires \\separated(buf + (0 .. len - 1), out);"}],
        "assigns": [],
    }
    in_comment = "/*@ requires \\valid(out); // requires \\separated(buf + (0 .. len - 1), out);\n*/"
    in_literal = '/*@ requires name != "\\separated(buf, out)";\n*/'
    for text in (in_comment, in_literal):
        assert extract_frame_clauses(text)["separated"] == []
        assert check_frame_preserved(skeleton, text)
    real = "/*@ requires \\valid(out); // why\n    requires \\separated(buf + (0 .. len - 1), out);\n*/"
    assert extract_frame_clauses(real)["separated"] == [["buf + (0 .. len - 1)", "out"]]
    assert check_frame_preserved(skeleton, real) == []


def test_a_nested_line_annotation_is_a_comment() -> None:
    # Probe cases B, D and M: the kernel drops `//@ ...` inside an annotation like any `//` comment.
    block = "/*@ assigns *p;\n  //@ assigns *q \\from \\nothing;\n*/"
    assert extract_frame_clauses(block)["assigns"] == [{"locs": ["*p"], "from": [], "from_nothing": False}]
    line = "//@ requires a > 0; //@ requires b > 0;"
    assert _clauses(line) == [("requires", "", "a > 0")]
    # Two line annotations are two annotations: the second is not nested in the first.
    assert _clauses("//@ requires a > 0;\n//@ requires b > 0;") == [
        ("requires", "", "a > 0"),
        ("requires", "", "b > 0"),
    ]
    source = "//@ ensures L5_out: \\result == 0;\nint f(void);\n"
    assert find_named_clause(source, "L5_out") == "\\result == 0"


def test_a_nested_annotation_in_ghost_code_stays_visible() -> None:
    # Probe p3a: ghost code is C, so the kernel reads `//@ assert` there and skips the plain comment.
    ghost = (KERNEL_COMMENT_FIXTURES / "p3a.c").read_text(encoding="utf-8")
    masked = mask_comments_and_literals(ghost, acsl="mask")
    assert len(masked) == len(ghost)
    assert "//@ assert nested_in_ghost: x == a;" in masked
    assert "plain comment" not in masked and "\\false" not in masked
    hidden = "void f(int a)\n{\n  /*@ ghost int x = a;\n      //@ admit x == 0;\n  */\n}\n"
    assert any("admit" in e for e in find_unsound_acsl_keywords(tokenize_c_acsl(hidden)))


def test_a_comment_does_not_make_a_trivial_postcondition_look_substantial() -> None:
    source = "/*@ ensures L5_sanitized: \\true // == \\old(x) + y\n    ;\n*/\nint f(int x);\n"
    predicate = find_named_clause(source, "L5_sanitized")
    assert predicate == "\\true"
    assert is_trivial_predicate(predicate)
    shaped = "/*@ assigns \\result;\n    ensures \\result >= 0 // == \\old(x) + y\n    ;\n*/"
    assert contract_shape(shaped) == SHAPE_SAFETY_ONLY
    assert contract_shape("/*@ assigns \\result;\n    ensures \\result == \\old(x) + y;\n*/") == "functional"


def test_a_comment_in_front_of_the_label_does_not_hide_the_named_clause() -> None:
    # Probe case L: the kernel prints `ensures lbl_real: \result == 0;`.
    source = "/*@ ensures // lbl_fake:\n      lbl_real: \\result == 0;\n*/\nint case_l(void);\n"
    assert find_named_clause(source, "lbl_real") == "\\result == 0"
    assert find_named_clause(source, "lbl_fake") is None


# ---------------------------------------------------------------------------
# A comment must not hide what a check forbids
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "annotation",
    [
        "/*@ requires \\false //@ x\n    ;\n*/",
        "/*@ requires \\false // x\n    ;\n*/",
        "/*@ requires @ \\false;\n*/",
        "/*@ requires \\false @;\n*/",
        "/*@ requires\n  @ ok: @ \\false;\n  @*/",
    ],
)
def test_a_vacuous_requires_is_seen_through_comments_and_at_signs(annotation: str) -> None:
    errors = find_unsound_acsl_keywords(tokenize_c_acsl(annotation + "\nvoid f(int a);\n"))
    assert any("vacuous" in e for e in errors), errors


def test_a_real_requires_beside_a_commented_false_is_not_vacuous() -> None:
    ok = "/*@ requires a > 0; // not \\false\n    requires b > 0; //@ requires \\false;\n*/\nvoid f(int a, int b);\n"
    assert find_unsound_acsl_keywords(tokenize_c_acsl(ok)) == []


def test_a_comment_does_not_hide_a_value_constraint_from_the_trust_boundary_check() -> None:
    hidden = "/*@ requires // \\valid(\n      len <= 64;\n*/"
    violations = entry_requires_violations(hidden, ["buf", "len"])
    assert len(violations) == 1 and "len" in violations[0]
    shape = "/*@ requires \\valid_read(buf + (0 .. len - 1)); // len <= 64\n*/"
    assert entry_requires_violations(shape, ["buf", "len"]) == []


# ---------------------------------------------------------------------------
# `@` is white space, literals are not comments
# ---------------------------------------------------------------------------


def test_an_at_sign_reads_as_white_space() -> None:
    # Probe case K (`assigns *p, *q;`) and p3b.
    assert extract_frame_clauses("/*@ assigns *p @ , *q;\n*/")["assigns"] == [
        {"locs": ["*p", "*q"], "from": [], "from_nothing": False}
    ]
    assert _clauses('/*@ ensures @ lbl: @ s != "a@b";\n*/') == [("ensures", "lbl", 's != "a@b"')]


def test_an_at_sign_does_not_hide_a_forbidden_construct() -> None:
    hidden_type = "/*@ logic @ int twice(integer x) = 2 * x; */\nint f(int a);\n"
    assert any("C integer type" in e for e in find_unsound_acsl_keywords(tokenize_c_acsl(hidden_type)))
    allowed = "/*@ logic @ integer twice(integer x) = 2 * x; */\nint f(int a);\n"
    assert find_unsound_acsl_keywords(tokenize_c_acsl(allowed)) == []
    hidden_loop = "void f(void)\n{\n  /*@ loop @ invariant \\false; */\n  while (1) {\n  }\n}\n"
    assert any("vacuous" in e for e in find_unsound_acsl_keywords(tokenize_c_acsl(hidden_loop)))
    real_loop = "void f(int n)\n{\n  /*@ loop @ invariant n >= 0; */\n  while (n > 0) {\n    n--;\n  }\n}\n"
    assert find_unsound_acsl_keywords(tokenize_c_acsl(real_loop)) == []


def test_slashes_in_a_literal_do_not_open_a_comment() -> None:
    # Probe p3f: the kernel types `"a // b"` as char[7], and reads `'/'` as a character.
    text = "/*@ requires s == \"a // b\" || len > 0;\n    requires c == '/' || len > 1; // requires len > 2;\n*/"
    assert _clauses(text) == [("requires", "", 's == "a // b" || len > 0'), ("requires", "", "c == '/' || len > 1")]
    body = _acsl_comment_body(text)
    assert '"a // b" || len > 0' in body and "len > 2" not in body


def test_comment_body_drops_nested_annotations_and_comments() -> None:
    body = _acsl_comment_body("/*@ assigns *p; // , *q\n  @ //@ assigns *r;\n  @*/")
    assert _clauses(body) == [("assigns", "", "*p")]
    assert _clauses(_acsl_comment_body("//@ assigns *p; // , *q")) == [("assigns", "", "*p")]


# ---------------------------------------------------------------------------
# A backslash at the end of a line
# ---------------------------------------------------------------------------

SPLICE_BASE = "int f(int a)\n{\n  a = 5;\n  return a;\n}\n"


def test_a_new_annotation_line_ending_in_a_backslash_is_refused() -> None:
    # Probe p3c: cpp joins the next line to the `//@` comment, and the statement `a = 5;` is gone.
    swallowed = "int f(int a)\n{\n  //@ assert a > 0; \\\n  a = 5;\n  return a;\n}\n"
    errors = verify_acsl_only(SPLICE_BASE, swallowed, path="f.c")
    assert any("backslash" in e for e in errors), errors
    # Probe p3d: the same in a `//` comment of a block annotation.
    block = "/*@ requires a > 0; // comment \\\n    requires b > 0;\n*/\n" + SPLICE_BASE
    assert any("backslash" in e for e in verify_acsl_only(SPLICE_BASE, block, path="f.c"))
    trailing_space = "int f(int a)\n{\n  //@ assert a > 0; \\ \n  a = 5;\n  return a;\n}\n"
    assert any("backslash" in e for e in verify_acsl_only(SPLICE_BASE, trailing_space, path="f.c"))


def test_ordinary_backslashes_and_baseline_annotations_are_accepted() -> None:
    work = "/*@ requires a > 0;\n    ensures \\result == \\old(a) || \\true;\n*/\n" + SPLICE_BASE
    assert verify_acsl_only(SPLICE_BASE, work, path="f.c") == []
    # An annotation the baseline already has is the target's, not the agent's.
    baseline = "int f(int a)\n{\n  //@ assert a > 0; \\\n  a = 5;\n  return a;\n}\n"
    assert verify_acsl_only(baseline, baseline, path="f.c") == []


# ---------------------------------------------------------------------------
# The parser against what the kernel printed
# ---------------------------------------------------------------------------


def _kernel_printed(log_name: str, section: str) -> str:
    """The code Frama-C printed (`-print`) in one `@@ <section>` part of a recorded log."""
    log = (KERNEL_COMMENT_FIXTURES / log_name).read_text(encoding="utf-8")
    part = log.split(f"@@ {section}\n", 1)[1].split("\n@@ ", 1)[0]
    return part.split("/* Generated by Frama-C */\n", 1)[1]


@pytest.mark.parametrize(
    ("source", "log", "section", "function"),
    [
        ("probe2.c", "probe2.log", "DEFAULT probe2.c", "case_b"),
        ("probe2.c", "probe2.log", "DEFAULT probe2.c", "case_c"),
        ("probe2.c", "probe2.log", "DEFAULT probe2.c", "case_d"),
        ("probe2.c", "probe2.log", "DEFAULT probe2.c", "case_i"),
        ("probe2.c", "probe2.log", "DEFAULT probe2.c", "case_k"),
        ("probe2.c", "probe2.log", "DEFAULT probe2.c", "case_l"),
        ("probe2.c", "probe2.log", "DEFAULT probe2.c", "case_m"),
        ("probe_n.c", "probe2.log", "DEFAULT probe_n.c", "case_n"),
        ("p3b.c", "probe3.log", "ACTIVE p3b.c", "at_sign"),
        ("p3f.c", "probe3.log", "ACTIVE p3f.c", "char_with_slash"),
    ],
)
def test_the_clauses_read_are_the_clauses_the_kernel_printed(
    source: str, log: str, section: str, function: str
) -> None:
    written = (KERNEL_COMMENT_FIXTURES / source).read_text(encoding="utf-8")
    printed = _kernel_printed(log, section)

    def squeezed(text: str) -> list[tuple[str, str, str]]:
        contract = function_contract_text(text, function, is_header=True)
        return [(kind, label, re.sub(r"\s+", "", pred)) for kind, label, pred, _span in iter_clauses(contract)]

    kernel = squeezed(printed)
    assert kernel, f"the kernel printed no contract for {function}"
    assert squeezed(written) == kernel


def test_the_run1_shape_against_the_kernel() -> None:
    # Probe case A: the kernel prints `assigns (a_frame: *p); assigns (a_frame: *p) \from \nothing;`.
    printed = _kernel_printed("probe2.log", "DEFAULT probe2.c")
    kernel_contract = function_contract_text(printed, "case_a", is_header=True)
    assert "*p" in kernel_contract and "q" not in kernel_contract
    written = (KERNEL_COMMENT_FIXTURES / "probe2.c").read_text(encoding="utf-8")
    ours = extract_frame_clauses(function_contract_text(written, "case_a", is_header=True))["assigns"]
    assert ours == [{"locs": ["*p"], "from": ["\\nothing"], "from_nothing": True}]


def test_the_recorded_kernel_refuses_the_forms_the_parser_does_not_model() -> None:
    first = (KERNEL_COMMENT_FIXTURES / "probe.log").read_text(encoding="utf-8")
    # Case E: a block comment inside a line annotation aborts the parse.
    assert "lexical error, unexpected block-comment opening" in first
    third = (KERNEL_COMMENT_FIXTURES / "probe3.log").read_text(encoding="utf-8")
    # p3c and p3d under the default warning keys: a line ending in a backslash is fatal.
    for name in ("p3c.c", "p3d.c"):
        part = third.split(f"@@ DEFAULTKEYS {name}\n", 1)[1].split("\n@@ ", 1)[0]
        assert "annot-error treated as fatal error" in part and part.rstrip().endswith("rc=1")
    # p3c with the key downgraded: the C statement after the annotation is gone from the printed code.
    active = third.split("@@ ACTIVE p3c.c\n", 1)[1].split("\n@@ ", 1)[0]
    assert re.search(r"\{\s*return a;\s*\}", active) and "a = 5" not in active
