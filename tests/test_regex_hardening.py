"""Regexes that read a miss as "nothing wrong": each case here once passed a check it should have failed."""

from __future__ import annotations

import pytest

import acsl_ast
import build_capture
import cache
import eva_tuning
import harness_reach
import run_eacsl_fuzz
import stub_check
import trust

pytestmark = pytest.mark.unit


def _unsound(annotation: str) -> list[str]:
    tokens = acsl_ast.tokenize_c_acsl(annotation + "\nint f(char c, char d, int x, int n);\n")
    return acsl_ast.find_unsound_acsl_keywords(tokens)


# ---------------------------------------------------------------------------
# acsl_ast: unsound-construct scan
# ---------------------------------------------------------------------------


def test_a_quote_character_literal_does_not_hide_the_annotation_text_after_it():
    errors = _unsound("/*@ requires c != '\"'; admit requires \\false; ensures d != '\"'; */")
    assert any("'admit'" in e for e in errors)
    assert any("vacuous" in e for e in errors)


def test_a_string_literal_still_hides_its_own_content():
    assert _unsound('/*@ requires \\valid_read("admit axiom"); */') == []


@pytest.mark.parametrize(
    "clause",
    [
        "requires \\false;",
        "requires 0;",
        "requires lbl: \\false;",
        "requires (\\false);",
        "requires 1 == 0;",
        "requires 0x0;",
        "requires \\false && x > 0;",
        "requires x > 0 && (\\false);",
        "requires x != x;",
        "requires !\\true;",
        "assumes (0);",
        "loop invariant \\false || 2 < 1;",
    ],
)
def test_a_clause_that_is_false_by_its_form_is_vacuous(clause):
    errors = _unsound(f"/*@ {clause} */")
    assert len([e for e in errors if "vacuous" in e]) == 1, errors


@pytest.mark.parametrize(
    "clause",
    [
        "requires x != n;",
        "requires n > 0;",
        "requires \\false || x > 0;",
        "requires \\forall integer i; 0 <= i < n ==> i != n;",
        "requires x == 0;",
        "assumes n == 0;",
        "ensures \\false;",
        "requires 0 <= x < n;",
    ],
)
def test_a_satisfiable_clause_is_not_vacuous(clause):
    assert [e for e in _unsound(f"/*@ {clause} */") if "vacuous" in e] == []


def test_trivially_false_predicate_is_conservative():
    assert acsl_ast.is_trivially_false_predicate("(1 == 0)")
    assert acsl_ast.is_trivially_false_predicate("\\true ==> \\false")
    assert not acsl_ast.is_trivially_false_predicate("p(x)")
    assert not acsl_ast.is_trivially_false_predicate("x != y")
    assert not acsl_ast.is_trivially_false_predicate("!p(x)")


# ---------------------------------------------------------------------------
# stub_check: Eva precondition warnings
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "location, function",
    [
        ("fc_stub_smoke.c:12", "function memcpy"),
        ("fc_stub_smoke.c:12:3", "function memcpy"),
        ("fc_stub_smoke.c:12", "function memcpy, behavior copy"),
    ],
)
def test_the_eva_warning_keeps_its_file_and_line(location, function):
    log = f"[eva:alarm] {location}: Warning: \n  {function}: precondition 'valid_dest' got status unknown.\n"
    m = stub_check._WARNING_RE.search(log)
    assert m is not None
    assert (m.group("file"), m.group("line"), m.group("fn")) == ("fc_stub_smoke.c", "12", "memcpy")
    assert m.group("status") == "unknown"


# ---------------------------------------------------------------------------
# eva_tuning: coverage gate
# ---------------------------------------------------------------------------

_EVA_SUMMARY = """\
[eva:final-states] Values at end of function entry:
  x ∈ {0}
[eva:summary] ====== ANALYSIS SUMMARY ======
  2 functions analyzed (out of 40): 5% coverage.
  In these functions, 20 statements reached (out of 500): 4% coverage.
"""


def test_low_coverage_is_seen_without_the_coverage_estimation_line():
    out = eva_tuning.parse_eva_reachability(_EVA_SUMMARY, "entry", "eva_main")
    assert out["entry_reached"] is True
    assert out["reachability"] == "low_coverage"
    assert "coverage_estimate_pct" not in out["eva_coverage"]


def test_the_coverage_estimation_line_still_decides_when_present():
    out = eva_tuning.parse_eva_reachability(_EVA_SUMMARY + "Coverage estimation = 91.0%\n", "entry", "eva_main")
    assert out["reachability"] == "ok"


# ---------------------------------------------------------------------------
# run_eacsl_fuzz: crash outside the checked functions
# ---------------------------------------------------------------------------


def _segv(frame0: str) -> str:
    return (
        "==7==ERROR: UndefinedBehaviorSanitizer: SEGV on unknown address 0x10 (pc 0x5f T7)\n"
        f"    #0 0x5fd4a2ce31af in {frame0}\n"
        "    #1 0x5fd4a2ce3c04 in dispatch /w/src/nlmsg.c:40:3\n"
        "    #2 0x5fd4a2ce9a55 in LLVMFuzzerTestOneInput /w/harness.c:12:3\n"
        "SUMMARY: UndefinedBehaviorSanitizer: SEGV in parse_attr\n"
    )


@pytest.mark.parametrize(
    "frame0",
    [
        "parse_attr /w/src/attr_tables.inc:41:9",
        "parse_attr /w/src/gram.y:812",
        "parse_attr (/w/guard.bin+0x4f1)",
        "parse_attr /w/my src/attr.c:41:9",
    ],
)
def test_a_checked_function_frame_is_seen_whatever_its_file(frame0):
    assert run_eacsl_fuzz.crash_outside_checked_functions(_segv(frame0), ["parse_attr"]) is None


def test_a_crash_in_other_code_is_still_excused():
    why = run_eacsl_fuzz.crash_outside_checked_functions(_segv("parse_attr /w/src/gram.y:812"), ["other_fn"])
    assert why is not None and "SEGV" in why


# ---------------------------------------------------------------------------
# harness_reach: what a harness names is not what it calls
# ---------------------------------------------------------------------------

_FNS = {"stat", "hash", "rec_parse", "rec_put", "rec_print", "on_msg", "rec_next"}


def _roots(body: str, macros: dict[str, set[str]] | None = None) -> set[str]:
    return harness_reach.harness_roots(body, _FNS, macros or {})


def test_only_used_functions_are_roots():
    text = """\
#include "api.h"
int rec_put(unsigned char *buf, unsigned long n, unsigned short type);
#if 0
static void unused(void) { rec_print(0, 0); }
#endif
int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {
    struct stat st;
    int hash = 0;
    char *stat_name = "rec_next failed\\n";
    /* rec_next(r) */
    if (size > 4) return rec_parse(data, size);
    return hash + st.hash;
}
"""
    assert _roots(text) == {"rec_parse"}


def test_a_function_used_as_a_value_is_a_root():
    text = """\
static cb_t table_cb = on_msg;
int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {
    cb_t cb = rec_print;
    register_cb(rec_put);
    (void)rec_parse(data, size);
    return 0;
}
"""
    assert _roots(text) == {"on_msg", "rec_print", "rec_put", "rec_parse"}


def test_macro_uses_and_local_macro_bodies_are_roots():
    text = """\
#define CALL(b, n) rec_parse(b, n)
int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {
    rec_for_each(r, data, size) { }
    return CALL(data, size);
}
"""
    assert _roots(text, {"rec_for_each": {"rec_next"}}) == {"rec_parse", "rec_next"}


def test_text_the_tokenizer_cannot_read_falls_back_to_every_identifier():
    assert _roots("int f(void) { return rec_parse(0, 0); /* unclosed") == {"rec_parse"}


# ---------------------------------------------------------------------------
# build_capture: test units
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name, files",
    [
        ("plugins/check_http", ["plugins/check_http.c"]),
        ("bin/health-check", ["src/health.c"]),
        ("lib/libspell-check.so.1", ["src/spell.c"]),
        ("libbounds.a", ["src/bounds_check.c", "src/sanity_check.c"]),
    ],
)
def test_check_in_a_name_does_not_make_a_test_unit(name, files):
    assert build_capture.test_reason(name, files) is None


@pytest.mark.parametrize(
    "name, files, reason",
    [
        ("test_parse", ["src/t.c"], "name"),
        ("check/runner", ["check/runner.c"], "directory"),
        ("runner", ["tests/check_money.c"], "test_sources"),
    ],
)
def test_test_units_are_still_marked(name, files, reason):
    assert build_capture.test_reason(name, files) == reason


# ---------------------------------------------------------------------------
# trust: the threat-model block
# ---------------------------------------------------------------------------

_BLOCK = '{"version": 1}'


@pytest.mark.parametrize(
    "text",
    [
        f"```framac-threat-model\n{_BLOCK}\n```\n",
        f"  ```framac-threat-model\n  {_BLOCK}\n  ```\n",
        f"```json framac-threat-model\n{_BLOCK}\n`````\n",
        f"~~~ {{framac-threat-model}}\r\n{_BLOCK}\r\n~~~\r\n",
    ],
)
def test_the_threat_model_block_is_read(text):
    assert trust.extract_block(text) == ({"version": 1}, [])


def test_a_block_that_cannot_be_read_is_an_error_not_an_absent_block():
    block, errors = trust.extract_block(f"1. Model:\n\n    - ```framac-threat-model\n      {_BLOCK}\n      ```\n")
    assert block is None and len(errors) == 1 and "framac-threat-model" in errors[0]


def test_prose_that_names_the_block_is_not_an_error():
    assert trust.extract_block("Add a `framac-threat-model` block to this file.\n") == (None, [])


# ---------------------------------------------------------------------------
# cache: annotations that apply beyond one function
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "annotation, is_global",
    [
        ("/*@ global invariant inv: x >= 0; */", True),
        ("/*@ strong global invariant inv: x >= 0; */", True),
        ("//@ volatile x reads rd writes wr;", True),
        ("/*@ predicate p(int x) = x > 0; */", True),
        ("/*@ requires n > 0; assigns \\nothing; */", False),
        ("/*@ loop invariant 0 <= i <= n; */", False),
    ],
)
def test_global_annotations_stay_in_the_digest(annotation, is_global):
    assert bool(cache._GLOBAL_ACSL_DECL_RE.search(annotation)) is is_global


# ---------------------------------------------------------------------------
# M4: D7, B5, B7
# ---------------------------------------------------------------------------


def test_d7_multi_dim_and_array_pointer_param_declarations():
    import generate_harness as gh

    # Multi-dimensional array parameter
    p_matrix = gh._parse_c_param("int matrix[3][4]", 0)
    assert p_matrix["name"] == "matrix"
    assert p_matrix["is_pointer"] is True
    assert "(*)[4]" in p_matrix["type"] or "[3][4]" in p_matrix["type"]

    # Array pointer parameter
    p_arr_ptr = gh._parse_c_param("int (*ptr)[10]", 0)
    assert p_arr_ptr["name"] == "ptr"
    assert p_arr_ptr["is_pointer"] is True
    assert "(*)[10]" in p_arr_ptr["type"]

    # Declaration formatting helper
    assert gh._format_c_decl("int [4]", "arg_0") == "int arg_0[4];"
    assert gh._format_c_decl("int", "x") == "int x;"


def test_b5_extract_function_prototype_uses_phase0_model():
    import generate_harness as gh

    model = {
        "functions": {
            "src/test.c#compute": {
                "name": "compute",
                "signature": "int compute(int x, char *buf)",
                "formals": ["x", "buf"],
            }
        }
    }
    params = gh.extract_function_prototype("compute", model=model)
    assert len(params) == 2
    assert params[0]["name"] == "x"
    assert params[1]["name"] == "buf"


def test_b7_source_defines_main_uses_symbols_and_masks_literals(tmp_path):
    import pipeline_make as pm

    src = tmp_path / "app.c"
    src.write_text('const char *str = "void main(int x, char *y[]) {";\n', encoding="utf-8")

    # Without defined_functions symbol, string literal should NOT be treated as main() definition
    assert pm._source_defines_main(src) is False

    # With capture defined_functions symbol
    capture = {
        "compiles": [
            {
                "file": "app.c",
                "defined_functions": ["app.c#main"],
            }
        ]
    }
    assert pm._source_defines_main(src, capture=capture) is True

