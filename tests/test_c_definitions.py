"""Tests for scripts/c_definitions.py: function definitions and #define macros found with the tokenizer."""

from __future__ import annotations

from c_definitions import extract_functions_from_code, extract_macro_definitions


class TestTokenFunctionExtraction:
    """Tests for token-based C function definition extraction."""

    def test_extracts_multiline_attributes_and_function_pointer_params(self) -> None:
        src = """\
#include <stddef.h>
#include <stdint.h>

/* Forward declaration must not be treated as a definition */
int proto_only(const uint8_t *buf, size_t len);

__attribute__((warn_unused_result))
static inline const uint8_t *
step_cursor(
    const uint8_t * restrict cursor,
    size_t remaining,
    int (*on_byte)(uint8_t b, void *ctx),
    void *ctx
) {
    if (cursor == NULL || remaining == 0) {
        return NULL;
    }
    if (on_byte != NULL) {
        int rc = on_byte(cursor[0], ctx);
        if (rc < 0) {
            return NULL;
        }
    }
    return cursor + 1;
}

/* Function returning a function pointer */
int (*select_op(int mode))(int, int) {
    (void)mode;
    return 0;
}
"""
        fns = extract_functions_from_code(src)
        names = [f["name"] for f in fns]
        assert names == ["step_cursor", "select_op"]

        assert "on_byte" in [t.text for t in fns[0]["param_tokens"]]
        assert fns[0]["line"] < fns[0]["end_line"]

    def test_macro_call_with_brace_argument_does_not_hide_later_functions(self):
        # x509-parser: DECL_HASH_ALG(md2, "MD2", P99_PROTECT({ 0x06, 0x08 }));
        src = """
int before(void) { return 0; }
DECLARE_TABLE(md2, "MD2", PROTECT({ 0x06, 0x08 }));
int after(int x) { return x; }
static int last(void) { return 1; }
"""
        assert [f["name"] for f in extract_functions_from_code(src)] == ["before", "after", "last"]

    def test_statement_expression_argument_does_not_hide_later_functions(self):
        src = """
int value = WRAP(({ int y = 1; y; }));
int after(void) { return value; }
"""
        assert [f["name"] for f in extract_functions_from_code(src)] == ["after"]

    def test_extern_c_block_still_exposes_its_functions_and_later_ones(self):
        src = """
extern "C" {
int inner(void) { return 0; }
}
int outer(void) { return 1; }
"""
        assert [f["name"] for f in extract_functions_from_code(src)] == ["inner", "outer"]


class TestMacroDefinitions:
    def test_macro_callees_and_loops(self) -> None:
        src = """#define ADVANCE_TOKEN(tok, toklen) do { \
    while (1) { \
        tok = findchar_fast(tok, buf_end, ranges, sizeof(ranges) - 1, &found); \
        if (found) break; \
    } \
} while (0)
#define ADVANCE_TWICE(t, l) ADVANCE_TOKEN(t, l); ADVANCE_TOKEN(t, l)
"""
        macros = extract_macro_definitions(src)
        assert "findchar_fast" in macros["ADVANCE_TOKEN"]["callees"]
        assert macros["ADVANCE_TOKEN"]["loop_count"] == 1
        assert macros["ADVANCE_TOKEN"]["params"] == ["tok", "toklen"]
        # Through another macro, transitively.
        assert "findchar_fast" in macros["ADVANCE_TWICE"]["callees"]
        assert macros["ADVANCE_TWICE"]["loop_count"] == 1


class TestParenthesizedDeclarators:
    """Regression tests for PB-1: function-pointer-returning / parenthesized declarators."""

    def test_all_declarator_shapes_resolve_the_real_name(self) -> None:
        cases = {
            "int foo(int a) { return a; }": "foo",
            "void *bar(size_t n) { return 0; }": "bar",
            "void *(baz)(size_t c, void **a) { return 0; }": "baz",
            "int (*qux(int a))(char) { return 0; }": "qux",
            "void (*(quux)(size_t c, void **a)) { return; }": "quux",
            "int (corge)(int x) { return x; }": "corge",
            "static void (*(alloc)(size_t count, void **abstract)) { return; }": "alloc",
        }
        for src, expected in cases.items():
            names = [f["name"] for f in extract_functions_from_code(src, path="<t>")]
            assert names == [expected], f"{src!r} -> {names}"

    def test_type_keywords_are_never_function_names(self) -> None:
        src = "static void (*(ssh2_default_alloc)(size_t count, void **abstract)) { return; }\n"
        names = [f["name"] for f in extract_functions_from_code(src, path="<t>")]
        assert names == ["ssh2_default_alloc"]
        assert "void" not in names
