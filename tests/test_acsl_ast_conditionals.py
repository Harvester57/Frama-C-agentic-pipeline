#!/usr/bin/env python3
"""
The source scanners of scripts/acsl_ast.py read one configuration of a file's preprocessor conditionals.

libmodbus opens the same block in both arms of a conditional and closes it once after `#endif`
(`modbus-tcp.c`, `_connect` and `_modbus_tcp_listen`; `modbus-rtu.c`, `_modbus_rtu_connect`). Counted across
both arms, the depth never returned to 0 and every later function of the file could not be located.
"""

from __future__ import annotations

import pytest

from acsl_ast import (
    _find_body_brace_offset,
    _find_matching_delim,
    contract_declaration_spans,
    extract_top_level_acsl_declarations,
    function_declaration_spans,
    locate_all_definition_spans,
    locate_all_prototype_spans,
    locate_function_span,
    splice_prover_changes,
    tokenize_c_acsl,
)

# modbus-tcp.c:379-388, `_connect`: the arms differ in length and both open the block.
LIBMODBUS_CONNECT = """\
static int _connect(int sockfd, const struct timeval *ro_tv)
{
    int rc = connect(sockfd, addr, addrlen);

#ifdef OS_WIN32
    int wsaError = 0;
    if (rc == -1) {
        wsaError = WSAGetLastError();
    }

    if (wsaError == WSAEWOULDBLOCK || wsaError == WSAEINPROGRESS) {
#else
    if (rc == -1 && errno == EINPROGRESS) {
#endif
        rc = select(sockfd + 1, NULL, &wset, NULL, &tv);
    }
    return rc;
}
"""

# modbus-rtu.c:761-765, `_modbus_rtu_connect`, inside the `#else` arm of a whole-function `#if defined(_WIN32)`.
LIBMODBUS_RTU_CONNECT = """\
static int _modbus_rtu_connect(modbus_t *ctx)
{
#if defined(_WIN32)
    ctx->s = 1;
#else
#ifdef HAVE_STRUCT_TERMIOS2
    if (ioctl(ctx->s, TCGETS2, &ctx_rtu->old_tios) < 0) {
#else
    if (tcgetattr(ctx->s, &ctx_rtu->old_tios) < 0) {
#endif
        close(ctx->s);
        return -1;
    }
#endif
    return 0;
}
"""

# modbus-rtu.c:329-369, `_modbus_rtu_send`: one block split over two conditionals on the same macro.
LIBMODBUS_RTU_SEND = """\
static ssize_t _modbus_rtu_send(modbus_t *ctx, const uint8_t *req, int req_length)
{
#if defined(_WIN32)
    return -1;
#else
#if HAVE_DECL_TIOCM_RTS
    if (ctx_rtu->rts != MODBUS_RTU_RTS_NONE) {
        return size;
    } else {
#endif
        return write(ctx->s, req, req_length);
#if HAVE_DECL_TIOCM_RTS
    }
#endif
#endif
}
"""

AFTER = """\
/*@ assigns \\nothing; */
int after(modbus_t *ctx)
{
    return ctx->s;
}

int last(void)
{
    return 2;
}
"""

ARMS = {
    "libmodbus_connect": LIBMODBUS_CONNECT,
    "libmodbus_rtu_connect": LIBMODBUS_RTU_CONNECT,
    "libmodbus_rtu_send": LIBMODBUS_RTU_SEND,
    "nested": (
        "int first(int a)\n{\n#ifdef A\n#ifdef B\n    if (a) {\n#else\n    if (a > 1) {\n#endif\n"
        "#else\n#ifdef C\n    while (a) {\n#else\n    for (;;) {\n#endif\n#endif\n        a--;\n    }\n    return a;\n}\n"
    ),
    "elif": (
        "int first(int a)\n{\n#if defined(A)\n    if (a == 1) {\n#elif defined(B)\n    if (a == 2) {\n"
        "#elif defined(C)\n    if (a == 3) {\n#else\n    if (a == 4) {\n#endif\n        a = 0;\n    }\n    return a;\n}\n"
    ),
    "if_without_else": "int first(int a)\n{\n#ifdef A\n    a++;\n#endif\n    return a;\n}\n",
    "same_macro_opens_and_closes": (
        "int first(int a)\n{\n#ifdef A\n    if (a) {\n#endif\n        a = 0;\n#ifdef A\n    }\n#endif\n    return a;\n}\n"
    ),
    "second_arm_opens_and_negation_closes": (
        "int first(int a)\n{\n#ifdef A\n    a = 1;\n#else\n    if (a) {\n#endif\n        a = 0;\n"
        "#ifndef A\n    }\n#endif\n    return a;\n}\n"
    ),
    "negation_spelled_with_defined": (
        "int first(int a)\n{\n#if defined(A)\n    a = 1;\n#else\n    if (a) {\n#endif\n        a = 0;\n"
        "#if !defined A\n    }\n#endif\n    return a;\n}\n"
    ),
    "disabled_first_arm": (
        "int first(int a)\n{\n#if 0\n    if (a) {\n#else\n    while (a) {\n        a--;\n#endif\n    }\n    return a;\n}\n"
    ),
    "both_arms_close_the_block": (
        "int first(int a)\n{\n    if (a) {\n#ifdef A\n        a = 1;\n    }\n#else\n        a = 2;\n    }\n#endif\n"
        "    return a;\n}\n"
    ),
    "parens_split_across_arms": (
        "int first(int a)\n{\n#ifdef A\n    a = call(a,\n#else\n    a = other(a, a,\n#endif\n             a);\n    return a;\n}\n"
    ),
    "ordinary_balanced_arms": (
        "int first(int a)\n{\n#ifdef A\n    if (a) { a = 1; }\n#else\n    if (a) { a = 2; }\n#endif\n    return a;\n}\n"
    ),
    "unrelated_conditions_fall_back_to_counting": (
        "int first(int a)\n{\n#ifdef A\n    a = 1;\n#else\n    if (a) {\n#endif\n        a = 0;\n"
        "#if defined(B) || defined(C)\n    }\n#endif\n    return a;\n}\n"
    ),
}


@pytest.mark.parametrize("name", sorted(ARMS))
def test_every_function_after_the_conditional_is_located(name: str) -> None:
    source = ARMS[name] + AFTER
    defined = locate_all_definition_spans(source)
    assert {"after", "last"} <= set(defined)
    for function in ("after", "last"):
        span = locate_function_span(source, function)
        assert span is not None and span.text == defined[function].text
        decls = contract_declaration_spans(source, function)
        assert [d.span.text for d in decls] == [span.text]
    assert defined["after"].text.startswith("/*@ assigns \\nothing; */\nint after(")


@pytest.mark.parametrize("name", sorted(ARMS))
def test_the_span_of_the_function_with_the_conditional_covers_both_arms(name: str) -> None:
    source = ARMS[name] + AFTER
    function = source[: source.index("(")].split()[-1]
    span = locate_function_span(source, function)
    assert span is not None
    assert span.text == ARMS[name].rstrip("\n")
    assert locate_all_definition_spans(source)[function].text == span.text
    assert [d.kind for d in function_declaration_spans(source, function)] == ["definition"]


def _open_index(tokens: list, text: str, nth: int = 0) -> int:
    return [i for i, t in enumerate(tokens) if t.kind == "c_token" and t.text == text][nth]


def test_find_matching_delim_matches_the_body_past_two_opening_arms() -> None:
    tokens = tokenize_c_acsl(LIBMODBUS_CONNECT)
    body = _open_index(tokens, "{")
    close = _find_matching_delim(tokens, body, "{", "}")
    assert tokens[close].end == LIBMODBUS_CONNECT.rindex("}") + 1


def test_find_matching_delim_matches_a_block_opened_in_the_second_arm() -> None:
    tokens = tokenize_c_acsl(LIBMODBUS_RTU_CONNECT)
    second_arm = _open_index(tokens, "{", 2)
    assert tokens[second_arm].line == 9
    close = _find_matching_delim(tokens, second_arm, "{", "}")
    assert tokens[close].line == 13


def test_find_matching_delim_matches_parens_split_across_arms() -> None:
    source = ARMS["parens_split_across_arms"]
    tokens = tokenize_c_acsl(source)
    first_call = next(i for i, t in enumerate(tokens) if t.text == "call") + 1
    close = _find_matching_delim(tokens, first_call, "(", ")")
    assert tokens[close].line == source[: source.index("a);")].count("\n") + 1


def test_find_matching_delim_on_ordinary_code_is_unchanged() -> None:
    source = "int f(int a) { if (a) { a = (a + 1); } return a; }\n"
    tokens = tokenize_c_acsl(source)
    assert tokens[_find_matching_delim(tokens, _open_index(tokens, "{"), "{", "}")].end == len(source) - 1
    unclosed = tokenize_c_acsl("int f(void) {")
    assert _find_matching_delim(unclosed, _open_index(unclosed, "{"), "{", "}") == -1


def test_parameters_split_across_arms_keep_the_definition_visible() -> None:
    source = "int f(int a,\n#ifdef A\n      int b)\n#else\n      long b)\n#endif\n{\n    return a;\n}\n" + AFTER
    assert source.startswith(locate_all_definition_spans(source)["f"].text)
    span = locate_function_span(source, "f")
    assert span is not None and span.text.endswith("return a;\n}")
    assert span.text[_find_body_brace_offset(span.text) :].startswith("{\n    return a;")
    assert {"after", "last"} <= set(locate_all_definition_spans(source))


def test_a_definition_header_duplicated_in_both_arms_shares_one_body() -> None:
    source = "#ifdef A\nint f(int a) {\n#else\nint f(long a) {\n#endif\n    return 0;\n}\n" + AFTER
    span = locate_function_span(source, "f")
    assert span is not None and span.text.endswith("return 0;\n}")
    assert {"f", "after", "last"} <= set(locate_all_definition_spans(source))


def test_a_function_defined_only_in_an_else_arm_stays_locatable() -> None:
    source = "#ifdef A\nint win(void) { return 1; }\n#else\nint posix(void) { return 2; }\n#endif\n" + AFTER
    assert {"win", "posix", "after", "last"} <= set(locate_all_definition_spans(source))
    span = locate_function_span(source, "posix")
    assert span is not None and span.text == "int posix(void) { return 2; }"
    assert [d.kind for d in contract_declaration_spans(source, "posix")] == ["definition"]


def test_the_same_function_defined_in_both_arms_keeps_the_first_definition() -> None:
    source = "#ifdef A\nint f(void) { return 1; }\n#else\nint f(void) { return 2; }\n#endif\n"
    assert locate_all_definition_spans(source)["f"].text == "int f(void) { return 1; }"
    assert [d.span.text for d in contract_declaration_spans(source, "f")] == [
        "int f(void) { return 1; }",
        "int f(void) { return 2; }",
    ]
    assert len(function_declaration_spans(source, "f")) == 2


def test_a_linkage_block_opened_under_cplusplus_still_shows_its_prototypes() -> None:
    source = (
        '#ifdef __cplusplus\nextern "C" {\n#endif\nint api(int a);\n#ifdef __cplusplus\n}\n#endif\nint more(void);\n'
    )
    assert [s.function for s in locate_all_prototype_spans(source)] == ["api", "more"]


def test_prototypes_after_the_conditional_are_located() -> None:
    source = LIBMODBUS_CONNECT + "int proto(int a);\n"
    assert [s.function for s in locate_all_prototype_spans(source)] == ["proto"]


def test_top_level_acsl_after_the_conditional_is_extracted() -> None:
    source = LIBMODBUS_CONNECT + "/*@ predicate p(integer x) = x > 0; */\n"
    assert [d["name"] for d in extract_top_level_acsl_declarations(source)] == ["p"]


def test_conditional_directives_with_comments_and_continuations_are_read() -> None:
    source = (
        "int first(int a)\n{\n#ifdef A /* the first spelling */\n    a = 1;\n#else // other\n    if (a) {\n#endif\n"
        "        a = 0;\n#if !defined( A ) \\\n    /* negated */\n    }\n#endif\n    return a;\n}\n" + AFTER
    )
    assert {"first", "after", "last"} <= set(locate_all_definition_spans(source))


def test_a_stray_else_or_endif_in_a_fragment_is_not_an_error() -> None:
    fragment = "    a = 1;\n#else\n    a = 2;\n#endif\n}\nint g(void) { return 0; }\n"
    assert "g" in locate_all_definition_spans(fragment)


def _proved(text: str, function: str, clause: str) -> str:
    """`text` with `clause` added in front of `function`'s definition, as a prover's edit does."""
    span = locate_function_span(text, function)
    assert span is not None
    return text[: span.start_byte] + f"/*@ {clause} */\n" + text[span.start_byte :]


def test_splice_of_a_function_after_the_conditional_end_to_end() -> None:
    base = LIBMODBUS_CONNECT + AFTER
    agent = _proved(base, "last", "ensures \\result == 2;")
    current = _proved(base, "after", "requires \\valid_read(ctx);")
    spliced = splice_prover_changes(base, agent, current, "last", path="src/modbus-tcp.c")
    assert "/*@ ensures \\result == 2; */\nint last(void)" in spliced
    assert "/*@ requires \\valid_read(ctx); */" in spliced
    assert spliced.count("#ifdef OS_WIN32") == 1


@pytest.mark.parametrize("contract_only", [False, True])
def test_splice_of_the_function_holding_the_conditional_keeps_both_arms(contract_only: bool) -> None:
    base = LIBMODBUS_CONNECT + AFTER
    agent = _proved(base, "_connect", "requires sockfd >= 0;")
    spliced = splice_prover_changes(base, agent, base, "_connect", path="src/modbus-tcp.c", contract_only=contract_only)
    assert spliced == agent


def test_splice_still_refuses_a_function_that_diverged_from_the_base() -> None:
    base = LIBMODBUS_CONNECT + AFTER
    agent = _proved(base, "last", "ensures \\result == 2;")
    current = _proved(base, "last", "ensures \\result >= 0;")
    with pytest.raises(Exception, match="diverged from agent base snapshot"):
        splice_prover_changes(base, agent, current, "last", path="src/modbus-tcp.c")
