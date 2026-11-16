#!/usr/bin/env python3
"""
Unit tests for scripts/acsl_ast.py:
- Canonical ACSL declaration extraction with parameter types and full profiles
- Comment-only and whitespace-only ACSL annotation block detection and stripping
- Conflicting predicate profile detection across declarations
- Preserving valid overloads while deduplicating identical profiles
"""

from __future__ import annotations

import pytest

from acsl_ast import (
    ScopeViolationError,
    _extract_decl_param_types,
    _is_acsl_comment_or_whitespace_only,
    added_top_level_acsl_declarations,
    check_conflicting_acsl_profiles,
    contract_shape,
    dedup_acsl_declarations,
    extract_top_level_acsl_declarations,
    function_returns_void,
    splice_prover_changes,
    verify_acsl_only,
)


class TestAcslAstProfileAndStripping:
    def test_extract_top_level_declarations_parameter_types_and_profile(self) -> None:
        source = """
        /*@
          logic integer c_strlen(char *s) =
            (s[0] == '\\0') ? 0 : 1 + c_strlen(s + 1);

          predicate valid_c_string(char *s) =
            s != \\null && 0 <= c_strlen(s) && \\valid_read(s + (0 .. c_strlen(s)));

          predicate valid_read_buffer(char *buf, integer len) =
            len >= 0 && (len == 0 || (buf != \\null && \\valid_read(buf + (0 .. len - 1))));

          predicate valid_read_buffer(unsigned char *buf, integer len) =
            len >= 0 && (len == 0 || (buf != \\null && \\valid_read(buf + (0 .. len - 1))));

          predicate is_printable_ascii(char c) =
            (0x20 <= c <= 0x7E);

          predicate buffer_is_zeroed(unsigned char *buf, integer len) =
            \\forall integer k; 0 <= k < len ==> buf[k] == 0;
        */
        """
        decls = extract_top_level_acsl_declarations(source, path="test.h")
        by_name = {d["name"]: d for d in decls if d["name"] != "valid_read_buffer"}
        read_bufs = [d for d in decls if d["name"] == "valid_read_buffer"]

        assert by_name["c_strlen"]["kind"] == "logic"
        assert by_name["c_strlen"]["param_types"] == ("char *",)
        assert by_name["c_strlen"]["full_profile"] == "c_strlen(char *)"

        assert by_name["valid_c_string"]["kind"] == "predicate"
        assert by_name["valid_c_string"]["param_types"] == ("char *",)
        assert by_name["valid_c_string"]["full_profile"] == "valid_c_string(char *)"

        assert by_name["is_printable_ascii"]["param_types"] == ("char",)
        assert by_name["is_printable_ascii"]["full_profile"] == "is_printable_ascii(char)"

        assert by_name["buffer_is_zeroed"]["param_types"] == ("unsigned char *", "integer")
        assert by_name["buffer_is_zeroed"]["full_profile"] == "buffer_is_zeroed(unsigned char *, integer)"

        assert len(read_bufs) == 2
        assert read_bufs[0]["param_types"] == ("char *", "integer")
        assert read_bufs[1]["param_types"] == ("unsigned char *", "integer")

    def test_is_acsl_comment_or_whitespace_only(self) -> None:
        assert _is_acsl_comment_or_whitespace_only("")
        assert _is_acsl_comment_or_whitespace_only("   \t  \n  ")
        assert _is_acsl_comment_or_whitespace_only("// just a comment\n")
        assert _is_acsl_comment_or_whitespace_only("\n * // multi line comment\n * \n")
        assert _is_acsl_comment_or_whitespace_only("/* nested C comment */")

        assert not _is_acsl_comment_or_whitespace_only("predicate foo() = \\true;")
        assert not _is_acsl_comment_or_whitespace_only("requires \\valid(p);")
        assert not _is_acsl_comment_or_whitespace_only("assigns \\nothing;")

    def test_dedup_strips_comment_and_whitespace_only_blocks(self) -> None:
        # 1. Block originally containing only comments
        src_comment_only = """
#ifndef TEST_H
#define TEST_H

/*@
  // Layer 5 & 6 shared logic predicates: do not split on keywords in comments!
  // Another informative comment line
*/

int some_fn(void);

#endif
"""
        deduped, removed = dedup_acsl_declarations(src_comment_only, existing_names=set())
        assert removed == []
        assert "/*@" not in deduped
        assert "some_fn(void)" in deduped

        # 2. Block becoming empty after deduplication
        src_with_decl = """
#ifndef TEST_H
#define TEST_H

/*@
  // Header description comment
  predicate buffer_is_zeroed(unsigned char *buf, integer len) =
    \\forall integer k; 0 <= k < len ==> buf[k] == 0;
*/

int some_fn(void);

#endif
"""
        deduped, removed = dedup_acsl_declarations(
            src_with_decl,
            existing_names={"buffer_is_zeroed/2"},
        )
        assert removed == ["buffer_is_zeroed"]
        assert "/*@" not in deduped
        assert "some_fn(void)" in deduped

        # 3. Block containing another declaration retains comments and remaining decl
        src_multi_decl = """
#ifndef TEST_H
#define TEST_H

/*@
  predicate buffer_is_zeroed(unsigned char *buf, integer len) =
    \\forall integer k; 0 <= k < len ==> buf[k] == 0;

  // Header description comment
  predicate custom_predicate(int x) =
    x > 0;
*/

int some_fn(void);

#endif
"""
        deduped, removed = dedup_acsl_declarations(
            src_multi_decl,
            existing_names={"buffer_is_zeroed/2"},
        )
        assert removed == ["buffer_is_zeroed"]
        assert "/*@" in deduped
        assert "Header description comment" in deduped
        assert "custom_predicate" in deduped
        assert "buffer_is_zeroed" not in deduped

    def test_check_conflicting_acsl_profiles(self) -> None:
        existing = [
            {
                "kind": "predicate",
                "name": "buffer_is_zeroed",
                "arity": 2,
                "param_types": ("unsigned char *", "integer"),
                "full_profile": "buffer_is_zeroed(unsigned char *, integer)",
                "path": "acsl_vocabulary.h",
                "line": 30,
            },
            {
                "kind": "predicate",
                "name": "valid_read_buffer",
                "arity": 2,
                "param_types": ("char *", "integer"),
                "full_profile": "valid_read_buffer(char *, integer)",
                "path": "acsl_vocabulary.h",
                "line": 15,
            },
            {
                "kind": "predicate",
                "name": "valid_read_buffer",
                "arity": 2,
                "param_types": ("unsigned char *", "integer"),
                "full_profile": "valid_read_buffer(unsigned char *, integer)",
                "path": "acsl_vocabulary.h",
                "line": 18,
            },
        ]

        # Case 1: Conflicting parameter type (char* vs unsigned char*)
        conflicting_new = [
            {
                "kind": "predicate",
                "name": "buffer_is_zeroed",
                "arity": 2,
                "param_types": ("char *", "integer"),
                "full_profile": "buffer_is_zeroed(char *, integer)",
                "line": 12,
            }
        ]
        conflicts = check_conflicting_acsl_profiles(conflicting_new, existing, source_path="bad_header.h")
        assert len(conflicts) == 1
        assert "Conflicting profile for predicate 'buffer_is_zeroed'" in conflicts[0]
        assert "buffer_is_zeroed(char *, integer)" in conflicts[0]
        assert "buffer_is_zeroed(unsigned char *, integer)" in conflicts[0]
        assert "acsl_vocabulary.h:30" in conflicts[0]
        assert "bad_header.h:12" in conflicts[0]

        # Case 2: Matching overload (char* matches one of valid_read_buffer overloads)
        matching_new = [
            {
                "kind": "predicate",
                "name": "valid_read_buffer",
                "arity": 2,
                "param_types": ("char *", "integer"),
                "full_profile": "valid_read_buffer(char *, integer)",
                "line": 20,
            }
        ]
        assert check_conflicting_acsl_profiles(matching_new, existing, source_path="good_header.h") == []

        # Case 3: Conflicting declarations within the new file itself
        internal_conflict = [
            {
                "kind": "predicate",
                "name": "check_magic",
                "arity": 1,
                "param_types": ("char *",),
                "full_profile": "check_magic(char *)",
                "line": 5,
            },
            {
                "kind": "predicate",
                "name": "check_magic",
                "arity": 1,
                "param_types": ("unsigned char *",),
                "full_profile": "check_magic(unsigned char *)",
                "line": 9,
            },
        ]
        internal_errs = check_conflicting_acsl_profiles(internal_conflict, [], source_path="internal.h")
        assert len(internal_errs) == 1
        assert "Conflicting profile for predicate 'check_magic'" in internal_errs[0]

    def test_anonymous_multiword_parameter_types_preserved(self) -> None:
        """Regression test for Bug 1: Anonymous parameter declarations with multi-word types must not be truncated."""
        # 1. Direct param extraction
        assert _extract_decl_param_types("predicate", " p(unsigned int)", "p") == ("unsigned int",)
        assert _extract_decl_param_types("predicate", " p(unsigned int x)", "p") == ("unsigned int",)
        assert _extract_decl_param_types("predicate", " p(unsigned char)", "p") == ("unsigned char",)
        assert _extract_decl_param_types("predicate", " p(unsigned char c)", "p") == ("unsigned char",)
        assert _extract_decl_param_types("predicate", " p(unsigned long)", "p") == ("unsigned long",)
        assert _extract_decl_param_types("predicate", " p(unsigned long l)", "p") == ("unsigned long",)
        assert _extract_decl_param_types("predicate", " p(unsigned short)", "p") == ("unsigned short",)
        assert _extract_decl_param_types("predicate", " p(signed char)", "p") == ("signed char",)
        assert _extract_decl_param_types("predicate", " p(long long)", "p") == ("long long",)
        assert _extract_decl_param_types("predicate", " p(struct token)", "p") == ("struct token",)
        assert _extract_decl_param_types("predicate", " p(struct token tok)", "p") == ("struct token",)
        assert _extract_decl_param_types("predicate", " p(const struct token)", "p") == ("const struct token",)
        assert _extract_decl_param_types("predicate", " p(const struct token tok)", "p") == ("const struct token",)

        # 2. Top-level extraction and conflict checking
        d_uint = extract_top_level_acsl_declarations("/*@ predicate check(unsigned int); */")
        d_uchar = extract_top_level_acsl_declarations("/*@ predicate check(unsigned char); */")
        d_named = extract_top_level_acsl_declarations("/*@ predicate check(unsigned int x); */")

        assert d_uint[0]["param_types"] == ("unsigned int",)
        assert d_uchar[0]["param_types"] == ("unsigned char",)
        assert d_named[0]["param_types"] == ("unsigned int",)

        # Differing anonymous types MUST be flagged as conflicting
        conflicts_diff = check_conflicting_acsl_profiles(d_uint, d_uchar)
        assert len(conflicts_diff) == 1
        assert "unsigned int" in conflicts_diff[0] and "unsigned char" in conflicts_diff[0]

        # Same type (one anonymous, one named) must NOT conflict
        assert check_conflicting_acsl_profiles(d_uint, d_named) == []

    def test_canonical_overloads_no_internal_self_conflict(self) -> None:
        """Regression test for Bug 2: Declarations in new_decls matching canonical vocabulary overloads must not self-conflict."""
        header_src = """/*@
          predicate valid_read_buffer(char *buf, integer len) =
            len >= 0 && (len == 0 || (buf != \\null && \\valid_read(buf + (0 .. len - 1))));

          predicate valid_read_buffer(unsigned char *buf, integer len) =
            len >= 0 && (len == 0 || (buf != \\null && \\valid_read(buf + (0 .. len - 1))));

          predicate valid_write_buffer(char *buf, integer len) =
            len >= 0 && (len == 0 || (buf != \\null && \\valid(buf + (0 .. len - 1))));

          predicate valid_write_buffer(unsigned char *buf, integer len) =
            len >= 0 && (len == 0 || (buf != \\null && \\valid(buf + (0 .. len - 1))));
        */
        """
        decls = extract_top_level_acsl_declarations(header_src, path="buffer_ops.h")
        assert len(decls) == 4

        # When checked against empty existing_decls, canonical overloads must not conflict internally
        conflicts_empty = check_conflicting_acsl_profiles(decls, [], source_path="buffer_ops.h")
        assert conflicts_empty == []

        # Non-canonical overload (e.g. int * for valid_read_buffer) MUST be flagged
        bad_overload_src = "/*@ predicate valid_read_buffer(int *buf, integer len); */"
        bad_decls = extract_top_level_acsl_declarations(bad_overload_src, path="bad_buffer.h")
        mixed_decls = decls + bad_decls
        conflicts_mixed = check_conflicting_acsl_profiles(mixed_decls, [], source_path="mixed.h")
        assert len(conflicts_mixed) >= 1
        assert any("valid_read_buffer" in c and "int *" in c for c in conflicts_mixed)


# ---------------------------------------------------------------------------
# Top-level declarations a prover adds outside its function (prover brief, Step B: Inductive Lemmas)
# ---------------------------------------------------------------------------

_BASE = "/*@ requires n >= 0;\n  @ assigns \\nothing;\n  @ ensures \\result == n;\n  @*/\nint f(int n) { return n; }\n"
_GHOST = (
    "/*@ ghost\n"
    "  /@ requires n >= 0;\n"
    "   @ decreases n;\n"
    "   @ assigns \\nothing;\n"
    "   @ ensures n >= 0;\n"
    "   @/\n"
    "  void lem(int n) { if (n <= 0) return; lem(n - 1); }\n"
    "*/\n"
)


class TestTopLevelAdditions:
    def test_a_ghost_function_with_its_own_contract_is_one_named_declaration(self) -> None:
        decls = extract_top_level_acsl_declarations(_GHOST + _BASE)
        assert [(d["kind"], d["name"], d["line"]) for d in decls] == [("ghost", "lem", 1)]
        assert decls[0]["text"].endswith("lem(n - 1); }")

    def test_a_ghost_variable_is_still_named(self) -> None:
        decls = extract_top_level_acsl_declarations("/*@ ghost int counter = 0; */\n" + _BASE)
        assert [(d["kind"], d["name"]) for d in decls] == [("ghost", "counter")]

    def test_added_declarations_count_repeats_and_ignore_base_ones(self) -> None:
        pred = "/*@ predicate pos(integer x) = x > 0; */\n"
        assert added_top_level_acsl_declarations(_BASE, _GHOST + _BASE) == ["ghost lem"]
        assert added_top_level_acsl_declarations(pred + _BASE, pred + _GHOST + _BASE) == ["ghost lem"]
        assert added_top_level_acsl_declarations(pred + _BASE, pred + pred + _BASE) == ["predicate pos"]
        assert added_top_level_acsl_declarations(_BASE, _BASE) == []

    def test_splice_refuses_a_ghost_function_and_names_it(self) -> None:
        agent = _GHOST + _BASE
        assert verify_acsl_only(_BASE, agent) == []
        with pytest.raises(ScopeViolationError, match=r"top-level ACSL declaration\(s\) outside 'f': ghost lem;"):
            splice_prover_changes(_BASE, agent, _BASE, "f")

    def test_splice_refuses_a_top_level_predicate_and_names_it(self) -> None:
        agent = "/*@ predicate pos(integer x) = x > 0; */\n" + _BASE
        with pytest.raises(ScopeViolationError, match=r"outside 'f': predicate pos;"):
            splice_prover_changes(_BASE, agent, _BASE, "f", path="m.c")

    def test_a_contract_only_edit_still_splices(self) -> None:
        agent = _BASE.replace("requires n >= 0;", "requires n >= 0;\n  @ requires n <= 100;")
        assert splice_prover_changes(_BASE, agent, _BASE, "f") == agent

    def test_another_edit_outside_the_span_keeps_the_old_message(self) -> None:
        base = "int g(void) { return 0; }\n" + _BASE
        agent = "int g(void) { /*@ assert \\true; */ return 0; }\n" + _BASE
        with pytest.raises(ScopeViolationError, match=r"agent modified content outside assigned function 'f'$"):
            splice_prover_changes(base, agent, base, "f")


_BEHAVIOR_CONTRACT = """/*@ assigns \\nothing;
  @ behavior negative:
  @   assumes n < 0;
  @   ensures \\result == -1;
  @ behavior other:
  @   assumes n >= 0;
  @   ensures \\result == 0;
  @ complete behaviors;
  @*/"""


class TestContractShape:
    @pytest.mark.parametrize(
        "contract",
        [
            # The result against an input, the pre-state, an input bound, a logic function of the inputs.
            "/*@ assigns \\nothing; ensures \\result == \\old(x) + 1; */",
            "/*@ assigns \\nothing; ensures 0 <= \\result <= n; */",
            "/*@ assigns \\nothing; ensures \\result == sum(a, n); */",
            "/*@ assigns \\nothing; ensures n < 0 ==> \\result == -1; */",
            # The content of an assigned location against its old value, an input, or the result.
            "/*@ assigns *p; ensures *p == \\old(*p) + 1; */",
            "/*@ assigns out->len; ensures out->len == n; */",
            "/*@ assigns *p; ensures \\result == *p; */",
            "/*@ assigns buf[0 .. n - 1]; ensures \\forall integer i; 0 <= i < n ==> buf[i] == 0; */",
            "/*@ assigns *p; ensures \\at(*p, Post) == \\at(*p, Pre); */",
            # No assigns clause: any value of the post-state may be an output.
            "/*@ ensures g == \\old(g) + 1; */",
            # A constant result is functional once the behavior's `assumes` ties it to an input.
            _BEHAVIOR_CONTRACT,
            # One functional clause is enough.
            "/*@ assigns \\nothing; ensures \\result >= 0; ensures \\result == a + b; */",
        ],
    )
    def test_functional(self, contract: str) -> None:
        assert contract_shape(contract) == "functional"

    @pytest.mark.parametrize(
        "contract",
        [
            "/*@ requires \\valid(p); assigns \\nothing; */",
            # A constant range, also through a cast or as a set of constants.
            "/*@ assigns \\nothing; ensures \\result >= 0; */",
            "/*@ assigns \\nothing; ensures (uint8_t)\\result >= 0; */",
            "/*@ assigns \\nothing; ensures \\result == 0 || \\result == -1; */",
            "/*@ assigns \\nothing; ensures \\result == MNL_CB_OK; */",
            "/*@ assigns *p; ensures *p == 5; */",
            # Validity, initialization and separation, whatever their arguments name.
            "/*@ assigns \\nothing; ensures \\result == \\null || \\valid(\\result + (0 .. n - 1)); */",
            "/*@ assigns buf[0 .. n - 1]; ensures \\initialized(buf + (0 .. n - 1)); */",
            "/*@ assigns *p; ensures \\separated(p, q); */",
            "/*@ assigns buf[0 .. n - 1]; ensures valid_read_buffer(buf, n); */",
            # One output against itself, the pre-state alone, a trivial clause.
            "/*@ assigns p->x; ensures p->x <= p->cap; */",
            "/*@ assigns \\nothing; ensures \\old(n) >= 0; */",
            "/*@ assigns \\nothing; ensures \\true; ensures \\result == \\result; */",
            # A behavior without an `assumes` ties the constant to nothing.
            "/*@ assigns \\nothing; behavior only: ensures \\result == 0; */",
        ],
    )
    def test_safety_only(self, contract: str) -> None:
        assert contract_shape(contract) == "safety_only"

    def test_not_applicable_needs_void_and_assigns_nothing(self) -> None:
        nothing = "/*@ requires \\valid_read(p); assigns \\nothing; */"
        assert contract_shape(nothing, returns_void=True) == "not_applicable"
        # A function that returns a value owes its caller a word about it.
        assert contract_shape(nothing, returns_void=False) == "safety_only"
        # A void function that writes, or that says nothing about what it writes, has outputs.
        assert contract_shape("/*@ assigns *p; */", returns_void=True) == "safety_only"
        assert contract_shape("/*@ requires \\valid(p); */", returns_void=True) == "safety_only"
        assert contract_shape("/*@ assigns *p; ensures *p == \\old(*p) + 1; */", returns_void=True) == "functional"

    def test_no_contract_is_unknown(self) -> None:
        assert contract_shape("") == "unknown"
        assert contract_shape("  \n", returns_void=True) == "unknown"

    def test_function_returns_void(self) -> None:
        source = (
            "void *alloc(int n);\n"
            "/*@ assigns \\nothing; */\n"
            "void f(int *p) { }\n"
            "static inline unsigned int g(void) { return 0; }\n"
        )
        assert function_returns_void(source, "f") is True
        assert function_returns_void(source, "g") is False
        # `void *` is a result, and a prototype is read in a header only.
        assert function_returns_void(source, "alloc", is_header=True) is False
        assert function_returns_void(source, "alloc") is None
        assert function_returns_void(source, "missing") is None
