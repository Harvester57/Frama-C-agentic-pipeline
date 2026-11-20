#!/usr/bin/env python3
"""
Unit tests for scripts/acsl_ast.py:
- Canonical ACSL declaration extraction with parameter types and full profiles
- Comment-only and whitespace-only ACSL annotation block detection and stripping
- Conflicting predicate profile detection across declarations
- Preserving valid overloads while deduplicating identical profiles
"""

from __future__ import annotations

from pathlib import Path

import pytest

from acsl_ast import (
    AcslError,
    ScopeViolationError,
    _extract_decl_param_types,
    _is_acsl_comment_or_whitespace_only,
    added_top_level_acsl_declarations,
    check_conflicting_acsl_profiles,
    contract_shape,
    dedup_acsl_declarations,
    extract_top_level_acsl_declarations,
    find_in_body_ghost_declarations,
    find_target_unsound_axioms_or_admits,
    find_top_level_lemmas,
    find_unsound_acsl_keywords,
    find_unsound_recursive_logic,
    function_returns_void,
    splice_prover_changes,
    tokenize_c_acsl,
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


class TestTier1SoundnessChecks:
    """Tier 1 soundness checks: global lemmas, target axioms/admits, and recursive logic/predicates.

    Trap snippets adapted from MIT-licensed sysprog21/frama-c-mcp fixtures (commit 4b935a0).
    """

    @pytest.mark.unit
    def test_find_top_level_lemmas_standalone_axiomatic_and_ignores_non_wp(self) -> None:
        src = (
            "/*@ lemma unprovable: \\false; */\n"
            "/*@ lemma provable: \\forall integer i; i + 0 == i; */\n"
            "/*@ axiomatic Ax { lemma in_ax: \\true; } */\n"
            "/*@ admit lemma adm_lem: \\false; */\n"
            "/*@{ lemma doxygen_ignored: \\false; */\n"
            "/* // lemma c_comment_ignored: \\false; */\n"
            "/*@ // lemma inner_acsl_comment_ignored: \\false;\n"
            "    predicate ok(integer n) = n >= 0;\n"
            "*/\n"
            'const char *msg = "/*@ lemma string_ignored: \\false; */";\n'
            "#if defined(__FRAMAC_EACSL__)\n"
            "/*@ lemma eacsl_only_ignored: \\false; */\n"
            "#endif\n"
            "#ifdef __FRAMAC_EACSL__\n"
            "/*@ lemma eacsl_ifdef_ignored: \\false; */\n"
            "#else\n"
            "/*@ lemma wp_else_seen: \\true; */\n"
            "#endif\n"
            "int f(int x) { return x; }\n"
        )
        assert find_top_level_lemmas(src, path="lemma-unproved.c") == [
            "unprovable",
            "provable",
            "in_ax",
            "adm_lem",
            "wp_else_seen",
        ]

    @pytest.mark.unit
    def test_find_target_unsound_axioms_or_admits(self) -> None:
        # MIT fixture: sysprog21/frama-c-mcp axiom-licensed.c
        axiom_src = "/*@ axiom bogus: \\false; */\nint main(void) { return 0; }\n"
        hits = find_target_unsound_axioms_or_admits(axiom_src, path="axiom-licensed.c")
        assert len(hits) == 1
        assert "'axiom'" in hits[0]

        admit_src = (
            "/*@{ axiom dox_ignored: \\false; */\n"
            'const char *s = "/*@ admit \\false; */";\n'
            "#if defined(__FRAMAC_EACSL__)\n"
            "/*@ axiom eacsl_ignored: \\false; */\n"
            "#endif\n"
            "void f(int x) {\n"
            "  /*@ ghost int y = x; //@ admit y == 0;\n"
            "  */\n"
            "}\n"
        )
        admit_hits = find_target_unsound_axioms_or_admits(admit_src, path="admit.c")
        assert len(admit_hits) == 1
        assert "'admit'" in admit_hits[0]

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "bad_src",
        [
            # MIT fixture: sysprog21/frama-c-mcp recursive-logic-unsound.c
            "/*@ logic integer bad(integer n) = bad(n) + 1; */\nint f(int x) { return 0; }\n",
            # Unbounded descent without base-case guard
            "/*@ logic integer bad(integer n) = bad(n - 1) + 1; */\n",
            # Base guard exists, but call does not descend
            "/*@ logic integer bad(integer n) = n <= 0 ? 0 : bad(n) + 1; */\n",
            # Lower-bound guard with wrong-direction recursion
            "/*@ logic integer bad(integer n) = n <= 0 ? 0 : bad(n + 1) + 1; */\n",
            # Inverted ternary puts recursive call in base branch
            "/*@ logic integer bad(integer n) = n <= 0 ? bad(n - 1) : 0; */\n",
            # One descending call and one non-descending call
            "/*@ logic integer bad(integer n) = n <= 0 ? 0 : bad(n - 1) + bad(n); */\n",
            # Mutual recursion cycle
            "/*@ logic integer a(integer n) = b(n);\n    logic integer b(integer n) = a(n); */\n",
            # Mutual recursion cycle even with guards
            (
                "/*@ logic integer a(integer n) = n <= 0 ? 0 : b(n - 1);\n"
                "    logic integer b(integer n) = n <= 0 ? 0 : a(n - 1); */\n"
            ),
            # Non-well-founded recursive predicate
            "/*@ predicate bad_p(integer n) = bad_p(n); */\n",
            # Zero-arg self-recursion
            "/*@ logic integer bad_const = bad_const + 1; */\n",
            # Sentinel guard without advance
            "/*@ logic integer bad_str(char *s) = s[0] == '\\0' ? 0 : 1 + bad_str(s); */\n",
            # Partner upper bound moving away instead of staying fixed/converging
            "/*@ logic integer bad_rng(int *a, integer lo, integer hi) = lo >= hi ? 0 : a[lo] + bad_rng(a, lo + 1, hi + 1); */\n",
        ],
    )
    def test_find_unsound_recursive_logic_rejects_unsound_definitions(self, bad_src: str) -> None:
        direct_errs = find_unsound_recursive_logic(bad_src, path="rec.c")
        assert direct_errs, bad_src
        kw_errs = find_unsound_acsl_keywords(tokenize_c_acsl(bad_src, path="rec.c"), path="rec.c")
        assert any("recursive ACSL" in e for e in kw_errs), kw_errs
        base = "int f(int x) { return 0; }\n"
        if "int f(" not in bad_src:
            verify_errs = verify_acsl_only(base, bad_src + base, path="rec.c")
        else:
            verify_errs = verify_acsl_only(base, bad_src, path="rec.c")
        assert any("recursive ACSL" in e for e in verify_errs), verify_errs

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "good_src",
        [
            "/*@ logic integer sum(integer n) = n <= 0 ? 0 : n + sum(n - 1); */\n",
            "/*@ logic integer sum_eq(integer n) = n == 0 ? 0 : n + sum_eq(n - 1); */\n",
            "/*@ logic integer sum_flip(integer n) = n > 0 ? n + sum_flip(n - 1) : 0; */\n",
            "/*@ logic integer fib(integer n) = n <= 1 ? n : fib(n - 1) + fib(n - 2); */\n",
            "/*@ logic integer rng(int *a, integer lo, integer hi) = lo >= hi ? 0 : a[lo] + rng(a, lo + 1, hi); */\n",
            "/*@ logic integer rng2(int *a, integer lo, integer hi) = lo < hi ? a[hi - 1] + rng2(a, lo, hi - 1) : 0; */\n",
            "/*@ logic integer c_strlen(char *s) = (s[0] == '\\0') ? 0 : 1 + c_strlen(s + 1); */\n",
            "/*@ logic integer star_strlen(char *s) = *s == '\\0' ? 0 : 1 + star_strlen(s + 1); */\n",
            "/*@ predicate all_pos(int *a, integer n) = n <= 0 || (a[n - 1] > 0 && all_pos(a, n - 1)); */\n",
            "/*@ predicate all_pos_imp(int *a, integer n) = n > 0 ==> (a[n - 1] > 0 && all_pos_imp(a, n - 1)); */\n",
            "/*@ logic integer chained(int *a, integer n) = a == \\null ? 0 : n <= 0 ? 0 : a[n - 1] + chained(a, n - 1); */\n",
            # E-ACSL-only block is skipped even if non-well-founded
            "#if defined(__FRAMAC_EACSL__)\n/*@ logic integer eacsl_only(integer n) = eacsl_only(n) + 1; */\n#endif\n",
        ],
    )
    def test_find_unsound_recursive_logic_accepts_well_founded_and_eacsl_blocks(self, good_src: str) -> None:
        assert find_unsound_recursive_logic(good_src, path="ok.c") == []
        assert find_unsound_acsl_keywords(tokenize_c_acsl(good_src, path="ok.c"), path="ok.c") == []

    @pytest.mark.unit
    def test_fc_compat_types_eacsl_strlen_passes_recursive_logic_check(self) -> None:
        compat = Path(__file__).resolve().parent.parent / "templates" / "fc_stubs" / "fc_compat_types.h"
        text = compat.read_text(encoding="utf-8")
        assert find_unsound_recursive_logic(text, path=str(compat)) == []
        assert find_top_level_lemmas(text, path=str(compat)) == []
        assert find_target_unsound_axioms_or_admits(text, path=str(compat)) == []


_IN_BODY_BASE = (
    "int walk(const char *buf, const char *p, int n, int cond) {\n  (void)buf; (void)p; (void)cond;\n  return n;\n}\n"
)


def _with_body_snippet(snippet: str) -> str:
    return _IN_BODY_BASE.replace("  return n;\n", f"  {snippet}\n  return n;\n")


class TestInBodyGhostDeclarations:
    """Reject block-scope ghost function prototypes/definitions/externs/contracts while allowing valid ghost code."""

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "bad_snippet",
        [
            r"/*@ ghost /@ ensures \false; @/ extern void fake(void); fake(); */",
            r"/*@ ghost /@ requires \true; ensures \result == 42; @/ int fake(int x); */",
            "/*@ ghost extern void fake(void); */",
            "/*@ ghost extern int ghost_global; */",
            "/*@ ghost void fake(void); */",
            "/*@ ghost int fake(int x); */",
            "/*@ ghost int fake(); */",
            "/*@ ghost const char *fake(const char *s); */",
            "/*@ ghost const struct foo *fake(size_t n); */",
            "/*@ ghost my_typedef_t fake(int x); */",
            "/*@ ghost my_typedef_t *fake(int x); */",
            "/*@ ghost void helper(int n) { if (n <= 0) return; helper(n - 1); } */",
            "/*@ ghost static void helper(void) { } */",
            "/*@ ghost static inline int helper(int x) { return x + 1; } */",
            "/*@ ghost int helper(x) int x; { return x; } */",
            "/*@ ghost int (fake)(int x); */",
            "/*@ ghost int (*fake(int x))(int); */",
            "/*@ ghost int a = 0, fake(int x); */",
            "/*@ ghost { extern void fake(void); fake(); } */",
            "/*@ ghost if (cond) { void fake(void); fake(); } */",
            "/*@ ghost int r = ({ void fake(void); fake(); }); */",
            r"/*@ ghost /@ ensures \false; @/ int x = 0; */",
            "/*@ ghost\n  @ /@ ensures \\false; @/\n  @ void fake(void);\n  @*/",
            "//@ ghost extern void fake(void);",
            "//@ ghost void fake(void);",
            "//@ ghost static void helper(void) { }",
            r"//@ ghost /@ requires \true; ensures \result == 42; @/ int fake(int x);",
            "//@ ghost void\n  //@ ghost fake(void);",
            "/*@ ghost void */ /*@ ghost fake(void); */",
        ],
        ids=[
            "contract-extern-proto-and-call",
            "contract-proto-with-requires-ensures",
            "extern-void-proto",
            "extern-var-decl",
            "plain-void-proto",
            "plain-int-proto",
            "empty-param-proto",
            "const-ptr-proto",
            "const-struct-ptr-proto",
            "typedef-ret-proto",
            "typedef-ptr-ret-proto",
            "recursive-ghost-fn-def",
            "static-void-fn-def",
            "static-inline-fn-def",
            "kr-fn-def",
            "parenthesized-fn-declarator",
            "fn-returning-fn-ptr-proto",
            "mixed-var-and-fn-proto",
            "nested-compound-extern-proto",
            "if-body-fn-proto",
            "gnu-stmt-expr-fn-proto",
            "contract-on-ghost-var-decl",
            "at-margin-contract-and-proto",
            "line-form-extern-proto",
            "line-form-plain-proto",
            "line-form-static-fn-def",
            "line-form-contract-and-proto",
            "split-line-form-proto",
            "split-block-form-proto",
        ],
    )
    def test_rejects_forbidden_in_body_ghost_declarations(self, bad_snippet: str) -> None:
        src = _with_body_snippet(bad_snippet)
        direct_errs = find_in_body_ghost_declarations(src, path="m.c")
        assert direct_errs, bad_snippet
        assert all("forbidden" in e and "in-body ghost" in e for e in direct_errs), direct_errs

        kw_errs = find_unsound_acsl_keywords(tokenize_c_acsl(src, path="m.c"), path="m.c")
        assert any("in-body ghost" in e for e in kw_errs), kw_errs

        verify_errs = verify_acsl_only(_IN_BODY_BASE, src, path="m.c")
        assert any("in-body ghost" in e for e in verify_errs), verify_errs

    @pytest.mark.unit
    def test_rejects_active_else_arm_of_eacsl_guard(self) -> None:
        src = _with_body_snippet(
            "#if defined(__FRAMAC_EACSL__)\n"
            "  /*@ ghost size_t idx = 0; */\n"
            "#else\n"
            "  /*@ ghost void fake(void); */\n"
            "#endif"
        )
        errs = find_in_body_ghost_declarations(src, path="m.c")
        assert len(errs) == 1
        assert "'fake'" in errs[0]

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "good_snippet",
        [
            # Ghost variable declarations & initializers (including Tier 3a idioms)
            "/*@ ghost size_t idx = 0; */",
            "/*@ ghost int k = (int)n; */",
            "/*@ ghost const char *base = p; */",
            "/*@ ghost const struct foo *q = ptr; */",
            "/*@ ghost unsigned long acc = 0UL; */",
            "/*@ ghost size_t len = strlen(p); */",
            "/*@ ghost int r = foo(n, cond); */",
            "/*@ ghost int arr[8] = {0}; */",
            "/*@ ghost static int local_cnt = 0; */",
            "/*@ ghost int (*fp)(int) = &cb; */",
            "/*@ ghost int (*fp)(int); */",
            "/*@ ghost my_t (*fp)(int); */",
            "/*@ ghost struct tmp { int a; int b; } st = { 1, 2 }; */",
            "/*@ ghost typeof(p) base = p; */",
            # Ghost assignments, casts, and control-flow statements
            "/*@ ghost idx++; */",
            "/*@ ghost idx = (size_t)(p - buf); */",
            "/*@ ghost (void)idx; */",
            "/*@ ghost (void)lemma_strlen_step(p, n); */",
            "/*@ ghost (*fp)(n); */",
            "/*@ ghost get_fn(arg)(n); */",
            "/*@ ghost if (cond) { idx += 1; } */",
            "/*@ ghost if (cond) lemma_strlen_step(p, n); else fc_lemma_foo(p, buf); */",
            "/*@ ghost while (idx < n) { idx++; } */",
            "/*@ ghost for (size_t i = 0; i < (size_t)n; i++) { acc += i; } */",
            "/*@ ghost do { idx++; } while (0); */",
            "/*@ ghost switch (n) { case 0: fc_lemma_foo(p, buf); break; default: lemma_strlen_step(p, n); break; } */",
            "/*@ ghost done: fc_lemma_foo(p, buf); */",
            "/*@ ghost return fc_lemma_foo(p, buf); */",
            # Ghost function calls (no return type before identifier)
            "/*@ ghost lemma_strlen_step(p, n); */",
            "/*@ ghost fc_lemma_foo(p, buf); */",
            # Embedded ghost loop annotations & assertions (not contracts attached to declarations)
            "/*@ ghost size_t i = 0; /@ loop invariant 0 <= i <= n; loop assigns i; loop variant n - i; @/ while (i < (size_t)n) { i++; } */",
            "/*@ ghost size_t idx = 0; /@ assert idx == 0; @/ idx++; */",
            "/*@ ghost size_t idx = 0; //@ assert idx == 0;\n  */",
            "/*@ ghost size_t idx = 0; /@ // ensures \\false;\n assert idx == 0; @/ size_t k = idx; */",
            # Line-form legitimate ghost statements
            "//@ ghost size_t idx = 0;\n  //@ ghost idx++;\n  //@ ghost lemma_strlen_step(p, n);",
            # Frama-C ghost actual-argument syntax
            "/*@ ghost (p, n) */",
            # Commented-out or string-literal fake prototypes inside ghost blocks
            "/*@ ghost // extern void fake(void);\n  size_t idx = 0; */",
            r'/*@ ghost const char *msg = "extern void fake(void); /@ ensures \false; @/"; */',
            # Non-ghost identifier starting with `ghost`
            "/*@ ghost_label: assert n >= 0; */",
        ],
    )
    def test_allows_legitimate_in_body_ghost_code(self, good_snippet: str) -> None:
        src = _with_body_snippet(good_snippet)
        assert find_in_body_ghost_declarations(src, path="ok.c") == [], good_snippet
        assert find_unsound_acsl_keywords(tokenize_c_acsl(src, path="ok.c"), path="ok.c") == [], good_snippet
        assert verify_acsl_only(_IN_BODY_BASE, src, path="ok.c") == [], good_snippet

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "ignored_snippet",
        [
            "#if defined(__FRAMAC_EACSL__)\n  /*@ ghost extern void fake(void); */\n#endif",
            "#ifdef __FRAMAC_EACSL__\n  /*@ ghost void helper(void) { } */\n#endif",
            "#if 0\n  /*@ ghost /@ ensures \\false; @/ extern void fake(void); */\n#endif",
            "#if !defined(__FRAMAC_EACSL__)\n  /*@ ghost size_t idx = 0; */\n#else\n  /*@ ghost void fake(void); */\n#endif",
            "/*@{ ghost extern void fake(void); */",
            "/*@* ghost void helper(void) { } */",
            "//@{ ghost extern void fake(void);",
            "/* /*@ ghost extern void fake(void); */ */",
            "// /*@ ghost extern void fake(void); */",
            'const char *lit = "/*@ ghost extern void fake(void); */";',
        ],
        ids=[
            "if-defined-eacsl",
            "ifdef-eacsl",
            "if-0",
            "else-of-not-eacsl",
            "doxygen-block-open",
            "doxygen-block-star",
            "doxygen-line-open",
            "c-block-comment",
            "c-line-comment",
            "c-string-literal",
        ],
    )
    def test_ignores_inactive_preprocessor_comments_literals_and_doxygen(self, ignored_snippet: str) -> None:
        src = _with_body_snippet(ignored_snippet)
        assert find_in_body_ghost_declarations(src, path="ok.c") == []

    @pytest.mark.unit
    def test_file_scope_ghost_extern_c_and_struct_ghost_fields(self) -> None:
        # File-scope ghost function (brace_depth == 0) is NOT an in-body ghost declaration
        assert find_in_body_ghost_declarations(_GHOST + _BASE, path="top.c") == []

        # File-scope ghost function inside `extern "C" { ... }` stays at brace_depth == 0
        extern_c_ok = (
            '#ifdef __cplusplus\nextern "C" {\n#endif\n'
            + _GHOST
            + "int f(int n) { /*@ ghost size_t idx = 0; */ return n; }\n"
            + "#ifdef __cplusplus\n}\n#endif\n"
        )
        assert find_in_body_ghost_declarations(extern_c_ok, path="hdr.h") == []

        # In-body ghost prototype inside `extern "C" { ... }` IS caught
        extern_c_bad = 'extern "C" {\n  int f(int n) { /*@ ghost extern void fake(void); */ return n; }\n}\n'
        errs = find_in_body_ghost_declarations(extern_c_bad, path="hdr.h")
        assert len(errs) == 1 and "'fake'" in errs[0]

        # Struct ghost fields (including function-pointer fields) are allowed
        struct_src = (
            "struct S {\n  int x;\n  /*@ ghost size_t ghost_len; */\n  /*@ ghost void (*ghost_cb)(int); */\n};\n"
        )
        assert find_in_body_ghost_declarations(struct_src, path="s.h") == []

    @pytest.mark.unit
    def test_verify_acsl_only_and_splice_prover_changes_end_to_end(self) -> None:
        # 1. Legitimate Tier 3a ghost index + pointer anchor + cast + increment + ghost call splices cleanly
        good_agent = _IN_BODY_BASE.replace(
            "  (void)buf; (void)p; (void)cond;\n",
            "  (void)buf; (void)p; (void)cond;\n"
            "  /*@ ghost const char *base = p; */\n"
            "  /*@ ghost size_t idx = 0; */\n"
            "  /*@ ghost idx = (size_t)(p - buf); */\n"
            "  /*@ ghost idx++; */\n"
            "  /*@ ghost lemma_strlen_step(base, n); */\n",
        )
        assert verify_acsl_only(_IN_BODY_BASE, good_agent, path="walk.c") == []
        assert splice_prover_changes(_IN_BODY_BASE, good_agent, _IN_BODY_BASE, "walk", path="walk.c") == good_agent

        # 2. Forbidden in-body ghost declarations are rejected by both verify_acsl_only and splice_prover_changes
        for bad_snippet in (
            r"/*@ ghost /@ ensures \false; @/ extern void fake(void); fake(); */",
            r"/*@ ghost /@ requires \true; ensures \result == 42; @/ int fake(int x); */",
            "/*@ ghost extern void fake(void); */",
            "/*@ ghost void helper(int n) { if (n > 0) helper(n - 1); } */",
            "/*@ ghost static void helper(void) { } */",
            "//@ ghost extern void fake(void);",
        ):
            bad_agent = _with_body_snippet(bad_snippet)
            v_errs = verify_acsl_only(_IN_BODY_BASE, bad_agent, path="walk.c")
            assert any("in-body ghost" in e for e in v_errs), (bad_snippet, v_errs)
            with pytest.raises(AcslError, match=r"in-body ghost"):
                splice_prover_changes(_IN_BODY_BASE, bad_agent, _IN_BODY_BASE, "walk", path="walk.c")

        # 3. Header `static inline` body with forbidden in-body ghost declaration is also rejected on splice
        hdr_base = "static inline int hfn(int x) {\n  return x;\n}\n"
        hdr_bad = "static inline int hfn(int x) {\n  //@ ghost extern void fake(void);\n  return x;\n}\n"
        with pytest.raises(AcslError, match=r"in-body ghost"):
            splice_prover_changes(hdr_base, hdr_bad, hdr_base, "hfn", is_header=True, path="walk.h")

        # 4. Baseline preservation: pre-existing in-body ghost declaration is not blamed on line shifts,
        #    while adding a second one or attaching a contract to it IS flagged
        preexisting_base = _with_body_snippet("/*@ ghost void legacy_proto(void); */")
        shifted_ok = "/*@ assigns \\nothing; */\n" + preexisting_base
        assert verify_acsl_only(preexisting_base, shifted_ok, path="legacy.c") == []

        upgraded_with_contract = preexisting_base.replace(
            "/*@ ghost void legacy_proto(void); */",
            r"/*@ ghost /@ ensures \false; @/ void legacy_proto(void); */",
        )
        assert any(
            "in-body ghost" in e for e in verify_acsl_only(preexisting_base, upgraded_with_contract, path="legacy.c")
        )

        added_second = preexisting_base.replace(
            "  return n;\n",
            "  /*@ ghost void legacy_proto(void); */\n  return n;\n",
        )
        assert any("in-body ghost" in e for e in verify_acsl_only(preexisting_base, added_second, path="legacy.c"))

        # 5. check_unsound=False skips the soundness check consistently with other unsound checks
        bad_agent = _with_body_snippet("/*@ ghost extern void fake(void); */")
        assert verify_acsl_only(_IN_BODY_BASE, bad_agent, path="walk.c", check_unsound=False) == []
