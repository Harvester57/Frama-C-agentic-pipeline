"""
Adversarial empirical stress-tests for Milestone M1 (AST Foundations & Stubs).
Author: challenger_m1_1
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import acsl_ast
import function_slice
import mutation_check
from acsl_ast import AcslSyntaxError, iter_clauses, tokenize_c_acsl

pytestmark = pytest.mark.unit


# ===========================================================================
# 1. Stress-test ACSL clause iteration (iter_clauses)
# ===========================================================================


class TestAcslClauseIterationAdversarial:
    """Stress-test iter_clauses with complex nested binders, comments, and literals."""

    def test_deeply_nested_mixed_binders(self):
        """Quantifiers (\\forall, \\exists, \\let) at multiple levels."""
        text = (
            "/*@ ensures \\forall integer i; 0 <= i < n ==>\n"
            "      \\exists integer j; 0 <= j < m &&\n"
            "        (\\forall integer k; 0 <= k < p ==> a[i][j][k] == 0);\n"
            "    ensures \\let diff = max - min; diff >= 0;\n"
            "*/"
        )
        clauses = list(iter_clauses(text))
        assert len(clauses) == 2
        assert clauses[0][0] == "ensures"
        assert "\\forall integer i;" in clauses[0][2]
        assert "\\exists integer j;" in clauses[0][2]
        assert "\\forall integer k;" in clauses[0][2]
        assert clauses[1][0] == "ensures"
        assert clauses[1][2] == "\\let diff = max - min; diff >= 0"

        # Check exact spans
        for kind, _label, _pred, span in clauses:
            assert text[span[0] : span[1]].startswith(kind)
            assert text[span[0] : span[1]].endswith(";")

    def test_semicolons_in_string_and_char_literals(self):
        """Semicolons within string and character literals must not prematurely terminate clauses."""
        text = (
            '/*@ requires valid_format("format;with;semicolons;");\n'
            "    requires sep == ';';\n"
            "    ensures \\result == 0;\n"
            "*/"
        )
        clauses = list(iter_clauses(text))
        assert len(clauses) == 3
        assert clauses[0][0] == "requires"
        assert 'valid_format("format;with;semicolons;")' in clauses[0][2]
        assert clauses[1][0] == "requires"
        assert "sep == ';'" in clauses[1][2]
        assert clauses[2][0] == "ensures"
        assert clauses[2][2] == "\\result == 0"

    def test_tricky_comments_with_keywords_and_semicolons(self):
        """Line comments containing semicolons and clause keywords must be masked out."""
        text = (
            "/*@ requires x > 0; // comment with ; and requires y > 0;\n"
            "    ensures z > 0; // comment with ensures w > 0;\n"
            "*/"
        )
        clauses = list(iter_clauses(text))
        assert len(clauses) == 2
        assert clauses[0][0] == "requires"
        assert clauses[1][0] == "ensures"

    def test_all_standard_clause_heads(self):
        """All supported clause keywords are recognized."""
        text = (
            "/*@ requires r > 0;\n"
            "    assumes a > 0;\n"
            "    ensures e > 0;\n"
            "    assigns *p;\n"
            "    allocates \\nothing;\n"
            "    frees \\nothing;\n"
            "    terminates \\true;\n"
            "    exits \\false;\n"
            "    breaks \\false;\n"
            "    continues \\false;\n"
            "    returns \\false;\n"
            "    decreases d;\n"
            "    loop invariant li > 0;\n"
            "    loop assigns la;\n"
            "    loop variant lv;\n"
            "*/"
        )
        clauses = list(iter_clauses(text))
        kinds = [c[0] for c in clauses]
        expected_kinds = [
            "requires",
            "assumes",
            "ensures",
            "assigns",
            "allocates",
            "frees",
            "terminates",
            "exits",
            "breaks",
            "continues",
            "returns",
            "decreases",
            "loop invariant",
            "loop assigns",
            "loop variant",
        ]
        assert kinds == expected_kinds

    def test_field_names_resembling_keywords_are_not_clause_heads(self):
        """Field accesses like s.ensures or p->requires must not be misidentified as clause starts."""
        text = "/*@ requires s.ensures == 0 && p->requires == 1; ensures s.assigns != 0; */"
        clauses = list(iter_clauses(text))
        assert len(clauses) == 2
        assert clauses[0][0] == "requires"
        assert clauses[0][2] == "s.ensures == 0 && p->requires == 1"
        assert clauses[1][0] == "ensures"
        assert clauses[1][2] == "s.assigns != 0"

    def test_multiple_labels_parsed(self):
        """Multiple labels on a single clause are joined with commas."""
        text = "/*@ requires lbl1: lbl2: lbl3: x > 0; */"
        clauses = list(iter_clauses(text))
        assert len(clauses) == 1
        assert clauses[0][1] == "lbl1, lbl2, lbl3"
        assert clauses[0][2] == "x > 0"

    def test_find_named_clause_with_multiple_labels(self):
        """find_named_clause successfully resolves any label from a multi-label clause."""
        text = "/*@ requires r1: r2: x > 0; ensures ok1: ok2: \\result == 0; */"
        assert acsl_ast.find_named_clause(text, "r1") == "x > 0"
        assert acsl_ast.find_named_clause(text, "r2") == "x > 0"
        assert acsl_ast.find_named_clause(text, "ok1") == "\\result == 0"
        assert acsl_ast.find_named_clause(text, "ok2") == "\\result == 0"
        assert acsl_ast.find_named_clause(text, "nonexistent") is None

    def test_continuation_line_label_with_at_margin(self):
        """A clause label on a continuation line starting with ACSL '@' margin should be recognized."""
        text = "/*@ requires\n  @   my_label: x > 0;\n*/"
        clauses = list(iter_clauses(text))
        assert len(clauses) == 1
        assert clauses[0][1] == "my_label"
        assert clauses[0][2] == "x > 0"
        assert acsl_ast.find_named_clause(text, "my_label") == "x > 0"

    def test_multi_line_labels_with_at_margin(self):
        """Multiple labels across continuation lines with '@' margins should all be extracted."""
        text = "/*@ requires r1:\n  @   r2: x > 0;\n*/"
        clauses = list(iter_clauses(text))
        assert len(clauses) == 1
        assert clauses[0][1] == "r1, r2"
        assert clauses[0][2] == "x > 0"
        assert acsl_ast.find_named_clause(text, "r2") == "x > 0"


# ===========================================================================
# 2. Stress-test spec mutation (mutation_check.spec_mutants)
# ===========================================================================


class TestSpecMutantsAdversarial:
    """Stress-test spec_mutants operator flipping and equivalence preservation."""

    def test_equivalence_operator_never_corrupted(self):
        """Complex formulas with <==>, ==>, <=, >= must never mutate <==> into <=>."""
        contract = "/*@ ensures (a <= b <==> c >= d) ==> (e <= f <==> g >= h);\n    ensures x <= y <==> z >= w;\n*/"
        mutants = dict(mutation_check.spec_mutants(contract, 10))
        for name, mut in mutants.items():
            assert "<=>" not in mut, f"Corrupted equivalence operator found in {name}: {mut}"
            assert "-=>" not in mut, f"Corrupted operator found in {name}: {mut}"

        # Check weaken-ensures mutants flipped <= to < and >= to >
        weaken_0 = mutants.get("weaken-ensures-0")
        assert weaken_0 is not None
        assert "(a < b <==> c > d) ==> (e < f <==> g > h)" in weaken_0

    def test_duplicate_ensures_clauses_mutated_individually(self):
        """Identical ensures clauses must be dropped and mutated by exact span, not string replacement."""
        contract = "/*@ ensures a <= 1;\n    ensures a <= 1;\n*/"
        mutants = dict(mutation_check.spec_mutants(contract, 10))

        # drop-ensures-0 drops first, leaves second
        drop_0 = mutants["drop-ensures-0"]
        assert drop_0.count("ensures a <= 1;") == 1

        # drop-ensures-1 drops second, leaves first
        drop_1 = mutants["drop-ensures-1"]
        assert drop_1.count("ensures a <= 1;") == 1

        # weaken-ensures-0 mutates only the first
        weaken_0 = mutants["weaken-ensures-0"]
        assert "ensures a < 1;" in weaken_0
        assert "ensures a <= 1;" in weaken_0

        # weaken-ensures-1 mutates only the second
        weaken_1 = mutants["weaken-ensures-1"]
        assert "ensures a <= 1;" in weaken_1
        assert "ensures a < 1;" in weaken_1

    def test_shift_and_arrow_operators_preserved(self):
        """Operators like <<=, >>=, -> must not be confused with relational flips."""
        contract = "/*@ ensures p->len <= (limit >> 1); */"
        mutants = dict(mutation_check.spec_mutants(contract, 5))
        weaken_0 = mutants.get("weaken-ensures-0")
        assert weaken_0 is not None
        assert "p->len < (limit >> 1)" in weaken_0


# ===========================================================================
# 3. Stress-test implementation mutation (mutation_check.impl_mutants)
# ===========================================================================


class TestImplMutantsAdversarial:
    """Stress-test impl_mutants with return statements and relational ops in strings/comments."""

    def test_returns_and_relops_in_comments_and_strings_ignored(self):
        """Return statements and relops in comments and strings must never become mutants."""
        body = """{
            // return 0; <= >= <==>
            /* multiline
               return -1;
               p->val >= 10
            */
            const char *msg = "return 99; <= >= ";
            const char *esc = "escaped \\" return -42; \\" literal";
            char c = '<';
            int return_val = 5;
            if (x <= 10 && y >= 20 && p->len < 30 && z > 40) {
                return 0;
            }
            return -5;
        }"""
        mutants = dict(mutation_check.impl_mutants(body, 20))

        # Must NOT contain mutants for comments or strings
        assert "return-99-to-100" not in mutants
        assert "return--42-to--41" not in mutants
        assert "return--1-to-0" not in mutants

        # Must contain real code mutants
        assert "flip-<=" in mutants
        assert "flip->=" in mutants
        assert "flip-<" in mutants
        assert "flip->" in mutants
        assert "return-0-to-1" in mutants
        assert "return--5-to--4" in mutants

        # Verify mutated return produces valid code
        ret_neg = mutants["return--5-to--4"]
        assert "return -4;" in ret_neg

    def test_duplicate_return_constants_mutated_by_span(self):
        """Two identical return statements in the same body are mutated independently."""
        body = "int f(int x) { if (x > 0) return 0; return 0; }"
        mutants = mutation_check.impl_mutants(body, 10)
        ret_mutants = [m for name, m in mutants if name == "return-0-to-1"]
        assert len(ret_mutants) == 2
        # First mutant modifies only first return
        assert "if (x > 0) return 1; return 0;" in ret_mutants[0]
        # Second mutant modifies only second return
        assert "if (x > 0) return 0; return 1;" in ret_mutants[1]


# ===========================================================================
# 4. Stress-test logic signature checking (find_unsound_acsl_keywords)
# ===========================================================================


class TestLogicSignaturesAdversarial:
    """Stress-test logic declarations with label lists, pointer types, and bare C types."""

    @pytest.mark.parametrize(
        "sig",
        [
            "/*@ logic integer f{L}(int x); */",
            "/*@ logic integer f{L1, L2}(int x); */",
            "/*@ logic integer f{\n  Here,\n  Pre\n}(int x); */",
            "/*@ logic integer f{L}(int *p, int x); */",
            "/*@ logic integer f{L}(uintptr_t x); */",
            "/*@ logic integer f{L}(intptr_t x); */",
            "/*@ logic integer f{L}(ptrdiff_t x); */",
            "/*@ logic integer f{L}(size_t x); */",
            "/*@ logic integer f{L}(ssize_t x); */",
            "/*@ logic integer f{L}(unsigned x); */",
            "/*@ logic integer f{L}(signed x); */",
            "/*@ logic integer f{L}(const unsigned int x); */",
        ],
    )
    def test_forbidden_c_int_parameters_flagged(self, sig):
        tokens = tokenize_c_acsl(sig)
        errors = acsl_ast.find_unsound_acsl_keywords(tokens)
        assert any("forbidden C integer parameter" in e for e in errors), f"Failed for {sig}: {errors}"

    @pytest.mark.parametrize(
        "sig",
        [
            "/*@ logic unsigned f{L}(integer x); */",
            "/*@ logic signed f{L}(integer x); */",
            "/*@ logic uintptr_t f{L}(integer x); */",
            "/*@ logic intptr_t f{L}(integer x); */",
            "/*@ logic ptrdiff_t f{L}(integer x); */",
            "/*@ logic size_t f{L}(integer x); */",
            "/*@ logic ssize_t f{L}(integer x); */",
            "/*@ logic unsigned f(integer x); */",
            "/*@ logic unsigned zero = 0; */",
        ],
    )
    def test_forbidden_c_int_return_types_flagged(self, sig):
        tokens = tokenize_c_acsl(sig)
        errors = acsl_ast.find_unsound_acsl_keywords(tokens)
        assert any("forbidden C integer type in ACSL logic signature" in e for e in errors), (
            f"Failed for {sig}: {errors}"
        )

    @pytest.mark.parametrize(
        "sig",
        [
            "/*@ logic integer f{L}(integer x); */",
            "/*@ logic real g{L1, L2}(real x, real y); */",
            "/*@ logic boolean h{Here}(int *p); */",
            "/*@ logic integer k(integer a, integer b); */",
        ],
    )
    def test_sound_logic_signatures_pass(self, sig):
        tokens = tokenize_c_acsl(sig)
        errors = acsl_ast.find_unsound_acsl_keywords(tokens)
        assert errors == [], f"Unexpected errors for sound signature {sig}: {errors}"


# ===========================================================================
# 5. Stress-test tolerant tokenizing & AcslSyntaxError attributes
# ===========================================================================


class TestFunctionSliceTolerantTokenizing:
    """Stress-test function_slice._tokenize_tolerant with unclosed literals and comments."""

    def test_acsl_syntax_error_attributes_populated(self):
        """AcslSyntaxError must provide line, kind, and offset attributes."""
        with pytest.raises(AcslSyntaxError) as exc_info:
            tokenize_c_acsl('int a = 1;\nchar *s = "unclosed;')
        exc = exc_info.value
        assert exc.line == 2
        assert exc.kind == "string_literal"
        assert exc.offset == 21

        with pytest.raises(AcslSyntaxError) as exc_info_c:
            tokenize_c_acsl("/* unclosed comment")
        exc_c = exc_info_c.value
        assert exc_c.line == 1
        assert exc_c.kind == "c_block_comment"
        assert exc_c.offset == 0

        with pytest.raises(AcslSyntaxError) as exc_info_acsl:
            tokenize_c_acsl("int x;\n/*@ unclosed acsl")
        exc_acsl = exc_info_acsl.value
        assert exc_acsl.line == 2
        assert exc_acsl.kind == "acsl_block_comment"
        assert exc_acsl.offset == 7

    def test_tokenize_tolerant_recovers_unclosed_block_comment(self):
        """_tokenize_tolerant closes unclosed block comments by appending newline and closing marker."""
        bad = "int f() {\n  return 0;\n}\n/* unclosed at EOF"
        clean, toks = function_slice._tokenize_tolerant(bad)
        assert clean.endswith("\n*/")
        assert any(t.kind == "c_comment" for t in toks)
        assert any(t.text == "return" for t in toks)

    def test_tokenize_tolerant_recovers_multiple_bad_literals(self):
        """_tokenize_tolerant blanks up to 64 bad lines while keeping line numbers intact."""
        code = "int a = 1;\nchar *s1 = 'bad1;\nint b = 2;\nchar *s2 = \"bad2;\nint c = 3;\n"
        clean, toks = function_slice._tokenize_tolerant(code)
        tokens_text = [t.text for t in toks if t.kind == "c_token"]
        assert "a" in tokens_text
        assert "b" in tokens_text
        assert "c" in tokens_text
        # Line count remains unchanged
        assert clean.count("\n") == code.count("\n")
