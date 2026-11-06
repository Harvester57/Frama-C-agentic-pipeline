"""Tests for scripts/acsl_ast.py and M2 workspace_overlay.py (TDD: ACSL-only lexer, span splicer, agent overlay merge)."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

import workspace_overlay
from acsl_ast import (
    AcslSyntaxError,
    ScopeViolationError,
    locate_all_definition_spans,
    locate_all_prototype_spans,
    locate_function_span,
    splice_architect_header,
    splice_prover_changes,
    tokenize_c_acsl,
    verify_acsl_only,
)

BASELINE_C = """\
#include "parser.h"

/* Parse header magic */
int parse_magic(const uint8_t *buf, size_t len) {
    if (buf == NULL || len < 4) {
        return -1;
    }
    int acc = 0;
    for (size_t i = 0; i < 4; i++) {
        acc += buf[i];
    }
    return acc;
}

int parse_payload(const uint8_t *buf, size_t len, int *out) {
    if (buf == NULL || out == NULL) {
        return -1;
    }
    const char *literal = "/*@ not an acsl comment */";
    (void)literal;
    *out = (int)len;
    return 0;
}
"""

BASELINE_H = """\
#ifndef PARSER_H
#define PARSER_H

#include <stddef.h>
#include <stdint.h>

int parse_magic(const uint8_t *buf, size_t len);

int parse_payload(const uint8_t *buf, size_t len, int *out);

#endif /* PARSER_H */
"""


class TestVerifyAcslOnly:
    """Tests for C/ACSL lexical tokenization and annotation-only verification."""

    def test_verify_acsl_only_accepts_block_and_line_acsl(self) -> None:
        """Adding block/line ACSL contracts, loop invariants, ghost state, and predicates passes."""
        annotated = """\
#include "parser.h"

/*@ predicate valid_magic_len(integer n) = n >= 4; */
/*@ ghost int g_magic_checked = 0; */

/* Parse header magic */
/*@
  requires buf == \\null || \\valid_read(buf + (0 .. len - 1));
  assigns g_magic_checked;
  ensures \\result >= -1;
*/
int parse_magic(const uint8_t *buf, size_t len) {
    if (buf == NULL || len < 4) {
        return -1;
    }
    int acc = 0;
    /*@
      loop invariant 0 <= i <= 4;
      loop invariant 0 <= acc <= 4 * 255;
      loop assigns i, acc;
      loop variant 4 - i;
    */
    for (size_t i = 0; i < 4; i++) {
        //@ assert \\valid_read(buf + i);
        acc += buf[i];
    }
    /*@ ghost g_magic_checked = 1; */
    return acc;
}

int parse_payload(const uint8_t *buf, size_t len, int *out) {
    if (buf == NULL || out == NULL) {
        return -1;
    }
    const char *literal = "/*@ not an acsl comment */";
    (void)literal;
    *out = (int)len;
    return 0;
}
"""
        errors = verify_acsl_only(BASELINE_C, annotated, path="parser.c")
        assert errors == []

    @pytest.mark.parametrize(
        "mutator,expected_substring",
        [
            (lambda s: s.replace("i < 4", "i <= 4"), "non-ACSL token"),
            (lambda s: s.replace("return -1;", "return 0;"), "non-ACSL token"),
            (lambda s: '#include "extra.h"\n' + s, "non-ACSL token"),
            (lambda s: s + "\nstatic inline void helper(void) {}\n", "non-ACSL token"),
            (lambda s: s.replace("/* Parse header magic */", "/* Modified normal comment */"), "non-ACSL token"),
        ],
        ids=[
            "operator-change",
            "return-value-change",
            "added-include",
            "added-c-function",
            "modified-normal-c-comment",
        ],
    )
    def test_verify_acsl_only_rejects_c_modifications(
        self,
        mutator: Callable[[str], str],
        expected_substring: str,
    ) -> None:
        """Any modification to C tokens, preprocessor directives, or normal comments is rejected."""
        mutated = mutator(BASELINE_C)
        errors = verify_acsl_only(BASELINE_C, mutated, path="parser.c")
        assert len(errors) >= 1
        assert any(expected_substring in err for err in errors)

    def test_verify_acsl_only_preserves_strings_containing_acsl_markers(self) -> None:
        """String literals containing /*@ or //@ are treated as C tokens and cannot be altered."""
        mutated = BASELINE_C.replace("/*@ not an acsl comment */", "/*@ changed inside string */")
        errors = verify_acsl_only(BASELINE_C, mutated, path="parser.c")
        assert len(errors) >= 1
        assert "parser.c" in errors[0]

    def test_verify_acsl_only_rejects_unclosed_acsl_comment(self) -> None:
        """An unclosed /*@ comment raises AcslSyntaxError or returns a clear error."""
        broken = BASELINE_C + "\n/*@ requires x > 0;\n"
        with pytest.raises(AcslSyntaxError, match="unclosed"):
            tokenize_c_acsl(broken)
        errors = verify_acsl_only(BASELINE_C, broken, path="parser.c")
        assert len(errors) == 1
        assert "unclosed" in errors[0].lower()

    @pytest.mark.parametrize(
        "forbidden_acsl",
        [
            "/*@ admit x > 0; */",
            "/*@ axiomatic Foo { axiom bar: \\true; } */",
            "/*@ inductive is_sorted(int *a, integer n) { case empty: is_sorted(a, 0); } */",
            "/*@ logic int bad_sum(int x) = x + 1; */",
            "/*@ logic integer bad_param(size_t n) = n; */",
            "/*@ invariant 0 <= i <= n; */",
            "/*@ exits \x0calse; */",
            "/*@ requires \\false; */",
            "/*@ requires dead: 0; */",
            "/*@ loop invariant \\false; */",
            "/*@ behavior b: assumes \\false; */",
        ],
        ids=[
            "admit-clause",
            "axiom-declaration",
            "inductive-declaration",
            "logic-c-int-return-type",
            "logic-c-size-t-param-type",
            "statement-invariant-without-loop",
            "formfeed-escaped-false-in-acsl",
            "vacuous-requires-false",
            "vacuous-requires-zero",
            "vacuous-loop-invariant-false",
            "vacuous-assumes-false",
        ],
    )
    def test_verify_acsl_only_rejects_unsound_admit_or_axiom(self, forbidden_acsl: str) -> None:
        """Agent patches introducing admit, axiom, inductive, C integer types in logic, or bare invariant are flagged."""
        annotated = forbidden_acsl + "\n" + BASELINE_C
        errors = verify_acsl_only(BASELINE_C, annotated, path="parser.c")
        assert len(errors) >= 1
        assert any("unsound" in e.lower() or "forbidden" in e.lower() or "syntax hazard" in e.lower() for e in errors)

    def test_verify_acsl_only_rejects_empty_named_behaviors(self) -> None:
        """Frama-C 34+ forbids empty named behaviors (`behavior b: ;`) in function and statement
        contracts (fatal annot-error "unexpected token ';'"); the mechanical check flags them pre-splice."""
        from acsl_ast import find_empty_named_behaviors

        fn_level = "/*@ behavior b: ; */\n" + BASELINE_C
        errors = verify_acsl_only(BASELINE_C, fn_level, path="parser.c")
        assert any("empty named behavior" in e for e in errors)

        stmt_level = BASELINE_C.replace(
            "int parse_magic(const uint8_t *buf, size_t len) {",
            "int parse_magic(const uint8_t *buf, size_t len) {\n    /*@ behavior b: ; */",
        )
        errors = verify_acsl_only(BASELINE_C, stmt_level, path="parser.c")
        assert any("empty named behavior" in e for e in errors)

        # A non-empty named behavior passes both the splice check and the standalone scan.
        ok = "/*@ behavior b: assumes len >= 4; */\n" + BASELINE_C
        assert verify_acsl_only(BASELINE_C, ok, path="parser.c") == []
        assert find_empty_named_behaviors(tokenize_c_acsl(ok, path="parser.c"), path="parser.c") == []

    def test_verify_acsl_only_allows_valid_logic_integer_and_loop_invariant(self) -> None:
        """Valid logic integer functions (including pointer parameters) and loop/type/global invariants pass."""
        valid_acsl = (
            "/*@ logic integer good_fn(int *arr, integer n) = n + 1;\n    type invariant pos_int(int x) = x >= 0;\n*/\n"
        )
        annotated = valid_acsl + BASELINE_C
        errors = verify_acsl_only(BASELINE_C, annotated, path="parser.c")
        assert errors == []

    def test_templates_acsl_are_pure_acsl(self, repo_root: Path) -> None:
        """All Layer 4-6 .acsl template files contain zero executable C tokens or #includes, and external_stubs.h has zero ACSL hazards."""
        from acsl_ast import find_unsound_acsl_keywords

        acsl_dir = repo_root / "templates" / "acsl"
        for name in (
            "layer4_auth_state_machine.acsl",
            "layer5_output_sanitization.acsl",
            "layer6_zeroization_and_taint.acsl",
        ):
            text = (acsl_dir / name).read_text(encoding="utf-8")
            tokens = tokenize_c_acsl(text)
            c_tokens = [t for t in tokens if t.kind not in ("whitespace", "acsl_block", "acsl_line", "c_comment")]
            assert c_tokens == [], f"{name} contains non-ACSL C tokens: {c_tokens[:5]}"
            assert find_unsound_acsl_keywords(tokens, path=name) == []

        stubs_text = (acsl_dir / "external_stubs.h").read_text(encoding="utf-8")
        stub_tokens = tokenize_c_acsl(stubs_text)
        assert find_unsound_acsl_keywords(stub_tokens, path="external_stubs.h") == []

        from build_callgraph_dag import extract_functions_from_code
        from framac_common import augment_framac_cppflags

        fc_stubs_dir = repo_root / "templates" / "fc_stubs"
        for stub_path in sorted(fc_stubs_dir.rglob("*.h")):
            st_text = stub_path.read_text(encoding="utf-8")
            st_tokens = tokenize_c_acsl(st_text, path=str(stub_path))
            assert find_unsound_acsl_keywords(st_tokens, path=str(stub_path)) == []
            # Ensure fc_stubs headers contain only declarations/types, never C function bodies
            assert extract_functions_from_code(st_text, path=str(stub_path)) == []

        aug = augment_framac_cppflags("-Iworkspace/work/include")
        assert "templates/fc_stubs" in aug
        assert "-include " in aug and "fc_compat_types.h" in aug


class TestSpanLocationAndSplicing:
    """Tests for function span extraction and same-wave parallel prover splicing."""

    def test_locate_function_span_in_c_and_h(self) -> None:
        """Locates exact function definition span in .c and prototype span in .h."""
        c_span = locate_function_span(BASELINE_C, "parse_magic", is_header=False)
        assert c_span is not None
        assert c_span.text.startswith("int parse_magic")
        assert c_span.text.endswith("}")

        h_span = locate_function_span(BASELINE_H, "parse_magic", is_header=True)
        assert h_span is not None
        assert h_span.text == "int parse_magic(const uint8_t *buf, size_t len);"

    def test_prover_scope_rejects_editing_other_function(self) -> None:
        """A prover assigned to parse_magic that annotates parse_payload is rejected."""
        wrong_scope = BASELINE_C.replace(
            "int parse_payload(",
            "/*@ requires len > 0; */\nint parse_payload(",
        )
        with pytest.raises(ScopeViolationError, match="outside assigned function 'parse_magic'"):
            splice_prover_changes(
                base_work_text=BASELINE_C,
                agent_work_text=wrong_scope,
                current_work_text=BASELINE_C,
                function_name="parse_magic",
                is_header=False,
                path="parser.c",
            )

    def test_same_wave_parallel_provers_merge_cleanly(self, tmp_path: Path) -> None:
        """Two provers starting from the same baseline annotate different functions in the same .c and .h files."""
        target = tmp_path / "target"
        target.mkdir()
        (target / "parser.c").write_text(BASELINE_C, encoding="utf-8")
        (target / "parser.h").write_text(BASELINE_H, encoding="utf-8")

        run_dir = tmp_path / "run"
        overlay = run_dir / "workspace"
        workspace_overlay.init_overlay(target, overlay)

        # Initialize two concurrent provers from the same initial workspace/work/ state
        workspace_overlay.init_agent_overlay(run_dir, "prover-magic", overlay)
        workspace_overlay.init_agent_overlay(run_dir, "prover-payload", overlay)

        # Prover 1 annotates parse_magic in its scratch copy (adding 12 lines of ACSL)
        p1_c = run_dir / "agents" / "prover-magic" / "scratch" / "work" / "parser.c"
        p1_h = run_dir / "agents" / "prover-magic" / "scratch" / "work" / "parser.h"
        p1_c.write_text(
            BASELINE_C.replace(
                "    for (size_t i = 0; i < 4; i++) {",
                "    /*@\n"
                "      loop invariant 0 <= i <= 4;\n"
                "      loop invariant 0 <= acc <= 1020;\n"
                "      loop assigns i, acc;\n"
                "      loop variant 4 - i;\n"
                "    */\n"
                "    for (size_t i = 0; i < 4; i++) {",
            ),
            encoding="utf-8",
        )
        p1_h.write_text(
            BASELINE_H.replace(
                "int parse_magic(const uint8_t *buf, size_t len);",
                "/*@\n"
                "  requires buf == \\null || \\valid_read(buf + (0 .. len - 1));\n"
                "  assigns \\nothing;\n"
                "*/\n"
                "int parse_magic(const uint8_t *buf, size_t len);",
            ),
            encoding="utf-8",
        )

        # Prover 2 annotates parse_payload in its scratch copy (which still has unshifted line numbers!)
        p2_c = run_dir / "agents" / "prover-payload" / "scratch" / "work" / "parser.c"
        p2_h = run_dir / "agents" / "prover-payload" / "scratch" / "work" / "parser.h"
        p2_c.write_text(
            BASELINE_C.replace(
                "    *out = (int)len;",
                "    //@ assert out != \\null;\n    *out = (int)len;",
            ),
            encoding="utf-8",
        )
        p2_h.write_text(
            BASELINE_H.replace(
                "int parse_payload(const uint8_t *buf, size_t len, int *out);",
                "/*@\n"
                "  requires out == \\null || \\valid(out);\n"
                "  assigns *out;\n"
                "*/\n"
                "int parse_payload(const uint8_t *buf, size_t len, int *out);",
            ),
            encoding="utf-8",
        )

        # Parent serially merges Prover 1 then Prover 2
        res1 = workspace_overlay.merge_agent_overlay(
            run_dir=run_dir,
            agent_id="prover-magic",
            role="prover",
            overlay_dir=overlay,
            c_file="parser.c",
            function="parse_magic",
            header_file="parser.h",
            skip_reverify=True,
        )
        assert res1["ok"] is True
        assert (run_dir / res1["patch_artifact"]).is_file()

        res2 = workspace_overlay.merge_agent_overlay(
            run_dir=run_dir,
            agent_id="prover-payload",
            role="prover",
            overlay_dir=overlay,
            c_file="parser.c",
            function="parse_payload",
            header_file="parser.h",
            skip_reverify=True,
        )
        assert res2["ok"] is True
        assert (run_dir / res2["patch_artifact"]).is_file()

        # Verify both functions' annotations are present in workspace/work/ and pass ACSL-only check
        merged_c = (overlay / "work" / "parser.c").read_text(encoding="utf-8")
        merged_h = (overlay / "work" / "parser.h").read_text(encoding="utf-8")
        assert "loop invariant 0 <= i <= 4;" in merged_c
        assert "//@ assert out != \\null;" in merged_c
        assert "\\valid_read(buf + (0 .. len - 1))" in merged_h
        assert "\\valid(out)" in merged_h

        check_res = workspace_overlay.check_acsl_only(overlay)
        assert check_res["ok"] is True
        assert check_res["errors"] == []

    def test_merge_agent_rolls_back_on_verification_failure(self, tmp_path: Path) -> None:
        """If the parent verification callback fails after splicing, workspace/work/ is rolled back."""
        target = tmp_path / "target"
        target.mkdir()
        (target / "parser.c").write_text(BASELINE_C, encoding="utf-8")
        (target / "parser.h").write_text(BASELINE_H, encoding="utf-8")

        run_dir = tmp_path / "run"
        overlay = run_dir / "workspace"
        workspace_overlay.init_overlay(target, overlay)
        workspace_overlay.init_agent_overlay(run_dir, "prover-fail", overlay)

        p_c = run_dir / "agents" / "prover-fail" / "scratch" / "work" / "parser.c"
        p_c.write_text(
            BASELINE_C.replace(
                "    return acc;",
                "    //@ assert acc > 99999;\n    return acc;",
            ),
            encoding="utf-8",
        )

        res = workspace_overlay.merge_agent_overlay(
            run_dir=run_dir,
            agent_id="prover-fail",
            role="prover",
            overlay_dir=overlay,
            c_file="parser.c",
            function="parse_magic",
            header_file="parser.h",
            skip_reverify=False,
            verify_hook=lambda: (False, "guardrail rejected overconstrained assert"),
        )
        assert res["ok"] is False
        assert res["rolled_back"] is True
        assert "guardrail rejected" in res["reason"]
        # Confirm workspace/work/parser.c was restored to baseline
        assert (overlay / "work" / "parser.c").read_text(encoding="utf-8") == BASELINE_C

    def test_verify_acsl_only_preprocessor_guard_hint(self) -> None:
        """Adding #ifndef/#define/#endif guards to a header gives an explicit hint about automatic deduplication."""
        guarded_h = (
            "#ifndefSHARED_ACSL_GUARD\n#define SHARED_ACSL_GUARD\n"
            "/*@ predicate foo(integer x) = x > 0; */\n"
            "#endif\n" + BASELINE_H
        )
        errors = verify_acsl_only(BASELINE_H, guarded_h, path="parser.h")
        assert len(errors) >= 1
        assert any("deduplicated automatically by merge-agent" in e for e in errors)

    def test_dedup_acsl_declarations_preserves_forall_and_comments(self) -> None:
        """
        Multi-line quantified predicates (\\forall integer k; ...) and // comments containing
        'logic'/'predicate' keywords are parsed and deduplicated without truncation.
        """
        from acsl_ast import dedup_acsl_declarations, extract_top_level_acsl_declarations

        annotated_h = """\
#ifndef PARSER_H
#define PARSER_H

#include <stddef.h>
#include <stdint.h>

/*@
  // Layer 5 & 6 shared logic predicates: do not split on keywords in comments!
  predicate no_crlf_or_nul(char *buf, integer len) =
    \\forall integer k; 0 <= k < len ==>
      buf[k] != '\\r' && buf[k] != '\\n' && buf[k] != '\\0';

  predicate buffer_is_zeroed(uint8_t *buf, integer len) =
    \\forall integer k; 0 <= k < len ==> buf[k] == 0;

  logic integer c_strlen(char *s) =
    (s[0] == '\\0') ? 0 : 1 + c_strlen(s + 1);

  predicate unique_magic_bound(integer n) =
    \\forall integer j; 0 <= j < n ==> j >= 0;
*/

/*@
  requires buf == \\null || \\valid_read(buf + (0 .. len - 1));
  assigns \\nothing;
*/
int parse_magic(const uint8_t *buf, size_t len);

int parse_payload(const uint8_t *buf, size_t len, int *out);

#endif /* PARSER_H */
"""
        decls = extract_top_level_acsl_declarations(annotated_h)
        assert [d["name"] for d in decls] == [
            "no_crlf_or_nul",
            "buffer_is_zeroed",
            "c_strlen",
            "unique_magic_bound",
        ]

        deduped_h, removed = dedup_acsl_declarations(
            annotated_h,
            existing_names={"no_crlf_or_nul", "buffer_is_zeroed", "c_strlen"},
            baseline_text=BASELINE_H,
        )
        assert removed == ["no_crlf_or_nul", "buffer_is_zeroed", "c_strlen"]
        assert "no_crlf_or_nul" not in deduped_h
        assert "buffer_is_zeroed" not in deduped_h
        assert "c_strlen" not in deduped_h
        assert "predicate unique_magic_bound(integer n) =" in deduped_h
        assert "\\forall integer j; 0 <= j < n ==> j >= 0;" in deduped_h
        assert "requires buf == \\null || \\valid_read(buf + (0 .. len - 1));" in deduped_h
        assert verify_acsl_only(BASELINE_H, deduped_h, path="parser.h") == []

    def test_architect_multi_header_merge_deduplicates_shared_predicates(self, tmp_path: Path) -> None:
        """Merging two architect headers that both define no_crlf_or_nul automatically deduplicates the second."""
        target = tmp_path / "target"
        target.mkdir()
        h2_base = "#ifndef OTHER_H\n#define OTHER_H\nint other_fn(char *s);\n#endif\n"
        (target / "parser.c").write_text(BASELINE_C, encoding="utf-8")
        (target / "parser.h").write_text(BASELINE_H, encoding="utf-8")
        (target / "other.h").write_text(h2_base, encoding="utf-8")

        run_dir = tmp_path / "run"
        overlay = run_dir / "workspace"
        workspace_overlay.init_overlay(target, overlay)
        workspace_overlay.init_agent_overlay(run_dir, "arch-1", overlay)
        workspace_overlay.init_agent_overlay(run_dir, "arch-2", overlay)

        shared_pred = (
            "/*@\n"
            "  predicate no_crlf_or_nul(char *buf, integer len) =\n"
            "    \\forall integer k; 0 <= k < len ==> buf[k] != '\\r' && buf[k] != '\\n' && buf[k] != '\\0';\n"
            "*/\n"
        )
        (run_dir / "agents/arch-1/scratch/work/parser.h").write_text(
            BASELINE_H.replace("int parse_magic", shared_pred + "int parse_magic"),
            encoding="utf-8",
        )
        (run_dir / "agents/arch-2/scratch/work/other.h").write_text(
            h2_base.replace("int other_fn", shared_pred + "/*@ assigns \\nothing; */\nint other_fn"),
            encoding="utf-8",
        )

        r1 = workspace_overlay.merge_agent_overlay(
            run_dir=run_dir,
            agent_id="arch-1",
            role="architect",
            overlay_dir=overlay,
            header_file="parser.h",
            skip_reverify=True,
        )
        assert r1["ok"] is True
        assert r1["deduplicated_declarations"] == []

        r2 = workspace_overlay.merge_agent_overlay(
            run_dir=run_dir,
            agent_id="arch-2",
            role="architect",
            overlay_dir=overlay,
            header_file="other.h",
            skip_reverify=True,
        )
        assert r2["ok"] is True
        assert r2["deduplicated_declarations"] == ["no_crlf_or_nul"]
        assert "no_crlf_or_nul" in (overlay / "work/parser.h").read_text(encoding="utf-8")
        assert "no_crlf_or_nul" not in (overlay / "work/other.h").read_text(encoding="utf-8")
        assert "assigns \\nothing;" in (overlay / "work/other.h").read_text(encoding="utf-8")

    def test_prover_auto_sibling_header_and_source_path_normalization(self, tmp_path: Path) -> None:
        """
        1. When a prover edits both parser.c and parser.h and --header is omitted, parser.h is auto-inferred.
        2. _resolve_overlay_source strips doubled workspace/work/ prefixes and resolves workspace/stubs/.
        """
        target = tmp_path / "target"
        target.mkdir()
        (target / "parser.c").write_text(BASELINE_C, encoding="utf-8")
        (target / "parser.h").write_text(BASELINE_H, encoding="utf-8")

        run_dir = tmp_path / "run"
        overlay = run_dir / "workspace"
        workspace_overlay.init_overlay(target, overlay)
        stubs_dir = overlay / "stubs"
        stubs_dir.mkdir(parents=True)
        stub_c = stubs_dir / "ext_stubs.c"
        stub_c.write_text("int stub_fn(void) { return 0; }\n", encoding="utf-8")

        # Verify _resolve_overlay_source path normalization
        work_dir = overlay / "work"
        assert workspace_overlay._resolve_overlay_source(run_dir, work_dir, "workspace/work/parser.c") == str(
            work_dir / "parser.c"
        )
        assert workspace_overlay._resolve_overlay_source(run_dir, work_dir, "workspace/stubs/ext_stubs.c") == str(
            stub_c
        )

        workspace_overlay.init_agent_overlay(run_dir, "prover-auto-h", overlay)
        (run_dir / "agents/prover-auto-h/scratch/work/parser.c").write_text(
            BASELINE_C.replace("    return acc;", "    //@ assert acc >= 0;\n    return acc;"),
            encoding="utf-8",
        )
        (run_dir / "agents/prover-auto-h/scratch/work/parser.h").write_text(
            BASELINE_H.replace(
                "int parse_magic(const uint8_t *buf, size_t len);",
                "/*@ assigns \\nothing; */\nint parse_magic(const uint8_t *buf, size_t len);",
            ),
            encoding="utf-8",
        )

        # Omit header_file -> should automatically infer parser.h
        res = workspace_overlay.merge_agent_overlay(
            run_dir=run_dir,
            agent_id="prover-auto-h",
            role="prover",
            overlay_dir=overlay,
            c_file="parser.c",
            function="parse_magic",
            header_file=None,
            skip_reverify=True,
        )
        assert res["ok"] is True
        assert set(res["modified_files"]) == {"parser.c", "parser.h"}
        assert "assigns \\nothing;" in (work_dir / "parser.h").read_text(encoding="utf-8")

    def test_merge_batch_happy_path_and_bisect_on_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """
        merge_agent_batch merges multiple agents in one pass when reverify succeeds, and
        automatically bisects when batch reverify fails so good agents stay merged.
        """
        target = tmp_path / "target"
        target.mkdir()
        (target / "parser.c").write_text(BASELINE_C, encoding="utf-8")
        (target / "parser.h").write_text(BASELINE_H, encoding="utf-8")

        run_dir = tmp_path / "run"
        overlay = run_dir / "workspace"
        workspace_overlay.init_overlay(target, overlay)
        workspace_overlay.init_agent_overlay(run_dir, "prover-1", overlay)
        workspace_overlay.init_agent_overlay(run_dir, "prover-2", overlay)

        (run_dir / "agents/prover-1/scratch/work/parser.c").write_text(
            BASELINE_C.replace("    return acc;", "    //@ assert acc >= 0;\n    return acc;"),
            encoding="utf-8",
        )
        (run_dir / "agents/prover-2/scratch/work/parser.c").write_text(
            BASELINE_C.replace("    *out = (int)len;", "    //@ assert out != \\null;\n    *out = (int)len;"),
            encoding="utf-8",
        )

        specs = [
            {"agent_id": "prover-1", "role": "prover", "file": "parser.c", "function": "parse_magic"},
            {"agent_id": "prover-2", "role": "prover", "file": "parser.c", "function": "parse_payload"},
        ]
        batch_ok = workspace_overlay.merge_agent_batch(
            run_dir=run_dir,
            entries=specs,
            overlay_dir=overlay,
            skip_reverify=True,
        )
        assert batch_ok["ok"] is True
        assert batch_ok["bisected"] is False
        assert len(batch_ok["merged"]) == 2

        # Now reset workspace/work/ to baseline and simulate prover-2 failing verification during batch merge
        (overlay / "work/parser.c").write_text(BASELINE_C, encoding="utf-8")

        def fake_reverify(
            run_dir, overlay_dir, agent_id, role, c_file, function, module, sources, cppflags, ldflags="", wp_par=None
        ):
            assert wp_par is not None and wp_par >= 1  # parallel re-checks share the job budget
            if function == "parse_payload":
                return False, "parse_payload WP failed"
            return True, "ok"

        monkeypatch.setattr(workspace_overlay, "_run_parent_reverify", fake_reverify)
        batch_bisect = workspace_overlay.merge_agent_batch(
            run_dir=run_dir,
            entries=specs,
            overlay_dir=overlay,
            skip_reverify=False,
        )
        assert batch_bisect["ok"] is False
        assert batch_bisect["bisected"] is True
        assert len(batch_bisect["merged"]) == 1
        assert len(batch_bisect["failed"]) == 1
        merged_c = (overlay / "work/parser.c").read_text(encoding="utf-8")
        assert "//@ assert acc >= 0;" in merged_c
        assert "//@ assert out != \\null;" not in merged_c
        assert (run_dir / "agents/prover-1/artifacts/parse_magic.patch").is_file()
        assert not (run_dir / "agents/prover-2/artifacts/parse_payload.patch").exists()

    def test_overloaded_acsl_predicates_preserved_across_headers(self, tmp_path: Path) -> None:
        """
        Overloaded ACSL predicates/logic functions with the same name and different parameter
        arities (e.g. valid_slice/2 vs valid_slice/3) are preserved, whereas identical-arity
        redeclarations are deduplicated.
        """
        target = tmp_path / "target"
        target.mkdir()
        (target / "parser.c").write_text(BASELINE_C, encoding="utf-8")
        (target / "parser.h").write_text(BASELINE_H, encoding="utf-8")
        (target / "other.h").write_text(
            "#ifndef OTHER_H\n#define OTHER_H\nint other_fn(int x);\n#endif\n", encoding="utf-8"
        )

        run_dir = tmp_path / "run"
        overlay = run_dir / "workspace"
        workspace_overlay.init_overlay(target, overlay)
        workspace_overlay.init_agent_overlay(run_dir, "arch-overload-1", overlay)
        workspace_overlay.init_agent_overlay(run_dir, "arch-overload-2", overlay)

        pred_arity_2 = "/*@ predicate valid_slice(char *p, integer n) = \\valid(p + (0 .. n - 1)); */\n"
        pred_arity_3 = "/*@ predicate valid_slice(char *p, integer lo, integer hi) = \\valid(p + (lo .. hi)); */\n"

        (run_dir / "agents/arch-overload-1/scratch/work/parser.h").write_text(
            BASELINE_H.replace("#define PARSER_H\n", "#define PARSER_H\n" + pred_arity_2),
            encoding="utf-8",
        )
        (run_dir / "agents/arch-overload-2/scratch/work/other.h").write_text(
            "#ifndef OTHER_H\n#define OTHER_H\n"
            + pred_arity_2
            + pred_arity_3
            + "/*@ assigns \\nothing; */\nint other_fn(int x);\n#endif\n",
            encoding="utf-8",
        )

        r1 = workspace_overlay.merge_agent_overlay(
            run_dir=run_dir,
            agent_id="arch-overload-1",
            role="architect",
            overlay_dir=overlay,
            header_file="parser.h",
            skip_reverify=True,
        )
        assert r1["ok"] is True

        r2 = workspace_overlay.merge_agent_overlay(
            run_dir=run_dir,
            agent_id="arch-overload-2",
            role="architect",
            overlay_dir=overlay,
            header_file="other.h",
            skip_reverify=True,
        )
        assert r2["ok"] is True
        assert r2["deduplicated_declarations"] == ["valid_slice"]
        other_text = (overlay / "work/other.h").read_text(encoding="utf-8")
        # Arity-2 duplicate was stripped, but arity-3 overload was preserved!
        assert "integer lo, integer hi" in other_text
        assert "integer n)" not in other_text

    def test_merge_batch_shared_header_auto_infer_and_harness_cppflags(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """
        When two provers in a batch both edit parser.c and also add ACSL to the shared sibling
        parser.h without explicit --header, merge_agent_batch merges both .c and .h changes cleanly
        and inherits cppflags from workspace/harnesses/harness_<mod>.json when --cppflags is omitted.
        """
        target = tmp_path / "target"
        target.mkdir()
        (target / "parser.c").write_text(BASELINE_C, encoding="utf-8")
        (target / "parser.h").write_text(BASELINE_H, encoding="utf-8")

        run_dir = tmp_path / "run"
        overlay = run_dir / "workspace"
        workspace_overlay.init_overlay(target, overlay)
        (overlay / "harnesses").mkdir(parents=True, exist_ok=True)
        (overlay / "harnesses/harness_parser.json").write_text(
            json.dumps(
                {
                    "module": "parser",
                    "sources": ["workspace/work/parser.c"],
                    "header": "parser.h",
                    "cppflags": "-Iworkspace/work -DCUSTOM_FLAG=1",
                    "ldflags": "-lm",
                }
            ),
            encoding="utf-8",
        )

        workspace_overlay.init_agent_overlay(run_dir, "prover-h1", overlay)
        workspace_overlay.init_agent_overlay(run_dir, "prover-h2", overlay)

        (run_dir / "agents/prover-h1/scratch/work/parser.c").write_text(
            BASELINE_C.replace("    return acc;", "    //@ assert acc >= 0;\n    return acc;"),
            encoding="utf-8",
        )
        (run_dir / "agents/prover-h1/scratch/work/parser.h").write_text(
            BASELINE_H.replace(
                "int parse_magic(const uint8_t *buf, size_t len);",
                "/*@ assigns \\nothing; */\nint parse_magic(const uint8_t *buf, size_t len);",
            ),
            encoding="utf-8",
        )

        (run_dir / "agents/prover-h2/scratch/work/parser.c").write_text(
            BASELINE_C.replace("    *out = (int)len;", "    //@ assert out != \\null;\n    *out = (int)len;"),
            encoding="utf-8",
        )
        (run_dir / "agents/prover-h2/scratch/work/parser.h").write_text(
            BASELINE_H.replace(
                "int parse_payload(const uint8_t *buf, size_t len, int *out);",
                "/*@ requires \\valid(out); */\nint parse_payload(const uint8_t *buf, size_t len, int *out);",
            ),
            encoding="utf-8",
        )

        seen_cppflags: list[str] = []

        def fake_reverify(
            run_dir, agent_id, role, overlay_dir, c_file, function, module, sources, cppflags, ldflags="", wp_par=None
        ):
            seen_cppflags.append(cppflags)
            return True, "ok"

        monkeypatch.setattr(workspace_overlay, "_run_parent_reverify", fake_reverify)
        batch_res = workspace_overlay.merge_agent_batch(
            run_dir=run_dir,
            entries=[
                {"agent_id": "prover-h1", "role": "prover", "file": "parser.c", "function": "parse_magic"},
                {"agent_id": "prover-h2", "role": "prover", "file": "parser.c", "function": "parse_payload"},
            ],
            overlay_dir=overlay,
            default_module="parser",
            skip_reverify=False,
        )
        assert batch_res["ok"] is True
        assert "-Iworkspace/work -DCUSTOM_FLAG=1" in seen_cppflags
        merged_h = (overlay / "work/parser.h").read_text(encoding="utf-8")
        assert "assigns \\nothing;" in merged_h
        assert "requires \\valid(out);" in merged_h

    def test_prover_merge_resolves_non_sibling_header_from_harness_sidecar(self, tmp_path: Path) -> None:
        """
        When a module has multiple .c files sharing a module header whose stem differs from the
        .c file stem (e.g. src/snmp/ber.c + include/snmp.h recorded in harness_snmp.json),
        merge_agent_overlay and merge_agent_batch automatically splice the prover's prototype
        contract edits in include/snmp.h without requiring an explicit --header argument.
        """
        target = tmp_path / "target"
        (target / "src/snmp").mkdir(parents=True)
        (target / "include").mkdir(parents=True)
        (target / "src/snmp/ber.c").write_text(BASELINE_C, encoding="utf-8")
        (target / "include/snmp.h").write_text(BASELINE_H, encoding="utf-8")

        run_dir = tmp_path / "run"
        overlay = run_dir / "workspace"
        workspace_overlay.init_overlay(target, overlay)
        (overlay / "harnesses").mkdir(parents=True, exist_ok=True)
        (overlay / "harnesses/harness_snmp.json").write_text(
            json.dumps(
                {
                    "module": "snmp",
                    "sources": ["workspace/work/src/snmp/ber.c"],
                    "header": "include/snmp.h",
                    "cppflags": "-Iworkspace/work/include",
                }
            ),
            encoding="utf-8",
        )

        workspace_overlay.init_agent_overlay(run_dir, "prover-ber", overlay)
        (run_dir / "agents/prover-ber/scratch/work/src/snmp/ber.c").write_text(
            BASELINE_C.replace("    return acc;", "    //@ assert acc >= 0;\n    return acc;"),
            encoding="utf-8",
        )
        (run_dir / "agents/prover-ber/scratch/work/include/snmp.h").write_text(
            BASELINE_H.replace(
                "int parse_magic(const uint8_t *buf, size_t len);",
                "/*@ assigns \\nothing; */\nint parse_magic(const uint8_t *buf, size_t len);",
            ),
            encoding="utf-8",
        )

        res = workspace_overlay.merge_agent_overlay(
            run_dir=run_dir,
            agent_id="prover-ber",
            role="prover",
            overlay_dir=overlay,
            c_file="src/snmp/ber.c",
            function="parse_magic",
            module="snmp",
            skip_reverify=True,
        )
        assert res["ok"] is True
        assert set(res["modified_files"]) == {"src/snmp/ber.c", "include/snmp.h"}
        assert "assigns \\nothing;" in (overlay / "work/include/snmp.h").read_text(encoding="utf-8")

    def test_check_acsl_only_accepts_agent_scratch_root(self, tmp_path: Path) -> None:
        """Passing --overlay agents/<id>/scratch compares scratch/base vs scratch/work instead of failing on base/."""
        target = tmp_path / "target"
        target.mkdir()
        (target / "parser.c").write_text(BASELINE_C, encoding="utf-8")
        run_dir = tmp_path / "run"
        overlay = run_dir / "workspace"
        workspace_overlay.init_overlay(target, overlay)
        workspace_overlay.init_agent_overlay(run_dir, "prover-1", overlay)

        scratch = run_dir / "agents/prover-1/scratch"
        (scratch / "work/parser.c").write_text(
            BASELINE_C.replace("    return acc;", "    //@ assert acc >= 0;\n    return acc;"),
            encoding="utf-8",
        )
        res = workspace_overlay.check_acsl_only(scratch)
        assert res["ok"] is True and res["errors"] == []


class TestTolerantArchitectHeaderMerge:
    """Tests for Milestone M1: Tolerant Header Merging (acsl_ast.splice_architect_header)."""

    def test_locate_all_prototype_spans_and_predicate_separation(self) -> None:
        """locate_all_prototype_spans finds all prototypes and does not absorb top-level predicates."""
        spans = locate_all_prototype_spans(BASELINE_H, path="parser.h")
        assert [s.function for s in spans] == ["parse_magic", "parse_payload"]
        assert spans[0].text == "int parse_magic(const uint8_t *buf, size_t len);"
        assert spans[1].text == "int parse_payload(const uint8_t *buf, size_t len, int *out);"

        # Preceding predicate must not be swallowed into parse_magic span
        src_with_pred = (
            "/*@ predicate valid_buf(char *b) = b != \\null; */\nint parse_magic(const uint8_t *buf, size_t len);\n"
        )
        spans_pred = locate_all_prototype_spans(src_with_pred, path="test.h")
        assert len(spans_pred) == 1
        assert spans_pred[0].function == "parse_magic"
        assert "predicate valid_buf" not in spans_pred[0].text
        assert spans_pred[0].text == "int parse_magic(const uint8_t *buf, size_t len);"

        fn_span = locate_function_span(src_with_pred, "parse_magic", is_header=True)
        assert fn_span is not None
        assert "predicate valid_buf" not in fn_span.text

    def test_splice_architect_header_fast_paths(self) -> None:
        """Fast paths: returns agent when current == base; returns current when agent == base or agent == current."""
        base_h = BASELINE_H
        annotated_magic = base_h.replace(
            "int parse_magic(const uint8_t *buf, size_t len);",
            "/*@ assigns \\nothing; */\nint parse_magic(const uint8_t *buf, size_t len);",
        )
        annotated_payload = base_h.replace(
            "int parse_payload(const uint8_t *buf, size_t len, int *out);",
            "/*@ requires out == \\null || \\valid(out); */\nint parse_payload(const uint8_t *buf, size_t len, int *out);",
        )

        # 1. current_text == base_text -> returns agent_text
        res1 = splice_architect_header(base_h, annotated_magic, base_h, path="parser.h")
        assert res1 == annotated_magic

        # 2. agent_text == base_text -> returns current_text
        res2 = splice_architect_header(base_h, base_h, annotated_payload, path="parser.h")
        assert res2 == annotated_payload

        # 3. agent_text == current_text -> returns current_text
        res3 = splice_architect_header(base_h, annotated_magic, annotated_magic, path="parser.h")
        assert res3 == annotated_magic

    def test_splice_architect_header_disjoint_prototypes(self) -> None:
        """Disjoint prototype modifications by architect and concurrent agent succeed and preserve C tokens."""
        base_h = BASELINE_H
        # Architect annotates parse_magic
        agent_h = base_h.replace(
            "int parse_magic(const uint8_t *buf, size_t len);",
            "/*@\n"
            "  requires buf == \\null || \\valid_read(buf + (0 .. len - 1));\n"
            "  assigns \\nothing;\n"
            "*/\n"
            "int parse_magic(const uint8_t *buf, size_t len);",
        )
        # Concurrent agent annotated parse_payload
        curr_h = base_h.replace(
            "int parse_payload(const uint8_t *buf, size_t len, int *out);",
            "/*@\n"
            "  requires out == \\null || \\valid(out);\n"
            "  assigns *out;\n"
            "*/\n"
            "int parse_payload(const uint8_t *buf, size_t len, int *out);",
        )

        spliced = splice_architect_header(base_h, agent_h, curr_h, path="parser.h")
        assert "\\valid_read(buf + (0 .. len - 1))" in spliced
        assert "\\valid(out)" in spliced
        assert "assigns \\nothing;" in spliced
        assert "assigns *out;" in spliced
        # Non-ACSL tokens match baseline identically
        assert verify_acsl_only(base_h, spliced, path="parser.h") == []

    def test_splice_architect_header_identical_concurrent_contract(self) -> None:
        """Identical contract added by both architect and concurrent prover succeeds without conflict."""
        base_h = BASELINE_H
        annotated_magic = base_h.replace(
            "int parse_magic(const uint8_t *buf, size_t len);",
            "/*@ requires len >= 4; assigns \\nothing; */\nint parse_magic(const uint8_t *buf, size_t len);",
        )
        spliced = splice_architect_header(base_h, annotated_magic, annotated_magic, path="parser.h")
        assert "requires len >= 4;" in spliced
        assert spliced.count("requires len >= 4;") == 1
        assert verify_acsl_only(base_h, spliced, path="parser.h") == []

        # Also test with whitespace differences: normalized contracts match
        agent_h = base_h.replace(
            "int parse_magic(const uint8_t *buf, size_t len);",
            "/*@\n  requires len >= 4;\n  assigns \\nothing;\n*/\nint parse_magic(const uint8_t *buf, size_t len);",
        )
        curr_h = base_h.replace(
            "int parse_magic(const uint8_t *buf, size_t len);",
            "/*@ requires len >= 4; assigns \\nothing; */\nint parse_magic(const uint8_t *buf, size_t len);",
        )
        spliced2 = splice_architect_header(base_h, agent_h, curr_h, path="parser.h")
        assert "requires len >= 4;" in spliced2
        assert verify_acsl_only(base_h, spliced2, path="parser.h") == []

    def test_splice_architect_header_conflicting_prototype_contract(self) -> None:
        """Conflicting contracts on the same prototype raise ScopeViolationError."""
        base_h = BASELINE_H
        agent_h = base_h.replace(
            "int parse_magic(const uint8_t *buf, size_t len);",
            "/*@ requires len >= 4; assigns \\nothing; */\nint parse_magic(const uint8_t *buf, size_t len);",
        )
        curr_h = base_h.replace(
            "int parse_magic(const uint8_t *buf, size_t len);",
            "/*@ requires len >= 8; assigns \\nothing; */\nint parse_magic(const uint8_t *buf, size_t len);",
        )

        with pytest.raises(
            ScopeViolationError,
            match=r"conflicting concurrent modification to prototype contract of 'parse_magic'",
        ):
            splice_architect_header(base_h, agent_h, curr_h, path="parser.h")

    def test_splice_architect_header_predicates_disjoint_and_dedup(self) -> None:
        """Disjoint predicates merge into spliced text and identical predicates deduplicate cleanly."""
        base_h = BASELINE_H
        shared_p = "/*@ predicate non_null(char *p) = p != \\null; */\n"
        p1 = "/*@ predicate valid_magic_len(integer n) = n >= 4; */\n"
        p2 = "/*@ predicate valid_payload_len(integer n) = n > 0; */\n"

        # Architect adds P1 and shared_p
        agent_h = base_h.replace("#define PARSER_H\n", f"#define PARSER_H\n\n{shared_p}{p1}")
        # Concurrent agent added P2 and shared_p
        curr_h = base_h.replace("#define PARSER_H\n", f"#define PARSER_H\n\n{shared_p}{p2}")

        spliced = splice_architect_header(base_h, agent_h, curr_h, path="parser.h")
        assert "valid_magic_len" in spliced
        assert "valid_payload_len" in spliced
        assert "non_null" in spliced
        # Deduplication ensures non_null appears exactly once
        assert spliced.count("predicate non_null") == 1
        assert verify_acsl_only(base_h, spliced, path="parser.h") == []

    def test_splice_architect_header_conflicting_predicate_declaration(self) -> None:
        """Conflicting predicate declarations with the same name/profile raise ScopeViolationError."""
        base_h = BASELINE_H
        p_conflict_agent = "/*@ predicate check_magic(integer n) = n >= 4; */\n"
        p_conflict_curr = "/*@ predicate check_magic(integer n) = n >= 8; */\n"
        agent_h_conf = base_h.replace("#define PARSER_H\n", f"#define PARSER_H\n\n{p_conflict_agent}")
        curr_h_conf = base_h.replace("#define PARSER_H\n", f"#define PARSER_H\n\n{p_conflict_curr}")

        with pytest.raises(ScopeViolationError, match=r"conflicting concurrent declaration of 'check_magic'"):
            splice_architect_header(base_h, agent_h_conf, curr_h_conf, path="parser.h")

    def test_architect_header_merge_tolerates_concurrent_prover_on_disjoint_function(self, tmp_path: Path) -> None:
        """Architect merge succeeds when a concurrent prover already updated a disjoint prototype in the header."""
        target = tmp_path / "target"
        target.mkdir()
        (target / "parser.c").write_text(BASELINE_C, encoding="utf-8")
        (target / "parser.h").write_text(BASELINE_H, encoding="utf-8")

        run_dir = tmp_path / "run"
        overlay = run_dir / "workspace"
        workspace_overlay.init_overlay(target, overlay)

        # Initialize concurrent architect and prover from same baseline
        workspace_overlay.init_agent_overlay(run_dir, "arch-1", overlay)
        workspace_overlay.init_agent_overlay(run_dir, "prover-payload", overlay)

        # Prover annotates parse_payload in its scratch copy
        p_h = run_dir / "agents/prover-payload/scratch/work/parser.h"
        p_h.write_text(
            BASELINE_H.replace(
                "int parse_payload(const uint8_t *buf, size_t len, int *out);",
                "/*@\n  requires out == \\null || \\valid(out);\n  assigns *out;\n*/\n"
                "int parse_payload(const uint8_t *buf, size_t len, int *out);",
            ),
            encoding="utf-8",
        )

        # Architect annotates parse_magic in its scratch copy
        a_h = run_dir / "agents/arch-1/scratch/work/parser.h"
        a_h.write_text(
            BASELINE_H.replace(
                "int parse_magic(const uint8_t *buf, size_t len);",
                "/*@\n  requires buf == \\null || \\valid_read(buf + (0 .. len - 1));\n  assigns \\nothing;\n*/\n"
                "int parse_magic(const uint8_t *buf, size_t len);",
            ),
            encoding="utf-8",
        )

        # Prover merges first
        res_p = workspace_overlay.merge_agent_overlay(
            run_dir=run_dir,
            agent_id="prover-payload",
            role="prover",
            overlay_dir=overlay,
            c_file="parser.c",
            function="parse_payload",
            header_file="parser.h",
            skip_reverify=True,
        )
        assert res_p["ok"] is True

        # Architect merges second (sees concurrent header modification)
        res_a = workspace_overlay.merge_agent_overlay(
            run_dir=run_dir,
            agent_id="arch-1",
            role="architect",
            overlay_dir=overlay,
            header_file="parser.h",
            skip_reverify=True,
        )
        assert res_a["ok"] is True

        # Verify both contracts are present in workspace/work/parser.h
        merged_h = (overlay / "work/parser.h").read_text(encoding="utf-8")
        assert "\\valid_read(buf + (0 .. len - 1))" in merged_h
        assert "\\valid(out)" in merged_h
        check_res = workspace_overlay.check_acsl_only(overlay)
        assert check_res["ok"] is True and check_res["errors"] == []

    def test_architect_header_merge_rejects_concurrent_conflict_on_same_function(self, tmp_path: Path) -> None:
        """Architect merge rolls back and raises ScopeViolationError on conflicting prototype contract."""
        target = tmp_path / "target"
        target.mkdir()
        (target / "parser.c").write_text(BASELINE_C, encoding="utf-8")
        (target / "parser.h").write_text(BASELINE_H, encoding="utf-8")

        run_dir = tmp_path / "run"
        overlay = run_dir / "workspace"
        workspace_overlay.init_overlay(target, overlay)

        workspace_overlay.init_agent_overlay(run_dir, "prover-magic", overlay)
        workspace_overlay.init_agent_overlay(run_dir, "arch-conflict", overlay)

        # Prover attaches contract A to parse_magic
        (run_dir / "agents/prover-magic/scratch/work/parser.h").write_text(
            BASELINE_H.replace(
                "int parse_magic(const uint8_t *buf, size_t len);",
                "/*@ requires len >= 4; assigns \\nothing; */\nint parse_magic(const uint8_t *buf, size_t len);",
            ),
            encoding="utf-8",
        )
        # Architect attaches conflicting contract B to parse_magic
        (run_dir / "agents/arch-conflict/scratch/work/parser.h").write_text(
            BASELINE_H.replace(
                "int parse_magic(const uint8_t *buf, size_t len);",
                "/*@ requires len >= 8; assigns \\nothing; */\nint parse_magic(const uint8_t *buf, size_t len);",
            ),
            encoding="utf-8",
        )

        # Prover merges first
        res_p = workspace_overlay.merge_agent_overlay(
            run_dir=run_dir,
            agent_id="prover-magic",
            role="prover",
            overlay_dir=overlay,
            c_file="parser.c",
            function="parse_magic",
            header_file="parser.h",
            skip_reverify=True,
        )
        assert res_p["ok"] is True

        # Architect merge raises ScopeViolationError on conflict
        with pytest.raises(
            ScopeViolationError,
            match=r"conflicting concurrent modification to prototype contract of 'parse_magic'",
        ):
            workspace_overlay.merge_agent_overlay(
                run_dir=run_dir,
                agent_id="arch-conflict",
                role="architect",
                overlay_dir=overlay,
                header_file="parser.h",
                skip_reverify=True,
            )

        # Workspace header remains intact with Prover's contract
        work_h = (overlay / "work/parser.h").read_text(encoding="utf-8")
        assert "len >= 4" in work_h
        assert "len >= 8" not in work_h


def test_all_definition_spans_agree_with_locate_function_span() -> None:
    source = (
        BASELINE_C
        + r"""
/*@ assigns \nothing; */
static int with_contract(int a) { return a; }
int proto_only(int b);
int with_contract_again(void) { return 0; }
"""
    )
    spans = locate_all_definition_spans(source)
    assert {"parse_magic", "parse_payload", "with_contract", "with_contract_again"} <= set(spans)
    assert "proto_only" not in spans
    for name, span in spans.items():
        assert span == locate_function_span(source, name), name
