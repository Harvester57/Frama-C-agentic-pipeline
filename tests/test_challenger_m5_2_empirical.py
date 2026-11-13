"""
Empirical stress tests for Milestone M5 (Patterns, Deduplication, Removals, and Test Convergence).
Challenger 2 suite: adversarial stress-testing of E1 removals, Roman numeral footers, and downstream fixes.
"""

from __future__ import annotations

import re

import pytest

from eva_options import option_problem
from extract_references import _PAGE_NUMBER_RE, clean_page
from frame_skeleton import _offset_expr
from prover_candidates import _oracle_summary
from resources import cache_mount_mode
from run_wp_function import classify_unproven_goal

# ============================================================================
# 1. Roman Numeral Generator for 1..99
# ============================================================================

def _to_roman(n: int) -> str:
    """Convert integer 1..99 to lowercase Roman numeral."""
    val = [
        (90, "xc"), (50, "l"), (40, "xl"), (10, "x"),
        (9, "ix"), (5, "v"), (4, "iv"), (1, "i")
    ]
    roman = ""
    for v, sym in val:
        while n >= v:
            roman += sym
            n -= v
    return roman


# ============================================================================
# 2. Stress Tests for Roman Numeral Page Footers (_PAGE_NUMBER_RE)
# ============================================================================

class TestRomanNumeralFooters:
    """Adversarial stress testing for _PAGE_NUMBER_RE and clean_page footer dropping."""

    @pytest.mark.parametrize("n", range(1, 90))
    def test_valid_roman_numerals_1_to_89_match(self, n: int):
        roman = _to_roman(n)
        assert _PAGE_NUMBER_RE.match(roman) is not None, f"Failed for Roman numeral {n}: {roman!r}"

    @pytest.mark.parametrize("n", range(90, 100))
    def test_valid_roman_numerals_90_to_99_match(self, n: int):
        roman = _to_roman(n)
        assert _PAGE_NUMBER_RE.match(roman) is not None, f"Failed for Roman numeral {n}: {roman!r}"

    @pytest.mark.parametrize(
        "arabic",
        ["0", "1", "42", "89", "100", "999", "12345", "  42  ", "\t100\n"],
    )
    def test_valid_arabic_numerals_match(self, arabic: str):
        assert _PAGE_NUMBER_RE.match(arabic) is not None

    @pytest.mark.parametrize(
        "word",
        [
            "mix",
            "dim",
            "c",
            "d",
            "cc",
            "lxxxx",
            "iiii",
            "vv",
            "INDEX",
            "CHAPTER",
            "civil",
            "vivid",
            "mill",
            "did",
            "id",
            "mid",
            "mimic",
            "livid",
            "div",
            "I",
            "IV",
            "V",
            "IX",
            "X",
            "XL",
            "L",
            "XC",
            "",
            "   ",
            "\t",
            "\n",
            "ixv",
            "iix",
            "il",
            "ic",
            "xd",
            "xm",
            "vx",
            "vl",
            "lc",
            "dm",
            "ll",
            "dd",
            "mm",
            "xxxx",
            "foo",
            "bar",
        ],
    )
    def test_words_and_invalid_roman_do_not_match(self, word: str):
        assert _PAGE_NUMBER_RE.match(word) is None, f"Word falsely matched as page number: {word!r}"

    def test_clean_page_preserves_words_and_drops_footers(self):
        page_with_mix = "Some technical text\nwith options and mix"
        assert clean_page(page_with_mix) == ["Some technical text", "with options and mix"]

        page_with_dim = "Heading\narray dim"
        assert clean_page(page_with_dim) == ["Heading", "array dim"]

        page_with_c = "Language:\nc"
        assert clean_page(page_with_c) == ["Language:", "c"]

        page_with_d = "Option:\nd"
        assert clean_page(page_with_d) == ["Option:", "d"]

        page_with_cc = "Compiler:\ncc"
        assert clean_page(page_with_cc) == ["Compiler:", "cc"]

        page_with_iv = "Front matter page\niv"
        assert clean_page(page_with_iv) == ["Front matter page"]

        page_with_arabic = "Body text page\n42"
        assert clean_page(page_with_arabic) == ["Body text page"]

        page_with_lxxxviii = "Preface page\nlxxxviii"
        assert clean_page(page_with_lxxxviii) == ["Preface page"]


# ============================================================================
# 3. Stress Tests for eva_options.py (entry.partition(":"))
# ============================================================================

class TestEvaOptionsPartition:
    """Stress testing option_problem for func_value options."""

    @pytest.mark.parametrize(
        "entry",
        [
            ":foo",       # empty head
            "foo:",       # empty tail
            "::",         # empty head and tail
            "",           # empty string
            "   ",        # whitespace only
            " :foo",      # whitespace head
            "foo :bar",   # trailing whitespace in head
            " foo:bar",   # leading whitespace in head
            "123foo:bar", # invalid C identifier in head
            "-bad:bar",   # dash in C identifier head
            "foo\n:bar",  # newline in head
        ],
    )
    def test_slevel_function_rejects_invalid_entries(self, entry: str):
        prob = option_problem("slevel-function", entry)
        assert prob is not None, f"Expected rejection for entry {entry!r}"

    @pytest.mark.parametrize(
        "entry",
        [
            "f:100",
            "my_func:200",
            "_init:0",
            "f:bar:baz",     # partition splits at first colon: head='f', tail='bar:baz'
            "func_name:1000",
        ],
    )
    def test_slevel_function_accepts_valid_entries(self, entry: str):
        prob = option_problem("slevel-function", entry)
        assert prob is None, f"Expected acceptance for entry {entry!r}, got: {prob}"

    def test_slevel_function_list_uniqueness(self):
        prob = option_problem("slevel-function", ["f:10", "f:20"])
        assert prob is None
        prob_dup = option_problem("slevel-function", ["f:10", "f:10"])
        assert prob_dup is not None and "unique" in prob_dup

    @pytest.mark.parametrize(
        "entry",
        [
            ":f",
            "octagon:",
            "::",
            "",
            "   ",
            "OCTAGON:f",  # domain name must be lowercase
            "123dom:f",
            "_dom:f",
        ],
    )
    def test_domains_function_rejects_invalid_entries(self, entry: str):
        prob = option_problem("domains-function", entry)
        assert prob is not None, f"Expected rejection for domain entry {entry!r}"

    @pytest.mark.parametrize(
        "entry",
        [
            "octagon:f",
            "multidim:my_func",
            "cvalue:init",
            "octagon:f:extra",
        ],
    )
    def test_domains_function_accepts_valid_entries(self, entry: str):
        prob = option_problem("domains-function", entry)
        assert prob is None, f"Expected acceptance for domain entry {entry!r}, got: {prob}"


# ============================================================================
# 4. Stress Tests for frame_skeleton.py (inner.strip() == root)
# ============================================================================

class TestFrameSkeletonRootCheck:
    """Stress testing _offset_expr for pointer dereferences and root matching."""

    @pytest.mark.parametrize(
        "lval,root,expected",
        [
            ("*p", "p", ("zero", "0")),
            ("*(p)", "p", ("zero", "0")),
            ("*( p )", "p", ("zero", "0")),
            ("*(  p  )", "p", ("zero", "0")),
            ("*(p + 4)", "p", ("expr", "4")),
            ("*(p + i)", "p", ("expr", "i")),
            ("*(p + (i * 4))", "p", ("expr", "(i * 4)")),
            ("*p_other", "p", None),
            ("*(p_other)", "p", None),
            ("*(p_other + 1)", "p", None),
            ("*(prefix_p)", "p", None),
            ("*(p2)", "p", None),
            ("*p", "ptr", None),
            ("*(ptr)", "ptr", ("zero", "0")),
            ("*(ptr + 8)", "ptr", ("expr", "8")),
            ("p[0]", "p", ("expr", "0")),
            ("p[i]", "p", ("expr", "i")),
            ("p[i + 1]", "p", ("expr", "i + 1")),
            ("p->f", "p", ("zero", "0")),
            ("p.f", "p", ("zero", "0")),
            ("(*p).f", "p", ("zero", "0")),
            ("(* p ).f", "p", ("zero", "0")),
        ],
    )
    def test_offset_expr_classification(self, lval: str, root: str, expected: tuple[str, str] | None):
        res = _offset_expr(lval, root)
        assert res == expected, f"For lval={lval!r}, root={root!r}: expected {expected}, got {res}"

    def test_string_equality_vs_old_regex_equivalence(self):
        """Verify inner.strip() == root matches re.fullmatch(re.escape(root), inner.strip())."""
        roots = ["p", "ptr", "my_var", "arr_1", "buf"]
        candidates = [
            "p", "  p  ", "p ", " p", "ptr", "my_var", "arr_1", "buf",
            "p + 1", "p[0]", "p_extra", "prefix_p", "p2", "", "   "
        ]
        for r in roots:
            for c in candidates:
                old_behavior = bool(re.fullmatch(rf"{re.escape(r)}", c.strip()))
                new_behavior = (c.strip() == r)
                assert old_behavior == new_behavior, f"Discrepancy for root={r!r}, candidate={c!r}"


# ============================================================================
# 5. Stress Tests for prover_candidates.py (.lower().endswith(...))
# ============================================================================

class TestProverCandidatesEndswith:
    """Stress testing prover_candidates invalid goal detection via endswith."""

    @pytest.mark.parametrize(
        "annot,expected_invalid",
        [
            ("loop_invariant_established", True),
            ("loop_invariant_preserved", True),
            ("LOOP_INVARIANT_ESTABLISHED", True),
            ("Loop_Invariant_Preserved", True),
            ("_established", True),
            ("_preserved", True),
            ("_ESTABLISHED", True),
            ("_PRESERVED", True),
            ("my_goal_established", True),
            ("my_goal_preserved", True),
            # Negative cases
            ("loop_invariant_established_extra", False),
            ("loop_invariant_preserved_tail", False),
            ("established", False),  # missing leading underscore
            ("preserved", False),    # missing leading underscore
            ("loop_invariant_establish", False),
            ("loop_invariant_preserve", False),
            ("", False),
            ("contract_postcondition", False),
            ("rte_mem_access", False),
            ("something_established_here", False),
        ],
    )
    def test_annotation_suffix_matching(self, annot: str, expected_invalid: bool):
        report = {
            "unproven_goals": [
                {"annotation": annot, "kind": "Invariant"}
            ]
        }
        res = _oracle_summary("test_oracle", report)
        invalid_count = res.get("invalid", 0)
        assert (invalid_count == 1) == expected_invalid, (
            f"For annot={annot!r}: expected invalid={expected_invalid}, got count={invalid_count}"
        )

    def test_oracle_summary_with_mixed_and_empty_goals(self):
        report = {
            "unproven_goals": [
                {"annotation": "g1_established"},
                {"annotation": "g2_preserved"},
                {"annotation": "g3_other"},
                {"annotation": None},
                {},
                {"annotation": ""},
                {"annotation": "g4_PRESERVED"},
            ]
        }
        res = _oracle_summary("test_oracle", report)
        assert res.get("invalid") == 3


# ============================================================================
# 6. Stress Tests for run_wp_function.py (Assigns Buckets)
# ============================================================================

class TestRunWpAssignsBuckets:
    """Stress testing unproven goal bucket classification for assigns clauses."""

    @pytest.mark.parametrize(
        "row,expected_bucket",
        [
            ({"kind": "Assigns", "annotation": "assigns x;"}, "step_a_assigns"),
            ({"kind": "assigns", "annotation": ""}, "step_a_assigns"),
            ({"kind": "Postcondition", "annotation": "ensures \\result == 0;"}, "step_c_contract_postcondition"),
            ({"kind": "Invariant", "annotation": "loop invariant x >= 0;"}, "step_b_loop_invariant"),
            ({"kind": "Variant", "annotation": "loop variant n - i;"}, "step_b_loop_invariant"),
            ({"kind": "RTE", "annotation": "rte: mem_access"}, "step_c_rte_obligation"),
            ({"kind": "Precondition", "annotation": "requires \\valid(p);"}, "step_c_caller_precondition"),
        ],
    )
    def test_classify_unproven_goal_buckets(self, row: dict, expected_bucket: str):
        assert classify_unproven_goal(row) == expected_bucket

    def test_assigns_vcs_proven_logic(self):
        """Simulate assigns_vcs_proven check with empty and non-empty step_a_assigns."""
        buckets_empty: dict[str, list] = {"step_a_assigns": []}
        buckets_with_fail: dict[str, list] = {
            "step_a_assigns": [{"kind": "Assigns", "annotation": "assigns buf[0..n];"}]
        }

        assert (len(buckets_empty["step_a_assigns"]) == 0) is True
        assert (len(buckets_with_fail["step_a_assigns"]) == 0) is False


# ============================================================================
# 7. Stress Tests for resources.py (Cache Allowlist Validation)
# ============================================================================

class TestResourcesCacheAllowlist:
    """Stress testing cache_mount_mode allowlist check without _PLAIN_COMMAND."""

    @pytest.mark.parametrize(
        "cmd",
        [
            "python3 /opt/framac-pipeline/scripts/cache.py gc",
            "python3 /opt/framac-pipeline/scripts/cache.py stats",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py build-check",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py ingest",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run build",
            "python3   /opt/framac-pipeline/scripts/cache.py   gc",  # extra whitespace
            "\tpython3 /opt/framac-pipeline/scripts/cache.py stats\n",
            "python3 $S/cache.py gc",
            "python3 ${S}/cache.py stats",
            "python3 $S/pipeline_make.py build-check",
            "python3 ${S}/pipeline_make.py ingest",
        ],
    )
    def test_allowlist_commands_grant_rw_when_requested(self, cmd: str):
        mode = cache_mount_mode(cmd, cache_rw_requested=True, cache_dir="/tmp/cache")
        assert mode == "rw", f"Failed to grant rw for allowlisted command: {cmd!r}"

    @pytest.mark.parametrize(
        "cmd",
        [
            "python3 /opt/framac-pipeline/scripts/cache.py gc",
            "python3 $S/cache.py stats",
            "python3 $S/pipeline_make.py build-check",
        ],
    )
    def test_allowlist_commands_return_ro_when_not_requested(self, cmd: str):
        mode = cache_mount_mode(cmd, cache_rw_requested=False, cache_dir="/tmp/cache")
        assert mode == "ro"

    @pytest.mark.parametrize(
        "bad_cmd",
        [
            # Shell command injections
            "python3 /opt/framac-pipeline/scripts/cache.py gc; rm -rf /",
            "python3 /opt/framac-pipeline/scripts/cache.py gc && rm -rf /",
            "python3 /opt/framac-pipeline/scripts/cache.py gc | cat",
            "python3 /opt/framac-pipeline/scripts/cache.py gc\nrm -rf /",
            "python3 /opt/framac-pipeline/scripts/cache.py gc `whoami`",
            "python3 /opt/framac-pipeline/scripts/cache.py gc $(whoami)",
            # Extra arguments
            "python3 /opt/framac-pipeline/scripts/cache.py gc --extra-arg",
            "python3 /opt/framac-pipeline/scripts/cache.py gc foo",
            # Subcommands not in allowlist
            "python3 /opt/framac-pipeline/scripts/cache.py init",
            "python3 /opt/framac-pipeline/scripts/cache.py prune",
            "python3 /opt/framac-pipeline/scripts/cache.py clear",
            "python3 /opt/framac-pipeline/scripts/cache.py purge",
            "python3 /opt/framac-pipeline/scripts/cache.py wipe",
            # Different binary or script
            "python3 /opt/framac-pipeline/scripts/other.py gc",
            "bash /opt/framac-pipeline/scripts/cache.py gc",
            "sh /opt/framac-pipeline/scripts/cache.py gc",
            # Empty and garbage
            "",
            "   ",
            "invalid command",
            "echo hello",
        ],
    )
    def test_non_allowlist_commands_never_grant_rw(self, bad_cmd: str):
        mode = cache_mount_mode(bad_cmd, cache_rw_requested=True, cache_dir="/tmp/cache")
        assert mode == "ro", f"Insecurely granted rw for command: {bad_cmd!r}"
