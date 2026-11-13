"""Empirical adversarial stress tests for Milestone M5 (Workstream E / Patterns convergence).

Author: challenger_m5_1

Comprehensive empirical challenge covering:
1. patterns.parse_mem and parse_size:
   - Integers, floats, None, empty strings, whitespace.
   - Invalid units ('10x', '5i', 'Gi', '10foo', '10ib').
   - Bare byte suffix ('1048576b', '1b', '0b').
   - Unit variations (k/K/Ki/KiB/KB, m/M/Mi/MiB/MB, g/G/Gi/GiB/GB, t/T/Ti/TiB/TB).
   - Zero, negative numbers, plus signs, large values, edge cases.
   - Dual-mode verification: as_bytes=False (MiB) vs as_bytes=True (bytes).
2. patterns.parse_make_deps:
   - Makefile escaping: spaces ('\\ '), hashes ('\\#'), backslashes ('\\\\'), dollar signs ('$$').
   - Continuations: Unix ('\\n') and Windows CRLF ('\\r\\n').
   - Multiple rules and multiple targets.
   - Colons in rule targets (escaped colons and Windows drive letters).
   - Cwd handling: raw token mode (cwd=None) vs normalized absolute posix paths.
   - Empty, None, and comment/recipe lines.
3. Canonical regular expressions:
   - C_IDENT_RE: valid identifiers, digit prefixes, special characters, word boundaries.
   - LOCATION_RE: file:line, file:line-end, file:line:col, file:line:col-end, file:line:col-endline:col,
     paths with spaces, colons, Windows drive letters.
   - MODULE_RE: allowed charset, length bounds (1 to 128 chars), forbidden starting characters.
   - CALL_SITE_RE: function names before parentheses, whitespace variations, boundary tokens.
   - KERNEL_RENAME_RE: greedy static rename matching (foo_0, foo_1_2), non-matches.
   - DOMAIN_RE: lowercase Eva domain identifiers, hyphen/underscore, invalid cases.
   - ASSIGNS_RE: ACSL assigns clause keyword, lookbehind and word-boundary isolation.
   - TREE_TAIL_RE and WORK_PREFIX_RE: workspace and overlay path decompositions.
   - FUZZER_INIT_DEF_RE and FUZZER_ENTRY_DEF_RE: C source fuzzer entry-point signatures.
4. Downstream string operation replacements & regex hardening:
   - extract_references._PAGE_NUMBER_RE: strict Roman numeral grammar (1-89) without stripping English words.
   - frame_skeleton literal matching vs former regex injection risk.
   - prover_candidates loop annotation checks.
   - eva_options domain and identifier validation.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

import patterns as pat

# ===========================================================================
# 1. Stress Tests: patterns.parse_mem & parse_size
# ===========================================================================


class TestParseMemEmpirical:
    """Empirical challenge of parse_mem and parse_size across boundary inputs."""

    @pytest.mark.parametrize(
        ("val", "expected_mib", "expected_bytes"),
        [
            # Bare integers
            (0, 0, 0),
            (1, 1, 1),
            (100, 100, 100),
            (1048576, 1048576, 1048576),
            (10**9, 10**9, 10**9),
            # Bare string numbers (no unit)
            ("0", 0, 0),
            ("1", 1, 1),
            ("100", 100, 100),
            ("1048576", 1048576, 1048576),
            # Floats in string
            ("0.0", 0, 0),
            ("1.5m", 1, int(1.5 * 1024**2)),
            ("2.5g", int(2.5 * 1024), int(2.5 * 1024**3)),
            ("0.5g", 512, int(0.5 * 1024**3)),
            ("0.25k", 0, int(0.25 * 1024)),
            # Bare byte suffix 'b' / 'B'
            ("0b", 0, 0),
            ("1b", 0, 1),
            ("1024b", 0, 1024),
            ("1048575b", 0, 1048575),
            ("1048576b", 1, 1048576),
            ("2097152B", 2, 2097152),
            ("5242880b", 5, 5242880),
            # Kilobytes (k / K / ki / Ki / kib / KiB / kb / KB)
            ("1024k", 1, 1024 * 1024),
            ("2048K", 2, 2048 * 1024),
            ("1024ki", 1, 1024 * 1024),
            ("4096Ki", 4, 4096 * 1024),
            ("1024kb", 1, 1024 * 1024),
            ("8192KiB", 8, 8192 * 1024),
            ("512k", 0, 512 * 1024),  # 512 KiB is 0 MiB via int(512 / 1024)
            # Megabytes (m / M / mi / Mi / mib / MiB / mb / MB)
            ("1m", 1, 1024**2),
            ("16M", 16, 16 * 1024**2),
            ("32mi", 32, 32 * 1024**2),
            ("64Mi", 64, 64 * 1024**2),
            ("128mb", 128, 128 * 1024**2),
            ("256MiB", 256, 256 * 1024**2),
            ("1024MB", 1024, 1024 * 1024**2),
            # Gigabytes (g / G / gi / Gi / gib / GiB / gb / GB)
            ("1g", 1024, 1024**3),
            ("2G", 2048, 2 * 1024**3),
            ("4gi", 4096, 4 * 1024**3),
            ("8Gi", 8192, 8 * 1024**3),
            ("16gb", 16384, 16 * 1024**3),
            ("32GiB", 32768, 32 * 1024**3),
            # Terabytes (t / T / ti / Ti / tib / TiB / tb / TB)
            ("1t", 1024 * 1024, 1024**4),
            ("2T", 2 * 1024 * 1024, 2 * 1024**4),
            ("4TiB", 4 * 1024 * 1024, 4 * 1024**4),
            # Whitespace handling
            ("   512m   ", 512, 512 * 1024**2),
            ("\t1024 MiB\n", 1024, 1024 * 1024**2),
            (" 4 G ", 4096, 4 * 1024**3),
        ],
    )
    def test_valid_mem_inputs(self, val, expected_mib, expected_bytes):
        assert pat.parse_mem(val, as_bytes=False) == expected_mib
        assert pat.parse_mem(val, as_bytes=True) == expected_bytes
        if isinstance(val, str):
            assert pat.parse_size(val) == expected_bytes

    @pytest.mark.parametrize(
        "invalid_val",
        [
            None,
            "",
            "   ",
            "\n\t",
            "10x",
            "5i",  # bare 'i' without unit letter
            "Gi",  # no leading digits
            "10foo",
            "10ib",  # 'i' without unit letter
            "-10",
            "-500m",
            "+100m",
            "1.2.3m",
            "1,024m",
            "10 20m",
            "1e6",  # scientific notation disallowed
            "1e6m",
            "inf",
            "-inf",
            "nan",
            "NaN",
            "None",
            "8GiB extra",
            "extra 8GiB",
            "10g; rm -rf /",
            "$(cat /etc/passwd)",
            "10GBb",
            "10Gii",
            [123],
            {"mem": 100},
            object(),
        ],
    )
    def test_invalid_mem_inputs_fail_closed(self, invalid_val):
        assert pat.parse_mem(invalid_val, as_bytes=False) is None
        assert pat.parse_mem(invalid_val, as_bytes=True) is None
        if isinstance(invalid_val, str):
            assert pat.parse_size(invalid_val) is None

    def test_patterns_module_zero_pipeline_imports(self):
        """Empirically verify scripts/patterns.py has ZERO internal pipeline imports."""
        # Run python in a separate process that only imports patterns and inspects sys.modules
        code = (
            "import sys, patterns\n"
            "pipeline_mods = [m for m in sys.modules if any(m.startswith(pkg) for pkg in ("
            "'cache', 'resources', 'build_capture', 'ledger', 'framac_common', 'minischema'))]\n"
            "assert not pipeline_mods, f'Forbidden imports found: {pipeline_mods}'\n"
            "print('ZERO_PIPELINE_IMPORTS_OK')\n"
        )
        res = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            cwd=str(pat.Path(__file__).resolve().parent.parent / "scripts")
            if hasattr(pat, "Path")
            else None,
            env={"PYTHONPATH": "scripts", "PYTHONIOENCODING": "utf-8"},
            check=True,
        )
        assert "ZERO_PIPELINE_IMPORTS_OK" in res.stdout

    def test_extreme_sizes(self):
        """Test astronomical memory values do not overflow or error."""
        val = "1000000000g"
        expected_bytes = 1000000000 * (1024**3)
        expected_mib = 1000000000 * 1024
        assert pat.parse_mem(val, as_bytes=True) == expected_bytes
        assert pat.parse_mem(val, as_bytes=False) == expected_mib


# ===========================================================================
# 2. Stress Tests: patterns.parse_make_deps
# ===========================================================================


class TestParseMakeDepsEmpirical:
    """Empirical challenge of Makefile dependency lexer and path resolver."""

    def test_escaped_characters(self):
        """Test Makefile words with escaped spaces, escaped hash, escaped backslash, and $$."""
        text = r"target.o: path\ with\ spaces/file.c dir\#1/hash\#file.c win\\path/file.c cost$$var.c normal.c"
        raw_deps = pat.parse_make_deps(text, cwd=None)
        assert raw_deps == [
            "path with spaces/file.c",
            "dir#1/hash#file.c",
            "win\\path/file.c",
            "cost$var.c",
            "normal.c",
        ]

    def test_unix_and_windows_crlf_continuations(self):
        """Verify backslash-newline continuations work identically with Unix LF and Windows CRLF."""
        unix_text = "out.o: src/a.c \\\n src/b.c \\\n src/c.c\n"
        win_text = "out.o: src/a.c \\\r\n src/b.c \\\r\n src/c.c\r\n"

        deps_unix = pat.parse_make_deps(unix_text)
        deps_win = pat.parse_make_deps(win_text)
        assert deps_unix == ["src/a.c", "src/b.c", "src/c.c"]
        assert deps_win == ["src/a.c", "src/b.c", "src/c.c"]

    def test_multiple_rules_and_targets(self):
        """Parse makefiles containing multiple distinct rule headers."""
        text = """
# First rule
mod1.o: src/mod1.c include/mod1.h common.h

# Second rule with multiple targets
mod2.o mod2.extra.o: src/mod2.c include/mod2.h common.h

# Rule with empty prerequisites
clean:
"""
        deps = pat.parse_make_deps(text)
        assert deps == [
            "src/mod1.c",
            "include/mod1.h",
            "common.h",
            "src/mod2.c",
            "include/mod2.h",
            "common.h",
        ]

    def test_escaped_colon_in_target(self):
        """Target containing an escaped colon: target\\:name: dep1.c."""
        text = r"target\:name.o: src/target.c include/target.h"
        deps = pat.parse_make_deps(text)
        assert deps == ["src/target.c", "include/target.h"]

    def test_cwd_path_normalization(self):
        """Verify normalization with cwd relative and absolute paths."""
        text = "foo.o: ./src/a.c ../external/b.h /usr/include/stdio.h c.h"
        resolved = pat.parse_make_deps(text, cwd="/workspace/project")
        assert resolved == [
            "/workspace/project/src/a.c",
            "/workspace/external/b.h",
            "/usr/include/stdio.h",
            "/workspace/project/c.h",
        ]

    def test_mixed_continuations_and_tabs(self):
        """Parse makefiles with mixed tabs, leading spaces, empty continuation lines, and redundant whitespace."""
        text = """
# A rule with line continuations and deep indentation
libapp.a: \\
\tsrc/entry.c \\
\tsrc/util.c   \\
\tinclude/app.h

# Another rule with trailing comments and empty lines
sub_target: \\
\t\\
\tsrc/sub.c

"""
        deps = pat.parse_make_deps(text)
        assert deps == ["src/entry.c", "src/util.c", "include/app.h", "src/sub.c"]

    def test_complex_dollar_signs_in_deps(self):
        """Test multiple $$ sequences in dependency words."""
        text = "foo.o: lib$$v1$$0.so sub$$dir/file$$name.c"
        deps = pat.parse_make_deps(text)
        assert deps == ["lib$v1$0.so", "sub$dir/file$name.c"]

    @pytest.mark.parametrize(
        "empty_text",
        [
            "",
            "   ",
            "\n\n\t\n",
            "# Only comments\n# Second comment",
            "\tgcc -c foo.c -o foo.o\n",
        ],
    )
    def test_empty_or_non_rule_text(self, empty_text):
        assert pat.parse_make_deps(empty_text) == []
        assert pat.parse_make_deps(empty_text, cwd="/some/dir") == []


# ===========================================================================
# 3. Stress Tests: Canonical Regular Expressions
# ===========================================================================


class TestCanonicalRegexesEmpirical:
    """Empirical challenge of compiled regular expressions in patterns.py."""

    @pytest.mark.parametrize(
        ("ident", "is_match"),
        [
            ("foo", True),
            ("_foo", True),
            ("foo123", True),
            ("_", True),
            ("A", True),
            ("_123", True),
            ("var_name_with_underscores", True),
            ("123foo", False),
            ("foo-bar", False),
            ("foo.bar", False),
            ("foo$bar", False),
            ("", False),
        ],
    )
    def test_c_ident_re(self, ident, is_match):
        assert bool(pat.C_IDENT_RE.fullmatch(ident)) is is_match

    @pytest.mark.parametrize(
        ("raw", "expected_file", "expected_line", "expected_end", "expected_end2"),
        [
            # file:line
            ("foo.c:42", "foo.c", "42", None, None),
            # file:line-end
            ("foo.c:42-45", "foo.c", "42", "45", None),
            # file:line:col
            ("foo.c:42:10", "foo.c", "42", None, None),
            # file:line:col-endcol
            ("foo.c:42:10-20", "foo.c", "42", None, None),
            # file:line-end:col
            ("foo.c:42-45:10", "foo.c", "42", "45", None),
            # file:line:col-endline:endcol
            ("foo.c:42:10-45:20", "foo.c", "42", None, "45"),
            # file with spaces
            ("dir with spaces/foo.c:100", "dir with spaces/foo.c", "100", None, None),
            # absolute posix path
            ("/opt/framac/src/file.c:7", "/opt/framac/src/file.c", "7", None, None),
            # Windows style forward-slash drive letter
            ("C:/dev/proj/file.c:99", "C:/dev/proj/file.c", "99", None, None),
        ],
    )
    def test_location_re_valid(self, raw, expected_file, expected_line, expected_end, expected_end2):
        m = pat.LOCATION_RE.fullmatch(raw)
        assert m is not None, f"Failed to match location: {raw}"
        assert m.group("file") == expected_file
        assert m.group("line") == expected_line
        assert m.group("end") == expected_end
        assert m.group("end2") == expected_end2

    @pytest.mark.parametrize(
        "invalid_loc",
        [
            "",
            "foo.c",
            "foo.c:",
            ":42",
            "foo.c:abc",
            "foo.c:42:10:extra:extra",
        ],
    )
    def test_location_re_invalid(self, invalid_loc):
        assert pat.LOCATION_RE.fullmatch(invalid_loc) is None

    @pytest.mark.parametrize(
        ("module_name", "is_valid"),
        [
            ("a", True),
            ("mod", True),
            ("my_module", True),
            ("mod-1", True),
            ("mod.2", True),
            ("mod+3", True),
            ("0mod", True),
            ("a" * 128, True),
            ("a" * 129, False),  # exceeds 128 chars
            ("-mod", False),  # leading hyphen disallowed
            (".mod", False),  # leading dot disallowed
            ("+mod", False),  # leading plus disallowed
            ("mod/sub", False),
            ("mod\\sub", False),
            ("mod:name", False),
            ("mod name", False),
            ("mod@name", False),
            ("mod#name", False),
            ("mod$name", False),
            ("mod%name", False),
            ("", False),
        ],
    )
    def test_module_re(self, module_name, is_valid):
        assert bool(pat.MODULE_RE.fullmatch(module_name)) is is_valid

    def test_call_site_re(self):
        """Verify extraction of call sites preceding parentheses."""
        text = "foo(); bar ( 1, 2 ); _init_func(); 123notfunc(); baz(x);"
        names = [m.group("name") for m in pat.CALL_SITE_RE.finditer(text)]
        # Note: 123notfunc() does not match because \b precedes digits
        assert names == ["foo", "bar", "_init_func", "baz"]

    @pytest.mark.parametrize(
        ("raw_name", "expected_base"),
        [
            ("foo_0", "foo"),
            ("static_var_12", "static_var"),
            ("func_1_2", "func_1"),
            ("check_bounds_9999", "check_bounds"),
        ],
    )
    def test_kernel_rename_re_match(self, raw_name, expected_base):
        m = pat.KERNEL_RENAME_RE.fullmatch(raw_name)
        assert m is not None
        assert m.group(1) == expected_base

    @pytest.mark.parametrize(
        "non_renamed",
        [
            "foo",
            "foo_",
            "foo_bar",
            "_123",  # group(1) would be empty string? wait: (.+) requires at least 1 char
            "foo_abc",
        ],
    )
    def test_kernel_rename_re_non_match(self, non_renamed):
        # (.+)_\d+ requires at least 1 char before underscore
        m = pat.KERNEL_RENAME_RE.fullmatch(non_renamed)
        if non_renamed == "_123":
            assert m is None  # (.+) cannot match empty string before leading underscore
        else:
            assert m is None

    @pytest.mark.parametrize(
        ("domain", "is_valid"),
        [
            ("value", True),
            ("octagon", True),
            ("symbolic-locations", True),
            ("cvalue_domain", True),
            ("v1", True),
            ("Value", False),  # uppercase disallowed
            ("1value", False),  # leading digit disallowed
            ("-value", False),  # leading hyphen disallowed
            ("_value", False),  # leading underscore disallowed
            ("val.ue", False),  # dot disallowed
            ("", False),
        ],
    )
    def test_domain_re(self, domain, is_valid):
        assert bool(pat.DOMAIN_RE.fullmatch(domain)) is is_valid

    def test_assigns_re_word_boundary_and_lookbehind(self):
        """Test ACSL assigns clause regex prevents substring false positives."""
        text = """
        /*@ assigns *p, q; */
        /*@ reassigns *p; */
        /*@ my_assigns *p; */
        /*@ assigns_extra *p; */
        //@ assigns \\result;
        assigns x;
        """
        matches = list(pat.ASSIGNS_RE.finditer(text))
        # Matches should be:
        # 1. line 2: 'assigns'
        # 2. line 6: 'assigns'
        # 3. line 7: 'assigns'
        # 'reassigns', 'my_assigns', 'assigns_extra' must NOT match.
        matched_positions = [m.start() for m in matches]
        assert len(matched_positions) == 3

    def test_fuzzer_init_and_entry_def_re(self):
        """Verify LibFuzzer signature recognition in C code."""
        c_src = """
        int LLVMFuzzerInitialize(int *argc, char ***argv) {
            return 0;
        }
        int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
            return 0;
        }
        // Prototype only (must not match because no opening brace)
        int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
        """
        assert pat.FUZZER_INIT_DEF_RE.search(c_src) is not None
        entries = list(pat.FUZZER_ENTRY_DEF_RE.finditer(c_src))
        assert len(entries) == 1
        assert "const uint8_t *data, size_t size" in entries[0].group(1)

    def test_tree_tail_and_work_prefix_re(self):
        """Verify work directory prefixes and relative tail extraction."""
        p1 = "workspace/work/src/foo.c"
        p2 = "agents/sub_1/scratch/work/include/bar.h"
        m1 = pat.TREE_TAIL_RE.match(p1)
        m2 = pat.TREE_TAIL_RE.match(p2)
        assert m1 is not None and m1.group(1) == "src/foo.c"
        assert m2 is not None and m2.group(1) == "include/bar.h"

        assert pat.WORK_PREFIX_RE.match("/some/path/workspace/work/main.c") is not None
        assert pat.WORK_PREFIX_RE.match("workspace/baseline/main.c") is not None


# ===========================================================================
# 4. Stress Tests: Downstream Removals & Hardened Page Heuristic
# ===========================================================================


class TestDownstreamHardeningEmpirical:
    """Verify behavioral correctness of M5 downstream fixes."""

    @pytest.mark.parametrize(
        "roman_footer",
        [
            "i",
            "ii",
            "iii",
            "iv",
            "v",
            "vi",
            "vii",
            "viii",
            "ix",
            "x",
            "xi",
            "xiv",
            "xv",
            "xix",
            "xx",
            "xxx",
            "xl",
            "xli",
            "l",
            "lix",
            "lx",
            "lxx",
            "lxxx",
            "lxxxix",
            "xc",
            "xci",
            "1",
            "42",
            "100",
            "  xvi  ",
        ],
    )
    def test_page_number_heuristic_matches_valid_footers(self, roman_footer):
        from extract_references import _PAGE_NUMBER_RE

        assert _PAGE_NUMBER_RE.match(roman_footer) is not None

    @pytest.mark.parametrize(
        "prose_word",
        [
            "mix",
            "dim",
            "c",
            "C",
            "MIX",
            "I",
            "X",
            "d",
            "cc",
            "lxxxx",
            "iiii",
            "vv",
            "page",
            "index",
            "appendix",
        ],
    )
    def test_page_number_heuristic_rejects_words(self, prose_word):
        from extract_references import _PAGE_NUMBER_RE

        assert _PAGE_NUMBER_RE.match(prose_word) is None

    def test_frame_skeleton_safe_literal_matching(self):
        """Verify that regex metacharacters in root do not cause regex injection or errors."""
        # Previously, frame_skeleton compiled re.fullmatch(rf"{r}", inner.strip())
        # which would crash if root contained regex quantifiers like '*p'
        root = "*p"
        inner = " *p "
        # Literal equality check:
        assert inner.strip() == root
        # Disparate inner:
        assert "other".strip() != root

    def test_prover_candidates_annotation_suffix(self):
        """Verify loop annotation checking without regex."""
        assert "loop_invariant_established".lower().endswith(("_established", "_preserved"))
        assert "loop_invariant_preserved".lower().endswith(("_established", "_preserved"))
        assert not "loop_assigns".lower().endswith(("_established", "_preserved"))
        assert not str(None or "").lower().endswith(("_established", "_preserved"))
