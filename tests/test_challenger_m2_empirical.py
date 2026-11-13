"""
Adversarial empirical stress-tests for Milestone M2 (Schemas & Infra Guards).
Author: challenger_m2_1

Empirically challenges:
1. `function_id` pattern across schemas (build_capture, phase0_model, security_props)
2. Threat model `size` pattern in schemas/threat_model.schema.json
3. `benchmark.assert_no_host_paths` in scripts/benchmark.py
4. `minischema.compile_pattern` in scripts/minischema.py
"""

from __future__ import annotations

import pytest

import benchmark
import minischema
import trust
from conftest import ROOT

pytestmark = pytest.mark.unit

SCHEMA_DIR = ROOT / "schemas"
_ID_SCHEMAS = ("phase0_model", "build_capture", "security_props")


def _schema(name: str) -> dict:
    return minischema.load_schema(SCHEMA_DIR / f"{name}.schema.json")


# ===========================================================================
# 1. Stress-test `function_id` schema pattern
# ===========================================================================


class TestFunctionIdSchemaPattern:
    """Adversarial challenge tests for the canonical `function_id` pattern."""

    @pytest.mark.parametrize("name", _ID_SCHEMAS)
    @pytest.mark.parametrize(
        "valid_id",
        [
            "src/a.c#func",
            "dir/sub/file.c#parse_tlv",
            "include/my lib/a.h#g",
            "a.c#_ZN3foo3barEv",
            "a.c#parse.constprop.0",
            "a.c#f@@VERS_1.0",
            "a.c#f@@VERS",
            "a.c#$helper",
            "a.c#_f",
            "a.c#f.bar",
            "a.c#f@bar",
            "a.c#f$bar",
            ".constprop.0#func",
            "deep/nested/path/to/source.c#compute_hash",
        ],
    )
    def test_function_id_accepts_valid_ids(self, name: str, valid_id: str):
        validator = minischema.Validator(_schema(name))
        errors = validator.errors(valid_id, {"$ref": "#/definitions/function_id"})
        assert errors == [], f"Unexpected error for {valid_id!r} in {name}: {errors}"

    @pytest.mark.parametrize("name", _ID_SCHEMAS)
    @pytest.mark.parametrize(
        "invalid_id",
        [
            "",
            "#",
            "a.c#",
            "#f",
            "f",
            "a.c#f\n",
            "\na.c#f",
            " a.c#f",
            "a.c#f ",
            "a.c# ",
            " #f",
            "see a.c#f",
            "a.c#b.c#f",
            "a.c#1f",
            "a.c#123",
            "a.c#f#extra",
            "a.c##f",
            "#a.c#f",
            "a.c#f/g",
            "a.c#f\\g",
            "a.c#f;g",
            "a.c#f\x00bar",
            "a.c#fé",
            "a.c#f\ud83d",
            "a.c#.constprop.0",
            "a.c#f: no definition found",
        ],
    )
    def test_function_id_rejects_malformed_ids(self, name: str, invalid_id: str):
        validator = minischema.Validator(_schema(name))
        errors = validator.errors(invalid_id, {"$ref": "#/definitions/function_id"})
        assert errors != [], f"Expected rejection but accepted {invalid_id!r} in {name}"

    @pytest.mark.parametrize("name", _ID_SCHEMAS)
    def test_function_id_embedded_newlines_in_directory_path(self, name: str):
        """
        Challenge: check behavior when a newline is injected in the directory
        part of a path (e.g. 'include/my\\nlib/a.h#g').
        Documenting behavior: [^#]*\\/ permits \\n in the directory path.
        """
        validator = minischema.Validator(_schema(name))
        newline_id = "include/my\nlib/a.h#g"
        errors = validator.errors(newline_id, {"$ref": "#/definitions/function_id"})
        assert errors != [], f"Expected rejection for newline in directory path {newline_id!r} in {name}"


# ===========================================================================
# 2. Stress-test threat model `size` pattern
# ===========================================================================


class TestThreatModelSizePattern:
    """Adversarial stress-test for threat model size expression pattern."""

    def _make_model(self, size: str) -> dict:
        return {
            "schema_version": 1,
            "target": "demo",
            "summary": "demo",
            "input_sources": [],
            "trusted_callers": [],
            "secrets": [
                {
                    "name": "key",
                    "kind": "local",
                    "function": "f",
                    "size": size,
                    "description": "a secret key",
                }
            ],
            "auth_gates": [],
            "output_sinks": [],
        }

    @pytest.mark.parametrize(
        "valid_size",
        [
            "32",
            "len",
            "len * 2",
            "(len + 1) / 2",
            "ctx->len",
            "sizeof(key) / 4",
            "2 * (n - 1)",
            "-1",
            "-(len)",
            "*len",
            "len / *factor",
            "32 + 1 - 2",
            "32.0",
            "32 > 1",
            "32 -> x",
            "len >> 2",
            " 32 ",
        ],
    )
    def test_threat_model_size_accepts_valid_c_expressions(self, valid_size: str):
        errors = trust.validate_block(self._make_model(valid_size))
        assert errors == [], f"Unexpected error for valid size {valid_size!r}: {errors}"

    @pytest.mark.parametrize(
        "attack_size",
        [
            "/*",
            "*/",
            "//",
            "/* len",
            "len */",
            "32 /* comment */",
            "len // 2",
            "len */ admit ensures 0 == 0; /*",
            "len*/2",
            "len/*2",
            "len\n",
            "len\r\n",
            "len\n// comment",
            "len\n/* comment */",
            "/*/* */*/",
            "/* // */",
            "len; exit(0);",
            "len { evil }",
            "len [ 0 ]",
            "len % 4",
            "len | 1",
            "len & 1",
            "len ^ 1",
            "len << 2",
            '"string"',
            "'c'",
            "\\x00",
            "len\x00extra",
            "",
        ],
    )
    def test_threat_model_size_refuses_comment_bypasses_and_injections(self, attack_size: str):
        errors = trust.validate_block(self._make_model(attack_size))
        assert any("secrets[0].size" in e for e in errors), (
            f"Expected attack size {attack_size!r} to be rejected, got errors: {errors}"
        )

    def test_threat_model_size_whitespace_only_accepted(self):
        """
        Challenge: check behavior for whitespace-only size ('   ').
        Because ' ' is in [A-Za-z0-9_ ()*+/.>-], '   ' matches the regex
        and threat_model schema lacks 'visibleContent: true' on size.
        """
        errors = trust.validate_block(self._make_model("   "))
        assert errors == [], "Whitespace-only size was rejected"


# ===========================================================================
# 3. Stress-test `benchmark.assert_no_host_paths`
# ===========================================================================


class TestBenchmarkAssertNoHostPaths:
    """Adversarial stress-test for host path detection in scripts/benchmark.py."""

    @pytest.mark.parametrize(
        "host_path",
        [
            r"C:\Users\me\project\a.c",
            "C:/Users/me/project/a.c",
            "c:/Users/me/project/a.c",
            r"c:\Users\me\project\a.c",
            r"C:\\Users\\me\\project\\a.c",
            r"C:\\\\Users\\\\me\\\\project\\\\a.c",
            "nested: C:/Users/me/x.c:1: error",
            "/home/me/project/a.c",
            "/Users/me/project/a.c",
            "/root/project/a.c",
            "/tmp/scratch/a.c",
            "/var/log/syslog",
            "/etc/passwd",
            r"\\?\C:\Users\file",
            "file:///C:/Users/me",
            "/framac-run/../home/user/code",
            "/framac-run/../../../../etc/shadow",
        ],
    )
    def test_assert_no_host_paths_detects_host_paths(self, host_path: str):
        with pytest.raises(benchmark.BenchmarkError):
            benchmark.assert_no_host_paths({"report": host_path})

    @pytest.mark.parametrize(
        "safe_value",
        [
            "/framac-run/workspace/work/a.c",
            "/framac-run",
            "workspace/reports/summary.json",
            "src/main.c",
            "https://github.com/example/repo",
            "http://example.com/a/b",
            "git+ssh://git@github.com/repo/foo",
            "status: ok",
            "v1.0",
        ],
    )
    def test_assert_no_host_paths_accepts_clean_values(self, safe_value: str):
        benchmark.assert_no_host_paths({"data": safe_value})

    def test_challenge_vulnerability_host_path_in_dict_key_ignored(self):
        """Vulnerability challenge resolved: assert_no_host_paths checks dict keys."""
        payload = {
            "target": "demo",
            "files": {
                r"C:\Users\florian\secret\main.c": {"lines": 100},
                "/home/florian/code/secret.c": {"lines": 200},
            },
        }
        with pytest.raises(benchmark.BenchmarkError) as exc_info:
            benchmark.assert_no_host_paths(payload)
        assert "host path in the run file" in str(exc_info.value)

    @pytest.mark.parametrize(
        "unc_path",
        [
            r"\\server\share\secret.c",
            r"\\wsl$\Ubuntu\home\florian\code.c",
            "//server/share/secret.c",
            "file:///home/user/repo/file.c",
            r"\Users\florian\project\a.c",
        ],
    )
    def test_challenge_vulnerability_unc_paths_bypassed(self, unc_path: str):
        """Vulnerability challenge resolved: Windows UNC and network paths are refused."""
        with pytest.raises(benchmark.BenchmarkError):
            benchmark.assert_no_host_paths({"report": unc_path})

    def test_challenge_false_positive_relative_paths_with_dot_slash(self):
        """False positive challenge resolved: relative paths are accepted."""
        benchmark.assert_no_host_paths({"relative": "./workspace/reports/summary.json"})
        benchmark.assert_no_host_paths({"parent_rel": "../src/main.c"})


# ===========================================================================
# 4. Stress-test `minischema.compile_pattern`
# ===========================================================================


class TestMinischemaCompilePattern:
    """Adversarial stress-test for minischema.compile_pattern."""

    def test_compile_pattern_anchors_translated_to_z(self):
        compiled = minischema.compile_pattern(r"^abc$")
        assert compiled.pattern == r"^abc\Z"
        assert compiled.search("abc")
        assert not compiled.search("abc\n")
        assert not compiled.search("xabc")
        assert not compiled.search("abcx")

    def test_compile_pattern_escaped_dollar_preserved(self):
        compiled = minischema.compile_pattern(r"^cost\$")
        assert compiled.pattern == r"^cost\$"
        assert compiled.search("cost$")
        assert compiled.search("cost$\n")

    def test_compile_pattern_dollar_in_character_class_preserved(self):
        compiled = minischema.compile_pattern(r"^a[$]b$")
        assert compiled.pattern == r"^a[$]b\Z"
        assert compiled.search("a$b")
        assert not compiled.search("a$b\n")

    def test_compile_pattern_negated_class_with_dollar(self):
        compiled = minischema.compile_pattern(r"^[^$]+$")
        assert compiled.pattern == r"^[^$]+\Z"
        assert compiled.search("abc")
        assert not compiled.search("a$b")

    def test_compile_pattern_bracket_start_variations(self):
        # Class starting with literal ']'
        c1 = minischema.compile_pattern(r"^[]$]+$")
        assert c1.pattern == r"^[]$]+\Z"
        assert c1.search("]$$]")
        assert not c1.search("abc")

        # Inverted class starting with literal ']'
        c2 = minischema.compile_pattern(r"^[^]$]+$")
        assert c2.pattern == r"^[^]$]+\Z"
        assert c2.search("abc")
        assert not c2.search("]")
        assert not c2.search("$")

    def test_compile_pattern_escaped_brackets_in_class(self):
        compiled = minischema.compile_pattern(r"^[a\]$]+$")
        assert compiled.pattern == r"^[a\]$]+\Z"
        assert compiled.search("a]$$")
        assert not compiled.search("b")

    def test_compile_pattern_multiple_alternation_anchors(self):
        compiled = minischema.compile_pattern(r"^(?:first$|second$)")
        assert compiled.pattern == r"^(?:first\Z|second\Z)"
        assert compiled.search("first")
        assert compiled.search("second")
        assert not compiled.search("first\n")
        assert not compiled.search("second\n")

    def test_compile_pattern_double_and_triple_escaped_slashes(self):
        # Two backslashes followed by dollar: literal \ followed by anchor $
        c2 = minischema.compile_pattern(r"^x\\$")
        assert c2.pattern == r"^x\\\Z"
        assert c2.search("x\\")
        assert not c2.search("x\\\n")

        # Three backslashes followed by dollar: literal \ followed by literal \$
        c3 = minischema.compile_pattern(r"^x\\\$")
        assert c3.pattern == r"^x\\\$"
        assert c3.search("x\\$")

        # Four backslashes followed by dollar: literal \\ followed by anchor $
        c4 = minischema.compile_pattern(r"^x\\\\$")
        assert c4.pattern == r"^x\\\\\Z"
        assert c4.search("x\\\\")
        assert not c4.search("x\\\\\n")

    def test_compile_pattern_lookaround_anchors(self):
        c_lookahead = minischema.compile_pattern(r"^(?=.*$).+$")
        assert c_lookahead.pattern == r"^(?=.*\Z).+\Z"
        assert c_lookahead.search("hello")
        assert not c_lookahead.search("hello\n")
