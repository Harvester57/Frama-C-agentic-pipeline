"""
Adversarial empirical stress-tests for Milestone M4 (Workstream R2).
Author: challenger_m4_1
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import api_harness as ah
import eacsl_toolchain as et
import generate_harness
import pipeline_make as pm
import run_eacsl_fuzz as rf
from fingerprint import make_fingerprint
from pipeline_make import _param_problem, _source_defines_main
from test_pipeline_make import ACSL, _make_run

# ===========================================================================
# 1. Stress-test `main(` collision detection
# ===========================================================================


class TestMainCollisionDetection:
    """Stress-test regex and detection logic for main( collisions."""

    @pytest.mark.parametrize(
        "content,expected",
        [
            ("int main(int argc, char **argv) { return 0; }", True),
            ("int main(void)\n{\n    return 0;\n}", True),
            ("int\nmain\n(\nint argc\n,\nchar **argv\n)\n{\nreturn 0;\n}", True),
            ("int main() { return 0; }", True),
            ("void main(void) {}", True),
            ("/* int main(int argc, char **argv) { return 0; } */", False),
            ("// int main(void) { return 0; }", False),
            ("int domain(int argc, char **argv) { return 0; }", False),
            ("void check_domain(void) {}", False),
            ("int main_entry(void) { return 0; }", False),
            ('const char *msg = "Error in main(): check logs";', False),
            ('const char *code = "Calling main() in thread";', False),
            ("int main(void);", False),
            ("int main(int argc, char **argv);", False),
            ("int wrapper(void) { return main(0, (void*)0); }", False),
            ("struct Config { int main; } cfg;", False),
            ("int f(void) { int main = 1; return main; }", False),
            (
                'const char *str = "void main(int x, char *y[]) {";',
                False,
            ),  # Literal masking prevents false positives on string literals
        ],
    )
    def test_source_defines_main_unit(self, tmp_path: Path, content: str, expected: bool):
        src_file = tmp_path / "test.c"
        src_file.write_text(content, encoding="utf-8")
        assert _source_defines_main(src_file) is expected

    def test_pipeline_make_adds_dmain_flag_only_when_main_defined(self, tmp_path: Path):
        """Verify pipeline_make adds -Dmain=__framac_module_main_<mod> ONLY when main is defined."""
        run = _make_run(tmp_path)

        # Module 1: cfg defines actual main
        cfg_c = run / "workspace/work/src/cfg/parse.c"
        cfg_c.write_text(
            "int main(int argc, char **argv) {\n    return 0;\n}\n",
            encoding="utf-8",
        )

        # Module 2: snmp has comment-only main and domain()
        snmp_c = run / "workspace/work/src/snmp/pdu.c"
        snmp_c.write_text(
            "/* int main() { return 0; } */\n"
            "// int main(void) {}\n"
            'const char *msg = "main() called";\n'
            "int domain(int x) { return x * 2; }\n",
            encoding="utf-8",
        )

        plan = pm.build_plan(run, templates_dir=ACSL)

        # cfg MUST have -Dmain=__framac_module_main_cfg
        assert any("-Dmain=__framac_module_main_cfg" in tok for tok in plan.modules["cfg"].cppflags)

        # snmp MUST NOT have -Dmain=
        assert not any("-Dmain=" in tok for tok in plan.modules["snmp"].cppflags)

    def test_generate_harness_adds_dmain_flag_only_when_main_defined(self, tmp_path: Path):
        """Verify generate_harness adds -Dmain=__framac_module_main_<mod> ONLY when main is defined."""
        out_dir = tmp_path / "workspace/harnesses"
        src_dir = tmp_path / "src"
        src_dir.mkdir(parents=True)

        # Target with main(void)\n{
        main_c = src_dir / "has_main.c"
        main_c.write_text("int main(void)\n{\n    return 0;\n}\n", encoding="utf-8")
        (src_dir / "has_main.h").write_text("int main(void);\n", encoding="utf-8")

        generate_harness.generate_module_harness(
            module_name="has_main",
            sources=[str(main_c)],
            header_include="has_main.h",
            entry_fn="main",
            max_input_size=128,
            cppflags="-Isrc",
            out_dir=out_dir,
            include_source=False,
        )
        sidecar_main = json.loads((out_dir / "harness_has_main.json").read_text(encoding="utf-8"))
        assert "-Dmain=__framac_module_main_has_main" in sidecar_main["cppflags"]

        # Target with domain() and string literal "main()"
        no_main_c = src_dir / "no_main.c"
        no_main_c.write_text(
            'const char *err = "error in main()";\nint domain(int x) { return x + 1; }\n',
            encoding="utf-8",
        )
        (src_dir / "no_main.h").write_text("int domain(int x);\n", encoding="utf-8")

        generate_harness.generate_module_harness(
            module_name="no_main",
            sources=[str(no_main_c)],
            header_include="no_main.h",
            entry_fn="domain",
            max_input_size=128,
            cppflags="-Isrc",
            out_dir=out_dir,
            include_source=False,
        )
        sidecar_nomain = json.loads((out_dir / "harness_no_main.json").read_text(encoding="utf-8"))
        assert "-Dmain=" not in sidecar_nomain["cppflags"]


# ===========================================================================
# 2. Stress-test `pipeline_make.py` parameters
# ===========================================================================


class TestPipelineMakeParameters:
    """Stress-test validation and clearing of fuzz_engine, wp_exclude_files, wp_extra_sources."""

    @pytest.mark.parametrize(
        "engine,valid",
        [
            ("auto", True),
            ("eacsl", True),
            ("sanitizers", True),
            ("invalid_engine", False),
            ("AUTO", False),
            ("eacsl ", False),
            ("sanitizers\n", False),
            ("", False),  # empty str is invalid value directly; clearing is handled in params_set
            (123, False),
            (None, False),
            (["auto"], False),
        ],
    )
    def test_fuzz_engine_validation(self, engine, valid):
        prob = _param_problem("fuzz_engine", engine)
        if valid:
            assert prob is None
        else:
            assert prob is not None
            assert "must be one of: 'auto', 'eacsl', 'sanitizers'" in prob

    @pytest.mark.parametrize("key", ["wp_exclude_files", "wp_extra_sources"])
    @pytest.mark.parametrize(
        "val,valid",
        [
            ([], True),
            (["src/a.c"], True),
            (["src/a.c", "src/b.c", "include/c.h"], True),
            ("src/a.c", False),  # string not list
            (123, False),
            ({"src/a.c": 1}, False),
            (None, False),
            ([""], False),  # empty item
            (["-flag.c"], False),  # starts with dash
            (["src/\na.c"], False),  # newline
            (["src/\ra.c"], False),  # carriage return
            (["src/\0a.c"], False),  # null byte
            ([123], False),  # non-string item
            ([None], False),  # None item
            (["src/a.c", ""], False),  # one good, one bad
        ],
    )
    def test_wp_file_lists_validation(self, key, val, valid):
        prob = _param_problem(key, val)
        if valid:
            assert prob is None
        else:
            assert prob is not None
            assert "must be a list of file paths" in prob

    def test_params_set_rejects_invalid_values(self, tmp_path: Path):
        run = _make_run(tmp_path)

        # Invalid fuzz_engine
        with pytest.raises(ValueError, match="must be one of: 'auto', 'eacsl', 'sanitizers'"):
            pm.params_set(run, "snmp", fuzz_engine="invalid_engine")

        # Invalid wp_exclude_files type
        with pytest.raises(ValueError, match="must be a list of file paths"):
            pm.params_set(run, "snmp", wp_exclude_files="not_a_list")

        # Invalid wp_extra_sources items
        with pytest.raises(ValueError, match="must be a list of file paths"):
            pm.params_set(run, "snmp", wp_extra_sources=["-dash_option.c"])

    def test_cli_clear_wp_file_lists(self, tmp_path: Path, capsys):
        run = _make_run(tmp_path)

        # Set them first
        rc = pm.main(
            [
                "--run-dir",
                str(run),
                "params",
                "set",
                "--module",
                "snmp",
                "--wp-exclude-files",
                "src/snmp/ber.c",
                "--wp-extra-sources",
                "src/util/str.c",
            ]
        )
        assert rc == 0
        out1 = json.loads(capsys.readouterr().out)
        assert out1["overrides"]["wp_exclude_files"] == ["src/snmp/ber.c"]
        assert out1["overrides"]["wp_extra_sources"] == ["src/util/str.c"]

        # Clear them via empty flag
        rc2 = pm.main(
            [
                "--run-dir",
                str(run),
                "params",
                "set",
                "--module",
                "snmp",
                "--wp-exclude-files",
                "--wp-extra-sources",
            ]
        )
        assert rc2 == 0
        out2 = json.loads(capsys.readouterr().out)
        assert "wp_exclude_files" not in out2["overrides"]
        assert "wp_extra_sources" not in out2["overrides"]
        assert out2["effective"]["wp_exclude_files"] == []
        assert out2["effective"]["wp_extra_sources"] == []

    def test_cli_rejects_invalid_fuzz_engine(self, tmp_path: Path):
        run = _make_run(tmp_path)

        with pytest.raises(SystemExit):
            pm.main(
                [
                    "--run-dir",
                    str(run),
                    "params",
                    "set",
                    "--module",
                    "snmp",
                    "--fuzz-engine",
                    "invalid_engine",
                ]
            )


# ===========================================================================
# 3. Adversarial Stress-Tests: A4 Error Location Parsing
# ===========================================================================


class TestA4ErrorLocationParsing:
    """Stress-test error location parsing for UBSan/E-ACSL with unusual file paths."""

    @pytest.mark.parametrize(
        "log,exp_file,exp_line,exp_fn",
        [
            (
                "src/parser/grammar.y: In function 'yyparse'\n"
                "src/parser/grammar.y:128: Error: Assertion failed:\n"
                "\tThe failing predicate is:\n\trte/index_bound:\n\t\ti < 8.\n",
                "src/parser/grammar.y",
                128,
                "yyparse",
            ),
            (
                "C:\\project\\src\\tables.inc: In function 'parse_inc'\n"
                "C:\\project\\src\\tables.inc:42:5: Error: Assertion failed:\n"
                "\tThe failing predicate is:\n\tlen > 0.\n",
                "C:\\project\\src\\tables.inc",
                42,
                "parse_inc",
            ),
            (
                "d:\\build\\scanner.l: In function 'yylex'\n"
                "d:\\build\\scanner.l:99: Error: Assertion failed:\n"
                "\tThe failing predicate is:\n\ttok != 0.\n",
                "d:\\build\\scanner.l",
                99,
                "yylex",
            ),
            (
                "extensionless_file: In function 'bare_fn'\n"
                "extensionless_file:15:1: Error: Assertion failed:\n"
                "\tThe failing predicate is:\n\tx == 1.\n",
                "extensionless_file",
                15,
                "bare_fn",
            ),
            (
                "../sub/module.cpp: In function 'cpp_func'\n"
                "../sub/module.cpp:200: Error: Assertion failed:\n"
                "\tThe failing predicate is:\n\ts != 0.\n",
                "../sub/module.cpp",
                200,
                "cpp_func",
            ),
            (
                "include/header.hpp: In function 'hpp_func'\n"
                "include/header.hpp:35:12: Error: Assertion failed:\n"
                "\tThe failing predicate is:\n\tk > 0.\n",
                "include/header.hpp",
                35,
                "hpp_func",
            ),
        ],
    )
    def test_eacsl_new_style_adversarial_paths(self, log, exp_file, exp_line, exp_fn):
        res = rf.parse_eacsl_failure(log)
        assert res is not None
        assert res["file"] == exp_file
        assert res["line"] == exp_line
        assert res["function"] == exp_fn

    @pytest.mark.parametrize(
        "log,exp_file,exp_line,exp_fn",
        [
            (
                "Assertion failed at line 42 in file C:\\proj\\tables.inc in function parse_hdr.\n"
                "The failing predicate is:\nlen <= 64.\n",
                "C:\\proj\\tables.inc",
                42,
                "parse_hdr",
            ),
            (
                "Assertion failed at line 10 in file src/parser.y.\nThe failing predicate is:\nx == 0.\n",
                "src/parser.y",
                10,
                "unknown_function",
            ),
            (
                "Assertion failed at line 88 in file extensionless_script in function run_step.\n"
                "The failing predicate is:\nrc == 0.\n",
                "extensionless_script",
                88,
                "run_step",
            ),
            (
                "Assertion failed at line 17 in file ../relative/helper.cc in function helper_fn.\n"
                "The failing predicate is:\nptr != 0.\n",
                "../relative/helper.cc",
                17,
                "helper_fn",
            ),
        ],
    )
    def test_eacsl_old_style_adversarial_paths(self, log, exp_file, exp_line, exp_fn):
        res = rf.parse_eacsl_failure(log)
        assert res is not None
        assert res["file"] == exp_file
        assert res["line"] == exp_line
        assert res["function"] == exp_fn

    @pytest.mark.parametrize(
        "log,exp_file,exp_line,exp_alarm",
        [
            (
                "src/attr_tables.inc:41:9: runtime error: load of null pointer of type 'const int'\n",
                "src/attr_tables.inc",
                41,
                "mem_access",
            ),
            (
                "C:\\workspace\\helper.cpp:100:5: runtime error: signed integer overflow: 2147483640 + 10 cannot be represented in type 'int'\n",
                "C:\\workspace\\helper.cpp",
                100,
                "signed_overflow",
            ),
            (
                "../shared/math.tcc:55: runtime error: division by zero\n",
                "../shared/math.tcc",
                55,
                "division_by_zero",
            ),
            (
                "extensionless:12:3: runtime error: shift exponent 32 is too large for 32-bit type 'int'\n",
                "extensionless",
                12,
                "shift",
            ),
        ],
    )
    def test_ubsan_adversarial_paths(self, log, exp_file, exp_line, exp_alarm):
        res = rf.parse_sanitizer_failure(log)
        assert res is not None
        assert res["file"] == exp_file
        assert res["line"] == exp_line
        assert res["alarm_kind"] == exp_alarm


# ===========================================================================
# 4. Adversarial Stress-Tests: A5 Stack Frame Attribution
# ===========================================================================


class TestA5StackFrameAttribution:
    """Stress-test stack frame attribution decoupled from file and line."""

    def test_stack_frame_without_file_attributes_function(self):
        log = (
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000014\n"
            "READ of size 4 at 0x602000000014\n"
            "    #0 0x5555555c9876 in parse_attr (/workspace/guard.bin+0x4f1)\n"
        )
        res = rf.parse_sanitizer_failure(log)
        assert res is not None
        assert res["function"] == "parse_attr"
        assert res["file"] == "unknown"
        assert res["line"] == 0

    def test_stack_frame_with_hex_address_only(self):
        log = "==1==ERROR: AddressSanitizer: SEGV on unknown address 0x0\n    #0 0x7fff1234abcd in compute_hash\n"
        res = rf.parse_sanitizer_failure(log)
        assert res is not None
        assert res["function"] == "compute_hash"
        assert res["file"] == "unknown"

    def test_stack_frame_runtime_interceptor_filtering(self):
        log = (
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x123\n"
            "WRITE of size 8 at 0x123\n"
            "    #0 0x555 in __interceptor_memmove (/lib/asan.so+0x1)\n"
            "    #1 0x556 in __asan_memcpy (/lib/asan.so+0x2)\n"
            "    #2 0x557 in my_worker /src/worker.inc:88:2\n"
            "    #3 0x558 in LLVMFuzzerTestOneInput /src/harness.c:20:1\n"
        )
        res = rf.parse_sanitizer_failure(log)
        assert res is not None
        assert res["function"] == "my_worker"
        assert res["file"] == "/src/worker.inc"
        assert res["line"] == 88

    def test_stack_frame_recursive_calls(self):
        log = (
            "==1==ERROR: AddressSanitizer: stack-overflow on address 0x123\n"
            "    #0 0x111 in recurse /src/tree.c:10:5\n"
            "    #1 0x222 in recurse /src/tree.c:15:5\n"
            "    #2 0x333 in main /src/main.c:5:1\n"
        )
        res = rf.parse_sanitizer_failure(log)
        assert res is not None
        assert res["function"] == "recurse"
        assert res["line"] == 10

    def test_stack_frame_fail_closed_on_empty_and_garbage(self):
        assert rf.parse_sanitizer_failure("") is None
        assert rf.parse_sanitizer_failure("completely arbitrary output with no errors") is None
        assert rf.parse_eacsl_failure("") is None
        assert rf.parse_runtime_failure("") is None


# ===========================================================================
# 5. Adversarial Stress-Tests: D1 Multi-word ASan Kinds
# ===========================================================================


class TestD1MultiWordAsanKinds:
    """Stress-test matching multi-word AddressSanitizer error kinds."""

    @pytest.mark.parametrize(
        "header,exp_kind,exp_alarm",
        [
            (
                "ERROR: AddressSanitizer: attempting double-free on address 0x1234",
                "asan_attempting_double_free",
                "freeable",
            ),
            (
                "ERROR: AddressSanitizer: attempting free on address which was not malloc()-ed: 0x1234",
                "asan_attempting_free_on_address_which_was_not_malloc_ed",
                "freeable",
            ),
            (
                "ERROR: AddressSanitizer: requested allocation size 0x7fffffffffffffff exceeds maximum supported size",
                "asan_requested_allocation_size",
                "mem_access",
            ),
            (
                "ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1234",
                "asan_heap_buffer_overflow",
                "mem_access",
            ),
            (
                "ERROR: AddressSanitizer: stack-buffer-overflow on address 0x1234",
                "asan_stack_buffer_overflow",
                "mem_access",
            ),
            (
                "ERROR: AddressSanitizer: global-buffer-overflow on address 0x1234",
                "asan_global_buffer_overflow",
                "mem_access",
            ),
            (
                "ERROR: AddressSanitizer: heap-use-after-free on address 0x1234",
                "asan_heap_use_after_free",
                "dangling_pointer",
            ),
            (
                "ERROR: AddressSanitizer: initialization-order-fiasco on address 0x1234",
                "asan_initialization_order_fiasco",
                "mem_access",
            ),
        ],
    )
    def test_asan_multi_word_kinds_and_slugs(self, header, exp_kind, exp_alarm):
        log = f"==1=={header}\n    #0 0x1 in func /src/test.c:10:1\n"
        res = rf.parse_sanitizer_failure(log)
        assert res is not None
        assert res["kind"] == exp_kind
        assert res["alarm_kind"] == exp_alarm


# ===========================================================================
# 6. Adversarial Stress-Tests: D2 Access Size Normalization
# ===========================================================================


class TestD2AccessSizeNormalization:
    """Stress-test byte access size stripping from ASan predicates and fingerprints."""

    @pytest.mark.parametrize("size", [1, 2, 4, 8, 16, 32, 64])
    def test_read_access_sizes_fingerprint_identically(self, size):
        log1 = (
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x123\n"
            f"READ of size {size} at 0x123\n"
            "    #0 0x1 in target_fn /src/buf.c:20:5\n"
        )
        log_base = (
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x123\n"
            "READ of size 4 at 0x123\n"
            "    #0 0x1 in target_fn /src/buf.c:20:5\n"
        )
        res1 = rf.parse_sanitizer_failure(log1)
        res_base = rf.parse_sanitizer_failure(log_base)
        assert res1 is not None and res_base is not None
        assert res1["predicate"] == "rte: mem_access: AddressSanitizer: heap-buffer-overflow (READ)"
        fp1 = make_fingerprint(res1["file"], res1["function"], res1["alarm_kind"], res1["predicate"])
        fp_base = make_fingerprint(
            res_base["file"], res_base["function"], res_base["alarm_kind"], res_base["predicate"]
        )
        assert fp1 == fp_base

    @pytest.mark.parametrize("size", [1, 2, 4, 8, 16, 32, 64])
    def test_write_access_sizes_fingerprint_identically(self, size):
        log1 = (
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x123\n"
            f"WRITE of size {size} at 0x123\n"
            "    #0 0x1 in target_fn /src/buf.c:20:5\n"
        )
        log_base = (
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x123\n"
            "WRITE of size 8 at 0x123\n"
            "    #0 0x1 in target_fn /src/buf.c:20:5\n"
        )
        res1 = rf.parse_sanitizer_failure(log1)
        res_base = rf.parse_sanitizer_failure(log_base)
        assert res1 is not None and res_base is not None
        assert res1["predicate"] == "rte: mem_access: AddressSanitizer: heap-buffer-overflow (WRITE)"
        fp1 = make_fingerprint(res1["file"], res1["function"], res1["alarm_kind"], res1["predicate"])
        fp_base = make_fingerprint(
            res_base["file"], res_base["function"], res_base["alarm_kind"], res_base["predicate"]
        )
        assert fp1 == fp_base

    def test_read_and_write_fingerprints_differ(self):
        log_r = (
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x123\n"
            "READ of size 4 at 0x123\n"
            "    #0 0x1 in target_fn /src/buf.c:20:5\n"
        )
        log_w = (
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x123\n"
            "WRITE of size 4 at 0x123\n"
            "    #0 0x1 in target_fn /src/buf.c:20:5\n"
        )
        res_r = rf.parse_sanitizer_failure(log_r)
        res_w = rf.parse_sanitizer_failure(log_w)
        assert res_r is not None and res_w is not None
        fp_r = make_fingerprint(res_r["file"], res_r["function"], res_r["alarm_kind"], res_r["predicate"])
        fp_w = make_fingerprint(res_w["file"], res_w["function"], res_w["alarm_kind"], res_w["predicate"])
        assert fp_r != fp_w


# ===========================================================================
# 7. Adversarial Stress-Tests: D3 LLD Linker Diagnostics
# ===========================================================================


class TestD3LldLinkerDiagnostics:
    """Stress-test parsing linker diagnostics from GNU ld and LLVM lld."""

    def test_parse_undefined_references_formats_and_prefixes(self):
        log = (
            "ld.lld: error: undefined symbol: custom_init\n"
            ">>> referenced by init.c:12\n"
            "ld.lld: error: undefined symbol: 'single_quoted'\n"
            'ld.lld: error: undefined symbol: "double_quoted"\n'
            "ld.lld: error: undefined symbol:   extra_spaces\n"
            "ld.lld: error: undefined symbol:\ttabs_before\n"
            "ld.lld: error: undefined symbol: _my_func\n"
            "ld.lld: error: undefined symbol: __custom_init\n"
            "ld.lld: error: undefined symbol: ___triple_under\n"
            "ld.lld: error: undefined symbol: _Z3barv\n"
            "/usr/bin/ld: foo.o: in function 'main':\n"
            "foo.c:(.text+0x10): undefined reference to 'gnu_ld_sym'\n"
            "foo.c:(.text+0x20): undefined reference to `backtick_sym'\n"
            'foo.c:(.text+0x30): undefined reference to "double_ld_sym"\n'
            "ld.lld: error: undefined symbol: custom_init\n"
        )
        refs = rf.parse_undefined_references(log)
        expected = [
            "custom_init",
            "single_quoted",
            "double_quoted",
            "extra_spaces",
            "tabs_before",
            "_my_func",
            "__custom_init",
            "___triple_under",
            "_Z3barv",
            "gnu_ld_sym",
            "backtick_sym",
            "double_ld_sym",
        ]
        assert refs == expected

    def test_parse_undefined_fallbacks_formats_and_deduplication(self):
        log = (
            "ld.lld: error: undefined symbol: snprintf_va_3\n"
            ">>> referenced by fuzz_transport.c:123\n"
            "ld.lld: error: undefined symbol: 'open_fallback_1'\n"
            "ld.lld: error: undefined symbol:    fcntl_fallback_2\n"
            "undefined reference to 'syslog_fallback_0'\n"
            "undefined reference to `printf_va_1'\n"
            "ld.lld: error: undefined symbol: not_a_fallback_sym\n"
            "ld.lld: error: undefined symbol: snprintf_va_3\n"
        )
        fallbacks = et.parse_undefined_fallbacks(log)
        assert fallbacks == ["snprintf_va_3", "open_fallback_1", "fcntl_fallback_2", "syslog_fallback_0", "printf_va_1"]


# ===========================================================================
# 8. Adversarial Stress-Tests: D4 Libc Call Site Detection
# ===========================================================================


class TestD4LibcCallSiteDetection:
    """Stress-test detecting libc calls in complex statements and macros."""

    def test_find_errno_shim_calls_in_complex_c_constructs(self):
        code = (
            "int __fc_eacsl_errno;\n"
            "extern int close(int fd);\n"
            "extern ssize_t read(int fd, void *buf, size_t count);\n"
            "extern int open(const char *path, int flags);\n"
            "void test_calls(int fd, char *buf) {\n"
            "    int r1 = (fd >= 0) ? close(fd) : -1;\n"
            "    int r2 = (fd < 0) ? -1 : close(fd);\n"
            "    return (\n"
            "        close(fd)\n"
            "    );\n"
            "    if (!close(fd)) {}\n"
            "    if (fd > 0 && close(fd) == 0) {}\n"
            "    if (fd <= 0 || close(fd) != 0) {}\n"
            "    while (read(fd, buf, 10) > 0) {}\n"
            "    switch (read(fd, buf, 1)) {}\n"
            "    ssize_t s = (ssize_t)read(fd, buf, 4);\n"
            "}\n"
        )
        calls = et.find_errno_shim_calls(code)
        assert "close" in calls
        assert "read" in calls

    def test_unshimmed_libc_calls_emit_warning(self, tmp_path):
        src = tmp_path / "test_unshimmed.c"
        src.write_text("void f(int fd) { close(fd); }\n", encoding="utf-8")
        with pytest.warns(UserWarning, match="libc call.*without errno shim.*close"):
            res = et.build_errno_shim_object(src, tmp_path / "shim_out")
        assert res["status"] == "none"
        assert res.get("unshimmed") == ["close"]


# ===========================================================================
# 9. Adversarial Stress-Tests: D5 Store Block Suffix Variations
# ===========================================================================


class TestD5StoreBlockSuffixVariations:
    """Stress-test store block integer suffix variations and fallback warnings."""

    @pytest.mark.parametrize(
        "suffix",
        ["0UL", "100ULL", "20U", "30L", "40", "0u", "100ull", "20u", "30l", "0Lu", "0uL", "0LLU"],
    )
    def test_mark_formals_and_readonly_support_all_suffixes(self, suffix):
        src = f"int f_struct(int k)\n{{\n  __e_acsl_store_block((void *)(& k),{suffix});\n  return k + 1;\n}}\n"
        patched, n = et.mark_formals_initialized(src)
        assert n == 1
        assert "__e_acsl_full_init((void *)(& k));" in patched

        src_ro = (
            f"  __e_acsl_store_block((void *)(& kGlobal), {suffix});\n"
            "  __e_acsl_full_init((void *)(& kGlobal));\n"
            "  __e_acsl_mark_readonly((void *)kGlobal);\n"
        )
        patched_ro, n_ro = et.fix_readonly_scalar_globals(src_ro)
        assert n_ro == 1
        assert "__e_acsl_mark_readonly((void *)(& kGlobal));" in patched_ro

    def test_store_block_unmatched_syntax_triggers_warning(self):
        bad_src = "int f(int k) {\n  __e_acsl_store_block((void *)(& k), 40xyz);\n  return k;\n}\n"
        with pytest.warns(UserWarning, match="__e_acsl_store_block lines exist in text but none matched"):
            patched_bad, n_bad = et.mark_formals_initialized(bad_src)
        assert n_bad == 0


# ===========================================================================
# 10. Adversarial Stress-Tests: D6 API Lifecycle Names
# ===========================================================================


class TestD6ApiLifecycleNames:
    """Stress-test word-bounded API lifecycle detection regexes."""

    @pytest.mark.parametrize(
        "name,is_init",
        [
            ("Freezer_Init", True),
            ("QCBORDecode_Init", True),
            ("UsefulOutBuf_Init", True),
            ("ctx_init", True),
            ("init_ctx", True),
            ("buf_new", True),
            ("bar_create", True),
            ("FooInit", True),
            ("InitContext", True),
            ("Init", True),
            ("Initialize", False),
            ("InitializeFoo", False),
            ("FooInitialize", False),
            ("my_initialize_ctx", False),
            ("InitialValue", False),
            ("Initiate", False),
            ("Primitive", False),
        ],
    )
    def test_init_name_boundaries(self, name, is_init):
        match = bool(ah._INIT_NAME_RE.search(name))
        assert match is is_init, f"Init name match mismatch for {name}: {match} != {is_init}"

    @pytest.mark.parametrize(
        "name,is_dtor",
        [
            ("DestroyAll", True),
            ("seccomp_release", True),
            ("foo_free", True),
            ("bar_destroy", True),
            ("ctx_close", True),
            ("FooFree", True),
            ("Foo_Free", True),
            ("FreeFoo", True),
            ("BarDestroy", True),
            ("DestroyBar", True),
            ("HandleRelease", True),
            ("ReleaseHandle", True),
            ("seccomp_Release", True),
            ("deinit_ctx", True),
            ("cleanup_buf", True),
            ("unref_obj", True),
            ("ReleasableBuf", False),
            ("Releasable", False),
            ("Freeze", False),
            ("Freezer", False),
            ("Freelist", False),
            ("Freedom", False),
            ("Destroyer", False),
            ("Destroying", False),
            ("Closed", False),
            ("Closet", False),
            ("Unrefined", False),
        ],
    )
    def test_dtor_name_boundaries(self, name, is_dtor):
        match = bool(ah._DTOR_NAME_RE.search(name))
        assert match is is_dtor, f"Dtor name match mismatch for {name}: {match} != {is_dtor}"
