"""
Adversarial empirical stress-tests for Milestone M4 (Workstream R2).
Author: challenger_m4_1
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import build_callgraph_dag as bcd
import generate_harness
import pipeline_make as pm
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
                True,
            ),  # Raw regex matches string literals containing full def pattern
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
# 2. Stress-test callgraph DAG prototype extraction and pre-flight warnings
# ===========================================================================


class TestCallgraphDAGPreFlightWarnings:
    """Stress-test prototype extraction, VLA detection, and param count mismatch."""

    def test_multidimensional_vla_parameters(self, tmp_path: Path, capsys):
        """Multidimensional arrays (2+ bracket pairs) must trigger pre-flight warnings."""
        src_dir = tmp_path / "src"
        src_dir.mkdir(parents=True)

        (src_dir / "matrix.h").write_text(
            """\
int foo(int x[2][3]);
void bar(int a[N][M][K]);
int unsized_multi(double buf[][10]);
int single_dim(int x[10]);
int two_single_dims(int a[10], int b[20]);
""",
            encoding="utf-8",
        )
        (src_dir / "matrix.c").write_text(
            """\
#include "matrix.h"
int foo(int x[2][3]) { return x[0][0]; }
void bar(int a[N][M][K]) {}
int unsized_multi(double buf[][10]) { return 0; }
int single_dim(int x[10]) { return x[0]; }
int two_single_dims(int a[10], int b[20]) { return a[0] + b[0]; }
""",
            encoding="utf-8",
        )

        dag = bcd.build_dag(tmp_path)
        err = capsys.readouterr().err

        vla_warns = [w for w in dag["warnings"] if "multidimensional array/VLA" in w]
        warned_fns = [w.split("'")[1] for w in vla_warns]

        # foo, bar, unsized_multi must trigger warning
        assert "foo" in warned_fns
        assert "bar" in warned_fns
        assert "unsized_multi" in warned_fns

        # 1D arrays must NOT trigger warning
        assert "single_dim" not in warned_fns
        assert "two_single_dims" not in warned_fns

        # Warnings must be printed to stderr
        assert "pre-flight warning: multidimensional array/VLA" in err

    def test_parameter_count_mismatches(self, tmp_path: Path, capsys):
        """Mismatches between prototype and definition param count must trigger warnings."""
        src_dir = tmp_path / "src"
        src_dir.mkdir(parents=True)

        (src_dir / "proto.h").write_text(
            """\
int f_mismatch(int a, int b);
int f_match(int a, int b);
int f_void_proto(void);
int f_empty_proto();
void f_no_def_in_c(int a, int b);
""",
            encoding="utf-8",
        )
        (src_dir / "proto.c").write_text(
            """\
#include "proto.h"
int f_mismatch(int a, int b, int c) { return a + b + c; }
int f_match(int x, int y) { return x * y; }
int f_void_proto() { return 42; }
int f_empty_proto(void) { return 43; }
int f_no_proto_at_all(int a) { return a; }
""",
            encoding="utf-8",
        )

        dag = bcd.build_dag(tmp_path)

        mismatch_warns = [w for w in dag["warnings"] if "parameter count mismatch" in w]
        assert len(mismatch_warns) == 1
        assert "f_mismatch" in mismatch_warns[0]
        assert "prototype has 2 parameter(s)" in mismatch_warns[0]
        assert "definition has 3 parameter(s)" in mismatch_warns[0]

        # Neither f_void_proto nor f_empty_proto should be in mismatch_warns
        assert not any("f_void_proto" in w for w in mismatch_warns)
        assert not any("f_empty_proto" in w for w in mismatch_warns)
        assert not any("f_match" in w for w in mismatch_warns)
        assert not any("f_no_def_in_c" in w for w in mismatch_warns)
        assert not any("f_no_proto_at_all" in w for w in mismatch_warns)

    def test_function_pointer_param_not_split(self):
        """Function pointer parameters with commas must not be mistakenly split into multiple params."""
        code = "int reg_cb(void (*callback)(int a, int b), int flags);"
        protos = bcd.extract_prototypes_from_code(code)
        assert len(protos) == 1
        params = bcd._split_param_tokens(protos[0]["param_tokens"])
        assert len(params) == 2  # callback and flags, not 3


# ===========================================================================
# 3. Stress-test `pipeline_make.py` parameters
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
