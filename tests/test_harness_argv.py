"""Tests for the `argv` harness entry style (CLI main(argc, argv)) in scripts/generate_harness.py."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import generate_harness
from generate_harness import _build_invocations, generate_module_harness

MAIN_C = """\
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc > 1) {
        return (int)strlen(argv[1]);
    }
    return 0;
}
"""


def _workspace(tmp_path: Path) -> Path:
    work = tmp_path / "workspace" / "work"
    work.mkdir(parents=True)
    (work / "tool.c").write_text(MAIN_C, encoding="utf-8")
    return tmp_path


def test_argv_invocations_model_upstream_eva_stubs():
    eva_call, fuzz_call = _build_invocations("main", "argv")
    # Eva side: upstream share/libc/eva_stubs.c pattern (docs/upstream/sources/eva_stubs.c).
    assert "Frama_C_interval(0, 5)" in eva_call
    assert "Frama_C_make_unknown(argv[i], 255)" in eva_call
    assert "//@ loop unroll 5;" in eva_call
    assert "main(argc, argv);" in eva_call
    # Fuzz side: the input becomes argv[1] as a NUL-terminated string.
    assert "memcpy(argv1, bounded_buf, size)" in fuzz_call
    assert 'char *argv[2] = {(char *)"prog", argv1};' in fuzz_call
    assert "main(2, argv);" in fuzz_call


def test_argv_harness_renames_target_main_in_sidecar_cppflags(tmp_path):
    run = _workspace(tmp_path)
    harnesses = run / "workspace" / "harnesses"
    res = generate_module_harness(
        module_name="tool",
        sources=["workspace/work/tool.c"],
        header_include="none",
        entry_fn="main",
        max_input_size=256,
        cppflags="-I.",
        out_dir=harnesses,
        entry_style="argv",
        auto_prelude=False,
    )
    assert res["entry_style"] == "argv"
    assert "-Dmain=__framac_target_main" in res["cppflags"]
    sidecar = json.loads((harnesses / "harness_tool.json").read_text(encoding="utf-8"))
    assert sidecar["entry_style"] == "argv"
    assert "-Dmain=__framac_target_main" in sidecar["cppflags"]
    text = (harnesses / "harness_tool.c").read_text(encoding="utf-8")
    assert "Frama_C_interval(0, 5)" in text
    assert "main(argc, argv);" in text
    assert "main(2, argv);" in text


def test_cli_defaults_to_argv_style_when_entry_is_main(tmp_path, capsys):
    run = _workspace(tmp_path)
    out = run / "workspace" / "harnesses"
    rc = generate_harness.main(
        [
            "--module",
            "tool",
            "--sources",
            "workspace/work/tool.c",
            "--header",
            "none",
            "--entry-fn",
            "main",
            "--cppflags",
            "-I.",
            "--out-dir",
            str(out),
            "--no-auto-prelude",
        ]
    )
    assert rc == 0
    res = json.loads(capsys.readouterr().out)
    assert res["entry_style"] == "argv"
    # An explicit --entry-style wins over the auto-default.
    rc = generate_harness.main(
        [
            "--module",
            "tool",
            "--sources",
            "workspace/work/tool.c",
            "--header",
            "none",
            "--entry-fn",
            "main",
            "--entry-style",
            "void_call",
            "--cppflags",
            "-I.",
            "--out-dir",
            str(out),
            "--no-auto-prelude",
        ]
    )
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["entry_style"] == "void_call"


def test_argv_harness_compiles_with_gcc(tmp_path):
    """The generated harness + target compile together with the sidecar cppflags (main renamed)."""
    cc = shutil.which("gcc") or shutil.which("clang")
    if cc is None:
        import pytest

        pytest.skip("no C compiler available")
    run = _workspace(tmp_path)
    harnesses = run / "workspace" / "harnesses"
    res = generate_module_harness(
        module_name="tool",
        sources=["workspace/work/tool.c"],
        header_include="none",
        entry_fn="main",
        max_input_size=256,
        cppflags="-I.",
        out_dir=harnesses,
        entry_style="argv",
        auto_prelude=False,
    )
    harness = harnesses / "harness_tool.c"
    # LibFuzzer branch (no __FRAMAC__): the harness must be valid C with the -D rename applied.
    proc = subprocess.run(
        [
            cc,
            "-fsyntax-only",
            "-D__FRAMAC_EACSL__",
            *res["cppflags"].split(),
            str(harness),
            str(run / "workspace/work/tool.c"),
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    # Eva branch: __FRAMAC__ defined, Frama_C_* builtins come from Frama-C's __fc_builtin.h, which
    # is not on this host, so only check the harness text carries the builtin include guard.
    text = harness.read_text(encoding="utf-8")
    assert '#include "__fc_builtin.h"' in text


# png-fix-itxt.c: K&R-style `int\nmain(void)` right after a macro whose last continuation line ends
# in `break`.
NO_ARG_MAIN_C = """\
#include <stdio.h>

/* Read one character, break on EOF */
#define GETBREAK inchar=getchar(); \
                 c=(inchar & 0xffU);\
                 if (inchar != c) break
int
main(void)
{
   int inchar; unsigned char c;
   for (;;) { GETBREAK; }
   return 0;
}
"""


def test_declaration_after_a_macro_with_continuation_lines(tmp_path):
    src = tmp_path / "png-fix-itxt.c"
    src.write_text(NO_ARG_MAIN_C, encoding="utf-8")
    assert generate_harness.extract_function_declaration("main", None, [str(src)]) == "int main(void);"
    assert generate_harness.extract_function_prototype("main", None, [str(src)]) == []


def test_declaration_head_drops_statement_keywords(tmp_path):
    src = tmp_path / "f.c"
    # A stray statement keyword left before a definition (an unbalanced macro) is not a return type.
    src.write_text("return\nunsigned long\nf(int x)\n{ return x; }\n", encoding="utf-8")
    assert generate_harness.extract_function_declaration("f", None, [str(src)]) == "unsigned long f(int x);"


def test_argv_style_refuses_a_main_without_parameters(tmp_path):
    src = tmp_path / "png-fix-itxt.c"
    src.write_text(NO_ARG_MAIN_C, encoding="utf-8")
    out = tmp_path / "harnesses"
    try:
        generate_module_harness(
            module_name="png_fix_itxt",
            sources=[str(src)],
            header_include=None,
            entry_fn="main",
            max_input_size=256,
            cppflags="-I.",
            out_dir=out,
            entry_style="argv",
            auto_prelude=False,
        )
    except ValueError as exc:
        assert "takes no arguments" in str(exc)
        assert "harness_reach.py exempt --module png_fix_itxt" in str(exc)
    else:
        raise AssertionError("an argv harness for main(void) must not be written")
    assert not (out / "harness_png_fix_itxt.c").exists()
    assert not (out / "harness_png_fix_itxt.json").exists()
