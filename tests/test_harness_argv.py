"""Tests for the `argv` harness entry style (CLI main(argc, argv)) in scripts/generate_harness.py."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

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


# mpack run-3, module sax_example: the module header (examples/sax-example.h) declares the module's
# API but not main, which lives in examples/sax-example.c.
SAX_H = """\
#ifndef SAX_H
#define SAX_H
#include <stddef.h>
int parse_blob(const char *data, size_t length);
#endif
"""

SAX_C = """\
#include <string.h>
#include "sax.h"

int parse_blob(const char *data, size_t length) {
    return length > 0 && data[0] == 'x';
}

int main(int argc, char** argv) {
    if (argc > 1) {
        return parse_blob(argv[1], strlen(argv[1]));
    }
    return 0;
}
"""


def _sax_workspace(tmp_path: Path, monkeypatch, header: str = SAX_H, source: str = SAX_C) -> Path:
    # Sources and -I directories are run-relative, as in a real run.
    monkeypatch.chdir(tmp_path)
    work = tmp_path / "workspace" / "work"
    work.mkdir(parents=True)
    (work / "sax.h").write_text(header, encoding="utf-8")
    (work / "sax.c").write_text(source, encoding="utf-8")
    return tmp_path


def _sax_harness(run: Path) -> tuple[dict, str]:
    harnesses = run / "workspace" / "harnesses"
    res = generate_module_harness(
        module_name="sax_example",
        sources=["workspace/work/sax.c"],
        header_include="sax.h",
        entry_fn="main",
        max_input_size=256,
        cppflags="-Iworkspace/work",
        out_dir=harnesses,
        entry_style="argv",
        auto_prelude=False,
    )
    return res, (harnesses / "harness_sax_example.c").read_text(encoding="utf-8")


def _main_declarations(text: str) -> list[str]:
    return [ln.strip() for ln in text.splitlines() if ln.strip().startswith("int main(") and ln.strip().endswith(";")]


def test_argv_harness_declares_main_when_the_module_header_does_not(tmp_path, monkeypatch):
    _, text = _sax_harness(_sax_workspace(tmp_path, monkeypatch))
    assert _main_declarations(text) == ["int main(int argc, char** argv);"]
    decl_at = text.index("int main(int argc, char** argv);")
    # After the module header (so its types are known), before both calls (Eva and fuzz).
    assert text.index('#include "sax.h"') < decl_at < text.index("main(argc, argv);")
    assert decl_at < text.index("main(2, argv);")


def test_argv_harness_declaration_follows_the_target_definition(tmp_path, monkeypatch):
    # A `const char *argv[]` main: the canonical `char **argv` prototype would conflict with it.
    source = SAX_C.replace("int main(int argc, char** argv)", "int main(int argc, const char *argv[])")
    _, text = _sax_harness(_sax_workspace(tmp_path, monkeypatch, source=source))
    assert _main_declarations(text) == ["int main(int argc, const char *argv[]);"]


def test_argv_harness_declares_canonical_main_when_the_definition_is_not_found(tmp_path, monkeypatch):
    run = _sax_workspace(tmp_path, monkeypatch)
    harnesses = run / "workspace" / "harnesses"
    generate_module_harness(
        module_name="sax_example",
        sources=["workspace/work/missing.c"],
        header_include="sax.h",
        entry_fn="main",
        max_input_size=256,
        cppflags="-Iworkspace/work",
        out_dir=harnesses,
        entry_style="argv",
        auto_prelude=False,
    )
    text = (harnesses / "harness_sax_example.c").read_text(encoding="utf-8")
    assert _main_declarations(text) == ["int main(int argc, char **argv);"]


def test_argv_harness_keeps_the_module_header_declaration_of_main(tmp_path, monkeypatch):
    header = SAX_H.replace("#endif", "int main(int, char *[]);\n#endif")
    _, text = _sax_harness(_sax_workspace(tmp_path, monkeypatch, header=header))
    # The header's own declaration is the only one: the harness adds none beside it.
    assert _main_declarations(text) == []


def test_argv_harness_declaration_stays_below_the_prelude_headers(tmp_path, monkeypatch):
    # The module header needs a type from a sibling header it never includes: the auto-prelude
    # inserts that header before it, and main's declaration stays below both.
    header = SAX_H.replace("size_t length", "blob_len_t length")
    source = SAX_C.replace('#include "sax.h"', '#include "types.h"\n#include "sax.h"').replace(
        "size_t length", "blob_len_t length"
    )
    run = _sax_workspace(tmp_path, monkeypatch, header=header, source=source)
    (run / "workspace" / "work" / "types.h").write_text("typedef unsigned long blob_len_t;\n", encoding="utf-8")
    snapshots: list[str] = []

    def clang(cmd, **kwargs):
        text = Path(cmd[-1]).read_text(encoding="utf-8")
        snapshots.append(text)
        stderr = (
            "" if '#include "types.h"' in text else "workspace/work/sax.h:4:28: error: unknown type name 'blob_len_t'\n"
        )
        return subprocess.CompletedProcess(cmd, 1 if stderr else 0, stdout="", stderr=stderr)

    res = generate_module_harness(
        module_name="sax_example",
        sources=["workspace/work/sax.c"],
        header_include="sax.h",
        entry_fn="main",
        max_input_size=256,
        cppflags="-Iworkspace/work",
        out_dir=run / "workspace" / "harnesses",
        entry_style="argv",
        prelude_clang="clang",
        prelude_runner=clang,
    )
    assert res["prelude_headers"] == ["types.h"]
    text = (run / "workspace" / "harnesses" / "harness_sax_example.c").read_text(encoding="utf-8")
    assert _main_declarations(text) == ["int main(int argc, char** argv);"]
    types_at, header_at = text.index('#include "types.h"'), text.index('#include "sax.h"')
    assert types_at < header_at < text.index("int main(int argc, char** argv);") < text.index("main(argc, argv);")


def test_argv_style_refuses_a_main_void_seen_only_in_the_module_header(tmp_path, monkeypatch):
    # The definition is not among the sources: the header's `int main(void)` decides.
    header = SAX_H.replace("#endif", "int main(void);\n#endif")
    run = _sax_workspace(tmp_path, monkeypatch, header=header)
    out = run / "workspace" / "harnesses"
    with pytest.raises(ValueError, match="takes no arguments"):
        generate_module_harness(
            module_name="sax_example",
            sources=["workspace/work/missing.c"],
            header_include="sax.h",
            entry_fn="main",
            max_input_size=256,
            cppflags="-Iworkspace/work",
            out_dir=out,
            entry_style="argv",
            auto_prelude=False,
        )
    assert not (out / "harness_sax_example.c").exists()
    assert not (out / "harness_sax_example.json").exists()


def test_argv_style_refuses_a_main_void_with_a_module_header(tmp_path, monkeypatch):
    header = SAX_H.replace("#endif", "int main(void);\n#endif")
    source = SAX_C.replace(
        "int main(int argc, char** argv) {\n    if (argc > 1) {\n        return parse_blob(argv[1], strlen(argv[1]));\n    }",
        "int main(void) {",
    )
    run = _sax_workspace(tmp_path, monkeypatch, header=header, source=source)
    out = run / "workspace" / "harnesses"
    with pytest.raises(ValueError, match="harness_reach.py exempt --module sax_example"):
        generate_module_harness(
            module_name="sax_example",
            sources=["workspace/work/sax.c"],
            header_include="sax.h",
            entry_fn="main",
            max_input_size=256,
            cppflags="-Iworkspace/work",
            out_dir=out,
            entry_style="argv",
            auto_prelude=False,
        )
    assert not (out / "harness_sax_example.c").exists()
    assert not (out / "harness_sax_example.json").exists()


def test_argv_harness_with_header_compiles_without_implicit_declaration(tmp_path, monkeypatch):
    """The mpack sax_example shape compiles with the sidecar cppflags and implicit declarations as errors."""
    cc = shutil.which("clang") or shutil.which("gcc")
    if cc is None:
        import pytest

        pytest.skip("no C compiler available")
    run = _sax_workspace(tmp_path, monkeypatch)
    res, _ = _sax_harness(run)
    proc = subprocess.run(
        [
            cc,
            "-fsyntax-only",
            "-Werror=implicit-function-declaration",
            "-D__FRAMAC_EACSL__",
            *res["cppflags"].split(),
            str(run / "workspace/harnesses/harness_sax_example.c"),
            str(run / "workspace/work/sax.c"),
        ],
        capture_output=True,
        text=True,
        cwd=run,
    )
    assert proc.returncode == 0, proc.stderr


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
