"""
Line directives in the Phase 0 model (scripts/phase0_model.py, scripts/phase0_dump.ml).

Generated sources (flex's `toke.c`, bison's `gram.c` in sudo) carry `#line` directives naming their
grammar file and themselves, relative to the directory they were generated in. Frama-C ignores a
directive whose file does not exist relative to its own working directory, and with it the return
markers cpp writes after each `#include`: the definitions that follow were located in the last header
entered (`toke.h`, a libc header) at lines counted on from there, or dropped. The model now parses such
a source from a copy with its directives blanked, and attributes a definition that a directive in a
header still moved out of its compiled source back to that source (dump schema 7 `root`).
"""

from __future__ import annotations

import json
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import phase0_model as pm  # noqa: E402
from conftest import ANALYSIS_IMAGE, BUILD_IMAGE, ROOT, require_docker_images  # noqa: E402

LD_FIXTURE = ROOT / "tests" / "fixtures" / "phase0" / "model" / "line_directives"


def _no_lines(_rel: str) -> list[str] | None:
    return None


# ---------------------------------------------------------------------------------------------------
# blank_line_directives
# ---------------------------------------------------------------------------------------------------


@pytest.mark.unit
def test_blank_line_directives_keeps_every_line_number_and_names_the_source():
    src = (
        b"#include <stdio.h>\r\n"
        b'#line 1 "gram.y"\r\n'
        b"int a;\r\n"
        b'  #  line 12 "gram.c"\r\n'
        b'# 40 "toke.l"\r\n'
        b"#line 7 \\\r\n"
        b'"split.y"\r\n'
        b"int b;\r\n"
    )
    out = pm.blank_line_directives(src, "/t/src/gram.c")
    assert out is not None
    first, rest = out.split(b"\n", 1)
    assert first == b'#line 1 "/t/src/gram.c"'
    lines = rest.split(b"\r\n")
    # Same lines at the same numbers: directives (and a continued one's second line) are empty.
    assert lines[:8] == [b"#include <stdio.h>", b"", b"int a;", b"", b"", b"", b"", b"int b;"]
    assert rest.count(b"\r\n") == src.count(b"\r\n")


@pytest.mark.unit
def test_blank_line_directives_leaves_a_source_without_directives_and_continued_text_alone():
    assert pm.blank_line_directives(b"int x;\n#include <a.h>\n#if 1\n#endif\n", "/t/a.c") is None
    # A line continuing a #define is part of the macro, not a directive of its own.
    macro = b"#define S(x) \\\n# 1\nint y;\n"
    assert pm.blank_line_directives(macro, "/t/a.c") is None


@pytest.mark.unit
def test_blank_line_directives_escapes_the_path_and_drops_a_bom():
    out = pm.blank_line_directives(b'\xef\xbb\xbf#line 2 "x.l"\nint z;\n', '/t/we"ird\\dir/a.c')
    assert out == b'#line 1 "/t/we\\"ird\\\\dir/a.c"\n\nint z;\n'


@pytest.mark.unit
def test_line_directive_copy_writes_only_sources_that_need_it(tmp_path):
    tree = tmp_path / "tree"
    (tree / "src").mkdir(parents=True)
    (tree / "src" / "plain.c").write_bytes(b"int p;\n")
    (tree / "src" / "gram.c").write_bytes(b'#line 1 "gram.y"\nint g;\n')
    dest = tmp_path / "copies"
    assert pm.line_directive_copy((tree / "src" / "plain.c").as_posix(), dest) is None
    assert pm.line_directive_copy((tree / "src" / "missing.c").as_posix(), dest) is None
    copy = pm.line_directive_copy((tree / "src" / "gram.c").as_posix(), dest)
    assert copy is not None and copy == (dest / "gram.c").as_posix()
    assert Path(copy).read_bytes() == f'#line 1 "{(tree / "src" / "gram.c").as_posix()}"\n\nint g;\n'.encode()
    assert pm.line_directive_flags("/t/src/gram.c") == ["-iquote", "/t/src"]


# ---------------------------------------------------------------------------------------------------
# attribute_definition: the rule
# ---------------------------------------------------------------------------------------------------


TOKE_H = ["#ifndef TOKE_H", "#define TOKE_H", "bool append(const char *, int);", "#endif"]
INLINE_H = ["#ifndef I_H", "static inline int twice(int a)", "{ return 2 * a; }", "#endif"]
LD_SOURCES = ["src/gram.c", "src/toke.c"]


def _lines_of(files: dict[str, list[str]]):
    return lambda rel: files.get(rel)


@pytest.mark.unit
def test_a_compiled_source_is_kept_whatever_the_directives():
    got = pm.attribute_definition("src/gram.c", "src/gram.c", 9, 20, LD_SOURCES, True, _no_lines)
    assert got == ("src/gram.c", False)


@pytest.mark.unit
def test_without_line_directives_a_header_location_is_trusted():
    # The existing behavior: no directive in play, Frama-C's location stands.
    got = pm.attribute_definition("src/toke.h", "src/gram.c", 800, 900, LD_SOURCES, False, _no_lines)
    assert got == ("src/toke.h", False)


@pytest.mark.unit
def test_a_header_left_current_by_an_ignored_directive_gives_way_to_the_compiled_source():
    # sudo run-1: gram.c's functions were `toke.h#sudoersparse` at line 800 of a 40-line header; a
    # stale position always lies past the end of the header it was left in.
    lines = _lines_of({"src/toke.h": TOKE_H})
    got = pm.attribute_definition("src/toke.h", "src/gram.c", 800, 950, LD_SOURCES, True, lines)
    assert got == ("src/gram.c", True)
    got = pm.attribute_definition("src/toke.h", "src/gram.c", 4, 5, LD_SOURCES, True, lines)
    assert got == ("src/gram.c", True)
    # A header that cannot be read holds nothing.
    assert pm.attribute_definition("src/gone.h", "src/gram.c", 1, 1, LD_SOURCES, True, _no_lines) == (
        "src/gram.c",
        True,
    )


@pytest.mark.unit
def test_a_header_or_included_source_whose_text_has_those_lines_keeps_them():
    # A header's static inline, and (sudo, in jobs that also include gram.h with its ignored
    # directives) pwutil_impl.c, included by cvtsudoers_pwutil.c with its functions renamed by macros.
    lines = _lines_of({"src/i.h": INLINE_H, "src/pwutil_impl.c": ["/* impl */"] * 400})
    got = pm.attribute_definition("src/i.h", "src/gram.c", 2, 3, LD_SOURCES, True, lines)
    assert got == ("src/i.h", False)
    got = pm.attribute_definition("src/pwutil_impl.c", "src/gram.c", 238, 344, LD_SOURCES, True, lines)
    assert got == ("src/pwutil_impl.c", False)


@pytest.mark.unit
def test_a_grammar_file_a_directive_names_is_never_the_definitions_file():
    # A directive Frama-C followed (the file exists relative to it): `gram.y` holds the action text,
    # but the build compiles gram.c. Suspect even when the job recorded no directive.
    lines = _lines_of({"src/gram.y": ["%{", "int sudoerserror(void)", "{ return 0; }", "%}"]})
    got = pm.attribute_definition("src/gram.y", "src/gram.c", 2, 3, LD_SOURCES, False, lines)
    assert got == ("src/gram.c", True)


@pytest.mark.unit
def test_outside_the_tree_or_without_a_compiled_root_nothing_moves():
    # Frama-C's libc defines functions in headers the project includes: they stay out of the model.
    assert pm.attribute_definition(None, "src/toke.c", 1168, 1168, LD_SOURCES, True, _no_lines) == (None, False)
    # A root that is no compiled source of the job (old dump: no root) leaves the location as it was.
    assert pm.attribute_definition("src/toke.h", None, 900, 901, LD_SOURCES, True, _no_lines) == (
        "src/toke.h",
        False,
    )
    assert pm.attribute_definition("src/toke.h", "src/other.c", 900, 901, LD_SOURCES, True, _no_lines) == (
        "src/toke.h",
        False,
    )


# ---------------------------------------------------------------------------------------------------
# ModelBuilder.add_dump on a recorded dump (schema 7)
# ---------------------------------------------------------------------------------------------------


def _ld_tree(tmp_path: Path) -> Path:
    tree = tmp_path / "tree"
    (tree / "src").mkdir(parents=True)
    (tree / "src" / "toke.h").write_text("\n".join(TOKE_H) + "\n", encoding="utf-8")
    (tree / "src" / "i.h").write_text("\n".join(INLINE_H) + "\n", encoding="utf-8")
    (tree / "src" / "gram.c").write_text(
        '#include "toke.h"\n#include "i.h"\nstatic int state;\nint\nparse(void)\n{\n  return state;\n}\n',
        encoding="utf-8",
    )
    return tree


def _ld_dump(tree: Path) -> dict:
    # The dump writes the root absolute; tree_rel takes a tree-relative one as well, which keeps this
    # test independent of the host's path syntax.
    root = "src/gram.c"

    def fn(name: str, loc: str, first: int, last: int, static: bool = False) -> dict:
        return {
            "kernel_name": name, "name": name, "loc": loc, "root": root, "first_line": first, "last_line": last,
            "static": static, "inline": False, "signature": "int(void)", "loops": 1, "cyclomatic": 2,
            "formals": [], "writes": {"pointer": 0, "params": [], "globals": ["state"]},
            "address_refs": [], "global_refs": ["state"], "calls": [],
        }  # fmt: skip

    return {
        "schema": 7,
        "functions": [
            fn("parse", "src/toke.h:812-815", 812, 815),
            fn("twice", "src/i.h:2-3", 2, 3, static=True),
        ],
        "declared": [],
        "address_taken": [],
        "globals": [
            {
                "name": "state",
                "kernel_name": "state",
                "loc": "src/toke.h:810",
                "root": root,
                "static": True,
                "type": "int",
                "size": 4,
                "init_functions": [],
                "init_globals": [],
            },
        ],  # fmt: skip
    }


def _ld_builder(tree: Path) -> pm.ModelBuilder:
    capture = {"units": {"libg.a": {"kind": "static_lib", "files": ["src/gram.c"], "links": []}}}
    return pm.ModelBuilder(capture, tree.as_posix())


@pytest.mark.unit
def test_add_dump_moves_a_misplaced_definition_and_global_to_the_compiled_source(tmp_path):
    tree = _ld_tree(tmp_path)
    b = _ld_builder(tree)
    b.add_dump(["libg.a"], _ld_dump(tree), sources=["src/gram.c"], line_directives=True)
    assert set(b.functions) == {"src/gram.c#parse", "src/i.h#twice"}
    parse = b.functions["src/gram.c#parse"]
    # The lines of its definition in gram.c's text, not the header's stale count.
    assert (parse["line"], parse["end_line"], parse["lines"]) == (4, 8, 5)
    assert parse["relocated_from"] == "src/toke.h:812-815" and parse["header"] is False
    assert parse["loops"] == 1 and parse["writes"]["globals"] == ["state"]
    twice = b.functions["src/i.h#twice"]
    assert twice["header"] is True and "relocated_from" not in twice
    assert set(b.global_vars) == {"src/gram.c#state"}
    assert [m["file"] for m in b.relocated] == ["src/gram.c", "src/gram.c"]


@pytest.mark.unit
def test_add_dump_without_line_directives_keeps_the_dumps_locations(tmp_path):
    tree = _ld_tree(tmp_path)
    b = _ld_builder(tree)
    b.add_dump(["libg.a"], _ld_dump(tree), sources=["src/gram.c"])
    assert set(b.functions) == {"src/toke.h#parse", "src/i.h#twice"}
    assert b.functions["src/toke.h#parse"]["line"] == 812 and not b.relocated


@pytest.mark.unit
def test_add_dump_gives_unknown_lines_when_the_source_text_has_no_single_definition(tmp_path):
    tree = _ld_tree(tmp_path)
    dump = _ld_dump(tree)
    dump["functions"][0]["name"] = dump["functions"][0]["kernel_name"] = "sudoerslex"  # YY_DECL: no literal name
    b = _ld_builder(tree)
    b.add_dump(["libg.a"], dump, sources=["src/gram.c"], line_directives=True)
    rec = b.functions["src/gram.c#sudoerslex"]
    assert (rec["line"], rec["end_line"], rec["lines"]) == (0, 0, None)


# ---------------------------------------------------------------------------------------------------
# framac_parse and the GCC paths parse the blanked copy
# ---------------------------------------------------------------------------------------------------


def _ld_source_tree(tmp_path: Path) -> Path:
    tree = tmp_path / "tree"
    (tree / "src").mkdir(parents=True)
    (tree / "src" / "gram.c").write_bytes(b'#include "toke.h"\n#line 1 "gram.y"\nint parse(void) { return 0; }\n')
    (tree / "src" / "plain.c").write_bytes(b"int plain(void) { return 1; }\n")
    return tree


@pytest.mark.unit
def test_framac_parse_reads_the_blanked_copy_and_maps_its_root_back(tmp_path):
    tree = _ld_source_tree(tmp_path)
    t = tree.as_posix()
    seen: dict = {}

    def runner(cmd, cwd=None, env=None, **_kw):
        seen["cmd"] = cmd
        copy = next(a for a in cmd if a.endswith("/gram.c") and a != f"{t}/src/gram.c")
        seen["copy"] = Path(copy).read_bytes()
        dump = {
            "schema": 7,
            "functions": [
                {"kernel_name": "parse", "name": "parse", "loc": "src/gram.c:3", "root": copy},
                {"kernel_name": "plain", "name": "plain", "loc": "src/plain.c:1", "root": f"{t}/src/plain.c"},
            ],
            "globals": [],
        }
        Path(env[pm.DUMP_OUT_ENV]).write_text(json.dumps(dump), encoding="utf-8")
        log = "[kernel:pp:line-directive] Warning: \n  ignoring non-existing file 'toke.l', referenced in a line directive\n"
        return subprocess.CompletedProcess(cmd, 0, log, "")

    job = {
        "key": "k",
        "compiles": [
            {"source": "src/gram.c", "flags": ["-DX=1"], "system_flags": []},
            {"source": "src/plain.c", "flags": [], "system_flags": []},
        ],
    }
    res = pm.framac_parse(job, t, None, tmp_path / "m.cmxs", tmp_path / "logs", False, runner)
    assert res["status"] == "ok"
    cmd = seen["cmd"]
    assert f"{t}/src/plain.c" in cmd and f"{t}/src/gram.c" not in cmd
    per_file = next(a for a in cmd if a.startswith("-cpp-extra-args-per-file="))
    assert per_file.endswith(f":-iquote {t}/src -DX=1") and "/gram.c:" in per_file
    assert seen["copy"] == f'#line 1 "{t}/src/gram.c"\n#include "toke.h"\n\nint parse(void) {{ return 0; }}\n'.encode()
    roots = {f["name"]: f["root"] for f in res["dump"]["functions"]}
    assert roots == {"parse": f"{t}/src/gram.c", "plain": f"{t}/src/plain.c"}
    assert res["line_directives"] == {"blanked": ["src/gram.c"], "ignored": ["toke.l"]}


@pytest.mark.unit
def test_gcc_fallback_and_macro_scan_compile_the_blanked_copy(tmp_path):
    tree = _ld_source_tree(tmp_path)
    t = tree.as_posix()
    cmds: list[list[str]] = []

    def runner(cmd, cwd=None, env=None, **_kw):
        cmds.append(list(cmd))
        return subprocess.CompletedProcess(cmd, 1, "", "no")

    c = {"source": "src/gram.c", "cwd": "src", "arguments": ["cc", "-c", "gram.c"], "flags": [], "system_flags": []}
    pm.gcc_callgraph({"key": "k", "compiles": [c]}, t, None, tmp_path / "logs", runner=runner)
    pm.macro_aliases(c, t, None, runner=runner)
    plain = {**c, "source": "src/plain.c", "arguments": ["cc", "-c", "plain.c"]}
    pm.macro_aliases(plain, t, None, runner=runner)
    gcc, defs, plain_defs = cmds
    compiled = gcc[gcc.index("-c") + 1]
    assert gcc[:3] == ["gcc", "-iquote", f"{t}/src"] and compiled.endswith("/gram.c") and compiled != f"{t}/src/gram.c"
    assert defs[:3] == ["gcc", "-iquote", f"{t}/src"] and defs[-1].endswith("/gram.c") and defs[-1] != f"{t}/src/gram.c"
    assert "-iquote" not in plain_defs and plain_defs[-1] == f"{t}/src/plain.c"


# ---------------------------------------------------------------------------------------------------
# Docker-backed: build capture in the build image, then the model in the analysis image
# ---------------------------------------------------------------------------------------------------


def _line_of(rel: str, text: str) -> int:
    lines = (LD_FIXTURE / rel).read_text(encoding="utf-8").splitlines()
    return next(i for i, line in enumerate(lines, 1) if text in line)


@pytest.mark.integration
@pytest.mark.slow
def test_line_directive_fixture_attributes_every_definition_to_its_compiled_source(tmp_path):
    require_docker_images(ANALYSIS_IMAGE, BUILD_IMAGE)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    vol = f"p0linedir-test-{uuid.uuid4().hex[:12]}"

    def docker(args: list[str], timeout: int = 900) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["docker", *args], capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, check=False,
        )  # fmt: skip

    docker(["volume", "create", vol])
    try:
        common = [
            "run", "--rm", "--network", "none",
            "-v", f"{LD_FIXTURE.resolve()}:/target:ro", "-v", f"{run_dir.resolve()}:/framac-run",
            "-v", f"{vol}:/framac-scratch",
            "-v", f"{ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
            "-v", f"{ROOT / 'schemas'}:/opt/framac-pipeline/schemas:ro", "-w", "/framac-run",
        ]  # fmt: skip
        py = "python3 /opt/framac-pipeline/scripts"
        cap = docker(
            [*common, BUILD_IMAGE,
             f"{py}/build_capture.py run --scratch /framac-scratch --recipe-file '' --command 'make'"]
        )  # fmt: skip
        assert cap.returncode == 0, cap.stdout + cap.stderr
        mod = docker([*common, "--entrypoint", "sh", ANALYSIS_IMAGE, "-c", f"{py}/phase0_model.py run --no-broker"])
        assert mod.returncode == 0, mod.stdout + mod.stderr
        model = json.loads((run_dir / pm.DEFAULT_OUT).read_text(encoding="utf-8"))
    finally:
        docker(["volume", "rm", "-f", vol])

    assert model["status"] == "ok" and not pm.validate_model(model)
    fns = model["functions"]
    assert set(fns) == {
        "src/scan.c#helper", "src/scan.c#scan_entry", "src/scan.c#scan_len", "src/scan.c#lex_peek",
        "src/scan.c#util_id", "src/gram.c#parse", "src/hdrline.c#hdr_fn", "src/lexer.h#lex_twice",
        "src/gram.c#gen_twice",
    }  # fmt: skip
    # Physical lines of the compiled source, not the grammar's or a header's.
    for fid, text in [
        ("src/scan.c#helper", "static int helper"),
        ("src/scan.c#scan_entry", "int scan_entry"),
        ("src/scan.c#scan_len", "int scan_len"),
        ("src/gram.c#parse", "int parse(void)"),
        ("src/hdrline.c#hdr_fn", "int hdr_fn"),
    ]:
        rel = fid.split("#")[0]
        assert fns[fid]["line"] == _line_of(rel, text), fid
        assert "relocated_from" not in fns[fid]
    assert fns["src/gram.c#parse"]["end_line"] == _line_of("src/gram.c", "return gram_state") + 1
    assert fns["src/lexer.h#lex_twice"]["header"] and fns["src/lexer.h#lex_twice"]["line"] == 4
    # gen.h's own `#line 1 "gen.def"` left the position in util.h: attributed to the source it was
    # parsed from, lines unknown (no literal definition of it in gram.c), with a warning.
    gen = fns["src/gram.c#gen_twice"]
    assert gen["relocated_from"].startswith("src/util.h:") and gen["line"] == 0
    assert any("line directive located outside" in w and "src/util.h:" in w for w in model["warnings"])
    assert set(model["global_variables"]) == {"src/scan.c#scan_global", "src/gram.c#gram_state"}
    job = next(j for j in model["parse_jobs"] if "src/gram.c" in j["sources"])
    assert job["line_directives"]["blanked"] == ["src/gram.c", "src/hdrline.c", "src/scan.c"]
    assert job["line_directives"]["ignored"] == ["gen.def"]
    assert "libld.a" in model["units"]
