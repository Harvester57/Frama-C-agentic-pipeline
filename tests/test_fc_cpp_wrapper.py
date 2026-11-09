"""
scripts/fc_cpp_wrapper.py: the gcc `-wrapper` that repairs `offsetof` with a non-constant index in
Frama-C's preprocessed output, and its wiring into every Frama-C parse and the E-ACSL frontend.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

import eacsl_toolchain
import fc_cpp_wrapper as W
import framac_common
from conftest import ANALYSIS_IMAGE, ROOT, require_docker_images

CC1 = "/usr/libexec/gcc/x86_64-linux-gnu/14/cc1"


def _pp(body: str, file: str = "src/arch.c", line: int = 50) -> str:
    """Preprocessed text as cc1 writes it: a line marker, then the code."""
    return f'# 1 "<built-in>"\n# {line} "{file}"\n{body}'


# ---------------------------------------------------------------------------------------------------
# The rewrite
# ---------------------------------------------------------------------------------------------------


@pytest.mark.unit
def test_a_non_constant_index_becomes_integer_arithmetic_on_a_folded_offset():
    text = _pp("unsigned long f(int a) { return __builtin_offsetof(struct d, args[a]); }\n", line=54)
    new, notes = W.rewrite_text(text)
    expected = "(__builtin_offsetof(struct d, args) + (__typeof__(sizeof(0)))(a) * sizeof((((struct d *)0)->args)[0]))"
    assert f"return {expected};" in new
    assert notes == [
        {
            "file": "src/arch.c",
            "line": 54,
            "kind": "offsetof with a non-constant index",
            "original": "__builtin_offsetof(struct d, args[a])",
            "rewritten": expected,
        }
    ]


@pytest.mark.unit
@pytest.mark.parametrize(
    "call",
    [
        "__builtin_offsetof(struct d, args)",
        "__builtin_offsetof(struct d, args[2])",
        "__builtin_offsetof(struct d, args[ (0x1UL) ])",
        "__builtin_offsetof(struct d, in.v[3][0])",
    ],
)
def test_constant_designators_are_left_for_the_kernel_to_fold(call):
    text = _pp(f'_Static_assert({call} >= 0, "x");\nsize_t k = {call};\n')
    assert W.rewrite_text(text) == (text, [])


@pytest.mark.unit
def test_comments_literals_and_directive_lines_are_never_touched():
    call = "__builtin_offsetof(struct d, args[i])"
    text = _pp(
        f"#define default_arg_offset(x) {call}\n/* {call} */\n// {call}\nconst char *s = \"{call}\";\nchar c = '[';\n"
    )
    assert W.rewrite_text(text) == (text, [])


@pytest.mark.unit
def test_nested_designators_go_through_the_element_type():
    text = _pp(
        "a = __builtin_offsetof(struct o, in[i].v[j]);\n"
        "b = __builtin_offsetof(struct o, m[i][j]);\n"
        "c = __builtin_offsetof(struct o, m[1][j]);\n"
    )
    new, notes = W.rewrite_text(text)
    elem = "__typeof__((((struct o *)0)->in)[0])"
    assert [n["rewritten"] for n in notes] == [
        "(__builtin_offsetof(struct o, in) + (__typeof__(sizeof(0)))(i) * sizeof((((struct o *)0)->in)[0])"
        f" + __builtin_offsetof({elem}, v) + (__typeof__(sizeof(0)))(j) * sizeof(((({elem} *)0)->v)[0]))",
        "(__builtin_offsetof(struct o, m) + (__typeof__(sizeof(0)))(i) * sizeof((((struct o *)0)->m)[0])"
        " + (__typeof__(sizeof(0)))(j) * sizeof(((((struct o *)0)->m)[0])[0]))",
        "(__builtin_offsetof(struct o, m[1]) + (__typeof__(sizeof(0)))(j) * sizeof((((struct o *)0)->m[1])[0]))",
    ]
    assert [n["line"] for n in notes] == [50, 51, 52]
    assert new.count("\n") == text.count("\n")


@pytest.mark.unit
def test_a_call_over_several_lines_keeps_the_line_count():
    text = _pp("x = __builtin_offsetof(struct d,\n    args[n -\n 1]);\nint after;\n")
    new, notes = W.rewrite_text(text)
    assert len(notes) == 1 and "(__typeof__(sizeof(0)))(n - 1)" in notes[0]["rewritten"]
    assert new.count("\n") == text.count("\n")
    assert new.splitlines()[-1] == "int after;"


@pytest.mark.unit
def test_the_null_pointer_offset_idiom_becomes_a_folded_offset():
    # gperf's string-pool tables (libseccomp syscalls.perf.c) and hand-written offsetof macros.
    text = _pp(
        "static const struct e t[] = {\n"
        "  {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str5, 3},\n"
        "  {(int)(long)&(((struct stringpool_t *)0)->stringpool_str12), 4},\n"
        "};\n"
        "size_t a = ((size_t) &((T *)((void *)0))->in.v[2]);\n"
        "size_t b = (unsigned long)&((struct o *)(0))->m[i];\n",
        file="src/syscalls.perf.c",
        line=10,
    )
    new, notes = W.rewrite_text(text)
    assert [(n["line"], n["kind"], n["rewritten"]) for n in notes] == [
        (11, "null-pointer offset idiom", "__builtin_offsetof(struct stringpool_t, stringpool_str5)"),
        (12, "null-pointer offset idiom", "__builtin_offsetof(struct stringpool_t, stringpool_str12)"),
        (14, "null-pointer offset idiom", "__builtin_offsetof(T, in.v[2])"),
        (
            15,
            "null-pointer offset idiom",
            "(__builtin_offsetof(struct o, m) + (__typeof__(sizeof(0)))(i) * sizeof((((struct o *)0)->m)[0]))",
        ),
    ]
    assert "{(int)(size_t)__builtin_offsetof(struct stringpool_t, stringpool_str5), 3}," in new
    assert "{(int)(long)__builtin_offsetof(struct stringpool_t, stringpool_str12), 4}," in new
    assert "size_t a = ((size_t) __builtin_offsetof(T, in.v[2]));" in new
    assert new.count("\n") == text.count("\n")


@pytest.mark.unit
@pytest.mark.parametrize(
    "expr",
    [
        "&((struct s *)0)->m",  # no cast: a pointer, not an offset
        "(char *)&((struct s *)0)->m",  # a pointer cast
        "(void)&((struct s *)0)->m",
        "(size_t)&((struct s *)p)->m",  # not a null pointer
        "(size_t)&((struct s *)0)->next->m",  # a dereference
        "(size_t)&((struct s *)0)->f(1)",
        "x && (size_t)((struct s *)0)->m",  # no `&`
        "sizeof(((struct s *)0)->m)",
    ],
)
def test_other_uses_of_a_null_struct_pointer_are_left_alone(expr):
    text = _pp(f"long v = {expr};\n/* (size_t)&((struct s *)0)->m */\n")
    assert W.rewrite_text(text) == (text, [])


@pytest.mark.unit
def test_line_markers_inside_a_system_header_expansion_are_skipped():
    # gcc output for `offsetof` from a system <stddef.h> (E-ACSL host-header builds): the macro's own
    # tokens carry the system-header flags, the arguments the user file's, so markers split the call.
    text = (
        '# 7 "s.c"\n'
        "unsigned long f(int a) { return (\n"
        '# 7 "s.c" 3 4\n'
        "        __builtin_offsetof (\n"
        '# 7 "s.c"\n'
        "        struct d\n"
        '# 7 "s.c" 3 4\n'
        "        , \n"
        '# 7 "s.c"\n'
        "        args[a]\n"
        '# 7 "s.c" 3 4\n'
        "        )\n"
        '# 7 "s.c"\n'
        "        ); }\n"
    )
    new, notes = W.rewrite_text(text)
    rewritten = "(__builtin_offsetof(struct d, args) + (__typeof__(sizeof(0)))(a) * sizeof((((struct d *)0)->args)[0]))"
    assert [(n["file"], n["line"], n["rewritten"]) for n in notes] == [("s.c", 7, rewritten)]
    assert new.count("\n") == text.count("\n")
    # The markers inside the call go (its newlines stay); the one before and the one after stay.
    before, after = new.split(rewritten)
    assert before.endswith('# 7 "s.c" 3 4\n        ')
    assert after == "\n" * 8 + '\n# 7 "s.c"\n        ); }\n'


@pytest.mark.unit
@pytest.mark.parametrize(
    "call",
    [
        "__builtin_offsetof(struct d, args[i]->x)",  # not a designator
        "__builtin_offsetof(struct d, args[])",
        "__builtin_offsetof(struct d)",
        "__builtin_offsetof(struct d, args[i]",  # unbalanced
    ],
)
def test_anything_that_is_not_a_designator_is_left_alone(call):
    text = _pp(f"y = {call};\n")
    assert W.rewrite_text(text) == (text, [])


# ---------------------------------------------------------------------------------------------------
# The wrapper around gcc's subcommands
# ---------------------------------------------------------------------------------------------------


def _fake_cc1(content: str, rc: int = 0):
    calls: list[list[str]] = []

    def call(cmd: list[str]) -> int:
        calls.append(cmd)
        out = W.output_path(cmd)
        if out:
            Path(out).write_text(content, encoding="utf-8", newline="\n")
        return rc

    return call, calls


@pytest.mark.unit
def test_the_preprocessor_output_is_rewritten_after_a_successful_run(tmp_path, capsys):
    out = tmp_path / "arch.i"
    call, calls = _fake_cc1(_pp("r = __builtin_offsetof(struct d, args[x]);\n"))
    cmd = [CC1, "-E", "-quiet", "/t/src/arch.c", "-o", str(out)]
    assert W.run(cmd, call=call) == 0
    assert calls == [cmd]
    assert "__builtin_offsetof(struct d, args) + " in out.read_text(encoding="utf-8")
    assert "[fc-cpp] src/arch.c:50: offsetof with a non-constant index rewritten" in capsys.readouterr().err
    assert not list(tmp_path.glob("*.fc-cpp"))


@pytest.mark.unit
@pytest.mark.parametrize(
    ("cmd", "rc", "env"),
    [
        ([CC1, "-E", "-M", "a.c", "-o", "{out}"], 0, None),  # a dependency listing
        (["/usr/bin/as", "a.s", "-o", "{out}"], 0, None),  # not the preprocessor
        ([CC1, "-E", "a.c", "-o", "{out}"], 1, None),  # the preprocessor failed
        ([CC1, "-E", "a.c", "-o", "{out}"], 0, "off"),  # FRAMAC_CPP_REWRITE=off
    ],
)
def test_other_subcommands_failures_and_the_switch_leave_the_output_alone(tmp_path, monkeypatch, cmd, rc, env):
    out = tmp_path / "a.i"
    text = _pp("r = __builtin_offsetof(struct d, args[x]);\n")
    call, _ = _fake_cc1(text, rc)
    if env:
        monkeypatch.setenv(W.DISABLE_ENV, env)
    assert W.run([c.replace("{out}", str(out)) for c in cmd], call=call) == rc
    assert out.read_text(encoding="utf-8") == text


@pytest.mark.unit
def test_a_failed_rewrite_fails_open(tmp_path, capsys):
    assert W.rewrite_file(str(tmp_path / "missing.i")) == []
    assert "[fc-cpp] warning: offsetof rewrite skipped" in capsys.readouterr().err


@pytest.mark.unit
def test_the_wrapper_is_an_lf_python_script_gcc_can_execute():
    head = (ROOT / "scripts" / "fc_cpp_wrapper.py").read_bytes()[:40]
    assert head.startswith(b"#!/usr/bin/env python3\n"), "a CRLF shebang cannot run in the container"


# ---------------------------------------------------------------------------------------------------
# Wiring, and no offsetof override anywhere
# ---------------------------------------------------------------------------------------------------


@pytest.mark.unit
def test_no_fc_stub_redefines_offsetof():
    # A null-pointer `offsetof` is an invalid pointer for Eva (-warn-invalid-pointer), loses the folded
    # constant for WP and breaks `_Static_assert` on offsets: the wrapper repairs the one form Frama-C
    # rejects instead.
    stubs = ROOT / "templates" / "fc_stubs"
    for header in stubs.rglob("*.h"):
        code = [ln for ln in header.read_text(encoding="utf-8").splitlines() if ln.lstrip().startswith("#")]
        assert not any("define offsetof" in " ".join(ln.split()) for ln in code), header


@pytest.mark.unit
def test_compat_header_is_frama_c_only_and_keeps_linux_declarations_out_of_eacsl():
    text = (ROOT / "templates" / "fc_stubs" / "fc_compat_types.h").read_text(encoding="utf-8")
    # Empty for every non-Frama-C compile (fc_stubs README rule 4).
    assert "#if defined(__FRAMAC__)\n" in text and "defined(__FRAMAC_EACSL__)\n\n/* `offsetof`" not in text
    fc_libc = text.split("#else /* Frama-C __fc_libc */", 1)[1].split("#endif /* __FRAMAC_EACSL__ */", 1)[0]
    for decl in ("long syscall(long number, ...);", "#define _IOWR(type, nr, size)", "#define _IOC_TYPECHECK(t)"):
        assert decl in fc_libc and text.count(decl) == 1, decl


@pytest.mark.unit
def test_every_framac_parse_runs_the_preprocessor_under_the_wrapper(monkeypatch):
    monkeypatch.setattr(framac_common, "framac_cpp_wrapper", lambda: "/opt/framac-pipeline/scripts/fc_cpp_wrapper.py")
    flags = framac_common.augment_framac_cppflags("-Isrc -DX=1").split()
    i = flags.index("-wrapper")
    assert flags[i + 1] == "/opt/framac-pipeline/scripts/fc_cpp_wrapper.py"
    assert flags.index("-Isrc") < i
    again = framac_common.augment_framac_cppflags(" ".join(flags)).split()
    assert again.count("-wrapper") == 1
    monkeypatch.setattr(framac_common, "framac_cpp_wrapper", lambda: None)
    assert "-wrapper" not in framac_common.augment_framac_cppflags("-Isrc").split()


@pytest.mark.unit
def test_the_eacsl_frontend_runs_under_the_wrapper_and_the_backend_does_not(monkeypatch, tmp_path):
    monkeypatch.setattr(eacsl_toolchain, "framac_cpp_wrapper", lambda: "/opt/framac-pipeline/scripts/fc_cpp_wrapper.py")
    flags = eacsl_toolchain.build_eacsl_flag_sets("-Isrc -std=gnu99", fc_stubs=tmp_path)
    front, back = flags["frontend"].split(), flags["backend"].split()
    assert front[:2] == ["-D__FRAMAC_EACSL__", "-D_Float128=double"]
    assert front[front.index("-wrapper") + 1] == "/opt/framac-pipeline/scripts/fc_cpp_wrapper.py"
    assert "-wrapper" not in back


@pytest.mark.unit
def test_the_wrapper_is_only_offered_where_gcc_can_run_it(tmp_path):
    spaced = tmp_path / "my dir" / "fc_cpp_wrapper.py"
    spaced.parent.mkdir()
    spaced.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    spaced.chmod(0o755)
    assert framac_common.framac_cpp_wrapper(spaced) is None  # `-wrapper` and e-acsl-gcc split on it
    assert framac_common.framac_cpp_wrapper(tmp_path / "missing.py") is None


# ---------------------------------------------------------------------------------------------------
# End to end in the analysis image (FRAMAC_DOCKER_TESTS=1)
# ---------------------------------------------------------------------------------------------------

SECCOMP_LIKE = """\
#include <stddef.h>
struct d { int nr; unsigned int arch; unsigned long long ip; unsigned long long args[6]; };
#define default_arg_offset(x) (offsetof(struct d, args[x]))
/*@ requires 0 <= a < 6;
    assigns \\nothing;
    ensures \\result == 16 + 8 * a; */
unsigned long arg_off(int a) { return default_arg_offset(a); }
/*@ assigns \\nothing;
    ensures \\result == 16; */
unsigned long const_off(void) { return offsetof(struct d, args); }
_Static_assert(offsetof(struct d, args) == 16, "layout");
int main(void) { return arg_off(3) == 40 && const_off() == 16 ? 0 : 1; }
"""

# gperf's string-pool table (libseccomp syscalls.perf.c): Eva with -warn-invalid-pointer stopped on it
# with "globals initialization is not computable" before the null-pointer idiom was rewritten.
GPERF_LIKE = """\
#include <stddef.h>
#include <string.h>
struct stringpool_t { char stringpool_str0[sizeof("read")]; char stringpool_str1[sizeof("openat")]; };
static const struct stringpool_t stringpool_contents = { "read", "openat" };
#define stringpool ((const char *) &stringpool_contents)
struct entry { int name; int num; };
static const struct entry wordlist[] = {
  {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str0, 0},
  {(int)(long)&((struct stringpool_t *)0)->stringpool_str1, 257},
};
/*@ requires 0 <= i < 2; assigns \\nothing; */
int lookup(int i, const char *s) { return strcmp(stringpool + wordlist[i].name, s) == 0 ? wordlist[i].num : -1; }
int main(void) { return lookup(1, "openat") == 257 ? 0 : 1; }
"""


@pytest.mark.integration
@pytest.mark.slow
def test_frama_c_and_eacsl_accept_a_non_constant_offsetof_without_losing_precision(tmp_path):
    require_docker_images(ANALYSIS_IMAGE)
    (tmp_path / "s.c").write_text(SECCOMP_LIKE, encoding="utf-8", newline="\n")
    (tmp_path / "g.c").write_text(GPERF_LIKE, encoding="utf-8", newline="\n")
    py = 'import sys; sys.path.insert(0, "/opt/framac-pipeline/scripts"); '
    script = (
        "trap 'cat /w/*.log' EXIT; set -e; cd /w; "
        f"A=$(python3 -c '{py}import framac_common; print(framac_common.augment_framac_cppflags(\"-I.\"))'); "
        f'F=$(python3 -c \'{py}import eacsl_toolchain as T; print(T.build_eacsl_flag_sets("-I.", fuzzer=False)["frontend"])\'); '
        'frama-c -no-unicode s.c -cpp-extra-args="$A" -print > print.log 2>&1; '
        'frama-c -no-unicode s.c -cpp-extra-args="$A" -eva -warn-invalid-pointer > eva.log 2>&1; '
        'frama-c -no-unicode s.c -cpp-extra-args="$A" -wp -wp-rte -warn-invalid-pointer > wp.log 2>&1; '
        'e-acsl-gcc --full-mtracking -G clang -E "$F" -O bin s.c > eacsl.log 2>&1; ./bin.e-acsl; '
        'frama-c -no-unicode g.c -cpp-extra-args="$A" -eva -warn-invalid-pointer > gperf.log 2>&1; '
    )
    proc = subprocess.run(
        [
            "docker", "run", "--rm", "--network", "none",
            "-v", f"{tmp_path}:/w",
            "-v", f"{ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
            "-v", f"{ROOT / 'templates'}:/opt/framac-pipeline/templates:ro",
            "--entrypoint", "bash", ANALYSIS_IMAGE, "-c", script,
        ],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900, check=False,
    )  # fmt: skip
    log = proc.stdout + proc.stderr
    assert proc.returncode == 0, log
    assert "[fc-cpp] /w/s.c:7: offsetof with a non-constant index rewritten" in log
    assert "__retres = 16UL;" in log  # the constant offset is still folded
    assert log.count("0 alarms generated by the analysis.") == 2  # s.c and the gperf table
    assert "[fc-cpp] /w/g.c:8: null-pointer offset idiom rewritten" in log
    assert "not computable" not in log
    proved = re.search(r"Proved goals:\s+(\d+) / (\d+)", log)
    assert proved and proved.group(1) == proved.group(2), log
