"""
scripts/fc_cpp_wrapper.py: the gcc `-wrapper` that repairs `offsetof` with a non-constant index in
Frama-C's preprocessed output, and its wiring into every Frama-C parse and the E-ACSL frontend; and
scripts/fc_cpp_wrapper_eacsl.py, the E-ACSL frontend's variant that also writes `<==>` as two implications.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import eacsl_toolchain
import fc_cpp_wrapper as W
import framac_common
from conftest import ANALYSIS_IMAGE, ROOT, require_docker_images, wp_proved_goals

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
# E-ACSL only: `<==>` as two implications
# ---------------------------------------------------------------------------------------------------


def _iff(body: str) -> str:
    new, _ = W.rewrite_iff_body(body)
    return " ".join(new.split())


@pytest.mark.unit
@pytest.mark.parametrize(
    ("body", "expected"),
    [
        # The libmnl contract that failed the Tier 6 guardrail.
        (
            r" ensures empty_iff_zero: (\result != 0) <==> (b->buflen == 0); ",
            r"ensures empty_iff_zero: ((((\result != 0)) ==> ((b->buflen == 0))) && "
            r"(((b->buflen == 0)) ==> ((\result != 0))));",
        ),
        # `==>` binds tighter than `<==>`; a binder's body holds the `<==>`.
        (
            r" ensures \forall integer i; 0 <= i < n ==> a[i] == 0 <==> \result; ",
            r"ensures \forall integer i; (((0 <= i < n ==> a[i] == 0) ==> (\result)) && "
            r"((\result) ==> (0 <= i < n ==> a[i] == 0)));",
        ),
        # A binder on the right keeps its own `;` inside the operand.
        (
            r" ensures (x == 0) <==> \forall integer i; 0 <= i < n ==> a[i] == 0; ",
            r"ensures ((((x == 0)) ==> (\forall integer i; 0 <= i < n ==> a[i] == 0)) && "
            r"((\forall integer i; 0 <= i < n ==> a[i] == 0) ==> ((x == 0))));",
        ),
        # Inside a group, a call argument, a ternary branch, a `\let` body and a definition.
        (r" ensures r: x == 0 ==> (\result <==> \old(y) > 0); ",
         r"ensures r: x == 0 ==> ((((\result) ==> (\old(y) > 0)) && ((\old(y) > 0) ==> (\result))));"),
        (r" ensures P(a, b <==> c); ", r"ensures P(a, (((b) ==> (c)) && ((c) ==> (b))));"),
        (r" ensures c ? a <==> b : d; ", r"ensures c ? (((a) ==> (b)) && ((b) ==> (a))) : d;"),
        (r" ensures \let v = x + 1; v > 0 <==> x >= 0; ",
         r"ensures \let v = x + 1; (((v > 0) ==> (x >= 0)) && ((x >= 0) ==> (v > 0)));"),
        (r" predicate p(int x) = x > 0 <==> x != 0; ",
         r"predicate p(int x) = (((x > 0) ==> (x != 0)) && ((x != 0) ==> (x > 0)));"),
        # Labelled terms, and `loop invariant` (two keywords) in front of the left operand.
        (r" loop invariant (s == 0) <==> (i == 0 && n == \at(n, Pre)); ",
         r"loop invariant ((((s == 0)) ==> ((i == 0 && n == \at(n, Pre)))) && "
         r"(((i == 0 && n == \at(n, Pre))) ==> ((s == 0))));"),
        # `<==>` is left-associative: (a <==> b) <==> c.
        (r" ensures a <==> b <==> c; ",
         r"ensures ((((((a) ==> (b)) && ((b) ==> (a)))) ==> (c)) && "
         r"((c) ==> ((((a) ==> (b)) && ((b) ==> (a))))));"),
        # Numbers, ranges and bit operators keep their spelling in the copies.
        (r" ensures \valid(p + (0 .. 1)) <==> x --> 1.5e0 > 0x1Fu; ",
         r"ensures (((\valid(p + (0 .. 1))) ==> (x --> 1.5e0 > 0x1Fu)) && "
         r"((x --> 1.5e0 > 0x1Fu) ==> (\valid(p + (0 .. 1)))));"),
    ],
)  # fmt: skip
def test_every_equivalence_becomes_two_implications(body, expected):
    assert _iff(body) == expected
    assert "<==>" not in W.rewrite_iff_body(body)[0]


@pytest.mark.unit
def test_the_equivalence_rewrite_keeps_lines_and_leaves_c_and_other_comments_alone():
    text = _pp(
        "/*@ requires \\valid(b);\n"
        "    @ assigns \\nothing;\n"
        "    @ ensures (\\result != 0) // why\n"
        "    @   <==> (b->n == 0); */\n"
        'int f(struct s *b) { char *m = "a <==> b"; /* x <==> y */ return b->n == 0; }\n'
        "//@ ghost int g = 0;\n"
        "int h(int r) { /*@ assert (r != 0) <==> (\\at(r, Pre) != 0); */ return r; }\n",
        file="src/f.c",
        line=10,
    )
    new, notes = W.rewrite_iff_text(text)
    assert new.count("\n") == text.count("\n")
    assert new.count("<==>") == 2  # the string literal and the plain comment
    assert '"a <==> b"' in new and "/* x <==> y */" in new
    # The first implication keeps the operands' lines; the reversed copy is on one line, without the comment.
    assert (
        "ensures ((((\\result != 0)) // why\n    @   ==> ((b->n == 0))) && (((b->n == 0)) ==> ((\\result != 0))));"
        in new
    )
    assert [(n["file"], n["line"]) for n in notes] == [("src/f.c", 10), ("src/f.c", 16)]
    assert W.rewrite_iff_text(_pp("int x = a <= b;\n")) == (_pp("int x = a <= b;\n"), [])


@pytest.mark.unit
def test_an_equivalence_without_operand_is_left_for_the_kernel():
    assert W.rewrite_iff_body(" ensures <==> x; ") == (" ensures <==> x; ", 0)


# ---------------------------------------------------------------------------------------------------
# ACSL annotations (and `-dD` macro bodies): `__alignof__` / `__alignof` -> `_Alignof`
# ---------------------------------------------------------------------------------------------------


@pytest.mark.unit
def test_alignof_rewrites_annotations_and_define_bodies_but_leaves_c_code_strings_and_comments_alone():
    text = _pp(
        "#define MPACK_ALIGNOF(T) __alignof__(T)\n"
        "#define MPACK_ALIGNOF_ALIAS __alignof__\n"
        "#define MSVC_ALIGNOF(T) __alignof (T)\n"
        '#define MSG "__alignof__(int)"\n'
        "#define CMT 1 /* __alignof__(int) */\n"
        "#define PASTE(a) a ## __alignof__\n"
        "/*@ requires n > 0;\n"
        "    @ // __alignof__(my_t) inside a comment\n"
        "    @ ensures \\result % __alignof__(my_t) == 0;\n"
        "    @ ensures \\result % __alignof\n"
        "    @   (my_t) == 0;\n"
        '    @ ensures s != "__alignof__(my_t)"; */\n'
        "//@ ensures \\result >= __alignof(int);\n"
        "/* __alignof__(my_t) in a plain comment */\n"
        "// __alignof__(my_t) in a line comment\n"
        'const char *s = "/*@ ensures __alignof__(my_t); */";\n'
        "size_t f(size_t n) { return n + __alignof__(my_t); }\n"
        "long long __max_align_ll __attribute__((__aligned__(__alignof__(long long))));\n",
        file="src/mpack-writer.c",
        line=10,
    )
    new, notes = W.rewrite_alignof_text(text)
    assert new.count("\n") == text.count("\n")
    # Rewritten in `#define` replacement bodies and ACSL annotations.
    assert "#define MPACK_ALIGNOF(T) _Alignof(T)\n" in new
    assert "#define MPACK_ALIGNOF_ALIAS _Alignof\n" in new
    assert "#define MSVC_ALIGNOF(T) _Alignof (T)\n" in new
    assert "ensures \\result % _Alignof(my_t) == 0;" in new
    assert "ensures \\result % _Alignof\n    @   (my_t) == 0;" in new
    assert "//@ ensures \\result >= _Alignof(int);\n" in new
    # Untouched: strings, comments, `##`, and C code (including glibc's max_align_t).
    assert '#define MSG "__alignof__(int)"\n' in new
    assert "#define CMT 1 /* __alignof__(int) */\n" in new
    assert "#define PASTE(a) a ## __alignof__\n" in new
    assert "// __alignof__(my_t) inside a comment" in new
    assert 'ensures s != "__alignof__(my_t)";' in new
    assert "/* __alignof__(my_t) in a plain comment */" in new
    assert "// __alignof__(my_t) in a line comment" in new
    assert 'const char *s = "/*@ ensures __alignof__(my_t); */";' in new
    assert "size_t f(size_t n) { return n + __alignof__(my_t); }" in new
    assert "__attribute__((__aligned__(__alignof__(long long))))" in new
    assert [(n["file"], n["line"]) for n in notes] == [
        ("src/mpack-writer.c", 10),
        ("src/mpack-writer.c", 11),
        ("src/mpack-writer.c", 12),
        ("src/mpack-writer.c", 16),
        ("src/mpack-writer.c", 22),
    ]


@pytest.mark.unit
def test_alignof_without_open_paren_in_annotation_or_part_of_identifier_is_untouched():
    text = _pp(
        "/*@ predicate p(int x) = __alignof__ == 0 && my__alignof__(x) == 0 && __alignof__x(x) == 0; */\n"
        "#define __alignof__(T) _Alignof(T)\n"
        "#define KEEP_IDENT(T) my__alignof__(T) + __alignof__x(T)\n",
        file="src/t.c",
        line=1,
    )
    assert W.rewrite_alignof_text(text) == (text, [])


@pytest.mark.unit
def test_alignof_rewrite_runs_for_both_wp_and_eacsl_wrappers_and_respects_disable_env(tmp_path, monkeypatch, capsys):
    text = _pp(
        "#define ALIGN(T) __alignof__(T)\n/*@ ensures \\result == __alignof__(int); */\nint f(void) { return __alignof__(int); }\n",
        file="src/a.c",
        line=5,
    )
    out = tmp_path / "a.i"
    cmd = [CC1, "-E", "src/a.c", "-o", str(out)]

    # WP / Eva wrapper (`fc_cpp_wrapper.run`).
    call, _ = _fake_cc1(text)
    assert W.run(cmd, call=call) == 0
    rewritten = out.read_text(encoding="utf-8")
    assert "#define ALIGN(T) _Alignof(T)\n" in rewritten
    assert "ensures \\result == _Alignof(int);" in rewritten
    assert "return __alignof__(int);" in rewritten
    err = capsys.readouterr().err
    assert "[fc-cpp] src/a.c:5: 1 `__alignof__` in a `#define` (ACSL: `_Alignof`) rewritten" in err
    assert "[fc-cpp] src/a.c:6: 1 `__alignof__` in an annotation (ACSL: `_Alignof`) rewritten" in err

    # E-ACSL wrapper (`fc_cpp_wrapper_eacsl.run_eacsl`).
    import fc_cpp_wrapper_eacsl

    call, _ = _fake_cc1(text)
    assert fc_cpp_wrapper_eacsl.run_eacsl(cmd, call=call) == 0
    assert "ensures \\result == _Alignof(int);" in out.read_text(encoding="utf-8")
    capsys.readouterr()

    # Disabled by FRAMAC_CPP_REWRITE=off.
    monkeypatch.setenv(W.DISABLE_ENV, "off")
    call, _ = _fake_cc1(text)
    assert W.run(cmd, call=call) == 0
    assert out.read_text(encoding="utf-8") == text


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
def test_only_the_eacsl_wrapper_rewrites_equivalences(tmp_path, capsys):
    text = _pp("/*@ ensures (\\result != 0) <==> (b->n == 0); */\nint f(struct s *b);\n", file="src/f.c", line=3)
    out = tmp_path / "f.i"
    call, _ = _fake_cc1(text)
    cmd = [CC1, "-E", "src/f.c", "-o", str(out)]
    assert W.run(cmd, call=call) == 0
    assert out.read_text(encoding="utf-8") == text  # Eva and WP read the contract as written
    assert W.run(cmd, call=call, iff=True) == 0
    assert "<==>" not in out.read_text(encoding="utf-8")
    assert (
        "[fc-cpp] src/f.c:3: 1 `<==>` in an annotation (E-ACSL: two implications) rewritten" in capsys.readouterr().err
    )
    # The E-ACSL wrapper's entry point (fc_cpp_wrapper_eacsl.run_eacsl) asks for the `<==>` rewrite.
    import fc_cpp_wrapper_eacsl

    call, _ = _fake_cc1(text)
    assert fc_cpp_wrapper_eacsl.run_eacsl(cmd, call=call) == 0
    assert "<==>" not in out.read_text(encoding="utf-8")


@pytest.mark.unit
def test_a_failed_rewrite_fails_open(tmp_path, capsys):
    assert W.rewrite_file(str(tmp_path / "missing.i")) == []
    assert "[fc-cpp] warning: rewrite skipped" in capsys.readouterr().err


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
    asked: list[Path] = []

    def wrapper(path: Path) -> str:
        asked.append(path)
        return "/opt/framac-pipeline/scripts/fc_cpp_wrapper_eacsl.py"

    monkeypatch.setattr(eacsl_toolchain, "framac_cpp_wrapper", wrapper)
    flags = eacsl_toolchain.build_eacsl_flag_sets("-Isrc -std=gnu99", fc_stubs=tmp_path)
    front, back = flags["frontend"].split(), flags["backend"].split()
    assert front[:2] == ["-D__FRAMAC_EACSL__", "-D_Float128=double"]
    # The E-ACSL variant (with the `<==>` rewrite), not the Eva/WP wrapper.
    assert asked == [ROOT / "scripts" / "fc_cpp_wrapper_eacsl.py"]
    assert front[front.index("-wrapper") + 1] == "/opt/framac-pipeline/scripts/fc_cpp_wrapper_eacsl.py"
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
    assert all(proved == total for proved, total in wp_proved_goals(log)), log


# The libmnl contract shape that the Frama-C 35 guardrail refused (docs/upstream/frama-c/frama-c-eacsl-iff-labelled-term.md),
# plus a body assertion over `\at` and a binder.
IFF_LABELLED = r"""struct s { int n; };
/*@ requires \valid(b);
    assigns b->n;
    ensures empty_iff_zero: (\result != 0) <==> (\old(b->n) == 0);
    ensures all: \forall integer i; 0 <= i < 1 ==> (b->n == 5 <==> \true); */
int f(struct s *b) {
  int r = b->n == 0;
  b->n = 5;
  /*@ assert (r != 0) <==> (\at(b->n, Pre) == 0); */
  return r;
}
/*@ ensures wrong: (\result != 0) <==> (x == 0); */
int g(int x) { return x != 0; }
int main(int argc, char **argv) {
  struct s x = { 0 };
  int ok = f(&x) == 1 && x.n == 5;
  if (argc > 1) g(0);  /* violates `wrong`: the rewritten check still fires */
  return ok ? 0 : 1;
}
"""


@pytest.mark.integration
@pytest.mark.slow
def test_eacsl_builds_and_checks_equivalences_over_labelled_terms(tmp_path):
    require_docker_images(ANALYSIS_IMAGE)
    (tmp_path / "i.c").write_text(IFF_LABELLED, encoding="utf-8", newline="\n")
    py = 'import sys; sys.path.insert(0, "/opt/framac-pipeline/scripts"); '
    script = (
        "cd /w; "
        f'F=$(python3 -c \'{py}import eacsl_toolchain as T; print(T.build_eacsl_flag_sets("-I.", fuzzer=False)["frontend"])\'); '
        'case "$F" in *fc_cpp_wrapper_eacsl.py*) ;; *) echo "NO EACSL WRAPPER: $F"; exit 9;; esac; '
        # Without the rewrite, Frama-C 35 stops (keeps this test honest about what it repairs).
        'FRAMAC_CPP_REWRITE=off e-acsl-gcc --full-mtracking -G clang -E "$F" -O off i.c > off.log 2>&1; echo "off_rc=$?"; '
        'e-acsl-gcc --full-mtracking -G clang -E "$F" -O bin i.c > on.log 2>&1; echo "on_rc=$?"; cat on.log; '
        './bin.e-acsl; echo "run_rc=$?"; ./bin.e-acsl violate > viol.log 2>&1; echo "viol_rc=$?"; cat viol.log; '
        "grep -c 'labels pre-analysis was not performed' off.log || true"
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
    assert "on_rc=0" in log and "run_rc=0" in log, log
    assert "[fc-cpp] /w/i.c:2: 2 `<==>` in an annotation (E-ACSL: two implications) rewritten" in log, log
    assert "[fc-cpp] /w/i.c:9: 1 `<==>`" in log and "[fc-cpp] /w/i.c:12: 1 `<==>`" in log, log
    # The rewritten postcondition is still checked: g(0) breaks it at run time.
    violation = (tmp_path / "viol.log").read_text(encoding="utf-8", errors="replace")
    assert "viol_rc=0" not in log and "Postcondition" in violation and "wrong" in violation, log
    if "off_rc=0" not in log:  # Frama-C 35: the original text fails as diagnosed; 34 builds both
        assert "labels pre-analysis was not performed" in (tmp_path / "off.log").read_text(encoding="utf-8"), log


# mpack run-4 (`mpack-platform.h:1409-1429` / `MPACK_BUILD_ALIGNMENT`): selects `_Alignof` under C11+
# and `__alignof__` under `-std=c99`. Both function-like and alias macro forms are exercised.
MPACK_ALIGN_LIKE = r"""#include <stddef.h>
#include <stdint.h>

typedef struct {
    int count;
    double payload;
} my_build_t;

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define MY_ALIGNOF(T) _Alignof(T)
#define MY_ALIGNOF_KW _Alignof
#else
#define MY_ALIGNOF(T) __alignof__(T)
#define MY_ALIGNOF_KW __alignof__
#endif

#define MY_BUILD_ALIGNMENT MY_ALIGNOF(my_build_t)
#define MY_BUILD_ALIGNMENT_ALIAS MY_ALIGNOF_KW(my_build_t)

/*@ requires n <= 1024;
    assigns \nothing;
    ensures \result >= n;
    ensures \result < n + MY_BUILD_ALIGNMENT;
    ensures \result % MY_BUILD_ALIGNMENT == 0;
    ensures \result % MY_BUILD_ALIGNMENT_ALIAS == 0;
*/
size_t align_build(size_t n) {
    size_t a = MY_BUILD_ALIGNMENT;
    size_t rem = n % a;
    return rem == 0 ? n : n + (a - rem);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    (void)data;
    size_t n = size <= 1024 ? size : 1024;
    return align_build(n) >= n ? 0 : 1;
}
"""

DIRECT_ALIGNOF_LIKE = r"""#include <stddef.h>
typedef struct { int a; double b; } my_t;
/*@ assigns \nothing;
    ensures \result == __alignof__(my_t); */
size_t get_align(void) { return __alignof__(my_t); }
"""


@pytest.mark.integration
@pytest.mark.slow
def test_wp_and_eacsl_guardrail_agree_on_alignof_macros_under_default_and_c99(tmp_path):
    require_docker_images(ANALYSIS_IMAGE)
    (tmp_path / "mpack_align.c").write_text(MPACK_ALIGN_LIKE, encoding="utf-8", newline="\n")
    (tmp_path / "direct_align.c").write_text(DIRECT_ALIGNOF_LIKE, encoding="utf-8", newline="\n")
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "seed1").write_bytes(b"abc")
    (corpus / "seed2").write_bytes(b"12345678")

    probe = (
        'trap \'for f in /w/*.err /w/*.stdout; do [ -s "$f" ] && echo "=== $f ===" && tail -n 40 "$f"; done\' EXIT; '
        "set -e; cd /w; "
        "export PYTHONPATH=/opt/framac-pipeline/scripts; "
        # (a) Default (no -std=): both WP and E-ACSL guardrail use C11+/gnu17, so MY_BUILD_ALIGNMENT
        # expands to _Alignof(my_build_t) directly with no __alignof__ rewrite needed.
        "python3 /opt/framac-pipeline/scripts/run_wp_function.py "
        "--file mpack_align.c --function align_build --cppflags '-I.' "
        "--out-dir /w/wp_default --out-json /w/wp_default.json > /w/wp_default.stdout 2> /w/wp_default.err; "
        "python3 /opt/framac-pipeline/scripts/run_eacsl_fuzz.py guardrail "
        "--sources mpack_align.c --cppflags '-I.' --out-bin /w/guard_default "
        "--corpus-dir /w/corpus --functions align_build --extra-runs 0 --no-cache "
        "--out-json /w/guard_default.json > /w/guard_default.stdout 2> /w/guard_default.err; "
        # (b) Explicit -std=c99: both WP and E-ACSL guardrail hit the __alignof__ branch; the
        # wrapper rewrites `#define` bodies to `_Alignof`, so both prove and pass cleanly.
        "python3 /opt/framac-pipeline/scripts/run_wp_function.py "
        "--file mpack_align.c --function align_build --cppflags '-I. -std=c99' "
        "--out-dir /w/wp_c99 --out-json /w/wp_c99.json > /w/wp_c99.stdout 2> /w/wp_c99.err; "
        "python3 /opt/framac-pipeline/scripts/run_eacsl_fuzz.py guardrail "
        "--sources mpack_align.c --cppflags '-I. -std=c99' --out-bin /w/guard_c99 "
        "--corpus-dir /w/corpus --functions align_build --extra-runs 0 --no-cache "
        "--out-json /w/guard_c99.json > /w/guard_c99.stdout 2> /w/guard_c99.err; "
        # Direct `__alignof__(my_t)` written inside an ACSL annotation also proves under -std=c99.
        "python3 /opt/framac-pipeline/scripts/run_wp_function.py "
        "--file direct_align.c --function get_align --cppflags '-I. -std=c99' "
        "--out-dir /w/wp_direct --out-json /w/wp_direct.json > /w/wp_direct.stdout 2> /w/wp_direct.err; "
        # Negative control: with FRAMAC_CPP_REWRITE=off under -std=c99, Frama-C rejects __alignof__(.
        "FRAMAC_CPP_REWRITE=off python3 /opt/framac-pipeline/scripts/run_wp_function.py "
        "--file mpack_align.c --function align_build --cppflags '-I. -std=c99' "
        "--out-dir /w/wp_c99_off --out-json /w/wp_c99_off.json > /w/wp_c99_off.stdout 2> /w/wp_c99_off.err || true; "
        "echo PROBE_DONE"
    )
    proc = subprocess.run(
        [
            "docker", "run", "--rm", "--network", "none",
            "-v", f"{tmp_path}:/w",
            "-v", f"{ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
            "-v", f"{ROOT / 'templates'}:/opt/framac-pipeline/templates:ro",
            "--entrypoint", "bash", ANALYSIS_IMAGE, "-c", probe,
        ],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900, check=False,
    )  # fmt: skip
    log = proc.stdout + proc.stderr
    assert proc.returncode == 0 and "PROBE_DONE" in log, log

    import json

    wp_default = json.loads((tmp_path / "wp_default.json").read_text(encoding="utf-8"))
    guard_default = json.loads((tmp_path / "guard_default.json").read_text(encoding="utf-8"))
    guard_default_log = (tmp_path / "guard_default.compile.log").read_text(encoding="utf-8", errors="replace")
    assert wp_default["status"] == "all_proven", wp_default
    assert guard_default["status"] == "passed_dynamic_oracle", guard_default
    assert "-std=gnu17" in guard_default_log, guard_default_log
    assert "`__alignof__`" not in guard_default_log, guard_default_log

    wp_c99 = json.loads((tmp_path / "wp_c99.json").read_text(encoding="utf-8"))
    guard_c99 = json.loads((tmp_path / "guard_c99.json").read_text(encoding="utf-8"))
    guard_c99_log = (tmp_path / "guard_c99.compile.log").read_text(encoding="utf-8", errors="replace")
    assert wp_c99["status"] == "all_proven", wp_c99
    assert guard_c99["status"] == "passed_dynamic_oracle", guard_c99
    assert "[fc-cpp]" in guard_c99_log and "`__alignof__`" in guard_c99_log, guard_c99_log

    wp_direct = json.loads((tmp_path / "wp_direct.json").read_text(encoding="utf-8"))
    assert wp_direct["status"] == "all_proven", wp_direct

    wp_c99_off = json.loads((tmp_path / "wp_c99_off.json").read_text(encoding="utf-8"))
    assert wp_c99_off["status"] != "all_proven", wp_c99_off
    off_text = json.dumps(wp_c99_off) + (tmp_path / "wp_c99_off.err").read_text(encoding="utf-8", errors="replace")
    assert "unexpected token ')'" in off_text, off_text
