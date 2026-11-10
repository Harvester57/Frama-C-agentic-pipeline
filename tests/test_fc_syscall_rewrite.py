"""
scripts/fc_cpp_wrapper.py, typed `syscall` rewrites (plan step S6): `syscall(<x86_64 number>, ...)` becomes
`__fc_syscall_<name>(...)` for read, recvfrom and getrandom when the preprocessed text declares the target.
"""

from __future__ import annotations

import pytest

import fc_cpp_wrapper as W
from conftest import ROOT

pytestmark = pytest.mark.unit

CC1 = "/usr/libexec/gcc/x86_64-linux-gnu/14/cc1"
DECLS = (
    "long syscall(long number, ...);\n"
    "long __fc_syscall_read(int fd, void *buf, size_t count);\n"
    "long __fc_syscall_recvfrom(int sockfd, void *buf, size_t len, int flags, void *src_addr, void *addrlen);\n"
    "long __fc_syscall_getrandom(void *buf, size_t buflen, unsigned int flags);\n"
)


def _pp(body: str, decls: str = DECLS, file: str = "src/rand.c", line: int = 10) -> str:
    """Preprocessed text: the force-included declarations, then the target file from `line` on."""
    return f'# 1 "<built-in>"\n# 1 "fc_compat_types.h"\n{decls}# {line} "{file}"\n{body}'


def test_a_constant_number_becomes_the_typed_call_and_is_logged():
    text = _pp("long f(char *b) { return syscall(318, b, 16, 0); }\n")
    new, notes = W.rewrite_syscall_text(text)
    assert "return __fc_syscall_getrandom(b, 16, 0);" in new
    assert notes == [
        {
            "file": "src/rand.c",
            "line": 10,
            "kind": "syscall getrandom",
            "original": "syscall(318, b, 16, 0)",
            "rewritten": "__fc_syscall_getrandom(b, 16, 0)",
        }
    ]
    assert "long syscall(long number, ...);" in new  # the declaration is not a call


@pytest.mark.parametrize(
    ("call", "expected"),
    [
        ("syscall(0, fd, buf, sizeof(buf))", "__fc_syscall_read(fd, buf, sizeof(buf))"),
        (
            "syscall((long)45, s, b, n, 0, (void *)0, (void *)0)",
            "__fc_syscall_recvfrom(s, b, n, 0, (void *)0, (void *)0)",
        ),
        ("syscall ( (318) , p , f(a, b) , 0x1U )", "__fc_syscall_getrandom(p, f(a, b), 0x1U)"),
        ("syscall(0x13e, p, n, 0)", "__fc_syscall_getrandom(p, n, 0)"),
    ],
)
def test_number_and_argument_forms(call, expected):
    new, notes = W.rewrite_syscall_text(_pp(f"long r = {call};\n"))
    assert f"long r = {expected};" in new and len(notes) == 1


@pytest.mark.parametrize(
    "body",
    [
        "long r = syscall(317, a, b, c);\n",  # a number without a typed declaration
        "long r = syscall(n, a, b, c);\n",  # not a constant
        "long r = syscall(318, a, b);\n",  # wrong argument count
        "long r = o.syscall(318, a, b, c);\n",  # a member, not the function
        "long r = p->syscall(318, a, b, c);\n",
        "long r = my_syscall(318, a, b, c);\n",
        '/* syscall(318, a, b, c) */ const char *s = "syscall(318, a, b, c)";\n',
        "/*@ assigns \\nothing; ensures \\result == syscall(318, a, b, c); */\n",
    ],
)
def test_other_calls_are_left_alone(body):
    text = _pp(body)
    assert W.rewrite_syscall_text(text) == (text, [])


def test_nothing_happens_without_the_typed_declarations():
    # E-ACSL builds: fc_compat_types.h declares the typed functions in its __fc_libc branch only.
    text = _pp("long r = syscall(318, a, 16, 0);\n", decls="long syscall(long number, ...);\n")
    assert W.rewrite_syscall_text(text) == (text, [])
    only_read = _pp(
        "long r = syscall(318, a, 16, 0); long s = syscall(0, 3, a, 1);\n",
        decls="long __fc_syscall_read(int fd, void *buf, size_t count);\n",
    )
    new, notes = W.rewrite_syscall_text(only_read)
    assert [n["kind"] for n in notes] == ["syscall read"] and "syscall(318, a, 16, 0)" in new


def test_a_multi_line_call_keeps_the_line_count():
    text = _pp("long r = syscall(318,\n  buf,\n  16, 0);\nint after;\n")
    new, notes = W.rewrite_syscall_text(text)
    assert new.count("\n") == text.count("\n")
    assert "__fc_syscall_getrandom(buf, 16, 0)\n\n;\nint after;" in new and notes[0]["line"] == 10


def test_line_markers_around_a_system_macro_stay_in_place():
    # What gcc writes for `syscall(SYS_getrandom, buf, sizeof buf, 0)` (glibc's <sys/syscall.h>, -dD).
    body = (
        "  long r = syscall(\n"
        '# 7 "/w/r.c" 3 4\n'
        "                  318\n"
        '# 7 "/w/r.c"\n'
        "                               , buf, sizeof buf, 0);\n"
        "  if (r != 16) return -1;\n"
    )
    text = _pp(body, file="/w/r.c", line=7)
    new, notes = W.rewrite_syscall_text(text)
    assert (
        '  long r = __fc_syscall_getrandom(buf, sizeof buf, 0)\n# 7 "/w/r.c" 3 4\n\n# 7 "/w/r.c"\n;\n'
        "  if (r != 16) return -1;\n"
    ) in new
    assert new.count("\n") == text.count("\n")
    assert notes[0]["line"] == 7 and notes[0]["original"] == "syscall( 318 , buf, sizeof buf, 0)"


def test_the_file_rewrite_runs_it_after_preprocessing(tmp_path, capsys):
    out = tmp_path / "r.i"
    text = _pp("long r = syscall(318, b, 16, 0);\n")

    def call(cmd: list[str]) -> int:
        out.write_text(text, encoding="utf-8")
        return 0

    assert W.run([CC1, "-E", "src/rand.c", "-o", str(out)], call=call) == 0
    assert "__fc_syscall_getrandom(b, 16, 0)" in out.read_text(encoding="utf-8")
    assert "[fc-cpp] src/rand.c:10: syscall getrandom rewritten: syscall(318, b, 16, 0) -> " in capsys.readouterr().err


def test_typed_input_syscalls_are_input_readers_for_trust():
    import trust

    for name in ("read", "recvfrom"):
        assert f"{W.SYSCALL_PREFIX}{name}" in trust.INPUT_READERS


def test_every_typed_syscall_has_a_contract_in_the_fc_libc_branch_only():
    text = (ROOT / "templates" / "fc_stubs" / "fc_compat_types.h").read_text(encoding="utf-8")
    fc_libc = text.split("#else /* Frama-C __fc_libc */", 1)[1].split("#endif /* __FRAMAC_EACSL__ */", 1)[0]
    for name, _ in W.TYPED_SYSCALLS.values():
        decl = f"long {W.SYSCALL_PREFIX}{name}("
        assert text.count(decl) == 1 and decl in fc_libc, name
        before = fc_libc.split(decl, 1)[0]
        contract = before[before.rindex("/*@") :]
        assert "assigns" in contract and "ensures" in contract and "*/" in contract, name
