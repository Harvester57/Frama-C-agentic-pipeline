"""
Contracts of templates/fc_stubs/fc_compat_types.h against the real Frama-C (FRAMAC_DOCKER_TESTS=1), plan
docs/plans/templates-and-stubs-improvement-plan.md: typed syscalls (S6), the LP64 assertion (S9), the wipe
contracts (M6), the string vocabulary (S8).
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

from conftest import ANALYSIS_IMAGE, ROOT, require_docker_images, wp_proved_goals

image = pytest.mark.integration
slow = pytest.mark.slow

PY = 'import sys; sys.path.insert(0, "/opt/framac-pipeline/scripts"); '
FRAMAC_FLAGS = f"A=$(python3 -c '{PY}import framac_common; print(framac_common.augment_framac_cppflags(\"-I.\"))'); "
EACSL_FLAGS = (
    f"F=$(python3 -c '{PY}import eacsl_toolchain as T; "
    'print(T.build_eacsl_flag_sets("-I.", fuzzer=False)["frontend"])\'); '
)


def _run_in_image(tmp_path: Path, files: dict[str, str], script: str, timeout: int = 900) -> str:
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8", newline="\n")
    proc = subprocess.run(
        [
            "docker", "run", "--rm", "--network", "none",
            "-v", f"{tmp_path}:/w",
            "-v", f"{ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
            "-v", f"{ROOT / 'templates'}:/opt/framac-pipeline/templates:ro",
            "--entrypoint", "bash", ANALYSIS_IMAGE, "-c", "cd /w; " + script,
        ],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, check=False,
    )  # fmt: skip
    log = proc.stdout + proc.stderr
    assert proc.returncode == 0, log
    return log


def _proved(log: str, tag: str) -> tuple[int, int]:
    """(proved, total) over every WP summary line of the section: at least one, none with zero goals."""
    section = log.split(f"=={tag}==", 1)[1].split("==", 1)[0]
    goals = wp_proved_goals(section)
    return sum(p for p, _ in goals), sum(t for _, t in goals)


# ---------------------------------------------------------------------------------------------------
# S6: syscall(SYS_x, ...) -> __fc_syscall_x(...)
# ---------------------------------------------------------------------------------------------------

SYSCALLS_C = r"""#include <sys/syscall.h>
#include <unistd.h>
#include <sys/socket.h>

int seed(void) {
  char buf[16];
  long r = syscall(SYS_getrandom, buf, sizeof buf, 0);
  if (r != (long)sizeof buf) return -1;
  /*@ assert filled: \initialized(&buf[0 .. 15]); */
  return buf[0] + buf[15];
}

int rd(int fd) {
  char b[8];
  long n = syscall(SYS_read, fd, b, sizeof b);
  if (n < 1) return -1;
  /*@ assert got: \initialized(&b[0 .. n - 1]); */
  return b[n - 1];
}

int rf(int s) {
  char b[8];
  struct sockaddr sa;
  socklen_t l = sizeof sa;
  long n = syscall(SYS_recvfrom, s, b, sizeof b, 0, &sa, &l);
  if (n < 1) return -1;
  return b[n - 1] + sa.sa_family;
}

long other(void) { return syscall(SYS_getpid); }

int main(void) { return seed() + rd(0) + rf(3) + (int)other(); }
"""


@image
@slow
def test_typed_syscalls_write_their_buffers_in_eva_and_wp_and_never_reach_eacsl(tmp_path):
    require_docker_images(ANALYSIS_IMAGE)
    script = (
        FRAMAC_FLAGS + EACSL_FLAGS + "set -e; "
        'echo "==eva=="; frama-c -no-unicode s.c -cpp-extra-args="$A" -eva -eva-precision 1 2>&1; '
        'echo "==wp=="; frama-c -no-unicode s.c -cpp-extra-args="$A" -wp -wp-model Typed -wp-check-memory-model '
        "-wp-rte -wp-fct seed,rd -wp-timeout 20 -wp-cache none 2>&1; "
        'echo "==eacsl=="; gcc -E -D__FRAMAC__ $F s.c -o eacsl.i 2>&1; '
        'echo "eacsl typed: $(grep -c __fc_syscall_ eacsl.i || true)"; echo "==end=="'
    )
    log = _run_in_image(tmp_path, {"s.c": SYSCALLS_C}, script)
    eva = log.split("==eva==", 1)[1].split("==wp==", 1)[0]
    for line, name in ((7, "getrandom"), (15, "read"), (25, "recvfrom")):
        assert f"[fc-cpp] /w/s.c:{line}: syscall {name} rewritten" in eva, eva
    assert "syscall getpid" not in eva  # other numbers keep syscall's own contract
    # The buffer getrandom filled is initialized once the count was checked (it stayed uninitialized before).
    assert "&(buf[0])" not in eva and "&buf[15]" not in eva, eva
    assert "invalid memory access" not in eva, eva
    proved, total = _proved(log, "wp")
    assert proved == total, log.split("==wp==", 1)[1]
    assert "eacsl typed: 0" in log  # E-ACSL keeps the real syscall


# ---------------------------------------------------------------------------------------------------
# S9: the header refuses a machdep that is not LP64
# ---------------------------------------------------------------------------------------------------


@pytest.mark.unit
def test_the_lp64_assertion_guards_every_frama_c_parse():
    text = (ROOT / "templates" / "fc_stubs" / "fc_compat_types.h").read_text(encoding="utf-8")
    head = text.split("#if defined(__FRAMAC__)\n", 1)[1].split("#if defined(__FRAMAC_EACSL__)", 1)[0]
    assert "_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8," in head  # both branches see it


@image
@slow
def test_a_non_lp64_machdep_stops_at_parse_time(tmp_path):
    require_docker_images(ANALYSIS_IMAGE)
    script = (
        FRAMAC_FLAGS + 'echo "==x86_64=="; frama-c -no-unicode m.c -cpp-extra-args="$A" -machdep x86_64 2>&1; '
        'echo "rc=$?"; echo "==x86_32=="; frama-c -no-unicode m.c -cpp-extra-args="$A" -machdep x86_32 2>&1; '
        'echo "rc=$?"; echo "==end=="'
    )
    log = _run_in_image(tmp_path, {"m.c": "int main(void) { return 0; }\n"}, script)
    good = log.split("==x86_64==", 1)[1].split("==x86_32==", 1)[0]
    bad = log.split("==x86_32==", 1)[1]
    assert "rc=0" in good, good
    assert "rc=0" not in bad and "assumes an LP64 machdep" in bad, bad


# ---------------------------------------------------------------------------------------------------
# M6: a wipe through explicit_bzero or memset_s proves without a loop
# ---------------------------------------------------------------------------------------------------

WIPE_C = r"""#include <string.h>
#include <stdint.h>

static char ckey[16];
static char mkey[16];
static unsigned char ukey[16];
static uint8_t u8key[32];

/*@ assigns ckey[0 .. 15];
    ensures wiped: \forall integer i; 0 <= i < 16 ==> ckey[i] == 0; */
void close_c(void) { explicit_bzero(ckey, sizeof ckey); }

/*@ assigns mkey[0 .. 15];
    ensures wiped: \forall integer i; 0 <= i < 16 ==> mkey[i] == 0; */
void close_m(void) { (void)memset_s(mkey, sizeof mkey, 0, sizeof mkey); }

/*@ assigns ukey[0 .. 15];
    ensures wiped: \forall integer i; 0 <= i < 16 ==> ukey[i] == 0; */
void close_u(void) { explicit_bzero(ukey, sizeof ukey); }

/*@ assigns u8key[0 .. 31];
    ensures wiped: \forall integer i; 0 <= i < 32 ==> u8key[i] == 0; */
void close_u8(void) { (void)memset_s(u8key, sizeof u8key, 0, sizeof u8key); }

/*@ assigns ckey[0 .. 15];
    ensures wiped: \forall integer i; 0 <= i < 16 ==> ckey[i] == 0; */
void close_short(void) { explicit_bzero(ckey, 8); }

int main(void) {
  ckey[3] = 7; close_c();
  mkey[3] = 7; close_m();
  /*@ assert eva_wiped: ckey[3] == 0 && mkey[15] == 0; */
  return 0;
}
"""


def _wp_unproved(log: str, tag: str) -> set[str]:
    section = log.split(f"=={tag}==", 1)[1].split("==", 1)[0]
    return set(re.findall(r"\[wp\] \[(?:Timeout|Unknown|Failed)\] (\S+)", section))


@image
@slow
def test_a_wipe_through_explicit_bzero_or_memset_s_proves_without_a_loop(tmp_path):
    require_docker_images(ANALYSIS_IMAGE)
    wp = (
        'frama-c -no-unicode w.c -cpp-extra-args="$A" -wp -wp-check-memory-model -wp-rte -wp-timeout 20 '
        "-wp-cache none -wp-fct close_c,close_m,close_u,close_u8,close_short -wp-model"
    )
    script = (
        FRAMAC_FLAGS + f'echo "==typed=="; {wp} Typed 2>&1; echo "==cast=="; {wp} Typed+cast 2>&1; '
        'echo "==eva=="; frama-c -no-unicode w.c -cpp-extra-args="$A" -eva 2>&1; echo "==end=="'
    )
    log = _run_in_image(tmp_path, {"w.c": WIPE_C}, script)
    typed, cast = _wp_unproved(log, "typed"), _wp_unproved(log, "cast")
    # Typed, the model whose proofs count: a `char` key, through either function.
    assert not {g for g in typed if g.startswith(("typed_close_c_", "typed_close_m_"))}, typed
    # An unsigned char / uint8_t key: Typed rejects its conversion to `void *`; Typed+cast proves it.
    assert any(g.startswith("typed_close_u_") for g in typed), typed
    assert not {g for g in cast if g.startswith(("typed_cast_close_u_", "typed_cast_close_u8_"))}, cast
    # A partial wipe never proves.
    assert "typed_close_short_ensures_wiped" in typed and "typed_cast_close_short_ensures_wiped" in cast
    assert "Assertions        1 valid" in log.split("==eva==", 1)[1], log


# ---------------------------------------------------------------------------------------------------
# S8: one string vocabulary (Frama-C libc's names), executable under E-ACSL
# ---------------------------------------------------------------------------------------------------

STRINGS = ("valid_read_string", "valid_string", "valid_read_nstring", "valid_string_or_null")


def _eacsl_string_block() -> str:
    text = (ROOT / "templates" / "fc_stubs" / "fc_compat_types.h").read_text(encoding="utf-8")
    marker = text.index("The string vocabulary")
    start = text.index("/*@", marker)
    return text[start : text.index("*/", start)]


@pytest.mark.unit
def test_eacsl_builds_define_libc_s_string_names_and_nothing_else():
    block = _eacsl_string_block()
    defined = set(re.findall(r"predicate (\w+)\(", block))
    # Plus the private helpers that keep one predicate call after each quantifier guard
    # (E-ACSL 35 drops the first conjunct of `\exists i; guard && P && Q`).
    assert defined - {"__fc_eacsl_read_nul_at", "__fc_eacsl_nul_at"} == set(STRINGS)
    logic_fns = set(re.findall(r"logic\s+[\w\s]+?\s+(\w+)\(", block))
    assert logic_fns - {"__fc_eacsl_strlen_inc"} == {"strlen"}
    # C integer return type avoids GMP in E-ACSL loop variants; the non-recursive helper avoids
    # E-ACSL duplicating the recursive call 3x inside an explicit cast's overflow RTE check.
    assert "logic unsigned int strlen(char *s)" in block
    assert "logic integer strlen(" not in block
    assert "__fc_eacsl_strlen_inc(strlen(s + 1))" in block
    assert "valid_nstring" not in (ROOT / "templates" / "fc_stubs" / "fc_compat_types.h").read_text(encoding="utf-8")
    # libc semantics: n readable initialized bytes, or a shorter string.
    nstring = block.split("predicate valid_read_nstring", 1)[1].split("predicate", 1)[0]
    assert "\\initialized(s + (0 .. n - 1))" in nstring and "|| valid_read_string(s)" in nstring


@pytest.mark.unit
def test_the_vocabulary_names_the_canonical_strings_and_keeps_the_aliases():
    vocab = (ROOT / "templates" / "acsl" / "acsl_vocabulary.h").read_text(encoding="utf-8")
    for name in (*STRINGS, "strlen(s)", "no_crlf_string(s)"):
        assert name in vocab, name
    assert '#include "__fc_string_axiomatic.h"' in vocab
    assert "predicate valid_c_string(char *s) = valid_read_string(s);" in vocab
    assert "logic integer c_strlen(char *s) = strlen(s);" in vocab
    for brief in ("prover_brief.md", "header_architect_brief.md"):
        text = (ROOT / "skills" / "framac-wp" / brief).read_text(encoding="utf-8")
        assert "One String Vocabulary" in text and "no_crlf_string(s)" in text, brief
        assert "valid_c_string(s)` (" not in text  # named only as a name never to write


STRINGS_C = r"""#include <string.h>
#include <stdio.h>

/*@ requires valid_read_string(s);
    requires valid_c_string(s);
    requires no_crlf_string(s);
    requires strlen(s) < 64 && c_strlen(s) == strlen(s);
    assigns \nothing;
    ensures \result == strlen(s); */
size_t len(const char *s) { return strlen(s); }

/*@ requires valid_read_nstring(s, n);
    assigns \nothing; */
size_t nlen(const char *s, size_t n) { return strnlen(s, n); }

/*@ requires valid_string_or_null(s);
    assigns \nothing; */
int first(char *s) { return s ? s[0] : -1; }

int main(int argc, char **argv) {
  char ok[] = "hello";
  char raw[4] = {'a', 'b', 'c', 'd'};
  char crlf[] = "a\r\n";
  size_t a = len(ok);
  size_t b = nlen(raw, 4); /* libc semantics: 4 readable bytes, no NUL needed */
  size_t c = nlen(ok, 64); /* a string shorter than n */
  int d = first(0) + first(ok);
  printf("ok %zu %zu %zu %d\n", a, b, c, d);
  fflush(stdout);
  if (argc > 1 && argv[1][0] == 'r') return (int)len(raw); /* not a string: must fail */
  if (argc > 1 && argv[1][0] == 'c') return (int)len(crlf); /* CR/LF: must fail */
  return 0;
}
"""


@image
@slow
def test_the_string_vocabulary_runs_under_eacsl_and_proves_under_wp(tmp_path):
    require_docker_images(ANALYSIS_IMAGE)
    script = (
        FRAMAC_FLAGS + EACSL_FLAGS + 'echo "==eacsl=="; '
        'e-acsl-gcc -c -F -e-acsl-full-mtracking -E "$F" -o s.frama.c -O bin s.c > build.log 2>&1; echo "build=$?"; '
        './bin.e-acsl 2>&1; echo "run_ok=$?"; ./bin.e-acsl r 2>&1; echo "run_raw=$?"; ./bin.e-acsl c 2>&1; echo "run_crlf=$?"; '
        'echo "==wp=="; frama-c -no-unicode s.c -cpp-extra-args="$A" -wp -wp-model Typed -wp-check-memory-model '
        "-wp-rte -wp-fct len,nlen,first -wp-timeout 20 -wp-cache none 2>&1; "
        'echo "==eva=="; frama-c -no-unicode s.c -cpp-extra-args="$A" -eva 2>&1; echo "==end=="'
    )
    log = _run_in_image(tmp_path, {"s.c": STRINGS_C}, script)
    eacsl = log.split("==eacsl==", 1)[1].split("==wp==", 1)[0]
    assert "build=0" in eacsl, (tmp_path / "build.log").read_text(encoding="utf-8", errors="replace")
    # Every name executes, the unterminated n-byte buffer satisfies valid_read_nstring (libc semantics).
    assert "ok 5 4 5 103" in eacsl and "run_ok=0" in eacsl, eacsl
    assert "run_raw=0" not in eacsl and "run_crlf=0" not in eacsl, eacsl
    assert "no_crlf_string" in eacsl.split("run_raw=", 1)[1], eacsl
    proved, total = _proved(log, "wp")
    assert proved == total, log.split("==wp==", 1)[1]
    eva = log.split("==eva==", 1)[1]
    assert eva.count("Invalid") + eva.count("invalid") >= 1, eva


STRLEN_VARIANT_C = r"""#include <stdio.h>
#include <string.h>

/*@ requires valid_read_string(s);
  @ terminates \true;
  @ exits \false;
  @ assigns \nothing;
  @ ensures \result >= 0; */
int walk_ptr(const char *s) {
  int acc = 0;
  /*@ loop invariant valid_read_string(s);
    @ loop invariant acc >= 0;
    @ loop assigns s, acc;
    @ loop variant strlen(s) + 0; */
  while (*s != '\0') {
    acc ^= (unsigned char)*s;
    s++;
  }
  return acc;
}

/*@ requires valid_read_string(s);
  @ requires strlen(s) <= 1024;
  @ terminates \true;
  @ exits \false;
  @ assigns \nothing;
  @ ensures \result == strlen(s); */
size_t walk_plus1(const char *s) {
  size_t n = 0;
  /*@ loop invariant valid_read_string(s);
    @ loop invariant n + strlen(s) == \at(strlen(s), Pre);
    @ loop assigns s, n;
    @ loop variant strlen(s) + 1; */
  while (*s != '\0') {
    n++;
    s++;
  }
  return n;
}

/*@ requires valid_read_string(s);
  @ requires strlen(s) <= 1024;
  @ terminates \true;
  @ exits \false;
  @ assigns \nothing;
  @ ensures \result == strlen(s); */
int walk_idx(const char *s) {
  int i = 0;
  /*@ loop invariant 0 <= i <= strlen(s);
    @ loop assigns i;
    @ loop variant strlen(s) - i; */
  while (s[i] != '\0') {
    i++;
  }
  return i;
}

/*@ requires valid_read_string(s);
  @ assigns \nothing; */
int walk_bad(const char *s) {
  int step = 0;
  /*@ loop invariant valid_read_string(s);
    @ loop assigns s, step;
    @ loop variant strlen(s) + 0; */
  while (*s != '\0') {
    if (step == 0) {
      step = 1;
    } else {
      s++;
    }
  }
  return step;
}

int main(int argc, char **argv) {
  char empty[] = "";
  char buf[65];
  memset(buf, 'a', 64);
  buf[64] = '\0';
  printf("ok %d %zu %d\n", walk_ptr(empty), walk_plus1(buf), walk_idx(buf));
  fflush(stdout);
  if (argc > 1 && argv[1][0] == 'b') return walk_bad(buf);
  return 0;
}
"""


@image
@slow
def test_strlen_loop_variant_proves_under_wp_and_is_checked_at_runtime_under_eacsl(tmp_path):
    require_docker_images(ANALYSIS_IMAGE)
    eacsl_flags = (
        f"F=$(python3 -c '{PY}import eacsl_toolchain as T; "
        'print(T.build_eacsl_flag_sets("-I.", fuzzer=False, full_mtracking=True)["frontend"])\'); '
        f"B=$(python3 -c '{PY}import eacsl_toolchain as T; "
        'print(T.build_eacsl_flag_sets("-I.", fuzzer=False, full_mtracking=True)["backend"])\'); '
    )
    checks = "--libc-replacements --validate-format-strings"
    script = (
        FRAMAC_FLAGS + eacsl_flags + 'echo "==eacsl=="; '
        f"e-acsl-gcc -n --no-constfold {checks} -G clang "
        f'-F "-rte -machdep gcc_x86_64 -e-acsl-full-mtracking -rte-initialized @all -warn-unsigned-downcast" '
        '-E "$F" -o v.inst.c v.c > s1.log 2>&1; echo "stage1=$?"; '
        f'e-acsl-gcc -C {checks} -G clang -e "$B" -O vbin v.inst.c > s2.log 2>&1; echo "stage2=$?"; '
        'timeout 10 ./vbin.e-acsl 2>&1; echo "run_ok=$?"; '
        'timeout 10 ./vbin.e-acsl b 2>&1; echo "run_bad=$?"; '
        'echo "==wp=="; frama-c -no-unicode -machdep gcc_x86_64 v.c -cpp-extra-args="$A" '
        "-wp -wp-model Typed -wp-check-memory-model -wp-rte -wp-fct walk_ptr,walk_plus1,walk_idx "
        '-wp-timeout 20 -wp-cache none 2>&1; echo "==end=="'
    )
    log = _run_in_image(tmp_path, {"v.c": STRLEN_VARIANT_C}, script, timeout=600)
    s1_log = (tmp_path / "s1.log").read_text(encoding="utf-8", errors="replace")
    s2_log = (tmp_path / "s2.log").read_text(encoding="utf-8", errors="replace")
    eacsl = log.split("==eacsl==", 1)[1].split("==wp==", 1)[0]
    assert "stage1=0" in eacsl, s1_log
    assert "stage2=0" in eacsl, s2_log
    assert "loop variant using GMP" not in s1_log, s1_log
    inst = (tmp_path / "v.inst.c").read_text(encoding="utf-8", errors="replace")
    assert inst.count('kind = "Variant"') == 8, inst
    for sig, expected_rec in (
        ("unsigned int __gen_e_acsl___fc_eacsl_strlen_inc(unsigned int n)\n{", 0),
        ("unsigned int __gen_e_acsl_strlen_here(char *s)\n{", 1),
    ):
        idx = inst.index(sig)
        body = inst[idx : inst.index("\n}\n", idx) + 3]
        assert "__gmpz_" not in body, body
        assert body.count("__gen_e_acsl_strlen_here(") == expected_rec + (1 if expected_rec else 0), body
    assert "ok 0 64 64" in eacsl and "run_ok=0" in eacsl, eacsl
    assert "run_bad=0" not in eacsl and "Variant failed" in eacsl, eacsl
    proved, total = _proved(log, "wp")
    assert proved == total, log.split("==wp==", 1)[1]


# ---------------------------------------------------------------------------------------------------
# GCC's `__restrict__` on the E-ACSL frontend (mpack run-3, 2026-11-17): Frama-C's parser knows
# `restrict` and `__restrict` only; its own libc maps the GCC spelling (features.h), host glibc does not.
# ---------------------------------------------------------------------------------------------------

RESTRICT_C = r"""#include <string.h>
#include <stdio.h>
#include <wchar.h>

#define MPACK_RESTRICT __restrict__

struct w { char *position; };

void cp(char *__restrict__ dst, const char *__restrict__ src, size_t n);
void cp(char *MPACK_RESTRICT dst, const char *MPACK_RESTRICT src, size_t n) { memcpy(dst, src, n); }

void d(struct w *writer) { char *MPACK_RESTRICT p = writer->position; p[0] = 0; }

int main(void) {
  char a[4] = "abc", b[4];
  struct w x = { b };
  cp(b, a, 4);
  d(&x);
  printf("ok %d\n", (int)strlen(b + 1));
  return 0;
}
"""


def _eacsl_host_block() -> str:
    text = (ROOT / "templates" / "fc_stubs" / "fc_compat_types.h").read_text(encoding="utf-8")
    start = text.index("#if defined(__FRAMAC_EACSL__)")
    return text[start : text.index("#else /* Frama-C __fc_libc */", start)]


@pytest.mark.unit
def test_eacsl_host_headers_map_the_gcc_restrict_spelling_before_any_include():
    block = _eacsl_host_block()
    define = "#ifndef __restrict__\n#define __restrict__ __restrict\n#endif"
    assert define in block, block[:400]
    assert block.index(define) < block.index("#include <stdint.h>")
    # Inside the __FRAMAC__ guard: a clang compile without Frama-C never sees it.
    text = (ROOT / "templates" / "fc_stubs" / "fc_compat_types.h").read_text(encoding="utf-8")
    assert text.index("#if defined(__FRAMAC__)") < text.index(define)


@image
@slow
def test_gcc_restrict_spelling_builds_under_eacsl_and_clang(tmp_path):
    require_docker_images(ANALYSIS_IMAGE)
    script = (
        EACSL_FLAGS + 'echo "==eacsl=="; '
        'e-acsl-gcc -c -F -e-acsl-full-mtracking -E "$F" -o r.frama.c -O bin r.c > build.log 2>&1; echo "build=$?"; '
        './bin.e-acsl 2>&1; echo "run=$?"; '
        'echo "==cpp=="; gcc -E -D__FRAMAC__ $F r.c 2>/dev/null | grep -c __restrict__; '
        'echo "==clang=="; clang -fsyntax-only -include /opt/framac-pipeline/templates/fc_stubs/fc_compat_types.h r.c 2>&1; '
        'echo "clang=$?"; echo "==end=="'
    )
    log = _run_in_image(tmp_path, {"r.c": RESTRICT_C}, script, timeout=600)
    eacsl = log.split("==eacsl==", 1)[1].split("==cpp==", 1)[0]
    assert "build=0" in eacsl, (tmp_path / "build.log").read_text(encoding="utf-8", errors="replace")
    assert "ok 2" in eacsl and "run=0" in eacsl, eacsl
    # No `__restrict__` survives the frontend preprocessing, from the target or from glibc.
    assert log.split("==cpp==", 1)[1].split("==clang==", 1)[0].strip() == "0", log
    assert "clang=0" in log.split("==clang==", 1)[1], log


# ---------------------------------------------------------------------------------------------------
# Checked-arithmetic builtins (mpack run-3, 2026-11-17): Frama-C called __builtin_add_overflow & co as
# undeclared functions; clang refused the E-ACSL output's redeclaration, Eva and WP lost the store.
# ---------------------------------------------------------------------------------------------------

OVERFLOW_BUILTINS = tuple(
    f"__builtin_{name}_overflow"
    for name in (
        "add", "sub", "mul",
        "sadd", "saddl", "saddll", "uadd", "uaddl", "uaddll",
        "ssub", "ssubl", "ssubll", "usub", "usubl", "usubll",
        "smul", "smull", "smulll", "umul", "umull", "umulll",
    )
) + ("__builtin_add_overflow_p", "__builtin_sub_overflow_p", "__builtin_mul_overflow_p")  # fmt: skip

OVERFLOW_C = r"""#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define P(e) printf("%d ", (int)(e))

static int calls;
static long next(long v) {
  calls++;
  return v;
}

/* mpack's use: size_t operands behind a cast, result through a pointer. */
int grow(size_t a, size_t b, size_t *out) { return __builtin_add_overflow((size_t)(a), (size_t)(b), out); }

int main(void) {
  int i;
  unsigned u;
  long l;
  unsigned long ul;
  long long ll;
  unsigned long long ull;
  signed char sc;
  unsigned char uc;
  short sh;
  size_t z;
  P(__builtin_add_overflow(INT_MAX, 1, &i)); P(i);
  P(__builtin_add_overflow(INT_MIN, -1, &i)); P(i);
  P(__builtin_sub_overflow(0u, 1u, &u)); printf("%u ", u);
  P(__builtin_sub_overflow(0u, 1u, &i)); P(i);
  P(__builtin_add_overflow(-1, 1u, &u)); printf("%u ", u);
  P(__builtin_add_overflow(LLONG_MIN, LLONG_MIN, &ll)); printf("%lld ", ll);
  P(__builtin_sub_overflow(LLONG_MIN, 1, &ll)); printf("%lld ", ll);
  P(__builtin_mul_overflow(LLONG_MIN, -1, &ll)); printf("%lld ", ll);
  P(__builtin_mul_overflow(LLONG_MIN, -1, &ull)); printf("%llu ", ull);
  P(__builtin_mul_overflow(ULLONG_MAX, ULLONG_MAX, &ull)); printf("%llu ", ull);
  P(__builtin_mul_overflow(ULLONG_MAX, 2ull, &ll)); printf("%lld ", ll);
  P(__builtin_mul_overflow((size_t)1 << 40, (size_t)1 << 30, &ul)); printf("%lu ", ul);
  P(__builtin_mul_overflow(0x123456789abcdefull, 0xfedcba987654321ull, &ull)); printf("%llu ", ull);
  P(__builtin_mul_overflow(-0x123456789abcdefll, 0x7edcba987654321ll, &ll)); printf("%lld ", ll);
  P(__builtin_add_overflow(ULLONG_MAX, ULLONG_MAX, &ull)); printf("%llu ", ull);
  P(__builtin_add_overflow(200, 100, &uc)); P(uc);
  P(__builtin_add_overflow(100, 100, &sc)); P(sc);
  P(__builtin_sub_overflow(-100, 100, &sc)); P(sc);
  P(__builtin_mul_overflow(-300, 300, &sh)); P(sh);
  P(__builtin_sub_overflow(-5, -7, &u)); printf("%u ", u);
  P(__builtin_sub_overflow(5, 7, &ul)); printf("%lu ", ul);
  P(__builtin_sub_overflow(LLONG_MIN, LLONG_MAX, &ull)); printf("%llu ", ull);
  P(__builtin_sub_overflow(ULLONG_MAX, LLONG_MIN, &ll)); printf("%lld ", ll);
  i = 7; P(__builtin_add_overflow(i, i, &i)); P(i);
  calls = 0; P(__builtin_mul_overflow(next(3), next(4), &l)); P(l); P(calls);
  P(__builtin_add_overflow(1, 2, &i) || __builtin_mul_overflow(INT_MAX, 2, &i)); P(i);
  P(__builtin_add_overflow_p(INT_MAX, 1, (int)0));
  P(__builtin_mul_overflow_p(1000, 1000, (short)0));
  P(__builtin_sub_overflow_p(1, 2, 0u));
  P(__builtin_sadd_overflow(INT_MAX, 1, &i)); P(i);
  P(__builtin_uaddl_overflow(ULONG_MAX, 1ul, &ul)); printf("%lu ", ul);
  P(__builtin_umull_overflow(1ul << 33, 1ul << 31, &ul)); printf("%lu ", ul);
  P(__builtin_ssubll_overflow(LLONG_MIN, 1, &ll)); printf("%lld ", ll);
  P(grow(SIZE_MAX, 1, &z)); printf("%zu ", z);
  P(grow(40, 2, &z)); printf("%zu", z);
  printf("\n");
  return 0;
}
"""


@pytest.mark.unit
def test_overflow_builtins_are_defined_only_where_frama_c_lacks_them():
    text = (ROOT / "templates" / "fc_stubs" / "fc_compat_types.h").read_text(encoding="utf-8")
    framac = text.index("#if defined(__FRAMAC__)")
    block = text.index("#ifndef __FC_OVF")
    block_end = text.index("#endif /* __FC_OVF */")
    eacsl = text.index("#if defined(__FRAMAC_EACSL__)", block)
    eacsl_end = text.index("#endif /* __FRAMAC_EACSL__ */", eacsl)
    assert framac < block < eacsl < eacsl_end < block_end
    for name in OVERFLOW_BUILTINS:
        at = text.index(f"#define {name}(")
        assert block < at < block_end, name
        if name.endswith("_p"):
            # Frama-C's own libc has no `_p` form: every parse gets it.
            assert not eacsl < at < eacsl_end, name
        else:
            # FRAMAC_SHARE/libc/__fc_gcc_builtins.h declares these on a GCC machdep, after this header:
            # only the E-ACSL frontend (host headers) may define them.
            assert eacsl < at < eacsl_end, name


KERNEL_LIBC_C = r"""#include <stddef.h>
#include <stdint.h>

int typed(int a, int b, int *r) { return __builtin_sadd_overflow(a, b, r); }
int generic(size_t a, size_t b, size_t *r) { return __builtin_mul_overflow(a, b, r); }
int pred(size_t a, size_t b) { return __builtin_mul_overflow_p(a, b, (size_t)0); }

int main(void) {
  int i;
  size_t z;
  return typed(1, 2, &i) + generic(3, 4, &z) + pred(5, 6);
}
"""


@image
@slow
def test_overflow_builtins_parse_with_frama_c_libc_on_the_pipeline_machdep(tmp_path):
    """Eva, WP and Phase 0 parse with Frama-C's libc on gcc_x86_64, whose __fc_machdep.h includes
    __fc_gcc_builtins.h after the force-included compat header (2026-11-17: a macro for a typed form broke
    that header's declarations, `__fc_gcc_builtins.h:37: syntax error`)."""
    require_docker_images(ANALYSIS_IMAGE)
    warn = "-warn-signed-downcast -warn-unsigned-overflow -warn-unsigned-downcast"
    script = (
        FRAMAC_FLAGS + 'echo "==eva=="; '
        f'frama-c -no-unicode -machdep gcc_x86_64 k.c -cpp-extra-args="$A" -eva -eva-precision 1 {warn} 2>&1; '
        'echo "rc=$?"; echo "==end=="'
    )
    log = _run_in_image(tmp_path, {"k.c": KERNEL_LIBC_C}, script, timeout=300)
    eva = log.split("==eva==", 1)[1].split("==end==", 1)[0]
    assert "rc=0" in eva, eva
    assert "syntax error" not in eva, eva
    # The typed and generic forms come from Frama-C's libc, the `_p` form from the compat header.
    assert "implicit-function-declaration" not in eva and "missing-spec" not in eva, eva
    assert "0 alarms generated" in eva, eva


@image
@slow
def test_overflow_builtins_match_gcc_under_eacsl(tmp_path):
    require_docker_images(ANALYSIS_IMAGE)
    eacsl_flags = (
        f"F=$(python3 -c '{PY}import eacsl_toolchain as T; "
        'print(T.build_eacsl_flag_sets("-I.", fuzzer=False, full_mtracking=True)["frontend"])\'); '
        f"B=$(python3 -c '{PY}import eacsl_toolchain as T; "
        'print(T.build_eacsl_flag_sets("-I.", fuzzer=False, full_mtracking=True)["backend"])\'); '
    )
    checks = "--libc-replacements --validate-format-strings"
    script = (
        eacsl_flags + 'echo "==gcc=="; gcc -O1 -w o.c -o native && ./native; '
        # The two stages of scripts/fuzz_build.py, clang preprocessing and backend included.
        f'echo "==eacsl=="; e-acsl-gcc -n --no-constfold {checks} -G clang '
        f'-F "-rte -machdep gcc_x86_64 -e-acsl-full-mtracking -rte-initialized @all -warn-unsigned-downcast" '
        '-E "$F" -o o.instrumented.c o.c > s1.log 2>&1; echo "stage1=$?"; '
        f'e-acsl-gcc -C {checks} -G clang -e "$B" -O ebin o.instrumented.c > s2.log 2>&1; echo "stage2=$?"; '
        'echo "proto=$(grep -c "missing proto" o.instrumented.c)"; ./ebin.e-acsl; echo "run=$?"; '
        'echo "==end=="'
    )
    log = _run_in_image(tmp_path, {"o.c": OVERFLOW_C}, script, timeout=600)
    native = log.split("==gcc==", 1)[1].split("==eacsl==", 1)[0].strip()
    eacsl = log.split("==eacsl==", 1)[1].split("==end==", 1)[0]
    build = "\n".join(
        (tmp_path / f).read_text(encoding="utf-8", errors="replace")
        for f in ("s1.log", "s2.log")
        if (tmp_path / f).is_file()
    )
    assert "stage1=0" in eacsl and "stage2=0" in eacsl, build
    assert "proto=0" in eacsl, eacsl
    assert "run=0" in eacsl, eacsl
    # Same results as GCC's own builtins, case by case.
    assert native and native in eacsl, (native, eacsl)


# ---------------------------------------------------------------------------------------------------
# Modem-line bits (libmodbus run-1, 2026-11-18): __fc_libc's <sys/ioctl.h> defines TIOCMGET / TIOCMSET but
# not the TIOCM_* bits of Linux <asm-generic/termios.h>; Phase 0 lost libmodbus.so to the gcc fallback with
# `src/modbus-rtu.c:254: User Error: Cannot resolve variable TIOCM_RTS`.
# ---------------------------------------------------------------------------------------------------

# Linux <asm-generic/termios.h> (x86_64 and every architecture using the generic layout).
TIOCM_BITS = {
    "TIOCM_LE": "0x001", "TIOCM_DTR": "0x002", "TIOCM_RTS": "0x004", "TIOCM_ST": "0x008",
    "TIOCM_SR": "0x010", "TIOCM_CTS": "0x020", "TIOCM_CAR": "0x040", "TIOCM_RNG": "0x080",
    "TIOCM_DSR": "0x100", "TIOCM_CD": "TIOCM_CAR", "TIOCM_RI": "TIOCM_RNG", "TIOCM_OUT1": "0x2000",
    "TIOCM_OUT2": "0x4000", "TIOCM_LOOP": "0x8000",
}  # fmt: skip

_TIOCM_DEFINE = re.compile(r"^#define\s+(TIOCM_\w+)\s+(\S+)", re.MULTILINE)

# Linux <asm-generic/ioctls.h>: the termios2 requests (libmodbus with HAVE_STRUCT_TERMIOS2 stopped next at
# `Cannot resolve variable TCGETS2`).
TERMIOS2_REQUESTS = {
    "TCGETS2": "_IOR('T', 0x2A, struct termios2)",
    "TCSETS2": "_IOW('T', 0x2B, struct termios2)",
    "TCSETSW2": "_IOW('T', 0x2C, struct termios2)",
    "TCSETSF2": "_IOW('T', 0x2D, struct termios2)",
}

# libmodbus's src/modbus-rtu-private.h: <asm/termbits.h> with `struct termios` renamed away, then <termios.h>.
TIOCM_C = r"""#define termios
#include <asm/termbits.h>
#undef termios
#include <sys/ioctl.h>
#include <termios.h>

_Static_assert(TCGETS2 == 0x802C542AUL && TCSETS2 == 0x402C542BUL, "x86_64 termios2 requests");

int set_baud(int fd, unsigned baud) {
  struct termios2 tios;
  if (ioctl(fd, TCGETS2, &tios) < 0) return -1;
  tios.c_cflag |= BOTHER;
  tios.c_ispeed = baud;
  tios.c_ospeed = baud;
  return ioctl(fd, TCSETS2, &tios);
}

int set_rts(int fd, int on) {
  int flags;
  if (ioctl(fd, TIOCMGET, &flags) == -1) return -1;
  if (on)
    flags |= TIOCM_RTS;
  else
    flags &= ~TIOCM_RTS;
  return ioctl(fd, TIOCMSET, &flags) + (flags & (TIOCM_CTS | TIOCM_CD | TIOCM_RI | TIOCM_LOOP));
}

int main(void) { return set_rts(3, 1) + set_baud(3, 250000); }
"""

# The request numbers gcc computes from glibc's own headers.
TERMIOS2_GCC_C = r"""#include <stdio.h>
#define termios
#include <asm/termbits.h>
#undef termios
#include <sys/ioctl.h>

int main(void) {
  printf("%lu %lu\n", (unsigned long)TCGETS2, (unsigned long)TCSETS2);
  return 0;
}
"""


@pytest.mark.unit
def test_modem_line_bits_and_termios2_requests_are_defined_for_frama_c_libc_only():
    text = (ROOT / "templates" / "fc_stubs" / "fc_compat_types.h").read_text(encoding="utf-8")
    fc_libc = text.split("#else /* Frama-C __fc_libc */", 1)[1].split("#endif /* __FRAMAC_EACSL__ */", 1)[0]
    assert dict(_TIOCM_DEFINE.findall(fc_libc)) == TIOCM_BITS
    for name, value in (*TIOCM_BITS.items(), *TERMIOS2_REQUESTS.items()):
        # Guarded (a later __fc_libc may define them), and nowhere else: E-ACSL builds read glibc's.
        assert f"#ifndef {name}\n#define {name} {value}\n#endif" in fc_libc, name
        assert text.count(f"#define {name} ") == 1, name
    # The requests expand through the _IOC encoding defined above them.
    assert fc_libc.index("#define _IOR(") < fc_libc.index("#define TCGETS2 ")


@image
@slow
def test_modem_line_bits_and_termios2_requests_parse_with_frama_c_libc_as_gcc_reads_them(tmp_path):
    require_docker_images(ANALYSIS_IMAGE)
    script = (
        FRAMAC_FLAGS + 'echo "==parse=="; '
        'frama-c -no-unicode t.c -cpp-extra-args="$A" -print 2>&1; echo "rc=$?"; '
        'echo "==linux=="; grep "^#define[[:space:]]*TIOCM_" /usr/include/asm-generic/termios.h; '
        'echo "==gcc=="; gcc g.c -o g && ./g; echo "==end=="'
    )
    log = _run_in_image(tmp_path, {"t.c": TIOCM_C, "g.c": TERMIOS2_GCC_C}, script, timeout=300)
    parse = log.split("==parse==", 1)[1].split("==linux==", 1)[0]
    assert "rc=0" in parse and "Cannot resolve variable" not in parse, parse
    assert "flags |= 0x004;" in parse, parse
    linux = log.split("==linux==", 1)[1].split("==gcc==", 1)[0]
    assert dict(_TIOCM_DEFINE.findall(linux)) == TIOCM_BITS, linux
    # The `_Static_assert`s of TIOCM_C held under Frama-C; gcc computes the same numbers from glibc.
    gcc = log.split("==gcc==", 1)[1].split("==end==", 1)[0].split()
    assert gcc == [str(0x802C542A), str(0x402C542B)], gcc


# ---------------------------------------------------------------------------------------------------
# __fc_libc model objects under E-ACSL (libmodbus run-1, 2026-11-18): WP proved `assigns __fc_sockfds[s]`
# (setsockopt), `assigns __fc_fds[fd]` (close) and `assigns Frama_C_entropy_source` (tcflush), the
# guardrail's E-ACSL build stopped at "unbound logic variable __fc_sockfds": host glibc declares none.
# ---------------------------------------------------------------------------------------------------

# Name -> declarator in the E-ACSL branch, as __fc_libc types them (__fc_builtin.h, __fc_define_fds.h,
# sys/socket.h, __fc_select.h).
LIBC_MODEL_OBJECTS = {
    "Frama_C_entropy_source": "volatile int Frama_C_entropy_source",
    "__fc_fds": "volatile int __fc_fds[__FC_MAX_OPEN_FILES]",
    "__fc_sockfds": "struct __fc_sockfds_type __fc_sockfds[__FC_MAX_OPEN_SOCKETS]",
    "__fc_socket_counter": "int __fc_socket_counter",
    "__fc_fds_state": "volatile int __fc_fds_state",
}


@pytest.mark.unit
def test_eacsl_host_headers_define_the_libc_model_objects_weakly():
    block = _eacsl_host_block()
    for name, declarator in LIBC_MODEL_OBJECTS.items():
        # A definition, not `extern` (full memory tracking registers the address: undefined reference)
        # nor a ghost (printed as a comment: a clause E-ACSL executes would not compile).
        assert f"\n{declarator} __attribute__((weak));" in block, name
        assert f"extern {declarator}" not in block and f"ghost {declarator}" not in block, name
    for macro in ("__FC_MAX_OPEN_FILES", "__FC_MAX_OPEN_SOCKETS"):
        assert f"#ifndef {macro}\n#define {macro} 1024\n#endif" in block, macro
    assert "struct __fc_sockfds_type {\n  int x;\n};" in block
    # E-ACSL only: __fc_libc declares them itself for Eva and WP.
    text = (ROOT / "templates" / "fc_stubs" / "fc_compat_types.h").read_text(encoding="utf-8")
    assert block.count("__attribute__((weak));") == text.count("__attribute__((weak));")
    # The five __fc_libc model objects plus __fc_eacsl_errno (shared-header `assigns errno;` shim).
    assert text.count("__attribute__((weak));") == len(LIBC_MODEL_OBJECTS) + 1
    assert text.count("struct __fc_sockfds_type {") == 1


LIBC_MODEL_C = r"""#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <sys/socket.h>
#include <termios.h>
#include <unistd.h>

/*@ requires valid_socket: 0 <= s < __FC_MAX_OPEN_SOCKETS;
  @ assigns __fc_sockfds[s];
  @*/
int set_nodelay(int s)
{
  int one = 1;
  return setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
}

/*@ requires valid_fd: 0 <= fd < __FC_MAX_OPEN_FILES;
  @ assigns __fc_fds[fd];
  @*/
int do_close(int fd) { return close(fd); }

/*@ assigns Frama_C_entropy_source; */
int flush(int fd) { return tcflush(fd, TCIOFLUSH); }

/*@ assigns \nothing;
  @ ensures quiet_source: Frama_C_entropy_source == 0 ==> \result == 0;
  @*/
int quiet(void) { return 0; }

int main(void)
{
  /* A descriptor no process has open: every call fails with EBADF and changes nothing. */
  int r = set_nodelay(1000) + do_close(1000) + flush(1000) + quiet();
  printf("ok %d\n", r);
  return 0;
}
"""


@image
@slow
def test_contracts_naming_libc_model_objects_prove_under_wp_and_build_under_eacsl(tmp_path):
    require_docker_images(ANALYSIS_IMAGE)
    eacsl_flags = (
        f"F=$(python3 -c '{PY}import eacsl_toolchain as T; "
        'print(T.build_eacsl_flag_sets("-I.", fuzzer=False, full_mtracking=True)["frontend"])\'); '
    )
    script = (
        FRAMAC_FLAGS + eacsl_flags + 'echo "==eacsl=="; '
        'e-acsl-gcc -c -F -e-acsl-full-mtracking -E "$F" -o m.frama.c -O bin m.c > build.log 2>&1; echo "build=$?"; '
        './bin.e-acsl 2>&1; echo "run=$?"; '
        # set_nodelay under Bytes only, as on libmodbus: Typed hides `&one` cast to setsockopt's `char *`
        # (Cast with incompatible pointers types), so its optval precondition times out there.
        'echo "==wp=="; frama-c -no-unicode m.c -cpp-extra-args="$A" -wp -wp-model Typed '
        "-wp-fct do_close,flush,quiet -wp-timeout 20 -wp-cache none 2>&1; "
        'echo "==bytes=="; frama-c -no-unicode m.c -cpp-extra-args="$A" -wp -wp-model Bytes '
        '-wp-fct set_nodelay,do_close,flush,quiet -wp-timeout 20 -wp-cache none 2>&1; echo "==end=="'
    )
    log = _run_in_image(tmp_path, {"m.c": LIBC_MODEL_C}, script, timeout=900)
    eacsl = log.split("==eacsl==", 1)[1].split("==wp==", 1)[0]
    build = (tmp_path / "build.log").read_text(encoding="utf-8", errors="replace")
    assert "unbound logic variable" not in build, build
    assert "undefined reference" not in build, build
    assert "build=0" in eacsl, build
    assert "ok -3" in eacsl and "run=0" in eacsl, eacsl
    for tag in ("wp", "bytes"):
        proved, total = _proved(log, tag)
        assert proved == total, log.split(f"=={tag}==", 1)[1]


# ---------------------------------------------------------------------------------------------------
# Shared-header `assigns errno;` shim (libmodbus run-1, 2026-11-18): a contract in a shared header
# naming `errno` aborted with `Failure: unbound logic variable errno` in translation units that did
# not `#include <errno.h>` before the header (for example helpers and harnesses).
# ---------------------------------------------------------------------------------------------------


@pytest.mark.unit
def test_fc_compat_types_and_errno_stub_map_errno_without_including_errno_h():
    compat = (ROOT / "templates" / "fc_stubs" / "fc_compat_types.h").read_text(encoding="utf-8")
    errno_h = (ROOT / "templates" / "fc_stubs" / "errno.h").read_text(encoding="utf-8")

    # Never `#include <errno.h>` inside the force-included compat header: that would pull glibc
    # `<features.h>` / `<errno.h>` and 130+ `E*` macros ahead of line 1 of target sources.
    assert re.search(r"^\s*#\s*include\b.*errno\.h", compat, re.MULTILINE) is None

    eacsl = _eacsl_host_block()
    assert "#ifndef __FC_EACSL_ERRNO_DEFINED\n#define __FC_EACSL_ERRNO_DEFINED 1" in eacsl
    assert "\nint __fc_eacsl_errno __attribute__((weak));\n" in eacsl
    assert "#ifndef errno\n#define errno __fc_eacsl_errno\n#endif" in eacsl

    fc_libc = compat.split("#else /* Frama-C __fc_libc */", 1)[1].split("#endif /* __FRAMAC_EACSL__ */", 1)[0]
    assert '__PRAGMA_PUSH("errno.h")' in fc_libc
    assert "__FC_EXTERN_FOR_MACRO(errno) _Thread_local int __fc_errno;" in fc_libc
    assert "#define errno __fc_errno" in fc_libc
    assert "__POP_FC_STDLIB" in fc_libc

    # templates/fc_stubs/errno.h must `#undef errno` before `#include_next <errno.h>` so glibc's
    # `<errno.h>` does not emit a macro-redefined warning, guard `__fc_eacsl_errno` with
    # `__FC_EACSL_ERRNO_DEFINED`, and re-map `errno` afterwards.
    inc_next = errno_h.index("#include_next <errno.h>")
    assert errno_h.index("#undef errno") < inc_next
    after = errno_h[inc_next:]
    assert "#ifndef __FC_EACSL_ERRNO_DEFINED\n#define __FC_EACSL_ERRNO_DEFINED 1" in after
    assert "int __fc_eacsl_errno __attribute__((weak));" in after
    assert "#undef errno\n#define errno __fc_eacsl_errno" in after


SHARED_ERRNO_API_H = r"""#ifndef API_H
#define API_H
#include <stddef.h>

/*@ requires valid_out: \valid(out);
  @ terminates \true;
  @ exits \false;
  @ assigns *out, errno;
  @ ensures neg_err: x < 0 ==> \result == -1;
  @ ensures nonneg_ok: x >= 0 ==> \result == 0 && *out == x;
  @*/
int set_value(int x, int *out);

/*@ requires valid_s: s != \null && valid_read_string(s);
  @ assigns errno;
  @*/
int parse_overflow_errno(const char *s);

/*@ assigns errno; */
int close_bad_fd(void);

/*@ requires valid_hay: hlen > 0 && \valid_read(hay + (0 .. hlen - 1));
  @ requires valid_ndl: nlen > 0 && \valid_read(ndl + (0 .. nlen - 1));
  @ assigns \nothing;
  @*/
int has_subslice(const char *hay, size_t hlen, const char *ndl, size_t nlen);
#endif
"""

SHARED_ERRNO_A_C = r"""#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include "api.h"

int set_value(int x, int *out) {
  if (x < 0) {
    errno = EINVAL;
    return -1;
  }
  *out = x;
  return 0;
}

int parse_overflow_errno(const char *s) {
  char *end = NULL;
  errno = 0;
  (void)strtol(s, &end, 10);
  return errno;
}

int close_bad_fd(void) {
  errno = 0;
  if (close(1000) == -1) {
    return errno;
  }
  return 0;
}
"""

SHARED_ERRNO_B_C = r"""#define _GNU_SOURCE
#include <string.h>
#include "api.h"

#if defined(__FRAMAC_EACSL__) && (defined(_ERRNO_H) || defined(EINVAL))
#error "fc_compat_types.h must not include <errno.h> under E-ACSL"
#endif
#if defined(FC_STUBS_KEEP_LIBC_GETSOCKOPT) && defined(FC_STUBS_NO_SCHED_AFFINITY_DECLS) && defined(EINVAL)
#error "fc_compat_types.h must not include <errno.h> under __fc_libc"
#endif

int has_subslice(const char *hay, size_t hlen, const char *ndl, size_t nlen) {
  const void *p = memmem(hay, hlen, ndl, nlen);
#if !defined(__FRAMAC__)
  /* Under clang without __FRAMAC__, #define _GNU_SOURCE on line 1 must still expose __USE_GNU APIs. */
  const void *r = memrchr(hay, (int)(unsigned char)ndl[0], hlen);
  return (p != NULL && r != NULL) ? 1 : 0;
#else
  return p != NULL ? 1 : 0;
#endif
}
"""

SHARED_ERRNO_HARNESS_C = r"""#define _GNU_SOURCE
#include <stdint.h>
#include <stdlib.h>
#include "api.h"

#if defined(__FRAMAC_EACSL__) && (defined(_ERRNO_H) || defined(EINVAL))
#error "fc_compat_types.h must not include <errno.h> into harness"
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  (void)data;
  (void)size;
  int out = 0;
  if (set_value(-1, &out) != -1 || errno != 22) abort();
  if (set_value(42, &out) != 0 || out != 42) abort();
  if (parse_overflow_errno("99999999999999999999999999") != 34) abort();
  if (close_bad_fd() != 9) abort();
  char hay[4] = {'a', 'b', 'c', 'd'};
  char ndl[2] = {'b', 'c'};
  if (has_subslice(hay, 4, ndl, 2) != 1) abort();
  return 0;
}
"""

SHARED_ERRNO_EVA_MAIN_C = r"""#include "api.h"

int eva_main(void) {
  int out = 0;
  int r1 = set_value(-1, &out);
  int r2 = set_value(7, &out);
  char hay[4] = {'a', 'b', 'c', 'd'};
  char ndl[2] = {'b', 'c'};
  int r3 = has_subslice(hay, 4, ndl, 2);
  return r1 + r2 + r3 + out;
}
"""


@image
@slow
def test_shared_header_assigns_errno_works_in_wp_eva_eacsl_guardrail_and_preserves_gnu_source(tmp_path):
    """
    A shared header declaring `assigns *out, errno;` and `assigns errno;` must parse, prove, analyze,
    and run across TUs where only `a.c` includes `<errno.h>` while `b.c`, `harness.c`, and `eva_main.c`
    do not: WP (`run_wp_function.py`), Eva (`frama-c -eva`, both default and with every opt-out flag),
    E-ACSL guardrail (`run_eacsl_fuzz.py guardrail`, multi-TU + `errno_shim`), `-fno-common` linking,
    and native clang (`#define _GNU_SOURCE` on line 1 exposing GNU declarations).
    """
    require_docker_images(ANALYSIS_IMAGE)
    optouts = (
        "-DFC_STUBS_KEEP_LIBC_GETSOCKOPT -DFC_STUBS_KEEP_LIBC_GETOPT -DFC_STUBS_KEEP_LIBC_STRLCPY "
        "-DFC_STUBS_NO_PIPE2_DECL -DFC_STUBS_NO_NETDB_DECLS -DFC_STUBS_NO_SCHED_AFFINITY_DECLS "
        "-DFC_STUBS_NO_NETINET_LINUX_DECLS"
    )
    script = (
        FRAMAC_FLAGS + EACSL_FLAGS + "set -e; "
        "mkdir -p corpus; printf 'x' > corpus/seed1; "
        'echo "==wp=="; '
        "FRAMAC_CACHE=off python3 /opt/framac-pipeline/scripts/run_wp_function.py "
        '--file a.c --extra-sources b.c --function set_value --cppflags "-I." '
        "--out-dir wp_out --out-json wp.json > wp_cli.log 2>&1; "
        'echo "==eva=="; '
        "frama-c -no-unicode -machdep gcc_x86_64 -kernel-warn-key annot-error=abort -warn-left-shift-negative "
        '-cpp-extra-args="$A" a.c b.c eva_main.c -main eva_main -eva 2>&1; '
        'echo "==eva_optouts=="; '
        "frama-c -no-unicode -machdep gcc_x86_64 -kernel-warn-key annot-error=abort -warn-left-shift-negative "
        f'-cpp-extra-args="$A {optouts}" a.c b.c eva_main.c -main eva_main -eva 2>&1; '
        'echo "==cpp_warn=="; '
        "gcc -E -Wall -Wextra -D__FRAMAC__ $F a.c > /dev/null 2> cpp.err; cat cpp.err; "
        'echo "==guardrail=="; '
        "FRAMAC_CACHE=off python3 /opt/framac-pipeline/scripts/run_eacsl_fuzz.py guardrail "
        "--sources a.c b.c harness.c --out-bin out/guard_mod --corpus-dir corpus --extra-runs 20 "
        '--module errno_mod --cppflags "-I." '
        "--functions set_value parse_overflow_errno close_bad_fd has_subslice "
        "--no-cache --no-verdict-cache --out-json guard.json > guard_cli.log 2>&1; "
        'echo "==fno_common=="; '
        "e-acsl-gcc -C --libc-replacements --validate-format-strings -G clang "
        '-e "-fno-common -O1 -Wno-implicit-function-declaration -fsanitize=fuzzer" '
        '-l "out/guard_mod_errno_shim/eacsl_errno_shim.o -Wl,--wrap=strtol,--wrap=close" '
        "-O out/guard_nocommon out/guard_mod.instrumented.c "
        "/opt/framac-pipeline/templates/eacsl_runtime/fuzz_init.c > nocommon.log 2>&1; "
        "./out/guard_nocommon.e-acsl -runs=1 corpus/seed1 > nocommon_run.log 2>&1; "
        'echo "==clang=="; '
        "clang -std=c11 -Wall -Werror=implicit-function-declaration "
        "-I/opt/framac-pipeline/templates/fc_stubs "
        "-include /opt/framac-pipeline/templates/fc_stubs/fc_compat_types.h -c a.c -o a.o 2>&1; "
        "clang -std=c11 -Wall -Werror=implicit-function-declaration "
        "-I/opt/framac-pipeline/templates/fc_stubs "
        "-include /opt/framac-pipeline/templates/fc_stubs/fc_compat_types.h -c b.c -o b.o 2>&1; "
        'echo "==end=="'
    )
    files = {
        "api.h": SHARED_ERRNO_API_H,
        "a.c": SHARED_ERRNO_A_C,
        "b.c": SHARED_ERRNO_B_C,
        "harness.c": SHARED_ERRNO_HARNESS_C,
        "eva_main.c": SHARED_ERRNO_EVA_MAIN_C,
    }
    log = _run_in_image(tmp_path, files, script, timeout=900)

    wp = json.loads((tmp_path / "wp.json").read_text(encoding="utf-8"))
    assert wp["status"] == "all_proven", wp
    assert wp["assigns_vcs_proven"] is True, wp

    for tag, next_tag in (("eva", "eva_optouts"), ("eva_optouts", "cpp_warn")):
        section = log.split(f"=={tag}==", 1)[1].split(f"=={next_tag}==", 1)[0]
        assert "No errors or warnings raised during the analysis." in section, section
        assert "0 alarms generated by the analysis." in section, section
        assert "unbound logic variable" not in section, section

    cpp_err = (tmp_path / "cpp.err").read_text(encoding="utf-8", errors="replace")
    assert '"errno" redefined' not in cpp_err, cpp_err

    guard = json.loads((tmp_path / "guard.json").read_text(encoding="utf-8"))
    assert guard["status"] == "passed_dynamic_oracle", guard
    assert guard["compile"]["returncode"] == 0, guard
    shim = guard["compile"]["errno_shim"]
    assert shim is not None and shim["status"] == "built", shim
    assert {"strtol", "close"} <= set(shim["wrapped"]), shim
    reach = guard["reach"]
    assert reach["unreached"] == [], reach
    for fn in ("set_value", "parse_overflow_errno", "close_bad_fd", "has_subslice"):
        assert (reach["functions"].get(fn) or 0) > 0, (fn, reach)
    inst = (tmp_path / "out" / "guard_mod.instrumented.c").read_text(encoding="utf-8", errors="replace")
    assert "int __fc_eacsl_errno __attribute__((__weak__));" in inst
