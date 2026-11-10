"""
Contracts of templates/fc_stubs/fc_compat_types.h against the real Frama-C (FRAMAC_DOCKER_TESTS=1), plan
docs/templates-and-stubs-improvement-plan.md: typed syscalls (S6), the LP64 assertion (S9), the wipe
contracts (M6), the string vocabulary (S8).
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from conftest import ANALYSIS_IMAGE, ROOT, require_docker_images

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
    section = log.split(f"=={tag}==", 1)[1].split("==", 1)[0]
    m = re.search(r"Proved goals:\s+(\d+) / (\d+)", section)
    assert m, section
    return int(m.group(1)), int(m.group(2))


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
    start = text.index("logic integer strlen(char *s)")
    return text[start : text.index("*/", start)]


@pytest.mark.unit
def test_eacsl_builds_define_libc_s_string_names_and_nothing_else():
    block = _eacsl_string_block()
    defined = set(re.findall(r"predicate (\w+)\(", block))
    # Plus the private helpers that keep one predicate call after each quantifier guard
    # (E-ACSL 35 drops the first conjunct of `\exists i; guard && P && Q`).
    assert defined - {"__fc_eacsl_read_nul_at", "__fc_eacsl_nul_at"} == set(STRINGS)
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
