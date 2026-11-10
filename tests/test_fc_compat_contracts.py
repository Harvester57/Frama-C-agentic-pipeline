"""
Contracts of templates/fc_stubs/fc_compat_types.h against the real Frama-C (FRAMAC_DOCKER_TESTS=1), plan
docs/templates-and-stubs-improvement-plan.md: typed syscalls (S6).
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from conftest import ANALYSIS_IMAGE, ROOT, require_docker_images

pytestmark = [pytest.mark.integration, pytest.mark.slow]

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
