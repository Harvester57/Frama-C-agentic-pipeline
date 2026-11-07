"""Libc contract overrides in templates/fc_stubs/fc_compat_types.h (Eva / WP)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from framac_common import augment_framac_cppflags

pytestmark = pytest.mark.unit

COMPAT = Path(__file__).resolve().parent.parent / "templates" / "fc_stubs" / "fc_compat_types.h"
CALLER = """\
#include <sys/socket.h>
int main(void) {{
  int opt;
  socklen_t olen = {optlen};
  return getsockopt(3, 270, 1, &opt, &olen);
}}
"""


def test_getsockopt_override_renames_the_libc_declaration_before_any_include():
    text = COMPAT.read_text(encoding="utf-8")
    rename = text.index("#define getsockopt __fc_libc_getsockopt_unbounded")
    assert rename < text.index("#include <sys/socket.h>") < text.index("#undef getsockopt")
    assert r"\valid((char *)optval + (0 .. *optlen - 1))" in text
    # Only for Frama-C's libc: E-ACSL builds use host headers, which have no contract to fix.
    assert (
        text.rindex("#if defined(__FRAMAC_EACSL__)", 0, rename) < text.index("#else /* Frama-C __fc_libc */") < rename
    )


def _eva_preconditions(tmp_path: Path, optlen: str) -> str:
    src = tmp_path / "caller.c"
    src.write_text(CALLER.format(optlen=optlen), encoding="utf-8")
    proc = subprocess.run(
        ["frama-c", f"-cpp-extra-args={augment_framac_cppflags('-I.')}", str(src), "-eva"],
        capture_output=True,
        text=True,
        check=False,
        cwd=tmp_path,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc.stdout


@pytest.mark.skipif(shutil.which("frama-c") is None, reason="needs Frama-C (inside the image)")
def test_eva_accepts_a_correct_getsockopt_call_and_flags_an_oversized_optlen(tmp_path):
    ok = _eva_preconditions(tmp_path, "sizeof opt")
    assert "got status invalid" not in ok
    bad = _eva_preconditions(tmp_path, "8")
    assert "precondition 'optval_null_or_valid' got status invalid" in bad
