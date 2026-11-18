"""The seed recorder wraps API calls a test makes into the project's shared library (libmodbus run-1)."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import seed_harvest as sh

pytestmark = pytest.mark.unit

LIB = """\
volatile int lib_sink;
int lib_inner(int x) { lib_sink += x; return x + 1; }
int lib_outer(int x) { return lib_inner(x * 10) + 1; }
"""

# The test calls the library's API through undefined references, resolved from libapi.so at run time.
DRIVER = """\
int lib_inner(int x);
int lib_outer(int x);
int main(void) { return lib_outer(3) + lib_inner(4) == 37 ? 0 : 1; }
"""


def _compilers() -> list[str]:
    if not sys.platform.startswith("linux") or not shutil.which("nm"):
        return []
    return [c for c in ("gcc", "clang") if shutil.which(c)]


@pytest.mark.skipif(not _compilers(), reason="needs gcc or clang and nm on Linux")
@pytest.mark.parametrize("cc", _compilers() or ["none"])
def test_recorder_wraps_calls_into_a_shared_library(tmp_path: Path, cc: str) -> None:
    (tmp_path / "lib.c").write_text(LIB, newline="\n")
    (tmp_path / "driver.c").write_text(DRIVER, newline="\n")
    lib_dir = tmp_path / "libs"
    lib_dir.mkdir()
    so = lib_dir / "libapi.so"
    subprocess.run([cc, "-shared", "-fPIC", "-O2", str(tmp_path / "lib.c"), "-o", str(so)], check=True, timeout=120)
    driver_o = tmp_path / "driver.o"
    subprocess.run([cc, "-c", "-O2", str(tmp_path / "driver.c"), "-o", str(driver_o)], check=True, timeout=120)
    link = [cc, "-o", str(tmp_path / "t"), str(driver_o), str(so)]  # libtool's shape: the .so by path
    subprocess.run(link, check=True, timeout=120)
    exe = tmp_path / "t"

    # The API is not defined in the executable: only its undefined references name it.
    assert not {"lib_inner", "lib_outer"} & sh.defined_functions(exe)
    assert {"lib_inner", "lib_outer"} <= sh.undefined_functions(exe)

    # Relink as `record` does: recorder objects first, the build's link arguments, then the wraps.
    plans = [sh.plan_function("lib_inner", "int(int)"), sh.plan_function("lib_outer", "int(int)")]
    out = tmp_path / "calls"
    out.mkdir()
    rt_c, wr_c = tmp_path / "rt.c", tmp_path / "wrap.c"
    rt_c.write_text(sh.runtime_source(len(plans)), newline="\n")
    wr_c.write_text(sh.wrapper_source(plans, []), newline="\n")
    rt_o, wr_o = tmp_path / "rt.o", tmp_path / "wrap.o"
    rt_flags = ["-O1", "-fPIC", "-w", f'-DFC_OUT_DIR="{out}"']
    subprocess.run([cc, "-c", *rt_flags, str(rt_c), "-o", str(rt_o)], check=True, timeout=120)
    subprocess.run([cc, "-c", "-O0", "-fPIC", "-w", str(wr_c), "-o", str(wr_o)], check=True, timeout=120)
    wraps = [f"-Wl,--wrap={p['name']}" for p in plans]
    subprocess.run([link[0], str(rt_o), str(wr_o), *link[1:], *wraps], check=True, timeout=120)
    env = {**os.environ, "LD_LIBRARY_PATH": str(lib_dir)}  # as libtool's wrapper script sets it
    assert subprocess.run([str(exe)], env=env, timeout=60).returncode == 0

    records = []
    for f in out.glob("calls-*.txt"):
        records += [sh.parse_record_line(line) for line in f.read_text().splitlines()]
    calls = sorted((r["fn"], int.from_bytes(bytes.fromhex(r["args"]["0"][0][2]), "little")) for r in records if r)
    # lib_outer's own call to lib_inner stays inside the library: not wrapped, not recorded.
    assert calls == [("lib_inner", 4), ("lib_outer", 3)]
