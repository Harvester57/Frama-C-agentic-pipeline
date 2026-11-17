"""The seed recorder keeps recording after a test longjmps out of a wrapped API call (mpack run-3)."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import seed_harvest as sh

pytestmark = pytest.mark.unit

LIB_A = """\
int lib_b(int x);
extern void (*lib_hook)(void);
int lib_a(int x) {
    int r = lib_b(100);
    if (lib_hook) lib_hook();
    return r + x;
}
"""

LIB_B = """\
void (*lib_hook)(void);
volatile int lib_sink;
int lib_b(int x) { lib_sink += x; return x + 1; }
"""

# lib_a(1) calls lib_b(100) (nested) and then the test's assert handler, which longjmps back:
# lib_a's wrapper never leaves. Every later outermost call must still be recorded: lib_b(6), from
# helpers deeper than the dead wrapper's frame (whose stale frame then lies above the live ones),
# and lib_b(2..4) and lib_a(5) from main, at the dead wrapper's own depth.
DRIVER = """\
#include <setjmp.h>
#include <stddef.h>
int lib_a(int x);
int lib_b(int x);
extern void (*lib_hook)(void);
static jmp_buf env;
static void fail(void) { longjmp(env, 1); }
__attribute__((noinline)) static int deep(int n) {
    volatile char pad[512];
    for (int i = 0; i < (int)sizeof pad; i++) pad[i] = (char)n;
    return n ? deep(n - 1) + pad[0] : lib_b(6);
}
int main(void) {
    if (setjmp(env) == 0) {
        lib_hook = fail;
        lib_a(1);
        return 2;
    }
    lib_hook = NULL;
    deep(3);
    for (volatile int i = 2; i <= 4; i++) lib_b(i);
    lib_a(5);
    return 0;
}
"""


def _compilers() -> list[str]:
    if not sys.platform.startswith("linux"):
        return []
    return [c for c in ("gcc", "clang") if shutil.which(c)]


@pytest.mark.skipif(not _compilers(), reason="needs gcc or clang on Linux")
@pytest.mark.parametrize("cc", _compilers() or ["none"])
def test_recorder_records_outermost_calls_after_a_longjmp(tmp_path: Path, cc: str) -> None:
    plans = [sh.plan_function("lib_a", "int(int)"), sh.plan_function("lib_b", "int(int)")]
    out = tmp_path / "calls"
    out.mkdir()
    sources = {
        "rt.c": sh.runtime_source(len(plans)),
        "wrap.c": sh.wrapper_source(plans, []),
        "lib_a.c": LIB_A,
        "lib_b.c": LIB_B,
        "driver.c": DRIVER,
    }
    objs = []
    for name, text in sources.items():
        (tmp_path / name).write_text(text, newline="\n")
        obj = tmp_path / (name[:-2] + ".o")
        flags = ["-O1", "-w", f'-DFC_OUT_DIR="{out}"'] if name == "rt.c" else ["-O2", "-Wall", "-Werror"]
        subprocess.run([cc, "-c", *flags, str(tmp_path / name), "-o", str(obj)], check=True, timeout=120)
        objs.append(str(obj))
    exe = tmp_path / "t"
    wraps = "-Wl,--wrap=lib_a,--wrap=lib_b"
    subprocess.run([cc, *objs, wraps, "-o", str(exe)], check=True, timeout=120)
    assert subprocess.run([str(exe)], timeout=60).returncode == 0

    records = []
    for f in out.glob("calls-*.txt"):
        records += [sh.parse_record_line(line) for line in f.read_text().splitlines()]
    calls = [(r["fn"], int.from_bytes(bytes.fromhex(r["args"]["0"][0][2]), "little")) for r in records if r]
    # The nested lib_b(100) calls are never recorded; the calls after the longjmp are outermost.
    assert calls == [("lib_a", 1), ("lib_b", 6), ("lib_b", 2), ("lib_b", 3), ("lib_b", 4), ("lib_a", 5)]
