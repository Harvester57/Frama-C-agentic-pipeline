"""A header in a slice's `sources` never reaches a clang compile line (mpack run-3, S6).

mpack defines functions in its headers (`MPACK_INLINE`), so the Phase 0 model maps them to the
header and the `--api` generator lists `mpack-writer.h` among the harness sources. Frama-C (E-ACSL's
first stage, Eva, WP) parses a header as a file of its own; clang treats it as a precompiled-header
output, and `clang ... mod.h ... -o bin` fails with `cannot specify -o when generating multiple output
files`. Every sanitizer and coverage build of the module failed that way.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import framac_common
import fuzz_build
import fuzz_coverage
import harness_reach


class _Recorder:
    """A clang that records its command line and writes the output binary."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, cmd, **kwargs):
        self.calls.append(list(cmd))
        if "-o" in cmd:
            Path(cmd[cmd.index("-o") + 1]).write_bytes(b"\x7fELF")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")


@pytest.fixture
def slice_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FRAMAC_CACHE", "off")
    (tmp_path / "mod.h").write_text("static inline int twice(int x) { return 2 * x; }\n", encoding="utf-8")
    (tmp_path / "mod.c").write_text('#include "mod.h"\nint entry(int x) { return twice(x); }\n', encoding="utf-8")
    (tmp_path / "harness_mod.c").write_text('#include "mod.h"\nint other(void) { return 0; }\n', encoding="utf-8")
    return tmp_path


SOURCES = ["mod.c", "mod.h", "harness_mod.c"]


@pytest.mark.parametrize("build", ["sanitizer", "coverage"])
def test_clang_builds_drop_header_sources(slice_dir, build):
    rec = _Recorder()
    fn = fuzz_build.compile_sanitizer_binary if build == "sanitizer" else fuzz_build.compile_coverage_binary
    res = fn(list(SOURCES), Path("bin/fuzz_mod"), "-I.", runner=rec, use_cache=False)
    assert res["returncode"] == 0
    (cmd,) = rec.calls
    assert "mod.h" not in cmd
    assert cmd.count("mod.c") == 1 and cmd.count("harness_mod.c") == 1
    assert "mod.h" not in res["command"].split()


def test_cached_sanitizer_build_drops_header_sources(slice_dir, monkeypatch):
    monkeypatch.delenv("FRAMAC_CACHE")
    (slice_dir / "run-metadata.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setenv("FRAMAC_IMAGE_ID", "sha256:test-image")
    rec = _Recorder()
    res = fuzz_build.compile_sanitizer_binary(list(SOURCES), Path("bin/fuzz_mod"), "-I.", runner=rec)
    assert res["returncode"] == 0
    builds = [c for c in rec.calls if "-M" not in c]
    assert builds and all("mod.h" not in c for c in builds)


def test_compile_inputs_keeps_translation_units_only():
    srcs = ["a.c", "inc/b.h", "c.hpp", "d.HH", "e.hxx", "workspace/work/src/f.c", "g.cc", "h.inc"]
    assert framac_common.compile_inputs(srcs) == ["a.c", "workspace/work/src/f.c", "g.cc"]


def test_header_function_the_corpus_ran_counts_as_executed():
    # The coverage build compiles no header, but a header function the translation units instantiate
    # is in the coverage mapping under the header's name: the summary keeps it and the dynamic reach
    # gate finds its executions by the DAG's file (mpack's MPACK_INLINE tag accessors).
    header = "/framac-run/workspace/work/src/mpack/mpack-common.h"
    source = "/framac-run/workspace/work/src/mpack/mpack-common.c"
    code = fuzz_coverage.LLVM_COV_CODE_REGION
    export = {
        "data": [
            {
                "functions": [
                    {
                        "name": "mpack_tag_type",
                        "count": 5,
                        "filenames": [header],
                        "regions": [[432, 1, 434, 2, 5, 0, 0, code]],
                    },
                    {
                        "name": "mpack_tag_cmp",
                        "count": 2,
                        "filenames": [source],
                        "regions": [[80, 1, 90, 2, 2, 0, 0, code]],
                    },
                ]
            }
        ]
    }
    summary = fuzz_coverage.summarize_coverage_export(export)
    rows = {f["function"]: f for f in summary["functions"]}
    assert rows["mpack_tag_type"]["executions"] == 5 and rows["mpack_tag_type"]["file"].endswith("mpack-common.h")
    dag = {"functions": {"mpack_tag_type": {"name": "mpack_tag_type", "file": "src/mpack/mpack-common.h"}}}
    runs = harness_reach._executions({"functions": summary["functions"]})
    assert harness_reach._entry_executions("mpack_tag_type", dag, runs) == 5


def test_slice_functions_still_include_header_definitions(slice_dir):
    # The header stays in `sources` as data: E-ACSL's -rte-select / -e-acsl-functions list comes from
    # it, and only the header names its inline functions.
    found = fuzz_build._discover_slice_functions(list(SOURCES))
    assert "twice" in found and "entry" in found
