"""
Post-build move/copy of built executables and libraries (CryptoLib `cl-p0-20261123`).

CryptoLib's `test/CMakeLists.txt` attaches a `POST_BUILD` command to every unit test that runs
`cmake -E copy $<TARGET_FILE:...> ${PROJECT_BINARY_DIR}/bin/<name>` followed by
`cmake -E remove $<TARGET_FILE:...>`, and CTest runs the copy in `build/internal/bin/`.
`build_capture.py` now follows `cp`/`mv`/`install`/`cmake -E copy|copy_if_different|rename` in
`events.jsonl` to record `installed_as` on each unit, and `seed_harvest.py record` probes,
relinks, and places the wrapped binary at every in-tree `installed_as` copy.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

import build_capture as bc
import seed_harvest as sh
import validate_artifacts
from conftest import BUILD_IMAGE, ROOT, require_docker_images

TREE = "/s/tree"
ELF64_X86_64 = b"\x7fELF\x02\x01\x01" + b"\x00" * 11 + (62).to_bytes(2, "little")
ELF32_I386 = b"\x7fELF\x01\x01\x01" + b"\x00" * 11 + (3).to_bytes(2, "little")


def _ex(exe: str, args: list[str], cwd: str = TREE) -> dict[str, Any]:
    return {"exe": exe, "args": args, "cwd": cwd}


# ---------------------------------------------------------------------------------------------------
# 1. File transfer parsing and build_capture tracking
# ---------------------------------------------------------------------------------------------------


@pytest.mark.unit
def test_parse_file_action_covers_cp_mv_install_cmake_rm_and_mkdir() -> None:
    assert bc.parse_file_action("cmake", ["cmake", "-E", "copy", "a", "b"]) == {
        "kind": "transfer",
        "move": False,
        "srcs": ["a"],
        "dst": "b",
        "dst_is_dir": None,
    }
    assert bc.parse_file_action("cmake", ["cmake", "-E", "copy_if_different", "-t", "bin", "a", "b"]) == {
        "kind": "transfer",
        "move": False,
        "srcs": ["a", "b"],
        "dst": "bin",
        "dst_is_dir": True,
    }
    assert bc.parse_file_action("cmake", ["cmake", "-E", "rename", "a", "b"]) == {
        "kind": "transfer",
        "move": True,
        "srcs": ["a"],
        "dst": "b",
        "dst_is_dir": False,
    }
    assert bc.parse_file_action("cmake", ["cmake", "-E", "remove", "-f", "a", "b"]) == {
        "kind": "remove",
        "paths": ["a", "b"],
    }
    assert bc.parse_file_action("cmake", ["cmake", "-E", "rm", "-rf", "a"]) == {"kind": "remove", "paths": ["a"]}
    assert bc.parse_file_action("cmake", ["cmake", "-E", "make_directory", "bin"]) == {"kind": "mkdir", "dirs": ["bin"]}
    assert bc.parse_file_action("cmake", ["cmake", "-E", "cmake_echo_color", "hi"]) is None

    # GNU optional-value long option `--preserve` must not consume the source operand.
    assert bc.parse_file_action("cp", ["cp", "--preserve", "a", "b"]) == {
        "kind": "transfer",
        "move": False,
        "srcs": ["a"],
        "dst": "b",
        "dst_is_dir": None,
    }
    assert bc.parse_file_action("cp", ["cp", "-ft", "bin", "a", "b"]) == {
        "kind": "transfer",
        "move": False,
        "srcs": ["a", "b"],
        "dst": "bin",
        "dst_is_dir": True,
    }
    assert bc.parse_file_action("cp", ["cp", "-T", "a", "b"]) == {
        "kind": "transfer",
        "move": False,
        "srcs": ["a"],
        "dst": "b",
        "dst_is_dir": False,
    }
    assert bc.parse_file_action("cp", ["cp", "-a", "a", "."])["dst_is_dir"] is True  # type: ignore[index]
    assert bc.parse_file_action("cp", ["cp", "-s", "a", "b"]) is None
    assert bc.parse_file_action("cp", ["cp", "--parents", "a/b", "dst"]) is None

    assert bc.parse_file_action("mv", ["mv", "-f", "a", "b/"]) == {
        "kind": "transfer",
        "move": True,
        "srcs": ["a"],
        "dst": "b/",
        "dst_is_dir": True,
    }
    assert bc.parse_file_action("mv", ["mv", "--exchange", "a", "b"]) is None

    assert bc.parse_file_action("install", ["install", "-c", "-m", "755", "-D", "a", "bin/a"]) == {
        "kind": "transfer",
        "move": False,
        "srcs": ["a"],
        "dst": "bin/a",
        "dst_is_dir": False,
    }
    assert bc.parse_file_action("install", ["install", "-D", "-t", "bin", "a"]) == {
        "kind": "transfer",
        "move": False,
        "srcs": ["a"],
        "dst": "bin",
        "dst_is_dir": True,
    }
    assert bc.parse_file_action("install", ["install", "-d", "bin", "lib"]) == {"kind": "mkdir", "dirs": ["bin", "lib"]}
    assert bc.parse_file_action("rm", ["rm", "-f", "a"]) == {"kind": "remove", "paths": ["a"]}
    assert bc.parse_file_action("unlink", ["unlink", "a"]) == {"kind": "remove", "paths": ["a"]}
    assert bc.parse_file_action("mkdir", ["mkdir", "-p", "-m", "755", "bin"]) == {"kind": "mkdir", "dirs": ["bin"]}


@pytest.mark.unit
def test_classify_executions_tracks_cmake_post_build_copy_and_remove() -> None:
    src_dir = f"{TREE}/build/internal/src"
    test_dir = f"{TREE}/build/internal/test"
    execs = [
        _ex("/usr/bin/cc", ["cc", "-fPIC", "-c", "-o", "lib.o", f"{TREE}/src/lib.c"], src_dir),
        _ex("/usr/bin/cc", ["cc", "-shared", "-o", "libcryptolib.so", "lib.o"], src_dir),
        _ex(
            "/usr/bin/cmake",
            [
                "/usr/bin/cmake",
                "-E",
                "copy",
                f"{src_dir}/libcryptolib.so",
                f"{TREE}/build/internal/libcryptolib.so",
            ],
            src_dir,
        ),
        _ex("/usr/bin/cc", ["cc", "-c", "-o", "ut.o", f"{TREE}/test/ut_tc_process.c"], test_dir),
        _ex("/usr/bin/cc", ["cc", "ut.o", "-o", "ut_tc_process", "../src/libcryptolib.so"], test_dir),
        _ex(
            "/usr/bin/cmake",
            [
                "/usr/bin/cmake",
                "-E",
                "copy",
                f"{test_dir}/ut_tc_process",
                f"{TREE}/build/internal/bin/ut_tc_process",
            ],
            test_dir,
        ),
        _ex("/usr/bin/cmake", ["/usr/bin/cmake", "-E", "remove", f"{test_dir}/ut_tc_process"], test_dir),
    ]
    cap = bc.classify_executions(execs, TREE)
    units = bc.derive_units(cap, TREE)
    assert units["build/internal/src/libcryptolib.so"]["installed_as"] == ["build/internal/libcryptolib.so"]
    assert units["build/internal/test/ut_tc_process"]["installed_as"] == ["build/internal/bin/ut_tc_process"]
    assert units["build/internal/test/ut_tc_process"]["test"] is True
    assert units["build/internal/test/ut_tc_process"]["links"] == ["build/internal/src/libcryptolib.so"]


@pytest.mark.unit
def test_classify_executions_follows_chains_dirs_removes_and_copied_library_links() -> None:
    execs = [
        _ex("/usr/bin/cc", ["cc", "-fPIC", "-c", "-o", "build/src/lib.o", "src/lib.c"]),
        _ex("/usr/bin/cc", ["cc", "-shared", "-o", "build/src/libfoo.so", "build/src/lib.o"]),
        _ex("/bin/mkdir", ["mkdir", "-p", "build/lib", "build/stage", "build/bin"]),
        # Copy into a directory named without a trailing slash (known from mkdir).
        _ex("/bin/cp", ["cp", "build/src/libfoo.so", "build/lib"]),
        # Executable links against the copied shared library path.
        _ex("/usr/bin/cc", ["cc", "-c", "-o", "build/test/t.o", "test/t.c"]),
        _ex("/usr/bin/cc", ["cc", "-o", "build/test/t", "build/test/t.o", "build/lib/libfoo.so"]),
        # Chained copy -> mv drops the intermediate path; an unrelated overwrite and rm also clean up.
        _ex("/bin/cp", ["cp", "build/test/t", "build/stage/t"]),
        _ex("/bin/mv", ["mv", "build/stage/t", "build/bin/t"]),
        _ex("/bin/cp", ["cp", "build/test/t", "build/bin/t_removed"]),
        _ex("/bin/rm", ["rm", "-f", "build/bin/t_removed"]),
        _ex("/bin/cp", ["cp", "build/test/t", "build/bin/t_overwritten"]),
        _ex("/bin/cp", ["cp", "README.md", "build/bin/t_overwritten"]),
        _ex("/usr/bin/install", ["install", "-m", "755", "build/test/t", "build/bin/t_inst"]),
        # Out-of-tree copy is ignored.
        _ex("/bin/cp", ["cp", "build/test/t", "/tmp/outside/t"]),
    ]
    cap = bc.classify_executions(execs, TREE)
    units = bc.derive_units(cap, TREE)
    assert units["build/src/libfoo.so"]["installed_as"] == ["build/lib/libfoo.so"]
    assert units["build/test/t"]["links"] == ["build/src/libfoo.so"]
    assert units["build/test/t"]["installed_as"] == ["build/bin/t", "build/bin/t_inst"]


@pytest.mark.unit
def test_drop_vanished_probes_and_check_architecture_follow_installed_as(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    (tree / "build/bin").mkdir(parents=True)
    (tree / "build/bin/ut_ok").write_bytes(ELF64_X86_64)
    (tree / "build/bin/ut_32").write_bytes(ELF32_I386)
    tree_posix = tree.as_posix()
    execs = [
        # Compile-and-link where both generated source and original link output are deleted after move.
        _ex("/usr/bin/cc", ["cc", "-o", "build/test/ut_ok", "build/gen_ok.c"], tree_posix),
        _ex("/bin/mv", ["mv", "build/test/ut_ok", "build/bin/ut_ok"], tree_posix),
        _ex("/usr/bin/cc", ["cc", "-o", "build/test/ut_32", "build/gen_32.c"], tree_posix),
        _ex("/bin/mv", ["mv", "build/test/ut_32", "build/bin/ut_32"], tree_posix),
    ]
    cap = bc.classify_executions(execs, tree_posix)
    assert bc.drop_vanished_probes(cap, tree_posix) == []
    assert sorted(cap["artifacts"]) == ["build/test/ut_32", "build/test/ut_ok"]

    arch = bc.check_architecture(cap["compiles"], cap["artifacts"], tree_posix)
    assert arch["files"] == 2
    assert arch["unknown"] == 0
    assert arch["unsupported_total"] == 1
    assert arch["unsupported"][0]["file"] == "build/test/ut_32"
    assert arch["unsupported"][0]["decided_by"] == "header"


@pytest.mark.unit
def test_build_capture_schema_accepts_installed_as() -> None:
    sample = {
        "schema_version": 1,
        "generated_at": "2026-11-23T00:00:00Z",
        "status": "ok",
        "target": "/target",
        "warnings": [],
        "compiles": [],
        "units": {
            "build/test/ut_tc": {
                "kind": "executable",
                "test": True,
                "test_reason": "directory",
                "files": ["test/ut_tc.c"],
                "objects": ["build/test/ut_tc.o"],
                "links": [],
                "external_libs": [],
                "cppflags": [],
                "entry_points": ["test/ut_tc.c#main"],
                "embedded_api": [],
                "installed_as": ["build/bin/ut_tc"],
            }
        },
    }
    assert validate_artifacts.validate_build_capture(sample) == []


# ---------------------------------------------------------------------------------------------------
# 2. seed_harvest.py record with installed_as (unit tests)
# ---------------------------------------------------------------------------------------------------


def _post_build_record_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    units: dict[str, dict[str, Any]],
    existing_files: list[str],
    recipe: dict[str, Any],
    events: list[dict[str, Any]] | None = None,
    relink_writes: dict[str, bytes] | None = None,
) -> tuple[Path, list[list[str]], list[Path]]:
    monkeypatch.chdir(tmp_path)
    reports = tmp_path / "workspace" / "reports"
    reports.mkdir(parents=True)
    tree = tmp_path / "scratch" / "tree"
    tree.mkdir(parents=True)
    for rel in existing_files:
        p = tree / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"\x7fELF-orig")
    if events is not None:
        ev_dir = reports / "build_capture"
        ev_dir.mkdir(parents=True, exist_ok=True)
        ev_text = "".join(json.dumps({"started": {"execution": e}}) + "\n" for e in events)
        (ev_dir / "events.jsonl").write_text(ev_text, encoding="utf-8", newline="\n")
    (tmp_path / "run-metadata.json").write_text(json.dumps({"build": recipe}), encoding="utf-8")
    model = {
        "status": "ok",
        "entry_points": ["src/lib.c#f"],
        "functions": {"src/lib.c#f": {"name": "f", "signature": "int(const unsigned char *, unsigned long)"}},
        "units": {},
    }
    (reports / "phase0_model.json").write_text(json.dumps(model), encoding="utf-8")
    capture = {"status": "ok", "scratch": {"tree": str(tree)}, "units": units, "compiles": []}
    (reports / "build_capture.json").write_text(json.dumps(capture), encoding="utf-8")

    ran: list[list[str]] = []
    probed: list[Path] = []
    writes = relink_writes or {}

    class Res:
        returncode = 0
        timed_out = False
        stdout = stderr = ""

    def sandboxed(argv: list[str], cwd: Path, scratch: Path, timeout: int, env: dict[str, str]) -> Res:
        argv_s = [str(a) for a in argv]
        ran.append(argv_s)
        if argv_s and argv_s[0] == "cc" and "-o" in argv_s:
            out_arg = argv_s[argv_s.index("-o") + 1]
            out_path = Path(out_arg) if Path(out_arg).is_absolute() else (cwd / out_arg)
            rel_out = out_path.relative_to(tree).as_posix()
            if rel_out in writes:
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_bytes(writes[rel_out])
        return Res()

    def undef(exe: Path) -> set[str]:
        probed.append(exe)
        return {"f"}

    exes = [n for n, u in units.items() if u["kind"] == "executable"]
    if events is None:
        monkeypatch.setattr(
            sh,
            "link_commands",
            lambda ev, t: {n: {"args": ["cc", "-o", n], "cwd": str(t)} for n in exes},
        )
    monkeypatch.setattr(sh, "defined_functions", lambda exe: set())
    monkeypatch.setattr(sh, "undefined_functions", undef)
    monkeypatch.setattr(sh, "_run", lambda argv, cwd, timeout: (0, ""))
    monkeypatch.setattr(sh, "_compile_wrappers", lambda cc, fl, plans, where, c, o, w: (True, plans, ""))
    monkeypatch.setattr(sh, "_sandboxed", sandboxed)
    monkeypatch.setattr(sh.shutil, "which", lambda name: None)
    return tree, ran, probed


@pytest.mark.unit
def test_seed_harvest_record_relinks_and_places_post_build_moved_test_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    units = {
        "build/test/ut_tc": {
            "kind": "executable",
            "test": True,
            "objects": [],
            "installed_as": ["build/bin/ut_tc"],
        }
    }
    tree, ran, probed = _post_build_record_fixture(
        tmp_path,
        monkeypatch,
        units=units,
        existing_files=["build/bin/ut_tc"],
        recipe={"command": "cmake --build build", "test_command": "ctest --test-dir build"},
        relink_writes={"build/test/ut_tc": b"\x7fELF-wrapped"},
    )
    assert sh.main(["record", "--scratch", str(tmp_path / "scratch")]) == 0
    report = json.loads((tmp_path / "workspace" / "reports" / "seed_harvest.json").read_text(encoding="utf-8"))
    assert validate_artifacts.validate_seed_harvest(report) == []
    assert probed == [tree / "build/bin/ut_tc"]
    assert report["relink"]["build/test/ut_tc"] == {
        "status": "relinked",
        "wrapped": ["f"],
        "installed_as": ["build/bin/ut_tc"],
    }
    assert (tree / "build/bin/ut_tc").read_bytes() == b"\x7fELF-wrapped"
    assert not (tree / "build/test/ut_tc").exists()
    assert ran[-1] == ["sh", "-c", "ctest --test-dir build"]


@pytest.mark.unit
def test_seed_harvest_record_updates_copy_when_original_link_output_also_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    units = {
        "build/test/ut_tc": {
            "kind": "executable",
            "test": True,
            "objects": [],
            "installed_as": ["build/bin/ut_tc"],
        }
    }
    tree, _, probed = _post_build_record_fixture(
        tmp_path,
        monkeypatch,
        units=units,
        existing_files=["build/test/ut_tc", "build/bin/ut_tc"],
        recipe={"command": "cmake --build build", "test_command": "ctest --test-dir build"},
        relink_writes={"build/test/ut_tc": b"\x7fELF-wrapped"},
    )
    assert sh.main(["record", "--scratch", str(tmp_path / "scratch")]) == 0
    report = json.loads((tmp_path / "workspace" / "reports" / "seed_harvest.json").read_text(encoding="utf-8"))
    assert report["relink"]["build/test/ut_tc"]["status"] == "relinked"
    assert report["relink"]["build/test/ut_tc"]["installed_as"] == ["build/bin/ut_tc"]
    assert probed == [tree / "build/test/ut_tc"]
    assert (tree / "build/test/ut_tc").read_bytes() == b"\x7fELF-wrapped"
    assert (tree / "build/bin/ut_tc").read_bytes() == b"\x7fELF-wrapped"


@pytest.mark.unit
def test_seed_harvest_record_falls_back_to_events_jsonl_for_older_captures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tree_posix = (tmp_path / "scratch" / "tree").as_posix()
    test_dir = f"{tree_posix}/build/test"
    units = {"build/test/ut_tc": {"kind": "executable", "test": True, "objects": []}}
    events = [
        {"executable": "/usr/bin/cc", "arguments": ["cc", "-o", "ut_tc", "ut.o"], "working_dir": test_dir},
        {
            "executable": "/usr/bin/cmake",
            "arguments": ["cmake", "-E", "copy", f"{test_dir}/ut_tc", f"{tree_posix}/build/bin/ut_tc"],
            "working_dir": test_dir,
        },
        {
            "executable": "/usr/bin/cmake",
            "arguments": ["cmake", "-E", "remove", f"{test_dir}/ut_tc"],
            "working_dir": test_dir,
        },
    ]
    tree, _, probed = _post_build_record_fixture(
        tmp_path,
        monkeypatch,
        units=units,
        existing_files=["build/bin/ut_tc"],
        recipe={"command": "cmake --build build", "test_command": "ctest --test-dir build"},
        events=events,
        relink_writes={"build/test/ut_tc": b"\x7fELF-wrapped"},
    )
    assert sh.main(["record", "--scratch", str(tmp_path / "scratch")]) == 0
    report = json.loads((tmp_path / "workspace" / "reports" / "seed_harvest.json").read_text(encoding="utf-8"))
    assert report["relink"]["build/test/ut_tc"]["status"] == "relinked"
    assert report["relink"]["build/test/ut_tc"]["installed_as"] == ["build/bin/ut_tc"]
    assert probed == [tree / "build/bin/ut_tc"]
    assert (tree / "build/bin/ut_tc").read_bytes() == b"\x7fELF-wrapped"


@pytest.mark.unit
def test_seed_harvest_without_test_command_runs_moved_executable_with_moved_shared_lib_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    units = {
        "build/src/demo": {"kind": "executable", "test": False, "objects": [], "installed_as": ["build/bin/demo"]},
        "build/src/libx.so": {
            "kind": "shared_lib",
            "test": False,
            "objects": [],
            "installed_as": ["build/lib/libx.so"],
        },
    }
    tree, ran, _ = _post_build_record_fixture(
        tmp_path,
        monkeypatch,
        units=units,
        existing_files=["build/bin/demo", "build/lib/libx.so"],
        recipe={"command": "cmake --build build"},
        relink_writes={"build/src/demo": b"\x7fELF-wrapped"},
    )
    assert sh.main(["record", "--scratch", str(tmp_path / "scratch")]) == 0
    report = json.loads((tmp_path / "workspace" / "reports" / "seed_harvest.json").read_text(encoding="utf-8"))
    assert report["relink"]["build/src/demo"]["status"] == "relinked"
    assert report["library_path"] == [str(tree / "build/lib")]
    assert ran[-1] == [str(tree / "build/bin/demo")]


@pytest.mark.unit
def test_seed_harvest_ignores_escaping_installed_as_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    escape = tmp_path / "outside_bin"
    escape.write_bytes(b"\x7fELF-outside")
    units = {
        "build/test/ut_tc": {
            "kind": "executable",
            "test": True,
            "objects": [],
            "installed_as": ["../../outside_bin", str(escape)],
        }
    }
    _post_build_record_fixture(
        tmp_path,
        monkeypatch,
        units=units,
        existing_files=[],
        recipe={"command": "make", "test_command": "ctest"},
    )
    assert sh.main(["record", "--scratch", str(tmp_path / "scratch")]) == 0
    report = json.loads((tmp_path / "workspace" / "reports" / "seed_harvest.json").read_text(encoding="utf-8"))
    assert report["status"] == "not_relinked"
    assert report["relink"]["build/test/ut_tc"]["status"] == "not_built"
    assert escape.read_bytes() == b"\x7fELF-outside"


# ---------------------------------------------------------------------------------------------------
# 3. Docker: real CMake POST_BUILD copy-and-remove captured and seed-recorded in the build image
# ---------------------------------------------------------------------------------------------------

CMAKE_ROOT = """\
cmake_minimum_required(VERSION 3.16)
project(postbuild_demo C)
enable_testing()
add_subdirectory(src)
add_subdirectory(test)
"""

CMAKE_SRC = """\
add_library(demo SHARED lib.c)
target_include_directories(demo PUBLIC ${PROJECT_SOURCE_DIR}/include)
add_custom_command(TARGET demo POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:demo> ${PROJECT_BINARY_DIR}/$<TARGET_FILE_NAME:demo>)
"""

CMAKE_TEST = """\
add_executable(ut_demo ut_demo.c)
target_link_libraries(ut_demo PRIVATE demo)
add_custom_command(TARGET ut_demo POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PROJECT_BINARY_DIR}/bin
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:ut_demo> ${PROJECT_BINARY_DIR}/bin/$<TARGET_FILE_NAME:ut_demo>
    COMMAND ${CMAKE_COMMAND} -E remove $<TARGET_FILE:ut_demo>)
add_test(NAME ut_demo COMMAND ${PROJECT_BINARY_DIR}/bin/ut_demo)
"""

DEMO_H = """\
#ifndef DEMO_H
#define DEMO_H
#include <stddef.h>
int demo_check(const unsigned char *buf, size_t len);
#endif
"""

DEMO_LIB_C = """\
#include "demo.h"
int demo_check(const unsigned char *buf, size_t len) {
    if (!buf || len == 0) return -1;
    return (int)buf[0] + (int)len;
}
"""

DEMO_UT_C = """\
#include "demo.h"
int main(void) {
    const unsigned char frame[4] = {0x20, 0x01, 0x02, 0x03};
    return demo_check(frame, sizeof(frame)) == 0x24 ? 0 : 1;
}
"""

CMAKE_DRIVE_PY = """\
import json, os, shutil, sys
sys.path.insert(0, "/opt/framac-pipeline/scripts")
W = "/tmp/postbuild_w"
shutil.rmtree(W, ignore_errors=True)
os.makedirs(W + "/run")
shutil.copytree("/w/target", W + "/target")
os.chdir(W + "/run")

import build_capture, seed_harvest, validate_artifacts

recipe = {
    "command": "cmake -S . -B build && cmake --build build",
    "workdir": ".",
    "packages": [],
    "env": {},
    "test_command": "ctest --test-dir build --output-on-failure",
    "origin": "user",
}
with open("run-metadata.json", "w", encoding="utf-8") as fh:
    json.dump({"build": recipe}, fh)

rc_cap = build_capture.main(["run", "--target", W + "/target", "--scratch", W + "/scratch", "--state", ""])
capture = json.load(open("workspace/reports/build_capture.json", encoding="utf-8"))
cap_errs = validate_artifacts.validate_build_capture(capture)

model = {
    "status": "ok",
    "entry_points": ["src/lib.c#demo_check"],
    "functions": {
        "src/lib.c#demo_check": {
            "name": "demo_check",
            "signature": "int(unsigned char *,unsigned long)",
            "formals": [{"name": "buf"}, {"name": "len"}],
        }
    },
    "units": {},
}
with open("workspace/reports/phase0_model.json", "w", encoding="utf-8") as fh:
    json.dump(model, fh)

rc_seed = seed_harvest.main(["record", "--scratch", W + "/scratch", "--timeout", "120"])
report = json.load(open("workspace/reports/seed_harvest.json", encoding="utf-8"))
seed_errs = validate_artifacts.validate_seed_harvest(report)
calls = [json.loads(ln) for ln in open("workspace/seed_records/calls.jsonl", encoding="utf-8").read().splitlines() if ln]

print("RESULT " + json.dumps({
    "rc_cap": rc_cap,
    "cap_status": capture.get("status"),
    "cap_errs": cap_errs,
    "arch_unknown": (capture.get("architecture") or {}).get("unknown"),
    "ut_unit": capture.get("units", {}).get("build/test/ut_demo"),
    "lib_unit": capture.get("units", {}).get("build/src/libdemo.so"),
    "rc_seed": rc_seed,
    "seed_status": report.get("status"),
    "seed_errs": seed_errs,
    "relink": report.get("relink"),
    "test_rc": (report.get("test") or {}).get("returncode"),
    "by_function": (report.get("calls") or {}).get("by_function"),
    "calls": calls,
    "orig_exists_after": os.path.exists(W + "/scratch/tree/build/test/ut_demo"),
    "bin_exists_after": os.path.exists(W + "/scratch/tree/build/bin/ut_demo"),
}))
"""


@pytest.mark.integration
@pytest.mark.slow
def test_cmake_post_build_copy_and_remove_captured_and_recorded_in_build_image(tmp_path: Path) -> None:
    require_docker_images(BUILD_IMAGE)
    files = {
        "target/CMakeLists.txt": CMAKE_ROOT,
        "target/src/CMakeLists.txt": CMAKE_SRC,
        "target/test/CMakeLists.txt": CMAKE_TEST,
        "target/include/demo.h": DEMO_H,
        "target/src/lib.c": DEMO_LIB_C,
        "target/test/ut_demo.c": DEMO_UT_C,
        "drive.py": CMAKE_DRIVE_PY,
    }
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8", newline="\n")
    tag = os.environ.get("FRAMAC_RUN_TAG", "pytest-seed-post-build-move")
    proc = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "--label", f"framac.run={tag}",
         "-v", f"{tmp_path}:/w:ro",
         "-v", f"{ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
         "-v", f"{ROOT / 'schemas'}:/opt/framac-pipeline/schemas:ro",
         "--entrypoint", "sh", BUILD_IMAGE, "-c", "timeout 600 python3 /w/drive.py"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900, check=False,
    )  # fmt: skip
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    line = next((ln for ln in proc.stdout.splitlines() if ln.startswith("RESULT ")), None)
    assert line is not None, out
    res = json.loads(line[len("RESULT ") :])
    assert res["rc_cap"] == 0 and res["cap_status"] == "ok", res
    assert res["cap_errs"] == [], res
    assert res["arch_unknown"] == 0, res
    assert res["ut_unit"]["installed_as"] == ["build/bin/ut_demo"], res
    assert res["lib_unit"]["installed_as"] == ["build/libdemo.so"], res
    assert res["rc_seed"] == 0 and res["seed_status"] == "ok", res
    assert res["seed_errs"] == [], res
    assert res["relink"]["build/test/ut_demo"] == {
        "status": "relinked",
        "wrapped": ["demo_check"],
        "installed_as": ["build/bin/ut_demo"],
    }, res
    assert res["test_rc"] == 0, res
    assert res["by_function"] == {"demo_check": 1}, res
    assert res["calls"][0]["fn"] == "demo_check"
    assert res["calls"][0]["args"]["0"] == [["b", 0, "20010203"]], res
    assert res["orig_exists_after"] is False and res["bin_exists_after"] is True, res
