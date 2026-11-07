"""
The target's environment in the analysis image (plan step I3b): scripts/target_env.py turns the run's
snapshot into include and link flags, and every Frama-C parse, E-ACSL, sanitizer and coverage build
picks them up.
"""

import json
import shlex
from pathlib import Path

import pytest

import cache
import framac_common
import run_eacsl_fuzz
import target_env


def _snapshot(tmp_path: Path, files: dict[str, str]) -> Path:
    snap = tmp_path / "snapshot"
    for path in files:
        dest = snap / "root" / path.lstrip("/")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text("x", encoding="utf-8")
    (snap / "manifest.json").write_text(json.dumps({"digest": "d1", "files": files}), encoding="utf-8")
    return snap


CRYPTOLIB_FILES = {
    "/usr/include/gcrypt.h": "h1",
    "/usr/include/x86_64-linux-gnu/gpg-error.h": "h2",
    "/usr/include/mysql/mysql.h": "h3",
    "/lib/x86_64-linux-gnu/libgcrypt.so.20": "l1",
    "/lib/x86_64-linux-gnu/libgpg-error.so.0": "l2",
    "/usr/lib/x86_64-linux-gnu/libgcrypt.so": "l3",
}


@pytest.fixture
def snapshot(tmp_path, monkeypatch):
    snap = _snapshot(tmp_path, CRYPTOLIB_FILES)
    monkeypatch.setenv("FRAMAC_SNAPSHOT_DIR", str(snap))
    return snap


@pytest.mark.unit
def test_no_snapshot_changes_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("FRAMAC_SNAPSHOT_DIR", str(tmp_path / "none"))
    assert target_env.snapshot_dir() is None and target_env.snapshot_digest() is None
    assert target_env.with_include_flags("-I. -DX=1") == "-I. -DX=1"
    assert target_env.with_link_flags("-lgcrypt") == "-lgcrypt"
    assert target_env.link_flags() == []


@pytest.mark.unit
def test_include_flags_name_the_compile_dirs_then_the_default_system_dirs(snapshot):
    root = (snapshot / "root").as_posix()
    flags = target_env.include_flags(root, ["-Iinclude", "-I", "/usr/include/mysql", "-I/opt/missing", "-DX"])
    assert flags[0::2] == ["-idirafter"] * 3
    assert [d.removeprefix(root) for d in flags[1::2]] == [
        "/usr/include/mysql",
        "/usr/include/x86_64-linux-gnu",
        "/usr/include",
    ]
    assert target_env.include_flags(None, ["-I/usr/include"]) == []


@pytest.mark.unit
def test_link_flags_give_every_library_dir_an_rpath(snapshot):
    root = (snapshot / "root").as_posix()
    assert target_env.library_dirs() == [f"{root}/lib/x86_64-linux-gnu", f"{root}/usr/lib/x86_64-linux-gnu"]
    flags = target_env.link_flags()
    for d in target_env.library_dirs():
        assert ["-L", d] == flags[flags.index("-L", flags.index(d) - 1) : flags.index(d) + 1]
        assert f"-Wl,-rpath,{d}" in flags and f"-Wl,-rpath-link,{d}" in flags
    # DT_RPATH, not DT_RUNPATH: libgcrypt's own dependency (libgpg-error) must resolve from there too.
    assert flags[-1] == "-Wl,--disable-new-dtags"
    assert shlex.split(target_env.with_link_flags("-lgcrypt"))[0] == "-lgcrypt"


@pytest.mark.unit
def test_framac_parses_search_the_snapshot_last(snapshot):
    flags = shlex.split(framac_common.augment_framac_cppflags("-Iworkspace/stubs -I/usr/include/mysql"))
    root = (snapshot / "root").as_posix()
    assert flags.index("-Iworkspace/stubs") < flags.index("-idirafter")
    assert f"{root}/usr/include/mysql" in flags and f"{root}/usr/include" in flags


@pytest.mark.unit
def test_clang_builds_compile_and_link_against_the_snapshot(snapshot, tmp_path):
    calls = []

    def runner(cmd, **kw):
        calls.append(cmd)

        class P:
            returncode, stdout, stderr = 0, "", ""

        return P()

    res = run_eacsl_fuzz.compile_sanitizer_binary(
        ["h.c"], tmp_path / "bin", "-I.", ldflags_extra="-lgcrypt", runner=runner, use_cache=False
    )
    cmd = res["command"].split()
    root = (snapshot / "root").as_posix()
    assert cmd.index("-idirafter") < cmd.index("h.c") < cmd.index("-lgcrypt") < cmd.index("-L")
    assert f"-Wl,-rpath,{root}/lib/x86_64-linux-gnu" in cmd


@pytest.mark.unit
def test_the_snapshot_digest_is_part_of_the_cache_toolchain(snapshot, monkeypatch):
    monkeypatch.setenv("FRAMAC_IMAGE_ID", "sha256:abc")
    assert cache.toolchain_id() == "image:sha256:abc+snapshot:d1"
    monkeypatch.setenv("FRAMAC_SNAPSHOT_DIR", str(snapshot.parent / "none"))
    assert cache.toolchain_id() == "image:sha256:abc"
