"""
Open topic O7: Frama-C parses read the build image's copies of the libc headers Frama-C's libc lacks
(`linux-libc-dev`, glibc's `elf.h`) from the run's snapshot, before the analysis image's own system
directories, and `-idirafter` directories are matched as whole tokens. target_env.with_include_flags owns
the order; framac_common.augment_framac_cppflags only asks for it (`nostdinc=True`).
"""

from __future__ import annotations

import hashlib
import shlex
from pathlib import Path

import pytest

import build_capture as bc
import framac_common
import target_env


def _image_dirs(monkeypatch) -> list[str]:
    """The analysis image's system directories, as if they existed on this host."""
    dirs = list(target_env.IMAGE_SYSTEM_DIRS)
    monkeypatch.setattr(target_env, "image_system_dirs", lambda: list(dirs))
    return dirs


def _idirafter(words: list[str]) -> list[str]:
    return [words[i + 1] for i, w in enumerate(words[:-1]) if w == "-idirafter"]


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _export(tmp_path: Path, with_libc: bool) -> tuple[Path, dict]:
    """A snapshot with one target header under /usr/include and, `with_libc`, three exported libc gaps."""
    src = tmp_path / "build-image"
    target_hdr = _write(src / "json.h", "int json_parse(const char *);\n")
    libc = None
    if with_libc:
        libc = {
            "/usr/include/elf.h": _write(src / "elf.h", "#define EI_NIDENT (16)\n"),
            "/usr/include/linux/audit.h": _write(src / "audit.h", "#define AUDIT_ARCH_X86_64 0xC000003EU\n"),
            "/usr/include/x86_64-linux-gnu/asm/types.h": _write(src / "types.h", "typedef unsigned int __u32;\n"),
        }
    snap = tmp_path / "run" / "workspace" / "snapshot"
    # export_snapshot copies `files` by their own path: give it the file under its system name.
    root_src = _write(tmp_path / "sysroot" / "usr" / "include" / "json-c" / "json.h", target_hdr.read_text())
    summary = bc.export_snapshot(snap, {root_src.as_posix(): {}}, libc=libc)
    # The target header as the build saw it: <root>/usr/include/json-c/json.h.
    _write(snap / "root" / "usr" / "include" / "json-c" / "json.h", "int json_parse(const char *);\n")
    return snap, summary


@pytest.mark.unit
def test_a_unit_idirafter_below_usr_include_does_not_drop_usr_include(tmp_path, monkeypatch):
    monkeypatch.setenv("FRAMAC_SNAPSHOT_DIR", str(tmp_path / "none"))
    image = _image_dirs(monkeypatch)
    for unit_flags in (
        "-idirafter /usr/include/foo -I.",
        "-idirafter/usr/include/foo -I.",
        "-I. -idirafter /usr/includes",
    ):
        dirs = _idirafter(shlex.split(framac_common.augment_framac_cppflags(unit_flags)))
        assert [d for d in dirs if d in image] == image, unit_flags
    # The exact directory, in either spelling, is not added a second time.
    for unit_flags in ("-I. -idirafter /usr/include", "-I. -idirafter/usr/include"):
        words = shlex.split(framac_common.augment_framac_cppflags(unit_flags))
        assert words.count("/usr/include") + words.count("-idirafter/usr/include") == 1, unit_flags
    once = framac_common.augment_framac_cppflags("-Isrc")
    again = shlex.split(framac_common.augment_framac_cppflags(once))
    assert _idirafter(again).count("/usr/include") == 1


@pytest.mark.unit
def test_exported_uapi_headers_come_before_the_image_s(tmp_path, monkeypatch):
    snap, summary = _export(tmp_path, with_libc=True)
    assert summary["libc"] == 3 and summary["files"] == 4
    manifest = target_env._manifest(snap)
    assert sorted(manifest["libc"]) == [
        "/usr/include/elf.h",
        "/usr/include/linux/audit.h",
        "/usr/include/x86_64-linux-gnu/asm/types.h",
    ]
    assert (snap / "libc/usr/include/linux/audit.h").read_text(encoding="utf-8").startswith("#define AUDIT_ARCH")
    monkeypatch.setenv("FRAMAC_SNAPSHOT_DIR", str(snap))
    image = _image_dirs(monkeypatch)
    root, libc = (snap / "root").as_posix(), (snap / "libc").as_posix()
    dirs = _idirafter(shlex.split(framac_common.augment_framac_cppflags("-I. -idirafter /usr/include/foo")))
    assert dirs == [
        "/usr/include/foo",
        f"{root}/usr/include",
        f"{libc}/usr/include/x86_64-linux-gnu",
        f"{libc}/usr/include",
        *image,
    ]
    again = framac_common.augment_framac_cppflags(framac_common.augment_framac_cppflags("-I."))
    assert all(_idirafter(shlex.split(again)).count(d) == 1 for d in dirs[1:])
    # The compiler builds (gcc, clang, the E-ACSL frontend) search their own system directories first:
    # neither the export nor the image's directories are added for them.
    gcc_dirs = _idirafter(shlex.split(target_env.with_include_flags("-I.")))
    assert gcc_dirs == [f"{root}/usr/include"]


@pytest.mark.unit
def test_an_older_capture_without_the_export_keeps_today_s_flags(tmp_path, monkeypatch):
    snap, summary = _export(tmp_path, with_libc=False)
    assert "libc" not in summary and "libc" not in target_env._manifest(snap)
    hdr = tmp_path / "sysroot" / "usr" / "include" / "json-c" / "json.h"
    content = hashlib.sha256(hdr.read_bytes()).hexdigest()
    # The digest an export without the libc gaps always had: (path, sha256) of `root/` only.
    assert summary["digest"] == hashlib.sha256(f"{hdr.as_posix()}\0{content}\n".encode()).hexdigest()
    # A stray libc/ directory is not read without the manifest's key.
    _write(snap / "libc" / "usr" / "include" / "elf.h", "#error stale\n")
    monkeypatch.setenv("FRAMAC_SNAPSHOT_DIR", str(snap))
    image = _image_dirs(monkeypatch)
    assert target_env.libc_include_flags() == []
    root = (snap / "root").as_posix()
    words = shlex.split(framac_common.augment_framac_cppflags("-I."))
    assert _idirafter(words) == [f"{root}/usr/include", *image]
    assert words.index("-I.") < words.index(f"{root}/usr/include")
    # No snapshot at all: the image's directories only, as before.
    monkeypatch.setenv("FRAMAC_SNAPSHOT_DIR", str(tmp_path / "none"))
    assert _idirafter(shlex.split(framac_common.augment_framac_cppflags("-I."))) == image
    assert target_env.with_include_flags("-I. -DX=1") == "-I. -DX=1"


@pytest.mark.unit
def test_the_capture_exports_only_the_gaps_of_frama_c_s_libc():
    headers = [
        {"path": "/usr/include/linux/audit.h", "package": "linux-libc-dev", "class": "libc"},
        {"path": "/usr/include/x86_64-linux-gnu/bits/../asm/types.h", "package": "linux-libc-dev", "class": "libc"},
        {"path": "/usr/include/elf.h", "package": "libc6-dev", "class": "libc"},
        {"path": "/usr/include/stdio.h", "package": "libc6-dev", "class": "libc"},
        {"path": "/usr/include/zlib.h", "package": "zlib1g-dev", "class": "package"},
        {"path": "/usr/lib/gcc/x86_64-linux-gnu/12/include/stddef.h", "package": "libgcc-12-dev", "class": "toolchain"},
    ]
    gaps = bc.framac_libc_gaps(headers)
    assert sorted(gaps) == [
        "/usr/include/elf.h",
        "/usr/include/linux/audit.h",
        "/usr/include/x86_64-linux-gnu/asm/types.h",
    ]
    assert gaps["/usr/include/elf.h"] == {
        "path": "/usr/include/elf.h",
        "package": "libc6-dev",
        "source": "/usr/include/elf.h",
    }


@pytest.mark.unit
def test_a_header_behind_a_symlinked_system_dir_is_exported_where_include_finds_it():
    # Debian trixie: /usr/include/x86_64-linux-gnu/asm/types.h -> /usr/lib/linux/uapi/x86/asm/types.h,
    # and `cc -M` names the real path (gcc's default -fcanonical-system-headers), which no `-idirafter`
    # of a Frama-C parse reaches.
    file_link = {"/usr/lib/linux/uapi/x86/asm/types.h": "/usr/include/x86_64-linux-gnu/asm/types.h"}
    assert bc.include_path("/usr/lib/linux/uapi/x86/asm/types.h", file_link) == next(iter(file_link.values()))
    # A linked directory maps every header below it.
    links = {"/usr/lib/linux/uapi/x86/asm": "/usr/include/x86_64-linux-gnu/asm"}
    headers = [{"path": "/usr/lib/linux/uapi/x86/asm/types.h", "package": "linux-libc-dev", "class": "libc"}]
    assert bc.framac_libc_gaps(headers, links) == {
        "/usr/include/x86_64-linux-gnu/asm/types.h": {
            "path": "/usr/include/x86_64-linux-gnu/asm/types.h",
            "package": "linux-libc-dev",
            "source": "/usr/lib/linux/uapi/x86/asm/types.h",
        }
    }
    assert bc.include_path("/usr/lib/linux/uapi/x86/asmx/a.h", links) == "/usr/lib/linux/uapi/x86/asmx/a.h"
    assert bc.system_dir_links(["/nonexistent-o7-dir"]) == {}


@pytest.mark.unit
def test_build_snapshot_hands_the_gaps_to_the_export_and_reports_them(tmp_path, monkeypatch):
    seen: dict = {}

    def export(snapshot, files, generated=None, generated_dirs=None, libc=None):
        seen.update(files=files, libc=libc)
        return {"digest": "0" * 64, "files": len(files) + len(libc or {}), "generated": 0, "libc": len(libc or {})}

    owners = {
        "/usr/include/linux/seccomp.h": "linux-libc-dev",
        "/usr/lib/linux/uapi/x86/asm/types.h": "linux-libc-dev",
        "/usr/include/elf.h": "libc6-dev",
        "/usr/include/stdlib.h": "libc6-dev",
        "/usr/include/seccomp.h": "libseccomp-dev",
    }
    monkeypatch.setattr(bc, "export_snapshot", export)
    monkeypatch.setattr(
        bc, "system_dir_links", lambda: {"/usr/lib/linux/uapi/x86/asm": "/usr/include/x86_64-linux-gnu/asm"}
    )
    monkeypatch.setattr(bc, "run_tool", lambda *a, **k: (1, "", ""))
    monkeypatch.setattr(
        bc,
        "classify_system_paths",
        lambda paths: {p: {"package": owners.get(p), "class": bc.owner_class(owners.get(p))} for p in paths},
    )
    warnings: list[str] = []
    result = bc.build_snapshot(tmp_path / "snap", tmp_path, {}, set(owners), {}, warnings)
    asm = "/usr/include/x86_64-linux-gnu/asm/types.h"
    assert sorted(seen["libc"]) == ["/usr/include/elf.h", "/usr/include/linux/seccomp.h", asm]
    assert seen["libc"][asm] == Path("/usr/lib/linux/uapi/x86/asm/types.h")
    assert list(seen["files"]) == ["/usr/include/seccomp.h"]
    assert result["framac_libc_gaps"] == [
        {"path": "/usr/include/elf.h", "package": "libc6-dev"},
        {"path": "/usr/include/linux/seccomp.h", "package": "linux-libc-dev"},
        {"path": asm, "package": "linux-libc-dev", "source": "/usr/lib/linux/uapi/x86/asm/types.h"},
    ]
    assert result["excluded"]["libc_headers"] == 1
    assert [h["path"] for h in result["headers"]] == ["/usr/include/seccomp.h"]
    base = {"schema_version": 1, "generated_at": "t", "target": "/target", "warnings": [], "status": "error"}
    assert not bc.validate_report({**base, "error": "x", "snapshot": result})
    result["framac_libc_gaps"][0]["class"] = "libc"
    assert bc.validate_report({**base, "error": "x", "snapshot": result})
