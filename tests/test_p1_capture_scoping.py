"""
Unit tests for P1 capture & model scoping (W1-A):
  - build_capture.py: DATA_TYPES, exported_data_symbols, unit_visibility, embedded_api_source
  - phase0_model.py: propagation of const/has_init/raw_type on global_variables and
    unit_visibility/exported_data_symbols/embedded_api_source on units
  - schemas/build_capture.schema.json & schemas/phase0_model.schema.json validation
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

import build_capture as bc
import phase0_model as pm

TREE = "/framac-scratch/tree"


def _exec(args: list[str], cwd: str = TREE) -> dict[str, Any]:
    return {"exe": f"/usr/bin/{args[0]}", "args": args, "cwd": cwd}


def _make_base_report(target: Path) -> dict[str, Any]:
    return {
        "schema_version": bc.SCHEMA_VERSION,
        "generated_at": "2026-11-22T00:00:00Z",
        "status": bc.STATUS_OK,
        "target": str(target),
        "warnings": [],
        "build": {
            "returncode": 0,
            "timed_out": False,
            "seconds": 0.1,
            "executions": 1,
            "log": "workspace/reports/build_capture/build.log",
            "events": "workspace/reports/build_capture/events.jsonl",
        },
    }


def _stub_snapshot(*_a: Any, **_k: Any) -> dict[str, Any]:
    return {
        "root": "/run/workspace/snapshot/root",
        "digest": "0" * 64,
        "files": 0,
        "headers": [],
        "libraries": [],
        "packages": [],
    }


def _run_analyse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    execs: list[dict[str, Any]],
    headers: dict[str, str],
    dep_map: dict[str, list[str]],
    sym_map: Mapping[str, Mapping[str, tuple[str, str | None]]],
    *,
    nm_dynamic_map: dict[str, str] | None = None,
    installed_headers: list[Path] | None = None,
) -> dict[str, Any]:
    tree = tmp_path / "tree"
    tree.mkdir(parents=True, exist_ok=True)
    for rel, text in headers.items():
        p = tree / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")

    def fake_deps(c: dict[str, Any], t: str) -> tuple[list[str], None]:
        hs = dep_map.get(c["source"], [])
        return [c["object"], *(f"{t}/{h}" for h in hs)], None

    def fake_syms(c: dict[str, Any], _t: str, _tmp: Path, _idx: int) -> tuple[dict[str, tuple[str, str | None]], None]:
        return dict(sym_map.get(c["source"], {})), None

    orig_run_tool = bc.run_tool

    def fake_run_tool(cmd: list[str], cwd: Path | str | None = None, timeout: int = 120) -> tuple[int, str, str]:
        if cmd[:3] == ["nm", "-D", "--defined-only"] and nm_dynamic_map is not None:
            target_path = Path(cmd[3])
            rel = target_path.relative_to(tree).as_posix()
            if rel in nm_dynamic_map:
                return 0, nm_dynamic_map[rel], ""
            return 1, "", "not found"
        if cmd[:3] == ["cc", "-E", "-P"]:
            # Fallback to raw header text inside declared_in without invoking host cc.
            return 1, "", "stubbed cc"
        return orig_run_tool(cmd, cwd=cwd, timeout=timeout)

    monkeypatch.setattr(bc, "compile_deps", fake_deps)
    monkeypatch.setattr(bc, "compile_symbols", fake_syms)
    monkeypatch.setattr(bc, "run_tool", fake_run_tool)
    if installed_headers is not None:
        monkeypatch.setattr(bc, "try_install", lambda *_a: (installed_headers, "install"))
    else:
        monkeypatch.setattr(bc, "try_install", lambda *_a: ([], "no install target"))
    monkeypatch.setattr(bc, "generated_headers", lambda *_a: [])
    monkeypatch.setattr(bc, "generated_sources", lambda *_a: ([], []))
    monkeypatch.setattr(bc, "build_snapshot", _stub_snapshot)

    cap = bc.classify_executions(execs, TREE)
    report = _make_base_report(tmp_path / "target")
    bc.analyse(report, cap, tree, tmp_path / "scratch", {}, 60, 1)
    return report


@pytest.mark.unit
def test_multifile_executable_visibility_and_embedded_api_source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Multi-file executable gets unit_visibility='executable' and embedded_api_source when embedded_api is populated."""
    execs = [
        _exec(["cc", "-c", "src/main.c", "-o", "build/main.o"]),
        _exec(["cc", "-c", "src/parse.c", "-o", "build/parse.o"]),
        _exec(["cc", "-o", "build/app", "build/main.o", "build/parse.o"]),
        _exec(["cc", "-c", "src/solo.c", "-o", "build/solo.o"]),
        _exec(["cc", "-o", "build/solo", "build/solo.o"]),
        _exec(["cc", "-c", "tests/t_app.c", "-o", "build/t_app.o"]),
        _exec(["cc", "-o", "build/app_test", "build/t_app.o"]),
    ]
    headers = {"src/parse.h": "int parse_line(const char *s);\n"}
    dep_map = {
        "src/main.c": ["src/parse.h"],
        "src/parse.c": ["src/parse.h"],
        "src/solo.c": [],
        "tests/t_app.c": [],
    }
    sym_map = {
        "src/main.c": {"main": ("T", None)},
        "src/parse.c": {"parse_line": ("T", None), "internal_helper": ("t", None)},
        "src/solo.c": {"main": ("T", None)},
        "tests/t_app.c": {"main": ("T", None)},
    }
    report = _run_analyse(tmp_path, monkeypatch, execs, headers, dep_map, sym_map)
    assert bc.validate_report(report) == []

    app = report["units"]["build/app"]
    assert app["unit_visibility"] == "executable"
    assert app["entry_points"] == ["src/main.c#main"]
    assert app["embedded_api"] == ["src/parse.c#parse_line"]
    assert app["embedded_api_source"] == "header_declared_internal"
    assert app["exported_data_symbols"] == []

    solo = report["units"]["build/solo"]
    assert solo["unit_visibility"] == "executable"
    assert solo["embedded_api"] == []
    assert "embedded_api_source" not in solo

    # Test units do not receive unit_visibility.
    test_u = report["units"]["build/app_test"]
    assert test_u["test"] is True
    assert "unit_visibility" not in test_u


@pytest.mark.unit
def test_plugin_so_vs_public_shared_lib_classification(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Plugin .so exporting only data structs gets plugin_so; normal or empty .so gets public_lib."""
    execs = [
        _exec(["cc", "-c", "plugins/sudoers/policy.c", "-o", "build/policy.o"]),
        _exec(["cc", "-shared", "-o", "build/sudoers.so", "build/policy.o"]),
        _exec(["cc", "-c", "lib/util.c", "-o", "build/util.o"]),
        _exec(["cc", "-shared", "-o", "build/libsudo_util.so", "build/util.o"]),
        _exec(["cc", "-c", "lib/hidden.c", "-o", "build/hidden.o"]),
        _exec(["cc", "-shared", "-o", "build/libhidden.so", "build/hidden.o"]),
    ]
    sym_map = {
        "plugins/sudoers/policy.c": {
            "sudoers_policy_open": ("t", None),
            "sudoers_policy": ("D", None),
            "sudoers_io": ("D", None),
        },
        "lib/util.c": {
            "sudo_strlcpy": ("T", None),
            "sudo_weak_fn": ("W", None),
            "sudo_debug_level": ("B", None),
        },
        "lib/hidden.c": {"priv_helper": ("t", None)},
    }
    nm_dynamic = {
        "build/sudoers.so": (
            "0000000000004020 D sudoers_policy\n"
            "0000000000004120 D sudoers_io\n"
            "0000000000004200 R sudoers_meta@@SUDO_1.0\n"
            "0000000000004300 B __bss_start\n"
            "0000000000004300 D _edata\n"
            "0000000000004308 B _end\n"
            "0000000000001000 T _init\n"
        ),
        "build/libsudo_util.so": (
            "0000000000001100 T sudo_strlcpy\n"
            "0000000000001140 W sudo_weak_fn\n"
            "0000000000004010 B sudo_debug_level\n"
            "0000000000004020 B __bss_start\n"
            "0000000000004020 D _edata\n"
            "0000000000004028 B _end\n"
        ),
        "build/libhidden.so": ("0000000000004000 B __bss_start\n0000000000004000 D _edata\n0000000000004008 B _end\n"),
    }
    report = _run_analyse(tmp_path, monkeypatch, execs, {}, {}, sym_map, nm_dynamic_map=nm_dynamic)
    assert bc.validate_report(report) == []

    plugin = report["units"]["build/sudoers.so"]
    assert plugin["entry_points"] == []
    assert plugin["exported_data_symbols"] == ["sudoers_io", "sudoers_meta", "sudoers_policy"]
    assert plugin["unit_visibility"] == "plugin_so"

    pub_so = report["units"]["build/libsudo_util.so"]
    assert pub_so["entry_points"] == ["lib/util.c#sudo_strlcpy", "lib/util.c#sudo_weak_fn"]
    # Weak function `sudo_weak_fn` is in entry_points and excluded from exported_data_symbols.
    assert pub_so["exported_data_symbols"] == ["sudo_debug_level"]
    assert pub_so["unit_visibility"] == "public_lib"

    # Fallback: neither exported functions nor exported data -> public_lib.
    hidden = report["units"]["build/libhidden.so"]
    assert hidden["entry_points"] == []
    assert hidden["exported_data_symbols"] == []
    assert hidden["unit_visibility"] == "public_lib"


@pytest.mark.unit
def test_static_lib_visibility_internal_vs_standalone_vs_installed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Non-installed static_lib linked by non-test exe/so is internal_convenience; standalone or installed is public_lib."""
    execs = [
        _exec(["cc", "-c", "lib/conv.c", "-o", "build/conv.o"]),
        _exec(["ar", "rcs", "build/libconv.a", "build/conv.o"]),
        _exec(["cc", "-c", "lib/soconv.c", "-o", "build/soconv.o"]),
        _exec(["ar", "rcs", "build/libsoconv.a", "build/soconv.o"]),
        _exec(["cc", "-c", "lib/standalone.c", "-o", "build/standalone.o"]),
        _exec(["ar", "rcs", "build/libstandalone.a", "build/standalone.o"]),
        _exec(["cc", "-c", "src/main.c", "-o", "build/main.o"]),
        _exec(["cc", "-o", "build/app", "build/main.o", "build/libconv.a"]),
        _exec(["cc", "-c", "plugins/mod.c", "-o", "build/mod.o"]),
        _exec(["cc", "-shared", "-o", "build/mod.so", "build/mod.o", "build/libsoconv.a"]),
        _exec(["cc", "-c", "tests/t_standalone.c", "-o", "build/t_standalone.o"]),
        _exec(["cc", "-o", "build/standalone_test", "build/t_standalone.o", "build/libstandalone.a"]),
    ]
    headers = {
        "include/lib.h": "int conv_fn(int x);\nint soconv_fn(int x);\nint standalone_fn(int x);\n",
    }
    dep_map = {
        "lib/conv.c": ["include/lib.h"],
        "lib/soconv.c": ["include/lib.h"],
        "lib/standalone.c": ["include/lib.h"],
        "src/main.c": ["include/lib.h"],
        "plugins/mod.c": ["include/lib.h"],
        "tests/t_standalone.c": ["include/lib.h"],
    }
    sym_map = {
        "lib/conv.c": {"conv_fn": ("T", None)},
        "lib/soconv.c": {"soconv_fn": ("T", None)},
        "lib/standalone.c": {"standalone_fn": ("T", None)},
        "src/main.c": {"main": ("T", None)},
        "plugins/mod.c": {"mod_api": ("T", None)},
        "tests/t_standalone.c": {"main": ("T", None)},
    }
    nm_dynamic = {"build/mod.so": "0000000000001000 T mod_api\n"}

    # Without install: linked by non-test exe/so -> internal_convenience; linked only by test exe -> public_lib.
    no_install = _run_analyse(
        tmp_path / "no_inst", monkeypatch, execs, headers, dep_map, sym_map, nm_dynamic_map=nm_dynamic
    )
    assert bc.validate_report(no_install) == []
    assert no_install["public_headers"]["method"] == "outside_source_dirs"
    assert no_install["units"]["build/libconv.a"]["unit_visibility"] == "internal_convenience"
    assert no_install["units"]["build/libsoconv.a"]["unit_visibility"] == "internal_convenience"
    assert no_install["units"]["build/libstandalone.a"]["unit_visibility"] == "public_lib"
    assert no_install["units"]["build/app"]["unit_visibility"] == "executable"
    assert no_install["units"]["build/mod.so"]["unit_visibility"] == "public_lib"
    assert "unit_visibility" not in no_install["units"]["build/standalone_test"]

    # With install: public["method"] == "install" and lib.h declares all three libraries' APIs -> public_lib.
    staged = tmp_path / "inst" / "staged" / "include" / "lib.h"
    staged.parent.mkdir(parents=True, exist_ok=True)
    staged.write_text(headers["include/lib.h"], encoding="utf-8")
    with_install = _run_analyse(
        tmp_path / "inst",
        monkeypatch,
        execs,
        headers,
        dep_map,
        sym_map,
        nm_dynamic_map=nm_dynamic,
        installed_headers=[staged],
    )
    assert bc.validate_report(with_install) == []
    assert with_install["public_headers"]["method"] == "install"
    assert with_install["units"]["build/libconv.a"]["unit_visibility"] == "public_lib"
    assert with_install["units"]["build/libsoconv.a"]["unit_visibility"] == "public_lib"
    assert with_install["units"]["build/libstandalone.a"]["unit_visibility"] == "public_lib"


@pytest.mark.unit
def test_static_lib_visibility_unrelated_installed_header_vs_installed_api(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """
    When `make install` stages only an unrelated header (like sudo's `sudo_plugin.h`), linked internal `.a`
    archives whose symbols are NOT declared in installed headers stay `internal_convenience`, while:
      - standalone `.a` archives not linked by any non-test exe/so stay `public_lib`,
      - linked `.a` archives whose own API IS declared in installed headers stay `public_lib`, and
      - linked `.a` archives whose `.a` file itself is staged under `scratch/install` stay `public_lib`.
    """
    execs = [
        _exec(["cc", "-c", "lib/logsrv/log.c", "-o", "build/log.o"]),
        _exec(["ar", "rcs", "build/liblogsrv.a", "build/log.o"]),
        _exec(["cc", "-c", "lib/pub/pub.c", "-o", "build/pub.o"]),
        _exec(["ar", "rcs", "build/libpub.a", "build/pub.o"]),
        _exec(["cc", "-c", "lib/staged/staged.c", "-o", "build/staged.o"]),
        _exec(["ar", "rcs", "build/libstaged.a", "build/staged.o"]),
        _exec(["cc", "-c", "lib/standalone/alone.c", "-o", "build/alone.o"]),
        _exec(["ar", "rcs", "build/libstandalone.a", "build/alone.o"]),
        _exec(["cc", "-c", "src/daemon.c", "-o", "build/daemon.o"]),
        _exec(
            [
                "cc",
                "-o",
                "build/daemon",
                "build/daemon.o",
                "build/liblogsrv.a",
                "build/libpub.a",
                "build/libstaged.a",
            ]
        ),
        _exec(["cc", "-c", "plugins/sudoers/policy.c", "-o", "build/policy.o"]),
        _exec(["cc", "-shared", "-o", "build/sudoers.so", "build/policy.o", "build/liblogsrv.a"]),
    ]
    headers = {
        "include/sudo_plugin.h": "struct sudo_plugin_api { int version; };\n",
        "include/log_server.h": "int logsrv_unpack(const unsigned char *buf, int len);\n",
        "include/pub.h": "int pub_parse(const char *s);\n",
        "include/staged_priv.h": "int staged_only_fn(int x);\n",
        "include/alone.h": "int alone_decode(const unsigned char *b);\n",
    }
    dep_map = {
        "lib/logsrv/log.c": ["include/sudo_plugin.h", "include/log_server.h"],
        "lib/pub/pub.c": ["include/pub.h"],
        "lib/staged/staged.c": ["include/staged_priv.h"],
        "lib/standalone/alone.c": ["include/alone.h"],
        "src/daemon.c": ["include/log_server.h", "include/pub.h", "include/staged_priv.h"],
        "plugins/sudoers/policy.c": ["include/sudo_plugin.h", "include/log_server.h"],
    }
    sym_map = {
        "lib/logsrv/log.c": {"logsrv_unpack": ("T", None)},
        "lib/pub/pub.c": {"pub_parse": ("T", None)},
        "lib/staged/staged.c": {"staged_only_fn": ("T", None)},
        "lib/standalone/alone.c": {"alone_decode": ("T", None)},
        "src/daemon.c": {"main": ("T", None)},
        "plugins/sudoers/policy.c": {"sudoers_policy": ("D", None)},
    }
    nm_dynamic = {"build/sudoers.so": "0000000000004000 D sudoers_policy\n"}

    # Stage sudo_plugin.h + pub.h (NOT log_server.h or staged_priv.h), plus libstaged.a itself.
    run_root = tmp_path / "sudo_like"
    inst_inc = run_root / "scratch" / "install" / "usr" / "local" / "include"
    inst_inc.mkdir(parents=True, exist_ok=True)
    staged_plugin_h = inst_inc / "sudo_plugin.h"
    staged_plugin_h.write_text(headers["include/sudo_plugin.h"], encoding="utf-8")
    staged_pub_h = inst_inc / "pub.h"
    staged_pub_h.write_text(headers["include/pub.h"], encoding="utf-8")
    inst_lib = run_root / "scratch" / "install" / "usr" / "local" / "lib"
    inst_lib.mkdir(parents=True, exist_ok=True)
    (inst_lib / "libstaged.a").write_bytes(b"!<arch>\n")

    report = _run_analyse(
        run_root,
        monkeypatch,
        execs,
        headers,
        dep_map,
        sym_map,
        nm_dynamic_map=nm_dynamic,
        installed_headers=[staged_plugin_h, staged_pub_h],
    )
    assert bc.validate_report(report) == []
    assert report["public_headers"]["method"] == "install"
    assert report["units"]["build/liblogsrv.a"]["unit_visibility"] == "internal_convenience"
    assert report["units"]["build/libpub.a"]["unit_visibility"] == "public_lib"
    assert report["units"]["build/libstaged.a"]["unit_visibility"] == "public_lib"
    assert report["units"]["build/libstandalone.a"]["unit_visibility"] == "public_lib"
    assert report["units"]["build/sudoers.so"]["unit_visibility"] == "plugin_so"
    assert report["units"]["build/daemon"]["unit_visibility"] == "executable"

    # Re-evaluating offline from the saved report (with warnings) reproduces the same classification
    # for declared-in-installed vs unrelated-header internal convenience archives.
    units = report["units"]
    pub = report["public_headers"]
    warns = report["warnings"]
    assert bc.classify_unit_visibility("build/liblogsrv.a", units["build/liblogsrv.a"], units, pub, warnings=warns) == (
        "internal_convenience"
    )
    assert bc.classify_unit_visibility("build/libpub.a", units["build/libpub.a"], units, pub, warnings=warns) == (
        "public_lib"
    )
    assert bc.classify_unit_visibility(
        "build/libstandalone.a", units["build/libstandalone.a"], units, pub, warnings=warns
    ) == "public_lib"
    # Even a 4-arg call without `warnings` keeps liblogsrv.a as internal_convenience (consumer fallback
    # mixed relative paths into public_headers["files"]) and keeps standalone nanopb-style .a as public_lib.
    assert bc.classify_unit_visibility("build/liblogsrv.a", units["build/liblogsrv.a"], units, pub) == (
        "internal_convenience"
    )
    assert bc.classify_unit_visibility("build/libstandalone.a", units["build/libstandalone.a"], units, pub) == (
        "public_lib"
    )


@pytest.mark.unit
def test_phase0_model_preserves_global_metadata_and_unit_visibility(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """phase0_model carries const/has_init/raw_type on globals and unit_visibility/exported_data_symbols on units."""
    tree = tmp_path / "tree"
    (tree / "plugins").mkdir(parents=True)
    (tree / "src").mkdir(parents=True)
    (tree / "plugins" / "sudoers.c").write_text("int dummy;\n", encoding="utf-8")
    (tree / "src" / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")

    capture = {
        "schema_version": 1,
        "generated_at": "2026-11-22T00:00:00Z",
        "status": "ok",
        "target": str(tmp_path / "target"),
        "scratch": {"root": str(tmp_path), "tree": str(tree)},
        "snapshot": {"root": None, "digest": None},
        "compiles": [
            {
                "source": "plugins/sudoers.c",
                "object": "build/sudoers.o",
                "cwd": ".",
                "compiler": "cc",
                "arguments": ["cc", "-c", "plugins/sudoers.c", "-o", "build/sudoers.o"],
                "flags": [],
                "system_flags": [],
                "headers": [],
            },
            {
                "source": "src/main.c",
                "object": "build/main.o",
                "cwd": ".",
                "compiler": "cc",
                "arguments": ["cc", "-c", "src/main.c", "-o", "build/main.o"],
                "flags": [],
                "system_flags": [],
                "headers": ["src/internal.h"],
            },
        ],
        "units": {
            "build/sudoers.so": {
                "kind": "shared_lib",
                "test": False,
                "test_reason": None,
                "files": ["plugins/sudoers.c"],
                "objects": ["build/sudoers.o"],
                "links": [],
                "external_libs": [],
                "cppflags": [],
                "entry_points": [],
                "embedded_api": [],
                "exported_data_symbols": ["sudoers_io", "sudoers_policy"],
                "unit_visibility": "plugin_so",
            },
            "build/sudo": {
                "kind": "executable",
                "test": False,
                "test_reason": None,
                "files": ["src/main.c"],
                "objects": ["build/main.o"],
                "links": [],
                "external_libs": [],
                "cppflags": [],
                "entry_points": ["src/main.c#main"],
                "embedded_api": ["src/main.c#main"],
                "embedded_api_source": "header_declared_internal",
                "exported_data_symbols": [],
                "unit_visibility": "executable",
            },
        },
        "warnings": [],
    }
    cap_path = tmp_path / "build_capture.json"
    cap_path.write_text(json.dumps(capture), encoding="utf-8")

    dumps_by_unit = {
        "build/sudoers.so": {
            "schema": 8,
            "functions": [
                {
                    "kernel_name": "policy_open",
                    "name": "policy_open",
                    "loc": "plugins/sudoers.c:10",
                    "first_line": 10,
                    "last_line": 15,
                    "static": True,
                    "inline": False,
                    "signature": "int(int)",
                    "loops": 0,
                    "cyclomatic": 1,
                    "calls": [],
                    "address_refs": [],
                    "global_refs": [],
                }
            ],
            "globals": [
                {
                    "name": "sudoers_policy",
                    "kernel_name": "sudoers_policy",
                    "loc": "plugins/sudoers.c:20",
                    "static": False,
                    "type": "struct policy_plugin",
                    "const": True,
                    "has_init": True,
                    "raw_type": "policy_plugin_t const",
                    "size": 64,
                    "init_functions": ["policy_open"],
                    "init_globals": [],
                },
                {
                    "name": "sudoers_state",
                    "kernel_name": "sudoers_state",
                    "loc": "plugins/sudoers.c:25",
                    "static": True,
                    "type": "int",
                    "const": False,
                    "has_init": False,
                    "raw_type": "int",
                    "size": 4,
                    "init_functions": [],
                    "init_globals": [],
                },
            ],
            "address_taken": ["policy_open"],
            "declared": [],
        },
        # Older dump (schema 7) without const / has_init / raw_type keys.
        "build/sudo": {
            "schema": 7,
            "functions": [
                {
                    "kernel_name": "main",
                    "name": "main",
                    "loc": "src/main.c:1",
                    "first_line": 1,
                    "last_line": 3,
                    "static": False,
                    "inline": False,
                    "signature": "int(void)",
                    "loops": 0,
                    "cyclomatic": 1,
                    "calls": [],
                    "address_refs": [],
                    "global_refs": [],
                }
            ],
            "globals": [
                {
                    "name": "legacy_flag",
                    "kernel_name": "legacy_flag",
                    "loc": "src/main.c:2",
                    "static": False,
                    "type": "int",
                    "size": 4,
                    "init_functions": [],
                    "init_globals": [],
                }
            ],
            "address_taken": [],
            "declared": [],
        },
    }

    monkeypatch.setattr(pm, "compile_dump_module", lambda *_a, **_k: (tmp_path / "fake.cmxs", ""))
    monkeypatch.setattr(pm, "macro_aliases", lambda *_a, **_k: [])

    def fake_parse(job: dict[str, Any], *_a: Any, **_k: Any) -> dict[str, Any]:
        unit_name = job["units"][0]
        return {"status": "ok", "dump": dumps_by_unit[unit_name], "seconds": 0.05}

    monkeypatch.setattr(pm, "framac_parse", fake_parse)

    model, rc = pm.build_model(cap_path, tmp_path / "phase0_model.json", jobs_n=1, broker=False)
    assert rc == 0
    assert pm.validate_model(model) == []

    # Unit visibility and exported_data_symbols carried from build_capture.json.
    so_unit = model["units"]["build/sudoers.so"]
    assert so_unit["unit_visibility"] == "plugin_so"
    assert so_unit["exported_data_symbols"] == ["sudoers_io", "sudoers_policy"]

    exe_unit = model["units"]["build/sudo"]
    assert exe_unit["unit_visibility"] == "executable"
    assert exe_unit["exported_data_symbols"] == []
    assert exe_unit["embedded_api_source"] == "header_declared_internal"

    # Schema 8 globals preserve const, has_init, raw_type.
    pol = model["global_variables"]["plugins/sudoers.c#sudoers_policy"]
    assert pol["const"] is True
    assert pol["has_init"] is True
    assert pol["raw_type"] == "policy_plugin_t const"
    assert pol["init_functions"] == ["plugins/sudoers.c#policy_open"]

    state = model["global_variables"]["plugins/sudoers.c#sudoers_state"]
    assert state["const"] is False
    assert state["has_init"] is False
    assert state["raw_type"] == "int"

    # Older schema 7 dump defaults gracefully without failing.
    legacy = model["global_variables"]["src/main.c#legacy_flag"]
    assert legacy["const"] is False
    assert legacy["has_init"] is False
    assert legacy["raw_type"] == ""


@pytest.mark.unit
def test_schemas_reject_invalid_unit_visibility():
    """Both schemas accept valid visibility values and reject unknown ones."""
    cap = _make_base_report(Path("/target"))
    cap["units"] = {
        "libx.so": {
            "kind": "shared_lib",
            "test": False,
            "test_reason": None,
            "files": ["x.c"],
            "objects": ["x.o"],
            "links": [],
            "external_libs": [],
            "cppflags": [],
            "entry_points": [],
            "embedded_api": [],
            "exported_data_symbols": ["sym_a"],
            "unit_visibility": "bogus_visibility",
        }
    }
    assert bc.validate_report(cap) != []
    cap["units"]["libx.so"]["unit_visibility"] = "plugin_so"
    assert bc.validate_report(cap) == []

    model: dict[str, Any] = {
        "schema_version": pm.SCHEMA_VERSION,
        "generated_at": "2026-11-22T00:00:00Z",
        "status": "ok",
        "capture": "workspace/reports/build_capture.json",
        "warnings": [],
        "units": {
            "libx.so": {
                "kind": "shared_lib",
                "test": False,
                "files": ["x.c"],
                "links": [],
                "parse": {"status": "ok"},
                "concurrent": False,
                "exported_data_symbols": ["sym_a"],
                "unit_visibility": "bogus_visibility",
            }
        },
    }
    assert pm.validate_model(model) != []
    model["units"]["libx.so"]["unit_visibility"] = "plugin_so"
    assert pm.validate_model(model) == []
