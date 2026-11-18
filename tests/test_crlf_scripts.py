"""
CRLF scripts a Linux shell cannot run (scripts/line_endings.py): the scan, the early warning of
`workspace_overlay.py init`, and the hint on a failed build (build_capture.py) or test command
(seed_harvest.py). A target checked out on Windows with core.autocrlf=true has `#!/bin/sh\\r` scripts.

Fixtures are written as bytes here, never as CRLF files on disk in the repository.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import build_capture as bc
import line_endings
import seed_harvest as sh
import workspace_overlay

pytestmark = pytest.mark.unit

CRLF_SHEBANG = b"#!/bin/sh\r\nset -e\r\necho ok\r\n"
LF_SHEBANG = b"#!/bin/sh\nset -e\necho ok\n"


def _crlf_target(root: Path) -> Path:
    (root / "tools").mkdir(parents=True)
    (root / "tools" / "unit.sh").write_bytes(CRLF_SHEBANG)
    (root / "lib.c").write_bytes(b"int f(void)\r\n{\r\n  return 0;\r\n}\r\n")
    return root


# --- the scan --------------------------------------------------------------------------------------


def test_a_crlf_shebang_is_found_and_an_lf_one_is_not(tmp_path):
    (tmp_path / "a.sh").write_bytes(CRLF_SHEBANG)
    (tmp_path / "b.sh").write_bytes(LF_SHEBANG)
    (tmp_path / "run").write_bytes(b"#!/usr/bin/env python3\r\nprint(1)\r\n")
    scan = line_endings.scan_crlf_scripts(tmp_path)
    assert [h.path for h in scan.hits] == ["a.sh", "run"]
    assert scan.hits[0].first_line == "#!/bin/sh\\r"
    assert scan.complete


def test_crlf_text_binary_and_git_files_are_not_scripts(tmp_path):
    (tmp_path / "lib.c").write_bytes(b"#include <x.h>\r\nint x;\r\n")
    (tmp_path / "notes.txt").write_bytes(b"#! not a script, says the extension\r\n")
    (tmp_path / "blob").write_bytes(b"#!\r\n\x00\x01\x02")
    (tmp_path / ".git" / "hooks").mkdir(parents=True)
    (tmp_path / ".git" / "hooks" / "pre-commit").write_bytes(CRLF_SHEBANG)
    assert line_endings.scan_crlf_scripts(tmp_path).hits == []


def test_a_named_shell_script_without_shebang_is_found(tmp_path):
    (tmp_path / "config.sub").write_bytes(b"# config.sub\r\nset -e\r\n")
    (tmp_path / "ltmain.sh").write_bytes(b"# sourced\nok\n")
    scan = line_endings.scan_crlf_scripts(tmp_path)
    assert [(h.path, h.first_line) for h in scan.hits] == [("config.sub", None)]


def test_the_listing_is_capped(tmp_path):
    for i in range(7):
        (tmp_path / f"s{i}.sh").write_bytes(CRLF_SHEBANG)
    summary = line_endings.summary(line_endings.scan_crlf_scripts(tmp_path), limit=3)
    assert summary["count"] == 7 and summary["paths"] == ["s0.sh", "s1.sh", "s2.sh"]
    assert summary["complete"] is True


def test_the_scan_stops_after_its_file_budget(tmp_path):
    for i in range(5):
        (tmp_path / f"s{i}.sh").write_bytes(CRLF_SHEBANG)
    scan = line_endings.scan_crlf_scripts(tmp_path, max_files=2)
    assert len(scan.hits) == 2 and not scan.complete


def test_the_hint_names_the_script_the_log_names_first(tmp_path):
    _crlf_target(tmp_path)
    (tmp_path / "configure").write_bytes(CRLF_SHEBANG)
    scan = line_endings.scan_crlf_scripts(tmp_path)
    hint = line_endings.failure_hint("the test command", 127, "sh: 1: tools/unit.sh: not found", scan)
    assert hint is not None
    assert hint.startswith("the test command exited 127; tools/unit.sh has CRLF line endings (#!/bin/sh\\r)")
    assert "core.autocrlf false" in hint and "sed -i 's/\\r$//'" in hint and "\r" not in hint


def test_no_hint_without_crlf_scripts_or_for_an_unrelated_failure(tmp_path):
    empty = line_endings.scan_crlf_scripts(tmp_path)
    assert line_endings.failure_hint("the build", 127, "sh: 1: x: not found", empty) is None
    _crlf_target(tmp_path)
    scan = line_endings.scan_crlf_scripts(tmp_path)
    assert line_endings.failure_hint("the build", 2, "lib.c:1: error: expected ';'", scan) is None
    # a shell reading a CRLF script: no exit 126/127, but the shell's own message
    assert line_endings.failure_hint("the build", 2, "/bin/sh: 0: Illegal option -", scan) is not None


def test_a_shell_syntax_error_on_a_crlf_script_gets_the_hint(tmp_path):
    # libmodbus run-1 (2026-11-18): under `bear intercept` dash reads the `#! /bin/sh\r` script and
    # stops at its first `then\r`; no 126/127, no `Illegal option -`. Repro in framac-build:latest.
    (tmp_path / "autogen.sh").write_bytes(b"#! /bin/sh\r\nif [ -f configure.ac ]; then\r\n  echo ok\r\nfi\r\n")
    scan = line_endings.scan_crlf_scripts(tmp_path)
    command = './autogen.sh && ./configure && make -j"$(nproc)"'
    dash = './autogen.sh: 22: Syntax error: end of file unexpected (expecting "then")\n'
    bash = "./autogen.sh: line 9: syntax error: unexpected end of file\n"
    for log in (dash, bash):
        hint = line_endings.failure_hint("the build command", 2, log, scan, command)
        assert hint is not None
        assert hint.startswith("the build command exited 2; autogen.sh has CRLF line endings (#! /bin/sh\\r)")


def test_a_shell_syntax_error_naming_no_crlf_script_gives_no_hint(tmp_path):
    scan = line_endings.scan_crlf_scripts(_crlf_target(tmp_path))
    for log in (
        './build.sh: 3: Syntax error: "fi" unexpected\n',
        "./build.sh: line 3: syntax error near unexpected token `fi'\n",
        "parse.y:12.5-10: syntax error, unexpected identifier\n",
    ):
        assert line_endings.failure_hint("the build command", 2, log, scan, "./build.sh && make") is None


def test_crlf_autotools_inputs_are_found(tmp_path):
    (tmp_path / "m4").mkdir()
    (tmp_path / "configure.ac").write_bytes(b"AC_INIT([x], [1])\r\nAC_OUTPUT\r\n")
    (tmp_path / "Makefile.am").write_bytes(b"SUBDIRS = src\r\n")
    (tmp_path / "m4" / "ax_x.m4").write_bytes(b"AC_DEFUN([AX_X], [:])\r\n")
    (tmp_path / "configure.in").write_bytes(b"AC_INIT\nAC_OUTPUT\n")
    scan = line_endings.scan_crlf_scripts(tmp_path)
    assert [(h.path, h.first_line) for h in scan.hits] == [
        ("Makefile.am", None),
        ("configure.ac", None),
        ("m4/ax_x.m4", None),
    ]


def test_a_configure_syntax_error_from_a_crlf_configure_ac_gets_the_hint(tmp_path):
    # libmodbus run-1 (2026-11-18), after `sed` over the scripts: autoconf copies the `\r` of a
    # CRLF configure.ac into the generated configure, which bash then cannot parse. The generated
    # configure itself has no CRLF in its head, so `configure` in the log points at configure.ac.
    (tmp_path / "configure.ac").write_bytes(b"AC_INIT([x], [1])\r\nAC_CHECK_HEADERS([ \\\r\n  a.h \\\r\n])\r\n")
    (tmp_path / "autogen.sh").write_bytes(LF_SHEBANG)
    scan = line_endings.scan_crlf_scripts(tmp_path)
    log = (
        "./configure: line 14962: syntax error near unexpected token "
        '`as_ac_Header=`printf "%s\\n" "ac_cv_header_$ac_header" | sed "$as_sed_sh"`\'\n'
    )
    command = "sed -i 's/\\r$//' autogen.sh && ./autogen.sh && ./configure && make"
    hint = line_endings.failure_hint("the build command", 2, log, scan, command)
    assert hint is not None
    assert hint.startswith("the build command exited 2; configure.ac has CRLF line endings")
    assert "Makefile.am" in hint and "m4" in hint
    # the same error with no CRLF autotools input in the tree is not blamed on line endings
    (tmp_path / "configure.ac").write_bytes(b"AC_INIT([x], [1])\n")
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "unit.sh").write_bytes(CRLF_SHEBANG)
    scan = line_endings.scan_crlf_scripts(tmp_path)
    assert line_endings.failure_hint("the build command", 2, log, scan, command) is None


def test_a_127_naming_no_crlf_script_singles_none_out(tmp_path):
    scan = line_endings.scan_crlf_scripts(_crlf_target(tmp_path))
    hint = line_endings.failure_hint("the build command", 127, "sh: 1: ninja: not found", scan, "ninja")
    assert hint is not None
    assert hint.startswith("the build command exited 127; the tree has 1 script(s) with CRLF line endings")
    assert "if the command runs one" in hint


# --- the early warning -----------------------------------------------------------------------------


def test_overlay_init_warns_about_a_crlf_checkout(tmp_path):
    target = _crlf_target(tmp_path / "target")
    meta = workspace_overlay.init_overlay(target, tmp_path / "workspace")
    assert meta["crlf_scripts"]["paths"] == ["tools/unit.sh"]
    (warning,) = meta["warnings"]
    assert warning.startswith("the target checkout has CRLF line endings")
    assert "tools/unit.sh (#!/bin/sh\\r)" in warning and "core.autocrlf false" in warning
    on_disk = json.loads((tmp_path / "workspace" / "overlay_meta.json").read_text(encoding="utf-8"))
    assert on_disk["warnings"] == meta["warnings"]


def test_overlay_init_is_silent_on_an_lf_checkout(tmp_path):
    target = tmp_path / "target"
    (target / "tools").mkdir(parents=True)
    (target / "tools" / "unit.sh").write_bytes(LF_SHEBANG)
    (target / "lib.c").write_bytes(b"int f(void) { return 0; }\n")
    meta = workspace_overlay.init_overlay(target, tmp_path / "workspace")
    assert meta["warnings"] == [] and meta["crlf_scripts"]["count"] == 0


# --- the hint at failure ---------------------------------------------------------------------------


def test_a_test_command_exiting_127_on_a_crlf_script_gets_the_hint(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    reports = tmp_path / "workspace" / "reports"
    reports.mkdir(parents=True)
    tree = _crlf_target(tmp_path / "scratch" / "tree")
    (tree / "unit_test").write_bytes(b"\x7fELF\x00")
    recipe = {"command": "make", "test_command": "tools/unit.sh more"}
    (tmp_path / "run-metadata.json").write_text(json.dumps({"build": recipe}))
    model = {
        "status": "ok",
        "entry_points": ["lib#f"],
        "functions": {"lib#f": {"name": "f", "signature": "int (const unsigned char *, unsigned long)"}},
        "units": {},
    }
    (reports / "phase0_model.json").write_text(json.dumps(model))
    units = {"unit_test": {"kind": "executable", "test": True, "objects": []}}
    capture = {"status": "ok", "scratch": {"tree": str(tree)}, "units": units, "compiles": []}
    (reports / "build_capture.json").write_text(json.dumps(capture))

    def sandboxed(argv, cwd, scratch, timeout, env):
        if argv[:2] == ["sh", "-c"]:
            return SimpleNamespace(
                returncode=127, timed_out=False, stdout="", stderr="sh: 1: tools/unit.sh: not found\n"
            )
        return SimpleNamespace(returncode=0, timed_out=False, stdout="", stderr="")

    monkeypatch.setattr(sh, "link_commands", lambda ev, t: {n: {"args": ["cc", "-o", n], "cwd": str(t)} for n in units})
    monkeypatch.setattr(sh, "defined_functions", lambda exe: {"f"})
    monkeypatch.setattr(sh, "_run", lambda argv, cwd, timeout: (0, ""))
    monkeypatch.setattr(sh, "_compile_wrappers", lambda cc, fl, plans, where, c, o, w: (True, plans, ""))
    monkeypatch.setattr(sh, "_sandboxed", sandboxed)
    monkeypatch.setattr(sh.shutil, "which", lambda name: None)
    assert sh.main(["record", "--scratch", str(tmp_path / "scratch")]) == 0
    report = json.loads((reports / "seed_harvest.json").read_text())
    hints = [w for w in report["warnings"] if "CRLF" in w]
    assert len(hints) == 1
    assert hints[0].startswith("the test command exited 127; tools/unit.sh has CRLF line endings (#!/bin/sh\\r)")
    assert not any("does not match its schema" in w for w in report["warnings"])


def test_a_failed_build_on_a_crlf_script_gets_the_hint(tmp_path, monkeypatch):
    target = _crlf_target(tmp_path / "target")
    recipe: dict = {
        "command": "tools/unit.sh",
        "workdir": ".",
        "packages": [],
        "env": {},
        "test_command": None,
        "install_command": None,
        "snapshot_extra": [],
        "origin": "user",
    }

    def run_sandboxed_shell(command, cwd, scratch, timeout, env_, wrap):
        return SimpleNamespace(returncode=127, timed_out=False, stdout="", stderr="sh: 1: tools/unit.sh: not found\n")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(bc, "host_machine", lambda: bc.SUPPORTED_ARCH)
    monkeypatch.setattr(bc, "load_recipe", lambda args: dict(recipe))
    monkeypatch.setattr(bc, "packages_missing", lambda pkgs: [])
    monkeypatch.setattr(bc, "job_count", lambda: 1)
    monkeypatch.setattr(bc, "run_sandboxed_shell", run_sandboxed_shell)
    args = argparse.Namespace(target=str(target), scratch=str(tmp_path / "scratch"), timeout=30)
    report, code = bc.capture(args)
    assert code == bc.EXIT_NEEDS_RECIPE
    assert report["diagnostics"]["crlf_scripts"]["paths"] == ["tools/unit.sh"]
    hints = [w for w in report["warnings"] if "CRLF" in w]
    assert len(hints) == 1 and hints[0].startswith("the build command exited 127; tools/unit.sh has CRLF")
    assert not bc.validate_report({**report, "status": bc.STATUS_NEEDS_RECIPE})


def test_a_build_failing_with_a_syntax_error_in_a_crlf_script_gets_the_hint(tmp_path, monkeypatch):
    # libmodbus run-1 (2026-11-18): rc 2 and dash's syntax error are the whole log.
    target = tmp_path / "target"
    target.mkdir()
    (target / "autogen.sh").write_bytes(b"#! /bin/sh\r\nif [ -f configure.ac ]; then\r\n  echo ok\r\nfi\r\n")
    recipe: dict = {
        "command": './autogen.sh && ./configure && make -j"$(nproc)"',
        "workdir": ".",
        "packages": [],
        "env": {},
        "test_command": None,
        "install_command": None,
        "snapshot_extra": [],
        "origin": "user",
    }

    def run_sandboxed_shell(command, cwd, scratch, timeout, env_, wrap):
        err = './autogen.sh: 22: Syntax error: end of file unexpected (expecting "then")\n'
        return SimpleNamespace(returncode=2, timed_out=False, stdout="", stderr=err)

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(bc, "host_machine", lambda: bc.SUPPORTED_ARCH)
    monkeypatch.setattr(bc, "load_recipe", lambda args: dict(recipe))
    monkeypatch.setattr(bc, "packages_missing", lambda pkgs: [])
    monkeypatch.setattr(bc, "job_count", lambda: 1)
    monkeypatch.setattr(bc, "run_sandboxed_shell", run_sandboxed_shell)
    args = argparse.Namespace(target=str(target), scratch=str(tmp_path / "scratch"), timeout=30)
    report, code = bc.capture(args)
    assert code == bc.EXIT_NEEDS_RECIPE
    assert report["diagnostics"]["crlf_scripts"]["paths"] == ["autogen.sh"]
    hints = [w for w in report["warnings"] if "CRLF" in w]
    assert len(hints) == 1 and hints[0].startswith("the build command exited 2; autogen.sh has CRLF")
    assert not bc.validate_report({**report, "status": bc.STATUS_NEEDS_RECIPE})
