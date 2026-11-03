"""Tests for workspace_overlay.py parent reverify scoping (Item 6)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import workspace_overlay as WO


def test_parent_reverify_scoped_by_function_and_unique_binary(tmp_path, monkeypatch):
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True)
    overlay_dir = tmp_path / "overlay"
    overlay_dir.mkdir(parents=True)
    work_dir = overlay_dir / "work"
    work_dir.mkdir(parents=True)
    harnesses_dir = overlay_dir / "harnesses"
    harnesses_dir.mkdir(parents=True)
    (harnesses_dir / "harness_parser.c").write_text("int main() { return 0; }\n", encoding="utf-8")
    (work_dir / "parser.c").write_text("int parse_magic() { return 1; }\nint parse_body() { return 2; }\n", encoding="utf-8")

    captured_cmds: list[list[str]] = []

    def fake_subprocess_run(cmd, cwd=None, capture_output=None, text=None, encoding=None, errors=None):
        captured_cmds.append(list(cmd))
        out_json_idx = cmd.index("--out-json") + 1
        json_path = Path(cmd[out_json_idx])
        json_path.parent.mkdir(parents=True, exist_ok=True)
        if any("run_wp_function.py" in str(c) for c in cmd):
            json_path.write_text(json.dumps({"status": "all_proven"}), encoding="utf-8")
        else:
            json_path.write_text(json.dumps({"status": "passed_dynamic_oracle"}), encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(WO.subprocess, "run", fake_subprocess_run)

    # 1. Prover reverify with function="parse_magic"
    ok1, reason1 = WO._run_parent_reverify(
        run_dir=run_dir,
        agent_id="prover-magic",
        role="prover",
        overlay_dir=overlay_dir,
        c_file="parser.c",
        function="parse_magic",
        module="parser",
        sources=["parser.c"],
        cppflags="-I.",
    )
    assert ok1 is True
    guard_cmds = [c for c in captured_cmds if any("run_eacsl_fuzz.py" in str(x) for x in c)]
    cmd1 = guard_cmds[0]
    assert "--functions" in cmd1
    fn_idx = cmd1.index("--functions") + 1
    assert cmd1[fn_idx] == "parse_magic"

    out_bin_idx1 = cmd1.index("--out-bin") + 1
    bin_path1 = Path(cmd1[out_bin_idx1])
    assert bin_path1.name == "guard_parser_parse_magic"

    # 2. Prover reverify for a different function in same module: function="parse_body"
    ok2, reason2 = WO._run_parent_reverify(
        run_dir=run_dir,
        agent_id="prover-body",
        role="prover",
        overlay_dir=overlay_dir,
        c_file="parser.c",
        function="parse_body",
        module="parser",
        sources=["parser.c"],
        cppflags="-I.",
    )
    assert ok2 is True
    guard_cmds = [c for c in captured_cmds if any("run_eacsl_fuzz.py" in str(x) for x in c)]
    cmd2 = guard_cmds[1]
    assert "--functions" in cmd2
    assert cmd2[cmd2.index("--functions") + 1] == "parse_body"

    out_bin_idx2 = cmd2.index("--out-bin") + 1
    bin_path2 = Path(cmd2[out_bin_idx2])
    assert bin_path2.name == "guard_parser_parse_body"
    # Binaries and parent directory tags must not collide
    assert bin_path1 != bin_path2
    assert bin_path1.parent != bin_path2.parent

    # 3. Architect reverify where function is None
    ok3, reason3 = WO._run_parent_reverify(
        run_dir=run_dir,
        agent_id="arch-parser",
        role="architect",
        overlay_dir=overlay_dir,
        c_file=None,
        function=None,
        module="parser",
        sources=["parser.c"],
        cppflags="-I.",
    )
    assert ok3 is True
    guard_cmds = [c for c in captured_cmds if any("run_eacsl_fuzz.py" in str(x) for x in c)]
    cmd3 = guard_cmds[2]
    assert "--functions" not in cmd3
    bin_path3 = Path(cmd3[cmd3.index("--out-bin") + 1])
    assert bin_path3.name == "guard_parser"
    assert bin_path3 != bin_path1
    assert bin_path3 != bin_path2
