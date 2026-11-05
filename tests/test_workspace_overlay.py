"""Tests for workspace_overlay.py parent reverify scoping (Item 6)."""

from __future__ import annotations

import json
import os
import posixpath
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import cache
import pipeline_make
import workspace_overlay as WO
from conftest import ROOT
from eacsl_toolchain import build_eacsl_flag_sets


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
    (work_dir / "parser.c").write_text(
        "int parse_magic() { return 1; }\nint parse_body() { return 2; }\n", encoding="utf-8"
    )

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
    out_bin_idx3 = cmd3.index("--out-bin") + 1
    bin_path3 = Path(cmd3[out_bin_idx3])
    assert bin_path3.name == "guard_parser"
    assert bin_path3 != bin_path1
    assert bin_path3 != bin_path2


def test_splice_prover_changes_contract_only_and_has_function_contract():
    from acsl_ast import has_function_contract, splice_prover_changes

    base_c = """\
static int helper(int x) {
    int i = 0;
    while (i < x) {
        i++;
    }
    return i;
}
"""
    agent_c = """\
/*@ requires x >= 0;
  @ assigns \\nothing;
  @ ensures \\result == x;
  @*/
static int helper(int x) {
    int i = 0;
    /*@ loop invariant 0 <= i <= x;
      @ loop assigns i;
      @*/
    while (i < x) {
        i++;
    }
    return i;
}
"""
    assert has_function_contract(base_c, "helper") is False
    assert has_function_contract(agent_c, "helper") is True

    contract_spliced = splice_prover_changes(
        base_work_text=base_c,
        agent_work_text=agent_c,
        current_work_text=base_c,
        function_name="helper",
        is_header=False,
        path="helper.c",
        contract_only=True,
    )
    assert "requires x >= 0;" in contract_spliced
    assert "assigns \\nothing;" in contract_spliced
    assert "loop invariant" not in contract_spliced


def test_parent_reverify_allow_partial_wp(tmp_path, monkeypatch):
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True)
    overlay_dir = tmp_path / "overlay"
    work_dir = overlay_dir / "work"
    work_dir.mkdir(parents=True)
    (work_dir / "parser.c").write_text("int helper(int x) { return x; }\n", encoding="utf-8")

    partial_report: dict[str, object] = {
        "status": "unproven_goals_remain",
        "soundness": {"ok": True},
        "unproven_by_bucket": {"step_a_assigns": [], "step_b_loop_invariant": [{"line": 5}]},
    }

    def fake_run(cmd, cwd=None, capture_output=None, text=None, encoding=None, errors=None):
        json_path = Path(cmd[cmd.index("--out-json") + 1])
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(partial_report), encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(WO.subprocess, "run", fake_run)

    # Without allow_partial_wp, unproven_goals_remain is rejected
    ok_strict, _ = WO._run_parent_reverify(
        run_dir=run_dir,
        agent_id="prove-helper",
        role="prover",
        overlay_dir=overlay_dir,
        c_file="parser.c",
        function="helper",
        module=None,
        sources=None,
        cppflags="-I.",
        allow_partial_wp=False,
    )
    assert ok_strict is False

    # With allow_partial_wp=True and step_a_assigns == [] + soundness.ok == True, it passes
    ok_partial, _ = WO._run_parent_reverify(
        run_dir=run_dir,
        agent_id="prove-helper",
        role="prover",
        overlay_dir=overlay_dir,
        c_file="parser.c",
        function="helper",
        module=None,
        sources=None,
        cppflags="-I.",
        allow_partial_wp=True,
    )
    assert ok_partial is True

    # If step_a_assigns has unproven goals, allow_partial_wp rejects it
    partial_report["unproven_by_bucket"] = {"step_a_assigns": [{"line": 2}], "step_b_loop_invariant": [{"line": 5}]}
    ok_bad_assigns, _ = WO._run_parent_reverify(
        run_dir=run_dir,
        agent_id="prove-helper",
        role="prover",
        overlay_dir=overlay_dir,
        c_file="parser.c",
        function="helper",
        module=None,
        sources=None,
        cppflags="-I.",
        allow_partial_wp=True,
    )
    assert ok_bad_assigns is False


def test_normalize_status_maps_partially_proven_to_valid():
    from framac_common import STATUS_VALID, normalize_status

    assert normalize_status("Partially proven") == STATUS_VALID


def test_wp_diagnostics_and_tail_retry_and_macro_loop_filter(tmp_path, monkeypatch):
    import run_wp_function as RWF

    # 1. Why3 MemAddr.addr vs int diagnostic hint + pointer-difference equality hint
    res_unproven = {
        "status": "unproven_goals_remain",
        "soundness": {"ok": True, "tier_a_aborts": [], "tier_b_unsound": []},
        "unproven_by_bucket": {
            "step_a_assigns": [],
            "step_b_loop_invariant": [
                {"kind": "loop_invariant", "annotation": "buf_end - buf == 0 ==> buf == buf_end"}
            ],
            "step_c_rte_obligation": [],
            "step_c_caller_precondition": [],
            "step_c_contract_postcondition": [],
        },
        "unproven_goals": [{"kind": "loop_invariant", "annotation": "buf_end - buf == 0 ==> buf == buf_end"}],
        "wp_why3_memaddr_limitation": True,
        "wp_macro_loop_limitation": True,
    }
    hints = RWF.derive_wp_diagnostic_hints(
        res_unproven,
        "[Why3 Error] Type mismatch between frama_c_wp.memaddr.MemAddr.addr and int",
    )
    assert any("MemAddr.addr and int" in h and "unreachable_branch" in h for h in hints)
    assert any("Pointer-difference equality bridge" in h for h in hints)
    assert any("file-scope `#define` macro" in h for h in hints)

    # 2. Macro-loop line detection + filtering Missing assigns clause on macro-loop line
    c_file = tmp_path / "macro_test.c"
    c_file.write_text(
        "#define LOOP_MAC(x) do { while (1) { if (x) break; } } while (0)\n"
        "int caller(int x) {\n"
        "    LOOP_MAC(x);\n"
        "    return x;\n"
        "}\n",
        encoding="utf-8",
    )
    macro_lines = RWF._find_macro_loop_lines(c_file, "caller")
    assert 3 in macro_lines

    # 3. Automatic focused tail retry when >=90% VCs are proven with a small timeout tail
    out_dir = tmp_path / "wp_out"
    calls: list[list[str]] = []

    def fake_frama_c_run(cmd, capture_output=None, text=None, encoding=None, errors=None, timeout=None):
        calls.append(list(cmd))
        csv_idx = cmd.index("-report-csv") + 1
        csv_path = Path(cmd[csv_idx])
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        is_tail = "_tail.csv" in csv_path.name
        rows = [
            "directory\tfile\tfunction\tline\tkind\tstatus\tproperty",
            f".\tmacro_test.c\tcaller\t2\tensures\t{'Partially proven' if is_tail else 'Unknown'}\tp1",
        ]
        for i in range(5):
            rows.append(f".\tmacro_test.c\tcaller\t{i + 4}\tassert\tPartially proven\tg{i}")
        csv_path.write_text("\n".join(rows) + "\n", encoding="utf-8")
        stdout = (
            "[wp] macro_test.c:3: Warning: Missing assigns clause (assigns 'everything' instead)\n"
            f"[wp] Proved goals:   {37 if is_tail else 36} / 37\n"
            f"[wp]   Timeout:           {0 if is_tail else 1}\n"
        )
        return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(RWF.subprocess, "run", fake_frama_c_run)
    wp_res = RWF.run_wp_on_function(
        c_file=c_file,
        fn_name="caller",
        out_dir=out_dir,
        timeout=15,
        wp_steps=0,
        retry_bitwise=False,
        retry_tail=True,
        cache_dir="off",
    )
    assert len(calls) == 2
    assert "-wp-steps" not in calls[1]
    assert wp_res["status"] == "all_proven"
    assert wp_res["soundness"]["ok"] is True
    assert wp_res["assigns_vcs_proven"] is True
    assert len(wp_res["soundness"].get("macro_loop_warnings") or []) == 1
    assert wp_res.get("tail_retry", {}).get("triggered") is True
    assert wp_res["tail_retry"]["timeout"] == 45
    assert wp_res["tail_retry"]["wp_steps"] == 0

    # 4. Prover WP flag propagation into parent re-check / sweep & partial-merge assigns gate
    run_dir = tmp_path / "flag_run"
    agent_scratch = run_dir / "agents" / "prove-get_token_to_eol-2" / "scratch"
    agent_scratch.mkdir(parents=True, exist_ok=True)
    (agent_scratch / "wp_get_token_to_eol.json").write_text(
        json.dumps(
            {
                "status": "all_proven",
                "function": "get_token_to_eol",
                "wp_model": "Typed+int",
                "soundness": {
                    "ok": True,
                    "reduced_checks": [
                        "-warn-unsigned-overflow / -warn-unsigned-downcast OFF",
                        "-warn-invalid-pointer OFF",
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    flags = WO.infer_prover_wp_flags(
        run_dir,
        agent_id="prove-get_token_to_eol-2",
        c_file="picohttpparser.c",
        function="get_token_to_eol",
    )
    assert flags == ["--no-warn-unsigned", "--no-warn-invalid-pointer", "--wp-model", "Typed+int"]

    # Default flags when no reduced checks were used
    assert WO.infer_prover_wp_flags(run_dir, function="other_fn") == ["--no-warn-unsigned-downcast"]

    # Partial merge assigns gate accepts legacy 'Partially proven' assigns and rejects 'Unknown' assigns
    assert WO.assigns_verified_for_partial_merge(
        {
            "unproven_by_bucket": {
                "step_a_assigns": [{"line": 447, "status": "Partially proven", "annotation": "assigns *p"}]
            }
        }
    )
    assert not WO.assigns_verified_for_partial_merge(
        {"unproven_by_bucket": {"step_a_assigns": [{"line": 447, "status": "Unknown", "annotation": "assigns *p"}]}}
    )
    assert not WO.assigns_verified_for_partial_merge({"assigns_vcs_proven": False, "unproven_by_bucket": {}})


def test_prepare_agent_scales_max_retries_by_profile(tmp_path):
    target = tmp_path / "target"
    src = target / "src"
    src.mkdir(parents=True)
    (src / "m.c").write_text("int f(int x) { return x; }\n", encoding="utf-8")

    for profile, expected_retries, expected_wall in (("quick", 2, 300), ("standard", 4, 900), ("deep", 6, 1800)):
        run_dir = tmp_path / f"run_{profile}"
        WO.init_overlay(target, run_dir / "workspace")
        (run_dir / "run-metadata.json").write_text(json.dumps({"profile": profile}), encoding="utf-8")
        WO.prepare_agent(
            run_dir=run_dir,
            agent_id=f"prove-f-{profile}",
            role="prover",
            c_file="src/m.c",
            function="f",
        )
        budget = json.loads(
            (run_dir / "agents" / f"prove-f-{profile}" / "scratch" / ".prover_budget.json").read_text(encoding="utf-8")
        )
        assert budget["max_retries"] == expected_retries
        assert budget["max_wp_invocations"] == expected_retries + 2
        assert budget["max_wall_clock_s"] == expected_wall


# ---------------------------------------------------------------------------
# An agent's oracles read its scratch headers (the layout is QCBOR's)
# ---------------------------------------------------------------------------

NESTED_FLAGS = "-I. -Iworkspace/work/inc/nest -Iworkspace/work/inc -Iworkspace/work/src"
NESTED_AGENT = "prove-nest-add"
NESTED_SCRATCH = f"agents/{NESTED_AGENT}/scratch/work"
NESTED_API_H = "#ifndef NEST_API_H\n#define NEST_API_H\nint nest_add(int a);\n#endif\n"
NESTED_HARNESS = """#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "api.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    int a = 0;
    memcpy(&a, data, size < sizeof a ? size : sizeof a);
    (void)nest_add(a);
    return 0;
}
"""


def _nested_module(tmp_path: Path, cppflags: str = NESTED_FLAGS) -> Path:
    """`src/api.c` includes "nest/api.h", which names no file directly under the tree's root."""
    target = tmp_path / "target"
    (target / "inc" / "nest").mkdir(parents=True)
    (target / "src").mkdir()
    (target / "inc" / "api.h").write_text('#include "nest/api.h"\n', encoding="utf-8")
    (target / "inc" / "nest" / "api.h").write_text(NESTED_API_H, encoding="utf-8")
    (target / "inc" / "nest" / "cfg.h").write_text("#ifndef NEST_CFG_H\n#define NEST_CFG_H\n#endif\n", encoding="utf-8")
    (target / "src" / "api.c").write_text(
        '#include "nest/api.h"\nint nest_add(int a) { return a; }\n', encoding="utf-8"
    )
    run_dir = tmp_path / "run"
    WO.init_overlay(target, run_dir / "workspace")
    harnesses = run_dir / "workspace" / "harnesses"
    (harnesses / "harness_nest.c").write_text(NESTED_HARNESS, encoding="utf-8")
    (harnesses / "harness_nest.json").write_text(
        json.dumps(
            {"sources": ["workspace/work/src/api.c"], "cppflags": cppflags, "ldflags": "", "header": "inc/nest/api.h"}
        ),
        encoding="utf-8",
    )
    return run_dir


def _prepare_nested(run_dir: Path, role: str = "prover", agent_id: str = NESTED_AGENT) -> tuple[dict, str]:
    prep = WO.prepare_agent(
        run_dir=run_dir,
        agent_id=agent_id,
        role=role,
        module="nest",
        function="nest_add" if role == "prover" else None,
        c_file="src/api.c" if role == "prover" else None,
        header_file="inc/nest/api.h",
    )
    return prep, (run_dir / prep["brief_file"]).read_text(encoding="utf-8")


def _oracle_argv(brief: str, script: str) -> list[str]:
    """The brief's command that runs `script`, as a shell would split it."""
    lines = [line.strip() for line in brief.splitlines()]
    return shlex.split(
        next(line for line in lines if line.startswith(f"python3 /opt/framac-pipeline/scripts/{script}"))
    )


def _oracle_cppflags(argv: list[str]) -> str:
    return next(word[len("--cppflags=") :] for word in argv if word.startswith("--cppflags="))


def _argv_values(argv: list[str], option: str) -> list[str]:
    start = argv.index(option) + 1
    end = next((i for i in range(start, len(argv)) if argv[i].startswith("--")), len(argv))
    return argv[start:end]


def _find_include(name: str, includer_dir: str, cppflags: str, run_dir: Path) -> str | None:
    """Where gcc finds `#include "name"`: the includer's directory, then -iquote, -I, -isystem, -idirafter."""
    dirs: dict[str, list[str]] = {"-iquote": [], "-I": [], "-isystem": [], "-idirafter": []}
    words = shlex.split(cppflags)
    i = 0
    while i < len(words):
        for option, found in dirs.items():
            if words[i] == option:
                found.append(words[i + 1])
                i += 1
            elif words[i].startswith(option):
                found.append(words[i][len(option) :])
        i += 1
    for directory in [includer_dir, *dirs["-iquote"], *dirs["-I"], *dirs["-isystem"], *dirs["-idirafter"]]:
        if (run_dir / directory / name).is_file():
            return posixpath.normpath(f"{directory}/{name}")
    return None


def test_prover_oracle_commands_resolve_nested_headers_in_the_scratch_copy(tmp_path):
    run_dir = _nested_module(tmp_path)
    src_dir = f"{NESTED_SCRATCH}/src"
    prep, brief = _prepare_nested(run_dir)

    # Why this module: the flags the brief used to pass resolve these names to the shared tree.
    old_flags = f"-I{NESTED_SCRATCH} {NESTED_FLAGS}"
    assert _find_include("nest/api.h", src_dir, old_flags, run_dir) == "workspace/work/inc/nest/api.h"
    assert _find_include("api.h", "workspace/harnesses", old_flags, run_dir) == "workspace/work/inc/nest/api.h"

    expected = (
        f"-I{NESTED_SCRATCH} -I. -I{NESTED_SCRATCH}/inc/nest -Iworkspace/work/inc/nest "
        f"-I{NESTED_SCRATCH}/inc -Iworkspace/work/inc -I{NESTED_SCRATCH}/src -Iworkspace/work/src"
    )
    guardrail = _oracle_argv(brief, "run_eacsl_fuzz.py")
    wp = _oracle_argv(brief, "run_wp_function.py")
    assert _argv_values(guardrail, "--sources") == [f"{src_dir}/api.c", "workspace/harnesses/harness_nest.c"]
    assert _argv_values(wp, "--file") == [f"{src_dir}/api.c"]
    for argv in (guardrail, wp):
        flags = _oracle_cppflags(argv)
        assert flags == expected
        assert _find_include("nest/api.h", src_dir, flags, run_dir) == f"{NESTED_SCRATCH}/inc/nest/api.h"
        # The directory that wins is the one that wins on the merged tree: inc/nest, not inc.
        assert _find_include("api.h", "workspace/harnesses", flags, run_dir) == f"{NESTED_SCRATCH}/inc/nest/api.h"
        assert _find_include("api.h", "workspace/harnesses", NESTED_FLAGS, run_dir) == "workspace/work/inc/nest/api.h"

    # The parent still re-checks the merged tree with the module's own flags.
    assert prep["merge_command"].endswith(f"--cppflags='{NESTED_FLAGS}'")


def test_architect_guardrail_resolves_nested_headers_in_the_scratch_copy(tmp_path):
    run_dir = _nested_module(tmp_path)
    prep, brief = _prepare_nested(run_dir, role="architect", agent_id="arch-nest")
    flags = _oracle_cppflags(_oracle_argv(brief, "run_eacsl_fuzz.py"))
    assert _find_include("api.h", "workspace/harnesses", flags, run_dir) == (
        "agents/arch-nest/scratch/work/inc/nest/api.h"
    )
    assert prep["merge_command"].endswith(f"--cppflags='{NESTED_FLAGS}'")


def test_shared_tree_commands_keep_the_module_flags(tmp_path):
    run_dir = _nested_module(tmp_path)
    for role, agent_id in (("breaker", "break-nest"), ("verifier", "verify-nest")):
        _, brief = _prepare_nested(run_dir, role=role, agent_id=agent_id)
        assert set(re.findall(r"--cppflags='([^']*)'", brief)) == {NESTED_FLAGS}


def test_prepare_agent_explicit_cppflags_also_get_scratch_twins(tmp_path):
    run_dir = _nested_module(tmp_path)
    prep = WO.prepare_agent(
        run_dir=run_dir,
        agent_id=NESTED_AGENT,
        role="prover",
        module="nest",
        function="nest_add",
        c_file="src/api.c",
        cppflags="-Iworkspace/work/inc",
    )
    brief = (run_dir / prep["brief_file"]).read_text(encoding="utf-8")
    assert _oracle_cppflags(_oracle_argv(brief, "run_wp_function.py")) == (
        f"-I{NESTED_SCRATCH} -I{NESTED_SCRATCH}/inc -Iworkspace/work/inc"
    )


@pytest.mark.parametrize(
    "module_flags, expected",
    [
        # Layouts from real runs.
        ("-I. -Iworkspace/work", f"-I{NESTED_SCRATCH} -I. -Iworkspace/work"),
        (
            "-I. -Iworkspace/work/inc -include workspace/harnesses/compat.h",
            f"-I{NESTED_SCRATCH} -I. -I{NESTED_SCRATCH}/inc -Iworkspace/work/inc -include workspace/harnesses/compat.h",
        ),
        (
            "-Iworkspace/stubs -include cfg.h -DDEBUG -I/framac-run/workspace/work/inc "
            "-I/framac-run/workspace/work/src/../inc -I/usr/include -Iworkspace/work/inc -Iworkspace/work/src/../inc",
            f"-I{NESTED_SCRATCH} -Iworkspace/stubs -include cfg.h -DDEBUG -I{NESTED_SCRATCH}/inc "
            "-I/framac-run/workspace/work/inc -I/framac-run/workspace/work/src/../inc -I/usr/include "
            "-Iworkspace/work/inc -Iworkspace/work/src/../inc",
        ),
        # Every spelling the flag allowlist accepts.
        ("-I workspace/work/inc", f"-I{NESTED_SCRATCH} -I{NESTED_SCRATCH}/inc -I workspace/work/inc"),
        ("-iquote workspace/work/inc", f"-I{NESTED_SCRATCH} -iquote{NESTED_SCRATCH}/inc -iquote workspace/work/inc"),
        ("-iquoteworkspace/work/inc", f"-I{NESTED_SCRATCH} -iquote{NESTED_SCRATCH}/inc -iquoteworkspace/work/inc"),
        ("-isystem workspace/work/inc", f"-I{NESTED_SCRATCH} -isystem{NESTED_SCRATCH}/inc -isystem workspace/work/inc"),
        (
            "-idirafter workspace/work/inc",
            f"-I{NESTED_SCRATCH} -idirafter{NESTED_SCRATCH}/inc -idirafter workspace/work/inc",
        ),
        ("-include workspace/work/inc/nest/cfg.h", f"-I{NESTED_SCRATCH} -include {NESTED_SCRATCH}/inc/nest/cfg.h"),
        ("-imacros workspace/work/inc/nest/cfg.h", f"-I{NESTED_SCRATCH} -imacros {NESTED_SCRATCH}/inc/nest/cfg.h"),
    ],
)
def test_scratch_flags_render_and_stay_inside_the_flag_allowlist(tmp_path, module_flags, expected):
    run_dir = _nested_module(tmp_path, cppflags=module_flags)
    _, brief = _prepare_nested(run_dir)
    flags = _oracle_cppflags(_oracle_argv(brief, "run_wp_function.py"))
    assert flags == expected

    assert pipeline_make.check_flags(shlex.split(module_flags)) == []
    assert pipeline_make.check_flags(shlex.split(flags)) == []
    # e-acsl-gcc re-splits what it is given: the guardrail must accept the scratch flags too.
    assert NESTED_SCRATCH in build_eacsl_flag_sets(flags)["frontend"]


def test_scratch_flags_keep_a_define_the_brief_quotes(tmp_path):
    module_flags = r"""-DNAME=\"x\" -DTITLE="a b" -Iworkspace/work/inc"""
    run_dir = _nested_module(tmp_path, cppflags=module_flags)
    _, brief = _prepare_nested(run_dir)
    assert _oracle_cppflags(_oracle_argv(brief, "run_wp_function.py")) == (
        f'-I{NESTED_SCRATCH} -DNAME=\\"x\\" -DTITLE="a b" -I{NESTED_SCRATCH}/inc -Iworkspace/work/inc'
    )


def _gcc_deps(cppflags: str, source: str, run_dir: Path) -> list[str]:
    proc = subprocess.run(
        ["gcc", "-M", *shlex.split(cppflags), source], cwd=run_dir, capture_output=True, text=True, encoding="utf-8"
    )
    assert proc.returncode == 0, proc.stderr
    return cache.parse_make_deps(proc.stdout)


@pytest.mark.skipif(shutil.which("gcc") is None, reason="needs gcc")
def test_rendered_oracle_commands_read_the_scratch_headers_under_gcc(tmp_path):
    # With a config header forced in: its include guard would hide a second copy of it.
    run_dir = _nested_module(tmp_path, cppflags=f"{NESTED_FLAGS} -include workspace/work/inc/nest/cfg.h")
    _, brief = _prepare_nested(run_dir)
    api_h = f"{NESTED_SCRATCH}/inc/nest/api.h"
    cfg_h = f"{NESTED_SCRATCH}/inc/nest/cfg.h"

    guardrail = _oracle_argv(brief, "run_eacsl_fuzz.py")
    wp = _oracle_argv(brief, "run_wp_function.py")
    runs = [(_oracle_cppflags(wp), source) for source in _argv_values(wp, "--file")]
    runs += [(_oracle_cppflags(guardrail), source) for source in _argv_values(guardrail, "--sources")]
    assert len(runs) == 3
    for flags, source in runs:
        deps = _gcc_deps(flags, source, run_dir)
        assert api_h in deps and cfg_h in deps, deps
        assert not [dep for dep in deps if dep.startswith("workspace/work/")], deps

    # The flags the brief used to pass read the shared headers of this module.
    old_flags = f"-I{NESTED_SCRATCH} {NESTED_FLAGS} -include workspace/work/inc/nest/cfg.h"
    deps = _gcc_deps(old_flags, f"{NESTED_SCRATCH}/src/api.c", run_dir)
    assert "workspace/work/inc/nest/api.h" in deps and api_h not in deps
    assert "workspace/work/inc/nest/cfg.h" in deps and cfg_h not in deps


def _write_scratch_contract(run_dir: Path, contract: str) -> None:
    """A contract in the prover's scratch header only: the shared header stays without it."""
    header = run_dir / NESTED_SCRATCH / "inc" / "nest" / "api.h"
    header.write_text(
        NESTED_API_H.replace("int nest_add(int a);", f"{contract}\nint nest_add(int a);"), encoding="utf-8"
    )
    assert (run_dir / "workspace" / "work" / "inc" / "nest" / "api.h").read_text(encoding="utf-8") == NESTED_API_H


def _run_oracle(argv: list[str], run_dir: Path, cppflags: str | None = None) -> dict:
    """Run a rendered brief command from the run directory, with this checkout's scripts."""
    script = ROOT / "scripts" / Path(argv[1]).name
    words = [f"--cppflags={cppflags}" if cppflags is not None and w.startswith("--cppflags=") else w for w in argv[2:]]
    out_json = run_dir / words[words.index("--out-json") + 1]
    if out_json.exists():
        out_json.unlink()
    proc = subprocess.run(
        [sys.executable, str(script), *words],
        cwd=run_dir,
        env={**os.environ, "FRAMAC_CACHE": "off"},
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
    )
    assert out_json.is_file(), proc.stderr or proc.stdout
    return json.loads(out_json.read_text(encoding="utf-8"))


@pytest.mark.skipif(shutil.which("frama-c") is None, reason="needs Frama-C")
def test_a_scratch_contract_is_seen_by_the_provers_own_wp_run(tmp_path):
    run_dir = _nested_module(tmp_path)
    _, brief = _prepare_nested(run_dir)
    wp = _oracle_argv(brief, "run_wp_function.py")

    # False for every input: a clean report would mean WP never saw it, as with the old flags.
    _write_scratch_contract(run_dir, "/*@ assigns \\nothing;\n    ensures only_in_scratch: \\result == a + 1; */")
    report = _run_oracle(wp, run_dir)
    assert report["status"] == "unproven_goals_remain", report.get("wp_log_tail")
    assert ["only_in_scratch" in goal["annotation"] for goal in report["unproven_goals"]] == [True]
    old_report = _run_oracle(wp, run_dir, cppflags=f"-I{NESTED_SCRATCH} {NESTED_FLAGS}")
    assert old_report["status"] == "all_proven"

    _write_scratch_contract(run_dir, "/*@ assigns \\nothing;\n    ensures only_in_scratch: \\result == a; */")
    report = _run_oracle(wp, run_dir)
    assert report["status"] == "all_proven", report.get("wp_log_tail")
    assert report["total_goals"] > old_report["total_goals"]


@pytest.mark.skipif(shutil.which("frama-c") is None or shutil.which("clang") is None, reason="needs E-ACSL")
def test_a_scratch_contract_is_seen_by_the_provers_own_guardrail(tmp_path):
    run_dir = _nested_module(tmp_path)
    (run_dir / "workspace" / "corpus" / "nest").mkdir(parents=True)
    _, brief = _prepare_nested(run_dir)
    guardrail = _oracle_argv(brief, "run_eacsl_fuzz.py")

    # False for every input: it passes only if the guardrail never sees it, as with the old flags.
    _write_scratch_contract(run_dir, "/*@ ensures only_in_scratch: \\result == a + 1; */")
    assert _run_oracle(guardrail, run_dir)["status"] == "rejected_overconstrained"
    old_report = _run_oracle(guardrail, run_dir, cppflags=f"-I{NESTED_SCRATCH} {NESTED_FLAGS}")
    assert old_report["status"] == "passed_dynamic_oracle"


# ---------------------------------------------------------------------------
# A sidecar `header` is the name the harness includes, not a path in the work tree
# ---------------------------------------------------------------------------

UMBRELLA_FLAGS = "-I. -Iworkspace/work/inc -Iworkspace/work/inc/nest -Iworkspace/work/src"
PROTO_WITH_CONTRACT = "#ifndef NEST_API_H\n#define NEST_API_H\n/*@ requires a >= 0; */\nint nest_add(int a);\n#endif\n"


def _bare_header_module(tmp_path: Path, cppflags: str) -> Path:
    run_dir = _nested_module(tmp_path, cppflags)
    sidecar = run_dir / "workspace" / "harnesses" / "harness_nest.json"
    meta = json.loads(sidecar.read_text(encoding="utf-8"))
    meta["header"] = "api.h"
    sidecar.write_text(json.dumps(meta), encoding="utf-8")
    return run_dir


def _prepare_bare(run_dir: Path, **kwargs) -> dict:
    return WO.prepare_agent(
        run_dir=run_dir,
        agent_id=NESTED_AGENT,
        role="prover",
        module="nest",
        function="nest_add",
        c_file="src/api.c",
        **kwargs,
    )


# Flags where the include name finds the nested header directly, and where it finds the umbrella
# `inc/api.h` that only includes it (QCBOR: `qcbor.h` versus `inc/qcbor/qcbor_main_decode.h`).
@pytest.mark.parametrize("flags", [NESTED_FLAGS, UMBRELLA_FLAGS])
def test_bare_sidecar_header_resolves_to_the_declaring_tree_file(tmp_path, flags):
    run_dir = _bare_header_module(tmp_path, flags)
    prep = _prepare_bare(run_dir)
    assert prep["header"] == "inc/nest/api.h"
    assert (run_dir / "workspace" / "work" / prep["header"]).is_file()
    assert "--header inc/nest/api.h" in prep["merge_command"]
    brief = (run_dir / prep["brief_file"]).read_text(encoding="utf-8")
    assert f"{NESTED_SCRATCH}/inc/nest/api.h" in brief or "inc/nest/api.h" in brief
    assert f"{NESTED_SCRATCH}/api.h" not in brief
    assert (run_dir / NESTED_SCRATCH / prep["header"]).is_file()


def test_bare_header_enrich_batch_entry_uses_the_tree_file(tmp_path):
    run_dir = _bare_header_module(tmp_path, UMBRELLA_FLAGS)
    _prepare_bare(run_dir)
    item = WO._enrich_batch_entry(
        run_dir,
        run_dir / "workspace",
        {"agent_id": NESTED_AGENT, "role": "prover", "module": "nest", "file": "src/api.c", "function": "nest_add"},
        None,
        None,
        None,
        None,
        "",
    )
    assert item["header_file"] == "inc/nest/api.h"


@pytest.mark.parametrize("flags", [NESTED_FLAGS, UMBRELLA_FLAGS])
@pytest.mark.parametrize("header_arg", ["api.h", None])
def test_prover_contract_in_nested_header_merges(tmp_path, flags, header_arg):
    run_dir = _bare_header_module(tmp_path, flags)
    _prepare_bare(run_dir)
    (run_dir / NESTED_SCRATCH / "inc" / "nest" / "api.h").write_text(PROTO_WITH_CONTRACT, encoding="utf-8")
    res = WO.merge_agent_overlay(
        run_dir=run_dir,
        agent_id=NESTED_AGENT,
        role="prover",
        c_file="src/api.c",
        function="nest_add",
        header_file=header_arg,
        module="nest",
        cppflags=flags,
        verify_hook=lambda: (True, ""),
    )
    assert res["ok"]
    merged = (run_dir / "workspace" / "work" / "inc" / "nest" / "api.h").read_text(encoding="utf-8")
    assert "requires a >= 0" in merged


def test_prover_edit_outside_function_scope_is_still_rejected(tmp_path):
    run_dir = _bare_header_module(tmp_path, UMBRELLA_FLAGS)
    _prepare_bare(run_dir)
    scratch = run_dir / NESTED_SCRATCH
    (scratch / "inc" / "nest" / "api.h").write_text(PROTO_WITH_CONTRACT, encoding="utf-8")
    (scratch / "inc" / "nest" / "cfg.h").write_text(
        "#ifndef NEST_CFG_H\n#define NEST_CFG_H\n/*@ predicate p = \true; */\n#endif\n", encoding="utf-8"
    )
    with pytest.raises(WO.ScopeViolationError, match="inc/nest/cfg.h"):
        WO.merge_agent_overlay(
            run_dir=run_dir,
            agent_id=NESTED_AGENT,
            role="prover",
            c_file="src/api.c",
            function="nest_add",
            header_file="api.h",
            module="nest",
            cppflags=UMBRELLA_FLAGS,
            verify_hook=lambda: (True, ""),
        )
    # The umbrella header is not in the prover's scope either.
    (scratch / "inc" / "nest" / "cfg.h").write_text(
        "#ifndef NEST_CFG_H\n#define NEST_CFG_H\n#endif\n", encoding="utf-8"
    )
    (scratch / "inc" / "api.h").write_text('#include "nest/api.h"\n/*@ predicate q = \true; */\n', encoding="utf-8")
    with pytest.raises(WO.ScopeViolationError, match="inc/api.h"):
        WO.merge_agent_overlay(
            run_dir=run_dir,
            agent_id=NESTED_AGENT,
            role="prover",
            c_file="src/api.c",
            function="nest_add",
            header_file="api.h",
            module="nest",
            cppflags=UMBRELLA_FLAGS,
            verify_hook=lambda: (True, ""),
        )
