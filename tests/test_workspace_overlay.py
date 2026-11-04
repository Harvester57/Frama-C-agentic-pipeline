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
