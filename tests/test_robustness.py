"""Failure handling that must never read as a result: killed/timed-out tools, stale reports, half-done merges."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

import run_eva_slice
import run_wp_function
import workspace_overlay
from conftest import write_json

CSV_HEADER = "directory\tfile\tfunction\tline\tkind\tstatus\tproperty\n"


def _c_file(tmp_path: Path) -> Path:
    c = tmp_path / "f.c"
    c.write_text("int f(int x) { return x; }\n", encoding="utf-8")
    return c


def test_failure_reason_mapping():
    assert run_wp_function.failure_reason(None, True) == "timeout"
    assert run_wp_function.failure_reason(-9, False) == "oom_killed"
    assert run_wp_function.failure_reason(137, False) == "oom_killed"
    assert run_wp_function.failure_reason(-11, False) == "signal_11"
    assert run_wp_function.failure_reason(2, False) == "crashed"
    assert run_wp_function.failure_reason(0, False) == "no_report"


def test_wp_killed_run_with_stale_csv_is_analysis_error(tmp_path, monkeypatch):
    out = tmp_path / "wp"
    out.mkdir()
    # A report left by an earlier run must not be read as this run's (all Valid) result.
    (out / "wp_f.csv").write_text(CSV_HEADER + ".\tf.c\tf\t1\trte: mem_access\tValid\tx\n", encoding="utf-8")

    def fake_run(cmd, **kwargs):
        if "-wp" not in cmd:  # ACSL syntax pre-check
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(cmd, -9, stdout="[wp] 12 goals scheduled\n", stderr="")

    monkeypatch.setattr(run_wp_function.subprocess, "run", fake_run)
    res = run_wp_function.run_wp_on_function(_c_file(tmp_path), "f", out, retry_bitwise=False)
    assert res["status"] == "analysis_error" and res["reason"] == "oom_killed"
    assert res["next_synthesis_focus"] == "analysis_error_rerun_required"
    assert res["unproven_count"] == 0 and res["total_goals"] == 0
    assert not (out / "wp_f.csv").exists()


def test_wp_wall_timeout_is_analysis_error(tmp_path, monkeypatch):
    seen = {}

    def fake_run(cmd, **kwargs):
        if "-wp" not in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        seen["timeout"] = kwargs.get("timeout")
        raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout"), output=b"[wp] proving", stderr=None)

    monkeypatch.setattr(run_wp_function.subprocess, "run", fake_run)
    res = run_wp_function.run_wp_on_function(_c_file(tmp_path), "f", tmp_path / "wp", wall_timeout=7, retry_bitwise=False)
    assert seen["timeout"] == 7
    assert res["status"] == "analysis_error" and res["reason"] == "timeout"
    assert "[wp] proving" in (tmp_path / "wp" / "wp_f.log").read_text(encoding="utf-8")


def test_wp_bitwise_retry_never_accepts_an_analysis_error(tmp_path, monkeypatch):
    def fake_run(cmd, **kwargs):
        if "-wp" not in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        model = cmd[cmd.index("-wp-model") + 1]
        if model == "Typed":
            csv = Path(cmd[cmd.index("-report-csv") + 1])
            csv.write_text(CSV_HEADER + ".\tf.c\tf\t1\trte: shift\tUnknown\tx << 3\n", encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(cmd, -9, stdout="", stderr="")  # the retry is OOM-killed

    monkeypatch.setattr(run_wp_function.subprocess, "run", fake_run)
    res = run_wp_function.run_wp_on_function(_c_file(tmp_path), "f", tmp_path / "wp")
    assert res["status"] == "unproven_goals_remain" and "bitwise_retry" not in res
    assert (tmp_path / "wp" / "wp_f.csv").is_file()  # the first attempt's artifacts stay intact


def test_wp_refuses_a_job_too_small_for_one_prover(tmp_path, monkeypatch):
    # Starved provers fail goals that a properly sized machine proves: never run, say why.
    monkeypatch.setenv("FRAMAC_JOB_MEM_MB", "200")
    monkeypatch.setattr(run_wp_function.subprocess, "run", lambda *a, **k: pytest.fail("frama-c must not run"))
    res = run_wp_function.run_wp_on_function(_c_file(tmp_path), "f", tmp_path / "wp", retry_bitwise=False)
    assert res["status"] == "analysis_error" and res["reason"] == "insufficient_memory"
    assert res["sizing"]["memory_limit_mb"] == 200 and "1768 MiB" in res["error_summary"][0]


def test_eva_wall_timeout_is_reported(tmp_path, monkeypatch):
    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout"), output="[eva] analyzing\n", stderr="")

    monkeypatch.setattr(run_eva_slice.subprocess, "run", fake_run)
    res = run_eva_slice.run_eva_on_slice([str(_c_file(tmp_path))], "eva_main", tmp_path / "eva", timeout=9)
    assert res["status"] == "analysis_timeout" and res["returncode"] is None
    assert "9 s" in res["error_summary"][0]


def test_eva_killed_by_the_oom_killer_says_so(tmp_path, monkeypatch):
    monkeypatch.setattr(run_eva_slice.subprocess, "run",
                        lambda cmd, **kw: subprocess.CompletedProcess(cmd, -9, stdout="", stderr=""))
    res = run_eva_slice.run_eva_on_slice([str(_c_file(tmp_path))], "eva_main", tmp_path / "eva")
    assert (res["status"], res["reason"], res["returncode"]) == ("analysis_error", "oom_killed", -9)
    assert res["error_summary"] == ["Frama-C Eva produced no report (oom_killed, exit code -9)"]


# ---------------------------------------------------------------------------
# Overlay: host paths in briefs, journaled merges, per-agent parent reports
# ---------------------------------------------------------------------------

BASE_C = "int f(int x) {\n    return x;\n}\n"


def _overlay(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    target.mkdir()
    (target / "a.c").write_text(BASE_C, encoding="utf-8")
    run_dir = tmp_path / "run-1"
    workspace_overlay.init_overlay(target, run_dir / "workspace")
    return run_dir


def test_brief_uses_host_paths_from_wrapper_environment(tmp_path, monkeypatch):
    run_dir = _overlay(tmp_path)
    monkeypatch.setenv("FRAMAC_TARGET_HOST", "/srv/code/target")
    monkeypatch.setenv("FRAMAC_RUN_HOST", '/home/u/framac-pipeline/demo/run-1"')
    res = workspace_overlay.prepare_agent(run_dir, "prover-1", "prover", function="f", c_file="a.c")
    brief = (run_dir / res["brief_file"]).read_text(encoding="utf-8")
    assert '-TargetDir "/srv/code/target"' in brief
    assert '-RunDir "/home/u/framac-pipeline/demo/run-1"' in brief
    assert "/framac-run" not in brief.split("-RunDir", 1)[1].split("\n", 1)[0]


def test_brief_scopes_same_named_statics_by_file_and_renders_scheduler_context(tmp_path, capsys):
    run_dir = _overlay(tmp_path)
    (run_dir / "workspace/work/b.c").write_text("static int f(int y) {\n    return y;\n}\n", encoding="utf-8")
    # The DAG keys functions by bare name: its entry for f describes a.c's definition, not b.c's.
    write_json(run_dir / "workspace/reports/callgraph_dag.json",
               {"functions": {"f": {"file": "a.c", "module": "ma", "security_properties": ["layer4_auth"]}}, "modules": {}})
    write_json(run_dir / "coverage-ledger.json", [
        {"coverage_id": "a.c#f::rte", "file": "a.c", "function": "f", "module": "ma", "status": "planned"},
        {"coverage_id": "b.c#f::rte", "file": "b.c", "function": "f", "module": "mb", "status": "planned"},
    ])
    res = workspace_overlay.prepare_agent(run_dir, "prover-b", "prover", function="f", c_file="b.c")
    assert (res["module"], res["file"]) == ("mb", "b.c")
    brief = (run_dir / res["brief_file"]).read_text(encoding="utf-8")
    assert '["b.c#f::rte"]' in brief and "a.c#f::rte" not in brief and "layer4_auth" not in brief

    # A breaker lists the stalled prover's goals, not the shared report of another same-named function.
    write_json(run_dir / "workspace/reports/wp/f.json", {"unproven_goals": [{"property": "goal_of_a"}]})
    write_json(run_dir / "agents/prover-b/artifacts/wp_f.json", {"unproven_goals": [{"property": "goal_of_b"}]})
    res = workspace_overlay.prepare_agent(run_dir, "breaker-b", "breaker", function="f", c_file="b.c",
                                          wp_report="agents/prover-b/artifacts/wp_f.json")
    brief = (run_dir / res["brief_file"]).read_text(encoding="utf-8")
    assert "goal_of_b" in brief and "goal_of_a" not in brief
    assert "`agents/prover-b/artifacts/wp_f.json`" in brief

    # A negotiating callee prover gets every request verbatim; request text is never substituted.
    req = {"id": "req_0001_h_to_f", "caller_function": "h", "callee_function": "f",
           "needed_clause": "ensures \\result >= 0; // {agent_id}", "reason": "h indexes a table with it"}
    write_json(run_dir / "workspace/reports/strengthen_requests.json", {"requests": [req]})
    rc = workspace_overlay.main(["prepare-agent", "--run-dir", str(run_dir), "--agent-id", "negotiate-f",
                                 "--role", "prover", "--function", "f", "--file", "b.c", "--request-id", req["id"]])
    assert rc == 0
    brief = (run_dir / json.loads(capsys.readouterr().out)["brief_file"]).read_text(encoding="utf-8")
    section = brief.split("## Contract Negotiation Requests", 1)[1]
    assert json.loads(section.split("```json\n", 1)[1].split("\n```", 1)[0]) == [req]
    rc = workspace_overlay.main(["prepare-agent", "--run-dir", str(run_dir), "--agent-id", "negotiate-f",
                                 "--role", "prover", "--function", "f", "--file", "b.c", "--request-id", "req_9999"])
    assert rc == 1 and "req_9999" in json.loads(capsys.readouterr().out)["error"]


def test_killed_merge_is_rolled_back_by_the_next_caller(tmp_path):
    run_dir = _overlay(tmp_path)
    work_file = run_dir / "workspace/work/a.c"
    # Simulate a merge that died after splicing but before verification.
    workspace_overlay._write_merge_journal(run_dir.resolve(), "merge-agent:prover-9", {"a.c": work_file.read_bytes()})
    work_file.write_text("/*@ assert unverified; */\n" + BASE_C, encoding="utf-8")
    res = workspace_overlay.prepare_agent(run_dir, "prover-1", "prover", function="f", c_file="a.c")
    assert res["recovered_journal"] == {"recovered_from": "merge-agent:prover-9", "restored_files": ["a.c"]}
    assert work_file.read_text(encoding="utf-8") == BASE_C
    assert (run_dir / "agents/prover-1/scratch/work/a.c").read_text(encoding="utf-8") == BASE_C
    assert not (run_dir / "state/merge-journal.json").exists()


def test_merge_journals_before_splicing_and_restores_on_interrupt(tmp_path, monkeypatch):
    run_dir = _overlay(tmp_path)
    workspace_overlay.init_agent_overlay(run_dir, "prover-1")
    (run_dir / "agents/prover-1/scratch/work/a.c").write_text(BASE_C.replace("    return x;", "    //@ assert x == x;\n    return x;"), encoding="utf-8")
    seen = {}

    def interrupted(*args, **kwargs):
        seen["journal"] = json.loads((run_dir / "state/merge-journal.json").read_text(encoding="utf-8"))
        seen["work"] = (run_dir / "workspace/work/a.c").read_text(encoding="utf-8")
        raise KeyboardInterrupt

    monkeypatch.setattr(workspace_overlay, "_run_parent_reverify", interrupted)
    with pytest.raises(KeyboardInterrupt):
        workspace_overlay.merge_agent_overlay(run_dir, "prover-1", "prover", c_file="a.c", function="f")
    assert "a.c" in seen["journal"]["files"] and "assert x == x" in seen["work"]
    assert (run_dir / "workspace/work/a.c").read_text(encoding="utf-8") == BASE_C
    assert not (run_dir / "state/merge-journal.json").exists()


def _fake_wp_subprocess(statuses: dict):
    def fake_run(cmd, **kwargs):
        if any(str(c).endswith("run_wp_function.py") for c in cmd):
            out = Path(cmd[cmd.index("--out-json") + 1])
            fn = cmd[cmd.index("--function") + 1]
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps({"status": statuses.get(str(out), "all_proven"), "function": fn}), encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
    return fake_run


def test_parent_wp_report_is_per_agent_and_published_only_when_unambiguous(tmp_path, monkeypatch):
    run_dir = _overlay(tmp_path).resolve()
    overlay = run_dir / "workspace"
    monkeypatch.setattr(workspace_overlay.subprocess, "run", _fake_wp_subprocess({}))
    ok, _ = workspace_overlay._run_parent_reverify(run_dir, "prover-1", "prover", overlay, "a.c", "f", None, None, "-I.")
    assert ok and (run_dir / "agents/prover-1/scratch/parent_wp/f.json").is_file()
    assert (overlay / "reports/wp/f.json").is_file()

    # Two static functions named f in different files: never publish under the shared name.
    (overlay / "reports/wp/f.json").unlink()
    write_json(run_dir / "coverage-ledger.json", [
        {"function": "f", "file": "a.c", "module": "a"},
        {"function": "f", "file": "b.c", "module": "b"},
    ])
    ok, _ = workspace_overlay._run_parent_reverify(run_dir, "prover-2", "prover", overlay, "a.c", "f", None, None, "-I.")
    assert ok and (run_dir / "agents/prover-2/scratch/parent_wp/f.json").is_file()
    assert not (overlay / "reports/wp/f.json").exists()


def test_batch_entry_module_is_resolved_by_file_and_function(tmp_path):
    run_dir = _overlay(tmp_path).resolve()
    write_json(run_dir / "coverage-ledger.json", [
        {"function": "f", "file": "a.c", "module": "mod_a"},
        {"function": "f", "file": "b.c", "module": "mod_b"},
    ])
    overlay = run_dir / "workspace"
    enrich = workspace_overlay._enrich_batch_entry
    ambiguous = enrich(run_dir, overlay, {"agent_id": "prover-1", "function": "f"}, None, None, None, None, "")
    assert ambiguous["module"] is None and ambiguous["c_file"] is None
    exact = enrich(run_dir, overlay, {"agent_id": "prover-1", "function": "f", "file": "b.c"}, None, None, None, None, "")
    assert exact["module"] == "mod_b"
