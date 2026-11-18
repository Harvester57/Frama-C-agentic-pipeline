"""A merge says whether the dual-oracle guardrail ran.

`_run_parent_reverify` runs the E-ACSL guardrail only when it has a module and its harness sources. The
merge-agent command refuses a module without sources (tests/test_merge_agent_single_path.py); the API callers
(wp_scheduler's partial-contract and architect merges, the batch merge, the proof-carry replay) passed what the
sidecar gave and, when it gave nothing, merged with WP only: the result had the same shape as one whose
guardrail passed.

The guardrail report used here is the one recorded from the analysis image under tests/fixtures/eacsl_ignored
(`unb_requires.json`, status `passed_dynamic_oracle`).
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

import proof_carry
import workspace_overlay
import wp_scheduler as S
from test_wp_scheduler import Sim, tasks

pytestmark = pytest.mark.unit

GUARD_REPORT = json.loads(
    (Path(__file__).parent / "fixtures" / "eacsl_ignored" / "unb_requires.json").read_text(encoding="utf-8")
)
AGENT = "prove-f"
BASE_C = "int f(int x)\n{\n    return x;\n}\n"
PROVED_C = "/*@ assigns \\nothing; */\n" + BASE_C
BASE_H = "int f(int x);\n"
SIDECAR = {"module": "m", "sources": ["src/m.c"], "cppflags": "-Isrc", "ldflags": ""}


def _run(tmp_path: Path, sidecar: dict | None, agent: str = AGENT, role: str = "prover") -> tuple[Path, Path]:
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "m.c").write_text(BASE_C, encoding="utf-8")
    (target / "src" / "m.h").write_text(BASE_H, encoding="utf-8")
    run_dir = (tmp_path / "run").resolve()
    overlay = run_dir / "workspace"
    workspace_overlay.init_overlay(target, overlay)
    if sidecar is not None:
        (overlay / "harnesses").mkdir(parents=True, exist_ok=True)
        (overlay / "harnesses" / "harness_m.json").write_text(json.dumps(sidecar), encoding="utf-8")
    workspace_overlay.init_agent_overlay(run_dir, agent, overlay)
    scratch = run_dir / "agents" / agent / "scratch" / "work" / "src"
    if role == "prover":
        (scratch / "m.c").write_text(PROVED_C, encoding="utf-8")
    else:
        (scratch / "m.h").write_text("/*@ assigns \\nothing; */\n" + BASE_H, encoding="utf-8")
    return run_dir, overlay


def _tools(monkeypatch) -> list[str]:
    """Fake `run_wp_function.py` (all proven) and `run_eacsl_fuzz.py guardrail` (the recorded pass)."""
    ran: list[str] = []

    def fake_run(cmd, **_kwargs):
        script = next((Path(str(c)).name for c in cmd if str(c).endswith(".py")), "")
        ran.append(script)
        out = Path(cmd[cmd.index("--out-json") + 1])
        out.parent.mkdir(parents=True, exist_ok=True)
        if script == "run_wp_function.py":
            report = {"status": "all_proven", "function": cmd[cmd.index("--function") + 1], "limits": {}}
        else:
            report = GUARD_REPORT
        out.write_text(json.dumps(report), encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(workspace_overlay.subprocess, "run", fake_run)
    return ran


def _merge(run_dir: Path, overlay: Path, **kwargs) -> dict:
    return workspace_overlay.merge_agent_overlay(
        run_dir=run_dir, agent_id=AGENT, role="prover", overlay_dir=overlay, c_file="src/m.c", function="f", **kwargs
    )


def _parent_wp(run_dir: Path, agent: str = AGENT) -> dict:
    return json.loads((run_dir / "agents" / agent / "scratch" / "parent_wp" / "f.json").read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# The single merge (wp_scheduler._merge_partial_prover, _merge_architect, the proof-carry replay)
# ---------------------------------------------------------------------------


def test_a_module_without_harness_sources_merges_with_an_explicit_not_run(tmp_path: Path, monkeypatch) -> None:
    run_dir, overlay = _run(tmp_path, {"module": "m", "cppflags": "-Isrc"})
    ran = _tools(monkeypatch)
    res = _merge(run_dir, overlay, module="m", sources=None)
    assert res["ok"] is True and ran == ["run_wp_function.py"]
    assert res["guardrail"]["status"] == "not_run"
    assert "module m" in res["guardrail"]["reason"] and "sources" in res["guardrail"]["reason"]
    # The report the ledger ingests says the same: it never has the shape of a pass.
    assert _parent_wp(run_dir)["limits"]["guardrail"] == res["guardrail"]


def test_sources_the_caller_did_not_pass_come_from_the_sidecar_and_the_guardrail_runs(
    tmp_path: Path, monkeypatch
) -> None:
    run_dir, overlay = _run(tmp_path, SIDECAR)
    ran = _tools(monkeypatch)
    res = _merge(run_dir, overlay, module="m", sources=None)
    assert res["ok"] is True and ran == ["run_eacsl_fuzz.py", "run_wp_function.py"]
    assert res["guardrail"]["status"] == "passed_dynamic_oracle"
    assert res["guardrail"]["report"] == f"agents/{AGENT}/scratch/parent_guard_f.json"
    assert _parent_wp(run_dir)["limits"]["guardrail"]["status"] == "passed_dynamic_oracle"


def test_a_merge_without_a_module_says_the_guardrail_did_not_run(tmp_path: Path, monkeypatch) -> None:
    run_dir, overlay = _run(tmp_path, SIDECAR)
    _tools(monkeypatch)
    res = _merge(run_dir, overlay)
    assert res["guardrail"]["status"] == "not_run" and "no module" in res["guardrail"]["reason"]


def test_a_stale_guardrail_report_is_not_read_as_this_merges_pass(tmp_path: Path, monkeypatch) -> None:
    run_dir, overlay = _run(tmp_path, None)
    stale = run_dir / "agents" / AGENT / "scratch" / "parent_guard_f.json"
    stale.write_text(json.dumps(GUARD_REPORT), encoding="utf-8")
    _tools(monkeypatch)
    res = _merge(run_dir, overlay, module="m", sources=None)
    assert res["guardrail"]["status"] == "not_run" and not stale.exists()


def test_a_merge_whose_re_check_the_caller_skipped_says_so(tmp_path: Path) -> None:
    run_dir, overlay = _run(tmp_path, SIDECAR)
    res = _merge(run_dir, overlay, module="m", skip_reverify=True)
    assert res["guardrail"]["status"] == "not_run" and "skip_reverify" in res["guardrail"]["reason"]


def test_an_architect_merge_without_harness_sources_says_not_run(tmp_path: Path, monkeypatch) -> None:
    run_dir, overlay = _run(tmp_path, None, agent="architect-m", role="architect")
    ran = _tools(monkeypatch)
    res = workspace_overlay.merge_agent_overlay(
        run_dir=run_dir,
        agent_id="architect-m",
        role="architect",
        overlay_dir=overlay,
        header_file="src/m.h",
        module="m",
    )
    assert res["ok"] is True and ran == []
    assert res["guardrail"]["status"] == "not_run"


# ---------------------------------------------------------------------------
# The batch merge (wp_scheduler merge-pending)
# ---------------------------------------------------------------------------

ENTRY = {"agent_id": AGENT, "role": "prover", "file": "src/m.c", "function": "f", "module": "m"}


def test_a_batch_of_a_module_without_harness_sources_says_not_run(tmp_path: Path, monkeypatch) -> None:
    run_dir, overlay = _run(tmp_path, None)
    ran = _tools(monkeypatch)
    res = workspace_overlay.merge_agent_batch(run_dir, [ENTRY], overlay_dir=overlay)
    (merged,) = res["merged"]
    assert ran == ["run_wp_function.py"]
    assert merged["guardrail"]["status"] == "not_run" and "module m" in merged["guardrail"]["reason"]
    assert _parent_wp(run_dir)["limits"]["guardrail"] == merged["guardrail"]


def test_a_batch_whose_module_guardrail_passed_says_so(tmp_path: Path, monkeypatch) -> None:
    run_dir, overlay = _run(tmp_path, SIDECAR)
    ran = _tools(monkeypatch)
    res = workspace_overlay.merge_agent_batch(run_dir, [ENTRY], overlay_dir=overlay)
    (merged,) = res["merged"]
    assert sorted(ran) == ["run_eacsl_fuzz.py", "run_wp_function.py"]
    assert merged["guardrail"]["status"] == "passed_dynamic_oracle"
    assert merged["guardrail"]["report"] == f"agents/{AGENT}/scratch/parent_guard_m.json"
    assert _parent_wp(run_dir)["limits"]["guardrail"]["status"] == "passed_dynamic_oracle"


# ---------------------------------------------------------------------------
# wp_scheduler: the callers, and what stays on the task
# ---------------------------------------------------------------------------


@pytest.fixture
def sim(run_dir, monkeypatch):
    return Sim(run_dir, monkeypatch)


NOT_RUN = {"status": "not_run", "reason": "module m has no harness sidecar with sources"}


def test_a_merge_without_guardrail_is_noted_on_the_task(sim, monkeypatch) -> None:
    sim.build({"a": ("src/m/a.c", "m", [])})
    S.cmd_init()
    S.cmd_next("auto", prepare=True)
    sim.prover("prove-a", "a", "src/m/a.c")
    S.cmd_complete("prove-a")
    plain = sim.merge_agent_batch

    def batch(run_dir, entries, **kw):
        res = plain(run_dir, entries, **kw)
        for merged in res["merged"]:
            merged["guardrail"] = NOT_RUN
        return res

    monkeypatch.setattr(S.DEPS, "merge_agent_batch", batch)
    out = S.cmd_merge_pending(force=True)
    assert out["merged"][0]["merge_notes"] == {"guardrail": NOT_RUN}
    assert tasks()["prove:src/m/a.c#a"]["merge_notes"] == {"guardrail": NOT_RUN}


def test_a_passed_guardrail_leaves_no_note() -> None:
    assert S._merge_notes({"ok": True, "guardrail": {"status": "passed_dynamic_oracle", "report": "x.json"}}) == {}
    assert S._merge_notes({"ok": True, "guardrail": NOT_RUN}) == {"guardrail": NOT_RUN}


def test_an_architect_merge_without_guardrail_is_noted_on_the_task(sim, monkeypatch) -> None:
    sim.build({"a": ("src/m/a.c", "m", [])}, sidecars={"m": {"header": "src/m/m.h"}})
    monkeypatch.setattr(
        S.DEPS,
        "merge_agent_overlay",
        lambda *a, **kw: {"ok": True, "agent_id": a[1], "modified_files": [], "guardrail": NOT_RUN},
    )
    S.cmd_init()
    out = S.cmd_next("auto", prepare=True)
    arch = next(t for t in out["tasks"] if t["kind"] == "arch")
    sim.architect(arch["agent_id"], "src/m/m.h")
    done = S.cmd_complete(arch["agent_id"])
    assert done["action"] == "merged" and done["merge_notes"] == {"guardrail": NOT_RUN}
    assert tasks()["arch:m"]["merge_notes"] == {"guardrail": NOT_RUN}


# ---------------------------------------------------------------------------
# proof_carry: the replay keeps the guardrail status of each carried proof
# ---------------------------------------------------------------------------


def test_the_carried_row_names_the_guardrail_status() -> None:
    assert proof_carry.carried_guardrail({"ok": True, "guardrail": NOT_RUN}) == NOT_RUN
    passed = {"status": "passed_dynamic_oracle", "report": "agents/x/scratch/parent_guard_f.json"}
    assert proof_carry.carried_guardrail({"ok": True, "guardrail": passed}) == passed
    # A merge function that says nothing (an injected one) is not read as a pass.
    assert proof_carry.carried_guardrail({"ok": True})["status"] == "unknown"
