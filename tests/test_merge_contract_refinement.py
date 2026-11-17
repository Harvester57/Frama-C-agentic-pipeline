"""The merge re-check records whether a merged contract still gives what the one it replaced gave."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

import contract_refinement
import workspace_overlay

pytestmark = pytest.mark.unit

MERGE_BASE_C = """\
/*@ requires a > 0;
    assigns \\nothing;
    ensures \\result == a + 1; */
int inc(int a) {
    return a + 1;
}

int twice(int a) {
    return a * 2;
}
"""

MERGE_WEAKER_C = MERGE_BASE_C.replace("ensures \\result == a + 1;", "ensures \\result > a;")

MERGE_TWICE_C = MERGE_BASE_C.replace(
    "int twice(int a) {", "/*@ assigns \\nothing;\n    ensures \\result == a * 2; */\nint twice(int a) {"
)


def _run(tmp_path: Path, agents: dict[str, str]) -> tuple[Path, Path]:
    target = tmp_path / "target"
    target.mkdir()
    (target / "calc.c").write_text(MERGE_BASE_C, encoding="utf-8")
    run_dir = tmp_path / "run"
    overlay = run_dir / "workspace"
    workspace_overlay.init_overlay(target, overlay)
    for aid, text in agents.items():
        workspace_overlay.init_agent_overlay(run_dir, aid, overlay)
        (run_dir / "agents" / aid / "scratch" / "work" / "calc.c").write_text(text, encoding="utf-8")
    return run_dir, overlay


def _fake_reverify(run_dir, agent_id, role, overlay_dir, c_file, function, module, sources, cppflags, **kw):
    wp_json = Path(run_dir) / "agents" / agent_id / "scratch" / "parent_wp" / f"{function}.json"
    wp_json.parent.mkdir(parents=True, exist_ok=True)
    wp_json.write_text(json.dumps({"function": function, "status": "all_proven"}), encoding="utf-8")
    return True, "ok"


@pytest.fixture
def probe_calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    """Capture (new, previous) contract text instead of running WP; answer `weaker`."""
    calls: list[tuple[str, str]] = []

    def fake_check(new, previous, include, cppflags, **kw):
        calls.append((new.text(), previous.text()))
        return {"verdict": "weaker", "reason": "fake", "clauses": [{"contract": "previous", "kind": "ensures"}]}

    monkeypatch.setattr(contract_refinement, "refinement_check", fake_check)
    monkeypatch.setattr(workspace_overlay, "_run_parent_reverify", _fake_reverify)
    return calls


def test_single_merge_compares_against_the_contract_before_the_splice(tmp_path, probe_calls) -> None:
    run_dir, overlay = _run(tmp_path, {"prove-inc": MERGE_WEAKER_C})
    res = workspace_overlay.merge_agent_overlay(
        run_dir=run_dir, agent_id="prove-inc", role="prover", overlay_dir=overlay, c_file="calc.c", function="inc"
    )
    assert res["ok"] is True, res
    assert res["contract_refinement"]["verdict"] == "weaker"
    ((new, previous),) = probe_calls
    assert "\\result > a" in new and "\\result == a + 1" in previous
    wp = json.loads((run_dir / "agents/prove-inc/scratch/parent_wp/inc.json").read_text(encoding="utf-8"))
    assert wp["contract_refinement"]["verdict"] == "weaker"


def test_a_first_contract_records_nothing(tmp_path, probe_calls) -> None:
    run_dir, overlay = _run(tmp_path, {"prove-twice": MERGE_TWICE_C})
    res = workspace_overlay.merge_agent_overlay(
        run_dir=run_dir, agent_id="prove-twice", role="prover", overlay_dir=overlay, c_file="calc.c", function="twice"
    )
    assert res["ok"] is True, res
    assert "contract_refinement" not in res and probe_calls == []


def test_a_failing_probe_is_recorded_as_undecided_and_the_merge_stands(tmp_path, monkeypatch) -> None:
    def boom(*a, **kw):
        raise RuntimeError("no frama-c")

    monkeypatch.setattr(contract_refinement, "refinement_check", boom)
    monkeypatch.setattr(workspace_overlay, "_run_parent_reverify", _fake_reverify)
    run_dir, overlay = _run(tmp_path, {"prove-inc": MERGE_WEAKER_C})
    res = workspace_overlay.merge_agent_overlay(
        run_dir=run_dir, agent_id="prove-inc", role="prover", overlay_dir=overlay, c_file="calc.c", function="inc"
    )
    assert res["ok"] is True
    assert res["contract_refinement"]["verdict"] == "undecided"
    assert "\\result > a" in (overlay / "work/calc.c").read_text(encoding="utf-8")


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("frama-c") is None, reason="Frama-C not available")
def test_real_merge_recheck_records_weaker(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(workspace_overlay, "_run_parent_reverify", _fake_reverify)
    monkeypatch.chdir(tmp_path)
    run_dir, overlay = _run(tmp_path, {"prove-inc": MERGE_WEAKER_C})
    res = workspace_overlay.merge_agent_overlay(
        run_dir=run_dir, agent_id="prove-inc", role="prover", overlay_dir=overlay, c_file="calc.c", function="inc"
    )
    refinement = res["contract_refinement"]
    assert refinement["verdict"] == "weaker", refinement
    assert [c["text"] for c in refinement["clauses"]] == ["\\result == a + 1"]
    print(f"merge re-check probe (ms): {refinement.get('elapsed_ms')}")


def test_batch_merge_records_the_check_once_the_round_passes(tmp_path, probe_calls) -> None:
    run_dir, overlay = _run(tmp_path, {"prove-inc": MERGE_WEAKER_C, "prove-twice": MERGE_TWICE_C})
    out = workspace_overlay.merge_agent_batch(
        run_dir=run_dir,
        entries=[
            {"agent_id": "prove-inc", "role": "prover", "file": "calc.c", "function": "inc"},
            {"agent_id": "prove-twice", "role": "prover", "file": "calc.c", "function": "twice"},
        ],
        overlay_dir=overlay,
    )
    assert out["ok"] is True, out
    by_agent = {m["agent_id"]: m for m in out["merged"]}
    assert by_agent["prove-inc"]["contract_refinement"]["verdict"] == "weaker"
    assert "contract_refinement" not in by_agent["prove-twice"]
    assert all("previous_contract" not in m for m in out["merged"])
    ((new, previous),) = probe_calls
    assert "\\result > a" in new and "\\result == a + 1" in previous
