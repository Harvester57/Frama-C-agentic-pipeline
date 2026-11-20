r"""The merge refuses a prover result that deletes its function's `assigns` clause.

libmodbus run-1 (2026-11-18): `prove-modbus_write_register` removed `assigns *ctx \from reg_addr, value;` and
`ensures status: \result >= -1;` from the contract the architect had merged on the prototype in `src/modbus.h`,
WP proved what was left, and the result was merged as `all_proven`. The clause was not in the projected frame
skeleton, so the frame check had nothing to protect.

The contract texts under tests/fixtures/libmodbus_run1_contracts/ are cut from that run (see
tests/test_contract_clause_changes.py). The WP reports are built by run_wp_function.py from Frama-C's own
recorded output under tests/fixtures/wp_frame_clause/ (see tests/test_wp_frame_clause.py).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

import run_wp_function as W
import workspace_overlay
from acsl_ast import AcslError

pytestmark = pytest.mark.unit

RUN1 = Path(__file__).parent / "fixtures" / "libmodbus_run1_contracts"
WP_FIXTURES = Path(__file__).parent / "fixtures" / "wp_frame_clause"
FN = "modbus_write_register"
C_REL, H_REL = "src/modbus.c", "src/modbus.h"
AGENT = "prove-modbus_write_register"

ARCHITECT_H = (RUN1 / "modbus_write_register.base.h").read_text(encoding="utf-8")
PROVER_H = (RUN1 / "modbus_write_register.candidate.h").read_text(encoding="utf-8")
SOURCE_C = (RUN1 / "modbus_write_register.c").read_text(encoding="utf-8")
# The target itself has no ACSL: the architect's contract exists only in the shared work tree.
TARGET_H = re.sub(r"/\*@.*?\*/\n", "", ARCHITECT_H, flags=re.DOTALL)
PROTOTYPE = "MODBUS_API int modbus_write_register(modbus_t *ctx, int reg_addr, const uint16_t value);"
DEFINITION = "int modbus_write_register(modbus_t *ctx, int addr, const uint16_t value)"
REMOVED_ASSIGNS = "assigns *ctx \\from reg_addr, value;"


def _with_register_contract(*clauses: str) -> str:
    """The architect's header with the contract of modbus_write_register replaced by `clauses`."""
    head, _, _ = ARCHITECT_H.rpartition("/*@")
    body = "".join(f"  {c}\n" for c in clauses)
    return f"{head}/*@\n{body}*/\n{PROTOTYPE}\n"


def _run(tmp_path: Path, tree_h: str = ARCHITECT_H, agent_h: str | None = None, agent_c: str | None = None):
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / C_REL).write_text(SOURCE_C, encoding="utf-8")
    (target / H_REL).write_text(TARGET_H, encoding="utf-8")
    run_dir = (tmp_path / "run").resolve()
    overlay = run_dir / "workspace"
    workspace_overlay.init_overlay(target, overlay)
    (overlay / "work" / H_REL).write_text(tree_h, encoding="utf-8")
    workspace_overlay.init_agent_overlay(run_dir, AGENT, overlay)
    scratch = run_dir / "agents" / AGENT / "scratch" / "work"
    if agent_h is not None:
        (scratch / H_REL).write_text(agent_h, encoding="utf-8")
    if agent_c is not None:
        (scratch / C_REL).write_text(agent_c, encoding="utf-8")
    return run_dir, overlay


def _merge(run_dir: Path, overlay: Path, **kwargs) -> dict:
    kwargs.setdefault("skip_reverify", True)
    return workspace_overlay.merge_agent_overlay(
        run_dir=run_dir, agent_id=AGENT, role="prover", overlay_dir=overlay, c_file=C_REL, function=FN, **kwargs
    )


# ---------------------------------------------------------------------------
# The recorded case
# ---------------------------------------------------------------------------


def test_run1_fixture_target_has_no_contract() -> None:
    assert "/*@" not in TARGET_H and PROTOTYPE in TARGET_H
    assert REMOVED_ASSIGNS in ARCHITECT_H and REMOVED_ASSIGNS not in PROVER_H


def test_run1_prover_deleting_the_assigns_clause_is_refused(tmp_path: Path) -> None:
    run_dir, overlay = _run(tmp_path, agent_h=PROVER_H)
    with pytest.raises(AcslError) as exc:
        _merge(run_dir, overlay)
    message = str(exc.value)
    assert workspace_overlay.FRAME_REFUSAL in message
    assert FN in message and "`assigns *ctx \\from reg_addr, value`" in message
    # The prover is told what to do instead.
    assert "Keep an `assigns` clause" in message and "strengthening request" in message
    assert (overlay / "work" / H_REL).read_text(encoding="utf-8") == ARCHITECT_H


def test_run1_refusal_is_also_what_the_dry_run_says(tmp_path: Path) -> None:
    """`wp_scheduler.py requeue --frame-refused` asks this before it puts a result back in the merge queue."""
    run_dir, _overlay = _run(tmp_path)
    refusal = workspace_overlay.merged_frame_refusal(run_dir, C_REL, FN, None, None, "-I.", {H_REL: PROVER_H})
    assert refusal is not None and "`assigns *ctx \\from reg_addr, value`" in refusal
    assert workspace_overlay.merged_frame_refusal(run_dir, C_REL, FN, None, None, "-I.", {}) is None


def test_run1_prover_is_refused_by_the_batch_merge(tmp_path: Path) -> None:
    run_dir, overlay = _run(tmp_path, agent_h=PROVER_H)
    res = workspace_overlay.merge_agent_batch(
        run_dir,
        [{"agent_id": AGENT, "role": "prover", "file": C_REL, "function": FN}],
        overlay_dir=overlay,
        skip_reverify=True,
    )
    assert res["merged"] == []
    (failed,) = res["failed"]
    assert workspace_overlay.FRAME_REFUSAL in failed["reason"] and "assigns *ctx" in failed["reason"]
    assert (overlay / "work" / H_REL).read_text(encoding="utf-8") == ARCHITECT_H


# ---------------------------------------------------------------------------
# Controls: legitimate changes to the frame still merge, and what else was removed is recorded
# ---------------------------------------------------------------------------

KEPT = ("requires ctx_shape: ctx == \\null || \\valid(ctx);", "terminates \\true;", "exits \\false;")


@pytest.mark.parametrize(
    "assigns",
    [
        "assigns ctx->debug \\from value;",  # tightened
        "assigns *ctx \\from reg_addr, value, ctx->slave;",  # rewritten \from
        "assigns *ctx;",  # no \from
    ],
)
def test_a_tightened_or_rewritten_assigns_still_merges(tmp_path: Path, assigns: str) -> None:
    agent_h = _with_register_contract(*KEPT, assigns, "ensures status: \\result >= -1;")
    run_dir, overlay = _run(tmp_path, agent_h=agent_h)
    res = _merge(run_dir, overlay)
    assert res["ok"] is True
    changes = res["contract_changes"]
    assert changes["available"] is True and changes["had_contract"] is True
    assert changes["assigns_removed"] == [] and changes["ensures_removed"] == []
    assert assigns in (overlay / "work" / H_REL).read_text(encoding="utf-8")


def test_an_assigns_clause_moved_to_the_definition_still_merges(tmp_path: Path) -> None:
    agent_h = _with_register_contract(*KEPT, "ensures status: \\result >= -1;")
    agent_c = SOURCE_C.replace(DEFINITION, "/*@ assigns *ctx \\from addr, value; */\n" + DEFINITION)
    run_dir, overlay = _run(tmp_path, agent_h=agent_h, agent_c=agent_c)
    res = _merge(run_dir, overlay)
    assert res["ok"] is True and res["contract_changes"]["assigns_removed"] == []


def test_a_removed_ensures_is_merged_and_recorded(tmp_path: Path) -> None:
    agent_h = _with_register_contract(*KEPT, REMOVED_ASSIGNS, "ensures null_status: ctx == \\null ==> \\result == -1;")
    run_dir, overlay = _run(tmp_path, agent_h=agent_h)
    res = _merge(run_dir, overlay)
    assert res["ok"] is True
    changes = res["contract_changes"]
    assert changes["ensures_removed"] == [{"behavior": "default!", "clauses": ["\\result >= -1"]}]
    assert changes["assigns_removed"] == [] and changes["behaviors_removed"] == []
    assert changes["baseline_assigns_in"] == ["default!"]


def test_a_function_without_a_baseline_contract_still_merges(tmp_path: Path) -> None:
    agent_h = TARGET_H.replace(PROTOTYPE, "/*@ ensures \\result >= -1; */\n" + PROTOTYPE)
    run_dir, overlay = _run(tmp_path, tree_h=TARGET_H, agent_h=agent_h)
    res = _merge(run_dir, overlay)
    assert res["ok"] is True
    changes = res["contract_changes"]
    assert changes["had_contract"] is False and changes["baseline_assigns_in"] == []


# ---------------------------------------------------------------------------
# Named behaviors
# ---------------------------------------------------------------------------

BEHAVIORS = (
    "behavior null: assumes ctx == \\null; assigns \\nothing; ensures \\result == -1;",
    "behavior live: assumes ctx != \\null; assigns *ctx; ensures \\result >= -1;",
)


def test_an_assigns_clause_removed_from_a_named_behavior_is_refused(tmp_path: Path) -> None:
    tree_h = _with_register_contract(*BEHAVIORS)
    agent_h = _with_register_contract(BEHAVIORS[0], "behavior live: assumes ctx != \\null; ensures \\result >= -1;")
    run_dir, overlay = _run(tmp_path, tree_h=tree_h, agent_h=agent_h)
    with pytest.raises(AcslError, match="behavior 'live'"):
        _merge(run_dir, overlay)


def test_a_removed_behavior_takes_its_assigns_only_when_the_default_behavior_frames_the_function(
    tmp_path: Path,
) -> None:
    tree_h = _with_register_contract(*BEHAVIORS)
    # Without a default `assigns`, the removed behavior's frame is gone: refused.
    run_dir, overlay = _run(tmp_path / "a", tree_h=tree_h, agent_h=_with_register_contract(BEHAVIORS[0]))
    with pytest.raises(AcslError, match="behavior 'live'"):
        _merge(run_dir, overlay)
    # With one, the function is still framed in every case: merged, and the removed behavior is recorded.
    agent_h = _with_register_contract("assigns *ctx;", BEHAVIORS[0])
    run_dir, overlay = _run(tmp_path / "b", tree_h=tree_h, agent_h=agent_h)
    res = _merge(run_dir, overlay)
    assert res["ok"] is True
    assert res["contract_changes"]["behaviors_removed"] == ["live"]
    assert res["contract_changes"]["assigns_removed"] == [{"behavior": "live", "clauses": ["*ctx"]}]


# ---------------------------------------------------------------------------
# A comparison that cannot be made
# ---------------------------------------------------------------------------


def _no_comparison(baseline, candidate, function):
    import acsl_ast

    result = acsl_ast._empty_contract_comparison(function)
    result["reason"] = "the declarations of 'modbus_write_register' differ between baseline and candidate"
    return result


def test_no_comparison_is_refused_when_the_function_had_a_contract(tmp_path: Path, monkeypatch) -> None:
    agent_h = _with_register_contract(*KEPT, REMOVED_ASSIGNS, "ensures status: \\result >= -1;", "ensures \\true;")
    run_dir, overlay = _run(tmp_path, agent_h=agent_h)
    monkeypatch.setattr(workspace_overlay, "compare_function_contracts", _no_comparison)
    with pytest.raises(AcslError) as exc:
        _merge(run_dir, overlay)
    assert "cannot be compared" in str(exc.value) and "declarations of 'modbus_write_register' differ" in str(exc.value)


def test_no_comparison_does_not_block_a_function_that_had_no_contract(tmp_path: Path, monkeypatch) -> None:
    agent_h = TARGET_H.replace(PROTOTYPE, "/*@ ensures \\result >= -1; */\n" + PROTOTYPE)
    run_dir, overlay = _run(tmp_path, tree_h=TARGET_H, agent_h=agent_h)
    monkeypatch.setattr(workspace_overlay, "compare_function_contracts", _no_comparison)
    res = _merge(run_dir, overlay)
    assert res["ok"] is True
    assert res["contract_changes"]["available"] is False and res["contract_changes"]["had_contract"] is False


# ---------------------------------------------------------------------------
# The parent WP report: `frame_summary.assigns_clause`
# ---------------------------------------------------------------------------


def _wp_report(tmp_path: Path, monkeypatch, name: str) -> dict:
    """run_wp_function.py's report for the recorded Frama-C output of `name` (tests/test_wp_frame_clause.py)."""

    def recorded(cmd, **_kwargs):
        if "-wp" in cmd and "-report-csv" in cmd:
            shutil.copyfile(WP_FIXTURES / f"{name}.csv", cmd[cmd.index("-report-csv") + 1])
            log = (WP_FIXTURES / f"{name}.log").read_text(encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout=log, stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    with monkeypatch.context() as patch:
        patch.setattr(W.subprocess, "run", recorded)
        report = W.run_wp_on_function(
            WP_FIXTURES / "src" / "frame.c",
            name,
            tmp_path / f"wp_{name}",
            cache_dir="off",
            retry_tail=False,
            retry_bitwise=False,
            retry_bytes=False,
            retry_cast_probe=False,
        )
    assert report["status"] == "all_proven"
    return report


def _parent_wp_answers(monkeypatch, report: dict) -> None:
    def fake_run(cmd, **_kwargs):
        if any(str(c).endswith("run_wp_function.py") for c in cmd):
            out = Path(cmd[cmd.index("--out-json") + 1])
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps({**report, "function": cmd[cmd.index("--function") + 1]}), encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(workspace_overlay.subprocess, "run", fake_run)


def _reverify(run_dir: Path, overlay: Path, **kwargs) -> tuple[bool, str]:
    return workspace_overlay._run_parent_reverify(
        run_dir, AGENT, "prover", overlay, C_REL, FN, None, None, "-I.", **kwargs
    )


@pytest.mark.parametrize("name, state", [("post_only", "absent"), ("guarded_some", "behaviors_only")])
def test_a_proved_contract_without_a_frame_is_refused_when_the_baseline_had_one(
    tmp_path: Path, monkeypatch, name: str, state: str
) -> None:
    report = _wp_report(tmp_path, monkeypatch, name)
    assert report["frame_summary"]["assigns_clause"] == state
    run_dir, overlay = _run(tmp_path)
    _parent_wp_answers(monkeypatch, report)
    ok, reason = _reverify(run_dir, overlay, baseline_had_assigns=True)
    assert not ok
    assert f"assigns_clause={state!r}" in reason and "`assigns` clause" in reason
    # Nothing is published for a contract that is not merged.
    assert not (overlay / "reports" / "wp" / f"{FN}.json").exists()


def test_a_function_that_never_had_a_frame_is_not_refused_for_having_none(tmp_path: Path, monkeypatch) -> None:
    report = _wp_report(tmp_path, monkeypatch, "post_only")
    run_dir, overlay = _run(tmp_path)
    _parent_wp_answers(monkeypatch, report)
    assert _reverify(run_dir, overlay, baseline_had_assigns=False) == (True, "verified")
    # A caller that says nothing about the baseline (a re-check of a merged function) is not refused either.
    assert _reverify(run_dir, overlay) == (True, "verified")


def test_a_proved_frame_is_accepted_when_the_baseline_had_one(tmp_path: Path, monkeypatch) -> None:
    report = _wp_report(tmp_path, monkeypatch, "pure_ok")
    assert report["frame_summary"]["assigns_clause"] == "present"
    run_dir, overlay = _run(tmp_path)
    _parent_wp_answers(monkeypatch, report)
    assert _reverify(run_dir, overlay, baseline_had_assigns=True) == (True, "verified")


def test_a_merge_without_a_frame_says_so_in_its_result(tmp_path: Path, monkeypatch) -> None:
    agent_h = TARGET_H.replace(PROTOTYPE, "/*@ ensures \\result >= -1; */\n" + PROTOTYPE)
    run_dir, overlay = _run(tmp_path, tree_h=TARGET_H, agent_h=agent_h)
    _parent_wp_answers(monkeypatch, _wp_report(tmp_path, monkeypatch, "post_only"))
    res = _merge(run_dir, overlay, skip_reverify=False)
    assert res["ok"] is True
    assert res["frame_state"] == {
        "assigns_clause": "absent",
        "assigns_vcs_proven": False,
        "baseline_had_assigns": False,
    }


def test_the_single_merge_tells_the_parent_check_that_the_baseline_had_a_frame(tmp_path: Path, monkeypatch) -> None:
    """The text keeps an `assigns`, WP reports none: the report decides, and the tree is rolled back."""
    agent_h = _with_register_contract(*KEPT, REMOVED_ASSIGNS, "ensures null_status: ctx == \\null ==> \\result == -1;")
    run_dir, overlay = _run(tmp_path, agent_h=agent_h)
    _parent_wp_answers(monkeypatch, _wp_report(tmp_path, monkeypatch, "post_only"))
    res = _merge(run_dir, overlay, skip_reverify=False)
    assert res["ok"] is False and res["rolled_back"] is True
    assert "assigns_clause='absent'" in res["reason"]
    assert (overlay / "work" / H_REL).read_text(encoding="utf-8") == ARCHITECT_H


def test_the_batch_merge_tells_the_parent_check_that_the_baseline_had_a_frame(tmp_path: Path, monkeypatch) -> None:
    agent_h = _with_register_contract(*KEPT, REMOVED_ASSIGNS, "ensures null_status: ctx == \\null ==> \\result == -1;")
    run_dir, overlay = _run(tmp_path, agent_h=agent_h)
    _parent_wp_answers(monkeypatch, _wp_report(tmp_path, monkeypatch, "post_only"))
    res = workspace_overlay.merge_agent_batch(
        run_dir, [{"agent_id": AGENT, "role": "prover", "file": C_REL, "function": FN}], overlay_dir=overlay
    )
    assert res["merged"] == []
    assert "assigns_clause='absent'" in res["failed"][0]["reason"]
    assert (overlay / "work" / H_REL).read_text(encoding="utf-8") == ARCHITECT_H


def test_the_batch_merge_records_contract_changes_and_the_frame_state(tmp_path: Path, monkeypatch) -> None:
    agent_h = _with_register_contract(*KEPT, REMOVED_ASSIGNS, "ensures null_status: ctx == \\null ==> \\result == -1;")
    run_dir, overlay = _run(tmp_path, agent_h=agent_h)
    _parent_wp_answers(monkeypatch, _wp_report(tmp_path, monkeypatch, "pure_ok"))
    res = workspace_overlay.merge_agent_batch(
        run_dir, [{"agent_id": AGENT, "role": "prover", "file": C_REL, "function": FN}], overlay_dir=overlay
    )
    (merged,) = res["merged"]
    assert merged["contract_changes"]["ensures_removed"] == [{"behavior": "default!", "clauses": ["\\result >= -1"]}]
    assert merged["frame_state"] == {
        "assigns_clause": "present",
        "assigns_vcs_proven": True,
        "baseline_had_assigns": True,
    }


# ---------------------------------------------------------------------------
# Complete-behaviors whole-function frame transitions (Task 2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("complete_clause", ["complete behaviors;", "complete behaviors null, live;"])
def test_default_assigns_replaced_by_complete_behaviors_with_assigns_merges(
    tmp_path: Path, complete_clause: str
) -> None:
    agent_h = _with_register_contract(*BEHAVIORS, complete_clause)
    run_dir, overlay = _run(tmp_path, agent_h=agent_h)
    res = _merge(run_dir, overlay)
    assert res["ok"] is True
    changes = res["contract_changes"]
    assert changes["baseline_has_whole_frame"] is True
    assert changes["candidate_has_whole_frame"] is True


@pytest.mark.parametrize(
    "clauses",
    [
        # Complete behaviors, but one behavior has no `assigns` clause.
        (BEHAVIORS[0], "behavior live: assumes ctx != \\null; ensures \\result >= -1;", "complete behaviors;"),
        # Both behaviors have `assigns`, but there is no `complete behaviors;` clause.
        (*BEHAVIORS, "disjoint behaviors;"),
    ],
)
def test_default_assigns_replaced_by_incomplete_behavior_frame_is_still_refused(
    tmp_path: Path, clauses: tuple[str, ...]
) -> None:
    agent_h = _with_register_contract(*clauses)
    run_dir, overlay = _run(tmp_path, agent_h=agent_h)
    with pytest.raises(AcslError, match=workspace_overlay.FRAME_REFUSAL):
        _merge(run_dir, overlay)
    assert (overlay / "work" / H_REL).read_text(encoding="utf-8") == ARCHITECT_H


def test_removing_complete_behaviors_coverage_of_a_whole_frame_is_refused(tmp_path: Path) -> None:
    tree_h = _with_register_contract(*BEHAVIORS, "complete behaviors;")
    agent_h = _with_register_contract(*BEHAVIORS)
    run_dir, overlay = _run(tmp_path, tree_h=tree_h, agent_h=agent_h)
    with pytest.raises(AcslError, match="complete behaviors"):
        _merge(run_dir, overlay)
    assert (overlay / "work" / H_REL).read_text(encoding="utf-8") == tree_h


def test_named_behavior_only_baseline_does_not_trigger_no_frame_refusal(tmp_path: Path, monkeypatch) -> None:
    tree_h = _with_register_contract("behavior live: assumes ctx != \\null; assigns *ctx;")
    agent_h = _with_register_contract("behavior live: assumes ctx != \\null; assigns *ctx; ensures \\result >= -1;")
    run_dir, overlay = _run(tmp_path, tree_h=tree_h, agent_h=agent_h)
    _parent_wp_answers(monkeypatch, _wp_report(tmp_path, monkeypatch, "guarded_some"))
    res = _merge(run_dir, overlay, skip_reverify=False)
    assert res["ok"] is True
    assert res["frame_state"] == {
        "assigns_clause": "behaviors_only",
        "assigns_vcs_proven": False,
        "baseline_had_assigns": False,
    }


# ---------------------------------------------------------------------------
# Architect merges: cannot silently delete an existing `assigns` clause (Task 1)
# ---------------------------------------------------------------------------

ARCH_AGENT = "arch-libmodbus"


def _arch_run(tmp_path: Path, tree_h: str = ARCHITECT_H, agent_h: str = PROVER_H) -> tuple[Path, Path]:
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / C_REL).write_text(SOURCE_C, encoding="utf-8")
    (target / H_REL).write_text(TARGET_H, encoding="utf-8")
    run_dir = (tmp_path / "run").resolve()
    overlay = run_dir / "workspace"
    workspace_overlay.init_overlay(target, overlay)
    (overlay / "work" / H_REL).write_text(tree_h, encoding="utf-8")
    workspace_overlay.init_agent_overlay(run_dir, ARCH_AGENT, overlay)
    (run_dir / "agents" / ARCH_AGENT / "scratch" / "work" / H_REL).write_text(agent_h, encoding="utf-8")
    return run_dir, overlay


def test_architect_deleting_existing_assigns_is_refused(tmp_path: Path) -> None:
    run_dir, overlay = _arch_run(tmp_path, tree_h=ARCHITECT_H, agent_h=PROVER_H)
    with pytest.raises(AcslError) as exc:
        workspace_overlay.merge_agent_overlay(
            run_dir=run_dir,
            agent_id=ARCH_AGENT,
            role="architect",
            overlay_dir=overlay,
            header_file=H_REL,
            skip_reverify=True,
        )
    message = str(exc.value)
    assert workspace_overlay.FRAME_REFUSAL in message
    assert FN in message and "`assigns *ctx \\from reg_addr, value`" in message
    assert (overlay / "work" / H_REL).read_text(encoding="utf-8") == ARCHITECT_H


def test_architect_deleting_existing_assigns_is_refused_in_batch_and_dry_run(tmp_path: Path) -> None:
    run_dir, overlay = _arch_run(tmp_path, tree_h=ARCHITECT_H, agent_h=PROVER_H)
    dry = workspace_overlay.merged_frame_refusal(
        run_dir, None, None, H_REL, None, "-I.", {H_REL: PROVER_H}, role="architect"
    )
    assert dry is not None and workspace_overlay.FRAME_REFUSAL in dry and FN in dry
    res = workspace_overlay.merge_agent_batch(
        run_dir,
        [{"agent_id": ARCH_AGENT, "role": "architect", "header": H_REL}],
        overlay_dir=overlay,
        skip_reverify=True,
    )
    assert res["merged"] == []
    (failed,) = res["failed"]
    assert workspace_overlay.FRAME_REFUSAL in failed["reason"] and FN in failed["reason"]
    assert (overlay / "work" / H_REL).read_text(encoding="utf-8") == ARCHITECT_H


def test_architect_adding_or_tightening_header_contracts_merges_cleanly(tmp_path: Path) -> None:
    tightened_h = _with_register_contract(*KEPT, "assigns ctx->debug \\from value;", "ensures status: \\result >= -1;")
    run_dir, overlay = _arch_run(tmp_path, tree_h=ARCHITECT_H, agent_h=tightened_h)
    res = workspace_overlay.merge_agent_overlay(
        run_dir=run_dir,
        agent_id=ARCH_AGENT,
        role="architect",
        overlay_dir=overlay,
        header_file=H_REL,
        skip_reverify=True,
    )
    assert res["ok"] is True
    assert res["contract_changes"]["available"] is True
    assert res["contract_changes"]["assigns_removed"] == []
    assert res["contract_changes"]["ensures_removed"] == []
    assert FN in res["contract_changes"]["functions"]
    assert (overlay / "work" / H_REL).read_text(encoding="utf-8") == tightened_h

    # Adding a brand-new contract to an unannotated header also merges cleanly.
    run_dir2, overlay2 = _arch_run(tmp_path / "fresh", tree_h=TARGET_H, agent_h=ARCHITECT_H)
    res2 = workspace_overlay.merge_agent_overlay(
        run_dir=run_dir2,
        agent_id=ARCH_AGENT,
        role="architect",
        overlay_dir=overlay2,
        header_file=H_REL,
        skip_reverify=True,
    )
    assert res2["ok"] is True and res2["contract_changes"]["assigns_removed"] == []


def test_architect_removing_ensures_while_keeping_assigns_merges_and_records_change(tmp_path: Path) -> None:
    agent_h = _with_register_contract(*KEPT, REMOVED_ASSIGNS, "ensures null_status: ctx == \\null ==> \\result == -1;")
    run_dir, overlay = _arch_run(tmp_path, tree_h=ARCHITECT_H, agent_h=agent_h)
    res = workspace_overlay.merge_agent_overlay(
        run_dir=run_dir,
        agent_id=ARCH_AGENT,
        role="architect",
        overlay_dir=overlay,
        header_file=H_REL,
        skip_reverify=True,
    )
    assert res["ok"] is True
    assert res["contract_changes"]["assigns_removed"] == []
    assert res["contract_changes"]["ensures_removed"] == [
        {"behavior": "default!", "clauses": ["\\result >= -1"], "function": FN}
    ]


def test_architect_deleting_assigns_on_static_inline_header_definition_is_refused(tmp_path: Path) -> None:
    base_h = "static inline int bump(int *p) { *p = 1; return 0; }\n"
    framed_h = "/*@ requires \\valid(p);\n    assigns *p;\n*/\n" + base_h
    stripped_h = "/*@ requires \\valid(p);\n    ensures \\result == 0;\n*/\n" + base_h
    target = tmp_path / "target"
    target.mkdir()
    (target / "inline.h").write_text(base_h, encoding="utf-8")
    run_dir = (tmp_path / "run").resolve()
    overlay = run_dir / "workspace"
    workspace_overlay.init_overlay(target, overlay)
    (overlay / "work" / "inline.h").write_text(framed_h, encoding="utf-8")
    workspace_overlay.init_agent_overlay(run_dir, ARCH_AGENT, overlay)
    (run_dir / "agents" / ARCH_AGENT / "scratch" / "work" / "inline.h").write_text(stripped_h, encoding="utf-8")
    with pytest.raises(AcslError, match=r"bump.*assigns \*p"):
        workspace_overlay.merge_agent_overlay(
            run_dir=run_dir,
            agent_id=ARCH_AGENT,
            role="architect",
            overlay_dir=overlay,
            header_file="inline.h",
            skip_reverify=True,
        )
    assert (overlay / "work" / "inline.h").read_text(encoding="utf-8") == framed_h
