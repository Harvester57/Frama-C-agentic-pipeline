"""Specification knowledge base (scripts/spec_kb.py): seed build from the reference
manuals, keyword retrieval, brief section, trajectory mining, repair hints, kill-switch."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import spec_kb  # noqa: E402
from run_wp_function import derive_wp_diagnostic_hints  # noqa: E402


def _fake_references(tmp_path: Path) -> Path:
    refs = tmp_path / "references"
    (refs / "acsl").mkdir(parents=True)
    manual = refs / "acsl" / "frama-c-acsl-implementation.md"
    manual.write_text(
        "# ACSL\n"
        "line2\n"
        "line3\n"
        "## 2.3 Function contracts\n"
        "requires assigns ensures behavior clauses order\n"
        "\\valid \\separated memory locations\n"
        "line8\n"
        "## 2.4.2 Loop annotations\n"
        "loop invariant loop assigns loop variant decreases\n"
        "\\forall integer k; 0 <= k < n ==> a[k] == 0\n",
        encoding="utf-8",
    )
    (refs / "INDEX.md").write_text(
        "# index\n"
        "acsl/frama-c-acsl-implementation.md:4-6   2.3 Function contracts  (p. 13)\n"
        "acsl/frama-c-acsl-implementation.md:8-10   2.4.2 Loop annotations  (p. 20)\n",
        encoding="utf-8",
    )
    return refs


def test_build_seed_kb_slices_index_sections_with_keywords(tmp_path: Path) -> None:
    kb = spec_kb.build_seed_kb(_fake_references(tmp_path))
    assert kb["kind"] == "seed" and len(kb["items"]) == 2
    contracts, loops = kb["items"]
    assert contracts["title"] == "2.3 Function contracts"
    assert "\\valid" in contracts["keywords"] and "separated" in contracts["keywords"]
    assert "loop invariant" in loops["content"]
    assert "loop" in loops["keywords"] and "\\forall" in loops["keywords"]


def test_query_kb_ranks_by_keyword_overlap(tmp_path: Path) -> None:
    kb = spec_kb.build_seed_kb(_fake_references(tmp_path))
    hits = spec_kb.query_kb(kb, "loop invariant loop assigns loop variant decreases")
    assert hits and "Loop annotations" in hits[0]["title"]
    hits = spec_kb.query_kb(kb, "\\valid \\separated requires assigns memory locations")
    assert hits and "Function contracts" in hits[0]["title"]
    assert spec_kb.query_kb(kb, "completely unrelated zzz qqq") == []


def test_function_query_uses_features_skeleton_and_loop_classes() -> None:
    record = {
        "features": {"loops": True, "strings": True, "floats": False},
        "frame_skeleton": {
            "status": "ok",
            "separated": [{"clause": "requires \\separated(buf + (0 .. 1), out);"}],
            "assigns": [{"clause": "assigns *out \\from buf + (0 .. 1), len;"}],
        },
        "loops": [{"guard": "i < n", "var_classes": {"inductive": ["i"], "unchanged": [], "non_inductive": []}}],
        "may_alias": [{"a": "buf", "b": "out"}],
    }
    q = spec_kb.function_query(record)
    assert "loop invariant" in q and "valid_read_nstring" in q
    assert "\\separated" in q and "assigns \\from" in q and "inductive" in q and "i < n" in q


def test_kb_section_for_renders_top_items_and_kill_switch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    overlay = tmp_path / "workspace"
    kb_dir = spec_kb.kb_dir_of(overlay)
    kb_dir.mkdir(parents=True)
    seed = spec_kb.build_seed_kb(_fake_references(tmp_path))
    (kb_dir / "seed.json").write_text(json.dumps(seed), encoding="utf-8")
    record = {
        "features": {"loops": True},
        "frame_skeleton": {"status": "ok", "separated": [], "assigns": []},
        "loops": [],
        "may_alias": [],
    }
    section = spec_kb.kb_section_for(overlay, record)
    assert "## Retrieved ACSL Knowledge" in section
    assert "Loop annotations" in section
    monkeypatch.setenv(spec_kb.KB_ENV, "off")
    assert spec_kb.kb_section_for(overlay, record) == ""
    assert spec_kb.enabled() is False


def _fake_run(tmp_path: Path) -> Path:
    run_dir = tmp_path / "run"
    agent = run_dir / "agents" / "prover-1"
    (agent / "scratch" / "candidates" / "c1").mkdir(parents=True)
    (agent / "scratch" / "candidates" / "c1" / "wp_f.json").write_text(
        json.dumps(
            {
                "status": "unproven_goals_remain",
                "function": "f",
                "unproven_goals": [
                    {"kind": "loop_invariant", "annotation": "typed_f_loop_invariant_bound_preserved", "line": 4}
                ],
            }
        ),
        encoding="utf-8",
    )
    (agent / "scratch" / "result.json").write_text(json.dumps({"status": "all_proven"}), encoding="utf-8")
    (agent / "artifacts").mkdir(parents=True)
    (agent / "artifacts" / "f.patch").write_text(
        "--- a/m.c\n+++ b/m.c\n@@ -4,1 +4,2 @@\n int f(void) {\n+  /*@ loop invariant bound: 0 <= i <= n; */\n+  //@ assert \\valid(p);\n",
        encoding="utf-8",
    )
    # A stalled agent contributing a harmful vote for the same error.
    agent2 = run_dir / "agents" / "prover-2"
    (agent2 / "scratch" / "candidates" / "c1").mkdir(parents=True)
    (agent2 / "scratch" / "candidates" / "c1" / "wp_g.json").write_text(
        json.dumps(
            {
                "function": "g",
                "unproven_goals": [{"kind": "loop_invariant", "annotation": "typed_g_loop_invariant_bound_preserved"}],
            }
        ),
        encoding="utf-8",
    )
    (agent2 / "scratch" / "result.json").write_text(json.dumps({"status": "stalled_after_k_retries"}), encoding="utf-8")
    (agent2 / "artifacts").mkdir(parents=True)
    (agent2 / "artifacts" / "g.patch").write_text(
        "--- a/m.c\n+++ b/m.c\n@@ -1,1 +1,2 @@\n+//@ assert \\true;\n", encoding="utf-8"
    )
    return run_dir


def test_mine_run_builds_helpfulness_scored_repair_items(tmp_path: Path) -> None:
    run_dir = _fake_run(tmp_path)
    out = run_dir / "workspace" / "reports" / "kb" / "evolved.json"
    evolved = spec_kb.mine_run(run_dir, out)
    items = {it["id"]: it for it in evolved["items"]}
    item = items["err:loop_invariant:loop_invariant_bound_preserved"]
    assert item["helpful"] == 1 and item["harmful"] == 1
    assert "loop invariant bound: 0 <= i <= n;" in item["fix"]
    assert "\\valid(p)" in item["fix"]
    assert json.loads(out.read_text(encoding="utf-8"))["schema"] == spec_kb.KB_SCHEMA


def test_mine_run_prunes_to_top_l(tmp_path: Path) -> None:
    run_dir = _fake_run(tmp_path)
    evolved = spec_kb.mine_run(run_dir, top_l=0)
    assert evolved["items"] == []


def test_repair_hints_from_evolved_kb(tmp_path: Path) -> None:
    run_dir = _fake_run(tmp_path)
    kb_dir = run_dir / "workspace" / "reports" / "kb"
    spec_kb.mine_run(run_dir, kb_dir / "evolved.json")
    res = {
        "status": "unproven_goals_remain",
        "soundness": {"ok": True},
        "unproven_by_bucket": {"step_b_loop_invariant": [{"kind": "loop_invariant"}]},
        "unproven_goals": [
            {"kind": "loop_invariant", "annotation": "typed_h_loop_invariant_bound_preserved", "line": 9}
        ],
    }
    hints = derive_wp_diagnostic_hints(res, kb_dir=kb_dir)
    assert any("Repair pattern from earlier runs" in h and "loop_invariant_bound_preserved" in h for h in hints), hints
    # Kill-switch: no repair hints when the KB is off.
    import pytest as _pt  # noqa: F401


def test_repair_hints_disabled_by_kill_switch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_dir = _fake_run(tmp_path)
    kb_dir = run_dir / "workspace" / "reports" / "kb"
    spec_kb.mine_run(run_dir, kb_dir / "evolved.json")
    monkeypatch.setenv(spec_kb.KB_ENV, "off")
    res = {
        "status": "unproven_goals_remain",
        "soundness": {"ok": True},
        "unproven_by_bucket": {"step_b_loop_invariant": [{"kind": "loop_invariant"}]},
        "unproven_goals": [
            {"kind": "loop_invariant", "annotation": "typed_h_loop_invariant_bound_preserved", "line": 9}
        ],
    }
    assert not any("Repair pattern" in h for h in derive_wp_diagnostic_hints(res, kb_dir=kb_dir))


def test_brief_gets_kb_section_via_prepare_agent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import function_facts as ff
    import workspace_overlay

    refs = _fake_references(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    (target / "mod.h").write_text("int sum_clamped(const int *src, int n, int *out_sum);\n", encoding="utf-8")
    (target / "mod.c").write_text(
        '#include "mod.h"\nint sum_clamped(const int *src, int n, int *out_sum) { *out_sum = 0; return 0; }\n',
        encoding="utf-8",
    )
    run_dir = tmp_path / "run"
    overlay = run_dir / "workspace"
    workspace_overlay.init_overlay(target, overlay)
    # Seed KB + facts for the function, so the KB section is rendered.
    kb_dir = spec_kb.kb_dir_of(overlay)
    kb_dir.mkdir(parents=True)
    (kb_dir / "seed.json").write_text(json.dumps(spec_kb.build_seed_kb(refs)), encoding="utf-8")
    facts_dir = overlay / "reports" / "facts"
    facts_dir.mkdir(parents=True)
    (facts_dir / "mod.json").write_text(
        json.dumps(
            {
                "schema": ff.FACTS_SCHEMA,
                "module": "mod",
                "functions": {
                    "mod.c#sum_clamped": {
                        "name": "sum_clamped",
                        "features": {"loops": True, "pointer_len_params": True},
                        "frame_skeleton": {"status": "ok", "separated": [], "assigns": []},
                        "loops": [],
                        "may_alias": [],
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("FRAMAC_REFERENCES_HOST", str(refs))
    prep = workspace_overlay.prepare_agent(
        run_dir=run_dir,
        agent_id="prover_sum",
        role="prover",
        module="mod",
        function="sum_clamped",
        c_file="mod.c",
        header_file="mod.h",
    )
    brief = (run_dir / prep["brief_file"]).read_text(encoding="utf-8")
    assert spec_kb.KB_SENTINEL not in brief
    assert "## Retrieved ACSL Knowledge" in brief
    assert "Loop annotations" in brief
    # Kill-switch: the section disappears.
    monkeypatch.setenv(spec_kb.KB_ENV, "off")
    prep2 = workspace_overlay.prepare_agent(
        run_dir=run_dir,
        agent_id="prover_sum2",
        role="prover",
        module="mod",
        function="sum_clamped",
        c_file="mod.c",
        header_file="mod.h",
    )
    brief2 = (run_dir / prep2["brief_file"]).read_text(encoding="utf-8")
    assert "Retrieved ACSL Knowledge" not in brief2


# ---------------------------------------------------------------------------
# Obstructions: dead ends not to repeat
# ---------------------------------------------------------------------------


def _write(path: Path, doc: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc), encoding="utf-8")


def _guard(run_dir: Path, agent: str, cand: int, status: str, predicate: str, **failure: object) -> None:
    scratch = run_dir / "agents" / agent / "scratch"
    _write(scratch / ".prover_budget.json", {"function": "parse", "file": "src/p.c"})
    _write(
        scratch / "candidates" / f"c{cand}" / "guard_parse.json",
        {
            "status": status,
            "failure": {
                "function": "parse",
                "line": 12,
                "kind": "postcondition",
                "label": "bound",
                "predicate": predicate,
                **failure,
            },
        },
    )


def _obstruction_run(tmp_path: Path) -> Path:
    run_dir = tmp_path / "run"
    _guard(run_dir, "prove-parse", 3, "rejected_overconstrained", "\\result <= 64")
    _guard(run_dir, "prove-parse-2", 1, "rejected_overconstrained", "\\result <= 64")
    _guard(run_dir, "prove-parse-2", 2, "code_fault", "rte: mem_access: \\valid_read(p)", is_rte=True)
    _guard(run_dir, "prove-parse-3", 1, "rejected_overconstrained", "n / d > 0", annotation_rte=True)
    _write(
        run_dir / "workspace" / "reports" / "strengthen_requests.json",
        {
            "requests": [
                {
                    "id": "r1",
                    "status": "rejected_by_callee",
                    "caller_function": "read_pkt",
                    "callee_function": "parse_hdr",
                    "callee_file": "src/h.c",
                    "needed_clause": "ensures \\result <= 64;",
                    "resolution_note": "the header length field is attacker-controlled: no bound holds",
                },
                {
                    "id": "r2",
                    "status": "rejected_by_callee",
                    "caller_function": "read_pkt",
                    "callee_function": "missing",
                    "needed_clause": "ensures \\result > 0;",
                    "resolution_note": "not dispatched: callee not found in the ledger or the call graph",
                },
                {
                    "id": "r3",
                    "status": "pending",
                    "caller_function": "read_pkt",
                    "callee_function": "parse_hdr",
                    "needed_clause": "ensures \\result >= 0;",
                },
            ]
        },
    )
    return run_dir


def test_mine_obstructions_merges_refutations_and_keeps_only_real_rejections(tmp_path: Path) -> None:
    run_dir = _obstruction_run(tmp_path)
    doc = spec_kb.mine_obstructions(run_dir)
    out = spec_kb.kb_dir_of(run_dir / "workspace") / spec_kb.OBSTRUCTIONS_FILE
    assert json.loads(out.read_text(encoding="utf-8"))["schema"] == spec_kb.OBSTRUCTION_SCHEMA
    items = doc["items"]
    guards = [it for it in items if it["kind"] == "guardrail_refutation"]
    reqs = [it for it in items if it["kind"] == "rejected_strengthening"]
    assert len(guards) == 2  # the code_fault is a code defect candidate, not a dead end
    bound = next(it for it in guards if it["predicate"] == "\\result <= 64")
    assert bound["seen"] == 2 and bound["function"] == "parse" and bound["file"] == "src/p.c"
    assert bound["annotation_rte"] is False and bound["id"].startswith("guard:parse:")
    assert next(it for it in guards if it["predicate"] == "n / d > 0")["annotation_rte"] is True
    assert [it["id"] for it in reqs] == ["req:r1"]
    # Mining again sees no new source: nothing is counted twice.
    again = spec_kb.mine_obstructions(run_dir)
    assert next(it for it in again["items"] if it["id"] == bound["id"])["seen"] == 2


def test_mine_run_fills_the_obstruction_store_and_never_raises(tmp_path: Path) -> None:
    run_dir = _obstruction_run(tmp_path)
    (run_dir / "agents" / "prove-parse" / "scratch" / "candidates" / "c9").mkdir()
    (run_dir / "agents" / "prove-parse" / "scratch" / "candidates" / "c9" / "guard_parse.json").write_text(
        "{broken", encoding="utf-8"
    )
    spec_kb.mine_run(run_dir)
    out = spec_kb.kb_dir_of(run_dir / "workspace") / spec_kb.OBSTRUCTIONS_FILE
    assert len(json.loads(out.read_text(encoding="utf-8"))["items"]) == 3
    assert spec_kb.mine_obstructions(tmp_path / "nowhere", tmp_path / "o.json")["items"] == []


def test_obstructions_for_filters_by_function_and_callee_and_caps(tmp_path: Path) -> None:
    run_dir = _obstruction_run(tmp_path)
    overlay = run_dir / "workspace"
    spec_kb.mine_obstructions(run_dir)
    got = spec_kb.obstructions_for(overlay, "parse", ["src/h.c#parse_hdr"])
    assert [it["kind"] for it in got] == ["guardrail_refutation"] * 2 + ["rejected_strengthening"]
    assert spec_kb.obstructions_for(overlay, "other", ["parse_hdr"])[0]["id"] == "req:r1"
    assert spec_kb.obstructions_for(overlay, "other", ["other_callee"]) == []
    extra = [
        {"kind": "guardrail_refutation", "function": "parse", "predicate": f"x > {i}", "candidate": i}
        for i in range(20)
    ]
    capped = spec_kb.obstructions_for(overlay, "parse", ["parse_hdr"], extra)
    assert len(capped) == spec_kb.MAX_OBSTRUCTIONS_RENDERED
    assert capped[0]["predicate"] == "x > 0"


def test_obstructions_for_reads_live_rejections_before_any_mining(tmp_path: Path) -> None:
    run_dir = _obstruction_run(tmp_path)
    got = spec_kb.obstructions_for(run_dir / "workspace", "read_pkt", ["parse_hdr"])
    assert [it["id"] for it in got] == ["req:r1"]


def test_obstructions_section_renders_both_wordings_and_honours_the_kill_switch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir = _obstruction_run(tmp_path)
    overlay = run_dir / "workspace"
    spec_kb.mine_obstructions(run_dir)
    text = spec_kb.obstructions_section_for(overlay, "parse", ["parse_hdr"])
    assert text.startswith("## Known Dead Ends (Do Not Repeat)")
    assert "`\\result <= 64` (line 12, label `bound`): failed under E-ACSL on a corpus input (candidate" in text
    assert "`n / d > 0` (line 12, label `bound`): evaluated an undefined term at runtime" in text
    assert "Callee `parse_hdr`: `ensures \\result <= 64;` was requested by `read_pkt` and could not be proven" in text
    assert "not dispatched" not in text and "valid_read" not in text
    assert spec_kb.obstructions_section_for(overlay, "unrelated", []) == ""
    monkeypatch.setenv(spec_kb.KB_ENV, "off")
    assert spec_kb.obstructions_section_for(overlay, "parse", ["parse_hdr"]) == ""


def test_mine_run_counts_each_agent_once(tmp_path: Path) -> None:
    # The scheduler mines after every `complete`: an agent mined before must not vote again.
    run_dir = _fake_run(tmp_path)
    spec_kb.mine_run(run_dir)
    evolved = spec_kb.mine_run(run_dir)
    item = {it["id"]: it for it in evolved["items"]}["err:loop_invariant:loop_invariant_bound_preserved"]
    assert item["helpful"] == 1 and item["harmful"] == 1
    assert evolved["mined_agents"] == ["prover-1", "prover-2"]


def test_finished_only_leaves_a_running_agent_for_later(tmp_path: Path) -> None:
    run_dir = _fake_run(tmp_path)
    result = run_dir / "agents" / "prover-2" / "scratch" / "result.json"
    saved = result.read_text(encoding="utf-8")
    result.unlink()
    evolved = spec_kb.mine_run(run_dir, finished_only=True)
    assert evolved["mined_agents"] == ["prover-1"]
    result.write_text(saved, encoding="utf-8")
    evolved = spec_kb.mine_run(run_dir, finished_only=True)
    item = {it["id"]: it for it in evolved["items"]}["err:loop_invariant:loop_invariant_bound_preserved"]
    assert evolved["mined_agents"] == ["prover-1", "prover-2"] and item["harmful"] == 1


def test_mine_after_complete_fills_both_stores_unless_switched_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir = _fake_run(tmp_path)
    monkeypatch.setenv("FRAMAC_SPEC_KB", "off")
    assert spec_kb.mine_after_complete(run_dir) == {"skipped": "FRAMAC_SPEC_KB=off"}
    assert not (run_dir / "workspace" / "reports" / "kb").exists()
    monkeypatch.delenv("FRAMAC_SPEC_KB")
    out = spec_kb.mine_after_complete(run_dir)
    assert out["mined_agents"] == 2 and out["evolved_items"] >= 1
    kb = run_dir / "workspace" / "reports" / "kb"
    assert (kb / "evolved.json").is_file() and (kb / spec_kb.OBSTRUCTIONS_FILE).is_file()
