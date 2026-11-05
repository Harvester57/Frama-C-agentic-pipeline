"""Phase-3 scheduler on synthetic runs: dependencies, gates, merges, negotiation and recovery (fake overlays)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

import checkpoint
import ledger as L
import workspace_overlay
import wp_scheduler as S
from conftest import evidence, unit, write_json
from fingerprint import make_fingerprint

TIER1 = "Tier 1A (Untrusted Binary / Network Parser)"


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def tasks():
    return load("state/wp_schedule.json")["tasks"]


def units():
    return {u["coverage_id"]: u for u in load("coverage-ledger.json")}


def ids(out):
    return [t["task"] for t in out["tasks"]]


def ready():
    return [r["task"] for r in S.cmd_status()["ready"]]


def wp_report(fn, file_field, status="all_proven", reason=None):
    goals: list[dict]
    if status == "all_proven":
        by_class, goals = {"rte": {"proven": 2, "proven_under_hyp": 0, "unproven": 0}}, []
    elif status == "analysis_error":
        by_class, goals = {}, []
    else:
        by_class = {"rte": {"proven": 1, "proven_under_hyp": 0, "unproven": 1}}
        goals = [{"obligation_class": "rte", "kind": "assert", "line": 3, "annotation": "p != 0"}]
    report = {
        "status": status,
        "function": fn,
        "file": file_field,
        "by_obligation_class": by_class,
        "unproven_goals": goals,
        "limits": {"vacuity": {"status": "consistent", "doomed": [], "dead_goals": 0}},
    }
    if reason:
        report["reason"] = reason
    return report


def request(callee, n):
    return {
        "callee": callee,
        "callee_file": f"src/m/{callee}.c",
        "header_file": f"src/m/{callee}.h",
        "needed_clause": f"ensures R{n}: n >= {n};",
        "reason": f"the caller needs bound {n}",
    }


class Sim:
    """A synthetic run directory with fake overlay operations (no Frama-C, no work tree)."""

    def __init__(self, run_dir: Path, monkeypatch):
        self.run_dir = run_dir
        self.prepared: list[tuple] = []
        self.merge_calls: list[list[str]] = []
        self.merge_fail: dict[str, str] = {}
        self.parent_status: dict[str, str] = {}
        self.modified: dict[str, list[str]] = {}
        self.recheck_calls: list[str] = []
        self.recheck_ok: dict[str, bool] = {}
        self.arch_merges: list[tuple] = []
        self.on_prepare = None
        self.clock = 1_000_000.0
        monkeypatch.setattr(S.DEPS, "prepare_agent", self.prepare_agent)
        monkeypatch.setattr(S.DEPS, "merge_agent_batch", self.merge_agent_batch)
        monkeypatch.setattr(S.DEPS, "merge_agent_overlay", self.merge_agent_overlay)
        monkeypatch.setattr(S.DEPS, "recheck_function", self.recheck_function)
        monkeypatch.setattr(S.DEPS, "recommend", lambda max_agents=None: {"max_agents": max_agents or 8})
        monkeypatch.setattr(S.DEPS, "now", lambda: self.clock)
        monkeypatch.delenv("FRAMAC_SCHEDULER", raising=False)

    # ----------------------------------------------------------------- run setup

    def build(self, functions, *, units=None, extra_units=(), collisions=(), sidecars=None, modules=None):
        """functions: {name: (file, module, [callees])}; one planned rte unit each unless `units` is given."""
        dag_fns: dict[str, dict] = {}
        mods: dict[str, dict] = {}
        for name, (file, module, callees) in functions.items():
            dag_fns[name] = {"name": name, "file": file, "module": module, "internal_callees": list(callees), "wave": 0}
            mod = mods.setdefault(module, {"tier": TIER1, "files": [], "run_eva": True, "run_eacsl_fuzz": True})
            if file not in mod["files"]:
                mod["files"].append(file)
        for name, rec in dag_fns.items():
            rec["internal_callers"] = sorted(n for n, other in dag_fns.items() if name in other["internal_callees"])
        for name, mod in mods.items():
            mod["required_sources"] = sorted(mod["files"])
            mod.update((modules or {}).get(name, {}))
        modules = mods
        write_json(
            self.run_dir / "workspace/reports/callgraph_dag.json",
            {
                "functions": dag_fns,
                "modules": modules,
                "name_collisions": list(collisions),
                "recursion_cycles": [],
            },
        )
        if units is None:
            units = [
                unit(file, name, "rte", module=module, tier=TIER1) for name, (file, module, _) in functions.items()
            ]
        all_units = sorted([*units, *extra_units], key=lambda u: u["coverage_id"])
        write_json(self.run_dir / "coverage-ledger.json", all_units)
        write_json(self.run_dir / "candidates.json", [])
        for mod, extra in (sidecars or {}).items():
            write_json(
                self.run_dir / f"workspace/harnesses/harness_{mod}.json",
                {
                    "module": mod,
                    "sources": [],
                    "cppflags": "-I.",
                    "repair_attempts": 0,
                    "max_repair_attempts": 2,
                    **extra,
                },
            )

    def eva_candidate(self, module, file, fn):
        """An Eva Invalid alarm: a real candidate, its unit moved to `candidate` by the ledger."""
        path = self.run_dir / f"workspace/reports/eva/{module}.json"
        write_json(
            path,
            {
                "status": "ok",
                "module": module,
                "unknown_obligations_by_function": {},
                "invalid_alarms": [
                    {"file": file, "function": fn, "line": 3, "kind": "mem_access", "annotation": "p != 0"}
                ],
                "dead_alarms": [],
                "assumed_properties": [],
                "functions_with_properties": [fn],
            },
        )
        L.cmd_ingest_eva([path])
        return [c["fingerprint"] for c in load("candidates.json") if c["location"]["function"] == fn][0]

    # ------------------------------------------------------------- agent results

    def prover(self, aid, fn, file, status="all_proven", requests=(), hypothesis=None, wp_status=None, wp_reason=None):
        report = f"agents/{aid}/scratch/wp_{fn}.json"
        wp_status = wp_status or ("all_proven" if status == "all_proven" else "unproven_goals_remain")
        write_json(self.run_dir / report, wp_report(fn, f"agents/{aid}/scratch/work/{file}", wp_status, wp_reason))
        write_json(
            self.run_dir / f"agents/{aid}/scratch/result.json",
            {
                "role": "prover",
                "agent_id": aid,
                "file": file,
                "function": fn,
                "status": status,
                "patch": None,
                "evidence": [{"tool_output": report, "result": wp_status}],
                "unproven_goals": [] if status == "all_proven" else [{"line": 3, "annotation": "p != 0"}],
                "strengthening_requests": [dict(r) for r in requests],
                "boundary_assumptions": [],
                "fault_hypothesis": hypothesis,
            },
        )

    def architect(self, aid, header, status="passed"):
        write_json(
            self.run_dir / f"agents/{aid}/scratch/result.json",
            {
                "role": "architect",
                "agent_id": aid,
                "header": header,
                "status": status,
                "patch": None,
                "evidence": [{"tool_output": f"agents/{aid}/scratch/notes.txt", "result": status}],
                "boundary_assumptions": [],
                "notes": "",
            },
        )

    def breaker(self, aid, fn, file, crash=False, hypothesis=None):
        scratch = self.run_dir / f"agents/{aid}/scratch"
        scratch.mkdir(parents=True, exist_ok=True)
        seeds = []
        if crash:
            (scratch / "seed-1").write_bytes(b"\x02\x03")
            (scratch / "crash-1").write_bytes(b"\x00\x01")
            seeds = [f"agents/{aid}/scratch/seed-1"]
        write_json(
            scratch / "result.json",
            {
                "role": "breaker",
                "agent_id": aid,
                "file": file,
                "function": fn,
                "status": "crash_found" if crash else "clean",
                "seeds": seeds,
                "crash_artifact": f"agents/{aid}/scratch/crash-1" if crash else None,
                "failing_predicate": "p != 0" if crash else None,
                "analysis": "Probed the length field.",
                "suggested_requires": None,
                "fault_hypothesis": hypothesis,
            },
        )

    def finish(self, aid, fn, file, force=False):
        """A prover proves its function and the result is merged."""
        self.prover(aid, fn, file)
        assert S.cmd_complete(aid)["action"] == "queued_for_merge"
        out = S.cmd_merge_pending(force=force)
        assert any(m["agent_id"] == aid for m in out["merged"]), out
        return out

    # ------------------------------------------------------------ fake overlays

    def prepare_agent(self, run_dir, agent_id, role, **kw):
        self.prepared.append((agent_id, role, kw))
        if self.on_prepare:
            self.on_prepare(agent_id, role, kw)
        (Path(run_dir) / "agents" / agent_id / "scratch").mkdir(parents=True, exist_ok=True)
        (Path(run_dir) / "agents" / agent_id / "brief.md").write_text(f"brief for {agent_id}\n", encoding="utf-8")
        return {"ok": True, "agent_id": agent_id, "role": role, "brief_file": f"agents/{agent_id}/brief.md"}

    def merge_agent_batch(self, run_dir, entries, **kw):
        self.merge_calls.append([e["agent_id"] for e in entries])
        merged, failed = [], []
        for e in entries:
            aid, fn = e["agent_id"], e["function"]
            status = self.parent_status.get(aid, "unproven_goals_remain" if aid in self.merge_fail else "all_proven")
            rel = f"agents/{aid}/scratch/parent_wp/{fn}.json"
            write_json(self.run_dir / rel, wp_report(fn, f"workspace/work/{e['file']}", status, "oom_killed"))
            if aid in self.merge_fail:
                failed.append({"ok": False, "rolled_back": True, "agent_id": aid, "reason": self.merge_fail[aid]})
            else:
                merged.append(
                    {"ok": True, "agent_id": aid, "modified_files": self.modified.get(aid, []), "parent_wp_report": rel}
                )
        return {"ok": not failed, "batch_verified": True, "bisected": bool(failed), "merged": merged, "failed": failed}

    def merge_agent_overlay(self, run_dir, agent_id, role, **kw):
        self.arch_merges.append((agent_id, role, kw))
        return {
            "ok": agent_id not in self.merge_fail,
            "agent_id": agent_id,
            "modified_files": self.modified.get(agent_id, []),
            "reason": self.merge_fail.get(agent_id),
        }

    def recheck_function(self, run_dir, agent_id, file, function, module):
        self.recheck_calls.append(function)
        ok = self.recheck_ok.get(function, True)
        rel = f"agents/{agent_id}/scratch/parent_wp/{function}.json"
        write_json(
            self.run_dir / rel,
            wp_report(function, f"workspace/work/{file}", "all_proven" if ok else "unproven_goals_remain"),
        )
        return {
            "ok": ok,
            "reason": "verified" if ok else "parent WP check returned status='unproven_goals_remain'",
            "report": rel,
        }


@pytest.fixture
def sim(run_dir, monkeypatch):
    return Sim(run_dir, monkeypatch)


# ---------------------------------------------------------------------------
# Dependency shapes
# ---------------------------------------------------------------------------


def test_chain_runs_callees_first_and_callers_wait_for_the_merge(sim, capsys):
    sim.build({"a": ("src/m/a.c", "m", ["b"]), "b": ("src/m/b.c", "m", ["c"]), "c": ("src/m/c.c", "m", [])})
    checkpoint.cmd_init(Path("state"), "/target", "verify")
    init = S.cmd_init()
    assert init["by_kind"] == {"prove": {"pending": 3}} and init["waves"] == 3
    t = tasks()
    assert t["prove:src/m/a.c#a"]["deps"] == ["gate:m", "prove:src/m/b.c#b"]
    assert [t[f"prove:src/m/{n}.c#{n}"]["height"] for n in "abc"] == [0, 1, 2]
    queue = load("workspace/reports/wp_queue.json")
    assert [w["functions"] for w in queue["waves"]] == [["src/m/c.c#c"], ["src/m/b.c#b"], ["src/m/a.c#a"]]
    assert [q["function"] for q in queue["queue"]] == ["c", "b", "a"]

    nxt = S.cmd_next("auto", prepare=True)
    assert ids(nxt) == ["prove:src/m/c.c#c"] and nxt["slots"]["available"] == 8
    task = nxt["tasks"][0]
    assert (task["agent_id"], task["role"], task["brief_file"]) == ("prove-c", "prover", "agents/prove-c/brief.md")
    assert task["coverage_ids"] == ["src/m/c.c#c::rte"] and nxt["briefs"] == ["agents/prove-c/brief.md"]
    assert sim.prepared == [("prove-c", "prover", {"module": "m", "function": "c", "c_file": "src/m/c.c"})]
    u = units()["src/m/c.c#c::rte"]
    assert (u["status"], u["agent_id"]) == ("in_progress", "prove-c")

    sim.prover("prove-c", "c", "src/m/c.c")
    assert S.cmd_complete("prove-c")["action"] == "queued_for_merge"
    assert S.cmd_complete("prove-c")["action"] == "already_completed"
    assert S.cmd_next("auto", prepare=True)["tasks"] == []  # b waits for the merge, not just the proof

    merged = S.cmd_merge_pending()
    assert merged["fired"][0]["module"] == "m"
    assert {"no_running_provers", "caller_waiting"} <= set(merged["fired"][0]["reasons"])
    assert merged["merged"][0]["checkpoint"] == {"saved": True, "shard": "c"}
    assert "c" in load("state/progress.json")["shards_done"]["phase3"]
    assert units()["src/m/c.c#c::rte"]["status"] == "covered"
    assert ids(S.cmd_next("auto", prepare=True)) == ["prove:src/m/b.c#b"]
    capsys.readouterr()


def test_diamond_releases_both_branches_and_joins_on_both(sim):
    sim.build(
        {
            "a": ("src/m/a.c", "m", ["b", "c"]),
            "b": ("src/m/b.c", "m", ["d"]),
            "c": ("src/m/c.c", "m", ["d"]),
            "d": ("src/m/d.c", "m", []),
        }
    )
    S.cmd_init()
    assert ids(S.cmd_next("auto", prepare=True)) == ["prove:src/m/d.c#d"]
    sim.finish("prove-d", "d", "src/m/d.c")
    assert sorted(ids(S.cmd_next("auto", prepare=True))) == ["prove:src/m/b.c#b", "prove:src/m/c.c#c"]
    sim.finish("prove-b", "b", "src/m/b.c", force=True)
    assert S.cmd_next("auto", prepare=True)["tasks"] == []  # a still needs c
    sim.finish("prove-c", "c", "src/m/c.c")
    assert ids(S.cmd_next("auto", prepare=True)) == ["prove:src/m/a.c#a"]


def test_recursion_group_is_ready_together_and_its_callers_wait_for_every_member(sim):
    sim.build({"f": ("src/r/f.c", "r", ["g"]), "g": ("src/r/g.c", "r", ["f", "g"]), "h": ("src/r/h.c", "r", ["f"])})
    S.cmd_init()
    t = tasks()
    f, g, h = (t[f"prove:src/r/{n}.c#{n}"] for n in "fgh")
    assert f["scc"] and f["scc"] == g["scc"] and h["scc"] is None
    assert (f["wave"], g["wave"], h["wave"]) == (0, 0, 1)
    assert load("workspace/reports/wp_queue.json")["recursion_groups"] == [["src/r/f.c#f", "src/r/g.c#g"]]
    assert sorted(ids(S.cmd_next("auto", prepare=True))) == ["prove:src/r/f.c#f", "prove:src/r/g.c#g"]

    sim.finish("prove-f", "f", "src/r/f.c", force=True)
    assert S.cmd_next("auto", prepare=True)["tasks"] == []  # h needs the whole group

    sim.modified["prove-g"] = ["src/r/g.c"]  # g's contract changed after its peer f was merged
    out = sim.finish("prove-g", "g", "src/r/g.c")
    assert out["merged"][0]["rechecks_queued"] == ["recheck:src/r/f.c#f"]
    assert sim.recheck_calls == ["f"] and out["rechecks"]["ok"][0]["task"] == "prove:src/r/f.c#f"
    assert tasks()["prove:src/r/f.c#f"]["state"] == "done"
    assert ids(S.cmd_next("auto", prepare=True)) == ["prove:src/r/h.c#h"]


def test_name_collisions_resolve_same_file_statics_and_otherwise_wait_for_every_definition(sim):
    sim.build(
        {
            "helper": ("src/a/x.c", "a", []),
            "top": ("src/c/z.c", "c", ["helper"]),
            "local": ("src/b/y.c", "b", ["helper"]),
        },
        extra_units=[unit("src/b/y.c", "helper", "rte", module="b", tier=TIER1)],
        collisions=[{"function": "helper", "files": ["src/a/x.c", "src/b/y.c"]}],
    )
    S.cmd_init()
    t = tasks()
    ha, hb = "prove:src/a/x.c#helper", "prove:src/b/y.c#helper"
    assert {ha, hb} <= set(t["prove:src/c/z.c#top"]["deps"])  # ambiguous: every same-named function
    assert hb in t["prove:src/b/y.c#local"]["deps"] and ha not in t["prove:src/b/y.c#local"]["deps"]  # static wins
    slug_b = t[hb]["slug"]
    assert t[ha]["slug"] == "helper" and slug_b.startswith("helper_") and slug_b != "helper"

    nxt = S.cmd_next("auto", prepare=True)
    assert sorted(x["agent_id"] for x in nxt["tasks"]) == sorted(["prove-helper", f"prove-{slug_b}"])
    sim.finish("prove-helper", "helper", "src/a/x.c", force=True)
    assert units()["src/a/x.c#helper::rte"]["status"] == "covered"
    assert units()["src/b/y.c#helper::rte"]["status"] == "in_progress"  # the other static is untouched
    assert S.cmd_next("auto", prepare=True)["tasks"] == []
    sim.finish(f"prove-{slug_b}", "helper", "src/b/y.c")
    assert sorted(ids(S.cmd_next("auto", prepare=True))) == ["prove:src/b/y.c#local", "prove:src/c/z.c#top"]


def test_prover_waits_for_the_architects_of_its_module_and_of_every_callee_module(sim):
    covered_g = unit(
        "src/m2/g.c",
        "g",
        "rte",
        status="covered",
        module="m2",
        tier=TIER1,
        evidence=[evidence(tool_output="workspace/reports/eva/m2.json")],
    )
    write_json(sim.run_dir / "workspace/reports/eva/m2.json", {"status": "ok", "module": "m2"})
    sim.build(
        {"f": ("src/m1/f.c", "m1", ["g"]), "g": ("src/m2/g.c", "m2", []), "g2": ("src/m2/g2.c", "m2", [])},
        units=[
            unit("src/m1/f.c", "f", "rte", module="m1", tier=TIER1),
            covered_g,
            unit("src/m2/g2.c", "g2", "rte", module="m2", tier=TIER1),
        ],
        sidecars={"m1": {"header": "src/m1/m1.h"}, "m2": {"header": "src/m2/m2.h"}},
    )
    S.cmd_init()
    t = tasks()
    assert "prove:src/m2/g.c#g" not in t  # g has nothing left to prove, its module's architect still matters
    assert t["prove:src/m1/f.c#f"]["deps"] == ["arch:m1", "arch:m2", "gate:m1"]
    assert t["arch:m2"]["header"] == "src/m2/m2.h" and t["arch:m2"]["deps"] == ["gate:m2"]

    assert sorted(ids(S.cmd_next("auto", prepare=True))) == ["arch:m1", "arch:m2"]
    assert {(a, r) for a, r, _ in sim.prepared} == {("arch-m1", "architect"), ("arch-m2", "architect")}

    sim.architect("arch-m1", "src/m1/m1.h")
    out = S.cmd_complete("arch-m1")
    assert out["action"] == "merged" and sim.arch_merges[0][2]["header_file"] == "src/m1/m1.h"
    assert S.cmd_next("auto", prepare=True)["tasks"] == []  # f still needs m2's architect

    sim.architect("arch-m2", "src/m2/m2.h", status="failed")
    assert S.cmd_complete("arch-m2")["action"] == "architect_failed"  # provers proceed anyway
    assert sorted(ids(S.cmd_next("auto", prepare=True))) == ["prove:src/m1/f.c#f", "prove:src/m2/g2.c#g2"]


def test_priority_is_caller_height_then_eva_unknowns_then_name(sim):
    sim.build(
        {
            "p": ("src/m/p.c", "m", []),
            "p1": ("src/m/p1.c", "m", ["p"]),
            "p2": ("src/m/p2.c", "m", ["p1"]),
            "q": ("src/m/q.c", "m", []),
            "r": ("src/m/r.c", "m", []),
            "s": ("src/m/s.c", "m", []),
        }
    )
    write_json(
        sim.run_dir / "workspace/reports/eva/m.json",
        {"status": "ok", "module": "m", "unknown_obligations_by_function": {"q": [{}] * 5, "r": [{}]}},
    )
    S.cmd_init()
    order = [ids(S.cmd_next("1"))[0] for _ in range(4)]
    assert order == ["prove:src/m/p.c#p", "prove:src/m/q.c#q", "prove:src/m/r.c#r", "prove:src/m/s.c#s"]


# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------


def _stall_and_dispatch_breaker(sim):
    sim.build({"f": ("src/m/f.c", "m", []), "h": ("src/m/h.c", "m", ["f"])}, sidecars={"m": {}})
    S.cmd_init()
    assert ids(S.cmd_next("auto", prepare=True)) == ["prove:src/m/f.c#f"]
    sim.prover("prove-f", "f", "src/m/f.c", status="stalled_after_k_retries")
    out = S.cmd_complete("prove-f")
    assert out["action"] == "blocked" and "breaker:src/m/f.c#f" in out["new_tasks"]
    assert units()["src/m/f.c#f::rte"]["status"] == "blocked"
    assert ready() == ["breaker:src/m/f.c#f", "prove:src/m/h.c#h"]  # the stalled callee released its caller
    brk = S.cmd_next("1", prepare=True)
    assert ids(brk) == ["breaker:src/m/f.c#f"]
    assert (
        brk["tasks"][0]["agent_id"] == "breaker-f"
        and brk["tasks"][0]["wp_report"] == "agents/prove-f/artifacts/wp_f.json"
    )
    # The brief is rendered from the stalled prover's report, not workspace/reports/wp/f.json.
    assert sim.prepared[-1][2]["wp_report"] == "agents/prove-f/artifacts/wp_f.json"


def test_breaker_crash_reopens_the_gate_until_the_module_is_refreshed(sim):
    _stall_and_dispatch_breaker(sim)
    sim.breaker("breaker-f", "f", "src/m/f.c", crash=True)
    out = S.cmd_complete("breaker-f")
    assert out["result_status"] == "crash_found"
    assert "repair:m" not in out.get("new_tasks", [])
    assert len(list((sim.run_dir / "workspace/corpus/m").iterdir())) == 2  # the seed and the crashing input
    fp = load("candidates.json")[0]["fingerprint"]
    assert tasks()[f"verify:{fp}"]["state"] == "pending"
    assert S.cmd_status()["gates"]["gate:m"] == {"open": False, "waiting_on": [f"verify:{fp}"]}

    nxt = S.cmd_next("auto", prepare=True)
    assert nxt["parent_tasks"] == [] and ids(nxt) == [f"verify:{fp}"]
    ver = nxt["tasks"][0]
    L.cmd_scaffold_verifier(
        fp, "needs_validation", ver["agent_id"], out_path=Path(f"agents/{ver['agent_id']}/scratch/result.json")
    )
    assert S.cmd_complete(ver["agent_id"])["decision"] == "needs_validation"
    assert ids(S.cmd_next("auto", prepare=True)) == ["prove:src/m/h.c#h"]


def test_breaker_fault_hypothesis_adds_a_verify_task_that_closes_the_gate(sim):
    _stall_and_dispatch_breaker(sim)
    hyp = {"input_condition": "len > 4", "predicate": "p != 0", "why_not_reproduced": "budget exhausted"}
    sim.breaker("breaker-f", "f", "src/m/f.c", hypothesis=hyp)
    S.cmd_complete("breaker-f")
    fp = load("candidates.json")[0]["fingerprint"]
    assert tasks()[f"verify:{fp}"]["state"] == "pending"
    assert S.cmd_status()["gates"]["gate:m"] == {"open": False, "waiting_on": [f"verify:{fp}"]}

    nxt = S.cmd_next("auto", prepare=True)
    assert ids(nxt) == [f"verify:{fp}"]  # h waits behind the gate
    ver = nxt["tasks"][0]
    assert ver["role"] == "verifier" and ver["candidate_fingerprint"] == fp
    assert sim.prepared[-1][2] == {"module": "m", "candidate_fp": fp}
    L.cmd_scaffold_verifier(
        fp, "needs_validation", ver["agent_id"], out_path=Path(f"agents/{ver['agent_id']}/scratch/result.json")
    )
    assert S.cmd_complete(ver["agent_id"])["decision"] == "needs_validation"
    assert ids(S.cmd_next("auto", prepare=True)) == ["prove:src/m/h.c#h"]


def test_harness_induced_rejection_creates_a_repair_that_holds_the_gate(sim):
    sim.build({"f": ("src/m/f.c", "m", []), "h": ("src/m/h.c", "m", [])}, sidecars={"m": {}})
    fp = sim.eva_candidate("m", "src/m/f.c", "f")
    S.cmd_init()
    assert f"verify:{fp}" in tasks() and "prove:src/m/f.c#f" not in tasks()  # f has no planned unit
    assert S.cmd_status()["gates"]["gate:m"]["waiting_on"] == [f"verify:{fp}"]

    nxt = S.cmd_next("auto", prepare=True)
    assert ids(nxt) == [f"verify:{fp}"]
    ver = nxt["tasks"][0]
    assert ver["harness_meta"] == "workspace/harnesses/harness_m.json" and ver["replay_reports"] == []
    L.cmd_scaffold_verifier(
        fp, "rejected", ver["agent_id"], out_path=Path(f"agents/{ver['agent_id']}/scratch/result.json")
    )
    out = S.cmd_complete(ver["agent_id"])
    assert out["decision"] == "rejected" and "repair:m" in out["new_tasks"]
    assert units()["src/m/f.c#f::rte"]["status"] == "planned"
    assert "prove:src/m/f.c#f" in tasks()  # planned again: it gets a prove task

    nxt = S.cmd_next("auto", prepare=True)
    assert nxt["tasks"] == [] and [p["task"] for p in nxt["parent_tasks"]] == ["repair:m"]
    assert any("--record-repair workspace/harnesses/harness_m.json" in a for a in nxt["parent_tasks"][0]["actions"])
    S.cmd_refresh("m")
    assert sorted(ids(S.cmd_next("auto", prepare=True))) == ["prove:src/m/f.c#f", "prove:src/m/h.c#h"]


def test_gate_waits_for_every_slice_covering_the_module_but_not_for_tier3_slices(sim):
    tier3 = "Tier 3 (Internal State / Glue Module)"
    sim.build(
        {"u": ("src/lib/u.c", "lib", []), "a": ("src/app/a.c", "app", ["u"]), "gfn": ("src/glue/g.c", "glue", ["u"])},
        units=[
            unit("src/lib/u.c", "u", "rte", module="lib", tier=TIER1),
            unit("src/app/a.c", "a", "rte", module="app", tier=TIER1),
            unit(
                "src/glue/g.c",
                "gfn",
                "rte",
                status="deferred",
                module="glue",
                tier=tier3,
                unresolved=["tier3_not_scheduled"],
            ),
        ],
        modules={
            "app": {"required_sources": ["src/app/a.c", "src/lib/u.c"]},
            "glue": {"tier": tier3, "required_sources": ["src/glue/g.c", "src/lib/u.c"], "run_eacsl_fuzz": False},
        },
    )
    glue_fp = make_fingerprint("src/glue/g.c", "gfn", "mem_access", "q != 0")
    write_json(
        sim.run_dir / "candidates.json",
        [
            {
                "fingerprint": glue_fp,
                "status": "unverified",
                "origin": "eva",
                "proposed_verdict": "needs_validation",
                "module": "glue",
                "location": {"file": "src/glue/g.c", "line": 3, "function": "gfn"},
                "property": {"kind": "mem_access", "predicate": "q != 0"},
                "reproducers": [],
                "tool_outputs": ["workspace/reports/eva/glue.json"],
                "linked_units": [],
                "first_seen": "2026-10-30T00:00:00+00:00",
            }
        ],
    )
    app_fp = sim.eva_candidate("app", "src/app/a.c", "a")
    S.cmd_init()
    state = load("state/wp_schedule.json")
    assert state["gates"]["gate:lib"]["contributors"] == ["app", "lib"]  # app's slice compiles lib's file
    assert S.cmd_status()["gates"]["gate:lib"]["waiting_on"] == [f"verify:{app_fp}"]  # glue (Tier 3) never gates
    assert sorted(ready()) == sorted([f"verify:{app_fp}", f"verify:{glue_fp}"])


def test_replay_reports_are_found_by_fingerprint_and_passed_to_the_verifier(sim):
    sim.build({"f": ("src/m/f.c", "m", [])}, sidecars={"m": {}})
    fp = sim.eva_candidate("m", "src/m/f.c", "f")
    write_json(sim.run_dir / f"workspace/reports/replay/{S._fp_slug(fp)}.json", {"artifacts": []})
    write_json(sim.run_dir / "workspace/reports/replay/other.json", {"artifacts": [{"fingerprint": fp}]})
    write_json(sim.run_dir / "workspace/reports/replay/unrelated.json", {"artifacts": [{"fingerprint": "x"}]})
    S.cmd_init()
    ver = S.cmd_next("auto", prepare=True)["tasks"][0]
    assert ver["replay_reports"] == [
        "workspace/reports/replay/other.json",
        f"workspace/reports/replay/{S._fp_slug(fp)}.json",
    ]


# ---------------------------------------------------------------------------
# Negotiation and contract re-checks
# ---------------------------------------------------------------------------


def test_negotiation_requeues_the_caller_and_is_capped_per_pair(sim):
    sim.build({"f": ("src/m/f.c", "m", ["g"]), "g": ("src/m/g.c", "m", [])})
    S.cmd_init()
    assert ids(S.cmd_next("auto", prepare=True)) == ["prove:src/m/g.c#g"]
    sim.finish("prove-g", "g", "src/m/g.c")
    assert ids(S.cmd_next("auto", prepare=True)) == ["prove:src/m/f.c#f"]

    for n, (prover, negotiator) in enumerate([("prove-f", "negotiate-g"), ("prove-f-2", "negotiate-g-2")], start=1):
        sim.prover(prover, "f", "src/m/f.c", status="stalled_after_k_retries", requests=[request("g", n)])
        out = S.cmd_complete(prover)
        assert "negotiate:src/m/g.c#g" in out["new_tasks"]
        neg = [x for x in S.cmd_next("auto", prepare=True)["tasks"] if x["kind"] == "negotiate"][0]
        assert (neg["agent_id"], neg["role"], neg["function"]) == (negotiator, "prover", "g")
        assert neg["requests"][0]["needed_clause"] == f"ensures R{n}: n >= {n};"
        assert neg["callers"] == ["prove:src/m/f.c#f"]
        prepared = [kw for aid, _, kw in sim.prepared if aid == negotiator][-1]
        assert [r["needed_clause"] for r in prepared["requests"]] == [
            f"ensures R{n}: n >= {n};"
        ]  # rendered into the brief
        sim.finish(negotiator, "g", "src/m/g.c", force=True)
        assert tasks()["prove:src/m/f.c#f"]["state"] == "pending"  # requeued once the request was applied
        redo = [x for x in S.cmd_next("auto", prepare=True)["tasks"] if x["kind"] == "prove"]
        assert redo[0]["agent_id"] == f"prove-f-{n + 1}"
        assert units()["src/m/f.c#f::rte"]["status"] == "in_progress"  # blocked -> in_progress by CAS

    sim.prover("prove-f-3", "f", "src/m/f.c", status="stalled_after_k_retries", requests=[request("g", 3)])
    out = S.cmd_complete("prove-f-3")
    assert out["negotiations_capped"][0]["callee"] == "src/m/g.c#g"
    assert tasks()["negotiate:src/m/g.c#g"]["state"] == "done"
    reqs = load("workspace/reports/strengthen_requests.json")["requests"]
    assert [r["status"] for r in reqs] == ["verified_and_applied", "verified_and_applied", "rejected_by_callee"]
    assert "cap" in reqs[-1]["resolution_note"]


def test_requests_arriving_during_a_negotiation_start_a_follow_up_round(sim):
    sim.build({"f": ("src/m/f.c", "m", ["g"]), "h": ("src/m/h.c", "m", ["g"]), "g": ("src/m/g.c", "m", [])})
    S.cmd_init()
    S.cmd_next("auto", prepare=True)
    sim.finish("prove-g", "g", "src/m/g.c")
    S.cmd_next("auto", prepare=True)  # prove-f, prove-h
    sim.prover("prove-f", "f", "src/m/f.c", status="stalled_after_k_retries", requests=[request("g", 1)])
    S.cmd_complete("prove-f")
    assert "negotiate-g" in [x["agent_id"] for x in S.cmd_next("auto", prepare=True)["tasks"]]
    sim.prover("prove-h", "h", "src/m/h.c", status="stalled_after_k_retries", requests=[request("g", 2)])
    S.cmd_complete("prove-h")  # negotiate:g is running: h's request waits for the next round
    assert tasks()["negotiate:src/m/g.c#g"]["followup_callers"] == ["prove:src/m/h.c#h"]

    out = sim.finish("negotiate-g", "g", "src/m/g.c", force=True)
    assert out["negotiation"][0]["requeued_callers"] == ["prove:src/m/f.c#f"]
    neg = tasks()["negotiate:src/m/g.c#g"]
    assert neg["state"] == "pending" and neg["callers"] == ["prove:src/m/h.c#h"]
    assert tasks()["prove:src/m/h.c#h"]["state"] == "blocked"  # requeued only once its own request resolves
    nxt = S.cmd_next("auto", prepare=True)["tasks"]
    follow = [x for x in nxt if x["kind"] == "negotiate"][0]
    assert follow["agent_id"] == "negotiate-g-2" and follow["requests"][0]["caller_function"] == "h"
    sim.finish("negotiate-g-2", "g", "src/m/g.c", force=True)
    assert tasks()["prove:src/m/h.c#h"]["state"] == "pending"


def test_contract_change_rechecks_merged_callers_and_a_failure_reproves_them(sim):
    sim.build({"f": ("src/m/f.c", "m", ["g"]), "h": ("src/m/h.c", "m", ["g"]), "g": ("src/m/g.c", "m", [])})
    S.cmd_init()
    S.cmd_next("auto", prepare=True)
    sim.finish("prove-g", "g", "src/m/g.c")
    assert sorted(ids(S.cmd_next("auto", prepare=True))) == ["prove:src/m/f.c#f", "prove:src/m/h.c#h"]
    sim.prover("prove-h", "h", "src/m/h.c", status="stalled_after_k_retries", requests=[request("g", 1)])
    S.cmd_complete("prove-h")
    sim.finish("prove-f", "f", "src/m/f.c")
    assert tasks()["prove:src/m/f.c#f"]["outcome"] == "merged"

    neg = [x for x in S.cmd_next("auto", prepare=True)["tasks"] if x["kind"] == "negotiate"][0]
    sim.modified[neg["agent_id"]] = ["src/m/g.h"]
    sim.recheck_ok["f"] = False
    out = sim.finish(neg["agent_id"], "g", "src/m/g.c", force=True)
    assert out["merged"][0]["rechecks_queued"] == ["recheck:src/m/f.c#f"]
    assert sim.recheck_calls == ["f"] and out["rechecks"]["reprove"][0]["task"] == "prove:src/m/f.c#f"
    t = tasks()
    assert t["prove:src/m/f.c#f"]["state"] == "pending" and t["prove:src/m/h.c#h"]["state"] == "pending"
    assert units()["src/m/f.c#f::rte"]["status"] == "blocked"
    agents = sorted(x["agent_id"] for x in S.cmd_next("auto", prepare=True)["tasks"] if x["kind"] == "prove")
    assert agents == ["prove-f-2", "prove-h-2"]


# ---------------------------------------------------------------------------
# merge-pending
# ---------------------------------------------------------------------------


def test_merge_pending_triggers(sim):
    fns: dict[str, tuple[str, str, list[str]]] = {n: (f"src/m/{n}.c", "m", []) for n in "abcdefg"}
    fns.update({"x": ("src/n/x.c", "n", ["y"]), "y": ("src/n/y.c", "n", []), "z": ("src/n/z.c", "n", [])})
    sim.build(fns)
    S.cmd_init()
    assert len(S.cmd_next("20", prepare=True)["tasks"]) == 9  # x waits for y

    def complete(*names):
        for n in names:
            sim.prover(f"prove-{n}", n, fns[n][0])
            S.cmd_complete(f"prove-{n}")

    complete("a")
    out = S.cmd_merge_pending()
    assert out["fired"] == [] and out["waiting"] == [{"module": "m", "queued": 1, "oldest_s": 0.0}]
    sim.clock += 301
    assert S.cmd_merge_pending()["fired"][0]["reasons"] == ["max_wait"]

    complete("b")
    assert S.cmd_merge_pending(force=True)["fired"][0]["reasons"] == ["forced"]

    complete("c", "d", "e")
    assert S.cmd_merge_pending()["fired"] == []
    complete("f")
    out = S.cmd_merge_pending()
    assert out["fired"][0]["reasons"] == ["batch_full"] and len(out["merged"]) == 4

    complete("g")
    assert S.cmd_merge_pending()["fired"][0]["reasons"] == ["no_running_provers"]

    complete("y")
    out = S.cmd_merge_pending(module="n")
    assert out["fired"] == [{"module": "n", "reasons": ["caller_waiting"], "agents": ["prove-y"]}]
    assert ids(S.cmd_next("auto", prepare=True)) == ["prove:src/n/x.c#x"]
    assert sim.merge_calls == [
        ["prove-a"],
        ["prove-b"],
        ["prove-c", "prove-d", "prove-e", "prove-f"],
        ["prove-g"],
        ["prove-y"],
    ]


def test_failed_merge_is_requeued_once_then_blocks(sim):
    sim.build({"f": ("src/m/f.c", "m", [])})
    S.cmd_init()
    S.cmd_next("auto", prepare=True)
    sim.merge_fail["prove-f"] = "parent guardrail returned status='failed_dynamic_oracle'"
    sim.prover("prove-f", "f", "src/m/f.c")
    S.cmd_complete("prove-f")
    out = S.cmd_merge_pending()
    assert out["failed"][0]["action"] == "requeued" and out["failed"][0]["units_released"] == ["src/m/f.c#f::rte"]
    assert units()["src/m/f.c#f::rte"]["status"] == "planned"

    assert S.cmd_next("auto", prepare=True)["tasks"][0]["agent_id"] == "prove-f-2"
    sim.merge_fail["prove-f-2"] = "parent WP check on merged tree returned status='unproven_goals_remain'"
    sim.prover("prove-f-2", "f", "src/m/f.c")
    S.cmd_complete("prove-f-2")
    out = S.cmd_merge_pending()
    assert out["failed"][0]["action"] == "blocked"
    assert tasks()["prove:src/m/f.c#f"]["state"] == "blocked"
    assert units()["src/m/f.c#f::rte"]["status"] == "blocked"


def test_parent_analysis_error_retries_the_merge_once_then_blocks(sim):
    sim.build({"f": ("src/m/f.c", "m", [])})
    S.cmd_init()
    S.cmd_next("auto", prepare=True)
    sim.merge_fail["prove-f"] = "parent WP check on merged tree returned status='analysis_error'"
    sim.parent_status["prove-f"] = "analysis_error"
    sim.prover("prove-f", "f", "src/m/f.c")
    S.cmd_complete("prove-f")
    first = S.cmd_merge_pending()
    assert first["failed"][0]["action"] == "retry_merge" and tasks()["prove:src/m/f.c#f"]["state"] == "merge_queued"
    second = S.cmd_merge_pending()
    assert second["failed"][0]["action"] == "blocked_analysis_error"
    u = units()["src/m/f.c#f::rte"]
    assert u["status"] == "blocked" and any("analysis_error" in r for r in u["unresolved"])
    assert sim.merge_calls == [["prove-f"], ["prove-f"]]


# ---------------------------------------------------------------------------
# Ledger safety and recovery
# ---------------------------------------------------------------------------


def test_prepare_never_overwrites_a_unit_that_just_became_a_candidate(sim):
    sim.build({"f": ("src/m/f.c", "m", [])})
    S.cmd_init()
    sim.on_prepare = lambda aid, role, kw: sim.eva_candidate("m", "src/m/f.c", "f")
    out = S.cmd_next("auto", prepare=True)
    assert out["tasks"] == [] and out["briefs"] == []
    assert out["skipped"] == [{"task": "prove:src/m/f.c#f", "agent_id": "prove-f", "reason": "candidate"}]
    u = units()["src/m/f.c#f::rte"]
    assert u["status"] == "candidate" and u["agent_id"] is None and len(u["result_fingerprints"]) == 1
    t = tasks()["prove:src/m/f.c#f"]
    assert (t["state"], t["outcome"]) == ("skipped", "candidate")
    fp = load("candidates.json")[0]["fingerprint"]
    assert ready() == [f"verify:{fp}"]


def test_reconcile_returns_orphaned_in_progress_units_and_reports_stale_briefs(sim):
    sim.build(
        {"f": ("src/m/f.c", "m", []), "g": ("src/m/g.c", "m", [])},
        units=[
            unit("src/m/f.c", "f", "rte", status="in_progress", agent_id="prover-old", module="m", tier=TIER1),
            unit("src/m/g.c", "g", "rte", module="m", tier=TIER1),
        ],
        sidecars={"m": {"header": "src/m/m.h"}},
    )
    brief = sim.run_dir / "agents/prover-old/brief.md"
    brief.parent.mkdir(parents=True)
    brief.write_text("Prove {function_name} in {c_file} with {references_dir}.\n", encoding="utf-8")
    S.cmd_init()
    assert "prove:src/m/f.c#f" not in tasks()  # without --reconcile an in_progress unit is left alone

    # The pre-scheduler architect of module m already merged its header.
    (sim.run_dir / "agents/arch-m/artifacts").mkdir(parents=True)
    (sim.run_dir / "agents/arch-m/artifacts/m.patch").write_text("--- a/src/m/m.h\n", encoding="utf-8")
    out = S.cmd_init(reconcile=True)
    assert out["reconciled_units"] == [{"coverage_id": "src/m/f.c#f::rte", "agent_id": "prover-old"}]
    assert units()["src/m/f.c#f::rte"]["status"] == "planned" and "prove:src/m/f.c#f" in tasks()
    assert out["stale_briefs"] == [
        {
            "brief": "agents/prover-old/brief.md",
            "agent_id": "prover-old",
            "live": False,
            "reasons": ["unrendered placeholders: {c_file}, {function_name}"],
            "action": "re-render with next --prepare",
        }
    ]
    assert out["adopted_architects"] == ["arch:m"] and tasks()["arch:m"]["outcome"] == "merged_before_scheduler"
    assert sorted(ids(S.cmd_next("auto", prepare=True))) == ["prove:src/m/f.c#f", "prove:src/m/g.c#g"]
    assert S.cmd_init(reconcile=True)["reconciled_units"] == []  # live agents keep their units


def test_analysis_error_is_retried_once_then_blocks_the_units(sim):
    sim.build({"f": ("src/m/f.c", "m", [])})
    S.cmd_init()
    S.cmd_next("auto", prepare=True)
    cid = "src/m/f.c#f::rte"
    sim.prover("prove-f", "f", "src/m/f.c", status="blocked", wp_status="analysis_error", wp_reason="oom_killed")
    out = S.cmd_complete("prove-f")
    assert (out["action"], out["reason"]) == ("retry_analysis_error", "oom_killed")
    u = units()[cid]
    assert u["status"] == "planned" and u["evidence"][-1]["result"] == "wp_analysis_error"
    assert "breaker:src/m/f.c#f" not in tasks()

    assert S.cmd_next("auto", prepare=True)["tasks"][0]["agent_id"] == "prove-f-2"
    sim.prover("prove-f-2", "f", "src/m/f.c", status="blocked", wp_status="analysis_error", wp_reason="timeout")
    out = S.cmd_complete("prove-f-2")
    assert out["action"] == "blocked_analysis_error"
    u = units()[cid]
    assert u["status"] == "blocked" and any("analysis_error" in r and "timeout" in r for r in u["unresolved"])
    assert tasks()["prove:src/m/f.c#f"]["state"] == "blocked"
    assert all(x["status"] != "in_progress" for x in units().values())


def test_invalid_results_are_rerun_once_then_never_leave_units_in_progress(sim):
    sim.build({"f": ("src/m/f.c", "m", [])})
    S.cmd_init()
    S.cmd_next("auto", prepare=True)
    (sim.run_dir / "agents/prove-f/scratch/result.json").write_text("Here is my result: {}", encoding="utf-8")
    out = S.cmd_complete("prove-f")
    assert out["action"] == "requeued_invalid_result" and out["validation_errors"]
    assert units()["src/m/f.c#f::rte"]["status"] == "planned"
    assert S.cmd_next("auto", prepare=True)["tasks"][0]["agent_id"] == "prove-f-2"
    sim.prover("prove-f-2", "g", "src/m/f.c")  # a result for the wrong function
    out = S.cmd_complete("prove-f-2")
    assert out["action"] == "blocked_invalid_result"
    # No evidence to block it with: the unit returns to planned, never stays in_progress.
    assert units()["src/m/f.c#f::rte"]["status"] == "planned" and out["units"]["planned"] == ["src/m/f.c#f::rte"]


def test_requeue_stale_agents_and_accept_a_late_result(sim):
    sim.build({"f": ("src/m/f.c", "m", []), "g": ("src/m/g.c", "m", [])})
    S.cmd_init()
    S.cmd_next("1", prepare=True)  # prove-f
    sim.clock += 31 * 60
    S.cmd_next("1", prepare=True)  # prove-g, fresh
    out = S.cmd_requeue(stale_minutes=30)
    assert [r["task"] for r in out["requeued"]] == ["prove:src/m/f.c#f"]
    assert units()["src/m/f.c#f::rte"]["status"] == "planned"
    assert units()["src/m/g.c#g::rte"]["status"] == "in_progress"

    # The requeued agent answers after all, before the task was handed out again: accepted.
    sim.prover("prove-f", "f", "src/m/f.c")
    late = S.cmd_complete("prove-f")
    assert late["late_result"] and late["action"] == "queued_for_merge"

    S.cmd_requeue(agent_id="prove-g")
    assert S.cmd_next("auto", prepare=True)["tasks"][0]["agent_id"] == "prove-g-2"
    sim.prover("prove-g", "g", "src/m/g.c")
    assert S.cmd_complete("prove-g")["action"] == "stale_agent"


def test_waves_mode_keeps_a_barrier_between_waves(sim, monkeypatch):
    sim.build(
        {
            "a": ("src/m/a.c", "m", ["b"]),
            "b": ("src/m/b.c", "m", ["c"]),
            "c": ("src/m/c.c", "m", []),
            "d": ("src/m/d.c", "m", []),
        }
    )
    S.cmd_init()
    monkeypatch.setenv("FRAMAC_SCHEDULER", "waves")
    nxt = S.cmd_next("auto", prepare=True)
    assert nxt["mode"] == "waves" and sorted(ids(nxt)) == ["prove:src/m/c.c#c", "prove:src/m/d.c#d"]
    sim.finish("prove-c", "c", "src/m/c.c", force=True)
    assert ready() == []  # wave 0 still has d running
    monkeypatch.delenv("FRAMAC_SCHEDULER")
    assert ready() == ["prove:src/m/b.c#b"]  # the ready queue would not wait
    monkeypatch.setenv("FRAMAC_SCHEDULER", "waves")
    sim.finish("prove-d", "d", "src/m/d.c")
    assert ids(S.cmd_next("auto", prepare=True)) == ["prove:src/m/b.c#b"]


def test_real_overlay_prepare_and_merge_round_trip(sim, monkeypatch):
    """The scheduler against the real prepare_agent / merge_agent_batch (only the WP subprocess is faked)."""
    target = sim.run_dir.parent / "target"
    (target / "src/m").mkdir(parents=True)
    (target / "src/m/f.c").write_text("int f(int x) {\n    return x;\n}\n", encoding="utf-8")
    workspace_overlay.init_overlay(target, sim.run_dir / "workspace")
    sim.build({"f": ("src/m/f.c", "m", [])})
    monkeypatch.setattr(S.DEPS, "prepare_agent", workspace_overlay.prepare_agent)
    monkeypatch.setattr(S.DEPS, "merge_agent_batch", workspace_overlay.merge_agent_batch)

    def fake_run(cmd, **kwargs):
        if any(str(c).endswith("run_wp_function.py") for c in cmd):
            out = Path(cmd[cmd.index("--out-json") + 1])
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(
                json.dumps(wp_report(cmd[cmd.index("--function") + 1], cmd[cmd.index("--file") + 1])), encoding="utf-8"
            )
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="unavailable in tests")

    monkeypatch.setattr(workspace_overlay.subprocess, "run", fake_run)
    S.cmd_init()
    task = S.cmd_next("auto", prepare=True)["tasks"][0]
    assert "f" in (sim.run_dir / task["brief_file"]).read_text(encoding="utf-8")
    scratch_c = sim.run_dir / "agents/prove-f/scratch/work/src/m/f.c"
    scratch_c.write_text("/*@ assigns \\nothing; */\nint f(int x) {\n    return x;\n}\n", encoding="utf-8")
    sim.prover("prove-f", "f", "src/m/f.c")
    assert S.cmd_complete("prove-f")["action"] == "queued_for_merge"
    out = S.cmd_merge_pending()
    assert out["failed"] == [] and out["merged"][0]["parent_wp_report"] == "agents/prove-f/scratch/parent_wp/f.json"
    assert "assigns \\nothing" in (sim.run_dir / "workspace/work/src/m/f.c").read_text(encoding="utf-8")
    assert units()["src/m/f.c#f::rte"]["status"] == "covered"
    assert S.cmd_status()["done"]


def test_status_and_cli(sim, capsys):
    sim.build({"a": ("src/m/a.c", "m", ["b"]), "b": ("src/m/b.c", "m", [])})
    assert S.main(["init"]) == 0
    capsys.readouterr()
    assert S.main(["status"]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["counts"] == {"pending": 2} and status["critical_path"] == 2
    assert [r["task"] for r in status["ready"]] == ["prove:src/m/b.c#b"] and not status["done"]

    assert S.main(["next", "--slots", "many"]) == 1
    assert "--slots" in json.loads(capsys.readouterr().out)["error"]
    assert S.main(["complete", "--agent-id", "nobody"]) == 1
    assert "unknown agent id" in json.loads(capsys.readouterr().out)["error"]
    assert S.main(["next", "--slots", "auto", "--max-agents", "1"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["slots"]["max_agents"] == 1 and [t["agent_id"] for t in out["tasks"]] == ["prove-b"]


def test_batch_transitions_in_claim_and_park_units(sim, monkeypatch):
    sim.build(
        {
            "f": ("src/m/f.c", "m", []),
            "g": ("src/m/g.c", "m", []),
        },
        extra_units=[unit("src/m/f.c", "f", "l2_termination", module="m", tier=TIER1)],
    )
    S.cmd_init()
    batch_calls: list[list[dict]] = []
    orig_many = S.DEPS.transition_many

    def spy_many(items):
        batch_calls.append(list(items))
        return orig_many(items)

    monkeypatch.setattr(S.DEPS, "transition_many", spy_many)
    dispatched = S.cmd_next("auto", prepare=True)["tasks"]
    assert len(dispatched) == 2
    assert len(batch_calls) == 1
    assert {item["id"] for item in batch_calls[0]} == {
        "src/m/f.c#f::rte",
        "src/m/f.c#f::l2_termination",
        "src/m/g.c#g::rte",
    }
    task = next(t for t in dispatched if t["function"] == "f")

    # Park units when one unit has evidence and one does not: both handled in a single transition_many call.
    u_map, c_map = L.load_state()
    L.add_evidence(
        u_map["src/m/f.c#f::rte"],
        "wp",
        "run_wp_function.py",
        "wp_unproven",
        False,
        "workspace/reports/wp/f.json",
        "1 goal unproven",
    )
    (sim.run_dir / "workspace/reports/wp").mkdir(parents=True, exist_ok=True)
    (sim.run_dir / "workspace/reports/wp/f.json").write_text("{}\n", encoding="utf-8")
    L.commit(u_map, c_map)

    parked = S._park_units(
        {
            "kind": "prove",
            "file": "src/m/f.c",
            "function": "f",
            "agents": [task["agent_id"]],
            "units": task["coverage_ids"],
        },
        task["agent_id"],
        "stalled after retries",
    )
    assert len(batch_calls) == 2
    assert parked["blocked"] == ["src/m/f.c#f::rte"]
    assert parked["planned"] == ["src/m/f.c#f::l2_termination"]
    assert parked["errors"] == []


def test_caller_merged_with_blocked_callee_audits_hypotheses(sim):
    sim.build({"caller": ("src/m/a.c", "m", ["callee"]), "callee": ("src/m/b.c", "m", [])}, sidecars={"m": {}})
    S.cmd_init()
    # Dispatch and stall callee so callee becomes blocked and releases caller
    t_callee = S.cmd_next("auto", prepare=True)["tasks"][0]
    assert t_callee["function"] == "callee"
    sim.prover(t_callee["agent_id"], "callee", "src/m/b.c", status="stalled_after_k_retries")
    out = S.cmd_complete(t_callee["agent_id"])
    assert out["action"] == "blocked" and tasks()["prove:src/m/b.c#callee"]["state"] == "blocked"

    # Dispatch caller (and breaker); complete breaker cleanly
    dispatched = S.cmd_next("auto", prepare=True)["tasks"]
    brk_task = next(t for t in dispatched if t["kind"] == "breaker")
    sim.breaker(brk_task["agent_id"], "callee", "src/m/b.c", crash=False)
    S.cmd_complete(brk_task["agent_id"])

    t_caller = next(t for t in dispatched if t["kind"] == "prove")
    assert t_caller["function"] == "caller"
    aid_caller = t_caller["agent_id"]
    sim.prover(aid_caller, "caller", "src/m/a.c", status="all_proven")
    assert S.cmd_complete(aid_caller)["action"] == "queued_for_merge"

    # Make merge_agent_batch write a parent WP report with proven_under_hyp=1
    orig_batch = sim.merge_agent_batch

    def batch_with_hyp(run_dir, entries, **kw):
        res = orig_batch(run_dir, entries, **kw)
        for m in res["merged"]:
            rep_path = sim.run_dir / m["parent_wp_report"]
            rep = json.loads(rep_path.read_text(encoding="utf-8"))
            rep["by_obligation_class"] = {"rte": {"proven": 1, "proven_under_hyp": 1, "unproven": 0}}
            write_json(rep_path, rep)
        return res

    sim.merge_agent_batch = batch_with_hyp
    S.DEPS.merge_agent_batch = batch_with_hyp
    S.cmd_merge_pending()

    caller_unit = units()["src/m/a.c#caller::rte"]
    assert caller_unit["status"] == "covered"
    cch = [a for a in caller_unit["assumptions"] if a["kind"] == "callee_contract_hypothesis"]
    assert len(cch) == 1
    assert "src/m/b.c#callee::rte" in cch[0]["related_units"]


def test_shell_unverifiable_leaf_is_deprioritized_and_alloc_stall_skips_breaker(sim, monkeypatch):
    sim.build({"a_shell": ("src/m/a.c", "m", []), "b_core": ("src/m/b.c", "m", [])})
    dag = load(sim.run_dir / "workspace/reports/callgraph_dag.json")
    dag["functions"]["a_shell"]["verifiability"] = "shell_unverifiable_wp"
    dag["functions"]["a_shell"]["wp_blockers"] = ["dynamic_allocation"]
    dag["functions"]["b_core"]["verifiability"] = "core_provable"
    write_json(sim.run_dir / "workspace/reports/callgraph_dag.json", dag)

    S.cmd_init()
    # 'a_shell' is shell_unverifiable_wp so it is immediately skipped by the scheduler
    # (no prover slot burned) and its unit is parked; 'b_core' is dispatched directly.
    assert tasks()["prove:src/m/a.c#a_shell"]["state"] == "skipped"
    assert tasks()["prove:src/m/a.c#a_shell"]["outcome"] == "shell_unverifiable_wp"
    assert units()["src/m/a.c#a_shell::rte"]["status"] == "deferred"

    monkeypatch.setattr(S.DEPS, "recommend", lambda max_agents=None: {"max_agents": 1})
    first = S.cmd_next("auto", prepare=True)["tasks"]
    assert [t["function"] for t in first] == ["b_core"]
    sim.finish(first[0]["agent_id"], "b_core", "src/m/b.c")

    assert S.cmd_next("auto", prepare=True)["tasks"] == []
    assert not any(t["kind"] == "breaker" for t in tasks().values())
    assert S.cmd_status()["done"]


def test_negotiate_skips_callee_already_in_candidate_status_and_tracks_wall_budget(sim):
    sim.build({"leaf": ("src/m/a.c", "m", []), "caller": ("src/m/b.c", "m", ["leaf"])})
    S.cmd_init()
    # Dispatch leaf first and verify wall_budget_s is populated
    nxt = S.cmd_next("auto", prepare=True)
    assert nxt["tasks"][0]["wall_budget_s"] > 0

    # Mark leaf's unit as candidate before caller requests strengthening
    u_path = sim.run_dir / "coverage-ledger.json"
    u_list = load(u_path)
    for u in u_list:
        if u["function"] == "leaf":
            u["status"] = "candidate"
            u["result_fingerprints"] = ["src/m/a.c#leaf::rte::0123456789"]
    write_json(u_path, u_list)

    # Attempting to emit a negotiation for a callee whose unit is already candidate is skipped
    sched = load(sim.run_dir / "state/wp_schedule.json")
    ctx = S.Ctx()
    out: dict = {"errors": []}
    S._emit_negotiations(
        sched,
        ctx,
        {"id": "prove:src/m/b.c#caller", "file": "src/m/b.c", "function": "caller"},
        [{"id": "req-1", "callee_function": "leaf", "callee_file": "src/m/a.c"}],
        out,
    )
    assert out.get("negotiations_created", []) == []
    assert out.get("negotiations_skipped", [{}])[0].get("reason") == "candidate"


def test_is_done_requires_no_planned_or_in_progress_units(sim):
    sim.build({"f": ("src/m/f.c", "m", [])})
    S.cmd_init()
    assert not S.cmd_status()["done"]

    # Even if all tasks are marked done in schedule, an open ledger unit prevents completion
    sched_path = sim.run_dir / "state/wp_schedule.json"
    sched = load(sched_path)
    for t in sched["tasks"].values():
        t["state"] = "done"
    write_json(sched_path, sched)

    assert not S._is_done(sched)

    # Once unit is covered, _is_done returns True
    u_path = sim.run_dir / "coverage-ledger.json"
    u_list = load(u_path)
    u_list[0]["status"] = "covered"
    u_list[0]["evidence"] = [
        {"phase": "wp", "producer": "p", "result": "proved", "discharging": True, "tool_output": None, "summary": "ok"}
    ]
    write_json(u_path, u_list)
    assert S._is_done(sched)


def test_architect_merge_retries_on_analysis_error(sim, monkeypatch):
    sim.build({"f": ("src/m/f.c", "m", [])}, sidecars={"m": {"header": "src/m/m.h"}})
    S.cmd_init()
    nxt = S.cmd_next("auto", prepare=True)
    arch_task = [t for t in nxt["tasks"] if t["kind"] == "arch"][0]
    aid = arch_task["agent_id"]
    assert aid.startswith("arch-m")

    call_count = [0]

    def retry_then_succeed(run_dir, agent_id, role, **kw):
        sim.arch_merges.append((agent_id, role, kw))
        call_count[0] += 1
        if call_count[0] == 1:
            return {"ok": False, "reason": "parent guardrail returned status='analysis_error'"}
        return {"ok": True, "agent_id": agent_id, "modified_files": ["src/m/m.h"]}

    monkeypatch.setattr(S.DEPS, "merge_agent_overlay", retry_then_succeed)
    sim.architect(aid, "src/m/m.h")

    out = S.cmd_complete(aid)
    assert out["action"] == "merged"
    assert call_count[0] == 2
    t = tasks()["arch:m"]
    assert t["state"] == "done" and t["outcome"] == "merged"
    assert t.get("analysis_retries") == 1


def test_architect_merge_exhausts_retries_on_persistent_analysis_error(sim, monkeypatch):
    sim.build({"f": ("src/m/f.c", "m", [])}, sidecars={"m": {"header": "src/m/m.h"}})
    S.cmd_init()
    nxt = S.cmd_next("auto", prepare=True)
    arch_task = [t for t in nxt["tasks"] if t["kind"] == "arch"][0]
    aid = arch_task["agent_id"]

    call_count = [0]

    def always_analysis_error(run_dir, agent_id, role, **kw):
        sim.arch_merges.append((agent_id, role, kw))
        call_count[0] += 1
        return {"ok": False, "reason": "parent guardrail returned status='analysis_error'"}

    monkeypatch.setattr(S.DEPS, "merge_agent_overlay", always_analysis_error)
    sim.architect(aid, "src/m/m.h")

    out = S.cmd_complete(aid)
    assert out["action"] == "merge_failed"
    assert call_count[0] == S.MAX_ANALYSIS_ERRORS
    t = tasks()["arch:m"]
    assert t["state"] == "done" and t["outcome"] == "merge_failed"
    assert t.get("analysis_retries") == S.MAX_ANALYSIS_ERRORS - 1


def test_architect_merge_does_not_retry_non_analysis_error(sim, monkeypatch):
    sim.build({"f": ("src/m/f.c", "m", [])}, sidecars={"m": {"header": "src/m/m.h"}})
    S.cmd_init()
    nxt = S.cmd_next("auto", prepare=True)
    arch_task = [t for t in nxt["tasks"] if t["kind"] == "arch"][0]
    aid = arch_task["agent_id"]

    call_count = [0]

    def syntax_error(run_dir, agent_id, role, **kw):
        sim.arch_merges.append((agent_id, role, kw))
        call_count[0] += 1
        return {"ok": False, "reason": "parent guardrail returned status='rejected_overconstrained'"}

    monkeypatch.setattr(S.DEPS, "merge_agent_overlay", syntax_error)
    sim.architect(aid, "src/m/m.h")

    out = S.cmd_complete(aid)
    assert out["action"] == "merge_failed"
    assert call_count[0] == 1  # No retry on contract rejection
    t = tasks()["arch:m"]
    assert t["state"] == "done" and t["outcome"] == "merge_failed"
    assert not t.get("analysis_retries")


def test_stalled_prover_with_sound_contract_triggers_partial_merge(sim, monkeypatch):
    sim.build({"caller": ("src/m/p.c", "m", ["callee"]), "callee": ("src/m/p.c", "m", [])})
    S.cmd_init()
    nxt = S.cmd_next("auto", prepare=True)
    callee_task = [t for t in nxt["tasks"] if t["task"] == "prove:src/m/p.c#callee"][0]
    aid = callee_task["agent_id"]

    # Write a sound WP report with 0 unproven step_a_assigns goals and a function contract in scratch
    scratch_c = sim.run_dir / f"agents/{aid}/scratch/work/src/m/p.c"
    scratch_c.parent.mkdir(parents=True, exist_ok=True)
    scratch_c.write_text(
        "/*@ requires x >= 0;\n  @ assigns \\nothing;\n  @ ensures \\result == x;\n  @*/\n"
        "static int callee(int x) { return x; }\n"
        "int caller(int x) { return callee(x); }\n",
        encoding="utf-8",
    )
    write_json(
        sim.run_dir / f"agents/{aid}/scratch/guard_callee.json",
        {"status": "passed_dynamic_oracle"},
    )
    report_rel = f"agents/{aid}/scratch/wp_callee.json"
    write_json(
        sim.run_dir / report_rel,
        {
            "status": "unproven_goals_remain",
            "function": "callee",
            "file": f"agents/{aid}/scratch/work/src/m/p.c",
            "soundness": {"ok": True},
            "by_obligation_class": {"rte": {"proven": 4, "proven_under_hyp": 0, "unproven": 1}},
            "unproven_by_bucket": {
                "step_a_assigns": [],
                "step_b_loop_invariant": [{"line": 3, "annotation": "p != 0"}],
                "step_c_rte_obligation": [],
                "step_c_caller_precondition": [],
                "step_c_contract_postcondition": [],
            },
            "unproven_goals": [{"obligation_class": "rte", "kind": "assert", "line": 3, "annotation": "p != 0"}],
        },
    )
    write_json(
        sim.run_dir / f"agents/{aid}/scratch/result.json",
        {
            "role": "prover",
            "agent_id": aid,
            "file": "src/m/p.c",
            "function": "callee",
            "status": "stalled_after_k_retries",
            "patch": None,
            "evidence": [{"tool_output": report_rel, "result": "unproven_goals_remain"}],
            "unproven_goals": [{"line": 3, "annotation": "p != 0"}],
            "strengthening_requests": [],
            "boundary_assumptions": [],
            "fault_hypothesis": None,
        },
    )
    sim.modified[aid] = ["src/m/p.c"]

    out = S.cmd_complete(aid)
    assert out["action"] == "blocked"
    assert out.get("partial_merge", {}).get("ok") is True
    # Verify merge_agent_overlay was called with role="prover" and allow_partial_wp=True
    prover_merges = [(a, r, kw) for (a, r, kw) in sim.arch_merges if a == aid and r == "prover"]
    assert len(prover_merges) == 1
    assert prover_merges[0][2].get("allow_partial_wp") is True
    # Callee task remains blocked, while partial_contract_merged is recorded and caller is now ready
    t_callee = tasks()["prove:src/m/p.c#callee"]
    assert t_callee["state"] == "blocked"
    assert t_callee.get("partial_contract_merged") is True
    assert "prove:src/m/p.c#caller" in ready()


def test_deep_and_quick_profile_scheduling(sim):
    """Under deep profile, Tier 3 rte units are scheduled; under quick profile, only Tier 1A entry chains are scheduled."""
    tier3 = "Tier 3 (Internal State / Glue Module)"
    tier1b = "Tier 1B (Structured Packet / Buffer Emitter)"
    functions = {
        "entry_parse": ("src/p/parse.c", "parser", ["glue_helper"]),
        "glue_helper": ("src/g/glue.c", "glue", []),
        "emit_pkt": ("src/e/emit.c", "emitter", []),
    }
    custom_units = [
        unit("src/p/parse.c", "entry_parse", "rte", module="parser", tier=TIER1),
        unit("src/g/glue.c", "glue_helper", "rte", module="glue", tier=tier3, status="planned"),
        unit("src/e/emit.c", "emit_pkt", "rte", module="emitter", tier=tier1b, status="planned"),
    ]
    sim.build(
        functions,
        units=custom_units,
        modules={
            "parser": {"tier": TIER1},
            "glue": {"tier": tier3, "run_eva": False, "run_eacsl_fuzz": False},
            "emitter": {"tier": tier1b},
        },
    )

    # 1. Quick profile: schedules entry_parse (Tier 1A) and its callee glue_helper, skips unrelated Tier 1B emit_pkt.
    write_json(sim.run_dir / "run-metadata.json", {"profile": "quick"})
    S.cmd_init()
    quick_tasks = tasks()
    assert "prove:src/p/parse.c#entry_parse" in quick_tasks
    assert "prove:src/g/glue.c#glue_helper" in quick_tasks
    assert "prove:src/e/emit.c#emit_pkt" not in quick_tasks
    assert "prove:src/g/glue.c#glue_helper" in ready()

    # 2. Deep profile: schedules all planned units including emit_pkt and Tier 3 glue_helper.
    write_json(sim.run_dir / "run-metadata.json", {"profile": "deep"})
    S.cmd_init()
    deep_tasks = tasks()
    assert "prove:src/e/emit.c#emit_pkt" in deep_tasks
    assert "prove:src/g/glue.c#glue_helper" in deep_tasks
