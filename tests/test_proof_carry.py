"""Tests for scripts/proof_carry.py: the `proofs` cache namespace, publishing from wp-sweep and the wp-replay step."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

import cache
import ledger
import proof_carry as pc
import workspace_overlay
from conftest import metadata, unit, write_json

pytestmark = pytest.mark.unit

HEADER_FRESH = """#ifndef M_H
#define M_H
int inc(int a);
int twice(int a);
#endif
"""

HEADER_PROVEN = """#ifndef M_H
#define M_H
/*@ predicate small(integer x) = x < 1000; */
/*@ requires small(a);
    assigns \\nothing;
    ensures \\result == a + 1; */
int inc(int a);
int twice(int a);
#endif
"""

C_FRESH = """#include "m.h"
int inc(int a) { return a + 1; }
int twice(int a) {
  int r = a;
  for (int i = 0; i < 2; i++) r = inc(r);
  return r;
}
int other(int a) { return a; }
"""

C_PROVEN = """#include "m.h"
int inc(int a) { return a + 1; }
/*@ requires a < 10;
    assigns \\nothing;
    ensures \\result == a + 2; */
int twice(int a) {
  int r = a;
  /*@ loop invariant 0 <= i <= 2;
      loop invariant r == a + i;
      loop assigns i, r;
      loop variant 2 - i; */
  for (int i = 0; i < 2; i++) r = inc(r);
  return r;
}
/*@ assigns \\nothing; */
int other(int a) { return a; }
"""

DAG = {
    "functions": {
        "src/m.c#inc": {"name": "inc", "file": "src/m.c", "module": "m", "internal_callees": []},
        "src/m.c#twice": {"name": "twice", "file": "src/m.c", "module": "m", "internal_callees": ["src/m.c#inc"]},
        "src/m.c#other": {"name": "other", "file": "src/m.c", "module": "m", "internal_callees": []},
    }
}

LIMITS = {"vacuity": {"status": "consistent"}}


class FakePlan:
    def __init__(self, flags: list[str] | None = None) -> None:
        self.flags = flags if flags is not None else ["-I."]

    def wp_cppflags_for(self, module):
        return list(self.flags), ""

    def wp_extra_sources_for(self, module):
        return []


@pytest.fixture(autouse=True)
def _cache_env(monkeypatch, tmp_path):
    monkeypatch.setenv("FRAMAC_IMAGE_ID", "test-image")
    monkeypatch.delenv("FRAMAC_CACHE", raising=False)
    monkeypatch.delenv("FRAMAC_PROOF_CARRY", raising=False)
    monkeypatch.delenv("FRAMAC_SNAPSHOT_DIR", raising=False)
    shared = tmp_path / "shared"
    shared.mkdir()
    monkeypatch.setenv("FRAMAC_SHARED_CACHE_DIR", str(shared))
    monkeypatch.setenv("FRAMAC_CACHE_MODE", "rw")
    return shared


def _make_run(root: Path, c_text: str, h_text: str, units: list[dict] | None = None) -> Path:
    write_json(root / "run-metadata.json", metadata())
    for base in ("work", "baseline"):
        d = root / "workspace" / base / "src"
        d.mkdir(parents=True, exist_ok=True)
        (d / "m.c").write_text(c_text, encoding="utf-8", newline="")
        (d / "m.h").write_text(h_text, encoding="utf-8", newline="")
    write_json(root / pc.DAG_JSON, DAG)
    write_json(root / pc.LEDGER_JSON, units or [])
    return root


def _report(root: Path, fn: str, status: str = "all_proven", rel: str | None = None) -> Path:
    path = root / (rel or f"workspace/reports/wp-sweep/src_m.c__{fn}.json")
    write_json(
        path,
        {
            "function": fn,
            "file": "workspace/work/src/m.c",
            "status": status,
            "by_obligation_class": {"rte": {"proven": 2, "unproven": 0}},
            "soundness": {"reduced_checks": ["-warn-unsigned-overflow / -warn-unsigned-downcast OFF"]},
            "limits": LIMITS,
        },
    )
    return path


def _key(root: Path, fn: str, flags=None) -> str:
    header = pc.resolve_header(root, root / "workspace", "src/m.c", fn, "m")
    mat = pc.proof_key_material(
        root, root / "workspace", "src/m.c", fn, "m", flags or ["-I."], DAG["functions"], None, header
    )
    assert mat is not None
    return cache.make_key(pc.NS, mat)


def _publish(root: Path, fn: str, status: str = "all_proven", **kw) -> tuple[bool, str]:
    rep = _report(root, fn, status)
    entry = {"file": "src/m.c", "function": fn, "module": "m", **kw}
    return pc.publish_proof(root, root / "workspace", entry, rep, ["-I."], DAG["functions"], [], ["--no-warn-unsigned"])


# ---------------------------------------------------------------------------
# Key
# ---------------------------------------------------------------------------


def test_key_is_stable_and_ignores_the_carried_contract(tmp_path):
    a = _make_run(tmp_path / "a", C_PROVEN, HEADER_PROVEN)
    b = _make_run(tmp_path / "b", C_FRESH, HEADER_FRESH)
    # Same C code: the contract being carried (and every other annotation) does not key itself, so the
    # key a sweep publishes under is the one a fresh tree looks up, once its callees carry the same contracts.
    assert _key(a, "inc") == _key(a, "inc") == _key(b, "inc")
    assert _key(a, "twice") != _key(b, "twice")  # its callee inc has no contract on the fresh tree


def test_key_changes_with_body_callee_contract_and_flags(tmp_path):
    a = _make_run(tmp_path / "a", C_PROVEN, HEADER_PROVEN)
    base = _key(a, "twice")
    assert _key(a, "twice", flags=["-I.", "-DX=1"]) != base
    h = a / "workspace/work/src/m.h"
    h.write_text(HEADER_PROVEN.replace("\\result == a + 1", "\\result == 1 + a"), encoding="utf-8")
    assert _key(a, "twice") != base  # callee contract changed
    h.write_text(HEADER_PROVEN, encoding="utf-8")
    assert _key(a, "twice") == base
    c = a / "workspace/work/src/m.c"
    c.write_text(C_PROVEN.replace("int r = a;", "int r = a + 0;"), encoding="utf-8")
    assert _key(a, "twice") != base  # body changed


def test_key_ignores_an_unrelated_annotation_in_the_same_file(tmp_path):
    a = _make_run(tmp_path / "a", C_PROVEN, HEADER_PROVEN)
    base = _key(a, "twice")
    c = a / "workspace/work/src/m.c"
    c.write_text(C_PROVEN.replace("/*@ assigns \\nothing; */\nint other", "int other"), encoding="utf-8")
    assert _key(a, "twice") == base


def test_unkeyable_function_has_no_material(tmp_path):
    a = _make_run(tmp_path / "a", C_FRESH, HEADER_FRESH)
    assert pc.proof_key_material(a, a / "workspace", "src/m.c", "nope", "m", ["-I."], {}) is None
    assert pc.proof_key_material(a, a / "workspace", "src/missing.c", "inc", "m", ["-I."], {}) is None


# ---------------------------------------------------------------------------
# Publishing
# ---------------------------------------------------------------------------


def test_publish_writes_contract_and_report_to_run_and_shared_store(tmp_path, _cache_env):
    a = _make_run(tmp_path / "a", C_PROVEN, HEADER_PROVEN)
    ok, key = _publish(a, "inc")
    assert ok, key
    for root in (a / "state/cache", _cache_env):
        entry = cache.Store(root).get(pc.NS, key)
        assert entry is not None
        assert sorted((entry.path / "files").iterdir()) == [
            entry.path / "files/contract.json",
            entry.path / "files/wp_report.json",
        ]
        doc = json.loads((entry.path / "files/contract.json").read_text(encoding="utf-8"))
        assert doc["function"] == "inc" and doc["header_file"] == "src/m.h"
        assert "ensures \\result == a + 1" in doc["contract_h"] and doc["wp_report_status"] == "all_proven"
        assert [d["name"] for d in doc["top_level_decls"]] == ["small"]
        assert doc["wp_extra_flags"] == ["--no-warn-unsigned"] and doc["run_id"] == "run-1"
        assert entry.data == {"function": "inc", "file": "src/m.c", "module": "m"}


def test_publish_keeps_body_annotations(tmp_path):
    a = _make_run(tmp_path / "a", C_PROVEN, HEADER_PROVEN)
    ok, key = _publish(a, "twice")
    assert ok
    entry = cache.lookup(pc.NS, key, a)
    assert entry is not None
    doc = json.loads((entry.path / "files/contract.json").read_text(encoding="utf-8"))
    assert "loop invariant r == a + i;" in doc["span_c"] and "requires a < 10;" in doc["contract_c"]


def test_nothing_published_for_unproven_eva_only_or_switched_off(tmp_path, monkeypatch):
    a = _make_run(tmp_path / "a", C_PROVEN, HEADER_PROVEN)
    assert _publish(a, "inc", status="unproven_goals_remain") == (False, "sweep report is not all_proven")
    assert _publish(a, "inc", eva_only=True)[0] is False
    monkeypatch.setenv("FRAMAC_PROOF_CARRY", "off")
    assert _publish(a, "inc") == (False, "FRAMAC_PROOF_CARRY=off")
    monkeypatch.delenv("FRAMAC_PROOF_CARRY")
    monkeypatch.setenv("FRAMAC_CACHE", "off")
    assert _publish(a, "inc") == (False, "cache disabled")
    assert not (a / "state/cache" / pc.NS).exists()


def test_read_only_shared_store_is_never_written(tmp_path, monkeypatch, _cache_env):
    monkeypatch.setenv("FRAMAC_CACHE_MODE", "ro")
    a = _make_run(tmp_path / "a", C_PROVEN, HEADER_PROVEN)
    ok, key = _publish(a, "inc")
    assert ok  # the run store
    assert list(_cache_env.rglob("*")) == []
    assert cache.Store(a / "state/cache").get(pc.NS, key) is not None


# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------


def _planned_units() -> list[dict]:
    return [
        unit("src/m.c", "inc", "rte", module="m"),
        unit("src/m.c", "twice", "rte", module="m"),
        unit("src/m.c", "other", "rte", module="m"),
    ]


class FakeMerge:
    """Applies the agent's changed files to workspace/work/ and writes a parent WP report (no Frama-C)."""

    def __init__(self, run: Path, fail: set[str] | None = None, raise_for: set[str] | None = None) -> None:
        self.run = run
        self.fail = fail or set()
        self.raise_for = raise_for or set()
        self.calls: list[tuple[str, str, dict]] = []

    def __call__(self, run_dir, agent_id, role, overlay=None, **kw):
        self.calls.append((agent_id, role, kw))
        fn = kw.get("function") or ""
        if fn in self.raise_for:
            raise workspace_overlay.ScopeViolationError("agent modified content outside assigned function")
        if fn in self.fail:
            return {
                "ok": False,
                "rolled_back": True,
                "reason": "parent WP check on merged tree returned status='timeout'",
            }
        scratch = run_dir / "agents" / agent_id / "scratch"
        for p in (scratch / "work").rglob("*"):
            if p.is_file():
                rel = p.relative_to(scratch / "work")
                shutil.copy2(p, run_dir / "workspace/work" / rel)
        out = {"ok": True, "agent_id": agent_id}
        if role == "prover":
            rep = f"agents/{agent_id}/scratch/parent_wp/{fn}.json"
            _report(run_dir, fn, rel=rep)
            out["parent_wp_report"] = rep
        return out


def _ledger_calls(run: Path, monkeypatch):
    monkeypatch.chdir(run)

    def ingest(rep):
        out = ledger.cmd_ingest_wp([Path(rep)])
        return True, json.dumps(out)

    def mark(rep, entry, key):
        return ledger.cmd_mark_carried(Path(rep), entry, key)["marked"]

    return ingest, mark


def _seed_store(tmp_path: Path) -> None:
    """Run 1: the swept, annotated tree publishes inc and twice (shared store, FRAMAC_CACHE_MODE=rw)."""
    a = _make_run(tmp_path / "run1", C_PROVEN, HEADER_PROVEN)
    assert _publish(a, "inc")[0]
    assert _publish(a, "twice")[0]


def test_replay_reproves_callees_first_and_credits_units(tmp_path, monkeypatch):
    _seed_store(tmp_path)
    run = _make_run(tmp_path / "run2", C_FRESH, HEADER_FRESH, _planned_units())
    merge = FakeMerge(run)
    ingest, mark = _ledger_calls(run, monkeypatch)
    summary = pc.replay(run, FakePlan(), merge=merge, ingest=ingest, mark=mark)

    assert summary["hits"] == 2 and summary["reproven"] == 2 and summary["misses"] == 1, summary
    assert summary["rejected"] == []
    # inc first: twice's key folds in inc's contract, which only the first replay put on the tree.
    assert [f["function"] for f in summary["carried"]] == ["inc", "twice"]
    # The predicate inc's contract names goes in first, through an architect merge of the header.
    assert [(c[1], c[2].get("function")) for c in merge.calls] == [
        ("architect", None),
        ("prover", "inc"),
        ("prover", "twice"),
    ]
    assert all(c[2].get("contract_only") is False for c in merge.calls if c[1] == "prover")
    work = (run / "workspace/work/src/m.c").read_text(encoding="utf-8")
    assert "loop invariant r == a + i;" in work
    assert "predicate small" in (run / "workspace/work/src/m.h").read_text(encoding="utf-8")
    units = {u["function"]: u for u in json.loads((run / "coverage-ledger.json").read_text(encoding="utf-8"))}
    for fn in ("inc", "twice"):
        u = units[fn]
        assert u["status"] == "covered"
        ev = [e for e in u["evidence"] if e["phase"] == "wp" and e["discharging"]]
        assert [e["result"] for e in ev] == ["carried_forward_reproven"]
        assert ev[0]["details"]["proof_carry"]["entry"] == f"state/proof-carry/src_m.c__{fn}/contract.json"
        assert (run / ev[0]["tool_output"]).is_file()
    assert units["other"]["status"] == "planned"
    # The swept report seeded the agent, so the parent re-check reuses its reduced checks.
    agent = summary["carried"][0]["agent_id"]
    assert (run / "agents" / agent / "scratch/wp_inc.json").is_file()
    assert json.loads((run / pc.SUMMARY_REL).read_text(encoding="utf-8"))["reproven"] == 2


def test_failed_reproof_leaves_units_planned_and_removes_the_agent(tmp_path, monkeypatch):
    _seed_store(tmp_path)
    run = _make_run(tmp_path / "run2", C_FRESH, HEADER_FRESH, _planned_units())
    merge = FakeMerge(run, fail={"inc"})
    ingest, mark = _ledger_calls(run, monkeypatch)
    summary = pc.replay(run, FakePlan(), merge=merge, ingest=ingest, mark=mark)

    assert summary["reproven"] == 0
    assert summary["rejected"][0]["function"] == "inc" and "timeout" in summary["rejected"][0]["reason"]
    # twice now misses: inc's contract never reached the tree.
    assert summary["hits"] == 1 and summary["misses"] == 2
    assert not any(p.name.startswith("carry-") for p in (run / "agents").iterdir())
    units = json.loads((run / "coverage-ledger.json").read_text(encoding="utf-8"))
    assert {u["status"] for u in units} == {"planned"}


def test_scope_violation_is_a_rejection(tmp_path, monkeypatch):
    _seed_store(tmp_path)
    run = _make_run(tmp_path / "run2", C_FRESH, HEADER_FRESH, _planned_units())
    ingest, mark = _ledger_calls(run, monkeypatch)
    summary = pc.replay(run, FakePlan(), merge=FakeMerge(run, raise_for={"inc"}), ingest=ingest, mark=mark)
    assert summary["rejected"][0]["reason"].startswith("ScopeViolationError")
    assert not any(p.name.startswith("carry-") for p in (run / "agents").iterdir())


def test_declaration_conflict_is_skipped(tmp_path, monkeypatch):
    _seed_store(tmp_path)
    h = HEADER_FRESH.replace("int inc(int a);", "/*@ predicate small(integer x) = x < 5; */\nint inc(int a);")
    run = _make_run(tmp_path / "run2", C_FRESH, h, _planned_units())
    merge = FakeMerge(run)
    ingest, mark = _ledger_calls(run, monkeypatch)
    summary = pc.replay(run, FakePlan(), merge=merge, ingest=ingest, mark=mark)
    assert summary["rejected"] == [{"file": "src/m.c", "function": "inc", "reason": "declaration conflict: small"}]
    assert not any(c[2].get("function") == "inc" for c in merge.calls)


def test_miss_is_counted_and_nothing_merged(tmp_path, monkeypatch):
    run = _make_run(tmp_path / "run2", C_FRESH, HEADER_FRESH, _planned_units())
    merge = FakeMerge(run)
    ingest, mark = _ledger_calls(run, monkeypatch)
    summary = pc.replay(run, FakePlan(), merge=merge, ingest=ingest, mark=mark)
    assert summary["misses"] == 3 and summary["hits"] == 0 and merge.calls == []


def test_switched_off_replay_writes_a_skipped_summary(tmp_path, monkeypatch):
    _seed_store(tmp_path)
    run = _make_run(tmp_path / "run2", C_FRESH, HEADER_FRESH, _planned_units())
    monkeypatch.setenv("FRAMAC_PROOF_CARRY", "off")
    summary = pc.replay(run, None)
    assert summary["skipped"] is True and summary["reason"] == "FRAMAC_PROOF_CARRY=off"
    assert json.loads((run / pc.SUMMARY_REL).read_text(encoding="utf-8"))["skipped"] is True


def test_replay_never_writes_the_shared_store_in_ro_mode(tmp_path, monkeypatch, _cache_env):
    _seed_store(tmp_path)
    before = sorted(p.relative_to(_cache_env).as_posix() for p in _cache_env.rglob("*"))
    monkeypatch.setenv("FRAMAC_CACHE_MODE", "ro")
    run = _make_run(tmp_path / "run2", C_FRESH, HEADER_FRESH, _planned_units())
    ingest, mark = _ledger_calls(run, monkeypatch)
    summary = pc.replay(run, FakePlan(), merge=FakeMerge(run), ingest=ingest, mark=mark)
    assert summary["reproven"] == 2
    after = sorted(p.relative_to(_cache_env).as_posix() for p in _cache_env.rglob("*"))
    assert [p for p in after if not p.endswith("meta.json")] == [p for p in before if not p.endswith("meta.json")]
    assert all(str(Path(c["agent_id"])) for c in summary["carried"])


def test_mark_carried_relabels_only_that_reports_evidence(tmp_path, monkeypatch):
    run = _make_run(tmp_path / "run", C_FRESH, HEADER_FRESH, _planned_units())
    monkeypatch.chdir(run)
    rep = _report(run, "inc", rel="workspace/reports/wp/inc.json")
    ledger.cmd_ingest_wp([rep])
    write_json(run / "state/proof-carry/x/contract.json", {})
    out = ledger.cmd_mark_carried(Path("workspace/reports/wp/inc.json"), "state/proof-carry/x/contract.json", "k" * 64)
    assert out["marked"] == ["src/m.c#inc::rte"]
    units = {u["function"]: u for u in json.loads((run / "coverage-ledger.json").read_text(encoding="utf-8"))}
    ev = units["inc"]["evidence"][-1]
    assert ev["result"] == "carried_forward_reproven" and ev["discharging"] is True
    assert ev["details"]["proof_carry"] == {"entry": "state/proof-carry/x/contract.json", "key": "k" * 64}
    assert ev["details"]["limits"] == LIMITS
    assert ledger.cmd_mark_carried(Path("workspace/reports/wp/other.json"), "e", "k")["marked"] == []
