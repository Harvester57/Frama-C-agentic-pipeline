"""Same-root-cause verify candidates are verified one at a time, and later siblings see the first verdict.

QCBOR run-2: twenty E-ACSL `initialization` candidates with one predicate hash (`c132f24cbe`, the
predicate `\\initialized(&uOffset)`), in twenty functions of one link unit, all copied one uninitialized
`size_t` that one callee's early return left unwritten. The scheduler released them in parallel, so
no verifier saw another's verdict: 17 confirmed, 1 duplicate, 1 `other`, 1 `disproved_by_source`.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

import fingerprint as FP
import workspace_overlay as WO
import wp_scheduler as S
from conftest import ROOT, confirmed_record, write_json
from test_p5_circuit_breaker import _complete_verifier_as, _write_sudo_harness
from test_wp_scheduler import Sim, tasks

pytestmark = pytest.mark.unit

_MOD = "libqcbor_a"
_SIB_SUFFIX = "c132f24cbe"
_SIB_KIND = "initialization"
_SIB_PRED = r"\initialized(&uOffset)"


@pytest.fixture
def sim(run_dir: Path, monkeypatch: pytest.MonkeyPatch) -> Sim:
    monkeypatch.setenv("FRAMAC_VERIFIER_BREAKER", "off")
    monkeypatch.setenv("FRAMAC_HARNESS_SMOKE", "off")
    monkeypatch.setenv("FRAMAC_FUZZ_EXPLORE_JUDGE", "off")
    return Sim(run_dir, monkeypatch)


def _candidate(sim: Sim, fn: str, kind: str, suffix: str, predicate: str, idx: int) -> dict[str, Any]:
    file_path = f"src/{_MOD}/{fn}.c"
    fp = f"{file_path}#{fn}::{kind}::{suffix}"
    payload = bytes([idx, idx + 1])
    crash_rel = f"workspace/crashes/{_MOD}/crash-{fn}"
    (sim.run_dir / crash_rel).parent.mkdir(parents=True, exist_ok=True)
    (sim.run_dir / crash_rel).write_bytes(payload)
    write_json(
        sim.run_dir / f"workspace/reports/replay/{S._fp_slug(fp)}.json",
        {
            "candidate_fingerprint": fp,
            "status": "reproduced",
            "fingerprint_matches": True,
            "artifacts": [{"path": crash_rel, "sha256": hashlib.sha256(payload).hexdigest(), "reproducible": True}],
        },
    )
    fuzz_out = f"workspace/reports/fuzz/{_MOD}.json"
    return {
        "fingerprint": fp,
        "status": "unverified",
        "origin": "fuzz",
        "proposed_verdict": "confirmed",
        "module": _MOD,
        "location": {"file": file_path, "line": 10 + idx, "function": fn},
        "property": {"kind": kind, "predicate": predicate},
        "reproducers": [crash_rel],
        "tool_outputs": [fuzz_out],
        "linked_units": [f"{file_path}#{fn}::rte"],
        "first_seen": "2026-11-24T00:00:00Z",
        "observations": [
            {
                "fingerprint": fp,
                "origin": "fuzz",
                "engine": "eacsl",
                "kind": "eacsl_initialization",
                "message": predicate,
                "tool_output": fuzz_out,
                "reproducer": crash_rel,
            }
        ],
    }


def _seed(sim: Sim, siblings: int, distinct: int = 0) -> list[dict[str, Any]]:
    """`siblings` candidates sharing kind and predicate hash, plus `distinct` unrelated ones, in one module."""
    sib_fns = [f"GetT{i:02d}InMapN" for i in range(siblings)]
    other_fns = [f"Other{i:02d}" for i in range(distinct)]
    fns: dict[str, tuple[str, str, list[str]]] = {fn: (f"src/{_MOD}/{fn}.c", _MOD, []) for fn in [*sib_fns, *other_fns]}
    sim.build(fns, sidecars={_MOD: {"entry_style": "dispatch", "dispatch_case_count": 4}})
    digest = _write_sudo_harness(sim, _MOD)
    write_json(
        sim.run_dir / f"workspace/reports/fuzz/{_MOD}.json",
        {"status": "ok", "module": _MOD, "harness_digest": digest},
    )
    cands = [_candidate(sim, fn, _SIB_KIND, _SIB_SUFFIX, _SIB_PRED, i) for i, fn in enumerate(sib_fns)]
    cands += [
        _candidate(sim, fn, "mem_access", f"{i + 1:010x}", f"\\valid_read(p + {i})", 50 + i)
        for i, fn in enumerate(other_fns)
    ]
    write_json(sim.run_dir / "candidates.json", cands)
    return cands


def _is_sibling(fp: str) -> bool:
    return fp.endswith(f"::{_SIB_KIND}::{_SIB_SUFFIX}")


# ---------------------------------------------------------------------------
# The sibling key
# ---------------------------------------------------------------------------


def test_sibling_key_groups_kind_and_predicate_hash_within_a_module() -> None:
    a = f"src/qcbor_number_decode.c#QCBORDecode_GetTBigNumberInMapN::{_SIB_KIND}::{_SIB_SUFFIX}"
    b = f"src/qcbor_tag_decode.c#QCBORDecode_GetTEpochDateInMapN::{_SIB_KIND}::{_SIB_SUFFIX}"
    assert FP.root_cause_sibling_key(_MOD, a) == FP.root_cause_sibling_key(_MOD, b)
    assert FP.root_cause_sibling_key(_MOD, a) != FP.root_cause_sibling_key("other_mod", b)
    assert FP.root_cause_sibling_key(_MOD, a) != FP.root_cause_sibling_key(_MOD, a.replace(_SIB_SUFFIX, "d2eda762d7"))
    assert FP.root_cause_sibling_key(_MOD, a) != FP.root_cause_sibling_key(_MOD, a.replace(_SIB_KIND, "mem_access"))
    # Not a canonical fingerprint: never grouped.
    assert FP.root_cause_sibling_key(_MOD, "fp-1") is None
    assert FP.root_cause_sibling_key(_MOD, "") is None


# ---------------------------------------------------------------------------
# (a) Serialization in the scheduler
# ---------------------------------------------------------------------------


def test_siblings_dispatch_one_representative_and_distinct_candidates_are_not_held(sim: Sim) -> None:
    _seed(sim, siblings=3, distinct=1)
    S.cmd_init()

    first = S.cmd_next("auto", prepare=True)
    dispatched = [t["fingerprint"] for t in first["tasks"]]
    # One sibling (the representative) and the unrelated candidate, not all three siblings.
    assert len([fp for fp in dispatched if _is_sibling(fp)]) == 1
    assert len([fp for fp in dispatched if not _is_sibling(fp)]) == 1

    # While the representative runs, its siblings stay pending.
    assert S.cmd_next("auto", prepare=True)["tasks"] == []
    rep = next(t for t in first["tasks"] if _is_sibling(t["fingerprint"]))

    # Its verdict is ingested: the other two are released together.
    assert _complete_verifier_as(sim, rep, "confirmed")["decision"] == "confirmed"
    second = S.cmd_next("auto", prepare=True)
    released = sorted(t["fingerprint"] for t in second["tasks"])
    assert len(released) == 2
    assert all(_is_sibling(fp) for fp in released)
    assert rep["fingerprint"] not in released


def test_breaker_on_siblings_drain_without_deadlock(sim: Sim, monkeypatch: pytest.MonkeyPatch) -> None:
    """Above the probe fan-out threshold, the probe filter and the sibling filter together never stall."""
    monkeypatch.setenv("FRAMAC_VERIFIER_BREAKER", "on")
    _seed(sim, siblings=6, distinct=0)
    S.cmd_init()

    first = S.cmd_next("auto", prepare=True)
    assert len(first["tasks"]) == 1

    completed: set[str] = set()
    running = list(first["tasks"])
    for _ in range(20):
        if not running:
            break
        for t in running:
            _complete_verifier_as(sim, t, "confirmed")
            completed.add(t["fingerprint"])
        running = S.cmd_next("auto", prepare=True)["tasks"]
        pending = [t for t in tasks().values() if t["kind"] == "verify" and t["state"] == "pending"]
        live = [t for t in tasks().values() if t["kind"] == "verify" and t["state"] in S.LIVE]
        # Never a step with pending verifiers, none running and none dispatched.
        assert not (pending and not live and not running), pending
    assert len(completed) == 6


# ---------------------------------------------------------------------------
# (d) A representative that ends without a verdict still releases its siblings
# ---------------------------------------------------------------------------


def _complete_invalid(task_desc: dict[str, Any]) -> dict[str, Any]:
    aid = str(task_desc["agent_id"])
    write_json(Path(f"agents/{aid}/scratch/result.json"), {"role": "crash_verifier"})
    return S.cmd_complete(aid)


def test_representative_blocked_without_verdict_releases_siblings(sim: Sim) -> None:
    _seed(sim, siblings=3)
    S.cmd_init()

    first = S.cmd_next("auto", prepare=True)
    assert len(first["tasks"]) == 1
    # First invalid result: requeued to pending; still exactly one sibling at a time.
    assert _complete_invalid(first["tasks"][0])["action"] == "requeued_invalid_result"
    retry = S.cmd_next("auto", prepare=True)
    assert len(retry["tasks"]) == 1
    # Second invalid result: the task is blocked with no verdict.
    out = _complete_invalid(retry["tasks"][0])
    assert out["action"] == "blocked_invalid_result"
    blocked = [t for t in tasks().values() if t["kind"] == "verify" and t["state"] == "blocked"]
    assert len(blocked) == 1

    # The remaining siblings are released, not held forever behind the failed representative.
    after = S.cmd_next("auto", prepare=True)
    assert len(after["tasks"]) == 2
    assert all(_is_sibling(t["fingerprint"]) for t in after["tasks"])


# ---------------------------------------------------------------------------
# (b) A sibling's brief lists the verified representative's record
# ---------------------------------------------------------------------------


def _brief_run(tmp_path: Path) -> tuple[Path, str, str, str, str]:
    target = tmp_path / "target"
    target.mkdir()
    (target / "a.c").write_text("int a(void) { return 0; }\n", encoding="utf-8")
    run = tmp_path / "run"
    WO.init_overlay(target, run / "workspace")
    write_json(run / "run-metadata.json", {"profile": "standard"})
    write_json(
        run / "workspace/reports/callgraph_dag.json",
        {"modules": {_MOD: {"tier": "Tier 1A", "functions": ["a"]}}, "functions": {}},
    )
    write_json(
        run / f"workspace/harnesses/harness_{_MOD}.json",
        {"module": _MOD, "sources": ["workspace/work/a.c"], "entry_fn": "a"},
    )
    rep_fp = f"src/qcbor_number_decode.c#QCBORDecode_GetTBigNumberInMapN::{_SIB_KIND}::{_SIB_SUFFIX}"
    sib_fp = f"src/qcbor_tag_decode.c#QCBORDecode_GetTEpochDateInMapN::{_SIB_KIND}::{_SIB_SUFFIX}"
    other_mod_fp = f"src/other.c#OtherFn::{_SIB_KIND}::{_SIB_SUFFIX}"
    unrelated_fp = "src/qcbor_main_decode.c#QCBORDecode_Private_GetItemChecks::initialization::d2eda762d7"

    def cand(fp: str, module: str, status: str) -> dict[str, Any]:
        file_, fn = fp.split("::", 1)[0].split("#")
        return {
            "fingerprint": fp,
            "status": status,
            "origin": "fuzz",
            "module": module,
            "location": {"file": file_, "line": 1, "function": fn},
            "property": {"kind": _SIB_KIND, "predicate": _SIB_PRED},
        }

    write_json(
        run / "candidates.json",
        [
            cand(rep_fp, _MOD, "verified"),
            cand(sib_fp, _MOD, "unverified"),
            cand(other_mod_fp, "other_mod", "verified"),
            cand(unrelated_fp, _MOD, "verified"),
        ],
    )
    rep = confirmed_record(rep_fp)
    rep["severity"] = "low"
    rep["root_cause"] = "GetItemInMapNoCheck returns early on a sticky error without writing *puOffset."
    rep["decision_point"] = {
        "file": "src/qcbor_spiffy_decode.c",
        "line": 489,
        "function": "QCBORDecode_Private_GetItemInMapNoCheck",
        "controlled_by": "attacker_input",
        "description": "early return on uLastError",
        "basis": "located",
    }
    other = confirmed_record(other_mod_fp)
    other["root_cause"] = "A root cause in another module."
    unrelated = confirmed_record(unrelated_fp)
    unrelated["root_cause"] = "A different predicate."
    write_json(run / "findings.json", [rep, other, unrelated])
    return run, rep_fp, sib_fp, other_mod_fp, unrelated_fp


def test_sibling_brief_lists_the_verified_representative_record(tmp_path: Path) -> None:
    run, rep_fp, sib_fp, other_mod_fp, unrelated_fp = _brief_run(tmp_path)
    WO.prepare_agent(run_dir=run, agent_id="verify-sib", role="verifier", module=_MOD, candidate_fp=sib_fp)
    brief = (run / "agents/verify-sib/brief.md").read_text(encoding="utf-8")
    assert "## Verified Siblings" in brief
    section = brief[brief.index("## Verified Siblings") :]
    assert rep_fp in section
    assert "confirmed" in section
    assert "src/qcbor_spiffy_decode.c:489" in section
    assert "QCBORDecode_Private_GetItemInMapNoCheck" in section
    assert "returns early on a sticky error" in section
    # Another module, or another predicate hash, is not a sibling.
    assert other_mod_fp not in section
    assert unrelated_fp not in section
    # The rule that goes with the list: duplicate on the same decision point, else verify independently.
    assert "duplicate" in section


def test_brief_without_verified_siblings_has_no_sibling_section(tmp_path: Path) -> None:
    run, rep_fp, _sib_fp, _o, _u = _brief_run(tmp_path)
    # The representative itself: its only sibling is unverified, so there is nothing to list.
    WO.prepare_agent(run_dir=run, agent_id="verify-rep", role="verifier", module=_MOD, candidate_fp=rep_fp)
    brief = (run / "agents/verify-rep/brief.md").read_text(encoding="utf-8")
    assert "## Verified Siblings" not in brief


# ---------------------------------------------------------------------------
# (c) The brief rule for a true alarm whose value is never consumed
# ---------------------------------------------------------------------------


def test_brief_states_one_outcome_for_a_true_alarm_without_effect() -> None:
    text = (ROOT / "skills" / "framac-wp" / "crash_verifier_brief.md").read_text(encoding="utf-8")
    assert "### True Alarm Without Effect" in text
    start = text.index("### True Alarm Without Effect")
    section = text[start : text.index("\n### ", start + 1)]
    # One outcome, stated plainly.
    assert '`decision: "confirmed"`' in section
    assert '`severity: "low"`' in section
    assert "never consumed" in section
    # The outcomes the run-2 verifiers split on are ruled out by name.
    for refused in ("disproved_by_source", '"other"'):
        assert refused in section
    # Where the decision point goes, so siblings agree on it.
    assert "decision point" in section.lower()
    # The low anchor names it too.
    rules = text[text.index("## Strict Rules") : text.index("## Verification Protocol")]
    assert "never consumed" in rules
