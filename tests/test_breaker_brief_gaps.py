"""The breaker brief and its result: crashes in other functions, the line, untestable goals, the direct driver.

libmodbus run-1 (2026-11-18): `breaker-modbus_tcp_connect` returned `clean` although its whole-module
campaign failed in five other functions; nothing turned them into candidates. minmea run-1: the campaign
never reached a header `static inline`, and only a hand-written driver showed its overflow.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import re
import shlex
from pathlib import Path

import pytest

import fuzz_build
import ledger
import run_eacsl_fuzz
import validate_artifacts
import wp_scheduler as S
from conftest import evidence, metadata, unit, write_json
from fingerprint import make_fingerprint
from test_brief_result_contract import BRIEF_AGENT_ID, _json_blocks, _render
from test_wp_scheduler import Sim, ids, load, tasks, units

pytestmark = pytest.mark.unit

BRK_AID = "breaker-1"
BRK_FILE = "src/snmp/ber.c"
BRK_FN = "ber_decode_len"
OTHER_FILE = "src/snmp/tag.c"
OTHER_FN = "ber_decode_tag"
OTHER_PRED = "pos + n <= 2147483647"
OTHER_LINE = 42
OTHER_FP = make_fingerprint(OTHER_FILE, OTHER_FN, "signed_overflow", OTHER_PRED)
# The flags run_wp_function.py gives WP that Frama-C's RTE leaves off by default (RTE manual, options).
WP_ONLY_WARN_FLAGS = (
    "-warn-unsigned-overflow",
    "-warn-unsigned-downcast",
    "-warn-signed-downcast",
    "-warn-invalid-pointer",
    "-warn-right-shift-negative",
)


def _load(run_dir: Path, name: str):
    return json.loads((run_dir / name).read_text(encoding="utf-8"))


def _breaker_result(**over) -> dict:
    res: dict = {
        "role": "breaker",
        "agent_id": BRK_AID,
        "file": BRK_FILE,
        "function": BRK_FN,
        "status": "clean",
        "seeds": [],
        "crash_artifact": None,
        "failing_predicate": None,
        "analysis": "The length check in the caller bounds the read.",
        "fault_hypothesis": None,
    }
    res.update(over)
    return res


def _source(run_dir: Path, file: str, n: int = 60) -> None:
    """A work-tree source with distinct lines, so a detection's line has a statement site."""
    path = run_dir / "workspace/work" / file
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"int v{i} = {i};\n" for i in range(1, n + 1)), encoding="utf-8")


def _seed_run(run_dir: Path) -> None:
    """Two functions: the breaker's (stalled, blocked) and another one already proven (covered)."""
    _source(run_dir, BRK_FILE)
    _source(run_dir, OTHER_FILE)
    write_json(run_dir / "run-metadata.json", metadata("in_progress"))
    write_json(run_dir / "workspace/reports/eva/snmp.json", {"status": "ok", "module": "snmp"})
    write_json(run_dir / f"workspace/reports/wp/{BRK_FN}.json", {"status": "unproven_goals_remain"})
    stalled = unit(
        BRK_FILE,
        BRK_FN,
        "rte",
        status="blocked",
        evidence=[evidence("wp", "wp_unproven", False, f"workspace/reports/wp/{BRK_FN}.json")],
        unresolved=["unproven mem_access"],
    )
    proven = unit(OTHER_FILE, OTHER_FN, "rte", status="covered", evidence=[evidence()])
    write_json(run_dir / "coverage-ledger.json", [stalled, proven])


def _crash(run_dir: Path, name: str, blob: bytes, aid: str = BRK_AID) -> tuple[str, str]:
    rel = f"agents/{aid}/scratch/crashes/{name}"
    path = run_dir / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(blob)
    return rel, hashlib.sha256(blob).hexdigest()


def _campaign_report(run_dir: Path, records: list[tuple[str, str]], aid: str = BRK_AID, line: int = OTHER_LINE) -> None:
    """A campaign --out-json in the breaker's scratch whose replays failed in OTHER_FN."""
    write_json(
        run_dir / f"agents/{aid}/scratch/breaker_{BRK_FN}.json",
        {
            "mode": "campaign",
            "status": "crash",
            "artifacts": [
                {
                    "artifact": art,
                    "kind": "crash",
                    "sha256": sha,
                    "reproducible": True,
                    "failure": {
                        "file": OTHER_FILE,
                        "function": OTHER_FN,
                        "line": line,
                        "predicate": OTHER_PRED,
                        "alarm_kind": "signed_overflow",
                        "kind": "rte",
                    },
                }
                for art, sha in records
            ],
        },
    )


def _ingest(run_dir: Path, res: dict) -> dict:
    path = run_dir / f"agents/{res['agent_id']}/scratch/result.json"
    write_json(path, res)
    assert list(validate_artifacts.validate_agent_result(res)) == []
    return ledger.cmd_ingest_agent_hypothesis(path, module="snmp")


def _other_entry(art: str, **over) -> dict:
    entry = {
        "crash_artifact": art,
        "file": OTHER_FILE,
        "function": OTHER_FN,
        "line": 7,
        "failing_predicate": OTHER_PRED,
    }
    entry.update(over)
    return entry


# ---------------------------------------------------------------------------
# Gap 1: crashes in other functions become unverified candidates
# ---------------------------------------------------------------------------


def test_a_clean_breaker_turns_a_crash_in_another_function_into_a_candidate(run_dir):
    _seed_run(run_dir)
    art, sha = _crash(run_dir, "crash-a", b"\x01\x02")
    _campaign_report(run_dir, [(art, sha)])
    out = _ingest(run_dir, _breaker_result(other_function_crashes=[_other_entry(art)]))
    assert out["candidates_added"] == 1 and out["other_function_crashes_recorded"] == 1
    (cand,) = _load(run_dir, "candidates.json")
    assert cand["fingerprint"] == OTHER_FP and cand["status"] == "unverified" and cand["origin"] == "breaker"
    # The location is the campaign's own failure record (line 42), not the line the breaker copied (7).
    assert cand["location"] == {"file": OTHER_FILE, "line": OTHER_LINE, "function": OTHER_FN}
    assert cand["site"] and cand["proposed_verdict"] == "confirmed"
    assert cand["module"] == "snmp" and cand["reproducers"] == [f"workspace/crashes/snmp/crash-{sha[:16]}"]
    assert (run_dir / cand["reproducers"][0]).read_bytes() == b"\x01\x02"
    # Already proven, but the crash reopens it as a candidate until a verifier decides.
    other = next(u for u in _load(run_dir, "coverage-ledger.json") if u["function"] == OTHER_FN)
    assert other["status"] == "candidate" and OTHER_FP in other["result_fingerprints"]
    assert any(e["result"] == "breaker_other_function_crash" for e in other["evidence"])
    assert not (run_dir / "workspace/corpus/snmp").exists()  # never a seed


def test_a_second_report_of_the_same_failure_adds_a_reproducer_not_a_candidate(run_dir):
    _seed_run(run_dir)
    art1, sha1 = _crash(run_dir, "crash-a", b"\x01")
    _campaign_report(run_dir, [(art1, sha1)])
    _ingest(run_dir, _breaker_result(other_function_crashes=[_other_entry(art1)]))
    art2, sha2 = _crash(run_dir, "crash-b", b"\x02", aid="breaker-2")
    _campaign_report(run_dir, [(art2, sha2)], aid="breaker-2")
    out = _ingest(run_dir, _breaker_result(agent_id="breaker-2", other_function_crashes=[_other_entry(art2)]))
    assert out["candidates_added"] == 0
    (cand,) = _load(run_dir, "candidates.json")
    assert len(cand["reproducers"]) == 2


def test_a_failure_phase_1_already_ledgered_lands_on_its_fuzz_candidate(run_dir):
    """The campaign replays workspace/corpus/<harness>, so a breaker re-lists known fuzz failures."""
    _seed_run(run_dir)
    known = run_dir / "workspace/crashes/snmp/crash-known"
    known.parent.mkdir(parents=True, exist_ok=True)
    known.write_bytes(b"\x01\x02")
    abs_file = f"/framac-run/workspace/work/{OTHER_FILE}"
    failure: dict = {
        "file": abs_file,
        "function": OTHER_FN,
        "line": OTHER_LINE,
        "predicate": OTHER_PRED,
        "alarm_kind": "signed_overflow",
        "kind": "rte",
    }
    fuzz_fp = make_fingerprint(abs_file, OTHER_FN, "signed_overflow", OTHER_PRED)
    write_json(
        run_dir / "workspace/reports/fuzz/snmp.json",
        {
            "module": "snmp",
            "status": "crash",
            "artifacts": [
                {
                    "artifact": "workspace/crashes/snmp/crash-known",
                    "kind": "crash",
                    "fingerprint": fuzz_fp,
                    "reproducible": True,
                    "failure": failure,
                }
            ],
        },
    )
    ledger.cmd_ingest_fuzz([Path("workspace/reports/fuzz/snmp.json")])
    (fuzz_cand,) = _load(run_dir, "candidates.json")
    art, sha = _crash(run_dir, "crash-a", b"\x03")
    write_json(
        run_dir / f"agents/{BRK_AID}/scratch/breaker_{BRK_FN}.json",
        {"mode": "campaign", "artifacts": [{"artifact": art, "sha256": sha, "reproducible": True, "failure": failure}]},
    )
    entry = _other_entry(art, file=abs_file)  # copied as printed: an absolute path validates
    out = _ingest(run_dir, _breaker_result(other_function_crashes=[entry]))
    assert out["candidates_added"] == 0 and out["other_function_crashes_recorded"] == 1
    (cand,) = _load(run_dir, "candidates.json")
    assert cand["fingerprint"] == fuzz_cand["fingerprint"] == fuzz_fp and len(cand["reproducers"]) == 2


def test_without_a_campaign_record_the_claimed_location_is_kept_and_only_proposed_for_validation(run_dir):
    _seed_run(run_dir)
    art, _ = _crash(run_dir, "crash-a", b"\x05")
    _ingest(run_dir, _breaker_result(other_function_crashes=[_other_entry(art)]))
    (cand,) = _load(run_dir, "candidates.json")
    assert cand["location"] == {"file": OTHER_FILE, "line": 7, "function": OTHER_FN}
    assert cand["proposed_verdict"] == "needs_validation" and cand["status"] == "unverified"


def test_an_unreadable_entry_is_skipped_and_the_main_crash_is_still_recorded(run_dir):
    _seed_run(run_dir)
    main_art, _ = _crash(run_dir, "crash-main", b"\x09")
    res = _breaker_result(
        status="crash_found",
        crash_artifact=main_art,
        failing_predicate=r"\valid_read(buf + off)",
        line=12,
        other_function_crashes=[_other_entry(f"agents/{BRK_AID}/scratch/crashes/missing")],
    )
    out = _ingest(run_dir, res)
    assert out["candidates_added"] == 1 and "other_function_crashes_recorded" not in out
    assert [s["index"] for s in out["other_function_crashes_skipped"]] == [0]
    (cand,) = _load(run_dir, "candidates.json")
    assert cand["location"] == {"file": BRK_FILE, "line": 12, "function": BRK_FN} and cand["site"]


def test_the_crash_found_line_comes_from_the_campaign_when_it_failed_in_the_assigned_function(run_dir):
    _seed_run(run_dir)
    art, sha = _crash(run_dir, "crash-main", b"\x0a")
    write_json(
        run_dir / f"agents/{BRK_AID}/scratch/breaker_{BRK_FN}.json",
        {
            "mode": "campaign",
            "artifacts": [
                {
                    "artifact": art,
                    "sha256": sha,
                    "reproducible": True,
                    "failure": {"file": BRK_FILE, "function": f"__gen_e_acsl_{BRK_FN}", "line": 31, "predicate": "x"},
                }
            ],
        },
    )
    res = _breaker_result(status="crash_found", crash_artifact=art, failing_predicate=r"\valid_read(buf + off)")
    _ingest(run_dir, res)
    (cand,) = _load(run_dir, "candidates.json")
    assert cand["location"]["line"] == 31 and cand["location"]["function"] == BRK_FN


def test_a_fault_hypothesis_with_a_line_gets_a_site(run_dir):
    _seed_run(run_dir)
    hyp = {"input_condition": "len 0x84", "predicate": r"\valid_read(buf + off)", "why_not_reproduced": "driver only"}
    _ingest(run_dir, _breaker_result(fault_hypothesis=hyp, line=12))
    (cand,) = _load(run_dir, "candidates.json")
    assert cand["location"]["line"] == 12 and cand["site"]


def test_scheduler_completion_opens_a_verify_task_for_a_crash_in_an_already_proven_function(run_dir, monkeypatch):
    sim = Sim(run_dir, monkeypatch)
    write_json(run_dir / "workspace/reports/eva/m.json", {"status": "ok", "module": "m"})
    proven_g = unit(
        "src/m/g.c",
        "g",
        "rte",
        status="covered",
        module="m",
        evidence=[evidence(tool_output="workspace/reports/eva/m.json")],
    )
    sim.build(
        {"f": ("src/m/f.c", "m", []), "g": ("src/m/g.c", "m", [])},
        units=[unit("src/m/f.c", "f", "rte", module="m"), proven_g],
        sidecars={"m": {}},
    )
    S.cmd_init()
    assert ids(S.cmd_next("auto", prepare=True)) == ["prove:src/m/f.c#f"]
    sim.prover("prove-f", "f", "src/m/f.c", status="stalled_after_k_retries")
    S.cmd_complete("prove-f")
    assert ids(S.cmd_next("1", prepare=True)) == ["breaker:src/m/f.c#f"]
    art, sha = _crash(run_dir, "crash-g", b"\x07", aid="breaker-f")
    pred = "x + 1 <= 2147483647"
    write_json(
        run_dir / "agents/breaker-f/scratch/breaker_f.json",
        {
            "mode": "campaign",
            "artifacts": [
                {
                    "artifact": art,
                    "sha256": sha,
                    "reproducible": True,
                    "failure": {
                        "file": "src/m/g.c",
                        "function": "g",
                        "line": 5,
                        "predicate": pred,
                        "alarm_kind": "signed_overflow",
                    },
                }
            ],
        },
    )
    entry = {"crash_artifact": art, "file": "src/m/g.c", "function": "g", "line": 5, "failing_predicate": pred}
    write_json(
        run_dir / "agents/breaker-f/scratch/result.json",
        _breaker_result(agent_id="breaker-f", file="src/m/f.c", function="f", other_function_crashes=[entry]),
    )
    out = S.cmd_complete("breaker-f")
    assert out["result_status"] == "clean"
    assert out["other_function_crashes"] == {"listed": 1, "recorded": 1, "skipped": []}
    fp = make_fingerprint("src/m/g.c", "g", "signed_overflow", pred)
    assert tasks()[f"verify:{fp}"]["state"] == "pending"
    assert ids(S.cmd_next("auto", prepare=True)) == [f"verify:{fp}"]
    assert units()["src/m/g.c#g::rte"]["status"] == "candidate"
    assert not (run_dir / "workspace/corpus/m").exists() or not any((run_dir / "workspace/corpus/m").iterdir())
    assert load("candidates.json")[0]["reproducers"][0].startswith("workspace/crashes/m/crash-")


# ---------------------------------------------------------------------------
# Result contract: validator, schema, brief skeleton
# ---------------------------------------------------------------------------


def test_suggested_requires_is_gone_from_schema_and_brief(tmp_path):
    branch = validate_artifacts.get_schema("agent-result")["definitions"]["breaker"]
    assert "suggested_requires" not in branch["properties"] and "suggested_requires" not in branch["required"]
    errs = list(validate_artifacts.validate_agent_result(_breaker_result(suggested_requires=None)))
    assert errs == ["$.suggested_requires: unexpected property"]
    brief = _render(tmp_path / "brief", "breaker")
    assert '"suggested_requires"' not in brief and "`suggested_requires`" not in brief


@pytest.mark.parametrize(
    ("over", "message"),
    [
        ({"other_function_crashes": [_other_entry("workspace/crashes/x")]}, "must live under agents/breaker-1/"),
        (
            {
                "status": "crash_found",
                "crash_artifact": f"agents/{BRK_AID}/scratch/c",
                "failing_predicate": "p",
                "other_function_crashes": [_other_entry(f"agents/{BRK_AID}/scratch/c")],
            },
            "already the result's crash_artifact",
        ),
        (
            {"other_function_crashes": [_other_entry(f"agents/{BRK_AID}/scratch/c")] * 2},
            "listed twice",
        ),
        ({"line": 3}, "$.line:"),
        ({"other_function_crashes": [_other_entry(f"agents/{BRK_AID}/scratch/c", extra=1)]}, "unexpected property"),
    ],
)
def test_validator_refuses_malformed_breaker_entries(over, message):
    errs = list(validate_artifacts.validate_agent_result(_breaker_result(**over)))
    assert any(message in e for e in errs), errs


def test_brief_skeleton_shows_the_other_function_crashes_entry_with_the_schema_keys(tmp_path):
    brief = _render(tmp_path, "breaker")
    (skeleton,) = [json.loads(b) for b in _json_blocks(brief) if '"role": "breaker"' in b]
    item = validate_artifacts.get_schema("agent-result")["definitions"]["breaker"]["properties"][
        "other_function_crashes"
    ]
    (example,) = skeleton["other_function_crashes"]
    assert set(example) == set(item["items"]["properties"]) and "line" in skeleton
    res = _breaker_result(
        agent_id=BRIEF_AGENT_ID,
        other_function_crashes=[{**example, "crash_artifact": f"agents/{BRIEF_AGENT_ID}/scratch/crashes/crash-1"}],
    )
    assert list(validate_artifacts.validate_agent_result(res)) == []


def test_brief_states_reachability_and_the_reworded_stop_rule(tmp_path):
    brief = _render(tmp_path, "breaker")
    assert "**Reachability:** `untrusted_surface`" in brief and "{reachability}" not in brief
    assert "Stop at the first failing assertion" not in brief
    rule = next(ln for ln in brief.splitlines() if ln.startswith("- Do not explore impact beyond the first failure"))
    assert "other_function_crashes" in rule


# ---------------------------------------------------------------------------
# Gap 3: goals the campaign cannot test
# ---------------------------------------------------------------------------


def test_the_untestable_rte_kinds_the_brief_names_match_the_two_builds(tmp_path):
    brief = _render(tmp_path, "breaker")
    section = brief.split("## Goals a Campaign Cannot Test", 1)[1].split("## Execution Steps", 1)[0]
    wp_src = Path(inspect.getfile(fuzz_build)).with_name("run_wp_function.py").read_text(encoding="utf-8")
    eacsl_src = inspect.getsource(fuzz_build._compile_eacsl_binary_uncached)
    for flag in WP_ONLY_WARN_FLAGS:
        assert f'"{flag}"' in wp_src, flag  # WP checks it ...
        assert flag in section, flag  # ... the brief says the campaign does not
        if flag != "-warn-unsigned-downcast":
            assert flag not in eacsl_src, flag
    # The only one the E-ACSL build can add is behind --warn-unsigned-downcast, which the campaign does not pass.
    campaign = next(ln for ln in brief.splitlines() if "run_eacsl_fuzz.py campaign" in ln)
    assert "--warn-unsigned-downcast" not in campaign
    for kind in ("unsigned_overflow", "unsigned_downcast", "signed_downcast", "pointer_value"):
        assert f"rte: {kind}" in section
    for clause in ("`assigns`", "`loop assigns`", "`decreases`", "`terminates`", "lemmas"):
        assert clause in section
    assert "proof_gap" in section and "fault_hypothesis" in section


# ---------------------------------------------------------------------------
# Gap 4: the direct-driver fallback uses real run_eacsl_fuzz.py options
# ---------------------------------------------------------------------------


def _driver_argv(brief: str) -> list[str]:
    line = next(ln.strip() for ln in brief.splitlines() if "run_eacsl_fuzz.py replay" in ln and "driver_" in ln)
    return shlex.split(line)[2:]


@pytest.mark.parametrize("engine", [None, "sanitizers"])
def test_the_driver_command_parses_and_builds_only_the_function(tmp_path, monkeypatch, engine):
    brief = _render(tmp_path, "breaker")
    argv = _driver_argv(brief) + (["--engine", engine] if engine else [])
    seen: dict = {}

    def fake_prepare(module, sources, out_bin, **kw):
        seen.update(module=module, sources=sources, out_bin=str(out_bin), **kw)
        return {"module": module, "binary": None, "reason": "test"}

    monkeypatch.setattr(run_eacsl_fuzz.crash_replay, "prepare_replay_binary", fake_prepare)
    monkeypatch.chdir(tmp_path)
    run_eacsl_fuzz.main(argv)
    assert seen["functions"] == ["f"] and seen["engine"] == (engine or "auto")
    assert seen["sources"][-1] == f"agents/{BRIEF_AGENT_ID}/scratch/driver_f.c"
    assert seen["out_bin"].replace("\\", "/") == f"agents/{BRIEF_AGENT_ID}/scratch/driver_f"
    assert re.search(r"must not define `main` or `LLVMFuzzerInitialize`", brief)
    assert "never a `crash_found`" in brief
