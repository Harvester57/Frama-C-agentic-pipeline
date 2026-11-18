"""
`ledger.py ingest-verifier`: a reproducer counts for a `confirmed` verdict only when the parent's replay
of it failed on the record's defect, not on any failure.

The candidates and replay reports under tests/fixtures/replay_identity/ are the recorded ones of
libmodbus run-1 and mpack run-4: the reports byte for byte, the candidate records as the run wrote them
(`_stage` reopens them: `unverified`, no resolved fingerprints). `inputs.json` holds the bytes of the
replayed inputs, `sources.json` the source lines the failures are at and the DAG extents of their
functions. The verdict records are written here: these tests are about which replays a verdict may
count, not about the verdicts those runs reached.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

import ledger as L
from conftest import confirmed_record, metadata, unit, write_json
from fingerprint import make_fingerprint
from module_map import ModuleMap

pytestmark = pytest.mark.unit

REPLAY_IDENTITY = Path(__file__).resolve().parent / "fixtures" / "replay_identity"
REPLAY_DIR = "workspace/reports/replay"

MODBUS = "libmodbus_run1"
MODBUS_DATA = "src/modbus-data.c"
ABCD = "src/modbus-data.c#modbus_get_float_abcd::mem_access::35b22ac2fe"
ABCD_EACSL = "src/modbus-data.c#modbus_get_float_abcd::initialization::f3c81a75e0"
ABCD_REPORT = "src_modbus-data.c_modbus_get_float_abcd_mem_access_35b22ac2fe-6c70583bd2.json"
ABCD_ASAN_INPUT = "workspace/crashes/libmodbus_so_5_1_0/crash-550974fbf6087616129fe4b148c1f154faa02e1d"
ABCD_EACSL_INPUT = "workspace/crashes/libmodbus_so_5_1_0/crash-d9605760cae43a02c1d19543b5ac4945a271dee9"
BADC = "src/modbus-data.c#modbus_get_float_badc::mem_access::8caef6cae1"
BADC_REPORT = "src_modbus-data.c_modbus_get_float_badc_mem_access_8caef6cae1-f3c13ef943.json"
BADC_INPUT = "workspace/crashes/libmodbus_so_5_1_0/crash-5892157a052cb477987072a6e488afa69278758e"
HANG = "harness_libmodbus_so_5_1_0.c#unknown_function::timeout::c2aa56485a"
HANG_REPORT = "harness_libmodbus_so_5_1_0.c_unknown_function_timeout_c2aa56485a-1d669e3ab1.json"
HANG_INPUT = "workspace/crashes/libmodbus_so_5_1_0/timeout-246633d057b6f4f9f8b086114e28a13ec0017dd6"
SEND_MSG = "src/modbus.c#send_msg::timeout::8d02b7ec71"
RTU = "src/modbus-rtu.c#modbus_rtu_set_serial_mode::rte::2820aa2803"
RTU_REPORT = "src_modbus-rtu.c_modbus_rtu_set_serial_mode_rte_2820aa2803-af66832d28.json"
FREE_REPORT = "unknown_free_freeable_c2bf36bd0d-2dba217fa2.json"

MPACK = "mpack_run4"
MPACK_EACSL = "src/mpack/mpack-writer.c#mpack_builder_complete::initialization::0f273bdef1"
MPACK_SAN = "src/mpack/mpack-writer.c#mpack_builder_complete::mem_access::6856d80f4e"
MPACK_SAN_REPORT = "src_mpack_mpack-writer.c_mpack_builder_complete_mem_access_6856d80f4e-e4b19e8d3a.json"
MPACK_INPUT = "workspace/crashes/libmpack_a__mpack_writer_2/crash-8aab9277e568265082fbe49b276a52f2adb1bf92"


def _fixture(name: str):
    return json.loads((REPLAY_IDENTITY / name).read_text(encoding="utf-8"))


def _stage(run_dir: Path, fixture: str, *, acsl_lines: int = 0) -> dict[str, dict]:
    """
    A run directory holding the fixture's candidates (reopened), replay reports, replayed inputs, DAG
    extents and source lines. With `acsl_lines`, the work tree has that many annotation lines above the
    code and `workspace/baseline` keeps the source as it was (Phase 3 after a merge). Returns the candidates.
    """
    sources = _fixture("sources.json")[fixture]
    write_json(run_dir / "run-metadata.json", metadata("in_progress"))
    functions = {
        name: {**rec, "name": name, "wave": 0, "has_loops": False, "security_properties": []}
        for name, rec in sources["functions"].items()
    }
    modules = {rec["module"]: {"tier": "Tier 1A (Untrusted Binary / Network Parser)"} for rec in functions.values()}
    write_json(
        run_dir / "workspace/reports/callgraph_dag.json",
        {"callgraph_source": "frama_c", "modules": modules, "functions": functions},
    )
    for file, lines in sources["lines"].items():
        length = max(rec["end_line"] for rec in functions.values() if rec["file"] == file)
        text = [lines.get(str(n), f"int pad_{n};") for n in range(1, length + 1)]
        trees = {"work": ["//@ ghost int annotation;"] * acsl_lines + text}
        if acsl_lines:
            trees["baseline"] = text
        for tree, body in trees.items():
            path = run_dir / "workspace" / tree / file
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("\n".join(body) + "\n", encoding="utf-8", newline="\n")
    for rel_path, blob in _fixture("inputs.json")[fixture].items():
        (run_dir / rel_path).parent.mkdir(parents=True, exist_ok=True)
        (run_dir / rel_path).write_bytes(bytes.fromhex(blob["hex"]))
    (run_dir / REPLAY_DIR).mkdir(parents=True, exist_ok=True)
    for report in sorted((REPLAY_IDENTITY / fixture / "replay").glob("*.json")):
        shutil.copyfile(report, run_dir / REPLAY_DIR / report.name)
    candidates = {}
    for recorded in _fixture(f"{fixture}/candidates.json"):
        cand = {**recorded, "status": "unverified"}
        for key in ("resolved_fingerprints", "last_rejection", "refingerprint_reason"):
            cand.pop(key, None)
        candidates[cand["fingerprint"]] = cand
    _write_candidates(run_dir, candidates)
    units = [unit(rec["file"], name, "rte", module=rec["module"]) for name, rec in functions.items()]
    if fixture == MODBUS:
        units.append(unit("src/modbus.c", "send_msg", "rte", module="libmodbus_so_5_1_0"))
    write_json(run_dir / "coverage-ledger.json", sorted(units, key=lambda u: u["coverage_id"]))
    return candidates


def _write_candidates(run_dir: Path, candidates: dict[str, dict]) -> None:
    write_json(run_dir / "candidates.json", [candidates[key] for key in sorted(candidates)])


def _record(run_dir: Path, cand: dict, report: str, input_path: str, **changed) -> dict:
    """A `confirmed` record on `cand` that lists `input_path` and cites the replay report `report`."""
    rec = confirmed_record(changed.get("fingerprint") or cand["fingerprint"])
    loc = dict(changed.get("location") or cand["location"])
    blob = (run_dir / input_path).read_bytes()
    rec.update(
        location=loc,
        property=dict(changed.get("property") or cand["property"]),
        trace=[{"kind": "sink", **loc, "description": "The failing statement."}],
        evidence=[{"phase": "fuzz", "tool_output": f"{REPLAY_DIR}/{report}", "description": "Parent replay."}],
        reproducers=[
            {
                "input": input_path,
                "sha256": hashlib.sha256(blob).hexdigest(),
                "size_bytes": len(blob),
                "command": f"fuzz_{cand['module']} {Path(input_path).name}",
                "observed_result": "The parent replay's failure.",
            }
        ],
        linked_units=[f"{loc['file']}#{loc['function']}::rte"],
    )
    rec["harness"].update(file=f"workspace/harnesses/harness_{cand['module']}.c", entry_function=loc["function"])
    return rec


def _ingest(
    run_dir: Path,
    cand_fp: str,
    rec: dict,
    reports: list[str],
    reason: str | None = None,
    more: list[dict] | None = None,
) -> dict:
    result = run_dir / "agents" / "verifier-1" / "scratch" / "verifier_result.json"
    data: dict[str, object] = {
        "role": "crash_verifier",
        "agent_id": "verifier-1",
        "candidate_fingerprint": cand_fp,
        "decision": "confirmed",
        "refingerprint_reason": reason,
        "record": rec,
    }
    if more:
        data["additional_records"] = more
    write_json(result, data)
    return L.cmd_ingest_verifier(result, replay_reports=[run_dir / REPLAY_DIR / name for name in reports])


def _findings(run_dir: Path) -> dict[str, dict]:
    path = run_dir / "findings.json"
    return {f["fingerprint"]: f for f in json.loads(path.read_text(encoding="utf-8"))} if path.is_file() else {}


def _status(run_dir: Path, fp: str) -> str:
    cands = json.loads((run_dir / "candidates.json").read_text(encoding="utf-8"))
    return next(c["status"] for c in cands if c["fingerprint"] == fp)


def _judge(run_dir: Path, cand: dict, candidates: dict[str, dict], arts: list[tuple[str, dict]]) -> tuple[str, dict]:
    """`_judge_reproducer` for a record that keeps the candidate's fingerprint and location."""
    mm = ModuleMap.load(run_dir)
    placer = L._FailurePlacer(mm, L._candidate_harness_module(mm, cand), run_dir)
    rec = {"fingerprint": cand["fingerprint"], "location": cand["location"]}
    return L._judge_reproducer(arts, L._accepted_failures(cand, candidates, rec, placer), placer)


def _artifacts(run_dir: Path, report: str) -> list[tuple[str, dict]]:
    data = json.loads((run_dir / REPLAY_DIR / report).read_text(encoding="utf-8"))
    return [(f"{REPLAY_DIR}/{report}", art) for art in data["artifacts"]]


def _site_of(file: str, line: int, function: str) -> str | None:
    return L._candidate_site(file, line, function, L._dag_line_index())


# ------------------------------------------------------------------ the regression


def test_a_replay_that_failed_at_another_candidates_statement_does_not_confirm(run_dir):
    """
    The verifier of the `modbus_get_float_badc` candidate lists an input whose parent replay is
    `reproducible: true` with the listed sha256, but failed in `modbus_get_float_abcd` (line 89, not 133):
    the shape of minmea run-1, where a verifier's seed failed in another function than the candidate's.
    """
    candidates = _stage(run_dir, MODBUS)
    rec = _record(run_dir, candidates[BADC], ABCD_REPORT, ABCD_ASAN_INPUT)
    with pytest.raises(L.LedgerError) as refused:
        _ingest(run_dir, BADC, rec, [ABCD_REPORT])
    message = str(refused.value)
    assert "on another failure" in message
    # Both failures are named: the candidate's, and the one the replay hit, with the report that says so.
    assert f"{BADC} at {MODBUS_DATA}:133 in modbus_get_float_badc" in message
    assert f"{ABCD} at {MODBUS_DATA}:89 in modbus_get_float_abcd" in message
    assert f"{REPLAY_DIR}/{ABCD_REPORT}" in message
    assert f"That failure is candidate {ABCD} (unverified), which gets its own verdict" in message
    assert _findings(run_dir) == {} and _status(run_dir, BADC) == "unverified"


# ------------------------------------------------------------------ what still confirms


def test_a_replay_on_the_candidates_fingerprint_confirms(run_dir):
    candidates = _stage(run_dir, MODBUS)
    rec = _record(run_dir, candidates[BADC], BADC_REPORT, BADC_INPUT)
    out = _ingest(run_dir, BADC, rec, [BADC_REPORT])
    assert out["decision"] == "confirmed" and "reproducers_not_compared" not in out
    finding = _findings(run_dir)[BADC]
    assert finding["verdict"] == "confirmed" and len(finding["evidence"]) == 1
    assert _status(run_dir, BADC) == "verified"


def test_a_replay_by_the_other_engine_at_the_candidates_statement_confirms(run_dir):
    """E-ACSL reports the sanitizer candidate's statement under its own fingerprint (another kind and hash)."""
    candidates = _stage(run_dir, MODBUS)
    cand = candidates[ABCD]
    # The staged source gives the site the run recorded, so the comparison below is the run's.
    assert _site_of(MODBUS_DATA, 89, "modbus_get_float_abcd") == cand["site"]
    eacsl = [a for a in _artifacts(run_dir, ABCD_REPORT) if a[1]["fingerprint"] == ABCD_EACSL]
    assert _judge(run_dir, cand, candidates, eacsl)[1]["basis"] == "the fingerprint of an observation of the candidate"
    # Without the E-ACSL and Eva observations, the statement site alone says it is the same defect.
    cand["observations"] = [o for o in cand["observations"] if o["fingerprint"] == ABCD]
    assert _judge(run_dir, cand, candidates, eacsl)[1]["basis"] == "the statement site of the candidate"
    _write_candidates(run_dir, candidates)
    out = _ingest(run_dir, ABCD, _record(run_dir, cand, ABCD_REPORT, ABCD_EACSL_INPUT), [ABCD_REPORT])
    assert out["decision"] == "confirmed" and "reproducers_not_compared" not in out
    assert _findings(run_dir)[ABCD]["verdict"] == "confirmed"


@pytest.mark.parametrize("acsl_lines", [7, 40])
def test_annotations_merged_above_the_statement_keep_the_comparison(run_dir, acsl_lines):
    """
    Phase 3: the work tree has annotation lines the baseline has not. The recorded report names the
    statement by its line before the merge (89); a replay made after it names the shifted line. With 40
    lines, the shifted line lies in the baseline extent of the next function. Both are the candidate's site.
    """
    candidates = _stage(run_dir, MODBUS, acsl_lines=acsl_lines)
    cand = candidates[ABCD]
    cand["observations"] = [o for o in cand["observations"] if o["fingerprint"] == ABCD]
    _write_candidates(run_dir, candidates)
    assert _site_of(MODBUS_DATA, 89, "modbus_get_float_abcd") != cand["site"]  # line 89 is other text now
    mm = ModuleMap.load(run_dir)
    placer = L._FailurePlacer(mm, "libmodbus_so_5_1_0", run_dir)
    assert cand["site"] in placer.sites(MODBUS_DATA, 89, "modbus_get_float_abcd")
    assert cand["site"] in placer.sites(MODBUS_DATA, 89 + acsl_lines, "modbus_get_float_abcd")
    out = _ingest(run_dir, ABCD, _record(run_dir, cand, ABCD_REPORT, ABCD_EACSL_INPUT), [ABCD_REPORT])
    assert out["decision"] == "confirmed" and "reproducers_not_compared" not in out


def test_a_replay_on_a_related_candidates_failure_confirms(run_dir):
    """mpack: the sanitizer build stops two lines above the E-ACSL candidate's statement; the two are `related`."""
    candidates = _stage(run_dir, MPACK)
    cand = candidates[MPACK_EACSL]
    rec = _record(run_dir, cand, MPACK_SAN_REPORT, MPACK_INPUT)
    out = _ingest(run_dir, MPACK_EACSL, rec, [MPACK_SAN_REPORT])
    assert out["decision"] == "confirmed" and "reproducers_not_compared" not in out
    assert _findings(run_dir)[MPACK_EACSL]["verdict"] == "confirmed"


def test_the_same_replay_without_the_related_link_does_not_confirm(run_dir):
    candidates = _stage(run_dir, MPACK)
    del candidates[MPACK_EACSL]["related"]
    _write_candidates(run_dir, candidates)
    rec = _record(run_dir, candidates[MPACK_EACSL], MPACK_SAN_REPORT, MPACK_INPUT)
    with pytest.raises(L.LedgerError) as refused:
        _ingest(run_dir, MPACK_EACSL, rec, [MPACK_SAN_REPORT])
    message = str(refused.value)
    assert f"{MPACK_EACSL} at src/mpack/mpack-writer.c:1793" in message
    assert f"{MPACK_SAN} at src/mpack/mpack-writer.c:1791" in message
    assert f"That failure is candidate {MPACK_SAN} (unverified)" in message
    assert _findings(run_dir) == {}


def test_a_record_that_keeps_the_fingerprint_cannot_move_the_statement(run_dir):
    """The record is the verifier's: writing the line its input failed at (1791) does not make that the defect."""
    candidates = _stage(run_dir, MPACK)
    del candidates[MPACK_EACSL]["related"]
    _write_candidates(run_dir, candidates)
    rec = _record(
        run_dir,
        candidates[MPACK_EACSL],
        MPACK_SAN_REPORT,
        MPACK_INPUT,
        location={**candidates[MPACK_EACSL]["location"], "line": 1791},
    )
    with pytest.raises(L.LedgerError, match="on another failure") as refused:
        _ingest(run_dir, MPACK_EACSL, rec, [MPACK_SAN_REPORT])
    assert f"the candidate's failure: {MPACK_EACSL} at src/mpack/mpack-writer.c:1793" in str(refused.value)
    assert _findings(run_dir) == {}


def test_a_refingerprinted_record_counts_a_replay_on_the_failure_it_names(run_dir):
    """What the refusal above leaves open: a record that says, with a reason, that the defect is the other statement."""
    candidates = _stage(run_dir, MPACK)
    del candidates[MPACK_EACSL]["related"]
    _write_candidates(run_dir, candidates)
    renamed = make_fingerprint(
        "src/mpack/mpack-writer.c", "mpack_builder_complete", "mem_access", "no build in progress"
    )
    rec = _record(
        run_dir,
        candidates[MPACK_EACSL],
        MPACK_SAN_REPORT,
        MPACK_INPUT,
        fingerprint=renamed,
        location={**candidates[MPACK_EACSL]["location"], "line": 1791},
    )
    out = _ingest(
        run_dir, MPACK_EACSL, rec, [MPACK_SAN_REPORT], reason="The defect is the missing build, two lines up."
    )
    assert out["decision"] == "confirmed" and "reproducers_not_compared" not in out
    assert _findings(run_dir)[renamed]["verdict"] == "confirmed"


def _split_off_record(run_dir: Path, candidates: dict[str, dict], input_path: str) -> dict:
    """An additional record on the `badc` candidate that names the `abcd` statement as a second defect."""
    fp = make_fingerprint(MODBUS_DATA, "modbus_get_float_abcd", "mem_access", "\\valid_read(src + (0 .. 1))")
    return _record(
        run_dir,
        candidates[BADC],
        ABCD_REPORT,
        input_path,
        fingerprint=fp,
        location=candidates[ABCD]["location"],
    )


def test_an_additional_record_counts_a_replay_on_its_own_failure(run_dir):
    candidates = _stage(run_dir, MODBUS)
    first = _record(run_dir, candidates[BADC], BADC_REPORT, BADC_INPUT)
    second = _split_off_record(run_dir, candidates, ABCD_ASAN_INPUT)
    out = _ingest(run_dir, BADC, first, [BADC_REPORT, ABCD_REPORT], reason="Two defects.", more=[second])
    assert out["decision"] == "confirmed" and "reproducers_not_compared" not in out
    assert {f["verdict"] for f in _findings(run_dir).values()} == {"confirmed"}
    assert set(_findings(run_dir)) == {BADC, second["fingerprint"]}


def test_an_additional_record_does_not_count_a_replay_on_the_candidates_failure(run_dir):
    """A split-off record is another defect: the input that fails at the candidate's statement does not show it."""
    candidates = _stage(run_dir, MODBUS)
    first = _record(run_dir, candidates[BADC], BADC_REPORT, BADC_INPUT)
    second = _split_off_record(run_dir, candidates, BADC_INPUT)
    with pytest.raises(L.LedgerError, match="on another failure") as refused:
        _ingest(run_dir, BADC, first, [BADC_REPORT, ABCD_REPORT], reason="Two defects.", more=[second])
    message = str(refused.value)
    assert f"this additional record's own failure: {second['fingerprint']} at {MODBUS_DATA}:89" in message
    assert f"The replay hit: {BADC} at {MODBUS_DATA}:133" in message
    assert _findings(run_dir) == {} and _status(run_dir, BADC) == "unverified"


def test_a_candidate_without_a_line_is_compared_by_function_and_kind(run_dir):
    """
    A breaker's hypothesis has no line. The replay names line 1053 of the annotated work tree, which the
    baseline extents place in `modbus_rtu_set_rts`: the function the report names decides.
    """
    candidates = _stage(run_dir, MODBUS)
    outcome, seen = _judge(run_dir, candidates[RTU], candidates, _artifacts(run_dir, RTU_REPORT))
    assert outcome == "match"
    assert seen["basis"] == "the function and kind of the candidate (one of the two has no statement to compare)"
    assert seen["functions"] == {"modbus_rtu_set_serial_mode", "modbus_rtu_set_rts"}
    # The same replay is not the failure of a candidate that has a statement elsewhere,
    assert _judge(run_dir, candidates[BADC], candidates, _artifacts(run_dir, RTU_REPORT))[0] == "mismatch"
    # nor of a hypothesis of another kind in that function: only a hypothesis that leaves its kind open (`rte`) matches.
    other_kind = {**candidates[RTU], "property": {"kind": "signed_overflow", "predicate": "mode + 1 <= 2147483647"}}
    assert _judge(run_dir, other_kind, candidates, _artifacts(run_dir, RTU_REPORT))[0] == "mismatch"


# ------------------------------------------------------------------ a replay that names no statement


def test_an_unparsed_failure_counts_for_the_candidates_own_input_and_the_finding_says_so(run_dir):
    """
    The timeout candidate's replay failed (return code 70) and no failure report could be parsed. The input
    was recorded on the candidate by the campaign, so it counts, and the finding records what was not compared.
    """
    candidates = _stage(run_dir, MODBUS)
    rec = _record(
        run_dir,
        candidates[HANG],
        HANG_REPORT,
        HANG_INPUT,
        fingerprint=SEND_MSG,
        location={"file": "src/modbus.c", "line": 210, "function": "send_msg"},
        property={"kind": "timeout", "predicate": "send_msg does not terminate when the backend send keeps failing"},
    )
    out = _ingest(run_dir, HANG, rec, [HANG_REPORT], reason="The hang is the retry loop of send_msg.")
    sha = rec["reproducers"][0]["sha256"]
    assert out["decision"] == "confirmed" and out["reproducers_not_compared"] == [sha]
    notes = [e for e in _findings(run_dir)[SEND_MSG]["evidence"] if e["description"].startswith("Failure identity not")]
    assert len(notes) == 1 and notes[0]["tool_output"] == f"{REPLAY_DIR}/{HANG_REPORT}"
    assert "no failure report could be parsed from its output (return code 70)" in notes[0]["description"]
    assert HANG_INPUT in notes[0]["description"] and sha in notes[0]["description"]
    assert "recorded on the candidate before verification" in notes[0]["description"]


def test_an_unparsed_failure_does_not_count_for_an_input_the_candidate_did_not_record(run_dir):
    """The same replay, listed by the verifier of another candidate: nothing shows it is that candidate's failure."""
    candidates = _stage(run_dir, MODBUS)
    rec = _record(run_dir, candidates[BADC], HANG_REPORT, HANG_INPUT)
    with pytest.raises(L.LedgerError) as refused:
        _ingest(run_dir, BADC, rec, [HANG_REPORT])
    message = str(refused.value)
    assert "cannot be compared with the candidate's failure" in message
    assert "no failure report could be parsed from its output (return code 70)" in message
    assert f"{BADC} at {MODBUS_DATA}:133" in message and f"{REPLAY_DIR}/{HANG_REPORT}" in message
    assert _findings(run_dir) == {} and _status(run_dir, BADC) == "unverified"


def test_a_failure_without_a_source_line_is_not_compared(run_dir):
    """A runtime's libc check (`unknown#free::freeable`, line 0) names no statement of the target."""
    candidates = _stage(run_dir, MODBUS)
    outcome, seen = _judge(run_dir, candidates[BADC], candidates, _artifacts(run_dir, FREE_REPORT))
    assert outcome == "uncompared"
    assert seen["what"] == "the failure it reports (unknown#free::freeable::c2bf36bd0d) has no source line"


def test_a_report_that_kept_only_the_fingerprint_is_compared_by_it(run_dir):
    """
    The older report shape, cut from the recorded artifacts: sha256, `reproducible` and the fingerprint,
    no `failure`. The candidate's own fingerprint matches; another one names no statement to refuse on.
    """
    candidates = _stage(run_dir, MODBUS)
    keep = ("artifact", "sha256", "size_bytes", "reproducible", "fingerprint")
    own = [(r, {k: a[k] for k in keep}) for r, a in _artifacts(run_dir, BADC_REPORT)]
    other = [(r, {k: a[k] for k in keep}) for r, a in _artifacts(run_dir, ABCD_REPORT) if a["fingerprint"] == ABCD]
    assert _judge(run_dir, candidates[BADC], candidates, own)[1]["basis"] == "the fingerprint of the candidate"
    outcome, seen = _judge(run_dir, candidates[BADC], candidates, other)
    assert outcome == "uncompared" and seen["what"] == f"the failure it reports ({ABCD}) has no source line"
    # One replay that names the candidate's failure is enough, whatever the others say.
    assert _judge(run_dir, candidates[BADC], candidates, other + own)[0] == "match"
