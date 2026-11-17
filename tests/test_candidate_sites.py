"""Candidates grouped by statement site (D1, D1a): the site key and the ledger's use of it."""

from __future__ import annotations

import copy

import pytest

import failure_identity as FI
import ledger as L
from conftest import write_json
from fingerprint import make_fingerprint
from test_ledger import DAG, load, seed, units_by_id
from validate_artifacts import validate_candidates

pytestmark = pytest.mark.unit

BER = "src/snmp/ber.c"
PRED_SAN = "mem_access: \\valid_read(buf + off)"
PRED_SAN_NEXT = "mem_access: \\valid_read(buf + off + 1)"
PRED_EACSL = "mem_access: \\valid(buf + off)"
PRED_EVA = "mem_access: \\valid_read(buf + off + 2)"
RTE_UNIT = "src/snmp/ber.c#ber_decode_len::rte"


def _ber_source(lines_above: int = 0) -> str:
    """ber.c with `ber_decode_len` at lines 30-60: lines 42 and 44 identical, line 47 different."""
    body = [f"int pad_{i};" for i in range(1, 61)]
    body[41] = "    return buf[off];"  # line 42
    body[43] = "    return buf[off];"  # line 44
    body[46] = "    buf[off] = 0;"  # line 47
    return "\n".join(["/* header */"] * lines_above + body) + "\n"


@pytest.fixture
def ber_run(run_dir):
    """A seeded run with ber.c's source and the DAG's extents for ber_decode_len (30-60)."""
    seed(run_dir)
    dag = copy.deepcopy(DAG)
    dag["functions"]["ber_decode_tag"].update(line=10, end_line=25)
    dag["functions"]["ber_decode_len"].update(line=30, end_line=60)
    write_json(run_dir / "workspace/reports/callgraph_dag.json", dag)
    src = run_dir / "workspace" / "work" / "src" / "snmp"
    src.mkdir(parents=True, exist_ok=True)
    (src / "ber.c").write_text(_ber_source(), encoding="utf-8")
    return run_dir


def _fuzz(run_dir, name: str, *, engine: str, predicate: str, line: int, function: str = "ber_decode_len") -> str:
    """Ingest one fuzz report with one reproducible failure; returns the detection's fingerprint."""
    crash = run_dir / "workspace" / "crashes" / "snmp" / f"crash-{name}"
    crash.parent.mkdir(parents=True, exist_ok=True)
    crash.write_bytes(b"\x30\x84")
    fp = make_fingerprint(BER, function, "mem_access", predicate)
    report = {
        "mode": "campaign",
        "module": "snmp",
        "status": "crash_found",
        "engine_used": engine,
        "artifacts": [
            {
                "artifact": str(crash),
                "kind": "crash",
                "sha256": name,
                "size_bytes": 2,
                "reproducible": True,
                "engine": engine,
                "fingerprint": fp,
                "failure": {
                    "file": "/framac-run/workspace/work/src/snmp/ber.c",
                    "function": function,
                    "kind": "assertion",
                    "alarm_kind": "mem_access",
                    "is_rte": True,
                    "predicate": predicate,
                    "line": line,
                },
            }
        ],
    }
    path = run_dir / "workspace" / "reports" / "fuzz" / f"snmp-{name}.json"
    write_json(path, report)
    L.cmd_ingest_fuzz([path])
    return fp


def _candidates(run_dir) -> dict[str, dict]:
    return {c["fingerprint"]: c for c in load(run_dir / "candidates.json")}


SITE_SOURCE = """\
int f(int *p, int n) {
    p[n] = 0;
    p[n] = 0;
    return p[0];
}
int g(int *q) {
    q[1] = 0;
    return q[1];
}
"""


@pytest.fixture
def site_run(tmp_path, monkeypatch):
    """A run directory whose workspace/work holds src/site.c."""
    src = tmp_path / "workspace" / "work" / "src"
    src.mkdir(parents=True)
    (src / "site.c").write_text(SITE_SOURCE, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_two_identical_lines_in_one_function_give_two_sites(site_run):
    fn_range = (1, 5)  # f
    first = FI.site_key("src/site.c", "f", 2, fn_range)
    second = FI.site_key("src/site.c", "f", 3, fn_range)
    assert first is not None and second is not None
    assert first != second
    assert first.endswith("#1") and second.endswith("#2")


def test_a_unique_line_has_no_occurrence_suffix(site_run):
    key = FI.site_key("src/site.c", "g", 7, (6, 9))
    assert key is not None and "#" not in key.split("@", 1)[1]


def test_the_key_ignores_the_range_when_the_line_is_unique_in_it(site_run):
    with_range = FI.site_key("src/site.c", "g", 7, (6, 9))
    without_range = FI.site_key("src/site.c", "g", 7)
    assert with_range == without_range


def test_lines_inserted_above_keep_the_site(site_run):
    before = FI.site_key("src/site.c", "g", 7, (6, 9))
    text = (site_run / "workspace" / "work" / "src" / "site.c").read_text(encoding="utf-8")
    (site_run / "workspace" / "work" / "src" / "site.c").write_text(
        "/* a */\n/* b */\n/* c */\n" + text, encoding="utf-8"
    )
    after = FI.site_key("src/site.c", "g", 10, (9, 12))
    assert before is not None and before == after


def test_a_site_needs_a_readable_line(site_run):
    assert FI.site_key("src/missing.c", "f", 2) is None
    assert FI.site_key("src/site.c", "f", 0) is None
    assert FI.site_key("src/site.c", "f", 999) is None


def test_the_site_key_is_file_function_and_text_hash(site_run):
    key = FI.site_key("src/site.c", "g", 7)
    assert key == f"src/site.c#g@{FI.line_text_hash('src/site.c', 7)}"


# ------------------------------------------------------------------ the ledger's grouping (F5)


def _ber_path(run_dir):
    return run_dir / "workspace" / "work" / "src" / "snmp" / "ber.c"


def test_asan_eacsl_and_eva_at_one_statement_give_one_candidate_with_three_observations(ber_run):
    fp_san = _fuzz(ber_run, "san", engine="sanitizers", predicate=PRED_SAN, line=42)
    _fuzz(ber_run, "eac", engine="eacsl", predicate=PRED_EACSL, line=42)
    units, candidates = L.load_state()
    alarm = {"kind": "mem_access", "annotation": PRED_EVA, "line": 42, "function": "ber_decode_len", "file": BER}
    L._ingest_unscheduled_eva_invalid(units, candidates, alarm, "snmp", "eva.json")
    L.commit(units, candidates)
    cands = _candidates(ber_run)
    assert list(cands) == [fp_san]
    assert [o["origin"] for o in cands[fp_san]["observations"]] == ["fuzz", "fuzz", "eva"]
    # The Eva detection links its unit under the candidate's key, not its own fingerprint.
    assert units_by_id(ber_run)[RTE_UNIT]["result_fingerprints"] == [fp_san]


def test_two_overflows_on_two_lines_give_two_candidates(ber_run):
    fp_a = _fuzz(ber_run, "a", engine="sanitizers", predicate=PRED_SAN, line=42)
    fp_b = _fuzz(ber_run, "b", engine="sanitizers", predicate=PRED_SAN_NEXT, line=47)
    assert sorted(_candidates(ber_run)) == sorted([fp_a, fp_b])


def test_two_identical_lines_in_one_function_give_two_candidates(ber_run):
    _fuzz(ber_run, "a", engine="sanitizers", predicate=PRED_SAN, line=42)
    _fuzz(ber_run, "b", engine="sanitizers", predicate=PRED_SAN_NEXT, line=44)
    assert len(_candidates(ber_run)) == 2


def test_lines_inserted_above_keep_the_site_of_a_candidate(ber_run):
    fp_a = _fuzz(ber_run, "a", engine="sanitizers", predicate=PRED_SAN, line=42)
    _ber_path(ber_run).write_text(_ber_source(lines_above=3), encoding="utf-8")
    _fuzz(ber_run, "b", engine="eacsl", predicate=PRED_EACSL, line=45)
    cands = _candidates(ber_run)
    assert list(cands) == [fp_a]
    assert len(cands[fp_a]["observations"]) == 2


def test_a_detection_at_the_site_of_a_verified_candidate_opens_a_new_candidate(ber_run):
    fp_a = _fuzz(ber_run, "a", engine="sanitizers", predicate=PRED_SAN, line=42)
    records = load(ber_run / "candidates.json")
    for rec in records:
        if rec["fingerprint"] == fp_a:
            rec["status"] = "verified"
    write_json(ber_run / "candidates.json", records)
    fp_b = _fuzz(ber_run, "b", engine="eacsl", predicate=PRED_EACSL, line=42)
    cands = _candidates(ber_run)
    assert sorted(cands) == sorted([fp_a, fp_b])
    assert cands[fp_a]["status"] == "verified"


def test_the_eacsl_observation_sets_the_property_of_a_sanitizer_candidate(ber_run):
    fp_a = _fuzz(ber_run, "a", engine="sanitizers", predicate=PRED_SAN, line=42)
    _fuzz(ber_run, "b", engine="eacsl", predicate=PRED_EACSL, line=42)
    assert _candidates(ber_run)[fp_a]["property"]["predicate"] == PRED_EACSL


def test_a_code_fault_at_a_known_site_links_the_site_candidates_key(ber_run):
    """The prover's code fault is the third ingest path: it must not link its own fingerprint."""
    from test_ledger_p1 import _code_fault_report, _prover_result

    key = _fuzz(ber_run, "a", engine="sanitizers", predicate=PRED_SAN, line=42)
    aid = "prover-site"
    scratch = ber_run / "agents" / aid / "scratch"
    report = _code_fault_report("/container/run/none")
    # Another kind and predicate than the candidate's, so the function-and-kind rule cannot find it: only the site can.
    report["failure"]["alarm_kind"] = "uninitialized"
    report["failure"]["predicate"] = r"\initialized(buf + off)"
    write_json(scratch / "guard_ber_decode_len.json", report)
    write_json(scratch / "wp_ber_decode_len.json", {"status": "unproven_goals_remain"})
    res_path = scratch / "result.json"
    write_json(
        res_path,
        _prover_result(
            aid,
            [
                {"tool_output": f"agents/{aid}/scratch/wp_ber_decode_len.json", "result": "unproven_goals_remain"},
                {"tool_output": f"agents/{aid}/scratch/guard_ber_decode_len.json", "result": "code_fault"},
            ],
        ),
    )
    out = L.cmd_ingest_agent_hypothesis(res_path, module="snmp")
    assert out["candidates_added"] == 0
    assert list(_candidates(ber_run)) == [key]
    assert units_by_id(ber_run)[RTE_UNIT]["result_fingerprints"] == [key]


def test_candidates_without_site_load_and_validate(run_dir):
    old_fp = make_fingerprint(BER, "ber_decode_len", "mem_access", PRED_SAN)
    old = {
        "fingerprint": old_fp,
        "status": "unverified",
        "origin": "fuzz",
        "proposed_verdict": "needs_validation",
        "module": "snmp",
        "location": {"file": BER, "line": 42, "function": "ber_decode_len"},
        "property": {"kind": "mem_access", "predicate": PRED_SAN},
        "reproducers": [],
        "tool_outputs": ["workspace/reports/fuzz/old.json"],
        "linked_units": [],
        "first_seen": "2026-11-01T00:00:00Z",
    }
    write_json(run_dir / "candidates.json", [old])
    assert list(validate_candidates(load(run_dir / "candidates.json"))) == []
    units, candidates = L.load_state()
    assert candidates[old_fp].get("observations") is None
