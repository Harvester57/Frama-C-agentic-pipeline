"""Crash Verifier brief gaps: replay engine, Rule 2, layout, and the harness a verifier names.

- A candidate found by the sanitizer build replays clean on the E-ACSL binary (minmea run-1,
  `verify-minmea_parse_zda_ea5e61f9eb`): the brief must send the verifier to the candidate's own engine.
- Strict Rule 2 must not limit `confirmed` to E-ACSL failures: the pipeline confirms sanitizer
  (including LeakSanitizer) failures the parent's replay reproduces.
- A candidate may carry its link unit: the verifier's brief names the sub-module harness the parent replays on.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import crash_replay
import ledger
import workspace_overlay as WO
from conftest import ROOT, confirmed_record, metadata, unit, write_json
from fingerprint import make_fingerprint

_BRIEF_PATH = ROOT / "skills" / "framac-wp" / "crash_verifier_brief.md"
_SAN_FP = make_fingerprint("minmea.c", "minmea_parse_zda", "signed_overflow", "-x <= 2147483647")


def _brief_text() -> str:
    return _BRIEF_PATH.read_text(encoding="utf-8")


def _section(text: str, heading: str) -> str:
    start = text.index(heading)
    nxt = text.find("\n### ", start + len(heading))
    nxt2 = text.find("\n## ", start + len(heading))
    ends = [e for e in (nxt, nxt2) if e != -1]
    return text[start : min(ends)] if ends else text[start:]


# Gap 1: replay with the candidate's engine.


def test_case_a_replays_with_the_candidates_engine_and_keeps_the_sanitizer_witness():
    case_a = _section(_brief_text(), "### Case A")
    assert "Replay with the engine that found the candidate" in case_a
    assert "--engine sanitizers" in case_a
    assert "sanitizer_compile.binary" in case_a
    assert "eacsl+sanitizers" in case_a
    # The E-ACSL clean replay is expected and stated, never a reason to reject.
    assert "not_reproduced" in case_a
    assert "record.verifier.notes" in case_a
    assert "never reject the candidate because of it" in case_a


def test_dual_engine_report_names_the_sanitizer_engine_for_a_sanitizer_artifact(run_dir: Path):
    """What the parent's replay keys the engine on (crash_replay._candidate_engine), as the brief says."""
    write_json(
        run_dir / "workspace/reports/fuzz/minmea.json",
        {
            "module": "minmea",
            "engine_used": "eacsl+sanitizers",
            "compile": {"binary": "workspace/harnesses/fuzz_minmea.e-acsl"},
            "sanitizer_compile": {"binary": "workspace/harnesses/fuzz_minmea"},
            "artifacts": [{"fingerprint": _SAN_FP, "engine": "sanitizers"}],
        },
    )
    cand = {"fingerprint": _SAN_FP, "tool_outputs": ["workspace/reports/fuzz/minmea.json"]}
    assert crash_replay._candidate_engine(cand) == "sanitizers"


def test_an_observation_reproducer_replays_on_its_own_engine():
    cand = {
        "fingerprint": _SAN_FP,
        "reproducers": ["workspace/crashes/minmea/crash-a", "workspace/crashes/minmea/crash-b"],
        "observations": [
            {"fingerprint": _SAN_FP, "engine": "sanitizers", "reproducer": "workspace/crashes/minmea/crash-b"}
        ],
    }
    groups = crash_replay._reproducers_by_engine(cand, "eacsl", use_observations=True)
    assert {k: [p.name for p in v] for k, v in groups.items()} == {"eacsl": ["crash-a"], "sanitizers": ["crash-b"]}


def test_ingest_verifier_confirms_a_sanitizer_only_witness_with_a_clean_eacsl_replay(run_dir: Path):
    """The parent's sanitizer replay reproduces, its E-ACSL replay does not: the verdict is confirmed."""
    write_json(run_dir / "run-metadata.json", metadata("in_progress"))
    fuzz_rel = "workspace/reports/fuzz/minmea.json"
    # The fuzz report alone holds no reproducible artifact: only the parent's replays can confirm.
    write_json(run_dir / fuzz_rel, {"module": "minmea", "engine_used": "eacsl+sanitizers", "artifacts": []})
    fuzz_evidence = {
        "phase": "fuzz",
        "producer": "run_eacsl_fuzz.py",
        "result": "fuzz_failure",
        "discharging": False,
        "tool_output": fuzz_rel,
        "summary": "UBSan failure on the sanitizer build",
    }
    write_json(
        run_dir / "coverage-ledger.json",
        [
            unit(
                "minmea.c",
                "minmea_parse_zda",
                "rte",
                status="candidate",
                evidence=[fuzz_evidence],
                result_fingerprints=[_SAN_FP],
            )
        ],
    )
    crash = b"$GPZDA,,,,-2147483648,00*00"
    sha = hashlib.sha256(crash).hexdigest()
    crash_rel = "workspace/crashes/minmea/crash-zda"
    (run_dir / crash_rel).parent.mkdir(parents=True, exist_ok=True)
    (run_dir / crash_rel).write_bytes(crash)
    art = {"artifact": crash_rel, "sha256": sha, "size_bytes": len(crash)}
    san_report = run_dir / "workspace/reports/replay/zda-san.json"
    write_json(
        san_report,
        {
            "mode": "replay",
            "status": "reproduced",
            "engine_used": "sanitizers",
            "artifacts": [{**art, "reproducible": True, "fingerprint": _SAN_FP}],
        },
    )
    eacsl_report = run_dir / "workspace/reports/replay/zda-eacsl.json"
    write_json(
        eacsl_report,
        {
            "mode": "replay",
            "status": "not_reproduced",
            "engine_used": "eacsl",
            "artifacts": [{**art, "reproducible": False}],
        },
    )
    write_json(
        run_dir / "candidates.json",
        [
            {
                "fingerprint": _SAN_FP,
                "status": "unverified",
                "origin": "fuzz",
                "proposed_verdict": "confirmed",
                "module": "minmea",
                "location": {"file": "minmea.c", "line": 635, "function": "minmea_parse_zda"},
                "property": {"kind": "signed_overflow", "predicate": "-x <= 2147483647"},
                "reproducers": [crash_rel],
                "tool_outputs": [fuzz_rel],
                "linked_units": ["minmea.c#minmea_parse_zda::rte"],
                "first_seen": "2026-11-14T00:00:00+00:00",
            }
        ],
    )
    rec = confirmed_record(_SAN_FP)
    rec["location"] = {"file": "minmea.c", "line": 635, "function": "minmea_parse_zda"}
    rec["property"] = {"kind": "signed_overflow", "predicate": "-x <= 2147483647"}
    rec["linked_units"] = ["minmea.c#minmea_parse_zda::rte"]
    rec["evidence"] = [{"phase": "fuzz", "tool_output": fuzz_rel, "description": "UBSan replay on the sanitizer build"}]
    rec["reproducers"] = [
        {
            "input": crash_rel,
            "sha256": sha,
            "size_bytes": len(crash),
            "command": "python3 /opt/framac-pipeline/scripts/run_eacsl_fuzz.py replay --module minmea "
            "--inputs workspace/crashes/minmea/crash-zda --binary workspace/harnesses/fuzz_minmea",
            "observed_result": "UBSan: negation of -2147483648 cannot be represented in type int",
        }
    ]
    rec["verifier"]["notes"] = "E-ACSL build: not_reproduced (abs() is in libc, not instrumented); expected."
    res_path = run_dir / "agents/verifier-1/scratch/result.json"
    write_json(
        res_path,
        {
            "role": "crash_verifier",
            "agent_id": "verifier-1",
            "candidate_fingerprint": _SAN_FP,
            "decision": "confirmed",
            "refingerprint_reason": None,
            "record": rec,
        },
    )
    # The E-ACSL replay alone confirms nothing: the sanitizer replay is the witness.
    with pytest.raises(ledger.LedgerError, match="parent-verified reproducible crash report"):
        ledger.cmd_ingest_verifier(res_path, replay_reports=[eacsl_report])
    out = ledger.cmd_ingest_verifier(res_path, replay_reports=[eacsl_report, san_report])
    assert out["decision"] == "confirmed"
    findings = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))
    assert [f["verdict"] for f in findings] == ["confirmed"]


# Gap 2: Rule 2 names every engine whose failure the parent's replay accepts.


def test_rule_2_accepts_sanitizer_and_leaksanitizer_failures():
    rules = _section(_brief_text(), "## Strict Rules")
    rule2 = rules[rules.index("2. **Never Confirm") : rules.index("3. **Severity")]
    assert "triggers an E-ACSL failure through the module harness" not in rule2
    for engine in ("E-ACSL", "ASan", "UBSan", "LeakSanitizer"):
        assert engine in rule2
    assert "parent's own replay" in rule2


# Gap 3: layout.


def test_counter_example_witnesses_are_in_case_b_and_leaks_follow_case_b():
    text = _brief_text()
    case_a = _section(text, "### Case A")
    case_b = _section(text, "### Case B")
    assert "WP counter-example witnesses" not in case_a
    assert "WP counter-example witnesses" in case_b
    pos_a, pos_b = text.index("### Case A"), text.index("### Case B")
    pos_leak, pos_dp = text.index("### Memory Leaks"), text.index("### Decision Point")
    assert pos_a < pos_b < pos_leak < pos_dp


# Gap 4: the harness a verifier names.


def test_brief_template_builds_harness_paths_from_the_harness_module():
    text = _brief_text()
    for stale in ("harness_{module_name}", "fuzz_{module_name}", "--module {module_name}", "fuzz/{module_name}"):
        assert stale not in text, stale


def test_verifier_brief_names_the_submodule_harness_of_a_link_unit_candidate(tmp_path: Path):
    """A hypothesis candidate carries its link unit (`libm_a`); its harness is the sub-module `m`."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "m.c").write_text("int parse(char *s) { return s ? 1 : 0; }\n", encoding="utf-8")
    run = tmp_path / "run"
    WO.init_overlay(target, run / "workspace")
    write_json(run / "run-metadata.json", {"profile": "standard"})
    write_json(
        run / "workspace/reports/callgraph_dag.json",
        {
            "modules": {"libm_a": {"tier": "Tier 1A", "functions": ["parse"]}},
            "functions": {"parse": {"name": "parse", "file": "m.c", "module": "libm_a", "wave": 0}},
        },
    )
    write_json(
        run / "workspace/harnesses/harness_m.json",
        {"module": "m", "unit": "libm_a", "sources": ["workspace/work/m.c"], "header": "m.h", "entry_fn": "parse"},
    )
    write_json(
        run / "workspace/harnesses/harness_tf_x.json",
        {
            "module": "tf_x",
            "unit": "libm_a",
            "sources": ["workspace/work/m.c", "workspace/work/fuzz.c"],
            "target_fuzzer": {"id": "x", "source": "workspace/work/fuzz.c"},
        },
    )
    fp = make_fingerprint("m.c", "parse", "mem_access", r"\valid_read(s)")
    write_json(
        run / "candidates.json",
        [
            {
                "fingerprint": fp,
                "status": "unverified",
                "origin": "breaker",
                "module": "libm_a",
                "location": {"file": "m.c", "line": 1, "function": "parse"},
            }
        ],
    )
    WO.prepare_agent(run_dir=run, agent_id="verify-parse", role="verifier", module="libm_a", candidate_fp=fp)
    brief = (run / "agents/verify-parse/brief.md").read_text(encoding="utf-8")
    assert "workspace/harnesses/harness_m.c" in brief
    assert "workspace/reports/fuzz/m.json" in brief
    assert "--module m " in brief
    assert "harness_libm_a" not in brief
    assert "--module libm_a" not in brief
    # Sources and flags come from the sub-module's sidecar, not the unit's merged one.
    assert "fuzz.c" not in brief
    # The candidate's own module is still named.
    assert "in module **`libm_a`**" in brief
