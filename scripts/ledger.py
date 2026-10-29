#!/usr/bin/env python3
"""
Coverage ledger, candidate, and verifier verdict management (parent-only writer).

Subcommands (run with the run directory as working directory):
  seed                     --dag workspace/reports/callgraph_dag.json [--scope PATH ...]
  ingest-fuzz              <workspace/reports/fuzz/*.json ...>
  ingest-eva               <workspace/reports/eva/*.json ...>
  ingest-wp                <workspace/reports/wp/*.json ...>
  ingest-agent-hypothesis  <agent_result.json> [--module MOD]
  ingest-verifier          <verifier_result.json> [--replay-report <fuzz.json> ...] [--harness-meta <harness_mod.json>]
  transition               --id COVERAGE_ID --status STATUS [--agent-id ID] [--reason TEXT]
  summary

Units are function x obligation class (docs/v2-design.md, Section 5). Every write
is validated against schemas/ before it is committed atomically; an invalid
result is never written.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fingerprint import make_fingerprint, normalize_file  # noqa: E402
from framac_common import ArtifactError, atomic_write_json, load_json_optional, load_json_strict, utc_now  # noqa: E402
from promote_artifact import PromotionError, promote_file, promote_seeds  # noqa: E402
from run_wp_function import goal_obligation_class  # noqa: E402
from validate_artifacts import (  # noqa: E402
    validate_agent_result,
    validate_candidates,
    validate_findings,
    validate_ledger,
)

LEDGER = Path("coverage-ledger.json")
CANDIDATES = Path("candidates.json")
FINDINGS = Path("findings.json")

LAYER_TO_CLASS = {2: "l2_termination", 3: "l3_frame", 4: "l4_auth", 5: "l5_output", 6: "l6_secret"}
UNIT_PATH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@+-]*$")
FN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
NO_TOUCH = {"deferred", "out_of_scope", "not_applicable"}


class LedgerError(RuntimeError):
    pass


def unit_id(file: str, function: str, cls: str) -> str:
    return f"{file}#{function}::{cls}"


def new_unit(file, function, cls, module, tier, wave, source, status, unresolved=None, reason="") -> dict:
    unit = {
        "coverage_id": unit_id(file, function, cls),
        "file": file,
        "function": function,
        "obligation_class": cls,
        "module": module,
        "tier": tier,
        "wave": wave,
        "callgraph_source": source,
        "status": status,
        "agent_id": None,
        "evidence": [],
        "result_fingerprints": [],
        "unresolved": list(unresolved or []),
        "assumptions": [],
        "attempts": [],
    }
    if reason:
        unit["inference_reason"] = reason
    return unit


def load_state() -> Tuple[Dict[str, dict], Dict[str, dict]]:
    ledger = load_json_optional(LEDGER, [])
    candidates = load_json_optional(CANDIDATES, [])
    return {u["coverage_id"]: u for u in ledger}, {c["fingerprint"]: c for c in candidates}


def load_all_state() -> Tuple[Dict[str, dict], Dict[str, dict], Dict[str, dict]]:
    units, candidates = load_state()
    findings = load_json_optional(FINDINGS, [])
    return units, candidates, {f["fingerprint"]: f for f in findings}


def commit(
    units: Dict[str, dict],
    candidates: Dict[str, dict],
    findings: Optional[Dict[str, dict]] = None,
    run_dir: Optional[Path] = None,
) -> None:
    ledger = [units[k] for k in sorted(units)]
    cands = [candidates[k] for k in sorted(candidates)]
    errors = list(validate_ledger(ledger, run_dir)) + [f"candidates: {e}" for e in validate_candidates(cands)]
    recs: Optional[List[dict]] = None
    if findings is not None:
        recs = [findings[k] for k in sorted(findings)]
        errors.extend(f"findings: {e}" for e in validate_findings(recs, run_dir))
    if errors:
        raise LedgerError("refusing to write invalid ledger/candidates/findings:\n  " + "\n  ".join(errors[:50]))
    atomic_write_json(LEDGER, ledger)
    atomic_write_json(CANDIDATES, cands)
    if recs is not None:
        atomic_write_json(FINDINGS, recs)


def add_evidence(
    unit: dict,
    phase: str,
    producer: str,
    result: str,
    discharging: bool,
    tool_output: Optional[str],
    summary: str,
    details: Optional[dict] = None,
) -> None:
    ev = {
        "phase": phase,
        "producer": producer,
        "result": result,
        "discharging": discharging,
        "tool_output": tool_output,
        "summary": summary,
    }
    if details:
        ev["details"] = details
    if ev not in unit["evidence"]:
        unit["evidence"].append(ev)


def add_assumption(unit: dict, kind: str, description: str, related: Optional[List[str]] = None) -> None:
    a = {"kind": kind, "description": description, "related_units": sorted(set(related or []))}
    if a not in unit["assumptions"]:
        unit["assumptions"].append(a)


def mark_candidate(unit: dict, fingerprint: str) -> None:
    if unit["status"] in ("out_of_scope", "not_applicable"):
        return
    if fingerprint not in unit["result_fingerprints"]:
        unit["result_fingerprints"].append(fingerprint)
    unit["status"] = "candidate"
    unit["agent_id"] = None
    unit["unresolved"] = []


def upsert_candidate(
    candidates,
    fp,
    origin,
    proposed,
    module,
    location,
    prop,
    reproducers,
    tool_output,
    linked,
    note=None,
) -> dict:
    cand = candidates.get(fp)
    if cand is None:
        cand = {
            "fingerprint": fp,
            "status": "unverified",
            "origin": origin,
            "proposed_verdict": proposed,
            "module": module or "",
            "location": location,
            "property": prop,
            "reproducers": [],
            "tool_outputs": [],
            "linked_units": [],
            "first_seen": utc_now(),
        }
        candidates[fp] = cand
    if proposed == "confirmed":
        cand["proposed_verdict"] = "confirmed"
    for r in reproducers:
        if r not in cand["reproducers"]:
            cand["reproducers"].append(r)
    if tool_output and tool_output not in cand["tool_outputs"]:
        cand["tool_outputs"].append(tool_output)
    for cid in linked:
        if cid not in cand["linked_units"]:
            cand["linked_units"].append(cid)
    if note:
        cand.setdefault("notes", [])
        if note not in cand["notes"]:
            cand["notes"].append(note)
    return cand


def rel(path: str) -> str:
    """Run-relative, forward-slash form of a tool output path (cwd is the run directory)."""
    p = Path(path)
    if p.is_absolute():
        try:
            return p.resolve().relative_to(Path.cwd().resolve()).as_posix()
        except ValueError:
            return p.as_posix()
    text = p.as_posix()
    while text.startswith("./"):
        text = text[2:]
    return text


def units_for_function(units: Dict[str, dict], file: str, function: str) -> List[dict]:
    nf = normalize_file(file)
    exact = [u for u in units.values() if u["function"] == function and u["file"] == nf]
    if exact:
        return exact
    by_name = [u for u in units.values() if u["function"] == function]
    files = {u["file"] for u in by_name}
    return by_name if len(files) == 1 else []


# --------------------------------------------------------------------- seed

def cmd_seed(dag_path: Path, scope: List[str], callgraph_source: str) -> dict:
    dag = load_json_strict(dag_path)
    units, candidates = load_state()
    modules = dag.get("modules", {})
    added, skipped = 0, []
    for fn_name, fn in sorted(dag.get("functions", {}).items()):
        name = fn.get("name", fn_name)
        file = normalize_file(fn.get("file", ""))
        if not FN_RE.match(name) or not UNIT_PATH_RE.match(file):
            skipped.append(f"{file}#{name}")
            continue
        module = fn.get("module") or "unknown"
        tier = modules.get(module, {}).get("tier", "unclassified")
        wave = fn.get("wave")
        in_scope = not scope or any(file == s.rstrip("/") or file.startswith(s.rstrip("/") + "/") for s in scope)

        classes = [("rte", "")]
        if fn.get("has_loops"):
            classes.append(("l2_termination", "function contains loops"))
        for prop in fn.get("security_properties", []):
            cls = LAYER_TO_CLASS.get(prop.get("layer"))
            if cls and cls not in [c for c, _ in classes]:
                classes.append((cls, prop.get("reason", "")))

        for cls, reason in classes:
            cid = unit_id(file, name, cls)
            if cid in units:
                continue
            if not in_scope:
                unit = new_unit(
                    file, name, cls, module, tier, wave, callgraph_source, "out_of_scope",
                    ["outside requested scope_paths"], reason,
                )
            elif tier.startswith("Tier 3"):
                unit = new_unit(
                    file, name, cls, module, tier, wave, callgraph_source, "deferred",
                    ["tier3_not_scheduled: no harness is generated for Tier 3 modules in this profile"], reason,
                )
            else:
                unit = new_unit(file, name, cls, module, tier, wave, callgraph_source, "planned", None, reason)
            if fn.get("verifiability") or fn.get("wp_blockers") or fn.get("wp_notes"):
                bk = unit.setdefault("bookkeeping", {})
                if fn.get("verifiability"):
                    bk["verifiability"] = fn["verifiability"]
                if fn.get("wp_blockers"):
                    bk["wp_blockers"] = fn["wp_blockers"]
                if fn.get("wp_notes"):
                    bk["wp_notes"] = fn["wp_notes"]
            units[cid] = unit
            added += 1
    commit(units, candidates)
    return {"added_units": added, "total_units": len(units), "skipped_unsupported_names": skipped}


# ---------------------------------------------------------------- ingestion

def _module_units(units: Dict[str, dict], module: str) -> List[dict]:
    return [u for u in units.values() if u["module"] == module and u["status"] not in NO_TOUCH]


def cmd_ingest_fuzz(paths: List[Path]) -> dict:
    units, candidates = load_state()
    stats = {"reports": 0, "candidates": 0}
    for path in paths:
        report = load_json_strict(path)
        stats["reports"] += 1
        tool_output = rel(str(path))
        module = report.get("module") or path.stem
        status = report.get("status", "unknown")
        mod_units = _module_units(units, module)

        if status == "clean":
            for u in mod_units:
                add_evidence(
                    u, "fuzz", "run_eacsl_fuzz.py", "fuzz_clean", False, tool_output,
                    "E-ACSL + LibFuzzer campaign found no failure (not a proof).",
                )
            continue
        if status in ("compile_error", "fuzzer_error", "sandbox_unavailable"):
            for u in mod_units:
                add_evidence(
                    u, "fuzz", "run_eacsl_fuzz.py", f"fuzz_{status}", False, tool_output,
                    f"Fuzz campaign did not run to completion ({status}).",
                )
            continue

        for art in report.get("artifacts", []):
            artifact_rel = rel(art["artifact"])
            failure = art.get("failure")
            if failure and art.get("fingerprint"):
                fp = art["fingerprint"]
                file = normalize_file(failure["file"])
                function = failure["function"]
                cls = goal_obligation_class({"kind": failure.get("kind", ""), "annotation": failure.get("predicate", "")})
                linked = [
                    u["coverage_id"]
                    for u in units_for_function(units, file, function)
                    if u["obligation_class"] == cls and u["status"] not in ("out_of_scope", "not_applicable")
                ]
                proposed = "confirmed" if art.get("reproducible") else "needs_validation"
                note = None if art.get("reproducible") else "crash did not reproduce on replay"
                if not linked:
                    note = (note + "; " if note else "") + f"no ledger unit for {file}#{function}::{cls} (harness or unseeded code)"
                upsert_candidate(
                    candidates, fp, "fuzz", proposed, module,
                    {"file": file, "line": failure.get("line", 0), "function": function},
                    {"kind": failure.get("alarm_kind") or failure.get("kind") or "assertion", "predicate": failure.get("predicate", "")},
                    [artifact_rel], tool_output, linked, note,
                )
                for cid in linked:
                    add_evidence(
                        units[cid], "fuzz", "run_eacsl_fuzz.py", "fuzz_failure", False, tool_output,
                        f"E-ACSL failure {failure.get('alarm_kind') or failure.get('kind')} at line {failure.get('line')}.",
                        {"artifact": artifact_rel, "reproducible": art.get("reproducible")},
                    )
                    mark_candidate(units[cid], fp)
            else:
                kind = art.get("kind", "crash")
                digest = hashlib.sha256(f"{module}:{kind}:{art.get('sha256', '') if kind in ('crash', 'leak') else ''}".encode()).hexdigest()[:10]
                fp = f"harness_{re.sub(r'[^A-Za-z0-9_.-]', '_', module)}.c#unknown_function::{'unparsed_' + kind if kind in ('crash', 'leak') else kind}::{digest}"
                upsert_candidate(
                    candidates, fp, "fuzz", "needs_validation", module,
                    {"file": f"harness_{module}.c", "line": 0, "function": "unknown_function"},
                    {"kind": kind, "predicate": ""},
                    [artifact_rel], tool_output, [],
                    "no E-ACSL failure report could be parsed; verifier must triage and link units",
                )
            stats["candidates"] += 1
    commit(units, candidates)
    return stats


def cmd_ingest_eva(paths: List[Path]) -> dict:
    units, candidates = load_state()
    stats = {"reports": 0, "covered": 0, "candidates": 0}
    for path in paths:
        report = load_json_strict(path)
        stats["reports"] += 1
        tool_output = rel(str(path))
        module = report.get("module") or path.stem
        rte_units = [u for u in _module_units(units, module) if u["obligation_class"] == "rte"]

        if report.get("status") != "ok":
            for u in rte_units:
                add_evidence(
                    u, "eva", "run_eva_slice.py", "eva_analysis_error", False, tool_output,
                    "Eva did not complete; no property statuses are available.",
                )
            continue

        unknown_by_fn = report.get("unknown_obligations_by_function", {})
        invalid_by_fn: Dict[str, List[dict]] = {}
        for alarm in report.get("invalid_alarms", []):
            invalid_by_fn.setdefault(alarm.get("function", ""), []).append(alarm)
        dead_fns = {a.get("function") for a in report.get("dead_alarms", [])}
        assumed_by_fn: Dict[str, int] = {}
        for a in report.get("assumed_properties", []):
            assumed_by_fn[a.get("function", "")] = assumed_by_fn.get(a.get("function", ""), 0) + 1
        with_props = set(report.get("functions_with_properties", []))

        for u in rte_units:
            fn = u["function"]
            for alarm in invalid_by_fn.get(fn, []):
                fp = make_fingerprint(alarm.get("file") or u["file"], fn, alarm.get("kind", ""), alarm.get("annotation", ""))
                upsert_candidate(
                    candidates, fp, "eva", "needs_validation", module,
                    {"file": normalize_file(alarm.get("file") or u["file"]), "line": int(alarm.get("line") or 0), "function": fn},
                    {"kind": alarm.get("kind") or "assertion", "predicate": alarm.get("annotation", "")},
                    [], tool_output, [u["coverage_id"]],
                    "Eva Invalid status without a concrete witness input",
                )
                add_evidence(
                    u, "eva", "run_eva_slice.py", "eva_invalid", False, tool_output,
                    f"Eva reports Invalid at line {alarm.get('line')}: {alarm.get('annotation', '')[:200] or alarm.get('kind', '')}",
                )
                mark_candidate(u, fp)
                stats["candidates"] += 1
            if assumed_by_fn.get(fn):
                add_assumption(u, "stub_contract", f"{assumed_by_fn[fn]} property status(es) 'Considered valid' (libc/stub specifications) under Eva.")
            if fn in invalid_by_fn:
                continue
            if fn in unknown_by_fn:
                add_evidence(
                    u, "eva", "run_eva_slice.py", "eva_unknown", False, tool_output,
                    f"{len(unknown_by_fn[fn])} RTE obligation(s) remain Unknown; queued for WP.",
                )
            elif fn in with_props and fn not in dead_fns:
                add_evidence(
                    u, "eva", "run_eva_slice.py", "eva_all_valid", True, tool_output,
                    "Every RTE obligation in this function is Valid under Eva.",
                )
                add_assumption(
                    u, "boundary_assumption",
                    f"Eva result holds for calling contexts reachable from eva_main of module '{module}'.",
                )
                if u["status"] in ("planned", "blocked"):
                    u["status"] = "covered"
                    u["unresolved"] = []
                    stats["covered"] += 1
            elif fn in dead_fns:
                add_evidence(
                    u, "eva", "run_eva_slice.py", "eva_dead", False, tool_output,
                    "Properties are dead under the module harness: function not reached from eva_main (harness gap).",
                )
            else:
                add_evidence(
                    u, "eva", "run_eva_slice.py", "eva_no_properties", False, tool_output,
                    "Eva reported no property for this function (trivial or not reached).",
                )
    commit(units, candidates)
    return stats


def cmd_ingest_wp(paths: List[Path]) -> dict:
    units, candidates = load_state()
    stats = {"reports": 0, "covered": 0, "blocked": 0}
    for path in paths:
        report = load_json_strict(path)
        if "function" not in report or "status" not in report or report.get("mode") == "guardrail":
            continue
        stats["reports"] += 1
        tool_output = rel(str(path))
        fn = report["function"]
        targets = [u for u in units_for_function(units, report.get("file", ""), fn) if u["status"] not in NO_TOUCH]
        if report["status"] == "acsl_syntax_error":
            for u in targets:
                add_evidence(
                    u, "wp", "run_wp_function.py", "wp_acsl_syntax_error", False, tool_output,
                    "ACSL kernel check failed; WP did not run.",
                )
            continue
        if report["status"] in ("wp_aborted", "unsound_proof"):
            soundness = report.get("soundness", {})
            issues = (
                soundness.get("tier_a_aborts", [])
                + soundness.get("tier_a_abort_errors", [])
                + soundness.get("tier_b_unsound", [])
                + soundness.get("tier_b_unsound_warnings", [])
                + soundness.get("memory_model_hypotheses", [])
                + soundness.get("unproven_global_lemmas", [])
            )
            summary = "; ".join(issues[:3]) if issues else f"WP reported {report['status']}"
            for u in targets:
                add_evidence(
                    u, "wp", "run_wp_function.py", f"wp_{report['status']}", False, tool_output,
                    f"WP soundness gate rejected proof ({report['status']}): {summary[:220]}",
                )
                if u["status"] != "candidate":
                    u["status"] = "blocked"
                    u["unresolved"] = [f"{report['status']}: {msg[:180]}" for msg in (issues[:10] or [summary])]
                    stats["blocked"] += 1
            continue
        soundness = report.get("soundness", {})
        by_class = report.get("by_obligation_class", {})
        all_proven = report["status"] == "all_proven"
        unproven_by_class: Dict[str, List[dict]] = {}
        for g in report.get("unproven_goals", []):
            unproven_by_class.setdefault(g.get("obligation_class", "rte"), []).append(g)

        for u in targets:
            if u["status"] == "candidate":
                add_evidence(
                    u, "wp", "run_wp_function.py", f"wp_{report['status']}", False, tool_output,
                    "WP result recorded on a unit with an open candidate; candidate verdict takes precedence.",
                )
                continue
            cls = u["obligation_class"]
            counts = by_class.get(cls)
            if counts and counts.get("unproven", 0) > 0:
                goals = unproven_by_class.get(cls, [])
                add_evidence(
                    u, "wp", "run_wp_function.py", "wp_unproven", False, tool_output,
                    f"{counts['unproven']} goal(s) unproven, {counts.get('proven', 0)} proven.",
                )
                u["status"] = "blocked"
                u["unresolved"] = [
                    f"unproven {g.get('kind') or 'goal'} at line {g.get('line')}: {(g.get('annotation') or '')[:160]}".strip()
                    for g in goals[:10]
                ] or [f"{counts['unproven']} unproven goal(s)"]
                stats["blocked"] += 1
            elif counts and (counts.get("proven", 0) + counts.get("proven_under_hyp", 0)) > 0 and all_proven:
                add_evidence(
                    u, "wp", "run_wp_function.py", "wp_proven", True, tool_output,
                    f"{counts.get('proven', 0)} goal(s) proven, {counts.get('proven_under_hyp', 0)} valid under hypotheses.",
                )
                if counts.get("proven_under_hyp", 0):
                    add_assumption(
                        u, "valid_under_hyp",
                        f"{counts['proven_under_hyp']} goal(s) valid under hypotheses (callee contracts); resolved by the proof audit.",
                    )
                if soundness.get("reduced_checks"):
                    add_assumption(
                        u, "other",
                        f"WP run with reduced RTE check flags: {', '.join(soundness['reduced_checks'])}.",
                    )
                if soundness.get("assumed_function_pointer_goals"):
                    add_assumption(
                        u, "other",
                        f"WP assumed degenerated \\valid_function goals: {len(soundness['assumed_function_pointer_goals'])} goal(s).",
                    )
                u["status"] = "covered"
                u["unresolved"] = []
                stats["covered"] += 1
            elif cls == "rte" and all_proven and not counts:
                add_evidence(
                    u, "wp", "run_wp_function.py", "wp_no_rte_goals", True, tool_output,
                    "WP generated no RTE goal for this function.",
                )
                if soundness.get("reduced_checks"):
                    add_assumption(
                        u, "other",
                        f"WP run with reduced RTE check flags: {', '.join(soundness['reduced_checks'])}.",
                    )
                u["status"] = "covered"
                u["unresolved"] = []
                stats["covered"] += 1
            elif counts and not all_proven:
                add_evidence(
                    u, "wp", "run_wp_function.py", "wp_function_incomplete", False, tool_output,
                    f"Goals of class {cls} are proven, but the function proof is incomplete; not credited.",
                )
            else:
                hint = f" (layer clauses must be named {cls[:2].upper()}_*)" if cls in ("l4_auth", "l5_output", "l6_secret") else ""
                add_evidence(
                    u, "wp", "run_wp_function.py", "wp_no_credited_goals", False, tool_output,
                    f"No WP goal could be credited to {cls}{hint}.",
                )
    commit(units, candidates)
    return stats


# --------------------------------------------- M2 hypotheses & crash verifier

def _infer_module_for_function(units: Dict[str, dict], file: str, function: str) -> str:
    matched = units_for_function(units, file, function)
    if matched:
        return matched[0].get("module") or "unknown"
    return "unknown"


def cmd_ingest_agent_hypothesis(result_path: Path, module: Optional[str] = None) -> dict:
    """
    Promote breaker seeds (if any) and record a prover/breaker fault_hypothesis
    as an unverified candidate in candidates.json.
    """
    res = load_json_strict(result_path)
    errs = validate_agent_result(res)
    if errs:
        raise LedgerError("invalid agent-result:\n  " + "\n  ".join(errs[:20]))

    role = res["role"]
    if role not in ("prover", "breaker"):
        raise LedgerError(f"ingest-agent-hypothesis expects prover or breaker result (got {role!r})")

    units, candidates = load_state()
    aid = res["agent_id"]
    file = normalize_file(res["file"])
    fn = res["function"]
    mod = module or _infer_module_for_function(units, file, fn)

    seeds_promoted: List[dict] = []
    if role == "breaker" and res.get("seeds"):
        prom = promote_seeds(Path.cwd(), aid, mod, list(res["seeds"]))
        seeds_promoted = list(prom["promoted"])

    candidates_added = 0
    fh = res.get("fault_hypothesis")
    if fh is not None:
        cls = goal_obligation_class({"kind": "assertion", "annotation": fh["predicate"]})
        fp = make_fingerprint(file, fn, cls, fh["predicate"])
        fn_units = [u for u in units_for_function(units, file, fn) if u["status"] not in ("out_of_scope", "not_applicable")]
        linked = [u["coverage_id"] for u in fn_units if u["obligation_class"] == cls] or [u["coverage_id"] for u in fn_units]
        if res.get("evidence"):
            tool_out = res["evidence"][0]["tool_output"]
        else:
            prom_res = promote_file(Path.cwd(), aid, rel(str(result_path)), kind="artifact")
            tool_out = str(prom_res["dest"])
        note = f"input_condition: {fh['input_condition']}; why_not_reproduced: {fh['why_not_reproduced']}"
        upsert_candidate(
            candidates,
            fp,
            role,
            "needs_validation",
            mod,
            {"file": file, "line": 0, "function": fn},
            {"kind": cls, "predicate": fh["predicate"]},
            [],
            tool_out,
            linked,
            note,
        )
        phase = "breaker" if role == "breaker" else "wp"
        for cid in linked:
            add_evidence(
                units[cid],
                phase,
                aid,
                f"{role}_fault_hypothesis",
                False,
                tool_out,
                f"Fault hypothesis on {fh['predicate'][:120]}",
            )
            mark_candidate(units[cid], fp)
        candidates_added += 1

    commit(units, candidates, run_dir=Path.cwd())
    return {
        "agent_id": aid,
        "role": role,
        "seeds_promoted": seeds_promoted,
        "candidates_added": candidates_added,
    }


def _collect_reproducible_shas(run_dir: Path, report_paths: List[Path], tool_outputs: List[str]) -> Set[str]:
    shas: Set[str] = set()
    all_paths = list(report_paths) + [run_dir / t for t in tool_outputs]
    seen_paths: Set[Path] = set()
    for p in all_paths:
        try:
            rp = p.resolve()
        except OSError:
            continue
        if rp in seen_paths or not rp.is_file():
            continue
        seen_paths.add(rp)
        try:
            data = load_json_strict(rp)
        except ArtifactError:
            continue
        if isinstance(data, dict):
            for art in data.get("artifacts", []):
                if isinstance(art, dict) and art.get("reproducible") is True and art.get("sha256"):
                    shas.add(str(art["sha256"]))
    return shas


def _merge_finding_record(existing: dict, incoming: dict) -> None:
    if existing["verdict"] != incoming["verdict"]:
        raise LedgerError(
            f"cannot merge conflicting verdicts for {existing['fingerprint']}: "
            f"{existing['verdict']} vs {incoming['verdict']}"
        )
    for key in ("reproducers", "evidence", "linked_units"):
        if key in existing and key in incoming:
            for item in incoming[key]:
                if item not in existing[key]:
                    existing[key].append(item)


def cmd_ingest_verifier(
    result_path: Path,
    replay_reports: Optional[List[Path]] = None,
    harness_meta_path: Optional[Path] = None,
) -> dict:
    """
    Validate and ingest a crash_verifier subagent result, promoting scratch artifacts/crashes,
    mechanically verifying confirmed reproducers against parent replay reports, updating
    findings.json and candidates.json, and transitioning coverage-ledger.json units.
    """
    run_dir = Path.cwd().resolve()
    res = load_json_strict(result_path)
    errs = validate_agent_result(res)
    if errs:
        raise LedgerError("invalid crash_verifier result:\n  " + "\n  ".join(errs[:25]))
    if res.get("role") != "crash_verifier":
        raise LedgerError(f"expected role='crash_verifier', got {res.get('role')!r}")

    units, candidates, findings = load_all_state()
    aid = res["agent_id"]
    cand_fp = res["candidate_fingerprint"]
    if cand_fp not in candidates:
        raise LedgerError(f"unknown candidate_fingerprint: {cand_fp}")
    cand = candidates[cand_fp]
    module = cand.get("module") or "unknown"

    reproducible_shas = _collect_reproducible_shas(
        run_dir,
        list(replay_reports or []),
        list(cand.get("tool_outputs") or []),
    )

    meta_file = harness_meta_path or (run_dir / "workspace" / "harnesses" / f"harness_{module}.json")
    harness_exhausted = False
    if meta_file and meta_file.is_file():
        try:
            hmeta = load_json_strict(meta_file)
            harness_exhausted = int(hmeta.get("repair_attempts", 0)) >= int(hmeta.get("max_repair_attempts", 2))
        except ArtifactError:
            harness_exhausted = False

    records = [copy.deepcopy(res["record"])] + [copy.deepcopy(r) for r in (res.get("additional_records") or [])]
    resolved_fps: List[str] = []

    for rec in records:
        fp = rec["fingerprint"]
        if fp not in resolved_fps:
            resolved_fps.append(fp)

        # Promote any verifier evidence files residing in agents/<aid>/scratch/
        for ev in rec.get("evidence", []):
            tout = ev.get("tool_output")
            if isinstance(tout, str) and tout.replace("\\", "/").startswith(f"agents/{aid}/scratch/"):
                prom_ev = promote_file(run_dir, aid, tout, kind="artifact")
                ev["tool_output"] = str(prom_ev["dest"])

        verdict = rec["verdict"]
        primary_ev_out = rec["evidence"][0]["tool_output"] if rec.get("evidence") else None

        if verdict == "confirmed":
            for rep in rec["reproducers"]:
                inp = rep["input"].replace("\\", "/")
                if inp.startswith(f"agents/{aid}/scratch/"):
                    prom_crash = promote_file(run_dir, aid, inp, kind="crash", module=module)
                    rep["input"] = str(prom_crash["dest"])
                    rep["sha256"] = str(prom_crash["sha256"])
                    rep["size_bytes"] = int(prom_crash["size_bytes"])
                if rep["sha256"] not in reproducible_shas:
                    raise LedgerError(
                        f"confirmed finding {fp} requires a parent-verified reproducible crash report "
                        f"matching sha256 {rep['sha256']}"
                    )

            fix_patch = rec["remediation"].get("fix_patch")
            if isinstance(fix_patch, str) and fix_patch.replace("\\", "/").startswith(f"agents/{aid}/scratch/"):
                prom_fix = promote_file(run_dir, aid, fix_patch, kind="artifact")
                rec["remediation"]["fix_patch"] = str(prom_fix["dest"])

            # Expand linked_units to all active or deferred units of the confirmed-buggy function so it is excluded from WP
            fn_units = [
                u for u in units_for_function(units, rec["location"]["file"], rec["location"]["function"])
                if u["status"] not in ("out_of_scope", "not_applicable")
            ]
            for u in fn_units:
                if u["coverage_id"] not in rec["linked_units"]:
                    rec["linked_units"].append(u["coverage_id"])

            for cid in rec["linked_units"]:
                if cid not in units:
                    raise LedgerError(f"confirmed record {fp} references unknown unit {cid}")
                u = units[cid]
                if cand_fp != fp and cand_fp in u["result_fingerprints"]:
                    u["result_fingerprints"].remove(cand_fp)
                add_evidence(
                    u, "verifier", aid, "confirmed", False, primary_ev_out,
                    f"Crash verifier confirmed {fp} ({rec['severity']}).",
                )
                mark_candidate(u, fp)

        elif verdict == "needs_validation":
            for cid in rec["linked_units"]:
                if cid not in units:
                    raise LedgerError(f"needs_validation record {fp} references unknown unit {cid}")
                u = units[cid]
                if cand_fp != fp and cand_fp in u["result_fingerprints"]:
                    u["result_fingerprints"].remove(cand_fp)
                add_evidence(
                    u, "verifier", aid, "needs_validation", False, primary_ev_out,
                    f"Crash verifier classified {fp} as needs_validation.",
                )
                mark_candidate(u, fp)

        elif verdict == "rejected":
            rej_class = rec["rejection_class"]
            affected_cids = set(rec["linked_units"]) | set(cand.get("linked_units") or [])
            for cid in sorted(affected_cids):
                if cid not in units:
                    raise LedgerError(f"rejected record {fp} references unknown unit {cid}")
                u = units[cid]
                for old_fp in (cand_fp, fp):
                    if old_fp in u["result_fingerprints"]:
                        u["result_fingerprints"].remove(old_fp)
                attempt_entry = {
                    "phase": "verifier",
                    "agent_id": aid,
                    "decision": "rejected",
                    "rejection_class": rej_class,
                    "reason": rec["reason"],
                    "result_fingerprints": [fp],
                }
                if attempt_entry not in u["attempts"]:
                    u["attempts"].append(attempt_entry)
                add_evidence(
                    u, "verifier", aid, f"rejected:{rej_class}", False, primary_ev_out,
                    f"Rejected ({rej_class}): {rec['reason'][:140]}",
                )
                if not u["result_fingerprints"] and u["status"] == "candidate":
                    if rej_class == "harness_induced" and harness_exhausted:
                        u["status"] = "blocked"
                        u["unresolved"] = sorted(
                            set(u["unresolved"] + [f"harness_repair_exhausted: {rec['reason']}"])
                        )
                    else:
                        u["status"] = "covered" if any(e.get("discharging") for e in u["evidence"]) else "planned"
                        u["agent_id"] = None
                        u["unresolved"] = []

        if fp in findings:
            _merge_finding_record(findings[fp], rec)
        else:
            findings[fp] = rec

    cand["status"] = "verified"
    cand["resolved_fingerprints"] = resolved_fps
    if res.get("refingerprint_reason"):
        cand["refingerprint_reason"] = res["refingerprint_reason"]

    commit(units, candidates, findings, run_dir=run_dir)
    return {
        "candidate_fingerprint": cand_fp,
        "decision": res["decision"],
        "resolved_fingerprints": resolved_fps,
        "harness_exhausted": harness_exhausted,
    }


# ---------------------------------------------------------------- transition

def cmd_transition(cid: str, status: str, agent_id: Optional[str], reason: Optional[str]) -> dict:
    units, candidates = load_state()
    if cid not in units:
        raise LedgerError(f"unknown coverage id {cid}")
    u = units[cid]
    if status in ("in_progress",):
        if not agent_id:
            raise LedgerError("in_progress requires --agent-id")
        u["agent_id"] = agent_id
        u["unresolved"] = []
    elif status in NO_TOUCH:
        if u["evidence"]:
            raise LedgerError(f"{cid} carries evidence; use 'blocked' with a reason instead of hiding it in {status}")
        if not reason:
            raise LedgerError(f"{status} requires --reason")
        u["agent_id"] = None
        u["unresolved"] = [reason]
    elif status == "blocked":
        if not reason:
            raise LedgerError("blocked requires --reason")
        u["unresolved"] = sorted(set(u["unresolved"] + [reason]))
    elif status == "planned":
        u["agent_id"] = None
        u["unresolved"] = []
    u["status"] = status
    commit(units, candidates)
    return u


def cmd_close_remaining(reason: str) -> dict:
    """
    Close all remaining 'planned' or 'in_progress' units at the end of a bounded campaign:
    - Units that already carry non-discharging evidence (e.g. fuzz_clean, eva_unknown)
      transition to 'blocked' with `reason` appended to `unresolved` (preserving evidence).
    - Units with no evidence transition to 'deferred' with `unresolved = [reason]`.
    """
    if not (reason or "").strip():
        raise LedgerError("close-remaining requires a non-empty --reason")
    clean_reason = reason.strip()
    units, candidates = load_state()
    to_blocked = 0
    to_deferred = 0
    for u in units.values():
        if u["status"] in ("planned", "in_progress"):
            u["agent_id"] = None
            if u["evidence"]:
                u["status"] = "blocked"
                u["unresolved"] = sorted(set(u["unresolved"] + [clean_reason]))
                to_blocked += 1
            else:
                u["status"] = "deferred"
                u["unresolved"] = [clean_reason]
                to_deferred += 1
    commit(units, candidates)
    return {
        "transitioned_to_blocked": to_blocked,
        "transitioned_to_deferred": to_deferred,
    }


def cmd_scaffold_verifier(
    cand_fp: str,
    decision: str,
    agent_id: str,
    file_override: Optional[str] = None,
    fn_override: Optional[str] = None,
    line_override: Optional[int] = None,
    severity: str = "high",
    out_path: Optional[Path] = None,
) -> dict:
    """
    Generate a schema-valid crash_verifier result skeleton from `candidates.json`
    and its referenced fuzz/Eva tool reports so verifiers do not hand-craft 20-field JSONs.
    """
    units, candidates = load_state()
    if cand_fp not in candidates:
        raise LedgerError(f"unknown candidate_fingerprint: {cand_fp}")
    cand = candidates[cand_fp]
    module = cand.get("module") or "unknown"
    loc = cand.get("location") or {}
    prop = cand.get("property") or {}

    loc_file = normalize_file(file_override or loc.get("file") or "unknown.c")
    loc_fn = (fn_override or loc.get("function") or "unknown_function").strip()
    loc_line = int(line_override if line_override is not None else (loc.get("line") or 1))
    if loc_line < 1:
        loc_line = 1

    p_kind = prop.get("kind") or "mem_access"
    p_pred = prop.get("predicate") or p_kind

    if loc_file != normalize_file(loc.get("file") or "") or loc_fn != (loc.get("function") or ""):
        rec_fp = make_fingerprint(loc_file, loc_fn, p_kind, p_pred)
        refp_reason: Optional[str] = (
            f"Resolved candidate location {loc.get('file')}#{loc.get('function')} "
            f"to {loc_file}#{loc_fn} at line {loc_line}."
        )
    else:
        rec_fp = cand_fp
        refp_reason = None

    fn_units = [
        u["coverage_id"]
        for u in units_for_function(units, loc_file, loc_fn)
        if u["status"] not in ("out_of_scope", "not_applicable")
    ]
    linked = fn_units or list(cand.get("linked_units") or [])
    tool_outputs = list(cand.get("tool_outputs") or [])
    primary_tool = tool_outputs[0] if tool_outputs else f"workspace/reports/fuzz/{module}.json"
    ev_phase = "eva" if cand.get("origin") == "eva" else "fuzz"

    harness_file = f"workspace/harnesses/harness_{module}.c"
    entry_fn = loc_fn
    hmeta_path = Path("workspace/harnesses") / f"harness_{module}.json"
    if hmeta_path.is_file():
        try:
            hmeta = load_json_strict(hmeta_path)
            harness_file = hmeta.get("harness_file") or harness_file
            entry_fn = hmeta.get("entry_fn") or entry_fn
        except ArtifactError:
            pass

    reproducers: List[dict] = []
    for rep_rel in cand.get("reproducers") or []:
        rep_path = Path(rep_rel)
        sha = "0" * 64
        sz = 0
        if rep_path.is_file():
            raw = rep_path.read_bytes()
            sha = hashlib.sha256(raw).hexdigest()
            sz = len(raw)
        reproducers.append({
            "input": rep_rel,
            "sha256": sha,
            "size_bytes": sz,
            "command": f"workspace/harnesses/fuzz_{module} -runs=1 {rep_rel}",
            "observed_result": f"{p_kind}: {p_pred}",
        })

    base_fields = {
        "verdict": decision,
        "fingerprint": rec_fp,
        "title": f"{p_kind} in {loc_fn} ({loc_file}:{loc_line})",
        "description": f"Runtime or static violation of {p_pred} at {loc_file}:{loc_line} in {loc_fn}.",
        "location": {"file": loc_file, "line": loc_line, "function": loc_fn},
        "property": {"kind": p_kind, "predicate": p_pred},
    }

    if decision == "confirmed":
        record = {
            **base_fields,
            "root_cause": f"Unchecked input reaches {loc_file}:{loc_line} in {loc_fn}.",
            "intended_behavior": f"Validate bounds and preconditions before executing line {loc_line} in {loc_fn}.",
            "trace": [
                {
                    "kind": "entrypoint",
                    "file": loc_file,
                    "line": loc_line,
                    "function": entry_fn,
                    "description": f"Harness invokes {entry_fn}.",
                },
                {
                    "kind": "sink",
                    "file": loc_file,
                    "line": loc_line,
                    "function": loc_fn,
                    "description": f"Violation of {p_pred} at {loc_file}:{loc_line}.",
                },
            ],
            "evidence": [
                {
                    "phase": ev_phase,
                    "tool_output": primary_tool,
                    "description": f"Reproduced {p_kind} failure in {loc_fn}.",
                }
            ],
            "reachability": "untrusted_surface",
            "harness": {
                "file": harness_file,
                "entry_function": entry_fn,
                "contract_respected": True,
                "notes": f"Reproduced via {harness_file}.",
            },
            "reproducers": reproducers,
            "severity": severity,
            "severity_rationale": f"Reproducible {p_kind} reachable from {entry_fn}.",
            "remediation": {
                "summary": f"Enforce bounds check in {loc_fn} before line {loc_line}.",
                "invariant": p_pred,
                "fix_patch": None,
            },
            "linked_units": linked,
            "verifier": {
                "agent_id": agent_id,
                "method": "reproduced_and_source_review",
                "notes": f"Verified reproducibility and root cause at {loc_file}:{loc_line}.",
            },
        }
    elif decision == "needs_validation":
        nv_origin = (
            "eva_invalid_no_witness"
            if cand.get("origin") == "eva"
            else ("fuzz_timeout_or_oom" if p_kind in ("timeout", "oom") else "fault_hypothesis")
        )
        record = {
            **base_fields,
            "origin": nv_origin,
            "claimed_root_cause": f"Potential {p_kind} at {loc_file}:{loc_line} in {loc_fn}.",
            "trace": [
                {
                    "kind": "sink",
                    "file": loc_file,
                    "line": loc_line,
                    "function": loc_fn,
                    "description": f"Candidate {p_kind} at {loc_file}:{loc_line}.",
                }
            ],
            "evidence": [
                {
                    "phase": ev_phase,
                    "tool_output": primary_tool,
                    "description": f"Tool reported {p_kind} candidate in {loc_fn}.",
                }
            ],
            "reachability": "untrusted_surface",
            "blockers": [f"Requires caller/environment state validation for {loc_fn}."],
            "validation_plan": {
                "local": f"Replay with full state initialization in {harness_file}."
            },
            "linked_units": linked,
            "verifier": {
                "agent_id": agent_id,
                "method": "source_review",
                "notes": f"Triaged {p_kind} candidate at {loc_file}:{loc_line}.",
            },
        }
    else:
        record = {
            **base_fields,
            "claimed_root_cause": f"Candidate {p_kind} at {loc_file}:{loc_line}.",
            "evidence": [
                {
                    "phase": ev_phase,
                    "tool_output": primary_tool,
                    "description": f"Tool output for rejected candidate {cand_fp}.",
                }
            ],
            "rejection_class": "harness_induced",
            "reason": f"Candidate in {loc_fn} does not occur under valid entry preconditions.",
            "linked_units": linked,
            "verifier": {
                "agent_id": agent_id,
                "method": "source_review",
                "notes": f"Rejected candidate {cand_fp} after source review.",
            },
        }

    result_obj = {
        "role": "crash_verifier",
        "agent_id": agent_id,
        "candidate_fingerprint": cand_fp,
        "decision": decision,
        "refingerprint_reason": refp_reason,
        "record": record,
    }
    if out_path is not None:
        atomic_write_json(out_path, result_obj)
    return result_obj


def cmd_summary() -> dict:
    units, candidates, findings = load_all_state()
    by_status: Dict[str, int] = {}
    by_class: Dict[str, Dict[str, int]] = {}
    for u in units.values():
        by_status[u["status"]] = by_status.get(u["status"], 0) + 1
        c = by_class.setdefault(u["obligation_class"], {})
        c[u["status"]] = c.get(u["status"], 0) + 1
    by_verdict: Dict[str, int] = {}
    for f in findings.values():
        v = f.get("verdict", "unknown")
        by_verdict[v] = by_verdict.get(v, 0) + 1
    return {
        "units": len(units),
        "by_status": by_status,
        "by_class": by_class,
        "candidates_unverified": sum(1 for c in candidates.values() if c["status"] == "unverified"),
        "findings_by_verdict": by_verdict,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Coverage ledger and candidate management (parent-only).")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("seed")
    p.add_argument("--dag", type=Path, default=Path("workspace/reports/callgraph_dag.json"))
    p.add_argument("--scope", action="append", default=[])
    p.add_argument("--callgraph-source", choices=["frama_c", "regex"], default="regex")
    for name in ("ingest-fuzz", "ingest-eva", "ingest-wp"):
        p = sub.add_parser(name)
        p.add_argument("reports", nargs="+", type=Path)
    p_hyp = sub.add_parser("ingest-agent-hypothesis")
    p_hyp.add_argument("result", type=Path)
    p_hyp.add_argument("--module", default=None)
    p_ver = sub.add_parser("ingest-verifier")
    p_ver.add_argument("result", type=Path)
    p_ver.add_argument("--replay-report", action="append", type=Path, default=[])
    p_ver.add_argument("--harness-meta", type=Path, default=None)
    p = sub.add_parser("transition")
    p.add_argument("--id", required=True)
    p.add_argument(
        "--status",
        required=True,
        choices=["planned", "in_progress", "blocked", "deferred", "out_of_scope", "not_applicable"],
    )
    p.add_argument("--agent-id", default=None)
    p.add_argument("--reason", default=None)
    p_close = sub.add_parser("close-remaining")
    p_close.add_argument("--reason", required=True, help="Reason for closing remaining planned/in_progress units")
    p_scaf = sub.add_parser("scaffold-verifier")
    p_scaf.add_argument("--fingerprint", required=True, help="Candidate fingerprint in candidates.json")
    p_scaf.add_argument("--decision", required=True, choices=["confirmed", "needs_validation", "rejected"])
    p_scaf.add_argument("--agent-id", default="verifier-1")
    p_scaf.add_argument("--file", default=None, help="Override source file path (triggers refingerprint)")
    p_scaf.add_argument("--function", default=None, help="Override function name (triggers refingerprint)")
    p_scaf.add_argument("--line", type=int, default=None, help="Override 1-based source line")
    p_scaf.add_argument("--severity", choices=["critical", "high", "medium", "low"], default="high")
    p_scaf.add_argument("--out", type=Path, default=None, help="Write scaffolded crash_verifier JSON to this path")
    sub.add_parser("summary")
    args = parser.parse_args(argv)

    try:
        if args.cmd == "seed":
            out = cmd_seed(args.dag, args.scope, args.callgraph_source)
        elif args.cmd == "ingest-fuzz":
            out = cmd_ingest_fuzz(args.reports)
        elif args.cmd == "ingest-eva":
            out = cmd_ingest_eva(args.reports)
        elif args.cmd == "ingest-wp":
            out = cmd_ingest_wp(args.reports)
        elif args.cmd == "ingest-agent-hypothesis":
            out = cmd_ingest_agent_hypothesis(args.result, args.module)
        elif args.cmd == "ingest-verifier":
            out = cmd_ingest_verifier(args.result, args.replay_report, args.harness_meta)
        elif args.cmd == "transition":
            out = cmd_transition(args.id, args.status, args.agent_id, args.reason)
        elif args.cmd == "close-remaining":
            out = cmd_close_remaining(args.reason)
        elif args.cmd == "scaffold-verifier":
            out = cmd_scaffold_verifier(
                args.fingerprint,
                args.decision,
                args.agent_id,
                file_override=args.file,
                fn_override=args.function,
                line_override=args.line,
                severity=args.severity,
                out_path=args.out,
            )
        else:
            out = cmd_summary()
    except (LedgerError, PromotionError, ArtifactError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        return 1
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
