#!/usr/bin/env python3
"""
Coverage ledger, candidate, and verifier verdict management (parent-only writer).

Subcommands (run with the run directory as working directory):
  seed                     --dag workspace/reports/callgraph_dag.json [--scope PATH ...]
                           [--security-props workspace/reports/security_props.json] [--refresh]
                           (refuses while the reach gate fails, or while the model has a threat
                           model and security_props.json is missing; --refresh re-derives the
                           units without evidence from the current DAG; records the stub overlay's
                           active contracts as record-stub-contracts does)
  ingest-fuzz              <workspace/reports/fuzz/*.json ...>
  ingest-eva               <workspace/reports/eva/*.json ...>
  ingest-wp                <workspace/reports/wp/*.json ...> [--sweep]
  ingest-agent-hypothesis  <agent_result.json> [--module MOD]
                           (fault_hypothesis, proof_gap, breaker crash_found, prover guardrail code_fault)
  record-boundary-assumptions <agent_result.json>   (prover / architect boundary_assumptions)
  record-stub-contracts    [--report workspace/reports/stubs.json] [--check-report workspace/reports/stub_check.json]
                           (the run's stub overlay, scripts/stub_gen.py; its stub-check, scripts/stub_check.py)
  ingest-verifier          <verifier_result.json> [--replay-report <fuzz.json> ...] [--harness-meta <harness_mod.json>]
                           (settles decision_point.basis from workspace/reports/decision_point/, and
                           supersedes the rejection of a candidate that later tool evidence reopened)
  transition               --id COVERAGE_ID --status STATUS [--agent-id ID] [--reason TEXT] [--expect STATUS ...]
  transition-many          --spec-json JSON|PATH
  close-remaining          --reason TEXT
  gate-reach               hold the planned units of dynamically gated modules out of WP, release them when the gap closes
  scaffold-verifier       --fingerprint FP --decision DECISION [...]
  mark-carried             --report <wp report> --entry <restored proofs entry> --key KEY
                           (scripts/proof_carry.py: evidence of a re-proven carried contract)
  audit-hypotheses         [--dag workspace/reports/callgraph_dag.json]
  summary | status

Units are function x obligation class (docs/guides/v2-design.md, Section 5). The security classes come
from scripts/security_props.py (step I9) when its report exists: l3_frame for every function writing
through a pointer, and one class per MetAcsl property kind (l3_isolation, l4_auth_state,
l4_auth_required, l4_invariant, l4_call_rule, l5_sanitized, l6_wiped, l6_no_leak) on the functions
holding its generated annotations; each such unit
names the properties it must discharge under `bookkeeping.security_properties`. An obligation
security_props.py decided from the model (plan step M2) is recorded under
`bookkeeping.decided_properties` at seed time: a violation blocks the unit, and a unit whose every
property was decided satisfied is covered by evidence of phase `static`. `ingest-wp` also credits a
MetAcsl-class unit whose properties MetAcsl loaded and decided statically (no goal left), unless an
Eva module left a check of them open (`bookkeeping.eva_verdicts`). Every write
is validated against schemas/ before it is committed atomically; an invalid
result is never written. Every read-modify-write holds the run-wide `ledger` lock
(framac_common.run_lock), so concurrent containers of one run never lose updates.

A rejected candidate is reopened when a tool later reproduces a failure at its sink (a breaker
crash_found, a guardrail code_fault with a crash input, a new fuzz reproducer), unless the verifier
cited a refuting tool output (`refutation_basis: checked`); see tool_evidence_on_verified_candidate.
FRAMAC_REJECTION_REOPEN=off restores the earlier behaviour (the signal is evidence only).
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import functools
import hashlib
import json
import os
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cache  # noqa: E402
import decision_point_check  # noqa: E402
import phase0_gates  # noqa: E402
from contract_negotiator import cmd_ingest_prover  # noqa: E402
from failure_identity import is_sanitizer_allocation_cap, parse_eacsl_resource_abort, site_key  # noqa: E402
from fingerprint import make_fingerprint, normalize_file, normalize_kind  # noqa: E402
from framac_common import (  # noqa: E402
    DEFAULT_JSON_MAX_BYTES,
    EVA_REPORT_MAX_BYTES,
    STUB_REPORT_REL,
    ArtifactError,
    RunLockTimeout,
    atomic_write_json,
    eva_alarm_in_file,
    is_safe_relative_path,
    load_agent_result_json,
    load_json_optional,
    load_json_strict,
    run_lock,
    utc_now,
    wp_limits_problem,
    wp_model_assumption,
    wp_model_problem,
)
from module_map import ModuleMap  # noqa: E402
from patterns import KERNEL_RENAME_RE  # noqa: E402
from promote_artifact import PromotionError, promote_file, promote_seeds  # noqa: E402
from run_wp_function import goal_obligation_class  # noqa: E402
from validate_artifacts import (  # noqa: E402
    validate_agent_result,
    validate_candidates,
    validate_findings,
    validate_ledger,
)
from workspace_overlay import harness_module_for_function, scope_keys  # noqa: E402

LEDGER = Path("coverage-ledger.json")
CANDIDATES = Path("candidates.json")
FINDINGS = Path("findings.json")

# The DAG's own layer facts (build_callgraph_dag.py). Layers 4-6, and the isolation of an asset in
# Layer 3, are the MetAcsl classes below.
LAYER_TO_CLASS = {2: "l2_termination", 3: "l3_frame"}
# Step I9: classes keyed to the MetAcsl properties of scripts/security_props.py. l3_isolation (asset
# writers and readers), l4_invariant and l4_call_rule are the kinds of
# docs/plans/metacsl-exploitation-plan.md, section 3.3; l3_frame is the plain assigns obligation, which
# WP's own goals credit, and is no MetAcsl class.
METACSL_CLASSES = (
    "l3_isolation",
    "l4_auth_state",
    "l4_auth_required",
    "l4_invariant",
    "l4_call_rule",
    "l5_sanitized",
    "l6_wiped",
    "l6_no_leak",
)
SECURITY_CLASSES = ("l3_frame", *METACSL_CLASSES)
DEFAULT_SECURITY_PROPS = Path("workspace/reports/security_props.json")
# The stub overlay's report (scripts/stub_gen.py) and its stub-check (scripts/stub_check.py).
DEFAULT_STUB_REPORT = Path(STUB_REPORT_REL)
DEFAULT_STUB_CHECK = Path("workspace/reports/stub_check.json")
# Plan step M2: obligations security_props.py decided from the model, recorded at seed time as
# evidence of this phase. A seed refresh re-derives a unit whose only evidence is of this phase.
DECIDED_VERDICTS = ("satisfied", "violated")
STATIC_PHASE = "static"
MODEL_JSON = Path("workspace/reports/phase0_model.json")
UNIT_PATH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@+-]*$")
FN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
NO_TOUCH = {"deferred", "out_of_scope", "not_applicable"}
NO_EVIDENCE_STATES = NO_TOUCH
ALLOWED_MANUAL_STATUSES = frozenset({"planned", "in_progress", "blocked", "deferred", "out_of_scope", "not_applicable"})


class LedgerError(RuntimeError):
    pass


_F = TypeVar("_F", bound=Callable)


def ledger_locked(fn: _F) -> _F:
    """Run a read-modify-write ledger command under the run-wide `ledger` lock."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        with run_lock("ledger"):
            return fn(*args, **kwargs)

    return wrapper  # type: ignore[return-value]


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


def load_state() -> tuple[dict[str, dict], dict[str, dict]]:
    ledger = load_json_optional(LEDGER, [])
    candidates = load_json_optional(CANDIDATES, [])
    return {u["coverage_id"]: u for u in ledger}, {c["fingerprint"]: c for c in candidates}


def load_all_state() -> tuple[dict[str, dict], dict[str, dict], dict[str, dict]]:
    units, candidates = load_state()
    findings = load_json_optional(FINDINGS, [])
    return units, candidates, {f["fingerprint"]: f for f in findings}


def commit(
    units: dict[str, dict],
    candidates: dict[str, dict],
    findings: dict[str, dict] | None = None,
    run_dir: Path | None = None,
) -> None:
    ledger = [units[k] for k in sorted(units)]
    cands = [candidates[k] for k in sorted(candidates)]
    errors = list(validate_ledger(ledger, run_dir)) + [f"candidates: {e}" for e in validate_candidates(cands)]
    recs: list[dict] | None = None
    if findings is not None:
        recs = [findings[k] for k in sorted(findings)]
        errors.extend(f"findings: {e}" for e in validate_findings(recs, run_dir))
    if errors:
        raise LedgerError("refusing to write invalid ledger/candidates/findings:\n  " + "\n  ".join(errors[:50]))
    atomic_write_json(LEDGER, ledger)
    atomic_write_json(CANDIDATES, cands)
    if recs is not None:
        atomic_write_json(FINDINGS, recs)

    # Workstream 5: Auto-transition run-metadata.json from "complete" to "in_progress"
    # whenever an unverified candidate or an active planned/in_progress unit exists.
    has_unverified_cand = any(c.get("status") == "unverified" for c in cands)
    has_open_unit = any(u.get("status") in ("planned", "in_progress") for u in ledger)
    meta_path = (run_dir or Path.cwd()) / "run-metadata.json"
    if meta_path.is_file():
        try:
            meta = load_json_strict(meta_path)
            changed_meta = False
            reopened = False
            if (
                (has_unverified_cand or has_open_unit)
                and isinstance(meta, dict)
                and meta.get("run_status") == "complete"
            ):
                meta["run_status"] = "in_progress"
                meta["incomplete_reason"] = None
                changed_meta = True
                reopened = True
            if reopened or (isinstance(meta, dict) and meta.get("run_status") == "in_progress"):
                if meta.get("snapshot_manifest") or meta.get("snapshot_digest"):
                    meta["snapshot_manifest"] = None
                    meta["snapshot_digest"] = None
                    changed_meta = True
                snap_manifest = (run_dir or Path.cwd()) / "state" / "snapshot-manifest.json"
                if snap_manifest.is_file():
                    with contextlib.suppress(OSError):
                        snap_manifest.unlink()
            if changed_meta:
                atomic_write_json(meta_path, meta)
        except ArtifactError:
            pass


# details.gap_kind of a proof_gap whose reason starts with "inductive lemma required" (prover brief, Step B: Inductive Lemmas).
INDUCTIVE_LEMMA_GAP = "inductive_lemma_required"


def add_evidence(
    unit: dict,
    phase: str,
    producer: str,
    result: str,
    discharging: bool,
    tool_output: str | None,
    summary: str,
    details: dict | None = None,
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


def add_assumption(unit: dict, kind: str, description: str, related: list[str] | None = None) -> None:
    a = {"kind": kind, "description": description, "related_units": sorted(set(related or []))}
    if a not in unit["assumptions"]:
        unit["assumptions"].append(a)


def wp_report_models(report: dict) -> list[str]:
    """The WP memory models a report's verdict was obtained under: its own and a triggered bitwise retry's."""
    retry = report.get("bitwise_retry") or {}
    models = [report.get("wp_model"), retry.get("wp_model") if retry.get("triggered") else None]
    return [m for m in models if isinstance(m, str) and m.strip()]


def add_wp_limit_assumptions(unit: dict, limits: dict, function: str, model_assumption: str | None = None) -> None:
    """What a credited proof did not establish stays visible as an open assumption on the unit."""
    if model_assumption:
        add_assumption(unit, "other", model_assumption)
    if limits["vacuity"]["status"] == "inconclusive":
        add_assumption(unit, "other", f"The consistency check of {function}'s contract was inconclusive.")
    oracle = limits.get("dynamic_oracle") or {}
    if (limits.get("guardrail_corpus") or {}).get("empty"):
        add_assumption(
            unit,
            "other",
            f"The guardrail corpus was empty: {function}'s contract was proven but never exercised on a real input.",
        )
    elif oracle.get("exercised") is False:
        add_assumption(
            unit,
            "other",
            f"No guardrail input reached {function}: its contract was proven but not exercised at runtime.",
        )
    guardrail = guardrail_limit_note(limits, function)
    if guardrail:
        add_assumption(unit, "other", guardrail)
    for text in unchecked_clause_notes(limits, function):
        add_assumption(unit, "other", text)


# `limits.guardrail.status` of a parent WP report (workspace_overlay.py): the E-ACSL guardrail ran and passed.
GUARDRAIL_PASSED_STATUS = "passed_dynamic_oracle"


def guardrail_limit_note(limits: dict, function: str) -> str | None:
    """
    The assumption text for a credited WP result whose limits say its guardrail did not pass
    (`limits.guardrail`: {status: `not_run`, reason} when the parent re-check ran none, a contract
    re-check included), or None when it passed or the report does not record the key (written before
    it existed). `not_run` is never a pass. An earlier result of the same unit whose guardrail passed
    keeps its evidence entry; this note is about the result credited now, and says so.
    """
    record = limits.get("guardrail")
    status = record.get("status") if isinstance(record, dict) else None
    if not isinstance(record, dict) or status == GUARDRAIL_PASSED_STATUS:
        return None
    reason = _one_line(record.get("reason"), 200) or "no reason recorded"
    if status != "not_run":
        return (
            f"The E-ACSL guardrail of the WP result credited for {function} did not pass (status "
            f"`{_one_line(status, 60) or 'not recorded'}`, {reason}): the proof stands on WP alone."
        )
    return (
        f"No E-ACSL guardrail ran for the WP result credited for {function} ({reason}): this proof was not "
        "exercised at runtime. A guardrail that passed for an earlier result of the unit, if any, is in its "
        "evidence and checked the contract as it was then."
    )


# Clauses named one by one on a unit; the rest are counted (the evidence's `details.limits` has them all).
UNCHECKED_CLAUSES_NAMED = 20


def _one_line(text: object, limit: int) -> str:
    flat = " ".join(str(text or "").split())
    return flat if len(flat) <= limit else flat[: limit - 3] + "..."


def unchecked_clause_text(clause: dict) -> str:
    """`requires `label: predicate` at file:line` for one record of `limits.dynamic_oracle.unchecked_clauses`."""
    label, body = _one_line(clause.get("label"), 60), _one_line(clause.get("clause"), 160)
    shown = f"{label}: {body}" if label and body else label or body
    where = f"{clause.get('file') or 'an unknown file'}:{clause.get('line') or '?'}"
    via = f", through `{_one_line(clause.get('via'), 60)}`" if clause.get("via") else ""
    return f"{clause.get('kind') or 'clause'}" + (f" `{shown}`" if shown else "") + f" at {where}{via}"


def unchecked_clause_notes(limits: dict, function: str) -> list[str]:
    """
    What the parent guardrail of a credited proof did not execute, as assumption texts: one per clause
    of `limits.dynamic_oracle.unchecked_clauses` ({function, kind, label, clause, file, line, reason,
    via}: E-ACSL warned `Ignoring annotation` and generated no check, run_eacsl_fuzz.py
    dynamic_oracle_fields), and one for the ignored annotations no function could be read for
    (`unattributed`). A guardrail that `passed` says nothing about these clauses: WP alone stands for
    them. `unchecked_clauses: None` means the guardrail had no build report to read them from: not
    known, which is not "none", and an assumption of its own. A report without the key (written before
    it existed) adds nothing.
    """
    oracle = limits.get("dynamic_oracle")
    if not isinstance(oracle, dict):
        return []
    notes: list[str] = []
    raw = oracle.get("unchecked_clauses")
    if "unchecked_clauses" in oracle and not isinstance(raw, list):
        notes.append(
            f"The guardrail of {function} did not report which clauses E-ACSL generated no check for: whether "
            f"the dynamic oracle executed every clause of {function} is not known."
        )
    clauses = [c for c in raw if isinstance(c, dict)] if isinstance(raw, list) else []
    for clause in clauses[:UNCHECKED_CLAUSES_NAMED]:
        owner = str(clause.get("function") or function)
        notes.append(
            f"The dynamic oracle never executed the {unchecked_clause_text(clause)} of {owner}: E-ACSL generated "
            f"no check for it ({_one_line(clause.get('reason'), 200) or 'no reason recorded'}). The guardrail "
            f"that passed for {function} says nothing about this clause; it rests on the WP proof alone."
        )
    if len(clauses) > UNCHECKED_CLAUSES_NAMED:
        notes.append(
            f"The dynamic oracle never executed {len(clauses) - UNCHECKED_CLAUSES_NAMED} more clause(s) of "
            f"{function}'s guardrail build (E-ACSL generated no check; see the limits of the WP evidence)."
        )
    loose = oracle.get("unattributed")
    if isinstance(loose, list) and loose:
        first = loose[0] if isinstance(loose[0], dict) else {}
        where = f"{first.get('file') or 'an unknown file'}:{first.get('line') or '?'}"
        notes.append(
            f"E-ACSL ignored {len(loose)} annotation(s) in {function}'s guardrail build that could not be tied to "
            f"a function (first: {where}, {_one_line(first.get('reason'), 160) or 'no reason recorded'}): whether "
            f"a clause of {function} was among them is not known."
        )
    return notes


def mark_candidate(unit: dict, fingerprint: str) -> None:
    if unit["status"] in ("out_of_scope", "not_applicable"):
        return
    if fingerprint not in unit["result_fingerprints"]:
        unit["result_fingerprints"].append(fingerprint)
    unit["status"] = "candidate"
    unit["agent_id"] = None
    unit["unresolved"] = []


def _observe(cand: dict, fp: str, origin: str, engine: str | None, prop: dict, tool_output: str, reproducers) -> None:
    """Append what one detection saw at the candidate's site (`observations`), once per fingerprint, origin and engine."""
    observations = cand.setdefault("observations", [])
    if any(o["fingerprint"] == fp and o["origin"] == origin and o["engine"] == engine for o in observations):
        return
    observations.append(
        {
            "fingerprint": fp,
            "origin": origin,
            "engine": engine,
            "kind": str((prop or {}).get("kind") or ""),
            "message": str((prop or {}).get("predicate") or ""),
            "tool_output": tool_output or "",
            "reproducer": str(reproducers[0]) if reproducers else None,
        }
    )


def landing_candidate(candidates, fp, site: str | None) -> dict | None:
    """
    The candidate a detection with fingerprint `fp` at `site` is recorded on, by upsert_candidate's rule: the
    candidate keyed by `fp`, else the unverified candidate at the site. None when the detection opens a new one.
    Callers read a candidate's state through this before recording the detection.
    """
    cand = candidates.get(fp)
    if cand is None and site is not None:
        cand = next(
            (c for c in candidates.values() if c.get("site") == site and c.get("status") == "unverified"),
            None,
        )
    return cand


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
    *,
    site: str | None = None,
    engine: str | None = None,
) -> dict:
    """
    Record one detection and return the candidate it landed on. Its key is `cand["fingerprint"]`, which
    is not always `fp`: a detection at the `site` of an unverified candidate that `fp` does not key takes
    that candidate (D1, F5). Callers use the returned candidate's fingerprint for everything after this.
    """
    cand = landing_candidate(candidates, fp, site)
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
            "observations": [],
        }
        if site is not None:
            cand["site"] = site
        candidates[fp] = cand
    else:
        first_engine = (cand.get("observations") or [{}])[0].get("engine")
        if (origin == "eva" or engine == "eacsl") and first_engine == "sanitizers":
            # The E-ACSL or Eva reading of a site a sanitizer saw first names the bug better.
            cand["property"] = prop
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
    _observe(cand, fp, origin, engine, prop, tool_output, reproducers)
    return cand


# ------------------------------------------------- reopening a rejected candidate
#
# A rejection made on reasoning alone must not silence a later reproduced crash at the same sink.
# FRAMAC_REJECTION_REOPEN=off restores the earlier behaviour: the signal is recorded as evidence only.
REOPEN_ENV = "FRAMAC_REJECTION_REOPEN"
UNSTATED_BASIS = "unstated"
# `checked` because ingest read "not reached" from a report (see _dead_code_on_disk): a reproduced
# crash at that location contradicts the report's reading, so such a rejection is reopened.
INGEST_RAISED_BASIS_SOURCES = frozenset({"eva_dead", "fuzz_coverage"})
# Reopenings per candidate when the harness sidecar names no repair budget (generate_harness.py:
# MAX_HARNESS_REPAIR_ATTEMPTS). The bound is the harness repair budget: a rejected crash can only
# legitimately come back after a repair of the harness it was found through, and the harness gets
# `max_repair_attempts` repairs.
DEFAULT_MAX_REOPENINGS = 2
HARNESS_DIR = Path("workspace/harnesses")


def rejection_reopen_enabled() -> bool:
    """FRAMAC_REJECTION_REOPEN=off: tool evidence never reopens a rejected candidate (A/B switch)."""
    return os.environ.get(REOPEN_ENV, "on").strip().lower() != "off"


def _harness_state(module: str) -> dict:
    """Digest of the module's harness source and its repair budget (cwd is the run directory)."""
    state: dict[str, Any] = {"sha256": None, "repair_attempts": None, "max_reopenings": DEFAULT_MAX_REOPENINGS}
    source = HARNESS_DIR / f"harness_{module}.c"
    try:
        if source.is_file():
            state["sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    except OSError:
        pass
    try:
        meta = load_json_optional(HARNESS_DIR / f"harness_{module}.json", {})
    except ArtifactError:
        meta = {}
    if isinstance(meta, dict):
        with contextlib.suppress(TypeError, ValueError):
            state["repair_attempts"] = int(meta.get("repair_attempts", 0))
        with contextlib.suppress(TypeError, ValueError):
            state["max_reopenings"] = max(0, int(meta.get("max_repair_attempts", DEFAULT_MAX_REOPENINGS)))
    return state


def _rejected_resolution(cand: dict, findings: dict[str, dict]) -> list[dict] | None:
    """The rejected records a verified candidate resolved to; None unless every resolved record is one."""
    if cand.get("status") != "verified":
        return None
    recs = [findings.get(fp) for fp in cand.get("resolved_fingerprints") or [cand["fingerprint"]]]
    if not recs or any(r is None or r.get("verdict") != "rejected" for r in recs):
        return None
    return [r for r in recs if r is not None]


def _attempt_basis_source(units: dict[str, dict], cand: dict, fp: str) -> str | None:
    """How the last rejection of `fp` got its basis, read from the linked units' attempt entries."""
    for cid in cand.get("linked_units") or []:
        for attempt in reversed((units.get(cid) or {}).get("attempts") or []):
            if attempt.get("decision") == "rejected" and fp in (attempt.get("result_fingerprints") or []):
                return attempt.get("refutation_basis_source")
    return None


def tool_evidence_on_verified_candidate(
    units: dict[str, dict],
    findings: dict[str, dict],
    cand: dict,
    *,
    source: str,
    phase: str,
    producer: str,
    artifact: str,
    tool_output: str,
    linked: list[str],
    already_listed: bool,
    override_checked: bool = False,
) -> str:
    """
    A tool-reproduced signal (`artifact`: a crash input a tool replayed) arrived for a verified
    candidate. Returns what was done:

    - `not_rejected`: the candidate is not a verified rejection; nothing done.
    - `known`: the artifact was already listed on the candidate (and the harness of a
      `harness_induced` rejection has not changed since): no new information, nothing done.
    - `reopened`: the candidate is `unverified` again, its units are `candidate` again, and a
      `reopened` entry records the time, the evidence and the rejection's class and basis. The
      rejected record stays in findings.json until the next verdict supersedes it (ingest-verifier).
    - `contradicted`: not reopened, the evidence is recorded on the candidate
      (`contradicting_evidence`) and on the units, with the reason:
      `checked_rejection` (the verifier cited a tool output that refutes the candidate; for a
      `harness_induced` rejection this holds only while the harness is the one it was made on),
      `harness_unchanged` (a `harness_induced` rejection and the same harness source: the crash
      recurring through the unrepaired harness says nothing new; not for the `sibling_verdict`
      source, an opposite verdict on the same sink) or `reopen_limit`.

    `override_checked`: the evidence outweighs a `checked` rejection (a sibling verdict that
    confirmed the same sink with a reproducer: one of the two verifiers is wrong, and a cited tool
    output does not say which). The reopening limit still applies.
    """
    recs = _rejected_resolution(cand, findings)
    if recs is None:
        return "not_rejected"
    fp = cand["fingerprint"]
    primary = recs[0]
    rej_class = primary["rejection_class"]
    basis = primary.get("refutation_basis") or UNSTATED_BASIS
    last = cand.get("last_rejection")
    ctx: dict = last if isinstance(last, dict) else {}

    def source_of(rec: dict) -> str | None:
        recorded = ctx.get("refutation_basis_source") if rec is primary else None
        return recorded or _attempt_basis_source(units, cand, rec["fingerprint"])

    basis_source = source_of(primary)
    harness = _harness_state(_candidate_harness_module(ModuleMap.load("."), cand))
    rejected_sha = ctx.get("harness_sha256")
    harness_known = bool(rejected_sha and harness["sha256"])
    harness_changed = harness_known and rejected_sha != harness["sha256"]

    if already_listed and not (rej_class == "harness_induced" and harness_changed):
        return "known"

    # What a verifier cited about a `harness_induced` rejection speaks for the harness it was made on.
    verifier_checked = (
        not override_checked
        and not (rej_class == "harness_induced" and harness_changed)
        and any(
            r.get("refutation_basis") == "checked" and source_of(r) not in INGEST_RAISED_BASIS_SOURCES for r in recs
        )
    )
    reason: str | None = None
    if verifier_checked:
        reason = "checked_rejection"
    elif rej_class == "harness_induced" and harness_known and not harness_changed and source != "sibling_verdict":
        # A sibling's opposite verdict on the same crash is not the harness speaking again.
        reason = "harness_unchanged"
    elif len(cand.get("reopened") or []) >= harness["max_reopenings"]:
        reason = "reopen_limit"

    described = {"rejection_class": rej_class, "refutation_basis": basis}
    if basis_source:
        described["refutation_basis_source"] = basis_source
    evidence = {"source": source, "artifact": artifact, "tool_output": tool_output}
    affected = [cid for cid in dict.fromkeys([*linked, *(cand.get("linked_units") or [])]) if cid in units]

    if reason is not None:
        seen = cand.setdefault("contradicting_evidence", [])
        if all((e.get("artifact"), e.get("reason")) != (artifact, reason) for e in seen):
            seen.append({"at": utc_now(), **evidence, "reason": reason, **described})
        for cid in affected:
            add_evidence(
                units[cid],
                phase,
                producer,
                "rejection_contradicted",
                False,
                tool_output,
                f"A reproduced failure contradicts the rejection ({rej_class}, basis {basis}) of {fp}; "
                f"not reopened: {reason}.",
                {"artifact": artifact, "fingerprint": fp, "reason": reason},
            )
        return "contradicted"

    entry: dict[str, Any] = {
        "at": utc_now(),
        "evidence": evidence,
        **described,
        "rejected_fingerprints": [r["fingerprint"] for r in recs],
    }
    if rej_class == "harness_induced" and harness_known:
        entry["harness_changed"] = harness_changed
    if cand.get("refingerprint_reason"):
        entry["refingerprint_reason"] = cand["refingerprint_reason"]
    cand.setdefault("reopened", []).append(entry)
    cand["status"] = "unverified"
    cand["proposed_verdict"] = "confirmed"
    cand.pop("resolved_fingerprints", None)
    cand.pop("refingerprint_reason", None)
    for cid in affected:
        u = units[cid]
        if u["status"] in ("out_of_scope", "not_applicable"):
            continue
        u["attempts"].append(
            {
                "phase": phase,
                "agent_id": None,
                "decision": "reopened",
                **described,
                "evidence": artifact,
                "result_fingerprints": [fp],
            }
        )
        mark_candidate(u, fp)
    return "reopened"


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


def units_for_function(units: dict[str, dict], file: str, function: str) -> list[dict]:
    nf = normalize_file(file)
    exact = [u for u in units.values() if u["function"] == function and u["file"] == nf]
    if exact:
        return exact
    by_name = [u for u in units.values() if u["function"] == function]
    files = {u["file"] for u in by_name}
    return by_name if len(files) == 1 else []


# --------------------------------------------------------------------- seed

VALID_PROFILES = ("quick", "standard", "deep")


def _resolve_seed_profile(profile: str | None, dag_path: Path) -> str:
    if profile in VALID_PROFILES:
        return profile
    for cand in (Path("run-metadata.json"), dag_path.parent.parent.parent / "run-metadata.json"):
        if cand.is_file():
            meta = load_json_optional(cand, {})
            if isinstance(meta, dict) and meta.get("profile") in VALID_PROFILES:
                return str(meta["profile"])
    return "standard"


HEADER_UNREACHED = "header_unreached: no entry point of the build reaches this header function"
# The prefix of a unit deferred because its link unit is on the GCC fallback (Eva and WP blocked).
CALLGRAPH_FALLBACK = "callgraph_fallback"


def _apply_decided(unit: dict, decided: list[dict], tool_output: str | None) -> None:
    """
    Record the security obligations security_props.py decided from the model (plan step M2: a text
    sink handed string literals only) on a freshly derived unit: under `bookkeeping.decided_properties`,
    and, for a planned unit, as its status. A violation blocks the unit; a unit whose every property
    of its class was decided satisfied is covered by that decision (evidence phase `static`). A unit
    that still has undecided properties stays planned for WP.
    """
    bk = unit.setdefault("bookkeeping", {})
    bk["decided_properties"] = sorted(decided, key=lambda d: (d["property"], d["verdict"]))
    if unit["status"] != "planned":
        return
    violated = [d for d in decided if d["verdict"] == "violated"]
    if violated:
        add_evidence(
            unit,
            STATIC_PHASE,
            "security_props.py",
            "decided_violated",
            False,
            tool_output,
            f"Decided from the model: {violated[0]['property']} does not hold ({violated[0]['reason']})."[:400],
        )
        unit["status"] = "blocked"
        unit["unresolved"] = list(
            dict.fromkeys(f"{d['property']} violated (decided from the model): {d['reason']}"[:240] for d in violated)
        )
    elif not bk.get("security_properties"):
        names = ", ".join(sorted({d["property"] for d in decided}))
        add_evidence(
            unit,
            STATIC_PHASE,
            "security_props.py",
            "decided_syntactically",
            True,
            tool_output,
            f"Decided from the model, no WP goal: {names} holds ({decided[0]['reason']})."[:400],
        )
        unit["status"] = "covered"


def _decided_violation(unit: dict) -> bool:
    """Whether security_props.py decided, from the model, that a property of this unit is violated."""
    return any(d.get("verdict") == "violated" for d in (unit.get("bookkeeping") or {}).get("decided_properties") or [])


def _decided_only(unit: dict) -> bool:
    """Whether every property of this unit was decided from the model: no WP goal is generated for it."""
    bk = unit.get("bookkeeping") or {}
    return bool(bk.get("decided_properties")) and not bk.get("security_properties")


def _meta_facts(path: Path | None = None) -> dict:
    """
    What security_props.json says about where its MetAcsl properties are not checked, or are checked
    by an in-code check rather than by MetAcsl (package E of docs/plans/metacsl-exploitation-plan.md:
    MetAcsl gives a call placed in an initializer no \\calling, \\writing or \\strong_invariant
    instance). Keys are (`file#function`, property):

      gaps    -> [why]: the property does not check something in the function. From the property's
                 `unchecked` (an initializer site no check could be written for, a caller left out of
                 the targets), the obligation entry's `unchecked`, and the `init_checks` of the
                 function that `code_checks` does not hold (listed, never written into the work tree);
      placed  -> [line]: the in-code checks written there (`code_checks`), which a WP run of the
                 function must report as goals.

    `initializers` is the document's `initializer_flags` (whether the model says which calls are
    initializers), None when the document does not say: no such field, or no readable file.

    Empty without the file. Read as the generator precomputed it; nothing is derived from the model.
    """
    out: dict = {"gaps": {}, "placed": {}, "initializers": None}
    try:
        doc = load_json_optional(path or DEFAULT_SECURITY_PROPS, {})
    except ArtifactError:
        return out
    if not isinstance(doc, dict):
        return out
    flags = doc.get("initializer_flags")
    if isinstance(flags, dict) and isinstance(flags.get("known"), bool):
        out["initializers"] = flags

    def fid(ref: object) -> str:
        file, _, name = str(ref or "").rpartition("#")
        return f"{normalize_file(file)}#{name}"

    def gap(key: tuple[str, str], why: str) -> None:
        found = out["gaps"].setdefault(key, [])
        if why not in found:
            found.append(why)

    placed_count: dict[tuple[str, str], int] = {}
    for c in doc.get("code_checks") or []:
        if isinstance(c, dict) and c.get("function") and c.get("property"):
            key = (fid(c["function"]), str(c["property"]))
            out["placed"].setdefault(key, []).append(int(c.get("line") or 0))
            placed_count[key] = placed_count.get(key, 0) + 1
    for prop in doc.get("properties") or []:
        if not isinstance(prop, dict) or not prop.get("name"):
            continue
        name = str(prop["name"])
        for u in prop.get("unchecked") or []:
            if isinstance(u, dict) and u.get("function"):
                where = f" (line {u['line']})" if u.get("line") else ""
                gap((fid(u["function"]), name), f"{u.get('reason') or 'not checked'}{where}")
        listed: dict[tuple[str, str], list[dict]] = {}
        for c in prop.get("init_checks") or []:
            if isinstance(c, dict) and c.get("function"):
                listed.setdefault((fid(c["function"]), name), []).append(c)
        for key, sites in listed.items():
            if len(sites) > placed_count.get(key, 0):
                calls = ", ".join(f"{s.get('callee')} at line {s.get('line')}" for s in sites)
                gap(key, f"its check(s) at the initializer call(s) of {calls} are listed but not written into the work tree")
    for ref, items in (doc.get("obligations") or {}).items():
        for ob in items if isinstance(items, list) else []:
            if isinstance(ob, dict) and ob.get("unchecked") and ob.get("property"):
                gap((fid(ref), str(ob["property"])), str(ob["unchecked"]))
    return out


def _unit_fid(unit: dict) -> str:
    return f"{normalize_file(unit['file'])}#{unit['function']}"


def _meta_unchecked(unit: dict, facts: dict | None) -> list[str]:
    """`<property>: <why>` for each property of the unit security_props.json says is not checked in its function."""
    if unit["obligation_class"] not in METACSL_CLASSES or not facts:
        return []
    fid = _unit_fid(unit)
    names = (unit.get("bookkeeping") or {}).get("security_properties") or []
    return [f"{n}: {why}" for n in sorted(names) for why in facts["gaps"].get((fid, str(n))) or []]


def _meta_initializers_unknown(unit: dict, facts: dict | None) -> str | None:
    """
    Why the unit's properties may have an unchecked call placed in an initializer, or None. MetAcsl
    gives such a call no \\calling, \\writing (from the callee's `assigns`) or \\strong_invariant
    instance, so "no goal left" proves nothing when the model cannot say where those calls are. This
    bars the no-goal credit only: a goal WP proved, or an Eva check, is a check that did run.

    A document without `initializer_flags` was written before the field: it may come from a model
    with or without flags, so it is refused too, and re-running `security_props.py run` settles it.
    """
    if facts is None:
        return None
    flags = facts["initializers"]
    if flags is None:
        return (
            "security_props.json has no `initializer_flags` (older than that field), so a call placed in an "
            "initializer may be unchecked: re-run `security_props.py run`"
        )
    if flags["known"]:
        return None
    skipped = {str(n) for n in flags.get("properties") or []}
    names = sorted(str(n) for n in (unit.get("bookkeeping") or {}).get("security_properties") or [] if str(n) in skipped)
    if not names:
        return None
    return (
        f"the model does not say which calls are initializers, where MetAcsl generates no instance of {', '.join(names)}: "
        "rebuild the model (dump schema 5) and re-run `security_props.py run`"
    )


def _meta_no_goal_bar(unit: dict, facts: dict | None) -> tuple[str, str] | None:
    """(evidence result, why) of _meta_no_goal_credit_barred."""
    verdicts = (unit.get("bookkeeping") or {}).get("eva_verdicts") or {}
    blocking = sorted(m for m, v in verdicts.items() if v in EVA_BLOCKING)
    if blocking:
        return (
            "wp_meta_simplified_eva_open",
            "Eva left a check of them open in module(s) "
            + ", ".join(f"'{m}' ({verdicts[m]})" for m in blocking)
            + ", so an instance exists that this run did not prove",
        )
    gaps = _meta_unchecked(unit, facts)
    if gaps:
        return "wp_meta_unchecked", "; ".join(gaps)
    fid = _unit_fid(unit)
    names = (unit.get("bookkeeping") or {}).get("security_properties") or []
    placed = {str(n): (facts or {}).get("placed", {}).get((fid, str(n))) for n in names}
    placed = {n: lines for n, lines in placed.items() if lines}
    if placed:
        where = "; ".join(f"{n} at line(s) {', '.join(map(str, sorted(set(ls))))}" for n, ls in sorted(placed.items()))
        return (
            "wp_meta_check_not_reported",
            f"the in-code check(s) written into the function ({where}) are not among this run's goals "
            "(a work tree without them, or rows the runner could not name)",
        )
    unknown = _meta_initializers_unknown(unit, facts)
    if unknown:
        return "wp_meta_initializers_unknown", unknown
    return None


def _meta_no_goal_credit_barred(unit: dict, facts: dict | None = None) -> str | None:
    """
    Why a MetAcsl-class unit WP has no goal for must not be credited as decided statically
    (`wp_meta_simplified`), or None. The no-goal credit rests on MetAcsl having dropped every instance
    as obviously true in the per-function parse; it has no proof behind it, so anything that says an
    instance exists and is open, or that something is not checked at all, outweighs it:

      - an Eva module left a check of the unit's properties Unknown, Invalid or unclassified
        (`bookkeeping.eva_verdicts`, the verdicts of EVA_BLOCKING that keep `ingest-eva` from covering
        the unit): the module parse generated a check the per-function parse did not;
      - security_props.json (`facts`, _meta_facts) says a property of the unit is not checked in its
        function: a site under the property's `unchecked`, an obligation entry with `unchecked`, or an
        initializer check listed under `init_checks` that `code_checks` does not hold. `ingest-wp`
        refuses every credit to such a unit (wp_meta_unchecked), not only this one;
      - an in-code check was written into the function (`code_checks`) and the run has no goal of
        the class: the run did not see it;
      - the model does not say which calls are initializers (_meta_initializers_unknown) and a property
        of the unit has a context MetAcsl skips at such a call.

    A goal WP proves is concerned by none but the second: it credits the unit whatever Eva left open.
    """
    found = _meta_no_goal_bar(unit, facts)
    return found[1] if found else None


def _meta_decided_statically(unit: dict, report: dict) -> bool:
    """
    Whether a WP run that ended `all_proven` with no goal of a MetAcsl unit's class decided it: MetAcsl
    loaded every property the unit must discharge (`security_props.properties` of the report) and its
    simplification (-meta-simpl, the default) dropped each instance in the function as obviously true
    (a global separated from the secret, a write of a local). Without a loaded property, an error
    loading them, or no property named on the unit, nothing was decided.
    """
    sp = report.get("security_props")
    names = set((unit.get("bookkeeping") or {}).get("security_properties") or [])
    if not isinstance(sp, dict) or sp.get("error") or not names:
        return False
    return names <= {str(n) for n in sp.get("properties") or []}


def _meta_not_evaluated(unit: dict, report: dict, has_goals: bool) -> str | None:
    """
    Why a WP report does not show that MetAcsl evaluated the properties of an L4-L6 unit, or None.

    A property stated on a call (`\\called == f`) generates no instance, and no message, when `f` is
    not in the files WP parsed: the run looks exactly like one whose every instance MetAcsl decided
    statically. libmodbus run-1: `send_msg` and `_modbus_receive_msg` (modbus.c) carry
    `L5_sanitized__modbus_tcp_send`, whose sink is a static function of modbus-tcp.c reached through
    `ctx->backend->send` only. run_wp_function.py records, per such property, whether the function's name
    occurs in the parsed files (`security_props.call_targets`); a unit naming a property whose function
    was not seen is not credited, with or without goals of its class. Without goals, a report that does
    not record the field (written before it existed) shows nothing either.
    """
    sp = report.get("security_props")
    names = set((unit.get("bookkeeping") or {}).get("security_properties") or [])
    if not isinstance(sp, dict) or sp.get("error") or not names:
        return None
    targets = sp.get("call_targets")
    if not isinstance(targets, dict):
        if has_goals or not names <= {str(n) for n in sp.get("properties") or []}:
            return None
        return (
            "the report does not say whether the functions its properties are stated on are in the files WP "
            "parsed (security_props.call_targets: not recorded; a report written before the field existed)"
        )
    unseen = [
        f"{n} (on the calls of {t.get('function')})"
        for n in sorted(names)
        if isinstance(t := targets.get(n), dict) and t.get("seen") is not True
    ]
    if not unseen:
        return None
    return (
        f"MetAcsl generated no instance of {', '.join(unseen)}: the files WP parsed do not name that function, "
        "so a call that reaches it through a function pointer was not checked"
    )


def wp_frame_problem(report: dict) -> tuple[str, str] | None:
    """
    Why an `all_proven` WP report does not show a proven frame for its function, as (evidence result,
    reason), or None when it does: the report says the contract has an `assigns` clause
    (`frame_summary.assigns_clause: present`, read by run_wp_function.py from Frama-C's own output) and
    that no assigns goal is unproven. A contract without the clause has no assigns goal that could
    fail, so zero unproven frame goals prove nothing there (libmodbus run-1, modbus_write_register).
    `unknown` is never a frame: the report CSV does not say which behavior an `assigns clause` row
    belongs to, so a proven row may be one named behavior's. A report written before the field
    existed reads as `unknown`.
    """
    raw = report.get("frame_summary")
    frame: dict = raw if isinstance(raw, dict) else {}
    state = frame.get("assigns_clause")
    function = report.get("function")
    if state == "absent":
        return "wp_no_frame_clause", f"the contract WP proved for {function} has no `assigns` clause"
    if state == "behaviors_only":
        named = ", ".join(str(b) for b in frame.get("assigns_behaviors") or []) or "some"
        return (
            "wp_no_frame_clause",
            f"the contract WP proved for {function} has an `assigns` clause in named behaviors only ({named}), "
            "which do not cover the function: it has no `assigns` clause of its own",
        )
    if state != "present":
        return (
            "wp_frame_not_shown",
            f"the report does not show that the contract of {function} has an `assigns` clause "
            f"(frame_summary.assigns_clause: {state if isinstance(state, str) else 'not recorded'}; a run limited "
            "with --prop, a log without a property report, or a report written before the field existed)",
        )
    if frame.get("assigns_vcs_proven") is not True or report.get("assigns_vcs_proven") is False:
        return "wp_frame_not_shown", f"the report does not say that the assigns goals of {function} are proven"
    return None


def _load_security_obligations(path: Path | None) -> tuple[dict[str, list[dict]] | None, str]:
    """security_props.py's obligations per `file#name`, and a status (`ok`, `absent`, `invalid`)."""
    path = path or DEFAULT_SECURITY_PROPS
    if not path.is_file():
        return None, "absent"
    data = load_json_optional(path, None)
    if not isinstance(data, dict) or not isinstance(data.get("obligations"), dict):
        return None, "invalid"
    return data["obligations"], "ok"


def _derive_units(
    dag: dict,
    dag_path: Path,
    scope: list[str],
    callgraph_source: str,
    profile: str | None,
    obligations: dict[str, list[dict]] | None,
    sec_props_output: str | None = None,
) -> tuple[dict[str, dict], dict[str, str], list[str], set[str], set[tuple[str, str]]]:
    """
    Every unit the DAG derives, whatever the ledger already holds: coverage id -> unit; the ids
    deferred for an unreached header (`unreached`) or the GCC fallback (`fallback`); the names
    skipped as unsupported; the functions security_props.py's obligations matched; and the DAG's
    (file, name) pairs. `sec_props_output` is the security_props.json the decided obligations
    (plan step M2) cite as their evidence.
    """
    modules = dag.get("modules", {})
    # With link units (step I5b) each function has its own tier (scripts/tiers.py, step I8).
    link_units = dag.get("module_kind") == "link_unit"
    resolved_profile = _resolve_seed_profile(profile, dag_path)
    derived: dict[str, dict] = {}
    tags: dict[str, str] = {}
    skipped: list[str] = []
    sec_matched: set[str] = set()
    dag_fns: set[tuple[str, str]] = set()
    for fn_name, fn in sorted(dag.get("functions", {}).items()):
        name = fn.get("name", fn_name)
        file = normalize_file(fn.get("file", ""))
        if not FN_RE.fullmatch(name) or not UNIT_PATH_RE.fullmatch(file):
            skipped.append(f"{file}#{name}")
            continue
        dag_fns.add((file, name))
        module = fn.get("module") or "unknown"
        if link_units:
            tier = fn.get("tier") or modules.get(module, {}).get("tier") or "unclassified"
        else:
            tier = modules.get(module, {}).get("tier") or fn.get("tier") or "unclassified"
        concurrent = link_units and bool(modules.get(module, {}).get("concurrent"))
        wave = fn.get("wave")
        # A header (static inline) function no entry point of the build reaches: deferred until a
        # harness reaches it (Eva ingest re-plans it then). Public inline API is such a function.
        unreached_header = bool(fn.get("header")) and not fn.get("reached", True)
        source = fn.get("callgraph_source") or callgraph_source
        in_scope = not scope or any(file == s.rstrip("/") or file.startswith(s.rstrip("/") + "/") for s in scope)

        classes = [("rte", "")]
        if fn.get("has_loops"):
            classes.append(("l2_termination", "function contains loops"))
        for prop in fn.get("security_properties", []):
            cls = LAYER_TO_CLASS.get(prop.get("layer"))
            if cls and cls not in [c for c, _ in classes]:
                classes.append((cls, prop.get("reason", "")))
        sec_names: dict[str, list[str]] = {}
        sec_decided: dict[str, list[dict]] = {}
        for ob in (obligations or {}).get(f"{file}#{name}") or []:
            cls = ob.get("class")
            if cls not in SECURITY_CLASSES:
                continue
            sec_matched.add(f"{file}#{name}")
            if ob.get("decided") in DECIDED_VERDICTS:
                sec_decided.setdefault(cls, []).append(
                    {
                        "property": str(ob.get("property")),
                        "verdict": ob["decided"],
                        "reason": str(ob.get("decided_reason") or ob["decided"]),
                    }
                )
            else:
                sec_names.setdefault(cls, []).append(str(ob.get("property")))
            if cls not in [c for c, _ in classes]:
                classes.append((cls, str(ob.get("reason") or "")))

        for cls, reason in classes:
            cid = unit_id(file, name, cls)
            if cid in derived:
                continue
            if not in_scope:
                unit = new_unit(
                    file,
                    name,
                    cls,
                    module,
                    tier,
                    wave,
                    source,
                    "out_of_scope",
                    ["outside requested scope_paths"],
                    reason,
                )
            elif tier.startswith("NO_TOUCH"):
                unit = new_unit(
                    file,
                    name,
                    cls,
                    module,
                    tier,
                    wave,
                    source,
                    "out_of_scope",
                    ["no_touch_tier: excluded by risk tier classification"],
                    reason,
                )
            elif tier.startswith("Tier 3"):
                # Step I8 (scripts/tiers.py): Tier 3 is deferred under quick; otherwise its RTE is planned.
                if resolved_profile != "quick" and cls == "rte":
                    unit = new_unit(file, name, cls, module, tier, wave, source, "planned", None, reason)
                elif resolved_profile != "quick":
                    unit = new_unit(
                        file,
                        name,
                        cls,
                        module,
                        tier,
                        wave,
                        source,
                        "deferred",
                        [
                            f"tier3_not_scheduled: Layers 2-6 are not scheduled for Tier 3 in the {resolved_profile} profile"
                        ],
                        reason,
                    )
                else:
                    unit = new_unit(
                        file,
                        name,
                        cls,
                        module,
                        tier,
                        wave,
                        source,
                        "deferred",
                        ["tier3_not_scheduled: Tier 3 is deferred under the quick profile"],
                        reason,
                    )
            else:
                unit = new_unit(file, name, cls, module, tier, wave, source, "planned", None, reason)
            if fn.get("eva_wp_blocked") and unit["status"] == "planned":
                # Its unit is on the GCC fallback: Eva and WP cannot run on it, fuzzing still does.
                unit["status"] = "deferred"
                unit["unresolved"] = [f"{CALLGRAPH_FALLBACK}: {fn['eva_wp_blocked']}"]
                tags[cid] = "fallback"
            if unreached_header and unit["status"] == "planned":
                unit["status"] = "deferred"
                unit["unresolved"] = [HEADER_UNREACHED]
                tags[cid] = "unreached"
            if sec_names.get(cls):
                unit.setdefault("bookkeeping", {})["security_properties"] = sorted(set(sec_names[cls]))
            if sec_decided.get(cls):
                _apply_decided(unit, sec_decided[cls], sec_props_output)
            if fn.get("callgraph_fallback"):
                unit.setdefault("bookkeeping", {})["callgraph_fallback"] = fn["callgraph_fallback"]
            if concurrent:
                # The link unit starts threads: Eva and WP results assume sequential execution.
                unit.setdefault("bookkeeping", {})["concurrent"] = True
            if fn.get("model_only"):
                # Only Frama-C's configuration compiles it: Eva and WP may analyse it, but the real
                # build (and so every fuzz harness) does not contain it.
                unit.setdefault("bookkeeping", {})["model_only"] = fn["model_only"]
            if fn.get("verifiability") or fn.get("wp_blockers") or fn.get("wp_notes"):
                bk = unit.setdefault("bookkeeping", {})
                if fn.get("verifiability"):
                    bk["verifiability"] = fn["verifiability"]
                if fn.get("wp_blockers"):
                    bk["wp_blockers"] = fn["wp_blockers"]
                if fn.get("wp_notes"):
                    bk["wp_notes"] = fn["wp_notes"]
            derived[cid] = unit
    return derived, tags, skipped, sec_matched, dag_fns


# What `seed --refresh` may re-derive: a unit in one of these statuses that carries no evidence, or
# one whose only evidence is the seed's own decision from the model (phase `static`, plan step M2).
REFRESHABLE = frozenset({"planned", "deferred", "out_of_scope"})
# The bookkeeping keys the seed writes (a refresh replaces them; any other key is kept).
SEED_BOOKKEEPING = (
    "security_properties",
    "decided_properties",
    "callgraph_fallback",
    "concurrent",
    "model_only",
    "verifiability",
    "wp_blockers",
    "wp_notes",
)
LEFT_DAG = "left_dag: the function is no longer in the call-graph DAG"
CLASS_NOT_DERIVED = "class_not_derived: the call-graph DAG no longer derives this obligation class for the function"
REFRESH_LIST_MAX = 50


def _has_evidence(unit: dict) -> bool:
    """
    Whether a phase has worked on the unit: what `seed --refresh` never rewrites. The seed's own
    decisions from the model (evidence phase `static`) do not count: a refresh decides again.
    """
    return bool(
        any(e.get("phase") != STATIC_PHASE for e in unit.get("evidence") or [])
        or unit.get("result_fingerprints")
        or unit.get("attempts")
        or unit.get("assumptions")
        or unit.get("agent_id")
    )


def _rederived(unit: dict, new: dict | None, reason: str) -> dict:
    """The unit as the current DAG derives it (`new`), or retired `out_of_scope` with `reason`."""
    out = copy.deepcopy(unit)
    if new is None:
        out["status"] = "out_of_scope"
        out["unresolved"] = [reason]
        out["agent_id"] = None
        return out
    for key in ("module", "tier", "wave", "callgraph_source", "status", "unresolved", "agent_id"):
        out[key] = copy.deepcopy(new[key])
    # Only reached without evidence of a phase (_has_evidence): the seed's decisions follow the model.
    out["evidence"] = copy.deepcopy(new.get("evidence") or [])
    if "inference_reason" in new:
        out["inference_reason"] = new["inference_reason"]
    else:
        out.pop("inference_reason", None)
    bk = {k: v for k, v in (out.get("bookkeeping") or {}).items() if k not in SEED_BOOKKEEPING}
    bk.update(copy.deepcopy(new.get("bookkeeping") or {}))
    if bk:
        out["bookkeeping"] = bk
    else:
        out.pop("bookkeeping", None)
    return out


def _refresh_units(
    units: dict[str, dict], derived: dict[str, dict], added: set[str], dag_fns: set[tuple[str, str]]
) -> dict:
    """
    Re-derive the ledger's units without evidence (planned, deferred, out of scope) from the
    current DAG; a unit the DAG no longer derives is retired `out_of_scope` with the reason. A unit
    with evidence is never touched: it is counted under `kept_with_evidence` when the DAG changed it.
    """
    changed: dict[str, list[str]] = {"updated": [], "retired": [], "kept_with_evidence": []}
    for cid in sorted(units):
        if cid in added:
            continue
        unit = units[cid]
        new = derived.get(cid)
        reason = LEFT_DAG if (normalize_file(unit["file"]), unit["function"]) not in dag_fns else CLASS_NOT_DERIVED
        target = _rederived(unit, new, reason)
        if target == unit:
            continue
        seed_decided = bool(unit.get("evidence")) and not _has_evidence(unit)
        if (unit["status"] not in REFRESHABLE and not seed_decided) or _has_evidence(unit):
            changed["kept_with_evidence"].append(cid)
            continue
        units[cid] = target
        changed["updated" if new is not None else "retired"].append(cid)
    return {
        "added": len(added),
        **{k: len(v) for k, v in changed.items()},
        "units": {"added": sorted(added)[:REFRESH_LIST_MAX], **{k: v[:REFRESH_LIST_MAX] for k, v in changed.items()}},
    }


PROPERTY_RELOCATED = "property_relocated"


def relocated_properties(doc: object) -> dict[str, dict[str, str]]:
    """
    `file#name` -> {property: where it is checked instead}, from the `relocated` records of a
    security_props.json (a wrapper sink, threat-model field `checked_at`): the functions the wrapper's
    property is no longer generated at (`not_generated_at`), and the inner sinks' properties its in-code
    check stands for inside the wrapper (`superseded`). Empty for a report without relocations.
    """
    moved: dict[str, dict[str, str]] = {}
    props = doc.get("properties") if isinstance(doc, dict) else None
    for prop in props if isinstance(props, list) else []:
        rel_rec = prop.get("relocated") if isinstance(prop, dict) else None
        if not isinstance(rel_rec, dict):
            continue
        name, wrapper = str(prop.get("name")), str(rel_rec.get("wrapper"))
        for fid in rel_rec.get("not_generated_at") or []:
            moved.setdefault(str(fid), {})[name] = f"{name} is checked inside {wrapper}, where it hands the buffer over"
        for item in rel_rec.get("superseded") or []:
            if isinstance(item, dict) and item.get("function") and item.get("property"):
                moved.setdefault(str(item["function"]), {})[str(item["property"])] = (
                    f"{name}, written before the call in {wrapper}, is checked in its place"
                )
    return moved


def _refresh_relocated(units: dict[str, dict], derived: dict[str, dict], doc: object, tool_output: str | None) -> dict:
    """
    `seed --refresh` after security_props.py moved a property (`relocated_properties`): a unit that a
    phase already worked on is never re-derived by `_refresh_units`, so it would stay keyed on a
    property no run generates any more (libmodbus run-1: twelve callers of `send_msg` blocked on
    `L5_sanitized_send_msg`). Such a unit keeps its evidence and gets a note; its
    `bookkeeping.security_properties` follow the report; it is retired when the report derives no
    property of its class for the function any more, and planned again otherwise: no earlier result on
    the moved property says anything about the one that replaces it. A retired unit is `blocked` with
    the reason `property_relocated: ...`, not `out_of_scope`: the ledger refuses an `out_of_scope` unit
    that carries evidence (validate_artifacts.py), and the evidence is kept. A unit with an open
    candidate is left as it is and listed.
    """
    moved = relocated_properties(doc)
    out: dict[str, list[str]] = {"retired": [], "replanned": [], "kept_candidate": []}
    for cid in sorted(units):
        unit = units[cid]
        bk = unit.get("bookkeeping") or {}
        new = derived.get(cid)
        kept = set((new or {}).get("bookkeeping", {}).get("security_properties") or [])
        here = moved.get(f"{normalize_file(unit['file'])}#{unit['function']}") or {}
        stale = sorted(n for n in bk.get("security_properties") or [] if n in here and n not in kept)
        if not stale or not _has_evidence(unit):
            continue
        if unit["status"] == "candidate":
            out["kept_candidate"].append(cid)
            continue
        why = "; ".join(here[n] for n in stale)
        add_evidence(
            unit,
            STATIC_PHASE,
            "security_props.py",
            PROPERTY_RELOCATED,
            False,
            tool_output,
            f"No longer generated at this function: {why}. Earlier results on {', '.join(stale)} do not decide the unit."[
                :400
            ],
        )
        unit["agent_id"] = None
        if new is None:
            unit["status"] = "blocked"
            unit["unresolved"] = [f"{PROPERTY_RELOCATED}: {why}"[:240]]
            unit["bookkeeping"] = {k: v for k, v in bk.items() if k != "security_properties"}
            if not unit["bookkeeping"]:
                unit.pop("bookkeeping")
            out["retired"].append(cid)
        else:
            unit["status"] = new["status"]
            unit["unresolved"] = copy.deepcopy(new["unresolved"])
            unit["bookkeeping"] = {
                k: v for k, v in bk.items() if k not in ("security_properties", "decided_properties")
            }
            for key in ("security_properties", "decided_properties"):
                if key in (new.get("bookkeeping") or {}):
                    unit["bookkeeping"][key] = copy.deepcopy(new["bookkeeping"][key])
            unit["evidence"] += copy.deepcopy(new.get("evidence") or [])
            out["replanned"].append(cid)
    return {k: v[:REFRESH_LIST_MAX] for k, v in out.items()} | {"count": sum(len(v) for v in out.values())}


@ledger_locked
def cmd_seed(
    dag_path: Path,
    scope: list[str],
    callgraph_source: str,
    profile: str | None = None,
    security_props: Path | None = None,
    refresh: bool = False,
    stub_report: Path = DEFAULT_STUB_REPORT,
    stub_check: Path | None = DEFAULT_STUB_CHECK,
) -> dict:
    """
    Add the units the DAG derives that the ledger lacks; an existing unit is never rewound. With
    `refresh` (a Phase 0 re-run on a changed target), the units without evidence also follow the
    current DAG (`_refresh_units`), the units keyed on a property security_props.py moved elsewhere
    are retired or planned again (`_refresh_relocated`), and the result reports what changed
    (`refresh`, `refresh.relocated`). The stub overlay's active
    contracts (`stub_report`, when present) are recorded as `stub_contract` assumptions as
    `record-stub-contracts` does, so a seed run by hand records them too.
    """
    dag = load_json_strict(dag_path)
    units, candidates = load_state()
    obligations, sec_status = _load_security_obligations(security_props)
    derived, tags, skipped, sec_matched, dag_fns = _derive_units(
        dag, dag_path, scope, callgraph_source, profile, obligations, rel(str(security_props or DEFAULT_SECURITY_PROPS))
    )
    added = [cid for cid in sorted(derived) if cid not in units]
    for cid in added:
        units[cid] = derived[cid]
    changes = _refresh_units(units, derived, set(added), dag_fns) if refresh else None
    if changes is not None and sec_status == "ok":
        props_path = security_props or DEFAULT_SECURITY_PROPS
        changes["relocated"] = _refresh_relocated(
            units, derived, load_json_optional(props_path, None), rel(str(props_path))
        )
    stubs = _apply_stub_contracts(units, stub_report, stub_check)
    commit(units, candidates)
    out: dict[str, Any] = {
        "added_units": len(added),
        "total_units": len(units),
        "skipped_unsupported_names": skipped,
        "deferred_unreached_header_units": sum(1 for cid in added if tags.get(cid) == "unreached"),
        "deferred_callgraph_fallback_units": sum(1 for cid in added if tags.get(cid) == "fallback"),
        "security_props": {
            "status": sec_status,
            "functions": len(sec_matched),
            "unmatched": sorted(set(obligations or {}) - sec_matched)[:20],
        },
        "stub_contracts": stubs,
    }
    if changes is not None:
        out["refresh"] = changes
    return out


def seed_input_problems(security_props: Path | None = None, run_dir: Path = Path(".")) -> list[str]:
    """
    Why the seed must not run yet: a failed or stale reach gate (as `wp_scheduler.py init`), or a
    model with a threat model but no security_props.py report, which would leave out the MetAcsl
    classes. Empty when the inputs are ready.
    """
    reasons = [f"Phase 0 reach gate: {r}" for r in phase0_gates.check(run_dir, need=("reach",))]
    model = load_json_optional(run_dir / MODEL_JSON, None)
    trust_block = model.get("trust") if isinstance(model, dict) else None
    threat = trust_block.get("threat_model") if isinstance(trust_block, dict) else None
    if isinstance(threat, dict) and threat.get("status") == "ok":
        path = security_props or DEFAULT_SECURITY_PROPS
        _, status = _load_security_obligations(path)
        if status != "ok":
            what = "is missing" if status == "absent" else "is not a security_props.py report"
            reasons.append(
                f"{path.as_posix()} {what} while the model has a threat model: run "
                "`security_props.py run` first, or the seed leaves out the MetAcsl classes"
            )
    return reasons


# ---------------------------------------------------------------- ingestion


def _module_units(units: dict[str, dict], module: str, scope: set[tuple[str, str]] | None = None) -> list[dict]:
    """Open units of DAG module `module`, limited to `scope` ((file, function) pairs) when given."""
    return [
        u
        for u in units.values()
        if u["module"] == module
        and u["status"] not in NO_TOUCH
        and (scope is None or (normalize_file(u["file"]), u["function"]) in scope)
    ]


def _report_scope(mm: ModuleMap, module: str) -> tuple[str, set[tuple[str, str]] | None]:
    """
    The DAG module (unit) a harness module's report credits and the functions it answers for: a
    sub-module of a link unit answers for its own scope (its lexer module's functions, as its report
    did before step I5b), a unit's own harness for the whole unit (None).
    """
    return mm.unit_of(module), scope_keys(mm, module)


def fuzz_keep_going_errors(report: dict) -> list[str]:
    """
    Why a campaign's keep-going rounds stopped before every dispatch case was fuzzed (`keep_going.status:
    error`, e.g. a crash in a case the round had skipped), from the report and each engine's part.
    """
    engines = report.get("engines")
    parts = [report, *(engines.values() if isinstance(engines, dict) else [])]
    errors: list[str] = []
    for part in parts:
        kg = part.get("keep_going") if isinstance(part, dict) else None
        if isinstance(kg, dict) and kg.get("status") == "error":
            text = str(kg.get("error") or "no reason recorded")
            if text not in errors:
                errors.append(text)
    return errors


def fuzz_engine_note(report: dict) -> str:
    """Human-readable engine qualifier for fuzz evidence (sanitizer fallback has narrower checks)."""
    if report.get("engine_used") == "sanitizers":
        reason = report.get("engine_fallback_reason")
        suffix = f"; E-ACSL fallback reason: {reason}" if reason else ""
        return f"Clang ASan+UBSan + LibFuzzer (no E-ACSL contract checks, no intra-object bounds checks{suffix})"
    if report.get("engine_used") == "eacsl+sanitizers":
        reduced = (
            f"; E-ACSL reduced checks: {', '.join(report['reduced_checks'])}" if report.get("reduced_checks") else ""
        )
        return f"Clang ASan+UBSan + LibFuzzer, then E-ACSL + LibFuzzer (each artifact names its engine{reduced})"
    if report.get("reduced_checks"):
        return f"E-ACSL + LibFuzzer (reduced checks: {', '.join(report['reduced_checks'])})"
    return "E-ACSL + LibFuzzer"


def _fuzz_coverage_executions(module: str) -> tuple[dict[tuple[str, str], int] | None, str]:
    """
    Executions per (file, function) in the module's coverage report, or None with the reason the report
    cannot say which functions ran. A usable report (D21) is `ok`, or `partial` with no input left
    unreplayed. A function the report does not list did not run; the file is compared normalized, as
    every ledger match is (`units_for_function`), not by suffix.
    """
    path = COVERAGE_REPORT_DIR / f"{module}.json"
    if not path.is_file():
        return None, "no coverage report"
    try:
        cov = load_json_optional(path, None)
    except (ArtifactError, OSError, ValueError):
        return None, "coverage report unreadable"
    if not isinstance(cov, dict):
        return None, "coverage report unreadable"
    status = cov.get("status")
    if status == "partial":
        inputs: dict = cov["inputs"] if isinstance(cov.get("inputs"), dict) else {}
        missing = inputs.get("not_replayed") or 0
        if missing:
            return None, f"partial coverage: {missing} of {inputs.get('total') or '?'} inputs not replayed"
    elif status != "ok":
        return None, f"coverage report status {status or 'unknown'}"
    counts: dict[tuple[str, str], int] = {}
    for row in cov.get("functions") or []:
        if not isinstance(row, dict) or not isinstance(row.get("function"), str) or not row.get("file"):
            continue
        key = (normalize_file(str(row["file"])), row["function"])
        executions = row.get("executions")
        counts[key] = counts.get(key, 0) + (executions if isinstance(executions, int) else 0)
    return counts, ""


def _eacsl_resource_abort(art: dict) -> dict | None:
    """
    The E-ACSL runtime resource abort of an artifact without a failure (run_eacsl_fuzz.py marks it as
    `eacsl_resource_abort`; an older report is read from its replay tail's stack), or None.
    """
    if art.get("failure") or art.get("engine") not in (None, "eacsl"):
        return None
    marked = art.get("eacsl_resource_abort")
    if isinstance(marked, dict):
        return marked
    found = parse_eacsl_resource_abort(str(art.get("replay_log_tail") or ""))
    if found is None:
        return None
    attribution = art.get("attribution")
    san_failure = attribution.get("failure") if isinstance(attribution, dict) else None
    if is_sanitizer_allocation_cap(san_failure):
        # ASan's own allocator cap on the same input (run-4 reports, before allocator_may_return_null=1).
        return {**found, "sanitizer_replay": "allocation_size_too_big"}
    if san_failure:
        return None
    if art.get("kind") == "oom" and isinstance(attribution, dict) and attribution.get("out_of_memory"):
        # libFuzzer's OOM, and the sanitizer build ran out of memory too: not the E-ACSL limit alone.
        return None
    return {**found, "sanitizer_replay": "unavailable" if not attribution else "no_failure"}


def _fuzz_meta_route(units: dict[str, dict], failure: dict, file: str, function: str, report: dict) -> dict | None:
    """
    Where the failed run-time check of a MetAcsl property lands (a failure with `meta_property`,
    failure_identity._meta_failure), None for any other failure. `file` and `function` are the
    failure's, as the campaign located them. Returns {harness_induced} or {cls, linked, notes}:

      a guard (`meta_guard`)   E-ACSL could not evaluate the property's predicate there (an invalid
                               read, an uninitialized value): class `rte` at the function, never a
                               violation of the property. Read first: a guard carries the property's
                               class too.
      `harness_induced`        a `requires` the harness broke by calling the protected function
                               itself: no candidate against the target, no unit.
      a precondition           the unit is the caller's (`caller`), in which a WP or Eva run places
                               the same obligation; without a known caller it links nothing.
      any other check          the unit `file#function::class` of the property's class.
    The class is the failure's `obligation_class` when the ledger knows it (METACSL_CLASSES), else the
    one its predicate spells. A function the build reports as an unplanned instance of the property
    (the report's `security_props.unplanned_instances`: MetAcsl instantiated it where
    security_props.json lists no instance) links nothing, even when it has a unit of the class for
    another property. Units are looked up as for any other failure (`units_for_function`).
    """
    name = failure.get("meta_property")
    if not isinstance(name, str) or not name:
        return None

    def _linked(fn: str, cls: str) -> list[str]:
        return [
            u["coverage_id"]
            for u in units_for_function(units, file, fn)
            if u["obligation_class"] == cls and u["status"] not in ("out_of_scope", "not_applicable")
        ]

    guard = failure.get("meta_guard")
    if guard:
        return {
            "cls": "rte",
            "linked": _linked(function, "rte"),
            "notes": [
                f"a guard ({guard}) of the run-time check of {name} failed: E-ACSL could not evaluate the "
                "property there, which is an alarm of its own (class rte), not a violation of the property"
            ],
        }
    if failure.get("harness_induced") is True:
        return {"harness_induced": True}
    own = failure.get("obligation_class")
    cls = (
        own
        if isinstance(own, str) and own in METACSL_CLASSES
        else goal_obligation_class({"kind": failure.get("kind", ""), "annotation": failure.get("predicate", "")})
    )
    notes: list[str] = []
    where = function
    if failure.get("kind") == "precondition":
        caller = failure.get("caller")
        if not isinstance(caller, str) or not caller:
            return {
                "cls": cls,
                "linked": [],
                "notes": [
                    f"the precondition {name} of {function} failed and the report names no caller: "
                    "no unit is linked (the obligation is its callers')"
                ],
            }
        where = caller
        notes.append(f"the precondition {name} of {function} failed at its call in {caller}: the unit is the caller's")
    section = report.get("security_props")
    unplanned = section.get("unplanned_instances") if isinstance(section, dict) else None
    listed = unplanned.get(name) if isinstance(unplanned, dict) else None
    if isinstance(listed, list) and where in listed:
        notes.append(
            f"{where} is not an instance of {name} in security_props.json (an unplanned instance: MetAcsl "
            "checks the property there, the plan seeded no unit for it): no unit is linked"
        )
        return {"cls": cls, "linked": [], "notes": notes}
    linked = _linked(where, cls)
    if not linked:
        notes.append(f"no ledger unit for {where}::{cls} of {name} (harness, unplanned or unseeded code)")
    return {"cls": cls, "linked": linked, "notes": notes}


def _fuzz_security_props_lost(report: dict) -> str | None:
    """
    Why the campaign's E-ACSL binary checked none of the run's MetAcsl properties although the engine
    is on (the report's `security_props`: a build the properties broke, an unreadable file, a
    toolchain that cannot take them), or None. A module no property has an instance in is not that.
    """
    section = report.get("security_props")
    if not isinstance(section, dict):
        return None
    status, reason = section.get("status"), str(section.get("reason") or "no reason recorded")
    if status in ("dropped", "error"):
        return f"{status}: {reason}"
    if status == "skipped" and not reason.startswith("no property has an instance"):
        return f"skipped: {reason}"
    return None


@ledger_locked
def cmd_ingest_fuzz(paths: list[Path]) -> dict:
    units, candidates = load_state()
    reopen = rejection_reopen_enabled()
    findings = {f["fingerprint"]: f for f in load_json_optional(FINDINGS, [])} if reopen else {}
    mm = ModuleMap.load(".")
    # A failure lands on the function its line lies in, as Eva rows do (a renamed static, `f_0`,
    # still credits `f`); the reported name, through the model's kernel_names, only without a line.
    index = _dag_line_index(dag=mm.dag)
    kernel = _model_kernel_names()
    stats: dict[str, Any] = {"reports": 0, "candidates": 0}
    ingested_modules: list[str] = []
    for path in paths:
        report = load_json_strict(path)
        stats["reports"] += 1
        tool_output = rel(str(path))
        module = report.get("module") or path.stem
        status = report.get("status", "unknown")
        # A sub-module's campaign speaks for the functions in its scope, within its link unit.
        mod_units = _module_units(units, *_report_scope(mm, module))
        engine_note = fuzz_engine_note(report)
        # Each engine that failed is recorded on the module's units whatever the merged status is: a crash
        # by the other engine does not hide it (F9). Placed before the status dispatch, so every branch reaches it.
        engine_errors = report.get("engine_errors")
        for engine, err in engine_errors.items() if isinstance(engine_errors, dict) else []:
            reason = str((err or {}).get("reason") or "no reason recorded")
            for u in mod_units:
                add_evidence(
                    u,
                    "fuzz",
                    "run_eacsl_fuzz.py",
                    "fuzz_fuzzer_error",
                    False,
                    tool_output,
                    f"{engine} campaign did not run to completion ({reason}); the other engine's results are ingested.",
                )
        # The run's MetAcsl properties and this campaign's build (the report's `security_props`, only
        # with `eacsl` in meta_engines): what the user must see goes to the command's output, and a
        # build that lost every property is recorded on the units those properties stand for.
        meta_warnings = report.get("security_props_warnings")
        if isinstance(meta_warnings, list) and meta_warnings:
            stats.setdefault("security_props_warnings", {})[module] = [str(w) for w in meta_warnings]
        meta_lost = _fuzz_security_props_lost(report)
        if meta_lost and status not in ("compile_error", "fuzzer_error", "sandbox_unavailable", "not_run"):
            for u in mod_units:
                if u["obligation_class"] in METACSL_CLASSES:
                    add_evidence(
                        u,
                        "fuzz",
                        "run_eacsl_fuzz.py",
                        "fuzz_meta_not_checked",
                        False,
                        tool_output,
                        f"The campaign's E-ACSL binary checked no MetAcsl property at run time ({meta_lost}): "
                        "its result says nothing about this unit's property.",
                    )

        if status == "clean":
            ingested_modules.append(module)
            executions, unmeasured = _fuzz_coverage_executions(module)
            for u in mod_units:
                if executions is None:
                    add_evidence(
                        u,
                        "fuzz",
                        "run_eacsl_fuzz.py",
                        "fuzz_clean",
                        False,
                        tool_output,
                        f"{engine_note} campaign found no failure (not a proof). "
                        f"Which functions ran was not measured ({unmeasured}).",
                    )
                    continue
                if executions.get((normalize_file(u["file"]), u["function"]), 0) == 0:
                    add_evidence(
                        u,
                        "fuzz",
                        "run_eacsl_fuzz.py",
                        "fuzz_not_executed",
                        False,
                        tool_output,
                        f"{engine_note} campaign: no replayed input executed this function (not evidence of anything).",
                    )
                    continue
                add_evidence(
                    u,
                    "fuzz",
                    "run_eacsl_fuzz.py",
                    "fuzz_clean",
                    False,
                    tool_output,
                    f"{engine_note} campaign found no failure (not a proof).",
                )
            continue
        if status in ("compile_error", "fuzzer_error", "sandbox_unavailable", "not_run", "insufficient_memory"):
            if status == "not_run":
                summary = f"Fuzz campaign was never run ({report.get('reason') or 'no report produced'})."
            elif status == "insufficient_memory":
                reason_text = (
                    report.get("reason")
                    or "; ".join(str(x) for x in (report.get("error_summary") or []) if x)
                    or "insufficient_memory"
                )
                summary = f"Fuzz campaign could not run ({reason_text})."
            else:
                summary = f"Fuzz campaign did not run to completion ({status})."
            for u in mod_units:
                add_evidence(u, "fuzz", "run_eacsl_fuzz.py", f"fuzz_{status}", False, tool_output, summary)
            continue

        ingested_modules.append(module)
        for kg_error in fuzz_keep_going_errors(report):
            # The crashes below are still ingested; the cases the rounds never got to were not fuzzed.
            for u in mod_units:
                add_evidence(
                    u,
                    "fuzz",
                    "run_eacsl_fuzz.py",
                    "fuzz_keep_going_error",
                    False,
                    tool_output,
                    f"Keep-going fuzz rounds stopped early, the remaining dispatch cases were not fuzzed: {kg_error}",
                )
        resource_aborts: list[tuple[str, dict]] = []
        for art in report.get("artifacts", []):
            artifact_rel = rel(art["artifact"])
            failure = art.get("failure")
            if failure and art.get("fingerprint"):
                fp = art["fingerprint"]
                file = normalize_file(failure["file"])
                # The fingerprint and the location keep the reported name: replay and minimization
                # match the failures they reproduce against it.
                function = failure["function"]
                link_unit = str((mm.modules.get(mm.unit_of(module)) or {}).get("unit") or mm.unit_of(module))
                source_fn = _located_function(file, failure.get("line"), function, index, kernel, link_unit)
                # A failed run-time check of a MetAcsl property goes by its own rules (_fuzz_meta_route).
                meta = _fuzz_meta_route(units, failure, file, source_fn, report)
                if meta is not None and meta.get("harness_induced"):
                    # The harness called a protected function itself: listed, never a candidate, no unit.
                    stats.setdefault("meta_harness_induced", []).append(
                        {
                            "module": module,
                            "property": failure.get("meta_property"),
                            "function": function,
                            "caller": failure.get("caller"),
                            "artifact": artifact_rel,
                            "fingerprint": fp,
                        }
                    )
                    continue
                cls = (
                    meta["cls"]
                    if meta is not None
                    else goal_obligation_class(
                        {"kind": failure.get("kind", ""), "annotation": failure.get("predicate", "")}
                    )
                )
                # A leak has no obligation class (D5): it links no unit, whatever the units of its function are.
                leak = failure.get("alarm_kind") == "memory_leak"
                if meta is not None:
                    linked = list(meta["linked"])
                else:
                    linked = (
                        []
                        if leak
                        else [
                            u["coverage_id"]
                            for u in units_for_function(units, file, source_fn)
                            if u["obligation_class"] == cls and u["status"] not in ("out_of_scope", "not_applicable")
                        ]
                    )
                proposed = "confirmed" if art.get("reproducible") else "needs_validation"
                notes = [] if art.get("reproducible") else ["crash did not reproduce on replay"]
                if source_fn != function:
                    notes.append(f"reported in {function}, which is {source_fn} in the source")
                if meta is not None:
                    notes.extend(meta["notes"])
                elif leak:
                    notes.append("a memory leak has no obligation class: no unit is linked (D5)")
                elif not linked:
                    notes.append(f"no ledger unit for {file}#{source_fn}::{cls} (harness or unseeded code)")
                note = "; ".join(notes) or None
                # The state read is of the candidate this detection lands on (its key, or the site's unverified one).
                site = _candidate_site(file, failure.get("line"), source_fn, index)
                prior = landing_candidate(candidates, fp, site)
                already_listed = prior is not None and artifact_rel in prior["reproducers"]
                rejected_before = reopen and prior is not None and _rejected_resolution(prior, findings) is not None
                cand = upsert_candidate(
                    candidates,
                    fp,
                    "fuzz",
                    proposed,
                    module,
                    {"file": file, "line": failure.get("line", 0), "function": function},
                    {
                        "kind": failure.get("alarm_kind") or failure.get("kind") or "assertion",
                        "predicate": failure.get("predicate", ""),
                    },
                    [artifact_rel],
                    tool_output,
                    linked,
                    note,
                    site=site,
                    engine=_detection_engine(art, report),
                )
                # A detection at a known site lands on that site's candidate: its key, not `fp`, from here on.
                fp = cand["fingerprint"]
                for cid in linked:
                    add_evidence(
                        units[cid],
                        "fuzz",
                        "run_eacsl_fuzz.py",
                        "fuzz_failure",
                        False,
                        tool_output,
                        f"{engine_note} failure {failure.get('alarm_kind') or failure.get('kind')} at line {failure.get('line')}.",
                        {"artifact": artifact_rel, "reproducible": art.get("reproducible")},
                    )
                    if not rejected_before:
                        mark_candidate(units[cid], fp)
                if rejected_before and art.get("reproducible"):
                    # A reproducer replayed by the campaign on a rejected candidate: reopen it or
                    # record the contradiction. Its units stay as the rejection left them otherwise.
                    outcome = tool_evidence_on_verified_candidate(
                        units,
                        findings,
                        candidates[fp],
                        source="fuzz_reproducer",
                        phase="fuzz",
                        producer="run_eacsl_fuzz.py",
                        artifact=artifact_rel,
                        tool_output=tool_output,
                        linked=linked,
                        already_listed=already_listed,
                    )
                    if outcome in ("reopened", "contradicted"):
                        stats[outcome] = stats.get(outcome, 0) + 1
            elif (resource_abort := _eacsl_resource_abort(art)) is not None:
                # The E-ACSL runtime stopped on its own limit (its tracked heap zone): no target check
                # failed and no sanitizer replay located a failure. Not a candidate; the units say so.
                resource_aborts.append((artifact_rel, resource_abort))
                continue
            else:
                kind = art.get("kind", "crash")
                # An OOM is keyed by its input too: `module:oom:` alone merged every OOM of a module (mpack run-4).
                digest = hashlib.sha256(
                    f"{module}:{kind}:{art.get('sha256', '') if kind in ('crash', 'leak', 'oom') else ''}".encode()
                ).hexdigest()[:10]
                fp = f"harness_{re.sub(r'[^A-Za-z0-9_.-]', '_', module)}.c#unknown_function::{'unparsed_' + kind if kind in ('crash', 'leak') else kind}::{digest}"
                cand = upsert_candidate(
                    candidates,
                    fp,
                    "fuzz",
                    "needs_validation",
                    module,
                    {"file": f"harness_{module}.c", "line": 0, "function": "unknown_function"},
                    {"kind": kind, "predicate": ""},
                    [artifact_rel],
                    tool_output,
                    [],
                    "no E-ACSL failure report could be parsed; verifier must triage and link units"
                    + ("; did not reproduce on replay" if art.get("reproducible") is False else ""),
                    engine=_detection_engine(art, report),
                )
                fp = cand["fingerprint"]
            stats["candidates"] += 1
        if resource_aborts:
            stats["eacsl_resource_aborts"] = stats.get("eacsl_resource_aborts", 0) + len(resource_aborts)
            limits = sorted(
                {
                    f"{a.get('resource')} limit"
                    + (f" of {a['limit_mb']} MiB" if a.get("limit_mb") else "")
                    + f" (sanitizer replay: {a.get('sanitizer_replay', 'unavailable')})"
                    for _, a in resource_aborts
                }
            )
            shown = [r for r, _ in resource_aborts[:5]]
            more = f" and {len(resource_aborts) - 5} more" if len(resource_aborts) > 5 else ""
            for u in mod_units:
                add_evidence(
                    u,
                    "fuzz",
                    "run_eacsl_fuzz.py",
                    "fuzz_eacsl_resource_limit",
                    False,
                    tool_output,
                    f"{len(resource_aborts)} input(s) stopped the E-ACSL runtime on its own {'; '.join(limits)}, "
                    "not on a target check: no candidate. E-ACSL checked nothing past that allocation for these "
                    "inputs; replay them on the sanitizer build to cover them.",
                    {"artifacts": shown + ([more.strip()] if more else [])},
                )
    commit(units, candidates)
    if cache.shared_mode() == "rw" and ingested_modules:
        published_corpora: dict[str, int] = {}
        for mod_name in sorted(set(ingested_modules)):
            c_dirs = [
                Path("workspace") / "corpus" / mod_name,
                Path("workspace") / "corpora" / mod_name,
            ]
            pub_count = 0
            for cd in c_dirs:
                if cd.is_dir():
                    pub_count += cache.publish_corpus(mod_name, cd)
            if pub_count > 0:
                published_corpora[mod_name] = pub_count
        if published_corpora:
            stats["published_corpora"] = published_corpora
    return stats


def _alarm_in_file(alarm: dict, unit_file: str) -> bool:
    """Whether an Eva report row lies in `unit_file` (delegates to framac_common.eva_alarm_in_file)."""
    return eva_alarm_in_file(alarm, unit_file)


def _extract_eva_report_sources(report: dict) -> set[str] | None:
    """
    Collect normalized target source files covered by an Eva report when `report["sources"]`
    is present.
    When `include_source: true` is used, `report["sources"]` lists only
    `workspace/harnesses/harness_<mod>.c` while the actual analyzed C files appear in
    `functions_with_properties_by_file`, `invalid_alarms`, `unknown_obligations_by_function`,
    `dead_alarms`, and `assumed_properties` (or, if none of those carry file paths, all module
    units are in scope of the `#include`-based slice).
    """
    raw_sources = report.get("sources")
    if not raw_sources:
        return None
    files: set[str] = set()
    for s in raw_sources:
        nf = normalize_file(str(s))
        if nf and not nf.startswith("workspace/harnesses/") and not Path(nf).name.startswith("harness_"):
            files.add(nf)
    if files:
        return files

    # All entries in `report["sources"]` were harness files (`include_source: true`).
    # Extract target files from `functions_with_properties_by_file` when present; otherwise
    # return `None` so all units of the module are eligible (individual alarm matching still
    # checks `_alarm_in_file(alarm, u_file)`).
    raw_props_by_file = report.get("functions_with_properties_by_file") or []
    if isinstance(raw_props_by_file, dict):
        for fpath in raw_props_by_file:
            nf = normalize_file(str(fpath))
            if nf and not Path(nf).name.startswith("harness_"):
                files.add(nf)
    elif isinstance(raw_props_by_file, list):
        for item in raw_props_by_file:
            if isinstance(item, dict) and item.get("file"):
                nf = normalize_file(str(item["file"]))
                if nf and not Path(nf).name.startswith("harness_"):
                    files.add(nf)
    for key in ("invalid_alarms", "dead_alarms", "assumed_properties"):
        for alarm in report.get(key) or []:
            if isinstance(alarm, dict):
                joined = (
                    f"{alarm['directory'].rstrip('/')}/{alarm['file']}"
                    if alarm.get("directory") and alarm.get("file")
                    else (alarm.get("file") or "")
                )
                nf = normalize_file(str(joined))
                if nf and not Path(nf).name.startswith("harness_"):
                    files.add(nf)
    unknown_by_fn = report.get("unknown_obligations_by_function") or {}
    if isinstance(unknown_by_fn, dict):
        for items in unknown_by_fn.values():
            if isinstance(items, list):
                for alarm in items:
                    if isinstance(alarm, dict):
                        joined = (
                            f"{alarm['directory'].rstrip('/')}/{alarm['file']}"
                            if alarm.get("directory") and alarm.get("file")
                            else (alarm.get("file") or "")
                        )
                        nf = normalize_file(str(joined))
                        if nf and not Path(nf).name.startswith("harness_"):
                            files.add(nf)
    return files or None


def _wp_discharged(unit: dict) -> bool:
    """Whether a WP proof, not only Eva, discharges this unit."""
    return any(
        isinstance(e, dict) and e.get("phase") == "wp" and e.get("discharging") for e in unit.get("evidence") or []
    )


# What the summary of the no-goal credit says. cmd_mark_carried renames a carried credit's result and
# keeps this text.
_NO_GOAL_CREDIT_TEXT = "decided every instance in this function statically"


def _is_no_goal_credit(evidence: dict) -> bool:
    """The evidence of `wp_meta_simplified`, also under the name a proof carried forward gets."""
    result = evidence.get("result")
    if result == "carried_forward_reproven":
        return _NO_GOAL_CREDIT_TEXT in str(evidence.get("summary") or "")
    return result == "wp_meta_simplified"


def _wp_cover_is_no_goal(unit: dict) -> bool:
    """Whether the unit's latest WP credit is the no-goal credit: no proven goal stands behind its cover."""
    credits = [
        e
        for e in unit.get("evidence") or []
        if isinstance(e, dict) and e.get("phase") == "wp" and e.get("discharging")
    ]
    return bool(credits) and _is_no_goal_credit(credits[-1])


def _withdraw_no_goal_credit(unit: dict, blocking: list[str]) -> bool:
    """
    An Eva module left a check of the unit open, so an instance exists that the no-goal credit said did
    not: the credit stops discharging (a rejected candidate must not fall back on it) and a cover
    resting on it goes back to planned, as a unit Eva left open before WP ran stays. True when a cover
    was withdrawn.
    """
    for e in unit["evidence"]:
        if isinstance(e, dict) and e.get("phase") == "wp" and _is_no_goal_credit(e):
            e["discharging"] = False
    reopened = unit["status"] == "covered"
    if reopened:
        unit["status"] = "planned"
        unit["agent_id"] = None
        unit["unresolved"] = []
    add_evidence(
        unit,
        "eva",
        "run_eva_slice.py",
        "eva_no_goal_credit_withdrawn",
        False,
        (unit["evidence"][-1] or {}).get("tool_output") if unit["evidence"] else None,
        "MetAcsl left WP no goal here, but Eva leaves a check of this unit's properties open in module(s) "
        + ", ".join(f"'{m}'" for m in blocking)
        + ": the no-goal credit (`wp_meta_simplified`) is withdrawn.",
    )
    return reopened


_KERNEL_RENAME_RE = KERNEL_RENAME_RE


def _kernel_renames(reported: set[str], unit_names: set[str]) -> dict[str, str]:
    """
    Eva names -> ledger function names for the copies the Frama-C kernel renamed: a static (often a
    header `static inline`) defined in several translation units of one analysis keeps its name once
    and becomes `f_0`, `f_1`... elsewhere. Only a name no unit has, whose stem one does, is mapped; the
    alarms keep their file, which still has to match the unit's.
    """
    out: dict[str, str] = {}
    for name in reported:
        m = _KERNEL_RENAME_RE.fullmatch(name)
        if m and name not in unit_names and m.group(1) in unit_names:
            out[name] = m.group(1)
    return out


DAG_REPORT = Path("workspace/reports/callgraph_dag.json")
# One module's Eva verdict on one function, kept per unit in bookkeeping.eva_verdicts (module ->
# verdict). A module's newest report replaces its verdicts; the unit's Eva status is decided from all
# of them, so the order reports arrive in, and which of them are new, does not matter.
EVA_BLOCKING = frozenset({"invalid", "unknown", "other"})
_EVA_ASSUMPTION_PREFIXES = ("Eva result holds", "Eva slice '")


def _dag_line_index(dag_path: Path = DAG_REPORT, dag: dict | None = None) -> dict[str, list[tuple[int, int, str]]]:
    """file -> (first line, last line, function name) of every DAG function with a known extent."""
    if dag is None:
        dag = load_json_optional(dag_path, {})
    out: dict[str, list[tuple[int, int, str]]] = {}
    for key, rec in ((dag or {}).get("functions") or {}).items() if isinstance(dag, dict) else []:
        if not isinstance(rec, dict):
            continue
        line, end = rec.get("line"), rec.get("end_line")
        if isinstance(line, int) and isinstance(end, int) and 0 < line <= end:
            out.setdefault(normalize_file(str(rec.get("file") or "")), []).append(
                (line, end, str(rec.get("name") or key))
            )
    return out


def _detection_engine(art: dict, report: dict) -> str | None:
    """The engine that found a fuzz artifact: its own `engine`, else the report's `engine_used` (None for a dual run without one)."""
    for value in (art.get("engine"), report.get("engine_used")):
        if value in ("eacsl", "sanitizers"):
            return value
    return None


def _candidate_site(file: str, line: object, function: str, index: dict[str, list[tuple[int, int, str]]]) -> str | None:
    """
    The statement site (failure_identity.site_key) of a detection at `file`:`line` in `function`, the
    DAG function the line lies in when it is known (the function's line range numbers identical lines).
    None when the line is not positive or cannot be read: such a detection keys on its own fingerprint.
    """
    if not isinstance(line, int) or line <= 0 or not file or file == "unknown":
        return None
    norm = normalize_file(file)
    spans = [s for s in (index or {}).get(norm, []) if s[0] <= line <= s[1]]
    if not spans:
        return site_key(file, function, line)
    # The DAG's name for the line, so that every engine's report of the site names the same function.
    span = min(spans, key=lambda s: s[1] - s[0])
    return site_key(file, span[2], line, (span[0], span[1]))


def _model_kernel_names(model_path: Path = MODEL_JSON) -> dict[tuple[str, str], dict[str, str]]:
    """
    (file, kernel name) -> {link unit: source name} for every function the Frama-C kernel renamed in
    some unit's parse (the model's `kernel_names`: a same-named static becomes `f_0`).
    """
    try:
        model = load_json_optional(model_path, None)
    except ArtifactError:
        return {}
    out: dict[tuple[str, str], dict[str, str]] = {}
    fns = model.get("functions") if isinstance(model, dict) else None
    for rec in fns.values() if isinstance(fns, dict) else []:
        if not isinstance(rec, dict) or not isinstance(rec.get("kernel_names"), dict):
            continue
        name, file = str(rec.get("name") or ""), normalize_file(str(rec.get("file") or ""))
        for unit, kernel in rec["kernel_names"].items():
            if name and isinstance(kernel, str) and kernel != name:
                out.setdefault((file, kernel), {})[str(unit)] = name
    return out


def _located_function(
    file: str,
    line: object,
    reported: str,
    index: dict[str, list[tuple[int, int, str]]],
    kernel: dict[tuple[str, str], dict[str, str]],
    link_unit: str,
) -> str:
    """
    The DAG function a failure at `file`:`line` lies in, by line range (as Eva ingest places its
    rows). Only a location the line cannot place uses the reported name, mapped back to its source
    name when the kernel renamed it (the report's link unit first).
    """
    spans = index.get(file)
    if spans and isinstance(line, int) and line > 0:
        inside = [s for s in spans if s[0] <= line <= s[1]]
        if inside:
            return min(inside, key=lambda s: s[1] - s[0])[2]
    names = kernel.get((file, reported))
    if names:
        if link_unit in names:
            return names[link_unit]
        if len(set(names.values())) == 1:
            return next(iter(names.values()))
    return reported


def _eva_row_function(row: object, index: dict[str, list[tuple[int, int, str]]], reported: str) -> str:
    """
    The DAG function an Eva row lies in, by file and line: exact even when the kernel renamed the
    function (`f_0`) or the row names a caller's inlined copy. Falls back to the name Eva reported.
    """
    if isinstance(row, dict):
        line = row.get("line")
        spans = index.get(_eva_alarm_path(row)) if index else None
        if spans and isinstance(line, int) and line > 0:
            inside = [s for s in spans if s[0] <= line <= s[1]]
            if inside:
                return min(inside, key=lambda s: s[1] - s[0])[2]
    return reported


def _unit_eva_verdicts(unit: dict) -> dict:
    return unit.setdefault("bookkeeping", {}).setdefault("eva_verdicts", {})


# Plan step M3: the Eva taint checks security_props.py writes into the work tree (`run --eva-taint`)
# report as user assertions on `\tainted(...)`. Their status belongs to the property's l6_no_leak
# unit, never to the function's rte unit: bookkeeping.eva_taint (module -> verdict), and a taint
# Unknown or Invalid keeps the unit from being credited (a copy of the secret may reach the sink).
TAINT_CLASS = "l6_no_leak"
TAINT_UNRESOLVED = "Eva taint: "
TAINT_BLOCKING = frozenset({"invalid", "unknown"})


def _is_taint_row(row: object) -> bool:
    return isinstance(row, dict) and "\\tainted(" in str(row.get("annotation") or "")


def _code_key(row: dict) -> tuple[str, int]:
    return _eva_alarm_path(row), int(row.get("line") or 0)


def _is_taint_or_code_row(row: object, code: set[tuple[str, int]]) -> bool:
    if not isinstance(row, dict):
        return False
    return _is_taint_row(row) or ("check" in str(row.get("kind") or "") and _code_key(row) in code)


def _split_taint_rows(report: dict, code: set[tuple[str, int]] | None = None) -> tuple[dict, list[tuple[str, dict]]]:
    """
    The report without its taint rows and the rows of in-code checks security_props.py placed (`code`:
    file and line, plan step M6), and those rows with their verdict (unknown, invalid, dead).
    """
    code = code or set()

    def _is_taint_row(row: object) -> bool:
        return _is_taint_or_code_row(row, code)

    out = dict(report)
    rows: list[tuple[str, dict]] = []
    raw = report.get("unknown_obligations_by_function")
    if isinstance(raw, dict):
        kept: dict[str, list] = {}
        for fn, found in raw.items():
            keep = []
            for row in found if isinstance(found, list) else []:
                if _is_taint_row(row):
                    rows.append(("unknown", row))
                else:
                    keep.append(row)
            if keep:
                kept[fn] = keep
        out["unknown_obligations_by_function"] = kept
    for key, verdict in (("invalid_alarms", "invalid"), ("dead_alarms", "dead")):
        found = report.get(key)
        if isinstance(found, list):
            rows += [(verdict, r) for r in found if _is_taint_row(r)]
            out[key] = [r for r in found if not _is_taint_row(r)]
    return out, rows


def _taint_checks(path: Path = DEFAULT_SECURITY_PROPS) -> list[dict]:
    """The taint checks security_props.py placed ([] without its report or without taint)."""
    try:
        doc = load_json_optional(path, {})
    except ArtifactError:
        return []
    record = doc.get("eva_taint") if isinstance(doc, dict) else None
    checks = record.get("checks") if isinstance(record, dict) and record.get("enabled") else None
    return [c for c in checks or [] if isinstance(c, dict) and c.get("function")]


def _code_checks(path: Path = DEFAULT_SECURITY_PROPS) -> dict[tuple[str, int, int], dict]:
    """
    (file, line, index) -> the in-code check security_props.py placed there (plan steps M6 and M7, and
    package E's checks at calls placed in initializers). One line can carry several checks (one
    initializer, two properties): `index` is a check's position among them (absent: 0, the M6 and
    M7 checks are alone on their line). A second check without an index on the same line takes the
    next free position.
    """
    try:
        doc = load_json_optional(path, {})
    except ArtifactError:
        return {}
    checks = doc.get("code_checks") if isinstance(doc, dict) else None
    out: dict[tuple[str, int, int], dict] = {}
    for c in checks or []:
        if not isinstance(c, dict) or not c.get("function"):
            continue
        file, line = normalize_file(str(c.get("file"))), int(c.get("line") or 0)
        index = int(c["index"]) if isinstance(c.get("index"), int) else 0
        while (file, line, index) in out:
            index += 1
        out[(file, line, index)] = c
    return out


def _code_lines(checks: dict[tuple[str, int, int], dict]) -> dict[tuple[str, int], list[dict]]:
    """(file, line) -> the in-code checks of that line, in index order: what an Eva row (file and line only) can match."""
    out: dict[tuple[str, int], list[dict]] = {}
    for file, line, index in sorted(checks):
        out.setdefault((file, line), []).append(checks[(file, line, index)])
    return out


def _ingest_code_checks(
    units: dict[str, dict],
    rows: list[tuple[str, dict]],
    lines: dict[tuple[str, int], list[dict]],
    module: str,
    tool_output: str,
) -> None:
    """
    Eva's statuses of the in-code checks (M6 wipes, M7 gate failures, initializer checks): evidence on
    their property's unit (WP decides it). Eva's report lists only the open rows, so a row on a line
    that holds several checks cannot be told apart by its position there: it is filed under every
    check of the line.
    """
    for verdict, row in rows:
        for check in lines.get(_code_key(row)) or []:
            for u in units.values():
                if (
                    str(check.get("property")) in ((u.get("bookkeeping") or {}).get("security_properties") or [])
                    and u["function"] == str(row.get("function") or "")
                    and _alarm_in_file(row, u["file"])
                ):
                    add_evidence(
                        u,
                        "eva",
                        "run_eva_slice.py",
                        f"eva_check_{verdict}",
                        False,
                        tool_output,
                        f"Eva slice '{module}': {check.get('property')} at line {row.get('line')} is {verdict}; "
                        "WP proves the check.",
                    )


def _open_code_checks(
    unit: dict, code_rows: list[tuple[str, dict]], lines: dict[tuple[str, int], list[dict]]
) -> list[str]:
    """The verdicts of the open Eva rows of in-code checks of the unit's properties in its function."""
    names = set((unit.get("bookkeeping") or {}).get("security_properties") or [])
    out = []
    for verdict, row in code_rows:
        if str(row.get("function") or "") != unit["function"] or not _alarm_in_file(row, unit["file"]):
            continue
        if any(str(c.get("property")) in names for c in lines.get(_code_key(row)) or []):
            out.append(verdict)
    return out


def _file_open_code_checks_of_no_goal_covers(
    units: dict[str, dict],
    code_rows: list[tuple[str, dict]],
    lines: dict[tuple[str, int], list[dict]],
    module: str,
    touched: set[str],
) -> None:
    """
    An in-code check Eva left Unknown or Invalid in a unit covered by the no-goal credit is the module's
    verdict on that unit, also when the report has no MetAcsl instance of its properties there (a
    check placed after the credit, an Eva run that did not load the properties).
    """
    for u in units.values() if code_rows else ():
        if u["obligation_class"] not in METACSL_CLASSES or u["status"] != "covered" or not _wp_cover_is_no_goal(u):
            continue
        found = _open_code_checks(u, code_rows, lines)
        if "invalid" in found or "unknown" in found:
            _unit_eva_verdicts(u).setdefault(module, "invalid" if "invalid" in found else "unknown")
            touched.add(u["coverage_id"])


def _taint_open(unit: dict) -> list[str]:
    """The modules whose Eva taint verdict on this unit is Unknown or Invalid."""
    verdicts = (unit.get("bookkeeping") or {}).get("eva_taint") or {}
    return sorted(m for m, v in verdicts.items() if v in TAINT_BLOCKING)


def _ingest_taint(
    units: dict[str, dict],
    rows: list[tuple[str, dict]],
    checks: list[dict],
    module: str,
    report: dict,
    tool_output: str,
) -> int:
    """File one Eva report's taint statuses under the l6_no_leak units; returns how many units it touched."""
    names = {(normalize_file(str(c["file"])), int(c.get("line") or 0)): str(c["property"]) for c in checks}
    found: dict[str, list[tuple[str, dict]]] = {}
    for verdict, row in rows:
        fn = str(row.get("function") or "")
        for u in units.values():
            if u["obligation_class"] == TAINT_CLASS and u["function"] == fn and _alarm_in_file(row, u["file"]):
                found.setdefault(u["coverage_id"], []).append((verdict, row))
    # A placed check with no Unknown, Invalid or Dead row in a function Eva analysed held: Valid.
    analysed = set(report.get("functions_with_properties") or [])
    for c in checks:
        file, _, fn = str(c["function"]).rpartition("#")
        if fn not in analysed:
            continue
        for u in units.values():
            if (
                u["obligation_class"] == TAINT_CLASS
                and u["function"] == fn
                and normalize_file(u["file"]) == normalize_file(file)
            ):
                found.setdefault(u["coverage_id"], [])
    for cid, unit_rows in found.items():
        u = units[cid]
        verdicts = {v for v, _ in unit_rows}
        verdict = next((v for v in ("invalid", "unknown", "dead") if v in verdicts), "valid")
        u.setdefault("bookkeeping", {}).setdefault("eva_taint", {})[module] = verdict
        where = [
            f"{names.get((_eva_alarm_path(r), int(r.get('line') or 0)), 'taint check')} at line {r.get('line')}"
            for _, r in unit_rows
        ]
        summary = {
            "valid": f"Eva slice '{module}': every taint check here holds (no copy of the secret reaches a sink "
            "from eva_main's contexts); the direct-flow proof is still WP's.",
            "dead": f"Eva slice '{module}': the taint check(s) are dead ({', '.join(where[:5])}): not reached.",
            "unknown": f"Eva slice '{module}': the secret's taint may reach a sink ({', '.join(where[:5])}).",
            "invalid": f"Eva slice '{module}': the secret's taint reaches a sink ({', '.join(where[:5])}).",
        }[verdict]
        add_evidence(u, "eva", "run_eva_slice.py", f"eva_taint_{verdict}", False, tool_output, summary)
        if verdict in TAINT_BLOCKING and u["status"] in ("planned", "blocked", "covered"):
            u["status"] = "blocked"
            u["unresolved"] = [x for x in u.get("unresolved") or [] if not x.startswith(TAINT_UNRESOLVED)] + [
                f"{TAINT_UNRESOLVED}{w}: the secret's taint may reach the sink (indirect flow)" for w in where[:5]
            ]
    return len(found)


def _taint_reopen(unit: dict) -> None:
    """A unit blocked only by Eva taint verdicts that no longer block: planned again (WP decides)."""
    unresolved = unit.get("unresolved") or []
    if unit["status"] != "blocked" or _taint_open(unit) or not unresolved:
        return
    if all(str(x).startswith(TAINT_UNRESOLVED) for x in unresolved):
        unit["status"] = "planned"
        unit["unresolved"] = []


# MetAcsl under Eva (docs/plans/metacsl-exploitation-plan.md, package B). With `eva` in
# security_props.json's `meta_engines`, run_eva_slice.py loads the module's meta-properties and reports
# the checks MetAcsl generated under `security_props`, outside the status lists the rte units read. Each
# planned instance there (`instances`: property, `file#name`, rows per status) is one property of one
# L4-L6 unit, filed with the rules of the rte rows: bookkeeping.eva_verdicts (module -> verdict), a cover
# only when some module proves every check and none leaves one open, an Unknown left to WP, an Invalid a
# candidate. Rows in harness code (`outside_instances`) and in target functions that are no instance
# (`unplanned_instances`) are in the report only: they never reach a unit.
_META_VERDICT_ORDER = ("invalid", "other", "unknown", "dead", "none", "valid")
_META_ROW_RE = re.compile(r"^\s*[A-Za-z_]\w*\s*[:,]\s*meta\s*[:,]")
_META_ROW_LISTS = ("invalid_alarms", "dead_alarms", "assumed_properties", "other_properties")


def _eva_meta_section(report: dict) -> dict | None:
    """The report's `security_props` when the run parsed a meta file and filed its rows; else None."""
    section = report.get("security_props")
    if not isinstance(section, dict) or section.get("error") or not section.get("meta_file"):
        return None
    return section


def _is_eva_meta_row(row: object, meta_name: str) -> bool:
    if not isinstance(row, dict):
        return False
    return Path(str(row.get("file") or "")).name == meta_name or bool(
        _META_ROW_RE.match(str(row.get("annotation") or ""))
    )


def _without_eva_meta_rows(report: dict, section: dict) -> dict:
    """
    The report without any MetAcsl row in its status lists. run_eva_slice.py never puts one there; a
    report from another writer must not turn a property's check into an RTE verdict of its function.
    """
    meta_name = Path(str(section.get("meta_file"))).name
    out = dict(report)
    raw = report.get("unknown_obligations_by_function")
    if isinstance(raw, dict):
        kept = {
            fn: [r for r in rows if not _is_eva_meta_row(r, meta_name)]
            for fn, rows in raw.items()
            if isinstance(rows, list)
        }
        out["unknown_obligations_by_function"] = {fn: rows for fn, rows in kept.items() if rows}
    for key in _META_ROW_LISTS:
        found = report.get(key)
        if isinstance(found, list):
            out[key] = [r for r in found if not _is_eva_meta_row(r, meta_name)]
    return out


def _eva_meta_instance_verdict(entry: object) -> str:
    """One planned instance's verdict from its row counts; `none` when MetAcsl generated no row for it."""
    if not isinstance(entry, dict):
        return "none"
    for bucket in ("invalid", "other", "unknown", "dead"):
        if entry.get(bucket):
            return bucket
    return "valid" if entry.get("valid") else "none"


def _eva_meta_cover_barred(unit: dict, facts: dict | None = None) -> bool:
    """
    An L4-L6 unit Eva's checks cannot cover: decided violated from the model, its taint check is open,
    or security_props.json says a property of it is not checked in its function (_meta_unchecked: Eva's
    module parse skips the same initializer calls MetAcsl skips under WP).
    """
    return unit["obligation_class"] in METACSL_CLASSES and (
        _decided_violation(unit) or bool(_taint_open(unit)) or bool(_meta_unchecked(unit, facts))
    )


def _ingest_eva_meta(
    units: dict[str, dict],
    candidates: dict[str, dict],
    section: dict,
    module: str,
    report: dict,
    tool_output: str,
    index: dict[str, list[tuple[int, int, str]]],
    touched: set[str],
    code_rows: list[tuple[str, dict]] | None = None,
    lines: dict[tuple[str, int], list[dict]] | None = None,
) -> tuple[int, int]:
    """
    File one Eva report's MetAcsl statuses under the L4-L6 units; returns (units given a verdict,
    candidates opened). A unit gets a verdict when the report lists an instance of one of its
    properties in its function; the unit's verdict is the worst of its properties', and an in-code
    check of one of them that Eva left open in the function (`code_rows`: Unknown, Invalid or Dead
    rows of the checks `lines` lists, package E's initializer checks) counts as `unknown`, since it is
    the same obligation at a call MetAcsl gave no instance:

      invalid  a check is Invalid: a candidate per Invalid row, the unit becomes `candidate`;
      other    a status Eva left unclassified, or a row that cannot be told apart from another file's
               same-named function: not credited;
      unknown  a check is Unknown: evidence only, WP proves the property;
      dead     the checks are dead under this harness (a harness gap);
      none     MetAcsl generated no check for a property here (it decided the instance statically, or
               did not instantiate it in this parse): not credited, WP's own MetAcsl run decides;
      valid    every property has checks and all are Valid: discharging evidence.

    The caller's loop over `touched` then covers or reopens the unit from every module's verdict.
    """
    entries: dict[tuple[str, str, str], dict] = {}
    for entry in section.get("instances") or []:
        if not isinstance(entry, dict):
            continue
        file, _, fn = str(entry.get("instance") or "").rpartition("#")
        entries[(str(entry.get("property")), normalize_file(file), fn)] = entry
    invalid_rows: dict[tuple[str, str], list[dict]] = {}
    for row in section.get("open_rows") or []:
        if isinstance(row, dict) and row.get("role") == "instance" and row.get("status_bucket") == "invalid":
            invalid_rows.setdefault((str(row.get("property")), str(row.get("instance"))), []).append(row)
    reduced_checks = [str(x) for x in (report.get("reduced_checks") or []) if str(x).strip()]
    filed = opened = 0
    for u in units.values():
        if u["obligation_class"] not in METACSL_CLASSES or u["status"] in NO_TOUCH or _decided_violation(u):
            continue
        names = [str(n) for n in (u.get("bookkeeping") or {}).get("security_properties") or []]
        u_file, fn = u["file"], u["function"]
        mine = {n: entries.get((n, normalize_file(u_file), fn)) for n in names}
        if not any(e is not None for e in mine.values()):
            continue  # this slice has no instance of the unit's properties in its function
        filed += 1
        touched.add(u["coverage_id"])
        per = {n: _eva_meta_instance_verdict(e) for n, e in mine.items()}
        open_code = _open_code_checks(u, code_rows, lines) if code_rows and lines else []
        if open_code:
            per["in-code checks"] = "unknown"
        verdict = min(per.values(), key=_META_VERDICT_ORDER.index)
        _unit_eva_verdicts(u)[module] = verdict
        listed = ", ".join(sorted(per))
        where = f"Eva slice '{module}': "
        if verdict == "invalid":
            for name in sorted(n for n, v in per.items() if v == "invalid"):
                instance = str((mine[name] or {}).get("instance"))
                rows = invalid_rows.get((name, instance)) or [
                    {"kind": "meta", "annotation": f"{name}: meta: (the report does not list the row)", "line": 0}
                ]
                for row in rows:
                    # A generated precondition is reported at its call site, in this function's own
                    # file; a generated assertion sits in the meta file and has no line here.
                    line = int(row.get("line") or 0) if row.get("file") and _alarm_in_file(row, u_file) else 0
                    kind = str(row.get("kind") or "assertion")
                    annotation = str(row.get("annotation") or "")
                    cand = upsert_candidate(
                        candidates,
                        make_fingerprint(u_file, fn, kind, annotation),
                        "eva",
                        "needs_validation",
                        module,
                        {"file": normalize_file(u_file), "line": line, "function": fn},
                        {"kind": kind, "predicate": annotation},
                        [],
                        tool_output,
                        [u["coverage_id"]],
                        f"Eva Invalid status of a check MetAcsl generated from {name}, without a concrete witness input",
                        site=_candidate_site(u_file, line, fn, index),
                    )
                    add_evidence(
                        u,
                        "eva",
                        "run_eva_slice.py",
                        "eva_meta_invalid",
                        False,
                        tool_output,
                        f"{where}Invalid{f' at line {line}' if line else ''}: {annotation[:200] or name}",
                    )
                    mark_candidate(u, cand["fingerprint"])
                    opened += 1
            continue
        count = sum(int((e or {}).get(verdict) or 0) for e in mine.values())
        if verdict == "unknown":
            count += len(open_code)
        if verdict == "other":
            add_evidence(
                u,
                "eva",
                "run_eva_slice.py",
                "eva_meta_unclassified",
                False,
                tool_output,
                f"{where}{count} check(s) of {listed} have a status Eva left unclassified, or sit in a function "
                "several files define under one name; not credited.",
            )
        elif verdict == "unknown":
            add_evidence(
                u,
                "eva",
                "run_eva_slice.py",
                "eva_meta_unknown",
                False,
                tool_output,
                f"{where}{count} check(s) of {listed} remain Unknown; WP proves the property.",
            )
        elif verdict == "dead":
            add_evidence(
                u,
                "eva",
                "run_eva_slice.py",
                "eva_meta_dead",
                False,
                tool_output,
                f"{where}the checks of {listed} are dead under the module harness: not reached from eva_main "
                "(harness gap).",
            )
        elif verdict == "none":
            missing = ", ".join(sorted(n for n, v in per.items() if v == "none"))
            add_evidence(
                u,
                "eva",
                "run_eva_slice.py",
                "eva_meta_no_instance",
                False,
                tool_output,
                f"{where}MetAcsl generated no check for {missing} in this function (decided statically, or not "
                "instantiated in this slice); not credited, WP's own MetAcsl run decides.",
            )
        else:
            summary = f"every check MetAcsl generated from {listed} in this function is Valid under Eva"
            if reduced_checks:
                summary += f" (reduced_checks: {', '.join(reduced_checks)})"
            add_evidence(u, "eva", "run_eva_slice.py", "eva_meta_valid", True, tool_output, f"{where}{summary}.")
            if reduced_checks:
                add_assumption(
                    u,
                    "boundary_assumption",
                    f"Eva slice '{module}' ran with reduced checks ({', '.join(reduced_checks)}).",
                )
    return filed, opened


@ledger_locked
def cmd_ingest_eva(paths: list[Path]) -> dict:
    units, candidates = load_state()
    stats = {"reports": 0, "covered": 0, "candidates": 0}
    mm = ModuleMap.load(".")
    index = _dag_line_index(dag=mm.dag)
    unit_names = {u["function"] for u in units.values()}
    touched: set[str] = set()
    taint_checks = _taint_checks()
    code_lines = _code_lines(_code_checks())
    meta_facts = _meta_facts()
    for path in paths:
        report = load_json_strict(path, max_bytes=EVA_REPORT_MAX_BYTES)
        stats["reports"] += 1
        tool_output = rel(str(path))
        # `module` is the report's harness module; verdicts and candidates stay keyed by it. With link
        # units it is a unit or a sub-module of one, and its report speaks for the unit's functions.
        module = report.get("module") or path.stem
        unit_module, scope = _report_scope(mm, module)
        report_sources = _extract_eva_report_sources(report)

        def owned(u: dict, unit_module: str = unit_module, report_sources: set[str] | None = report_sources) -> bool:
            if u["obligation_class"] != "rte" or u["module"] != unit_module:
                return False
            if report_sources and normalize_file(u["file"]) not in report_sources:
                # A report lists the .c files it analysed; header functions are compiled into them.
                return not normalize_file(u["file"]).endswith(".c")
            return True

        def answers(u: dict, scope: set[tuple[str, str]] | None = scope) -> bool:
            """Owned and in the harness's scope: what it records even when it analysed nothing there."""
            return owned(u) and (scope is None or (normalize_file(u["file"]), u["function"]) in scope)

        if report.get("status") != "ok":
            for u in _module_units(units, unit_module, scope):
                if owned(u):
                    add_evidence(
                        u,
                        "eva",
                        "run_eva_slice.py",
                        "eva_analysis_error",
                        False,
                        tool_output,
                        "Eva did not complete; no property statuses are available.",
                    )
            continue

        # This module's newest report replaces every verdict its earlier ones gave.
        taint_reset: list[dict] = []
        for u in units.values():
            verdicts = (u.get("bookkeeping") or {}).get("eva_verdicts")
            if isinstance(verdicts, dict) and module in verdicts:
                del verdicts[module]
                touched.add(u["coverage_id"])
            taint = (u.get("bookkeeping") or {}).get("eva_taint")
            if isinstance(taint, dict) and module in taint:
                del taint[module]
                taint_reset.append(u)
        report, split_rows = _split_taint_rows(report, set(code_lines))
        code_rows = [(v, r) for v, r in split_rows if _code_key(r) in code_lines and not _is_taint_row(r)]
        taint_rows = [(v, r) for v, r in split_rows if _is_taint_row(r)]
        _ingest_code_checks(units, code_rows, code_lines, module, tool_output)
        taint_units = _ingest_taint(units, taint_rows, taint_checks, module, report, tool_output)
        if taint_units:
            stats["taint_units"] = stats.get("taint_units", 0) + taint_units
        for u in taint_reset:
            _taint_reopen(u)
        meta_section = _eva_meta_section(report)
        if meta_section is not None:
            report = _without_eva_meta_rows(report, meta_section)
            meta_units, meta_candidates = _ingest_eva_meta(
                units, candidates, meta_section, module, report, tool_output, index, touched, code_rows, code_lines
            )
            if meta_units:
                stats["meta_units"] = stats.get("meta_units", 0) + meta_units
            stats["candidates"] += meta_candidates
        _file_open_code_checks_of_no_goal_covers(units, code_rows, code_lines, module, touched)

        def by_function(rows: object, reported: str | None = None) -> dict[str, list]:
            out: dict[str, list] = {}
            for row in rows if isinstance(rows, list) else []:
                name = reported if reported is not None else str((row or {}).get("function") or "")
                out.setdefault(_eva_row_function(row, index, name), []).append(row)
            return out

        unknown_by_fn: dict[str, list] = {}
        raw_unknown = report.get("unknown_obligations_by_function") or {}
        for fn_name, rows in raw_unknown.items() if isinstance(raw_unknown, dict) else []:
            for key, found in by_function(rows, str(fn_name)).items():
                unknown_by_fn.setdefault(key, []).extend(found)
        invalid_by_fn = by_function(report.get("invalid_alarms", []))
        dead_by_fn = by_function(report.get("dead_alarms", []))
        assumed_by_fn = by_function(report.get("assumed_properties", []))
        other_by_fn = by_function(report.get("other_properties", []))
        props_by_fn: dict[str, list[dict]] = {}
        raw_props_by_file = report.get("functions_with_properties_by_file") or []
        if isinstance(raw_props_by_file, dict):
            for fpath, fns in raw_props_by_file.items():
                for fn_name in fns or []:
                    props_by_fn.setdefault(str(fn_name), []).append({"file": str(fpath), "function": str(fn_name)})
        else:
            for item in raw_props_by_file:
                if isinstance(item, dict) and item.get("function"):
                    props_by_fn.setdefault(str(item["function"]), []).append(item)
        with_props = set(report.get("functions_with_properties", []))
        # Names no row's line placed (the property lists carry none): the kernel's renamed copies.
        for renamed, original in _kernel_renames(
            {*unknown_by_fn, *invalid_by_fn, *dead_by_fn, *assumed_by_fn, *other_by_fn, *props_by_fn, *with_props},
            unit_names,
        ).items():
            for by_fn in (unknown_by_fn, invalid_by_fn, dead_by_fn, assumed_by_fn, other_by_fn, props_by_fn):
                if renamed in by_fn:
                    by_fn[original] = [*(by_fn.get(original) or []), *by_fn.pop(renamed)]
            if renamed in with_props:
                with_props.add(original)
        reported_fns = {*unknown_by_fn, *invalid_by_fn, *dead_by_fn, *assumed_by_fn, *other_by_fn, *props_by_fn}
        reduced_checks = [str(x) for x in (report.get("reduced_checks") or []) if str(x).strip()]
        tuning = report.get("tuning")
        combination = tuning.get("combination") if isinstance(tuning, dict) else None
        upgraded = combination.get("upgraded") if isinstance(combination, dict) else None
        combined_fns = {str(item.get("function")) for item in upgraded or [] if isinstance(item, dict)}
        # Invalid alarms already turned into a candidate for a unit; the rest are ingested after the
        # loop so none is dropped (remediation plan H7).
        consumed: set[int] = set()

        def in_file(rows: list, u_file: str) -> list:
            return [a for a in rows if not isinstance(a, dict) or _alarm_in_file(a, u_file)]

        for u in units.values():
            if u["obligation_class"] != "rte" or u["status"] in ("out_of_scope", "not_applicable"):
                continue
            if u["status"] == "deferred" and u.get("unresolved") != [HEADER_UNREACHED]:
                continue
            own = owned(u)
            fn = u["function"]
            if not answers(u) and fn not in reported_fns:
                continue
            u_file = u["file"]
            unit_invalids = [a for a in invalid_by_fn.get(fn, []) if isinstance(a, dict) and _alarm_in_file(a, u_file)]
            unit_unknowns = in_file(unknown_by_fn.get(fn) or [], u_file)
            unit_deads = in_file(dead_by_fn.get(fn, []), u_file)
            unit_assumed = in_file(assumed_by_fn.get(fn, []), u_file)
            unit_others = in_file(other_by_fn.get(fn, []), u_file)
            if props_by_fn:
                has_props = any(_alarm_in_file(p, u_file) for p in props_by_fn.get(fn, []))
            elif report_sources:
                has_props = fn in with_props and (normalize_file(u_file) in report_sources)
            else:
                has_props = own and fn in with_props
            has_props = has_props or bool(unit_invalids or unit_unknowns or unit_deads or unit_assumed or unit_others)
            if not answers(u) and not has_props:
                continue  # another harness's slice that never analysed this function
            if has_props and u["status"] == "deferred":
                # A harness reaches this header function after all: it is work again.
                u["status"] = "planned"
                u["unresolved"] = []
            if u["status"] == "deferred":
                continue  # still unreached: no evidence on a deferred unit
            touched.add(u["coverage_id"])
            where = "" if own else f"Eva slice '{module}' (another module's harness): "

            for alarm in unit_invalids:
                consumed.add(id(alarm))
                fp = make_fingerprint(u_file, fn, alarm.get("kind", ""), alarm.get("annotation", ""))
                cand = upsert_candidate(
                    candidates,
                    fp,
                    "eva",
                    "needs_validation",
                    # The harness module: a candidate is replayed and verified through its harness.
                    module,
                    {"file": normalize_file(u_file), "line": int(alarm.get("line") or 0), "function": fn},
                    {"kind": alarm.get("kind") or "assertion", "predicate": alarm.get("annotation", "")},
                    [],
                    tool_output,
                    [u["coverage_id"]],
                    "Eva Invalid status without a concrete witness input"
                    if own
                    else f"Eva Invalid status in cross-module slice '{module}' without a concrete witness input",
                    site=_candidate_site(u_file, alarm.get("line"), fn, index),
                )
                fp = cand["fingerprint"]  # the site's candidate may be another detection's key
                add_evidence(
                    u,
                    "eva",
                    "run_eva_slice.py",
                    "eva_invalid",
                    False,
                    tool_output,
                    (
                        f"Eva reports Invalid at line {alarm.get('line')}: "
                        if own
                        else f"Eva slice '{module}' reports Invalid at line {alarm.get('line')}: "
                    )
                    + (alarm.get("annotation", "")[:200] or alarm.get("kind", "")),
                )
                mark_candidate(u, fp)
                stats["candidates"] += 1
            if unit_assumed:
                add_assumption(
                    u,
                    "stub_contract",
                    f"{len(unit_assumed)} property status(es) 'Considered valid' (libc/stub specifications) under Eva.",
                )
            if unit_invalids:
                verdict = "invalid"
            elif unit_others:
                verdict = "other"
            elif unit_unknowns:
                verdict = "unknown"
            elif has_props and not unit_deads:
                verdict = "valid"
            elif unit_deads:
                verdict = "dead"
            else:
                verdict = "none"
            _unit_eva_verdicts(u)[module] = verdict
            if unit_invalids:
                continue
            if unit_others:
                # Inconsistent or unrecognized statuses settle nothing: the unit stays open for WP.
                statuses = sorted({str(a.get("status") or "?") for a in unit_others if isinstance(a, dict)})
                add_evidence(
                    u,
                    "eva",
                    "run_eva_slice.py",
                    "eva_unclassified_status",
                    False,
                    tool_output,
                    f"{where}{len(unit_others)} property status(es) Eva left unclassified "
                    f"({', '.join(statuses)[:120]}); not credited.",
                )
            if unit_unknowns:
                add_evidence(
                    u,
                    "eva",
                    "run_eva_slice.py",
                    "eva_unknown",
                    False,
                    tool_output,
                    f"{where}{len(unit_unknowns)} RTE obligation(s) remain Unknown; queued for WP.",
                )
            elif verdict == "valid":
                summary_msg = "Every RTE obligation in this function is Valid under Eva"
                if reduced_checks:
                    summary_msg += f" (reduced_checks: {', '.join(reduced_checks)})"
                add_evidence(u, "eva", "run_eva_slice.py", "eva_all_valid", True, tool_output, f"{where}{summary_msg}.")
                if reduced_checks:
                    # Say what each reduced check means only when it is the one in force: most runs only
                    # carry -no-warn-unsigned-downcast (C11 modular conversions).
                    recursion = any("assigns" in rc or "recursi" in rc for rc in reduced_checks)
                    add_assumption(
                        u,
                        "boundary_assumption",
                        f"Eva slice '{module}' ran with reduced checks ({', '.join(reduced_checks)})"
                        + (
                            "; recursive or missing assigns specifications were treated as warnings."
                            if recursion
                            else "."
                        ),
                    )
                if fn in combined_fns:
                    add_assumption(
                        u,
                        "boundary_assumption",
                        f"Eva slice '{module}': some obligations here are discharged by per-obligation combination "
                        "of tuning runs, each Valid in a complete run of the same sources and harness.",
                    )
            elif unit_others:
                pass
            elif unit_deads:
                add_evidence(
                    u,
                    "eva",
                    "run_eva_slice.py",
                    "eva_dead",
                    False,
                    tool_output,
                    f"{where}Properties are dead under the module harness: function not reached from eva_main "
                    "(harness gap).",
                )
            else:
                add_evidence(
                    u,
                    "eva",
                    "run_eva_slice.py",
                    "eva_no_properties",
                    False,
                    tool_output,
                    "Eva reported no property for this function (trivial or not reached).",
                )

        for alarm in report.get("invalid_alarms", []):
            if id(alarm) in consumed or not isinstance(alarm, dict):
                continue
            consumed.add(id(alarm))
            _ingest_unscheduled_eva_invalid(units, candidates, alarm, module, tool_output, unit_module, index)
            stats["candidates"] += 1

    # Each touched unit's Eva status, from every module's verdict: covered only when some module's
    # harness proves every RTE obligation in it and none leaves one Unknown, Invalid or unclassified.
    # An L4-L6 unit follows the same rule over the checks MetAcsl generated for its properties
    # (_ingest_eva_meta), unless the model decided it violated or its taint check is open.
    for cid in sorted(touched):
        u = units[cid]
        verdicts = (u.get("bookkeeping") or {}).get("eva_verdicts") or {}
        valid = sorted(m for m, v in verdicts.items() if v == "valid")
        blocking = sorted(m for m, v in verdicts.items() if v in EVA_BLOCKING)
        established = bool(valid) and not blocking and not _eva_meta_cover_barred(u, meta_facts)
        u["assumptions"] = [
            a
            for a in u["assumptions"]
            if not (
                a.get("kind") == "boundary_assumption"
                and str(a.get("description") or "").startswith("Eva result holds")
            )
        ]
        if established:
            names = ", ".join(f"'{m}'" for m in valid)
            add_assumption(
                u,
                "boundary_assumption",
                f"Eva result holds for calling contexts reachable from eva_main of module{'s' if len(valid) > 1 else ''} {names}.",
            )
            if u["status"] in ("planned", "blocked"):
                u["status"] = "covered"
                u["unresolved"] = []
                stats["covered"] += 1
            continue
        u["assumptions"] = [
            a
            for a in u["assumptions"]
            if not (
                a.get("kind") == "boundary_assumption"
                and str(a.get("description") or "").startswith(_EVA_ASSUMPTION_PREFIXES)
            )
        ]
        if blocking and u["status"] in ("covered", "candidate") and _wp_cover_is_no_goal(u):
            # WP gave the no-goal credit before this report opened a check of the unit. An Invalid
            # check has already made the unit a candidate: only the credit is left to take away.
            if _withdraw_no_goal_credit(u, blocking):
                stats["reopened"] = stats.get("reopened", 0) + 1
        elif u["status"] == "covered" and not _wp_discharged(u):
            # Covered by Eva alone, and a module's report no longer establishes it (a repaired harness
            # reaching new contexts, or another module's harness leaving obligations open): open again.
            u["status"] = "planned"
            u["agent_id"] = None
            u["unresolved"] = []
            why = ", ".join(f"'{m}'" for m in blocking) or "none proves it"
            what = "check of this unit's properties" if u["obligation_class"] in METACSL_CLASSES else "RTE obligation"
            add_evidence(
                u,
                "eva",
                "run_eva_slice.py",
                "eva_cover_withdrawn",
                False,
                (u["evidence"][-1] or {}).get("tool_output") if u["evidence"] else None,
                f"Eva no longer proves every {what} here (module(s) leaving obligations open: {why}); back to planned.",
            )
            stats["reopened"] = stats.get("reopened", 0) + 1
    commit(units, candidates)
    return stats


def _eva_alarm_path(alarm: dict) -> str:
    """Repository-relative file of an Eva report row ('' when the row carries no file)."""
    raw_file = str(alarm.get("file") or "").replace("\\", "/").strip()
    raw_dir = str(alarm.get("directory") or "").replace("\\", "/").strip().rstrip("/")
    if raw_file and raw_dir and raw_dir != "." and not raw_file.startswith("/"):
        raw_file = f"{raw_dir}/{raw_file}"
    return normalize_file(raw_file) if raw_file else ""


def _ingest_unscheduled_eva_invalid(
    units: dict[str, dict],
    candidates: dict[str, dict],
    alarm: dict,
    module: str,
    tool_output: str,
    unit_module: str | None = None,
    index: dict[str, list[tuple[int, int, str]]] | None = None,
) -> None:
    """
    An Eva Invalid alarm no scheduled rte unit took (remediation plan H7), mirroring the fuzz path:
    a deferred (Tier 3) unit of the function is linked and becomes `candidate`; a function with no
    eligible unit (out_of_scope / not_applicable / unseeded / harness code) still gets an unlinked
    `needs_validation` candidate rather than being dropped. `module` is the report's harness module
    (the candidate's), `unit_module` the DAG module it belongs to (default: the same).
    """
    unit_module = unit_module or module
    index = _dag_line_index() if index is None else index
    fn = str(alarm.get("function") or "")
    alarm_file = _eva_alarm_path(alarm)
    linked_units = [
        u
        for u in units_for_function(units, alarm_file, fn)
        if u["obligation_class"] == "rte"
        and u["status"] not in ("out_of_scope", "not_applicable")
        and _alarm_in_file(alarm, u["file"])
    ]
    kind = alarm.get("kind", "")
    annotation = alarm.get("annotation", "")
    line = int(alarm.get("line") or 0)
    prop = {"kind": kind or "assertion", "predicate": annotation}
    if linked_units:
        u_file = linked_units[0]["file"]
        fp = make_fingerprint(u_file, fn, kind, annotation)
        cand = upsert_candidate(
            candidates,
            fp,
            "eva",
            "needs_validation",
            module,
            {"file": normalize_file(u_file), "line": line, "function": fn},
            prop,
            [],
            tool_output,
            [u["coverage_id"] for u in linked_units],
            # Same note the module / cross-module loops write once the unit is `candidate`, so
            # re-ingesting the report is a no-op.
            "Eva Invalid status without a concrete witness input"
            if linked_units[0]["module"] == unit_module
            else f"Eva Invalid status in cross-module slice '{module}' without a concrete witness input",
            site=_candidate_site(u_file, line, fn, index),
        )
        fp = cand["fingerprint"]
        for u in linked_units:
            _unit_eva_verdicts(u)[module] = "invalid"
            add_evidence(
                u,
                "eva",
                "run_eva_slice.py",
                "eva_invalid",
                False,
                tool_output,
                f"Eva slice '{module}' reports Invalid at line {alarm.get('line')}: {annotation[:200] or kind}",
            )
            mark_candidate(u, fp)
        return
    file = alarm_file or "unknown"
    function = fn or "unknown_function"
    fp = make_fingerprint(file, function, kind, annotation)
    upsert_candidate(
        candidates,
        fp,
        "eva",
        "needs_validation",
        module,
        {"file": file, "line": line, "function": function},
        prop,
        [],
        tool_output,
        [],
        f"Eva Invalid status without a concrete witness input; no ledger unit for {file}#{function}::rte "
        "(out of scope, not applicable, harness or unseeded code)",
        site=_candidate_site(file, line, function, index),
    )


@ledger_locked
def cmd_ingest_wp(paths: list[Path], sweep: bool = False) -> dict:
    """
    Ingest WP reports. With `sweep`, each report is the trusted end-of-run re-proof of its function
    (`pipeline_make.py sweep`): a WP-covered unit the report does not credit again, whatever the
    reason (unproven goals, analysis or ACSL error, unmet limits, a missing report), stops counting
    as covered and becomes `blocked`.
    """
    units, candidates = load_state()
    stats = {"reports": 0, "covered": 0, "blocked": 0}
    credited: set[str] = set()
    sweep_checks: list[tuple[str, str, list[str]]] = []
    meta_facts = _meta_facts()
    for path in paths:
        report = load_json_strict(path)
        if "function" not in report or "status" not in report or report.get("mode") == "guardrail":
            continue
        stats["reports"] += 1
        tool_output = rel(str(path))
        fn = report["function"]
        targets = [u for u in units_for_function(units, report.get("file", ""), fn) if u["status"] not in NO_TOUCH]
        if sweep:
            wp_covered = [
                u["coverage_id"]
                for u in targets
                if u["status"] == "covered"
                and any(e.get("phase") == "wp" and e.get("discharging") for e in u.get("evidence") or [])
            ]
            sweep_checks.append((str(report["status"]), tool_output, wp_covered))
        models = wp_report_models(report)
        model_problem = next((p for p in map(wp_model_problem, models) if p), None)
        model_assumption = next((a for a in map(wp_model_assumption, models) if a), None)
        if report["status"] == "all_proven" and model_problem:
            # A model that is not evidence (`cast`, `Hoare`, `nat`, ...), including a report written
            # before run_wp_function.py refused the model itself: the proof is unsound.
            soundness = dict(report.get("soundness") or {})
            soundness["tier_b_unsound"] = [*(soundness.get("tier_b_unsound") or []), model_problem]
            report = {**report, "status": "unsound_proof", "soundness": soundness}
        if report["status"] == "acsl_syntax_error":
            for u in targets:
                add_evidence(
                    u,
                    "wp",
                    "run_wp_function.py",
                    "wp_acsl_syntax_error",
                    False,
                    tool_output,
                    "ACSL kernel check failed; WP did not run.",
                )
            continue
        if report["status"] == "analysis_error":
            # Frama-C was killed or crashed (OOM, wall-clock limit): no goal was decided, so the
            # unit status is left to the scheduler (retry once, then blocked).
            reason = str(report.get("reason") or "unknown")
            for u in targets:
                add_evidence(
                    u,
                    "wp",
                    "run_wp_function.py",
                    "wp_analysis_error",
                    False,
                    tool_output,
                    f"WP did not complete ({reason}); no goal was credited.",
                    details={"reason": reason},
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
                    u,
                    "wp",
                    "run_wp_function.py",
                    f"wp_{report['status']}",
                    False,
                    tool_output,
                    f"WP soundness gate rejected proof ({report['status']}): {summary[:220]}",
                )
                if u["status"] != "candidate":
                    u["status"] = "blocked"
                    u["unresolved"] = list(
                        dict.fromkeys(f"{report['status']}: {msg[:180]}" for msg in (issues[:10] or [summary]))
                    )
                    stats["blocked"] += 1
            continue
        soundness = report.get("soundness", {})
        by_class = report.get("by_obligation_class", {})
        all_proven = report["status"] == "all_proven"
        raw_limits = report.get("limits")
        limits_problem = wp_limits_problem(raw_limits)
        # Every branch that reads the limits is guarded by `all_proven` after the `limits_problem` branch,
        # so it only runs on a dict; the fallback just keeps that visible to the type checker.
        limits: dict = raw_limits if isinstance(raw_limits, dict) else {}
        frame_problem = wp_frame_problem(report) if all_proven else None
        unproven_by_class: dict[str, list[dict]] = {}
        for g in report.get("unproven_goals", []):
            unproven_by_class.setdefault(g.get("obligation_class", "rte"), []).append(g)

        for u in targets:
            if u["status"] == "candidate":
                add_evidence(
                    u,
                    "wp",
                    "run_wp_function.py",
                    f"wp_{report['status']}",
                    False,
                    tool_output,
                    "WP result recorded on a unit with an open candidate; candidate verdict takes precedence.",
                )
                continue
            if _decided_violation(u):
                # Decided from the model (plan step M2): no WP result outweighs the literal it was shown.
                add_evidence(
                    u,
                    "wp",
                    "run_wp_function.py",
                    f"wp_{report['status']}",
                    False,
                    tool_output,
                    "WP result recorded on a unit decided violated from the model; not credited.",
                )
                continue
            if _decided_only(u):
                # Every property of the unit was decided from the model: WP has no goal of it to report.
                continue
            if _taint_open(u):
                # Plan step M3: Eva's taint domain says a copy of the secret may reach a sink here.
                add_evidence(
                    u,
                    "wp",
                    "run_wp_function.py",
                    f"wp_{report['status']}",
                    False,
                    tool_output,
                    f"WP result recorded on a unit whose Eva taint check is open (module(s) "
                    f"{', '.join(_taint_open(u))}); not credited.",
                )
                continue
            gaps = _meta_unchecked(u, meta_facts)
            if gaps:
                # Package E: a site the property does not check (an initializer call no check could be
                # written for, a caller left out of the targets). A goal proven elsewhere in the
                # function, or none at all, says nothing about it.
                add_evidence(
                    u,
                    "wp",
                    "run_wp_function.py",
                    "wp_meta_unchecked",
                    False,
                    tool_output,
                    f"WP result recorded on a unit whose property is not checked everywhere in the function: "
                    f"{gaps[0]}; not credited."[:400],
                )
                if u["status"] != "blocked":
                    stats["blocked"] += 1
                u["status"] = "blocked"
                u["unresolved"] = [f"not checked: {g}"[:240] for g in gaps[:10]]
                continue
            cls = u["obligation_class"]
            counts = by_class.get(cls)
            if counts and counts.get("unproven", 0) > 0:
                goals = unproven_by_class.get(cls, [])
                add_evidence(
                    u,
                    "wp",
                    "run_wp_function.py",
                    "wp_unproven",
                    False,
                    tool_output,
                    f"{counts['unproven']} goal(s) unproven, {counts.get('proven', 0)} proven.",
                )
                u["status"] = "blocked"
                u["unresolved"] = list(
                    dict.fromkeys(
                        f"unproven {g.get('kind') or 'goal'} at line {g.get('line')}: {(g.get('annotation') or '')[:160]}".strip()
                        for g in goals[:10]
                    )
                ) or [f"{counts['unproven']} unproven goal(s)"]
                stats["blocked"] += 1
            elif all_proven and limits_problem:
                add_evidence(
                    u,
                    "wp",
                    "run_wp_function.py",
                    "wp_limits_unmet",
                    False,
                    tool_output,
                    f"Proof not credited: {limits_problem}.",
                )
            elif all_proven and cls in limits.get("classes_without_real_clause", []):
                add_evidence(
                    u,
                    "wp",
                    "run_wp_function.py",
                    "wp_trivial_clause_only",
                    False,
                    tool_output,
                    f"Every {cls} clause holds whatever the function does "
                    f"({', '.join(limits.get('trivial_layer_clauses', []))}); not credited.",
                )
            elif all_proven and cls == "l3_frame" and frame_problem:
                # Both credits below (proven goals of the class, and none left by Qed) need a frame to be about.
                add_evidence(
                    u,
                    "wp",
                    "run_wp_function.py",
                    frame_problem[0],
                    False,
                    tool_output,
                    f"Frame not credited: {frame_problem[1]}. The unit stays open until WP proves an `assigns` "
                    "clause of the function's own contract.",
                )
            elif (
                all_proven
                and cls in METACSL_CLASSES
                and (not_evaluated := _meta_not_evaluated(u, report, bool(counts)))
            ):
                # Before both credits below: proven goals of the class, and none left by MetAcsl's simplification.
                add_evidence(
                    u,
                    "wp",
                    "run_wp_function.py",
                    "wp_meta_not_evaluated",
                    False,
                    tool_output,
                    f"Not credited: {not_evaluated}."[:400],
                )
            elif counts and (counts.get("proven", 0) + counts.get("proven_under_hyp", 0)) > 0 and all_proven:
                add_evidence(
                    u,
                    "wp",
                    "run_wp_function.py",
                    "wp_proven",
                    True,
                    tool_output,
                    f"{counts.get('proven', 0)} goal(s) proven, {counts.get('proven_under_hyp', 0)} valid under hypotheses.",
                    details={"limits": limits},
                )
                add_wp_limit_assumptions(u, limits, report["function"], model_assumption)
                if counts.get("proven_under_hyp", 0):
                    add_assumption(
                        u,
                        "valid_under_hyp",
                        f"{counts['proven_under_hyp']} goal(s) valid under hypotheses (callee contracts); resolved by the proof audit.",
                    )
                if soundness.get("reduced_checks"):
                    add_assumption(
                        u,
                        "other",
                        f"WP run with reduced RTE check flags: {', '.join(soundness['reduced_checks'])}.",
                    )
                if soundness.get("assumed_function_pointer_goals"):
                    add_assumption(
                        u,
                        "other",
                        f"WP assumed degenerated \\valid_function goals: {len(soundness['assumed_function_pointer_goals'])} goal(s).",
                    )
                u["status"] = "covered"
                u["unresolved"] = []
                credited.add(u["coverage_id"])
                stats["covered"] += 1
            elif cls in ("rte", "l2_termination", "l3_frame") and all_proven and not counts:
                ev_result = "wp_no_rte_goals" if cls == "rte" else "wp_qed_simplified"
                ev_summary = (
                    "WP generated no RTE goal for this function."
                    if cls == "rte"
                    else f"WP soundness passed and Qed discharged {cls} with zero remaining prover goals."
                )
                add_evidence(
                    u,
                    "wp",
                    "run_wp_function.py",
                    ev_result,
                    True,
                    tool_output,
                    ev_summary,
                    details={"limits": limits},
                )
                add_wp_limit_assumptions(u, limits, report["function"], model_assumption)
                if soundness.get("reduced_checks"):
                    add_assumption(
                        u,
                        "other",
                        f"WP run with reduced RTE check flags: {', '.join(soundness['reduced_checks'])}.",
                    )
                u["status"] = "covered"
                u["unresolved"] = []
                credited.add(u["coverage_id"])
                stats["covered"] += 1
            elif (
                cls in METACSL_CLASSES
                and all_proven
                and not counts
                and _meta_decided_statically(u, report)
                and (bar := _meta_no_goal_bar(u, meta_facts))
            ):
                # No goal, and something says an instance is open (docs/troubleshooting/eva.md) or an
                # in-code check of the function was not among the goals: the unit keeps its status,
                # and the next Eva report or a WP run with a goal decides.
                names = ", ".join(sorted((u.get("bookkeeping") or {}).get("security_properties") or []))
                add_evidence(
                    u,
                    "wp",
                    "run_wp_function.py",
                    bar[0],
                    False,
                    tool_output,
                    f"MetAcsl loaded {names} and left no {cls} goal in this function, but {bar[1]}; not credited."[:400],
                )
            elif cls in METACSL_CLASSES and all_proven and not counts and _meta_decided_statically(u, report):
                # MetAcsl's -meta-simpl drops an instance it decides statically: no goal is left, the
                # property still holds in this function (docs/troubleshooting/security-properties.md, M1).
                names = ", ".join(sorted((u.get("bookkeeping") or {}).get("security_properties") or []))
                add_evidence(
                    u,
                    "wp",
                    "run_wp_function.py",
                    "wp_meta_simplified",
                    True,
                    tool_output,
                    f"MetAcsl loaded {names} and decided every instance in this function statically "
                    f"(no {cls} goal left); WP soundness passed.",
                    details={"limits": limits},
                )
                add_wp_limit_assumptions(u, limits, report["function"], model_assumption)
                u["status"] = "covered"
                u["unresolved"] = []
                credited.add(u["coverage_id"])
                stats["covered"] += 1
            elif counts and not all_proven:
                add_evidence(
                    u,
                    "wp",
                    "run_wp_function.py",
                    "wp_function_incomplete",
                    False,
                    tool_output,
                    f"Goals of class {cls} are proven, but the function proof is incomplete; not credited.",
                )
            else:
                add_evidence(
                    u,
                    "wp",
                    "run_wp_function.py",
                    "wp_no_credited_goals",
                    False,
                    tool_output,
                    f"No WP goal could be credited to {cls}.",
                )
    for status, tool_output, wp_covered in sweep_checks:
        for cid in wp_covered:
            u = units[cid]
            if cid in credited or u["status"] != "covered":
                continue
            add_evidence(
                u,
                "wp",
                "pipeline_make.py",
                "wp_sweep_not_reproven",
                False,
                tool_output,
                f"The trusted end-of-run re-proof did not re-establish this unit (WP status: {status}).",
            )
            u["status"] = "blocked"
            u["unresolved"] = [f"wp-sweep re-proof did not re-establish this unit (WP status: {status})"]
            stats["blocked"] += 1
    commit(units, candidates)
    return stats


@ledger_locked
def cmd_mark_carried(report: Path, entry: str, key: str) -> dict:
    """
    Record that the covered units a WP report just credited (`ingest-wp <report>`) were carried
    forward from an earlier run's wp-sweep (scripts/proof_carry.py) and re-proven on the current
    tree: their discharging WP evidence from that report becomes `carried_forward_reproven`, with
    the restored cache entry (`entry`, run-relative) and its key under `details.proof_carry`. The
    credit itself still comes from the re-proof; this only names where the contract came from.
    """
    units, candidates = load_state()
    tool_output = rel(str(report))
    marked: list[str] = []
    for cid in sorted(units):
        u = units[cid]
        if u["status"] != "covered":
            continue
        for ev in u.get("evidence") or []:
            if ev.get("phase") == "wp" and ev.get("discharging") and ev.get("tool_output") == tool_output:
                ev["result"] = "carried_forward_reproven"
                ev["producer"] = "proof_carry.py"
                if not str(ev.get("summary") or "").startswith("Carried forward"):
                    ev["summary"] = (
                        "Carried forward from an earlier run's wp-sweep and re-proven on the current tree: "
                        f"{ev.get('summary') or ''}"
                    ).strip()
                details = ev.setdefault("details", {})
                details["proof_carry"] = {"entry": rel(entry), "key": key}
                if cid not in marked:
                    marked.append(cid)
    if marked:
        commit(units, candidates)
    return {"report": tool_output, "marked": marked}


# --------------------------------------------- M2 hypotheses & crash verifier


def _infer_module_for_function(units: dict[str, dict], file: str, function: str) -> str:
    """The DAG module (with link units: the unit) of a function's ledger units."""
    matched = units_for_function(units, file, function)
    if matched:
        return matched[0].get("module") or "unknown"
    return "unknown"


def _candidate_harness_module(mm: ModuleMap, cand: dict) -> str:
    """
    The harness module a candidate is replayed and verified through (its sidecar, build, fuzz
    report). Candidates name their harness module; one recorded before step I5b may name a link
    unit instead, which resolves to the unit's harness answering for the candidate's function.
    """
    module = cand.get("module") or "unknown"
    loc = cand.get("location") or {}
    return harness_module_for_function(mm, module, loc.get("file"), loc.get("function")) or module


def _add_related(cand: dict, other_fp: str, reason: str) -> bool:
    """Record a `related` link on a candidate, once per other fingerprint. True when it was added."""
    related = cand.setdefault("related", [])
    if any(r.get("fingerprint") == other_fp for r in related):
        return False
    related.append({"fingerprint": other_fp, "reason": reason})
    return True


@ledger_locked
def cmd_link_related(index_path: Path) -> dict:
    """
    D1b: link candidates that other engines report on one reproducer. A replay index entry's
    `cross_engine.failures` names the failures its reproducer makes on the other engine. A failure whose
    fingerprint keys another candidate, or is one of its observations, and that lies in the same file and
    function as the entry's candidate, gives both candidates a `related` entry, once. The verifier then sees
    one bug (D17: the second is rejected as `duplicate`).
    """
    index = load_json_strict(index_path)
    units, candidates = load_state()
    owner: dict[str, str] = {}
    for key, cand in candidates.items():
        owner.setdefault(key, key)
        for obs in cand.get("observations") or []:
            owner.setdefault(obs["fingerprint"], key)
    links = 0
    for entry_fp, entry in (index.get("by_fingerprint") or {}).items():
        cross = entry.get("cross_engine") if isinstance(entry, dict) else None
        found = candidates.get(entry_fp)
        if not isinstance(cross, dict) or found is None:
            continue
        loc = found.get("location") or {}
        file, function = normalize_file(loc.get("file") or ""), loc.get("function")
        for failure in cross.get("failures") or []:
            other_key = owner.get(str(failure.get("fingerprint") or ""))
            if other_key is None or other_key == entry_fp:
                continue
            if normalize_file(str(failure.get("file") or "")) != file or failure.get("function") != function:
                continue
            reason = (
                f"cross-engine replay: {cross.get('engine')} fails at "
                f"{failure.get('file')}:{failure.get('line')} on the same reproducer"
            )
            links += _add_related(found, other_key, reason)
            links += _add_related(candidates[other_key], entry_fp, reason)
    if links:
        commit(units, candidates)
    return {"index": str(index_path), "links_added": links}


def _find_matching_sink_candidate(
    candidates: dict[str, dict],
    file: str,
    function: str,
    kind_or_cls: str,
    predicate: str,
    site: str | None = None,
) -> dict | None:
    """
    Find an existing candidate for the same `(file, function, normalized_kind)` sink
    so a prover/breaker hypothesis or breaker crash merges with an existing fuzz/Eva
    candidate instead of inflating `candidates.json` with a second fingerprint.

    With a `site` (a detection with a line, D1c), the candidate at that site wins; the function-and-kind
    rule applies only when no candidate has the site, or when the detection has none.
    """
    if site is not None:
        at_site = next((c for c in candidates.values() if c.get("site") == site), None)
        if at_site is not None:
            return at_site
    norm_f = normalize_file(file)
    norm_k = normalize_kind(kind_or_cls, predicate)
    for cand in candidates.values():
        loc = cand.get("location") or {}
        if normalize_file(loc.get("file") or "") != norm_f or loc.get("function") != function:
            continue
        prop = cand.get("property") or {}
        cand_k = normalize_kind(prop.get("kind") or "", prop.get("predicate") or "")
        if cand_k == norm_k or norm_k in ("rte", "assertion", "property") or cand_k in ("rte", "assertion", "property"):
            return cand
    return None


def _breaker_campaign_failures(aid: str) -> dict[str, dict]:
    """
    sha256 -> artifact record (with a parsed `failure`) of every campaign report directly under the
    breaker's scratch (`run_eacsl_fuzz.py campaign --out-json`, `"mode": "campaign"`). The location of a
    breaker crash is taken from these tool records when one matches the crash file, never from the
    agent's own words. Replay and driver reports are not campaign reports and are ignored.
    """
    found: dict[str, dict] = {}
    scratch = Path("agents") / aid / "scratch"
    try:
        paths = sorted(p for p in scratch.glob("*.json") if p.name != "result.json")
    except OSError:
        return found
    for p in paths:
        report = _read_scratch_json(aid, p.as_posix())
        if not isinstance(report, dict) or report.get("mode") != "campaign":
            continue
        for art in report.get("artifacts") or []:
            if isinstance(art, dict) and isinstance(art.get("failure"), dict) and art.get("sha256"):
                found.setdefault(str(art["sha256"]), art)
    return found


class _BreakerCrashContext:
    """What every crash of one breaker result is recorded with (`_ingest_breaker_crash`)."""

    def __init__(
        self,
        units: dict[str, dict],
        candidates: dict[str, dict],
        aid: str,
        mod: str,
        result_path: Path,
        campaign: dict[str, dict],
        findings: dict[str, dict] | None,
        reopen_outcomes: list[str],
    ) -> None:
        self.units = units
        self.candidates = candidates
        self.aid = aid
        self.mod = mod
        self.result_path = result_path
        self.campaign = campaign
        self.findings = findings
        self.reopen_outcomes = reopen_outcomes
        # Placed as cmd_ingest_fuzz places a campaign failure, so the same failure gets the same candidate.
        mm = ModuleMap.load(".")
        self.index = _dag_line_index(dag=mm.dag)
        self.kernel = _model_kernel_names()
        self.link_unit = str((mm.modules.get(mm.unit_of(mod)) or {}).get("unit") or mm.unit_of(mod))


def _ingest_breaker_crash(
    ctx: _BreakerCrashContext, crash_src: str, claimed: dict, *, note: str, assigned: bool
) -> int:
    """
    Record one crashing input of a breaker as an unverified candidate; 1 when a new candidate was created.

    `assigned` is the breaker's own `crash_found` (located in the assigned function, as before);
    otherwise an `other_function_crashes` entry. An entry whose input has a failure record in a campaign
    report of the breaker's scratch (`_breaker_campaign_failures`, matched by sha256) is placed exactly
    as `cmd_ingest_fuzz` places that record: the same fingerprint, the function its line lies in, the
    same site, so a failure Phase 1 already ledgered lands on its candidate. Without a record the
    breaker's own fields are used and the candidate is only proposed for validation. The input is
    promoted to workspace/crashes/<harness module>/ and listed as the reproducer: the scheduler replays
    it on that module's binary before a verifier's verdict is ingested, so the agent's claim is never a
    finding by itself. Deduplicated like a guardrail `code_fault`: the exact fingerprint first, then the
    candidate at the same statement site, then the same function and kind (`_find_matching_sink_candidate`).
    """
    crash_rel = rel(crash_src)
    record: dict | None = None
    if crash_rel.startswith(f"agents/{ctx.aid}/scratch/"):
        prom_crash = promote_file(Path.cwd(), ctx.aid, crash_rel, kind="crash", module=ctx.mod)
        crash_rel = str(prom_crash["dest"])
        record = ctx.campaign.get(str(prom_crash["sha256"]))
    failure = (record or {}).get("failure") or {}
    claimed_line = claimed.get("line") if isinstance(claimed.get("line"), int) else 0
    leak = False
    tool_backed = False
    if assigned:
        ffile, ffn = normalize_file(str(claimed["file"])), str(claimed["function"])
        source_fn = ffn
        pred = str(claimed["failing_predicate"])
        kind = goal_obligation_class({"kind": "assertion", "annotation": pred})
        cls = kind
        tool_fn = str(failure.get("function") or "").removeprefix("__gen_e_acsl_")
        tool_file = normalize_file(str(failure.get("file") or ""))
        same_place = bool(failure) and tool_fn == ffn and tool_file in ("unknown", ffile)
        line = int(failure.get("line") or 0) if same_place else claimed_line
        proposed = "confirmed"
        tool_backed = True
    elif failure:
        # The reported name stays in the fingerprint and the location, as cmd_ingest_fuzz keeps it.
        ffile = normalize_file(str(failure.get("file") or ""))
        ffn = str(failure.get("function") or "") or "unknown_function"
        pred = str(failure.get("predicate") or "")
        kind = str(failure.get("alarm_kind") or failure.get("kind") or "assertion")
        line = failure.get("line") if isinstance(failure.get("line"), int) else 0
        source_fn = _located_function(ffile, line, ffn, ctx.index, ctx.kernel, ctx.link_unit)
        cls = goal_obligation_class({"kind": failure.get("kind", ""), "annotation": pred})
        leak = failure.get("alarm_kind") == "memory_leak"
        proposed = "confirmed" if record and record.get("reproducible") else "needs_validation"
        tool_backed = True
    else:
        ffile = normalize_file(str(claimed.get("file") or ""))
        if not is_safe_relative_path(ffile):
            ffile = "unknown"
        ffn = str(claimed.get("function") or "") or "unknown_function"
        source_fn = ffn
        pred = str(claimed.get("failing_predicate") or "")
        kind = goal_obligation_class({"kind": "assertion", "annotation": pred})
        cls = kind
        line = claimed_line
        proposed = "needs_validation"
        note += "; location as the breaker reported it (no campaign record of this input in its scratch)"
    exact_fp = make_fingerprint(ffile, ffn, kind, pred)
    site = _candidate_site(ffile, line, source_fn, ctx.index)
    existing_cand = ctx.candidates.get(exact_fp) or _find_matching_sink_candidate(
        ctx.candidates, ffile, source_fn, kind, pred, site=site
    )
    fp = existing_cand["fingerprint"] if existing_cand is not None else exact_fp
    fn_units = [
        u
        for u in units_for_function(ctx.units, ffile, source_fn)
        if u["status"] not in ("out_of_scope", "not_applicable")
    ]
    # A leak has no obligation class (D5): it links no unit. Otherwise the class's units, else all of them.
    linked = (
        []
        if leak
        else [u["coverage_id"] for u in fn_units if u["obligation_class"] == cls]
        or [u["coverage_id"] for u in fn_units]
    )
    if not linked:
        note += f"; no ledger unit for {ffile}#{source_fn}::{cls}"
    tool_out = str(promote_file(Path.cwd(), ctx.aid, rel(str(ctx.result_path)), kind="artifact")["dest"])
    already_listed = existing_cand is not None and crash_rel in existing_cand["reproducers"]
    verified_before = existing_cand is not None and existing_cand.get("status") == "verified"
    keys_before = len(ctx.candidates)
    cand = upsert_candidate(
        ctx.candidates,
        fp,
        "breaker",
        proposed,
        ctx.mod,
        {"file": ffile, "line": line, "function": ffn},
        {"kind": normalize_kind(kind, pred), "predicate": pred},
        [crash_rel],
        tool_out,
        linked,
        note,
        site=site,
    )
    fp = cand["fingerprint"]
    evidence_kind = "breaker_crash_found" if assigned else "breaker_other_function_crash"
    for cid in linked:
        add_evidence(
            ctx.units[cid],
            "breaker",
            ctx.aid,
            evidence_kind,
            False,
            tool_out,
            f"Breaker reproduced failure on {pred[:120]}",
            {"artifact": crash_rel},
        )
        if existing_cand is None or existing_cand.get("status") == "unverified":
            mark_candidate(ctx.units[cid], fp)
    # Only a tool's report of the failure reopens a rejected candidate; a breaker's own words never do.
    if ctx.findings is not None and existing_cand is not None and verified_before and tool_backed:
        ctx.reopen_outcomes.append(
            tool_evidence_on_verified_candidate(
                ctx.units,
                ctx.findings,
                existing_cand,
                source="breaker_crash_found",
                phase="breaker",
                producer=ctx.aid,
                artifact=crash_rel,
                tool_output=tool_out,
                linked=linked,
                already_listed=already_listed,
            )
        )
    return 1 if len(ctx.candidates) > keys_before else 0


@ledger_locked
def cmd_ingest_agent_hypothesis(result_path: Path, module: str | None = None) -> dict:
    """
    Promote breaker seeds (if any), record prover strengthening_requests into
    contract_negotiator, and record a prover/breaker fault_hypothesis (or breaker
    crash_found artifact) as an unverified candidate in candidates.json.
    """
    res = load_agent_result_json(result_path)
    errs = validate_agent_result(res)
    if errs:
        raise LedgerError("invalid agent-result:\n  " + "\n  ".join(errs[:20]))

    role = res["role"]
    if role not in ("prover", "breaker"):
        raise LedgerError(f"ingest-agent-hypothesis expects prover or breaker result (got {role!r})")

    units, candidates = load_state()
    reopen = rejection_reopen_enabled()
    findings = {f["fingerprint"]: f for f in load_json_optional(FINDINGS, [])} if reopen else {}
    reopen_outcomes: list[str] = []
    aid = res["agent_id"]
    file = normalize_file(res["file"])
    fn = res["function"]
    # A harness module: seeds and crashes go to its corpus, the candidate is verified through it.
    mod = harness_module_for_function(
        ModuleMap.load("."), module or _infer_module_for_function(units, file, fn), file, fn
    )
    mod = mod or "unknown"

    seeds_promoted: list[dict] = []
    seeds_refused_hanging: list[dict] = []
    if role == "breaker" and res.get("seeds"):
        prom = promote_seeds(Path.cwd(), aid, mod, list(res["seeds"]))
        seeds_promoted = list(prom["promoted"])
        seeds_refused_hanging = list(prom["refused_hanging"])

    strengthening_requests_added = 0
    if role == "prover" and res.get("strengthening_requests"):
        neg_res = cmd_ingest_prover(
            Path("workspace/reports/strengthen_requests.json"),
            result_path,
        )
        strengthening_requests_added = int(neg_res.get("added_count", 0))

    candidates_added = 0
    fh = res.get("fault_hypothesis")
    pg = res.get("proof_gap")
    if pg is not None:
        cls = goal_obligation_class({"kind": "assertion", "annotation": pg["predicate"]})
        fn_units = [
            u for u in units_for_function(units, file, fn) if u["status"] not in ("out_of_scope", "not_applicable")
        ]
        linked = [u["coverage_id"] for u in fn_units if u["obligation_class"] == cls] or [
            u["coverage_id"] for u in fn_units
        ]
        if res.get("evidence"):
            tool_out = res["evidence"][0]["tool_output"]
        else:
            prom_res = promote_file(Path.cwd(), aid, rel(str(result_path)), kind="artifact")
            tool_out = str(prom_res["dest"])
        phase = "breaker" if role == "breaker" else "wp"
        gap_note = f"proof_gap: {pg['predicate']}: {pg['reason']}"
        # Counted per target in REPORT.md (prover brief, Step B: Inductive Lemmas): the input to the shared-lemma-library decision.
        gap_details = (
            {"gap_kind": INDUCTIVE_LEMMA_GAP}
            if str(pg["reason"]).lstrip().lower().startswith("inductive lemma required")
            else None
        )
        for cid in linked:
            u = units[cid]
            add_evidence(
                u,
                phase,
                aid,
                "proof_gap",
                False,
                tool_out,
                f"Proof gap on {pg['predicate'][:120]}: {pg['reason'][:140]}",
                gap_details,
            )
            u["status"] = "blocked"
            u["agent_id"] = None
            if gap_note not in u["unresolved"]:
                u["unresolved"] = sorted(set(u["unresolved"] + [gap_note]))

    if fh is not None:
        cls = goal_obligation_class({"kind": "assertion", "annotation": fh["predicate"]})
        # A breaker may name the line of its hypothesis (`line`): the candidate then has a statement site.
        fh_line = res.get("line") if role == "breaker" and isinstance(res.get("line"), int) else 0
        fh_site = _candidate_site(file, fh_line, fn, _dag_line_index()) if fh_line else None
        existing_cand = _find_matching_sink_candidate(candidates, file, fn, cls, fh["predicate"], site=fh_site)
        fp = (
            existing_cand["fingerprint"]
            if existing_cand is not None
            else make_fingerprint(file, fn, cls, fh["predicate"])
        )
        fn_units = [
            u for u in units_for_function(units, file, fn) if u["status"] not in ("out_of_scope", "not_applicable")
        ]
        linked = [u["coverage_id"] for u in fn_units if u["obligation_class"] == cls] or [
            u["coverage_id"] for u in fn_units
        ]
        if res.get("evidence"):
            tool_out = res["evidence"][0]["tool_output"]
        else:
            prom_res = promote_file(Path.cwd(), aid, rel(str(result_path)), kind="artifact")
            tool_out = str(prom_res["dest"])
        note = f"input_condition: {fh['input_condition']}; why_not_reproduced: {fh['why_not_reproduced']}"
        cand = upsert_candidate(
            candidates,
            fp,
            role,
            "needs_validation",
            mod,
            {"file": file, "line": fh_line, "function": fn},
            {"kind": cls, "predicate": fh["predicate"]},
            [],
            tool_out,
            linked,
            note,
            site=fh_site,
        )
        fp = cand["fingerprint"]
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
            if existing_cand is None or existing_cand.get("status") == "unverified":
                mark_candidate(units[cid], fp)
        if existing_cand is None:
            candidates_added += 1

    other_crashes_recorded = 0
    other_crashes_skipped: list[dict] = []
    if role == "breaker":
        campaign = _breaker_campaign_failures(aid)
        ctx = _BreakerCrashContext(
            units, candidates, aid, mod, result_path, campaign, findings if reopen else None, reopen_outcomes
        )
        if res.get("status") == "crash_found" and res.get("crash_artifact"):
            pred = str(res.get("failing_predicate") or (fh["predicate"] if fh else "") or "crash_found")
            candidates_added += _ingest_breaker_crash(
                ctx,
                str(res["crash_artifact"]),
                {"file": file, "function": fn, "line": res.get("line"), "failing_predicate": pred},
                note=str(res.get("analysis") or "breaker reproduced crash"),
                assigned=True,
            )
        main_crash = rel(str(res.get("crash_artifact") or ""))
        for idx, entry in enumerate(res.get("other_function_crashes") or []):
            src = rel(str(entry.get("crash_artifact") or ""))
            if not src or src == main_crash:
                continue
            try:
                candidates_added += _ingest_breaker_crash(
                    ctx,
                    src,
                    entry,
                    note=(
                        f"breaker {aid} (assigned {file}#{fn}): its campaign failed in another function; "
                        "the parent replays the input before any verdict"
                    ),
                    assigned=False,
                )
                other_crashes_recorded += 1
            except (PromotionError, ArtifactError, OSError, ValueError) as exc:
                # One unreadable entry must not cost the main crash, the seeds or the other entries.
                other_crashes_skipped.append({"index": idx, "crash_artifact": src, "reason": f"{exc}"[:300]})

    code_faults_recorded = 0
    if role == "prover":
        for report_rel in _prover_code_fault_reports(res, aid):
            added = _ingest_prover_code_fault(
                units, candidates, aid, mod, report_rel, findings if reopen else None, reopen_outcomes
            )
            code_faults_recorded += 1
            candidates_added += added

    commit(units, candidates, run_dir=Path.cwd())
    return {
        "agent_id": aid,
        "role": role,
        "seeds_promoted": seeds_promoted,
        **({"seeds_refused_hanging": seeds_refused_hanging} if seeds_refused_hanging else {}),
        "candidates_added": candidates_added,
        "strengthening_requests_added": strengthening_requests_added,
        "proof_gaps_recorded": 1 if pg is not None else 0,
        "code_faults_recorded": code_faults_recorded,
        **({"other_function_crashes_recorded": other_crashes_recorded} if other_crashes_recorded else {}),
        **({"other_function_crashes_skipped": other_crashes_skipped} if other_crashes_skipped else {}),
        **({"candidates_reopened": reopen_outcomes.count("reopened")} if "reopened" in reopen_outcomes else {}),
        **(
            {"rejections_contradicted": reopen_outcomes.count("contradicted")}
            if "contradicted" in reopen_outcomes
            else {}
        ),
    }


_MAX_GUARDRAIL_REPORT_BYTES = 8 * 1024 * 1024
_TEST_UNIT_WRITTEN_RE = re.compile(r"Test unit written to\s+(?P<path>\S+)")


def _read_scratch_json(aid: str, src_rel: str) -> Any:
    """Parse a JSON file under agents/<aid>/scratch/ (None when absent, unsafe, oversized or malformed)."""
    norm = src_rel.replace("\\", "/")
    if not is_safe_relative_path(norm) or not norm.startswith(f"agents/{aid}/scratch/"):
        return None
    p = Path(norm)
    try:
        if p.is_symlink() or not p.is_file() or p.stat().st_size > _MAX_GUARDRAIL_REPORT_BYTES:
            return None
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


def _prover_code_fault_reports(res: dict, aid: str) -> list[str]:
    """
    The guardrail reports a prover named in `evidence` whose status is `code_fault`: the dual-oracle
    guardrail reproduced an RTE failure in target code on a real input (prover_brief.md, Oracle 1).
    """
    found: list[str] = []
    for ev in res.get("evidence") or []:
        src = rel(str(ev.get("tool_output") or ""))
        if src in found or not src.endswith(".json"):
            continue
        report = _read_scratch_json(aid, src)
        if (
            isinstance(report, dict)
            and report.get("status") == "code_fault"
            and isinstance(report.get("failure"), dict)
        ):
            found.append(src)
    return found


def _guardrail_crash_input(report: dict, aid: str) -> str | None:
    """Run-relative crashing input libFuzzer wrote under agents/<aid>/scratch/ (from `runtime_trace`)."""
    marker = f"agents/{aid}/scratch/"
    # The guardrail names the input itself; the truncated trace is the fallback for older reports.
    explicit = str(report.get("crash_input") or "").replace("\\", "/")
    if explicit.startswith(marker) and is_safe_relative_path(explicit):
        p = Path(explicit)
        if p.is_file() and not p.is_symlink():
            return explicit
    for m in _TEST_UNIT_WRITTEN_RE.finditer(str(report.get("runtime_trace") or "")):
        path = m.group("path").replace("\\", "/")
        idx = path.find(marker)
        if idx < 0:
            continue
        cand = path[idx:]
        if is_safe_relative_path(cand) and Path(cand).is_file() and not Path(cand).is_symlink():
            return cand
    return None


def _ingest_prover_code_fault(
    units: dict[str, dict],
    candidates: dict[str, dict],
    aid: str,
    mod: str,
    report_rel: str,
    findings: dict[str, dict] | None = None,
    reopen_outcomes: list[str] | None = None,
) -> int:
    """
    Turn a prover's guardrail `code_fault` into a candidate (remediation plan H8), mirroring the breaker
    `crash_found` branch: the guardrail report is promoted and recorded as the tool output, the crashing
    input (when libFuzzer wrote one under the agent's scratch) is promoted as a crash reproducer, and the
    function's units of the failing obligation class are linked and marked `candidate`. Returns 1 when a
    new candidate was created. With `findings` (FRAMAC_REJECTION_REOPEN on), a crash input on a rejected
    candidate reopens it or is recorded as contradicting evidence (tool_evidence_on_verified_candidate).
    """
    src = Path(report_rel)
    prom_report = promote_file(
        Path.cwd(), aid, report_rel, kind="artifact", dest_name=f"code_fault_{src.parent.name}_{src.name}"
    )
    tool_out = str(prom_report["dest"])
    report = load_json_strict(Path(tool_out))
    failure = report["failure"]
    ffile = normalize_file(str(failure.get("file") or ""))
    ffn = str(failure.get("function") or "")
    if ffn.startswith("__gen_e_acsl_"):
        ffn = ffn[len("__gen_e_acsl_") :]
    kind = str(failure.get("alarm_kind") or failure.get("kind") or "assertion")
    pred = str(failure.get("predicate") or "")
    exact_fp = make_fingerprint(ffile, ffn, kind, pred)
    line = int(failure.get("line") or 0)
    site = _candidate_site(ffile, line, ffn or "unknown_function", _dag_line_index())
    existing_cand = candidates.get(exact_fp) or _find_matching_sink_candidate(
        candidates, ffile, ffn, kind, pred, site=site
    )
    fp = existing_cand["fingerprint"] if existing_cand is not None else exact_fp
    cls = goal_obligation_class({"kind": failure.get("kind", ""), "annotation": pred})
    fn_units = [
        u for u in units_for_function(units, ffile, ffn) if u["status"] not in ("out_of_scope", "not_applicable")
    ]
    linked = [u["coverage_id"] for u in fn_units if u["obligation_class"] == cls] or [
        u["coverage_id"] for u in fn_units
    ]
    crash_rel: str | None = None
    crash_src = _guardrail_crash_input(report, aid)
    if crash_src is not None:
        crash_rel = str(promote_file(Path.cwd(), aid, crash_src, kind="crash", module=mod)["dest"])
    proposed = "confirmed" if crash_rel else "needs_validation"
    note = "prover dual-oracle guardrail reproduced an RTE failure on a real input (code_fault)"
    if crash_rel is None:
        note += "; the crashing input was not found under the agent scratch, verifier must reproduce"
    if not linked:
        note += f"; no ledger unit for {ffile}#{ffn}::{cls} (harness or unseeded code)"
    already_listed = existing_cand is not None and crash_rel is not None and crash_rel in existing_cand["reproducers"]
    verified_before = existing_cand is not None and existing_cand.get("status") == "verified"
    keys_before = len(candidates)
    cand = upsert_candidate(
        candidates,
        fp,
        "prover",
        proposed,
        mod,
        {"file": ffile or "unknown", "line": line, "function": ffn or "unknown_function"},
        {"kind": kind, "predicate": pred},
        [crash_rel] if crash_rel else [],
        tool_out,
        linked,
        note,
        site=site,
    )
    fp = cand["fingerprint"]
    created = len(candidates) > keys_before
    for cid in linked:
        add_evidence(
            units[cid],
            "wp",
            aid,
            "guardrail_code_fault",
            False,
            tool_out,
            f"Guardrail code_fault {kind} at line {failure.get('line')}: {pred[:120]}",
            {"artifact": crash_rel} if crash_rel else None,
        )
        if existing_cand is None or existing_cand.get("status") == "unverified":
            mark_candidate(units[cid], fp)
    if findings is not None and existing_cand is not None and verified_before and crash_rel is not None:
        outcome = tool_evidence_on_verified_candidate(
            units,
            findings,
            existing_cand,
            source="guardrail_code_fault",
            phase="wp",
            producer=aid,
            artifact=crash_rel,
            tool_output=tool_out,
            linked=linked,
            already_listed=already_listed,
        )
        if reopen_outcomes is not None:
            reopen_outcomes.append(outcome)
    return 1 if created else 0


@ledger_locked
def cmd_record_boundary_assumptions(result_path: Path) -> dict:
    """
    Record an agent's `boundary_assumptions` (remediation plan H8) as `boundary_assumption` entries on
    the units its work credits: every unit that is not deferred / out_of_scope / not_applicable of the
    prover's function, or of each function an architect lists in `functions` (an architect result
    without that list records nothing and says so). Idempotent: an assumption already on a unit is
    not added again.
    """
    res = load_agent_result_json(result_path)
    errs = validate_agent_result(res)
    if errs:
        raise LedgerError("invalid agent-result:\n  " + "\n  ".join(errs[:20]))
    role = res["role"]
    if role not in ("prover", "architect"):
        raise LedgerError(f"record-boundary-assumptions expects a prover or architect result (got {role!r})")
    descriptions: list[str] = []
    for text in res.get("boundary_assumptions") or []:
        d = str(text).strip()
        if d and d not in descriptions:
            descriptions.append(d)
    out: dict[str, Any] = {"agent_id": res["agent_id"], "role": role, "assumptions": len(descriptions)}
    if role == "architect":
        functions = [(str(f["file"]), str(f["function"])) for f in res.get("functions") or []]
    else:
        functions = [(str(res["file"]), str(res["function"]))]
    if not functions:
        out.update(
            {
                "units": [],
                "added": 0,
                "skipped_reason": "architect result does not name the functions it contracted",
            }
        )
        return out
    units, candidates = load_state()
    targets = [
        u
        for file, function in functions
        for u in units_for_function(units, file, function)
        if u["status"] not in NO_TOUCH
    ]
    added = 0
    for u in targets:
        for d in descriptions:
            if any(a["kind"] == "boundary_assumption" and a["description"] == d for a in u["assumptions"]):
                continue
            add_assumption(u, "boundary_assumption", d)
            added += 1
    if added:
        commit(units, candidates, run_dir=Path.cwd())
    out.update({"units": sorted(u["coverage_id"] for u in targets), "added": added})
    if descriptions and not targets:
        names = ", ".join(f"{file}#{function}" for file, function in functions)
        out["skipped_reason"] = f"no schedulable ledger unit for {names}"
    return out


STUB_ASSUMPTION_PREFIX = "Overlay stub contract of "
STUB_ACTIVE_STATES = ("incomplete", "filled", "manual")


def stub_check_status(check: dict | None, header: str, digest: str | None, fn: str) -> str | None:
    """
    What scripts/stub_check.py found for `fn` of `header` at this `digest` (None when it was not checked, or
    checked at another digest): the dynamic check's status, else Eva's, else the header's.
    """
    rec = ((check or {}).get("headers") or {}).get(header)
    if not isinstance(rec, dict) or not digest or rec.get("digest") != digest:
        return None
    for kind in ("dynamic", "eva"):
        f = ((rec.get(kind) or {}).get("functions") or {}).get(fn)
        if isinstance(f, dict) and f.get("status"):
            return f"{kind} {f['status']}" + ("" if rec.get("status") != "failed" else ", header failed")
    status = rec.get("status")
    return str(status) if status else None


def stub_contract_descriptions(report: dict, check: dict | None = None) -> dict[tuple[str, str], list[str]]:
    """
    (caller file, caller function) -> the `stub_contract` descriptions of the overlay contracts it calls
    (scripts/stub_gen.py's report): one per active contract (filled, incomplete, manual), naming the header
    and its digest, so a report can say what a proof rests on, and, from `check` (stub_check.py's report),
    what the stub-check of that same header content found.
    """
    out: dict[tuple[str, str], list[str]] = {}
    for header, rec in sorted((report.get("headers") or {}).items()):
        if not isinstance(rec, dict):
            continue
        full_digest = rec.get("digest")
        digest = str(full_digest or "")[:12]
        for fn, f in sorted((rec.get("functions") or {}).items()):
            state = f.get("state")
            if state not in STUB_ACTIVE_STATES:
                continue
            check_status = stub_check_status(check, header, full_digest, fn)
            text = (
                f"{STUB_ASSUMPTION_PREFIX}{fn} in {header} (sha256 {digest}, {state}) is assumed, not proven"
                + (f"; stub-check: {check_status}" if check_status else "")
                + "."
            )
            for caller in f.get("callers") or []:
                file, _, name = str(caller).rpartition("#")
                if file and name:
                    out.setdefault((file, name), []).append(text)
    return out


def _apply_stub_contracts(units: dict[str, dict], report_path: Path, check_path: Path | None) -> dict:
    """
    Make the `stub_contract` assumptions of `units` match the stub report at `report_path` (and the
    stub-check statuses at `check_path`), in memory; the caller commits when `units_changed` is not 0.
    """
    report = load_json_optional(report_path, None)
    if not isinstance(report, dict):
        return {
            "recorded": 0,
            "units_changed": 0,
            "skipped_reason": f"no stub report at {report_path}: run `stubs` first",
        }
    check = load_json_optional(check_path, None) if check_path is not None else None
    wanted = stub_contract_descriptions(report, check if isinstance(check, dict) else None)
    changed = 0
    recorded = 0
    for u in units.values():
        kept = [
            a
            for a in u["assumptions"]
            if not (
                a.get("kind") == "stub_contract" and str(a.get("description") or "").startswith(STUB_ASSUMPTION_PREFIX)
            )
        ]
        new = list(kept)
        if u["status"] not in NO_TOUCH:
            for text in wanted.get((u["file"], u["function"]), []):
                a = {"kind": "stub_contract", "description": text, "related_units": []}
                if a not in new:
                    new.append(a)
                    recorded += 1
        if new != u["assumptions"]:
            u["assumptions"] = new
            changed += 1
    return {"recorded": recorded, "units_changed": changed, "callers": len(wanted)}


@ledger_locked
def cmd_record_stub_contracts(report_path: Path, check_path: Path | None = None) -> dict:
    """
    Record the run's stub overlay contracts (`stub_gen.py run`) as `stub_contract` assumptions on the
    units of the functions that call them. Replaces the overlay assumptions recorded before, so an
    edited header (a new digest) or a contract back in draft never leaves a stale one, and running it
    again changes nothing. No ledger yet: nothing to do, `seed` records them when it creates the units.
    """
    if not Path(LEDGER).is_file():
        return {"recorded": 0, "skipped_reason": "no ledger yet: `ledger.py seed` records the stub contracts"}
    units, candidates = load_state()
    out = _apply_stub_contracts(units, report_path, check_path)
    if out["units_changed"]:
        commit(units, candidates, run_dir=Path.cwd())
    return out


def _collect_reproducible_artifacts(
    run_dir: Path, report_paths: list[Path], tool_outputs: list[str]
) -> dict[str, list[tuple[str, dict]]]:
    """
    sha256 -> (report, artifact record) of every input a parent report (the replay reports, then the
    candidate's tool outputs) replayed and saw fail. The record says what the replay failed on.
    """
    found: dict[str, list[tuple[str, dict]]] = {}
    all_paths = list(report_paths) + [run_dir / t for t in tool_outputs]
    seen_paths: set[Path] = set()
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
                    found.setdefault(str(art["sha256"]), []).append((rel(str(rp)), art))
    return found


# ------------------------------------------- what the parent's replay of a reproducer failed on
#
# A `confirmed` reproducer counts only when the parent's replay of it failed on the defect the record is
# about, not on any failure. Fingerprints differ per engine by design (D1), so the comparison is the one
# candidates are grouped by: the candidate's key, an observation's fingerprint, the candidate's statement
# site, the same of a `related` candidate (D1b), or the record's own fingerprint and site (only for a
# record the verifier refingerprinted; an additional record has nothing else). Where one side has no
# statement (a hypothesis without a line, a failure a runtime reports without one), function and kind
# stand for it, as hypotheses merge (D1c).
UNLOCATED_FUNCTION = "unknown_function"
# How the evidence entry of a counted reproducer whose failure could not be compared starts (ingest-verifier);
# generate_report.py finds such findings by it.
IDENTITY_NOT_COMPARED = "Failure identity not compared:"


class _FailurePlacer:
    """
    Places a failure's line for comparison with a candidate's site. The DAG's extents and the sites
    recorded in Phases 1 and 2 are in baseline lines. A report replayed after annotations were merged
    names lines of the work tree; one replayed before names baseline lines, and says nothing of which.
    `sites` therefore reads a line each way it can have been meant: at most three keys, one of them the
    site `ingest-fuzz` would record for the line now.
    """

    def __init__(self, mm: ModuleMap, module: str, run_dir: Path) -> None:
        self.index = _dag_line_index(dag=mm.dag)
        self.kernel = _model_kernel_names()
        self.link_unit = str((mm.modules.get(mm.unit_of(module)) or {}).get("unit") or mm.unit_of(module))
        self.run_dir = run_dir
        self._readings: dict[tuple[str, int], list[tuple[str, int]]] = {}

    def readings(self, file: str, line: object) -> list[tuple[str, int]]:
        """(source path, line) for each reading of `file`:`line`; none for a line that is not positive."""
        if not isinstance(line, int) or line <= 0 or file in ("", "unknown"):
            return []
        if (file, line) not in self._readings:
            from workspace_overlay import map_work_to_baseline_line

            baseline = f"workspace/baseline/{file}"
            mapped = map_work_to_baseline_line(file, line, run_dir=self.run_dir)[0]
            # As ingest-fuzz reads it; a work-tree line mapped back to the baseline; a baseline line.
            self._readings[(file, line)] = list(dict.fromkeys([(file, line), (baseline, mapped), (baseline, line)]))
        return self._readings[(file, line)]

    def functions(self, file: str, line: object, reported: str) -> set[str]:
        """The names the function of a failure can go by: the reported one and the DAG's for each reading."""
        names = {
            _located_function(file, at, reported, self.index, self.kernel, self.link_unit)
            for _, at in self.readings(file, line)
        }
        return {n for n in (reported, *names) if n and n != UNLOCATED_FUNCTION}

    def sites(self, file: str, line: object, reported: str) -> set[str]:
        """The statement site of `file`:`line` under each reading (failure_identity.site_key)."""
        found: set[str] = set()
        for path, at in self.readings(file, line):
            function = _located_function(file, at, reported, self.index, self.kernel, self.link_unit)
            site = _candidate_site(path, at, function or UNLOCATED_FUNCTION, self.index)
            if site:
                found.add(site)
        return found


def _candidate_input_shas(run_dir: Path, cand: dict, replayed: dict[str, list[tuple[str, dict]]]) -> set[str]:
    """sha256 of the inputs recorded on the candidate before its verdict (its `reproducers`)."""
    own: set[str] = set()
    for raw in cand.get("reproducers") or []:
        path = raw.get("input") if isinstance(raw, dict) else raw
        if isinstance(path, str) and path:
            own.add(rel(path))
    shas: set[str] = set()
    for path in own:
        try:
            shas.add(hashlib.sha256((run_dir / path).read_bytes()).hexdigest())
        except OSError:
            continue
    for sha, arts in replayed.items():
        if any(rel(str(art.get("artifact") or "")) in own for _, art in arts):
            shas.add(sha)
    return shas


def _accepted_failures(
    cand: dict, candidates: dict[str, dict], rec: dict, placer: _FailurePlacer, split_off: bool = False
) -> dict:
    """
    The failures that are the defect of `rec`, a verdict record on `cand`: `fingerprints`, statement
    `sites` and recorded `lines` (file, line), each mapped to whose it is; the `sink` (file, function,
    kind) that stands for a missing statement, and whether there is one to compare with (`has_statement`).

    The record is the verifier's, so its own fingerprint and location count only where it says it
    names another failure than the candidate's key (a refingerprinted record, which needs a reason): a
    record that keeps the key cannot move the statement to where its input failed. A `split_off`
    record (an additional record) is another defect: only its own fingerprint and location count.
    """
    fingerprints: dict[str, str] = {}
    sites: dict[str, str] = {}
    lines: dict[tuple[str, int], str] = {}

    def place(loc: dict, stored: object, whose: str) -> bool:
        file, line = normalize_file(str(loc.get("file") or "")), loc.get("line")
        found = (
            {stored} if isinstance(stored, str) and stored else placer.sites(file, line, str(loc.get("function") or ""))
        )
        for site in sorted(found):
            sites.setdefault(site, whose)
        if isinstance(line, int) and line > 0 and file != "unknown":
            lines.setdefault((file, line), whose)
            return True
        return bool(found)

    def add(other: dict, whose: str) -> bool:
        fingerprints.setdefault(str(other.get("fingerprint") or ""), whose)
        for obs in other.get("observations") or []:
            if isinstance(obs, dict) and obs.get("fingerprint"):
                fingerprints.setdefault(str(obs["fingerprint"]), f"an observation of {whose}")
        return place(other.get("location") or {}, other.get("site"), whose)

    has_statement = False
    if not split_off:
        has_statement = add(cand, "the candidate")
        for link in cand.get("related") or []:
            other = candidates.get(str(link.get("fingerprint") or "")) if isinstance(link, dict) else None
            if other is not None and other is not cand:
                add(other, f"related candidate {other['fingerprint']}")
    if split_off or rec.get("fingerprint") != cand.get("fingerprint"):
        fingerprints.setdefault(str(rec.get("fingerprint") or ""), "the record")
        placed = place(rec.get("location") or {}, None, "the record")
        has_statement = placed if split_off else has_statement
    fingerprints.pop("", None)

    sink: tuple[str, str, str] | None = None
    named = rec if split_off else cand
    loc, prop = named.get("location") or {}, named.get("property") or {}
    function = str(loc.get("function") or "")
    if function not in ("", UNLOCATED_FUNCTION):
        sink = (
            normalize_file(str(loc.get("file") or "")),
            function,
            normalize_kind(str(prop.get("kind") or ""), str(prop.get("predicate") or "")),
        )
    return {
        "fingerprints": fingerprints,
        "sites": sites,
        "lines": lines,
        "sink": sink,
        "sink_of": "the record" if split_off else "the candidate",
        "has_statement": has_statement,
    }


def _replayed_failure(art: dict, placer: _FailurePlacer) -> dict:
    """
    What a replayed artifact failed on. `statement` is False when the report gives no file and line to
    compare with a candidate's: no failure was parsed (a crash without a report, a timeout, a runtime
    resource abort), the failure has no source line (a runtime's libc check, an `unknown_function`
    one), or an older report kept only the fingerprint. `what` says which.
    """
    raw = art.get("failure")
    failure: dict = raw if isinstance(raw, dict) else {}
    fingerprint = str(art.get("fingerprint") or "")
    file = normalize_file(str(failure.get("file") or "")) if failure else "unknown"
    reported = str(failure.get("function") or "")
    kind = str(failure.get("alarm_kind") or failure.get("kind") or "")
    if not failure and "#" in fingerprint:
        # An older report: the fingerprint is all it says (`<file>#<function>::<kind>::<hash>`).
        file, _, tail = fingerprint.partition("#")
        reported, kind = (tail.split("::") + [""])[:2]
    raw_line = failure.get("line")
    line: int = raw_line if isinstance(raw_line, int) else 0
    if art.get("timed_out"):
        what = "the replay timed out"
    elif isinstance(art.get("eacsl_resource_abort"), dict):
        what = "the E-ACSL runtime stopped on its own resource limit"
    elif not failure and not fingerprint:
        what = f"no failure report could be parsed from its output (return code {art.get('returncode')})"
    else:
        what = f"the failure it reports ({fingerprint or kind or 'no fingerprint'}) has no source line"
    return {
        "fingerprint": fingerprint,
        "file": file,
        "line": line,
        "function": reported,
        "functions": placer.functions(file, line, reported),
        "kind": normalize_kind(kind, str(failure.get("predicate") or "")) if kind else "",
        "predicate": str(failure.get("predicate") or ""),
        "sites": placer.sites(file, line, reported),
        "statement": file != "unknown" and line > 0,
        "what": what,
    }


def _failure_match(seen: dict, accepted: dict) -> str | None:
    """Why the failure a replay hit is the record's defect (`_accepted_failures`), or None."""
    whose = accepted["fingerprints"].get(seen["fingerprint"])
    if whose:
        return f"the fingerprint of {whose}"
    for site in sorted(seen["sites"]):
        if site in accepted["sites"]:
            return f"the statement site of {accepted['sites'][site]}"
    if seen["statement"] and not seen["sites"]:
        # The line could not be read (no source under the run directory): the recorded line stands for the site.
        whose = accepted["lines"].get((seen["file"], seen["line"]))
        if whose:
            return f"the recorded line of {whose}"
    sink = accepted["sink"]
    if sink is not None and not (accepted["has_statement"] and seen["statement"]):
        same_file = seen["file"] == sink[0] or "unknown" in (seen["file"], sink[0])
        # A hypothesis may leave its kind open (`rte`); a replay that does is not shown to be of the sink's kind.
        same_kind = seen["kind"] == sink[2] or sink[2] in SINK_KIND_WILDCARDS
        if same_file and same_kind and sink[1] in seen["functions"]:
            return f"the function and kind of {accepted['sink_of']} (one of the two has no statement to compare)"
    return None


def _judge_reproducer(arts: list[tuple[str, dict]], accepted: dict, placer: _FailurePlacer) -> tuple[str, dict]:
    """
    How the parent's replays of one input compare with the record's defect: `match` when one of them
    failed on it, else `mismatch` when one failed at another statement (the input shows another
    defect), else `uncompared`: no replay of it names a statement. With it, the replay that decided.
    """
    other: dict | None = None
    blind: dict | None = None
    for report, art in arts:
        seen = {**_replayed_failure(art, placer), "report": report}
        basis = _failure_match(seen, accepted)
        if basis is not None:
            return "match", {**seen, "basis": basis}
        if seen["statement"]:
            other = other or seen
        else:
            blind = blind or seen
    if other is not None:
        return "mismatch", other
    return "uncompared", blind or {}


def _failure_text(fingerprint: str, loc: dict, prop: dict) -> str:
    """`<fingerprint> at <file>:<line> in <function> (<kind>: <predicate>)`, for a refusal message."""
    kind, predicate = str(prop.get("kind") or ""), " ".join(str(prop.get("predicate") or "").split())[:160]
    return (
        f"{fingerprint or 'a failure without a fingerprint'} at {loc.get('file') or 'unknown'}:{loc.get('line') or 0}"
        f" in {loc.get('function') or UNLOCATED_FUNCTION}"
        + (f" ({': '.join(x for x in (kind, predicate) if x)})" if kind or predicate else "")
    )


def _other_failure_refusal(
    fp: str, sha: str, cand: dict, rec: dict, seen: dict, candidates: dict[str, dict], split_off: bool = False
) -> str:
    """The refusal of a reproducer whose replay failed on another failure: it names both, and whose the other is."""
    own = _failure_text(fp, rec.get("location") or {}, rec.get("property") or {})
    if split_off:
        wanted = f"this additional record's own failure: {own}"
        rule = "An additional record counts only reproducers whose parent replay fails on its own failure."
    else:
        wanted = "the candidate's failure: " + _failure_text(
            str(cand.get("fingerprint") or ""), cand.get("location") or {}, cand.get("property") or {}
        )
        if fp != cand.get("fingerprint"):
            wanted += f"; the record's: {own}"
        rule = (
            "List only reproducers whose parent replay fails on the candidate's failure, at its statement, or on a "
            "failure recorded as its observation or as a related candidate."
        )
    hit = _failure_text(
        seen["fingerprint"],
        {"file": seen["file"], "line": seen["line"], "function": seen["function"]},
        {"kind": seen["kind"], "predicate": seen["predicate"]},
    )
    owner = next(
        (
            key
            for key, other in candidates.items()
            if seen["fingerprint"]
            and (
                key == seen["fingerprint"]
                or any(o.get("fingerprint") == seen["fingerprint"] for o in other.get("observations") or [])
            )
        ),
        None,
    )
    if owner is not None:
        whose = f"That failure is candidate {owner} ({candidates[owner].get('status')}), which gets its own verdict."
    else:
        whose = (
            "No candidate records that failure: if it is a defect, return it as its own record (additional_records, "
            "its own fingerprint, the file and line the replay names, this reproducer, refingerprint_reason)."
        )
    return (
        f"confirmed finding {fp}: the parent's replay of reproducer sha256 {sha} failed, but on another failure "
        f"than this record's. Expected {wanted}. The replay hit: {hit} (report {seen['report']}). {whose} {rule}"
    )


# A generic kind matches any kind at the same sink line (a prover's `rte` goal and a fuzz `mem_access`).
SINK_KIND_WILDCARDS = ("rte", "assertion", "property")
SinkKey = tuple[str, str, int, str]


def _sink_key(rec: dict, run_dir: Path | None = None) -> SinkKey | None:
    """
    The canonical sink of a verdict record: `(normalized_file, function, baseline_line, normalized_kind)`,
    or None when the record has no usable location. The decision point plays no part (a rejected
    record has none).
    """
    loc = rec.get("location") or {}
    rec_file = normalize_file(loc.get("file") or "")
    rec_fn = loc.get("function") or ""
    rec_line = int(loc.get("line") or 0)
    if not rec_file or not rec_fn or rec_line <= 0:
        return None
    from workspace_overlay import map_work_to_baseline_line

    base_line, _ = map_work_to_baseline_line(rec_file, rec_line, run_dir=run_dir)
    prop = rec.get("property") or {}
    return rec_file, rec_fn, base_line, normalize_kind(prop.get("kind") or "", prop.get("predicate") or "")


def _same_sink(a: SinkKey, b: SinkKey) -> bool:
    return a[:3] == b[:3] and (a[3] == b[3] or a[3] in SINK_KIND_WILDCARDS or b[3] in SINK_KIND_WILDCARDS)


def _find_matching_sink_finding(
    findings: dict[str, dict],
    rec: dict,
    run_dir: Path | None = None,
) -> dict | None:
    """
    Find an already-recorded finding with the same verdict and the same canonical sink (_sink_key)
    so two different fingerprints for the same root cause (e.g. a prover hypothesis predicate and a
    fuzz crash predicate at the same line) merge into a single finding instead of inflating the
    report count.
    """
    key = _sink_key(rec, run_dir)
    if key is None:
        return None
    for existing in findings.values():
        if existing.get("verdict") != rec.get("verdict"):
            continue
        ekey = _sink_key(existing, run_dir)
        if ekey is not None and _same_sink(key, ekey):
            return existing
    return None


SIBLING_VERDICT_SOURCE = "sibling_verdict"


def _verdict_family(rec: dict) -> str | None:
    """`positive` (confirmed, needs_validation), `negative` (rejected, but not as a duplicate) or None."""
    if rec.get("verdict") in ("confirmed", "needs_validation"):
        return "positive"
    if rec.get("verdict") == "rejected" and rec.get("rejection_class") != "duplicate":
        return "negative"
    return None


def sink_conflicts(findings: dict[str, dict], run_dir: Path | None = None) -> list[tuple[str, str]]:
    """Pairs `(positive, negative)` of verdict records at the same sink with opposite verdicts, sorted."""
    keyed: dict[str, list[tuple[str, SinkKey]]] = {"positive": [], "negative": []}
    for fp, rec in sorted(findings.items()):
        family = _verdict_family(rec)
        key = _sink_key(rec, run_dir) if family else None
        if family and key is not None:
            keyed[family].append((fp, key))
    return [(pos, neg) for pos, pkey in keyed["positive"] for neg, nkey in keyed["negative"] if _same_sink(pkey, nkey)]


def _refresh_conflicts_with(findings: dict[str, dict], pairs: list[tuple[str, str]]) -> None:
    """Rewrite `conflicts_with` of every record from the current pairs (a superseded or merged record drops out)."""
    partners: dict[str, set[str]] = {}
    for pos, neg in pairs:
        partners.setdefault(pos, set()).add(neg)
        partners.setdefault(neg, set()).add(pos)
    for fp, rec in findings.items():
        if fp in partners:
            rec["conflicts_with"] = sorted(partners[fp])
        else:
            rec.pop("conflicts_with", None)


def _sibling_evidence(rec: dict) -> tuple[str, str]:
    """What a re-verification is handed from the positive sibling: (artifact, tool_output)."""
    tool_output = rec["evidence"][0]["tool_output"] if rec.get("evidence") else FINDINGS.as_posix()
    reproducers = rec.get("reproducers") or []
    artifact = reproducers[0]["input"] if reproducers else tool_output
    return artifact, tool_output


def _reconcile_sink_conflicts(
    units: dict[str, dict],
    candidates: dict[str, dict],
    findings: dict[str, dict],
    run_dir: Path,
    ingested: list[str],
) -> list[dict]:
    """
    Record opposite verdicts at one sink on both records (`conflicts_with`) and give the rejected
    candidate of each pair that involves a record of this ingest one re-verification: it is reopened
    through tool_evidence_on_verified_candidate with the `sibling_verdict` source, which skips the
    `harness_unchanged` suppression and keeps the reopening limit. A `checked` rejection is kept
    against a `needs_validation` sibling and re-verified against a `confirmed` one (a reproduced
    crash and a cited refutation at one sink cannot both hold; QCBOR run-6, EncodeHead). A candidate
    already reopened by a sibling verdict is not reopened again (`already_reverified`), so a second
    rejection leaves the pair flagged for the report. Nothing picks a side.
    """
    pairs = sink_conflicts(findings, run_dir)
    _refresh_conflicts_with(findings, pairs)
    out: list[dict] = []
    for pos, neg in pairs:
        if pos not in ingested and neg not in ingested:
            continue
        entry: dict[str, Any] = {"positive": pos, "negative": neg}
        cands = [
            c
            for _, c in sorted(candidates.items())
            if c.get("status") == "verified" and neg in (c.get("resolved_fingerprints") or [c["fingerprint"]])
        ]
        cand = next((c for c in cands if c["fingerprint"] == neg), cands[0] if cands else None)
        if cand is None:
            entry["outcome"] = "awaiting_verdict"
        elif not rejection_reopen_enabled():
            entry["outcome"] = "not_reopened"
        elif any((r.get("evidence") or {}).get("source") == SIBLING_VERDICT_SOURCE for r in cand.get("reopened") or []):
            entry["outcome"] = "already_reverified"
        else:
            artifact, tool_output = _sibling_evidence(findings[pos])
            entry["outcome"] = tool_evidence_on_verified_candidate(
                units,
                findings,
                cand,
                source=SIBLING_VERDICT_SOURCE,
                phase="verifier",
                producer="ledger.py",
                artifact=artifact,
                tool_output=tool_output,
                linked=[],
                already_listed=False,
                override_checked=findings[pos].get("verdict") == "confirmed",
            )
            if entry["outcome"] == "contradicted":
                entry["reason"] = next(
                    e["reason"]
                    for e in reversed(cand["contradicting_evidence"])
                    if (e["source"], e["artifact"]) == (SIBLING_VERDICT_SOURCE, artifact)
                )
        out.append(entry)
    return out


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


EVA_REPORT_DIR = Path("workspace/reports/eva")
COVERAGE_REPORT_DIR = Path("workspace/reports/coverage")


def _row_line(row: dict) -> int:
    try:
        return int(row.get("line") or 0)
    except (TypeError, ValueError):
        return 0


def _dead_code_on_disk(run_dir: Path, module: str, location: dict) -> dict | None:
    """
    Tool output already on disk that agrees with a `dead_code` rejection at `location`, or None.

    - Eva: the module's report completed and lists a Dead property at the file and line, and no Invalid,
      Unknown or inconsistent property there.
    - Phase 1 coverage: the module's coverage report is complete (`status: ok`) and the function was
      never executed.

    Both say "not reached under this module's harness", which is what the verifier claims. A missing,
    unreadable or incomplete report agrees with nothing.
    """
    loc_file = normalize_file(str(location.get("file") or ""))
    loc_fn = str(location.get("function") or "")
    loc_line = _row_line(location)
    if not loc_file or loc_line < 1:
        return None

    def load(path: Path, max_bytes: int = DEFAULT_JSON_MAX_BYTES) -> dict:
        try:
            data = load_json_optional(run_dir / path, {}, max_bytes=max_bytes)
        except ArtifactError:
            return {}
        return data if isinstance(data, dict) else {}

    def here(row: object) -> bool:
        return (
            isinstance(row, dict)
            and bool(row.get("file"))
            and eva_alarm_in_file(row, loc_file)
            and _row_line(row) == loc_line
        )

    eva_path = EVA_REPORT_DIR / f"{module}.json"
    eva = load(eva_path, max_bytes=EVA_REPORT_MAX_BYTES)
    if eva.get("status") == "ok":
        dead = eva.get("dead_alarms")
        unknown = eva.get("unknown_obligations_by_function")
        live: list = [
            *(eva.get("invalid_alarms") or []),
            *(eva.get("other_properties") or []),
            *(row for rows in (unknown.values() if isinstance(unknown, dict) else []) for row in rows or []),
        ]
        if any(here(r) for r in (dead if isinstance(dead, list) else [])) and not any(here(r) for r in live):
            return {
                "source": "eva_dead",
                "phase": "eva",
                "tool_output": eva_path.as_posix(),
                "description": f"Eva reports the properties at {loc_file}:{loc_line} Dead under the module harness.",
            }

    cov_path = COVERAGE_REPORT_DIR / f"{module}.json"
    cov = load(cov_path)
    if cov.get("status") == "ok" and loc_fn:
        rows = [
            f
            for f in cov.get("functions") or []
            if isinstance(f, dict)
            and f.get("function") == loc_fn
            and normalize_file(str(f.get("file") or "")) == loc_file
        ]
        if rows and all(f.get("executions") == 0 for f in rows):
            return {
                "source": "fuzz_coverage",
                "phase": "fuzz",
                "tool_output": cov_path.as_posix(),
                "description": f"Phase 1 coverage: no corpus input executed {loc_fn} ({loc_file}).",
            }
    return None


def _open_reopening(cand: dict) -> dict | None:
    """The `reopened` entry of a candidate that awaits its next verdict, else None."""
    entries = cand.get("reopened") or []
    if cand.get("status") != "unverified" or not entries or "resolved" in entries[-1]:
        return None
    return entries[-1]


def _prior_verdict(old: dict, reopening: dict) -> dict:
    """What stays in findings.json of a rejected record superseded after its candidate was reopened."""
    prior = {k: old[k] for k in ("verdict", "fingerprint", "rejection_class", "reason", "evidence", "verifier")}
    if old.get("refutation_basis"):
        prior["refutation_basis"] = old["refutation_basis"]
    prior["superseded_at"] = utc_now()
    prior["reopened_by"] = dict(reopening["evidence"])
    return prior


def _settle_decision_point_basis(run_dir: Path, cand_fp: str, rec: dict) -> dict | None:
    """
    Settle `decision_point.basis` of a confirmed / needs_validation record against the patch-and-replay
    report on disk (decision_point_check.py), as _dead_code_on_disk does for a `dead_code` rejection:

    - an agreeing report (same candidate, same decision point, the patch at that location, status
      `checked`) raises the basis to `checked` and is cited in the record's evidence;
    - a stated `checked` without one is lowered to `located`.

    Returns the fields for the units' attempt entry, or None for a record with no basis at all.
    Recorded and reported only: no unit status and no severity depends on it.
    """
    dp = rec["decision_point"]
    stated = dp.get("basis")
    agrees = decision_point_check.agreeing_report(run_dir, cand_fp, rec["fingerprint"], dp)
    basis = stated
    fields: dict[str, Any] = {}
    if agrees is not None:
        basis = "checked"
        fields["decision_point_basis_source"] = "patch_replay"
        fields.update(agrees["flags"])
        cited = {"phase": "verifier", "tool_output": agrees["tool_output"], "description": agrees["description"]}
        if all(e.get("tool_output") != cited["tool_output"] for e in rec["evidence"]):
            rec["evidence"].append(cited)
    elif stated == "checked":
        basis = "located"
        fields["decision_point_basis_lowered"] = decision_point_check.disagreement(
            run_dir, cand_fp, rec["fingerprint"], dp
        )
    if basis is None:
        return None
    dp["basis"] = basis
    if basis != stated:
        fields["decision_point_basis_stated"] = stated or UNSTATED_BASIS
    return {"decision_point_basis": basis, **fields}


@ledger_locked
def cmd_ingest_verifier(
    result_path: Path,
    replay_reports: list[Path] | None = None,
    harness_meta_path: Path | None = None,
) -> dict:
    """
    Validate and ingest a crash_verifier subagent result, promoting scratch artifacts/crashes,
    mechanically verifying confirmed reproducers against parent replay reports, updating
    findings.json and candidates.json, and transitioning coverage-ledger.json units.
    """
    run_dir = Path.cwd().resolve()
    res = load_agent_result_json(result_path)
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
    mm = ModuleMap.load(run_dir)
    module = _candidate_harness_module(mm, cand)

    # A reopened candidate: this verdict supersedes the rejected record(s) it was reopened from. They
    # leave findings.json here and come back as `prior_verdicts` of the new record (see below).
    reopening = _open_reopening(cand)
    superseded: list[dict] = []
    for old_fp in (reopening or {}).get("rejected_fingerprints") or []:
        if (findings.get(old_fp) or {}).get("verdict") == "rejected":
            superseded.append(findings.pop(old_fp))
    rejection_sources: dict[str, str | None] = {}

    replayed = _collect_reproducible_artifacts(
        run_dir,
        list(replay_reports or []),
        list(cand.get("tool_outputs") or []),
    )
    placer = _FailurePlacer(mm, module, run_dir)
    own_inputs = _candidate_input_shas(run_dir, cand, replayed)
    uncompared: list[str] = []

    meta_file = harness_meta_path or (run_dir / "workspace" / "harnesses" / f"harness_{module}.json")
    harness_exhausted = False
    if meta_file and meta_file.is_file():
        try:
            hmeta = load_json_strict(meta_file)
            harness_exhausted = int(hmeta.get("repair_attempts", 0)) >= int(hmeta.get("max_repair_attempts", 2))
        except ArtifactError:
            harness_exhausted = False

    records = [copy.deepcopy(res["record"])] + [copy.deepcopy(r) for r in (res.get("additional_records") or [])]
    resolved_fps: list[str] = []

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
        rec.pop("prior_verdicts", None)  # written by this command only, never taken from a verifier
        rec.pop("conflicts_with", None)  # likewise (_reconcile_sink_conflicts)
        dp_attempt: dict | None = None
        if verdict in ("confirmed", "needs_validation") and isinstance(rec.get("decision_point"), dict):
            fields = _settle_decision_point_basis(run_dir, cand_fp, rec)
            if fields is not None:
                dp_attempt = {
                    "phase": "verifier",
                    "agent_id": aid,
                    "decision": verdict,
                    **fields,
                    "result_fingerprints": [fp],
                }

        if verdict == "confirmed":
            split_off = rec is not records[0]  # an additional record: another defect than the candidate's
            accepted = _accepted_failures(cand, candidates, rec, placer, split_off)
            for rep in rec["reproducers"]:
                inp = rep["input"].replace("\\", "/")
                if inp.startswith(f"agents/{aid}/scratch/"):
                    prom_crash = promote_file(run_dir, aid, inp, kind="crash", module=module)
                    rep["input"] = str(prom_crash["dest"])
                    rep["sha256"] = str(prom_crash["sha256"])
                    rep["size_bytes"] = int(prom_crash["size_bytes"])
                if rep["sha256"] not in replayed:
                    raise LedgerError(
                        f"confirmed finding {fp} requires a parent-verified reproducible crash report "
                        f"matching sha256 {rep['sha256']}"
                    )
                # The replay must have failed on this record's defect, not on any failure.
                outcome, seen = _judge_reproducer(replayed[rep["sha256"]], accepted, placer)
                if outcome == "mismatch":
                    raise LedgerError(_other_failure_refusal(fp, rep["sha256"], cand, rec, seen, candidates, split_off))
                if outcome == "uncompared":
                    if split_off:
                        wanted = "this additional record's own failure: " + _failure_text(
                            fp, rec.get("location") or {}, rec.get("property") or {}
                        )
                        why = "Such a replay does not count for an additional record."
                    else:
                        wanted = "the candidate's failure: " + _failure_text(
                            cand_fp, cand.get("location") or {}, cand.get("property") or {}
                        )
                        why = (
                            "Such a replay counts only for an input recorded on the candidate before verification, "
                            "and this one is not."
                        )
                    if split_off or rep["sha256"] not in own_inputs:
                        raise LedgerError(
                            f"confirmed finding {fp}: the parent's replay of reproducer sha256 {rep['sha256']} failed, "
                            f"but {seen.get('what')} (report {seen.get('report')}), so it cannot be compared with "
                            f"{wanted}. {why} List a reproducer whose parent replay reports that failure"
                            + ("" if split_off else ", or one recorded on the candidate")
                            + ", and cite this input in record.evidence."
                        )
                    # Counted, and said: the finding states that the parent could not compare the failure.
                    report = str(seen.get("report") or "")
                    note = {
                        "phase": "fuzz",
                        "tool_output": report if is_safe_relative_path(report) else rec["evidence"][0]["tool_output"],
                        "description": (
                            f"{IDENTITY_NOT_COMPARED} the parent's replay of {rep['input']} (sha256 "
                            f"{rep['sha256']}) failed, but {seen.get('what')} (report {report}). It is not shown to "
                            f"be {wanted}. It counts because the input was recorded on the candidate before "
                            "verification."
                        ),
                    }
                    if note not in rec["evidence"]:
                        rec["evidence"].append(note)
                    if rep["sha256"] not in uncompared:
                        uncompared.append(rep["sha256"])

            fix_patch = rec["remediation"].get("fix_patch")
            if isinstance(fix_patch, str) and fix_patch.replace("\\", "/").startswith(f"agents/{aid}/scratch/"):
                prom_fix = promote_file(run_dir, aid, fix_patch, kind="artifact")
                rec["remediation"]["fix_patch"] = str(prom_fix["dest"])

            # Expand linked_units to all active or deferred units of the confirmed-buggy function so it is excluded from WP
            fn_units = [
                u
                for u in units_for_function(units, rec["location"]["file"], rec["location"]["function"])
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
                    u,
                    "verifier",
                    aid,
                    "confirmed",
                    False,
                    primary_ev_out,
                    f"Crash verifier confirmed {fp} ({rec['severity']}).",
                )
                if dp_attempt is not None and dp_attempt not in u["attempts"]:
                    u["attempts"].append(dp_attempt)
                mark_candidate(u, fp)

        elif verdict == "needs_validation":
            for cid in rec["linked_units"]:
                if cid not in units:
                    raise LedgerError(f"needs_validation record {fp} references unknown unit {cid}")
                u = units[cid]
                if cand_fp != fp and cand_fp in u["result_fingerprints"]:
                    u["result_fingerprints"].remove(cand_fp)
                add_evidence(
                    u,
                    "verifier",
                    aid,
                    "needs_validation",
                    False,
                    primary_ev_out,
                    f"Crash verifier classified {fp} as needs_validation.",
                )
                if dp_attempt is not None and dp_attempt not in u["attempts"]:
                    u["attempts"].append(dp_attempt)
                mark_candidate(u, fp)

        elif verdict == "rejected":
            rej_class = rec["rejection_class"]
            # Evidence basis of the rejection (record and report only: no unit status depends on it).
            stated_basis = rec.get("refutation_basis") or UNSTATED_BASIS
            basis = stated_basis
            basis_source: str | None = None
            if rej_class == "dead_code" and basis != "checked":
                agrees = _dead_code_on_disk(run_dir, module, rec["location"])
                if agrees is not None:
                    basis = "checked"
                    basis_source = agrees["source"]
                    rec["refutation_basis"] = basis
                    cited = {k: agrees[k] for k in ("phase", "tool_output", "description")}
                    if all(e.get("tool_output") != cited["tool_output"] for e in rec["evidence"]):
                        rec["evidence"].append(cited)
            rejection_sources[fp] = basis_source
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
                    "refutation_basis": basis,
                    "reason": rec["reason"],
                    "result_fingerprints": [fp],
                }
                if basis != stated_basis:
                    attempt_entry["refutation_basis_stated"] = stated_basis
                    attempt_entry["refutation_basis_source"] = basis_source
                if attempt_entry not in u["attempts"]:
                    u["attempts"].append(attempt_entry)
                add_evidence(
                    u,
                    "verifier",
                    aid,
                    f"rejected:{rej_class}",
                    False,
                    primary_ev_out,
                    f"Rejected ({rej_class}, basis {basis}): {rec['reason'][:140]}",
                )
                if not u["result_fingerprints"] and u["status"] == "candidate":
                    if rej_class == "harness_induced" and not harness_exhausted:
                        u["status"] = "covered" if any(e.get("discharging") for e in u["evidence"]) else "planned"
                        u["agent_id"] = None
                        u["unresolved"] = []
                    elif rej_class == "harness_induced" and harness_exhausted:
                        u["status"] = "blocked"
                        u["unresolved"] = sorted(set(u["unresolved"] + [f"harness_repair_exhausted: {rec['reason']}"]))
                        u["agent_id"] = None
                    else:
                        has_discharging = any(e.get("discharging") for e in u["evidence"])
                        u["status"] = "covered" if has_discharging else "blocked"
                        u["agent_id"] = None
                        if has_discharging:
                            u["unresolved"] = []
                        else:
                            u["unresolved"] = [
                                f"candidate_rejected ({rej_class}): {rec.get('reason') or 'candidate disproved'}"
                            ]
                elif u["status"] in NO_EVIDENCE_STATES:
                    # Its deferral reason no longer explains a blocked unit: the rejection comes first.
                    u["status"] = "blocked"
                    reason = f"candidate_rejected ({rej_class}): {rec.get('reason') or 'candidate disproved'}"
                    u["unresolved"] = list(dict.fromkeys([reason, *(u.get("unresolved") or [])]))

        if fp in findings:
            _merge_finding_record(findings[fp], rec)
        else:
            existing_sink = _find_matching_sink_finding(findings, rec, run_dir=run_dir)
            if existing_sink is not None:
                canon_fp = existing_sink["fingerprint"]
                _merge_finding_record(existing_sink, rec)
                if fp in resolved_fps:
                    resolved_fps = [canon_fp if x == fp else x for x in resolved_fps]
                    resolved_fps = list(dict.fromkeys(resolved_fps))
                for cid in rec.get("linked_units") or []:
                    if cid in units:
                        u = units[cid]
                        if fp != canon_fp and fp in u["result_fingerprints"]:
                            u["result_fingerprints"].remove(fp)
                        if u["status"] == "candidate" and canon_fp not in u["result_fingerprints"]:
                            u["result_fingerprints"].append(canon_fp)
                if not res.get("refingerprint_reason") and not cand.get("refingerprint_reason"):
                    cand["refingerprint_reason"] = (
                        f"Merged duplicate sink finding {fp} into canonical finding {canon_fp}."
                    )
            else:
                findings[fp] = rec

    if reopening is not None:
        # The history stays in findings.json: the superseded rejection(s), oldest first, on the record
        # that now answers for the candidate.
        target = findings[resolved_fps[0]]
        history = list(target.get("prior_verdicts") or [])
        for old in superseded:
            for prior in [*(old.get("prior_verdicts") or []), _prior_verdict(old, reopening)]:
                if all((h["fingerprint"], h["reason"]) != (prior["fingerprint"], prior["reason"]) for h in history):
                    history.append(prior)
        if history:
            target["prior_verdicts"] = history
        for old in superseded:
            old_fp = old["fingerprint"]
            if old_fp in findings:
                continue
            # Another candidate merged into the superseded record follows it to the new one.
            for other in candidates.values():
                other_fps = other.get("resolved_fingerprints") or [other["fingerprint"]]
                if other is cand or other.get("status") != "verified" or old_fp not in other_fps:
                    continue
                other["resolved_fingerprints"] = list(
                    dict.fromkeys(resolved_fps[0] if x == old_fp else x for x in other_fps)
                )
                if not other.get("refingerprint_reason"):
                    other["refingerprint_reason"] = (
                        f"Rejected finding {old_fp} was superseded by {resolved_fps[0]} "
                        f"after candidate {cand_fp} was reopened."
                    )
        reopening["resolved"] = {
            "at": utc_now(),
            "decision": res["decision"],
            "resolved_fingerprints": list(resolved_fps),
        }

    cand["status"] = "verified"
    cand["resolved_fingerprints"] = resolved_fps
    if res.get("refingerprint_reason"):
        cand["refingerprint_reason"] = res["refingerprint_reason"]

    # What a later tool signal needs to know about this rejection (tool_evidence_on_verified_candidate).
    cand.pop("last_rejection", None)
    resolved_recs = [findings[x] for x in resolved_fps]
    if rejection_reopen_enabled() and all(r["verdict"] == "rejected" for r in resolved_recs):
        harness = _harness_state(module)
        last: dict[str, Any] = {
            "at": utc_now(),
            "rejection_class": resolved_recs[0]["rejection_class"],
            "refutation_basis": resolved_recs[0].get("refutation_basis") or UNSTATED_BASIS,
            "harness_sha256": harness["sha256"],
            "repair_attempts": harness["repair_attempts"],
        }
        source = rejection_sources.get(records[0]["fingerprint"])
        if source:
            last["refutation_basis_source"] = source
        cand["last_rejection"] = last

    # Opposite verdicts at one sink (this verdict against an earlier one, either way round).
    conflicts = _reconcile_sink_conflicts(units, candidates, findings, run_dir, resolved_fps)

    commit(units, candidates, findings, run_dir=run_dir)
    return {
        "candidate_fingerprint": cand_fp,
        "decision": res["decision"],
        "resolved_fingerprints": resolved_fps,
        "harness_exhausted": harness_exhausted,
        # Reproducers counted although the parent's replay named no failure to compare (see the record's evidence).
        **({"reproducers_not_compared": uncompared} if uncompared else {}),
        **({"superseded_rejections": [o["fingerprint"] for o in superseded]} if superseded else {}),
        **({"sink_conflicts": conflicts} if conflicts else {}),
    }


# ---------------------------------------------------------------- transition


def _apply_transition(
    units: dict[str, dict],
    cid: str,
    status: str,
    agent_id: str | None = None,
    reason: str | None = None,
    expected: list[str] | None = None,
) -> dict:
    if status not in ALLOWED_MANUAL_STATUSES:
        raise LedgerError(
            f"cannot manually transition to {status!r}; allowed manual statuses: {sorted(ALLOWED_MANUAL_STATUSES)}"
        )
    if cid not in units:
        raise LedgerError(f"unknown coverage id {cid}")
    u = units[cid]
    if expected and u["status"] not in expected:
        raise LedgerError(
            f"{cid} is {u['status']!r}, expected one of {sorted(expected)}; transition to {status!r} refused"
        )
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
    return u


@ledger_locked
def cmd_transition(
    cid: str,
    status: str,
    agent_id: str | None,
    reason: str | None,
    expected: list[str] | None = None,
) -> dict:
    """
    Move one unit to `status`. With `expected`, this is a compare-and-set: the transition is
    refused unless the unit is currently in one of those statuses (a scheduler preparing a
    prover must never overwrite a unit that an ingest just marked `candidate`).
    """
    units, candidates = load_state()
    u = _apply_transition(units, cid, status, agent_id, reason, expected)
    commit(units, candidates)
    return u


@ledger_locked
def cmd_transition_many(items: list[dict]) -> list[dict]:
    """
    Apply a batch of unit status transitions atomically in one load + validate + commit cycle.
    Each item is `{"id": cid, "status": status, "agent_id": ..., "reason": ..., "expected": ...}`.
    If any transition fails, no change is committed.
    """
    if not items:
        return []
    units, candidates = load_state()
    updated: list[dict] = []
    for item in items:
        cid = item.get("id") or item.get("coverage_id")
        status = item.get("status")
        if not cid or not status:
            raise LedgerError("transition_many item requires 'id' and 'status'")
        updated.append(
            _apply_transition(
                units,
                str(cid),
                str(status),
                item.get("agent_id"),
                item.get("reason"),
                item.get("expected"),
            )
        )
    commit(units, candidates)
    return updated


@ledger_locked
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


# D2, D18: a dynamic reach gap holds back the planned units of its module from WP. Such a unit is `blocked`,
# with this reason and a `reach_gated` evidence entry (non-discharging). When the gap is gone it returns to
# `planned`, unless another reason still blocks it.
DYNAMIC_GAP_REASON = "dynamic_reach_gap: "
REACH_GATED_RESULT = "reach_gated"
REACH_GATE_TOOL_OUTPUT = "workspace/reports/harness_reach_dynamic.json"


def _is_reach_gated(evidence: dict) -> bool:
    return evidence.get("result") == REACH_GATED_RESULT


@ledger_locked
def cmd_gate_reach(run_dir: Path = Path(".")) -> dict:
    """
    Hold the planned units of each dynamically gated module out of WP, and release them once the gap is gone.

    For each module of `phase0_gates.dynamic_gaps`: every `planned` unit in its scope becomes `blocked`, with
    the reason `dynamic_reach_gap: <entry points>` and `reach_gated` evidence; a unit already blocked by that
    reason has both refreshed. Every other unit is left as it is. A `blocked` unit whose dynamic reason is
    not among the current gaps loses that reason, and returns to `planned` only when no reason is left (a
    unit blocked for another reason stays blocked). Its `reach_gated` evidence goes too, unless the unit would
    stay blocked with no other evidence: `blocked` needs partial evidence.
    """
    gaps = phase0_gates.dynamic_gaps(Path(run_dir))
    units, candidates = load_state()
    gated_cids: set[str] = set()
    blocked = 0
    if gaps:
        mm = ModuleMap.load(run_dir)
        for module, entry_points in gaps.items():
            reason = DYNAMIC_GAP_REASON + ", ".join(entry_points)
            for u in _module_units(units, *_report_scope(mm, module)):
                others = [r for r in u["unresolved"] if not r.startswith(DYNAMIC_GAP_REASON)]
                has_dynamic = len(others) != len(u["unresolved"])
                if not (u["status"] == "planned" or (u["status"] == "blocked" and has_dynamic)):
                    continue
                u["status"] = "blocked"
                u["unresolved"] = sorted(set(others + [reason]))
                u["evidence"] = [e for e in u["evidence"] if not _is_reach_gated(e)]
                add_evidence(
                    u,
                    "fuzz",
                    "harness_reach.py",
                    REACH_GATED_RESULT,
                    False,
                    REACH_GATE_TOOL_OUTPUT,
                    f"Dynamic reach gate: {module} never executed {', '.join(entry_points)} in its corpus; "
                    "the unit waits for the gap to close (not a proof).",
                )
                gated_cids.add(u["coverage_id"])
                blocked += 1
    reopened = 0
    for cid, u in units.items():
        if cid in gated_cids or u["status"] != "blocked":
            continue
        if not any(r.startswith(DYNAMIC_GAP_REASON) for r in u["unresolved"]):
            continue
        others = [r for r in u["unresolved"] if not r.startswith(DYNAMIC_GAP_REASON)]
        kept = [e for e in u["evidence"] if not _is_reach_gated(e)]
        if others:
            u["unresolved"] = others
            if kept:
                u["evidence"] = kept
        else:
            u["status"] = "planned"
            u["agent_id"] = None
            u["unresolved"] = []
            u["evidence"] = kept
        reopened += 1
    commit(units, candidates)
    return {"gated_modules": gaps, "blocked": blocked, "reopened": reopened}


def cmd_scaffold_verifier(
    cand_fp: str,
    decision: str,
    agent_id: str,
    file_override: str | None = None,
    fn_override: str | None = None,
    line_override: int | None = None,
    severity: str = "high",
    out_path: Path | None = None,
) -> dict:
    """
    Generate a schema-valid crash_verifier result skeleton from `candidates.json`
    and its referenced fuzz/Eva tool reports so verifiers do not hand-craft 20-field JSONs.
    """
    units, candidates = load_state()
    if cand_fp not in candidates:
        raise LedgerError(f"unknown candidate_fingerprint: {cand_fp}")
    cand = candidates[cand_fp]
    module = _candidate_harness_module(ModuleMap.load("."), cand)
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
        refp_reason: str | None = (
            f"Resolved candidate location {loc.get('file')}#{loc.get('function')} "
            f"to {loc_file}#{loc_fn} at line {loc_line}."
        )
    else:
        rec_fp = cand_fp
        refp_reason = None

    if decision == "confirmed":
        fn_units = [
            u["coverage_id"]
            for u in units_for_function(units, loc_file, loc_fn)
            if u["status"] not in ("out_of_scope", "not_applicable")
        ]
        linked = fn_units or list(cand.get("linked_units") or [])
    else:
        # The candidate's own units; failing those, the resolved function's units that may carry evidence
        # (a deferred or out-of-scope unit must not, so a rejection never links one). A candidate in a libc
        # stub or harness code with no target function links nothing.
        linked = list(cand.get("linked_units") or []) or [
            u["coverage_id"]
            for u in units_for_function(units, loc_file, loc_fn)
            if u["status"] not in NO_EVIDENCE_STATES
        ]
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

    # The module's own build, as the fuzz report names it (`<out-bin>.e-acsl` for E-ACSL builds).
    try:
        fuzz_report = load_json_optional(Path("workspace/reports/fuzz") / f"{module}.json", {})
    except ArtifactError:
        fuzz_report = {}
    compile_info = fuzz_report.get("compile") if isinstance(fuzz_report, dict) else None
    binary = (compile_info or {}).get("binary") if isinstance(compile_info, dict) else None
    binary = binary or f"workspace/harnesses/fuzz_{module}.e-acsl"
    reproducers: list[dict] = []
    for rep_rel in cand.get("reproducers") or []:
        rep_path = Path(rep_rel)
        sha = "0" * 64
        sz = 0
        if rep_path.is_file():
            raw = rep_path.read_bytes()
            sha = hashlib.sha256(raw).hexdigest()
            sz = len(raw)
        reproducers.append(
            {
                "input": rep_rel,
                "sha256": sha,
                "size_bytes": sz,
                "command": (
                    f"python3 /opt/framac-pipeline/scripts/run_eacsl_fuzz.py replay --module {module} "
                    f"--inputs {rep_rel} --binary {binary}"
                ),
                "observed_result": f"{p_kind}: {p_pred}",
            }
        )

    base_fields = {
        "verdict": decision,
        "fingerprint": rec_fp,
        "title": f"{p_kind} in {loc_fn} ({loc_file}:{loc_line})",
        "description": f"Runtime or static violation of {p_pred} at {loc_file}:{loc_line} in {loc_fn}.",
        "location": {"file": loc_file, "line": loc_line, "function": loc_fn},
        "property": {"kind": p_kind, "predicate": p_pred},
    }

    # A placeholder at the sink: the verifier moves it to the earliest outside choice that makes the
    # failure inevitable and names who controls it (attacker_input, harness_choice or environment).
    decision_point = {
        "file": loc_file,
        "line": loc_line,
        "function": loc_fn,
        "controlled_by": "attacker_input",
        "description": f"Placeholder: fuzz input bytes reach {loc_fn} unvalidated; name the deciding step.",
        # The weakest basis: `located` once the step is traced in the source; `checked` comes only from
        # a decision_point_check.py report, which ingest-verifier reads itself.
        "basis": "model",
    }

    if decision == "confirmed":
        record = {
            **base_fields,
            "root_cause": f"Unchecked input reaches {loc_file}:{loc_line} in {loc_fn}.",
            "decision_point": decision_point,
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
            "decision_point": decision_point,
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
            "validation_plan": {"local": f"Replay with full state initialization in {harness_file}."},
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
            # The weakest basis: the verifier raises it to `located` or `checked` with what it cites.
            "refutation_basis": "model",
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


@ledger_locked
def cmd_audit_hypotheses(dag_path: Path = Path("workspace/reports/callgraph_dag.json")) -> dict:
    """
    Resolve provisional `valid_under_hyp` assumptions on WP-covered units against the call graph:
    - If every in-scope callee in the DAG is deductively proven by WP (`covered` with discharging
      `wp` evidence and no `blocked`/`candidate` units), remove `valid_under_hyp` and record
      `phase="audit"`, `result="hypotheses_discharged"` evidence.
    - If any callee in the DAG is `blocked`, `candidate`, `planned`, `in_progress`, `deferred`,
      or covered only by Eva (`phase="eva"`, no discharging `wp` evidence), attach an explicit
      `callee_contract_hypothesis` assumption referencing the callee's `related_units`.
    """
    units, candidates = load_state()
    dag = load_json_optional(dag_path, {}) if dag_path else {}
    dag_fns = dag.get("functions", {}) if isinstance(dag, dict) else {}

    dag_fns = dag_fns if isinstance(dag_fns, dict) else {}

    def _ref(key: str) -> tuple[str, str]:
        """(file, name) of a DAG key: its record's, else the key itself (`file#name` or a plain name)."""
        fmeta = dag_fns.get(key)
        file_part, sep, name_part = str(key).partition("#")
        if isinstance(fmeta, dict) and fmeta.get("name"):
            return normalize_file(fmeta.get("file") or (file_part if sep else "")), str(fmeta["name"])
        return (normalize_file(file_part), name_part) if sep else ("", str(key))

    # A DAG key is the plain name, or `file#name` when the name collides: callees are resolved to
    # (file, name) through their own records, never matched by name alone.
    callees_by_key: dict[tuple[str, str], list[tuple[str, str]]] = {}
    callees_by_name: dict[str, list[tuple[str, str]]] = {}
    for key, fmeta in dag_fns.items():
        if not isinstance(fmeta, dict):
            continue
        fn_file, fn_name = _ref(key)
        raw_callees = fmeta.get("internal_callees") or fmeta.get("direct_callees") or fmeta.get("callees") or []
        refs = [_ref(c) for c in raw_callees if isinstance(c, str) and c and c != key]
        clean_callees = [r for r in refs if r != (fn_file, fn_name)]
        if fn_file and fn_name:
            callees_by_key[(fn_file, fn_name)] = clean_callees
        if fn_name and fn_name not in callees_by_name:
            callees_by_name[fn_name] = clean_callees

    units_by_fn_name: dict[str, list[dict]] = {}
    units_by_ref: dict[tuple[str, str], list[dict]] = {}
    for u in units.values():
        units_by_fn_name.setdefault(u["function"], []).append(u)
        units_by_ref.setdefault((normalize_file(u["file"]), u["function"]), []).append(u)

    def _has_wp_discharge(unit_obj: dict) -> bool:
        return any(
            isinstance(e, dict) and e.get("phase") == "wp" and e.get("discharging")
            for e in (unit_obj.get("evidence") or [])
        )

    hyp_kinds = ("valid_under_hyp", "callee_contract_hypothesis")
    audited: dict[str, list[dict]] = {}
    # Name-only resolutions: a stale DAG (no record for the caller, or a callee key without one).
    warnings: set[str] = set()
    for u in units.values():
        if u["status"] != "covered" or not _has_wp_discharge(u):
            continue
        u_file = normalize_file(u["file"])
        u_fn = u["function"]
        callee_names = callees_by_key.get((u_file, u_fn))
        if callee_names is None:
            callee_names = callees_by_name.get(u_fn, [])
            if u_fn in callees_by_name:
                warnings.add(
                    f"{u_file}#{u_fn} has no DAG record: its callees are those of the first record named {u_fn}"
                )

        callee_units: list[dict] = []
        for cfile, cname in callee_names:
            if cfile:
                # The callee's own units: same file and name, whatever its DAG key.
                pool = units_by_ref.get((cfile, cname), [])
            else:
                # An old DAG without the callee's record: by name, the caller's file first.
                pool = units_by_fn_name.get(cname, [])
                if pool:
                    warnings.add(f"callee {cname} of {u_file}#{u_fn} has no DAG record: its units are matched by name")
            cand_units = [
                cu
                for cu in pool
                if cu["status"] not in ("out_of_scope", "not_applicable")
                and not (normalize_file(cu["file"]) == u_file and cu["function"] == u_fn)
            ]
            same_file = [cu for cu in cand_units if normalize_file(cu["file"]) == u_file]
            callee_units.extend(cand_units if cfile else (same_file or cand_units))
        audited[u["coverage_id"]] = callee_units

    # Conditionality is transitive: a caller is proven unconditionally only when each callee is, so
    # a callee that is itself proven under an open hypothesis keeps its callers conditional. Seed the
    # open set with units whose own callees are not WP-proven, and units that keep a hypothesis no
    # callee can discharge, then propagate up the call graph to a fixpoint.
    open_ids: set[str] = set()
    for cid, callee_units in audited.items():
        u = units[cid]
        has_vuh = any(a.get("kind") in hyp_kinds for a in u["assumptions"])
        if any(cu["status"] != "covered" or not _has_wp_discharge(cu) for cu in callee_units) or (
            has_vuh and not callee_units
        ):
            open_ids.add(cid)
    changed = True
    while changed:
        changed = False
        for cid, callee_units in audited.items():
            if cid not in open_ids and any(cu["coverage_id"] in open_ids for cu in callee_units):
                open_ids.add(cid)
                changed = True

    discharged = 0
    conditional = 0
    for cid, callee_units in audited.items():
        u = units[cid]
        unproven_callees = [
            cu
            for cu in callee_units
            if cu["status"] != "covered" or not _has_wp_discharge(cu) or cu["coverage_id"] in open_ids
        ]
        has_vuh = any(a.get("kind") in hyp_kinds for a in u["assumptions"])

        if unproven_callees:
            rel_ids = sorted({cu["coverage_id"] for cu in unproven_callees})
            u["assumptions"] = [
                a for a in u["assumptions"] if a.get("kind") not in ("valid_under_hyp", "callee_contract_hypothesis")
            ]
            add_assumption(
                u,
                "callee_contract_hypothesis",
                "Caller proof relies on callee contract(s) not deductively proven by WP, or proven only under "
                f"open hypotheses: {', '.join(rel_ids[:5])}.",
                related=rel_ids,
            )
            conditional += 1
        elif has_vuh and callee_units:
            u["assumptions"] = [
                a for a in u["assumptions"] if a.get("kind") not in ("valid_under_hyp", "callee_contract_hypothesis")
            ]
            add_evidence(
                u,
                "audit",
                "ledger.py",
                "hypotheses_discharged",
                False,
                None,
                "All callee contracts in the call graph are deductively proven by WP.",
            )
            discharged += 1

    commit(units, candidates)
    for warning in sorted(warnings):
        print(f"audit-hypotheses: warning: {warning}; rebuild the DAG", file=sys.stderr)
    return {"discharged": discharged, "conditional": conditional, "warnings": sorted(warnings)}


def cmd_summary() -> dict:
    units, candidates, findings = load_all_state()
    by_status: dict[str, int] = {}
    by_class: dict[str, dict[str, int]] = {}
    for u in units.values():
        by_status[u["status"]] = by_status.get(u["status"], 0) + 1
        c = by_class.setdefault(u["obligation_class"], {})
        c[u["status"]] = c.get(u["status"], 0) + 1
    by_verdict: dict[str, int] = {}
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


def _parse_transitions_spec(raw: str) -> list[dict]:
    text = (raw or "").strip()
    if not text:
        return []
    path = Path(text)
    if not text.startswith("[") and path.is_file():
        data = load_json_strict(path)
    else:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise LedgerError(f"invalid --spec-json: {exc}") from exc
    if not isinstance(data, list):
        raise LedgerError("--spec-json must be a JSON list of transition objects")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Coverage ledger and candidate management (parent-only).")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("seed")
    p.add_argument("--dag", type=Path, default=Path("workspace/reports/callgraph_dag.json"))
    p.add_argument("--scope", action="append", default=[])
    p.add_argument("--callgraph-source", choices=["frama_c", "gcc_callgraph"], default="frama_c")
    p.add_argument("--profile", choices=["quick", "standard", "deep"], default=None)
    p.add_argument(
        "--security-props",
        type=Path,
        default=None,
        help=f"scripts/security_props.py's report (default {DEFAULT_SECURITY_PROPS}, used when present)",
    )
    p.add_argument(
        "--refresh",
        action="store_true",
        help="Also re-derive the units without evidence from the current DAG (a Phase 0 re-run on a changed target)",
    )
    for name in ("ingest-fuzz", "ingest-eva", "ingest-wp"):
        p = sub.add_parser(name)
        p.add_argument("reports", nargs="+", type=Path)
        if name == "ingest-wp":
            p.add_argument(
                "--sweep",
                action="store_true",
                help="Reports are the trusted wp-sweep re-proof: WP-covered units they do not credit become blocked",
            )
    p_hyp = sub.add_parser("ingest-agent-hypothesis")
    p_hyp.add_argument("result", type=Path)
    p_hyp.add_argument("--module", default=None)
    p_ba = sub.add_parser("record-boundary-assumptions")
    p_ba.add_argument("result", type=Path)
    p_sc = sub.add_parser(
        "record-stub-contracts", help="Record the stub overlay's active contracts as stub_contract assumptions"
    )
    p_sc.add_argument("--report", type=Path, default=DEFAULT_STUB_REPORT)
    p_sc.add_argument("--check-report", type=Path, default=DEFAULT_STUB_CHECK)
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
    p.add_argument(
        "--expect",
        action="append",
        default=[],
        help="Compare-and-set: refuse unless the unit's current status is one of these (repeatable)",
    )
    p_many = sub.add_parser("transition-many")
    p_many.add_argument(
        "--spec-json",
        required=True,
        help="JSON list (or path to JSON file) of {id, status, agent_id?, reason?, expected?} transitions",
    )
    sub.add_parser(
        "gate-reach",
        help="Hold the planned units of dynamically gated modules out of WP, release the rest (D2, D18)",
    )
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
    p_mc = sub.add_parser(
        "mark-carried", help="Label the units a WP report credited as carried forward (scripts/proof_carry.py)"
    )
    p_mc.add_argument("--report", required=True, type=Path)
    p_mc.add_argument("--entry", required=True, help="Restored proofs cache entry, run-relative")
    p_mc.add_argument("--key", required=True)
    p_audit = sub.add_parser("audit-hypotheses", help="Resolve valid_under_hyp assumptions against callgraph_dag.json")
    p_audit.add_argument("--dag", type=Path, default=Path("workspace/reports/callgraph_dag.json"))
    p_related = sub.add_parser("link-related", help="Link candidates that other engines report on one reproducer (D1b)")
    p_related.add_argument(
        "--index", type=Path, required=True, help="The replay index (replay-candidates --cross-engine)"
    )
    sub.add_parser("summary")
    sub.add_parser("status", help="Alias for summary")
    args = parser.parse_args(argv)

    out: object
    try:
        if args.cmd == "seed":
            problems = seed_input_problems(args.security_props)
            if problems:
                print(json.dumps({"ok": False, "error": "seed inputs not ready", "reasons": problems}, indent=2))
                return 1
            out = cmd_seed(
                args.dag, args.scope, args.callgraph_source, args.profile, args.security_props, refresh=args.refresh
            )
        elif args.cmd == "ingest-fuzz":
            out = cmd_ingest_fuzz(args.reports)
        elif args.cmd == "ingest-eva":
            out = cmd_ingest_eva(args.reports)
        elif args.cmd == "ingest-wp":
            out = cmd_ingest_wp(args.reports, sweep=args.sweep)
        elif args.cmd == "mark-carried":
            out = cmd_mark_carried(args.report, args.entry, args.key)
        elif args.cmd == "ingest-agent-hypothesis":
            out = cmd_ingest_agent_hypothesis(args.result, args.module)
        elif args.cmd == "record-boundary-assumptions":
            out = cmd_record_boundary_assumptions(args.result)
        elif args.cmd == "record-stub-contracts":
            out = cmd_record_stub_contracts(args.report, args.check_report)
        elif args.cmd == "ingest-verifier":
            out = cmd_ingest_verifier(args.result, args.replay_report, args.harness_meta)
        elif args.cmd == "link-related":
            out = cmd_link_related(args.index)
        elif args.cmd == "transition":
            out = cmd_transition(args.id, args.status, args.agent_id, args.reason, args.expect or None)
        elif args.cmd == "transition-many":
            out = cmd_transition_many(_parse_transitions_spec(args.spec_json))
        elif args.cmd == "close-remaining":
            out = cmd_close_remaining(args.reason)
        elif args.cmd == "gate-reach":
            out = cmd_gate_reach()
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
        elif args.cmd == "audit-hypotheses":
            out = cmd_audit_hypotheses(args.dag)
        else:
            out = cmd_summary()
    except (LedgerError, PromotionError, ArtifactError, RunLockTimeout) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        return 1
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
