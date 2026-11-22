#!/usr/bin/env python3
"""
Derives the human-readable and SARIF reports from the run's sources of truth:

  run-metadata.json, coverage-ledger.json, findings.json, candidates.json

Outputs (in the run directory unless overridden):
  REPORT.md            run status first, confirmed table, needs-validation table,
                       assurance summary (unconditional vs conditional proofs),
                       coverage gaps
  FINDINGS-DETAIL.md   full record for every confirmed finding
  NEEDS-VALIDATION.md  full record for every needs_validation lead
  report.sarif         verdict records only (confirmed = error, needs_validation = warning)

Every input is validated first; an invalid input aborts without writing anything.
The prose never changes a verdict, severity, blocker or coverage state: it only
renders what the validated JSON says. Raw Eva/WP SARIF stays in workspace/reports/.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fingerprint import normalize_file, normalize_kind  # noqa: E402
from framac_common import (  # noqa: E402
    WP_EXPERIMENTAL_MODEL_ASSUMPTION,
    ArtifactError,
    load_json_optional,
    load_json_strict,
)
from ledger import (  # noqa: E402
    GUARDRAIL_PASSED_STATUS,
    IDENTITY_NOT_COMPARED,
    INDUCTIVE_LEMMA_GAP,
    METACSL_CLASSES,
    PROPERTY_RELOCATED,
    relocated_properties,
    unchecked_clause_text,
)
from mutation_check import WpReportIndex, classify_open_unit, discover_wp_reports  # noqa: E402
from phase0_gates import dynamic_gaps  # noqa: E402
from validate_artifacts import validate_run_dir  # noqa: E402
from workspace_overlay import map_work_to_baseline_line  # noqa: E402

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
CLASSES = [
    "rte",
    "l2_termination",
    "l3_frame",
    "l3_isolation",
    "l4_auth_state",
    "l4_auth_required",
    "l4_invariant",
    "l4_call_rule",
    "l5_sanitized",
    "l6_wiped",
    "l6_no_leak",
]
# The ledger's prefix for a unit deferred because its link unit is on the GCC fallback (ledger.py).
CALLGRAPH_FALLBACK = "callgraph_fallback"


def md_escape(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ").strip()


def loc(rec: dict, run_dir: Path | None = None) -> str:
    loc_obj = rec["location"]
    raw_line = int(loc_obj["line"])
    base_line, work_line = map_work_to_baseline_line(loc_obj["file"], raw_line, run_dir=run_dir)
    if base_line != work_line and base_line > 0 and work_line > 0:
        return f"`{loc_obj['file']}:{base_line}` (work: `{loc_obj['file']}:{work_line}`, `{loc_obj['function']}`)"
    return f"`{loc_obj['file']}:{raw_line}` (`{loc_obj['function']}`)"


def dedupe_findings_for_report(findings: list[dict], run_dir: Path | None = None) -> list[dict]:
    """
    Collapse duplicate verdict records that share the same `(verdict, file, function, canonical_line, kind)`
    into a single display record, preserving all reproducers, evidence entries, and related fingerprints.
    """
    merged: list[dict] = []
    for raw in findings:
        rec = copy.deepcopy(raw)
        if rec.get("verdict") not in ("confirmed", "needs_validation"):
            merged.append(rec)
            continue
        loc_obj = rec.get("location") or {}
        f_norm = normalize_file(loc_obj.get("file") or "")
        fn = loc_obj.get("function") or ""
        line = int(loc_obj.get("line") or 0)
        base_line, _ = map_work_to_baseline_line(f_norm, line, run_dir=run_dir)
        prop = rec.get("property") or {}
        k_norm = normalize_kind(prop.get("kind") or "", prop.get("predicate") or "")

        matched = None
        for existing in merged:
            if existing.get("verdict") != rec.get("verdict"):
                continue
            eloc = existing.get("location") or {}
            if normalize_file(eloc.get("file") or "") != f_norm or eloc.get("function") != fn:
                continue
            ebase, _ = map_work_to_baseline_line(f_norm, int(eloc.get("line") or 0), run_dir=run_dir)
            if ebase != base_line or base_line <= 0:
                continue
            eprop = existing.get("property") or {}
            ekind = normalize_kind(eprop.get("kind") or "", eprop.get("predicate") or "")
            if (
                ekind == k_norm
                or ekind in ("rte", "assertion", "property")
                or k_norm in ("rte", "assertion", "property")
            ):
                matched = existing
                break
        if matched is None:
            merged.append(rec)
            continue
        for key in ("reproducers", "evidence", "linked_units"):
            if key in matched and key in rec:
                for item in rec[key]:
                    if item not in matched[key]:
                        matched[key].append(item)
        if rec.get("conflicts_with"):
            matched["conflicts_with"] = sorted({*(matched.get("conflicts_with") or []), *rec["conflicts_with"]})
        if rec["fingerprint"] != matched["fingerprint"]:
            rel_fps = matched.setdefault("_related_fingerprints", [])
            if rec["fingerprint"] not in rel_fps:
                rel_fps.append(rec["fingerprint"])
        if rec.get("verdict") == "confirmed":
            if SEVERITY_ORDER.get(rec.get("severity", "low"), 3) < SEVERITY_ORDER.get(
                matched.get("severity", "low"), 3
            ):
                matched["severity"] = rec["severity"]
                matched["severity_rationale"] = rec["severity_rationale"]
    return merged


def decision_point_text(rec: dict) -> str | None:
    """The verifier's decision point as one line, or None for a record without one."""
    dp = rec.get("decision_point")
    if not isinstance(dp, dict):
        return None
    basis = f" (basis `{dp['basis']}`)" if dp.get("basis") else ""
    return (
        f"`{dp['file']}:{dp['line']}` in `{dp['function']}`, controlled by `{dp['controlled_by']}`{basis}: "
        f"{md_escape(dp['description'])}"
    )


def decision_point_basis_lines(records: list[dict]) -> list[str]:
    """Decision points counted by basis; nothing when no record states one."""
    counts = Counter(
        r["decision_point"].get("basis") or "unstated" for r in records if isinstance(r.get("decision_point"), dict)
    )
    if not counts or set(counts) == {"unstated"}:
        return []
    cells = ", ".join(f"{counts[b]} `{b}`" for b in REFUTATION_BASES if counts[b])
    return [
        f"Decision points by basis: {cells} (`checked`: a patch at that location removes the failure for the "
        "recorded reproducers, nothing more; `located`: traced in the source; `model`: reasoning only).",
        "",
    ]


def prior_verdict_text(rec: dict) -> str | None:
    """The rejection(s) a record superseded after its candidate was reopened, as one line."""
    prior = rec.get("prior_verdicts") or []
    if not prior:
        return None
    return "; ".join(
        f"rejected as `{p['rejection_class']}` (basis `{p.get('refutation_basis') or 'unstated'}`) by "
        f"`{p['verifier']['agent_id']}`, reopened by `{p['reopened_by']['source']}` "
        f"(`{p['reopened_by']['artifact']}`): {md_escape(p['reason'])}"
        for p in prior
    )


def _verdict_label(rec: dict) -> str:
    if rec["verdict"] == "rejected":
        return f"rejected as `{rec['rejection_class']}`, basis `{rec.get('refutation_basis') or 'unstated'}`"
    return str(rec["verdict"])


def _reverified_by_sibling(rejected: dict) -> bool:
    """The rejection was reopened by its sibling's opposite verdict and came back rejected again."""
    return any(p["reopened_by"]["source"] == "sibling_verdict" for p in rejected.get("prior_verdicts") or [])


def conflict_text(rec: dict, by_fp: dict[str, dict]) -> str | None:
    """The opposite verdicts recorded at this record's sink (`conflicts_with`), as one line."""
    parts = []
    for fp in rec.get("conflicts_with") or []:
        other = by_fp.get(fp)
        if other is None:
            continue
        rejected = other if other["verdict"] == "rejected" else rec
        again = ", re-verified after reopening, still opposite" if _reverified_by_sibling(rejected) else ""
        parts.append(f"`{fp}`: {_verdict_label(other)}{again}")
    return "; ".join(parts) or None


def sink_conflict_lines(findings: list[dict], candidates: list[dict]) -> list[str]:
    """
    Pairs of verdict records at the same sink with opposite verdicts (findings.json `conflicts_with`,
    ledger.py _reconcile_sink_conflicts). Nothing when there is none.
    """
    by_fp = {r["fingerprint"]: r for r in findings}
    pairs = sorted(
        {
            (r["fingerprint"], fp)
            for r in findings
            if r["verdict"] != "rejected"
            for fp in r.get("conflicts_with") or []
            if fp in by_fp
        }
    )
    if not pairs:
        return []
    out = [
        f"- **Opposite verdicts at one sink:** {len(pairs)} pair(s). Not reconciled automatically: both records "
        "stand, and each pair needs a look."
    ]
    for pos, neg in pairs[:50]:
        rej = by_fp[neg]
        # A reopened candidate has no resolved_fingerprints; its reopening names the rejection.
        cands = [
            c
            for c in candidates
            if neg == c["fingerprint"]
            or neg in (c.get("resolved_fingerprints") or [])
            or any(neg in r.get("rejected_fingerprints", []) for r in c.get("reopened") or [])
        ]
        sibling = [
            e
            for c in cands
            for e in [*(r["evidence"] for r in c.get("reopened") or []), *(c.get("contradicting_evidence") or [])]
            if e.get("source") == "sibling_verdict"
        ]
        if _reverified_by_sibling(rej):
            status = "the rejection was reopened, re-verified and rejected again"
        elif any(c["status"] == "unverified" for c in cands):
            status = "the rejection is reopened and awaits re-verification"
        elif sibling and sibling[-1].get("reason"):
            status = f"the rejection was not reopened ({sibling[-1]['reason']})"
        else:
            status = "the rejection was not reopened"
        out.append(f"  - `{pos}` ({_verdict_label(by_fp[pos])}) vs `{neg}` ({_verdict_label(rej)}): {status}")
    out.append("")
    return out


def reopening_lines(candidates: list[dict]) -> list[str]:
    """
    Rejections that later tool-reproduced evidence reopened, and those it contradicted without
    reopening (candidates.json: `reopened`, `contradicting_evidence`). Nothing when there is neither.
    """
    reopened = [c for c in candidates if c.get("reopened")]
    by_reason: Counter = Counter()
    for c in candidates:
        for reason in {e.get("reason") for e in c.get("contradicting_evidence") or []}:
            by_reason[reason] += 1
    if not reopened and not by_reason:
        return []
    out: list[str] = []
    if reopened:
        times = sum(len(c["reopened"]) for c in reopened)
        awaiting = sum(1 for c in reopened if "resolved" not in c["reopened"][-1])
        final = Counter(c["reopened"][-1]["resolved"]["decision"] for c in reopened if "resolved" in c["reopened"][-1])
        after = ", ".join(f"{final[d]} {d}" for d in ("confirmed", "needs_validation", "rejected") if final[d])
        out.append(
            f"- **Reopened rejections:** {len(reopened)} candidate(s), {times} time(s) in all: a reproduced failure "
            "(or an opposite verdict at the same sink, `sibling_verdict`) arrived after a rejection whose basis "
            "was not a verifier-cited tool output"
            + (f"; verdict after reopening: {after}" if after else "")
            + (f"; {awaiting} still awaiting a verdict" if awaiting else "")
            + "."
        )
        for c in reopened[:50]:
            last = c["reopened"][-1]
            out.append(
                f"  - `{c['fingerprint']}`: rejected as `{last['rejection_class']}` (basis `{last['refutation_basis']}`), "
                f"reopened by `{last['evidence']['source']}` (`{last['evidence']['artifact']}`)"
            )
    if by_reason["checked_rejection"]:
        out.append(
            f"- **Contradicted `checked` rejections:** {by_reason['checked_rejection']} candidate(s): a reproduced "
            "failure (or an opposite verdict at the same sink) arrived after a rejection that cites a refuting tool "
            "output. They stay rejected; both the "
            "tool output and the reproducer need a look."
        )
    if by_reason["harness_unchanged"]:
        out.append(
            f"- Recurred through an unrepaired harness: {by_reason['harness_unchanged']} `harness_induced` "
            "rejection(s) (not reopened: the same harness says nothing new)."
        )
    if by_reason["reopen_limit"]:
        out.append(
            f"- Not reopened again: {by_reason['reopen_limit']} candidate(s) reached the reopening limit "
            "(the harness repair budget)."
        )
    out.append("")
    return out


def shared_decision_point_lines(confirmed: list[dict]) -> list[str]:
    """
    Confirmed findings whose decision point is the same file and line: possibly one defect seen at
    several sinks. Report only; fingerprints and merging do not use it.
    """
    groups: dict[tuple[str, int], list[dict]] = {}
    for r in confirmed:
        dp = r.get("decision_point")
        if isinstance(dp, dict):
            groups.setdefault((normalize_file(dp["file"]), int(dp["line"])), []).append(r)
    shared = {k: v for k, v in groups.items() if len(v) > 1}
    if not shared:
        return []
    out = [
        "Confirmed findings that share a decision point (possibly one defect; they stay separate records):",
        "",
    ]
    for (file_, line), recs in sorted(shared.items()):
        fps = ", ".join(f"`{r['fingerprint']}`" for r in sorted(recs, key=lambda r: r["fingerprint"]))
        out.append(f"- `{file_}:{line}`: {fps}")
    out.append("")
    return out


REFUTATION_BASES = ("checked", "located", "model", "unstated")


def rejection_basis_lines(rejected: list[dict]) -> list[str]:
    """Rejections counted by class and evidence basis; a record without a basis counts as `unstated`."""
    if not rejected:
        return []
    counts = Counter((r["rejection_class"], r.get("refutation_basis") or "unstated") for r in rejected)
    out = [
        "Rejected candidates by class and evidence basis (`checked`: a cited tool output refutes the "
        "candidate; `located`: file and line of the check or dead branch; `model`: reasoning only):",
        "",
        "| Rejection class | " + " | ".join(REFUTATION_BASES) + " |",
        "| :--- | " + " | ".join("---:" for _ in REFUTATION_BASES) + " |",
    ]
    for cls in sorted({c for c, _ in counts}):
        out.append(f"| `{cls}` | " + " | ".join(str(counts[(cls, b)]) for b in REFUTATION_BASES) + " |")
    out.append("")
    return out


def load_inputs(run_dir: Path) -> dict:
    errors = validate_run_dir(run_dir)
    if errors:
        raise ArtifactError("inputs failed validation:\n  " + "\n  ".join(errors))
    raw_findings = load_json_optional(run_dir / "findings.json", [])
    ledger = load_json_strict(run_dir / "coverage-ledger.json")
    return {
        "run_dir": run_dir,
        "meta": load_json_strict(run_dir / "run-metadata.json"),
        "ledger": ledger,
        "wp_meta_runs": load_wp_meta_runs(run_dir, ledger),
        "findings": dedupe_findings_for_report(raw_findings, run_dir=run_dir),
        "candidates": load_json_optional(run_dir / "candidates.json", []),
        "coverage": load_coverage_reports(run_dir),
        "mutation": load_json_optional(run_dir / "workspace/reports/mutation.json", None),
        "capture": load_json_optional(run_dir / "workspace/reports/build_capture.json", None),
        "model": load_json_optional(run_dir / "workspace/reports/phase0_model.json", None),
        "security_props": load_json_optional(run_dir / "workspace/reports/security_props.json", None),
        "merge_notes": load_merge_notes(run_dir),
        "fuzz_security_props": load_fuzz_security_props(run_dir),
        "smoke_reports": load_smoke_reports(run_dir),
        "judge_reports": load_judge_reports(run_dir),
        "phase1_fuzz_reports": load_phase1_fuzz_reports(run_dir),
    }


# Where wp_scheduler.py keeps its tasks; a merged task carries `merge_notes` when its merge was not clean.
WP_SCHEDULE = Path("state/wp_schedule.json")
MERGE_NOTE_ROWS_MAX = 40
MERGE_NOTE_REMOVALS = (
    ("assigns_removed", "`assigns` removed"),
    ("ensures_removed", "`ensures` removed"),
)


def load_merge_notes(run_dir: Path) -> list[dict]:
    """
    What the merges of the run's provers left to say, one item per task of `state/wp_schedule.json` that
    carries `merge_notes` (wp_scheduler.py: `contract_changes` when the merged contract lost a clause or
    could not be compared with the one it replaced, `frame_state` when WP proved the function without a
    frame, `guardrail` when none passed). Read defensively: the file is the scheduler's own state, and
    a run without it, or a task without the key, has nothing to list.
    """
    try:
        state = load_json_optional(run_dir / WP_SCHEDULE, None)
    except ArtifactError:
        return []
    tasks = state.get("tasks") if isinstance(state, dict) else None
    items = tasks.items() if isinstance(tasks, dict) else enumerate(tasks if isinstance(tasks, list) else [])
    out: list[dict] = []
    for tid, task in items:
        notes = task.get("merge_notes") if isinstance(task, dict) else None
        if isinstance(notes, dict) and notes:
            out.append(
                {
                    "task": str(task.get("id") or tid),
                    "function": str(task.get("function") or ""),
                    "notes": notes,
                    "state": task.get("state"),
                    "outcome": task.get("outcome"),
                }
            )
    return sorted(out, key=lambda n: (n["function"], n["task"]))


def _removed_clauses(items: object) -> str:
    """`default: ensures a; ensures b | behavior x: ...` for a `{behavior, clauses}` list of a contract change."""
    parts: list[str] = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        behavior = str(item.get("behavior") or "")
        where = "the contract outside named behaviors" if behavior in ("", "default!") else f"behavior `{behavior}`"
        clauses = [" ".join(str(c).split())[:160] for c in item.get("clauses") or []]
        parts.append(f"{where}: " + ("; ".join(f"`{md_escape(c)}`" for c in clauses) or "clause text not recorded"))
    return " | ".join(parts)


def merge_notes_lines(notes: list[dict] | None) -> list[str]:
    """
    The merges that were accepted but not clean: a merged contract that lost an `ensures`, an `assigns`,
    a behavior or a completeness clause against the contract it replaced (or could not be compared with
    it), a function proved without a frame, a merge no guardrail passed for. A proof of a weaker
    contract is still a proof; the report says what the contract no longer states.
    """
    rows: list[str] = []
    for item in notes or []:
        said: list[str] = []
        raw = item.get("notes")
        note: dict = raw if isinstance(raw, dict) else {}
        changes = note.get("contract_changes")
        if isinstance(changes, dict):
            if changes.get("available") is False:
                said.append(
                    "the merged contract could not be compared with the one it replaced "
                    f"({md_escape(str(changes.get('reason') or 'no reason recorded'))[:200]})"
                )
            for key, label in MERGE_NOTE_REMOVALS:
                if text := _removed_clauses(changes.get(key)):
                    said.append(f"{label} in {text}")
            for key, label in (("behaviors_removed", "behaviors removed"), ("completeness_removed", "removed")):
                gone = [str(x) for x in changes.get(key) or []] if isinstance(changes.get(key), list) else []
                if gone:
                    said.append(f"{label}: " + ", ".join(f"`{md_escape(' '.join(g.split())[:120])}`" for g in gone))
        frame = note.get("frame_state")
        if isinstance(frame, dict):
            had = " (the contract it replaced had one)" if frame.get("baseline_had_assigns") else ""
            said.append(
                "the WP report of the merge does not show a frame for the whole function (`assigns` clause: "
                f"`{md_escape(str(frame.get('assigns_clause')))}`){had}"
            )
        guard = note.get("guardrail")
        if isinstance(guard, dict):
            said.append(
                f"no guardrail pass (`{md_escape(str(guard.get('status')))}`: "
                f"{md_escape(' '.join(str(guard.get('reason') or 'no reason recorded').split()))[:200]})"
            )
        if said:
            # The note is of the last merge of the task; the task may have been queued again or parked since.
            state, outcome = item.get("state"), item.get("outcome")
            if (state is not None and state != "done") or (outcome is not None and outcome != "merged"):
                said.append(
                    f"the task is not a finished merge now (state `{md_escape(str(state))}`, outcome "
                    f"`{md_escape(str(outcome))}`)"
                )
            rows.append(f"- `{md_escape(item.get('function') or item.get('task') or '?')}`: " + "; ".join(said) + ".")
    if not rows:
        return []
    out = [
        f"Merges accepted with a note ({len(rows)}; `merge_notes` of the tasks in `{WP_SCHEDULE.as_posix()}`). "
        "Whatever is credited for these functions is for the contract as merged, which states less than the one "
        "it replaced where a clause is listed as removed:",
        "",
        *rows[:MERGE_NOTE_ROWS_MAX],
    ]
    if len(rows) > MERGE_NOTE_ROWS_MAX:
        out.append(f"- ... and {len(rows) - MERGE_NOTE_ROWS_MAX} more")
    return [*out, ""]


def identity_not_compared(rec: dict) -> list[str]:
    """
    The evidence entries of a finding that say the parent's replay of a counted reproducer could not be
    compared with the candidate's failure (`ledger.py ingest-verifier`, `IDENTITY_NOT_COMPARED`): the
    input failed, but not on a failure that names a statement.
    """
    return [
        str(e.get("description"))
        for e in rec.get("evidence") or []
        if isinstance(e, dict) and str(e.get("description") or "").startswith(IDENTITY_NOT_COMPARED)
    ]


def identity_not_compared_text(rec: dict) -> str | None:
    """One sentence for a finding with such entries: how many of its reproducers, and what that means."""
    notes = identity_not_compared(rec)
    if not notes:
        return None
    return (
        f"for {len(notes)} reproducer(s) the parent's replay failed, but not on a failure that could be compared "
        "with this finding's (no failure report parsed, or one that names no statement), so the replay does not "
        "show that the failure is this finding's; they count because the inputs were recorded on the candidate "
        "before verification (see the evidence in `FINDINGS-DETAIL.md`)"
    )


def load_coverage_reports(run_dir: Path) -> list[dict]:
    """`run_eacsl_fuzz.py coverage` reports by module; an unreadable one is shown as such, not dropped."""
    reports: list[dict] = []
    for path in sorted((run_dir / "workspace/reports/coverage").glob("*.json")):
        try:
            report = load_json_strict(path)
        except ArtifactError:
            report = None
        if not isinstance(report, dict):
            report = {"status": "unreadable"}
        reports.append({**report, "module": str(report.get("module") or path.stem)})
    return reports


def load_smoke_reports(run_dir: Path) -> list[dict]:
    """`harness_smoke.py run` reports from `workspace/reports/smoke/*.json`, sorted by module."""
    smoke_dir = Path(run_dir) / "workspace/reports/smoke"
    if not smoke_dir.is_dir():
        return []
    reports: list[dict] = []
    for path in sorted(smoke_dir.glob("*.json")):
        try:
            report = load_json_strict(path)
        except ArtifactError:
            report = None
        if not isinstance(report, dict):
            report = {"status": "unreadable"}
        reports.append({**report, "module": str(report.get("module") or path.stem)})
    return reports


def load_judge_reports(run_dir: Path) -> list[dict]:
    """`run_eacsl_fuzz.py judge` reports from `workspace/reports/judge/*.json`, sorted by module."""
    judge_dir = Path(run_dir) / "workspace/reports/judge"
    if not judge_dir.is_dir():
        return []
    reports: list[dict] = []
    for path in sorted(judge_dir.glob("*.json")):
        try:
            report = load_json_strict(path)
        except ArtifactError:
            report = None
        if not isinstance(report, dict):
            report = {"status": "unreadable"}
        reports.append({**report, "module": str(report.get("module") or path.stem)})
    return reports


def load_phase1_fuzz_reports(run_dir: Path) -> list[dict]:
    """
    Phase 1 Explore (`mode == "campaign"`, `discovering_step == "explore"` or P4 telemetry/blinding)
    and deep `eacsl-fuzz` (`mode == "eacsl-fuzz"` / `discovering_step == "eacsl_fuzz"`) reports from
    `workspace/reports/fuzz/*.json` and `workspace/reports/eacsl_fuzz/*.json`. Returns `[]` on legacy
    runs that have no Explore/Judge or telemetry data.
    """
    rdir = Path(run_dir)
    judge_mods = {
        path.stem for path in (rdir / "workspace/reports/judge").glob("*.json")
    } if (rdir / "workspace/reports/judge").is_dir() else set()
    reports: list[dict] = []
    for sub in ("workspace/reports/fuzz", "workspace/reports/eacsl_fuzz"):
        d = rdir / sub
        if not d.is_dir():
            continue
        for path in sorted(d.glob("*.json")):
            try:
                report = load_json_strict(path)
            except ArtifactError:
                continue
            if not isinstance(report, dict):
                continue
            mode = report.get("mode")
            if mode not in ("campaign", "eacsl-fuzz"):
                continue
            step = report.get("discovering_step")
            mod = str(report.get("module") or path.stem)
            has_p4_fields = bool(
                step in ("explore", "eacsl_fuzz")
                or mode == "eacsl-fuzz"
                or isinstance(report.get("telemetry"), dict)
                or report.get("blinded_cases")
                or report.get("partial_blinded")
                or report.get("status") in ("blinded", "partial_blinded", "unspent_blinded", "startup_error")
                or mod in judge_mods
            )
            if not has_p4_fields:
                continue
            reports.append({**report, "module": mod})
    return reports


def harness_smoke_lines(reports: list[dict] | None) -> list[str]:
    """
    Harness Smoke Gate summary (P3): startup errors and quarantined cases per module from
    `workspace/reports/smoke/*.json`. Returns `[]` when no smoke reports exist.
    """
    if not reports:
        return []
    lines = [
        "### Harness Smoke Gate",
        "",
        "| Module | Status | Startup | Quarantined cases | Candidate warnings | Wall (s) |",
        "| :--- | :--- | :--- | :--- | :--- | ---: |",
    ]
    startup_notes: list[str] = []
    for r in reports:
        mod = md_escape(str(r.get("module") or "?"))
        status = md_escape(str(r.get("status") or "unknown"))
        raw_startup = r.get("startup")
        startup: dict = raw_startup if isinstance(raw_startup, dict) else {}
        if startup.get("ok") is True:
            startup_cell = "ok"
        elif startup.get("ok") is False:
            eng = startup.get("failing_engine") or "unknown"
            startup_cell = f"failed (`{md_escape(str(eng))}`)"
            reason = md_escape(str(startup.get("reason") or "startup failure"))
            startup_notes.append(f"- `{mod}` startup error (`{md_escape(str(eng))}`): {reason}")
        else:
            startup_cell = "n/a"
        q_cases = [str(c) for c in (r.get("quarantined_cases") or [])]
        w_cases = [str(c) for c in (r.get("candidate_warning_cases") or [])]
        q_cell = ", ".join(q_cases) if q_cases else "none"
        w_cell = ", ".join(w_cases) if w_cases else "none"
        wall = r.get("wall_s")
        wall_cell = f"{wall:.2f}" if isinstance(wall, (int, float)) else "n/a"
        lines.append(f"| `{mod}` | `{status}` | {startup_cell} | {q_cell} | {w_cell} | {wall_cell} |")
    lines.append("")
    if startup_notes:
        lines += ["Startup errors:", "", *startup_notes, ""]
    return lines


def _format_blinded_cases(report: dict) -> str:
    raw_cases = report.get("blinded_cases")
    cases: list = raw_cases if isinstance(raw_cases, list) else []
    ids = [str(c["case"]) for c in cases if isinstance(c, dict) and "case" in c]
    if ids:
        prefix = "partial: " if report.get("partial_blinded") else ""
        return prefix + ", ".join(ids)
    if report.get("status") == "blinded":
        fp = report.get("blinded_fingerprint")
        return f"all (`{md_escape(str(fp))}`)" if fp else "all"
    if report.get("status") == "partial_blinded":
        return "partial"
    return "none"


def phase1_explore_judge_lines(
    fuzz_reports: list[dict] | None,
    judge_reports: list[dict] | None,
) -> list[str]:
    """
    Phase 1 Explore / Judge Breakdown (`P2c`): renders `explore` (execs, coverage, blinded/partial_blinded),
    `judge` (judged, failed, not_judged, batch_state_only), and `eacsl_fuzz` (under `deep`).
    Returns `[]` when neither Explore/Judge nor `eacsl-fuzz` reports exist.
    """
    explore_rows = [
        r for r in (fuzz_reports or []) if r.get("mode") != "eacsl-fuzz" and r.get("discovering_step") != "eacsl_fuzz"
    ]
    eacsl_fuzz_rows = [
        r for r in (fuzz_reports or []) if r.get("mode") == "eacsl-fuzz" or r.get("discovering_step") == "eacsl_fuzz"
    ]
    judge_rows = list(judge_reports or [])
    if not explore_rows and not judge_rows and not eacsl_fuzz_rows:
        return []

    lines = ["### Phase 1 Explore / Judge Breakdown", ""]
    if explore_rows:
        lines += [
            "**Explore:**",
            "",
            "| Module | Status | Executions | Max cov | Blinded |",
            "| :--- | :--- | ---: | ---: | :--- |",
        ]
        for r in sorted(explore_rows, key=lambda x: str(x.get("module") or "")):
            mod = md_escape(str(r.get("module") or "?"))
            status = md_escape(str(r.get("status") or "unknown"))
            raw_tel = r.get("telemetry")
            tel: dict = raw_tel if isinstance(raw_tel, dict) else {}
            execs = tel.get("total_executions")
            max_cov = tel.get("max_cov")
            execs_cell = str(execs) if isinstance(execs, int) else "n/a"
            cov_cell = str(max_cov) if isinstance(max_cov, int) else "n/a"
            lines.append(f"| `{mod}` | `{status}` | {execs_cell} | {cov_cell} | {_format_blinded_cases(r)} |")
        lines.append("")

    if judge_rows:
        lines += [
            "**Judge (E-ACSL):**",
            "",
            "| Module | Status | Judged | Failed | Not judged | Batch-state-only | Blinded |",
            "| :--- | :--- | ---: | ---: | ---: | ---: | :--- |",
        ]
        for r in sorted(judge_rows, key=lambda x: str(x.get("module") or "")):
            mod = md_escape(str(r.get("module") or "?"))
            status = md_escape(str(r.get("status") or "unknown"))
            raw_inp = r.get("inputs")
            inp: dict = raw_inp if isinstance(raw_inp, dict) else {}
            judged = inp.get("judged", 0)
            failed = inp.get("failed", 0)
            not_judged = r.get("not_judged", inp.get("not_judged", 0))
            bso = len(r.get("batch_state_only") or [])
            lines.append(
                f"| `{mod}` | `{status}` | {judged} | {failed} | {not_judged} | {bso} | {_format_blinded_cases(r)} |"
            )
        lines.append("")

    if eacsl_fuzz_rows:
        lines += [
            "**E-ACSL Fuzz (`deep`):**",
            "",
            "| Module | Status | Executions | Max cov | Unspent budget (s) |",
            "| :--- | :--- | ---: | ---: | ---: |",
        ]
        for r in sorted(eacsl_fuzz_rows, key=lambda x: str(x.get("module") or "")):
            mod = md_escape(str(r.get("module") or "?"))
            status = md_escape(str(r.get("status") or "unknown"))
            raw_ef_tel = r.get("telemetry")
            ef_tel: dict = raw_ef_tel if isinstance(raw_ef_tel, dict) else {}
            execs = ef_tel.get("total_executions")
            max_cov = ef_tel.get("max_cov")
            unspent = r.get("unspent_budget_s")
            execs_cell = str(execs) if isinstance(execs, int) else "n/a"
            cov_cell = str(max_cov) if isinstance(max_cov, int) else "n/a"
            unspent_cell = f"{unspent:.1f}" if isinstance(unspent, (int, float)) else "0.0"
            lines.append(f"| `{mod}` | `{status}` | {execs_cell} | {cov_cell} | {unspent_cell} |")
        lines.append("")

    return lines


def verifier_circuit_breaker_lines(candidates: list[dict] | None) -> list[str]:
    """
    Verifier Circuit Breaker summary (P5): count of candidates superseded after harness repair
    (`superseded_by_repair`) vs. verified candidates. Returns `[]` when no candidates were superseded.
    """
    cands = list(candidates or [])
    superseded = [c for c in cands if c.get("status") == "superseded_by_repair"]
    if not superseded:
        return []
    verified = [c for c in cands if c.get("status") == "verified"]
    by_mod: Counter = Counter(str(c.get("module") or "unknown") for c in superseded)
    out = [
        "### Verifier Circuit Breaker",
        "",
        f"- **Superseded after harness repair (`superseded_by_repair`):** {len(superseded)} candidate(s) "
        f"(vs. {len(verified)} verified candidate(s)).",
    ]
    for mod, count in sorted(by_mod.items()):
        reasons = sorted({str(c.get("superseded_reason")) for c in superseded if str(c.get("module") or "unknown") == mod and c.get("superseded_reason")})
        suffix = f": {md_escape(reasons[0])}" if reasons else ""
        out.append(f"  - `{md_escape(mod)}`: {count} superseded{suffix}")
    out.append("")
    return out


def fuzz_reach_lines(reports: list[dict]) -> list[str]:
    """What each corpus executed: reach only, so a reached function is neither safe nor proven."""
    if not reports:
        return ["Fuzz reach was not measured (`pipeline_make.py run coverage`).", ""]
    lines = [
        "Fuzz reach (what each corpus executes on a plain coverage build; this is not evidence of safety):",
        "",
        "| Module | Status | Inputs replayed | Functions reached | Regions covered |",
        "| :--- | :--- | ---: | ---: | ---: |",
    ]
    unreached: list[str] = []
    for r in reports:
        inputs = r.get("inputs") or {}
        totals = r.get("totals") or {}
        fns = totals.get("functions") or {}
        regions = totals.get("regions") or {}
        lines.append(
            f"| `{md_escape(r['module'])}` | `{md_escape(str(r.get('status')))}` "
            f"| {inputs.get('replayed', 0)} / {inputs.get('total', 0)} "
            f"| {fns.get('reached', 0)} / {fns.get('total', 0)} "
            f"| {regions.get('covered', 0)} / {regions.get('total', 0)} |"
        )
        unreached += [
            f"- `{md_escape(str(f.get('function')))}` at `{md_escape(str(f.get('file')))}:{f.get('line')}` ({md_escape(r['module'])})"
            for f in r.get("functions") or []
            if not f.get("executions")
        ]
    lines.append("")
    if unreached:
        lines += [f"Functions no replayed input reached ({len(unreached)}):", ""]
        lines += unreached[:50]
        if len(unreached) > 50:
            lines.append(f"- ... and {len(unreached) - 50} more (see workspace/reports/coverage/)")
        lines.append("")
    return lines


def dynamic_gate_lines(run_dir: Path) -> list[str]:
    """
    The modules the dynamic reach gate holds back from WP (D2, D18): one line each with its entry points
    the corpus never executed. Their fuzz and Eva still run; their planned units are blocked
    (`ledger.py gate-reach`). Nothing when no module is held back.
    """
    gaps = dynamic_gaps(Path(run_dir))
    if not gaps:
        return []
    lines = [
        "### Modules held back from WP by the dynamic reach gate",
        "",
        "Their planned units are blocked (`ledger.py gate-reach`) until the gap closes; their fuzz and Eva ran.",
        "",
    ]
    lines += [
        f"- `{md_escape(module)}`: never executed {md_escape(', '.join(entries))}" for module, entries in gaps.items()
    ]
    lines.append("")
    return lines


def header_api_lines(run_dir: Path) -> list[str]:
    """
    R1: per module of the dynamic reach report (workspace/reports/harness_reach_dynamic.json), the public
    header functions the corpus never executed (`header_api_unexecuted`). They are not entry points, so a
    passing reach gate says nothing about them. Nothing when no module has one.
    """
    try:
        doc = load_json_optional(Path(run_dir) / "workspace/reports/harness_reach_dynamic.json", None)
    except (ArtifactError, OSError, ValueError):
        return []
    rows = doc.get("modules") if isinstance(doc, dict) else None
    if not isinstance(rows, dict):
        return []
    lines: list[str] = []
    for module, row in sorted(rows.items()):
        never = row.get("header_api_unexecuted") if isinstance(row, dict) else None
        if not isinstance(never, dict) or not never.get("count"):
            continue
        names = [str(n) for n in never.get("functions") or []]
        more = f", ... and {never['count'] - len(names)} more" if never["count"] > len(names) else ""
        lines.append(
            f"- `{md_escape(str(module))}`: {never['count']} of {row.get('header_api_functions', '?')} public header "
            f"functions never executed: {md_escape(', '.join(names))}{more}"
        )
    if not lines:
        return []
    return [
        "### Public header functions the corpus never executed",
        "",
        "A function a public header defines (`static inline`) is not an entry point: no reach gate counts it, "
        "so a passing gate does not mean it ran.",
        "",
        *lines,
        "",
    ]


def const_union_rewrite_lines(run_dir: Path) -> list[str]:
    """
    O9: the modules whose E-ACSL build dropped `const` from `static const union` declarations in the E-ACSL
    frontend's text (`compile.const_union_rewrites` of workspace/build/<mod>.build.json). One line, or nothing.
    """
    built: dict[str, int] = {}
    for path in sorted((Path(run_dir) / "workspace/build").glob("*.build.json")):
        try:
            report = load_json_optional(path, None)
        except (ArtifactError, OSError, ValueError):
            continue
        comp = report.get("compile") if isinstance(report, dict) else None
        if not isinstance(comp, dict):
            continue
        n = comp.get("const_union_rewrites")
        if isinstance(n, int) and n > 0 and comp.get("returncode") == 0 and comp.get("engine") == "eacsl":
            built[str(report.get("module") or path.name.removesuffix(".build.json"))] = n
    if not built:
        return []
    shown = ", ".join(f"`{md_escape(m)}` ({n})" for m, n in sorted(built.items()))
    return [
        f"- **E-ACSL `static const union` rewrite:** {len(built)} module(s) were built with `const` dropped from "
        f"their `static const union` declarations (count in parentheses) in the E-ACSL frontend's text only, "
        f"because of an E-ACSL bug (pub/frama-c#2795): E-ACSL did not check those objects as read-only, and "
        f"the E-ACSL binary holds them as writable data. The sanitizer and coverage builds, Eva and WP keep "
        f"`const`. {shown}.",
        "",
    ]


def incomplete_alignof_lines(run_dir: Path) -> list[str]:
    """
    The modules whose E-ACSL build made pointer-alignment checks on opaque handles vacuous
    (`compile.incomplete_alignof` of workspace/build/<mod>.build.json, eacsl_toolchain.rewrite_incomplete_alignof).
    One line, or nothing.
    """
    built: dict[str, tuple[int, list[str]]] = {}
    for path in sorted((Path(run_dir) / "workspace/build").glob("*.build.json")):
        try:
            report = load_json_optional(path, None)
        except (ArtifactError, OSError, ValueError):
            continue
        comp = report.get("compile") if isinstance(report, dict) else None
        if not isinstance(comp, dict) or comp.get("returncode") != 0 or comp.get("engine") != "eacsl":
            continue
        rec = comp.get("incomplete_alignof")
        if isinstance(rec, dict) and rec.get("rewrites"):
            mod = str(report.get("module") or path.name.removesuffix(".build.json"))
            built[mod] = (len(rec.get("checks") or []), [str(t) for t in rec.get("types") or []])
    if not built:
        return []
    shown = ", ".join(
        f"`{md_escape(m)}` ({n}: {md_escape(', '.join(types))})" for m, (n, types) in sorted(built.items())
    )
    return [
        f"- **E-ACSL alignment checks on opaque handles made vacuous:** {len(built)} module(s) were built with "
        "the pointer-alignment checks on types their instrumented file leaves incomplete rewritten to "
        "alignment 1 (count of source assertions and the types in parentheses), because clang rejects "
        "`_Alignof` of an incomplete type (pub/frama-c#2805). Those pointers are assumed aligned, not checked; "
        f"each build result lists the assertions in `incomplete_alignof`. {shown}.",
        "",
    ]


def load_fuzz_security_props(run_dir: Path) -> list[dict]:
    """
    What each fuzzed module's E-ACSL build did with the run's MetAcsl properties, one row per module
    whose report says anything: {module, report, record, warnings, harness_induced}. Read from the
    campaign report workspace/reports/fuzz/<mod>.json (`security_props`, `security_props_warnings`,
    `security_props_harness_induced`, written by run_eacsl_fuzz.py), and from the build report
    workspace/build/<mod>.build.json for a module without a campaign report. The other reports of
    the fuzz directory (replays) are not a module's campaign and are not read. Empty for a run
    without `eacsl` in `meta_engines`: no report has those fields then.
    """
    run_dir = Path(run_dir)
    found: dict[str, tuple[Path, dict]] = {}
    for directory, suffix, mode in (
        ("workspace/reports/fuzz", ".json", "campaign"),
        ("workspace/build", ".build.json", "build"),
    ):
        for path in sorted((run_dir / directory).glob("*" + suffix)):
            module = path.name.removesuffix(suffix)
            if module in found:
                continue  # the campaign's build is the one that was fuzzed
            try:
                report = load_json_optional(path, None)
            except (ArtifactError, OSError, ValueError):
                report = None
            if not isinstance(report, dict):
                report = {}  # unreadable: nothing to print, and a campaign report still hides the build's
            if report.get("mode") in (None, mode):
                found[module] = (path, report)
    rows: list[dict] = []
    for module, (path, report) in sorted(found.items()):
        record = report.get("security_props")
        warnings = report.get("security_props_warnings")
        induced = report.get("security_props_harness_induced")
        row = {
            "module": str(report.get("module") or module),
            "report": path.relative_to(run_dir).as_posix(),
            "record": record if isinstance(record, dict) else {},
            "warnings": [str(w) for w in warnings] if isinstance(warnings, list) else [],
            "harness_induced": [i for i in induced if isinstance(i, dict)] if isinstance(induced, list) else [],
        }
        if row["record"] or row["warnings"] or row["harness_induced"]:
            rows.append(row)
    return rows


# `security_props.status` of a build that checks none of the properties it was given (fuzz_build.py).
FUZZ_META_LOST = ("dropped", "error")


def fuzz_meta_inactive_lines(rows: list[dict]) -> list[str]:
    """
    A warning per module whose fuzz binary lost the MetAcsl properties (`dropped`: the build failed
    with them and was redone without; `error`: the properties file could not be loaded): fuzzing
    checked no security property there, which the absence of a candidate must not hide.
    """
    out: list[str] = []
    for row in rows:
        record = row["record"]
        if record.get("status") not in FUZZ_META_LOST:
            continue
        reason = md_escape(str(record.get("reason") or "no reason recorded"))
        log = md_escape(str(record.get("log") or row["report"]))
        out += [
            "> [!WARNING]",
            f"> MetAcsl run-time checks: NOT ACTIVE for module {md_escape(row['module'])} ({reason}). "
            f"No Layer 3-6 property was checked by fuzzing; see {log}.",
            "",
        ]
    return out


def fuzz_meta_note_lines(rows: list[dict]) -> list[str]:
    """
    The properties a fuzz binary does not check, or checks elsewhere than planned (one line per
    warning of a build that kept its properties), and the precondition failures the harness caused
    itself (`ledger.py ingest-fuzz` makes no candidate of them).
    """
    lines: list[str] = []
    for row in rows:
        if row["record"].get("status") not in FUZZ_META_LOST:
            lines += [f"- MetAcsl run-time checks, {md_escape(row['module'])}: {md_escape(w)}" for w in row["warnings"]]
        lines += [
            f"- {md_escape(str(i.get('property')))} failed in {md_escape(str(i.get('function')))}, called by harness "
            f"function {md_escape(str(i.get('caller')))}: not a finding against the target."
            for i in row["harness_induced"]
        ]
    if not lines:
        return []
    return ["### MetAcsl run-time checks in the fuzz builds", "", *lines, ""]


def open_work(data: dict) -> dict:
    unverified = [c for c in data["candidates"] if c["status"] == "unverified"]
    open_units = [u for u in data["ledger"] if u["status"] in ("planned", "in_progress")]
    return {"unverified": unverified, "open_units": open_units}


def assurance_table(ledger: list[dict]) -> list[str]:
    cols = [
        "covered (unconditional)",
        "covered (with assumptions)",
        "candidate",
        "blocked",
        "planned",
        "in_progress",
        "deferred",
        "out_of_scope",
        "not_applicable",
    ]
    counts: dict[str, Counter[str]] = defaultdict(Counter)
    for u in ledger:
        key = u["status"]
        if key == "covered":
            key = "covered (with assumptions)" if u["assumptions"] else "covered (unconditional)"
        counts[u["obligation_class"]][key] += 1
    lines = ["| Obligation class | " + " | ".join(cols) + " |", "| :--- |" + " ---: |" * len(cols)]
    for cls in CLASSES:
        if cls in counts:
            lines.append(f"| `{cls}` | " + " | ".join(str(counts[cls][c]) for c in cols) + " |")
    total: Counter[str] = Counter()
    for c in counts.values():
        total.update(c)
    lines.append("| **total** | " + " | ".join(f"**{total[c]}**" for c in cols) + " |")
    return lines


CONTRACT_SHAPE_NOT_RECORDED = "not recorded"
# acsl_ast.CONTRACT_SHAPES, then the proofs whose report predates the field.
CONTRACT_SHAPE_ORDER = ("functional", "safety_only", "not_applicable", "unknown", CONTRACT_SHAPE_NOT_RECORDED)
UNCHECKED_CLAUSE_ROWS_MAX = 40


def verdict_limits_section(ledger: list[dict]) -> list[str]:
    """What the WP verdicts did and did not establish, from the limits on their evidence."""
    unexercised: set[str] = set()
    inconclusive: set[str] = set()
    unchecked: set[str] = set()
    trivial: set[str] = set()
    # Per function, not per ledger unit: one proof is the evidence of several obligation classes.
    shapes: dict[str, str] = {}
    never_run: dict[str, dict[str, str]] = {}
    unattributed: dict[str, int] = {}
    # `limits.guardrail` of each unit's latest credited WP result: `not_run` is never a pass.
    no_guardrail: dict[str, str] = {}
    clauses_unreported: set[str] = set()
    frames: dict[str, dict] = {}
    credited = 0
    for u in ledger:
        guard_passed = False
        latest_guard: dict | None = None
        for e in u["evidence"]:
            limits = (e.get("details") or {}).get("limits")
            if e["phase"] != "wp" or not isinstance(limits, dict):
                continue
            credited += 1
            name = f"{u['file']}#{u['function']}"
            guard = limits.get("guardrail")
            if isinstance(guard, dict):
                guard_passed = guard_passed or (latest_guard or {}).get("status") == GUARDRAIL_PASSED_STATUS
                latest_guard = guard
            oracle = limits.get("dynamic_oracle")
            oracle = oracle if isinstance(oracle, dict) else {}
            if oracle.get("exercised") is False:
                unexercised.add(name)
            if "unchecked_clauses" in oracle and not isinstance(oracle["unchecked_clauses"], list):
                clauses_unreported.add(name)
            # The clauses E-ACSL generated no check for: the guardrail passed without executing them.
            clauses = oracle.get("unchecked_clauses")
            for clause in clauses if isinstance(clauses, list) else []:
                if isinstance(clause, dict):
                    reason = " ".join(str(clause.get("reason") or "no reason recorded").split())
                    never_run.setdefault(name, {})[unchecked_clause_text(clause)] = reason
            loose = oracle.get("unattributed")
            if isinstance(loose, list) and loose:
                unattributed[name] = max(unattributed.get(name, 0), len(loose))
            if (limits.get("vacuity") or {}).get("status") == "inconclusive":
                inconclusive.add(name)
            unchecked.update(f"{name} ({c})" for c in limits.get("unchecked_layer_clauses") or [])
            trivial.update(f"{name} ({c})" for c in limits.get("trivial_layer_clauses") or [])
            # A proof carried from an older run records no shape: counted apart, never as safety-only.
            shape = limits.get("contract_shape")
            if isinstance(shape, str) and shape:
                shapes[name] = shape
            else:
                shapes.setdefault(name, CONTRACT_SHAPE_NOT_RECORDED)
            frame = limits.get("frame_only_ensures")
            if isinstance(frame, dict) and frame.get("status") in ("decided", "undecided"):
                frames[name] = frame
        if latest_guard is not None and latest_guard.get("status") != GUARDRAIL_PASSED_STATUS:
            why = " ".join(str(latest_guard.get("reason") or "no reason recorded").split())[:200]
            if latest_guard.get("status") != "not_run":
                why = f"status `{latest_guard.get('status')}`, {why}"
            if guard_passed:
                why += "; an earlier result's guardrail passed, on the contract as it was then"
            no_guardrail[f"{u['file']}#{u['function']}"] = why
    if not credited:
        return []
    out = [
        "Verdict limits:",
        "",
        "- Contract consistency means no prover refuted the contract within its timeout, not that it is satisfiable.",
        "- Trivial-clause detection is syntactic: a tautology it cannot recognize is still credited.",
    ]
    # The semantic reading wins when it decided that every `ensures` follows from the frame alone; an
    # `ensures` it could not derive from the frame is no evidence of a functional contract.
    semantic = {
        name
        for name, f in frames.items()
        if f.get("status") == "decided"
        and f.get("all_frame_only") is True
        and int(f.get("ensures") or 0) > 0
        and shapes.get(name) in ("functional", "safety_only")
    }
    for name in semantic:
        shapes[name] = "safety_only"
    shape_counts = Counter(shapes.values())
    if set(shape_counts) - {CONTRACT_SHAPE_NOT_RECORDED}:
        order = [s for s in CONTRACT_SHAPE_ORDER if s in shape_counts] + sorted(
            set(shape_counts) - set(CONTRACT_SHAPE_ORDER)
        )
        out.append(
            "- Contract shape of the proven functions, read from the contract text (syntactic"
            + (f"; {len(semantic)} `safety_only` by the semantic reading" if semantic else "")
            + "): "
            + ", ".join(f"`{s}` {shape_counts[s]}" for s in order)
            + ". A `safety_only` proof is fully credited for the absence of runtime errors, but its "
            "postconditions state validity, initialization or a constant range at most, so a caller learns "
            "nothing about the result."
        )
    if frames:
        decided = [f for f in frames.values() if f.get("status") == "decided"]
        total = sum(int(f.get("ensures") or 0) for f in decided)
        frame_only = sum(len(f.get("frame_only") or []) for f in decided)
        undecided = len(frames) - len(decided)
        out.append(
            f"- Postconditions that follow from the `requires` and `assigns` alone (semantic, contract refinement "
            f"probe): {frame_only} of {total} `ensures` in {len(decided)} proven functions; the probe could not "
            f"decide for {undecided} function(s). Such a postcondition holds for any body, so it tells a caller "
            "nothing about this one."
        )
    safety_only = {
        f"{name} (semantic)" if name in semantic else name for name, shape in shapes.items() if shape == "safety_only"
    }
    for label, names in (
        ("Proven with a safety-only contract", safety_only),
        ("Proven, but no guardrail input reached the function", unexercised),
        ("Proven, but the guardrail did not report which clauses E-ACSL generated no check for", clauses_unreported),
        ("Contract consistency check inconclusive", inconclusive),
        ("Layer clauses that say nothing about the function", trivial),
        ("Layer clauses whose source could not be read", unchecked),
    ):
        if names:
            shown = ", ".join(f"`{n}`" for n in sorted(names)[:20])
            more = f" and {len(names) - 20} more" if len(names) > 20 else ""
            out.append(f"- {label} ({len(names)}): {shown}{more}")
    if no_guardrail:
        out.append(
            f"- Proven, but the latest credited WP result had no E-ACSL guardrail pass ({len(no_guardrail)}): "
            "these proofs stand on WP alone, not exercised at runtime."
        )
        out += [
            f"  - `{name}`: {md_escape(why)}" for name, why in sorted(no_guardrail.items())[:UNCHECKED_CLAUSE_ROWS_MAX]
        ]
        if len(no_guardrail) > UNCHECKED_CLAUSE_ROWS_MAX:
            out.append(f"  - ... and {len(no_guardrail) - UNCHECKED_CLAUSE_ROWS_MAX} more (`limits.guardrail`)")
    if never_run:
        total = sum(len(c) for c in never_run.values())
        out.append(
            f"- Proven, and the guardrail passed, but the dynamic oracle never executed {total} clause(s) of "
            f"{len(never_run)} function(s): E-ACSL generated no check for them, so they rest on the WP proof alone."
        )
        rows = [(name, text, reason) for name in sorted(never_run) for text, reason in sorted(never_run[name].items())]
        for name, text, reason in rows[:UNCHECKED_CLAUSE_ROWS_MAX]:
            out.append(f"  - `{name}`: {md_escape(text)} ({md_escape(reason[:200])})")
        if len(rows) > UNCHECKED_CLAUSE_ROWS_MAX:
            out.append(
                f"  - ... and {len(rows) - UNCHECKED_CLAUSE_ROWS_MAX} more (`limits.dynamic_oracle.unchecked_clauses` "
                "of the WP evidence in `coverage-ledger.json`)"
            )
    if unattributed:
        shown = ", ".join(f"`{n}` ({unattributed[n]})" for n in sorted(unattributed)[:20])
        more = f" and {len(unattributed) - 20} more" if len(unattributed) > 20 else ""
        out.append(
            "- E-ACSL ignored annotations in the guardrail build that could not be tied to a function, so whether a "
            f"clause of the proven function was among them is not known ({len(unattributed)}): {shown}{more}"
        )
    out.append("")
    return out


TRUST_ROWS_MAX = 60


RELOCATED_NAMES_MAX = 12


def _code_names(names: list, limit: int = RELOCATED_NAMES_MAX) -> str:
    shown = ", ".join(f"`{md_escape(str(n))}`" for n in names[:limit])
    return shown + (f" and {len(names) - limit} more" if len(names) > limit else "")


def relocated_props_lines(props: dict, ledger: list[dict] | None = None) -> list[str]:
    """
    The properties security_props.py checks somewhere else than where the threat model declares the
    sink (`properties[*].relocated`, a wrapper sink with `checked_at`): where the property is no longer
    generated, where it is checked instead and through which call, the properties that check stands
    for, and what the model does not show. With the ledger, the units still keyed on a property moved
    away from their function (no `seed --refresh` since) are listed: their status is about a property
    no run generates any more.
    """
    moved = [p for p in props.get("properties") or [] if isinstance(p, dict) and isinstance(p.get("relocated"), dict)]
    if not moved:
        return []
    out = ["### Properties checked somewhere else than at the calls of their sink", ""]
    for prop in moved:
        rec = prop["relocated"]
        name, wrapper = str(prop.get("name")), str(rec.get("wrapper"))
        callers = [str(c) for c in rec.get("not_generated_at") or []]
        out.append(
            f"- `{md_escape(name)}`: not generated at the {len(callers)} caller(s) of `{md_escape(wrapper)}`"
            + (f" ({_code_names(callers)})" if callers else "")
            + f"; checked inside `{md_escape(wrapper)}` instead, before it hands the buffer over."
        )
        for site in rec.get("checked_at") or []:
            if not isinstance(site, dict):
                continue
            targets = site.get("candidates") or site.get("inner_sinks") or []
            out.append(
                f"  - Checked before the {md_escape(str(site.get('kind') or 'direct'))} call "
                f"`{md_escape(str(site.get('call')))}` at `{md_escape(str(site.get('loc')))}`"
                + (f", which can dispatch to {_code_names(targets)}" if site.get("kind") == "indirect" else "")
                + "."
            )
        stands_for = [
            f"{s.get('property')} in {s.get('function')}" for s in rec.get("superseded") or [] if isinstance(s, dict)
        ]
        if stands_for:
            out.append(f"  - That check stands for {_code_names(stands_for)}, which MetAcsl is not given there.")
        others = [
            f"{o.get('call')} at {o.get('loc')}" for o in rec.get("other_indirect_calls") or [] if isinstance(o, dict)
        ]
        if others:
            out.append(f"  - Other calls through a pointer in the wrapper, which get no check: {_code_names(others)}.")
        out += [
            f"  - {md_escape(str(e)[:1].upper() + str(e)[1:])}."
            for e in rec.get("evidence") or []
            if str(e).startswith("not shown")
        ]
    if ledger:
        retired = sorted(
            str(u.get("coverage_id"))
            for u in ledger
            if any(str(r).startswith(f"{PROPERTY_RELOCATED}:") for r in u.get("unresolved") or [])
        )
        if retired:
            out.append(
                f"- {len(retired)} unit(s) had results on a property before it moved and are retired "
                f"({_code_names(retired)}): no property of their class is generated at these functions any more. "
                "They read `blocked` in the ledger, which keeps their earlier evidence; nothing is left to prove there."
            )
        where = relocated_properties(props)
        stale = sorted(
            f"{u.get('coverage_id')} ({', '.join(names)})"
            for u in ledger
            if u.get("status") != "out_of_scope"
            and (
                names := sorted(
                    n
                    for n in (u.get("bookkeeping") or {}).get("security_properties") or []
                    if n in where.get(f"{u.get('file')}#{u.get('function')}", {})
                )
            )
        )
        if stale:
            out.append(
                f"- **{len(stale)} ledger unit(s) are still keyed on a property that is no longer generated at their "
                f"function** ({_code_names(stale)}): their status says nothing about the check that replaced it. "
                "`ledger.py seed --refresh` retires them or plans them again."
            )
    return [*out, ""]


# How many rows a list of the MetAcsl sections shows, and how many callers one of its rows names.
META_LIST_MAX = 30
META_CALLERS_MAX = 8
# The warnings about a threat-model item (security_props.WARNING_PREFIX).
_NEW_KIND_PREFIXES = ("asset ", "invariant ", "call rule ")
_ITEM_PREFIXES = ("secret ", "auth gate ", "output sink ", *_NEW_KIND_PREFIXES)
_INITIALIZER_WARNING = "the model's call sites do not say which calls are initializers"
# What a `\writing` property's `declared_callees` lists mean, in the order they are shown.
_DECLARED_CALLEE_KINDS = (
    ("set_assigns", "its `assigns` holds a set, which stops MetAcsl: the callers are left out of the property"),
    ("no_assigns", "it has no `assigns`: MetAcsl checks nothing it writes"),
    ("unknown", "its declaration could not be read"),
)
# The evidence of a unit the ledger refused a credit (scripts/ledger.py).
_LEDGER_BARS = frozenset(
    {
        "wp_meta_unchecked",
        "wp_meta_check_not_reported",
        "wp_meta_simplified_eva_open",
        "wp_meta_initializers_unknown",
        "eva_no_goal_credit_withdrawn",
    }
)
_METACSL_SET_ASSIGNS = "metacsl_set_assigns"


def _capped(rows: list[str], where: str) -> list[str]:
    """At most META_LIST_MAX rows, and where the others are."""
    if len(rows) <= META_LIST_MAX:
        return rows
    return [*rows[:META_LIST_MAX], f"- ... and {len(rows) - META_LIST_MAX} more ({where})"]


def _names(items: list[str]) -> str:
    """Code-quoted names, at most META_CALLERS_MAX of them."""
    shown = ", ".join(f"`{md_escape(i)}`" for i in items[:META_CALLERS_MAX])
    return shown + (f" and {len(items) - META_CALLERS_MAX} more" if len(items) > META_CALLERS_MAX else "")


def security_props_lines(props: dict | None, ledger: list[dict] | None = None) -> list[str]:
    """
    What security_props.json says is not checked. From its warnings: the threat-model items that became
    no property (a returned secret, a name the build lacks, an unusable sink parameter, a text the
    generator refused); a forwarding sink whose property was kept (`output sink <name>: it forwards to
    ...`), checked at a weaker place than the threat model allows; the properties of the newer kinds
    generated with a warning; and the properties blind to what a declared function writes. From the
    properties: the sites each leaves `unchecked` and its `declared_callees`.
    Then the properties it moved (`relocated_props_lines`).
    """
    if not isinstance(props, dict):
        return []
    properties = [p for p in props.get("properties") or [] if isinstance(p, dict)]
    names = {str(p.get("name")) for p in properties}
    items: list[str] = []
    kept: list[str] = []
    warned: list[str] = []
    declared: list[str] = []
    for raw in props.get("warnings") or []:
        w = str(raw)
        if not w.startswith(_ITEM_PREFIXES):
            continue
        if _is_kept_forwarding_sink(w):
            kept.append(w)
        elif _is_declared_callee_warning(w, names):
            declared.append(w)
        elif w.startswith(_NEW_KIND_PREFIXES) and _kept_its_property(w, names):
            warned.append(w)
        else:
            items.append(w)
    out: list[str] = []
    for heading, intro, found in (
        ("### Threat-model items without a property", None, items),
        (
            "### Output sinks whose property is checked before their buffer is complete",
            "Each of these sinks has its property, checked at its own calls: it forwards to a declared sink, "
            "and one of its calls through a pointer also reaches a function that reaches no declared sink.",
            kept,
        ),
        ("### Properties generated with a warning", None, warned),
        (
            "### Properties that do not see what declared functions write",
            "Each of these properties exists. MetAcsl takes what a declared function writes from its `assigns`.",
            declared,
        ),
    ):
        if not found:
            continue
        out += [heading, ""]
        if intro:
            out += [intro, ""]
        out += _capped([f"- {md_escape(w)}" for w in found], "`workspace/reports/security_props.json`, `warnings`")
        out.append("")
    out += _unchecked_lines(properties) + _declared_callee_lines(properties)
    return out + relocated_props_lines(props, ledger)


def _is_kept_forwarding_sink(warning: str) -> bool:
    """security_props.py's warning for a forwarding sink it could not move to the innermost sinks."""
    head, sep, rest = warning.partition(": ")
    return bool(sep) and head.startswith("output sink ") and rest.startswith("it forwards to ")


def _names_a_property(head: str, names: set[str]) -> bool:
    """`<item> (<property>)`, the head of a warning about a property that was generated."""
    return head.endswith(")") and head.rpartition(" (")[2][:-1] in names


def _is_declared_callee_warning(warning: str, names: set[str]) -> bool:
    """security_props.py's warning about the declared functions a `\\writing` property calls."""
    head, _, rest = warning.partition(": ")
    return _names_a_property(head, names) and (
        rest.startswith("the declared function(s) ") or " assign(s) a set (`assigns " in rest
    )


def _kept_its_property(warning: str, names: set[str]) -> bool:
    """
    Whether a warning about an asset, invariant or call rule leaves its property generated. Any other
    form counts as an item without a property: the report then claims less than was checked, never more.
    """
    head, _, rest = warning.partition(": ")
    return (
        _names_a_property(head, names)
        or rest.startswith("the predicate names ")
        or rest.endswith(("MetAcsl targets them all by name", ": that name is left out"))
        or (head.endswith((" writers", " readers", " scope")) and rest.endswith("nor called by one"))
    )


def _unchecked_lines(properties: list[dict]) -> list[str]:
    """Per property, what its `unchecked` says it does not check: function, callee, line and reason."""
    rows: list[str] = []
    for prop in properties:
        for site in prop.get("unchecked") or []:
            if not isinstance(site, dict):
                continue
            call = f", call of `{md_escape(str(site['callee']))}`" if site.get("callee") else ""
            line = f" at line {site['line']}" if call and site.get("line") else ""
            reason = md_escape(str(site.get("reason") or "not checked"))
            where = f"`{md_escape(str(prop.get('name')))}` in `{md_escape(str(site.get('function')))}`"
            rows.append(f"- {where}{call}{line}: {reason}")
    if not rows:
        return []
    source = "`workspace/reports/security_props.json`, `unchecked`"
    return ["### Where a property does not check its function", "", *_capped(rows, source), ""]


def _declared_callee_lines(properties: list[dict]) -> list[str]:
    """Per `\\writing` property, the declared functions it cannot see into, with their callers."""
    rows: list[str] = []
    for prop in properties:
        declared = prop.get("declared_callees")
        if not isinstance(declared, dict):
            continue
        for kind, meaning in _DECLARED_CALLEE_KINDS:
            for entry in declared.get(kind) or []:
                if isinstance(entry, dict):
                    callers = _names([str(c) for c in entry.get("callers") or []]) or "none"
                    rows.append(
                        f"- `{md_escape(str(prop.get('name')))}`: `{md_escape(str(entry.get('callee')))}`, {meaning}; "
                        f"callers: {callers}"
                    )
    if not rows:
        return []
    where = "`workspace/reports/security_props.json`, `declared_callees`"
    return ["### Declared functions the write-checking properties call", "", *_capped(rows, where), ""]


def initializer_flags_lines(props: dict | None) -> list[str]:
    """
    A warning when the Phase 0 model does not say which calls are initializers: MetAcsl generates no
    instance of several contexts at such a call, and nothing else checks it there.
    """
    if not isinstance(props, dict):
        return []
    flags = props.get("initializer_flags")
    unknown = isinstance(flags, dict) and flags.get("known") is False
    said = next((str(w) for w in props.get("warnings") or [] if str(w).startswith(_INITIALIZER_WARNING)), None)
    if not unknown and said is None:
        return []
    text = said or f"{_INITIALIZER_WARNING}: MetAcsl generates no instance of some properties at such a call"
    return ["> [!WARNING]", f"> MetAcsl initializer calls: NOT CHECKED. {md_escape(text)}.", ""]


def ledger_bar_lines(ledger: list[dict]) -> list[str]:
    """The open units the ledger refused a credit, each with its latest refusal and the reason it gives."""
    rows: list[str] = []
    for u in sorted(ledger, key=lambda unit: str(unit.get("coverage_id"))):
        if u.get("status") in ("covered", "candidate", "out_of_scope", "not_applicable"):
            continue
        bars = [e for e in u.get("evidence") or [] if isinstance(e, dict) and e.get("result") in _LEDGER_BARS]
        if bars:
            rows.append(
                f"- `{md_escape(str(u.get('coverage_id')))}` (`{md_escape(str(u.get('status')))}`), "
                f"`{bars[-1]['result']}`: {md_escape(str(bars[-1].get('summary') or ''))}"
            )
    if not rows:
        return []
    return ["### Units the ledger refused a credit", "", *_capped(rows, "`coverage-ledger.json`, `evidence`"), ""]


def load_wp_meta_runs(run_dir: Path, ledger: list[dict]) -> list[dict]:
    """
    The latest WP report of each function with a MetAcsl unit (`workspace/reports/wp/<fn>.json`,
    else `workspace/reports/wp/work/<slug>_<fn>.json` for its file) when MetAcsl stopped the run on a
    set-valued `assigns` or in-code check rows stayed unnamed: {function, file, stopped, callees, unnamed}.
    """
    functions = {
        (str(u.get("file")), str(u.get("function"))) for u in ledger if u.get("obligation_class") in METACSL_CLASSES
    }
    if not functions:
        return []
    rdir = Path(run_dir)
    wp_index = WpReportIndex(discover_wp_reports(rdir), run_dir=rdir)
    rows: list[dict] = []
    for file, function in sorted(functions):
        report = wp_index.get(file, function) or {}
        failure = report.get("metacsl_failure")
        section = report.get("security_props")
        unnamed = section.get("code_checks_unnamed") if isinstance(section, dict) else None
        stopped = report.get("reason") == _METACSL_SET_ASSIGNS
        if stopped or unnamed:
            rows.append(
                {
                    "function": function,
                    "file": file,
                    "stopped": stopped,
                    "callees": [str(c) for c in (failure.get("callees") or [])] if isinstance(failure, dict) else [],
                    "unnamed": [u for u in unnamed or [] if isinstance(u, dict)],
                }
            )
    return rows


def _unnamed_check_text(entry: dict) -> str:
    """
    One row of a WP report's `code_checks_unnamed`: a property whose in-code check the source audit
    refused (`property`, `reason`), or a line whose check rows do not match the checks written there.
    """
    if entry.get("property"):
        at = f" at line {entry['line']}" if entry.get("line") else ""
        why = md_escape(str(entry.get("reason") or "not named"))
        return f"`{md_escape(str(entry['property']))}`{at} ({why})"
    return f"line {entry.get('line')} ({entry.get('checks')} check(s), {entry.get('rows')} row(s))"


def wp_meta_run_lines(runs: list[dict]) -> list[str]:
    """What load_wp_meta_runs found: each WP run MetAcsl stopped, and each with check rows left unnamed."""
    rows: list[str] = []
    for run in runs:
        where = f"`{md_escape(run['function'])}` (`{md_escape(run['file'])}`)"
        if run["stopped"]:
            named = f"called function(s) {_names(run['callees'])}" if run["callees"] else "no callee could be named"
            rows.append(
                f"- {where}: MetAcsl stopped on an `assigns` that holds a set (`{_METACSL_SET_ASSIGNS}`), {named}. "
                "Write one `assigns` term per location; running it again does not help."
            )
        if run["unnamed"]:
            lines = ", ".join(_unnamed_check_text(u) for u in run["unnamed"])
            rows.append(
                f"- {where}: in-code check rows stayed unnamed (`code_checks_unnamed`) at {lines}, so they credit "
                "no property."
            )
    if not rows:
        return []
    return ["### WP runs MetAcsl stopped or left unnamed", "", *_capped(rows, "`workspace/reports/wp/`"), ""]


def trust_lines(model: dict | None) -> list[str]:
    """
    The trust boundary (scripts/trust.py, plan step I7): the threat model and CodeQL used, then each
    unit's entry points with their trust and the rule that decided it. Empty without a model with trust.
    """
    if not isinstance(model, dict) or not isinstance(model.get("trust"), dict):
        return []
    block = model["trust"]
    tm = block.get("threat_model") or {}
    cq = block.get("codeql") or {}
    functions = model.get("functions") or {}
    tm_text = f"`{tm.get('status')}`" + (f" (`{md_escape(str(tm.get('path')))}`)" if tm.get("path") else "")
    if tm.get("status") != "ok" and tm.get("reason"):
        tm_text += f": {md_escape(str(tm['reason']))}"
    cq_text = f"`{cq.get('status')}`" + (f", {cq.get('facts')} fact(s)" if cq.get("facts") is not None else "")
    out = ["### Trust boundary", "", f"- **Threat model:** {tm_text}", f"- **CodeQL:** {cq_text}"]
    by_source = (block.get("summary") or {}).get("by_source") or {}
    if by_source:
        out.append(
            "- **Functions:** " + ", ".join(f"{n} {k.replace(':', ' by ')}" for k, n in sorted(by_source.items()))
        )
    rows: list[str] = []
    for unit, u in sorted((model.get("units") or {}).items()):
        if u.get("test"):
            continue
        api: list[str] = [*(u.get("entry_points") or []), *(u.get("embedded_api") or [])]
        for fid in dict.fromkeys(api):
            t = (functions.get(fid) or {}).get("trust")
            if not isinstance(t, dict):
                continue
            also = [x for x in t.get("sources") or [] if x != t.get("source")]
            source = t.get("source", "") + (f" (also {', '.join(also)})" if also else "")
            if t.get("overridden"):
                source += f" (overrides {', '.join(t['overridden'])})"
            rows.append(
                f"| `{md_escape(unit)}` | `{md_escape(fid)}` | {t.get('value')}"
                f"{' (boundary)' if t.get('boundary') else ''} | {md_escape(source)} |"
            )
    if rows:
        out += ["", "| Unit | Entry point | Trust | Source |", "| :--- | :--- | :--- | :--- |"]
        out += rows[:TRUST_ROWS_MAX]
        if len(rows) > TRUST_ROWS_MAX:
            out.append(f"| ... | {len(rows) - TRUST_ROWS_MAX} more (see workspace/reports/phase0_model.json) | | |")
    out.append("")
    return out


SEMANTIC_FILES_MAX = 5


def semantic_flags_lines(capture: dict | None) -> list[str]:
    """
    Non-test link units built with compiler flags that alter signed-overflow, signedness, or
    struct-layout semantics relative to Frama-C `-machdep gcc_x86_64` (Tier 2 Part A). Empty when
    `build_capture.json` is absent or no non-test unit carries any active semantic flag.
    """
    if not isinstance(capture, dict):
        return []
    units = capture.get("units") or {}
    rows: list[tuple[str, dict]] = []
    for name, u in sorted(units.items()):
        if not isinstance(u, dict) or u.get("test"):
            continue
        sem = u.get("semantic_flags") or []
        for entry in sorted(sem, key=lambda e: str(e.get("flag") or "")):
            if isinstance(entry, dict) and entry.get("flag"):
                rows.append((name, entry))
    if not rows:
        return []
    out = [
        "### Semantic compiler flags",
        "",
        "> [!WARNING]",
        "> The non-test link unit(s) below were built with compiler flags that change signed-overflow, "
        "signedness, or struct-layout semantics. Frama-C (`-machdep gcc_x86_64`, RTE/Eva/WP) and Phase 1 "
        "builds (E-ACSL, Clang sanitizers) analysed them without these flags: `signed_overflow` alarms "
        "under `-fwrapv`/`-fno-strict-overflow` may be false positives, and layout/signedness flags may "
        "cause alarms and proofs to refer to a different ABI.",
        "",
        "| Unit | Flag | Category | Scope | Affected files |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]
    for name, entry in rows:
        files = [str(f) for f in entry.get("files") or []]
        shown = ", ".join(f"`{md_escape(f)}`" for f in files[:SEMANTIC_FILES_MAX])
        if len(files) > SEMANTIC_FILES_MAX:
            shown += f" (+ {len(files) - SEMANTIC_FILES_MAX} more)"
        out.append(
            f"| `{md_escape(name)}` | `{md_escape(str(entry['flag']))}` | "
            f"`{md_escape(str(entry.get('category') or ''))}` | `{md_escape(str(entry.get('scope') or ''))}` | "
            f"{shown or 'none'} |"
        )
    out.append("")
    return out


def parse_loss_lines(model: dict | None) -> list[str]:
    """
    Non-test Frama-C-parsed units that emitted C-level `[kernel:...]` parse-loss warnings under
    Phase 0's `-no-annot` parse (Tier 2 Part B). Returns body lines to place under `### Phase 0 parse`,
    or `[]` when no non-test parsed unit has `has_parse_loss == True`.
    """
    if not isinstance(model, dict):
        return []
    units = model.get("units") or {}
    affected: list[tuple[str, dict]] = []
    benign_filtered = 0
    for name, u in sorted(units.items()):
        if not isinstance(u, dict) or u.get("test"):
            continue
        parse = u.get("parse") or {}
        if parse.get("status") != "ok":
            continue
        pw = parse.get("warnings")
        if not isinstance(pw, dict):
            continue
        benign_filtered += sum(int(v) for v in ((pw.get("attrs_unknown") or {}).get("benign") or {}).values())
        if pw.get("has_parse_loss"):
            affected.append((name, pw))
    if not affected:
        return []
    out = [
        "Non-test link units parsed by Frama-C (`-no-annot`) with C-level parse-loss or silent "
        "AST-alteration warnings:",
        "",
        "| Unit | asm:clobber | Semantic / unknown attrs | Unclassified [kernel:...] categories (project / total) |",
        "| :--- | ---: | :--- | :--- |",
    ]
    for name, pw in affected:
        asm = pw.get("asm_clobber") or {}
        asm_cell = f"{asm.get('project_count', 0)} / {asm.get('count', 0)}" if asm.get("count") else "0"
        attrs = pw.get("attrs_unknown") or {}
        attr_parts = [f"`{md_escape(k)}` ({v})" for k, v in sorted((attrs.get("semantic") or {}).items())]
        attr_parts += [
            f"`{md_escape(k)}` ({v}, unclassified)" for k, v in sorted((attrs.get("unclassified") or {}).items())
        ]
        attr_cell = ", ".join(attr_parts) or "none"
        uncls = pw.get("unclassified_categories") or {}
        cat_parts = [
            f"`{md_escape(cat)}` ({info.get('project_count', 0)}/{info.get('count', 0)})"
            for cat, info in sorted(
                uncls.items(), key=lambda kv: (-int((kv[1] or {}).get("project_count") or 0), kv[0])
            )
            if isinstance(info, dict)
        ]
        cat_cell = ", ".join(cat_parts) or "none"
        out.append(f"| `{md_escape(name)}` | {asm_cell} | {attr_cell} | {cat_cell} |")
    note = "Phase 0 parses with `-no-annot` (C-level parse losses only; annotation warnings are checked in Eva/WP)."
    if benign_filtered > 0:
        note += f" {benign_filtered} benign GCC/Clang attribute warning(s) were filtered out."
    out += ["", note, ""]
    return out


def fallback_lines(model: dict | None, ledger: list[dict]) -> list[str]:
    """
    Link units Frama-C could not parse (decision D2): their call graph comes from GCC, they are fuzzed
    with the sanitizers, and their Eva and WP units are deferred (`callgraph_fallback: ...` in the
    ledger). One row per unit: Frama-C's first error and what was deferred. Units the GCC fallback could
    not parse either (`unparsed`) come first, with both first errors. With `--alias`, the model's Alias
    narrowing is summarized after it. Non-test parsed units with Phase 0 `-no-annot` C parse-loss
    warnings are listed under the same heading. Empty when none of those applies.
    """
    if not isinstance(model, dict):
        return []
    units = model.get("units") or {}
    functions = model.get("functions") or {}
    fallback = {
        name: str((u.get("parse") or {}).get("error") or "no error recorded")
        for name, u in sorted(units.items())
        if isinstance(u, dict) and (u.get("parse") or {}).get("status") == "gcc_fallback"
    }
    # Units the GCC fallback could not parse either: no call graph at all, so nothing of them is analysed.
    unparsed = {
        name: (
            str((u.get("parse") or {}).get("error") or "no error recorded"),
            str((u.get("parse") or {}).get("gcc_error") or "no error recorded"),
        )
        for name, u in sorted(units.items())
        if isinstance(u, dict) and (u.get("parse") or {}).get("status") == "unparsed"
    }
    raw_alias = model.get("alias")
    alias: dict = raw_alias if isinstance(raw_alias, dict) else {}
    parse_loss = parse_loss_lines(model)
    if not fallback and not unparsed and not alias.get("enabled") and not parse_loss:
        return []
    out = ["### Phase 0 parse", ""]
    if unparsed:
        out += [
            "Link units neither Frama-C nor the GCC fallback could parse: their own parse contributed no "
            "function or call edge to the model, so code only they compile was neither fuzzed nor analysed.",
            "",
            "| Unit | First Frama-C error | First GCC error |",
            "| :--- | :--- | :--- |",
        ]
        out += [
            f"| `{md_escape(name)}` | {md_escape(err)[:240]} | {md_escape(gcc)[:240]} |"
            for name, (err, gcc) in unparsed.items()
        ]
        out.append("")
    if fallback:
        deferred: dict[tuple[str, str], list[dict]] = defaultdict(list)
        for u in ledger:
            if u.get("status") == "deferred" and str((u.get("unresolved") or [""])[0]).startswith(CALLGRAPH_FALLBACK):
                deferred[(str(u.get("file")), str(u.get("function")))].append(u)
        out += [
            "Link units Frama-C could not parse: their call graph comes from GCC (`-fcallgraph-info`), they are "
            "fuzzed with the sanitizers, and their Eva and WP work is deferred.",
            "",
            "| Unit | First Frama-C error | Functions | Deferred units |",
            "| :--- | :--- | ---: | :--- |",
        ]
        for name, error in fallback.items():
            fns = {
                (str(f.get("file")), str(f.get("name"))) for f in functions.values() if name in (f.get("units") or [])
            }
            classes = Counter(str(u.get("obligation_class")) for key in fns for u in deferred.get(key, []))
            shown = ", ".join(f"{n} `{c}`" for c, n in sorted(classes.items())) or "none"
            out.append(f"| `{md_escape(name)}` | {md_escape(error)[:240]} | {len(fns)} | {shown} |")
        out.append("")
    if alias.get("enabled"):
        sites = alias.get("sites") or {}
        text = ", ".join(f"{n} {k}" for k, n in sorted(sites.items())) or "no indirect site"
        out += [
            f"- **Alias narrowing** (`--alias`): module `{alias.get('module')}`; indirect sites by reason: {text}; "
            f"{alias.get('dropped_candidates', 0)} type-match candidate(s) dropped.",
            "",
        ]
    out += parse_loss
    return out


def concurrency_lines(ledger: list[dict]) -> list[str]:
    """
    One sentence per link unit that starts threads (`bookkeeping.concurrent`, set by `ledger.py
    seed`): Eva and WP analyse each function as if no other thread ran, so their results there
    assume sequential execution.
    """
    modules = sorted(
        {str(u.get("module") or "unknown") for u in ledger if (u.get("bookkeeping") or {}).get("concurrent")}
    )
    if not modules:
        return []
    out = ["Concurrency:", ""]
    out += [
        f"- `{md_escape(m)}` starts threads: its Eva and WP results assume sequential execution "
        "(no interleaving with its other threads was analysed)."
        for m in modules
    ]
    out.append("")
    return out


def model_only_lines(ledger: list[dict]) -> list[str]:
    """
    The functions only Frama-C's configuration compiles (`bookkeeping.model_only`, from the DAG's
    `model_only`): Eva and WP results on them describe code the real build does not contain, and no
    fuzz harness runs them.
    """
    marked: dict[str, str] = {}
    for u in ledger:
        why = (u.get("bookkeeping") or {}).get("model_only")
        if why:
            marked.setdefault(f"{u.get('function') or 'unknown'} ({u.get('file') or '?'})", str(why))
    if not marked:
        return []
    out = ["Functions the real build does not compile:", ""]
    out += [f"- {md_escape(fn)}: {md_escape(why)}." for fn, why in sorted(marked.items())]
    out.append("")
    return out


def spec_quality_section(data: dict) -> list[str]:
    """
    Mutation-based specification quality (COINS/KBSpec) plus the evaluation-duality
    split of open units into prover-limited vs spec-limited. Empty when no
    mutation.json exists (the check is opt-in: scripts/mutation_check.py).
    """
    out: list[str] = []
    mutation = data.get("mutation")
    if isinstance(mutation, dict) and mutation.get("totals"):
        t = mutation["totals"]
        out += ["### Specification quality (mutation check)", ""]
        out.append(
            f"- Functions checked: {t.get('functions', 0)}; contract mutants: {t.get('spec_mutants', 0)} "
            f"({t.get('equivalent', 0)} equivalent -> completeness {t.get('completeness')}); "
            f"implementation mutants: {t.get('impl_mutants', 0)} ({t.get('rejected', 0)} rejected -> "
            f"precision {t.get('precision')})"
        )
        if "trivial_body_checked" in t:
            accepted = t.get("trivial_body_accepted_functions") or []
            line = (
                f"- Trivial-stub check: {t.get('trivial_body_checked', 0)} functions checked, "
                f"{len(accepted)} accept a body that does nothing"
            )
            if accepted:
                line += ": " + ", ".join(f"`{fn}`" for fn in accepted) + " (their contracts constrain no result)"
            out.append(line)
        unchecked = sorted(fn for fn, f in (mutation.get("functions") or {}).items() if f.get("error"))
        if t.get("preprocessing_failed") or unchecked:
            line = f"- Mutants that failed to preprocess (setup, not the contract): {t.get('preprocessing_failed', 0)}"
            if unchecked:
                line += "; not checked: " + ", ".join(f"`{fn}`" for fn in unchecked)
            out.append(line)
        out.append("")
        for fn, f in sorted((mutation.get("functions") or {}).items()):
            if f.get("completeness") is None and f.get("precision") is None:
                continue
            line = (
                f"- `{fn}`: completeness {f.get('completeness')} (spec mutants {f.get('spec_mutants')}, "
                f"equivalent {f.get('equivalent')}), precision {f.get('precision')} "
                f"(impl mutants {f.get('impl_mutants')}, rejected {f.get('rejected')})"
            )
            if "trivial_body_rejected" in f:
                stub = f["trivial_body_rejected"]
                line += f", trivial stub rejected: {'n/a' if stub is None else ('yes' if stub else 'no')}"
            out.append(line)
        out.append("")
    # Evaluation duality: an open unit is prover-limited (tool/verifier limit) or
    # spec-limited (the contract genuinely does not hold) — read from its WP report.
    run_dir = data.get("run_dir")
    ledger = data.get("ledger") or []
    open_units = [u for u in ledger if u.get("status") not in ("covered", "excluded", "candidate")]
    counts: Counter = Counter()
    if run_dir is not None and open_units:
        rdir = Path(run_dir)
        wp_index = WpReportIndex(discover_wp_reports(rdir), run_dir=rdir)
        for u in open_units:
            fn = str(u.get("function") or "")
            u_file = str(u.get("file") or "")
            if not u_file:
                cid = str(u.get("coverage_id") or "")
                if "#" in cid:
                    u_file = cid.split("#", 1)[0]
            rep = wp_index.get(u_file, fn) if fn else None
            counts[classify_open_unit(rep)] += 1
    # Proofs a prover gave up on because they need an inductive lemma it may not write (prover brief, Step B: Inductive Lemmas).
    lemma_gap_fns = sorted(
        {
            str(u.get("function") or "?")
            for u in open_units
            if any(
                (ev.get("details") or {}).get("gap_kind") == INDUCTIVE_LEMMA_GAP
                for ev in u.get("evidence") or []
                if isinstance(ev, dict)
            )
        }
    )
    if counts or lemma_gap_fns:
        out += ["### Open units: prover-limited vs spec-limited", ""]
        for kind in ("prover_limited", "spec_limited", "unknown"):
            if counts.get(kind):
                out.append(f"- **{kind}**: {counts[kind]}")
        if lemma_gap_fns:
            out.append(
                f"- **inductive lemma required**: {len(lemma_gap_fns)} function(s): "
                + ", ".join(f"`{fn}`" for fn in lemma_gap_fns)
            )
        out.append("")
    return out


def render_report(data: dict) -> str:
    meta, ledger = data["meta"], data["ledger"]
    run_dir = data.get("run_dir")
    findings = dedupe_findings_for_report(data["findings"], run_dir=run_dir)
    work = open_work(data)
    confirmed = sorted(
        (r for r in findings if r["verdict"] == "confirmed"),
        key=lambda r: (SEVERITY_ORDER[r["severity"]], r["fingerprint"]),
    )
    needs = [r for r in findings if r["verdict"] == "needs_validation"]
    rejected = [r for r in findings if r["verdict"] == "rejected"]
    src = meta["source_ref"]

    out: list[str] = ["# Frama-C Verification Report", ""]
    out += ["## 1. Run status and scope", ""]
    status_line = meta["run_status"]
    if meta["run_status"] == "incomplete":
        status_line += f" (reason: {meta['incomplete_reason']})"
    out += [
        f"- **Run:** `{meta['run_id']}` of `{meta['repo']}`",
        f"- **Status:** **{status_line}**",
        f"- **Target:** `{meta['target']}`",
        f"- **Source ref:** {src['vcs']} `{src['commit'] or 'n/a'}`"
        + (" (dirty worktree)" if src.get("dirty") else ""),
        f"- **Profile:** `{meta['profile']}`; **scope:** {', '.join(f'`{p}`' for p in meta['scope_paths']) or 'whole target'}; **budget:** {meta['budget'] if meta['budget'] is not None else 'not set'}",
        f"- **Execution:** sandboxed, local only (outer: `{meta['sandbox']['outer']}`, inner: `{meta['sandbox']['inner']}`)",
        f"- **Prior runs used:** {', '.join(meta['prior_runs']) or 'none (this run does not imply that a single pass exhausts the target)'}",
        "",
    ]
    partial = meta["run_status"] != "complete" or meta["profile"] == "quick" or meta["scope_paths"]
    if partial:
        out.append("> [!WARNING]")
        out.append(
            "> This is a partial pass. "
            + ("It is not complete; " if meta["run_status"] != "complete" else "")
            + ("the quick profile coarsens coverage; " if meta["profile"] == "quick" else "")
            + ("only the listed scope paths were in scope; " if meta["scope_paths"] else "")
            + "do not read the absence of findings outside the covered units as evidence of safety."
        )
        out.append("")
    fuzz_meta = data.get("fuzz_security_props") or []
    out += fuzz_meta_inactive_lines(fuzz_meta)
    out += initializer_flags_lines(data.get("security_props"))
    if work["unverified"]:
        out.append(
            f"**{len(work['unverified'])} candidate(s) have not been independently verified.** They are not findings and are listed here only so the gap is visible:"
        )
        out.append("")
        for c in work["unverified"][:50]:
            out.append(f"- `{c['fingerprint']}` ({c['origin']}, proposed {c['proposed_verdict']})")
        if len(work["unverified"]) > 50:
            out.append(f"- ... and {len(work['unverified']) - 50} more (see candidates.json)")
        out.append("")
    if work["open_units"]:
        out.append(f"**{len(work['open_units'])} coverage unit(s) are still planned or in progress.**")
        out.append("")
    out += trust_lines(data.get("model"))
    out += security_props_lines(data.get("security_props"), ledger)
    out += ledger_bar_lines(ledger)
    out += wp_meta_run_lines(data.get("wp_meta_runs") or [])
    out += fuzz_meta_note_lines(fuzz_meta)
    out += semantic_flags_lines(data.get("capture"))
    out += fallback_lines(data.get("model"), ledger)

    out += ["## 2. Summary", ""]
    sev = Counter(r["severity"] for r in confirmed)
    covered = [u for u in ledger if u["status"] == "covered"]
    cond = [u for u in covered if u["assumptions"]]
    blocked = [u for u in ledger if u["status"] == "blocked"]

    wp_units = [
        u for u in covered if any(e.get("phase") == "wp" and e.get("discharging", True) for e in u.get("evidence", []))
    ]
    eva_units = [
        u
        for u in covered
        if u not in wp_units
        and any(e.get("phase") == "eva" and e.get("discharging", True) for e in u.get("evidence", []))
    ]
    # Security obligations security_props.py decided from the model (a sink handed string literals).
    static_units = [
        u
        for u in covered
        if u not in wp_units
        and u not in eva_units
        and any(e.get("phase") == "static" and e.get("discharging") for e in u.get("evidence", []))
    ]
    other_covered = len(covered) - len(wp_units) - len(eva_units) - len(static_units)
    proof_breakdown = f" ({len(wp_units)} proven by WP, {len(eva_units)} discharged by Eva"
    if static_units:
        proof_breakdown += f", {len(static_units)} decided from the model"
    proof_breakdown += f", {other_covered} other)" if other_covered else ")"

    out += [
        f"- **Confirmed findings:** {len(confirmed)}"
        + (" (" + ", ".join(f"{sev[s]} {s}" for s in SEVERITY_ORDER if sev[s]) + ")" if confirmed else ""),
        f"- **Needs validation:** {len(needs)} (no severity; exact blockers listed)",
        f"- **Rejected candidates:** {len(rejected)} (retained to suppress repeated claims)",
        f"- **Blocked units:** {len(blocked)}",
        f"- **Proof coverage:** {len(covered) - len(cond)} unit(s) proven unconditionally, {len(cond)} proven under open assumptions, out of {len(ledger)} unit(s){proof_breakdown}",
    ]
    carried = {
        (u["file"], u["function"])
        for u in covered
        if any(e.get("result") == "carried_forward_reproven" for e in u.get("evidence", []))
    }
    if carried:
        out.append(f"- Carried forward from earlier runs and re-proven: {len(carried)} function(s)")
    out.append("")
    out += rejection_basis_lines(rejected)
    out += reopening_lines(data["candidates"])
    out += verifier_circuit_breaker_lines(data["candidates"])
    out += sink_conflict_lines(data["findings"], data["candidates"])
    out += decision_point_basis_lines([*confirmed, *needs])
    by_fp = {r["fingerprint"]: r for r in data["findings"]}

    out += ["## 3. Confirmed findings", ""]
    if not confirmed:
        out += ["No confirmed findings.", ""]
    else:
        out += [
            "| Severity | Title | Location | Reachability | Observed result |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ]
        for r in confirmed:
            out.append(
                f"| {r['severity']} | {md_escape(r['title'])} | {loc(r, run_dir)} | `{r['reachability']}` | {md_escape(r['reproducers'][0]['observed_result'])[:160]} |"
            )
        out.append("")
        blind = [r for r in confirmed if identity_not_compared(r)]
        if blind:
            out += [
                f"**{len(blind)} of {len(confirmed)} confirmed finding(s) count a reproducer whose failure identity "
                "was not compared**: the parent's replay of the input failed, but not on a failure that could be "
                "compared with the finding's (no failure report parsed, or one that names no statement), so the "
                "replay does not show that the failure is the finding's. Each is marked below: "
                + ", ".join(f"`{r['fingerprint']}`" for r in blind)
                + ".",
                "",
            ]
        for r in confirmed:
            related_fps = r.get("_related_fingerprints") or []
            fp_suffix = f" (also merged: {', '.join(f'`{f}`' for f in related_fps)})" if related_fps else ""
            out += [
                f"### {md_escape(r['title'])}",
                "",
                f"- **Fingerprint:** `{r['fingerprint']}`{fp_suffix}",
                f"- **Location:** {loc(r, run_dir)}; failing property `{md_escape(r['property']['kind'])}`: `{md_escape(r['property']['predicate'])}`",
                f"- **Root cause:** {md_escape(r['root_cause'])}",
                *([f"- **Decision point:** {dp}"] if (dp := decision_point_text(r)) else []),
                *([f"- **Earlier verdict:** {pv}"] if (pv := prior_verdict_text(r)) else []),
                *([f"- **Conflicting verdict:** {cv}"] if (cv := conflict_text(r, by_fp)) else []),
                *([f"- **Failure identity not compared:** {ni}"] if (ni := identity_not_compared_text(r)) else []),
                f"- **Reproduce:** `{md_escape(r['reproducers'][0]['command'])}` with `{r['reproducers'][0]['input']}`",
                f"- **Severity rationale:** {md_escape(r['severity_rationale'])}",
                f"- **Fix:** {md_escape(r['remediation']['summary'])} (invariant: {md_escape(r['remediation']['invariant'])})",
                "",
            ]
        out += shared_decision_point_lines(confirmed)

    out += ["## 4. Needs validation", ""]
    if not needs:
        out += ["No open leads.", ""]
    else:
        out += ["| Title | Location | Blockers | Next step |", "| :--- | :--- | :--- | :--- |"]
        for r in needs:
            plan = r["validation_plan"].get("local") or r["validation_plan"].get("owner")
            out.append(
                f"| {md_escape(r['title'])} | {loc(r, run_dir)} | {md_escape('; '.join(r['blockers']))} | {md_escape(plan)} |"
            )
        out.append("")

    out += ["## 5. Assurance summary", ""]
    out += assurance_table(ledger)
    out.append("")
    kinds = Counter(a["kind"] for u in covered for a in u["assumptions"])
    if kinds:
        out.append("Open assumptions on covered units:")
        out.append("")
        for k, n in sorted(kinds.items()):
            out.append(f"- `{k}`: {n}")
        experimental = sum(
            1 for u in covered if any(a["description"] == WP_EXPERIMENTAL_MODEL_ASSUMPTION for a in u["assumptions"])
        )
        if experimental:
            out.append(f"- of these, {experimental} unit(s) {WP_EXPERIMENTAL_MODEL_ASSUMPTION}")
        out.append("")
    out += verdict_limits_section(ledger)
    out += merge_notes_lines(data.get("merge_notes"))
    out += concurrency_lines(ledger)
    out += model_only_lines(ledger)
    if run_dir:
        out += const_union_rewrite_lines(Path(run_dir))
        out += incomplete_alignof_lines(Path(run_dir))
    out += spec_quality_section(data)

    out += ["## 6. Coverage gaps", ""]
    blocked = [u for u in ledger if u["status"] == "blocked"]
    if blocked:
        out.append(f"Blocked units ({len(blocked)}):")
        out.append("")
        for u in blocked[:50]:
            out.append(f"- `{u['coverage_id']}`: {md_escape('; '.join(u['unresolved']))[:240]}")
        if len(blocked) > 50:
            out.append(f"- ... and {len(blocked) - 50} more (see coverage-ledger.json)")
        out.append("")
    reasons = Counter(
        (u["status"], u["unresolved"][0])
        for u in ledger
        if u["status"] in ("deferred", "out_of_scope", "not_applicable")
    )
    if reasons:
        out.append("Units not worked in this run:")
        out.append("")
        for (st, reason), n in sorted(reasons.items()):
            out.append(f"- {n} `{st}`: {md_escape(reason)}")
        out.append("")
    if not blocked and not reasons:
        out += ["No blocked, deferred, or out-of-scope units.", ""]
    out += fuzz_reach_lines(data.get("coverage") or [])
    if data.get("run_dir"):
        out += dynamic_gate_lines(Path(data["run_dir"]))
        out += header_api_lines(Path(data["run_dir"]))
    out += harness_smoke_lines(data.get("smoke_reports"))
    out += phase1_explore_judge_lines(data.get("phase1_fuzz_reports"), data.get("judge_reports"))

    hardening = [h for u in ledger for h in u.get("bookkeeping", {}).get("hardening", [])]
    if hardening:
        out += ["## 7. Hardening notes (not findings)", ""]
        out += [f"- {md_escape(h)}" for h in sorted(set(hardening))]
        out.append("")

    out += [
        "## Artifacts",
        "",
        "- `findings.json`, `coverage-ledger.json`, `candidates.json`, `run-metadata.json`",
        "- `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md`, `report.sarif`",
        "- Raw tool output: `workspace/reports/`",
        "",
    ]
    return "\n".join(out)


def _trace_lines(rec: dict) -> list[str]:
    lines = []
    for t in rec.get("trace", []):
        lines.append(
            f"1. **{t['kind']}** `{t['file']}:{t['line']}` in `{t['function']}`: {md_escape(t['description'])}"
        )
    return lines


def _evidence_lines(rec: dict) -> list[str]:
    return [f"- [{e['phase']}] `{e['tool_output']}`: {md_escape(e['description'])}" for e in rec["evidence"]]


def related_candidates_line(record: dict, candidates: list[dict]) -> str | None:
    """
    `Related candidates: ...` for a finding whose candidate names related candidates (D1b: another engine
    reports the same reproducer, see ledger.py link-related). None when there are none.
    """
    keys = {record["fingerprint"], *(record.get("_related_fingerprints") or [])}
    names: list[str] = []
    for cand in candidates:
        if cand.get("fingerprint") in keys or keys & set(cand.get("resolved_fingerprints") or []):
            for link in cand.get("related") or []:
                if link["fingerprint"] not in names:
                    names.append(link["fingerprint"])
    if not names:
        return None
    return "Related candidates: " + ", ".join(f"`{name}`" for name in names)


def render_findings_detail(findings: list[dict], run_dir: Path | None = None) -> str:
    deduped = dedupe_findings_for_report(findings, run_dir=run_dir)
    by_fp = {r["fingerprint"]: r for r in findings}
    candidates = load_json_optional(run_dir / "candidates.json", []) if run_dir is not None else []
    confirmed = sorted(
        (r for r in deduped if r["verdict"] == "confirmed"),
        key=lambda r: (SEVERITY_ORDER[r["severity"]], r["fingerprint"]),
    )
    out = ["# Confirmed Findings: Detail", ""]
    if not confirmed:
        return "\n".join(out + ["No confirmed findings.", ""])
    for r in confirmed:
        related_fps = r.get("_related_fingerprints") or []
        fp_suffix = f" (also merged: {', '.join(f'`{f}`' for f in related_fps)})" if related_fps else ""
        related_line = related_candidates_line(r, candidates)
        out += [
            f"## {md_escape(r['title'])}",
            "",
            f"- **Fingerprint:** `{r['fingerprint']}`{fp_suffix}",
            *([f"- {related_line}"] if related_line else []),
            f"- **Severity:** {r['severity']} ({md_escape(r['severity_rationale'])})",
            f"- **Reachability:** `{r['reachability']}`",
            f"- **Location:** {loc(r, run_dir)}",
            f"- **Failing property:** `{md_escape(r['property']['kind'])}`: `{md_escape(r['property']['predicate'])}`",
            "",
            md_escape(r["description"]),
            "",
            f"**Root cause.** {md_escape(r['root_cause'])}",
            "",
            *([f"**Decision point.** {dp}", ""] if (dp := decision_point_text(r)) else []),
            *([f"**Conflicting verdict.** {cv}", ""] if (cv := conflict_text(r, by_fp)) else []),
            *(
                [f"**Failure identity not compared.** {ni[0].upper()}{ni[1:]}.", ""]
                if (ni := identity_not_compared_text(r))
                else []
            ),
            f"**Intended behavior.** {md_escape(r['intended_behavior'])}",
            "",
            "**Trace.**",
            "",
            *_trace_lines(r),
            "",
            f"**Harness.** `{r['harness']['file']}` entry `{r['harness']['entry_function']}`; contract respected. {md_escape(r['harness']['notes'])}",
            "",
            "**Reproducers.**",
            "",
        ]
        for rep in r["reproducers"]:
            out += [
                f"- `{rep['input']}` ({rep['size_bytes']} bytes, sha256 `{rep['sha256']}`)",
                f"  - command: `{md_escape(rep['command'])}`",
                f"  - observed: {md_escape(rep['observed_result'])}",
            ]
        out += [
            "",
            "**Evidence.**",
            "",
            *_evidence_lines(r),
            "",
            f"**Remediation.** {md_escape(r['remediation']['summary'])}",
            "",
            f"Invariant to enforce: {md_escape(r['remediation']['invariant'])}",
            "",
        ]
        if r["remediation"]["fix_patch"]:
            out += [f"Candidate fix patch (not applied): `{r['remediation']['fix_patch']}`", ""]
        out += [
            f"_Verified by `{r['verifier']['agent_id']}` ({r['verifier']['method']}): {md_escape(r['verifier']['notes'])}_",
            "",
        ]
    return "\n".join(out)


def render_needs_validation(findings: list[dict], run_dir: Path | None = None) -> str:
    deduped = dedupe_findings_for_report(findings, run_dir=run_dir)
    by_fp = {r["fingerprint"]: r for r in findings}
    needs = [r for r in deduped if r["verdict"] == "needs_validation"]
    out = [
        "# Needs Validation",
        "",
        "Prioritized leads without severity. Each names the exact fact that blocked confirmation.",
        "",
    ]
    if not needs:
        return "\n".join(out + ["No open leads.", ""])
    for r in needs:
        out += [
            f"## {md_escape(r['title'])}",
            "",
            f"- **Fingerprint:** `{r['fingerprint']}`",
            f"- **Origin:** `{r['origin']}`; **reachability:** `{r['reachability']}`",
            f"- **Location:** {loc(r, run_dir)}",
            f"- **Property:** `{md_escape(r['property']['kind'])}`: `{md_escape(r['property']['predicate'])}`",
            "",
            md_escape(r["description"]),
            "",
            f"**Claimed root cause.** {md_escape(r['claimed_root_cause'])}",
            "",
            *([f"**Decision point.** {dp}", ""] if (dp := decision_point_text(r)) else []),
            *([f"**Conflicting verdict.** {cv}", ""] if (cv := conflict_text(r, by_fp)) else []),
            "**Trace.**",
            "",
            *_trace_lines(r),
            "",
            "**Blockers.**",
            "",
            *[f"- {md_escape(b)}" for b in r["blockers"]],
            "",
            "**Validation plan.**",
            "",
        ]
        if "local" in r["validation_plan"]:
            out.append(f"- Local: {md_escape(r['validation_plan']['local'])}")
        if "owner" in r["validation_plan"]:
            out.append(f"- Owner-observed: {md_escape(r['validation_plan']['owner'])}")
        out += ["", "**Evidence.**", "", *_evidence_lines(r), ""]
    return "\n".join(out)


def render_sarif(findings: list[dict], run_dir: Path | None = None) -> dict:
    deduped = dedupe_findings_for_report(findings, run_dir=run_dir)
    records = [r for r in deduped if r["verdict"] in ("confirmed", "needs_validation")]
    rules: dict[str, dict] = {}
    results = []
    for r in records:
        rule_id = "framac/" + r["property"]["kind"].strip().lower().replace(" ", "_")
        rules.setdefault(
            rule_id, {"id": rule_id, "shortDescription": {"text": f"Frama-C property kind: {r['property']['kind']}"}}
        )
        props = {"verdict": r["verdict"], "reachability": r["reachability"]}
        if not_compared := identity_not_compared(r):
            # Reproducers counted although the parent's replay could not be compared with the candidate's failure.
            props["failureIdentityNotCompared"] = len(not_compared)
        if r["verdict"] == "confirmed":
            props["severity"] = r["severity"]
            sev = r["severity"].lower()
            if sev in ("critical", "high"):
                level = "error"
            elif sev == "medium":
                level = "warning"
            elif sev == "low":
                level = "note"
            else:
                level = "error"
        else:
            level = "warning"
        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": f"{r['title']}: {r['description']}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": r["location"]["file"]},
                            "region": {"startLine": r["location"]["line"]},
                        },
                        "logicalLocations": [{"name": r["location"]["function"], "kind": "function"}],
                    }
                ],
                "partialFingerprints": {"framacFingerprint/v1": r["fingerprint"]},
                "properties": props,
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "framac-pipeline",
                        "informationUri": "https://frama-c.com/",
                        "rules": [rules[k] for k in sorted(rules)],
                    }
                },
                "results": results,
            }
        ],
    }


def generate(run_dir: Path, out_dir: Path) -> dict:
    data = load_inputs(run_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "report_md": out_dir / "REPORT.md",
        "findings_detail_md": out_dir / "FINDINGS-DETAIL.md",
        "needs_validation_md": out_dir / "NEEDS-VALIDATION.md",
        "sarif": out_dir / "report.sarif",
    }
    rdir = data.get("run_dir")
    paths["report_md"].write_text(render_report(data), encoding="utf-8")
    paths["findings_detail_md"].write_text(render_findings_detail(data["findings"], rdir), encoding="utf-8")
    paths["needs_validation_md"].write_text(render_needs_validation(data["findings"], rdir), encoding="utf-8")
    paths["sarif"].write_text(json.dumps(render_sarif(data["findings"], rdir), indent=2) + "\n", encoding="utf-8")
    work = open_work(data)
    return {
        **{k: str(v) for k, v in paths.items()},
        "run_status": data["meta"]["run_status"],
        "unverified_candidates": len(work["unverified"]),
        "open_units": len(work["open_units"]),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Derive REPORT.md, FINDINGS-DETAIL.md, NEEDS-VALIDATION.md and report.sarif."
    )
    parser.add_argument("--run-dir", type=Path, default=Path("."))
    parser.add_argument("--out-dir", type=Path, default=None)
    args = parser.parse_args()
    try:
        res = generate(args.run_dir, args.out_dir or args.run_dir)
    except ArtifactError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        return 1
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
