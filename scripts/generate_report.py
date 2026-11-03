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
from framac_common import ArtifactError, load_json_optional, load_json_strict  # noqa: E402
from validate_artifacts import validate_run_dir  # noqa: E402
from workspace_overlay import map_work_to_baseline_line  # noqa: E402

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
CLASSES = ["rte", "l2_termination", "l3_frame", "l4_auth", "l5_output", "l6_secret"]


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


def load_inputs(run_dir: Path) -> dict:
    errors = validate_run_dir(run_dir)
    if errors:
        raise ArtifactError("inputs failed validation:\n  " + "\n  ".join(errors))
    raw_findings = load_json_optional(run_dir / "findings.json", [])
    return {
        "run_dir": run_dir,
        "meta": load_json_strict(run_dir / "run-metadata.json"),
        "ledger": load_json_strict(run_dir / "coverage-ledger.json"),
        "findings": dedupe_findings_for_report(raw_findings, run_dir=run_dir),
        "candidates": load_json_optional(run_dir / "candidates.json", []),
    }


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

    out += ["## 2. Summary", ""]
    sev = Counter(r["severity"] for r in confirmed)
    covered = [u for u in ledger if u["status"] == "covered"]
    cond = [u for u in covered if u["assumptions"]]
    blocked = [u for u in ledger if u["status"] == "blocked"]

    wp_units = [
        u
        for u in covered
        if any(e.get("phase") == "wp" and e.get("discharging", True) for e in u.get("evidence", []))
    ]
    eva_units = [
        u
        for u in covered
        if u not in wp_units
        and any(e.get("phase") == "eva" and e.get("discharging", True) for e in u.get("evidence", []))
    ]
    other_covered = len(covered) - len(wp_units) - len(eva_units)
    if other_covered:
        proof_breakdown = f" ({len(wp_units)} proven by WP, {len(eva_units)} discharged by Eva, {other_covered} other)"
    else:
        proof_breakdown = f" ({len(wp_units)} proven by WP, {len(eva_units)} discharged by Eva)"

    out += [
        f"- **Confirmed findings:** {len(confirmed)}"
        + (" (" + ", ".join(f"{sev[s]} {s}" for s in SEVERITY_ORDER if sev[s]) + ")" if confirmed else ""),
        f"- **Needs validation:** {len(needs)} (no severity; exact blockers listed)",
        f"- **Rejected candidates:** {len(rejected)} (retained to suppress repeated claims)",
        f"- **Blocked units:** {len(blocked)}",
        f"- **Proof coverage:** {len(covered) - len(cond)} unit(s) proven unconditionally, {len(cond)} proven under open assumptions, out of {len(ledger)} unit(s){proof_breakdown}",
        "",
    ]

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
        for r in confirmed:
            related_fps = r.get("_related_fingerprints") or []
            fp_suffix = f" (also merged: {', '.join(f'`{f}`' for f in related_fps)})" if related_fps else ""
            out += [
                f"### {md_escape(r['title'])}",
                "",
                f"- **Fingerprint:** `{r['fingerprint']}`{fp_suffix}",
                f"- **Location:** {loc(r, run_dir)}; failing property `{md_escape(r['property']['kind'])}`: `{md_escape(r['property']['predicate'])}`",
                f"- **Root cause:** {md_escape(r['root_cause'])}",
                f"- **Reproduce:** `{md_escape(r['reproducers'][0]['command'])}` with `{r['reproducers'][0]['input']}`",
                f"- **Severity rationale:** {md_escape(r['severity_rationale'])}",
                f"- **Fix:** {md_escape(r['remediation']['summary'])} (invariant: {md_escape(r['remediation']['invariant'])})",
                "",
            ]

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
        out.append("")

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


def render_findings_detail(findings: list[dict], run_dir: Path | None = None) -> str:
    deduped = dedupe_findings_for_report(findings, run_dir=run_dir)
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
        out += [
            f"## {md_escape(r['title'])}",
            "",
            f"- **Fingerprint:** `{r['fingerprint']}`{fp_suffix}",
            f"- **Severity:** {r['severity']} ({md_escape(r['severity_rationale'])})",
            f"- **Reachability:** `{r['reachability']}`",
            f"- **Location:** {loc(r, run_dir)}",
            f"- **Failing property:** `{md_escape(r['property']['kind'])}`: `{md_escape(r['property']['predicate'])}`",
            "",
            md_escape(r["description"]),
            "",
            f"**Root cause.** {md_escape(r['root_cause'])}",
            "",
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
