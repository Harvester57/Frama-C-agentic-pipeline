#!/usr/bin/env python3
"""
Validators for the pipeline's shared artifacts (stdlib only).

Subcommands:
  findings      <findings.json>       [--run-dir DIR]
  candidates    <candidates.json>
  ledger        <coverage-ledger.json> [--run-dir DIR]
  metadata      <run-metadata.json>
  snapshot      <snapshot-manifest.json> [--run-dir DIR]
  agent-result  <result.json>
  run-dir       <run-dir>             (all present artifacts + cross-file consistency)

Each check runs the JSON Schema contract in schemas/ and then semantic checks
that a schema cannot express (state table, fingerprint consistency, trace
ordering, severity caps, safe paths, evidence existence, cross-file links).

Exit code 0 when valid, 1 when errors were found, 2 on usage/IO problems.
Validator success proves format and consistency only, not that a claim is true.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fingerprint import is_valid_fingerprint  # noqa: E402
from framac_common import (  # noqa: E402
    ArtifactError,
    is_safe_agent_id,
    is_safe_relative_path,
    load_agent_result_json,
    load_json_strict,
    wp_limits_problem,
)
from minischema import MAX_ERRORS, Validator, load_schema  # noqa: E402

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def schema_dir() -> Path:
    here = Path(__file__).resolve().parent
    for candidate in (here.parent / "schemas", Path("/opt/framac-pipeline/schemas")):
        if candidate.is_dir():
            return candidate
    raise ArtifactError("schemas/ directory not found")


_SCHEMAS: dict[str, dict] = {}


def get_schema(name: str) -> dict:
    if name not in _SCHEMAS:
        _SCHEMAS[name] = load_schema(schema_dir() / f"{name}.schema.json")
    return _SCHEMAS[name]


class Errors(list):
    def add(self, msg: str) -> None:
        if len(self) < MAX_ERRORS:
            self.append(msg)


def _path_ok(errors: Errors, where: str, value: str | None) -> None:
    if value is not None and not is_safe_relative_path(value):
        errors.add(f"{where}: unsafe or non-relative path {value!r}")


def _exists(errors: Errors, where: str, run_dir: Path | None, value: str | None) -> None:
    if run_dir is not None and value is not None and is_safe_relative_path(value):
        if not (run_dir / value).is_file():
            errors.add(f"{where}: referenced file does not exist under run dir: {value}")


# ---------------------------------------------------------------- findings

SEVERITY_CAP_INTERNAL = {"medium", "low"}


def check_trace(errors: Errors, where: str, trace: list[dict]) -> None:
    kinds = [t.get("kind") for t in trace]
    if len(kinds) == 1:
        if kinds[0] not in ("entrypoint", "sink"):
            errors.add(f"{where}: a one-entry trace must be 'entrypoint' or 'sink'")
        return
    if kinds[0] != "entrypoint" or kinds[-1] != "sink" or any(k != "propagation" for k in kinds[1:-1]):
        errors.add(
            f"{where}: multi-entry trace must start with 'entrypoint', end with 'sink', and use 'propagation' in between"
        )


def validate_findings(data, run_dir: Path | None = None) -> Errors:
    errors = Errors()
    for e in Validator(get_schema("findings")).errors(data):
        errors.add(e)
    if errors or not isinstance(data, list):
        return errors

    seen = set()
    fps = [r.get("fingerprint") for r in data]
    if fps != sorted(fps):
        errors.add("$: records must be sorted by fingerprint")
    for idx, rec in enumerate(data):
        where = f"$[{idx}]"
        fp = rec["fingerprint"]
        if fp in seen:
            errors.add(f"{where}.fingerprint: duplicate fingerprint {fp}")
        seen.add(fp)
        if not is_valid_fingerprint(fp):
            errors.add(f"{where}.fingerprint: not a <file>#<function>::<kind>::<hash> fingerprint")
        elif f"#{rec['location']['function']}::" not in fp:
            errors.add(f"{where}.fingerprint: function part does not match location.function")
        _path_ok(errors, f"{where}.location.file", rec["location"]["file"])
        for t_idx, step in enumerate(rec.get("trace", [])):
            _path_ok(errors, f"{where}.trace[{t_idx}].file", step["file"])
        if "trace" in rec:
            check_trace(errors, f"{where}.trace", rec["trace"])
        for e_idx, ev in enumerate(rec["evidence"]):
            _path_ok(errors, f"{where}.evidence[{e_idx}].tool_output", ev["tool_output"])
            _exists(errors, f"{where}.evidence[{e_idx}].tool_output", run_dir, ev["tool_output"])
        if rec["verdict"] == "confirmed":
            if rec["reachability"] == "internal_api" and rec["severity"] not in SEVERITY_CAP_INTERNAL:
                errors.add(f"{where}.severity: internal_api reachability caps severity at medium")
            _path_ok(errors, f"{where}.harness.file", rec["harness"]["file"])
            _path_ok(errors, f"{where}.remediation.fix_patch", rec["remediation"]["fix_patch"])
            for r_idx, rep in enumerate(rec["reproducers"]):
                rw = f"{where}.reproducers[{r_idx}]"
                _path_ok(errors, f"{rw}.input", rep["input"])
                if run_dir is not None and is_safe_relative_path(rep["input"]):
                    f = run_dir / rep["input"]
                    if not f.is_file():
                        errors.add(f"{rw}.input: reproducer file does not exist under run dir")
                    else:
                        blob = f.read_bytes()
                        if hashlib.sha256(blob).hexdigest() != rep["sha256"]:
                            errors.add(f"{rw}.sha256: does not match reproducer contents")
                        if len(blob) != rep["size_bytes"]:
                            errors.add(f"{rw}.size_bytes: does not match reproducer size")
    return errors


# -------------------------------------------------------------- candidates


def validate_candidates(data) -> Errors:
    errors = Errors()
    for e in Validator(get_schema("candidates")).errors(data):
        errors.add(e)
    if errors:
        return errors
    seen = set()
    for idx, cand in enumerate(data):
        fp = cand["fingerprint"]
        if fp in seen:
            errors.add(f"$[{idx}].fingerprint: duplicate fingerprint {fp}")
        seen.add(fp)
        if not is_valid_fingerprint(fp):
            errors.add(f"$[{idx}].fingerprint: invalid fingerprint format")
    return errors


# ------------------------------------------------------------------ ledger

NO_EVIDENCE_STATES = {"deferred", "out_of_scope", "not_applicable"}


def validate_ledger(data, run_dir: Path | None = None) -> Errors:
    errors = Errors()
    for e in Validator(get_schema("coverage-ledger")).errors(data):
        errors.add(e)
    if errors:
        return errors

    ids = [u["coverage_id"] for u in data]
    if ids != sorted(ids):
        errors.add("$: units must be sorted by coverage_id")
    id_set = set()
    for idx, unit in enumerate(data):
        where = f"$[{idx}]"
        cid = unit["coverage_id"]
        if cid in id_set:
            errors.add(f"{where}.coverage_id: duplicate {cid}")
        id_set.add(cid)
        expected = f"{unit['file']}#{unit['function']}::{unit['obligation_class']}"
        if cid != expected:
            errors.add(f"{where}.coverage_id: must equal {expected!r}")
        _path_ok(errors, f"{where}.file", unit["file"])

        st = unit["status"]
        agent = unit["agent_id"]
        ev = unit["evidence"]
        fps = unit["result_fingerprints"]
        unres = unit["unresolved"]

        if agent is not None and not is_safe_agent_id(agent):
            errors.add(f"{where}.agent_id: not a canonical lowercase agent id")
        if st != "candidate" and fps:
            errors.add(f"{where}: only 'candidate' units may carry result_fingerprints")
        if st == "planned":
            if agent is not None:
                errors.add(f"{where}: planned unit must have agent_id null")
            if unres:
                errors.add(f"{where}: planned unit must have no unresolved entries")
        elif st == "in_progress":
            if agent is None:
                errors.add(f"{where}: in_progress unit needs an agent_id")
            if unres:
                errors.add(f"{where}: in_progress unit must have no unresolved entries")
        elif st == "blocked":
            if not ev:
                errors.add(f"{where}: blocked unit needs partial evidence")
            if not unres:
                errors.add(f"{where}: blocked unit needs a nonempty unresolved blocker")
        elif st == "covered":
            if not any(e["discharging"] for e in ev):
                errors.add(f"{where}: covered unit needs at least one discharging evidence entry")
            if unres:
                errors.add(f"{where}: covered unit must have no unresolved entries")
        elif st == "candidate":
            if not ev:
                errors.add(f"{where}: candidate unit needs evidence")
            if not fps:
                errors.add(f"{where}: candidate unit needs result_fingerprints")
        elif st in NO_EVIDENCE_STATES:
            if agent is not None:
                errors.add(f"{where}: {st} unit must have agent_id null")
            if ev:
                errors.add(f"{where}: {st} unit must not hide evidence (use 'blocked' for partial work)")
            if not unres:
                errors.add(f"{where}: {st} unit needs a nonempty reason in unresolved")

        for f_idx, fp in enumerate(fps):
            if not is_valid_fingerprint(fp):
                errors.add(f"{where}.result_fingerprints[{f_idx}]: invalid fingerprint")
        for e_idx, item in enumerate(ev):
            if item["phase"] == "wp" and item["discharging"]:
                problem = wp_limits_problem((item.get("details") or {}).get("limits"))
                if problem:
                    errors.add(f"{where}.evidence[{e_idx}]: discharging WP evidence is invalid: {problem}")
            _path_ok(errors, f"{where}.evidence[{e_idx}].tool_output", item["tool_output"])
            _exists(errors, f"{where}.evidence[{e_idx}].tool_output", run_dir, item["tool_output"])

    for idx, unit in enumerate(data):
        for a_idx, assumption in enumerate(unit["assumptions"]):
            for rel in assumption["related_units"]:
                if rel not in id_set:
                    errors.add(f"$[{idx}].assumptions[{a_idx}]: related unit {rel} not in ledger")
    return errors


# ---------------------------------------------------------------- metadata


def validate_metadata(data) -> Errors:
    errors = Errors()
    for e in Validator(get_schema("run-metadata")).errors(data):
        errors.add(e)
    if errors:
        return errors
    if data["run_status"] == "incomplete" and not (data["incomplete_reason"] or "").strip():
        errors.add("$.incomplete_reason: required when run_status is 'incomplete'")
    if data["run_status"] != "incomplete" and data["incomplete_reason"] is not None:
        errors.add("$.incomplete_reason: must be null unless run_status is 'incomplete'")
    for idx, p in enumerate(data["scope_paths"]):
        _path_ok(errors, f"$.scope_paths[{idx}]", p)
    if data.get("snapshot_manifest") is not None:
        _path_ok(errors, "$.snapshot_manifest", data["snapshot_manifest"])
    return errors


# ------------------------------------------------------- snapshot manifest


def validate_snapshot_manifest(data, run_dir: Path | None = None) -> Errors:
    errors = Errors()
    if not isinstance(data, dict):
        errors.add("$: snapshot manifest must be an object")
        return errors
    if data.get("schema_version") != 1:
        errors.add("$.schema_version: must equal 1")
    if not isinstance(data.get("run_id"), str) or not data.get("run_id"):
        errors.add("$.run_id: must be a non-empty string")
    manifest_sha = data.get("manifest_sha256")
    if not isinstance(manifest_sha, str) or not _HEX64_RE.match(manifest_sha):
        errors.add("$.manifest_sha256: must be a 64-character lowercase hex sha256")
    files = data.get("files")
    if not isinstance(files, dict):
        errors.add("$.files: must be an object mapping relative paths to {sha256, size}")
        return errors
    for rel, info in files.items():
        where = f"$.files[{rel!r}]"
        _path_ok(errors, where, rel)
        if not isinstance(info, dict):
            errors.add(f"{where}: must be an object")
            continue
        sha = info.get("sha256")
        size = info.get("size")
        if not isinstance(sha, str) or not _HEX64_RE.match(sha):
            errors.add(f"{where}.sha256: must be a 64-character lowercase hex sha256")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            errors.add(f"{where}.size: must be a non-negative integer")
        if run_dir is not None and is_safe_relative_path(rel):
            full = Path(run_dir) / rel
            if not full.is_file():
                errors.add(f"{where}: snapshotted file missing from run dir: {rel}")
            else:
                blob = full.read_bytes()
                if isinstance(size, int) and len(blob) != size:
                    errors.add(f"{where}.size: file size changed (expected {size}, got {len(blob)})")
                if isinstance(sha, str) and hashlib.sha256(blob).hexdigest() != sha:
                    errors.add(f"{where}.sha256: file digest changed after snapshot: {rel}")
    if isinstance(manifest_sha, str) and _HEX64_RE.match(manifest_sha):
        computed = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if computed != manifest_sha:
            errors.add("$.manifest_sha256: does not match canonical digest of $.files")
    return errors


# ------------------------------------------------------------ agent result


def _under_agent_dir(errors: Errors, where: str, agent_id: str, value: str | None) -> None:
    if value is None:
        return
    _path_ok(errors, where, value)
    if not value.startswith(f"agents/{agent_id}/"):
        errors.add(f"{where}: must live under agents/{agent_id}/ (agents write only to their own directory)")


def validate_agent_result(data) -> Errors:
    errors = Errors()
    for e in Validator(get_schema("agent-result")).errors(data):
        errors.add(e)
    if errors:
        return errors
    role = data["role"]
    aid = data["agent_id"]
    if not is_safe_agent_id(aid):
        errors.add("$.agent_id: not a canonical lowercase agent id")
    if role == "prover":
        _under_agent_dir(errors, "$.patch", aid, data["patch"])
        if data["status"] == "all_proven":
            if data["unproven_goals"]:
                errors.add("$.unproven_goals: must be empty when status is all_proven")
            if data["fault_hypothesis"] is not None:
                errors.add("$.fault_hypothesis: must be null when status is all_proven")
            if data.get("proof_gap") is not None:
                errors.add("$.proof_gap: must be null when status is all_proven")
        elif not data["unproven_goals"] and data["status"] != "blocked":
            # The brief's blocked exits (a guardrail code_fault, a repeated analysis_error) decide no
            # goal: they name the report that blocked them in `evidence` (required by the schema).
            errors.add("$.unproven_goals: required when the proof did not complete")
        for idx, ev in enumerate(data["evidence"]):
            _path_ok(errors, f"$.evidence[{idx}].tool_output", ev["tool_output"])
        for idx, req in enumerate(data.get("strengthening_requests") or []):
            _path_ok(errors, f"$.strengthening_requests[{idx}].header_file", req.get("header_file"))
            if req.get("callee_file") is not None:
                _path_ok(errors, f"$.strengthening_requests[{idx}].callee_file", req.get("callee_file"))
    elif role == "breaker":
        for idx, seed in enumerate(data["seeds"]):
            _under_agent_dir(errors, f"$.seeds[{idx}]", aid, seed)
        _under_agent_dir(errors, "$.crash_artifact", aid, data["crash_artifact"])
        if data["status"] == "crash_found" and (data["crash_artifact"] is None or not data["failing_predicate"]):
            errors.add("$: crash_found requires crash_artifact and failing_predicate")
        if data["status"] == "crash_found" and data["fault_hypothesis"] is not None:
            errors.add("$.fault_hypothesis: a reproduced crash is not a hypothesis; set null")
    elif role == "architect":
        _under_agent_dir(errors, "$.patch", aid, data["patch"])
    elif role == "crash_verifier":
        record = data["record"]
        for e in validate_findings([record]):
            errors.add(e.replace("$[0]", "$.record", 1))
        if record.get("verdict") != data["decision"]:
            errors.add("$.record.verdict: must equal decision")
        extra_recs = data.get("additional_records") or []
        for idx, extra in enumerate(extra_recs):
            for e in validate_findings([extra]):
                errors.add(e.replace("$[0]", f"$.additional_records[{idx}]", 1))
        if (record.get("fingerprint") != data["candidate_fingerprint"] or extra_recs) and not (
            data["refingerprint_reason"] or ""
        ).strip():
            errors.add(
                "$.refingerprint_reason: required when the record fingerprint differs from the candidate or additional_records are present"
            )
    elif role == "critic":
        if data["stop"] and (data["missing_units"] or data["reassign_ids"]):
            errors.add("$.stop: may only be true when no missing_units and no reassign_ids are proposed")
    return errors


# ----------------------------------------------------------------- run dir


def validate_run_dir(run_dir: Path) -> Errors:
    errors = Errors()
    loaded = {}
    validators: tuple[tuple[str, Any, bool], ...] = (
        ("run-metadata.json", validate_metadata, False),
        ("coverage-ledger.json", validate_ledger, True),
        ("candidates.json", validate_candidates, False),
        ("findings.json", validate_findings, True),
    )
    for name, fn, needs_run in validators:
        path = run_dir / name
        if not path.exists():
            if name in ("run-metadata.json", "coverage-ledger.json"):
                errors.add(f"{name}: missing")
            continue
        try:
            data = load_json_strict(path)
        except ArtifactError as exc:
            errors.add(f"{name}: {exc}")
            continue
        loaded[name] = data
        for e in fn(data, run_dir) if needs_run else fn(data):
            errors.add(f"{name}: {e}")
    if errors:
        return errors

    ledger = {u["coverage_id"]: u for u in loaded.get("coverage-ledger.json", [])}
    findings = {r["fingerprint"]: r for r in loaded.get("findings.json", [])}
    candidates = {c["fingerprint"]: c for c in loaded.get("candidates.json", [])}

    for fp, rec in findings.items():
        for cid in rec["linked_units"]:
            unit = ledger.get(cid)
            if unit is None:
                errors.add(f"findings.json: {fp} links unknown unit {cid}")
            elif fp not in unit["result_fingerprints"] and not any(
                fp in a.get("result_fingerprints", []) for a in unit["attempts"]
            ):
                errors.add(f"findings.json: {fp} not recorded in result_fingerprints of {cid}")
    for fp, cand in candidates.items():
        resolved_fps = cand.get("resolved_fingerprints") or [fp]
        if cand["status"] == "verified":
            missing_fps = [rfp for rfp in resolved_fps if rfp not in findings]
            if missing_fps:
                errors.add(
                    f"candidates.json: {fp} marked verified but resolved fingerprint(s) {missing_fps} have no findings.json record"
                )
            if resolved_fps != [fp] and not (cand.get("refingerprint_reason") or "").strip():
                errors.add(
                    f"candidates.json: {fp} was refingerprinted/split to {resolved_fps} without refingerprint_reason"
                )
        if cand["status"] == "unverified" and fp in findings:
            errors.add(f"candidates.json: {fp} has a verdict but is still marked unverified")
        for cid in cand["linked_units"]:
            if cid not in ledger:
                errors.add(f"candidates.json: {fp} links unknown unit {cid}")
    for cid, unit in ledger.items():
        for fp in unit["result_fingerprints"]:
            if fp not in findings and fp not in candidates:
                errors.add(
                    f"coverage-ledger.json: {cid} references fingerprint {fp} found in neither findings nor candidates"
                )

    meta = loaded.get("run-metadata.json")
    if meta and meta["run_status"] == "complete":
        if any(c["status"] == "unverified" for c in candidates.values()):
            errors.add("run-metadata.json: run cannot be complete while unverified candidates remain")
        open_units = [cid for cid, u in ledger.items() if u["status"] in ("planned", "in_progress")]
        if open_units:
            errors.add(f"run-metadata.json: run cannot be complete with {len(open_units)} planned/in_progress units")

    snap_rel = (meta.get("snapshot_manifest") if meta else None) or "state/snapshot-manifest.json"
    snap_path = run_dir / snap_rel
    if snap_path.exists() or (meta and meta.get("snapshot_manifest")):
        if not snap_path.is_file():
            errors.add(f"{snap_rel}: snapshot manifest missing")
        else:
            try:
                snap_data = load_json_strict(snap_path)
            except ArtifactError as exc:
                errors.add(f"{snap_rel}: {exc}")
            else:
                for e in validate_snapshot_manifest(snap_data, run_dir):
                    errors.add(f"{snap_rel}: {e}")
                if (
                    meta
                    and meta.get("snapshot_digest")
                    and snap_data.get("manifest_sha256") != meta.get("snapshot_digest")
                ):
                    errors.add(f"{snap_rel}: manifest_sha256 does not match run-metadata.json snapshot_digest")
    return errors


# --------------------------------------------------------------------- CLI


def _emit(errors: Errors) -> int:
    print(json.dumps({"ok": not errors, "error_count": len(errors), "errors": list(errors)}, indent=2))
    return 0 if not errors else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Validate Frama-C pipeline artifacts.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("findings", "ledger", "snapshot"):
        p = sub.add_parser(name)
        p.add_argument("path", type=Path)
        p.add_argument("--run-dir", type=Path, default=None)
    for name in ("candidates", "metadata", "agent-result"):
        p = sub.add_parser(name)
        p.add_argument("path", type=Path)
    p = sub.add_parser("run-dir")
    p.add_argument("path", type=Path)
    args = parser.parse_args(argv)

    try:
        if args.cmd == "run-dir":
            return _emit(validate_run_dir(args.path))
        if args.cmd == "agent-result":
            data = load_agent_result_json(args.path)
            return _emit(validate_agent_result(data))
        data = load_json_strict(args.path)
        if args.cmd == "findings":
            return _emit(validate_findings(data, args.run_dir))
        if args.cmd == "ledger":
            return _emit(validate_ledger(data, args.run_dir))
        if args.cmd == "snapshot":
            return _emit(validate_snapshot_manifest(data, args.run_dir))
        if args.cmd == "candidates":
            return _emit(validate_candidates(data))
        return _emit(validate_metadata(data))
    except ArtifactError as exc:
        print(json.dumps({"ok": False, "error_count": 1, "errors": [str(exc)]}, indent=2))
        return 2


if __name__ == "__main__":
    sys.exit(main())
