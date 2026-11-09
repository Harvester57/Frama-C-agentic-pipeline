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
  dag | sidecar | build-check | reach-dynamic | seed-harvest | build-capture | phase0-model
  | security-props  <artifact.json>    (Phase 0 artifacts, remediation R5)
  traces        <traces.jsonl>
  run-dir       <run-dir>             (all present artifacts + cross-file consistency)

`run-dir` also checks the Phase 0 artifacts present under workspace/ (PHASE0_ARTIFACTS, the harness
sidecars and workspace/seed_records/traces.jsonl), and fails on the schema problems their producers
recorded in `warnings` (schema_warning: producers write the artifact anyway).

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
        for idx, item in enumerate(data.get("functions") or []):
            _path_ok(errors, f"$.functions[{idx}].file", item.get("file"))
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

PHASE0_GATES = "workspace/reports/phase0_gates.json"


def validate_phase0_gates(data: Any) -> Errors:
    """
    The Phase 0 gate stamp (phase0_gates.py): its shape. Reports older than a failed gate are not
    errors: a harness repair fails the gate again while the previous campaign's report is still there.
    """
    errors = Errors()
    if not isinstance(data, dict):
        errors.add("$: must be an object")
        return errors
    for section, flag, row_flag in (("reach", "passed", "passed"), ("build_check", "ok", "ok")):
        entry = data.get(section)
        if entry is None:
            continue
        if not isinstance(entry, dict) or not isinstance(entry.get(flag), bool):
            errors.add(f"$.{section}.{flag}: must be a boolean")
            continue
        modules = entry.get("modules")
        if not isinstance(modules, dict) or not all(
            isinstance(r, dict) and isinstance(r.get(row_flag), bool) for r in modules.values()
        ):
            errors.add(f"$.{section}.modules: must map each module to an object with a boolean {row_flag!r}")
            continue
        # A build-check that found no module in the plan records why (`error`) and fails.
        expected = all(r[row_flag] for r in modules.values()) and not (not modules and entry.get("error"))
        if entry[flag] != expected:
            errors.add(f"$.{section}.{flag}: must be true exactly when every module passed and no error was recorded")
    return errors


# ------------------------------------------------------- Phase 0 artifacts

# One self-validation policy (remediation R5): a producer writes its artifact even when it does not
# match its schema, and records the problems in its `warnings` with this prefix (schema_warning);
# `run-dir` fails on such a warning as on a schema error found now.
SCHEMA_WARNING_PREFIX = "schema: "
_RECORDED_SCHEMA_RE = re.compile(r"^schema:|does not match its schema")


def schema_problems(name: str, data: Any) -> list[str]:
    """The problems of `data` against schemas/<name>.schema.json."""
    return list(Validator(get_schema(name)).errors(data))


def schema_warning(name: str, data: Any) -> str | None:
    """The warning a producer records when its artifact does not match its schema, else None."""
    try:
        problems = schema_problems(name, data)
    except (ArtifactError, OSError, ValueError) as exc:
        return f"{SCHEMA_WARNING_PREFIX}cannot check against schemas/{name}.schema.json: {exc}"
    return f"{SCHEMA_WARNING_PREFIX}{'; '.join(problems[:5])}" if problems else None


def recorded_schema_warnings(data: Any) -> list[str]:
    """The schema warnings a producer recorded in the artifact's `warnings`."""
    warnings = data.get("warnings") if isinstance(data, dict) else None
    if not isinstance(warnings, list):
        return []
    return [w for w in warnings if isinstance(w, str) and _RECORDED_SCHEMA_RE.search(w)]


def _schema_check(name: str, data: Any) -> Errors:
    errors = Errors()
    for e in schema_problems(name, data):
        errors.add(e)
    for w in recorded_schema_warnings(data):
        errors.add(f"$.warnings: the producer recorded a schema problem: {w}")
    return errors


def validate_build_capture(data: Any) -> Errors:
    return _schema_check("build_capture", data)


def validate_phase0_model(data: Any) -> Errors:
    return _schema_check("phase0_model", data)


def validate_security_props(data: Any) -> Errors:
    return _schema_check("security_props", data)


def validate_seed_harvest(data: Any) -> Errors:
    return _schema_check("seed_harvest", data)


def validate_fuzz_assets(data: Any) -> Errors:
    return _schema_check("fuzz_assets", data)


def validate_dynamic_reach(data: Any) -> Errors:
    errors = _schema_check("harness_reach_dynamic", data)
    if errors:
        return errors
    for name, row in data["modules"].items():
        where = f"$.modules[{name!r}]"
        if row["module"] != name:
            errors.add(f"{where}.module: must equal its key")
        if row["passed"] != (not row["gaps"]):
            errors.add(f"{where}.passed: must be true exactly when there is no gap")
        if row["entry_points"] != len(row["executions"]):
            errors.add(f"{where}.entry_points: must count the entries of `executions`")
    return errors


def validate_build_check(data: Any) -> Errors:
    errors = _schema_check("build_check", data)
    if errors:
        return errors
    rows = data["modules"]
    expected = all(r["ok"] for r in rows.values()) and not (not rows and data.get("error"))
    if data["ok"] != expected:
        errors.add("$.ok: must be true exactly when every module is ok and no error was recorded")
    for name, row in rows.items():
        if row["ok"] != (row["status"] in ("eacsl", "sanitizers_chosen")):
            errors.add(f"$.modules[{name!r}].ok: must be true exactly for status eacsl or sanitizers_chosen")
    return errors


def validate_sidecar(data: Any, module: str | None = None) -> Errors:
    """A harness sidecar; `module` is the name its file gives it (harness_<module>.json)."""
    errors = _schema_check("harness_sidecar", data)
    if errors:
        return errors
    if module is not None and data["module"] != module:
        errors.add(f"$.module: {data['module']!r} does not match the file name (harness_{module}.json)")
    cases = data.get("api_cases") or []
    if [c["selector"] for c in cases] != list(range(len(cases))):
        errors.add("$.api_cases: selectors must number the cases 0, 1, ... in order")
    if cases and data["entry_style"] != "dispatch":
        errors.add("$.api_cases: an API harness is a dispatch harness")
    if data.get("entry_style") == "dispatch" and cases and len(cases) != len(data.get("dispatch_cases") or []):
        errors.add("$.api_cases: one layout per dispatch case")
    return errors


DAG_NO_VERSION = (
    "no schema_version: the DAG predates the GCC-fallback blocking (defect 6; build_callgraph_dag.py "
    "block_fallback_units), so a unit Frama-C cannot parse may still be routed to Eva and WP: rebuild it"
)


def validate_dag(data: Any) -> Errors:
    """The call-graph DAG: its schema, its version, and the links ModuleMap and the gates follow."""
    errors = _schema_check("callgraph_dag", data)
    if errors:
        return errors
    if data.get("module_kind") == "link_unit" and "schema_version" not in data:
        errors.add(f"$: {DAG_NO_VERSION}")
    functions: dict[str, dict] = data["functions"]
    modules: dict[str, dict] = data["modules"]
    for section in ("modules", "lexer_modules", "submodules"):
        for name, rec in (data.get(section) or {}).items():
            where = f"$.{section}[{name!r}]"
            for field in ("functions", "candidate_entry_points"):
                unknown = [k for k in rec.get(field) or [] if k not in functions]
                if unknown:
                    errors.add(f"{where}.{field}: not in $.functions: {unknown[:5]}")
            if section == "submodules" and rec["unit"] not in modules:
                errors.add(f"{where}.unit: {rec['unit']!r} is not a module")
    for path_mod, unit in (data.get("unit_of_lexer_module") or {}).items():
        if unit not in modules:
            errors.add(f"$.unit_of_lexer_module[{path_mod!r}]: {unit!r} is not a module")
    for key, rec in functions.items():
        if rec["module"] not in modules:
            errors.add(f"$.functions[{key!r}].module: {rec['module']!r} is not a module")
        for field in ("internal_callees", "internal_callers"):
            unknown = [k for k in rec[field] if k not in functions]
            if unknown:
                errors.add(f"$.functions[{key!r}].{field}: not in $.functions: {unknown[:5]}")
    for name, rec in modules.items():
        if rec.get("callgraph_fallback") and data.get("module_kind") == "link_unit" and "schema_version" in data:
            if rec.get("run_eva") is not False or rec.get("run_wp_full") is not False:
                errors.add(f"$.modules[{name!r}]: a unit on the GCC fallback must have run_eva and run_wp_full false")
            blocked = [k for k in rec["functions"] if not functions[k].get("eva_wp_blocked")]
            if blocked:
                errors.add(
                    f"$.modules[{name!r}]: functions of a unit on the GCC fallback lack eva_wp_blocked: {blocked[:5]}"
                )
    return errors


def validate_traces(path: Path) -> Errors:
    """workspace/seed_records/traces.jsonl: one trace object per line."""
    errors = Errors()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        errors.add(f"cannot read: {exc}")
        return errors
    for no, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except ValueError as exc:
            errors.add(f"line {no}: not JSON: {exc}")
            continue
        for e in schema_problems("seed_trace", rec):
            errors.add(f"line {no}: {e}")
    return errors


REPORTS = "workspace/reports"
HARNESS_DIR = "workspace/harnesses"
TRACES_JSONL = "workspace/seed_records/traces.jsonl"
PHASE0_ARTIFACTS: tuple[tuple[str, Any], ...] = (
    (f"{REPORTS}/build_capture.json", validate_build_capture),
    (f"{REPORTS}/phase0_model.json", validate_phase0_model),
    (f"{REPORTS}/security_props.json", validate_security_props),
    (f"{REPORTS}/callgraph_dag.json", validate_dag),
    (f"{REPORTS}/build_check.json", validate_build_check),
    (f"{REPORTS}/harness_reach_dynamic.json", validate_dynamic_reach),
    (f"{REPORTS}/seed_harvest.json", validate_seed_harvest),
    (f"{REPORTS}/fuzz_assets.json", validate_fuzz_assets),
)


def validate_phase0_artifacts(run_dir: Path) -> Errors:
    """The Phase 0 artifacts present in a run directory, each against its schema (see PHASE0_ARTIFACTS)."""
    errors = Errors()
    for rel, fn in PHASE0_ARTIFACTS:
        path = run_dir / rel
        if not path.is_file():
            continue
        try:
            data = load_json_strict(path)
        except ArtifactError as exc:
            errors.add(f"{rel}: {exc}")
            continue
        for e in fn(data):
            errors.add(f"{rel}: {e}")
    harness_dir = run_dir / HARNESS_DIR
    for path in sorted(harness_dir.glob("harness_*.json")) if harness_dir.is_dir() else []:
        rel = f"{HARNESS_DIR}/{path.name}"
        try:
            data = load_json_strict(path)
        except ArtifactError as exc:
            errors.add(f"{rel}: {exc}")
            continue
        for e in validate_sidecar(data, path.stem[len("harness_") :]):
            errors.add(f"{rel}: {e}")
    traces = run_dir / TRACES_JSONL
    if traces.is_file():
        for e in validate_traces(traces):
            errors.add(f"{TRACES_JSONL}: {e}")
    return errors


PHASE0_COMMANDS: dict[str, Any] = {
    "dag": validate_dag,
    "sidecar": validate_sidecar,
    "build-check": validate_build_check,
    "reach-dynamic": validate_dynamic_reach,
    "seed-harvest": validate_seed_harvest,
    "fuzz-assets": validate_fuzz_assets,
    "build-capture": validate_build_capture,
    "phase0-model": validate_phase0_model,
    "security-props": validate_security_props,
}


def validate_run_dir(run_dir: Path) -> Errors:
    errors = _validate_run_dir_core(run_dir)
    for e in validate_phase0_artifacts(run_dir):
        errors.add(e)
    return errors


def _validate_run_dir_core(run_dir: Path) -> Errors:
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

    gates_path = run_dir / PHASE0_GATES
    if gates_path.is_file():
        try:
            gates = load_json_strict(gates_path)
        except ArtifactError as exc:
            errors.add(f"{PHASE0_GATES}: {exc}")
        else:
            for e in validate_phase0_gates(gates):
                errors.add(f"{PHASE0_GATES}: {e}")

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
    for name in (*PHASE0_COMMANDS, "traces"):
        p = sub.add_parser(name)
        p.add_argument("path", type=Path)
    p = sub.add_parser("run-dir")
    p.add_argument("path", type=Path)
    args = parser.parse_args(argv)

    try:
        if args.cmd == "run-dir":
            return _emit(validate_run_dir(args.path))
        if args.cmd == "traces":
            if not args.path.is_file():
                raise ArtifactError(f"{args.path}: not found")
            return _emit(validate_traces(args.path))
        if args.cmd in PHASE0_COMMANDS:
            data = load_json_strict(args.path)
            if args.cmd == "sidecar":
                stem = args.path.stem
                return _emit(validate_sidecar(data, stem[len("harness_") :] if stem.startswith("harness_") else None))
            return _emit(PHASE0_COMMANDS[args.cmd](data))
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
