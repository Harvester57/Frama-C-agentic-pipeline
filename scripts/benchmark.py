#!/usr/bin/env python3
"""
Repeatable benchmark of this pipeline: measures what a change to its filters, Eva configuration or
briefs actually does, instead of assuming it. See docs/benchmark.md.

Host commands (stdlib only; tools run in the framac-pipeline container, so targets are fetched here):
  check-manifest                 validate benchmark/manifest.json
  fetch [--set S] [--target T]   clone the selected targets at their pinned revisions
  run [--compare NAME|FILE]      Phases 0 to 2 plus reproducer replay, no LLM; writes one JSON per run
  compare BASELINE CURRENT       print the differences between two runs
  baseline --run FILE            store a run as a baseline under benchmark/baselines/
  measure-llm --run-file FILE    add Phase 3 metrics after an LLM host has driven /framac-wp on a run dir
  migrate-units --dag T=FILE     record in the manifest the link unit of each harness module (step I5b)
  seeded [--project P]           the phase0 set: seeded-bug projects (scripts/benchmark_seeded.py)

Commands that run inside the container, from the run directory (started by `run`):
  inner-phase0, inner-replay, inner-gate

Nothing here chooses a machine size: the wrappers lease CPUs and memory per container and Make sizes
-j from that lease. The limits that decide results (WP memlimit, fuzz rss limit, per-input timeouts,
replay seeds) stay the tools' own fixed values, and are recorded in the run file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from benchmark_compare import SCHEMA_VERSION, Tolerances, compare_runs, load_run, rate_block, render_text  # noqa: E402
from fingerprint import make_fingerprint, normalize_file  # noqa: E402
from minischema import Validator, load_schema  # noqa: E402
from mutation_check import summarize_mutation  # noqa: E402
from resources import FUZZ_RSS_LIMIT_MB, WP_MEMLIMIT_MB  # noqa: E402

SCRIPTS_DIR = Path(__file__).resolve().parent
PIPELINE_ROOT = SCRIPTS_DIR.parent
BENCHMARK_DIR = PIPELINE_ROOT / "benchmark"
DEFAULT_MANIFEST = BENCHMARK_DIR / "manifest.json"
BASELINES_DIR = BENCHMARK_DIR / "baselines"
ASSETS_DIR = BENCHMARK_DIR / "assets"
RUN_SCHEMA = PIPELINE_ROOT / "schemas" / "benchmark-run.schema.json"
CONTAINER_SCRIPTS = "/opt/framac-pipeline/scripts"

# Per-run directory (the wrappers mount it at /framac-run). run_metadata.py requires the name run-<N>.
BENCH_SUBDIR = "bench"
RUN_DIR_NAME = "run-1"
PER_INPUT_TIMEOUT_S = 10  # run_eacsl_fuzz.DEFAULT_PER_INPUT_TIMEOUT_S; checked by a test

CONTENT_DIRS = ("scripts", "templates", "schemas", "skills")
VERDICT_FIELDS = (
    "description",
    "root_cause",
    "intended_behavior",
    "severity_rationale",
    "remediation_summary",
    "remediation_invariant",
)

EXCLUDED_STATUSES = frozenset({"deferred", "out_of_scope", "not_applicable"})
TOOL_FAILURE_RESULTS = frozenset({"eva_analysis_error", "wp_analysis_error", "wp_wp_aborted"})
NOT_REACHED_RESULTS = frozenset({"eva_dead", "eva_no_properties"})

_EVA_FUNCTIONS_RE = re.compile(r"(\d+) functions? analyzed \(out of (\d+)\)")
_EVA_STATEMENTS_RE = re.compile(r"(\d+) statements? reached \(out of (\d+)\)")
_RENAMED_STATIC_RE = re.compile(r"(.+)_\d+")
_HOST_PATH_RE = re.compile(r"(?:[A-Za-z]:\\|/Users/|/home/)")


class BenchmarkError(RuntimeError):
    pass


def _say(message: str) -> None:
    print(f"[benchmark] {message}", file=sys.stderr, flush=True)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def write_json(path: Path, data: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    os.replace(tmp, path)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


def load_manifest(path: Path = DEFAULT_MANIFEST) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def validate_manifest(manifest: dict, assets_dir: Path = ASSETS_DIR) -> list[str]:
    """Problems in the manifest (empty when it is usable): dangling references, wrong digests, bad sets."""
    problems: list[str] = []
    targets = {t["id"]: t for t in manifest.get("targets", [])}
    if len(targets) != len(manifest.get("targets", [])):
        problems.append("duplicate target id")
    for tid, target in targets.items():
        if target.get("set") not in ("recall", "comparison"):
            problems.append(f"{tid}: set must be recall or comparison")
        if not re.fullmatch(r"[0-9a-f]{40}", str(target.get("revision") or "")):
            problems.append(f"{tid}: revision must be a full commit id")
        names = [m["name"] for m in target.get("modules", [])]
        if not names:
            problems.append(f"{tid}: no modules")
        if len(names) != len(set(names)):
            problems.append(f"{tid}: duplicate module")
        for asset in target.get("assets", []):
            if not (assets_dir / asset["path"]).is_file():
                problems.append(f"{tid}: missing asset {asset['path']}")
        tm = target.get("threat_model")
        if tm is not None:
            tm_path = assets_dir / str(tm.get("path"))
            if not tm_path.is_file():
                problems.append(f"{tid}: missing threat model {tm.get('path')}")
            elif sha256_hex(tm_path.read_bytes()) != tm.get("sha256"):
                problems.append(f"{tid}: threat model {tm.get('path')} does not match its sha256")
    seen: set[str] = set()
    for bug in manifest.get("bugs", []):
        bid = bug["id"]
        if bid in seen:
            problems.append(f"duplicate bug {bid}")
        seen.add(bid)
        try:
            data = bytes.fromhex(bug["input_hex"])
        except ValueError:
            problems.append(f"{bid}: input_hex is not hexadecimal")
        else:
            if sha256_hex(data) != bug["input_sha256"]:
                problems.append(f"{bid}: input_sha256 does not match input_hex")
        if not any(r.get("required") for r in bug.get("replays", [])):
            problems.append(f"{bid}: no required replay")
        missing = sorted(set(VERDICT_FIELDS) - set(bug.get("verdict") or {}))
        if missing:
            problems.append(f"{bid}: verdict lacks {', '.join(missing)}")
        for replay in bug.get("replays", []):
            target = targets.get(replay["target"])
            if target is None:
                problems.append(f"{bid}: unknown target {replay['target']}")
            elif replay["module"] not in {m["name"] for m in target.get("modules", [])}:
                problems.append(f"{bid}: unknown module {replay['target']}/{replay['module']}")
            if replay.get("engine") not in ("eacsl", "sanitizers"):
                problems.append(f"{bid}: engine must be eacsl or sanitizers")
            if not replay.get("lines"):
                problems.append(f"{bid}: replay without expected lines")
    return problems


def select_targets(manifest: dict, sets: Iterable[str] = ("all",), names: Iterable[str] = ()) -> list[dict]:
    wanted_sets = set(sets)
    wanted_names = set(names)
    known = {t["id"] for t in manifest["targets"]}
    unknown = wanted_names - known
    if unknown:
        raise BenchmarkError(f"unknown target(s): {', '.join(sorted(unknown))}; known: {', '.join(sorted(known))}")
    if wanted_names:
        return [t for t in manifest["targets"] if t["id"] in wanted_names]
    if "all" in wanted_sets:
        return list(manifest["targets"])
    return [t for t in manifest["targets"] if t["set"] in wanted_sets]


def harness_digest(target: dict, manifest: dict, assets_dir: Path = ASSETS_DIR) -> str:
    """Everything the benchmark itself decides for a target; a change means counts are not like for like."""
    material = {
        "profile": manifest.get("profile"),
        "scope": target.get("scope"),
        "modules": target.get("modules"),
        "compile_commands": target.get("compile_commands"),
        "assets": {
            a["path"]: sha256_hex((assets_dir / a["path"]).read_bytes())
            for a in sorted(target.get("assets", []), key=lambda x: x["path"])
        },
    }
    return sha256_hex(json.dumps(material, sort_keys=True).encode())


def content_digest(root: Path = PIPELINE_ROOT, dirs: Iterable[str] = CONTENT_DIRS) -> str:
    """Digest of the pipeline's own files, so a baseline says exactly which pipeline produced it."""
    h = hashlib.sha256()
    for name in dirs:
        base = root / name
        if not base.is_dir():
            continue
        for path in sorted(p for p in base.rglob("*") if p.is_file() and "__pycache__" not in p.parts):
            h.update(path.relative_to(root).as_posix().encode())
            h.update(b"\0")
            h.update(path.read_bytes().replace(b"\r\n", b"\n"))
    return h.hexdigest()


def _git(args: list[str], cwd: Path | None = None, check: bool = True) -> str:
    proc = subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False
    )
    if check and proc.returncode != 0:
        raise BenchmarkError(f"git {' '.join(args)} failed: {(proc.stderr or proc.stdout).strip()}")
    return (proc.stdout or "").strip()


def pipeline_identity(root: Path = PIPELINE_ROOT) -> dict:
    commit = _git(["rev-parse", "HEAD"], cwd=root, check=False) or None
    dirty = bool(_git(["status", "--porcelain", "--untracked-files=no"], cwd=root, check=False)) if commit else None
    return {"commit": commit, "dirty": dirty, "content_digest": content_digest(root)}


# ---------------------------------------------------------------------------
# Fetch (host: the container has no network)
# ---------------------------------------------------------------------------


def checkout_dir(target: dict, work_dir: Path) -> Path:
    return work_dir / "targets" / target["checkout"]


def target_dir(target: dict, work_dir: Path) -> Path:
    base = checkout_dir(target, work_dir)
    return base / target["subdir"] if target.get("subdir") else base


def fetch_targets(targets: list[dict], work_dir: Path, manifest: dict) -> dict[str, str]:
    """
    Clone each selected target at its pinned revision, byte-exact on every OS (no line-ending
    conversion). Targets sharing a checkout share a sparse clone holding the union of their
    subdirectories, including any target of the manifest, so selecting one never drops another's.
    Returns target id -> problem, for targets that could not be fetched.
    """
    problems: dict[str, str] = {}
    by_checkout: dict[str, list[dict]] = {}
    for target in targets:
        by_checkout.setdefault(target["checkout"], []).append(target)
    for name, group in by_checkout.items():
        first = group[0]
        path = checkout_dir(first, work_dir)
        try:
            if not (path / ".git").exists():
                path.parent.mkdir(parents=True, exist_ok=True)
                _say(f"fetching {first['url']} into {path}")
                _git(
                    [
                        "clone",
                        "--quiet",
                        "--filter=blob:none",
                        "--no-checkout",
                        "-c",
                        "core.autocrlf=false",
                        "-c",
                        "core.eol=lf",
                        first["url"],
                        str(path),
                    ]
                )
            subdirs = sorted({t["subdir"] for t in manifest["targets"] if t["checkout"] == name and t.get("subdir")})
            if subdirs:
                _git(["sparse-checkout", "set", "--cone", *subdirs], cwd=path)
            rev = first["revision"]
            if _git(["cat-file", "-t", rev], cwd=path, check=False) != "commit":
                _git(["fetch", "--quiet", "--filter=blob:none", "origin", rev], cwd=path)
            _git(["checkout", "--quiet", "--detach", rev], cwd=path)
            head = _git(["rev-parse", "HEAD"], cwd=path)
            if head != rev:
                raise BenchmarkError(f"checked out {head}, expected {rev}")
            if _git(["status", "--porcelain", "--untracked-files=no"], cwd=path):
                raise BenchmarkError(f"{path} has local modifications")
        except (BenchmarkError, OSError) as exc:
            for target in group:
                problems[target["id"]] = str(exc)
    return problems


# ---------------------------------------------------------------------------
# Pure logic: replay classification, unit buckets, recall decisions
# ---------------------------------------------------------------------------


def classify_replay(artifact: dict | None, expected: dict) -> tuple[str, str | None]:
    """
    One replay against what the bug report recorded. Reproducing somewhere else is not keeping the
    bug: a false alarm that fires earlier would look like a reproduction but hide the real defect.
    Returns (reproduced | mismatch | not_reproduced | tool_failure, reason).
    """
    if artifact is None:
        return "tool_failure", "no replay result"
    if artifact.get("timed_out"):
        return "tool_failure", "replay timed out"
    if not artifact.get("reproducible"):
        return "not_reproduced", f"the input ran clean (exit code {artifact.get('returncode')})"
    failure = artifact.get("failure")
    if not failure:
        return "mismatch", "the input failed, but no failure report could be parsed"
    file = normalize_file(failure.get("file") or "")
    line = int(failure.get("line") or 0)
    function = failure.get("function")
    kind = failure.get("alarm_kind") or failure.get("kind")
    if file != expected["file"] or function != expected["function"] or kind != expected["alarm_kind"]:
        return "mismatch", f"failed at {file}:{line} in {function} ({kind})"
    if line not in expected["lines"]:
        return "mismatch", f"right function, unexpected line {line} (expected {expected['lines']})"
    return "reproduced", None


def unit_bucket(unit: dict) -> str:
    """proved | not_proved | tool_failure | not_reached | not_attempted | excluded, for one ledger unit."""
    status = unit.get("status")
    if status in EXCLUDED_STATUSES:
        return "excluded"
    if status == "covered":
        return "proved"
    if status == "candidate":
        return "not_proved"
    results = [e.get("result") for e in unit.get("evidence") or [] if e.get("phase") in ("eva", "wp")]
    last = results[-1] if results else None
    if last in TOOL_FAILURE_RESULTS:
        return "tool_failure"
    if status == "blocked":
        return "not_proved"
    if last is None:
        return "not_attempted"
    return "not_reached" if last in NOT_REACHED_RESULTS else "not_proved"


def _bucket_block(buckets: Counter) -> dict:
    # not_reached is not a tool failure, but nothing was decided: it lowers only the strict rate.
    block = rate_block(buckets["proved"], buckets["not_proved"], buckets["tool_failure"] + buckets["not_reached"])
    block["tool_failure"] = buckets["tool_failure"]
    block["not_reached"] = buckets["not_reached"]
    block["not_attempted"] = buckets["not_attempted"]
    return block


def summarize_units(ledger: list[dict]) -> dict:
    """Proof pass rate per call-graph wave and per obligation class, plus the covered and candidate unit ids."""
    by_wave: dict[str, Counter] = {}
    by_class: dict[str, Counter] = {}
    total: Counter = Counter()
    excluded = 0
    covered: list[str] = []
    candidate: list[str] = []
    for unit in ledger:
        bucket = unit_bucket(unit)
        if bucket == "excluded":
            excluded += 1
            continue
        wave = str(unit.get("wave")) if unit.get("wave") is not None else "none"
        by_wave.setdefault(wave, Counter())[bucket] += 1
        by_class.setdefault(str(unit.get("obligation_class")), Counter())[bucket] += 1
        total[bucket] += 1
        if unit.get("status") == "covered":
            covered.append(unit["coverage_id"])
        elif unit.get("status") == "candidate":
            candidate.append(unit["coverage_id"])
    return {
        "total": _bucket_block(total),
        "excluded": excluded,
        "by_wave": {k: _bucket_block(v) for k, v in by_wave.items()},
        "by_class": {k: _bucket_block(v) for k, v in by_class.items()},
        "covered": sorted(covered),
        "candidate": sorted(candidate),
    }


def decide_bug(bug: dict, outcomes: dict[tuple[str, str, str], dict]) -> dict:
    """
    Status of one recall bug from its replays. `outcomes` maps (target, module, engine) to the replay
    record; a replay that is absent was not selected. A bug is retained only when every selected
    required replay reproduced at the recorded site AND the mechanical gate confirmed it.
    """
    replays = []
    for spec in bug["replays"]:
        record = outcomes.get((spec["target"], spec["module"], spec["engine"]))
        entry = {
            "target": spec["target"],
            "module": spec["module"],
            "engine": spec["engine"],
            "required": bool(spec.get("required")),
            "outcome": "not_run",
        }
        if record:
            entry.update(
                outcome=record.get("outcome", "tool_failure"),
                reason=record.get("reason"),
                observed=record.get("observed"),
                fingerprint_as_recorded=record.get("fingerprint_as_recorded"),
                gate=record.get("gate"),
                eva_site=record.get("eva_site"),
                found_by_campaign=record.get("found_by_campaign"),
            )
        replays.append(entry)
    required = [r for r in replays if r["required"]]
    ran = [r for r in required if r["outcome"] != "not_run"]
    result: dict = {"status": "not_run", "reason": None, "replays": replays, "partial": False}
    if not ran:
        return result
    result["partial"] = len(ran) != len(required)
    decided_bad = [r for r in ran if r["outcome"] in ("mismatch", "not_reproduced")]
    if decided_bad:
        first = decided_bad[0]
        result.update(status="lost", reason=f"{first['target']}/{first['engine']}: {first.get('reason')}")
        return result
    tool_failed = [r for r in ran if r["outcome"] == "tool_failure"]
    if tool_failed:
        first = tool_failed[0]
        result.update(status="undecided", reason=f"{first['target']}/{first['engine']}: {first.get('reason')}")
        return result
    not_confirmed = [r for r in ran if r.get("gate") != "confirmed"]
    if not_confirmed:
        first = not_confirmed[0]
        result.update(status="lost", reason=f"{first['target']}/{first['engine']}: gate result {first.get('gate')}")
        return result
    result["status"] = "retained"
    return result


def recall_block(bugs: dict[str, dict]) -> dict:
    """Totals over per-bug entries; the two rates count a tool failure as undecided or as a failure."""
    statuses = Counter(entry["status"] for entry in bugs.values())
    return {
        "expected": len(bugs),
        "retained": statuses["retained"],
        "lost": sorted(k for k, v in bugs.items() if v["status"] == "lost"),
        "undecided": sorted(k for k, v in bugs.items() if v["status"] == "undecided"),
        "not_run": sorted(k for k, v in bugs.items() if v["status"] == "not_run"),
        "rates": rate_block(statuses["retained"], statuses["lost"], statuses["undecided"]),
        "bugs": bugs,
    }


# ---------------------------------------------------------------------------
# Metrics collection (host side: reads the run directory)
# ---------------------------------------------------------------------------


def _eva_coverage(log_text: str) -> dict:
    out: dict[str, int] = {}
    m = _EVA_FUNCTIONS_RE.search(log_text)
    if m:
        out["functions_analyzed"], out["functions_total"] = int(m.group(1)), int(m.group(2))
    m = _EVA_STATEMENTS_RE.search(log_text)
    if m:
        out["statements_reached"], out["statements_total"] = int(m.group(1)), int(m.group(2))
    return out


def in_scope_file(path: str, scope: Iterable[str]) -> bool:
    paths = [s.rstrip("/") for s in scope]
    return not paths or any(path == s or path.startswith(s + "/") for s in paths)


def _target_function_key(row: dict, function: str, scope: Iterable[str]) -> str | None:
    """`file#function` when an Eva row lies in the target's in-scope code; None for libc, stubs and harnesses."""
    directory = (row.get("directory") or "").replace("\\", "/").rstrip("/")
    file = (row.get("file") or "").replace("\\", "/")
    joined = f"{directory}/{file}" if directory and directory != "." else file
    if not joined.startswith("workspace/work/") and "/workspace/work/" not in joined:
        return None
    path = normalize_file(joined)
    return f"{path}#{function}" if in_scope_file(path, scope) else None


def _original_function_name(function: str, analyzed: set[str]) -> str:
    """Frama-C renames a static function it meets again in another translation unit (`f_0`): still one prover task."""
    match = _RENAMED_STATIC_RE.fullmatch(function)
    return match.group(1) if match and match.group(1) in analyzed else function


def summarize_eva(report: dict, ledger_rte: set[str], scope: Iterable[str] = (), run_dir: Path | None = None) -> dict:
    """
    One module's Eva block. A function with an Unknown costs a prover task only if the ledger has a
    unit for it, so one without a unit is reported apart: its Unknowns would silently go unproven.
    """
    status = report.get("status")
    block: dict = {
        "status": status,
        "reason": report.get("reason"),
        "error_summary": [str(x)[:300] for x in (report.get("error_summary") or [])[:3]],
    }
    if status != "ok":
        return block
    in_scope: set[str] = set()
    other: set[str] = set()
    kinds: Counter = Counter()
    analyzed = set(report.get("functions_with_properties") or [])
    for function, rows in (report.get("unknown_obligations_by_function") or {}).items():
        for row in rows:
            row = row if isinstance(row, dict) else {}
            kinds[row.get("kind") or "unknown"] += 1
            key = _target_function_key(row, _original_function_name(function, analyzed), scope)
            renamed = _RENAMED_STATIC_RE.fullmatch(function)
            if key is not None and key not in ledger_rte and renamed:
                # A renamed copy (`f_0`) of a function whose only analysed copies were renamed.
                stem = _target_function_key(row, renamed.group(1), scope)
                key = stem if stem in ledger_rte else key
            if key is None:
                other.add(function)
            else:
                in_scope.add(key)
    coverage = {}
    log_file = report.get("log_file")
    if run_dir is not None and log_file:
        try:
            coverage = _eva_coverage((run_dir / log_file).read_text(encoding="utf-8", errors="replace"))
        except OSError:
            coverage = {}
    block.update(
        valid=report.get("valid_count", 0),
        unknown=report.get("unknown_count", 0),
        invalid=report.get("invalid_count", 0),
        dead=report.get("dead_count", 0),
        assumed=report.get("assumed_count", 0),
        total=report.get("total_properties", 0),
        discharged_pct=report.get("discharged_percentage"),
        functions_with_unknown=sorted(in_scope),
        functions_with_unknown_count=len(in_scope),
        functions_with_unknown_no_unit=sorted(in_scope - ledger_rte),
        other_functions_with_unknown=sorted(other),
        unknown_by_kind=dict(sorted(kinds.items())),
        invalid_ids=sorted(
            make_fingerprint(
                a.get("file") or "", a.get("function") or "", a.get("kind") or "", a.get("annotation") or ""
            )
            for a in report.get("invalid_alarms") or []
        ),
        reduced_checks=sorted(report.get("reduced_checks") or []),
        undeclared_functions=sorted(report.get("undeclared_functions") or []),
        coverage=coverage,
    )
    return block


def summarize_fuzz(report: dict | None) -> dict | None:
    if not report:
        return None
    if report.get("stub"):
        return {"status": "not_run", "reason": report.get("reason")}
    fingerprints = sorted({a["fingerprint"] for a in report.get("artifacts") or [] if a.get("fingerprint")})
    sizing = report.get("sizing") or {}
    return {
        "status": report.get("status"),
        "engine": report.get("engine_used"),
        "engine_fallback_reason": report.get("engine_fallback_reason"),
        "artifacts": len(report.get("artifacts") or []),
        "fingerprints": fingerprints,
        "budget_cpu_s": sizing.get("fuzz_budget_cpu_s"),
        "workers": sizing.get("workers"),
        "max_time_s": sizing.get("max_time"),
        "reduced_checks": sorted(report.get("reduced_checks") or []),
    }


def summarize_build(report: dict | None) -> dict | None:
    if not report:
        return None
    return {
        "status": report.get("status"),
        "engine": report.get("engine_used"),
        "engine_fallback_reason": report.get("engine_fallback_reason"),
        "reduced_checks": sorted(report.get("reduced_checks") or []),
    }


def summarize_candidates(candidates: list[dict]) -> dict:
    fingerprints: dict[str, list[str]] = {}
    for cand in candidates:
        outputs = cand.get("tool_outputs") or []
        # Seeded by the benchmark's own replay, not found by a tool on its own.
        source = "replay" if outputs and all("bench-replay-" in o for o in outputs) else cand.get("origin", "unknown")
        fingerprints.setdefault(source, []).append(cand["fingerprint"])
    return {
        "total": len(candidates),
        "unverified": sum(1 for c in candidates if c.get("status") == "unverified"),
        "fingerprints": {k: sorted(v) for k, v in sorted(fingerprints.items())},
    }


def summarize_queue(queue_doc: dict | None) -> dict:
    tasks = [t for t in (queue_doc or {}).get("queue") or [] if t.get("state") == "pending"]
    by_wave = Counter(str(t.get("wave")) for t in tasks)
    return {
        "count": len(tasks),
        "by_wave": dict(sorted(by_wave.items())),
        "functions": sorted(f"{t.get('file')}#{t.get('function')}" for t in tasks),
    }


def _history_files(run_dir: Path) -> set[Path]:
    root = run_dir / "state" / "resource-history"
    return set(root.glob("*/*.json")) if root.is_dir() else set()


def _job_wall_seconds(run_dir: Path, cls: str) -> dict[str, float]:
    """Wall time of each Make recipe of a job class, by module (the sub-lease records; retries add up)."""
    totals: dict[str, float] = {}
    for path in (run_dir / "state" / "resource-history" / cls).glob("*.json"):
        record = read_json(path, {}) or {}
        key, wall = record.get("key"), record.get("wall_seconds")
        if record.get("scope") == "job" and key and isinstance(wall, (int, float)):
            totals[key] = round(totals.get(key, 0.0) + wall, 1)
    return totals


def modules_without_harness(ledger: list[dict], target: dict, dag: dict | None = None) -> list[str]:
    """
    In-scope modules no harness covers: Eva never runs on them, so their units can only read as tool
    failures. With link units (step I5b) a harness module covers the unit it belongs to.
    """
    harnessed = {m["name"] for m in target["modules"]}
    unit_of = (dag or {}).get("unit_of_lexer_module") or {}
    harnessed |= {unit_of[m] for m in harnessed if m in unit_of}
    active = {str(u.get("module")) for u in ledger if unit_bucket(u) != "excluded"}
    return sorted(active - harnessed)


def _profile_deferred_modules(run_dir: Path, names: list[str]) -> dict[str, str]:
    """Harness modules the run's profile defers by tier (step I8: Tier 3 under quick), with the reason."""
    from module_map import ModuleMap
    from tiers import is_deferred

    profile = (read_json(run_dir / "run-metadata.json", {}) or {}).get("profile")
    if not profile:
        return {}
    mm = ModuleMap.load(run_dir)
    out: dict[str, str] = {}
    for name in names:
        tier = mm.tier_of(name) or ""
        if is_deferred(tier, profile):
            out[name] = f"{tier.split(' (')[0]} deferred under the {profile} profile"
    return out


def collect_target_metrics(run_dir: Path, target: dict, phase_notes: list[str] | None = None) -> dict:
    """Everything the run file records about one target, read back from its run directory."""
    ledger = read_json(run_dir / "coverage-ledger.json", []) or []
    ledger_rte = {f"{u['file']}#{u['function']}" for u in ledger if u.get("obligation_class") == "rte"}
    eva_wall = _job_wall_seconds(run_dir, "eva")
    build_wall = _job_wall_seconds(run_dir, "build")
    fuzz_wall = _job_wall_seconds(run_dir, "fuzz")
    modules: dict[str, dict] = {}
    with_unknown: set[str] = set()
    problems = list(phase_notes or [])
    deferred = _profile_deferred_modules(run_dir, [m["name"] for m in target["modules"]])
    for module in target["modules"]:
        name = module["name"]
        eva_report = read_json(run_dir / "workspace" / "reports" / "eva" / f"{name}.json")
        eva_block = None
        if eva_report:
            eva_block = summarize_eva(eva_report, ledger_rte, target.get("scope") or (), run_dir)
            if name in eva_wall:
                eva_block["wall_s"] = eva_wall[name]
            with_unknown.update(eva_block.get("functions_with_unknown") or [])
            if eva_block["status"] != "ok":
                problems.append(f"eva {name}: {eva_block['status']}")
        elif name not in deferred:
            problems.append(f"eva {name}: no report")
        entry: dict = {
            "eva": eva_block,
            "fuzz": summarize_fuzz(read_json(run_dir / "workspace" / "reports" / "fuzz" / f"{name}.json")),
            "build": summarize_build(read_json(run_dir / "workspace" / "build" / f"{name}.build.json")),
        }
        if entry["build"] and name in build_wall:
            entry["build"]["wall_s"] = build_wall[name]
        if entry["fuzz"] and name in fuzz_wall:
            entry["fuzz"]["wall_s"] = fuzz_wall[name]
        if name in deferred:
            entry["deferred"] = deferred[name]
        modules[name] = entry
    dag = read_json(run_dir / "workspace" / "reports" / "callgraph_dag.json", {}) or {}
    return {
        "dag": {
            "functions": dag.get("total_functions"),
            "waves": dag.get("total_waves"),
            "c_files": dag.get("total_c_files"),
            "name_collisions": len(dag.get("name_collisions") or []),
            "recursion_cycles": len(dag.get("recursion_cycles") or []),
            "modules": sorted(dag.get("modules") or []),
        },
        "modules": modules,
        "functions_with_unknown": sorted(with_unknown),
        "functions_with_unknown_count": len(with_unknown),
        "functions_with_unknown_no_unit": sorted(with_unknown - ledger_rte),
        # Eva alone marked these covered while some module's Eva run leaves an Unknown in them.
        "covered_with_unknown": sorted(
            f"{u['file']}#{u['function']}"
            for u in ledger
            if u.get("obligation_class") == "rte"
            and u.get("status") == "covered"
            and f"{u['file']}#{u['function']}" in with_unknown
            and not any(e.get("phase") == "wp" and e.get("discharging") for e in u.get("evidence") or [])
        ),
        "prover_tasks": summarize_queue(read_json(run_dir / "workspace" / "reports" / "wp_queue.json")),
        "units": summarize_units(ledger),
        "modules_without_harness": modules_without_harness(ledger, target, dag),
        "candidates": summarize_candidates(read_json(run_dir / "candidates.json", []) or []),
        "mutation": summarize_mutation(run_dir / "workspace" / "reports" / "mutation.json"),
        "problems": problems,
    }


# ---------------------------------------------------------------------------
# Phase 3 (optional; the LLM host drives /framac-wp, this only reads what it left)
# ---------------------------------------------------------------------------


def summarize_phase3(run_dir: Path, usage: dict | None = None) -> dict:
    """
    Prover outcomes per wave, stalls, iterations and tokens. Tokens and exact iteration counts exist
    only when the host reports them (`usage`: {"agents": {id: {"input_tokens", "output_tokens",
    "iterations"}}}); otherwise they stay null rather than estimated.
    """
    schedule = read_json(run_dir / "state" / "wp_schedule.json", {}) or {}
    tasks = list((schedule.get("tasks") or {}).values())
    provers = [t for t in tasks if t.get("kind") == "prove"]
    per_wave: dict[str, Counter] = {}
    total: Counter = Counter()
    outcomes: Counter = Counter()
    dispatches = 0
    for task in provers:
        outcomes[str(task.get("outcome") or task.get("state"))] += 1
        dispatches += int(task.get("dispatches") or 0)
        if task.get("outcome") in ("no_open_units", "candidate"):
            continue  # nothing to prove, or excluded from WP because the function has a confirmed bug
        if task.get("outcome") == "merged":
            bucket = "passed"
        elif task.get("analysis_errors") or task.get("state") not in ("done", "blocked"):
            bucket = "undecided"  # a tool failure, or never finished: a timeout counts here
        else:
            bucket = "failed"
        total[bucket] += 1
        per_wave.setdefault(str(task.get("wave")), Counter())[bucket] += 1
    goals: Counter = Counter()
    for path in (run_dir / "workspace" / "reports" / "wp").glob("*.json"):
        report = read_json(path, {}) or {}
        for key in ("total_goals", "proven_count", "proven_under_hyp_count", "unproven_count"):
            goals[key] += int(report.get(key) or 0)
        goals["reports"] += 1
        if report.get("status") == "analysis_error":
            goals["analysis_errors"] += 1
    wp_containers = sum(
        1
        for path in (run_dir / "state" / "resource-history" / "wp").glob("*.json")
        if (read_json(path, {}) or {}).get("scope") == "container"
    )
    agents = (usage or {}).get("agents") or {}
    tokens = None
    iterations = None
    if agents:
        tokens = {
            "input": sum(int(a.get("input_tokens") or 0) for a in agents.values()),
            "output": sum(int(a.get("output_tokens") or 0) for a in agents.values()),
            "source": "host",
        }
        reported = [a["iterations"] for a in agents.values() if isinstance(a.get("iterations"), int)]
        iterations = sum(reported) if reported else None
    breakers = Counter(str(t.get("outcome")) for t in tasks if t.get("kind") == "breaker")
    return {
        "function_rate": rate_block(total["passed"], total["failed"], total["undecided"]),
        "function_rate_by_wave": {
            w: rate_block(c["passed"], c["failed"], c["undecided"]) for w, c in sorted(per_wave.items())
        },
        "prover_outcomes": dict(sorted(outcomes.items())),
        "stalls": outcomes["stalled_after_k_retries"],
        "dispatches": dispatches,
        "wp_containers": wp_containers,
        "iterations_host_reported": iterations,
        "breakers": dict(sorted(breakers.items())),
        "goals": dict(sorted(goals.items())),
        "tokens": tokens,
    }


# ---------------------------------------------------------------------------
# Running one target (host side)
# ---------------------------------------------------------------------------


def _is_windows() -> bool:
    return os.name == "nt"


def wrapper_argv(
    target: Path,
    run_dir: Path,
    repo: str,
    *,
    cls: str | None = None,
    packages: str = "",
    image: str | None = None,
    build_image: bool = False,
    scratch: bool = False,
) -> list[str]:
    """
    The wrapper command for this OS. The shared cross-run cache stays off: a benchmark must not reuse old results.
    `build_image` runs the stage in the build image (framac-build, or framac-build:<repo> with packages),
    `scratch` mounts the run's scratch volume at /framac-scratch.
    """
    if _is_windows():
        shell = shutil.which("pwsh") or shutil.which("powershell")
        if not shell:
            raise BenchmarkError("PowerShell not found: the Windows wrapper needs pwsh or powershell")
        argv = [
            shell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(PIPELINE_ROOT / "wrappers" / "framac-docker.ps1"),
        ]
        argv += [
            "-TargetDir",
            str(target),
            "-RunDir",
            str(run_dir),
            "-RepoName",
            repo,
            "-CacheDir",
            "off",
            "-BuildIfMissing",
        ]
        argv += ["-Class", cls] if cls else []
        argv += ["-TargetPackages", packages] if packages else []
        argv += ["-Image", image] if image else []
        argv += ["-BuildImage"] if build_image else []
        argv += ["-Scratch"] if scratch else []
        return argv
    argv = ["bash", str(PIPELINE_ROOT / "wrappers" / "framac-docker.sh")]
    argv += [
        "--target",
        str(target),
        "--run-dir",
        str(run_dir),
        "--repo",
        repo,
        "--cache-dir",
        "off",
        "--build-if-missing",
    ]
    argv += ["--class", cls] if cls else []
    argv += ["--target-packages", packages] if packages else []
    argv += ["--build-image"] if build_image else []
    argv += ["--scratch"] if scratch else []
    return argv


def run_stage(
    name: str,
    command: str,
    target: Path,
    run_dir: Path,
    repo: str,
    *,
    cls: str | None = None,
    packages: str = "",
    image: str | None = None,
    build_image: bool = False,
    scratch: bool = False,
) -> dict:
    """Run one command in a fresh container; rc, wall time and the CPU time the container recorded."""
    log_path = run_dir / BENCH_SUBDIR / "logs" / f"{name}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    before = _history_files(run_dir)
    argv = wrapper_argv(
        target, run_dir, repo, cls=cls, packages=packages, image=image, build_image=build_image, scratch=scratch
    )
    argv += [command] if _is_windows() else ["--", command]
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    if image and not _is_windows():
        env["FRAMAC_DOCKER_IMAGE"] = image
    started = time.monotonic()
    with open(log_path, "w", encoding="utf-8", errors="replace") as log:
        log.write(f"$ {command}\n")
        log.flush()
        proc = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, env=env, check=False)
    wall = round(time.monotonic() - started, 1)
    cpu = 0.0
    for path in _history_files(run_dir) - before:
        record = read_json(path, {}) or {}
        if record.get("scope") == "container" and isinstance(record.get("cpu_seconds"), (int, float)):
            cpu += record["cpu_seconds"]
    _say(f"  {name}: rc={proc.returncode} wall={wall}s cpu={round(cpu, 1)}s")
    return {"rc": proc.returncode, "wall_s": wall, "cpu_s": round(cpu, 1)}


def target_spec(target: dict, manifest: dict, *, fuzz_budget: int | None, eva_timeout: int | None) -> dict:
    """The file the container-side steps read: everything about the target, no host path."""
    replays = []
    for bug in manifest.get("bugs", []):
        for replay in bug["replays"]:
            if replay["target"] != target["id"]:
                continue
            replays.append(
                {
                    "bug": bug["id"],
                    "module": replay["module"],
                    "engine": replay["engine"],
                    "required": bool(replay.get("required")),
                    "file": bug["file"],
                    "function": bug["function"],
                    "alarm_kind": bug["alarm_kind"],
                    "fingerprint": bug["fingerprint"],
                    "lines": replay["lines"],
                    "input_hex": bug["input_hex"],
                    "input_sha256": bug["input_sha256"],
                    "verdict": bug["verdict"],
                    "reachability": bug["reachability"],
                    "severity": bug["severity"],
                    "title": bug["title"],
                }
            )
    defaults = manifest.get("defaults") or {}
    budget = fuzz_budget if fuzz_budget is not None else defaults.get("fuzz_budget_cpu_s")
    timeout = eva_timeout if eva_timeout is not None else defaults.get("eva_timeout_s")
    modules = []
    for module in target["modules"]:
        params = {"fuzz_budget": budget, "eva_timeout": timeout, **(module.get("params") or {})}
        modules.append(
            {
                "name": module["name"],
                "harness": module["harness"],
                "params": params,
                "reach_gaps_accepted": module.get("reach_gaps_accepted"),
                "unit": module.get("unit"),
            }
        )
    return {
        "id": target["id"],
        "repo": target["repo_name"],
        "profile": manifest.get("profile", "standard"),
        "scope": target.get("scope") or [],
        "modules": modules,
        "assets": target.get("assets") or [],
        "compile_commands": target.get("compile_commands"),
        "reach_exempt_modules": target.get("reach_exempt_modules") or {},
        # The build recipe build_capture.py runs (its `--recipe-file bench/spec.json` reads this block).
        "build": {**target["build"], "origin": "benchmark"} if target.get("build") else None,
        "replays": replays,
    }


def summarize_capture(report: dict | None) -> dict:
    """What the run file records of the build capture (its output is consumed from step I3 on)."""
    if not report:
        return {"status": "no_report"}
    out: dict[str, Any] = {"status": report.get("status")}
    if report.get("status") == "ok":
        units = report.get("units") or {}
        kinds = Counter(u.get("kind") for u in units.values() if not u.get("test"))
        out.update(
            units=len(units),
            test_units=sum(1 for u in units.values() if u.get("test")),
            kinds=dict(sorted((str(k), v) for k, v in kinds.items())),
            compiles=len(report.get("compiles") or []),
            entry_points=len(report.get("entry_points") or []),
            snapshot_files=(report.get("snapshot") or {}).get("files"),
            snapshot_digest=(report.get("snapshot") or {}).get("digest"),
            build_s=(report.get("build") or {}).get("seconds"),
            seconds=report.get("seconds"),
        )
    else:
        diag = report.get("diagnostics") or {}
        out["first_error"] = diag.get("first_error") or report.get("error")
        out["candidate_packages"] = diag.get("candidate_packages") or []
    return out


def run_capture(spec: dict, mount: Path, run_dir: Path, repo: str, packages: str, stages: dict[str, dict]) -> dict:
    """
    The build capture stage: build_capture.py in the build image (derived with the recipe's packages, or
    the target's), on the run's scratch volume, writing the run's snapshot; then the Phase 0 model
    (phase0_model.py) over that volume, in the analysis image. The volume is removed afterwards: later
    stages read the snapshot from the run directory, not the build tree.
    """
    if not spec.get("build"):
        return {"status": "no_recipe"}
    recipe_packages = " ".join((spec["build"] or {}).get("packages") or []) or packages
    stages["capture"] = run_stage(
        "capture",
        f"python3 {CONTAINER_SCRIPTS}/build_capture.py run --recipe-file {BENCH_SUBDIR}/spec.json",
        mount,
        run_dir,
        repo,
        cls="phase-dynamic",
        packages=recipe_packages,
        build_image=True,
        scratch=True,
    )
    summary = summarize_capture(read_json(run_dir / "workspace" / "reports" / "build_capture.json"))
    stages["capture"]["status"] = summary["status"]
    if summary["status"] == "ok":
        stages["model"] = run_stage(
            "model",
            f"python3 {CONTAINER_SCRIPTS}/phase0_model.py run",
            mount,
            run_dir,
            repo,
            cls="phase-static",
            scratch=True,
        )
        summary["model"] = summarize_model(read_json(run_dir / "workspace" / "reports" / "phase0_model.json"))
        stages["model"]["status"] = summary["model"]["status"]
    drop = wrapper_argv(mount, run_dir, repo) + (["-RemoveScratch"] if _is_windows() else ["--remove-scratch"])
    subprocess.run(drop, capture_output=True, check=False)
    return summary


def summarize_model(model: dict | None) -> dict:
    """What the run file records of the Phase 0 model: parse outcome per unit, size, and its cost."""
    if not model:
        return {"status": "no_report"}
    out: dict[str, Any] = {"status": model.get("status")}
    if model.get("status") != "ok":
        out["error"] = model.get("error")
        return out
    parses = Counter((u.get("parse") or {}).get("status") for u in (model.get("units") or {}).values())
    edges = Counter(e.get("kind") for e in model.get("edges") or [])
    out.update(
        parses=dict(sorted((str(k), v) for k, v in parses.items())),
        gcc_fallback=sorted(n for n, u in (model.get("units") or {}).items() if u["parse"]["status"] == "gcc_fallback"),
        functions=len(model.get("functions") or {}),
        direct_edges=edges.get("direct", 0),
        indirect_edges=edges.get("indirect", 0),
        macro_aliases=len(model.get("macro_aliases") or {}),
        thread_entries=len(model.get("thread_entries") or []),
        # Step I7: the threat model and CodeQL the trust annotation used, and its counts per rule.
        trust={
            "threat_model": ((model.get("trust") or {}).get("threat_model") or {}).get("status"),
            "codeql": ((model.get("trust") or {}).get("codeql") or {}).get("status"),
            "by_source": ((model.get("trust") or {}).get("summary") or {}).get("by_source"),
        },
        parse_s=round(sum(j.get("seconds") or 0 for j in model.get("parse_jobs") or []), 2),
        seconds=model.get("seconds"),
    )
    return out


def run_target(
    target: dict,
    manifest: dict,
    work_dir: Path,
    run_id: str,
    *,
    run_fuzz: bool,
    fuzz_budget: int | None,
    eva_timeout: int | None,
    phase0_only: bool = False,
) -> dict:
    tid = target["id"]
    mount = target_dir(target, work_dir)
    run_dir = (work_dir / "runs" / run_id / tid / RUN_DIR_NAME).resolve()
    if run_dir.exists():
        raise BenchmarkError(f"run directory {run_dir} already exists: pass a new --run-id")
    (run_dir / BENCH_SUBDIR / "assets").mkdir(parents=True)
    spec = target_spec(target, manifest, fuzz_budget=fuzz_budget, eva_timeout=eva_timeout)
    write_json(run_dir / BENCH_SUBDIR / "spec.json", spec)
    for asset in target.get("assets") or []:
        dest = run_dir / BENCH_SUBDIR / "assets" / asset["path"]
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ASSETS_DIR / asset["path"], dest)

    repo = target["repo_name"]
    packages = target.get("target_packages") or ""
    stages: dict[str, dict] = {}
    notes: list[str] = []
    started = time.monotonic()
    _say(f"{tid}: {mount.name} at {target['revision'][:12]}")

    def stage(name: str, command: str, cls: str | None = None) -> bool:
        # Every stage after the capture runs in the analysis image: target packages reach it only
        # through the run's snapshot (workspace/snapshot/), never through a derived image.
        info = run_stage(name, command, mount, run_dir, repo, cls=cls)
        stages[name] = info
        if info["rc"] != 0:
            notes.append(f"stage {name}: rc={info['rc']}")
        return info["rc"] == 0

    py = f"python3 {CONTAINER_SCRIPTS}"
    # A target's threat model (step I7) is supplied with the run, where trust.py looks first; it is
    # not part of harness_digest, as it changes no harness and no count the baselines compare.
    if target.get("threat_model"):
        (run_dir / "workspace").mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ASSETS_DIR / target["threat_model"]["path"], run_dir / "workspace" / "THREAT_MODEL.md")
    # The capture comes first: it writes the snapshot every later Frama-C and compiler step reads.
    capture = run_capture(spec, mount, run_dir, repo, packages, stages)
    if capture["status"] != "ok":
        notes.append(f"capture: {capture['status']}: {capture.get('first_error') or 'see bench/logs/capture.log'}")
    # A unit on the GCC fallback is flagged in the run file (build_capture.model.gcc_fallback), not a failure.
    model = capture.get("model") or {}
    if capture["status"] == "ok" and model.get("status") != "ok":
        notes.append(f"model: {model.get('status')}: {model.get('error') or 'see bench/logs/model.log'}")
    ok = stage("phase0", f"{py}/benchmark.py inner-phase0", "eva")
    if ok and (read_json(run_dir / BENCH_SUBDIR / "phase0.json", {}) or {}).get("ok") is not True:
        ok = False
        notes.append("phase0: see bench/phase0.json")
    if ok and not phase0_only:
        # build-check builds every module and records the E-ACSL gate the fuzz targets check.
        stage("build", f"{py}/pipeline_make.py build-check")
        if run_fuzz:
            stage("fuzz", f"{py}/pipeline_make.py run fuzz")
        stage("eva", f"{py}/pipeline_make.py run eva")
        if spec["replays"]:
            stage("replay", f"{py}/benchmark.py inner-replay", "phase-dynamic")
        stage("ingest", f"{py}/pipeline_make.py run ingest")
        if spec["replays"]:
            stage("gate", f"{py}/benchmark.py inner-gate", "light")
        stage("queue", f"{py}/pipeline_make.py run replay wp-queue")
        # As /framac-verify does after Phase 2, so an LLM host can continue this run directory with /framac-wp.
        stage(
            "checkpoint",
            f"{py}/checkpoint.py save-phase state --phase 2 --from-file workspace/reports/callgraph_dag.json",
            "light",
        )
    metrics = collect_target_metrics(run_dir, target, notes)
    metadata = read_json(run_dir / "run-metadata.json", {}) or {}
    entry = {
        "set": target["set"],
        "repo": target["url"],
        "revision": target["revision"],
        "subdir": target.get("subdir"),
        "harness_digest": harness_digest(target, manifest),
        "status": "ok" if ok and not metrics["problems"] else ("failed" if not ok else "partial"),
        "stages": stages,
        "wall_s": round(time.monotonic() - started, 1),
        "cpu_s": round(sum(s["cpu_s"] for s in stages.values()), 1),
        **metrics,
    }
    entry["build_capture"] = capture
    entry["_replay"] = annotate_replays(read_json(run_dir / BENCH_SUBDIR / "replay.json", {}) or {}, spec, run_dir)
    entry["_gate"] = read_json(run_dir / BENCH_SUBDIR / "gate.json", {}) or {}
    entry["_metadata"] = {
        "toolchain": metadata.get("toolchain") or {},
        "pool": ((metadata.get("resources") or {}).get("pool") or {}),
    }
    return entry


def eva_site_status(report: dict | None, file: str, function: str, lines: Iterable[int]) -> str:
    """
    What Eva says at a confirmed bug's site: invalid | unknown | dead | not_flagged | no_analysis.
    A static phase that stops flagging a real bug is unsound there, or its harness stopped reaching
    it, whatever the alarm counts did. It does not decide retention, but it must not go unnoticed.
    """
    if not report or report.get("status") != "ok":
        return "no_analysis"
    wanted = {int(line) for line in lines}

    def at_site(row: Any) -> bool:
        if not isinstance(row, dict) or row.get("function", function) != function:
            return False
        directory, name = row.get("directory") or "", row.get("file") or ""
        path = normalize_file(f"{directory}/{name}" if directory and directory != "." else name)
        return path == file and str(row.get("line") or "").isdigit() and int(row["line"]) in wanted

    if any(at_site(row) for row in report.get("invalid_alarms") or []):
        return "invalid"
    if any(at_site(row) for row in (report.get("unknown_obligations_by_function") or {}).get(function) or []):
        return "unknown"
    if any(at_site(row) for row in report.get("dead_alarms") or []):
        return "dead"
    return "not_flagged"


def annotate_replays(replay_doc: dict, spec: dict, run_dir: Path) -> dict:
    """Add to each replay what the other phases saw at the bug's site: Eva's status, and the campaign's finding."""
    specs = {(item["bug"], item["engine"]): item for item in spec.get("replays") or []}
    for record in replay_doc.get("results") or []:
        item = specs.get((record.get("bug"), record.get("engine")))
        if item is None:
            continue
        reports = run_dir / "workspace" / "reports"
        report = read_json(reports / "eva" / f"{record['module']}.json")
        record["eva_site"] = eva_site_status(report, item["file"], item["function"], item["lines"])
        fuzz = read_json(reports / "fuzz" / f"{record['module']}.json") or {}
        prefix = f"{item['file']}#{item['function']}::{item['alarm_kind']}::"
        record["found_by_campaign"] = any(
            str(artifact.get("fingerprint") or "").startswith(prefix) for artifact in fuzz.get("artifacts") or []
        )
    return replay_doc


def replay_outcomes(tid: str, replay_doc: dict, gate_doc: dict) -> dict[str, dict[tuple[str, str, str], dict]]:
    """bug id -> (target, module, engine) -> record, joining a target's replay and gate results."""
    gates = gate_doc.get("results") or {}
    outcomes: dict[str, dict[tuple[str, str, str], dict]] = {}
    for record in replay_doc.get("results") or []:
        merged = dict(record)
        merged["gate"] = gates.get(record["bug"], {}).get("gate") if record.get("required") else None
        outcomes.setdefault(record["bug"], {})[(tid, record["module"], record["engine"])] = merged
    return outcomes


# ---------------------------------------------------------------------------
# Container-side steps (run from the run directory)
# ---------------------------------------------------------------------------


def _load_spec() -> dict:
    return json.loads((Path(BENCH_SUBDIR) / "spec.json").read_text(encoding="utf-8"))


def _harness_argv(module: dict) -> list[str]:
    """generate_harness.py arguments from a manifest entry. Flag values use `=` so a leading '-' stays a value."""
    h = module["harness"]
    argv = [
        sys.executable,
        str(SCRIPTS_DIR / "generate_harness.py"),
        "--module",
        module["name"],
        "--sources",
        *h["sources"],
        "--header",
        h["header"],
        "--entry-fn",
        h["entry_fn"],
        "--entry-style",
        h.get("entry_style", "custom"),
        "--max-size",
        str(h.get("max_input_size", 1500)),
        f"--cppflags={h.get('cppflags', '-I.')}",
        f"--ldflags={h.get('ldflags', '')}",
        "--reachability",
        h.get("reachability", "untrusted_surface"),
        "--out-dir",
        "workspace/harnesses",
    ]
    for flag, key in (("--call-expr", "call_expr"), ("--eva-expr", "eva_expr"), ("--fuzz-expr", "fuzz_expr")):
        if h.get(key):
            argv.append(f"{flag}={h[key]}")
    for include in h.get("extra_includes") or []:
        argv += ["--extra-include", include]
    for callee in h.get("stubbed_callees") or []:
        argv += ["--stubbed-callee", callee]
    for note in h.get("contract_notes") or []:
        argv += ["--contract-note", note]
    if h.get("null_terminate"):
        argv.append("--null-terminate")
    if h.get("include_source"):
        argv.append("--include-source")
    if module.get("unit"):
        argv.append(f"--unit={module['unit']}")
    return argv


def unit_of_harness_module(dag: dict, name: str) -> str | None:
    """The link unit a manifest harness module falls in, per a DAG (None without link units or when unknown)."""
    if dag.get("module_kind") != "link_unit":
        return None
    if name in (dag.get("modules") or {}):
        return name
    return (dag.get("unit_of_lexer_module") or {}).get(name)


def unit_mismatches(spec_modules: list[dict], dag: dict) -> list[str]:
    """Manifest modules whose recorded `unit` is not the one the DAG puts them in."""
    out = []
    for module in spec_modules:
        want = module.get("unit")
        got = unit_of_harness_module(dag, module["name"])
        if want and dag.get("module_kind") == "link_unit" and got != want:
            out.append(f"{module['name']}: manifest unit {want!r}, DAG unit {got!r}")
    return out


def migrate_units(manifest: dict, dags: dict[str, dict]) -> dict[str, dict[str, str]]:
    """
    Record each harness module's link unit (`unit`) in the manifest from a link-unit DAG of its target.
    Harness module names do not change: a module whose name is a lexer module becomes a sub-module of
    the unit holding its functions. Returns {target: {module: unit}} for what was recorded.
    """
    changed: dict[str, dict[str, str]] = {}
    for target in manifest["targets"]:
        dag = dags.get(target["id"])
        if dag is None:
            continue
        if dag.get("module_kind") != "link_unit":
            raise BenchmarkError(f"{target['id']}: the DAG has no link units (built without the Phase 0 model?)")
        for module in target["modules"]:
            unit = unit_of_harness_module(dag, module["name"])
            if unit is None:
                raise BenchmarkError(f"{target['id']}: module {module['name']!r} is in no link unit of the DAG")
            if module.get("unit") != unit:
                module["unit"] = unit
                changed.setdefault(target["id"], {})[module["name"]] = unit
    return changed


def apply_reach_exemptions(spec: dict, harness_dir: Path = Path("workspace/harnesses")) -> dict:
    """
    Record the manifest's reach exemptions before the gate runs: modules it names in
    `reach_exempt_modules` (example and test programs), and every entry point the gate reports as
    unreached for a module with `reach_gaps_accepted` (a pinned recall harness drives only the entry
    points of the known bugs). Each exemption carries the manifest's reason.
    """
    import harness_reach  # container side, like pipeline_make

    for module, reason in sorted((spec.get("reach_exempt_modules") or {}).items()):
        harness_reach.record_exempt(harness_dir, module, None, str(reason))
    accepted = {m["name"]: m["reach_gaps_accepted"] for m in spec["modules"] if m.get("reach_gaps_accepted")}
    functions = 0
    if accepted:
        report = harness_reach.run_check(Path("workspace/reports/callgraph_dag.json"), harness_dir, sorted(accepted))
        for row in report["modules"]:
            for fn in row.get("gaps") or []:
                harness_reach.record_exempt(harness_dir, row["module"], fn, str(accepted[row["module"]]))
                functions += 1
    return {"modules_exempted": len(spec.get("reach_exempt_modules") or {}), "functions_exempted": functions}


def inner_phase0() -> int:
    """Phase 0 for a pinned harness spec: what /framac-slice does, with every judgment call already recorded."""
    import pipeline_make  # the container step needs the Make layer; the host never does

    spec = _load_spec()
    steps: list[dict] = []
    result: dict = {"ok": False, "steps": steps, "missing_modules": []}
    log_path = Path(BENCH_SUBDIR) / "logs" / "phase0-steps.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    scope_args = [a for s in spec["scope"] for a in ("--scope", s)]
    py = sys.executable

    def script(name: str) -> str:
        return str(SCRIPTS_DIR / name)

    with open(log_path, "w", encoding="utf-8", errors="replace") as log:

        def step(name: str, argv: list[str]) -> bool:
            started = time.monotonic()
            log.write(f"\n$ {' '.join(argv)}\n")
            log.flush()
            proc = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, check=False)
            steps.append({"name": name, "rc": proc.returncode, "wall_s": round(time.monotonic() - started, 2)})
            return proc.returncode == 0

        ok = step(
            "run_metadata",
            [py, script("run_metadata.py"), "init", "--repo", spec["repo"], "--profile", spec["profile"], *scope_args],
        ) and step(
            "overlay", [py, script("workspace_overlay.py"), "init", "--target", "/target", "--overlay", "workspace"]
        )
        if ok:
            for asset in spec["assets"]:
                dest = Path(asset["to"])
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(Path(BENCH_SUBDIR) / "assets" / asset["path"], dest)
            dag_args = [
                py,
                script("build_callgraph_dag.py"),
                "--target",
                "workspace/work",
                "--out",
                "workspace/reports/callgraph_dag.json",
            ]
            if spec.get("compile_commands"):
                dag_args += ["--compile-commands", spec["compile_commands"]]
            else:
                dag_args += ["--emit-compile-commands", "workspace/reports/compile_commands.json"]
            ok = step("dag", dag_args)
        if ok:
            dag = read_json(Path("workspace/reports/callgraph_dag.json"), {}) or {}
            # A harness module is a DAG module or, with link units (step I5b), a lexer module of one.
            known = {*(dag.get("modules") or {}), *(dag.get("unit_of_lexer_module") or {})}
            result["missing_modules"] = [m["name"] for m in spec["modules"] if m["name"] not in known]
            result["unit_mismatches"] = unit_mismatches(spec["modules"], dag)
            ok = not result["missing_modules"] and not result["unit_mismatches"]
        if ok:
            for module in spec["modules"]:
                ok = step(f"harness:{module['name']}", _harness_argv(module)) and ok
            for module in spec["modules"]:
                params = {k: v for k, v in (module.get("params") or {}).items() if v is not None}
                if params:
                    try:
                        pipeline_make.params_set(Path("."), module["name"], **params)
                    except (ValueError, RuntimeError) as exc:  # includes framac_common.ArtifactError
                        steps.append({"name": f"params:{module['name']}", "rc": 1, "error": str(exc)})
                        ok = False
        if ok:
            # The manifest's recorded exemptions, then the reach gate itself (it writes the stamp the
            # build, fuzz and Eva targets check).
            try:
                steps.append({"name": "reach_exemptions", "rc": 0, **apply_reach_exemptions(spec)})
            except (ValueError, RuntimeError, OSError) as exc:
                steps.append({"name": "reach_exemptions", "rc": 1, "error": str(exc)})
                ok = False
            ok = step("reach_gate", [py, script("harness_reach.py"), "check"]) and ok
        if ok:
            ok = (
                step(
                    "seed",
                    [
                        py,
                        script("ledger.py"),
                        "seed",
                        "--dag",
                        "workspace/reports/callgraph_dag.json",
                        "--profile",
                        spec["profile"],
                        *scope_args,
                    ],
                )
                and step("validate", [py, script("validate_artifacts.py"), "run-dir", "."])
                and step("checkpoint", [py, script("checkpoint.py"), "init", "state", "--target", "/target"])
                and step(
                    "checkpoint_phase0",
                    [
                        py,
                        script("checkpoint.py"),
                        "save-phase",
                        "state",
                        "--phase",
                        "0",
                        "--from-file",
                        "workspace/reports/callgraph_dag.json",
                    ],
                )
                and step("make_gen", [py, script("pipeline_make.py"), "gen"])
            )
    result["ok"] = bool(ok)
    write_json(Path(BENCH_SUBDIR) / "phase0.json", result)
    print(json.dumps({k: result.get(k) for k in ("ok", "missing_modules", "unit_mismatches")}))
    return 0 if ok else 1


def _replay_input(item: dict) -> Path:
    """The reproducer as a file under workspace/crashes (byte-exact from the manifest, digest checked)."""
    data = bytes.fromhex(item["input_hex"])
    if sha256_hex(data) != item["input_sha256"]:
        raise BenchmarkError(f"{item['bug']}: input digest mismatch")
    path = Path("workspace/crashes") / item["module"] / f"crash-{item['input_sha256'][:40]}"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def inner_replay() -> int:
    """
    Replay each bug's reproducer on the binary the pipeline builds today. Reports with a required
    replay that reproduced go through normal fuzz ingestion, so a filter added there is measured.
    """
    import run_eacsl_fuzz as fuzz

    spec = _load_spec()
    groups: dict[tuple[str, str], list[dict]] = {}
    for item in spec["replays"]:
        groups.setdefault((item["module"], item["engine"]), []).append(item)
    results: list[dict] = []
    for (module, engine), items in sorted(groups.items()):
        started = time.monotonic()
        inputs = {id(item): _replay_input(item) for item in items}
        failure_reason = None
        report: dict = {}
        try:
            build = fuzz.replay_build_spec(module, Path("workspace/harnesses"))
            prepared = fuzz.prepare_replay_binary(
                module,
                build["sources"],
                Path("workspace/harnesses") / (f"fuzz_{module}" if engine == "eacsl" else f"replay_san_{module}"),
                attribution=False,
                engine=engine,
                cppflags=build["cppflags"],
                ldflags=build["ldflags"],
                rte_initialized=bool(build.get("rte_initialized", True)),
            )
            report = fuzz.replay_report(
                module,
                sorted(set(inputs.values())),
                Path(BENCH_SUBDIR) / "scratch" / f"{module}-{engine}",
                prepared=prepared,
                per_input_timeout=PER_INPUT_TIMEOUT_S,
            )
            if report.get("status") == "error":
                failure_reason = str(report.get("reason") or "replay failed")
        except (OSError, ValueError, RuntimeError) as exc:
            failure_reason = f"{type(exc).__name__}: {exc}"
        by_path = {Path(a["artifact"]).as_posix(): a for a in report.get("artifacts") or []}
        to_ingest = []
        for item in items:
            artifact = by_path.get(inputs[id(item)].as_posix())
            outcome, reason = ("tool_failure", failure_reason) if failure_reason else classify_replay(artifact, item)
            failure = (artifact or {}).get("failure") or {}
            observed = {
                "file": normalize_file(failure.get("file") or "") if failure else None,
                "line": failure.get("line"),
                "function": failure.get("function"),
                "alarm_kind": failure.get("alarm_kind") or failure.get("kind"),
                "predicate": failure.get("predicate"),
                "fingerprint": (artifact or {}).get("fingerprint"),
            }
            results.append(
                {
                    "bug": item["bug"],
                    "module": module,
                    "engine": engine,
                    "required": item["required"],
                    "outcome": outcome,
                    "reason": reason,
                    "observed": observed,
                    "fingerprint_as_recorded": observed["fingerprint"] == item["fingerprint"],
                    "engine_used": report.get("engine_used"),
                    "wall_s": round(time.monotonic() - started, 1),
                }
            )
            if item["required"] and outcome == "reproduced":
                to_ingest.append(artifact)
        if to_ingest:
            ingest_report = {k: v for k, v in report.items() if k != "artifacts"}
            ingest_report["artifacts"] = to_ingest
            write_json(Path("workspace/reports/fuzz") / f"bench-replay-{module}-{engine}.json", ingest_report)
    write_json(Path(BENCH_SUBDIR) / "replay.json", {"results": results})
    print(json.dumps({r["bug"] + "/" + r["engine"]: r["outcome"] for r in results}, indent=1))
    return 0


def verifier_result(
    item: dict, replay: dict, candidate: dict, harness: dict, report_path: str, input_path: Path
) -> dict:
    """
    The crash_verifier result for a bug a human-checked campaign already confirmed. The judgment text
    is recorded in the manifest; this exercises everything mechanical around it, including
    `ledger.py ingest-verifier`, which refuses a confirmation without a reproducible replay.
    """
    observed = replay["observed"]
    verdict = item["verdict"]
    fingerprint = observed["fingerprint"]
    line = int(observed["line"])
    data = input_path.read_bytes()
    agent_id = f"bench-gate-{item['bug'].lower()}"
    record = {
        "verdict": "confirmed",
        "fingerprint": fingerprint,
        "title": item["title"],
        "description": verdict["description"],
        "location": {"file": observed["file"], "line": line, "function": observed["function"]},
        "property": {"kind": observed["alarm_kind"], "predicate": observed["predicate"] or item["alarm_kind"]},
        "root_cause": verdict["root_cause"],
        "intended_behavior": verdict["intended_behavior"],
        "trace": [
            {
                "kind": "sink",
                "file": observed["file"],
                "line": line,
                "function": observed["function"],
                "description": f"Replay of the recorded reproducer fails here ({replay['engine']}).",
            }
        ],
        "evidence": [
            {"phase": "fuzz", "tool_output": report_path, "description": "Benchmark replay of the recorded reproducer."}
        ],
        "reachability": item["reachability"],
        "harness": {
            "file": f"workspace/harnesses/harness_{item['module']}.c",
            "entry_function": harness["entry_fn"],
            "contract_respected": True,
            "notes": "Pinned harness spec from the campaign whose crash verifier confirmed this bug (docs/bugs-found).",
        },
        "reproducers": [
            {
                "input": input_path.as_posix(),
                "sha256": sha256_hex(data),
                "size_bytes": len(data),
                "command": f"python3 {CONTAINER_SCRIPTS}/benchmark.py inner-replay",
                "observed_result": f"{observed['alarm_kind']} at {observed['file']}:{line} in {observed['function']}",
            }
        ],
        "severity": item["severity"],
        "severity_rationale": verdict["severity_rationale"],
        "remediation": {
            "summary": verdict["remediation_summary"],
            "invariant": verdict["remediation_invariant"],
            "fix_patch": None,
        },
        "linked_units": list(candidate.get("linked_units") or []),
        "verifier": {
            "agent_id": agent_id,
            "method": "reproduced",
            "notes": "Mechanical benchmark gate: the replay is new, the judgment text comes from the original verifier.",
        },
    }
    return {
        "role": "crash_verifier",
        "agent_id": agent_id,
        "candidate_fingerprint": fingerprint,
        "decision": "confirmed",
        "refingerprint_reason": None,
        "record": record,
    }


def inner_gate() -> int:
    """
    The mechanical part of the Crash Verification Gate: the candidate must exist after normal
    ingestion (a filter may have dropped it) and `ingest-verifier` must accept the confirmation.
    """
    spec = _load_spec()
    replay_doc = read_json(Path(BENCH_SUBDIR) / "replay.json", {}) or {}
    items = {(i["bug"], i["engine"]): i for i in spec["replays"]}
    harnesses = {m["name"]: m["harness"] for m in spec["modules"]}
    candidates = {c["fingerprint"]: c for c in read_json(Path("candidates.json"), []) or []}
    results: dict[str, dict] = {}
    for replay in replay_doc.get("results") or []:
        if not replay.get("required") or replay.get("outcome") != "reproduced":
            continue
        item = items[(replay["bug"], replay["engine"])]
        fingerprint = replay["observed"]["fingerprint"]
        candidate = candidates.get(fingerprint)
        if candidate is None:
            results[replay["bug"]] = {"gate": "filtered_at_ingest", "detail": f"no candidate {fingerprint}"}
            continue
        if not candidate.get("linked_units"):
            results[replay["bug"]] = {"gate": "no_ledger_unit", "detail": str(candidate.get("notes"))}
            continue
        report_path = f"workspace/reports/fuzz/bench-replay-{replay['module']}-{replay['engine']}.json"
        input_path = Path("workspace/crashes") / replay["module"] / f"crash-{item['input_sha256'][:40]}"
        result = verifier_result(item, replay, candidate, harnesses[replay["module"]], report_path, input_path)
        result_path = Path("agents") / result["agent_id"] / "scratch" / "result.json"
        write_json(result_path, result)
        proc = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS_DIR / "ledger.py"),
                "ingest-verifier",
                str(result_path),
                "--replay-report",
                report_path,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if proc.returncode != 0:
            results[replay["bug"]] = {"gate": "rejected", "detail": ((proc.stderr or "") + (proc.stdout or ""))[-600:]}
            continue
        findings = {f["fingerprint"]: f for f in read_json(Path("findings.json"), []) or []}
        resolved = json.loads(proc.stdout or "{}").get("resolved_fingerprints") or [fingerprint]
        confirmed = any((findings.get(fp) or {}).get("verdict") == "confirmed" for fp in resolved)
        results[replay["bug"]] = {"gate": "confirmed" if confirmed else "not_confirmed", "resolved": resolved}
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "validate_artifacts.py"), "run-dir", "."],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    write_json(
        Path(BENCH_SUBDIR) / "gate.json",
        {"results": results, "validators_ok": proc.returncode == 0, "validators_output": (proc.stdout or "")[-2000:]},
    )
    print(json.dumps(results, indent=1))
    return 0 if proc.returncode == 0 else 1


# ---------------------------------------------------------------------------
# Run files
# ---------------------------------------------------------------------------


def validate_run(run: dict) -> list[str]:
    """Contract problems of a run file (schemas/benchmark-run.schema.json); empty when it is usable."""
    return list(Validator(load_schema(RUN_SCHEMA)).errors(run))


def assert_no_host_paths(value: Any, where: str = "$") -> None:
    """A run file may be committed as a baseline: it must not carry a home directory or machine layout."""
    if isinstance(value, dict):
        for key, item in value.items():
            assert_no_host_paths(item, f"{where}.{key}")
    elif isinstance(value, list):
        for idx, item in enumerate(value):
            assert_no_host_paths(item, f"{where}[{idx}]")
    elif isinstance(value, str) and _HOST_PATH_RE.search(value):
        raise BenchmarkError(f"host path in the run file at {where}: {value[:120]}")


def scrub_host_paths(value: Any, replacements: list[tuple[str, str]]) -> Any:
    """Replace host path prefixes that tools echo into error text."""
    if isinstance(value, dict):
        return {k: scrub_host_paths(v, replacements) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub_host_paths(v, replacements) for v in value]
    if isinstance(value, str):
        for old, new in replacements:
            value = value.replace(old, new).replace(old.replace("\\", "/"), new)
    return value


def default_work_dir() -> Path:
    env = (os.environ.get("FRAMAC_BENCH_DIR") or "").strip()
    return Path(env) if env else Path.home() / "framac-pipeline" / "benchmark"


def new_run_id() -> str:
    return datetime.now(timezone.utc).strftime("bench-%Y%m%dT%H%M%SZ")


def build_run_file(
    manifest: dict, run_id: str, targets: dict[str, dict], selection: dict, limits: dict, work_dir: Path
) -> dict:
    toolchain: dict = {}
    machine: dict = {}
    clean_targets: dict[str, dict] = {}
    by_bug: dict[str, dict[tuple[str, str, str], dict]] = {}
    for tid, entry in targets.items():
        entry = dict(entry)
        replay_doc, gate_doc, meta = entry.pop("_replay", {}), entry.pop("_gate", {}), entry.pop("_metadata", {})
        toolchain = toolchain or meta.get("toolchain") or {}
        machine = machine or meta.get("pool") or {}
        for bug, records in replay_outcomes(tid, replay_doc, gate_doc).items():
            by_bug.setdefault(bug, {}).update(records)
        if gate_doc and not gate_doc.get("validators_ok", True):
            entry["problems"] = [*entry.get("problems", []), "validators failed after the gate"]
            entry["status"] = "partial" if entry.get("status") == "ok" else entry.get("status")
        clean_targets[tid] = entry
    recall = recall_block({bug["id"]: decide_bug(bug, by_bug.get(bug["id"], {})) for bug in manifest.get("bugs", [])})
    machine = {k: machine.get(k) for k in ("cpus", "mem_mb")} if machine else {}
    run = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "created_at": utc_now(),
        "mode": "deterministic",
        "pipeline": pipeline_identity(),
        "toolchain": toolchain,
        "machine": machine,
        "limits": {
            "wp_memlimit_mb": WP_MEMLIMIT_MB,
            "fuzz_rss_limit_mb": FUZZ_RSS_LIMIT_MB,
            "replay_per_input_timeout_s": PER_INPUT_TIMEOUT_S,
            **limits,
        },
        "selection": selection,
        "targets": clean_targets,
        "recall": recall,
        "briefs": None,
        "totals": {
            "wall_s": round(sum(t.get("wall_s") or 0 for t in clean_targets.values()), 1),
            "cpu_s": round(sum(t.get("cpu_s") or 0 for t in clean_targets.values()), 1),
        },
    }
    replacements = [
        (str(work_dir.resolve()), "<work>"),
        (str(Path.home()), "<home>"),
        (str(PIPELINE_ROOT), "<pipeline>"),
    ]
    return scrub_host_paths(run, replacements)


def print_summary(run: dict) -> None:
    recall = run.get("recall") or {}
    rates = recall.get("rates") or {}
    print(
        f"Run {run.get('run_id')}: toolchain {(run.get('toolchain') or {}).get('frama-c')}, wall {run['totals']['wall_s']}s, CPU {run['totals']['cpu_s']}s"
    )
    print(
        f"Recall: {recall.get('retained')}/{recall.get('expected')} retained; lost {recall.get('lost')}, "
        f"undecided {recall.get('undecided')}, not run {recall.get('not_run')}; "
        f"rate over decided {rates.get('over_decided')}, strict {rates.get('strict')}"
    )
    drifted = sorted(
        bug
        for bug, entry in (recall.get("bugs") or {}).items()
        if any(r.get("required") and r.get("fingerprint_as_recorded") is False for r in entry.get("replays") or [])
    )
    if drifted:
        print(f"  Same site, but not the fingerprint docs/bugs-found records: {', '.join(drifted)}")
    for tid, target in sorted((run.get("targets") or {}).items()):
        units = (target.get("units") or {}).get("total") or {}
        print(
            f"  {tid} [{target.get('status')}]: {target.get('functions_with_unknown_count')} function(s) with an Unknown, "
            f"{(target.get('prover_tasks') or {}).get('count')} prover task(s), units proved {units.get('passed')} "
            f"(over decided {units.get('over_decided')}, strict {units.get('strict')}), wall {target.get('wall_s')}s, CPU {target.get('cpu_s')}s"
        )
        if target.get("functions_with_unknown_no_unit"):
            print(
                f"    WARNING: {len(target['functions_with_unknown_no_unit'])} function(s) with an Unknown have no ledger unit, so no prover is assigned"
            )
        if target.get("covered_with_unknown"):
            print(
                f"    WARNING: {len(target['covered_with_unknown'])} unit(s) covered by Eva although an Eva run leaves an Unknown in them: "
                + ", ".join(target["covered_with_unknown"][:5])
            )
        if target.get("modules_without_harness"):
            print(f"    In scope with no harness: {', '.join(target['modules_without_harness'])}")
        for name, module in sorted((target.get("modules") or {}).items()):
            eva = module.get("eva") or {}
            if eva.get("status") == "ok":
                fuzz = module.get("fuzz") or {}
                campaign = f"; campaign {fuzz.get('status')} ({fuzz.get('engine')})" if fuzz else ""
                print(
                    f"    {name}: Valid {eva.get('valid')}, Unknown {eva.get('unknown')}, Invalid {eva.get('invalid')}, "
                    f"Dead {eva.get('dead')}; {eva.get('functions_with_unknown_count')} function(s) with an Unknown{campaign}"
                )
            else:
                print(f"    {name}: Eva {eva.get('status') or 'no report'} {eva.get('reason') or ''}".rstrip())
    not_run = (run.get("selection") or {}).get("targets_not_run") or {}
    for tid, reason in sorted(not_run.items()):
        print(f"  {tid}: NOT RUN ({reason})")


def resolve_baseline(name_or_path: str) -> Path:
    path = Path(name_or_path)
    if path.is_file():
        return path
    candidate = BASELINES_DIR / f"{name_or_path}.json"
    if candidate.is_file():
        return candidate
    raise BenchmarkError(f"no baseline {name_or_path!r}: neither a file nor {candidate}")


def merge_runs(runs: list[dict]) -> dict:
    """A baseline from several runs (a slow target can be re-baselined alone): later runs win, per target and per bug."""
    merged = json.loads(json.dumps(runs[0]))
    for run in runs[1:]:
        merged["targets"].update(run.get("targets") or {})
        merged["recall"]["bugs"].update(
            {k: v for k, v in run["recall"]["bugs"].items() if v.get("status") != "not_run"}
        )
        for key in ("pipeline", "toolchain", "machine", "limits", "created_at", "run_id"):
            merged[key] = run.get(key, merged.get(key))
        if run.get("briefs"):
            merged["briefs"] = run["briefs"]
    merged["recall"] = recall_block(merged["recall"]["bugs"])
    merged["totals"] = {
        "wall_s": round(sum(t.get("wall_s") or 0 for t in merged["targets"].values()), 1),
        "cpu_s": round(sum(t.get("cpu_s") or 0 for t in merged["targets"].values()), 1),
    }
    return merged


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def cmd_run(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.manifest)
    problems = validate_manifest(manifest)
    if problems:
        raise BenchmarkError("manifest problems: " + "; ".join(problems))
    if getattr(args, "profile", None):
        # The run's profile (run-metadata.json); it is part of harness_digest, so compare flags it.
        manifest = {**manifest, "profile": args.profile}
    work_dir = Path(args.work_dir).resolve()
    targets = select_targets(manifest, args.set or ["all"], args.target or [])
    run_id = args.run_id or new_run_id()
    not_run = {t["id"]: "not selected" for t in manifest["targets"] if t not in targets}
    fetch_problems = fetch_targets(targets, work_dir, manifest)
    results: dict[str, dict] = {}
    for target in targets:
        if target["id"] in fetch_problems:
            not_run[target["id"]] = f"fetch failed: {fetch_problems[target['id']]}"
            continue
        results[target["id"]] = run_target(
            target,
            manifest,
            work_dir,
            run_id,
            run_fuzz=not args.no_fuzz,
            fuzz_budget=args.fuzz_budget,
            eva_timeout=args.eva_timeout,
            phase0_only=args.phase0_only,
        )
    defaults = manifest.get("defaults") or {}
    limits = {
        "eva_timeout_s": args.eva_timeout if args.eva_timeout is not None else defaults.get("eva_timeout_s"),
        "fuzz_budget_cpu_s": args.fuzz_budget if args.fuzz_budget is not None else defaults.get("fuzz_budget_cpu_s"),
    }
    selection = {
        "sets": args.set or ["all"],
        "targets": sorted(results),
        "targets_not_run": not_run,
        "fuzz": not args.no_fuzz,
        "profile": manifest.get("profile", "standard"),
        "left_out": manifest.get("left_out") or {},
    }
    run = build_run_file(manifest, run_id, results, selection, limits, work_dir)
    if args.briefs_dataset:
        import benchmark_briefs

        run["briefs"] = benchmark_briefs.run_control_arm(Path(args.briefs_dataset), work_dir, run_id)
    out = Path(args.out) if args.out else work_dir / "results" / f"{run_id}.json"
    write_json(out, run)
    for problem in validate_run(run):
        _say(f"run file contract problem: {problem}")
    print_summary(run)
    print(f"Run file: {out}")
    if not args.compare:
        recall = run["recall"]
        return 1 if recall["lost"] or recall["undecided"] else 0
    baseline = load_run(resolve_baseline(args.compare))
    result = compare_runs(baseline, run, Tolerances())
    print(f"\nDifferences against baseline {args.compare}:")
    print(render_text(result, verbose=args.verbose))
    return 1 if result.failed(args.fail_on) else 0


def cmd_compare(args: argparse.Namespace) -> int:
    baseline = load_run(resolve_baseline(args.baseline))
    current = load_run(args.current)
    result = compare_runs(baseline, current, Tolerances(), require_all=args.require_all)
    print(render_text(result, verbose=args.verbose))
    if args.json:
        write_json(Path(args.json), result.to_json())
    return 1 if result.failed(args.fail_on) else 0


def cmd_baseline(args: argparse.Namespace) -> int:
    runs = [load_run(p) for p in args.run]
    run = merge_runs(runs)
    problems = validate_run(run)
    if problems:
        raise BenchmarkError("not a valid run file: " + "; ".join(problems[:5]))
    assert_no_host_paths(run)
    recall = run["recall"]
    if (recall["lost"] or recall["undecided"]) and not args.force:
        raise BenchmarkError(
            f"refusing to store a baseline that does not keep every bug: lost {recall['lost']}, "
            f"undecided {recall['undecided']} (--force overrides)"
        )
    out = BASELINES_DIR / f"{args.name}.json"
    write_json(out, run)
    print(f"Stored {out} from {', '.join(r['run_id'] for r in runs)}")
    if recall["not_run"]:
        print(f"Bugs not covered by this baseline: {recall['not_run']}")
    return 0


def cmd_fetch(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.manifest)
    work_dir = Path(args.work_dir).resolve()
    targets = select_targets(manifest, args.set or ["all"], args.target or [])
    problems = fetch_targets(targets, work_dir, manifest)
    for tid, problem in sorted(problems.items()):
        print(f"{tid}: {problem}", file=sys.stderr)
    print(json.dumps({t["id"]: str(target_dir(t, work_dir)) for t in targets if t["id"] not in problems}, indent=2))
    return 1 if problems else 0


def cmd_check_manifest(args: argparse.Namespace) -> int:
    problems = validate_manifest(load_manifest(args.manifest))
    for problem in problems:
        print(problem, file=sys.stderr)
    print(json.dumps({"ok": not problems, "problems": len(problems)}))
    return 1 if problems else 0


def cmd_measure_llm(args: argparse.Namespace) -> int:
    run = load_run(args.run_file)
    manifest = load_manifest(args.manifest)
    target = next((t for t in manifest["targets"] if t["id"] == args.target), None)
    if target is None or args.target not in run["targets"]:
        raise BenchmarkError(f"target {args.target!r} is not in this run")
    work_dir = Path(args.work_dir).resolve()
    run_dir = Path(args.run_dir) if args.run_dir else work_dir / "runs" / run["run_id"] / args.target / RUN_DIR_NAME
    if not (run_dir / "state" / "wp_schedule.json").is_file():
        raise BenchmarkError(f"{run_dir} has no Phase 3 schedule; run /framac-wp on it first")
    usage = read_json(Path(args.host_usage)) if args.host_usage else None
    entry = run["targets"][args.target]
    metrics = collect_target_metrics(run_dir, target, entry.get("problems"))
    entry.update(metrics)
    entry["phase3"] = summarize_phase3(run_dir, usage)
    run["mode"] = "deterministic+llm"
    replacements = [(str(work_dir), "<work>"), (str(Path.home()), "<home>")]
    write_json(Path(args.out), scrub_host_paths(run, replacements))
    print(json.dumps(entry["phase3"], indent=2))
    return 0


def cmd_migrate_units(args: argparse.Namespace) -> int:
    dags: dict[str, dict] = {}
    for item in args.dag:
        tid, sep, path = item.partition("=")
        if not sep:
            raise BenchmarkError(f"--dag wants TARGET=FILE, got {item!r}")
        dag = read_json(Path(path))
        if not isinstance(dag, dict):
            raise BenchmarkError(f"{path}: not a DAG")
        dags[tid] = dag
    manifest = load_manifest(args.manifest)
    changed = migrate_units(manifest, dags)
    if changed and not args.dry_run:
        Path(args.manifest).write_bytes(json.dumps(manifest, indent=1).encode("utf-8"))
    print(json.dumps(changed, indent=2, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Repeatable benchmark of the Frama-C pipeline (docs/benchmark.md).")
    sub = parser.add_subparsers(dest="cmd", required=True)
    # The phase0 set has its own runner and options (scripts/benchmark_seeded.py run --help).
    sub.add_parser("seeded", help="The phase0 set: seeded-bug projects (benchmark_seeded.py run; see its --help)")
    raw = sys.argv[1:] if argv is None else list(argv)
    if raw[:1] == ["seeded"]:
        import benchmark_seeded

        return benchmark_seeded.main(["run", *raw[1:]])

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
        p.add_argument(
            "--work-dir",
            default=None,
            help="Targets, run directories and results (default: ~/framac-pipeline/benchmark or FRAMAC_BENCH_DIR)",
        )

    def selection(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--set",
            action="append",
            choices=["recall", "comparison", "all"],
            help="Which set (repeatable; default all)",
        )
        p.add_argument("--target", action="append", help="Only this target id (repeatable)")

    p_run = sub.add_parser("run", help="Phases 0 to 2 plus reproducer replay, with no LLM")
    common(p_run)
    selection(p_run)
    p_run.add_argument("--run-id", default=None)
    p_run.add_argument("--out", default=None, help="Run file (default: <work-dir>/results/<run-id>.json)")
    p_run.add_argument("--no-fuzz", action="store_true", help="Skip Phase 1 campaigns (Eva and replay only)")
    p_run.add_argument("--phase0-only", action="store_true", help="Stop after Phase 0 (to check a harness spec)")
    p_run.add_argument(
        "--fuzz-budget", type=int, default=None, help="CPU-seconds per campaign (default: the manifest's)"
    )
    p_run.add_argument(
        "--eva-timeout", type=int, default=None, help="Eva wall-clock seconds per module (default: the manifest's)"
    )
    p_run.add_argument(
        "--profile",
        choices=["quick", "standard", "deep"],
        default=None,
        help="Pipeline profile of the runs (default: the manifest's); quick defers Tier 3 modules",
    )
    p_run.add_argument(
        "--compare", default=None, help="Baseline name or file; print the differences and exit 1 on a regression"
    )
    p_run.add_argument("--fail-on", choices=["regression", "warning"], default="regression")
    p_run.add_argument("--verbose", action="store_true", help="Also print info and not_compared rows")
    p_run.add_argument(
        "--briefs-dataset", default=None, help="Assert-program dataset directory: also run the no-LLM control arm"
    )
    p_run.set_defaults(func=cmd_run)

    p_cmp = sub.add_parser("compare", help="Print the differences between a baseline and a run file")
    p_cmp.add_argument("baseline", help="Baseline name (under benchmark/baselines) or file")
    p_cmp.add_argument("current", type=Path)
    p_cmp.add_argument("--require-all", action="store_true", help="A bug that was not run counts as lost")
    p_cmp.add_argument("--fail-on", choices=["regression", "warning"], default="regression")
    p_cmp.add_argument("--json", default=None, help="Also write the differences to this file")
    p_cmp.add_argument("--verbose", action="store_true")
    p_cmp.set_defaults(func=cmd_compare)

    p_base = sub.add_parser("baseline", help="Store run file(s) as a baseline under benchmark/baselines")
    p_base.add_argument(
        "--run", action="append", type=Path, required=True, help="Run file (repeatable: later ones win per target)"
    )
    p_base.add_argument("--name", default="default")
    p_base.add_argument("--force", action="store_true", help="Store even if a bug is not retained")
    p_base.set_defaults(func=cmd_baseline)

    p_fetch = sub.add_parser("fetch", help="Clone the selected targets at their pinned revisions")
    common(p_fetch)
    selection(p_fetch)
    p_fetch.set_defaults(func=cmd_fetch)

    p_check = sub.add_parser("check-manifest", help="Validate the manifest")
    p_check.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    p_check.set_defaults(func=cmd_check_manifest)

    p_llm = sub.add_parser(
        "measure-llm", help="Add Phase 3 metrics to a run file after /framac-wp ran on a target's run directory"
    )
    common(p_llm)
    p_llm.add_argument("--run-file", type=Path, required=True)
    p_llm.add_argument("--target", required=True)
    p_llm.add_argument("--run-dir", default=None, help="Default: <work-dir>/runs/<run-id>/<target>/run-1")
    p_llm.add_argument(
        "--host-usage",
        default=None,
        help='JSON the host wrote: {"agents": {id: {"input_tokens", "output_tokens", "iterations"}}}',
    )
    p_llm.add_argument("--out", required=True)
    p_llm.set_defaults(func=cmd_measure_llm)

    p_mig = sub.add_parser(
        "migrate-units", help="Record each harness module's link unit in the manifest, from link-unit DAGs"
    )
    p_mig.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    p_mig.add_argument(
        "--dag", action="append", required=True, help="TARGET=callgraph_dag.json of a run with link units (repeatable)"
    )
    p_mig.add_argument("--dry-run", action="store_true")
    p_mig.set_defaults(func=cmd_migrate_units)

    for name, func in (("inner-phase0", inner_phase0), ("inner-replay", inner_replay), ("inner-gate", inner_gate)):
        sub.add_parser(name, help="Container-side step, started by `run`").set_defaults(inner=func)

    args = parser.parse_args(argv)
    if hasattr(args, "inner"):
        return args.inner()
    if hasattr(args, "work_dir") and args.work_dir is None:
        args.work_dir = str(default_work_dir())
    try:
        return args.func(args)
    except (BenchmarkError, OSError, ValueError) as exc:
        print(f"benchmark: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
