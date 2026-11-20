#!/usr/bin/env python3
"""
Manages the run's workspace/ shadow overlay (inside ~/framac-pipeline/<repo>/run-<N>/)
and per-agent isolated scratch overlays (agents/<agent-id>/scratch/work/).

Guarantees:
1. Target repository files are never modified during a run (inside the container
   the target is mounted read-only at /target).
2. Subagents work in isolated scratch copies (agents/<id>/scratch/work/).
3. Only ACSL-only changes within the subagent's assigned function/header scope
   are spliced into workspace/work/, and the parent re-verifies the merged tree
   (rolling back automatically on failure) before committing.
4. Writes to workspace/work/ hold the run-wide `merge` lock and are journaled in
   state/merge-journal.json, so a merge killed between splice and rollback is undone
   by the next merge or prepare call instead of leaving unverified ACSL behind.
5. A merge batch re-checks its overlays in parallel within the job budget (one guardrail
   per module, one WP run per prover) and converges to the largest passing subset.
6. `apply-in-place` is a host-side step run after the final report.
"""

from __future__ import annotations

import argparse
import base64
import difflib
import hashlib
import inspect
import json
import os
import posixpath
import re
import shlex
import shutil
import subprocess
import sys
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import contract_refinement  # noqa: E402
import function_facts  # noqa: E402
import function_slice  # noqa: E402
import line_endings  # noqa: E402
import prover_candidates  # noqa: E402
import spec_kb  # noqa: E402
import target_env  # noqa: E402
from acsl_ast import (  # noqa: E402
    DEFAULT_BEHAVIOR,
    AcslError,
    ConflictingProfileError,
    ScopeViolationError,
    TrustBoundaryError,
    check_conflicting_acsl_profiles,
    check_frame_preserved,
    compare_function_contracts,
    contract_declaration_spans,
    contract_has_whole_frame,
    declaration_contract_text,
    declaration_param_names,
    dedup_acsl_declarations,
    entry_requires_violations,
    extract_top_level_acsl_declarations,
    function_declaration_spans,
    function_trust_records,
    is_trust_boundary,
    locate_all_definition_spans,
    locate_all_prototype_spans,
    locate_function_span,
    mask_comments_and_literals,
    splice_architect_header,
    splice_prover_changes,
    verify_acsl_only,
)
from fingerprint import normalize_file  # noqa: E402
from framac_common import (  # noqa: E402
    EVA_REPORT_MAX_BYTES,
    PROVER_WALL_BUDGET_S,
    ArtifactError,
    atomic_write_json,
    eva_alarm_in_file,
    is_pipeline_output_dir,
    is_safe_agent_id,
    is_safe_relative_path,
    load_agent_result_json,
    load_json_optional,
    load_json_strict,
    normalize_flag_args,
    run_lock,
    scratch_first_cppflags,
    source_tree_relpath,
    utc_now,
    wp_model_problem,
)
from module_map import ModuleMap, load_sidecars  # noqa: E402
from resources import (  # noqa: E402
    FRAMAC_KERNEL_RESERVE_MB,
    WP_MEMLIMIT_MB,
    Budget,
    job_budget,
    wp_parallelism,
)
from run_eacsl_fuzz import FUZZ_MIN_MEMORY_MB  # noqa: E402

SOURCE_EXTS = {".c", ".h", ".acsl", ".i"}
ACSL_CHECK_EXTS = {".c", ".h"}
BUILD_FILES = {"compile_commands.json", "Makefile", "GNUmakefile", "CMakeLists.txt"}
_WORK_PREFIX_RE = re.compile(
    r"^(?:/framac-run/)?(?:workspace/(?:work|baseline)/|agents/[A-Za-z0-9_-]+/scratch/(?:work|base)/|/target/)"
)


class StaleBaselineError(RuntimeError):
    """The target changed after the overlay baseline was captured."""


def _journal_path(run_dir: Path) -> Path:
    return run_dir / "state" / "merge-journal.json"


def _write_merge_journal(run_dir: Path, owner: str, backups: dict[str, bytes]) -> None:
    atomic_write_json(
        _journal_path(run_dir),
        {
            "owner": owner,
            "created_at": utc_now(),
            "files": {rel: base64.b64encode(raw).decode("ascii") for rel, raw in sorted(backups.items())},
        },
    )


def _clear_merge_journal(run_dir: Path) -> None:
    try:
        _journal_path(run_dir).unlink()
    except FileNotFoundError:
        pass


def recover_merge_journal(run_dir: Path, overlay_dir: Path | None = None) -> dict | None:
    """
    Restore workspace/work/ files that a killed merge left spliced but unverified. Call it
    while holding the `merge` lock: a journal present then can only belong to a dead merge.
    """
    run_dir = Path(run_dir).resolve()
    path = _journal_path(run_dir)
    if not path.is_file():
        return None
    data = load_json_strict(path)
    shared_work = (overlay_dir or (run_dir / "workspace")).resolve() / "work"
    restored: list[str] = []
    for rel_str, encoded in (data.get("files") or {}).items():
        if not is_safe_relative_path(rel_str):
            continue
        (shared_work / rel_str).write_bytes(base64.b64decode(encoded))
        restored.append(rel_str)
    _clear_merge_journal(run_dir)
    return {"recovered_from": data.get("owner"), "restored_files": restored}


def _parent_wp_report_rel(agent_id: str, function: str) -> str:
    return f"agents/{agent_id}/scratch/parent_wp/{function}.json"


def _function_files(run_dir: Path, function: str) -> set[str]:
    """Distinct source files that define a function of this name (static functions can collide)."""
    units = load_json_optional(run_dir / "coverage-ledger.json", [])
    return {_normalize_work_relpath(u.get("file") or "") for u in units if u.get("function") == function}


_REPORT_FILE_PREFIX_RE = re.compile(
    r"^(?:.*/)?(?:workspace/(?:work|baseline)/|agents/[A-Za-z0-9_-]+/scratch/(?:work|base)/)"
)
_WP_SLUG_LIMIT = 40


def wp_work_slug(c_file: str) -> str:
    """
    Directory stem of a file in `workspace/reports/wp/work/`: its normalised path in `[a-z0-9_]`. A path
    whose slug exceeds the limit keeps a prefix and a hash of the whole path, so two long paths never share a stem.
    """
    norm = _normalize_work_relpath(c_file or "")
    slug = re.sub(r"[^a-z0-9_]+", "_", norm.lower()).strip("_") or "task"
    if len(slug) <= _WP_SLUG_LIMIT:
        return slug
    digest = hashlib.sha1(norm.encode("utf-8")).hexdigest()[:8]
    return f"{slug[: _WP_SLUG_LIMIT - 9].rstrip('_')}_{digest}"


def baseline_wp_report_rel(c_file: str, function: str) -> str:
    """
    Where the Phase-3 baseline writes the WP report of one function of one file, relative to the overlay:
    keyed by file and function, one level below `reports/wp/` so `reports/wp/*.json` globs never see it.
    """
    return f"reports/wp/work/{wp_work_slug(c_file)}_{function}.json"


def wp_report_is_for(report: Any, c_file: str | None, function: str | None) -> bool:
    """
    Whether a WP report describes `function` of `c_file`. A report that names no function or no file is
    not contradicted; one that names another function or another file is not this function's.
    """
    if not isinstance(report, dict):
        return False
    if function and report.get("function") not in (None, function):
        return False
    rep_file = str(report.get("file") or "")
    if not c_file or not rep_file:
        return True
    want = _normalize_work_relpath(c_file)
    got = _REPORT_FILE_PREFIX_RE.sub("", rep_file.replace("\\", "/"))
    got = _normalize_work_relpath(got)
    if got == want:
        return True
    absolute = got.startswith("/") or bool(re.match(r"^[A-Za-z]:/", got))
    return absolute and got.endswith("/" + want)


def load_function_wp_report(overlay: Path, c_file: str | None, function: str) -> dict:
    """
    The latest WP report of `function` in `c_file`: the canonical `reports/wp/<function>.json` when it is this
    file's (a merge refreshes it), else the baseline's report of this file. {} when neither exists.
    """
    candidates = [overlay / "reports" / "wp" / f"{function}.json"]
    if c_file:
        candidates.append(overlay / baseline_wp_report_rel(c_file, function))
    for path in candidates:
        data = load_json_optional(path, {})
        if data and wp_report_is_for(data, c_file, function):
            return data
    return {}


PROVER_WALL_BUDGET_CEILING_S: dict[str, int] = {
    "quick": 600,
    "standard": 2400,
    "deep": 3600,
}
_BUDGET_SCALE_GOAL_THRESHOLD = 40
_BUDGET_SCALE_VC_THRESHOLD = 80
_BUDGET_SCALE_EVA_THRESHOLD = 25
_BUDGET_SCALE_LOC_THRESHOLD = 150
_BUDGET_SCALE_LOOP_THRESHOLD = 3


def _safe_nonneg_int(value: Any) -> int:
    if isinstance(value, bool) or value is None:
        return 0
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _wp_report_size_signals(report: dict) -> tuple[int, int]:
    """Return `(total_goals, vc_total)` from a WP report, including partial_verdicts of a killed run."""
    if not isinstance(report, dict) or not report:
        return 0, 0
    total_goals = _safe_nonneg_int(report.get("total_goals"))
    vc_stats = report.get("wp_vc_stats")
    vc_total = _safe_nonneg_int(vc_stats.get("total")) if isinstance(vc_stats, dict) else 0
    partial = report.get("partial_verdicts")
    if isinstance(partial, dict):
        vc_total = max(vc_total, _safe_nonneg_int(partial.get("scheduled_vcs")))
        vc_total = max(vc_total, _safe_nonneg_int(partial.get("completed_vcs")))
    return total_goals, vc_total


def _latest_earlier_agent_wp_report(run_dir: Path, agent_id: str, function: str, c_file: str | None) -> dict:
    """
    Most recent earlier agent's WP report for `(function, c_file)` that carries goal or VC counts
    (including `partial_verdicts` from a killed WP call). Used only for budget sizing when no
    canonical/baseline report exists yet.
    """
    agents = run_dir / "agents"
    if not function or not agents.is_dir():
        return {}
    best: tuple[float, str, dict] | None = None
    for agent in sorted(agents.iterdir()):
        if agent.name == agent_id or not agent.is_dir():
            continue
        scratch = agent / "scratch"
        budget = load_json_optional(scratch / prover_candidates.BUDGET_FILE, None)
        if not isinstance(budget, dict) or budget.get("function") != function:
            continue
        if c_file and _normalize_work_relpath(str(budget.get("file") or "")) != c_file:
            continue
        for candidate in (scratch / f"wp_{function}.json", scratch / "wp" / f"wp_{function}.json"):
            if not candidate.is_file():
                continue
            data = load_json_optional(candidate, {})
            if not isinstance(data, dict) or not data or not wp_report_is_for(data, c_file, function):
                continue
            goals, vcs = _wp_report_size_signals(data)
            if goals == 0 and vcs == 0:
                continue
            try:
                mtime = candidate.stat().st_mtime
            except OSError:
                mtime = 0.0
            key = (mtime, agent.name)
            if best is None or key > (best[0], best[1]):
                best = (mtime, agent.name, data)
    return best[2] if best is not None else {}


def scale_prover_wall_budget_s(
    base_s: int,
    *,
    profile: str,
    total_goals: int = 0,
    vc_total: int = 0,
    eva_unknowns: int = 0,
    loop_count: int = 0,
    loc: int = 0,
) -> tuple[int, str | None]:
    """
    Scale a prover's wall-clock budget for large functions using already-computed size signals.

    Small and medium functions keep `base_s` unchanged and return `(base_s, None)`.
    When WP counts are present (`total_goals > 0` or `vc_total > 0`), scale from goal and VC counts;
    otherwise fall back to Eva unknown obligations, function LOC, and loop count. Always bounded
    between `base_s` and the profile ceiling (`quick: 600`, `standard: 2400`, `deep: 3600`).
    """
    base = max(1, int(base_s))
    norm_profile = str(profile or "standard").strip().lower()
    ceiling = max(base, PROVER_WALL_BUDGET_CEILING_S.get(norm_profile, PROVER_WALL_BUDGET_CEILING_S["standard"]))

    goals = _safe_nonneg_int(total_goals)
    vcs = _safe_nonneg_int(vc_total)
    unknowns = _safe_nonneg_int(eva_unknowns)
    loops = _safe_nonneg_int(loop_count)
    lines = _safe_nonneg_int(loc)

    has_wp = goals > 0 or vcs > 0
    bump = 0
    parts: list[str] = []

    if has_wp:
        if goals > _BUDGET_SCALE_GOAL_THRESHOLD or vcs > _BUDGET_SCALE_VC_THRESHOLD:
            goal_bump = max(0, goals - _BUDGET_SCALE_GOAL_THRESHOLD) * 10
            vc_bump = max(0, vcs - _BUDGET_SCALE_VC_THRESHOLD) * 5
            bump = max(goal_bump, vc_bump)
            if goals > 0:
                parts.append(f"{goals} WP goals")
            if vcs > 0:
                parts.append(f"{vcs} VCs")
    else:
        eva_bump = max(0, unknowns - _BUDGET_SCALE_EVA_THRESHOLD) * 15
        loc_bump = max(0, lines - _BUDGET_SCALE_LOC_THRESHOLD) * 3
        loop_bump = max(0, loops - (_BUDGET_SCALE_LOOP_THRESHOLD - 1)) * 120
        bump = eva_bump + loc_bump + loop_bump
        if eva_bump > 0:
            parts.append(f"{unknowns} Eva unknowns")
        if loc_bump > 0:
            parts.append(f"{lines} LOC")
        if loop_bump > 0:
            parts.append(f"{loops} loops")

    if bump <= 0:
        return base, None

    scaled = min(ceiling, base + bump)
    if scaled <= base:
        return base, None

    detail = ", ".join(parts)
    if base + bump > ceiling:
        reason = f"scaled from {base}s to {scaled}s cap for large function ({detail})"
    else:
        reason = f"scaled from {base}s for large function ({detail})"
    return scaled, reason


class OverlayMergeError(RuntimeError):
    """An agent scratch overlay failed scope, ACSL-only, or parent re-verification checks."""


def should_copy(path: Path, rel_parts: tuple) -> bool:
    if any(p.startswith(".framac") or p == ".git" or p == "node_modules" for p in rel_parts):
        return False
    if path.suffix.lower() in SOURCE_EXTS:
        return True
    if path.name in BUILD_FILES:
        return True
    return False


def _rewrite_compile_commands(cc_path: Path, old_dir: Path, new_dir: Path) -> None:
    if not cc_path.exists():
        return
    try:
        entries = json.loads(cc_path.read_text(encoding="utf-8"))
        old_str = str(old_dir).replace("\\", "/")
        new_str = str(new_dir).replace("\\", "/")
        for entry in entries:
            if isinstance(entry, dict):
                for key in ("directory", "file", "command"):
                    if key in entry and isinstance(entry[key], str):
                        entry[key] = entry[key].replace(old_str, new_str)
        cc_path.write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")
    except (OSError, json.JSONDecodeError):
        pass


def init_overlay(target_dir: Path, overlay_dir: Path, force: bool = False) -> dict:
    target_dir = target_dir.resolve()
    overlay_dir = overlay_dir.resolve()

    if overlay_dir.exists() and force:
        shutil.rmtree(overlay_dir)

    baseline_dir = overlay_dir / "baseline"
    work_dir = overlay_dir / "work"
    contracts_dir = overlay_dir / "contracts"
    harnesses_dir = overlay_dir / "harnesses"
    reports_dir = overlay_dir / "reports"

    to_copy: list[tuple[Path, Path]] = []
    stale: list[str] = []
    skipped_output: list[str] = []
    for root, dirs, files in os.walk(target_dir):
        rel_root = Path(root).relative_to(target_dir)
        dirs[:] = [d for d in dirs if not d.startswith(".framac") and d not in {".git", "__pycache__", "build_framac"}]
        # Run results kept inside the target are not source: copying them would hand their
        # annotated headers and harnesses to this run.
        skipped_output += [(rel_root / d).as_posix() for d in dirs if is_pipeline_output_dir(Path(root) / d)]
        dirs[:] = [d for d in dirs if not is_pipeline_output_dir(Path(root) / d)]
        for fname in files:
            src_file = Path(root) / fname
            rel_path = rel_root / fname
            if should_copy(src_file, rel_path.parts):
                to_copy.append((src_file, rel_path))
                base_file = baseline_dir / rel_path
                if base_file.exists() and base_file.read_bytes() != src_file.read_bytes():
                    stale.append(str(rel_path).replace("\\", "/"))
    if stale:
        raise StaleBaselineError(
            f"{len(stale)} target file(s) changed since this overlay was initialized "
            f"(e.g. {', '.join(stale[:5])}). Start a new run directory instead of resuming."
        )

    for d in (baseline_dir, work_dir, contracts_dir, harnesses_dir, reports_dir):
        d.mkdir(parents=True, exist_ok=True)

    copied_files: list[str] = []
    for src_file, rel_path in to_copy:
        for dest_base in (baseline_dir, work_dir):
            dest_file = dest_base / rel_path
            dest_file.parent.mkdir(parents=True, exist_ok=True)
            if not dest_file.exists():
                shutil.copy2(src_file, dest_file)
        copied_files.append(str(rel_path).replace("\\", "/"))

    _rewrite_compile_commands(work_dir / "compile_commands.json", target_dir, work_dir)

    # A Windows checkout (core.autocrlf=true) has CRLF scripts the build container cannot run: said
    # here, before the build capture or the test command fails on them with a bare `not found`.
    crlf = line_endings.scan_crlf_scripts(target_dir)
    crlf_warning = line_endings.overlay_warning(crlf)
    meta = {
        "target_dir": str(target_dir),
        "overlay_dir": str(overlay_dir),
        "work_dir": str(work_dir),
        "baseline_dir": str(baseline_dir),
        "copied_count": len(copied_files),
        "skipped_pipeline_output": sorted(skipped_output),
        "crlf_scripts": line_endings.summary(crlf),
        "warnings": [crlf_warning] if crlf_warning else [],
    }
    (overlay_dir / "overlay_meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    # A capture that already ran (a resumed or re-initialized overlay): the C sources its build generated
    # (nginx's objs/ngx_modules.c) are in the snapshot, not in the target. Installed into baseline/ and
    # work/ like the target's own files; the capture installs them itself when it runs after init.
    generated = target_env.install_generated_sources(overlay_dir)
    if any(generated.values()):
        meta = load_json_optional(overlay_dir / "overlay_meta.json", meta)
    return meta


def _copy_tree(src: Path, dest: Path) -> None:
    """
    Copy a directory tree to a new `dest`: `cp -a --reflink=auto` on POSIX (copy-on-write
    clones where the filesystem supports them, a plain copy elsewhere), else shutil.copytree.
    Always independent copies, never symlinks or hardlinks.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "posix" and shutil.which("cp"):
        try:
            proc = subprocess.run(
                ["cp", "-a", "--reflink=auto", str(src), str(dest)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            if proc.returncode == 0 and dest.is_dir():
                return
        except OSError:
            pass
        if dest.exists():
            shutil.rmtree(dest)  # a partial copy (e.g. a cp without --reflink)
    shutil.copytree(src, dest)


def init_agent_overlay(run_dir: Path, agent_id: str, overlay_dir: Path | None = None) -> dict:
    """Create an isolated per-agent scratch copy of workspace/work/ under agents/<agent-id>/scratch/."""
    if not is_safe_agent_id(agent_id):
        raise ArtifactError(f"invalid canonical agent_id: {agent_id!r}")
    run_dir = run_dir.resolve()
    overlay = (overlay_dir or (run_dir / "workspace")).resolve()
    shared_work = overlay / "work"
    if not shared_work.is_dir():
        raise ArtifactError(f"shared work directory does not exist: {shared_work}")

    agent_root = run_dir / "agents" / agent_id
    scratch_work = agent_root / "scratch" / "work"
    scratch_base = agent_root / "scratch" / "base"
    artifacts_dir = agent_root / "artifacts"

    for dest in (scratch_work, scratch_base):
        if dest.exists():
            shutil.rmtree(dest)
        _copy_tree(shared_work, dest)
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    _rewrite_compile_commands(scratch_work / "compile_commands.json", shared_work, scratch_work)

    return {
        "agent_id": agent_id,
        "scratch_work": str(scratch_work.relative_to(run_dir)).replace("\\", "/"),
        "scratch_base": str(scratch_base.relative_to(run_dir)).replace("\\", "/"),
        "artifacts_dir": str(artifacts_dir.relative_to(run_dir)).replace("\\", "/"),
    }


def _resolve_baseline_and_work(overlay_dir: Path, work_dir: Path | None = None) -> tuple[Path, Path]:
    """
    Resolve `(baseline_dir, target_work)` for both `workspace/` (`baseline/` + `work/`)
    and agent scratch directories (`agents/<id>/scratch` with `base/` + `work/`).
    """
    overlay_dir = overlay_dir.resolve()
    baseline_dir = overlay_dir / "baseline"
    if not baseline_dir.is_dir() and (overlay_dir / "base").is_dir() and (overlay_dir / "work").is_dir():
        baseline_dir = overlay_dir / "base"
    if work_dir is not None:
        resolved_work = work_dir.resolve()
        if (resolved_work / "base").is_dir() and (resolved_work / "work").is_dir():
            if not baseline_dir.is_dir():
                baseline_dir = resolved_work / "base"
            resolved_work = resolved_work / "work"
        elif (resolved_work / "baseline").is_dir() and (resolved_work / "work").is_dir():
            baseline_dir = resolved_work / "baseline"
            resolved_work = resolved_work / "work"
        elif resolved_work.name == "work" and (resolved_work.parent / "base").is_dir() and not baseline_dir.is_dir():
            baseline_dir = resolved_work.parent / "base"
        target_work = resolved_work
    else:
        target_work = (overlay_dir / "work").resolve()
    return baseline_dir, target_work


def map_work_to_baseline_line(
    file_rel: str,
    line: int,
    run_dir: Path | None = None,
    overlay_dir: Path | None = None,
) -> tuple[int, int]:
    """
    Map a line number in `workspace/work/<file_rel>` (or `workspace/baseline/<file_rel>`) to
    `(canonical_baseline_line, current_work_line)` by aligning C tokens between baseline and work.
    If `line` already matches a statement in `baseline` that shifted to a later line in `work`,
    returns `(line, shifted_work_line)`; if `line` matches the shifted statement in `work`,
    returns `(canonical_baseline_line, line)`.
    """
    if line <= 0:
        return (line, line)
    root = (run_dir or Path.cwd()).resolve()
    ov = (overlay_dir or (root / "workspace")).resolve()
    norm_rel = _normalize_work_relpath(file_rel)
    base_file = ov / "baseline" / norm_rel
    if not base_file.is_file():
        base_file = ov / "base" / norm_rel
    work_file = ov / "work" / norm_rel
    if not base_file.is_file() or not work_file.is_file():
        return (line, line)
    try:
        base_text = base_file.read_text(encoding="utf-8", errors="replace")
        work_text = work_file.read_text(encoding="utf-8", errors="replace")
        if base_text == work_text:
            return (line, line)
        from acsl_ast import tokenize_c_acsl

        base_c = [
            t
            for t in tokenize_c_acsl(base_text, path=norm_rel)
            if t.kind not in ("whitespace", "acsl_block", "acsl_line")
        ]
        work_c = [
            t
            for t in tokenize_c_acsl(work_text, path=norm_rel)
            if t.kind not in ("whitespace", "acsl_block", "acsl_line")
        ]
        if len(base_c) != len(work_c) or not base_c:
            return (line, line)
        w2b: dict[int, int] = {}
        b2w: dict[int, int] = {}
        for bt, wt in zip(base_c, work_c, strict=True):
            w2b.setdefault(wt.line, bt.line)
            b2w.setdefault(bt.line, wt.line)
        if line in w2b and w2b[line] != line:
            return (w2b[line], line)
        if line in b2w and b2w[line] != line:
            return (line, b2w[line])
        if line in w2b:
            b_line = w2b[line]
            return (b_line, b2w.get(b_line, line))
    except Exception:
        return (line, line)
    return (line, line)


def check_acsl_only(
    overlay_dir: Path,
    work_dir: Path | None = None,
    files: list[str] | None = None,
) -> dict:
    """Verify that work_dir (default: overlay_dir/work) differs from overlay_dir/baseline only in ACSL comments."""
    baseline_dir, target_work = _resolve_baseline_and_work(overlay_dir, work_dir)

    errors: list[str] = []
    checked = 0

    if files:
        rel_list = [f.replace("\\", "/") for f in files]
    else:
        rel_set = set()
        for base in (baseline_dir, target_work):
            if base.is_dir():
                for root, _, fnames in os.walk(base):
                    for fname in fnames:
                        p = Path(root) / fname
                        if p.suffix.lower() in ACSL_CHECK_EXTS:
                            rel_set.add(p.relative_to(base).as_posix())
        rel_list = sorted(rel_set)

    for rel_str in rel_list:
        if not is_safe_relative_path(rel_str):
            errors.append(f"{rel_str}: unsafe relative path")
            continue
        base_file = baseline_dir / rel_str
        work_file = target_work / rel_str
        if not base_file.is_file() and work_file.is_file():
            errors.append(
                f"{rel_str}: new source file created outside baseline "
                f"(compared work_dir={target_work.as_posix()} against baseline_dir={baseline_dir.as_posix()})"
            )
            continue
        if base_file.is_file() and not work_file.is_file():
            errors.append(
                f"{rel_str}: baseline source file deleted "
                f"(compared work_dir={target_work.as_posix()} against baseline_dir={baseline_dir.as_posix()})"
            )
            continue
        if not base_file.is_file():
            continue
        base_text = base_file.read_text(encoding="utf-8", errors="replace")
        work_text = work_file.read_text(encoding="utf-8", errors="replace")
        checked += 1
        if base_text != work_text:
            errors.extend(verify_acsl_only(base_text, work_text, path=rel_str))

    return {
        "ok": len(errors) == 0,
        "checked_files": checked,
        "baseline_dir": baseline_dir.as_posix(),
        "work_dir": target_work.as_posix(),
        "errors": errors,
    }


def _collect_changed_files(base_dir: Path, work_dir: Path) -> list[str]:
    changed: list[str] = []
    seen = set()
    for root_dir in (base_dir, work_dir):
        for root, _, files in os.walk(root_dir):
            for fname in files:
                p = Path(root) / fname
                if p.suffix.lower() not in SOURCE_EXTS:
                    continue
                rel = p.relative_to(root_dir).as_posix()
                if rel in seen:
                    continue
                seen.add(rel)
                bf = base_dir / rel
                wf = work_dir / rel
                if not bf.is_file() or not wf.is_file() or bf.read_bytes() != wf.read_bytes():
                    changed.append(rel)
    return sorted(changed)


def _normalize_work_relpath(raw_path: str) -> str:
    norm = (raw_path or "").replace("\\", "/").strip()
    norm = _WORK_PREFIX_RE.sub("", norm)
    while norm.startswith("./"):
        norm = norm[2:]
    return norm


def _include_dirs_in_order(cppflags: str, run_dir: Path, work_dir: Path) -> list[str]:
    """Tree-relative include directories of `cppflags` in the order `#include "x.h"` searches them."""
    try:
        words = shlex.split(cppflags or "")
    except ValueError:
        words = (cppflags or "").split()
    by_option: dict[str, list[str]] = {o: [] for o in ("-iquote", "-I", "-isystem", "-idirafter")}
    i = 0
    while i < len(words):
        option = next((o for o in sorted(by_option, key=len, reverse=True) if words[i].startswith(o)), None)
        if option is None:
            i += 1
            continue
        path = words[i][len(option) :]
        if not path and i + 1 < len(words):
            i += 1
            path = words[i]
        i += 1
        rel = source_tree_relpath(f"{path.rstrip('/')}/_", run_dir, work_dir) if path else None
        if rel is not None:
            by_option[option].append(rel[:-1].strip("/"))
    return [d for option in by_option for d in by_option[option]]


def _resolve_include_header(run_dir: Path, work_dir: Path, header: str | None, cppflags: str) -> str | None:
    """
    The tree-relative file a harness sidecar's `header` names. The sidecar records the name the
    harness includes (`qcbor.h`), which is a tree path only when the module's flags put the tree root
    on the include path; otherwise search the include directories as the preprocessor would. A name
    that matches nothing is returned unchanged.
    """
    if not header:
        return header
    norm = _normalize_work_relpath(header)
    if "/" in norm and (work_dir / norm).is_file():
        return norm
    for d in _include_dirs_in_order(cppflags, run_dir, work_dir):
        cand = f"{d}/{norm}" if d else norm
        if (work_dir / cand).is_file():
            return posixpath.normpath(cand)
    if (work_dir / norm).is_file():
        return norm
    tails = [p.relative_to(work_dir).as_posix() for p in work_dir.rglob(Path(norm).name) if p.is_file()]
    tails = [t for t in tails if t == norm or t.endswith("/" + norm)]
    return tails[0] if len(tails) == 1 else norm


def header_function_names(text: str, path: str = "<input>") -> list[str]:
    """
    The functions a header declares (prototypes and `static inline` definitions): the ones whose contracts a
    header architect may write. Its guardrails check these (`--functions` in its brief, `--reach-functions`
    in the parent's re-check), so a failure in other code of the module is never its `code_fault`.
    An architect adds no declaration, so the work tree's header gives the same set as its patched one.
    An unreadable header gives [] (the guardrail then checks the whole module, as before).
    """
    try:
        names = {s.function for s in locate_all_prototype_spans(text, path=path)}
        names |= set(locate_all_definition_spans(text, path=path))
    except (AcslError, ValueError):
        return []
    return sorted(n for n in names if n)


def _header_functions_of(
    run_dir: Path, overlay: Path, module: str | None, header: str | None, cppflags: str
) -> list[str]:
    """header_function_names of `header` (as named by a brief or a merge entry) in the shared work tree."""
    if not header:
        return []
    rel = _resolve_include_header(
        run_dir, overlay / "work", _normalize_work_relpath(header), _module_header_flags(overlay, module, cppflags)
    )
    if not rel:
        return []
    try:
        text = (overlay / "work" / rel).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return header_function_names(text, rel)


def _declares_function(text: str, function: str) -> bool:
    """Whether comment-stripped header `text` has a prototype (not a definition) of `function`."""
    text = re.sub(r"/\*.*?\*/|//[^\n]*", " ", text, flags=re.S)
    for m in re.finditer(rf"\b{re.escape(function)}\s*\(", text):
        depth = 1
        j = m.end()
        while j < len(text) and depth:
            depth += {"(": 1, ")": -1}.get(text[j], 0)
            j += 1
        tail = re.match(r"[^;{}]*?([;{])", text[j:], flags=re.S)
        if depth == 0 and tail and tail.group(1) == ";":
            return True
    return False


def _prover_header(
    run_dir: Path, work_dir: Path, c_file: str | None, function: str | None, header: str | None, cppflags: str
) -> str | None:
    """
    The header a prover may edit for `function`: the one that declares its prototype. The sidecar's
    header is the one the harness includes, often an umbrella that only includes the real one
    (`qcbor.h` for `inc/qcbor/qcbor_main_decode.h`), so when the resolved header does not hold the
    declaration look at the C file's sibling header, then at the one header in the tree that does.
    """
    resolved = _resolve_include_header(run_dir, work_dir, header, cppflags)
    if not function:
        return resolved

    def declares(rel: str | None) -> bool:
        path = work_dir / rel if rel else None
        if path is None or not path.is_file():
            return False
        try:
            return _declares_function(path.read_text(encoding="utf-8", errors="replace"), function)
        except OSError:
            return False

    if declares(resolved):
        return resolved
    sibling = Path(c_file).with_suffix(".h").as_posix() if c_file else None
    if declares(sibling):
        return sibling
    holders = [
        rel for rel in (p.relative_to(work_dir).as_posix() for p in sorted(work_dir.rglob("*.h"))) if declares(rel)
    ]
    return holders[0] if len(holders) == 1 else resolved


# ------------------------------------------- link units and harness sub-modules (step I5b)
#
# A ledger unit's `module` is a DAG module, which is a link unit (`libqcbor_a`; there is no DAG without
# the Phase 0 model) whose harnesses may be sub-modules (`harness_qcbor_main_decode.json`, sidecar
# `unit`). Whatever needs a sidecar, a harness, a corpus or a per-harness report "for a unit" resolves
# it here: the unit's own harness when it has one, else its sub-modules (flags and sources: their
# union). Under a DAG without link units (an old run directory, a test fixture) the DAG modules are the
# harness modules and every helper is the identity.

_MODULE_MAP_CACHE: dict[tuple, ModuleMap] = {}
# Flags whose argument is the next word: kept together when flag strings are merged.
_FLAGS_WITH_ARG = frozenset(
    {"-include", "-imacros", "-isystem", "-iquote", "-idirafter", "-I", "-D", "-U", "-L", "-l", "-x", "-Xlinker"}
)


def _stamp(path: Path) -> tuple[int, int] | None:
    try:
        st = path.stat()
    except OSError:
        return None
    return st.st_mtime_ns, st.st_size


def module_map_for(overlay: Path) -> ModuleMap:
    """The ModuleMap of a workspace overlay (`reports/callgraph_dag.json`, `harnesses/`), reused while unchanged."""
    overlay = Path(overlay)
    dag_path = overlay / "reports" / "callgraph_dag.json"
    hdir = overlay / "harnesses"
    sidecar_stamps = tuple((p.name, _stamp(p)) for p in sorted(hdir.glob("harness_*.json"))) if hdir.is_dir() else ()
    key = (str(overlay.resolve()), _stamp(dag_path), sidecar_stamps)
    mm = _MODULE_MAP_CACHE.get(key)
    if mm is None:
        try:
            dag = load_json_optional(dag_path, {})
        except ArtifactError:
            dag = {}
        mm = ModuleMap(dag if isinstance(dag, dict) else {}, load_sidecars(hdir))
        _MODULE_MAP_CACHE.clear()
        _MODULE_MAP_CACHE[key] = mm
    return mm


def harness_modules_of(mm: ModuleMap, module: str | None) -> list[str]:
    """
    The harness modules (sidecars) standing for `module`: for a DAG module, every harness of its unit
    (its own included); for a harness module, itself. Empty when nothing has a sidecar.
    """
    if not module:
        return []
    if module in mm.modules:
        subs = mm.submodules(module)
        if subs:
            return subs
    return [module] if module in mm.sidecars else []


def scope_keys(mm: ModuleMap, module: str) -> set[tuple[str, str]] | None:
    """
    (file, function) of what a sub-module harness answers for (ModuleMap.scope_functions); None
    when the harness answers for its whole unit: a unit's own harness, any harness without link
    units, or a sub-module whose scope comes out empty.
    """
    if not mm.is_submodule(module):
        return None
    out: set[tuple[str, str]] = set()
    for key in mm.scope_functions(module):
        rec = mm.functions.get(key) or {}
        out.add((normalize_file(str(rec.get("file") or "")), str(rec.get("name") or key)))
    return out or None


def dag_function_record(dag_fns: dict, function: str | None, c_file: str | None = None) -> dict:
    """
    The DAG record of `function` (defined in `c_file` when given). The DAG keys a function by its
    plain name, or by `file#name` when the name collides; `function` may also be that key. Without
    `c_file`, a colliding name resolves only when one record has it. {} when nothing matches.
    """
    if not function or not isinstance(dag_fns, dict):
        return {}
    want = _normalize_work_relpath(c_file) if c_file else None

    def file_ok(rec: dict) -> bool:
        return not want or not rec.get("file") or _normalize_work_relpath(str(rec["file"])) == want

    direct = dag_fns.get(function)
    if isinstance(direct, dict) and file_ok(direct):
        return direct
    name = function.rpartition("#")[2] if "#" in function else function
    matches = [
        rec
        for key, rec in dag_fns.items()
        if isinstance(rec, dict) and str(rec.get("name") or str(key).rpartition("#")[2]) == name and file_ok(rec)
    ]
    if want:
        matches = [rec for rec in matches if rec.get("file")] or matches
    return matches[0] if len(matches) == 1 else {}


def harness_module_for_function(
    mm: ModuleMap, module: str | None, file: str | None = None, function: str | None = None
) -> str | None:
    """
    The harness module to build, replay or read per-harness reports of on behalf of `module` (a
    ledger unit's module): `module` itself when it is a harness module or has its own harness, else
    the sub-module whose scope holds `file#function`, else the unit's first sub-module.
    """
    if not module or module not in mm.modules or module in mm.sidecars:
        return module
    subs = mm.submodules(module)
    if not subs:
        return module
    if file and function:
        key = (normalize_file(file), function)
        for sub in subs:
            scope = scope_keys(mm, sub)
            if scope and key in scope:
                return sub
    return mm.harness_module_for(module) or module


def merge_flags(values: list[str | None]) -> str:
    """Every distinct flag (with its argument) of several flag strings, first-seen order."""
    present = [v for v in values if v]
    if len(set(present)) <= 1:
        return present[0] if present else ""
    groups: list[tuple[str, ...]] = []
    for value in present:
        try:
            words = shlex.split(value)
        except ValueError:
            words = value.split()
        i = 0
        while i < len(words):
            group = (words[i], words[i + 1]) if words[i] in _FLAGS_WITH_ARG and i + 1 < len(words) else (words[i],)
            i += len(group)
            if group not in groups:
                groups.append(group)
    return " ".join(shlex.quote(w) for g in groups for w in g)


def merged_sidecar(mm: ModuleMap, module: str | None) -> dict:
    """
    The sidecar standing for `module`: its own; for a unit with several harnesses, their union
    (`sources`, `headers`, `cppflags`, `ldflags`; the first `header`), naming them in
    `harness_modules`. Per-harness fields (entry function, repair counts) are not merged: use
    `harness_modules_of` for those.
    """
    mods = harness_modules_of(mm, module)
    metas = [mm.sidecars[m] for m in mods if isinstance(mm.sidecars.get(m), dict)]
    if len(metas) <= 1:
        return dict(metas[0]) if metas else {}
    sources: list[str] = []
    headers: list[str] = []
    for meta in metas:
        sources += [s for s in meta.get("sources") or [] if isinstance(s, str) and s not in sources]
        headers += [h for h in meta.get("headers") or [] if isinstance(h, str) and h not in headers]
    merged: dict[str, Any] = {
        "module": module,
        "harness_modules": mods,
        "sources": sources,
        "cppflags": merge_flags([m.get("cppflags") for m in metas]),
        "ldflags": merge_flags([m.get("ldflags") for m in metas]),
    }
    header = next((m["header"] for m in metas if m.get("header")), None)
    if header:
        merged["header"] = header
    if headers:
        merged["headers"] = headers
    return merged


def module_param(modules_params: dict, mm: ModuleMap, module: str | None, key: str) -> list | None:
    """
    A list parameter of `workspace/build/params.json` for `module`: its own entry, else the union over
    its unit's harness modules (None when no entry sets it).
    """
    if not module or not isinstance(modules_params, dict):
        return None
    own = (modules_params.get(module) or {}).get(key)
    if own is not None:
        return own
    out: list | None = None
    for sub in harness_modules_of(mm, module):
        vals = (modules_params.get(sub) or {}).get(key)
        if vals is not None:
            out = [*(out or []), *(v for v in vals if v not in (out or []))]
    return out


def _module_header_flags(overlay: Path, module: str | None, cppflags: str | None) -> str:
    """The flags a header name is resolved with: the caller's, then the module's own."""
    own = merged_sidecar(module_map_for(overlay), module).get("cppflags") if module else None
    return " ".join(f for f in (cppflags, own) if f)


def _resolve_overlay_source(run_dir: Path, work_dir: Path, src: str) -> str:
    """
    Resolve a `--sources` entry to a concrete file path:
    - Strips leading `workspace/work/` or `agents/<id>/scratch/work/` so paths never double.
    - Resolves `workspace/stubs/...` or run-relative external files against `run_dir` when
      they live outside `work_dir`.
    """
    norm = (src or "").replace("\\", "/").strip()
    stripped = _normalize_work_relpath(norm)
    in_work = work_dir / stripped
    if in_work.is_file():
        return str(in_work)
    run_rel = norm.removeprefix("/framac-run/")
    in_run = run_dir / run_rel
    if in_run.is_file():
        return str(in_run)
    direct = Path(src)
    if direct.is_file():
        return str(direct.resolve())
    return str(in_work)


_INCLUDE_RE = re.compile(r'^\s*#\s*include\s*["<]([^">]+)[">]', re.MULTILINE)


def resolve_acsl_vocabulary_path(work_dir: Path | None = None) -> Path | None:
    """Locate the canonical templates/acsl/acsl_vocabulary.h header."""
    if work_dir is not None:
        cand = work_dir / "templates" / "acsl" / "acsl_vocabulary.h"
        if cand.is_file():
            return cand
        cand = work_dir / "acsl_vocabulary.h"
        if cand.is_file():
            return cand
    container_path = Path("/opt/framac-pipeline/templates/acsl/acsl_vocabulary.h")
    if container_path.is_file():
        return container_path
    local_path = Path(__file__).resolve().parent.parent / "templates" / "acsl" / "acsl_vocabulary.h"
    if local_path.is_file():
        return local_path
    return None


def _find_transitive_includes(
    header_rel: str,
    work_dir: Path,
    header_text: str | None = None,
) -> set[str]:
    """
    Find all relative paths of headers in `work_dir` transitively included by `header_rel`.
    `header_text` can be provided if `header_rel` in memory differs from disk.
    """
    if not work_dir.is_dir():
        return set()

    all_headers: dict[str, list[Path]] = {}
    for root, _, files in os.walk(work_dir):
        for fname in files:
            p = Path(root) / fname
            if p.suffix.lower() in {".h", ".acsl"}:
                all_headers.setdefault(p.name, []).append(p)

    norm_root = _normalize_work_relpath(header_rel)
    visited: set[str] = set()
    queue: list[tuple[str, str | None]] = [(norm_root, header_text)]

    while queue:
        current_rel, curr_text = queue.pop(0)
        curr_path = work_dir / current_rel
        if curr_text is None:
            if not curr_path.is_file():
                continue
            try:
                curr_text = curr_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

        for m in _INCLUDE_RE.finditer(curr_text):
            target = m.group(1).replace("\\", "/").strip()
            cand = (curr_path.parent / target).resolve()
            if not cand.is_file():
                cand = (work_dir / target).resolve()
            if not cand.is_file():
                target_fname = Path(target).name
                candidates = all_headers.get(target_fname, [])
                if len(candidates) == 1:
                    cand = candidates[0].resolve()
                elif len(candidates) > 1:
                    for c in candidates:
                        if c.as_posix().endswith(target):
                            cand = c.resolve()
                            break

            if cand.is_file():
                try:
                    rel = cand.relative_to(work_dir.resolve()).as_posix()
                except ValueError:
                    continue
                if rel != norm_root and rel not in visited:
                    visited.add(rel)
                    queue.append((rel, None))

    return visited


def _collect_all_header_declarations_with_metadata(
    work_dir: Path,
    exclude_rels: set[str] | None = None,
) -> list[dict]:
    """Collect all top-level ACSL declarations across all headers in work_dir and acsl_vocabulary.h."""
    exclude = exclude_rels or set()
    decls: list[dict] = []

    vocab_p = resolve_acsl_vocabulary_path(work_dir)
    if vocab_p and vocab_p.is_file():
        try:
            vocab_text = vocab_p.read_text(encoding="utf-8", errors="replace")
            for d in extract_top_level_acsl_declarations(vocab_text, path=vocab_p.name):
                d_copy = dict(d)
                d_copy["path"] = vocab_p.name
                decls.append(d_copy)
        except Exception:
            pass

    if not work_dir.is_dir():
        return decls

    for root, _, files in os.walk(work_dir):
        for fname in sorted(files):
            p = Path(root) / fname
            if p.suffix.lower() not in {".h", ".acsl"}:
                continue
            rel = p.relative_to(work_dir).as_posix()
            if rel in exclude:
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
                for d in extract_top_level_acsl_declarations(text, path=rel):
                    d_copy = dict(d)
                    d_copy["path"] = rel
                    decls.append(d_copy)
            except Exception:
                continue

    return decls


def _collect_in_scope_header_declarations(
    work_dir: Path,
    header_rel: str,
    header_text: str | None = None,
) -> set[str]:
    """
    Collect top-level ACSL declaration identifiers and profile keys that are in scope
    for `header_rel`: ONLY declarations from `acsl_vocabulary.h` and transitively included
    headers in `work_dir`.
    """
    names: set[str] = set()

    # 1. Canonical acsl_vocabulary.h
    vocab_p = resolve_acsl_vocabulary_path(work_dir)
    if vocab_p and vocab_p.is_file():
        try:
            vocab_text = vocab_p.read_text(encoding="utf-8", errors="replace")
            for d in extract_top_level_acsl_declarations(vocab_text, path=vocab_p.name):
                names.add(d.get("profile_key") or d["name"])
                if d.get("full_profile"):
                    names.add(d["full_profile"])
        except Exception:
            pass

    # 2. Transitive includes of header_rel
    transitive_rels = _find_transitive_includes(header_rel, work_dir, header_text=header_text)
    for inc_rel in sorted(transitive_rels):
        p = work_dir / inc_rel
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
            for d in extract_top_level_acsl_declarations(text, path=inc_rel):
                names.add(d.get("profile_key") or d["name"])
                if d.get("full_profile"):
                    names.add(d["full_profile"])
        except Exception:
            continue

    return names


def assigns_verified_for_partial_merge(wp_report: dict | None) -> bool:
    """
    Return True when a WP report has 0 unproven step_a_assigns VCs.
    Tolerates legacy reports where Frama-C 33+ 'Partially proven' (Consolidation.Pending)
    assigns clauses were placed in step_a_assigns despite having 100% proven VCs.
    """
    if not isinstance(wp_report, dict):
        return False
    if wp_report.get("assigns_vcs_proven") is False:
        return False
    step_a = ((wp_report.get("unproven_by_bucket") or {}).get("step_a_assigns")) or []
    unproven = [
        g for g in step_a if not isinstance(g, dict) or str(g.get("status") or "").strip().lower() != "partially proven"
    ]
    return len(unproven) == 0


def infer_prover_wp_flags(
    run_dir: Path,
    overlay_dir: Path | None = None,
    agent_id: str | None = None,
    c_file: str | None = None,
    function: str | None = None,
) -> list[str]:
    """
    Infer the WP RTE check and memory-model CLI flags used by the prover for `function`
    so parent merge re-checks, contract re-checks, and final WP sweeps run with matching
    reduced-check assumptions (which `ledger.py` records explicitly on covered units) and
    WP model. Defaults to `['--no-warn-unsigned-downcast']`. A memory model that
    `framac_common.wp_model_problem` rejects (`cast`, `Hoare`, `Region`, `nat`, ...) is never
    replayed; `prover_wp_model_problem` refuses the merge of a prover that used one.
    """
    reduced, wp_model, _own, wrap_code_lines = _prover_wp_config(run_dir, overlay_dir, agent_id, c_file, function)
    flags: list[str] = []
    if any("-warn-unsigned-overflow / -warn-unsigned-downcast OFF" in r for r in reduced):
        flags.append("--no-warn-unsigned")
        if wrap_code_lines:
            flags.append(f"--wrap-code-lines={','.join(str(n) for n in wrap_code_lines)}")
            # The signed-downcast waiver on declared wrap lines (run_wp_function.py), valid only
            # together with --no-warn-unsigned and declared lines.
            if any("-warn-signed-downcast OFF" in r for r in reduced):
                flags.append("--waive-signed-downcast")
    else:
        flags.append("--no-warn-unsigned-downcast")
    if any("-warn-invalid-pointer OFF" in r for r in reduced):
        flags.append("--no-warn-invalid-pointer")
    # Replay only an accepted model; never the unsound `cast` option or a model that is not evidence.
    if (
        wp_model
        and wp_model != "Typed"
        and re.fullmatch(r"[A-Za-z0-9_+,-]+", wp_model)
        and wp_model_problem(wp_model) is None
    ):
        flags.extend(["--wp-model", wp_model])
    return flags


def prover_wp_model_problem(
    run_dir: Path,
    overlay_dir: Path | None = None,
    agent_id: str | None = None,
    c_file: str | None = None,
    function: str | None = None,
) -> str | None:
    """
    Why the memory model of the prover's own WP report (the one `infer_prover_wp_flags` replays,
    read from the agent's scratch, artifacts or result evidence) is not evidence, or None. The
    parent re-check cannot replay such a model, so the prover's proof is not the one re-checked.
    """
    _reduced, wp_model, own, _lines = _prover_wp_config(run_dir, overlay_dir, agent_id, c_file, function)
    return wp_model_problem(wp_model) if own and wp_model else None


def _prover_wp_config(
    run_dir: Path,
    overlay_dir: Path | None,
    agent_id: str | None,
    c_file: str | None,
    function: str | None,
) -> tuple[list[str], str | None, bool, list[int]]:
    """
    (reduced checks, WP model, whether the model comes from the prover's own report, declared
    wrap lines) of the report the prover's proof is replayed from.
    """
    overlay = (overlay_dir or (run_dir / "workspace")).resolve()
    norm_c = _normalize_work_relpath(c_file) if c_file else None
    cand_paths: list[tuple[Path, bool]] = []  # (report, the prover's own)
    if agent_id and function and is_safe_agent_id(agent_id):
        agent_dir = run_dir / "agents" / agent_id
        cand_paths.append((agent_dir / "scratch" / f"wp_{function}.json", True))
        cand_paths.append((agent_dir / "artifacts" / f"wp_{function}.json", True))
        res_file = agent_dir / "scratch" / "result.json"
        if res_file.is_file():
            res_data = load_json_optional(res_file, {}) or {}
            if isinstance(res_data, dict):
                for ev in res_data.get("evidence") or []:
                    tout = str((ev or {}).get("tool_output") or "").replace("\\", "/").strip()
                    if tout.startswith(f"agents/{agent_id}/") and tout.endswith(".json"):
                        cand_paths.append((run_dir / tout, True))
        cand_paths.append((agent_dir / "scratch" / "parent_wp" / f"{function}.json", False))
    if function:
        cand_paths.append((overlay / "reports" / "wp" / f"{function}.json", False))
        if norm_c:
            cand_paths.append((overlay / baseline_wp_report_rel(norm_c, function), False))

    reduced: list[str] = []
    wp_model: str | None = None
    model_own = False
    wrap_code_lines: list[int] = []

    def _note_wraps(report: dict) -> None:
        declared = (report.get("unsigned_wraps") or {}).get("declared_code_lines")
        if isinstance(declared, list) and not wrap_code_lines:
            wrap_code_lines.extend(n for n in declared if isinstance(n, int) and not isinstance(n, bool))

    for p, own in cand_paths:
        if not p.is_file() or p.is_symlink():
            continue
        rep = load_json_optional(p, {}) or {}
        if not isinstance(rep, dict) or rep.get("mode") == "guardrail":
            continue
        if function and rep.get("function") not in (None, function):
            continue
        if not own and not wp_report_is_for(rep, norm_c, function):
            continue  # another file's report of a same-named static function
        rc = (rep.get("soundness") or {}).get("reduced_checks")
        if isinstance(rc, list):
            for item in rc:
                if isinstance(item, str) and item not in reduced:
                    reduced.append(item)
        m = rep.get("wp_model") or (
            (rep.get("bitwise_retry") or {}).get("wp_model")
            if (rep.get("bitwise_retry") or {}).get("triggered")
            else None
        )
        if isinstance(m, str) and m.strip() and wp_model is None:
            wp_model = m.strip()
            model_own = own
        _note_wraps(rep)
        if reduced or wp_model:
            break

    if function and not reduced:
        ledger_units = load_json_optional(run_dir / "coverage-ledger.json", [])
        if isinstance(ledger_units, list):
            for u in ledger_units:
                if not isinstance(u, dict) or u.get("function") != function:
                    continue
                if norm_c and _normalize_work_relpath(str(u.get("file") or "")) != norm_c:
                    continue
                for a in u.get("assumptions") or []:
                    desc = str((a or {}).get("description") or "")
                    if "-warn-unsigned-overflow / -warn-unsigned-downcast OFF" in desc:
                        reduced.append("-warn-unsigned-overflow / -warn-unsigned-downcast OFF")
                    if "-warn-invalid-pointer OFF" in desc:
                        reduced.append("-warn-invalid-pointer OFF")
                    if "-warn-signed-downcast OFF" in desc:
                        reduced.append("-warn-signed-downcast OFF on declared wrap lines")
                for ev in u.get("evidence") or []:
                    if not isinstance(ev, dict) or ev.get("phase") != "wp":
                        continue
                    tout = str(ev.get("tool_output") or "").replace("\\", "/").strip()
                    if tout and tout.endswith(".json"):
                        ep = run_dir / tout
                        if ep.is_file() and not ep.is_symlink():
                            rep = load_json_optional(ep, {}) or {}
                            if isinstance(rep, dict):
                                _note_wraps(rep)
                                for item in ((rep.get("soundness") or {}).get("reduced_checks")) or []:
                                    if isinstance(item, str) and item not in reduced:
                                        reduced.append(item)
                                m = rep.get("wp_model") or (
                                    (rep.get("bitwise_retry") or {}).get("wp_model")
                                    if (rep.get("bitwise_retry") or {}).get("triggered")
                                    else None
                                )
                                if isinstance(m, str) and m.strip() and wp_model is None:
                                    wp_model = m.strip()
    return reduced, wp_model, model_own, wrap_code_lines


def _collect_existing_header_declarations(work_dir: Path, exclude_rels: set[str]) -> set[str]:
    """Collect top-level ACSL declaration profile keys from all `.h`/`.acsl` files in `work_dir` except `exclude_rels`."""
    names: set[str] = set()
    for d in _collect_all_header_declarations_with_metadata(work_dir, exclude_rels):
        names.add(d.get("profile_key") or d["name"])
    return names


def _supports_kwarg(func: Any, kwarg: str) -> bool:
    """Return True if `func` accepts `kwarg` as a named parameter or via `**kwargs`."""
    try:
        sig = inspect.signature(func)
        return kwarg in sig.parameters or any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
    except (ValueError, TypeError):
        return True


def _wp_report_detail(wp_report: dict) -> str:
    """`: <reason>; <first error line>` of a WP report (run_wp_function.py), or '' when it has neither."""
    parts: list[str] = []
    reason = wp_report.get("reason")
    if isinstance(reason, str) and reason.strip():
        parts.append(reason.strip())
    syntax = wp_report.get("syntax_check")
    soundness = wp_report.get("soundness")
    for errors in (
        wp_report.get("preprocess_errors"),
        syntax.get("errors") if isinstance(syntax, dict) else None,
        soundness.get("tier_a_aborts") if isinstance(soundness, dict) else None,
        soundness.get("tier_b_unsound") if isinstance(soundness, dict) else None,
    ):
        first = (
            next((e for e in errors if isinstance(e, str) and e.strip()), None) if isinstance(errors, list) else None
        )
        if first is not None:
            line = first.strip().splitlines()[0][:300]
            if not any(line in p for p in parts):
                parts.append(line)
            break
    return (": " + "; ".join(parts)) if parts else ""


PARENT_WP_WALL_TIMEOUT_ENV = "FRAMAC_PARENT_WP_WALL_TIMEOUT"
DEFAULT_PARENT_WP_WALL_TIMEOUT_S = 600
PARENT_WP_SUBPROCESS_GRACE_S = 60


def parent_wp_wall_timeout(explicit: int | None = None) -> int | None:
    """
    Wall-clock limit (seconds) for the parent WP re-check inside `_run_parent_reverify`.
    Reads `explicit` if given, else `FRAMAC_PARENT_WP_WALL_TIMEOUT`, else `DEFAULT_PARENT_WP_WALL_TIMEOUT_S` (600 s).
    `0` or `off` (also `none`/`false`/`no`/`disabled`) disables the limit and returns None.
    """
    if explicit is not None:
        return explicit if explicit > 0 else None
    raw = (os.environ.get(PARENT_WP_WALL_TIMEOUT_ENV) or "").strip().lower()
    if raw:
        if raw in ("0", "off", "none", "false", "no", "disabled"):
            return None
        try:
            val = int(float(raw))
        except ValueError:
            return DEFAULT_PARENT_WP_WALL_TIMEOUT_S
        return val if val > 0 else None
    return DEFAULT_PARENT_WP_WALL_TIMEOUT_S


def _run_parent_reverify(
    run_dir: Path,
    agent_id: str,
    role: str,
    overlay_dir: Path,
    c_file: str | None,
    function: str | None,
    module: str | None,
    sources: list[str] | None,
    cppflags: str,
    ldflags: str = "",
    wp_par: int | None = None,
    allow_partial_wp: bool = False,
    wp_extra_sources: list[str] | None = None,
    reach_functions: list[str] | None = None,
    baseline_had_assigns: bool | None = None,
    guardrail_note: dict | None = None,
    wp_wall_timeout: int | None = None,
) -> tuple[bool, str]:
    """
    Run dynamic guardrail (and WP for provers) on the merged workspace/work/ tree. `wp_par`
    caps the WP run's concurrent provers when several re-checks share the job budget (default:
    `auto`, the whole budget). The guardrail binary is built outside the agent's scratch, at a
    path fixed per module build, so an unchanged module is restored from the build cache.
    `reach_functions`: functions whose reach a module-wide guardrail (no `function`) measures,
    without narrowing its instrumentation; the report is at `_parent_guard_json(...)`.
    `baseline_had_assigns`: whether the contract this merge replaces had an `assigns` clause. When it
    had, a full proof whose WP report says the function has no frame (`frame_summary.assigns_clause`
    `absent` or `behaviors_only`) is refused; None (a re-check of a merged function) refuses nothing.

    The guardrail runs only with a `module` and its harness `sources`. Without them a prover's WP report
    gets `limits.guardrail` = {"status": "not_run", "reason": ...} (`guardrail_note` when the caller knows
    the reason better, e.g. the batch, whose module guardrail is a check of its own); with them, the
    guardrail's status. A report without `limits.guardrail` was written before this field existed.
    """
    scripts_dir = Path(__file__).resolve().parent
    work_dir = overlay_dir / "work"
    guard_report: dict | None = None
    guardrail_gap = _guardrail_gap(module, sources)
    if guardrail_gap and (function or module):
        # No guardrail runs in this call: a report left by an earlier one must not be read as its result.
        _parent_guard_json(run_dir, agent_id, function, module).unlink(missing_ok=True)

    if role == "prover" and c_file and function:
        # A proof under a memory model that is not evidence is never replayed, so the parent check
        # would re-prove under another model than the prover's: refuse it outright.
        model_problem = prover_wp_model_problem(
            run_dir,
            overlay_dir=overlay_dir,
            agent_id=agent_id,
            c_file=_normalize_work_relpath(c_file),
            function=function,
        )
        if model_problem:
            return False, f"prover's WP report used a memory model that is not accepted: {model_problem}"

    if module and sources:
        # A link unit is built through one of its harnesses (the one answering for `function`).
        mm = module_map_for(overlay_dir)
        hmod = harness_module_for_function(mm, module, c_file, function) or module
        # Use that harness's own sources: the merged sidecar of a unit also carries its target-fuzz
        # sub-modules, and compiling their `<fuzzer>.c` here renames the fuzz entry and leaves
        # libFuzzer's `main` with no real `LLVMFuzzerTestOneInput` (minmea run-1, 2026-11-14).
        h_sources = (mm.sidecars.get(hmod) or {}).get("sources")
        if isinstance(h_sources, list) and h_sources:
            sources = [str(s) for s in h_sources if isinstance(s, str) and s]
        harness = overlay_dir / "harnesses" / f"harness_{hmod}.c"
        corpus = overlay_dir / "corpus" / hmod
        # The parent re-check must use the same reduced checks as the module's build:
        # a module fuzzed with -no-rte-initialized would otherwise re-trip an
        # initialization alarm the module opted out of and be misread as code_fault.
        # Same for --no-fuzz-libc-checks (a false `... unallocated` report on a string libc allocated).
        rte_initialized = True
        libc_checks = True
        try:
            import pipeline_make  # imported lazily; the overlay also works without the Make layer

            _plan = pipeline_make.build_plan(run_dir)
            _eff = pipeline_make.effective_params(pipeline_make.load_params(run_dir), hmod, _plan.profile)
            rte_initialized = bool(_eff.get("fuzz_rte_initialized", True))
            libc_checks = bool(_eff.get("fuzz_libc_checks", True))
        except Exception:
            rte_initialized = True
            libc_checks = True
        build_tag_items: list = [list(sources), cppflags, ldflags, rte_initialized]
        if not libc_checks:
            build_tag_items.append("no-libc-checks")
        if function:
            build_tag_items.append(function)
        build_tag = hashlib.sha256(json.dumps(build_tag_items).encode()).hexdigest()[:10]
        safe_module = re.sub(r"[^A-Za-z0-9_.-]+", "_", hmod)
        bin_name = f"guard_{safe_module}_{function}" if function else f"guard_{safe_module}"
        guard_bin = run_dir / "state" / "parent_guard" / f"{safe_module}-{build_tag}" / bin_name
        guard_scratch = run_dir / "agents" / agent_id / "scratch" / "parent_guard"
        guard_json = _parent_guard_json(run_dir, agent_id, function, module)
        work_sources = [_resolve_overlay_source(run_dir, work_dir, s) for s in sources]
        if not any(Path(ws).name == harness.name for ws in work_sources):
            work_sources.append(str(harness))
        cmd = [
            sys.executable,
            str(scripts_dir / "run_eacsl_fuzz.py"),
            "guardrail",
            "--sources",
            *work_sources,
            "--out-bin",
            str(guard_bin),
            "--scratch-dir",
            str(guard_scratch),
            "--corpus-dir",
            str(corpus),
            "--extra-runs",
            "50",
            # `--opt=value`: argparse rejects a separate value that starts with '-' (e.g. `-I.`).
            f"--cppflags={cppflags}",
            "--module",
            hmod,
            "--no-verdict-cache",
            "--out-json",
            str(guard_json),
        ]
        if function:
            cmd.extend(["--functions", function])
        elif reach_functions:
            cmd.extend(["--reach-functions", *sorted(set(reach_functions))])
        if not rte_initialized:
            cmd.append("--no-rte-initialized")
        if not libc_checks:
            cmd.append("--no-libc-checks")
        if ldflags:
            cmd.append(f"--ldflags={ldflags}")
        proc = subprocess.run(cmd, cwd=str(run_dir), capture_output=True, text=True, encoding="utf-8", errors="replace")
        if proc.returncode != 0 or not guard_json.is_file():
            return (
                False,
                f"parent guardrail failed (rc={proc.returncode}): {proc.stderr.strip() or proc.stdout.strip()}",
            )
        report = json.loads(guard_json.read_text(encoding="utf-8"))
        if report.get("status") != "passed_dynamic_oracle":
            return False, f"parent guardrail returned status={report.get('status')!r}"
        guard_report = report

    if role == "prover" and c_file and function:
        norm_c = _normalize_work_relpath(c_file)
        wp_out_dir = run_dir / "agents" / agent_id / "scratch" / "parent_wp"
        # Written per agent: same-named static functions re-checked in parallel must never
        # read each other's report. Published under reports/wp/ only after success.
        wp_json = run_dir / _parent_wp_report_rel(agent_id, function)
        if wp_json.exists():
            wp_json.unlink()
        wp_extra_flags = infer_prover_wp_flags(
            run_dir,
            overlay_dir=overlay_dir,
            agent_id=agent_id,
            c_file=norm_c,
            function=function,
        )
        wall_timeout = parent_wp_wall_timeout(wp_wall_timeout)
        cmd = [
            sys.executable,
            str(scripts_dir / "run_wp_function.py"),
            "--file",
            str(work_dir / norm_c),
            "--function",
            function,
            "--out-dir",
            str(wp_out_dir),
            f"--cppflags={cppflags}",
            "--wp-par",
            str(wp_par) if wp_par else "auto",
            "--wall-timeout",
            str(wall_timeout if wall_timeout is not None else 0),
            *wp_extra_flags,
            # Witness models for failed goals, so crash verifiers get a concrete counter-example
            # for any Invalid the merged candidate still carries (report: counter_example_goals).
            "--counter-examples",
            "--sarif",
            "--ignore-prover-budget",
            "--out-json",
            str(wp_json),
        ]
        if wp_extra_sources:
            cmd.extend(["--extra-sources", *wp_extra_sources])
        proc_timeout = wall_timeout + PARENT_WP_SUBPROCESS_GRACE_S if wall_timeout is not None else None
        run_kwargs: dict[str, Any] = {
            "cwd": str(run_dir),
            "capture_output": True,
            "text": True,
            "encoding": "utf-8",
            "errors": "replace",
        }
        if proc_timeout is not None and _supports_kwarg(subprocess.run, "timeout"):
            run_kwargs["timeout"] = proc_timeout
        try:
            proc = subprocess.run(cmd, **run_kwargs)
        except subprocess.TimeoutExpired:
            wp_json.unlink(missing_ok=True)
            return (
                False,
                f"parent WP re-check timed out after {proc_timeout}s (wall limit {wall_timeout}s) for {function}",
            )
        if proc.returncode != 0 or not wp_json.is_file():
            return False, f"parent WP check failed (rc={proc.returncode}): {proc.stderr.strip() or proc.stdout.strip()}"
        wp_report = json.loads(wp_json.read_text(encoding="utf-8"))
        wp_status = wp_report.get("status")
        if allow_partial_wp:
            sound_ok = bool((wp_report.get("soundness") or {}).get("ok"))
            assigns_ok = assigns_verified_for_partial_merge(wp_report)
            if wp_status not in ("all_proven", "unproven_goals_remain") or not sound_ok or not assigns_ok:
                return (
                    False,
                    f"parent partial WP check rejected (status={wp_status!r}, sound_ok={sound_ok}, "
                    f"assigns_verified={assigns_ok}){_wp_report_detail(wp_report)}",
                )
        elif wp_status != "all_proven":
            return False, f"parent WP check on merged tree returned status={wp_status!r}{_wp_report_detail(wp_report)}"
        else:
            frame_state = (wp_report.get("frame_summary") or {}).get("assigns_clause")
            if baseline_had_assigns and frame_state in NO_FRAME_STATES:
                return False, _no_frame_refusal(function, str(frame_state))
        if guard_report is not None:
            _apply_guard_limits(wp_report, function, guard_report)
        else:
            # The proof stands on WP alone: the report says so, in a shape no reader can take for a pass.
            limits = wp_report.get("limits")
            if not isinstance(limits, dict):
                limits = wp_report["limits"] = {}
            limits["guardrail"] = guardrail_note or guardrail_not_run(guardrail_gap or "no guardrail report")
        wp_json.write_text(json.dumps(wp_report, indent=2) + "\n", encoding="utf-8")
        _publish_canonical_wp(run_dir, overlay_dir, wp_json, norm_c, function)

    return True, "verified"


GUARDRAIL_PASSED = "passed_dynamic_oracle"
GUARDRAIL_NOT_RUN = "not_run"


def guardrail_not_run(reason: str) -> dict:
    """The `guardrail` value of a merge result or of a WP report's limits when no guardrail ran: never a pass."""
    return {"status": GUARDRAIL_NOT_RUN, "reason": reason}


def _guardrail_gap(module: str | None, sources: list[str] | None) -> str | None:
    """Why `_run_parent_reverify` cannot run the E-ACSL guardrail with these inputs, or None when it can."""
    if not module:
        return "no module was named for the re-check, so there is no harness to build the guardrail from"
    if not sources:
        return (
            f"module {module} has no harness sidecar with sources (workspace/harnesses/harness_*.json), "
            "so no guardrail binary can be built for it"
        )
    return None


def _guardrail_outcome(
    run_dir: Path, agent_id: str, function: str | None, module: str | None, sources: list[str] | None
) -> dict:
    """
    What the guardrail of a parent re-check that succeeded established, for the merge result: its status and
    report, or `not_run` with the reason. Read from the report `_run_parent_reverify` wrote in this call (it
    removes an older one when it runs no guardrail), so a missing report is `not_run`, never a pass.
    """
    gap = _guardrail_gap(module, sources)
    if gap:
        return guardrail_not_run(gap)
    path = _parent_guard_json(run_dir, agent_id, function, module)
    report = load_json_optional(path, {}) if path.is_file() else None
    if not isinstance(report, dict) or not report.get("status"):
        return guardrail_not_run(
            f"the parent re-check left no guardrail report at {path.relative_to(run_dir).as_posix()}"
        )
    return {"status": report["status"], "report": path.relative_to(run_dir).as_posix()}


# `frame_summary.assigns_clause` of a WP report (run_wp_function.frame_clause_state) when nothing was proved
# about what the function writes.
NO_FRAME_STATES = ("absent", "behaviors_only")


def _no_frame_refusal(function: str | None, frame_state: str) -> str:
    detail = (
        "WP found no `assigns` clause for the function"
        if frame_state == "absent"
        else "only some named behaviors have an `assigns` clause and they do not cover the function"
    )
    return (
        f"parent WP check on merged tree proved every goal of {function}, but its contract has no frame "
        f"(frame_summary.assigns_clause={frame_state!r}: {detail}), and the contract it replaces had an `assigns` "
        "clause. Nothing was proved about what the function writes. Put an `assigns` clause back in the default "
        "behavior (or one in each behavior of a `complete behaviors` set); when a callee without a usable contract "
        "makes it unprovable, keep the clause, return the function as not proven and file a strengthening request."
    )


def _merged_contract(
    work_dir: Path, c_file: str | None, function: str | None, cppflags: str
) -> contract_refinement.FunctionContract | None:
    """The contract of `function` as it stands in `work_dir` (None when it cannot be read)."""
    if not c_file or not function:
        return None
    try:
        return contract_refinement.read_function_contract(work_dir / c_file, function, cppflags)
    except (OSError, AcslError):
        return None


def record_contract_refinement(
    run_dir: Path,
    overlay_dir: Path,
    agent_id: str,
    c_file: str,
    function: str,
    cppflags: str,
    previous: contract_refinement.FunctionContract | None,
) -> dict | None:
    """
    Merge re-check, use 1 of scripts/contract_refinement.py: whether the contract just merged for
    `function` gives everything the contract it replaced did. Runs on the merged tree after the parent
    WP re-check passed, and writes the verdict into the parent WP report (`contract_refinement`) and its
    canonical copy. `weaker` and `undecided` never block the merge: the scheduler re-checks the merged
    callers against the new contract and reopens any whose proof no longer holds. None (nothing recorded)
    when no contract was merged before.
    """
    if previous is not None and not previous.pieces:
        return None
    work_dir = overlay_dir / "work"
    new = _merged_contract(work_dir, c_file, function, cppflags)
    if previous is None or new is None:
        res: dict = {
            "verdict": contract_refinement.UNDECIDED,
            "reason": "the previous or the merged contract could not be read",
            "probe_run": False,
        }
    else:
        try:
            res = contract_refinement.refinement_check(new, previous, work_dir / c_file, cppflags)
        except Exception as exc:  # the check is a record: it never fails a merge that passed its re-check
            res = {"verdict": contract_refinement.UNDECIDED, "reason": f"{type(exc).__name__}: {exc}"}
    wp_json = run_dir / _parent_wp_report_rel(agent_id, function)
    try:
        wp_report = json.loads(wp_json.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        wp_report = None
    if isinstance(wp_report, dict):
        wp_report["contract_refinement"] = res
        wp_json.write_text(json.dumps(wp_report, indent=2) + "\n", encoding="utf-8")
        _publish_canonical_wp(run_dir, overlay_dir, wp_json, c_file, function)
    return res


def _parent_guard_json(run_dir: Path, agent_id: str, function: str | None, module: str | None) -> Path:
    """Where `_run_parent_reverify` writes its guardrail report."""
    return run_dir / "agents" / agent_id / "scratch" / f"parent_guard_{function or module}.json"


def function_name_is_shared(run_dir: Path, function: str, norm_c: str) -> bool:
    """Whether the ledger has `function` in a file other than `norm_c` (a same-named static function)."""
    return len(_function_files(run_dir, function) - {norm_c}) > 0


def _publish_canonical_wp(run_dir: Path, overlay_dir: Path, wp_json: Path, norm_c: str, function: str) -> None:
    """Copy a parent WP report to reports/wp/<function>.json unless the name is ambiguous across files."""
    if not function_name_is_shared(run_dir, function, norm_c):
        canonical = overlay_dir / "reports" / "wp" / f"{function}.json"
        canonical.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(wp_json, canonical)


def _apply_guard_limits(wp_report: dict, function: str, guard_report: dict) -> bool:
    """
    Record in `wp_report["limits"]` what the parent guardrail established for `function`:
    `dynamic_oracle` {exercised, hits, executed_inputs} from its reach and `guardrail_corpus`
    {total, replayed, sampled, empty}. A pass on an empty corpus replayed no real input, so it is
    recorded as not exercised (an open assumption in the ledger), never as a pass on inputs.
    `guardrail` {status} says that this guardrail ran (`_run_parent_reverify` writes `not_run` there
    when none did). `dynamic_oracle` also gets `unchecked_clauses` (list, or None when not known) and,
    when there are any, `unattributed`. Returns whether anything was recorded (always, since
    `guardrail` is).
    """
    limits = wp_report.setdefault("limits", {})
    limits["guardrail"] = {"status": guard_report.get("status")}
    corpus_empty = bool(guard_report.get("corpus_empty"))
    changed = True
    if "corpus_total" in guard_report:
        limits["guardrail_corpus"] = {
            "total": guard_report.get("corpus_total"),
            "replayed": guard_report.get("corpus_replayed"),
            "sampled": bool(guard_report.get("corpus_sampled")),
            "empty": corpus_empty,
        }
        changed = True
    reach = guard_report.get("reach")
    if isinstance(reach, dict) and reach.get("measured"):
        limits["dynamic_oracle"] = {
            "exercised": function not in (reach.get("unreached") or []) and not corpus_empty,
            "hits": (reach.get("functions") or {}).get(function),
            "executed_inputs": reach.get("executed_inputs"),
        }
        changed = True
    elif corpus_empty:
        limits["dynamic_oracle"] = {
            "exercised": False,
            "hits": None,
            "executed_inputs": reach.get("executed_inputs") if isinstance(reach, dict) else None,
        }
        changed = True
    # What E-ACSL generated no check for (run_eacsl_fuzz.dynamic_oracle_fields): a pass says nothing
    # about those clauses. `unchecked_clauses` is this function's items; None when the guardrail had no
    # build report to read them from (not known, which is not "none"). `unattributed` lists the
    # ignored annotations no function could be read for, whichever function they belong to.
    oracle = limits.setdefault("dynamic_oracle", {})
    unchecked = guard_report.get("unchecked_clauses")
    oracle["unchecked_clauses"] = (
        [c for c in unchecked if isinstance(c, dict) and c.get("function") == function]
        if isinstance(unchecked, list)
        else None
    )
    unattributed = guard_report.get("unattributed_ignored_annotations")
    if isinstance(unattributed, list) and unattributed:
        oracle["unattributed"] = unattributed
    return changed


def _record_batch_reach(run_dir: Path, overlay_dir: Path, item: dict, guard_report: dict) -> None:
    """Add the module guardrail's limits to a batch prover's parent WP report (and its canonical copy)."""
    if not item.get("function") or not item.get("c_file"):
        return
    wp_json = run_dir / _parent_wp_report_rel(item["agent_id"], item["function"])
    try:
        wp_report = json.loads(wp_json.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    if not isinstance(wp_report, dict) or not _apply_guard_limits(wp_report, item["function"], guard_report):
        return
    wp_json.write_text(json.dumps(wp_report, indent=2) + "\n", encoding="utf-8")
    _publish_canonical_wp(run_dir, overlay_dir, wp_json, _normalize_work_relpath(item["c_file"]), item["function"])


def merge_agent_overlay(
    run_dir: Path,
    agent_id: str,
    role: str,
    overlay_dir: Path | None = None,
    c_file: str | None = None,
    function: str | None = None,
    header_file: str | None = None,
    module: str | None = None,
    sources: list[str] | None = None,
    cppflags: str = "-I.",
    ldflags: str = "",
    skip_reverify: bool = False,
    verify_hook: Callable[[], tuple[bool, str]] | None = None,
    journal: bool = True,
    allow_partial_wp: bool = False,
    contract_only: bool = False,
    wp_extra_sources: list[str] | None = None,
) -> dict:
    """
    Validate an agent's scratch overlay (ACSL-only + role/function scope), structurally
    splice its annotations into workspace/work/, deduplicate shared ACSL declarations across
    headers, re-verify on the merged tree (rolling back on failure), and write the resulting
    unified diff into agents/<id>/artifacts/. Holds the `merge` lock; with `journal`, the
    pre-splice contents are journaled so a killed merge is rolled back by the next caller.
    """
    run_dir = Path(run_dir).resolve()
    with run_lock("merge", run_dir):
        recovered = recover_merge_journal(run_dir, overlay_dir) if journal else None
        res = _merge_agent_overlay_locked(
            run_dir,
            agent_id,
            role,
            overlay_dir,
            c_file,
            function,
            header_file,
            module,
            sources,
            cppflags,
            ldflags,
            skip_reverify,
            verify_hook,
            journal,
            allow_partial_wp=allow_partial_wp,
            contract_only=contract_only,
            wp_extra_sources=wp_extra_sources,
        )
        if recovered:
            res["recovered_journal"] = recovered
        return res


def _callee_names(fn_meta: dict) -> list[str]:
    """The function's callees from its call graph record, as plain names (`file#fn` keys lose the file)."""
    for key in ("internal_callees", "direct_callees", "callees"):
        raw = fn_meta.get(key)
        if isinstance(raw, list) and raw:
            return sorted({str(c).rsplit("#", 1)[-1] for c in raw if c})
    return []


def _earlier_refutations(run_dir: Path, agent_id: str, function: str | None, c_file: str | None) -> list[dict]:
    """
    Clauses the guardrail refuted on earlier provers of the same function and file in this run. A re-dispatch gets a
    fresh agent id (wp_scheduler._assign_agent), so the earlier attempts live in other agents' scratch directories.
    """
    agents = run_dir / "agents"
    if not function or not agents.is_dir():
        return []
    out: list[dict] = []
    for agent in sorted(agents.iterdir()):
        scratch = agent / "scratch"
        if agent.name == agent_id or not (scratch / prover_candidates.STATE_FILE).is_file():
            continue
        try:
            budget = json.loads((scratch / prover_candidates.BUDGET_FILE).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(budget, dict) or budget.get("function") != function:
            continue
        if c_file and _normalize_work_relpath(str(budget.get("file") or "")) != c_file:
            continue
        for clause in prover_candidates.refuted_clauses(scratch):
            out.append({**clause, "kind": "guardrail_refutation", "function": function, "source": agent.name})
    return out


def _load_function_facts(overlay: Path, module: str | None, c_file: str | None, function: str | None) -> dict | None:
    """
    A function's facts (`reports/facts/<harness module>.json`): the module's own report, then that
    of the harness answering for the function, then those of its unit's other harnesses.
    """
    if not (module and c_file and function):
        return None
    mm = module_map_for(overlay)
    first = harness_module_for_function(mm, module, c_file, function)
    candidates: list[str] = [module, *([first] if first else []), *harness_modules_of(mm, module)]
    for name in dict.fromkeys(candidates):
        record = function_facts.load_function_facts(overlay, name, c_file, function)
        if record is not None:
            return record
    return None


def _function_frame_skeleton(
    overlay: Path, module: str | None, c_file: str | None, function: str | None
) -> dict | None:
    """The projected frame skeleton of `function` from the module's facts, or None (fail-open)."""
    if not (module and c_file and function):
        return None
    record = _load_function_facts(overlay, module, c_file, function)
    if not isinstance(record, dict):
        return None
    skel = record.get("frame_skeleton")
    return skel if isinstance(skel, dict) else None


def _frame_contract_files(
    run_dir: Path,
    overlay: Path,
    c_file: str | None,
    function: str | None,
    header_file: str | None,
    module: str | None,
    header_flags: str,
    changed_rels: list[str],
) -> list[str]:
    """
    The files that can hold `function`'s contract: its source, the header declaring it and whatever the
    agent changed. Only read by the frame check: what the agent may edit is decided by the merge's scope check.
    """
    header = header_file
    if not header and module:
        named = merged_sidecar(module_map_for(overlay), module).get("header")
        header = _prover_header(run_dir, overlay / "work", c_file, function, named and str(named), header_flags)
    return list(dict.fromkeys(rel for rel in (c_file, header, *changed_rels) if rel))


def _merged_contract_acsl(shared_work: Path, rels: list[str], new_contents: dict[str, str], function: str) -> str:
    """
    The function contract of `function`'s declarations in `rels` as the merge leaves them: the spliced text of
    a file the agent changed, the shared tree's text of any other. An unchanged file that cannot be read
    contributes no clause, so it can only make the frame check refuse. Annotations inside the body are not
    part of the contract: a statement contract there says nothing about what the function writes.
    """
    parts: list[str] = []
    for rel in rels:
        spliced = new_contents.get(rel)
        try:
            text = spliced if spliced is not None else (shared_work / rel).read_text(encoding="utf-8")
            # A header may declare the function twice (prototype and `static inline` definition); the
            # contract can sit on either declaration, so read the contract of every one. Frama-C merges
            # the contracts and takes the union of their `assigns`, which is what "some clause lists the
            # location" checks.
            pieces = [
                declaration_contract_text(decl, rel)
                for decl in contract_declaration_spans(text, function, is_header=rel.endswith(".h"), path=rel)
            ]
        except (AcslError, ValueError, OSError):  # UnicodeDecodeError is a ValueError
            if spliced is not None:
                raise
            continue
        for piece in pieces:
            if piece and piece not in parts:
                parts.append(piece)
    return "\n".join(parts)


FRAME_REFUSAL = "frame-preservation check failed"


def _frame_refusal(
    skeleton: dict,
    run_dir: Path,
    overlay: Path,
    c_file: str | None,
    function: str | None,
    header_file: str | None,
    module: str | None,
    header_flags: str,
    new_contents: dict[str, str],
) -> str | None:
    """
    Why the merge refuses this result, or None. The projected frame skeleton is a required minimum: a prover
    candidate that deletes or weakens a projected \\separated / assigns...\\from clause is rejected. The contract
    may live in the .c or the .h, whichever of them the agent changed (possibly neither), so the function's
    contract is checked as the merge would leave it in all of them together.
    """
    rels = _frame_contract_files(run_dir, overlay, c_file, function, header_file, module, header_flags, [*new_contents])
    acsl = _merged_contract_acsl(overlay / "work", rels, new_contents, function or "")
    errors = check_frame_preserved(skeleton, acsl, path=c_file or "<work>")
    return f"{FRAME_REFUSAL}:\n  " + "\n  ".join(errors) if errors else None


def _had_contract(texts: dict[str, str], function: str) -> bool | None:
    """Whether a declaration of `function` in `texts` carries a contract; None when a text cannot be read."""
    try:
        return any(
            declaration_contract_text(decl, rel).strip()
            for rel, text in texts.items()
            for decl in function_declaration_spans(text, function, path=rel)
        )
    except AcslError:
        return None


def _has_whole_frame(change: Mapping[str, Any], side: str) -> bool:
    """
    Whether `side` (`"baseline"` or `"candidate"`) of a `contract_change` dict frames the whole function:
    explicit `*_has_whole_frame` when present, else whether `DEFAULT_BEHAVIOR` has an `assigns` clause.
    """
    key = f"{side}_has_whole_frame"
    if key in change:
        return bool(change[key])
    return DEFAULT_BEHAVIOR in (change.get(f"{side}_assigns_in") or ())


def contract_change(shared_work: Path, rels: list[str], new_contents: dict[str, str], function: str) -> dict:
    """
    What a prover or architect merge changes in the contract of `function` (the merge result's `contract_changes`):
    the contract in `rels` on the shared tree against the one the merge leaves there (`new_contents` for the files
    it changes), compared clause by clause (acsl_ast.compare_function_contracts).

    - `available`, `reason`: whether the two could be compared, and why not;
    - `had_contract`: the shared tree had a contract for the function (None: its text cannot be read);
    - `baseline_assigns_in`, `candidate_assigns_in`: the behaviors with an `assigns` clause before and after
      (`default!` is the contract outside every named behavior);
    - `baseline_has_whole_frame`, `candidate_has_whole_frame`: whether the baseline / candidate frames the
      whole function (a default `assigns` clause, or a `complete behaviors` set whose behaviors all have one);
    - `assigns_removed`, `ensures_removed`: `{behavior, clauses}` per behavior that lost its `assigns` clause
      altogether, or some `ensures` clause; `behaviors_removed`, `completeness_removed`: the named behaviors
      and the `complete` / `disjoint` clauses that are gone.

    An unchanged file that cannot be read is left out of both sides: what it holds is there before and after.
    """
    before: dict[str, str] = {}
    after: dict[str, str] = {}
    for rel in rels:
        try:
            text = (shared_work / rel).read_text(encoding="utf-8")
        except (OSError, ValueError):  # UnicodeDecodeError is a ValueError
            if rel in new_contents:
                raise
            continue
        before[rel] = text
        after[rel] = new_contents.get(rel, text)
    cmp = compare_function_contracts(before, after, function)
    behaviors = cmp["behaviors"]
    return {
        "function": function,
        "files": list(before),
        "available": bool(cmp["available"]),
        "reason": cmp["reason"],
        "had_contract": bool(cmp["had_contract"]) if cmp["available"] else _had_contract(before, function),
        "baseline_assigns_in": [n for n, e in behaviors.items() if e["assigns"]["baseline"]],
        "candidate_assigns_in": [n for n, e in behaviors.items() if e["assigns"]["candidate"]],
        "baseline_has_whole_frame": contract_has_whole_frame(cmp, "baseline"),
        "candidate_has_whole_frame": contract_has_whole_frame(cmp, "candidate"),
        "assigns_removed": [
            {"behavior": n, "clauses": [c["text"] for c in behaviors[n]["assigns"]["baseline"]]}
            for n in cmp["summary"]["assigns_removed_in"]
        ],
        "ensures_removed": [
            {"behavior": n, "clauses": list(behaviors[n]["ensures"]["removed"])}
            for n in cmp["summary"]["ensures_removed_in"]
        ],
        "behaviors_removed": list(cmp["summary"]["behaviors_removed"]),
        "completeness_removed": list(cmp["completeness"]["removed"]),
    }


def contract_change_errors(change: dict) -> list[str]:
    """
    Why the merge refuses the contract change `change` (contract_change), or []. Refused:

    - an `assigns` clause the contract had, in the default behavior or in a named one, with none left in that
      behavior. A tightened or rewritten clause is not a removal. Replacing a default `assigns` with a
      `complete behaviors` set whose behaviors each have an `assigns` clause is not a removal either (the whole
      function remains framed). A named behavior removed as a whole takes its clause with it only when the result
      still frames the whole function (default `assigns`, or a `complete behaviors` set where every behavior has
      one);
    - removing `complete behaviors` coverage that was the baseline's only whole-function frame;
    - a comparison that cannot be made, unless the function is known to have had no contract.

    A removed `ensures` or behavior is not refused: `change` records it for the ledger and the report.
    """
    fn = change["function"]
    if not change["available"]:
        if change["had_contract"] is False:
            return []
        had = "had a contract" if change["had_contract"] else "may have had a contract (its text cannot be read)"
        return [
            f"{fn}: its contract before and after the merge cannot be compared ({change['reason']}), and the "
            f"function {had}. A result that may remove a clause is not merged unchecked: keep every declaration "
            f"of {fn} and its C text as they are, change ACSL annotations only, and return the result again."
        ]
    errors: list[str] = []
    candidate_framed = _has_whole_frame(change, "candidate")
    for item in change["assigns_removed"]:
        name = item["behavior"]
        if (name == DEFAULT_BEHAVIOR or name in change["behaviors_removed"]) and candidate_framed:
            continue
        where = "its contract" if name == DEFAULT_BEHAVIOR else f"behavior '{name}' of its contract"
        clauses = ", ".join(f"`assigns {c}`" for c in item["clauses"])
        errors.append(
            f"{fn}: the result removes {clauses} from {where} and leaves no `assigns` clause there, so nothing "
            f"would be proved about what {fn} writes. Keep an `assigns` clause there: it may be tightened or "
            "rewritten, never deleted. When a callee without a usable contract makes it unprovable, keep the "
            "clause, return the function as not proven and file a strengthening request for that callee."
        )
    if not errors and _has_whole_frame(change, "baseline") and not candidate_framed:
        errors.append(
            f"{fn}: the result removes `complete behaviors` coverage of its `assigns` clauses and leaves no "
            f"whole-function `assigns` clause, so nothing would be proved about what {fn} writes. Keep a "
            "default `assigns` clause or a `complete behaviors` set whose behaviors each have an `assigns` clause."
        )
    return errors


def _contract_refusal(change: dict) -> str | None:
    errors = contract_change_errors(change)
    return f"{FRAME_REFUSAL}:\n  " + "\n  ".join(errors) if errors else None


def _architect_contract_changes(
    shared_work: Path, rels: list[str], new_contents: dict[str, str]
) -> tuple[dict | None, list[str]]:
    """
    Check every function declared in modified header files `rels` against the shared tree so an architect
    merge cannot silently delete an existing `assigns` clause. Returns `(aggregated_changes, refusal_errors)`.
    """
    hdr_rels = [rel for rel in rels if rel.endswith(".h") and rel in new_contents]
    if not hdr_rels:
        return None, []
    per_fn: dict[str, dict] = {}
    errors: list[str] = []
    for rel in hdr_rels:
        before_text = (shared_work / rel).read_text(encoding="utf-8")
        after_text = new_contents[rel]
        fns = sorted(set(header_function_names(before_text, rel)) | set(header_function_names(after_text, rel)))
        for fn in fns:
            change = contract_change(shared_work, [rel], new_contents, fn)
            errors.extend(contract_change_errors(change))
            per_fn[fn] = change
    if errors:
        return None, errors
    if not per_fn:
        return None, []
    reasons = [c["reason"] for c in per_fn.values() if not c["available"] and c.get("reason")]
    return (
        {
            "files": hdr_rels,
            "available": all(c["available"] for c in per_fn.values()),
            "reason": "; ".join(reasons),
            "functions": per_fn,
            "assigns_removed": [{**item, "function": fn} for fn, c in per_fn.items() for item in c["assigns_removed"]],
            "ensures_removed": [{**item, "function": fn} for fn, c in per_fn.items() for item in c["ensures_removed"]],
            "behaviors_removed": [f"{fn}:{b}" for fn, c in per_fn.items() for b in c["behaviors_removed"]],
            "completeness_removed": [f"{fn}: {cl}" for fn, c in per_fn.items() for cl in c["completeness_removed"]],
        },
        [],
    )


def _changed_prover_header(
    run_dir: Path,
    overlay: Path,
    c_file: str,
    function: str,
    module: str | None,
    header_flags: str,
    changed_rels: list[str],
) -> str | None:
    """The header of a prover merge that names none: the one it changed beside its source, or its module's."""
    sibling = Path(c_file).with_suffix(".h").as_posix()
    if sibling in changed_rels:
        return sibling
    stem_matches = [r for r in changed_rels if r.endswith(".h") and Path(r).stem == Path(c_file).stem]
    if len(stem_matches) == 1:
        return stem_matches[0]
    named = merged_sidecar(module_map_for(overlay), module).get("header") if module else None
    header = _prover_header(run_dir, overlay / "work", c_file, function, str(named), header_flags) if named else None
    return header if header in changed_rels else None


def merged_frame_refusal(
    run_dir: Path,
    c_file: str | None,
    function: str | None,
    header_file: str | None,
    module: str | None,
    cppflags: str,
    new_contents: dict[str, str],
    *,
    role: str = "prover",
) -> str | None:
    """The merge's own frame check, run dry on a prover or architect result spliced into `new_contents`."""
    run_dir = Path(run_dir).resolve()
    overlay = run_dir / "workspace"
    if role == "architect" or (not c_file and not function):
        _changes, arch_errors = _architect_contract_changes(overlay / "work", [*new_contents], new_contents)
        return f"{FRAME_REFUSAL}:\n  " + "\n  ".join(arch_errors) if arch_errors else None
    c_rel = _normalize_work_relpath(c_file or "")
    fn = function or ""
    skeleton = _function_frame_skeleton(overlay, module, c_rel, fn)
    flags = _module_header_flags(overlay, module, cppflags)
    header = (
        _prover_header(run_dir, overlay / "work", c_rel, fn, _normalize_work_relpath(header_file), flags)
        if header_file
        else _changed_prover_header(run_dir, overlay, c_rel, fn, module, flags, [*new_contents])
    )
    rels = _frame_contract_files(run_dir, overlay, c_rel, fn, header, module, flags, [*new_contents])
    refusal = _contract_refusal(contract_change(overlay / "work", rels, new_contents, fn))
    if refusal or skeleton is None:
        return refusal
    return _frame_refusal(skeleton, run_dir, overlay, c_rel, fn, header, module, flags, new_contents)


TRUST_BOUNDARY_REASON = "trust-boundary check failed"


def _untrusted_entry_metas(
    overlay: Path, module: str | None, function: str | None = None, file: str | None = None
) -> list[dict]:
    """
    The harness sidecars standing for `module` (all of its unit's harnesses for a link unit) whose
    entry function is an untrusted_surface entry. Each sidecar is read from disk, so a malformed one
    fails the merge instead of being skipped. `function` is checked too when its trust (step I7)
    puts it on the trust boundary and no harness enters through it: a dispatch harness drives
    several API functions but names one entry. Its trust is that of `function` in `file` (a
    same-named static elsewhere keeps its own), and the entry records the file.
    """
    out = _sidecar_untrusted_entries(overlay, module)
    if function and not any(m.get("entry_fn") == function for m in out):
        if is_trust_boundary(function_trust_records(overlay), function, file):
            entry: dict = {"entry_fn": function, "reachability": "untrusted_surface", "trust_boundary": True}
            if file:
                entry["file"] = file
            # The harnesses of the same unit may NUL-terminate the input even though none of them
            # is the entry named here (`minmea_checksum` is called by the `minmea` harness from its
            # NUL-terminated copy). Carry that shape fact, or `valid_read_string` on the attacker
            # string is misread as a value constraint (minmea run-1, 2026-11-14).
            if any(bool(m.get("null_terminate")) or m.get("entry_style") in ("c_string", "argv") for m in out):
                entry["null_terminate"] = True
            out.append(entry)
    return out


def _sidecar_untrusted_entries(overlay: Path, module: str | None) -> list[dict]:
    if not module:
        return []
    names = harness_modules_of(module_map_for(overlay), module)
    if (overlay / "harnesses" / f"harness_{module}.json").is_file() and module not in names:
        names = [module, *names]
    out: list[dict] = []
    for name in names:
        hmeta = load_json_optional(overlay / "harnesses" / f"harness_{name}.json", {})
        if not isinstance(hmeta, dict) or not hmeta.get("entry_fn"):
            continue
        # prepare_agent treats a sidecar without `reachability` as untrusted_surface; so does this check.
        if (hmeta.get("reachability") or "untrusted_surface") == "untrusted_surface":
            out.append(hmeta)
    return out


def entry_trust_boundary_errors(
    hmeta: dict, rel: str, merged_text: str, agent_text: str, base_text: str, baseline_text: str
) -> list[str]:
    """
    Trust-boundary violations an agent adds to the untrusted_surface entry function's contract in
    `rel` (docs/guides/v2-design.md §6). Only the entry function is checked, and only when the agent
    changed its contract; violations already in the target's own baseline ACSL are not the agent's.
    An entry that records its `file` (one the function's trust put on the boundary) is checked in
    that source and in headers, never in another source's same-named static.

    In a header, every declaration of the entry is checked (a `static inline` function is often
    declared twice and a contract may sit on either), each against its own formal names: the
    prototype may call a parameter `pUOutBuf` and the definition `pMe` (QCBOR run-6).
    """
    entry = str(hmeta.get("entry_fn") or "")
    if not entry or Path(rel).suffix not in ACSL_CHECK_EXTS:
        return []
    is_hdr = rel.endswith(".h")
    entry_file = _normalize_work_relpath(str(hmeta.get("file") or ""))
    if entry_file and not is_hdr and _normalize_work_relpath(rel) != entry_file:
        return []
    try:
        if [declaration_contract_text(d, rel) for d in contract_declaration_spans(agent_text, entry, is_hdr, rel)] == [
            declaration_contract_text(d, rel) for d in contract_declaration_spans(base_text, entry, is_hdr, rel)
        ]:
            return []
        merged_decls = contract_declaration_spans(merged_text, entry, is_hdr, rel)
        baseline_decls = contract_declaration_spans(baseline_text, entry, is_hdr, rel)
    except AcslError:
        return []  # the ACSL-only check reports unparsable files
    globals_ = {str(hmeta[k]) for k in ("global_buf", "global_len") if hmeta.get(k)}
    nul = bool(hmeta.get("null_terminate")) or hmeta.get("entry_style") in ("c_string", "argv")

    def violations(decls: list) -> list[str]:
        out: list[str] = []
        for decl in decls:
            params = set(declaration_param_names(decl, rel)) | globals_
            for v in entry_requires_violations(declaration_contract_text(decl, rel), params, nul_terminated=nul):
                if v not in out:
                    out.append(v)
        return out

    found = violations(merged_decls)
    if not found:
        return []
    pre_existing = set(violations(baseline_decls))
    return [f"{rel}: {entry}: {v}" for v in found if v not in pre_existing]


def _merge_agent_overlay_locked(
    run_dir: Path,
    agent_id: str,
    role: str,
    overlay_dir: Path | None,
    c_file: str | None,
    function: str | None,
    header_file: str | None,
    module: str | None,
    sources: list[str] | None,
    cppflags: str,
    ldflags: str,
    skip_reverify: bool,
    verify_hook: Callable[[], tuple[bool, str]] | None,
    journal: bool,
    allow_partial_wp: bool = False,
    contract_only: bool = False,
    wp_extra_sources: list[str] | None = None,
) -> dict:
    if not is_safe_agent_id(agent_id):
        raise ArtifactError(f"invalid agent_id: {agent_id!r}")
    if role not in ("prover", "architect"):
        raise ArtifactError(f"only 'prover' and 'architect' overlays can be merged (got {role!r})")

    run_dir = run_dir.resolve()
    overlay = (overlay_dir or (run_dir / "workspace")).resolve()
    baseline_dir = overlay / "baseline"
    shared_work = overlay / "work"
    agent_root = run_dir / "agents" / agent_id
    scratch_work = agent_root / "scratch" / "work"
    scratch_base = agent_root / "scratch" / "base"
    artifacts_dir = agent_root / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    if not scratch_work.is_dir() or not scratch_base.is_dir():
        raise OverlayMergeError(f"agent scratch overlay not initialized for {agent_id}")

    norm_c_file = _normalize_work_relpath(c_file) if c_file else None
    norm_header_file = _normalize_work_relpath(header_file) if header_file else None
    header_flags = _module_header_flags(overlay, module, cppflags)
    if norm_header_file:
        if role == "prover":
            norm_header_file = _prover_header(
                run_dir, shared_work, norm_c_file, function, norm_header_file, header_flags
            )
        else:
            norm_header_file = _resolve_include_header(run_dir, shared_work, norm_header_file, header_flags)

    changed_rels = _collect_changed_files(scratch_base, scratch_work)
    allowed_rels = set()
    if role == "architect":
        if not norm_header_file:
            raise ArtifactError("architect merge requires header_file")
        allowed_rels.add(norm_header_file)
    else:
        if not norm_c_file or not function:
            raise ArtifactError("prover merge requires c_file and function")
        allowed_rels.add(norm_c_file)
        if not norm_header_file:
            # Auto-infer sibling or module header when the prover also updated its function prototype contract
            norm_header_file = _changed_prover_header(
                run_dir, overlay, norm_c_file, function, module, header_flags, changed_rels
            )
        if norm_header_file:
            allowed_rels.add(norm_header_file)

    disallowed = [r for r in changed_rels if r not in allowed_rels]
    if disallowed:
        raise ScopeViolationError(
            f"agent {agent_id} ({role}) modified files outside allowed scope {sorted(allowed_rels)}: {disallowed}"
        )

    # Save backup of shared_work files for atomic rollback
    backups: dict[str, bytes] = {}
    new_contents: dict[str, str] = {}
    texts_before: dict[str, tuple[str, str, str]] = {}  # rel -> (agent, agent's base, baseline)
    deduplicated_declarations: list[str] = []

    frame_skel = (
        _function_frame_skeleton(overlay, module, norm_c_file, function) if role == "prover" and function else None
    )

    for rel_str in changed_rels:
        try:
            curr_file = shared_work / rel_str
            base_file = scratch_base / rel_str
            agent_file = scratch_work / rel_str
            baseline_file = baseline_dir / rel_str
            if not baseline_file.is_file():
                raise ScopeViolationError(f"{rel_str}: new files cannot be added by overlays; file not in baseline")
            if not curr_file.is_file():
                raise ScopeViolationError(f"{rel_str}: file missing from shared work tree")
            if not base_file.is_file() or not agent_file.is_file():
                raise ScopeViolationError(f"{rel_str}: file missing from agent scratch")
            base_snap_text = base_file.read_text(encoding="utf-8")
            agent_text = agent_file.read_text(encoding="utf-8")
            curr_text = curr_file.read_text(encoding="utf-8")
            baseline_text = baseline_file.read_text(encoding="utf-8")
            backups[rel_str] = curr_file.read_bytes()
        except (ScopeViolationError, OverlayMergeError, AcslError, ArtifactError):
            raise
        except UnicodeDecodeError as exc:
            raise OverlayMergeError(f"{rel_str}: file is not valid UTF-8: {exc}") from exc
        except OSError as exc:
            raise OverlayMergeError(f"{rel_str}: failed reading file: {exc}") from exc

        # Check ACSL-only against baseline first
        acsl_errs = verify_acsl_only(baseline_text, agent_text, path=rel_str)
        if acsl_errs:
            raise AcslError(f"ACSL-only check failed on {rel_str}:\n  " + "\n  ".join(acsl_errs))

        is_hdr = rel_str.endswith(".h")
        if role == "architect":
            if curr_text != base_snap_text:
                spliced = splice_architect_header(
                    base_text=base_snap_text,
                    agent_text=agent_text,
                    current_text=curr_text,
                    path=rel_str,
                )
            else:
                spliced = agent_text
        else:
            spliced = splice_prover_changes(
                base_work_text=base_snap_text,
                agent_work_text=agent_text,
                current_work_text=curr_text,
                function_name=function or "",
                is_header=is_hdr,
                path=rel_str,
                contract_only=contract_only,
            )

        if is_hdr:
            # 1. Detect conflicting predicate profiles across headers and acsl_vocabulary.h
            all_existing = _collect_all_header_declarations_with_metadata(shared_work, {rel_str})
            curr_decls = extract_top_level_acsl_declarations(spliced, path=rel_str)
            conflicts = check_conflicting_acsl_profiles(curr_decls, all_existing, source_path=rel_str)
            if conflicts:
                raise ConflictingProfileError(
                    f"Conflicting ACSL profile(s) detected during merge of {rel_str}:\n  " + "\n  ".join(conflicts)
                )

            # 2. Deduplicate ONLY declarations in acsl_vocabulary.h or transitively included headers
            existing_names = _collect_in_scope_header_declarations(shared_work, rel_str, header_text=spliced)
            spliced, removed_decls = dedup_acsl_declarations(
                spliced,
                existing_names,
                baseline_text=baseline_text,
                path=rel_str,
            )
            for dname in removed_decls:
                if dname not in deduplicated_declarations:
                    deduplicated_declarations.append(dname)

        # Verify merged text against baseline
        merged_errs = verify_acsl_only(baseline_text, spliced, path=rel_str)
        if merged_errs:
            raise AcslError(f"Merged ACSL-only check failed on {rel_str}:\n  " + "\n  ".join(merged_errs))
        new_contents[rel_str] = spliced
        texts_before[rel_str] = (agent_text, base_snap_text, baseline_text)

    contract_changes: dict | None = None
    if role == "prover" and function:
        # The contract the shared tree holds now against the one this merge leaves: an `assigns` clause may be
        # tightened or rewritten, never deleted (libmodbus run-1, modbus_write_register).
        contract_changes = contract_change(
            shared_work,
            _frame_contract_files(
                run_dir, overlay, norm_c_file, function, norm_header_file, module, header_flags, [*new_contents]
            ),
            new_contents,
            function,
        )
        contract_refusal = _contract_refusal(contract_changes)
        if contract_refusal:
            raise AcslError(contract_refusal)
    elif role == "architect" and new_contents:
        # Check every function declared in the modified header so an architect cannot delete an existing `assigns`.
        contract_changes, arch_errors = _architect_contract_changes(shared_work, [*new_contents], new_contents)
        if arch_errors:
            raise AcslError(f"{FRAME_REFUSAL}:\n  " + "\n  ".join(arch_errors))
    baseline_had_assigns = (
        _has_whole_frame(contract_changes, "baseline") if role == "prover" and contract_changes is not None else None
    )

    if frame_skel is not None:
        frame_refusal = _frame_refusal(
            frame_skel, run_dir, overlay, norm_c_file, function, norm_header_file, module, header_flags, new_contents
        )
        if frame_refusal:
            raise AcslError(frame_refusal)

    entry_metas = _untrusted_entry_metas(overlay, module, function, norm_c_file)
    if entry_metas:
        # On an untrusted_surface entry, `requires` may state memory shape only: a value constraint on
        # attacker-controlled bytes or lengths would define the bug away (docs/guides/v2-design.md §6).
        # A link unit has one entry per harness: every one of them is checked.
        tb_errs: list[str] = []
        for entry_meta in entry_metas:
            for rel_str in changed_rels:
                for err in entry_trust_boundary_errors(
                    entry_meta, rel_str, new_contents[rel_str], *texts_before[rel_str]
                ):
                    if err not in tb_errs:
                        tb_errs.append(err)
        if tb_errs:
            raise TrustBoundaryError(
                f"{TRUST_BOUNDARY_REASON} (untrusted_surface entry requires):\n  " + "\n  ".join(tb_errs)
            )

    patch_stem = function if role == "prover" and function else Path(norm_header_file or "header").stem
    patch_path = artifacts_dir / f"{patch_stem}.patch"

    reverifies = not skip_reverify and verify_hook is None
    if reverifies and module and not sources:
        # An API caller that passed no sources (wp_scheduler, the proof-carry replay) gets the module's own, as
        # merge-agent and the batch do: the guardrail must not be skipped because nobody looked them up.
        side_sources = merged_sidecar(module_map_for(overlay), module).get("sources")
        if isinstance(side_sources, list):
            sources = [str(s) for s in side_sources if isinstance(s, str) and s] or None

    # The contract this merge replaces, read before the splice is written: the merge re-check compares
    # the merged contract against it (record_contract_refinement).
    previous_contract = (
        _merged_contract(shared_work, norm_c_file, function, cppflags) if role == "prover" and changed_rels else None
    )

    if journal:
        _write_merge_journal(run_dir, f"merge-agent:{agent_id}", backups)
    try:
        # Write spliced contents to workspace/work/
        for rel_str, text in new_contents.items():
            (shared_work / rel_str).write_text(text, encoding="utf-8")

        # Parent-side re-verification on the merged workspace/work/ tree
        if not skip_reverify:
            if verify_hook is not None:
                ok, reason = verify_hook()
            elif allow_partial_wp:
                ok, reason = _run_parent_reverify(
                    run_dir,
                    agent_id,
                    role,
                    overlay,
                    norm_c_file,
                    function,
                    module,
                    sources,
                    cppflags,
                    ldflags=ldflags,
                    allow_partial_wp=True,
                )
            else:
                reverify_kwargs: dict[str, Any] = {
                    "ldflags": ldflags,
                }
                if baseline_had_assigns is not None and _supports_kwarg(_run_parent_reverify, "baseline_had_assigns"):
                    reverify_kwargs["baseline_had_assigns"] = baseline_had_assigns
                if wp_extra_sources is not None and _supports_kwarg(_run_parent_reverify, "wp_extra_sources"):
                    reverify_kwargs["wp_extra_sources"] = wp_extra_sources
                if role == "architect" and norm_header_file:
                    # The module guardrail checks the header's functions: a failure in other code is
                    # excused as outside them, never this contract's code_fault (mpack run-4).
                    arch_fns = header_function_names(
                        new_contents.get(norm_header_file)
                        or (shared_work / norm_header_file).read_text(encoding="utf-8", errors="replace"),
                        norm_header_file,
                    )
                    if arch_fns and _supports_kwarg(_run_parent_reverify, "reach_functions"):
                        reverify_kwargs["reach_functions"] = arch_fns
                try:
                    ok, reason = _run_parent_reverify(
                        run_dir,
                        agent_id,
                        role,
                        overlay,
                        norm_c_file,
                        function,
                        module,
                        sources,
                        cppflags,
                        **reverify_kwargs,
                    )
                except TypeError as exc:
                    if "wp_extra_sources" in str(exc) and "wp_extra_sources" in reverify_kwargs:
                        reverify_kwargs.pop("wp_extra_sources", None)
                        ok, reason = _run_parent_reverify(
                            run_dir,
                            agent_id,
                            role,
                            overlay,
                            norm_c_file,
                            function,
                            module,
                            sources,
                            cppflags,
                            **reverify_kwargs,
                        )
                    else:
                        raise
            if not ok:
                for rel_str, raw in backups.items():
                    (shared_work / rel_str).write_bytes(raw)
                if journal:
                    _clear_merge_journal(run_dir)
                if patch_path.is_file():
                    try:
                        patch_path.unlink()
                    except OSError:
                        pass
                return {
                    "ok": False,
                    "rolled_back": True,
                    "agent_id": agent_id,
                    "modified_files": changed_rels,
                    "deduplicated_declarations": deduplicated_declarations,
                    "reason": reason,
                }
    except BaseException:
        for rel_str, raw in backups.items():
            (shared_work / rel_str).write_bytes(raw)
        if journal:
            _clear_merge_journal(run_dir)
        raise
    if journal:
        _clear_merge_journal(run_dir)

    # Export unified diff of the agent's change to agents/<agent-id>/artifacts/
    diff_chunks: list[str] = []
    for rel_str in changed_rels:
        before_lines = backups[rel_str].decode("utf-8", errors="replace").splitlines(keepends=True)
        after_lines = new_contents[rel_str].splitlines(keepends=True)
        udiff = list(
            difflib.unified_diff(
                before_lines,
                after_lines,
                fromfile=f"a/{rel_str}",
                tofile=f"b/{rel_str}",
            )
        )
        if udiff:
            diff_chunks.append("".join(udiff))

    patch_path.write_text("\n".join(diff_chunks), encoding="utf-8")

    result = {
        "ok": True,
        "rolled_back": False,
        "agent_id": agent_id,
        "modified_files": changed_rels,
        "deduplicated_declarations": deduplicated_declarations,
        "patch_artifact": patch_path.relative_to(run_dir).as_posix(),
    }
    if contract_changes is not None:
        result["contract_changes"] = contract_changes
    # Whether the dual-oracle guardrail ran is part of the result: a merge on WP alone never looks like a pass.
    if skip_reverify:
        result["guardrail"] = guardrail_not_run("the caller skipped the parent re-check (skip_reverify)")
    elif verify_hook is not None:
        result["guardrail"] = guardrail_not_run("the caller's verify hook replaced the parent re-check")
    else:
        result["guardrail"] = _guardrail_outcome(run_dir, agent_id, function, module, sources)
    if role == "prover" and function and not skip_reverify and verify_hook is None:
        # The report to ingest: written for this agent only, so same-named functions never collide.
        result["parent_wp_report"] = _parent_wp_report_rel(agent_id, function)
        _note_frame_state(run_dir, result)
        if norm_c_file and changed_rels:
            refinement = record_contract_refinement(
                run_dir, overlay, agent_id, norm_c_file, function, cppflags, previous_contract
            )
            if refinement is not None:
                result["contract_refinement"] = refinement
    elif role == "prover" and skip_reverify and previous_contract is not None:
        # A batch splice: the batch re-check runs the comparison once its round passes.
        result["previous_contract"] = previous_contract.to_dict()
    return result


def _note_frame_state(run_dir: Path, result: dict) -> None:
    """
    Add `frame_state` to a prover's merge result: what its parent WP report says about the function's frame
    (`assigns_clause`: present | behaviors_only | absent | unknown, and `assigns_vcs_proven`) and whether the
    contract it replaced had a whole-function `assigns` frame. A function merged without a frame is visible here.
    """
    report = load_json_optional(run_dir / str(result.get("parent_wp_report") or ""), {})
    frame = report.get("frame_summary") if isinstance(report, dict) else None
    if not isinstance(frame, dict) or "assigns_clause" not in frame:
        return
    changes = result.get("contract_changes")
    result["frame_state"] = {
        "assigns_clause": frame.get("assigns_clause"),
        "assigns_vcs_proven": frame.get("assigns_vcs_proven"),
        "baseline_had_assigns": _has_whole_frame(changes, "baseline") if isinstance(changes, dict) else False,
    }


def single_merge_build_inputs(
    overlay: Path,
    module: str | None,
    sources: list[str] | None,
    cppflags: str | None,
    ldflags: str | None,
    reverify: bool = True,
) -> tuple[list[str] | None, str, str]:
    """
    (sources, cppflags, ldflags) for one `merge-agent` call: what the caller passed, else the
    module's merged harness sidecar (as `_enrich_batch_entry` does for a batch), else `-I.` and no
    sources. A merge that re-verifies with `module` but resolves no sources is refused: the parent
    re-check would otherwise skip the E-ACSL guardrail without saying so (QCBOR run-6).
    """
    hmeta: dict = merged_sidecar(module_map_for(Path(overlay)), module) if module else {}
    side_sources = hmeta.get("sources")
    out_sources = sources or (
        [str(s) for s in side_sources if isinstance(s, str) and s] if isinstance(side_sources, list) else None
    )
    out_sources = out_sources or None
    out_cppflags = cppflags or str(hmeta.get("cppflags") or "") or "-I."
    out_ldflags = ldflags if ldflags is not None else str(hmeta.get("ldflags") or "")
    if module and reverify and not out_sources:
        raise ArtifactError(
            f"merge-agent --module {module}: no harness sources found for the module, so the parent "
            "re-check cannot run the E-ACSL guardrail; pass --sources (and --cppflags) explicitly"
        )
    return out_sources, out_cppflags, out_ldflags


def _enrich_batch_entry(
    run_dir: Path,
    overlay: Path,
    raw_entry: dict,
    default_role: str | None,
    default_module: str | None,
    default_sources: list[str] | None,
    default_cppflags: str | None,
    default_ldflags: str,
    default_wp_extra_sources: list[str] | None = None,
) -> dict:
    entry = dict(raw_entry)
    agent_id = entry["agent_id"]
    res_path = run_dir / "agents" / agent_id / "scratch" / "result.json"
    agent_res: dict = {}
    if res_path.is_file():
        try:
            agent_res = load_agent_result_json(res_path)
        except Exception:
            agent_res = {}

    role = entry.get("role") or agent_res.get("role") or default_role
    c_file = entry.get("file") or entry.get("c_file") or agent_res.get("file")
    function = entry.get("function") or agent_res.get("function")
    header_file = entry.get("header") or entry.get("header_file") or agent_res.get("header")
    module = entry.get("module") or default_module

    scratch_base = run_dir / "agents" / agent_id / "scratch" / "base"
    scratch_work = run_dir / "agents" / agent_id / "scratch" / "work"
    if scratch_base.is_dir() and scratch_work.is_dir():
        changed = _collect_changed_files(scratch_base, scratch_work)
        if role == "architect" and not header_file:
            hdrs = [c for c in changed if c.endswith(".h")]
            if len(hdrs) == 1:
                header_file = hdrs[0]
        elif role == "prover" and not c_file:
            cs = [c for c in changed if c.endswith(".c")]
            if len(cs) == 1:
                c_file = cs[0]

    if not module and function:
        # Match by file and function: static functions in different files can share a name.
        ledger_units = load_json_optional(run_dir / "coverage-ledger.json", [])
        norm_c = _normalize_work_relpath(c_file) if c_file else None
        matches = [
            u
            for u in ledger_units
            if u.get("function") == function
            and (norm_c is None or _normalize_work_relpath(u.get("file") or "") == norm_c)
        ]
        if len({_normalize_work_relpath(u.get("file") or "") for u in matches}) == 1:
            module = matches[0].get("module")
            if not c_file:
                c_file = matches[0].get("file")

    mm = module_map_for(overlay)
    hmeta: dict = merged_sidecar(mm, module) if module else {}
    sources = entry.get("sources") or default_sources or hmeta.get("sources")
    cppflags = entry.get("cppflags") or default_cppflags or hmeta.get("cppflags") or "-I."
    if role == "prover" and not header_file and isinstance(hmeta, dict) and hmeta.get("header"):
        header_file = _prover_header(
            run_dir,
            overlay / "work",
            c_file,
            function,
            str(hmeta["header"]),
            _module_header_flags(overlay, module, cppflags),
        )
    ldflags = (
        entry.get("ldflags") if entry.get("ldflags") is not None else (default_ldflags or hmeta.get("ldflags") or "")
    )
    wp_extra_sources = entry.get("wp_extra_sources") or default_wp_extra_sources
    if wp_extra_sources is None and module:
        for pfile in (overlay / "build" / "params.json", run_dir / "workspace" / "build" / "params.json"):
            if pfile.is_file():
                try:
                    pdata = json.loads(pfile.read_text(encoding="utf-8"))
                    wp_extra_sources = module_param(pdata.get("modules", {}), mm, module, "wp_extra_sources")
                    if wp_extra_sources is not None:
                        break
                except Exception:
                    pass

    return {
        "agent_id": agent_id,
        "role": role,
        "c_file": c_file,
        "function": function,
        "header_file": header_file,
        "module": module,
        "sources": sources,
        "cppflags": cppflags,
        "ldflags": ldflags,
        "wp_extra_sources": wp_extra_sources,
    }


def _batch_touched_files(run_dir: Path, entries: list[dict]) -> list[str]:
    touched: set[str] = set()
    for e in entries:
        aid = e.get("agent_id") or ""
        if not is_safe_agent_id(aid):
            continue
        scratch = run_dir / "agents" / aid / "scratch"
        if (scratch / "base").is_dir() and (scratch / "work").is_dir():
            touched.update(_collect_changed_files(scratch / "base", scratch / "work"))
    return sorted(touched)


def merge_agent_batch(
    run_dir: Path,
    entries: list[dict],
    overlay_dir: Path | None = None,
    cppflags: str | None = None,
    ldflags: str = "",
    skip_reverify: bool = False,
    verify_hook: Callable[[dict], tuple[bool, str]] | None = None,
    default_role: str | None = None,
    default_module: str | None = None,
    default_sources: list[str] | None = None,
    default_wp_extra_sources: list[str] | None = None,
    wp_extra_sources: list[str] | None = None,
) -> dict:
    """
    Merge a batch of architect or prover overlays onto `workspace/work/`, deduplicating
    shared ACSL declarations across headers and re-checking the combined tree in parallel
    within the job budget: one E-ACSL guardrail per unique module build and one WP run per
    prover. Overlays whose checks fail are rejected, the pre-batch snapshot is restored and
    the passing subset re-spliced and re-verified until a round passes (`bisected`); overlays
    of a module whose shared guardrail failed are then retried one by one on the result.
    Holds the `merge` lock and journals the pre-batch contents of every touched file.
    """
    run_dir = Path(run_dir).resolve()
    with run_lock("merge", run_dir):
        recovered = recover_merge_journal(run_dir, overlay_dir)
        shared_work = (overlay_dir or (run_dir / "workspace")).resolve() / "work"
        journal_backups = {
            rel: (shared_work / rel).read_bytes()
            for rel in _batch_touched_files(run_dir, entries)
            if (shared_work / rel).is_file()
        }
        owner = "merge-batch:" + ",".join(str(e.get("agent_id")) for e in entries)
        _write_merge_journal(run_dir, owner, journal_backups)
        try:
            res = _merge_agent_batch_locked(
                run_dir,
                entries,
                overlay_dir,
                cppflags,
                ldflags,
                skip_reverify,
                verify_hook,
                default_role,
                default_module,
                default_sources,
                default_wp_extra_sources=default_wp_extra_sources or wp_extra_sources,
            )
        except BaseException:
            for rel_str, raw in journal_backups.items():
                (shared_work / rel_str).write_bytes(raw)
            _clear_merge_journal(run_dir)
            raise
        _clear_merge_journal(run_dir)
        if recovered:
            res["recovered_journal"] = recovered
        return res


def _splice_batch(run_dir: Path, overlay: Path, items: list[dict]) -> tuple[list[tuple[dict, dict]], list[dict]]:
    """Splice each item onto workspace/work/ without verification; (spliced (item, result), failures)."""
    spliced: list[tuple[dict, dict]] = []
    failures: list[dict] = []
    for item in items:
        try:
            res = merge_agent_overlay(
                run_dir=run_dir,
                agent_id=item["agent_id"],
                role=item["role"] or "",
                overlay_dir=overlay,
                c_file=item["c_file"],
                function=item["function"],
                header_file=item["header_file"],
                module=item["module"],
                sources=item["sources"],
                cppflags=item["cppflags"],
                ldflags=item["ldflags"],
                skip_reverify=True,
                journal=False,
                wp_extra_sources=item.get("wp_extra_sources"),
            )
            # For the parent WP check of this item: whether the contract it replaces had a whole-function frame.
            changes = res.get("contract_changes")
            item["baseline_had_assigns"] = (
                _has_whole_frame(changes, "baseline")
                if item.get("role") == "prover" and isinstance(changes, dict)
                else None
            )
            spliced.append((item, res))
        except (OverlayMergeError, AcslError, ScopeViolationError, ArtifactError, UnicodeDecodeError, OSError) as exc:
            failures.append(
                {
                    "ok": False,
                    "rolled_back": True,
                    "agent_id": item.get("agent_id"),
                    "reason": str(exc),
                }
            )
    return spliced, failures


def _verify_batch_round(
    run_dir: Path,
    overlay: Path,
    items: list[dict],
    verify_hook: Callable[[dict], tuple[bool, str]] | None,
) -> list[tuple[list[int], str, bool]]:
    """
    Re-check the spliced tree: one guardrail per unique module build and one WP run per prover,
    run in parallel with workers = min(checks, CPUs) and `-wp-par` = CPUs // workers each.
    Returns the failed checks as (indices of the implicated items, reason, whether the check is a
    module-wide guardrail, which can fail on code none of the implicated items changed).
    """
    if verify_hook is not None:
        failures: list[tuple[list[int], str, bool]] = []
        for i, item in enumerate(items):
            item["guardrail"] = guardrail_not_run("the caller's verify hook replaced the parent re-check")
            ok, reason = verify_hook(item)
            if not ok:
                failures.append(([i], reason, False))
        return failures

    checks: list[tuple[list[int], dict]] = []
    modules: dict[tuple[str, tuple[str, ...], str, str], list[int]] = {}
    for i, item in enumerate(items):
        # Each item's merge result says whether a guardrail checked it (`guardrail`); a module without
        # harness sources has none, and its items say so instead of looking like the others.
        gap = _guardrail_gap(item.get("module"), item.get("sources"))
        item["guardrail"] = guardrail_not_run(gap or "the batch's module guardrail left no report for this item")
        if not gap:
            mod_key = (item["module"], tuple(item["sources"]), item["cppflags"], item["ldflags"])
            modules.setdefault(mod_key, []).append(i)
    # The module guardrail measures the reach of the batch's prover functions, as the single
    # merge-agent path does per function, so their proofs record `limits.dynamic_oracle`.
    reach_by_check: dict[int, list[int]] = {}
    for (mod, srcs, cpp, ld), idxs in modules.items():
        provers = [i for i in idxs if _is_prover_check_item(items[i])]
        # An architect's header functions are checked too (mpack run-4: a known defect in `main` was
        # otherwise the architect's code_fault).
        arch_fns = {
            fn
            for i in idxs
            if items[i].get("role") == "architect"
            for fn in _header_functions_of(run_dir, overlay, mod, items[i].get("header_file"), cpp)
        }
        mod_kwargs: dict[str, Any] = {
            "agent_id": items[idxs[0]]["agent_id"],
            "role": "architect",
            "c_file": None,
            "function": None,
            "module": mod,
            "sources": list(srcs),
            "cppflags": cpp,
            "ldflags": ld,
        }
        if provers or arch_fns:
            mod_kwargs["reach_functions"] = sorted({items[i]["function"] for i in provers} | arch_fns)
        if provers:
            reach_by_check[len(checks)] = provers
        checks.append((idxs, mod_kwargs))
    prover_check: dict[int, int] = {}
    for i, item in enumerate(items):
        if _is_prover_check_item(item):
            prover_check[i] = len(checks)
            chk_kwargs: dict[str, Any] = {
                "agent_id": item["agent_id"],
                "role": "prover",
                "c_file": item["c_file"],
                "function": item["function"],
                "module": None,
                "sources": None,
                "cppflags": item["cppflags"],
                "ldflags": item["ldflags"],
            }
            if item.get("wp_extra_sources") is not None:
                chk_kwargs["wp_extra_sources"] = item["wp_extra_sources"]
            if item.get("baseline_had_assigns") is not None:
                chk_kwargs["baseline_had_assigns"] = item["baseline_had_assigns"]
            # This check runs WP only. The report keeps this note unless the module guardrail of the batch
            # passes and `_record_batch_reach` writes its result over it.
            chk_kwargs["guardrail_note"] = item["guardrail"]
            checks.append(
                (
                    [i],
                    chk_kwargs,
                )
            )
    if not checks:
        return []

    budget = job_budget()
    cpus = max(1, budget.cpus)
    wp_min_mem = FRAMAC_KERNEL_RESERVE_MB + WP_MEMLIMIT_MB
    has_guardrail = any(kwargs.get("module") and kwargs.get("sources") for _, kwargs in checks)
    req_mem_per_worker = max(wp_min_mem, FUZZ_MIN_MEMORY_MB) if has_guardrail else wp_min_mem
    workers_by_mem = max(1, budget.mem_mb // req_mem_per_worker)
    workers = max(1, min(len(checks), cpus, workers_by_mem))
    per_worker_budget = Budget(
        cpus=max(1, cpus // workers),
        mem_mb=max(256, budget.mem_mb // workers),
        source=budget.source,
    )
    wp_par = wp_parallelism(per_worker_budget)

    def _check(kwargs: dict) -> tuple[bool, str]:
        call_kwargs = dict(kwargs)
        if call_kwargs.get("wp_extra_sources") is None or not _supports_kwarg(_run_parent_reverify, "wp_extra_sources"):
            call_kwargs.pop("wp_extra_sources", None)
        for optional in ("reach_functions", "baseline_had_assigns", "guardrail_note"):
            if optional in call_kwargs and not _supports_kwarg(_run_parent_reverify, optional):
                call_kwargs.pop(optional, None)
        try:
            return _run_parent_reverify(run_dir=run_dir, overlay_dir=overlay, wp_par=wp_par, **call_kwargs)
        except TypeError as exc:
            if "wp_extra_sources" in str(exc) and "wp_extra_sources" in call_kwargs:
                call_kwargs.pop("wp_extra_sources", None)
                return _run_parent_reverify(run_dir=run_dir, overlay_dir=overlay, wp_par=wp_par, **call_kwargs)
            raise

    pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="parent-recheck")
    try:
        futures = [pool.submit(_check, kwargs) for _, kwargs in checks]
        outcomes = [f.result() for f in futures]
    except BaseException:
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    pool.shutdown(wait=True)
    for (idxs, kwargs), (ok, _reason) in zip(checks, outcomes, strict=True):
        if ok and kwargs.get("module") and kwargs.get("sources"):
            outcome = _guardrail_outcome(run_dir, kwargs["agent_id"], None, kwargs["module"], kwargs["sources"])
            for i in idxs:
                items[i]["guardrail"] = outcome
    for ci, prover_idxs in reach_by_check.items():
        if not outcomes[ci][0]:
            continue
        mod_kwargs = checks[ci][1]
        guard_json = _parent_guard_json(run_dir, mod_kwargs["agent_id"], None, mod_kwargs["module"])
        guard_report = load_json_optional(guard_json, {})
        if not isinstance(guard_report, dict) or guard_report.get("status") != "passed_dynamic_oracle":
            continue
        for i in prover_idxs:
            if outcomes[prover_check[i]][0]:
                _record_batch_reach(run_dir, overlay, items[i], guard_report)
    return [
        (idxs, reason, bool(kwargs["module"]))
        for (idxs, kwargs), (ok, reason) in zip(checks, outcomes, strict=True)
        if not ok
    ]


def _is_prover_check_item(item: dict) -> bool:
    return item.get("role") == "prover" and bool(item.get("c_file")) and bool(item.get("function"))


def _rejected_result(item: dict, splice_res: dict, reason: str) -> dict:
    return {
        "ok": False,
        "rolled_back": True,
        "agent_id": item["agent_id"],
        "modified_files": splice_res.get("modified_files", []),
        "deduplicated_declarations": splice_res.get("deduplicated_declarations", []),
        "reason": reason,
    }


def _drop_patch(run_dir: Path, splice_res: dict) -> None:
    rel = splice_res.get("patch_artifact")
    if rel:
        try:
            (run_dir / rel).unlink()
        except OSError:
            pass


def _merge_agent_batch_locked(
    run_dir: Path,
    entries: list[dict],
    overlay_dir: Path | None,
    cppflags: str | None,
    ldflags: str,
    skip_reverify: bool,
    verify_hook: Callable[[dict], tuple[bool, str]] | None,
    default_role: str | None,
    default_module: str | None,
    default_sources: list[str] | None,
    default_wp_extra_sources: list[str] | None = None,
) -> dict:
    run_dir = run_dir.resolve()
    overlay = (overlay_dir or (run_dir / "workspace")).resolve()
    shared_work = overlay / "work"
    if not shared_work.is_dir():
        raise ArtifactError(f"shared work directory does not exist: {shared_work}")

    enriched = [
        _enrich_batch_entry(
            run_dir,
            overlay,
            e,
            default_role=default_role,
            default_module=default_module,
            default_sources=default_sources,
            default_cppflags=cppflags,
            default_ldflags=ldflags,
            default_wp_extra_sources=default_wp_extra_sources,
        )
        for e in entries
    ]

    # Snapshot every file a splice may touch, before any splicing
    batch_backups: dict[str, bytes] = {
        rel: (shared_work / rel).read_bytes()
        for rel in _batch_touched_files(run_dir, entries)
        if (shared_work / rel).is_file()
    }

    def _restore_snapshot() -> None:
        for rel_str, raw in batch_backups.items():
            path = shared_work / rel_str
            if not path.is_file() or path.read_bytes() != raw:
                path.write_bytes(raw)

    spliced_entries, failed_results = _splice_batch(run_dir, overlay, enriched)

    def _dedup_union(results: list[dict]) -> list[str]:
        names: list[str] = []
        for r in results:
            for d in r.get("deduplicated_declarations", []):
                if d not in names:
                    names.append(d)
        return names

    if skip_reverify or not spliced_entries:
        merged_results = [r for _, r in spliced_entries]
        for r in merged_results:
            r.pop("previous_contract", None)
        return {
            "ok": len(failed_results) == 0,
            "batch_verified": not skip_reverify,
            "bisected": False,
            "merged": merged_results,
            "failed": failed_results,
            "deduplicated_declarations": _dedup_union(merged_results),
        }

    # Verify the combined tree. Failed checks reject the overlays they implicate, or defer them to a
    # retry alone; the snapshot is restored, the rest re-spliced and re-verified, until a round
    # passes (a fixpoint: dropping a callee's contract can break a caller's proof). Every failing
    # round removes at least one overlay, so this ends within len(spliced_entries) + 1 rounds.
    active = spliced_entries
    deferred: list[tuple[dict, str]] = []
    bisected = False
    batch_fail_reason = ""
    rounds = 0
    while active:
        rounds += 1
        failures = _verify_batch_round(run_dir, overlay, [item for item, _ in active], verify_hook)
        if not failures:
            break
        bisected = True
        batch_fail_reason = batch_fail_reason or failures[0][1]
        hard: dict[int, str] = {}
        ambiguous: dict[int, str] = {}
        for idxs, reason, module_wide in failures:
            for i in idxs:
                (ambiguous if module_wide else hard).setdefault(i, reason)
        for i in hard:
            ambiguous.pop(i, None)
        for i, reason in hard.items():
            item, res = active[i]
            failed_results.append(_rejected_result(item, res, reason))
            _drop_patch(run_dir, res)
        for i, reason in ambiguous.items():
            # A module guardrail failed: it also checks code the overlays did not change, so none can
            # be blamed yet, however many there are. Each is retried alone on the converged tree.
            deferred.append((active[i][0], reason))
            _drop_patch(run_dir, active[i][1])
        remaining = [item for i, (item, _) in enumerate(active) if i not in hard and i not in ambiguous]
        _restore_snapshot()
        active, splice_failures = _splice_batch(run_dir, overlay, remaining)
        failed_results.extend(splice_failures)

    merged_results = []
    for item, r in active:
        # The splice ran without a re-check; the batch's own checks are what this item's guardrail status is.
        r["guardrail"] = item.get("guardrail") or guardrail_not_run("the batch ran no check for this item")
        raw_previous = r.pop("previous_contract", None)
        if verify_hook is None and item["role"] == "prover" and item.get("function"):
            r["parent_wp_report"] = _parent_wp_report_rel(item["agent_id"], item["function"])
            _note_frame_state(run_dir, r)
            if item.get("c_file") and r.get("modified_files"):
                previous = (
                    contract_refinement.FunctionContract.from_dict(raw_previous)
                    if isinstance(raw_previous, dict)
                    else None
                )
                refinement = record_contract_refinement(
                    run_dir,
                    overlay,
                    item["agent_id"],
                    _normalize_work_relpath(item["c_file"]),
                    item["function"],
                    item["cppflags"],
                    previous,
                )
                if refinement is not None:
                    r["contract_refinement"] = refinement
        merged_results.append(r)

    for item, batch_reason in deferred:
        indiv_hook = (lambda it=item: verify_hook(it)) if verify_hook is not None else None
        res = merge_agent_overlay(
            run_dir=run_dir,
            agent_id=item["agent_id"],
            role=item["role"] or "",
            overlay_dir=overlay,
            c_file=item["c_file"],
            function=item["function"],
            header_file=item["header_file"],
            module=item["module"],
            sources=item["sources"],
            cppflags=item["cppflags"],
            ldflags=item["ldflags"],
            skip_reverify=False,
            verify_hook=indiv_hook,
            journal=False,
            wp_extra_sources=item.get("wp_extra_sources"),
        )
        if res["ok"]:
            merged_results.append(res)
        else:
            res["batch_failure_reason"] = batch_reason
            failed_results.append(res)

    result = {
        "ok": len(failed_results) == 0,
        "batch_verified": True,
        "bisected": bisected,
        "rounds": rounds,
        "merged": merged_results,
        "failed": failed_results,
        "deduplicated_declarations": _dedup_union(merged_results),
    }
    if bisected:
        result["batch_failure_reason"] = batch_fail_reason
    return result


def _brief_path(value: str) -> str:
    """Briefs embed paths inside double quotes; a quote in the value would break the command."""
    return str(value).replace('"', "")


# Every brief carries one shared "How to run commands" section (skills/framac-wp/run_commands.md): the
# subagents run on the host and reach the container only through the wrapper, with host paths.
RUN_COMMANDS_SENTINEL = "<!-- run-commands -->"
RUN_COMMANDS_FRAGMENT = "run_commands.md"


def _pipeline_host_dir(references_host: str) -> str:
    """Host path of the pipeline checkout, from the host path of its docs/references (mixed separators on Windows)."""
    root = re.sub(r"[\\/]+docs[\\/]+references[\\/]*$", "", references_host)
    return root if root != references_host else str(Path(__file__).resolve().parent.parent)


def _resolve_brief_template(role: str) -> str:
    filename_map = {
        "architect": "header_architect_brief.md",
        "prover": "prover_brief.md",
        "breaker": "breaker_brief.md",
        "verifier": "crash_verifier_brief.md",
        "run_commands": RUN_COMMANDS_FRAGMENT,
    }
    fname = filename_map[role]
    here = Path(__file__).resolve().parent
    for base in (here.parent / "skills" / "framac-wp", Path("/opt/framac-pipeline/skills/framac-wp")):
        cand = base / fname
        if cand.is_file():
            return cand.read_text(encoding="utf-8")
    raise ArtifactError(f"brief template {fname} not found in skills/framac-wp")


_FACTS_UNSET = object()


def _prover_context(
    run_dir: Path,
    overlay: Path,
    agent_root: Path,
    agent_id: str,
    module: str | None,
    function: str | None,
    c_file: str | None,
    header: str | None,
    cppflags: str,
    dag_functions: dict,
    *,
    facts_record: Any = _FACTS_UNSET,
) -> tuple[str, dict[str, bool] | None, dict]:
    """
    A prover's deterministic context: (brief section, features selecting the brief's conditional
    parts, summary for the caller). Facts come from `pipeline_make.py run facts`; the slice is built
    here because it must show the contracts in this agent's snapshot. Any problem only means less
    context, and None as features keeps every conditional part of the brief.
    """
    if not function_facts.context_enabled():
        return "", None, {"enabled": False}
    if not (function and c_file):
        return "", None, {"enabled": True, "facts": False, "slice": "no_target"}
    work_dir = agent_root / "scratch" / "work"
    context_dir = agent_root / "scratch" / "context"
    record = (
        _load_function_facts(overlay, module, c_file, function)
        if facts_record is _FACTS_UNSET
        else (facts_record if isinstance(facts_record, dict) else None)
    )
    slice_result = function_slice.build_slice(
        run_dir,
        work_dir,
        c_file,
        function,
        f"-Iagents/{agent_id}/scratch/work {cppflags}",
        out_dir=context_dir,
        header_file=header,
        dag_functions=dag_functions,
    )
    usable_slice = slice_result if slice_result.get("status") in ("ok", "degraded") else None
    try:
        snapshot = (work_dir / c_file).read_text(encoding="utf-8", errors="replace")
    except OSError:
        snapshot = None
    section = function_facts.render_section(record, usable_slice, snapshot, function)
    features = record.get("features") if record is not None else None
    summary = {
        "enabled": True,
        "facts": record is not None,
        "slice": slice_result.get("status"),
        "slice_reason": slice_result.get("reason"),
        "section_chars": len(section),
    }
    return section, features if isinstance(features, dict) else None, summary


REJECTED_RESULT_MAX_ERRORS = 10
REJECTED_RESULT_MAX_ERROR_CHARS = 300
_REJECTED_RESULT_REUSE = {
    "prover": (
        "Its annotations are in `{prev}work/` (and in its patch, if it wrote one). They were never checked "
        "by the parent: read them as a starting point, write them into your own scratch work tree, and run "
        "both oracles yourself before you write your result. Unchanged goals are answered from the proof cache."
    ),
    "architect": (
        "Its contracts are in `{prev}work/` (and in its patch, if it wrote one). They were never checked by "
        "the parent: read them as a starting point, write them into your own scratch work tree, and run the "
        "syntax check and the guardrail yourself before you write your result."
    ),
    "breaker": (
        "Its seeds, if any, are under `{prev}seeds/`: you may copy them into your own seeds directory, and "
        "must run the campaign yourself."
    ),
    "verifier": "Its replay outputs under `{prev}` may guide you, but reproduce and decide yourself.",
}


CALLEES_WITHOUT_CONTRACT_MAX = 20


def _callees_without_contract_section(callees: list[str] | None, role: str) -> str:
    """
    Appended to a prover's brief when the scheduler dispatched it although some callees have no contract
    its proof can see and none can be obtained (wp_scheduler `callees_without_contract`, `<file>#<name>`
    keys: a crash candidate, an out-of-scope function, or a negotiation that ended without a contract).
    """
    if role != "prover" or not callees:
        return ""
    rows = []
    for key in list(dict.fromkeys(str(c) for c in callees))[:CALLEES_WITHOUT_CONTRACT_MAX]:
        cfile, cname = (re.sub(r"[\s`]+", " ", part).strip() for part in key.rpartition("#")[::2])
        rows.append(f"- `{cname}`" + (f" (`{cfile}`)" if cfile else ""))
    more = len(set(callees)) - len(rows)
    if more > 0:
        rows.append(f"- ... and {more} more")
    return (
        "\n## Calls Without a Contract\n\n"
        "These callees have no ACSL contract your proof can see, and the pipeline could not get one (a crash "
        "candidate, a function out of scope, or a negotiation that ended without a contract):\n\n"
        + "\n".join(rows)
        + "\n\nWP applies its default specification to these calls: they may write anything and guarantee "
        "nothing. Do not assume any postcondition of these calls, do not write a contract for them, and do not "
        "file a strengthening request for them. Prove what holds without them, and list the goals that depend "
        "on their effects in `unproven_goals`.\n"
    )


CALLER_USAGE_MAX_CALLERS = 6
CALLER_USAGE_LINES_AFTER = 4
CALLER_USAGE_MAX_LINE_CHARS = 160


def _call_sites(work_dir: Path, caller_file: str, caller: str, callee: str) -> list[tuple[int, list[str]]]:
    """
    The textual calls of `callee` in the definition of `caller` (`work_dir/caller_file`): for each, its
    1-based line and the source lines from the call line on (at most CALLER_USAGE_LINES_AFTER after it,
    never past the caller's body). Comments, literals and ACSL are not searched. [] when the file or the
    definition cannot be read, or the call is not written by name (a call through a pointer).
    """
    try:
        text = (work_dir / caller_file).read_text(encoding="utf-8", errors="replace")
        span = locate_function_span(text, caller, path=caller_file)
    except (OSError, AcslError):
        return []
    if span is None:
        return []
    body = text[span.start_byte : span.end_byte]
    masked = mask_comments_and_literals(body, acsl="blank", on_error="mask", path=caller_file)
    lines = text.splitlines()
    sites: list[tuple[int, list[str]]] = []
    seen: set[int] = set()
    for match in re.finditer(rf"(?<![A-Za-z0-9_.>]){re.escape(callee)}\s*\(", masked):
        line = span.start_line + masked.count("\n", 0, match.start())
        if line in seen:
            continue
        seen.add(line)
        last = min(line + CALLER_USAGE_LINES_AFTER, span.end_line, len(lines))
        sites.append((line, [lines[i - 1][:CALLER_USAGE_MAX_LINE_CHARS] for i in range(line, last + 1)]))
    return sites


def _caller_usage_section(overlay: Path, function: str | None, fn_meta: dict, dag_fns: dict, role: str) -> str:
    """
    "How the callers use this function" in a prover's brief: for each direct caller in the call-graph
    DAG, its first textual call of `function` and the lines after it, read from `workspace/work/`. A
    function with no caller in the DAG gets a sentence saying it is an entry point. Empty for other roles
    and when the DAG has no record of the function.
    """
    if role != "prover" or not function or not fn_meta:
        return ""
    name = function.rpartition("#")[2]
    callers = [str(c) for c in fn_meta.get("internal_callers") or []]
    head = "\n## How the Callers Use This Function\n\n"
    if not callers:
        return (
            head + f"No function in the analysed code calls `{name}`: it is an API entry point (or reached only "
            "through a function pointer). Its callers are outside the slice, so its contract is what they rely "
            "on: state in `ensures` what the function gives them (the result's range and meaning, the memory "
            "it writes), not only that it runs without errors.\n"
        )
    blocks: list[str] = []
    not_shown = 0
    for key in callers:
        rec = dag_function_record(dag_fns, key)
        cfile = _normalize_work_relpath(str(rec.get("file") or "")) if rec else ""
        cname = str(rec.get("name") or key.rpartition("#")[2]) if rec else key.rpartition("#")[2]
        if len(blocks) >= CALLER_USAGE_MAX_CALLERS:
            not_shown += 1
            continue
        sites = _call_sites(overlay / "work", cfile, cname, name) if cfile else []
        if not sites:
            not_shown += 1
            continue
        line, text = sites[0]
        more = f", and {len(sites) - 1} more call(s) in it" if len(sites) > 1 else ""
        code = "\n".join(text).replace("```", "'''")
        blocks.append(f"`{cname}` (`{cfile}` line {line}{more}):\n\n```c\n{code}\n```\n")
    if blocks:
        out = (
            head
            + f"Where the direct callers of `{name}` call it, and what they do next (from `workspace/work/`):\n\n"
            + "\n".join(blocks)
        )
    else:
        out = head + f"No call of `{name}` by name was found in its callers' code.\n"
    if not_shown:
        out += (
            f"\n{not_shown} caller(s) not shown: over the limit of {CALLER_USAGE_MAX_CALLERS}, or calling "
            "through a pointer or a macro.\n"
        )
    return out


PROVEN_EXAMPLES_MAX = 2
PROVEN_EXAMPLE_MAX_LINES = 30


def _example_candidates(function: str, fn_meta: dict, dag_fns: dict) -> list[tuple[int, str]]:
    """(distance, DAG key) of the functions near `function`: its direct callees (0), then the other callees
    of its direct callers (1), in DAG order, each once and never `function` itself."""
    name = function.rpartition("#")[2]
    out: dict[str, int] = {}
    for key in fn_meta.get("internal_callees") or []:
        out.setdefault(str(key), 0)
    for caller in fn_meta.get("internal_callers") or []:
        for key in dag_function_record(dag_fns, str(caller)).get("internal_callees") or []:
            out.setdefault(str(key), 1)
    return [(d, k) for k, d in out.items() if k.rpartition("#")[2] != name]


def _proven_examples_section(
    overlay: Path, function: str | None, fn_meta: dict, dag_fns: dict, cppflags: str, role: str
) -> str:
    """
    "Proven Contracts Near This Function" in a prover's brief: up to PROVEN_EXAMPLES_MAX contracts of
    functions already `all_proven` in this run (their latest WP report, `load_function_wp_report`), the
    nearest in the call graph first (direct callees, then functions sharing a caller) and, at the same
    distance, a `functional` contract shape before any other. Each contract is inlined as written in
    `workspace/work/`, cut at PROVEN_EXAMPLE_MAX_LINES lines. Empty when none is proven yet.
    """
    if role != "prover" or not function or not fn_meta:
        return ""
    work = overlay / "work"
    found: list[tuple[int, int, str, str, contract_refinement.FunctionContract]] = []
    for order, (distance, key) in enumerate(_example_candidates(function, fn_meta, dag_fns)):
        rec = dag_function_record(dag_fns, key)
        cfile = _normalize_work_relpath(str(rec.get("file") or "")) if rec else ""
        cname = str(rec.get("name") or key.rpartition("#")[2]) if rec else ""
        if not cfile or not cname:
            continue
        report = load_function_wp_report(overlay, cfile, cname)
        if report.get("status") != "all_proven":
            continue
        contract = _merged_contract(work, cfile, cname, cppflags)
        if contract is None or not contract.pieces:
            continue
        shape = str((report.get("limits") or {}).get("contract_shape") or "not recorded")
        found.append((distance * 2 + (shape != "functional"), order, cname, cfile, contract))
    if not found:
        return ""
    found.sort(key=lambda item: item[:2])
    blocks = []
    for _, _, cname, cfile, contract in found[:PROVEN_EXAMPLES_MAX]:
        lines: list[str] = []
        for piece in contract.pieces:
            lines += [*piece.acsl.splitlines(), f"{piece.declarator};"]
        cut = len(lines) - PROVEN_EXAMPLE_MAX_LINES
        if cut > 0:
            lines = [*lines[:PROVEN_EXAMPLE_MAX_LINES], f"/* ... {cut} more line(s) in workspace/work/{cfile} */"]
        code = "\n".join(lines).replace("```", "'''")
        blocks.append(f"`{cname}` (`{cfile}`):\n\n```c\n{code}\n```\n")
    return (
        "\n## Proven Contracts Near This Function\n\n"
        "Contracts this run has already proven (WP `all_proven`) for functions close to yours in the call "
        "graph, as they stand in `workspace/work/`. WP proved them on this code base, so their idioms, "
        "predicates and level of detail are a model to follow. Never copy a clause without checking that it "
        "holds for your function.\n\n" + "\n".join(blocks)
    )


def _rejected_result_section(rejected_result: dict | None, agent_id: str, role: str) -> str:
    """
    Appended to the brief of an agent that re-runs a task whose previous result.json failed validation
    (wp_scheduler `requeued_invalid_result`): the validation errors, so that the new result does not
    repeat them, and where the previous agent's work is. The rejected result itself stays discarded.
    Error texts embed key names the previous agent chose: they are shown as capped JSON strings.
    """
    if not isinstance(rejected_result, dict):
        return ""
    errors = [
        str(e).replace("`", "'")[:REJECTED_RESULT_MAX_ERROR_CHARS]
        for e in (rejected_result.get("errors") or [])[:REJECTED_RESULT_MAX_ERRORS]
    ]
    if not errors:
        return ""
    prev = str(rejected_result.get("agent_id") or "")
    who = f"Agent `{prev}`" if is_safe_agent_id(prev) else "An earlier agent"
    out = (
        "\n## Previous Attempt: Result Rejected\n\n"
        f"{who} already worked on this task. The parent discarded its `result.json`, and with it the whole "
        "attempt, because the file failed validation:\n\n"
        "```json\n" + json.dumps(errors, indent=2) + "\n```\n\n"
        "These are errors of the result file, not of the analysis. Do not repeat them, and run the "
        "validation command of this brief before you return.\n"
    )
    if is_safe_agent_id(prev):
        out += (
            "\n"
            + _REJECTED_RESULT_REUSE[role].format(prev=f"agents/{prev}/scratch/")
            + " Never copy its `result.json` or its reports: your result names your own agent id and only "
            + f"files under `agents/{agent_id}/`.\n"
        )
    return out


def _negotiation_evidence_section(caller_evidence: list[dict] | None, callee_history: dict | None) -> str:
    """
    The seam evidence appended to the Contract Negotiation Requests: why each caller stalled (its
    unproven goals at the call site) and this function's previous prover run. Empty when there is
    neither, so the brief is then unchanged.
    """
    out = ""
    entries = [e for e in caller_evidence or [] if isinstance(e, dict)]
    if entries:
        out += "\n### Why the callers stalled (seam evidence)\n\n"
        for entry in entries:
            report = entry.get("report")
            where = f"report `{report}`" if report else "no WP report found"
            out += f"- `{entry.get('caller')}` (`{entry.get('caller_file')}`, {where}):\n"
            goals = [g for g in entry.get("goals") or [] if isinstance(g, dict)]
            if not goals:
                out += "  - no unproven goal at the call site was recorded\n"
            for g in goals:
                annotation = " ".join(str(g.get("annotation") or "").replace("`", "'").split())
                kind = str(g.get("kind") or "goal")
                prop = f"{kind} `{annotation}`" if annotation else kind
                bucket = g.get("diagnostic_bucket") or "unclassified"
                out += f"  - line {g.get('line')}, {prop}: {g.get('status') or 'Unknown'} (`{bucket}`)\n"
    if callee_history:
        rank = callee_history.get("best_rank")
        # prover_candidates stores best_rank as a dict ({failed, proved, invalid, ...}); older states used a list.
        if isinstance(rank, dict) and rank:
            rank_text = ", ".join(f"{k} {v}" for k, v in rank.items() if v is not None)
        elif isinstance(rank, list | tuple) and rank:
            rank_text = f"({', '.join(str(x) for x in rank)})"
        else:
            rank_text = "none recorded"
        out += (
            "\n### Your function's previous prover run\n\n"
            f"Agent `{callee_history.get('agent_id')}` ran {callee_history.get('iterations')} iterations; "
            f"best rank: {rank_text}; "
            f"last WP status `{callee_history.get('last_wp_status')}`, "
            f"last guardrail `{callee_history.get('last_guardrail_status')}`. "
            "Its scratch is read-only to you; do not copy clauses the guardrail refuted.\n"
        )
    if out:
        out += (
            "\nProve the requested clauses first; if a requested clause is exactly what the caller's goal "
            "needs but cannot hold, say which caller goal would remain open.\n"
        )
    return out


def prepare_agent(
    run_dir: Path,
    agent_id: str,
    role: str,
    overlay_dir: Path | None = None,
    module: str | None = None,
    function: str | None = None,
    c_file: str | None = None,
    header_file: str | None = None,
    max_retries: int = 4,
    candidate_fp: str | None = None,
    cppflags: str | None = None,
    ldflags: str | None = None,
    wp_report: str | None = None,
    requests: list[dict] | None = None,
    caller_evidence: list[dict] | None = None,
    callee_history: dict | None = None,
    rejected_result: dict | None = None,
    eva_unknown_obligations: list[dict] | None = None,
    callees_without_contract: list[str] | None = None,
) -> dict:
    """
    Initialize an agent's scratch directory/overlay and render its populated brief markdown
    file (`agents/<agent-id>/brief.md`) from `callgraph_dag.json`, `coverage-ledger.json`,
    `workspace/harnesses/harness_<mod>.json`, and `workspace/reports/eva/<mod>.json`.

    `wp_report` names the WP report whose unproven goals the brief lists (a breaker gets the
    stalled prover's report); the default is `workspace/reports/wp/<function>.json`.
    `requests` are strengthening requests a negotiating callee prover must answer; they are
    appended to its brief, followed by the seam evidence when given: `caller_evidence` (each
    caller's unproven goals at the call site, from its stalled WP report) and `callee_history`
    (a summary of this function's previous prover run).
    `rejected_result` (`{"agent_id", "errors"}`) is set when this agent re-runs a task whose previous
    result.json failed validation: the brief ends with those errors.
    `callees_without_contract` (`<file>#<name>` keys, from the scheduler) are the prover's callees that
    have no contract and cannot get one: the brief names them.
    """
    if not is_safe_agent_id(agent_id):
        raise ArtifactError(f"invalid canonical agent_id: {agent_id!r}")
    if role not in ("architect", "prover", "breaker", "verifier"):
        raise ArtifactError(f"unsupported role for prepare-agent: {role!r}")

    run_dir = run_dir.resolve()
    overlay = (overlay_dir or (run_dir / "workspace")).resolve()
    agent_root = run_dir / "agents" / agent_id

    overlay_info: dict = {}
    if role in ("architect", "prover"):
        # Snapshot workspace/work/ under the merge lock: never mid-merge, never half-merged.
        with run_lock("merge", run_dir):
            recovered = recover_merge_journal(run_dir, overlay)
            overlay_info = init_agent_overlay(run_dir, agent_id, overlay)
        if recovered:
            overlay_info["recovered_journal"] = recovered
    else:
        (agent_root / "scratch").mkdir(parents=True, exist_ok=True)
        (agent_root / "artifacts").mkdir(parents=True, exist_ok=True)

    run_meta = load_json_optional(run_dir / "run-metadata.json", {})
    dag = load_json_optional(overlay / "reports" / "callgraph_dag.json", {})
    ledger_units = load_json_optional(run_dir / "coverage-ledger.json", [])
    candidates_list = load_json_optional(run_dir / "candidates.json", [])

    dag_fns = dag.get("functions", {}) if isinstance(dag, dict) else {}
    dag_mods = dag.get("modules", {}) if isinstance(dag, dict) else {}

    norm_c_file = _normalize_work_relpath(c_file) if c_file else None
    norm_header = _normalize_work_relpath(header_file) if header_file else None

    fn_meta = dag_function_record(dag_fns, function, norm_c_file)
    if not norm_c_file and fn_meta.get("file"):
        norm_c_file = _normalize_work_relpath(fn_meta["file"])
    if not module and fn_meta.get("module"):
        module = fn_meta["module"]

    def _same_file(unit: dict) -> bool:
        return not norm_c_file or _normalize_work_relpath(unit.get("file") or "") == norm_c_file

    fn_units = [u for u in ledger_units if function and u.get("function") == function and _same_file(u)]
    if fn_units:
        if not norm_c_file and fn_units[0].get("file"):
            norm_c_file = _normalize_work_relpath(fn_units[0]["file"])
            fn_units = [u for u in fn_units if _same_file(u)]
        if not module and fn_units[0].get("module"):
            module = fn_units[0]["module"]

    cand_obj: dict = {}
    if candidate_fp:
        for c in candidates_list:
            if c.get("fingerprint") == candidate_fp:
                cand_obj = c
                if not module and c.get("module"):
                    module = c["module"]
                break

    # A link unit's harnesses (sub-modules): their merged sidecar gives the sources and flags, and
    # each one's entry function and reachability count (see `reachability` below).
    mm = module_map_for(overlay)
    hmeta: dict = merged_sidecar(mm, module) if module else {}
    harness_names = harness_modules_of(mm, module)
    harness_metas = [mm.sidecars[m] for m in harness_names if isinstance(mm.sidecars.get(m), dict)] or (
        [hmeta] if hmeta else []
    )

    if not norm_header:
        if norm_c_file:
            cand_h = Path(norm_c_file).with_suffix(".h").as_posix()
            if (overlay / "work" / cand_h).is_file():
                norm_header = cand_h
        if not norm_header and hmeta.get("header"):
            norm_header = _normalize_work_relpath(hmeta["header"])

    # The brief names one harness: a link unit's sub-module answering for this function (or its
    # header), never the union of the unit's harnesses. `tf_` target-fuzz modules are not candidates.
    harness_module_name = module
    if module:
        if role == "architect":
            harness_module_name = (
                next(
                    (
                        m
                        for m in harness_modules_of(mm, module)
                        if isinstance(mm.sidecars.get(m), dict)
                        and _normalize_work_relpath(str(mm.sidecars[m].get("header") or ""))
                        == _normalize_work_relpath(norm_header or "")
                    ),
                    None,
                )
                or harness_module_for_function(mm, module)
                or module
            )
        elif function and role in ("prover", "breaker"):
            harness_module_name = harness_module_for_function(mm, module, norm_c_file, function) or module
        elif role == "verifier":
            # A hypothesis or Eva candidate may carry its link unit: the harness the parent replays it on
            # (wp_scheduler._verify_harness_module, crash_replay.replay_build_spec) is the one whose scope
            # holds the candidate's location.
            raw_loc = cand_obj.get("location")
            cand_loc: dict = raw_loc if isinstance(raw_loc, dict) else {}
            harness_module_name = (
                harness_module_for_function(
                    mm,
                    module,
                    str(cand_loc.get("file") or norm_c_file or "") or None,
                    str(cand_loc.get("function") or function or "") or None,
                )
                or module
            )
    brief_meta = mm.sidecars.get(harness_module_name) if harness_module_name else None
    if not isinstance(brief_meta, dict) or not brief_meta:
        brief_meta = hmeta

    raw_sources = (
        brief_meta.get("sources")
        or (dag_mods.get(module or "", {}).get("files") if module else [])
        or ([norm_c_file] if norm_c_file else [])
    )
    scratch_sources_list: list[str] = []
    module_sources_list: list[str] = []
    merge_sources_list: list[str] = []
    harness_files = {f"harness_{m}.c" for m in [*([module] if module else []), *harness_names]}
    for raw_s in raw_sources:
        norm_s = (raw_s or "").replace("\\", "/").strip().removeprefix("/framac-run/")
        if not norm_s:
            continue
        if Path(norm_s).name in harness_files:
            continue
        stripped = _normalize_work_relpath(norm_s)
        is_in_work = (
            norm_s.startswith("workspace/work/")
            or (overlay / "work" / stripped).is_file()
            or (not norm_s.startswith("workspace/") and not (run_dir / norm_s).is_file())
        )
        if is_in_work:
            scratch_sources_list.append(f"agents/{agent_id}/scratch/work/{stripped}")
            module_sources_list.append(f"workspace/work/{stripped}")
            merge_sources_list.append(stripped)
        else:
            scratch_sources_list.append(norm_s)
            module_sources_list.append(norm_s)
            merge_sources_list.append(norm_s)
    scratch_sources_str = " ".join(scratch_sources_list)
    module_sources_str = " ".join(module_sources_list)

    eff_cppflags = cppflags if cppflags is not None else (brief_meta.get("cppflags") or "-I.")
    eff_ldflags = ldflags if ldflags is not None else (brief_meta.get("ldflags") or "")

    # The sidecar's header is the name the harness includes; the brief needs the file in the tree.
    header_flags = _module_header_flags(overlay, module, eff_cppflags)
    if role == "prover":
        norm_header = _prover_header(run_dir, overlay / "work", norm_c_file, function, norm_header, header_flags)
    else:
        norm_header = _resolve_include_header(run_dir, overlay / "work", norm_header, header_flags)

    wp_report_rel: str | None = None
    wp_data: dict = {}
    if wp_report:
        wp_report_path = Path(wp_report) if Path(wp_report).is_absolute() else run_dir / wp_report
        wp_data = load_json_optional(wp_report_path, {})
        wp_report_rel = wp_report.replace("\\", "/")
    elif function:
        wp_data = load_function_wp_report(overlay, norm_c_file, function)

    unknown_obligations: list = []
    if eva_unknown_obligations is not None:
        unknown_obligations = list(eva_unknown_obligations) if function else []
    elif function:
        # Eva reports are per harness: only load them when preparing a function-scoped brief,
        # and tolerate oversized or unreadable reports gracefully.
        for name in dict.fromkeys([*([module] if module else []), *harness_names]):
            try:
                eva_report = load_json_optional(
                    overlay / "reports" / "eva" / f"{name}.json",
                    {},
                    max_bytes=EVA_REPORT_MAX_BYTES,
                )
            except ArtifactError:
                continue
            if not isinstance(eva_report, dict) or not eva_report:
                continue
            raw_unknowns = (eva_report.get("unknown_obligations_by_function") or {}).get(function, [])
            if not isinstance(raw_unknowns, list):
                continue
            rows = [
                a
                for a in raw_unknowns
                if not (norm_c_file and isinstance(a, dict)) or eva_alarm_in_file(a, norm_c_file)
            ]
            # Another harness's report of the same unit repeats rows the first one listed.
            seen = list(unknown_obligations)
            unknown_obligations += [a for a in rows if a not in seen]

    unproven_goals = wp_data.get("unproven_goals", []) if isinstance(wp_data, dict) else []
    if not unproven_goals and unknown_obligations:
        unproven_goals = unknown_obligations

    sec_props = []
    wave_index = 0
    untrusted_entries = []
    if fn_meta:
        sec_props = fn_meta.get("security_properties", [])
        wave_index = fn_meta.get("wave", 0)
    elif module and not function:
        # A module-level agent (an architect without a function): every function of the module.
        entry_fns = {m.get("entry_fn") for m in harness_metas if m.get("entry_fn")}
        for fn_key, fmeta in dag_fns.items():
            if isinstance(fmeta, dict) and fmeta.get("module") == module:
                for sp in fmeta.get("security_properties", []):
                    if sp not in sec_props:
                        sec_props.append(sp)
                fn_name = str(fmeta.get("name") or fn_key)
                if fn_name in entry_fns:
                    untrusted_entries.append(fn_name)
    # Step I9: the MetAcsl properties whose generated annotations this function must discharge.
    sec_doc = load_json_optional(overlay / "reports" / "security_props.json", None) if function else None
    if isinstance(sec_doc, dict) and norm_c_file and function:
        import security_props

        sec_props = [*sec_props, *security_props.brief_entries(sec_doc, norm_c_file, function)]

    def _untrusted_for(meta: dict) -> bool:
        if meta.get("reachability") == "internal_api":
            return False
        return not (function and meta.get("entry_fn") and function != meta.get("entry_fn"))

    # Untrusted when any harness of the unit enters through this function (or names no entry), or when
    # its trust (step I7) puts it on the trust boundary.
    reachability = (
        "untrusted_surface"
        if not harness_metas
        or any(_untrusted_for(m) for m in harness_metas)
        or (function and is_trust_boundary(function_trust_records(overlay), function, norm_c_file))
        else "internal_api"
    )

    coverage_ids = [u["coverage_id"] for u in fn_units if u.get("status") not in ("out_of_scope", "not_applicable")]

    unit_bk = (fn_units[0].get("bookkeeping") or {}) if fn_units and isinstance(fn_units[0], dict) else {}
    verifiability = str(fn_meta.get("verifiability") or unit_bk.get("verifiability") or "core_provable")
    wp_blockers = list(fn_meta.get("wp_blockers") or unit_bk.get("wp_blockers") or [])
    wp_notes = list(fn_meta.get("wp_notes") or unit_bk.get("wp_notes") or [])
    profile = str(run_meta.get("profile") or "standard").strip().lower()

    effective_max_retries = max_retries
    base_wall_s = PROVER_WALL_BUDGET_S.get(profile, PROVER_WALL_BUDGET_S["standard"])
    max_wall_clock_s = base_wall_s
    scaling_reason: str | None = None
    max_wp_invocations = effective_max_retries + 2
    facts_record: dict | None = None
    if role == "prover":
        if max_retries == 4 and (profile == "quick" or verifiability == "shell_unverifiable_wp"):
            effective_max_retries = 2
        elif max_retries == 4 and profile == "deep":
            effective_max_retries = 6
        facts_record = _load_function_facts(overlay, module, norm_c_file, function)
        env_wall = (os.environ.get("FRAMAC_PROVER_WALL_BUDGET_S") or "").strip()
        if env_wall.isdigit() and int(env_wall) > 0:
            base_wall_s = int(env_wall)
            max_wall_clock_s = base_wall_s
        elif verifiability == "shell_unverifiable_wp":
            base_wall_s = 300
            max_wall_clock_s = 300
        else:
            wp_goals, wp_vcs = _wp_report_size_signals(wp_data)
            if wp_goals == 0 and wp_vcs == 0 and function:
                earlier_wp = _latest_earlier_agent_wp_report(run_dir, agent_id, function, norm_c_file)
                wp_goals, wp_vcs = _wp_report_size_signals(earlier_wp)
            facts_loc = len(facts_record.get("code_lines") or []) if isinstance(facts_record, dict) else 0
            facts_loops = len(facts_record.get("loops") or []) if isinstance(facts_record, dict) else 0
            dag_loc = _safe_nonneg_int(fn_meta.get("loc")) if isinstance(fn_meta, dict) else 0
            dag_loops = _safe_nonneg_int(fn_meta.get("loop_count")) if isinstance(fn_meta, dict) else 0
            max_wall_clock_s, scaling_reason = scale_prover_wall_budget_s(
                base_wall_s,
                profile=profile,
                total_goals=wp_goals,
                vc_total=wp_vcs,
                eva_unknowns=len(unknown_obligations),
                loop_count=max(facts_loops, dag_loops),
                loc=max(facts_loc, dag_loc),
            )
        max_wp_invocations = effective_max_retries + 2
        budget_payload: dict[str, Any] = {
            "agent_id": agent_id,
            "function": function or "",
            "file": norm_c_file or "",
            "header": norm_header or "",
            "profile": profile,
            "verifiability": verifiability,
            "wp_blockers": wp_blockers,
            "max_retries": effective_max_retries,
            "max_wp_invocations": max_wp_invocations,
            "max_wall_clock_s": max_wall_clock_s,
            "budget_base_s": base_wall_s,
            "wp_invocations": 0,
            "first_wp_at": None,
        }
        if scaling_reason is not None:
            budget_payload["budget_scaling_reason"] = scaling_reason
        atomic_write_json(agent_root / "scratch" / ".prover_budget.json", budget_payload)

    cand_short = "candidate"
    if candidate_fp:
        raw_short = candidate_fp.split("::")[-1] if "::" in candidate_fp else candidate_fp
        cand_short = re.sub(r"[^A-Za-z0-9_.-]+", "_", raw_short).strip("_")[:40] or "candidate"

    tpl = _resolve_brief_template(role)
    context_section = ""
    kb_section = ""
    prover_context: dict = {}
    if role == "prover":
        context_section, features, prover_context = _prover_context(
            run_dir,
            overlay,
            agent_root,
            agent_id,
            module,
            function,
            norm_c_file,
            norm_header,
            eff_cppflags,
            dag_fns,
            facts_record=facts_record,
        )
        tpl = function_facts.render_conditionals(tpl, features)
        if spec_kb.enabled():
            kb_section = spec_kb.kb_section_for(overlay, facts_record)
    if role in ("prover", "breaker") and spec_kb.enabled():
        # Dead ends: clauses refuted on this function (earlier dispatches included) and rejected callee requests.
        kb_section += spec_kb.obstructions_section_for(
            overlay,
            function,
            _callee_names(fn_meta),
            _earlier_refutations(run_dir, agent_id, function, norm_c_file),
        )
    tpl = tpl.replace(RUN_COMMANDS_SENTINEL, _resolve_brief_template("run_commands").rstrip("\n"))
    # An architect's guardrail checks the header's functions, as a prover's checks its function (mpack run-4:
    # without it, a known defect in the program's `main` was the architect's `code_fault`).
    header_fns: list[str] = []
    if role == "architect" and norm_header:
        try:
            header_fns = header_function_names(
                (overlay / "work" / norm_header).read_text(encoding="utf-8", errors="replace"), norm_header
            )
        except OSError:
            header_fns = []
    references_host = _brief_path(
        os.environ.get("FRAMAC_REFERENCES_HOST") or str(Path(__file__).resolve().parent.parent / "docs" / "references")
    )
    replacements = {
        "{agent_id}": agent_id,
        "{module_name}": module or "unknown",
        "{harness_module_name}": harness_module_name or module or "unknown",
        "{header_file}": norm_header or "",
        "{c_file}": norm_c_file or "",
        "{function_name}": function or "",
        "{wave_index}": str(wave_index),
        "{scratch_module_sources}": scratch_sources_str,
        "{module_sources}": module_sources_str,
        "{cppflags}": eff_cppflags,
        # What an agent's own oracles use, so that they read its scratch headers. merge_cmd keeps
        # the module's flags: the parent re-checks the merged tree.
        "{scratch_cppflags}": scratch_first_cppflags(
            f"-Iagents/{agent_id}/scratch/work {eff_cppflags}", run_dir, agent_root / "scratch" / "work"
        ),
        "{ldflags}": eff_ldflags,
        "{security_properties_json}": json.dumps(sec_props),
        "{untrusted_entry_functions_json}": json.dumps(untrusted_entries),
        "{coverage_ids_json}": json.dumps(coverage_ids),
        "{unknown_obligations_json}": json.dumps(unknown_obligations),
        "{reachability}": reachability,
        "{max_retries}": str(effective_max_retries),
        "{unproven_goals_json}": json.dumps(unproven_goals),
        "{candidate_fingerprint}": candidate_fp or "",
        "{candidate_short}": cand_short,
        "{candidate_json}": json.dumps(cand_obj),
        # Host paths: agents invoke the host-side wrapper, which needs host paths, never the
        # container's /target and /framac-run. The wrapper passes them as environment.
        "{target_dir}": _brief_path(os.environ.get("FRAMAC_TARGET_HOST") or run_meta.get("target") or "/target"),
        "{run_dir}": _brief_path(os.environ.get("FRAMAC_RUN_HOST") or run_meta.get("run_dir_host") or str(run_dir)),
        "{references_dir}": references_host,
        # The wrappers live in the same checkout as docs/references (both are host paths).
        "{pipeline_dir}": _pipeline_host_dir(references_host),
        "{header_functions_args}": f"--functions {' '.join(header_fns)}" if header_fns else "",
    }
    rendered = tpl
    for k, v in replacements.items():
        rendered = rendered.replace(k, v)
    # After substitution, like what is appended below: source text and reports are data, never placeholders.
    rendered = rendered.replace(function_facts.CONTEXT_SENTINEL + "\n\n", context_section and context_section + "\n")
    rendered = rendered.replace(spec_kb.KB_SENTINEL + "\n\n", kb_section and kb_section + "\n")
    if role == "prover":
        fn_label = function or "this function"
        rendered += (
            "\n## WP Verifiability & Iteration Budget\n\n"
            f"- **Static WP Verifiability Classification:** `{verifiability}`\n"
        )
        if wp_blockers:
            rendered += f"- **Detected WP Blockers:** `{json.dumps(wp_blockers)}`\n"
        if wp_notes:
            rendered += f"- **Detected WP Notes:** `{json.dumps(wp_notes)}`\n"
        rendered += (
            f"- **Enforced Budget (`agents/{agent_id}/scratch/.prover_budget.json`):** "
            f"at most `{max_wp_invocations}` `run_wp_function.py` invocations and `{max_wall_clock_s}s` wall-clock, "
            "counted from your first `run_wp_function.py` call; time your later calls spend queued for a WP "
            "lease in the host resource broker does not count.\n"
        )
        if scaling_reason:
            rendered += f"- **Budget Scaling:** {scaling_reason}.\n"
        if verifiability == "shell_unverifiable_wp" or "dynamic_allocation" in wp_blockers:
            rendered += (
                f"- **Fast-Fail Rule for `{fn_label}`:** This function is classified as `shell_unverifiable_wp` "
                f"(blockers: `{', '.join(wp_blockers) or 'structural'}`). Frama-C WP does not support dynamic "
                "allocation predicates (`\\freeable`, `\\fresh`, `\\allocable`, `allocates`, `frees`) from "
                "`<stdlib.h>`. Prove all dischargeable non-allocation RTE/frame/loop obligations, verify that the "
                "E-ACSL guardrail passes (`passed_dynamic_oracle`), and as soon as only WP-unsupported allocation "
                "or structural goals remain (or `next_synthesis_focus` is "
                '`"wp_dynamic_allocation_limitation_stop_now"` / `"budget_exhausted_write_result_json_now"`), '
                'immediately write `result.json` with `"status": "stalled_after_k_retries"`. Never write '
                "synthetic `probe_*.c` files.\n"
            )
    if wp_report_rel:
        rendered += (
            "\n## Stalled Prover's WP Report\n\n"
            f"The unproven goals above come from `{wp_report_rel}`. Read it for each goal's exact "
            "property name, line and prover verdicts.\n"
        )
    if requests:
        fn_label = function or "the callee"
        rendered += (
            "\n## Contract Negotiation Requests\n\n"
            f"Callers asked you to strengthen `{fn_label}`'s contract. Add each `needed_clause` below to "
            f"`{fn_label}`'s contract, then prove `{fn_label}` against the strengthened contract with both "
            "oracles. Return `all_proven` only when every requested clause is in place and proven: the "
            "parent then merges it and requeues the callers. If a clause does not hold, leave it out, "
            "return `stalled_after_k_retries` or `blocked`, and say in `unproven_goals` which clause "
            "fails and why. Never weaken an existing clause to make a requested one provable.\n\n"
            "```json\n" + json.dumps(requests, indent=2) + "\n```\n"
        )
        rendered += _negotiation_evidence_section(caller_evidence, callee_history)
    rendered += _caller_usage_section(overlay, function, fn_meta, dag_fns, role)
    rendered += _proven_examples_section(overlay, function, fn_meta, dag_fns, eff_cppflags, role)
    rendered += _callees_without_contract_section(callees_without_contract, role)
    rendered += _rejected_result_section(rejected_result, agent_id, role)

    brief_path = agent_root / "brief.md"
    brief_path.parent.mkdir(parents=True, exist_ok=True)
    brief_path.write_text(rendered, encoding="utf-8")

    merge_cmd: str | None = None
    src_args = f" --sources {' '.join(merge_sources_list)}" if merge_sources_list else ""
    # `--opt='value'`: argparse rejects a separate value that starts with '-' (e.g. `-I.`, `-lbsd`).
    ld_args = f" --ldflags='{eff_ldflags}'" if eff_ldflags else ""
    if role == "architect":
        merge_cmd = (
            f"python3 /opt/framac-pipeline/scripts/workspace_overlay.py merge-agent "
            f"--agent-id {agent_id} --role architect --header {norm_header or '<header>'} "
            f"--module {module or '<mod>'}{src_args} --cppflags='{eff_cppflags}'{ld_args}"
        )
    elif role == "prover":
        hdr_arg = f" --header {norm_header}" if norm_header else ""
        merge_cmd = (
            f"python3 /opt/framac-pipeline/scripts/workspace_overlay.py merge-agent "
            f"--agent-id {agent_id} --role prover --file {norm_c_file or '<file>'} "
            f"--function {function or '<fn>'}{hdr_arg} "
            f"--module {module or '<mod>'}{src_args} --cppflags='{eff_cppflags}'{ld_args}"
        )

    return {
        "ok": True,
        "agent_id": agent_id,
        "role": role,
        "module": module,
        "file": norm_c_file,
        "header": norm_header,
        "function": function,
        "brief_file": brief_path.relative_to(run_dir).as_posix(),
        "merge_command": merge_cmd,
        **({"prover_context": prover_context} if prover_context else {}),
        **overlay_info,
    }


def export_diff(overlay_dir: Path, out_patch: Path) -> dict:
    overlay_dir = overlay_dir.resolve()
    baseline_dir = overlay_dir / "baseline"
    work_dir = overlay_dir / "work"
    contracts_dir = overlay_dir / "contracts"
    contracts_dir.mkdir(parents=True, exist_ok=True)

    diff_chunks: list[str] = []
    modified_files: list[str] = []

    for root, _, files in os.walk(work_dir):
        for fname in sorted(files):
            work_file = Path(root) / fname
            if work_file.suffix.lower() not in SOURCE_EXTS:
                continue
            rel_path = work_file.relative_to(work_dir)
            base_file = baseline_dir / rel_path

            work_lines = work_file.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
            base_lines = (
                base_file.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
                if base_file.exists()
                else []
            )

            rel_str = str(rel_path).replace("\\", "/")
            udiff = list(
                difflib.unified_diff(
                    base_lines,
                    work_lines,
                    fromfile=f"a/{rel_str}",
                    tofile=f"b/{rel_str}",
                )
            )
            if udiff:
                diff_chunks.append("".join(udiff))
                modified_files.append(rel_str)
                if work_file.suffix.lower() in {".h", ".acsl"}:
                    dest_contract = contracts_dir / rel_path
                    dest_contract.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(work_file, dest_contract)

    out_patch.parent.mkdir(parents=True, exist_ok=True)
    out_patch.write_text("\n".join(diff_chunks), encoding="utf-8")
    manifest = _contracts_manifest(overlay_dir, work_dir, [m for m in modified_files if m.endswith((".h", ".acsl"))])
    atomic_write_json(contracts_dir / "MANIFEST.json", manifest)
    return {
        "patch_file": str(out_patch),
        "modified_files": modified_files,
        "modified_count": len(modified_files),
        "contracts_manifest": (contracts_dir / "MANIFEST.json").as_posix(),
        "contracts_by_status": manifest["by_status"],
    }


def _contracts_manifest(overlay_dir: Path, work_dir: Path, headers: list[str]) -> dict:
    """
    What each exported header contract is worth: the patch carries every merged contract (callers were
    proven against them), but only a contract whose function is `covered` in the ledger is proven. Each
    contracted prototype gets its function's status: `proven` (every unit covered, no open assumption),
    `proven_under_assumptions`, or `unproven` (a contract other proofs rely on, not established itself).
    """
    ledger_units = load_json_optional(overlay_dir.parent / "coverage-ledger.json", [])
    by_fn: dict[str, list[dict]] = {}
    for u in ledger_units if isinstance(ledger_units, list) else []:
        if isinstance(u, dict) and u.get("status") not in ("deferred", "out_of_scope", "not_applicable"):
            by_fn.setdefault(str(u.get("function")), []).append(u)

    def status_of(fn: str) -> str:
        units = by_fn.get(fn) or []
        if not units or any(u.get("status") != "covered" for u in units):
            return "unproven"
        return "proven_under_assumptions" if any(u.get("assumptions") for u in units) else "proven"

    entries: dict[str, list[dict]] = {}
    counts: dict[str, int] = {}
    for rel_str in headers:
        try:
            source = (work_dir / rel_str).read_text(encoding="utf-8", errors="replace")
            spans = locate_all_prototype_spans(source, path=rel_str)
        except (OSError, AcslError):
            spans = []
        rows = []
        for span in spans:
            if "/*@" not in span.text and "//@" not in span.text:
                continue
            st = status_of(span.function)
            counts[st] = counts.get(st, 0) + 1
            rows.append({"function": span.function, "status": st})
        entries[rel_str] = rows
    return {"generated_at": utc_now(), "headers": entries, "by_status": counts}


def apply_in_place(overlay_dir: Path, target_dir: Path) -> dict:
    overlay_dir = overlay_dir.resolve()
    target_dir = target_dir.resolve()
    acsl_check = check_acsl_only(overlay_dir)
    if not acsl_check["ok"]:
        raise AcslError(
            "Refusing to apply work tree with non-ACSL modifications to target:\n  "
            + "\n  ".join(acsl_check["errors"][:20])
        )
    baseline_dir = overlay_dir / "baseline"
    work_dir = overlay_dir / "work"
    # The C sources the build generated (target_env.install_generated_sources) are no file of the target:
    # their ACSL stays in the overlay.
    meta = load_json_optional(overlay_dir / target_env.OVERLAY_META, {})
    generated = set(meta.get(target_env.GENERATED_SOURCES_KEY) or {}) if isinstance(meta, dict) else set()
    generated |= set(target_env.generated_source_paths(overlay_dir / Path(target_env.SNAPSHOT_REL).name))

    synced: list[str] = []
    skipped_generated: list[str] = []
    for root, _, files in os.walk(work_dir):
        for fname in sorted(files):
            work_file = Path(root) / fname
            if work_file.suffix.lower() not in SOURCE_EXTS:
                continue
            rel_path = work_file.relative_to(work_dir)
            if rel_path.as_posix() in generated:
                skipped_generated.append(rel_path.as_posix())
                continue
            base_file = baseline_dir / rel_path
            target_file = target_dir / rel_path

            work_bytes = work_file.read_bytes()
            base_bytes = base_file.read_bytes() if base_file.exists() else b""
            if work_bytes != base_bytes:
                target_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(work_file, target_file)
                synced.append(str(rel_path).replace("\\", "/"))

    out: dict[str, Any] = {"applied_in_place": synced, "count": len(synced)}
    if skipped_generated:
        out["skipped_generated"] = sorted(skipped_generated)
    return out


def _load_rejected_result_arg(raw: str) -> dict:
    """Load `--rejected-result` from an inline JSON object string, a JSON file path, or `@<path>`."""
    stripped = raw.strip()
    if not stripped:
        raise ArtifactError("--rejected-result: empty value; expected a JSON object or JSON file path")
    if stripped.startswith("@"):
        source = stripped[1:]
        if not source:
            raise ArtifactError("--rejected-result: missing file path after '@'")
        data = load_json_strict(Path(source))
        label = source
    elif (
        stripped[0] in '{["'
        or stripped in ("null", "true", "false")
        or re.fullmatch(r"-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?", stripped)
    ):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ArtifactError(f"--rejected-result: invalid JSON: {exc}") from exc
        label = "--rejected-result"
    else:
        data = load_json_strict(Path(raw))
        label = raw
    if not isinstance(data, dict):
        raise ArtifactError(f"{label}: expected a JSON object")
    if "errors" in data and data["errors"] is not None and not isinstance(data["errors"], list):
        raise ArtifactError(f"{label}: 'errors' must be a JSON list")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manage the run's workspace/ shadow overlay and agent overlays.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init")
    p_init.add_argument("--target", type=Path, required=True)
    p_init.add_argument("--overlay", type=Path, default=Path("workspace"))
    p_init.add_argument("--force", action="store_true")

    p_gen = sub.add_parser(
        "install-generated",
        help="Install the C sources the build generated (snapshot manifest generated_sources) in baseline/ and work/",
    )
    p_gen.add_argument("--overlay", type=Path, default=Path("workspace"))

    p_agent = sub.add_parser("init-agent")
    p_agent.add_argument("--run-dir", type=Path, default=Path("."))
    p_agent.add_argument("--agent-id", required=True)
    p_agent.add_argument("--overlay", type=Path, default=None)

    p_prep = sub.add_parser("prepare-agent")
    p_prep.add_argument("--run-dir", type=Path, default=Path("."))
    p_prep.add_argument("--agent-id", required=True)
    p_prep.add_argument("--role", choices=["architect", "prover", "breaker", "verifier"], required=True)
    p_prep.add_argument("--overlay", type=Path, default=None)
    p_prep.add_argument("--module", default=None)
    p_prep.add_argument("--function", default=None)
    p_prep.add_argument("--file", default=None)
    p_prep.add_argument("--header", default=None)
    p_prep.add_argument("--max-retries", type=int, default=4)
    p_prep.add_argument("--candidate-fp", default=None)
    p_prep.add_argument("--cppflags", default=None)
    p_prep.add_argument("--ldflags", default=None)
    p_prep.add_argument(
        "--wp-report", default=None, help="WP report whose unproven goals the brief lists (run-relative)"
    )
    p_prep.add_argument(
        "--request-id",
        action="append",
        default=[],
        help="Strengthening request the callee prover must answer (repeatable)",
    )
    p_prep.add_argument(
        "--caller-evidence-json",
        type=Path,
        default=None,
        help="JSON list of the callers' call-site goals, rendered under the negotiation requests",
    )
    p_prep.add_argument(
        "--callee-history-json",
        type=Path,
        default=None,
        help="JSON object summarizing the callee's previous prover run, rendered under the requests",
    )
    p_prep.add_argument(
        "--rejected-result",
        "--rejected-result-json",
        dest="rejected_result",
        default=None,
        help=(
            "JSON object (inline, file path, or @path) describing a rejected previous result "
            '({"agent_id": "...", "errors": [...]}), rendered under Previous Attempt: Result Rejected'
        ),
    )

    p_check = sub.add_parser("check-acsl-only")
    p_check.add_argument("--overlay", type=Path, default=Path("workspace"))
    p_check.add_argument("--work-dir", type=Path, default=None)
    p_check.add_argument("--file", action="append", default=[])

    p_merge = sub.add_parser("merge-agent")
    p_merge.add_argument("--run-dir", type=Path, default=Path("."))
    p_merge.add_argument("--agent-id", required=True)
    p_merge.add_argument("--role", choices=["prover", "architect"], required=True)
    p_merge.add_argument("--overlay", type=Path, default=None)
    p_merge.add_argument("--file", default=None)
    p_merge.add_argument("--function", default=None)
    p_merge.add_argument("--header", default=None)
    p_merge.add_argument("--module", default=None)
    p_merge.add_argument("--sources", nargs="*", default=None, help="Default: the --module's harness sources")
    p_merge.add_argument("--cppflags", default=None, help="Default: the --module's cppflags, else -I.")
    p_merge.add_argument(
        "--ldflags", default=None, help="Extra linker flags for parent guardrail (default: the --module's)"
    )
    p_merge.add_argument("--skip-reverify", action="store_true")
    p_merge.add_argument(
        "--allow-partial-wp",
        action="store_true",
        help="Allow merging a stalled prover whose assigns and soundness are verified so callers can use its contract",
    )
    p_merge.add_argument(
        "--contract-only",
        action="store_true",
        help="Splice only the function contract pre-body span (preserve original C body without loop annotations)",
    )

    p_batch = sub.add_parser("merge-batch")
    p_batch.add_argument("--run-dir", type=Path, default=Path("."))
    p_batch.add_argument("--overlay", type=Path, default=None)
    p_batch.add_argument("--spec-json", type=Path, default=None, help="JSON file with list of agent merge specs")
    p_batch.add_argument("--agents", nargs="*", default=None, help="Agent IDs to merge in batch")
    p_batch.add_argument("--role", choices=["prover", "architect"], default=None)
    p_batch.add_argument("--module", default=None)
    p_batch.add_argument("--sources", nargs="*", default=None)
    p_batch.add_argument("--cppflags", default=None)
    p_batch.add_argument("--ldflags", default="")
    p_batch.add_argument("--skip-reverify", action="store_true")

    p_diff = sub.add_parser("export-diff")
    p_diff.add_argument("--overlay", type=Path, default=Path("workspace"))
    p_diff.add_argument("--out", type=Path, default=Path("workspace/reports/verified_acsl.patch"))

    p_sync = sub.add_parser("apply-in-place", help="Host-side only: the container mounts the target read-only")
    p_sync.add_argument("--overlay", type=Path, default=Path("workspace"))
    p_sync.add_argument("--target", type=Path, required=True)

    raw_argv = list(argv) if argv is not None else sys.argv[1:]
    args = parser.parse_args(normalize_flag_args(raw_argv, ("--cppflags", "--ldflags")))
    try:
        if args.cmd == "init":
            res = init_overlay(args.target, args.overlay, args.force)
        elif args.cmd == "install-generated":
            res = target_env.install_generated_sources(args.overlay)
        elif args.cmd == "init-agent":
            res = init_agent_overlay(args.run_dir, args.agent_id, args.overlay)
        elif args.cmd == "prepare-agent":
            requests = None
            if args.request_id:
                req_file = (args.overlay or args.run_dir / "workspace") / "reports" / "strengthen_requests.json"
                req_data = load_json_optional(req_file, {})
                known = (
                    {r.get("id"): r for r in (req_data.get("requests") or []) if isinstance(r, dict)}
                    if isinstance(req_data, dict)
                    else {}
                )
                missing = [rid for rid in args.request_id if rid not in known]
                if missing:
                    raise ArtifactError(f"unknown strengthening request(s) in {req_file}: {', '.join(missing)}")
                requests = [known[rid] for rid in args.request_id]
            caller_evidence = load_json_strict(args.caller_evidence_json) if args.caller_evidence_json else None
            if caller_evidence is not None and not isinstance(caller_evidence, list):
                raise ArtifactError(f"{args.caller_evidence_json}: expected a JSON list")
            callee_history = load_json_strict(args.callee_history_json) if args.callee_history_json else None
            if callee_history is not None and not isinstance(callee_history, dict):
                raise ArtifactError(f"{args.callee_history_json}: expected a JSON object")
            rejected_result = (
                _load_rejected_result_arg(args.rejected_result) if args.rejected_result is not None else None
            )
            res = prepare_agent(
                run_dir=args.run_dir,
                agent_id=args.agent_id,
                role=args.role,
                overlay_dir=args.overlay,
                module=args.module,
                function=args.function,
                c_file=args.file,
                header_file=args.header,
                max_retries=args.max_retries,
                candidate_fp=args.candidate_fp,
                cppflags=args.cppflags,
                ldflags=args.ldflags,
                wp_report=args.wp_report,
                requests=requests,
                caller_evidence=caller_evidence,
                callee_history=callee_history,
                rejected_result=rejected_result,
            )
        elif args.cmd == "check-acsl-only":
            res = check_acsl_only(args.overlay, args.work_dir, args.file or None)
            print(json.dumps(res, indent=2))
            return 0 if res["ok"] else 1
        elif args.cmd == "merge-agent":
            m_sources, m_cppflags, m_ldflags = single_merge_build_inputs(
                (args.overlay or args.run_dir / "workspace"),
                args.module,
                args.sources,
                args.cppflags,
                args.ldflags,
                reverify=not args.skip_reverify,
            )
            res = merge_agent_overlay(
                run_dir=args.run_dir,
                agent_id=args.agent_id,
                role=args.role,
                overlay_dir=args.overlay,
                c_file=args.file,
                function=args.function,
                header_file=args.header,
                module=args.module,
                sources=m_sources,
                cppflags=m_cppflags,
                ldflags=m_ldflags,
                skip_reverify=args.skip_reverify,
                allow_partial_wp=args.allow_partial_wp,
                contract_only=args.contract_only,
            )
            print(json.dumps(res, indent=2))
            return 0 if res["ok"] else 1
        elif args.cmd == "merge-batch":
            batch_entries: list[dict] = []
            if args.spec_json is not None:
                raw_spec = json.loads(args.spec_json.read_text(encoding="utf-8"))
                batch_entries.extend(raw_spec["agents"] if isinstance(raw_spec, dict) else raw_spec)
            for aid in args.agents or []:
                batch_entries.append({"agent_id": aid})
            if not batch_entries:
                raise ArtifactError("merge-batch requires --spec-json or --agents")
            res = merge_agent_batch(
                run_dir=args.run_dir,
                entries=batch_entries,
                overlay_dir=args.overlay,
                cppflags=args.cppflags,
                ldflags=args.ldflags,
                skip_reverify=args.skip_reverify,
                default_role=args.role,
                default_module=args.module,
                default_sources=args.sources,
            )
            print(json.dumps(res, indent=2))
            return 0 if res["ok"] else 1
        elif args.cmd == "export-diff":
            res = export_diff(args.overlay, args.out)
        elif args.cmd == "apply-in-place":
            res = apply_in_place(args.overlay, args.target)
        else:
            return 1
    except (StaleBaselineError, OverlayMergeError, AcslError, ScopeViolationError, ArtifactError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        return 1

    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
