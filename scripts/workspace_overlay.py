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
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import function_facts  # noqa: E402
import function_slice  # noqa: E402
import spec_kb  # noqa: E402
from acsl_ast import (  # noqa: E402
    AcslError,
    ConflictingProfileError,
    ScopeViolationError,
    TrustBoundaryError,
    check_conflicting_acsl_profiles,
    check_frame_preserved,
    dedup_acsl_declarations,
    entry_requires_violations,
    extract_top_level_acsl_declarations,
    function_contract_text,
    function_param_names,
    function_trust_records,
    is_trust_boundary,
    locate_all_prototype_spans,
    locate_function_span,
    splice_architect_header,
    splice_prover_changes,
    tokenize_c_acsl,
    verify_acsl_only,
)
from fingerprint import normalize_file  # noqa: E402
from framac_common import (  # noqa: E402
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
    wp_model_unsound,
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

    meta = {
        "target_dir": str(target_dir),
        "overlay_dir": str(overlay_dir),
        "work_dir": str(work_dir),
        "baseline_dir": str(baseline_dir),
        "copied_count": len(copied_files),
        "skipped_pipeline_output": sorted(skipped_output),
    }
    (overlay_dir / "overlay_meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
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
# A ledger unit's `module` is a DAG module: with the Phase 0 model, a link unit (`libqcbor_a`) whose
# harnesses are sub-modules (`harness_qcbor_main_decode.json`, sidecar `unit`). Whatever needs a
# sidecar, a harness, a corpus or a per-harness report "for a unit" resolves it here: the unit's own
# harness when it has one, else its sub-modules (flags and sources: their union). Without link units
# the DAG modules are the harness modules and every helper is the identity.

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
    run_rel = re.sub(r"^/framac-run/", "", norm)
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
    WP model. Defaults to `['--no-warn-unsigned-downcast']`.
    """
    overlay = (overlay_dir or (run_dir / "workspace")).resolve()
    norm_c = _normalize_work_relpath(c_file) if c_file else None
    cand_paths: list[Path] = []
    if agent_id and function and is_safe_agent_id(agent_id):
        agent_dir = run_dir / "agents" / agent_id
        cand_paths.append(agent_dir / "scratch" / f"wp_{function}.json")
        cand_paths.append(agent_dir / "artifacts" / f"wp_{function}.json")
        res_file = agent_dir / "scratch" / "result.json"
        if res_file.is_file():
            res_data = load_json_optional(res_file, {}) or {}
            if isinstance(res_data, dict):
                for ev in res_data.get("evidence") or []:
                    tout = str((ev or {}).get("tool_output") or "").replace("\\", "/").strip()
                    if tout.startswith(f"agents/{agent_id}/") and tout.endswith(".json"):
                        cand_paths.append(run_dir / tout)
        cand_paths.append(agent_dir / "scratch" / "parent_wp" / f"{function}.json")
    if function:
        cand_paths.append(overlay / "reports" / "wp" / f"{function}.json")

    reduced: list[str] = []
    wp_model: str | None = None
    wrap_code_lines: list[int] = []

    def _note_wraps(report: dict) -> None:
        declared = (report.get("unsigned_wraps") or {}).get("declared_code_lines")
        if isinstance(declared, list) and not wrap_code_lines:
            wrap_code_lines.extend(n for n in declared if isinstance(n, int) and not isinstance(n, bool))

    for p in cand_paths:
        if not p.is_file() or p.is_symlink():
            continue
        rep = load_json_optional(p, {}) or {}
        if not isinstance(rep, dict) or rep.get("mode") == "guardrail":
            continue
        if function and rep.get("function") not in (None, function):
            continue
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

    flags: list[str] = []
    if any("-warn-unsigned-overflow / -warn-unsigned-downcast OFF" in r for r in reduced):
        flags.append("--no-warn-unsigned")
        if wrap_code_lines:
            flags.append(f"--wrap-code-lines={','.join(str(n) for n in wrap_code_lines)}")
    else:
        flags.append("--no-warn-unsigned-downcast")
    if any("-warn-invalid-pointer OFF" in r for r in reduced):
        flags.append("--no-warn-invalid-pointer")
    # Never carry the unsound `cast` model into a parent re-check or the sweep.
    if (
        wp_model
        and wp_model != "Typed"
        and re.match(r"^[A-Za-z0-9_+,-]+$", wp_model)
        and not wp_model_unsound(wp_model)
    ):
        flags.extend(["--wp-model", wp_model])
    return flags


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
) -> tuple[bool, str]:
    """
    Run dynamic guardrail (and WP for provers) on the merged workspace/work/ tree. `wp_par`
    caps the WP run's concurrent provers when several re-checks share the job budget (default:
    `auto`, the whole budget). The guardrail binary is built outside the agent's scratch, at a
    path fixed per module build, so an unchanged module is restored from the build cache.
    `reach_functions`: functions whose reach a module-wide guardrail (no `function`) measures,
    without narrowing its instrumentation; the report is at `_parent_guard_json(...)`.
    """
    scripts_dir = Path(__file__).resolve().parent
    work_dir = overlay_dir / "work"
    guard_report: dict | None = None

    if module and sources:
        # A link unit is built through one of its harnesses (the one answering for `function`).
        hmod = harness_module_for_function(module_map_for(overlay_dir), module, c_file, function) or module
        harness = overlay_dir / "harnesses" / f"harness_{hmod}.c"
        corpus = overlay_dir / "corpus" / hmod
        # The parent re-check must use the same reduced checks as the module's build:
        # a module fuzzed with -no-rte-initialized would otherwise re-trip the E-ACSL
        # by-value-struct initialization artifact here and be misread as code_fault.
        rte_initialized = True
        try:
            import pipeline_make  # imported lazily; the overlay also works without the Make layer

            _plan = pipeline_make.build_plan(run_dir)
            _eff = pipeline_make.effective_params(pipeline_make.load_params(run_dir), hmod, _plan.profile)
            rte_initialized = bool(_eff.get("fuzz_rte_initialized", True))
        except Exception:
            rte_initialized = True
        build_tag_items = [list(sources), cppflags, ldflags, rte_initialized]
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
        proc = subprocess.run(cmd, cwd=str(run_dir), capture_output=True, text=True, encoding="utf-8", errors="replace")
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
                    f"assigns_verified={assigns_ok})",
                )
        elif wp_status != "all_proven":
            return False, f"parent WP check on merged tree returned status={wp_status!r}"
        if guard_report is not None and _apply_guard_limits(wp_report, function, guard_report):
            wp_json.write_text(json.dumps(wp_report, indent=2) + "\n", encoding="utf-8")
        _publish_canonical_wp(run_dir, overlay_dir, wp_json, norm_c, function)

    return True, "verified"


def _parent_guard_json(run_dir: Path, agent_id: str, function: str | None, module: str | None) -> Path:
    """Where `_run_parent_reverify` writes its guardrail report."""
    return run_dir / "agents" / agent_id / "scratch" / f"parent_guard_{function or module}.json"


def _publish_canonical_wp(run_dir: Path, overlay_dir: Path, wp_json: Path, norm_c: str, function: str) -> None:
    """Copy a parent WP report to reports/wp/<function>.json unless the name is ambiguous across files."""
    if len(_function_files(run_dir, function) - {norm_c}) == 0:
        canonical = overlay_dir / "reports" / "wp" / f"{function}.json"
        canonical.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(wp_json, canonical)


def _apply_guard_limits(wp_report: dict, function: str, guard_report: dict) -> bool:
    """
    Record in `wp_report["limits"]` what the parent guardrail established for `function`:
    `dynamic_oracle` {exercised, hits, executed_inputs} from its reach and `guardrail_corpus`
    {total, replayed, sampled, empty}. A pass on an empty corpus replayed no real input, so it is
    recorded as not exercised (an open assumption in the ledger), never as a pass on inputs.
    Returns whether anything was recorded.
    """
    limits = wp_report.setdefault("limits", {})
    corpus_empty = bool(guard_report.get("corpus_empty"))
    changed = False
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


def _load_function_facts(overlay: Path, module: str | None, c_file: str | None, function: str | None) -> dict | None:
    """
    A function's facts (`reports/facts/<harness module>.json`): the module's own report, then that
    of the harness answering for the function, then those of its unit's other harnesses.
    """
    if not (module and c_file and function):
        return None
    mm = module_map_for(overlay)
    first = harness_module_for_function(mm, module, c_file, function)
    for name in dict.fromkeys([module, *([first] if first else []), *harness_modules_of(mm, module)]):
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


def _acsl_text_of_span(span) -> str:
    """The ACSL comment texts inside a function span (its contract and body annotations)."""
    try:
        tokens = tokenize_c_acsl(span.text, path=span.function)
    except AcslError:
        return ""
    return "\n".join(t.text for t in tokens if t.kind in ("acsl_block", "acsl_line"))


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
    `rel` (docs/v2-design.md §6). Only the entry function is checked, and only when the agent
    changed its contract; violations already in the target's own baseline ACSL are not the agent's.
    An entry that records its `file` (one the function's trust put on the boundary) is checked in
    that source and in headers, never in another source's same-named static.
    """
    entry = str(hmeta.get("entry_fn") or "")
    if not entry or Path(rel).suffix not in ACSL_CHECK_EXTS:
        return []
    is_hdr = rel.endswith(".h")
    entry_file = _normalize_work_relpath(str(hmeta.get("file") or ""))
    if entry_file and not is_hdr and _normalize_work_relpath(rel) != entry_file:
        return []
    try:
        if function_contract_text(agent_text, entry, is_hdr, rel) == function_contract_text(
            base_text, entry, is_hdr, rel
        ):
            return []
        contract = function_contract_text(merged_text, entry, is_hdr, rel)
        params = set(function_param_names(merged_text, entry, is_hdr, rel))
        baseline_contract = function_contract_text(baseline_text, entry, is_hdr, rel)
    except AcslError:
        return []  # the ACSL-only check reports unparsable files
    params.update(str(hmeta[k]) for k in ("global_buf", "global_len") if hmeta.get(k))
    nul = bool(hmeta.get("null_terminate")) or hmeta.get("entry_style") in ("c_string", "argv")
    found = entry_requires_violations(contract, params, nul_terminated=nul)
    if not found:
        return []
    pre_existing = set(entry_requires_violations(baseline_contract, params, nul_terminated=nul))
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
            sibling_h = Path(norm_c_file).with_suffix(".h").as_posix()
            if sibling_h in changed_rels:
                norm_header_file = sibling_h
            else:
                stem_matches = [r for r in changed_rels if r.endswith(".h") and Path(r).stem == Path(norm_c_file).stem]
                if len(stem_matches) == 1:
                    norm_header_file = stem_matches[0]
                elif module:
                    hmeta = merged_sidecar(module_map_for(overlay), module)
                    if hmeta.get("header"):
                        mod_hdr = _prover_header(
                            run_dir, shared_work, norm_c_file, function, str(hmeta["header"]), header_flags
                        )
                        if mod_hdr in changed_rels:
                            norm_header_file = mod_hdr
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

    if frame_skel is not None:
        # The projected frame skeleton is a required minimum: a prover candidate that deletes
        # or weakens a projected \separated / assigns...\from clause is rejected. The contract
        # may live in the .c or the .h, so check the ACSL of the function's span across all
        # spliced files together.
        frame_parts: list[str] = []
        for rel_str in changed_rels:
            span = locate_function_span(
                new_contents[rel_str], function or "", is_header=rel_str.endswith(".h"), path=rel_str
            )
            if span is not None:
                frame_parts.append(_acsl_text_of_span(span))
        frame_errs = check_frame_preserved(frame_skel, "\n".join(frame_parts), path=norm_c_file or "<work>")
        if frame_errs:
            raise AcslError("frame-preservation check failed:\n  " + "\n  ".join(frame_errs))

    entry_metas = _untrusted_entry_metas(overlay, module, function, norm_c_file)
    if entry_metas:
        # On an untrusted_surface entry, `requires` may state memory shape only: a value constraint on
        # attacker-controlled bytes or lengths would define the bug away (docs/v2-design.md §6).
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
                if wp_extra_sources is not None and _supports_kwarg(_run_parent_reverify, "wp_extra_sources"):
                    reverify_kwargs["wp_extra_sources"] = wp_extra_sources
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
    if role == "prover" and function and not skip_reverify and verify_hook is None:
        # The report to ingest: written for this agent only, so same-named functions never collide.
        result["parent_wp_report"] = _parent_wp_report_rel(agent_id, function)
    return result


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
) -> list[tuple[list[int], str]]:
    """
    Re-check the spliced tree: one guardrail per unique module build and one WP run per prover,
    run in parallel with workers = min(checks, CPUs) and `-wp-par` = CPUs // workers each.
    Returns the failed checks as (indices of the implicated items, reason).
    """
    if verify_hook is not None:
        failures: list[tuple[list[int], str]] = []
        for i, item in enumerate(items):
            ok, reason = verify_hook(item)
            if not ok:
                failures.append(([i], reason))
        return failures

    checks: list[tuple[list[int], dict]] = []
    modules: dict[tuple[str, tuple[str, ...], str, str], list[int]] = {}
    for i, item in enumerate(items):
        if item.get("module") and item.get("sources"):
            mod_key = (item["module"], tuple(item["sources"]), item["cppflags"], item["ldflags"])
            modules.setdefault(mod_key, []).append(i)
    # The module guardrail measures the reach of the batch's prover functions, as the single
    # merge-agent path does per function, so their proofs record `limits.dynamic_oracle`.
    reach_by_check: dict[int, list[int]] = {}
    for (mod, srcs, cpp, ld), idxs in modules.items():
        provers = [i for i in idxs if _is_prover_check_item(items[i])]
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
        if provers:
            mod_kwargs["reach_functions"] = sorted({items[i]["function"] for i in provers})
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
        if "reach_functions" in call_kwargs and not _supports_kwarg(_run_parent_reverify, "reach_functions"):
            call_kwargs.pop("reach_functions", None)
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
    return [(idxs, reason) for (idxs, _), (ok, reason) in zip(checks, outcomes, strict=True) if not ok]


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
        return {
            "ok": len(failed_results) == 0,
            "batch_verified": not skip_reverify,
            "bisected": False,
            "merged": merged_results,
            "failed": failed_results,
            "deduplicated_declarations": _dedup_union(merged_results),
        }

    # Verify the combined tree. Failed checks reject the overlays they implicate; the snapshot is
    # restored, the rest re-spliced and re-verified, until a round passes (a fixpoint: dropping a
    # callee's contract can break a caller's proof). Every failing round removes at least one
    # overlay, so this ends within len(spliced_entries) + 1 rounds.
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
        for idxs, reason in failures:
            for i in idxs:
                (hard if len(idxs) == 1 else ambiguous).setdefault(i, reason)
        for i in hard:
            ambiguous.pop(i, None)
        for i, reason in hard.items():
            item, res = active[i]
            failed_results.append(_rejected_result(item, res, reason))
            _drop_patch(run_dir, res)
        for i, reason in ambiguous.items():
            # A module guardrail failed with several overlays of that module in the batch: none can
            # be blamed yet, so each is retried alone on top of the converged tree.
            deferred.append((active[i][0], reason))
            _drop_patch(run_dir, active[i][1])
        remaining = [item for i, (item, _) in enumerate(active) if i not in hard and i not in ambiguous]
        _restore_snapshot()
        active, splice_failures = _splice_batch(run_dir, overlay, remaining)
        failed_results.extend(splice_failures)

    merged_results = []
    for item, r in active:
        if verify_hook is None and item["role"] == "prover" and item.get("function"):
            r["parent_wp_report"] = _parent_wp_report_rel(item["agent_id"], item["function"])
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


def _resolve_brief_template(role: str) -> str:
    filename_map = {
        "architect": "header_architect_brief.md",
        "prover": "prover_brief.md",
        "breaker": "breaker_brief.md",
        "verifier": "crash_verifier_brief.md",
    }
    fname = filename_map[role]
    here = Path(__file__).resolve().parent
    for base in (here.parent / "skills" / "framac-wp", Path("/opt/framac-pipeline/skills/framac-wp")):
        cand = base / fname
        if cand.is_file():
            return cand.read_text(encoding="utf-8")
    raise ArtifactError(f"brief template {fname} not found in skills/framac-wp")


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
    record = _load_function_facts(overlay, module, c_file, function)
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
) -> dict:
    """
    Initialize an agent's scratch directory/overlay and render its populated brief markdown
    file (`agents/<agent-id>/brief.md`) from `callgraph_dag.json`, `coverage-ledger.json`,
    `workspace/harnesses/harness_<mod>.json`, and `workspace/reports/eva/<mod>.json`.

    `wp_report` names the WP report whose unproven goals the brief lists (a breaker gets the
    stalled prover's report); the default is `workspace/reports/wp/<function>.json`.
    `requests` are strengthening requests a negotiating callee prover must answer; they are
    appended to its brief.
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

    raw_sources = (
        hmeta.get("sources")
        or (dag_mods.get(module or "", {}).get("files") if module else [])
        or ([norm_c_file] if norm_c_file else [])
    )
    scratch_sources_list: list[str] = []
    module_sources_list: list[str] = []
    merge_sources_list: list[str] = []
    harness_files = {f"harness_{m}.c" for m in [*([module] if module else []), *harness_names]}
    for raw_s in raw_sources:
        norm_s = re.sub(r"^/framac-run/", "", (raw_s or "").replace("\\", "/").strip())
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

    eff_cppflags = cppflags if cppflags is not None else (hmeta.get("cppflags") or "-I.")
    eff_ldflags = ldflags if ldflags is not None else (hmeta.get("ldflags") or "")

    # The sidecar's header is the name the harness includes; the brief needs the file in the tree.
    header_flags = _module_header_flags(overlay, module, eff_cppflags)
    if role == "prover":
        norm_header = _prover_header(run_dir, overlay / "work", norm_c_file, function, norm_header, header_flags)
    else:
        norm_header = _resolve_include_header(run_dir, overlay / "work", norm_header, header_flags)

    # Eva reports are per harness: a link unit's are those of its harnesses.
    eva_reports = [
        rep
        for name in dict.fromkeys([*([module] if module else []), *harness_names])
        for rep in [load_json_optional(overlay / "reports" / "eva" / f"{name}.json", {})]
        if isinstance(rep, dict) and rep
    ]
    wp_report_rel: str | None = None
    wp_data: dict = {}
    if wp_report:
        wp_report_path = Path(wp_report) if Path(wp_report).is_absolute() else run_dir / wp_report
        wp_data = load_json_optional(wp_report_path, {})
        wp_report_rel = wp_report.replace("\\", "/")
    elif function:
        wp_data = load_json_optional(overlay / "reports" / "wp" / f"{function}.json", {})

    unknown_obligations: list = []
    for eva_report in eva_reports if function else []:
        raw_unknowns = (eva_report.get("unknown_obligations_by_function") or {}).get(function, [])
        rows = [
            a for a in raw_unknowns if not (norm_c_file and isinstance(a, dict)) or eva_alarm_in_file(a, norm_c_file)
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
    max_wall_clock_s = 900
    max_wp_invocations = effective_max_retries + 2
    if role == "prover":
        if max_retries == 4 and (profile == "quick" or verifiability == "shell_unverifiable_wp"):
            effective_max_retries = 2
        elif max_retries == 4 and profile == "deep":
            effective_max_retries = 6
        env_wall = (os.environ.get("FRAMAC_PROVER_WALL_BUDGET_S") or "").strip()
        if env_wall.isdigit() and int(env_wall) > 0:
            max_wall_clock_s = int(env_wall)
        elif verifiability == "shell_unverifiable_wp":
            max_wall_clock_s = 300
        else:
            max_wall_clock_s = PROVER_WALL_BUDGET_S.get(profile, PROVER_WALL_BUDGET_S["standard"])
        max_wp_invocations = effective_max_retries + 2
        budget_payload = {
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
            "wp_invocations": 0,
            "first_wp_at": None,
        }
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
            run_dir, overlay, agent_root, agent_id, module, function, norm_c_file, norm_header, eff_cppflags, dag_fns
        )
        tpl = function_facts.render_conditionals(tpl, features)
        if spec_kb.enabled():
            record = _load_function_facts(overlay, module, norm_c_file, function)
            kb_section = spec_kb.kb_section_for(overlay, record)
    replacements = {
        "{agent_id}": agent_id,
        "{module_name}": module or "unknown",
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
        "{references_dir}": _brief_path(
            os.environ.get("FRAMAC_REFERENCES_HOST")
            or str(Path(__file__).resolve().parent.parent / "docs" / "references")
        ),
    }
    rendered = tpl
    for k, v in replacements.items():
        rendered = rendered.replace(k, v)
    # After substitution, like what is appended below: source text and reports are data, never placeholders.
    rendered = rendered.replace(function_facts.CONTEXT_SENTINEL + "\n\n", context_section and context_section + "\n")
    rendered = rendered.replace(spec_kb.KB_SENTINEL + "\n\n", kb_section and kb_section + "\n")
    if role == "prover" and (verifiability != "core_provable" or wp_blockers or wp_notes or profile == "quick"):
        fn_label = function or "this function"
        rendered += (
            "\n## WP Verifiability & Iteration Budget\n\n"
            f"- **Static WP Verifiability Classification:** `{verifiability}`\n"
            f"- **Detected WP Blockers:** `{json.dumps(wp_blockers)}`\n"
            f"- **Detected WP Notes:** `{json.dumps(wp_notes)}`\n"
            f"- **Enforced Budget (`agents/{agent_id}/scratch/.prover_budget.json`):** "
            f"at most `{max_wp_invocations}` `run_wp_function.py` invocations and `{max_wall_clock_s}s` wall-clock.\n"
        )
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

    synced: list[str] = []
    for root, _, files in os.walk(work_dir):
        for fname in sorted(files):
            work_file = Path(root) / fname
            if work_file.suffix.lower() not in SOURCE_EXTS:
                continue
            rel_path = work_file.relative_to(work_dir)
            base_file = baseline_dir / rel_path
            target_file = target_dir / rel_path

            work_bytes = work_file.read_bytes()
            base_bytes = base_file.read_bytes() if base_file.exists() else b""
            if work_bytes != base_bytes:
                target_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(work_file, target_file)
                synced.append(str(rel_path).replace("\\", "/"))

    return {"applied_in_place": synced, "count": len(synced)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manage the run's workspace/ shadow overlay and agent overlays.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init")
    p_init.add_argument("--target", type=Path, required=True)
    p_init.add_argument("--overlay", type=Path, default=Path("workspace"))
    p_init.add_argument("--force", action="store_true")

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
    p_merge.add_argument("--sources", nargs="*", default=None)
    p_merge.add_argument("--cppflags", default="-I.")
    p_merge.add_argument("--ldflags", default="", help="Extra linker flags for parent guardrail")
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
            )
        elif args.cmd == "check-acsl-only":
            res = check_acsl_only(args.overlay, args.work_dir, args.file or None)
            print(json.dumps(res, indent=2))
            return 0 if res["ok"] else 1
        elif args.cmd == "merge-agent":
            res = merge_agent_overlay(
                run_dir=args.run_dir,
                agent_id=args.agent_id,
                role=args.role,
                overlay_dir=args.overlay,
                c_file=args.file,
                function=args.function,
                header_file=args.header,
                module=args.module,
                sources=args.sources,
                cppflags=args.cppflags,
                ldflags=args.ldflags,
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
