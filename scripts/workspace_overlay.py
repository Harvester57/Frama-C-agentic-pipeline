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
4. `apply-in-place` is a host-side step run after the final report.
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

from acsl_ast import (  # noqa: E402
    AcslError,
    ScopeViolationError,
    dedup_acsl_declarations,
    extract_top_level_acsl_declarations,
    splice_prover_changes,
    verify_acsl_only,
)
from framac_common import (  # noqa: E402
    ArtifactError,
    is_safe_agent_id,
    is_safe_relative_path,
    load_agent_result_json,
    load_json_optional,
)


SOURCE_EXTS = {".c", ".h", ".acsl", ".i"}
ACSL_CHECK_EXTS = {".c", ".h"}
BUILD_FILES = {"compile_commands.json", "Makefile", "GNUmakefile", "CMakeLists.txt"}
_WORK_PREFIX_RE = re.compile(
    r"^(?:/framac-run/)?(?:workspace/(?:work|baseline)/|agents/[A-Za-z0-9_-]+/scratch/(?:work|base)/|/target/)"
)


class StaleBaselineError(RuntimeError):
    """The target changed after the overlay baseline was captured."""


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

    to_copy: List[Tuple[Path, Path]] = []
    stale: List[str] = []
    for root, dirs, files in os.walk(target_dir):
        rel_root = Path(root).relative_to(target_dir)
        dirs[:] = [
            d for d in dirs
            if not d.startswith(".framac") and d not in {".git", "__pycache__", "build_framac"}
        ]
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

    copied_files: List[str] = []
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
    }
    (overlay_dir / "overlay_meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    return meta


def init_agent_overlay(run_dir: Path, agent_id: str, overlay_dir: Optional[Path] = None) -> dict:
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
        shutil.copytree(shared_work, dest)
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    _rewrite_compile_commands(scratch_work / "compile_commands.json", shared_work, scratch_work)

    return {
        "agent_id": agent_id,
        "scratch_work": str(scratch_work.relative_to(run_dir)).replace("\\", "/"),
        "scratch_base": str(scratch_base.relative_to(run_dir)).replace("\\", "/"),
        "artifacts_dir": str(artifacts_dir.relative_to(run_dir)).replace("\\", "/"),
    }


def check_acsl_only(
    overlay_dir: Path,
    work_dir: Optional[Path] = None,
    files: Optional[List[str]] = None,
) -> dict:
    """Verify that work_dir (default: overlay_dir/work) differs from overlay_dir/baseline only in ACSL comments."""
    overlay_dir = overlay_dir.resolve()
    baseline_dir = overlay_dir / "baseline"
    target_work = (work_dir or (overlay_dir / "work")).resolve()

    errors: List[str] = []
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
            errors.append(f"{rel_str}: new source file created outside baseline")
            continue
        if base_file.is_file() and not work_file.is_file():
            errors.append(f"{rel_str}: baseline source file deleted")
            continue
        if not base_file.is_file():
            continue
        base_text = base_file.read_text(encoding="utf-8", errors="replace")
        work_text = work_file.read_text(encoding="utf-8", errors="replace")
        checked += 1
        if base_text != work_text:
            errors.extend(verify_acsl_only(base_text, work_text, path=rel_str))

    return {"ok": len(errors) == 0, "checked_files": checked, "errors": errors}


def _collect_changed_files(base_dir: Path, work_dir: Path) -> List[str]:
    changed: List[str] = []
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


def _collect_existing_header_declarations(work_dir: Path, exclude_rels: set[str]) -> set[str]:
    """Collect top-level ACSL declaration profile keys from all `.h`/`.acsl` files in `work_dir` except `exclude_rels`."""
    names: set[str] = set()
    if not work_dir.is_dir():
        return names
    for root, _, files in os.walk(work_dir):
        for fname in sorted(files):
            p = Path(root) / fname
            if p.suffix.lower() not in {".h", ".acsl"}:
                continue
            rel = p.relative_to(work_dir).as_posix()
            if rel in exclude_rels:
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
                for decl in extract_top_level_acsl_declarations(text, path=rel):
                    names.add(decl.get("profile_key") or decl["name"])
            except Exception:
                continue
    return names


def _run_parent_reverify(
    run_dir: Path,
    agent_id: str,
    role: str,
    overlay_dir: Path,
    c_file: Optional[str],
    function: Optional[str],
    module: Optional[str],
    sources: Optional[List[str]],
    cppflags: str,
    ldflags: str = "",
) -> Tuple[bool, str]:
    """Run dynamic guardrail (and WP for provers) on the merged workspace/work/ tree."""
    scripts_dir = Path(__file__).resolve().parent
    work_dir = overlay_dir / "work"

    if module and sources:
        harness = overlay_dir / "harnesses" / f"harness_{module}.c"
        corpus = overlay_dir / "corpus" / module
        guard_bin = run_dir / "agents" / agent_id / "scratch" / f"parent_guard_{function or module}"
        guard_scratch = run_dir / "agents" / agent_id / "scratch" / "parent_guard"
        guard_json = run_dir / "agents" / agent_id / "scratch" / f"parent_guard_{function or module}.json"
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
            "--cppflags",
            cppflags,
            "--out-json",
            str(guard_json),
        ]
        if ldflags:
            cmd.extend(["--ldflags", ldflags])
        proc = subprocess.run(cmd, cwd=str(run_dir), capture_output=True, text=True)
        if proc.returncode != 0 or not guard_json.is_file():
            return False, f"parent guardrail failed (rc={proc.returncode}): {proc.stderr.strip() or proc.stdout.strip()}"
        report = json.loads(guard_json.read_text(encoding="utf-8"))
        if report.get("status") != "passed_dynamic_oracle":
            return False, f"parent guardrail returned status={report.get('status')!r}"

    if role == "prover" and c_file and function:
        norm_c = _normalize_work_relpath(c_file)
        wp_out_dir = run_dir / "agents" / agent_id / "scratch" / "parent_wp"
        wp_json = overlay_dir / "reports" / "wp" / f"{function}.json"
        cmd = [
            sys.executable,
            str(scripts_dir / "run_wp_function.py"),
            "--file",
            str(work_dir / norm_c),
            "--function",
            function,
            "--out-dir",
            str(wp_out_dir),
            "--cppflags",
            cppflags,
            "--out-json",
            str(wp_json),
        ]
        proc = subprocess.run(cmd, cwd=str(run_dir), capture_output=True, text=True)
        if proc.returncode != 0 or not wp_json.is_file():
            return False, f"parent WP check failed (rc={proc.returncode}): {proc.stderr.strip() or proc.stdout.strip()}"
        wp_report = json.loads(wp_json.read_text(encoding="utf-8"))
        if wp_report.get("status") != "all_proven":
            return False, f"parent WP check on merged tree returned status={wp_report.get('status')!r}"

    return True, "verified"


def merge_agent_overlay(
    run_dir: Path,
    agent_id: str,
    role: str,
    overlay_dir: Optional[Path] = None,
    c_file: Optional[str] = None,
    function: Optional[str] = None,
    header_file: Optional[str] = None,
    module: Optional[str] = None,
    sources: Optional[List[str]] = None,
    cppflags: str = "-I.",
    ldflags: str = "",
    skip_reverify: bool = False,
    verify_hook: Optional[Callable[[], Tuple[bool, str]]] = None,
) -> dict:
    """
    Validate an agent's scratch overlay (ACSL-only + role/function scope), structurally
    splice its annotations into workspace/work/, deduplicate shared ACSL declarations across
    headers, re-verify on the merged tree (rolling back on failure), and write the resulting
    unified diff into agents/<id>/artifacts/.
    """
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
            # Auto-infer sibling header when the prover also updated its function prototype contract
            sibling_h = Path(norm_c_file).with_suffix(".h").as_posix()
            if sibling_h in changed_rels:
                norm_header_file = sibling_h
            else:
                stem_matches = [
                    r for r in changed_rels
                    if r.endswith(".h") and Path(r).stem == Path(norm_c_file).stem
                ]
                if len(stem_matches) == 1:
                    norm_header_file = stem_matches[0]
        if norm_header_file:
            allowed_rels.add(norm_header_file)

    disallowed = [r for r in changed_rels if r not in allowed_rels]
    if disallowed:
        raise ScopeViolationError(
            f"agent {agent_id} ({role}) modified files outside allowed scope {sorted(allowed_rels)}: {disallowed}"
        )

    # Save backup of shared_work files for atomic rollback
    backups: Dict[str, bytes] = {}
    new_contents: Dict[str, str] = {}
    deduplicated_declarations: List[str] = []

    for rel_str in changed_rels:
        base_snap_text = (scratch_base / rel_str).read_text(encoding="utf-8")
        agent_text = (scratch_work / rel_str).read_text(encoding="utf-8")
        curr_file = shared_work / rel_str
        curr_text = curr_file.read_text(encoding="utf-8")
        baseline_text = (baseline_dir / rel_str).read_text(encoding="utf-8")
        backups[rel_str] = curr_file.read_bytes()

        # Check ACSL-only against baseline first
        acsl_errs = verify_acsl_only(baseline_text, agent_text, path=rel_str)
        if acsl_errs:
            raise AcslError(f"ACSL-only check failed on {rel_str}:\n  " + "\n  ".join(acsl_errs))

        is_hdr = rel_str.endswith(".h")
        if role == "architect":
            if curr_text != base_snap_text:
                raise ScopeViolationError(f"{rel_str}: header modified concurrently since architect started")
            spliced = agent_text
        else:
            spliced = splice_prover_changes(
                base_work_text=base_snap_text,
                agent_work_text=agent_text,
                current_work_text=curr_text,
                function_name=function or "",
                is_header=is_hdr,
                path=rel_str,
            )

        if is_hdr:
            existing_names = _collect_existing_header_declarations(shared_work, {rel_str})
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

    # Write spliced contents to workspace/work/
    for rel_str, text in new_contents.items():
        (shared_work / rel_str).write_text(text, encoding="utf-8")

    patch_stem = function if role == "prover" and function else Path(norm_header_file or "header").stem
    patch_path = artifacts_dir / f"{patch_stem}.patch"

    # Parent-side re-verification on the merged workspace/work/ tree
    if not skip_reverify:
        if verify_hook is not None:
            ok, reason = verify_hook()
        else:
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
            )
        if not ok:
            for rel_str, raw in backups.items():
                (shared_work / rel_str).write_bytes(raw)
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

    # Export unified diff of the agent's change to agents/<agent-id>/artifacts/
    diff_chunks: List[str] = []
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

    return {
        "ok": True,
        "rolled_back": False,
        "agent_id": agent_id,
        "modified_files": changed_rels,
        "deduplicated_declarations": deduplicated_declarations,
        "patch_artifact": patch_path.relative_to(run_dir).as_posix(),
    }


def _enrich_batch_entry(
    run_dir: Path,
    overlay: Path,
    raw_entry: dict,
    default_role: Optional[str],
    default_module: Optional[str],
    default_sources: Optional[List[str]],
    default_cppflags: Optional[str],
    default_ldflags: str,
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
        ledger_units = load_json_optional(run_dir / "coverage-ledger.json", [])
        for u in ledger_units:
            if u.get("function") == function:
                module = u.get("module")
                if not c_file:
                    c_file = u.get("file")
                break

    hmeta: dict = {}
    if module:
        hmeta = load_json_optional(overlay / "harnesses" / f"harness_{module}.json", {})

    sources = entry.get("sources") or default_sources or hmeta.get("sources")
    cppflags = entry.get("cppflags") or default_cppflags or hmeta.get("cppflags") or "-I."
    ldflags = entry.get("ldflags") if entry.get("ldflags") is not None else (default_ldflags or hmeta.get("ldflags") or "")

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
    }


def merge_agent_batch(
    run_dir: Path,
    entries: List[dict],
    overlay_dir: Optional[Path] = None,
    cppflags: Optional[str] = None,
    ldflags: str = "",
    skip_reverify: bool = False,
    verify_hook: Optional[Callable[[dict], Tuple[bool, str]]] = None,
    default_role: Optional[str] = None,
    default_module: Optional[str] = None,
    default_sources: Optional[List[str]] = None,
) -> dict:
    """
    Merge a batch of architect or prover overlays onto `workspace/work/`, deduplicating
    shared ACSL declarations across headers and running a single E-ACSL guardrail per
    unique module (plus WP per prover). If the combined guardrail/WP fails, automatically
    bisects by rolling back and testing each overlay individually so good overlays succeed.
    """
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
        )
        for e in entries
    ]

    # Snapshot all files in shared_work prior to batch splicing
    batch_backups: Dict[str, bytes] = {}
    for root, _, files in os.walk(shared_work):
        for fname in files:
            p = Path(root) / fname
            if p.suffix.lower() in SOURCE_EXTS:
                batch_backups[p.relative_to(shared_work).as_posix()] = p.read_bytes()

    spliced_entries: List[Tuple[dict, dict]] = []
    failed_results: List[dict] = []
    all_deduped: List[str] = []

    for item in enriched:
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
            )
            for d in res.get("deduplicated_declarations", []):
                if d not in all_deduped:
                    all_deduped.append(d)
            spliced_entries.append((item, res))
        except (OverlayMergeError, AcslError, ScopeViolationError, ArtifactError) as exc:
            failed_results.append({
                "ok": False,
                "rolled_back": True,
                "agent_id": item.get("agent_id"),
                "reason": str(exc),
            })

    if skip_reverify or not spliced_entries:
        merged_results = [r for _, r in spliced_entries]
        return {
            "ok": len(failed_results) == 0,
            "batch_verified": not skip_reverify,
            "bisected": False,
            "merged": merged_results,
            "failed": failed_results,
            "deduplicated_declarations": all_deduped,
        }

    # Run 1 guardrail per unique module and 1 WP check per prover on the combined work tree
    batch_ok = True
    batch_fail_reason = ""
    checked_modules: set[Tuple[str, Tuple[str, ...], str, str]] = set()

    for item, _ in spliced_entries:
        if verify_hook is not None:
            ok, reason = verify_hook(item)
            if not ok:
                batch_ok = False
                batch_fail_reason = reason
                break
            continue

        mod = item.get("module")
        srcs = item.get("sources")
        if mod and srcs:
            mod_key = (mod, tuple(srcs), item["cppflags"], item["ldflags"])
            if mod_key not in checked_modules:
                checked_modules.add(mod_key)
                ok, reason = _run_parent_reverify(
                    run_dir=run_dir,
                    agent_id=item["agent_id"],
                    role="architect",
                    overlay_dir=overlay,
                    c_file=None,
                    function=None,
                    module=mod,
                    sources=srcs,
                    cppflags=item["cppflags"],
                    ldflags=item["ldflags"],
                )
                if not ok:
                    batch_ok = False
                    batch_fail_reason = reason
                    break

        if item["role"] == "prover" and item.get("c_file") and item.get("function"):
            ok, reason = _run_parent_reverify(
                run_dir=run_dir,
                agent_id=item["agent_id"],
                role="prover",
                overlay_dir=overlay,
                c_file=item["c_file"],
                function=item["function"],
                module=None,
                sources=None,
                cppflags=item["cppflags"],
                ldflags=item["ldflags"],
            )
            if not ok:
                batch_ok = False
                batch_fail_reason = reason
                break

    if batch_ok:
        merged_results = [r for _, r in spliced_entries]
        return {
            "ok": len(failed_results) == 0,
            "batch_verified": True,
            "bisected": False,
            "merged": merged_results,
            "failed": failed_results,
            "deduplicated_declarations": all_deduped,
        }

    # Automatic Bisection / Isolation Fallback: restore pre-batch snapshot and test each spliced agent individually
    for rel_str, raw in batch_backups.items():
        (shared_work / rel_str).write_bytes(raw)

    merged_results = []
    all_deduped = []
    for item, _ in spliced_entries:
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
        )
        if res["ok"]:
            for d in res.get("deduplicated_declarations", []):
                if d not in all_deduped:
                    all_deduped.append(d)
            merged_results.append(res)
        else:
            failed_results.append(res)

    return {
        "ok": len(failed_results) == 0,
        "batch_verified": True,
        "bisected": True,
        "batch_failure_reason": batch_fail_reason,
        "merged": merged_results,
        "failed": failed_results,
        "deduplicated_declarations": all_deduped,
    }


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


def prepare_agent(
    run_dir: Path,
    agent_id: str,
    role: str,
    overlay_dir: Optional[Path] = None,
    module: Optional[str] = None,
    function: Optional[str] = None,
    c_file: Optional[str] = None,
    header_file: Optional[str] = None,
    max_retries: int = 4,
    candidate_fp: Optional[str] = None,
    cppflags: Optional[str] = None,
    ldflags: Optional[str] = None,
) -> dict:
    """
    Initialize an agent's scratch directory/overlay and render its populated brief markdown
    file (`agents/<agent-id>/brief.md`) from `callgraph_dag.json`, `coverage-ledger.json`,
    `workspace/harnesses/harness_<mod>.json`, and `workspace/reports/eva/<mod>.json`.
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
        overlay_info = init_agent_overlay(run_dir, agent_id, overlay)
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

    if function and function in dag_fns:
        fn_meta = dag_fns[function]
        if not norm_c_file and fn_meta.get("file"):
            norm_c_file = _normalize_work_relpath(fn_meta["file"])
        if not module and fn_meta.get("module"):
            module = fn_meta["module"]

    fn_units = [u for u in ledger_units if function and u.get("function") == function]
    if fn_units:
        if not norm_c_file and fn_units[0].get("file"):
            norm_c_file = _normalize_work_relpath(fn_units[0]["file"])
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

    hmeta: dict = {}
    if module:
        hmeta = load_json_optional(overlay / "harnesses" / f"harness_{module}.json", {})

    if not norm_header:
        if norm_c_file:
            cand_h = Path(norm_c_file).with_suffix(".h").as_posix()
            if (overlay / "work" / cand_h).is_file():
                norm_header = cand_h
        if not norm_header and hmeta.get("header"):
            norm_header = _normalize_work_relpath(hmeta["header"])

    raw_sources = hmeta.get("sources") or (dag_mods.get(module or "", {}).get("files") if module else []) or ([norm_c_file] if norm_c_file else [])
    scratch_sources_list: List[str] = []
    module_sources_list: List[str] = []
    merge_sources_list: List[str] = []
    harness_name = f"harness_{module}.c" if module else ""
    for raw_s in raw_sources:
        norm_s = re.sub(r"^/framac-run/", "", (raw_s or "").replace("\\", "/").strip())
        if not norm_s:
            continue
        if harness_name and Path(norm_s).name == harness_name:
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

    eva_report = load_json_optional(overlay / "reports" / "eva" / f"{module}.json", {}) if module else {}
    wp_report = load_json_optional(overlay / "reports" / "wp" / f"{function}.json", {}) if function else {}

    unknown_obligations = []
    if isinstance(eva_report, dict) and function:
        unknown_obligations = eva_report.get("unknown_obligations_by_function", {}).get(function, [])

    unproven_goals = wp_report.get("unproven_goals", []) if isinstance(wp_report, dict) else []
    if not unproven_goals and unknown_obligations:
        unproven_goals = unknown_obligations

    sec_props = []
    wave_index = 0
    untrusted_entries = []
    if function and function in dag_fns:
        sec_props = dag_fns[function].get("security_properties", [])
        wave_index = dag_fns[function].get("wave", 0)
    elif module:
        for fn_name, fmeta in dag_fns.items():
            if fmeta.get("module") == module:
                for sp in fmeta.get("security_properties", []):
                    if sp not in sec_props:
                        sec_props.append(sp)
                if fmeta.get("is_entry") or fn_name == hmeta.get("entry_fn"):
                    untrusted_entries.append(fn_name)

    reachability = "untrusted_surface"
    if hmeta.get("reachability") == "internal_api":
        reachability = "internal_api"
    elif function and hmeta.get("entry_fn") and function != hmeta.get("entry_fn"):
        reachability = "internal_api"

    coverage_ids = [u["coverage_id"] for u in fn_units if u.get("status") not in ("out_of_scope", "not_applicable")]

    cand_short = "candidate"
    if candidate_fp:
        raw_short = candidate_fp.split("::")[-1] if "::" in candidate_fp else candidate_fp
        cand_short = re.sub(r"[^A-Za-z0-9_.-]+", "_", raw_short).strip("_")[:40] or "candidate"

    tpl = _resolve_brief_template(role)
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
        "{ldflags}": eff_ldflags,
        "{security_properties_json}": json.dumps(sec_props),
        "{untrusted_entry_functions_json}": json.dumps(untrusted_entries),
        "{coverage_ids_json}": json.dumps(coverage_ids),
        "{unknown_obligations_json}": json.dumps(unknown_obligations),
        "{reachability}": reachability,
        "{max_retries}": str(max_retries),
        "{unproven_goals_json}": json.dumps(unproven_goals),
        "{candidate_fingerprint}": candidate_fp or "",
        "{candidate_short}": cand_short,
        "{candidate_json}": json.dumps(cand_obj),
        "{target_dir}": str(run_meta.get("target_dir") or "/target"),
        "{run_dir}": str(run_dir),
    }
    rendered = tpl
    for k, v in replacements.items():
        rendered = rendered.replace(k, v)

    brief_path = agent_root / "brief.md"
    brief_path.parent.mkdir(parents=True, exist_ok=True)
    brief_path.write_text(rendered, encoding="utf-8")

    merge_cmd: Optional[str] = None
    src_args = f" --sources {' '.join(merge_sources_list)}" if merge_sources_list else ""
    ld_args = f" --ldflags '{eff_ldflags}'" if eff_ldflags else ""
    if role == "architect":
        merge_cmd = (
            f"python3 /opt/framac-pipeline/scripts/workspace_overlay.py merge-agent "
            f"--agent-id {agent_id} --role architect --header {norm_header or '<header>'} "
            f"--module {module or '<mod>'}{src_args} --cppflags '{eff_cppflags}'{ld_args}"
        )
    elif role == "prover":
        hdr_arg = f" --header {norm_header}" if norm_header else ""
        merge_cmd = (
            f"python3 /opt/framac-pipeline/scripts/workspace_overlay.py merge-agent "
            f"--agent-id {agent_id} --role prover --file {norm_c_file or '<file>'} "
            f"--function {function or '<fn>'}{hdr_arg} "
            f"--module {module or '<mod>'}{src_args} --cppflags '{eff_cppflags}'{ld_args}"
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
        **overlay_info,
    }


def export_diff(overlay_dir: Path, out_patch: Path) -> dict:
    overlay_dir = overlay_dir.resolve()
    baseline_dir = overlay_dir / "baseline"
    work_dir = overlay_dir / "work"
    contracts_dir = overlay_dir / "contracts"
    contracts_dir.mkdir(parents=True, exist_ok=True)

    diff_chunks: List[str] = []
    modified_files: List[str] = []

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
    return {
        "patch_file": str(out_patch),
        "modified_files": modified_files,
        "modified_count": len(modified_files),
    }


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

    synced: List[str] = []
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


def main(argv: Optional[List[str]] = None) -> int:
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

    args = parser.parse_args(argv)
    try:
        if args.cmd == "init":
            res = init_overlay(args.target, args.overlay, args.force)
        elif args.cmd == "init-agent":
            res = init_agent_overlay(args.run_dir, args.agent_id, args.overlay)
        elif args.cmd == "prepare-agent":
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
            )
            print(json.dumps(res, indent=2))
            return 0 if res["ok"] else 1
        elif args.cmd == "merge-batch":
            batch_entries: List[dict] = []
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

