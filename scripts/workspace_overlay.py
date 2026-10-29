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
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

from acsl_ast import AcslError, ScopeViolationError, splice_prover_changes, verify_acsl_only  # noqa: E402
from framac_common import ArtifactError, is_safe_agent_id, is_safe_relative_path  # noqa: E402


SOURCE_EXTS = {".c", ".h", ".acsl", ".i"}
ACSL_CHECK_EXTS = {".c", ".h"}
BUILD_FILES = {"compile_commands.json", "Makefile", "GNUmakefile", "CMakeLists.txt"}


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
        work_sources = [str(work_dir / s) for s in sources] + [str(harness)]
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
        proc = subprocess.run(cmd, cwd=str(run_dir), capture_output=True, text=True)
        if proc.returncode != 0 or not guard_json.is_file():
            return False, f"parent guardrail failed (rc={proc.returncode}): {proc.stderr.strip() or proc.stdout.strip()}"
        report = json.loads(guard_json.read_text(encoding="utf-8"))
        if report.get("status") != "passed_dynamic_oracle":
            return False, f"parent guardrail returned status={report.get('status')!r}"

    if role == "prover" and c_file and function:
        wp_out_dir = run_dir / "agents" / agent_id / "scratch" / "parent_wp"
        wp_json = overlay_dir / "reports" / "wp" / f"{function}.json"
        cmd = [
            sys.executable,
            str(scripts_dir / "run_wp_function.py"),
            "--file",
            str(work_dir / c_file),
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
    skip_reverify: bool = False,
    verify_hook: Optional[Callable[[], Tuple[bool, str]]] = None,
) -> dict:
    """
    Validate an agent's scratch overlay (ACSL-only + role/function scope), structurally
    splice its annotations into workspace/work/, re-verify on the merged tree (rolling
    back on failure), and write the resulting unified diff into agents/<id>/artifacts/.
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

    changed_rels = _collect_changed_files(scratch_base, scratch_work)
    allowed_rels = set()
    if role == "architect":
        if not header_file:
            raise ArtifactError("architect merge requires header_file")
        allowed_rels.add(header_file.replace("\\", "/"))
    else:
        if not c_file or not function:
            raise ArtifactError("prover merge requires c_file and function")
        allowed_rels.add(c_file.replace("\\", "/"))
        if header_file:
            allowed_rels.add(header_file.replace("\\", "/"))

    disallowed = [r for r in changed_rels if r not in allowed_rels]
    if disallowed:
        raise ScopeViolationError(
            f"agent {agent_id} ({role}) modified files outside allowed scope {sorted(allowed_rels)}: {disallowed}"
        )

    # Save backup of shared_work files for atomic rollback
    backups: Dict[str, bytes] = {}
    new_contents: Dict[str, str] = {}

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

        if role == "architect":
            if curr_text != base_snap_text:
                raise ScopeViolationError(f"{rel_str}: header modified concurrently since architect started")
            spliced = agent_text
        else:
            is_hdr = rel_str.endswith(".h")
            spliced = splice_prover_changes(
                base_work_text=base_snap_text,
                agent_work_text=agent_text,
                current_work_text=curr_text,
                function_name=function or "",
                is_header=is_hdr,
                path=rel_str,
            )

        # Verify merged text against baseline
        merged_errs = verify_acsl_only(baseline_text, spliced, path=rel_str)
        if merged_errs:
            raise AcslError(f"Merged ACSL-only check failed on {rel_str}:\n  " + "\n  ".join(merged_errs))
        new_contents[rel_str] = spliced

    # Write spliced contents to workspace/work/
    for rel_str, text in new_contents.items():
        (shared_work / rel_str).write_text(text, encoding="utf-8")

    # Parent-side re-verification on the merged workspace/work/ tree
    if not skip_reverify:
        if verify_hook is not None:
            ok, reason = verify_hook()
        else:
            ok, reason = _run_parent_reverify(
                run_dir, agent_id, role, overlay, c_file, function, module, sources, cppflags
            )
        if not ok:
            for rel_str, raw in backups.items():
                (shared_work / rel_str).write_bytes(raw)
            return {
                "ok": False,
                "rolled_back": True,
                "agent_id": agent_id,
                "modified_files": changed_rels,
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

    patch_stem = function if role == "prover" and function else Path(header_file or "header").stem
    patch_path = artifacts_dir / f"{patch_stem}.patch"
    patch_path.write_text("\n".join(diff_chunks), encoding="utf-8")

    return {
        "ok": True,
        "rolled_back": False,
        "agent_id": agent_id,
        "modified_files": changed_rels,
        "patch_artifact": patch_path.relative_to(run_dir).as_posix(),
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
    p_merge.add_argument("--skip-reverify", action="store_true")

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
                skip_reverify=args.skip_reverify,
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
