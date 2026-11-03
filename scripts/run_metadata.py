#!/usr/bin/env python3
"""
Creates and updates run-metadata.json (parent-only).

  init        --repo NAME [--target /target] [--profile standard] [--scope PATH ...]
              [--budget N] [--prior-run PATH ...]
  set-status  --status in_progress|complete|incomplete [--reason TEXT] [--snapshot]
  snapshot    [--run-dir DIR] [--out PATH]
  show

The run id is the run directory name (run-<N>). The source ref is read from the
target's git metadata without modifying it. Toolchain versions and the available
sandbox mode are recorded so later runs can decide whether carried evidence is
still comparable, together with the host path of the run dir (FRAMAC_RUN_HOST) and
the resources the container measured (scripts/resources.py probe).
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from framac_common import (  # noqa: E402
    ArtifactError,
    atomic_write_json,
    is_safe_relative_path,
    load_json_optional,
    load_json_strict,
    utc_now,
)
from validate_artifacts import validate_metadata, validate_snapshot_manifest  # noqa: E402

META = Path("run-metadata.json")
SNAPSHOT_MANIFEST = Path("state/snapshot-manifest.json")
SNAPSHOT_CORE_FILES = ("coverage-ledger.json", "candidates.json", "findings.json")
SNAPSHOT_DIRS = ("workspace/reports", "workspace/crashes", "workspace/work")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _run(cmd: list[str], cwd: str | None = None) -> str | None:
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout.strip() if proc.returncode == 0 else None


def source_ref(target: str) -> dict:
    git = ["git", "-c", "safe.directory=*", "-C", target]
    commit = _run(git + ["rev-parse", "HEAD"])
    if commit is not None:
        status = _run(git + ["status", "--porcelain", "--untracked-files=no"])
        return {"vcs": "git", "commit": commit, "dirty": bool(status) if status is not None else None}
    env_commit = (os.environ.get("FRAMAC_TARGET_COMMIT") or "").strip()
    if env_commit:
        env_dirty = (os.environ.get("FRAMAC_TARGET_DIRTY") or "").strip().lower()
        dirty_val: bool | None = (
            True if env_dirty in ("1", "true", "yes") else (False if env_dirty in ("0", "false", "no") else None)
        )
        return {"vcs": "git", "commit": env_commit, "dirty": dirty_val}
    return {"vcs": "none", "commit": None, "dirty": None}


def toolchain() -> dict:
    versions = {}
    for name, cmd in (
        ("frama-c", ["frama-c", "-version"]),
        ("alt-ergo", ["alt-ergo", "--version"]),
        ("z3", ["z3", "--version"]),
        ("cvc5", ["cvc5", "--version"]),
        ("clang", ["clang", "--version"]),
    ):
        out = _run(cmd)
        versions[name] = out.splitlines()[0] if out else None
    return versions


OUTER_SANDBOXES = ("docker-hardened", "podman-hardened")


def outer_sandbox() -> str:
    """The hardened engine the wrapper started this container with (FRAMAC_OUTER_SANDBOX), else 'unknown'."""
    value = (os.environ.get("FRAMAC_OUTER_SANDBOX") or "").strip()
    return value if value in OUTER_SANDBOXES else "unknown"


def resources_summary() -> dict | None:
    """
    Compact view of the resources this container measured, plus under `pool` the node pool the
    host broker measured (FRAMAC_POOL_*), which this container's own lease is only a slice of.
    Never fails init.
    """
    try:
        from resources import parse_mem, probe

        summary = probe(scope="container").summary()
    except Exception:
        return None

    raw_cpus = (os.environ.get("FRAMAC_POOL_CPUS") or "").strip()
    raw_mem = (os.environ.get("FRAMAC_POOL_MEM_MB") or os.environ.get("FRAMAC_POOL_MEMORY") or "").strip()

    pool_cpus: int | None = None
    if raw_cpus:
        try:
            val = float(raw_cpus)
            if val > 0:
                pool_cpus = int(round(val))
        except ValueError:
            pass

    pool_mem = parse_mem(raw_mem) if raw_mem else None

    if pool_cpus is not None and pool_mem is not None and pool_cpus > 0 and pool_mem > 0:
        summary["pool"] = {"cpus": pool_cpus, "mem_mb": pool_mem, "source": "host broker"}
    else:
        try:
            host_b = probe(scope="host").budget()
            summary["pool"] = {
                "cpus": pool_cpus if (pool_cpus and pool_cpus > 0) else host_b.cpus,
                "mem_mb": pool_mem if (pool_mem and pool_mem > 0) else host_b.mem_mb,
                "source": f"host probe ({host_b.source})",
            }
        except Exception:
            try:
                mach_b = probe(scope="machine").budget()
                summary["pool"] = {
                    "cpus": pool_cpus if (pool_cpus and pool_cpus > 0) else mach_b.cpus,
                    "mem_mb": pool_mem if (pool_mem and pool_mem > 0) else mach_b.mem_mb,
                    "source": f"machine probe ({mach_b.source})",
                }
            except Exception:
                container_b = probe(scope="container").budget()
                summary["pool"] = {
                    "cpus": pool_cpus if (pool_cpus and pool_cpus > 0) else container_b.cpus,
                    "mem_mb": pool_mem if (pool_mem and pool_mem > 0) else container_b.mem_mb,
                    "source": f"container probe ({container_b.source})",
                }
    return summary


def inner_sandbox() -> str:
    """'rlimits' inside the container (POSIX), otherwise 'unknown'."""
    try:
        from sandbox_exec import SandboxUnavailable, sandbox_mode

        try:
            return sandbox_mode()
        except SandboxUnavailable:
            return "unknown"
    except Exception:
        return "unknown"


def write(meta: dict, path: Path = META) -> None:
    errors = validate_metadata(meta)
    if errors:
        raise ArtifactError("invalid run metadata:\n  " + "\n  ".join(errors))
    atomic_write_json(path, meta)


def verify_prior_run_snapshot(prior_dir: Path) -> None:
    """
    Verify that a prior run directory's snapshot manifest (when present) matches its on-disk files.
    Raises ArtifactError if a snapshotted file or digest was mutated after completion.
    """
    prior_dir = Path(prior_dir)
    if not prior_dir.is_dir():
        raise ArtifactError(f"prior run directory does not exist: {prior_dir}")
    prior_meta = load_json_optional(prior_dir / META, None)
    snap_rel = (prior_meta.get("snapshot_manifest") if isinstance(prior_meta, dict) else None) or str(SNAPSHOT_MANIFEST)
    snap_path = prior_dir / snap_rel
    if not snap_path.exists() and not (isinstance(prior_meta, dict) and prior_meta.get("snapshot_manifest")):
        return
    if not snap_path.is_file():
        raise ArtifactError(f"prior run {prior_dir}: snapshot manifest {snap_rel} is missing")
    snap_data = load_json_strict(snap_path)
    errors = validate_snapshot_manifest(snap_data, prior_dir)
    if isinstance(prior_meta, dict) and prior_meta.get("snapshot_digest"):
        if snap_data.get("manifest_sha256") != prior_meta.get("snapshot_digest"):
            errors.add("manifest_sha256 does not match run-metadata.json snapshot_digest")
    if errors:
        raise ArtifactError(f"prior run {prior_dir} failed snapshot integrity check:\n  " + "\n  ".join(errors))


def cmd_init(
    repo: str,
    target: str,
    profile: str,
    scope: list[str],
    budget: int | None,
    prior: list[str],
    run_id: str | None = None,
) -> dict:
    if META.exists():
        raise ArtifactError(f"{META} already exists; a run directory is initialized once")
    resolved_run_id = (run_id or os.environ.get("FRAMAC_RUN_ID") or Path.cwd().name).strip()
    if not re.match(r"^run-[0-9]+$", resolved_run_id):
        raise ArtifactError(
            f"run_id must match run-<N> (via --run-id, FRAMAC_RUN_ID, or working directory name), got {resolved_run_id!r}"
        )
    for p in prior:
        verify_prior_run_snapshot(Path(p))
    now = utc_now()
    meta = {
        "schema_version": 1,
        "run_id": resolved_run_id,
        "repo": repo,
        "target": os.environ.get("FRAMAC_TARGET_HOST") or target,
        "source_ref": source_ref(target),
        "profile": profile,
        "scope_paths": scope,
        "budget": budget,
        "execution_policy": "sandboxed-local-only",
        "sandbox": {
            "outer": outer_sandbox(),
            "inner": inner_sandbox(),
        },
        "prior_runs": prior,
        "toolchain": toolchain(),
        "run_dir_host": (os.environ.get("FRAMAC_RUN_HOST") or "").strip() or None,
        "run_status": "in_progress",
        "incomplete_reason": None,
        "created_at": now,
        "updated_at": now,
    }
    summary = resources_summary()
    if summary is not None:
        meta["resources"] = summary
    write(meta)
    return meta


def build_snapshot_manifest(run_dir: Path = Path(".")) -> dict:
    """
    Build a content-addressed snapshot manifest of a run directory's core artifacts
    (`coverage-ledger.json`, `candidates.json`, `findings.json`), referenced tool reports,
    and `workspace/{reports,crashes,work}` files.
    """
    run_dir = Path(run_dir).resolve()
    meta_path = run_dir / META
    meta = load_json_strict(meta_path) if meta_path.is_file() else {}
    rel_paths: set[str] = set()

    for name in SNAPSHOT_CORE_FILES:
        if (run_dir / name).is_file():
            rel_paths.add(name)

    for sub in SNAPSHOT_DIRS:
        base = run_dir / sub
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*")):
            if p.is_file() and not p.is_symlink() and not p.name.startswith("."):
                rel_paths.add(p.relative_to(run_dir).as_posix())

    # Include any tool_output or reproducer paths referenced in ledger, candidates, or findings.
    ledger = load_json_optional(run_dir / "coverage-ledger.json", [])
    if isinstance(ledger, list):
        for unit in ledger:
            if not isinstance(unit, dict):
                continue
            for ev in unit.get("evidence") or []:
                if isinstance(ev, dict) and isinstance(ev.get("tool_output"), str):
                    rel_paths.add(ev["tool_output"].replace("\\", "/"))
    candidates = load_json_optional(run_dir / "candidates.json", [])
    if isinstance(candidates, list):
        for cand in candidates:
            if not isinstance(cand, dict):
                continue
            for t in cand.get("tool_outputs") or []:
                if isinstance(t, str):
                    rel_paths.add(t.replace("\\", "/"))
            for rep in cand.get("reproducers") or []:
                if isinstance(rep, str):
                    rel_paths.add(rep.replace("\\", "/"))
                elif isinstance(rep, dict) and isinstance(rep.get("input"), str):
                    rel_paths.add(rep["input"].replace("\\", "/"))
    findings = load_json_optional(run_dir / "findings.json", [])
    if isinstance(findings, list):
        for rec in findings:
            if not isinstance(rec, dict):
                continue
            for ev in rec.get("evidence") or []:
                if isinstance(ev, dict) and isinstance(ev.get("tool_output"), str):
                    rel_paths.add(ev["tool_output"].replace("\\", "/"))
            for t in rec.get("tool_outputs") or []:
                if isinstance(t, str):
                    rel_paths.add(t.replace("\\", "/"))
            for rep in rec.get("reproducers") or []:
                if isinstance(rep, str):
                    rel_paths.add(rep.replace("\\", "/"))
                elif isinstance(rep, dict) and isinstance(rep.get("input"), str):
                    rel_paths.add(rep["input"].replace("\\", "/"))
            harness = rec.get("harness")
            if isinstance(harness, dict) and isinstance(harness.get("file"), str):
                rel_paths.add(harness["file"].replace("\\", "/"))
            remediation = rec.get("remediation")
            if isinstance(remediation, dict) and isinstance(remediation.get("fix_patch"), str):
                rel_paths.add(remediation["fix_patch"].replace("\\", "/"))

    files_map: dict[str, dict] = {}
    for rel in sorted(rel_paths):
        if not is_safe_relative_path(rel):
            continue
        full = (run_dir / rel).resolve()
        try:
            full.relative_to(run_dir)
        except ValueError:
            continue
        if not full.is_file() or full.is_symlink():
            continue
        files_map[rel] = {
            "sha256": _sha256_file(full),
            "size": full.stat().st_size,
        }

    manifest_sha256 = hashlib.sha256(json.dumps(files_map, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {
        "schema_version": 1,
        "run_id": meta.get("run_id") or run_dir.name,
        "generated_at": utc_now(),
        "manifest_sha256": manifest_sha256,
        "files": files_map,
    }


def cmd_snapshot(run_dir: Path = Path("."), out_path: Path | None = None) -> dict:
    run_dir = Path(run_dir).resolve()
    target = (Path(out_path) if out_path is not None else (run_dir / SNAPSHOT_MANIFEST)).resolve()
    try:
        rel_manifest = target.relative_to(run_dir).as_posix()
    except ValueError as exc:
        raise ArtifactError(
            f"snapshot manifest destination {target} must be inside the run directory {run_dir}"
        ) from exc
    if not is_safe_relative_path(rel_manifest):
        raise ArtifactError(f"snapshot manifest destination {target} is not a safe relative path under {run_dir}")
    manifest = build_snapshot_manifest(run_dir)
    atomic_write_json(target, manifest)
    meta_path = run_dir / META
    if meta_path.is_file():
        meta = load_json_strict(meta_path)
        meta["snapshot_manifest"] = rel_manifest
        meta["snapshot_digest"] = manifest["manifest_sha256"]
        meta["updated_at"] = utc_now()
        write(meta, meta_path)
    return manifest


def cmd_set_status(status: str, reason: str | None, snapshot: bool = False) -> dict:
    meta = load_json_strict(META)
    meta["run_status"] = status
    meta["incomplete_reason"] = reason if status == "incomplete" else None
    meta["updated_at"] = utc_now()
    if not snapshot:
        meta["snapshot_manifest"] = None
        meta["snapshot_digest"] = None
        snap_path = Path(SNAPSHOT_MANIFEST)
        if snap_path.is_file():
            with contextlib.suppress(OSError):
                snap_path.unlink()
    write(meta)
    if snapshot:
        cmd_snapshot(Path("."))
        meta = load_json_strict(META)
    return meta


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manage run-metadata.json and run snapshot manifests.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init")
    p.add_argument("--repo", required=True)
    p.add_argument("--run-id", default=None, help="Explicit run-<N> identifier (overrides FRAMAC_RUN_ID and cwd name)")
    p.add_argument("--target", default="/target")
    p.add_argument("--profile", choices=["quick", "standard", "deep"], default="standard")
    p.add_argument("--scope", action="append", default=[])
    p.add_argument("--budget", type=int, default=None)
    p.add_argument("--prior-run", action="append", default=[])
    for status_cmd in ("set-status", "finalize"):
        p = sub.add_parser(status_cmd)
        p.add_argument(
            "--status",
            required=(status_cmd == "set-status"),
            default="complete" if status_cmd == "finalize" else None,
            choices=["in_progress", "complete", "incomplete"],
        )
        p.add_argument("--reason", default=None)
        p.add_argument("--snapshot", action="store_true", help="Also emit state/snapshot-manifest.json")
    p = sub.add_parser("snapshot", help="Write state/snapshot-manifest.json for the run directory")
    p.add_argument("--run-dir", type=Path, default=Path("."))
    p.add_argument("--out", type=Path, default=None)
    sub.add_parser("show")
    args = parser.parse_args(argv)
    try:
        if args.cmd == "init":
            out = cmd_init(args.repo, args.target, args.profile, args.scope, args.budget, args.prior_run, args.run_id)
        elif args.cmd in ("set-status", "finalize"):
            out = cmd_set_status(args.status, args.reason, snapshot=args.snapshot)
        elif args.cmd == "snapshot":
            out = cmd_snapshot(args.run_dir, args.out)
        else:
            out = load_json_strict(META)
    except ArtifactError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        return 1
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
