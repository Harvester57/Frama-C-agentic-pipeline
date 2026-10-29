#!/usr/bin/env python3
"""
Creates and updates run-metadata.json (parent-only).

  init        --repo NAME [--target /target] [--profile standard] [--scope PATH ...]
              [--budget N] [--prior-run PATH ...]
  set-status  --status in_progress|complete|incomplete [--reason TEXT]
  show

The run id is the run directory name (run-<N>). The source ref is read from the
target's git metadata without modifying it. Toolchain versions and the available
sandbox mode are recorded so later runs can decide whether carried evidence is
still comparable.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from framac_common import ArtifactError, atomic_write_json, load_json_strict, utc_now  # noqa: E402
from validate_artifacts import validate_metadata  # noqa: E402

META = Path("run-metadata.json")


def _run(cmd: list[str], cwd: str | None = None) -> str | None:
    try:
        proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout.strip() if proc.returncode == 0 else None


def source_ref(target: str) -> dict:
    git = ["git", "-c", "safe.directory=*", "-C", target]
    commit = _run(git + ["rev-parse", "HEAD"])
    if commit is None:
        return {"vcs": "none", "commit": None, "dirty": None}
    status = _run(git + ["status", "--porcelain", "--untracked-files=no"])
    return {"vcs": "git", "commit": commit, "dirty": bool(status) if status is not None else None}


def toolchain() -> dict:
    versions = {}
    for name, cmd in (
        ("frama-c", ["frama-c", "-version"]),
        ("alt-ergo", ["alt-ergo", "--version"]),
        ("z3", ["z3", "--version"]),
        ("cvc5", ["cvc5", "--version"]),
        ("clang", ["clang", "--version"]),
        ("bwrap", ["bwrap", "--version"]),
    ):
        out = _run(cmd)
        versions[name] = out.splitlines()[0] if out else None
    return versions


def inner_sandbox() -> str:
    try:
        from sandbox_exec import SandboxUnavailable, sandbox_mode
        try:
            return sandbox_mode()
        except SandboxUnavailable:
            return "unknown"
    except Exception:
        return "unknown"


def write(meta: dict) -> None:
    errors = validate_metadata(meta)
    if errors:
        raise ArtifactError("invalid run metadata:\n  " + "\n  ".join(errors))
    atomic_write_json(META, meta)


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
            "outer": "docker-hardened" if os.environ.get("FRAMAC_OUTER_SANDBOX") == "docker-hardened" else "unknown",
            "inner": inner_sandbox(),
        },
        "prior_runs": prior,
        "toolchain": toolchain(),
        "run_status": "in_progress",
        "incomplete_reason": None,
        "created_at": now,
        "updated_at": now,
    }
    write(meta)
    return meta


def cmd_set_status(status: str, reason: str | None) -> dict:
    meta = load_json_strict(META)
    meta["run_status"] = status
    meta["incomplete_reason"] = reason if status == "incomplete" else None
    meta["updated_at"] = utc_now()
    write(meta)
    return meta


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manage run-metadata.json.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init")
    p.add_argument("--repo", required=True)
    p.add_argument("--run-id", default=None, help="Explicit run-<N> identifier (overrides FRAMAC_RUN_ID and cwd name)")
    p.add_argument("--target", default="/target")
    p.add_argument("--profile", choices=["quick", "standard", "deep"], default="standard")
    p.add_argument("--scope", action="append", default=[])
    p.add_argument("--budget", type=int, default=None)
    p.add_argument("--prior-run", action="append", default=[])
    p = sub.add_parser("set-status")
    p.add_argument("--status", required=True, choices=["in_progress", "complete", "incomplete"])
    p.add_argument("--reason", default=None)
    sub.add_parser("show")
    args = parser.parse_args(argv)
    try:
        if args.cmd == "init":
            out = cmd_init(args.repo, args.target, args.profile, args.scope, args.budget, args.prior_run, args.run_id)
        elif args.cmd == "set-status":
            out = cmd_set_status(args.status, args.reason)
        else:
            out = load_json_strict(META)
    except ArtifactError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        return 1
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
