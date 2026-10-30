#!/usr/bin/env python3
"""
Safe parent-side artifact, seed, and crash promotion from agents/<agent-id>/scratch/.

Enforces the security-audit promotion invariants:
1. Canonical lowercase agent_id and safe relative source path under agents/<agent-id>/scratch/.
2. Component-by-component os.lstat traversal check rejecting symlinks at every prefix.
3. Regular-file check (S_ISREG) and hardlink check (st_nlink == 1 on POSIX).
4. Explicit per-file and per-agent byte caps (64 KiB/seed or crash, 32 seeds/agent,
   1 MiB/artifact, 4 MiB total artifacts/agent).
5. Post-open fstat verification (TOCTOU guard on st_dev, st_ino, st_size).
6. Content-addressed SHA-256 naming for seeds and crashes + atomic temp-file replacement.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from framac_common import ArtifactError, is_safe_agent_id, is_safe_relative_path  # noqa: E402

MAX_SEED_BYTES = 64 * 1024
MAX_SEEDS_PER_AGENT = 32
MAX_ARTIFACT_BYTES = 1024 * 1024
MAX_AGENT_TOTAL_BYTES = 4 * 1024 * 1024


class PromotionError(ArtifactError):
    """Raised when a file in an agent's scratch directory fails safety or size checks."""


def _lstat_walk_no_symlinks(base_dir: Path, rel_path: str) -> os.stat_result:
    """Walk every path component from base_dir down to rel_path using lstat, rejecting symlinks."""
    current = base_dir
    for part in rel_path.split("/"):
        current = current / part
        try:
            st = os.lstat(current)
        except OSError as exc:
            raise PromotionError(f"cannot lstat {rel_path}: {exc}") from exc
        if stat.S_ISLNK(st.st_mode):
            raise PromotionError(f"symlink rejected along promotion path: {current}")
    return st


def _agent_artifacts_bytes(artifacts_dir: Path) -> int:
    if not artifacts_dir.is_dir():
        return 0
    total = 0
    for root, _, files in os.walk(artifacts_dir):
        for fname in files:
            try:
                total += (Path(root) / fname).stat().st_size
            except OSError:
                pass
    return total


def _atomic_write_bytes(dest: Path, blob: bytes) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{dest.name}.", suffix=".tmp", dir=str(dest.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(blob)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, dest)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def promote_file(
    run_dir: Path,
    agent_id: str,
    src_rel: str,
    kind: str = "artifact",
    module: str | None = None,
    dest_name: str | None = None,
) -> dict[str, Any]:
    """
    Validate and promote a single file from agents/<agent_id>/scratch/ into:
    - kind == 'artifact': agents/<agent_id>/artifacts/<dest_name or basename>
    - kind == 'seed':     workspace/corpus/<module>/seed-<sha256[:16]>
    - kind == 'crash':    workspace/crashes/<module>/crash-<sha256[:16]>
    """
    if not is_safe_agent_id(agent_id):
        raise PromotionError(f"invalid agent_id: {agent_id!r}")
    norm_rel = src_rel.replace("\\", "/")
    if not is_safe_relative_path(norm_rel):
        raise PromotionError(f"unsafe relative path: {src_rel!r}")
    expected_prefix = f"agents/{agent_id}/scratch/"
    if not norm_rel.startswith(expected_prefix):
        raise PromotionError(f"source path {norm_rel!r} must reside under {expected_prefix!r}")
    if kind not in ("artifact", "seed", "crash"):
        raise PromotionError(f"unsupported promotion kind: {kind!r}")
    if kind in ("seed", "crash") and not module:
        raise PromotionError(f"promotion kind {kind!r} requires a module name")

    run_dir = run_dir.resolve()
    st_pre = _lstat_walk_no_symlinks(run_dir, norm_rel)
    if not stat.S_ISREG(st_pre.st_mode):
        raise PromotionError(f"{norm_rel}: not a regular file")
    if os.name != "nt" and st_pre.st_nlink != 1:
        raise PromotionError(f"{norm_rel}: hardlinked file rejected (st_nlink={st_pre.st_nlink})")

    max_bytes = MAX_SEED_BYTES if kind in ("seed", "crash") else MAX_ARTIFACT_BYTES
    if st_pre.st_size > max_bytes:
        raise PromotionError(f"{norm_rel}: file size {st_pre.st_size} bytes exceeds limit ({max_bytes} bytes)")

    artifacts_dir = run_dir / "agents" / agent_id / "artifacts"
    if kind == "artifact":
        used = _agent_artifacts_bytes(artifacts_dir)
        if used + st_pre.st_size > MAX_AGENT_TOTAL_BYTES:
            raise PromotionError(
                f"{norm_rel}: cumulative artifacts for {agent_id} would exceed {MAX_AGENT_TOTAL_BYTES} bytes"
            )

    src_abs = run_dir / norm_rel
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(src_abs, flags)
    try:
        st_post = os.fstat(fd)
        if st_post.st_dev != st_pre.st_dev or st_post.st_ino != st_pre.st_ino or st_post.st_size != st_pre.st_size:
            raise PromotionError(f"{norm_rel}: file changed during promotion (TOCTOU detected)")
        blob = os.read(fd, st_pre.st_size + 1)
    finally:
        os.close(fd)

    if len(blob) != st_pre.st_size:
        raise PromotionError(f"{norm_rel}: short or long read ({len(blob)} != {st_pre.st_size})")

    sha256 = hashlib.sha256(blob).hexdigest()
    if kind == "seed":
        dest_rel = f"workspace/corpus/{module}/seed-{sha256[:16]}"
    elif kind == "crash":
        dest_rel = f"workspace/crashes/{module}/crash-{sha256[:16]}"
    else:
        safe_name = dest_name or Path(norm_rel).name
        if "/" in safe_name or "\\" in safe_name or safe_name in (".", ".."):
            raise PromotionError(f"invalid artifact destination name: {safe_name!r}")
        dest_rel = f"agents/{agent_id}/artifacts/{safe_name}"

    _atomic_write_bytes(run_dir / dest_rel, blob)
    return {
        "src": norm_rel,
        "dest": dest_rel,
        "sha256": sha256,
        "size_bytes": len(blob),
    }


def promote_seeds(
    run_dir: Path,
    agent_id: str,
    module: str,
    seed_rels: list[str],
) -> dict[str, Any]:
    """Promote up to MAX_SEEDS_PER_AGENT breaker seeds into workspace/corpus/<module>/."""
    if len(seed_rels) > MAX_SEEDS_PER_AGENT:
        raise PromotionError(f"too many seeds ({len(seed_rels)}) from {agent_id}; limit is {MAX_SEEDS_PER_AGENT}")
    promoted = [promote_file(run_dir, agent_id, s, kind="seed", module=module) for s in seed_rels]
    return {"agent_id": agent_id, "module": module, "promoted": promoted}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Safely promote files from agents/<id>/scratch/.")
    parser.add_argument("--run-dir", type=Path, default=Path("."))
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_art = sub.add_parser("promote-artifact")
    p_art.add_argument("--agent-id", required=True)
    p_art.add_argument("--src", required=True)
    p_art.add_argument("--dest-name", default=None)

    p_seeds = sub.add_parser("promote-seeds")
    p_seeds.add_argument("--agent-id", required=True)
    p_seeds.add_argument("--module", required=True)
    p_seeds.add_argument("seeds", nargs="+")

    p_crash = sub.add_parser("promote-crash")
    p_crash.add_argument("--agent-id", required=True)
    p_crash.add_argument("--module", required=True)
    p_crash.add_argument("--src", required=True)

    args = parser.parse_args(argv)
    try:
        if args.cmd == "promote-artifact":
            out = promote_file(args.run_dir, args.agent_id, args.src, kind="artifact", dest_name=args.dest_name)
        elif args.cmd == "promote-seeds":
            out = promote_seeds(args.run_dir, args.agent_id, args.module, args.seeds)
        else:
            out = promote_file(args.run_dir, args.agent_id, args.src, kind="crash", module=args.module)
    except PromotionError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        return 1

    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
