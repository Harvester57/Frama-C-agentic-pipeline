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
import math
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sandbox_exec  # noqa: E402
from framac_common import ArtifactError, is_safe_agent_id, is_safe_relative_path  # noqa: E402
from fuzz_common import SANITIZER_RUNTIME_ENV  # noqa: E402
from resources import FUZZ_RSS_LIMIT_MB  # noqa: E402

MAX_SEED_BYTES = 64 * 1024
MAX_SEEDS_PER_AGENT = 32
MAX_ARTIFACT_BYTES = 1024 * 1024
MAX_AGENT_TOTAL_BYTES = 4 * 1024 * 1024
DEFAULT_SEED_REPLAY_TIMEOUT_S = 5.0
_LIBFUZZER_TIMEOUT_EXITCODE = 70
_LIBFUZZER_ALARM_MARKER = "ALARM: working on the last Unit"
_LIBFUZZER_TIMEOUT_ERROR_MARKER = "ERROR: libFuzzer: timeout"


class PromotionError(ArtifactError):
    """Raised when a file in an agent's scratch directory fails safety or size checks."""


def _lstat_walk_no_symlinks(base_dir: Path, rel_path: str) -> os.stat_result:
    """Walk every path component from base_dir down to rel_path using lstat, rejecting symlinks."""
    current = base_dir
    st: os.stat_result | None = None
    for part in rel_path.split("/"):
        current = current / part
        try:
            st = os.lstat(current)
        except OSError as exc:
            raise PromotionError(f"cannot lstat {rel_path}: {exc}") from exc
        if stat.S_ISLNK(st.st_mode):
            raise PromotionError(f"symlink rejected along promotion path: {current}")
    if st is None:  # str.split always yields at least one part
        raise PromotionError(f"empty promotion path: {rel_path!r}")
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


def check_promotable(
    run_dir: Path, agent_id: str, src_rel: str, kind: str = "artifact", pending_bytes: int = 0
) -> os.stat_result:
    """
    The checks promote_file makes before it reads the file: safe path under agents/<agent_id>/scratch/,
    no symlink, a regular file, the per-file cap of the kind and, for an artifact, the per-agent total
    (`pending_bytes`: artifacts the same result promotes before this one). Raises PromotionError.
    `validate_artifacts.py agent-result` runs it too, so an agent sees what the ingest would refuse.
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

    run_dir = run_dir.resolve()
    st_pre = _lstat_walk_no_symlinks(run_dir, norm_rel)
    if not stat.S_ISREG(st_pre.st_mode):
        raise PromotionError(f"{norm_rel}: not a regular file")
    if os.name != "nt" and st_pre.st_nlink != 1:
        raise PromotionError(f"{norm_rel}: hardlinked file rejected (st_nlink={st_pre.st_nlink})")

    max_bytes = MAX_SEED_BYTES if kind in ("seed", "crash") else MAX_ARTIFACT_BYTES
    if st_pre.st_size > max_bytes:
        raise PromotionError(f"{norm_rel}: file size {st_pre.st_size} bytes exceeds limit ({max_bytes} bytes)")

    if kind == "artifact":
        used = _agent_artifacts_bytes(run_dir / "agents" / agent_id / "artifacts") + pending_bytes
        if used + st_pre.st_size > MAX_AGENT_TOTAL_BYTES:
            raise PromotionError(
                f"{norm_rel}: cumulative artifacts for {agent_id} would exceed {MAX_AGENT_TOTAL_BYTES} bytes"
            )
    return st_pre


def _read_validated_bytes(run_dir: Path, norm_rel: str, st_pre: os.stat_result) -> bytes:
    """Open `run_dir / norm_rel` with O_NOFOLLOW, verify fstat matches `st_pre`, and return its bytes."""
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
    return blob


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
    if kind in ("seed", "crash") and not module:
        raise PromotionError(f"promotion kind {kind!r} requires a module name")
    st_pre = check_promotable(run_dir, agent_id, src_rel, kind)
    norm_rel = src_rel.replace("\\", "/")
    run_dir = run_dir.resolve()
    blob = _read_validated_bytes(run_dir, norm_rel, st_pre)

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


def _timeout_artifacts(run_dir: Path, agent_id: str) -> dict[str, str]:
    """libFuzzer's `timeout-<sha1 of the input>` artifacts in the agent's scratch: {sha1: run-relative path}."""
    scratch = Path(run_dir).resolve() / "agents" / agent_id / "scratch"
    found: dict[str, str] = {}
    for root, _, files in os.walk(scratch):
        for name in sorted(files):
            if name.startswith("timeout-"):
                rel = (Path(root) / name).relative_to(Path(run_dir).resolve()).as_posix()
                found.setdefault(name[len("timeout-") :], rel)
    return found


def _hang_artifact_of(run_dir: Path, agent_id: str, seed_rel: str, artifacts: dict[str, str]) -> str | None:
    """The agent's own timeout artifact for this seed, when it saw the seed hang."""
    norm_rel = seed_rel.replace("\\", "/")
    if Path(norm_rel).name.startswith("timeout-"):
        check_promotable(run_dir, agent_id, norm_rel, "seed")
        return norm_rel
    if not artifacts:
        return None
    st_pre = check_promotable(run_dir, agent_id, norm_rel, "seed")
    blob = _read_validated_bytes(Path(run_dir).resolve(), norm_rel, st_pre)
    return artifacts.get(hashlib.sha1(blob, usedforsecurity=False).hexdigest())


def _format_timeout(timeout_s: float) -> str:
    return f"{timeout_s:g}"


def _discover_fuzz_binary(
    run_dir: Path,
    module: str,
    explicit_binary: Path | str | None = None,
) -> Path | None:
    """
    Locate an existing fuzz binary for `module` to screen seeds before promotion, or None.

    Checks `explicit_binary` first (when supplied), then `workspace/reports/fuzz/<module>.json`
    (`compile.binary` / `binary`), then `workspace/harnesses/fuzz_<module>.e-acsl` and
    `workspace/harnesses/fuzz_<module>`. Never fails when no binary exists on disk.
    """
    root = Path(run_dir).resolve()
    if explicit_binary is not None:
        raw = Path(explicit_binary)
        cand = raw if raw.is_absolute() else (root / raw)
        return cand if cand.is_file() else None

    if not module or "/" in module or "\\" in module or module in (".", "..") or ".." in module:
        return None

    candidates: list[Path] = []
    report_path = root / "workspace" / "reports" / "fuzz" / f"{module}.json"
    if report_path.is_file():
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            report = None
        if isinstance(report, dict):
            compile_info = report.get("compile")
            raw_paths = [
                compile_info.get("binary") if isinstance(compile_info, dict) else None,
                report.get("binary"),
            ]
            for raw_bin in raw_paths:
                if not isinstance(raw_bin, str) or not raw_bin.strip():
                    continue
                p = Path(raw_bin)
                candidates.append(p if p.is_absolute() else (root / p))
                if raw_bin.startswith("/framac-run/"):
                    candidates.append(root / raw_bin[len("/framac-run/") :])

    candidates.append(root / "workspace" / "harnesses" / f"fuzz_{module}.e-acsl")
    candidates.append(root / "workspace" / "harnesses" / f"fuzz_{module}")

    for cand in candidates:
        if cand.is_file():
            return cand
    return None


def _check_seed_hangs(binary: Path, seed_path: Path, timeout_s: float) -> str | None:
    """
    Replay a single seed input through `binary` under `sandbox_exec` with a bounded timeout.

    LibFuzzer is invoked with `-timeout=0` so its periodic SIGALRM timer (`UnitTimeoutSec / 2 + 1`)
    cannot interrupt a blocking `select()`/`poll()`/`sleep()` call with EINTR and make a hanging
    seed exit 0 early; instead `sandbox_exec.run_sandboxed` enforces the wall-clock bound and
    SIGKILLs the process group on timeout. Returns a refusal reason string when the input hangs
    (sandbox wall-timeout, libFuzzer exit code 70, `ALARM: working on the last Unit` /
    `ERROR: libFuzzer: timeout`, or a `timeout-*` artifact). Clean exits (rc 0), normal crashes
    (nonzero rc != 70 without timeout markers), and non-POSIX / non-executable environments return
    None so promotion is never falsely blocked.
    """
    if timeout_s <= 0:
        return None
    wall_timeout = max(1, math.ceil(timeout_s))
    reason = f"seed hung during pre-promotion screen (>{_format_timeout(timeout_s)}s)"
    try:
        seed_bytes = Path(seed_path).read_bytes()
    except OSError:
        return None

    with tempfile.TemporaryDirectory(prefix="framac-seed-screen-") as tmp_str:
        tmp_dir = Path(tmp_str)
        input_copy = tmp_dir / "seed"
        input_copy.write_bytes(seed_bytes)
        cmd = [
            str(Path(binary).resolve()),
            "-runs=1",
            "-timeout=0",
            f"-rss_limit_mb={FUZZ_RSS_LIMIT_MB}",
            f"-artifact_prefix={tmp_dir.as_posix()}/",
            str(input_copy),
        ]
        try:
            res = sandbox_exec.run_sandboxed(
                cmd,
                writable=[tmp_dir],
                timeout_s=wall_timeout,
                cwd=tmp_dir,
                limits=sandbox_exec.Limits(cpu_seconds=max(2, wall_timeout * 2), ignore_sigpipe=True),
                extra_env=SANITIZER_RUNTIME_ENV,
            )
        except (sandbox_exec.SandboxUnavailable, OSError):
            return None

        combined = f"{res.stdout}\n{res.stderr}"
        wrote_timeout = any(p.name.startswith("timeout-") for p in tmp_dir.iterdir() if p.is_file())
        if (
            res.timed_out
            or res.returncode == _LIBFUZZER_TIMEOUT_EXITCODE
            or _LIBFUZZER_ALARM_MARKER in combined
            or _LIBFUZZER_TIMEOUT_ERROR_MARKER in combined
            or wrote_timeout
        ):
            return reason
    return None


def promote_seeds(
    run_dir: Path,
    agent_id: str,
    module: str,
    seed_rels: list[str],
    *,
    binary: Path | str | None = None,
    replay_timeout: float = DEFAULT_SEED_REPLAY_TIMEOUT_S,
) -> dict[str, Any]:
    """
    Promote up to MAX_SEEDS_PER_AGENT breaker seeds into workspace/corpus/<module>/.

    Refuses a seed and records it in `refused_hanging` if:
    1. Its filename starts with `timeout-` or its bytes match a `timeout-<sha1>` artifact left in
       the agent's scratch directory; or
    2. `replay_timeout > 0`, a fuzz binary for `module` is available (supplied via `binary` or
       auto-discovered from `workspace/reports/fuzz/<module>.json` or `workspace/harnesses/`), and
       the bounded single-input replay hangs/times out.
    """
    if len(seed_rels) > MAX_SEEDS_PER_AGENT:
        raise PromotionError(f"too many seeds ({len(seed_rels)}) from {agent_id}; limit is {MAX_SEEDS_PER_AGENT}")
    if replay_timeout < 0:
        raise PromotionError(f"replay_timeout must be >= 0, got {replay_timeout}")
    root = Path(run_dir).resolve()
    artifacts = _timeout_artifacts(root, agent_id)
    fuzz_binary = _discover_fuzz_binary(root, module, binary) if replay_timeout > 0 else None
    bin_label = ""
    if fuzz_binary is not None:
        try:
            bin_label = fuzz_binary.resolve().relative_to(root).as_posix()
        except ValueError:
            bin_label = fuzz_binary.as_posix()

    promoted: list[dict[str, Any]] = []
    refused: list[dict[str, str]] = []
    screened_by_sha256: dict[str, str | None] = {}
    for seed in seed_rels:
        norm_rel = seed.replace("\\", "/")
        st_pre = check_promotable(root, agent_id, norm_rel, "seed")
        artifact = _hang_artifact_of(root, agent_id, norm_rel, artifacts)
        if artifact is not None:
            refused.append({"src": norm_rel, "artifact": artifact})
            continue
        if fuzz_binary is not None:
            blob = _read_validated_bytes(root, norm_rel, st_pre)
            seed_sha = hashlib.sha256(blob).hexdigest()
            if seed_sha not in screened_by_sha256:
                screened_by_sha256[seed_sha] = _check_seed_hangs(fuzz_binary, root / norm_rel, replay_timeout)
            hang_reason = screened_by_sha256[seed_sha]
            if hang_reason is not None:
                refused.append({"src": norm_rel, "reason": hang_reason, "binary": bin_label})
                continue
        promoted.append(promote_file(root, agent_id, norm_rel, kind="seed", module=module))
    return {"agent_id": agent_id, "module": module, "promoted": promoted, "refused_hanging": refused}


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
    p_seeds.add_argument(
        "--binary",
        type=Path,
        default=None,
        help="Optional fuzz binary to screen seeds for hangs before promotion (auto-discovered if omitted)",
    )
    p_seeds.add_argument(
        "--replay-timeout",
        type=float,
        default=DEFAULT_SEED_REPLAY_TIMEOUT_S,
        help="Per-seed replay timeout in seconds to screen hanging seeds (0 disables)",
    )
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
            out = promote_seeds(
                args.run_dir,
                args.agent_id,
                args.module,
                args.seeds,
                binary=args.binary,
                replay_timeout=args.replay_timeout,
            )
        else:
            out = promote_file(args.run_dir, args.agent_id, args.src, kind="crash", module=args.module)
    except PromotionError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        return 1

    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
