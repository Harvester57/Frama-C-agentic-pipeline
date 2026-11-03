#!/usr/bin/env python3
"""
Resource-limited execution of target-controlled binaries (LibFuzzer campaigns,
guardrail replays, reproducers, target builds).

Isolation model:
  - The isolation boundary is the hardened outer Docker container started by
    wrappers/framac-docker.{sh,ps1}: no network, all capabilities dropped,
    no-new-privileges, Docker's default seccomp and AppArmor profiles,
    cpu/memory/pids limits, target mounted read-only, only the run directory
    writable.
  - This module is the inner layer. It applies, to every run:
      * a cleared environment populated only from an explicit allowlist;
      * rlimits on CPU time, file size, open files and process count (optional
        address space), and core dumps disabled;
      * a wall-clock timeout that SIGKILLs the whole process group
        (the child is started in its own session).
  - There is NO filesystem isolation inside the container: a target-controlled
    binary can read anything the container user can read and write anywhere
    the container user can write, including the whole run directory.

RLIMIT_AS is NOT set by default: E-ACSL's shadow memory reserves very large
virtual regions and fails under an address-space limit. Memory is bounded by the
container cgroup (--memory) and by LibFuzzer's -rss_limit_mb instead.

Execution requires a POSIX host (i.e. inside the container); elsewhere
SandboxUnavailable is raised and nothing is run.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import signal
import subprocess
import sys
import threading
import typing
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
OUTPUT_TAIL_BYTES = 8000
DEFAULT_MAX_HEAD_BYTES = 64 * 1024
DEFAULT_MAX_TAIL_BYTES = 2 * 1024 * 1024
SANDBOX_MODE = "rlimits"


class SandboxUnavailable(RuntimeError):
    pass


@dataclass
class Limits:
    cpu_seconds: int = 600
    file_size_mb: int = 512
    open_files: int = 1024
    processes: int = 256
    address_space_mb: int | None = None


@dataclass
class SandboxResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool
    sandbox: str
    command: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "returncode": self.returncode,
            "timed_out": self.timed_out,
            "sandbox": self.sandbox,
            "command": self.command,
            "stdout_tail": self.stdout[-OUTPUT_TAIL_BYTES:],
            "stderr_tail": self.stderr[-OUTPUT_TAIL_BYTES:],
        }


def sandbox_mode() -> str:
    """'rlimits' on a POSIX host; raises SandboxUnavailable elsewhere."""
    if os.name != "posix":
        raise SandboxUnavailable("sandboxed execution requires a POSIX host (run inside the container)")
    return SANDBOX_MODE


def build_env(home: Path, extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {
        "PATH": DEFAULT_PATH,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": str(home),
        "TMPDIR": "/tmp",
    }
    for key, value in (extra or {}).items():
        if not key or "=" in key or "\x00" in key or "\x00" in str(value):
            raise ValueError(f"invalid environment entry {key!r}")
        env[key] = str(value)
    return env


def _make_preexec(limits: Limits):
    def _apply() -> None:
        import resource  # POSIX only; imported lazily so the module loads on any host

        def _set(which, value):
            if value is not None:
                resource.setrlimit(which, (value, value))  # type: ignore[attr-defined]

        _set(resource.RLIMIT_CPU, limits.cpu_seconds)  # type: ignore[attr-defined]
        _set(resource.RLIMIT_FSIZE, limits.file_size_mb * 1024 * 1024 if limits.file_size_mb else None)  # type: ignore[attr-defined]
        _set(resource.RLIMIT_NOFILE, limits.open_files)  # type: ignore[attr-defined]
        _set(resource.RLIMIT_NPROC, limits.processes)  # type: ignore[attr-defined]
        if limits.address_space_mb:
            _set(resource.RLIMIT_AS, limits.address_space_mb * 1024 * 1024)  # type: ignore[attr-defined]
        _set(resource.RLIMIT_CORE, 0)  # type: ignore[attr-defined]

    return _apply


class BoundedStreamDrainer:
    """
    Reads a stream continuously in chunks to prevent pipe deadlocks,
    retaining head and rolling tail chunks to bound total memory to O(1).
    """

    def __init__(
        self,
        stream: typing.IO[bytes] | None,
        head_limit: int = DEFAULT_MAX_HEAD_BYTES,
        tail_limit: int = DEFAULT_MAX_TAIL_BYTES,
    ) -> None:
        self.stream = stream
        self.head_limit = head_limit
        self.tail_limit = tail_limit
        self.head = bytearray()
        self.tail_chunks: collections.deque[bytes] = collections.deque()
        self.tail_len = 0
        self.total_bytes = 0

    def run(self) -> None:
        if self.stream is None:
            return
        chunk_size = 65536
        try:
            while True:
                chunk = self.stream.read(chunk_size)
                if not chunk:
                    break
                self.total_bytes += len(chunk)
                if len(self.head) < self.head_limit:
                    needed = self.head_limit - len(self.head)
                    self.head.extend(chunk[:needed])
                self.tail_chunks.append(chunk)
                self.tail_len += len(chunk)
                while self.tail_chunks and (self.tail_len - len(self.tail_chunks[0])) >= self.tail_limit:
                    self.tail_len -= len(self.tail_chunks.popleft())
        except OSError:
            pass

    def get_bytes(self) -> bytes:
        if self.total_bytes <= self.tail_limit:
            return b"".join(self.tail_chunks)
        tail_bytes = b"".join(self.tail_chunks)
        if len(tail_bytes) > self.tail_limit:
            tail_bytes = tail_bytes[-self.tail_limit:]
        if self.total_bytes <= len(self.head) + len(tail_bytes):
            overlap = len(self.head) + len(tail_bytes) - self.total_bytes
            return bytes(self.head) + tail_bytes[overlap:]
        omitted = self.total_bytes - len(self.head) - len(tail_bytes)
        marker = (
            b"\n... [output truncated: "
            + str(omitted).encode("ascii")
            + b" bytes omitted] ...\n"
        )
        return bytes(self.head) + marker + tail_bytes


def run_sandboxed(
    argv: Sequence[str],
    writable: Sequence[Path],
    timeout_s: int,
    cwd: Path | None = None,
    limits: Limits | None = None,
    extra_env: dict[str, str] | None = None,
) -> SandboxResult:
    mode = sandbox_mode()  # raises SandboxUnavailable on non-POSIX hosts
    limits = limits or Limits()
    writable = [Path(w).resolve() for w in writable]
    for w in writable:
        w.mkdir(parents=True, exist_ok=True)
    cwd = Path(cwd).resolve() if cwd else writable[0]
    env = build_env(home=writable[0], extra=extra_env)

    proc = subprocess.Popen(
        list(argv),
        cwd=str(cwd),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        preexec_fn=_make_preexec(limits),
    )
    drainer_out = BoundedStreamDrainer(proc.stdout)
    drainer_err = BoundedStreamDrainer(proc.stderr)
    t_out = threading.Thread(target=drainer_out.run, daemon=True)
    t_err = threading.Thread(target=drainer_err.run, daemon=True)
    t_out.start()
    t_err.start()

    timed_out = False
    try:
        proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(proc.pid, signal.SIGKILL)  # type: ignore[attr-defined]
        except (ProcessLookupError, AttributeError):
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass

    t_out.join(timeout=5.0)
    t_err.join(timeout=5.0)
    try:
        if proc.stdout:
            proc.stdout.close()
    except OSError:
        pass
    try:
        if proc.stderr:
            proc.stderr.close()
    except OSError:
        pass

    out_bytes = drainer_out.get_bytes()
    err_bytes = drainer_err.get_bytes()

    return SandboxResult(
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout=out_bytes.decode("utf-8", errors="replace"),
        stderr=err_bytes.decode("utf-8", errors="replace"),
        timed_out=timed_out,
        sandbox=mode,
        command=list(argv),
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a target-controlled command with rlimits, an environment allowlist and a timeout."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("probe", help="Report which sandbox mode is available")
    p_run = sub.add_parser("run")
    p_run.add_argument("--writable", type=Path, action="append", required=True)
    p_run.add_argument("--cwd", type=Path, default=None)
    p_run.add_argument("--timeout", type=int, default=300)
    p_run.add_argument("--cpu", type=int, default=600)
    p_run.add_argument("--setenv", action="append", default=[], help="KEY=VALUE allowlisted variable")
    p_run.add_argument("argv", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    if args.cmd == "probe":
        try:
            print(json.dumps({"sandbox": sandbox_mode()}))
            return 0
        except SandboxUnavailable as exc:
            print(json.dumps({"sandbox": "unavailable", "reason": str(exc)}))
            return 1

    argv = args.argv[1:] if args.argv and args.argv[0] == "--" else args.argv
    if not argv:
        parser.error("missing command after --")
    extra = dict(item.split("=", 1) for item in args.setenv)
    try:
        res = run_sandboxed(argv, args.writable, args.timeout, args.cwd, Limits(cpu_seconds=args.cpu), extra)
    except SandboxUnavailable as exc:
        print(json.dumps({"status": "sandbox_unavailable", "reason": str(exc)}))
        return 3
    print(json.dumps(res.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
