#!/usr/bin/env python3
"""
Inner sandbox for target-controlled binaries (LibFuzzer campaigns, guardrail
replays, reproducers, target builds).

Controls applied to every run:
  - bubblewrap: whole filesystem read-only, only the declared writable paths are
    bound read-write, fresh /tmp, network/IPC/UTS/user namespaces unshared,
    process dies with its parent;
  - cleared environment populated only from an explicit allowlist;
  - rlimits on CPU time, file size, open files and process count;
  - wall-clock timeout that kills the whole process group.

RLIMIT_AS is NOT set by default: E-ACSL's shadow memory reserves very large
virtual regions and fails under an address-space limit. Memory is bounded by the
container cgroup (--memory) and by LibFuzzer's -rss_limit_mb instead.

If bubblewrap is unavailable the run fails closed (SandboxUnavailable) unless the
operator sets FRAMAC_SANDBOX_DEGRADED=1, in which case only rlimits, the
environment allowlist and the timeout apply, and the result says "degraded".
"""

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence

DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
OUTPUT_TAIL_BYTES = 8000

# No PID namespace and no fresh /proc: Docker masks parts of /proc, which makes
# `bwrap --proc` fail with EPERM inside a container. /proc stays visible read-only
# through the root bind; the network, IPC, UTS and user namespaces are still unshared.
UNSHARE_FLAGS = ["--unshare-user-try", "--unshare-ipc", "--unshare-net", "--unshare-uts", "--unshare-cgroup-try"]


class SandboxUnavailable(RuntimeError):
    pass


@dataclass
class Limits:
    cpu_seconds: int = 600
    file_size_mb: int = 512
    open_files: int = 1024
    processes: int = 256
    address_space_mb: Optional[int] = None


@dataclass
class SandboxResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool
    sandbox: str
    command: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "returncode": self.returncode,
            "timed_out": self.timed_out,
            "sandbox": self.sandbox,
            "command": self.command,
            "stdout_tail": self.stdout[-OUTPUT_TAIL_BYTES:],
            "stderr_tail": self.stderr[-OUTPUT_TAIL_BYTES:],
        }


_BWRAP_OK: Optional[bool] = None


def bwrap_available() -> bool:
    global _BWRAP_OK
    if _BWRAP_OK is None:
        exe = shutil.which("bwrap")
        if not exe:
            _BWRAP_OK = False
        else:
            try:
                probe = subprocess.run(
                    [exe, *UNSHARE_FLAGS, "--ro-bind", "/", "/", "--dev", "/dev", "--tmpfs", "/tmp", "--die-with-parent", "true"],
                    capture_output=True, timeout=20,
                )
                _BWRAP_OK = probe.returncode == 0
            except (OSError, subprocess.SubprocessError):
                _BWRAP_OK = False
    return _BWRAP_OK


def degraded_allowed() -> bool:
    return os.environ.get("FRAMAC_SANDBOX_DEGRADED", "") == "1"


def sandbox_mode() -> str:
    """'bubblewrap', 'degraded', or raises SandboxUnavailable."""
    if bwrap_available():
        return "bubblewrap"
    if degraded_allowed():
        return "degraded"
    raise SandboxUnavailable(
        "bubblewrap cannot create a sandbox here (missing binary or user namespaces blocked). "
        "Refusing to run target-controlled code. Fix the container (see wrappers/) or set "
        "FRAMAC_SANDBOX_DEGRADED=1 to accept rlimit/env-only isolation; degraded runs are recorded."
    )


def build_env(home: Path, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
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


def build_bwrap_argv(
    argv: Sequence[str],
    writable: Sequence[Path],
    env: Dict[str, str],
    cwd: Path,
    bwrap_exe: str = "bwrap",
) -> List[str]:
    cmd = [bwrap_exe, "--die-with-parent", "--new-session", *UNSHARE_FLAGS, "--ro-bind", "/", "/", "--dev", "/dev", "--tmpfs", "/tmp"]
    for w in writable:
        p = str(Path(w))
        cmd += ["--bind", p, p]
    cmd.append("--clearenv")
    for key in sorted(env):
        cmd += ["--setenv", key, env[key]]
    cmd += ["--chdir", str(cwd), "--"]
    cmd += list(argv)
    return cmd


def _make_preexec(limits: Limits):
    def _apply() -> None:
        import resource  # POSIX only; imported lazily so the module loads on any host

        def _set(which, value):
            if value is not None:
                resource.setrlimit(which, (value, value))

        _set(resource.RLIMIT_CPU, limits.cpu_seconds)
        _set(resource.RLIMIT_FSIZE, limits.file_size_mb * 1024 * 1024 if limits.file_size_mb else None)
        _set(resource.RLIMIT_NOFILE, limits.open_files)
        _set(resource.RLIMIT_NPROC, limits.processes)
        if limits.address_space_mb:
            _set(resource.RLIMIT_AS, limits.address_space_mb * 1024 * 1024)
        _set(resource.RLIMIT_CORE, 0)
    return _apply


def run_sandboxed(
    argv: Sequence[str],
    writable: Sequence[Path],
    timeout_s: int,
    cwd: Optional[Path] = None,
    limits: Optional[Limits] = None,
    extra_env: Optional[Dict[str, str]] = None,
) -> SandboxResult:
    if os.name != "posix":
        raise SandboxUnavailable("sandboxed execution requires a POSIX host (run inside the container)")
    mode = sandbox_mode()
    limits = limits or Limits()
    writable = [Path(w).resolve() for w in writable]
    for w in writable:
        w.mkdir(parents=True, exist_ok=True)
    cwd = Path(cwd).resolve() if cwd else writable[0]
    env = build_env(home=writable[0], extra=extra_env)

    if mode == "bubblewrap":
        cmd = build_bwrap_argv(argv, writable, env, cwd, bwrap_exe=shutil.which("bwrap") or "bwrap")
        popen_env = {"PATH": DEFAULT_PATH}
    else:
        cmd = list(argv)
        popen_env = env

    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd),
        env=popen_env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        preexec_fn=_make_preexec(limits),
    )
    timed_out = False
    try:
        out, err = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        out, err = proc.communicate()
    return SandboxResult(
        returncode=proc.returncode,
        stdout=out.decode("utf-8", errors="replace"),
        stderr=err.decode("utf-8", errors="replace"),
        timed_out=timed_out,
        sandbox=mode,
        command=list(argv),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a target-controlled command in the inner sandbox.")
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
