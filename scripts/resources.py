#!/usr/bin/env python3
"""
Resource measurement, job sizing and leasing for the Frama-C pipeline (stdlib only).

The pipeline never assumes a machine size: every decision re-measures what this process may
actually use (cgroup v1/v2 limits walked up the hierarchy, CPU affinity and cpusets,
/proc/meminfo, Slurm allocations, user caps, the container engine's own view), so CPUs or
memory added to or removed from the node take effect on the next job.

Stable API (other scripts depend on it):
  job_budget()        -> Budget(cpus, mem_mb, source)  this job's CPUs and memory
  wp_parallelism()    -> int   -wp-par for a WP run under the current budget
  fuzz_workers()      -> int   LibFuzzer workers under the current budget
  pool_budget()       -> Budget  the whole pool (FRAMAC_POOL_* from the host broker, else the probe)
  recommend()         -> dict  pool, make_jobs, max_agents, per-class nominal grants, warnings
  infer_class(cmd)    -> str   job class of a container command line
  probe(scope)        -> Pool  the full measurement: sources, reserve, topology, engine view, warnings
  CLASSES[name]       -> JobClass

Leases (one protocol, two brokers):
  run     container broker: CPU+memory sub-leases inside one container (Make recipes)
  exec    host broker: one lease per container, sizing the `<engine> run` command line
  record  per-container usage (called by scripts/container_entry.sh) -> state/resource-history/
  status / gc   list leases / reclaim the leases of dead holders
  probe   the full measurement, for troubleshooting

Knobs: FRAMAC_POOL_CPUS / FRAMAC_POOL_MEMORY (caps), FRAMAC_RESERVE_CPUS / FRAMAC_RESERVE_MEMORY
(absolute or N%), FRAMAC_PIN=auto|on|off, FRAMAC_BROKER_DIR, FRAMAC_CACHE_DIR (or 'off'),
FRAMAC_ALLOW_UNENFORCED_LIMITS=1, FRAMAC_MAX_AGENTS, FRAMAC_RESOURCES_VERBOSE=1. Containers receive
FRAMAC_JOB_CPUS/_MEM_MB/_CLASS[/_KEY], FRAMAC_POOL_CPUS/_MEM_MB, FRAMAC_IMAGE_ID, FRAMAC_CACHE_MODE and,
when the shared store is mounted, FRAMAC_SHARED_CACHE_DIR. Test hooks: FRAMAC_PROBE_ROOT (fake
/proc and /sys tree), FRAMAC_PROBE_MEMO_S (probe memo, default 5 s).

Tool limits that decide results are fixed (WP_MEMLIMIT_MB, FUZZ_RSS_LIMIT_MB): hardware
changes how many provers or fuzz workers run at once, never what a single one may use, so
proofs and findings do not depend on the machine.
"""

from __future__ import annotations

import argparse
import contextlib
import errno
import hashlib
import json
import math
import os
import re
import secrets
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:  # POSIX advisory locks
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]
try:  # Windows byte-range locks
    import msvcrt
except ImportError:  # pragma: no cover - POSIX
    msvcrt = None  # type: ignore[assignment]

# Fixed per-process limits (never scaled with the machine; see module docstring).
WP_MEMLIMIT_MB = 1000
FUZZ_RSS_LIMIT_MB = 2048
FRAMAC_KERNEL_RESERVE_MB = 768
FUZZ_WORKER_OVERHEAD_MB = 512
DEFAULT_PIDS_LIMIT = 4096

PROBE_MEMO_S = 5.0
ENGINE_INFO_MAX_AGE_S = 30.0
HISTORY_DIR = Path("state") / "resource-history"
CONTAINER_CACHE_MOUNT = "/framac-cache"


@dataclass(frozen=True)
class Budget:
    cpus: int
    mem_mb: int
    source: str


@dataclass(frozen=True)
class JobClass:
    name: str
    runs_target_code: bool
    min_cpus: int
    max_cpus: int | None  # None: elastic, up to the pool
    mem_base_mb: int
    mem_per_cpu_mb: int
    gated: bool = True
    idempotent: bool = False
    wall_timeout_s: int | None = None


CLASSES: dict[str, JobClass] = {
    "light": JobClass("light", False, 1, 1, 1024, 0, gated=False, idempotent=True),
    "wp": JobClass("wp", False, 1, 8, FRAMAC_KERNEL_RESERVE_MB, WP_MEMLIMIT_MB, idempotent=True, wall_timeout_s=3600),
    "eva": JobClass("eva", False, 1, 1, 2048, 0, idempotent=True, wall_timeout_s=7200),
    "build": JobClass("build", False, 1, 4, 2048, 0, idempotent=True, wall_timeout_s=3600),
    "guardrail": JobClass("guardrail", True, 1, 2, 2048, 0, wall_timeout_s=1800),
    "fuzz": JobClass(
        "fuzz",
        True,
        1,
        16,
        FUZZ_WORKER_OVERHEAD_MB,
        int(FUZZ_RSS_LIMIT_MB * 1.25),
        wall_timeout_s=None,
    ),
    "replay": JobClass("replay", True, 1, 1, 1024, 0, idempotent=True, wall_timeout_s=1800),
    "selftest": JobClass("selftest", True, 1, 1, 1024, 0, idempotent=True, wall_timeout_s=1800),
    "verify": JobClass("verify", True, 1, None, 2048, 1024),
    "phase-static": JobClass("phase-static", False, 2, None, 2048, 1024),
    "phase-dynamic": JobClass("phase-dynamic", True, 2, None, 2048, 1536),
}

WP_NOMINAL_CPUS = 4
DEFAULT_MAX_AGENTS = 16
AGENT_DUTY = 2.0  # agents spend at least half their time in LLM inference


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _say(message: str) -> None:
    print(f"[resources] {message}", file=sys.stderr, flush=True)


def _is_real_root(root: Path) -> bool:
    return str(root) in ("/", "\\")


def _probe_root(root: Path | str | None = "/") -> Path:
    """The tree probes read: `root`, or FRAMAC_PROBE_ROOT (a test/debug hook) in place of the real '/'."""
    path = Path(root if root is not None else "/")
    override = (os.environ.get("FRAMAC_PROBE_ROOT") or "").strip()
    if override and _is_real_root(path):
        return Path(override)
    return path


def _join(root: Path, abs_path: str) -> Path:
    return Path(root) / abs_path.lstrip("/")


def _read_file(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError, ValueError):
        return None


def _read(root: Path, rel: str) -> str | None:
    return _read_file(_join(Path(root), rel))


def _env_int(name: str) -> int | None:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return None
    try:
        value = int(float(raw))
    except ValueError:
        return None
    return value if value > 0 else None


def _env_float(name: str) -> float | None:
    raw = (os.environ.get(name) or "").strip()
    try:
        value = float(raw) if raw else None
    except ValueError:
        return None
    return value if value is not None and value > 0 else None


def _int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(str(value).strip())
    except ValueError:
        return None


def _fmt_cpus(value: float) -> str:
    v = float(value)
    if abs(v - round(v)) < 1e-9:
        return str(int(round(v)))
    return f"{v:.2f}".rstrip("0").rstrip(".")


def _load_json(path: Path, max_bytes: int = 1 << 20) -> Any:
    try:
        if path.stat().st_size > max_bytes:
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None


def _retry_os(fn: Callable[[], Any], attempts: int = 50) -> Any:
    """Retry an operation that Windows refuses while another process briefly has the file open."""
    for attempt in range(attempts):
        try:
            return fn()
        except PermissionError:
            if attempt == attempts - 1:
                raise
            time.sleep(0.01)
    return None


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(3)}.tmp")
    tmp.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    try:
        _retry_os(lambda: os.replace(tmp, path))
    except OSError:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise


def _unlink(path: Path) -> None:
    def _rm() -> None:
        with contextlib.suppress(FileNotFoundError):
            path.unlink()

    with contextlib.suppress(OSError):
        _retry_os(_rm, attempts=20)


def parse_mem(value: str | int | None) -> int | None:
    """'8g', '512m', '1024' (MiB) or a byte count with a bare 'b' suffix ('1048576b') -> MiB."""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    m = re.fullmatch(r"\s*([0-9]+(?:\.[0-9]+)?)\s*([kKmMgGtT]?)([iI]?)([bB]?)\s*", str(value))
    if not m:
        return None
    num, unit = float(m.group(1)), m.group(2).lower()
    if not unit and m.group(3):
        return None  # 'i' without a unit letter
    if not unit and m.group(4):
        return int(num // (1024 * 1024))  # plain bytes
    factor = {"": 1, "k": 1 / 1024, "m": 1, "g": 1024, "t": 1024 * 1024}[unit]
    return int(num * factor)


def parse_cpu_list(text: str | None) -> list[int]:
    """'0-3,8,10-11' -> [0, 1, 2, 3, 8, 10, 11]."""
    out: list[int] = []
    for part in (text or "").replace("\n", ",").split(","):
        part = part.strip()
        if not part:
            continue
        lo, _, hi = part.partition("-")
        try:
            out.extend(range(int(lo), int(hi or lo) + 1))
        except ValueError:
            continue
    return sorted(set(out))


def format_cpu_list(ids: Iterable[int]) -> str:
    """[0, 1, 2, 3, 8, 10, 11] -> '0-3,8,10-11' (the --cpuset-cpus syntax)."""
    values = sorted(set(ids))
    parts: list[str] = []
    start = prev = None
    for v in values:
        if start is None:
            start = prev = v
        elif v == prev + 1:  # type: ignore[operator]
            prev = v
        else:
            parts.append(f"{start}-{prev}" if start != prev else f"{start}")
            start = prev = v
    if start is not None:
        parts.append(f"{start}-{prev}" if start != prev else f"{start}")
    return ",".join(parts)


def parse_slurm_cpus_per_node(value: str | None, node_index: int = 0) -> int | None:
    """SLURM_JOB_CPUS_PER_NODE ('4(x2),2' -> 4, 4, 2 per node): the count of node `node_index`."""
    counts: list[int] = []
    for part in (value or "").split(","):
        m = re.fullmatch(r"\s*(\d+)(?:\(x(\d+)\))?\s*", part)
        if m:
            counts.extend([int(m.group(1))] * int(m.group(2) or 1))
    if not counts:
        return None
    return counts[node_index] if 0 <= node_index < len(counts) else counts[0]


def slurm_limits(env: dict[str, str] | None = None) -> tuple[int | None, int | None]:
    """(CPUs, MiB) of this node's Slurm allocation, from the SLURM_* environment."""
    env = dict(os.environ) if env is None else env
    node = _int(env.get("SLURM_NODEID")) or 0
    cpu_values = [
        v
        for v in (
            _int(env.get("SLURM_CPUS_ON_NODE")),
            _int(env.get("SLURM_CPUS_PER_TASK")),
            parse_slurm_cpus_per_node(env.get("SLURM_JOB_CPUS_PER_NODE"), node),
        )
        if v and v > 0
    ]
    cpus = min(cpu_values) if cpu_values else None
    mem = _int(env.get("SLURM_MEM_PER_NODE"))
    if not mem:
        per_cpu = _int(env.get("SLURM_MEM_PER_CPU"))
        mem = per_cpu * cpus if per_cpu and cpus else None
    return cpus, (mem if mem and mem > 0 else None)


# ---------------------------------------------------------------------------
# cgroups (v2 hierarchy walk, v1 controllers resolved through the mountinfo root)
# ---------------------------------------------------------------------------

_UNLIMITED_BYTES = 1 << 60
_MIB = 1024 * 1024


@dataclass(frozen=True)
class Mount:
    root: str
    point: str
    fstype: str
    source: str
    options: str


def _unescape(text: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), text)


def parse_mountinfo(root: Path | str = "/") -> list[Mount]:
    """/proc/self/mountinfo as Mount records (mount root, mount point, fs type, source, super options)."""
    out: list[Mount] = []
    for line in (_read(Path(root), "/proc/self/mountinfo") or "").splitlines():
        pre, sep, post = line.partition(" - ")
        fields, tail = pre.split(), post.split()
        if not sep or len(fields) < 5 or not tail:
            continue
        out.append(
            Mount(
                root=_unescape(fields[3]),
                point=_unescape(fields[4]),
                fstype=tail[0],
                source=_unescape(tail[1]) if len(tail) > 1 else "",
                options=tail[2] if len(tail) > 2 else "",
            )
        )
    return out


def _bytes_mb(raw: str | None, ceil: bool = False) -> int | None:
    if raw is None or raw.strip() in ("", "max"):
        return None
    try:
        value = int(raw.split()[0])
    except ValueError:
        return None
    if value <= 0 or value >= _UNLIMITED_BYTES:
        return None
    return -(-value // _MIB) if ceil else value // _MIB


def _cpu_max(raw: str | None) -> float | None:
    if not raw:
        return None
    quota, _, period = raw.partition(" ")
    if quota == "max":
        return None
    try:
        q, p = int(quota), int(period or "100000")
    except ValueError:
        return None
    return q / p if q > 0 and p > 0 else None


def _cfs_quota(d: Path) -> float | None:
    try:
        q, p = int(_read_file(d / "cpu.cfs_quota_us") or ""), int(_read_file(d / "cpu.cfs_period_us") or "")
    except ValueError:
        return None
    return q / p if q > 0 and p > 0 else None


def _kv(text: str | None) -> dict[str, int]:
    out: dict[str, int] = {}
    for line in (text or "").splitlines():
        key, _, value = line.strip().partition(" ")
        with contextlib.suppress(ValueError):
            out[key] = int(value.strip())
    return out


@dataclass
class CgroupView:
    """Limits of this process's cgroup: the minimum over its ancestors (v2) or controller paths (v1)."""

    version: int | None = None
    cpu_quota: float | None = None
    mem_limit_mb: int | None = None
    cpuset: list[int] | None = None
    memory_dir: Path | None = None
    cpu_dir: Path | None = None
    pressure_dir: Path | None = None


def _leaf_dir(root: Path, mount: Mount, path: str) -> Path:
    mroot = mount.root.rstrip("/") or "/"
    if mroot == "/":
        rel = path
    elif path == mroot:
        rel = "/"
    elif path.startswith(mroot + "/"):
        rel = path[len(mroot) :]
    else:
        rel = "/"  # outside the mounted subtree (cgroup namespace, moved process): the mount point is our view
    if ".." in rel.split("/"):
        rel = "/"
    return _join(root, mount.point) / rel.lstrip("/")


def _ancestors(leaf: Path, top: Path) -> list[Path]:
    out = [leaf]
    cur = leaf
    while cur != top and top in cur.parents:
        cur = cur.parent
        out.append(cur)
    return out


def cgroup_view(root: Path | str = "/") -> CgroupView:
    """
    This process's cgroup limits. v2: `/proc/self/cgroup` path under the cgroup2 mount, with
    cpu.max / memory.max / memory.high taken as the minimum over every ancestor up to the mount
    point. v1: each controller's path resolved through its mount root in mountinfo. Without
    /proc/self/cgroup (minimal trees), the classic /sys/fs/cgroup locations are read.
    """
    root = Path(root)
    mounts = parse_mountinfo(root)
    v1: dict[str, tuple[Path, Path]] = {}
    v2: tuple[Path, Path] | None = None
    for line in (_read(root, "/proc/self/cgroup") or "").splitlines():
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        hier, ctrls, path = parts[0], [c for c in parts[1].split(",") if c], parts[2] or "/"
        if hier == "0" and not ctrls:
            m2 = next((m for m in mounts if m.fstype == "cgroup2"), None)
            if m2 is not None:
                v2 = (_leaf_dir(root, m2, path), _join(root, m2.point))
            continue
        for ctrl in ctrls:
            m1 = next((m for m in mounts if m.fstype == "cgroup" and ctrl in m.options.split(",")), None)
            if m1 is not None:
                v1[ctrl] = (_leaf_dir(root, m1, path), _join(root, m1.point))
    if v2 is None and not v1:
        base = _join(root, "/sys/fs/cgroup")
        if any((base / f).exists() for f in ("cgroup.controllers", "cpu.max", "memory.max", "cpuset.cpus.effective")):
            v2 = (base, base)
        else:
            for ctrl, sub in (
                ("memory", "memory"),
                ("cpu", "cpu,cpuacct"),
                ("cpu", "cpu"),
                ("cpuacct", "cpu,cpuacct"),
                ("cpuacct", "cpuacct"),
                ("cpuset", "cpuset"),
            ):
                if ctrl not in v1 and (base / sub).is_dir():
                    v1[ctrl] = (base / sub, base / sub)

    view = CgroupView()
    if {"memory", "cpu"} & set(v1):
        view.version = 1
        if "memory" in v1:
            leaf, top = v1["memory"]
            mems = [_bytes_mb(_read_file(d / "memory.limit_in_bytes")) for d in _ancestors(leaf, top)]
            view.mem_limit_mb = min((m for m in mems if m), default=None)
            view.memory_dir = leaf
        if "cpu" in v1:
            leaf, top = v1["cpu"]
            quotas = [_cfs_quota(d) for d in _ancestors(leaf, top)]
            view.cpu_quota = min((q for q in quotas if q), default=None)
        acct = v1.get("cpuacct") or v1.get("cpu")
        view.cpu_dir = acct[0] if acct else None
        if "cpuset" in v1:
            leaf, _top = v1["cpuset"]
            raw = _read_file(leaf / "cpuset.effective_cpus") or _read_file(leaf / "cpuset.cpus")
            view.cpuset = parse_cpu_list(raw) or None
        return view
    if v2 is not None:
        leaf, top = v2
        view.version = 2
        dirs = _ancestors(leaf, top)
        quotas = [_cpu_max(_read_file(d / "cpu.max")) for d in dirs]
        view.cpu_quota = min((q for q in quotas if q), default=None)
        mems = [_bytes_mb(_read_file(d / name)) for d in dirs for name in ("memory.max", "memory.high")]
        view.mem_limit_mb = min((m for m in mems if m), default=None)
        for d in dirs:
            raw = _read_file(d / "cpuset.cpus.effective")
            if raw:
                view.cpuset = parse_cpu_list(raw) or None
                break
        view.memory_dir = view.cpu_dir = view.pressure_dir = leaf
    return view


def cgroup_stats(root: Path | str = "/") -> dict:
    """Usage of this process's cgroup: peak memory (MiB), OOM kills, CPU time (µs), memory limit."""
    view = cgroup_view(root)
    out: dict[str, Any] = {
        "version": view.version,
        "peak_mb": None,
        "oom_kill": None,
        "cpu_usec": None,
        "limit_mb": view.mem_limit_mb,
    }
    if view.version == 2 and view.memory_dir is not None:
        out["peak_mb"] = _bytes_mb(_read_file(view.memory_dir / "memory.peak"), ceil=True)
        out["oom_kill"] = _kv(_read_file(view.memory_dir / "memory.events")).get("oom_kill")
        out["cpu_usec"] = _kv(_read_file(view.memory_dir / "cpu.stat")).get("usage_usec")
    elif view.version == 1:
        if view.memory_dir is not None:
            out["peak_mb"] = _bytes_mb(_read_file(view.memory_dir / "memory.max_usage_in_bytes"), ceil=True)
            out["oom_kill"] = _kv(_read_file(view.memory_dir / "memory.oom_control")).get("oom_kill")
        if view.cpu_dir is not None:
            usage = _int(_read_file(view.cpu_dir / "cpuacct.usage"))
            out["cpu_usec"] = usage // 1000 if usage is not None else None
    return out


# Compatibility helpers (single-value views of cgroup_view()).
def cgroup_cpu_limit(root: Path | str) -> float | None:
    return cgroup_view(root).cpu_quota


def cgroup_mem_limit_mb(root: Path | str) -> int | None:
    return cgroup_view(root).mem_limit_mb


def cpuset_cpus(root: Path | str) -> int | None:
    ids = cgroup_view(root).cpuset
    return len(ids) if ids else None


# ---------------------------------------------------------------------------
# Machine: CPUs, memory, pressure, topology, filesystems
# ---------------------------------------------------------------------------


def meminfo_mb(root: Path) -> dict[str, int]:
    info: dict[str, int] = {}
    for line in (_read(root, "/proc/meminfo") or "").splitlines():
        key, _, rest = line.partition(":")
        num = rest.strip().split(" ")[0]
        if num.isdigit():
            info[key.strip()] = int(num) // 1024
    return info


def _windows_memory() -> tuple[int | None, int | None]:
    """(total, available) physical memory in MiB via GlobalMemoryStatusEx."""
    try:
        import ctypes

        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        stat = MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):  # type: ignore[attr-defined]
            return int(stat.ullTotalPhys // _MIB), int(stat.ullAvailPhys // _MIB)
    except Exception:
        pass
    return None, None


def host_memory(root: Path | str = "/") -> tuple[int | None, int | None, str]:
    """(total MiB, available MiB, source) from /proc/meminfo, else the OS (real root only)."""
    root = Path(root)
    info = meminfo_mb(root)
    if info.get("MemTotal"):
        return info["MemTotal"], info.get("MemAvailable"), "meminfo"
    if not _is_real_root(root):
        return None, info.get("MemAvailable"), "meminfo"
    if os.name == "nt":
        total, avail = _windows_memory()
        return total, avail, "os"
    total = avail = None
    with contextlib.suppress(AttributeError, ValueError, OSError):
        total = int(os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE") // _MIB)  # type: ignore[attr-defined]
    with contextlib.suppress(AttributeError, ValueError, OSError):
        avail = int(os.sysconf("SC_AVPHYS_PAGES") * os.sysconf("SC_PAGE_SIZE") // _MIB)  # type: ignore[attr-defined]
    return total, avail, "os"


def _os_memory_mb() -> int | None:
    """Available physical memory of this machine (kept for callers of the original helper)."""
    return host_memory("/")[1]


def machine_cpus(root: Path | str = "/") -> tuple[int | None, list[int] | None]:
    """(count, ids) of the machine's online CPUs; ids are None where they mean nothing (Windows/macOS)."""
    root = Path(root)
    ids = parse_cpu_list(_read(root, "/sys/devices/system/cpu/online"))
    if ids:
        return len(ids), ids
    if _is_real_root(root):
        n = os.cpu_count()
        return n, (list(range(n)) if n and sys.platform.startswith("linux") else None)
    return None, None


def affinity_cpu_ids(root: Path | str = "/") -> list[int] | None:
    """CPU ids this process may run on (sched_getaffinity; Cpus_allowed_list in a fake tree)."""
    root = Path(root)
    if _is_real_root(root):
        getter = getattr(os, "sched_getaffinity", None)
        if getter is None:
            return None
        try:
            return sorted(getter(0))
        except OSError:
            return None
    m = re.search(r"^Cpus_allowed_list:\s*(\S+)", _read(root, "/proc/self/status") or "", re.M)
    return (parse_cpu_list(m.group(1)) or None) if m else None


def _affinity_count(root: Path) -> int | None:
    ids = affinity_cpu_ids(root)
    if ids:
        return len(ids)
    if _is_real_root(root):
        counter = getattr(os, "process_cpu_count", None)  # Python 3.13+: honours affinity on Windows too
        if counter is not None:
            with contextlib.suppress(OSError):
                return counter()
    return None


def read_psi(root: Path | str = "/", view: CgroupView | None = None) -> dict[str, dict[str, float]]:
    """avg10 pressure ('some'/'full') per resource: the cgroup's own files, else /proc/pressure."""
    out: dict[str, dict[str, float]] = {}
    for res in ("cpu", "memory", "io"):
        text = _read_file(view.pressure_dir / f"{res}.pressure") if view and view.pressure_dir else None
        if not text:
            text = _read(Path(root), f"/proc/pressure/{res}")
        values: dict[str, float] = {}
        for line in (text or "").splitlines():
            kind, _, rest = line.partition(" ")
            m = re.search(r"avg10=([0-9.]+)", rest)
            if m and kind in ("some", "full"):
                values[kind] = float(m.group(1))
        if values:
            out[res] = values
    return out


_TOPO_MEMO: dict[tuple[str, tuple[int, ...]], dict | None] = {}


def _l3_cpus(cache_dir: Path) -> list[int] | None:
    try:
        indexes = sorted(cache_dir.glob("index[0-9]*"))
    except OSError:
        return None
    for idx in indexes:
        if _read_file(idx / "level") == "3":
            return parse_cpu_list(_read_file(idx / "shared_cpu_list"))
    return None


def cpu_topology(root: Path | str, cpu_ids: Iterable[int]) -> dict | None:
    """
    Cores (SMT sibling groups), L3 domains and NUMA nodes of `cpu_ids`, from sysfs:
    topology/thread_siblings_list, cache/index*/shared_cpu_list (level 3), node*/cpulist.
    """
    root = Path(root)
    ids = sorted(set(cpu_ids))
    base = _join(root, "/sys/devices/system/cpu")
    if not ids or not base.is_dir():
        return None
    key = (str(root), tuple(ids))
    if key in _TOPO_MEMO:
        return _TOPO_MEMO[key]
    allowed = set(ids)
    cores: dict[tuple[int, ...], None] = {}
    l3: dict[tuple[int, ...], None] = {}
    for cpu in ids:
        siblings = set(parse_cpu_list(_read_file(base / f"cpu{cpu}" / "topology" / "thread_siblings_list"))) & allowed
        cores.setdefault(tuple(sorted(siblings or {cpu})), None)
        shared = _l3_cpus(base / f"cpu{cpu}" / "cache")
        group = tuple(sorted(set(shared or []) & allowed))
        if group:
            l3.setdefault(group, None)
    numa: list[list[int]] = []
    nodes = _join(root, "/sys/devices/system/node")
    for node in sorted(nodes.glob("node[0-9]*"), key=lambda p: int(p.name[4:]) if p.name[4:].isdigit() else 0):
        members = sorted(set(parse_cpu_list(_read_file(node / "cpulist"))) & allowed)
        if members:
            numa.append(members)
    core_list = sorted((list(c) for c in cores), key=lambda c: c[0])
    topo = {
        "cores": core_list,
        "l3": sorted((list(g) for g in l3), key=lambda g: g[0]),
        "numa": numa,
        "threads_per_core": max(len(c) for c in core_list),
    }
    _TOPO_MEMO[key] = topo
    return topo


_NETWORK_FS = frozenset({"cifs", "smb3", "smbfs", "9p", "virtiofs", "lustre", "gpfs", "beegfs", "ceph", "afs"})


def is_network_fs(fstype: str | None) -> bool:
    """Network or virtualized filesystems: slow I/O and unreliable flock (nfs*, cifs, 9p, fuse.*, ...)."""
    t = (fstype or "").lower()
    return bool(t) and (t.startswith(("nfs", "fuse")) or t in _NETWORK_FS)


def fs_type(path: str | Path, root: Path | str = "/", mounts: list[Mount] | None = None) -> str | None:
    """Filesystem type of `path`: the longest matching mount point in mountinfo (None when unknown)."""
    root = Path(root)
    mounts = parse_mountinfo(root) if mounts is None else mounts
    if not mounts:
        return None
    text = os.path.realpath(str(path)) if _is_real_root(root) and os.name == "posix" else str(path)
    text = text.replace("\\", "/")
    best: Mount | None = None
    best_len = -1
    for m in mounts:
        point = m.point.rstrip("/") or "/"
        if point == "/" or text == point or text.startswith(point + "/"):
            if len(point) >= best_len:  # later mounts on the same point shadow earlier ones
                best, best_len = m, len(point)
    return best.fstype if best else None


def _windows_remote_path(path: Path) -> bool:
    text = str(path)
    if text.startswith("\\\\"):
        return not text.startswith("\\\\?\\") or text.upper().startswith("\\\\?\\UNC\\")
    drive = os.path.splitdrive(text)[0]
    if not drive:
        return False
    try:
        import ctypes

        return ctypes.windll.kernel32.GetDriveTypeW(drive + "\\") == 4  # type: ignore[attr-defined]  # DRIVE_REMOTE
    except Exception:
        return False


def selinux_enforcing(root: Path | str = "/") -> bool:
    return _read(Path(root), "/sys/fs/selinux/enforce") == "1"


def in_container(root: Path | str = "/") -> bool:
    r = _probe_root(root)
    if (r / ".dockerenv").exists() or _join(r, "/run/.containerenv").exists():
        return True
    return _is_real_root(r) and bool(os.environ.get("container") or os.environ.get("FRAMAC_OUTER_SANDBOX"))


# ---------------------------------------------------------------------------
# Container engine view (docker / podman `info`)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EngineInfo:
    """What the engine reports about its host and which limit flags it can enforce."""

    kind: str = "unknown"  # docker | podman | unknown
    ncpu: int | None = None
    mem_total_mb: int | None = None
    vm_backed: bool = False  # containers run in a VM (Docker Desktop, podman machine, remote host)
    remote: bool = False  # the engine is on another machine (DOCKER_HOST/CONTAINER_HOST, remote service)
    rootless: bool = False
    cgroup_version: str | None = None
    cpu: bool = True  # --cpus
    cpuset: bool = True  # --cpuset-cpus
    memory: bool = True  # --memory
    swap: bool = True  # --memory-swap
    pids: bool = True  # --pids-limit
    os: str | None = None
    ok: bool = True
    error: str | None = None


def _remote_url(url: str | None) -> bool:
    url = (url or "").strip()
    return bool(url) and not url.startswith(("unix://", "npipe://"))


def is_wsl2(
    env: Mapping[str, str] | None = None,
    root: Path | str | None = None,
    platform: str | None = None,
) -> bool:
    """
    True when running inside a WSL2 Linux environment (where Docker Desktop shares the same
    utility VM kernel and CPUs as the WSL2 distro rather than a separate hypervisor VM).
    """
    plat = platform or sys.platform
    if not plat.startswith("linux"):
        return False
    check_env = os.environ if env is None else env
    if check_env.get("WSL_DISTRO_NAME") or check_env.get("WSL_INTEROP"):
        return True
    if root is not None or env is None:
        osrelease = (_read(_probe_root(root or "/"), "/proc/sys/kernel/osrelease") or "").lower()
        if "microsoft" in osrelease or "wsl" in osrelease:
            return True
    return False


def parse_engine_info(
    data: dict,
    env: dict[str, str] | None = None,
    platform: str | None = None,
    root: Path | str | None = None,
) -> EngineInfo:
    """Parse `<engine> info --format '{{json .}}'` output (Docker or Podman shape)."""
    use_env = dict(os.environ) if env is None else env
    plat = platform or sys.platform
    host_vm = plat.startswith(("win", "cygwin", "darwin"))  # Linux containers on Windows/macOS live in a VM
    host = data.get("host") if isinstance(data, dict) else None
    if isinstance(host, dict):  # podman
        ctrls = {str(c) for c in (host.get("cgroupControllers") or [])}
        raw_sec = host.get("security")
        security = raw_sec if isinstance(raw_sec, dict) else {}
        remote = bool(host.get("serviceIsRemote")) or _remote_url(use_env.get("CONTAINER_HOST"))
        mem = _int(host.get("memTotal"))
        return EngineInfo(
            kind="podman",
            ncpu=_int(host.get("cpus")),
            mem_total_mb=mem // _MIB if mem else None,
            vm_backed=remote or host_vm,
            remote=remote,
            rootless=bool(security.get("rootless")),
            cgroup_version=str(host.get("cgroupVersion") or "") or None,
            cpu="cpu" in ctrls,
            cpuset="cpuset" in ctrls,
            memory="memory" in ctrls,
            swap="memory" in ctrls,
            pids="pids" in ctrls,
            os=str(host.get("os") or "") or None,
        )
    os_name = str(data.get("OperatingSystem") or "")
    remote = _remote_url(use_env.get("DOCKER_HOST"))
    mem = _int(data.get("MemTotal"))
    security_opts = [str(s) for s in data.get("SecurityOptions") or []]
    # On Windows/macOS, Docker Desktop runs in a Hyper-V/Virtualization.framework VM (`host_vm`).
    # Inside WSL2, Docker Desktop's engine runs in the same WSL2 utility VM kernel as the caller,
    # so CPU IDs and topology match the caller's `/sys/devices/system/cpu`.
    desktop_vm = "docker desktop" in os_name.lower() and not is_wsl2(env, root, plat)
    return EngineInfo(
        kind="docker",
        ncpu=_int(data.get("NCPU")),
        mem_total_mb=mem // _MIB if mem else None,
        vm_backed=desktop_vm or remote or host_vm,
        remote=remote,
        rootless=any("name=rootless" in s for s in security_opts),
        cgroup_version=str(data.get("CgroupVersion") or "") or None,
        cpu=bool(data.get("CpuCfsQuota", True)),
        cpuset=bool(data.get("CPUSet", True)),
        memory=bool(data.get("MemoryLimit", True)),
        swap=bool(data.get("SwapLimit", True)),
        pids=bool(data.get("PidsLimit", True)),
        os=os_name or None,
    )


_ENGINE_MEMO: dict[str, tuple[float, EngineInfo]] = {}


def engine_info(
    engine: str,
    cache_dir: Path | str | None = None,
    max_age: float = ENGINE_INFO_MAX_AGE_S,
    runner: Callable[..., Any] | None = None,
) -> EngineInfo:
    """`<engine> info --format '{{json .}}'`, parsed; cached `max_age` seconds (in `cache_dir` when given)."""
    ident = "|".join(
        [
            engine,
            os.environ.get("DOCKER_HOST", ""),
            os.environ.get("CONTAINER_HOST", ""),
            os.environ.get("DOCKER_CONTEXT", ""),
        ]
    )
    digest = hashlib.sha256(ident.encode()).hexdigest()[:16]
    now = time.time()
    hit = _ENGINE_MEMO.get(digest)
    if hit and now - hit[0] < max_age and runner is None:
        return hit[1]
    cache = Path(cache_dir) / f"engine-{digest}.json" if cache_dir else None
    if cache is not None and runner is None:
        cached = _load_json(cache)
        if (
            isinstance(cached, dict)
            and isinstance(cached.get("data"), dict)
            and now - float(cached.get("ts") or 0) < max_age
        ):
            info = parse_engine_info(cached["data"])
            _ENGINE_MEMO[digest] = (now, info)
            return info
    run = runner or subprocess.run
    try:
        proc = run(
            [engine, "info", "--format", "{{json .}}"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return EngineInfo(ok=False, error=f"{engine} info: {exc}")
    out = (proc.stdout or "").strip()
    data = None
    if proc.returncode == 0 and out:
        with contextlib.suppress(ValueError):
            data = json.loads(out[out.find("{") :]) if "{" in out else None
    if not isinstance(data, dict):
        detail = (proc.stderr or out or "").strip().splitlines()
        return EngineInfo(ok=False, error=f"{engine} info failed: {detail[-1] if detail else proc.returncode}")
    info = parse_engine_info(data)
    _ENGINE_MEMO[digest] = (now, info)
    if cache is not None:
        with contextlib.suppress(OSError):
            _write_json(cache, {"ts": now, "engine": engine, "data": data})
    return info


def container_running(engine: str, lease_id: str) -> bool | None:
    """True/False when `<engine> ps` says whether the lease's container runs; None when it cannot tell."""
    try:
        proc = subprocess.run(
            [engine, "ps", "-q", "--filter", f"label=framac.lease={lease_id}"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return bool((proc.stdout or "").strip())


# ---------------------------------------------------------------------------
# Pool: everything a decision needs, measured now
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Pool:
    scope: str
    cpus: int
    mem_mb: int
    cpu_ids: tuple[int, ...] = ()
    machine_cpus: int | None = None
    subset: bool = False  # cpu_ids is a strict subset of the machine's online CPUs
    sources: dict = field(default_factory=dict)
    binding: dict = field(default_factory=dict)
    reserve: dict = field(default_factory=dict)
    mem_available_mb: int | None = None
    psi: dict = field(default_factory=dict)
    topology: dict | None = None
    engine: EngineInfo | None = None
    fs: dict = field(default_factory=dict)
    warnings: tuple[str, ...] = ()

    def budget(self) -> Budget:
        return Budget(
            cpus=self.cpus,
            mem_mb=self.mem_mb,
            source=f"cpu:{self.binding.get('cpus', '?')},mem:{self.binding.get('mem_mb', '?')}",
        )

    def summary(self) -> dict:
        """Compact record for run-metadata.json."""
        out = {
            "cpus": self.cpus,
            "mem_mb": self.mem_mb,
            "sources": {k: dict(v) for k, v in self.sources.items()},
            "binding": dict(self.binding),
            "reserve": dict(self.reserve),
            "warnings": list(self.warnings),
        }
        if self.scope == "container":
            pool_cpus = (os.environ.get("FRAMAC_POOL_CPUS") or "").strip()
            pool_mem = (os.environ.get("FRAMAC_POOL_MEM_MB") or "").strip()
            if pool_cpus.isdigit() and pool_mem.isdigit() and int(pool_cpus) > 0 and int(pool_mem) > 0:
                out["pool"] = {"cpus": int(pool_cpus), "mem_mb": int(pool_mem), "source": "host broker"}
        return out

    def to_dict(self) -> dict:
        out = asdict(self)
        out["cpu_ids"] = format_cpu_list(self.cpu_ids)
        out["warnings"] = list(self.warnings)
        return out


_PROBE_ENV = (
    "FRAMAC_POOL_CPUS",
    "FRAMAC_POOL_MEMORY",
    "FRAMAC_POOL_MEM_MB",
    "FRAMAC_RESERVE_CPUS",
    "FRAMAC_RESERVE_MEMORY",
    "FRAMAC_JOB_CPUS",
    "FRAMAC_JOB_MEM_MB",
    "SLURM_CPUS_ON_NODE",
    "SLURM_CPUS_PER_TASK",
    "SLURM_JOB_CPUS_PER_NODE",
    "SLURM_MEM_PER_NODE",
    "SLURM_MEM_PER_CPU",
    "SLURM_NODEID",
    "FRAMAC_PROBE_ROOT",
)
_PROBE_MEMO: dict[tuple, tuple[float, Pool]] = {}
_PROBE_LOCK = threading.Lock()


def _memo_seconds() -> float:
    try:
        return float(os.environ.get("FRAMAC_PROBE_MEMO_S", "") or PROBE_MEMO_S)
    except ValueError:
        return PROBE_MEMO_S


def _reserve_amount(raw: str | None, total: float, default: float, memory: bool) -> float:
    text = (raw or "").strip()
    if not text:
        return default
    if text.endswith("%"):
        try:
            return max(0.0, total * float(text[:-1]) / 100.0)
        except ValueError:
            return default
    if memory:
        value = parse_mem(text)
        return float(value) if value is not None else default
    try:
        return max(0.0, float(text))
    except ValueError:
        return default


def probe(
    scope: str = "host",
    engine: str | EngineInfo | None = None,
    root: Path | str = "/",
    *,
    run_dir: Path | str | None = None,
    cache_dir: Path | str | None = None,
    broker_dir: Path | str | None = None,
    fresh: bool = False,
) -> Pool:
    """
    Measure the pool now (memoized PROBE_MEMO_S seconds; FRAMAC_PROBE_MEMO_S=0 disables).
    The pool is the minimum over every source (machine, affinity/cpuset, cgroup limits up the
    hierarchy, Slurm, the engine's NCPU/MemTotal), minus a reserve (FRAMAC_RESERVE_CPUS, default
    max(0.5, 5%); FRAMAC_RESERVE_MEMORY, default max(1 GiB, 10%)), then capped by
    FRAMAC_POOL_CPUS / FRAMAC_POOL_MEMORY. In container scope the reserve only applies to a
    resource bounded by the machine itself: an explicit limit already is the host broker's grant.
    """
    if scope not in ("host", "container"):
        raise ValueError(f"scope must be 'host' or 'container', not {scope!r}")
    root_p = _probe_root(root)
    key = (scope, engine, str(root_p), str(run_dir), str(cache_dir), tuple(os.environ.get(k) for k in _PROBE_ENV))
    ttl = _memo_seconds()
    now = time.monotonic()
    if not fresh and ttl > 0:
        with _PROBE_LOCK:
            hit = _PROBE_MEMO.get(key)
        if hit is not None and now - hit[0] < ttl:
            return hit[1]
    pool = _probe(scope, engine, root_p, run_dir, cache_dir, broker_dir)
    with _PROBE_LOCK:
        if len(_PROBE_MEMO) > 64:
            _PROBE_MEMO.clear()
        _PROBE_MEMO[key] = (now, pool)
    return pool


def _probe(
    scope: str,
    engine: str | EngineInfo | None,
    root: Path,
    run_dir: Path | str | None,
    cache_dir: Path | str | None,
    broker_dir: Path | str | None,
) -> Pool:
    real = _is_real_root(root)
    eng: EngineInfo | None = None
    if scope == "host" and engine is not None:
        eng = engine if isinstance(engine, EngineInfo) else engine_info(engine, cache_dir=broker_dir)
    remote = bool(eng and eng.remote)
    native = not (eng and eng.vm_backed)  # this process's affinity and cgroups confine containers only then
    warnings: list[str] = []
    cpu: dict[str, float] = {}
    mem: dict[str, int] = {}

    n_machine, online = machine_cpus(root)
    view = cgroup_view(root)
    allowed = affinity_cpu_ids(root)
    if view.cpuset:
        allowed = sorted(set(allowed) & set(view.cpuset)) if allowed else list(view.cpuset)
    total_mb, avail_mb, _mem_src = host_memory(root)

    if not remote:
        if n_machine:
            cpu["machine"] = float(n_machine)
        if total_mb:
            mem["machine"] = total_mb
    if native:
        if allowed:
            cpu["affinity"] = float(len(allowed))
        else:
            count = _affinity_count(root)
            if count:
                cpu["affinity"] = float(count)
        if view.cpu_quota:
            cpu["cgroup"] = view.cpu_quota
        if view.mem_limit_mb:
            mem["cgroup"] = view.mem_limit_mb
    s_cpu, s_mem = slurm_limits()
    if s_cpu:
        cpu["slurm"] = float(s_cpu)
    if s_mem:
        mem["slurm"] = s_mem
    if eng is not None and eng.ncpu:
        cpu["engine"] = float(eng.ncpu)
    if eng is not None and eng.mem_total_mb:
        mem["engine"] = eng.mem_total_mb
    if scope == "container":
        grant_cpus, grant_mem = _env_float("FRAMAC_JOB_CPUS"), parse_mem(os.environ.get("FRAMAC_JOB_MEM_MB"))
        if grant_cpus:
            cpu["grant"] = grant_cpus
        if grant_mem:
            mem["grant"] = grant_mem
    if not cpu:
        cpu["default"] = 1.0
    if not mem:
        mem["default"] = 4096

    subset = bool(allowed and online and set(allowed) < set(online))
    machine_level = {"machine", "default"} | (set() if subset else {"affinity"})
    bind_cpu = min(cpu, key=lambda k: cpu[k])
    bind_mem = min(mem, key=lambda k: mem[k])
    raw_cpu, raw_mem = cpu[bind_cpu], mem[bind_mem]
    res_cpu = res_mem = 0.0
    if scope == "host" or bind_cpu in machine_level:
        res_cpu = _reserve_amount(os.environ.get("FRAMAC_RESERVE_CPUS"), raw_cpu, max(0.5, 0.05 * raw_cpu), False)
    if scope == "host" or bind_mem in machine_level:
        res_mem = _reserve_amount(os.environ.get("FRAMAC_RESERVE_MEMORY"), raw_mem, max(1024.0, 0.10 * raw_mem), True)
    eff_cpu, eff_mem = raw_cpu - res_cpu, raw_mem - res_mem
    cap_cpu = _env_float("FRAMAC_POOL_CPUS")
    cap_mem = min(
        (
            v
            for v in (parse_mem(os.environ.get("FRAMAC_POOL_MEMORY")), parse_mem(os.environ.get("FRAMAC_POOL_MEM_MB")))
            if v
        ),
        default=None,
    )
    binding = {"cpus": bind_cpu, "mem_mb": bind_mem}
    if cap_cpu is not None and cap_cpu < eff_cpu:
        eff_cpu, binding["cpus"] = cap_cpu, "cap"
    if cap_mem is not None and cap_mem < eff_mem:
        eff_mem, binding["mem_mb"] = float(cap_mem), "cap"
    if cap_cpu is not None:
        cpu["cap"] = cap_cpu
    if cap_mem is not None:
        mem["cap"] = cap_mem
    cpus = max(1, int(math.floor(eff_cpu + 1e-9)))
    mem_mb = max(256, int(eff_mem))

    if avail_mb is not None and (native or not remote) and avail_mb < mem_mb // 2:
        warnings.append(
            f"only {avail_mb} MiB of memory is available right now for a {mem_mb} MiB pool: "
            "other processes are using memory, so large grants may be OOM-killed"
        )
    psi = read_psi(root, view)
    if psi.get("memory", {}).get("some", 0.0) >= 20.0:
        warnings.append(f"memory pressure: {psi['memory']['some']:.0f}% of the last 10 s stalled on memory")
    if psi.get("cpu", {}).get("some", 0.0) >= 50.0:
        warnings.append(f"CPU pressure: {psi['cpu']['some']:.0f}% of the last 10 s waiting for a CPU")
    if not native and subset:
        warnings.append(
            f"this process may only use CPUs {format_cpu_list(allowed or [])}, but the engine runs "
            "containers in a VM where that restriction does not apply"
        )
    if eng is not None and not eng.ok:
        warnings.append(f"container engine view unavailable ({eng.error}); sizing from the host only")

    # Warn loudly when cgroup limits are much smaller than the broker pool / engine / host capacity.
    # In container scope, a cgroup limit that matches (or exceeds) the host broker's per-job grant
    # (FRAMAC_JOB_CPUS / FRAMAC_JOB_MEM_MB) is the expected lease for this job class (e.g. 1 CPU /
    # 1024 MiB for `light`), not an external cgroup throttle.
    grant_cpu = cpu.get("grant") if scope == "container" else None
    grant_mem = mem.get("grant") if scope == "container" else None
    ref_cpus_candidates = [
        v
        for v in (
            _env_float("FRAMAC_POOL_CPUS") if scope == "container" else None,
            cpu.get("engine"),
            cpu.get("machine"),
        )
        if v and v > 0
    ]
    ref_mem_candidates = [
        v
        for v in (
            parse_mem(os.environ.get("FRAMAC_POOL_MEM_MB")) if scope == "container" else None,
            mem.get("engine"),
            mem.get("machine"),
        )
        if v and v > 0
    ]
    cg_cpu = cpu.get("cgroup")
    if cg_cpu is not None and (grant_cpu is None or cg_cpu < grant_cpu - 1e-6) and ref_cpus_candidates:
        ref_cpu = max(ref_cpus_candidates)
        if (grant_cpu is not None and cg_cpu < grant_cpu - 1e-6) or (ref_cpu >= 2.0 and cg_cpu <= ref_cpu * 0.5):
            warnings.append(
                f"cgroup CPU limit ({_fmt_cpus(cg_cpu)} CPUs) is much smaller than pool/host capacity "
                f"({_fmt_cpus(ref_cpu)} CPUs): tasks in this cgroup are throttled to {_fmt_cpus(cg_cpu)} CPUs"
            )
    cg_mem = mem.get("cgroup")
    if cg_mem is not None and (grant_mem is None or cg_mem < grant_mem) and ref_mem_candidates:
        ref_mem = max(ref_mem_candidates)
        if (grant_mem is not None and cg_mem < grant_mem) or (ref_mem >= 2048 and cg_mem <= ref_mem // 2):
            warnings.append(
                f"cgroup memory limit ({cg_mem} MiB) is much smaller than pool/host capacity "
                f"({ref_mem} MiB): tasks in this cgroup are capped at {cg_mem} MiB"
            )

    if scope == "container" and real:
        if run_dir is None and Path("/framac-run").is_dir():
            run_dir = "/framac-run"
        if cache_dir is None and Path(CONTAINER_CACHE_MOUNT).is_dir():
            cache_dir = CONTAINER_CACHE_MOUNT
    mounts = parse_mountinfo(root)
    fs: dict[str, str | None] = {}
    for label, path in (("run_dir", run_dir), ("cache_dir", cache_dir)):
        if not path:
            continue
        if os.name == "nt" and real:
            remote_path = _windows_remote_path(Path(path))
            fs[label] = "remote" if remote_path else None
            if remote_path:
                warnings.append(f"{label.replace('_', ' ')} {path} is on a network drive: slower I/O than a local disk")
            continue
        kind = fs_type(path, root, mounts)
        fs[label] = kind
        if is_network_fs(kind):
            warnings.append(
                f"{label.replace('_', ' ')} {path} is on {kind} (network or virtualized filesystem): "
                "slower I/O than a local disk"
            )

    ids = tuple(allowed or online or ()) if native else ()
    topology = cpu_topology(root, ids) if ids else None
    return Pool(
        scope=scope,
        cpus=cpus,
        mem_mb=mem_mb,
        cpu_ids=ids,
        machine_cpus=n_machine,
        subset=subset and native,
        sources={"cpus": cpu, "mem_mb": mem},
        binding=binding,
        reserve={"cpus": round(res_cpu, 3), "mem_mb": int(res_mem)},
        mem_available_mb=avail_mb,
        psi=psi,
        topology=topology,
        engine=eng,
        fs=fs,
        warnings=tuple(warnings),
    )


# ---------------------------------------------------------------------------
# Budgets and sizing (stable API)
# ---------------------------------------------------------------------------


def job_budget(root: Path | str = "/", *, use_available: bool = True) -> Budget:
    """
    CPUs and memory this job may use: the minimum of the broker's grant (FRAMAC_JOB_CPUS /
    FRAMAC_JOB_MEM_MB), the cgroup limits (walked up the hierarchy) and the CPUs/memory the OS
    reports. Cgroup files are re-read on every call, so a resized container is never hidden
    behind a stale grant. `use_available=False` sizes memory from MemTotal instead of
    MemAvailable (the container broker accounts for its own leases' usage itself).
    """
    root = _probe_root(root)
    cpu_sources: list[tuple[float, str]] = []
    mem_sources: list[tuple[int, str]] = []
    cgroup_enforced = os.environ.get("FRAMAC_CGROUP_ENFORCED", "").strip() == "1"
    env_cpus, env_mem = _env_int("FRAMAC_JOB_CPUS"), parse_mem(os.environ.get("FRAMAC_JOB_MEM_MB"))
    view = cgroup_view(root)
    if view.cpu_quota:
        cpu_sources.append((view.cpu_quota, "cgroup"))
    if view.cpuset:
        cpu_sources.append((len(view.cpuset), "cpuset"))
    if env_cpus and not (cgroup_enforced and (view.cpu_quota or view.cpuset)):
        cpu_sources.append((env_cpus, "grant"))
    affinity = _affinity_count(root)
    if affinity:
        cpu_sources.append((affinity, "affinity"))
    else:
        n_machine, _ = machine_cpus(root)
        if n_machine:
            cpu_sources.append((n_machine, "os"))
    if view.mem_limit_mb:
        mem_sources.append((view.mem_limit_mb, "cgroup"))
    if env_mem and not (cgroup_enforced and view.mem_limit_mb):
        mem_sources.append((env_mem, "grant"))
    total, avail, mem_src = host_memory(root)
    machine_mem = avail if use_available else total
    if machine_mem:
        mem_sources.append((machine_mem, mem_src))
    elif not mem_sources:
        mem_sources.append((4096, "default"))
    if not cpu_sources:
        cpu_sources.append((1, "default"))
    cpus, cpu_src = min(cpu_sources, key=lambda t: t[0])
    mem, mem_src = min(mem_sources, key=lambda t: t[0])
    return Budget(
        cpus=max(1, int(math.floor(cpus + 1e-9))), mem_mb=max(256, int(mem)), source=f"cpu:{cpu_src},mem:{mem_src}"
    )


def enforced_memory_mb(root: Path | str = "/") -> int | None:
    """The memory limit actually imposed on this job (its grant or its cgroup), or None when unlimited."""
    cg_mem = cgroup_view(_probe_root(root)).mem_limit_mb
    cgroup_enforced = os.environ.get("FRAMAC_CGROUP_ENFORCED", "").strip() == "1"
    if cgroup_enforced and cg_mem is not None:
        return cg_mem
    limits = [v for v in (parse_mem(os.environ.get("FRAMAC_JOB_MEM_MB")), cg_mem) if v]
    return min(limits) if limits else None


def wp_parallelism(budget: Budget | None = None) -> int:
    """Concurrent provers (-wp-par): bounded by CPUs and by memory at the fixed -wp-memlimit."""
    b = budget or job_budget()
    by_mem = (b.mem_mb - FRAMAC_KERNEL_RESERVE_MB) // WP_MEMLIMIT_MB
    return max(1, min(b.cpus, by_mem))


def fuzz_workers(budget: Budget | None = None) -> int:
    """LibFuzzer workers: bounded by CPUs and by memory at the fixed -rss_limit_mb."""
    b = budget or job_budget()
    by_mem = (b.mem_mb - FUZZ_WORKER_OVERHEAD_MB) // int(FUZZ_RSS_LIMIT_MB * 1.25)
    return max(1, min(b.cpus, by_mem))


def pool_budget() -> Budget:
    """The whole pipeline pool: FRAMAC_POOL_* (set by the host broker) when present, else run-metadata.json's pool, else the probe."""
    cpus, mem = _env_int("FRAMAC_POOL_CPUS"), parse_mem(os.environ.get("FRAMAC_POOL_MEM_MB"))
    if cpus and mem:
        return Budget(cpus=cpus, mem_mb=mem, source="pool-env")
    if in_container():
        meta_path = Path("run-metadata.json")
        if meta_path.is_file():
            with contextlib.suppress(Exception):
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                meta_pool = ((meta.get("resources") or {}).get("pool") or {}) if isinstance(meta, dict) else {}
                mc = int(meta_pool.get("cpus") or 0)
                mm = int(meta_pool.get("mem_mb") or 0)
                if mc > 0 and mm > 0:
                    return Budget(cpus=cpus or mc, mem_mb=mem or mm, source="run-metadata-pool")
    own = probe(scope="container" if in_container() else "host").budget()
    return Budget(cpus=cpus or own.cpus, mem_mb=mem or own.mem_mb, source=f"pool-from-{own.source}")


def _cpu_bounds(min_cpus: int, max_cpus: int | None, pool_cpus: float, alone: bool = False) -> tuple[int, int]:
    """(lo, hi) CPUs for one grant: hi = min(max or pool, pool if alone else max(min, pool // 2)); both clamped to the pool."""
    pool_i = max(1, int(math.floor(pool_cpus + 1e-9)))
    lo = max(1, min(int(min_cpus), pool_i))
    if alone:
        hi = min(max_cpus if max_cpus else pool_i, pool_i)
    else:
        hi = min(max_cpus if max_cpus else pool_i, max(lo, pool_i // 2))
    return lo, max(lo, hi)


def nominal_grant(cls: JobClass, pool: Budget) -> dict:
    """What the broker grants one job of this class on an idle pool (the elastic formula, memory-fitted)."""
    alone = cls.name == "wp"
    max_c = cls.max_cpus
    if pool.cpus >= 32:
        if cls.name == "wp":
            max_c = 16
        elif cls.name == "guardrail":
            max_c = 4
    lo, hi = _cpu_bounds(cls.min_cpus, max_c, pool.cpus, alone=alone)
    cpus = hi if cls.gated else lo
    while cpus > lo and cls.mem_base_mb + cls.mem_per_cpu_mb * cpus > pool.mem_mb:
        cpus -= 1
    return {"cpus": cpus, "mem_mb": cls.mem_base_mb + cls.mem_per_cpu_mb * cpus}


def recommend(max_agents: int | None = None, pool: Budget | None = None) -> dict:
    """
    Sizing hints for skills, Make and the scheduler, recomputed from the current pool. `make_jobs`
    is the -j of a make that has the whole pool; inside a leased container, size from job_budget().
    """
    warnings: list[str] = []
    if pool is None:
        p = pool_budget()
        with contextlib.suppress(Exception):
            warnings = list(probe(scope="container" if in_container() else "host").warnings)
    else:
        p = pool
    wp = CLASSES["wp"]
    wp_cpus = max(1, min(WP_NOMINAL_CPUS, p.cpus))
    wp_mem = wp.mem_base_mb + wp.mem_per_cpu_mb * wp_cpus
    duty = 4.0 if p.cpus >= 16 else AGENT_DUTY
    by_cpu = math.floor(p.cpus * duty / wp_cpus)
    by_mem = math.floor(p.mem_mb * AGENT_DUTY / max(1, wp_mem))
    default_cap = 64 if p.cpus >= 64 else (32 if p.cpus >= 32 else DEFAULT_MAX_AGENTS)
    cap = max_agents or _env_int("FRAMAC_MAX_AGENTS") or default_cap
    agents = max(1, min(by_cpu, by_mem, cap))
    return {
        "pool": asdict(p),
        "make_jobs": max(1, p.cpus),
        "max_agents": agents,
        "classes": {name: nominal_grant(cls, p) for name, cls in CLASSES.items()},
        "fixed_limits": {"wp_memlimit_mb": WP_MEMLIMIT_MB, "fuzz_rss_limit_mb": FUZZ_RSS_LIMIT_MB},
        "warnings": warnings,
    }


_CLASS_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"run_wp_function\.py", "wp"),
    (r"run_eva_slice\.py", "eva"),
    (r"eva_tuning\.py", "eva"),
    (r"function_facts\.py", "eva"),
    (r"run_eacsl_fuzz\.py\s+(?:\S+\s+)*?campaign(?:\s|$)", "fuzz"),
    (r"run_eacsl_fuzz\.py\s+(?:\S+\s+)*?guardrail(?:\s|$)", "guardrail"),
    (r"run_eacsl_fuzz\.py\s+(?:\S+\s+)*?(?:replay(?:-candidates)?|coverage)(?:\s|$)", "replay"),
    (r"run_eacsl_fuzz\.py\s+(?:\S+\s+)*?selftest(?:\s|$)", "selftest"),
    (r"run_eacsl_fuzz\.py\s+(?:\S+\s+)*?build(?:\s|$)", "build"),
    (r"pipeline_make\.py\s+(?:\S+\s+)*?sweep(?:\s|$)", "phase-static"),
    (r"build_callgraph_dag\.py\b", "eva"),
    (r"extract_references\.py\b", "build"),
    # The target's own build under the sandbox (bear -- make, cmake, ninja ...): target code, sized like a phase.
    # Must appear before compiler patterns so sandboxed target builds are not downgraded to "build".
    (
        r"sandbox_exec\.py\s+run\b[^;&|]*?\s--\s+(?:\S*/)?(?:bear|make|gmake|cmake|ninja|meson|scons|configure)\b",
        "phase-dynamic",
    ),
    (r"sandbox_exec\.py\s+run\b", "replay"),
    (r"(?:^|[\s;&|(/])e-acsl-gcc(?:\.sh)?(?:\s|$)", "build"),
    (r"(?:^|[\s;&|(/])(?:clang|gcc)\b[^;&|]*-fsanitize=[^\s;&|]*fuzzer", "build"),
    (r"workspace_overlay\.py\s+merge-(?:agent|batch)\b", "verify"),
    (r"wp_scheduler\.py\s+(?:complete|merge-pending)\b", "verify"),
    # A direct Frama-C call (parse or annotation check): one single-threaded kernel, like Eva.
    (r"(?:^|[\s;&|(/])frama-c(?:\s|$)", "eva"),
)
# `minimize` replays crash inputs under cvise, so it runs target code like `replay`.
_DYNAMIC_MAKE_TARGETS = frozenset({"selftest", "fuzz", "coverage", "replay", "minimize"})
# Per-module targets that run target code (fuzz-<mod>, module-<mod>, ...); build-<mod>/eva-<mod> stay static.
_DYNAMIC_MAKE_PREFIXES = ("module-", "fuzz-", "coverage-", "replay-", "selftest-")
_MAKE_VALUE_OPTIONS = frozenset({"--jobs", "-j"})
_PIPELINE_SCRIPTS = "/opt/framac-pipeline/scripts"
_SCRIPT_VAR_RE = re.compile(r"(?<![A-Za-z0-9_])(?:\$S|\$\{S\})(?=/|\s|$)")


def expand_script_var(cmd: str) -> str:
    """Replace `$S` or `${S}` script-path shorthand with `/opt/framac-pipeline/scripts`."""
    return _SCRIPT_VAR_RE.sub(_PIPELINE_SCRIPTS, cmd or "")


def _make_targets(args: str) -> list[str]:
    """Targets of `pipeline_make.py run [--jobs N] <targets...>`: option tokens and their values dropped."""
    targets: list[str] = []
    skip_value = False
    for token in args.split():
        if skip_value:
            skip_value = False
            if token.isdigit():
                continue
        if token in _MAKE_VALUE_OPTIONS:
            skip_value = True
        elif not token.startswith("-"):
            targets.append(token)
    return targets


def _match_class_patterns(text: str) -> str | None:
    text = expand_script_var(text or "")
    m = re.search(r"pipeline_make\.py(?:\s+--run-dir(?:\s+\S+|=\S+))?\s+run\s+(?P<targets>[^;&|\n]*)", text)
    if m:
        targets = _make_targets(m.group("targets"))
        dynamic = any(t in _DYNAMIC_MAKE_TARGETS or t.startswith(_DYNAMIC_MAKE_PREFIXES) for t in targets)
        return "phase-dynamic" if dynamic else "phase-static"
    for pattern, name in _CLASS_PATTERNS:
        if re.search(pattern, text):
            return name
    return None


def _unwrap_command(cmd: str) -> str:
    text = (cmd or "").strip()
    for _ in range(5):
        m_entry = re.search(r"(?:^|[\s;&|(/])container_entry\.sh(?:\s+-[^\s]+)*\s+(.*)$", text)
        if m_entry:
            inner = m_entry.group(1).strip()
            if (inner.startswith('"') and inner.endswith('"')) or (inner.startswith("'") and inner.endswith("'")):
                inner = inner[1:-1]
            text = inner.strip()
            continue

        m_sh = re.search(
            r"(?:^|[\s;&|(/])(?:bash|sh)\s+(?:-[a-zA-Z0-9_-]*c\s+)(?:'([^']*)'|\"((?:[^\"\\]|\\.)*)\")(?:\s|$)",
            text,
            re.DOTALL,
        )
        if m_sh:
            inner = m_sh.group(1) if m_sh.group(1) is not None else m_sh.group(2)
            text = inner.strip()
            continue

        m_sh_bare = re.search(r"(?:^|[\s;&|(/])(?:bash|sh)\s+(?:-[a-zA-Z0-9_-]*c\s+)(.*)$", text)
        if m_sh_bare:
            inner = m_sh_bare.group(1).strip()
            if (inner.startswith('"') and inner.endswith('"')) or (inner.startswith("'") and inner.endswith("'")):
                inner = inner[1:-1]
            text = inner.strip()
            continue

        break
    return text


_SHELL_SHEBANG_RE = re.compile(r"#!\s*(?:\S*/)?(?:env\s+(?:-\S+\s+)*)?(?:ba|da)?sh(?:\s|$)")


def _extract_script_paths(cmd: str, base_dir: Path | str | None = None) -> list[tuple[Path, bool]]:
    """Path-like tokens of `cmd`, each with whether a `bash`/`sh` token names it as the script to run.

    Relative paths are resolved against `base_dir` first (the run directory), because a subagent
    often writes `agents/<id>/scratch/run_wp.sh` and invokes it from the host wrapper, whose own
    working directory is the pipeline checkout rather than the run directory.
    """
    paths: list[tuple[Path, bool]] = []
    token_lists: list[list[str]] = []
    try:
        token_lists.append(shlex.split(cmd, posix=(os.name != "nt")))
    except ValueError:
        pass
    token_lists.append(cmd.split())

    def resolve(cand: str) -> Path:
        path = Path(cand)
        if base_dir and not path.is_absolute():
            candidate = Path(base_dir) / path
            if candidate.is_file():
                return candidate
        return path

    seen: set[str] = set()
    for tokens in token_lists:
        for idx, tok in enumerate(tokens):
            clean_tok = tok.strip("\"'")
            if clean_tok in ("bash", "sh", "/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh"):
                for next_tok in tokens[idx + 1 :]:
                    if not next_tok.startswith("-"):
                        cand = next_tok.strip("\"'")
                        if cand not in seen:
                            seen.add(cand)
                            paths.append((resolve(cand), True))
                        break
            elif (
                clean_tok.endswith(".sh")
                or clean_tok.startswith("./")
                or clean_tok.startswith("/")
                or "\\" in clean_tok
            ):
                if clean_tok not in seen:
                    seen.add(clean_tok)
                    paths.append((resolve(clean_tok), False))
    return paths


def infer_class(cmd: str, base_dir: Path | str | None = None) -> str:
    """Job class of a container command line (sizing only; never a security decision)."""
    unwrapped = _unwrap_command(cmd or "")
    matched = _match_class_patterns(unwrapped)
    if matched:
        return matched

    # Check if the command runs an on-disk shell script file. Other files are not scanned: a pipeline
    # script's own source, or a report passed as an argument, can mention commands it does not run.
    for p, run_by_shell in _extract_script_paths(unwrapped, base_dir=base_dir):
        try:
            if p.is_file():
                content = p.read_text(encoding="utf-8", errors="replace")[:65536]
                if not (run_by_shell or p.suffix == ".sh" or _SHELL_SHEBANG_RE.match(content)):
                    continue
                script_matched = _match_class_patterns(content)
                if script_matched:
                    return script_matched
        except OSError:
            pass

    return "light"


# Commands allowed to write the shared cross-run cache (exact token match; see cache_mount_mode).
CACHE_RW_ALLOWLIST: frozenset[tuple[str, ...]] = frozenset(
    {
        ("python3", f"{_PIPELINE_SCRIPTS}/pipeline_make.py", "run", "build"),
        ("python3", f"{_PIPELINE_SCRIPTS}/pipeline_make.py", "run", "eva"),
        ("python3", f"{_PIPELINE_SCRIPTS}/pipeline_make.py", "run", "eva-tune"),
        ("python3", f"{_PIPELINE_SCRIPTS}/pipeline_make.py", "run", "facts"),
        ("python3", f"{_PIPELINE_SCRIPTS}/pipeline_make.py", "run", "wp-sweep"),
        ("python3", f"{_PIPELINE_SCRIPTS}/pipeline_make.py", "run", "ingest"),
        ("python3", f"{_PIPELINE_SCRIPTS}/pipeline_make.py", "run", "ingest", "wp-queue"),
        ("python3", f"{_PIPELINE_SCRIPTS}/pipeline_make.py", "ingest"),
        ("python3", f"{_PIPELINE_SCRIPTS}/cache.py", "gc"),
        ("python3", f"{_PIPELINE_SCRIPTS}/cache.py", "stats"),
    }
)
_PLAIN_COMMAND = re.compile(r"[A-Za-z0-9_./ \t-]*")


def is_known_static_command(cmd: str | None) -> bool:
    """
    True ONLY when `cmd` is known with certainty to run only static analysis, pure Python
    tooling, or compiler instrumentation without executing target binaries.
    Fails closed: any unrecognized command, shell expression, or sandboxed execution returns False.
    """
    if not cmd or not isinstance(cmd, str):
        return False
    text = expand_script_var(cmd.strip())
    if re.search(r"[;&|`$><\n\r]", text):
        return False
    # Any sandbox_exec.py run executes target code
    if "sandbox_exec.py" in text:
        return False
    # Strip python interpreter prefix if present
    clean = re.sub(r"^(?:/usr/bin/|/usr/local/bin/)?(?:python3?|pypy3?)\s+", "", text).strip()
    m = re.match(
        r"^(?:/opt/framac-pipeline/scripts/)?pipeline_make\.py(?:\s+--run-dir(?:\s+\S+|=\S+))?\s+(?P<sub>gen|plan|params|ingest|sweep|run)(?:\s+(?P<targets>.*))?$",
        clean,
    )
    if m:
        if m.group("sub") != "run":
            return True
        targets = _make_targets(m.group("targets") or "")
        if not targets:
            return False
        return not any(t in _DYNAMIC_MAKE_TARGETS or t.startswith(_DYNAMIC_MAKE_PREFIXES) for t in targets)
    if "run_eacsl_fuzz.py" in clean:
        return bool(
            re.match(r"^(?:/opt/framac-pipeline/scripts/)?run_eacsl_fuzz\.py\s+(?:\S+\s+)*?build(?:\s|$)", clean)
        ) and not any(sub in clean for sub in ("campaign", "guardrail", "replay", "selftest", "coverage"))
    static_tool_res = (
        r"^(?:/opt/framac-pipeline/scripts/)?run_wp_function\.py\b",
        r"^(?:/opt/framac-pipeline/scripts/)?run_eva_slice\.py\b",
        r"^(?:/opt/framac-pipeline/scripts/)?eva_tuning\.py\b",
        r"^(?:/opt/framac-pipeline/scripts/)?function_facts\.py\b",
        r"^(?:/opt/framac-pipeline/scripts/)?build_callgraph_dag\.py\b",
        r"^(?:/opt/framac-pipeline/scripts/)?extract_references\.py\b",
        r"^(?:/opt/framac-pipeline/scripts/)?generate_harness\.py\b",
        r"^(?:/opt/framac-pipeline/scripts/)?ledger\.py\b",
        r"^(?:/opt/framac-pipeline/scripts/)?run_metadata\.py\b",
        r"^(?:/opt/framac-pipeline/scripts/)?validate_artifacts\.py\b",
        r"^(?:/opt/framac-pipeline/scripts/)?cache\.py\b",
        r"^(?:/opt/framac-pipeline/scripts/)?generate_report\.py\b",
        r"^(?:/opt/framac-pipeline/scripts/)?contract_negotiator\.py\b",
        r"^(?:/usr/bin/|/usr/local/bin/)?(?:e-acsl-gcc(?:\.sh)?|frama-c(?:-gui)?)(?:\s|$)",
    )
    return any(re.search(pat, clean) for pat in static_tool_res)


def cache_mount_mode(cmd: str, cache_rw_requested: bool, cache_dir: str | Path | None = None) -> str:
    """
    How the shared cache is mounted for `cmd`: 'rw' only when rw was requested AND the command
    is exactly an allowlisted trusted step (plain tokens, no shell syntax at all, after expanding
    `$S` / `${S}`); 'off' when the cache dir is 'off' or FRAMAC_CACHE=off; 'ro' otherwise. Class
    inference plays no part.
    """
    if cache_dir is not None and str(cache_dir).strip().lower() == "off":
        return "off"
    if (os.environ.get("FRAMAC_CACHE") or "").strip().lower() == "off":
        return "off"
    text = expand_script_var(cmd or "")
    if cache_rw_requested and _PLAIN_COMMAND.fullmatch(text) and tuple(text.split()) in CACHE_RW_ALLOWLIST:
        return "rw"
    return "ro"


# ---------------------------------------------------------------------------
# Resource history (state/resource-history/<class>/<ts>-<rand>.json)
# ---------------------------------------------------------------------------

_HISTORY_KEEP = 400
_SHARED_HISTORY_SUBDIR = "resource-history"


def _prune_history_dir(d: Path) -> None:
    with contextlib.suppress(OSError):
        names = sorted(n for n in os.listdir(d) if n.endswith(".json"))
        for name in names[: max(0, len(names) - _HISTORY_KEEP)]:
            _unlink(d / name)


def _shared_history_dirs(cls: str, cache_dir: Path | str | None = None) -> list[Path]:
    """Shared cross-run resource-history directories for `cls`, when enabled."""
    if (os.environ.get("FRAMAC_CACHE") or "").strip().lower() == "off":
        return []
    shared = str(cache_dir or os.environ.get("FRAMAC_SHARED_CACHE_DIR") or "").strip()
    if not shared or shared.lower() == "off":
        return []
    sp = Path(shared)
    if not sp.is_dir():
        return []
    return [sp / _SHARED_HISTORY_SUBDIR / cls]


def write_history(run_dir: Path | str, record: dict) -> Path | None:
    """
    Store one usage record of a known class under the run dir (and mirror into the shared
    store when `FRAMAC_CACHE_MODE=rw`); returns the run-dir path.
    """
    cls = record.get("class")
    if cls not in CLASSES:
        return None
    d = Path(run_dir) / HISTORY_DIR / str(cls)
    d.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    fname = f"{stamp}-{secrets.token_hex(4)}.json"
    path = d / fname
    _write_json(path, record)
    _prune_history_dir(d)
    if (os.environ.get("FRAMAC_CACHE_MODE") or "").strip().lower() == "rw":
        for sd in _shared_history_dirs(str(cls)):
            with contextlib.suppress(OSError):
                sd.mkdir(parents=True, exist_ok=True)
                _write_json(sd / fname, record)
                _prune_history_dir(sd)
    return path


def history_estimate(
    run_dir: Path | str | None,
    cls: str,
    key: str | None = None,
    last: int = 5,
    cache_dir: Path | str | None = None,
) -> int | None:
    """Memory (MiB) the history suggests: 1.25 x the max of the last `last` peaks (2 x after an OOM kill)."""
    if run_dir is None or cls not in CLASSES:
        return None
    dirs = [Path(run_dir) / HISTORY_DIR / cls, *_shared_history_dirs(cls, cache_dir=cache_dir)]
    candidates: list[tuple[str, Path]] = []
    seen_names: set[str] = set()
    for d in dirs:
        try:
            names = [n for n in os.listdir(d) if n.endswith(".json")]
        except OSError:
            continue
        for n in names:
            if n not in seen_names:
                seen_names.add(n)
                candidates.append((n, d / n))
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0], reverse=True)
    loaded_records: list[dict] = []
    for _, path in candidates[:64]:
        rec = _load_json(path, max_bytes=64 * 1024)
        if isinstance(rec, dict):
            loaded_records.append(rec)

    def _extract_values(match_fn: Callable[[str | None], bool]) -> list[float]:
        vals: list[float] = []
        for rec in loaded_records:
            rec_key = rec.get("key") or None
            if not match_fn(rec_key):
                continue
            peak = rec.get("peak_mb")
            if isinstance(peak, bool) or not isinstance(peak, (int, float)) or peak <= 0:
                continue
            vals.append(float(peak) * (2.0 if rec.get("oom_killed") else 1.25))
            if len(vals) >= last:
                break
        return vals

    # Tier 1: exact match
    values = _extract_values(lambda rk: rk == (key or None))
    if values:
        return int(math.ceil(max(values)))

    # Tier 2 (TU prefix): If no exact match and '#' in key
    if key and "#" in key:
        tu_prefix = key.split("#", 1)[0]
        values = _extract_values(lambda rk: bool(rk and (rk == tu_prefix or rk.startswith(f"{tu_prefix}#"))))
        if values:
            return int(math.ceil(max(values)))

    # Tier 3 (Module prefix): If no match and ':' in key
    if key and ":" in key:
        mod_prefix = key.split(":", 1)[0]
        values = _extract_values(lambda rk: bool(rk and (rk == mod_prefix or rk.startswith(f"{mod_prefix}:"))))
        if values:
            return int(math.ceil(max(values)))

    return None


# ---------------------------------------------------------------------------
# Locks and leases
# ---------------------------------------------------------------------------


def _lock_fd(fd: int, blocking: bool) -> bool:
    if fcntl is not None:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))  # type: ignore[attr-defined]
            return True
        except BlockingIOError:
            return False
        except OSError as exc:
            if exc.errno in (errno.EAGAIN, errno.EACCES):
                return False
            raise
    if msvcrt is not None:
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            return False
    return True  # no locking primitive at all: best effort


class FileLock:
    """Exclusive lock on a file: fcntl.flock on POSIX, msvcrt.locking on Windows. Released by the OS on death."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self._fd: int | None = None

    @property
    def held(self) -> bool:
        return self._fd is not None

    def acquire(self, blocking: bool = True, timeout: float | None = None) -> bool:
        if self._fd is not None:
            return True
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        deadline = None if timeout is None else time.monotonic() + timeout
        delay = 0.005
        try:
            while True:
                if _lock_fd(fd, blocking=blocking and deadline is None and msvcrt is None):
                    self._fd = fd
                    return True
                if not blocking or (deadline is not None and time.monotonic() >= deadline):
                    os.close(fd)
                    return False
                time.sleep(delay)
                delay = min(delay * 2, 0.05)
        except BaseException:
            with contextlib.suppress(OSError):
                os.close(fd)
            raise

    def release(self) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_UN)  # type: ignore[attr-defined]
            elif msvcrt is not None:
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
        finally:
            os.close(fd)


def lock_is_held(path: Path | str) -> bool:
    """True when some live process holds the lock file (a dead holder's lock is released by the OS)."""
    path = Path(path)
    if not path.exists():
        return False
    probe_lock = FileLock(path)
    try:
        if probe_lock.acquire(blocking=False):
            probe_lock.release()
            return False
        return True
    except OSError:
        return True  # cannot tell: never reclaim on doubt


_LEASE_ID_RE = re.compile(r"^[0-9a-f]{12}$")


def new_lease_id() -> str:
    return secrets.token_hex(6)


@dataclass
class Grant:
    cpus: float
    mem_mb: int
    cpu_set: list[int] | None = None


@dataclass
class Lease:
    id: str
    cls: str
    key: str | None
    cpus: float
    mem_mb: int
    cpu_set: list[int] | None
    gated: bool
    grant_no: int
    single: bool  # no other lease was live when this one was granted
    pool_cpus: int
    pool_mem_mb: int
    waited: bool = False
    warnings: list[str] = field(default_factory=list)
    lock: FileLock | None = field(default=None, repr=False)


def _mem_need(demand: dict, cpus: float) -> int:
    """Memory model of a demand at `cpus`: fixed, else base + per_cpu x cpus, raised to the history floor."""
    if demand.get("fixed_mem_mb"):
        return int(demand["fixed_mem_mb"])
    need = int(demand.get("mem_base_mb") or 0) + int(demand.get("mem_per_cpu_mb") or 0) * int(math.ceil(cpus - 1e-9))
    return max(need, int(demand.get("mem_floor_mb") or 0))


def _mem_for(demand: dict, cpus: float, pool_mem: int) -> int:
    return max(1, min(_mem_need(demand, cpus), int(pool_mem)))  # a demand larger than the pool is clamped to it


def _min_need(demand: dict, pool_cpus: float, pool_mem: int) -> tuple[float, int]:
    fixed = demand.get("fixed_cpus")
    cpus = (
        min(float(fixed), float(max(1, int(pool_cpus))))
        if fixed
        else float(_cpu_bounds(demand.get("min_cpus") or 1, demand.get("max_cpus"), pool_cpus)[0])
    )
    return cpus, _mem_for(demand, cpus, pool_mem)


def _fit(
    demand: dict,
    free_cpus: float,
    free_mem: int,
    pool_cpus: float,
    pool_mem: int,
    waiting_others: int,
    taken: set[int],
    placer: Callable[[int, set[int]], list[int] | None] | None,
    alone: bool = False,
) -> Grant | None:
    fixed = demand.get("fixed_cpus")
    if fixed:
        wanted: list[float] = [min(float(fixed), float(max(1, int(pool_cpus))))]
    else:
        is_wp = demand.get("class") == "wp"
        lo, hi = _cpu_bounds(demand.get("min_cpus") or 1, demand.get("max_cpus"), pool_cpus, alone=(alone and is_wp))
        share = int(max(0.0, free_cpus) + 1e-9) // (1 + max(0, waiting_others))
        top = max(lo, min(share, hi))
        wanted = [float(c) for c in range(top, lo - 1, -1)]  # lower CPUs until the memory fits
    for index, want in enumerate(wanted):
        cpu_set = None
        actual = want
        if placer is not None:
            cpu_set = placer(int(math.ceil(want - 1e-9)), taken)
            if not cpu_set:
                continue
            actual = float(len(cpu_set))
        mem = _mem_need(demand, actual)
        if mem > pool_mem:
            if index < len(wanted) - 1:
                continue  # fewer CPUs need less memory
            mem = max(1, int(pool_mem))  # larger than the whole pool even at the minimum: clamped to it
        if actual <= free_cpus + 1e-9 and mem <= free_mem:
            return Grant(cpus=actual, mem_mb=mem, cpu_set=cpu_set)
    return None


def _norm_run_dir(run_dir: Any) -> str | None:
    if not run_dir:
        return None
    s = str(run_dir).strip()
    if not s:
        return None
    try:
        return os.path.normcase(os.path.realpath(s))
    except OSError:
        return s


def _entry_runs_target_code(entry: dict) -> bool:
    if isinstance(entry.get("runs_target_code"), bool):
        return bool(entry["runs_target_code"])
    cls_obj = CLASSES.get(str(entry.get("class") or ""))
    return bool(cls_obj.runs_target_code) if cls_obj else True


def _run_dir_conflict(a: dict, b: dict) -> bool:
    """
    A `cache_mode='rw'` container and a `runs_target_code=True` container must never run
    concurrently on the same `run_dir`, because both bind-mount `<run_dir>:/workspace:rw`
    and target code could mutate sources/outputs while the `rw` container writes the shared store.
    """
    ra, rb = _norm_run_dir(a.get("run_dir")), _norm_run_dir(b.get("run_dir"))
    if not ra or not rb or ra != rb:
        return False
    a_rw = a.get("cache_mode") == "rw"
    b_rw = b.get("cache_mode") == "rw"
    a_tc = _entry_runs_target_code(a)
    b_tc = _entry_runs_target_code(b)
    return (a_rw and b_tc) or (b_rw and a_tc)


def _queue(entries: list[dict]) -> list[dict]:
    waiting = [e for e in entries if e.get("state") == "waiting" and e.get("gated", True)]
    return sorted(waiting, key=lambda e: (int(e.get("seq") or 0), str(e.get("id"))))


def plan_grant(
    me: dict,
    entries: list[dict],
    pool_cpus: float,
    pool_mem: int,
    placer: Callable[[int, set[int]], list[int] | None] | None = None,
) -> Grant | None:
    """
    Grant for ticket `me` now, or None to keep waiting. CPUs are elastic:
    clamp(free // (1 + waiting), min, min(max or pool, max(min, pool // 2))), lowered until the
    memory (base + per_cpu x cpus, raised by history) fits. Tickets are served FIFO; a later
    ticket is granted first (backfill) only when the head of the queue still fits afterwards.
    A `cache_mode='rw'` ticket and a `runs_target_code=True` ticket on the same `run_dir` are
    mutually exclusive.
    """
    granted_all = [e for e in entries if e.get("state") == "granted"]
    if any(_run_dir_conflict(me, e) for e in granted_all):
        return None
    granted = [e for e in granted_all if e.get("gated", True)]
    free_cpus = pool_cpus - sum(float(e.get("cpus") or 0) for e in granted)
    free_mem = int(pool_mem) - sum(int(e.get("mem_mb") or 0) for e in granted)
    queue = _queue(entries)
    if not any(e.get("id") == me.get("id") for e in queue):
        queue = _queue([*queue, {**me, "state": "waiting", "gated": True}])
    taken: set[int] = set()
    for e in granted:
        taken.update(int(c) for c in e.get("cpu_set") or [])
    waiting_others = len(queue) - 1
    alone = (not granted) and (waiting_others == 0)
    cls_name = me.get("class") or (me.get("demand") or {}).get("class")
    if cls_name and "class" not in me["demand"]:
        me["demand"]["class"] = cls_name
    grant = _fit(me["demand"], free_cpus, free_mem, pool_cpus, pool_mem, waiting_others, taken, placer, alone=alone)
    if grant is None:
        return None
    head = queue[0]
    if head.get("id") != me.get("id"):
        if _run_dir_conflict(me, head):
            return None
        need_cpus, need_mem = _min_need(head["demand"], pool_cpus, pool_mem)
        if need_cpus > free_cpus - grant.cpus + 1e-9 or need_mem > free_mem - grant.mem_mb:
            return None
    return grant


def queue_position(lease_id: str, entries: list[dict]) -> tuple[int, int]:
    ids = [e.get("id") for e in _queue(entries)]
    return (ids.index(lease_id) + 1 if lease_id in ids else 0), len(ids)


def rebalance_grants(
    entries: list[dict],
    pool_cpus: float,
    pool_mem: int,
    placer: Callable[[int, set[int]], list[int] | None] | None = None,
) -> list[dict]:
    """
    Plan grow-only CPU/memory increases for running elastic container leases when the queue is
    empty and free pool resources exist. Never shrinks CPUs or memory (shrinking `--memory` below
    a running container's resident usage can kill or fail it).
    """
    if _queue(entries):
        return []
    granted = sorted(
        (e for e in entries if e.get("state") == "granted" and e.get("gated", True)),
        key=lambda e: (int(e.get("seq") or 0), str(e.get("id"))),
    )
    if not granted:
        return []
    used_cpus = sum(float(e.get("cpus") or 0) for e in granted)
    used_mem = sum(int(e.get("mem_mb") or 0) for e in granted)
    free_cpus = float(pool_cpus) - used_cpus
    free_mem = int(pool_mem) - used_mem
    if free_cpus <= 1e-9 and free_mem <= 0:
        return []

    eligible: list[dict] = []
    for e in granted:
        if not e.get("container"):
            continue
        demand = e.get("demand") or {}
        if demand.get("fixed_cpus") or demand.get("fixed_mem_mb"):
            continue
        cur_cpus = float(e.get("cpus") or 1)
        cur_mem = int(e.get("mem_mb") or 0)
        _lo, hi = _cpu_bounds(demand.get("min_cpus") or 1, demand.get("max_cpus"), pool_cpus)
        target_mem_at_cur = _mem_for(demand, cur_cpus, pool_mem)
        if cur_cpus + 1e-9 < hi or cur_mem < target_mem_at_cur:
            eligible.append(e)
    if not eligible:
        return []

    taken: set[int] = set()
    for e in granted:
        taken.update(int(c) for c in (e.get("cpu_set") or []))

    alone = len(granted) == 1
    updates: list[dict] = []
    for idx, e in enumerate(eligible):
        remaining = len(eligible) - idx
        demand = e.get("demand") or {}
        cls_name = e.get("class") or demand.get("class")
        is_wp = cls_name == "wp"
        cur_cpus = float(e.get("cpus") or 1)
        cur_mem = int(e.get("mem_mb") or 0)
        cur_cpuset = sorted(int(c) for c in (e.get("cpu_set") or []))
        _lo, hi = _cpu_bounds(demand.get("min_cpus") or 1, demand.get("max_cpus"), pool_cpus, alone=(alone and is_wp))
        extra_share = int(math.floor(max(0.0, free_cpus) / remaining + 1e-9))
        if extra_share == 0 and free_cpus >= 1.0 - 1e-9:
            extra_share = 1
        cur_int = int(math.ceil(cur_cpus - 1e-9))
        top = max(cur_int, min(int(hi), int(math.floor(cur_cpus + extra_share + 1e-9))))
        for want in range(top, cur_int - 1, -1):
            actual = max(cur_cpus, float(want))
            new_cpuset: list[int] | None = list(cur_cpuset) if cur_cpuset else None
            if (cur_cpuset or placer is not None) and actual > cur_cpus + 1e-9:
                if placer is None:
                    continue
                need_extra = int(math.ceil(actual - 1e-9)) - len(cur_cpuset)
                if need_extra > 0:
                    added = placer(need_extra, taken)
                    if not added:
                        continue
                    new_cpuset = sorted(set(cur_cpuset) | set(added))
                    actual = float(len(new_cpuset))
            delta_cpus = actual - cur_cpus
            if delta_cpus < -1e-9 or delta_cpus > free_cpus + 1e-9:
                continue
            new_mem = max(cur_mem, _mem_for(demand, actual, pool_mem))
            delta_mem = new_mem - cur_mem
            if delta_mem < 0 or delta_mem > free_mem:
                continue
            if delta_cpus > 1e-9 or delta_mem > 0:
                updates.append(
                    {
                        "id": str(e["id"]),
                        "container": str(e["container"]),
                        "engine": e.get("engine"),
                        "old_cpus": cur_cpus,
                        "cpus": actual,
                        "old_mem_mb": cur_mem,
                        "mem_mb": new_mem,
                        "old_cpu_set": cur_cpuset or None,
                        "cpu_set": new_cpuset,
                    }
                )
                free_cpus -= delta_cpus
                free_mem -= delta_mem
                if new_cpuset:
                    taken.update(new_cpuset)
                break
    return updates


class Broker:
    """
    Leases over a pool, shared by every process using the same broker dir:
    leases/<id>.json records a ticket or grant; leases/<id>.lock is held by its owner for the
    lease's lifetime, so a lock that can be taken means the owner died and the lease is reclaimed
    (unless `container_alive` says its container still runs). broker.lock serializes decisions.
    The pool is re-measured on every attempt, so a shrink blocks new grants; grants are never
    preempted. Light (ungated) classes are registered but never wait and never count.
    """

    def __init__(
        self,
        directory: Path | str,
        pool_fn: Callable[[], Any],
        *,
        history_fn: Callable[[str, str | None], int | None] | None = None,
        placer: Callable[[int, set[int]], list[int] | None] | None = None,
        container_alive: Callable[[dict], bool | None] | None = None,
        poll: float = 0.1,
        max_poll: float = 0.5,
        orphan_recheck_s: float = 5.0,
        log: Any = None,
    ) -> None:
        self.dir = Path(directory)
        self.leases = self.dir / "leases"
        self.leases.mkdir(parents=True, exist_ok=True)
        self.pool_fn = pool_fn
        self.history_fn = history_fn
        self.placer = placer
        self.container_alive = container_alive
        self.poll = poll
        self.max_poll = max_poll
        self.orphan_recheck_s = orphan_recheck_s
        self.log = log

    @contextlib.contextmanager
    def locked(self) -> Iterator[None]:
        lock = FileLock(self.dir / "broker.lock")
        lock.acquire()
        try:
            yield
        finally:
            lock.release()

    def _counters(self) -> dict[str, int]:
        data = _load_json(self.dir / "counters.json")
        data = data if isinstance(data, dict) else {}
        return {"seq": int(data.get("seq") or 0), "grants": int(data.get("grants") or 0)}

    def _write_entry(self, entry: dict) -> None:
        clean = {k: v for k, v in entry.items() if k not in ("alive", "orphaned")}
        _write_json(self.leases / f"{entry['id']}.json", clean)

    def _drop(self, lease_id: str) -> None:
        _unlink(self.leases / f"{lease_id}.json")
        _unlink(self.leases / f"{lease_id}.lock")

    def _container_running(self, entry: dict) -> bool:
        now = time.time()
        if "orphan_running" in entry and now - float(entry.get("orphan_checked_at") or 0) < self.orphan_recheck_s:
            return bool(entry["orphan_running"])
        running = self.container_alive(entry) if self.container_alive else False
        keep = True if running is None else bool(running)  # cannot tell: keep it, re-check later
        entry["orphan_checked_at"], entry["orphan_running"] = now, keep
        with contextlib.suppress(OSError):
            self._write_entry(entry)
        return keep

    def entries(self, reap: bool = True) -> list[dict]:
        """Live tickets and leases (call under `locked()`); dead holders' entries are reclaimed when `reap`."""
        out: list[dict] = []
        for path in sorted(self.leases.glob("*.json")):
            lease_id = path.stem
            if not _LEASE_ID_RE.fullmatch(lease_id):
                continue
            entry = _load_json(path)
            alive = lock_is_held(self.leases / f"{lease_id}.lock")
            if not isinstance(entry, dict) or entry.get("id") != lease_id:
                if not alive and reap:
                    self._drop(lease_id)
                continue
            entry["alive"] = alive
            if not alive:
                if (
                    entry.get("state") == "granted"
                    and entry.get("container")
                    and self.container_alive is not None
                    and self._container_running(entry)
                ):
                    entry["orphaned"] = True
                elif reap:
                    self._drop(lease_id)
                    continue
            out.append(entry)
        return out

    def acquire(
        self,
        cls_name: str,
        key: str | None = None,
        *,
        fixed_cpus: float | None = None,
        fixed_mem_mb: int | None = None,
        mem_floor_mb: int | None = None,
        lease_id: str | None = None,
        extra: dict | None = None,
        timeout: float | None = None,
    ) -> Lease:
        cls = CLASSES[cls_name]
        lid = lease_id or new_lease_id()
        lock = FileLock(self.leases / f"{lid}.lock")
        lock.acquire()
        try:
            return self._acquire(lid, lock, cls, key, fixed_cpus, fixed_mem_mb, mem_floor_mb, extra or {}, timeout)
        except BaseException:
            with contextlib.suppress(Exception), self.locked():
                _unlink(self.leases / f"{lid}.json")
            lock.release()
            _unlink(self.leases / f"{lid}.lock")
            raise

    def _grant(
        self, entry: dict, grant: Grant, pool: Any, single: bool, warnings: list[str], lock: FileLock, waited: bool
    ) -> Lease:
        counters = self._counters()
        counters["grants"] += 1
        entry.update(
            state="granted",
            cpus=grant.cpus,
            mem_mb=grant.mem_mb,
            cpu_set=grant.cpu_set,
            grant_no=counters["grants"],
            granted_at=_utc_now(),
            pool={"cpus": int(pool.cpus), "mem_mb": int(pool.mem_mb)},
        )
        _write_json(self.dir / "counters.json", counters)
        self._write_entry(entry)
        return Lease(
            id=entry["id"],
            cls=entry["class"],
            key=entry.get("key"),
            cpus=grant.cpus,
            mem_mb=grant.mem_mb,
            cpu_set=grant.cpu_set,
            gated=bool(entry.get("gated", True)),
            grant_no=counters["grants"],
            single=single,
            pool_cpus=int(pool.cpus),
            pool_mem_mb=int(pool.mem_mb),
            waited=waited,
            warnings=warnings,
            lock=lock,
        )

    def _acquire(
        self,
        lid: str,
        lock: FileLock,
        cls: JobClass,
        key: str | None,
        fixed_cpus: float | None,
        fixed_mem_mb: int | None,
        mem_floor_mb: int | None,
        extra: dict,
        timeout: float | None,
    ) -> Lease:
        hist = None
        if self.history_fn is not None:
            with contextlib.suppress(Exception):
                hist = self.history_fn(cls.name, key)
        floor = max(v for v in (mem_floor_mb or 0, hist or 0))
        demand = {
            "class": cls.name,
            "min_cpus": cls.min_cpus,
            "max_cpus": cls.max_cpus,
            "mem_base_mb": cls.mem_base_mb,
            "mem_per_cpu_mb": cls.mem_per_cpu_mb,
            "mem_floor_mb": floor or None,
            "fixed_cpus": float(fixed_cpus) if fixed_cpus else None,
            "fixed_mem_mb": int(fixed_mem_mb) if fixed_mem_mb else None,
        }
        runs_tc = extra.pop("runs_target_code", None)
        if runs_tc is None:
            runs_tc = cls.runs_target_code
        entry = {
            "id": lid,
            "state": "waiting",
            "class": cls.name,
            "key": key,
            "gated": cls.gated,
            "runs_target_code": runs_tc,
            "pid": os.getpid(),
            "host": socket.gethostname(),
            "created_at": _utc_now(),
            "demand": demand,
            **extra,
        }
        warnings: list[str] = []
        pool = self.pool_fn()
        need_cpus = float(fixed_cpus) if fixed_cpus else float(cls.min_cpus)
        if need_cpus > pool.cpus:
            warnings.append(
                f"{cls.name} asks for {_fmt_cpus(need_cpus)} CPUs but the pool has {pool.cpus}: clamped to the pool"
            )
        model_mem = fixed_mem_mb or max(cls.mem_base_mb + cls.mem_per_cpu_mb * int(math.ceil(need_cpus)), floor)
        if model_mem > pool.mem_mb:
            warnings.append(f"{cls.name} needs {model_mem} MiB but the pool has {pool.mem_mb} MiB: clamped to the pool")
        for w in warnings:
            self._report(w)
        with self.locked():
            self._sweep_locks()
            counters = self._counters()
            counters["seq"] += 1
            entry["seq"] = counters["seq"]
            _write_json(self.dir / "counters.json", counters)
            others = [e for e in self.entries() if e.get("state") == "granted"]
            if not cls.gated:
                conflicting = [e for e in others if _run_dir_conflict(entry, e)]
                if not conflicting:
                    cpus = min(need_cpus, float(max(1, pool.cpus)))
                    return self._grant(
                        entry,
                        Grant(cpus, _mem_for(demand, cpus, pool.mem_mb)),
                        pool,
                        not others,
                        warnings,
                        lock,
                        waited=False,
                    )
                self._report(
                    f"{cls.name} lease {lid} waiting on run-dir conflict on {entry.get('run_dir')} "
                    f"with {[c.get('id') for c in conflicting]}"
                )
            self._write_entry(entry)
        deadline = None if timeout is None else time.monotonic() + timeout
        delay, last_pos, last_report, waited = self.poll, None, 0.0, False
        while True:
            with self.locked():
                entries = self.entries()
                if not any(e.get("id") == lid for e in entries):  # reclaimed by mistake: register again
                    self._write_entry(entry)
                    entries.append(dict(entry))
                pool = self.pool_fn()
                if not cls.gated:
                    others = [e for e in entries if e.get("id") != lid and e.get("state") == "granted"]
                    if not any(_run_dir_conflict(entry, e) for e in others):
                        cpus = min(need_cpus, float(max(1, pool.cpus)))
                        return self._grant(
                            entry,
                            Grant(cpus, _mem_for(demand, cpus, pool.mem_mb)),
                            pool,
                            not others,
                            warnings,
                            lock,
                            waited,
                        )
                    grant = None
                else:
                    grant = plan_grant(entry, entries, pool.cpus, pool.mem_mb, self.placer)
                    if grant is not None:
                        others = [e for e in entries if e.get("id") != lid and e.get("state") == "granted"]
                        return self._grant(entry, grant, pool, not others, warnings, lock, waited)
                pos, total = queue_position(lid, entries)
                used_cpus = sum(
                    float(e.get("cpus") or 0) for e in entries if e.get("state") == "granted" and e.get("gated", True)
                )
                used_mem = sum(
                    int(e.get("mem_mb") or 0) for e in entries if e.get("state") == "granted" and e.get("gated", True)
                )
            waited = True
            now = time.monotonic()
            if pos != last_pos or now - last_report >= 30.0:
                self._report(
                    f"{cls.name} lease {lid} waiting: #{pos} of {total} in queue "
                    f"(in use {_fmt_cpus(used_cpus)}/{pool.cpus} CPUs, {used_mem}/{pool.mem_mb} MiB)"
                )
                last_pos, last_report = pos, now
            if deadline is not None and now >= deadline:
                raise TimeoutError(f"no {cls.name} lease within {timeout:.0f}s")
            time.sleep(delay)
            delay = min(delay * 1.5, self.max_poll)

    def release(self, lease: Lease) -> bool:
        """Drop the lease. True when it was the only lease from grant to release (a single job)."""
        single = False
        try:
            with self.locked():
                counters = self._counters()
                others = [
                    e for e in self.entries(reap=False) if e.get("id") != lease.id and e.get("state") == "granted"
                ]
                single = lease.single and counters["grants"] == lease.grant_no and not others
                _unlink(self.leases / f"{lease.id}.json")
        finally:
            if lease.lock is not None:
                lease.lock.release()
            _unlink(self.leases / f"{lease.id}.lock")
        return single

    def rebalance(
        self,
        *,
        eng: EngineInfo | None = None,
        runner: Callable[..., Any] | None = None,
        dry_run: bool = False,
    ) -> list[dict]:
        """
        Grow running elastic container leases when the queue is empty and free pool resources exist.
        Never shrinks CPUs or memory. Runs `<engine> update` and updates the lease JSON on success.
        """
        run = runner or subprocess.run
        applied: list[dict] = []
        plans_to_run: list[tuple[dict, list[str]]] = []
        with self.locked():
            entries = self.entries(reap=True)
            pool = self.pool_fn()
            if pool is None:
                return []
            placer = self.placer
            if placer is None and isinstance(pool, Pool) and pool.topology and pool.cpu_ids:
                if any(e.get("cpu_set") for e in entries) or (eng and pin_plan(pool, eng).exclusive):
                    placer = _cpuset_placer(pool)
            plans = rebalance_grants(entries, pool.cpus, pool.mem_mb, placer)
            if not plans:
                return []
            by_id = {str(e["id"]): e for e in entries}
            for plan in plans:
                entry = by_id.get(plan["id"])
                if entry is None:
                    continue
                engine_bin = str(plan.get("engine") or _default_engine() or "docker")
                use_eng = eng or engine_info(engine_bin, cache_dir=self.dir, runner=runner)
                argv = build_engine_update_argv(
                    engine_bin,
                    plan["container"],
                    cpus=plan["cpus"] if plan["cpus"] > plan["old_cpus"] + 1e-9 else None,
                    mem_mb=plan["mem_mb"] if plan["mem_mb"] > plan["old_mem_mb"] else None,
                    cpu_set=plan["cpu_set"] if plan["cpu_set"] != plan["old_cpu_set"] else None,
                    eng=use_eng,
                )
                if argv is None:
                    continue
                plans_to_run.append((plan, argv))

        for plan, argv in plans_to_run:
            rec = {**plan, "argv": argv, "applied": False}
            if dry_run:
                applied.append(rec)
                continue
            try:
                proc = run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15)
                if proc.returncode == 0:
                    with self.locked():
                        current = self.entries(reap=False)
                        entry = next((e for e in current if str(e.get("id")) == str(plan["id"])), None)
                        if entry is not None:
                            entry["cpus"] = plan["cpus"]
                            entry["mem_mb"] = plan["mem_mb"]
                            entry["cpu_set"] = plan["cpu_set"]
                            entry["rebalanced_at"] = _utc_now()
                            self._write_entry(entry)
                    rec["applied"] = True
                else:
                    rec["error"] = proc.stderr.strip() or f"exit code {proc.returncode}"
            except subprocess.TimeoutExpired as exc:
                rec["error"] = f"timed out after {exc.timeout}s"
            except (OSError, subprocess.SubprocessError) as exc:
                rec["error"] = str(exc)
            applied.append(rec)
        return applied

    def _sweep_locks(self) -> None:
        """Remove lock files left without a lease (Windows cannot delete a file another process is probing)."""
        leases = {p.stem for p in self.leases.glob("*.json")}
        for path in self.leases.glob("*.lock"):
            if path.stem not in leases and _LEASE_ID_RE.fullmatch(path.stem) and not lock_is_held(path):
                _unlink(path)

    def gc(self) -> list[str]:
        """Reclaim dead holders' leases and stray lock files; returns the reclaimed ids."""
        with self.locked():
            before = {p.stem for p in self.leases.glob("*.json")}
            alive = {e["id"] for e in self.entries(reap=True)}
            self._sweep_locks()
        return sorted(before - alive)

    def _report(self, message: str) -> None:
        if self.log is not None:
            print(f"[resources] {message}", file=self.log, flush=True)


# ---------------------------------------------------------------------------
# Container broker: `run` (sub-leases inside one container) and `record`
# ---------------------------------------------------------------------------


def container_broker_dir() -> Path:
    env = (os.environ.get("FRAMAC_BROKER_DIR") or "").strip()
    if env:
        return Path(env)
    return Path("/tmp/framac-broker") if os.name == "posix" else Path(tempfile.gettempdir()) / "framac-broker"


@contextlib.contextmanager
def _forward_signals(handler: Callable[[int], None]) -> Iterator[None]:
    previous: dict[int, Any] = {}
    if threading.current_thread() is threading.main_thread():
        for name in ("SIGINT", "SIGTERM", "SIGHUP", "SIGBREAK"):
            sig = getattr(signal, name, None)
            if sig is None:
                continue
            with contextlib.suppress(OSError, ValueError):
                previous[sig] = signal.signal(sig, lambda s, _f: handler(s))
    try:
        yield
    finally:
        for sig, old in previous.items():
            with contextlib.suppress(OSError, ValueError, TypeError):
                signal.signal(sig, old if old is not None else signal.SIG_DFL)


def _shell_rc(rc: int) -> int:
    return 128 - rc if rc < 0 else rc


def _run_child(cmd: list[str], env: dict[str, str]) -> tuple[int, int | None]:
    """Run `cmd`; (returncode, max RSS of its process tree in MiB when the OS reports it)."""
    try:
        proc = subprocess.Popen(cmd, env=env)
    except OSError as exc:
        _say(f"cannot start {cmd[0]!r}: {exc}")
        return 127, None

    def _forward(sig: int) -> None:
        with contextlib.suppress(OSError, ValueError):
            proc.send_signal(sig)

    with _forward_signals(_forward):
        if hasattr(os, "wait4"):
            try:
                _pid, status, usage = os.wait4(proc.pid, 0)
            except ChildProcessError:
                return (proc.returncode if proc.returncode is not None else 0), None
            rc = os.waitstatus_to_exitcode(status)
            proc.returncode = rc
            scale = 1024 if sys.platform.startswith("linux") else _MIB  # KiB on Linux, bytes on macOS
            return rc, (int(-(-usage.ru_maxrss // scale)) if usage.ru_maxrss else None)
        while True:
            try:
                return proc.wait(timeout=0.5), None
            except subprocess.TimeoutExpired:
                continue


def _file_sig(path: str | None) -> tuple[int, int, int] | None:
    if not path:
        return None
    try:
        st = os.stat(path)
    except OSError:
        return None
    return st.st_size, st.st_mtime_ns, st.st_ino


def _output_rc(rc: int, output: str | None, before: tuple[int, int, int] | None) -> int:
    """--output P: success when the command produced P (a stale, untouched P does not count)."""
    if output is None:
        return rc
    after = _file_sig(output)
    if after is not None and (before is None or after != before):
        return 0
    return rc


def _oom_killed(rc: int, before: dict, after: dict) -> bool:
    """SIGKILL (directly, or as a shell reports it) together with a new oom_kill in memory.events."""
    if rc not in (-9, 137):
        return False
    b, a = before.get("oom_kill"), after.get("oom_kill")
    return a is not None and b is not None and a > b


def _record_run_history(
    cls_name: str,
    key: str | None,
    lease: Lease,
    rc: int,
    oom: bool,
    peak: int | None,
    source: str | None,
    wall: float,
    attempt: int,
) -> None:
    if not Path("run-metadata.json").is_file():
        return
    rec = {
        "class": cls_name,
        "key": key,
        "ts": _utc_now(),
        "rc": rc,
        "peak_mb": peak,
        "oom_killed": oom,
        "cpus": lease.cpus,
        "mem_mb": lease.mem_mb,
        "wall_seconds": round(wall, 3),
        "source": source,
        "scope": "job",
        "attempt": attempt,
    }
    with contextlib.suppress(OSError):
        write_history(Path.cwd(), rec)


def cmd_run(argv: list[str], root: Path | str = "/") -> int:
    """`run --class C [--key K] [--output P] -- cmd...`: run cmd under a CPU+memory sub-lease of this container."""
    opts, cmd = _split_dashdash(argv)
    parser = argparse.ArgumentParser(prog="resources.py run", description="Run a command under a container sub-lease.")
    parser.add_argument("--class", dest="cls", default="auto", help="Job class (default: inferred from the command)")
    parser.add_argument("--key", default=None, help="History key, e.g. the function or module name")
    parser.add_argument("--output", default=None, help="Exit 0 when the command produced this file")
    args = parser.parse_args(opts)
    if not cmd:
        parser.error("missing command after --")
    cls_name = infer_class(shlex.join(cmd)) if args.cls in ("", "auto") else args.cls
    if cls_name not in CLASSES:
        parser.error(f"unknown class {cls_name!r} (one of: {', '.join(CLASSES)})")
    before_out = _file_sig(args.output)
    if os.environ.get("FRAMAC_SUBLEASE_ID"):
        # Nested inside a sub-lease of this container: the outer lease already covers this command.
        rc, _ = _run_child(cmd, dict(os.environ))
        return _output_rc(_shell_rc(rc), args.output, before_out)

    root_p = _probe_root(root)
    broker_dir = container_broker_dir()
    problem = prepare_broker_dir(broker_dir, default_location=not os.environ.get("FRAMAC_BROKER_DIR"))
    if problem:
        _say(problem)
        return 2
    run_dir = Path.cwd()
    broker = Broker(
        broker_dir,
        lambda: job_budget(root_p, use_available=False),
        history_fn=lambda c, k: history_estimate(run_dir, c, k),
        log=sys.stderr,
    )
    floor: int | None = None
    attempt = 0
    while True:
        attempt += 1
        lease = broker.acquire(cls_name, args.key, mem_floor_mb=floor)
        env = dict(os.environ)
        env.update(
            FRAMAC_JOB_CPUS=_fmt_cpus(lease.cpus),
            FRAMAC_JOB_MEM_MB=str(lease.mem_mb),
            FRAMAC_JOB_CLASS=cls_name,
            FRAMAC_SUBLEASE_ID=lease.id,
        )
        if args.key:
            env["FRAMAC_JOB_KEY"] = args.key
        before = cgroup_stats(root_p)
        start = time.monotonic()
        try:
            rc, maxrss = _run_child(cmd, env)
        finally:
            single = broker.release(lease)
        wall = time.monotonic() - start
        after = cgroup_stats(root_p)
        oom = _oom_killed(rc, before, after)
        peak, source = maxrss, ("rusage" if maxrss else None)
        cg_peak, cg_before = after.get("peak_mb"), before.get("peak_mb")
        if single and cg_peak and (cg_before is None or cg_peak > cg_before) and cg_peak > (peak or 0):
            peak, source = cg_peak, "cgroup"  # alone in the container: its new memory.peak is this job's
        _record_run_history(cls_name, args.key, lease, rc, oom, peak, source, wall, attempt)
        if oom and CLASSES[cls_name].idempotent and attempt == 1:
            floor = 2 * lease.mem_mb
            _say(f"{cls_name} job was OOM-killed with {lease.mem_mb} MiB; retrying once with {floor} MiB")
            continue
        return _output_rc(_shell_rc(rc), args.output, before_out)


def cmd_record(rc: int, cls: str | None = None, key: str | None = None, root: Path | str = "/") -> int:
    """Write this container's usage to state/resource-history/ (when run-metadata.json is in the cwd); return rc."""
    try:
        cls_name = cls or os.environ.get("FRAMAC_JOB_CLASS") or "light"
        key = key or os.environ.get("FRAMAC_JOB_KEY") or None
        stats = cgroup_stats(_probe_root(root))
        oom = bool(stats.get("oom_kill"))
        peak = stats.get("peak_mb")
        if peak is None and oom:
            peak = stats.get("limit_mb")
        usec = stats.get("cpu_usec")
        rec = {
            "class": cls_name,
            "key": key,
            "ts": _utc_now(),
            "rc": rc,
            "peak_mb": peak,
            "oom_killed": oom,
            "oom_kills": stats.get("oom_kill"),
            "cpu_seconds": round(usec / 1e6, 3) if usec is not None else None,
            "cpus": _env_float("FRAMAC_JOB_CPUS"),
            "mem_mb": parse_mem(os.environ.get("FRAMAC_JOB_MEM_MB")),
            "source": "cgroup",
            "scope": "container",
        }
        written = write_history(Path.cwd(), rec) if Path("run-metadata.json").is_file() else None
        print(json.dumps({**rec, "written": str(written) if written else None}))
    except Exception as exc:  # recording must never change the command's outcome
        _say(f"record failed: {exc}")
    return rc


# ---------------------------------------------------------------------------
# Host broker: `exec` (one lease per container), pinning, engine command line
# ---------------------------------------------------------------------------


def host_broker_dir() -> Path:
    env = (os.environ.get("FRAMAC_BROKER_DIR") or "").strip()
    if env:
        return Path(env)
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "framac-pipeline" / "broker"
    return Path(f"/tmp/framac-pipeline-{os.getuid()}") / "broker"  # type: ignore[attr-defined]


def prepare_broker_dir(path: Path, default_location: bool = False) -> str | None:
    """Create the broker dir; return why it cannot be used (network filesystem, foreign owner, symlink)."""
    try:
        if default_location and os.name == "posix" and str(path.parent).startswith("/tmp/framac-pipeline-"):
            with contextlib.suppress(FileExistsError):
                os.mkdir(path.parent, 0o700)
            st = os.lstat(path.parent)
            if not os.path.isdir(path.parent) or os.path.islink(path.parent) or st.st_uid != os.getuid():  # type: ignore[attr-defined]
                return f"broker dir {path.parent} is not a directory owned by this user; set FRAMAC_BROKER_DIR"
        path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return f"cannot create broker dir {path}: {exc}"
    if os.name == "nt":
        if _windows_remote_path(path):
            return f"broker dir {path} is on a network drive; set FRAMAC_BROKER_DIR to a local directory"
        return None
    kind = fs_type(path)
    if is_network_fs(kind):
        return f"broker dir {path} is on {kind}; leases need a local filesystem (set FRAMAC_BROKER_DIR)"
    return None


@dataclass(frozen=True)
class PinPlan:
    exclusive: bool  # allocate exclusive whole-core CPU sets per lease
    confine: tuple[int, ...] | None  # shared allowed set every container is confined to
    warnings: tuple[str, ...] = ()


def pin_plan(pool: Pool, eng: EngineInfo, mode: str | None = None, platform: str | None = None) -> PinPlan:
    """
    CPU placement policy (FRAMAC_PIN=auto|on|off). On a native Linux engine, a process affinity
    that is a strict subset of the machine (Slurm, cpusets) is always passed as --cpuset-cpus,
    since containers created by the daemon would escape it. `auto` also pins each lease to
    exclusive whole cores when the allowed CPUs span several NUMA nodes or L3 domains.
    """
    mode = (mode or os.environ.get("FRAMAC_PIN") or "auto").strip().lower()
    if mode not in ("auto", "on", "off"):
        mode = "auto"
    native = (platform or sys.platform).startswith("linux") and not eng.vm_backed and not eng.remote
    warnings: list[str] = []
    confine: tuple[int, ...] | None = None
    if native and pool.subset and pool.cpu_ids:
        if eng.cpuset:
            confine = tuple(pool.cpu_ids)
        else:
            warnings.append(
                f"this process may only use CPUs {format_cpu_list(pool.cpu_ids)}, but {eng.kind} cannot "
                "set --cpuset-cpus (cpuset controller not delegated): containers may use other CPUs"
            )
    if not native:
        if mode == "on":
            warnings.append("FRAMAC_PIN=on ignored: the engine runs containers in a VM or on another host")
        return PinPlan(False, confine, tuple(warnings))
    if mode == "off" or not eng.cpuset or not pool.topology:
        return PinPlan(False, confine, tuple(warnings))
    topo = pool.topology
    multi = len(topo.get("numa") or []) > 1 or len(topo.get("l3") or []) > 1
    return PinPlan(mode == "on" or multi, confine, tuple(warnings))


def allocate_cpuset(topology: dict, allowed: Iterable[int], taken: Iterable[int], cpus: int) -> list[int] | None:
    """
    An exclusive set of whole free cores with at least `cpus` logical CPUs. Inside one domain
    when one fits (finest of L3/NUMA first; best fit = the fullest domain that still fits, to
    limit fragmentation), else spread over the emptiest domains. None when not enough free cores.
    """
    allowed_set, taken_set = set(allowed), set(taken)
    cores: list[list[int]] = []
    seen: set[int] = set()
    for core in topology.get("cores") or []:
        members = sorted(set(core) & (allowed_set - seen))
        if members:
            cores.append(members)
            seen.update(members)
    cores.extend([cpu] for cpu in sorted(allowed_set - seen))
    free = [c for c in cores if not taken_set.intersection(c)]
    want = max(1, int(cpus))
    if sum(len(c) for c in free) < want:
        return None

    def take(candidates: list[list[int]]) -> list[int] | None:
        out: list[int] = []
        for core in candidates:
            out.extend(core)
            if len(out) >= want:
                return sorted(out)
        return None

    levels = []
    for name in ("l3", "numa"):
        domains = [s for s in (set(d) & allowed_set for d in topology.get(name) or []) if s]
        if len(domains) > 1:
            levels.append(domains)
    levels.sort(key=len, reverse=True)  # finest partition first
    for domains in levels:
        best: tuple[int, int, list[list[int]]] | None = None
        for dom in domains:
            dcores = [c for c in free if set(c) <= dom]
            threads = sum(len(c) for c in dcores)
            if threads >= want and (best is None or (threads, min(dom)) < best[:2]):
                best = (threads, min(dom), dcores)
        if best is not None:
            return take(best[2])
    if not levels:
        return take(free)
    coarse = levels[-1]
    order = sorted(coarse, key=lambda d: (-sum(len(c) for c in free if set(c) <= d), min(d)))
    ordered = [c for d in order for c in free if set(c) <= d]
    ordered += [c for c in free if c not in ordered]
    return take(ordered)


_MANAGED_FLAGS = frozenset({"--cpus", "--cpuset-cpus", "--memory", "-m", "--memory-swap", "--pids-limit", "--name"})


def build_engine_argv(
    engine_argv: list[str],
    *,
    lease_id: str,
    cls_name: str,
    cpus: float,
    mem_mb: int,
    eng: EngineInfo,
    pool_cpus: int,
    pool_mem_mb: int,
    key: str | None = None,
    cpu_set: Iterable[int] | None = None,
    confine: Iterable[int] | None = None,
    pids_limit: int | None = DEFAULT_PIDS_LIMIT,
    cache_host: str | Path | None = None,
    cache_mode: str = "off",
    selinux: bool = False,
    command: str | None = None,
    image_id: str | None = None,
) -> list[str]:
    """
    `<engine> run <lease flags> <caller's flags...> [command]`. Inserted right after `run`: the
    lease's --name/--label, --init, the CPU/memory/pids limits (each only when the engine can
    enforce it), the job and pool environment, and the shared cache mount.
    """
    if len(engine_argv) < 2 or engine_argv[1] != "run":
        raise ValueError("the engine command line must start with '<engine> run'")
    flags = ["--name", f"framac-{lease_id}", "--label", f"framac.lease={lease_id}", "--init"]
    exclusive = sorted(set(cpu_set or []))
    if exclusive and eng.cpuset:
        flags += ["--cpuset-cpus", format_cpu_list(exclusive)]
    else:
        if eng.cpu:
            flags += ["--cpus", _fmt_cpus(cpus)]
        shared = sorted(set(confine or []))
        if shared and eng.cpuset:
            flags += ["--cpuset-cpus", format_cpu_list(shared)]
    if eng.memory:
        flags += ["--memory", f"{int(mem_mb)}m"]
        if eng.swap:
            flags += ["--memory-swap", f"{int(mem_mb)}m"]
    if pids_limit and eng.pids:
        flags += ["--pids-limit", str(int(pids_limit))]
    env = [
        ("FRAMAC_JOB_CPUS", _fmt_cpus(cpus)),
        ("FRAMAC_JOB_MEM_MB", str(int(mem_mb))),
        ("FRAMAC_JOB_CLASS", cls_name),
    ]
    if eng.cpu or eng.memory:
        env.append(("FRAMAC_CGROUP_ENFORCED", "1"))
    if key:
        env.append(("FRAMAC_JOB_KEY", key))
    env += [("FRAMAC_POOL_CPUS", str(int(pool_cpus))), ("FRAMAC_POOL_MEM_MB", str(int(pool_mem_mb)))]
    if image_id:
        env.append(("FRAMAC_IMAGE_ID", image_id))
    mounted = cache_mode in ("ro", "rw") and bool(cache_host)
    env.append(("FRAMAC_CACHE_MODE", cache_mode if mounted else "off"))
    if mounted:
        env.append(("FRAMAC_SHARED_CACHE_DIR", CONTAINER_CACHE_MOUNT))  # read by scripts/cache.py
    for name, value in env:
        flags += ["-e", f"{name}={value}"]
    if mounted:
        opts = [] if cache_mode == "rw" else ["ro"]
        if selinux:
            opts.append("z")
        flags += ["-v", f"{cache_host}:{CONTAINER_CACHE_MOUNT}" + (":" + ",".join(opts) if opts else "")]
    tail = list(engine_argv[2:]) + ([command] if command is not None else [])
    return [engine_argv[0], "run", *flags, *tail]


def build_engine_update_argv(
    engine_bin: str,
    container: str,
    *,
    cpus: float | None = None,
    mem_mb: int | None = None,
    cpu_set: Iterable[int] | None = None,
    eng: EngineInfo | None = None,
) -> list[str] | None:
    """
    `<engine> update <flags> <container>` for grow-only resizing of a running container.
    Only emits flags the engine can enforce; returns None if no flag applies.
    """
    info = eng or EngineInfo()
    flags: list[str] = []
    exclusive = sorted(set(cpu_set or []))
    if exclusive:
        if info.cpuset:
            flags += ["--cpuset-cpus", format_cpu_list(exclusive)]
    elif cpus is not None and info.cpu:
        flags += ["--cpus", _fmt_cpus(cpus)]
    if mem_mb is not None and info.memory:
        flags += ["--memory", f"{int(mem_mb)}m"]
        if info.swap:
            flags += ["--memory-swap", f"{int(mem_mb)}m"]
    if not flags:
        return None
    return [engine_bin, "update", *flags, container]


_REPO_PARTITION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


def _cache_plan(cache_dir: str | None, cache_rw: bool, command: str | None) -> tuple[Path | None, str]:
    raw = cache_dir if cache_dir is not None else (os.environ.get("FRAMAC_CACHE_DIR") or None)
    mode = cache_mount_mode(command or "", cache_rw, raw)
    if mode == "off":
        return None, "off"
    path = Path(raw).expanduser() if raw else Path.home() / ".cache" / "framac-pipeline"
    repo = (os.environ.get("FRAMAC_REPO") or "").strip()
    if repo:
        # One store per repository (the wrappers' repo name): a repository's runs only ever read
        # entries that its own runs' trusted steps wrote.
        part = repo if _REPO_PARTITION_RE.fullmatch(repo) else hashlib.sha256(repo.encode()).hexdigest()[:16]
        path = path / "repos" / part
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        _say(f"shared cache disabled: cannot create {path}: {exc}")
        return None, "off"
    return path.resolve(), mode


def _cpuset_placer(pool: Pool) -> Callable[[int, set[int]], list[int] | None]:
    topo, allowed = dict(pool.topology or {}), list(pool.cpu_ids)

    def place(want: int, taken: set[int]) -> list[int] | None:
        return allocate_cpuset(topo, allowed, taken, want)

    return place


def _run_engine(argv: list[str], engine_bin: str, name: str) -> int:
    try:
        proc = subprocess.Popen(argv)
    except OSError as exc:
        _say(f"cannot start {argv[0]!r}: {exc}")
        return 127
    killed: list[int] = []

    def _kill(sig: int) -> None:
        if killed:
            return
        killed.append(sig)
        _say(f"signal {sig}: killing container {name}")
        with contextlib.suppress(OSError):
            subprocess.Popen([engine_bin, "kill", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    with _forward_signals(_kill):
        while True:
            try:
                return _shell_rc(proc.wait(timeout=0.5))
            except subprocess.TimeoutExpired:
                continue


def cmd_exec(argv: list[str]) -> int:
    """`exec [--class C] --run-dir R [...] -- <engine> run ...`: run one container under a host lease."""
    opts, engine_argv = _split_dashdash(argv)
    parser = argparse.ArgumentParser(prog="resources.py exec", description="Run a container under a host lease.")
    parser.add_argument(
        "--class", dest="cls", default="auto", help="Job class (default: inferred from FRAMAC_CONTAINER_CMD)"
    )
    parser.add_argument("--key", default=None)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--cpus", default=None, help="Fixed CPU grant (still registered with the broker)")
    parser.add_argument("--memory", default=None, help="Fixed memory grant, e.g. 8g")
    parser.add_argument("--pids-limit", type=int, default=None)
    parser.add_argument("--cache-dir", default=None, help="Shared cache dir on the host, or 'off'")
    parser.add_argument(
        "--cache-rw",
        action="store_true",
        help="Writable shared cache for the allowlisted commands; the default unless FRAMAC_CACHE_RW=off",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print the engine command line instead of running it")
    args = parser.parse_args(opts)
    if len(engine_argv) < 2 or engine_argv[1] != "run":
        parser.error("expected: exec [options] -- <engine> run [engine options] <image> [args]")
    engine_bin = shutil.which(engine_argv[0])
    if not engine_bin:
        _say(f"container engine {engine_argv[0]!r} not found on PATH")
        return 127
    clash = next((a for a in engine_argv[2:] if a.split("=", 1)[0] in _MANAGED_FLAGS), None)
    if clash:
        parser.error(f"{clash} is managed by the broker; pass --cpus/--memory/--pids-limit to exec instead")
    command = os.environ.get("FRAMAC_CONTAINER_CMD")
    if args.cls in ("", "auto"):
        cls_name = infer_class(command or "", base_dir=args.run_dir)
        cls = CLASSES[cls_name]
        runs_target_code = cls.runs_target_code or not is_known_static_command(command)
    else:
        cls_name = args.cls
        if cls_name not in CLASSES:
            parser.error(f"unknown class {cls_name!r} (one of: {', '.join(CLASSES)})")
        cls = CLASSES[cls_name]
        runs_target_code = cls.runs_target_code
    fixed_cpus = None
    if args.cpus:
        try:
            fixed_cpus = float(args.cpus)
        except ValueError:
            fixed_cpus = None
        if not fixed_cpus or fixed_cpus <= 0:
            parser.error(f"invalid --cpus {args.cpus!r}")
    fixed_mem = parse_mem(args.memory) if args.memory else None
    if args.memory and not fixed_mem:
        parser.error(f"invalid --memory {args.memory!r}")

    broker_dir = host_broker_dir()
    problem = prepare_broker_dir(broker_dir, default_location=not os.environ.get("FRAMAC_BROKER_DIR"))
    if problem:
        _say(problem)
        return 2
    eng = engine_info(engine_bin, cache_dir=broker_dir)
    if not eng.ok:
        _say(f"container engine view unavailable ({eng.error}); sizing from the host and passing every limit flag")
    missing = [n for n, ok in (("memory", eng.memory), ("pids", eng.pids)) if not ok]
    if missing and runs_target_code and os.environ.get("FRAMAC_ALLOW_UNENFORCED_LIMITS") != "1":
        _say(
            f"{eng.kind} cannot enforce {' and '.join(missing)} limits here (cgroup controllers not available or "
            f"not delegated), so class {cls_name}, which runs target code, is refused. Delegate the controllers "
            "(e.g. systemd Delegate=cpu cpuset memory pids) or set FRAMAC_ALLOW_UNENFORCED_LIMITS=1."
        )
        return 2
    run_dir = Path(args.run_dir)
    # The exact allowlist decides; FRAMAC_CACHE_RW=off keeps the shared store read-only everywhere.
    cache_rw = args.cache_rw or (os.environ.get("FRAMAC_CACHE_RW") or "on").strip().lower() not in (
        "0",
        "off",
        "no",
        "false",
    )
    cache_host, cache_mode = _cache_plan(args.cache_dir, cache_rw, command)

    def pool_fn() -> Pool:
        return probe("host", engine=eng, run_dir=run_dir, cache_dir=cache_host, broker_dir=broker_dir)

    pool = pool_fn()
    plan = pin_plan(pool, eng)
    placer = _cpuset_placer(pool) if plan.exclusive and pool.topology and cls.gated else None
    lease_id = new_lease_id()
    name = f"framac-{lease_id}"
    broker = Broker(
        broker_dir,
        pool_fn,
        history_fn=lambda c, k: history_estimate(run_dir, c, k, cache_dir=cache_host),
        placer=placer,
        container_alive=lambda e: container_running(str(e.get("engine") or engine_bin), e["id"]),
        log=sys.stderr,
    )
    if cache_mode == "rw" and not args.cache_rw:
        norm_rd = _norm_run_dir(run_dir)
        with broker.locked():
            entries = broker.entries()
        if norm_rd and any(_norm_run_dir(e.get("run_dir")) == norm_rd and _entry_runs_target_code(e) for e in entries):
            cache_mode = "ro"
            _say("shared cache mounted read-only: a target-code job is active on this run directory")
    lease = broker.acquire(
        cls_name,
        args.key,
        fixed_cpus=fixed_cpus,
        fixed_mem_mb=fixed_mem,
        lease_id=lease_id,
        extra={
            "container": name,
            "engine": engine_bin,
            "scope": "host",
            "run_dir": str(run_dir),
            "cache_mode": cache_mode,
            "runs_target_code": runs_target_code,
        },
    )
    try:
        for warning in plan.warnings:
            _say(warning)
        full = build_engine_argv(
            [engine_bin, *engine_argv[1:]],
            lease_id=lease.id,
            cls_name=cls_name,
            key=args.key,
            cpus=lease.cpus,
            mem_mb=lease.mem_mb,
            cpu_set=lease.cpu_set,
            confine=plan.confine,
            pids_limit=args.pids_limit or DEFAULT_PIDS_LIMIT,
            eng=eng,
            pool_cpus=lease.pool_cpus,
            pool_mem_mb=lease.pool_mem_mb,
            cache_host=cache_host,
            cache_mode=cache_mode,
            selinux=selinux_enforcing(),
            command=command,
            image_id=os.environ.get("FRAMAC_IMAGE_ID") or None,
        )
        if lease.waited or os.environ.get("FRAMAC_RESOURCES_VERBOSE") == "1":
            _say(
                f"{cls_name} lease {lease.id}: {_fmt_cpus(lease.cpus)} CPUs, {lease.mem_mb} MiB "
                f"(pool {lease.pool_cpus} CPUs, {lease.pool_mem_mb} MiB)"
            )
        if args.dry_run:
            print(
                json.dumps(
                    {
                        "argv": full,
                        "class": cls_name,
                        "lease": lease.id,
                        "cpus": lease.cpus,
                        "mem_mb": lease.mem_mb,
                        "cpu_set": lease.cpu_set,
                        "cache_mode": cache_mode,
                    },
                    indent=2,
                )
            )
            return 0
        return _run_engine(full, engine_bin, name)
    finally:
        broker.release(lease)
        if lease.gated and not args.dry_run:
            with contextlib.suppress(Exception):
                broker.rebalance(eng=eng)


def _default_engine() -> str | None:
    """The engine `exec` would most likely run: FRAMAC_CONTAINER_ENGINE, else docker, else podman."""
    pref = (os.environ.get("FRAMAC_CONTAINER_ENGINE") or "auto").strip().lower()
    for name in [pref] if pref in ("docker", "podman") else ["docker", "podman"]:
        found = shutil.which(name)
        if found:
            return found
    return None


def _status(scope: str, broker_dir: str | None, gc: bool, engine: str | None = None) -> dict:
    if scope == "auto":
        scope = "container" if in_container() else "host"
    d = Path(broker_dir) if broker_dir else (container_broker_dir() if scope == "container" else host_broker_dir())
    out: dict[str, Any] = {"scope": scope, "broker_dir": str(d), "granted": [], "waiting": [], "reclaimed": []}
    with contextlib.suppress(Exception):
        if scope == "host":
            # The engine's view, as `exec` measures it: on Docker Desktop the VM, not the host's RAM.
            eng = (shutil.which(engine) or engine) if engine else _default_engine()
            out["pool"] = probe("host", engine=eng, broker_dir=d if eng else None).summary()
        else:
            out["pool"] = asdict(job_budget(use_available=False))
    if not (d / "leases").is_dir():
        return out
    broker = Broker(
        d,
        lambda: None,
        container_alive=(
            (lambda e: container_running(str(e["engine"]), e["id"]) if e.get("engine") else None)
            if scope == "host"
            else None
        ),
    )
    if gc:
        out["reclaimed"] = broker.gc()
    with broker.locked():
        entries = broker.entries(reap=False)
    keys = (
        "id",
        "class",
        "key",
        "state",
        "cpus",
        "mem_mb",
        "cpu_set",
        "pid",
        "host",
        "container",
        "created_at",
        "granted_at",
        "seq",
        "alive",
        "orphaned",
    )
    for e in sorted(entries, key=lambda e: int(e.get("seq") or 0)):
        row = {k: e.get(k) for k in keys if k in e}
        out["granted" if e.get("state") == "granted" else "waiting"].append(row)
    return out


def _split_dashdash(argv: list[str]) -> tuple[list[str], list[str]]:
    if "--" in argv:
        i = argv.index("--")
        return argv[:i], argv[i + 1 :]
    return argv, []


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "run":
        return cmd_run(argv[1:])
    if argv and argv[0] == "exec":
        return cmd_exec(argv[1:])
    parser = argparse.ArgumentParser(description="Measure resources, size pipeline jobs and lease them.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("budget", help="This job's CPUs and memory")
    p_rec = sub.add_parser("recommend", help="Sizing hints for skills, Make and the scheduler")
    p_rec.add_argument("--max-agents", type=int, default=None)
    p_rec.add_argument("--field", default=None, help="Print one top-level field (e.g. make_jobs, max_agents)")
    p_cls = sub.add_parser("classify", help="Job class of a command line")
    p_cls.add_argument("command")
    p_probe = sub.add_parser("probe", help="Full measurement of the pool (sources, reserve, topology, engine view)")
    p_probe.add_argument("--scope", choices=["host", "container", "auto"], default="auto")
    p_probe.add_argument("--engine", default=None, help="Container engine to query (host scope)")
    p_probe.add_argument("--run-dir", default=None)
    p_probe.add_argument("--summary", action="store_true", help="Print the compact run-metadata summary only")
    p_record = sub.add_parser("record", help="Record this container's usage (used by container_entry.sh)")
    p_record.add_argument("--rc", type=int, required=True, help="Exit code to record and return")
    p_record.add_argument("--class", dest="cls", default=None)
    p_record.add_argument("--key", default=None)
    for name, text in (("status", "List leases and tickets"), ("gc", "Reclaim the leases of dead holders")):
        p = sub.add_parser(name, help=text)
        p.add_argument("--scope", choices=["host", "container", "auto"], default="auto")
        p.add_argument("--broker-dir", default=None)
        p.add_argument(
            "--engine",
            default=None,
            help="Engine whose view sizes the host pool (default: FRAMAC_CONTAINER_ENGINE, docker, podman)",
        )
    p_reb = sub.add_parser("rebalance", help="Grow running elastic container leases into free pool resources")
    p_reb.add_argument("--broker-dir", default=None)
    p_reb.add_argument("--engine", default=None)
    p_reb.add_argument("--dry-run", action="store_true")
    sub.add_parser("run", help="Container broker: run --class C [--key K] [--output P] -- cmd...")
    sub.add_parser("exec", help="Host broker: exec [--class C] --run-dir R [...] -- <engine> run ...")
    args = parser.parse_args(argv)
    if args.cmd == "budget":
        out: object = asdict(job_budget())
    elif args.cmd == "recommend":
        rec = recommend(args.max_agents)
        if args.field:
            print(
                rec.get(args.field)
                if not isinstance(rec.get(args.field), (dict, list))
                else json.dumps(rec.get(args.field))
            )
            return 0
        out = rec
    elif args.cmd == "classify":
        out = {"class": infer_class(args.command)}
    elif args.cmd == "probe":
        scope = args.scope if args.scope != "auto" else ("container" if in_container() else "host")
        engine = (shutil.which(args.engine) or args.engine) if args.engine else None
        pool = probe(scope, engine=engine, run_dir=args.run_dir, broker_dir=host_broker_dir() if engine else None)
        out = pool.summary() if args.summary else pool.to_dict()
    elif args.cmd == "record":
        return cmd_record(args.rc, args.cls, args.key)
    elif args.cmd == "rebalance":
        bdir = Path(args.broker_dir) if args.broker_dir else host_broker_dir()
        eng_bin = (shutil.which(args.engine) or args.engine) if args.engine else _default_engine()
        eng_obj = engine_info(eng_bin, cache_dir=bdir) if eng_bin else None
        broker = Broker(
            bdir,
            lambda: probe("host", engine=eng_obj or eng_bin, broker_dir=bdir),
            container_alive=lambda e: container_running(str(e.get("engine") or eng_bin or "docker"), e["id"]),
        )
        out = {"rebalanced": broker.rebalance(eng=eng_obj, dry_run=args.dry_run)}
    else:
        out = _status(args.scope, args.broker_dir, gc=args.cmd == "gc", engine=args.engine)
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
