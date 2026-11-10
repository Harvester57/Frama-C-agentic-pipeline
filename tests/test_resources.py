"""
scripts/resources.py beyond the stable API: probes on fake /proc and /sys trees, engine views,
engine command lines, CPU pinning, the lease broker (with real processes), run/record/exec.
No Docker, Podman or Frama-C is needed: engines are canned JSON or tiny shims.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from typing import Any

import pytest

import resources as R

SCRIPT = Path(R.__file__).resolve()
GiB = 1024**3


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch):
    """Probes must only see the fake trees and variables a test sets."""
    for name in list(os.environ):
        if name.startswith(("FRAMAC_", "SLURM_")) or name in (
            "DOCKER_HOST",
            "CONTAINER_HOST",
            "DOCKER_CONTEXT",
            "WSL_DISTRO_NAME",
            "WSL_INTEROP",
        ):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("FRAMAC_PROBE_MEMO_S", "0")


def put(root: Path, rel: str, text: str) -> Path:
    path = root / rel.lstrip("/")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")
    return path


def wait_for(predicate, timeout: float = 20.0, step: float = 0.05):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(step)
    raise AssertionError("condition not reached in time")


# ---------------------------------------------------------------------------
# Probes on fake trees
# ---------------------------------------------------------------------------

CGROUP2_MOUNT = "30 23 0:26 / /sys/fs/cgroup rw,nosuid,nodev,noexec - cgroup2 cgroup2 rw,nsdelegate\n"


def test_cgroup_v2_takes_the_minimum_over_every_ancestor(tmp_path):
    put(tmp_path, "/proc/self/cgroup", "0::/user.slice/job.scope/step\n")
    put(tmp_path, "/proc/self/mountinfo", CGROUP2_MOUNT)
    cg = "/sys/fs/cgroup"
    put(tmp_path, f"{cg}/user.slice/cpu.max", "200000 100000\n")  # the tightest CPU limit is an ancestor
    put(tmp_path, f"{cg}/user.slice/memory.max", str(8 * GiB))
    put(tmp_path, f"{cg}/user.slice/job.scope/cpu.max", "600000 100000\n")
    put(tmp_path, f"{cg}/user.slice/job.scope/memory.max", str(3 * GiB))  # ...and memory the middle one
    put(tmp_path, f"{cg}/user.slice/job.scope/step/cpu.max", "max 100000\n")
    put(tmp_path, f"{cg}/user.slice/job.scope/step/memory.max", "max\n")
    put(tmp_path, f"{cg}/user.slice/job.scope/step/memory.high", str(5 * GiB))
    put(tmp_path, f"{cg}/user.slice/job.scope/step/cpuset.cpus.effective", "0-3\n")
    view = R.cgroup_view(tmp_path)
    assert (view.version, view.cpu_quota, view.mem_limit_mb, view.cpuset) == (2, 2.0, 3072, [0, 1, 2, 3])
    assert view.memory_dir == tmp_path / "sys/fs/cgroup/user.slice/job.scope/step"
    b = R.job_budget(tmp_path)
    assert (b.cpus, b.mem_mb) == (2, 3072)


def test_cgroup_v2_path_is_resolved_against_the_mount_root(tmp_path):
    # A cgroup namespace or a bind-mounted subtree: mountinfo's root field is the container's own cgroup.
    put(tmp_path, "/proc/self/cgroup", "0::/docker/abc/sub\n")
    put(tmp_path, "/proc/self/mountinfo", "30 23 0:26 /docker/abc /sys/fs/cgroup ro,nosuid - cgroup2 cgroup rw\n")
    put(tmp_path, "/sys/fs/cgroup/cpu.max", "300000 100000\n")
    put(tmp_path, "/sys/fs/cgroup/sub/memory.max", str(GiB))
    view = R.cgroup_view(tmp_path)
    assert view.cpu_quota == 3.0 and view.mem_limit_mb == 1024
    assert view.memory_dir == tmp_path / "sys/fs/cgroup/sub"


def test_cgroup_v1_limits_and_usage_through_mountinfo_roots(tmp_path):
    put(
        tmp_path,
        "/proc/self/cgroup",
        """
        12:memory:/docker/abc
        11:cpu,cpuacct:/docker/abc
        10:cpuset:/docker/abc
    """,
    )
    put(
        tmp_path,
        "/proc/self/mountinfo",
        """
        40 30 0:35 /docker/abc /sys/fs/cgroup/memory ro,nosuid - cgroup cgroup rw,memory
        41 30 0:36 /docker/abc /sys/fs/cgroup/cpu,cpuacct ro,nosuid - cgroup cgroup rw,cpu,cpuacct
        42 30 0:37 /docker/abc /sys/fs/cgroup/cpuset ro,nosuid - cgroup cgroup rw,cpuset
    """,
    )
    put(tmp_path, "/sys/fs/cgroup/memory/memory.limit_in_bytes", str(2 * GiB))
    put(tmp_path, "/sys/fs/cgroup/memory/memory.max_usage_in_bytes", str(700 * 1024 * 1024))
    put(tmp_path, "/sys/fs/cgroup/memory/memory.oom_control", "oom_kill_disable 0\nunder_oom 0\noom_kill 2\n")
    put(tmp_path, "/sys/fs/cgroup/cpu,cpuacct/cpu.cfs_quota_us", "150000")
    put(tmp_path, "/sys/fs/cgroup/cpu,cpuacct/cpu.cfs_period_us", "100000")
    put(tmp_path, "/sys/fs/cgroup/cpu,cpuacct/cpuacct.usage", "5000000000")
    put(tmp_path, "/sys/fs/cgroup/cpuset/cpuset.effective_cpus", "2-5")
    view = R.cgroup_view(tmp_path)
    assert (view.version, view.cpu_quota, view.mem_limit_mb, view.cpuset) == (1, 1.5, 2048, [2, 3, 4, 5])
    stats = R.cgroup_stats(tmp_path)
    assert (stats["peak_mb"], stats["oom_kill"], stats["cpu_usec"]) == (700, 2, 5_000_000)


def test_cgroup_v1_host_hierarchy_walks_up_to_the_mount_point(tmp_path):
    put(tmp_path, "/proc/self/cgroup", "5:memory:/slurm/uid_1/job_7\n")
    put(tmp_path, "/proc/self/mountinfo", "40 30 0:35 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n")
    put(tmp_path, "/sys/fs/cgroup/memory/slurm/uid_1/job_7/memory.limit_in_bytes", "9223372036854771712")  # unlimited
    put(tmp_path, "/sys/fs/cgroup/memory/slurm/uid_1/memory.limit_in_bytes", str(GiB))
    put(tmp_path, "/sys/fs/cgroup/memory/memory.limit_in_bytes", "9223372036854771712")
    assert R.cgroup_view(tmp_path).mem_limit_mb == 1024


def _machine(root: Path, cpus: str = "0-15", mem_gib: int = 64) -> Path:
    put(root, "/sys/devices/system/cpu/online", cpus + "\n")
    put(root, "/proc/meminfo", f"MemTotal: {mem_gib * 1024 * 1024} kB\nMemAvailable: {mem_gib * 1024 * 1024} kB\n")
    return root


def test_probe_slurm_allocation_reserve_and_caps(tmp_path, monkeypatch):
    root = _machine(tmp_path)
    monkeypatch.setenv("SLURM_CPUS_ON_NODE", "8")
    monkeypatch.setenv("SLURM_JOB_CPUS_PER_NODE", "8(x2)")
    monkeypatch.setenv("SLURM_MEM_PER_NODE", "16000")
    pool = R.probe("host", root=root)
    # min(machine 16, Slurm 8) - max(0.5, 5%); min(64 GiB, 16000 MB) - max(1 GiB, 10%).
    assert (pool.cpus, pool.mem_mb) == (7, 14400)
    assert pool.binding == {"cpus": "slurm", "mem_mb": "slurm"}
    assert pool.reserve == {"cpus": 0.5, "mem_mb": 1600}

    monkeypatch.setenv("FRAMAC_RESERVE_CPUS", "0")
    monkeypatch.setenv("FRAMAC_RESERVE_MEMORY", "25%")
    assert (R.probe("host", root=root).cpus, R.probe("host", root=root).mem_mb) == (8, 12000)

    monkeypatch.setenv("FRAMAC_POOL_CPUS", "4")
    monkeypatch.setenv("FRAMAC_POOL_MEMORY", "6g")
    capped = R.probe("host", root=root)
    assert (capped.cpus, capped.mem_mb, capped.binding) == (4, 6144, {"cpus": "cap", "mem_mb": "cap"})

    monkeypatch.delenv("SLURM_MEM_PER_NODE")
    monkeypatch.setenv("SLURM_MEM_PER_CPU", "1000")
    assert R.slurm_limits() == (8, 8000)
    assert R.parse_slurm_cpus_per_node("4(x2),2", 2) == 2 and R.parse_slurm_cpus_per_node("bogus") is None


def test_container_scope_reserves_only_for_machine_bound_resources(tmp_path, monkeypatch):
    root = _machine(tmp_path)
    put(root, "/sys/fs/cgroup/cpu.max", "400000 100000\n")
    put(root, "/sys/fs/cgroup/memory.max", "max\n")
    pool = R.probe("container", root=root)
    # The cgroup CPU limit is the host broker's grant: no reserve. Memory is only bounded by the machine.
    assert (pool.cpus, pool.binding["cpus"], pool.reserve["cpus"]) == (4, "cgroup", 0.0)
    assert (pool.binding["mem_mb"], pool.mem_mb) == ("machine", 58982)  # 64 GiB - max(1 GiB, 10%)
    monkeypatch.setenv("FRAMAC_JOB_CPUS", "2")
    monkeypatch.setenv("FRAMAC_JOB_MEM_MB", "3000")
    granted = R.probe("container", root=root)
    assert (granted.cpus, granted.mem_mb, granted.binding) == (2, 3000, {"cpus": "grant", "mem_mb": "grant"})
    summary = granted.summary()
    assert set(summary) >= {"cpus", "mem_mb", "sources", "warnings"} and summary["sources"]["cpus"]["grant"] == 2.0


def test_probe_reports_pressure_and_network_filesystems(tmp_path):
    root = _machine(tmp_path)
    put(
        root,
        "/proc/pressure/memory",
        "some avg10=35.00 avg60=1.00 avg300=0.00 total=1\nfull avg10=9.50 avg60=0 avg300=0 total=1\n",
    )
    put(root, "/proc/pressure/cpu", "some avg10=75.00 avg60=1.00 avg300=0.00 total=1\n")
    put(
        root,
        "/proc/self/mountinfo",
        """
        1 0 0:1 / / rw - overlay overlay rw
        2 1 0:2 /Users/x/run /framac-run rw - 9p C:\\134 rw,aname=drvfs
        3 1 0:3 / /framac-cache rw - ext4 /dev/sda1 rw
    """,
    )
    pool = R.probe("container", root=root, run_dir="/framac-run/sub", cache_dir="/framac-cache")
    assert pool.psi["memory"] == {"some": 35.0, "full": 9.5} and pool.psi["cpu"]["some"] == 75.0
    assert pool.fs == {"run_dir": "9p", "cache_dir": "ext4"}
    text = " | ".join(pool.warnings)
    assert "memory pressure" in text and "CPU pressure" in text and "9p" in text and "ext4" not in text
    for kind, network in (
        ("nfs4", True),
        ("fuse.sshfs", True),
        ("cifs", True),
        ("virtiofs", True),
        ("lustre", True),
        ("ext4", False),
        ("overlay", False),
        ("xfs", False),
        (None, False),
    ):
        assert R.is_network_fs(kind) is network, kind


def _two_numa_smt(root: Path) -> Path:
    """16 CPUs: NUMA node 0 = cores (0,8)..(3,11), node 1 = cores (4,12)..(7,15); one L3 per node."""
    cpu = "/sys/devices/system/cpu"
    put(root, f"{cpu}/online", "0-15\n")
    for n in range(16):
        core = n % 8
        put(root, f"{cpu}/cpu{n}/topology/thread_siblings_list", f"{core},{core + 8}\n")
        node_cpus = "0-3,8-11" if core < 4 else "4-7,12-15"
        put(root, f"{cpu}/cpu{n}/cache/index0/level", "1\n")
        put(root, f"{cpu}/cpu{n}/cache/index0/shared_cpu_list", f"{core},{core + 8}\n")
        put(root, f"{cpu}/cpu{n}/cache/index3/level", "3\n")
        put(root, f"{cpu}/cpu{n}/cache/index3/shared_cpu_list", node_cpus + "\n")
    put(root, "/sys/devices/system/node/node0/cpulist", "0-3,8-11\n")
    put(root, "/sys/devices/system/node/node1/cpulist", "4-7,12-15\n")
    return root


def test_topology_and_whole_core_allocator_on_two_numa_nodes(tmp_path):
    topo = R.cpu_topology(_two_numa_smt(tmp_path), range(16))
    assert topo is not None
    assert topo["cores"][:2] == [[0, 8], [1, 9]] and len(topo["cores"]) == 8 and topo["threads_per_core"] == 2
    assert topo["numa"] == [[0, 1, 2, 3, 8, 9, 10, 11], [4, 5, 6, 7, 12, 13, 14, 15]] and len(topo["l3"]) == 2

    taken: set[int] = set()
    first = R.allocate_cpuset(topo, range(16), taken, 4)
    assert first == [0, 1, 8, 9]  # whole cores, lowest domain on a tie
    taken |= set(first)
    second = R.allocate_cpuset(topo, range(16), taken, 3)
    assert second == [2, 3, 10, 11]  # rounded up to whole cores; best fit = fuller node 0
    taken |= set(second)
    third = R.allocate_cpuset(topo, range(16), taken, 6)
    assert third == [4, 5, 6, 12, 13, 14]  # stays inside node 1
    taken |= set(third)
    assert R.allocate_cpuset(topo, range(16), taken, 4) is None  # only one free core left
    # No single node has enough free cores: spread over the emptiest domains.
    busy = {0, 8, 1, 9, 2, 10, 4, 12, 5, 13, 6, 14}
    assert R.allocate_cpuset(topo, range(16), busy, 4) == [3, 7, 11, 15]
    # Restricted to an allowed subset (e.g. a Slurm cpuset): only node 1 cores.
    assert R.allocate_cpuset(topo, [4, 5, 12, 13], set(), 2) == [4, 12]


def test_pin_plan_policy(tmp_path, monkeypatch):
    topo = R.cpu_topology(_two_numa_smt(tmp_path), range(16))
    native = R.EngineInfo(kind="docker")
    multi = R.Pool(scope="host", cpus=15, mem_mb=60000, cpu_ids=tuple(range(16)), topology=topo)
    assert R.pin_plan(multi, native, platform="linux") == R.PinPlan(True, None, ())
    assert not R.pin_plan(multi, native, mode="off", platform="linux").exclusive
    assert not R.pin_plan(multi, R.EngineInfo(kind="docker", vm_backed=True), platform="linux").exclusive
    assert not R.pin_plan(multi, R.EngineInfo(kind="podman", cpuset=False), platform="linux").exclusive
    assert not R.pin_plan(multi, native, platform="win32").exclusive
    single = R.Pool(
        scope="host",
        cpus=7,
        mem_mb=60000,
        cpu_ids=tuple(range(8)),
        topology={"cores": [[i] for i in range(8)], "l3": [list(range(8))], "numa": [list(range(8))]},
    )
    assert not R.pin_plan(single, native, platform="linux").exclusive
    assert R.pin_plan(single, native, mode="on", platform="linux").exclusive
    # An affinity that is a strict subset of the machine (Slurm, cpusets) is always passed on.
    subset = R.Pool(scope="host", cpus=3, mem_mb=8000, cpu_ids=(4, 5, 6, 7), subset=True, topology=None)
    assert R.pin_plan(subset, native, platform="linux").confine == (4, 5, 6, 7)
    assert R.pin_plan(subset, native, mode="off", platform="linux").confine == (4, 5, 6, 7)
    no_cpuset = R.pin_plan(subset, R.EngineInfo(kind="podman", cpuset=False), platform="linux")
    assert no_cpuset.confine is None and "cpuset" in no_cpuset.warnings[0]
    assert R.pin_plan(subset, R.EngineInfo(kind="docker", vm_backed=True), platform="linux").confine is None


def test_probe_marks_affinity_subsets_and_reads_topology(tmp_path):
    root = _two_numa_smt(tmp_path)
    put(root, "/proc/meminfo", f"MemTotal: {32 * 1024 * 1024} kB\n")
    put(root, "/proc/self/status", "Name:\tpython\nCpus_allowed_list:\t4-7,12-15\n")
    pool = R.probe("host", root=root)
    assert pool.subset and pool.cpu_ids == (4, 5, 6, 7, 12, 13, 14, 15) and pool.binding["cpus"] == "affinity"
    assert pool.topology is not None and pool.topology["numa"] == [[4, 5, 6, 7, 12, 13, 14, 15]] and pool.cpus == 7


# ---------------------------------------------------------------------------
# Engine views
# ---------------------------------------------------------------------------

DOCKER_DESKTOP = {
    "NCPU": 12,
    "MemTotal": 16731901952,
    "OperatingSystem": "Docker Desktop (containerized)",
    "CgroupVersion": "2",
    "CpuCfsQuota": True,
    "CPUSet": True,
    "MemoryLimit": True,
    "SwapLimit": True,
    "PidsLimit": True,
    "SecurityOptions": ["name=seccomp,profile=builtin", "name=cgroupns"],
}


def test_engine_info_docker_desktop_and_native_docker():
    desktop = R.parse_engine_info(DOCKER_DESKTOP, env={}, platform="linux")
    assert (desktop.kind, desktop.ncpu, desktop.mem_total_mb, desktop.vm_backed, desktop.remote) == (
        "docker",
        12,
        15956,
        True,
        False,
    )
    assert desktop.cpu and desktop.cpuset and desktop.memory and desktop.swap and desktop.pids
    native = dict(
        DOCKER_DESKTOP,
        OperatingSystem="Ubuntu 24.04.1 LTS",
        SwapLimit=False,
        SecurityOptions=["name=seccomp,profile=builtin", "name=rootless", "name=cgroupns"],
    )
    info = R.parse_engine_info(native, env={}, platform="linux")
    assert not info.vm_backed and info.rootless and not info.swap and info.memory
    assert R.parse_engine_info(native, env={}, platform="win32").vm_backed  # Linux containers on Windows: a VM
    remote = R.parse_engine_info(native, env={"DOCKER_HOST": "tcp://build-host:2376"}, platform="linux")
    assert remote.remote and remote.vm_backed
    local_socket = R.parse_engine_info(
        native, env={"DOCKER_HOST": "unix:///run/user/1000/docker.sock"}, platform="linux"
    )
    assert not local_socket.remote and not local_socket.vm_backed


def _podman(controllers, rootless=True, remote=False):
    return {
        "host": {
            "cpus": 16,
            "memTotal": 32 * GiB,
            "cgroupVersion": "v2",
            "cgroupControllers": controllers,
            "security": {"rootless": rootless},
            "serviceIsRemote": remote,
            "os": "linux",
        },
        "store": {},
        "version": {"Version": "5.2.0"},
    }


def test_engine_info_rootless_podman_with_and_without_delegated_controllers():
    default = R.parse_engine_info(_podman(["memory", "pids"]), env={}, platform="linux")
    assert (default.kind, default.rootless, default.ncpu, default.mem_total_mb) == ("podman", True, 16, 32768)
    assert (default.cpu, default.cpuset, default.memory, default.swap, default.pids) == (False, False, True, True, True)
    full = R.parse_engine_info(_podman(["cpuset", "cpu", "io", "memory", "hugetlb", "pids"]), env={}, platform="linux")
    assert full.cpu and full.cpuset and full.memory and full.pids and not full.vm_backed
    none = R.parse_engine_info(_podman([]), env={}, platform="linux")  # cgroup v1 rootless: nothing enforceable
    assert not (none.cpu or none.cpuset or none.memory or none.swap or none.pids)
    machine = R.parse_engine_info(_podman(["memory", "pids"], remote=True), env={}, platform="linux")
    assert machine.remote and machine.vm_backed


def test_engine_info_runs_the_engine_once_and_caches_in_the_broker_dir(tmp_path):
    calls = []

    def runner(cmd, **_kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(DOCKER_DESKTOP) + "\n", stderr="")

    info = R.engine_info("fake-engine", cache_dir=tmp_path, runner=runner)
    assert info.ok and info.ncpu == 12 and calls == [["fake-engine", "info", "--format", "{{json .}}"]]
    R._ENGINE_MEMO.clear()
    cached = R.engine_info("fake-engine", cache_dir=tmp_path)  # served from the cache file, no process
    assert cached.ok and cached.ncpu == 12 and len(calls) == 1
    R._ENGINE_MEMO.clear()
    failing = R.engine_info(
        "fake-engine",
        cache_dir=tmp_path,
        runner=lambda cmd, **kw: subprocess.CompletedProcess(
            cmd, 1, stdout="", stderr="Cannot connect to the Docker daemon"
        ),
    )
    assert not failing.ok and failing.error is not None and "Cannot connect" in failing.error


# ---------------------------------------------------------------------------
# Engine command line
# ---------------------------------------------------------------------------


def _argv(**kw: Any):
    base: dict[str, Any] = dict(
        lease_id="0123456789ab",
        cls_name="wp",
        key="ber_decode",
        cpus=4,
        mem_mb=4768,
        eng=R.EngineInfo(kind="docker"),
        pool_cpus=11,
        pool_mem_mb=14000,
        pids_limit=4096,
        cache_host="/home/u/.cache/framac-pipeline",
        cache_mode="ro",
        command="true",
        image_id="sha256:abc",
    )
    base.update(kw)
    return R.build_engine_argv(
        [
            "docker",
            "run",
            "--rm",
            "-i",
            "--network",
            "none",
            "img:1",
            "/opt/framac-pipeline/scripts/container_entry.sh",
        ],
        **base,
    )


def _pairs(argv):
    return {(a, b) for a, b in zip(argv, argv[1:], strict=False)}


def test_engine_argv_inserts_lease_flags_limits_env_and_cache_after_run():
    argv = _argv()
    assert argv[:7] == [
        "docker",
        "run",
        "--name",
        "framac-0123456789ab",
        "--label",
        "framac.lease=0123456789ab",
        "--init",
    ]
    pairs = _pairs(argv)
    for pair in (
        ("--cpus", "4"),
        ("--memory", "4768m"),
        ("--memory-swap", "4768m"),
        ("--pids-limit", "4096"),
        ("-e", "FRAMAC_JOB_CPUS=4"),
        ("-e", "FRAMAC_JOB_MEM_MB=4768"),
        ("-e", "FRAMAC_JOB_CLASS=wp"),
        ("-e", "FRAMAC_JOB_KEY=ber_decode"),
        ("-e", "FRAMAC_POOL_CPUS=11"),
        ("-e", "FRAMAC_POOL_MEM_MB=14000"),
        ("-e", "FRAMAC_IMAGE_ID=sha256:abc"),
        ("-e", "FRAMAC_CACHE_MODE=ro"),
        ("-e", "FRAMAC_SHARED_CACHE_DIR=/framac-cache"),
        ("-v", "/home/u/.cache/framac-pipeline:/framac-cache:ro"),
    ):
        assert pair in pairs, pair
    assert "--cpuset-cpus" not in argv
    # The caller's flags follow the injected ones; the command string is the last argument.
    assert argv[-4:] == ["none", "img:1", "/opt/framac-pipeline/scripts/container_entry.sh", "true"]
    assert argv.index("--init") < argv.index("--rm")
    with pytest.raises(ValueError):
        R.build_engine_argv(
            ["docker", "ps"],
            lease_id="x",
            cls_name="wp",
            cpus=1,
            mem_mb=1,
            eng=R.EngineInfo(),
            pool_cpus=1,
            pool_mem_mb=1,
        )


def test_engine_argv_omits_limits_the_engine_cannot_enforce():
    nothing = R.EngineInfo(kind="podman", cpu=False, cpuset=False, memory=False, swap=False, pids=False)
    argv = _argv(eng=nothing, confine=[4, 5])
    for flag in ("--cpus", "--cpuset-cpus", "--memory", "--memory-swap", "--pids-limit"):
        assert flag not in argv, flag
    assert ("-e", "FRAMAC_JOB_CPUS=4") in _pairs(argv) and "--init" in argv and "framac.lease=0123456789ab" in argv
    no_swap = _argv(eng=R.EngineInfo(kind="docker", swap=False))
    assert ("--memory", "4768m") in _pairs(no_swap) and "--memory-swap" not in no_swap


def test_engine_argv_cpusets_for_subsets_and_exclusive_pins():
    shared = _argv(cpus=2, confine=[4, 5, 6, 7])
    assert ("--cpus", "2") in _pairs(shared) and ("--cpuset-cpus", "4-7") in _pairs(shared)
    pinned = _argv(cpus=4, cpu_set=[9, 1, 0, 8], confine=[0, 1, 8, 9, 10])
    assert ("--cpuset-cpus", "0-1,8-9") in _pairs(pinned) and "--cpus" not in pinned
    fractional = _argv(cpus=1.5)
    assert ("--cpus", "1.5") in _pairs(fractional) and ("-e", "FRAMAC_JOB_CPUS=1.5") in _pairs(fractional)


def test_engine_argv_cache_modes():
    assert ("-v", "/c:/framac-cache") in _pairs(_argv(cache_host="/c", cache_mode="rw"))
    assert ("-v", "/c:/framac-cache:ro,z") in _pairs(_argv(cache_host="/c", cache_mode="ro", selinux=True))
    assert ("-v", "/c:/framac-cache:z") in _pairs(_argv(cache_host="/c", cache_mode="rw", selinux=True))
    assert ("-e", "FRAMAC_SHARED_CACHE_DIR=/framac-cache") in _pairs(_argv(cache_host="/c", cache_mode="rw"))
    for off in (_argv(cache_host=None, cache_mode="off"), _argv(cache_host=None, cache_mode="ro")):
        assert ("-e", "FRAMAC_CACHE_MODE=off") in _pairs(off) and not any("/framac-cache" in a for a in off)
        assert not any(a.startswith("FRAMAC_SHARED_CACHE_DIR=") for a in off)


def test_cache_mount_mode_allowlist_is_exact(monkeypatch):
    s = "python3 /opt/framac-pipeline/scripts"
    for cmd in (
        f"{s}/pipeline_make.py run build",
        f"{s}/pipeline_make.py build-check",
        f"{s}/pipeline_make.py run eva",
        f"{s}/pipeline_make.py run wp-sweep",
        f"{s}/cache.py gc",
        f"{s}/cache.py stats",
        f"  {s}/cache.py   stats ",
    ):
        assert R.cache_mount_mode(cmd, True) == "rw", cmd
        assert R.cache_mount_mode(cmd, False) == "ro", cmd
    for cmd in (
        f"{s}/pipeline_make.py run build eva",
        f"{s}/pipeline_make.py build-check; touch x",
        f"{s}/pipeline_make.py run fuzz",
        f"{s}/cache.py gc; rm -rf /",
        f"{s}/cache.py gc && touch x",
        f"bash -c '{s}/cache.py gc'",
        f"{s}/cache.py gc $(id)",
        f"PYTHONPATH=/tmp {s}/cache.py gc",
        f"{s}/cache.py clear",
        "python3 /tmp/cache.py gc",
        "",
    ):
        assert R.cache_mount_mode(cmd, True) == "ro", cmd
    assert R.cache_mount_mode(f"{s}/cache.py gc", True, "off") == "off"
    monkeypatch.setenv("FRAMAC_CACHE", "off")
    assert R.cache_mount_mode(f"{s}/cache.py gc", True) == "off"


# ---------------------------------------------------------------------------
# Grant planning (pure)
# ---------------------------------------------------------------------------


def _ticket(lid, cls="wp", seq=1, state="waiting", **kw):
    c = R.CLASSES[cls]
    demand = {
        "min_cpus": c.min_cpus,
        "max_cpus": c.max_cpus,
        "mem_base_mb": c.mem_base_mb,
        "mem_per_cpu_mb": c.mem_per_cpu_mb,
        "mem_floor_mb": kw.pop("floor", None),
        "fixed_cpus": kw.pop("fixed_cpus", None),
        "fixed_mem_mb": kw.pop("fixed_mem", None),
    }
    return {"id": lid, "class": cls, "seq": seq, "state": state, "gated": c.gated, "demand": demand, **kw}


def test_plan_grant_elastic_cpus_memory_fit_and_clamps():
    me = _ticket("a")
    g1 = R.plan_grant(me, [me], 12, 32000)
    assert g1 is not None and g1.cpus == 8  # min(max 8, pool 12) when alone on idle pool
    # Under competition from a running job, clamped to pool // 2:
    competitor = _ticket("comp", cls="wp", state="granted", cpus=2.0, mem_mb=2768)
    g1_busy = R.plan_grant(me, [me, competitor], 12, 32000)
    assert g1_busy is not None and g1_busy.cpus == 6  # min(max 8, pool // 2)
    others = [_ticket("b", seq=2), _ticket("c", seq=3)]
    g2 = R.plan_grant(me, [me, *others], 12, 32000)
    assert g2 is not None and g2.cpus == 4  # free // (1 + waiting)
    g = R.plan_grant(me, [me], 12, 3000)  # 768 + 1000 x cpus must fit in 3000
    assert g is not None and (g.cpus, g.mem_mb) == (2, 2768)
    fixed = _ticket("f", fixed_cpus=3.0, fixed_mem=5000)
    gf = R.plan_grant(fixed, [fixed], 12, 32000)
    assert gf is not None and (gf.cpus, gf.mem_mb) == (3, 5000)
    big = _ticket("p", cls="phase-dynamic")  # min 2 CPUs on a 1-CPU pool: clamped
    assert R.plan_grant(big, [big], 1, 1000) == R.Grant(cpus=1.0, mem_mb=1000)
    floor = _ticket("h", cls="eva", floor=6000)  # history raises the estimate
    gh = R.plan_grant(floor, [floor], 4, 32000)
    assert gh is not None and gh.mem_mb == 6000


def test_plan_grant_fifo_backfill_and_shrink():
    holder = _ticket("x", cls="build", state="granted", cpus=3.0, mem_mb=2048)
    head = _ticket("h", cls="phase-static", seq=1)  # needs 2 CPUs, only 1 free
    late = _ticket("l", cls="eva", seq=2)  # needs 1 CPU
    entries = [holder, head, late]
    assert R.plan_grant(head, entries, 4, 32000) is None
    assert R.plan_grant(late, entries, 4, 32000) is None  # backfill would delay the blocked head
    assert R.plan_grant(late, entries, 5, 32000) is None  # 2 free: taking 1 would delay the head
    assert R.plan_grant(late, entries, 6, 32000) is not None  # head still fits afterwards: backfill
    assert R.queue_position("l", entries) == (2, 2)
    light = _ticket("q", cls="light", state="granted", cpus=1.0, mem_mb=1024)
    assert R.plan_grant(head, [*entries, light], 5, 32000) is not None  # light leases never count
    assert R.plan_grant(late, entries, 3, 32000) is None  # pool shrank below what is granted


def test_queue_serves_the_run_holding_fewest_grants_first(tmp_path):
    run_a, run_b = str(tmp_path / "a" / "run-1"), str(tmp_path / "b" / "run-1")
    held = [_ticket(f"g{i}", state="granted", cpus=1.0, mem_mb=1024, run_dir=run_a) for i in range(3)]
    burst = [_ticket(f"a{i}", seq=10 + i, run_dir=run_a) for i in range(5)]  # run A queued first
    late = _ticket("b0", seq=20, run_dir=run_b)  # run B arrives later, holding nothing
    entries = [*held, *burst, late]
    assert [e["id"] for e in R._queue(entries)][:2] == ["b0", "a0"]
    assert R.queue_position("b0", entries) == (1, 6)
    # Equal holdings: plain FIFO across runs.
    even = [*held, *(_ticket(f"h{i}", state="granted", cpus=1.0, mem_mb=1024, run_dir=run_b) for i in range(3))]
    assert [e["id"] for e in R._queue([*even, *burst, late])][:2] == ["a0", "a1"]
    # Light (ungated) grants do not count as holdings.
    light = [_ticket(f"l{i}", cls="light", state="granted", run_dir=run_b) for i in range(5)]
    assert R._queue([*held, *light, *burst, late])[0]["id"] == "b0"


def test_cache_partition_prefers_the_repo_key(monkeypatch):
    monkeypatch.setenv("FRAMAC_REPO", "libssh2")
    monkeypatch.delenv("FRAMAC_REPO_KEY", raising=False)
    assert R.cache_partition() == "libssh2"
    monkeypatch.setenv("FRAMAC_REPO_KEY", "libssh2-0123456789ab")
    assert R.cache_partition() == "libssh2-0123456789ab"
    assert R.cache_volume_name(R.cache_partition()) == "framac-cache-libssh2-0123456789ab"
    monkeypatch.setenv("FRAMAC_REPO_KEY", "../escape")
    assert R.cache_partition() is not None and "/" not in R.cache_partition()


def test_cache_volume_wanted_where_a_bind_mount_is_slow_or_wrong():
    local = R.EngineInfo(kind="docker")
    vm = R.EngineInfo(kind="docker", vm_backed=True)
    remote = R.EngineInfo(kind="docker", vm_backed=True, remote=True)
    assert R.cache_volume_wanted(local, "/c", setting="auto", fstype="ext4") == (False, "local disk")
    assert R.cache_volume_wanted(vm, "/c", setting="auto", fstype="ext4")[0]
    assert "remote" in R.cache_volume_wanted(remote, "/c", setting="auto")[1]
    assert R.cache_volume_wanted(local, "/mnt/c/x", setting="auto", fstype="9p") == (
        True,
        "/mnt/c/x is on 9p (network or virtualized filesystem)",
    )
    assert R.cache_volume_wanted(local, "/c", setting="auto", fstype="nfs4")[0]
    assert R.cache_volume_wanted(local, "C:/c", setting="auto", windows_remote=True)[0]
    assert R.cache_volume_wanted(vm, "/c", setting="off") == (False, "FRAMAC_CACHE_VOLUME=off")
    assert R.cache_volume_wanted(local, "/c", setting="on") == (True, "FRAMAC_CACHE_VOLUME=on")
    assert not R.cache_volume_wanted(R.EngineInfo(vm_backed=True, ok=False), "/c", setting="auto")[0]


def test_history_estimate_uses_recent_peaks_per_key(tmp_path):
    for peak, key, oom in ((100, "f", False), (400, "f", False), (900, "g", False), (300, "f", False)):
        R.write_history(tmp_path, {"class": "wp", "key": key, "peak_mb": peak, "oom_killed": oom})
        time.sleep(0.002)
    assert R.history_estimate(tmp_path, "wp", "f") == 500  # 1.25 x max(100, 400, 300)
    assert R.history_estimate(tmp_path, "wp", "g") == 1125
    assert R.history_estimate(tmp_path, "wp", None) is None and R.history_estimate(tmp_path, "eva", "f") is None
    R.write_history(tmp_path, {"class": "wp", "key": "f", "peak_mb": 450, "oom_killed": True})
    assert R.history_estimate(tmp_path, "wp", "f") == 900  # an OOM kill doubles the last peak
    (tmp_path / "state/resource-history/wp/zzzz-bad.json").write_text("{not json", encoding="utf-8")
    assert R.history_estimate(tmp_path, "wp", "f") == 900
    assert R.write_history(tmp_path, {"class": "../escape", "peak_mb": 1}) is None


def test_lease_of_a_dead_holder_is_kept_while_its_container_runs(tmp_path):
    pool = R.Budget(4, 8000, "t")
    running = {"value": True}
    checks = []

    def container_alive(entry):
        checks.append(entry["id"])
        return running["value"]

    broker = R.Broker(tmp_path, lambda: pool, container_alive=container_alive, orphan_recheck_s=0.0)
    dead = _ticket(
        "aaaaaaaaaaaa",
        cls="phase-static",
        state="granted",
        cpus=4.0,
        mem_mb=6144,
        container="framac-aaaaaaaaaaaa",
        engine="docker",
    )
    (tmp_path / "leases" / "aaaaaaaaaaaa.json").write_text(json.dumps(dead), encoding="utf-8")
    with broker.locked():
        entries = broker.entries()
    assert [e["id"] for e in entries] == ["aaaaaaaaaaaa"] and entries[0]["orphaned"] and not entries[0]["alive"]
    me = _ticket("bbbbbbbbbbbb", cls="eva")
    assert R.plan_grant(me, [*entries, me], pool.cpus, pool.mem_mb) is None  # still counted against the pool
    running["value"] = False
    with broker.locked():
        assert broker.entries() == []
    assert not (tmp_path / "leases" / "aaaaaaaaaaaa.json").exists() and checks == ["aaaaaaaaaaaa"] * 2
    # A dead holder without a container is reclaimed at once, and gc() reports it.
    (tmp_path / "leases" / "cccccccccccc.json").write_text(json.dumps(_ticket("cccccccccccc")), encoding="utf-8")
    assert broker.gc() == ["cccccccccccc"]


def test_in_process_acquire_release_and_light_leases(tmp_path):
    pool = R.Budget(4, 8000, "t")
    broker = R.Broker(tmp_path, lambda: pool)
    a = broker.acquire("build")
    assert (a.cpus, a.mem_mb, a.gated, a.single) == (2, 2048, True, True)
    light = broker.acquire("light")
    assert (light.cpus, light.mem_mb, light.gated) == (1, 1024, False)
    with broker.locked():
        states = {e["id"]: (e["state"], e["alive"]) for e in broker.entries()}
    assert states == {a.id: ("granted", True), light.id: ("granted", True)}
    assert broker.release(light) is False and broker.release(a) is False  # they overlapped: not single jobs
    with pytest.raises(TimeoutError):
        hog = broker.acquire("phase-static")  # 2 CPUs, 4096 MiB
        try:
            broker.acquire("phase-static", fixed_cpus=4, timeout=0.3)
        finally:
            broker.release(hog)
    with broker.locked():
        assert broker.entries() == []


# ---------------------------------------------------------------------------
# Real processes: the container broker (`run`), `record`, file locks
# ---------------------------------------------------------------------------

CHILD = textwrap.dedent("""
    import json, os, sys, time
    log_dir, name, hold = sys.argv[1], sys.argv[2], float(sys.argv[3])
    gate = sys.argv[4] if len(sys.argv) > 4 else ""
    rec = {"name": name, "cpus": float(os.environ.get("FRAMAC_JOB_CPUS") or 0),
           "mem": int(os.environ.get("FRAMAC_JOB_MEM_MB") or 0), "pid": os.getpid(), "start": time.time()}
    def dump(suffix):
        tmp = os.path.join(log_dir, name + suffix + ".tmp")
        with open(tmp, "w") as f:
            json.dump(rec, f)
        os.replace(tmp, os.path.join(log_dir, name + suffix))
    dump(".start.json")
    deadline = time.time() + hold
    while time.time() < deadline and not (gate and os.path.exists(gate)):
        time.sleep(0.02)
    rec["end"] = time.time()
    dump(".end.json")
""")


class Harness:
    """`resources.py run` processes over a fake cgroup pool, with children that log their grants."""

    def __init__(self, tmp_path: Path):
        self.tmp = tmp_path
        self.root = tmp_path / "root"
        self.logs = tmp_path / "logs"
        self.cwd = tmp_path / "cwd"
        self.broker = tmp_path / "broker"
        for d in (self.root / "sys/fs/cgroup", self.logs, self.cwd):
            d.mkdir(parents=True, exist_ok=True)
        self.child = tmp_path / "child.py"
        self.child.write_text(CHILD, encoding="utf-8")
        self.procs: list[subprocess.Popen] = []
        self.names: list[str] = []
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(("FRAMAC_", "SLURM_"))}
        self.env.update(
            FRAMAC_BROKER_DIR=str(self.broker),
            FRAMAC_PROBE_ROOT=str(self.root),
            PYTHONDONTWRITEBYTECODE="1",
            PYTHONIOENCODING="utf-8",
        )

    def set_pool(self, cpus: float, mem_mb: int) -> None:
        cg = self.root / "sys/fs/cgroup"
        (cg / "cpu.max").write_text(f"{int(cpus * 100000)} 100000\n", encoding="utf-8")
        (cg / "memory.max").write_text(f"{mem_mb * 1024 * 1024}\n", encoding="utf-8")

    def start(self, name: str, cls: str, hold: float = 0.3, gate: Path | None = None, extra=()) -> subprocess.Popen:
        cmd = [
            sys.executable,
            str(SCRIPT),
            "run",
            "--class",
            cls,
            *extra,
            "--",
            sys.executable,
            str(self.child),
            str(self.logs),
            name,
            str(hold),
        ] + ([str(gate)] if gate else [])
        with open(self.logs / f"{name}.broker.txt", "w", encoding="utf-8") as out:
            proc = subprocess.Popen(cmd, cwd=self.cwd, env=self.env, stdout=out, stderr=subprocess.STDOUT)
        self.procs.append(proc)
        self.names.append(name)
        return proc

    def output(self) -> str:
        parts = [f"--- {n}: " + (self.logs / f"{n}.broker.txt").read_text(encoding="utf-8") for n in self.names]
        return "\n".join(parts)

    def record(self, name: str, kind: str = "start") -> dict | None:
        path = self.logs / f"{name}.{kind}.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

    def waiting(self) -> int:
        count = 0
        for path in (self.broker / "leases").glob("*.json"):
            data = R._load_json(path)
            count += isinstance(data, dict) and data.get("state") == "waiting"
        return count

    def finish(self, timeout: float = 30.0) -> None:
        for proc in self.procs:
            proc.wait(timeout=timeout)

    def cleanup(self) -> None:
        for proc in self.procs:
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=10)
        for path in self.logs.glob("*.start.json"):
            pid = json.loads(path.read_text(encoding="utf-8"))["pid"]
            if not (self.logs / path.name.replace(".start.", ".end.")).exists():
                try:
                    os.kill(pid, signal.SIGTERM)
                except OSError:
                    pass


@pytest.fixture
def harness(tmp_path):
    h = Harness(tmp_path)
    yield h
    h.cleanup()


def test_concurrent_grants_never_exceed_the_pool(harness):
    harness.set_pool(4, 5120)  # memory allows two 2 GiB builds at once, CPUs four
    names = [f"job{i}" for i in range(6)]
    for name in names:
        harness.start(name, "build", hold=0.4)
    harness.finish()
    assert all(p.returncode == 0 for p in harness.procs), harness.output()
    recs = [harness.record(n, "end") for n in names]
    assert all(r and r["cpus"] >= 1 and r["mem"] == 2048 for r in recs), recs
    for r in recs:
        active = [x for x in recs if x["start"] <= r["start"] < x["end"]]
        assert sum(x["cpus"] for x in active) <= 4 and sum(x["mem"] for x in active) <= 5120, active
    assert not list((harness.broker / "leases").glob("*.json"))


def test_tickets_are_served_first_in_first_out(harness):
    harness.set_pool(1, 65536)
    gate = harness.tmp / "gate"
    harness.start("blocker", "eva", hold=60, gate=gate)
    wait_for(lambda: harness.record("blocker"))
    for i, name in enumerate(("a", "b", "c"), start=1):
        harness.start(name, "eva", hold=0.2)
        wait_for(lambda i=i: harness.waiting() == i)  # ticket registered before the next one is created
    gate.write_text("go", encoding="utf-8")
    harness.finish()
    starts = [harness.record(n)["start"] for n in ("a", "b", "c")]
    ends = [harness.record(n, "end")["end"] for n in ("a", "b", "c")]
    assert starts == sorted(starts) and starts[1] >= ends[0] and starts[2] >= ends[1]


def test_light_jobs_are_never_blocked(harness):
    harness.set_pool(1, 65536)
    gate = harness.tmp / "gate"
    harness.start("blocker", "eva", hold=60, gate=gate)
    wait_for(lambda: harness.record("blocker"))
    harness.start("quick", "light", hold=0)
    rec = wait_for(lambda: harness.record("quick", "end"), timeout=20)
    assert harness.record("blocker", "end") is None and rec["cpus"] == 1
    gate.write_text("go", encoding="utf-8")
    harness.finish()


def test_a_killed_holder_is_reclaimed(harness):
    harness.set_pool(2, 65536)
    holder = harness.start("holder", "phase-static", hold=60)  # takes both CPUs
    wait_for(lambda: harness.record("holder"))
    harness.start("next", "eva", hold=0)
    wait_for(lambda: harness.waiting() == 1)
    time.sleep(0.5)
    assert harness.record("next") is None
    holder.kill()  # the broker dies; the OS drops its lease lock
    holder.wait(timeout=10)
    killed_at = time.time()
    rec = wait_for(lambda: harness.record("next", "end"), timeout=20)
    assert rec["start"] >= killed_at - 0.05


def test_a_pool_shrink_blocks_new_grants_without_preemption(harness):
    harness.set_pool(4, 65536)
    gate = harness.tmp / "gate"
    harness.start("first", "phase-static", hold=60, gate=gate)  # 2 of 4 CPUs
    wait_for(lambda: harness.record("first"))
    assert harness.record("first")["cpus"] == 2
    harness.set_pool(2, 65536)  # the container was resized down
    harness.start("second", "eva", hold=0)
    wait_for(lambda: harness.waiting() == 1)
    time.sleep(1.0)
    assert harness.record("second") is None and harness.record("first", "end") is None
    grown_at = time.time()
    harness.set_pool(4, 65536)
    rec = wait_for(lambda: harness.record("second", "end"), timeout=20)
    assert rec["start"] >= grown_at - 0.05 and harness.record("first", "end") is None
    gate.write_text("go", encoding="utf-8")
    harness.finish()


def _run_cli(harness_or_env, args, cwd):
    env = harness_or_env.env if isinstance(harness_or_env, Harness) else harness_or_env
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=60
    )


def test_run_output_means_success_when_the_file_was_produced(harness):
    harness.set_pool(2, 8192)
    write_and_fail = "import sys; open(sys.argv[1], 'w').write('report'); sys.exit(3)"
    proc = _run_cli(
        harness,
        ["run", "--class", "light", "--output", "out.json", "--", sys.executable, "-c", write_and_fail, "out.json"],
        harness.cwd,
    )
    assert proc.returncode == 0, proc.stderr
    proc = _run_cli(
        harness,
        ["run", "--class", "light", "--output", "missing.json", "--", sys.executable, "-c", "import sys; sys.exit(3)"],
        harness.cwd,
    )
    assert proc.returncode == 3
    (harness.cwd / "stale.json").write_text("old", encoding="utf-8")  # an untouched old report does not count
    proc = _run_cli(
        harness,
        ["run", "--class", "light", "--output", "stale.json", "--", sys.executable, "-c", "import sys; sys.exit(4)"],
        harness.cwd,
    )
    assert proc.returncode == 4
    proc = _run_cli(
        harness, ["run", "--class", "light", "--", sys.executable, "-c", "import sys; sys.exit(5)"], harness.cwd
    )
    assert proc.returncode == 5


OOM_CHILD = textwrap.dedent("""
    import json, os, sys
    state, events = sys.argv[1], sys.argv[2]
    runs = json.load(open(state)) if os.path.exists(state) else []
    runs.append(int(os.environ["FRAMAC_JOB_MEM_MB"]))
    json.dump(runs, open(state, "w"))
    if len(runs) == 1:
        with open(events, "w") as f:
            f.write("low 0\\nhigh 0\\nmax 3\\noom 1\\noom_kill 1\\n")
        sys.exit(137)  # what a shell reports for a child killed by SIGKILL
    sys.exit(0)
""")


@pytest.mark.parametrize(("cls", "retried"), [("eva", True), ("guardrail", False)])
def test_oom_kill_is_retried_once_with_twice_the_memory_only_for_idempotent_classes(harness, cls, retried):
    harness.set_pool(4, 65536)
    events = harness.root / "sys/fs/cgroup/memory.events"
    events.write_text("low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n", encoding="utf-8")
    (harness.cwd / "run-metadata.json").write_text("{}", encoding="utf-8")
    child = harness.tmp / "oom_child.py"
    child.write_text(OOM_CHILD, encoding="utf-8")
    state = harness.tmp / "runs.json"
    proc = _run_cli(
        harness,
        ["run", "--class", cls, "--key", "mod1", "--", sys.executable, str(child), str(state), str(events)],
        harness.cwd,
    )
    runs = json.loads(state.read_text(encoding="utf-8"))
    first = R.CLASSES[cls].mem_base_mb
    if retried:
        assert proc.returncode == 0 and runs == [first, 2 * first], proc.stderr
        assert "retrying once" in proc.stderr
    else:
        assert proc.returncode == 137 and runs == [first], proc.stderr
    history = sorted((harness.cwd / "state/resource-history" / cls).glob("*.json"))
    recs = [json.loads(p.read_text(encoding="utf-8")) for p in history]
    assert recs[0]["oom_killed"] is True and recs[0]["key"] == "mod1" and len(recs) == (2 if retried else 1)


def test_record_writes_history_and_always_returns_the_exit_code(tmp_path):
    root = tmp_path / "root"
    put(root, "/sys/fs/cgroup/memory.max", str(4 * GiB))
    put(root, "/sys/fs/cgroup/memory.peak", str(1536 * 1024 * 1024))
    put(root, "/sys/fs/cgroup/memory.events", "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n")
    put(root, "/sys/fs/cgroup/cpu.stat", "usage_usec 2500000\nuser_usec 2000000\nsystem_usec 500000\n")
    run_dir = tmp_path / "run-1"
    run_dir.mkdir()
    (run_dir / "run-metadata.json").write_text("{}", encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("FRAMAC_", "SLURM_"))}
    env.update(
        FRAMAC_PROBE_ROOT=str(root),
        FRAMAC_JOB_CLASS="wp",
        FRAMAC_JOB_KEY="ber_decode",
        FRAMAC_JOB_CPUS="4",
        FRAMAC_JOB_MEM_MB="4768",
        PYTHONDONTWRITEBYTECODE="1",
    )
    proc = _run_cli(env, ["record", "--rc", "3"], run_dir)
    assert proc.returncode == 3, proc.stderr
    (path,) = list((run_dir / "state/resource-history/wp").glob("*.json"))
    rec = json.loads(path.read_text(encoding="utf-8"))
    assert {k: rec[k] for k in ("class", "key", "rc", "peak_mb", "oom_killed", "cpu_seconds", "cpus", "mem_mb")} == {
        "class": "wp",
        "key": "ber_decode",
        "rc": 3,
        "peak_mb": 1536,
        "oom_killed": False,
        "cpu_seconds": 2.5,
        "cpus": 4.0,
        "mem_mb": 4768,
    }
    assert R.history_estimate(run_dir, "wp", "ber_decode") == 1920
    # Outside a run dir nothing is written, and a broken probe still returns the exit code.
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    assert _run_cli(env, ["record", "--rc", "0", "--class", "eva"], elsewhere).returncode == 0
    assert not (elsewhere / "state").exists()
    env["FRAMAC_PROBE_ROOT"] = str(tmp_path / "missing")
    assert _run_cli(env, ["record", "--rc", "7"], run_dir).returncode == 7


LOCK_HOLDER = textwrap.dedent("""
    import sys, time
    sys.path.insert(0, sys.argv[1])
    import resources
    lock = resources.FileLock(sys.argv[2])
    assert lock.acquire(blocking=False)
    print("held", flush=True)
    time.sleep(120)
""")


def test_file_lock_is_released_when_the_holder_dies(tmp_path):
    path = tmp_path / "x.lock"
    holder = subprocess.Popen(
        [sys.executable, "-c", LOCK_HOLDER, str(SCRIPT.parent), str(path)], stdout=subprocess.PIPE, text=True
    )
    try:
        assert holder.stdout is not None and holder.stdout.readline().strip() == "held"
        assert R.lock_is_held(path)
        assert not R.FileLock(path).acquire(blocking=False)
    finally:
        holder.kill()
        holder.wait(timeout=10)
        if holder.stdout is not None:
            holder.stdout.close()
    wait_for(lambda: not R.lock_is_held(path), timeout=10)
    lock = R.FileLock(path)
    assert lock.acquire(blocking=False)
    lock.release()


@pytest.mark.skipif(os.name != "nt", reason="the msvcrt byte-range lock path only exists on Windows")
def test_windows_locks_use_msvcrt_and_exclude_other_handles(tmp_path):
    assert R.msvcrt is not None and R.fcntl is None
    first, second = R.FileLock(tmp_path / "w.lock"), R.FileLock(tmp_path / "w.lock")
    assert first.acquire(blocking=False)
    assert not second.acquire(blocking=False)  # a second handle, even in the same process, is refused
    assert not second.acquire(timeout=0.2)
    first.release()
    assert second.acquire(blocking=False)
    second.release()


@pytest.mark.skipif(os.name != "posix", reason="the fcntl lock path only exists on POSIX")
def test_posix_locks_use_flock_per_open_file(tmp_path):
    assert R.fcntl is not None
    first, second = R.FileLock(tmp_path / "p.lock"), R.FileLock(tmp_path / "p.lock")
    assert first.acquire(blocking=False) and not second.acquire(blocking=False)
    first.release()
    assert second.acquire(blocking=False)
    second.release()


# ---------------------------------------------------------------------------
# Host broker `exec` with a fake engine
# ---------------------------------------------------------------------------


def make_fake_engine(bin_dir: Path, info: dict, log: Path) -> None:
    """A `docker` on PATH answering info/images/image/ps/--version and logging `run` arguments (one per line)."""
    bin_dir.mkdir(parents=True, exist_ok=True)
    (bin_dir / "info.json").write_text(json.dumps(info), encoding="utf-8")
    script = bin_dir / "fake_engine.py"
    script.write_text(
        textwrap.dedent(f"""
        import pathlib, sys, time
        here = pathlib.Path(__file__).parent
        cmd = sys.argv[1] if len(sys.argv) > 1 else ""
        if cmd == "info":
            print((here / "info.json").read_text())
        elif cmd == "images":
            print("sha256:deadbeef")
        elif cmd == "image":
            print("sha256:feedface")
        elif cmd == "--version":
            print("Docker version 28.0.0")
        elif cmd == "kill":
            (here / "killed").write_text(" ".join(sys.argv[2:]))
        elif cmd == "volume":
            vols = here / "volumes"
            vols.mkdir(exist_ok=True)
            with (here / "volume_calls.txt").open("a", encoding="utf-8") as fh:
                fh.write(" ".join(sys.argv[2:]) + "\\n")
            name = sys.argv[-1]
            if sys.argv[2] == "inspect":
                sys.exit(0 if (vols / name).exists() else 1)
            elif sys.argv[2] == "create":
                (vols / name).write_text(" ".join(sys.argv[3:-1]))
            elif sys.argv[2] == "rm":
                (vols / name).unlink(missing_ok=True)
        elif cmd == "run" and "/bin/chmod" in sys.argv:  # cache volume init container
            (here / "init_args.txt").write_text("\\n".join(sys.argv[1:]) + "\\n", encoding="utf-8")
            sys.exit(int((here / "init_rc").read_text()) if (here / "init_rc").exists() else 0)
        elif cmd == "run":
            pathlib.Path({str(log)!r}).write_text("\\n".join(sys.argv[1:]) + "\\n", encoding="utf-8")
            if "FAKE_WAIT=1" in sys.argv:  # behave like a running container until `kill`
                (here / "started").write_text("1")
                for _ in range(3000):
                    if (here / "killed").exists():
                        sys.exit(137)
                    time.sleep(0.01)
                sys.exit(1)
            sys.exit(int(dict(a.split("=", 1) for a in sys.argv if a.startswith("FAKE_RC=")).get("FAKE_RC", 0)))
    """),
        encoding="utf-8",
    )
    if os.name == "nt":
        (bin_dir / "docker.cmd").write_text(f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n', encoding="utf-8")
    else:
        shim = bin_dir / "docker"
        shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n', encoding="utf-8")
        shim.chmod(0o700)


@pytest.fixture
def fake_engine(tmp_path, monkeypatch):
    probe_root = _machine(tmp_path / "probe_root")
    monkeypatch.setenv("FRAMAC_PROBE_ROOT", str(probe_root))

    def _make(info: dict) -> Path:
        log = tmp_path / "engine_run_args.txt"
        make_fake_engine(tmp_path / "bin", info, log)
        monkeypatch.setenv("PATH", str(tmp_path / "bin") + os.pathsep + os.environ.get("PATH", ""))
        monkeypatch.setenv("FRAMAC_BROKER_DIR", str(tmp_path / "broker"))
        monkeypatch.setenv("FRAMAC_CACHE_DIR", str(tmp_path / "cache"))
        monkeypatch.setenv("FRAMAC_CACHE_VOLUME", "off")  # bind mounts unless a test opts in
        monkeypatch.delenv("FRAMAC_REPO_KEY", raising=False)
        monkeypatch.setenv("FRAMAC_POOL_CPUS", "2")
        monkeypatch.setenv("FRAMAC_POOL_MEMORY", "4g")
        monkeypatch.setenv("FRAMAC_PROBE_ROOT", str(probe_root))
        R._ENGINE_MEMO.clear()
        return log

    return _make


def test_exec_dry_run_builds_the_full_engine_command(tmp_path, fake_engine, monkeypatch, capsys):
    fake_engine(DOCKER_DESKTOP)
    monkeypatch.setenv("FRAMAC_CONTAINER_CMD", "python3 /opt/framac-pipeline/scripts/run_wp_function.py --file a.c")
    monkeypatch.setenv("FRAMAC_IMAGE_ID", "sha256:feedface")
    rc = R.main(
        [
            "exec",
            "--run-dir",
            str(tmp_path / "run-1"),
            "--key",
            "f",
            "--dry-run",
            "--",
            "docker",
            "run",
            "--rm",
            "-i",
            "img",
            "/opt/framac-pipeline/scripts/container_entry.sh",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    argv = out["argv"]
    assert out["class"] == "wp" and Path(argv[0]).stem.lower() == "docker" and argv[1] == "run"
    pairs = _pairs(argv)
    assert ("--cpus", R._fmt_cpus(out["cpus"])) in pairs and ("--memory", f"{out['mem_mb']}m") in pairs
    assert ("-e", "FRAMAC_JOB_CLASS=wp") in pairs and ("-e", "FRAMAC_JOB_KEY=f") in pairs
    assert ("-e", "FRAMAC_IMAGE_ID=sha256:feedface") in pairs and ("-e", "FRAMAC_CACHE_MODE=ro") in pairs
    assert argv[-1] == "python3 /opt/framac-pipeline/scripts/run_wp_function.py --file a.c"
    assert not list((tmp_path / "broker" / "leases").glob("*.json"))  # the lease was released


def test_exec_mounts_this_repositorys_cache_partition_writable_only_for_allowlisted_steps(
    tmp_path, fake_engine, monkeypatch, capsys
):
    fake_engine(DOCKER_DESKTOP)
    monkeypatch.setenv("FRAMAC_REPO", "net-snmp")
    monkeypatch.delenv("FRAMAC_CACHE_RW", raising=False)

    def dry_run(cmd: str) -> tuple[str, list[str]]:
        monkeypatch.setenv("FRAMAC_CONTAINER_CMD", cmd)
        assert R.main(["exec", "--run-dir", str(tmp_path / "run-1"), "--dry-run", "--", "docker", "run", "img"]) == 0
        out = json.loads(capsys.readouterr().out)
        return out["cache_mode"], [v for f, v in _pairs(out["argv"]) if f == "-v"]

    partition = str((tmp_path / "cache" / "repos" / "net-snmp").resolve())
    mode, mounts = dry_run("python3 /opt/framac-pipeline/scripts/pipeline_make.py run build")  # no --cache-rw needed
    assert mode == "rw" and mounts == [f"{partition}:/framac-cache"]
    mode, mounts = dry_run("python3 /opt/framac-pipeline/scripts/pipeline_make.py run fuzz")
    assert mode == "ro" and mounts == [f"{partition}:/framac-cache:ro"]
    monkeypatch.setenv("FRAMAC_CACHE_RW", "off")
    assert dry_run("python3 /opt/framac-pipeline/scripts/pipeline_make.py run build")[0] == "ro"


def test_exec_puts_the_cache_in_a_named_volume_when_the_engine_runs_in_a_vm(tmp_path, fake_engine, monkeypatch, capsys):
    fake_engine(DOCKER_DESKTOP)
    monkeypatch.setattr(sys, "platform", "win32")  # Docker Desktop from the Windows host: vm_backed
    monkeypatch.setenv("FRAMAC_CACHE_VOLUME", "auto")
    monkeypatch.setenv("FRAMAC_REPO", "net-snmp")
    monkeypatch.setenv("FRAMAC_REPO_KEY", "net-snmp-0123456789ab")
    monkeypatch.delenv("FRAMAC_CACHE_RW", raising=False)
    monkeypatch.setenv("FRAMAC_CONTAINER_CMD", "python3 /opt/framac-pipeline/scripts/pipeline_make.py run fuzz")
    assert R.main(["exec", "--run-dir", str(tmp_path / "run-1"), "--dry-run", "--", "docker", "run", "img"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["cache_volume"] == "framac-cache-net-snmp-0123456789ab" and out["cache_mode"] == "ro"
    assert ("-v", "framac-cache-net-snmp-0123456789ab:/framac-cache:ro") in _pairs(out["argv"])
    assert ("-e", "FRAMAC_SHARED_CACHE_DIR=/framac-cache") in _pairs(out["argv"])
    assert not (tmp_path / "cache").exists()  # the slow host directory is never touched


def test_exec_creates_and_initializes_the_cache_volume_once(tmp_path, fake_engine, monkeypatch, capsys):
    log = fake_engine(DOCKER_DESKTOP)
    bin_dir = tmp_path / "bin"
    monkeypatch.setenv("FRAMAC_CACHE_VOLUME", "on")
    monkeypatch.setenv("FRAMAC_REPO_KEY", "net-snmp-0123456789ab")
    monkeypatch.setenv("FRAMAC_IMAGE_ID", "sha256:feedface")
    monkeypatch.setenv("FRAMAC_CONTAINER_CMD", "python3 /opt/framac-pipeline/scripts/pipeline_make.py run build")
    run = ["exec", "--run-dir", str(tmp_path / "run-1"), "--", "docker", "run", "--rm", "img", "/entry.sh"]
    assert R.main(run) == 0
    created = (bin_dir / "volumes" / "framac-cache-net-snmp-0123456789ab").read_text()
    assert "framac.cache=1" in created and "framac.repo=net-snmp-0123456789ab" in created
    init = (bin_dir / "init_args.txt").read_text().splitlines()
    assert init[-3:] == ["sha256:feedface", "1777", "/framac-cache"]
    assert ("--user", "0:0") in _pairs(init) and ("--network", "none") in _pairs(init)
    assert ("--cap-drop", "ALL") in _pairs(init)
    assert ("-v", "framac-cache-net-snmp-0123456789ab:/framac-cache") in _pairs(log.read_text().splitlines())
    (bin_dir / "init_args.txt").unlink()
    assert R.main(run) == 0
    assert not (bin_dir / "init_args.txt").exists()  # the existing volume is reused as is


def test_exec_falls_back_to_the_bind_mount_when_the_cache_volume_cannot_be_initialized(
    tmp_path, fake_engine, monkeypatch, capsys
):
    log = fake_engine(DOCKER_DESKTOP)
    bin_dir = tmp_path / "bin"
    (bin_dir / "init_rc").write_text("1")
    monkeypatch.setenv("FRAMAC_CACHE_VOLUME", "on")
    monkeypatch.setenv("FRAMAC_REPO_KEY", "net-snmp-0123456789ab")
    monkeypatch.setenv("FRAMAC_IMAGE_ID", "sha256:feedface")
    monkeypatch.setenv("FRAMAC_CONTAINER_CMD", "python3 /opt/framac-pipeline/scripts/pipeline_make.py run build")
    assert R.main(["exec", "--run-dir", str(tmp_path / "run-1"), "--", "docker", "run", "img", "/e.sh"]) == 0
    assert "bind-mounting the cache directory instead" in capsys.readouterr().err
    assert not (bin_dir / "volumes" / "framac-cache-net-snmp-0123456789ab").exists()  # removed for a retry
    partition = str((tmp_path / "cache" / "repos" / "net-snmp-0123456789ab").resolve())
    assert ("-v", f"{partition}:/framac-cache") in _pairs(log.read_text().splitlines())


def test_exec_runs_the_engine_and_returns_its_exit_code(tmp_path, fake_engine, monkeypatch):
    log = fake_engine(DOCKER_DESKTOP)
    monkeypatch.setenv("FRAMAC_CONTAINER_CMD", "true")
    rc = R.main(
        [
            "exec",
            "--run-dir",
            str(tmp_path / "run-1"),
            "--cpus",
            "1",
            "--memory",
            "1500m",
            "--",
            "docker",
            "run",
            "--rm",
            "-e",
            "FAKE_RC=9",
            "img",
            "/entry.sh",
        ]
    )
    assert rc == 9
    args = log.read_text(encoding="utf-8").splitlines()
    assert args[:6] == ["run", "--name", args[2], "--label", f"framac.lease={args[2][len('framac-') :]}", "--init"]
    assert ("--cpus", "1") in _pairs(args) and ("--memory", "1500m") in _pairs(args) and args[-1] == "true"


def test_exec_refuses_target_code_when_memory_or_pids_cannot_be_enforced(tmp_path, fake_engine, monkeypatch, capsys):
    fake_engine(_podman(["cpu", "cpuset"]))
    # Pin off: on multi-NUMA/L3 hosts FRAMAC_PIN=auto switches --cpus to --cpuset-cpus, which this
    # test does not assert (it checks the memory/pids refusal, not placement).
    monkeypatch.setenv("FRAMAC_PIN", "off")
    monkeypatch.setenv(
        "FRAMAC_CONTAINER_CMD", "python3 /opt/framac-pipeline/scripts/run_eacsl_fuzz.py campaign --module m"
    )
    run = ["exec", "--run-dir", str(tmp_path / "run-1"), "--dry-run", "--", "docker", "run", "img"]
    assert R.main(run) == 2 and "FRAMAC_ALLOW_UNENFORCED_LIMITS" in capsys.readouterr().err
    assert R.main(["exec", "--class", "wp", *run[1:]]) == 0  # no target code: allowed
    out = json.loads(capsys.readouterr().out)
    assert "--memory" not in out["argv"] and "--pids-limit" not in out["argv"] and "--cpus" in out["argv"]
    monkeypatch.setenv("FRAMAC_ALLOW_UNENFORCED_LIMITS", "1")
    assert R.main(run) == 0


def test_fake_engine_isolates_from_multi_numa_host_topology(tmp_path, fake_engine):
    fake_engine(DOCKER_DESKTOP)
    probe_root = Path(os.environ["FRAMAC_PROBE_ROOT"])
    assert probe_root.exists()
    topo = R.cpu_topology(probe_root, range(16))
    assert topo is not None
    assert len(topo.get("numa") or []) == 0
    assert len(topo.get("l3") or []) == 0

    # Under Linux with multi-NUMA host, pin_plan forces exclusive pinning (--cpuset-cpus).
    # With fake_engine's mock topology, exclusive pinning is avoided.
    eng = R.EngineInfo(kind="podman", cpuset=True, cpu=True)
    pool_isolated = R.Pool(scope="host", cpus=16, mem_mb=64 * 1024, topology=topo)
    plan_isolated = R.pin_plan(pool_isolated, eng, mode="auto", platform="linux")
    assert not plan_isolated.exclusive

    # Contrast with an un-isolated multi-NUMA host topology
    topo_multi = R.cpu_topology(_two_numa_smt(tmp_path / "multi_numa"), range(16))
    pool_multi = R.Pool(scope="host", cpus=16, mem_mb=64 * 1024, topology=topo_multi)
    plan_multi = R.pin_plan(pool_multi, eng, mode="auto", platform="linux")
    assert plan_multi.exclusive


def test_exec_rejects_limit_flags_it_manages(tmp_path, fake_engine, monkeypatch):
    fake_engine(DOCKER_DESKTOP)
    monkeypatch.setenv("FRAMAC_CONTAINER_CMD", "true")
    with pytest.raises(SystemExit) as exc:
        R.main(["exec", "--run-dir", str(tmp_path), "--", "docker", "run", "--memory=8g", "img"])
    assert exc.value.code == 2


@pytest.mark.skipif(os.name != "posix", reason="termination signals are delivered with kill(2) on POSIX only")
def test_exec_forwards_termination_as_an_engine_kill(tmp_path, fake_engine):
    log = fake_engine(DOCKER_DESKTOP)
    env = dict(os.environ, FRAMAC_CONTAINER_CMD="true")
    proc = subprocess.Popen(
        [
            sys.executable,
            str(SCRIPT),
            "exec",
            "--run-dir",
            str(tmp_path / "run-1"),
            "--",
            "docker",
            "run",
            "-e",
            "FAKE_WAIT=1",
            "img",
        ],
        env=env,
    )
    try:
        wait_for(lambda: (tmp_path / "bin" / "started").exists())
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=30) == 137
    finally:
        if proc.poll() is None:
            proc.kill()
    name = log.read_text(encoding="utf-8").splitlines()[2]
    assert (tmp_path / "bin" / "killed").read_text() == name and name.startswith("framac-")
    assert not list((tmp_path / "broker" / "leases").glob("*.json"))


@pytest.mark.skipif(os.name != "posix", reason="termination signals are delivered with kill(2) on POSIX only")
def test_run_forwards_termination_to_its_child(harness):
    harness.set_pool(2, 8192)
    proc = harness.start("victim", "eva", hold=60)
    wait_for(lambda: harness.record("victim"))
    proc.send_signal(signal.SIGTERM)
    assert proc.wait(timeout=30) == 128 + signal.SIGTERM
    assert harness.record("victim", "end") is None
    assert not list((harness.broker / "leases").glob("*.json"))


def test_status_lists_and_gc_reclaims(tmp_path, capsys):
    broker = R.Broker(tmp_path, lambda: R.Budget(4, 8000, "t"))
    live = broker.acquire("eva")
    (tmp_path / "leases" / "dddddddddddd.json").write_text(
        json.dumps(_ticket("dddddddddddd", state="granted", cpus=1, mem_mb=10)), encoding="utf-8"
    )
    assert R.main(["status", "--scope", "container", "--broker-dir", str(tmp_path)]) == 0
    status = json.loads(capsys.readouterr().out)
    assert {r["id"]: r["alive"] for r in status["granted"]} == {live.id: True, "dddddddddddd": False}
    assert R.main(["gc", "--scope", "container", "--broker-dir", str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out)["reclaimed"] == ["dddddddddddd"]
    broker.release(live)


def test_run_metadata_records_resources_host_run_dir_and_podman(tmp_path, monkeypatch):
    import run_metadata
    from validate_artifacts import validate_metadata

    root = _machine(tmp_path / "root")
    put(root, "/sys/fs/cgroup/cpu.max", "200000 100000\n")
    put(root, "/sys/fs/cgroup/memory.max", str(3 * GiB))
    monkeypatch.setenv("FRAMAC_PROBE_ROOT", str(root))
    monkeypatch.setenv("FRAMAC_OUTER_SANDBOX", "podman-hardened")
    monkeypatch.setenv("FRAMAC_RUN_HOST", "/home/u/framac-pipeline/demo/run-4")
    run = tmp_path / "run-4"
    run.mkdir()
    monkeypatch.chdir(run)
    assert run_metadata.main(["init", "--repo", "demo", "--target", str(tmp_path / "root"), "--profile", "quick"]) == 0
    meta = json.loads((run / "run-metadata.json").read_text(encoding="utf-8"))
    assert (
        meta["sandbox"]["outer"] == "podman-hardened" and meta["run_dir_host"] == "/home/u/framac-pipeline/demo/run-4"
    )
    assert (meta["resources"]["cpus"], meta["resources"]["mem_mb"]) == (2, 3072)
    assert "pool" in meta["resources"]  # pool is always populated with probe fallback
    assert meta["resources"]["pool"]["cpus"] >= 1
    assert meta["resources"]["pool"]["mem_mb"] >= 256
    assert list(validate_metadata(meta)) == []
    meta["sandbox"]["outer"] = "lxc"
    assert list(validate_metadata(meta))

    # Under the host broker, the init container's light lease is only a slice of the node pool.
    monkeypatch.setenv("FRAMAC_POOL_CPUS", "11")
    monkeypatch.setenv("FRAMAC_POOL_MEM_MB", "14360")
    (run / "run-metadata.json").unlink()
    assert run_metadata.main(["init", "--repo", "demo", "--target", str(tmp_path / "root"), "--profile", "quick"]) == 0
    meta = json.loads((run / "run-metadata.json").read_text(encoding="utf-8"))
    assert meta["resources"]["pool"] == {"cpus": 11, "mem_mb": 14360, "source": "host broker"}
    assert list(validate_metadata(meta)) == []


def test_cpu_list_round_trip_and_byte_sizes():
    assert R.format_cpu_list([11, 0, 1, 2, 3, 8, 10]) == "0-3,8,10-11" and R.format_cpu_list([]) == ""
    assert R.parse_cpu_list(R.format_cpu_list([5, 1, 2])) == [1, 2, 5]
    assert R.parse_mem("1048576b") == 1 and R.parse_mem("512mb") == 512 and R.parse_mem("1.5g") == 1536


def test_wsl2_docker_desktop_is_not_treated_as_vm_backed(tmp_path, monkeypatch):
    assert R.parse_engine_info(DOCKER_DESKTOP, env={}, platform="linux").vm_backed is True
    monkeypatch.setenv("WSL_DISTRO_NAME", "Ubuntu-24.04")
    assert R.parse_engine_info(DOCKER_DESKTOP, env=dict(os.environ), platform="linux").vm_backed is False
    monkeypatch.delenv("WSL_DISTRO_NAME")
    put(tmp_path, "/proc/sys/kernel/osrelease", "5.15.167.4-microsoft-standard-WSL2\n")
    assert R.is_wsl2(env={}, root=tmp_path, platform="linux") is True


def test_cache_mount_mode_expands_script_var(monkeypatch):
    monkeypatch.delenv("FRAMAC_CACHE_RW", raising=False)
    assert R.cache_mount_mode("python3 $S/pipeline_make.py run build", True) == "rw"
    assert R.cache_mount_mode("python3 ${S}/pipeline_make.py run wp-sweep", True) == "rw"
    assert R.cache_mount_mode("python3 $S/pipeline_make.py run fuzz", True) == "ro"
    assert R.cache_mount_mode("python3 $S/pipeline_make.py run build && id", True) == "ro"


def test_shared_cache_mirrors_and_reads_resource_history(tmp_path, monkeypatch):
    run1 = tmp_path / "run-1"
    run2 = tmp_path / "run-2"
    shared = tmp_path / "shared-cache"
    for r in (run1, run2):
        r.mkdir()
        (r / "run-metadata.json").write_text("{}", encoding="utf-8")
    shared.mkdir()
    monkeypatch.setenv("FRAMAC_SHARED_CACHE_DIR", str(shared))
    monkeypatch.setenv("FRAMAC_CACHE_MODE", "rw")
    R.write_history(
        run1,
        {
            "class": "eva",
            "key": "snmp",
            "rc": 0,
            "peak_mb": 3200,
            "oom_killed": False,
            "cpu_seconds": 4.0,
            "cpus": 1.0,
            "mem_mb": 4096,
        },
    )
    assert list((shared / "resource-history/eva").glob("*.json"))
    # A fresh run directory with read-only access to the shared cache inherits the historical peak.
    monkeypatch.setenv("FRAMAC_CACHE_MODE", "ro")
    assert R.history_estimate(run2, "eva", "snmp") == 4000


def test_run_dir_mutual_exclusion_between_rw_cache_and_target_code(tmp_path):
    run_a = str((tmp_path / "run-a").resolve())
    run_b = str((tmp_path / "run-b").resolve())
    pool = R.Budget(16, 65536, "test")
    # While a target-executing job is active on run_a, a writable-cache job on run_a must wait,
    # whereas the same job on run_b or a read-only job on run_a is granted immediately.
    active_fuzz = [_ticket("111111111111", state="granted", cls="fuzz", cpus=2, mem_mb=3072, run_dir=run_a)]
    me_rw_a = _ticket("aaaaaaaaaaaa", cls="phase-static", run_dir=run_a, cache_mode="rw")
    me_ro_a = _ticket("bbbbbbbbbbbb", cls="phase-static", run_dir=run_a, cache_mode="ro")
    me_rw_b = _ticket("cccccccccccc", cls="phase-static", run_dir=run_b, cache_mode="rw")
    assert R.plan_grant(me_rw_a, active_fuzz, pool.cpus, pool.mem_mb) is None
    assert R.plan_grant(me_ro_a, active_fuzz, pool.cpus, pool.mem_mb) is not None
    assert R.plan_grant(me_rw_b, active_fuzz, pool.cpus, pool.mem_mb) is not None

    # Symmetrically, while a writable-cache job is active on run_a, a target-executing job on run_a waits.
    active_rw = [
        _ticket(
            "222222222222", state="granted", cls="phase-static", cpus=2, mem_mb=4096, run_dir=run_a, cache_mode="rw"
        )
    ]
    fuzz_a = _ticket("dddddddddddd", cls="fuzz", run_dir=run_a, cache_mode="ro")
    eva_a = _ticket("eeeeeeeeeeee", cls="eva", run_dir=run_a, cache_mode="ro")
    fuzz_b = _ticket("ffffffffffff", cls="fuzz", run_dir=run_b, cache_mode="ro")
    assert R.plan_grant(fuzz_a, active_rw, pool.cpus, pool.mem_mb) is None
    assert R.plan_grant(eva_a, active_rw, pool.cpus, pool.mem_mb) is not None
    assert R.plan_grant(fuzz_b, active_rw, pool.cpus, pool.mem_mb) is not None


def test_grow_only_rebalancing_of_running_containers(tmp_path):
    pool = R.Budget(12, 32000, "test")
    # Two running elastic wp containers initially granted 2 CPUs / 2768 MiB each because a third job held 8 CPUs.
    # Once the third job finishes, 8 CPUs and 26464 MiB are free; both grow to 6 CPUs / 6768 MiB.
    a = _ticket(
        "111111111111",
        cls="wp",
        seq=1,
        state="granted",
        cpus=2.0,
        mem_mb=2768,
        container="framac-111111111111",
        engine="docker",
    )
    b = _ticket(
        "222222222222",
        cls="wp",
        seq=2,
        state="granted",
        cpus=2.0,
        mem_mb=2768,
        container="framac-222222222222",
        engine="docker",
    )
    fixed = _ticket(
        "333333333333",
        cls="wp",
        seq=3,
        state="granted",
        cpus=2.0,
        mem_mb=2768,
        fixed_cpus=2.0,
        container="framac-333333333333",
        engine="docker",
    )
    plans = R.rebalance_grants([a, b, fixed], pool.cpus, pool.mem_mb)
    assert [(p["id"], p["cpus"], p["mem_mb"]) for p in plans] == [
        ("111111111111", 5.0, 5768),
        ("222222222222", 5.0, 5768),
    ]
    # Once `fixed` also finishes, 8 CPUs are free and both elastic wp jobs grow to 6 CPUs / 6768 MiB.
    assert [(p["id"], p["cpus"], p["mem_mb"]) for p in R.rebalance_grants([a, b], pool.cpus, pool.mem_mb)] == [
        ("111111111111", 6.0, 6768),
        ("222222222222", 6.0, 6768),
    ]
    # Never rebalance while any gated ticket is waiting in the queue.
    waiter = _ticket("444444444444", cls="eva", seq=4, state="waiting")
    assert R.rebalance_grants([a, b, waiter], pool.cpus, pool.mem_mb) == []
    # Never shrink a container whose current grant already exceeds the pool share.
    over = _ticket(
        "555555555555",
        cls="wp",
        seq=1,
        state="granted",
        cpus=8.0,
        mem_mb=8768,
        container="framac-555555555555",
        engine="docker",
    )
    assert R.rebalance_grants([over], 4, 4000) == []

    # Broker.rebalance runs `<engine> update` and persists the grown grant on success.
    broker = R.Broker(tmp_path, lambda: pool)
    l1 = broker.acquire("wp", lease_id="111111111111", extra={"container": "framac-111111111111", "engine": "docker"})
    try:
        # Simulate that l1 was initially granted 2 CPUs / 2768 MiB under contention.
        entry_path = tmp_path / "leases" / "111111111111.json"
        data = json.loads(entry_path.read_text(encoding="utf-8"))
        data.update(cpus=2.0, mem_mb=2768)
        entry_path.write_text(json.dumps(data), encoding="utf-8")

        updates: list[list[str]] = []

        def fake_runner(cmd, **_kw):
            updates.append(list(cmd))
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        applied = broker.rebalance(eng=R.EngineInfo(kind="docker"), runner=fake_runner)
        assert len(applied) == 1 and applied[0]["applied"] is True
        assert applied[0]["cpus"] == 8.0 and applied[0]["mem_mb"] == 8768
        assert updates == [
            [
                "docker",
                "update",
                "--cpus",
                "8",
                "--memory",
                "8768m",
                "--memory-swap",
                "8768m",
                "framac-111111111111",
            ]
        ]
        persisted = json.loads(entry_path.read_text(encoding="utf-8"))
        assert persisted["cpus"] == 8.0 and persisted["mem_mb"] == 8768 and "rebalanced_at" in persisted
    finally:
        broker.release(l1)


def test_is_known_static_command_rejects_shell_chaining_and_anchors():
    assert R.is_known_static_command("python3 $S/ledger.py summary") is True
    assert R.is_known_static_command("python3 $S/pipeline_make.py gen") is True
    assert R.is_known_static_command("python3 $S/pipeline_make.py ingest") is True
    assert R.is_known_static_command("python3 $S/pipeline_make.py run eva") is True
    assert R.is_known_static_command("python3 $S/pipeline_make.py run") is False
    for cmd in (
        "python3 $S/ledger.py summary && ./evil",
        "frama-c -version; ./evil",
        "python3 $S/cache.py stats | sh",
        "python3 $S/cache.py stats $(id)",
        "./evil /opt/framac-pipeline/scripts/ledger.py",
        "./evil /opt/framac-pipeline/scripts/pipeline_make.py run eva",
    ):
        assert R.is_known_static_command(cmd) is False, cmd


def test_infer_class_run_eacsl_fuzz_subcommand_precedes_build_module_name():
    assert R.infer_class("python3 $S/run_eacsl_fuzz.py campaign --module build") == "fuzz"
    assert R.infer_class("python3 $S/run_eacsl_fuzz.py guardrail --module build") == "guardrail"
    assert R.infer_class("python3 $S/run_eacsl_fuzz.py replay --module build") == "replay"
    assert R.infer_class("python3 $S/run_eacsl_fuzz.py selftest --module build") == "selftest"
    assert R.infer_class("python3 $S/run_eacsl_fuzz.py build --module build") == "build"


def test_infer_class_sizes_build_check_like_run_build():
    # build-check runs `run build`; as `light` (1 GiB) Frama-C was killed instrumenting CryptoLib's crypto.
    for cmd in ("python3 $S/pipeline_make.py build-check", "python3 $S/pipeline_make.py --run-dir . build-check"):
        assert R.infer_class(cmd) == R.infer_class("python3 $S/pipeline_make.py run build") == "phase-static", cmd
    assert R.infer_class("python3 $S/pipeline_make.py gen") == "light"


def test_exec_auto_downgrades_cache_mode_when_target_code_lease_is_active_on_run_dir(
    tmp_path, fake_engine, monkeypatch, capsys
):
    root = _machine(tmp_path / "root")
    monkeypatch.setenv("FRAMAC_PROBE_ROOT", str(root))
    fake_engine(DOCKER_DESKTOP)
    monkeypatch.setenv("FRAMAC_REPO", "net-snmp")
    monkeypatch.setenv("FRAMAC_POOL_CPUS", "8")
    monkeypatch.setenv("FRAMAC_POOL_MEMORY", "16g")
    monkeypatch.delenv("FRAMAC_CACHE_RW", raising=False)

    assert R.cache_mount_mode("python3 $S/pipeline_make.py ingest", True) == "rw"
    # wp-queue runs wp-replay (the parent guardrail runs target code): never with a writable store.
    assert R.cache_mount_mode("python3 $S/pipeline_make.py run ingest wp-queue", True) == "ro"
    assert not R.is_known_static_command("python3 $S/pipeline_make.py run wp-queue")
    assert not R.is_known_static_command("python3 $S/pipeline_make.py run wp-replay")
    assert not R.is_known_static_command("python3 $S/pipeline_make.py wp-replay")

    run_dir = tmp_path / "run-1"
    run_dir.mkdir()
    broker = R.Broker(tmp_path / "broker", lambda: R.Budget(8, 16384, "test"))
    fuzz_lease = broker.acquire(
        "fuzz",
        fixed_cpus=1.0,
        fixed_mem_mb=1024,
        lease_id="111111111111",
        extra={"run_dir": str(run_dir), "cache_mode": "ro", "runs_target_code": True},
    )
    try:
        monkeypatch.setenv("FRAMAC_CONTAINER_CMD", "python3 /opt/framac-pipeline/scripts/pipeline_make.py run eva")
        assert R.main(["exec", "--run-dir", str(run_dir), "--dry-run", "--", "docker", "run", "img"]) == 0
        captured = capsys.readouterr()
        out = json.loads(captured.out)
        assert out["cache_mode"] == "ro"
        assert "shared cache mounted read-only: a target-code job is active on this run directory" in captured.err
    finally:
        broker.release(fuzz_lease)


def test_resources_summary_pool_parsing_and_fallback(monkeypatch):
    import run_metadata

    # 1. Float string for CPUs and unit suffix for memory
    monkeypatch.setenv("FRAMAC_POOL_CPUS", "12.0")
    monkeypatch.setenv("FRAMAC_POOL_MEM_MB", "20480MB")
    res = run_metadata.resources_summary()
    assert res is not None
    assert res["pool"] == {"cpus": 12, "mem_mb": 20480, "source": "host broker"}

    # 2. String with 'g' unit
    monkeypatch.setenv("FRAMAC_POOL_CPUS", "8")
    monkeypatch.setenv("FRAMAC_POOL_MEM_MB", "16GB")
    res2 = run_metadata.resources_summary()
    assert res2 is not None
    assert res2["pool"] == {"cpus": 8, "mem_mb": 16384, "source": "host broker"}

    # 3. Missing env vars fall back to host/machine/container probe and still populate pool
    monkeypatch.delenv("FRAMAC_POOL_CPUS", raising=False)
    monkeypatch.delenv("FRAMAC_POOL_MEM_MB", raising=False)
    monkeypatch.delenv("FRAMAC_POOL_MEMORY", raising=False)
    res_fallback = run_metadata.resources_summary()
    assert res_fallback is not None
    assert "pool" in res_fallback
    assert res_fallback["pool"]["cpus"] >= 1
    assert res_fallback["pool"]["mem_mb"] >= 256
    assert isinstance(res_fallback["pool"]["source"], str)


def test_infer_class_shell_unwrapping_and_script_inspection(tmp_path, monkeypatch):
    # Unwrapping bash -c, sh -c, and container_entry.sh
    assert R.infer_class('bash -c "python3 /opt/framac-pipeline/scripts/run_wp_function.py --file a.c"') == "wp"
    assert R.infer_class("sh -c 'run_eva_slice.py --sources a.c'") == "eva"
    assert (
        R.infer_class('container_entry.sh "python3 /opt/framac-pipeline/scripts/run_eacsl_fuzz.py campaign --module m"')
        == "fuzz"
    )
    assert R.infer_class('container_entry.sh bash -c "python3 /opt/framac-pipeline/scripts/run_wp_function.py"') == "wp"
    assert R.infer_class('bash -c "echo \\"hello\\" && python3 run_wp_function.py"') == "wp"

    # Shell script on disk
    wp_script = tmp_path / "run_wp.sh"
    wp_script.write_text(
        "#!/bin/bash\npython3 /opt/framac-pipeline/scripts/run_wp_function.py --file f.c\n", encoding="utf-8"
    )
    assert R.infer_class(f"bash {wp_script}") == "wp"
    assert R.infer_class(f"sh {wp_script}") == "wp"

    fuzz_script = tmp_path / "run_fuzz.sh"
    fuzz_script.write_text(
        "#!/bin/bash\nexec python3 /opt/framac-pipeline/scripts/run_eacsl_fuzz.py campaign --module x\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    assert R.infer_class("./run_fuzz.sh") == "fuzz"
    assert R.infer_class(str(fuzz_script)) == "fuzz"

    # Script without tool command falls back to light
    other_script = tmp_path / "other.sh"
    other_script.write_text("#!/bin/bash\necho hello world\n", encoding="utf-8")
    assert R.infer_class(f"bash {other_script}") == "light"


def test_infer_class_scans_only_shell_scripts(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    body = "python3 /opt/framac-pipeline/scripts/pipeline_make.py run fuzz\n"

    # Named by a shell, a .sh suffix, or a shell shebang: scanned, whatever the file is called.
    (tmp_path / "plain").write_text(body, encoding="utf-8")
    assert R.infer_class("bash ./plain") == "phase-dynamic"
    (tmp_path / "plain.sh").write_text(body, encoding="utf-8")
    assert R.infer_class("./plain.sh") == "phase-dynamic"
    for shebang in ("#!/bin/sh -e", "#!/usr/bin/env bash", "#!/usr/bin/env -S bash -e", "#!/bin/dash"):
        (tmp_path / "tool").write_text(f"{shebang}\n{body}", encoding="utf-8")
        assert R.infer_class("./tool") == "phase-dynamic", shebang

    # A file that only mentions the command is not what the job runs.
    (tmp_path / "driver.py").write_text(f"#!/usr/bin/env python3\nCMD = '''{body}'''\n", encoding="utf-8")
    assert R.infer_class("python3 ./driver.py next") == "light"
    assert R.infer_class("./driver.py next") == "light"
    (tmp_path / "notes.md").write_text(body, encoding="utf-8")
    assert R.infer_class("cat ./notes.md") == "light"
    (tmp_path / "shish").write_text(f"#!/usr/bin/shish\n{body}", encoding="utf-8")
    assert R.infer_class("./shish") == "light"


def test_infer_class_ignores_source_of_pipeline_scripts():
    # The class comes from the command, so running a script by absolute path (as in the image) must not change it.
    scripts = sorted(Path(R.__file__).parent.glob("*.py"))
    assert any(R._match_class_patterns(p.read_text(encoding="utf-8", errors="replace")[:65536]) for p in scripts)
    for path in scripts:
        assert R.infer_class(f'python3 "{path}" status') == R.infer_class(f"python3 {path.name} status"), path.name


def test_history_estimate_3_tier_hierarchical_fallback_and_oom_inheritance(tmp_path):
    """
    Test 3-tier hierarchical fallback in history_estimate:
    - Tier 1: exact match on <module>:<file>#<fn>
    - Tier 2 (TU prefix): search records matching <module>:<file> or starting with <module>:<file>#
      and inherit 2.0x OOM multiplier for sibling functions in heavy TUs
    - Tier 3 (Module prefix): search records matching <module> or starting with <module>:
    - Return None if no records match across all 3 tiers
    """
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    # Tier 1: exact match
    R.write_history(run_dir, {"class": "wp", "key": "mod_a:src/a.c#fn1", "peak_mb": 200, "oom_killed": False})
    est1 = R.history_estimate(run_dir, "wp", "mod_a:src/a.c#fn1")
    assert est1 == 250  # 200 * 1.25

    # Tier 2: sibling function in same TU falls back to TU prefix
    # Sibling fn2 has no record, but fn1 in src/a.c exists
    est2 = R.history_estimate(run_dir, "wp", "mod_a:src/a.c#fn2")
    assert est2 == 250

    # Tier 2: heavy TU with OOM killed record inherits 2.0x multiplier
    R.write_history(run_dir, {"class": "wp", "key": "mod_b:src/heavy.c#heavy_fn", "peak_mb": 500, "oom_killed": True})
    est_heavy_sibling = R.history_estimate(run_dir, "wp", "mod_b:src/heavy.c#sibling_fn")
    assert est_heavy_sibling == 1000  # 500 * 2.0

    # Also test record matching TU prefix exactly (<module>:<file>)
    R.write_history(run_dir, {"class": "wp", "key": "mod_c:src/tu_only.c", "peak_mb": 300, "oom_killed": False})
    est_tu_match = R.history_estimate(run_dir, "wp", "mod_c:src/tu_only.c#any_fn")
    assert est_tu_match == 375  # 300 * 1.25

    # Tier 3: unseen TU in known module falls back to module prefix
    # mod_a:src/unseen.c#some_fn has no src/unseen.c record, falls back to mod_a (which has mod_a:src/a.c#fn1)
    est3 = R.history_estimate(run_dir, "wp", "mod_a:src/unseen.c#some_fn")
    assert est3 == 250

    # Also test record matching module prefix exactly (<module>)
    R.write_history(run_dir, {"class": "wp", "key": "mod_d", "peak_mb": 400, "oom_killed": False})
    est_mod_match = R.history_estimate(run_dir, "wp", "mod_d:src/file.c#fn")
    assert est_mod_match == 500  # 400 * 1.25

    # Completely unknown key returns None
    assert R.history_estimate(run_dir, "wp", "unknown_mod:src/file.c#fn") is None
    assert R.history_estimate(run_dir, "wp", "nonexistent") is None
