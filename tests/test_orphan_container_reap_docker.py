"""
Docker-backed regression for orphaned `resources.py exec` containers (c-ares run-1, Phase 3).

An agent's shell timeout killed the PowerShell tree running `framac-docker.ps1`: on Windows that is
TerminateProcess, so `resources.py exec` never ran its signal handler and its `docker run --rm -i`
container kept running with no client, its lease counted against the pool forever. A reaping pass
(`resources.py gc` here; every `exec` acquire does one too) now kills it and drops the lease.

Opt-in, as it starts a container: FRAMAC_DOCKER_TESTS=1. It uses its own broker dir and run label
and removes only the containers carrying that label.
"""

from __future__ import annotations

import json
import os
import secrets
import signal
import subprocess
import sys
import time

import pytest

from conftest import BUILD_IMAGE, ROOT, require_docker_images

RESOURCES_PY = ROOT / "scripts" / "resources.py"


def _ps(label: str) -> list[str]:
    out = subprocess.run(
        ["docker", "ps", "-q", "--filter", f"label={label}"], capture_output=True, text=True, timeout=30, check=False
    )
    return (out.stdout or "").split()


def _wait(predicate, timeout: float, step: float = 0.5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(step)
    raise AssertionError("condition not reached in time")


def _kill_tree(proc: subprocess.Popen) -> None:
    """Kill the client and its children without signal handlers, as the opencode host does on Windows."""
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True, timeout=30, check=False)
    else:
        os.killpg(proc.pid, signal.SIGKILL)
    proc.wait(timeout=30)


@pytest.mark.slow
def test_container_of_a_terminated_exec_client_is_reaped(tmp_path):
    require_docker_images(BUILD_IMAGE)
    tag = f"orphanfix-test-{secrets.token_hex(4)}"
    broker = tmp_path / "broker"
    env = {
        **os.environ,
        "FRAMAC_BROKER_DIR": str(broker),
        "FRAMAC_RUN_TAG": tag,
        "FRAMAC_ORPHAN_GRACE_S": "0",
        "FRAMAC_CACHE_DIR": "off",
        "FRAMAC_CONTAINER_CMD": "600",  # exec appends it to the engine command line: `sleep 600`
    }
    client_argv = [
        sys.executable, str(RESOURCES_PY), "exec", "--class", "light", "--run-dir", str(tmp_path / "run"),
        "--", "docker", "run", "--rm", "-i", "--network", "none", "--label", f"framac.run={tag}",
        "--entrypoint", "sleep", BUILD_IMAGE,
    ]  # fmt: skip
    popen_kw: dict = {"start_new_session": True} if os.name != "nt" else {}
    client = subprocess.Popen(
        client_argv, env=env, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **popen_kw
    )
    try:
        _wait(lambda: _ps(f"framac.run={tag}"), timeout=120)
        leases = list((broker / "leases").glob("*.json"))
        assert len(leases) == 1
        lease_id = json.loads(leases[0].read_text(encoding="utf-8"))["id"]

        _kill_tree(client)
        time.sleep(3)
        assert _ps(f"framac.lease={lease_id}"), "the container should outlive its terminated client (the bug)"

        gc = [sys.executable, str(RESOURCES_PY), "gc", "--scope", "host", "--broker-dir", str(broker)]
        gc += ["--engine", "docker"]

        def reaped() -> bool:
            subprocess.run(gc, env=env, capture_output=True, timeout=120, check=False)
            return not (broker / "leases" / f"{lease_id}.json").exists()

        _wait(reaped, timeout=120, step=2.0)
        assert not _ps(f"framac.lease={lease_id}")
    finally:
        if client.poll() is None:
            _kill_tree(client)
        for cid in _ps(f"framac.run={tag}"):
            subprocess.run(["docker", "rm", "-f", cid], capture_output=True, timeout=60, check=False)
