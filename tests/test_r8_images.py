"""
Remediation plan step R8, Docker-backed (FRAMAC_DOCKER_TESTS=1; CI runs it after building both images):

  - both images have /framac-scratch, mode 1777, and a new scratch volume mounted there is writable by a
    non-root uid without a chmod step;
  - the snapshot check: a capture in the build image, as a non-root uid on a new volume, exports a
    package header and library (zlib) and the build's generated header (build/config.h); the analysis
    image, which sees the read-only target but not the scratch tree, compiles, links and runs the target
    and parses it with Frama-C from the snapshot alone.
"""

from __future__ import annotations

import json
import os
import subprocess
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

from conftest import ANALYSIS_IMAGE, BUILD_IMAGE, ROOT, require_docker_images

FIXTURE = ROOT / "tests" / "fixtures" / "r8_generated_header"
NON_ROOT = "12345:12345"
PY = "python3 /opt/framac-pipeline/scripts"

pytestmark = [pytest.mark.integration, pytest.mark.slow]


def docker(args: list[str], timeout: int = 900) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=timeout, check=False,
    )  # fmt: skip


@pytest.fixture
def volume() -> Iterator[str]:
    """A new, empty named volume, created as the wrappers create the scratch volume."""
    name = f"framac-r8-test-{uuid.uuid4().hex[:12]}"
    created = docker(["volume", "create", "--label", "framac.scratch=1", name])
    assert created.returncode == 0, created.stderr
    yield name
    docker(["volume", "rm", "-f", name])


@pytest.mark.parametrize("image", [BUILD_IMAGE, ANALYSIS_IMAGE])
def test_a_new_scratch_volume_is_writable_by_a_non_root_user(image, volume):
    require_docker_images(image)
    proc = docker(
        ["run", "--rm", "--network", "none", "--user", NON_ROOT, "-v", f"{volume}:/framac-scratch",
         "--entrypoint", "sh", image, "-c",
         "stat -c %a /framac-scratch && mkdir /framac-scratch/tree && touch /framac-scratch/tree/f && echo ok"]
    )  # fmt: skip
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.split() == ["1777", "ok"]


def _job_user(run_dir: Path) -> str:
    """The host uid on Linux (the bind-mounted run dir is its), else a fixed non-root uid."""
    getuid, getgid = getattr(os, "getuid", None), getattr(os, "getgid", None)
    if getuid is not None and getgid is not None and getuid() != 0:
        return f"{getuid()}:{getgid()}"
    run_dir.chmod(0o777)
    return NON_ROOT


def test_the_analysis_image_reads_package_and_generated_headers_from_the_snapshot(volume, tmp_path):
    require_docker_images(BUILD_IMAGE, ANALYSIS_IMAGE)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    user = _job_user(run_dir)
    common = [
        "run", "--rm", "--network", "none", "--user", user,
        "-v", f"{FIXTURE.resolve()}:/target:ro", "-v", f"{run_dir.resolve()}:/framac-run",
        "-v", f"{ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
        "-v", f"{ROOT / 'schemas'}:/opt/framac-pipeline/schemas:ro", "-w", "/framac-run",
    ]  # fmt: skip
    cap = docker(
        [*common, "-v", f"{volume}:/framac-scratch", BUILD_IMAGE,
         f"{PY}/build_capture.py run --scratch /framac-scratch --recipe-file '' --command make"]
    )  # fmt: skip
    assert cap.returncode == 0, cap.stdout + cap.stderr
    report = json.loads((run_dir / "workspace/reports/build_capture.json").read_text(encoding="utf-8"))
    snapshot = report["snapshot"]
    assert snapshot["generated"] == {"headers": ["build/config.h"], "include_dirs": ["build"]}
    assert any(h["path"].endswith("/zlib.h") for h in snapshot["headers"])
    manifest = json.loads((run_dir / "workspace/snapshot/manifest.json").read_text(encoding="utf-8"))
    assert manifest["generated_dirs"] == ["build"] and "build/config.h" in manifest["generated"]

    # The analysis image: no scratch volume, the target read-only (it has no build/config.h).
    flags = "-I/target -I/target/build"
    check = (
        "set -e; "
        f'F=$(python3 -c \'import sys; sys.path.insert(0, "/opt/framac-pipeline/scripts"); import target_env; '
        f'print(target_env.with_include_flags("{flags}"))\'); '
        'L=$(python3 -c \'import sys; sys.path.insert(0, "/opt/framac-pipeline/scripts"); import target_env; '
        'print(" ".join(target_env.link_flags()))\'); '
        'A=$(python3 -c \'import sys; sys.path.insert(0, "/opt/framac-pipeline/scripts"); import framac_common; '
        f'print(framac_common.augment_framac_cppflags("{flags}"))\'); '
        "test ! -e /target/build/config.h; "
        "gcc $F /target/demo.c -o /tmp/demo $L -lz; /tmp/demo; "
        'frama-c -no-unicode -cpp-extra-args="$A" /target/demo.c >/tmp/fc.log 2>&1 || { cat /tmp/fc.log; exit 1; }; '
        "echo parsed"
    )
    ana = docker([*common, "--entrypoint", "bash", ANALYSIS_IMAGE, "-lc", check])
    assert ana.returncode == 0, ana.stdout + ana.stderr
    lines = ana.stdout.split("\n")
    assert any(line.startswith("hello ") for line in lines), ana.stdout
    assert "parsed" in lines, ana.stdout
