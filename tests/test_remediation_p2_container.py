"""Remediation P2 (container): knob forwarding (M5), non-root jobs (M6), docs/references in the image (M11)."""

import os
import re
import shutil
import subprocess
import sys

import pytest

from conftest import ROOT
from test_sandbox_and_overlay import _engine_run_args, _fake_engine

# FRAMAC_* names that scripts/ mention but that a user does not set for the container: set by the wrappers,
# the host broker or the image, read only on the host (broker, benchmark driver), or internal plumbing.
NOT_FORWARDED = {
    # set by the wrappers
    "FRAMAC_OUTER_SANDBOX",
    "FRAMAC_REFERENCES_HOST",
    "FRAMAC_REPO",
    "FRAMAC_RUN_HOST",
    "FRAMAC_RUN_ID",
    "FRAMAC_TARGET_COMMIT",
    "FRAMAC_TARGET_DIRTY",
    "FRAMAC_TARGET_HOST",
    "FRAMAC_CONTAINER_CMD",
    # set by the host broker (resources.py exec) or by the image
    "FRAMAC_CACHE_MODE",
    "FRAMAC_CGROUP_ENFORCED",
    "FRAMAC_IMAGE_ID",
    "FRAMAC_JOB_CLASS",
    "FRAMAC_JOB_CPUS",
    "FRAMAC_JOB_KEY",
    "FRAMAC_JOB_MEM_MB",
    "FRAMAC_POOL_MEM_MB",
    "FRAMAC_SHARED_CACHE_DIR",
    "FRAMAC_SUBLEASE_ID",
    "FRAMAC_SHARE",
    # host broker / wrapper / benchmark-driver knobs (the pool reaches the container as the broker's measurement)
    "FRAMAC_ALLOW_UNENFORCED_LIMITS",
    "FRAMAC_BENCH_DIR",
    "FRAMAC_BROKER_DIR",
    "FRAMAC_CACHE_DIR",
    "FRAMAC_CACHE_RW",
    "FRAMAC_CONTAINER_ENGINE",
    "FRAMAC_DOCKER_IMAGE",
    "FRAMAC_PIN",
    "FRAMAC_POOL_CPUS",
    "FRAMAC_POOL_MEMORY",
    "FRAMAC_RESERVE_CPUS",
    "FRAMAC_RESERVE_MEMORY",
    # test hooks and internal plumbing
    "FRAMAC_AST_DUMP_OUT",
    "FRAMAC_PROBE_MEMO_S",
    "FRAMAC_PROBE_ROOT",
}
AB_SWITCHES = ("FRAMAC_FRAME_SKELETON", "FRAMAC_LOOP_TEMPLATES", "FRAMAC_SPEC_KB")


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def sh_knobs() -> list[str]:
    m = re.search(r"^for knob in (.*?); do$", _read("wrappers/framac-docker.sh"), re.M | re.S)
    assert m, "knob loop not found in framac-docker.sh"
    return m.group(1).replace("\\\n", " ").split()


def ps1_knobs() -> list[str]:
    m = re.search(r"foreach \(\$knob in @\((.*?)\)\) \{", _read("wrappers/framac-docker.ps1"), re.S)
    assert m, "knob loop not found in framac-docker.ps1"
    return re.findall(r'"(FRAMAC_[A-Z0-9_]+)"', m.group(1))


def compose_knobs() -> list[str]:
    return re.findall(r"^\s+- (FRAMAC_[A-Z0-9_]+)\s*$", _read("docker-compose.yml"), re.M)


def test_wrapper_knob_lists_are_identical_and_include_the_ab_switches():
    sh, ps1, compose = sh_knobs(), ps1_knobs(), compose_knobs()
    assert sh == ps1 == compose
    assert len(set(sh)) == len(sh)
    for name in AB_SWITCHES:
        assert name in sh, name
    assert not set(sh) & NOT_FORWARDED


def test_every_framac_variable_in_scripts_is_forwarded_or_known_not_to_be():
    mentioned: set[str] = set()
    for path in (ROOT / "scripts").glob("*.py"):
        mentioned |= set(re.findall(r"[\"'](FRAMAC_[A-Z0-9_]+)[\"']", path.read_text(encoding="utf-8")))
    unclassified = mentioned - set(sh_knobs()) - NOT_FORWARDED
    assert not unclassified, f"add to the wrappers' knob lists (or to NOT_FORWARDED): {sorted(unclassified)}"


def test_docs_list_every_forwarded_knob():
    docs = _read("docs/resources-and-caching.md")
    para = next(line for line in docs.splitlines() if line.startswith("Set every knob on the host"))
    for name in sh_knobs():
        assert f"`{name}`" in para, name


def test_compose_runs_as_a_non_root_user_with_a_valid_run_id():
    compose = _read("docker-compose.yml")
    assert re.search(r'^\s+user: "\$\{FRAMAC_UID:-(\d+)\}:\$\{FRAMAC_GID:-(\d+)\}"$', compose, re.M)
    m = re.search(r"- FRAMAC_RUN_ID=\$\{FRAMAC_RUN_ID:-([^}]+)\}", compose)
    assert m and re.match(r"^run-[0-9]+$", m.group(1))  # the format run_metadata.py init accepts


def test_ps1_passes_the_host_user_on_linux_and_macos_like_the_sh_wrapper():
    ps1 = _read("wrappers/framac-docker.ps1")
    assert '$OuterSandbox -eq "docker-hardened" -and ($IsLinux -or $IsMacOS)' in ps1
    assert '"--user", "${hostUid}:${hostGid}"' in ps1
    assert ps1.index('"--user"') < ps1.index("& $EngineName @dockerArgs")
    sh = _read("wrappers/framac-docker.sh")
    assert '"${OUTER_SANDBOX}" == "docker-hardened"' in sh and '--user "$(id -u):$(id -g)"' in sh


def test_image_is_usable_by_a_non_root_uid_and_ships_docs_references():
    dockerfile = _read("Dockerfile")
    assert "COPY docs/references/ /opt/framac-pipeline/docs/references/" in dockerfile
    assert "chmod -R a+rX /opt/framac-pipeline" in dockerfile
    assert "chmod -R a+rX /home/opam/.opam" in dockerfile
    assert re.search(r"chmod 1777 /home/opam\b", dockerfile)
    ignore = _read(".dockerignore").splitlines()
    assert "!docs/references/" in ignore and "!docs/references/**" in ignore
    assert "!docs/" not in ignore and "!docs/**" not in ignore  # the rest of docs/ stays out of the context
    assert (ROOT / "docs/references/INDEX.md").is_file()
    for rel in ("wrappers/framac-docker.sh", "wrappers/framac-docker.ps1", "docker-compose.yml"):
        assert "docs/references:/opt/framac-pipeline/docs/references:ro" in _read(rel), rel


def test_ps1_forwards_the_ab_switches_and_sets_user_only_off_windows(tmp_path):
    pwsh = shutil.which("pwsh") or shutil.which("powershell")
    if not pwsh:
        pytest.skip("pwsh/powershell not available")
    log_file, env = _fake_engine(tmp_path)
    env.update(FRAMAC_FRAME_SKELETON="off", FRAMAC_LOOP_TEMPLATES="off", FRAMAC_SPEC_KB="off")
    base = [
        pwsh,
        "-NoProfile",
        "-File",
        str(ROOT / "wrappers/framac-docker.ps1"),
        "-TargetDir",
        str(tmp_path / "target_repo"),
        "-RunDir",
        str(tmp_path / "run_1"),
    ]
    for extra in ([], ["-NoBroker"]):
        proc = subprocess.run([*base, *extra, "true"], env=env, capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr or proc.stdout
        args, pairs = _engine_run_args(log_file)
        for name in AB_SWITCHES:
            assert ("-e", f"{name}=off") in pairs, (extra, name)
        if sys.platform == "win32":
            assert "--user" not in args, extra
        else:
            assert ("--user", f"{os.getuid()}:{os.getgid()}") in pairs, extra
