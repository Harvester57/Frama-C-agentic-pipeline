"""Remediation P2 (container): knob forwarding (M5), non-root jobs (M6), docs/references in the image (M11)."""

import os
import re
import shutil
import subprocess
import sys

import pytest

from conftest import ROOT, dockerfile_command_args
from test_sandbox_and_overlay import _engine_run_args, _fake_engine

# FRAMAC_* names that scripts/ mention but that a user does not set for the container: set by the wrappers,
# the host broker or the image, read only on the host (broker, benchmark driver), or internal plumbing.
NOT_FORWARDED = {
    # set by the wrappers
    "FRAMAC_OUTER_SANDBOX",
    "FRAMAC_REFERENCES_HOST",
    "FRAMAC_REPO",
    "FRAMAC_REPO_KEY",
    "FRAMAC_RUN_TAG",
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
    "FRAMAC_LEASE_ID",
    "FRAMAC_LEASE_WAITED_S",
    "FRAMAC_POOL_MEM_MB",
    "FRAMAC_SHARED_CACHE_DIR",
    "FRAMAC_SUBLEASE_ID",
    "FRAMAC_SHARE",
    # C macros and per-process harness filters, not host-forwarded environment variables
    "FRAMAC_FUZZ_SKIP_CASES",
    "FRAMAC_FUZZ_ONLY_CASE",  # runtime per-process harness case filter (same category as FRAMAC_FUZZ_SKIP_CASES)
    "FRAMAC_EVA_SHARD",
    # the message a link stub prints when called (fuzz_build.LINK_STUB_MARKER), not an environment variable
    "FRAMAC_LINK_STUB_CALLED",
    # debugging switch read inside the container only (scripts/fc_cpp_wrapper.py)
    "FRAMAC_CPP_REWRITE",
    # host broker / wrapper / benchmark-driver knobs (the pool reaches the container as the broker's measurement)
    "FRAMAC_ALLOW_UNENFORCED_LIMITS",
    "FRAMAC_BENCH_DIR",
    "FRAMAC_BROKER_DIR",
    "FRAMAC_CACHE_DIR",
    "FRAMAC_CACHE_RW",
    "FRAMAC_CACHE_VOLUME",
    "FRAMAC_CONTAINER_ENGINE",
    "FRAMAC_DOCKER_IMAGE",
    "FRAMAC_ORPHAN_GRACE_S",
    "FRAMAC_PIN",
    "FRAMAC_POOL_CPUS",
    "FRAMAC_POOL_MEMORY",
    "FRAMAC_RESERVE_CPUS",
    "FRAMAC_RESERVE_MEMORY",
    # test hooks and internal plumbing
    "FRAMAC_AST_DUMP_OUT",
    "FRAMAC_P0_DUMP_OUT",
    "FRAMAC_P0_ALIAS_OUT",
    "FRAMAC_P0_ALIAS_TIMEOUT",
    "FRAMAC_SNAPSHOT_DIR",
    "FRAMAC_STUB_OVERLAY_DIR",
    "FRAMAC_PROBE_MEMO_S",
    "FRAMAC_PROBE_ROOT",
    "FRAMAC_SECURITY_PROPS",  # run_wp_function.py override; the default is the run's workspace/reports file
}
AB_SWITCHES = (
    "FRAMAC_FRAME_SKELETON",
    "FRAMAC_SPEC_KB",
    "FRAMAC_SPEC_KB_CURATED",
    "FRAMAC_NEGOTIATE_EVIDENCE",
    "FRAMAC_MUTATION_STUB",
    "FRAMAC_CANDIDATE_RANK",
    "FRAMAC_PROOF_CARRY",
    "FRAMAC_LOOP_SEEDS",
    "FRAMAC_REJECTION_REOPEN",
    "FRAMAC_HARNESS_SCOPE_V2",
    "FRAMAC_API_TRUST_SCHEMA",
    "FRAMAC_HARNESS_SMOKE",
    "FRAMAC_FUZZ_EXPLORE_JUDGE",
    "FRAMAC_VERIFIER_BREAKER",
    "FRAMAC_JUDGE_FRONTIER",
    "FRAMAC_FUZZ_PLATEAU_STOP",
    "FRAMAC_FUZZ_CRASH_STOP",
)
# The value that turns each switch to its baseline side.
AB_BASELINE = {name: "off" for name in AB_SWITCHES} | {"FRAMAC_CANDIDATE_RANK": "legacy"}


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


def test_wrapper_knob_lists_are_identical_and_include_the_ab_switches():
    sh, ps1 = sh_knobs(), ps1_knobs()
    assert sh == ps1
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
    docs = _read("docs/guides/resources-and-caching.md")
    para = next(line for line in docs.splitlines() if line.startswith("Set every knob on the host"))
    for name in sh_knobs():
        assert f"`{name}`" in para, name


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
    # The home directory itself, not only something under it (`/home/opam/.cache`).
    assert "/home/opam" in dockerfile_command_args(dockerfile, "chmod", "1777")
    without_home = "RUN chmod a+rx /home/opam /root \\\n    && chmod 1777 /home/opam/.cache /framac-run\n"
    assert dockerfile_command_args(without_home, "chmod", "1777") == {"/home/opam/.cache", "/framac-run"}
    ignore = _read(".dockerignore").splitlines()
    assert "!docs/references/" in ignore and "!docs/references/**" in ignore
    assert "docs/references/**/*.pdf" in ignore
    assert "!docs/" not in ignore and "!docs/**" not in ignore  # the rest of docs/ stays out of the context
    for excluded in (
        "scripts/benchmark.py",
        "scripts/extract_references.py",
        "scripts/libc_gap_report.py",
        "scripts/wp_residual_census.py",
        "skills/run-supervisor/",
        "skills/paper-assessment/",
        "skills/upstream-bug-report/",
    ):
        assert excluded in ignore, excluded
    assert (ROOT / "docs/references/INDEX.md").is_file()
    for rel in ("wrappers/framac-docker.sh", "wrappers/framac-docker.ps1"):
        assert "docs/references:/opt/framac-pipeline/docs/references:ro" in _read(rel), rel


def test_ps1_forwards_the_ab_switches_and_sets_user_only_off_windows(tmp_path):
    pwsh = shutil.which("pwsh") or shutil.which("powershell")
    if not pwsh:
        pytest.skip("pwsh/powershell not available")
    log_file, env = _fake_engine(tmp_path)
    env.update(AB_BASELINE)
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
            assert ("-e", f"{name}={AB_BASELINE[name]}") in pairs, (extra, name)
        if sys.platform == "win32":
            assert "--user" not in args, extra
        else:
            assert ("--user", f"{os.getuid()}:{os.getgid()}") in pairs, extra
