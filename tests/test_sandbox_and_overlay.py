import json
import os
import sys
from pathlib import Path

import pytest

import sandbox_exec as S
from conftest import ROOT, metadata
from validate_artifacts import validate_metadata
from workspace_overlay import StaleBaselineError, init_overlay


def test_env_allowlist_rejects_malformed_entries():
    env = S.build_env(Path("/s"), {"LIBFUZZER_OPT": "1"})
    assert env["HOME"] == str(Path("/s")) and env["LIBFUZZER_OPT"] == "1"
    assert "USER" not in env and "SSH_AUTH_SOCK" not in env
    with pytest.raises(ValueError):
        S.build_env(Path("/s"), {"A=B": "x"})


@pytest.mark.skipif(os.name != "posix", reason="sandbox_mode() is 'rlimits' only on POSIX hosts")
def test_sandbox_mode_is_rlimits_on_posix():
    assert S.sandbox_mode() == "rlimits"


@pytest.mark.skipif(os.name == "posix", reason="non-POSIX guard only")
def test_sandbox_mode_refuses_non_posix_host():
    with pytest.raises(S.SandboxUnavailable):
        S.sandbox_mode()


def test_bubblewrap_api_removed():
    for name in ("build_bwrap_argv", "bwrap_available", "degraded_allowed", "UNSHARE_FLAGS", "_BWRAP_OK"):
        assert not hasattr(S, name), name


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_container_configs_keep_default_seccomp_and_apparmor():
    for rel in ("wrappers/framac-docker.sh", "wrappers/framac-docker.ps1", "docker-compose.yml"):
        text = _read(rel)
        for forbidden in ("seccomp=unconfined", "seccomp:unconfined", "apparmor=unconfined"):
            assert forbidden not in text, f"{rel} contains {forbidden}"
        assert "FRAMAC_SANDBOX_DEGRADED" not in text, rel


def test_wrappers_fail_hard_on_legacy_sandbox_flags():
    sh = _read("wrappers/framac-docker.sh")
    assert "--no-inner-sandbox|--allow-degraded-sandbox)" in sh
    legacy_branch = sh.split("--no-inner-sandbox|--allow-degraded-sandbox)", 1)[1].split(";;", 1)[0]
    assert ">&2" in legacy_branch and "exit 2" in legacy_branch

    ps1 = _read("wrappers/framac-docker.ps1")
    assert "[switch]$NoInnerSandbox" in ps1 and "[switch]$AllowDegradedSandbox" in ps1
    assert '@("NoInnerSandbox", "AllowDegradedSandbox")' in ps1
    legacy_block = ps1.split('@("NoInnerSandbox", "AllowDegradedSandbox")', 1)[1].split("\n}\n", 1)[0]
    assert "$PSBoundParameters.ContainsKey($legacy)" in legacy_block
    assert "[Console]::Error.WriteLine" in legacy_block and "exit 2" in legacy_block
    # The legacy check runs before the container engine (legacy path) or the host broker is invoked.
    check = ps1.index('@("NoInnerSandbox", "AllowDegradedSandbox")')
    assert check < ps1.index("& $EngineName @dockerArgs") and check < ps1.index("& $pyExe @pyPre @execArgs")


def test_dockerfile_does_not_install_bubblewrap():
    assert "bubblewrap" not in _read("Dockerfile")


def test_run_metadata_accepts_rlimits_inner_sandbox():
    meta = metadata()
    for inner in ("rlimits", "bubblewrap", "degraded", "unknown"):
        meta["sandbox"]["inner"] = inner
        assert list(validate_metadata(meta)) == [], inner
    meta["sandbox"]["inner"] = "nsjail"
    assert list(validate_metadata(meta)) != []


@pytest.mark.skipif(os.name == "posix", reason="non-POSIX guard only")
def test_run_sandboxed_refuses_non_posix_host(tmp_path):
    with pytest.raises(S.SandboxUnavailable):
        S.run_sandboxed(["true"], [tmp_path], 5)


def test_overlay_refuses_stale_baseline(tmp_path):
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "a.c").write_text("int f(void){return 0;}\n", encoding="utf-8")
    overlay = tmp_path / "run-1" / "workspace"
    init_overlay(target, overlay)
    assert (overlay / "baseline" / "src" / "a.c").exists()
    init_overlay(target, overlay)  # unchanged target: resume is fine
    (target / "src" / "a.c").write_text("int f(void){return 1;}\n", encoding="utf-8")
    with pytest.raises(StaleBaselineError):
        init_overlay(target, overlay)


FAKE_ENGINE = '''
import json, pathlib, sys
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
elif cmd == "run":
    (here / "run_args.txt").write_text("\\n".join(sys.argv[1:]) + "\\n", encoding="utf-8")
'''

DOCKER_INFO = {"NCPU": 4, "MemTotal": 8 * 1024**3, "OperatingSystem": "Docker Desktop", "CgroupVersion": "2",
               "CpuCfsQuota": True, "CPUSet": True, "MemoryLimit": True, "SwapLimit": True, "PidsLimit": True}


def _fake_engine(tmp_path):
    """A `docker` on PATH (docker.cmd on Windows) that answers info/images/image/--version/ps and logs `run` args."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "info.json").write_text(json.dumps(DOCKER_INFO), encoding="utf-8")
    script = bin_dir / "fake_engine.py"
    script.write_text(FAKE_ENGINE, encoding="utf-8")
    if os.name == "nt":
        (bin_dir / "docker.cmd").write_text(f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n', encoding="utf-8")
    else:
        shim = bin_dir / "docker"
        shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n', encoding="utf-8")
        shim.chmod(0o755)
    (tmp_path / "target_repo").mkdir()
    (tmp_path / "run_1").mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith("FRAMAC_")}
    env["PATH"] = str(bin_dir) + os.pathsep + env.get("PATH", "")
    env.update(FRAMAC_PYTHON=sys.executable, FRAMAC_BROKER_DIR=str(tmp_path / "broker"),
               FRAMAC_CACHE_DIR=str(tmp_path / "cache"), FRAMAC_POOL_CPUS="2", FRAMAC_POOL_MEMORY="4g",
               PYTHONDONTWRITEBYTECODE="1")
    return bin_dir / "run_args.txt", env


def _engine_run_args(log):
    args = log.read_text(encoding="utf-8").splitlines()
    log.unlink()
    return args, {(a, b) for a, b in zip(args, args[1:], strict=False)}


def _assert_broker_flags(args, pairs, job_class):
    """The host broker's lease flags sit right after `run`; limits match the job env; the shim gets the command."""
    lease = args[2][len("framac-"):]
    assert args[:2] == ["run", "--name"] and ("--label", f"framac.lease={lease}") in pairs and "--init" in args
    env = dict(a.split("=", 1) for a in args if a.startswith("FRAMAC_"))
    assert env["FRAMAC_JOB_CLASS"] == job_class and 1 <= int(env["FRAMAC_POOL_CPUS"]) <= 2
    assert ("--cpus", env["FRAMAC_JOB_CPUS"]) in pairs
    assert ("--memory", env["FRAMAC_JOB_MEM_MB"] + "m") in pairs and ("--memory-swap", env["FRAMAC_JOB_MEM_MB"] + "m") in pairs
    assert ("--pids-limit", "4096") in pairs and env["FRAMAC_IMAGE_ID"] == "sha256:feedface"
    assert env["FRAMAC_OUTER_SANDBOX"] == "docker-hardened" and env["FRAMAC_RUN_HOST"]
    assert ("--entrypoint", "/bin/bash") in pairs and "/opt/framac-pipeline/skills:ro" in " ".join(args)
    assert env["FRAMAC_SHARED_CACHE_DIR"] == "/framac-cache" and env["FRAMAC_CACHE_MODE"] in ("ro", "rw")
    assert args.index("--init") < args.index("--network")    # injected before the caller's hardening flags
    return env


def test_wrappers_divide_cpu_memory_pids_and_mount_skills(tmp_path):
    import shutil
    import subprocess

    sh = _read("wrappers/framac-docker.sh")
    ps1 = _read("wrappers/framac-docker.ps1")
    for text in (sh, ps1):
        assert "/opt/framac-pipeline/skills:ro" in text
        assert "512" in text

    pwsh = shutil.which("pwsh") or shutil.which("powershell")
    if not pwsh:
        pytest.skip("pwsh/powershell not available")

    log_file, env = _fake_engine(tmp_path)
    proc = subprocess.run(
        [
            pwsh,
            "-NoProfile",
            "-File",
            str(ROOT / "wrappers/framac-docker.ps1"),
            "-TargetDir",
            str(tmp_path / "target_repo"),
            "-RunDir",
            str(tmp_path / "run_1"),
            "-NoBroker",
            "-Agents",
            "3",
            "true",
        ],
        env=env,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    args, _pairs = _engine_run_args(log_file)
    docker_invocation = " ".join(args)
    assert "--memory 2g" in docker_invocation
    assert "--pids-limit 1365" in docker_invocation
    assert "/opt/framac-pipeline/skills:ro" in docker_invocation
    # The legacy path keeps today's static flags: no lease, no entry shim, the command string last.
    assert "--init" not in args and "--label" not in args and "--entrypoint" not in args and args[-1] == "true"


def test_ps1_broker_path_sizes_the_container_through_resources_exec(tmp_path):
    import shutil
    import subprocess

    pwsh = shutil.which("pwsh") or shutil.which("powershell")
    if not pwsh:
        pytest.skip("pwsh/powershell not available")
    log_file, env = _fake_engine(tmp_path)
    base = [pwsh, "-NoProfile", "-File", str(ROOT / "wrappers/framac-docker.ps1"),
            "-TargetDir", str(tmp_path / "target_repo"), "-RunDir", str(tmp_path / "run_1")]

    proc = subprocess.run([*base, "-Class", "wp", "true"], env=env, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr or proc.stdout
    args, pairs = _engine_run_args(log_file)
    job = _assert_broker_flags(args, pairs, "wp")
    assert job["FRAMAC_CACHE_MODE"] == "ro" and any(a.endswith(":/framac-cache:ro") for a in args)
    assert args[-2:] == ["/opt/framac-pipeline/scripts/container_entry.sh", "true"]
    assert not list((tmp_path / "broker" / "leases").glob("*.json"))     # the lease was released

    trusted = "python3 /opt/framac-pipeline/scripts/cache.py stats"
    proc = subprocess.run([*base, "-CacheRw", trusted], env=env, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr or proc.stdout
    args, pairs = _engine_run_args(log_file)
    job = _assert_broker_flags(args, pairs, "light")
    assert job["FRAMAC_CACHE_MODE"] == "rw" and any(a.endswith(":/framac-cache") for a in args)
    assert args[-1] == trusted


def test_ps1_forwards_the_pipeline_knobs_read_inside_the_container(tmp_path):
    import shutil
    import subprocess

    pwsh = shutil.which("pwsh") or shutil.which("powershell")
    if not pwsh:
        pytest.skip("pwsh/powershell not available")
    log_file, env = _fake_engine(tmp_path)
    env.update(FRAMAC_SCHEDULER="waves", FRAMAC_MAX_AGENTS="3", FRAMAC_CACHE="off")
    base = [pwsh, "-NoProfile", "-File", str(ROOT / "wrappers/framac-docker.ps1"),
            "-TargetDir", str(tmp_path / "target_repo"), "-RunDir", str(tmp_path / "run_1")]
    for extra in ([], ["-NoBroker"]):
        proc = subprocess.run([*base, *extra, "true"], env=env, capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr or proc.stdout
        args, pairs = _engine_run_args(log_file)
        for knob in ("FRAMAC_SCHEDULER=waves", "FRAMAC_MAX_AGENTS=3", "FRAMAC_CACHE=off"):
            assert ("-e", knob) in pairs, (extra, knob)
        assert not any(a.startswith("FRAMAC_LOCK_STALE=") for a in args)  # unset knobs are not invented


@pytest.mark.skipif(os.name != "posix", reason="the bash wrapper targets POSIX hosts (Windows uses framac-docker.ps1)")
def test_sh_wrapper_broker_and_legacy_paths(tmp_path):
    import shutil
    import subprocess

    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash not available")
    log_file, env = _fake_engine(tmp_path)
    base = [bash, str(ROOT / "wrappers/framac-docker.sh"), "--target", str(tmp_path / "target_repo"),
            "--run-dir", str(tmp_path / "run_1")]

    proc = subprocess.run([*base, "--no-broker", "--agents", "3", "--", "true"], env=env, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    args, pairs = _engine_run_args(log_file)
    assert ("--pids-limit", "1365") in pairs and "--init" not in args and args[-1] == "true"

    proc = subprocess.run([*base, "--class", "wp", "--", "true"], env=env, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    args, pairs = _engine_run_args(log_file)
    job = _assert_broker_flags(args, pairs, "wp")
    assert job["FRAMAC_CACHE_MODE"] == "ro" and args[-2:] == ["/opt/framac-pipeline/scripts/container_entry.sh", "true"]

    trusted = ["python3", "/opt/framac-pipeline/scripts/pipeline_make.py", "run", "build"]
    proc = subprocess.run([*base, "--cache-rw", "--", *trusted], env=env, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    args, pairs = _engine_run_args(log_file)
    job = _assert_broker_flags(args, pairs, "phase-static")
    assert job["FRAMAC_CACHE_MODE"] == "rw" and args[-1] == " ".join(trusted)

    proc = subprocess.run([*base, "--agents", "2", "--", "true"], env=env, capture_output=True, text=True)
    assert proc.returncode == 0 and "deprecated" in proc.stderr

