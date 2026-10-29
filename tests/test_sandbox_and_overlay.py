import os
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
    # The legacy check runs before docker is invoked.
    assert ps1.index('@("NoInnerSandbox", "AllowDegradedSandbox")') < ps1.index("& docker @dockerArgs")


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
