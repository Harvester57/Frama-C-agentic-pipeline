import os
from pathlib import Path

import pytest

import sandbox_exec as S
from workspace_overlay import StaleBaselineError, init_overlay


def test_bwrap_argv_is_read_only_with_explicit_writable_binds():
    argv = S.build_bwrap_argv(["/bin/fuzz", "-runs=1"], [Path("/framac-run/agents/a/scratch")],
                              {"PATH": "/usr/bin", "HOME": "/framac-run/agents/a/scratch"}, Path("/framac-run/agents/a/scratch"))
    joined = " ".join(argv)
    assert "--ro-bind / /" in joined
    assert "--bind /framac-run/agents/a/scratch /framac-run/agents/a/scratch" in joined.replace("\\", "/")
    assert "--unshare-net" in argv and "--clearenv" in argv and "--die-with-parent" in argv
    assert argv[argv.index("--") + 1:] == ["/bin/fuzz", "-runs=1"]
    # Only allowlisted variables are set inside the sandbox.
    set_keys = [argv[i + 1] for i, a in enumerate(argv) if a == "--setenv"]
    assert set_keys == ["HOME", "PATH"]


def test_env_allowlist_rejects_malformed_entries():
    env = S.build_env(Path("/s"), {"LIBFUZZER_OPT": "1"})
    assert env["HOME"] == str(Path("/s")) and env["LIBFUZZER_OPT"] == "1"
    assert "USER" not in env and "SSH_AUTH_SOCK" not in env
    with pytest.raises(ValueError):
        S.build_env(Path("/s"), {"A=B": "x"})


def test_fail_closed_without_bwrap(monkeypatch):
    monkeypatch.setattr(S, "_BWRAP_OK", False)
    monkeypatch.delenv("FRAMAC_SANDBOX_DEGRADED", raising=False)
    with pytest.raises(S.SandboxUnavailable):
        S.sandbox_mode()
    monkeypatch.setenv("FRAMAC_SANDBOX_DEGRADED", "1")
    assert S.sandbox_mode() == "degraded"


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
