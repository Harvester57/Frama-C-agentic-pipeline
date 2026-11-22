"""Unit tests for P4 infrastructure prerequisites (P7a-P7f, P10c)."""

from __future__ import annotations

import json
import shutil
import sys
import types
from pathlib import Path
from typing import Any

import pytest

import fuzz_build
import resources as R
import sandbox_exec as S
from test_cache import FakeToolchain, _module

pytestmark = pytest.mark.unit


def _make_v2_cgroup(
    root: Path,
    *,
    cpu_max: str = "1500000 100000",
    mem_max_mb: int = 25088,
    mem_avail_mb: int = 32768,
    oom_kill: int | None = None,
) -> Path:
    cg = root / "sys" / "fs" / "cgroup"
    cg.mkdir(parents=True, exist_ok=True)
    (cg / "cpu.max").write_text(cpu_max + "\n", encoding="utf-8")
    (cg / "memory.max").write_text(f"{mem_max_mb * 1024 * 1024}\n", encoding="utf-8")
    if oom_kill is not None:
        (cg / "memory.events").write_text(
            f"low 0\nhigh 0\nmax 0\noom {oom_kill}\noom_kill {oom_kill}\n",
            encoding="utf-8",
        )
    proc = root / "proc"
    proc.mkdir(parents=True, exist_ok=True)
    (proc / "meminfo").write_text(
        f"MemTotal:       {mem_avail_mb * 1024} kB\nMemAvailable:   {mem_avail_mb * 1024} kB\n",
        encoding="utf-8",
    )
    return root


# ---------------------------------------------------------------------------
# P7e: FRAMAC_SUBLEASE_ID + FRAMAC_CGROUP_ENFORCED=1 grant enforcement
# ---------------------------------------------------------------------------


def test_p7e_sublease_honors_grant_even_when_outer_cgroup_enforced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = _make_v2_cgroup(tmp_path, cpu_max="1500000 100000", mem_max_mb=25088, mem_avail_mb=32768)
    monkeypatch.setenv("FRAMAC_CGROUP_ENFORCED", "1")
    monkeypatch.setenv("FRAMAC_JOB_CPUS", "3")
    monkeypatch.setenv("FRAMAC_JOB_MEM_MB", "8192")

    # Outer container (no sub-lease): cgroup wins over stale grant.
    monkeypatch.delenv("FRAMAC_SUBLEASE_ID", raising=False)
    outer = R.job_budget(root)
    assert (outer.cpus, outer.mem_mb) == (15, 25088)
    assert R.enforced_memory_mb(root) == 25088

    # Inner sub-lease: grant is included in min(grant, cgroup).
    monkeypatch.setenv("FRAMAC_SUBLEASE_ID", "sublease-abc123")
    inner = R.job_budget(root)
    assert (inner.cpus, inner.mem_mb) == (3, 8192)
    assert inner.source == "cpu:grant,mem:grant"
    assert R.enforced_memory_mb(root) == 8192
    assert R.fuzz_workers(inner) == 3


def test_p7e_sublease_still_clamped_by_smaller_cgroup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = _make_v2_cgroup(tmp_path, cpu_max="200000 100000", mem_max_mb=4096, mem_avail_mb=32768)
    monkeypatch.setenv("FRAMAC_CGROUP_ENFORCED", "1")
    monkeypatch.setenv("FRAMAC_SUBLEASE_ID", "sublease-xyz")
    monkeypatch.setenv("FRAMAC_JOB_CPUS", "8")
    monkeypatch.setenv("FRAMAC_JOB_MEM_MB", "16384")

    b = R.job_budget(root)
    assert (b.cpus, b.mem_mb) == (2, 4096)
    assert "cgroup" in b.source
    assert R.enforced_memory_mb(root) == 4096


# ---------------------------------------------------------------------------
# P7a-P7c: fuzz_workers_from_rss & FRAMAC_FUZZ_EXPLORE_JUDGE
# ---------------------------------------------------------------------------


def test_p7bc_fuzz_workers_from_rss_with_2048_cushion():
    assert R.FUZZ_RSS_LIMIT_MB == 2048
    assert R.FUZZ_SPIKE_CUSHION_MB == 2048
    assert R.FUZZ_WORKER_OVERHEAD_MB == 512

    # Design doc example: 15 ASan workers at 512 MiB + 512 base + 2048 cushion = 10,240 MiB.
    assert R.fuzz_worker_mem_mb(200) == 512
    assert R.fuzz_workers_from_rss(R.Budget(15, 25088, "t"), peak_rss_mb=200) == 15
    assert R.fuzz_workers_from_rss(R.Budget(15, 10240, "t"), peak_rss_mb=200) == 15
    assert R.fuzz_workers_from_rss(R.Budget(15, 10239, "t"), peak_rss_mb=200) == 14

    # Above 512 MiB floor: ceil(1.5 * 600) = 900 MiB/worker -> (10240 - 512 - 2048) // 900 = 8.
    assert R.fuzz_worker_mem_mb(600) == 900
    assert R.fuzz_worker_mem_mb(401) == 602
    assert R.fuzz_workers_from_rss(R.Budget(15, 10240, "t"), peak_rss_mb=600) == 8

    # Unmeasured (None / <=0) falls back to 2560 MiB/worker with cushion preserved.
    assert R.fuzz_worker_mem_mb(None) == int(R.FUZZ_RSS_LIMIT_MB * 1.25)
    assert R.fuzz_worker_mem_mb(0) == int(R.FUZZ_RSS_LIMIT_MB * 1.25)
    assert R.fuzz_workers_from_rss(R.Budget(15, 25088, "t"), peak_rss_mb=None) == 8

    # Explicit cushion override and minimum of 1 worker on tiny budgets.
    assert R.fuzz_workers_from_rss(R.Budget(15, 8192, "t"), peak_rss_mb=200, cushion_mb=0) == 15
    assert R.fuzz_workers_from_rss(R.Budget(4, 1024, "t"), peak_rss_mb=200) == 1


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, True),
        ("", True),
        ("off", False),
        ("0", False),
        ("false", False),
        ("no", False),
        ("on", True),
        ("ON", True),
        ("1", True),
        ("true", True),
        (" True ", True),
    ],
)
def test_fuzz_explore_judge_enabled_flag(monkeypatch: pytest.MonkeyPatch, raw: str | None, expected: bool):
    if raw is None:
        monkeypatch.delenv("FRAMAC_FUZZ_EXPLORE_JUDGE", raising=False)
    else:
        monkeypatch.setenv("FRAMAC_FUZZ_EXPLORE_JUDGE", raw)
    assert R.fuzz_explore_judge_enabled() is expected


# ---------------------------------------------------------------------------
# P7d: read_cgroup_oom_kills parsing & delta detection
# ---------------------------------------------------------------------------


def test_p7d_read_cgroup_oom_kills_v2_parsing_and_delta(tmp_path: Path):
    root = _make_v2_cgroup(tmp_path, oom_kill=2)
    assert R.read_cgroup_oom_kills(root) == 2

    # Increment oom_kill in memory.events and verify delta.
    events = root / "sys" / "fs" / "cgroup" / "memory.events"
    events.write_text("low 0\nhigh 0\nmax 4\noom 5\noom_kill 5\n", encoding="utf-8")
    assert R.read_cgroup_oom_kills(root) == 5
    assert R.read_cgroup_oom_kills(root, since=2) == 3
    assert R.read_cgroup_oom_kills(events_path=events, since=5) == 0
    assert R.read_cgroup_oom_kills(events, since=10) == 0  # non-negative clamp on counter reset


def test_p7d_read_cgroup_oom_kills_v1_and_missing(tmp_path: Path):
    # Minimal cgroup v1 tree
    v1_root = tmp_path / "v1"
    mem_dir = v1_root / "sys" / "fs" / "cgroup" / "memory"
    mem_dir.mkdir(parents=True)
    (mem_dir / "memory.oom_control").write_text("oom_kill_disable 0\nunder_oom 0\noom_kill 4\n", encoding="utf-8")
    assert R.read_cgroup_oom_kills(v1_root) == 4
    assert R.read_cgroup_oom_kills(v1_root, since=1) == 3

    # Missing cgroup files (non-Linux / absent hierarchy) returns None gracefully.
    empty_root = tmp_path / "empty"
    empty_root.mkdir()
    assert R.read_cgroup_oom_kills(empty_root) is None
    assert R.read_cgroup_oom_kills(empty_root, since=0) is None
    assert R.read_cgroup_oom_kills(events_path=tmp_path / "does-not-exist") is None


# ---------------------------------------------------------------------------
# P10c: sandbox_exec RLIMIT_CORE clamp
# ---------------------------------------------------------------------------


def _fake_resource(
    hard_core: int, *, rlim_infinity: int = -1
) -> tuple[types.SimpleNamespace, dict[str, tuple[int, int]]]:
    calls: dict[str, tuple[int, int]] = {}

    def _getrlimit(which: str) -> tuple[int, int]:
        if which == "core":
            return (hard_core, hard_core)
        return (rlim_infinity, rlim_infinity)

    def _setrlimit(which: str, value: tuple[int, int]) -> None:
        soft, hard = value
        if which == "core" and hard_core != rlim_infinity and (soft > hard_core or hard > hard_core):
            raise ValueError("not allowed to raise maximum limit")
        calls[which] = value

    mod = types.SimpleNamespace(
        RLIMIT_CPU="cpu",
        RLIMIT_FSIZE="fsize",
        RLIMIT_NOFILE="nofile",
        RLIMIT_NPROC="nproc",
        RLIMIT_AS="as",
        RLIMIT_CORE="core",
        RLIM_INFINITY=rlim_infinity,
        getrlimit=_getrlimit,
        setrlimit=_setrlimit,
    )
    return mod, calls


def test_p10c_rlimit_core_clamped_when_hard_is_zero(monkeypatch: pytest.MonkeyPatch):
    fake, calls = _fake_resource(hard_core=0)
    monkeypatch.setitem(sys.modules, "resource", fake)
    S._make_preexec(S.Limits())()
    assert calls["core"] == (0, 0)


@pytest.mark.parametrize("rlim_inf", [-1, (1 << 63) - 1])
def test_p10c_rlimit_core_uses_core_limit_bytes_when_hard_is_infinity(monkeypatch: pytest.MonkeyPatch, rlim_inf: int):
    fake, calls = _fake_resource(hard_core=rlim_inf, rlim_infinity=rlim_inf)
    monkeypatch.setitem(sys.modules, "resource", fake)
    S._make_preexec(S.Limits())()
    assert calls["core"] == (S.CORE_LIMIT_BYTES, S.CORE_LIMIT_BYTES)


def test_p10c_rlimit_core_clamped_to_core_limit_bytes_when_hard_positive(monkeypatch: pytest.MonkeyPatch):
    fake, calls = _fake_resource(hard_core=4096)
    monkeypatch.setitem(sys.modules, "resource", fake)
    S._make_preexec(S.Limits())()
    assert calls["core"] == (S.CORE_LIMIT_BYTES, S.CORE_LIMIT_BYTES)


# ---------------------------------------------------------------------------
# P7f: dual pre-build artifact recording & resolve_prebuilt_binary
# ---------------------------------------------------------------------------


def test_p7f_dual_prebuilt_enabled_vs_legacy_off(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    eacsl_calls: list[Path] = []
    san_calls: list[Path] = []

    def fake_eacsl(sources: list[str], out_bin: Path, *args: Any, **kwargs: Any) -> dict[str, Any]:
        # Real e-acsl-gcc writes `<out_bin>.e-acsl` and select_eacsl_binary returns that path.
        p = Path(out_bin)
        actual = p.with_name(f"{p.name}.e-acsl")
        actual.parent.mkdir(parents=True, exist_ok=True)
        actual.write_bytes(b"eacsl-bin")
        eacsl_calls.append(p)
        return {"returncode": 0, "binary": str(actual), "engine": "eacsl", "cache": {"hit": False, "key": "k-e"}}

    def fake_san(sources: list[str], out_bin: Path, *args: Any, **kwargs: Any) -> dict[str, Any]:
        p = Path(out_bin)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"san-bin")
        san_calls.append(p)
        return {"returncode": 0, "binary": str(p), "engine": "sanitizers", "cache": {"hit": False, "key": "k-s"}}

    monkeypatch.setattr(fuzz_build, "selftest_blocks_eacsl", lambda *a, **k: None)
    monkeypatch.setattr(fuzz_build, "compile_eacsl_binary", fake_eacsl)
    monkeypatch.setattr(fuzz_build, "compile_sanitizer_binary", fake_san)

    # Legacy mode (FRAMAC_FUZZ_EXPLORE_JUDGE=off): exact legacy output path, no dual build.
    monkeypatch.setenv("FRAMAC_FUZZ_EXPLORE_JUDGE", "off")
    legacy_out = tmp_path / "legacy" / "fuzz_mod"
    legacy = fuzz_build.build_module_binary(["mod.c"], legacy_out, engine="auto")
    assert legacy["engine_used"] == "eacsl"
    assert legacy["compile"]["binary"] == str(legacy_out.with_name("fuzz_mod.e-acsl"))
    assert "binaries" not in legacy
    assert "sanitizer_compile" not in legacy
    assert eacsl_calls == [legacy_out]
    assert san_calls == []

    # Enabled mode (FRAMAC_FUZZ_EXPLORE_JUDGE=on): builds BOTH <out_bin>.e-acsl and <out_bin>.san.
    eacsl_calls.clear()
    san_calls.clear()
    monkeypatch.setenv("FRAMAC_FUZZ_EXPLORE_JUDGE", "on")
    dual_out = tmp_path / "dual" / "fuzz_mod"
    dual = fuzz_build.build_module_binary(["mod.c"], dual_out, engine="auto")
    expected_eacsl = dual_out.with_name("fuzz_mod.e-acsl")
    expected_san = dual_out.with_name("fuzz_mod.san")
    assert dual["engine_used"] == "eacsl"
    assert eacsl_calls == [dual_out]
    assert san_calls == [expected_san]
    assert dual["binaries"] == {"sanitizers": str(expected_san), "eacsl": str(expected_eacsl)}
    assert dual["sanitizer_compile"]["returncode"] == 0
    assert dual["sanitizer_compile"]["binary"] == str(expected_san)
    assert expected_eacsl.is_file() and expected_san.is_file()


def test_p7f_dual_prebuilt_caches_both_binaries_and_falls_back_cleanly(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    run = tmp_path / "run-dual"
    run.mkdir()
    (run / "run-metadata.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.chdir(run)
    monkeypatch.setenv("FRAMAC_IMAGE_ID", "sha256:test-dual-image")
    monkeypatch.setenv("FRAMAC_FUZZ_EXPLORE_JUDGE", "on")
    monkeypatch.delenv("FRAMAC_CACHE", raising=False)
    monkeypatch.delenv("FRAMAC_SHARED_CACHE_DIR", raising=False)
    monkeypatch.setattr(fuzz_build, "_resolve_eacsl_gcc", lambda: ("e-acsl-gcc", True))
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    _module(run)
    fake = FakeToolchain(deps=["inc/mod.h"])
    real_eacsl, real_san = fuzz_build.compile_eacsl_binary, fuzz_build.compile_sanitizer_binary
    monkeypatch.setattr(fuzz_build, "compile_eacsl_binary", lambda *a, **k: real_eacsl(*a, **{"runner": fake, **k}))
    monkeypatch.setattr(fuzz_build, "compile_sanitizer_binary", lambda *a, **k: real_san(*a, **{"runner": fake, **k}))

    out_bin = Path("workspace/harnesses/fuzz_mod")
    first = fuzz_build.build_module_binary(["mod.c"], out_bin, engine="auto", cppflags="-Iinc", apply_selftest=False)
    assert first["compile"]["returncode"] == 0
    assert first["sanitizer_compile"]["returncode"] == 0
    assert Path(first["binaries"]["eacsl"]).name == "fuzz_mod.e-acsl"
    assert Path(first["binaries"]["sanitizers"]).name == "fuzz_mod.san"
    assert Path(first["binaries"]["eacsl"]).is_file()
    assert Path(first["binaries"]["sanitizers"]).is_file()
    builds_after_first = len(fake.builds())

    # Second call restores BOTH from cache without recompiling.
    second = fuzz_build.build_module_binary(["mod.c"], out_bin, engine="auto", cppflags="-Iinc", apply_selftest=False)
    assert second["compile"]["cache"]["hit"] is True
    assert second["sanitizer_compile"]["cache"]["hit"] is True
    assert len(fake.builds()) == builds_after_first


def test_p7f_dual_prebuilt_eacsl_fallback_records_sanitizers_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FRAMAC_FUZZ_EXPLORE_JUDGE", "on")
    monkeypatch.setattr(fuzz_build, "selftest_blocks_eacsl", lambda *a, **k: "eacsl_selftest_failed")

    def fake_san(sources: list[str], out_bin: Path, *args: Any, **kwargs: Any) -> dict[str, Any]:
        p = Path(out_bin)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"san")
        return {"returncode": 0, "binary": str(p), "engine": "sanitizers", "cache": {"hit": False, "key": None}}

    monkeypatch.setattr(fuzz_build, "compile_sanitizer_binary", fake_san)
    out_bin = tmp_path / "fuzz_m"
    res = fuzz_build.build_module_binary(["m.c"], out_bin, engine="auto", apply_selftest=True)
    assert res["engine_used"] == "sanitizers"
    assert res["engine_fallback_reason"] == "eacsl_selftest_failed"
    assert res["binaries"] == {"sanitizers": str(tmp_path / "fuzz_m.san"), "eacsl": None}
    assert res["sanitizer_compile"]["returncode"] == 0


def test_p7f_resolve_prebuilt_binary_success_and_errors(tmp_path: Path):
    san_bin = tmp_path / "fuzz_mod.san"
    eacsl_bin = tmp_path / "fuzz_mod.e-acsl"
    san_bin.write_bytes(b"san")
    eacsl_bin.write_bytes(b"eacsl")

    report = {
        "mode": "build",
        "module": "mod",
        "status": "built",
        "engine_used": "eacsl",
        "binary": str(eacsl_bin),
        "binaries": {"sanitizers": str(san_bin), "eacsl": str(eacsl_bin)},
        "compile": {"returncode": 0, "binary": str(eacsl_bin)},
        "sanitizer_compile": {"returncode": 0, "binary": str(san_bin)},
    }
    build_json = tmp_path / "workspace" / "build" / "mod.build.json"
    build_json.parent.mkdir(parents=True)
    build_json.write_text(json.dumps(report), encoding="utf-8")

    # Resolves from Path and dict.
    assert fuzz_build.resolve_prebuilt_binary(build_json, "sanitizers") == san_bin
    assert fuzz_build.resolve_prebuilt_binary(build_json, "eacsl") == eacsl_bin
    assert fuzz_build.resolve_prebuilt_binary(report, "sanitizers") == san_bin
    assert fuzz_build.resolve_prebuilt_binary(report, "eacsl") == eacsl_bin

    # Legacy build.json without `binaries` map still resolves via sanitizer_compile / binary.
    legacy_report = {k: v for k, v in report.items() if k != "binaries"}
    assert fuzz_build.resolve_prebuilt_binary(legacy_report, "sanitizers") == san_bin
    assert fuzz_build.resolve_prebuilt_binary(legacy_report, "eacsl") == eacsl_bin

    # Missing build.json file -> PrebuiltBinaryError.
    with pytest.raises(fuzz_build.PrebuiltBinaryError, match="not found"):
        fuzz_build.resolve_prebuilt_binary(tmp_path / "missing.build.json", "sanitizers")

    # Malformed build.json -> PrebuiltBinaryError.
    bad_json = tmp_path / "bad.build.json"
    bad_json.write_text("{not-json", encoding="utf-8")
    with pytest.raises(fuzz_build.PrebuiltBinaryError, match="cannot read"):
        fuzz_build.resolve_prebuilt_binary(bad_json, "sanitizers")

    # Engine explicitly null in binaries (e.g. E-ACSL fell back) -> PrebuiltBinaryError with reason.
    fallback_report = {
        "module": "mod",
        "engine_used": "sanitizers",
        "engine_fallback_reason": "eacsl_compile_failed",
        "binaries": {"sanitizers": str(san_bin), "eacsl": None},
    }
    with pytest.raises(fuzz_build.PrebuiltBinaryError, match="eacsl_compile_failed"):
        fuzz_build.resolve_prebuilt_binary(fallback_report, "eacsl")
    assert fuzz_build.resolve_prebuilt_binary(fallback_report, "sanitizers") == san_bin

    # Missing binary on disk -> PrebuiltBinaryError (unless require_exists=False).
    missing_bin = tmp_path / "gone.san"
    missing_report = {"module": "mod", "binaries": {"sanitizers": str(missing_bin), "eacsl": None}}
    with pytest.raises(fuzz_build.PrebuiltBinaryError, match="does not exist"):
        fuzz_build.resolve_prebuilt_binary(missing_report, "sanitizers")
    assert fuzz_build.resolve_prebuilt_binary(missing_report, "sanitizers", require_exists=False) == missing_bin

    # Unsupported engine name -> ValueError.
    with pytest.raises(ValueError, match="unsupported prebuilt binary engine"):
        fuzz_build.resolve_prebuilt_binary(report, "auto")
