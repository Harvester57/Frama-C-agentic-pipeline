"""
The dependency scan of a large module (scripts/cache.py `dependency_manifest`) in bounded calls.

sudo run-1: `gcc -M -MG` over sudoers_so's 147 sources in one call took 112 s idle and passed the
120 s DEPS_TIMEOUT_S under load, so the module's builds were never cached and the record said
only `{"hit": false, "key": null}`. The fake runners here time out on any call naming more than
CDS_SINGLE_CALL_LIMIT sources, the way the loaded machine did.
"""

from __future__ import annotations

import subprocess
import threading
from pathlib import Path

import pytest

import cache

CDS_N_SOURCES = 150
CDS_SINGLE_CALL_LIMIT = 40
CDS_HEADER = "common.h"
CDS_FC_HEADER = "fc_only.h"


def _cds_sources(root: Path, n: int = CDS_N_SOURCES) -> list[str]:
    names = [f"src_{i:03d}.c" for i in range(n)]
    for name in names:
        (root / name).write_text(f"/* {name} */\n", encoding="utf-8")
    (root / CDS_HEADER).write_text("/* common */\n", encoding="utf-8")
    (root / CDS_FC_HEADER).write_text("/* framac */\n", encoding="utf-8")
    return names


def _cds_srcs_in(cmd: list[str]) -> list[str]:
    return [a for a in cmd if a.endswith(".c")]


class CdsRunner:
    """`gcc`/`clang -M -MG` stand-in: one rule per source; a call naming too many sources times out."""

    def __init__(self, limit: int | None = CDS_SINGLE_CALL_LIMIT, fail_on: str | None = None, rc: int = 0) -> None:
        self.limit = limit
        self.fail_on = fail_on
        self.rc = rc
        self.calls: list[list[str]] = []
        self.timeouts: list[float] = []
        self._lock = threading.Lock()

    def __call__(self, cmd, **kwargs):
        cmd = list(cmd)
        with self._lock:
            self.calls.append(cmd)
            self.timeouts.append(kwargs.get("timeout"))
        srcs = _cds_srcs_in(cmd)
        if self.limit is not None and len(srcs) > self.limit:
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout"))
        if self.fail_on is not None and self.fail_on in srcs:
            if self.rc:
                return subprocess.CompletedProcess(cmd, self.rc, stdout="", stderr="fatal error: boom.h: No such file")
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout"))
        extra = f" {CDS_FC_HEADER}" if cmd[0] == "gcc" else ""
        out = "".join(f"{s[:-2]}.o: {s} {CDS_HEADER}{extra} \\\n  gen_{s[:-2]}.h\n" for s in srcs)
        return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")


@pytest.fixture
def cds_run(tmp_path, monkeypatch):
    """A run directory as cwd with caches on, a fixed toolchain identity and CDS_N_SOURCES sources."""
    d = tmp_path / "run-1"
    d.mkdir()
    (d / "run-metadata.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.chdir(d)
    monkeypatch.setenv("FRAMAC_IMAGE_ID", "sha256:test-image")
    monkeypatch.delenv("FRAMAC_CACHE", raising=False)
    monkeypatch.delenv("FRAMAC_CACHE_MODE", raising=False)
    monkeypatch.delenv("FRAMAC_SHARED_CACHE_DIR", raising=False)
    monkeypatch.delenv("FRAMAC_JOB_CPUS", raising=False)
    return d, _cds_sources(d)


def _cds_expected(srcs: list[str]) -> list[list[str]]:
    """The manifest one unbounded `gcc -M` + `clang -M` call reports: sources, headers, generated names."""
    deps = set(srcs) | {CDS_HEADER, CDS_FC_HEADER} | {f"gen_{s[:-2]}.h" for s in srcs}
    return [[d, cache.file_digest(d) or "missing"] for d in sorted(deps)]


def _cds_memo(srcs, runner, built: list[int]):
    out = Path("out.bin")

    def build():
        built.append(1)
        out.write_bytes(b"binary")
        return {"returncode": 0, "binary": str(out)}

    return cache.memoize(
        "eacsl-build",
        {"kind": "cds"},
        sources=srcs,
        dep_flags=["-Iinc"],
        build=build,
        outputs=lambda r: {"binary": out},
        ok=lambda r: r["returncode"] == 0,
        runner=runner,
    )


def test_large_module_manifest_survives_a_per_call_timeout(cds_run):
    _, srcs = cds_run
    runner = CdsRunner()
    deps = cache.dependency_manifest(srcs, ["-Iinc"], runner=runner)
    assert deps == _cds_expected(srcs)
    # Every call stays bounded: no call names more sources than a slow machine can scan in time.
    assert all(len(_cds_srcs_in(c)) <= CDS_SINGLE_CALL_LIMIT for c in runner.calls)
    assert all(t == cache.DEPS_TIMEOUT_S for t in runner.timeouts)
    # Both tools still scan every source, gcc with Frama-C's defines.
    for tool in ("gcc", "clang"):
        scanned = [s for c in runner.calls if c[0] == tool for s in _cds_srcs_in(c)]
        assert sorted(scanned) == sorted(srcs)
    assert all("-D__FRAMAC__" in c for c in runner.calls if c[0] == "gcc")
    assert all("-D__FRAMAC__" not in c for c in runner.calls if c[0] == "clang")


def test_chunked_manifest_and_key_equal_the_single_call_ones(cds_run):
    """Same files, same digests, same order: the cache keys of existing entries do not change."""
    _, srcs = cds_run
    chunked = cache.dependency_manifest(srcs, ["-Iinc"], runner=CdsRunner(limit=None))
    expected = _cds_expected(srcs)
    assert chunked == expected
    material = {"kind": "cds", "cwd": Path.cwd().as_posix()}
    assert cache.make_key("eacsl-build", dict(material, deps=chunked)) == cache.make_key(
        "eacsl-build", dict(material, deps=expected)
    )


@pytest.mark.parametrize("rc", [0, 1], ids=["timeout", "returncode"])
def test_one_failing_chunk_means_no_manifest(cds_run, rc):
    _, srcs = cds_run
    runner = CdsRunner(fail_on="src_077.c", rc=rc)
    assert cache.dependency_manifest(srcs, ["-Iinc"], runner=runner) is None
    # gcc failed, so clang never runs: the scan ends after about one call's timeout, not one per chunk.
    assert not any(c[0] == "clang" for c in runner.calls)


def test_a_failing_chunk_is_never_cached_and_the_record_says_why(cds_run):
    _, srcs = cds_run
    built: list[int] = []
    runner = CdsRunner(fail_on="src_077.c")
    first = _cds_memo(srcs, runner, built)
    second = _cds_memo(srcs, runner, built)
    assert built == [1, 1]
    for res in (first, second):
        rec = res["cache"]
        assert rec["hit"] is False and rec["key"] is None
        reason = rec["reason"]
        assert "gcc" in reason and "timed out" in reason and str(cache.DEPS_TIMEOUT_S) in reason
        # The failing call's sources (src_077.c is in the chunk src_072.c .. src_079.c) and the elapsed time.
        assert "src_072.c .. src_079.c" in reason and f"73-80 of {CDS_N_SOURCES}" in reason
        assert "scan stopped after" in reason
    assert not (Path("state") / "cache" / "eacsl-build").exists()


def test_a_failing_return_code_is_named_in_the_record(cds_run):
    _, srcs = cds_run
    res = _cds_memo(srcs, CdsRunner(fail_on="src_010.c", rc=1), [])
    reason = res["cache"]["reason"]
    assert "gcc" in reason and "exit 1" in reason and "boom.h" in reason


def test_a_large_module_is_cached_and_hits(cds_run):
    _, srcs = cds_run
    built: list[int] = []
    runner = CdsRunner()
    miss = _cds_memo(srcs, runner, built)
    hit = _cds_memo(srcs, runner, built)
    assert built == [1]
    assert miss["cache"]["hit"] is False and miss["cache"]["key"] and "reason" not in miss["cache"]
    assert hit["cache"] == {"hit": True, "key": miss["cache"]["key"]}


def test_a_replaced_manifest_function_without_reason_still_reports_one(cds_run, monkeypatch):
    _, srcs = cds_run
    monkeypatch.setattr(cache, "dependency_manifest", lambda sources, flags, runner=None: None)
    res = _cds_memo(srcs, CdsRunner(), [])
    assert res["cache"]["key"] is None and res["cache"]["reason"]


@pytest.mark.parametrize(("env", "expected"), [("1.5", 1), ("0.4", 1), ("3", 3), ("junk", None)])
def test_scan_workers_follow_the_job_cpu_grant(monkeypatch, env, expected):
    monkeypatch.setenv("FRAMAC_JOB_CPUS", env)
    workers = cache.deps_scan_workers(100)
    if expected is None:
        assert workers >= 1
    else:
        assert workers == min(expected, cache.DEPS_MAX_WORKERS)
    assert cache.deps_scan_workers(1) == 1
