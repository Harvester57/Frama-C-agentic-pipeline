"""The Eva report names the functions a slow run spent its time on (eva_flamegraph.cost_profile)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import eva_flamegraph
import run_eva_slice
from benchmark import cost_profile_line, summarize_eva

pytestmark = pytest.mark.unit

# Shaped like oscs-tweetnacl's r2v flamegraph: M is the costliest function on its own, the scalar
# multiplication with its callees.
FOLDED = """\
eva_main 10
eva_main;crypto_scalarmult;M 50
eva_main;crypto_scalarmult;car25519 20
eva_main;crypto_scalarmult 5
eva_main;hash;rec;rec 15
not a sample line
"""


def _write(path: Path, text: str = FOLDED) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_cost_profile_ranks_self_and_inclusive_time_as_shares(tmp_path: Path) -> None:
    profile = eva_flamegraph.cost_profile(_write(tmp_path / "flamegraph.txt"))
    assert profile is not None
    assert profile["self"] == [
        {"function": "M", "share": 0.5},
        {"function": "car25519", "share": 0.2},
        {"function": "rec", "share": 0.15},
        {"function": "eva_main", "share": 0.1},
        {"function": "crypto_scalarmult", "share": 0.05},
    ]
    # The root is the whole run, so it is left out; a recursive frame counts once per sample.
    assert profile["inclusive"][:3] == [
        {"function": "crypto_scalarmult", "share": 0.75},
        {"function": "M", "share": 0.5},
        {"function": "car25519", "share": 0.2},
    ]
    assert {"function": "rec", "share": 0.15} in profile["inclusive"]


def test_cost_profile_is_none_without_samples(tmp_path: Path) -> None:
    assert eva_flamegraph.cost_profile(tmp_path / "missing.txt") is None
    assert eva_flamegraph.cost_profile(_write(tmp_path / "empty.txt", "")) is None
    assert eva_flamegraph.cost_profile(_write(tmp_path / "zero.txt", "eva_main 0\n")) is None


def test_a_timed_out_run_reports_where_its_time_went(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = tmp_path / "eva"

    def fake_run(cmd, **kwargs):
        _write(out / "flamegraph.txt")  # Eva writes it as it goes, so a killed run leaves one
        raise subprocess.TimeoutExpired(cmd, float(kwargs.get("timeout") or 0), output="", stderr="")

    monkeypatch.setattr(run_eva_slice.subprocess, "run", fake_run)
    src = tmp_path / "a.c"
    src.write_text("int eva_main(void) { return 0; }\n", encoding="utf-8")
    res = run_eva_slice.run_eva_on_slice([str(src)], "eva_main", out, timeout=9)
    assert res["status"] == "analysis_timeout"
    assert res["cost_profile"]["run"] == "timed_out"
    assert res["cost_profile"]["self"][0] == {"function": "M", "share": 0.5}


def _fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, base_profile: bool) -> dict:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(run_eva_slice, "_input_digest", lambda sources, flags: "d")
    calls: list[int] = []

    def fake_execute(cmd, sources, main_fn, out_dir, reduced_checks, timeout, path_root=None):
        calls.append(1)
        if len(calls) == 1:
            res = {"status": "analysis_timeout", "error_summary": [], "sources": sources, "reduced_checks": []}
            if base_profile:
                res["cost_profile"] = {"run": "timed_out", "self": [{"function": "M", "share": 0.5}], "inclusive": []}
            return res
        # The fallback writes its own flamegraph.txt over the timed-out run's.
        _write(Path(out_dir) / "flamegraph.txt", "eva_main;cheap 4\n")
        return {"status": "ok", "sources": sources, "reduced_checks": []}

    monkeypatch.setattr(run_eva_slice, "_execute_eva", fake_execute)
    return run_eva_slice.run_eva_on_slice(["a.c"], "eva_main", tmp_path / "out", timeout=300, use_cache=False)


def test_a_fallback_keeps_the_timed_out_runs_profile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    res = _fallback(tmp_path, monkeypatch, base_profile=True)
    assert res["status"] == "ok" and res["timeout_fallback"] == "cvalue_fast"
    assert res["cost_profile"]["run"] == "timed_out"
    assert res["cost_profile"]["self"][0]["function"] == "M"


def test_a_fallback_reports_its_own_profile_when_the_timed_out_run_left_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    res = _fallback(tmp_path, monkeypatch, base_profile=False)
    assert res["cost_profile"]["run"] == "fallback"
    assert res["cost_profile"]["self"] == [{"function": "cheap", "share": 1.0}]


def test_the_benchmark_names_the_slow_functions() -> None:
    profile = {
        "run": "timed_out",
        "self": [{"function": "M", "share": 0.264}, {"function": "car25519", "share": 0.13}],
        "inclusive": [{"function": "crypto_scalarmult", "share": 0.671}],
    }
    report = {"status": "ok", "timeout_fallback": "cvalue_fast", "cost_profile": profile}
    block = summarize_eva(report, set())
    assert block["timeout_fallback"] == "cvalue_fast" and block["cost_profile"] == profile
    assert cost_profile_line(block) == (
        "Eva timed out and fell back to cvalue_fast; most time in: M 26%, car25519 13% "
        "(with callees: crypto_scalarmult 67%)"
    )
    timed_out = summarize_eva({"status": "analysis_timeout", "cost_profile": profile}, set())
    assert (cost_profile_line(timed_out) or "").startswith("Eva timed out; most time in: M 26%")
    assert cost_profile_line(summarize_eva({"status": "ok"}, set())) is None
