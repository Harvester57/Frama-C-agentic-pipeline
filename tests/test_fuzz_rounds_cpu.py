"""Keep-going rounds are bounded by CPU-seconds: wall seconds times LibFuzzer workers (F6, D19).

Time is faked: a fake campaign moves a fake clock, and `time.monotonic` reads it. No test sleeps.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import run_eacsl_fuzz as R

pytestmark = pytest.mark.unit


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now


@pytest.fixture
def clock(monkeypatch) -> FakeClock:
    fake = FakeClock()
    monkeypatch.setattr(R.time, "monotonic", fake.monotonic)
    return fake


def _crash(tmp_path: Path, case: int) -> dict:
    data = bytes([case])
    path = tmp_path / f"crash-{case}"
    path.write_bytes(data)
    return {"artifact": str(path), "kind": "crash", "sha256": data.hex(), "fingerprint": f"fp{case}"}


def _fake_campaign(clock: FakeClock, tmp_path: Path, *, workers: int, cpu_per_round: float, crashes):
    """Each round spends `cpu_per_round` CPU-seconds on `workers` workers, so `cpu / workers` wall seconds.

    `crashes[i]` lists the cases round i + 1 crashes in; a round past the list is clean.
    """
    calls: list[int] = []

    def campaign(binary, seconds, fork, *, extra_env=None):
        i = len(calls)
        calls.append(seconds)
        clock.now += cpu_per_round / workers
        arts = [_crash(tmp_path, c) for c in (crashes[i] if i < len(crashes) else [])]
        return {"status": "crash_found" if arts else "clean", "returncode": 1 if arts else 0, "artifacts": arts}

    return campaign


def _rebuild(mask: int):
    return Path(f"bin{mask}"), {"compile": {"returncode": 0}}


def _run(clock, tmp_path, *, workers: int, max_time: int, cpu_per_round: float, crashes, n_cases: int = 10):
    clock.now = 0.0
    campaign = _fake_campaign(clock, tmp_path, workers=workers, cpu_per_round=cpu_per_round, crashes=crashes)
    return R.run_campaign_rounds(
        Path("bin0"), max_time, campaign=campaign, rebuild=_rebuild, n_cases=n_cases, workers=workers
    )


def test_one_and_eight_workers_run_the_same_rounds(tmp_path, clock):
    # 240 CPU-seconds either way: 1 worker for 240 s, 8 workers for 30 s. Each round finds a new case.
    crashes = [[c] for c in range(6)]
    one = _run(clock, tmp_path, workers=1, max_time=240, cpu_per_round=60, crashes=crashes)
    eight = _run(clock, tmp_path, workers=8, max_time=30, cpu_per_round=60, crashes=crashes)

    def shape(res):
        return [(r["skipped_cases"], r["crashed_cases"], r.get("stopped")) for r in res["keep_going"]["rounds"]]

    assert len(shape(one)) == 4
    assert shape(one) == shape(eight)
    assert shape(one)[-1][2] == "time_budget_spent"
    # Round 4 crashed in case 3 as the time ran out: that case is not skipped, no round is left to skip it in.
    assert one["keep_going"]["skipped_cases"] == eight["keep_going"]["skipped_cases"] == [0, 1, 2]


@pytest.mark.parametrize(
    ("workers", "max_time", "round_cpu", "expected_rounds"),
    [
        (1, 20, 11, 1),  # 9 CPU-seconds left: no new round
        (1, 20, 9, 2),  # 11 CPU-seconds left: another round, which finds nothing new
        (4, 10, 31, 1),  # 40 - 31 = 9 CPU-seconds left
        (4, 10, 29, 2),  # 40 - 29 = 11 CPU-seconds left
    ],
)
def test_a_round_needs_ten_cpu_seconds_left(tmp_path, clock, workers, max_time, round_cpu, expected_rounds):
    res = _run(clock, tmp_path, workers=workers, max_time=max_time, cpu_per_round=round_cpu, crashes=[[0]])
    assert len(res["keep_going"]["rounds"]) == expected_rounds
