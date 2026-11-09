"""Folding a -eva-flamegraph file merges identical stacks without changing what any reader computes."""

from __future__ import annotations

from pathlib import Path

import pytest

import eva_flamegraph
import eva_shards

pytestmark = pytest.mark.unit

# One line per analysed call, as Eva writes it: the same stacks come back many times.
UNFOLDED = """\
eva_main;f 6.0
eva_main;f;inner 1.5
eva_main;shared 4
eva_main;f 2.0
eva_main;f;inner 0.5
eva_main 1
eva_main;shared 6
eva_main;g;rec;rec 0.1
eva_main;g;rec;rec 0.2
not a sample line
eva_main;bad -3
"""


def _write(path: Path, text: str = UNFOLDED) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_fold_merges_identical_stacks_sorted_and_drops_non_samples(tmp_path: Path) -> None:
    path = _write(tmp_path / "flamegraph.txt")
    assert eva_flamegraph.fold_flamegraph(path)
    assert path.read_text(encoding="utf-8").splitlines() == [
        "eva_main 1",
        "eva_main;f 8",
        "eva_main;f;inner 2",
        "eva_main;g;rec;rec 0.3",
        "eva_main;shared 10",
    ]
    assert not list(tmp_path.glob(".tmp_fold*"))


def test_fold_is_lossless_for_every_reader(tmp_path: Path) -> None:
    raw = _write(tmp_path / "raw.txt")
    folded = _write(tmp_path / "folded.txt")
    assert eva_flamegraph.fold_flamegraph(folded)
    assert eva_flamegraph.cost_profile(folded) == eva_flamegraph.cost_profile(raw)
    cases = ["f(x);", "shared(x); g(x);", "shared(x);"]
    assert eva_shards.case_costs(cases, folded) == eva_shards.case_costs(cases, raw)


def test_bucketed_fold_writes_the_same_lines(tmp_path: Path) -> None:
    lines = [f"eva_main;f{k % 37};g{k % 5} {k % 7}.25\n" for k in range(2000)]
    one = _write(tmp_path / "one.txt", "".join(lines))
    many = _write(tmp_path / "many.txt", "".join(lines))
    assert eva_flamegraph.fold_flamegraph(one)
    assert eva_flamegraph.fold_flamegraph(many, bucket_bytes=1024)
    assert sorted(many.read_text(encoding="utf-8").splitlines()) == one.read_text(encoding="utf-8").splitlines()
    assert eva_flamegraph.cost_profile(many) == eva_flamegraph.cost_profile(one)
    assert not list(tmp_path.glob(".tmp_fold*"))


def test_folding_twice_changes_nothing(tmp_path: Path) -> None:
    path = _write(tmp_path / "flamegraph.txt")
    eva_flamegraph.fold_flamegraph(path)
    once = path.read_text(encoding="utf-8")
    eva_flamegraph.fold_flamegraph(path)
    assert path.read_text(encoding="utf-8") == once


def test_times_never_use_an_exponent() -> None:
    assert eva_flamegraph._format_time(1e20) == "100000000000000000000"
    assert eva_flamegraph._format_time(0.000012) == "0.000012"
    assert eva_flamegraph._format_time(3.0) == "3"


def test_missing_file_is_not_folded(tmp_path: Path) -> None:
    assert not eva_flamegraph.fold_flamegraph(tmp_path / "absent.txt")
    assert not list(tmp_path.iterdir())


def test_concatenated_shard_profiles_are_folded(tmp_path: Path) -> None:
    a = _write(tmp_path / "a.txt", "eva_main;f 1.0\neva_main;f 2.0\n")
    b = _write(tmp_path / "b.txt", "eva_main;f 3.0\neva_main;g 1.0\n")
    dest = tmp_path / "out" / "flamegraph.txt"
    assert eva_shards.concat_flamegraphs([a, b], dest)
    assert dest.read_text(encoding="utf-8").splitlines() == ["eva_main;f 6", "eva_main;g 1"]
