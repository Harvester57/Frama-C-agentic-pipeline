"""O11: every prover candidate keeps its diff against scratch/base, so its iterations can be replayed later."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

import prover_candidates as PC
from test_prover_candidates import BASE_H, C_REL, CANDIDATES_BASE_C, H_REL, Prover, annotated, annotated_header


def _cand_dir(prover: Prover, n: int) -> Path:
    return prover.scratch / "candidates" / f"c{n}"


def _cand_entry(prover: Prover, n: int) -> dict:
    return next(c for c in prover.state()["candidates"].values() if c["id"] == n)


def _apply_to_base(prover: Prover, patch: Path, dest: Path) -> Path:
    """Copy scratch/base to `dest` and apply `patch` there with `git apply` (outside any repository)."""
    git = shutil.which("git")
    if git is None:
        pytest.skip("git not available")
    shutil.copytree(prover.scratch / "base", dest)
    proc = subprocess.run([git, "apply", "-p1", str(patch)], cwd=dest, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    return dest


@pytest.mark.unit
def test_two_oracle_runs_leave_two_patches_and_the_second_rebuilds_the_second_candidate(run_dir, tmp_path):
    prover = Prover(run_dir)
    prover.iterate("a")
    prover.edit(annotated_header("b"), H_REL)
    prover.iterate("b", failed=0, proved=6, status="all_proven")

    first, second = _cand_dir(prover, 1) / PC.CANDIDATE_PATCH, _cand_dir(prover, 2) / PC.CANDIDATE_PATCH
    assert first.is_file() and second.is_file() and first.read_bytes() != second.read_bytes()
    entry = _cand_entry(prover, 2)["patch"]
    assert entry["file"] == PC.CANDIDATE_PATCH and entry["bytes"] == len(second.read_bytes())

    # scratch/work is gone, as in an exported run: the patch alone rebuilds the candidate.
    shutil.rmtree(prover.scratch / "work")
    rebuilt = _apply_to_base(prover, second, tmp_path / "replay2")
    assert (rebuilt / C_REL).read_text(encoding="utf-8") == annotated("b")
    assert (rebuilt / H_REL).read_text(encoding="utf-8") == annotated_header("b")
    rebuilt = _apply_to_base(prover, first, tmp_path / "replay1")
    assert (rebuilt / C_REL).read_text(encoding="utf-8") == annotated("a")
    assert (rebuilt / H_REL).read_text(encoding="utf-8") == BASE_H


@pytest.mark.unit
def test_the_patch_is_written_once_per_candidate_and_is_empty_for_the_base_files(run_dir):
    prover = Prover(run_dir)
    prover.guard()
    patch = _cand_dir(prover, 1) / PC.CANDIDATE_PATCH
    assert patch.read_bytes() == b""  # scratch/work still equals scratch/base
    patch.write_bytes(b"marker")
    prover.wp()  # the second oracle on the same digest does not rewrite it
    assert patch.read_bytes() == b"marker"
    assert (prover.scratch / "work" / C_REL).read_text(encoding="utf-8") == CANDIDATES_BASE_C


@pytest.mark.unit
def test_a_patch_above_the_bound_is_not_written_and_says_so(run_dir, monkeypatch):
    monkeypatch.setattr(PC, "MAX_CANDIDATE_PATCH_BYTES", 64)
    prover = Prover(run_dir)
    block = prover.iterate("a")
    assert block["recorded"] is True and block["best"] == 1  # the candidate is still recorded and ranked
    cand = _cand_dir(prover, 1)
    assert not (cand / PC.CANDIDATE_PATCH).exists()
    marker = json.loads((cand / PC.CANDIDATE_PATCH_OMITTED).read_text(encoding="utf-8"))
    entry = _cand_entry(prover, 1)["patch"]
    assert entry["file"] is None and entry["bytes"] > 64 and "64-byte bound" in entry["omitted"]
    assert marker == {"candidate": 1, **entry}


@pytest.mark.unit
def test_a_patch_write_error_is_recorded_and_retried_without_losing_the_candidate(run_dir, monkeypatch):
    prover = Prover(run_dir)
    prover.edit(annotated("a"))
    real = PC._patch_bytes

    def broken(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(PC, "_patch_bytes", broken)
    assert prover.guard()["recorded"] is True
    assert _cand_entry(prover, 1)["patch"] == {"error": "OSError: disk full"}
    monkeypatch.setattr(PC, "_patch_bytes", real)
    assert prover.wp()["evaluated"] is True
    assert _cand_entry(prover, 1)["patch"]["file"] == PC.CANDIDATE_PATCH
    assert (_cand_dir(prover, 1) / PC.CANDIDATE_PATCH).is_file()
