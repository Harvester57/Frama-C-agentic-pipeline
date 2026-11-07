"""
Phase 0 redesign fixtures (tests/fixtures/phase0): the reproducers (one Phase 0 defect each, with an
exact ground truth) and the seeded-bug projects (one verified bug each, plus decoys). These checks keep
the ground truth consistent with the sources; the Docker-backed ones (opt-in) check that every project
still builds in the pipeline image.
"""

import json
import re
from pathlib import Path

import pytest

from conftest import PHASE0_FIXTURES

REPRODUCERS = sorted(p for p in (PHASE0_FIXTURES / "reproducers").iterdir() if (p / "truth.json").is_file())
SEEDED = sorted(p for p in (PHASE0_FIXTURES / "seeded").iterdir() if (p / "truth.json").is_file())
FID_RE = re.compile(r"^[\w./-]+\.[ch]#[A-Za-z_]\w*$")


def _truth(project: Path) -> dict:
    return json.loads((project / "truth.json").read_text(encoding="utf-8"))


def test_fixture_sets_are_present():
    assert len(REPRODUCERS) == 9
    assert len(SEEDED) == 7


@pytest.mark.unit
@pytest.mark.parametrize("project", REPRODUCERS, ids=lambda p: p.name)
def test_reproducer_truth_is_consistent(project):
    t = _truth(project)
    functions = set(t["functions"])
    assert functions and all(FID_RE.match(f) for f in functions)
    for fid in functions | set(t.get("not_compiled", [])):
        assert (project / fid.split("#")[0]).is_file(), fid
    assert not functions & set(t.get("not_compiled", []))
    for e in t["edges"]:
        assert e["caller"] in functions and e["callee"] in functions, e
        assert e["kind"] in ("direct", "indirect")
    assert set(t["entry_points"]) <= functions
    assert set(t.get("thread_entries", [])) <= functions
    for name, unit in t["units"].items():
        assert unit["kind"] in ("static_lib", "shared_lib", "executable"), name
        assert all((project / f).is_file() for f in unit["files"]), name
        assert set(unit.get("links", [])) <= set(t["units"]), name
    assert (project / "Makefile").is_file()


@pytest.mark.unit
@pytest.mark.parametrize("project", SEEDED, ids=lambda p: p.name)
def test_seeded_truth_points_at_real_code(project):
    t = _truth(project)
    assert t["bugs"], "a seeded project has at least one bug"
    for item in t["bugs"] + t.get("decoys", []):
        source = project / item["file"]
        assert source.is_file(), item
        text = source.read_text(encoding="utf-8")
        line = item.get("line")
        if line is not None:
            assert 1 <= line <= len(text.splitlines()), item
    for bug in t["bugs"]:
        assert bug["kind"] in ("mem_access", "signed_overflow", "division_by_zero"), bug
        assert (project / "repro" / f"{bug['id']}.bin").is_file(), bug
    assert all(FID_RE.match(e) for e in t["entry_points"])


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize("project", REPRODUCERS + SEEDED, ids=lambda p: p.name)
def test_fixture_builds_in_the_pipeline_image(project, docker_fixture_run):
    proc = docker_fixture_run(project, "make")
    assert proc.returncode == 0, proc.stdout[-1500:] + proc.stderr[-1500:]
