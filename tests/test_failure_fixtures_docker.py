"""
Docker-backed check of the failure fixtures (S2, D15): each C program under `fixtures/failures/programs/`
compiles with ASan and UBSan in the analysis image, runs, and its output parses to the kind and alarm kind
that `fixtures/failures/expected.json` gives the fixture of the same name. Skipped unless FRAMAC_DOCKER_TESTS=1.
Runs once in the validation V, not in the step's acceptance.
"""

import json
import subprocess
from pathlib import Path

import pytest

import failure_identity as FI
from conftest import ANALYSIS_IMAGE, require_docker_images

pytestmark = pytest.mark.integration

_DOCKER_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "failures"
_PROGRAM_DIR = _DOCKER_FIXTURES / "programs"
_PROGRAM_NAMES = sorted(p.stem for p in _PROGRAM_DIR.glob("*.c"))


@pytest.mark.parametrize("name", _PROGRAM_NAMES)
def test_program_output_parses_to_its_fixture_kind(name):
    require_docker_images(ANALYSIS_IMAGE)
    want = json.loads((_DOCKER_FIXTURES / "expected.json").read_text(encoding="utf-8"))[name]
    compile_and_run = (
        f"clang -g -O0 -fno-omit-frame-pointer -fsanitize=address,undefined -o /tmp/prog /p/{name}.c && /tmp/prog; true"
    )
    argv = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "-v",
        f"{_PROGRAM_DIR}:/p:ro",
        "--entrypoint",
        "sh",
        ANALYSIS_IMAGE,
        "-c",
        compile_and_run,
    ]
    res = subprocess.run(
        argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600, check=False
    )
    failure = FI.parse_runtime_failure(res.stdout + res.stderr)
    assert failure is not None, res.stderr[-2000:]
    assert failure["kind"] == want["kind"]
    assert failure["alarm_kind"] == want["alarm_kind"]
    # UBSan prints no stack: its function comes from the source file, which stays in the container here.
    if not want["kind"].startswith("ubsan_"):
        assert failure["function"] == want["function"], res.stderr[-2000:]
