"""crash_replay (D3 step 2): the replay and minimize names have one home, and run_eacsl_fuzz re-exports them."""

from __future__ import annotations

from pathlib import Path

import pytest

import crash_replay
import run_eacsl_fuzz as R

pytestmark = pytest.mark.unit

CRASH_REPLAY_MOVED_NAMES = (
    "replay_artifact",
    "replay_inputs",
    "_slim_compile",
    "prepare_replay_binary",
    "replay_report",
    "acsl_include_dir",
    "_unit_harness_module",
    "_sidecar_build_spec",
    "replay_build_spec",
    "_candidate_slug",
    "_candidate_engine",
    "_reproducer_paths",
    "replay_candidates",
    "find_creduce",
    "minimize_interest",
    "minimize_input",
    "minimize_candidates",
)
CRASH_REPLAY_SOURCE = Path(__file__).resolve().parent.parent / "scripts" / "crash_replay.py"


def test_run_eacsl_fuzz_reexports_every_moved_name():
    for name in CRASH_REPLAY_MOVED_NAMES:
        assert getattr(R, name) is getattr(crash_replay, name), name


def test_crash_replay_does_not_import_run_eacsl_fuzz():
    text = CRASH_REPLAY_SOURCE.read_text(encoding="utf-8")
    assert "import run_eacsl_fuzz" not in text
    assert "from run_eacsl_fuzz" not in text
