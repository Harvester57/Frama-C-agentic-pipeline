"""The names moved out of run_eacsl_fuzz.py (S1) are still there, and their homes stay free of run_eacsl_fuzz."""

from __future__ import annotations

from pathlib import Path

import pytest

import failure_identity
import fuzz_dictionary
import run_eacsl_fuzz as R

pytestmark = pytest.mark.unit


def test_run_eacsl_fuzz_reexports_every_moved_name() -> None:
    failure_names = [
        "_FN_RE",
        "_ERR_RE",
        "_OLD_RE",
        "_PRED_HEAD_RE",
        "_SEGMENT_RE",
        "_RUNTIME_FN_PREFIXES",
        "_RUNTIME_FILE_MARKERS",
        "_UBSAN_RE",
        "_UBSAN_VALUE_RE",
        "_ASAN_ERR_RE",
        "_ASAN_OP_RE",
        "_STACK_FRAME_RE",
        "_LIBC_FN",
        "_LIBC_TEMPLATES",
        "_LIBC_QUOTED_RE",
        "_EACSL_GEN_PREFIX",
        "_SIGNEDNESS_PAIRS",
        "STACK_FRAMES_MAX",
        "_PROCESS_FRAME_FNS",
        "is_runtime_function",
        "stable_ubsan_message",
        "_map_sanitizer_alarm_kind",
        "_resolve_source_candidates",
        "_is_acsl_annotation_line",
        "_resolve_function_at_line",
        "is_harness_fuzz_function",
        "_parse_segment_failure",
        "_caller_of_eacsl_runtime",
        "_parse_libc_failure",
        "_failing_predicate",
        "parse_eacsl_failure",
        "parse_sanitizer_failure",
        "parse_runtime_failure",
        "needs_attribution",
        "stack_frames",
        "failure_fingerprint",
    ]
    dictionary_names = [
        "_DICT_LINE_RE",
        "sanitize_dictionary_token",
        "sanitize_dictionary_line",
        "sanitize_dictionary_content",
        "sanitize_fuzzer_dictionary",
        "AUTO_DICT_DIR",
        "_dict_stem",
        "auto_dictionary_path",
        "dictionary_target_sources",
        "build_auto_dictionary",
        "resolve_campaign_dictionary",
        "extra_dictionary_path",
        "_dictionary_entry_lines",
        "merge_extra_dictionary",
    ]
    assert len(failure_names) == 36 and len(dictionary_names) == 14
    for name in failure_names:
        assert getattr(R, name) is getattr(failure_identity, name), name
    for name in dictionary_names:
        assert getattr(R, name) is getattr(fuzz_dictionary, name), name
    assert R._failure_fingerprint is failure_identity.failure_fingerprint


def test_failure_identity_does_not_import_run_eacsl_fuzz() -> None:
    scripts = Path(__file__).resolve().parents[1] / "scripts"
    for name in ("failure_identity.py", "fuzz_dictionary.py"):
        text = (scripts / name).read_text(encoding="utf-8")
        assert "import run_eacsl_fuzz" not in text, name
        assert "from run_eacsl_fuzz" not in text, name
