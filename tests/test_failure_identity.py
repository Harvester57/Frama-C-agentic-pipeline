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


def test_c5_parse_link_stub_abort_asan_and_eacsl_excerpts() -> None:
    """C5 / B4: FRAMAC_LINK_STUB_CALLED parses symbol/caller and returns None from parse_runtime_failure."""
    assert R.parse_link_stub_abort is failure_identity.parse_link_stub_abort

    asan_stderr = (
        "FRAMAC_LINK_STUB_CALLED: far_fn (not in the unit split's address-flow reach)\n"
        "==42== ERROR: libFuzzer: deadly signal\n"
        "    #0 0x555555612340 in __sanitizer_print_stack_trace (/tmp/fuzz_m+0xbe340)\n"
        "    #1 0x5555555aa001 in fuzzer::PrintStackTrace() (/tmp/fuzz_m+0x56001)\n"
        "    #2 0x7ffff7c42520 in raise (/lib/x86_64-linux-gnu/libc.so.6+0x42520)\n"
        "    #3 0x7ffff7c28898 in abort (/lib/x86_64-linux-gnu/libc.so.6+0x28898)\n"
        "    #4 0x555555640110 in __framac_link_stub_called workspace/build/fuzz_m_link_globals/link_stubs.c:16:3\n"
        "    #5 0x555555640200 in api_entry workspace/work/src/a.c:12:5\n"
        "    #6 0x555555640300 in LLVMFuzzerTestOneInput workspace/harnesses/harness_m.c:40:3\n"
    )
    stub = failure_identity.parse_link_stub_abort(asan_stderr)
    assert stub == {
        "symbol": "far_fn",
        "message": "FRAMAC_LINK_STUB_CALLED: far_fn (not in the unit split's address-flow reach)",
        "caller": "api_entry",
    }
    assert failure_identity.parse_runtime_failure(asan_stderr) is None

    eacsl_stderr = (
        "FRAMAC_LINK_STUB_CALLED: far_fn (not in the unit split's address-flow reach)\n"
        "==99== ERROR: libFuzzer: deadly signal\n"
        "    #0 0x555555511000 in fuzzer::PrintStackTrace() (/tmp/fuzz_m.e-acsl+0x11000)\n"
        "    #1 0x555555540000 in __framac_link_stub_called /tmp/fuzz_m.instrumented.c:55:3\n"
        "    #2 0x555555540050 in __gen_e_acsl_api_entry /tmp/fuzz_m.instrumented.c:120:7\n"
        "    #3 0x555555540090 in LLVMFuzzerTestOneInput /tmp/fuzz_m.instrumented.c:200:3\n"
    )
    stub_eacsl = failure_identity.parse_link_stub_abort(eacsl_stderr)
    assert stub_eacsl is not None and stub_eacsl["symbol"] == "far_fn" and stub_eacsl["caller"] == "api_entry"
    assert failure_identity.parse_runtime_failure(eacsl_stderr) is None

    # Non-anchored mention inside target text must not match.
    assert failure_identity.parse_link_stub_abort("note: FRAMAC_LINK_STUB_CALLED: far_fn\n") is None
