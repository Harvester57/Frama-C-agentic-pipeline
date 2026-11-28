"""Unit tests for pure-harness crash detection and E-ACSL libc caller attribution (W1-C)."""

from __future__ import annotations

import pytest

import failure_identity as FI

pytestmark = pytest.mark.unit

# Verbatim replay log from QCBOR run-1 Case 116 (`seed-17a8a928db558c9c`, size 32 bytes:
# 1-byte selector + 31 fixed slot bytes -> rest_n == 0, unguarded memcpy(dst, fuzz_buf + 31, 0)).
_QCBOR_CASE116_EACSL_LOG = """\
Running: /framac-run/workspace/seeds/libqcbor_a/seed-17a8a928db558c9c
memcpy: unallocated (or insufficient) space in source space
==14== ERROR: libFuzzer: deadly signal
    #0 0x00000046d818 in __sanitizer_print_stack_trace (/framac-run/workspace/harnesses/fuzz_libqcbor_a.e-acsl+0x46d818) (BuildId: 5632ae29fb93599f742d2a0e3b18fbd190823b94)
    #1 0x0000004403ec in fuzzer::PrintStackTrace() (/framac-run/workspace/harnesses/fuzz_libqcbor_a.e-acsl+0x4403ec) (BuildId: 5632ae29fb93599f742d2a0e3b18fbd190823b94)
    #2 0x000000425367 in fuzzer::Fuzzer::CrashCallback() (/framac-run/workspace/harnesses/fuzz_libqcbor_a.e-acsl+0x425367) (BuildId: 5632ae29fb93599f742d2a0e3b18fbd190823b94)
    #3 0x78eefb65bd6f  (/lib/x86_64-linux-gnu/libc.so.6+0x3fd6f) (BuildId: 5e5b51f4c39af9ac589408c1dc432ba390a273cc)
    #4 0x78eefb6b069b  (/lib/x86_64-linux-gnu/libc.so.6+0x9469b) (BuildId: 5e5b51f4c39af9ac589408c1dc432ba390a273cc)
    #5 0x78eefb65bc41 in raise (/lib/x86_64-linux-gnu/libc.so.6+0x3fc41) (BuildId: 5e5b51f4c39af9ac589408c1dc432ba390a273cc)
    #6 0x00000058cb90 in raise_abort /framac-run/workspace/harnesses/eacsl_share/format-runtime-1-a0dcfc7c8028/e-acsl/internals/e_acsl_private_assert.c:26:3
    #7 0x00000058cb90 in private_abort_fail /framac-run/workspace/harnesses/eacsl_share/format-runtime-1-a0dcfc7c8028/e-acsl/internals/e_acsl_private_assert.c:43:3
    #8 0x0000005a0dee in validate_allocated_space /framac-run/workspace/harnesses/eacsl_share/format-runtime-1-a0dcfc7c8028/e-acsl/libc_replacements/e_acsl_string.c:102:5
    #9 0x0000005a0dee in __e_acsl_builtin_memcpy /framac-run/workspace/harnesses/eacsl_share/format-runtime-1-a0dcfc7c8028/e-acsl/libc_replacements/e_acsl_string.c:222:3
    #10 0x00000056739b in LLVMFuzzerTestOneInput /framac-run/workspace/harnesses/fuzz_libqcbor_a.instrumented.c:189684:13
    #11 0x000000426a6a in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/framac-run/workspace/harnesses/fuzz_libqcbor_a.e-acsl+0x426a6a) (BuildId: 5632ae29fb93599f742d2a0e3b18fbd190823b94)
    #12 0x00000040e963 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) (/framac-run/workspace/harnesses/fuzz_libqcbor_a.e-acsl+0x40e963) (BuildId: 5632ae29fb93599f742d2a0e3b18fbd190823b94)
    #13 0x000000414aa1 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/framac-run/workspace/harnesses/fuzz_libqcbor_a.e-acsl+0x414aa1) (BuildId: 5632ae29fb93599f742d2a0e3b18fbd190823b94)
    #14 0x000000440f56 in main (/framac-run/workspace/harnesses/fuzz_libqcbor_a.e-acsl+0x440f56) (BuildId: 5632ae29fb93599f742d2a0e3b18fbd190823b94)
    #15 0x78eefb645ca7  (/lib/x86_64-linux-gnu/libc.so.6+0x29ca7) (BuildId: 5e5b51f4c39af9ac589408c1dc432ba390a273cc)
    #16 0x78eefb645d64 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x29d64) (BuildId: 5e5b51f4c39af9ac589408c1dc432ba390a273cc)
    #17 0x000000408f50 in _start (/framac-run/workspace/harnesses/fuzz_libqcbor_a.e-acsl+0x408f50) (BuildId: 5632ae29fb93599f742d2a0e3b18fbd190823b94)

NOTE: libFuzzer has rudimentary signal handlers.
      Combine libFuzzer with AddressSanitizer or similar for better crash reports.
SUMMARY: libFuzzer: deadly signal
"""

_TARGET_CALLER_EACSL_LOG = """\
Running: /framac-run/workspace/seeds/libqcbor_a/seed-target
memcpy: unallocated (or insufficient) space in source space
==14== ERROR: libFuzzer: deadly signal
    #0 0x00000046d818 in __sanitizer_print_stack_trace (/framac-run/workspace/harnesses/fuzz_libqcbor_a.e-acsl+0x46d818)
    #1 0x0000004403ec in fuzzer::PrintStackTrace() (/framac-run/workspace/harnesses/fuzz_libqcbor_a.e-acsl+0x4403ec)
    #2 0x78eefb65bc41 in raise (/lib/x86_64-linux-gnu/libc.so.6+0x3fc41)
    #3 0x00000058cb90 in raise_abort /framac-run/workspace/harnesses/eacsl_share/e-acsl/internals/e_acsl_private_assert.c:26:3
    #4 0x00000058cb90 in private_abort_fail /framac-run/workspace/harnesses/eacsl_share/e-acsl/internals/e_acsl_private_assert.c:43:3
    #5 0x0000005a0dee in validate_allocated_space /framac-run/workspace/harnesses/eacsl_share/e-acsl/libc_replacements/e_acsl_string.c:102:5
    #6 0x0000005a0dee in __e_acsl_builtin_memcpy /framac-run/workspace/harnesses/eacsl_share/e-acsl/libc_replacements/e_acsl_string.c:222:3
    #7 0x000000550120 in __gen_e_acsl_QCBORDecode_GetNext /framac-run/workspace/harnesses/fuzz_libqcbor_a.instrumented.c:44102:9
    #8 0x00000056739b in LLVMFuzzerTestOneInput /framac-run/workspace/harnesses/fuzz_libqcbor_a.instrumented.c:189684:13
    #9 0x000000426a6a in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/framac-run/workspace/harnesses/fuzz_libqcbor_a.e-acsl+0x426a6a)
    #10 0x000000440f56 in main (/framac-run/workspace/harnesses/fuzz_libqcbor_a.e-acsl+0x440f56)
"""


def test_qcbor_case116_eacsl_pure_harness_attribution_and_self_fault():
    caller, where = FI._caller_of_eacsl_runtime(_QCBOR_CASE116_EACSL_LOG)
    assert caller == "LLVMFuzzerTestOneInput"
    assert where == "/framac-run/workspace/harnesses/fuzz_libqcbor_a.instrumented.c:189684"

    failure = FI.parse_runtime_failure(_QCBOR_CASE116_EACSL_LOG)
    assert failure is not None
    assert failure["function"] == "LLVMFuzzerTestOneInput"
    assert failure["kind"] == "eacsl_libc_error"
    assert failure["alarm_kind"] == "mem_access"
    assert failure["predicate"] == "memcpy: unallocated (or insufficient) space in source space"
    assert failure["instrumented_location"] == "/framac-run/workspace/harnesses/fuzz_libqcbor_a.instrumented.c:189684"
    assert failure.get("harness_self_fault") is True

    parsed_frames = FI.stack_frames(_QCBOR_CASE116_EACSL_LOG)
    raw_frames = list(FI._STACK_FRAME_RE.finditer(_QCBOR_CASE116_EACSL_LOG))
    assert FI.is_pure_harness_crash(failure, parsed_frames) is True
    assert FI.is_pure_harness_crash(failure, raw_frames) is True

    # Must not be misclassified as startup; must quarantine as harness_setup_fault in smoke.
    assert FI.is_startup_failure(failure, _QCBOR_CASE116_EACSL_LOG) == (False, None)
    assert FI.classify_smoke_failure(failure, 31, _QCBOR_CASE116_EACSL_LOG) == "harness_setup_fault"


def test_eacsl_libc_caller_does_not_fall_through_to_libfuzzer_main():
    no_harness_frame_log = """\
memcpy: unallocated (or insufficient) space in source space
    #0 0x0000005a0dee in __e_acsl_builtin_memcpy /share/frama-c/e-acsl/libc_replacements/e_acsl_string.c:222:3
    #1 0x000000426a6a in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/tmp/fuzz.e-acsl+0x1)
    #2 0x000000440f56 in main (/tmp/fuzz.e-acsl+0x2)
    #3 0x78eefb645d64 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x3)
    #4 0x000000408f50 in _start (/tmp/fuzz.e-acsl+0x4)
"""
    caller, where = FI._caller_of_eacsl_runtime(no_harness_frame_log)
    assert (caller, where) == ("", "")

    failure = FI.parse_runtime_failure(no_harness_frame_log)
    assert failure is not None
    assert failure["function"] == "unknown_function"
    assert not failure.get("harness_self_fault")
    assert FI.is_pure_harness_crash(failure, FI.stack_frames(no_harness_frame_log)) is False


def test_embedded_target_harness_function_marks_harness_self_fault():
    embedded_log = """\
memcpy: unallocated (or insufficient) space in source space
    #0 0x0000005a0dee in __e_acsl_builtin_memcpy /share/frama-c/e-acsl/libc_replacements/e_acsl_string.c:222:3
    #1 0x00000056739b in __framac_target_embedded_entry /w/fuzz_m.instrumented.c:512:7
    #2 0x000000567500 in LLVMFuzzerTestOneInput /w/fuzz_m.instrumented.c:600:3
    #3 0x000000440f56 in main (/w/fuzz_m.e-acsl+0x440f56)
"""
    failure = FI.parse_runtime_failure(embedded_log)
    assert failure is not None
    assert failure["function"] == "__framac_target_embedded_entry"
    assert failure.get("harness_self_fault") is True
    assert FI.is_pure_harness_crash(failure, FI.stack_frames(embedded_log)) is True
    assert FI.is_pure_harness_crash(failure, list(FI._STACK_FRAME_RE.finditer(embedded_log))) is True


def test_target_frame_between_eacsl_runtime_and_harness_is_not_pure_harness_crash():
    caller, where = FI._caller_of_eacsl_runtime(_TARGET_CALLER_EACSL_LOG)
    assert caller == "QCBORDecode_GetNext"
    assert where == "/framac-run/workspace/harnesses/fuzz_libqcbor_a.instrumented.c:44102"

    failure = FI.parse_runtime_failure(_TARGET_CALLER_EACSL_LOG)
    assert failure is not None
    assert failure["function"] == "QCBORDecode_GetNext"
    assert not failure.get("harness_self_fault")

    parsed_frames = FI.stack_frames(_TARGET_CALLER_EACSL_LOG)
    raw_frames = list(FI._STACK_FRAME_RE.finditer(_TARGET_CALLER_EACSL_LOG))
    assert FI.is_pure_harness_crash(failure, parsed_frames) is False
    assert FI.is_pure_harness_crash(failure, raw_frames) is False
    assert FI.classify_smoke_failure(failure, 31, _TARGET_CALLER_EACSL_LOG) == "target_crash_candidate"


def test_is_pure_harness_crash_rejects_any_target_frame_even_with_harness_failure_dict():
    harness_failure = {
        "file": "unknown",
        "line": 0,
        "function": "LLVMFuzzerTestOneInput",
        "kind": "eacsl_libc_error",
        "alarm_kind": "mem_access",
        "is_rte": True,
        "predicate": "memcpy: unallocated (or insufficient) space in source space",
    }

    # Positive: empty frames or only runtime/signal/libc-without-file frames before LLVMFuzzerTestOneInput.
    assert FI.is_pure_harness_crash(harness_failure, []) is True
    assert (
        FI.is_pure_harness_crash(
            harness_failure,
            [
                {"function": "raise", "file": "", "line": 0},
                {"function": "validate_allocated_space", "file": "/share/frama-c/e-acsl/e_acsl_string.c", "line": 102},
                {"function": "LLVMFuzzerTestOneInput", "file": "/w/fuzz_m.instrumented.c", "line": 999},
                {"function": "main", "file": "", "line": 0},
            ],
        )
        is True
    )
    assert (
        FI.is_pure_harness_crash(
            harness_failure,
            [
                {"function": "memcpy", "file": "", "line": 0},
                {"function": "LLVMFuzzerTestOneInput", "file": "workspace/harnesses/harness_m.c", "line": 42},
            ],
        )
        is True
    )

    # Negative: target function (source-located, E-ACSL-wrapped, or stripped) before LLVMFuzzerTestOneInput.
    assert (
        FI.is_pure_harness_crash(
            harness_failure,
            [
                {"function": "parse_packet", "file": "src/parser.c", "line": 88},
                {"function": "LLVMFuzzerTestOneInput", "file": "workspace/harnesses/harness_m.c", "line": 42},
            ],
        )
        is False
    )
    assert (
        FI.is_pure_harness_crash(
            harness_failure,
            [
                {"function": "__gen_e_acsl_QCBORDecode_Init", "file": "/w/fuzz_m.instrumented.c", "line": 1200},
                {"function": "LLVMFuzzerTestOneInput", "file": "/w/fuzz_m.instrumented.c", "line": 9999},
            ],
        )
        is False
    )
    assert (
        FI.is_pure_harness_crash(
            harness_failure,
            [
                {"function": "stripped_target_fn", "file": "", "line": 0},
                {"function": "LLVMFuzzerTestOneInput", "file": "", "line": 0},
            ],
        )
        is False
    )

    # Negative: non-harness failure dicts.
    assert FI.is_pure_harness_crash(None, []) is False
    assert FI.is_pure_harness_crash({"function": "main"}, []) is False
    assert FI.is_pure_harness_crash({"function": "LLVMFuzzerInitialize"}, []) is False
    assert FI.is_pure_harness_crash({"function": "unknown_function"}, []) is False
    assert FI.is_pure_harness_crash({"function": "parse_packet"}, []) is False


def test_parse_eacsl_resource_abort_ignores_harness_entry_caller():
    log = (
        "/share/frama-c/e-acsl/observation_model/segment_model/e_acsl_segment_tracking.c:532: "
        "Exceeded heap allocation limit of 128MB\n"
        "    #0 0x1 in raise_abort /share/frama-c/e-acsl/internals/e_acsl_private_assert.c:26:3\n"
        "    #1 0x2 in unsafe_malloc /share/frama-c/e-acsl/observation_model/segment_model/e_acsl_segment_tracking.c:589:5\n"
        "    #2 0x3 in LLVMFuzzerTestOneInput /w/fuzz_m.instrumented.c:900:5\n"
        "    #3 0x4 in main (/w/fuzz_m.e-acsl+0x4)\n"
    )
    abort = FI.parse_eacsl_resource_abort(log)
    assert abort is not None
    assert abort["resource"] == "heap"
    assert abort["limit_mb"] == 128
    assert abort["caller"] is None
