"""Tests for hardened regexes and parsers in scripts/run_eacsl_fuzz.py (Milestone M4)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import run_eacsl_fuzz as R
from fingerprint import make_fingerprint

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# A4: Error Location Parsing without Extension Limits
# ---------------------------------------------------------------------------


def test_a4_eacsl_error_in_non_c_source_file():
    log = """src/parser/grammar.y: In function 'yyparse'
src/parser/grammar.y:128: Error: Assertion failed:
\tThe failing predicate is:
\trte/index_bound:
\t\ti < 8.
==1== ERROR: libFuzzer: deadly signal
"""
    f = R.parse_eacsl_failure(log)
    assert f is not None
    assert f["file"] == "src/parser/grammar.y"
    assert f["line"] == 128
    assert f["function"] == "yyparse"
    assert f["kind"] == "assertion"
    assert f["alarm_kind"] == "index_bound"
    assert f["is_rte"] is True


def test_a4_eacsl_old_style_in_inc_file():
    log = """Assertion failed at line 42 in file src/tables.inc in function parse_hdr.
The failing predicate is:
len <= 64.
"""
    f = R.parse_eacsl_failure(log)
    assert f is not None
    assert f["file"] == "src/tables.inc"
    assert f["line"] == 42
    assert f["function"] == "parse_hdr"
    assert f["predicate"] == "len <= 64"


def test_a4_ubsan_error_in_inc_and_cpp_files():
    log_inc = "src/attr_tables.inc:41:9: runtime error: load of null pointer of type 'const int'\n"
    f_inc = R.parse_sanitizer_failure(log_inc)
    assert f_inc is not None
    assert f_inc["file"] == "src/attr_tables.inc"
    assert f_inc["line"] == 41

    log_cpp = "src/helper.cpp:100:5: runtime error: signed integer overflow: 2147483640 + 10 cannot be represented in type 'int'\n"
    f_cpp = R.parse_sanitizer_failure(log_cpp)
    assert f_cpp is not None
    assert f_cpp["file"] == "src/helper.cpp"
    assert f_cpp["line"] == 100
    assert f_cpp["alarm_kind"] == "signed_overflow"


# ---------------------------------------------------------------------------
# A5: Stack Frame Attribution Decoupled from File and Line
# ---------------------------------------------------------------------------


def test_a5_stack_frame_without_file_does_not_fingerprint_unknown_function():
    log = """==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000014
READ of size 4 at 0x602000000014
    #0 0x55555558a122 in __asan_memcpy (/workspace/harness+0x4a122)
    #1 0x5555555c9876 in parse_attr (/workspace/guard.bin+0x4f1)
"""
    f = R.parse_sanitizer_failure(log)
    assert f is not None
    assert f["function"] == "parse_attr"
    assert f["file"] == "unknown"
    fp = make_fingerprint(f["file"], f["function"], f["alarm_kind"], f["predicate"])
    assert not fp.startswith("unknown#unknown_function")
    assert fp.startswith("unknown#parse_attr::")


def test_a5_stack_frame_with_non_c_file():
    log = """==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000014
READ of size 4 at 0x602000000014
    #0 0x5555555c9876 in parse_attr /workspace/src/tables.inc:41:9
"""
    f = R.parse_sanitizer_failure(log)
    assert f is not None
    assert f["function"] == "parse_attr"
    assert f["file"] == "/workspace/src/tables.inc"
    assert f["line"] == 41


# ---------------------------------------------------------------------------
# D1: Multi-word AddressSanitizer Error Kinds
# ---------------------------------------------------------------------------


def test_d1_asan_attempting_double_free():
    log = """==1==ERROR: AddressSanitizer: attempting double-free on address 0x602000000014
    #0 0x5555555c9876 in free_packet /workspace/src/packet.c:20:5
"""
    f = R.parse_sanitizer_failure(log)
    assert f is not None
    assert f["alarm_kind"] == "freeable"
    assert f["kind"] == "asan_attempting_double_free"
    assert "attempting double-free" in f["predicate"]


def test_d1_asan_attempting_free_not_malloced():
    log = """==1==ERROR: AddressSanitizer: attempting free on address which was not malloc()-ed: 0x602000000014
    #0 0x5555555c9876 in free_packet /workspace/src/packet.c:25:5
"""
    f = R.parse_sanitizer_failure(log)
    assert f is not None
    assert f["alarm_kind"] == "freeable"
    assert f["kind"] == "asan_attempting_free_on_address_which_was_not_malloc_ed"


def test_d1_asan_requested_allocation_size():
    log = """==1==ERROR: AddressSanitizer: requested allocation size 0x7fffffffffffffff exceeds maximum supported size of 0x10000000000
    #0 0x5555555c9876 in alloc_buf /workspace/src/buf.c:30:5
"""
    f = R.parse_sanitizer_failure(log)
    assert f is not None
    assert f["kind"] == "asan_requested_allocation_size"


# ---------------------------------------------------------------------------
# D2: Access Size Normalization in ASan Operation Predicates
# ---------------------------------------------------------------------------


def test_d2_asan_access_size_dropped_from_fingerprint():
    log_size1 = """==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000014
READ of size 1 at 0x602000000014
    #0 0x5555555c9876 in read_buf /workspace/src/buf.c:30:5
"""
    log_size4 = """==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000014
READ of size 4 at 0x602000000014
    #0 0x5555555c9876 in read_buf /workspace/src/buf.c:30:5
"""
    f1 = R.parse_sanitizer_failure(log_size1)
    f4 = R.parse_sanitizer_failure(log_size4)
    assert f1 is not None and f4 is not None
    assert f1["predicate"] == "rte: mem_access: AddressSanitizer: heap-buffer-overflow (READ)"
    assert f4["predicate"] == "rte: mem_access: AddressSanitizer: heap-buffer-overflow (READ)"
    fp1 = make_fingerprint(f1["file"], f1["function"], f1["alarm_kind"], f1["predicate"])
    fp4 = make_fingerprint(f4["file"], f4["function"], f4["alarm_kind"], f4["predicate"])
    assert fp1 == fp4


# ---------------------------------------------------------------------------
# D3: LLD Linker Diagnostics
# ---------------------------------------------------------------------------


def test_d3_lld_undefined_symbol_diagnostics():
    log = """ld.lld: error: undefined symbol: custom_init
>>> referenced by init.c:12 (/workspace/src/init.c:12)
ld.lld: error: undefined symbol: custom_cleanup
>>> referenced by init.c:18 (/workspace/src/init.c:18)
"""
    assert R.parse_undefined_references(log) == ["custom_init", "custom_cleanup"]


# ---------------------------------------------------------------------------
# B8: Dispatch Case Count from Sidecar JSON
# ---------------------------------------------------------------------------


def test_b8_dispatch_case_count_reads_sidecar_json(tmp_path: Path):
    harness_c = tmp_path / "harness_crypto.c"
    harness_json = tmp_path / "harness_crypto.json"
    harness_c.write_text(f"// {R.DISPATCH_SKIP_MACRO}\n", encoding="utf-8")
    harness_json.write_text(json.dumps({"dispatch_case_count": 7}), encoding="utf-8")
    assert R.dispatch_case_count([str(harness_c)]) == 7


@pytest.mark.parametrize(
    "sidecar",
    [{"dispatch_case_count": 0, "dispatch_cases": []}, {"api_cases": []}, {"dispatch_case_count": 5}],
)
def test_a_harness_that_is_not_a_dispatch_harness_runs_in_fork_mode(tmp_path: Path, sidecar):
    # Benchmark run ab-fc35dev (2026-11-13): every non-dispatch sidecar records dispatch_case_count 0;
    # read as a dispatch harness with no case, the first crash divided by zero and no campaign ran.
    harness_c = tmp_path / "harness_minmea.c"
    harness_c.write_text("int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { return 0; }\n")
    (tmp_path / "harness_minmea.json").write_text(json.dumps(sidecar), encoding="utf-8")
    # A source without the skip macro cannot skip cases, whatever its sidecar says.
    assert R.dispatch_case_count([str(harness_c)]) is None
    crash = tmp_path / "crash-1"
    crash.write_bytes(b"\x07")
    assert R.artifact_dispatch_case({"artifact": str(crash)}, 0) is None
    calls = []

    def campaign(binary, max_time, fork):
        calls.append(fork)
        return {"status": "ok", "artifacts": [{"artifact": str(crash), "kind": "crash"}]}

    res = R.run_campaign_rounds(Path("bin"), 60, campaign=campaign, rebuild=None, n_cases=0)
    assert res["keep_going"] == {"mode": "fork"} and calls == [True]


def test_a_replayed_input_that_hits_a_known_candidate_is_excluded():
    # minmea run-1 (2026-11-14): the shared corpus seed '$GPVTG,.0000000000' trips the already
    # confirmed minmea_scan overflow in every guardrail of module minmea, including an architect's
    # whole-module one, so no contract of the module could pass the dynamic oracle.
    log = """workspace/work/minmea.c: In function 'minmea_scan'
workspace/work/minmea.c:186: Error: Assertion failed:
\tThe failing predicate is:
\trte/signed_overflow:
\t\tscale * 10 <= 2147483647.
"""
    fp = R._failure_fingerprint(R.parse_eacsl_failure(log))
    assert fp
    why = R.crash_matches_known_candidate(log, {fp})
    assert why and fp in why and "minmea_scan" in why
    assert R.crash_matches_known_candidate(log, set()) is None
    assert R.crash_matches_known_candidate(log, {"minmea.c#other::signed_overflow::deadbeef00"}) is None
    # A contract assertion is not an RTE assertion, but a known fingerprint still identifies a
    # ledgered defect, so the exclusion is about the defect, not the alarm kind.
    assert R.crash_matches_known_candidate("no failure here", {fp}) is None


def test_known_candidate_fingerprints_reads_candidates_and_findings(tmp_path: Path):
    (tmp_path / "candidates.json").write_text(
        json.dumps([{"fingerprint": "a.c#f::signed_overflow::0123456789"}]), encoding="utf-8"
    )
    (tmp_path / "findings.json").write_text(
        json.dumps({"findings": {"b.c#g::signed_overflow::abcdef0123": {"fingerprint": "b.c#g::signed_overflow::abcdef0123"}}}),
        encoding="utf-8",
    )
    assert R.known_candidate_fingerprints(tmp_path) == {
        "a.c#f::signed_overflow::0123456789",
        "b.c#g::signed_overflow::abcdef0123",
    }
    assert R.known_candidate_fingerprints(tmp_path / "missing") == set()
