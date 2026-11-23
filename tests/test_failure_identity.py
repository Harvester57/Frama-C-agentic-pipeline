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


def test_parse_sanitizer_failure_recognizes_ubsan_segv_and_deadly_signals(tmp_path, monkeypatch) -> None:
    """
    libmnl / mpack E-ACSL builds emit Clang UBSan standalone deadly-signal reports
    (`UndefinedBehaviorSanitizer:DEADLYSIGNAL` / `ERROR: UndefinedBehaviorSanitizer: SEGV ...`)
    when ASan is absent. parse_sanitizer_failure and parse_runtime_failure must parse them
    consistently with ASan SEGV, extracting site, access direction, kind, alarm_kind, message,
    and an address-independent fingerprint.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src" / "attr.c"
    src.parent.mkdir(parents=True)
    lines = ["int dummy;\n"] * 41 + ["    return attr->nla_len;\n"]
    src.write_text("".join(lines), encoding="utf-8")

    ubsan_segv_read = (
        "INFO: Running with entropic power schedule (0xFF, 100).\n"
        "UndefinedBehaviorSanitizer:DEADLYSIGNAL\n"
        "==7==ERROR: UndefinedBehaviorSanitizer: SEGV on unknown address 0x76a8a3763c30 (pc 0x5fd4a2ce31af T7)\n"
        "==7==The signal is caused by a READ memory access.\n"
        "    #0 0x5fd4a2ce31af in mnl_attr_ok src/attr.c:42:12\n"
        "    #1 0x5fd4a2ce3c04 in mnl_attr_parse src/attr.c:1139:13\n"
        "    #2 0x5fd4a2ce9a55 in LLVMFuzzerTestOneInput workspace/harnesses/harness_attr.c:88:3\n"
        "    #3 0x5fd4a2c9b8ea in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/w/guard.bin+0x368ea)\n"
        "UndefinedBehaviorSanitizer can not provide additional info.\n"
        "SUMMARY: UndefinedBehaviorSanitizer: SEGV src/attr.c:42:12 in mnl_attr_ok\n"
        "==7==ABORTING\n"
    )
    f = failure_identity.parse_sanitizer_failure(ubsan_segv_read)
    assert f is not None
    assert f["file"] == "src/attr.c"
    assert f["line"] == 42
    assert f["function"] == "mnl_attr_ok"
    assert f["kind"] == "ubsan_segv"
    assert f["alarm_kind"] == "mem_access"
    assert f["is_rte"] is True
    assert f["predicate"].startswith("rte: mem_access: UndefinedBehaviorSanitizer: SEGV (READ) [line ")
    assert "SEGV on unknown address 0x76a8a3763c30" in f["message"]
    assert not failure_identity.needs_attribution(f)
    assert failure_identity.parse_runtime_failure(ubsan_segv_read) == f

    # A different faulting address at the same site produces the exact same fingerprint.
    other_addr = ubsan_segv_read.replace("0x76a8a3763c30", "0x000000000000").replace("0x5fd4a2ce31af", "0x555555551111")
    f_other = failure_identity.parse_sanitizer_failure(other_addr)
    assert f_other is not None
    assert failure_identity.failure_fingerprint(f) == failure_identity.failure_fingerprint(f_other)

    # WRITE memory access is distinguished in the predicate.
    ubsan_segv_write = ubsan_segv_read.replace("READ memory access", "WRITE memory access")
    f_write = failure_identity.parse_sanitizer_failure(ubsan_segv_write)
    assert f_write is not None
    assert "SEGV (WRITE)" in f_write["predicate"]

    # An E-ACSL `.instrumented.c` stack frame is parsed cleanly AND flagged for sanitizer attribution.
    inst_path = "/framac-run/workspace/harnesses/fuzz_attr.instrumented.c"
    inst_segv = ubsan_segv_read.replace("src/attr.c:42:12", f"{inst_path}:874:30")
    f_inst = failure_identity.parse_sanitizer_failure(inst_segv)
    assert f_inst is not None
    assert (f_inst["file"], f_inst["line"], f_inst["function"]) == (inst_path, 874, "mnl_attr_ok")
    assert f_inst["kind"] == "ubsan_segv"
    assert failure_identity.needs_attribution(f_inst)

    # Bare libc / runtime frames are skipped in favor of the target caller, matching ASan attribution.
    libc_segv = (
        "UndefinedBehaviorSanitizer:DEADLYSIGNAL\n"
        "==19==ERROR: UndefinedBehaviorSanitizer: SEGV on unknown address 0x000000000000 (pc 0x7f T19)\n"
        "==19==The signal is caused by a READ memory access.\n"
        "    #0 0x7ffff7a00111 in strlen (/lib/x86_64-linux-gnu/libc.so.6+0x1234)\n"
        "    #1 0x55555558a222 in mnl_attr_ok src/attr.c:42:12\n"
        "    #2 0x55555558a333 in LLVMFuzzerTestOneInput workspace/harnesses/harness_attr.c:10:3\n"
        "SUMMARY: UndefinedBehaviorSanitizer: SEGV (/lib/x86_64-linux-gnu/libc.so.6+0x1234) in strlen\n"
    )
    f_libc = failure_identity.parse_sanitizer_failure(libc_segv)
    assert f_libc is not None
    assert (f_libc["file"], f_libc["line"], f_libc["function"]) == ("src/attr.c", 42, "mnl_attr_ok")
    assert " in strlen from mnl_attr_ok" in f_libc["predicate"]

    # UBSan FPE maps to division_by_zero.
    ubsan_fpe = (
        "UndefinedBehaviorSanitizer:DEADLYSIGNAL\n"
        "==21==ERROR: UndefinedBehaviorSanitizer: FPE on unknown address 0x555555581234 (pc 0x555555581234 T21)\n"
        "    #0 0x555555581234 in div_mod src/attr.c:42:10\n"
    )
    f_fpe = failure_identity.parse_sanitizer_failure(ubsan_fpe)
    assert f_fpe is not None
    assert f_fpe["kind"] == "ubsan_fpe" and f_fpe["alarm_kind"] == "division_by_zero"

    # Stackless report falls back to SUMMARY location.
    stackless = (
        "==31==ERROR: UndefinedBehaviorSanitizer: SEGV on unknown address 0x0 (pc 0x1 T31)\n"
        "SUMMARY: UndefinedBehaviorSanitizer: SEGV src/attr.c:42:12 in mnl_attr_ok\n"
    )
    f_sum = failure_identity.parse_sanitizer_failure(stackless)
    assert f_sum is not None
    assert (f_sum["file"], f_sum["line"], f_sum["function"]) == ("src/attr.c", 42, "mnl_attr_ok")
    assert f_sum["kind"] == "ubsan_segv"


def test_parse_eacsl_allocator_observation_aborts() -> None:
    """E-ACSL observation-model `private_abort` messages in free/realloc parse as `freeable` failures."""
    free_stderr = (
        "Not a start of block (0x12b-d190) in free\n"
        "==42== ERROR: libFuzzer: deadly signal\n"
        "    #0 0x555555510000 in __sanitizer_print_stack_trace (/w/fuzz_m+0x10000)\n"
        "    #1 0x555555520000 in private_abort_fail (/w/fuzz_m+0x20000)\n"
        "    #2 0x555555530000 in __e_acsl_free (/w/fuzz_m+0x30000)\n"
        "    #3 0x555555540000 in __gen_e_acsl_target_free /w/src/mem.c:88:5\n"
        "    #4 0x555555550000 in LLVMFuzzerTestOneInput /w/workspace/harnesses/harness_m.c:40:3\n"
    )
    f_free = failure_identity.parse_eacsl_failure(free_stderr)
    assert f_free is not None
    assert f_free["kind"] == "eacsl_libc_error"
    assert f_free["alarm_kind"] == "freeable"
    assert f_free["function"] == "target_free"
    assert f_free["predicate"] == "free: not a start of block"
    assert f_free["is_rte"] is True
    assert not f_free.get("harness_self_fault")
    assert failure_identity.parse_runtime_failure(free_stderr) == f_free

    # Different block address in the message hashes to the exact same fingerprint.
    free_other = free_stderr.replace("0x12b-d190", "0x7fff-0040")
    f_free_other = failure_identity.parse_eacsl_failure(free_other)
    assert f_free_other is not None
    assert failure_identity.failure_fingerprint(f_free) == failure_identity.failure_fingerprint(f_free_other)

    # realloc variant and NULL-pointer free variant.
    realloc_stderr = free_stderr.replace("in free", "in realloc")
    f_realloc = failure_identity.parse_eacsl_failure(realloc_stderr)
    assert f_realloc is not None
    assert f_realloc["alarm_kind"] == "freeable"
    assert f_realloc["predicate"] == "realloc: not a start of block"

    null_free_stderr = free_stderr.replace("Not a start of block (0x12b-d190) in free", "NULL pointer in free")
    f_null = failure_identity.parse_eacsl_failure(null_free_stderr)
    assert f_null is not None
    assert f_null["alarm_kind"] == "freeable"
    assert f_null["predicate"] == "free: NULL pointer"

    # When called directly from the harness with no target frame, flag `harness_self_fault`.
    harness_free_stderr = (
        "Not a start of block (0x12b-d190) in free\n"
        "==43== ERROR: libFuzzer: deadly signal\n"
        "    #0 0x555555520000 in private_abort_fail (/w/fuzz_m+0x20000)\n"
        "    #1 0x555555530000 in __e_acsl_free (/w/fuzz_m+0x30000)\n"
        "    #2 0x555555550000 in LLVMFuzzerTestOneInput /w/workspace/harnesses/harness_m.c:40:3\n"
    )
    f_harness = failure_identity.parse_eacsl_failure(harness_free_stderr)
    assert f_harness is not None
    assert f_harness["function"] == "LLVMFuzzerTestOneInput"
    assert f_harness.get("harness_self_fault") is True
