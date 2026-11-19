"""
Synthetic E-ACSL, ASan, UBSan and LeakSanitizer outputs (S2): each parses to its expected record, and the
fingerprint keeps one defect apart from another. The texts are hand-written under `fixtures/failures/`,
with `src/demo.c` as the source their frames point to. Each parse runs in that directory, so the line text
of a frame can be read.
"""

import json
import re
from pathlib import Path

import pytest

import failure_identity as FI
import ledger as L
from conftest import write_json
from fingerprint import is_valid_fingerprint, make_fingerprint
from test_ledger import load, seed, units_by_id
from validate_artifacts import validate_candidates

pytestmark = pytest.mark.unit

_FAILURE_DIR = Path(__file__).resolve().parent / "fixtures" / "failures"
_EXPECTED_RECORDS: dict = json.loads((_FAILURE_DIR / "expected.json").read_text(encoding="utf-8"))
_FIXTURE_NAMES = sorted(_EXPECTED_RECORDS)
_RECORD_FIELDS = ("file", "line", "function", "kind", "alarm_kind", "predicate")


def _text(name: str) -> str:
    return (_FAILURE_DIR / f"{name}.txt").read_text(encoding="utf-8")


def _parse_in_fixtures(monkeypatch, name: str) -> dict:
    monkeypatch.chdir(_FAILURE_DIR)
    failure = FI.parse_runtime_failure(_text(name))
    assert failure is not None, name
    return failure


def _fingerprint_in_fixtures(monkeypatch, name: str) -> str:
    fp = FI.failure_fingerprint(_parse_in_fixtures(monkeypatch, name))
    assert fp is not None, name
    return fp


@pytest.mark.parametrize("name", _FIXTURE_NAMES)
def test_each_fixture_parses_to_its_expected_record(name, monkeypatch):
    got = _parse_in_fixtures(monkeypatch, name)
    want = _EXPECTED_RECORDS[name]
    assert want["synthetic"] is True
    for field in _RECORD_FIELDS:
        assert got[field] == want[field], field


def test_every_fixture_text_has_an_expected_record():
    texts = sorted(p.stem for p in _FAILURE_DIR.glob("*.txt"))
    assert texts == _FIXTURE_NAMES


def test_two_overflows_in_one_function_have_two_fingerprints(monkeypatch):
    a = _fingerprint_in_fixtures(monkeypatch, "asan_overflow_line_a")
    b = _fingerprint_in_fixtures(monkeypatch, "asan_overflow_line_b")
    assert a != b
    assert is_valid_fingerprint(a) and is_valid_fingerprint(b)


def test_inserting_lines_above_keeps_the_fingerprint(tmp_path, monkeypatch):
    before = _fingerprint_in_fixtures(monkeypatch, "asan_heap_overflow")
    src = (_FAILURE_DIR / "src" / "demo.c").read_text(encoding="utf-8")
    (tmp_path / "src").mkdir()
    with open(tmp_path / "src" / "demo.c", "w", encoding="utf-8", newline="\n") as fh:
        fh.write("/* added */\n/* added */\n/* added */\n" + src)
    text = _text("asan_heap_overflow")
    shifted = re.sub(r"src/demo\.c:(\d+)", lambda m: f"src/demo.c:{int(m.group(1)) + 3}", text)
    assert shifted != text
    monkeypatch.chdir(tmp_path)
    failure = FI.parse_runtime_failure(shifted)
    assert failure is not None
    assert failure["line"] == _EXPECTED_RECORDS["asan_heap_overflow"]["line"] + 3
    assert FI.failure_fingerprint(failure) == before


def test_an_unreadable_source_gives_the_predicate_without_a_line_hash(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # no src/demo.c here
    failure = FI.parse_runtime_failure(_text("asan_heap_overflow"))
    assert failure is not None
    assert "[line " not in failure["predicate"]
    with_hash = _EXPECTED_RECORDS["asan_heap_overflow"]["predicate"]
    assert failure["predicate"] == re.sub(r" \[line [0-9a-f]{10}\]$", "", with_hash)


def test_an_interceptor_frame_names_the_interceptor_and_its_caller(monkeypatch):
    failure = _parse_in_fixtures(monkeypatch, "asan_memcpy_overlap")
    assert failure["function"] == "copy_block"
    assert " in memcpy from copy_block [line " in failure["predicate"]


# The frames of a libc call as framac-analysis:latest prints them (Debian clang 19.1.7, static ASan runtime):
# no source location, the name without `__interceptor_`, sometimes behind the runtime's own helpers.
_BARE = "(/tmp/prog+0xcdefa) (BuildId: b66b8b41b662fb3faecaf12d07fe035f5676f003)"
_DOUBLE_FREE = "==13==ERROR: AddressSanitizer: attempting double-free on 0x503000000040 in thread T0:\n"
_OVERFLOW = "==63==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000018 at pc 0x1 bp 0x2 sp 0x3\n"
_READ_OP = "READ of size 9 at 0x502000000018 thread T0\n"


def _stack(*frames: str) -> str:
    return "".join(f"    #{i} 0x5ae09b724efa in {frame}\n" for i, frame in enumerate(frames))


@pytest.mark.parametrize("call", ["free", "realloc", "strlen", "strcpy", "atoi", "read", "fwrite", "getcwd"])
def test_a_bare_libc_frame_is_not_the_site_of_the_failure(call, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    text = _OVERFLOW + _READ_OP + _stack(f"{call} {_BARE}", "parse_name src/name.c:33:51", "main src/main.c:71:28")
    failure = FI.parse_runtime_failure(text)
    assert failure is not None
    assert (failure["file"], failure["line"], failure["function"]) == ("src/name.c", 33, "parse_name")
    assert f" in {call} from parse_name" in failure["predicate"]


@pytest.mark.parametrize("frame", ["__interceptor_free", "___interceptor_free"])
def test_the_prefixed_spellings_of_an_interceptor_name_the_same_call(frame, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    failure = FI.parse_runtime_failure(_DOUBLE_FREE + _stack(frame, "release src/a.c:10:5"))
    assert failure is not None
    assert failure["function"] == "release" and " in free from release" in failure["predicate"]


@pytest.mark.parametrize(
    ("helpers", "call"),
    [
        (["StrstrCheck(void*, char*, char const*, char const*) asan_interceptors.cpp.o", f"strstr {_BARE}"], "strstr"),
        (["StrtolFixAndCheck(void*, char const*, char**, char*, int) asan_interceptors.cpp.o", f"strtol {_BARE}"], "strtol"),
        (
            [
                "printf_common(void*, char const*, __va_list_tag*) asan_interceptors.cpp.o",
                f"vsnprintf {_BARE}",
                f"snprintf {_BARE}",
            ],
            "snprintf",
        ),
    ],
)
def test_the_runtime_helpers_behind_a_libc_call_name_the_call_the_target_made(helpers, call, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    failure = FI.parse_runtime_failure(_OVERFLOW + _stack(*helpers, "fill src/name.c:56:49"))
    assert failure is not None
    assert (failure["file"], failure["line"], failure["function"]) == ("src/name.c", 56, "fill")
    assert f" in {call} from fill" in failure["predicate"]


def test_two_double_frees_at_two_sites_have_two_fingerprints(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    one = FI.parse_runtime_failure(_DOUBLE_FREE + _stack(f"free {_BARE}", "release_a src/a.c:10:5"))
    two = FI.parse_runtime_failure(_DOUBLE_FREE + _stack(f"free {_BARE}", "release_b src/b.c:20:5"))
    assert FI.failure_fingerprint(one) != FI.failure_fingerprint(two)
    fingerprint = FI.failure_fingerprint(one)
    assert fingerprint is not None and fingerprint.startswith("src/a.c#release_a::freeable::")


def test_the_target_s_own_function_named_like_libc_is_the_site(tmp_path, monkeypatch):
    """A source location tells them apart: this `free` is code of the target."""
    monkeypatch.chdir(tmp_path)
    failure = FI.parse_runtime_failure(_OVERFLOW + _stack("free src/pool.c:12:3", "drop src/pool.c:40:5"))
    assert failure is not None
    assert (failure["file"], failure["line"], failure["function"]) == ("src/pool.c", 12, "free")
    assert " from " not in failure["predicate"]


def test_a_crash_stack_without_a_target_frame_does_not_borrow_one_from_the_free_stack(tmp_path, monkeypatch):
    """The harness made the second call: the target function on the `freed by` stack did nothing wrong."""
    monkeypatch.chdir(tmp_path)
    crash = _stack(
        f"free {_BARE}",
        "LLVMFuzzerTestOneInput /framac-run/workspace/harnesses/harness_mod.c:14:5",
        "fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/tmp/prog+0x4e4ba)",
    )
    freed = _stack(f"free {_BARE}", "target_release src/a.c:6:40")
    failure = FI.parse_runtime_failure(_DOUBLE_FREE + crash + "\nfreed by thread T0 here:\n" + freed)
    assert failure is not None
    assert failure["function"] != "target_release" and failure["file"] != "src/a.c"


def test_the_frame_of_a_shared_gcc_runtime_is_not_the_site(tmp_path, monkeypatch):
    """gcc's libasan has debug information, so its `free` carries a source location of the runtime."""
    monkeypatch.chdir(tmp_path)
    runtime = "free ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:52"
    failure = FI.parse_runtime_failure(_DOUBLE_FREE + _stack(runtime, "site src/a.c:23"))
    assert failure is not None
    assert (failure["file"], failure["line"], failure["function"]) == ("src/a.c", 23, "site")
    assert " in free from site" in failure["predicate"]


def test_asan_s_allocation_cap_stays_a_tool_limit_now_that_it_has_a_location(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    text = (
        "==17==ERROR: AddressSanitizer: requested allocation size 0x7fffffffffff (0x800000001000 after adjustments "
        "for alignment, red zones etc.) exceeds maximum supported size of 0x10000000000 (thread T0)\n"
    ) + _stack(f"malloc {_BARE}", "read_bytes src/reader.c:527:15")
    failure = FI.parse_runtime_failure(text)
    assert failure is not None
    assert (failure["file"], failure["line"]) == ("src/reader.c", 527)
    assert FI.is_sanitizer_allocation_cap(failure) and FI.needs_attribution(failure)


def test_a_leak_allocated_inside_a_libc_call_is_attributed_to_its_caller(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    text = (
        "==47==ERROR: LeakSanitizer: detected memory leaks\n\n"
        "Direct leak of 4097 byte(s) in 1 object(s) allocated from:\n"
        + _stack(f"malloc {_BARE}", f"realpath {_BARE}", "resolve src/path.c:22:47", "main src/main.c:33:9")
    )
    failure = FI.parse_runtime_failure(text)
    assert failure is not None
    assert (failure["file"], failure["line"], failure["function"]) == ("src/path.c", 22, "resolve")


def test_a_fixture_parsed_twice_gives_one_fingerprint_and_other_addresses_do_not_change_it(monkeypatch):
    once = _fingerprint_in_fixtures(monkeypatch, "asan_heap_overflow")
    assert _fingerprint_in_fixtures(monkeypatch, "asan_heap_overflow") == once
    text = _text("asan_heap_overflow")
    other = re.sub(r"0x[0-9a-f]+", "0x7f0000001234", text).replace("READ of size 4", "READ of size 8")
    assert other != text
    monkeypatch.chdir(_FAILURE_DIR)
    assert FI.failure_fingerprint(FI.parse_runtime_failure(other)) == once


def test_direct_and_indirect_leaks_are_two_kinds_with_alarm_kind_memory_leak(monkeypatch):
    direct = _parse_in_fixtures(monkeypatch, "lsan_direct")
    indirect = _parse_in_fixtures(monkeypatch, "lsan_indirect")
    assert direct["kind"] == "lsan_direct_leak"
    assert indirect["kind"] == "lsan_indirect_leak"
    assert direct["alarm_kind"] == indirect["alarm_kind"] == "memory_leak"
    assert direct["is_rte"] is False


def test_a_leak_is_attributed_to_the_first_target_frame(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    text = (
        "==9==ERROR: LeakSanitizer: detected memory leaks\n\n"
        "Direct leak of 32 byte(s) in 1 object(s) allocated from:\n"
        "    #0 0x1 in __interceptor_calloc\n"
        "    #1 0x2 in harness_entry harness_demo.c:12:5\n"
        "    #2 0x3 in target_fn src/demo.c:14:3\n"
        "    #3 0x4 in main\n"
    )
    failure = FI.parse_runtime_failure(text)
    assert failure is not None
    assert (failure["file"], failure["line"], failure["function"]) == ("src/demo.c", 14, "target_fn")


def test_ingest_fuzz_links_no_unit_for_a_leak(run_dir):
    seed(run_dir)
    crash = run_dir / "workspace/crashes/snmp/leak-abc"
    crash.parent.mkdir(parents=True, exist_ok=True)
    crash.write_bytes(b"\x30\x84")
    predicate = "memory_leak: LeakSanitizer: direct leak allocated in ber_decode_len"
    fp = make_fingerprint("src/snmp/ber.c", "ber_decode_len", "memory_leak", predicate)
    failure = {
        "file": "src/snmp/ber.c",
        "line": 42,
        "function": "ber_decode_len",
        "kind": "lsan_direct_leak",
        "alarm_kind": "memory_leak",
        "is_rte": False,
        "predicate": predicate,
    }
    report = {
        "mode": "campaign",
        "module": "snmp",
        "status": "crash_found",
        "artifacts": [
            {
                "artifact": str(crash),
                "kind": "leak",
                "sha256": "x",
                "size_bytes": 2,
                "reproducible": True,
                "fingerprint": fp,
                "failure": failure,
            }
        ],
    }
    write_json(run_dir / "workspace/reports/fuzz/snmp.json", report)
    L.cmd_ingest_fuzz([run_dir / "workspace/reports/fuzz/snmp.json"])
    cand = {c["fingerprint"]: c for c in load(run_dir / "candidates.json")}[fp]
    assert cand["property"]["kind"] == "memory_leak"
    assert cand["linked_units"] == []
    assert any("a memory leak has no obligation class: no unit is linked (D5)" in n for n in cand["notes"])
    # The unit the leak's function would link without D5 stays as it was.
    assert units_by_id(run_dir)["src/snmp/ber.c#ber_decode_len::rte"]["status"] == "planned"
    assert list(validate_candidates(load(run_dir / "candidates.json"))) == []
