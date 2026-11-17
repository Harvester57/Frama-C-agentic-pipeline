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
