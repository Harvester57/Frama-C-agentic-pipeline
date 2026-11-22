"""Unit tests for multi-segment trace harvesting in scripts/seed_harvest.py (W1-B)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import api_harness as ah
import seed_harvest as sh
import validate_artifacts as va

pytestmark = pytest.mark.unit


def _run_collect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, files: dict[str, list[str]]
) -> tuple[dict, list[dict]]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(tmp_path)
    out_dir = tmp_path / "calls"
    out_dir.mkdir(exist_ok=True)
    for name, lines in files.items():
        (out_dir / name).write_text("\n".join(lines) + ("\n" if lines else ""), encoding="ascii", newline="\n")
    report: dict[str, Any] = {"status": "error"}
    sh._collect(report, out_dir, [], tmp_path / "tree", 0.0)
    traces_path = tmp_path / "workspace" / "seed_records" / "traces.jsonl"
    assert list(va.validate_traces(traces_path)) == []
    raw_records = [json.loads(line) for line in traces_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return report, raw_records


def _sigs(records: list[dict]) -> list[tuple[str, ...]]:
    return [tuple(c["fn"] for c in rec["calls"]) for rec in records]


def test_monolithic_single_pid_1000_calls_preserves_late_distinct_segments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A 1,000+ call single-PID runner (like ./qcbortest) keeps late encoder, map-sort, and mempool sequences."""
    lines: list[str] = []

    # 120 repeated 4-call early decoder tests (480 calls) reusing the same stack context address.
    for i in range(120):
        payload = f"a161{(i % 256):02x}01"
        lines.extend(
            [
                f"QCBORDecode_Init 1n0={payload} 2i=00000000 0x=7ffd1000",
                "QCBORDecode_GetNext 0x=7ffd1000 1x=7ffd1080",
                "QCBORDecode_GetInt64 0x=7ffd1000 1x=7ffd1090",
                "QCBORDecode_Finish 0x=7ffd1000",
            ]
        )
        if i % 30 == 0:
            # Non-context utility calls (no pointer arguments at all).
            lines.append(f"UsefulBuf_Compare 0n0={payload} 1n0={payload}")

    assert len(lines) > 400

    # Late distinct encoder sequence after call 400.
    lines.extend(
        [
            "QCBOREncode_Init 1n0=00000000 0x=7ffd2000",
            "QCBOREncode_AddInt64 1i=2a00000000000000 0x=7ffd2000",
            "QCBOREncode_Finish 0x=7ffd2000 1x=7ffd2080",
        ]
    )

    # Late distinct map-sort sequence reusing the encoder address (CloseAndSortMap must not split before Finish).
    lines.extend(
        [
            "QCBOREncode_Init 1n0=00000000 0x=7ffd2000",
            "QCBOREncode_OpenMap 0x=7ffd2000",
            "QCBOREncode_AddInt64 1i=0700000000000000 0x=7ffd2000",
            "QCBOREncode_CloseAndSortMap 0x=7ffd2000",
            "QCBOREncode_Finish 0x=7ffd2000 1x=7ffd2080",
        ]
    )

    # Late distinct mempool sequence reusing the decoder address.
    lines.extend(
        [
            "QCBORDecode_Init 1n0=5f41614162ff 2i=00000000 0x=7ffd1000",
            "QCBORDecode_SetMemPool 1n0=0000000000000000 2i=00000000 0x=7ffd1000",
            "QCBORDecode_GetNext 0x=7ffd1000 1x=7ffd1080",
            "QCBORDecode_Finish 0x=7ffd1000",
        ]
    )

    # Pad with more duplicate early decoder tests well past 1,000 total calls.
    for i in range(140):
        payload = f"a161{(i % 256):02x}02"
        lines.extend(
            [
                f"QCBORDecode_Init 1n0={payload} 2i=00000000 0x=7ffd1000",
                "QCBORDecode_GetNext 0x=7ffd1000 1x=7ffd1080",
                "QCBORDecode_GetInt64 0x=7ffd1000 1x=7ffd1090",
                "QCBORDecode_Finish 0x=7ffd1000",
            ]
        )

    assert len(lines) >= 1000

    report, records = _run_collect(tmp_path, monkeypatch, {"calls-42.txt": lines})
    sigs = _sigs(records)

    early_sig = ("QCBORDecode_Init", "QCBORDecode_GetNext", "QCBORDecode_GetInt64", "QCBORDecode_Finish")
    encoder_sig = ("QCBOREncode_Init", "QCBOREncode_AddInt64", "QCBOREncode_Finish")
    map_sort_sig = (
        "QCBOREncode_Init",
        "QCBOREncode_OpenMap",
        "QCBOREncode_AddInt64",
        "QCBOREncode_CloseAndSortMap",
        "QCBOREncode_Finish",
    )
    mempool_sig = ("QCBORDecode_Init", "QCBORDecode_SetMemPool", "QCBORDecode_GetNext", "QCBORDecode_Finish")

    # All late distinct sequences are captured; duplicate early tests deduplicate to a single entry.
    assert sigs.count(early_sig) == 1
    assert encoder_sig in sigs
    assert map_sort_sig in sigs
    assert mempool_sig in sigs
    assert any("UsefulBuf_Compare" in s for s in sigs)

    # Schema, PID, and size bounds hold for every trace segment.
    assert report["traces"] == len(records) <= sh.MAX_TRACES
    assert report["calls"]["recorded"] == len(lines)
    for rec in records:
        assert set(rec) == {"pid", "calls"}
        assert rec["pid"] == "42"
        assert 2 <= len(rec["calls"]) <= sh.MAX_TRACE_CALLS
        for call in rec["calls"]:
            assert set(call) == {"fn", "args", "addrs", "sizes"}

    # api_harness consumes the harvested segments directly without modification.
    loaded = ah.load_traces(tmp_path / "workspace" / "seed_records" / "traces.jsonl")
    assert len(loaded) == len(records)
    ctx_segs = ah._context_segments(loaded, {"QCBORDecode_Init", "QCBOREncode_Init"})
    ctx_fn_lists = [[c["fn"] for c in seg] for _init, seg in ctx_segs]
    assert ["QCBORDecode_SetMemPool", "QCBORDecode_GetNext", "QCBORDecode_Finish"] in ctx_fn_lists
    assert [
        "QCBOREncode_OpenMap",
        "QCBOREncode_AddInt64",
        "QCBOREncode_CloseAndSortMap",
        "QCBOREncode_Finish",
    ] in ctx_fn_lists


def test_destructor_reuse_splits_without_initializer_and_keeps_two_step_dtors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lines = [
        # Non-init open/destroy pairs reusing address a000.
        "db_open 1s=61 0x=a000",
        "db_query 1s=71 0x=a000",
        "db_destroy 0x=a000",
        "db_open 1s=62 0x=a000",
        "db_insert 1s=69 0x=a000",
        "db_destroy 0x=a000",
        # Two-step close + free stays in one segment; subsequent call starts a fresh segment.
        "modbus_new_tcp 1s=31 0x=b000",
        "modbus_connect 0x=b000",
        "modbus_close 0x=b000",
        "modbus_free 0x=b000",
        "modbus_connect 0x=b000",
        "modbus_receive 0x=b000",
        # Container closer (mpack_finish_map) does not split before mpack_writer_destroy.
        "mpack_writer_init 0x=c000",
        "mpack_start_map 0x=c000",
        "mpack_finish_map 0x=c000",
        "mpack_writer_destroy 0x=c000",
    ]
    _report, records = _run_collect(tmp_path, monkeypatch, {"calls-5.txt": lines})
    sigs = _sigs(records)

    assert ("db_open", "db_query", "db_destroy") in sigs
    assert ("db_open", "db_insert", "db_destroy") in sigs
    assert ("modbus_new_tcp", "modbus_connect", "modbus_close", "modbus_free") in sigs
    assert ("modbus_connect", "modbus_receive") in sigs
    assert ("mpack_writer_init", "mpack_start_map", "mpack_finish_map", "mpack_writer_destroy") in sigs


def test_interleaved_contexts_separate_cleanly(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    lines = [
        "QCBOREncode_Init 0x=e000",
        "QCBORDecode_Init 0x=d000",
        "QCBOREncode_AddInt64 1i=01 0x=e000",
        "QCBORDecode_GetNext 0x=d000",
        "QCBOREncode_Finish 0x=e000",
        "QCBORDecode_Finish 0x=d000",
    ]
    _report, records = _run_collect(tmp_path, monkeypatch, {"calls-3.txt": lines})
    assert _sigs(records) == [
        ("QCBOREncode_Init", "QCBOREncode_AddInt64", "QCBOREncode_Finish"),
        ("QCBORDecode_Init", "QCBORDecode_GetNext", "QCBORDecode_Finish"),
    ]


def test_dedup_keeps_richest_and_first_on_tie(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # PID 10: sparse segment (no payload bytes) followed by a richer segment with the same signature.
    lines_10 = [
        "ctx_init 0x=1000",
        "ctx_parse 0x=1000",
        "ctx_free 0x=1000",
        "ctx_init 1b=deadbeefcafebabe 2i=01000000 0x=1000",
        "ctx_parse 1i=02000000 0x=1000",
        "ctx_free 0x=1000",
    ]
    # PID 11: equal richness to PID 10's richer segment at a different address (must not overwrite first).
    lines_11 = [
        "ctx_init 1b=0011223344556677 2i=03000000 0x=2000",
        "ctx_parse 1i=04000000 0x=2000",
        "ctx_free 0x=2000",
    ]
    report, records = _run_collect(tmp_path, monkeypatch, {"calls-10.txt": lines_10, "calls-11.txt": lines_11})
    assert report["traces"] == 1 and len(records) == 1
    assert records[0]["pid"] == "10"
    assert records[0]["calls"][0]["args"]["1"] == [["b", 0, "deadbeefcafebabe"]]
    assert records[0]["calls"][0]["addrs"]["0"] == "1000"


def test_per_segment_and_total_caps_remain_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sh, "MAX_TRACE_CALLS", 16)
    monkeypatch.setattr(sh, "MAX_TRACES", 4)

    lines: list[str] = []
    # One oversized 40-call context segment: capped at 16, yet Finish at call 40 still enables clean split.
    lines.append("enc_init 1i=01 0x=f000")
    lines.extend(f"enc_add 1i={i:02x} 0x=f000" for i in range(38))
    lines.append("enc_finish 0x=f000")

    # Distinct follow-up segments exceeding MAX_TRACES=4.
    for k in range(8):
        lines.extend(
            [
                f"enc_init 1i={k:02x} 0x=f000",
                f"enc_op_{k} 0x=f000",
                "enc_finish 0x=f000",
            ]
        )

    # Richer instance of an already-kept signature after the cap is full upgrades in place without exceeding cap.
    lines.extend(
        [
            "enc_init 1i=ff 2b=0102030405060708 0x=f000",
            "enc_op_0 1b=aabbccdd 0x=f000",
            "enc_finish 0x=f000",
        ]
    )

    report, records = _run_collect(tmp_path, monkeypatch, {"calls-9.txt": lines})
    assert report["traces"] == 4 and len(records) == 4
    assert all(2 <= len(rec["calls"]) <= 16 for rec in records)
    # Oversized segment kept its initializer at index 0 and capped at 16 calls.
    assert len(records[0]["calls"]) == 16
    assert records[0]["calls"][0]["fn"] == "enc_init"
    # Existing signature enc_op_0 upgraded to the richer instance even after cap was reached.
    op0_rec = next(rec for rec in records if rec["calls"][1]["fn"] == "enc_op_0")
    assert op0_rec["calls"][0]["args"]["2"] == [["b", 0, "0102030405060708"]]


def test_non_context_sliding_window_captures_late_and_boundary_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sh, "NON_CONTEXT_WINDOW_CALLS", 8)
    lines: list[str] = []
    # Many identical early non-context calls deduplicate instead of filling MAX_TRACES.
    lines.extend("util_cmp 0i=01 1i=02" for _ in range(31))
    # Two late distinct calls straddling the 8-call window boundary (indices 31 and 32).
    lines.append("util_find 0s=6162")
    lines.append("util_skip 0i=04")
    lines.extend("util_cmp 0i=01 1i=02" for _ in range(12))

    report, records = _run_collect(tmp_path, monkeypatch, {"calls-12.txt": lines})
    assert report["traces"] == len(records) <= sh.MAX_TRACES
    assert all(2 <= len(rec["calls"]) <= 8 for rec in records)
    # Because of the overlapping sliding window, util_find and util_skip appear together in one segment.
    assert any("util_find" in s and "util_skip" in s for s in _sigs(records))

    # A single isolated non-context call produces no trace (minItems: 2 invariant).
    report_one, records_one = _run_collect(tmp_path / "one", monkeypatch, {"calls-13.txt": ["util_cmp 0i=01"]})
    assert report_one["traces"] == 0 and records_one == []


def test_cross_param_producer_consumer_chains_preserved(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Links via primary address (0x -> 3x) and via secondary address (1x -> 3x).
    lines = [
        "keypair 0a=0000 1a=0000 0x=100 1x=200",
        "box 0a=00 1b=6869 3a=0000 0x=300 1x=400 3x=100",
        "gen_sk 0a=0000 1a=0000 0x=500 1x=600",
        "sign 0a=00 1b=6162 3a=0000 0x=700 1x=800 3x=600",
    ]
    _report, records = _run_collect(tmp_path, monkeypatch, {"calls-20.txt": lines})
    sigs = _sigs(records)
    assert ("keypair", "box") in sigs
    assert ("gen_sk", "sign") in sigs
    for rec in records:
        assert ah.chains(rec["calls"]) == [[0, 1]]


def test_active_context_eviction_bounds_open_contexts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sh, "MAX_ACTIVE_CONTEXTS", 4)
    lines: list[str] = []
    # Open 6 distinct 2-call contexts sequentially so eviction triggers cleanly.
    for i in range(6):
        addr = f"{0x1000 + i * 0x100:x}"
        lines.append(f"ctx_init 1i={i:02x} 0x={addr}")
        lines.append(f"ctx_step_{i} 0x={addr}")
    # Add 6 distinct 1-call orphans to exercise orphan eviction too.
    for i in range(6):
        addr = f"{0x9000 + i * 0x100:x}"
        lines.append(f"solo_{i} 0x={addr}")

    report, records = _run_collect(tmp_path, monkeypatch, {"calls-21.txt": lines})
    sigs = _sigs(records)
    assert report["traces"] == len(records)
    for i in range(6):
        assert ("ctx_init", f"ctx_step_{i}") in sigs
    flat_fns = {fn for sig in sigs for fn in sig}
    for i in range(6):
        assert f"solo_{i}" in flat_fns
