"""
Global-state setup prefixes for trace-derived `--api` sequence cases (CryptoLib `cl-p0-api-seeds-20261123`).

Libraries that keep their configuration and runtime state in global variables (such as CryptoLib's
`Crypto_Config_CryptoLib > Crypto_Config_TC > Crypto_Config_Add_TC_Gvcid_Managed_Parameters >
Crypto_Init > Crypto_TC_ProcessSecurity > Crypto_Shutdown`) pass no shared pointer between their
setup calls and their target entry points. `api_harness.py` now derives backward-closed global-state
setup prefixes (and matching 0-arg teardowns) from recorded traces + the Phase 0 model's
`writes.globals` / `global_refs`, binding every setup parameter to its exact concrete recorded value
without consuming fuzz bytes.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

import api_harness as ah
import seed_harvest as sh
from conftest import ANALYSIS_IMAGE, ROOT, require_docker_images


def _fn(
    file: str,
    name: str,
    sig: str,
    formals: list[dict[str, Any]],
    *,
    writes_globals: list[str] | None = None,
    global_refs: list[str] | None = None,
    callees: list[str] | None = None,
) -> tuple[str, dict[str, Any]]:
    fid = f"{file}#{name}"
    return fid, {
        "name": name,
        "file": file,
        "signature": sig,
        "formals": formals,
        "static": False,
        "writes": {"pointer": 0, "params": [], "globals": list(writes_globals or [])},
        "global_refs": list(global_refs or []),
        "call_sites": [{"callee": c, "line": 1, "literals": {}, "initializer": False} for c in (callees or [])],
    }


def _global_lib_fixture() -> tuple[dict[str, Any], dict[str, Any]]:
    """A miniature CryptoLib-shaped global-state library model and DAG."""
    entries = [
        _fn(
            "src/cfg.c",
            "lib_config",
            "int(unsigned char,unsigned char)",
            [{"name": "mode", "kind": "scalar"}, {"name": "flags", "kind": "scalar"}],
            writes_globals=["g_cfg"],
            global_refs=["src/cfg.c#g_cfg"],
        ),
        _fn(
            "src/cfg.c",
            "lib_add_param",
            "int(struct param_s)",
            [{"name": "p", "kind": "struct"}],
            writes_globals=["g_params"],
            global_refs=["src/cfg.c#g_params"],
        ),
        _fn(
            "src/cfg.c",
            "lib_init",
            "int()",
            [],
            writes_globals=["g_cfg", "g_state"],
            global_refs=["src/cfg.c#g_cfg", "src/cfg.c#g_params", "src/cfg.c#g_state"],
        ),
        _fn(
            "src/cfg.c",
            "lib_init_with_cfg",
            "int(struct param_s *)",
            [{"name": "cfg_p", "kind": "pointer"}],
            writes_globals=["g_cfg", "g_state"],
            global_refs=["src/cfg.c#g_cfg", "src/cfg.c#g_state"],
        ),
        _fn(
            "src/cfg.c",
            "lib_init_unit_test",
            "int()",
            [],
            callees=["lib_config", "lib_add_param", "lib_init"],
        ),
        _fn(
            "src/cfg.c",
            "lib_shutdown",
            "int()",
            [],
            writes_globals=["g_cfg", "g_params", "g_state"],
            global_refs=["src/cfg.c#g_cfg", "src/cfg.c#g_params", "src/cfg.c#g_state"],
        ),
        _fn(
            "src/cfg.c",
            "lib_config_file",
            "int(char *)",
            [{"name": "path", "kind": "pointer"}],
            writes_globals=["g_cfg"],
            global_refs=["src/cfg.c#g_cfg"],
        ),
        _fn(
            "src/proc.c",
            "lib_sanity_check",
            "int()",
            [],
            global_refs=["src/cfg.c#g_cfg", "src/cfg.c#g_params", "src/cfg.c#g_state"],
        ),
        _fn(
            "src/proc.c",
            "lib_process",
            "int(const unsigned char *,unsigned long)",
            [{"name": "buf", "kind": "const_pointer"}, {"name": "len", "kind": "scalar"}],
            callees=["lib_sanity_check"],
        ),
        _fn(
            "src/proc.c",
            "lib_print",
            "void(const unsigned char *)",
            [{"name": "buf", "kind": "const_pointer"}],
        ),
        _fn(
            "src/proc.c",
            "lib_helper_a",
            "void(unsigned char *)",
            [{"name": "p", "kind": "pointer"}],
        ),
        _fn(
            "src/proc.c",
            "lib_helper_b",
            "void(unsigned char *)",
            [{"name": "p", "kind": "pointer"}],
        ),
    ]
    model_fns = dict(entries)
    dag_fns = {
        fid: {
            "name": rec["name"],
            "file": rec["file"],
            "is_static": False,
            "module": "libdemo",
            "unit": "libdemo.so",
        }
        for fid, rec in model_fns.items()
    }
    entry_ids = [fid for fid, rec in model_fns.items() if rec["name"] != "lib_sanity_check"]
    dag = {
        "functions": dag_fns,
        "modules": {
            "libdemo": {
                "unit": "libdemo.so",
                "files": ["src/cfg.c", "src/proc.c"],
                "functions": list(dag_fns),
                "candidate_entry_points": entry_ids,
            }
        },
        "units": {"libdemo.so": {"kind": "shared_lib", "functions": list(dag_fns), "entry_points": entry_ids}},
    }
    model = {"status": "ok", "functions": model_fns, "entry_points": entry_ids}
    return dag, model


@pytest.mark.unit
def test_global_state_flow_computes_transitive_writes_and_refs() -> None:
    _, model = _global_lib_fixture()
    tw, tr = ah._global_state_flow(model["functions"])
    assert tw["lib_config"] == {"g_cfg"}
    assert tw["lib_init"] == {"g_cfg", "g_state"}
    assert tw["lib_init_unit_test"] == {"g_cfg", "g_params", "g_state"}
    # lib_process reaches lib_sanity_check which reads all three globals.
    assert tr["lib_process"] == {"g_cfg", "g_params", "g_state"}
    assert tw["lib_process"] == set()
    # A model with no global writes yields empty maps (no-op for stateless libraries).
    assert ah._global_state_flow({"a.c#f": {"name": "f", "writes": {"globals": []}}}) == ({}, {})


@pytest.mark.unit
def test_global_setup_sequence_binds_recorded_args_without_fuzz_bytes_and_feeds_seeds() -> None:
    dag, model = _global_lib_fixture()
    param_hex = "0102030405060708"
    traces = [
        # Window without setup: same-function repeat of lib_process that should be skipped.
        [
            {"fn": "lib_process", "args": {"0": [["b", 0, "aabb"]], "1": [["i", 0, "0200"]]}, "addrs": {"0": "1000"}},
            {"fn": "lib_process", "args": {"0": [["b", 0, "ccdd"]], "1": [["i", 0, "0200"]]}, "addrs": {"0": "1000"}},
        ],
        # Full recorded global-state setup -> single lib_process call (no shared pointer) -> teardown.
        [
            {"fn": "lib_config", "args": {"0": [["i", 0, "02"]], "1": [["i", 0, "3f"]]}, "addrs": {}},
            {"fn": "lib_add_param", "args": {"0": [["t", 0, param_hex]]}, "addrs": {}},
            {"fn": "lib_init", "args": {}, "addrs": {}},
            {
                "fn": "lib_process",
                "args": {"0": [["b", 0, "deadbeef"]], "1": [["i", 0, "0400000000000000"]]},
                "addrs": {"0": "2000"},
            },
            {"fn": "lib_shutdown", "args": {}, "addrs": {}},
        ],
    ]
    structs = {"struct param_s": {"size": 8, "pointers": False, "bools": False}}
    res = ah.plan(dag, model, "libdemo", "libdemo.so", 1024, traces=traces, struct_layouts=structs)
    seqs = [(i, lay, res["cases"][i]) for i, lay in enumerate(res["layouts"]) if lay.get("kind") == "sequence"]
    assert len(seqs) == 1
    sel, lay, stmt = seqs[0]
    assert lay["calls"] == ["lib_config", "lib_add_param", "lib_init", "lib_process", "lib_shutdown"]
    # Setup and teardown consume zero fuzz slots; lib_process (call 3) still owns the full rest buffer.
    assert lay["slots"] == []
    assert lay["rest"] == {"call": 3, "param": 0, "kind": "bytes"}
    assert "(void)lib_config(((unsigned char)2ULL), ((unsigned char)63ULL));" in stmt
    assert "static const unsigned char c1a0_rec[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };" in stmt
    assert "if (sizeof(c1a0) == sizeof(c1a0_rec)) { memcpy(&c1a0, c1a0_rec, sizeof(c1a0_rec)); }" in stmt
    assert "(void)lib_add_param(c1a0);" in stmt
    assert "(void)lib_init();" in stmt
    assert "(void)lib_shutdown();" in stmt
    assert "FRAMAC_FUZZ_COPY" not in stmt

    # seed_harvest.layout_seeds produces the matched trace frame seed first, plus all other recorded calls.
    layouts = [{**x, "selector": idx} for idx, x in enumerate(res["layouts"])]
    seeds = sh.layout_seeds(layouts, [], traces)
    assert seeds[sel][0] == bytes([sel]) + bytes.fromhex("deadbeef")
    assert set(seeds[sel]) == {bytes([sel]) + bytes.fromhex(h) for h in ("deadbeef", "aabb", "ccdd")}


@pytest.mark.unit
def test_global_setup_trims_earlier_init_and_dedups_repeated_setup_calls_before_cap() -> None:
    dag, model = _global_lib_fixture()
    p1 = "1100000000000000"
    p2 = "2200000000000000"
    traces = [
        [
            # Earlier init from a prior test without teardown, then config + 5 repeated add_param + init.
            {"fn": "lib_init_unit_test", "args": {}, "addrs": {}},
            {"fn": "lib_config", "args": {"0": [["i", 0, "02"]], "1": [["i", 0, "01"]]}, "addrs": {}},
            {"fn": "lib_add_param", "args": {"0": [["t", 0, p1]]}, "addrs": {}},
            {"fn": "lib_add_param", "args": {"0": [["t", 0, p1]]}, "addrs": {}},
            {"fn": "lib_add_param", "args": {"0": [["t", 0, p1]]}, "addrs": {}},
            {"fn": "lib_add_param", "args": {"0": [["t", 0, p1]]}, "addrs": {}},
            {"fn": "lib_add_param", "args": {"0": [["t", 0, p2]]}, "addrs": {}},
            {"fn": "lib_init", "args": {}, "addrs": {}},
            {"fn": "lib_process", "args": {"0": [["b", 0, "aa"]], "1": [["i", 0, "0100000000000000"]]}, "addrs": {}},
            {"fn": "lib_shutdown", "args": {}, "addrs": {}},
        ]
    ]
    structs = {"struct param_s": {"size": 8, "pointers": False, "bools": False}}
    res = ah.plan(dag, model, "libdemo", "libdemo.so", 1024, traces=traces, struct_layouts=structs)
    seqs = [(lay, res["cases"][i]) for i, lay in enumerate(res["layouts"]) if lay.get("kind") == "sequence"]
    assert len(seqs) == 1
    lay, stmt = seqs[0]
    # Earlier lib_init_unit_test is trimmed; exact duplicate lib_add_param(p1) calls collapse while
    # distinct additive registrations (p1 and p2) are both preserved alongside lib_config.
    assert lay["calls"] == ["lib_config", "lib_add_param", "lib_add_param", "lib_init", "lib_process", "lib_shutdown"]
    assert "0x11, 0x00" in stmt
    assert "0x22, 0x00" in stmt


@pytest.mark.unit
def test_global_setup_preserves_multiple_additive_registrations_and_ranks_by_concrete_args() -> None:
    dag, model = _global_lib_fixture()
    structs = {"struct param_s": {"size": 8, "pointers": False, "bools": False}}
    rare_p = "ff00000000000000"
    good_p = "0300000000000000"
    traces = [
        # Rare 1-off negative test appears first in traces.
        [
            {"fn": "lib_config", "args": {"0": [["i", 0, "09"]], "1": [["i", 0, "00"]]}, "addrs": {}},
            {"fn": "lib_add_param", "args": {"0": [["t", 0, rare_p]]}, "addrs": {}},
            {"fn": "lib_init", "args": {}, "addrs": {}},
            {"fn": "lib_process", "args": {"0": [["b", 0, "dead"]], "1": [["i", 0, "0200000000000000"]]}, "addrs": {}},
            {"fn": "lib_shutdown", "args": {}, "addrs": {}},
        ],
        # Canonical configuration appears 3 times with the same concrete setup arguments.
        [
            {"fn": "lib_config", "args": {"0": [["i", 0, "02"]], "1": [["i", 0, "01"]]}, "addrs": {}},
            {"fn": "lib_add_param", "args": {"0": [["t", 0, good_p]]}, "addrs": {}},
            {"fn": "lib_init", "args": {}, "addrs": {}},
            {"fn": "lib_process", "args": {"0": [["b", 0, "1122"]], "1": [["i", 0, "0200000000000000"]]}, "addrs": {}},
            {"fn": "lib_process", "args": {"0": [["b", 0, "3344"]], "1": [["i", 0, "0200000000000000"]]}, "addrs": {}},
            {"fn": "lib_process", "args": {"0": [["b", 0, "5566"]], "1": [["i", 0, "0200000000000000"]]}, "addrs": {}},
            {"fn": "lib_shutdown", "args": {}, "addrs": {}},
        ],
    ]
    res = ah.plan(dag, model, "libdemo", "libdemo.so", 1024, traces=traces, struct_layouts=structs)
    seqs = [(i, lay, res["cases"][i]) for i, lay in enumerate(res["layouts"]) if lay.get("kind") == "sequence"]
    assert len(seqs) == 1
    sel, lay, stmt = seqs[0]
    assert lay["calls"] == ["lib_config", "lib_add_param", "lib_init", "lib_process", "lib_shutdown"]
    assert "(void)lib_config(((unsigned char)2ULL), ((unsigned char)1ULL));" in stmt
    assert "0x03, 0x00" in stmt
    assert "0xff, 0x00" not in stmt

    # Multi-registration cap: 14 distinct additive calls keep lib_config + lib_init + earliest 10 adds.
    many_adds = [
        {"fn": "lib_add_param", "args": {"0": [["t", 0, f"{k:02x}" + "00" * 7]]}, "addrs": {}} for k in range(1, 15)
    ]
    trace_many = [
        {"fn": "lib_config", "args": {"0": [["i", 0, "02"]], "1": [["i", 0, "01"]]}, "addrs": {}},
        *many_adds,
        {"fn": "lib_init", "args": {}, "addrs": {}},
        {"fn": "lib_process", "args": {"0": [["b", 0, "aa"]], "1": [["i", 0, "0100000000000000"]]}, "addrs": {}},
        {"fn": "lib_shutdown", "args": {}, "addrs": {}},
    ]
    res_many = ah.plan(dag, model, "libdemo", "libdemo.so", 1024, traces=[trace_many], struct_layouts=structs)
    seqs_many = [
        (lay, res_many["cases"][i]) for i, lay in enumerate(res_many["layouts"]) if lay.get("kind") == "sequence"
    ]
    assert len(seqs_many) == 1
    m_lay, m_stmt = seqs_many[0]
    assert m_lay["calls"][0] == "lib_config"
    assert m_lay["calls"][-3:] == ["lib_init", "lib_process", "lib_shutdown"]
    assert m_lay["calls"].count("lib_add_param") == ah.GLOBAL_SETUP_MAX_PREFIX - 2
    assert "0x01, 0x00" in m_stmt
    assert "0x0a, 0x00" in m_stmt
    assert "0x0b, 0x00" not in m_stmt


@pytest.mark.unit
def test_global_teardown_resets_single_setup_cases_teardownless_sequences_and_seeds_all_calls() -> None:
    dag, model = _global_lib_fixture()
    traces = [
        # Teardown observed in one trace; a second trace calls lib_process twice without teardown.
        [
            {"fn": "lib_config", "args": {"0": [["i", 0, "02"]], "1": [["i", 0, "01"]]}, "addrs": {}},
            {"fn": "lib_init", "args": {}, "addrs": {}},
            {"fn": "lib_shutdown", "args": {}, "addrs": {}},
        ],
        [
            {"fn": "lib_config", "args": {"0": [["i", 0, "02"]], "1": [["i", 0, "01"]]}, "addrs": {}},
            {"fn": "lib_init", "args": {}, "addrs": {}},
            {"fn": "lib_process", "args": {"0": [["b", 0, "aa11"]], "1": [["i", 0, "0200000000000000"]]}, "addrs": {}},
            {"fn": "lib_process", "args": {"0": [["b", 0, "bb22"]], "1": [["i", 0, "0200000000000000"]]}, "addrs": {}},
        ],
    ]
    res = ah.plan(dag, model, "libdemo", "libdemo.so", 1024, traces=traces)
    singles = {lay["calls"][0]: res["cases"][i] for i, lay in enumerate(res["layouts"]) if lay.get("kind") == "single"}
    assert "(void)lib_shutdown();" in singles["lib_config"]
    assert "(void)lib_shutdown();" in singles["lib_init"]
    assert "(void)lib_shutdown();" not in singles["lib_init_with_cfg"]
    assert "(void)lib_shutdown();" not in singles["lib_process"]

    seqs = [(i, lay, res["cases"][i]) for i, lay in enumerate(res["layouts"]) if lay.get("kind") == "sequence"]
    assert len(seqs) == 1
    sel, lay, stmt = seqs[0]
    assert lay["calls"] == ["lib_config", "lib_init", "lib_process", "lib_shutdown"]
    assert "(void)lib_shutdown();" in stmt

    # layout_seeds collects every recorded call of lib_process (from traces + calls pool).
    layouts = [{**x, "selector": idx} for idx, x in enumerate(res["layouts"])]
    extra_calls = [
        {"fn": "lib_process", "args": {"0": [["b", 0, "cc33"]], "1": [["i", 0, "0200000000000000"]]}},
    ]
    seeds = sh.layout_seeds(layouts, extra_calls, traces)
    assert set(seeds[sel]) == {
        bytes([sel]) + bytes.fromhex("aa11"),
        bytes([sel]) + bytes.fromhex("bb22"),
        bytes([sel]) + bytes.fromhex("cc33"),
    }


@pytest.mark.unit
def test_global_setup_skips_pointer_path_pointer_struct_and_missing_recorded_args() -> None:
    dag, model = _global_lib_fixture()
    traces = [
        [
            {"fn": "lib_config_file", "args": {"0": [["s", 0, "2f657463"]]}, "addrs": {"0": "900"}},
            # Missing recorded scalar arg 1 for lib_config -> must not read fuzz bytes.
            {"fn": "lib_config", "args": {"0": [["i", 0, "02"]]}, "addrs": {}},
            # Struct containing a pointer -> must not memcpy raw pointer bytes.
            {"fn": "lib_add_param", "args": {"0": [["t", 0, "0102030405060708"]]}, "addrs": {}},
            {"fn": "lib_init", "args": {}, "addrs": {}},
            {"fn": "lib_process", "args": {"0": [["b", 0, "aa"]], "1": [["i", 0, "0100000000000000"]]}, "addrs": {}},
            {"fn": "lib_shutdown", "args": {}, "addrs": {}},
        ]
    ]
    structs = {"struct param_s": {"size": 8, "pointers": True, "bools": False}}
    res = ah.plan(dag, model, "libdemo", "libdemo.so", 1024, traces=traces, struct_layouts=structs)
    seqs = [lay for lay in res["layouts"] if lay.get("kind") == "sequence"]
    # Only lib_init (0 params) is safe to materialize; lib_config_file, incomplete lib_config, and
    # pointer-bearing lib_add_param are all excluded.
    assert [s["calls"] for s in seqs] == [["lib_init", "lib_process", "lib_shutdown"]]


@pytest.mark.unit
def test_global_setup_prepends_to_pointer_chains_and_keeps_unrelated_chains() -> None:
    dag, model = _global_lib_fixture()
    traces = [
        # Multi-function chain WITH preceding global setup.
        [
            {"fn": "lib_config", "args": {"0": [["i", 0, "01"]], "1": [["i", 0, "02"]]}, "addrs": {}},
            {"fn": "lib_init", "args": {}, "addrs": {}},
            {
                "fn": "lib_process",
                "args": {"0": [["b", 0, "aa"]], "1": [["i", 0, "0100000000000000"]]},
                "addrs": {"0": "500"},
            },
            {"fn": "lib_print", "args": {}, "addrs": {"0": "500"}},
            {"fn": "lib_shutdown", "args": {}, "addrs": {}},
        ],
        # Multi-function chain WITHOUT setup for a target that needs setup -> skipped.
        [
            {
                "fn": "lib_process",
                "args": {"0": [["b", 0, "bb"]], "1": [["i", 0, "0100000000000000"]]},
                "addrs": {"0": "600"},
            },
            {"fn": "lib_print", "args": {}, "addrs": {"0": "600"}},
            {"fn": "lib_print", "args": {}, "addrs": {"0": "600"}},
        ],
        # Unrelated pointer chain whose functions need no global setup -> kept as-is.
        [
            {"fn": "lib_helper_a", "args": {}, "addrs": {"0": "700"}},
            {"fn": "lib_helper_b", "args": {}, "addrs": {"0": "700"}},
        ],
    ]
    res = ah.plan(dag, model, "libdemo", "libdemo.so", 1024, traces=traces)
    seqs = [lay["calls"] for lay in res["layouts"] if lay.get("kind") == "sequence"]
    assert ["lib_config", "lib_init", "lib_process", "lib_shutdown"] in seqs
    assert ["lib_config", "lib_init", "lib_process", "lib_print", "lib_shutdown"] in seqs
    assert ["lib_helper_a", "lib_helper_b"] in seqs
    assert ["lib_process", "lib_print", "lib_print"] not in seqs


@pytest.mark.unit
def test_global_setup_respects_trust_schema_off_rollback() -> None:
    dag, model = _global_lib_fixture()
    traces = [
        [
            {"fn": "lib_config", "args": {"0": [["i", 0, "02"]], "1": [["i", 0, "3f"]]}, "addrs": {}},
            {"fn": "lib_init", "args": {}, "addrs": {}},
            {
                "fn": "lib_process",
                "args": {"0": [["b", 0, "aa"]], "1": [["i", 0, "0100000000000000"]]},
                "addrs": {"0": "100"},
            },
            {
                "fn": "lib_process",
                "args": {"0": [["b", 0, "bb"]], "1": [["i", 0, "0100000000000000"]]},
                "addrs": {"0": "100"},
            },
            {"fn": "lib_shutdown", "args": {}, "addrs": {}},
        ]
    ]
    res = ah.plan(dag, model, "libdemo", "libdemo.so", 1024, traces=traces, trust_schema=False)
    seqs = [lay["calls"] for lay in res["layouts"] if lay.get("kind") == "sequence"]
    assert seqs == [["lib_process", "lib_process"]]


@pytest.mark.unit
def test_record_layouts_marks_packed_bitfield_typedef_enum_struct_pointer_free() -> None:
    ast = {
        "kind": "TranslationUnitDecl",
        "inner": [
            {
                "kind": "TypedefDecl",
                "name": "ModeEnum",
                "type": {"qualType": "enum (unnamed enum at h.h:1:9)"},
            },
            {
                "kind": "RecordDecl",
                "tagUsed": "struct",
                "name": "packed_cfg",
                "completeDefinition": True,
                "inner": [
                    {"kind": "PackedAttr"},
                    {
                        "kind": "FieldDecl",
                        "name": "ver",
                        "isBitfield": True,
                        "type": {"qualType": "uint8_t", "desugaredQualType": "unsigned char"},
                    },
                    {"kind": "FieldDecl", "name": "mode", "type": {"qualType": "ModeEnum"}},
                    {"kind": "FieldDecl", "name": "max_len", "type": {"qualType": "int"}},
                ],
            },
            {
                "kind": "RecordDecl",
                "tagUsed": "struct",
                "name": "packed_with_ptr",
                "completeDefinition": True,
                "inner": [
                    {"kind": "PackedAttr"},
                    {"kind": "FieldDecl", "name": "p", "type": {"qualType": "unsigned char *"}},
                ],
            },
        ],
    }
    layouts, declared = ah.record_layouts(ast)
    # Neither packed struct has an unpacked byte-offset layout, but only packed_cfg is pointer-free.
    assert "struct packed_cfg" not in layouts
    assert "struct packed_cfg" in declared.pointer_free_records
    assert "struct packed_with_ptr" not in declared.pointer_free_records


@pytest.mark.unit
def test_global_pointer_ownership_heap_freed_static_retained_and_stack_copied() -> None:
    """
    A global setup function taking non-const record pointers must allocate each pointer according
    to the target's global-variable ownership:
    - pointer matching a pointer global freed by the global teardown -> heap `calloc` + OOM guard
      + teardown call + `else { free(...); }` (avoids stack-use-after-scope / bad-free on next call);
    - pointer matching a pointer global NOT freed by any teardown -> `static` storage (never dangles);
    - pointer whose matching globals are value structs or arrays -> stack storage, still paired with
      global teardown because the global types are known.
    """
    model_fns: dict[str, dict[str, Any]] = {
        "src/cfg.c#lib_init_with_cfgs": {
            "name": "lib_init_with_cfgs",
            "file": "src/cfg.c",
            "signature": "int(struct val_cfg_s *,struct arr_cfg_s *,struct owned_cfg_s *)",
            "formals": [
                {"name": "val_p", "kind": "pointer"},
                {"name": "arr_p", "kind": "pointer"},
                {"name": "owned_p", "kind": "pointer"},
            ],
            "static": False,
            "writes": {"pointer": 0, "params": [], "globals": ["g_val", "g_arr", "g_owned"]},
            "global_refs": ["src/cfg.c#g_val", "src/cfg.c#g_arr", "src/cfg.c#g_owned"],
            "call_sites": [],
        },
        "src/cfg.c#lib_register_ext": {
            "name": "lib_register_ext",
            "file": "src/cfg.c",
            "signature": "int(struct retained_cfg_s *)",
            "formals": [{"name": "ret_p", "kind": "pointer"}],
            "static": False,
            "writes": {"pointer": 0, "params": [], "globals": ["g_retained"]},
            "global_refs": ["src/cfg.c#g_retained"],
            "call_sites": [],
        },
        "src/cfg.c#lib_shutdown": {
            "name": "lib_shutdown",
            "file": "src/cfg.c",
            "signature": "int()",
            "formals": [],
            "static": False,
            "writes": {"pointer": 0, "params": [], "globals": ["g_val", "g_owned"]},
            "global_refs": ["src/cfg.c#g_val", "src/cfg.c#g_owned"],
            "call_sites": [{"callee": "free", "line": 10, "literals": {}, "initializer": False}],
        },
        "src/cfg.c#lib_process": {
            "name": "lib_process",
            "file": "src/cfg.c",
            "signature": "int(const unsigned char *,unsigned long)",
            "formals": [{"name": "buf", "kind": "const_pointer"}, {"name": "len", "kind": "scalar"}],
            "static": False,
            "writes": {"pointer": 0, "params": [], "globals": []},
            "global_refs": ["src/cfg.c#g_val", "src/cfg.c#g_owned"],
            "call_sites": [],
        },
    }
    dag_fns = {
        fid: {"name": rec["name"], "file": rec["file"], "is_static": False, "module": "libown", "unit": "libown.so"}
        for fid, rec in model_fns.items()
    }
    entry_ids = list(dag_fns)
    dag = {
        "functions": dag_fns,
        "modules": {
            "libown": {
                "unit": "libown.so",
                "files": ["src/cfg.c"],
                "functions": entry_ids,
                "candidate_entry_points": entry_ids,
            }
        },
        "units": {"libown.so": {"kind": "shared_lib", "functions": entry_ids, "entry_points": entry_ids}},
    }
    model = {
        "status": "ok",
        "functions": model_fns,
        "entry_points": entry_ids,
        "global_variables": {
            "src/cfg.c#g_val": {"name": "g_val", "type": "struct val_cfg_s", "raw_type": "struct val_cfg_s"},
            "src/cfg.c#g_arr": {"name": "g_arr", "type": "struct arr_cfg_s [8]", "raw_type": "struct arr_cfg_s [8]"},
            "src/cfg.c#g_owned": {
                "name": "g_owned",
                "type": "struct owned_cfg_s *",
                "raw_type": "struct owned_cfg_s *",
            },
            "src/cfg.c#g_retained": {
                "name": "g_retained",
                "type": "struct retained_cfg_s *",
                "raw_type": "struct retained_cfg_s *",
            },
        },
    }
    structs = {
        "struct val_cfg_s": {"size": 4, "pointers": False, "bools": False},
        "struct arr_cfg_s": {"size": 4, "pointers": False, "bools": False},
        "struct owned_cfg_s": {"size": 8, "pointers": False, "bools": False},
        "struct retained_cfg_s": {"size": 8, "pointers": False, "bools": False},
    }
    traces = [[{"fn": "lib_shutdown", "args": {}, "addrs": {}}]]
    res = ah.plan(dag, model, "libown", "libown.so", 256, traces=traces, struct_layouts=structs)
    by_fn = {
        lay["calls"][0]: (lay, res["cases"][idx])
        for idx, lay in enumerate(res["layouts"])
        if lay.get("kind") == "single"
    }

    _, init_stmt = by_fn["lib_init_with_cfgs"]
    # `val_cfg_s` and `arr_cfg_s` are value/array globals -> stack storage; `owned_cfg_s` -> heap calloc + teardown.
    assert "struct val_cfg_s c0a0; memset(&c0a0, 0, sizeof(c0a0));" in init_stmt
    assert "struct arr_cfg_s c0a1; memset(&c0a1, 0, sizeof(c0a1));" in init_stmt
    assert "struct owned_cfg_s *c0a2 = (struct owned_cfg_s *)calloc(1, sizeof(struct owned_cfg_s));" in init_stmt
    assert "if (c0a2 != 0) {" in init_stmt
    assert "lib_init_with_cfgs(&c0a0, &c0a1, c0a2)" in init_stmt
    assert "(void)lib_shutdown();" in init_stmt
    assert "} else { free(c0a2); FRAMAC_PROBE_INIT_FAIL(harness_selector); }" in init_stmt

    _, ret_stmt = by_fn["lib_register_ext"]
    # `g_retained` is a pointer global not freed by teardown -> `static` storage so it never dangles.
    assert "static struct retained_cfg_s c0a0; memset(&c0a0, 0, sizeof(c0a0));" in ret_stmt
    assert "calloc(" not in ret_stmt
    assert "lib_shutdown();" not in ret_stmt

    # Even without any recorded traces, retained non-freed pointer globals still get `static` storage
    # and freeing-teardown pointer globals still get `calloc` + teardown to prevent bad-free.
    res_notrace = ah.plan(dag, model, "libown", "libown.so", 256, struct_layouts=structs)
    by_fn_nt = {
        lay["calls"][0]: res_notrace["cases"][idx]
        for idx, lay in enumerate(res_notrace["layouts"])
        if lay.get("kind") == "single"
    }
    assert "static struct retained_cfg_s c0a0; memset(&c0a0, 0, sizeof(c0a0));" in by_fn_nt["lib_register_ext"]
    assert "calloc(1, sizeof(struct owned_cfg_s))" in by_fn_nt["lib_init_with_cfgs"]
    assert "(void)lib_shutdown();" in by_fn_nt["lib_init_with_cfgs"]


@pytest.mark.unit
def test_sequence_layout_records_setup_calls_and_passes_harness_sidecar_schema() -> None:
    from validate_artifacts import schema_problems

    dag, model = _global_lib_fixture()
    traces = [
        [
            {"fn": "lib_config", "args": {"0": [["i", 0, "02"]], "1": [["i", 0, "01"]]}, "addrs": {}},
            {"fn": "lib_init", "args": {}, "addrs": {}},
            {
                "fn": "lib_process",
                "args": {"0": [["b", 0, "deadbeef"]], "1": [["i", 0, "0400000000000000"]]},
                "addrs": {"0": "2000"},
            },
            {"fn": "lib_shutdown", "args": {}, "addrs": {}},
        ]
    ]
    res = ah.plan(dag, model, "libdemo", "libdemo.so", 256, traces=traces)
    seqs = [lay for lay in res["layouts"] if lay.get("kind") == "sequence"]
    assert len(seqs) == 1
    assert seqs[0]["setup_calls"] == ["lib_config", "lib_init"]
    sidecar = {
        "module": "libdemo",
        "harness_file": "workspace/harnesses/harness_libdemo.c",
        "sources": ["src/cfg.c", "src/proc.c"],
        "cppflags": "",
        "entry_fn": "lib_process",
        "entry_style": "dispatch",
        "api_harness": True,
        "api_cases": [{**lay, "selector": i} for i, lay in enumerate(res["layouts"])],
        "dispatch_cases": res["cases"],
    }
    assert schema_problems("harness_sidecar", sidecar) == []


# ---------------------------------------------------------------------------------------------------
# Docker: packed bitfield setup struct + global init + ASan/LSan execution + Frama-C Eva parse
# ---------------------------------------------------------------------------------------------------

GLOBAL_LIB_H = """\
#ifndef GLOBAL_LIB_H
#define GLOBAL_LIB_H
#include <stddef.h>
#include <stdint.h>

typedef enum { FLAG_OFF = 0, FLAG_ON = 1 } FlagEnum;

struct packed_param {
    uint8_t ver : 4;
    uint16_t scid : 10;
    uint8_t vcid : 6;
    FlagEnum has_crc;
    int set_flag;
} __attribute__((packed));

int glib_config(uint8_t mode);
int glib_add_param(struct packed_param p);
int glib_init(void);
int glib_process(const uint8_t *buf, size_t len);
int glib_shutdown(void);
#endif
"""

GLOBAL_LIB_C = """\
#include "global_lib.h"
#include <stdlib.h>

static uint8_t g_mode = 0;
static struct packed_param g_param;
static uint8_t *g_scratch = NULL;
int g_configured_hits = 0;

int glib_config(uint8_t mode) {
    g_mode = mode;
    return 0;
}

int glib_add_param(struct packed_param p) {
    g_param = p;
    return 0;
}

int glib_init(void) {
    if (g_mode != 2) return -1;
    if (g_scratch) free(g_scratch);
    g_scratch = (uint8_t *)malloc(32);
    return g_scratch ? 0 : -2;
}

int glib_process(const uint8_t *buf, size_t len) {
    if (g_mode != 2 || g_scratch == NULL || g_param.set_flag != 1 || g_param.scid != 3) {
        return -103;
    }
    g_configured_hits++;
    if (!buf || len == 0) return 0;
    g_scratch[0] = buf[0];
    return (int)g_scratch[0];
}

int glib_shutdown(void) {
    free(g_scratch);
    g_scratch = NULL;
    g_mode = 0;
    g_param.set_flag = 0;
    return 0;
}
"""

DOCKER_DRIVE_PY = """\
import json, os, shutil, subprocess, sys
from pathlib import Path
sys.path.insert(0, "/opt/framac-pipeline/scripts")
W = "/tmp/gsetup_w"
shutil.rmtree(W, ignore_errors=True)
shutil.copytree("/w", W)
os.chdir(W)

# Measure the exact sizeof + recorded bytes of `struct packed_param` as a test would pass it.
probe_src = '''
#include "global_lib.h"
#include <stdio.h>
int main(void) {
    struct packed_param p = {0};
    p.ver = 0; p.scid = 3; p.vcid = 1; p.has_crc = FLAG_ON; p.set_flag = 1;
    const unsigned char *b = (const unsigned char *)&p;
    for (size_t i = 0; i < sizeof(p); i++) printf("%02x", b[i]);
    putchar(10);
    return 0;
}
'''
Path("rec_param.c").write_text(probe_src, encoding="utf-8")
subprocess.run(["clang", "-I.", "rec_param.c", "-o", "rec_param"], check=True)
param_hex = subprocess.run(["./rec_param"], capture_output=True, text=True, check=True).stdout.strip()

import api_harness as ah

# Build minimal harness header file to probe clang AST layouts.
Path("probe_h.c").write_text('#include "global_lib.h"\\n', encoding="utf-8")
layouts, visible = ah.probe_layouts(Path("probe_h.c"), "-I.")

model_fns = {
    "global_lib.c#glib_config": {
        "name": "glib_config", "file": "global_lib.c", "signature": "int(unsigned char)",
        "formals": [{"name": "mode", "kind": "scalar"}], "static": False,
        "writes": {"pointer": 0, "params": [], "globals": ["g_mode"]},
        "global_refs": ["global_lib.c#g_mode"], "call_sites": [],
    },
    "global_lib.c#glib_add_param": {
        "name": "glib_add_param", "file": "global_lib.c", "signature": "int(struct packed_param)",
        "formals": [{"name": "p", "kind": "struct"}], "static": False,
        "writes": {"pointer": 0, "params": [], "globals": ["g_param"]},
        "global_refs": ["global_lib.c#g_param"], "call_sites": [],
    },
    "global_lib.c#glib_init": {
        "name": "glib_init", "file": "global_lib.c", "signature": "int()",
        "formals": [], "static": False,
        "writes": {"pointer": 0, "params": [], "globals": ["g_scratch"]},
        "global_refs": ["global_lib.c#g_mode", "global_lib.c#g_scratch"], "call_sites": [],
    },
    "global_lib.c#glib_process": {
        "name": "glib_process", "file": "global_lib.c", "signature": "int(const unsigned char *,unsigned long)",
        "formals": [{"name": "buf", "kind": "const_pointer"}, {"name": "len", "kind": "scalar"}], "static": False,
        "writes": {"pointer": 0, "params": [], "globals": []},
        "global_refs": ["global_lib.c#g_mode", "global_lib.c#g_param", "global_lib.c#g_scratch"], "call_sites": [],
    },
    "global_lib.c#glib_shutdown": {
        "name": "glib_shutdown", "file": "global_lib.c", "signature": "int()",
        "formals": [], "static": False,
        "writes": {"pointer": 0, "params": [], "globals": ["g_mode", "g_param", "g_scratch"]},
        "global_refs": ["global_lib.c#g_mode", "global_lib.c#g_param", "global_lib.c#g_scratch"], "call_sites": [],
    },
}
dag_fns = {k: {"name": v["name"], "file": v["file"], "is_static": False, "module": "m", "unit": "libg.so"} for k, v in model_fns.items()}
dag = {"functions": dag_fns, "modules": {"m": {"unit": "libg.so", "files": ["global_lib.c"], "functions": list(dag_fns), "candidate_entry_points": list(dag_fns)}}, "units": {"libg.so": {"kind": "shared_lib", "functions": list(dag_fns), "entry_points": list(dag_fns)}}}
model = {"status": "ok", "functions": model_fns, "entry_points": list(dag_fns)}
traces = [[
    {"fn": "glib_config", "args": {"0": [["i", 0, "02"]]}, "addrs": {}},
    {"fn": "glib_add_param", "args": {"0": [["t", 0, param_hex]]}, "addrs": {}},
    {"fn": "glib_init", "args": {}, "addrs": {}},
    {"fn": "glib_process", "args": {"0": [["b", 0, "4243"]], "1": [["i", 0, "0200000000000000"]]}, "addrs": {"0": "100"}},
    {"fn": "glib_shutdown", "args": {}, "addrs": {}},
]]
res = ah.plan(dag, model, "m", "libg.so", 256, traces=traces, struct_layouts=layouts, visible=visible)
seqs = [(i, lay, res["cases"][i]) for i, lay in enumerate(res["layouts"]) if lay.get("kind") == "sequence"]
assert len(seqs) == 1, seqs
sel, lay, stmt = seqs[0]

# Compile and run the generated sequence case under ASan + LSan + UBSan and check g_configured_hits!
harness_c = f'''
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "global_lib.h"
#define FRAMAC_FUZZ_COPY(b, o) ((b) + (o))
extern int g_configured_hits;
int run_case(const uint8_t *fuzz_buf, size_t fuzz_len) {{
    {stmt}
    return g_configured_hits;
}}
#ifndef FRAMAC_EVA_MODE
int main(void) {{
    const uint8_t in[2] = {{0x42, 0x43}};
    int hits = run_case(in, sizeof(in));
    return hits == 1 ? 0 : 1;
}}
#else
int eva_main(void) {{
    const uint8_t in[2] = {{0x42, 0x43}};
    return run_case(in, sizeof(in));
}}
#endif
'''
Path("run_seq.c").write_text(harness_c, encoding="utf-8")
subprocess.run(["clang", "-O1", "-g", "-fsanitize=address,undefined", "-I.", "run_seq.c", "global_lib.c", "-o", "run_seq"], check=True)
env = {**os.environ, "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1"}
run_p = subprocess.run(["./run_seq"], capture_output=True, text=True, env=env, timeout=60)
fc_p = subprocess.run(["frama-c", "-machdep", "gcc_x86_64", "-cpp-extra-args=-I. -DFRAMAC_EVA_MODE", "-main", "eva_main", "run_seq.c", "global_lib.c"], capture_output=True, text=True, timeout=120)
print("RESULT " + json.dumps({
    "pf": "struct packed_param" in visible.pointer_free_records,
    "calls": lay["calls"],
    "slots": lay["slots"],
    "rest": lay["rest"],
    "run_rc": run_p.returncode,
    "run_err": run_p.stderr[-500:],
    "fc_rc": fc_p.returncode,
    "fc_err": (fc_p.stdout + fc_p.stderr)[-500:],
}))
"""


@pytest.mark.integration
@pytest.mark.slow
def test_docker_global_setup_packed_struct_executes_configured_path_without_leaks(tmp_path: Path) -> None:
    require_docker_images(ANALYSIS_IMAGE)
    for rel, text in {
        "global_lib.h": GLOBAL_LIB_H,
        "global_lib.c": GLOBAL_LIB_C,
        "drive.py": DOCKER_DRIVE_PY,
    }.items():
        (tmp_path / rel).write_text(text, encoding="utf-8", newline="\n")
    tag = os.environ.get("FRAMAC_RUN_TAG", "pytest-api-harness-global-setup")
    proc = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "--label", f"framac.run={tag}",
         "-v", f"{tmp_path}:/w:ro",
         "-v", f"{ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
         "--entrypoint", "sh", ANALYSIS_IMAGE, "-c", "timeout 300 python3 /w/drive.py"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=400, check=False,
    )  # fmt: skip
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    line = next((ln for ln in proc.stdout.splitlines() if ln.startswith("RESULT ")), None)
    assert line is not None, out
    res = json.loads(line[len("RESULT ") :])
    assert res["pf"] is True, res
    assert res["calls"] == ["glib_config", "glib_add_param", "glib_init", "glib_process", "glib_shutdown"], res
    assert res["slots"] == [] and res["rest"] == {"call": 3, "param": 0, "kind": "bytes"}, res
    assert res["run_rc"] == 0, res
    assert res["fc_rc"] == 0, res


OWN_LIB_H = """\
#ifndef OWN_LIB_H
#define OWN_LIB_H
#include <stddef.h>
#include <stdint.h>

typedef struct { int x; } val_cfg_t;
typedef struct { int y; } owned_cfg_t;

int own_init_with_cfgs(val_cfg_t *v, owned_cfg_t *o);
int own_shutdown(void);
#endif
"""

OWN_LIB_C = """\
#include "own_lib.h"
#include <stdlib.h>

val_cfg_t g_val;
owned_cfg_t *g_owned = NULL;
int g_hidden_hits = 0;

int own_init_with_cfgs(val_cfg_t *v, owned_cfg_t *o) {
    if (v) g_val = *v;
    if (g_owned && g_owned != o) free(g_owned);
    g_owned = o;
    return 0;
}

int own_shutdown(void) {
    if (g_owned) {
        free(g_owned);
        g_owned = NULL;
    }
    return 0;
}

/* Exported in object file, intentionally omitted from own_lib.h. */
int own_hidden_api(const unsigned char *buf, unsigned long len) {
    g_hidden_hits += (buf && len > 0) ? 1 : 0;
    return g_hidden_hits;
}
"""

DOCKER_OWN_DRIVE_PY = """\
import json, os, shutil, subprocess, sys
from pathlib import Path
sys.path.insert(0, "/opt/framac-pipeline/scripts")
W = "/tmp/gown_w"
shutil.rmtree(W, ignore_errors=True)
shutil.copytree("/w", W)
os.chdir(W)

import api_harness as ah

model_fns = {
    "own_lib.c#own_init_with_cfgs": {
        "name": "own_init_with_cfgs", "file": "own_lib.c",
        "signature": "int(struct __anonstruct_val_cfg_t_1 *,struct __anonstruct_owned_cfg_t_2 *)",
        "formals": [{"name": "v", "kind": "pointer"}, {"name": "o", "kind": "pointer"}],
        "static": False,
        "writes": {"pointer": 0, "params": [], "globals": ["g_val", "g_owned"]},
        "global_refs": ["own_lib.c#g_val", "own_lib.c#g_owned"], "call_sites": [],
    },
    "own_lib.c#own_shutdown": {
        "name": "own_shutdown", "file": "own_lib.c", "signature": "int()", "formals": [],
        "static": False,
        "writes": {"pointer": 0, "params": [], "globals": ["g_owned"]},
        "global_refs": ["own_lib.c#g_owned"],
        "call_sites": [{"callee": "free", "line": 17, "literals": {}, "initializer": False}],
    },
    "own_lib.c#own_hidden_api": {
        "name": "own_hidden_api", "file": "own_lib.c",
        "signature": "int(unsigned char *,unsigned long)",
        "formals": [{"name": "buf", "kind": "const_pointer"}, {"name": "len", "kind": "scalar"}],
        "static": False,
        "writes": {"pointer": 0, "params": [], "globals": []},
        "global_refs": [], "call_sites": [],
    },
}
dag_fns = {
    k: {"name": v["name"], "file": v["file"], "is_static": False, "module": "own", "unit": "libown.so"}
    for k, v in model_fns.items()
}
dag = {
    "module_kind": "link_unit",
    "functions": dag_fns,
    "modules": {"own": {"unit": "libown.so", "files": ["own_lib.c"], "functions": list(dag_fns), "candidate_entry_points": list(dag_fns)}},
    "units": {"libown.so": {"kind": "shared_lib", "functions": list(dag_fns), "entry_points": list(dag_fns)}},
}
model = {
    "status": "ok",
    "functions": model_fns,
    "entry_points": list(dag_fns),
    "global_variables": {
        "own_lib.c#g_val": {"name": "g_val", "type": "struct __anonstruct_val_cfg_t_1", "raw_type": "val_cfg_t"},
        "own_lib.c#g_owned": {"name": "g_owned", "type": "struct __anonstruct_owned_cfg_t_2 *", "raw_type": "owned_cfg_t *"},
    },
}
Path("dag.json").write_text(json.dumps(dag), encoding="utf-8")
Path("model.json").write_text(json.dumps(model), encoding="utf-8")
Path("traces.jsonl").write_text(
    json.dumps({"calls": [{"fn": "own_shutdown", "args": {}, "addrs": {}}]}) + "\\n", encoding="utf-8"
)
out_dir = Path("out_h")
out_dir.mkdir(exist_ok=True)
res = ah.generate(
    "own", "own_lib.h", 64, "-I.", out_dir,
    unit="own", dag_path=Path("dag.json"), model_path=Path("model.json"),
    traces_path=Path("traces.jsonl"), variadic={},
)
sidecar = json.loads((out_dir / "harness_own.json").read_text(encoding="utf-8"))
harness_c = out_dir / "harness_own.c"

driver = '''
#include <stddef.h>
#include <stdint.h>
extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern int g_hidden_hits;
int main(void) {
    for (int round = 0; round < 5; round++) {
        for (uint8_t sel = 0; sel < 8; sel++) {
            uint8_t buf[16] = {sel, 1, 2, 3, 4, 5, 6, 7};
            LLVMFuzzerTestOneInput(buf, sizeof(buf));
        }
    }
    return g_hidden_hits > 0 ? 0 : 2;
}
'''
Path("driver.c").write_text(driver, encoding="utf-8")
c_proc = subprocess.run(
    ["clang", "-O1", "-g", "-fsanitize=address,undefined", "-I.", "driver.c", str(harness_c), "own_lib.c", "-o", "run_own"],
    capture_output=True, text=True, check=False,
)
env = {**os.environ, "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1"}
r_proc = subprocess.run(["./run_own"], capture_output=True, text=True, env=env, timeout=60) if c_proc.returncode == 0 else None
fc_proc = subprocess.run(
    ["frama-c", "-machdep", "gcc_x86_64", "-cpp-extra-args=-I. -DFRAMAC_EVA_MODE", "-main", "eva_main", str(harness_c), "own_lib.c"],
    capture_output=True, text=True, timeout=120,
)
print("RESULT " + json.dumps({
    "api_cases": res["api_cases"],
    "api_skipped": res["api_skipped"],
    "synth": (sidecar.get("api_headers") or {}).get("synthesized_prototypes"),
    "compile_rc": c_proc.returncode,
    "compile_err": c_proc.stderr[-500:],
    "run_rc": r_proc.returncode if r_proc else -1,
    "run_err": r_proc.stderr[-500:] if r_proc else "",
    "fc_rc": fc_proc.returncode,
    "fc_err": (fc_proc.stdout + fc_proc.stderr)[-500:],
}))
"""


@pytest.mark.integration
@pytest.mark.slow
def test_docker_global_pointer_ownership_and_synth_proto_asan_and_framac(tmp_path: Path) -> None:
    require_docker_images(ANALYSIS_IMAGE)
    for rel, text in {
        "own_lib.h": OWN_LIB_H,
        "own_lib.c": OWN_LIB_C,
        "drive.py": DOCKER_OWN_DRIVE_PY,
    }.items():
        (tmp_path / rel).write_text(text, encoding="utf-8", newline="\n")
    tag = os.environ.get("FRAMAC_RUN_TAG", "pytest-api-harness-own-synth")
    proc = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "--label", f"framac.run={tag}",
         "-v", f"{tmp_path}:/w:ro",
         "-v", f"{ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
         "--entrypoint", "sh", ANALYSIS_IMAGE, "-c", "timeout 300 python3 /w/drive.py"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=400, check=False,
    )  # fmt: skip
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    line = next((ln for ln in proc.stdout.splitlines() if ln.startswith("RESULT ")), None)
    assert line is not None, out
    res = json.loads(line[len("RESULT ") :])
    assert res["api_cases"] == 3 and res["api_skipped"] == {}, res
    assert res["synth"] == {"own_hidden_api": "extern int own_hidden_api(unsigned char const *, unsigned long);"}, res
    assert res["compile_rc"] == 0, res
    assert res["run_rc"] == 0, res
    assert res["fc_rc"] == 0, res
