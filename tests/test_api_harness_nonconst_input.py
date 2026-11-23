"""Tests for non-const writable input buffers, (byte *, len *) pairs, and heap-size probers."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import api_harness as ah
import seed_harvest as sh

SPARE = 1024
DOCKER = os.environ.get("FRAMAC_DOCKER_TESTS") == "1"
IMAGE = os.environ.get("FRAMAC_ANALYSIS_IMAGE", "framac-analysis:latest")
REPO_ROOT = Path(__file__).resolve().parent.parent


def _formals(*spec: tuple[str, str]) -> list[dict[str, str]]:
    return [{"name": name, "kind": kind} for name, kind in spec]


def _make_dag_model(
    model_fns: dict[str, dict],
    entry_ids: list[str],
    *,
    module: str = "libdemo",
    unit: str = "libdemo.so",
    files: list[str] | None = None,
) -> tuple[dict, dict]:
    srcs = list(files or ["demo.c"])
    dag_fns = {
        fid: {
            "name": rec["name"],
            "file": rec.get("file", srcs[0]),
            "is_static": False,
            "module": module,
            "unit": unit,
        }
        for fid, rec in model_fns.items()
    }
    dag = {
        "functions": dag_fns,
        "modules": {
            module: {
                "unit": unit,
                "files": srcs,
                "functions": list(dag_fns),
                "candidate_entry_points": entry_ids,
            }
        },
        "units": {unit: {"kind": "shared_lib", "functions": list(dag_fns), "entry_points": entry_ids}},
    }
    model = {"status": "ok", "functions": model_fns, "entry_points": entry_ids}
    return dag, model


@pytest.mark.unit
def test_recorded_input_buffers_ignores_pointee_p_and_zero_only_b() -> None:
    traces = [
        [
            {
                "fn": "tm_proc",
                "args": {
                    "0": [["b", 0, "002c000011223344"]],
                    "1": [["i", 0, "0800"]],
                    "3": [["p", 0, "ff00"]],
                },
            },
            {
                "fn": "zero_out",
                "args": {"0": [["b", 0, "0000000000000000"]], "1": [["i", 0, "0800"]]},
            },
            {
                "fn": "only_pointee",
                "args": {"0": [["p", 0, "20"]], "1": [["p", 0, "2e000000"]]},
            },
        ]
    ]
    got = ah.recorded_input_buffers(traces)
    assert got == {"tm_proc": {0}}


@pytest.mark.unit
def test_nonconst_pair_with_recorded_b_or_input_name_passes_exact_bounds_fuzz_buf() -> None:
    # 1. Input-named non-const pair without traces (`p_ingest`, `len_ingest`): direct writable
    # `fuzz_buf + fuzz_off` so ASan / E-ACSL / Eva enforce exact end bounds (no spare-size zero pad).
    tm_rec = {
        "name": "tm_proc",
        "signature": "int(unsigned char *,unsigned short,struct tm_out *,unsigned short *)",
        "formals": _formals(
            ("p_ingest", "pointer"),
            ("len_ingest", "value"),
            ("pp_processed_frame", "pointer"),
            ("p_decrypted_length", "pointer"),
        ),
    }
    stmt, layout, why = ah.single_case("tm_proc", tm_rec, SPARE)
    assert why is None and stmt is not None and layout is not None
    assert "(unsigned char *)(fuzz_buf + fuzz_off)" in stmt
    assert f"unsigned char c0a0[{SPARE}]" not in stmt
    assert "memcpy(c0a0," not in stmt
    assert "c0a1 = (unsigned short)rest_n;" in stmt
    assert layout["rest"] == {"call": 0, "param": 0, "kind": "bytes"}
    assert layout["slots"] == []
    # True outputs stay zeroed (not filled from fuzz input).
    assert f"static _Alignas(16) unsigned char c0a2[{SPARE}]; memset(c0a2, 0, sizeof(c0a2));" in stmt
    assert f"static _Alignas(16) unsigned char c0a3[{SPARE}]; memset(c0a3, 0, sizeof(c0a3));" in stmt

    # 2. Neutral parameter names (`data`, `size`) promoted ONLY when traces recorded a non-zero `b` buffer.
    crc_rec = {
        "name": "calc_crc",
        "signature": "unsigned short(unsigned char *,int)",
        "formals": _formals(("data", "pointer"), ("size", "value")),
    }
    stmt_no_tr, lay_no_tr, _ = ah.single_case("calc_crc", crc_rec, SPARE)
    assert stmt_no_tr is not None and lay_no_tr is not None
    assert lay_no_tr["rest"] is None
    assert lay_no_tr["slots"] == [{"call": 0, "param": 1, "size": 4, "kind": "int"}]

    api_tr = ah.ApiInfo(recorded_input_buffers={"calc_crc": {0}})
    stmt_tr, lay_tr, _ = ah.single_case("calc_crc", crc_rec, SPARE, api_tr)
    assert stmt_tr is not None and lay_tr is not None
    assert lay_tr["rest"] == {"call": 0, "param": 0, "kind": "bytes"}
    assert lay_tr["slots"] == []
    assert "(unsigned char *)(fuzz_buf + fuzz_off)" in stmt_tr
    assert "memcpy(c0a0," not in stmt_tr


@pytest.mark.unit
def test_nonconst_pair_rejects_output_names_non_length_names_and_threat_model_outputs() -> None:
    api_tr = ah.ApiInfo(
        trust_schema=True,
        recorded_input_buffers={"out_fn": {0}, "port_fn": {0}, "idx_fn": {0}, "tm_out_fn": {0}},
    )
    # 1. Explicit output names stay zeroed even if traces recorded non-zero bytes (e.g. uninit stack).
    out_rec = {
        "name": "out_fn",
        "signature": "int(unsigned char *,unsigned short)",
        "formals": _formals(("out_buf", "pointer"), ("out_len", "value")),
    }
    _, lay_out, _ = ah.single_case("out_fn", out_rec, SPARE, api_tr)
    assert lay_out is not None and lay_out["rest"] is None

    # 2. Non-length unsigned scalar (`kmc_crypto_port`) is never promoted as a length.
    port_rec = {
        "name": "port_fn",
        "signature": "int(char *,unsigned short)",
        "formals": _formals(("hostname", "pointer"), ("kmc_crypto_port", "value")),
    }
    _, lay_port, _ = ah.single_case("port_fn", port_rec, SPARE, api_tr)
    assert lay_port is not None and lay_port["rest"] is None

    # 3. Index-named unsigned scalar (`byte_idx`) is never promoted as a length even with `p_ingest`.
    idx_rec = {
        "name": "idx_fn",
        "signature": "int(unsigned char *,unsigned short)",
        "formals": _formals(("p_ingest", "pointer"), ("byte_idx", "value")),
    }
    _, lay_idx, _ = ah.single_case("idx_fn", idx_rec, SPARE, api_tr)
    assert lay_idx is not None and lay_idx["rest"] is None

    # 4. Threat model marking only `other` as attacker keeps non-const `(buf, len)` as caller_storage (zeroed).
    tm_rec = {
        "name": "tm_out_fn",
        "signature": "int(unsigned char *,unsigned long,unsigned int)",
        "formals": _formals(("in_scratch", "pointer"), ("in_len", "value"), ("other", "value")),
    }
    et_other = ah._EntryTrust(input_role="entry", attacker_params=["other"])
    stmt_cs, lay_cs, _ = ah.single_case("tm_out_fn", tm_rec, SPARE, api_tr, entry_trust=et_other)
    assert stmt_cs is not None and lay_cs is not None
    assert lay_cs["rest"] is None
    assert "sizeof(c0a0_buf)" in stmt_cs

    # 5. Threat model explicitly naming a non-const buffer in `attacker_params` DOES feed it from rest (exact bounds).
    et_att = ah._EntryTrust(input_role="entry", attacker_params=["in_scratch"])
    stmt_att, lay_att, _ = ah.single_case("tm_out_fn", tm_rec, SPARE, api_tr, entry_trust=et_att)
    assert stmt_att is not None and lay_att is not None
    assert lay_att["rest"] == {"call": 0, "param": 0, "kind": "bytes"}
    assert "(unsigned char *)(fuzz_buf + fuzz_off)" in stmt_att
    assert "memcpy(c0a0," not in stmt_att


@pytest.mark.unit
def test_buf_len_ptr_pair_feeds_exact_bounds_buffer_and_len_pointer_in_single_and_shared_sequences() -> None:
    # Single case: Crypto_TC_ProcessSecurity(uint8_t *ingest, int *len_ingest, struct tc *out)
    tc_rec = {
        "name": "tc_proc",
        "signature": "int(unsigned char *,int *,struct tc_out *)",
        "formals": _formals(("ingest", "pointer"), ("len_ingest", "pointer"), ("tc_out", "pointer")),
        "global_refs": ["g_cfg"],
        "writes": {"globals": [], "params": []},
        "call_sites": [],
    }
    stmt, lay, why = ah.single_case("tc_proc", tc_rec, SPARE)
    assert why is None and stmt is not None and lay is not None
    assert lay["rest"] == {"call": 0, "param": 0, "kind": "bytes"}
    assert lay["slots"] == []
    assert "int c0a1 = 0;" in stmt
    assert "(unsigned char *)(fuzz_buf + fuzz_off)" in stmt
    assert f"unsigned char c0a0[{SPARE}]" not in stmt
    assert "memcpy(c0a0," not in stmt
    assert "c0a1 = (int)rest_n;" in stmt
    assert "(int *)&c0a1" in stmt

    # Threat model explicitly naming `ingest` also marks `int *len_ingest` as attacker and feeds rest.
    tc_tm_rec = {
        "name": "tc_proc_2",
        "signature": "int(unsigned char *,int *)",
        "formals": _formals(("ingest", "pointer"), ("len_ingest", "pointer")),
    }
    api_tm = ah.ApiInfo(trust_schema=True)
    et = ah._EntryTrust(input_role="entry", attacker_params=["ingest"])
    stmt_tm, lay_tm, why_tm = ah.single_case("tc_proc_2", tc_tm_rec, SPARE, api_tm, entry_trust=et)
    assert why_tm is None and stmt_tm is not None and lay_tm is not None
    assert lay_tm["rest"] == {"call": 0, "param": 0, "kind": "bytes"}
    assert "(int *)&c0a1" in stmt_tm

    # Pure output `(unsigned char *buffer, unsigned short *length)` stays zeroed.
    reply_rec = {
        "name": "get_reply",
        "signature": "int(unsigned char *,unsigned short *)",
        "formals": _formals(("buffer", "pointer"), ("length", "pointer")),
    }
    stmt_r, lay_r, _ = ah.single_case("get_reply", reply_rec, SPARE)
    assert stmt_r is not None and lay_r is not None
    assert lay_r["rest"] is None
    assert "unsigned short c0a1[4];" in stmt_r

    # Sequence case where two calls share `ingest` buffer `s0`: first call copies rest into `s0`
    # and passes `&c1a1` with `c1a1 = (int)rest_n`; second call clamps its length slot to `sizeof(s0)`.
    dag, model = _make_dag_model(
        {
            "demo.c#lib_init": {
                "name": "lib_init",
                "file": "demo.c",
                "signature": "int(void)",
                "formals": [],
                "writes": {"globals": ["g_cfg"], "params": []},
                "global_refs": ["g_cfg"],
                "call_sites": [],
            },
            "demo.c#tc_proc": {**tc_rec, "file": "demo.c"},
            "demo.c#lib_shutdown": {
                "name": "lib_shutdown",
                "file": "demo.c",
                "signature": "int(void)",
                "formals": [],
                "writes": {"globals": ["g_cfg"], "params": []},
                "global_refs": ["g_cfg"],
                "call_sites": [],
            },
        },
        ["demo.c#lib_init", "demo.c#tc_proc", "demo.c#lib_shutdown"],
    )
    traces = [
        [
            {"fn": "lib_init", "args": {}, "addrs": {}},
            {"fn": "tc_proc", "args": {"0": [["b", 0, "2003042d00000102"]]}, "addrs": {"0": "100", "1": "200"}},
            {"fn": "tc_proc", "args": {"0": [["b", 0, "2003042d00000102"]]}, "addrs": {"0": "100", "1": "204"}},
            {"fn": "lib_shutdown", "args": {}, "addrs": {}},
        ]
    ]
    res = ah.plan(dag, model, "libdemo", "libdemo.so", SPARE, traces=traces)
    seqs = [(lay, st) for lay, st in zip(res["layouts"], res["cases"], strict=True) if lay.get("kind") == "sequence"]
    shared_seq = [(lay, st) for lay, st in seqs if lay["calls"] == ["lib_init", "tc_proc", "tc_proc", "lib_shutdown"]]
    assert len(shared_seq) == 1
    s_lay, s_stmt = shared_seq[0]
    assert s_lay["rest"] == {"call": 1, "param": 0, "kind": "bytes"}
    assert "memcpy(s0, FRAMAC_FUZZ_COPY(fuzz_buf, fuzz_off), rest_n);" in s_stmt
    assert "c1a1 = (int)rest_n;" in s_stmt
    assert "(int *)&c1a1" in s_stmt
    assert "(int *)&c2a1" in s_stmt


@pytest.mark.unit
def test_heap_buffer_prober_uses_calloc_and_free_for_writable_input() -> None:
    dag, model = _make_dag_model(
        {
            "demo.c#check_buf": {
                "name": "check_buf",
                "file": "demo.c",
                "signature": "int(unsigned char *,unsigned short)",
                "formals": _formals(("buf", "pointer"), ("required", "value")),
                "call_sites": [{"callee": "malloc_usable_size"}],
            },
            "demo.c#apply_sec": {
                "name": "apply_sec",
                "file": "demo.c",
                "signature": "int(unsigned char *,unsigned short)",
                "formals": _formals(("pTfBuffer", "pointer"), ("len_ingest", "value")),
                "call_sites": [{"callee": "check_buf"}],
            },
        },
        ["demo.c#apply_sec", "demo.c#check_buf"],
    )
    res = ah.plan(dag, model, "libdemo", "libdemo.so", SPARE)
    by_fn = {lay["calls"][0]: (lay, st) for lay, st in zip(res["layouts"], res["cases"], strict=True)}
    lay_a, stmt_a = by_fn["apply_sec"]
    assert lay_a["rest"] == {"call": 0, "param": 0, "kind": "bytes"}
    expected_spare = 2 * SPARE + 1024
    assert f"unsigned char *c0a0 = (unsigned char *)calloc(1, {expected_spare}U);" in stmt_a
    assert "if (c0a0 != 0 && rest_n > 0) { memcpy(c0a0, FRAMAC_FUZZ_COPY(fuzz_buf, fuzz_off), rest_n); }" in stmt_a
    assert "if (c0a0 != 0) { (void)apply_sec((unsigned char *)c0a0, c0a1); } free(c0a0);" in stmt_a

    # Direct caller with output-style neutral pair (`check_buf`) also gets heap allocation + free.
    _, stmt_c = by_fn["check_buf"]
    assert f"unsigned char *c0a0 = (unsigned char *)calloc(1, {expected_spare}U);" in stmt_c
    assert "free(c0a0);" in stmt_c


@pytest.mark.unit
def test_seed_harvest_plan_and_wrapper_record_buf_len_ptr_pair() -> None:
    plan_in = sh.plan_function(
        "tc_proc",
        "int(unsigned char *,int *,struct tc_out *)",
        names=["ingest", "len_ingest", "tc_out"],
    )
    assert plan_in["supported"] is True
    assert plan_in["params"][0]["record"] == "bp"
    assert plan_in["params"][0]["len_pointee"] == "int"
    src = sh.wrapper_source([plan_in], [])
    assert "void fc_mem_lenptr(int idx, const void *p, const void *lenp, size_t len_size, int len_signed);" in src
    assert "fc_mem_lenptr(0, a0, a1, sizeof(int), 1);" in src

    # Output-named `(out_buf, out_len)` does not record `bp`.
    plan_out = sh.plan_function(
        "get_reply",
        "int(unsigned char *,unsigned short *)",
        names=["reply_buf", "reply_len"],
    )
    assert plan_out["supported"] is True
    assert plan_out["params"][0]["record"] != "bp"


@pytest.mark.unit
def test_multi_call_sequence_feeds_secondary_nonconst_inputs_with_exact_size_allocs() -> None:
    dag, model = _make_dag_model(
        {
            "demo.c#lib_init": {
                "name": "lib_init",
                "file": "demo.c",
                "signature": "int(void)",
                "formals": [],
                "writes": {"globals": ["g_cfg"], "params": []},
                "global_refs": ["g_cfg"],
                "call_sites": [],
            },
            "demo.c#aos_proc": {
                "name": "aos_proc",
                "file": "demo.c",
                "signature": "int(unsigned char *,unsigned short,struct aos_out *)",
                "formals": _formals(("p_ingest", "pointer"), ("len_ingest", "value"), ("p_out", "pointer")),
                "writes": {"globals": [], "params": ["p_out"]},
                "global_refs": ["g_cfg"],
                "call_sites": [],
            },
            "demo.c#aos_print": {
                "name": "aos_print",
                "file": "demo.c",
                "signature": "void(struct aos_out *)",
                "formals": _formals(("p_out", "pointer")),
                "writes": {"globals": [], "params": []},
                "global_refs": [],
                "call_sites": [],
            },
            "demo.c#lib_shutdown": {
                "name": "lib_shutdown",
                "file": "demo.c",
                "signature": "int(void)",
                "formals": [],
                "writes": {"globals": ["g_cfg"], "params": []},
                "global_refs": ["g_cfg"],
                "call_sites": [],
            },
        },
        ["demo.c#lib_init", "demo.c#aos_proc", "demo.c#aos_print", "demo.c#lib_shutdown"],
    )
    # Two unshared calls to `aos_proc` sharing `p_out` (addr 300) with `aos_print`:
    # call 1 gets direct exact-bounds `fuzz_buf + fuzz_off`; call 2 gets an exact-size `malloc` copy of rest.
    traces = [
        [
            {"fn": "lib_init", "args": {}, "addrs": {}},
            {
                "fn": "aos_proc",
                "args": {"0": [["b", 0, "400300010203"]]},
                "addrs": {"0": "100", "2": "300"},
            },
            {
                "fn": "aos_proc",
                "args": {"0": [["b", 0, "400300040506"]]},
                "addrs": {"0": "200", "2": "300"},
            },
            {"fn": "aos_print", "args": {}, "addrs": {"0": "300"}},
            {"fn": "lib_shutdown", "args": {}, "addrs": {}},
        ]
    ]
    res = ah.plan(dag, model, "libdemo", "libdemo.so", SPARE, traces=traces)
    seqs = [
        (lay, st)
        for lay, st in zip(res["layouts"], res["cases"], strict=True)
        if lay.get("kind") == "sequence" and lay["calls"].count("aos_proc") == 2
    ]
    assert len(seqs) == 1
    s_lay, s_stmt = seqs[0]
    assert s_lay["rest"] == {"call": 1, "param": 0, "kind": "bytes"}
    assert "(unsigned char *)(fuzz_buf + fuzz_off)" in s_stmt
    assert "c2a0_alloc = (unsigned char *)malloc(c2a0_n > 0U ? c2a0_n : 1U);" in s_stmt
    assert "c2a0 = (c2a0_n > 0U) ? c2a0_alloc : (c2a0_alloc + 1);" in s_stmt
    assert "memcpy(c2a0, FRAMAC_FUZZ_COPY(fuzz_buf, fuzz_off), c2a0_n);" in s_stmt
    assert "free(c2a0_alloc);" in s_stmt
    assert "unsigned char c2a0[" not in s_stmt


@pytest.mark.unit
def test_rule_ef_frees_allocating_out_pairs_producers_and_heap_allocs_free_helpers() -> None:
    dag, model = _make_dag_model(
        {
            "demo.c#apply_sec": {
                "name": "apply_sec",
                "file": "demo.c",
                "signature": "int(const unsigned char *,unsigned short,unsigned char **,unsigned short *)",
                "formals": _formals(
                    ("in_frame", "const_pointer"),
                    ("in_len", "value"),
                    ("pp_out_frame", "pointer"),
                    ("p_out_len", "pointer"),
                ),
                "call_sites": [{"callee": "calloc"}],
            },
            "demo.c#get_view": {
                "name": "get_view",
                "file": "demo.c",
                "signature": "int(unsigned char **,unsigned short *)",
                "formals": _formals(("pp_out", "pointer"), ("p_len", "pointer")),
                "call_sites": [{"callee": "malloc"}],
            },
            "demo.c#deep_copy_str": {
                "name": "deep_copy_str",
                "file": "demo.c",
                "signature": "int(const char *,char **)",
                "formals": _formals(("src", "const_pointer"), ("dst_str", "pointer")),
                "call_sites": [{"callee": "malloc"}],
            },
            "demo.c#copy_cursor": {
                "name": "copy_cursor",
                "file": "demo.c",
                "signature": "int(const char *,char **)",
                "formals": _formals(("src", "const_pointer"), ("endptr", "pointer")),
                "call_sites": [{"callee": "malloc"}],
            },
            "demo.c#prepare_aad": {
                "name": "prepare_aad",
                "file": "demo.c",
                "signature": "unsigned char *(const unsigned char *,unsigned short)",
                "formals": _formals(("buf", "const_pointer"), ("len", "value")),
                "writes": {"globals": [], "params": []},
                "call_sites": [{"callee": "calloc"}],
            },
            "demo.c#find_needle": {
                "name": "find_needle",
                "file": "demo.c",
                "signature": "char *(const char *,const char *)",
                "formals": _formals(("hay", "const_pointer"), ("needle", "const_pointer")),
                "writes": {"globals": [], "params": []},
                "call_sites": [{"callee": "malloc"}],
            },
            "demo.c#safe_free_ptr": {
                "name": "safe_free_ptr",
                "file": "demo.c",
                "signature": "void(void *)",
                "formals": _formals(("ptr", "pointer")),
                "call_sites": [{"callee": "free"}],
            },
        },
        [
            "demo.c#apply_sec",
            "demo.c#get_view",
            "demo.c#deep_copy_str",
            "demo.c#copy_cursor",
            "demo.c#prepare_aad",
            "demo.c#find_needle",
            "demo.c#safe_free_ptr",
        ],
    )
    res = ah.plan(dag, model, "libdemo", "libdemo.so", SPARE)
    by_fn = {lay["calls"][0]: st for lay, st in zip(res["layouts"], res["cases"], strict=True)}
    # Allocating `(byte **, len *)` out-pair is declared as a pointer (never a static byte array) and freed.
    assert "unsigned char * c0a2;" in by_fn["apply_sec"]
    assert "free(c0a2);" in by_fn["apply_sec"]
    # Borrowed getter `get_view` is NOT freed (avoids double-free on internal slices missing `const`).
    assert "free(" not in by_fn["get_view"]
    # Allocating `deep_copy_str` frees `char **` output; cursor `endptr` does NOT.
    assert "free(c0a1);" in by_fn["deep_copy_str"]
    assert "free(" not in by_fn["copy_cursor"]
    # Direct-allocating non-global producer `prepare_aad` frees its return; `find_needle` does NOT.
    assert "void *c0r = (void *)prepare_aad(" in by_fn["prepare_aad"]
    assert "free(c0r);" in by_fn["prepare_aad"]
    assert "free(" not in by_fn["find_needle"]
    # Single-arg freeing helper gets a heap `calloc(1, 64U)`, never a `static` array.
    assert "unsigned char *c0a0 = (unsigned char *)calloc(1, 64U);" in by_fn["safe_free_ptr"]
    assert "static _Alignas(16)" not in by_fn["safe_free_ptr"]


# ---------------------------------------------------------------------------------------------------
# Docker: real generate_harness --api + exact-bounds 1-byte over-read caught by ASan AND E-ACSL + Eva
# ---------------------------------------------------------------------------------------------------

NONCONST_LIB_H = """\
#ifndef NONCONST_LIB_H
#define NONCONST_LIB_H
#include <stddef.h>
#include <stdint.h>

struct proc_out {
    uint8_t tag;
    uint16_t payload_len;
};

int demo_init(uint8_t expected_scid);
int demo_apply_inplace(uint8_t *pTfBuffer, uint16_t len_ingest);
int demo_proc_tc(uint8_t *ingest, int *len_ingest, struct proc_out *out);
int demo_get_reply(uint8_t *reply, uint16_t *reply_len);
int demo_shutdown(void);
#endif
"""

NONCONST_LIB_C = """\
#include "nonconst_lib.h"
#if defined(__linux__) && !defined(__FRAMAC__)
#include <malloc.h>
#endif
#include <stdio.h>
#include <stdlib.h>

static int g_ready = 0;
static uint8_t g_scid = 0;
static void *g_state = NULL;

static int check_buf_size(uint8_t *buf, uint16_t required) {
#if defined(__linux__) && !defined(__FRAMAC__)
    if (malloc_usable_size(buf) < required) return -10;
#else
    (void)buf;
    (void)required;
#endif
    return 0;
}

int demo_init(uint8_t expected_scid) {
    if (g_state) free(g_state);
    g_state = malloc(32);
    if (!g_state) return -1;
    g_scid = expected_scid;
    g_ready = 1;
    return 0;
}

int demo_apply_inplace(uint8_t *pTfBuffer, uint16_t len_ingest) {
    if (!g_ready || !pTfBuffer) return -1;
    if (len_ingest < 8) return -2;
    if (pTfBuffer[0] != g_scid) return -3;
    if (check_buf_size(pTfBuffer, 64) != 0) return -4;
    pTfBuffer[0] ^= 0x55;
    puts("REACHED_APPLY_INPLACE");
    return 0;
}

int demo_proc_tc(uint8_t *ingest, int *len_ingest, struct proc_out *out) {
    if (!g_ready || !ingest || !len_ingest || !out) return -1;
    if (*len_ingest < 5) return -2;
    /* Recall bug pattern (CRYPTOLIB-01): 5-byte frame 0003000424 reads ingest[5] past frame end. */
    if (ingest[0] == 0x00 && ingest[1] == 0x03 && ingest[2] == 0x00 && ingest[3] == 0x04 && ingest[4] == 0x24) {
        int byte_idx = 5;
        out->tag = ingest[byte_idx];
        return 0;
    }
    if (*len_ingest < 8) return -2;
    if (ingest[0] != 0x20 || ingest[1] != g_scid) return -3;
    out->tag = ingest[2];
    out->payload_len = (uint16_t)(*len_ingest - 2);
    *len_ingest = *len_ingest - 2;
    puts("REACHED_PROC_TC");
    return 0;
}

int demo_get_reply(uint8_t *reply, uint16_t *reply_len) {
    if (!reply || !reply_len) return -1;
    reply[0] = 0xAA;
    *reply_len = 1;
    return 0;
}

int demo_shutdown(void) {
    free(g_state);
    g_state = NULL;
    g_ready = 0;
    g_scid = 0;
    return 0;
}
"""

NONCONST_TEST_C = """\
#include "nonconst_lib.h"
#include <stdlib.h>
#include <string.h>

int main(void) {
    demo_init(44);
    uint8_t *tm = (uint8_t *)calloc(1, 64);
    tm[0] = 44; tm[1] = 0x11; tm[2] = 0x22; tm[7] = 0x77;
    demo_apply_inplace(tm, 12);
    free(tm);
    demo_shutdown();

    demo_init(44);
    uint8_t tc[16] = {0x20, 44, 0x99, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
    int tc_len = 12;
    struct proc_out out;
    memset(&out, 0, sizeof(out));
    demo_proc_tc(tc, &tc_len, &out);
    demo_shutdown();
    return 0;
}
"""

DOCKER_DRIVER_PY = r"""
import json, os, pathlib, subprocess, sys
sys.path.insert(0, "/repo/scripts")
import seed_harvest as sh

work = pathlib.Path("/tmp/nonconst_test")
ws_work = work / "workspace" / "work"
ws_reports = work / "workspace" / "reports"
ws_seeds = work / "workspace" / "seed_records"
ws_harnesses = work / "workspace" / "harnesses"
for d in (ws_work, ws_reports, ws_seeds, ws_harnesses):
    d.mkdir(parents=True, exist_ok=True)
os.chdir(work)

# 1. Compile and run test binary with seed_harvest recorder runtime + wrappers (`fc_mem_lenptr`).
plans = [
    sh.plan_function("demo_init", "int(unsigned char)", names=["expected_scid"]),
    sh.plan_function("demo_apply_inplace", "int(unsigned char *,unsigned short)", names=["pTfBuffer", "len_ingest"]),
    sh.plan_function("demo_proc_tc", "int(unsigned char *,int *,struct proc_out *)", names=["ingest", "len_ingest", "out"]),
    sh.plan_function("demo_shutdown", "int(void)", names=[]),
]
assert all(p["supported"] for p in plans), plans
assert plans[2]["params"][0]["record"] == "bp"

rt_c = work / "fc_rt.c"
wrap_c = work / "fc_wrap.c"
rt_c.write_text(
    sh.RECORDER_RUNTIME % {"cap": 4096, "total": 100000, "max_calls": 100, "funcs": len(plans), "stack": 64},
    encoding="utf-8",
)
wrap_c.write_text(sh.wrapper_source(plans, ["nonconst_lib.h"]), encoding="utf-8")

rec_dir = work / "rec_out"
rec_dir.mkdir()
wrap_flags = [f"-Wl,--wrap={p['name']}" for p in plans]
rec_bin = work / "rec_test"
subprocess.run(
    [
        "clang", "-O1", "-g", f"-I{ws_work}", f'-DFC_OUT_DIR="{rec_dir}"',
        str(ws_work / "test_main.c"), str(ws_work / "nonconst_lib.c"), str(rt_c), str(wrap_c), *wrap_flags,
        "-o", str(rec_bin),
    ],
    check=True,
)
subprocess.run([str(rec_bin)], check=True)

trace = []
for f in sorted(rec_dir.glob("calls-*.txt")):
    for line in f.read_text(encoding="utf-8").splitlines():
        row = sh.parse_record_line(line)
        if row:
            trace.append(row)

tc_calls = [c for c in trace if c["fn"] == "demo_proc_tc"]
assert len(tc_calls) == 1, trace
tc_b = [bytes.fromhex(hx) for k, _off, hx in tc_calls[0]["args"].get("0", []) if k == "b"]
assert len(tc_b) == 1 and len(tc_b[0]) == 12 and tc_b[0][:3] == bytes([0x20, 44, 0x99]), tc_calls[0]

# 2. Write model, DAG, traces and generate a REAL dual-use harness with generate_harness.py --api.
entry_ids = [
    "nonconst_lib.c#demo_init",
    "nonconst_lib.c#demo_apply_inplace",
    "nonconst_lib.c#demo_proc_tc",
    "nonconst_lib.c#demo_get_reply",
    "nonconst_lib.c#demo_shutdown",
]
model = {
    "status": "ok",
    "entry_points": entry_ids,
    "functions": {
        "nonconst_lib.c#check_buf_size": {
            "name": "check_buf_size",
            "file": "nonconst_lib.c",
            "signature": "int(unsigned char *,unsigned short)",
            "formals": [{"name": "buf", "kind": "pointer"}, {"name": "required", "kind": "value"}],
            "writes": {"globals": [], "params": []},
            "global_refs": [],
            "call_sites": [{"callee": "malloc_usable_size"}],
        },
        "nonconst_lib.c#demo_init": {
            "name": "demo_init",
            "file": "nonconst_lib.c",
            "signature": "int(unsigned char)",
            "formals": [{"name": "expected_scid", "kind": "value"}],
            "writes": {"globals": ["g_ready", "g_scid", "g_state"], "params": []},
            "global_refs": ["g_ready", "g_scid", "g_state"],
            "call_sites": [{"callee": "malloc"}, {"callee": "free"}],
        },
        "nonconst_lib.c#demo_apply_inplace": {
            "name": "demo_apply_inplace",
            "file": "nonconst_lib.c",
            "signature": "int(unsigned char *,unsigned short)",
            "formals": [{"name": "pTfBuffer", "kind": "pointer"}, {"name": "len_ingest", "kind": "value"}],
            "writes": {"globals": [], "params": ["pTfBuffer"]},
            "global_refs": ["g_ready", "g_scid"],
            "call_sites": [{"callee": "check_buf_size"}],
        },
        "nonconst_lib.c#demo_proc_tc": {
            "name": "demo_proc_tc",
            "file": "nonconst_lib.c",
            "signature": "int(unsigned char *,int *,struct proc_out *)",
            "formals": [{"name": "ingest", "kind": "pointer"}, {"name": "len_ingest", "kind": "pointer"}, {"name": "out", "kind": "pointer"}],
            "writes": {"globals": [], "params": ["len_ingest", "out"]},
            "global_refs": ["g_ready", "g_scid"],
            "call_sites": [],
        },
        "nonconst_lib.c#demo_get_reply": {
            "name": "demo_get_reply",
            "file": "nonconst_lib.c",
            "signature": "int(unsigned char *,unsigned short *)",
            "formals": [{"name": "reply", "kind": "pointer"}, {"name": "reply_len", "kind": "pointer"}],
            "writes": {"globals": [], "params": ["reply", "reply_len"]},
            "global_refs": [],
            "call_sites": [],
        },
        "nonconst_lib.c#demo_shutdown": {
            "name": "demo_shutdown",
            "file": "nonconst_lib.c",
            "signature": "int(void)",
            "formals": [],
            "writes": {"globals": ["g_ready", "g_scid", "g_state"], "params": []},
            "global_refs": ["g_ready", "g_scid", "g_state"],
            "call_sites": [{"callee": "free"}],
        },
    },
}
dag_fns = {
    fid: {"name": rec["name"], "file": "nonconst_lib.c", "is_static": False, "module": "nonconst", "unit": "libnonconst.so"}
    for fid, rec in model["functions"].items()
}
dag = {
    "module_kind": "link_unit",
    "target_dir": str(ws_work),
    "functions": dag_fns,
    "modules": {
        "nonconst": {
            "unit": "libnonconst.so",
            "files": ["nonconst_lib.c"],
            "functions": list(dag_fns),
            "candidate_entry_points": entry_ids,
            "cppflags": [f"-I{ws_work}"],
        }
    },
    "units": {"libnonconst.so": {"kind": "shared_lib", "functions": list(dag_fns), "entry_points": entry_ids}},
}
(ws_reports / "phase0_model.json").write_text(json.dumps(model), encoding="utf-8")
(ws_reports / "callgraph_dag.json").write_text(json.dumps(dag), encoding="utf-8")
(ws_seeds / "traces.jsonl").write_text(json.dumps({"calls": trace}) + "\n", encoding="utf-8")

subprocess.run(
    [
        "python3", "/repo/scripts/generate_harness.py",
        "--module", "nonconst",
        "--unit", "libnonconst.so",
        "--api",
        "--header", "nonconst_lib.h",
        "--cppflags", f"-I{ws_work}",
        "--max-size", "1024",
        "--out-dir", str(ws_harnesses),
    ],
    check=True,
)
subprocess.run(
    ["python3", "/repo/scripts/validate_artifacts.py", "sidecar", str(ws_harnesses / "harness_nonconst.json")],
    check=True,
)

sidecar = json.loads((ws_harnesses / "harness_nonconst.json").read_text(encoding="utf-8"))
layouts = sidecar["api_cases"]
seeds_by_sel = sh.layout_seeds(layouts, trace, [trace])
apply_sel = next(l["selector"] for l in layouts if l["kind"] == "sequence" and "demo_apply_inplace" in l["calls"])
proc_sel = next(l["selector"] for l in layouts if l["kind"] == "sequence" and "demo_proc_tc" in l["calls"])
assert apply_sel in seeds_by_sel and len(seeds_by_sel[apply_sel]) >= 1, seeds_by_sel
assert proc_sel in seeds_by_sel and len(seeds_by_sel[proc_sel]) >= 1, seeds_by_sel

seed_apply = work / "seed_apply.bin"
seed_proc = work / "seed_proc.bin"
overread_in = work / "overread_5b.bin"
seed_apply.write_bytes(seeds_by_sel[apply_sel][0])
seed_proc.write_bytes(seeds_by_sel[proc_sel][0])
overread_in.write_bytes(bytes([proc_sel]) + bytes.fromhex("0003000424"))

h_c = ws_harnesses / "harness_nonconst.c"
sources = [str(h_c), str(ws_work / "nonconst_lib.c")]

# 3. Build sanitizer binary via run_eacsl_fuzz.py: valid seeds pass (with LSan + malloc_usable_size),
#    and the 5-byte over-read triggers ASan heap-buffer-overflow (READ of size 1) in demo_proc_tc.
san_bin = ws_harnesses / "fuzz_nonconst.sanitizers"
subprocess.run(
    [
        "python3", "/repo/scripts/run_eacsl_fuzz.py", "build",
        "--engine", "sanitizers",
        "--module", "nonconst",
        "--dag", str(ws_reports / "callgraph_dag.json"),
        "--sources", *sources,
        "--cppflags", f"-I{ws_work}",
        "--out-bin", str(san_bin),
        "--out-json", str(work / "san_build.json"),
    ],
    check=True,
)
san_env = {**os.environ, "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1", "UBSAN_OPTIONS": "halt_on_error=1"}
rr = subprocess.run([str(san_bin), str(seed_apply), str(seed_proc)], capture_output=True, text=True, check=True, env=san_env)
assert "REACHED_APPLY_INPLACE" in rr.stdout, rr.stdout
assert "REACHED_PROC_TC" in rr.stdout, rr.stdout

ov_san = subprocess.run([str(san_bin), str(overread_in)], capture_output=True, text=True, env=san_env)
ov_san_out = ov_san.stdout + "\n" + ov_san.stderr
assert ov_san.returncode != 0, f"Expected ASan over-read crash, got rc=0:\n{ov_san_out}"
assert "heap-buffer-overflow" in ov_san_out and "demo_proc_tc" in ov_san_out, ov_san_out

# 4. Build E-ACSL binary via run_eacsl_fuzz.py: valid seeds pass, and the 5-byte over-read fails
#    with E-ACSL's `\valid_read` assertion inside demo_proc_tc.
eacsl_out = ws_harnesses / "fuzz_nonconst"
subprocess.run(
    [
        "python3", "/repo/scripts/run_eacsl_fuzz.py", "build",
        "--engine", "eacsl",
        "--module", "nonconst",
        "--dag", str(ws_reports / "callgraph_dag.json"),
        "--sources", *sources,
        "--cppflags", f"-I{ws_work}",
        "--out-bin", str(eacsl_out),
        "--out-json", str(work / "eacsl_build.json"),
    ],
    check=True,
)
eacsl_meta = json.loads((work / "eacsl_build.json").read_text(encoding="utf-8"))
assert eacsl_meta["status"] == "built", eacsl_meta
eacsl_bin = eacsl_meta["binary"]
er = subprocess.run([eacsl_bin, str(seed_apply), str(seed_proc)], capture_output=True, text=True, check=True)
assert "REACHED_APPLY_INPLACE" in er.stdout, er.stdout
assert "REACHED_PROC_TC" in er.stdout, er.stdout

ov_eacsl = subprocess.run([eacsl_bin, str(overread_in)], capture_output=True, text=True)
ov_eacsl_out = ov_eacsl.stdout + "\n" + ov_eacsl.stderr
assert ov_eacsl.returncode != 0, f"Expected E-ACSL over-read assertion, got rc=0:\n{ov_eacsl_out}"
assert "Assertion failed" in ov_eacsl_out and "demo_proc_tc" in ov_eacsl_out, ov_eacsl_out
assert "\\valid_read" in ov_eacsl_out or "\\initialized" in ov_eacsl_out, ov_eacsl_out

# 5. Parse real dual-use harness with Frama-C Eva!
subprocess.run(
    ["frama-c", "-machdep", "gcc_x86_64", "-main", "eva_main", f"-cpp-extra-args=-I{ws_work}", str(h_c), str(ws_work / "nonconst_lib.c")],
    check=True,
    capture_output=True,
    text=True,
)
print("DOCKER_NONCONST_OK")
"""


@pytest.mark.integration
@pytest.mark.skipif(not DOCKER, reason="set FRAMAC_DOCKER_TESTS=1 to run Docker integration tests")
def test_docker_nonconst_inout_and_lenptr_record_harness_asan_and_eva(tmp_path: Path) -> None:
    (tmp_path / "nonconst_lib.h").write_text(NONCONST_LIB_H, encoding="utf-8", newline="\n")
    (tmp_path / "nonconst_lib.c").write_text(NONCONST_LIB_C, encoding="utf-8", newline="\n")
    (tmp_path / "test_main.c").write_text(NONCONST_TEST_C, encoding="utf-8", newline="\n")

    setup_and_run = (
        "import pathlib, shutil\n"
        "dst = pathlib.Path('/tmp/nonconst_test/workspace/work')\n"
        "dst.mkdir(parents=True, exist_ok=True)\n"
        "for f in pathlib.Path('/src').iterdir():\n"
        "    shutil.copy2(f, dst / f.name)\n" + DOCKER_DRIVER_PY
    )
    proc = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "-i",
            "-v",
            f"{REPO_ROOT}:/repo:ro",
            "-v",
            f"{tmp_path}:/src:ro",
            IMAGE,
            "python3",
            "-",
        ],
        input=setup_and_run,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=240,
    )
    assert proc.returncode == 0, f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    assert "DOCKER_NONCONST_OK" in proc.stdout
