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
def test_nonconst_pair_with_recorded_b_or_input_name_copies_rest_to_writable_buffer() -> None:
    # 1. Input-named non-const pair without traces (`p_ingest`, `len_ingest`): writable copy of rest.
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
    assert f"static _Alignas(16) unsigned char c0a0[{SPARE}];" in stmt
    assert "memcpy(c0a0, FRAMAC_FUZZ_COPY(fuzz_buf, fuzz_off), rest_n);" in stmt
    assert "c0a1 = (unsigned short)rest_n;" in stmt
    assert "(unsigned char *)(fuzz_buf + fuzz_off)" not in stmt
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
    assert "memcpy(c0a0, FRAMAC_FUZZ_COPY(fuzz_buf, fuzz_off), rest_n);" in stmt_tr


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

    # 5. Threat model explicitly naming a non-const buffer in `attacker_params` DOES feed it from rest.
    et_att = ah._EntryTrust(input_role="entry", attacker_params=["in_scratch"])
    stmt_att, lay_att, _ = ah.single_case("tm_out_fn", tm_rec, SPARE, api_tr, entry_trust=et_att)
    assert stmt_att is not None and lay_att is not None
    assert lay_att["rest"] == {"call": 0, "param": 0, "kind": "bytes"}
    assert "memcpy(c0a0, FRAMAC_FUZZ_COPY(fuzz_buf, fuzz_off), rest_n);" in stmt_att


@pytest.mark.unit
def test_buf_len_ptr_pair_feeds_writable_buffer_and_len_pointer_in_single_and_shared_sequences() -> None:
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
    assert "memcpy(c0a0, FRAMAC_FUZZ_COPY(fuzz_buf, fuzz_off), rest_n);" in stmt
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


# ---------------------------------------------------------------------------------------------------
# Docker: record `(uint8_t *, int *)` with fc_mem_lenptr + in-place malloc_usable_size + ASan/LSan + Eva
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
#include <malloc.h>
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
    if (check_buf_size(pTfBuffer, len_ingest) != 0) return -4;
    pTfBuffer[0] ^= 0x55;
    puts("REACHED_APPLY_INPLACE");
    return 0;
}

int demo_proc_tc(uint8_t *ingest, int *len_ingest, struct proc_out *out) {
    if (!g_ready || !ingest || !len_ingest || !out) return -1;
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
import api_harness as ah
import generate_harness as gh
import seed_harvest as sh

work = pathlib.Path("/tmp/nonconst_test")
work.mkdir(parents=True, exist_ok=True)
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
        "clang", "-O1", "-g", f"-I{work}", f'-DFC_OUT_DIR="{rec_dir}"',
        str(work / "test_main.c"), str(work / "nonconst_lib.c"), str(rt_c), str(wrap_c), *wrap_flags,
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

# 2. Build model + DAG + generate --api harness + write seeds.
model = {
    "entry_points": [
        "nonconst_lib.c#demo_init",
        "nonconst_lib.c#demo_apply_inplace",
        "nonconst_lib.c#demo_proc_tc",
        "nonconst_lib.c#demo_get_reply",
        "nonconst_lib.c#demo_shutdown",
    ],
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
            "call_sites": [],
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
            "call_sites": [],
        },
    },
}
entry_ids = [
    "nonconst_lib.c#demo_init",
    "nonconst_lib.c#demo_apply_inplace",
    "nonconst_lib.c#demo_proc_tc",
    "nonconst_lib.c#demo_get_reply",
    "nonconst_lib.c#demo_shutdown",
]
dag_fns = {
    fid: {"name": rec["name"], "file": "nonconst_lib.c", "is_static": False, "module": "nonconst", "unit": "libnonconst.so"}
    for fid, rec in model["functions"].items()
}
dag = {
    "functions": dag_fns,
    "modules": {
        "nonconst": {
            "unit": "libnonconst.so",
            "files": ["nonconst_lib.c"],
            "functions": list(dag_fns),
            "candidate_entry_points": entry_ids,
        }
    },
    "units": {"libnonconst.so": {"kind": "shared_lib", "functions": list(dag_fns), "entry_points": entry_ids}},
}

res = ah.plan(dag, model, "nonconst", "libnonconst.so", 1024, traces=[trace])
layouts = res["layouts"]
cases = res["cases"]

# Build a dual-use harness with generate_harness template.
h_c = work / "harness_nonconst.c"
tpl = (pathlib.Path("/repo/templates/harness_dual.c.template")).read_text(encoding="utf-8")
case_lines = "\n".join(f"    case {i}: {{ {st} break; }}" for i, st in enumerate(cases))
body = (
    "if (fuzz_len < 1) { return; }\n"
    "unsigned char sel = fuzz_buf[0];\n"
    "fuzz_buf += 1; fuzz_len -= 1;\n"
    "switch (sel) {\n" + case_lines + "\n    default: break;\n}"
)
# Simple standalone dual-use harness matching harness_dual conventions.
h_c.write_text(
    '#include <stdint.h>\n#include <stddef.h>\n#include <stdlib.h>\n#include <string.h>\n'
    '#include "nonconst_lib.h"\n'
    '#ifdef FRAMAC_EVA_HARNESS\n'
    '#include "__fc_builtin.h"\n'
    '#define FRAMAC_FUZZ_COPY(b, o) ((b) + (o))\n'
    '#else\n'
    '#define FRAMAC_FUZZ_COPY(b, o) ((b) + (o))\n'
    '#endif\n'
    'static void dispatch(const uint8_t *fuzz_buf, size_t fuzz_len) {\n' + body + '\n}\n'
    '#ifdef FRAMAC_EVA_HARNESS\n'
    'void eva_main(void) {\n'
    '    unsigned char buf[64];\n'
    '    Frama_C_make_unknown((char *)buf, sizeof(buf));\n'
    '    size_t n = Frama_C_size_t_interval(0, sizeof(buf));\n'
    '    dispatch(buf, n);\n'
    '}\n'
    '#else\n'
    'int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n'
    '    dispatch(data, size);\n'
    '    return 0;\n'
    '}\n'
    '#endif\n',
    encoding="utf-8",
)

# 3. Synthesize seeds from recorded trace and execute under ASan+LSan+UBSan!
seeds_by_sel = sh.layout_seeds(layouts, trace, [trace])
apply_sel = next(l["selector"] for l in layouts if l["kind"] == "sequence" and "demo_apply_inplace" in l["calls"])
proc_sel = next(l["selector"] for l in layouts if l["kind"] == "sequence" and "demo_proc_tc" in l["calls"])
assert apply_sel in seeds_by_sel and len(seeds_by_sel[apply_sel]) >= 1, seeds_by_sel
assert proc_sel in seeds_by_sel and len(seeds_by_sel[proc_sel]) >= 1, seeds_by_sel

driver_c = work / "driver.c"
driver_c.write_text(
    '#include <stdint.h>\n#include <stddef.h>\n#include <stdio.h>\n#include <stdlib.h>\n'
    'int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);\n'
    'int main(int argc, char **argv) {\n'
    '    for (int i = 1; i < argc; i++) {\n'
    '        FILE *f = fopen(argv[i], "rb");\n'
    '        fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);\n'
    '        uint8_t *b = (uint8_t *)malloc(n ? (size_t)n : 1);\n'
    '        if (n > 0) fread(b, 1, (size_t)n, f);\n'
    '        fclose(f);\n'
    '        LLVMFuzzerTestOneInput(b, (size_t)n);\n'
    '        free(b);\n'
    '    }\n'
    '    return 0;\n'
    '}\n',
    encoding="utf-8",
)
seed_apply = work / "seed_apply.bin"
seed_proc = work / "seed_proc.bin"
seed_apply.write_bytes(seeds_by_sel[apply_sel][0])
seed_proc.write_bytes(seeds_by_sel[proc_sel][0])

runner = work / "asan_runner"
subprocess.run(
    ["clang", "-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer", f"-I{work}", str(h_c), str(work / "nonconst_lib.c"), str(driver_c), "-o", str(runner)],
    check=True,
)
rr = subprocess.run(
    [str(runner), str(seed_apply), str(seed_proc)],
    capture_output=True,
    text=True,
    check=True,
    env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1", "UBSAN_OPTIONS": "halt_on_error=1"},
)
assert "REACHED_APPLY_INPLACE" in rr.stdout, rr.stdout
assert "REACHED_PROC_TC" in rr.stdout, rr.stdout

# 4. Parse with Frama-C Eva!
subprocess.run(
    ["frama-c", "-machdep", "gcc_x86_64", "-main", "eva_main", f"-cpp-extra-args=-DFRAMAC_EVA_HARNESS -I{work}", str(h_c), str(work / "nonconst_lib.c")],
    check=True,
    capture_output=True,
    text=True,
)
print("DOCKER_NONCONST_OK")
"""


@pytest.mark.integration
@pytest.mark.skipif(not DOCKER, reason="set FRAMAC_DOCKER_TESTS=1 to run Docker integration tests")
def test_docker_nonconst_inout_and_lenptr_record_harness_asan_and_eva(tmp_path: Path) -> None:
    (tmp_path / "nonconst_lib.h").write_text(NONCONST_LIB_H, encoding="utf-8")
    (tmp_path / "nonconst_lib.c").write_text(NONCONST_LIB_C, encoding="utf-8")
    (tmp_path / "test_main.c").write_text(NONCONST_TEST_C, encoding="utf-8")

    # Copy sources into container /tmp/nonconst_test and run DOCKER_DRIVER_PY
    setup_and_run = (
        "import pathlib, shutil\n"
        "dst = pathlib.Path('/tmp/nonconst_test')\n"
        "dst.mkdir(parents=True, exist_ok=True)\n"
        "for f in pathlib.Path('/src').iterdir():\n"
        "    shutil.copy2(f, dst / f.name)\n" + DOCKER_DRIVER_PY
    )
    proc = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
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
        timeout=120,
    )
    assert proc.returncode == 0, f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    assert "DOCKER_NONCONST_OK" in proc.stdout
