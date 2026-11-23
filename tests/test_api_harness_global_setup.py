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

    # seed_harvest.layout_seeds produces the recorded frame seed for this sequence selector.
    layouts = [{**x, "selector": idx} for idx, x in enumerate(res["layouts"])]
    seeds = sh.layout_seeds(layouts, [], traces)
    assert seeds[sel] == [bytes([sel]) + bytes.fromhex("deadbeef")]


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
    # Earlier lib_init_unit_test is trimmed; repeated lib_add_param collapsed so lib_config stays!
    assert lay["calls"] == ["lib_config", "lib_add_param", "lib_init", "lib_process", "lib_shutdown"]
    assert "0x22, 0x00" in stmt


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
