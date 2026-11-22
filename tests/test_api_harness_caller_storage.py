"""Tests for W1-A: trusted caller-owned writable scratch/output buffer builder (S2 generalization)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import api_harness as ah
from validate_artifacts import validate_sidecar

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Helpers to construct minimal DAG / model / struct-layout fixtures
# ---------------------------------------------------------------------------


def _useful_buf_layout(*, reversed_order: bool = False, const_ptr: bool = False, bytes_flag: bool | None = True) -> dict[str, Any]:
    ptr_field: dict[str, Any] = {
        "name": "ptr",
        "kind": "ptr",
        "off": 8 if reversed_order else 0,
        "size": 8,
        "pointers": True,
        "const": const_ptr,
    }
    if bytes_flag is not None:
        ptr_field["bytes"] = bytes_flag
    len_field: dict[str, Any] = {
        "name": "len",
        "kind": "int",
        "off": 0 if reversed_order else 8,
        "size": 8,
        "pointers": False,
        "ctype": "unsigned long",
    }
    return {
        "what": "struct",
        "size": 16,
        "align": 8,
        "pointers": True,
        "fields": [len_field, ptr_field] if reversed_order else [ptr_field, len_field],
    }


def _make_fixture(
    fns: dict[str, tuple[str, list[tuple[str, str]], list[str] | None]],
    layouts: dict[str, dict[str, Any]],
    *,
    role: str = "entry",
    global_variables: dict[str, dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, dict[str, Any]]]:
    """
    Build a minimal DAG, Phase 0 model, and struct-layouts mapping.
    `fns` maps `fn_name -> (signature, [(formal_name, formal_kind), ...], attacker_params_or_None)`.
    """
    dag_fns: dict[str, dict[str, Any]] = {}
    model_fns: dict[str, dict[str, Any]] = {}
    input_sources: list[dict[str, Any]] = []
    for fn, (sig, formals, att_params) in fns.items():
        key = f"lib.c#{fn}"
        dag_fns[key] = {"name": fn, "file": "lib.c", "is_static": False, "module": "lib"}
        if att_params is not None:
            dag_fns[key]["trust"] = {
                "value": "untrusted",
                "source": "threat_model",
                "input_role": role,
                "attacker_params": list(att_params),
            }
            input_sources.append({"function": fn, "role": role, "params": list(att_params), "description": fn})
        model_fns[key] = {
            "name": fn,
            "file": "lib.c",
            "signature": sig,
            "formals": [{"name": n, "kind": k} for n, k in formals],
        }
    tm_block: dict[str, Any] = {"status": "ok", "input_sources": input_sources}
    gvars = dict(global_variables or {})
    dag: dict[str, Any] = {
        "module_kind": "link_unit",
        "trust": {"threat_model": tm_block},
        "modules": {"lib": {"candidate_entry_points": list(dag_fns), "functions": list(dag_fns), "files": ["lib.c"]}},
        "functions": dag_fns,
        "global_variables": gvars,
    }
    model: dict[str, Any] = {
        "status": "ok",
        "trust": {"threat_model": tm_block},
        "units": {"lib": {"kind": "static_lib", "test": False, "files": ["lib.c"], "links": []}},
        "functions": model_fns,
        "global_variables": gvars,
    }
    return dag, model, layouts


def _case_for(planned: dict[str, Any], fn: str) -> tuple[str, dict[str, Any]]:
    matches = [
        (stmt, lay)
        for stmt, lay in zip(planned["cases"], planned["layouts"], strict=True)
        if lay["kind"] == "single" and lay["calls"] == [fn]
    ]
    assert len(matches) == 1, f"expected 1 single case for {fn}, got {len(matches)}; skipped={planned['skipped']}"
    return matches[0]


# ---------------------------------------------------------------------------
# Shape (a): Trusted by-value writable buffer structs ({ptr, len} and {len, ptr})
# ---------------------------------------------------------------------------


def test_byval_writable_struct_ptr_len_order(monkeypatch: pytest.MonkeyPatch):
    """QCBOR `UsefulBuf { void *ptr; size_t len; }` passed by value as a trusted caller-storage buffer."""
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _make_fixture(
        {
            "encode_head": (
                "struct q_useful_buf_c(struct q_useful_buf,unsigned char,unsigned long)",
                [("Buffer", "value"), ("uMajorType", "value"), ("uArgument", "value")],
                ["uMajorType", "uArgument"],
            ),
        },
        {
            "struct q_useful_buf": _useful_buf_layout(reversed_order=False, const_ptr=False),
            "struct q_useful_buf_c": _useful_buf_layout(reversed_order=False, const_ptr=True),
        },
    )

    planned = ah.plan(dag, model, "lib", "lib", 256, struct_layouts=layouts)
    assert "lib.c#encode_head" not in planned["auto_exempt"]
    assert "lib.c#encode_head" not in planned["skipped"]

    stmt, lay = _case_for(planned, "encode_head")
    spare = ah.spare_bytes(256)
    assert f"_Alignas(16) unsigned char c0a0_buf[{spare}]; memset(c0a0_buf, 0, sizeof(c0a0_buf));" in stmt
    assert "struct q_useful_buf c0a0; memset(&c0a0, 0, sizeof(c0a0));" in stmt
    assert "c0a0.ptr = (void *)c0a0_buf; c0a0.len = (unsigned long)sizeof(c0a0_buf);" in stmt
    assert "(void)encode_head(c0a0, c0a1, c0a2);" in stmt
    # Buffer is fixed-capacity harness storage: no fuzz slot on param 0, only on attacker params 1 & 2.
    assert [s["param"] for s in lay["slots"]] == [1, 2]
    assert any(f"argument 0: {ah.CALLER_STORAGE_NOTE}" in n for n in lay.get("notes") or [])


def test_byval_writable_struct_len_ptr_order_and_byte_pointees(monkeypatch: pytest.MonkeyPatch):
    """`{len, ptr}` field order (writable `ngx_str_t` shape) and `uint8_t *` / `char *` / `unsigned char *` pointees."""
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    rev_layout = {
        "what": "struct",
        "size": 16,
        "align": 8,
        "pointers": True,
        "fields": [
            {"name": "cap", "kind": "int", "off": 0, "size": 8, "pointers": False, "ctype": "unsigned long"},
            {"name": "data", "kind": "ptr", "off": 8, "size": 8, "pointers": True, "const": False, "bytes": True},
        ],
    }
    pointee_layout = {
        "what": "struct",
        "size": 16,
        "align": 8,
        "pointers": True,
        "fields": [
            {"name": "buf_size", "kind": "int", "off": 0, "size": 4, "pointers": False, "ctype": "unsigned int"},
            {
                "name": "buf",
                "kind": "ptr",
                "off": 8,
                "size": 8,
                "pointers": True,
                "const": False,
                "pointee": "uint8_t",
            },
        ],
    }
    dag, model, layouts = _make_fixture(
        {
            "copy_rev": (
                "int(unsigned char *,unsigned long,struct rev_buf)",
                [("src", "const_pointer"), ("src_len", "value"), ("dst", "value")],
                ["src"],
            ),
            "copy_u8": (
                "int(unsigned char *,unsigned long,struct u8_buf)",
                [("src", "const_pointer"), ("src_len", "value"), ("dst", "value")],
                ["src"],
            ),
        },
        {"struct rev_buf": rev_layout, "struct u8_buf": pointee_layout},
    )

    planned = ah.plan(dag, model, "lib", "lib", 256, struct_layouts=layouts)
    spare = ah.spare_bytes(256)

    stmt_rev, lay_rev = _case_for(planned, "copy_rev")
    assert f"_Alignas(16) unsigned char c0a2_buf[{spare}]; memset(c0a2_buf, 0, sizeof(c0a2_buf));" in stmt_rev
    assert "c0a2.data = (void *)c0a2_buf; c0a2.cap = (unsigned long)sizeof(c0a2_buf);" in stmt_rev
    assert lay_rev["rest"] == {"call": 0, "param": 0, "kind": "bytes"}
    assert lay_rev["slots"] == []
    assert any(f"argument 2: {ah.CALLER_STORAGE_NOTE}" in n for n in lay_rev.get("notes") or [])

    stmt_u8, lay_u8 = _case_for(planned, "copy_u8")
    assert f"_Alignas(16) unsigned char c0a2_buf[{spare}]; memset(c0a2_buf, 0, sizeof(c0a2_buf));" in stmt_u8
    assert "c0a2.buf = (void *)c0a2_buf; c0a2.buf_size = (unsigned int)sizeof(c0a2_buf);" in stmt_u8
    assert lay_u8["rest"] == {"call": 0, "param": 0, "kind": "bytes"}
    assert any(f"argument 2: {ah.CALLER_STORAGE_NOTE}" in n for n in lay_u8.get("notes") or [])


def test_byval_caller_storage_with_ctx_initializer_preserves_builder_rest(monkeypatch: pytest.MonkeyPatch):
    """
    QCBOR `GetTBigNumberInMapSZ` shape: decoder context initialized via `dec_init`, trusted `const char *szLabel`
    bound to a literal, AND trusted `UsefulBuf BigNumberBuf` backed by a fixed harness array.
    `dec_init` must still claim whole-input `rest`.
    """
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _make_fixture(
        {
            "dec_init": (
                "void(struct dec_ctx *,unsigned char *,unsigned long)",
                [("pMe", "pointer"), ("in", "const_pointer"), ("in_len", "value")],
                None,
            ),
            "get_bignum_in_map_sz": (
                "void(struct dec_ctx *,char *,struct q_useful_buf,struct q_useful_buf_c *,_Bool *)",
                [
                    ("pMe", "pointer"),
                    ("szLabel", "const_pointer"),
                    ("BigNumberBuf", "value"),
                    ("pBigNumber", "pointer"),
                    ("pbIsNegative", "pointer"),
                ],
                ["pMe", "pBigNumber"],
            ),
        },
        {
            "struct dec_ctx": {
                "what": "struct",
                "size": 8,
                "align": 4,
                "pointers": False,
                "fields": [{"name": "pos", "kind": "int", "off": 0, "size": 4, "pointers": False, "ctype": "int"}],
            },
            "struct q_useful_buf": _useful_buf_layout(const_ptr=False),
            "struct q_useful_buf_c": _useful_buf_layout(const_ptr=True),
        },
    )

    planned = ah.plan(dag, model, "lib", "lib", 256, struct_layouts=layouts)
    assert "lib.c#get_bignum_in_map_sz" not in planned["auto_exempt"]
    stmt, lay = _case_for(planned, "get_bignum_in_map_sz")
    assert lay["builder"] == "dec_init"
    assert lay["rest"] == {"call": 1, "param": 1, "kind": "bytes"}
    assert f'(char *)"{ah.TRUSTED_STRING_DEFAULT}"' in stmt
    assert "c0a2.ptr = (void *)c0a2_buf; c0a2.len = (unsigned long)sizeof(c0a2_buf);" in stmt
    assert any(f"argument 2: {ah.CALLER_STORAGE_NOTE}" in n for n in lay.get("notes") or [])


def test_byval_caller_storage_combines_with_schema_instance_expansion(monkeypatch: pytest.MonkeyPatch):
    """A function taking both a trusted S3 schema descriptor and a trusted `UsefulBuf` expands schema cases cleanly."""
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    gvars = {
        "schema.pb.c#MsgA_desc": {
            "name": "MsgA_desc",
            "file": "schema.pb.c",
            "static": False,
            "const": True,
            "has_init": True,
            "type": "struct schema_desc",
            "raw_type": "const struct schema_desc",
            "size": 64,
            "units": ["lib"],
        },
    }
    dag, model, layouts = _make_fixture(
        {
            "decode_with_scratch": (
                "int(struct schema_desc *,unsigned char *,unsigned long,struct q_useful_buf)",
                [
                    ("desc", "const_pointer"),
                    ("wire", "const_pointer"),
                    ("wire_len", "value"),
                    ("scratch", "value"),
                ],
                ["wire"],
            ),
        },
        {
            "struct schema_desc": {
                "what": "struct",
                "size": 16,
                "align": 8,
                "pointers": True,
                "fields": [
                    {"name": "count", "kind": "int", "off": 0, "size": 4, "pointers": False, "ctype": "unsigned int"},
                    {"name": "fields", "kind": "ptr", "off": 8, "size": 8, "pointers": True, "const": True},
                ],
            },
            "struct q_useful_buf": _useful_buf_layout(const_ptr=False),
        },
        global_variables=gvars,
    )

    planned = ah.plan(dag, model, "lib", "lib", 256, struct_layouts=layouts)
    stmt, lay = _case_for(planned, "decode_with_scratch")
    assert lay["schema_instance"] == "MsgA_desc"
    assert "&MsgA_desc" in stmt
    assert "c0a3.ptr = (void *)c0a3_buf; c0a3.len = (unsigned long)sizeof(c0a3_buf);" in stmt
    assert lay["rest"] == {"call": 0, "param": 1, "kind": "bytes"}


# ---------------------------------------------------------------------------
# Shape (b): Trusted writable `(void */byte *, size_t)` scratch pairs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ptr_type", ["void *", "unsigned char *", "char *"])
def test_trusted_writable_ptr_len_pair_fixed_capacity(monkeypatch: pytest.MonkeyPatch, ptr_type: str):
    """
    A trusted writable `(void */byte *, size_t)` scratch pair where neither pointer nor length is
    marked attacker-controlled gets a fixed `_Alignas(16)` array and `sizeof(<var>_buf)` (never 0!).
    """
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _make_fixture(
        {
            "decode_into": (
                f"int(unsigned char *,unsigned long,{ptr_type},unsigned long)",
                [
                    ("in_buf", "const_pointer"),
                    ("in_len", "value"),
                    ("scratch", "pointer"),
                    ("scratch_len", "value"),
                ],
                ["in_buf"],
            ),
        },
        {},
    )

    planned = ah.plan(dag, model, "lib", "lib", 256, struct_layouts=layouts)
    assert "lib.c#decode_into" not in planned["auto_exempt"]
    stmt, lay = _case_for(planned, "decode_into")
    spare = ah.spare_bytes(256)
    assert f"_Alignas(16) unsigned char c0a2_buf[{spare}]; memset(c0a2_buf, 0, sizeof(c0a2_buf));" in stmt
    assert "unsigned long c0a3 = (unsigned long)sizeof(c0a2_buf);" in stmt
    assert f"({ptr_type})c0a2_buf, c0a3);" in stmt
    # Neither scratch nor scratch_len consumes fuzz slots; attacker `in_buf` still claims rest.
    assert lay["slots"] == []
    assert lay["rest"] == {"call": 0, "param": 0, "kind": "bytes"}
    assert any(f"argument 2: {ah.CALLER_STORAGE_NOTE}" in n for n in lay.get("notes") or [])


def test_trusted_writable_ptr_len_pair_attacker_sized_clamps_to_buffer(monkeypatch: pytest.MonkeyPatch):
    """
    When the length parameter of a writable scratch pair is explicitly marked attacker-sized
    (`attacker_params` includes `scratch_len` but not `scratch`), the length is fuzzed and clamped
    to `0..sizeof(<var>_buf)`, while the pointer stays the harness-owned array (never forged).
    """
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _make_fixture(
        {
            "decode_sized": (
                "int(unsigned char *,unsigned long,void *,unsigned long)",
                [
                    ("in_buf", "const_pointer"),
                    ("in_len", "value"),
                    ("scratch", "pointer"),
                    ("scratch_len", "value"),
                ],
                ["in_buf", "scratch_len"],
            ),
        },
        {},
    )

    planned = ah.plan(dag, model, "lib", "lib", 256, struct_layouts=layouts)
    stmt, lay = _case_for(planned, "decode_sized")
    spare = ah.spare_bytes(256)
    assert f"_Alignas(16) unsigned char c0a2_buf[{spare}]; memset(c0a2_buf, 0, sizeof(c0a2_buf));" in stmt
    assert "if ((unsigned long long)c0a3 > sizeof(c0a2_buf)) { c0a3 = (unsigned long)sizeof(c0a2_buf); }" in stmt
    assert "(void *)c0a2_buf, c0a3);" in stmt
    assert [s["param"] for s in lay["slots"]] == [3]
    assert lay["rest"] == {"call": 0, "param": 0, "kind": "bytes"}
    assert any(ah.CALLER_STORAGE_NOTE in n and "attacker-sized" in n for n in lay.get("notes") or [])


def test_writable_ptr_beside_non_length_trusted_scalar_keeps_scalar_zeroed(monkeypatch: pytest.MonkeyPatch):
    """`(void *out, unsigned int flags)` is NOT a `(buf, len)` pair: `flags` stays zeroed, not `sizeof(buf)`."""
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _make_fixture(
        {
            "parse_flags": (
                "int(unsigned char *,unsigned long,void *,unsigned int)",
                [
                    ("in_buf", "const_pointer"),
                    ("in_len", "value"),
                    ("out_buf", "pointer"),
                    ("uFlags", "value"),
                ],
                ["in_buf"],
            ),
        },
        {},
    )

    planned = ah.plan(dag, model, "lib", "lib", 256, struct_layouts=layouts)
    stmt, lay = _case_for(planned, "parse_flags")
    assert "unsigned int c0a3; memset(&c0a3, 0, sizeof(c0a3));" in stmt
    assert "sizeof(c0a2_buf)" not in stmt
    assert not any(ah.CALLER_STORAGE_NOTE in n for n in lay.get("notes") or [])


# ---------------------------------------------------------------------------
# Negative tests: read-only / const / multi-ptr / fnptr / opaque / state stay exempt
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fn_name", "param_name", "sig", "formals", "extra_layouts"),
    [
        (
            "takes_const_buf_ptr_len",
            "ROBuf",
            "int(unsigned long,struct q_useful_buf_c)",
            [("uOffset", "value"), ("ROBuf", "value")],
            {"struct q_useful_buf_c": _useful_buf_layout(reversed_order=False, const_ptr=True)},
        ),
        (
            "takes_const_buf_len_ptr",
            "ROBufRev",
            "int(unsigned long,struct ro_rev_buf)",
            [("uOffset", "value"), ("ROBufRev", "value")],
            {"struct ro_rev_buf": _useful_buf_layout(reversed_order=True, const_ptr=True)},
        ),
        (
            "takes_multi_ptr_struct",
            "MultiBuf",
            "int(unsigned long,struct multi_ptr)",
            [("uOffset", "value"), ("MultiBuf", "value")],
            {
                "struct multi_ptr": {
                    "what": "struct",
                    "size": 24,
                    "align": 8,
                    "pointers": True,
                    "fields": [
                        {"name": "p1", "kind": "ptr", "off": 0, "size": 8, "pointers": True, "const": False, "bytes": True},
                        {"name": "p2", "kind": "ptr", "off": 8, "size": 8, "pointers": True, "const": False, "bytes": True},
                        {"name": "len", "kind": "int", "off": 16, "size": 8, "pointers": False, "ctype": "unsigned long"},
                    ],
                }
            },
        ),
        (
            "takes_fnptr_struct",
            "CallbackBuf",
            "int(unsigned long,struct fnptr_buf)",
            [("uOffset", "value"), ("CallbackBuf", "value")],
            {
                "struct fnptr_buf": {
                    "what": "struct",
                    "size": 16,
                    "align": 8,
                    "pointers": True,
                    "fields": [
                        {"name": "cb", "kind": "fnptr", "off": 0, "size": 8, "pointers": True},
                        {"name": "len", "kind": "int", "off": 8, "size": 8, "pointers": False, "ctype": "unsigned long"},
                    ],
                }
            },
        ),
        (
            "takes_non_byte_ptr_struct",
            "TypedBuf",
            "int(unsigned long,struct int_slice)",
            [("uOffset", "value"), ("TypedBuf", "value")],
            {
                "struct int_slice": {
                    "what": "struct",
                    "size": 16,
                    "align": 8,
                    "pointers": True,
                    "fields": [
                        {"name": "items", "kind": "ptr", "off": 0, "size": 8, "pointers": True, "const": False},
                        {"name": "len", "kind": "int", "off": 8, "size": 8, "pointers": False, "ctype": "unsigned long"},
                    ],
                }
            },
        ),
        (
            "takes_non_len_field_struct",
            "CtxFlags",
            "int(unsigned long,struct ctx_flags)",
            [("uOffset", "value"), ("CtxFlags", "value")],
            {
                "struct ctx_flags": {
                    "what": "struct",
                    "size": 16,
                    "align": 8,
                    "pointers": True,
                    "fields": [
                        {"name": "ptr", "kind": "ptr", "off": 0, "size": 8, "pointers": True, "const": False, "bytes": True},
                        {"name": "flags", "kind": "int", "off": 8, "size": 4, "pointers": False, "ctype": "unsigned int"},
                    ],
                }
            },
        ),
        (
            "takes_unknown_layout_struct",
            "OpaqueVal",
            "int(unsigned long,struct opaque_state)",
            [("uOffset", "value"), ("OpaqueVal", "value")],
            {},
        ),
        (
            "takes_union_buf",
            "UnionBuf",
            "int(unsigned long,union buf_union)",
            [("uOffset", "value"), ("UnionBuf", "value")],
            {
                "union buf_union": {
                    "what": "union",
                    "size": 8,
                    "align": 8,
                    "pointers": True,
                    "fields": [
                        {"name": "ptr", "kind": "ptr", "off": 0, "size": 8, "pointers": True, "const": False, "bytes": True},
                        {"name": "len", "kind": "int", "off": 0, "size": 8, "pointers": False, "ctype": "unsigned long"},
                    ],
                }
            },
        ),
        (
            "restore_cursor",
            "pSavedState",
            "void(unsigned long,struct saved_cursor *)",
            [("uOffset", "value"), ("pSavedState", "const_pointer")],
            {
                "struct saved_cursor": {
                    "what": "struct",
                    "size": 16,
                    "align": 8,
                    "pointers": False,
                    "fields": [
                        {"name": "offset", "kind": "int", "off": 0, "size": 8, "pointers": False, "ctype": "unsigned long"},
                        {"name": "depth", "kind": "int", "off": 8, "size": 4, "pointers": False, "ctype": "int"},
                    ],
                }
            },
        ),
        (
            "map_search",
            "pInfo",
            "int(unsigned long,struct map_search_info *)",
            [("uOffset", "value"), ("pInfo", "pointer")],
            {
                "struct map_search_info": {
                    "what": "struct",
                    "size": 16,
                    "align": 8,
                    "pointers": True,
                    "fields": [
                        {"name": "ptr", "kind": "ptr", "off": 0, "size": 8, "pointers": True, "const": False, "bytes": True},
                        {"name": "len", "kind": "int", "off": 8, "size": 8, "pointers": False, "ctype": "unsigned long"},
                    ],
                }
            },
        ),
        (
            "takes_const_pair",
            "ro_buf",
            "int(unsigned long,void *,unsigned long)",
            [("uOffset", "value"), ("ro_buf", "const_pointer"), ("ro_len", "value")],
            {},
        ),
    ],
)
def test_non_caller_storage_shapes_stay_auto_exempt(
    monkeypatch: pytest.MonkeyPatch,
    fn_name: str,
    param_name: str,
    sig: str,
    formals: list[tuple[str, str]],
    extra_layouts: dict[str, dict[str, Any]],
):
    """Read-only, const-ptr, multi-ptr, fnptr, union, pointer-to-state, and opaque structs stay auto-exempt."""
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _make_fixture({fn_name: (sig, formals, ["uOffset"])}, extra_layouts)

    planned = ah.plan(dag, model, "lib", "lib", 256, struct_layouts=layouts)
    key = f"lib.c#{fn_name}"
    assert planned["auto_exempt"].get(key) == f"trusted parameter {param_name} has no instance"
    assert planned["skipped"].get(key) == f"trusted parameter {param_name} has no instance"
    assert planned["cases"] == []


# ---------------------------------------------------------------------------
# Feature-flag rollback (`FRAMAC_API_TRUST_SCHEMA=off`) and generate() sidecar check
# ---------------------------------------------------------------------------


def test_flag_off_restores_legacy_behavior(monkeypatch: pytest.MonkeyPatch):
    """`FRAMAC_API_TRUST_SCHEMA=off` disables caller-storage binding and restores legacy slot behavior."""
    dag, model, layouts = _make_fixture(
        {
            "encode_head": (
                "int(struct q_useful_buf,unsigned char)",
                [("Buffer", "value"), ("uMajorType", "value")],
                ["uMajorType"],
            ),
            "decode_into": (
                "int(unsigned char *,unsigned long,void *,unsigned long)",
                [
                    ("in_buf", "const_pointer"),
                    ("in_len", "value"),
                    ("scratch", "pointer"),
                    ("scratch_len", "value"),
                ],
                ["in_buf"],
            ),
        },
        {"struct q_useful_buf": _useful_buf_layout(const_ptr=False)},
    )

    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "off")
    planned = ah.plan(dag, model, "lib", "lib", 256, struct_layouts=layouts)
    assert planned["auto_exempt"] == {}

    stmt_enc, lay_enc = _case_for(planned, "encode_head")
    # Legacy `_fill_fields` reads a fuzzed `field_len` slot for Buffer.len instead of fixed `sizeof(c0a0_buf)`.
    assert "c0a0_buf" not in stmt_enc
    assert any(s["kind"] == "field_len" for s in lay_enc["slots"])
    assert not any(ah.CALLER_STORAGE_NOTE in n for n in lay_enc.get("notes") or [])

    stmt_dec, lay_dec = _case_for(planned, "decode_into")
    # Legacy output pair fuzzes `c0a3` as an `int` slot instead of fixed `sizeof(c0a2_buf)`.
    assert "c0a2_buf" not in stmt_dec
    assert any(s["param"] == 3 and s["kind"] == "int" for s in lay_dec["slots"])
    assert not any(ah.CALLER_STORAGE_NOTE in n for n in lay_dec.get("notes") or [])


def test_generate_sidecar_valid_and_eva_fuzz_parity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """`api_harness.generate` writes a schema-valid sidecar and identical caller-storage bodies in Eva and LibFuzzer."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _make_fixture(
        {
            "process_bignum": (
                "int(unsigned long,struct q_useful_buf)",
                [("uVal", "value"), ("BigNumberBuf", "value")],
                ["uVal"],
            ),
            "decode_into": (
                "int(unsigned char *,unsigned long,void *,unsigned long)",
                [
                    ("in_buf", "const_pointer"),
                    ("in_len", "value"),
                    ("scratch", "pointer"),
                    ("scratch_len", "value"),
                ],
                ["in_buf"],
            ),
        },
        {"struct q_useful_buf": _useful_buf_layout(const_ptr=False)},
    )
    reports = tmp_path / "workspace" / "reports"
    harnesses = tmp_path / "workspace" / "harnesses"
    reports.mkdir(parents=True)
    harnesses.mkdir(parents=True)
    dag_path = reports / "callgraph_dag.json"
    model_path = reports / "phase0_model.json"
    dag_path.write_text(json.dumps(dag), encoding="utf-8")
    model_path.write_text(json.dumps(model), encoding="utf-8")

    res = ah.generate(
        module="lib",
        header="none",
        max_input_size=256,
        cppflags="",
        out_dir=harnesses,
        unit="lib",
        auto_prelude=False,
        probe=False,
        dag_path=dag_path,
        model_path=model_path,
        struct_layouts=layouts,
        variadic={},
    )
    sidecar = json.loads(Path(res["harness_meta"]).read_text(encoding="utf-8"))
    harness_c = Path(res["harness_file"]).read_text(encoding="utf-8")

    assert not validate_sidecar(sidecar, module="lib")
    assert "api_auto_exempt" not in sidecar
    eva_part, fuzz_part = harness_c.split("LLVMFuzzerTestOneInput", 1)
    assert "c0a1.ptr = (void *)c0a1_buf; c0a1.len = (unsigned long)sizeof(c0a1_buf);" in eva_part
    assert "c0a1.ptr = (void *)c0a1_buf; c0a1.len = (unsigned long)sizeof(c0a1_buf);" in fuzz_part
    assert "unsigned long c0a3 = (unsigned long)sizeof(c0a2_buf);" in eva_part
    assert "unsigned long c0a3 = (unsigned long)sizeof(c0a2_buf);" in fuzz_part
