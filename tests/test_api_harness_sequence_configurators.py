"""Tests for W2-C: optional `no-attacker-data` context configurators in recorded sequence cases."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

import api_harness as ah
from validate_artifacts import validate_sidecar

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------


def _useful_buf_layout(*, const_ptr: bool = False) -> dict[str, Any]:
    return {
        "what": "struct",
        "size": 16,
        "align": 8,
        "pointers": True,
        "fields": [
            {"name": "ptr", "kind": "ptr", "off": 0, "size": 8, "pointers": True, "const": const_ptr, "bytes": True},
            {"name": "len", "kind": "int", "off": 8, "size": 8, "pointers": False, "ctype": "unsigned long"},
        ],
    }


def _plain_struct_layout(*field_names: str) -> dict[str, Any]:
    return {
        "what": "struct",
        "size": 4 * len(field_names),
        "align": 4,
        "pointers": False,
        "fields": [
            {"name": name, "kind": "int", "off": 4 * i, "size": 4, "pointers": False, "ctype": "int"}
            for i, name in enumerate(field_names)
        ],
    }


def _qcbor_like_fixture(
    extra_fns: dict[str, dict[str, Any]] | None = None,
    *,
    mempool_in_entries: bool = False,
    extra_layouts: dict[str, dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, dict[str, Any]]]:
    """
    Build a QCBOR-shaped DAG, Phase 0 model, and struct layouts with:
      - `QCBORDecode_Init` (entry, attacker_params=[pMe, EncodedCBOR])
      - `QCBORDecode_SetMemPool` (no-attacker-data configurator, taking `struct q_useful_buf Pool` and `_Bool`)
      - `QCBORDecode_CompatibilityV1` (no-attacker-data configurator, taking only `pMe`)
      - `QCBORDecode_GetNext` (entry, attacker_params=[pMe, pDecodedItem])
    """
    base_fns: dict[str, dict[str, Any]] = {
        "QCBORDecode_Init": {
            "file": "qcbor_decode.c",
            "signature": "void(struct _QCBORDecodeContext *,struct q_useful_buf_c,int)",
            "formals": [
                {"name": "pMe", "kind": "pointer"},
                {"name": "EncodedCBOR", "kind": "value"},
                {"name": "uConfigFlags", "kind": "value"},
            ],
            "attacker_params": ["pMe", "EncodedCBOR"],
            "in_entries": True,
        },
        "QCBORDecode_SetMemPool": {
            "file": "qcbor_decode.c",
            "signature": "int(struct _QCBORDecodeContext *,struct q_useful_buf,_Bool)",
            "formals": [
                {"name": "pMe", "kind": "pointer"},
                {"name": "Pool", "kind": "value"},
                {"name": "bAllStrings", "kind": "value"},
            ],
            "attacker_params": None,
            "in_entries": mempool_in_entries,
        },
        "QCBORDecode_CompatibilityV1": {
            "file": "qcbor_decode.c",
            "signature": "void(struct _QCBORDecodeContext *)",
            "formals": [{"name": "pMe", "kind": "pointer"}],
            "attacker_params": None,
            "in_entries": False,
        },
        "QCBORDecode_GetNext": {
            "file": "qcbor_decode.c",
            "signature": "int(struct _QCBORDecodeContext *,struct _QCBORItem *)",
            "formals": [
                {"name": "pMe", "kind": "pointer"},
                {"name": "pDecodedItem", "kind": "pointer"},
            ],
            "attacker_params": ["pMe", "pDecodedItem"],
            "in_entries": True,
        },
    }
    if extra_fns:
        base_fns.update(extra_fns)

    dag_fns: dict[str, dict[str, Any]] = {}
    model_fns: dict[str, dict[str, Any]] = {}
    input_sources: list[dict[str, Any]] = []
    trusted_callers: list[dict[str, Any]] = []
    candidate_entries: list[str] = []
    all_files: set[str] = set()

    for name, spec in base_fns.items():
        fname = str(spec.get("file") or "qcbor_decode.c")
        is_static = bool(spec.get("is_static", False))
        is_header = bool(spec.get("header", False))
        key = f"{fname}#{name}"
        all_files.add(fname)
        drec: dict[str, Any] = {
            "name": name,
            "file": fname,
            "is_static": is_static,
            "header": is_header,
            "module": "libqcbor_a",
        }
        if spec.get("trusted_caller"):
            drec["trust"] = {"value": "trusted", "source": "threat_model"}
            trusted_callers.append({"functions": [name], "reason": "trusted internal helper"})
        elif spec.get("attacker_params") is not None:
            att = list(spec["attacker_params"])
            drec["trust"] = {
                "value": "untrusted",
                "source": "threat_model",
                "input_role": str(spec.get("role") or "entry"),
                "attacker_params": att,
            }
            input_sources.append(
                {"function": name, "role": str(spec.get("role") or "entry"), "params": att, "description": name}
            )
        else:
            drec["trust"] = {"value": "untrusted", "source": "default"}

        dag_fns[key] = drec
        mrec: dict[str, Any] = {
            "name": name,
            "file": fname,
            "static": is_static,
            "header": is_header,
            "signature": spec["signature"],
            "formals": spec["formals"],
        }
        if spec.get("call_sites"):
            mrec["call_sites"] = spec["call_sites"]
        model_fns[key] = mrec
        if spec.get("in_entries", False):
            candidate_entries.append(key)

    tm_block: dict[str, Any] = {"status": "ok", "input_sources": input_sources}
    if trusted_callers:
        tm_block["trusted_callers"] = trusted_callers

    dag: dict[str, Any] = {
        "module_kind": "link_unit",
        "trust": {"threat_model": tm_block},
        "modules": {
            "libqcbor_a": {
                "candidate_entry_points": candidate_entries,
                "functions": list(dag_fns),
                "files": sorted(all_files),
            }
        },
        "functions": dag_fns,
        "global_variables": {},
    }
    model: dict[str, Any] = {
        "status": "ok",
        "trust": {"threat_model": tm_block},
        "units": {
            "libqcbor.a": {
                "kind": "static_lib",
                "test": False,
                "files": sorted(all_files),
                "links": [],
            }
        },
        "functions": model_fns,
        "global_variables": {},
    }
    layouts: dict[str, dict[str, Any]] = {
        "struct _QCBORDecodeContext": _plain_struct_layout("depth", "pos", "len"),
        "struct _QCBORItem": _plain_struct_layout("uDataType", "uNestingLevel"),
        "struct q_useful_buf": _useful_buf_layout(const_ptr=False),
        "struct q_useful_buf_c": _useful_buf_layout(const_ptr=True),
    }
    if extra_layouts:
        layouts.update(extra_layouts)
    return dag, model, layouts


def _recorded_sequences(planned: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    return [
        (stmt, lay)
        for stmt, lay in zip(planned["cases"], planned["layouts"], strict=True)
        if lay["kind"] == "sequence" and not lay.get("entry")
    ]


# ---------------------------------------------------------------------------
# Core W2-C tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mempool_in_entries", [False, True])
def test_mempool_configurator_stays_in_recorded_sequence_and_has_no_single_case(
    monkeypatch: pytest.MonkeyPatch,
    mempool_in_entries: bool,
):
    """
    A traced `QCBORDecode_Init -> QCBORDecode_SetMemPool -> QCBORDecode_GetNext` segment keeps
    `QCBORDecode_SetMemPool` even though it is `no-attacker-data` (absent from `records`), backs
    `UsefulBuf Pool` with W1-A's fixed harness array, and emits zero single cases for it.
    """
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _qcbor_like_fixture(mempool_in_entries=mempool_in_entries)
    trace = [
        {"fn": "QCBORDecode_Init", "args": {}, "addrs": {"0": "0xctx1"}},
        {"fn": "QCBORDecode_SetMemPool", "args": {}, "addrs": {"0": "0xctx1"}},
        {"fn": "QCBORDecode_GetNext", "args": {}, "addrs": {"0": "0xctx1"}},
    ]

    planned = ah.plan(dag, model, "libqcbor_a", "libqcbor.a", 256, traces=[trace], struct_layouts=layouts)

    # No single case for the no-attacker-data configurator.
    singles = [lay for lay in planned["layouts"] if lay["kind"] == "single"]
    assert all("QCBORDecode_SetMemPool" not in lay["calls"] for lay in singles)
    if mempool_in_entries:
        assert planned["auto_exempt"].get("qcbor_decode.c#QCBORDecode_SetMemPool") == ah.NO_ATTACKER_DATA_REASON

    # Recorded sequence case calls Init -> SetMemPool -> GetNext on the shared decode context.
    seqs = _recorded_sequences(planned)
    assert len(seqs) == 1
    stmt, lay = seqs[0]
    assert lay["calls"] == ["QCBORDecode_Init", "QCBORDecode_SetMemPool", "QCBORDecode_GetNext"]

    spare = ah.spare_bytes(256)
    assert f"_Alignas(16) unsigned char c1a1_buf[{spare}]; memset(c1a1_buf, 0, sizeof(c1a1_buf));" in stmt
    assert "struct q_useful_buf c1a1; memset(&c1a1, 0, sizeof(c1a1));" in stmt
    assert "c1a1.ptr = (void *)c1a1_buf; c1a1.len = (unsigned long)sizeof(c1a1_buf);" in stmt
    assert "_Bool c1a2; memset(&c1a2, 0, sizeof(c1a2));" in stmt
    assert "(void)QCBORDecode_Init((struct _QCBORDecodeContext *)s0, c0a1, c0a2);" in stmt
    assert "(void)QCBORDecode_SetMemPool((struct _QCBORDecodeContext *)s0, c1a1, c1a2);" in stmt
    assert "QCBORDecode_GetNext((struct _QCBORDecodeContext *)s0, &c2a1)" in stmt
    assert stmt.index("QCBORDecode_Init(") < stmt.index("QCBORDecode_SetMemPool(") < stmt.index("QCBORDecode_GetNext(")

    # Configurator consumes no fuzz slots and does not steal `rest` from QCBORDecode_Init.
    assert lay["slots"] == []
    assert lay["rest"] == {"call": 0, "param": 1, "kind": "bytes", "off": 0}
    assert any(f"call 1 argument 1: {ah.CALLER_STORAGE_NOTE}" in n for n in lay.get("notes") or [])


def test_direct_sequence_case_resolves_configurator_from_api_records():
    """Direct `sequence_case` resolves a configurator from `api.records` under `api.trust_schema=True`."""
    dag, model, layouts = _qcbor_like_fixture()
    init_rec = model["functions"]["qcbor_decode.c#QCBORDecode_Init"]
    mempool_rec = model["functions"]["qcbor_decode.c#QCBORDecode_SetMemPool"]
    next_rec = model["functions"]["qcbor_decode.c#QCBORDecode_GetNext"]
    records = {"QCBORDecode_Init": init_rec, "QCBORDecode_GetNext": next_rec}
    api = ah.ApiInfo(
        structs=layouts,
        probed=True,
        inits={"struct _QCBORDecodeContext": "QCBORDecode_Init"},
        candidates={"struct _QCBORDecodeContext": {"QCBORDecode_Init"}},
        records={"QCBORDecode_Init": init_rec, "QCBORDecode_SetMemPool": mempool_rec},
        trust_schema=True,
    )
    trust = {
        "QCBORDecode_Init": ah._EntryTrust(input_role="entry", attacker_params=["pMe", "EncodedCBOR"]),
        "QCBORDecode_GetNext": ah._EntryTrust(input_role="entry", attacker_params=["pMe", "pDecodedItem"]),
    }
    trace = [
        {"fn": "QCBORDecode_Init", "args": {}, "addrs": {"0": "0xctx"}},
        {"fn": "QCBORDecode_SetMemPool", "args": {}, "addrs": {"0": "0xctx"}},
        {"fn": "QCBORDecode_GetNext", "args": {}, "addrs": {"0": "0xctx"}},
    ]

    stmt, lay, why = ah.sequence_case(trace, [0, 1, 2], records, 768, api, trust)
    assert why is None and stmt is not None and lay is not None
    assert lay["calls"] == ["QCBORDecode_Init", "QCBORDecode_SetMemPool", "QCBORDecode_GetNext"]
    assert "c1a1.ptr = (void *)c1a1_buf; c1a1.len = (unsigned long)sizeof(c1a1_buf);" in stmt
    assert "(void)QCBORDecode_SetMemPool((struct _QCBORDecodeContext *)s0, c1a1, c1a2);" in stmt


def test_configurator_binds_trusted_cstring_and_recorded_scalar(monkeypatch: pytest.MonkeyPatch):
    """
    A configurator's non-shared `const char *` binds via F1's trusted C-string literal, and its
    non-`_Bool` scalar binds via recorded trace values (never arbitrary fuzz bytes).
    """
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _qcbor_like_fixture(
        extra_fns={
            "QCBORDecode_ConfigureTag": {
                "file": "qcbor_decode.c",
                "signature": "void(struct _QCBORDecodeContext *,char *,unsigned int)",
                "formals": [
                    {"name": "pMe", "kind": "pointer"},
                    {"name": "szProfile", "kind": "const_pointer"},
                    {"name": "uMode", "kind": "value"},
                ],
                "attacker_params": None,
                "in_entries": False,
            },
        }
    )
    trace = [
        {"fn": "QCBORDecode_Init", "args": {}, "addrs": {"0": "0xctx1"}},
        {
            "fn": "QCBORDecode_ConfigureTag",
            "args": {
                "1": [["s", 0, b"strict".hex()]],
                "2": [["i", 0, (7).to_bytes(4, "little").hex()]],
            },
            "addrs": {"0": "0xctx1"},
        },
        {"fn": "QCBORDecode_GetNext", "args": {}, "addrs": {"0": "0xctx1"}},
    ]

    planned = ah.plan(dag, model, "libqcbor_a", "libqcbor.a", 256, traces=[trace], struct_layouts=layouts)
    seqs = _recorded_sequences(planned)
    assert len(seqs) == 1
    stmt, lay = seqs[0]
    assert lay["calls"] == ["QCBORDecode_Init", "QCBORDecode_ConfigureTag", "QCBORDecode_GetNext"]
    assert '(char *)"strict"' in stmt
    assert "7ULL" in stmt
    assert any("call 1 argument 2: trusted scalar" in n and "recorded" in n for n in lay.get("notes") or [])


def test_trace_with_only_no_attacker_data_calls_produces_no_sequence_case(monkeypatch: pytest.MonkeyPatch):
    """A trace containing only `no-attacker-data` configurator calls emits zero sequence cases."""
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _qcbor_like_fixture()
    trace = [
        {"fn": "QCBORDecode_SetMemPool", "args": {}, "addrs": {"0": "0xctx1"}},
        {"fn": "QCBORDecode_CompatibilityV1", "args": {}, "addrs": {"0": "0xctx1"}},
    ]

    planned = ah.plan(dag, model, "libqcbor_a", "libqcbor.a", 256, traces=[trace], struct_layouts=layouts)
    assert _recorded_sequences(planned) == []

    # Direct `sequence_case` also rejects a chain with zero calls in `records`.
    api = ah.ApiInfo(
        structs=layouts,
        probed=True,
        records={
            "QCBORDecode_SetMemPool": model["functions"]["qcbor_decode.c#QCBORDecode_SetMemPool"],
            "QCBORDecode_CompatibilityV1": model["functions"]["qcbor_decode.c#QCBORDecode_CompatibilityV1"],
        },
        trust_schema=True,
    )
    stmt, lay, why = ah.sequence_case(trace, [0, 1], {}, 768, api)
    assert stmt is None and lay is None and why == "sequence has no API entry point"


def test_external_unknown_call_filtered_without_breaking_chain(monkeypatch: pytest.MonkeyPatch):
    """An external/unknown call outside both `records` and `api.records` is stripped without breaking the chain."""
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _qcbor_like_fixture()
    trace = [
        {"fn": "QCBORDecode_Init", "args": {}, "addrs": {"0": "0xctx1"}},
        {"fn": "external_test_helper", "args": {}, "addrs": {"0": "0xctx1"}},
        {"fn": "QCBORDecode_SetMemPool", "args": {}, "addrs": {"0": "0xctx1"}},
        {"fn": "another_unknown_fn", "args": {}, "addrs": {"0": "0xctx1"}},
        {"fn": "QCBORDecode_GetNext", "args": {}, "addrs": {"0": "0xctx1"}},
    ]

    planned = ah.plan(dag, model, "libqcbor_a", "libqcbor.a", 256, traces=[trace], struct_layouts=layouts)
    seqs = _recorded_sequences(planned)
    assert len(seqs) == 1
    _stmt, lay = seqs[0]
    assert lay["calls"] == ["QCBORDecode_Init", "QCBORDecode_SetMemPool", "QCBORDecode_GetNext"]


@pytest.mark.parametrize(
    ("bad_name", "bad_spec"),
    [
        (
            "QCBORDecode_Private_TrustedOnly",
            {
                "file": "qcbor_decode.c",
                "signature": "void(struct _QCBORDecodeContext *)",
                "formals": [{"name": "pMe", "kind": "pointer"}],
                "trusted_caller": True,
                "in_entries": False,
            },
        ),
        (
            "static_helper",
            {
                "file": "qcbor_decode.c",
                "signature": "void(struct _QCBORDecodeContext *)",
                "formals": [{"name": "pMe", "kind": "pointer"}],
                "is_static": True,
                "in_entries": False,
            },
        ),
        (
            "header_inline_cfg",
            {
                "file": "qcbor_decode.h",
                "signature": "void(struct _QCBORDecodeContext *)",
                "formals": [{"name": "pMe", "kind": "pointer"}],
                "is_static": True,
                "header": True,
                "in_entries": False,
            },
        ),
        (
            "variadic_cfg",
            {
                "file": "qcbor_decode.c",
                "signature": "void(struct _QCBORDecodeContext *,char *,...)",
                "formals": [
                    {"name": "pMe", "kind": "pointer"},
                    {"name": "fmt", "kind": "const_pointer"},
                ],
                "in_entries": False,
            },
        ),
        (
            "path_taking_cfg",
            {
                "file": "qcbor_decode.c",
                "signature": "void(struct _QCBORDecodeContext *,char *)",
                "formals": [
                    {"name": "pMe", "kind": "pointer"},
                    {"name": "filename", "kind": "const_pointer"},
                ],
                "in_entries": False,
            },
        ),
    ],
)
def test_disallowed_configurator_categories_are_filtered_out(
    monkeypatch: pytest.MonkeyPatch,
    bad_name: str,
    bad_spec: dict[str, Any],
):
    """Trusted-only, static, header-static, variadic, and path-taking calls are never admitted as configurators."""
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _qcbor_like_fixture(extra_fns={bad_name: bad_spec})
    visible = ah.Declared({"QCBORDecode_Init", "QCBORDecode_GetNext", bad_name})
    trace = [
        {"fn": "QCBORDecode_Init", "args": {}, "addrs": {"0": "0xctx1"}},
        {"fn": bad_name, "args": {}, "addrs": {"0": "0xctx1"}},
        {"fn": "QCBORDecode_GetNext", "args": {}, "addrs": {"0": "0xctx1"}},
    ]

    planned = ah.plan(
        dag, model, "libqcbor_a", "libqcbor.a", 256, traces=[trace], struct_layouts=layouts, visible=visible
    )
    seqs = _recorded_sequences(planned)
    assert len(seqs) == 1
    assert seqs[0][1]["calls"] == ["QCBORDecode_Init", "QCBORDecode_GetNext"]


def test_invisible_configurator_is_filtered_when_layout_probe_ran(monkeypatch: pytest.MonkeyPatch):
    """A configurator not declared in the included headers (`visible`) is excluded once the layout probe runs."""
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _qcbor_like_fixture()
    visible = ah.Declared({"QCBORDecode_Init", "QCBORDecode_GetNext"})  # SetMemPool intentionally absent
    trace = [
        {"fn": "QCBORDecode_Init", "args": {}, "addrs": {"0": "0xctx1"}},
        {"fn": "QCBORDecode_SetMemPool", "args": {}, "addrs": {"0": "0xctx1"}},
        {"fn": "QCBORDecode_GetNext", "args": {}, "addrs": {"0": "0xctx1"}},
    ]

    planned = ah.plan(
        dag, model, "libqcbor_a", "libqcbor.a", 256, traces=[trace], struct_layouts=layouts, visible=visible
    )
    seqs = _recorded_sequences(planned)
    assert len(seqs) == 1
    assert seqs[0][1]["calls"] == ["QCBORDecode_Init", "QCBORDecode_GetNext"]


@pytest.mark.parametrize(
    ("cfg_name", "cfg_sig", "cfg_formals", "extra_layouts", "expected_why_substr"),
    [
        (
            "QCBORDecode_SetOpaqueCfg",
            "void(struct _QCBORDecodeContext *,struct opaque_cfg *)",
            [{"name": "pMe", "kind": "pointer"}, {"name": "pCfg", "kind": "const_pointer"}],
            {},
            "trusted parameter pCfg has no instance",
        ),
        (
            "QCBORDecode_SetConstBuf",
            "void(struct _QCBORDecodeContext *,struct ro_cfg_buf)",
            [{"name": "pMe", "kind": "pointer"}, {"name": "RoBuf", "kind": "value"}],
            {"struct ro_cfg_buf": _useful_buf_layout(const_ptr=True)},
            "trusted parameter RoBuf has no instance",
        ),
    ],
)
def test_configurator_with_unsupported_trusted_param_fails_safely(
    monkeypatch: pytest.MonkeyPatch,
    cfg_name: str,
    cfg_sig: str,
    cfg_formals: list[dict[str, str]],
    extra_layouts: dict[str, dict[str, Any]],
    expected_why_substr: str,
):
    """
    A configurator with an unsupported trusted parameter (opaque pointer or const-pointer struct
    with no schema instance) cleanly fails in `sequence_case` and never crashes `plan()`.
    """
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _qcbor_like_fixture(
        extra_fns={
            cfg_name: {
                "file": "qcbor_decode.c",
                "signature": cfg_sig,
                "formals": cfg_formals,
                "attacker_params": None,
                "in_entries": False,
            }
        },
        extra_layouts=extra_layouts,
    )
    # 1. Direct `sequence_case` returns (None, None, why) without raising.
    records = {
        "QCBORDecode_Init": model["functions"]["qcbor_decode.c#QCBORDecode_Init"],
        "QCBORDecode_GetNext": model["functions"]["qcbor_decode.c#QCBORDecode_GetNext"],
    }
    api = ah.ApiInfo(
        structs=layouts,
        probed=True,
        inits={"struct _QCBORDecodeContext": "QCBORDecode_Init"},
        candidates={"struct _QCBORDecodeContext": {"QCBORDecode_Init"}},
        records={
            "QCBORDecode_Init": records["QCBORDecode_Init"],
            cfg_name: model["functions"][f"qcbor_decode.c#{cfg_name}"],
        },
        trust_schema=True,
    )
    trust = {
        "QCBORDecode_Init": ah._EntryTrust(input_role="entry", attacker_params=["pMe", "EncodedCBOR"]),
        "QCBORDecode_GetNext": ah._EntryTrust(input_role="entry", attacker_params=["pMe", "pDecodedItem"]),
    }
    trace3 = [
        {"fn": "QCBORDecode_Init", "args": {}, "addrs": {"0": "0xctx"}},
        {"fn": cfg_name, "args": {}, "addrs": {"0": "0xctx"}},
        {"fn": "QCBORDecode_GetNext", "args": {}, "addrs": {"0": "0xctx"}},
    ]
    stmt, lay, why = ah.sequence_case(trace3, [0, 1, 2], records, 768, api, trust)
    assert stmt is None and lay is None and why is not None and expected_why_substr in why

    # 2. Through `plan()`: 2-call `[Init, BadCfg]` drops cleanly without crashing.
    trace2 = trace3[:2]
    planned2 = ah.plan(dag, model, "libqcbor_a", "libqcbor.a", 256, traces=[trace2], struct_layouts=layouts)
    assert _recorded_sequences(planned2) == []
    assert all(cfg_name not in c for c in planned2["cases"])

    # 3. Through `plan()`: 3-call `[Init, BadCfg, GetNext]` drops BadCfg and preserves `[Init, GetNext]`.
    planned3 = ah.plan(dag, model, "libqcbor_a", "libqcbor.a", 256, traces=[trace3], struct_layouts=layouts)
    assert all(cfg_name not in c for c in planned3["cases"])
    assert [lay["calls"] for _s, lay in _recorded_sequences(planned3)] == [["QCBORDecode_Init", "QCBORDecode_GetNext"]]


def test_stateful_prefixes_keep_recorded_configurator_and_fallback_when_unbuildable(
    monkeypatch: pytest.MonkeyPatch,
):
    """
    `stateful_prefixes` retains valid configurators inside recorded context segments (e.g.
    `SetMemPool -> EnterMap -> GetIntInMapSZ`) and falls back cleanly if a configurator fails.
    """
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _qcbor_like_fixture(
        extra_fns={
            "QCBORDecode_EnterMap": {
                "file": "qcbor_decode.c",
                "signature": "void(struct _QCBORDecodeContext *)",
                "formals": [{"name": "pMe", "kind": "pointer"}],
                "attacker_params": ["pMe"],
                "in_entries": True,
            },
            "QCBORDecode_GetIntInMapSZ": {
                "file": "qcbor_decode.c",
                "signature": "void(struct _QCBORDecodeContext *,char *,long *)",
                "formals": [
                    {"name": "pMe", "kind": "pointer"},
                    {"name": "szLabel", "kind": "const_pointer"},
                    {"name": "pnVal", "kind": "pointer"},
                ],
                "attacker_params": ["pMe", "pnVal"],
                "in_entries": True,
            },
        }
    )
    trace = [
        {"fn": "QCBORDecode_Init", "args": {}, "addrs": {"0": "0xctx1"}},
        {"fn": "QCBORDecode_SetMemPool", "args": {}, "addrs": {"0": "0xctx1"}},
        {"fn": "QCBORDecode_EnterMap", "args": {}, "addrs": {"0": "0xctx1"}},
        {
            "fn": "QCBORDecode_GetIntInMapSZ",
            "args": {"1": [["s", 0, b"key".hex()]]},
            "addrs": {"0": "0xctx1"},
        },
    ]

    planned = ah.plan(dag, model, "libqcbor_a", "libqcbor.a", 256, traces=[trace], struct_layouts=layouts)
    stateful = [
        (stmt, lay)
        for stmt, lay in zip(planned["cases"], planned["layouts"], strict=True)
        if lay["kind"] == "sequence" and lay.get("entry") == "qcbor_decode.c#QCBORDecode_GetIntInMapSZ"
    ]
    assert len(stateful) == 1
    stmt, lay = stateful[0]
    assert lay["state"] == "recorded"
    assert lay["calls"] == ["QCBORDecode_SetMemPool", "QCBORDecode_EnterMap", "QCBORDecode_GetIntInMapSZ"]
    assert "QCBORDecode_Init(" in stmt
    assert "c0a1.ptr = (void *)c0a1_buf; c0a1.len = (unsigned long)sizeof(c0a1_buf);" in stmt
    assert '(char *)"key"' in stmt


def test_flag_off_restores_legacy_sequence_filtering_and_ordering(monkeypatch: pytest.MonkeyPatch):
    """`FRAMAC_API_TRUST_SCHEMA=off` disables configurator inclusion and restores legacy behavior."""
    dag, model, layouts = _qcbor_like_fixture(mempool_in_entries=False)
    trace = [
        {"fn": "QCBORDecode_Init", "args": {}, "addrs": {"0": "0xctx1"}},
        {"fn": "QCBORDecode_SetMemPool", "args": {}, "addrs": {"0": "0xctx1"}},
        {"fn": "QCBORDecode_GetNext", "args": {}, "addrs": {"0": "0xctx1"}},
    ]

    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "off")
    planned = ah.plan(dag, model, "libqcbor_a", "libqcbor.a", 256, traces=[trace], struct_layouts=layouts)
    seqs = _recorded_sequences(planned)
    assert len(seqs) == 1
    assert seqs[0][1]["calls"] == ["QCBORDecode_Init", "QCBORDecode_GetNext"]
    assert all("QCBORDecode_SetMemPool(" not in c for c in planned["cases"])

    # Direct `sequence_case` with `trust_schema=False` rejects functions absent from `records`.
    records = {
        "QCBORDecode_Init": model["functions"]["qcbor_decode.c#QCBORDecode_Init"],
        "QCBORDecode_GetNext": model["functions"]["qcbor_decode.c#QCBORDecode_GetNext"],
    }
    api_off = ah.ApiInfo(
        structs=layouts,
        probed=True,
        records={"QCBORDecode_SetMemPool": model["functions"]["qcbor_decode.c#QCBORDecode_SetMemPool"]},
        trust_schema=False,
    )
    stmt, lay, why = ah.sequence_case(trace, [0, 1, 2], records, 768, api_off)
    assert stmt is None and lay is None and why == "QCBORDecode_SetMemPool is not an API function of this module"


def test_generate_sidecar_valid_and_eva_fuzz_parity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """`api_harness.generate` emits a schema-valid sidecar and identical configurator sequences in Eva and Fuzz."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _qcbor_like_fixture(mempool_in_entries=False)

    reports = tmp_path / "workspace" / "reports"
    harnesses = tmp_path / "workspace" / "harnesses"
    reports.mkdir(parents=True)
    harnesses.mkdir(parents=True)
    dag_path = reports / "callgraph_dag.json"
    model_path = reports / "phase0_model.json"
    traces_path = tmp_path / "traces.jsonl"
    dag_path.write_text(json.dumps(dag), encoding="utf-8")
    model_path.write_text(json.dumps(model), encoding="utf-8")
    trace = [
        {"fn": "QCBORDecode_Init", "args": {}, "addrs": {"0": "0xctx1"}},
        {"fn": "QCBORDecode_SetMemPool", "args": {}, "addrs": {"0": "0xctx1"}},
        {"fn": "QCBORDecode_GetNext", "args": {}, "addrs": {"0": "0xctx1"}},
    ]
    traces_path.write_text(json.dumps({"pid": "1", "calls": trace}) + "\n", encoding="utf-8")

    res = ah.generate(
        module="libqcbor_a",
        header="none",
        max_input_size=256,
        cppflags="",
        out_dir=harnesses,
        unit="libqcbor.a",
        auto_prelude=False,
        probe=False,
        dag_path=dag_path,
        model_path=model_path,
        traces_path=traces_path,
        struct_layouts=layouts,
        variadic={},
    )
    sidecar = json.loads(Path(res["harness_meta"]).read_text(encoding="utf-8"))
    harness_c = Path(res["harness_file"]).read_text(encoding="utf-8")

    assert not validate_sidecar(sidecar, module="libqcbor_a")
    seq_cases = [c for c in sidecar["api_cases"] if c["kind"] == "sequence"]
    assert [c["calls"] for c in seq_cases] == [["QCBORDecode_Init", "QCBORDecode_SetMemPool", "QCBORDecode_GetNext"]]
    eva_part, fuzz_part = harness_c.split("LLVMFuzzerTestOneInput", 1)
    body = sidecar["dispatch_cases"][seq_cases[0]["selector"]]
    assert "QCBORDecode_SetMemPool((struct _QCBORDecodeContext *)s0, c1a1, c1a2);" in body
    assert eva_part.count(body) == 1 and fuzz_part.count(body) == 1


# ---------------------------------------------------------------------------
# Read-only verification against ~/framac-pipeline/QCBOR/run-1 (when present)
# ---------------------------------------------------------------------------


_QCBOR_RUN1_WS = Path.home() / "framac-pipeline" / "QCBOR" / "run-1" / "workspace"
_QCBOR_MODEL = _QCBOR_RUN1_WS / "reports" / "phase0_model.json"
_QCBOR_DAG = _QCBOR_RUN1_WS / "reports" / "callgraph_dag.json"


@pytest.mark.skipif(
    not (_QCBOR_MODEL.is_file() and _QCBOR_DAG.is_file()),
    reason="local read-only QCBOR run-1 reports not present",
)
def test_qcbor_run1_mempool_sequence_syntax_and_compile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    Read-only verification against `~/framac-pipeline/QCBOR/run-1/workspace/reports/phase0_model.json`
    with a synthetic `QCBORDecode_Init -> QCBORDecode_SetMemPool -> QCBORDecode_GetNext` trace.
    Verifies exact C bindings and, when clang or the analysis Docker image is available, confirms
    `clang -fsyntax-only -std=c11 -Wall -Wextra` succeeds against QCBOR's real headers.
    """
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    model = json.loads(_QCBOR_MODEL.read_text(encoding="utf-8"))
    dag = json.loads(_QCBOR_DAG.read_text(encoding="utf-8"))
    layouts = {
        "struct q_useful_buf": _useful_buf_layout(const_ptr=False),
        "struct q_useful_buf_c": _useful_buf_layout(const_ptr=True),
    }
    trace = [
        {"fn": "QCBORDecode_Init", "args": {}, "addrs": {"0": "0x7000"}},
        {"fn": "QCBORDecode_SetMemPool", "args": {}, "addrs": {"0": "0x7000"}},
        {"fn": "QCBORDecode_GetNext", "args": {}, "addrs": {"0": "0x7000"}},
    ]

    planned = ah.plan(dag, model, "libqcbor_a", "libqcbor.a", 1024, traces=[trace], struct_layouts=layouts)
    assert all("QCBORDecode_SetMemPool" not in lay["calls"] for lay in planned["layouts"] if lay["kind"] == "single")
    seqs = [
        (stmt, lay)
        for stmt, lay in _recorded_sequences(planned)
        if lay["calls"] == ["QCBORDecode_Init", "QCBORDecode_SetMemPool", "QCBORDecode_GetNext"]
    ]
    assert len(seqs) == 1
    stmt, lay = seqs[0]
    spare = ah.spare_bytes(1024)
    assert f"_Alignas(16) unsigned char c1a1_buf[{spare}]; memset(c1a1_buf, 0, sizeof(c1a1_buf));" in stmt
    assert "c1a1.ptr = (void *)c1a1_buf; c1a1.len = (unsigned long)sizeof(c1a1_buf);" in stmt
    assert "(void)QCBORDecode_Init((struct _QCBORDecodeContext *)s0, c0a1, c0a2);" in stmt
    assert "(void)QCBORDecode_SetMemPool((struct _QCBORDecodeContext *)s0, c1a1, c1a2);" in stmt
    assert "QCBORDecode_GetNext((struct _QCBORDecodeContext *)s0, (struct _QCBORItem *)c2a1)" in stmt
    assert lay["rest"] == {"call": 0, "param": 1, "kind": "bytes", "off": 0}

    inc_dir = _QCBOR_RUN1_WS / "work" / "inc"
    if not (inc_dir / "qcbor" / "qcbor_decode.h").is_file():
        return
    c_file = tmp_path / "check_qcbor_mempool_seq.c"
    c_file.write_text(
        "#include <stdalign.h>\n"
        "#include <stdbool.h>\n"
        "#include <stddef.h>\n"
        "#include <stdint.h>\n"
        "#include <string.h>\n"
        "#include <qcbor/qcbor_decode.h>\n"
        "void check_seq(const uint8_t *fuzz_buf, size_t fuzz_len) {\n"
        f"  {stmt}\n"
        "}\n",
        encoding="utf-8",
        newline="\n",
    )
    clang = shutil.which("clang")
    if clang:
        proc = subprocess.run(
            [clang, "-fsyntax-only", "-std=c11", "-Wall", "-Wextra", f"-I{inc_dir}", str(c_file)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        return
    docker = shutil.which("docker")
    if docker:
        probe_img = subprocess.run(
            [docker, "image", "inspect", "framac-analysis:patched"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
        if probe_img.returncode == 0:
            proc = subprocess.run(
                [
                    docker,
                    "run",
                    "--rm",
                    "--entrypoint",
                    "clang",
                    "-v",
                    f"{(_QCBOR_RUN1_WS / 'work').resolve()}:/work:ro",
                    "-v",
                    f"{tmp_path.resolve()}:/scratch:ro",
                    "framac-analysis:patched",
                    "-fsyntax-only",
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-I/work/inc",
                    "/scratch/check_qcbor_mempool_seq.c",
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=False,
            )
            assert proc.returncode == 0, proc.stderr
