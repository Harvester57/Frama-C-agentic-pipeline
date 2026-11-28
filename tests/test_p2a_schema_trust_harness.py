"""Tests for P2A deterministic --api upgrades (S1-S3, ownership/backend/TAILQ hygiene, corpus mapping)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import api_harness as ah
import fuzz_assets as fa
import generate_harness as gh
from validate_artifacts import validate_sidecar

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Feature-flag gating
# ---------------------------------------------------------------------------


def test_api_trust_schema_env_flag():
    assert ah.api_trust_schema_enabled({}) is True
    assert ah.api_trust_schema_enabled({ah.API_TRUST_SCHEMA_ENV: ""}) is True
    assert ah.api_trust_schema_enabled({ah.API_TRUST_SCHEMA_ENV: "off"}) is False
    assert ah.api_trust_schema_enabled({ah.API_TRUST_SCHEMA_ENV: "0"}) is False
    assert ah.api_trust_schema_enabled({ah.API_TRUST_SCHEMA_ENV: "false"}) is False
    assert ah.api_trust_schema_enabled({ah.API_TRUST_SCHEMA_ENV: "no"}) is False
    for val in ("on", "ON", "1", "true", "True", "yes", "YES"):
        assert ah.api_trust_schema_enabled({ah.API_TRUST_SCHEMA_ENV: val}) is True


# ---------------------------------------------------------------------------
# nanopb-shaped fixture (S1, S2, S3, SD1b, corpus mapping, Eva soundness)
# ---------------------------------------------------------------------------


def _nanopb_fixture(
    *,
    include_globals: bool = True,
    per_fn_trust: bool = True,
    fallback_input_sources: bool = False,
    tm_path: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, dict[str, Any]]]:
    """Build a nanopb-shaped DAG, Phase 0 model, and struct layouts."""
    funcs_dag: dict[str, dict[str, Any]] = {
        "pb_decode.c#pb_decode": {"name": "pb_decode", "file": "pb_decode.c", "is_static": False, "module": "nanopb"},
        "pb_decode.c#pb_decode_ex": {
            "name": "pb_decode_ex",
            "file": "pb_decode.c",
            "is_static": False,
            "module": "nanopb",
        },
        "pb_decode.c#pb_decode_varint": {
            "name": "pb_decode_varint",
            "file": "pb_decode.c",
            "is_static": False,
            "module": "nanopb",
        },
        "pb_decode.c#pb_istream_from_buffer": {
            "name": "pb_istream_from_buffer",
            "file": "pb_decode.c",
            "is_static": False,
            "module": "nanopb",
        },
        "pb_encode.c#pb_ostream_from_buffer": {
            "name": "pb_ostream_from_buffer",
            "file": "pb_encode.c",
            "is_static": False,
            "module": "nanopb",
        },
        "pb_common.c#pb_field_iter_begin": {
            "name": "pb_field_iter_begin",
            "file": "pb_common.c",
            "is_static": False,
            "module": "nanopb",
        },
        "pb_common.c#pb_field_iter_find": {
            "name": "pb_field_iter_find",
            "file": "pb_common.c",
            "is_static": False,
            "module": "nanopb",
        },
        "pb_decode.c#pb_trusted_helper": {
            "name": "pb_trusted_helper",
            "file": "pb_decode.c",
            "is_static": False,
            "module": "nanopb",
        },
    }

    if per_fn_trust:
        funcs_dag["pb_decode.c#pb_decode"]["trust"] = {
            "value": "untrusted",
            "source": "threat_model",
            "input_role": "entry",
            "attacker_params": ["stream"],
        }
        funcs_dag["pb_decode.c#pb_decode_ex"]["trust"] = {
            "value": "untrusted",
            "source": "threat_model",
            "input_role": "entry",
            "attacker_params": ["stream"],
        }
        funcs_dag["pb_decode.c#pb_decode_varint"]["trust"] = {
            "value": "untrusted",
            "source": "threat_model",
            "input_role": "reader",
            "attacker_params": None,
        }
        funcs_dag["pb_common.c#pb_field_iter_find"]["trust"] = {
            "value": "untrusted",
            "source": "threat_model",
            "input_role": "entry",
            "attacker_params": ["iter", "tag"],
        }
        funcs_dag["pb_decode.c#pb_trusted_helper"]["trust"] = {
            "value": "trusted",
            "source": "threat_model",
            "input_role": None,
            "attacker_params": None,
        }

    tm_block: dict[str, Any] = {"status": "ok"}
    if tm_path is not None:
        tm_block["path"] = str(tm_path)
    if fallback_input_sources:
        tm_block["input_sources"] = [
            {"function": "pb_decode", "role": "entry", "params": ["stream"], "description": "wire stream"},
            {"function": "pb_decode_ex", "role": "entry", "params": ["stream"], "description": "wire stream"},
            {"function": "pb_decode_varint", "role": "reader", "description": "varint reader"},
            {
                "function": "pb_field_iter_find",
                "role": "entry",
                "params": ["iter", "tag"],
                "description": "field lookup",
            },
        ]
        tm_block["trusted_callers"] = [
            {"functions": ["pb_trusted_helper"], "reason": "internal helper"},
        ]

    gvars: dict[str, dict[str, Any]] = {}
    if include_globals:
        gvars = {
            "alltypes.pb.c#AllTypes_msg": {
                "name": "AllTypes_msg",
                "file": "alltypes.pb.c",
                "static": False,
                "const": True,
                "has_init": True,
                "type": "struct pb_msgdesc_s",
                "raw_type": "pb_msgdesc_t const",
                "size": 128,
                "units": ["nanopb"],
                "init_globals": ["AllTypes_field_info", "SubMessage_msg"],
                "init_functions": [],
            },
            "alltypes.pb.c#Zeta_msg": {
                "name": "Zeta_msg",
                "file": "alltypes.pb.c",
                "static": False,
                "const": True,
                "has_init": True,
                "type": "struct pb_msgdesc_s",
                "raw_type": "const pb_msgdesc_t",
                "size": 128,
                "units": ["nanopb"],
                "init_globals": ["Zeta_field_info"],
                "init_functions": [],
            },
            "alltypes.pb.c#Big_msg": {
                "name": "Big_msg",
                "file": "alltypes.pb.c",
                "static": False,
                "const": True,
                "has_init": True,
                "type": "struct pb_msgdesc_s",
                "raw_type": "const pb_msgdesc_t",
                "size": 96,
                "units": ["nanopb"],
                "init_globals": [],
                "init_functions": [],
            },
            "alltypes.pb.c#Med_msg": {
                "name": "Med_msg",
                "file": "alltypes.pb.c",
                "static": False,
                "const": True,
                "has_init": True,
                "type": "struct pb_msgdesc_s",
                "raw_type": "const pb_msgdesc_t",
                "size": 64,
                "units": ["nanopb"],
                "init_globals": [],
                "init_functions": [],
            },
            "alltypes.pb.c#Small_msg": {
                "name": "Small_msg",
                "file": "alltypes.pb.c",
                "static": False,
                "const": True,
                "has_init": True,
                "type": "struct pb_msgdesc_s",
                "raw_type": "const pb_msgdesc_t",
                "size": 32,
                "units": ["nanopb"],
                "init_globals": [],
                "init_functions": [],
            },
            # Ineligible globals that must be filtered out:
            "alltypes.pb.c#Mutable_msg": {
                "name": "Mutable_msg",
                "file": "alltypes.pb.c",
                "static": False,
                "const": False,
                "has_init": True,
                "type": "struct pb_msgdesc_s",
                "raw_type": "pb_msgdesc_t",
                "size": 512,
                "units": ["nanopb"],
            },
            "alltypes.pb.c#Static_msg": {
                "name": "Static_msg",
                "file": "alltypes.pb.c",
                "static": True,
                "const": True,
                "has_init": True,
                "type": "struct pb_msgdesc_s",
                "raw_type": "const pb_msgdesc_t",
                "size": 512,
                "units": ["nanopb"],
            },
            "alltypes.pb.c#Uninit_msg": {
                "name": "Uninit_msg",
                "file": "alltypes.pb.c",
                "static": False,
                "const": True,
                "has_init": False,
                "type": "struct pb_msgdesc_s",
                "raw_type": "const pb_msgdesc_t",
                "size": 512,
                "units": ["nanopb"],
            },
        }

    dag: dict[str, Any] = {
        "module_kind": "link_unit",
        "trust": {"threat_model": tm_block},
        "modules": {
            "nanopb": {
                "candidate_entry_points": list(funcs_dag),
                "functions": list(funcs_dag),
                "files": ["pb_decode.c", "pb_encode.c", "pb_common.c"],
            }
        },
        "functions": funcs_dag,
        "global_variables": gvars,
    }
    model: dict[str, Any] = {
        "status": "ok",
        "trust": {"threat_model": tm_block},
        "units": {
            "nanopb": {
                "kind": "static_lib",
                "test": False,
                "files": ["pb_decode.c", "pb_encode.c", "pb_common.c"],
                "links": [],
            }
        },
        "functions": {
            "pb_decode.c#pb_decode": {
                "name": "pb_decode",
                "file": "pb_decode.c",
                "signature": "_Bool(struct pb_istream_s *,struct pb_msgdesc_s *,void *)",
                "formals": [
                    {"name": "stream", "kind": "pointer"},
                    {"name": "fields", "kind": "const_pointer"},
                    {"name": "dest_struct", "kind": "pointer"},
                ],
            },
            "pb_decode.c#pb_decode_ex": {
                "name": "pb_decode_ex",
                "file": "pb_decode.c",
                "signature": "_Bool(struct pb_istream_s *,struct pb_msgdesc_s *,void *,unsigned int)",
                "formals": [
                    {"name": "stream", "kind": "pointer"},
                    {"name": "fields", "kind": "const_pointer"},
                    {"name": "dest_struct", "kind": "pointer"},
                    {"name": "flags", "kind": "value"},
                ],
            },
            "pb_decode.c#pb_decode_varint": {
                "name": "pb_decode_varint",
                "file": "pb_decode.c",
                "signature": "_Bool(struct pb_istream_s *,unsigned long long *)",
                "formals": [
                    {"name": "stream", "kind": "pointer"},
                    {"name": "dest", "kind": "pointer"},
                ],
            },
            "pb_decode.c#pb_istream_from_buffer": {
                "name": "pb_istream_from_buffer",
                "file": "pb_decode.c",
                "signature": "struct pb_istream_s(unsigned char *,unsigned long)",
                "formals": [
                    {"name": "buf", "kind": "const_pointer"},
                    {"name": "bufsize", "kind": "value"},
                ],
            },
            "pb_encode.c#pb_ostream_from_buffer": {
                "name": "pb_ostream_from_buffer",
                "file": "pb_encode.c",
                "signature": "struct pb_ostream_s(unsigned char *,unsigned long)",
                "formals": [
                    {"name": "buf", "kind": "pointer"},
                    {"name": "bufsize", "kind": "value"},
                ],
            },
            "pb_common.c#pb_field_iter_begin": {
                "name": "pb_field_iter_begin",
                "file": "pb_common.c",
                "signature": "_Bool(struct pb_field_iter_s *,struct pb_msgdesc_s *,void *)",
                "formals": [
                    {"name": "iter", "kind": "pointer"},
                    {"name": "desc", "kind": "const_pointer"},
                    {"name": "message", "kind": "pointer"},
                ],
            },
            "pb_common.c#pb_field_iter_find": {
                "name": "pb_field_iter_find",
                "file": "pb_common.c",
                "signature": "_Bool(struct pb_field_iter_s *,unsigned int)",
                "formals": [
                    {"name": "iter", "kind": "pointer"},
                    {"name": "tag", "kind": "value"},
                ],
            },
            "pb_decode.c#pb_trusted_helper": {
                "name": "pb_trusted_helper",
                "file": "pb_decode.c",
                "signature": "int(struct pb_istream_s *)",
                "formals": [{"name": "stream", "kind": "pointer"}],
            },
        },
        "global_variables": gvars,
    }
    layouts: dict[str, dict[str, Any]] = {
        "struct pb_msgdesc_s": {
            "what": "struct",
            "size": 24,
            "align": 8,
            "pointers": True,
            "fields": [
                {"name": "field_count", "kind": "int", "off": 0, "size": 4, "pointers": False, "ctype": "unsigned int"},
                {"name": "field_info", "kind": "ptr", "off": 8, "size": 8, "pointers": True, "const": True},
                {"name": "submsg_info", "kind": "ptr", "off": 16, "size": 8, "pointers": True, "const": True},
            ],
        },
        "struct pb_istream_s": {
            "what": "struct",
            "size": 24,
            "align": 8,
            "pointers": True,
            "fields": [
                {"name": "callback", "kind": "fnptr", "off": 0, "size": 8, "pointers": True},
                {"name": "state", "kind": "ptr", "off": 8, "size": 8, "pointers": True, "const": False},
                {
                    "name": "bytes_left",
                    "kind": "int",
                    "off": 16,
                    "size": 8,
                    "pointers": False,
                    "ctype": "unsigned long",
                },
            ],
        },
        "struct pb_field_iter_s": {
            "what": "struct",
            "size": 16,
            "align": 8,
            "pointers": True,
            "fields": [
                {"name": "descriptor", "kind": "ptr", "off": 0, "size": 8, "pointers": True, "const": True},
                {"name": "message", "kind": "ptr", "off": 8, "size": 8, "pointers": True, "const": False},
            ],
        },
    }
    return dag, model, layouts


def test_nanopb_s1_s2_s3_trusted_schema_never_fuzzed_and_capped_at_4(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _nanopb_fixture()

    planned = ah.plan(dag, model, "nanopb", "nanopb", 256, struct_layouts=layouts)

    # Non-attacker functions and trusted_callers are auto-exempted, never fuzzed.
    auto_exempt = planned["auto_exempt"]
    for non_attacker in (
        "pb_decode.c#pb_istream_from_buffer",
        "pb_encode.c#pb_ostream_from_buffer",
        "pb_common.c#pb_field_iter_begin",
        "pb_decode.c#pb_trusted_helper",
    ):
        assert auto_exempt[non_attacker] == ah.NO_ATTACKER_DATA_REASON
        assert planned["skipped"][non_attacker] == ah.NO_ATTACKER_DATA_REASON

    # pb_decode expands to exactly MAX_SCHEMA_INSTANCES (4) cases, largest/richest first, Small_msg dropped.
    decode_pairs = [
        (stmt, lay)
        for stmt, lay in zip(planned["cases"], planned["layouts"], strict=True)
        if lay["calls"] == ["pb_decode"]
    ]
    assert len(decode_pairs) == ah.MAX_SCHEMA_INSTANCES
    assert [lay["schema_instance"] for _, lay in decode_pairs] == [
        "AllTypes_msg",
        "Zeta_msg",
        "Big_msg",
        "Med_msg",
    ]
    for stmt, lay in decode_pairs:
        inst = lay["schema_instance"]
        # S2 by-value builder builds the stream directly from fuzz bytes (with safe non-NULL empty slice).
        assert lay["builder"] == "pb_istream_from_buffer"
        assert "static uint8_t c1a0_empty[1] = {0};" in stmt
        assert (
            "c0a0 = pb_istream_from_buffer("
            "(unsigned char *)((fuzz_len > fuzz_off) ? (fuzz_buf + fuzz_off) : c1a0_empty), "
            "(unsigned long)((fuzz_len > fuzz_off) ? (fuzz_len - fuzz_off) : 0U));" in stmt
        )
        # Trusted descriptor is bound to the real const schema instance, NEVER fuzzed!
        assert f"pb_decode(&c0a0, &{inst}, (void *)c0a2)" in stmt
        assert lay["slots"] == []
        assert lay["rest"] == {"call": 1, "param": 0, "kind": "bytes"}
        assert lay["inits"] == [{"fn": "pb_istream_from_buffer", "call": 1, "for": {"call": 0, "param": 0}}]
        assert "field_count" not in stmt

    # pb_decode_ex: trusted scalar `flags` is zeroed without a fuzz slot!
    ex_pairs = [
        (stmt, lay)
        for stmt, lay in zip(planned["cases"], planned["layouts"], strict=True)
        if lay["calls"] == ["pb_decode_ex"]
    ]
    assert len(ex_pairs) == ah.MAX_SCHEMA_INSTANCES
    for stmt, lay in ex_pairs:
        assert lay["slots"] == []
        assert "unsigned int c0a3; memset(&c0a3, 0, sizeof(c0a3));" in stmt

    # Reader `pb_decode_varint`: stream built from fuzz bytes via S2 builder; output `dest` gets clean buffer.
    reader_pairs = [
        (stmt, lay)
        for stmt, lay in zip(planned["cases"], planned["layouts"], strict=True)
        if lay["calls"] == ["pb_decode_varint"]
    ]
    assert len(reader_pairs) == 1
    r_stmt, r_lay = reader_pairs[0]
    assert r_lay["builder"] == "pb_istream_from_buffer"
    assert "static uint8_t c1a0_empty[1] = {0};" in r_stmt
    assert (
        "c0a0 = pb_istream_from_buffer("
        "(unsigned char *)((fuzz_len > fuzz_off) ? (fuzz_buf + fuzz_off) : c1a0_empty), "
        "(unsigned long)((fuzz_len > fuzz_off) ? (fuzz_len - fuzz_off) : 0U));" in r_stmt
    )
    assert r_lay["slots"] == []
    assert r_lay["rest"] == {"call": 1, "param": 0, "kind": "bytes"}

    # SD1b schema-taking builder: `pb_field_iter_find` initializes `iter` via `pb_field_iter_begin` + S3 instance.
    iter_pairs = [
        (stmt, lay)
        for stmt, lay in zip(planned["cases"], planned["layouts"], strict=True)
        if lay["calls"] == ["pb_field_iter_find"]
    ]
    assert len(iter_pairs) == ah.MAX_SCHEMA_INSTANCES
    assert [lay["schema_instance"] for _, lay in iter_pairs] == ["AllTypes_msg", "Zeta_msg", "Big_msg", "Med_msg"]
    for stmt, lay in iter_pairs:
        inst = lay["schema_instance"]
        assert lay["builder"] == "pb_field_iter_begin"
        assert f"(void)pb_field_iter_begin((struct pb_field_iter_s *)&c0a0, &{inst}," in stmt
        assert "pb_field_iter_find(&c0a0, c0a1)" in stmt

    # Schema externs & sources recorded for linking.
    assert "AllTypes_msg" in planned["schema_externs"]
    assert planned["schema_externs"]["AllTypes_msg"] == "extern pb_msgdesc_t const AllTypes_msg;"
    assert "alltypes.pb.c" in planned["schema_sources"]


def test_nanopb_trusted_param_without_instance_is_auto_exempt(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _nanopb_fixture(include_globals=False)

    planned = ah.plan(dag, model, "nanopb", "nanopb", 256, struct_layouts=layouts)

    # No const pb_msgdesc_s global -> pb_decode, pb_decode_ex, pb_field_iter_find skipped with exact SD2(c) reason.
    assert planned["auto_exempt"]["pb_decode.c#pb_decode"] == "trusted parameter fields has no instance"
    assert planned["auto_exempt"]["pb_decode.c#pb_decode_ex"] == "trusted parameter fields has no instance"
    assert planned["auto_exempt"]["pb_common.c#pb_field_iter_find"] == "trusted parameter iter has no instance"
    # Reader `pb_decode_varint` needs only the stream builder (no descriptor) -> still generated!
    assert [lay["calls"] for lay in planned["layouts"]] == [["pb_decode_varint"]]


def test_nanopb_fallback_input_sources_when_dag_lacks_per_fn_roles(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _nanopb_fixture(per_fn_trust=False, fallback_input_sources=True)

    planned = ah.plan(dag, model, "nanopb", "nanopb", 256, struct_layouts=layouts)

    assert planned["auto_exempt"]["pb_encode.c#pb_ostream_from_buffer"] == ah.NO_ATTACKER_DATA_REASON
    assert planned["auto_exempt"]["pb_decode.c#pb_trusted_helper"] == ah.NO_ATTACKER_DATA_REASON
    decode_lays = [lay for lay in planned["layouts"] if lay["calls"] == ["pb_decode"]]
    assert len(decode_lays) == ah.MAX_SCHEMA_INSTANCES
    assert decode_lays[0]["schema_instance"] == "AllTypes_msg"
    assert decode_lays[0]["builder"] == "pb_istream_from_buffer"


def test_nanopb_flags_off_preserves_legacy_behavior(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "off")
    dag, model, layouts = _nanopb_fixture()

    planned = ah.plan(dag, model, "nanopb", "nanopb", 256, struct_layouts=layouts)

    assert planned["auto_exempt"] == {}
    # Every entry (including pb_ostream_from_buffer and pb_trusted_helper) gets a legacy single case.
    called = {lay["calls"][0] for lay in planned["layouts"]}
    assert {"pb_decode", "pb_ostream_from_buffer", "pb_trusted_helper", "pb_field_iter_begin"} <= called
    # No schema_instance or builder metadata in legacy mode.
    assert all("schema_instance" not in lay and "builder" not in lay for lay in planned["layouts"])
    # Legacy pb_decode has only 1 case and does not call pb_istream_from_buffer.
    decode_stmts = [
        stmt for stmt, lay in zip(planned["cases"], planned["layouts"], strict=True) if lay["calls"] == ["pb_decode"]
    ]
    assert len(decode_stmts) == 1
    assert "pb_istream_from_buffer" not in decode_stmts[0]
    assert "&AllTypes_msg" not in decode_stmts[0]


def test_nanopb_end_to_end_generate_sidecar_schema_and_corpus_mapping(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _nanopb_fixture()

    reports = tmp_path / "workspace" / "reports"
    harnesses = tmp_path / "workspace" / "harnesses"
    reports.mkdir(parents=True)
    harnesses.mkdir(parents=True)
    dag_path = reports / "callgraph_dag.json"
    model_path = reports / "phase0_model.json"
    dag_path.write_text(json.dumps(dag), encoding="utf-8")
    model_path.write_text(json.dumps(model), encoding="utf-8")

    # Generate via api_harness.generate (probe=False so test has no clang dependency)
    res = ah.generate(
        module="nanopb",
        header="none",
        max_input_size=256,
        cppflags="",
        out_dir=harnesses,
        unit="nanopb",
        auto_prelude=False,
        probe=False,
        dag_path=dag_path,
        model_path=model_path,
        struct_layouts=layouts,
        variadic={},
    )
    sidecar_path = Path(res["harness_meta"])
    harness_c = Path(res["harness_file"]).read_text(encoding="utf-8")
    sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))

    # Schema validation passes cleanly with schema_instance, builder, and api_auto_exempt!
    errs = validate_sidecar(sidecar, module="nanopb")
    assert not errs, f"sidecar validation errors: {list(errs)}"
    assert sidecar["api_auto_exempt"]["pb_encode.c#pb_ostream_from_buffer"] == ah.NO_ATTACKER_DATA_REASON
    assert sidecar["api_auto_exempt"]["pb_decode.c#pb_trusted_helper"] == ah.NO_ATTACKER_DATA_REASON
    assert "extern pb_msgdesc_t const AllTypes_msg;" in harness_c
    # Eva soundness invariant: eva_main still uses Frama_C_make_unknown over full attacker input!
    assert "Frama_C_make_unknown(" in harness_c

    # Corpus mapping (fuzz_assets.write_module) maps whole-input seeds onto all 4 S3 pb_decode cases!
    corpus_dir = tmp_path / "workspace" / "fuzz_assets" / "corpora" / "alltypes_corpus"
    corpus_dir.mkdir(parents=True)
    seed_payload = b"\x08\x96\x01"
    (corpus_dir / "deadbeef01234567").write_bytes(seed_payload)
    fa_doc = {
        "schema_version": 1,
        "generated_at": "2026-11-22T00:00:00Z",
        "target": "/target",
        "fuzzers": [],
        "corpora": [{"id": "alltypes_corpus", "path": "tests/corpus", "kind": "dir", "imported": {"kept": 1}}],
        "mappings": [
            {
                "corpus": "alltypes_corpus",
                "fuzzer": None,
                "functions": ["pb_decode"],
                "ignored": False,
                "reason": None,
                "source": "agent",
            }
        ],
        "warnings": [],
    }
    report = fa.write_module("nanopb", sidecar, harness_c, fa_doc)
    decode_selectors = [lay["selector"] for lay in sidecar["api_cases"] if lay["calls"] == ["pb_decode"]]
    assert len(decode_selectors) == 4
    assert sorted(int(k) for k in report["cases"]) == sorted(decode_selectors)
    assert report["inputs"] == 4
    written = sorted(p.read_bytes() for p in (tmp_path / "workspace" / "imported_corpus" / "nanopb").iterdir())
    assert written == [bytes([sel]) + seed_payload for sel in sorted(decode_selectors)]

    # With FRAMAC_API_TRUST_SCHEMA=off, fuzz_assets preserves legacy behavior (does not follow builder inits).
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "off")
    legacy_sels = fa._whole_input_selectors(sidecar, harness_c, {"pb_decode"})
    assert legacy_sels == []


def test_generate_harness_cli_passes_globals_and_trust(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _nanopb_fixture()

    reports = tmp_path / "workspace" / "reports"
    harnesses = tmp_path / "workspace" / "harnesses"
    reports.mkdir(parents=True)
    harnesses.mkdir(parents=True)
    (reports / "callgraph_dag.json").write_text(json.dumps(dag), encoding="utf-8")
    (reports / "phase0_model.json").write_text(json.dumps(model), encoding="utf-8")

    captured: dict[str, Any] = {}
    orig_generate = ah.generate

    def spy_generate(*args: Any, **kwargs: Any) -> dict[str, Any]:
        captured["global_variables"] = kwargs.get("global_variables")
        captured["trust"] = kwargs.get("trust")
        kwargs["probe"] = False
        kwargs["struct_layouts"] = layouts
        kwargs["variadic"] = {}
        return orig_generate(*args, **kwargs)

    monkeypatch.setattr(ah, "generate", spy_generate)
    rc = gh.main(["--api", "--module", "nanopb", "--unit", "nanopb", "--header", "none", "--no-auto-prelude"])
    assert rc == 0
    assert isinstance(captured["global_variables"], dict)
    assert "alltypes.pb.c#AllTypes_msg" in captured["global_variables"]
    assert captured["trust"] == dag["trust"]
    sidecar = json.loads((harnesses / "harness_nanopb.json").read_text(encoding="utf-8"))
    assert "api_auto_exempt" in sidecar
    assert not validate_sidecar(sidecar, module="nanopb")


# ---------------------------------------------------------------------------
# libmodbus-shaped multi-backend handle fixture
# ---------------------------------------------------------------------------


def _libmodbus_fixture() -> tuple[dict[str, Any], dict[str, Any], ah.Declared]:
    fns: dict[str, tuple[str, list[dict[str, str]], dict[str, Any]]] = {
        "modbus.c#modbus_new_tcp": (
            "struct _modbus *(char *,int)",
            [{"name": "ip", "kind": "const_pointer"}, {"name": "port", "kind": "value"}],
            {"ret": "struct _modbus *", "params": [None, None]},
        ),
        "modbus.c#modbus_new_tcp_pi": (
            "struct _modbus *(char *,char *)",
            [{"name": "node", "kind": "const_pointer"}, {"name": "service", "kind": "const_pointer"}],
            {"ret": "struct _modbus *", "params": [None, None]},
        ),
        "modbus.c#modbus_new_rtu": (
            "struct _modbus *(char *,int,char,int,int)",
            [
                {"name": "device", "kind": "const_pointer"},
                {"name": "baud", "kind": "value"},
                {"name": "parity", "kind": "value"},
                {"name": "data_bit", "kind": "value"},
                {"name": "stop_bit", "kind": "value"},
            ],
            {"ret": "struct _modbus *", "params": [None, None, None, None, None]},
        ),
        "modbus.c#modbus_free": (
            "void(struct _modbus *)",
            [{"name": "ctx", "kind": "pointer"}],
            {"ret": None, "params": ["struct _modbus *"]},
        ),
        "modbus.c#modbus_tcp_pi_listen": (
            "int(struct _modbus *,int)",
            [{"name": "ctx", "kind": "pointer"}, {"name": "nb_connection", "kind": "value"}],
            {"ret": None, "params": ["struct _modbus *", None]},
        ),
        "modbus.c#modbus_tcp_listen": (
            "int(struct _modbus *,int)",
            [{"name": "ctx", "kind": "pointer"}, {"name": "nb_connection", "kind": "value"}],
            {"ret": None, "params": ["struct _modbus *", None]},
        ),
        "modbus.c#modbus_rtu_set_serial_mode": (
            "int(struct _modbus *,int)",
            [{"name": "ctx", "kind": "pointer"}, {"name": "mode", "kind": "value"}],
            {"ret": None, "params": ["struct _modbus *", None]},
        ),
        "modbus.c#modbus_read_bits": (
            "int(struct _modbus *,int,int,unsigned char *)",
            [
                {"name": "ctx", "kind": "pointer"},
                {"name": "addr", "kind": "value"},
                {"name": "nb", "kind": "value"},
                {"name": "dest", "kind": "pointer"},
            ],
            {"ret": None, "params": ["struct _modbus *", None, None, None]},
        ),
    }
    dag_fns = {k: {"name": k.split("#")[1], "file": "modbus.c", "is_static": False, "module": "modbus"} for k in fns}
    dag = {
        "module_kind": "link_unit",
        "modules": {"modbus": {"candidate_entry_points": list(fns), "functions": list(fns)}},
        "functions": dag_fns,
    }
    model = {
        "status": "ok",
        "functions": {
            k: {"name": k.split("#")[1], "file": "modbus.c", "signature": sig, "formals": formals}
            for k, (sig, formals, _) in fns.items()
        },
    }
    visible = ah.Declared(
        [k.split("#")[1] for k in fns],
        prototypes={k.split("#")[1]: proto for k, (_, _, proto) in fns.items()},
    )
    return dag, model, visible


def test_libmodbus_backend_matched_constructors(monkeypatch: pytest.MonkeyPatch):
    dag, model, visible = _libmodbus_fixture()

    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    planned_on = ah.plan(dag, model, "modbus", "modbus", 256, struct_layouts={}, visible=visible)
    by_fn_on = {
        lay["calls"][0]: stmt
        for stmt, lay in zip(planned_on["cases"], planned_on["layouts"], strict=True)
        if lay["kind"] == "single"
    }
    assert "modbus_new_tcp_pi(" in by_fn_on["modbus_tcp_pi_listen"]
    assert "modbus_new_tcp(" in by_fn_on["modbus_tcp_listen"]
    assert "modbus_new_tcp_pi(" not in by_fn_on["modbus_tcp_listen"]
    assert "modbus_new_rtu(" in by_fn_on["modbus_rtu_set_serial_mode"]
    assert "modbus_new_tcp(" in by_fn_on["modbus_read_bits"]

    # With flag off, legacy behavior picks fewest-param / alphabetically-first constructor (`modbus_new_tcp`).
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "off")
    planned_off = ah.plan(dag, model, "modbus", "modbus", 256, struct_layouts={}, visible=visible)
    by_fn_off = {
        lay["calls"][0]: stmt
        for stmt, lay in zip(planned_off["cases"], planned_off["layouts"], strict=True)
        if lay["kind"] == "single"
    }
    assert "modbus_new_tcp(" in by_fn_off["modbus_tcp_pi_listen"]
    assert "modbus_new_tcp(" in by_fn_off["modbus_rtu_set_serial_mode"]


# ---------------------------------------------------------------------------
# sudo-shaped TAILQ_HEAD / STAILQ_HEAD & refcount helper skips
# ---------------------------------------------------------------------------


def _sudo_fixture() -> tuple[dict[str, Any], dict[str, Any], dict[str, dict[str, Any]]]:
    dag_fns = {
        "list.c#tailq_push": {"name": "tailq_push", "file": "list.c", "is_static": False, "module": "sudo"},
        "list.c#stailq_push": {"name": "stailq_push", "file": "list.c", "is_static": False, "module": "sudo"},
        "list.c#ctx_push": {"name": "ctx_push", "file": "list.c", "is_static": False, "module": "sudo"},
        "rcstr.c#sudo_rcstr_addref": {
            "name": "sudo_rcstr_addref",
            "file": "rcstr.c",
            "is_static": False,
            "module": "sudo",
        },
        "rcstr.c#sudo_rcstr_delref": {
            "name": "sudo_rcstr_delref",
            "file": "rcstr.c",
            "is_static": False,
            "module": "sudo",
        },
        "obj.c#obj_unref": {"name": "obj_unref", "file": "obj.c", "is_static": False, "module": "sudo"},
        "obj.c#obj_decref": {"name": "obj_decref", "file": "obj.c", "is_static": False, "module": "sudo"},
    }
    dag = {
        "module_kind": "link_unit",
        "modules": {"sudo": {"candidate_entry_points": list(dag_fns), "functions": list(dag_fns)}},
        "functions": dag_fns,
    }
    model = {
        "status": "ok",
        "functions": {
            "list.c#tailq_push": {
                "name": "tailq_push",
                "file": "list.c",
                "signature": "void(struct item_list *,int)",
                "formals": [{"name": "head", "kind": "pointer"}, {"name": "val", "kind": "value"}],
            },
            "list.c#stailq_push": {
                "name": "stailq_push",
                "file": "list.c",
                "signature": "void(struct sitem_list *,int)",
                "formals": [{"name": "head", "kind": "pointer"}, {"name": "val", "kind": "value"}],
            },
            "list.c#ctx_push": {
                "name": "ctx_push",
                "file": "list.c",
                "signature": "void(struct sudo_ctx *)",
                "formals": [{"name": "ctx", "kind": "pointer"}],
            },
            "rcstr.c#sudo_rcstr_addref": {
                "name": "sudo_rcstr_addref",
                "file": "rcstr.c",
                "signature": "char *(char *)",
                "formals": [{"name": "s", "kind": "const_pointer"}],
            },
            "rcstr.c#sudo_rcstr_delref": {
                "name": "sudo_rcstr_delref",
                "file": "rcstr.c",
                "signature": "void(char *)",
                "formals": [{"name": "s", "kind": "const_pointer"}],
            },
            "obj.c#obj_unref": {
                "name": "obj_unref",
                "file": "obj.c",
                "signature": "void(struct refobj *)",
                "formals": [{"name": "obj", "kind": "pointer"}],
            },
            "obj.c#obj_decref": {
                "name": "obj_decref",
                "file": "obj.c",
                "signature": "void(struct refobj *)",
                "formals": [{"name": "obj", "kind": "pointer"}],
            },
        },
    }
    layouts: dict[str, dict[str, Any]] = {
        "struct item_list": {
            "what": "struct",
            "size": 16,
            "align": 8,
            "pointers": True,
            "fields": [
                {"name": "tqh_first", "kind": "ptr", "off": 0, "size": 8, "pointers": True, "const": False},
                {"name": "tqh_last", "kind": "ptr", "off": 8, "size": 8, "pointers": True, "const": False},
            ],
        },
        "struct sitem_list": {
            "what": "struct",
            "size": 16,
            "align": 8,
            "pointers": True,
            "fields": [
                {"name": "stqh_first", "kind": "ptr", "off": 0, "size": 8, "pointers": True, "const": False},
                {"name": "stqh_last", "kind": "ptr", "off": 8, "size": 8, "pointers": True, "const": False},
            ],
        },
        "struct sudo_ctx": {
            "what": "struct",
            "size": 24,
            "align": 8,
            "pointers": True,
            "fields": [
                {"name": "flags", "kind": "int", "off": 0, "size": 4, "pointers": False, "ctype": "int"},
                {
                    "name": "env_list",
                    "kind": "record",
                    "what": "struct",
                    "ctype": "struct item_list",
                    "off": 8,
                    "size": 16,
                    "pointers": True,
                },
            ],
        },
        "struct refobj": {
            "what": "struct",
            "size": 8,
            "align": 8,
            "pointers": False,
            "fields": [{"name": "refcnt", "kind": "int", "off": 0, "size": 4, "pointers": False, "ctype": "int"}],
        },
    }
    return dag, model, layouts


def test_sudo_tailq_stailq_init_and_refcount_skips(monkeypatch: pytest.MonkeyPatch):
    dag, model, layouts = _sudo_fixture()

    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    planned = ah.plan(dag, model, "sudo", "sudo", 256, struct_layouts=layouts)
    by_fn = {lay["calls"][0]: stmt for stmt, lay in zip(planned["cases"], planned["layouts"], strict=True)}

    # Top-level TAILQ_HEAD and STAILQ_HEAD initialized properly (never leaving tqh_last == NULL).
    assert "c0a0.tqh_first = NULL; c0a0.tqh_last = &c0a0.tqh_first;" in by_fn["tailq_push"]
    assert "c0a0.stqh_first = NULL; c0a0.stqh_last = &c0a0.stqh_first;" in by_fn["stailq_push"]
    # Nested TAILQ_HEAD inside a non-const context struct also initialized properly!
    assert "c0a0.env_list.tqh_first = NULL; c0a0.env_list.tqh_last = &c0a0.env_list.tqh_first;" in by_fn["ctx_push"]

    # Refcount helpers without producer are auto-exempted with exact contract reason.
    for key in (
        "rcstr.c#sudo_rcstr_addref",
        "rcstr.c#sudo_rcstr_delref",
        "obj.c#obj_unref",
        "obj.c#obj_decref",
    ):
        assert planned["auto_exempt"][key] == ah.REFCOUNT_EXEMPT_REASON
        assert planned["skipped"][key] == ah.REFCOUNT_EXEMPT_REASON
        assert key.split("#")[1] not in by_fn

    # Legacy mode (flag off): no TAILQ init, no refcount skip.
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "off")
    planned_off = ah.plan(dag, model, "sudo", "sudo", 256, struct_layouts=layouts)
    by_fn_off = {lay["calls"][0]: stmt for stmt, lay in zip(planned_off["cases"], planned_off["layouts"], strict=True)}
    assert "tqh_last = &c0a0.tqh_first" not in by_fn_off["tailq_push"]
    assert "sudo_rcstr_addref" in by_fn_off
    assert "sudo_rcstr_delref" in by_fn_off
    assert planned_off["auto_exempt"] == {}


# ---------------------------------------------------------------------------
# Wave 6 follow-up fixes (W7-C):
#   1. Whole-input `rest` feeding for S2 `(buf, len)` builders (even with param_sizes)
#   2. Nullable default-allocator trusted pointer params (`ProtobufCAllocator *`)
#   3. `static` functions recorded in `api_auto_exempt`
# ---------------------------------------------------------------------------


def test_s2_builder_with_param_sizes_feeds_whole_input_rest_and_maps_corpus(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """
    Reproduces Wave 6 A/B-1b (`nanopb`): `pb_istream_from_buffer` had internal call-site
    `param_sizes={"0": {"min": 10, "max": 10}}`, which pinned it to a 10-byte stack buffer
    (`slots=2, rest=None`) and made `fuzz_assets._whole_input_selectors` map 0 cases.
    """
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _nanopb_fixture(include_globals=False)
    # Real nanopb internal call site records param_sizes=10 on pb_istream_from_buffer(buf, msglen).
    model["functions"]["pb_decode.c#pb_istream_from_buffer"]["param_sizes"] = {"0": {"min": 10, "max": 10}}
    # Add pb_read (output buf, count) and a target function that claims rest itself.
    dag["functions"]["pb_decode.c#pb_read"] = {
        "name": "pb_read",
        "file": "pb_decode.c",
        "is_static": False,
        "module": "nanopb",
        "trust": {"value": "untrusted", "source": "threat_model", "input_role": "reader", "attacker_params": None},
    }
    dag["functions"]["pb_decode.c#pb_compare_extra"] = {
        "name": "pb_compare_extra",
        "file": "pb_decode.c",
        "is_static": False,
        "module": "nanopb",
        "trust": {
            "value": "untrusted",
            "source": "threat_model",
            "input_role": "entry",
            "attacker_params": ["stream", "extra"],
        },
    }
    dag["modules"]["nanopb"]["candidate_entry_points"].extend(["pb_decode.c#pb_read", "pb_decode.c#pb_compare_extra"])
    dag["modules"]["nanopb"]["functions"].extend(["pb_decode.c#pb_read", "pb_decode.c#pb_compare_extra"])
    model["functions"]["pb_decode.c#pb_read"] = {
        "name": "pb_read",
        "file": "pb_decode.c",
        "signature": "_Bool(struct pb_istream_s *,unsigned char *,unsigned long)",
        "formals": [
            {"name": "stream", "kind": "pointer"},
            {"name": "buf", "kind": "pointer"},
            {"name": "count", "kind": "value"},
        ],
    }
    model["functions"]["pb_decode.c#pb_compare_extra"] = {
        "name": "pb_compare_extra",
        "file": "pb_decode.c",
        "signature": "_Bool(struct pb_istream_s *,unsigned char *,unsigned long)",
        "formals": [
            {"name": "stream", "kind": "pointer"},
            {"name": "extra", "kind": "const_pointer"},
            {"name": "extra_len", "kind": "value"},
        ],
    }

    reports = tmp_path / "workspace" / "reports"
    harnesses = tmp_path / "workspace" / "harnesses"
    reports.mkdir(parents=True)
    harnesses.mkdir(parents=True)
    dag_path = reports / "callgraph_dag.json"
    model_path = reports / "phase0_model.json"
    dag_path.write_text(json.dumps(dag), encoding="utf-8")
    model_path.write_text(json.dumps(model), encoding="utf-8")

    res = ah.generate(
        module="nanopb",
        header="none",
        max_input_size=256,
        cppflags="",
        out_dir=harnesses,
        unit="nanopb",
        auto_prelude=False,
        probe=False,
        dag_path=dag_path,
        model_path=model_path,
        struct_layouts=layouts,
        variadic={},
    )
    harness_c = Path(res["harness_file"]).read_text(encoding="utf-8")
    sidecar = json.loads(Path(res["harness_meta"]).read_text(encoding="utf-8"))
    assert not validate_sidecar(sidecar, module="nanopb")

    # Eva soundness: full-range Frama_C_make_unknown over input_buf preserved.
    assert "Frama_C_make_unknown((char *)input_buf, input_len);" in harness_c

    from seed_harvest import harness_cases

    by_fn = {lay["calls"][0]: lay for lay in sidecar["api_cases"]}
    case_body = dict(harness_cases(harness_c))
    case_line = {fn: case_body[lay["selector"]] for fn, lay in by_fn.items()}
    # pb_decode_varint: builder consumes whole-input rest (NO 10-byte stack buffer, 0 slots!).
    varint_lay = by_fn["pb_decode_varint"]
    assert varint_lay["slots"] == []
    assert varint_lay["rest"] == {"call": 1, "param": 0, "kind": "bytes"}
    assert varint_lay["builder"] == "pb_istream_from_buffer"
    assert "c1a0[10]" not in case_line["pb_decode_varint"]
    assert "c1a0_empty" in case_line["pb_decode_varint"]

    # pb_read: its `(buf, count)` is a writable output pair, so pb_istream_from_buffer STILL claims rest!
    read_lay = by_fn["pb_read"]
    assert read_lay["rest"] == {"call": 1, "param": 0, "kind": "bytes"}
    assert read_lay["builder"] == "pb_istream_from_buffer"
    assert "c1a0[10]" not in case_line["pb_read"]
    assert "c1a0_empty" in case_line["pb_read"]

    # pb_compare_extra: target ITSELF has an attacker `(const buf, len)` pair -> target claims rest, not builder!
    cmp_lay = by_fn["pb_compare_extra"]
    assert cmp_lay["rest"] == {"call": 0, "param": 1, "kind": "bytes"}
    assert "c1a0[10]" in case_line["pb_compare_extra"]

    # fuzz_assets maps whole-input corpus onto S2-builder cases (>0 mapped cases, via target OR builder name).
    corpus_dir = tmp_path / "workspace" / "fuzz_assets" / "corpora" / "nanopb_corpus"
    corpus_dir.mkdir(parents=True)
    (corpus_dir / "aabbccdd00112233").write_bytes(b"\x08\xac\x02")
    fa_doc = {
        "schema_version": 1,
        "generated_at": "2026-11-22T00:00:00Z",
        "target": "/target",
        "fuzzers": [],
        "corpora": [{"id": "nanopb_corpus", "path": "tests/corpus", "kind": "dir", "imported": {"kept": 1}}],
        "mappings": [
            {
                "corpus": "nanopb_corpus",
                "fuzzer": None,
                "functions": ["pb_istream_from_buffer"],
                "ignored": False,
                "reason": None,
                "source": "agent",
            }
        ],
        "warnings": [],
    }
    report = fa.write_module("nanopb", sidecar, harness_c, fa_doc)
    assert report["inputs"] > 0
    assert str(varint_lay["selector"]) in report["cases"]

    # Also maps when mapped directly to `pb_decode_varint`.
    assert fa._whole_input_selectors(sidecar, harness_c, {"pb_decode_varint"}) == [varint_lay["selector"]]

    # Flag off: legacy behavior preserved (no builder rest mapping in fuzz_assets, no S2 by-value builder).
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "off")
    assert fa._whole_input_selectors(sidecar, harness_c, {"pb_decode_varint"}) == []
    planned_off = ah.plan(dag, model, "nanopb", "nanopb", 256, struct_layouts=layouts)
    varint_off = next(
        (s, lay)
        for s, lay in zip(planned_off["cases"], planned_off["layouts"], strict=True)
        if lay["calls"] == ["pb_decode_varint"]
    )
    assert "pb_istream_from_buffer" not in varint_off[0]
    assert "c1a0_empty" not in varint_off[0]


def test_s2_pointer_init_builder_with_param_sizes_feeds_whole_input_rest(monkeypatch: pytest.MonkeyPatch):
    """Pointer-init S2 builder `reader_init(struct reader *, const char *, size_t)` with param_sizes gets rest."""
    dag_fns = {
        "r.c#reader_init": {"name": "reader_init", "file": "r.c", "is_static": False, "module": "m"},
        "r.c#reader_parse": {
            "name": "reader_parse",
            "file": "r.c",
            "is_static": False,
            "module": "m",
            "trust": {"value": "untrusted", "source": "threat_model", "input_role": "entry", "attacker_params": ["r"]},
        },
    }
    dag = {
        "module_kind": "link_unit",
        "trust": {"threat_model": {"status": "ok"}},
        "modules": {"m": {"candidate_entry_points": list(dag_fns), "functions": list(dag_fns)}},
        "functions": dag_fns,
    }
    model = {
        "status": "ok",
        "trust": {"threat_model": {"status": "ok"}},
        "functions": {
            "r.c#reader_init": {
                "name": "reader_init",
                "file": "r.c",
                "signature": "void(struct reader *,char *,unsigned long)",
                "formals": [
                    {"name": "r", "kind": "pointer"},
                    {"name": "buf", "kind": "const_pointer"},
                    {"name": "len", "kind": "value"},
                ],
                "param_sizes": {"1": {"min": 12, "max": 12}},
            },
            "r.c#reader_parse": {
                "name": "reader_parse",
                "file": "r.c",
                "signature": "int(struct reader *)",
                "formals": [{"name": "r", "kind": "pointer"}],
            },
        },
    }

    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    planned = ah.plan(dag, model, "m", "m", 256, struct_layouts={})
    assert len(planned["layouts"]) == 1
    stmt, lay = planned["cases"][0], planned["layouts"][0]
    assert lay["calls"] == ["reader_parse"]
    assert lay["builder"] == "reader_init"
    assert lay["slots"] == []
    assert lay["rest"] == {"call": 1, "param": 1, "kind": "bytes"}
    assert "static uint8_t c1a1_empty[1] = {0};" in stmt
    assert "(fuzz_len > fuzz_off) ? (fuzz_buf + fuzz_off) : c1a1_empty" in stmt

    # Flag off: legacy behavior keeps 12-byte param_sizes stack buffer and rest=None.
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "off")
    planned_off = ah.plan(dag, model, "m", "m", 256, struct_layouts={})
    parse_off = next(
        (s, lay)
        for s, lay in zip(planned_off["cases"], planned_off["layouts"], strict=True)
        if lay["calls"] == ["reader_parse"]
    )
    assert parse_off[1]["rest"] is None
    assert len(parse_off[1]["slots"]) == 2
    assert "c1a1[12]" in parse_off[0]


def test_nullable_default_allocator_trusted_pointer_and_strict_schema_guardrail(monkeypatch: pytest.MonkeyPatch):
    """
    Reproduces Wave 6 A/B-1a / A/B-4b (`sudo`):
    - `ProtobufCAllocator *allocator` (and `alloc` / `mem_alloc` / type containing `Allocator`)
      receives `NULL` under `FRAMAC_API_TRUST_SCHEMA=on` instead of being skipped.
    - Non-allocator trusted schema pointers (`pb_msgdesc_t *fields`, `ProtobufCMessageDescriptor *desc`,
      `pb_field_iter_t *iter`, `pb_field_t *field`) MUST STILL refuse with
      `"trusted parameter <name> has no instance"` when no S3 instance exists.
    """
    dag_fns = {
        "log_server.pb-c.c#client_message__unpack": {
            "name": "client_message__unpack",
            "file": "log_server.pb-c.c",
            "is_static": False,
            "module": "liblogsrv_a",
            "trust": {
                "value": "untrusted",
                "source": "threat_model",
                "input_role": "entry",
                "attacker_params": ["data"],
            },
        },
        "log_server.pb-c.c#server_message__unpack": {
            "name": "server_message__unpack",
            "file": "log_server.pb-c.c",
            "is_static": False,
            "module": "liblogsrv_a",
            "trust": {
                "value": "untrusted",
                "source": "threat_model",
                "input_role": "entry",
                "attacker_params": ["data"],
            },
        },
        "log_server.pb-c.c#custom_alloc_unpack": {
            "name": "custom_alloc_unpack",
            "file": "log_server.pb-c.c",
            "is_static": False,
            "module": "liblogsrv_a",
            "trust": {
                "value": "untrusted",
                "source": "threat_model",
                "input_role": "entry",
                "attacker_params": ["data"],
            },
        },
        "log_server.pb-c.c#generic_unpack_needs_desc": {
            "name": "generic_unpack_needs_desc",
            "file": "log_server.pb-c.c",
            "is_static": False,
            "module": "liblogsrv_a",
            "trust": {
                "value": "untrusted",
                "source": "threat_model",
                "input_role": "entry",
                "attacker_params": ["data"],
            },
        },
        "pb_decode.c#pb_decode": {
            "name": "pb_decode",
            "file": "pb_decode.c",
            "is_static": False,
            "module": "liblogsrv_a",
            "trust": {
                "value": "untrusted",
                "source": "threat_model",
                "input_role": "entry",
                "attacker_params": ["data"],
            },
        },
    }
    dag = {
        "module_kind": "link_unit",
        "trust": {"threat_model": {"status": "ok"}},
        "modules": {"liblogsrv_a": {"candidate_entry_points": list(dag_fns), "functions": list(dag_fns)}},
        "functions": dag_fns,
        "global_variables": {},
    }
    model = {
        "status": "ok",
        "trust": {"threat_model": {"status": "ok"}},
        "functions": {
            "log_server.pb-c.c#client_message__unpack": {
                "name": "client_message__unpack",
                "file": "log_server.pb-c.c",
                "signature": "struct _ClientMessage *(struct _ProtobufCAllocator *,unsigned long,unsigned char *)",
                "formals": [
                    {"name": "allocator", "kind": "pointer"},
                    {"name": "len", "kind": "value"},
                    {"name": "data", "kind": "const_pointer"},
                ],
            },
            # Matched via type name (`ProtobufCAllocator`) even when param name is generic `a`.
            "log_server.pb-c.c#server_message__unpack": {
                "name": "server_message__unpack",
                "file": "log_server.pb-c.c",
                "signature": "struct _ServerMessage *(struct ProtobufCAllocator *,unsigned long,unsigned char *)",
                "formals": [
                    {"name": "a", "kind": "pointer"},
                    {"name": "len", "kind": "value"},
                    {"name": "data", "kind": "const_pointer"},
                ],
            },
            # Matched via param name (`mem_alloc`) even when type does not contain "Allocator".
            "log_server.pb-c.c#custom_alloc_unpack": {
                "name": "custom_alloc_unpack",
                "file": "log_server.pb-c.c",
                "signature": "int(struct mem_ops *,unsigned long,unsigned char *)",
                "formals": [
                    {"name": "mem_alloc", "kind": "pointer"},
                    {"name": "len", "kind": "value"},
                    {"name": "data", "kind": "const_pointer"},
                ],
            },
            # Has BOTH a descriptor (`desc`) and an allocator (`allocator`): MUST STILL refuse without desc instance!
            "log_server.pb-c.c#generic_unpack_needs_desc": {
                "name": "generic_unpack_needs_desc",
                "file": "log_server.pb-c.c",
                "signature": "void *(struct _ProtobufCMessageDescriptor *,struct _ProtobufCAllocator *,unsigned long,unsigned char *)",
                "formals": [
                    {"name": "desc", "kind": "const_pointer"},
                    {"name": "allocator", "kind": "pointer"},
                    {"name": "len", "kind": "value"},
                    {"name": "data", "kind": "const_pointer"},
                ],
            },
            # Non-allocator schema descriptor `fields`: MUST STILL refuse without an S3 instance!
            "pb_decode.c#pb_decode": {
                "name": "pb_decode",
                "file": "pb_decode.c",
                "signature": "_Bool(unsigned char *,unsigned long,struct pb_msgdesc_s *)",
                "formals": [
                    {"name": "data", "kind": "const_pointer"},
                    {"name": "len", "kind": "value"},
                    {"name": "fields", "kind": "const_pointer"},
                ],
            },
        },
        "global_variables": {},
    }

    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    planned = ah.plan(dag, model, "liblogsrv_a", "liblogsrv_a", 256, struct_layouts={})
    by_fn = {lay["calls"][0]: (stmt, lay) for stmt, lay in zip(planned["cases"], planned["layouts"], strict=True)}

    # All three allocator-taking unpackers are generated with NULL for allocator and rest for (len, data).
    for fn in ("client_message__unpack", "server_message__unpack", "custom_alloc_unpack"):
        assert fn in by_fn
        stmt, lay = by_fn[fn]
        assert f"{fn}(NULL, (unsigned long)(fuzz_len - fuzz_off), (unsigned char *)(fuzz_buf + fuzz_off))" in stmt
        assert lay["slots"] == []
        assert lay["rest"] == {"call": 0, "param": 2, "kind": "bytes"}

    # STRICT GUARDRAIL: non-allocator trusted descriptors NEVER receive NULL and still auto-exempt.
    assert "pb_decode" not in by_fn
    assert planned["auto_exempt"]["pb_decode.c#pb_decode"] == "trusted parameter fields has no instance"
    assert "generic_unpack_needs_desc" not in by_fn
    assert (
        planned["auto_exempt"]["log_server.pb-c.c#generic_unpack_needs_desc"]
        == "trusted parameter desc has no instance"
    )

    # Flag off: legacy behavior does NOT pass NULL for allocator without null_defaults doc comment.
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "off")
    planned_off = ah.plan(dag, model, "liblogsrv_a", "liblogsrv_a", 256, struct_layouts={})
    by_fn_off = {lay["calls"][0]: stmt for stmt, lay in zip(planned_off["cases"], planned_off["layouts"], strict=True)}
    assert "client_message__unpack(NULL," not in by_fn_off["client_message__unpack"]
    assert "client_message__unpack(&c0a0," in by_fn_off["client_message__unpack"]
    assert planned_off["auto_exempt"] == {}


def test_static_functions_recorded_in_api_auto_exempt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    Reproduces Wave 6 A/B-1b / A/B-4a (`nanopb` static readers `buf_read`, `pb_readbyte`):
    when `FRAMAC_API_TRUST_SCHEMA=on`, skipped `static` functions are recorded in `api_auto_exempt`
    as `"static: not callable from the harness"`; when `off`, `api_auto_exempt` stays absent/empty.
    """
    monkeypatch.chdir(tmp_path)
    dag, model, layouts = _nanopb_fixture(include_globals=False)
    dag["functions"]["pb_decode.c#buf_read"] = {
        "name": "buf_read",
        "file": "pb_decode.c",
        "is_static": True,
        "module": "nanopb",
        "trust": {"value": "untrusted", "source": "threat_model", "input_role": "reader", "attacker_params": None},
    }
    dag["functions"]["pb_decode.c#pb_readbyte"] = {
        "name": "pb_readbyte",
        "file": "pb_decode.c",
        "is_static": True,
        "module": "nanopb",
        "trust": {"value": "untrusted", "source": "threat_model", "input_role": "reader", "attacker_params": None},
    }
    dag["modules"]["nanopb"]["candidate_entry_points"].extend(["pb_decode.c#buf_read", "pb_decode.c#pb_readbyte"])
    dag["modules"]["nanopb"]["functions"].extend(["pb_decode.c#buf_read", "pb_decode.c#pb_readbyte"])

    reports = tmp_path / "workspace" / "reports"
    harnesses = tmp_path / "workspace" / "harnesses"
    reports.mkdir(parents=True)
    harnesses.mkdir(parents=True)
    dag_path = reports / "callgraph_dag.json"
    model_path = reports / "phase0_model.json"
    dag_path.write_text(json.dumps(dag), encoding="utf-8")
    model_path.write_text(json.dumps(model), encoding="utf-8")

    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    res_on = ah.generate(
        module="nanopb",
        header="none",
        max_input_size=256,
        cppflags="",
        out_dir=harnesses,
        unit="nanopb",
        auto_prelude=False,
        probe=False,
        dag_path=dag_path,
        model_path=model_path,
        struct_layouts=layouts,
        variadic={},
    )
    sidecar_on = json.loads(Path(res_on["harness_meta"]).read_text(encoding="utf-8"))
    assert not validate_sidecar(sidecar_on, module="nanopb")
    for key in ("pb_decode.c#buf_read", "pb_decode.c#pb_readbyte"):
        assert sidecar_on["api_skipped"][key] == ah.STATIC_NOT_CALLABLE_REASON
        assert sidecar_on["api_auto_exempt"][key] == ah.STATIC_NOT_CALLABLE_REASON
        assert res_on["api_auto_exempt"][key] == ah.STATIC_NOT_CALLABLE_REASON

    # Flag off: static functions stay in api_skipped only; api_auto_exempt is absent.
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "off")
    res_off = ah.generate(
        module="nanopb",
        header="none",
        max_input_size=256,
        cppflags="",
        out_dir=harnesses,
        unit="nanopb",
        auto_prelude=False,
        probe=False,
        dag_path=dag_path,
        model_path=model_path,
        struct_layouts=layouts,
        variadic={},
    )
    sidecar_off = json.loads(Path(res_off["harness_meta"]).read_text(encoding="utf-8"))
    assert "api_auto_exempt" not in sidecar_off
    assert "api_auto_exempt" not in res_off
    assert sidecar_off["api_skipped"]["pb_decode.c#buf_read"] == ah.STATIC_NOT_CALLABLE_REASON


# ---------------------------------------------------------------------------
# Trusted NUL-terminated string parameters (QCBOR run-1 `szLabel`)
# ---------------------------------------------------------------------------


def _cstring_fixture(
    *,
    label_type: str = "char const *",
    label_kind: str = "const_pointer",
    attacker: tuple[str, ...] = ("c", "out"),
    label_sizes: dict[str, int] | None = None,
    after_label: tuple[str, str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, dict[str, Any]]]:
    """
    A QCBOR-shaped map lookup `int lookup(struct ctx *c, const char *szLabel, int *out)` whose
    threat-model `input_sources` entry lists only the context and the output (`params`): the label is
    chosen by the application, so it is a trusted parameter, not attacker data. `after_label` adds a
    scalar `(ctype, name)` between the label and `out` (QCBOR's `uint32_t uConvertTypes`).
    """
    extra_types = f"{after_label[0]}," if after_label else ""
    extra_formals = [{"name": after_label[1], "kind": "value"}] if after_label else []
    key = "lookup.c#lookup"
    tm_block: dict[str, Any] = {
        "status": "ok",
        "input_sources": [
            {"function": "lookup", "role": "entry", "params": list(attacker), "description": "map search by label"},
        ],
    }
    rec: dict[str, Any] = {
        "name": "lookup",
        "file": "lookup.c",
        "signature": f"int(struct ctx *,{label_type},{extra_types}int *)",
        "formals": [
            {"name": "c", "kind": "pointer"},
            {"name": "szLabel", "kind": label_kind},
            *extra_formals,
            {"name": "out", "kind": "pointer"},
        ],
    }
    if label_sizes is not None:
        rec["param_sizes"] = {"1": label_sizes}
    dag: dict[str, Any] = {
        "module_kind": "link_unit",
        "trust": {"threat_model": tm_block},
        "modules": {"qcbor": {"candidate_entry_points": [key], "functions": [key], "files": ["lookup.c"]}},
        "functions": {key: {"name": "lookup", "file": "lookup.c", "is_static": False, "module": "qcbor"}},
        "global_variables": {},
    }
    model: dict[str, Any] = {
        "status": "ok",
        "trust": {"threat_model": tm_block},
        "units": {"qcbor": {"kind": "static_lib", "test": False, "files": ["lookup.c"], "links": []}},
        "functions": {key: rec},
        "global_variables": {},
    }
    layouts: dict[str, dict[str, Any]] = {
        "struct ctx": {
            "what": "struct",
            "size": 8,
            "align": 4,
            "pointers": False,
            "fields": [
                {"name": "pos", "kind": "int", "off": 0, "size": 4, "pointers": False, "ctype": "int"},
                {"name": "len", "kind": "int", "off": 4, "size": 4, "pointers": False, "ctype": "int"},
            ],
        }
    }
    return dag, model, layouts


def _lookup_cases(planned: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    return [
        (stmt, lay)
        for stmt, lay in zip(planned["cases"], planned["layouts"], strict=True)
        if lay["calls"] == ["lookup"]
    ]


def test_trusted_cstring_param_is_bound_to_a_literal_not_exempted(monkeypatch: pytest.MonkeyPatch):
    """
    QCBOR run-1 (2026-11-22): 27 `--api` entry points such as `QCBORDecode_SeekToLabelSZ(pCtx,
    const char *szLabel)` landed in `api_auto_exempt` as `trusted parameter szLabel has no instance`,
    so the text-label map search was never driven. A trusted `const char *` is bound to a fixed
    NUL-terminated literal, a value the application could pass, never to fuzz bytes.
    """
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _cstring_fixture()

    planned = ah.plan(dag, model, "qcbor", "qcbor", 256, struct_layouts=layouts)

    assert "lookup.c#lookup" not in planned["auto_exempt"], planned["auto_exempt"]
    assert "lookup.c#lookup" not in planned["skipped"], planned["skipped"]
    cases = _lookup_cases(planned)
    assert len(cases) == 1
    stmt, lay = cases[0]
    literal = '"' + ah.TRUSTED_STRING_DEFAULT + '"'
    assert f"(char const *){literal}" in stmt
    assert "lookup(" in stmt
    # The label is never read from the input: no slot and no rest for argument 1.
    assert all(s.get("param") != 1 for s in lay["slots"])
    assert lay["rest"] is None or lay["rest"].get("param") != 1
    assert any("argument 1: trusted string parameter" in n and literal in n for n in lay.get("notes") or [])


def test_trusted_cstring_param_prefers_the_literal_the_tests_pass(monkeypatch: pytest.MonkeyPatch):
    """The recorded seed traces give the label the target's own tests pass (most frequent wins)."""
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _cstring_fixture()
    traces = [
        [
            {"fn": "lookup", "args": {"1": [["s", 0, b"first integer".hex()]]}},
            {"fn": "lookup", "args": {"1": [["s", 0, b"map in a map".hex()]]}},
            {"fn": "lookup", "args": {"1": [["s", 0, b"map in a map".hex()]]}},
            # Not printable, or too long: never a literal.
            {"fn": "lookup", "args": {"1": [["s", 0, "0a00ff"]]}},
            {"fn": "lookup", "args": {"1": [["s", 0, ("41" * (ah.TRUSTED_STRING_MAX_BYTES + 1))]]}},
            {"fn": "lookup", "args": {"1": [["s", 0, "0a00ff"]]}},
            {"fn": "lookup", "args": {"1": [["s", 0, "0a00ff"]]}},
        ]
    ]

    planned = ah.plan(dag, model, "qcbor", "qcbor", 256, traces=traces, struct_layouts=layouts)

    (stmt, lay), *_ = _lookup_cases(planned)
    assert '(char const *)"map in a map"' in stmt
    assert any("recorded" in n and '"map in a map"' in n for n in lay.get("notes") or [])


def test_trusted_cstring_recorded_literal_is_escaped(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _cstring_fixture()
    text = b'say "hi"? \\'
    traces = [[{"fn": "lookup", "args": {"1": [["s", 0, text.hex()]]}}, {"fn": "other", "args": {}}]]

    planned = ah.plan(dag, model, "qcbor", "qcbor", 256, traces=traces, struct_layouts=layouts)

    (stmt, _lay), *_ = _lookup_cases(planned)
    assert f"(char const *){ah.c_string_literal(text)}" in stmt


def test_attacker_cstring_param_is_still_fuzzed(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _cstring_fixture(attacker=("c", "szLabel", "out"))

    planned = ah.plan(dag, model, "qcbor", "qcbor", 256, struct_layouts=layouts)

    (stmt, lay), *_ = _lookup_cases(planned)
    assert lay["rest"] == {"call": 0, "param": 1, "kind": "string"}
    assert f'"{ah.TRUSTED_STRING_DEFAULT}"' not in stmt
    assert not any("trusted string parameter" in n for n in lay.get("notes") or [])


@pytest.mark.parametrize(
    "variant",
    [
        # A byte buffer, not a string: a literal could be shorter than what the callee reads.
        {"label_type": "void const *"},
        {"label_type": "unsigned char const *"},
        # The callers pass a fixed-size object: its size, not a string's NUL, bounds the read.
        {"label_sizes": {"min": 16, "max": 16, "n": 2}},
        # Not positively read-only per the model: the callee may write through it.
        {"label_kind": "pointer"},
    ],
)
def test_trusted_non_string_pointer_stays_exempt(monkeypatch: pytest.MonkeyPatch, variant: dict[str, Any]):
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _cstring_fixture(**variant)

    planned = ah.plan(dag, model, "qcbor", "qcbor", 256, struct_layouts=layouts)

    if variant.get("label_kind") == "pointer":
        # A writable `char *` the threat model does not list is an output buffer: never a literal.
        for stmt, _lay in _lookup_cases(planned):
            assert f'"{ah.TRUSTED_STRING_DEFAULT}"' not in stmt
        return
    assert planned["auto_exempt"]["lookup.c#lookup"] == "trusted parameter szLabel has no instance"
    assert _lookup_cases(planned) == []


@pytest.mark.parametrize(
    "after_label",
    [("unsigned int", "uConvertTypes"), ("unsigned char", "uTagRequirement"), ("unsigned long", "uOptions")],
)
def test_trusted_cstring_beside_a_trusted_scalar_gets_the_literal(
    monkeypatch: pytest.MonkeyPatch, after_label: tuple[str, str]
):
    """
    QCBOR's `QCBORDecode_GetInt64ConvertAllInMapSZ(pCtx, szLabel, uint32_t uConvertTypes, pnValue)`:
    the unsigned scalar after the label looks like a length, but the threat model leaves it trusted,
    so it is zeroed and the label still gets its literal.
    """
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _cstring_fixture(after_label=after_label)

    planned = ah.plan(dag, model, "qcbor", "qcbor", 256, struct_layouts=layouts)

    assert "lookup.c#lookup" not in planned["auto_exempt"], planned["auto_exempt"]
    (stmt, lay), *_ = _lookup_cases(planned)
    assert f'(char const *)"{ah.TRUSTED_STRING_DEFAULT}", c0a2,' in stmt
    assert f"{after_label[0]} c0a2; memset(&c0a2, 0, sizeof(c0a2));" in stmt
    assert all(s.get("param") not in (1, 2) for s in lay["slots"])


def test_trusted_cstring_beside_an_attacker_length_stays_exempt(monkeypatch: pytest.MonkeyPatch):
    """A length the attacker controls beside a literal would read past it: no case, as before."""
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _cstring_fixture(after_label=("unsigned long", "uLen"), attacker=("c", "uLen", "out"))

    planned = ah.plan(dag, model, "qcbor", "qcbor", 256, struct_layouts=layouts)

    assert planned["auto_exempt"]["lookup.c#lookup"] == "trusted parameter szLabel has no instance"


def test_trusted_cstring_flag_off_is_unchanged(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "off")
    dag, model, layouts = _cstring_fixture()

    planned = ah.plan(dag, model, "qcbor", "qcbor", 256, struct_layouts=layouts)

    assert planned["auto_exempt"] == {}
    (stmt, lay), *_ = _lookup_cases(planned)
    assert f'"{ah.TRUSTED_STRING_DEFAULT}"' not in stmt
    assert lay["rest"] == {"call": 0, "param": 1, "kind": "string"}


def test_trusted_cstring_generate_sidecar_valid_and_both_copies_bind_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _cstring_fixture()
    reports = tmp_path / "workspace" / "reports"
    harnesses = tmp_path / "workspace" / "harnesses"
    reports.mkdir(parents=True)
    harnesses.mkdir(parents=True)
    dag_path = reports / "callgraph_dag.json"
    model_path = reports / "phase0_model.json"
    dag_path.write_text(json.dumps(dag), encoding="utf-8")
    model_path.write_text(json.dumps(model), encoding="utf-8")

    res = ah.generate(
        module="qcbor",
        header="none",
        max_input_size=256,
        cppflags="",
        out_dir=harnesses,
        unit="qcbor",
        auto_prelude=False,
        probe=False,
        dag_path=dag_path,
        model_path=model_path,
        struct_layouts=layouts,
        variadic={},
    )
    sidecar = json.loads(Path(res["harness_meta"]).read_text(encoding="utf-8"))
    harness_c = Path(res["harness_file"]).read_text(encoding="utf-8")

    assert not validate_sidecar(sidecar, module="qcbor")
    assert "lookup.c#lookup" not in (sidecar.get("api_auto_exempt") or {})
    case = next(c for c in sidecar["api_cases"] if c["calls"] == ["lookup"])
    assert any("trusted string parameter" in n for n in case.get("notes") or [])
    # The Eva entry and the LibFuzzer entry dispatch the same case body, literal included.
    call = f'(char const *)"{ah.TRUSTED_STRING_DEFAULT}"'
    eva_part, fuzz_part = harness_c.split("LLVMFuzzerTestOneInput", 1)
    assert "int eva_main(void)" in eva_part
    assert eva_part.count(call) == 1
    assert fuzz_part.count(call) == 1


# ---------------------------------------------------------------------------
# Stateful entry points (QCBOR run-1: closers and in-map accessors called on a fresh context)
# ---------------------------------------------------------------------------


def _int_field(name: str, off: int) -> dict[str, Any]:
    return {"name": name, "kind": "int", "off": off, "size": 4, "pointers": False, "ctype": "int"}


def _stateful_fixture() -> tuple[dict[str, Any], dict[str, Any], dict[str, dict[str, Any]]]:
    """
    A QCBOR-shaped encoder and decoder, each on a caller-allocated context its initializer sets up.

    Encoder: `enc_init(e, cap)` reads no data (only the storage size), `enc_open_map(e)`,
    `enc_add_int(e, v)`, `enc_close_and_sort_map(e)` (an error when no map is open) and
    `enc_finish(e, struct bufc *out)`; `buf_from_sz(s)` builds a `struct bufc` by value.
    Decoder: `dec_init(d, buf, len)` takes the document (an entry point, as `QCBORDecode_Init`; the
    encoder's initializer is not one, as `QCBOREncode_Init`), `dec_enter_map(d, uType)` whose type the
    application chooses, the in-map accessors `dec_get_int_in_map_sz(d, szLabel, out)` and
    `dec_get_bool_in_map_n(d, nLabel, out)` (both through `dec_map_search`, which fails unless a map
    is entered), `dec_seek_to_label_n(d, nLabel)` (the same search, no scope word in its name),
    `dec_exit_map(d)` and `dec_get_next(d, out)`, which works on a fresh context.
    """
    fns: dict[str, tuple[str, list[tuple[str, str]], list[str], tuple[str, ...] | None]] = {
        # name: (signature, formals, callees, attacker params; None: not an entry point)
        "enc_init": ("void(struct enc *,unsigned long)", [("e", "pointer"), ("cap", "value")], [], None),
        "enc_open_map": ("void(struct enc *)", [("e", "pointer")], ["enc_open_nesting"], ("e",)),
        "enc_add_int": ("void(struct enc *,long)", [("e", "pointer"), ("v", "value")], [], ("e", "v")),
        "enc_close_and_sort_map": ("int(struct enc *)", [("e", "pointer")], ["enc_close_nesting"], ("e",)),
        "enc_finish": ("int(struct enc *,struct bufc *)", [("e", "pointer"), ("out", "pointer")], [], ("e", "out")),
        "enc_open_nesting": ("void(struct enc *)", [("e", "pointer")], [], None),
        "enc_close_nesting": ("int(struct enc *)", [("e", "pointer")], [], None),
        "buf_from_sz": ("struct bufc(char const *)", [("s", "const_pointer")], [], None),
        "dec_init": (
            "void(struct dec *,unsigned char const *,unsigned long)",
            [("d", "pointer"), ("buf", "const_pointer"), ("len", "value")],
            [],
            ("d", "buf", "len"),
        ),
        "dec_enter_map": ("void(struct dec *,unsigned char)", [("d", "pointer"), ("uType", "value")], [], ("d",)),
        "dec_exit_map": ("void(struct dec *)", [("d", "pointer")], [], ("d",)),
        "dec_get_next": ("int(struct dec *,long *)", [("d", "pointer"), ("out", "pointer")], [], ("d", "out")),
        "dec_get_int_in_map_sz": (
            "void(struct dec *,char const *,long *)",
            [("d", "pointer"), ("szLabel", "const_pointer"), ("out", "pointer")],
            ["dec_map_search"],
            ("d", "out"),
        ),
        "dec_get_bool_in_map_n": (
            "void(struct dec *,long,_Bool *)",
            [("d", "pointer"), ("nLabel", "value"), ("out", "pointer")],
            ["dec_map_search"],
            ("d", "out"),
        ),
        "dec_seek_to_label_n": (
            "void(struct dec *,long)",
            [("d", "pointer"), ("nLabel", "value")],
            ["dec_map_search"],
            ("d",),
        ),
        "dec_map_search": ("int(struct dec *,long)", [("d", "pointer"), ("n", "value")], ["dec_match_label"], None),
        "dec_match_label": ("int(long)", [("n", "value")], [], None),
    }
    tm_block: dict[str, Any] = {
        "status": "ok",
        "input_sources": [
            {"function": n, "role": "entry", "params": list(att), "description": n}
            for n, (_s, _f, _c, att) in fns.items()
            if att is not None
        ],
    }
    keys = {n: f"{n.split('_', 1)[0]}.c#{n}" for n in fns}
    model_fns: dict[str, Any] = {}
    dag_fns: dict[str, Any] = {}
    for n, (sig, formals, callees, _att) in fns.items():
        f = keys[n].split("#", 1)[0]
        model_fns[keys[n]] = {
            "name": n,
            "file": f,
            "signature": sig,
            "formals": [{"name": a, "kind": k} for a, k in formals],
            "call_sites": [{"callee": c, "line": 1, "literals": {}, "initializer": False} for c in callees],
        }
        dag_fns[keys[n]] = {"name": n, "file": f, "is_static": False, "module": "lib"}
    entries = [keys[n] for n, (_s, _f, _c, att) in fns.items() if att is not None]
    files = sorted({k.split("#", 1)[0] for k in keys.values()})
    dag: dict[str, Any] = {
        "module_kind": "link_unit",
        "trust": {"threat_model": tm_block},
        "modules": {"lib": {"candidate_entry_points": entries, "functions": list(keys.values()), "files": files}},
        "functions": dag_fns,
        "global_variables": {},
    }
    model: dict[str, Any] = {
        "status": "ok",
        "trust": {"threat_model": tm_block},
        "units": {"lib": {"kind": "static_lib", "test": False, "files": files, "links": []}},
        "functions": model_fns,
        "global_variables": {},
    }

    def _struct(*names: str) -> dict[str, Any]:
        fields = [_int_field(name, 4 * k) for k, name in enumerate(names)]
        return {"what": "struct", "size": 4 * len(names), "align": 4, "pointers": False, "fields": fields}

    layouts = {
        "struct enc": _struct("depth", "count", "used"),
        "struct dec": _struct("depth", "pos", "len"),
        "struct bufc": _struct("off", "len"),
    }
    return dag, model, layouts


def _stateful(planned: dict[str, Any], entry: str) -> list[tuple[str, dict[str, Any]]]:
    """The stateful cases (`sequence` cases led up to `entry`) of a plan."""
    return [
        (stmt, lay)
        for stmt, lay in zip(planned["cases"], planned["layouts"], strict=True)
        if lay["kind"] == "sequence" and lay.get("entry") == entry
    ]


def test_a_closer_on_a_fresh_context_gets_its_opener_and_data_first(monkeypatch: pytest.MonkeyPatch):
    """
    QCBOR run-1 (2026-11-22): case 35 was `QCBOREncode_Init(&c0a0, c1a1); QCBOREncode_CloseAndSortMap(&c0a0);`,
    whose only input is the storage size: closing a map nobody opened returns an error, so the map sort
    never ran. A closer gets a case that opens first (its paired opener) and adds data from the input,
    since the encoder's initializer reads none.
    """
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _stateful_fixture()

    planned = ah.plan(dag, model, "lib", "lib", 256, struct_layouts=layouts)

    # The single case stays.
    assert any(lay["calls"] == ["enc_close_and_sort_map"] and lay["kind"] == "single" for lay in planned["layouts"])
    cases = _stateful(planned, "enc.c#enc_close_and_sort_map")
    assert len(cases) == 1, [lay["calls"] for lay in planned["layouts"]]
    stmt, lay = cases[0]
    assert lay["calls"] == ["enc_open_map", *["enc_add_int"] * ah.STATE_FEED_CALLS, "enc_close_and_sort_map"]
    assert lay["state"] == "model"
    assert [i["fn"] for i in lay.get("inits") or []] == ["enc_init"]
    # One context through every call, set up once, in that order.
    assert stmt.index("enc_init(") < stmt.index("enc_open_map(") < stmt.index("enc_add_int(")
    assert stmt.index("enc_add_int(") < stmt.index("enc_close_and_sort_map(")
    assert stmt.count("enc_init(") == 1
    # The data of each add comes from the input.
    adds = [k + 1 for k in range(ah.STATE_FEED_CALLS)]
    assert sorted({s["call"] for s in lay["slots"] if s["param"] == 1 and s["call"] in adds}) == adds
    assert any("stateful case" in n for n in lay.get("notes") or [])


def test_an_in_map_accessor_gets_the_enter_call_first_and_keeps_its_trusted_label(monkeypatch: pytest.MonkeyPatch):
    """
    QCBOR run-1: the `*InMapSZ` accessors ran right after `QCBORDecode_Init`, so the map search returned
    `QCBOR_ERR_MAP_NOT_ENTERED` before any label match. The accessor gets a case that enters a map first;
    the decoder's initializer reads the document, so no data call is added, and the trusted label stays
    a literal, as in the single case.
    """
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _stateful_fixture()

    planned = ah.plan(dag, model, "lib", "lib", 256, struct_layouts=layouts)

    (stmt, lay), *more = _stateful(planned, "dec.c#dec_get_int_in_map_sz")
    assert not more
    assert lay["calls"] == ["dec_enter_map", "dec_get_int_in_map_sz"]
    assert [i["fn"] for i in lay.get("inits") or []] == ["dec_init"]
    assert stmt.index("dec_init(") < stmt.index("dec_enter_map(") < stmt.index("dec_get_int_in_map_sz(")
    assert f'(char const *)"{ah.TRUSTED_STRING_DEFAULT}"' in stmt
    assert all(not (s["call"] == 1 and s["param"] == 1) for s in lay["slots"])
    assert lay["rest"] is None or (lay["rest"]["call"], lay["rest"]["param"]) != (1, 1)
    # The closer of the decoder gets its opener too; an accessor without the scope word reaches the same
    # guarded search as the in-map accessors; a function that works on a fresh context gets nothing.
    assert [lay["calls"] for _s, lay in _stateful(planned, "dec.c#dec_exit_map")] == [["dec_enter_map", "dec_exit_map"]]
    seek = _stateful(planned, "dec.c#dec_seek_to_label_n")
    assert [lay["calls"] for _s, lay in seek] == [["dec_enter_map", "dec_seek_to_label_n"]]
    assert _stateful(planned, "dec.c#dec_get_next") == []
    assert _stateful(planned, "enc.c#enc_add_int") == []
    # Bounded: no stateful case is longer than the cap.
    for lay in planned["layouts"]:
        if lay.get("state"):
            assert len(lay["calls"]) <= ah.STATE_MAX_PREFIX + 1


def test_a_recorded_chain_binds_trusted_parameters_as_the_single_cases_do(monkeypatch: pytest.MonkeyPatch):
    """
    QCBOR run-1 (F1 note): `sequence_case` called `_bind_call` without the threat model's roles, so the
    recorded `Init -> EnterBoundedMapOrArray -> GetItemInMapSZ` chain fuzzed the trusted label. The chain
    now binds it as the single case does (the recorded literal), and a trusted scalar the application
    chose (the type of map to enter) takes one of the values the target's tests passed, not zero.
    """
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _stateful_fixture()
    trace = [
        {"fn": "dec_init", "args": {"2": [["i", 0, "0400000000000000"]]}, "addrs": {"0": "d0"}},
        {"fn": "dec_enter_map", "args": {"1": [["i", 0, "05"]]}, "addrs": {"0": "d0"}},
        {"fn": "dec_get_int_in_map_sz", "args": {"1": [["s", 0, b"lbl".hex()]]}, "addrs": {"0": "d0", "2": "o1"}},
    ]

    planned = ah.plan(dag, model, "lib", "lib", 256, traces=[trace], struct_layouts=layouts)

    chain = [
        (stmt, lay)
        for stmt, lay in zip(planned["cases"], planned["layouts"], strict=True)
        if lay["kind"] == "sequence" and not lay.get("entry")
    ]
    assert [lay["calls"] for _s, lay in chain] == [["dec_init", "dec_enter_map", "dec_get_int_in_map_sz"]]
    stmt, lay = chain[0]
    assert '(char const *)"lbl"' in stmt
    assert all(not (s["call"] == 2 and s["param"] == 1) for s in lay["slots"])
    assert lay["rest"] is None or (lay["rest"]["call"], lay["rest"]["param"]) != (2, 1)
    # The map type: read from the input, kept to what the tests passed.
    assert any(s["call"] == 1 and s["param"] == 1 for s in lay["slots"])
    assert "5ULL" in stmt
    assert any("argument 1: trusted scalar" in n and "recorded" in n for n in lay.get("notes") or [])
    # The stateful case of the accessor replays the recorded prefix, with the same bindings.
    (st_stmt, st_lay), *_ = _stateful(planned, "dec.c#dec_get_int_in_map_sz")
    assert st_lay["state"] == "recorded"
    assert st_lay["calls"] == ["dec_enter_map", "dec_get_int_in_map_sz"]
    assert '(char const *)"lbl"' in st_stmt and "5ULL" in st_stmt


def test_a_by_value_builder_of_a_shared_buffer_assigns_through_its_type(monkeypatch: pytest.MonkeyPatch):
    """
    QCBOR run-1: the recorded encoder chain (48 calls) was built, then the compile probe dropped it on
    `s1 = UsefulBuf_FromSZ(...)`: the shared `UsefulBufC *` of two `QCBOREncode_Finish` calls is a byte
    array, and the by-value builder of its struct was assigned to the array. The drop was silent: a
    sequence case names no entry point, so nothing went to `api_skipped`.
    """
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _stateful_fixture()
    trace = [
        {"fn": "enc_init", "args": {}, "addrs": {"0": "e0"}},
        {"fn": "enc_open_map", "args": {}, "addrs": {"0": "e0"}},
        {"fn": "enc_finish", "args": {}, "addrs": {"0": "e0", "1": "b0"}},
        {"fn": "enc_init", "args": {}, "addrs": {"0": "e0"}},
        {"fn": "enc_finish", "args": {}, "addrs": {"0": "e0", "1": "b0"}},
    ]

    planned = ah.plan(dag, model, "lib", "lib", 256, traces=[trace], struct_layouts=layouts)

    chain = [
        stmt
        for stmt, lay in zip(planned["cases"], planned["layouts"], strict=True)
        if lay["kind"] == "sequence" and "enc_finish" in lay["calls"] and not lay.get("entry")
    ]
    assert chain, [lay["calls"] for lay in planned["layouts"]]
    stmt = chain[0]
    assert " s1 = buf_from_sz(" not in stmt
    assert "*(struct bufc *)s1 = buf_from_sz(" in stmt


def test_stateful_cases_go_first_over_the_case_limit(monkeypatch: pytest.MonkeyPatch):
    """
    The stateful cases come after every single case, a public header function's included: over the
    case limit they are cut first, so no entry point loses its only case to an extra stateful one.
    """
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _stateful_fixture()
    hdr = "inc/lib.h#h_peek"
    dag["functions"][hdr] = {"name": "h_peek", "file": "inc/lib.h", "is_static": True, "header": True, "module": "lib"}
    dag["modules"]["lib"]["candidate_entry_points"].append(hdr)
    dag["modules"]["lib"]["functions"].append(hdr)
    model["functions"][hdr] = {
        "name": "h_peek",
        "file": "inc/lib.h",
        "static": True,
        "header": True,
        "signature": "int(int)",
        "formals": [{"name": "p0", "kind": "value"}],
    }
    entry = {"function": "h_peek", "role": "entry", "params": ["p0"], "description": "h_peek"}
    dag["trust"]["threat_model"]["input_sources"].append(entry)
    visible = ah.Declared({str(rec["name"]) for rec in dag["functions"].values()})

    full = ah.plan(dag, model, "lib", "lib", 256, struct_layouts=layouts, visible=visible)
    kinds = [bool(lay.get("state")) for lay in full["layouts"]]
    assert any(kinds), "the fixture has stateful cases"
    # Every stateful case is after every other case, the header function's single case included.
    assert kinds == sorted(kinds)
    assert any(lay.get("entry") == hdr for lay in full["layouts"])
    n_other = kinds.count(False)

    monkeypatch.setattr(ah, "MAX_CASES", n_other + 1)
    capped = ah.plan(dag, model, "lib", "lib", 256, struct_layouts=layouts, visible=visible)
    assert [lay for lay in capped["layouts"] if not lay.get("state")] == [
        lay for lay in full["layouts"] if not lay.get("state")
    ]
    assert sum(1 for lay in capped["layouts"] if lay.get("state")) == 1
    assert not any("more than" in why for why in capped["skipped"].values()), capped["skipped"]


def test_generate_reports_a_dropped_sequence_case_and_keeps_both_copies_equal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """
    The stateful cases are `sequence` cases with an `entry` and a `state`: the sidecar stays valid and
    the Eva and LibFuzzer copies dispatch the same bodies. A case the compile probe refuses that names
    no entry point is reported instead of vanishing.
    """
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(ah.API_TRUST_SCHEMA_ENV, "on")
    dag, model, layouts = _stateful_fixture()
    reports = tmp_path / "workspace" / "reports"
    harnesses = tmp_path / "workspace" / "harnesses"
    reports.mkdir(parents=True)
    harnesses.mkdir(parents=True)
    dag_path = reports / "callgraph_dag.json"
    model_path = reports / "phase0_model.json"
    dag_path.write_text(json.dumps(dag), encoding="utf-8")
    model_path.write_text(json.dumps(model), encoding="utf-8")
    traces_path = tmp_path / "traces.jsonl"
    trace = [
        {"fn": "dec_init", "args": {}, "addrs": {"0": "d0"}},
        {"fn": "dec_enter_map", "args": {"1": [["i", 0, "05"]]}, "addrs": {"0": "d0"}},
        {"fn": "dec_get_next", "args": {}, "addrs": {"0": "d0"}},
    ]
    traces_path.write_text(json.dumps({"pid": "1", "calls": trace}) + "\n", encoding="utf-8")
    refused: list[int] = []

    def fake_probe(harness_c: Path, cppflags: str, clang: str | None = None):
        text = harness_c.read_text(encoding="utf-8")
        bad = {}
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("case ") and "dec_get_next(" in stripped and "dec_enter_map(" in stripped:
                sel = int(stripped.split()[1].rstrip("U:"))
                if "dec_init(" in stripped and "dec_exit_map(" not in stripped:
                    bad[sel] = "harness_lib.c:1: error: refused for the test"
        refused.extend(sorted(bad))
        return bad, []

    monkeypatch.setattr(ah, "probe_cases", fake_probe)
    res = ah.generate(
        module="lib",
        header="none",
        max_input_size=256,
        cppflags="",
        out_dir=harnesses,
        unit="lib",
        auto_prelude=False,
        probe=True,
        dag_path=dag_path,
        model_path=model_path,
        traces_path=traces_path,
        struct_layouts=layouts,
        visible=ah.Declared({f["name"] for f in model["functions"].values()}),
        variadic={},
    )
    sidecar = json.loads(Path(res["harness_meta"]).read_text(encoding="utf-8"))
    harness_c = Path(res["harness_file"]).read_text(encoding="utf-8")

    assert not validate_sidecar(sidecar, module="lib")
    stateful = [c for c in sidecar["api_cases"] if c.get("state")]
    assert {c["entry"] for c in stateful} >= {"enc.c#enc_close_and_sort_map", "dec.c#dec_get_int_in_map_sz"}
    assert all(c["kind"] == "sequence" for c in stateful)
    # The recorded chain (no entry) was refused: reported with the probe's message.
    assert refused
    dropped = res["api_dropped_cases"]
    assert [d["calls"] for d in dropped] == [["dec_init", "dec_enter_map", "dec_get_next"]]
    assert "refused for the test" in dropped[0]["why"]
    eva_part, fuzz_part = harness_c.split("LLVMFuzzerTestOneInput", 1)
    for case in stateful:
        body = sidecar["dispatch_cases"][case["selector"]]
        assert eva_part.count(body) == 1 and fuzz_part.count(body) == 1
