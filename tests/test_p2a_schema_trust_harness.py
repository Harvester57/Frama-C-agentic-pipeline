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
    assert ah.api_trust_schema_enabled({}) is False
    assert ah.api_trust_schema_enabled({ah.API_TRUST_SCHEMA_ENV: ""}) is False
    assert ah.api_trust_schema_enabled({ah.API_TRUST_SCHEMA_ENV: "off"}) is False
    assert ah.api_trust_schema_enabled({ah.API_TRUST_SCHEMA_ENV: "0"}) is False
    assert ah.api_trust_schema_enabled({ah.API_TRUST_SCHEMA_ENV: "false"}) is False
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
        # S2 by-value builder builds the stream directly from fuzz bytes.
        assert lay["builder"] == "pb_istream_from_buffer"
        assert (
            "c0a0 = pb_istream_from_buffer((unsigned char *)(fuzz_buf + fuzz_off), (unsigned long)(fuzz_len - fuzz_off));"
            in stmt
        )
        # Trusted descriptor is bound to the real const schema instance, NEVER fuzzed!
        assert f"pb_decode(&c0a0, &{inst}, (void *)c0a2);" in stmt
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
    assert (
        "c0a0 = pb_istream_from_buffer((unsigned char *)(fuzz_buf + fuzz_off), (unsigned long)(fuzz_len - fuzz_off));"
        in r_stmt
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
        assert "(void)pb_field_iter_find(&c0a0, c0a1);" in stmt

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
