"""
The `--api` harness respects the API's contract (docs/bugs/2026-11-09-qcbor-run4-fuzz-campaign-and-api-harness.md,
items A1-A5 and D1): no input byte in a pointer, contexts initialized first, no C string paired with an
enum, seeds that never carry a recorded pointer, and the compiler's reason for each dropped case.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

import api_harness as ah
import seed_harvest as sh
import validate_artifacts as va

pytestmark = pytest.mark.unit

SPARE = ah.spare_bytes(64)

# QCBOR's slices: struct q_useful_buf_c { const void *ptr; size_t len; } and its writable twin.
UBC: dict[str, Any] = {
    "what": "struct",
    "size": 16,
    "align": 8,
    "pointers": True,
    "fields": [
        {"name": "ptr", "kind": "ptr", "off": 0, "size": 8, "pointers": True, "const": True},
        {"name": "len", "kind": "int", "off": 8, "size": 8, "pointers": False, "ctype": "unsigned long"},
    ],
}
UB = {
    **UBC,
    "fields": [{**UBC["fields"][0], "const": False}, UBC["fields"][1]],
}
LAYOUTS = {"struct q_useful_buf_c": UBC, "struct q_useful_buf": UB}


def _formals(*kinds: str, names: tuple[str, ...] = ()) -> list[dict]:
    return [{"name": names[i] if i < len(names) else f"p{i}", "kind": k} for i, k in enumerate(kinds)]


def _api(**kw: Any) -> ah.ApiInfo:
    return ah.ApiInfo(structs=dict(LAYOUTS), probed=True, **kw)


# --- A1: structs by value with pointers ------------------------------------------------------------


def test_input_slice_by_value_points_at_the_input_never_takes_input_bytes_as_a_pointer():
    rec = {"signature": "int(struct q_useful_buf_c,struct q_useful_buf_c)", "formals": _formals("value", "value")}
    stmt, layout, _ = ah.single_case("UsefulBuf_Compare", rec, SPARE, _api())
    assert stmt is not None and layout is not None
    # Never the whole struct from the input.
    assert "memcpy(&c0a0, fuzz_buf" not in stmt and "memcpy(&c0a1, fuzz_buf" not in stmt
    # The first slice takes the rest of the input; the second a generator buffer read from the input.
    assert "c0a0.ptr = (void *)(fuzz_buf + fuzz_off); c0a0.len = (unsigned long)(fuzz_len - fuzz_off);" in stmt
    assert layout["rest"] == {"call": 0, "param": 0, "kind": "bytes", "off": 0}
    assert f"static unsigned char c0a1f0[{ah.PAIR_BYTES}]" in stmt and "c0a1.ptr = (void *)c0a1f0;" in stmt
    assert f"if ((unsigned long long)c0a1.len > {ah.PAIR_BYTES}ULL)" in stmt
    assert [(s["param"], s["kind"], s["size"], s.get("off")) for s in layout["slots"]] == [
        (1, "field_bytes", ah.PAIR_BYTES, 0),
        (1, "field_len", 8, 0),
    ]


def test_output_slice_by_value_gets_spare_storage_and_a_clamped_length():
    rec = {
        "signature": "void(struct useful_out_buf *,struct q_useful_buf)",
        "formals": _formals("pointer", "value"),
    }
    stmt, layout, _ = ah.single_case("UsefulOutBuf_Init", rec, SPARE, _api())
    assert stmt is not None and layout is not None
    assert f"static unsigned char c0a1f0[{SPARE}]" in stmt and "c0a1.ptr = (void *)c0a1f0;" in stmt
    assert f"if ((unsigned long long)c0a1.len > {SPARE}ULL)" in stmt
    assert layout["slots"] == [{"call": 0, "param": 1, "size": 8, "kind": "field_len", "off": 0, "max": SPARE}]
    assert layout["rest"] is None


def test_struct_with_pointers_and_no_layout_is_zeroed_with_a_reason():
    rec = {"signature": "int(struct q_useful_buf_c)", "formals": _formals("value")}
    stmt, layout, _ = ah.single_case("f", rec, SPARE, ah.ApiInfo(probed=True))
    assert stmt is not None and layout is not None
    assert "struct q_useful_buf_c c0a0; memset(&c0a0, 0, sizeof(c0a0));" in stmt and "memcpy(&c0a0" not in stmt
    assert layout["slots"] == [] and "layout not known" in layout["notes"][0]


def test_nested_fields_scalars_and_lone_pointers():
    outer = {
        "what": "struct",
        "size": 40,
        "align": 8,
        "pointers": True,
        "fields": [
            {"name": "flags", "kind": "int", "off": 0, "size": 4, "pointers": False, "ctype": "int"},
            {"name": "name", "kind": "ptr", "off": 8, "size": 8, "pointers": True, "const": True},
            {"name": "cb", "kind": "fnptr", "off": 16, "size": 8, "pointers": True},
            {
                "name": "data",
                "kind": "record",
                "off": 24,
                "size": 16,
                "pointers": True,
                "what": "struct",
                "ctype": "struct q_useful_buf_c",
            },
        ],
    }
    api = _api()
    api.structs["struct opts"] = outer
    stmt, layout, _ = ah.single_case("g", {"signature": "int(struct opts)", "formals": _formals("value")}, SPARE, api)
    assert stmt is not None and layout is not None
    assert "c0a0.name = (void *)c0a0f1;" in stmt and "c0a0.cb" not in stmt
    assert "c0a0.data.ptr = (void *)(fuzz_buf + fuzz_off);" in stmt
    assert layout["rest"] == {"call": 0, "param": 0, "kind": "bytes", "off": 24}
    assert layout["slots"] == [{"call": 0, "param": 0, "size": 4, "kind": "field", "off": 0}]


# --- A2: contexts initialized first ------------------------------------------------------------------


DECODE_INIT: dict[str, Any] = {
    "name": "QCBORDecode_Init",
    "signature": "void(struct _QCBORDecodeContext *,struct q_useful_buf_c,enum __anonenum_QCBORDecodeMode_7)",
    "formals": _formals("pointer", "value", "value"),
}
GET_INT: dict[str, Any] = {
    "name": "QCBORDecode_GetInt64",
    "signature": "void(struct _QCBORDecodeContext *,long *)",
    "formals": _formals("pointer", "pointer"),
    "param_sizes": {"0": {"max": 4024}},
}


def _init_api(traces: list[list[dict]] | None = None) -> ah.ApiInfo:
    other = {
        "name": "QCBORDecode_InitWithMemPool",
        "signature": "void(struct _QCBORDecodeContext *)",
        "formals": _formals("pointer"),
    }
    funcs: dict[str, dict] = {
        "a#QCBORDecode_Init": DECODE_INIT,
        "a#QCBORDecode_InitWithMemPool": other,
        "a#QCBORDecode_GetInt64": GET_INT,
    }
    inits, cands, records = ah.initializers(funcs, traces)
    return _api(inits=inits, candidates=cands, records=records)


def test_context_pointer_is_initialized_before_the_call_under_test():
    api = _init_api()
    assert api.inits == {"struct _QCBORDecodeContext": "QCBORDecode_Init"}
    stmt, layout, _ = ah.single_case("QCBORDecode_GetInt64", GET_INT, SPARE, api)
    assert stmt is not None and layout is not None
    assert "struct _QCBORDecodeContext c0a0; memset(&c0a0, 0, sizeof(c0a0));" in stmt
    assert "static unsigned char c0a0[" not in stmt
    init = "(void)QCBORDecode_Init((struct _QCBORDecodeContext *)&c0a0, c1a1, c1a2);"
    assert init in stmt and stmt.index(init) < stmt.index("(void)QCBORDecode_GetInt64(&c0a0, &c0a1);")
    # The initializer's input slice is the rest of the input (the CBOR to decode); its mode is a slot.
    assert "c1a1.ptr = (void *)(fuzz_buf + fuzz_off);" in stmt
    assert layout["rest"] == {"call": 1, "param": 1, "kind": "bytes", "off": 0}
    assert layout["inits"] == [{"fn": "QCBORDecode_Init", "call": 1, "for": {"call": 0, "param": 0}}]
    assert layout["slots"] == [{"call": 1, "param": 2, "size": 4, "kind": "int"}]


def test_the_initializers_own_case_does_not_initialize_first():
    stmt, layout, _ = ah.single_case("QCBORDecode_Init", DECODE_INIT, SPARE, _init_api())
    assert stmt is not None and layout is not None
    assert stmt.count("QCBORDecode_Init(") == 1 and "inits" not in layout


def test_traces_choose_the_initializer_and_types_without_one_stay_zeroed():
    traces = [[{"fn": "QCBORDecode_GetInt64"}, {"fn": "QCBORDecode_InitWithMemPool"}, {"fn": "QCBORDecode_Init"}]]
    assert _init_api(traces).inits == {"struct _QCBORDecodeContext": "QCBORDecode_InitWithMemPool"}
    # An output struct (QCBORItem) has no initializer: one zeroed object, no input.
    rec = {"signature": "int(struct _QCBORItem *)", "formals": _formals("pointer")}
    stmt, layout, _ = ah.single_case("next", rec, SPARE, _init_api())
    assert stmt is not None and layout is not None
    assert "struct _QCBORItem c0a0; memset(&c0a0, 0, sizeof(c0a0));" in stmt and layout["slots"] == []


def test_initializer_candidates_need_a_writable_struct_first_parameter_and_a_callable_symbol():
    funcs: dict[str, dict] = {
        "h#Foo_Init": {
            "name": "Foo_Init",
            "signature": "void(struct foo *)",
            "formals": _formals("pointer"),
            "static": True,
            "header": True,
        },
        "c#Bar_Init": {
            "name": "Bar_Init",
            "signature": "void(struct bar *)",
            "formals": _formals("pointer"),
            "static": True,
            "header": False,
        },
        "c#Baz_Init": {"name": "Baz_Init", "signature": "void(struct baz *)", "formals": _formals("const_pointer")},
        "c#Indefinite": {"name": "OpenIndefinite", "signature": "void(struct qux *)", "formals": _formals("pointer")},
    }
    assert ah.initializers(funcs)[0] == {}
    # A header function counts once the probe saw it declared in the harness.
    assert ah.initializers(funcs, visible={"Foo_Init"})[0] == {"struct foo": "Foo_Init"}


# --- A3: a C string next to an enum ------------------------------------------------------------------


def test_enum_after_a_char_pointer_is_not_a_length():
    assert sh.classify_type("enum QCBORDecodeTagReq") == {"kind": "int", "ctype": "int", "enum": True}
    assert not sh.is_length(sh.classify_type("enum QCBORDecodeTagReq"))
    assert sh.is_length(sh.classify_type("size_t")) and sh.is_length(sh.classify_type("unsigned int"), "flags")
    assert sh.is_length(sh.classify_type("int"), "nBytes") and sh.is_length(sh.classify_type("int"), None)
    assert not sh.is_length(sh.classify_type("int"), "flags")
    rec: dict[str, Any] = {
        "signature": "void(struct _QCBORDecodeContext *,char *,enum QCBORDecodeTagReq,struct q_useful_buf)",
        "formals": _formals("pointer", "const_pointer", "value", "value", names=("pMe", "szLabel", "uTagReq")),
    }
    stmt, layout, _ = ah.single_case("GetSZ", rec, SPARE, _api())
    assert stmt is not None and layout is not None
    # The label is a NUL-terminated string from the rest of the input; the enum a slot of its own.
    assert layout["rest"] == {"call": 0, "param": 1, "kind": "string"} and "c0a1[rest_n] = 0;" in stmt
    assert "(enum QCBORDecodeTagReq)(fuzz_len" not in stmt
    assert {"call": 0, "param": 2, "size": 4, "kind": "int"} in layout["slots"]
    plan = sh.plan_function("GetSZ", rec["signature"], None, ["pMe", "szLabel", "uTagReq", "Buf"])
    assert plan["params"][1]["record"] == "s"


def test_signed_length_pairs_keep_working():
    rec = {"signature": "int(char *,int)", "formals": _formals("const_pointer", "value", names=("buf", "len"))}
    stmt, layout, _ = ah.single_case("parse", rec, SPARE)
    assert stmt is not None and layout is not None
    assert layout["rest"] == {"call": 0, "param": 0, "kind": "bytes"}
    rec["formals"] = _formals("const_pointer", "value", names=("s", "flags"))
    _, layout, _ = ah.single_case("parse", rec, SPARE)
    assert layout is not None and layout["rest"] == {"call": 0, "param": 0, "kind": "string"}


# --- _Bool: only 0 and 1 are values (UBSan reports any other byte in the harness itself) -----------------


def test_bools_from_the_input_take_the_low_bit():
    fix = "{ unsigned char fc_b; memcpy(&fc_b, &c0a0, 1); c0a0 = (fc_b & 1U) != 0; }"
    stmt, layout, _ = ah.single_case("f", {"signature": "int(_Bool)", "formals": _formals("value")}, SPARE)
    assert stmt is not None and layout is not None and fix in stmt
    assert layout["slots"] == [{"call": 0, "param": 0, "size": 1, "kind": "int"}]
    stmt, _, _ = ah.single_case("g", {"signature": "int(_Bool *)", "formals": _formals("const_pointer")}, SPARE)
    assert stmt is not None and fix in stmt
    # A pointer-free struct holding a _Bool is filled field by field, never copied whole.
    tree = {
        "kind": "TranslationUnitDecl",
        "inner": [_record("opts", _field("on", "_Bool"), _field("n", "int"))],
    }
    layouts, _ = ah.record_layouts(tree)
    assert layouts["struct opts"]["bools"] and not layouts["struct opts"]["pointers"]
    api = ah.ApiInfo(structs=layouts, probed=True)
    stmt, layout, _ = ah.single_case("h", {"signature": "int(struct opts)", "formals": _formals("value")}, SPARE, api)
    assert stmt is not None and layout is not None
    assert "c0a0.on = (fc_b & 1U) != 0;" in stmt and "memcpy(&c0a0, fuzz_buf" not in stmt
    assert [(s["kind"], s["off"], s["size"]) for s in layout["slots"]] == [("field", 0, 1), ("field", 4, 4)]


# --- A4: seeds never carry a recorded pointer --------------------------------------------------------


def test_struct_slot_seeds_come_from_the_recorded_pair_data():
    rec = {"signature": "int(struct q_useful_buf_c,struct q_useful_buf_c)", "formals": _formals("value", "value")}
    _, layout, _ = ah.single_case("UsefulBuf_Compare", rec, SPARE, _api())
    assert layout is not None
    layout["selector"] = 7
    ptr = "efbeadde00000000"  # the test process's pointer, in the raw bytes
    args = {
        "0": [["t", 0, ptr + "0300000000000000"], ["n", 0, "616263"]],
        "1": [["t", 0, ptr + "0200000000000000"], ["n", 0, "7879"]],
    }
    seed = sh.layout_seed(layout, [args])
    assert seed is not None and bytes.fromhex(ptr) not in seed
    expected = bytes([7]) + b"xy".ljust(ah.PAIR_BYTES, b"\0") + (2).to_bytes(8, "little") + b"abc"
    assert seed == expected


def test_seeds_take_the_initializers_arguments_from_the_trace():
    _, layout, _ = ah.single_case("QCBORDecode_GetInt64", GET_INT, SPARE, _init_api())
    assert layout is not None
    layout["selector"] = 2
    trace = [
        {"fn": "QCBORDecode_Init", "args": {"1": [["n", 0, "a1"]], "2": [["i", 0, "00000000"]]}, "addrs": {"0": "100"}},
        {"fn": "QCBORDecode_Init", "args": {"1": [["n", 0, "bb"]], "2": [["i", 0, "01000000"]]}, "addrs": {"0": "200"}},
        {"fn": "QCBORDecode_GetInt64", "args": {}, "addrs": {"0": "100", "1": "300"}},
    ]
    seeds = sh.layout_seeds([layout], [], [trace])
    assert seeds == {2: [b"\x02\0\0\0\0\xa1"]}
    # A call no trace holds pairs with the initializer's recorded calls.
    calls = [
        {"fn": "QCBORDecode_GetInt64", "args": {"9": []}},
        {"fn": "QCBORDecode_Init", "args": {"1": [["n", 0, "cc"]], "2": [["i", 0, "00000000"]]}},
    ]
    assert sh.layout_seeds([layout], calls, [])[2] == [b"\x02\0\0\0\0\xcc"]


# --- A5: sequences ---------------------------------------------------------------------------------------


def test_sequence_initializer_gets_slices_by_the_same_rules():
    records: dict[str, dict] = {"QCBORDecode_Init": DECODE_INIT, "QCBORDecode_GetInt64": GET_INT}
    trace = [
        {"fn": "QCBORDecode_Init", "args": {}, "addrs": {"0": "100"}},
        {"fn": "QCBORDecode_GetInt64", "args": {}, "addrs": {"0": "100", "1": "300"}},
    ]
    stmt, layout, _ = ah.sequence_case(trace, [0, 1], records, SPARE, _init_api())
    assert stmt is not None and layout is not None
    assert "c0a1.ptr = (void *)(fuzz_buf + fuzz_off);" in stmt and "memcpy(&c0a1, fuzz_buf" not in stmt
    assert stmt.count("QCBORDecode_Init(") == 1 and "inits" not in layout
    assert "sizeof(struct _QCBORDecodeContext)" in stmt
    # A chain whose first use of the context is not its initializer gets it first.
    stmt, layout, _ = ah.sequence_case(list(reversed(trace)), [0, 1], records, SPARE, _init_api())
    assert stmt is not None and layout is not None
    assert stmt.index("QCBORDecode_Init((struct _QCBORDecodeContext *)s0") < stmt.index("QCBORDecode_GetInt64(")
    assert layout["inits"] == [{"fn": "QCBORDecode_Init", "call": 2, "for": {"call": 0, "param": 0}}]


# --- layouts from clang's AST ------------------------------------------------------------------------------


def _field(name: str, qual: str, desugared: str | None = None, **kw: Any) -> dict:
    t = {"qualType": qual, **({"desugaredQualType": desugared} if desugared else {})}
    return {"kind": "FieldDecl", "name": name, "type": t, **kw}


def _record(name: str, *fields: dict, tag: str = "struct") -> dict:
    return {"kind": "RecordDecl", "name": name, "tagUsed": tag, "completeDefinition": True, "inner": list(fields)}


def test_record_layouts_compute_offsets_pointers_and_reject_bitfields():
    tree = {
        "kind": "TranslationUnitDecl",
        "inner": [
            _record("q_useful_buf_c", _field("ptr", "const void *"), _field("len", "size_t", "unsigned long")),
            _record(
                "ctx",
                _field("mode", "uint8_t", "unsigned char"),
                _field("in", "UsefulBufC", "struct q_useful_buf_c"),
                _field("tags", "uint16_t[3]", "unsigned short[3]"),
                _field("kind", "enum Kind"),
            ),
            _record("bits", _field("a", "unsigned int", isBitfield=True)),
            _record("plain", _field("a", "int"), _field("b", "double")),
            {"kind": "FunctionDecl", "name": "QCBORDecode_Init", "inner": [_record("hidden", _field("x", "int"))]},
        ],
    }
    layouts, functions = ah.record_layouts(tree)
    assert functions == {"QCBORDecode_Init"}
    assert set(layouts) == {"struct q_useful_buf_c", "struct ctx", "struct plain"}
    ubc = layouts["struct q_useful_buf_c"]
    assert (ubc["size"], ubc["pointers"]) == (16, True)
    assert [(f["name"], f["kind"], f["off"], f.get("const")) for f in ubc["fields"]] == [
        ("ptr", "ptr", 0, True),
        ("len", "int", 8, None),
    ]
    ctx = layouts["struct ctx"]
    assert [(f["name"], f["off"]) for f in ctx["fields"]] == [("mode", 0), ("in", 8), ("tags", 24), ("kind", 32)]
    assert ctx["size"] == 40 and ctx["pointers"]
    assert layouts["struct plain"] == {
        "what": "struct",
        "size": 16,
        "align": 8,
        "pointers": False,
        "fields": [
            {"name": "a", "off": 0, "kind": "int", "size": 4, "pointers": False, "ctype": "int"},
            {"name": "b", "off": 8, "kind": "float", "size": 8, "pointers": False, "ctype": "double"},
        ],
    }


def test_probe_layouts_reads_the_ast_of_the_harness_without_its_cases(tmp_path):
    harness = tmp_path / "harness_lib.c"
    harness.write_text('#include "lib.h"\n    case 0U: { f(); } break;\n')
    seen: list[str] = []

    def fake_run(argv, **kwargs):
        seen.append(Path(argv[-1]).read_text())
        tree = {"kind": "TranslationUnitDecl", "inner": [_record("s", _field("a", "int"))]}
        return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(tree), stderr="")

    got = ah.probe_layouts(harness, "-I.", clang="clang", runner=fake_run)
    assert got is not None and set(got[0]) == {"struct s"}
    assert seen == ['#include "lib.h"\n\n'] and not list(tmp_path.glob(".*probe*"))
    bad = ah.probe_layouts(
        harness, "-I.", clang="clang", runner=lambda a, **k: subprocess.CompletedProcess(a, 1, "", "")
    )
    assert bad is None


# --- D1: the compiler's reason for a dropped case ------------------------------------------------------------


def test_case_diagnostics_keep_the_first_error_of_each_case(tmp_path, monkeypatch):
    harness = tmp_path / "harness_lib.c"
    harness.write_text("    case 0U: { f(); } break;\n    case 1U: { g(1); } break;\n")
    err = (
        f"{harness.name}:2:15: error: call to undeclared function 'g'; ISO C99 and later do not support it\n"
        f"{harness.name}:2:20: error: second error\n"
        "lib.h:3:1: error: elsewhere\n"
    )
    monkeypatch.setattr(
        ah.subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(argv, 1, stdout="", stderr=err)
    )
    diags = ah.case_diagnostics(harness, "-I.", clang="clang")
    assert diags == {
        1: f"{harness.name}:2: error: call to undeclared function 'g'; ISO C99 and later do not support it"
    }
    assert ah.failing_cases(harness, "-I.", clang="clang") == {1}


# --- the sidecar: generate with layouts, schema, seeds -----------------------------------------------------------


def test_generate_writes_valid_layouts_with_inits_and_notes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "lib.c").write_text("/* lib */\n")
    names = ["QCBORDecode_Init", "QCBORDecode_GetInt64", "UsefulBuf_Compare", "Opaque"]
    functions = {
        n: {
            "name": n,
            "file": "lib.c",
            "module": "lib",
            "is_static": False,
            "internal_callees": [],
            "internal_callers": [],
        }
        for n in names
    }
    dag = {
        "schema_version": 1,
        "module_kind": "link_unit",
        "callgraph_source": "frama_c",
        "warnings": [],
        "modules": {"lib": {"functions": names, "candidate_entry_points": names}},
        "functions": functions,
    }
    model = {
        "status": "ok",
        "functions": {
            "lib.c#QCBORDecode_Init": DECODE_INIT,
            "lib.c#QCBORDecode_GetInt64": GET_INT,
            "lib.c#UsefulBuf_Compare": {
                "signature": "int(struct q_useful_buf_c,struct q_useful_buf_c)",
                "formals": _formals("value", "value"),
            },
            "lib.c#Opaque": {"signature": "int(struct unknown_s)", "formals": _formals("value")},
        },
    }
    reports = tmp_path / "workspace" / "reports"
    reports.mkdir(parents=True)
    (reports / "callgraph_dag.json").write_text(json.dumps(dag))
    (reports / "phase0_model.json").write_text(json.dumps(model))
    ah.generate(
        module="lib",
        header=None,
        max_input_size=64,
        cppflags="-I.",
        out_dir=tmp_path / "workspace" / "harnesses",
        unit="lib",
        auto_prelude=False,
        probe=False,
        dag_path=reports / "callgraph_dag.json",
        model_path=reports / "phase0_model.json",
        traces_path=tmp_path / "none" / "traces.jsonl",
        struct_layouts=dict(LAYOUTS),
    )
    side = json.loads((tmp_path / "workspace" / "harnesses" / "harness_lib.json").read_text())
    assert list(va.validate_sidecar(side, "lib")) == []
    by_entry = {c["entry"]: c for c in side["api_cases"]}
    assert by_entry["QCBORDecode_GetInt64"]["inits"][0]["fn"] == "QCBORDecode_Init"
    assert "layout not known" in by_entry["Opaque"]["notes"][0]
    # The harness and the layouts agree: the seed writer lays out the init's input as the rest.
    rec = Path("workspace/seed_records")
    rec.mkdir(parents=True)
    (rec / "calls.jsonl").write_text(
        json.dumps({"fn": "QCBORDecode_GetInt64", "args": {}})
        + "\n"
        + json.dumps({"fn": "QCBORDecode_Init", "args": {"1": [["n", 0, "a0"]], "2": [["i", 0, "00000000"]]}})
        + "\n"
    )
    sh.write([])
    sel = by_entry["QCBORDecode_GetInt64"]["selector"]
    seeds = [p.read_bytes() for p in Path("workspace/seeds/lib").iterdir()]
    assert bytes([sel]) + b"\0\0\0\0\xa0" in seeds
