"""Tests for the whole-API harness (scripts/api_harness.py), its seeds and the benchmark's API reach."""

from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path
from typing import Any

import pytest

import api_harness as ah
import seed_harvest as sh
from benchmark import summarize_api_reach
from benchmark_compare import compare_runs

pytestmark = pytest.mark.unit

SPARE = ah.spare_bytes(64)


def _dag(functions: dict[str, dict], entries: list[str]) -> dict:
    return {
        "module_kind": "link_unit",
        "modules": {"lib": {"candidate_entry_points": entries, "functions": list(functions)}},
        "functions": functions,
    }


def _fn(name: str, file: str = "lib.c", static: bool = False) -> dict:
    return {"name": name, "file": file, "is_static": static, "module": "lib"}


def _model(**functions: dict) -> dict:
    return {"status": "ok", "functions": {f"lib.c#{n}": rec for n, rec in functions.items()}}


def _formals(*kinds: str) -> list[dict]:
    return [{"name": f"p{i}", "kind": k} for i, k in enumerate(kinds)]


# --- cases ------------------------------------------------------------------------------------------


def test_input_pair_takes_the_rest_of_the_input():
    stmt, layout, why = ah.single_case(
        "parse",
        {"signature": "int(unsigned char *,unsigned long)", "formals": _formals("const_pointer", "value")},
        SPARE,
    )
    assert why is None and stmt is not None and layout is not None
    assert "(unsigned char *)(fuzz_buf + fuzz_off), (unsigned long)(fuzz_len - fuzz_off)" in stmt
    assert layout["rest"] == {"call": 0, "param": 0, "kind": "bytes"}
    assert layout["slots"] == []


def test_output_pair_gets_a_spare_buffer_and_a_clamped_length():
    stmt, layout, _ = ah.single_case(
        "fill", {"signature": "void(unsigned char *,unsigned long)", "formals": _formals("pointer", "value")}, SPARE
    )
    assert stmt is not None and layout is not None
    assert f"static _Alignas(16) unsigned char c0a0[{SPARE}]" in stmt
    assert f"if ((unsigned long long)c0a1 > {SPARE}ULL)" in stmt
    assert layout["rest"] is None
    assert layout["slots"] == [{"call": 0, "param": 1, "size": 8, "kind": "int"}]


def test_known_size_gives_an_exact_stack_buffer_read_from_the_input():
    rec = {
        "signature": "int(unsigned char *,unsigned char *)",
        "formals": _formals("pointer", "const_pointer"),
        "param_sizes": {"0": {"min": 32, "max": 32, "sites": 2}, "1": {"min": 24, "max": 24, "sites": 2}},
    }
    stmt, layout, _ = ah.single_case("box", rec, SPARE)
    assert stmt is not None and layout is not None
    assert "unsigned char c0a0[32]; memset" in stmt and "static _Alignas(16) unsigned char c0a0" not in stmt
    assert "unsigned char c0a1[24]" in stmt
    # The output is zeroed; only the input is read from the fuzz input.
    assert layout["slots"] == [{"call": 0, "param": 1, "size": 24, "kind": "bytes"}]


def test_unknown_size_byte_pointer_is_a_zeroed_spare_buffer():
    stmt, layout, _ = ah.single_case(
        "key", {"signature": "int(unsigned char *)", "formals": _formals("const_pointer")}, SPARE
    )
    assert stmt is not None and layout is not None
    assert f"static _Alignas(16) unsigned char c0a0[{SPARE}]" in stmt
    assert layout["slots"] == [] and layout["rest"] is None


def test_lone_const_char_pointer_takes_the_rest_as_a_string():
    stmt, layout, _ = ah.single_case("open", {"signature": "int(char *)", "formals": _formals("const_pointer")}, SPARE)
    assert stmt is not None and layout is not None
    assert "c0a0[rest_n] = 0;" in stmt
    assert layout["rest"] == {"call": 0, "param": 0, "kind": "string"}


def test_scalars_structs_and_pointers_to_objects():
    rec = {
        "signature": "int(int,struct cfg,struct ctx *,unsigned long *,void (*)(int))",
        "formals": _formals("value", "value", "pointer", "pointer", "value"),
    }
    stmt, layout, _ = ah.single_case("run", rec, SPARE)
    assert stmt is not None and layout is not None
    # A pointer to a struct is one object; a pointer to a scalar a small array (`_scalar_array`).
    assert "struct cfg c0a1;" in stmt and "struct ctx c0a2;" in stmt
    assert f"unsigned long c0a3[{ah.ARRAY_ELEMENTS}];" in stmt
    assert "(void)run(c0a0, c0a1, &c0a2, (unsigned long *)c0a3, 0);" in stmt
    # Without a layout the struct by value may hold pointers: zeroed, with the reason in the notes.
    assert [(s["param"], s["kind"], s["size"]) for s in layout["slots"]] == [(0, "int", 4)]
    assert "struct cfg" in layout["notes"][0] and "zeroed" in layout["notes"][0]
    # A pointer-free layout reads it from the input, at its known size.
    api = ah.ApiInfo(structs={"struct cfg": {"what": "struct", "size": 8, "pointers": False, "fields": []}})
    _, layout, _ = ah.single_case("run", rec, SPARE, api)
    assert layout is not None
    assert [(s["param"], s["kind"], s["size"]) for s in layout["slots"]] == [(0, "int", 4), (1, "struct", 8)]


@pytest.mark.parametrize(
    "sig,why",
    [("int(char *,...)", "variadic"), ("int(struct __anonstruct_x_1)", "anonymous struct by value"), ("bad", None)],
)
def test_functions_the_generator_cannot_call(sig, why):
    stmt, layout, reason = ah.single_case("f", {"signature": sig}, SPARE)
    assert stmt is None and layout is None and reason
    if why:
        assert why in reason


def test_plan_covers_the_scope_and_skips_with_reasons():
    dag = _dag(
        {"main": _fn("main"), "a": _fn("a"), "b": _fn("b"), "s": _fn("s", static=True), "v": _fn("v")},
        ["main", "a", "b", "s", "v"],
    )
    model = _model(
        main={"signature": "int()"},
        a={"signature": "int(unsigned char *,unsigned long)", "formals": _formals("const_pointer", "value")},
        b={"signature": "void(int)", "formals": _formals("value")},
        v={"signature": "int(char *,...)"},
    )
    p = ah.plan(dag, model, "lib", "lib", 64)
    assert p["entries"] == ["a", "b"]
    assert [lay["selector"] for lay in p["layouts"]] == [0, 1]
    assert set(p["skipped"]) == {"s", "v"}
    assert "static" in p["skipped"]["s"] and "variadic" in p["skipped"]["v"]


def test_a_translated_variadic_definition_is_skipped_as_variadic():
    # Frama-C's model of `bool scan(const char *sentence, const char *format, ...)`: no `...` in the
    # signature, a last formal for the rest. A case would call it as a three-parameter function: an
    # empty format, and a pointer read from the input where the variable arguments go.
    scan: dict[str, Any] = {
        "signature": "_Bool(char *,char *,void **)",
        "formals": [
            {"name": "sentence", "kind": "const_pointer"},
            {"name": "format", "kind": "const_pointer"},
            {"name": sh.VA_PARAMS, "kind": "const_pointer"},
        ],
    }
    assert ah.plan_params(scan["signature"], scan["formals"]) == (None, "variadic")
    assert ah.single_case("scan", scan, SPARE) == (None, None, "variadic")
    dag = _dag({"a": _fn("a"), "scan": _fn("scan")}, ["a", "scan"])
    model = _model(a={"signature": "void(int)", "formals": _formals("value")}, scan=scan)
    p = ah.plan(dag, model, "lib", "lib", 64)
    # Without a call site of the target's own programs to copy (tests/test_variadic_calls.py), no case.
    assert p["entries"] == ["a"] and p["skipped"] == {"scan": ah.NO_VARIADIC_SITE}
    assert p["skipped"]["scan"].startswith("variadic")
    assert all("scan(" not in c for c in p["cases"])
    # A trace that calls it is not replayed either.
    trace = [{"fn": "scan", "addrs": {"0": "10"}}, {"fn": "scan", "addrs": {"0": "10"}}]
    stmt, layout, why = ah.sequence_case(trace, [0, 1], {"scan": scan}, SPARE)
    assert stmt is None and layout is None and why == "scan: variadic"


# --- sequences ---------------------------------------------------------------------------------------


def _trace() -> list[dict]:
    return [
        {"fn": "keypair", "args": {}, "addrs": {"0": "100", "1": "200"}},
        {"fn": "hash", "args": {"1": [["b", 0, "aa"]]}, "addrs": {"0": "900", "1": "901"}},
        {"fn": "box", "args": {"1": [["b", 0, "6869"]]}, "addrs": {"0": "300", "1": "301", "3": "100", "4": "200"}},
    ]


def test_chains_group_calls_by_shared_pointers():
    assert ah.chains(_trace()) == [[0, 2]]


def test_sequence_case_passes_shared_buffers_between_calls():
    records: dict[str, Any] = {
        "keypair": {
            "signature": "int(unsigned char *,unsigned char *)",
            "formals": _formals("pointer", "pointer"),
            "param_sizes": {"0": {"max": 32}, "1": {"max": 32}},
        },
        "box": {
            "signature": "int(unsigned char *,unsigned char *,unsigned long long,unsigned char *,unsigned char *)",
            "formals": _formals("pointer", "const_pointer", "value", "const_pointer", "const_pointer"),
            "param_sizes": {"3": {"max": 32}, "4": {"max": 32}},
        },
    }
    stmt, layout, why = ah.sequence_case(_trace(), [0, 2], records, SPARE)
    assert why is None and stmt is not None and layout is not None
    assert stmt.index("(void)keypair((unsigned char *)s0, (unsigned char *)s1);") < stmt.index("(void)box(")
    assert "(unsigned char *)s0, (unsigned char *)s1);" in stmt.split("(void)box(")[1]
    assert layout["calls"] == ["keypair", "box"] and layout["kind"] == "sequence"
    # keypair writes the shared buffers; box takes the rest of the input as its message.
    assert layout["rest"] == {"call": 1, "param": 1, "kind": "bytes"}
    # box's output receives mlen bytes, mlen from the input: a spare buffer, even with a call-site size
    # or a recorded size from the trace
    records["box"]["param_sizes"]["0"] = {"max": 64}
    trace = _trace()
    trace[2] = {**trace[2], "sizes": {"0": 1}}
    stmt, _, _ = ah.sequence_case(trace, [0, 2], records, SPARE)
    assert stmt is not None and f"static _Alignas(16) unsigned char c1a0[{SPARE}];" in stmt
    shared_out = [{"fn": "box", "args": {}, "addrs": {"0": "500"}}, {"fn": "box", "args": {}, "addrs": {"1": "500"}}]
    stmt, _, _ = ah.sequence_case(shared_out, [0, 1], records, SPARE)
    assert stmt is not None and f"static _Alignas(16) unsigned char s0[{SPARE}];" in stmt


def test_single_case_gives_a_variable_length_call_spare_outputs():
    rec: dict[str, Any] = {
        "signature": "int(unsigned char *,unsigned char *,unsigned long long,unsigned char *)",
        "formals": _formals("pointer", "const_pointer", "value", "const_pointer"),
        "param_sizes": {"0": {"max": 64}, "3": {"max": 24}},
    }
    stmt, layout, _ = ah.single_case("box", rec, SPARE)
    assert stmt is not None and layout is not None
    assert f"static _Alignas(16) unsigned char c0a0[{SPARE}];" in stmt and "unsigned char c0a3[24];" in stmt
    # with a known-size input there is no variable length: the output keeps its call-site size
    rec["param_sizes"]["1"] = {"max": 16}
    stmt, _, _ = ah.single_case("box", rec, SPARE)
    assert stmt is not None and "unsigned char c0a0[64];" in stmt


def test_plan_adds_sequence_cases_from_traces():
    dag = _dag({"keypair": _fn("keypair"), "box": _fn("box"), "hash": _fn("hash")}, ["keypair", "box", "hash"])
    model = _model(
        keypair={"signature": "int(unsigned char *,unsigned char *)", "formals": _formals("pointer", "pointer")},
        box={"signature": "int(unsigned char *,unsigned char *,unsigned long long,unsigned char *,unsigned char *)"},
        hash={"signature": "int(unsigned char *,unsigned char *,unsigned long long)"},
    )
    p = ah.plan(dag, model, "lib", "lib", 64, [_trace(), _trace()])
    kinds = [lay["kind"] for lay in p["layouts"]]
    assert kinds == ["single", "single", "single", "sequence"]
    # A call into another module (randombytes filling the nonce) drops out; the chain stays.
    entropy = {"fn": "randombytes", "args": {}, "addrs": {"0": "700"}}
    traced = [entropy, *_trace()]
    traced[3] = {**traced[3], "addrs": {**traced[3]["addrs"], "2": "700"}}
    p = ah.plan(dag, model, "lib", "lib", 64, [traced])
    assert [lay["calls"] for lay in p["layouts"] if lay["kind"] == "sequence"] == [["keypair", "box"]]


# --- seeds from layouts --------------------------------------------------------------------------------


def test_layout_seed_lays_out_slots_then_the_rest():
    layout = {
        "selector": 3,
        "slots": [
            {"call": 0, "param": 0, "size": 4, "kind": "int"},
            {"call": 0, "param": 1, "size": 4, "kind": "bytes"},
        ],
        "rest": {"call": 0, "param": 2, "kind": "bytes"},
    }
    args = {"0": [["i", 0, "01000000"]], "1": [["a", 0, "aabb"]], "2": [["b", 0, "68656c6c6f"]]}
    assert sh.layout_seed(layout, [args]) == bytes([3]) + b"\x01\0\0\0" + b"\xaa\xbb\0\0" + b"hello"
    # Nothing recorded feeds the case: no seed.
    assert sh.layout_seed(layout, [{}]) is None


def test_layout_seeds_for_singles_and_sequences():
    single = {
        "selector": 0,
        "kind": "single",
        "calls": ["hash"],
        "slots": [],
        "rest": {"call": 0, "param": 1, "kind": "bytes"},
    }
    seq = {
        "selector": 1,
        "kind": "sequence",
        "calls": ["keypair", "box"],
        "slots": [],
        "rest": {"call": 1, "param": 1, "kind": "bytes"},
    }
    calls = [{"fn": "hash", "args": {"1": [["b", 0, "aa"]]}}]
    seeds = sh.layout_seeds([single, seq], calls, [_trace()])
    assert seeds == {0: [b"\x00\xaa"], 1: [b"\x01hi"]}


def test_write_uses_the_sidecar_layout(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    hd = Path("workspace/harnesses")
    hd.mkdir(parents=True)
    layout = {
        "selector": 0,
        "kind": "single",
        "calls": ["hash"],
        "slots": [],
        "rest": {"call": 0, "param": 1, "kind": "bytes"},
    }
    (hd / "harness_lib.json").write_text(json.dumps({"max_input_size": 64, "api_cases": [layout]}))
    (hd / "harness_lib.c").write_text("/* not parsed */")
    rec = Path("workspace/seed_records")
    rec.mkdir(parents=True)
    (rec / "calls.jsonl").write_text(json.dumps({"fn": "hash", "args": {"1": [["b", 0, "6869"]]}}) + "\n")
    out = sh.write([])
    assert out["modules"]["lib"]["seeds"] == 1
    assert [p.read_bytes() for p in Path("workspace/seeds/lib").iterdir()] == [b"\x00hi"]


def test_case_probe_finds_the_headers_the_build_generated(tmp_path, monkeypatch):
    # Without them a target header fails first (libpng: pnglibconf.h), on no case's line, and the
    # probe drops nothing: no case was checked.
    import subprocess

    snap = tmp_path / "snapshot"
    (snap / "generated/build").mkdir(parents=True)
    (snap / "manifest.json").write_text(json.dumps({"digest": "d", "files": {}, "generated_dirs": ["build"]}))
    monkeypatch.setenv("FRAMAC_SNAPSHOT_DIR", str(snap))
    harness = tmp_path / "harness_lib.c"
    harness.write_text("    case 0U: { f(); break; }\n    case 1U: { g(1); break; }\n")
    seen: list[list[str]] = []

    def fake_run(argv, **kwargs):
        seen.append(list(argv))
        return subprocess.CompletedProcess(
            argv, 1, stdout="", stderr=f"{harness.name}:2:15: error: too many arguments\n"
        )

    monkeypatch.setattr(ah.subprocess, "run", fake_run)
    assert ah.failing_cases(harness, "-Iworkspace/work", clang="clang") == {1}
    argv = seen[0]
    assert argv[argv.index("-idirafter") + 1] == (snap / "generated/build").as_posix()


def _generate_fixture(tmp_path, monkeypatch, names: list[str]) -> tuple[Path, list[list[str]]]:
    """A DAG and a model with one `int <name>(int)` per name; harness writes are faked and logged."""
    import generate_harness

    monkeypatch.chdir(tmp_path)
    out = tmp_path / "workspace" / "harnesses"
    out.mkdir(parents=True)
    dag = _dag({n: _fn(n) for n in names}, names)
    model = _model(**{n: {"signature": "int(int)", "formals": _formals("value")} for n in names})
    (tmp_path / "dag.json").write_text(json.dumps(dag))
    (tmp_path / "model.json").write_text(json.dumps(model))
    writes: list[list[str]] = []

    def fake_generate(**kw):
        cases = list(kw["dispatch_cases"])
        writes.append(cases)
        assert kw["fail_on_compile_error"] is False  # the probe judges compile errors
        harness = out / f"harness_{kw['module_name']}.c"
        harness.write_text("".join(f"    case {i}U: {{ {c} }} break;\n" for i, c in enumerate(cases)))
        meta = out / f"harness_{kw['module_name']}.json"
        meta.write_text(json.dumps({"module": kw["module_name"], "dispatch_cases": cases}))
        return {"harness_file": str(harness), "harness_meta": str(meta), "cppflags": ""}

    monkeypatch.setattr(generate_harness, "generate_module_harness", fake_generate)
    monkeypatch.setattr(ah, "probe_layouts", lambda *a, **k: None)  # no struct to lay out
    return out, writes


def _gen(out: Path, **kw: Any) -> dict:
    return ah.generate(
        "lib",
        None,
        64,
        "",
        out,
        unit="lib",
        dag_path=Path("dag.json"),
        model_path=Path("model.json"),
        traces_path=Path("none/traces.jsonl"),
        **kw,
    )


def test_case_probe_drops_every_failing_case_and_rewrites_the_harness(tmp_path, monkeypatch):
    """pngwutil: more failing cases than one compile reports; the sidecar must match the harness left."""
    names = ["ok_a", "bad_1", "bad_2", "ok_b", "bad_3", "bad_4", "bad_5"]
    out, writes = _generate_fixture(tmp_path, monkeypatch, names)

    def probe(harness_c, cppflags, clang=None):
        lines = Path(harness_c).read_text().splitlines()
        bad = [i for i, line in enumerate(lines) if "bad_" in line]
        return {i: "error" for i in bad[:2]}, []  # a capped compiler: two failing cases per compile

    monkeypatch.setattr(ah, "probe_cases", probe)
    res = _gen(out)

    assert len(writes) == 4  # 5 bad cases, 2 per round, then the clean write
    assert all("bad_" not in c for c in writes[-1])
    meta = json.loads((out / "harness_lib.json").read_text())
    assert [lay["calls"] for lay in meta["api_cases"]] == [["ok_a"], ["ok_b"]]
    assert [lay["selector"] for lay in meta["api_cases"]] == [0, 1]
    assert len(meta["dispatch_cases"]) == len(meta["api_cases"]) == res["api_cases"]
    assert set(meta["api_skipped"]) == {f"bad_{i}" for i in range(1, 6)}


def test_case_probe_fails_on_errors_outside_the_cases_and_keeps_the_previous_harness(tmp_path, monkeypatch):
    out, writes = _generate_fixture(tmp_path, monkeypatch, ["a", "b"])
    (out / "harness_lib.c").write_text("previous")
    (out / "harness_lib.json").write_text('{"previous": true}')
    monkeypatch.setattr(ah, "probe_cases", lambda h, c, clang=None: ({}, ["harness_lib.c:3:1: error: x"]))

    with pytest.raises(ah.ApiHarnessError, match="does not compile outside its cases"):
        _gen(out)
    assert (out / "harness_lib.c").read_text() == "previous"
    assert (out / "harness_lib.json").read_text() == '{"previous": true}'


def test_no_compiling_case_leaves_no_harness(tmp_path, monkeypatch):
    out, _ = _generate_fixture(tmp_path, monkeypatch, ["bad_1", "bad_2"])
    monkeypatch.setattr(ah, "probe_cases", lambda h, c, clang=None: ({0: "error", 1: "error"}, []))

    with pytest.raises(ah.ApiHarnessError, match="no API case compiles"):
        _gen(out)
    assert not (out / "harness_lib.c").exists() and not (out / "harness_lib.json").exists()


def test_case_probe_lifts_the_error_cap_and_reports_unlocated_errors(tmp_path, monkeypatch):
    import subprocess

    harness = tmp_path / "harness_lib.c"
    harness.write_text("    case 0U: { f(); } break;\n")
    seen: list[list[str]] = []

    def fake_run(argv, **kwargs):
        seen.append(list(argv))
        return subprocess.CompletedProcess(argv, 1, stdout="", stderr="clang: error: unknown argument\n")

    monkeypatch.setattr(ah.subprocess, "run", fake_run)
    assert ah.probe_cases(harness, "", clang="/usr/bin/clang-18") == ({}, ["clang: error: unknown argument"])
    assert "-ferror-limit=0" in seen[0]
    ah.probe_cases(harness, "", clang="/usr/bin/gcc")
    assert "-fmax-errors=0" in seen[1] and "-ferror-limit=0" not in seen[1]


# --- variable names (PTF WriteAnomaly: `redefinition of 'c0a0'`) ----------------------------------------

# `int WriteAnomaly(const AnomalyDBEntry_T *AnomalyElement, char ChainId[])`: the model spells the
# typedef as its struct, the call sites pass one object (`param_sizes`), and the struct holds pointers.
_ANOMALY_H = (
    "typedef struct AnomalyBase_T {\n"
    "    const unsigned char *Data;\n    unsigned int DataLen;\n    char *Name;\n    int Id;\n"
    "} AnomalyDBEntry_T;\n"
    "int WriteAnomaly(const AnomalyDBEntry_T *AnomalyElement, char ChainId[]);\n"
)
_ANOMALY_LAYOUT = {
    "what": "struct",
    "size": 32,
    "align": 8,
    "pointers": True,
    "fields": [
        {"name": "Data", "off": 0, "kind": "ptr", "size": 8, "pointers": True, "const": True},
        {"name": "DataLen", "off": 8, "kind": "int", "size": 4, "pointers": False, "ctype": "unsigned int"},
        {"name": "Name", "off": 16, "kind": "ptr", "size": 8, "pointers": True, "const": False},
        {"name": "Id", "off": 24, "kind": "int", "size": 4, "pointers": False, "ctype": "int"},
    ],
}
_ANOMALY_REC = {
    "signature": "int(struct AnomalyBase_T *,char *)",
    "formals": [{"name": "AnomalyElement", "kind": "const_pointer"}, {"name": "ChainId", "kind": "pointer"}],
    "param_sizes": {"0": {"min": 32, "max": 32, "sites": 1}},
}


def _declared(stmt: str) -> list[str]:
    """The zero-initialized variables a case declares (`<type> <name>[...]; memset(...)`), as the generator writes them."""
    import re

    return re.findall(r"(?:^|; |\} )(?:static )?(?:_Alignas\(\d+\) )?(?:[A-Za-z_]\w* )+([^ ;=]+?)(?:\[[^;]*\])?;", stmt)


def test_pointer_field_storage_of_a_struct_in_an_array_has_an_identifier_for_a_name():
    api = ah.ApiInfo(structs={"struct AnomalyBase_T": _ANOMALY_LAYOUT}, probed=True)
    stmt, layout, why = ah.single_case("WriteAnomaly", _ANOMALY_REC, SPARE, api)
    assert why is None and stmt is not None and layout is not None
    # The object is an array of the call sites' size, its fields are filled through `c0a0[0]`...
    assert "struct AnomalyBase_T c0a0[(32 + sizeof(struct AnomalyBase_T) - 1) / sizeof(struct AnomalyBase_T)];" in stmt
    assert "c0a0[0].Data = (void *)(fuzz_buf + fuzz_off);" in stmt
    # ... and the storage of its lone pointer field was `static unsigned char c0a0[0]f2[N]`: a second
    # `c0a0`, of type `unsigned char[0]`.
    assert "c0a0[0]f" not in stmt
    assert (
        f"static _Alignas(16) unsigned char c0a0_0_f2[{SPARE}];" in stmt and "c0a0[0].Name = (void *)c0a0_0_f2;" in stmt
    )
    names = _declared(stmt)
    assert names == ["c0a0", "c0a0_0_f2", "c0a1"]
    # Without a call-site size the object is one struct, named as before.
    stmt, _, _ = ah.single_case("WriteAnomaly", {**_ANOMALY_REC, "param_sizes": {}}, SPARE, api)
    assert stmt is not None and f"static _Alignas(16) unsigned char c0a0f2[{SPARE}];" in stmt


@pytest.mark.skipif(shutil.which("clang") is None, reason="needs clang")
def test_the_struct_array_case_compiles(tmp_path):
    import subprocess

    api = ah.ApiInfo(structs={"struct AnomalyBase_T": _ANOMALY_LAYOUT}, probed=True)
    stmt, _, _ = ah.single_case("WriteAnomaly", _ANOMALY_REC, SPARE, api)
    src = tmp_path / "harness_lib.c"
    src.write_text(
        "#include <stddef.h>\n#include <string.h>\n#define FRAMAC_FUZZ_COPY(buf, off) ((buf) + (off))\n"
        + _ANOMALY_H
        + "void run(const unsigned char *fuzz_buf, size_t fuzz_len) {\n    switch (fuzz_len % 1U) {\n"
        + f"    case 0U: {{ {stmt} }} break;\n"
        + "    }\n}\n"
    )
    proc = subprocess.run(["clang", "-fsyntax-only", "-x", "c", str(src)], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    assert ah.probe_cases(src, "") == ({}, [])


def test_a_case_never_declares_a_name_twice():
    case = ah._Case(SPARE)
    assert case.declare("c0a0") == "c0a0"
    with pytest.raises(ah._DeclError, match="'c0a0' would be declared twice"):
        case.declare("c0a0")
    with pytest.raises(ah._DeclError, match=r"'c0a0\[0\]f2' is not a C identifier"):
        case.declare("c0a0[0]f2")


def test_a_name_collision_skips_the_function_with_a_reason():
    # Field paths `a.b` and `a_b` give their pointer storage the same name: the case is not written.
    ptr = {"name": "p", "off": 0, "kind": "ptr", "size": 8, "pointers": True, "const": False}
    inner = {"what": "struct", "size": 8, "align": 8, "pointers": True, "fields": [ptr]}

    def member(name: str, off: int, ctype: str) -> dict:
        return {
            "name": name,
            "off": off,
            "kind": "record",
            "size": 8,
            "pointers": True,
            "what": "struct",
            "ctype": ctype,
        }

    structs = {
        "struct inner": inner,
        "struct mid": {**inner, "fields": [member("b", 0, "struct inner")]},
        "struct outer": {
            "what": "struct",
            "size": 16,
            "align": 8,
            "pointers": True,
            "fields": [member("a", 0, "struct mid"), member("a_b", 8, "struct inner")],
        },
    }
    rec = {"signature": "int(struct outer)", "formals": _formals("value")}
    stmt, layout, why = ah.single_case("take", rec, SPARE, ah.ApiInfo(structs=structs, probed=True))
    assert stmt is None and layout is None
    assert why == "generator defect: variable 'c0a0_a_bf0' would be declared twice in the case"

    dag = _dag({"take": _fn("take"), "ok": _fn("ok")}, ["take", "ok"])
    model = _model(take=rec, ok={"signature": "int(int)", "formals": _formals("value")})
    p = ah.plan(dag, model, "lib", "lib", 64, struct_layouts=structs, visible=set())
    assert p["skipped"] == {"take": why} and [lay["calls"] for lay in p["layouts"]] == [["ok"]]


# --- hand-written cases (`--api --dispatch-case`) -------------------------------------------------------

_CUSTOM_CASE = "if (fuzz_len >= 4) { (void)take_by_value(fuzz_buf); }"


def test_api_appends_hand_written_cases_and_a_regeneration_keeps_them(tmp_path, monkeypatch):
    out, writes = _generate_fixture(tmp_path, monkeypatch, ["a", "b"])
    monkeypatch.setattr(ah, "probe_cases", lambda h, c, clang=None: ({}, []))

    res = _gen(out, dispatch_cases=[f"  {_CUSTOM_CASE}  ", ""])

    assert len(writes[-1]) == 3 and writes[-1][2] == _CUSTOM_CASE and "a(" in writes[-1][0]
    meta = json.loads((out / "harness_lib.json").read_text())
    assert meta["api_cases"][2] == {"kind": "custom", "calls": [], "slots": [], "rest": None, "selector": 2}
    assert [lay["selector"] for lay in meta["api_cases"]] == [0, 1, 2]
    assert len(meta["dispatch_cases"]) == len(meta["api_cases"]) == res["api_cases"] == 3
    assert res["api_custom"] == 1 and res["api_entries"] == 2
    assert ah.previous_custom_cases(meta) == [_CUSTOM_CASE]
    # The sidecar schema takes the custom layout (and the moved extra includes of the prelude).
    from validate_artifacts import schema_problems

    doc = {**meta, "extra_includes_first": ["mod_prelude.h"]}
    assert not [p for p in schema_problems("harness_sidecar", doc) if "api_cases" in p or "extra_includes" in p]
    bad = {**meta, "api_cases": [*meta["api_cases"][:2], {**meta["api_cases"][2], "calls": ["a"]}]}
    assert [p for p in schema_problems("harness_sidecar", bad) if "api_cases" in p]

    # Without the flag (None), the next run keeps the case; with it, the given cases replace it.
    _gen(out)
    assert writes[-1][2:] == [_CUSTOM_CASE]
    _gen(out, dispatch_cases=["(void)other();", _CUSTOM_CASE])
    assert writes[-1][2:] == ["(void)other();", _CUSTOM_CASE]
    res = _gen(out, dispatch_cases=[""])
    assert len(writes[-1]) == 2 and res["api_custom"] == 0
    assert all(lay["kind"] == "single" for lay in json.loads((out / "harness_lib.json").read_text())["api_cases"])


def test_seed_writers_make_nothing_for_a_hand_written_case(tmp_path, monkeypatch):
    import fuzz_assets

    out, _ = _generate_fixture(tmp_path, monkeypatch, ["a"])
    monkeypatch.setattr(ah, "probe_cases", lambda h, c, clang=None: ({}, []))
    _gen(out, dispatch_cases=[_CUSTOM_CASE])
    meta = json.loads((out / "harness_lib.json").read_text())

    calls = [
        {"fn": "a", "args": {"0": [["i", 0, "07000000"]]}},
        {"fn": "take_by_value", "args": {"0": [["b", 0, "00"]]}},
    ]
    seeds = sh.layout_seeds(meta["api_cases"], calls, [])
    assert seeds[1] == [] and len(seeds[0]) == 1 and seeds[0][0][0] == 0
    assert fuzz_assets._whole_input_selectors(meta, "", {"a", "take_by_value"}) == []


def test_a_dropped_generated_case_renumbers_the_hand_written_one(tmp_path, monkeypatch):
    out, writes = _generate_fixture(tmp_path, monkeypatch, ["ok_a", "bad_1", "ok_b"])

    def probe(harness_c, cppflags, clang=None):
        lines = Path(harness_c).read_text().splitlines()
        return {i: "error" for i, line in enumerate(lines) if "bad_" in line}, []

    monkeypatch.setattr(ah, "probe_cases", probe)
    _gen(out, dispatch_cases=[_CUSTOM_CASE])

    meta = json.loads((out / "harness_lib.json").read_text())
    assert [(lay["selector"], lay["kind"]) for lay in meta["api_cases"]] == [
        (0, "single"),
        (1, "single"),
        (2, "custom"),
    ]
    assert meta["dispatch_cases"][2] == _CUSTOM_CASE and writes[-1][2] == _CUSTOM_CASE
    assert set(meta["api_skipped"]) == {"bad_1"}


def test_a_hand_written_case_that_does_not_compile_fails_the_generation(tmp_path, monkeypatch):
    out, _ = _generate_fixture(tmp_path, monkeypatch, ["a", "b"])
    (out / "harness_lib.c").write_text("previous")
    (out / "harness_lib.json").write_text('{"previous": true}')
    monkeypatch.setattr(
        ah,
        "probe_cases",
        lambda h, c, clang=None: ({3: "harness_lib.c:9: error: use of undeclared identifier 'x'"}, []),
    )

    with pytest.raises(
        ah.ApiHarnessError, match=r"--dispatch-case 2 of 2 does not compile .*undeclared identifier 'x'"
    ):
        _gen(out, dispatch_cases=["(void)one();", "(void)two(x);"])
    assert (out / "harness_lib.c").read_text() == "previous"
    assert (out / "harness_lib.json").read_text() == '{"previous": true}'


def test_a_hand_written_case_of_several_lines_is_refused(tmp_path, monkeypatch):
    out, writes = _generate_fixture(tmp_path, monkeypatch, ["a"])
    with pytest.raises(ah.ApiHarnessError, match="--dispatch-case 1 of 1 must be one line of C"):
        _gen(out, dispatch_cases=["(void)one();\n(void)two();"])
    assert writes == []


def test_hand_written_cases_keep_their_selectors_free(monkeypatch):
    names = ["a", "b", "c"]
    dag = _dag({n: _fn(n) for n in names}, names)
    model = _model(**{n: {"signature": "int(int)", "formals": _formals("value")} for n in names})
    monkeypatch.setattr(ah, "MAX_CASES", 3)
    p = ah.plan(dag, model, "lib", "lib", 64, reserve=1)
    assert len(p["cases"]) == 2 and p["skipped"] == {"c": "more than 3 cases"}


def test_the_switch_counts_the_hand_written_case_like_any_other():
    """One selector space: the case count, the skip mask and the Eva shard guards index it by position."""
    import generate_harness

    text = generate_harness._build_dispatch_invocation(["(void)a(0);", "(void)b(0);", _CUSTOM_CASE])
    assert "switch (harness_selector) { /* dispatch selector: identity, 3 cases */" in text
    assert "(harness_selector & 63U)" in text
    assert (
        f"#if !defined(FRAMAC_EVA_SHARD) || defined(FRAMAC_EVA_SHARD_CASE_2)\n        case 2U: {{ {_CUSTOM_CASE} }} break;"
        in text
    )


def test_cli_api_passes_dispatch_cases(tmp_path, monkeypatch, capsys):
    import generate_harness

    seen: list[dict] = []

    def fake(**kw):
        seen.append(kw)
        return {"ok": True}

    monkeypatch.setattr(ah, "generate", fake)
    base = ["--api", "--module", "lib", "--out-dir", str(tmp_path)]
    assert generate_harness.main([*base, f"--dispatch-case={_CUSTOM_CASE}"]) == 0
    assert generate_harness.main(base) == 0
    assert generate_harness.main([*base, "--dispatch-case="]) == 0
    capsys.readouterr()
    assert [kw["dispatch_cases"] for kw in seen] == [[_CUSTOM_CASE], None, [""]]


# --- benchmark ------------------------------------------------------------------------------------------


def test_summarize_api_reach_counts_exemptions_apart(tmp_path):
    reach = {
        "modules": [
            {
                "module": "a",
                "entry_points": 25,
                "entry_points_reached": 2,
                "exempt": {f"f{i}": "why" for i in range(23)},
            },
            {"module": "b", "entry_points": 4, "entry_points_reached": 4},
        ]
    }
    (tmp_path / "a.json").write_text(json.dumps({"seeds": 5}))
    out = summarize_api_reach(reach, tmp_path)
    assert out is not None
    assert (out["entry_points"], out["reached"], out["exempt"], out["seeds"]) == (29, 6, 23, 5)
    assert out["modules"]["a"] == {"entry_points": 25, "reached": 2, "exempt": 23, "seeds": 5}
    assert summarize_api_reach(None) is None


def test_summarize_api_reach_does_not_count_a_units_view_twice():
    # tweetnacl: the harness row holds 25 entry points; the unit's view lists 27 (the same 25, main,
    # and randombytes, which no harness holds and an exemption waves through)
    reach = {
        "modules": [
            {"module": "tweetnacl", "entry_points": 25, "entry_points_reached": 25, "exempt": {}},
            {
                "module": "main",
                "harness_modules": ["tweetnacl"],
                "entry_points": 27,
                "unharnessed_entry_points": ["randombytes"],
                "exempt": {"randombytes": "OS entropy"},
            },
        ]
    }
    out = summarize_api_reach(reach)
    assert out is not None
    assert (out["entry_points"], out["reached"], out["exempt"]) == (26, 25, 1)


def _run(api: dict | None) -> dict:
    target = {"revision": "r", "harness_digest": "h", "status": "ok", "problems": [], "wall_s": 1.0, "cpu_s": 1.0}
    if api is not None:
        target["api_reach"] = api
    return {"schema_version": 1, "run_id": "x", "recall": {"bugs": {}}, "targets": {"t": target}}


@pytest.mark.parametrize("before,after,severity", [(2, 25, "improvement"), (25, 2, "regression")])
def test_compare_flags_api_reach_changes(before, after, severity):
    base = _run({"entry_points": 25, "reached": before, "exempt": 0, "modules": {}})
    cur = copy.deepcopy(base)
    cur["targets"]["t"]["api_reach"]["reached"] = after
    result = compare_runs(base, cur)
    assert [d.severity for d in result.diffs if d.area == "api_reach"] == [severity]


def test_compare_without_api_reach_in_the_baseline_is_not_compared():
    result = compare_runs(_run(None), _run({"entry_points": 25, "reached": 25, "exempt": 0, "modules": {}}))
    assert [d.severity for d in result.diffs if d.area == "api_reach"] == ["not_compared"]


# ---------------------------------------------------------------------------
# D6: Word-Bounded API Lifecycle Names
# ---------------------------------------------------------------------------


def test_api_lifecycle_names_respect_word_boundaries():
    """D6: Match Init/Free/Destroy/Release only on word boundaries."""
    # Positives
    for name in [
        "QCBORDecode_Init",
        "UsefulOutBuf_Init",
        "ctx_init",
        "init_ctx",
        "foo_new",
        "bar_create",
        "FooInit",
        "InitContext",
        "Init",
    ]:
        assert ah._INIT_NAME_RE.search(name), f"Init regex missed positive: {name}"

    for name in [
        "seccomp_release",
        "foo_free",
        "bar_destroy",
        "ctx_close",
        "FooFree",
        "Foo_Free",
        "FreeFoo",
        "BarDestroy",
        "DestroyBar",
        "HandleRelease",
        "ReleaseHandle",
        "seccomp_Release",
    ]:
        assert ah._DTOR_NAME_RE.search(name), f"Dtor regex missed positive: {name}"

    # Negatives (must NOT match)
    for name in ["Initialize", "InitializeFoo", "FooInitialize", "InitialValue", "Initiate", "Primitive"]:
        assert not ah._INIT_NAME_RE.search(name), f"Init regex false positive: {name}"

    for name in ["Freeze", "Freezer", "Freelist", "Freedom", "Destroyer", "Releasable"]:
        assert not ah._DTOR_NAME_RE.search(name), f"Dtor regex false positive: {name}"
