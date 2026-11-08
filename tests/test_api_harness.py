"""Tests for the whole-API harness (scripts/api_harness.py), its seeds and the benchmark's API reach."""

from __future__ import annotations

import copy
import json
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
    assert f"static unsigned char c0a0[{SPARE}]" in stmt
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
    assert "unsigned char c0a0[32]; memset" in stmt and "static unsigned char c0a0" not in stmt
    assert "unsigned char c0a1[24]" in stmt
    # The output is zeroed; only the input is read from the fuzz input.
    assert layout["slots"] == [{"call": 0, "param": 1, "size": 24, "kind": "bytes"}]


def test_unknown_size_byte_pointer_is_a_zeroed_spare_buffer():
    stmt, layout, _ = ah.single_case(
        "key", {"signature": "int(unsigned char *)", "formals": _formals("const_pointer")}, SPARE
    )
    assert stmt is not None and layout is not None
    assert f"static unsigned char c0a0[{SPARE}]" in stmt
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
    assert "struct cfg c0a1;" in stmt and "struct ctx c0a2;" in stmt and "unsigned long c0a3;" in stmt
    assert "(void)run(c0a0, c0a1, &c0a2, &c0a3, 0);" in stmt
    assert [(s["param"], s["kind"], s["size"]) for s in layout["slots"]] == [(0, "int", 4), (1, "struct", None)]


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
    assert stmt is not None and f"static unsigned char c1a0[{SPARE}];" in stmt
    shared_out = [{"fn": "box", "args": {}, "addrs": {"0": "500"}}, {"fn": "box", "args": {}, "addrs": {"1": "500"}}]
    stmt, _, _ = ah.sequence_case(shared_out, [0, 1], records, SPARE)
    assert stmt is not None and f"static unsigned char s0[{SPARE}];" in stmt


def test_single_case_gives_a_variable_length_call_spare_outputs():
    rec: dict[str, Any] = {
        "signature": "int(unsigned char *,unsigned char *,unsigned long long,unsigned char *)",
        "formals": _formals("pointer", "const_pointer", "value", "const_pointer"),
        "param_sizes": {"0": {"max": 64}, "3": {"max": 24}},
    }
    stmt, layout, _ = ah.single_case("box", rec, SPARE)
    assert stmt is not None and layout is not None
    assert f"static unsigned char c0a0[{SPARE}];" in stmt and "unsigned char c0a3[24];" in stmt
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
