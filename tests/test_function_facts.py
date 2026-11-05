"""Per-function prover facts: kernel dump handling, Eva flows, rendering and brief assembly."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import function_facts as ff  # noqa: E402
import kernel_ast  # noqa: E402
import run_eva_slice as eva  # noqa: E402

BRIEF = (ROOT / "skills" / "framac-wp" / "prover_brief.md").read_text(encoding="utf-8")
MARKER_RE = re.compile(r"<!--\s*(?:if:|else|endif)")


def _formal(name, kind="scalar", pointee=None, char_like=False, const=False, restrict=False):
    out = {"name": name, "type": "t", "kind": kind, "restrict": restrict}
    if pointee:
        out.update(pointee=pointee, pointee_canon=pointee, pointee_const=const, char_like=char_like)
    return out


def _access(lval, base, kind="formal", pointer=True, loc="m.c:9", temp=False):
    return {
        "lval": lval,
        "base": base,
        "base_kind": kind,
        "base_temp": temp,
        "through_pointer": pointer,
        "loc": loc,
    }


def _write(lval, base, kind="formal", pointer=True, values=(), temp=False):
    return {
        "lval": lval,
        "base": base,
        "base_kind": kind,
        "base_temp": temp,
        "through_pointer": pointer,
        "values": list(values),
    }


def _loop(index=0, parent=None, loc="m.c:9", guard="i < n", writes=(), reads=(), **kw):
    return {
        "index": index,
        "parent": parent,
        "loc": loc,
        "guard": guard,
        "writes": list(writes),
        "reads": list(reads),
        "calls": kw.get("calls", []),
        "exits": kw.get("exits", []),
        "pointer_walkers": kw.get("pointer_walkers", []),
        "strided_writes": kw.get("strided_writes", []),
    }


def _raw(name, loc, **kw):
    kernel = dict.fromkeys(
        (
            "floats",
            "unions",
            "structs",
            "pointer_arith",
            "pointer_compare",
            "char_pointers",
            "nul_test",
            "division",
            "bitwise",
            "nonlinear",
            "switch",
            "goto",
            "arrays",
        ),
        False,
    )
    kernel.update(kw.get("features", {}))
    return {
        "kernel_name": kw.get("kernel_name", name),
        "name": name,
        "loc": loc,
        "static": kw.get("static", False),
        "variadic": False,
        "return_type": kw.get("return_type", "int"),
        "formals": kw.get("formals", []),
        "loops": kw.get("loops", []),
        "calls": kw.get("calls", []),
        "writes": kw.get("writes", []),
        "reads": kw.get("reads", []),
        "return_paths": kw.get("return_paths", []),
        "derived_pointers": kw.get("derived_pointers", []),
        "truncated": False,
        "features": kernel,
    }


def _record(raw, text, flows=None, cycle=None, others=None):
    by_kernel = {raw["kernel_name"]: raw, **{o["kernel_name"]: o for o in others or []}}
    file = kernel_ast.parse_location(raw["loc"])["file"]
    return ff._function_record(raw, file, text, cycle, by_kernel, flows or {"status": "ok", "by_function": {}})


# ---------------------------------------------------------------------------
# Eva flows
# ---------------------------------------------------------------------------


def test_split_locations_respects_braces_and_string_literals() -> None:
    assert eva.split_locations('g; d[0..15]; r{.len; .buf[0..4]}; "a;b"[0..3]; \\nothing') == [
        "g",
        "d[0..15]",
        "r{.len; .buf[0..4]}",
        '"a;b"[0..3]',
    ]


def test_parse_deps_handles_the_layouts_frama_c_prints() -> None:
    log = """[from] Computing for function fill
[from] ====== DEPENDENCIES COMPUTED ======
  These dependencies hold at termination for the executions that terminate:
[from] Function copy_buf:
  g_state FROM n
  counters[0..7] FROM counters[0..7]; n; k (and SELF)
  \\result FROM \\nothing
[from] Function fill:
  r.len FROM r; n
   .buf[0..4] FROM r; n (and SELF)
[from] Function wrapped:
  r FROM buf; buf_end; next_char; ret; input_buf[0..4095];
         token_char_map (and SELF)
[from] Function separate_from_line:
  hdrs[0].name
      FROM buf; buf_end; token;
           token_char_map (and SELF)
      [0].name_len
      FROM buf; token_len
[from] Function pure:
  NO EFFECTS
[from] Function stuck:
  NON TERMINATING - NO EFFECTS
[from] ====== END OF DEPENDENCIES ======
[kernel] after
"""
    deps = eva.parse_deps_log(log)
    assert deps["copy_buf"]["writes"] == [
        {"loc": "g_state", "and_self": False, "from": ["n"]},
        {"loc": "counters[0..7]", "and_self": True, "from": ["counters[0..7]", "n", "k"]},
    ]
    assert deps["copy_buf"]["result_from"] == []
    assert [w["loc"] for w in deps["fill"]["writes"]] == ["r.len", "r.buf[0..4]"]
    assert deps["wrapped"]["writes"][0]["from"][-1] == "token_char_map"
    assert deps["wrapped"]["writes"][0]["and_self"] is True
    assert [w["loc"] for w in deps["separate_from_line"]["writes"]] == ["hdrs[0].name", "hdrs[0].name_len"]
    assert deps["separate_from_line"]["writes"][0]["from"] == ["buf", "buf_end", "token", "token_char_map"]
    assert deps["separate_from_line"]["writes"][1]["from"] == ["buf", "token_len"]
    assert deps["pure"]["no_effects"] is True and deps["pure"]["non_terminating"] is False
    assert deps["stuck"]["non_terminating"] is True


def test_parse_inout_sections() -> None:
    log = """[inout] Out (external) for function fill:
    counters[5]; r{.len; .buf[0..4]}
[inout] Inputs for function fill:
    counters[5];
    table[0..3]
[inout] InOut (internal) for function fill:
  Operational inputs:
    counters[5]; r; n
  Operational inputs on termination:
    counters[5]; r; n
  Sure outputs:
    k; __retres
[inout] Inputs for function empty:
    \\nothing
[from] Computing for function fill
"""
    inout = eva.parse_inout_log(log)
    assert inout["fill"]["out_external"] == ["counters[5]", "r{.len; .buf[0..4]}"]
    assert inout["fill"]["inputs"] == ["counters[5]", "table[0..3]"]
    assert inout["fill"]["operational_inputs"] == ["counters[5]", "r", "n"]
    assert inout["fill"]["sure_outputs"] == ["k", "__retres"]
    assert inout["empty"]["inputs"] == []


def test_parse_callgraph_dot_uses_labels() -> None:
    dot = """digraph G {
  "UV dispatch (3)" [color="#B09040", label="dispatch",
                     shape=diamond, style="bold", ];
  "UV callee_abs (4)" [label="callee_abs"];
  "UV dispatch (3)" -> "UV callee_abs (4)";
}
"""
    assert eva.parse_callgraph_dot(dot) == {"dispatch": ["callee_abs"]}


def test_flows_step_never_changes_eva_status(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="frama-c", timeout=1)

    monkeypatch.setattr(eva.subprocess, "run", boom)
    flows = eva.collect_flows(tmp_path / "x.sav", tmp_path)
    assert flows["status"] == "timeout" and flows["by_function"] == {}


# ---------------------------------------------------------------------------
# Kernel dump handling
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("workspace/work/m.c:12", ("workspace/work/m.c", 12, 12)),
        ("m.c:12-15", ("m.c", 12, 15)),
        ("m.c:12:3-9", ("m.c", 12, 12)),
        ("m.c:12-15:3-9", ("m.c", 12, 15)),
        ("<generated by x>", ("", 0, 0)),
        (None, ("", 0, 0)),
    ],
)
def test_parse_location(text, expected) -> None:
    loc = kernel_ast.parse_location(text)
    assert (loc["file"], loc["line"], loc["end_line"]) == expected


def test_recursion_cycles_finds_self_and_mutual_recursion() -> None:
    edges = {"a": ["a"], "even": ["odd"], "odd": ["even", "leaf"], "leaf": [], "top": ["even"]}
    assert kernel_ast.recursion_cycles(edges) == [["a"], ["even", "odd"]]


def test_call_graph_is_usable_without_facts() -> None:
    functions = [
        _raw("f", "m.c:1", calls=[{"callee": "g", "kernel_name": "g", "indirect": False}]),
        _raw("g", "m.c:2", calls=[{"indirect": True, "expr": "fp"}, {"callee": "memcpy", "kernel_name": "memcpy"}]),
    ]
    graph = kernel_ast.call_graph(functions)
    assert graph["callgraph_source"] == "frama-c-kernel"
    assert graph["edges"] == {"f": ["g"], "g": []}  # only definitions: memcpy has none here
    assert graph["indirect_calls"] == {"g": ["fp"]}


def _fake_run(ast_doc=None, compile_rc=0, framac_rc=0, framac_exc=None):
    calls = []

    def run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[0] == "ocamlfind":
            if compile_rc == 0:
                (Path(kwargs["cwd"]) / cmd[cmd.index("-o") + 1]).write_bytes(b"cmxs")
            return subprocess.CompletedProcess(cmd, compile_rc, "", "Error: Unbound value" if compile_rc else "")
        if cmd[0] == "frama-c":
            if framac_exc:
                raise framac_exc
            if ast_doc is not None:
                Path(kwargs["env"][kernel_ast.OUT_ENV]).write_text(json.dumps(ast_doc), encoding="utf-8")
            return subprocess.CompletedProcess(cmd, framac_rc, "", "parse error" if framac_rc else "")
        if cmd[0] in ("gcc", "clang"):
            return subprocess.CompletedProcess(cmd, 0, f"x.o: {cmd[-1]}\n", "")
        raise AssertionError(cmd)

    run.calls = calls  # type: ignore[attr-defined]
    return run


def test_dump_reports_every_failure_as_a_status() -> None:
    assert kernel_ast.dump_kernel_ast(["m.c"], runner=_fake_run(compile_rc=2))["status"] == "compile_failed"
    assert kernel_ast.dump_kernel_ast(["m.c"], runner=_fake_run(framac_rc=1))["status"] == "parse_failed"
    timed_out = subprocess.TimeoutExpired(cmd="frama-c", timeout=1)
    assert kernel_ast.dump_kernel_ast(["m.c"], runner=_fake_run(framac_exc=timed_out))["status"] == "timeout"
    assert kernel_ast.dump_kernel_ast(["m.c"], runner=_fake_run(framac_exc=OSError("x")))["status"] == "tool_missing"


def test_dump_never_parses_acsl_and_loads_the_module_from_a_private_directory(tmp_path: Path) -> None:
    run = _fake_run({"schema": 1, "functions": [_raw("f", "m.c:1")]})
    res = kernel_ast.dump_kernel_ast(["m.c"], cppflags="-I.", cwd=tmp_path, runner=run)
    assert res["status"] == "ok" and res["functions"][0]["name"] == "f"
    framac = next(c for c in run.calls if c[0] == "frama-c")
    assert "-no-annot" in framac
    module = framac[framac.index("-load-module") + 1]
    assert str(tmp_path) not in module, "the compiled module must not live in the run directory"


def test_selftest_says_whether_the_dump_works() -> None:
    good = {"functions": [_raw("total", "s.c:1", loops=[_loop(loc="s.c:3", guard="i < n")])]}
    assert kernel_ast.selftest(runner=_fake_run(good))["ok"] is True
    assert kernel_ast.selftest(runner=_fake_run(compile_rc=2))["status"] == "compile_failed"
    assert kernel_ast.selftest(runner=_fake_run(compile_rc=2))["ok"] is False
    wrong = {"functions": [_raw("total", "s.c:1")]}
    assert kernel_ast.selftest(runner=_fake_run(wrong))["ok"] is False


# ---------------------------------------------------------------------------
# One function's facts
# ---------------------------------------------------------------------------

M_C = """int table[4];
int copy_buf(char *dst, const char *src, int n) {
  int i;
  for (i = 0; i < n; i++) dst[i] = src[i];
  g = n;
  return 0;
}
"""


def test_writes_reads_and_loop_of_a_copy_loop() -> None:
    raw = _raw(
        "copy_buf",
        "m.c:2",
        formals=[
            _formal("dst", "pointer", "char", char_like=True),
            _formal("src", "pointer", "char", char_like=True, const=True),
            _formal("n"),
        ],
        loops=[
            _loop(
                loc="m.c:4",
                writes=[
                    _write("*(dst + i)", "dst", values=["*(src + i)"]),
                    _write("i", "i", "local", False, ["i + 1"]),
                ],
                reads=[_access("*(src + i)", "src", loc="m.c:4")],
            )
        ],
        writes=[_access("*(dst + i)", "dst", loc="m.c:4"), _access("g", "g", "global", False, "m.c:5")],
        reads=[_access("*(src + i)", "src", loc="m.c:4")],
    )
    rec = _record(raw, M_C)
    loop = rec["loops"][0]
    assert loop["line"] == 4 and loop["header"] == "for (i = 0; i < n; i++)" and not loop["macro_expanded"]
    assert loop["scalars"] == [{"var": "i", "updates": ["i + 1"]}]
    assert loop["memory_writes"][0]["root"] == "dst"
    assert loop["read_only"] is False and loop["in_place"] == []
    assert {w["root"] for w in rec["writes"]} == {"dst", "g"}
    assert rec["may_alias"] == [
        {"a": "dst", "b": "src", "written": ["dst"], "reason": "same pointee type"},
    ]
    assert rec["features"]["loops"] and rec["features"]["pointer_len_params"]
    assert not rec["features"]["floats"] and not rec["features"]["recursion"]


def test_restrict_pointers_are_not_reported_as_aliased() -> None:
    raw = _raw(
        "f",
        "m.c:1",
        formals=[_formal("a", "pointer", "int", restrict=True), _formal("b", "pointer", "int")],
        writes=[_access("*a", "a")],
    )
    assert _record(raw, "int f(int *restrict a, int *b) { *a = *b; return 0; }\n")["may_alias"] == []


def test_different_pointee_types_are_not_aliased_unless_char_like() -> None:
    raw = _raw(
        "f",
        "m.c:1",
        formals=[
            _formal("a", "pointer", "int"),
            _formal("b", "pointer", "long"),
            _formal("c", "pointer", "char", True),
        ],
        writes=[_access("*a", "a")],
    )
    pairs = _record(raw, "int f(int *a, long *b, char *c) { *a = 1; return 0; }\n")["may_alias"]
    assert [(p["a"], p["b"]) for p in pairs] == [("a", "c")]


def test_loop_guidance_facts_for_sequenced_in_place_and_strided_loops() -> None:
    text = """void f(int *a, int *b, int n) {
  int i;
  for (i = 0; i < n; i++) a[i] = 0;
  for (i = 0; i < n; i++) b[i] = a[i];
  for (i = 0; i < n; i++) a[i] = a[i] + 1;
  for (i = 0; i < n; i++) { b[2 * i] = 0; }
  for (i = 0; i < n; i++) if (a[i]) break;
}
"""
    index_update = _write("i", "i", "local", False, ["i + 1"])
    loops = [
        _loop(0, loc="m.c:3", writes=[_write("*(a + i)", "a", values=["0"]), index_update]),
        _loop(
            1,
            loc="m.c:4",
            writes=[_write("*(b + i)", "b", values=["*(a + i)"]), index_update],
            reads=[_access("*(a + i)", "a")],
        ),
        _loop(
            2,
            loc="m.c:5",
            writes=[_write("*(a + i)", "a", values=["*(a + i) + 1"]), index_update],
            reads=[_access("*(a + i)", "a")],
        ),
        _loop(3, loc="m.c:6", writes=[_write("*(b + 2 * i)", "b", values=["0"]), index_update], strided_writes=["b"]),
        _loop(4, loc="m.c:7", writes=[index_update], reads=[_access("*(a + i)", "a")]),
    ]
    rec = _record(_raw("f", "m.c:1", formals=[_formal("a", "pointer", "int")], loops=loops), text)
    by_line = {loop["line"]: loop for loop in rec["loops"]}
    assert by_line[4]["prior_writers"] == [{"line": 3, "roots": ["a"]}]
    assert by_line[3]["prior_writers"] == []
    assert by_line[5]["in_place"] == ["a"]
    assert by_line[4]["in_place"] == []
    assert by_line[6]["strided_writes"] == ["b"]
    assert by_line[7]["read_only"] is True
    features = rec["features"]
    assert features["loop_reads_earlier_writes"] and features["in_place_loop"]
    assert features["strided_writes"] and features["read_only_loop"]


def test_a_struct_field_read_and_written_is_not_an_in_place_transform() -> None:
    text = "void f(struct s *d, int n) {\n  for (int i = 0; i < n; i++) d->total += i;\n}\n"
    loop = _loop(
        loc="m.c:2",
        writes=[_write("d->total", "d", values=["d->total + i"]), _write("i", "i", "local", False, ["i + 1"])],
        reads=[_access("d->total", "d")],
    )
    rec = _record(_raw("f", "m.c:1", loops=[loop]), text)
    assert rec["loops"][0]["in_place"] == []
    assert rec["features"]["in_place_loop"] is False


def test_nested_loops_are_not_reported_as_earlier_writers() -> None:
    text = "void f(int *a, int n) {\n  for (int i = 0; i < n; i++)\n    for (int j = 0; j < n; j++) a[j] = a[i];\n}\n"
    loops = [
        _loop(0, loc="m.c:2", writes=[_write("*(a + j)", "a")], reads=[_access("*(a + i)", "a")]),
        _loop(1, 0, loc="m.c:3", writes=[_write("*(a + j)", "a")], reads=[_access("*(a + i)", "a")]),
    ]
    rec = _record(_raw("f", "m.c:1", loops=loops), text)
    assert rec["loops"][1]["prior_writers"] == []


def test_macro_expanded_loop_is_flagged_from_the_real_source() -> None:
    text = "#define WALK(p, e) while ((p) < (e)) { (p)++; }\nvoid f(char *p, char *e) {\n  WALK(p, e);\n}\n"
    loop = _loop(
        loc="m.c:3", guard="p < e", writes=[_write("p", "p", "formal", False, ["p + 1"])], pointer_walkers=["p"]
    )
    rec = _record(_raw("f", "m.c:2", loops=[loop]), text)
    assert rec["loops"][0]["macro_expanded"] is True
    assert rec["loops"][0]["header"] == "WALK(p, e);"
    assert rec["features"]["macro_loops"] and rec["features"]["pointer_walk"]
    section = ff.render_section(rec, function="f")
    assert "macro expansion" in section and "guard `p < e`" in section


def test_writes_through_kernel_temporaries_resolve_to_the_formal() -> None:
    text = "int f(const char *p, char *out) {\n  char *q = out;\n  while (*p) *q++ = *p++;\n  return 0;\n}\n"
    loop = _loop(
        loc="m.c:3",
        guard="*p",
        writes=[
            _write("*tmp", "tmp", "local", True, ["*tmp_0"], temp=True),
            _write("p", "p", "formal", False, ["p + 1"]),
        ],
        reads=[_access("*tmp_0", "tmp_0", "local", temp=True), _access("*p", "p")],
        pointer_walkers=["p", "tmp"],
    )
    raw = _raw(
        "f",
        "m.c:1",
        formals=[_formal("p", "pointer", "char", True), _formal("out", "pointer", "char", True)],
        loops=[loop],
        writes=[_access("*tmp", "tmp", "local", temp=True)],
        derived_pointers=[
            {"local": "tmp", "formal": "out"},
            {"local": "tmp_0", "formal": "p"},
            {"local": "q", "formal": "out"},
        ],
    )
    rec = _record(raw, text)
    assert rec["writes"] == [{"lval": None, "root": "out", "root_kind": "formal", "through_pointer": True, "line": 9}]
    assert rec["loops"][0]["memory_writes"][0]["root"] == "out"
    assert rec["loops"][0]["pointer_walkers"] == ["p"]
    assert [p["written"] for p in rec["may_alias"]] == [["out"]]
    section = ff.render_section(rec, function="f")
    assert "through `out`" in section and "tmp" not in section


def test_private_local_arrays_are_not_frame_facts() -> None:
    raw = _raw("f", "m.c:1", writes=[_access("buf[i]", "buf", "local", False)])
    assert _record(raw, "void f(void) { int buf[4]; buf[0] = 1; }\n")["writes"] == []


def test_recursion_with_decreasing_argument() -> None:
    text = "int sum_rec(int n) {\n  if (n <= 0) return 0;\n  return n + sum_rec(n - 1);\n}\n"
    raw = _raw(
        "sum_rec",
        "m.c:1",
        formals=[_formal("n")],
        calls=[
            {
                "callee": "sum_rec",
                "kernel_name": "sum_rec",
                "indirect": False,
                "args": ["n - 1"],
                "arg_shapes": [{"position": 0, "arg": "n - 1", "shape": "minus_const", "formal": "n"}],
                "loc": "m.c:3",
                "in_loop": False,
            }
        ],
    )
    rec = _record(raw, text, cycle=["sum_rec"])
    assert rec["recursion"]["self"] is True
    assert rec["recursion"]["calls"][0]["decreasing"] == [
        {"arg": "n - 1", "shape": "minus_const", "formal": "n", "parameter": "n"}
    ]
    assert rec["features"]["recursion"] is True
    section = ff.render_section(rec, function="sum_rec")
    assert "needs `decreases`" in section and "parameter `n` gets `n - 1` (minus const)" in section


def test_mutual_recursion_names_the_callee_parameter() -> None:
    odd = _raw("odd", "m.c:2", formals=[_formal("k")])
    even = _raw(
        "even",
        "m.c:1",
        formals=[_formal("n")],
        calls=[
            {
                "callee": "odd",
                "kernel_name": "odd",
                "indirect": False,
                "args": ["n - 1"],
                "arg_shapes": [{"position": 0, "arg": "n - 1", "shape": "minus_const", "formal": "n"}],
                "loc": "m.c:1",
            }
        ],
    )
    rec = _record(even, "int even(int n) { return n ? odd(n - 1) : 1; }\n", cycle=["even", "odd"], others=[odd])
    assert rec["recursion"]["self"] is False and rec["recursion"]["cycle"] == ["even", "odd"]
    assert rec["recursion"]["calls"][0]["decreasing"][0]["parameter"] == "k"


def test_indirect_call_targets_come_from_eva() -> None:
    text = "int dispatch(int (*fp)(int), int x) {\n  return fp(x);\n}\n"
    calls = [{"indirect": True, "expr": "fp", "args": ["x"], "loc": "m.c:2", "in_loop": False}]
    raw = _raw("dispatch", "m.c:1", calls=calls)
    flows = {"status": "ok", "by_function": {}, "call_edges": {"dispatch": ["callee_abs"]}}
    rec = _record(raw, text, flows=flows)
    assert rec["calls"][0]["eva_targets"] == ["callee_abs"]
    assert rec["features"]["indirect_calls"] is True
    assert "resolved it to `callee_abs`" in ff.render_section(rec, function="dispatch")
    without_eva = _record(raw, text, flows={"status": "unavailable"})
    assert without_eva["calls"][0]["eva_targets"] is None
    assert "no Eva run" in ff.render_section(without_eva, function="dispatch")


def test_eva_record_cleans_temporaries_and_string_literal_bases() -> None:
    long_literal = '"' + "\\000" * 200 + '"'
    flow = {
        "writes": [
            {"loc": "tmp", "from": ["n"], "and_self": False},
            {"loc": "__retres", "from": ["n"], "and_self": False},
            {"loc": "r", "from": ["buf", "tmp"], "and_self": True},
            {"loc": "r", "from": ["buf", "ret"], "and_self": False},
        ],
        "inputs": [long_literal + "[0..3]", "input_buf[0..15]"],
    }
    rec = ff._eva_record(flow, "ok")
    assert rec["writes"] == [{"loc": "r", "from": ["buf", "ret"], "and_self": True}]
    assert rec["reads"] == ["<string literal>", "input_buf[0..15]"]
    assert ff._eva_record(None, "ok") == {"status": "not_reached"}
    assert ff._eva_record(None, "timeout") == {"status": "unavailable"}


def test_string_feature_needs_a_nul_test_or_a_string_call_not_just_char_pointers() -> None:
    text = "int f(const char *buf, const char *end) { return end - buf; }\n"
    formals = [_formal("buf", "pointer", "char", True), _formal("end", "pointer", "char", True)]
    plain = _raw("f", "m.c:1", formals=formals, features={"char_pointers": True})
    assert _record(plain, text)["features"]["strings"] is False
    tested = _raw("f", "m.c:1", formals=formals, features={"char_pointers": True, "nul_test": True})
    assert _record(tested, text)["features"]["strings"] is True
    called = _raw("f", "m.c:1", formals=formals, calls=[{"callee": "strlen", "kernel_name": "strlen", "loc": "m.c:1"}])
    assert _record(called, text)["features"]["strings"] is True
    alone = _raw("f", "m.c:1", formals=[_formal("s", "pointer", "char", True)])
    assert _record(alone, "int f(const char *s) { return 0; }\n")["features"]["strings"] is True


def test_assert_literal_feature_comes_from_the_source() -> None:
    text = 'int f(int s) {\n  switch (s) { default: assert(!"unreachable"); }\n  return 0;\n}\n'
    assert _record(_raw("f", "m.c:1"), text)["features"]["assert_literal"] is True
    assert _record(_raw("f", "m.c:1"), "int f(int s) { assert(s); return 0; }\n")["features"]["assert_literal"] is False


# ---------------------------------------------------------------------------
# Module documents and caching
# ---------------------------------------------------------------------------


def test_same_named_statics_stay_apart_and_harness_code_is_left_out(tmp_path: Path) -> None:
    (tmp_path / "workspace" / "work").mkdir(parents=True)
    a_c = tmp_path / "workspace" / "work" / "a.c"
    b_c = tmp_path / "workspace" / "work" / "b.c"
    a_c.write_text("static int helper(int x) {\n  return x;\n}\n", encoding="utf-8")
    b_c.write_text("static int helper(int y) {\n  y = y + 1;\n  return y;\n}\n", encoding="utf-8")
    doc = {
        "functions": [
            _raw("helper", f"{a_c.as_posix()}:1", static=True, formals=[_formal("x")]),
            _raw("helper", f"{b_c.as_posix()}:1", kernel_name="helper_0", static=True, formals=[_formal("y")]),
            _raw("eva_main", "workspace/harnesses/harness_m.c:3"),
        ]
    }
    flows = {"status": "ok", "by_function": {"helper_0": {"writes": [{"loc": "g", "from": [], "and_self": False}]}}}

    def fake_rel(path):
        if path.endswith("harness_m.c"):
            return None
        return Path(path).name

    original, ff.work_relative = ff.work_relative, fake_rel
    try:
        result = ff.build_module_facts("m", ["a.c"], "-I.", flows, runner=_fake_run(doc))
    finally:
        ff.work_relative = original
    assert sorted(result["functions"]) == ["a.c#helper", "b.c#helper"]
    assert result["functions"]["a.c#helper"]["formals"][0]["name"] == "x"
    assert result["functions"]["b.c#helper"]["formals"][0]["name"] == "y"
    assert result["functions"]["a.c#helper"]["eva"] == {"status": "not_reached"}
    assert result["functions"]["b.c#helper"]["eva"]["writes"][0]["loc"] == "g"
    assert result["status"] == "ok"


def test_callers_show_what_they_pass_and_what_they_checked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    Path("m.c").write_text(
        "int leaf(int n) {\n  return n;\n}\nint top(int k) {\n  if (k > 0) return leaf(k);\n  return 0;\n}\n"
        "void eva_main(void) {\n  top(1);\n}\n",
        encoding="utf-8",
    )
    leaf_call = {
        "callee": "leaf",
        "kernel_name": "leaf",
        "indirect": False,
        "args": ["k"],
        "arg_shapes": [],
        "conditions": ["k > 0"],
        "conditions_partial": False,
        "loc": "m.c:5",
        "in_loop": False,
    }
    top_call = {**leaf_call, "callee": "top", "kernel_name": "top", "args": ["1"], "conditions": []}
    doc = {
        "functions": [
            _raw("leaf", "m.c:1", formals=[_formal("n")]),
            _raw("top", "m.c:4", formals=[_formal("k")], calls=[leaf_call]),
            _raw("eva_main", "workspace/harnesses/harness_m.c:8", calls=[top_call]),
        ]
    }
    result = ff.build_module_facts("m", ["m.c"], "-I.", None, runner=_fake_run(doc))
    leaf, top = result["functions"]["m.c#leaf"], result["functions"]["m.c#top"]
    assert leaf["called_by"] == [{"caller": "top", "args": ["k"], "conditions": ["k > 0"], "in_loop": False}]
    assert top["called_by"] == [], "a harness is not a caller whose checks a contract can rely on"
    section = ff.render_section(leaf, function="leaf")
    assert "- `top`: `leaf(k)` when `k > 0`" in section
    assert "**Callers:** none in this module" in ff.render_section(top, function="top")


def test_ast_failure_gives_a_failed_document_without_functions() -> None:
    result = ff.build_module_facts("m", ["a.c"], "-I.", None, runner=_fake_run(compile_rc=2))
    assert result["status"] == "failed" and result["functions"] == {}
    assert result["ast"]["status"] == "compile_failed"


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("workspace/work/src/a.c", "src/a.c"),
        ("/framac-run/workspace/work/a.c", "a.c"),
        ("agents/prove-f/scratch/work/a.c", "a.c"),
        ("/target/src/a.c", "src/a.c"),
        ("src/a.c", "src/a.c"),
        ("workspace/harnesses/harness_m.c", None),
        ("FRAMAC_SHARE/libc/string.h", None),
        ("/usr/include/stdio.h", None),
    ],
)
def test_work_relative(path, expected) -> None:
    assert ff.work_relative(path) == expected


def test_generate_is_cached_by_content(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FRAMAC_CACHE", "on")
    monkeypatch.setenv("FRAMAC_IMAGE_ID", "test-image")
    Path("workspace/work").mkdir(parents=True)
    source = Path("workspace/work/m.c")
    source.write_text("int f(void) {\n  return 0;\n}\n", encoding="utf-8")
    report = Path("eva.json")
    report.write_text(json.dumps({"flows": {"status": "ok", "by_function": {}}}), encoding="utf-8")
    doc = {"functions": [_raw("f", "workspace/work/m.c:1")]}
    run = _fake_run(doc)
    out = Path("workspace/reports/facts/m.json")
    args = ("m", ["workspace/work/m.c"], "-I.", report, out)

    first = ff.generate(*args, runner=run)
    assert first["status"] == "ok" and first["cache"]["hit"] is False
    assert "workspace/work/m.c#f" not in json.loads(out.read_text())["functions"]
    assert "m.c#f" in json.loads(out.read_text())["functions"]
    frama_runs = sum(1 for c in run.calls if c[0] == "frama-c")

    out.unlink()
    second = ff.generate(*args, runner=run)
    assert second["cache"]["hit"] is True and out.is_file()
    assert sum(1 for c in run.calls if c[0] == "frama-c") == frama_runs

    source.write_text("int f(void) {\n  return 1;\n}\n", encoding="utf-8")
    assert ff.generate(*args, runner=run)["cache"]["hit"] is False

    report.write_text(json.dumps({"flows": {"status": "timeout", "by_function": {}}}), encoding="utf-8")
    assert ff.generate(*args, runner=run)["cache"]["hit"] is False


def test_a_failed_generation_is_not_cached(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FRAMAC_CACHE", "on")
    monkeypatch.setenv("FRAMAC_IMAGE_ID", "test-image")
    Path("m.c").write_text("int f(void);\n", encoding="utf-8")
    out = Path("facts.json")
    res = ff.generate("m", ["m.c"], "-I.", None, out, runner=_fake_run(compile_rc=1))
    assert res["status"] == "failed" and json.loads(out.read_text())["functions"] == {}
    good = _fake_run({"functions": [_raw("f", "m.c:1")]})
    assert ff.generate("m", ["m.c"], "-I.", None, out, runner=good)["cache"]["hit"] is False


# ---------------------------------------------------------------------------
# Conditional briefs
# ---------------------------------------------------------------------------


def test_render_conditionals_grammar() -> None:
    text = "a\n<!-- if: x -->\nb\n<!-- else -->\nc\n<!-- endif -->\nd"
    assert ff.render_conditionals(text, {"x": True}) == "a\nb\nd"
    assert ff.render_conditionals(text, {"x": False}) == "a\nc\nd"
    orred = "<!-- if: x or y -->\nb\n<!-- endif -->"
    assert ff.render_conditionals(orred, {"x": False, "y": True}) == "b"
    assert ff.render_conditionals(orred, {"x": False, "y": False}) == ""
    negated = "<!-- if: not x -->\nb\n<!-- endif -->"
    assert ff.render_conditionals(negated, {"x": False}) == "b"
    assert ff.render_conditionals(negated, {"x": True}) == ""
    nested = "<!-- if: x -->\n<!-- if: y -->\nb\n<!-- else -->\nc\n<!-- endif -->\n<!-- else -->\nd\n<!-- endif -->"
    assert ff.render_conditionals(nested, {"x": True, "y": False}) == "c"
    assert ff.render_conditionals(nested, {"x": False, "y": False}) == "d"


def test_without_facts_every_gate_is_open_except_the_facts_gate() -> None:
    text = "<!-- if: floats -->\nb\n<!-- endif -->\n<!-- if: facts -->\nf\n<!-- else -->\ne\n<!-- endif -->"
    assert ff.render_conditionals(text, None) == "b\ne"
    assert ff.render_conditionals(text, {"floats": False}) == "f"
    assert ff.render_conditionals("<!-- if: unheard_of -->\nb\n<!-- endif -->", {"floats": False}) == "b"


def _features(**on) -> dict:
    names = {
        name
        for expr in re.findall(r"^\s*<!--\s*if:\s*(.*?)\s*-->", BRIEF, re.MULTILINE)
        for name in re.findall(r"[a-z_]+", expr)
        if name not in ("or", "not")
    }
    out = dict.fromkeys(names, False)
    out.update(on)
    return out


def _brief_sections_for(**on) -> str:
    return ff.render_conditionals(BRIEF, _features(**on))


def test_brief_markers_balance_and_every_rendering_is_clean() -> None:
    assert BRIEF.count("<!-- endif -->") == len(re.findall(r"<!--\s*if:", BRIEF))
    for features in (None, _features(), _features(loops=True, recursion=True, strings=True)):
        rendered = ff.render_conditionals(BRIEF, features)
        assert not MARKER_RE.search(rendered)


def test_strict_rules_survive_for_the_plainest_function() -> None:
    rendered = _brief_sections_for()
    strict = rendered[rendered.index("## Strict Rules") : rendered.index("## Mandatory Synthesis Order")]
    original = BRIEF[BRIEF.index("## Strict Rules") : BRIEF.index("## Mandatory Synthesis Order")]
    assert strict == original
    for rule in (
        "Pure ACSL Annotations Only",
        "Function-Level Scope Isolation",
        "Trust Boundary & No Magic Bounds",
        "Named Clauses & Enforced Clause Order",
        "No Silent Unsoundness",
        "No Environment Probing",
    ):
        assert rule in rendered
    for always in (
        "The Dual-Oracle Verification Loop",
        "Exit Criteria and Result",
        "Function clause order",
        "Pre-state in `ensures`",
        "Smoke Test for Vacuous Contracts",
        "Keep Your Best Candidate, Not Your Last",
    ):
        assert always in rendered


@pytest.mark.parametrize(
    ("feature", "needle"),
    [
        ("strings", "Concrete Dual-Oracle C-String Predicates"),
        ("floats", "Floating-point comparisons"),
        ("unions", "Struct / union equality"),
        ("structs", "Padded-struct / union"),
        ("pointer_walk", "Pointer-Difference Equality Bridge"),
        ("pointer_walk", "ghost size_t idx"),
        ("indirect_calls", "For functions with indirect calls"),
        ("assert_literal", 'Unreachable `assert(!"string_literal")` Branches'),
        ("macro_loops", "Unannotatable File-Scope"),
        ("pointer_len_params", "Zero-length"),
        ("recursion", "Recursive function:"),
        ("recursion", "Inductive Lemmas Without Coq"),
        ("loops", "Distinguishing Establishment vs. Preservation Failures"),
        ("loops", "Loop counter upper bound"),
        ("loop_reads_earlier_writes", "over the **full finished range**"),
        ("in_place_loop", "In-place transforms"),
        ("strided_writes", "Doubled or strided index writes"),
        ("read_only_loop", "A loop that writes no memory still needs"),
    ],
)
def test_conditional_guidance_appears_only_with_its_feature(feature: str, needle: str) -> None:
    assert needle not in _brief_sections_for()
    on = {feature: True}
    if feature in ("loop_reads_earlier_writes", "in_place_loop", "strided_writes", "read_only_loop", "pointer_walk"):
        on["loops"] = True
    assert needle in _brief_sections_for(**on)
    assert needle in ff.render_conditionals(BRIEF, None), "without facts a prover keeps all guidance"


def test_step_a_only_asks_for_enumeration_without_facts() -> None:
    assert "Inspect every loop, pointer write" in ff.render_conditionals(BRIEF, None)
    with_facts = _brief_sections_for(facts=True)
    assert "Inspect every loop, pointer write" not in with_facts
    assert "Start from the **Deterministic Function Context**" in with_facts


def test_loopless_function_gets_the_loopless_template() -> None:
    plain = _brief_sections_for()
    assert "has no loop" in plain and "loop invariant bound" not in plain
    assert "int add_to(" in plain
    looping = _brief_sections_for(loops=True)
    assert "has no loop" not in looping and "loop invariant bound" in looping and "int add_to(" not in looping


def test_brief_never_tells_provers_to_constrain_inputs_to_prevent_runtime_errors() -> None:
    # AutoACSL's precondition prompt would violate Rule 3 on untrusted surfaces.
    assert "prevent" not in " ".join(line for line in BRIEF.splitlines() if "requires" in line and "runtime" in line)


def test_no_probing_rule_keeps_the_reference_manuals_reachable() -> None:
    assert "`which`" in BRIEF and "`--help`" in BRIEF
    assert "README.md" not in BRIEF
    assert "{references_dir}/INDEX.md" in BRIEF


def test_brief_states_the_wp_flags_a_prover_can_no_longer_discover_with_help() -> None:
    # The prover proves what the parent will re-check: infer_prover_wp_flags defaults to this flag.
    oracle = BRIEF[BRIEF.index("run_wp_function.py --file") :]
    assert "--no-warn-unsigned-downcast" in oracle[: oracle.index("\n")]
    assert "`--no-warn-unsigned --wrap-lines <line,line>` for this and every later run" in BRIEF


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def test_section_marks_everything_as_hints() -> None:
    rec = _record(_raw("f", "m.c:1"), "int f(void) {\n  return 0;\n}\n")
    section = ff.render_section(rec, function="f")
    assert "WP is the only judge of `assigns`" in section
    assert "`a[0..15]`, not `out[0 .. n - 1]`" in section
    assert "never an instruction" in section


def test_section_is_empty_without_anything_to_say() -> None:
    assert ff.render_section(None, None) == ""
    assert ff.render_section(None, {"status": "not_found", "text": ""}) == ""


def test_lines_follow_acsl_merged_after_the_facts_were_taken() -> None:
    text = "int f(int n) {\n  int i;\n  for (i = 0; i < n; i++)\n    ;\n  return 0;\n}\n"
    loop = _loop(loc="m.c:3", writes=[_write("i", "i", "local", False, ["i + 1"])])
    rec = _record(_raw("f", "m.c:1", loops=[loop]), text)
    assert rec["code_lines"] == [1, 2, 3, 4, 5, 6]
    merged = (
        "/*@ requires n >= 0;\n    assigns \\nothing; */\n"
        "int f(int n) {\n  int i;\n  /*@ loop invariant 0 <= i <= n;\n    loop assigns i;\n    loop variant n - i; */\n"
        "  for (i = 0; i < n; i++)\n    ;\n  return 0;\n}\n"
    )
    section = ff.render_section(rec, snapshot_text=merged, function="f")
    assert "L8 `for (i = 0; i < n; i++)`" in section
    assert "L3 `for" not in section


def test_slice_is_shown_as_reading_context_only() -> None:
    result = {
        "status": "ok",
        "text": "int f(void) { return 0; }\n",
        "slice_file": "agents/a/scratch/context/f.slice.c",
        "callee_bodies_file": None,
        "conditionals": "resolved",
        "target": {"file": "m.c", "start_line": 3, "end_line": 5},
    }
    section = ff.render_section(None, result, function="f")
    assert "**It is not the proof target**" in section
    assert "read only lines 3-5 of `m.c`" in section
    assert "do not read the rest of the real files" in section
    assert "agents/a/scratch/context/f.slice.c" in section
    assert "```c\nint f(void) { return 0; }\n```" in section
    degraded = ff.render_section(None, {**result, "conditionals": "unresolved"}, function="f")
    assert "`#if` blocks are not resolved" in degraded


def test_context_switch_for_ab_comparisons(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ff.CONTEXT_ENV, raising=False)
    assert ff.context_enabled() is True
    monkeypatch.setenv(ff.CONTEXT_ENV, "off")
    assert ff.context_enabled() is False


# ---------------------------------------------------------------------------
# The real tools, when they are installed
# ---------------------------------------------------------------------------

needs_framac = pytest.mark.skipif(
    shutil.which("frama-c") is None or shutil.which("ocamlfind") is None,
    reason="needs Frama-C and ocamlfind (inside the framac-pipeline image)",
)

REAL_SOURCE = """
#define WALK(p, e) while ((p) < (e)) { (p)++; }
typedef union { int i; char c[4]; } u_t;
static int table[4] = {1, 2, 3, 4};
int g_state;

int copy_buf(char *dst, const char *src, unsigned n) {
  unsigned i;
  for (i = 0; i < n; i++) dst[i] = src[i];
  g_state = (int)n;
  return 0;
}
int sum_rec(int n) {
  if (n <= 0) return 0;
  return n + sum_rec(n - 1);
}
const char *skip(const char *p, const char *e) {
  WALK(p, e);
  return p;
}
unsigned my_strlen(const char *s) {
  unsigned n = 0;
  while (*s++) n++;
  return n;
}
void two_loops(int *a, int *b, int n) {
  int i;
  for (i = 0; i < n; i++) a[i] = table[i & 3];
  for (i = 0; i < n; i++) b[i] = a[i] + 1;
}
void doubled(int *a, int n) {
  for (int i = 0; i < n; i++) { a[2 * i] = 0; a[2 * i + 1] = 0; }
}
int dispatch(int (*fp)(int), int x) {
  return fp(x);
}
int early(int *p, int n) {
  if (p == 0) return -1;
  for (int i = 0; i < n; i++) {
    if (p[i] < 0) return i;
  }
  return 0;
}
int use_union(u_t *u) {
  u->i = 3;
  return u->c[0];
}
double avg(const float *v, int n) {
  double s = 0.0;
  for (int i = 0; i < n; i++) s += v[i];
  return n ? s / n : 0.0;
}
"""


@needs_framac
def test_real_selftest() -> None:
    res = kernel_ast.selftest()
    assert res["ok"] is True, res


@needs_framac
def test_real_kernel_dump(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    Path("workspace/work").mkdir(parents=True)
    Path("workspace/work/m.c").write_text(REAL_SOURCE, encoding="utf-8")
    doc = ff.build_module_facts("m", ["workspace/work/m.c"], "-I.", None)
    assert doc["status"] == "partial", doc["ast"]
    fns = doc["functions"]

    copy_buf = fns["m.c#copy_buf"]
    assert copy_buf["loops"][0]["header"] == "for (i = 0; i < n; i++)"
    assert copy_buf["loops"][0]["guard"] == "i < n"
    assert {w["root"] for w in copy_buf["writes"]} == {"dst", "g_state"}
    assert copy_buf["may_alias"][0]["written"] == ["dst"]

    assert fns["m.c#sum_rec"]["recursion"]["calls"][0]["decreasing"][0]["shape"] == "minus_const"
    assert fns["m.c#skip"]["loops"][0]["macro_expanded"] is True
    assert fns["m.c#skip"]["features"]["pointer_walk"] is True
    assert fns["m.c#my_strlen"]["features"]["strings"] is True
    assert fns["m.c#copy_buf"]["features"]["strings"] is False

    two_loops = fns["m.c#two_loops"]
    assert two_loops["loops"][1]["prior_writers"][0]["roots"] == ["a"]
    assert fns["m.c#doubled"]["loops"][0]["strided_writes"] == ["a"]
    assert fns["m.c#dispatch"]["features"]["indirect_calls"] is True
    assert fns["m.c#use_union"]["features"]["unions"] is True
    assert fns["m.c#avg"]["features"]["floats"] is True

    early = fns["m.c#early"]
    assert early["loops"][0]["exits"][0]["kind"] == "return"
    assert [p["value"] for p in early["return_paths"]] == ["-1", "i", "0"]
    assert early["return_paths"][0]["conditions"] == ["p == (int *)0"]
    assert fns["m.c#sum_rec"]["called_by"] == [], "recursion is not a caller"


@needs_framac
def test_real_flows_from_a_saved_session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    Path("m.c").write_text(
        REAL_SOURCE + "\nvoid eva_main(void) {\n  char d[4]; char s[4] = {0};\n  copy_buf(d, s, 4);\n"
        "  dispatch(sum_rec, 1);\n}\n",
        encoding="utf-8",
    )
    res = eva.run_eva_on_slice(
        ["m.c"], "eva_main", Path("out"), slevel=10, allow_incomplete_recursion_specs=True, use_cache=False
    )
    assert res["flows"]["status"] == "ok", res["flows"]
    flow = res["flows"]["by_function"]["copy_buf"]
    assert {w["loc"] for w in flow["writes"]} == {"g_state", "d[0..3]"}
    assert "s[0..3]" in flow["inputs"]
    assert res["flows"]["call_edges"]["dispatch"] == ["sum_rec"]
