"""
Regressions for the stub, kernel-fact and frame-skeleton slice of docs/plans/regex-hardening-plan.md
(B1, B9, B12, C8, and the dedupe and removal items of workstream E that touch the same modules).

Every Frama-C wording, report row and dump record below was captured in framac-analysis:latest on
2026-11-11 (Frama-C's `-report-csv`, `Printer.pp_vdecl`, scripts/kernel_ast_dump.ml).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import acsl_ast
import c_definitions
import extract_references
import frame_skeleton
import function_facts as ff
import function_slice
import kernel_ast
import libc_gap_report
import mutation_check
import prover_candidates
import stub_check
import stub_gen
from acsl_ast import AcslSyntaxError

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# B1: stub_check.check_eva reads the report CSV
# ---------------------------------------------------------------------------

_CSV_HEADER = ("directory", "file", "line", "function", "property kind", "status", "property")
_HASH_PROTO = "int ml_hash(unsigned char const *data, size_t len, unsigned char out[32])"
_SUM_PROTO = "int ml_sum(char const *s, size_t n)"
_ID_PROTO = "int ml_id(int x)"
_VALID_DATA = r"valid_data: len > 0 ==> \valid_read(data + (0 .. len - 1))"
_VALID_OUT = r"valid_out: \valid(out + (0 .. 31))"
_VALID_S = r"valid_s: \valid_read(s + (0 .. n - 1))"
_EVA_DONE = "[eva] done for function fc_stub_smoke_main\n"


def _smoke_sigs():
    parsed = [stub_check.parse_proto(p) for p in (_HASH_PROTO, _SUM_PROTO, _ID_PROTO)]
    sigs = [s for s in parsed if s is not None]
    assert len(sigs) == len(parsed)
    _, lines_of = stub_check.smoke_source("mylib.h", sigs)
    line = {where: n for n, where in lines_of.items()}
    return sigs, line


def _csv(rows) -> str:
    return "".join("\t".join(str(c) for c in row) + "\n" for row in (_CSV_HEADER, *rows))


def _call_row(line, caller, callee, status, prop, file="fc_stub_smoke.c"):
    return (".", file, line, caller, f"precondition of {callee}", status, prop)


def _run_eva(monkeypatch, tmp_path, sigs, rows, log=_EVA_DONE, write_csv=True):
    seen: dict = {}

    def fake_run(cmd, cwd, timeout=0, env=None):
        seen["cmd"] = cmd
        if write_csv:
            target = Path(cwd) / cmd[cmd.index("-report-csv") + 1]
            target.write_text(_csv(rows), encoding="utf-8", newline="")
        return 0, log

    monkeypatch.setattr(stub_check, "_run", fake_run)
    res = stub_check.check_eva("mylib.h", sigs, tmp_path)
    return res, seen


def test_check_eva_reads_the_precondition_rows_of_the_report(monkeypatch, tmp_path):
    sigs, line = _smoke_sigs()
    rows = [
        _call_row(line["ml_hash", "ok"], "fc_smoke_ok_ml_hash", "ml_hash", "Valid", _VALID_DATA),
        _call_row(line["ml_hash", "ok"], "fc_smoke_ok_ml_hash", "ml_hash", "Valid", _VALID_OUT),
        _call_row(
            line["ml_hash", "short"], "fc_smoke_short_ml_hash", "ml_hash", "Invalid or unreachable", _VALID_DATA
        ),
        _call_row(line["ml_hash", "short"], "fc_smoke_short_ml_hash", "ml_hash", "Valid", _VALID_OUT),
        _call_row(line["ml_sum", "ok"], "fc_smoke_ok_ml_sum", "ml_sum", "Valid", _VALID_S),
        _call_row(line["ml_sum", "short"], "fc_smoke_short_ml_sum", "ml_sum", "Unknown", _VALID_S),
        # Rows that are not a smoke call's: a libc call the smoke program makes, and the contract itself.
        _call_row(line["ml_id", "ok"] - 1, "fc_smoke_ok_ml_id", "memset", "Unknown", "valid_s: valid_or_empty(s, n)"),
        (".", "mylib.h", 4, "ml_hash", "precondition", "Invalid or unreachable", _VALID_DATA),
    ]
    res, seen = _run_eva(monkeypatch, tmp_path, sigs, rows)
    assert "-report-csv" in seen["cmd"]
    assert res["status"] == "ok"
    fns = res["functions"]
    assert fns["ml_hash"]["status"] == "passed" and fns["ml_hash"]["valid_call_alarms"] == []
    assert fns["ml_hash"]["short_call_alarms"] == [f"{_VALID_DATA}: invalid or unreachable"]
    assert fns["ml_sum"]["status"] == "passed"
    assert fns["ml_sum"]["short_call_alarms"] == [f"{_VALID_S}: unknown"]
    assert fns["ml_id"] == {"valid_call_alarms": [], "status": "passed", "short_call": "not_applicable"}


def test_check_eva_reports_an_alarm_the_log_wording_would_hide(monkeypatch, tmp_path):
    """The log regex needs `function <f>: precondition ... got status`: the CSV row does not."""
    sigs, line = _smoke_sigs()
    rows = [
        _call_row(line["ml_hash", "ok"], "fc_smoke_ok_ml_hash", "ml_hash", "Unknown", r"\valid_read(data)"),
        _call_row(line["ml_hash", "short"], "fc_smoke_short_ml_hash", "ml_hash", "Valid", _VALID_OUT),
        _call_row(line["ml_sum", "ok"], "fc_smoke_ok_ml_sum", "ml_sum", "Valid", _VALID_S),
        _call_row(line["ml_sum", "short"], "fc_smoke_short_ml_sum", "ml_sum", "Valid", _VALID_S),
    ]
    res, _ = _run_eva(monkeypatch, tmp_path, sigs, rows)
    fns = res["functions"]
    assert fns["ml_hash"]["status"] == "valid_call_alarm"
    assert fns["ml_hash"]["valid_call_alarms"] == [r"\valid_read(data): unknown"]
    assert fns["ml_sum"]["status"] == "too_weak" and fns["ml_sum"]["short_call_alarms"] == []


def test_a_dead_short_call_does_not_count_as_caught(monkeypatch, tmp_path):
    sigs, line = _smoke_sigs()
    rows = [
        _call_row(line["ml_sum", "ok"], "fc_smoke_ok_ml_sum", "ml_sum", "Valid", _VALID_S),
        _call_row(line["ml_sum", "short"], "fc_smoke_short_ml_sum", "ml_sum", "Dead", _VALID_S),
    ]
    res, _ = _run_eva(monkeypatch, tmp_path, sigs, rows)
    assert res["functions"]["ml_sum"]["status"] == "too_weak"
    # The other way round, a valid call whose precondition is not Valid is reported, whatever the status.
    rows = [_call_row(line["ml_sum", "ok"], "fc_smoke_ok_ml_sum", "ml_sum", "Dead", _VALID_S)]
    res, _ = _run_eva(monkeypatch, tmp_path, sigs, rows)
    assert res["functions"]["ml_sum"]["valid_call_alarms"] == [f"{_VALID_S}: dead"]


def test_check_eva_fails_closed_without_the_report(monkeypatch, tmp_path):
    sigs, _ = _smoke_sigs()
    res, _ = _run_eva(monkeypatch, tmp_path, sigs, [], write_csv=False)
    assert res["status"] == "error" and "report" in res["reason"]


def test_a_log_warning_the_report_does_not_carry_is_still_an_alarm(monkeypatch, tmp_path):
    sigs, line = _smoke_sigs()
    log = (
        f"[eva:alarm] fc_stub_smoke.c:{line['ml_sum', 'ok']}: Warning: \n"
        "  function ml_sum, behavior big: precondition 'aligned_s' got status unknown.\n" + _EVA_DONE
    )
    rows = [_call_row(line["ml_sum", "short"], "fc_smoke_short_ml_sum", "ml_sum", "Unknown", _VALID_S)]
    res, _ = _run_eva(monkeypatch, tmp_path, sigs, rows, log=log)
    rec = res["functions"]["ml_sum"]
    assert rec["status"] == "valid_call_alarm"
    assert rec["valid_call_alarms"] == ["'aligned_s': unknown (Eva log only)"]


# ---------------------------------------------------------------------------
# B12: void return, struct members
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("proto", "expected"),
    [
        # As Printer.pp_vdecl prints them (the Phase 0 model's `proto`).
        ("void __atomic_clear(_Bool *ptr, int model)", True),
        ("extern void plain(void)", True),
        ("__inline static void quiet(int *p)", True),
        (" __attribute__((__noreturn__)) void die(int code)", True),
        ("void ( __attribute__((__noreturn__)) die3)(int code)", True),
        ("void *alloc(size_t n)", False),
        ("int *mk(void)", False),
        ("int ( __attribute__((__warn_unused_result__)) checked)(char const * restrict s, unsigned char out[32])", False),
        ("int (*getcb(int which))(int )", False),
        ("void (*signal_like(int sig, void (*handler)(int )))(int )", False),
        ("char const *name_of(struct ctx const *c)", False),
        # As a header writes them.
        ("static inline void f(int x);", True),
        ("_Noreturn void die(int code);", True),
        ("void __attribute__((noreturn)) die(int code)", True),
        ("void f(void) __attribute__((cold));", True),
        ("void const *f(void)", False),
        ("unsigned f(void)", False),
        # Not a prototype.
        ("int x", None),
        ("", None),
        ("void 'x", None),
    ],
)
def test_returns_void(proto, expected):
    assert c_definitions.returns_void(proto) is expected


def test_the_declarator_of_a_function_returning_a_function_pointer():
    code = "void (*signal_like(int sig, void (*handler)(int)))(int) { return handler; }\n"
    assert [f["name"] for f in c_definitions.extract_functions_from_code(code)] == ["signal_like"]
    code = "int (*getcb(int which))(int) { return 0; }\n"
    assert [f["name"] for f in c_definitions.extract_functions_from_code(code)] == ["getcb"]


@pytest.mark.parametrize(
    "proto",
    [
        "__inline static void quiet(int *p)",
        " __attribute__((__noreturn__)) void die(int *p)",
        "void ( __attribute__((__noreturn__)) die3)(int *p)",
    ],
)
def test_the_skeleton_of_a_void_function_has_no_result(proto):
    lines = stub_gen.skeleton_contract(proto, [{"name": "p", "kind": "pointer"}])
    assert lines[-1] == r"assigns *p \from p;"


def test_the_skeleton_of_a_function_returning_a_function_pointer_keeps_its_result():
    lines = stub_gen.skeleton_contract("void (*signal_like(int sig))(int )", [{"name": "sig", "kind": "value"}])
    assert lines[-1] == r"assigns \result \from sig;"
    assert any("result: a pointer" in line for line in lines)


def test_parse_proto_shares_the_void_test():
    sig = stub_check.parse_proto(" __attribute__((__noreturn__)) void die(int code)")
    assert sig is not None and sig["name"] == "die" and sig["returns_void"]
    sig = stub_check.parse_proto("__inline static void quiet(int *p)")
    assert sig is not None and sig["returns_void"]
    assert stub_check.call_lines(sig, "v", False)[-1] == "  quiet((int *)v_0);"
    sig = stub_check.parse_proto("void *alloc(size_t n)")
    assert sig is not None and not sig["returns_void"]


def test_struct_members_reads_every_declarator():
    text = """
    struct s {
        int a, b;               /* two members */
        char *p, q[4], **r;
        void (*cb)(int x, char *y);
        int (*table[4])(void);
        int x __attribute__((packed));
        __attribute__((aligned(8))) long y;
        struct in_addr addr;    // a struct-typed member
        unsigned f : 3, g;
        unsigned : 5;
        union { int u1; long u2; } un, *unp;
        struct { int anon; };
        struct inner { int deep; } in1;
        struct lonely { int z; };
        const char *const name;
    };
    """
    members = stub_check.struct_members(text)
    assert members["s"] == ["a", "b", "p", "q", "r", "cb", "table", "x", "y", "addr", "g", "un", "unp", "in1", "name"]
    assert members["inner"] == ["deep"] and members["lonely"] == ["z"]


def test_struct_members_fail_closed_on_a_header_that_does_not_tokenize(tmp_path):
    text = "struct a { int x; };\nchar c = 'x;\n"
    with pytest.raises(AcslSyntaxError):
        stub_check.struct_members(text)
    res = stub_check.check_shipped_layout("a.h", text, tmp_path, [], tmp_path)
    assert res["status"] == "error" and "unclosed" in res["reason"]


# ---------------------------------------------------------------------------
# kernel_ast.parse_location, stub_gen.decl_file
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("a.c:12", ("a.c", 12, 12)),
        ("a.c:12-15", ("a.c", 12, 15)),
        ("a.c:12:3", ("a.c", 12, 12)),
        ("a.c:12:3-9", ("a.c", 12, 12)),
        ("a.c:12-15:3-9", ("a.c", 12, 15)),
        ("a.c:12:3-15:9", ("a.c", 12, 15)),
        ("C:/src/a.c:12:3-15:9", ("C:/src/a.c", 12, 15)),
        ("/usr/include/x86_64-linux-gnu/bits/a.h:7", ("/usr/include/x86_64-linux-gnu/bits/a.h", 7, 7)),
    ],
)
def test_parse_location_reads_every_printed_form(text, expected):
    loc = kernel_ast.parse_location(text)
    assert (loc["file"], loc["line"], loc["end_line"]) == expected
    assert loc["known"] is True


@pytest.mark.parametrize("text", ["<generated by x>", "", None, "a.c", "a.c:", "a.c:12:x"])
def test_parse_location_marks_a_miss(text):
    loc = kernel_ast.parse_location(text)
    assert loc == {"file": "", "line": 0, "end_line": 0, "known": False}


def test_decl_file_uses_the_kernel_location_parser():
    assert not hasattr(stub_gen, "_LOC_RE")
    assert stub_gen.decl_file("/usr/include/json-c/json.h:12:3-15:9") == "/usr/include/json-c/json.h"
    assert stub_gen.decl_file("FRAMAC_SHARE/libc/string.h:164") == "FRAMAC_SHARE/libc/string.h"
    assert stub_gen.decl_file(" not a location ") == "not a location"
    assert stub_gen.classify({"decl": "/usr/include/json-c/json.h:12:3-15:9", "proto": "int f(void)"}) == (
        "host_header",
        "/usr/include/json-c/json.h",
    )


def test_a_function_whose_location_does_not_parse_is_reported(monkeypatch):
    raw = {"kernel_name": "f", "name": "f", "loc": "<generated>", "calls": []}
    monkeypatch.setattr(kernel_ast, "dump_kernel_ast", lambda *a, **k: {"status": "ok", "functions": [raw]})
    doc = ff.build_module_facts("m", ["m.c"], "-I.", {"status": "ok"})
    assert doc["functions"] == {}
    assert doc["warnings"] == ["f: kernel location '<generated>' not understood, function left out"]


# ---------------------------------------------------------------------------
# B9: kernel temporaries by flag
# ---------------------------------------------------------------------------

# scripts/kernel_ast_dump.ml on:
#   int user_retres(int *out, int __retres) {
#     if (__retres > 3) { *out = __retres; return 1; }
#     *out = ext(__retres) + ext(1);
#     return 0;
#   }
_USER_RETRES_C = (
    "int user_retres(int *out, int __retres) {\n"
    "  if (__retres > 3) {\n    *out = __retres;\n    return 1;\n  }\n"
    "  *out = ext(__retres) + ext(1);\n  return 0;\n}\n"
)
_INT_PTR = {"type": "int *", "kind": "pointer", "restrict": False, "pointee": "int", "pointee_canon": "int"}


def _user_retres_raw() -> dict:
    return {
        "kernel_name": "user_retres",
        "name": "user_retres",
        "loc": "t.c:1",
        "static": False,
        "variadic": False,
        "return_type": "int",
        "formals": [
            {"name": "out", **_INT_PTR, "pointee_const": False, "char_like": False},
            {"name": "__retres", "type": "int", "kind": "scalar", "restrict": False},
        ],
        "loops": [],
        "calls": [
            {
                "callee": "ext",
                "kernel_name": "ext",
                "indirect": False,
                "args": ["__retres"],
                "arg_shapes": [],
                "conditions": ["!(__retres > 3)"],
                "conditions_partial": False,
                "loc": "t.c:6",
                "in_loop": False,
            }
        ],
        "writes": [
            {
                "lval": "*out",
                "base": "out",
                "base_kind": "formal",
                "base_temp": False,
                "through_pointer": True,
                "loc": "t.c:3",
                "values": ["__retres", "tmp + tmp_0"],
            }
        ],
        "reads": [],
        "return_paths": [
            {"value": "1", "conditions": ["__retres > 3"], "conditions_partial": False, "in_loop": None, "loc": "t.c:7"},
            {
                "value": "0",
                "conditions": ["!(__retres > 3)"],
                "conditions_partial": False,
                "in_loop": None,
                "loc": "t.c:7",
            },
        ],
        "derived_pointers": [],
        "temps": ["tmp", "tmp_0", "__retres_6"],
        "truncated": False,
        "features": {},
    }


# The same dump on:
#   int user_tmp(const int *a, int n) {
#     int tmp = 0;
#     int tmp_1 = n;
#     for (int i = 0; i < tmp_1; i++) tmp += a[i];
#     return tmp > 100 ? 100 : tmp;
#   }
_USER_TMP_C = (
    "int user_tmp(const int *a, int n) {\n  int tmp = 0;\n  int tmp_1 = n;\n"
    "  for (int i = 0; i < tmp_1; i++) tmp += a[i];\n  return tmp > 100 ? 100 : tmp;\n}\n"
)


def _user_tmp_raw() -> dict:
    read = {
        "lval": "*(a + i)",
        "base": "a",
        "base_kind": "formal",
        "base_temp": False,
        "through_pointer": True,
        "loc": "t.c:4",
    }
    return {
        "kernel_name": "user_tmp",
        "name": "user_tmp",
        "loc": "t.c:1",
        "static": False,
        "variadic": False,
        "return_type": "int",
        "formals": [
            {
                "name": "a",
                "type": "int const *",
                "kind": "pointer",
                "restrict": False,
                "pointee": "int const",
                "pointee_canon": "int",
                "pointee_const": True,
                "char_like": False,
            },
            {"name": "n", "type": "int", "kind": "scalar", "restrict": False},
        ],
        "loops": [
            {
                "index": 0,
                "parent": None,
                "loc": "t.c:4",
                "guard": "i < tmp_1",
                "writes": [
                    {
                        "lval": "i",
                        "base": "i",
                        "base_kind": "local",
                        "base_temp": False,
                        "through_pointer": False,
                        "values": ["i + 1"],
                    },
                    {
                        "lval": "tmp",
                        "base": "tmp",
                        "base_kind": "local",
                        "base_temp": False,
                        "through_pointer": False,
                        "values": ["tmp + *(a + i)"],
                    },
                ],
                "reads": [read],
                "calls": [],
                "exits": [],
                "pointer_walkers": [],
                "strided_writes": [],
            }
        ],
        "calls": [],
        "writes": [],
        "reads": [read],
        "return_paths": [
            {"value": "100", "conditions": ["tmp > 100"], "conditions_partial": False, "in_loop": None, "loc": "t.c:5"},
            {"value": "tmp", "conditions": ["!(tmp > 100)"], "conditions_partial": False, "in_loop": None, "loc": "t.c:5"},
        ],
        "derived_pointers": [],
        "temps": ["tmp_0"],
        "truncated": False,
        "features": {},
    }


def _facts(raw: dict, text: str, flows: dict | None = None) -> dict:
    by_kernel = {raw["kernel_name"]: raw}
    return ff._function_record(raw, "t.c", text, None, by_kernel, flows or {"status": "ok", "by_function": {}})


def test_a_user_variable_named_like_a_temporary_is_kept():
    rec = _facts(_user_retres_raw(), _USER_RETRES_C)
    # `__retres` is the user's formal; `tmp + tmp_0` names the kernel's temporaries.
    assert rec["writes"][0]["values"] == ["__retres"]
    assert [p["conditions"] for p in rec["return_paths"]] == [["__retres > 3"], ["!(__retres > 3)"]]
    assert rec["kernel_temps"] == ["__retres_6", "tmp", "tmp_0"]

    rec = _facts(_user_tmp_raw(), _USER_TMP_C)
    loop = rec["loops"][0]
    assert loop["guard"] == "i < tmp_1"
    assert {s["var"]: s["updates"] for s in loop["scalars"]} == {"i": ["i + 1"], "tmp": ["tmp + *(a + i)"]}
    assert [(p["value"], p["conditions"]) for p in rec["return_paths"]] == [
        ("100", ["tmp > 100"]),
        ("tmp", ["!(tmp > 100)"]),
    ]


def test_a_dump_without_the_flag_falls_back_to_the_name_pattern():
    raw = _user_retres_raw()
    del raw["temps"]
    rec = _facts(raw, _USER_RETRES_C)
    assert rec["writes"][0].get("values") is None
    assert [p["conditions"] for p in rec["return_paths"]] == [[], []]
    assert rec["kernel_temps"] is None


def test_temp_names():
    assert kernel_ast.temp_names({"temps": ["tmp_0", "__retres"]}) == ["tmp_0", "__retres"]
    assert kernel_ast.temp_names({"temps": []}) == []
    assert kernel_ast.temp_names({}) is None
    assert kernel_ast.temp_names({"temps": "tmp"}) is None


def test_eva_locations_follow_the_flag():
    flows = {
        "status": "ok",
        "by_function": {
            "user_tmp": {
                "writes": [
                    {"loc": "tmp", "from": ["a[0..9]", "tmp_1", "tmp_0"]},
                    {"loc": "tmp_0", "from": ["tmp"]},
                ],
                "inputs": [],
            }
        },
    }
    rec = _facts(_user_tmp_raw(), _USER_TMP_C, flows)
    assert rec["eva"]["writes"] == [{"loc": "tmp", "from": ["a[0..9]", "tmp_1"], "and_self": False}]


def test_caller_conditions_follow_the_callers_flag():
    """`caller(int *p, int tmp)` calling `user_tmp(p, tmp)` under `tmp > 2`, and `die(1)` under a kernel `tmp_1`."""
    callee = _user_tmp_raw()
    die = {"kernel_name": "die", "name": "die", "loc": "t.c:20", "calls": [], "temps": []}
    caller = {
        "kernel_name": "caller",
        "name": "caller",
        "loc": "t.c:9",
        "temps": ["tmp_0", "tmp_1", "tmp_2", "__retres"],
        "calls": [
            {
                "callee": "user_tmp",
                "kernel_name": "user_tmp",
                "indirect": False,
                "args": ["(int const *)p", "tmp"],
                "conditions": ["tmp > 2"],
                "conditions_partial": False,
                "loc": "t.c:10",
                "in_loop": False,
            },
            {
                "callee": "die",
                "kernel_name": "die",
                "indirect": False,
                "args": ["1"],
                "conditions": ["!(tmp > 2)", "!(tmp_1)"],
                "conditions_partial": False,
                "loc": "t.c:12",
                "in_loop": False,
            },
        ],
    }
    records: dict[str, dict] = {
        "t.c#user_tmp": {"kernel_name": "user_tmp", "name": "user_tmp", "called_by": []},
        "t.c#die": {"kernel_name": "die", "name": "die", "called_by": []},
    }
    ff._link_callers([caller, callee, die], records)
    assert records["t.c#user_tmp"]["called_by"][0]["conditions"] == ["tmp > 2"]
    assert records["t.c#die"]["called_by"][0]["conditions"] == ["!(tmp > 2)"]
    lines: list[str] = []
    ff._render_callers(records["t.c#user_tmp"], lines)
    assert any("when `tmp > 2`" in line for line in lines)
    # Facts written before the flag: the conditions were not filtered when linked, the name pattern applies.
    old = {"name": "f", "called_by": [{"caller": "g", "args": ["x"], "conditions": ["tmp > 2", "x > 0"]}]}
    lines = []
    ff._render_callers(old, lines)
    assert any("when `x > 0`" in line for line in lines) and not any("tmp" in line for line in lines)


# ---------------------------------------------------------------------------
# C8: frame_skeleton offsets
# ---------------------------------------------------------------------------


def _loops(guard: str, var: str = "i") -> list[dict]:
    return [{"guard": guard, "scalars": [{"var": var, "updates": [f"{var} + 1"]}]}]


@pytest.mark.parametrize(
    ("guard", "expected"),
    [
        ("i < n", ("range", ("n", False))),
        ("i <= n", ("range", ("n", True))),
        ("i < 16", ("range", ("16", False))),
        ("i < 16U", ("range", ("16U", False))),
        ("n > i", ("range", ("n", False))),
        ("n >= i", ("range", ("n", True))),
        ("(unsigned long)i < len", ("range", ("len", False))),
        ("i < n && *(a + i) != 0", ("range", ("n", False))),
        ("*(a + i) != 0 && i < n", ("range", ("n", False))),
        ("(i < n) && ok", ("range", ("n", False))),
        # A bound that is not one identifier or literal is not entry-expressible as written.
        ("i < s->len", ("unknown", None)),
        ("i < n * 2", ("unknown", None)),
        ("i < n - 1", ("unknown", None)),
        ("i < (int)n", ("unknown", None)),
        ("n - 1 > i", ("unknown", None)),
        # Not a bound on `i`.
        ("i < n || more", ("unknown", None)),
        ("j + i < n", ("unknown", None)),
        ("p->i < n", ("unknown", None)),
        ("!(i < n)", ("unknown", None)),
        ("f(i < n)", ("unknown", None)),
        ("i != n", ("unknown", None)),
        ("i > n", ("unknown", None)),
        ("", ("unknown", None)),
    ],
)
def test_the_range_of_a_loop_index(guard, expected):
    assert frame_skeleton._classify_offset("i", _loops(guard)) == expected


def test_a_constant_offset_and_an_index_no_loop_moves():
    assert frame_skeleton._classify_offset("3", []) == ("const", 3)
    assert frame_skeleton._classify_offset("3UL", []) == ("const", 3)
    assert frame_skeleton._classify_offset("k", _loops("i < n")) == ("unknown", None)
    assert frame_skeleton._classify_offset("i + 1", _loops("i < n")) == ("unknown", None)


@pytest.mark.parametrize(
    ("lval", "expected"),
    [
        ("p", ("zero", "0")),
        ("*p", ("zero", "0")),
        ("*(p)", ("zero", "0")),
        ("*( p )", ("zero", "0")),
        ("*(p + i)", ("expr", "i")),
        ("p[i]", ("expr", "i")),
        ("p[a[i]]", ("expr", "a[i]")),
        ("p[a[i]].f", ("expr", "a[i]")),
        ("p[ i ][j]", ("expr", "i")),
        ("p->f", ("zero", "0")),
        ("(*p).f", ("zero", "0")),
        ("*(pp)", None),
        ("pp[i]", None),
        ("p[i", None),
        ("q[i]", None),
    ],
)
def test_the_offset_of_an_access(lval, expected):
    assert frame_skeleton._offset_expr(lval, "p") == expected


def test_a_reversed_guard_gives_a_region_not_an_operator():
    record = {
        "formals": [{"name": "dst", "kind": "pointer"}, {"name": "n", "kind": "scalar"}],
        "writes": [{"lval": "*(dst + i)", "root": "dst", "root_kind": "formal", "through_pointer": True}],
        "reads": [],
        "loops": [
            {
                "header": "for (i = 0; n > i; i++)",
                "guard": "n > i",
                "scalars": [{"var": "i", "updates": ["i + 1"]}],
                "memory_writes": [{"lval": "*(dst + i)", "root": "dst", "root_kind": "formal", "values": ["0"]}],
                "reads": [],
            }
        ],
    }
    out = frame_skeleton._compute(record)
    assert [a["loc"] for a in out["assigns"]] == ["*(dst + (0 .. n - 1))"]
    assert out["status"] == "ok"


# ---------------------------------------------------------------------------
# c_definitions: the comment-strip retry
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "broken",
    [
        "int f(void) { char c = 'x; return c; }\n",
        "int f(void) { return 0; }\n/* never closed\n",
        'const char *s = "never closed;\nint f(void) { return 0; }\n',
        "/*@ requires x;\nint f(int x) { return x; }\n",
        # The one shape the retry used to accept: a block comment opened inside a line comment. The
        # tokenizer is right (the `/*` is commented out), and the retry answered with every line
        # after the collapsed "comment" shifted.
        "// see /* the\nint f(void) { char c = 'x; return c; }\n// end */\nint g(void) { return 0; }\n",
    ],
)
def test_a_source_that_does_not_tokenize_is_an_error(broken):
    with pytest.raises(AcslSyntaxError):
        c_definitions.extract_functions_from_code(broken)
    with pytest.raises(AcslSyntaxError):
        c_definitions.extract_macro_definitions(broken)


# ---------------------------------------------------------------------------
# Low: prover_candidates, libc_gap_report, extract_references
# ---------------------------------------------------------------------------


def test_invalid_invariants_are_counted_by_suffix():
    report = {
        "status": "failed",
        "unproven_count": 3,
        "proven_count": 1,
        "proven_under_hyp_count": 0,
        "unproven_goals": [
            {"annotation": "typed_f_loop_invariant_bound_established"},
            {"annotation": "typed_f_loop_invariant_bound_PRESERVED"},
            {"annotation": "typed_f_preserved_len_ensures"},
            {"annotation": None},
        ],
    }
    assert prover_candidates._oracle_summary("wp", report)["invalid"] == 2


def test_one_assigns_pattern():
    assert libc_gap_report._ASSIGNS_RE is stub_gen._ASSIGNS_RE
    assert libc_gap_report.has_assigns(r"/*@ assigns \nothing; */")
    assert not libc_gap_report.has_assigns("/*@ requires no_assigns(x); // assigns later\n */")


@pytest.mark.parametrize("last", ["mix", "dim", "c", "C", "MIX", "I", "X", "  d", "cc", "lxxxx", "iiii", "vv"])
def test_a_page_whose_last_line_is_a_word_keeps_it(last):
    assert extract_references.clean_page(f"first line\n{last}\n") == ["first line", last.rstrip()]


@pytest.mark.parametrize("number", ["12", "  7  ", "iv", "xii", "  xxxix", "xliv", "lxxxviii"])
def test_a_page_number_footer_is_dropped(number):
    assert extract_references.clean_page(f"first line\n{number}\n") == ["first line"]


# ---------------------------------------------------------------------------
# M1: AST Foundations & Stubs (B2, B3, B10, C9, C10)
# ---------------------------------------------------------------------------


def test_iter_clauses_preserves_binder_semicolons():
    text = "/*@ ensures \\forall integer i; 0 <= i < n ==> a[i] == 0; ensures *out == 1; */"
    clauses = list(acsl_ast.iter_clauses(text))
    assert len(clauses) == 2
    assert clauses[0][0] == "ensures"
    assert clauses[0][2] == "\\forall integer i; 0 <= i < n ==> a[i] == 0"
    assert clauses[1][2] == "*out == 1"


def test_iter_clauses_handles_multiple_labels():
    text = "/*@ requires r1: r2: x > 0; */"
    clauses = list(acsl_ast.iter_clauses(text))
    assert len(clauses) == 1
    assert clauses[0][0] == "requires"
    assert clauses[0][1] == "r1, r2"
    assert clauses[0][2] == "x > 0"


def test_find_named_clause_with_iter_clauses():
    text = "/*@ requires r1: x > 0; ensures ok: \\result == 0; */"
    assert acsl_ast.find_named_clause(text, "r1") == "x > 0"
    assert acsl_ast.find_named_clause(text, "ok") == "\\result == 0"
    assert acsl_ast.find_named_clause(text, "missing") is None


def test_extract_frame_clauses_loop_assigns_distinction():
    text = "/*@ loop assigns i; assigns *p; */"
    frames = acsl_ast.extract_frame_clauses(text)
    assert len(frames["assigns"]) == 1
    assert frames["assigns"][0]["locs"] == ["*p"]


def test_mask_comments_and_literals_length_and_lines():
    s = 'int a = 1; /* block\ncomment */ char *p = "str;ing"; // line\n'
    m = acsl_ast.mask_comments_and_literals(s, acsl="blank")
    assert len(m) == len(s)
    assert m.count("\n") == s.count("\n")


def test_tokenize_tolerant_recovers_via_attributes():
    bad = "int f() {\n  char *p = 'unclosed;\n  return 0;\n}\n"
    clean, toks = function_slice._tokenize_tolerant(bad)
    assert any(t.text == "return" for t in toks)


def test_spec_mutants_preserves_acsl_equivalence():
    contract = "/*@ ensures a <= b <==> c <= d; */"
    mutants = dict(mutation_check.spec_mutants(contract, 4))
    assert "weaken-ensures-0" in mutants
    assert "<==>" in mutants["weaken-ensures-0"]
    assert "<=>" not in mutants["weaken-ensures-0"]


def test_impl_mutants_ignores_return_in_comments_and_strings():
    body = 'int f() { // return 0;\n  char *s = "return 1;"; return 42; }'
    mutants = dict(mutation_check.impl_mutants(body, 4))
    assert "return-42-to-43" in mutants
    assert "return-0-to-1" not in mutants
    assert "return-1-to-2" not in mutants


def test_logic_signature_label_list_and_bare_unsigned():
    tokens = acsl_ast.tokenize_c_acsl("/*@ logic integer f{L}(int x); */")
    errors = acsl_ast.find_unsound_acsl_keywords(tokens)
    assert any("forbidden C integer parameter 'int x'" in e for e in errors)

    tokens_bare = acsl_ast.tokenize_c_acsl("/*@ logic unsigned g(integer n); */")
    errors_bare = acsl_ast.find_unsound_acsl_keywords(tokens_bare)
    assert any("forbidden C integer type in ACSL logic signature 'logic unsigned'" in e for e in errors_bare)

    tokens_ptr = acsl_ast.tokenize_c_acsl("/*@ logic uintptr_t h(integer n); */")
    errors_ptr = acsl_ast.find_unsound_acsl_keywords(tokens_ptr)
    assert any("forbidden C integer type in ACSL logic signature 'logic uintptr_t'" in e for e in errors_ptr)

    tokens_ptrdiff = acsl_ast.tokenize_c_acsl("/*@ logic ptrdiff_t k(integer n); */")
    errors_ptrdiff = acsl_ast.find_unsound_acsl_keywords(tokens_ptrdiff)
    assert any("forbidden C integer type in ACSL logic signature 'logic ptrdiff_t'" in e for e in errors_ptrdiff)
