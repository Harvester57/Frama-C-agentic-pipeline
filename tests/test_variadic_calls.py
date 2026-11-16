"""
The variadic API gets dispatch cases from the call sites of the target's own programs
(scripts/variadic_calls.py, `api_harness.variadic_case`): minmea's `minmea_scan(sentence, format, ...)`
copies a field into the caller's buffer with no length check for the format `s` (CVE-2026-29974), and
the API harness never called it.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import api_harness as ah
import seed_harvest as sh
import validate_artifacts as va
import variadic_calls as vc

pytestmark = pytest.mark.unit

VA_SPARE = ah.spare_bytes(128)
SCAN_PROTO = "bool (const char *, const char *, ...)"
# Frama-C's model of `bool scan(const char *sentence, const char *format, ...)`. The sizes are those
# of the literals the callers pass: no contract for the sentence.
SCAN: dict[str, Any] = {
    "name": "scan",
    "file": "lib.c",
    "signature": "_Bool(char *,char *,void **)",
    "formals": [
        {"name": "sentence", "kind": "const_pointer"},
        {"name": "format", "kind": "const_pointer"},
        {"name": sh.VA_PARAMS, "kind": "const_pointer"},
    ],
    "param_sizes": {"0": {"min": 4, "max": 12, "sites": 3}, "1": {"min": 2, "max": 22, "sites": 3}},
}
S_SITE: dict[str, Any] = {"format": "s", "format_param": 1, "varargs": [{"type": "char[80]", "pass": "array"}]}
TF_SITE: dict[str, Any] = {
    "format": "tf",
    "format_param": 1,
    "varargs": [{"type": "int", "pass": "addr"}, {"type": "struct fl", "pass": "addr"}],
}


# --- clang's AST, as `clang -Xclang -ast-dump=json` prints the calls of minmea's tests ---------------


def _lit(text: str) -> dict:
    spelled = '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'
    literal = {"kind": "StringLiteral", "type": {"qualType": f"char[{len(text) + 1}]"}, "value": spelled}
    decay = {"kind": "ImplicitCastExpr", "castKind": "ArrayToPointerDecay", "inner": [literal]}
    return {"kind": "ImplicitCastExpr", "castKind": "NoOp", "type": {"qualType": "const char *"}, "inner": [decay]}


def _var(name: str, qual: str, desugared: str | None = None, decl: str = "VarDecl") -> dict:
    t = {"qualType": qual, **({"desugaredQualType": desugared} if desugared else {})}
    return {"kind": "DeclRefExpr", "type": t, "referencedDecl": {"kind": decl, "name": name, "type": t}}


def _addr(node: dict) -> dict:
    return {"kind": "UnaryOperator", "opcode": "&", "inner": [node]}


def _decay(node: dict) -> dict:
    return {"kind": "ImplicitCastExpr", "castKind": "ArrayToPointerDecay", "inner": [node]}


def _rvalue(node: dict) -> dict:
    return {"kind": "ImplicitCastExpr", "castKind": "LValueToRValue", "inner": [node]}


def _call(fn: str, proto: str, *args: dict) -> dict:
    ref = {"kind": "DeclRefExpr", "referencedDecl": {"kind": "FunctionDecl", "name": fn, "type": {"qualType": proto}}}
    callee = {"kind": "ImplicitCastExpr", "castKind": "FunctionToPointerDecay", "inner": [ref]}
    return {"kind": "CallExpr", "type": {"qualType": "bool"}, "inner": [callee, *args]}


def _tu(**functions: list[dict]) -> dict:
    decls = [
        {"kind": "FunctionDecl", "name": name, "inner": [{"kind": "CompoundStmt", "inner": calls}]}
        for name, calls in functions.items()
    ]
    return {"kind": "TranslationUnitDecl", "inner": decls}


def _scan(*args: dict) -> dict:
    return _call("scan", SCAN_PROTO, *args)


def test_decode_literal_reads_clangs_spelling():
    assert vc.decode_literal('"s"') == b"s"
    assert vc.decode_literal('"a\\"b\\\\c\\n\\001\\x7f"') == b'a"b\\c\n\x01\x7f'
    assert vc.decode_literal('"\\0001"') == b"\x001"  # at most three octal digits
    assert vc.decode_literal('L"wide"') is None and vc.decode_literal('"bad \\q"') is None
    assert vc.decode_literal(None) is None


def test_a_one_object_call_and_a_multi_object_call_are_harvested():
    tree = _tu(
        test_s=[_scan(_lit("foo,bar,baz"), _lit("s"), _decay(_var("value", "char[80]")))],
        test_many=[
            _scan(
                _rvalue(_var("sentence", "const char *")),
                _lit("tTf"),
                _addr(_var("type", "char[6]")),
                _addr(_var("t", "struct minmea_time")),
                _addr(_var("f", "minmea_float_t", "struct minmea_float")),
            )
        ],
    )
    sites, skipped = vc.call_sites(tree, {"scan": 2})
    assert skipped == []
    assert sites[0] == {
        "function": "scan",
        "caller": "test_s",
        "format": "s",
        "format_param": 1,
        "varargs": [{"type": "char[80]", "pass": "array"}],
        "data": {"0": b"foo,bar,baz".hex()},
    }
    # A sentence that is no literal gives no seed data; the objects keep their declared types, with
    # a typedef resolved as clang resolved it.
    assert sites[1]["caller"] == "test_many" and sites[1]["data"] == {}
    assert sites[1]["varargs"] == [
        {"type": "char[6]", "pass": "addr"},
        {"type": "struct minmea_time", "pass": "addr"},
        {"type": "struct minmea_float", "pass": "addr"},
    ]


@pytest.mark.parametrize(
    ("args", "why"),
    [
        ([_lit("x"), _rvalue(_var("fmt", "const char *")), _addr(_var("c", "char"))], "format is not a string literal"),
        ([_lit("x"), _lit("s"), _rvalue(_var("p", "char *"))], "a pointer variable of type 'char *'"),
        ([_lit("x"), _lit("i"), _rvalue(_var("n", "int"))], "a value of type 'int'"),
        (
            [_lit("x"), _lit("s"), _addr({"kind": "ArraySubscriptExpr", "type": {"qualType": "char"}})],
            "one element of an array",
        ),
        ([_lit("x"), _lit("s"), {"kind": "CStyleCastExpr", "type": {"qualType": "char *"}}], "CStyleCastExpr"),
        ([_lit("x"), _lit("p"), _addr(_var("p", "char *"))], "holds a pointer"),
        ([_lit("x"), _lit("s"), _decay(_var("v", "char[n]"))], "no constant size"),
        ([_lit("x"), _lit("t"), _addr(_var("u", "struct (unnamed struct at t.c:3:5)"))], "unnamed type"),
        ([_lit("x"), _lit("s"), _lit("literal")], "a string literal"),
    ],
)
def test_call_sites_whose_objects_cannot_be_sized_are_skipped_with_the_reason(args, why):
    sites, skipped = vc.call_sites(_tu(t=[_scan(*args)]), {"scan": 2})
    assert sites == [] and len(skipped) == 1
    assert why in skipped[0]["why"] and skipped[0]["caller"] == "t"


def test_a_member_and_a_parameter_are_declared_objects():
    member = {"kind": "MemberExpr", "name": "time", "type": {"qualType": "struct minmea_time"}}
    tree = _tu(t=[_scan(_lit("x"), _lit("Ti"), _addr(member), _addr(_var("out", "int", decl="ParmVarDecl")))])
    sites, skipped = vc.call_sites(tree, {"scan": 2})
    assert skipped == []
    assert [v["type"] for v in sites[0]["varargs"]] == ["struct minmea_time", "int"]


def test_a_function_whose_last_fixed_parameter_is_no_const_string_has_no_format():
    calls = [
        _call("emit", "int (int, ...)", _rvalue(_var("n", "int")), _addr(_var("x", "int"))),
        _call("put", "int (char *, ...)", _lit("s"), _addr(_var("x", "int"))),
        _call("scan", "bool (const char *, ...)", _lit("s"), _addr(_var("x", "int"))),
        {**_scan(_lit("x"), _lit("s"), _decay(_var("v", "char[8]"))), "containsErrors": True},
    ]
    sites, skipped = vc.call_sites(_tu(t=calls), {"emit": 1, "put": 1, "scan": 2})
    assert sites == []
    assert ["not `const char *`" in s["why"] for s in skipped[:2]] == [True, True]
    assert "1 fixed parameters where it is called, 2 in the model" in skipped[2]["why"]
    assert "could not type" in skipped[3]["why"]
    assert vc.is_format_type("const char *restrict") and not vc.is_format_type("char *const")
    assert vc.prototype("int (*(const char *, ...))(int)") is None


# --- the harvest: functions, sources, report --------------------------------------------------------


def _model(**extra: dict) -> dict:
    functions = {"lib.c#scan": SCAN, **{f"lib.c#{n}": rec for n, rec in extra.items()}}
    return {"status": "ok", "generated_at": "t0", "entry_points": sorted(functions), "functions": functions}


def _capture() -> dict:
    compiles = [
        {"source": "lib.c", "flags": ["-DLIB"], "system_flags": []},
        {"source": "tests.c", "flags": ["-I", "include", "-DT=1"], "system_flags": ["-isystem", "/usr/include/x"]},
        {"source": "example.c", "flags": [], "system_flags": []},
        {"source": "gone.c", "flags": [], "system_flags": []},
    ]
    units = {
        "liblib.a": {"kind": "static_lib", "files": ["lib.c"]},
        "tests": {"kind": "executable", "files": ["tests.c", "gone.c"], "test": True},
        "example": {"kind": "executable", "files": ["example.c"]},
    }
    return {"status": "ok", "compiles": compiles, "units": units}


def _work(tmp_path: Path) -> Path:
    work = tmp_path / "workspace" / "work"
    work.mkdir(parents=True)
    (work / "lib.c").write_text("bool scan(const char *s, const char *f, ...) { return scan(s, f); }\n")
    (work / "tests.c").write_text('void t(void) { scan("a", "s", v); }\n')
    (work / "example.c").write_text("int main(void) { return 0; } /* no rescan here */\n")
    return work


def _clang_writes(ast: Any, returncode: int = 0, stderr: str = "", seen: list[dict] | None = None):
    """A fake `runner` that writes `ast` (JSON of a tree, or raw bytes) where harvest sends clang's stdout."""
    data = ast if isinstance(ast, bytes) else json.dumps(ast).encode()

    def fake_run(argv, **kwargs):
        if seen is not None:
            seen.append({"argv": list(argv), **kwargs})
        kwargs["stdout"].write(data)
        return subprocess.CompletedProcess(argv, returncode, stdout=None, stderr=stderr)

    return fake_run


def _leftovers(work: Path) -> list[str]:
    """Files harvest left beside the work tree (its temporary AST files go there)."""
    return sorted(p.name for p in work.parent.iterdir() if p.name != work.name)


def test_harvest_reads_the_programs_sources_and_groups_the_call_sites(tmp_path, monkeypatch):
    monkeypatch.delenv("FRAMAC_SNAPSHOT_DIR", raising=False)
    work = _work(tmp_path)
    tree = _tu(
        test_s=[
            _scan(_lit("foo,bar,baz"), _lit("s"), _decay(_var("value", "char[80]"))),
            _scan(_lit(",bar"), _lit("s"), _decay(_var("value", "char[80]"))),
            _scan(_lit("foo,bar,baz"), _lit("s"), _decay(_var("value", "char[80]"))),
            _scan(_lit("x"), _lit("s"), _decay(_var("small", "char[8]"))),
            _scan(_lit("x"), _lit("s"), _rvalue(_var("p", "char *"))),
        ]
    )
    seen: list[dict] = []
    report = vc.harvest(_model(), _capture(), work, clang="clang", runner=_clang_writes(tree, seen=seen))
    assert list(va.validate_variadic_calls(report)) == []
    assert report["status"] == "ok" and report["model_generated_at"] == "t0"
    # The library's own source is not a caller; a program that does not name the function is not parsed.
    assert report["sources"] == {
        "scanned": ["tests.c"],
        "library": 1,
        "not_calling": 1,
        "missing": ["gone.c"],
        "failed": {},
        "over_cap": 0,
        "over_budget": 0,
    }
    assert report["warnings"] == [] and _leftovers(work) == []
    argv = seen[0]["argv"]
    assert len(seen) == 1 and argv[-1] == str(work / "tests.c") and "-ast-dump=json" in argv
    # clang's stdout goes to a file, not a pipe, with the limit of one source.
    assert "capture_output" not in seen[0] and seen[0]["timeout"] == vc.CLANG_TIMEOUT_S
    assert argv[argv.index("-I") + 1] == (work.resolve() / "include").as_posix() and "-DT=1" in argv
    scan = report["functions"]["scan"]
    assert (scan["key"], scan["fixed"], scan["sites"], scan["unusable"]) == ("lib.c#scan", 2, 5, 1)
    assert [(c["varargs"][0]["type"], c["sites"]) for c in scan["cases"]] == [("char[80]", 3), ("char[8]", 1)]
    assert scan["cases"][0]["data"] == [{"0": b"foo,bar,baz".hex()}, {"0": b",bar".hex()}]
    assert scan["cases"][0]["callers"] == ["tests.c:test_s"]
    assert scan["skipped"] == [
        {"source": "tests.c", "caller": "test_s", "why": scan["skipped"][0]["why"]},
    ] and "pointer variable" in scan["skipped"][0]["why"]


def test_harvest_statuses_are_reasons_not_failures(tmp_path):
    work = _work(tmp_path)
    assert vc.harvest(None, _capture(), work)["status"] == "no_model"
    plain = {"status": "ok", "entry_points": ["lib.c#f"], "functions": {"lib.c#f": {"signature": "int(int)"}}}
    assert vc.harvest(plain, _capture(), work, clang="clang")["status"] == "no_variadic_api"
    assert vc.harvest(_model(), None, work, clang="clang")["status"] == "no_capture"

    no_ast = _clang_writes(b"", returncode=1, stderr="fatal error")
    report = vc.harvest(_model(), _capture(), work, clang="clang", runner=no_ast)
    assert report["status"] == "ok" and list(report["sources"]["failed"]) == ["tests.c"]
    assert report["functions"]["scan"]["cases"] == []
    assert list(va.validate_variadic_calls(report)) == []
    assert _leftovers(work) == []


def _many_callers(tmp_path: Path, n: int) -> tuple[Path, dict]:
    """A work tree whose `n` test sources all call `scan`, and their capture."""
    work = tmp_path / "workspace" / "work"
    work.mkdir(parents=True)
    names = [f"t{i}.c" for i in range(n)]
    for name in names:
        (work / name).write_text('void t(void) { scan("a", "s", v); }\n')
    compiles = [{"source": name, "flags": [], "system_flags": []} for name in names]
    return work, {"status": "ok", "compiles": compiles, "units": {"t": {"kind": "executable", "files": names}}}


def test_the_harvest_budget_cuts_the_last_clang_and_counts_the_sources_left_out(tmp_path, monkeypatch):
    monkeypatch.delenv("FRAMAC_SNAPSHOT_DIR", raising=False)
    work, capture = _many_callers(tmp_path, 5)
    tree = _tu(t=[_scan(_lit("x"), _lit("s"), _decay(_var("v", "char[8]")))])
    now = [1000.0]
    timeouts: list[float] = []

    def slow_clang(argv, **kwargs):
        # Each clang takes 400 s of the (fake, monotonic) clock; one cut short by the budget times out.
        timeouts.append(kwargs["timeout"])
        now[0] += 400
        if kwargs["timeout"] < vc.CLANG_TIMEOUT_S:
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
        kwargs["stdout"].write(json.dumps(tree).encode())
        return subprocess.CompletedProcess(argv, 0, stdout=None, stderr="")

    assert vc.HARVEST_BUDGET_S == 900
    report = vc.harvest(_model(), capture, work, clang="clang", runner=slow_clang, clock=lambda: now[0])
    assert list(va.validate_variadic_calls(report)) == []
    # 900 s: two full clangs (0 -> 400 -> 800), a third limited to the 100 s left, then nothing.
    assert timeouts == [300, 300, 100]
    src = report["sources"]
    assert report["status"] == "ok" and src["scanned"] == ["t0.c", "t1.c"] and src["over_budget"] == 2
    assert list(src["failed"]) == ["t2.c"] and "left of the harvest budget" in src["failed"]["t2.c"]
    assert src["over_cap"] == 0
    # The harvest keeps the cases it has, and says once what it left out.
    assert report["functions"]["scan"]["cases"][0]["sites"] == 2
    assert [w for w in report["warnings"] if "budget" in w] == report["warnings"]
    assert len(report["warnings"]) == 1 and report["warnings"][0].startswith("2 source(s)")
    assert _leftovers(work) == []


def test_an_ast_above_the_cap_is_refused_without_being_read(tmp_path, monkeypatch):
    monkeypatch.delenv("FRAMAC_SNAPSHOT_DIR", raising=False)
    work = _work(tmp_path)
    tree = _tu(t=[_scan(_lit("x"), _lit("s"), _decay(_var("v", "char[8]")))])
    data = json.dumps(tree).encode()
    dirs: list[Any] = []
    temporary_file, real_load = vc.tempfile.TemporaryFile, json.load

    def where(*a, **k):
        dirs.append(k.get("dir"))
        return temporary_file(*a, **k)

    def no_load(*a, **k):
        raise AssertionError("an AST above the cap was read")

    monkeypatch.setattr(vc.tempfile, "TemporaryFile", where)
    monkeypatch.setattr(vc, "MAX_AST_BYTES", len(data) - 1)
    monkeypatch.setattr(vc.json, "load", no_load)
    report = vc.harvest(_model(), _capture(), work, clang="clang", runner=_clang_writes(data))
    assert list(va.validate_variadic_calls(report)) == []
    assert report["status"] == "ok" and report["sources"]["scanned"] == []
    why = report["sources"]["failed"]["tests.c"]
    assert f"{len(data)} bytes, above the cap of {len(data) - 1}" in why and "not read" in why
    # The temporary file is in the workspace (the run's disk), and is gone afterwards.
    assert dirs == [work.parent] and _leftovers(work) == []
    # At the cap itself, the AST is read.
    monkeypatch.setattr(vc.json, "load", real_load)
    monkeypatch.setattr(vc, "MAX_AST_BYTES", len(data))
    report = vc.harvest(_model(), _capture(), work, clang="clang", runner=_clang_writes(data))
    assert report["sources"]["scanned"] == ["tests.c"] and report["sources"]["failed"] == {}


def test_the_temporary_ast_is_removed_when_clang_fails(tmp_path, monkeypatch):
    monkeypatch.delenv("FRAMAC_SNAPSHOT_DIR", raising=False)
    work = _work(tmp_path)

    def times_out(argv, **kwargs):
        kwargs["stdout"].write(b'{"kind": "Transl')
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    for runner in (times_out, _clang_writes(b'{"kind": "Transl'), _clang_writes(b"[1]")):
        report = vc.harvest(_model(), _capture(), work, clang="clang", runner=runner)
        assert report["status"] == "ok" and list(report["sources"]["failed"]) == ["tests.c"]
        assert _leftovers(work) == []
    # A timeout within the limit of one source is not blamed on the budget.
    report = vc.harvest(_model(), _capture(), work, clang="clang", runner=times_out)
    assert "TimeoutExpired" in report["sources"]["failed"]["tests.c"]
    assert "budget" not in report["sources"]["failed"]["tests.c"]


def test_harvest_through_a_real_process_writing_to_the_file(tmp_path, monkeypatch):
    # The default runner is subprocess.run: a child process (Python standing in for clang) writes
    # the AST straight into the temporary file harvest gives it.
    monkeypatch.delenv("FRAMAC_SNAPSHOT_DIR", raising=False)
    work = _work(tmp_path)
    ast = tmp_path / "ast.json"
    ast.write_text(json.dumps(_tu(t=[_scan(_lit("x"), _lit("s"), _decay(_var("v", "char[8]")))])))
    child = "import shutil, sys; shutil.copyfileobj(open(sys.argv[1], 'rb'), sys.stdout.buffer)"

    def as_python(argv, **kwargs):
        return subprocess.run([sys.executable, "-c", child, str(ast)], **kwargs)

    report = vc.harvest(_model(), _capture(), work, clang="clang", runner=as_python)
    assert report["status"] == "ok" and report["sources"]["scanned"] == ["tests.c"]
    assert [c["varargs"][0]["type"] for c in report["functions"]["scan"]["cases"]] == ["char[8]"]
    assert _leftovers(work) == []


def test_only_variadic_api_entry_points_are_harvested():
    model = _model(
        plain={"signature": "int(int)"},
        dots={"name": "dots", "signature": "int(char *,...)", "formals": [{"name": "f", "kind": "const_pointer"}]},
        hidden={"signature": "int(char *,...)", "static": True},
    )
    assert vc.variadic_api(model) == {
        "dots": {"key": "lib.c#dots", "fixed": 1, "file": None},
        "scan": {"key": "lib.c#scan", "fixed": 2, "file": "lib.c"},
    }


def test_ensure_harvests_when_the_report_is_missing_or_from_another_model(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    reports = tmp_path / "workspace" / "reports"
    reports.mkdir(parents=True)
    model_path, report_path = reports / "phase0_model.json", reports / "variadic_calls.json"
    model_path.write_text(json.dumps(_model()))
    runs: list[str] = []

    def fake_harvest(model, capture, *a, **k):
        runs.append(model["generated_at"])
        case = {**S_SITE, "sites": 1, "callers": ["tests.c:t"], "data": []}
        entry = {"key": "lib.c#scan", "fixed": 2, "sites": 1, "unusable": 0, "cases": [case], "skipped": []}
        return {
            "schema_version": 1,
            "generated_at": "now",
            "status": "ok",
            "model_generated_at": model["generated_at"],
            "functions": {"scan": entry},
            "warnings": [],
        }

    monkeypatch.setattr(vc, "harvest", fake_harvest)
    got = vc.ensure(report_path, model_path, reports / "build_capture.json")
    assert runs == ["t0"] and got["scan"][0]["format"] == "s"
    assert json.loads(report_path.read_text())["warnings"] == []  # the report matches its schema
    assert vc.ensure(report_path, model_path, reports / "build_capture.json") == got and runs == ["t0"]
    model_path.write_text(json.dumps({**_model(), "generated_at": "t1"}))
    vc.ensure(report_path, model_path, reports / "build_capture.json")
    assert runs == ["t0", "t1"]


@pytest.mark.skipif(shutil.which("clang") is None, reason="needs clang")
def test_harvest_with_clang_itself(tmp_path, monkeypatch):
    monkeypatch.delenv("FRAMAC_SNAPSHOT_DIR", raising=False)
    work = tmp_path / "workspace" / "work"
    work.mkdir(parents=True)
    (work / "lib.h").write_text(
        "#include <stdbool.h>\nstruct fl { int value; int scale; };\n"
        "bool scan(const char *sentence, const char *format, ...);\n"
    )
    (work / "tests.c").write_text(
        '#include "lib.h"\n#define LEN 80\n'
        "void test_s(void) { char value[LEN]; scan(\"foo,bar\", \"s\", value); }\n"
        "void test_many(const char *sentence) { int t; struct fl f; scan(sentence, \"tf\", &t, &f); }\n"
        "void test_fmt(const char *fmt) { char c; scan(\"x\", fmt, &c); }\n"
        "void test_ptr(char *out) { scan(\"x\", \"s\", out); }\n"
    )
    capture = {
        "status": "ok",
        "compiles": [{"source": "tests.c", "flags": [], "system_flags": []}],
        "units": {"tests": {"kind": "executable", "files": ["tests.c"]}},
    }
    report = vc.harvest(_model(), capture, work)
    assert list(va.validate_variadic_calls(report)) == []
    scan = report["functions"]["scan"]
    assert [(c["format"], c["varargs"]) for c in scan["cases"]] == [
        ("s", S_SITE["varargs"]),
        ("tf", TF_SITE["varargs"]),
    ]
    assert scan["cases"][0]["data"] == [{"0": b"foo,bar".hex()}]
    assert sorted(s["caller"] for s in scan["skipped"]) == ["test_fmt", "test_ptr"]


# --- the dispatch cases -----------------------------------------------------------------------------


def test_the_case_fixes_the_format_and_declares_the_call_sites_objects():
    stmt, layout, why = ah.variadic_case("scan", SCAN, S_SITE, VA_SPARE)
    assert why is None and stmt is not None and layout is not None
    # The object of the call site, at its size, on the stack, zeroed, passed by name.
    assert "char c0v0[80]; memset(c0v0, 0, sizeof(c0v0));" in stmt and "static char c0v0" not in stmt
    # The format is the literal; the sentence is the rest of the input, NUL-terminated.
    assert '(void)scan((char *)c0a0, (char *)"s", c0v0);' in stmt
    assert f"static unsigned char c0a0[{VA_SPARE}]" in stmt and "c0a0[rest_n] = 0;" in stmt
    assert layout == {
        "kind": "variadic",
        "calls": ["scan"],
        "slots": [],
        "rest": {"call": 0, "param": 0, "kind": "string"},
        "format": "s",
        "format_param": 1,
        "varargs": [{"type": "char[80]", "pass": "array"}],
    }


def test_no_input_byte_reaches_the_format_or_an_object():
    stmt, layout, _ = ah.variadic_case("scan", SCAN, TF_SITE, VA_SPARE)
    assert stmt is not None and layout is not None
    assert "int c0v0; memset(&c0v0, 0, sizeof(c0v0));" in stmt
    assert "struct fl c0v1; memset(&c0v1, 0, sizeof(c0v1));" in stmt
    assert '(void)scan((char *)c0a0, (char *)"tf", &c0v0, &c0v1);' in stmt
    # The only copy from the input goes into the sentence's own buffer.
    assert re.findall(r"memcpy\((\w+)", stmt) == ["c0a0"]
    assert not re.search(r"memcpy\(&?c0v", stmt)
    call = stmt[stmt.index("(void)scan(") :]
    assert "fuzz_buf" not in call and "FRAMAC_FUZZ_COPY" not in call
    assert layout["slots"] == []


def test_the_format_literal_is_written_with_the_generators_own_escapes():
    assert ah.c_string_literal(b'a"b\\c%d\n\xff??)') == '"a\\042b\\134c%d\\012\\377\\077\\077)"'
    site = {**S_SITE, "format": 'c;"\n'}
    stmt, layout, _ = ah.variadic_case("scan", SCAN, site, VA_SPARE)
    assert stmt is not None and layout is not None
    assert '(char *)"c;\\042\\012"' in stmt and "\n" not in stmt
    assert layout["format"] == 'c;"\n'


@pytest.mark.parametrize(
    ("site", "why"),
    [
        ({**S_SITE, "format_param": 0}, "not the last fixed parameter"),
        ({**S_SITE, "varargs": [{"type": "char *", "pass": "addr"}]}, "cannot be declared"),
        ({**S_SITE, "varargs": [{"type": "int", "pass": "array"}]}, "cannot be declared"),
        ({**S_SITE, "varargs": [{"type": "char[80]", "pass": "value"}]}, "cannot be declared"),
        ({"format_param": 1, "varargs": []}, "no format literal"),
    ],
)
def test_a_call_site_the_generator_cannot_spell_makes_no_case(site, why):
    stmt, layout, got = ah.variadic_case("scan", SCAN, site, VA_SPARE)
    assert stmt is None and layout is None and why in str(got)


def test_a_format_that_is_not_a_const_string_in_the_model_makes_no_case():
    writable = {**SCAN, "formals": [SCAN["formals"][0], {"name": "format", "kind": "pointer"}, SCAN["formals"][2]]}
    assert "not `const char *`" in str(ah.variadic_case("scan", writable, S_SITE, VA_SPARE)[2])
    declared = {"signature": "int(char *,unsigned long,char *,...)", "formals": []}
    stmt, layout, _ = ah.variadic_case("emit", declared, {**S_SITE, "format_param": 2}, VA_SPARE)
    assert stmt is not None and layout is not None
    # A declaration (`...` in the signature): the other fixed parameters follow the usual rules.
    assert '(char *)(fuzz_buf + fuzz_off), (unsigned long)(fuzz_len - fuzz_off), (char *)"s", c0v0);' in stmt
    assert layout["rest"] == {"call": 0, "param": 0, "kind": "bytes"}


def _lib_dag(*names: str) -> dict:
    functions = {n: {"name": n, "file": "lib.c", "is_static": False, "module": "lib"} for n in names}
    return {
        "module_kind": "link_unit",
        "modules": {"lib": {"candidate_entry_points": list(names), "functions": list(names)}},
        "functions": functions,
    }


def _lib_model() -> dict:
    functions = {"lib.c#a": {"signature": "void(int)", "formals": [{"name": "x", "kind": "value"}]}, "lib.c#scan": SCAN}
    return {"status": "ok", "functions": functions}


def test_plan_gives_one_case_per_format_and_objects_after_the_single_cases():
    sites = [TF_SITE, S_SITE, dict(S_SITE), {**S_SITE, "varargs": [{"type": "char *", "pass": "addr"}]}]
    p = ah.plan(_lib_dag("scan", "a"), _lib_model(), "lib", "lib", 128, variadic={"scan": sites})
    assert p["entries"] == ["scan", "a"] and p["skipped"] == {}
    # The single case first, then the call site that passes an array, each format once.
    assert [(lay["kind"], lay.get("format"), lay["selector"]) for lay in p["layouts"]] == [
        ("single", None, 0),
        ("variadic", "s", 1),
        ("variadic", "tf", 2),
    ]
    assert all(lay["entry"] == "scan" for lay in p["layouts"][1:])
    assert [d["why"] for d in p["variadic_dropped"]] == [
        "variable argument 0: an object of type 'char *' cannot be declared"
    ]


def test_a_variadic_function_without_a_usable_call_site_stays_skipped():
    dag, model = _lib_dag("a", "scan"), _lib_model()
    p = ah.plan(dag, model, "lib", "lib", 128)
    assert p["entries"] == ["a"] and p["skipped"] == {"scan": ah.NO_VARIADIC_SITE}
    assert p["skipped"]["scan"].startswith("variadic")
    bad = {**S_SITE, "varargs": [{"type": "char *", "pass": "addr"}]}
    p = ah.plan(dag, model, "lib", "lib", 128, variadic={"scan": [bad], "other": [S_SITE]})
    assert p["skipped"]["scan"].startswith(ah.NO_VARIADIC_SITE) and "cannot be declared" in p["skipped"]["scan"]
    assert all("scan(" not in c for c in p["cases"])


def test_the_cap_keeps_the_call_sites_that_pass_a_buffer():
    scalars = [{**TF_SITE, "format": f"f{i}"} for i in range(ah.MAX_VARIADIC_CASES + 3)]
    p = ah.plan(_lib_dag("scan"), _lib_model(), "lib", "lib", 128, variadic={"scan": [*scalars, S_SITE]})
    formats = [lay["format"] for lay in p["layouts"]]
    assert len(formats) == ah.MAX_VARIADIC_CASES and formats[0] == "s"
    assert len(p["variadic_dropped"]) == 4 and "more than 32 variadic cases" in p["variadic_dropped"][0]["why"]
    assert p["skipped"] == {}


def test_the_selector_cap_skips_the_function_only_when_no_case_is_left():
    sites = [{**TF_SITE, "format": f"f{i}"} for i in range(3)]
    p = ah.plan(_lib_dag("a", "scan"), _lib_model(), "lib", "lib", 128, variadic={"scan": sites}, reserve=253)
    assert [lay["kind"] for lay in p["layouts"]] == ["single", "variadic"] and p["skipped"] == {}
    assert [d["format"] for d in p["variadic_dropped"]] == ["f1", "f2"]
    p = ah.plan(_lib_dag("a", "scan"), _lib_model(), "lib", "lib", 128, variadic={"scan": sites}, reserve=254)
    assert p["skipped"] == {"scan": "more than 255 cases"}


def test_a_variadic_function_takes_no_part_in_sequences():
    trace = [{"fn": "scan", "addrs": {"0": "10"}}, {"fn": "scan", "addrs": {"0": "10"}}]
    p = ah.plan(_lib_dag("scan"), _lib_model(), "lib", "lib", 128, traces=[trace], variadic={"scan": [S_SITE]})
    assert [lay["kind"] for lay in p["layouts"]] == ["variadic"]


# --- the sidecar, the compile probe and the seeds ---------------------------------------------------


def _generate(tmp_path: Path, monkeypatch, **kw: Any) -> tuple[dict, dict]:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "lib.c").write_text("/* lib */\n")
    reports = tmp_path / "workspace" / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    dag = {
        **_lib_dag("a", "scan"),
        "schema_version": 1,
        "callgraph_source": "frama_c",
        "warnings": [],
    }
    for rec in dag["functions"].values():
        rec.update(internal_callees=[], internal_callers=[])
    (reports / "callgraph_dag.json").write_text(json.dumps(dag))
    (reports / "phase0_model.json").write_text(json.dumps(_lib_model()))
    result = ah.generate(
        module="lib",
        header=None,
        max_input_size=128,
        cppflags="-I.",
        out_dir=tmp_path / "workspace" / "harnesses",
        unit="lib",
        auto_prelude=False,
        dag_path=reports / "callgraph_dag.json",
        model_path=reports / "phase0_model.json",
        traces_path=tmp_path / "none" / "traces.jsonl",
        **kw,
    )
    side = json.loads((tmp_path / "workspace" / "harnesses" / "harness_lib.json").read_text())
    return result, side


def _report(*cases: dict) -> dict:
    entry = {"key": "lib.c#scan", "fixed": 2, "sites": len(cases), "unusable": 0, "cases": list(cases), "skipped": []}
    return {
        "schema_version": 1,
        "generated_at": "now",
        "status": "ok",
        "model_generated_at": None,
        "functions": {"scan": entry},
        "warnings": [],
    }


def test_generate_reads_the_report_and_the_seeds_come_from_the_literal_data(tmp_path, monkeypatch):
    reports = tmp_path / "workspace" / "reports"
    reports.mkdir(parents=True)
    data = [{"0": b"foo,bar,baz".hex()}, {"0": b",bar".hex()}]
    report = _report(
        {**S_SITE, "sites": 3, "callers": ["tests.c:test_s"], "data": data},
        {**TF_SITE, "sites": 1, "callers": ["tests.c:test_tf"], "data": []},
        {**S_SITE, "varargs": [{"type": "char[8]", "pass": "array"}], "sites": 1, "callers": [], "data": [data[0]]},
    )
    assert list(va.validate_variadic_calls(report)) == []
    (reports / "variadic_calls.json").write_text(json.dumps(report))
    result, side = _generate(tmp_path, monkeypatch, probe=False, struct_layouts={})
    assert list(va.validate_sidecar(side, "lib")) == []
    assert side["api_skipped"] == {} and "api_variadic_dropped" not in side
    assert result["api_entries"] == 2 and result["api_variadic"] == 3 and result["api_cases"] == 4
    kinds = [(lay["kind"], lay.get("format"), [v["type"] for v in lay.get("varargs", [])]) for lay in side["api_cases"]]
    assert kinds == [
        ("single", None, []),
        ("variadic", "s", ["char[80]"]),
        ("variadic", "s", ["char[8]"]),
        ("variadic", "tf", ["int", "struct fl"]),
    ]
    harness = (tmp_path / "workspace" / "harnesses" / "harness_lib.c").read_text()
    assert '(char *)"s", c0v0);' in harness and "char c0v0[8];" in harness
    # Seeds without any recorded call: the selector, then the call sites' literal sentence, for every
    # case of that format.
    out = sh.write([])
    assert out["modules"]["lib"]["status"] == "ok" and out["modules"]["lib"]["seeds"] == 4
    seeds = sorted(p.read_bytes() for p in Path("workspace/seeds/lib").iterdir())
    assert seeds == [b"\x01,bar", b"\x01foo,bar,baz", b"\x02,bar", b"\x02foo,bar,baz"]
    summary = json.loads(Path("workspace/reports/seeds/lib.json").read_text())
    assert summary["cases"]["1"] == {"functions": ["scan"], "kind": "variadic", "from_calls": 2}
    assert summary["cases"]["3"]["from_calls"] == 0


def test_layout_seeds_round_trip_the_variadic_layout():
    stmt, layout, _ = ah.variadic_case("scan", SCAN, S_SITE, VA_SPARE)
    assert stmt is not None and layout is not None
    lay = {**layout, "selector": 7, "entry": "scan"}
    cases = {
        "scan": [
            {**S_SITE, "data": [{"0": b"a,b".hex()}, {"0": b"a,b".hex()}, {}]},
            {**TF_SITE, "data": [{"0": b"other format".hex()}]},
        ],
        "other": [{**S_SITE, "data": [{"0": b"other function".hex()}]}],
    }
    assert sh.layout_seeds([lay], [], [], cases) == {7: [b"\x07a,b"]}
    assert sh.layout_seeds([lay], [], []) == {7: []}
    # The seed is what the case reads: its selector, no slot, the sentence as the rest.
    bindings = sh.case_bindings(stmt, {"scan"})
    assert bindings["slots"] == [] and layout["rest"]["kind"] == "string"


def test_write_skips_a_module_with_no_record_and_no_call_site_data(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    hd = Path("workspace/harnesses")
    hd.mkdir(parents=True)
    _, layout, _ = ah.variadic_case("scan", SCAN, S_SITE, VA_SPARE)
    assert layout is not None
    (hd / "harness_lib.json").write_text(json.dumps({"max_input_size": 64, "api_cases": [{**layout, "selector": 0}]}))
    (hd / "harness_lib.c").write_text("/* not parsed */")
    out = sh.write([])
    assert out["modules"]["lib"]["status"] == "skipped" and "no records" in out["modules"]["lib"]["reason"]


def test_a_case_the_compiler_refuses_is_dropped_and_the_function_stays_called(tmp_path, monkeypatch):
    import generate_harness

    out = tmp_path / "workspace" / "harnesses"
    out.mkdir(parents=True)

    def fake_generate(**kw):
        cases = list(kw["dispatch_cases"])
        harness = out / f"harness_{kw['module_name']}.c"
        harness.write_text("".join(f"    case {i}U: {{ {c} }} break;\n" for i, c in enumerate(cases)))
        meta = out / f"harness_{kw['module_name']}.json"
        meta.write_text(json.dumps({"module": kw["module_name"], "dispatch_cases": cases}))
        return {"harness_file": str(harness), "harness_meta": str(meta), "cppflags": ""}

    def probe(harness_c, cppflags, clang=None):
        lines = Path(harness_c).read_text().splitlines()
        return {i: "harness_lib.c:3: error: unknown type" for i, t in enumerate(lines) if "struct fl" in t}, []

    monkeypatch.setattr(generate_harness, "generate_module_harness", fake_generate)
    monkeypatch.setattr(ah, "probe_layouts", lambda *a, **k: None)
    monkeypatch.setattr(ah, "probe_cases", probe)
    result, side = _generate(tmp_path, monkeypatch, variadic={"scan": [S_SITE, TF_SITE]})
    assert [(lay["kind"], lay.get("format"), lay["selector"]) for lay in side["api_cases"]] == [
        ("single", None, 0),
        ("variadic", "s", 1),
    ]
    assert side["api_skipped"] == {} and result["api_skipped"] == {} and result["api_entries"] == 2
    assert side["api_variadic_dropped"] == [
        {
            "entry": "scan",
            "format": "tf",
            "varargs": TF_SITE["varargs"],
            "why": "the case does not compile with the target's headers: harness_lib.c:3: error: unknown type",
        }
    ]
    # With every case of the function refused, it is skipped, with the compiler's reason.
    monkeypatch.setattr(
        ah, "probe_cases", lambda h, c, clang=None: ({i: "e" for i, t in enumerate(Path(h).read_text().splitlines()) if "scan(" in t}, [])
    )
    result, side = _generate(tmp_path, monkeypatch, variadic={"scan": [S_SITE, TF_SITE]})
    assert [lay["kind"] for lay in side["api_cases"]] == ["single"]
    assert "does not compile" in side["api_skipped"]["scan"] and len(side["api_variadic_dropped"]) == 2


def test_the_schemas_know_the_report_and_the_case_kind():
    assert va.get_schema("variadic_calls")["$comment"]
    assert va.PHASE0_COMMANDS["variadic-calls"] is va.validate_variadic_calls
    assert any(path.endswith("variadic_calls.json") for path, _ in va.PHASE0_ARTIFACTS)
    _, layout, _ = ah.variadic_case("scan", SCAN, S_SITE, VA_SPARE)
    assert layout is not None
    case = {**layout, "selector": 0, "entry": "scan"}
    schema = va.get_schema("harness_sidecar")
    one_case = {"definitions": schema["definitions"], "$ref": "#/definitions/variadic_case"}
    assert va.Validator(one_case).errors(case) == []
    assert va.Validator(one_case).errors({**case, "varargs": [{"type": "int", "pass": "value"}]})
    assert va.Validator(one_case).errors({k: v for k, v in case.items() if k != "format"})
