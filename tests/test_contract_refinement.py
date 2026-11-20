"""
Contract refinement probe (scripts/contract_refinement.py): probe generation text in, text out, the
verdict rules on recorded WP outcomes, and (`integration`, needs Frama-C) the probe run for real on a
refinement, a weakening and a postcondition that follows from `assigns`.
"""

from __future__ import annotations

import dataclasses
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import contract_refinement as CR
from conftest import ANALYSIS_IMAGE, ROOT, require_docker_images

needs_framac = pytest.mark.skipif(shutil.which("frama-c") is None, reason="Frama-C not available")

PROBE_HEADER = (
    "#ifndef API_H\n#define API_H\n#define LIMIT 100\n"
    "/*@ predicate small(integer x) = -LIMIT <= x <= LIMIT; */\n"
    "int add(int a, int b);\n#endif\n"
)


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


def _contract(tmp_path: Path, name: str, text: str, function: str, header: str | None = None) -> CR.FunctionContract:
    if header is not None:
        _write(tmp_path, "api.h", header)
    return CR.read_function_contract(_write(tmp_path, name, text), function, "-I.")


@pytest.mark.unit
def test_reads_pieces_from_the_definition_and_the_header(tmp_path):
    header = PROBE_HEADER.replace("int add(int a, int b);", "/*@ requires small(a); */\nint add(int a, int b);")
    c = _contract(
        tmp_path,
        "api.c",
        '#include "api.h"\n/*@ assigns \\nothing;\n  @ ensures \\result == a + b; */\nint add(int a, int b) { return a + b; }\n',
        "add",
        header,
    )
    assert [Path(p.file).name for p in c.pieces] == ["api.c", "api.h"]
    assert c.pieces[0].line == 2 and c.pieces[1].line == 5
    assert c.definition is not None and c.definition.declarator == "int add(int a, int b)"
    assert c.definition.params == ["a", "b"] and c.returns_void is False
    assert CR.FunctionContract.from_dict(json.loads(json.dumps(c.to_dict()))) == c


@pytest.mark.unit
def test_frame_only_probe_of_a_split_contract_has_no_empty_annotation(tmp_path):
    # libmnl run 1, mnl_nlmsg_batch_is_empty: requires/assigns on the header prototype, the only ensures on
    # the definition. Stripping the ensures left `/*@ */`, which Frama-C refuses.
    header = PROBE_HEADER.replace(
        "int add(int a, int b);", "/*@ requires small(a);\n    assigns \\nothing; */\nint add(int a, int b);"
    )
    c = _contract(
        tmp_path,
        "api.c",
        '#include "api.h"\n/*@ ensures \\result == a + b; */\nint add(int a, int b) { return a + b; }\n',
        "add",
        header,
    )
    assert c.definition is not None
    unit = CR.build_probe(c.pieces, c.pieces, c.definition, False, Path("/w/api.c"), "add", strip_given_ensures=True)
    comments = re.findall(r"/\*@(.*?)\*/", unit.text, flags=re.S)
    assert comments and all(body.strip() for body in comments)
    assert unit.text.count("int add__given(int a, int b);") == 2
    assert unit.text.count("ensures") == 1


@pytest.mark.unit
def test_probe_text_declares_given_and_defines_probe_with_labels(tmp_path):
    new = _contract(
        tmp_path,
        "new.c",
        '#include "api.h"\n/*@ requires small(a) && small(b);\n    assigns \\nothing;\n'
        "    ensures \\result >= a + b - 1; */\nstatic inline int add(int a, int b) { return a + b; }\n",
        "add",
        PROBE_HEADER,
    )
    old = _contract(
        tmp_path,
        "old.c",
        '#include "api.h"\n/*@ requires small(a) && small(b);\n    assigns \\nothing;\n'
        "    ensures r: \\result == a + b; */\nstatic inline int add(int a, int b) { return a + b; }\n",
        "add",
    )
    assert old.definition is not None
    unit = CR.build_probe(new.pieces, old.pieces, old.definition, False, Path("/w/new.c"), "add")
    text = unit.text
    assert text.startswith('#include "/w/new.c"\n')
    assert "int add__given(int a, int b);" in text and "static" not in text and "inline" not in text
    assert "int add__probe(int a, int b);" in text
    assert "int add__probe(int a, int b)\n{\n  return add__given(a, b);\n}" in text
    # Every requires / ensures carries its own name; an existing name stays behind it.
    assert "requires fcprobe_1: small(a)" in text and "ensures fcprobe_4: r: \\result == a + b;" in text
    assert "assigns \\nothing;" in text and "fcprobe_" not in text.split("assigns")[1][:12]
    # The labels map back to the clause as written in its own file.
    assert unit.labels[4].contract == "probe" and unit.labels[4].kind == "ensures"
    assert Path(unit.labels[4].file).name == "old.c" and unit.labels[4].line == 4
    assert unit.labels[4].text == "\\result == a + b"
    assert unit.ensures_labels == [4]
    assert [r.kind for r in unit.by_kind["assigns"]] == ["assigns"]


@pytest.mark.unit
def test_void_function_calls_without_return(tmp_path):
    c = _contract(
        tmp_path,
        "s.c",
        "/*@ requires \\valid(p); assigns *p; ensures *p == v; */\nvoid set(int *p, int v) { *p = v; }\n",
        "set",
    )
    assert c.definition is not None and c.returns_void is True
    unit = CR.build_probe(c.pieces, c.pieces, c.definition, True, Path("/w/s.c"), "set")
    assert "{\n  set__given(p, v);\n}" in unit.text


@pytest.mark.unit
def test_strip_ensures_keeps_behaviors_and_fills_an_emptied_one():
    body = CR.acsl_body(
        "/*@ requires r: x > 0;\n  @ assigns \\nothing;\n  @ ensures e: \\result > 0;\n"
        "  @ behavior pos: assumes x > 1; ensures \\result > 1;\n"
        "  @ behavior any: ensures \\result >= 0;\n  @ complete behaviors; */"
    )
    out = CR.strip_ensures(body)
    assert "ensures" not in out
    assert "requires r: x > 0;" in out and "behavior pos: assumes x > 1;" in out
    assert "behavior any: assumes \\true;" in out and "complete behaviors;" in out
    # Offsets of what stays are unchanged (line numbers of the original clauses).
    assert out.count("\n") == body.count("\n")


@pytest.mark.unit
def test_acsl_body_keeps_offsets():
    text = "/*@ requires a;\n  @ ensures b; */"
    body = CR.acsl_body(text)
    assert len(body) == len(text) and "@" not in body and "requires a;" in body


@pytest.mark.unit
def test_variadic_function_is_undecided(tmp_path):
    src = "/*@ requires n >= 0; assigns \\nothing; */\nint lg(const char *f, int n, ...) { return n; }\n"
    c = _contract(tmp_path, "lg.c", src, "lg")
    assert c.definition is not None and c.definition.variadic
    with pytest.raises(CR.ProbeError, match="variadic"):
        CR.build_probe(c.pieces, c.pieces, c.definition, False, Path("/w/lg.c"), "lg")
    stronger = dataclasses.replace(c.pieces[0], acsl="/*@ requires n > 0; assigns \\nothing; */")
    changed = CR.FunctionContract(function="lg", pieces=[stronger], definition=c.definition, returns_void=False)
    res = CR.refinement_check(changed, c, tmp_path / "lg.c")
    assert res["verdict"] == CR.UNDECIDED and "variadic" in res["reason"] and not res["probe_run"]


@pytest.mark.unit
@pytest.mark.parametrize(
    ("declarator", "function", "match"),
    [
        ("int f()", "f", "empty parameter list"),
        ("int f(int a, )", "f", "malformed parameter list"),
        ("int f(, int a)", "f", "malformed parameter list"),
        ("int f(void, int a)", "f", "malformed parameter list"),
        ("int f", "f", "parameter list not found"),
        ("int f(int a", "f", "parameter list not found"),
        ("int f(int a) garbage", "f", "unexpected text"),
        ("int (*getcb(int k))", "getcb", "malformed nested declarator"),
        ("int (*getcb(int k, ...))(int)", "getcb", "variadic"),
        ("int kr(a) int b;", "kr", "does not match parameter list"),
        ("int kr(a, b) int a; int a;", "kr", "duplicate K&R declaration"),
        ("int kr(a, a) int a;", "kr", "duplicate parameter name"),
        ("int kr(a) int a = 1;", "kr", "invalid K&R parameter declaration"),
        ("int kr(a) static int a;", "kr", "invalid K&R parameter declaration"),
        ("int kr(a) ; int a;", "kr", "malformed K&R parameter declarations"),
        ("int kr(a) struct *a;", "kr", "unrecognized K&R parameter declaration"),
    ],
)
def test_declarators_the_probe_cannot_carry_are_undecided(declarator, function, match):
    piece = CR.Piece(file="x.c", line=1, acsl="/*@ assigns \\nothing; */", declarator=declarator, params=["a"])
    with pytest.raises(CR.ProbeError, match=match):
        CR.build_probe([piece], [piece], piece, False, Path("/w/x.c"), function)


@pytest.mark.unit
def test_function_without_a_usable_declaration_is_undecided(tmp_path):
    # A missing declaration yields no pieces and an undecided comparison.
    missing = _contract(tmp_path, "missing.c", "int other(int x) { return x; }\n", "absent")
    assert missing.pieces == [] and missing.definition is None
    unit, run, res = CR.compare(missing, missing, tmp_path / "missing.c")
    assert unit is None and run == {} and res["verdict"] == CR.UNDECIDED

    # An empty-paren prototype (unspecified parameters) cannot forward arguments.
    empty_proto = _contract(
        tmp_path,
        "unproto.h",
        "/*@ assigns \\nothing; */\nint unproto();\n",
        "unproto",
    )
    assert empty_proto.definition is None
    unit, run, res = CR.compare(empty_proto, empty_proto, tmp_path / "unproto.h")
    assert unit is None and run == {} and res["verdict"] == CR.UNDECIDED

    # A definition with an empty parameter list `()` (as opposed to `(void)`) stays undecided.
    empty_def = _contract(
        tmp_path,
        "empty_def.c",
        "/*@ assigns \\nothing; ensures \\result == 1; */\nint empty_def() { return 1; }\n",
        "empty_def",
    )
    assert empty_def.definition is not None and empty_def.definition.params is None
    unit, run, res = CR.compare(empty_def, empty_def, tmp_path / "empty_def.c")
    assert unit is None and run == {} and res["verdict"] == CR.UNDECIDED
    assert "empty parameter list" in res["reason"]

    # An unnamed parameter in a nested declarator definition is still refused.
    unnamed_nested = _contract(
        tmp_path,
        "unnamed_nested.c",
        "int (*fp_v)(int);\n/*@ assigns \\nothing; */\nint (*unnamed_cb(int))(int) { return fp_v; }\n",
        "unnamed_cb",
    )
    assert unnamed_nested.definition is not None and unnamed_nested.definition.params is None
    unit, run, res = CR.compare(unnamed_nested, unnamed_nested, tmp_path / "unnamed_nested.c")
    assert unit is None and run == {} and res["verdict"] == CR.UNDECIDED
    assert "unnamed" in res["reason"]


@pytest.mark.unit
def test_kr_and_nested_declarator_spans_params_and_contract_shape(tmp_path):
    import acsl_ast

    source = """\
typedef int (*cb_t)(int);
typedef int fn_t(int);
int (*fp_var)(int);
int g_init = helper(1);
void outer(int (*inner_cb(int))(int));
void outer2(int inner_fn(int));
MACRO(a)
int x;
int after_macro(void) { return x; }

/*@ assigns \\nothing;
    ensures \\result == a + *b; */
int kr_add(a, b)
int a;
char *b;
{
    return a + *b;
}

/*@ assigns \\nothing; */
void kr_void(a)
int a;
{
    (void)a;
}

/*@ assigns \\nothing;
    ensures \\result == s.x; */
int kr_struct(s)
struct { int x; } s;
{
    return s.x;
}

/*@ assigns \\nothing; */
int kr_cb(cb)
int (*cb)(int);
{
    return cb(1);
}

/*@ assigns \\nothing;
    ensures \\result != \\null; */
int (*getcb(int k))(int);

/*@ assigns \\nothing;
    ensures \\result != \\null; */
int (*getcb(int k))(int)
{
    return fp_var;
}

/*@ assigns \\nothing; */
void (*signal_like(int sig, void (*func)(int)))(int);

/*@ assigns \\nothing; */
int (*(*chain(int x))(int y))(int z) { return 0; }

/*@ assigns \\nothing; */
int (*row(int i))[4];

int (*unnamed_cb(int))(int);
"""

    # K&R definitions
    kr_decls = acsl_ast.contract_declaration_spans(source, "kr_add")
    assert [d.kind for d in kr_decls] == ["definition"]
    assert kr_decls[0].span.text.startswith("/*@ assigns \\nothing;") and kr_decls[0].span.text.endswith("}")
    assert acsl_ast.function_param_names(source, "kr_add") == ["a", "b"]
    assert acsl_ast.function_returns_void(source, "kr_add") is False
    assert acsl_ast.contract_shape(acsl_ast.function_contract_text(source, "kr_add"), False) == "functional"

    assert acsl_ast.function_returns_void(source, "kr_void") is True
    assert acsl_ast.contract_shape(acsl_ast.function_contract_text(source, "kr_void"), True) == "not_applicable"

    assert acsl_ast.function_param_names(source, "kr_struct") == ["s"]
    assert "ensures \\result == s.x" in acsl_ast.function_contract_text(source, "kr_struct")
    assert acsl_ast.function_param_names(source, "kr_cb") == ["cb"]

    # Nested declarators (prototype + definition, signal-like, double-nested, pointer-to-array)
    cb_hdr_decls = acsl_ast.contract_declaration_spans(source, "getcb", is_header=True)
    assert [d.kind for d in cb_hdr_decls] == ["prototype", "definition"]
    assert acsl_ast.function_param_names(source, "getcb", is_header=True) == ["k"]
    assert acsl_ast.function_returns_void(source, "getcb", is_header=True) is False
    assert acsl_ast.function_returns_void(source, "signal_like", is_header=True) is False
    assert acsl_ast.function_param_names(source, "signal_like", is_header=True) == ["sig", "func"]
    assert [d.kind for d in acsl_ast.contract_declaration_spans(source, "chain")] == ["definition"]
    assert acsl_ast.function_param_names(source, "chain") == ["x"]
    assert [d.kind for d in acsl_ast.contract_declaration_spans(source, "row", is_header=True)] == ["prototype"]
    assert acsl_ast.function_param_names(source, "row", is_header=True) == ["i"]
    # Unnamed parameter in a nested declarator is still skipped.
    assert acsl_ast.function_param_names(source, "unnamed_cb", is_header=True) == []

    # Bulk scanners find all real declarations and reject non-declarations.
    protos = {s.function for s in acsl_ast.locate_all_prototype_spans(source)}
    defs = set(acsl_ast.locate_all_definition_spans(source))
    assert {"outer", "outer2", "getcb", "signal_like", "row", "unnamed_cb"} <= protos
    assert {"after_macro", "kr_add", "kr_void", "kr_struct", "kr_cb", "getcb", "chain"} <= defs
    for bogus in ("cb_t", "fn_t", "fp_var", "helper", "inner_cb", "inner_fn", "MACRO", "func"):
        assert bogus not in protos and bogus not in defs
        assert acsl_ast.function_declaration_spans(source, bogus) == []

    # `read_function_contract` and `build_probe` now synthesize valid probes for nested declarators.
    c_nested = _contract(tmp_path, "nested.c", source, "getcb")
    assert c_nested.definition is not None and c_nested.definition.params == ["k"]
    assert c_nested.returns_void is False and len(c_nested.pieces) == 1
    assert acsl_ast.contract_shape(c_nested.text(), bool(c_nested.returns_void)) == "safety_only"
    unit = CR.build_probe(c_nested.pieces, c_nested.pieces, c_nested.definition, False, tmp_path / "nested.c", "getcb")
    assert "int (*getcb__given(int k))(int);" in unit.text
    assert "int (*getcb__probe(int k))(int);" in unit.text
    assert "int (*getcb__probe(int k))(int)\n{\n  return getcb__given(k);\n}" in unit.text


@pytest.mark.unit
def test_kr_probe_synthesis_rewrites_to_ansi(tmp_path):
    source = """\
struct pt { int x; int y; };

/*@ requires \\valid_read(b);
    assigns \\nothing;
    ensures \\result == a + *b; */
int kr_add(a, b)
int a;
char *b;
{
    return a + *b;
}

/*@ requires \\valid_read(b);
    assigns \\nothing;
    ensures \\result == a + *b; */
static int kr_reg_order(a, b)
const char *b;
register int a;
{
    return a + *b;
}

/*@ requires \\valid_read(b) && \\valid_read(c + (0 .. 3));
    assigns \\nothing;
    ensures \\result == a + *b + c[0]; */
int kr_multi(a, b, c)
int a, *b, c[4];
{
    return a + *b + c[0];
}

/*@ assigns \\nothing;
    ensures \\result == a + b; */
int kr_default(a, b)
int a;
{
    return a + b;
}

/*@ assigns \\nothing;
    ensures \\result == a; */
int kr_reg_default(a)
register a;
{
    return a;
}

/*@ assigns \\nothing;
    ensures \\result == s.x; */
int kr_struct_named(s)
struct pt s;
{
    return s.x;
}

/*@ assigns \\nothing;
    ensures \\result == s.x; */
int kr_struct_anon(s)
struct { int x; } s;
{
    return s.x;
}

/*@ assigns \\nothing; */
int kr_cb(cb)
int (*cb)(int);
{
    return cb(1);
}

/*@ requires \\valid_read(p);
    assigns \\nothing;
    ensures \\result == (*p)[0]; */
int kr_arr_ptr(p)
int (*p)[4];
{
    return (*p)[0];
}

/*@ requires \\valid(p);
    assigns *p;
    ensures *p == v; */
void kr_void(p, v)
int *p;
int v;
{
    *p = v;
}
"""
    c_path = _write(tmp_path, "kr_all.c", source)

    cases = [
        (
            "kr_add",
            "int kr_add__given(int a, char *b);",
            "int kr_add__probe(int a, char *b)\n{\n  return kr_add__given(a, b);\n}",
        ),
        (
            "kr_reg_order",
            "int kr_reg_order__given(int a, const char *b);",
            "int kr_reg_order__probe(int a, const char *b)\n{\n  return kr_reg_order__given(a, b);\n}",
        ),
        (
            "kr_multi",
            "int kr_multi__given(int a, int *b, int c[4]);",
            "int kr_multi__probe(int a, int *b, int c[4])\n{\n  return kr_multi__given(a, b, c);\n}",
        ),
        (
            "kr_default",
            "int kr_default__given(int a, int b);",
            "int kr_default__probe(int a, int b)\n{\n  return kr_default__given(a, b);\n}",
        ),
        (
            "kr_reg_default",
            "int kr_reg_default__given(int a);",
            "int kr_reg_default__probe(int a)\n{\n  return kr_reg_default__given(a);\n}",
        ),
        (
            "kr_struct_named",
            "int kr_struct_named__given(struct pt s);",
            "int kr_struct_named__probe(struct pt s)\n{\n  return kr_struct_named__given(s);\n}",
        ),
        (
            "kr_struct_anon",
            "int kr_struct_anon__given(struct { int x; } s);",
            "int kr_struct_anon__probe(struct { int x; } s)\n{\n  return kr_struct_anon__given(s);\n}",
        ),
        (
            "kr_cb",
            "int kr_cb__given(int (*cb)(int));",
            "int kr_cb__probe(int (*cb)(int))\n{\n  return kr_cb__given(cb);\n}",
        ),
        (
            "kr_arr_ptr",
            "int kr_arr_ptr__given(int (*p)[4]);",
            "int kr_arr_ptr__probe(int (*p)[4])\n{\n  return kr_arr_ptr__given(p);\n}",
        ),
        (
            "kr_void",
            "void kr_void__given(int *p, int v);",
            "void kr_void__probe(int *p, int v)\n{\n  kr_void__given(p, v);\n}",
        ),
    ]
    for fn, expected_given, expected_def in cases:
        c = CR.read_function_contract(c_path, fn)
        assert c.definition is not None, fn
        unit = CR.build_probe(c.pieces, c.pieces, c.definition, bool(c.returns_void), c_path, fn)
        assert expected_given in unit.text, f"{fn}:\n{unit.text}"
        assert expected_def in unit.text, f"{fn}:\n{unit.text}"
        if fn == "kr_reg_order":
            assert "static" not in unit.text and "register" not in unit.text

    # A manually constructed Piece without a trailing semicolon on its K&R declaration also synthesizes cleanly.
    piece = CR.Piece(file="x.c", line=1, acsl="/*@ assigns \\nothing; */", declarator="int kr(a) int a", params=["a"])
    unit = CR.build_probe([piece], [piece], piece, False, Path("/w/x.c"), "kr")
    assert "int kr__given(int a);" in unit.text
    assert "int kr__probe(int a)\n{\n  return kr__given(a);\n}" in unit.text


@pytest.mark.unit
def test_kr_split_contract_header_and_definition_builds_probe(tmp_path):
    header = "/*@ requires a > 0;\n    assigns \\nothing; */\nint kr_split(int a, char *b);\n"
    src = '#include "api.h"\n/*@ ensures \\result == a + *b; */\nint kr_split(a, b)\nint a;\nchar *b;\n{ return a + *b; }\n'
    c = _contract(tmp_path, "kr_split.c", src, "kr_split", header)
    assert c.definition is not None and c.definition.params == ["a", "b"]
    unit = CR.build_probe(
        c.pieces, c.pieces, c.definition, False, tmp_path / "kr_split.c", "kr_split", strip_given_ensures=True
    )
    assert unit.text.count("int kr_split__given(int a, char *b);") == 2
    assert "int kr_split__probe(int a, char *b)\n{\n  return kr_split__given(a, b);\n}" in unit.text
    comments = re.findall(r"/\*@(.*?)\*/", unit.text, flags=re.S)
    assert comments and all(body.strip() for body in comments)


@pytest.mark.unit
def test_nested_declarator_probe_synthesis(tmp_path):
    source = """\
int (*fp_var)(int);
static int mat[4][4];

/*@ assigns \\nothing;
    ensures \\result != \\null; */
static int (*getcb(int k))(int)
{
    return fp_var;
}

/*@ requires 0 <= i < 4;
    assigns \\nothing;
    ensures \\result == &mat[i]; */
int (*row(int i))[4]
{
    return &mat[i];
}

/*@ requires func != \\null;
    assigns \\nothing;
    ensures \\result == func; */
void (*signal_like(int sig, void (*func)(int)))(int)
{
    return func;
}

/*@ assigns \\nothing; */
int (*(*chain(int x))(int y))(int z)
{
    return 0;
}

/*@ assigns \\nothing; */
const int *(* const qual_cb(const int a, char * const b))(double)
{
    return 0;
}

/*@ assigns \\nothing; */
int (*get_printf(int mode))(const char *, ...)
{
    return 0;
}

/*@ requires \\valid_read(a + (0 .. 3));
    assigns \\nothing;
    ensures \\result == a[0]; */
static int arr_static_param(int a[static 4])
{
    return a[0];
}
"""
    c_path = _write(tmp_path, "nested_all.c", source)

    cases = [
        (
            "getcb",
            "int (*getcb__given(int k))(int);",
            "int (*getcb__probe(int k))(int)\n{\n  return getcb__given(k);\n}",
        ),
        (
            "row",
            "int (*row__given(int i))[4];",
            "int (*row__probe(int i))[4]\n{\n  return row__given(i);\n}",
        ),
        (
            "signal_like",
            "void (*signal_like__given(int sig, void (*func)(int)))(int);",
            "void (*signal_like__probe(int sig, void (*func)(int)))(int)\n{\n  return signal_like__given(sig, func);\n}",
        ),
        (
            "chain",
            "int (*(*chain__given(int x))(int y))(int z);",
            "int (*(*chain__probe(int x))(int y))(int z)\n{\n  return chain__given(x);\n}",
        ),
        (
            "qual_cb",
            "const int *(* const qual_cb__given(const int a, char * const b))(double);",
            "const int *(* const qual_cb__probe(const int a, char * const b))(double)\n{\n  return qual_cb__given(a, b);\n}",
        ),
        (
            "get_printf",
            "int (*get_printf__given(int mode))(const char *, ...);",
            "int (*get_printf__probe(int mode))(const char *, ...)\n{\n  return get_printf__given(mode);\n}",
        ),
        (
            "arr_static_param",
            "int arr_static_param__given(int a[static 4]);",
            "int arr_static_param__probe(int a[static 4])\n{\n  return arr_static_param__given(a);\n}",
        ),
    ]
    for fn, expected_given, expected_def in cases:
        c = CR.read_function_contract(c_path, fn)
        assert c.definition is not None and c.returns_void is False, fn
        unit = CR.build_probe(c.pieces, c.pieces, c.definition, bool(c.returns_void), c_path, fn)
        assert expected_given in unit.text, f"{fn}:\n{unit.text}"
        assert expected_def in unit.text, f"{fn}:\n{unit.text}"
        if fn == "getcb":
            assert "static" not in unit.text


@pytest.mark.unit
def test_nested_declarator_split_contract_builds_probe(tmp_path):
    header = "/*@ requires k >= 0;\n    assigns \\nothing; */\nint (*getcb(int k))(int);\n"
    src = '#include "api.h"\nint (*fp_var)(int);\n/*@ ensures \\result != \\null; */\nint (*getcb(int k))(int) { return fp_var; }\n'
    c = _contract(tmp_path, "nested_split.c", src, "getcb", header)
    assert c.definition is not None and c.definition.params == ["k"] and c.returns_void is False
    unit = CR.build_probe(c.pieces, c.pieces, c.definition, False, tmp_path / "nested_split.c", "getcb")
    assert unit.text.count("int (*getcb__given(int k))(int);") == 2
    assert "int (*getcb__probe(int k))(int)\n{\n  return getcb__given(k);\n}" in unit.text


@pytest.mark.unit
def test_unnamed_formal_in_the_definition_is_undecided(tmp_path):
    proto = CR.Piece(file="h.h", line=1, acsl="/*@ assigns \\nothing; */", declarator="int f(int)", params=None)
    with pytest.raises(CR.ProbeError, match="unnamed"):
        CR.build_probe([proto], [proto], proto, False, Path("/w/f.c"), "f")


@pytest.mark.unit
def test_a_contract_without_assigns_is_undecided(tmp_path):
    c = _contract(
        tmp_path, "n.c", "/*@ requires \\valid(p); ensures *p == v; */\nvoid na(int *p, int v) { *p = v; }\n", "na"
    )
    assert c.definition is not None
    with pytest.raises(CR.ProbeError, match="no `assigns`"):
        CR.build_probe(c.pieces, c.pieces, c.definition, True, Path("/w/n.c"), "na")


@pytest.mark.unit
def test_refinement_check_skips_the_probe_when_nothing_changed(tmp_path, monkeypatch):
    def boom(*_a, **_k):
        raise AssertionError("no probe run expected")

    monkeypatch.setattr(CR, "run_probe", boom)
    src = "/*@ assigns \\nothing; ensures \\result == 1; */\nint one(void) { return 1; }\n"
    c = _contract(tmp_path, "o.c", src, "one")
    assert CR.refinement_check(c, c, tmp_path / "o.c")["verdict"] == CR.REFINES
    empty = CR.FunctionContract(function="one")
    res = CR.refinement_check(c, empty, tmp_path / "o.c")
    assert res["verdict"] == CR.REFINES and res["reason"] == "no previous contract" and not res["probe_run"]


@pytest.mark.unit
def test_probe_is_never_written_under_the_work_tree(tmp_path):
    unit = CR.ProbeUnit(text="int x;\n", function="f")
    res = CR.run_probe(unit, keep_dir=tmp_path / "run" / "workspace" / "work" / "probe", wp_par=1)
    assert not res["ok"] and "workspace/work" in res["reason"]
    assert not (tmp_path / "run" / "workspace" / "work" / "probe" / CR.PROBE_FILE).exists()


def _unit_with_labels() -> CR.ProbeUnit:
    unit = CR.ProbeUnit(text="", function="f")
    unit.labels[1] = CR.ClauseRef("given", "requires", "new.c", 3, "x > 0")
    unit.labels[2] = CR.ClauseRef("probe", "ensures", "old.c", 5, "\\result == x")
    unit.labels[3] = CR.ClauseRef("probe", "ensures", "old.c", 6, "\\result > 0")
    unit.ensures_labels = [2, 3]
    unit.by_kind["assigns"] = [CR.ClauseRef("probe", "assigns", "old.c", 4, "\\nothing")]
    return unit


def _entry(goal: str, prop: str, passed: bool, verdict: str = "valid") -> dict:
    return {"goal": goal, "property": prop, "function": "f__probe", "passed": passed, "verdict": verdict}


def _run(*entries: dict, models: tuple[str, ...] = ()) -> dict:
    return {"ok": True, "entries": list(entries), "models": list(models), "elapsed_ms": 10}


PROVED_REST = (
    _entry("typed_f_probe_terminates", "f_probe_terminates", True),
    _entry("typed_f_probe_assigns", "f_probe_assigns", True),
    _entry("typed_f__probe_call_f__given_f_given_requires_fcprobe_1", "f_given_requires_fcprobe_1", True),
)


@pytest.mark.unit
def test_verdict_rules_on_recorded_goals():
    unit = _unit_with_labels()
    ok2 = _entry("typed_f_probe_ensures_fcprobe_2", "f_probe_ensures_fcprobe_2", True)
    ok3 = _entry("typed_f_probe_ensures_fcprobe_3", "f_probe_ensures_fcprobe_3", True)
    bad2 = _entry("typed_f_probe_ensures_fcprobe_2", "f_probe_ensures_fcprobe_2", False, "unknown")
    slow3 = _entry("typed_f_probe_ensures_fcprobe_3", "f_probe_ensures_fcprobe_3", False, "timeout")

    assert CR.decide(unit, _run(*PROVED_REST, ok2, ok3))["verdict"] == CR.REFINES
    # A model for the goal: the previous clause is not implied.
    res = CR.decide(unit, _run(*PROVED_REST, bad2, ok3, models=("typed_f_probe_ensures_fcprobe_2",)))
    assert res["verdict"] == CR.WEAKER
    assert res["clauses"] == [
        {
            "contract": "probe",
            "kind": "ensures",
            "file": "old.c",
            "line": 5,
            "text": "\\result == x",
            "verdict_kind": "unknown",
            "model": True,
        }
    ]
    # No model (a timeout): undecided, never weaker.
    res = CR.decide(unit, _run(*PROVED_REST, ok2, slow3))
    assert res["verdict"] == CR.UNDECIDED and res["undecided_clauses"][0]["line"] == 6
    # A refuted clause and an open one: weaker, the open one listed apart.
    res = CR.decide(unit, _run(*PROVED_REST, bad2, slow3, models=("typed_f_probe_ensures_fcprobe_2",)))
    assert res["verdict"] == CR.WEAKER and [r["line"] for r in res["undecided_clauses"]] == [6]
    # The new requires is not implied by the previous one (goal at the call).
    req = _entry(
        "typed_f__probe_call_f__given_f_given_requires_fcprobe_1", "f_given_requires_fcprobe_1", False, "unknown"
    )
    res = CR.decide(unit, _run(PROVED_REST[0], PROVED_REST[1], req, ok2, ok3, models=(req["goal"],)))
    assert res["verdict"] == CR.WEAKER and res["clauses"][0]["contract"] == "given"
    # An unproved goal that is none of the compared clauses (here: termination, B has no terminates).
    term = _entry("typed_f_probe_terminates", "f_probe_terminates", False, "unknown")
    res = CR.decide(unit, _run(term, PROVED_REST[1], ok2, ok3, models=(term["goal"],)))
    assert res["verdict"] == CR.UNDECIDED and "none of the compared clauses" in res["reason"]
    # Nothing proved at all, no goal, a failed run.
    assert CR.decide(unit, _run(bad2))["verdict"] == CR.UNDECIDED
    assert CR.decide(unit, _run())["verdict"] == CR.UNDECIDED
    assert CR.decide(unit, {"ok": False, "reason": "rc=1"}) == {
        "goal_timeout_s": CR.PROBE_GOAL_TIMEOUT_S,
        "elapsed_ms": None,
        "verdict": CR.UNDECIDED,
        "reason": "rc=1",
    }
    # assigns goals map to B's assigns clauses.
    assigns_bad = _entry("typed_f_probe_assigns_normal", "f_probe_assigns", False, "unknown")
    res = CR.decide(unit, _run(PROVED_REST[0], assigns_bad, ok2, ok3, models=(assigns_bad["goal"],)))
    assert res["verdict"] == CR.WEAKER and res["clauses"][0]["kind"] == "assigns"


@pytest.mark.unit
def test_frame_summary_reads_ensures_goals():
    unit = _unit_with_labels()
    ok2 = _entry("typed_f_probe_ensures_fcprobe_2", "f_probe_ensures_fcprobe_2", True)
    ok3 = _entry("typed_f_probe_ensures_fcprobe_3", "f_probe_ensures_fcprobe_3", True)
    bad3 = _entry("typed_f_probe_ensures_fcprobe_3", "f_probe_ensures_fcprobe_3", False, "unknown")
    slow3 = _entry("typed_f_probe_ensures_fcprobe_3", "f_probe_ensures_fcprobe_3", False, "timeout")

    def summary(*entries, models=()):
        return CR.frame_summary(unit, CR.classify_goals(unit, _run(*entries, models=models)))

    every = summary(*PROVED_REST, ok2, ok3)
    assert every["status"] == CR.FRAME_DECIDED and every["all_frame_only"] is True
    assert [r["line"] for r in every["frame_only"]] == [5, 6] and "contract" not in every["frame_only"][0]
    some = summary(*PROVED_REST, ok2, bad3, models=(bad3["goal"],))
    assert some["status"] == CR.FRAME_DECIDED and some["all_frame_only"] is False
    assert [r["line"] for r in some["not_frame_only"]] == [6]
    open_ = summary(*PROVED_REST, ok2, slow3)
    assert open_["status"] == CR.FRAME_UNDECIDED and open_["all_frame_only"] is False
    other = summary(PROVED_REST[0], _entry("g", "f_probe_assigns", False, "unknown"), ok2, ok3)
    assert other["status"] == CR.FRAME_UNDECIDED


@pytest.mark.unit
def test_frame_only_without_ensures_is_not_applicable(tmp_path):
    c = _contract(tmp_path, "z.c", "/*@ requires \\valid(p); assigns *p; */\nvoid z(int *p) { *p = 0; }\n", "z")
    res = CR.frame_only_ensures(c, tmp_path / "z.c")
    assert res["status"] == CR.FRAME_NOT_APPLICABLE and res["ensures"] == 0


@pytest.mark.unit
def test_missing_frama_c_is_undecided(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    src = "/*@ requires \\valid(p); assigns *p; ensures *p == 0; */\nvoid z(int *p) { *p = 0; }\n"
    c = _contract(tmp_path, "z.c", src, "z")
    res = CR.frame_only_ensures(c, tmp_path / "z.c", wp_par=1)
    assert res["status"] == CR.FRAME_UNDECIDED and "could not be started" in str(res["reason"])


# ---------------------------------------------------------------------------
# Integration: the probe in the analysis image
# ---------------------------------------------------------------------------

REFINE_NEW = """#include "api.h"

/*@ requires small(a) && small(b);
    assigns \\nothing;
    ensures \\result >= a + b - 1; */
int add(int a, int b) { return a + b; }

struct pt { int x; int y; };

/*@ requires small(v.x) && small(v.y);
    assigns \\nothing;
    ensures \\result == v.x + v.y; */
static int sum_pt(struct pt v) { return v.x + v.y; }

/*@ requires \\valid(p) && \\valid_read(q) && \\separated(p, q);
    assigns *p;
    ensures *q == \\old(*q);
    ensures *p == v; */
void set(int *p, const int *q, int v) { *p = v; }
"""

REFINE_OLD = """#include "api.h"

/*@ requires small(a) && small(b);
    assigns \\nothing;
    ensures \\result == a + b; */
int add(int a, int b) { return a + b; }

struct pt { int x; int y; };

/*@ requires small(v.x) && small(v.y);
    assigns \\nothing;
    ensures \\result >= v.x + v.y - 1; */
static int sum_pt(struct pt v) { return v.x + v.y; }

/*@ requires \\valid(p) && \\valid_read(q) && \\separated(p, q);
    assigns *p; */
void set(int *p, const int *q, int v) { *p = v; }
"""


@pytest.mark.integration
@needs_framac
def test_real_probe_refinement_weakening_and_frame_only(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write(tmp_path, "api.h", PROBE_HEADER)
    new_c, old_c = _write(tmp_path, "new.c", REFINE_NEW), _write(tmp_path, "old.c", REFINE_OLD)

    def contracts(fn):
        return CR.read_function_contract(new_c, fn, "-I."), CR.read_function_contract(old_c, fn, "-I.")

    timings = {}
    # A refinement (a static function taking a struct by value): the new result is exact.
    new, old = contracts("sum_pt")
    res = CR.refinement_check(new, old, new_c, "-I.", work_dir=tmp_path / "probe")
    assert res["verdict"] == CR.REFINES, res
    timings["refines"] = res["elapsed_ms"]
    # A weakening: the new contract no longer gives `\result == a + b`.
    new, old = contracts("add")
    res = CR.refinement_check(new, old, new_c, "-I.", work_dir=tmp_path / "probe")
    assert res["verdict"] == CR.WEAKER, res
    assert [(c["contract"], c["kind"], c["line"], c["text"]) for c in res["clauses"]] == [
        ("previous", "ensures", 5, "\\result == a + b")
    ]
    timings["weaker"] = res["elapsed_ms"]
    # Postconditions of `set`: `*q` is unchanged by the frame alone, `*p == v` is the function's work.
    new, _old = contracts("set")
    res = CR.frame_only_ensures(new, new_c, "-I.", work_dir=tmp_path / "probe")
    assert res["status"] == CR.FRAME_DECIDED and res["all_frame_only"] is False, res
    assert [c["text"] for c in res["frame_only"]] == ["*q == \\old(*q)"]
    assert [c["text"] for c in res["not_frame_only"]] == ["*p == v"]
    timings["frame_only"] = res["elapsed_ms"]
    print(f"probe timings (ms): {json.dumps(timings)}")
    # Nothing was left behind: the probe directory is temporary.
    assert not any((tmp_path / "probe").glob("contract_probe_*"))


@pytest.mark.unit
def test_relative_include_paths_are_made_absolute():
    base = Path("/run")
    flags = CR.absolute_path_flags("-I. -Iwork/include -I /abs -isystem sys -include cfg.h -DX=1 -O2", base)
    assert flags == "-I/run -I/run/work/include -I/abs -isystem /run/sys -include /run/cfg.h -DX=1 -O2"
    assert CR.absolute_path_flags("", base) == ""
    assert CR.absolute_path_flags("-I'unterminated", base) == "-I'unterminated"


RUN_LAYOUT_HEADER = """\
/*@ assigns \\nothing;
    ensures \\result == a + b; */
int add(int a, int b);
/*@ requires \\valid(p) && \\valid_read(q) && \\separated(p, q);
    assigns *p;
    ensures *q == \\old(*q); */
void touch(int *p, const int *q);
"""

RUN_LAYOUT_C = """\
#include <lib/api.h>
int add(int a, int b) { return a + b; }
void touch(int *p, const int *q) { *p = 0; }
"""


@pytest.mark.integration
@needs_framac
def test_real_pipeline_uses_on_a_run_layout(tmp_path, monkeypatch):
    """The contract sits on a header found only through a relative `-I`, as in a run directory."""
    import run_wp_function

    monkeypatch.chdir(tmp_path)
    _write(tmp_path, "work/include/lib/api.h", RUN_LAYOUT_HEADER)
    c_file = _write(tmp_path, "work/src/api.c", RUN_LAYOUT_C)
    flags = "-I. -Iwork/include"
    consistent = {"status": "consistent", "doomed": [], "dead_goals": 0}
    report = {"status": "all_proven", "function": "touch", "soundness": {"ok": True}, "layer_goals": []}
    limits = run_wp_function.apply_verdict_limits(report, c_file, consistent, cppflags=flags)["limits"]
    assert limits["frame_only_ensures"]["status"] == CR.FRAME_DECIDED, limits
    assert limits["frame_only_ensures"]["all_frame_only"] is True
    previous = CR.read_function_contract(c_file, "add", flags)
    weaker_header = RUN_LAYOUT_HEADER.replace("\\result == a + b", "\\result >= a")
    _write(tmp_path, "work/include/lib/api.h", weaker_header)
    new = CR.read_function_contract(c_file, "add", flags)
    res = CR.refinement_check(new, previous, c_file, flags)
    assert res["verdict"] == CR.WEAKER, res
    print(
        f"run-layout probe timings (ms): frame {limits['frame_only_ensures'].get('elapsed_ms')}, "
        f"weaker {res.get('elapsed_ms')}"
    )


def _use_native_framac() -> bool:
    """True to invoke native `frama-c` in-process; False to run inside `ANALYSIS_IMAGE` (or skip)."""
    if shutil.which("frama-c") is not None:
        return True
    require_docker_images(ANALYSIS_IMAGE)
    return False


def _run_probe_cli_batch(tmp_path: Path, invocations: list[list[str]], monkeypatch: pytest.MonkeyPatch) -> list[dict]:
    """
    Run `contract_refinement.py` CLI invocations (paths relative to `tmp_path`), either in-process when
    `frama-c` is installed natively or in one `ANALYSIS_IMAGE` container when `FRAMAC_DOCKER_TESTS=1`.
    """
    if _use_native_framac():
        monkeypatch.chdir(tmp_path)
        results: list[dict] = []
        for idx, argv in enumerate(invocations):
            out = tmp_path / f"res_{idx}.json"
            assert CR.main([*argv, "--out-json", str(out)]) == 0
            results.append(json.loads(out.read_text(encoding="utf-8")))
        return results

    runner = tmp_path / "_run_batch.py"
    runner.write_text(
        "import json, subprocess, sys\n"
        "invocations = json.loads(sys.argv[1])\n"
        "for idx, argv in enumerate(invocations):\n"
        "    cmd = [sys.executable, '/opt/framac-pipeline/scripts/contract_refinement.py', *argv, "
        "'--out-json', f'/w/res_{idx}.json']\n"
        "    p = subprocess.run(cmd, cwd='/w', capture_output=True, text=True)\n"
        "    if p.returncode != 0:\n"
        "        sys.stderr.write(f'call {idx} failed (rc={p.returncode}):\\n{p.stdout}{p.stderr}\\n')\n"
        "        sys.exit(p.returncode)\n",
        encoding="utf-8",
        newline="\n",
    )
    proc = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "-v",
            f"{tmp_path.resolve()}:/w",
            "-v",
            f"{ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
            "-w",
            "/w",
            "--entrypoint",
            "python3",
            ANALYSIS_IMAGE,
            "/w/_run_batch.py",
            json.dumps(invocations),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return [json.loads((tmp_path / f"res_{idx}.json").read_text(encoding="utf-8")) for idx in range(len(invocations))]


KR_STRONG_C = """\
/*@ requires -1000 <= a <= 1000 && \\valid_read(b);
    assigns \\nothing;
    ensures \\result == a + *b; */
int kr_add(a, b)
int a;
char *b;
{ return a + *b; }

/*@ requires -1000 <= a <= 1000 && -1000 <= b <= 1000;
    assigns \\nothing;
    ensures \\result == a + b; */
int kr_default(a, b)
int a;
{ return a + b; }

/*@ requires \\valid(p) && \\valid_read(q) && \\separated(p, q);
    assigns *p;
    ensures *q == \\old(*q);
    ensures *p == v; */
void kr_set(p, q, v)
int *p;
const int *q;
register int v;
{ *p = v; }

/*@ requires -1000 <= a <= 1000 && \\valid_read(b) && \\valid_read(c + (0 .. 3));
    requires -1000 <= *b <= 1000 && -1000 <= c[0] <= 1000;
    assigns \\nothing;
    ensures \\result == a + *b + c[0]; */
int kr_multi(a, b, c)
int a, *b, c[4];
{ return a + *b + c[0]; }
"""

KR_WEAK_C = """\
/*@ requires -1000 <= a <= 1000 && \\valid_read(b);
    assigns \\nothing;
    ensures \\result >= a + *b - 1; */
int kr_add(a, b)
int a;
char *b;
{ return a + *b; }

/*@ requires -1000 <= a <= 1000 && -1000 <= b <= 1000;
    assigns \\nothing;
    ensures \\result >= a + b - 1; */
int kr_default(a, b)
int a;
{ return a + b; }

/*@ requires -1000 <= a <= 1000 && \\valid_read(b) && \\valid_read(c + (0 .. 3));
    requires -1000 <= *b <= 1000 && -1000 <= c[0] <= 1000;
    assigns \\nothing;
    ensures \\result == c[0] + *b + a; */
int kr_multi(a, b, c)
int a, *b, c[4];
{ return a + *b + c[0]; }
"""

KR_EQUIV_C = KR_STRONG_C.replace("ensures \\result == a + b;", "ensures \\result == b + a;")


@pytest.mark.integration
def test_real_probe_kr_definitions(tmp_path, monkeypatch):
    """Frama-C 34 parses and decides probes synthesized from K&R definitions (compare + frame-only)."""
    _write(tmp_path, "strong.c", KR_STRONG_C)
    _write(tmp_path, "weak.c", KR_WEAK_C)
    _write(tmp_path, "equiv.c", KR_EQUIV_C)

    results = _run_probe_cli_batch(
        tmp_path,
        [
            ["compare", "--file", "strong.c", "--previous-file", "weak.c", "--function", "kr_add"],
            ["compare", "--file", "weak.c", "--previous-file", "strong.c", "--function", "kr_add"],
            ["compare", "--file", "equiv.c", "--previous-file", "strong.c", "--function", "kr_default"],
            ["compare", "--file", "weak.c", "--previous-file", "strong.c", "--function", "kr_default"],
            ["frame-only", "--file", "strong.c", "--function", "kr_set"],
            ["compare", "--file", "weak.c", "--previous-file", "strong.c", "--function", "kr_multi"],
        ],
        monkeypatch,
    )
    add_refines, add_weaker, def_equiv, def_weaker, set_frame, multi_equiv = results
    assert add_refines["verdict"] == CR.REFINES and add_refines["probe_run"] is True, add_refines
    assert add_weaker["verdict"] == CR.WEAKER, add_weaker
    assert [c["text"] for c in add_weaker["clauses"]] == ["\\result == a + *b"]
    assert def_equiv["verdict"] == CR.REFINES and def_equiv["probe_run"] is True, def_equiv
    assert def_weaker["verdict"] == CR.WEAKER, def_weaker
    assert [c["text"] for c in def_weaker["clauses"]] == ["\\result == a + b"]
    assert set_frame["status"] == CR.FRAME_DECIDED and set_frame["all_frame_only"] is False, set_frame
    assert [c["text"] for c in set_frame["frame_only"]] == ["*q == \\old(*q)"]
    assert [c["text"] for c in set_frame["not_frame_only"]] == ["*p == v"]
    assert multi_equiv["verdict"] == CR.REFINES and multi_equiv["probe_run"] is True, multi_equiv


NESTED_STRONG_C = """\
static int cb_a(int x) { return x; }
static int mat[4][4];

/*@ assigns \\nothing;
    ensures \\result == &cb_a; */
static int (*getcb(int k))(int)
{ return &cb_a; }

/*@ requires 0 <= i < 4;
    assigns \\nothing;
    ensures \\result == &mat[i]; */
int (*row(int i))[4]
{ return &mat[i]; }

/*@ requires func != \\null;
    assigns \\nothing;
    ensures \\result == func; */
void (*signal_like(int sig, void (*func)(int)))(int)
{ return func; }
"""

NESTED_WEAK_C = """\
static int cb_a(int x) { return x; }
static int mat[4][4];

/*@ assigns \\nothing;
    ensures \\result != \\null; */
static int (*getcb(int k))(int)
{ return &cb_a; }

/*@ requires 0 <= i < 4;
    assigns \\nothing;
    ensures \\result != \\null; */
int (*row(int i))[4]
{ return &mat[i]; }

/*@ requires func != \\null;
    assigns \\nothing;
    ensures \\result != \\null; */
void (*signal_like(int sig, void (*func)(int)))(int)
{ return func; }
"""


@pytest.mark.integration
def test_real_probe_nested_declarators(tmp_path, monkeypatch):
    """Frama-C 34 parses and decides probes synthesized from nested declarators (function/array pointers)."""
    _write(tmp_path, "strong.c", NESTED_STRONG_C)
    _write(tmp_path, "weak.c", NESTED_WEAK_C)

    results = _run_probe_cli_batch(
        tmp_path,
        [
            ["compare", "--file", "strong.c", "--previous-file", "weak.c", "--function", "getcb"],
            ["compare", "--file", "weak.c", "--previous-file", "strong.c", "--function", "getcb"],
            ["frame-only", "--file", "weak.c", "--function", "getcb"],
            ["compare", "--file", "strong.c", "--previous-file", "weak.c", "--function", "row"],
            ["compare", "--file", "weak.c", "--previous-file", "strong.c", "--function", "row"],
            ["compare", "--file", "strong.c", "--previous-file", "weak.c", "--function", "signal_like"],
            ["compare", "--file", "weak.c", "--previous-file", "strong.c", "--function", "signal_like"],
        ],
        monkeypatch,
    )
    cb_ref, cb_weak, cb_frame, row_ref, row_weak, sig_ref, sig_weak = results
    assert cb_ref["verdict"] == CR.REFINES and cb_ref["probe_run"] is True, cb_ref
    assert cb_weak["verdict"] == CR.WEAKER, cb_weak
    assert [c["text"] for c in cb_weak["clauses"]] == ["\\result == &cb_a"]
    assert cb_frame["status"] == CR.FRAME_DECIDED and cb_frame["all_frame_only"] is False, cb_frame
    assert [c["text"] for c in cb_frame["not_frame_only"]] == ["\\result != \\null"]
    assert row_ref["verdict"] == CR.REFINES and row_ref["probe_run"] is True, row_ref
    assert row_weak["verdict"] == CR.WEAKER, row_weak
    assert [c["text"] for c in row_weak["clauses"]] == ["\\result == &mat[i]"]
    assert sig_ref["verdict"] == CR.REFINES and sig_ref["probe_run"] is True, sig_ref
    assert sig_weak["verdict"] == CR.WEAKER, sig_weak
    assert [c["text"] for c in sig_weak["clauses"]] == ["\\result == func"]
