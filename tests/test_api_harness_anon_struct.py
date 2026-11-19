"""
Pointers to anonymous structs and unions declared through a typedef (nginx 1.31.9 run-3, 2026-11-19):
nginx declares its core types as typedefs of anonymous structs (`typedef struct { size_t len; u_char
*data; } ngx_str_t;`), which the Phase 0 model spells with Frama-C's generated tag
(`struct __anonstruct_ngx_str_t_13 *`). The `--api` generator refused every pointer whose pointee held
`struct __anon`, so 284 of the 370 functions `--api` skipped on nginx__ngx_event_openssl had no case.
The typedef name is declarable: the case declares the object through it and fills it as a named
struct of the same shape. A (length, pointer) field pair such as ngx_str_t's `{len, data}` is paired
like a (pointer, length) one, so the harness never hands the callee a length past its buffer.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest

import api_harness as ah
import generate_harness as gh

AS_REPO = Path(__file__).resolve().parents[1]
AS_STR = "struct __anonstruct_str_t_1"
AS_KV = "struct __anonstruct_kv_t_2"
AS_NUM = "union __anonunion_num_t_3"
AS_SBUF = "struct __anonstruct_sbuf_t_4"
AS_BARE = "struct __anonstruct_5"  # a struct with no name at all: declared inside a parameter list
AS_BIG = "struct __anonstruct_big_t_6"

# name -> (model signature, formal kinds, the declaration's parameter types as clang writes them, return).
AS_API: dict[str, tuple[str, list[str], list[str], str]] = {
    "str_check": (f"int({AS_STR} *)", ["const_pointer"], ["const str_t *"], "int"),
    "str_copy": (f"int({AS_STR} *,{AS_STR} *)", ["pointer", "const_pointer"], ["str_t *", "const str_t *"], "int"),
    "str_first": (f"{AS_STR} *({AS_KV} *)", ["pointer"], ["kv_t *"], "str_t *"),
    "kv_len": (f"unsigned long({AS_KV} *)", ["const_pointer"], ["const kv_t *"], "size_t"),
    "num_get": (f"int({AS_NUM} *)", ["const_pointer"], ["const num_t *"], "int"),
    "holder_len": ("unsigned long(struct holder *)", ["const_pointer"], ["const struct holder *"], "size_t"),
    "sbuf_init": (f"int({AS_SBUF} *,unsigned long)", ["pointer", "value"], ["sbuf_t *", "size_t"], "int"),
    "sbuf_put": (
        f"int({AS_SBUF} *,unsigned char *,unsigned long)",
        ["pointer", "const_pointer", "value"],
        ["sbuf_t *", "const unsigned char *", "size_t"],
        "int",
    ),
    "sbuf_free": (f"void({AS_SBUF} *)", ["pointer"], ["sbuf_t *"], "void"),
    "anon_use": (f"int({AS_BARE} *)", ["pointer"], ["struct (unnamed struct at lib.h:21:14) *"], "int"),
    # GMP's shape: `typedef struct { int _mp_alloc; int _mp_size; mp_limb_t *_mp_d; } __mpz_struct;`
    # and `typedef __mpz_struct mpz_t[1];`, a parameter `const mpz_t x` decays to `const big_t *`.
    "big_top": (f"unsigned long({AS_BIG} *)", ["const_pointer"], ["const big_t *"], "unsigned long"),
}
# The model's call-site sizes: str_copy's destination is a 16-byte object at its call sites.
AS_SIZES: dict[str, dict[str, dict[str, int]]] = {"str_copy": {"0": {"min": 16, "max": 16, "sites": 2}}}

# Field lists of the records, as clang 18/19 write them (qualType, desugaredQualType or None).
AS_FIELDS: dict[str, list[tuple[str, str, str | None]]] = {
    "str_t": [("len", "size_t", "unsigned long"), ("data", "unsigned char *", None)],
    "kv_t": [("key", "str_t", None), ("value", "str_t", None)],
    "num_t": [("i", "int", None), ("f", "float", None)],
    "sbuf_t": [("buf", "unsigned char *", None), ("cap", "size_t", "unsigned long"), ("used", "size_t", "unsigned long")],
    "big_t": [("alloc_", "int", None), ("size", "int", None), ("limbs", "unsigned long *", None)],
}
AS_WHAT = {"str_t": "struct", "kv_t": "struct", "num_t": "union", "sbuf_t": "struct", "big_t": "struct"}


def _as_records(names: list[str], api: dict | None = None) -> dict[str, dict]:
    out = {}
    for n in names:
        sig, kinds, _, _ = (api or AS_API)[n]
        rec: dict[str, Any] = {
            "name": n,
            "signature": sig,
            "formals": [{"name": f"p{i}", "kind": k} for i, k in enumerate(kinds)],
        }
        if n in AS_SIZES:
            rec["param_sizes"] = AS_SIZES[n]
        out[n] = rec
    return out


def _as_field(name: str, qual: str, desugared: str | None) -> dict:
    t = {"qualType": qual, **({"desugaredQualType": desugared} if desugared else {})}
    return {"kind": "FieldDecl", "name": name, "type": t}


def _as_tree(names: list[str], api: dict | None = None) -> dict:
    """
    A clang JSON AST of the header as clang 19 writes it: each `typedef struct { ... } str_t;` is a
    nameless RecordDecl, then a TypedefDecl whose qualType reads `struct str_t` and whose ElaboratedType
    owns the record by id.
    """
    inner: list[dict] = [
        {"kind": "TypedefDecl", "name": "size_t", "type": {"qualType": "unsigned long"}},
    ]
    for k, (tname, fields) in enumerate(AS_FIELDS.items()):
        rid = f"0xa{k}"
        what = AS_WHAT[tname]
        inner.append(
            {
                "id": rid,
                "kind": "RecordDecl",
                "tagUsed": what,
                "completeDefinition": True,
                "inner": [_as_field(*f) for f in fields],
            }
        )
        inner.append(
            {
                "id": f"0xb{k}",
                "kind": "TypedefDecl",
                "name": tname,
                "type": {"desugaredQualType": tname, "qualType": f"{what} {tname}"},
                "inner": [
                    {
                        "kind": "ElaboratedType",
                        "type": {"qualType": f"{what} {tname}"},
                        "ownedTagDecl": {"id": rid, "kind": "RecordDecl", "name": ""},
                        "inner": [{"kind": "RecordType", "type": {"qualType": tname}, "decl": {"id": rid, "kind": "RecordDecl", "name": ""}}],
                    }
                ],
            }
        )
    inner.append(
        {
            "id": "0xc0",
            "kind": "RecordDecl",
            "name": "holder",
            "tagUsed": "struct",
            "completeDefinition": True,
            "inner": [_as_field("name", "str_t", None), _as_field("x", "int", None)],
        }
    )
    # The parameter's own anonymous struct (`int anon_use(struct { int a; int b; } *p);`).
    inner.append(
        {
            "id": "0xc1",
            "kind": "RecordDecl",
            "tagUsed": "struct",
            "completeDefinition": True,
            "inner": [_as_field("a", "int", None), _as_field("b", "int", None)],
        }
    )
    for n in names:
        _, _, params, ret = (api or AS_API)[n]
        inner.append(
            {
                "kind": "FunctionDecl",
                "name": n,
                "type": {"qualType": f"{ret} ({', '.join(params)})"},
                "inner": [
                    {"kind": "ParmVarDecl", "name": f"p{i}", "type": {"qualType": t}} for i, t in enumerate(params)
                ],
            }
        )
    return {"kind": "TranslationUnitDecl", "inner": inner}


def _as_plan(
    names: list[str], tree: dict | None = None, probed: bool = True, api: dict | None = None
) -> dict[str, Any]:
    functions = {f"lib.c#{n}": {"name": n, "file": "lib.c"} for n in names}
    dag = {
        "warnings": [],
        "modules": {"lib": {"functions": list(functions), "candidate_entry_points": list(functions)}},
        "functions": functions,
    }
    recs = _as_records(names, api)
    model = {"status": "ok", "functions": {f"lib.c#{n}": recs[n] for n in names}}
    if not probed:
        return ah.plan(dag, model, "lib", "lib", 64, [], None, None, None)
    layouts, declared = ah.record_layouts(tree if tree is not None else _as_tree(names, api))
    return ah.plan(dag, model, "lib", "lib", 64, [], None, layouts, declared)


def _as_cases(p: dict[str, Any]) -> dict[str, str]:
    return {lay["entry"].split("#")[-1]: p["cases"][k] for k, lay in enumerate(p["layouts"]) if lay.get("entry")}


def _clamped(stmt: str, length: str) -> bool:
    """Whether `stmt` clamps the length field `length` to its buffer before any call."""
    m = re.search(rf"if \(\(unsigned long long\){re.escape(length)} > (\d+)ULL\) \{{ {re.escape(length)} = ", stmt)
    return m is not None and stmt.index(m.group(0)) < stmt.index("(void)")


# --- the layout probe ----------------------------------------------------------------------------------


@pytest.mark.unit
def test_the_probe_lays_out_records_declared_through_a_typedef_of_an_anonymous_record():
    layouts, _ = ah.record_layouts(_as_tree(list(AS_API)))
    assert [(f["name"], f["kind"], f["off"]) for f in layouts["str_t"]["fields"]] == [("len", "int", 0), ("data", "ptr", 8)]
    assert layouts["str_t"]["what"] == "struct" and layouts["str_t"]["size"] == 16
    assert layouts["num_t"]["what"] == "union" and layouts["num_t"]["size"] == 4
    # A field of such a type is a record of that typedef: kv_t and the named struct holder get a layout.
    key = layouts["kv_t"]["fields"][0]
    assert (key["kind"], key["ctype"], key["size"]) == ("record", "str_t", 16)
    assert layouts["kv_t"]["size"] == 32
    assert layouts["struct holder"]["fields"][0]["ctype"] == "str_t"
    # The parameter's own struct has no typedef: no layout under any name.
    assert not any(k.startswith("struct (") or "unnamed" in k for k in layouts)


@pytest.mark.unit
def test_the_probe_spells_pointers_to_anonymous_records_through_their_typedef():
    _, declared = ah.record_layouts(_as_tree(list(AS_API)))
    spelled = declared.anon_record_pointers  # type: ignore[attr-defined]
    assert spelled["str_check"] == {0: "str_t"}
    assert spelled["str_copy"] == {0: "str_t", 1: "str_t"}
    assert spelled["str_first"] == {-1: "str_t", 0: "kv_t"}
    assert spelled["num_get"] == {0: "num_t"}
    # A named struct and a struct with no name at all: nothing recorded.
    assert "holder_len" not in spelled and "anon_use" not in spelled


@pytest.mark.unit
def test_a_typedef_of_an_anonymous_record_is_no_opaque_handle():
    """clang 19 writes the typedef's type as `struct str_t`, a tag no header defines: not a handle."""
    _, declared = ah.record_layouts(_as_tree(list(AS_API)))
    protos = declared.prototypes  # type: ignore[attr-defined]
    for name, proto in protos.items():
        named = [*(proto.get("params") or []), proto.get("ret"), *(proto.get("outs") or {}).values()]
        assert not any(t and re.search(r"\b(str_t|kv_t|num_t|sbuf_t)\b", t) for t in named), (name, proto)


# --- the cases -------------------------------------------------------------------------------------------


@pytest.mark.unit
def test_pointers_to_anonymous_struct_typedefs_get_cases():
    """The nginx run-3 failure: every `ngx_str_t *` function was skipped as `pointer to an anonymous struct`."""
    p = _as_plan(list(AS_API))
    assert set(p["skipped"]) == {"lib.c#anon_use"}, p["skipped"]
    cases = _as_cases(p)
    for name, stmt in cases.items():
        assert "__anon" not in stmt, (name, stmt)
    # One object through the typedef, passed by address (the prototype's `const str_t *` takes it).
    assert "str_t c0a0; memset(&c0a0, 0, sizeof(c0a0));" in cases["str_check"]
    assert "(void)str_check(&c0a0);" in cases["str_check"]
    assert "(void)str_first(&c0a0);" in cases["str_first"]
    assert "num_t c0a0;" in cases["num_get"]


@pytest.mark.unit
def test_an_input_str_t_pairs_its_length_with_a_buffer_it_owns():
    """`{len, data}`: the length is read from the input, then clamped to the buffer `data` points to."""
    stmt = _as_cases(_as_plan(list(AS_API)))["str_check"]
    assert re.search(r"c0a0\.data = \(void \*\)c0a0f1;", stmt), stmt
    assert _clamped(stmt, "c0a0.len"), stmt
    # No input byte becomes a pointer: `data` is never the target of a copy from the input.
    assert "memcpy(&c0a0.data" not in stmt and "memcpy(&c0a0," not in stmt


@pytest.mark.unit
def test_records_of_anonymous_typedef_fields_are_filled_field_by_field():
    cases = _as_cases(_as_plan(list(AS_API)))
    kv = cases["kv_len"]
    for f in ("key", "value"):
        assert _clamped(kv, f"c0a0.{f}.len"), kv
        assert re.search(rf"c0a0\.{f}\.data = \(void \*\)\w+;", kv), kv
    # A named struct holding an ngx_str_t-like field: no longer zeroed for want of a layout.
    holder = cases["holder_len"]
    assert _clamped(holder, "c0a0.name.len") and "memcpy(&c0a0.x, " in holder, holder


@pytest.mark.unit
def test_outputs_and_sized_objects_are_declared_through_the_typedef():
    stmt = _as_cases(_as_plan(list(AS_API)))["str_copy"]
    # The destination: the call sites' 16 bytes, an array of `str_t`, cast to the header's type, zeroed.
    assert re.search(r"\bstr_t c0a0\[\(16 \+ sizeof\(str_t\) - 1\) / sizeof\(str_t\)\];", stmt), stmt
    assert "(void)str_copy((str_t *)c0a0, &c0a1);" in stmt, stmt
    assert "c0a0[0].len" not in stmt  # an output is not filled from the input
    assert _clamped(stmt, "c0a1.len"), stmt


@pytest.mark.unit
def test_an_anonymous_struct_typedef_gets_its_initializer_and_destructor():
    """sbuf_t has `sbuf_init` and `sbuf_free`: the case builds the object as for a named struct."""
    cases = _as_cases(_as_plan(list(AS_API)))
    put = cases["sbuf_put"]
    assert "sbuf_t c0a0; memset(&c0a0, 0, sizeof(c0a0));" in put, put
    init = "sbuf_init((sbuf_t *)&c0a0, "
    assert put.index(init) < put.index("sbuf_put(&c0a0, ") < put.index("(void)sbuf_free(&c0a0);"), put
    # The initializer's own case releases what it set up; the destructor's case runs after an initializer.
    assert "(void)sbuf_free(" in cases["sbuf_init"]
    free_ = cases["sbuf_free"]
    assert free_.index(init) < free_.index("(void)sbuf_free(&c0a0);"), free_
    assert free_.count("sbuf_free(") == 1


@pytest.mark.unit
def test_a_length_of_wider_elements_before_its_pointer_stays_zero():
    """GMP's `__mpz_struct { _mp_alloc, _mp_size, _mp_d }`: `_mp_size` counts limbs of a buffer the harness owns."""
    stmt = _as_cases(_as_plan(list(AS_API)))["big_top"]
    assert "big_t c0a0; memset(&c0a0, 0, sizeof(c0a0));" in stmt, stmt
    assert "memcpy(&c0a0.alloc_, " in stmt
    assert "memcpy(&c0a0.size, " not in stmt, stmt
    assert re.search(r"c0a0\.limbs = \(void \*\)\w+;", stmt), stmt
    lay = next(lay for lay in _as_plan(list(AS_API))["layouts"] if lay.get("entry") == "lib.c#big_top")
    assert any("field size" in n for n in lay.get("notes") or []), lay


@pytest.mark.unit
def test_a_struct_with_no_name_at_all_keeps_its_reason():
    p = _as_plan(list(AS_API))
    why = p["skipped"]["lib.c#anon_use"]
    assert why.startswith("pointer to an anonymous struct"), why
    # Without a probe nothing names a typedef: every such pointer is skipped with the same reason.
    p = _as_plan(["str_check", "num_get", "holder_len"], probed=False)
    assert p["skipped"]["lib.c#str_check"].startswith("pointer to an anonymous struct"), p["skipped"]
    assert p["skipped"]["lib.c#num_get"].startswith("pointer to an anonymous union"), p["skipped"]
    assert "lib.c#holder_len" not in p["skipped"]


@pytest.mark.unit
def test_an_initializer_of_a_struct_with_no_name_is_never_called():
    api = dict(AS_API)
    api["bare_init"] = (f"int({AS_BARE} *)", ["pointer"], ["struct (unnamed struct at lib.h:22:15) *"], "int")
    p = _as_plan(["anon_use", "bare_init", "str_check"], api=api)
    assert p["skipped"]["lib.c#bare_init"].startswith("pointer to an anonymous struct"), p["skipped"]
    assert p["skipped"]["lib.c#anon_use"].startswith("pointer to an anonymous struct"), p["skipped"]
    assert "bare_init" not in " ".join(p["cases"])


# --- end to end: real clang's AST of the header, then the cases compile and run ---------------------

AS_LIB_H = """#include <stddef.h>
typedef struct { size_t len; unsigned char *data; } str_t;
typedef struct { str_t key; str_t value; } kv_t;
typedef union { int i; float f; } num_t;
typedef struct { unsigned char *buf; size_t cap; size_t used; } sbuf_t;
typedef struct { int alloc_; int size; unsigned long *limbs; } big_t;
typedef big_t bignum[1];
struct holder { str_t name; int x; };
int str_check(const str_t *s);
int str_copy(str_t *dst, const str_t *src);
str_t *str_first(kv_t *kv);
size_t kv_len(const kv_t *kv);
int num_get(const num_t *n);
size_t holder_len(const struct holder *h);
int sbuf_init(sbuf_t *b, size_t cap);
int sbuf_put(sbuf_t *b, const unsigned char *p, size_t n);
void sbuf_free(sbuf_t *b);
int anon_use(struct { int a; int b; } *p);
unsigned long big_top(const bignum x);
"""

# Every function reads what its arguments point to, to their length: a length past its buffer is
# an ASan report, a NULL buffer with a length a SEGV.
AS_LIB_C = """#include <stdlib.h>
#include <string.h>
#include "lib.h"
static size_t sum(const str_t *s) {
    size_t i, h = 0;
    for (i = 0; i < s->len; i++) h += s->data[i];
    return h;
}
int str_check(const str_t *s) { return (int)(sum(s) & 0xff); }
int str_copy(str_t *dst, const str_t *src) {
    dst->len = src->len;
    dst->data = src->data;
    return (int)sum(dst);
}
str_t *str_first(kv_t *kv) { return &kv->key; }
size_t kv_len(const kv_t *kv) { return sum(&kv->key) + sum(&kv->value); }
int num_get(const num_t *n) { return n->i; }
size_t holder_len(const struct holder *h) { return sum(&h->name) + (size_t)(h->x & 1); }
int sbuf_init(sbuf_t *b, size_t cap) {
    if (cap > 4096) cap = 4096;
    b->buf = malloc(cap ? cap : 1);
    b->cap = b->buf ? cap : 0;
    b->used = 0;
    return b->buf ? 0 : -1;
}
int sbuf_put(sbuf_t *b, const unsigned char *p, size_t n) {
    if (b->buf == NULL || n > b->cap - b->used) return -1;
    memcpy(b->buf + b->used, p, n);
    b->used += n;
    return 0;
}
void sbuf_free(sbuf_t *b) { free(b->buf); b->buf = NULL; b->cap = b->used = 0; }
unsigned long big_top(const bignum x) { return x->size > 0 ? x->limbs[x->size - 1] : 0; }
"""

AS_AST_SCRIPT = "cd /fixture && clang -fsyntax-only -w -x c -Xclang -ast-dump=json lib.h"

AS_RUN_SCRIPT = r"""cp -r /fixture /tmp/w && cd /tmp/w
clang -fsyntax-only -Wall -Wno-visibility -Werror=incompatible-pointer-types -Werror=incompatible-pointer-types-discards-qualifiers -I. harness.c || exit 1
clang -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all -g -Wno-visibility -I. harness.c lib.c -o fz || exit 1
mkdir corpus
timeout 300 ./fz -runs=100000 -seed=7 -max_len=64 -detect_leaks=1 corpus > fz.log 2>&1 && echo FUZZ_CLEAN || tail -40 fz.log
"""


def _as_render(cases: list[str]) -> str:
    inv = gh._build_dispatch_invocation(cases)
    text = (AS_REPO / "templates" / "harness_dual.c.template").read_text(encoding="utf-8")
    for key, value in {
        "MODULE_NAME": "lib",
        "MODULE_HEADER": "lib.h",
        "MAX_INPUT_SIZE": "64",
        "TARGET_INVOCATION_EVA": inv,
        "TARGET_INVOCATION_FUZZ": inv,
    }.items():
        text = text.replace("{{" + key + "}}", value)
    return text


def _as_docker(tmp_path: Path, script: str, image: str) -> subprocess.CompletedProcess[str]:
    tag = os.environ.get("FRAMAC_RUN_TAG", "pytest-api-anon-struct")
    argv = [
        "docker", "run", "--rm", "--network", "none", "--label", f"framac.run={tag}",
        "-v", f"{tmp_path}:/fixture:ro", image, script,
    ]  # fmt: skip
    return subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900)


@pytest.mark.integration
def test_anonymous_struct_cases_compile_from_real_clang_and_run_clean(tmp_path):
    from conftest import ANALYSIS_IMAGE, require_docker_images

    require_docker_images(ANALYSIS_IMAGE)
    (tmp_path / "lib.h").write_text(AS_LIB_H, encoding="utf-8", newline="\n")
    (tmp_path / "lib.c").write_text(AS_LIB_C, encoding="utf-8", newline="\n")
    ast = _as_docker(tmp_path, AS_AST_SCRIPT, ANALYSIS_IMAGE)
    assert ast.returncode == 0, ast.stderr[-2000:]
    # The spellings and layouts come from clang's own AST of the header, not from a hand-written tree.
    p = _as_plan(list(AS_API), tree=json.loads(ast.stdout))
    assert set(p["skipped"]) == {"lib.c#anon_use"}, p["skipped"]
    cases = _as_cases(p)
    assert "str_t c0a0;" in cases["str_check"] and _clamped(cases["str_check"], "c0a0.len")
    assert _clamped(cases["kv_len"], "c0a0.value.len")
    (tmp_path / "harness.c").write_text(_as_render(p["cases"]), encoding="utf-8", newline="\n")
    proc = _as_docker(tmp_path, AS_RUN_SCRIPT, ANALYSIS_IMAGE)
    # A length past its buffer would be an ASan report; a type the compiler refuses fails the build.
    assert "FUZZ_CLEAN" in proc.stdout, (proc.stdout + proc.stderr)[-4000:]
