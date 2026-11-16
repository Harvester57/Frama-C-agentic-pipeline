"""
Pointers to anonymous enums (c-ares run-1, 2026-11-16): c-ares declares its enums as typedefs of
anonymous enums (`typedef enum { ... } ares_dns_class_t;`), which the Phase 0 model spells with
Frama-C's generated tag (`enum __anonenum_ares_dns_class_t_7 *`). The `--api` generator refused
any pointer whose pointee held `__anon`, calling it "a pointer to an anonymous struct", so
`ares_dns_class_fromstr`, `ares_dns_rec_type_fromstr` and `ares_dns_record_query_get` had no case.
An enum is an integer type: the case declares the object through the header's typedef, which the
layout probe reads from each declaration as written.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest

import api_harness as ah
import generate_harness as gh

AE_REPO = Path(__file__).resolve().parents[1]
AE_ST = "enum __anonenum_st_t_1"
AE_RTYPE = "enum __anonenum_rtype_t_6"
AE_CLS = "enum __anonenum_cls_t_7"

# name -> (model signature, formal kinds, the declaration's parameter types as clang writes them, return).
ANON_ENUM_API: dict[str, tuple[str, list[str], list[str], str]] = {
    "qrec_create": (
        f"{AE_ST}(struct qrec **,unsigned short)",
        ["pointer", "value"],
        ["qrec_t **", "unsigned short"],
        "st_t",
    ),
    "qrec_destroy": ("void(struct qrec *)", ["pointer"], ["qrec_t *"], "void"),
    "qrec_query_get": (
        f"{AE_ST}(struct qrec *,unsigned long,char **,{AE_RTYPE} *,{AE_CLS} *)",
        ["const_pointer", "value", "pointer", "pointer", "pointer"],
        ["const qrec_t *", "size_t", "const char **", "rtype_t *", "cls_t *"],
        "st_t",
    ),
    "cls_fromstr": (f"int({AE_CLS} *,char *)", ["pointer", "const_pointer"], ["cls_t *", "const char *"], "int"),
    "rtype_fromstr": (f"int({AE_RTYPE} *,char *)", ["pointer", "const_pointer"], ["rtype_t *", "const char *"], "int"),
    "cls_tostr": (f"char *({AE_CLS})", ["value"], ["cls_t"], "const char *"),
}
# The model's call-site sizes, as c-ares run-1's model has them for the three functions.
ANON_ENUM_SIZES: dict[str, dict[str, dict[str, int]]] = {
    "qrec_create": {"0": {"min": 8, "max": 8, "sites": 2}},
    "qrec_query_get": {
        "2": {"min": 8, "max": 8, "sites": 10},
        "3": {"min": 4, "max": 4, "sites": 6},
        "4": {"min": 4, "max": 4, "sites": 5},
    },
    "cls_fromstr": {"0": {"min": 4, "max": 4, "sites": 2}},
    "rtype_fromstr": {"0": {"min": 4, "max": 4, "sites": 2}},
}


def _enum_records(names: list[str], sizes: bool = True) -> dict[str, dict]:
    out = {}
    for n in names:
        sig, kinds, _, _ = ANON_ENUM_API[n]
        rec: dict[str, Any] = {
            "name": n,
            "signature": sig,
            "formals": [{"name": f"p{i}", "kind": k} for i, k in enumerate(kinds)],
        }
        if sizes and n in ANON_ENUM_SIZES:
            rec["param_sizes"] = ANON_ENUM_SIZES[n]
        out[n] = rec
    return out


def _enum_tree(names: list[str], typedefs: bool = True) -> dict:
    """A clang JSON AST of the header, as clang 18 writes it (`typedef enum { ... } cls_t;`)."""
    inner: list[dict] = [{"kind": "RecordDecl", "name": "qrec", "tagUsed": "struct"}]
    inner.append({"kind": "TypedefDecl", "name": "qrec_t", "type": {"qualType": "struct qrec"}})
    inner.append({"kind": "TypedefDecl", "name": "size_t", "type": {"qualType": "unsigned long"}})
    for t in ("st_t", "rtype_t", "cls_t"):
        if typedefs:
            inner.append({"kind": "TypedefDecl", "name": t, "type": {"qualType": f"enum {t}"}})
    for n in names:
        _, _, params, ret = ANON_ENUM_API[n]
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


def _enum_plan(names: list[str], tree: dict | None = None, sizes: bool = True, probed: bool = True) -> dict[str, Any]:
    functions = {f"lib.c#{n}": {"name": n, "file": "lib.c"} for n in names}
    dag = {
        "warnings": [],
        "modules": {"lib": {"functions": list(functions), "candidate_entry_points": list(functions)}},
        "functions": functions,
    }
    recs = _enum_records(names, sizes)
    model = {"status": "ok", "functions": {f"lib.c#{n}": recs[n] for n in names}}
    if not probed:
        return ah.plan(dag, model, "lib", "lib", 64, [], None, None, None)
    layouts, declared = ah.record_layouts(tree if tree is not None else _enum_tree(names))
    return ah.plan(dag, model, "lib", "lib", 64, [], None, layouts, declared)


def _enum_cases(p: dict[str, Any]) -> dict[str, str]:
    return {lay["entry"].split("#")[-1]: p["cases"][k] for k, lay in enumerate(p["layouts"]) if lay.get("entry")}


@pytest.mark.unit
def test_the_probe_spells_enum_pointer_parameters_through_the_header_typedef():
    _, declared = ah.record_layouts(_enum_tree(list(ANON_ENUM_API)))
    enums = declared.enum_pointers  # type: ignore[attr-defined]
    assert enums["cls_fromstr"] == {0: {"type": "cls_t *", "pointee": "cls_t"}}
    assert enums["qrec_query_get"] == {
        3: {"type": "rtype_t *", "pointee": "rtype_t"},
        4: {"type": "cls_t *", "pointee": "cls_t"},
    }
    # No pointer to an enum: nothing recorded (a handle, a by-value enum, a string).
    assert "qrec_create" not in enums and "cls_tostr" not in enums


@pytest.mark.unit
def test_pointers_to_anonymous_enums_get_cases_through_the_typedef():
    """The c-ares run-1 failure: the three functions were skipped as `pointer to an anonymous struct`."""
    p = _enum_plan(list(ANON_ENUM_API))
    assert p["skipped"] == {}
    cases = _enum_cases(p)
    for name, stmt in cases.items():
        assert "__anon" not in stmt, (name, stmt)
    cls = cases["cls_fromstr"]
    # The model's call sites pass 4 bytes: an array of one `cls_t`, cast to the header's type.
    assert re.search(r"\bcls_t c0a0\[\(4 \+ sizeof\(cls_t\) - 1\) / sizeof\(cls_t\)\];", cls), cls
    assert "(void)cls_fromstr((cls_t *)c0a0, (char *)c0a1);" in cls
    assert "(void)rtype_fromstr((rtype_t *)c0a0, (char *)c0a1);" in cases["rtype_fromstr"]


@pytest.mark.unit
def test_every_out_parameter_of_query_get_is_bound():
    stmt = _enum_cases(_enum_plan(list(ANON_ENUM_API)))["qrec_query_get"]
    m = re.search(r"\(void\)qrec_query_get\(([^;]*)\);", stmt)
    assert m, stmt
    args = [a.strip() for a in m.group(1).split(",")]
    # `const char **name` keeps its nested `const` (test_api_harness_nested_const.py).
    assert args == ["(struct qrec *)c0a0", "c0a1", "(const char **)c0a2", "(rtype_t *)c0a3", "(cls_t *)c0a4"]
    assert "rtype_t c0a3[" in stmt and "cls_t c0a4[" in stmt
    # The record handle is built through its out-parameter constructor and released after the call.
    assert stmt.index("qrec_create(") < stmt.index("qrec_query_get(") < stmt.index("qrec_destroy(")


@pytest.mark.unit
def test_without_call_site_sizes_the_enum_is_one_object_passed_by_address():
    cases = _enum_cases(_enum_plan(list(ANON_ENUM_API), sizes=False))
    cls = cases["cls_fromstr"]
    assert "cls_t c0a0; memset(&c0a0, 0, sizeof(c0a0));" in cls
    assert "(void)cls_fromstr(&c0a0, " in cls
    get = cases["qrec_query_get"]
    assert "rtype_t c0a3;" in get and "cls_t c0a4;" in get and ", &c0a3, &c0a4);" in get


@pytest.mark.unit
def test_an_anonymous_enum_without_a_typedef_name_is_skipped_as_an_enum():
    # No probe: nothing names the enum; the case is skipped, and the reason does not say struct.
    p = _enum_plan(["cls_fromstr", "cls_tostr"], probed=False)
    why = p["skipped"]["lib.c#cls_fromstr"]
    assert "anonymous enum" in why and "struct" not in why, why
    assert AE_CLS in why
    # A by-value anonymous enum is an integer: it keeps its case.
    assert "lib.c#cls_tostr" not in p["skipped"]
    assert "int c0a0;" in _enum_cases(p)["cls_tostr"]
    # A header whose typedef the probe cannot see (an unnamed enum, no typedef): the same reason.
    p = _enum_plan(["cls_fromstr"], tree=_enum_tree(["cls_fromstr"], typedefs=False))
    assert "anonymous enum" in p["skipped"]["lib.c#cls_fromstr"]


@pytest.mark.unit
def test_pointers_to_anonymous_structs_keep_their_reason():
    assert ah.plan_params("int(struct __anonstruct_opts_t_3 *)") == (None, "pointer to an anonymous struct")
    assert ah.plan_params("int(union __anonunion_val_t_4 *)") == (None, "pointer to an anonymous union")
    assert ah.plan_params("int(struct __anonstruct_opts_t_3)")[1] == "anonymous struct by value"
    params, why = ah.plan_params(f"int({AE_CLS} *,char *)")
    assert why is None and params is not None and params[0].get("anon_enum") is True


# --- end to end: real clang's AST of the header, then the cases compile and run ---------------------

ENUM_LIB_H = """#include <stddef.h>
typedef enum { ST_OK = 0, ST_EBAD = 1, ST_ENOMEM = 2 } st_t;
typedef enum { RT_A = 1, RT_TXT = 16, RT_ANY = 255 } rtype_t;
typedef enum { CLS_IN = 1, CLS_CH = 3, CLS_ANY = 255 } cls_t;
typedef struct qrec qrec_t;
st_t qrec_create(qrec_t **out, unsigned short id);
void qrec_destroy(qrec_t *r);
st_t qrec_query_get(const qrec_t *r, size_t idx, const char **name, rtype_t *qtype, cls_t *qclass);
int cls_fromstr(cls_t *c, const char *s);
int rtype_fromstr(rtype_t *t, const char *s);
const char *cls_tostr(cls_t c);
"""

ENUM_LIB_C = """#include <stdlib.h>
#include <string.h>
#include "lib.h"
struct qrec { unsigned short id; const char *name; rtype_t type; cls_t cls; };
st_t qrec_create(qrec_t **out, unsigned short id) {
    qrec_t *r;
    *out = NULL;
    r = calloc(1, sizeof *r);
    if (r == NULL) return ST_ENOMEM;
    r->id = id; r->name = "q"; r->type = RT_A; r->cls = CLS_IN; *out = r;
    return ST_OK;
}
void qrec_destroy(qrec_t *r) { free(r); }
st_t qrec_query_get(const qrec_t *r, size_t idx, const char **name, rtype_t *qtype, cls_t *qclass) {
    if (idx != 0) return ST_EBAD;
    *name = r->name; *qtype = r->type; *qclass = r->cls;
    return ST_OK;
}
int cls_fromstr(cls_t *c, const char *s) {
    if (strcmp(s, "CH") == 0) { *c = CLS_CH; return 1; }
    *c = CLS_IN;
    return 1;
}
int rtype_fromstr(rtype_t *t, const char *s) { *t = s[0] == 'T' ? RT_TXT : RT_A; return 1; }
const char *cls_tostr(cls_t c) { return c == CLS_CH ? "CH" : "IN"; }
"""

ENUM_AST_SCRIPT = "cd /fixture && clang -fsyntax-only -x c -Xclang -ast-dump=json lib.h"

ENUM_RUN_SCRIPT = r"""cp -r /fixture /tmp/w && cd /tmp/w
clang -fsyntax-only -Wall -Werror=incompatible-pointer-types -Werror=incompatible-pointer-types-discards-qualifiers -I. harness.c || exit 1
clang -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all -g -I. harness.c lib.c -o fz || exit 1
mkdir corpus
./fz -runs=100000 -seed=7 -max_len=64 -detect_leaks=1 corpus > fz.log 2>&1 && echo FUZZ_CLEAN || tail -40 fz.log
"""


def _enum_render(cases: list[str]) -> str:
    inv = gh._build_dispatch_invocation(cases)
    text = (AE_REPO / "templates" / "harness_dual.c.template").read_text(encoding="utf-8")
    for key, value in {
        "MODULE_NAME": "lib",
        "MODULE_HEADER": "lib.h",
        "MAX_INPUT_SIZE": "64",
        "TARGET_INVOCATION_EVA": inv,
        "TARGET_INVOCATION_FUZZ": inv,
    }.items():
        text = text.replace("{{" + key + "}}", value)
    return text


def _docker(tmp_path: Path, script: str, image: str) -> subprocess.CompletedProcess[str]:
    argv = ["docker", "run", "--rm", "--network", "none", "-v", f"{tmp_path}:/fixture:ro", image, script]
    return subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900)


@pytest.mark.integration
def test_anonymous_enum_cases_compile_from_real_clang_and_run_clean(tmp_path):
    from conftest import ANALYSIS_IMAGE, require_docker_images

    require_docker_images(ANALYSIS_IMAGE)
    (tmp_path / "lib.h").write_text(ENUM_LIB_H, encoding="utf-8")
    (tmp_path / "lib.c").write_text(ENUM_LIB_C, encoding="utf-8")
    ast = _docker(tmp_path, ENUM_AST_SCRIPT, ANALYSIS_IMAGE)
    assert ast.returncode == 0, ast.stderr[-2000:]
    # The spellings come from clang's own AST of the header, not from a hand-written tree.
    p = _enum_plan(list(ANON_ENUM_API), tree=json.loads(ast.stdout))
    assert p["skipped"] == {}
    cases = _enum_cases(p)
    assert "(cls_t *)c0a0" in cases["cls_fromstr"]
    assert "(rtype_t *)c0a3, (cls_t *)c0a4" in cases["qrec_query_get"]
    kinds = [lay["kind"] for lay in p["layouts"]]
    assert "lifecycle" in kinds  # qrec_query_get is a method of the record's lifecycle case too
    (tmp_path / "harness.c").write_text(_enum_render(p["cases"]), encoding="utf-8")
    proc = _docker(tmp_path, ENUM_RUN_SCRIPT, ANALYSIS_IMAGE)
    # An object smaller than the enum the library writes would be an ASan report; a type the
    # compiler refuses fails the build.
    assert "FUZZ_CLEAN" in proc.stdout, (proc.stdout + proc.stderr)[-4000:]
