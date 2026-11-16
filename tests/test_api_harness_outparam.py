"""
Opaque handles built through out-parameter constructors (c-ares run-1, 2026-11-16): c-ares's handles
are pointers to structs its public headers only declare, made by `ares_status_t
ares_dns_record_create(ares_dns_record_t **dnsrec, ...)`, `int ares_init(ares_channel_t **)`,
`ares_dns_parse(buf, len, flags, ares_dns_record_t **)` and, for a child handle the record owns,
`ares_dns_record_rr_add(ares_dns_rr_t **rr_out, ares_dns_record_t *dnsrec, ...)`. The `--api`
generator knew only constructors that return the handle, so every case taking one declared a stack
object of the incomplete struct (`variable has incomplete type 'struct ares_dns_record'`).
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

import pytest

import api_harness as ah
import generate_harness as gh
import validate_artifacts as va

REPO = Path(__file__).resolve().parents[1]
REC = "struct rec *"
RR = "struct rr *"
CHAN = "struct chan *"
ST = "enum __anonenum_st_t_1"

# name -> (model signature, formal kinds, the declaration's parameter types as clang writes them).
OUTPARAM_API: dict[str, tuple[str, list[str], list[str], str]] = {
    "rec_create": (
        f"{ST}(struct rec **,unsigned short,unsigned short)",
        ["pointer", "value", "value"],
        ["rec_t **", "unsigned short", "unsigned short"],
        "st_t",
    ),
    "rec_destroy": ("void(struct rec *)", ["pointer"], ["rec_t *"], "void"),
    "rec_get_id": ("unsigned short(struct rec *)", ["const_pointer"], ["const rec_t *"], "unsigned short"),
    "rec_set_id": (f"{ST}(struct rec *,unsigned short)", ["pointer", "value"], ["rec_t *", "unsigned short"], "st_t"),
    "rec_rr_add": (
        f"{ST}(struct rr **,struct rec *,char *,enum __anonenum_rr_type_t_2,unsigned int)",
        ["pointer", "pointer", "const_pointer", "value", "value"],
        ["rr_t **", "rec_t *", "const char *", "rr_type_t", "unsigned int"],
        "st_t",
    ),
    "rec_parse": (
        f"{ST}(unsigned char *,unsigned long,struct rec **)",
        ["const_pointer", "value", "pointer"],
        ["const unsigned char *", "size_t", "rec_t **"],
        "st_t",
    ),
    "rr_get_ttl": ("unsigned int(struct rr *)", ["const_pointer"], ["const rr_t *"], "unsigned int"),
    "rr_set_name": (f"{ST}(struct rr *,char *)", ["pointer", "const_pointer"], ["rr_t *", "const char *"], "st_t"),
    "chan_init": ("int(struct chan **)", ["pointer"], ["chan_t **"], "int"),
    "chan_destroy": ("void(struct chan *)", ["pointer"], ["chan_t *"], "void"),
    "chan_set_timeout": ("int(struct chan *,int)", ["pointer", "value"], ["chan_t *", "int"], "int"),
}
# The model's call-site sizes of the out-parameters (c-ares's model has them: a pointer is 8 bytes).
OUT_SIZES = {"rec_create": 0, "rec_rr_add": 0, "rec_parse": 2, "chan_init": 0}


def _records(names: list[str]) -> dict[str, dict]:
    out = {}
    for n in names:
        sig, kinds, _, _ = OUTPARAM_API[n]
        rec: dict[str, Any] = {
            "name": n,
            "signature": sig,
            "formals": [{"name": f"p{i}", "kind": k} for i, k in enumerate(kinds)],
        }
        if n in OUT_SIZES:
            rec["param_sizes"] = {str(OUT_SIZES[n]): {"min": 8, "max": 8, "sites": 2}}
        out[n] = rec
    return out


def _tree(names: list[str]) -> dict:
    """clang's JSON AST of the public header: the structs are declared, never defined."""
    inner: list[dict] = []
    for tag in ("rec", "rr", "chan"):
        inner.append({"kind": "RecordDecl", "name": tag, "tagUsed": "struct"})
        inner.append({"kind": "TypedefDecl", "name": f"{tag}_t", "type": {"qualType": f"struct {tag}"}})
    inner.append({"kind": "TypedefDecl", "name": "st_t", "type": {"qualType": "enum st_t"}})
    inner.append({"kind": "TypedefDecl", "name": "rr_type_t", "type": {"qualType": "enum rr_type_t"}})
    inner.append({"kind": "TypedefDecl", "name": "size_t", "type": {"qualType": "unsigned long"}})
    for n in names:
        _, _, params, ret = OUTPARAM_API[n]
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


def _plan(names: list[str], traces: list[list[dict]] | None = None) -> dict[str, Any]:
    functions = {f"lib.c#{n}": {"name": n, "file": "lib.c"} for n in names}
    dag = {
        "warnings": [],
        "modules": {"lib": {"functions": list(functions), "candidate_entry_points": list(functions)}},
        "functions": functions,
    }
    recs = _records(names)
    model = {"status": "ok", "functions": {f"lib.c#{n}": recs[n] for n in names}}
    layouts, declared = ah.record_layouts(_tree(names))
    return ah.plan(dag, model, "lib", "lib", 64, traces or [], None, layouts, declared)


def _cases(p: dict[str, Any]) -> dict[str, str]:
    return {lay["entry"].split("#")[-1]: p["cases"][k] for k, lay in enumerate(p["layouts"]) if lay.get("entry")}


_STACK_OBJECT_RE = re.compile(r"\bstruct (?:rec|rr|chan) c\d+a\d+\b")


@pytest.mark.unit
def test_the_probe_records_out_parameter_handles_beside_the_handles_taken():
    _, declared = ah.record_layouts(_tree(list(OUTPARAM_API)))
    protos = declared.prototypes  # type: ignore[attr-defined]
    assert protos["rec_create"] == {"ret": None, "params": [None, None, None], "outs": {0: REC}}
    assert protos["rec_rr_add"] == {"ret": None, "params": [None, REC, None, None, None], "outs": {0: RR}}
    assert protos["rec_parse"]["outs"] == {2: REC}
    assert protos["rec_get_id"] == {"ret": None, "params": [REC]}


@pytest.mark.unit
def test_every_case_on_an_opaque_handle_builds_it_through_its_out_parameter_constructor():
    """The c-ares run-1 failure: no case may declare an object of an incomplete struct."""
    p = _plan(list(OUTPARAM_API))
    assert p["skipped"] == {}
    cases = _cases(p)
    assert set(cases) == set(OUTPARAM_API)
    for name, stmt in cases.items():
        assert not _STACK_OBJECT_RE.search(stmt), (name, stmt)
    # A getter: the record is built through its out-parameter, used only when built, then destroyed.
    get = cases["rec_get_id"]
    assert f"{REC} c0a0 = 0;" in get
    assert "(void)rec_create((struct rec **)&c0a0, c1a1, c1a2);" in get
    assert "if (c0a0 != 0) { (void)rec_get_id((struct rec *)c0a0); }" in get
    assert get.count("rec_destroy(") == 1 and "if (c0a0 != 0) { (void)rec_destroy(c0a0); }" in get
    assert get.index("rec_create(") < get.index("rec_get_id(") < get.index("rec_destroy(")
    lay = next(lay for lay in p["layouts"] if lay.get("entry") == "lib.c#rec_get_id")
    assert lay["inits"] == [{"fn": "rec_create", "call": 1, "for": {"call": 0, "param": 0}}]
    # The destructor's own case releases nothing twice.
    assert cases["rec_destroy"].count("rec_destroy(") == 1 and "rec_create(" in cases["rec_destroy"]
    # The channel: the same shape, its own constructor and destructor.
    assert "(void)chan_init((struct chan **)&c0a0);" in cases["chan_set_timeout"]
    assert "(void)chan_destroy(c0a0);" in cases["chan_set_timeout"]


@pytest.mark.unit
def test_a_child_handle_is_added_to_a_built_parent_and_released_with_it():
    cases = _cases(_plan(list(OUTPARAM_API)))
    ttl = cases["rr_get_ttl"]
    # The record first, then the record set added to it; the record set has no destructor of its own:
    # the record owns it, so only the record is destroyed, after the call.
    assert ttl.index("rec_create(") < ttl.index("rec_rr_add(") < ttl.index("rr_get_ttl(") < ttl.index("rec_destroy(")
    assert f"{RR} c0a0 = 0;" in ttl and "(struct rr **)&c0a0" in ttl
    assert "if (c0a0 != 0) { (void)rr_get_ttl((struct rr *)c0a0); }" in ttl
    assert ttl.count("rec_destroy(") == 1 and "rr_destroy" not in ttl
    # The child's constructor runs only on a built parent.
    assert re.search(r"if \(c0a0p != 0\) \{ \(void\)rec_rr_add\(\(struct rr \*\*\)&c0a0, \(struct rec \*\)c0a0p,", ttl)
    # The setter's string still takes the rest of the input, not the constructor's name argument.
    name = cases["rr_set_name"]
    assert "rr_set_name((struct rr *)c0a0, (char *)c0a1)" in name
    assert "memcpy(c0a1, FRAMAC_FUZZ_COPY(fuzz_buf, fuzz_off), rest_n)" in name


@pytest.mark.unit
def test_the_constructors_own_cases_release_what_they_build():
    cases = _cases(_plan(list(OUTPARAM_API)))
    create = cases["rec_create"]
    assert "if (c0a0 != 0) { (void)rec_destroy(c0a0); }" in create and create.count("rec_create(") == 1
    # A parser is a constructor too: its record is released, and nothing builds one before it.
    parse = cases["rec_parse"]
    assert "rec_create(" not in parse and "if (c0a2 != 0) { (void)rec_destroy(c0a2); }" in parse
    assert f"{REC} c0a2 = 0;" in parse
    # The child adder: its record set belongs to the record, which is destroyed; nothing else.
    add = cases["rec_rr_add"]
    assert "rr_destroy" not in add and add.count("rec_destroy(") == 1
    assert add.index("rec_create(") < add.index("rec_rr_add(") < add.index("rec_destroy(")


@pytest.mark.unit
def test_constructor_choice_traces_first_then_the_plainest_name():
    assert "rec_create(" in _cases(_plan(list(OUTPARAM_API)))["rec_set_id"]
    trace = [{"fn": "rec_parse", "addrs": {}}, {"fn": "rec_get_id", "addrs": {}}]
    stmt = _cases(_plan(list(OUTPARAM_API), [trace]))["rec_set_id"]
    assert "rec_parse(" in stmt and "rec_create(" not in stmt


@pytest.mark.unit
def test_no_constructor_skips_with_a_precise_reason_instead_of_an_incomplete_object():
    names = [n for n in OUTPARAM_API if n != "chan_init"]
    p = _plan(names)
    assert p["skipped"] == {
        "lib.c#chan_destroy": f"no constructor for opaque handle {CHAN}",
        "lib.c#chan_set_timeout": f"no constructor for opaque handle {CHAN}",
    }
    # Without the record's constructors, its child cannot be built either.
    p = _plan([n for n in OUTPARAM_API if n not in ("rec_create", "rec_parse")])
    assert p["skipped"]["lib.c#rec_get_id"] == f"no constructor for opaque handle {REC}"
    assert p["skipped"]["lib.c#rr_get_ttl"] == f"no constructor for opaque handle {REC}"
    for stmt in p["cases"]:
        assert not _STACK_OBJECT_RE.search(stmt), stmt


@pytest.mark.unit
def test_out_parameter_constructors_feed_the_lifecycle_cases():
    p = _plan(list(OUTPARAM_API))
    life = {lay["handle"]: (p["cases"][k], lay) for k, lay in enumerate(p["layouts"]) if lay["kind"] == "lifecycle"}
    assert set(life) == {REC, CHAN}  # the record set has no destructor: no lifecycle of its own
    stmt, lay = life[REC]
    assert lay["calls"] == ["rec_create", "rec_destroy"]
    assert f"{REC} fc_h = 0;" in stmt and "(void)rec_create((struct rec **)&fc_h, c0a1, c0a2);" in stmt
    assert "rec_parse" not in lay["methods"] and "rec_rr_add" in lay["methods"]
    assert stmt.endswith("(void)rec_destroy(fc_h); } (void)fuzz_off;")
    assert [(s["call"], s["param"]) for s in lay["slots"]] == [(0, 1), (0, 2)]
    assert not _STACK_OBJECT_RE.search(stmt)
    lay["selector"] = 0
    side = {
        "module": "lib",
        "harness_file": "harness_lib.c",
        "sources": ["lib.c"],
        "cppflags": "",
        "entry_fn": "rec_create",
        "entry_style": "dispatch",
        "dispatch_cases": [stmt],
        "api_harness": True,
        "api_cases": [lay],
    }
    assert list(va.validate_sidecar(side, "lib")) == []


@pytest.mark.unit
def test_return_style_handles_are_unchanged_and_initializers_skip_pointer_pointees():
    # A `T **` first parameter is not "a pointer to that struct": no initializer for `struct rec *`.
    recs = _records(["rec_create", "rec_parse"])
    inits, cands, _ = ah.initializers({f"lib.c#{n}": r for n, r in recs.items()})
    assert inits == {} and cands == {}


@pytest.mark.unit
def test_api_without_header_warns_and_names_the_public_headers(tmp_path, monkeypatch, capsys):
    """c-ares run-1: without --header, 18 of 19 cases were dropped as `call to undeclared function`."""
    import json

    from test_api_harness import _gen, _generate_fixture

    out, _ = _generate_fixture(tmp_path, monkeypatch, ["a", "b"])
    monkeypatch.setattr(ah, "probe_cases", lambda *a, **k: ({}, []))
    capture = {"public_headers": {"method": "install", "files": ["/framac-scratch/install/include/ares.h"]}}
    (tmp_path / "build_capture.json").write_text(json.dumps(capture), encoding="utf-8")
    res = _gen(out)
    assert len(res["api_warnings"]) == 1
    warning = res["api_warnings"][0]
    assert "--api without --header" in warning and "ares.h" in warning
    assert f"api_harness: warning: {warning}" in capsys.readouterr().err
    # With a header there is nothing to say.
    res = ah.generate(
        "lib",
        "lib.h",
        64,
        "",
        out,
        unit="lib",
        dag_path=Path("dag.json"),
        model_path=Path("model.json"),
        traces_path=Path("none/traces.jsonl"),
    )
    assert "api_warnings" not in res


# --- end to end: the cases compile and run against a c-ares-shaped library -------------------------

LIB_H = """#include <stddef.h>
typedef enum { ST_OK = 0, ST_ENOMEM = 1, ST_EBAD = 2 } st_t;
typedef enum { RR_A = 1, RR_TXT = 16 } rr_type_t;
typedef struct rec rec_t;
typedef struct rr rr_t;
typedef struct chan chan_t;
st_t rec_create(rec_t **out, unsigned short id, unsigned short flags);
void rec_destroy(rec_t *r);
unsigned short rec_get_id(const rec_t *r);
st_t rec_set_id(rec_t *r, unsigned short id);
st_t rec_rr_add(rr_t **rr_out, rec_t *r, const char *name, rr_type_t type, unsigned int ttl);
st_t rec_parse(const unsigned char *buf, size_t len, rec_t **out);
unsigned int rr_get_ttl(const rr_t *rr);
st_t rr_set_name(rr_t *rr, const char *name);
int chan_init(chan_t **out);
void chan_destroy(chan_t *c);
int chan_set_timeout(chan_t *c, int ms);
"""

LIB_C = """#include <stdlib.h>
#include <string.h>
#include "lib.h"
struct rr { char name[16]; rr_type_t type; unsigned int ttl; };
struct rec { unsigned short id; unsigned short flags; size_t n; struct rr *rrs[4]; };
struct chan { int timeout; };
st_t rec_create(rec_t **out, unsigned short id, unsigned short flags) {
    rec_t *r;
    if (out == NULL) return ST_EBAD;
    *out = NULL;
    r = calloc(1, sizeof *r);
    if (r == NULL) return ST_ENOMEM;
    r->id = id; r->flags = flags; *out = r;
    return ST_OK;
}
void rec_destroy(rec_t *r) {
    size_t i;
    if (r == NULL) return;
    for (i = 0; i < r->n; i++) free(r->rrs[i]);
    free(r);
}
unsigned short rec_get_id(const rec_t *r) { return r->id; }
st_t rec_set_id(rec_t *r, unsigned short id) { r->id = id; return ST_OK; }
st_t rec_rr_add(rr_t **rr_out, rec_t *r, const char *name, rr_type_t type, unsigned int ttl) {
    rr_t *rr;
    if (r->n >= 4) return ST_ENOMEM;
    rr = calloc(1, sizeof *rr);
    if (rr == NULL) return ST_ENOMEM;
    strncpy(rr->name, name, sizeof rr->name - 1);
    rr->type = type; rr->ttl = ttl;
    r->rrs[r->n++] = rr;
    *rr_out = rr;
    return ST_OK;
}
st_t rec_parse(const unsigned char *buf, size_t len, rec_t **out) {
    if (len < 4) return ST_EBAD;
    return rec_create(out, (unsigned short)(buf[0] | (buf[1] << 8)), (unsigned short)(buf[2] | (buf[3] << 8)));
}
unsigned int rr_get_ttl(const rr_t *rr) { return rr->ttl; }
st_t rr_set_name(rr_t *rr, const char *name) {
    strncpy(rr->name, name, sizeof rr->name - 1);
    return ST_OK;
}
int chan_init(chan_t **out) { *out = calloc(1, sizeof **out); return *out == NULL ? -1 : 0; }
void chan_destroy(chan_t *c) { free(c); }
int chan_set_timeout(chan_t *c, int ms) { c->timeout = ms; return 0; }
"""

OUTPARAM_SCRIPT = r"""cp -r /fixture /tmp/w && cd /tmp/w
clang -fsyntax-only -Wall -I. harness.c || exit 1
clang -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all -g -I. harness.c lib.c -o fz || exit 1
mkdir corpus
./fz -runs=200000 -seed=5 -max_len=64 -detect_leaks=1 corpus > fz.log 2>&1 && echo FUZZ_CLEAN || tail -40 fz.log
"""


def _render(cases: list[str]) -> str:
    inv = gh._build_dispatch_invocation(cases)
    text = (REPO / "templates" / "harness_dual.c.template").read_text(encoding="utf-8")
    for key, value in {
        "MODULE_NAME": "lib",
        "MODULE_HEADER": "lib.h",
        "MAX_INPUT_SIZE": "64",
        "TARGET_INVOCATION_EVA": inv,
        "TARGET_INVOCATION_FUZZ": inv,
    }.items():
        text = text.replace("{{" + key + "}}", value)
    return text


@pytest.mark.integration
def test_out_parameter_cases_compile_and_run_without_leaks_or_null_handles(tmp_path):
    from conftest import ANALYSIS_IMAGE, require_docker_images

    require_docker_images(ANALYSIS_IMAGE)
    p = _plan(list(OUTPARAM_API))
    assert p["skipped"] == {}
    (tmp_path / "lib.h").write_text(LIB_H, encoding="utf-8")
    (tmp_path / "lib.c").write_text(LIB_C, encoding="utf-8")
    (tmp_path / "harness.c").write_text(_render(p["cases"]), encoding="utf-8")
    argv = ["docker", "run", "--rm", "--network", "none", "-v", f"{tmp_path}:/fixture:ro", ANALYSIS_IMAGE]
    proc = subprocess.run(
        [*argv, OUTPARAM_SCRIPT], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900
    )
    out = proc.stdout + proc.stderr
    # The library dereferences its handles unchecked: a NULL or zeroed handle would crash; a handle
    # the case does not release would leak.
    assert "FUZZ_CLEAN" in proc.stdout, out[-4000:]
