"""
`--api` cases on objects the harness does not own (sudo run-1, module `liblogsrv_a`, protobuf-c).

Two fingerprints, six artifacts each, all from the generated harness:

  - `do_free` SEGV at `0xfffffffffffffff8`: `change_window_size__free_unpacked(&c0a0, &c0a1)` on a
    stack message that only went through `change_window_size__init`, with an all-zero
    `ProtobufCAllocator` (NULL `alloc` and `free`). `X__free_unpacked` frees a message `X__unpack`
    returned, with that allocator or NULL (the default);
  - `do_alloc` SEGV: every `X__unpack` case passed a memset-zero `ProtobufCAllocator`, so the first
    allocation called a NULL `alloc`.

The generator now:

  - passes a pointer to a table of function pointers (an allocator, an ops table, a sink) as NULL
    when a doc comment of the headers says a NULL one of that type selects the default
    (`null_default_records`), else as an object whose function pointers are harness functions
    (malloc/free wrappers for an allocator, no-op stubs otherwise), else skips the case: never a
    NULL function pointer the callee calls;
  - gives a destructor that also takes such a table (`X__free_unpacked(X *, Alloc *)`) only an
    object its producer returned in the same case (`X__unpack`, guarded on NULL), and releases what
    the producer's own case returns with it; with no producer the destructor's case is skipped;
  - binds a length before a byte pointer the call reads (`X__unpack(alloc, len, data)`) to the rest
    of the input, as a (pointer, length) pair is.
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

AHO_REPO = Path(__file__).resolve().parents[1]
AHO_ALLOC = "struct Alloc"
AHO_SINK = "struct Sink"
AHO_MSG = "struct Msg"

# name -> (signature, [(formal, kind)], call sites): the shape of a protobuf-c generated message API.
AHO_RECS: dict[str, tuple[str, list[tuple[str, str]], list[str]]] = {
    "msg__init": ("void(struct Msg *)", [("message", "pointer")], []),
    "msg__unpack": (
        "struct Msg *(struct Alloc *,unsigned long,unsigned char *)",
        [("allocator", "pointer"), ("len", "value"), ("data", "const_pointer")],
        ["pb_unpack_generic"],
    ),
    "msg__free_unpacked": (
        "void(struct Msg *,struct Alloc *)",
        [("message", "pointer"), ("allocator", "pointer")],
        ["pb_free_generic"],
    ),
    "msg__pack_to_sink": (
        "unsigned long(struct Msg *,struct Sink *)",
        [("message", "const_pointer"), ("sink", "pointer")],
        [],
    ),
    "msg__get_packed_size": ("unsigned long(struct Msg *)", [("message", "const_pointer")], []),
}

AHO_ALLOC_PROTO = {"ret": "void *", "params": ["void *", "size_t"]}
AHO_FREE_PROTO = {"ret": "void", "params": ["void *", "void *"]}
AHO_APPEND_PROTO = {"ret": "void", "params": ["Sink *", "size_t", "const uint8_t *"]}


def _aho_layouts(protos: bool = True) -> dict[str, dict[str, Any]]:
    def fn(name: str, off: int, proto: dict[str, Any]) -> dict[str, Any]:
        f: dict[str, Any] = {"name": name, "kind": "fnptr", "off": off, "size": 8, "pointers": True}
        if protos:
            f["proto"] = proto
        return f

    return {
        AHO_ALLOC: {
            "what": "struct",
            "size": 24,
            "align": 8,
            "pointers": True,
            "fields": [
                fn("alloc", 0, AHO_ALLOC_PROTO),
                fn("free", 8, AHO_FREE_PROTO),
                {"name": "allocator_data", "kind": "ptr", "off": 16, "size": 8, "pointers": True, "const": False},
            ],
        },
        AHO_SINK: {
            "what": "struct",
            "size": 8,
            "align": 8,
            "pointers": True,
            "fields": [fn("append", 0, AHO_APPEND_PROTO)],
        },
        AHO_MSG: {
            "what": "struct",
            "size": 24,
            "align": 8,
            "pointers": True,
            "fields": [
                {"name": "kind", "kind": "int", "off": 0, "size": 4, "pointers": False, "ctype": "int"},
                {"name": "n", "kind": "int", "off": 8, "size": 8, "pointers": False, "ctype": "unsigned long"},
                {"name": "bytes", "kind": "ptr", "off": 16, "size": 8, "pointers": True, "const": False},
            ],
        },
    }


def _aho_dag_model(
    recs: dict[str, tuple[str, list[tuple[str, str]], list[str]]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    functions = {f"pb.c#{n}": {"name": n, "file": "pb.c"} for n in recs}
    dag = {
        "warnings": [],
        "modules": {"lib": {"functions": list(functions), "candidate_entry_points": list(functions)}},
        "functions": functions,
    }
    model = {
        "status": "ok",
        "functions": {
            f"pb.c#{n}": {
                "name": n,
                "signature": sig,
                "formals": [{"name": a, "kind": k} for a, k in formals],
                "call_sites": [{"callee": c, "line": 1} for c in calls],
            }
            for n, (sig, formals, calls) in recs.items()
        },
    }
    return dag, model


def _aho_plan(
    recs: dict[str, tuple[str, list[tuple[str, str]], list[str]]] | None = None,
    null_defaults: set[str] | None = None,
    layouts: dict[str, dict[str, Any]] | None = None,
    traces: list[list[dict]] | None = None,
) -> dict[str, Any]:
    recs = AHO_RECS if recs is None else recs
    dag, model = _aho_dag_model(recs)
    declared = ah.Declared(set(recs))
    # Set after construction: the regression must fail on the behaviour, not on a new keyword.
    declared.null_defaults = {AHO_ALLOC} if null_defaults is None else null_defaults
    return ah.plan(dag, model, "lib", "lib", 64, traces or [], None, layouts or _aho_layouts(), declared)


def _aho_case(p: dict[str, Any], fn: str) -> tuple[str, dict[str, Any]]:
    for text, lay in zip(p["cases"], p["layouts"], strict=True):
        if lay.get("entry") == f"pb.c#{fn}":
            return text, lay
    raise AssertionError(f"no case for {fn}: {p['skipped']}")


def _at(text: str, needle: str) -> int:
    assert needle in text, (needle, text)
    return text.index(needle)


# --- the destructor gets only what its producer returned ----------------------------------------------


@pytest.mark.unit
def test_free_unpacked_gets_the_object_its_unpacker_returned_never_a_stack_object():
    text, lay = _aho_case(_aho_plan(), "msg__free_unpacked")
    # sudo run-1 case 12: `struct ChangeWindowSize c0a0; memset(...); change_window_size__init(&c0a0);
    # change_window_size__free_unpacked(&c0a0, &c0a1)`, an invalid free only the harness made.
    assert f"{AHO_MSG} c0a0;" not in text, text
    assert "msg__init(" not in text, text
    made = _at(text, "msg__unpack(")
    freed = _at(text, "msg__free_unpacked(")
    assert made < freed, text
    m = re.search(r"(\w+) = \(struct Msg \*\)msg__unpack\(", text)
    assert m, text
    var = m.group(1)
    assert f"if ({var} != 0) {{ (void)msg__free_unpacked((struct Msg *){var}, " in text, text
    # The unpacker reads the input: its (len, data) are the rest of it.
    assert "(fuzz_buf + fuzz_off)" in text and "(fuzz_len - fuzz_off)" in text, text
    assert lay["rest"] == {"call": 1, "param": 2, "kind": "bytes"}, lay
    assert lay["inits"] == [{"fn": "msg__unpack", "call": 1, "for": {"call": 0, "param": 0}}], lay
    assert lay["slots"] == [], lay


@pytest.mark.unit
def test_free_unpacked_without_a_producer_is_skipped_with_the_reason():
    recs = {n: r for n, r in AHO_RECS.items() if n != "msg__unpack"}
    p = _aho_plan(recs)
    why = p["skipped"].get("pb.c#msg__free_unpacked", "")
    assert why.startswith("frees an object only its producer makes"), p["skipped"]
    assert all("msg__free_unpacked(" not in t for t in p["cases"]), p["cases"]


@pytest.mark.unit
def test_a_sequence_never_hands_a_shared_buffer_to_the_destructor():
    # A recorded chain shares the message's address between calls: a static buffer, never something
    # the destructor may free.
    trace = [
        {"fn": "msg__get_packed_size", "addrs": {"0": "0x10"}},
        {"fn": "msg__free_unpacked", "addrs": {"0": "0x10", "1": "0"}},
    ]
    p = _aho_plan(traces=[trace])
    assert [lay["kind"] for lay in p["layouts"]].count("sequence") == 0, p["layouts"]


@pytest.mark.unit
def test_a_sequence_never_shares_a_zeroed_table_between_its_calls():
    # A recorded chain passes one allocator to two calls: a shared buffer would be a zeroed table. Each
    # call gets its own, by the same rule (here: harness functions, no documented NULL default).
    trace = [
        {"fn": "msg__unpack", "addrs": {"0": "0xa1", "2": "0xd0"}},
        {"fn": "msg__get_packed_size", "addrs": {"0": "0xd0"}},
        {"fn": "msg__unpack", "addrs": {"0": "0xa1", "2": "0xd1"}},
    ]
    p = _aho_plan(null_defaults=set(), traces=[trace])
    seqs = [t for t, lay in zip(p["cases"], p["layouts"], strict=True) if lay["kind"] == "sequence"]
    assert seqs, p["layouts"]
    for text in seqs:
        assert "(struct Alloc *)s" not in text, text
        assert re.search(r"c0a0\.alloc = framac_cb_\w+;", text) and re.search(r"c2a0\.alloc = framac_cb_\w+;", text), (
            text
        )


# --- allocator / ops tables ------------------------------------------------------------------------


@pytest.mark.unit
def test_an_allocator_documented_as_null_for_default_is_passed_as_null():
    text, lay = _aho_case(_aho_plan(), "msg__unpack")
    # sudo run-1 case 11: `struct ProtobufCAllocator c0a0; memset(&c0a0, 0, ...)`: a NULL `alloc`.
    assert f"{AHO_ALLOC} c0a0" not in text, text
    assert "msg__unpack((struct Alloc *)0, " in text, text
    assert any("NULL" in n and "default" in n for n in lay.get("notes") or []), lay


@pytest.mark.unit
def test_the_unpackers_case_takes_the_rest_of_the_input_and_frees_what_it_returns():
    text, lay = _aho_case(_aho_plan(), "msg__unpack")
    assert "(unsigned long)(fuzz_len - fuzz_off)" in text and "(unsigned char *)(fuzz_buf + fuzz_off)" in text, text
    assert lay["rest"] == {"call": 0, "param": 2, "kind": "bytes"}, lay
    assert lay["slots"] == [], lay
    # The message it returns is released with the paired destructor, or every run leaks one.
    assert "if (c0r != 0) { (void)msg__free_unpacked((struct Msg *)c0r, (struct Alloc *)0); }" in text, text


@pytest.mark.unit
def test_an_allocator_without_a_null_default_gets_malloc_and_free_wrappers():
    p = _aho_plan(null_defaults=set())
    text, _ = _aho_case(p, "msg__unpack")
    assert "(struct Alloc *)0" not in text, text
    assert re.search(r"c0a0\.alloc = framac_cb_\w+;", text), text
    assert re.search(r"c0a0\.free = framac_cb_\w+;", text), text
    stubs = p["stubs"]
    alloc = next(v for k, v in stubs.items() if k.endswith("_alloc"))
    free = next(v for k, v in stubs.items() if k.endswith("_free"))
    assert "malloc(" in alloc and "return" in alloc, alloc
    assert "free((void *)fc_p1);" in free, free
    # The destructor's case gets the same kind of allocator as the producer it calls.
    text, _ = _aho_case(p, "msg__free_unpacked")
    assert "(struct Alloc *)0" not in text and ".free = framac_cb_" in text, text


@pytest.mark.unit
def test_an_ops_table_without_a_null_default_gets_stubs_never_null():
    p = _aho_plan()
    text, _ = _aho_case(p, "msg__pack_to_sink")
    assert re.search(r"c0a1\.append = framac_cb_\w+;", text), text
    stub = next(v for k, v in p["stubs"].items() if k.endswith("_append"))
    assert "malloc(" not in stub and "free(" not in stub, stub


@pytest.mark.unit
def test_an_ops_table_whose_prototypes_cannot_be_spelled_skips_the_case():
    p = _aho_plan(null_defaults=set(), layouts=_aho_layouts(protos=False))
    for fn in ("msg__unpack", "msg__pack_to_sink", "msg__free_unpacked"):
        why = p["skipped"].get(f"pb.c#{fn}", "")
        assert "function pointers" in why, (fn, p["skipped"])
    assert all(".alloc" not in t and ".append" not in t for t in p["cases"]), p["cases"]


@pytest.mark.unit
def test_a_documented_null_default_needs_no_prototypes():
    p = _aho_plan(layouts=_aho_layouts(protos=False))
    text, _ = _aho_case(p, "msg__unpack")
    assert "msg__unpack((struct Alloc *)0, " in text, text


# --- the layout probe: doc comments and function-pointer fields ----------------------------------------


def _aho_text(text: str) -> dict[str, Any]:
    return {"kind": "TextComment", "text": text}


AHO_AST: dict[str, Any] = {
    "kind": "TranslationUnitDecl",
    "inner": [
        {"kind": "TypedefDecl", "name": "size_t", "type": {"qualType": "unsigned long"}},
        {"kind": "TypedefDecl", "name": "Alloc", "type": {"qualType": "struct Alloc"}},
        {
            "kind": "RecordDecl",
            "name": "Alloc",
            "tagUsed": "struct",
            "completeDefinition": True,
            "inner": [
                {
                    "kind": "FieldDecl",
                    "name": "alloc",
                    "type": {
                        "qualType": "void *(*)(void *, size_t)",
                        "desugaredQualType": "void *(*)(void *, unsigned long)",
                    },
                },
                {"kind": "FieldDecl", "name": "free", "type": {"qualType": "void (*)(void *, void *)"}},
                {"kind": "FieldDecl", "name": "allocator_data", "type": {"qualType": "void *"}},
            ],
        },
        {
            "kind": "RecordDecl",
            "name": "Buf",
            "tagUsed": "struct",
            "completeDefinition": True,
            "inner": [
                {
                    "kind": "FieldDecl",
                    "name": "allocator",
                    "type": {"qualType": "Alloc *", "desugaredQualType": "struct Alloc *"},
                    "inner": [
                        {
                            "kind": "FullComment",
                            "inner": [
                                {
                                    "kind": "ParagraphComment",
                                    "inner": [
                                        _aho_text(" Allocator to use. May be NULL to indicate the system allocator. ")
                                    ],
                                }
                            ],
                        }
                    ],
                },
            ],
        },
        {
            "kind": "FunctionDecl",
            "name": "pb_unpack_generic",
            "type": {"qualType": "void *(Alloc *, size_t, const unsigned char *)"},
            "inner": [
                # clang 19 writes a pointer to a typedef with no desugared form: the typedef is followed.
                {"kind": "ParmVarDecl", "name": "allocator", "type": {"qualType": "Alloc *"}},
                {"kind": "ParmVarDecl", "name": "len", "type": {"qualType": "size_t"}},
                {"kind": "ParmVarDecl", "name": "data", "type": {"qualType": "const unsigned char *"}},
                {
                    "kind": "FullComment",
                    "inner": [
                        {
                            "kind": "ParamCommandComment",
                            "param": "allocator",
                            "inner": [
                                {
                                    "kind": "ParagraphComment",
                                    "inner": [
                                        _aho_text("      `Alloc` to use for memory allocation. May be NULL to"),
                                        _aho_text("      specify the default allocator."),
                                    ],
                                }
                            ],
                        },
                        {
                            "kind": "ParamCommandComment",
                            "param": "data",
                            "inner": [
                                {"kind": "ParagraphComment", "inner": [_aho_text(" May be NULL when len is 0.")]}
                            ],
                        },
                    ],
                },
            ],
        },
    ],
}


@pytest.mark.unit
@pytest.mark.parametrize(
    ("text", "says"),
    [
        ("`Alloc` to use for memory allocation. May be NULL to specify the default allocator.", True),
        ("Allocator to use. May be NULL to indicate the system allocator.", True),
        ("Must not be NULL; use the default ops table when unsure.", False),
        ("A non-NULL table; NULL is not the default.", False),
        ("Cannot be NULL (there is no default allocator).", False),
        ("May be NULL when len is 0.", False),
    ],
)
def test_only_a_comment_that_makes_null_a_default_counts(text, says):
    says_null_default = getattr(ah, "_says_null_default", lambda _t: None)  # absent before rule G
    assert says_null_default(text) is says


@pytest.mark.unit
def test_the_probe_reads_a_null_default_from_doc_comments_and_spells_function_pointer_fields():
    layouts, declared = ah.record_layouts(AHO_AST)
    # "May be NULL ... default" on a parameter or a field of type `struct Alloc *`; "May be NULL" alone
    # (a data pointer with no default) says nothing about a default.
    assert getattr(declared, "null_defaults", set()) == {AHO_ALLOC}
    fields = {f["name"]: f for f in layouts[AHO_ALLOC]["fields"]}
    assert fields["alloc"].get("proto") == {"ret": "void *", "params": ["void *", "size_t"]}, fields
    assert fields["free"].get("proto") == {"ret": "void", "params": ["void *", "void *"]}, fields


# --- end to end: the generated harness fuzzes a protobuf-c-shaped API without a harness-made crash ------

AHO_FIXTURE_H = """#ifndef PB_H
#define PB_H
#include <stddef.h>
#include <stdint.h>
typedef struct Alloc Alloc;
struct Alloc {
	void *(*alloc)(void *allocator_data, size_t size);
	void (*free)(void *allocator_data, void *pointer);
	void *allocator_data;
};
typedef struct Sink Sink;
struct Sink {
	void (*append)(Sink *sink, size_t len, const uint8_t *data);
};
typedef struct Msg Msg;
struct Msg { int kind; size_t n; uint8_t *bytes; };
/**
 * Unpack a message.
 * \\param allocator
 *      `Alloc` to use for memory allocation. May be NULL to
 *      specify the default allocator.
 */
void *pb_unpack_generic(Alloc *allocator, size_t len, const uint8_t *data);
void msg__init(Msg *message);
Msg *msg__unpack(Alloc *allocator, size_t len, const uint8_t *data);
void msg__free_unpacked(Msg *message, Alloc *allocator);
size_t msg__pack_to_sink(const Msg *message, Sink *sink);
size_t msg__get_packed_size(const Msg *message);
#endif
"""

AHO_FIXTURE_C = """#include <stdlib.h>
#include <string.h>
#include "pb.h"
static void *sys_alloc(void *d, size_t n) { (void)d; return malloc(n); }
static void sys_free(void *d, void *p) { (void)d; free(p); }
static Alloc default_alloc = { sys_alloc, sys_free, NULL };
void *pb_unpack_generic(Alloc *allocator, size_t len, const uint8_t *data) {
	Msg *m;
	if (allocator == NULL) allocator = &default_alloc;
	m = allocator->alloc(allocator->allocator_data, sizeof(*m));
	if (m == NULL) return NULL;
	msg__init(m);
	if (len > 0) {
		m->kind = data[0];
		m->n = len - 1;
		m->bytes = allocator->alloc(allocator->allocator_data, len);
		if (m->bytes == NULL) { allocator->free(allocator->allocator_data, m); return NULL; }
		memcpy(m->bytes, data + 1, len - 1);
	}
	return m;
}
void msg__init(Msg *message) { memset(message, 0, sizeof(*message)); }
Msg *msg__unpack(Alloc *allocator, size_t len, const uint8_t *data) { return pb_unpack_generic(allocator, len, data); }
void msg__free_unpacked(Msg *message, Alloc *allocator) {
	if (message == NULL) return;
	if (allocator == NULL) allocator = &default_alloc;
	allocator->free(allocator->allocator_data, message->bytes);
	allocator->free(allocator->allocator_data, message);
}
size_t msg__pack_to_sink(const Msg *message, Sink *sink) {
	uint8_t k = (uint8_t)message->kind;
	sink->append(sink, 1, &k);
	if (message->n) sink->append(sink, message->n, message->bytes);
	return 1 + message->n;
}
size_t msg__get_packed_size(const Msg *message) { return 1 + message->n; }
"""

AHO_AST_SCRIPT = "cd /fixture && clang -fsyntax-only -w -x c -I. -Xclang -ast-dump=json probe.c"

AHO_FUZZ_SCRIPT = r"""cp -r /fixture /tmp/w && cd /tmp/w
clang -fsanitize=fuzzer,address -g -I. harness.c pb.c -o fz || exit 1
mkdir corpus
printf '\000' > corpus/a; printf '\001xyz' > corpus/b; printf '\002\001\002\003' > corpus/c; printf '\003' > corpus/d
ASAN_OPTIONS=detect_leaks=1 ./fz -runs=200000 -seed=7 -max_len=64 corpus > fz.log 2>&1
echo FUZZ_RC=$?
grep -m3 -E "ERROR: (AddressSanitizer|LeakSanitizer)|SUMMARY|#[0-9]+ .* in (msg__|pb_|do_)" fz.log
grep -m1 -E "^Done [0-9]+ runs" fz.log
frama-c -eva -main eva_main -cpp-extra-args=-I. harness.c pb.c > eva.log 2>&1 && echo EVA_OK || tail -20 eva.log
"""


def _aho_render(cases: list[str], stubs: list[str]) -> str:
    inv = gh._build_dispatch_invocation(cases)
    text = (AHO_REPO / "templates" / "harness_dual.c.template").read_text(encoding="utf-8")
    text = text.replace('#include "{{MODULE_HEADER}}"', "\n".join(['#include "pb.h"', *stubs]))
    for key, value in {
        "MODULE_NAME": "lib",
        "MAX_INPUT_SIZE": "64",
        "TARGET_INVOCATION_EVA": inv,
        "TARGET_INVOCATION_FUZZ": inv,
    }.items():
        text = text.replace("{{" + key + "}}", value)
    return text


@pytest.mark.integration
def test_the_generated_harness_fuzzes_an_unpack_free_api_without_a_harness_made_crash(tmp_path):
    from conftest import ANALYSIS_IMAGE, require_docker_images

    require_docker_images(ANALYSIS_IMAGE)
    (tmp_path / "pb.h").write_text(AHO_FIXTURE_H, encoding="utf-8", newline="\n")
    (tmp_path / "pb.c").write_text(AHO_FIXTURE_C, encoding="utf-8", newline="\n")
    (tmp_path / "probe.c").write_text('#include "pb.h"\n', encoding="utf-8", newline="\n")
    argv = ["docker", "run", "--rm", "--network", "none", "--entrypoint", "/bin/sh"]
    argv += ["-v", f"{tmp_path}:/fixture:ro", ANALYSIS_IMAGE, "-c"]
    proc = subprocess.run(
        [*argv, AHO_AST_SCRIPT], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    layouts, declared = ah.record_layouts(json.loads(proc.stdout))
    assert isinstance(declared, ah.Declared)
    found = set(getattr(declared, "null_defaults", set()))
    dag, model = _aho_dag_model(AHO_RECS)
    logs: dict[str, str] = {}
    for label, nulls in (("null_default", found), ("wrappers", set())):
        declared.null_defaults = nulls
        p = ah.plan(dag, model, "lib", "lib", 64, [], None, layouts, declared)
        assert not any(k.endswith(("__unpack", "__free_unpacked")) for k in p["skipped"]), p["skipped"]
        stubs = ah.stubs_used(p["cases"], p["stubs"])
        (tmp_path / "harness.c").write_text(_aho_render(p["cases"], stubs), encoding="utf-8", newline="\n")
        run = subprocess.run(
            [*argv, AHO_FUZZ_SCRIPT], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900
        )
        logs[label] = run.stdout + run.stderr
        assert "FUZZ_RC=0" in logs[label], logs[label][-4000:]
        assert "Sanitizer" not in logs[label], logs[label][-4000:]
        assert re.search(r"Done \d+ runs", logs[label]), logs[label][-4000:]
        # Frama-C parses the same harness (its stubs and cases) for Eva.
        assert "EVA_OK" in logs[label], logs[label][-4000:]
    # The probe's own AST of the fixture says the allocator may be NULL for the default.
    assert found == {AHO_ALLOC}
