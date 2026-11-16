"""
Pointers to qualified pointers (c-ares run-1, 2026-11-16): the Phase 0 model drops the `const` inside
nested pointers, so c-ares's `const char **name` (`ares_dns_record_query_get`) and
`const unsigned char **val` (`ares_dns_rr_get_opt`, `ares_dns_rr_get_opt_byid`) reached the `--api`
generator as `char **` and `unsigned char **`. The cases declared `char *` objects and cast them to
`(char **)`: clang only warns (`-Wincompatible-pointer-types-discards-qualifiers`), which the compile
probe hid with `-w`, and gcc 14 refuses the call. The layout probe now reads each such parameter as
the header writes it, and the compile probe makes that warning an error.
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

NC_REPO = Path(__file__).resolve().parents[1]

# name -> (model signature, formal kinds, the declaration's parameter types as clang writes them, return).
NC_API: dict[str, tuple[str, list[str], list[str], str]] = {
    "rec_create": ("int(struct rec **)", ["pointer"], ["rec_t **"], "int"),
    "rec_destroy": ("void(struct rec *)", ["pointer"], ["rec_t *"], "void"),
    "rec_name_get": (
        "int(struct rec *,unsigned long,char **)",
        ["const_pointer", "value", "pointer"],
        ["const rec_t *", "size_t", "const char **"],
        "int",
    ),
    "rec_opt_get": (
        "int(struct rec *,unsigned long,unsigned char **,unsigned long *)",
        ["const_pointer", "value", "pointer", "pointer"],
        ["const rec_t *", "size_t", "const unsigned char **", "size_t *"],
        "int",
    ),
    "rec_write": (
        "int(struct rec *,unsigned char **,unsigned long *)",
        ["const_pointer", "pointer", "pointer"],
        ["const rec_t *", "unsigned char **", "size_t *"],
        "int",
    ),
}
NC_SIZES: dict[str, dict[str, dict[str, int]]] = {
    "rec_create": {"0": {"min": 8, "max": 8, "sites": 2}},
    "rec_name_get": {"2": {"min": 8, "max": 8, "sites": 4}},
    "rec_opt_get": {"2": {"min": 8, "max": 8, "sites": 3}, "3": {"min": 8, "max": 8, "sites": 3}},
    "rec_write": {"1": {"min": 8, "max": 8, "sites": 2}, "2": {"min": 8, "max": 8, "sites": 2}},
}


def _nc_tree(api: dict[str, tuple[str, list[str], list[str], str]]) -> dict:
    """A clang JSON AST of the header, as clang writes the declarations."""
    inner: list[dict] = [
        {"kind": "RecordDecl", "name": "rec", "tagUsed": "struct"},
        {"kind": "TypedefDecl", "name": "rec_t", "type": {"qualType": "struct rec"}},
        {"kind": "TypedefDecl", "name": "size_t", "type": {"qualType": "unsigned long"}},
    ]
    for n, (_, _, params, ret) in api.items():
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


def _nc_plan(
    api: dict[str, tuple[str, list[str], list[str], str]],
    sizes: dict[str, dict[str, dict[str, int]]],
    tree: dict | None = None,
    probed: bool = True,
) -> dict[str, Any]:
    functions = {f"lib.c#{n}": {"name": n, "file": "lib.c"} for n in api}
    dag = {
        "warnings": [],
        "modules": {"lib": {"functions": list(functions), "candidate_entry_points": list(functions)}},
        "functions": functions,
    }
    recs: dict[str, dict[str, Any]] = {}
    for n, (sig, kinds, _, _) in api.items():
        rec: dict[str, Any] = {
            "name": n,
            "signature": sig,
            "formals": [{"name": f"p{i}", "kind": k} for i, k in enumerate(kinds)],
        }
        if n in sizes:
            rec["param_sizes"] = sizes[n]
        recs[f"lib.c#{n}"] = rec
    model = {"status": "ok", "functions": recs}
    if not probed:
        return ah.plan(dag, model, "lib", "lib", 64, [], None, None, None)
    layouts, declared = ah.record_layouts(tree if tree is not None else _nc_tree(api))
    return ah.plan(dag, model, "lib", "lib", 64, [], None, layouts, declared)


def _nc_cases(p: dict[str, Any]) -> dict[str, str]:
    return {lay["entry"].split("#")[-1]: p["cases"][k] for k, lay in enumerate(p["layouts"]) if lay.get("entry")}


def _nc_args(stmt: str, name: str) -> list[str]:
    m = re.search(rf"\(void\){name}\(([^;]*)\);", stmt)
    assert m, stmt
    return [a.strip() for a in m.group(1).split(",")]


@pytest.mark.unit
def test_the_probe_spells_pointers_to_qualified_pointers_as_written():
    api = dict(NC_API)
    api["names_join"] = (
        "int(char **,unsigned long)",
        ["const_pointer", "value"],
        ["const char *const *", "size_t"],
        "int",
    )
    api["names_fill"] = ("int(char **)", ["pointer"], ["char *const *restrict"], "int")
    api["anon_get"] = (
        "int(struct __anonstruct_o_1 **)",
        ["pointer"],
        ["const struct (unnamed struct at x.h:1:9) **"],
        "int",
    )
    api["cb_get"] = ("int(int (**)(int))", ["pointer"], ["int (*const *)(int)"], "int")
    _, declared = ah.record_layouts(_nc_tree(api))
    qual = declared.qualified_pointers  # type: ignore[attr-defined]
    assert qual["rec_name_get"] == {2: {"type": "const char **", "pointee": "const char *"}}
    assert qual["rec_opt_get"] == {2: {"type": "const unsigned char **", "pointee": "const unsigned char *"}}
    # The object a case declares drops its own qualifier: it is zeroed and written by the callee.
    assert qual["names_join"] == {0: {"type": "const char *const *", "pointee": "const char *"}}
    assert qual["names_fill"] == {0: {"type": "char *const *", "pointee": "char *"}}
    # No qualifier inside (a plain out-pointer, a handle), an anonymous type, a function pointer: nothing.
    for n in ("rec_write", "rec_create", "rec_destroy", "anon_get", "cb_get"):
        assert n not in qual, n


@pytest.mark.unit
def test_pointers_to_const_pointers_keep_the_header_spelling():
    """The c-ares run-1 failure: `(char **)c0a2` passed where the header declares `const char **`."""
    p = _nc_plan(NC_API, NC_SIZES)
    assert p["skipped"] == {}
    cases = _nc_cases(p)
    name = cases["rec_name_get"]
    assert _nc_args(name, "rec_name_get") == ["(struct rec *)c0a0", "c0a1", "(const char **)c0a2"]
    assert "const char * c0a2[(8 + sizeof(const char *) - 1) / sizeof(const char *)];" in name, name
    opt = cases["rec_opt_get"]
    assert _nc_args(opt, "rec_opt_get")[2] == "(const unsigned char **)c0a2"
    assert "const unsigned char * c0a2[" in opt
    # Nothing to keep: `unsigned char **buf` stays as the model spells it.
    assert _nc_args(cases["rec_write"], "rec_write")[1] == "(unsigned char **)c0a1"
    for stmt in p["cases"]:
        assert "(char **)" not in stmt and "(unsigned char **)c0a2" not in stmt, stmt


@pytest.mark.unit
def test_without_call_site_sizes_the_object_is_a_const_pointer_passed_by_address():
    cases = _nc_cases(_nc_plan(NC_API, {}))
    name = cases["rec_name_get"]
    assert "const char * c0a2; memset(&c0a2, 0, sizeof(c0a2));" in name, name
    assert _nc_args(name, "rec_name_get")[2] == "&c0a2"


@pytest.mark.unit
def test_without_the_probe_the_model_spelling_is_kept():
    p = _nc_plan(NC_API, NC_SIZES, probed=False)
    assert "lib.c#rec_name_get" not in p["skipped"]
    assert _nc_args(_nc_cases(p)["rec_name_get"], "rec_name_get")[2] == "(char **)c0a2"


@pytest.mark.unit
def test_the_header_spelling_does_not_change_how_the_object_is_filled():
    """Only the spelling moves to the header's: the model's pointee still decides zeroed or read."""
    sig = "int(struct item **,unsigned long)"
    sizes = {"items_sum": {"0": {"min": 16, "max": 16, "sites": 2}}}
    qualified = {"items_sum": (sig, ["const_pointer", "value"], ["const struct item *const *", "size_t"], "int")}
    plain = {"items_sum": (sig, ["const_pointer", "value"], ["struct item **", "size_t"], "int")}
    q = _nc_plan(qualified, sizes)
    b = _nc_plan(plain, sizes)
    assert q["layouts"] == b["layouts"]
    stmt = q["cases"][0]
    assert "const struct item * c0a0[" in stmt and "(const struct item *const *)c0a0" in stmt, stmt
    assert "memcpy(c0a0" not in stmt  # pointers to a struct are never read from the input
    assert (
        q["cases"][0]
        .replace("const struct item *const *", "struct item **")
        .replace("const struct item *", "struct item *")
        == b["cases"][0]
    )


@pytest.mark.unit
def test_the_compile_probe_refuses_dropped_nested_qualifiers(monkeypatch, tmp_path):
    seen: list[list[str]] = []

    def fake_run(argv: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        seen.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.delenv("FRAMAC_SNAPSHOT_DIR", raising=False)
    monkeypatch.setattr(ah.subprocess, "run", fake_run)
    harness = tmp_path / "h.c"
    harness.write_text("int x;\n", encoding="utf-8")
    flags = "-I. -DX=1 -Werror -Werror=shadow -pedantic-errors -Wp,-DY=2"
    assert ah.probe_cases(harness, flags, clang="/usr/bin/clang") == ({}, [])
    argv = seen[-1]
    # clang's `-w` would silence the -Werror= option: warnings stay on, only errors are read.
    assert "-w" not in argv
    assert argv[-3:] == ["-Wno-error", "-Werror=incompatible-pointer-types-discards-qualifiers", str(harness)]
    # The target's own error options are dropped (`-w` used to neutralise them); its other flags stay.
    for gone in ("-Werror", "-Werror=shadow", "-pedantic-errors"):
        assert gone not in argv
    assert "-DX=1" in argv and "-Wp,-DY=2" in argv
    # gcc refuses such a call on its own (gcc 14: -Wincompatible-pointer-types is an error).
    ah.probe_cases(harness, flags, clang="/usr/bin/gcc")
    assert "-w" in seen[-1] and not any("discards-qualifiers" in a for a in seen[-1])


NC_TAG = "[-Werror,-Wincompatible-pointer-types-discards-qualifiers]"


@pytest.mark.unit
def test_only_the_cases_are_held_to_the_nested_qualifier_error(monkeypatch, tmp_path):
    """The target's own code (an inline function of its headers) compiled under `-w`: it still does."""
    harness = tmp_path / "h.c"
    harness.write_text('#include "lib.h"\nint x;\n        case 0U: { f(0); } break;\n', encoding="utf-8")
    header_err = f"./lib.h:4:12: error: passing 'char **' to parameter of type 'const char **' {NC_TAG}"
    case_err = f"{harness.name}:3:22: error: passing 'char **' to parameter of type 'const char **' {NC_TAG}"
    outputs: list[str] = []

    def fake_run(argv: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 1, "", outputs[-1])

    monkeypatch.delenv("FRAMAC_SNAPSHOT_DIR", raising=False)
    monkeypatch.setattr(ah.subprocess, "run", fake_run)
    outputs.append(header_err + "\n1 error generated.\n")
    assert ah.probe_cases(harness, "-I.", clang="/usr/bin/clang") == ({}, [])
    outputs.append(header_err + "\n" + case_err + "\n2 errors generated.\n")
    bad, other = ah.probe_cases(harness, "-I.", clang="/usr/bin/clang") or ({}, [])
    assert list(bad) == [0] and "discards-qualifiers" in bad[0] and other == []
    # Any other error off the cases still fails the harness, as before.
    outputs.append(header_err + "\n./lib.h:9:1: error: unknown type name 'foo_t'\n2 errors generated.\n")
    assert ah.probe_cases(harness, "-I.", clang="/usr/bin/clang") == (
        {},
        ["./lib.h:9:1: error: unknown type name 'foo_t'"],
    )
    # A driver error next to it is not swallowed either.
    outputs.append(header_err + "\nclang: error: no such file or directory: 'x.c'\n")
    _, other = ah.probe_cases(harness, "-I.", clang="/usr/bin/clang") or ({}, [])
    assert other == ["clang: error: no such file or directory: 'x.c'"]


# --- end to end: real clang's AST of the header, then the cases compile strictly and run -----------

NC_LIB_H = """#include <stddef.h>
typedef struct rec rec_t;
int rec_create(rec_t **out);
void rec_destroy(rec_t *r);
int rec_name_get(const rec_t *r, size_t idx, const char **name);
int rec_opt_get(const rec_t *r, size_t idx, const unsigned char **val, size_t *val_len);
int rec_write(const rec_t *r, unsigned char **buf, size_t *buf_len);
"""

NC_LIB_C = """#include <stdlib.h>
#include "lib.h"
struct rec { const char *name; unsigned char opt[4]; };
static unsigned char wire[8];
int rec_create(rec_t **out) {
    rec_t *r = calloc(1, sizeof *r);
    *out = r;
    if (r == NULL) return 1;
    r->name = "q"; r->opt[0] = 7;
    return 0;
}
void rec_destroy(rec_t *r) { free(r); }
int rec_name_get(const rec_t *r, size_t idx, const char **name) {
    if (idx != 0) return 1;
    *name = r->name;
    return 0;
}
int rec_opt_get(const rec_t *r, size_t idx, const unsigned char **val, size_t *val_len) {
    if (idx != 0) return 1;
    *val = r->opt; *val_len = sizeof r->opt;
    return 0;
}
int rec_write(const rec_t *r, unsigned char **buf, size_t *buf_len) {
    wire[0] = r->opt[0]; *buf = wire; *buf_len = sizeof wire;
    return 0;
}
"""

NC_AST_SCRIPT = "cd /fixture && clang -fsyntax-only -x c -Xclang -ast-dump=json lib.h"

NC_RUN_SCRIPT = r"""cp -r /fixture /tmp/w && cd /tmp/w
clang -fsyntax-only -Wall -Werror=incompatible-pointer-types -Werror=incompatible-pointer-types-discards-qualifiers -I. harness.c || exit 1
gcc -fsyntax-only -I. harness.c || exit 1
python3 probe.py || exit 1
clang -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all -g -I. harness.c lib.c -o fz || exit 1
mkdir corpus
./fz -runs=100000 -seed=7 -max_len=64 -detect_leaks=1 corpus > fz.log 2>&1 && echo FUZZ_CLEAN || tail -40 fz.log
"""

NC_PROBE_PY = """import json, sys
from pathlib import Path
sys.path.insert(0, "/pipe/scripts")
import api_harness as ah
out = {n: ah.probe_cases(Path(n), "-I.") for n in ("harness.c", "harness_dropped.c")}
print("PROBE " + json.dumps(out))
"""


def _nc_render(cases: list[str]) -> str:
    inv = gh._build_dispatch_invocation(cases)
    text = (NC_REPO / "templates" / "harness_dual.c.template").read_text(encoding="utf-8")
    for key, value in {
        "MODULE_NAME": "lib",
        "MODULE_HEADER": "lib.h",
        "MAX_INPUT_SIZE": "64",
        "TARGET_INVOCATION_EVA": inv,
        "TARGET_INVOCATION_FUZZ": inv,
    }.items():
        text = text.replace("{{" + key + "}}", value)
    return text


def _nc_docker(tmp_path: Path, script: str, image: str) -> subprocess.CompletedProcess[str]:
    argv = ["docker", "run", "--rm", "--network", "none", "-v", f"{tmp_path}:/fixture:ro"]
    argv += ["-v", f"{NC_REPO}:/pipe:ro", image, script]
    return subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900)


@pytest.mark.integration
def test_nested_const_cases_compile_strictly_from_real_clang_and_run_clean(tmp_path):
    from conftest import ANALYSIS_IMAGE, require_docker_images

    require_docker_images(ANALYSIS_IMAGE)
    (tmp_path / "lib.h").write_text(NC_LIB_H, encoding="utf-8")
    (tmp_path / "lib.c").write_text(NC_LIB_C, encoding="utf-8")
    ast = _nc_docker(tmp_path, NC_AST_SCRIPT, ANALYSIS_IMAGE)
    assert ast.returncode == 0, ast.stderr[-2000:]
    # The spellings come from clang's own AST of the header, not from a hand-written tree.
    p = _nc_plan(NC_API, NC_SIZES, tree=json.loads(ast.stdout))
    assert p["skipped"] == {}
    cases = _nc_cases(p)
    assert "(const char **)c0a2" in cases["rec_name_get"]
    assert "(const unsigned char **)c0a2" in cases["rec_opt_get"]
    good = _nc_render(p["cases"])
    (tmp_path / "harness.c").write_text(good, encoding="utf-8")
    # The same harness as the generator wrote it before: the compile probe must refuse those cases.
    dropped = good.replace("(const char **)", "(char **)").replace("(const unsigned char **)", "(unsigned char **)")
    assert dropped != good
    (tmp_path / "harness_dropped.c").write_text(dropped, encoding="utf-8")
    (tmp_path / "probe.py").write_text(NC_PROBE_PY, encoding="utf-8")
    proc = _nc_docker(tmp_path, NC_RUN_SCRIPT, ANALYSIS_IMAGE)
    out = proc.stdout + proc.stderr
    m = re.search(r"^PROBE (.*)$", proc.stdout, re.MULTILINE)
    assert m, out[-4000:]
    probed = json.loads(m.group(1))
    assert probed["harness.c"] == [{}, []]
    bad, other = probed["harness_dropped.c"]
    assert other == []
    want = {str(k) for k, c in enumerate(p["cases"]) if "(const char **)" in c or "(const unsigned char **)" in c}
    assert want and set(bad) == want, bad
    assert all("discards qualifiers" in d for d in bad.values()), bad
    # A pointer object smaller than what the library writes would be an ASan report.
    assert "FUZZ_CLEAN" in proc.stdout, out[-4000:]
