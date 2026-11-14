"""Tests for the Phase 0 harness reachability gate (scripts/harness_reach.py) and the `dispatch` entry style."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

import harness_reach
from framac_common import ArtifactError
from generate_harness import _build_invocations, generate_module_harness

TIER_1A = "Tier 1A (Untrusted Binary / Network Parser)"

API_H = """\
#include <stddef.h>
#include <stdint.h>
struct rec { uint16_t len; uint16_t type; };
int rec_ok(const struct rec *r, int left);
struct rec *rec_next(const struct rec *r);
#define rec_for_each(r, buf, n) \\
    for ((r) = (const struct rec *)(buf); rec_ok((r), (n)); (r) = rec_next(r))
#define rec_for_each_alias(r, buf, n) rec_for_each(r, buf, n)
int rec_parse(const uint8_t *buf, size_t len);
int rec_put(uint8_t *buf, size_t buflen, uint16_t type);
void rec_print(const uint8_t *buf, size_t len);
"""

API_C = """\
#include "api.h"
int rec_ok(const struct rec *r, int left) { return left >= 4 && r->len >= 4 && r->len <= left; }
struct rec *rec_next(const struct rec *r) { return (struct rec *)((const uint8_t *)r + r->len); }
static int rec_check(const struct rec *r) { return r->type < 32; }
int rec_parse(const uint8_t *buf, size_t len) {
    const struct rec *r;
    int n = 0;
    rec_for_each(r, buf, (int)len) { n += rec_check(r); }
    return n;
}
int rec_put(uint8_t *buf, size_t buflen, uint16_t type) {
    if (buflen < 4) return -1;
    buf[0] = 4; buf[1] = 0; buf[2] = (uint8_t)type; buf[3] = 0;
    return 4;
}
void rec_print(const uint8_t *buf, size_t len) { (void)buf; (void)len; }
"""


def _fn(name, callees=(), static=False, module="api"):
    return {
        "name": name,
        "file": "src/api.c",
        "module": module,
        "is_static": static,
        "internal_callees": list(callees),
    }


def _dag() -> dict:
    functions = {
        "rec_ok": _fn("rec_ok"),
        "rec_next": _fn("rec_next"),
        "rec_check": _fn("rec_check", static=True),
        "rec_parse": _fn("rec_parse", ["rec_ok", "rec_next", "rec_check"]),
        "rec_put": _fn("rec_put"),
        "rec_print": _fn("rec_print"),
    }
    return {
        "modules": {
            "api": {
                "module": "api",
                "tier": TIER_1A,
                "functions": list(functions),
                "candidate_entry_points": ["rec_parse", "rec_put", "rec_print"],
            },
            "tools": {"module": "tools", "tier": TIER_1A, "functions": [], "candidate_entry_points": []},
            "glue": {"module": "glue", "tier": "Tier 3 (Internal Scalar / Glue Module)", "functions": []},
        },
        "functions": functions,
        "header_inline_callees": {},
    }


def _run_dir(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "workspace" / "work" / "src").mkdir(parents=True)
    (tmp_path / "workspace" / "work" / "include").mkdir(parents=True)
    (tmp_path / "workspace" / "work" / "include" / "api.h").write_text(API_H, encoding="utf-8")
    (tmp_path / "workspace" / "work" / "src" / "api.c").write_text(API_C, encoding="utf-8")
    (tmp_path / "workspace" / "reports").mkdir(parents=True)
    (tmp_path / "workspace" / "reports" / "callgraph_dag.json").write_text(json.dumps(_dag()), encoding="utf-8")
    return tmp_path


def _write_harness(run: Path, call: str, **extra) -> Path:
    hdir = run / "workspace" / "harnesses"
    hdir.mkdir(parents=True, exist_ok=True)
    harness = hdir / "harness_api.c"
    harness.write_text(f'#include "api.h"\nvoid drive(uint8_t *fuzz_buf, size_t fuzz_len) {{\n{call}\n}}\n')
    sidecar = {
        "module": "api",
        "harness_file": "workspace/harnesses/harness_api.c",
        "cppflags": "-Iworkspace/work/include",
        **extra,
    }
    (hdir / "harness_api.json").write_text(json.dumps(sidecar), encoding="utf-8")
    return hdir


def _api(report: dict) -> dict:
    return next(m for m in report["modules"] if m["module"] == "api")


# --- dispatch entry style -------------------------------------------------------------------


def test_dispatch_selects_one_case_per_input_byte():
    eva, fuzz = _build_invocations("rec_parse", "dispatch", dispatch_cases=["rec_parse(fuzz_buf, fuzz_len);", "  "])
    assert eva == fuzz
    assert "uint8_t harness_selector = fuzz_buf[0];" in eva
    assert "fuzz_buf += 1;" in eva and "fuzz_len -= 1;" in eva
    # Blank cases are dropped, so the modulus counts real cases only.
    assert "switch (harness_selector % 1U)" in eva
    assert "case 0U: { rec_parse(fuzz_buf, fuzz_len); } break;" in eva


def test_dispatch_requires_a_case_and_supports_null_termination():
    with pytest.raises(ValueError, match="dispatch-case"):
        _build_invocations("rec_parse", "dispatch", dispatch_cases=[])
    eva, fuzz = _build_invocations("rec_parse", "dispatch", null_terminate=True, dispatch_cases=["rec_print(0, 0);"])
    assert eva.startswith("input_buf[")
    assert "cstr_buf[size] = 0;" in fuzz and "harness_selector" in fuzz


def test_dispatch_harness_sidecar_records_cases_and_keeps_exemptions(tmp_path, monkeypatch):
    run = _run_dir(tmp_path, monkeypatch)
    hdir = run / "workspace" / "harnesses"
    cases = [
        "rec_parse(fuzz_buf, fuzz_len);",
        "uint8_t out[64]; (void)rec_put(out, sizeof(out), fuzz_len > 0 ? fuzz_buf[0] : 0);",
    ]
    kwargs: dict[str, Any] = dict(
        module_name="api",
        sources=["workspace/work/src/api.c"],
        header_include="api.h",
        entry_fn="rec_parse",
        max_input_size=256,
        cppflags="-Iworkspace/work/include",
        out_dir=hdir,
        entry_style="dispatch",
        auto_prelude=False,
        dispatch_cases=cases,
    )
    generate_module_harness(**kwargs)
    sidecar = json.loads((hdir / "harness_api.json").read_text(encoding="utf-8"))
    assert sidecar["entry_style"] == "dispatch"
    assert sidecar["dispatch_cases"] == cases
    assert sidecar["reach_exempt"] == {}
    harness_reach.record_exempt(hdir, "api", "rec_print", "debug printer, writes to stdout only")
    generate_module_harness(**kwargs)
    sidecar = json.loads((hdir / "harness_api.json").read_text(encoding="utf-8"))
    assert sidecar["reach_exempt"] == {"rec_print": "debug printer, writes to stdout only"}
    text = (hdir / "harness_api.c").read_text(encoding="utf-8")
    assert "switch (harness_selector % 2U)" in text

    clang = shutil.which("clang")
    if clang:
        proc = subprocess.run(
            [clang, "-fsyntax-only", "-x", "c", "-Iworkspace/work/include", str(hdir / "harness_api.c")],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr


# --- reachability gate ----------------------------------------------------------------------


def test_gate_fails_a_single_entry_harness_and_names_the_gaps(tmp_path, monkeypatch):
    run = _run_dir(tmp_path, monkeypatch)
    hdir = _write_harness(run, "rec_parse(fuzz_buf, fuzz_len);")
    report = harness_reach.run_check(run / "workspace/reports/callgraph_dag.json", hdir, ["api"])
    api = _api(report)
    assert report["passed"] is False
    assert api["gaps"] == ["rec_print", "rec_put"]
    assert api["entry_points_reached"] == 1
    # The closure follows internal callees, static helpers included.
    assert api["functions_reached"] == 4


def test_gate_expands_header_macros_and_honors_exemptions(tmp_path, monkeypatch):
    run = _run_dir(tmp_path, monkeypatch)
    hdir = _write_harness(
        run,
        "const struct rec *r; rec_for_each_alias(r, fuzz_buf, (int)fuzz_len) { (void)r; }\n"
        "uint8_t out[8]; (void)rec_put(out, sizeof(out), 1);",
    )
    dag = run / "workspace/reports/callgraph_dag.json"
    api = _api(harness_reach.run_check(dag, hdir, ["api"]))
    # rec_ok / rec_next come only through the (nested) iterator macro.
    assert {"rec_ok", "rec_next", "rec_put"} <= set(api["roots"])
    assert api["gaps"] == ["rec_parse", "rec_print"]

    harness_reach.record_exempt(hdir, "api", "rec_print", "debug printer")
    harness_reach.record_exempt(hdir, "api", "rec_parse", "covered by the parse module harness")
    api = _api(harness_reach.run_check(dag, hdir, ["api"]))
    assert api["passed"] is True
    assert api["exempt"] == {"rec_parse": "covered by the parse module harness", "rec_print": "debug printer"}


def test_gate_requires_a_harness_for_tier_1_and_2_modules(tmp_path, monkeypatch):
    run = _run_dir(tmp_path, monkeypatch)
    hdir = _write_harness(run, "rec_parse(fuzz_buf, fuzz_len); rec_put(fuzz_buf, fuzz_len, 0); rec_print(0, 0);")
    dag = run / "workspace/reports/callgraph_dag.json"
    report = harness_reach.run_check(dag, hdir, None)
    by_mod = {m["module"]: m for m in report["modules"]}
    assert by_mod["api"]["passed"] is True
    assert by_mod["tools"]["error"] == "no_harness"
    assert "glue" not in by_mod  # Tier 3 needs no harness
    assert report["passed"] is False

    harness_reach.record_exempt(hdir, "tools", None, "example programs, not library API")
    report = harness_reach.run_check(dag, hdir, None)
    assert report["passed"] is True
    assert {m["module"]: m for m in report["modules"]}["tools"]["exempt"] == "example programs, not library API"


def test_cli_exit_codes_and_report(tmp_path, monkeypatch, capsys):
    run = _run_dir(tmp_path, monkeypatch)
    hdir = _write_harness(run, "rec_parse(fuzz_buf, fuzz_len);")
    harness_reach.record_exempt(hdir, "tools", None, "examples")
    out = run / "workspace/reports/harness_reach.json"
    assert harness_reach.main(["check", "--harness-dir", str(hdir), "--out", str(out)]) == 1
    assert json.loads(out.read_text(encoding="utf-8"))["passed"] is False
    capsys.readouterr()
    assert (
        harness_reach.main(
            ["exempt", "--harness-dir", str(hdir), "--module", "api", "--function", "rec_put", "--reason", "  "]
        )
        == 2
    )
    for fn in ("rec_put", "rec_print"):
        assert (
            harness_reach.main(
                ["exempt", "--harness-dir", str(hdir), "--module", "api", "--function", fn, "--reason", "r"]
            )
            == 0
        )
    assert harness_reach.main(["check", "--harness-dir", str(hdir), "--out", "-"]) == 0
    assert (
        harness_reach.main(["check", "--dag", str(run / "missing.json"), "--harness-dir", str(hdir), "--out", "-"]) == 2
    )


# --- direct reach: an entry point the harness does not call itself is a gap -------------------

SCAN_H = """\
#include <stddef.h>
#include <stdint.h>
int scan(const char *s, const char *fmt);
int parse_a(const char *s);
int parse_b(const char *s);
#define scan_alias scan
"""
# Only the wrapper tests include it: with clang the roots are every function the harness's translation
# unit references, the body of an included inline function too.
SCAN_WRAPPER = 'static inline int scan_text(const char *s) { return scan(s, "s"); }\n'


def _scan_dag(wrapper_in_header: bool = True) -> dict:
    """parse_a and parse_b call the entry point `scan` with their own format; `scan_text` wraps it."""
    functions = {
        "scan": _fn("scan", ["is_field"]),
        "is_field": _fn("is_field", static=True),
        "parse_a": _fn("parse_a", ["scan"]),
        "parse_b": _fn("parse_b", ["scan"]),
        "scan_text": {**_fn("scan_text", ["scan"], static=True), "header": wrapper_in_header},
    }
    return {
        "modules": {
            "api": {
                "module": "api",
                "tier": TIER_1A,
                "functions": list(functions),
                "candidate_entry_points": ["parse_a", "parse_b", "scan"],
            }
        },
        "functions": functions,
    }


def _scan_run(tmp_path: Path, monkeypatch, call: str, dag: dict | None = None, wrapper: bool = False, **extra):
    run = _run_dir(tmp_path, monkeypatch)
    header = SCAN_H + (SCAN_WRAPPER if wrapper else "")
    (run / "workspace/work/include/api.h").write_text(header, encoding="utf-8", newline="\n")
    dag_path = run / "workspace/reports/callgraph_dag.json"
    dag_path.write_text(json.dumps(dag or _scan_dag()), encoding="utf-8", newline="\n")
    return dag_path, _write_harness(run, call, **extra)


PARSE_BOTH = "(void)parse_a((const char *)fuzz_buf); (void)parse_b((const char *)fuzz_buf);"


def test_entry_point_called_only_by_other_entry_points_is_a_gap(tmp_path, monkeypatch):
    dag, hdir = _scan_run(tmp_path, monkeypatch, PARSE_BOTH)
    report = harness_reach.run_check(dag, hdir, ["api"])
    api = _api(report)
    assert report["passed"] is False and api["passed"] is False
    assert api["gaps"] == ["scan"] and api["unreached_entry_points"] == ["scan"]
    assert api["reached_only_through"] == {"scan": ["parse_a", "parse_b"]}
    assert api["entry_points"] == 3 and api["entry_points_reached"] == 2
    # Internal functions keep the transitive reach: scan and is_field are below the roots.
    assert api["functions_reached"] == 4

    # Calling it from the harness makes it direct.
    _write_harness(tmp_path, PARSE_BOTH + ' (void)scan((const char *)fuzz_buf, "s");')
    api = _api(harness_reach.run_check(dag, hdir, ["api"]))
    assert api["passed"] is True and api["gaps"] == [] and api["reached_only_through"] == {}
    assert api["entry_points_reached"] == 3


def test_entry_point_no_root_leads_to_is_not_in_reached_only_through(tmp_path, monkeypatch):
    dag, hdir = _scan_run(tmp_path, monkeypatch, "(void)parse_a((const char *)fuzz_buf);")
    api = _api(harness_reach.run_check(dag, hdir, ["api"]))
    assert api["gaps"] == ["parse_b", "scan"]
    assert api["reached_only_through"] == {"scan": ["parse_a"]}


def test_exemption_clears_an_entry_point_reached_only_transitively(tmp_path, monkeypatch, capsys):
    import phase0_gates

    dag, hdir = _scan_run(tmp_path, monkeypatch, PARSE_BOTH)
    assert harness_reach.main(["check", "--harness-dir", str(hdir)]) == 1
    [reason] = phase0_gates.check(tmp_path, "api", ("reach",))
    assert "scan" in reason
    out = _exempt_cli(hdir, capsys, "scan")
    assert out["gate"] == {"rechecked": ["api"]}
    assert phase0_gates.check(tmp_path, "api", ("reach",)) == []
    api = _api(harness_reach.run_check(dag, hdir, ["api"]))
    assert api["passed"] is True and api["gaps"] == []
    assert api["exempt"] == {"scan": "cannot be driven from bytes"}
    # Still listed as not called by the harness, with the reason why a reader might think it is.
    assert api["unreached_entry_points"] == ["scan"] and api["entry_points_reached"] == 2
    assert api["reached_only_through"] == {"scan": ["parse_a", "parse_b"]}


def test_header_inline_wrapper_root_makes_the_wrapped_entry_point_direct(tmp_path, monkeypatch):
    call = PARSE_BOTH + " (void)scan_text((const char *)fuzz_buf);"
    dag, hdir = _scan_run(tmp_path, monkeypatch, call, wrapper=True)
    api = _api(harness_reach.run_check(dag, hdir, ["api"]))
    assert "scan_text" in api["roots"]
    assert api["passed"] is True and api["gaps"] == [] and api["reached_only_through"] == {}
    assert api["entry_points_reached"] == 3


def test_direct_reach_follows_header_inline_wrappers_only():
    by_name = harness_reach._functions_by_name(_scan_dag())
    direct = harness_reach.callee_closure({"scan_text"}, by_name, "api", follow=harness_reach.is_header_inline)
    # Through the wrapper to scan, and no further: is_field is scan's own callee.
    assert direct == {"scan_text", "scan"}
    assert harness_reach.callee_closure({"scan_text"}, by_name, "api") == {"scan_text", "scan", "is_field"}
    # The same function defined in a .c file is an ordinary caller: what it calls is not direct.
    by_name = harness_reach._functions_by_name(_scan_dag(wrapper_in_header=False))
    direct = harness_reach.callee_closure({"scan_text"}, by_name, "api", follow=harness_reach.is_header_inline)
    assert direct == {"scan_text"}
    assert harness_reach.transitive_only_roots(["scan"], {"scan_text", "parse_a"}, by_name, "api") == {
        "scan": ["parse_a", "scan_text"]
    }


def test_macro_alias_of_an_entry_point_counts_as_direct(tmp_path, monkeypatch):
    # A header macro alias...
    call = PARSE_BOTH + ' (void)scan_alias((const char *)fuzz_buf, "s");'
    dag, hdir = _scan_run(tmp_path, monkeypatch, call)
    api = _api(harness_reach.run_check(dag, hdir, ["api"]))
    assert "scan" in api["roots"] and api["passed"] is True and api["reached_only_through"] == {}


def test_model_macro_alias_of_an_entry_point_counts_as_direct():
    # ...and one only the model knows (`macro_aliases` in the DAG, defined by no header read here).
    text = 'void drive(const char *s) { parse_a(s); parse_b(s); scan_m(s, "s"); }\n'
    api = harness_reach.check_module("api", _scan_dag(), {}, text, [])
    assert api["gaps"] == ["scan"] and api["reached_only_through"] == {"scan": ["parse_a", "parse_b"]}
    dag_doc = {**_scan_dag(), "macro_aliases": {"scan_m": ["scan"]}}
    api = harness_reach.check_module("api", dag_doc, {}, text, [])
    assert "scan" in api["roots"] and api["passed"] is True and api["gaps"] == []
    assert api["reached_only_through"] == {}


MINMEA_PARSERS = [f"minmea_parse_{s}" for s in ("gbs", "gga", "gll", "gsa", "gst", "gsv", "rmc", "vtg", "zda")]


def test_minmea_shape_fails_the_gate_on_the_scanner_behind_the_parsers(tmp_path, monkeypatch):
    # minmea run-1: 17 entry points, 16 roots, `entry_points_reached: 17`, `gaps: []`. The variadic
    # minmea_scan was only called by the parsers, with their own format strings (CVE-2026-29974).
    callers = [*MINMEA_PARSERS, "minmea_sentence_id", "minmea_talker_id"]
    others = ["minmea_check", "minmea_checksum", "minmea_getdatetime", "minmea_gettime", "minmea_sentence"]
    unit = "libminmea_a"
    functions = {n: _ufn(n, unit, "minmea", TIER_1A, ["minmea_scan"]) for n in callers}
    functions.update({n: _ufn(n, unit, "minmea", TIER_1A) for n in others})
    functions["minmea_scan"] = _ufn("minmea_scan", unit, "minmea", TIER_1A, ["minmea_isfield"])
    functions["minmea_isfield"] = {**_ufn("minmea_isfield", unit, "minmea", TIER_1A, static=True), "header": True}
    entries = sorted(k for k, f in functions.items() if not f["is_static"])
    assert len(entries) == 17
    dag_doc = {
        "module_kind": "link_unit",
        "modules": {
            unit: {
                "module": unit,
                "tier": TIER_1A,
                "functions": sorted(functions),
                "candidate_entry_points": entries,
                "lexer_modules": ["minmea"],
            }
        },
        "functions": functions,
        "lexer_modules": {"minmea": {"module": "minmea", "tier": TIER_1A}},
        "unit_of_lexer_module": {"minmea": unit},
    }
    call = " ".join(f"{n}();" for n in [*callers, *others])
    dag, hdir = _unit_run(tmp_path, monkeypatch, {"minmea": call}, dag=dag_doc, units={"minmea": unit})
    report = harness_reach.run_check(dag, hdir, None)
    row = _rows(report)["minmea"]
    assert report["passed"] is False and row["passed"] is False
    assert row["entry_points"] == 17 and row["entry_points_reached"] == 16
    assert row["gaps"] == ["minmea_scan"]
    assert row["reached_only_through"] == {"minmea_scan": sorted(callers)}
    assert len(row["roots"]) == 16 and "minmea_scan" not in row["roots"]
    # Every function of the module is still below the roots.
    assert row["functions_reached"] == row["functions"] == 18


def test_target_fuzz_module_row_has_no_transitive_only_entry_point(tmp_path, monkeypatch):
    dag, hdir = _unit_run(tmp_path, monkeypatch, {"decode": "dec_run(); dec_peek();"})
    _add_target_fuzzer(tmp_path, FUZZER_C)
    tf = _rows(harness_reach.run_check(dag, hdir, ["tf_fuzz_kv"]))["tf_fuzz_kv"]
    assert tf["passed"] is True and tf["entry_points"] == 0 and tf["reached_only_through"] == {}


# --- link units as DAG modules (step I5b) ---------------------------------------------------

T2 = "Tier 2 (Recursive Heap / Tree Parser)"
T3 = "Tier 3 (Internal State / Glue Module)"


def _ufn(name: str, unit: str, lexer: str, tier: str, callees=(), static=False) -> dict:
    return {
        "name": name,
        "file": f"src/{lexer}.c",
        "module": unit,
        "lexer_module": lexer,
        "tier": tier,
        "is_static": static,
        "internal_callees": list(callees),
    }


def _unit_dag(exe: str = "kvtool", exe_lexer: str = "tool") -> dict:
    """libkv_a (lexer modules decode, encode, util, errs), an executable and an example program."""
    functions = {
        "dec_run": _ufn("dec_run", "libkv_a", "decode", TIER_1A, ["dec_step", "u_len"]),
        "dec_step": _ufn("dec_step", "libkv_a", "decode", TIER_1A, static=True),
        "dec_peek": _ufn("dec_peek", "libkv_a", "decode", TIER_1A),
        "enc_run": _ufn("enc_run", "libkv_a", "encode", T2),
        "u_len": _ufn("u_len", "libkv_a", "util", TIER_1A),
        "err_str": _ufn("err_str", "libkv_a", "errs", T3),
        "main": _ufn("main", exe, exe_lexer, TIER_1A, ["dec_run"]),
        "rnd": _ufn("rnd", exe, "rnd", TIER_1A),
        "demo_main": _ufn("demo_main", "kvdemo", "example", TIER_1A),
    }
    lexer_tiers = {"decode": TIER_1A, "encode": T2, "util": TIER_1A, "errs": T3, exe_lexer: TIER_1A}
    lexer_tiers.update({"rnd": TIER_1A, "example": TIER_1A})
    units = {"libkv_a": ["decode", "encode", "util", "errs"], exe: [exe_lexer, "rnd"], "kvdemo": ["example"]}
    modules = {
        u: {
            "module": u,
            "tier": TIER_1A,
            "functions": sorted(k for k, f in functions.items() if f["module"] == u),
            "candidate_entry_points": sorted(
                k for k, f in functions.items() if f["module"] == u and not f["is_static"]
            ),
            "lexer_modules": lexers,
        }
        for u, lexers in units.items()
    }
    return {
        "module_kind": "link_unit",
        "modules": modules,
        "functions": functions,
        "lexer_modules": {m: {"module": m, "tier": t} for m, t in lexer_tiers.items()},
        "unit_of_lexer_module": {m: u for u, lexers in units.items() for m in lexers},
        "header_inline_callees": {},
    }


def _unit_run(tmp_path: Path, monkeypatch, harnesses: dict[str, str], dag: dict | None = None, exempt=None, units=None):
    (tmp_path / "workspace/reports").mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    dag_path = tmp_path / "workspace/reports/callgraph_dag.json"
    dag_path.write_text(json.dumps(dag or _unit_dag()), encoding="utf-8")
    hdir = tmp_path / "workspace/harnesses"
    hdir.mkdir(parents=True)
    for name, call in harnesses.items():
        (hdir / f"harness_{name}.c").write_text(f"void drive(void) {{ {call} }}\n", encoding="utf-8")
        sidecar = {"module": name, "harness_file": f"workspace/harnesses/harness_{name}.c", "cppflags": "-I."}
        unit = (units or {"decode": "libkv_a", "encode": "libkv_a"}).get(name)
        if unit:
            sidecar["unit"] = unit
        (hdir / f"harness_{name}.json").write_text(json.dumps(sidecar), encoding="utf-8")
    if exempt:
        (hdir / harness_reach.MODULE_EXEMPT_FILE).write_text(json.dumps(exempt), encoding="utf-8")
    return dag_path, hdir


def _rows(report: dict) -> dict[str, dict]:
    return {m["module"]: m for m in report["modules"]}


def test_sub_module_is_gated_on_the_unit_api_in_its_scope(tmp_path, monkeypatch):
    dag, hdir = _unit_run(tmp_path, monkeypatch, {"decode": "dec_run();", "encode": "enc_run();"})
    rows = _rows(harness_reach.run_check(dag, hdir, ["decode"]))
    assert list(rows) == ["decode"]  # --module limits the check to the named harness module
    dec = rows["decode"]
    assert dec["unit"] == "libkv_a" and dec["tier"] == TIER_1A
    assert dec["entry_points"] == 2 and dec["gaps"] == ["dec_peek"]  # enc_run, u_len are other scopes
    assert dec["functions"] == 3 and dec["functions_reached"] == 2
    assert rows["decode"]["passed"] is False


def test_unit_row_reports_api_outside_every_harness_scope(tmp_path, monkeypatch):
    harnesses = {"decode": "dec_run(); dec_peek();", "encode": "enc_run();"}
    dag, hdir = _unit_run(tmp_path, monkeypatch, harnesses, exempt={"tool": "cli", "rnd": "entropy", "example": "ex"})
    report = harness_reach.run_check(dag, hdir, None)
    rows = _rows(report)
    assert rows["decode"]["passed"] and rows["encode"]["passed"]
    # u_len (lexer module util, reached by the decode harness but in no harness scope) is a unit gap;
    # err_str is Tier 3 code, deferred by design.
    lib = rows["libkv_a"]
    assert lib["harness_modules"] == ["decode", "encode"]
    assert lib["unharnessed_entry_points"] == ["u_len"] and lib["gaps"] == ["u_len"]
    assert report["passed"] is False
    # Units without a harness made of exempt lexer modules pass as exempt.
    assert (
        rows["kvtool"]["passed"]
        and "tool: cli" in rows["kvtool"]["exempt"]
        and "rnd: entropy" in rows["kvtool"]["exempt"]
    )
    assert rows["kvdemo"]["passed"] and "example: ex" in rows["kvdemo"]["exempt"]

    # The lexer module's key exempts its entry points at unit level; so does the unit's name.
    (hdir / harness_reach.MODULE_EXEMPT_FILE).write_text(
        json.dumps({"tool": "cli", "rnd": "entropy", "example": "ex", "util": "helpers"}), encoding="utf-8"
    )
    rows = _rows(harness_reach.run_check(dag, hdir, None))
    assert rows["libkv_a"]["passed"] and rows["libkv_a"]["exempt"] == {"u_len": "module util: helpers"}
    (hdir / harness_reach.MODULE_EXEMPT_FILE).write_text(
        json.dumps({"kvtool": "cli", "kvdemo": "ex", "libkv_a": "pinned"}), encoding="utf-8"
    )
    report = harness_reach.run_check(dag, hdir, None)
    rows = _rows(report)
    assert rows["libkv_a"]["exempt"] == {"u_len": "unit libkv_a: pinned"}
    assert rows["kvtool"]["exempt"] == "cli"  # a unit without a harness, exempt by name as a module was
    assert report["passed"] is True


def test_unit_without_harness_or_exemption_fails_no_harness(tmp_path, monkeypatch):
    dag, hdir = _unit_run(tmp_path, monkeypatch, {"decode": "dec_run(); dec_peek();"}, exempt={"example": "ex"})
    rows = _rows(harness_reach.run_check(dag, hdir, None))
    tool = rows["kvtool"]
    assert tool["error"] == "no_harness" and tool["gaps"] == ["main", "rnd"]
    assert rows["kvdemo"]["passed"]
    # An executable whose name is also one of its lexer modules (tweetnacl's `main`): with a harness
    # in the unit, that key exempts the lexer module only, never the rest of the unit.
    dag2, hdir2 = _unit_run(
        tmp_path / "b",
        monkeypatch,
        {"nacl": "main();"},
        dag=_unit_dag(exe="main", exe_lexer="main"),
        exempt={"main": "cli", "example": "ex"},
        units={"nacl": "main"},
    )
    rows = _rows(harness_reach.run_check(dag2, hdir2, None))
    assert rows["main"]["exempt"] == {"main": "module main: cli"} and rows["main"]["gaps"] == ["rnd"]


def test_unit_entry_point_exemption_lands_in_a_sub_module_sidecar(tmp_path, monkeypatch):
    harnesses = {"decode": "dec_run(); dec_peek();", "encode": "enc_run();"}
    dag, hdir = _unit_run(tmp_path, monkeypatch, harnesses, exempt={"kvtool": "cli", "kvdemo": "ex"})
    assert harness_reach.run_check(dag, hdir, None)["passed"] is False
    out = harness_reach.record_exempt(hdir, "libkv_a", "u_len", "internal helper", dag)
    assert out["reach_exempt"] == {"u_len": "internal helper"}
    assert json.loads((hdir / "harness_decode.json").read_text(encoding="utf-8"))["reach_exempt"] == {
        "u_len": "internal helper"
    }
    report = harness_reach.run_check(dag, hdir, None)
    assert report["passed"] is True and _rows(report)["libkv_a"]["exempt"] == {"u_len": "internal helper"}


# --- dynamic reach (step I6) ----------------------------------------------------------------


def _coverage(run: Path, executions: dict[str, int], status: str = "ok", inputs: dict | None = None) -> Path:
    cdir = run / "workspace" / "reports" / "coverage"
    cdir.mkdir(parents=True, exist_ok=True)
    rows = [{"function": f, "file": "src/api.c", "line": 1, "executions": n} for f, n in executions.items()]
    doc = {"status": status, "functions": rows, "inputs": inputs or {"replayed": 3}}
    (cdir / "api.json").write_text(json.dumps(doc))
    return cdir


def _dynamic_doc(run: Path) -> dict:
    return json.loads((run / "workspace/reports/harness_reach_dynamic.json").read_text())


def test_partial_coverage_with_unreplayed_inputs_is_unmeasured_and_clears_a_stale_failure(
    tmp_path, monkeypatch, capsys
):
    # QCBOR run-4: the replay stopped after 16 failing inputs, 1,971 of 2,240 never ran, and the gaps of
    # that lower bound failed the module and blocked wp-queue.
    import phase0_gates

    run = _run_dir(tmp_path, monkeypatch)
    hdir = _write_harness(run, "rec_parse(fuzz_buf, fuzz_len); rec_put(fuzz_buf, fuzz_len, 1);")
    harness_reach.record_exempt(hdir, "api", "rec_print", "debug output")
    harness_reach.record_exempt(hdir, "tools", None, "examples")
    assert harness_reach.main(["check", "--harness-dir", str(hdir)]) == 0
    # An earlier, complete measurement failed the module.
    _coverage(run, {"rec_parse": 40, "rec_put": 0})
    assert harness_reach.main(["dynamic", "--module", "api"]) == 1
    assert phase0_gates.check(run, "api", ("reach",))

    inputs = {"total": 2240, "replayed": 253, "failed": 16, "not_replayed": 1971}
    _coverage(run, {"rec_parse": 40, "rec_put": 0}, status="partial", inputs=inputs)
    capsys.readouterr()
    assert harness_reach.main(["dynamic", "--module", "api"]) == 2
    [row] = json.loads(capsys.readouterr().out)["modules"]
    assert row["passed"] is None and row["error"] == "partial coverage: 1971 of 2240 inputs not replayed"
    assert row["executions"] == {"rec_parse": 40, "rec_print": 0, "rec_put": 0}
    assert row["gaps_lower_bound"] == ["rec_put"] and "gaps" not in row
    doc = _dynamic_doc(run)
    assert doc["modules"] == {} and doc["unmeasured"] == {"api": row["error"]}
    # The stale dynamic failure is gone: the gate is what the static check says, and `check` agrees.
    assert phase0_gates.check(run, "api", ("reach",)) == []
    assert harness_reach.main(["check", "--harness-dir", str(hdir)]) == 0


def test_replayed_corpus_with_failing_inputs_is_a_measurement(tmp_path, monkeypatch):
    import phase0_gates
    from validate_artifacts import validate_dynamic_reach

    run = _run_dir(tmp_path, monkeypatch)
    hdir = _write_harness(run, "rec_parse(fuzz_buf, fuzz_len); rec_put(fuzz_buf, fuzz_len, 1);")
    harness_reach.record_exempt(hdir, "api", "rec_print", "debug output")
    harness_reach.record_exempt(hdir, "tools", None, "examples")
    assert harness_reach.main(["check", "--harness-dir", str(hdir)]) == 0
    inputs = {"total": 20, "replayed": 20, "failed": 4, "not_replayed": 0}
    _coverage(run, {"rec_parse": 40, "rec_put": 0}, status="partial", inputs=inputs)
    assert harness_reach.main(["dynamic", "--module", "api"]) == 1
    doc = _dynamic_doc(run)
    assert doc["modules"]["api"]["failed_inputs"] == 4 and doc["modules"]["api"]["gaps"] == ["rec_put"]
    assert validate_dynamic_reach(doc) == [] and "warnings" not in doc
    assert phase0_gates.check(run, "api", ("reach",))
    # The corpus later executes everything: the dynamic failure is lifted without a manual reach-gate.
    _coverage(run, {"rec_parse": 40, "rec_put": 3}, inputs={"total": 25, "replayed": 25, "not_replayed": 0})
    assert harness_reach.main(["dynamic", "--module", "api"]) == 0
    assert "failed_inputs" not in _dynamic_doc(run)["modules"]["api"]
    assert phase0_gates.check(run, "api", ("reach",)) == []


def test_unresolved_prelude_fails_the_static_gate(tmp_path, monkeypatch):
    # QCBOR run-4: generate_harness wrote harness and sidecar, then raised; the gate passed the harness.
    import phase0_gates

    run = _run_dir(tmp_path, monkeypatch)
    hdir = _write_harness(
        run,
        "rec_parse(fuzz_buf, fuzz_len); rec_put(fuzz_buf, fuzz_len, 1);",
        reach_exempt={"rec_print": "debug output"},
        prelude_status="unresolved",
        prelude_unresolved=["UsefulBufC", "QCBORItem"],
    )
    harness_reach.record_exempt(hdir, "tools", None, "examples")
    assert harness_reach.main(["check", "--harness-dir", str(hdir)]) == 1
    [reason] = phase0_gates.check(run, "api", ("reach",))
    assert "harness_prelude_unresolved: UsefulBufC, QCBORItem" in reason
    # A resolved prelude passes.
    _write_harness(
        run,
        "rec_parse(fuzz_buf, fuzz_len); rec_put(fuzz_buf, fuzz_len, 1);",
        reach_exempt={"rec_print": "debug output"},
        prelude_status="resolved",
        prelude_unresolved=[],
    )
    assert harness_reach.main(["check", "--harness-dir", str(hdir)]) == 0


def test_unexecuted_entry_point_reopens_the_gate_until_the_harness_changes(tmp_path, monkeypatch, capsys):
    import phase0_gates

    run = _run_dir(tmp_path, monkeypatch)
    hdir = _write_harness(run, "rec_parse(fuzz_buf, fuzz_len); rec_put(fuzz_buf, fuzz_len, 1);")
    harness_reach.record_exempt(hdir, "api", "rec_print", "debug output")
    harness_reach.record_exempt(hdir, "tools", None, "examples")
    assert harness_reach.main(["check", "--harness-dir", str(hdir)]) == 0
    assert phase0_gates.check(run, "api", ("reach",)) == []

    # The corpus never got past the guard in front of rec_put: the static gate passed, the dynamic one fails.
    _coverage(run, {"rec_parse": 40, "rec_put": 0, "rec_ok": 12})
    assert harness_reach.main(["dynamic", "--module", "api"]) == 1
    dyn = json.loads((run / "workspace/reports/harness_reach_dynamic.json").read_text())["modules"]["api"]
    assert dyn["gaps"] == ["rec_put"] and dyn["executions"] == {"rec_parse": 40, "rec_print": 0, "rec_put": 0}
    assert dyn["harness_digest"] == phase0_gates.harness_digest(run, "api", ignore_exempt=True)
    [reason] = phase0_gates.check(run, "api", ("reach",))
    assert "never executed" in reason

    # The static check keeps the gap while the harness is the one coverage measured...
    capsys.readouterr()
    assert harness_reach.main(["check", "--harness-dir", str(hdir)]) == 1
    assert phase0_gates.check(run, "api", ("reach",))
    # ...and a repaired harness clears it.
    _write_harness(
        run,
        "rec_put(fuzz_buf, fuzz_len, fuzz_len ? fuzz_buf[0] : 0); rec_parse(fuzz_buf, fuzz_len);",
        reach_exempt={"rec_print": "debug output"},
    )
    assert harness_reach.main(["check", "--harness-dir", str(hdir)]) == 0
    assert phase0_gates.check(run, "api", ("reach",)) == []

    # An executed entry point, or an exempted one, passes; no coverage report is a usage error.
    _coverage(run, {"rec_parse": 40, "rec_put": 2})
    assert harness_reach.main(["dynamic", "--module", "api"]) == 0
    _coverage(run, {"rec_parse": 40})
    harness_reach.record_exempt(hdir, "api", "rec_put", "writer, not reachable from input")
    assert harness_reach.main(["dynamic", "--module", "api"]) == 0
    _coverage(run, {}, status="error")
    assert harness_reach.main(["dynamic", "--module", "api"]) == 2


def _exempt_cli(hdir: Path, capsys, *functions: str, module: str = "api") -> dict:
    capsys.readouterr()
    argv = ["exempt", "--harness-dir", str(hdir), "--module", module, "--reason", "cannot be driven from bytes"]
    for fn in functions:
        argv += ["--function", fn]
    assert harness_reach.main(argv) == 0
    return json.loads(capsys.readouterr().out)


def test_exempting_a_dynamic_gap_reopens_the_gate_without_a_reach_gate_run(tmp_path, monkeypatch, capsys):
    # ptf-original run-2: coverage-<mod> stopped at the recorded dynamic failure, and reach-dynamic-<mod>,
    # which would have replaced it, depends on coverage-<mod>.
    import phase0_gates

    run = _run_dir(tmp_path, monkeypatch)
    hdir = _write_harness(run, "rec_parse(fuzz_buf, fuzz_len); rec_put(fuzz_buf, fuzz_len, 1); rec_print(0, 0);")
    harness_reach.record_exempt(hdir, "tools", None, "examples")
    assert harness_reach.main(["check", "--harness-dir", str(hdir)]) == 0
    _coverage(run, {"rec_parse": 40, "rec_put": 0, "rec_print": 0})
    assert harness_reach.main(["dynamic", "--module", "api"]) == 1
    [reason] = phase0_gates.check(run, "api", ("reach",))
    # The gate's message names both ways out.
    assert "never executed" in reason and "harness_reach.py check" in reason
    assert "harness_reach.py exempt --module api --function <fn>" in reason

    # One of the two gaps exempted: re-checked, still failing on the other.
    out = _exempt_cli(hdir, capsys, "rec_put")
    assert out["gate"]["rechecked"] == ["api"] and "never executed" in out["gate"]["still_failing"]["api"]
    assert phase0_gates.load_gates(run)["reach"]["modules"]["api"]["gaps"] == ["rec_print"]
    assert phase0_gates.check(run, "api", ("reach",))

    out = _exempt_cli(hdir, capsys, "rec_print")
    assert out["gate"] == {"rechecked": ["api"]}
    assert phase0_gates.check(run, "api", ("reach",)) == []
    assert phase0_gates.check(run, None, ("reach",)) == []


def test_exempt_takes_several_functions_and_keeps_a_passing_gate_passing(tmp_path, monkeypatch, capsys):
    import phase0_gates

    run = _run_dir(tmp_path, monkeypatch)
    hdir = _write_harness(run, "rec_parse(fuzz_buf, fuzz_len);")
    harness_reach.record_exempt(hdir, "tools", None, "examples")
    # Before the gate's first run nothing is recorded: `reach-gate` still has to run.
    out = _exempt_cli(hdir, capsys, "rec_put", "rec_print")
    assert out["function"] == ["rec_put", "rec_print"] and set(out["reach_exempt"]) == {"rec_put", "rec_print"}
    assert out["gate"] == {"rechecked": [], "note": "the reach gate has not run yet"}
    assert "reach" not in phase0_gates.load_gates(run)

    assert harness_reach.main(["check", "--harness-dir", str(hdir)]) == 0
    # The sidecar is part of the harness digest: a further exemption used to leave the row stale
    # ("the harness of api changed after the reach gate ran").
    out = _exempt_cli(hdir, capsys, "rec_parse")
    assert out["function"] == "rec_parse" and out["gate"] == {"rechecked": ["api"]}
    assert phase0_gates.check(run, "api", ("reach",)) == []


def test_module_exemption_clears_the_failed_row_of_that_module(tmp_path, monkeypatch, capsys):
    import phase0_gates

    run = _run_dir(tmp_path, monkeypatch)
    hdir = _write_harness(run, "rec_parse(fuzz_buf, fuzz_len); rec_put(fuzz_buf, fuzz_len, 1); rec_print(0, 0);")
    assert harness_reach.main(["check", "--harness-dir", str(hdir)]) == 1  # tools: no_harness
    assert phase0_gates.check(run, "tools", ("reach",))
    out = _exempt_cli(hdir, capsys, module="tools")
    assert out["gate"] == {"rechecked": ["tools"]}
    assert phase0_gates.check(run, None, ("reach",)) == []


def test_unit_exemption_in_a_sub_module_sidecar_re_records_the_unit_and_the_sub_module(tmp_path, monkeypatch, capsys):
    import phase0_gates

    harnesses = {"decode": "dec_run(); dec_peek();", "encode": "enc_run();"}
    dag, hdir = _unit_run(tmp_path, monkeypatch, harnesses, exempt={"kvtool": "cli", "kvdemo": "ex"})
    assert harness_reach.main(["check", "--dag", str(dag), "--harness-dir", str(hdir)]) == 1
    capsys.readouterr()
    argv = ["exempt", "--dag", str(dag), "--harness-dir", str(hdir), "--module", "libkv_a"]
    assert harness_reach.main([*argv, "--function", "u_len", "--reason", "internal helper"]) == 0
    gate = json.loads(capsys.readouterr().out)["gate"]
    # The exemption went into decode's sidecar, whose digest changed with it.
    assert {"libkv_a", "decode"} <= set(gate["rechecked"]) and "still_failing" not in gate
    for module in ("libkv_a", "decode", "encode"):
        assert phase0_gates.check(tmp_path, module, ("reach",)) == []


# --- target fuzz modules (tf_<id>: the target's own fuzz function) ---------------------------

TF_ENTRY = "__framac_target_embedded_LLVMFuzzerTestOneInput"


def _add_target_fuzzer(
    run: Path, fuzzer_text: str | None, unit: str = "libkv_a", name: str = "tf_fuzz_kv"
) -> dict[str, Any]:
    """A target fuzz module of `unit` around workspace/work/fuzz/fuzz_kv.c (not written when None)."""
    src = "workspace/work/fuzz/fuzz_kv.c"
    if fuzzer_text is not None:
        (run / src).parent.mkdir(parents=True, exist_ok=True)
        (run / src).write_text(fuzzer_text, encoding="utf-8")
    hdir = run / "workspace/harnesses"
    hdir.mkdir(parents=True, exist_ok=True)
    (hdir / f"harness_{name}.c").write_text(
        f'#include "{Path(src).name}"\nint LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n)'
        f" {{ return {TF_ENTRY}(d, n); }}\n",
        encoding="utf-8",
    )
    sidecar = {
        "module": name,
        "unit": unit,
        "harness_file": f"workspace/harnesses/harness_{name}.c",
        "cppflags": "-I.",
        "sources": [src],
        "scope_files": [src],
        "entry_fn": TF_ENTRY,
        "entry_style": "buffer_len",
        "target_fuzzer": {"id": "fuzz_kv", "source": src, "initialize": False},
    }
    (hdir / f"harness_{name}.json").write_text(json.dumps(sidecar), encoding="utf-8")
    return sidecar


FUZZER_C = "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { dec_run(); return 0; }\n"


def test_target_fuzz_module_takes_its_roots_from_the_fuzzer_source(tmp_path, monkeypatch):
    dag, hdir = _unit_run(
        tmp_path, monkeypatch, {"decode": "dec_run(); dec_peek();"}, exempt={"kvtool": "c", "kvdemo": "e"}
    )
    _add_target_fuzzer(tmp_path, FUZZER_C)
    rows = _rows(harness_reach.run_check(dag, hdir, None))
    tf = rows["tf_fuzz_kv"]
    assert tf["passed"] is True and tf["target_fuzzer"] == "fuzz_kv" and tf["unit"] == "libkv_a"
    # It answers for no entry point; its roots come from the fuzzer, not the wrapper.
    assert tf["entry_points"] == 0 and tf["gaps"] == [] and tf["roots"] == ["dec_run"]
    # Additive: the unit's own row is decided by its own harnesses only (u_len and enc_run stay gaps).
    lib = rows["libkv_a"]
    assert lib["harness_modules"] == ["decode"] and lib["passed"] is False


def test_target_fuzz_module_that_reaches_nothing_or_has_no_source_fails(tmp_path, monkeypatch):
    dag, hdir = _unit_run(tmp_path, monkeypatch, {"decode": "dec_run();"})
    _add_target_fuzzer(tmp_path, "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { return 0; }\n")
    tf = _rows(harness_reach.run_check(dag, hdir, ["tf_fuzz_kv"]))["tf_fuzz_kv"]
    assert tf["passed"] is False and tf["error"] == "target_fuzzer_reaches_nothing"

    (tmp_path / "workspace/work/fuzz/fuzz_kv.c").unlink()
    tf = _rows(harness_reach.run_check(dag, hdir, ["tf_fuzz_kv"]))["tf_fuzz_kv"]
    assert tf["passed"] is False and tf["error"] == "target_fuzzer_source_missing"


def test_unit_with_only_a_target_fuzz_module_still_fails_no_harness(tmp_path, monkeypatch):
    dag, hdir = _unit_run(tmp_path, monkeypatch, {}, exempt={"kvtool": "cli", "kvdemo": "ex"})
    _add_target_fuzzer(tmp_path, FUZZER_C)
    report = harness_reach.run_check(dag, hdir, None)
    rows = _rows(report)
    assert rows["tf_fuzz_kv"]["passed"] is True
    assert rows["libkv_a"]["error"] == "no_harness" and report["passed"] is False
    # Nor does an entry-point exemption of the unit land in the target fuzz module's sidecar.
    with pytest.raises((ArtifactError, OSError)):
        harness_reach.record_exempt(hdir, "libkv_a", "u_len", "helper", dag)
    assert "reach_exempt" not in json.loads((hdir / "harness_tf_fuzz_kv.json").read_text(encoding="utf-8"))


def test_dynamic_gate_holds_a_target_fuzz_module_to_no_entry_point(tmp_path, monkeypatch, capsys):
    dag, hdir = _unit_run(tmp_path, monkeypatch, {"decode": "dec_run(); dec_peek();"})
    _add_target_fuzzer(tmp_path, FUZZER_C)
    cdir = tmp_path / "workspace/reports/coverage"
    cdir.mkdir(parents=True)
    rows = [{"function": "dec_run", "file": "src/decode.c", "line": 1, "executions": 0}]
    (cdir / "tf_fuzz_kv.json").write_text(json.dumps({"status": "ok", "functions": rows, "inputs": {"replayed": 1}}))
    assert harness_reach.main(["dynamic", "--module", "tf_fuzz_kv"]) == 0
    out = json.loads((tmp_path / "workspace/reports/harness_reach_dynamic.json").read_text())
    row = out["modules"]["tf_fuzz_kv"]
    assert row["passed"] is True and row["entry_points"] == 0 and row["gaps"] == []
    assert "warnings" not in out


# ---------------------------------------------------------------------------
# B11: Clang AST Callee Extraction
# ---------------------------------------------------------------------------


def test_b11_callees_from_clang_ast():
    from harness_reach import _callees_from_clang_ast

    tree = {
        "kind": "TranslationUnitDecl",
        "inner": [
            {
                "kind": "FunctionDecl",
                "name": "LLVMFuzzerTestOneInput",
                "inner": [
                    {
                        "kind": "CompoundStmt",
                        "inner": [
                            {
                                "kind": "CallExpr",
                                "calleeDecl": {"name": "target_init"},
                                "inner": [
                                    {
                                        "kind": "DeclRefExpr",
                                        "referencedDecl": {"kind": "FunctionDecl", "name": "target_init"},
                                    }
                                ],
                            },
                            {
                                "kind": "CallExpr",
                                "inner": [
                                    {
                                        "kind": "DeclRefExpr",
                                        "referencedDecl": {"kind": "FunctionDecl", "name": "target_process"},
                                    }
                                ],
                            },
                            {
                                "kind": "DeclRefExpr",
                                "name": "target_cleanup",
                            },
                        ],
                    }
                ],
            }
        ],
    }
    callees = _callees_from_clang_ast(tree)
    assert callees == {"target_init", "target_process", "target_cleanup"}

