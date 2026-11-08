"""Tests for the Phase 0 harness reachability gate (scripts/harness_reach.py) and the `dispatch` entry style."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

import harness_reach
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
    kwargs = dict(
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


def _coverage(run: Path, executions: dict[str, int], status: str = "ok") -> Path:
    cdir = run / "workspace" / "reports" / "coverage"
    cdir.mkdir(parents=True, exist_ok=True)
    rows = [{"function": f, "file": "src/api.c", "line": 1, "executions": n} for f, n in executions.items()]
    (cdir / "api.json").write_text(json.dumps({"status": status, "functions": rows, "inputs": {"replayed": 3}}))
    return cdir


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
    assert dyn["harness_digest"] == phase0_gates.harness_digest(run, "api")
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
