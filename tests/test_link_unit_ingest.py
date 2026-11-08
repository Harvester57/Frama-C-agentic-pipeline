"""
Link units as ledger modules with harness sub-modules (step I5b): seeding, Eva and fuzz ingest,
candidate harness modules, the WP scheduler's per-unit sidecars and gates, the overlay's sidecar
resolution and the report's concurrency sentence.
"""

from __future__ import annotations

import json

import pytest

import generate_report as R
import ledger as L
import workspace_overlay as WO
import wp_scheduler as S
from conftest import write_json
from module_map import ModuleMap
from validate_artifacts import validate_ledger

pytestmark = pytest.mark.unit

T1A = "Tier 1A (Untrusted Binary / Network Parser)"
T2 = "Tier 2 (Heap/Tree Parser)"
DAG_REL = "workspace/reports/callgraph_dag.json"


def _fn(name: str, file: str, lexer: str, tier: str, line: int, end: int, wave: int = 0) -> dict:
    return {
        "name": name,
        "file": file,
        "module": "libx_a",
        "lexer_module": lexer,
        "tier": tier,
        "wave": wave,
        "line": line,
        "end_line": end,
    }


def link_dag(concurrent: bool = True) -> dict:
    """One library unit `libx_a` holding the lexer modules `decode` (Tier 1A) and `encode` (Tier 2)."""
    functions = {
        "dec_run": _fn("dec_run", "src/dec.c", "decode", T1A, 1, 20, 1),
        "dec_step": _fn("dec_step", "src/dec.c", "decode", T1A, 22, 40),
        "enc_run": _fn("enc_run", "src/enc.c", "encode", T2, 1, 30),
    }
    return {
        "callgraph_source": "frama_c",
        "module_kind": "link_unit",
        "functions": functions,
        "modules": {
            "libx_a": {
                "module": "libx_a",
                "unit": "libx.a",
                "kind": "static_library",
                "concurrent": concurrent,
                "files": ["src/dec.c", "src/enc.c"],
                "required_sources": ["src/dec.c", "src/enc.c"],
                "functions": sorted(functions),
                "candidate_entry_points": ["dec_run", "enc_run"],
                "lexer_modules": ["decode", "encode"],
                "tier": T1A,
                "run_eva": True,
                "run_eacsl_fuzz": True,
                "run_wp_full": True,
            }
        },
        "lexer_modules": {
            "decode": {"module": "decode", "tier": T1A, "functions": ["dec_run", "dec_step"]},
            "encode": {"module": "encode", "tier": T2, "functions": ["enc_run"]},
        },
        "unit_of_lexer_module": {"decode": "libx_a", "encode": "libx_a"},
    }


def sidecar(module: str, src: str, flag: str, entry: str) -> dict:
    return {
        "module": module,
        "unit": "libx_a",
        "sources": [f"workspace/work/{src}"],
        "cppflags": f"-I. -include workspace/harnesses/compat.h {flag}",
        "entry_fn": entry,
        "header": "x.h",
    }


def setup_run(run_dir, concurrent: bool = True) -> None:
    write_json(run_dir / DAG_REL, link_dag(concurrent))
    write_json(run_dir / "workspace/harnesses/harness_decode.json", sidecar("decode", "src/dec.c", "-DDEC", "dec_run"))
    write_json(run_dir / "workspace/harnesses/harness_encode.json", sidecar("encode", "src/enc.c", "-DENC", "enc_run"))
    L.cmd_seed(run_dir / DAG_REL, [], "frama_c")


def units(run_dir) -> dict[str, dict]:
    return {u["coverage_id"]: u for u in json.loads((run_dir / "coverage-ledger.json").read_text(encoding="utf-8"))}


def candidates(run_dir) -> list[dict]:
    return json.loads((run_dir / "candidates.json").read_text(encoding="utf-8"))


def assert_valid(run_dir) -> None:
    ledger = json.loads((run_dir / "coverage-ledger.json").read_text(encoding="utf-8"))
    assert list(validate_ledger(ledger, run_dir)) == []


def eva_report(module: str, props: dict, unknown: dict | None = None, invalid: list | None = None) -> dict:
    return {
        "status": "ok",
        "module": module,
        "functions_with_properties_by_file": props,
        "unknown_obligations_by_function": unknown or {},
        "invalid_alarms": invalid or [],
        "dead_alarms": [],
        "assumed_properties": [],
    }


def ingest_eva(run_dir, *reports: dict) -> dict:
    paths = []
    for rep in reports:
        path = run_dir / f"workspace/reports/eva/{rep['module']}.json"
        write_json(path, rep)
        paths.append(path)
    return L.cmd_ingest_eva(paths)


# ------------------------------------------------------------------- seed


def test_seed_keeps_lexer_tiers_and_marks_concurrent_units(run_dir):
    setup_run(run_dir)
    by_id = units(run_dir)
    assert by_id["src/dec.c#dec_run::rte"]["module"] == "libx_a"
    assert by_id["src/dec.c#dec_run::rte"]["tier"] == T1A
    assert by_id["src/enc.c#enc_run::rte"]["tier"] == T2  # its lexer module's, not the unit's
    assert all(u["bookkeeping"]["concurrent"] is True for u in by_id.values())
    assert_valid(run_dir)


def test_seed_of_a_unit_without_threads_records_nothing(run_dir):
    setup_run(run_dir, concurrent=False)
    assert all("concurrent" not in (u.get("bookkeeping") or {}) for u in units(run_dir).values())


def test_lexer_dag_seed_is_unchanged(run_dir):
    dag = {
        "callgraph_source": "frama_c",
        "modules": {"m": {"tier": T1A, "concurrent": True}},
        "functions": {"f": {"name": "f", "file": "src/f.c", "module": "m", "wave": 0, "tier": T2}},
    }
    write_json(run_dir / DAG_REL, dag)
    L.cmd_seed(run_dir / DAG_REL, [], "frama_c")
    (u,) = units(run_dir).values()
    assert u["tier"] == T1A and "bookkeeping" not in u


# ------------------------------------------------------------------- Eva


DEC_PROPS = {"workspace/work/src/dec.c": ["dec_run", "dec_step"]}
ENC_PROPS = {"workspace/work/src/enc.c": ["enc_run"], "workspace/work/src/dec.c": ["dec_step"]}


def test_every_sub_module_report_credits_its_units_functions(run_dir):
    setup_run(run_dir)
    out = ingest_eva(run_dir, eva_report("decode", DEC_PROPS), eva_report("encode", ENC_PROPS))
    by_id = units(run_dir)
    assert out["covered"] == 3
    assert by_id["src/dec.c#dec_run::rte"]["bookkeeping"]["eva_verdicts"] == {"decode": "valid"}
    assert by_id["src/enc.c#enc_run::rte"]["bookkeeping"]["eva_verdicts"] == {"encode": "valid"}
    step = by_id["src/dec.c#dec_step::rte"]
    assert step["status"] == "covered"
    assert step["bookkeeping"]["eva_verdicts"] == {"decode": "valid", "encode": "valid"}
    # Sub-modules of the function's own unit: never "another module's harness".
    assert not any("another module" in e["summary"] for u in by_id.values() for e in u["evidence"])
    assert_valid(run_dir)


def test_an_unknown_from_one_sub_module_keeps_the_unit_open(run_dir):
    setup_run(run_dir)
    unknown = {"dec_step": [{"file": "workspace/work/src/dec.c", "line": 30, "kind": "mem_access"}]}
    ingest_eva(run_dir, eva_report("decode", DEC_PROPS), eva_report("encode", ENC_PROPS, unknown))
    step = units(run_dir)["src/dec.c#dec_step::rte"]
    assert step["status"] == "planned"
    assert step["bookkeeping"]["eva_verdicts"] == {"decode": "valid", "encode": "unknown"}
    assert step["evidence"][-1]["summary"].startswith("1 RTE obligation(s) remain Unknown")


def test_a_sub_module_that_never_analysed_a_function_outside_its_scope_records_nothing(run_dir):
    setup_run(run_dir)
    ingest_eva(run_dir, eva_report("encode", {"workspace/work/src/enc.c": ["enc_run"]}))
    dec_run = units(run_dir)["src/dec.c#dec_run::rte"]
    assert dec_run["status"] == "planned" and dec_run["evidence"] == []


def test_eva_candidates_name_the_reports_harness_module_and_reingest_is_a_noop(run_dir):
    setup_run(run_dir)
    alarm = {"file": "workspace/work/src/dec.c", "function": "dec_step", "line": 25, "kind": "mem_access"}
    ingest_eva(run_dir, eva_report("encode", ENC_PROPS, invalid=[alarm]))
    (cand,) = candidates(run_dir)
    assert cand["module"] == "encode"
    assert cand["notes"] == ["Eva Invalid status without a concrete witness input"]
    before = (units(run_dir), candidates(run_dir))
    L.cmd_ingest_eva([run_dir / "workspace/reports/eva/encode.json"])
    assert (units(run_dir), candidates(run_dir)) == before
    assert_valid(run_dir)


def test_an_eva_error_of_a_sub_module_lands_on_its_scope_only(run_dir):
    setup_run(run_dir)
    write_json(run_dir / "workspace/reports/eva/encode.json", {"status": "analysis_error", "module": "encode"})
    L.cmd_ingest_eva([run_dir / "workspace/reports/eva/encode.json"])
    by_id = units(run_dir)
    assert by_id["src/enc.c#enc_run::rte"]["evidence"][-1]["result"] == "eva_analysis_error"
    assert by_id["src/dec.c#dec_run::rte"]["evidence"] == []


# ------------------------------------------------------------------- fuzz


def test_a_clean_sub_module_campaign_credits_its_scope_in_the_unit(run_dir):
    setup_run(run_dir)
    write_json(run_dir / "workspace/reports/fuzz/decode.json", {"module": "decode", "status": "clean"})
    L.cmd_ingest_fuzz([run_dir / "workspace/reports/fuzz/decode.json"])
    by_id = units(run_dir)
    for cid in ("src/dec.c#dec_run::rte", "src/dec.c#dec_step::rte"):
        assert by_id[cid]["evidence"][-1]["result"] == "fuzz_clean"
    assert by_id["src/enc.c#enc_run::rte"]["evidence"] == []


def test_fuzz_candidates_keep_the_harness_module(run_dir):
    setup_run(run_dir)
    fp = "src/enc.c#enc_run::mem_access::0123456789"
    report = {
        "module": "encode",
        "status": "crashes",
        "artifacts": [
            {
                "artifact": "workspace/crashes/encode/crash-1",
                "fingerprint": fp,
                "reproducible": True,
                "failure": {"file": "src/enc.c", "function": "enc_run", "line": 5, "kind": "mem_access"},
            }
        ],
    }
    write_json(run_dir / "workspace/reports/fuzz/encode.json", report)
    L.cmd_ingest_fuzz([run_dir / "workspace/reports/fuzz/encode.json"])
    (cand,) = candidates(run_dir)
    assert cand["module"] == "encode" and cand["linked_units"] == ["src/enc.c#enc_run::rte"]


# ------------------------------------------------------- candidates and overlay


def test_an_older_candidate_naming_the_unit_resolves_to_the_harness_of_its_function(run_dir):
    setup_run(run_dir)
    mm = ModuleMap.load(".")
    cand = {"module": "libx_a", "location": {"file": "src/enc.c", "function": "enc_run"}}
    assert L._candidate_harness_module(mm, cand) == "encode"
    assert L._candidate_harness_module(mm, {"module": "libx_a", "location": {}}) == "decode"
    assert L._candidate_harness_module(mm, {"module": "encode", "location": {}}) == "encode"


def test_overlay_resolves_a_units_sidecars(run_dir):
    setup_run(run_dir)
    mm = WO.module_map_for(run_dir / "workspace")
    assert WO.harness_modules_of(mm, "libx_a") == ["decode", "encode"]
    assert WO.harness_modules_of(mm, "encode") == ["encode"]
    merged = WO.merged_sidecar(mm, "libx_a")
    assert merged["sources"] == ["workspace/work/src/dec.c", "workspace/work/src/enc.c"]
    assert merged["cppflags"] == "-I. -include workspace/harnesses/compat.h -DDEC -DENC"
    assert merged["header"] == "x.h" and "entry_fn" not in merged
    assert WO.merged_sidecar(mm, "decode")["entry_fn"] == "dec_run"
    assert WO.harness_module_for_function(mm, "libx_a", "src/enc.c", "enc_run") == "encode"
    params = {"decode": {"wp_extra_sources": ["a.c"]}, "encode": {"wp_extra_sources": ["a.c", "b.c"]}}
    assert WO.module_param(params, mm, "libx_a", "wp_extra_sources") == ["a.c", "b.c"]
    # The trust boundary is checked against every harness entry of the unit.
    entries = {m["entry_fn"] for m in WO._untrusted_entry_metas(run_dir / "workspace", "libx_a")}
    assert entries == {"dec_run", "enc_run"}


def test_overlay_helpers_are_the_identity_without_link_units(run_dir):
    write_json(run_dir / DAG_REL, {"modules": {"m": {"tier": T1A}}, "functions": {}})
    write_json(run_dir / "workspace/harnesses/harness_m.json", {"module": "m", "cppflags": "-I.", "sources": ["a.c"]})
    mm = WO.module_map_for(run_dir / "workspace")
    assert WO.harness_modules_of(mm, "m") == ["m"]
    assert WO.merged_sidecar(mm, "m") == {"module": "m", "cppflags": "-I.", "sources": ["a.c"]}
    assert WO.harness_module_for_function(mm, "m", "a.c", "f") == "m"
    assert WO.harness_modules_of(mm, "other") == []


def test_merge_flags_keeps_flag_arguments_together():
    assert WO.merge_flags(["-I. -include a.h", "-I. -include b.h -DX=1", None]) == "-I. -include a.h -include b.h -DX=1"
    assert WO.merge_flags(["-I.", "-I."]) == "-I."
    assert WO.merge_flags([]) == ""


# ------------------------------------------------------------------- scheduler


def test_scheduler_gates_a_unit_on_its_sub_modules_candidates(run_dir):
    setup_run(run_dir)
    ctx = S.Ctx()
    assert {"src/dec.c", "src/enc.c"} <= ctx.slice_files["libx_a"]
    assert {"decode", "encode"} <= set(ctx.contributors("libx_a"))
    assert ctx.header("libx_a") == "x.h"
    verify = {
        "id": "verify:fp",
        "kind": "verify",
        "state": "pending",
        "module": "encode",
        "fingerprint": "src/enc.c#enc_run::mem_access::0123456789",
        "location_file": "src/enc.c",
        "location_function": "enc_run",
    }
    state = {
        "tasks": {"verify:fp": verify},
        "gates": {
            "gate:libx_a": {
                "module": "libx_a",
                "contributors": ctx.contributors("libx_a"),
                "files": sorted(ctx.module_files["libx_a"]),
                "harness_modules": ctx.harness_modules("libx_a"),
            }
        },
    }
    index = S._blocker_index(state)
    # Defect 13: the candidate's sub-module (encode) does not gate a function outside its scope...
    prove = {"kind": "prove", "file": "src/dec.c", "function": "dec_run"}
    assert S._gate_blockers(state, "libx_a", index, task=prove, ctx=ctx) == set()
    # ...but still gates the functions of its own scope.
    prove_enc = {"kind": "prove", "file": "src/enc.c", "function": "enc_run"}
    assert S._gate_blockers(state, "libx_a", index, task=prove_enc, ctx=ctx) == {"verify:fp"}
    assert S._gate_blockers(state, "libx_a", index) == {"verify:fp"}
    # An older verify task naming the unit runs through the harness of its function.
    old = dict(verify, module="libx_a")
    assert S._verify_harness_module(old, ctx) == "encode"


# ------------------------------------------------------------------- report


def test_report_says_concurrent_units_results_assume_sequential_execution():
    ledger = [
        {"module": "libx_a", "bookkeeping": {"concurrent": True}},
        {"module": "libx_a", "bookkeeping": {"concurrent": True}},
        {"module": "tool", "bookkeeping": {}},
    ]
    lines = R.concurrency_lines(ledger)
    assert lines[0] == "Concurrency:"
    assert [line for line in lines if line.startswith("- ")] == [
        "- `libx_a` starts threads: its Eva and WP results assume sequential execution "
        "(no interleaving with its other threads was analysed)."
    ]
    assert R.concurrency_lines([{"module": "m"}]) == []
