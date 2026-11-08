"""Eva ingest across modules (step I5a): a unit's Eva status comes from every module's report that
analysed its function, rows are placed in functions by file and line, and the outcome does not depend
on the order reports arrive in."""

import json

import pytest

import ledger as L
from conftest import write_json
from validate_artifacts import validate_ledger

pytestmark = pytest.mark.unit

TIER1 = "Tier 1A (Untrusted Binary / Network Parser)"
DAG = {
    "callgraph_source": "frama_c",
    "modules": {"a": {"tier": TIER1}, "b": {"tier": TIER1}},
    "functions": {
        "shared": {"name": "shared", "file": "src/s.c", "module": "a", "wave": 0, "line": 10, "end_line": 20},
        "user": {"name": "user", "file": "src/b.c", "module": "b", "wave": 1, "line": 1, "end_line": 9},
        "inl": {
            "name": "inl",
            "file": "inc/h.h",
            "module": "a",
            "wave": 0,
            "line": 3,
            "end_line": 8,
            "header": True,
            "reached": False,
        },
    },
}


def _seed(run_dir):
    write_json(run_dir / "workspace/reports/callgraph_dag.json", DAG)
    L.cmd_seed(run_dir / "workspace/reports/callgraph_dag.json", [], "frama_c")


def _report(module, props_by_file, unknown=None, name=None):
    rep = {
        "status": "ok",
        "module": module,
        "functions_with_properties_by_file": props_by_file,
        "unknown_obligations_by_function": unknown or {},
        "invalid_alarms": [],
        "dead_alarms": [],
        "assumed_properties": [],
    }
    return rep, name or module


def _ingest(run_dir, *reports):
    paths = []
    for rep, name in reports:
        path = run_dir / f"workspace/reports/eva/{name}.json"
        write_json(path, rep)
        paths.append(path)
    return L.cmd_ingest_eva(paths)


def _units(run_dir):
    return {u["coverage_id"]: u for u in json.loads((run_dir / "coverage-ledger.json").read_text(encoding="utf-8"))}


def _valid(run_dir):
    ledger = json.loads((run_dir / "coverage-ledger.json").read_text(encoding="utf-8"))
    assert list(validate_ledger(ledger, run_dir)) == []


UNKNOWN_IN_SHARED = {"shared": [{"file": "workspace/work/src/s.c", "line": 12, "kind": "mem_access"}]}
A_VALID = _report("a", {"src/s.c": ["shared"]})
B_UNKNOWN = _report("b", {"src/s.c": ["shared"], "src/b.c": ["user"]}, UNKNOWN_IN_SHARED)


@pytest.mark.parametrize("order", [(A_VALID, B_UNKNOWN), (B_UNKNOWN, A_VALID)], ids=["owner-first", "other-first"])
def test_unknown_from_another_module_blocks_cover_in_any_order(run_dir, order):
    _seed(run_dir)
    _ingest(run_dir, *order)
    shared = _units(run_dir)["src/s.c#shared::rte"]
    assert shared["status"] == "planned"
    assert shared["bookkeeping"]["eva_verdicts"] == {"a": "valid", "b": "unknown"}
    assert any(e["result"] == "eva_unknown" and "'b'" in e["summary"] for e in shared["evidence"])
    assert not any(a["description"].startswith("Eva result holds") for a in shared["assumptions"])
    _valid(run_dir)


def test_reports_ingested_one_at_a_time_reach_the_same_ledger(run_dir):
    _seed(run_dir)
    _ingest(run_dir, A_VALID)
    assert _units(run_dir)["src/s.c#shared::rte"]["status"] == "covered"
    out = _ingest(run_dir, B_UNKNOWN)
    shared = _units(run_dir)["src/s.c#shared::rte"]
    assert shared["status"] == "planned" and out["reopened"] == 1
    assert shared["evidence"][-1]["result"] == "eva_cover_withdrawn"
    _valid(run_dir)


def test_a_modules_newer_report_replaces_its_verdicts(run_dir):
    _seed(run_dir)
    _ingest(run_dir, A_VALID, B_UNKNOWN)
    # Module b's repaired harness no longer leaves anything open in `shared`.
    _ingest(run_dir, _report("b", {"src/s.c": ["shared"], "src/b.c": ["user"]}, name="b-2"))
    shared = _units(run_dir)["src/s.c#shared::rte"]
    assert shared["status"] == "covered"
    assert shared["bookkeeping"]["eva_verdicts"] == {"a": "valid", "b": "valid"}
    holds = [a["description"] for a in shared["assumptions"] if a["description"].startswith("Eva result holds")]
    assert holds == ["Eva result holds for calling contexts reachable from eva_main of modules 'a', 'b'."]
    _valid(run_dir)


def test_another_modules_slice_that_never_saw_a_function_leaves_it_alone(run_dir):
    _seed(run_dir)
    _ingest(run_dir, A_VALID, _report("b", {"src/b.c": ["user"]}))
    shared = _units(run_dir)["src/s.c#shared::rte"]
    assert shared["status"] == "covered"
    assert shared["bookkeeping"]["eva_verdicts"] == {"a": "valid"}


def test_rows_are_placed_by_line_in_the_function_that_holds_them(run_dir):
    _seed(run_dir)
    # Eva names the kernel's renamed copy `inl_3` and the inlined row under its caller: the line says
    # both lie in the header function `inl` (lines 3-8 of inc/h.h).
    rows = {
        "inl_3": [{"file": "workspace/work/inc/h.h", "line": 4, "kind": "mem_access"}],
        "shared": [{"file": "workspace/work/inc/h.h", "line": 7, "kind": "signed_overflow"}],
    }
    _ingest(run_dir, _report("b", {"src/b.c": ["user"]}, rows))
    units = _units(run_dir)
    inl = units["inc/h.h#inl::rte"]
    # Reached only through module b's harness: re-planned, with b's Unknowns.
    assert inl["status"] == "planned" and inl["unresolved"] == []
    assert inl["bookkeeping"]["eva_verdicts"] == {"b": "unknown"}
    assert "2 RTE obligation(s) remain Unknown" in inl["evidence"][-1]["summary"]
    # `shared` itself (src/s.c) got nothing from the header row.
    assert "eva_verdicts" not in (units["src/s.c#shared::rte"].get("bookkeeping") or {})
    _valid(run_dir)


def test_an_unreached_header_unit_no_slice_names_stays_deferred(run_dir):
    _seed(run_dir)
    _ingest(run_dir, A_VALID)
    inl = _units(run_dir)["inc/h.h#inl::rte"]
    assert inl["status"] == "deferred" and inl["evidence"] == []
    _valid(run_dir)
