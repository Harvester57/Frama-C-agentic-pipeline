r"""Open-world callbacks (QCBOR run-2, P10: UsefulOutBuf_Flush stalled after all its retries).

A call through a function pointer whose type no address-taken function of the program has: the callback is
supplied by the library's user, so no `//@ calls` can name a target. Frama-C 34 WP then havocs memory at
the call and assumes it may not terminate; a statement contract on the call is skipped, `\valid_function`
is not implemented, and a stub named in `calls` leaves an unprovable `Call point` goal while every other
goal is proved from the stub's unchecked contract. The pipeline detects the site in Phase 0
(build_callgraph_dag.open_indirect_sites), says so in the prover brief, and run_wp_function.py stops the
prover (`open_callback_boundary_stop_now`) and makes a `calls` naming a non-target Tier-B unsound.

tests/fixtures/wp_open_callback/: src/flush.c is the shape of UsefulOutBuf_Flush, src/flush_stub.c the
same with a stub named in `calls`, reports/callgraph_dag.json the DAG record run_wp_function.py reads.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

import build_callgraph_dag as bcd
import function_facts
import run_wp_function as W
import workspace_overlay as wo
from conftest import ANALYSIS_IMAGE, ROOT, require_docker_images

OPEN_CB_DIR = Path(__file__).parent / "fixtures" / "wp_open_callback"
OPEN_CB_DAG = json.loads((OPEN_CB_DIR / "reports" / "callgraph_dag.json").read_text(encoding="utf-8"))
OPEN_CB_SIG = "int(void *,BufC)"
# What WP 34 printed for src/flush.c (framac-analysis:latest), the unresolved call on line 44.
OPEN_CB_LOG = "[wp] src/flush.c:44: Warning: Missing 'calls' for default behavior\n"


def _goal(line: int, kind: str, annotation: str) -> dict:
    return {"file": "flush.c", "function": "OutBuf_Flush", "line": line, "kind": kind, "annotation": annotation}


# The unproven goals of src/flush.c under WP 34 (the Docker test below checks the same file end to end).
OPEN_CB_GOALS = [
    _goal(24, "termination clause", "\\true"),
    _goal(26, "assigns clause", "assigns pMe->data_len, pMe->err;"),
    _goal(27, "postcondition", "keep_flush: \\old(pMe)->pfFlush == \\old(pMe->pfFlush)"),
    _goal(28, "postcondition", "keep_ctx: \\old(pMe)->pFlushCtx == \\old(pMe->pFlushCtx)"),
    _goal(29, "postcondition", "err_values: \\old(pMe)->err == \\old(pMe->err) || \\old(pMe)->err == 1"),
    _goal(46, "mem_access", "\\valid(&pMe->err)"),
    _goal(48, "mem_access", "\\valid(&pMe->data_len)"),
]


def _report(goals: list[dict], status: str = "unproven_goals_remain") -> dict:
    return {
        "status": status,
        "function": "OutBuf_Flush",
        "unproven_goals": [dict(g) for g in goals],
        "soundness": {
            "ok": False,
            "tier_a_aborts": [],
            "tier_b_unsound": [
                "indirect call present without '//@ calls' while \\valid_function RTE guards are skipped"
            ],
        },
        "next_synthesis_focus": "tier_b_soundness_fix_required",
        "diagnostic_hints": [W.CALLS_ANNOTATION_HINT],
    }


# ---------------------------------------------------------------------------
# Phase 0: which indirect sites are open
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_only_a_typed_site_without_candidates_is_open() -> None:
    model = {
        "indirect_sites": [
            # UsefulOutBuf_Flush: no function of the type has its address taken. Two units, one site.
            {"caller": "src/u.c#flush", "expr": "pMe->pfFlush", "signature": OPEN_CB_SIG, "candidates": [], "loc": "src/u.c:558"},
            {"caller": "src/u.c#flush", "expr": "pMe->pfFlush", "signature": OPEN_CB_SIG, "candidates": [], "loc": "src/u.c:558"},
            # A closed site: the type match found the targets.
            {"caller": "src/d.c#alloc", "expr": "pMe->pfAllocator", "signature": "void *(void *)", "candidates": ["src/d.c#pool"]},
            # The GCC fallback knows no call-site type: unknown, never open.
            {"caller": "src/g.c#run", "expr": None, "signature": None, "candidates": []},
        ]
    }  # fmt: skip
    assert bcd.open_indirect_sites(model) == {
        "src/u.c#flush": [{"expr": "pMe->pfFlush", "signature": OPEN_CB_SIG, "loc": "src/u.c:558"}]
    }


@pytest.mark.unit
def test_the_wp_note_of_an_open_site_asks_for_no_calls_annotation() -> None:
    rec = {
        "is_variadic": False,
        "has_dynamic_alloc": False,
        "indirect_calls": ["pMe->pfFlush", "ops->cb"],
        "open_indirect_calls": [{"expr": "pMe->pfFlush", "signature": OPEN_CB_SIG}],
    }
    notes = bcd.wp_facts("flush", rec)["wp_notes"]
    assert notes[0] == "indirect call(s) ['ops->cb'] require '//@ calls <targets>;'"
    assert notes[1].startswith("open-world callback(s) ['pMe->pfFlush']: no function of the pointer's type")


@pytest.mark.unit
def test_the_dag_records_the_open_sites_of_a_function(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src/u.c").write_text("void flush(void *p) { }\nvoid other(void) { }\n", encoding="utf-8")
    base = {"file": "src/u.c", "end_line": 1, "lines": 1, "static": False, "inline": False, "header": False}
    base.update(loops=0, cyclomatic=1, source="frama-c-kernel", units=["lib"])
    model = {
        "status": "ok",
        "functions": {"src/u.c#flush": {**base, "name": "flush", "line": 1}, "src/u.c#other": {**base, "name": "other", "line": 2}},
        "edges": [],
        "units": {"lib": {"kind": "library", "test": False, "files": ["src/u.c"], "parse": {"status": "ok"}}},
        "indirect_sites": [{"caller": "src/u.c#flush", "expr": "pMe->pfFlush", "signature": OPEN_CB_SIG, "candidates": []}],
        "entry_points": ["src/u.c#flush"],
        "thread_entries": [],
    }  # fmt: skip
    dag = bcd.build_dag(tmp_path, model, units=False)
    flush, other = dag["functions"]["flush"], dag["functions"]["other"]
    assert flush["open_indirect_calls"] == [{"expr": "pMe->pfFlush", "signature": OPEN_CB_SIG, "loc": None}]
    assert flush["indirect_calls"] == ["pMe->pfFlush"]
    assert "open_indirect_calls" not in other


# ---------------------------------------------------------------------------
# The prover brief
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_the_brief_gives_the_recipe_only_where_a_site_is_open() -> None:
    template = wo._resolve_brief_template("prover")
    marker = "**Open-world callback"
    closed = function_facts.render_conditionals(template, {"indirect_calls": True, "open_callbacks": False})
    opened = function_facts.render_conditionals(template, {"indirect_calls": True, "open_callbacks": True})
    assert marker not in closed and "`//@ calls f1, f2;`" in closed
    assert marker in opened and "open_callback_boundary_stop_now" in opened
    # Without facts every gate is open: the recipe names the sites it applies to.
    assert marker in function_facts.render_conditionals(template, None)


@pytest.mark.unit
def test_the_prover_context_marks_the_open_site() -> None:
    dag_functions = {"flush": {"name": "flush", "file": "src/u.c", "open_indirect_calls": [{"expr": "pMe->pfFlush"}]}}
    assert wo.open_callback_sites(dag_functions, "src/u.c", "flush") == [{"expr": "pMe->pfFlush"}]
    assert wo.open_callback_sites(dag_functions, "src/other.c", "flush") == []
    record = {
        "calls": [
            {"line": 9, "indirect": True, "expr": "pMe->pfFlush", "eva_targets": []},
            {"line": 12, "indirect": True, "expr": "ops->cb", "eva_targets": ["real_cb"]},
        ]
    }
    marked = function_facts.mark_open_callbacks(record, ["pMe->pfFlush"])
    assert [c.get("open_callback", False) for c in marked["calls"]] == [True, False]
    assert "open_callback" not in record["calls"][0]  # a copy
    lines: list[str] = []
    function_facts._render_calls(marked, lambda line: line, lines)
    assert "open-world callback" in lines[1] and "Eva resolved it to `real_cb`" in lines[2]


# ---------------------------------------------------------------------------
# run_wp_function.py
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_an_open_callback_stops_the_prover_when_only_its_goals_remain(tmp_path: Path) -> None:
    res = W.apply_open_callback_boundary(
        _report(OPEN_CB_GOALS), OPEN_CB_DIR / "src" / "flush.c", "OutBuf_Flush", tmp_path, OPEN_CB_DAG, OPEN_CB_LOG
    )
    assert res["next_synthesis_focus"] == W.OPEN_CALLBACK_FOCUS == "open_callback_boundary_stop_now"
    boundary = res["open_callback_boundary"]
    assert boundary["call_lines"] == [44] and boundary["other_unproven"] == 0
    assert [g["line"] for g in boundary["downstream_goals"]] == [24, 26, 27, 28, 29, 46, 48]
    # Never a pass: the status and the soundness verdict stay what WP said.
    assert res["status"] == "unproven_goals_remain" and res["soundness"]["ok"] is False
    assert W.CALLS_ANNOTATION_HINT not in res["diagnostic_hints"]
    assert res["diagnostic_hints"][0].startswith("Open-world callback: `pMe->pfFlush`")


@pytest.mark.unit
def test_goals_before_the_call_keep_the_prover_going(tmp_path: Path) -> None:
    # The argument load on the call line and the line before it are provable (a shape `requires`).
    goals = [*OPEN_CB_GOALS, _goal(43, "pointer_value", "\\null == pMe->buf"), _goal(44, "pointer_value", "ctx")]
    res = W.apply_open_callback_boundary(
        _report(goals), OPEN_CB_DIR / "src" / "flush.c", "OutBuf_Flush", tmp_path, OPEN_CB_DAG, OPEN_CB_LOG
    )
    assert res["next_synthesis_focus"] == "tier_b_soundness_fix_required"
    assert res["open_callback_boundary"]["other_unproven"] == 2
    assert "prove those, then finish" in res["diagnostic_hints"][0]


@pytest.mark.unit
def test_a_stub_named_in_calls_at_an_open_site_is_unsound(tmp_path: Path) -> None:
    # What WP 34 leaves for src/flush_stub.c: every goal proved but the call point, soundness clean.
    report = _report([_goal(51, "wp_goal", "typed_OutBuf_Flush_call_point_OutBuf_FlushCallback_contract_s13")])
    report["soundness"] = {"ok": True, "tier_a_aborts": [], "tier_b_unsound": []}
    report["next_synthesis_focus"] = "step_c_contract_postcondition"
    res = W.apply_open_callback_boundary(
        report, OPEN_CB_DIR / "src" / "flush_stub.c", "OutBuf_Flush", tmp_path, OPEN_CB_DAG, ""
    )
    assert res["open_callback_boundary"]["foreign_calls_targets"] == ["OutBuf_FlushCallback_contract"]
    assert res["soundness"]["ok"] is False
    assert res["soundness"]["tier_b_unsound"][0].startswith("'//@ calls OutBuf_FlushCallback_contract' in OutBuf_Flush")
    assert res["next_synthesis_focus"] == "tier_b_soundness_fix_required"
    # A clean proof under such a stub would not stand either.
    proven = dict(report, status="all_proven", unproven_goals=[], soundness={"ok": True, "tier_b_unsound": []})
    res = W.apply_open_callback_boundary(
        proven, OPEN_CB_DIR / "src" / "flush_stub.c", "OutBuf_Flush", tmp_path, OPEN_CB_DAG, ""
    )
    assert res["status"] == "unsound_proof"


@pytest.mark.unit
def test_a_function_without_an_open_site_is_left_alone(tmp_path: Path) -> None:
    dag = {
        "functions": {
            "OutBuf_Flush": {"name": "OutBuf_Flush", "file": "src/flush.c", "indirect_calls": ["pMe->pfFlush"]}
        }
    }
    report = _report(OPEN_CB_GOALS)
    res = W.apply_open_callback_boundary(
        json.loads(json.dumps(report)), OPEN_CB_DIR / "src" / "flush.c", "OutBuf_Flush", tmp_path, dag, OPEN_CB_LOG
    )
    assert res == report
    assert W.calls_targets("//@ calls f, g;\n/*@ calls h; */ int calls;") == ["f", "g", "h"]


# ---------------------------------------------------------------------------
# End to end, in the analysis image
# ---------------------------------------------------------------------------


def _wp_in_image(work: Path, source: str) -> dict:
    script = (
        f"timeout 600 python3 /opt/framac-pipeline/scripts/run_wp_function.py --file {source} --function OutBuf_Flush "
        "--out-dir out/wp --cache-dir off --security-props none --timeout 10 --out-json out/report.json >/dev/null 2>&1; "
        "cat out/report.json"
    )
    mounts = []
    for name in ("scripts", "schemas", "skills", "templates"):
        mounts += ["-v", f"{ROOT / name}:/opt/framac-pipeline/{name}:ro"]
    proc = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "-v", f"{work}:/w", *mounts,
         "--entrypoint", "sh", ANALYSIS_IMAGE, "-c", f"cd /w && {script}"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900, check=False,
    )  # fmt: skip
    assert proc.stdout.strip(), proc.stderr
    return json.loads(proc.stdout)


@pytest.mark.integration
@pytest.mark.slow
def test_wp_on_the_fixture_stops_at_the_open_callback_and_refuses_a_stub(tmp_path: Path) -> None:
    require_docker_images(ANALYSIS_IMAGE)
    work = tmp_path / "w"
    shutil.copytree(OPEN_CB_DIR, work)
    res = _wp_in_image(work, "src/flush.c")
    assert res["status"] == "unproven_goals_remain" and res["soundness"]["ok"] is False
    assert res["next_synthesis_focus"] == "open_callback_boundary_stop_now"
    downstream = {(g["kind"], g["line"]) for g in res["open_callback_boundary"]["downstream_goals"]}
    assert {("termination clause", 24), ("assigns clause", 26), ("mem_access", 46), ("mem_access", 48)} <= downstream
    stub = _wp_in_image(work, "src/flush_stub.c")
    # The stub closes every goal but the call point: exactly why it must not count.
    assert [g["annotation"] for g in stub["unproven_goals"]] == [
        "typed_OutBuf_Flush_call_point_OutBuf_FlushCallback_contract_s13"
    ]
    assert stub["soundness"]["ok"] is False
    assert any("calls OutBuf_FlushCallback_contract" in m for m in stub["soundness"]["tier_b_unsound"])
