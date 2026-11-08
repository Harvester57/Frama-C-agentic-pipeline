"""R7 (docs/phase0-remediation-plan.md): one architect per harness header, sub-module gating, old classes gone."""

from __future__ import annotations

import json

import pytest

import run_wp_function as R
import wp_scheduler as S
from conftest import write_json
from test_wp_scheduler import Sim, ready, tasks

TIER3 = "Tier 3 (Internal Utility)"


@pytest.fixture
def sim(run_dir, monkeypatch):
    return Sim(run_dir, monkeypatch)


def _unit_with_two_harnesses(sim, headers=True, extra=None):
    """Link unit `u` with sub-module harnesses u_a (src/u/a.c) and u_b (src/u/b.c)."""
    sidecars = {
        "u_a": {"unit": "u", "sources": ["src/u/a.c"]},
        "u_b": {"unit": "u", "sources": ["src/u/b.c"]},
    }
    if headers:
        sidecars["u_a"]["header"] = "src/u/a.h"
        sidecars["u_b"]["header"] = "src/u/b.h"
    sim.build(
        {"fa": ("src/u/a.c", "u", []), "fb": ("src/u/b.c", "u", []), "gb": ("src/u/b.c", "u", [])},
        sidecars=sidecars,
        **(extra or {}),
    )


def test_a_unit_with_two_harnesses_and_two_headers_gets_two_architects(sim):
    _unit_with_two_harnesses(sim)
    S.cmd_init()
    t = tasks()
    archs = {tid: task for tid, task in t.items() if task["kind"] == "arch"}
    assert sorted(archs) == ["arch:u", "arch:u_b"]
    assert (archs["arch:u"]["header"], archs["arch:u"]["harness_module"]) == ("src/u/a.h", "u_a")
    assert (archs["arch:u_b"]["header"], archs["arch:u_b"]["harness_module"]) == ("src/u/b.h", "u_b")
    assert all(a["module"] == "u" and a["deps"] == ["gate:u"] for a in archs.values())
    # The headers are not on disk: a prover conservatively waits for every architect of its unit.
    assert t["prove:src/u/a.c#fa"]["deps"] == ["arch:u", "arch:u_b", "gate:u"]
    assert sorted(ready()) == ["arch:u", "arch:u_b"]


def test_an_architect_follows_its_header_and_one_whose_header_left_is_skipped(sim):
    _unit_with_two_harnesses(sim)
    S.cmd_init()
    # u_b no longer names a header: its architect has nothing to write.
    side = sim.run_dir / "workspace/harnesses/harness_u_b.json"
    write_json(side, {"module": "u_b", "unit": "u", "sources": ["src/u/b.c"], "cppflags": "-I."})
    S.cmd_init()
    t = tasks()
    assert t["arch:u_b"]["state"] == "skipped" and t["arch:u_b"]["outcome"] == "header_gone"
    assert t["prove:src/u/a.c#fa"]["deps"] == ["arch:u", "gate:u"]
    # A renamed header is taken over by the pending architect rather than duplicated.
    write_json(
        sim.run_dir / "workspace/harnesses/harness_u_a.json",
        {"module": "u_a", "unit": "u", "sources": ["src/u/a.c"], "cppflags": "-I.", "header": "src/u/a2.h"},
    )
    S.cmd_init()
    t = tasks()
    assert t["arch:u"]["header"] == "src/u/a2.h" and t["arch:u"]["state"] == "pending"
    assert sorted(tid for tid, task in t.items() if task["kind"] == "arch") == ["arch:u", "arch:u_b"]


def test_a_sub_modules_candidate_does_not_gate_another_sub_modules_functions(sim):
    _unit_with_two_harnesses(sim, headers=False)
    fp = sim.eva_candidate("u_b", "src/u/b.c", "fb")
    S.cmd_init()
    t = tasks()
    assert t[f"verify:{fp}"]["module"] == "u_b"
    now = ready()
    assert f"verify:{fp}" in now
    assert "prove:src/u/a.c#fa" in now  # u_a's scope never meets u_b's candidate
    assert "prove:src/u/b.c#gb" not in now  # gb is in u_b's scope: the candidate may be harness-induced


def test_an_out_of_scope_candidate_still_holds_the_callers_whose_cone_it_lies_in(sim):
    sim.build(
        {
            "fa": ("src/u/a.c", "u", ["fb"]),
            "fb": ("src/u/b.c", "u", []),
            "gb": ("src/u/b.c", "u", []),
            "hc": ("src/u/c.c", "u", []),
        },
        sidecars={
            "u_a": {"unit": "u", "sources": ["src/u/a.c"]},
            "u_b": {"unit": "u", "sources": ["src/u/b.c"]},
            # u_c answers for hc, but its campaign reached fb (outside its scope).
            "u_c": {"unit": "u", "sources": ["src/u/c.c"]},
        },
    )
    fp = sim.eva_candidate("u_c", "src/u/b.c", "fb")
    S.cmd_init()
    assert tasks()[f"verify:{fp}"]["module"] == "u_c"
    now = ready()
    assert "prove:src/u/b.c#gb" in now  # neither in u_c's scope nor calling fb
    assert "prove:src/u/a.c#fa" not in now  # fb, the candidate's location, is in fa's call cone
    assert "prove:src/u/c.c#hc" not in now  # u_c's own scope


def test_a_tier3_sub_module_is_inert(sim):
    sim.build(
        {"fa": ("src/u/a.c", "u", []), "fb": ("src/u/b.c", "u", [])},
        sidecars={
            "u_a": {"unit": "u", "sources": ["src/u/a.c"]},
            "u_b": {"unit": "u", "sources": ["src/u/b.c"]},
        },
    )
    dag_path = sim.run_dir / "workspace/reports/callgraph_dag.json"
    dag = json.loads(dag_path.read_text(encoding="utf-8"))
    dag["submodules"] = {"u_b": {"unit": "u", "tier": TIER3, "functions": ["fb"]}}
    write_json(dag_path, dag)
    ctx = S.Ctx()
    assert ctx.inert("u_b") and not ctx.inert("u_a") and not ctx.inert("u")


def test_dag_header_fields_are_not_read(sim):
    sim.build({"f": ("src/m/f.c", "m", [])}, modules={"m": {"header": "src/m/m.h", "headers": ["src/m/x.h"]}})
    S.cmd_init()
    assert not [tid for tid, task in tasks().items() if task["kind"] == "arch"]


@pytest.mark.parametrize(
    ("annotation", "expected"),
    [
        ("ensures L5_no_crlf: no_crlf_or_nul(out, \\result)", "rte"),
        ("L6_key_wiped: buffer_is_zeroed(k, 32)", "rte"),
        ("L4_x: assigns *p", "l3_frame"),
        ("L6_wiped_k: meta: \\forall integer i; k[i] == 0", "l6_wiped"),
        ("L4_auth_required_g: meta: ok != 0", "l4_auth_required"),
    ],
)
def test_hand_named_layer_clauses_take_the_class_of_their_kind(annotation, expected):
    assert R.goal_obligation_class({"kind": "postcondition", "annotation": annotation}) == expected


def test_old_layer_classes_are_gone():
    assert R.LAYER_CLASSES == {"l4_auth_state", "l4_auth_required", "l5_sanitized", "l6_wiped", "l6_no_leak"}
