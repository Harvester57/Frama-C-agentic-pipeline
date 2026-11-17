"""A prover's brief shows how the callers use its function (caller-sufficient contracts, step 3)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import workspace_overlay as WO

pytestmark = pytest.mark.unit

CALLERS_HEADING = "## How the Callers Use This Function"

CALLEE_C = """\
#include "lib.h"
int lookup(int k) {
    return k & 7;
}
"""

USER_C = """\
#include "lib.h"
static int table[8];
/*@ assigns \\nothing; ensures lookup(0) == 0; */
int use_one(int k) {
    // lookup( in a comment is not a call
    int i = lookup(k);
    if (i < 0)
        return -1;
    return table[i];
}
int use_two(int k) {
    int a = lookup(k);
    int b = lookup(k + 1);
    return a + b;
}
int via_ptr(int (*fp)(int), int k) {
    return fp(k);
}
"""


def _dag(callers: list[str]) -> dict:
    fns = {
        "lookup": {"name": "lookup", "file": "src/lib.c", "module": "m", "internal_callers": callers},
        "use_one": {"name": "use_one", "file": "src/user.c", "module": "m", "internal_callers": []},
        "use_two": {"name": "use_two", "file": "src/user.c", "module": "m", "internal_callers": []},
        "via_ptr": {"name": "via_ptr", "file": "src/user.c", "module": "m", "internal_callers": []},
    }
    return {"functions": fns, "modules": {}}


def _brief(tmp_path: Path, callers: list[str], function: str = "lookup", role: str = "prover") -> str:
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "lib.c").write_text(CALLEE_C, encoding="utf-8")
    (target / "src" / "user.c").write_text(USER_C, encoding="utf-8")
    (target / "src" / "lib.h").write_text("int lookup(int k);\n", encoding="utf-8")
    run_dir = tmp_path / "run"
    WO.init_overlay(target, run_dir / "workspace")
    dag = run_dir / "workspace" / "reports" / "callgraph_dag.json"
    dag.parent.mkdir(parents=True, exist_ok=True)
    dag.write_text(json.dumps(_dag(callers)), encoding="utf-8")
    res = WO.prepare_agent(run_dir=run_dir, agent_id="prove-x", role=role, c_file="src/lib.c", function=function)
    return (run_dir / res["brief_file"]).read_text(encoding="utf-8")


def test_the_brief_shows_each_call_and_the_lines_after_it(tmp_path):
    brief = _brief(tmp_path, ["use_one", "use_two", "via_ptr"])
    section = brief.split(CALLERS_HEADING, 1)[1]
    assert "`use_one` (`src/user.c` line 6):" in section
    assert "    int i = lookup(k);\n    if (i < 0)\n        return -1;\n    return table[i];\n}" in section
    # The contract and the comment of the caller are not call sites.
    assert "line 3" not in section and "line 5" not in section
    assert "`use_two` (`src/user.c` line 12, and 1 more call(s) in it):" in section
    # A caller through a pointer has no textual call: counted, not shown.
    assert "`via_ptr`" not in section and "1 caller(s) not shown" in section


def test_callers_over_the_cap_are_counted(tmp_path, monkeypatch):
    monkeypatch.setattr(WO, "CALLER_USAGE_MAX_CALLERS", 1)
    section = _brief(tmp_path, ["use_one", "use_two"]).split(CALLERS_HEADING, 1)[1]
    assert "`use_one`" in section and "`use_two`" not in section
    assert "1 caller(s) not shown: over the limit of 1" in section


def test_a_function_without_callers_is_named_an_entry_point(tmp_path):
    section = _brief(tmp_path, []).split(CALLERS_HEADING, 1)[1]
    assert "No function in the analysed code calls `lookup`: it is an API entry point" in section


def test_no_dag_record_and_other_roles_render_nothing(tmp_path):
    assert CALLERS_HEADING not in _brief(tmp_path / "a", ["use_one"], function="unknown_fn")
    assert CALLERS_HEADING not in _brief(tmp_path / "b", ["use_one"], role="breaker")


def test_call_sites_stop_at_the_end_of_the_caller(tmp_path):
    (tmp_path / "a.c").write_text("int g(void) { return f(1); }\nint h(void) { return 0; }\n", encoding="utf-8")
    sites = WO._call_sites(tmp_path, "a.c", "g", "f")
    assert sites == [(1, ["int g(void) { return f(1); }"])]
    assert WO._call_sites(tmp_path, "missing.c", "g", "f") == []
    assert WO._call_sites(tmp_path, "a.c", "absent", "f") == []


def test_source_text_cannot_leave_its_code_block(tmp_path):
    (tmp_path / "a.c").write_text('int g(void) {\n    f(1); /* ``` */\n    return 0;\n}\n', encoding="utf-8")
    dag: dict[str, dict] = {
        "f": {"name": "f", "file": "a.c", "internal_callers": ["g"]},
        "g": {"name": "g", "file": "a.c"},
    }
    run = tmp_path / "ws"
    (run / "work").mkdir(parents=True)
    (run / "work" / "a.c").write_text((tmp_path / "a.c").read_text(encoding="utf-8"), encoding="utf-8")
    section = WO._caller_usage_section(run, "f", dag["f"], dag, "prover")
    assert "/* ''' */" in section and section.count("```") == 2
