"""The header architect's guardrails check the header's functions, so a failure elsewhere is not its code_fault.

mpack run-4 (S18): `arch-sax_example__program` wrote a WP-proven contract for `parse_messagepack`, but its
guardrail ran without `--functions`, so the already-confirmed uninitialized read in the program's `main` (hit
by the empty input before `parse_messagepack` was entered) came back `code_fault` and the brief made it
return `failed`. The parent's architect re-check had the same gap (no `--reach-functions`).
"""

from __future__ import annotations

import json
from pathlib import Path

import workspace_overlay

_C = "int parse(const char *b, int n) {\n    return n;\n}\n\nint main(void) {\n    return parse(0, 0);\n}\n"
_H = (
    "#ifndef M_H\n#define M_H\n"
    "int parse(const char *b, int n);\n"
    "static inline int twice(int x) { return 2 * x; }\n"
    "typedef int (*cb_t)(int);\n"
    "extern int counter;\n"
    "#endif\n"
)
_CONTRACT = "/*@ requires n >= 0; assigns \\nothing; */\nint parse(const char *b, int n);"


def _run(tmp_path: Path, agents: tuple[str, ...] = ()) -> tuple[Path, Path]:
    target = tmp_path / "target"
    target.mkdir()
    (target / "m.c").write_text(_C, encoding="utf-8")
    (target / "m.h").write_text(_H, encoding="utf-8")
    run_dir = (tmp_path / "run").resolve()
    overlay = run_dir / "workspace"
    workspace_overlay.init_overlay(target, overlay)
    meta = {"module": "m", "sources": ["workspace/work/m.c"], "cppflags": "-I.", "header": "m.h", "entry_fn": "parse"}
    (overlay / "harnesses").mkdir(parents=True, exist_ok=True)
    (overlay / "harnesses" / "harness_m.json").write_text(json.dumps(meta), encoding="utf-8")
    for aid in agents:
        workspace_overlay.init_agent_overlay(run_dir, aid, overlay)
        hdr = run_dir / "agents" / aid / "scratch" / "work" / "m.h"
        hdr.write_text(_H.replace("int parse(const char *b, int n);", _CONTRACT), encoding="utf-8")
    return run_dir, overlay


def test_header_function_names_lists_prototypes_and_inline_definitions():
    assert workspace_overlay.header_function_names(_H, "m.h") == ["parse", "twice"]
    assert workspace_overlay.header_function_names("#define X 1\n", "x.h") == []


def test_architect_brief_guardrail_checks_the_header_functions(tmp_path):
    run_dir, _ = _run(tmp_path)
    res = workspace_overlay.prepare_agent(run_dir, "arch-m", "architect", module="m", header_file="m.h")
    brief = (run_dir / res["brief_file"]).read_text(encoding="utf-8")
    guard = next(line for line in brief.splitlines() if "run_eacsl_fuzz.py guardrail" in line)
    assert " --functions parse twice " in guard, guard


def _fake_reverify(calls: list[dict]):
    def fake(run_dir, agent_id, role, overlay_dir, c_file, function, module, sources, cppflags, **kw):
        calls.append({"role": role, "function": function, "module": module, **kw})
        return True, "verified"

    return fake


def test_architect_merge_guardrail_measures_the_header_functions(tmp_path, monkeypatch):
    run_dir, overlay = _run(tmp_path, ("arch-m",))
    calls: list[dict] = []
    monkeypatch.setattr(workspace_overlay, "_run_parent_reverify", _fake_reverify(calls))
    res = workspace_overlay.merge_agent_overlay(
        run_dir=run_dir,
        agent_id="arch-m",
        role="architect",
        overlay_dir=overlay,
        header_file="m.h",
        module="m",
        sources=["workspace/work/m.c"],
        cppflags="-I.",
    )
    assert res["ok"], res
    assert calls and calls[0]["reach_functions"] == ["parse", "twice"], calls


def test_architect_batch_merge_guardrail_measures_the_header_functions(tmp_path, monkeypatch):
    run_dir, _ = _run(tmp_path, ("arch-m",))
    calls: list[dict] = []
    monkeypatch.setattr(workspace_overlay, "_run_parent_reverify", _fake_reverify(calls))
    entries = [{"agent_id": "arch-m", "role": "architect", "header": "m.h", "module": "m"}]
    res = workspace_overlay.merge_agent_batch(run_dir, entries)
    assert res["ok"], res
    module_calls = [c for c in calls if c["module"] and not c["function"]]
    assert module_calls and module_calls[0].get("reach_functions") == ["parse", "twice"], calls
