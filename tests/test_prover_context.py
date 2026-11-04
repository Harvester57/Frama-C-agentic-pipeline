"""prepare-agent: the prover's rendered brief with facts, reading slice and conditional sections."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import function_facts as ff  # noqa: E402
from run_wp_function import _is_synthetic_probe_file, _locate_agent_scratch_dir  # noqa: E402
from test_function_facts import _access, _formal, _loop, _raw, _record, _write  # noqa: E402
from workspace_overlay import init_overlay, prepare_agent  # noqa: E402

MARKER_RE = re.compile(r"<!--\s*(?:if:|else|endif)")

MOD_H = r"""#ifndef MOD_H
#define MOD_H
#define MAX_ITEMS 8
typedef struct { int len; int items[MAX_ITEMS]; } box_t;
/*@ requires \valid(b);
    assigns \nothing;
    ensures \result >= 0; */
int box_len(const box_t *b);
int total(const box_t *b, int *out);
#endif
"""

MOD_C = """#include "mod.h"
static int unrelated_table[3] = {1, 2, 3};
int box_len(const box_t *b) { return b->len; }
int total(const box_t *b, int *out) {
  /* {function_name} and {agent_id} are source text here, never placeholders. */
  int acc = 0;
  for (int i = 0; i < box_len(b); i++) acc += b->items[i];
  *out = acc;
  return 0;
}
"""


def _prover_run(tmp_path: Path, facts: bool = True) -> Path:
    target = tmp_path / "target"
    target.mkdir()
    (target / "mod.h").write_text(MOD_H, encoding="utf-8")
    (target / "mod.c").write_text(MOD_C, encoding="utf-8")
    run_dir = tmp_path / "run"
    init_overlay(target, run_dir / "workspace")
    if facts:
        raw = _raw(
            "total",
            "mod.c:4",
            formals=[_formal("b", "pointer", "box_t", const=True), _formal("out", "pointer", "int")],
            loops=[
                _loop(
                    loc="mod.c:7",
                    guard="i < tmp",
                    writes=[
                        _write("acc", "acc", "local", False, ["acc + b->items[i]"]),
                        _write("i", "i", "local", False, ["i + 1"]),
                    ],
                    reads=[_access("b->items[i]", "b")],
                    calls=["box_len"],
                )
            ],
            writes=[_access("*out", "out", loc="mod.c:8")],
            reads=[_access("b->items[i]", "b", loc="mod.c:7")],
            calls=[
                {
                    "callee": "box_len",
                    "kernel_name": "box_len",
                    "indirect": False,
                    "args": ["b"],
                    "loc": "mod.c:7",
                    "in_loop": True,
                }
            ],
            features={"structs": True, "arrays": True},
        )
        flows = {
            "status": "ok",
            "by_function": {
                "total": {"writes": [{"loc": "res", "from": ["b", "out", "box"], "and_self": False}], "inputs": ["box"]}
            },
        }
        record = _record(raw, MOD_C, flows=flows)
        facts_dir = run_dir / "workspace" / "reports" / "facts"
        facts_dir.mkdir(parents=True)
        (facts_dir / "mod.json").write_text(
            json.dumps({"schema": ff.FACTS_SCHEMA, "status": "ok", "functions": {"mod.c#total": record}}),
            encoding="utf-8",
        )
    return run_dir


def _prepare(run_dir: Path, agent_id: str = "prove-total") -> dict:
    return prepare_agent(
        run_dir=run_dir,
        agent_id=agent_id,
        role="prover",
        module="mod",
        function="total",
        c_file="mod.c",
        header_file="mod.h",
    )


def test_rendered_brief_shows_facts_and_slice_and_only_the_sections_that_apply(tmp_path: Path) -> None:
    run_dir = _prover_run(tmp_path)
    prep = _prepare(run_dir)
    brief = (run_dir / prep["brief_file"]).read_text(encoding="utf-8")
    assert prep["prover_context"]["facts"] is True
    assert prep["prover_context"]["slice"] in ("ok", "degraded")

    # Facts, as hints.
    assert "## Deterministic Function Context" in brief
    assert "**WP is the only judge of `assigns`.**" in brief
    assert "`*out`" in brief and "L7 `for (int i = 0; i < box_len(b); i++)`" in brief
    assert "**Writes (Eva, this harness only):** `res` FROM `b`, `out`, `box`" in brief
    assert brief.index("## Deterministic Function Context") < brief.index("## Strict Rules")

    # The slice: the target's real text and what it references, not the unrelated global.
    section = brief[brief.index("### Reading Slice") : brief.index("## Strict Rules")]
    assert "**It is not the proof target**" in section
    assert "int total(const box_t *b, int *out)" in section
    assert "box_t" in section and "MAX_ITEMS" in section
    assert "int box_len(const box_t *b);" in section and "ensures" in section
    assert "unrelated_table" not in section

    # Assembled for this function.
    assert "Inspect every loop, pointer write" not in brief
    assert "Start from the **Deterministic Function Context**" in brief
    assert "Concrete Dual-Oracle C-String Predicates" not in brief
    assert "Floating-point comparisons" not in brief
    assert "Pointer-Difference Equality Bridge" not in brief
    assert "Distinguishing Establishment vs. Preservation Failures" in brief
    assert "Struct / union equality" in brief
    assert not MARKER_RE.search(brief)

    # Every strict rule stays, and source text is never treated as a placeholder.
    for rule in ("Pure ACSL Annotations Only", "Trust Boundary & No Magic Bounds", "No Environment Probing"):
        assert rule in brief
    assert "{function_name} and {agent_id} are source text here" in section

    # Files beside the brief.
    context = run_dir / "agents" / "prove-total" / "scratch" / "context"
    assert (context / "total.facts.json").is_file() and (context / "total.slice.c").is_file()
    budget = json.loads((run_dir / "agents" / "prove-total" / "scratch" / ".prover_budget.json").read_text())
    assert budget["header"] == "mod.h" and budget["file"] == "mod.c"


def test_slice_and_facts_cannot_become_the_proof_target(tmp_path: Path) -> None:
    run_dir = _prover_run(tmp_path)
    _prepare(run_dir)
    scratch = run_dir / "agents" / "prove-total" / "scratch"
    slice_file = scratch / "context" / "total.slice.c"
    located = _locate_agent_scratch_dir(slice_file, scratch / "wp")
    assert located is not None and _is_synthetic_probe_file(slice_file, located) is True
    assert _is_synthetic_probe_file(scratch / "work" / "mod.c", located) is False


def test_brief_without_a_facts_file_keeps_all_guidance_and_the_slice(tmp_path: Path) -> None:
    run_dir = _prover_run(tmp_path, facts=False)
    prep = _prepare(run_dir)
    brief = (run_dir / prep["brief_file"]).read_text(encoding="utf-8")
    assert prep["prover_context"]["facts"] is False
    assert "Inspect every loop, pointer write" in brief
    assert "Concrete Dual-Oracle C-String Predicates" in brief and "Floating-point comparisons" in brief
    assert "### Reading Slice" in brief
    assert "**Writes (AST" not in brief
    assert not MARKER_RE.search(brief)


def test_context_off_gives_the_full_brief_without_context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ff.CONTEXT_ENV, "off")
    run_dir = _prover_run(tmp_path)
    prep = _prepare(run_dir)
    brief = (run_dir / prep["brief_file"]).read_text(encoding="utf-8")
    assert prep["prover_context"] == {"enabled": False}
    assert "## Deterministic Function Context" not in brief and "### Reading Slice" not in brief
    assert "Inspect every loop, pointer write" in brief
    assert "Concrete Dual-Oracle C-String Predicates" in brief
    assert ff.CONTEXT_SENTINEL not in brief and not MARKER_RE.search(brief)
    assert not (run_dir / "agents" / "prove-total" / "scratch" / "context").exists()


def test_facts_of_a_same_named_static_elsewhere_are_not_used(tmp_path: Path) -> None:
    run_dir = _prover_run(tmp_path)
    (run_dir / "workspace" / "work" / "other.c").write_text("static int total(void) { return 1; }\n", encoding="utf-8")
    prep = prepare_agent(
        run_dir=run_dir, agent_id="prove-other", role="prover", module="mod", function="total", c_file="other.c"
    )
    brief = (run_dir / prep["brief_file"]).read_text(encoding="utf-8")
    assert prep["prover_context"]["facts"] is False
    assert "`*out`" not in brief


def test_other_roles_keep_their_briefs(tmp_path: Path) -> None:
    run_dir = _prover_run(tmp_path)
    prep = prepare_agent(run_dir=run_dir, agent_id="arch-mod", role="architect", module="mod", header_file="mod.h")
    assert "prover_context" not in prep
    assert "Deterministic Function Context" not in (run_dir / prep["brief_file"]).read_text(encoding="utf-8")
