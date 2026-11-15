"""A header function declared twice (prototype + `static inline` definition): splice, trust boundary, readers.

QCBOR run-6 (2026-11-15): `UsefulBuf.h` declares each API function as a prototype (formal `pUOutBuf`) and
later as a `static inline` definition (formal `pMe`). A prover contract may sit on either declaration, or on
both; Frama-C merges the two contracts. Every reader of a header function's contract must see both.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import acsl_ast
import workspace_overlay
from acsl_ast import ScopeViolationError, TrustBoundaryError, function_declaration_spans, splice_prover_changes

UB_H = """#ifndef H
#define H
typedef struct { int magic; unsigned len; char *ptr; } UB;

static inline void Reset(UB *pUOutBuf);

static inline int Other(UB *p);

static inline void Reset(UB *pMe)
{
   pMe->len = 0;
}

static inline int Other(UB *p)
{
   return p->magic;
}
#endif
"""

PROTO_C = "/*@ requires valid_p: \\valid(pUOutBuf);\n    assigns pUOutBuf->len;\n*/\n"
DEF_C = "/*@ requires valid_p: \\valid(pMe);\n    assigns pMe->len;\n*/\n"
OTHER_C = "/*@ requires \\valid_read(p);\n    assigns \\nothing;\n*/\n"

PROTO = "static inline void Reset(UB *pUOutBuf);"
DEF = "static inline void Reset(UB *pMe)\n{"
OTHER = "static inline int Other(UB *p);"
NOPROTO_H = UB_H.replace(PROTO + "\n\n", "")


def on_proto(t: str) -> str:
    return t.replace(PROTO, PROTO_C + PROTO)


def on_def(t: str) -> str:
    return t.replace(DEF, DEF_C + DEF)


def on_other(t: str) -> str:
    return t.replace(OTHER, OTHER_C + OTHER)


def body_assert(t: str) -> str:
    return t.replace("   pMe->len = 0;", "   pMe->len = 0;\n   //@ assert unproven: pMe->len == 0;")


def splice(base: str, agent: str, current: str, **kw) -> str:
    return splice_prover_changes(base, agent, current, "Reset", is_header=True, path="UB.h", **kw)


# ---------------------------------------------------------------------------
# The helper
# ---------------------------------------------------------------------------


def test_declaration_spans_lists_prototype_and_definition_in_source_order() -> None:
    spans = function_declaration_spans(on_def(on_proto(UB_H)), "Reset", path="UB.h")
    assert [d.kind for d in spans] == ["prototype", "definition"]
    assert spans[0].span.text == PROTO_C + PROTO
    assert spans[1].span.text.startswith(DEF_C + DEF) and spans[1].span.text.endswith("}")
    assert spans[0].span.end_byte < spans[1].span.start_byte
    assert [d.kind for d in function_declaration_spans(NOPROTO_H, "Reset")] == ["definition"]
    assert function_declaration_spans(UB_H, "Missing") == []


# ---------------------------------------------------------------------------
# Splice cases (the probe's list)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "agent_edit",
    [on_proto, on_def, lambda t: on_def(on_proto(t))],
    ids=["prototype-only", "definition-only", "both"],
)
def test_contract_on_any_declaration_is_spliced(agent_edit) -> None:
    agent = agent_edit(UB_H)
    assert splice(UB_H, agent, UB_H) == agent


def test_contract_on_both_declarations_is_spliced_next_to_an_unrelated_merge() -> None:
    out = splice(UB_H, on_def(on_proto(UB_H)), on_other(UB_H))
    assert out == on_other(on_def(on_proto(UB_H)))


@pytest.mark.parametrize(
    "agent_edit",
    [lambda t: on_other(on_def(on_proto(t))), lambda t: on_other(on_def(t))],
    ids=["both-plus-other", "definition-plus-other"],
)
def test_an_edit_outside_every_declaration_is_refused(agent_edit) -> None:
    with pytest.raises(ScopeViolationError, match=r"agent modified content outside assigned function 'Reset'$"):
        splice(UB_H, agent_edit(UB_H), UB_H)


def test_an_added_top_level_declaration_keeps_its_own_message() -> None:
    agent = on_def(UB_H).replace(DEF_C, "/*@ predicate ok(UB *p) = \\valid(p); */\n\n" + DEF_C)
    with pytest.raises(ScopeViolationError, match=r"added top-level ACSL declaration\(s\) outside 'Reset': predicate ok;"):
        splice(UB_H, agent, UB_H)


@pytest.mark.parametrize(
    "agent,current",
    [
        (on_def(on_proto(UB_H)), on_proto(UB_H)),
        (on_def(on_proto(UB_H)), on_def(UB_H)),
        (on_def(UB_H), on_def(UB_H).replace("valid_p", "v2")),
        (on_def(UB_H), on_proto(UB_H)),
    ],
    ids=["both-current-proto", "both-current-def", "def-current-def", "def-current-proto"],
)
def test_a_concurrent_change_of_any_declaration_is_reported_as_divergence(agent: str, current: str) -> None:
    with pytest.raises(ScopeViolationError, match="diverged from agent base snapshot"):
        splice(UB_H, agent, current)


def test_header_with_only_a_definition_accepts_a_contract_on_it() -> None:
    agent = on_def(NOPROTO_H)
    assert splice(NOPROTO_H, agent, NOPROTO_H) == agent


@pytest.mark.parametrize(
    "agent_edit",
    [on_def, lambda t: on_def(on_proto(t))],
    ids=["definition", "both"],
)
def test_contract_only_keeps_the_base_body_of_a_header_definition(agent_edit) -> None:
    out = splice(UB_H, body_assert(agent_edit(UB_H)), UB_H, contract_only=True)
    assert out == agent_edit(UB_H)
    assert "assert unproven" not in out


def test_without_contract_only_the_body_annotation_of_a_header_definition_is_kept() -> None:
    agent = body_assert(on_def(UB_H))
    assert splice(UB_H, agent, UB_H) == agent


# ---------------------------------------------------------------------------
# Trust boundary: every declaration of the entry, each with its own formals
# ---------------------------------------------------------------------------

BAD_PROTO = "/*@ requires magic_bound: pUOutBuf->len <= 64;\n*/\n"
BAD_DEF = "/*@ requires magic_bound: pMe->len <= 64;\n*/\n"
HMETA = {"entry_fn": "Reset", "file": "UB.h"}


@pytest.mark.parametrize(
    "agent,formal",
    [
        (UB_H.replace(PROTO, BAD_PROTO + PROTO), "pUOutBuf"),
        (UB_H.replace(DEF, BAD_DEF + DEF), "pMe"),
        (UB_H.replace(PROTO, PROTO_C + PROTO).replace(DEF, BAD_DEF + DEF), "pMe"),
    ],
    ids=["prototype", "definition", "shape-on-prototype-value-on-definition"],
)
def test_trust_boundary_sees_a_value_constraint_on_any_declaration(agent: str, formal: str) -> None:
    merged = splice(UB_H, agent, UB_H)
    errs = workspace_overlay.entry_trust_boundary_errors(HMETA, "UB.h", merged, agent, UB_H, UB_H)
    assert len(errs) == 1 and f"constrains attacker-controlled {formal}" in errs[0], errs


def test_trust_boundary_accepts_shape_on_both_declarations() -> None:
    agent = on_def(on_proto(UB_H))
    merged = splice(UB_H, agent, UB_H)
    assert workspace_overlay.entry_trust_boundary_errors(HMETA, "UB.h", merged, agent, UB_H, UB_H) == []


def test_trust_boundary_ignores_a_constraint_already_on_the_baseline_definition() -> None:
    baseline = UB_H.replace(DEF, BAD_DEF + DEF)
    agent = on_proto(baseline)
    merged = splice(baseline, agent, baseline)
    assert workspace_overlay.entry_trust_boundary_errors(HMETA, "UB.h", merged, agent, baseline, baseline) == []


def _header_run(tmp_path: Path, edit) -> tuple[Path, Path]:
    target = tmp_path / "target"
    target.mkdir()
    (target / "UB.h").write_text(UB_H, encoding="utf-8")
    run_dir = (tmp_path / "run").resolve()
    overlay = run_dir / "workspace"
    workspace_overlay.init_overlay(target, overlay)
    (overlay / "harnesses").mkdir(parents=True, exist_ok=True)
    (overlay / "harnesses" / "harness_m.json").write_text(
        json.dumps({"module": "m", "entry_fn": "Reset", "reachability": "untrusted_surface"}), encoding="utf-8"
    )
    workspace_overlay.init_agent_overlay(run_dir, "prove-reset", overlay)
    path = run_dir / "agents" / "prove-reset" / "scratch" / "work" / "UB.h"
    path.write_text(edit(path.read_text(encoding="utf-8")), encoding="utf-8")
    return run_dir, overlay


def test_merge_refuses_a_value_constraint_on_the_definition_of_a_header_entry(tmp_path: Path) -> None:
    run_dir, overlay = _header_run(tmp_path, lambda t: t.replace(DEF, BAD_DEF + DEF))
    with pytest.raises(TrustBoundaryError, match=r"(?s)UB\.h: Reset: requires pMe->len <= 64;"):
        workspace_overlay.merge_agent_overlay(
            run_dir, "prove-reset", "prover", overlay, c_file="UB.h", function="Reset", module="m", skip_reverify=True
        )
    assert (overlay / "work" / "UB.h").read_text(encoding="utf-8") == UB_H


def test_merge_accepts_a_shape_contract_on_both_declarations_of_a_header_entry(tmp_path: Path) -> None:
    run_dir, overlay = _header_run(tmp_path, lambda t: on_def(on_proto(t)))
    res = workspace_overlay.merge_agent_overlay(
        run_dir, "prove-reset", "prover", overlay, c_file="UB.h", function="Reset", module="m", skip_reverify=True
    )
    assert res["ok"]
    assert (overlay / "work" / "UB.h").read_text(encoding="utf-8") == on_def(on_proto(UB_H))


# ---------------------------------------------------------------------------
# Readers
# ---------------------------------------------------------------------------


def test_contract_readers_see_a_contract_on_the_definition() -> None:
    text = on_def(UB_H)
    assert acsl_ast.has_function_contract(text, "Reset", is_header=True)
    assert "valid(pMe)" in acsl_ast.function_contract_text(text, "Reset", True)
    assert not acsl_ast.has_function_contract(UB_H, "Reset", is_header=True)
    # A body annotation is not a contract.
    assert not acsl_ast.has_function_contract(body_assert(UB_H), "Reset", is_header=True)
    assert "assert" not in acsl_ast.function_contract_text(body_assert(on_def(UB_H)), "Reset", True)


def test_contract_text_of_a_header_function_joins_both_declarations() -> None:
    text = acsl_ast.function_contract_text(on_def(on_proto(UB_H)), "Reset", True)
    assert "valid(pUOutBuf)" in text and "valid(pMe)" in text
