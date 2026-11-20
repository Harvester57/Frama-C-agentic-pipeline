#!/usr/bin/env python3
"""
A source file that defines one function in both arms of a preprocessor conditional.

nanopb `pb_decode.c` defines `pb_release` under `#ifdef PB_ENABLE_MALLOC` and again in the `#else` arm. The
nanopb run-1 build does not define `PB_ENABLE_MALLOC`, so the prover put its contract on the `#else`
definition, the one Frama-C compiles; WP proved it. The merge read the first definition only and refused the
result: `pb_decode.c: agent modified content outside assigned function 'pb_release'`. Every definition of the
name is now the function's declaration set in a source file, as every declaration already is in a header.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import function_facts as ff
import workspace_overlay
from acsl_ast import (
    ScopeViolationError,
    contract_declaration_spans,
    function_contract_text,
    has_function_contract,
    splice_prover_changes,
)

# pb_decode.c (nanopb), the two definitions of pb_release with their conditional, shortened above and below.
NANOPB_TWINS = """\
#ifdef PB_ENABLE_MALLOC
static void pb_release_single_field(pb_field_iter_t *field)
{
    pb_free(*(void**)field->pField);
}

void pb_release(const pb_msgdesc_t *fields, void *dest_struct)
{
    pb_field_iter_t iter;

    if (!dest_struct)
        return; /* Ignore NULL pointers, similar to free() */

    if (!pb_field_iter_begin(&iter, fields, dest_struct))
        return; /* Empty message type */

    do
    {
        pb_release_single_field(&iter);
    } while (pb_field_iter_next(&iter));
}
#else
void pb_release(const pb_msgdesc_t *fields, void *dest_struct)
{
    /* Nothing to release without PB_ENABLE_MALLOC. */
    PB_UNUSED(fields);
    PB_UNUSED(dest_struct);
}
#endif

/* Field decoders */

bool pb_decode_bool(pb_istream_t *stream, bool *dest)
{
    return pb_dec_bool(stream, dest);
}
"""

# The contract of the prover's patch (agents/prove-pb_release-2/scratch/pb_release.patch in nanopb run-1).
NANOPB_CONTRACT = "/*@ terminates \\true;\n  @ exits \\false;\n  @ assigns \\nothing;\n  @*/\n"
NANOPB_ELSE_DEF = "#else\nvoid pb_release("

TWIN_SOURCE = (
    "int before(void) { return 0; }\n"
    "#ifdef A\n"
    "int f(int n) { return n + 1; }\n"
    "#else\n"
    "int f(int n) { return n + 2; }\n"
    "#endif\n"
    "int after_twins(void) { return 3; }\n"
)
TWIN_FIRST = "#ifdef A\nint f("
TWIN_SECOND = "#else\nint f("


def _annotate(text: str, anchor: str, clause: str) -> str:
    """`text` with `/*@ clause */` in front of the declaration that follows the directive line of `anchor`."""
    at = text.index(anchor)
    head, _, _ = anchor.partition("\n")
    insert = at + len(head) + 1 if head.startswith("#") else at + 1
    return text[:insert] + f"/*@ {clause} */\n" + text[insert:]


def _nanopb_proved() -> str:
    at = NANOPB_TWINS.index(NANOPB_ELSE_DEF) + len("#else\n")
    return NANOPB_TWINS[:at] + NANOPB_CONTRACT + NANOPB_TWINS[at:]


# ---------------------------------------------------------------------------
# splice_prover_changes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("contract_only", [False, True])
def test_nanopb_contract_on_the_else_definition_is_spliced(contract_only: bool) -> None:
    agent = _nanopb_proved()
    spliced = splice_prover_changes(
        NANOPB_TWINS, agent, NANOPB_TWINS, "pb_release", path="pb_decode.c", contract_only=contract_only
    )
    assert spliced == agent
    assert "#else\n/*@ terminates \\true;" in spliced


@pytest.mark.parametrize("contract_only", [False, True])
def test_contract_on_the_second_twin_is_spliced(contract_only: bool) -> None:
    agent = _annotate(TWIN_SOURCE, TWIN_SECOND, "ensures \\result == n + 2;")
    assert splice_prover_changes(TWIN_SOURCE, agent, TWIN_SOURCE, "f", path="x.c", contract_only=contract_only) == agent


@pytest.mark.parametrize("contract_only", [False, True])
def test_contract_on_the_first_twin_is_still_spliced(contract_only: bool) -> None:
    agent = _annotate(TWIN_SOURCE, TWIN_FIRST, "ensures \\result == n + 1;")
    assert splice_prover_changes(TWIN_SOURCE, agent, TWIN_SOURCE, "f", path="x.c", contract_only=contract_only) == agent


def test_contracts_on_both_twins_are_spliced() -> None:
    agent = _annotate(TWIN_SOURCE, TWIN_FIRST, "ensures \\result == n + 1;")
    agent = _annotate(agent, TWIN_SECOND, "ensures \\result == n + 2;")
    assert splice_prover_changes(TWIN_SOURCE, agent, TWIN_SOURCE, "f", path="x.c") == agent


def test_the_second_twin_is_spliced_into_a_tree_that_moved_elsewhere() -> None:
    agent = _annotate(TWIN_SOURCE, TWIN_SECOND, "ensures \\result == n + 2;")
    current = _annotate(TWIN_SOURCE, "\nint after_twins", "ensures \\result == 3;")
    spliced = splice_prover_changes(TWIN_SOURCE, agent, current, "f", path="x.c")
    assert "#else\n/*@ ensures \\result == n + 2; */\nint f(int n) { return n + 2; }" in spliced
    assert "/*@ ensures \\result == 3; */\nint after_twins" in spliced
    assert spliced.count("int f(int n)") == 2


def test_an_edit_outside_every_twin_is_still_refused() -> None:
    agent = _annotate(TWIN_SOURCE, TWIN_SECOND, "ensures \\result == n + 2;")
    agent = _annotate(agent, "\nint after_twins", "ensures \\result == 3;")
    with pytest.raises(ScopeViolationError, match="outside assigned function 'f'"):
        splice_prover_changes(TWIN_SOURCE, agent, TWIN_SOURCE, "f", path="x.c")
    nanopb = _annotate(_nanopb_proved(), "\nbool pb_decode_bool", "assigns *dest;")
    with pytest.raises(ScopeViolationError, match="outside assigned function 'pb_release'"):
        splice_prover_changes(NANOPB_TWINS, nanopb, NANOPB_TWINS, "pb_release", path="pb_decode.c")


def test_an_edit_on_another_function_inside_the_conditional_is_refused() -> None:
    agent = _annotate(_nanopb_proved(), "\nstatic void pb_release_single_field", "assigns \\nothing;")
    with pytest.raises(ScopeViolationError, match="outside assigned function 'pb_release'"):
        splice_prover_changes(NANOPB_TWINS, agent, NANOPB_TWINS, "pb_release", path="pb_decode.c")


def test_a_concurrent_change_of_the_second_twin_is_reported_as_divergence() -> None:
    agent = _annotate(TWIN_SOURCE, TWIN_FIRST, "ensures \\result == n + 1;")
    current = _annotate(TWIN_SOURCE, TWIN_SECOND, "ensures \\result >= 0;")
    with pytest.raises(ScopeViolationError, match="diverged from agent base snapshot"):
        splice_prover_changes(TWIN_SOURCE, agent, current, "f", path="x.c")


def test_contract_only_keeps_the_base_body_of_the_second_twin() -> None:
    agent = _annotate(TWIN_SOURCE, TWIN_SECOND, "ensures \\result == n + 2;")
    agent = agent.replace("{ return n + 2; }", "{ /*@ assert n == n; */ return n + 2; }")
    spliced = splice_prover_changes(TWIN_SOURCE, agent, TWIN_SOURCE, "f", path="x.c", contract_only=True)
    assert "/*@ ensures \\result == n + 2; */\nint f(int n) { return n + 2; }" in spliced
    assert "assert" not in spliced
    full = splice_prover_changes(TWIN_SOURCE, agent, TWIN_SOURCE, "f", path="x.c")
    assert full == agent


# ---------------------------------------------------------------------------
# Readers of the function's contract
# ---------------------------------------------------------------------------


def test_every_twin_definition_is_a_contract_declaration() -> None:
    decls = contract_declaration_spans(NANOPB_TWINS, "pb_release", path="pb_decode.c")
    assert [d.kind for d in decls] == ["definition", "definition"]
    assert "Nothing to release" in decls[1].span.text
    # A forward prototype in a source file is still not one.
    with_proto = "int f(int n);\n" + TWIN_SOURCE
    assert [d.kind for d in contract_declaration_spans(with_proto, "f")] == ["definition", "definition"]


def test_the_contract_of_the_second_twin_is_read() -> None:
    agent = _nanopb_proved()
    assert has_function_contract(agent, "pb_release", path="pb_decode.c")
    assert not has_function_contract(NANOPB_TWINS, "pb_release", path="pb_decode.c")
    text = function_contract_text(agent, "pb_release", path="pb_decode.c")
    assert "terminates \\true;" in text and "assigns \\nothing;" in text


def test_a_trust_boundary_violation_on_the_second_twin_of_an_entry_is_refused() -> None:
    agent = _annotate(TWIN_SOURCE, TWIN_SECOND, "requires n <= 64;")
    errors = workspace_overlay.entry_trust_boundary_errors(
        {"entry_fn": "f"}, "x.c", agent, agent, TWIN_SOURCE, TWIN_SOURCE
    )
    assert errors and "n" in errors[0]


# ---------------------------------------------------------------------------
# Merge: the frame check reads the spliced twin
# ---------------------------------------------------------------------------

TWIN_MERGE_SOURCE = """\
#include <stddef.h>

#ifdef WITH_COPY
int fill(int *out, size_t len) {
    *out = (int)len + 1;
    return 1;
}
#else
int fill(int *out, size_t len) {
    *out = (int)len;
    return 0;
}
#endif
"""

TWIN_MERGE_SKELETON = {
    "status": "ok",
    "separated": [],
    "assigns": [{"loc": "*out", "from": ["len"], "clause": "assigns *out \\from len;", "source": "ast"}],
    "notes": [],
}


def _twin_run(tmp_path: Path, agent_text: str) -> tuple[Path, Path]:
    target = tmp_path / "target"
    target.mkdir()
    (target / "fill.c").write_text(TWIN_MERGE_SOURCE, encoding="utf-8")
    run_dir = tmp_path / "run"
    overlay = run_dir / "workspace"
    workspace_overlay.init_overlay(target, overlay)
    workspace_overlay.init_agent_overlay(run_dir, "prover-1", overlay)
    (run_dir / "agents" / "prover-1" / "scratch" / "work" / "fill.c").write_text(agent_text, encoding="utf-8")
    facts_dir = overlay / "reports" / "facts"
    facts_dir.mkdir(parents=True, exist_ok=True)
    (facts_dir / "m.json").write_text(
        json.dumps(
            {
                "schema": ff.FACTS_SCHEMA,
                "module": "m",
                "status": "ok",
                "functions": {"fill.c#fill": {"name": "fill", "frame_skeleton": TWIN_MERGE_SKELETON}},
            }
        ),
        encoding="utf-8",
    )
    return run_dir, overlay


def _merge_twin(run_dir: Path, overlay: Path) -> dict:
    return workspace_overlay.merge_agent_overlay(
        run_dir=run_dir,
        agent_id="prover-1",
        role="prover",
        overlay_dir=overlay,
        c_file="fill.c",
        function="fill",
        module="m",
        skip_reverify=True,
    )


def test_merge_of_a_contract_on_the_else_twin(tmp_path: Path) -> None:
    agent = TWIN_MERGE_SOURCE.replace(
        "#else\nint fill(", "#else\n/*@ requires \\valid(out);\n    assigns *out \\from len; */\nint fill("
    )
    run_dir, overlay = _twin_run(tmp_path, agent)
    res = _merge_twin(run_dir, overlay)
    assert res["ok"] is True
    assert (overlay / "work" / "fill.c").read_text(encoding="utf-8") == agent


def test_merge_of_a_frameless_contract_on_the_else_twin_is_refused(tmp_path: Path) -> None:
    agent = TWIN_MERGE_SOURCE.replace("#else\nint fill(", "#else\n/*@ requires \\valid(out); */\nint fill(")
    run_dir, overlay = _twin_run(tmp_path, agent)
    with pytest.raises(Exception, match="frame-preservation"):
        _merge_twin(run_dir, overlay)
    assert (overlay / "work" / "fill.c").read_text(encoding="utf-8") == TWIN_MERGE_SOURCE
