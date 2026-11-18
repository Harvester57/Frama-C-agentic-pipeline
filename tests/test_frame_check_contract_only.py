"""The frame check reads the function contract only: a statement contract or an assertion inside the body
cannot stand for a projected `\\separated` / `assigns` clause the contract lacks (workspace_overlay merge
check and the proof-carry publish gate)."""

from __future__ import annotations

from pathlib import Path

import pytest

import proof_carry
import workspace_overlay
from acsl_ast import AcslError
from test_frame_preservation import BASELINE_C, DEFINITION, GOOD_CONTRACT, _init_tree, _merge

pytestmark = pytest.mark.unit

FRAME = "requires \\separated(buf + (0 .. len - 1), out);\n      assigns *out \\from buf + (0 .. len - 1), len;"
WRITE = "    *out = (int)len;\n"
# The projected clauses sit on the statement, the function contract says nothing about the frame.
BODY_ONLY_C = BASELINE_C.replace(DEFINITION, "/*@ requires \\valid(out); */\n" + DEFINITION).replace(
    WRITE, f"    /*@ {FRAME}\n    */\n{WRITE}"
)
# The control: the clauses are in the contract, and the body has annotations of its own.
BOTH_C = BASELINE_C.replace(DEFINITION, GOOD_CONTRACT + DEFINITION).replace(
    WRITE, f"    /*@ assigns *out; */\n{WRITE}    //@ assert *out == (int)len;\n"
)


def _agent_c(run_dir: Path, text: str) -> None:
    (run_dir / "agents" / "prover-1" / "scratch" / "work" / "parser.c").write_text(text, encoding="utf-8")


def test_a_statement_contract_does_not_satisfy_the_merge_frame_check(tmp_path: Path) -> None:
    run_dir, overlay = _init_tree(tmp_path)
    _agent_c(run_dir, BODY_ONLY_C)
    with pytest.raises(AcslError, match="frame-preservation") as exc:
        _merge(run_dir, overlay)
    assert "\\separated" in str(exc.value) and "assigns *out" in str(exc.value)
    assert (overlay / "work" / "parser.c").read_text(encoding="utf-8") == BASELINE_C


def test_a_contract_with_the_clauses_merges_whatever_the_body_annotates(tmp_path: Path) -> None:
    run_dir, overlay = _init_tree(tmp_path)
    _agent_c(run_dir, BOTH_C)
    res = _merge(run_dir, overlay)
    assert res["ok"] is True and res["modified_files"] == ["parser.c"]


def _definition(text: str) -> str:
    return text[text.index("/*@") :] if "/*@" in text.split(DEFINITION)[0] else text[text.index(DEFINITION) :]


def test_a_statement_contract_does_not_satisfy_the_proof_carry_gate(tmp_path: Path) -> None:
    _run_dir, overlay = _init_tree(tmp_path)
    errors = proof_carry.frame_gate_errors(
        overlay, "m", "parser.c", "parse_payload", [("parser.c", _definition(BODY_ONLY_C))]
    )
    assert len(errors) == 2 and any("\\separated" in e for e in errors) and any("assigns *out" in e for e in errors)


def test_the_proof_carry_gate_accepts_the_clauses_on_either_declaration(tmp_path: Path) -> None:
    _run_dir, overlay = _init_tree(tmp_path)
    gate = proof_carry.frame_gate_errors
    assert gate(overlay, "m", "parser.c", "parse_payload", [("parser.c", _definition(BOTH_C))]) == []
    prototype = GOOD_CONTRACT + "int parse_payload(const uint8_t *buf, size_t len, int *out);"
    spans = [("parser.c", _definition(BASELINE_C)), ("parser.h", prototype)]
    assert gate(overlay, "m", "parser.c", "parse_payload", spans) == []


def test_the_merge_and_the_publish_gate_read_the_same_text(tmp_path: Path) -> None:
    """Both go through acsl_ast.declaration_contract_text: neither sees `BODY_ONLY_C`'s statement contract."""
    acsl = workspace_overlay._merged_contract_acsl(tmp_path, ["parser.c"], {"parser.c": BODY_ONLY_C}, "parse_payload")
    assert acsl == "/*@ requires \\valid(out); */"
