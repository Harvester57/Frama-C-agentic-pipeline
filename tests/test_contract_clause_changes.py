"""
acsl_ast.compare_function_contracts: which clauses of a function's contract a candidate removed.

libmodbus run-1 (2026-11-18): `prove-modbus_write_register` deleted `assigns *ctx \\from reg_addr, value;`
and `ensures status: \\result >= -1;` from the contract in `src/modbus.h`, added one unrelated `ensures`,
reported `all_proven`, and the merge accepted it: the frame check only protects the clauses of the
projected skeleton. The merge gate is in workspace_overlay.py; this is the pure comparison it calls.

The before and after texts in `tests/fixtures/libmodbus_run1_contracts/` are line ranges of the agent's
recorded `scratch/base/` and `scratch/candidates/best/work/` trees, with its patch beside them.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from acsl_ast import DEFAULT_BEHAVIOR, compare_function_contracts  # noqa: E402

RUN1_CONTRACTS = ROOT / "tests" / "fixtures" / "libmodbus_run1_contracts"
EMPTY_DELTA: dict[str, list[str]] = {"baseline": [], "candidate": [], "removed": [], "added": []}

HEADER = "int parse(const unsigned char *buf, int len, int *out);\n"
SOURCE = "int parse(const unsigned char *data, int n, int *out)\n{\n    *out = n;\n    return 0;\n}\n"


def _with_contract(declaration: str, *clauses: str) -> str:
    return "/*@\n" + "".join(f"  {c}\n" for c in clauses) + "*/\n" + declaration


def _run1(name: str) -> str:
    return (RUN1_CONTRACTS / name).read_text(encoding="utf-8")


def _default(result: dict) -> dict:
    assert result["available"], result["reason"]
    return result["behaviors"][DEFAULT_BEHAVIOR]


# ---------------------------------------------------------------------------
# The run-1 regression
# ---------------------------------------------------------------------------


def test_run1_fixture_is_the_recorded_patch() -> None:
    patch = _run1("prove_modbus_write_register.patch").splitlines()
    removed = [line[1:] for line in patch if line.startswith("-") and not line.startswith("---")]
    added = [line[1:] for line in patch if line.startswith("+") and not line.startswith("+++")]
    base = _run1("modbus_write_register.base.h").splitlines()
    cand = _run1("modbus_write_register.candidate.h").splitlines()
    assert removed == ["  assigns *ctx \\from reg_addr, value;", "  ensures status: \\result >= -1;"]
    assert [line for line in base if line not in cand] == ["  assigns *ctx \\from reg_addr, value;"]
    assert base.count(removed[1]) == 2 and cand.count(removed[1]) == 1
    assert [line for line in cand if line not in base] == added


def test_run1_deleted_assigns_and_ensures_are_reported() -> None:
    source = _run1("modbus_write_register.c")
    result = compare_function_contracts(
        {"src/modbus.c": source, "src/modbus.h": _run1("modbus_write_register.base.h")},
        {"src/modbus.c": source, "src/modbus.h": _run1("modbus_write_register.candidate.h")},
        "modbus_write_register",
    )
    assert result["available"] is True and result["reason"] == ""
    assert result["had_contract"] is True and result["has_contract"] is True
    assert list(result["behaviors"]) == [DEFAULT_BEHAVIOR]
    default = result["behaviors"][DEFAULT_BEHAVIOR]
    assert default["assigns"] == {
        "baseline": [
            {
                "text": "*ctx \\from reg_addr, value",
                "locs": ["*ctx"],
                "from": ["reg_addr", "value"],
                "from_nothing": False,
            }
        ],
        "candidate": [],
        "status": "removed",
        "removed": ["*ctx \\from reg_addr, value"],
        "added": [],
        "locations_removed": ["*ctx"],
        "locations_added": [],
    }
    assert default["ensures"] == {
        "baseline": ["\\result >= -1"],
        "candidate": ["ctx == \\null ==> \\result == -1"],
        "removed": ["\\result >= -1"],
        "added": ["ctx == \\null ==> \\result == -1"],
    }
    assert default["requires"]["removed"] == [] and default["requires"]["added"] == []
    assert default["requires"]["baseline"] == ["ctx == \\null || \\valid(ctx)"]
    assert default["terminates"] == {"baseline": ["\\true"], "candidate": ["\\true"], "removed": [], "added": []}
    assert default["exits"] == {"baseline": ["\\false"], "candidate": ["\\false"], "removed": [], "added": []}
    assert result["summary"] == {
        "assigns_removed_in": [DEFAULT_BEHAVIOR],
        "ensures_removed_in": [DEFAULT_BEHAVIOR],
        "behaviors_removed": [],
    }
    assert result["declarations"]["baseline"] == [
        {"file": "src/modbus.c", "kind": "definition", "clauses": 0},
        {"file": "src/modbus.h", "kind": "prototype", "clauses": 5},
    ]
    assert result["declarations"]["candidate"][1] == {"file": "src/modbus.h", "kind": "prototype", "clauses": 4}
    json.dumps(result)


def test_run1_neighbour_function_is_unchanged() -> None:
    result = compare_function_contracts(
        {"src/modbus.h": _run1("modbus_write_register.base.h")},
        {"src/modbus.h": _run1("modbus_write_register.candidate.h")},
        "modbus_write_bit",
    )
    default = _default(result)
    assert default["assigns"]["status"] == "same"
    assert default["assigns"]["baseline"] == default["assigns"]["candidate"]
    assert all(not delta["removed"] and not delta["added"] for delta in default.values() if isinstance(delta, dict))
    assert result["summary"] == {"assigns_removed_in": [], "ensures_removed_in": [], "behaviors_removed": []}


def test_an_assigns_clause_commented_out_is_removed() -> None:
    base = _run1("modbus_write_register.base.h")
    commented = base.replace("  assigns *ctx \\from reg_addr, value;", "  // assigns *ctx \\from reg_addr, value;")
    assert commented != base
    result = compare_function_contracts({"src/modbus.h": base}, {"src/modbus.h": commented}, "modbus_write_register")
    assert _default(result)["assigns"]["status"] == "removed"
    assert result["summary"]["assigns_removed_in"] == [DEFAULT_BEHAVIOR]


# ---------------------------------------------------------------------------
# Controls: changes that are not a removal, or not the same removal
# ---------------------------------------------------------------------------


def test_a_narrowed_assigns_is_changed_not_removed() -> None:
    base = _with_contract(HEADER, "assigns *out, buf[0 .. len - 1] \\from len;", "ensures \\result == 0;")
    cand = _with_contract(HEADER, "assigns *out \\from len;", "ensures \\result == 0;")
    result = compare_function_contracts({"parse.h": base}, {"parse.h": cand}, "parse")
    assigns = _default(result)["assigns"]
    assert assigns["status"] == "changed"
    assert assigns["locations_removed"] == ["buf[0 .. len - 1]"] and assigns["locations_added"] == []
    assert assigns["removed"] == ["*out, buf[0 .. len - 1] \\from len"] and assigns["added"] == ["*out \\from len"]
    assert [c["locs"] for c in assigns["candidate"]] == [["*out"]]
    assert result["summary"]["assigns_removed_in"] == []


def test_a_rewritten_from_part_is_changed_with_the_same_locations() -> None:
    base = _with_contract(HEADER, "assigns *out \\from len, buf[0 .. len - 1];")
    cand = _with_contract(HEADER, "assigns *out \\from \\nothing;")
    assigns = _default(compare_function_contracts({"parse.h": base}, {"parse.h": cand}, "parse"))["assigns"]
    assert assigns["status"] == "changed"
    assert assigns["locations_removed"] == [] and assigns["locations_added"] == []
    assert assigns["baseline"][0]["from"] == ["len", "buf[0 .. len - 1]"]
    assert assigns["candidate"][0]["from"] == ["\\nothing"] and assigns["candidate"][0]["from_nothing"] is True


def test_a_renamed_label_or_reflowed_clause_is_not_a_removal() -> None:
    base = _with_contract(HEADER, "requires shape: \\valid(out);", "ensures status: \\result >= -1;")
    cand = (
        "/*@ requires out_valid:\n"
        "  @     \\valid( out ); // the caller owns it\n"
        "  @ ensures  result_bound :  (\\result>=-1) ;\n"
        "  @*/\n" + HEADER
    )
    default = _default(compare_function_contracts({"parse.h": base}, {"parse.h": cand}, "parse"))
    assert default["ensures"]["removed"] == [] and default["ensures"]["added"] == []
    assert default["requires"]["removed"] == [] and default["requires"]["added"] == []
    assert default["ensures"]["baseline"] == ["\\result >= -1"]


def test_a_clause_moved_between_prototype_and_definition_is_not_a_removal() -> None:
    # The definition names its formals differently (`data`, `n`): the moved clause is rewritten for them.
    baseline = {
        "parse.h": _with_contract(
            HEADER, "requires \\valid(out);", "assigns *out \\from len;", "ensures \\result == 0;"
        ),
        "parse.c": SOURCE,
    }
    candidate = {
        "parse.h": _with_contract(HEADER, "requires \\valid(out);"),
        "parse.c": _with_contract(SOURCE, "assigns *out \\from n;", "ensures \\result == 0;"),
    }
    result = compare_function_contracts(baseline, candidate, "parse")
    default = _default(result)
    assert result["formals_unified"] is True
    assert default["assigns"]["status"] == "same"
    assert default["assigns"]["baseline"][0]["text"] == "*out \\from len"
    assert default["assigns"]["candidate"][0]["text"] == "*out \\from n"
    assert default["assigns"]["removed"] == [] and default["assigns"]["added"] == []
    assert default["ensures"]["removed"] == [] and default["ensures"]["added"] == []
    assert [d["clauses"] for d in result["declarations"]["baseline"]] == [3, 0]
    assert [d["clauses"] for d in result["declarations"]["candidate"]] == [1, 2]
    # The same move, but the clause is dropped on the way: reported.
    candidate["parse.c"] = _with_contract(SOURCE, "ensures \\result == 0;")
    dropped = compare_function_contracts(baseline, candidate, "parse")
    assert _default(dropped)["assigns"]["status"] == "removed"


def test_unnamed_formals_turn_positional_matching_off() -> None:
    proto = "int parse(const unsigned char *, int, int *out);\n"
    baseline = {"parse.h": _with_contract(proto, "assigns *out;"), "parse.c": SOURCE}
    candidate = {"parse.h": proto, "parse.c": _with_contract(SOURCE, "assigns *out \\from n;")}
    result = compare_function_contracts(baseline, candidate, "parse")
    assert result["available"] is True and result["formals_unified"] is False
    assigns = _default(result)["assigns"]
    # The names are compared as written: `out` is `out` in both declarations.
    assert assigns["status"] == "changed" and assigns["locations_removed"] == [] and assigns["locations_added"] == []


def test_a_clause_moved_between_two_declarations_of_one_header_is_not_a_removal() -> None:
    proto = "static inline int twice(int x);\n"
    definition = "static inline int twice(int x)\n{\n    return 2 * x;\n}\n"
    baseline = {"twice.h": _with_contract(proto, "assigns \\nothing;", "ensures \\result == 2 * x;") + definition}
    candidate = {"twice.h": proto + _with_contract(definition, "assigns \\nothing;", "ensures \\result == 2 * x;")}
    result = compare_function_contracts(baseline, candidate, "twice")
    default = _default(result)
    assert default["assigns"]["status"] == "same" and default["ensures"]["removed"] == []
    assert [d["kind"] for d in result["declarations"]["baseline"]] == ["prototype", "definition"]


def test_a_duplicate_clause_dropped_from_one_declaration_is_not_a_removal() -> None:
    baseline = {
        "parse.h": _with_contract(HEADER, "ensures \\result == 0;"),
        "parse.c": _with_contract(SOURCE, "ensures \\result == 0;"),
    }
    candidate = {"parse.h": _with_contract(HEADER, "ensures \\result == 0;"), "parse.c": SOURCE}
    ensures = _default(compare_function_contracts(baseline, candidate, "parse"))["ensures"]
    assert ensures["removed"] == [] and ensures["added"] == []
    assert ensures["baseline"] == ["\\result == 0", "\\result == 0"] and ensures["candidate"] == ["\\result == 0"]


BEHAVIORS_BASE = _with_contract(
    HEADER,
    "requires \\valid(out);",
    "behavior ok:",
    "  assumes len >= 0;",
    "  assigns *out \\from len;",
    "  ensures \\result == 0;",
    "behavior bad:",
    "  assumes len < 0;",
    "  assigns \\nothing;",
    "  ensures \\result == -1;",
    "complete behaviors;",
    "disjoint behaviors ok, bad;",
)


def test_named_behaviors_are_compared_one_by_one() -> None:
    cand = _with_contract(
        HEADER,
        "requires \\valid(out);",
        "behavior ok:",
        "  assumes len >= 0;",
        "  assigns *out \\from len;",
        "  ensures \\result >= 0;",
        "behavior bad:",
        "  assumes len < 0;",
        "  ensures \\result == -1;",
        "disjoint behaviors ok, bad;",
    )
    result = compare_function_contracts({"parse.h": BEHAVIORS_BASE}, {"parse.h": cand}, "parse")
    assert list(result["behaviors"]) == [DEFAULT_BEHAVIOR, "ok", "bad"]
    default, ok, bad = (result["behaviors"][name] for name in (DEFAULT_BEHAVIOR, "ok", "bad"))
    assert default["assigns"]["status"] == "none" and default["ensures"] == EMPTY_DELTA
    assert default["requires"]["baseline"] == ["\\valid(out)"]
    assert ok["assigns"]["status"] == "same"
    assert ok["ensures"]["removed"] == ["\\result == 0"] and ok["ensures"]["added"] == ["\\result >= 0"]
    assert ok["assumes"] == {"baseline": ["len >= 0"], "candidate": ["len >= 0"], "removed": [], "added": []}
    assert bad["assigns"]["status"] == "removed" and bad["assigns"]["removed"] == ["\\nothing"]
    assert bad["ensures"]["removed"] == []
    assert result["completeness"] == {
        "baseline": ["complete behaviors", "disjoint behaviors ok, bad"],
        "candidate": ["disjoint behaviors ok, bad"],
        "removed": ["complete behaviors"],
        "added": [],
    }
    assert result["summary"] == {"assigns_removed_in": ["bad"], "ensures_removed_in": ["ok"], "behaviors_removed": []}


def test_a_deleted_behavior_and_a_clause_moved_out_of_one_are_reported() -> None:
    cand = _with_contract(
        HEADER,
        "requires \\valid(out);",
        "ensures \\result == 0;",
        "behavior ok:",
        "  assumes len >= 0;",
        "  assigns *out \\from len;",
    )
    result = compare_function_contracts({"parse.h": BEHAVIORS_BASE}, {"parse.h": cand}, "parse")
    bad = result["behaviors"]["bad"]
    assert bad["in_baseline"] is True and bad["in_candidate"] is False
    assert bad["assigns"]["status"] == "removed" and bad["ensures"]["removed"] == ["\\result == -1"]
    # `ensures \result == 0` left behavior `ok` for the default behavior: gone from one, new in the other.
    assert result["behaviors"]["ok"]["ensures"]["removed"] == ["\\result == 0"]
    assert result["behaviors"][DEFAULT_BEHAVIOR]["ensures"]["added"] == ["\\result == 0"]
    assert result["summary"]["behaviors_removed"] == ["bad"]


def test_a_function_that_had_no_contract() -> None:
    cand = _with_contract(HEADER, "assigns *out \\from len;", "ensures \\result == 0;")
    result = compare_function_contracts(
        {"parse.h": HEADER, "parse.c": SOURCE}, {"parse.h": cand, "parse.c": SOURCE}, "parse"
    )
    assert result["available"] is True
    assert result["had_contract"] is False and result["has_contract"] is True
    default = result["behaviors"][DEFAULT_BEHAVIOR]
    assert default["in_baseline"] is False and default["in_candidate"] is True
    assert default["assigns"]["status"] == "added" and default["assigns"]["baseline"] == []
    assert default["ensures"]["removed"] == [] and default["ensures"]["added"] == ["\\result == 0"]
    assert result["summary"] == {"assigns_removed_in": [], "ensures_removed_in": [], "behaviors_removed": []}
    # No contract on either side: still a comparison, with nothing in it.
    empty = compare_function_contracts({"parse.h": HEADER}, {"parse.h": HEADER}, "parse")
    assert empty["available"] is True and empty["had_contract"] is False and empty["has_contract"] is False
    assert empty["behaviors"][DEFAULT_BEHAVIOR]["assigns"]["status"] == "none"


def test_a_check_clause_is_not_the_clause_it_replaces() -> None:
    base = _with_contract(HEADER, "ensures \\result == 0;")
    cand = _with_contract(HEADER, "check ensures \\result == 0;")
    ensures = _default(compare_function_contracts({"parse.h": base}, {"parse.h": cand}, "parse"))["ensures"]
    assert ensures["removed"] == ["\\result == 0"] and ensures["added"] == ["check \\result == 0"]


def test_body_annotations_are_not_part_of_the_contract() -> None:
    # A statement contract in the body says nothing about the function's frame.
    base = _with_contract(SOURCE, "assigns *out \\from n;")
    in_body = SOURCE.replace("{\n", "{\n    //@ assigns *out \\from n;\n", 1)
    assert in_body != SOURCE
    result = compare_function_contracts({"parse.c": base}, {"parse.c": in_body}, "parse")
    assert _default(result)["assigns"]["status"] == "removed"
    assert result["has_contract"] is False


# ---------------------------------------------------------------------------
# No comparison: the result says why, and nothing raises
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("baseline", "candidate", "function", "reason"),
    [
        ({"parse.h": HEADER}, {"parse.h": HEADER}, "other", "no declaration of 'other'"),
        ({"parse.h": HEADER}, {"parse.h": "/*@ assigns \\nothing;\n" + HEADER}, "parse", "unclosed ACSL block comment"),
        ({"parse.h": HEADER, "parse.c": SOURCE}, {"parse.h": HEADER}, "parse", "do not cover the same files"),
        ({"parse.h": HEADER}, {"parse.h": HEADER + HEADER}, "parse", "declarations of 'parse' differ"),
        ({"parse.h": HEADER}, {"parse.h": "int parse(const unsigned char *buf, int len);\n"}, "parse", "differ"),
        ({}, {}, "parse", "no file"),
        ({"parse.h": None}, {"parse.h": HEADER}, "parse", "parse.h"),
        (None, None, "parse", "TypeError"),
        ({"parse.h": HEADER}, {"parse.h": HEADER}, "", "function name"),
    ],
)
def test_unavailable_comparisons_give_a_reason(baseline: object, candidate: object, function: str, reason: str) -> None:
    result = compare_function_contracts(baseline, candidate, function)  # type: ignore[arg-type]
    assert result["available"] is False
    assert reason in result["reason"], result["reason"]
    assert result["behaviors"] == {} and result["summary"] == {
        "assigns_removed_in": [],
        "ensures_removed_in": [],
        "behaviors_removed": [],
    }
    json.dumps(result)


def test_text_that_cannot_be_tokenized_never_raises() -> None:
    garbage = ['"unclosed', "/* open", "'x", "int parse(", "\x00\x01", "/*@ behavior : */ int parse(int a);", ")))}}}"]
    for left in garbage:
        for right in garbage:
            result = compare_function_contracts({"f.h": left}, {"f.h": right}, "parse")
            assert isinstance(result["available"], bool) and isinstance(result["reason"], str)
