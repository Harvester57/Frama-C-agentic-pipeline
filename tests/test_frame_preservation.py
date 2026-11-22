"""Frame-skeleton preservation at merge time: acsl_ast.extract_frame_clauses /
check_frame_preserved, and the workspace_overlay merge wiring that rejects a prover
candidate dropping a projected `\\separated` / `assigns ... \\from ...` clause."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import function_facts as ff  # noqa: E402
import workspace_overlay  # noqa: E402
import wp_scheduler  # noqa: E402
from acsl_ast import AcslError, check_frame_preserved, extract_frame_clauses  # noqa: E402

SKELETON = {
    "status": "ok",
    "separated": [
        {
            "roots": ["buf", "out"],
            "regions": ["buf + (0 .. len - 1)", "out"],
            "clause": "requires \\separated(buf + (0 .. len - 1), out);",
            "reason": "writes through `out` may overlap reads through `buf`",
        }
    ],
    "assigns": [
        {
            "loc": "*out",
            "from": ["buf + (0 .. len - 1)", "len"],
            "clause": "assigns *out \\from buf + (0 .. len - 1), len;",
            "source": "ast",
        }
    ],
    "notes": [],
}


def test_extract_frame_clauses_parses_separated_assigns_and_from() -> None:
    acsl = (
        "requires \\valid_read(buf + (0 .. len - 1));\n"
        "requires \\separated(buf + (0 .. len - 1), out);\n"
        "assigns *out \\from buf + (0 .. len - 1), len;\n"
        "ensures \\result == 0;\n"
    )
    clauses = extract_frame_clauses(acsl)
    assert clauses["separated"] == [["buf + (0 .. len - 1)", "out"]]
    assert clauses["assigns"] == [{"locs": ["*out"], "from": ["buf + (0 .. len - 1)", "len"], "from_nothing": False}]


def test_extract_frame_clauses_skips_loop_assigns_and_handles_nothing() -> None:
    acsl = "loop assigns i, acc, dst[0 .. n - 1];\nassigns \\nothing;\nassigns g \\from \\nothing;\n"
    clauses = extract_frame_clauses(acsl)
    assert clauses["separated"] == []
    assert clauses["assigns"] == [
        {"locs": ["\\nothing"], "from": [], "from_nothing": False},
        {"locs": ["g"], "from": ["\\nothing"], "from_nothing": True},
    ]


def test_extract_frame_clauses_handles_multiple_separated_args() -> None:
    clauses = extract_frame_clauses("requires \\separated(a + (0 .. 1), b, c + (0 .. 2));")
    assert clauses["separated"] == [["a + (0 .. 1)", "b", "c + (0 .. 2)"]]


def test_check_accepts_verbatim_and_stronger_candidates() -> None:
    verbatim = "requires \\separated(buf + (0 .. len - 1), out);\nassigns *out \\from buf + (0 .. len - 1), len;\n"
    assert check_frame_preserved(SKELETON, verbatim) == []
    stronger = (
        "requires \\separated(buf + (0 .. len - 1), out, other);\n"
        "assigns *out \\from buf + (0 .. len - 1), len, extra;\n"
    )
    assert check_frame_preserved(SKELETON, stronger) == []
    # Whitespace differences do not matter.
    spaced = "requires \\separated( buf+(0..len-1) , out ); assigns *out \\from buf+(0..len-1),len;"
    assert check_frame_preserved(SKELETON, spaced) == []


def test_check_rejects_dropped_or_weakened_clauses() -> None:
    no_separated = "assigns *out \\from buf + (0 .. len - 1), len;\n"
    errs = check_frame_preserved(SKELETON, no_separated)
    assert len(errs) == 1 and "\\separated" in errs[0]

    weaker_from = "requires \\separated(buf + (0 .. len - 1), out);\nassigns *out \\from len;\n"
    errs = check_frame_preserved(SKELETON, weaker_from)
    assert len(errs) == 1 and "*out" in errs[0]

    no_assigns = "requires \\separated(buf + (0 .. len - 1), out);\nensures \\result == 0;\n"
    assert check_frame_preserved(SKELETON, no_assigns)

    # A \separated over the wrong roots does not cover the pair.
    wrong_pair = "requires \\separated(buf + (0 .. len - 1), other);\nassigns *out \\from buf + (0 .. len - 1), len;\n"
    assert check_frame_preserved(SKELETON, wrong_pair)


def test_check_is_fail_open_without_a_skeleton() -> None:
    assert check_frame_preserved({"status": "disabled"}, "assigns \\nothing;") == []
    assert check_frame_preserved({}, "") == []
    assert check_frame_preserved({"status": "ok", "separated": [], "assigns": []}, "") == []


# ---------------------------------------------------------------------------
# Merge wiring
# ---------------------------------------------------------------------------

BASELINE_C = """\
#include "parser.h"

int parse_payload(const uint8_t *buf, size_t len, int *out) {
    if (buf == NULL || out == NULL) {
        return -1;
    }
    *out = (int)len;
    return 0;
}
"""

BASELINE_H = """\
#ifndef PARSER_H
#define PARSER_H

#include <stddef.h>
#include <stdint.h>

int parse_payload(const uint8_t *buf, size_t len, int *out);

#endif
"""

GOOD_H = BASELINE_H.replace(
    "int parse_payload(const uint8_t *buf, size_t len, int *out);",
    "/*@\n"
    "  requires len > 0 ==> \\valid_read(buf + (0 .. len - 1));\n"
    "  requires \\valid(out);\n"
    "  requires \\separated(buf + (0 .. len - 1), out);\n"
    "  assigns *out \\from buf + (0 .. len - 1), len;\n"
    "  ensures \\result == 0 || \\result == -1;\n"
    "*/\n"
    "int parse_payload(const uint8_t *buf, size_t len, int *out);",
)

WEAK_H = BASELINE_H.replace(
    "int parse_payload(const uint8_t *buf, size_t len, int *out);",
    "/*@\n  requires \\valid(out);\n  assigns *out;\n*/\nint parse_payload(const uint8_t *buf, size_t len, int *out);",
)


def _init_tree(
    tmp_path: Path, tree_c: str = BASELINE_C, tree_h: str = BASELINE_H, agents: int = 1
) -> tuple[Path, Path]:
    """A run whose shared tree already holds `tree_c` / `tree_h` when the agents' scratch overlays are cut from it."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "parser.c").write_text(BASELINE_C, encoding="utf-8")
    (target / "parser.h").write_text(BASELINE_H, encoding="utf-8")
    run_dir = tmp_path / "run"
    overlay = run_dir / "workspace"
    workspace_overlay.init_overlay(target, overlay)
    (overlay / "work" / "parser.c").write_text(tree_c, encoding="utf-8")
    (overlay / "work" / "parser.h").write_text(tree_h, encoding="utf-8")
    for n in range(1, agents + 1):
        workspace_overlay.init_agent_overlay(run_dir, f"prover-{n}", overlay)
    # The module's facts carry the projected skeleton for parser.c#parse_payload.
    facts_dir = overlay / "reports" / "facts"
    facts_dir.mkdir(parents=True, exist_ok=True)
    (facts_dir / "m.json").write_text(
        json.dumps(
            {
                "schema": ff.FACTS_SCHEMA,
                "module": "m",
                "status": "ok",
                "functions": {"parser.c#parse_payload": {"name": "parse_payload", "frame_skeleton": SKELETON}},
            }
        ),
        encoding="utf-8",
    )
    return run_dir, overlay


def _setup_run(tmp_path: Path, agent_h_text: str) -> tuple[Path, Path]:
    run_dir, overlay = _init_tree(tmp_path)
    (run_dir / "agents" / "prover-1" / "scratch" / "work" / "parser.h").write_text(agent_h_text, encoding="utf-8")
    return run_dir, overlay


def _merge(run_dir: Path, overlay: Path, **kwargs: object) -> dict:
    return workspace_overlay.merge_agent_overlay(
        run_dir=run_dir,
        agent_id="prover-1",
        role="prover",
        overlay_dir=overlay,
        c_file="parser.c",
        function="parse_payload",
        module="m",
        skip_reverify=True,
        **kwargs,  # type: ignore[arg-type]
    )


def test_merge_accepts_candidate_preserving_the_skeleton(tmp_path: Path) -> None:
    run_dir, overlay = _setup_run(tmp_path, GOOD_H)
    res = workspace_overlay.merge_agent_overlay(
        run_dir=run_dir,
        agent_id="prover-1",
        role="prover",
        overlay_dir=overlay,
        c_file="parser.c",
        function="parse_payload",
        header_file="parser.h",
        module="m",
        skip_reverify=True,
    )
    assert res["ok"] is True
    assert "\\separated(buf + (0 .. len - 1), out)" in (overlay / "work" / "parser.h").read_text(encoding="utf-8")


def test_merge_rejects_candidate_dropping_projected_frame_clauses(tmp_path: Path) -> None:
    run_dir, overlay = _setup_run(tmp_path, WEAK_H)
    with pytest.raises(AcslError, match="frame-preservation"):
        workspace_overlay.merge_agent_overlay(
            run_dir=run_dir,
            agent_id="prover-1",
            role="prover",
            overlay_dir=overlay,
            c_file="parser.c",
            function="parse_payload",
            header_file="parser.h",
            module="m",
            skip_reverify=True,
        )
    # Nothing was spliced.
    assert (overlay / "work" / "parser.h").read_text(encoding="utf-8") == BASELINE_H


def test_merge_fails_open_without_facts(tmp_path: Path) -> None:
    run_dir, overlay = _setup_run(tmp_path, WEAK_H)
    (overlay / "reports" / "facts" / "m.json").unlink()
    res = workspace_overlay.merge_agent_overlay(
        run_dir=run_dir,
        agent_id="prover-1",
        role="prover",
        overlay_dir=overlay,
        c_file="parser.c",
        function="parse_payload",
        header_file="parser.h",
        module="m",
        skip_reverify=True,
    )
    assert res["ok"] is True


# ---------------------------------------------------------------------------
# The contract is read from the merged tree, not only from the files the agent changed
# (libmodbus run-1: a negotiation that proved the contract already on the tree changed nothing,
# and every projected clause was reported missing)
# ---------------------------------------------------------------------------

DEFINITION = "int parse_payload(const uint8_t *buf, size_t len, int *out) {"
GOOD_CONTRACT = (
    "/*@\n"
    "  requires len > 0 ==> \\valid_read(buf + (0 .. len - 1));\n"
    "  requires \\valid(out);\n"
    "  requires \\separated(buf + (0 .. len - 1), out);\n"
    "  assigns *out \\from buf + (0 .. len - 1), len;\n"
    "*/\n"
)
GOOD_C = BASELINE_C.replace(DEFINITION, GOOD_CONTRACT + DEFINITION)
WEAK_C = BASELINE_C.replace(DEFINITION, "/*@\n  requires \\valid(out);\n  assigns *out;\n*/\n" + DEFINITION)
# A contract on the prototype that says nothing about the frame.
FRAMELESS_H = BASELINE_H.replace(
    "int parse_payload(const uint8_t *buf, size_t len, int *out);",
    "/*@ ensures \\result == 0 || \\result == -1; */\nint parse_payload(const uint8_t *buf, size_t len, int *out);",
)


def test_unchanged_result_with_the_contract_in_the_source_merges_as_a_no_op(tmp_path: Path) -> None:
    run_dir, overlay = _init_tree(tmp_path, tree_c=GOOD_C)
    res = _merge(run_dir, overlay)
    assert res["ok"] is True
    assert res["modified_files"] == []
    assert (overlay / "work" / "parser.c").read_text(encoding="utf-8") == GOOD_C


def test_unchanged_result_with_the_contract_on_an_unnamed_header_merges_as_a_no_op(tmp_path: Path) -> None:
    # No header is named (modbus_get_float_cdab: `header_file: ''`, its contract on the prototype in modbus.h).
    run_dir, overlay = _init_tree(tmp_path, tree_h=GOOD_H)
    res = _merge(run_dir, overlay)
    assert res["ok"] is True
    assert res["modified_files"] == []
    assert (overlay / "work" / "parser.h").read_text(encoding="utf-8") == GOOD_H


@pytest.mark.parametrize("named_header", [None, "parser.h"])
def test_agent_changing_only_the_header_keeps_the_contract_of_the_unchanged_source(
    tmp_path: Path, named_header: str | None
) -> None:
    run_dir, overlay = _init_tree(tmp_path, tree_c=GOOD_C)
    (run_dir / "agents" / "prover-1" / "scratch" / "work" / "parser.h").write_text(FRAMELESS_H, encoding="utf-8")
    res = _merge(run_dir, overlay, header_file=named_header)
    assert res["ok"] is True
    assert res["modified_files"] == ["parser.h"]
    assert (overlay / "work" / "parser.c").read_text(encoding="utf-8") == GOOD_C


def test_agent_changing_only_the_source_keeps_the_contract_of_the_unchanged_header(tmp_path: Path) -> None:
    run_dir, overlay = _init_tree(tmp_path, tree_h=GOOD_H)
    agent_c = BASELINE_C.replace(DEFINITION, "/*@ ensures \\result <= 0; */\n" + DEFINITION)
    (run_dir / "agents" / "prover-1" / "scratch" / "work" / "parser.c").write_text(agent_c, encoding="utf-8")
    res = _merge(run_dir, overlay)
    assert res["ok"] is True
    assert res["modified_files"] == ["parser.c"]


def test_unchanged_result_is_refused_when_the_tree_lacks_the_projected_clauses(tmp_path: Path) -> None:
    run_dir, overlay = _init_tree(tmp_path, tree_c=WEAK_C)
    with pytest.raises(AcslError, match="frame-preservation"):
        _merge(run_dir, overlay)
    assert (overlay / "work" / "parser.c").read_text(encoding="utf-8") == WEAK_C


@pytest.mark.parametrize(
    ("tree_c", "tree_h", "agent_h", "header"),
    [
        (GOOD_C, BASELINE_H, None, None),  # unchanged, the contract on the source
        (BASELINE_C, GOOD_H, None, None),  # unchanged, the contract on a header nobody named
        (WEAK_C, BASELINE_H, None, None),  # unchanged, and the tree lacks the clauses
        (BASELINE_C, BASELINE_H, GOOD_H, "parser.h"),
        (BASELINE_C, BASELINE_H, WEAK_H, "parser.h"),
    ],
)
def test_the_dry_run_of_a_requeue_gives_the_verdict_of_the_merge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tree_c: str, tree_h: str, agent_h: str | None, header: str | None
) -> None:
    run_dir, overlay = _init_tree(tmp_path, tree_c=tree_c, tree_h=tree_h)
    scratch = run_dir / "agents" / "prover-1" / "scratch"
    (scratch / "result.json").write_text(json.dumps({"status": "all_proven"}), encoding="utf-8")
    if agent_h is not None:
        (scratch / "work" / "parser.h").write_text(agent_h, encoding="utf-8")
    monkeypatch.chdir(run_dir)
    task = {"id": "prove:parser.c#parse_payload", "function": "parse_payload", "file": "parser.c", "module": "m"}

    dry = wp_scheduler._splice_refusal({**task, "header": header} if header else task, "prover-1")

    try:
        _merge(run_dir, overlay, header_file=header)
    except AcslError as exc:
        assert dry == str(exc)
    else:
        assert dry is None


def test_agent_weakening_the_contract_of_the_source_is_refused(tmp_path: Path) -> None:
    run_dir, overlay = _init_tree(tmp_path, tree_c=GOOD_C)
    (run_dir / "agents" / "prover-1" / "scratch" / "work" / "parser.c").write_text(WEAK_C, encoding="utf-8")
    with pytest.raises(AcslError, match="frame-preservation"):
        _merge(run_dir, overlay)
    assert (overlay / "work" / "parser.c").read_text(encoding="utf-8") == GOOD_C


def test_agent_weakening_the_header_is_refused_when_the_unchanged_source_has_no_frame(tmp_path: Path) -> None:
    run_dir, overlay = _init_tree(tmp_path, tree_c=WEAK_C, tree_h=GOOD_H)
    (run_dir / "agents" / "prover-1" / "scratch" / "work" / "parser.h").write_text(WEAK_H, encoding="utf-8")
    with pytest.raises(AcslError, match="frame-preservation"):
        _merge(run_dir, overlay, header_file="parser.h")
    assert (overlay / "work" / "parser.h").read_text(encoding="utf-8") == GOOD_H


def test_batch_merges_an_unchanged_result_and_refuses_one_on_a_tree_without_the_clauses(tmp_path: Path) -> None:
    entry = {"role": "prover", "file": "parser.c", "function": "parse_payload", "module": "m"}

    good_dir = tmp_path / "good"
    good_dir.mkdir()
    run_dir, overlay = _init_tree(good_dir, tree_c=GOOD_C)
    res = workspace_overlay.merge_agent_batch(
        run_dir, [{**entry, "agent_id": "prover-1"}], overlay_dir=overlay, skip_reverify=True
    )
    assert res["ok"] is True, res["failed"]
    assert [m["agent_id"] for m in res["merged"]] == ["prover-1"]

    weak_dir = tmp_path / "weak"
    weak_dir.mkdir()
    run_dir, overlay = _init_tree(weak_dir, tree_c=WEAK_C)
    res = workspace_overlay.merge_agent_batch(
        run_dir, [{**entry, "agent_id": "prover-1"}], overlay_dir=overlay, skip_reverify=True
    )
    assert res["ok"] is False
    assert res["merged"] == []
    assert "frame-preservation" in res["failed"][0]["reason"]
