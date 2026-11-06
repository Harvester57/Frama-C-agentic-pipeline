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


def _setup_run(tmp_path: Path, agent_h_text: str) -> tuple[Path, Path]:
    target = tmp_path / "target"
    target.mkdir()
    (target / "parser.c").write_text(BASELINE_C, encoding="utf-8")
    (target / "parser.h").write_text(BASELINE_H, encoding="utf-8")
    run_dir = tmp_path / "run"
    overlay = run_dir / "workspace"
    workspace_overlay.init_overlay(target, overlay)
    workspace_overlay.init_agent_overlay(run_dir, "prover-1", overlay)
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
    (run_dir / "agents" / "prover-1" / "scratch" / "work" / "parser.h").write_text(agent_h_text, encoding="utf-8")
    return run_dir, overlay


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
