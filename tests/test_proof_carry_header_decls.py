"""Proof carry of a header function whose contract sits on its `static inline` definition (QCBOR run-6)."""

from __future__ import annotations

from pathlib import Path

import pytest

import proof_carry as pc

pytestmark = pytest.mark.unit

TWO_DECLS_H = """#ifndef U_H
#define U_H
static inline int get(const int *p);

static inline int get(const int *pMe)
{
   return *pMe;
}
#endif
"""

DEF_ONLY_H = """#ifndef U_H
#define U_H
static inline int get(const int *pMe)
{
   return *pMe;
}
#endif
"""

DEF_CONTRACT = "/*@ requires \\valid_read(pMe);\n    assigns \\nothing;\n    ensures \\result == *pMe; */\n"
DEF_LINE = "static inline int get(const int *pMe)\n{"


def _work(tmp_path: Path, header_text: str) -> Path:
    work = tmp_path / "workspace" / "work"
    (work / "inc").mkdir(parents=True)
    (work / "inc" / "u.h").write_text(header_text, encoding="utf-8", newline="")
    return work


@pytest.mark.parametrize("header_text", [TWO_DECLS_H, DEF_ONLY_H], ids=["prototype-and-definition", "definition-only"])
def test_callee_digest_sees_a_contract_on_the_definition(tmp_path: Path, header_text: str) -> None:
    work = _work(tmp_path, header_text)
    # The DAG record of the callee does not name its file: only the caller's header is read.
    before = pc._callee_contract_digest(work, "", "get", ["inc/u.h"])
    (work / "inc" / "u.h").write_text(header_text.replace(DEF_LINE, DEF_CONTRACT + DEF_LINE), encoding="utf-8")
    assert pc._callee_contract_digest(work, "", "get", ["inc/u.h"]) != before


def test_declarations_go_before_a_lone_definition(tmp_path: Path) -> None:
    out = pc._insert_decls(DEF_ONLY_H, "get", [{"text": "predicate ok(integer x) = x > 0;"}], "inc/u.h")
    assert out is not None
    assert out.index("predicate ok") < out.index("static inline int get")
    with_proto = pc._insert_decls(TWO_DECLS_H, "get", [{"text": "predicate ok(integer x) = x > 0;"}], "inc/u.h")
    assert with_proto is not None
    assert with_proto.index("predicate ok") < with_proto.index("static inline int get(const int *p);")


def test_a_lone_header_definition_resolves_to_its_own_header(tmp_path: Path) -> None:
    _work(tmp_path, DEF_ONLY_H)
    assert pc.resolve_header(tmp_path, tmp_path / "workspace", "inc/u.h", "get", None) == "inc/u.h"


def test_replace_span_in_a_header_targets_the_prototype(tmp_path: Path) -> None:
    out = pc._replace_span(
        TWO_DECLS_H, "get", "/*@ assigns \\nothing; */\nstatic inline int get(const int *p);", True, "u.h"
    )
    assert out is not None and out.count("assigns \\nothing") == 1
    assert out.index("assigns") < out.index("static inline int get(const int *p);")
