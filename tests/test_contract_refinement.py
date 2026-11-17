"""
Contract refinement probe (scripts/contract_refinement.py): probe generation text in, text out, the
verdict rules on recorded WP outcomes, and (`integration`, needs Frama-C) the probe run for real on a
refinement, a weakening and a postcondition that follows from `assigns`.
"""

from __future__ import annotations

import dataclasses
import json
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import contract_refinement as CR

needs_framac = pytest.mark.skipif(shutil.which("frama-c") is None, reason="Frama-C not available")

PROBE_HEADER = (
    "#ifndef API_H\n#define API_H\n#define LIMIT 100\n"
    "/*@ predicate small(integer x) = -LIMIT <= x <= LIMIT; */\n"
    "int add(int a, int b);\n#endif\n"
)


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


def _contract(tmp_path: Path, name: str, text: str, function: str, header: str | None = None) -> CR.FunctionContract:
    if header is not None:
        _write(tmp_path, "api.h", header)
    return CR.read_function_contract(_write(tmp_path, name, text), function, "-I.")


@pytest.mark.unit
def test_reads_pieces_from_the_definition_and_the_header(tmp_path):
    header = PROBE_HEADER.replace("int add(int a, int b);", "/*@ requires small(a); */\nint add(int a, int b);")
    c = _contract(
        tmp_path,
        "api.c",
        '#include "api.h"\n/*@ assigns \\nothing;\n  @ ensures \\result == a + b; */\nint add(int a, int b) { return a + b; }\n',
        "add",
        header,
    )
    assert [Path(p.file).name for p in c.pieces] == ["api.c", "api.h"]
    assert c.pieces[0].line == 2 and c.pieces[1].line == 5
    assert c.definition is not None and c.definition.declarator == "int add(int a, int b)"
    assert c.definition.params == ["a", "b"] and c.returns_void is False
    assert CR.FunctionContract.from_dict(json.loads(json.dumps(c.to_dict()))) == c


@pytest.mark.unit
def test_probe_text_declares_given_and_defines_probe_with_labels(tmp_path):
    new = _contract(
        tmp_path,
        "new.c",
        '#include "api.h"\n/*@ requires small(a) && small(b);\n    assigns \\nothing;\n'
        "    ensures \\result >= a + b - 1; */\nstatic inline int add(int a, int b) { return a + b; }\n",
        "add",
        PROBE_HEADER,
    )
    old = _contract(
        tmp_path,
        "old.c",
        '#include "api.h"\n/*@ requires small(a) && small(b);\n    assigns \\nothing;\n'
        "    ensures r: \\result == a + b; */\nstatic inline int add(int a, int b) { return a + b; }\n",
        "add",
    )
    assert old.definition is not None
    unit = CR.build_probe(new.pieces, old.pieces, old.definition, False, Path("/w/new.c"), "add")
    text = unit.text
    assert text.startswith('#include "/w/new.c"\n')
    assert "int add__given(int a, int b);" in text and "static" not in text and "inline" not in text
    assert "int add__probe(int a, int b);" in text
    assert "int add__probe(int a, int b)\n{\n  return add__given(a, b);\n}" in text
    # Every requires / ensures carries its own name; an existing name stays behind it.
    assert "requires fcprobe_1: small(a)" in text and "ensures fcprobe_4: r: \\result == a + b;" in text
    assert "assigns \\nothing;" in text and "fcprobe_" not in text.split("assigns")[1][:12]
    # The labels map back to the clause as written in its own file.
    assert unit.labels[4].contract == "probe" and unit.labels[4].kind == "ensures"
    assert Path(unit.labels[4].file).name == "old.c" and unit.labels[4].line == 4
    assert unit.labels[4].text == "\\result == a + b"
    assert unit.ensures_labels == [4]
    assert [r.kind for r in unit.by_kind["assigns"]] == ["assigns"]


@pytest.mark.unit
def test_void_function_calls_without_return(tmp_path):
    c = _contract(
        tmp_path,
        "s.c",
        "/*@ requires \\valid(p); assigns *p; ensures *p == v; */\nvoid set(int *p, int v) { *p = v; }\n",
        "set",
    )
    assert c.definition is not None and c.returns_void is True
    unit = CR.build_probe(c.pieces, c.pieces, c.definition, True, Path("/w/s.c"), "set")
    assert "{\n  set__given(p, v);\n}" in unit.text


@pytest.mark.unit
def test_strip_ensures_keeps_behaviors_and_fills_an_emptied_one():
    body = CR.acsl_body(
        "/*@ requires r: x > 0;\n  @ assigns \\nothing;\n  @ ensures e: \\result > 0;\n"
        "  @ behavior pos: assumes x > 1; ensures \\result > 1;\n"
        "  @ behavior any: ensures \\result >= 0;\n  @ complete behaviors; */"
    )
    out = CR.strip_ensures(body)
    assert "ensures" not in out
    assert "requires r: x > 0;" in out and "behavior pos: assumes x > 1;" in out
    assert "behavior any: assumes \\true;" in out and "complete behaviors;" in out
    # Offsets of what stays are unchanged (line numbers of the original clauses).
    assert out.count("\n") == body.count("\n")


@pytest.mark.unit
def test_acsl_body_keeps_offsets():
    text = "/*@ requires a;\n  @ ensures b; */"
    body = CR.acsl_body(text)
    assert len(body) == len(text) and "@" not in body and "requires a;" in body


@pytest.mark.unit
def test_variadic_function_is_undecided(tmp_path):
    src = "/*@ requires n >= 0; assigns \\nothing; */\nint lg(const char *f, int n, ...) { return n; }\n"
    c = _contract(tmp_path, "lg.c", src, "lg")
    assert c.definition is not None and c.definition.variadic
    with pytest.raises(CR.ProbeError, match="variadic"):
        CR.build_probe(c.pieces, c.pieces, c.definition, False, Path("/w/lg.c"), "lg")
    stronger = dataclasses.replace(c.pieces[0], acsl="/*@ requires n > 0; assigns \\nothing; */")
    changed = CR.FunctionContract(function="lg", pieces=[stronger], definition=c.definition, returns_void=False)
    res = CR.refinement_check(changed, c, tmp_path / "lg.c")
    assert res["verdict"] == CR.UNDECIDED and "variadic" in res["reason"] and not res["probe_run"]


@pytest.mark.unit
@pytest.mark.parametrize(
    ("declarator", "function"),
    [("int kr(a) int a", "kr"), ("int (*getcb(int k))(int)", "getcb")],
)
def test_declarators_the_probe_cannot_carry_are_undecided(declarator, function):
    piece = CR.Piece(file="x.c", line=1, acsl="/*@ assigns \\nothing; */", declarator=declarator, params=["a"])
    with pytest.raises(CR.ProbeError, match="after the parameter list"):
        CR.build_probe([piece], [piece], piece, False, Path("/w/x.c"), function)


@pytest.mark.unit
def test_function_without_a_usable_declaration_is_undecided(tmp_path):
    # The span reader does not see a K&R definition: there is no declaration to write the probe on.
    c = _contract(tmp_path, "kr.c", "/*@ assigns \\nothing; */\nint kr(a) int a; { return a; }\n", "kr")
    unit, run, res = CR.compare(c, c, tmp_path / "kr.c")
    assert unit is None and run == {} and res["verdict"] == CR.UNDECIDED


@pytest.mark.unit
def test_unnamed_formal_in_the_definition_is_undecided(tmp_path):
    proto = CR.Piece(file="h.h", line=1, acsl="/*@ assigns \\nothing; */", declarator="int f(int)", params=None)
    with pytest.raises(CR.ProbeError, match="unnamed"):
        CR.build_probe([proto], [proto], proto, False, Path("/w/f.c"), "f")


@pytest.mark.unit
def test_a_contract_without_assigns_is_undecided(tmp_path):
    c = _contract(
        tmp_path, "n.c", "/*@ requires \\valid(p); ensures *p == v; */\nvoid na(int *p, int v) { *p = v; }\n", "na"
    )
    assert c.definition is not None
    with pytest.raises(CR.ProbeError, match="no `assigns`"):
        CR.build_probe(c.pieces, c.pieces, c.definition, True, Path("/w/n.c"), "na")


@pytest.mark.unit
def test_refinement_check_skips_the_probe_when_nothing_changed(tmp_path, monkeypatch):
    def boom(*_a, **_k):
        raise AssertionError("no probe run expected")

    monkeypatch.setattr(CR, "run_probe", boom)
    src = "/*@ assigns \\nothing; ensures \\result == 1; */\nint one(void) { return 1; }\n"
    c = _contract(tmp_path, "o.c", src, "one")
    assert CR.refinement_check(c, c, tmp_path / "o.c")["verdict"] == CR.REFINES
    empty = CR.FunctionContract(function="one")
    res = CR.refinement_check(c, empty, tmp_path / "o.c")
    assert res["verdict"] == CR.REFINES and res["reason"] == "no previous contract" and not res["probe_run"]


@pytest.mark.unit
def test_probe_is_never_written_under_the_work_tree(tmp_path):
    unit = CR.ProbeUnit(text="int x;\n", function="f")
    res = CR.run_probe(unit, keep_dir=tmp_path / "run" / "workspace" / "work" / "probe", wp_par=1)
    assert not res["ok"] and "workspace/work" in res["reason"]
    assert not (tmp_path / "run" / "workspace" / "work" / "probe" / CR.PROBE_FILE).exists()


def _unit_with_labels() -> CR.ProbeUnit:
    unit = CR.ProbeUnit(text="", function="f")
    unit.labels[1] = CR.ClauseRef("given", "requires", "new.c", 3, "x > 0")
    unit.labels[2] = CR.ClauseRef("probe", "ensures", "old.c", 5, "\\result == x")
    unit.labels[3] = CR.ClauseRef("probe", "ensures", "old.c", 6, "\\result > 0")
    unit.ensures_labels = [2, 3]
    unit.by_kind["assigns"] = [CR.ClauseRef("probe", "assigns", "old.c", 4, "\\nothing")]
    return unit


def _entry(goal: str, prop: str, passed: bool, verdict: str = "valid") -> dict:
    return {"goal": goal, "property": prop, "function": "f__probe", "passed": passed, "verdict": verdict}


def _run(*entries: dict, models: tuple[str, ...] = ()) -> dict:
    return {"ok": True, "entries": list(entries), "models": list(models), "elapsed_ms": 10}


PROVED_REST = (
    _entry("typed_f_probe_terminates", "f_probe_terminates", True),
    _entry("typed_f_probe_assigns", "f_probe_assigns", True),
    _entry("typed_f__probe_call_f__given_f_given_requires_fcprobe_1", "f_given_requires_fcprobe_1", True),
)


@pytest.mark.unit
def test_verdict_rules_on_recorded_goals():
    unit = _unit_with_labels()
    ok2 = _entry("typed_f_probe_ensures_fcprobe_2", "f_probe_ensures_fcprobe_2", True)
    ok3 = _entry("typed_f_probe_ensures_fcprobe_3", "f_probe_ensures_fcprobe_3", True)
    bad2 = _entry("typed_f_probe_ensures_fcprobe_2", "f_probe_ensures_fcprobe_2", False, "unknown")
    slow3 = _entry("typed_f_probe_ensures_fcprobe_3", "f_probe_ensures_fcprobe_3", False, "timeout")

    assert CR.decide(unit, _run(*PROVED_REST, ok2, ok3))["verdict"] == CR.REFINES
    # A model for the goal: the previous clause is not implied.
    res = CR.decide(unit, _run(*PROVED_REST, bad2, ok3, models=("typed_f_probe_ensures_fcprobe_2",)))
    assert res["verdict"] == CR.WEAKER
    assert res["clauses"] == [
        {
            "contract": "probe",
            "kind": "ensures",
            "file": "old.c",
            "line": 5,
            "text": "\\result == x",
            "verdict_kind": "unknown",
            "model": True,
        }
    ]
    # No model (a timeout): undecided, never weaker.
    res = CR.decide(unit, _run(*PROVED_REST, ok2, slow3))
    assert res["verdict"] == CR.UNDECIDED and res["undecided_clauses"][0]["line"] == 6
    # A refuted clause and an open one: weaker, the open one listed apart.
    res = CR.decide(unit, _run(*PROVED_REST, bad2, slow3, models=("typed_f_probe_ensures_fcprobe_2",)))
    assert res["verdict"] == CR.WEAKER and [r["line"] for r in res["undecided_clauses"]] == [6]
    # The new requires is not implied by the previous one (goal at the call).
    req = _entry(
        "typed_f__probe_call_f__given_f_given_requires_fcprobe_1", "f_given_requires_fcprobe_1", False, "unknown"
    )
    res = CR.decide(unit, _run(PROVED_REST[0], PROVED_REST[1], req, ok2, ok3, models=(req["goal"],)))
    assert res["verdict"] == CR.WEAKER and res["clauses"][0]["contract"] == "given"
    # An unproved goal that is none of the compared clauses (here: termination, B has no terminates).
    term = _entry("typed_f_probe_terminates", "f_probe_terminates", False, "unknown")
    res = CR.decide(unit, _run(term, PROVED_REST[1], ok2, ok3, models=(term["goal"],)))
    assert res["verdict"] == CR.UNDECIDED and "none of the compared clauses" in res["reason"]
    # Nothing proved at all, no goal, a failed run.
    assert CR.decide(unit, _run(bad2))["verdict"] == CR.UNDECIDED
    assert CR.decide(unit, _run())["verdict"] == CR.UNDECIDED
    assert CR.decide(unit, {"ok": False, "reason": "rc=1"}) == {
        "goal_timeout_s": CR.PROBE_GOAL_TIMEOUT_S,
        "elapsed_ms": None,
        "verdict": CR.UNDECIDED,
        "reason": "rc=1",
    }
    # assigns goals map to B's assigns clauses.
    assigns_bad = _entry("typed_f_probe_assigns_normal", "f_probe_assigns", False, "unknown")
    res = CR.decide(unit, _run(PROVED_REST[0], assigns_bad, ok2, ok3, models=(assigns_bad["goal"],)))
    assert res["verdict"] == CR.WEAKER and res["clauses"][0]["kind"] == "assigns"


@pytest.mark.unit
def test_frame_summary_reads_ensures_goals():
    unit = _unit_with_labels()
    ok2 = _entry("typed_f_probe_ensures_fcprobe_2", "f_probe_ensures_fcprobe_2", True)
    ok3 = _entry("typed_f_probe_ensures_fcprobe_3", "f_probe_ensures_fcprobe_3", True)
    bad3 = _entry("typed_f_probe_ensures_fcprobe_3", "f_probe_ensures_fcprobe_3", False, "unknown")
    slow3 = _entry("typed_f_probe_ensures_fcprobe_3", "f_probe_ensures_fcprobe_3", False, "timeout")

    def summary(*entries, models=()):
        return CR.frame_summary(unit, CR.classify_goals(unit, _run(*entries, models=models)))

    every = summary(*PROVED_REST, ok2, ok3)
    assert every["status"] == CR.FRAME_DECIDED and every["all_frame_only"] is True
    assert [r["line"] for r in every["frame_only"]] == [5, 6] and "contract" not in every["frame_only"][0]
    some = summary(*PROVED_REST, ok2, bad3, models=(bad3["goal"],))
    assert some["status"] == CR.FRAME_DECIDED and some["all_frame_only"] is False
    assert [r["line"] for r in some["not_frame_only"]] == [6]
    open_ = summary(*PROVED_REST, ok2, slow3)
    assert open_["status"] == CR.FRAME_UNDECIDED and open_["all_frame_only"] is False
    other = summary(PROVED_REST[0], _entry("g", "f_probe_assigns", False, "unknown"), ok2, ok3)
    assert other["status"] == CR.FRAME_UNDECIDED


@pytest.mark.unit
def test_frame_only_without_ensures_is_not_applicable(tmp_path):
    c = _contract(tmp_path, "z.c", "/*@ requires \\valid(p); assigns *p; */\nvoid z(int *p) { *p = 0; }\n", "z")
    res = CR.frame_only_ensures(c, tmp_path / "z.c")
    assert res["status"] == CR.FRAME_NOT_APPLICABLE and res["ensures"] == 0


@pytest.mark.unit
def test_missing_frama_c_is_undecided(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    src = "/*@ requires \\valid(p); assigns *p; ensures *p == 0; */\nvoid z(int *p) { *p = 0; }\n"
    c = _contract(tmp_path, "z.c", src, "z")
    res = CR.frame_only_ensures(c, tmp_path / "z.c", wp_par=1)
    assert res["status"] == CR.FRAME_UNDECIDED and "could not be started" in str(res["reason"])


# ---------------------------------------------------------------------------
# Integration: the probe in the analysis image
# ---------------------------------------------------------------------------

REFINE_NEW = """#include "api.h"

/*@ requires small(a) && small(b);
    assigns \\nothing;
    ensures \\result >= a + b - 1; */
int add(int a, int b) { return a + b; }

struct pt { int x; int y; };

/*@ requires small(v.x) && small(v.y);
    assigns \\nothing;
    ensures \\result == v.x + v.y; */
static int sum_pt(struct pt v) { return v.x + v.y; }

/*@ requires \\valid(p) && \\valid_read(q) && \\separated(p, q);
    assigns *p;
    ensures *q == \\old(*q);
    ensures *p == v; */
void set(int *p, const int *q, int v) { *p = v; }
"""

REFINE_OLD = """#include "api.h"

/*@ requires small(a) && small(b);
    assigns \\nothing;
    ensures \\result == a + b; */
int add(int a, int b) { return a + b; }

struct pt { int x; int y; };

/*@ requires small(v.x) && small(v.y);
    assigns \\nothing;
    ensures \\result >= v.x + v.y - 1; */
static int sum_pt(struct pt v) { return v.x + v.y; }

/*@ requires \\valid(p) && \\valid_read(q) && \\separated(p, q);
    assigns *p; */
void set(int *p, const int *q, int v) { *p = v; }
"""


@pytest.mark.integration
@needs_framac
def test_real_probe_refinement_weakening_and_frame_only(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write(tmp_path, "api.h", PROBE_HEADER)
    new_c, old_c = _write(tmp_path, "new.c", REFINE_NEW), _write(tmp_path, "old.c", REFINE_OLD)

    def contracts(fn):
        return CR.read_function_contract(new_c, fn, "-I."), CR.read_function_contract(old_c, fn, "-I.")

    timings = {}
    # A refinement (a static function taking a struct by value): the new result is exact.
    new, old = contracts("sum_pt")
    res = CR.refinement_check(new, old, new_c, "-I.", work_dir=tmp_path / "probe")
    assert res["verdict"] == CR.REFINES, res
    timings["refines"] = res["elapsed_ms"]
    # A weakening: the new contract no longer gives `\result == a + b`.
    new, old = contracts("add")
    res = CR.refinement_check(new, old, new_c, "-I.", work_dir=tmp_path / "probe")
    assert res["verdict"] == CR.WEAKER, res
    assert [(c["contract"], c["kind"], c["line"], c["text"]) for c in res["clauses"]] == [
        ("previous", "ensures", 5, "\\result == a + b")
    ]
    timings["weaker"] = res["elapsed_ms"]
    # Postconditions of `set`: `*q` is unchanged by the frame alone, `*p == v` is the function's work.
    new, _old = contracts("set")
    res = CR.frame_only_ensures(new, new_c, "-I.", work_dir=tmp_path / "probe")
    assert res["status"] == CR.FRAME_DECIDED and res["all_frame_only"] is False, res
    assert [c["text"] for c in res["frame_only"]] == ["*q == \\old(*q)"]
    assert [c["text"] for c in res["not_frame_only"]] == ["*p == v"]
    timings["frame_only"] = res["elapsed_ms"]
    print(f"probe timings (ms): {json.dumps(timings)}")
    # Nothing was left behind: the probe directory is temporary.
    assert not any((tmp_path / "probe").glob("contract_probe_*"))


@pytest.mark.unit
def test_relative_include_paths_are_made_absolute():
    base = Path("/run")
    flags = CR.absolute_path_flags("-I. -Iwork/include -I /abs -isystem sys -include cfg.h -DX=1 -O2", base)
    assert flags == "-I/run -I/run/work/include -I/abs -isystem /run/sys -include /run/cfg.h -DX=1 -O2"
    assert CR.absolute_path_flags("", base) == ""
    assert CR.absolute_path_flags("-I'unterminated", base) == "-I'unterminated"


RUN_LAYOUT_HEADER = """\
/*@ assigns \\nothing;
    ensures \\result == a + b; */
int add(int a, int b);
/*@ requires \\valid(p) && \\valid_read(q) && \\separated(p, q);
    assigns *p;
    ensures *q == \\old(*q); */
void touch(int *p, const int *q);
"""

RUN_LAYOUT_C = """\
#include <lib/api.h>
int add(int a, int b) { return a + b; }
void touch(int *p, const int *q) { *p = 0; }
"""


@pytest.mark.integration
@needs_framac
def test_real_pipeline_uses_on_a_run_layout(tmp_path, monkeypatch):
    """The contract sits on a header found only through a relative `-I`, as in a run directory."""
    import run_wp_function

    monkeypatch.chdir(tmp_path)
    _write(tmp_path, "work/include/lib/api.h", RUN_LAYOUT_HEADER)
    c_file = _write(tmp_path, "work/src/api.c", RUN_LAYOUT_C)
    flags = "-I. -Iwork/include"
    consistent = {"status": "consistent", "doomed": [], "dead_goals": 0}
    report = {"status": "all_proven", "function": "touch", "soundness": {"ok": True}, "layer_goals": []}
    limits = run_wp_function.apply_verdict_limits(report, c_file, consistent, cppflags=flags)["limits"]
    assert limits["frame_only_ensures"]["status"] == CR.FRAME_DECIDED, limits
    assert limits["frame_only_ensures"]["all_frame_only"] is True
    previous = CR.read_function_contract(c_file, "add", flags)
    weaker_header = RUN_LAYOUT_HEADER.replace("\\result == a + b", "\\result >= a")
    _write(tmp_path, "work/include/lib/api.h", weaker_header)
    new = CR.read_function_contract(c_file, "add", flags)
    res = CR.refinement_check(new, previous, c_file, flags)
    assert res["verdict"] == CR.WEAKER, res
    print(
        f"run-layout probe timings (ms): frame {limits['frame_only_ensures'].get('elapsed_ms')}, "
        f"weaker {res.get('elapsed_ms')}"
    )
