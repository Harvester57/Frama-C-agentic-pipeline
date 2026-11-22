"""Loop invariant seeds: candidates from loop facts, Houdini with WP, corpus filter, report and flag."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import function_facts as ff  # noqa: E402
import loop_seeds as ls  # noqa: E402
import wp_scheduler  # noqa: E402

BRIEF = (ROOT / "skills" / "framac-wp" / "prover_brief.md").read_text(encoding="utf-8")

SUM_INT = """\
/*@ requires len > 0 ==> \\valid_read(buf + (0 .. len - 1));
  @ assigns \\nothing;
  @*/
unsigned sum_int(const unsigned char *buf, int len) {
    unsigned acc = 0;
    int i;
    for (i = 0; i < len; i++) {
        acc = (acc + buf[i]) & 0xffffu;
    }
    return acc;
}
"""


def _loop(line, guard, scalars, index=0, parent=None, walkers=(), exits=(), **kw):
    """One loop as function_facts._loop_record stores it (the fields loop_seeds reads)."""
    return {
        "index": index,
        "parent": parent,
        "line": line,
        "header": kw.get("header", ""),
        "macro_expanded": kw.get("macro_expanded", False),
        "guard": guard,
        "scalars": [{"var": var, "updates": list(updates)} for var, updates in scalars],
        "memory_writes": kw.get("memory_writes", []),
        "calls": kw.get("calls", []),
        "exits": list(exits),
        "pointer_walkers": list(walkers),
    }


def _record(name, loops, formals=(), derived=None, file="m.c"):
    return {
        "name": name,
        "file": file,
        "code_lines": [],
        "formals": [{"name": n, "type": t, "kind": "pointer" if "*" in t else "scalar"} for n, t in formals],
        "loops": list(loops),
        "derived_pointers": dict(derived or {}),
    }


def _sum_int_record():
    loop = _loop(
        7,
        "i < len",
        [("acc", ["(acc + (unsigned int)*(buf + i)) & 0xffffu"]), ("i", ["i + 1"])],
        header="for (i = 0; i < len; i++)",
    )
    return _record("sum_int", [loop], [("buf", "unsigned char const *"), ("len", "int")])


def _predicates(record, text):
    return [(c.predicate, c.template) for c in ls.generate_candidates(record, text)]


# ---------------------------------------------------------------------------
# Conditions and operands
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("i < len", ("i", "<", "len")),
        ("(size_t)i < len", ("(size_t)i", "<", "len")),
        ("!(q != lim)", ("q", "==", "lim")),
        ("!((size_t)i < len)", ("(size_t)i", ">=", "len")),
        ("k != h->len", ("k", "!=", "h->len")),
        ("j + (unsigned int)1 < n", ("j + (unsigned int)1", "<", "n")),
        ("a < b && c < d", None),
        ("x << 2 < n", None),
        ("*p", None),
        ("a < b < c", None),
        (None, None),
    ],
)
def test_parse_condition(text, expected) -> None:
    assert ls.parse_condition(text) == expected


@pytest.mark.unit
def test_parse_operand_keeps_only_what_acsl_can_restate() -> None:
    plain = ls.parse_operand("len")
    assert plain is not None and plain.var == "len" and plain.text == "len" and not plain.memory
    cast = ls.parse_operand("(size_t)i")
    assert cast is not None and cast.var == "i" and cast.text == "(size_t)i"
    field = ls.parse_operand("h->len")
    assert field is not None and field.var is None and field.memory and field.paths == ("h->len",)
    arith = ls.parse_operand("n - 1UL")
    assert arith is not None and arith.text == "n - 1" and arith.literals == (1,) and arith.var is None
    literal = ls.parse_operand("0x10u")
    assert literal is not None and literal.literals == (16,) and literal.text == "0x10"
    for refused in ("*p", "f(x)", "a * b", "buf[i]", "a + b + c", "tmp_0 ? 1 : 2"):
        assert ls.parse_operand(refused) is None, refused


# ---------------------------------------------------------------------------
# Candidates
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_signed_index_loop_gets_bounds_and_the_guarded_form() -> None:
    assert _predicates(_sum_int_record(), SUM_INT) == [
        ("0 <= i", "counter_nonnegative"),
        ("i <= len", "guard_upper"),
        ("0 <= len ==> i <= len", "guard_upper_guarded"),
    ]
    cands = ls.generate_candidates(_sum_int_record(), SUM_INT)
    assert [c.name for c in cands] == ["seed_1", "seed_2", "seed_3"]
    assert cands[2].weaker_of == "i <= len" and {c.loop_line for c in cands} == {7}


@pytest.mark.unit
def test_unsigned_counter_gets_no_trivial_lower_bound_and_no_guarded_form() -> None:
    by_step = _record(
        "f", [_loop(3, "i < len", [("i", ["i + 1UL"])])], [("buf", "unsigned char const *"), ("len", "size_t")]
    )
    assert _predicates(by_step, "void f(void) {}\n") == [("i <= len", "guard_upper")]
    by_formal_type = _record("f", [_loop(3, "n > 0", [("n", ["n - 1"])])], [("n", "unsigned int")])
    assert _predicates(by_formal_type, "void f(void) {}\n") == [("0 <= n", "guard_lower")]


@pytest.mark.unit
def test_a_constant_bound_needs_the_literal_in_the_function_source() -> None:
    exits = [
        {"kind": "break", "condition": "!((size_t)i < len)", "line": 3},
        {"kind": "break", "condition": "!(i < 16)", "line": 3},
    ]
    record = _record("capped", [_loop(3, None, [("i", ["i + 1"])], exits=exits)], [("len", "size_t")])
    from_macro = "#define MAXN 16\nint capped(unsigned len) {\n  for (int i = 0; i < len && i < MAXN; i++) {}\n}\n"
    assert _predicates(record, from_macro) == [
        ("0 <= i", "counter_nonnegative"),
        ("(size_t)i <= len", "guard_upper"),
        ("0 <= len ==> (size_t)i <= len", "guard_upper_guarded"),
    ]
    literal = "int capped(unsigned len) {\n  // 99\n  for (int i = 0; i < len && i < 16; i++) {}\n}\n"
    assert ("i <= 16", "guard_upper") in _predicates(record, literal)
    # A number in a comment or an annotation is not the function's code.
    commented = "int capped(unsigned len) {\n  /* 16 */ //@ assert 16 == 16;\n  for (;;) {}\n}\n"
    assert ("i <= 16", "guard_upper") not in _predicates(record, commented)


@pytest.mark.unit
def test_a_break_inside_the_body_is_not_a_header_condition() -> None:
    exits = [{"kind": "break", "condition": "i >= cap", "line": 5}]
    record = _record("f", [_loop(3, "i < n", [("i", ["i + 1"])], exits=exits)], [("n", "int"), ("cap", "int")])
    assert not any("cap" in pred for pred, _ in _predicates(record, "void f(void) {}\n"))


@pytest.mark.unit
def test_bounds_the_loop_writes_and_non_counter_scalars_give_nothing() -> None:
    moving_bound = _record("f", [_loop(3, "i < n", [("i", ["i + 1"]), ("n", ["n - 1"])])], [("n", "int")])
    preds = [p for p, _ in _predicates(moving_bound, "void f(void) {}\n")]
    assert preds == ["0 <= i", "0 <= n"]  # each counter alone; never one against the other
    accumulator = _record("f", [_loop(3, "acc < n", [("acc", ["(acc + x) & 0xffu"])])], [("n", "int")])
    assert _predicates(accumulator, "void f(void) {}\n") == []
    memory_bound = _loop(3, "k != h->len", [("k", ["k + 1U"])])
    assert _predicates(_record("f", [memory_bound], [("h", "struct hdr const *")]), "void f(void) {}\n") == [
        ("k <= h->len", "guard_upper")
    ]
    writes = {**memory_bound, "memory_writes": [{"lval": "h->len", "root": "h"}]}
    assert _predicates(_record("f", [writes], [("h", "struct hdr *")]), "void f(void) {}\n") == []
    temp = _record("f", [_loop(3, "i < tmp_0", [("i", ["i + 1"])])], [])
    assert _predicates(temp, "void f(void) {}\n") == [("0 <= i", "counter_nonnegative")]


@pytest.mark.unit
def test_formal_pointer_walker_is_anchored_on_its_entry_value() -> None:
    loop = _loop(3, "p < end", [("acc", ["(acc + (unsigned int)*p) & 0xffffu"]), ("p", ["p + 1"])], walkers=["p"])
    record = _record("walk", [loop], [("p", "unsigned char const *"), ("end", "unsigned char const *")])
    assert _predicates(record, "void walk(void) {}\n") == [
        ("\\at(p, Pre) <= p", "walker_anchor"),
        ("\\base_addr(p) == \\base_addr(\\at(p, Pre))", "walker_base"),
        ("p <= end", "guard_upper"),
        ("\\at(p, Pre) <= end ==> p <= end", "guard_upper_guarded"),
    ]


@pytest.mark.unit
def test_local_walker_uses_the_formal_it_derives_from_or_only_its_guard() -> None:
    exits = [{"kind": "break", "condition": "!(q != lim)", "line": 3}]
    loop = _loop(3, None, [("q", ["q + 1"])], walkers=["q"], exits=exits)
    formals = [("s", "char const *"), ("lim", "char const *")]
    derived = _predicates(_record("skip", [loop], formals, derived={"q": "s"}), "void skip(void) {}\n")
    assert derived[0] == ("\\at(s, Pre) <= q", "walker_anchor")
    assert ("q <= lim", "guard_upper") in derived and ("lim <= q", "guard_lower") not in derived
    unknown_root = _predicates(_record("skip", [loop], formals), "void skip(void) {}\n")
    assert unknown_root == [("q <= lim", "guard_upper")]


@pytest.mark.unit
def test_inner_loop_restates_what_the_outer_loop_knows() -> None:
    outer = _loop(3, "r < rows", [("c", ["(size_t)0", "c + 1UL"]), ("r", ["r + 1UL"])], index=0)
    inner = _loop(4, "c < cols", [("c", ["c + 1UL"])], index=1, parent=0)
    record = _record("fill", [outer, inner], [("rows", "size_t"), ("cols", "size_t")])
    cands = ls.generate_candidates(record, "void fill(void) {}\n")
    assert [(c.loop_line, c.predicate, c.template) for c in cands] == [
        (3, "r <= rows", "guard_upper"),
        (4, "c <= cols", "guard_upper"),
        (4, "r < rows", "outer_guard"),  # and no restated `r <= rows`: the strict guard already says it
    ]
    # Nothing is restated about a variable the inner loop writes.
    writes_r = {**inner, "scalars": inner["scalars"] + [{"var": "r", "updates": ["r + 1UL"]}]}
    again = ls.generate_candidates({**record, "loops": [outer, writes_r]}, "void fill(void) {}\n")
    assert [c.template for c in again if c.loop_line == 4 and c.template.startswith("outer")] == []


@pytest.mark.unit
def test_candidates_skip_macro_loops_existing_invariants_and_used_seed_names() -> None:
    macro = {**_sum_int_record()["loops"][0], "macro_expanded": True}
    assert ls.generate_candidates({**_sum_int_record(), "loops": [macro]}, SUM_INT) == []
    pasted = SUM_INT.replace(
        "    for (i = 0",
        "    /*@ loop invariant seed_4: 0 <= i;\n      @ loop invariant mine: i<=len; */\n    for (i = 0",
    )
    record = _sum_int_record()
    record["loops"][0]["line"] = 9
    cands = ls.generate_candidates(record, pasted)
    assert [(c.name, c.predicate) for c in cands] == [("seed_5", "0 <= len ==> i <= len")]


@pytest.mark.unit
def test_existing_invariants_ignores_comments_nested_annotations_and_doxygen() -> None:
    # Commented-out, nested //@, doxygen, and plain C comments must not suppress candidate generation.
    commented = SUM_INT.replace(
        "    for (i = 0",
        (
            "    // loop invariant 0 <= i;\n"
            "    /*@* loop invariant i <= len; */\n"
            "    /*@ // loop invariant 0 <= i;\n"
            "      @ //@ loop invariant i <= len;\n"
            "      @ loop assigns i;\n"
            "      @*/\n"
            "    for (i = 0"
        ),
    )
    record = _sum_int_record()
    record["loops"][0]["line"] = 13
    preds = [c.predicate for c in ls.generate_candidates(record, commented)]
    assert "0 <= i" in preds and "i <= len" in preds

    # Real invariants with inline // comments or @ whitespace ARE recognized as already present.
    real = SUM_INT.replace(
        "    for (i = 0",
        (
            "    /*@ loop invariant 0 <= i // non-negative\n"
            "      @ ;\n"
            "      @ loop @ invariant @ i <= len;\n"
            "      @*/\n"
            "    for (i = 0"
        ),
    )
    record2 = _sum_int_record()
    record2["loops"][0]["line"] = 11
    assert [c.predicate for c in ls.generate_candidates(record2, real)] == ["0 <= len ==> i <= len"]


@pytest.mark.unit
def test_candidates_are_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ls, "MAX_CANDIDATES_PER_LOOP", 2)
    assert len(ls.generate_candidates(_sum_int_record(), SUM_INT)) == 2


# ---------------------------------------------------------------------------
# Insertion
# ---------------------------------------------------------------------------


def _seeds(*items):
    return [ls.Candidate(name, 0, line, pred, "t") for name, line, pred in items]


@pytest.mark.unit
def test_insert_gives_a_bare_loop_its_own_block() -> None:
    seeded, lines, skipped = ls.insert_seeds(SUM_INT, _seeds(("seed_1", 7, "0 <= i"), ("seed_2", 7, "i <= len")))
    assert skipped == {}
    assert (
        "/*@\nloop invariant seed_1: 0 <= i;\nloop invariant seed_2: i <= len;\n*/\nfor (i = 0; i < len; i++) {"
        in seeded
    )
    assert lines == {"seed_1": 8, "seed_2": 9}
    # Only annotations were added: the C tokens are those of the original.
    assert [t.text for t in ls.tokenize_c_acsl(seeded) if t.kind == "c_token"] == [
        t.text for t in ls.tokenize_c_acsl(SUM_INT) if t.kind == "c_token"
    ]


@pytest.mark.unit
def test_insert_joins_an_existing_loop_annotation_before_its_clauses() -> None:
    text = "void f(int n) {\n  int i;\n  /*@ loop invariant own: i >= 0;\n    @ loop assigns i;\n    @*/\n  for (i = 0; i < n; i++) {}\n}\n"
    seeded, lines, skipped = ls.insert_seeds(text, _seeds(("seed_1", 6, "i <= n")))
    assert skipped == {} and lines == {"seed_1": 4}
    assert "/*@\nloop invariant seed_1: i <= n;\n loop invariant own: i >= 0;" in seeded
    assert seeded.count("/*@") == 1  # Frama-C refuses two annotation blocks before one loop


@pytest.mark.unit
def test_insert_skips_loops_it_cannot_annotate() -> None:
    text = (
        "void f(int n) {\n  int i = 0;\n  if (n) while (i < n) i++;\n"
        "  //@ loop assigns i;\n  while (i < n) i++;\n"
        "  /*@ assert n >= 0; */\n  while (i < n) i++;\n}\n"
    )
    seeds = _seeds(("seed_1", 3, "i <= n"), ("seed_2", 5, "i <= n"), ("seed_3", 7, "i <= n"), ("seed_4", 99, "x"))
    seeded, lines, skipped = ls.insert_seeds(text, seeds)
    assert seeded == text and lines == {}
    assert set(skipped) == {3, 5, 7, 99}
    assert "not the first token" in skipped[3] and "//@" in skipped[5] and "not a loop annotation" in skipped[7]


@pytest.mark.unit
def test_insert_seeds_ignores_commented_loop_clauses_and_handles_at_and_doxygen() -> None:
    # A // comment or nested //@ mentioning `loop invariant` inside an assert block must not trick insert_seeds
    # into splicing loop invariants into that non-loop annotation block.
    fake_loop = (
        "void f(int n) {\n"
        "  int i = 0;\n"
        "  /*@ assert n >= 0; // loop invariant i >= 0;\n"
        "    @ //@ loop assigns i;\n"
        "    @*/\n"
        "  while (i < n) i++;\n"
        "}\n"
    )
    seeded, lines, skipped = ls.insert_seeds(fake_loop, _seeds(("seed_1", 6, "i <= n")))
    assert seeded == fake_loop and lines == {} and "not a loop annotation" in skipped[6]

    # A real loop annotation with `@` or a `//` comment between `loop` and `assigns` IS joined cleanly.
    at_loop = "void f(int n) {\n  int i = 0;\n  /*@ loop // note\n    @ @ assigns i; */\n  while (i < n) i++;\n}\n"
    seeded2, lines2, skipped2 = ls.insert_seeds(at_loop, _seeds(("seed_1", 5, "i <= n")))
    assert skipped2 == {} and "seed_1" in lines2 and seeded2.count("/*@") == 1
    assert "/*@\nloop invariant seed_1: i <= n;\n loop // note" in seeded2

    # A doxygen comment before a loop is a plain comment to Frama-C, so seeds get a fresh block after it.
    doxy = "void f(int n) {\n  int i = 0;\n  /*@* loop assigns i; */\n  while (i < n) i++;\n}\n"
    seeded3, lines3, skipped3 = ls.insert_seeds(doxy, _seeds(("seed_1", 4, "i <= n")))
    assert skipped3 == {} and "seed_1" in lines3
    assert "/*@* loop assigns i; */\n  /*@\nloop invariant seed_1: i <= n;\n*/\nwhile (i < n) i++;" in seeded3


# ---------------------------------------------------------------------------
# Houdini
# ---------------------------------------------------------------------------


class FakeWp:
    """A WP run decided by a table: per round, the seeds that fail and how."""

    def __init__(self, rounds, status="unproven_goals_remain", omit_rows=()):
        self.rounds = list(rounds)
        self.status = status
        self.omit_rows = set(omit_rows)
        self.calls: list[list[str]] = []
        self.texts: list[str] = []

    def __call__(self, copy: Path, function: str, names: list[str]) -> dict:
        text = copy.read_text(encoding="utf-8")
        self.calls.append(list(names))
        self.texts.append(text)
        failing = self.rounds.pop(0) if self.rounds else {}
        if isinstance(failing, dict) and "result" in failing:
            return failing
        log = "".join(
            f"[wp] [Timeout] typed_{function}_loop_invariant_{name}_{kind} (Qed 3ms) (Alt-Ergo)\n"
            for name, kinds in failing.items()
            for kind in kinds
        )
        rows = []
        for number, line in enumerate(text.split("\n"), 1):
            m = ls._SEED_CLAUSE_RE.match(line.strip())
            if m and m.group(1) not in self.omit_rows:
                status = "unknown" if m.group(1) in failing else "valid"
                rows.append({"line": number, "kind": "loop invariant", "function": function, "status": status})
        return {"result": {"status": self.status if failing else "all_proven"}, "log": log, "rows": rows}


def _houdini(tmp_path, wp, **kw):
    cands = ls.generate_candidates(_sum_int_record(), SUM_INT)
    summary = ls.houdini(SUM_INT, "sum_int", tmp_path / "sum.c", cands, wp, **kw)
    return cands, summary


@pytest.mark.unit
def test_houdini_drops_until_a_round_drops_nothing(tmp_path: Path) -> None:
    wp = FakeWp([{"seed_2": ["established"]}, {"seed_3": ["preserved", "established"]}, {}])
    cands, summary = _houdini(tmp_path, wp)
    assert wp.calls == [["seed_1", "seed_2", "seed_3"], ["seed_1", "seed_3"], ["seed_1"]]
    assert "seed_2" not in wp.texts[1] and "seed_3" not in wp.texts[2]
    assert summary["converged"] is True and summary["status"] == "ok" and len(summary["rounds"]) == 3
    assert [c.wp for c in cands] == [
        {"verdict": "proven", "round": 3},
        {"verdict": "dropped", "failed": ["established"], "round": 1},
        {"verdict": "dropped", "failed": ["established", "preserved"], "round": 2},
    ]
    assert summary["rounds"][0]["dropped"] == {"seed_2": ["established"]}


@pytest.mark.unit
def test_houdini_never_reads_a_missing_report_row_as_a_proof(tmp_path: Path) -> None:
    cands, summary = _houdini(tmp_path, FakeWp([{}, {}], omit_rows={"seed_3"}))
    assert [c.wp["verdict"] for c in cands] == ["proven", "proven", "dropped"]
    assert cands[2].wp["failed"] == ["not_proven"] and summary["converged"] is True


@pytest.mark.unit
def test_houdini_without_a_fixpoint_proves_nothing(tmp_path: Path) -> None:
    wp = FakeWp([{"seed_2": ["preserved"]}, {"seed_3": ["preserved"]}])
    cands, summary = _houdini(tmp_path, wp, max_rounds=2)
    assert summary["status"] == "round_limit" and summary["converged"] is False
    assert [c.wp["verdict"] for c in cands] == ["undecided", "dropped", "dropped"]


@pytest.mark.unit
def test_houdini_drops_the_clause_the_kernel_rejects_and_goes_on(tmp_path: Path) -> None:
    # seed_2 is on line 9 of the seeded copy (the block opens on line 7).
    rejected = {
        "result": {
            "status": "acsl_syntax_error",
            "syntax_check": {"errors": ["[kernel] sum.c:9: User Error: unbound logic variable len"]},
        }
    }
    cands, summary = _houdini(tmp_path, FakeWp([rejected, {}]))
    assert [c.wp["verdict"] for c in cands] == ["proven", "dropped", "proven"]
    assert cands[1].wp["failed"] == ["rejected_by_kernel"] and summary["converged"] is True
    unlocated = {"result": {"status": "acsl_syntax_error", "syntax_check": {"errors": ["[kernel] other.h:3: boom"]}}}
    cands, summary = _houdini(tmp_path, FakeWp([unlocated]))
    assert summary["status"] == "wp_failed" and {c.wp["verdict"] for c in cands} == {"undecided"}


@pytest.mark.unit
def test_houdini_reports_a_killed_wp_run_as_a_lost_hint(tmp_path: Path) -> None:
    killed = {"result": {"status": "analysis_error", "reason": "timeout"}}
    cands, summary = _houdini(tmp_path, FakeWp([killed]))
    assert summary["status"] == "timeout" and summary["converged"] is False
    assert {c.wp["verdict"] for c in cands} == {"undecided"}
    cands, summary = _houdini(tmp_path, FakeWp([]), deadline=0.0)
    assert summary["status"] == "timeout" and summary["rounds"] == []


# ---------------------------------------------------------------------------
# Corpus filter
# ---------------------------------------------------------------------------


class FakeGuard:
    def __init__(self, verdicts):
        self.verdicts = list(verdicts)
        self.texts: list[str] = []

    def __call__(self, copy: Path, function: str) -> dict:
        self.texts.append(copy.read_text(encoding="utf-8"))
        return self.verdicts.pop(0)


def _passed(reached=3):
    return {
        "status": "passed_dynamic_oracle",
        "reach": {"functions": {"sum_int": reached}},
        "corpus_total": 5,
        "corpus_replayed": 5,
        "corpus_sampled": False,
        # The build reported what E-ACSL ignored, and it ignored nothing (tests/test_unchecked_clauses_wiring.py).
        "unchecked_clauses": [],
        "unattributed_ignored_annotations": [],
    }


def _rejected(label, crash_input=None):
    return {
        "status": "rejected_overconstrained",
        "failure": {"label": label, "predicate": "i ≤ len", "is_rte": False},
        "crash_input": crash_input,
    }


@pytest.mark.unit
def test_corpus_filter_falsifies_one_candidate_per_replay_then_holds(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "seed-a").write_bytes(b"\x01" * 8)
    (corpus / "seed-b").write_bytes(b"\x02" * 8)
    crash = tmp_path / "crash-xyz"
    crash.write_bytes(b"\x02" * 8)
    cands = ls.generate_candidates(_sum_int_record(), SUM_INT)
    guard = FakeGuard([_rejected("seed_2", str(crash)), _passed()])
    summary = ls.corpus_filter(SUM_INT, "sum_int", tmp_path / "sum.c", cands, guard, corpus)
    assert summary["status"] == "ok" and [r.get("falsified") for r in summary["rounds"]] == ["seed_2", None]
    assert "seed_2" in guard.texts[0] and "seed_2" not in guard.texts[1]
    assert cands[1].corpus["verdict"] == "falsified" and cands[1].corpus["input"] == "seed-b"
    assert len(cands[1].corpus["input_sha256"]) == 64 and cands[1].corpus["input_size"] == 8
    assert cands[0].corpus == {"verdict": "held", "corpus_total": 5, "corpus_replayed": 5, "corpus_sampled": False}
    assert cands[2].corpus["verdict"] == "held"


@pytest.mark.unit
@pytest.mark.parametrize("reached", [0, None])
def test_a_function_no_input_reaches_holds_nothing(tmp_path: Path, reached) -> None:
    cands = ls.generate_candidates(_sum_int_record(), SUM_INT)
    ls.corpus_filter(SUM_INT, "sum_int", tmp_path / "sum.c", cands, FakeGuard([_passed(reached)]))
    assert {c.corpus["verdict"] for c in cands} == {"not_reached"}


@pytest.mark.unit
@pytest.mark.parametrize(
    "verdict",
    [
        {"status": "compile_error", "reason": "e-acsl failed"},
        {"status": "code_fault", "failure": {"label": "rte/mem_access", "predicate": "\\valid_read(buf + i)"}},
        {"status": "rejected_overconstrained", "failure": {"label": "valid_buf", "predicate": "len > 0"}},
        {"status": "sandbox_unavailable", "reason": "no sandbox"},
    ],
)
def test_a_replay_that_stops_elsewhere_tests_nothing(tmp_path: Path, verdict) -> None:
    cands = ls.generate_candidates(_sum_int_record(), SUM_INT)
    summary = ls.corpus_filter(SUM_INT, "sum_int", tmp_path / "sum.c", cands, FakeGuard([verdict]))
    assert summary["status"] == "incomplete" and summary["reason"].startswith(verdict["status"])
    assert {c.corpus["verdict"] for c in cands} == {"not_tested"}


@pytest.mark.unit
def test_corpus_rounds_are_bounded(tmp_path: Path) -> None:
    cands = ls.generate_candidates(_sum_int_record(), SUM_INT)
    guard = FakeGuard([_rejected("seed_1"), _rejected("seed_2")])
    summary = ls.corpus_filter(SUM_INT, "sum_int", tmp_path / "sum.c", cands, guard, max_rounds=2)
    assert summary["status"] == "round_limit"
    assert [c.corpus["verdict"] for c in cands] == ["falsified", "falsified", "not_tested"]


# ---------------------------------------------------------------------------
# The report
# ---------------------------------------------------------------------------


def _compute(tmp_path, wp, guard, record=None, text=SUM_INT):
    src = tmp_path / "work" / "sum.c"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text(text, encoding="utf-8")
    record = _sum_int_record() if record is None else record
    report = ls.compute(src, "sum_int", record, wp, guard, tmp_path / "copy", module="m")
    assert src.read_text(encoding="utf-8") == text  # the prover's file is never touched
    return report


@pytest.mark.unit
def test_report_labels_proven_and_corpus_only_seeds(tmp_path: Path) -> None:
    wp = FakeWp([{"seed_2": ["established"]}, {}])
    guard = FakeGuard([_passed()])
    report = _compute(tmp_path, wp, guard)
    assert report["status"] == "ok" and report["schema"] == ls.SEEDS_SCHEMA and "decides nothing" in report["note"]
    assert [(c["name"], c["label"]) for c in report["candidates"]] == [
        ("seed_1", "proven_inductive"),
        ("seed_2", "held_on_corpus_unproven"),
        ("seed_3", "proven_inductive"),
    ]
    assert report["proven"] == ["seed_1", "seed_3"] and report["held_on_corpus_unproven"] == ["seed_2"]
    # Only what WP dropped is replayed.
    assert "seed_2" in guard.texts[0] and "seed_1" not in guard.texts[0]
    json.dumps(report)
    shown = ls.render(report)
    assert "### Loop at L7 `for (i = 0; i < len; i++)`" in shown
    assert "**Proven inductive under the current contract" in shown
    assert "```c\nloop invariant seed_1: 0 <= i;\nloop invariant seed_3: 0 <= len ==> i <= len;\n```" in shown
    assert "**Held on every replayed corpus input (5 of 5), NOT proven**" in shown
    assert "- `loop invariant seed_2: i <= len;` WP: establishment failed." in shown
    assert "requires" in shown


@pytest.mark.unit
def test_a_guarded_form_is_redundant_beside_its_proven_strong_form(tmp_path: Path) -> None:
    guard = FakeGuard([])
    report = _compute(tmp_path, FakeWp([{}]), guard)
    assert [c["label"] for c in report["candidates"]] == ["proven_inductive", "proven_inductive", "redundant"]
    assert report["corpus"]["status"] == "not_needed" and guard.texts == []
    assert "0 <= len ==>" not in ls.render(report)


@pytest.mark.unit
def test_falsified_and_unreplayed_candidates_are_listed_as_dropped(tmp_path: Path) -> None:
    wp = FakeWp([{"seed_2": ["preserved"], "seed_3": ["preserved"]}, {}])
    report = _compute(tmp_path, wp, FakeGuard([_rejected("seed_2"), _passed()]))
    assert [c["label"] for c in report["candidates"]] == ["proven_inductive", "dropped", "held_on_corpus_unproven"]
    shown = ls.render(report)
    assert (
        "**Dropped** (do not write these):" in shown and "- `i <= len`: preservation failed; false on corpus" in shown
    )
    without_corpus = _compute(tmp_path, FakeWp([{"seed_2": ["preserved"]}, {}]), None)
    assert without_corpus["corpus"]["status"] == "skipped"
    assert without_corpus["candidates"][1]["label"] == "dropped"
    assert without_corpus["candidates"][1]["corpus"] == {"verdict": "not_run"}


@pytest.mark.unit
def test_a_failed_wp_filter_only_loses_hints(tmp_path: Path) -> None:
    report = _compute(tmp_path, FakeWp([{"result": {"status": "analysis_error", "reason": "oom_killed"}}]), None)
    assert report["status"] == "partial" and "oom_killed" in report["reason"]
    assert report["proven"] == [] and {c["label"] for c in report["candidates"]} == {"undecided"}
    shown = ls.render(report)
    assert "**Not decided**" in shown and "Proven inductive" not in shown


@pytest.mark.unit
def test_nothing_to_seed_is_reported_not_raised(tmp_path: Path) -> None:
    def never(*_args):
        raise AssertionError("no tool may run")

    assert _compute(tmp_path, never, None, record={**_sum_int_record(), "loops": []})["status"] == "no_loops"
    plain = {**_sum_int_record(), "loops": [_loop(7, None, [("acc", ["acc * 3"])])]}
    report = _compute(tmp_path, never, None, record=plain)
    assert report["status"] == "no_candidates" and "No seed for this function" in ls.render(report)
    assert ls.compute(tmp_path / "missing.c", "f", _sum_int_record(), never, None, tmp_path / "c")["status"] == "error"
    assert ls.compute(tmp_path / "missing.c", "f", None, never, None, tmp_path / "c")["status"] == "no_facts"


# ---------------------------------------------------------------------------
# Flag, CLI, brief, scheduler
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_flag_is_off_by_default_and_follows_the_context_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ff.LOOP_SEEDS_ENV, raising=False)
    monkeypatch.delenv(ff.CONTEXT_ENV, raising=False)
    assert ff.loop_seeds_enabled() is False
    for value in ("on", "1", "TRUE", " yes "):
        monkeypatch.setenv(ff.LOOP_SEEDS_ENV, value)
        assert ff.loop_seeds_enabled() is True
    for value in ("off", "0", "", "maybe"):
        monkeypatch.setenv(ff.LOOP_SEEDS_ENV, value)
        assert ff.loop_seeds_enabled() is False
    monkeypatch.setenv(ff.LOOP_SEEDS_ENV, "on")
    monkeypatch.setenv(ff.CONTEXT_ENV, "off")
    assert ff.loop_seeds_enabled() is False


@pytest.mark.unit
def test_cli_is_inert_when_the_flag_is_off(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    monkeypatch.delenv(ff.LOOP_SEEDS_ENV, raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "sum.c").write_text(SUM_INT, encoding="utf-8")
    monkeypatch.setattr(ls, "default_wp_runner", lambda *a, **k: pytest.fail("WP must not run"))
    assert ls.main(["--file", "sum.c", "--function", "sum_int", "--module", "m"]) == 0
    report = json.loads((tmp_path / ls.REPORT_DIR / "m" / "sum_int.json").read_text(encoding="utf-8"))
    assert report["status"] == "disabled" and report["candidates"] == []
    assert "status: disabled" in capsys.readouterr().out


@pytest.mark.unit
def test_cli_finds_facts_runs_the_filters_and_writes_the_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setenv(ff.LOOP_SEEDS_ENV, "on")
    monkeypatch.delenv(ff.CONTEXT_ENV, raising=False)
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "agents" / "p1" / "scratch" / "work" / "src" / "sum.c"
    src.parent.mkdir(parents=True)
    src.write_text(SUM_INT, encoding="utf-8")
    facts = tmp_path / "workspace" / "reports" / "facts" / "harness_unit.json"
    facts.parent.mkdir(parents=True)
    record = {**_sum_int_record(), "file": "src/sum.c"}
    facts.write_text(
        json.dumps({"schema": ff.FACTS_SCHEMA, "functions": {"src/sum.c#sum_int": record}}), encoding="utf-8"
    )
    wp = FakeWp([{"seed_2": ["established"]}, {}])
    seen: dict = {}

    def fake_wp_runner(orig, cppflags, out_dir, deadline):
        seen.update(orig=orig, cppflags=cppflags, out_dir=out_dir, deadline=deadline)
        return wp

    monkeypatch.setattr(ls, "default_wp_runner", fake_wp_runner)
    monkeypatch.setattr(ls, "default_full_runner", lambda orig, cppflags, out_dir, deadline: FakeFull([[], []]))
    out_json = tmp_path / "agents" / "p1" / "scratch" / "loop_seeds_sum_int.json"
    rc = ls.main(
        [
            "--file",
            "agents/p1/scratch/work/src/sum.c",
            "--function",
            "sum_int",
            "--module",
            "unit",  # the facts are filed under another name: any facts report naming the function serves
            "--cppflags",
            "-Iagents/p1/scratch/work -I.",
            "--out-json",
            str(out_json),
        ]
    )
    assert rc == 0
    report = json.loads(out_json.read_text(encoding="utf-8"))
    assert report["status"] == "ok" and report["proven"] == ["seed_1", "seed_3"]
    assert report["corpus"]["status"] == "skipped"  # no --sources, no --corpus-dir
    assert seen["cppflags"] == "-Iagents/p1/scratch/work -I." and seen["deadline"] is not None
    # The copy lives outside the agent's tree and is gone afterwards.
    assert "agents" not in Path(seen["out_dir"]).parts and not Path(seen["out_dir"]).exists()
    assert sorted(p.name for p in src.parent.iterdir()) == ["sum.c"]
    out = capsys.readouterr().out
    assert out.startswith("## Loop invariant seeds for `sum_int` (status: ok)")
    assert "loop invariant seed_1: 0 <= i;" in out


@pytest.mark.unit
def test_cli_survives_a_crashing_tool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    monkeypatch.setenv(ff.LOOP_SEEDS_ENV, "on")
    monkeypatch.delenv(ff.CONTEXT_ENV, raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "sum.c").write_text(SUM_INT, encoding="utf-8")
    monkeypatch.setattr(ls, "find_facts", lambda *a: _sum_int_record())

    def boom(*_a, **_k):
        def run(*_x):
            raise RuntimeError("prover exploded")

        return run

    monkeypatch.setattr(ls, "default_wp_runner", boom)
    assert ls.main(["--file", "sum.c", "--function", "sum_int", "--out-json", "r.json", "--json"]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["status"] == "error" and "prover exploded" in printed["reason"]
    assert json.loads((tmp_path / "r.json").read_text(encoding="utf-8")) == printed


@pytest.mark.unit
def test_wp_runner_adds_the_original_directory_and_restricts_to_the_seed_goals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import run_wp_function

    seen: dict = {}

    def fake_run(**kwargs):
        seen.update(kwargs)
        out_dir = kwargs["out_dir"]
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "wp_f.log").write_text("[wp] [Unknown] typed_f_loop_invariant_seed_2_preserved\n", encoding="utf-8")
        return {"status": "unproven_goals_remain"}

    monkeypatch.setattr(run_wp_function, "run_wp_on_function", fake_run)
    monkeypatch.setattr(run_wp_function, "default_wall_timeout", lambda _cli: 3600)
    runner = ls.default_wp_runner(Path("agents/p1/scratch/work/src/f.c"), "-I.", tmp_path / "wp", None)
    out = runner(tmp_path / "copy" / "f.c", "f", ["seed_1", "seed_2"])
    assert (
        out["result"] == {"status": "unproven_goals_remain"} and "seed_2_preserved" in out["log"] and out["rows"] == []
    )
    assert seen["prop"] == "seed_1,seed_2" and seen["cppflags"] == "-Iagents/p1/scratch/work/src -I."
    assert seen["timeout"] == ls.WP_GOAL_TIMEOUT_S and seen["wall_timeout"] == 3600
    # Hints must not use up the prover's own WP budget, and one run is one run.
    assert seen["ignore_prover_budget"] is True
    assert (seen["retry_bitwise"], seen["retry_tail"], seen["retry_cast_probe"]) == (False, False, False)
    assert "wp_par" not in seen  # sized by run_wp_function from the job's budget


@pytest.mark.unit
def test_guard_runner_needs_the_file_among_the_sources(tmp_path: Path) -> None:
    src = tmp_path / "a.c"
    src.write_text("int a;\n", encoding="utf-8")
    assert ls.default_guard_runner(src, [str(tmp_path / "b.c")], "-I.", "", tmp_path, "m", tmp_path / "o") is None
    assert ls.default_guard_runner(src, [str(src), "h.c"], "-I.", "", tmp_path, "m", tmp_path / "o") is not None


def _features(**on) -> dict[str, bool]:
    return {"loops": False, "pointer_walk": False, "structs": False, "recursion": False, **on}


@pytest.mark.unit
def test_brief_shows_the_seed_step_only_with_the_flag_and_a_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    marker = "scripts/loop_seeds.py --file agents/{agent_id}/scratch/work/{c_file}"
    assert BRIEF.count(marker) == 1
    monkeypatch.delenv(ff.CONTEXT_ENV, raising=False)
    monkeypatch.delenv(ff.LOOP_SEEDS_ENV, raising=False)
    assert marker not in ff.render_conditionals(BRIEF, _features(loops=True))
    assert marker not in ff.render_conditionals(BRIEF, None)
    monkeypatch.setenv(ff.LOOP_SEEDS_ENV, "on")
    with_loop = ff.render_conditionals(BRIEF, _features(loops=True))
    assert marker in with_loop
    for rule in (
        "Never add or strengthen a `requires` to make a seed hold.",
        "Drop a seed that stops proving",
        '"Proven inductive"',
        "NOT proven",
    ):
        assert rule in with_loop
    assert with_loop.index(marker) < with_loop.index("1. For every loop in `{function_name}`")
    assert marker not in ff.render_conditionals(BRIEF, _features(loops=False))
    assert marker not in ff.render_conditionals(BRIEF, None)  # no facts: nothing to seed from
    monkeypatch.setenv(ff.CONTEXT_ENV, "off")
    assert marker not in ff.render_conditionals(BRIEF, None)
    assert marker not in ff.render_conditionals(BRIEF, _features(loops=True))


@pytest.mark.unit
def test_brief_command_uses_only_placeholders_the_scheduler_fills() -> None:
    start = BRIEF.index("python3 /opt/framac-pipeline/scripts/loop_seeds.py")
    command = BRIEF[start : BRIEF.index("\n", start)]
    placeholders = set(__import__("re").findall(r"\{(\w+)\}", command))
    assert placeholders == {
        "agent_id",
        "c_file",
        "function_name",
        "harness_module_name",
        "scratch_cppflags",
        "ldflags",
        "scratch_module_sources",
    }
    assert all(wp_scheduler._PLACEHOLDER_RE.fullmatch("{" + name + "}") for name in placeholders)
    parser_args = (
        "--file",
        "--function",
        "--module",
        "--cppflags",
        "--ldflags",
        "--sources",
        "--corpus-dir",
        "--out-json",
    )
    assert all(arg in command for arg in parser_args)


@pytest.mark.unit
def test_scheduler_copies_the_provers_report_to_the_run_reports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(ff.CONTEXT_ENV, raising=False)
    monkeypatch.setenv(ff.LOOP_SEEDS_ENV, "on")
    task = {"function": "sum_int", "file": "src/sum.c", "module": "m"}
    scratch = tmp_path / "agents" / "p1" / "scratch"
    scratch.mkdir(parents=True)
    errors: list = []
    assert wp_scheduler._promote_loop_seeds(task, "p1", errors) is None  # no report: nothing to do
    report = {"schema": 1, "status": "ok", "function": "sum_int", "file": "agents/p1/scratch/work/src/sum.c"}
    src = scratch / "loop_seeds_sum_int.json"
    src.write_text(json.dumps({**report, "candidates": [], "proven": ["seed_1"]}), encoding="utf-8")
    dest = wp_scheduler._promote_loop_seeds(task, "p1", errors)
    assert dest == "workspace/reports/loop_seeds/m/sum_int.json" and errors == []
    copied = json.loads((tmp_path / dest).read_text(encoding="utf-8"))
    assert (
        copied["file"] == "src/sum.c" and copied["agent_file"].startswith("agents/p1/") and copied["agent_id"] == "p1"
    )
    assert copied["proven"] == ["seed_1"]
    # Another function's report, a malformed one, or the flag off: not copied.
    (tmp_path / dest).unlink()
    src.write_text(json.dumps({**report, "function": "other", "candidates": []}), encoding="utf-8")
    assert wp_scheduler._promote_loop_seeds(task, "p1", errors) is None
    src.write_text("{not json", encoding="utf-8")
    assert wp_scheduler._promote_loop_seeds(task, "p1", errors) is None
    src.write_text(json.dumps({**report, "candidates": []}), encoding="utf-8")
    monkeypatch.setenv(ff.LOOP_SEEDS_ENV, "off")
    assert wp_scheduler._promote_loop_seeds(task, "p1", errors) is None
    assert not (tmp_path / dest).exists()


@pytest.mark.unit
def test_report_path_never_leaves_the_reports_directory() -> None:
    assert ls.default_out_json("m", "f").as_posix() == "workspace/reports/loop_seeds/m/f.json"
    assert ls.default_out_json(None, "f").as_posix() == "workspace/reports/loop_seeds/_/f.json"
    assert ls.default_out_json("../../etc", "a/b").as_posix() == "workspace/reports/loop_seeds/_.._etc/a_b.json"


# ------------------------------------------------------------------ no-harm check


class FakeFull:
    """Full WP runs decided by a table: per run, the unproven goals as (kind, annotation, line)."""

    def __init__(self, runs, status=None):
        self.runs = list(runs)
        self.status = status
        self.seeds: list[list[str]] = []

    def __call__(self, copy: Path, function: str) -> dict:
        text = copy.read_text(encoding="utf-8")
        self.seeds.append(ls._SEED_CLAUSE_RE.findall(text))
        goals = self.runs.pop(0)
        if isinstance(goals, dict):
            return goals
        return {
            "status": self.status or ("unproven_goals_remain" if goals else "all_proven"),
            "unproven_goals": [{"kind": k, "annotation": a, "line": line} for k, a, line in goals],
        }


TERMINATION = ("termination clause", "\\true", 1)
MEM = ("mem_access", "\\valid_read(buf + i)", 9)


def _proven_names(report: dict, label: str = "proven_inductive") -> list[str]:
    return [c["name"] for c in report["candidates"] if c["label"] == label]


@pytest.mark.unit
def test_no_harm_keeps_the_seeds_when_wp_loses_no_goal(tmp_path: Path) -> None:
    full = FakeFull([[TERMINATION, MEM], [TERMINATION]])
    src = tmp_path / "sum.c"
    src.write_text(SUM_INT, encoding="utf-8")
    report = ls.compute(src, "sum_int", _sum_int_record(), FakeWp([{}]), None, tmp_path / "c", run_full=full)
    assert report["no_harm"]["status"] == "ok" and report["no_harm"]["newly_proved"] == 1
    assert report["no_harm"]["baseline_unproven"] == 2 and report["no_harm"]["lost"] == []
    assert full.seeds[0] == [] and full.seeds[1] == report["proven"] != []
    assert "loses no goal" in ls.render(report) and "proves 1 more" in ls.render(report)


@pytest.mark.unit
def test_no_harm_withholds_the_one_seed_whose_removal_restores_the_goal(tmp_path: Path) -> None:
    src = tmp_path / "sum.c"
    src.write_text(SUM_INT, encoding="utf-8")
    # Baseline, all seeds (loses MEM), without the first seed (still lost), without the second (restored).
    full = FakeFull([[TERMINATION], [TERMINATION, MEM], [TERMINATION, MEM], [TERMINATION]])
    report = ls.compute(src, "sum_int", _sum_int_record(), FakeWp([{}]), None, tmp_path / "c", run_full=full)
    check = report["no_harm"]
    assert check["status"] == "one_withheld" and [g["kind"] for g in check["lost"]] == ["mem_access"]
    all_seeds = full.seeds[1]
    assert full.seeds[2] == all_seeds[1:] and full.seeds[3] == [all_seeds[0], *all_seeds[2:]]
    assert _proven_names(report, "proven_withheld") == [all_seeds[1]]
    assert all_seeds[1] not in report["proven"] and all_seeds[0] in report["proven"]
    text = ls.render(report)
    assert "Proven, but withheld" in text and "mem_access" in text


@pytest.mark.unit
def test_no_harm_withholds_everything_when_no_single_removal_helps(tmp_path: Path) -> None:
    src = tmp_path / "sum.c"
    src.write_text(SUM_INT, encoding="utf-8")
    full = FakeFull([[TERMINATION]] + [[TERMINATION, MEM]] * 10)
    report = ls.compute(src, "sum_int", _sum_int_record(), FakeWp([{}]), None, tmp_path / "c", run_full=full)
    assert report["no_harm"]["status"] == "all_withheld" and report["proven"] == []
    assert len(report["no_harm"]["runs"]) <= 1 + ls.MAX_NO_HARM_RUNS
    assert _proven_names(report, "proven_withheld") != []


@pytest.mark.unit
def test_no_harm_that_cannot_run_withholds_nothing_and_says_so(tmp_path: Path) -> None:
    src = tmp_path / "sum.c"
    src.write_text(SUM_INT, encoding="utf-8")
    failed = FakeFull([{"status": "analysis_error", "reason": "timeout"}])
    report = ls.compute(src, "sum_int", _sum_int_record(), FakeWp([{}]), None, tmp_path / "c", run_full=failed)
    assert report["no_harm"]["status"] == "skipped" and "timeout" in report["no_harm"]["reason"]
    assert report["proven"] != [] and "were not checked" in ls.render(report)
    none = ls.compute(src, "sum_int", _sum_int_record(), FakeWp([{}]), None, tmp_path / "c2")
    assert none["no_harm"]["status"] == "skipped"
    late = ls.compute(
        src, "sum_int", _sum_int_record(), FakeWp([{}]), None, tmp_path / "c3", run_full=FakeFull([]), deadline=0.0
    )
    assert late["no_harm"]["status"] in ("skipped", "not_needed")


@pytest.mark.unit
def test_kernel_error_line_rejects_prefix_overlapping_filename() -> None:
    result = {
        "syntax_check": {
            "errors": ["[kernel] not_sum.c:9: User Error: boom", "prefix_sum.c:10: error", "other-sum.c:12: error"]
        }
    }
    assert ls._kernel_error_line(result, "sum.c") is None
    result_match = {"syntax_check": {"errors": ["[kernel] sum.c:9: User Error: boom"]}}
    assert ls._kernel_error_line(result_match, "sum.c") == 9
    result_dir = {"syntax_check": {"errors": ["[kernel] dir/sum.c:9: error"]}}
    assert ls._kernel_error_line(result_dir, "sum.c") == 9
    result_rel = {"syntax_check": {"errors": ["[kernel] ./sum.c:9: error"]}}
    assert ls._kernel_error_line(result_rel, "sum.c") == 9
    result_abs = {"syntax_check": {"errors": ["[kernel] /abs/path/sum.c:9: User Error: boom"]}}
    assert ls._kernel_error_line(result_abs, "sum.c") == 9
    result_ws = {"syntax_check": {"errors": ["[kernel] workspace/work/sum.c:9: error"]}}
    assert ls._kernel_error_line(result_ws, "sum.c") == 9
    result_dir_overlap = {"syntax_check": {"errors": ["[kernel] dir/not_sum.c:9: error", "dir/prefix_sum.c:10: error"]}}
    assert ls._kernel_error_line(result_dir_overlap, "sum.c") is None
