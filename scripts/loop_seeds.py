#!/usr/bin/env python3
"""
Loop invariant seeds for Function Prover subagents (stdlib only).

Eva does not hold the index-against-length relation at a widened loop head (measured, see
docs/plans/papers-generalization-plan.md, Tier 1), so the candidates come from the loop facts instead
(function_facts.py) and two oracles filter them:

  1. Syntactic candidates over the function's own formals and locals: `0 <= i` for a signed
     counter, `i <= bound` for each header condition that compares a counter with an operand the
     loop does not write, and for a pointer walker its anchor on the formal it starts from
     (`\\at(p, Pre) <= p`, same base) and its end bound. A literal bound is kept only
     when the literal is written in the function's source: a bound that exists only in a harness
     never becomes a candidate.
  2. Houdini with WP: every candidate is inserted as `loop invariant seed_<n>: ...;` in a scratch
     copy and only the seed goals are proved (`-wp-prop`). A candidate WP cannot establish or
     preserve is dropped and the rest is proved again, until a round drops nothing. Survivors are
     inductive under the function's current contract and loop annotations.
  3. Corpus filter: the candidates WP dropped are compiled as E-ACSL checks (the guardrail build
     and replay of run_eacsl_fuzz.py) and the Phase 1 corpus is replayed. An input that falsifies a
     candidate is recorded with it; a candidate no input falsifies is reported as "held on every
     replayed corpus input, not proven", which is a hint and nothing more.

WP runs first because a WP round on the seed goals alone costs about a second when nothing fails,
and a proven candidate needs no corpus check; the E-ACSL build is paid only for what WP dropped.

The tool decides nothing: it never writes the ledger, the work tree or a contract, and it never
adds a `requires`. A failure or a timeout only loses hints, and `status` in the report says so.

CLI (a prover runs it from the run directory, on its scratch overlay):
  loop_seeds.py --file agents/<id>/scratch/work/<c_file> --function f --module M \\
      --cppflags='<flags>' --sources <module sources> workspace/harnesses/harness_M.c \\
      --corpus-dir workspace/corpus/M --out-json agents/<id>/scratch/loop_seeds_f.json

It prints the surviving clauses ready to paste. Without --out-json the report goes to
workspace/reports/loop_seeds/<module>/<function>.json, where the scheduler also copies a prover's
report when the prover completes.

Gated by FRAMAC_LOOP_SEEDS=on (function_facts.loop_seeds_enabled; FRAMAC_PROVER_CONTEXT=off turns
it off too). Default: off.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import function_facts  # noqa: E402
from acsl_ast import AcslSyntaxError, locate_function_span, tokenize_c_acsl  # noqa: E402
from framac_common import (  # noqa: E402
    STATUS_VALID,
    STATUS_VALID_UNDER_HYP,
    atomic_write_json,
    normalize_flag_args,
    read_report_csv,
    utc_now,
)

SEEDS_SCHEMA = 1
REPORT_DIR = "workspace/reports/loop_seeds"
SEED_PREFIX = "seed_"
NOTE = "Hints for a prover. This report decides nothing about a unit's status."

# How much one function may ask of the oracles. These bound the work, they do not size it:
# concurrency and wall-clock limits come from resources.py through run_wp_function.py.
MAX_CANDIDATES_PER_LOOP = 10
MAX_CANDIDATES = 24
MAX_WP_ROUNDS = 6
MAX_CORPUS_ROUNDS = 4
# Seeded full-WP runs of the no-harm check: the whole proven set, then leave-one-out on the loop a
# lost goal sits in. Past this, every seed is withheld (the function is then as it was).
MAX_NO_HARM_RUNS = 4
# Per goal and per prover, fixed whatever the machine. Shorter than run_wp_function.py's default of 15 s:
# a seed that proves does so in milliseconds (measured), and a seed lost to this limit is only a lost hint,
# while every false candidate costs the whole limit.
WP_GOAL_TIMEOUT_S = 5

_AT = "\\at"
_BASE_ADDR = "\\base_addr"
_LOOP_KEYWORDS = frozenset({"for", "while", "do"})
_IDENT = r"[A-Za-z_]\w*"
_PATH_RE = re.compile(rf"{_IDENT}(?:\s*(?:\.|->)\s*{_IDENT})*")
_INT_RE = re.compile(r"(0[xX][0-9a-fA-F]+|\d+)([uUlL]*)(?![\w.])")
_CAST_RE = re.compile(rf"\(\s*{_IDENT}(?:\s+{_IDENT})*\s*\**\s*\)")
_UNSIGNED_TYPE_RE = re.compile(r"\bunsigned\b|\bsize_t\b|\buint\w*_t\b|\buintptr_t\b|\b_Bool\b")
_C_INT_TOKEN_RE = re.compile(r"^(0[xX][0-9a-fA-F]+|\d+)[uUlL]*$")
_SEED_NAME_RE = re.compile(rf"\b{SEED_PREFIX}(\d+)\b")
_SEED_CLAUSE_RE = re.compile(rf"loop\s+invariant\s+({SEED_PREFIX}\d+)\s*:")
_INVARIANT_RE = re.compile(rf"loop\s+invariant\s+(?:{_IDENT}\s*:\s*)*([^;]+);")
_LOOP_CLAUSE_RE = re.compile(r"\bloop\s+(?:invariant|assigns|variant|allocates|frees)\b")
_WP_FAIL_RE = re.compile(
    rf"^\[wp\]\s*\[(?:Timeout|Unknown|Failed|Stepout|NoResult)\][^\n]*loop_invariant_({SEED_PREFIX}\d+)_"
    r"(established|preserved)",
    re.IGNORECASE | re.MULTILINE,
)
_NEGATED = {"<": ">=", "<=": ">", ">": "<=", ">=": "<", "!=": "==", "==": "!="}
_MIRRORED = {"<": ">", "<=": ">=", ">": "<", ">=": "<=", "!=": "!=", "==": "=="}


# ---------------------------------------------------------------------------
# Candidates from the loop facts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Operand:
    """One side of a loop condition, in the kernel's normalized C: `[cast] atom [(+|-) [cast] atom]`."""

    text: str
    paths: tuple[str, ...]
    literals: tuple[int, ...]
    memory: bool
    var: str | None  # the identifier, when the operand is one identifier (possibly cast)


@dataclass
class Candidate:
    name: str
    loop_index: int
    loop_line: int
    predicate: str
    template: str
    weaker_of: str | None = None  # the predicate this one only relaxes
    wp: dict = field(default_factory=lambda: {"verdict": "not_run"})
    corpus: dict = field(default_factory=lambda: {"verdict": "not_run"})


def _strip_outer_parens(text: str) -> str:
    text = text.strip()
    while text.startswith("(") and text.endswith(")"):
        depth = 0
        for pos, ch in enumerate(text):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and pos != len(text) - 1:
                    return text
        text = text[1:-1].strip()
    return text


def _parse_term(text: str, pos: int) -> tuple[int, str, str | None, int | None, bool] | None:
    """(end, text, path, literal, cast) of `[cast] (path | integer)` at `pos`, or None."""
    while pos < len(text) and text[pos].isspace():
        pos += 1
    cast = ""
    m_cast = _CAST_RE.match(text, pos)
    if m_cast:
        after = m_cast.end()
        while after < len(text) and text[after].isspace():
            after += 1
        # `(n)` alone is a parenthesized identifier, a cast only when a term follows it.
        if after < len(text) and (text[after].isalnum() or text[after] == "_"):
            cast = "(" + " ".join(m_cast.group(0)[1:-1].split()) + ")"
            pos = after
    m_int = _INT_RE.match(text, pos)
    if m_int:
        return m_int.end(), cast + m_int.group(1), None, int(m_int.group(1), 0), bool(cast)
    m_path = _PATH_RE.match(text, pos)
    if m_path:
        path = re.sub(r"\s+", "", m_path.group(0))
        return m_path.end(), cast + path, path, None, bool(cast)
    return None


def parse_operand(text: str) -> Operand | None:
    """A condition operand simple enough to restate in ACSL unchanged; anything else is None."""
    text = _strip_outer_parens(text)
    first = _parse_term(text, 0)
    if first is None:
        return None
    pos, shown, path, literal, _cast = first
    paths = [path] if path else []
    literals = [literal] if literal is not None else []
    rest = text[pos:].strip()
    single = not rest
    if rest:
        if rest[0] not in "+-":
            return None
        second = _parse_term(rest, 1)
        if second is None or rest[second[0] :].strip():
            return None
        shown = f"{shown} {rest[0]} {second[1]}"
        if second[2]:
            paths.append(second[2])
        if second[3] is not None:
            literals.append(second[3])
    plain = single and path is not None and re.fullmatch(_IDENT, path) is not None
    return Operand(
        text=shown,
        paths=tuple(paths),
        literals=tuple(literals),
        memory=any("." in p or "->" in p for p in paths),
        var=path if plain else None,
    )


def parse_condition(text: str | None) -> tuple[str, str, str] | None:
    """(lhs, op, rhs) of one comparison, `!(a op b)` included; None for anything else."""
    if not text:
        return None
    text = _strip_outer_parens(text)
    if text.startswith("!"):
        inner = text[1:].strip()
        if not (inner.startswith("(") and _strip_outer_parens(inner) != inner):
            return None
        parsed = parse_condition(inner)
        return (parsed[0], _NEGATED[parsed[1]], parsed[2]) if parsed else None
    depth = 0
    found: tuple[int, str] | None = None
    pos = 0
    while pos < len(text):
        ch = text[pos]
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif depth == 0:
            two = text[pos : pos + 2]
            if two == "->":
                pos += 2
                continue
            if two in ("<<", ">>", "&&", "||"):
                return None
            op = two if two in ("<=", ">=", "!=", "==") else ch if ch in "<>" else None
            if op is None and ch in "=!&|?,":
                return None
            if op is not None:
                if found is not None:
                    return None
                found = (pos, op)
                pos += len(op)
                continue
        pos += 1
    if found is None:
        return None
    lhs, rhs = text[: found[0]].strip(), text[found[0] + len(found[1]) :].strip()
    return (lhs, found[1], rhs) if lhs and rhs else None


def _continue_conditions(loop: dict) -> list[tuple[str, str, str]]:
    """What holds whenever the loop goes on: its guard, and the negated breaks of its header."""
    out: list[tuple[str, str, str]] = []
    guard = parse_condition(loop.get("guard"))
    if guard:
        out.append(guard)
    for item in loop.get("exits") or []:
        # `a && b` in a header is normalized to breaks on the header's line; a break further down
        # is taken in the middle of an iteration and says nothing about the loop head.
        if item.get("kind") != "break" or item.get("line") != loop.get("line"):
            continue
        parsed = parse_condition(item.get("condition"))
        if parsed:
            out.append((parsed[0], _NEGATED[parsed[1]], parsed[2]))
    return [c for c in out if c[1] != "=="]


def _steps(loop: dict) -> dict[str, dict]:
    """Counter-like scalars of a loop: every self-referential update is `v + k` or `v - k`."""
    out: dict[str, dict] = {}
    for scalar in loop.get("scalars") or []:
        var = scalar.get("var") or ""
        if not re.fullmatch(_IDENT, var):
            continue
        step_re = re.compile(rf"^{re.escape(var)}\s*([+-])\s*(\([^()]*\)\s*)?(?:0[xX][0-9a-fA-F]+|\d+)([uUlL]*)$")
        directions: set[str] = set()
        unsigned = False
        counter = True
        for update in scalar.get("updates") or []:
            if not re.search(rf"\b{re.escape(var)}\b", update):
                continue  # a reset (`c = 0` in an outer loop): WP decides what survives it
            m = step_re.match(update.strip())
            if not m:
                counter = False
                break
            directions.add("up" if m.group(1) == "+" else "down")
            unsigned = unsigned or "u" in m.group(3).lower() or bool(_UNSIGNED_TYPE_RE.search(m.group(2) or ""))
        if counter and directions:
            out[var] = {"direction": directions.pop() if len(directions) == 1 else None, "unsigned": unsigned}
    return out


def source_literals(span_text: str, path: str = "<input>") -> set[int]:
    """Integer literals written in the function's own C tokens (comments and annotations excluded)."""
    try:
        tokens = tokenize_c_acsl(span_text, path=path)
    except AcslSyntaxError:
        return set()
    out: set[int] = set()
    for tok in tokens:
        m = _C_INT_TOKEN_RE.match(tok.text) if tok.kind == "c_token" else None
        if m:
            out.add(int(m.group(1), 0))
    return out


def _existing_invariants(span_text: str) -> set[str]:
    return {re.sub(r"\s+", "", m.group(1)) for m in _INVARIANT_RE.finditer(span_text)}


def _next_seed_number(span_text: str) -> int:
    return max((int(m.group(1)) for m in _SEED_NAME_RE.finditer(span_text)), default=0) + 1


def _loop_candidates(loop: dict, record: dict, literals: set[int]) -> list[tuple[str, str, str | None]]:
    """(predicate, template, predicate it relaxes) for one loop, strongest forms first."""
    steps = _steps(loop)
    walkers = [w for w in loop.get("pointer_walkers") or [] if re.fullmatch(_IDENT, w)]
    formals = {f.get("name"): f for f in record.get("formals") or []}
    derived = record.get("derived_pointers") or {}
    written = {s.get("var") for s in loop.get("scalars") or []}
    writes_memory = bool(loop.get("memory_writes")) or bool(loop.get("calls"))
    out: list[tuple[str, str, str | None]] = []

    def unsigned(var: str) -> bool:
        formal = formals.get(var)
        return bool(steps.get(var, {}).get("unsigned")) or bool(
            formal and _UNSIGNED_TYPE_RE.search(str(formal.get("type") or ""))
        )

    def anchor(walker: str) -> str | None:
        root = walker if walker in formals else derived.get(walker)
        return f"{_AT}({root}, Pre)" if root and root in formals else None

    def stable(bound: Operand) -> bool:
        if function_facts._TEMP_RE.search(bound.text):
            return False
        if any(lit != 0 and lit not in literals for lit in bound.literals):
            return False  # a constant the source does not write: a macro's value, or a harness size
        if bound.memory and writes_memory:
            return False
        return not any(re.split(r"\.|->", p)[0] in written for p in bound.paths)

    for walker in walkers:
        base = anchor(walker)
        if base is None:
            continue
        if steps.get(walker, {}).get("direction") == "down":
            out.append((f"{walker} <= {base}", "walker_anchor", None))
        else:
            out.append((f"{base} <= {walker}", "walker_anchor", None))
        out.append((f"{_BASE_ADDR}({walker}) == {_BASE_ADDR}({base})", "walker_base", None))

    for counter in steps:
        if counter not in walkers and not unsigned(counter):
            out.append((f"0 <= {counter}", "counter_nonnegative", None))

    for lhs_text, op, rhs_text in _continue_conditions(loop):
        lhs, rhs = parse_operand(lhs_text), parse_operand(rhs_text)
        if lhs is None or rhs is None:
            continue
        if not (lhs.var and (lhs.var in steps or lhs.var in walkers)):
            lhs, rhs, op = rhs, lhs, _MIRRORED[op]
        if not lhs.var or not (lhs.var in steps or lhs.var in walkers) or not stable(rhs):
            continue
        var = lhs.var
        direction = steps.get(var, {}).get("direction")
        shown, bound = lhs.text, rhs.text
        base = anchor(var) if var in walkers else None
        upper = op == "<" or (op == "!=" and direction != "down")
        lower = op == ">" or (op == "!=" and direction != "up")
        if upper:
            strong = f"{shown} <= {bound}"
            out.append((strong, "guard_upper", None))
            if base is not None:
                out.append((f"{base} <= {bound} ==> {strong}", "guard_upper_guarded", strong))
            elif var not in walkers and not unsigned(var):
                # A signed bound can be negative at entry: `i <= len` then fails establishment.
                out.append((f"0 <= {bound} ==> {strong}", "guard_upper_guarded", strong))
        if lower:
            out.append((f"{bound} <= {shown}", "guard_lower", None))
        if op == "<=":
            out.append((f"{shown} <= {bound} + 1", "guard_upper", None))
        if op == ">=":
            out.append((f"{bound} <= {shown} + 1", "guard_lower", None))
    return out


def _inherited_candidates(
    loop: dict, by_index: dict, own: dict[int, list[tuple[str, str, str | None]]], literals: set[int]
) -> list[tuple[str, str, str | None]]:
    """
    What the enclosing loops know and this loop leaves alone, restated here. WP forgets everything an
    inner loop may assign, and a loop without `loop assigns` may assign everything: the outer loop's
    own candidates are preserved only if the inner loop carries them too (measured on a nested fill).
    """
    written = {s.get("var") for s in loop.get("scalars") or []}
    writes_memory = bool(loop.get("memory_writes")) or bool(loop.get("calls"))

    def untouched(predicate: str) -> bool:
        if writes_memory and ("->" in predicate or "." in predicate):
            return False
        return not (set(re.findall(_IDENT, predicate)) & written)

    out: list[tuple[str, str, str | None]] = []
    implied: set[str] = set()
    seen = {loop.get("index")}
    parent = loop.get("parent")
    while parent is not None and parent not in seen and parent in by_index:
        seen.add(parent)
        outer = by_index[parent]
        for lhs_text, op, rhs_text in _continue_conditions(outer):
            lhs, rhs = parse_operand(lhs_text), parse_operand(rhs_text)
            if lhs is None or rhs is None:
                continue
            if any(lit != 0 and lit not in literals for lit in (*lhs.literals, *rhs.literals)):
                continue
            predicate = f"{lhs.text} {op} {rhs.text}"
            if untouched(predicate) and not function_facts._TEMP_RE.search(predicate):
                out.append((predicate, "outer_guard", None))
                # The outer loop's own `a <= b` holds in its body as the strict guard: do not restate it.
                if op in ("<", ">"):
                    implied.add(re.sub(r"\s+", "", f"{lhs.text} {op}= {rhs.text}"))
                    implied.add(re.sub(r"\s+", "", f"{rhs.text} {_MIRRORED[op]}= {lhs.text}"))
        out += [
            (pred, "outer_restated", weaker)
            for pred, _t, weaker in own.get(parent, [])
            if untouched(pred) and re.sub(r"\s+", "", pred) not in implied
        ]
        parent = outer.get("parent")
    return out


def generate_candidates(record: dict, text: str, mapped: Callable[[int], int] | None = None) -> list[Candidate]:
    """Named candidates for every annotatable loop of the function `record` describes, in `text`."""
    name = record.get("name") or ""
    span = locate_function_span(text, name, is_header=False, path=record.get("file") or "<input>")
    span_text = span.text if span is not None else ""
    literals = source_literals(span_text)
    present = _existing_invariants(span_text)
    number = _next_seed_number(span_text)
    mapped = mapped or (lambda line: line)
    out: list[Candidate] = []
    loops = record.get("loops") or []
    by_index = {lp.get("index"): lp for lp in loops}
    own = {lp.get("index"): _loop_candidates(lp, record, literals) for lp in loops}
    for loop in loops:
        if loop.get("macro_expanded") or not isinstance(loop.get("line"), int):
            continue
        seen: set[str] = set()
        kept = 0
        for predicate, template, weaker_of in own[loop.get("index")] + _inherited_candidates(
            loop, by_index, own, literals
        ):
            key = re.sub(r"\s+", "", predicate)
            if key in seen or key in present:
                continue
            if kept >= MAX_CANDIDATES_PER_LOOP or len(out) >= MAX_CANDIDATES:
                break
            seen.add(key)
            kept += 1
            out.append(
                Candidate(
                    name=f"{SEED_PREFIX}{number}",
                    loop_index=int(loop.get("index") or 0),
                    loop_line=mapped(loop["line"]),
                    predicate=predicate,
                    template=template,
                    weaker_of=weaker_of,
                )
            )
            number += 1
    return out


# ---------------------------------------------------------------------------
# The scratch copy
# ---------------------------------------------------------------------------


def insert_seeds(
    text: str, seeds: list[Candidate], path: str = "<input>"
) -> tuple[str, dict[str, int], dict[int, str]]:
    """
    `text` with each seed as a named loop invariant of its loop: (new text, line of each seed,
    reason by loop line for the loops that cannot take an annotation).

    Frama-C accepts one annotation block per loop, so seeds join an existing block (first, since
    `loop invariant` comes before `loop assigns`) or get a block of their own.
    """
    by_line: dict[int, list[Candidate]] = {}
    for seed in seeds:
        by_line.setdefault(seed.loop_line, []).append(seed)
    try:
        tokens = tokenize_c_acsl(text, path=path)
    except AcslSyntaxError as exc:
        return text, {}, dict.fromkeys(by_line, f"source does not tokenize: {exc}")
    edits: list[tuple[int, str]] = []
    skipped: dict[int, str] = {}
    for line, group in by_line.items():
        on_line = [i for i, tok in enumerate(tokens) if tok.line == line and tok.kind == "c_token"]
        if not on_line or tokens[on_line[0]].text not in _LOOP_KEYWORDS:
            skipped[line] = "the loop keyword is not the first token of its line"
            continue
        idx = on_line[0]
        prev = idx - 1
        while prev >= 0 and tokens[prev].kind == "whitespace":
            prev -= 1
        clauses = "".join(f"loop invariant {seed.name}: {seed.predicate};\n" for seed in group)
        before = tokens[prev] if prev >= 0 else None
        if before is not None and before.kind == "acsl_line":
            skipped[line] = "a `//@` annotation precedes the loop"
        elif before is not None and before.kind == "acsl_block" and _LOOP_CLAUSE_RE.search(before.text):
            edits.append((before.start + len("/*@"), "\n" + clauses))
        elif before is not None and before.kind == "acsl_block":
            skipped[line] = "an annotation that is not a loop annotation precedes the loop"
        else:
            edits.append((tokens[idx].start, "/*@\n" + clauses + "*/\n"))
    for offset, addition in sorted(edits, reverse=True):
        text = text[:offset] + addition + text[offset:]
    lines: dict[str, int] = {}
    for number, content in enumerate(text.split("\n"), 1):
        m = _SEED_CLAUSE_RE.match(content.strip())
        if m:
            lines[m.group(1)] = number
    return text, lines, skipped


# ---------------------------------------------------------------------------
# Houdini with WP
# ---------------------------------------------------------------------------

# (scratch copy, function, seed names) -> {"result": run_wp_function's dict, "log": str, "rows": report rows}
WpRunner = Callable[[Path, str, list[str]], dict]
# (scratch copy, function) -> a guardrail verdict (run_eacsl_fuzz.run_guardrail_check), or a `compile_error`
GuardRunner = Callable[[Path, str], dict]


def _kernel_error_line(result: dict, file_name: str) -> int | None:
    errors = (result.get("syntax_check") or {}).get("errors") or []
    for message in errors:
        m = re.search(rf"(?<![\w.-]){re.escape(file_name)}:(\d+)", str(message))
        if m:
            return int(m.group(1))
    return None


def houdini(
    text: str,
    function: str,
    copy: Path,
    candidates: list[Candidate],
    run_wp: WpRunner,
    max_rounds: int = MAX_WP_ROUNDS,
    deadline: float | None = None,
) -> dict:
    """
    Drop every candidate WP cannot establish or preserve, until a round drops none. Sets each
    candidate's `wp` verdict; only a round without a drop makes the remaining ones `proven`.
    """
    alive = list(candidates)
    rounds: list[dict] = []
    summary: dict = {"status": "ok", "converged": False, "rounds": rounds}
    while alive:
        if len(rounds) >= max_rounds:
            summary["status"] = "round_limit"
            break
        if deadline is not None and time.monotonic() >= deadline:
            summary["status"] = "timeout"
            break
        seeded, lines, skipped = insert_seeds(text, alive, path=copy.name)
        for seed in [s for s in alive if s.name not in lines]:
            seed.wp = {"verdict": "not_placed", "reason": skipped.get(seed.loop_line, "not inserted")}
        alive = [s for s in alive if s.name in lines]
        if not alive:
            break
        copy.write_text(seeded, encoding="utf-8", newline="\n")
        started = time.monotonic()
        run = run_wp(copy, function, [s.name for s in alive])
        result = run.get("result") or {}
        entry: dict = {
            "round": len(rounds) + 1,
            "seconds": round(time.monotonic() - started, 1),
            "seeds": [s.name for s in alive],
            "wp_status": result.get("status"),
            "dropped": {},
        }
        rounds.append(entry)
        status = result.get("status")
        if status == "acsl_syntax_error":
            # The kernel refuses the whole file for one clause it cannot type: drop that clause.
            bad_line = _kernel_error_line(result, copy.name)
            bad = next((s for s in alive if lines[s.name] == bad_line), None)
            if bad is None:
                summary["status"] = "wp_failed"
                summary["reason"] = "acsl_syntax_error not located on a seed"
                break
            bad.wp = {"verdict": "dropped", "failed": ["rejected_by_kernel"], "round": entry["round"]}
            entry["dropped"][bad.name] = ["rejected_by_kernel"]
            alive.remove(bad)
            continue
        if status in ("analysis_error", "wp_aborted") or status is None:
            summary["status"] = "timeout" if result.get("reason") == "timeout" else "wp_failed"
            summary["reason"] = str(result.get("reason") or status)
            break
        failures: dict[str, set[str]] = {}
        for m in _WP_FAIL_RE.finditer(run.get("log") or ""):
            failures.setdefault(m.group(1), set()).add(m.group(2).lower())
        valid_lines = {
            row["line"]
            for row in run.get("rows") or []
            if "invariant" in str(row.get("kind") or "").lower()
            and (not row.get("function") or row.get("function") == function)
            and row.get("status") in (STATUS_VALID, STATUS_VALID_UNDER_HYP)
        }
        for seed in list(alive):
            failed = sorted(failures.get(seed.name, ()))
            if not failed and lines[seed.name] in valid_lines:
                continue
            # No report row or a row that is not valid: never read as proven, whatever the log shows.
            seed.wp = {"verdict": "dropped", "failed": failed or ["not_proven"], "round": entry["round"]}
            entry["dropped"][seed.name] = seed.wp["failed"]
            alive.remove(seed)
        if not entry["dropped"]:
            summary["converged"] = True
            break
    verdict = "proven" if summary["converged"] else "undecided"
    for seed in alive:
        seed.wp = {"verdict": verdict, "round": len(rounds)}
    if not alive and summary["status"] == "ok":
        summary["converged"] = True
    return summary


# ---------------------------------------------------------------------------
# No-harm check
# ---------------------------------------------------------------------------

# (scratch copy, function) -> run_wp_function's dict for every goal of the function
FullWpRunner = Callable[[Path, str], dict]


def _unproven_keys(result: dict) -> Counter[tuple[str, str]]:
    return Counter(
        (str(g.get("kind") or ""), re.sub(r"\s+", " ", str(g.get("annotation") or "")).strip())
        for g in result.get("unproven_goals") or []
    )


def _usable(result: dict) -> bool:
    return result.get("status") in ("all_proven", "unproven_goals_remain") and isinstance(
        result.get("unproven_goals"), list
    )


def no_harm(
    text: str,
    function: str,
    copy: Path,
    proven: list[Candidate],
    run_full: FullWpRunner,
    max_runs: int = MAX_NO_HARM_RUNS,
    deadline: float | None = None,
) -> dict:
    """
    Proven seeds are true, but more hypotheses can make a solver miss a goal it proved without them
    (measured: `c <= cols` on a nested fill loses a nonlinear `\\valid`). Compare the function's
    unproven goals without seeds and with them; on a lost goal, try leaving out one seed of the
    loop the goal sits in, and withhold every seed if nothing within `max_runs` restores it. Sets
    `wp["withheld"]` on the seeds left out. A check that cannot run withholds nothing and says so.
    """
    summary: dict = {"status": "ok", "runs": [], "lost": [], "newly_proved": 0}

    def out_of_time() -> bool:
        return deadline is not None and time.monotonic() >= deadline

    def measure(kept: list[Candidate]) -> tuple[dict, dict[str, int]]:
        seeded, lines, _ = insert_seeds(text, kept, path=copy.name)
        copy.write_text(seeded, encoding="utf-8", newline="\n")
        started = time.monotonic()
        result = run_full(copy, function)
        summary["runs"].append(
            {
                "seeds": [c.name for c in kept],
                "seconds": round(time.monotonic() - started, 1),
                "wp_status": result.get("status"),
                "unproven": len(result.get("unproven_goals") or []),
            }
        )
        return result, lines

    def skip(reason: str) -> dict:
        summary.update(status="skipped", reason=reason)
        return summary

    if out_of_time():
        return skip("no time left")
    base, _ = measure([])
    if not _usable(base):
        return skip(f"baseline WP run: {base.get('reason') or base.get('status')}")
    before = _unproven_keys(base)
    summary["baseline_unproven"] = sum(before.values())

    def lost_goals(result: dict) -> list[dict]:
        extra = _unproven_keys(result) - before
        goals = []
        for g in result.get("unproven_goals") or []:
            key = (str(g.get("kind") or ""), re.sub(r"\s+", " ", str(g.get("annotation") or "")).strip())
            if extra.get(key, 0) > 0:
                extra[key] -= 1
                goals.append({"kind": key[0], "annotation": key[1], "line": g.get("line")})
        return goals

    def withhold(seeds: list[Candidate], reason: str) -> None:
        for seed in seeds:
            seed.wp["withheld"] = reason

    if out_of_time():
        return skip("no time left after the baseline run")
    full, lines = measure(proven)
    if not _usable(full):
        return skip(f"seeded WP run: {full.get('reason') or full.get('status')}")
    lost = lost_goals(full)
    summary["newly_proved"] = sum((before - _unproven_keys(full)).values())
    if not lost:
        return summary
    summary["lost"] = lost
    text_lost = "; ".join(f"{g['kind']} `{g['annotation']}`" for g in lost[:3])

    # The loop a lost goal sits in: the seeded loop whose annotation is the last one above the goal.
    suspects: list[Candidate] = []
    for goal in lost:
        above = [c for c in proven if isinstance(goal.get("line"), int) and lines.get(c.name, 0) < goal["line"]]
        if above:
            index = max(above, key=lambda c: lines[c.name]).loop_index
            suspects += [c for c in proven if c.loop_index == index and c not in suspects]
    for suspect in suspects:
        if len(summary["runs"]) - 1 >= max_runs or out_of_time():
            break
        kept = [c for c in proven if c is not suspect]
        trial, _ = measure(kept)
        if _usable(trial) and not lost_goals(trial):
            withhold([suspect], f"with it, WP no longer proves {text_lost}")
            summary.update(status="one_withheld", newly_proved=sum((before - _unproven_keys(trial)).values()))
            return summary
    withhold(proven, f"with the seeds, WP no longer proves {text_lost}, and leaving one out did not restore it")
    summary.update(status="all_withheld", newly_proved=0)
    return summary


# ---------------------------------------------------------------------------
# Corpus filter
# ---------------------------------------------------------------------------


def _input_evidence(crash_input: str | None, corpus_dir: Path | None) -> dict:
    """The falsifying input by content: the replay's own copy lives in a scratch directory."""
    if not crash_input:
        return {}
    path = Path(crash_input)
    try:
        data = path.read_bytes()
    except OSError:
        return {"input": None}
    digest = hashlib.sha256(data).hexdigest()
    name = None
    if corpus_dir is not None and Path(corpus_dir).is_dir():
        for item in sorted(Path(corpus_dir).iterdir()):
            try:
                if item.is_file() and item.stat().st_size == len(data) and item.read_bytes() == data:
                    name = item.name
                    break
            except OSError:
                continue
    return {"input": name, "input_sha256": digest, "input_size": len(data)}


def corpus_filter(
    text: str,
    function: str,
    copy: Path,
    candidates: list[Candidate],
    run_guard: GuardRunner,
    corpus_dir: Path | None = None,
    max_rounds: int = MAX_CORPUS_ROUNDS,
    deadline: float | None = None,
) -> dict:
    """
    Replay the corpus with `candidates` as runtime checks. A replay stops at the first failed check,
    so each round falsifies at most one candidate; the rest is replayed again without it.
    """
    testing = list(candidates)
    rounds: list[dict] = []
    summary: dict = {"status": "ok", "rounds": rounds}

    def leave(reason: str) -> None:
        for seed in testing:
            seed.corpus = {"verdict": "not_tested", "reason": reason}

    while testing:
        if len(rounds) >= max_rounds:
            summary["status"] = "round_limit"
            leave("round limit reached")
            break
        if deadline is not None and time.monotonic() >= deadline:
            summary["status"] = "timeout"
            leave("time budget spent")
            break
        seeded, lines, skipped = insert_seeds(text, testing, path=copy.name)
        for seed in [s for s in testing if s.name not in lines]:
            seed.corpus = {"verdict": "not_tested", "reason": skipped.get(seed.loop_line, "not inserted")}
        testing = [s for s in testing if s.name in lines]
        if not testing:
            break
        copy.write_text(seeded, encoding="utf-8", newline="\n")
        started = time.monotonic()
        guard = run_guard(copy, function)
        status = str(guard.get("status"))
        failure = guard.get("failure") or {}
        entry = {
            "round": len(rounds) + 1,
            "seconds": round(time.monotonic() - started, 1),
            "seeds": [s.name for s in testing],
            "guard_status": status,
        }
        rounds.append(entry)
        if status == "passed_dynamic_oracle":
            reached = ((guard.get("reach") or {}).get("functions") or {}).get(function)
            replay = {k: guard.get(k) for k in ("corpus_total", "corpus_replayed", "corpus_sampled")}
            summary.update(replay)
            summary["function_reached"] = reached
            for seed in testing:
                if isinstance(reached, int) and reached > 0:
                    seed.corpus = {"verdict": "held", **replay}
                else:
                    # No replayed input ran the function (or its reach is unknown): nothing was tested.
                    seed.corpus = {"verdict": "not_reached", **replay}
            testing = []
            break
        hit = next((s for s in testing if s.name == failure.get("label")), None)
        if status == "rejected_overconstrained" and hit is not None:
            hit.corpus = {
                "verdict": "falsified",
                "predicate": failure.get("predicate"),
                **_input_evidence(guard.get("crash_input"), corpus_dir),
            }
            entry["falsified"] = hit.name
            testing.remove(hit)
            continue
        # A build that fails, a check of the function's own contract that fails first, a code fault:
        # the replay stopped before it could say anything about the remaining candidates.
        where = failure.get("label") or failure.get("predicate") or guard.get("reason") or ""
        summary["status"] = "incomplete"
        summary["reason"] = f"{status}: {where}".rstrip(": ")[:300]
        leave(summary["reason"])
        break
    return summary


# ---------------------------------------------------------------------------
# Default runners (the real tools)
# ---------------------------------------------------------------------------


def _with_include(orig_dir: Path, cppflags: str) -> str:
    """A scratch copy sits elsewhere: `#include "x.h"` must still find the original's directory first."""
    return f"-I{orig_dir.as_posix()} {cppflags}".strip()


def default_wp_runner(orig_file: Path, cppflags: str, out_dir: Path, deadline: float | None) -> WpRunner:
    import run_wp_function

    def _run(copy: Path, function: str, names: list[str]) -> dict:
        wall = run_wp_function.default_wall_timeout(None)
        if deadline is not None:
            left = max(1, int(deadline - time.monotonic()))
            wall = min(wall, left) if wall else left
        result = run_wp_function.run_wp_on_function(
            c_file=copy,
            fn_name=function,
            out_dir=out_dir,
            cppflags=_with_include(orig_file.parent, cppflags),
            timeout=WP_GOAL_TIMEOUT_S,
            # The prover's own command proves with this check off; the seed goals do not depend on it.
            warn_unsigned_downcast=False,
            retry_bitwise=False,
            retry_tail=False,
            retry_cast_probe=False,
            prop=",".join(names),
            wall_timeout=wall,
            ignore_prover_budget=True,
        )
        log_path, csv_path = out_dir / f"wp_{function}.log", out_dir / f"wp_{function}.csv"
        log = log_path.read_text(encoding="utf-8", errors="replace") if log_path.is_file() else ""
        rows = read_report_csv(csv_path) if csv_path.is_file() else []
        return {"result": result, "log": log, "rows": rows}

    return _run


def default_full_runner(orig_file: Path, cppflags: str, out_dir: Path, deadline: float | None) -> FullWpRunner:
    """Every goal of the function, at run_wp_function's own goal timeout (what the prover's run uses)."""
    import run_wp_function

    def _run(copy: Path, function: str) -> dict:
        wall = run_wp_function.default_wall_timeout(None)
        if deadline is not None:
            left = max(1, int(deadline - time.monotonic()))
            wall = min(wall, left) if wall else left
        return run_wp_function.run_wp_on_function(
            c_file=copy,
            fn_name=function,
            out_dir=out_dir,
            cppflags=_with_include(orig_file.parent, cppflags),
            warn_unsigned_downcast=False,
            retry_bitwise=False,
            retry_tail=False,
            retry_cast_probe=False,
            wall_timeout=wall,
            ignore_prover_budget=True,
        )

    return _run


def default_guard_runner(
    orig_file: Path,
    sources: list[str],
    cppflags: str,
    ldflags: str,
    corpus_dir: Path,
    module: str,
    out_dir: Path,
) -> GuardRunner | None:
    """None when `orig_file` is not one of `sources`: there is nothing to substitute the copy for."""
    target = orig_file.resolve()
    index = next((i for i, s in enumerate(sources) if Path(s).resolve() == target), None)
    if index is None:
        return None

    def _run(copy: Path, function: str) -> dict:
        import fuzz_build
        import run_eacsl_fuzz
        from sandbox_exec import SandboxUnavailable

        swapped = list(sources)
        swapped[index] = str(copy)
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            # A plain build on purpose: it checks one seeded loop annotation of `function` on a copy,
            # and never loads the run's MetAcsl properties (only fuzz_build.build_module_binary does,
            # with `eacsl` in security_props.json's meta_engines). A property failing on a corpus
            # input would otherwise be read as the seed not holding.
            comp = fuzz_build.compile_eacsl_binary(
                swapped,
                out_dir / "guard",
                cppflags=_with_include(orig_file.parent, cppflags),
                functions=[function],
                ldflags_extra=ldflags,
                use_cache=False,
            )
            if comp.get("returncode") != 0:
                return {"status": "compile_error", "reason": comp.get("reason")}
            # The corpus only, no mutation: "held on every replayed corpus input" means exactly that.
            return run_eacsl_fuzz.run_guardrail_check(
                Path(comp["binary"]),
                corpus_dir,
                out_dir / "guard_scratch",
                0,
                module=module,
                use_cache=False,
                functions=[function],
            )
        except SandboxUnavailable as exc:
            return {"status": "sandbox_unavailable", "reason": str(exc)}

    return _run


# ---------------------------------------------------------------------------
# The report
# ---------------------------------------------------------------------------


def _label(seed: Candidate, proven: set[str]) -> str:
    if seed.wp.get("verdict") == "proven":
        if seed.wp.get("withheld"):
            return "proven_withheld"
        return "redundant" if seed.weaker_of in proven else "proven_inductive"
    if seed.wp.get("verdict") == "dropped" and seed.corpus.get("verdict") == "held":
        return "held_on_corpus_unproven"
    if seed.wp.get("verdict") in ("undecided", "not_run", "not_placed"):
        return "undecided"
    return "dropped"


def _base_report(function: str, file: str, module: str | None, status: str, reason: str | None = None) -> dict:
    report: dict = {
        "schema": SEEDS_SCHEMA,
        "status": status,
        "note": NOTE,
        "function": function,
        "file": file,
        "module": module,
        "generated_at": utc_now(),
        "candidates": [],
    }
    if reason:
        report["reason"] = reason
    return report


def compute(
    c_file: Path,
    function: str,
    record: dict | None,
    run_wp: WpRunner,
    run_guard: GuardRunner | None,
    work_dir: Path,
    module: str | None = None,
    corpus_dir: Path | None = None,
    deadline: float | None = None,
    run_full: FullWpRunner | None = None,
) -> dict:
    """The seeds report of one function. Never raises on a tool problem: `status` carries it."""
    shown_file = c_file.as_posix()
    if record is None:
        return _base_report(function, shown_file, module, "no_facts", "no facts record for this function")
    try:
        text = c_file.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return _base_report(function, shown_file, module, "error", f"cannot read the source: {exc}")
    loops = record.get("loops") or []
    if not loops:
        return _base_report(function, shown_file, module, "no_loops")
    try:
        candidates = generate_candidates(record, text, function_facts.line_mapper(record, text))
    except AcslSyntaxError as exc:
        return _base_report(function, shown_file, module, "error", f"source does not tokenize: {exc}")
    report = _base_report(function, shown_file, module, "ok")
    seeded_loops = {c.loop_index: c.loop_line for c in candidates}
    report["loops"] = [
        {"index": lp.get("index"), "line": seeded_loops[lp["index"]], "header": lp.get("header") or ""}
        for lp in loops
        if lp.get("index") in seeded_loops
    ]
    if not candidates:
        report["status"] = "no_candidates"
        return report

    started = time.monotonic()
    work_dir.mkdir(parents=True, exist_ok=True)
    copy = work_dir / c_file.name
    report["wp"] = houdini(text, function, copy, candidates, run_wp, deadline=deadline)
    dropped = [c for c in candidates if c.wp.get("verdict") == "dropped" and "rejected_by_kernel" not in c.wp["failed"]]
    if not dropped:
        report["corpus"] = {"status": "not_needed", "rounds": []}
    elif run_guard is None:
        report["corpus"] = {"status": "skipped", "reason": "no sources or corpus given", "rounds": []}
    else:
        report["corpus"] = corpus_filter(text, function, copy, dropped, run_guard, corpus_dir, deadline=deadline)

    proven = {c.predicate for c in candidates if c.wp.get("verdict") == "proven"}
    pasted = [
        c for c in candidates if c.wp.get("verdict") == "proven" and (c.weaker_of is None or c.weaker_of not in proven)
    ]
    if not pasted:
        report["no_harm"] = {"status": "not_needed", "runs": []}
    elif run_full is None:
        report["no_harm"] = {"status": "skipped", "reason": "no full WP runner given", "runs": []}
    else:
        report["no_harm"] = no_harm(text, function, copy, pasted, run_full, deadline=deadline)
    for cand in candidates:
        report["candidates"].append(
            {
                "name": cand.name,
                "loop_index": cand.loop_index,
                "loop_line": cand.loop_line,
                "predicate": cand.predicate,
                "template": cand.template,
                "label": _label(cand, proven),
                "wp": cand.wp,
                "corpus": cand.corpus,
            }
        )
    report["proven"] = [c["name"] for c in report["candidates"] if c["label"] == "proven_inductive"]
    report["held_on_corpus_unproven"] = [
        c["name"] for c in report["candidates"] if c["label"] == "held_on_corpus_unproven"
    ]
    wp_status = report["wp"]["status"]
    if wp_status != "ok":
        report["status"] = "timeout" if wp_status == "timeout" else "partial"
        report["reason"] = f"WP filter: {report['wp'].get('reason') or wp_status}"
    report["seconds"] = round(time.monotonic() - started, 1)
    return report


def _failure_text(wp: dict) -> str:
    names = {
        "established": "establishment failed",
        "preserved": "preservation failed",
        "rejected_by_kernel": "the kernel rejected the clause",
        "not_proven": "not proven",
    }
    return " and ".join(names.get(f, str(f)) for f in wp.get("failed") or []) or "not proven"


def render(report: dict) -> str:
    """The report as a prover reads it: clauses ready to paste, each group labelled."""
    function = report.get("function") or "?"
    status = report.get("status")
    lines = [f"## Loop invariant seeds for `{function}` (status: {status})", ""]
    if report.get("reason"):
        lines += [f"Reason: {report['reason']}", ""]
    candidates = report.get("candidates") or []
    if not candidates:
        lines.append("No seed for this function. Write the loop invariants as Step B describes.")
        return "\n".join(lines) + "\n"
    lines += [
        "Candidates generated from the loop facts, then filtered by WP and by a replay of the corpus. They are "
        "hints: WP stays the only judge, and none of them is a reason to add or strengthen a `requires`.",
        "",
    ]
    check = report.get("no_harm") or {}
    if check.get("status") == "ok":
        lines += [
            f"Checked on every goal of `{function}`: with the proven seeds pasted, WP loses no goal it proved "
            f"without them and proves {check.get('newly_proved', 0)} more.",
            "",
        ]
    elif check.get("status") == "skipped":
        lines += [
            f"The proven seeds were not checked against the function's other goals ({check.get('reason')}): "
            "if a goal that proved before stops proving after you paste them, remove them.",
            "",
        ]
    headers = {lp.get("index"): lp for lp in report.get("loops") or []}
    for index in dict.fromkeys(c["loop_index"] for c in candidates):
        group = [c for c in candidates if c["loop_index"] == index]
        header = (headers.get(index) or {}).get("header")
        lines.append(f"### Loop at L{group[0]['loop_line']}" + (f" `{header}`" if header else ""))
        lines.append("")
        proven = [c for c in group if c["label"] == "proven_inductive"]
        held = [c for c in group if c["label"] == "held_on_corpus_unproven"]
        undecided = [c for c in group if c["label"] == "undecided"]
        dropped = [c for c in group if c["label"] == "dropped"]
        withheld = [c for c in group if c["label"] == "proven_withheld"]
        if proven:
            lines.append(
                "**Proven inductive under the current contract and loop annotations** (paste into this loop's "
                "annotation, before `loop assigns`):"
            )
            lines += ["", "```c"] + [f"loop invariant {c['name']}: {c['predicate']};" for c in proven] + ["```", ""]
        if held:
            replay = held[0]["corpus"]
            lines.append(
                f"**Held on every replayed corpus input ({replay.get('corpus_replayed')} of "
                f"{replay.get('corpus_total')}), NOT proven** (a hint only: it may be true and need a stronger "
                "invariant beside it, or false on an input the corpus lacks):"
            )
            lines.append("")
            for c in held:
                lines.append(f"- `loop invariant {c['name']}: {c['predicate']};` WP: {_failure_text(c['wp'])}.")
            lines.append("")
        if withheld:
            lines.append(
                "**Proven, but withheld** (true, yet with them in the annotation WP lost a goal it proves "
                "without them; do not paste them unless a goal needs one):"
            )
            lines.append("")
            lines += [f"- `{c['predicate']}`: {c['wp'].get('withheld')}." for c in withheld]
            lines.append("")
        if undecided:
            lines.append("**Not decided** (the WP filter did not finish; treat as unknown):")
            lines.append("")
            lines += [f"- `{c['predicate']}`" for c in undecided]
            lines.append("")
        if dropped:
            lines.append("**Dropped** (do not write these):")
            lines.append("")
            for c in dropped:
                why = _failure_text(c["wp"])
                corpus = c["corpus"]
                if corpus.get("verdict") == "falsified":
                    name = corpus.get("input") or (corpus.get("input_sha256") or "")[:16] or "?"
                    why += f"; false on corpus input `{name}`"
                elif corpus.get("verdict") == "not_reached":
                    why += "; no replayed corpus input reaches this function"
                lines.append(f"- `{c['predicate']}`: {why}.")
            lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def default_out_json(module: str | None, function: str) -> Path:
    safe = [re.sub(r"[^A-Za-z0-9_.-]+", "_", part).strip(".") or "_" for part in (module or "_", function)]
    return Path(REPORT_DIR) / safe[0] / f"{safe[1]}.json"


def find_facts(overlay: Path, module: str | None, file: str, function: str) -> dict | None:
    """The function's facts: the module's own report, else whichever facts report describes the function."""
    rel = function_facts.work_relative(file) or file
    record = function_facts.load_function_facts(overlay, module, rel, function)
    if record is not None:
        return record
    # A link unit's facts are filed under its harness modules, not always under the name a brief gives.
    facts_dir = Path(overlay) / "reports" / "facts"
    for path in sorted(facts_dir.glob("*.json")) if facts_dir.is_dir() else []:
        record = function_facts.load_function_facts(overlay, path.stem, rel, function)
        if record is not None:
            return record
    return None


def run(
    c_file: Path,
    function: str,
    module: str | None,
    cppflags: str,
    sources: list[str],
    corpus_dir: Path | None,
    ldflags: str = "",
    facts_overlay: Path = Path("workspace"),
    max_seconds: int | None = None,
) -> dict:
    """Facts lookup, a private working directory, the real tools. Used by the CLI."""
    shown_file = c_file.as_posix()
    if not function_facts.loop_seeds_enabled():
        return _base_report(
            function, shown_file, module, "disabled", f"{function_facts.LOOP_SEEDS_ENV} is not on (or facts are off)"
        )
    record = find_facts(facts_overlay, module, shown_file, function)
    import run_wp_function

    budget = max_seconds if max_seconds else run_wp_function.default_wall_timeout(None)
    deadline = time.monotonic() + budget if budget else None
    # Outside the agent's tree: the copy is never part of its work tree, its patch or its WP budget.
    tmp = Path(tempfile.mkdtemp(prefix=f"loop_seeds_{function}_"))
    try:
        guard = None
        if sources and corpus_dir is not None and corpus_dir.is_dir():
            guard = default_guard_runner(c_file, sources, cppflags, ldflags, corpus_dir, module or "", tmp / "eacsl")
        return compute(
            c_file,
            function,
            record,
            default_wp_runner(c_file, cppflags, tmp / "wp", deadline),
            guard,
            tmp / "src",
            module=module,
            corpus_dir=corpus_dir,
            deadline=deadline,
            run_full=default_full_runner(c_file, cppflags, tmp / "wp_full", deadline),
        )
    except Exception as exc:  # hints only: no failure of this tool may stop a prover
        return _base_report(function, shown_file, module, "error", f"{type(exc).__name__}: {exc}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Loop invariant seeds, filtered by WP (Houdini) and by the corpus.")
    parser.add_argument("--file", type=Path, required=True, help="The C file holding the function (never modified)")
    parser.add_argument("--function", required=True)
    parser.add_argument("--module", default=None, help="Module name: selects workspace/reports/facts/<module>.json")
    parser.add_argument("--cppflags", default="-I.")
    parser.add_argument("--ldflags", default="")
    parser.add_argument("--sources", nargs="*", default=[], help="Module sources and harness, for the corpus filter")
    parser.add_argument("--corpus-dir", type=Path, default=None, help="Phase 1 corpus to replay (read-only)")
    parser.add_argument("--facts-overlay", type=Path, default=Path("workspace"))
    parser.add_argument("--max-seconds", type=int, default=None, help="Budget (default: the `wp` job class limit)")
    parser.add_argument("--out-json", type=Path, default=None)
    parser.add_argument("--json", action="store_true", help="Print the report as JSON instead of Markdown")
    raw = list(argv) if argv is not None else sys.argv[1:]
    args = parser.parse_args(normalize_flag_args(raw, ("--cppflags", "--ldflags")))
    report = run(
        args.file,
        args.function,
        args.module,
        args.cppflags,
        list(args.sources),
        args.corpus_dir,
        ldflags=args.ldflags,
        facts_overlay=args.facts_overlay,
        max_seconds=args.max_seconds,
    )
    out_json = args.out_json or default_out_json(args.module, args.function)
    try:
        atomic_write_json(out_json, report)
    except OSError as exc:
        print(f"loop_seeds: report not written to {out_json}: {exc}", file=sys.stderr)
    print(json.dumps(report, indent=2) if args.json else render(report), end="")
    return 0  # whatever happened, a prover goes on without seeds


if __name__ == "__main__":
    sys.exit(main())
