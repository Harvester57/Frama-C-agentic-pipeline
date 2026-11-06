#!/usr/bin/env python3
"""
Specification-quality measurement by mutation testing (COINS 2608.13077v1 /
KBSpec's C@All, 2606.21339v2), complementing WP pass/fail:

- completeness (C@All-style): mutate the ACSL *contract* of a proved function
  (drop an ensures clause, flip <= to <, replace an ensures with \\true). If WP
  still proves the mutant contract against the unchanged code, the mutant is
  equivalent and the original spec is incomplete. completeness = 1 - equivalent/total.
- precision (REJECT-style): mutate the *implementation* (flip < to <= in a guard,
  change a return constant). If WP then reports an ensures/behavior goal Invalid,
  the spec rejects the wrong code. precision = rejected/total.

Runs only on functions whose parent WP report (workspace/reports/wp/<fn>.json)
is all_proven, writes workspace/reports/mutation.json, and generate_report.py
renders it as a "Specification quality" section. Purely evaluative: it never
touches workspace/work/ (mutants are written to a temp dir).

CLI: mutation-check --run-dir D [--max-functions N] [--max-mutants M]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import run_wp_function  # noqa: E402
from acsl_ast import _find_body_brace_offset, locate_function_span, tokenize_c_acsl  # noqa: E402
from framac_common import atomic_write_json, load_json_optional, utc_now  # noqa: E402

MUTATION_SCHEMA = 1
DEFAULT_MAX_FUNCTIONS = 20
DEFAULT_MAX_MUTANTS = 6

_REL_OP_FLIP = [("<=", "<"), (">=", ">"), ("<", "<="), (">", ">=")]
_RETURN_CONST_RE = re.compile(r"\breturn\s+(-?\d+)\s*;")
_ENSURES_CLAUSE_RE = re.compile(r"\bensures\b[^;]*;")


def _acsl_text_of_span(span) -> str:
    try:
        tokens = tokenize_c_acsl(span.text, path=span.function)
    except Exception:
        return ""
    return "\n".join(t.text for t in tokens if t.kind in ("acsl_block", "acsl_line"))


def spec_mutants(contract_acsl: str, max_mutants: int) -> list[tuple[str, str]]:
    """Contract mutants: drop each ensures clause, flip <=/>= in ensures, \\true-ify one."""
    out: list[tuple[str, str]] = []
    clauses = _ENSURES_CLAUSE_RE.findall(contract_acsl)
    for i, clause in enumerate(clauses[:max_mutants]):
        out.append((f"drop-ensures-{i}", contract_acsl.replace(clause, "", 1)))
    for i, clause in enumerate(clauses[: max_mutants - len(out)]):
        flipped = clause.replace("<=", "<").replace(">=", ">")
        if flipped != clause:
            out.append((f"weaken-ensures-{i}", contract_acsl.replace(clause, flipped, 1)))
    if clauses and len(out) < max_mutants:
        out.append(("ensures-true", _ENSURES_CLAUSE_RE.sub(lambda m: r"ensures \true;", contract_acsl, count=1)))
    return out[:max_mutants]


def impl_mutants(body_text: str, max_mutants: int) -> list[tuple[str, str]]:
    """Implementation mutants: flip relational operators, change return constants."""
    out: list[tuple[str, str]] = []
    for op, flipped in _REL_OP_FLIP:
        if op in body_text:
            out.append((f"flip-{op}", body_text.replace(op, flipped, 1)))
        if len(out) >= max_mutants:
            break
    for m in _RETURN_CONST_RE.finditer(body_text):
        if len(out) >= max_mutants:
            break
        val = int(m.group(1))
        out.append((f"return-{val}-to-{val + 1}", body_text[: m.start()] + f"return {val + 1};" + body_text[m.end() :]))
    return out[:max_mutants]


def _is_rejection(report: dict) -> bool:
    """The spec rejects the mutant: an ensures/behavior goal came back Invalid."""
    for g in report.get("unproven_goals") or []:
        status = str(g.get("status") or "").lower()
        kind = str(g.get("kind") or "")
        if "invalid" in status and kind and not kind.startswith("rte"):
            return True
    return False


def _is_equivalent(report: dict) -> bool:
    """The mutant contract still proves against the unchanged code."""
    return report.get("status") == "all_proven"


def check_function(
    c_file: Path,
    fn: str,
    cppflags: str,
    out_dir: Path,
    wp_runner=None,
    max_mutants: int = DEFAULT_MAX_MUTANTS,
) -> dict:
    """
    Mutate the contract and the body of `fn` in `c_file`, run WP per mutant, and
    return {function, file, spec_mutants, equivalent, impl_mutants, rejected,
    completeness, precision, details}. `wp_runner` defaults to
    run_wp_function.run_wp_on_function and is injectable for tests.
    """
    runner = wp_runner or run_wp_function.run_wp_on_function
    text = c_file.read_text(encoding="utf-8", errors="replace")
    span = locate_function_span(text, fn, is_header=False, path=str(c_file))
    if span is None:
        return {"function": fn, "file": str(c_file), "error": "function span not found"}
    contract = _acsl_text_of_span(span)
    brace = _find_body_brace_offset(span.text, path=str(c_file))
    body = span.text[brace:] if brace is not None else span.text
    result: dict[str, Any] = {
        "function": fn,
        "file": str(c_file),
        "spec_mutants": 0,
        "equivalent": 0,
        "impl_mutants": 0,
        "rejected": 0,
        "completeness": None,
        "precision": None,
        "details": [],
    }
    with tempfile.TemporaryDirectory(prefix="framac-mutation-") as tmp:
        tmp_path = Path(tmp)
        for kind, mutants in (
            ("spec", spec_mutants(contract, max_mutants)),
            ("impl", impl_mutants(body, max_mutants)),
        ):
            for name, mutated in mutants:
                if kind == "spec":
                    # Replace the contract ACSL inside the span, keep the body.
                    new_span = _replace_contract_in_span(span.text, contract, mutated)
                else:
                    # Mutate the C body only; keep the contract in front of it.
                    new_span = span.text[:brace] + mutated if brace is not None else mutated
                mut_file = tmp_path / c_file.name
                mut_file.write_text(text[: span.start_byte] + new_span + text[span.end_byte :], encoding="utf-8")
                try:
                    report = runner(mut_file, fn, tmp_path / f"wp-{kind}-{name}", cppflags=cppflags)
                except Exception as exc:
                    report = {"status": "error", "reason": str(exc)}
                if kind == "spec":
                    result["spec_mutants"] += 1
                    eq = _is_equivalent(report)
                    result["equivalent"] += int(eq)
                    result["details"].append(
                        {"mutant": name, "kind": "spec", "equivalent": eq, "status": report.get("status")}
                    )
                else:
                    result["impl_mutants"] += 1
                    rej = _is_rejection(report)
                    result["rejected"] += int(rej)
                    result["details"].append(
                        {"mutant": name, "kind": "impl", "rejected": rej, "status": report.get("status")}
                    )
    if result["spec_mutants"]:
        result["completeness"] = round(1 - result["equivalent"] / result["spec_mutants"], 4)
    if result["impl_mutants"]:
        result["precision"] = round(result["rejected"] / result["impl_mutants"], 4)
    return result


def _replace_contract_in_span(span_text: str, old_contract: str, new_contract: str) -> str:
    """Swap the ACSL contract text inside the span, leaving C tokens untouched."""
    if old_contract and old_contract in span_text:
        return span_text.replace(old_contract, new_contract, 1)
    # Fallback: replace the leading ACSL block(s) before the first C token of the body.
    tokens = tokenize_c_acsl(span_text, path="<span>")
    out = []
    replaced = False
    for t in tokens:
        if not replaced and t.kind in ("acsl_block", "acsl_line"):
            out.append(new_contract)
            replaced = True
        elif t.kind in ("acsl_block", "acsl_line"):
            continue
        else:
            out.append(t.text)
    return "".join(out) if replaced else span_text


def classify_open_unit(wp_report: dict | None) -> str:
    """COINS evaluation duality: is an open unit prover-limited or spec-limited?"""
    if not isinstance(wp_report, dict):
        return "unknown"
    if wp_report.get("status") == "analysis_error":
        return "prover_limited"
    if wp_report.get("wp_allocation_limitation") or wp_report.get("wp_macro_loop_limitation"):
        return "prover_limited"
    frame = wp_report.get("frame_summary") or {}
    if frame.get("missing_assigns_warning"):
        return "spec_limited"
    unproven = wp_report.get("unproven_goals") or []
    if unproven and all("timeout" in str(g.get("status") or "").lower() for g in unproven):
        return "prover_limited"
    return "spec_limited"


def run_mutation_check(
    run_dir: Path,
    max_functions: int = DEFAULT_MAX_FUNCTIONS,
    max_mutants: int = DEFAULT_MAX_MUTANTS,
    wp_runner=None,
    out_path: Path | None = None,
) -> dict:
    """Run the mutation check over all all_proven functions of a run directory."""
    run_dir = Path(run_dir)
    wp_dir = run_dir / "workspace" / "reports" / "wp"
    work = run_dir / "workspace" / "work"
    out_path = out_path or run_dir / "workspace" / "reports" / "mutation.json"
    doc: dict[str, Any] = {"schema": MUTATION_SCHEMA, "generated_at": utc_now(), "functions": {}}
    if wp_dir.is_dir():
        reports = sorted(wp_dir.glob("*.json"))
        for rep_path in reports[:max_functions]:
            rep = load_json_optional(rep_path, {})
            if rep.get("status") != "all_proven":
                continue
            fn = str(rep.get("function") or rep_path.stem)
            c_file = Path(str(rep.get("file") or ""))
            if not c_file.is_absolute():
                c_file = work / c_file
            if not c_file.is_file():
                # The report's file path may be agent-scratch relative; try workspace/work by name.
                cand = work / c_file.name
                c_file = cand if cand.is_file() else c_file
            if not c_file.is_file():
                continue
            doc["functions"][fn] = check_function(
                c_file,
                fn,
                "-I.",
                run_dir / "workspace" / "reports" / "mutation-wp",
                wp_runner=wp_runner,
                max_mutants=max_mutants,
            )
    totals: dict[str, Any] = {
        "functions": len(doc["functions"]),
        "spec_mutants": sum(f.get("spec_mutants", 0) for f in doc["functions"].values()),
        "equivalent": sum(f.get("equivalent", 0) for f in doc["functions"].values()),
        "impl_mutants": sum(f.get("impl_mutants", 0) for f in doc["functions"].values()),
        "rejected": sum(f.get("rejected", 0) for f in doc["functions"].values()),
    }
    comps = [f["completeness"] for f in doc["functions"].values() if f.get("completeness") is not None]
    precs = [f["precision"] for f in doc["functions"].values() if f.get("precision") is not None]
    totals["completeness"] = round(sum(comps) / len(comps), 4) if comps else None
    totals["precision"] = round(sum(precs) / len(precs), 4) if precs else None
    doc["totals"] = totals
    atomic_write_json(out_path, doc)
    return doc


def summarize_mutation(path: Path) -> dict:
    """The benchmark-facing summary of a mutation.json report."""
    doc = load_json_optional(path, {})
    return doc.get("totals") or {}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Mutation-based specification quality check.")
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--max-functions", type=int, default=DEFAULT_MAX_FUNCTIONS)
    parser.add_argument("--max-mutants", type=int, default=DEFAULT_MAX_MUTANTS)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)
    doc = run_mutation_check(args.run_dir, args.max_functions, args.max_mutants, out_path=args.out)
    print(json.dumps(doc.get("totals") or {}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
