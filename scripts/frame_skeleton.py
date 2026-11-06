#!/usr/bin/env python3
"""
Deterministic projection of a function's frame information into an ACSL frame skeleton.

Inspired by AutoFraming (arXiv:2610.29046v1): the frame-critical content of a contract —
`requires \\separated(rho_p, rho_q);` for interfering pointer pairs and
`assigns L \\from r1, ..., rm;` for each caller-visible write — is computed from the
kernel-AST facts and Eva's `-deps` output, not left to the LLM. The skeleton is a
REQUIRED MINIMUM: a prover may strengthen it, never delete or weaken it, and the
merge-time check (acsl_ast.check_frame_preserved) rejects candidates that drop a clause.
WP remains the only judge of whether the clauses hold.

Input is one function record as built by function_facts._function_record (formals,
writes, reads, loops, may_alias, return_paths, eva). Output:

    {
      "status": "ok" | "partial" | "disabled",
      "separated": [{"roots": [a, b], "regions": [ra, rb], "clause": "requires \\separated(ra, rb);",
                     "reason": "..."}],
      "assigns":   [{"loc": L, "from": [f1, ...], "clause": "assigns L \\from f1, ...;",
                     "source": "ast" | "ast-superset"}],
      "notes":     ["..."],
    }

`partial` means some region/dependence was approximated (strongest entry-expressible
form); the prover must check it against the code. FRAMAC_FRAME_SKELETON=off disables
the projection (A/B ablation), yielding {"status": "disabled"}.
"""

from __future__ import annotations

import os
import re

SKELETON_ENV = "FRAMAC_FRAME_SKELETON"

_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_INT_RE = re.compile(r"\d+[uUlL]*")


def enabled() -> bool:
    """FRAMAC_FRAME_SKELETON=off: no skeleton, for A/B comparisons."""
    return (os.environ.get(SKELETON_ENV) or "").strip().lower() not in ("off", "0", "false", "no", "disabled")


# ---------------------------------------------------------------------------
# Expression helpers (kernel-normalized C text)
# ---------------------------------------------------------------------------


def _idents(expr: str | None) -> list[str]:
    return _IDENT_RE.findall(expr or "")


def _paren_group(text: str, open_idx: int) -> tuple[str, int]:
    """Inner text of the paren group opening at `open_idx`, and the index after its close."""
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1 : i], i + 1
    return text[open_idx + 1 :], len(text)


def _offset_expr(lval: str, root: str) -> tuple[str, str] | None:
    """
    The offset expression of an access rooted at `root`: ("const"|"expr"|"zero", text).
    Handles `*p`, `*(p + E)`, `p[E]`, `p->f`, `(*p).f`, `*(p + E)->f`, and bare `p`.
    """
    lv = (lval or "").strip()
    r = re.escape(root)
    if lv == root:
        return "zero", "0"
    if lv.startswith("*("):
        inner, _ = _paren_group(lv, 1)
        m = re.match(rf"^{r}\s*\+\s*(.+)$", inner.strip())
        if m:
            return "expr", m.group(1).strip()
        if re.fullmatch(rf"{r}", inner.strip()):
            return "zero", "0"
        return None
    if re.match(rf"^\*\s*{r}(\s|$|->|\.|\[)", lv):
        return "zero", "0"
    m = re.match(rf"^{r}\s*\[\s*(.+?)\s*\]", lv)
    if m:
        return "expr", m.group(1)
    if re.match(rf"^{r}\s*(->|\.)", lv):
        return "zero", "0"
    if re.match(rf"^\(\s*\*\s*{r}\s*\)\s*\.", lv):
        return "zero", "0"
    return None


def _classify_offset(expr: str, loops: list[dict]) -> tuple[str, object]:
    """("const", int) | ("range", (bound, inclusive)) | ("unknown", None)."""
    e = expr.strip()
    if _INT_RE.fullmatch(e):
        return "const", int(e.rstrip("uUlL"))
    if _IDENT_RE.fullmatch(e):
        for loop in loops:
            scalars = {s.get("var") for s in loop.get("scalars") or []}
            if e not in scalars:
                continue
            guard = str(loop.get("guard") or "")
            m = re.search(rf"\b{re.escape(e)}\s*(<=|<)\s*([A-Za-z_][A-Za-z0-9_]*|\d+)", guard) or re.search(
                rf"([A-Za-z_][A-Za-z0-9_]*|\d+)\s*(>=|>)\s*{re.escape(e)}\b", guard
            )
            if m:
                if m.lastindex == 2:
                    bound, incl = m.group(2), m.group(1) == "<="
                else:
                    bound, incl = m.group(1), m.group(2) == ">="
                return "range", (bound, incl)
        return "unknown", None
    return "unknown", None


# ---------------------------------------------------------------------------
# Access windows: region of a pointer root, entry-expressible
# ---------------------------------------------------------------------------


def _access_lvals(record: dict, root: str) -> list[str]:
    lvals: list[str] = []
    for item in list(record.get("writes") or []) + list(record.get("reads") or []):
        if item.get("root") == root and item.get("lval"):
            lvals.append(item["lval"])
    for loop in record.get("loops") or []:
        for item in list(loop.get("memory_writes") or []) + list(loop.get("reads") or []):
            if item.get("root") == root and item.get("lval"):
                lvals.append(item["lval"])
    return list(dict.fromkeys(lvals))


def _region(record: dict, root: str, loops: list[dict]) -> tuple[str, bool, str | None]:
    """(region text, exact, note). Strongest entry-expressible approximation of Omega(root)."""
    lvals = _access_lvals(record, root)
    if not lvals:
        return root, True, None
    consts: list[int] = []
    ranges: list[tuple[str, bool]] = []
    unknown = False
    for lv in lvals:
        off = _offset_expr(lv, root)
        if off is None:
            unknown = True
            continue
        kind, val = off
        if kind == "zero":
            consts.append(0)
            continue
        ck, cv = _classify_offset(str(val), loops)
        if ck == "const":
            consts.append(cv)
        elif ck == "range":
            ranges.append(cv)
        else:
            unknown = True
    if unknown:
        return root, False, f"access window of `{root}` is not fully entry-expressible; `{root}` alone is an approximation"
    if ranges:
        # Deterministic pick: the first range in source order; note when several differ.
        bound, incl = ranges[0]
        hi = bound if incl else f"{bound} - 1"
        note = None
        if len({(b, i) for b, i in ranges}) > 1:
            note = f"multiple access windows on `{root}`; using the first (`0 .. {hi}`)"
        if consts and (min(consts) < 0 or max(consts) > 0):
            note = (note + "; " if note else "") + f"constant offsets on `{root}` folded into the range"
        return f"{root} + (0 .. {hi})", True, note
    if consts:
        lo, hi = min(consts), max(consts)
        if lo == 0 and hi == 0:
            return root, True, None
        return f"{root} + ({lo} .. {hi})", True, None
    return root, True, None


# ---------------------------------------------------------------------------
# Skeleton computation
# ---------------------------------------------------------------------------


def _caller_roots(record: dict) -> tuple[set[str], dict[str, dict]]:
    formals = {f.get("name"): f for f in record.get("formals") or [] if f.get("name")}
    globals_seen = {
        item.get("root")
        for item in list(record.get("writes") or []) + list(record.get("reads") or [])
        if item.get("root_kind") == "global" and item.get("root")
    }
    return set(formals) | globals_seen, formals


def _loop_value_map(record: dict) -> dict[str, list[str]]:
    """lval -> RHS value expressions, from loop memory writes (function-level writes carry none)."""
    out: dict[str, list[str]] = {}
    for loop in record.get("loops") or []:
        for w in loop.get("memory_writes") or []:
            if w.get("lval"):
                out.setdefault(w["lval"], []).extend(w.get("values") or [])
    return out


def _loop_of_lval(record: dict, lval: str | None) -> dict | None:
    if not lval:
        return None
    for loop in record.get("loops") or []:
        if any(w.get("lval") == lval for w in loop.get("memory_writes") or []):
            return loop
    return None


def _guard_roots(loop: dict | None) -> set[str]:
    if not loop:
        return set()
    roots = set(_idents(str(loop.get("guard") or "")))
    for s in loop.get("scalars") or []:
        for u in s.get("updates") or []:
            roots.update(_idents(u))
    return roots


def _return_condition_roots(record: dict) -> set[str]:
    roots: set[str] = set()
    for path in record.get("return_paths") or []:
        for c in path.get("conditions") or []:
            roots.update(_idents(c))
    return roots


def _lift_dep(root: str, formals: dict[str, dict], record: dict, loops: list[dict]) -> str:
    """A caller-visible dependence root as an ACSL location: pointer roots become their region."""
    formal = formals.get(root)
    if formal and formal.get("kind") == "pointer":
        region, _, _ = _region(record, root, loops)
        return region
    return root


def compute(record: dict) -> dict:
    """Project one function record's frame information into a skeleton. Never raises."""
    if not enabled():
        return {"status": "disabled"}
    try:
        return _compute(record)
    except Exception as exc:  # a skeleton is a hint; never break facts generation
        return {"status": "partial", "separated": [], "assigns": [], "notes": [f"skeleton computation failed: {exc}"]}


def _compute(record: dict) -> dict:
    formals = {f.get("name"): f for f in record.get("formals") or [] if f.get("name")}
    caller, _ = _caller_roots(record)
    loops = record.get("loops") or []
    writes = record.get("writes") or []
    reads = record.get("reads") or []
    notes: list[str] = []
    partial = bool(record.get("truncated"))

    # --- read roots: everything a caller-visible value can flow from (data + control) ---
    read_roots: set[str] = {r.get("root") for r in reads if r.get("root")}
    value_map = _loop_value_map(record)
    for values in value_map.values():
        for v in values:
            read_roots.update(_idents(v))
    for loop in loops:
        read_roots.update(r.get("root") for r in loop.get("reads") or [] if r.get("root"))
        read_roots.update(_guard_roots(loop))
    read_roots.update(_return_condition_roots(record))
    read_roots &= caller

    written_roots: set[str] = {w.get("root") for w in writes if w.get("through_pointer") and w.get("root")}
    for loop in loops:
        written_roots.update(w.get("root") for w in loop.get("memory_writes") or [] if w.get("root"))
    written_roots &= caller

    # --- region separation: interfering pointer pairs only (no over-separation) ---
    separated: list[dict] = []
    for pair in record.get("may_alias") or []:
        a, b = pair.get("a"), pair.get("b")
        if not a or not b:
            continue
        interferes = (a in written_roots and b in read_roots) or (b in written_roots and a in read_roots)
        if not interferes:
            continue
        ra, ea, na = _region(record, a, loops)
        rb, eb, nb = _region(record, b, loops)
        partial = partial or not (ea and eb)
        for n in (na, nb):
            if n:
                notes.append(n)
        first, second = sorted((a, b))
        regions = {a: ra, b: rb}
        clause = f"requires \\separated({regions[first]}, {regions[second]});"
        separated.append(
            {
                "roots": [first, second],
                "regions": [regions[first], regions[second]],
                "clause": clause,
                "reason": f"writes through `{', '.join(pair.get('written') or [first])}` may overlap reads through the other pointer ({pair.get('reason', 'alias-compatible')})",
            }
        )
    separated.sort(key=lambda s: s["roots"])

    # --- write set + dependence footprints ---
    assigns: list[dict] = []
    seen_locs: dict[str, dict] = {}
    for w in writes:
        root = w.get("root") or ""
        if w.get("root_kind") not in ("formal", "global") or not root:
            continue
        lval = (w.get("lval") or "").strip() or root
        # Normalize a loop-indexed write to its whole written range (the paper's norm_f).
        loc = lval
        off = _offset_expr(lval, root)
        if off and off[0] == "expr":
            ck, cv = _classify_offset(str(off[1]), loops)
            if ck == "range":
                bound, incl = cv
                hi = bound if incl else f"{bound} - 1"
                loc = f"{root} + (0 .. {hi})"
            elif ck == "unknown":
                partial = True
                notes.append(f"write `{lval}` has a non-entry-expressible index; kept as written")
        entry = seen_locs.setdefault(loc, {"loc": loc, "from": set(), "source": "ast"})
        # Dependence footprint. With an AST value flow (the dump carries RHS expressions for
        # loop and straight-line writes alike): RHS roots + address/index roots + control
        # roots (enclosing-loop guard, or return-path conditions for straight-line writes).
        # Only when no RHS is known at all: sound superset of every caller-visible read root.
        loop = _loop_of_lval(record, lval)
        values = list(dict.fromkeys(list(w.get("values") or []) + list(value_map.get(lval) or [])))
        if values or loop is not None:
            deps: set[str] = set()
            for v in values:
                deps.update(_idents(v))
            if off and off[0] == "expr":
                deps.update(_idents(str(off[1])))
            deps.update(_guard_roots(loop))
            if loop is None:
                deps.update(_return_condition_roots(record))
        else:
            deps = set(read_roots) | _return_condition_roots(record)
            entry["source"] = "ast-superset"
        deps &= caller
        deps.discard(root)
        entry["from"].update(_lift_dep(d, formals, record, loops) for d in deps)

    for entry in seen_locs.values():
        froms = sorted(entry["from"])
        if froms:
            clause = f"assigns {entry['loc']} \\from {', '.join(froms)};"
        else:
            clause = f"assigns {entry['loc']} \\from \\nothing;"
        assigns.append({"loc": entry["loc"], "from": froms, "clause": clause, "source": entry["source"]})
    if not assigns:
        assigns.append({"loc": "\\nothing", "from": [], "clause": "assigns \\nothing;", "source": "ast"})
    assigns.sort(key=lambda a: a["loc"])

    return {
        "status": "partial" if partial else "ok",
        "separated": separated,
        "assigns": assigns,
        "notes": sorted(set(notes)),
    }
