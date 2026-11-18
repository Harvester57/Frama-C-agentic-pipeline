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
      "unprojected": [{"lval": W, "root": r, "line": n, "reason": "...",
                       "loop": {"line": n, "header": "...", "guard": "..."}}],
      "notes":     ["..."],
    }

Every required clause is one a function contract can state: it names formals, globals, fields,
cast types and literals only, and the kernel accepts its form (the cells `*(p + (lo .. hi))` in
`assigns` and after `\\from`; the address set `p + (lo .. hi)` only inside `\\separated`). A write
whose location names a local (an alias of a formal such as `ctx_tcp->t_id`, a loop index the facts
do not bound in entry terms, a location the kernel only names through a temporary) is NOT required:
it goes to `unprojected` with the reason (`loop` only for a write inside a loop) and to one `notes`
line, so the brief shows it as a hint and a reader sees that the minimum is incomplete there.

An `assigns` entry whose dependencies the facts do not give (several recorded values, a value
through a local, a value reading the written object itself, a loop reading memory the value flow
does not account for) carries `"from": []`, the clause `assigns L;` without `\\from`, and
`"from_unknown": true`. acsl_ast.check_frame_preserved then asks for the location only: any
candidate clause listing L covers it, whatever its `\\from`.

`partial` means some region/dependence was approximated (strongest entry-expressible
form) or left out; the prover must check it against the code. `assigns \\nothing` is projected only when
the function writes nothing caller-visible directly AND every call it makes reaches a module
function that writes nothing either, transitively (`write_free_callees`, computed over the
module by function_facts); otherwise a function without direct writes gets no assigns entry,
status `partial`, and a note naming the calls that may write. FRAMAC_FRAME_SKELETON=off disables
the projection (A/B ablation), yielding {"status": "disabled"}.
"""

from __future__ import annotations

import os
import re
from collections.abc import Collection

SKELETON_ENV = "FRAMAC_FRAME_SKELETON"
MAX_BLOCKERS_SHOWN = 6

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


def _bracket_group(text: str, open_idx: int) -> tuple[str, int] | None:
    """Inner text of the bracket group opening at `open_idx`, and the index after its close."""
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "[":
            depth += 1
        elif text[i] == "]":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1 : i], i + 1
    return None


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
        if inner.strip() == root:
            return "zero", "0"
        return None
    if re.match(rf"^\*\s*{r}(\s|$|->|\.|\[)", lv):
        return "zero", "0"
    if re.match(rf"^{r}\s*\[", lv):
        open_b = lv.find("[")
        res = _bracket_group(lv, open_b)
        if res is not None:
            inner, _ = res
            return "expr", inner.strip()
        return None
    if re.match(rf"^{r}\s*(->|\.)", lv):
        return "zero", "0"
    if re.match(rf"^\(\s*\*\s*{r}\s*\)\s*\.", lv):
        return "zero", "0"
    return None


def _strip_matching_parens(s: str) -> str:
    s = s.strip()
    while s.startswith("(") and s.endswith(")"):
        depth = 0
        matching = True
        for i, ch in enumerate(s):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and i < len(s) - 1:
                    matching = False
                    break
        if matching:
            s = s[1:-1].strip()
        else:
            break
    return s


def _simple_bound(text: str, entry: Collection[str] | None) -> bool:
    """One integer literal, or one identifier (with `entry` given: one a contract can name at entry)."""
    if _INT_RE.fullmatch(text):
        return True
    return bool(_IDENT_RE.fullmatch(text)) and (entry is None or text in entry)


def _guard_bound(e: str, loops: list[dict], entry: Collection[str] | None = None) -> tuple[dict, str, bool] | None:
    """(loop, bound, inclusive) for the loop whose guard bounds the index `e` from above by a simple bound."""
    for loop in loops:
        scalars = {s.get("var") for s in loop.get("scalars") or []}
        if e not in scalars:
            continue
        guard = str(loop.get("guard") or "")
        if not guard or "||" in guard:
            continue

        var_re = rf"^(?:\([^)]+\)\s*)?{re.escape(e)}$"
        conjuncts = [c.strip() for c in guard.split("&&")]
        for c in conjuncts:
            c = _strip_matching_parens(c)

            # Forward: <lhs: e> (<|<=) <rhs: bound>
            m_fwd = re.match(r"^(?P<lhs>.+?)\s*(?P<op><=|<=?)\s*(?P<rhs>.+)$", c)
            if m_fwd:
                lhs = m_fwd.group("lhs").strip()
                op = m_fwd.group("op").strip()
                rhs = m_fwd.group("rhs").strip()
                if re.match(var_re, lhs):
                    return (loop, rhs, op == "<=") if _simple_bound(rhs, entry) else None

            # Reverse: <lhs: bound> (>|>=) <rhs: e>
            m_rev = re.match(r"^(?P<lhs>.+?)\s*(?P<op>>=|>=?)\s*(?P<rhs>.+)$", c)
            if m_rev:
                lhs = m_rev.group("lhs").strip()
                op = m_rev.group("op").strip()
                rhs = m_rev.group("rhs").strip()
                if re.match(var_re, rhs):
                    return (loop, lhs, op == ">=") if _simple_bound(lhs, entry) else None
    return None


def _classify_offset(
    expr: str, loops: list[dict], entry: Collection[str] | None = None
) -> tuple[str, int | tuple[str, bool] | None]:
    """
    ("const", int) | ("range", (bound, inclusive)) | ("unknown", None). With `entry` (the names a
    contract can use, see `_entry_names`), a bound that is a local is "unknown": `p + (0 .. len - 1)`
    with `len` a local cannot be written in a contract.
    """
    e = expr.strip()
    if _INT_RE.fullmatch(e):
        return "const", int(e.rstrip("uUlL"))
    if _IDENT_RE.fullmatch(e):
        found = _guard_bound(e, loops, entry)
        if found is not None:
            return "range", (found[1], found[2])
    return "unknown", None


# ---------------------------------------------------------------------------
# Entry-expressibility: what a function contract can name
# ---------------------------------------------------------------------------

_NAME_OR_NUMBER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|\d+(?:\.\d+)?[A-Za-z0-9_]*")
_TYPE_NAME_RE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*(?:\s+[A-Za-z_][A-Za-z0-9_]*)*(?:\s*\*\s*(?:(?:const|volatile|restrict)\s*)*)*"
)


def _cast_spans(text: str) -> list[tuple[int, int]]:
    """
    Spans of the casts `(T)` in a kernel-printed expression. Conservative: a group that could be a
    parenthesised operand (`(a) * b`) or an argument list (`f(a)`) is not a cast, so its name is seen.
    """
    spans: list[tuple[int, int]] = []
    for i, ch in enumerate(text):
        if ch != "(":
            continue
        inner, end = _paren_group(text, i)
        inner = inner.strip()
        if not _TYPE_NAME_RE.fullmatch(inner):
            continue
        before = text[:i].rstrip()[-1:]
        if before and (before.isalnum() or before in "_)]"):
            continue
        after = text[end:].lstrip()[:1]
        typed = "*" in inner or len(inner.split()) > 1
        if after and (after.isalnum() or after in "_(" or (typed and after in "*&-+!~")):
            spans.append((i, end))
    return spans


def _without_casts(text: str) -> str:
    out = text
    for start, end in reversed(_cast_spans(text)):
        out = out[:start] + out[end:]
    return out


def _free_names(expr: str | None) -> list[str]:
    """
    The names an expression takes its meaning from: every identifier that is not a field name (after
    `->` or `.`), the type of a cast or part of a literal. A contract can state the expression only if
    each of them is a formal or a global.
    """
    text = expr or ""
    casts = _cast_spans(text)
    out: list[str] = []
    for m in _NAME_OR_NUMBER_RE.finditer(text):
        name = m.group(0)
        if name[0].isdigit() or any(start <= m.start() < end for start, end in casts):
            continue
        before = text[: m.start()].rstrip()
        if before.endswith("->") or (before.endswith(".") and not before.endswith("..")):
            continue
        if name not in out:
            out.append(name)
    return out


def _loop_scalars(loop: dict | None) -> set[str]:
    return {str(s.get("var")) for s in (loop or {}).get("scalars") or [] if s.get("var")}


def _entry_names(record: dict, caller: set[str]) -> set[str]:
    """
    The names a function contract can use for a written location: formals and globals, less those a
    loop of the function changes (a walked pointer or a counted-down length no longer holds its entry
    value at the write). A formal changed outside a loop is not in the facts and stays in.
    """
    changed: set[str] = set()
    for loop in record.get("loops") or []:
        changed |= _loop_scalars(loop)
    return (caller | _access_roots(record)) - changed


def _access_roots(record: dict) -> set[str]:
    """
    Roots the accesses themselves mark as a formal or a global, and globals under the name the kernel
    prints them by where it differs from the recorded root: `errno` is rooted at `__fc_errno`, and a
    contract says `errno`.
    """
    out: set[str] = set()
    for item in list(record.get("writes") or []) + list(record.get("reads") or []):
        if item.get("root_kind") in ("formal", "global") and item.get("root"):
            out.add(str(item["root"]))
        if item.get("root_kind") == "global" and not item.get("through_pointer"):
            m = _IDENT_RE.match(str(item.get("lval") or ""))
            if m:
                out.add(m.group(0))
    return out


def _index_start(var: str, loop: dict) -> int | None:
    """The non-negative literal the loop's `for` header sets `var` to; None when the facts show none."""
    header = str(loop.get("header") or "")
    m = re.match(r"^for\s*\(", header)
    if not m or ";" not in header[m.end() :]:
        return None
    init = header[m.end() :].split(";", 1)[0].strip()
    found = re.search(rf"(?:^|[\s,*]){re.escape(var)}\s*=\s*(\d+)[uUlL]*\s*(?:,|$)", init)
    return int(found.group(1)) if found else None


def _counts_up(var: str, loop: dict) -> bool:
    """Every recorded update of `var` in the loop is `var + <positive literal>`."""
    updates = [u for s in loop.get("scalars") or [] if s.get("var") == var for u in s.get("updates") or []]
    step_re = rf"{re.escape(var)}\s*\+\s*[1-9]\d*[uUlL]*"
    return bool(updates) and all(re.fullmatch(step_re, _strip_matching_parens(_without_casts(str(u)))) for u in updates)


def _written_range(index: str, loops: list[dict], entry: Collection[str]) -> tuple[str, str] | None:
    """
    (lo, hi) of the cells a loop writes through the index `index`, only when the facts give both bounds
    in entry terms: the guard bounds the index by a literal or by a formal or global no loop changes, the
    `for` header starts it at a literal, and it only counts up. Anything else is None: the range is then
    for the prover to state, not for the skeleton to require.
    """
    var = index.strip()
    if not _IDENT_RE.fullmatch(var):
        return None
    found = _guard_bound(var, loops, entry)
    if found is None:
        return None
    loop, bound, inclusive = found
    start = _index_start(var, loop)
    if start is None or not _counts_up(var, loop):
        return None
    return str(start), bound if inclusive else f"{bound} - 1"


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


def _region(
    record: dict, root: str, loops: list[dict], entry: Collection[str] | None = None
) -> tuple[str, bool, str | None]:
    """
    (region text, exact, note). Strongest entry-expressible approximation of Omega(root): a set of
    addresses (`root + (lo .. hi)`), as `\\separated` takes it. With `entry`, a range bounded by a local
    is not used: the region falls back to `root`.
    """
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
        ck, cv = _classify_offset(str(val), loops, entry)
        if ck == "const" and isinstance(cv, int):
            consts.append(cv)
        elif ck == "range" and isinstance(cv, tuple):
            ranges.append(cv)
        else:
            unknown = True
    if unknown:
        return (
            root,
            False,
            f"access window of `{root}` is not fully entry-expressible; `{root}` alone is an approximation",
        )
    if ranges:
        # Deterministic pick: the first range in source order; note when several differ.
        bound, incl = ranges[0]
        hi_b = bound if incl else f"{bound} - 1"
        note = None
        if len({(b, i) for b, i in ranges}) > 1:
            note = f"multiple access windows on `{root}`; using the first (`0 .. {hi_b}`)"
        if consts and (min(consts) < 0 or max(consts) > 0):
            note = (note + "; " if note else "") + f"constant offsets on `{root}` folded into the range"
        return f"{root} + (0 .. {hi_b})", True, note
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


def _lift_dep(
    root: str, formals: dict[str, dict], record: dict, loops: list[dict], entry: Collection[str] | None = None
) -> str:
    """
    A caller-visible dependence root as an ACSL location: a pointer root with a known access window
    becomes the cells of that window, `*(root + (lo .. hi))`. The window itself, `root + (lo .. hi)`,
    is a set of addresses, which the kernel refuses after `\\from` ("not a valid dependency").
    """
    formal = formals.get(root)
    if formal and formal.get("kind") == "pointer":
        region, _, _ = _region(record, root, loops, entry)
        return region if region == root else f"*({region})"
    return root


def _from_doubt(
    values: list[str], index: str | None, root: str, loop: dict | None, deps: set[str], caller: set[str]
) -> str | None:
    """
    Why the facts do not give the dependencies of a write; None when the recorded value flow accounts
    for it. A projected `\\from` is copied into contracts, so an understated one states something false.
    """
    if len(values) > 1:
        return "it is written with several values, and the condition that picks one is not in the facts"
    known = caller | _loop_scalars(loop)
    texts = values + ([index] if index else [])
    foreign = list(dict.fromkeys(n for text in texts for n in _free_names(text) if n not in known))
    if foreign:
        shown = ", ".join(f"`{n}`" for n in foreign)
        return f"its value or index names {shown}, which the facts do not show to be a formal or a global"
    if any(root in _free_names(v) for v in values):
        return f"its value reads through `{root}` itself, which the projected footprint leaves out"
    if loop is not None:
        loop_reads = {str(r.get("root")) for r in loop.get("reads") or [] if r.get("root") in caller}
        unread = sorted(loop_reads - deps - {root})
        if unread:
            shown = ", ".join(f"`{n}`" for n in unread)
            return f"the loop also reads through {shown}, and the facts do not say whether the value depends on it"
    return None


def _unexpressible(loc: str, record: dict, entry: Collection[str], caller: Collection[str]) -> str | None:
    """Why a contract cannot state `loc` (it names something that is not a formal or a global at entry)."""
    names = [n for n in _free_names(loc) if n not in entry]
    if not names:
        return None
    derived = record.get("derived_pointers")
    derived = derived if isinstance(derived, dict) else {}
    loop_vars: set[str] = set()
    for loop in record.get("loops") or []:
        loop_vars |= _loop_scalars(loop)
    parts: list[str] = []
    for name in names:
        if name in derived:
            parts.append(
                f"`{name}` is a local pointer derived from `{derived[name]}`, and the facts do not record "
                "the expression it holds"
            )
        elif name in caller:
            parts.append(f"`{name}` is changed by a loop, so it no longer holds its entry value at the write")
        elif name in loop_vars:
            parts.append(f"`{name}` is a loop variable, and the facts give no bounds for it that hold at entry")
        else:
            parts.append(f"`{name}` is not a formal or a global")
    return "; ".join(parts)


def writes_nothing_directly(record: dict) -> bool:
    """
    No caller-visible write in the function's own body: no write rooted at a formal or a global, no
    write through a pointer the facts cannot attribute (a local not derived from a formal), and a
    complete (not truncated) record. Calls are not looked at here: see `call_blockers`.
    """
    if record.get("truncated"):
        return False
    for w in record.get("writes") or []:
        if w.get("root_kind") != "local" or w.get("through_pointer"):
            return False
    for loop in record.get("loops") or []:
        for w in loop.get("memory_writes") or []:
            if w.get("root_kind") != "local":
                return False
    return True


def call_target(call: dict) -> str | None:
    """The kernel name a direct call reaches (older facts carry only `callee`); None for an indirect call."""
    if call.get("indirect"):
        return None
    return call.get("kernel_name") or call.get("callee") or None


def call_blockers(record: dict, write_free_callees: Collection[str] | None) -> list[str]:
    """
    The calls through which the function may write caller-visible memory: an indirect call, or a
    callee not in `write_free_callees` (the module's functions that write nothing, transitively;
    function_facts computes it). Without that verdict (None) every call may write.
    """
    out: list[str] = []
    for call in record.get("calls") or []:
        target = call_target(call)
        if target is None:
            out.append(f"an indirect call (`{call.get('expr') or '?'}`)")
        elif write_free_callees is None or target not in write_free_callees:
            out.append(f"`{call.get('callee') or target}`")
    return list(dict.fromkeys(out))


def compute(record: dict, write_free_callees: Collection[str] | None = None) -> dict:
    """
    Project one function record's frame information into a skeleton. Never raises.

    `write_free_callees`: kernel names of the module's functions that cannot write caller-visible
    memory, even through their own calls. `assigns \\nothing` is projected only for a function with no
    direct write whose every call reaches one of them; None means "unknown", so any call blocks it.
    """
    if not enabled():
        return {"status": "disabled"}
    try:
        return _compute(record, write_free_callees)
    except Exception as exc:  # a skeleton is a hint; never break facts generation
        return {
            "status": "partial",
            "separated": [],
            "assigns": [],
            "unprojected": [],
            "notes": [f"skeleton computation failed: {exc}"],
        }


def _compute(record: dict, write_free_callees: Collection[str] | None = None) -> dict:
    formals = {f.get("name"): f for f in record.get("formals") or [] if f.get("name")}
    caller, _ = _caller_roots(record)
    loops = record.get("loops") or []
    writes = record.get("writes") or []
    reads = record.get("reads") or []
    notes: list[str] = []
    partial = bool(record.get("truncated"))
    entry_names = _entry_names(record, caller)

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
        ra, ea, na = _region(record, a, loops, entry_names)
        rb, eb, nb = _region(record, b, loops, entry_names)
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
    unprojected: list[dict] = []
    seen_locs: dict[str, dict] = {}
    for w in writes:
        root = w.get("root") or ""
        if w.get("root_kind") not in ("formal", "global") or not root:
            continue
        lval = (w.get("lval") or "").strip()
        loop = _loop_of_lval(record, lval)
        # Normalize a loop-indexed write to the cells it writes (the paper's norm_f), when the facts
        # bound the index in entry terms. `*(root + (lo .. hi))`: the kernel refuses the bare address
        # set `root + (lo .. hi)` in `assigns` ("not an assignable left value").
        loc = lval or root
        off = _offset_expr(loc, root)
        if off and off[0] == "expr":
            writing = [lp for lp in loops if any(m.get("lval") == lval for m in lp.get("memory_writes") or [])]
            span = _written_range(str(off[1]), writing, entry_names)
            if span is not None:
                loc = f"*({root} + ({span[0]} .. {span[1]}))"
        # A required clause must be one a contract can state: a location naming a local (an alias of
        # a formal, a loop index) is recorded as not projected instead, with the reason.
        if not lval and w.get("through_pointer"):
            why: str | None = (
                f"the kernel names the written location through a temporary, so the facts do not say "
                f"which part of `{root}` is written"
            )
        else:
            why = _unexpressible(loc, record, entry_names, caller)
        if why:
            partial = True
            item: dict = {"lval": lval or None, "root": root, "line": w.get("line"), "reason": why}
            if loop is not None:
                item["loop"] = {key: loop.get(key) for key in ("line", "header", "guard")}
            if not any(u["lval"] == item["lval"] and u["root"] == root for u in unprojected):
                unprojected.append(item)
            notes.append(
                f"not required, so the minimum is incomplete here: the write to `{lval or root}` cannot be "
                f"stated in a contract as written ({why}); state the location it reaches over the formals "
                "and globals yourself"
            )
            continue
        entry = seen_locs.setdefault(loc, {"loc": loc, "from": set(), "source": "ast", "doubts": []})
        # Dependence footprint. With an AST value flow (the dump carries RHS expressions for
        # loop and straight-line writes alike): RHS roots + address/index roots + control
        # roots (enclosing-loop guard, or return-path conditions for straight-line writes).
        # Only when no RHS is known at all: sound superset of every caller-visible read root.
        values = list(dict.fromkeys(list(w.get("values") or []) + list(value_map.get(lval) or [])))
        index = str(off[1]) if off and off[0] == "expr" else None
        if values or loop is not None:
            deps: set[str] = set()
            for v in values:
                deps.update(_idents(v))
            if index:
                deps.update(_idents(index))
            deps.update(_guard_roots(loop))
            if loop is None:
                deps.update(_return_condition_roots(record))
        else:
            deps = set(read_roots) | _return_condition_roots(record)
            entry["source"] = "ast-superset"
        deps &= caller
        doubt = _from_doubt(values, index, root, loop, deps, caller | _access_roots(record))
        if doubt:
            entry["doubts"].append(doubt)
        deps.discard(root)
        entry["from"].update(_lift_dep(d, formals, record, loops, entry_names) for d in deps)

    for entry in seen_locs.values():
        if entry["doubts"]:
            # The facts do not give the dependencies: the location is required, a `\from` is not.
            partial = True
            notes.append(
                f"no `\\from` is projected for `{entry['loc']}`: {entry['doubts'][0]}; only the location is "
                "required, add the `\\from` you can justify"
            )
            assigns.append(
                {
                    "loc": entry["loc"],
                    "from": [],
                    "clause": f"assigns {entry['loc']};",
                    "source": entry["source"],
                    "from_unknown": True,
                }
            )
            continue
        froms = sorted(entry["from"])
        if froms:
            clause = f"assigns {entry['loc']} \\from {', '.join(froms)};"
        else:
            clause = f"assigns {entry['loc']} \\from \\nothing;"
        assigns.append({"loc": entry["loc"], "from": froms, "clause": clause, "source": entry["source"]})
    if not assigns:
        # `\nothing` only when nothing caller-visible can be written: not directly, not through a call.
        blockers = call_blockers(record, write_free_callees)
        if unprojected:
            notes.append(
                "no `assigns \\nothing` projected: the function writes caller-visible memory at locations "
                "the skeleton could not state (the writes noted as not required)"
            )
        elif not writes_nothing_directly(record):
            partial = True
            notes.append(
                "no `assigns \\nothing` projected: the body writes through a pointer the facts cannot "
                "attribute to a formal or a global, or the record is truncated"
            )
        elif blockers:
            partial = True
            shown = ", ".join(blockers[:MAX_BLOCKERS_SHOWN]) + (", ..." if len(blockers) > MAX_BLOCKERS_SHOWN else "")
            notes.append(
                f"no `assigns \\nothing` projected: the function may write through {shown} "
                "(a callee of this module that writes, possibly transitively, an indirect call, or a "
                "function outside the module); state what those calls assign"
            )
        else:
            assigns.append({"loc": "\\nothing", "from": [], "clause": "assigns \\nothing;", "source": "ast"})
    assigns.sort(key=lambda a: a["loc"])

    return {
        "status": "partial" if partial else "ok",
        "separated": separated,
        "assigns": assigns,
        "unprojected": unprojected,
        "notes": sorted(set(notes)),
    }
