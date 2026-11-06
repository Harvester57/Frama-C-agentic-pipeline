#!/usr/bin/env python3
"""
Specification knowledge base (KBSpec-style, arXiv:2606.21339v2) for ACSL.

Two sources, merged at query time:
  - seed: section-level items sliced out of the greppable reference manuals
    (docs/references/INDEX.md lines `<path>:<first>-<last>  <title>  (p. N)`),
    built once per run into `<overlay>/reports/kb/seed.json`;
  - evolved: (error -> fix) repair items mined from finished prover tasks
    (agents/<id>/scratch/candidates WP reports + artifacts/*.patch), with
    KBSpec's helpfulness triplet <helpful, harmful, neutral> and top-L pruning,
    stored in `<overlay>/reports/kb/evolved.json`.

Retrieval is deterministic keyword overlap (no embedding model in the container):
ACSL built-ins (`\\valid`, `\\separated`, ...) plus identifiers, scored against a
query built from the function's features, frame skeleton and loop classes.

Used in two places: the prover brief gets a "Retrieved ACSL Knowledge" section at
dispatch (workspace_overlay.prepare_agent, `<!-- spec-kb -->` sentinel), and
run_wp_function.derive_wp_diagnostic_hints turns failed goals into repair-pattern
hints from the evolved KB. FRAMAC_SPEC_KB=off disables everything (A/B runs).
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from framac_common import atomic_write_json, load_json_optional, utc_now  # noqa: E402

KB_ENV = "FRAMAC_SPEC_KB"
KB_SENTINEL = "<!-- spec-kb -->"
KB_SCHEMA = 1
MAX_ITEM_CHARS = 1200
TOP_G = 3
TOP_L_EVOLVED = 50
MAX_REPAIR_HINTS = 3

_STOPWORDS = frozenset(
    """the a an and or not if else for while do return int char void long short unsigned signed const
    static struct union enum typedef sizeof this that with then is in of to from by on at as it its
    be been are was were can may must should will would has have had do does did void true false null
    integer boolean logic predicate axiom lemma ghost assigns requires ensures invariant variant
    decreases terminates exits behavior complete disjoint behaviors""".split()
)

_ACSL_BUILTIN_RE = re.compile(r"\\[a-z_][a-z_0-9]*")
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_INDEX_LINE_RE = re.compile(r"^(\S+?\.md):(\d+)-(\d+)\s+(.+?)\s*\(p\. \d+\)\s*$")
_ACSL_LINE_RE = re.compile(
    r"\\(?:valid|valid_read|valid_string|valid_read_string|valid_read_nstring|separated|forall|exists|at|result|old|nothing|initialized|freeable|fresh|allocable|base_addr|block_length|offset|strlen|is_NaN|is_finite|integer|true|false)"
    r"|\b(?:loop\s+invariant|loop\s+assigns|loop\s+variant|assigns|requires|ensures|assert|decreases|terminates|exits|behavior|lemma|predicate|calls)\b"
)


def enabled() -> bool:
    """FRAMAC_SPEC_KB=off: no knowledge base, for A/B comparisons."""
    return (os.environ.get(KB_ENV) or "").strip().lower() not in ("off", "0", "false", "no", "disabled")


def _keywords(text: str) -> set[str]:
    kws = {m.group(0) for m in _ACSL_BUILTIN_RE.finditer(text or "")}
    for w in _IDENT_RE.findall(text or ""):
        lw = w.lower()
        if len(lw) > 2 and lw not in _STOPWORDS:
            kws.add(lw)
    return kws


# ---------------------------------------------------------------------------
# Seed KB from the reference manuals
# ---------------------------------------------------------------------------


def build_seed_kb(references_dir: Path) -> dict:
    """One item per INDEX.md section line, sliced out of the manual it points at."""
    items: list[dict] = []
    index = Path(references_dir) / "INDEX.md"
    if not index.is_file():
        return {"schema": KB_SCHEMA, "kind": "seed", "items": []}
    for line in index.read_text(encoding="utf-8", errors="replace").splitlines():
        m = _INDEX_LINE_RE.match(line.strip())
        if not m:
            continue
        rel, first, last, title = m.group(1), int(m.group(2)), int(m.group(3)), m.group(4).strip()
        manual = Path(references_dir) / rel
        if not manual.is_file():
            continue
        lines = manual.read_text(encoding="utf-8", errors="replace").splitlines()
        content = "\n".join(lines[max(0, first - 1) : last]).strip()
        if not content:
            continue
        if len(content) > MAX_ITEM_CHARS:
            content = content[:MAX_ITEM_CHARS] + "\n..."
        items.append(
            {
                "id": f"{rel}#{first}-{last}",
                "source": f"{rel}:{first}-{last}",
                "title": title,
                "content": content,
                "keywords": sorted(_keywords(title + "\n" + content[:3000])),
            }
        )
    return {"schema": KB_SCHEMA, "kind": "seed", "items": items, "built_at": utc_now()}


def query_kb(kb: dict, query: str, top_g: int = TOP_G) -> list[dict]:
    """Top-G items by keyword overlap with `query`; empty when nothing overlaps."""
    qk = _keywords(query)
    if not qk:
        return []
    scored = []
    for item in kb.get("items") or []:
        score = len(set(item.get("keywords") or []) & qk)
        if score:
            scored.append((score, item))
    scored.sort(key=lambda t: (-t[0], t[1].get("id", "")))
    return [item for _, item in scored[:top_g]]


# ---------------------------------------------------------------------------
# Query from a function's facts
# ---------------------------------------------------------------------------

_FEATURE_QUERY = {
    "loops": "loop invariant loop assigns loop variant decreases termination",
    "loop_reads_earlier_writes": "loop invariant forall earlier loop finished range",
    "in_place_loop": "loop invariant in-place processed unprocessed \\at LoopEntry",
    "strided_writes": "loop invariant strided linear range",
    "read_only_loop": "loop assigns loop invariant read-only loop",
    "macro_loops": "macro loop annotation preprocessor",
    "pointer_walk": "pointer walk loop invariant \\at base_addr offset pointer difference",
    "strings": "valid_read_nstring valid_read_string \\strlen nul terminated string",
    "floats": "\\is_NaN \\is_finite floating point",
    "unions": "union equality \\with struct",
    "structs": "struct field equality \\initialized padding",
    "arrays": "array \\valid_read range quantifier \\forall integer index",
    "division": "division modulo partial term guard",
    "bitwise": "bitwise shift",
    "nonlinear": "nonlinear arithmetic",
    "switch": "switch statement",
    "goto": "goto label",
    "indirect_calls": "calls function pointer \\valid_function indirect",
    "recursion": "decreases recursion lemma ghost inductive",
    "alloc": "allocates frees \\freeable \\fresh malloc dynamic allocation",
    "pointer_params": "\\valid \\separated pointer parameter",
    "pointer_len_params": "\\valid_read (0 .. n - 1) len > 0 zero-length buffer",
    "assert_literal": "assert unreachable \\false string literal",
}


def function_query(record: dict) -> str:
    """The retrieval query for one function: feature keywords + skeleton + loop classes."""
    feats = record.get("features") or {}
    parts = [_FEATURE_QUERY[name] for name, on in sorted(feats.items()) if on and name in _FEATURE_QUERY]
    q = " ".join(parts)
    skel = record.get("frame_skeleton") or {}
    for s in skel.get("separated") or []:
        q += " \\separated " + str(s.get("clause") or "")
    for a in skel.get("assigns") or []:
        q += " assigns \\from " + str(a.get("clause") or "")
    for loop in record.get("loops") or []:
        vc = loop.get("var_classes") or {}
        if vc.get("inductive"):
            q += " inductive loop invariant accumulator"
        if loop.get("guard"):
            q += " loop guard " + str(loop["guard"])
    for _ in record.get("may_alias") or []:
        q += " \\separated aliasing overlap"
    return q


# ---------------------------------------------------------------------------
# Loading and rendering
# ---------------------------------------------------------------------------


def default_references_dir() -> Path:
    env = os.environ.get("FRAMAC_REFERENCES_HOST")
    if env:
        return Path(env)
    return Path(__file__).resolve().parent.parent / "docs" / "references"


def kb_dir_of(overlay: Path) -> Path:
    return Path(overlay) / "reports" / "kb"


def load_kb(overlay: Path, references_dir: Path | None = None) -> dict:
    """Seed (built once into reports/kb/seed.json) merged with the evolved KB."""
    kb_dir = kb_dir_of(overlay)
    seed_path = kb_dir / "seed.json"
    if not seed_path.is_file():
        try:
            seed = build_seed_kb(references_dir or default_references_dir())
            atomic_write_json(seed_path, seed)
        except OSError:
            seed = {"items": []}
    else:
        seed = load_json_optional(seed_path, {})
    evolved = load_json_optional(kb_dir / "evolved.json", {})
    items = list(seed.get("items") or []) + list(evolved.get("items") or [])
    return {"schema": KB_SCHEMA, "items": items}


def kb_section_for(overlay: Path, record: dict | None, top_g: int = TOP_G) -> str:
    """The brief's 'Retrieved ACSL Knowledge' section, or "" when disabled/empty."""
    if not enabled() or record is None:
        return ""
    items = query_kb(load_kb(overlay), function_query(record), top_g)
    if not items:
        return ""
    lines = [
        "## Retrieved ACSL Knowledge",
        "",
        "Top matches from the specification knowledge base (seeded from the reference manuals under "
        "`{references_dir}`, evolved from earlier prover runs on this target) for this function's features. "
        "Read the relevant entry before writing annotations:",
        "",
    ]
    for item in items:
        title = item.get("title") or item.get("error") or item.get("id") or "item"
        lines.append(f"### {title} (`{item.get('source', '')}`)")
        lines.append("```")
        lines.append(str(item.get("content") or item.get("fix") or "")[:MAX_ITEM_CHARS])
        lines.append("```")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Evolved KB: mine (error -> fix) items from finished prover tasks
# ---------------------------------------------------------------------------


def error_signature(goal: dict, fn: str = "") -> str:
    """A function-independent signature of a failed goal: kind + annotation minus the
    `typed_<fn>_` prefix WP adds (when the function name is known), digits normalized."""
    ann = str(goal.get("annotation") or "")
    kind = str(goal.get("kind") or "")
    if fn:
        ann = re.sub(rf"^typed_{re.escape(fn)}_", "", ann)
    sig = re.sub(r"\d+", "N", ann) or ann
    return f"{kind}:{sig}"


def _added_acsl_lines(patch_text: str) -> list[str]:
    out: list[str] = []
    for line in patch_text.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            body = line[1:].strip()
            if body and _ACSL_LINE_RE.search(body):
                out.append(body)
    return out


def mine_run(run_dir: Path, kb_path: Path | None = None, top_l: int = TOP_L_EVOLVED) -> dict:
    """
    Update the evolved KB from a run directory: for each agent with a result, pair the error
    signatures seen in its candidate WP reports with the ACSL lines its merged patch added,
    and update each item's helpfulness triplet (helpful on all_proven, harmful on a stall).
    Keeps the top-L items by helpful-harmful. Never raises on a malformed run dir.
    """
    run_dir = Path(run_dir)
    kb_path = kb_path or kb_dir_of(run_dir / "workspace") / "evolved.json"
    evolved = load_json_optional(kb_path, {"schema": KB_SCHEMA, "kind": "evolved", "items": []})
    items = {it.get("id"): it for it in evolved.get("items") or [] if isinstance(it, dict)}
    agents = run_dir / "agents"
    if agents.is_dir():
        for agent in sorted(agents.iterdir()):
            if not agent.is_dir():
                continue
            result = load_json_optional(agent / "scratch" / "result.json", {})
            status = str(result.get("status") or "")
            errors: set[str] = set()
            cand_dir = agent / "scratch" / "candidates"
            if cand_dir.is_dir():
                for rep in sorted(cand_dir.rglob("wp_*.json")):
                    doc = load_json_optional(rep, {})
                    fn = str(doc.get("function") or "")
                    for g in doc.get("unproven_goals") or []:
                        if isinstance(g, dict):
                            errors.add(error_signature(g, fn))
            fixes: list[str] = []
            arts = agent / "artifacts"
            if arts.is_dir():
                for patch in sorted(arts.glob("*.patch")):
                    try:
                        fixes.extend(_added_acsl_lines(patch.read_text(encoding="utf-8", errors="replace")))
                    except OSError:
                        continue
            if not errors or not fixes:
                continue
            fix_blob = " | ".join(dict.fromkeys(fixes))[:MAX_ITEM_CHARS]
            for sig in sorted(errors):
                iid = f"err:{sig}"
                item = items.setdefault(
                    iid,
                    {
                        "id": iid,
                        "kind": "repair",
                        "error": sig,
                        "fix": "",
                        "source": agent.name,
                        "helpful": 0,
                        "harmful": 0,
                        "neutral": 0,
                        "keywords": [],
                    },
                )
                if status == "all_proven":
                    item["helpful"] = item.get("helpful", 0) + 1
                elif status:
                    item["harmful"] = item.get("harmful", 0) + 1
                else:
                    item["neutral"] = item.get("neutral", 0) + 1
                # A verified trajectory's fix wins over a stalled one's.
                if status == "all_proven" or not item.get("fix"):
                    item["fix"] = fix_blob
                item["source"] = agent.name
                item["keywords"] = sorted(_keywords(sig + " " + str(item.get("fix") or fix_blob)))
    ranked = sorted(items.values(), key=lambda it: (-(it.get("helpful", 0) - it.get("harmful", 0)), str(it.get("id"))))
    evolved["items"] = ranked[:top_l]
    evolved["updated_at"] = utc_now()
    try:
        atomic_write_json(kb_path, evolved)
    except OSError:
        pass
    return evolved


def repair_hints_for_goals(res: dict, kb_dir: Path) -> list[str]:
    """Repair-pattern hints from the evolved KB for the report's failed goals."""
    if not enabled():
        return []
    evolved = load_json_optional(Path(kb_dir) / "evolved.json", {})
    items = [it for it in evolved.get("items") or [] if it.get("kind") == "repair"]
    if not items:
        return []
    hints: list[str] = []
    fn = str(res.get("function") or "")
    for g in res.get("unproven_goals") or []:
        if not isinstance(g, dict):
            continue
        sig = error_signature(g, fn)
        matches = query_kb({"items": items}, sig + " " + str(g.get("annotation") or ""), top_g=1)
        for m in matches:
            fix = str(m.get("fix") or "").strip()
            if fix:
                hints.append(f"Repair pattern from earlier runs for `{sig}`: {fix[:300]}")
        if len(hints) >= MAX_REPAIR_HINTS:
            break
    return hints[:MAX_REPAIR_HINTS]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Specification knowledge base: seed, query, mine.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_seed = sub.add_parser("build-seed", help="Build the seed KB from the reference manuals")
    p_seed.add_argument("--references", type=Path, default=None)
    p_seed.add_argument("--out", type=Path, required=True)
    p_q = sub.add_parser("query", help="Query a KB file")
    p_q.add_argument("--kb", type=Path, required=True)
    p_q.add_argument("--query", required=True)
    p_q.add_argument("--top-g", type=int, default=TOP_G)
    p_m = sub.add_parser("mine", help="Mine (error->fix) items from a run directory into the evolved KB")
    p_m.add_argument("--run-dir", type=Path, required=True)
    p_m.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)
    if args.cmd == "build-seed":
        kb = build_seed_kb(args.references or default_references_dir())
        atomic_write_json(args.out, kb)
        print(f"seed: {len(kb['items'])} items -> {args.out}")
        return 0
    if args.cmd == "query":
        kb = load_json_optional(args.kb, {})
        for item in query_kb(kb, args.query, args.top_g):
            print(f"{item.get('id')}  {item.get('title') or item.get('error') or ''}")
        return 0
    if args.cmd == "mine":
        evolved = mine_run(args.run_dir, args.out)
        print(f"evolved: {len(evolved.get('items') or [])} items")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
