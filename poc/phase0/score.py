#!/usr/bin/env python3
"""
Phase 0 PoC scorer: the current lexer extractor (scripts/build_callgraph_dag.py, read-only) against
the new one (phase0b.py), on reproducers with exact ground truth and on the benchmark targets.

    score.py reproducers --dir poc/phase0/reproducers --out OUT [--only rNN_...]
    score.py targets --targets poc/phase0/targets.json --checkouts DIR --manifest benchmark/manifest.json --out OUT

Writes OUT/results.json and OUT/results.md. Runs inside the framac-pipeline image (phase0b needs
bear, frama-c, gcc, nm); the lexer extractor only needs python3.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
OLD_EXTRACTOR = REPO / "scripts" / "build_callgraph_dag.py"
NEW_EXTRACTOR = HERE / "phase0b.py"

sys.path.insert(0, str(HERE))
import phase0b  # noqa: E402

# --- Running both extractors ---------------------------------------------------------------------


def run_old(target: Path, out: Path) -> dict:
    """The current extractor, as Phase 0 runs it today (no compile_commands), converted to the model."""
    out.mkdir(parents=True, exist_ok=True)
    work = out / "work-old"
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(target, work, symlinks=True, ignore=shutil.ignore_patterns(".git"))
    dag_path = out / "callgraph_dag.json"
    t0 = time.monotonic()
    proc = subprocess.run(
        [sys.executable, str(OLD_EXTRACTOR), "--target", str(work), "--out", str(dag_path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=1800,
    )
    seconds = round(time.monotonic() - t0, 2)
    if proc.returncode != 0 or not dag_path.is_file():
        return {"status": "failed", "error": (proc.stderr or proc.stdout)[-800:], "seconds": seconds}
    return old_to_model(json.loads(dag_path.read_text(encoding="utf-8")), seconds)


def old_to_model(dag: dict, seconds: float) -> dict:
    fns = dag.get("functions", {})
    key_to_id = {k: f"{r['file']}#{r.get('name', k)}" for k, r in fns.items()}
    functions = {
        key_to_id[k]: {
            "file": r["file"],
            "name": r.get("name", k),
            "static": r.get("is_static", False),
            "units": [r.get("module")],
        }
        for k, r in fns.items()
    }
    edges = []
    for k, r in fns.items():
        for c in r.get("internal_callees", []):
            if c in key_to_id:
                edges.append({"caller": key_to_id[k], "callee": key_to_id[c], "kind": "direct", "sources": ["lexer"]})
    units = {
        name: {
            "kind": "module",
            "files": m.get("files", []),
            "links": [],
            "entry_points": [key_to_id[e] for e in m.get("candidate_entry_points", []) if e in key_to_id],
        }
        for name, m in dag.get("modules", {}).items()
    }
    return {
        "status": "ok",
        "extractor": "lexer",
        "functions": functions,
        "edges": edges,
        "units": units,
        "entry_points": sorted({e for u in units.values() for e in u["entry_points"]}),
        "thread_entries": [],
        "indirect_sites": [],
        "seconds": seconds,
    }


def run_new(target: Path, out: Path, build: str) -> dict:
    try:
        m = phase0b.extract(target, out, build, timeout=1800)
    except Exception as exc:  # the PoC reports, it does not stop the comparison
        return {"status": "failed", "error": f"{type(exc).__name__}: {exc}"}
    m["status"] = "ok" if m["build"]["status"] == "ok" else "build_failed"
    return m


# --- Scoring --------------------------------------------------------------------------------------


def pr(pred: set, truth: set) -> dict:
    tp = len(pred & truth)
    return {
        "precision": round(tp / len(pred), 3) if pred else (1.0 if not truth else 0.0),
        "recall": round(tp / len(truth), 3) if truth else 1.0,
        "tp": tp,
        "fp": sorted(pred - truth)[:20],
        "fn": sorted(truth - pred)[:20],
    }


def edge_set(model: dict, kind: str) -> set:
    return {(e["caller"], e["callee"]) for e in model.get("edges", []) if e["kind"] == kind}


def unit_match(model: dict, truth_units: dict) -> dict:
    """How many ground-truth link units appear with exactly their file set."""
    pred_sets = [frozenset(u.get("files", [])) for u in model.get("units", {}).values() if u.get("files")]
    exact = [n for n, u in truth_units.items() if frozenset(u["files"]) in pred_sets]
    return {"exact": len(exact), "of": len(truth_units), "missing": sorted(set(truth_units) - set(exact))}


def score_model(model: dict, truth: dict) -> dict:
    if model.get("status") not in ("ok",):
        return {"status": model.get("status"), "error": model.get("error") or model.get("build", {}).get("log_tail")}
    fset = set(model.get("functions", {}))
    return {
        "status": "ok",
        "functions": pr(fset, set(truth["functions"])),
        "not_compiled_reported": sorted(fset & set(truth.get("not_compiled", []))),
        "direct_edges": pr(
            edge_set(model, "direct"), {(e["caller"], e["callee"]) for e in truth["edges"] if e["kind"] == "direct"}
        ),
        "indirect_edges": pr(
            edge_set(model, "indirect"), {(e["caller"], e["callee"]) for e in truth["edges"] if e["kind"] == "indirect"}
        ),
        "entry_points": pr(set(model.get("entry_points", [])), set(truth.get("entry_points", []))),
        "thread_entries": pr(set(model.get("thread_entries", [])), set(truth.get("thread_entries", []))),
        "units": unit_match(model, truth.get("units", {})),
        "seconds": model.get("seconds"),
    }


def cmd_reproducers(args: argparse.Namespace) -> int:
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    results = {}
    for d in sorted(Path(args.dir).iterdir()):
        truth_path = d / "truth.json"
        if not truth_path.is_file() or (args.only and d.name not in args.only):
            continue
        truth = json.loads(truth_path.read_text(encoding="utf-8"))
        old = run_old(d, out / d.name / "old")
        new = run_new(d, out / d.name / "new", truth.get("build", "make"))
        results[d.name] = {
            "description": truth.get("description", ""),
            "old": score_model(old, truth),
            "new": score_model(new, truth),
        }
        print(
            f"{d.name}: old={summary_line(results[d.name]['old'])} new={summary_line(results[d.name]['new'])}",
            flush=True,
        )
    (out / "results.json").write_text(json.dumps(results, indent=1) + "\n", encoding="utf-8")
    (out / "results.md").write_text(render_reproducers(results), encoding="utf-8")
    return 0


def summary_line(s: dict) -> str:
    if s.get("status") != "ok":
        return s.get("status") or "?"
    return "F{:.2f}/{:.2f} D{:.2f}/{:.2f} I{:.2f} E{:.2f}/{:.2f} U{}/{}".format(
        s["functions"]["precision"],
        s["functions"]["recall"],
        s["direct_edges"]["precision"],
        s["direct_edges"]["recall"],
        s["indirect_edges"]["recall"],
        s["entry_points"]["precision"],
        s["entry_points"]["recall"],
        s["units"]["exact"],
        s["units"]["of"],
    )


def _cell(s: dict, key: str) -> str:
    if s.get("status") != "ok":
        return s.get("status") or "?"
    v = s[key]
    if key == "units":
        return f"{v['exact']}/{v['of']}"
    return f"{v['precision']:.2f} / {v['recall']:.2f}"


def render_reproducers(results: dict) -> str:
    cols = [
        ("functions", "Functions P/R"),
        ("direct_edges", "Direct edges P/R"),
        ("indirect_edges", "Indirect edges P/R"),
        ("entry_points", "Entry points P/R"),
        ("thread_entries", "Thread entries P/R"),
        ("units", "Units exact"),
    ]
    lines = ["# Phase 0 PoC: reproducers", "", "Each cell: current lexer → new extractor.", ""]
    lines.append("| Reproducer | " + " | ".join(c[1] for c in cols) + " | Not-compiled reported |")
    lines.append("| :--- |" + " :--- |" * (len(cols) + 1))
    for name, r in results.items():
        cells = [f"{_cell(r['old'], k)} → {_cell(r['new'], k)}" for k, _ in cols]
        nc = f"{len(r['old'].get('not_compiled_reported', []))} → {len(r['new'].get('not_compiled_reported', []))}"
        lines.append(f"| `{name}` | " + " | ".join(cells) + f" | {nc} |")
    lines += ["", "## Misses and false positives", ""]
    for name, r in results.items():
        for side in ("old", "new"):
            s = r[side]
            if s.get("status") != "ok":
                lines.append(f"- `{name}` {side}: {s.get('status')}: {str(s.get('error'))[:300]}")
                continue
            for k, _ in cols[:-1]:
                if s[k]["fn"] or s[k]["fp"]:
                    lines.append(f"- `{name}` {side} {k}: missed {s[k]['fn'][:6]}, extra {s[k]['fp'][:6]}")
            if s["units"]["missing"]:
                lines.append(f"- `{name}` {side} units not matched: {s['units']['missing']}")
    return "\n".join(lines) + "\n"


# --- Benchmark targets -----------------------------------------------------------------------------


def reachable(model: dict, roots: set) -> set:
    succ = defaultdict(set)
    for e in model.get("edges", []):
        succ[e["caller"]].add(e["callee"])
    seen, work = set(), list(roots)
    while work:
        n = work.pop()
        if n in seen:
            continue
        seen.add(n)
        work += succ[n] - seen
    return seen


def target_report(model: dict, bugs: list[dict]) -> dict:
    if model.get("status") != "ok":
        return {"status": model.get("status"), "error": model.get("error") or model.get("build", {}).get("log_tail")}
    fns = model.get("functions", {})
    reach = reachable(model, set(model.get("entry_points", [])))
    bug_rows = []
    for b in bugs:
        hits = [
            fid
            for fid, f in fns.items()
            if f["name"] == b["function"] and (f["file"] == b["file"] or f["file"].endswith("/" + b["file"]))
        ]
        bug_rows.append(
            {
                "bug": b["id"],
                "function": f"{b['file']}#{b['function']}",
                "inventoried": bool(hits),
                "reachable_from_entry": any(h in reach for h in hits),
            }
        )
    units = model.get("units", {})
    return {
        "status": "ok",
        "functions": len(fns),
        "direct_edges": len(edge_set(model, "direct")),
        "indirect_edges": len(edge_set(model, "indirect")),
        "indirect_sites": len(model.get("indirect_sites", [])),
        "units": len(units),
        "entry_points": len(model.get("entry_points", [])),
        "unreachable_functions": len(set(fns) - reach),
        "parse_failed_units": sorted(
            n for n, u in units.items() if u.get("frama_c", {}).get("status") == "parse_failed"
        ),
        "bugs": bug_rows,
        "seconds": model.get("seconds"),
    }


def cmd_targets(args: argparse.Namespace) -> int:
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    by_id = {t["id"]: t for t in manifest["targets"]}
    specs = json.loads(Path(args.targets).read_text(encoding="utf-8"))
    results = {}
    for tid, spec in specs.items():
        if args.only and tid not in args.only:
            continue
        t = by_id[tid]
        root = Path(args.checkouts) / "targets" / t["checkout"]  # benchmark.py fetch layout
        if t.get("subdir"):
            root = root / t["subdir"]
        bugs = [b for b in manifest.get("bugs", []) if any(r.get("target") == tid for r in b.get("replays", []))]
        old = run_old(root, out / tid / "old")
        new = run_new(root, out / tid / "new", spec["build"])
        old_r, new_r = target_report(old, bugs), target_report(new, bugs)
        diff = {}
        if old.get("status") == "ok" and new.get("status") == "ok":
            of, nf = set(old["functions"]), set(new["functions"])
            diff = {
                "only_old": sorted(of - nf)[:40],
                "only_new": sorted(nf - of)[:40],
                "only_old_count": len(of - nf),
                "only_new_count": len(nf - of),
            }
        results[tid] = {"old": old_r, "new": new_r, "inventory_diff": diff}
        print(
            f"{tid}: old={old_r.get('status')} {old_r.get('functions')} fns, new={new_r.get('status')} {new_r.get('functions')} fns",
            flush=True,
        )
    (out / "results.json").write_text(json.dumps(results, indent=1) + "\n", encoding="utf-8")
    (out / "results.md").write_text(render_targets(results), encoding="utf-8")
    return 0


def render_targets(results: dict) -> str:
    lines = ["# Phase 0 PoC: benchmark targets", "", "Each cell: current lexer → new extractor.", ""]
    lines.append(
        "| Target | Functions | Direct edges | Indirect edges | Units | Entry points | Unreachable fns | Parse-failed units | Seconds |"
    )
    lines.append("| :--- |" + " ---: |" * 8)

    def g(r: dict, k: str) -> str:
        if r.get("status") != "ok":
            return r.get("status") or "?"
        v = r.get(k)
        return str(len(v)) if isinstance(v, list) else str(v)

    for tid, r in results.items():
        keys = [
            "functions",
            "direct_edges",
            "indirect_edges",
            "units",
            "entry_points",
            "unreachable_functions",
            "parse_failed_units",
            "seconds",
        ]
        lines.append(f"| `{tid}` | " + " | ".join(f"{g(r['old'], k)} → {g(r['new'], k)}" for k in keys) + " |")
    lines += [
        "",
        "## Known bugs",
        "",
        "| Target | Bug | Function | Inventoried | Reachable from an entry point |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]
    for tid, r in results.items():
        old_b = {b["bug"]: b for b in r["old"].get("bugs", [])}
        for b in r["new"].get("bugs", []) or r["old"].get("bugs", []):
            o = old_b.get(b["bug"], {})
            lines.append(
                f"| `{tid}` | {b['bug']} | `{b['function']}` | {o.get('inventoried', '?')} → {b.get('inventoried', '?')} | {o.get('reachable_from_entry', '?')} → {b.get('reachable_from_entry', '?')} |"
            )
    lines += ["", "## Failures", ""]
    for tid, r in results.items():
        for side in ("old", "new"):
            if r[side].get("status") != "ok":
                lines.append(f"- `{tid}` {side}: {r[side].get('status')}: {str(r[side].get('error'))[-400:]}")
            elif r[side].get("parse_failed_units"):
                lines.append(f"- `{tid}` {side}: Frama-C could not parse {r[side]['parse_failed_units']}")
        d = r.get("inventory_diff") or {}
        if d:
            lines.append(
                f"- `{tid}` inventory: {d['only_old_count']} only in lexer (e.g. {d['only_old'][:5]}), {d['only_new_count']} only in new (e.g. {d['only_new'][:5]})"
            )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Phase 0 PoC scorer")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("reproducers")
    r.add_argument("--dir", default=str(HERE / "reproducers"))
    r.add_argument("--out", required=True)
    r.add_argument("--only", nargs="*")
    t = sub.add_parser("targets")
    t.add_argument("--targets", default=str(HERE / "targets.json"))
    t.add_argument("--checkouts", required=True)
    t.add_argument("--manifest", default=str(REPO / "benchmark" / "manifest.json"))
    t.add_argument("--out", required=True)
    t.add_argument("--only", nargs="*")
    a = p.parse_args(argv)
    return cmd_reproducers(a) if a.cmd == "reproducers" else cmd_targets(a)


if __name__ == "__main__":
    sys.exit(main())
