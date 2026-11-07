#!/usr/bin/env python3
"""
Phase 0 PoC: the new model (phase0b.py) written as a `callgraph_dag.json` the current pipeline reads.

This is the A/B view: it changes the inventory and the call edges, and keeps everything else of the
lexer's DAG, so a difference in the run comes from those two and nothing else.

- Functions, their files and their call edges (direct and indirect) come from the model.
- Module assignment is held fixed: a function belongs to the harness module that compiles its
  file, else to the lexer's module for that file (link units are a separate experiment, since the
  harnesses are written per lexer module).
- Tiers, cppflags, required_sources and the lexer's per-function analysis (loops aside, security
  properties, WP blockers) are copied from the lexer DAG where the function exists there.
- Waves and recursion cycles are recomputed on the new edges.

    dag_view.py --model model.json --lexer-dag lexer_dag.json --spec bench/spec.json --out callgraph_dag.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

_LEXER_KEEP = (
    "security_properties",
    "wp_blockers",
    "wp_notes",
    "verifiability",
    "takes_bounded_buffer",
    "writes_bounded_buffer",
    "uses_format_or_write",
    "has_zeroization",
    "has_dynamic_alloc",
    "has_pointer_cast",
    "has_backward_goto",
    "has_unsigned_wrap_idiom",
    "indirect_calls",
)


def _strip(path: str) -> str:
    return path[len("workspace/work/") :] if path.startswith("workspace/work/") else path


def build_view(model: dict, lexer: dict, harness_modules: list[dict], waves_fn: Any) -> dict:
    lex_fns = lexer.get("functions") or {}
    lex_by_id = {f"{r['file']}#{r.get('name', k)}": r for k, r in lex_fns.items() if isinstance(r, dict)}
    lex_modules = lexer.get("modules") or {}
    file_lex_module = {f: m for m, rec in lex_modules.items() for f in rec.get("files") or []}
    harness_of_file: dict[str, str] = {}
    for hm in harness_modules:
        for src in hm.get("sources") or []:
            harness_of_file.setdefault(_strip(src), hm["name"])

    fns = model.get("functions") or {}
    unit_files = {n: u.get("files") or [] for n, u in (model.get("units") or {}).items()}

    def module_of(fid: str, rec: dict) -> str:
        f = rec["file"]
        if f in harness_of_file:
            return harness_of_file[f]
        if f in file_lex_module:
            return file_lex_module[f]
        # A function defined in a header: the module owning most of the sources of its unit.
        votes: Counter = Counter()
        for unit in rec.get("units") or []:
            for src in unit_files.get(unit, []):
                mod = harness_of_file.get(src) or file_lex_module.get(src)
                if mod:
                    votes[mod] += 1
        return votes.most_common(1)[0][0] if votes else (Path(f).parent.name or Path(f).stem)

    names = Counter(r["name"] for r in fns.values())
    key_of = {fid: (r["name"] if names[r["name"]] == 1 else fid) for fid, r in fns.items()}

    succ: dict[str, set[str]] = defaultdict(set)
    for e in model.get("edges") or []:
        if e["caller"] in key_of and e["callee"] in key_of:
            succ[key_of[e["caller"]]].add(key_of[e["callee"]])

    functions: dict[str, dict] = {}
    for fid, r in sorted(fns.items()):
        key = key_of[fid]
        base = dict(lex_by_id.get(fid) or {})
        rec = {k: base[k] for k in _LEXER_KEEP if k in base}
        loops = int(r.get("loops") or 0)
        rec.update(
            name=r["name"],
            file=r["file"],
            module=module_of(fid, r),
            line=r.get("line", 0),
            is_static=bool(r.get("static")),
            has_loops=loops > 0,
            loop_count=loops,
            verifiability=base.get("verifiability", "core_provable"),
            wp_blockers=base.get("wp_blockers", []),
            wp_notes=list(base.get("wp_notes", [])),
            security_properties=list(base.get("security_properties", [])),
            internal_callees=sorted(succ[key] - {key}),
            self_recursive=key in succ[key],
            external_callees=sorted(base.get("external_callees") or []),
            callgraph_source=r.get("source", "phase0b"),
        )
        functions[key] = rec
    for key, rec in functions.items():
        rec["internal_callers"] = sorted(k for k, s in succ.items() if key in s and k != key)

    waves, cycles = waves_fn(functions, {k: set(v) for k, v in succ.items()})
    in_cycle = {f for c in cycles for f in c}
    for idx, wave in enumerate(waves):
        for key in wave:
            functions[key]["wave"] = idx
            functions[key]["is_recursive"] = key in in_cycle

    modules: dict[str, dict] = {}
    members: dict[str, list[str]] = defaultdict(list)
    for key, rec in functions.items():
        members[rec["module"]].append(key)
    entry = {key_of[e] for e in model.get("entry_points") or [] if e in key_of}
    for name in sorted(set(lex_modules) | set(members)):
        mod = dict(
            lex_modules.get(name)
            or {
                "module": name,
                "tier": "Tier 3 (Internal State / Glue Module)",
                "files": [],
                "required_sources": [],
                "cppflags": [],
            }
        )
        mod["functions"] = sorted(members.get(name, []))
        mod["function_count"] = len(mod["functions"])
        mod["files"] = sorted(
            set(mod.get("files") or [])
            | {functions[k]["file"] for k in mod["functions"] if functions[k]["file"].endswith(".c")}
        )
        mod["candidate_entry_points"] = sorted(k for k in mod["functions"] if k in entry)
        modules[name] = mod

    return {
        "target_dir": lexer.get("target_dir"),
        "callgraph_source": "phase0b",
        "total_c_files": len({r["file"] for r in functions.values() if r["file"].endswith(".c")}),
        "total_functions": len(functions),
        "total_waves": len(waves),
        "name_collisions": [],
        "header_inline_callees": {},
        "warnings": [],
        "modules": modules,
        "waves": [{"wave": i, "count": len(w), "functions": w} for i, w in enumerate(waves)],
        "recursion_cycles": cycles,
        "functions": functions,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="phase0b model -> callgraph_dag.json (A/B view)")
    p.add_argument("--model", type=Path, required=True)
    p.add_argument("--lexer-dag", type=Path, required=True)
    p.add_argument("--spec", type=Path, required=True)
    p.add_argument("--scripts", type=Path, default=Path("/opt/framac-pipeline/scripts"))
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args(argv)
    sys.path.insert(0, str(a.scripts))
    from build_callgraph_dag import compute_topological_waves

    spec = json.loads(a.spec.read_text(encoding="utf-8"))
    harness_modules = [{"name": m["name"], "sources": m["harness"].get("sources") or []} for m in spec["modules"]]
    view = build_view(
        json.loads(a.model.read_text(encoding="utf-8")),
        json.loads(a.lexer_dag.read_text(encoding="utf-8")),
        harness_modules,
        compute_topological_waves,
    )
    a.out.write_text(json.dumps(view, indent=1) + "\n", encoding="utf-8")
    print(json.dumps({"functions": view["total_functions"], "modules": sorted(view["modules"])}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
