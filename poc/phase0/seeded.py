#!/usr/bin/env python3
"""
Seeded-bug benchmark for Phase 0 (host side): each project of poc/phase0/seeded/ runs through
Phase 0 (lexer or phase0b), the fixed harness policy of seeded_inner.py, then the pipeline's own
build, fuzz, Eva and ingest, through the real wrapper (scripts/benchmark.py's run_stage, read-only
use). Each seeded bug is then scored as found by fuzzing, found by Eva (Invalid), flagged by Eva
(Unknown at its line) or missed; each decoy as fired or not.

    python -I poc/phase0/seeded.py run [--project sNN_name ...] [--mode lexer --mode phase0b]
    python -I poc/phase0/seeded.py score <results.json>     # re-score existing run directories

Results: poc/phase0/out/seeded/seeded-<stamp>.{json,md}.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import benchmark  # noqa: E402

CORPUS = HERE / "seeded"
OUT = HERE / "out" / "seeded"
POC_FILES = ("seeded_inner.py", "phase0b.py", "dag_view.py", "p0_dump.ml")
PM = "python3 /opt/framac-pipeline/scripts/pipeline_make.py"
MODES = ("lexer", "phase0b")


def _rel(path: str) -> str:
    path = benchmark.normalize_file(path or "")
    for prefix in ("workspace/work/", "/target/"):
        path = path.removeprefix(prefix)
    return path


def _join(row: dict) -> str:
    """An Eva row's file with its directory, as the report splits them."""
    directory, name = str(row.get("directory") or ""), str(row.get("file") or "")
    return f"{directory}/{name}" if directory and directory != "." else name


def _same(file_a: str, file_b: str) -> bool:
    a, b = _rel(file_a), _rel(file_b)
    return bool(a) and (a == b or a.endswith("/" + b) or b.endswith("/" + a))


def run_project(proj: Path, mode: str, run_root: Path, fuzz_budget: int) -> dict:
    truth = json.loads((proj / "truth.json").read_text(encoding="utf-8"))
    run_dir = (run_root / f"{proj.name}-{mode}" / benchmark.RUN_DIR_NAME).resolve()  # run_metadata wants run-<N>
    poc = run_dir / benchmark.BENCH_SUBDIR / "poc"
    poc.mkdir(parents=True)
    for f in POC_FILES:
        shutil.copyfile(HERE / f, poc / f)
    (poc / "build.txt").write_text(truth.get("build", "make") + "\n", encoding="utf-8")
    stages: dict[str, dict] = {}
    repo = proj.name.replace("_", "-")

    def stage(name: str, command: str, cls: str | None = None) -> bool:
        stages[name] = benchmark.run_stage(name, command, proj.resolve(), run_dir, repo, cls=cls)
        return stages[name]["rc"] == 0

    started = time.monotonic()
    ok = stage(
        "phase0",
        f"python3 -B {benchmark.BENCH_SUBDIR}/poc/seeded_inner.py --mode {mode} --repo {repo} --fuzz-budget {fuzz_budget}",
        "eva",
    )
    if ok:
        for name in ("build", "fuzz", "eva", "ingest"):
            stage(name, f"{PM} run {name}")
    return {"run_dir": str(run_dir), "stages": stages, "wall_s": round(time.monotonic() - started, 1)}


def score(run_dir: Path, truth: dict) -> dict:
    reports = run_dir / "workspace" / "reports"
    fuzz_hits: list[dict] = []
    fuzz_status: dict[str, str] = {}
    for f in sorted((reports / "fuzz").glob("*.json")):
        rep = benchmark.read_json(f, {}) or {}
        fuzz_status[f.stem] = rep.get("status", "?")
        for art in rep.get("artifacts") or []:
            fail = art.get("failure") or {}
            fp = str(art.get("fingerprint") or "")
            file_fn = fp.split("::", 1)[0]
            fuzz_hits.append(
                {
                    "file": fail.get("file") or file_fn.split("#")[0],
                    "function": fail.get("function") or (file_fn.split("#")[1] if "#" in file_fn else ""),
                    "line": fail.get("line"),
                    "kind": fail.get("kind"),
                }
            )
    eva_invalid: list[dict] = []
    eva_unknown: list[dict] = []
    eva_status: dict[str, str] = {}
    for f in sorted((reports / "eva").glob("*.json")):
        rep = benchmark.read_json(f, {}) or {}
        eva_status[f.stem] = rep.get("status", "?")
        for row in rep.get("invalid_alarms") or []:
            eva_invalid.append({**row, "file": _join(row)})
        for fn, rows in (rep.get("unknown_obligations_by_function") or {}).items():
            for row in rows or []:
                if isinstance(row, dict):
                    eva_unknown.append({"function": fn, **row, "file": _join(row)})

    def hit(rows: list[dict], file: str, function: str, line: int | None = None) -> bool:
        return any(
            r.get("function") == function
            and _same(str(r.get("file") or ""), file)
            and (line is None or str(r.get("line") or "") == str(line))
            for r in rows
        )

    # A bug and a decoy in the same function (two #if bodies of one function) are told apart by line.
    items = (truth.get("bugs") or []) + (truth.get("decoys") or [])
    shared = {
        (i["file"], i["function"])
        for i in items
        if sum(1 for j in items if (j["file"], j["function"]) == (i["file"], i["function"])) > 1
    }

    def at(item: dict) -> int | None:
        return item.get("line") if (item["file"], item["function"]) in shared else None

    bugs = {}
    for b in truth.get("bugs") or []:
        by_fuzz = hit(fuzz_hits, b["file"], b["function"], at(b))
        by_eva = hit(eva_invalid, b["file"], b["function"], at(b))
        flagged = hit(eva_unknown, b["file"], b["function"], b.get("line"))
        bugs[b["id"]] = {
            "mechanism": b.get("mechanism"),
            "function": f"{b['file']}#{b['function']}",
            "fuzz": by_fuzz,
            "eva_invalid": by_eva,
            "eva_unknown_at_line": flagged,
            "found": by_fuzz or by_eva,
        }
    decoys = {}
    for d in truth.get("decoys") or []:
        decoys[d["id"]] = {
            "kind": d.get("kind"),
            "function": f"{d['file']}#{d['function']}",
            "fired": hit(fuzz_hits, d["file"], d["function"], at(d))
            or hit(eva_invalid, d["file"], d["function"], at(d)),
        }
    known = {(b["file"], b["function"]) for b in truth.get("bugs") or []} | {
        (d["file"], d["function"]) for d in truth.get("decoys") or []
    }
    other = sorted(
        {
            f"{_rel(str(r.get('file')))}#{r.get('function')}"
            for r in fuzz_hits + eva_invalid
            if not any(r.get("function") == fn and _same(str(r.get("file") or ""), fl) for fl, fn in known)
        }
    )
    phase0 = benchmark.read_json(run_dir / "bench" / "phase0.json", {}) or {}
    policy = phase0.get("policy") or {}
    builds = {
        f.name.removesuffix(".build.json"): (benchmark.read_json(f, {}) or {}).get("status", "?")
        for f in sorted((run_dir / "workspace" / "build").glob("*.build.json"))
    }
    return {
        "phase0_ok": phase0.get("ok"),
        "harnesses": {m: i.get("cases") for m, i in policy.items() if i.get("harness")},
        "not_harnessed": {m: i.get("reason") for m, i in policy.items() if not i.get("harness")},
        "skipped_entries": {m: i.get("skipped") for m, i in policy.items() if i.get("skipped")},
        "builds": builds,
        "fuzz_status": fuzz_status,
        "eva_status": eva_status,
        "bugs": bugs,
        "decoys": decoys,
        "other_findings": other,
    }


def render(results: dict) -> str:
    lines = [
        "# Phase 0 seeded-bug benchmark",
        "",
        "Same harness policy for both modes; only Phase 0 differs. Each cell: lexer → phase0b.",
        "",
        "| Project | Mechanism | Bugs found (fuzz or Eva Invalid) | Eva Unknown at bug line | Decoys fired | Other findings | Harness cases |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    totals = {m: {"bugs": 0, "found": 0, "decoys": 0, "other": 0} for m in MODES}
    for proj, r in results.items():
        cells = []
        for key in ("found", "eva_unknown_at_line"):
            vals = []
            for m in MODES:
                s = r[m].get("score") or {}
                bugs = s.get("bugs") or {}
                vals.append(f"{sum(1 for b in bugs.values() if b[key])}/{len(bugs)}" if s else r[m].get("status", "?"))
            cells.append(" → ".join(vals))
        dec = [
            str(sum(1 for d in ((r[m].get("score") or {}).get("decoys") or {}).values() if d["fired"])) for m in MODES
        ]
        oth = [str(len((r[m].get("score") or {}).get("other_findings") or [])) for m in MODES]
        cases = [
            str(sum(len(c or []) for c in ((r[m].get("score") or {}).get("harnesses") or {}).values())) for m in MODES
        ]
        lines.append(
            f"| `{proj}` | {r.get('mechanism', '')} | {cells[0]} | {cells[1]} | {' → '.join(dec)} | {' → '.join(oth)} | {' → '.join(cases)} |"
        )
        for m in MODES:
            s = r[m].get("score") or {}
            totals[m]["bugs"] += len(s.get("bugs") or {})
            totals[m]["found"] += sum(1 for b in (s.get("bugs") or {}).values() if b["found"])
            totals[m]["decoys"] += sum(1 for d in (s.get("decoys") or {}).values() if d["fired"])
            totals[m]["other"] += len(s.get("other_findings") or [])
    lex, new = totals["lexer"], totals["phase0b"]
    lines.append(
        f"| **Total** | | {lex['found']}/{lex['bugs']} → {new['found']}/{new['bugs']} | | {lex['decoys']} → {new['decoys']} | {lex['other']} → {new['other']} | |"
    )
    lines += [
        "",
        "## Per bug",
        "",
        "| Project | Bug | Mechanism | Function | Lexer | phase0b |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    def how(b: dict | None) -> str:
        if not b:
            return "?"
        parts = [k for k in ("fuzz", "eva_invalid") if b[k]] or (
            ["eva unknown"] if b["eva_unknown_at_line"] else ["missed"]
        )
        return ", ".join(parts)

    for proj, r in results.items():
        lb = (r["lexer"].get("score") or {}).get("bugs") or {}
        nb = (r["phase0b"].get("score") or {}).get("bugs") or {}
        for bid in sorted(set(lb) | set(nb)):
            ref = nb.get(bid) or lb.get(bid) or {}
            lines.append(
                f"| `{proj}` | {bid} | {ref.get('mechanism')} | `{ref.get('function')}` | {how(lb.get(bid))} | {how(nb.get(bid))} |"
            )
    lines += ["", "## Details", ""]
    for proj, r in results.items():
        for m in MODES:
            s = r[m].get("score") or {}
            lines.append(
                f"- `{proj}` {m}: harnesses {s.get('harnesses')}; not harnessed {s.get('not_harnessed')}; "
                f"builds {s.get('builds')}; fuzz {s.get('fuzz_status')}; eva {s.get('eva_status')}; "
                f"decoys fired {[k for k, d in (s.get('decoys') or {}).items() if d['fired']]}; other {s.get('other_findings')}"
            )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Phase 0 seeded-bug benchmark")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--project", action="append", default=[])
    r.add_argument("--mode", action="append", choices=MODES, default=[])
    r.add_argument("--fuzz-budget", type=int, default=30)
    r.add_argument("--corpus", type=Path, default=CORPUS)
    s = sub.add_parser("score")
    s.add_argument("results", type=Path)
    s.add_argument("--corpus", type=Path, default=CORPUS)
    a = p.parse_args(argv)
    OUT.mkdir(parents=True, exist_ok=True)
    if a.cmd == "score":
        prior = json.loads(a.results.read_text(encoding="utf-8"))
        for proj, rr in prior.items():
            truth = json.loads((a.corpus / proj / "truth.json").read_text(encoding="utf-8"))
            for m in MODES:
                if rr.get(m, {}).get("run_dir"):
                    rr[m]["score"] = score(Path(rr[m]["run_dir"]), truth)
        a.results.write_text(json.dumps(prior, indent=1) + "\n", encoding="utf-8")
        a.results.with_suffix(".md").write_text(render(prior), encoding="utf-8")
        print(a.results.with_suffix(".md"))
        return 0
    stamp = time.strftime("%Y%m%d-%H%M%S")
    run_root = OUT / "runs" / stamp
    projects = [
        d for d in sorted(a.corpus.iterdir()) if (d / "truth.json").is_file() and (not a.project or d.name in a.project)
    ]
    modes = a.mode or list(MODES)
    out_file = OUT / f"seeded-{stamp}.json"
    results: dict[str, Any] = {}
    for proj in projects:
        truth = json.loads((proj / "truth.json").read_text(encoding="utf-8"))
        results[proj.name] = {"mechanism": truth.get("mechanism")}
        for m in MODES:
            if m not in modes:
                results[proj.name][m] = {"status": "not_run"}
                continue
            print(f"== {proj.name} {m}", flush=True)
            try:
                info = run_project(proj, m, run_root, a.fuzz_budget)
                info["score"] = score(Path(info["run_dir"]), truth)
                results[proj.name][m] = info
            except Exception as exc:  # one project failing must not lose the others
                results[proj.name][m] = {"status": "error", "error": f"{type(exc).__name__}: {exc}"}
            out_file.write_text(json.dumps(results, indent=1) + "\n", encoding="utf-8")
    out_file.with_suffix(".md").write_text(render(results), encoding="utf-8")
    print(f"results: {out_file.with_suffix('.md')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
