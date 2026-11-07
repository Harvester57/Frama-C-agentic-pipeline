#!/usr/bin/env python3
"""
Container side of the seeded-bug benchmark (seeded.py): Phase 0 with one of the two extractors,
then a fixed mechanical harness policy, then the pipeline's own ledger seed and Make generation.
The host runs build, fuzz, Eva and ingest afterwards with pipeline_make.py, as the benchmark does.

    python3 bench/poc/seeded_inner.py --mode lexer|phase0b --repo NAME [--build make] [--fuzz-budget 30]

Harness policy (identical for both modes, so only Phase 0 differs): for every DAG module, one
dispatch harness with one case per non-static, non-`main` candidate entry point, arguments
synthesized from the function's prototype (scalars from the first bytes, then buffer/length pairs,
NUL-terminated strings or output buffers), compiled from the module's required_sources with the
module's cppflags. What the extractor reports as entry points, sources and flags is what is fuzzed.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPTS = Path("/opt/framac-pipeline/scripts")
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(HERE))

import dag_view  # noqa: E402
import phase0b  # noqa: E402

import generate_harness  # noqa: E402
from build_callgraph_dag import compute_topological_waves  # noqa: E402

DAG = Path("workspace/reports/callgraph_dag.json")
WORK = "workspace/work"
_SCALAR_RE = re.compile(
    r"^(?:const\s+)?(?:(?:unsigned|signed)(?:\s+(?:int|long|short|char))?|int|long|short|char|size_t|ssize_t|u?int(?:8|16|32|64)_t)$"
)
_LEN_RE = re.compile(r"\b(size_t|unsigned|int|long|u?int(?:16|32|64)_t)\b")
MAX_CASES = 64


def sh(log: list[dict], name: str, argv: list[str]) -> bool:
    proc = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
    log.append({"step": name, "rc": proc.returncode, "tail": (proc.stdout + proc.stderr)[-1500:]})
    return proc.returncode == 0


def work_flags(flags: list[str] | str) -> str:
    """DAG cppflags (paths relative to the target root) as harness cppflags on the overlay."""
    toks = flags.split() if isinstance(flags, str) else [t for f in flags for t in f.split()]
    out: list[str] = []
    i = 0
    while i < len(toks):
        tok = toks[i]
        for opt in ("-iquote", "-isystem", "-idirafter", "-include", "-imacros", "-I"):
            if tok == opt and i + 1 < len(toks):
                val = toks[i + 1]
                i += 1
                tok = f"{opt} {val if val.startswith('/') else f'{WORK}/{val}'}"
                break
            if tok.startswith(opt) and len(tok) > len(opt) and opt == "-I":
                val = tok[2:]
                tok = f"-I{val if val.startswith('/') else f'{WORK}/{val}'}"
                break
        out.append(tok)
        i += 1
    return " ".join(out) or "-I."


def declaring_headers(names: list[str]) -> dict[str, str]:
    found: dict[str, str] = {}
    for h in sorted(Path(WORK).rglob("*.h")):
        try:
            text = h.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for n in names:
            if n not in found and re.search(rf"\b{re.escape(n)}\s*\([^;{{]*\)\s*;", text):
                found[n] = h.as_posix()
    return found


def synthesize_case(fn: str, params: list[dict]) -> str | None:
    """One dispatch-case statement calling `fn` on the fuzz input, or None for an unsupported signature."""
    stmts: list[str] = []
    args: list[str] = []
    i = 0
    while i < len(params):
        p = params[i]
        typ = " ".join(str(p.get("type") or "").split())
        nxt = " ".join(str(params[i + 1].get("type") or "").split()) if i + 1 < len(params) else ""
        if p.get("is_fn_pointer"):
            return None
        if "*" not in typ and _SCALAR_RE.match(typ):
            v = f"a{i}"
            stmts.append(
                f"{typ.replace('const ', '')} {v} = 0; if (fuzz_len >= sizeof {v}) {{ memcpy(&{v}, fuzz_buf, sizeof {v}); "
                f"fuzz_buf += sizeof {v}; fuzz_len -= sizeof {v}; }}"
            )
            args.append(v)
        elif "*" in typ and "const" in typ and nxt and "*" not in nxt and _LEN_RE.search(nxt):
            args += [f"({typ})fuzz_buf", f"({nxt.replace('const ', '')})fuzz_len"]
            i += 1
        elif "*" in typ and "const" in typ and "char" in typ:
            v = f"s{i}"
            stmts.append(
                f"char {v}[1501]; size_t n{i} = fuzz_len < 1500 ? fuzz_len : 1500; memcpy({v}, fuzz_buf, n{i}); {v}[n{i}] = 0;"
            )
            args.append(v)
        elif "*" in typ and nxt and "*" not in nxt and _LEN_RE.search(nxt):
            v = f"o{i}"
            stmts.append(f"uint8_t {v}[256]; memset({v}, 0, sizeof {v});")
            args += [f"({typ}){v}", f"({nxt.replace('const ', '')})sizeof {v}"]
            i += 1
        elif typ.count("*") == 1 and "const" not in typ and not re.search(r"\b(void|char)\b", typ):
            # An output struct: a zeroed local, passed by address.
            v = f"r{i}"
            stmts.append(f"{typ.replace('*', '').strip()} {v}; memset(&{v}, 0, sizeof {v});")
            args.append(f"&{v}")
        else:
            return None
        i += 1
    return " ".join(stmts + [f"(void){fn}({', '.join(args)});"])


def harness_policy(log: list[dict]) -> dict:
    dag = json.loads(DAG.read_text(encoding="utf-8"))
    fns = dag.get("functions") or {}
    report: dict = {}
    for mod, rec in sorted((dag.get("modules") or {}).items()):
        entries = []
        for key in rec.get("candidate_entry_points") or []:
            f = fns.get(key) or {}
            name = f.get("name") or key.rsplit("#", 1)[-1]
            if name == "main" or f.get("is_static"):
                continue
            entries.append(name)
        sources = [f"{WORK}/{s}" for s in rec.get("required_sources") or rec.get("files") or [] if s.endswith(".c")]
        # Files holding `main` would clash with the harness's own entry.
        sources = [
            s
            for s in sources
            if not any(r.get("name") == "main" and f"{WORK}/{r.get('file')}" == s for r in fns.values())
        ]
        cppflags = work_flags(rec.get("cppflags") or [])
        if not entries or not sources:
            report[mod] = {"harness": False, "reason": "no callable entry point" if not entries else "no sources"}
            continue
        headers = declaring_headers(entries)
        cases, skipped = [], []
        for name in entries[:MAX_CASES]:
            try:
                params = generate_harness.extract_function_prototype(name, headers.get(name), sources, cppflags)
            except ValueError as exc:
                skipped.append({"function": name, "reason": f"no prototype: {exc}"[:200]})
                continue
            case = synthesize_case(name, params)
            if case is None:
                skipped.append({"function": name, "reason": "unsupported signature"})
            else:
                cases.append((name, case))
        if not cases:
            report[mod] = {"harness": False, "reason": "no supported entry point", "skipped": skipped}
            continue
        hdrs = sorted({headers[n] for n, _ in cases if n in headers})
        argv = [
            sys.executable,
            str(SCRIPTS / "generate_harness.py"),
            "--module",
            mod,
            "--sources",
            *sources,
            "--header",
            hdrs[0] if hdrs else "none",
            "--entry-fn",
            cases[0][0],
            "--entry-style",
            "dispatch",
            f"--cppflags={cppflags}",
            "--max-size",
            "1500",
            "--out-dir",
            "workspace/harnesses",
            "--no-auto-prelude",
        ]
        for h in hdrs[1:]:
            argv += ["--extra-include", h]
        for _, c in cases:
            argv.append(f"--dispatch-case={c}")
        ok = sh(log, f"harness:{mod}", argv)
        report[mod] = {
            "harness": ok,
            "cases": [n for n, _ in cases],
            "skipped": skipped,
            "sources": sources,
            "cppflags": cppflags,
        }
    return report


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=["lexer", "phase0b"], required=True)
    p.add_argument("--repo", required=True)
    p.add_argument("--build", default="make")
    p.add_argument("--fuzz-budget", type=int, default=30)
    a = p.parse_args(argv)
    if (HERE / "build.txt").is_file():  # written by seeded.py: a build command may hold spaces and `&&`
        a.build = (HERE / "build.txt").read_text(encoding="utf-8").strip()
    py = sys.executable
    log: list[dict] = []
    result: dict = {"mode": a.mode, "steps": log}
    ok = sh(
        log, "run_metadata", [py, str(SCRIPTS / "run_metadata.py"), "init", "--repo", a.repo, "--profile", "standard"]
    )
    ok = ok and sh(
        log,
        "overlay",
        [py, str(SCRIPTS / "workspace_overlay.py"), "init", "--target", "/target", "--overlay", "workspace"],
    )
    if ok:
        if a.mode == "lexer":
            ok = sh(
                log,
                "dag",
                [
                    py,
                    str(SCRIPTS / "build_callgraph_dag.py"),
                    "--target",
                    WORK,
                    "--out",
                    str(DAG),
                    "--emit-compile-commands",
                    "workspace/reports/compile_commands.json",
                ],
            )
        else:
            model = phase0b.extract(Path("/target"), Path("workspace/reports/phase0b"), a.build, timeout=1800)
            ok = model["build"]["status"] == "ok"
            log.append({"step": "dag", "rc": 0 if ok else 1, "tail": model["build"].get("log_tail", "")})
            if ok:
                DAG.parent.mkdir(parents=True, exist_ok=True)
                DAG.write_text(
                    json.dumps(dag_view.build_unit_view(model, compute_topological_waves), indent=1) + "\n",
                    encoding="utf-8",
                )
    if ok:
        result["policy"] = harness_policy(log)
        ok = sh(log, "seed", [py, str(SCRIPTS / "ledger.py"), "seed", "--dag", str(DAG), "--profile", "standard"])
        ok = ok and sh(log, "checkpoint", [py, str(SCRIPTS / "checkpoint.py"), "init", "state", "--target", "/target"])
        ok = ok and sh(log, "make_gen", [py, str(SCRIPTS / "pipeline_make.py"), "gen"])
        for mod, info in (result.get("policy") or {}).items():
            if info.get("harness"):
                sh(
                    log,
                    f"params:{mod}",
                    [
                        py,
                        str(SCRIPTS / "pipeline_make.py"),
                        "params",
                        "set",
                        "--module",
                        mod,
                        "--fuzz-budget",
                        str(a.fuzz_budget),
                    ],
                )
    result["ok"] = bool(ok)
    Path("bench").mkdir(exist_ok=True)
    Path("bench/phase0.json").write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {"ok": result["ok"], "harnessed": [m for m, i in (result.get("policy") or {}).items() if i.get("harness")]}
        )
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
