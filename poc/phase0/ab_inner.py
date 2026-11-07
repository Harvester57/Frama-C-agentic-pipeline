#!/usr/bin/env python3
"""
Container side of the Phase 0 A/B (ab.py): `benchmark.py inner-phase0` with its call-graph step
replaced by the new extractor. Everything else of Phase 0 (overlay, harnesses from the manifest,
ledger seed, Make generation) is the benchmark's own code, unchanged.

The DAG step still runs the lexer, to `lexer_dag.json`, because the A/B view keeps its tiers and
per-function analysis; then phase0b.py extracts the model from the target's build and dag_view.py
writes `callgraph_dag.json` from both. Copied into <run-dir>/bench/poc/ by ab.py with build.txt.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPTS = Path("/opt/framac-pipeline/scripts")
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(HERE))

import dag_view  # noqa: E402
import phase0b  # noqa: E402

import benchmark  # noqa: E402
from build_callgraph_dag import compute_topological_waves  # noqa: E402

_run = subprocess.run


def _new_dag(argv: list[str], *args, **kwargs) -> subprocess.CompletedProcess:
    out = Path(argv[argv.index("--out") + 1])
    lexer_dag = out.with_name("lexer_dag.json")
    lexer_argv = list(argv)
    lexer_argv[lexer_argv.index("--out") + 1] = str(lexer_dag)
    proc = _run(lexer_argv, *args, **kwargs)
    if proc.returncode != 0:
        return proc
    build = (HERE / "build.txt").read_text(encoding="utf-8").strip()
    model = phase0b.extract(Path("/target"), out.parent / "phase0b", build, timeout=1800)
    if model["build"]["status"] != "ok":
        print(f"phase0b: target build failed: {model['build'].get('log_tail')}", file=sys.stderr)
        return subprocess.CompletedProcess(argv, 1)
    spec = json.loads((Path(benchmark.BENCH_SUBDIR) / "spec.json").read_text(encoding="utf-8"))
    harness_modules = [{"name": m["name"], "sources": m["harness"].get("sources") or []} for m in spec["modules"]]
    view = dag_view.build_view(
        model, json.loads(lexer_dag.read_text(encoding="utf-8")), harness_modules, compute_topological_waves
    )
    out.write_text(json.dumps(view, indent=1) + "\n", encoding="utf-8")
    print(json.dumps({"phase0b": "ok", "functions": view["total_functions"], "seconds": model["seconds"]}))
    return subprocess.CompletedProcess(argv, 0)


def _patched_run(argv, *args, **kwargs):
    if isinstance(argv, list) and any(str(x).endswith("build_callgraph_dag.py") for x in argv):
        return _new_dag([str(x) for x in argv], *args, **kwargs)
    return _run(argv, *args, **kwargs)


if __name__ == "__main__":
    subprocess.run = _patched_run  # type: ignore[assignment]
    sys.exit(benchmark.inner_phase0())
