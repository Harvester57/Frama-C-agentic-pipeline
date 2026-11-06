#!/usr/bin/env python3
"""
Render an Eva flamegraph (SVG + HTML) from a module's flamegraph.txt, written by every Eva run
(-eva-flamegraph, see run_eva_slice.py). Use it to find where a slow Eva run spends its time:

    python3 /opt/framac-pipeline/scripts/eva_flamegraph.py --dir workspace/eva/<mod>
    python3 /opt/framac-pipeline/scripts/pipeline_make.py run flamegraph-<mod>

It wraps upstream `frama-c-script flamegraph` (share/analysis-scripts/flamegraph.pl) with NOGUI=1,
so it works headless inside the container. Exit code 0 when flamegraph.svg was (re)generated.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


def render(flamegraph_txt: Path, out_dir: Path) -> tuple[int, list[str]]:
    if not flamegraph_txt.is_file():
        return 2, [f"error: {flamegraph_txt} not found: run the module's Eva analysis first (eva-<mod>)"]
    out_dir.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "NOGUI": "1"}
    proc = subprocess.run(
        ["frama-c-script", "flamegraph", str(flamegraph_txt), str(out_dir)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )
    produced = [str(p) for p in (out_dir / "flamegraph.svg", out_dir / "flamegraph.html") if p.is_file()]
    if proc.returncode != 0 or not produced:
        return proc.returncode or 1, [
            f"error: frama-c-script flamegraph failed (exit {proc.returncode})",
            (proc.stdout or "").strip(),
            (proc.stderr or "").strip(),
        ]
    return 0, produced


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render an Eva flamegraph from flamegraph.txt.")
    parser.add_argument("--dir", type=Path, default=None, help="Eva output directory containing flamegraph.txt")
    parser.add_argument("--module", default=None, help="Module name; --dir defaults to workspace/eva/<module>")
    parser.add_argument("--run-dir", type=Path, default=Path("."), help="Run directory (default: cwd)")
    args = parser.parse_args(list(argv) if argv is not None else sys.argv[1:])
    if args.dir is not None:
        eva_dir = args.dir
    elif args.module:
        eva_dir = args.run_dir / "workspace" / "eva" / args.module
    else:
        parser.error("give --dir or --module")
    code, lines = render(eva_dir / "flamegraph.txt", eva_dir)
    for line in lines:
        print(line)
    return code


if __name__ == "__main__":
    sys.exit(main())
