#!/usr/bin/env python3
"""
Render an Eva flamegraph (SVG + HTML) from a module's flamegraph.txt, written by the module's base
and plain Eva runs (-eva-flamegraph, see run_eva_slice.py; tuning rungs and loop trials skip it).
Use it to find where a slow Eva run spends its time:

    python3 /opt/framac-pipeline/scripts/eva_flamegraph.py --dir workspace/eva/<mod>
    python3 /opt/framac-pipeline/scripts/pipeline_make.py run flamegraph-<mod>

It wraps upstream `frama-c-script flamegraph` (share/analysis-scripts/flamegraph.pl) with NOGUI=1,
so it works headless inside the container. Exit code 0 when flamegraph.svg was (re)generated.

`cost_profile` reads the same file without rendering it: run_eva_slice.py puts it in the report of
a run that timed out or fell back, so the slow functions are named without anyone opening the graph.

`fold_flamegraph` merges identical stacks in place. Eva writes one line per analysed call, never
merged (2.5 GB, 7.1 M lines for QCBOR run-5's base run); every reader adds times per stack, so one
line per distinct stack with the summed time loses nothing for any of them.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import zlib
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import Any

# How many functions each list of a cost profile names. Fixed: it shapes the report, not a result.
COST_PROFILE_TOP = 5

# Input bytes folded in memory at once; a larger file is split into buckets by stack first. Fixed: it
# bounds memory (a few hundred MB per bucket at most), and the folded file is the same whatever it is.
FOLD_BUCKET_BYTES = 64 * 1024 * 1024
# At most this many bucket files open at once, whatever the file's size.
FOLD_MAX_BUCKETS = 256


def _format_time(t: float) -> str:
    """A time flamegraph.pl reads: plain decimal, never an exponent; integral sums stay integers."""
    if t == int(t):
        return str(int(t))
    return f"{t:.6f}".rstrip("0").rstrip(".")


def _parse_sample(line: str) -> tuple[str, float] | None:
    stack, _, raw = line.rstrip().rpartition(" ")
    try:
        t = float(raw)
    except ValueError:
        return None
    if not stack or t < 0 or t != t:
        return None
    return stack, t


def _fold_lines(lines: Iterable[str], out: Any) -> None:
    sums: defaultdict[str, float] = defaultdict(float)
    for line in lines:
        sample = _parse_sample(line)
        if sample is not None:
            sums[sample[0]] += sample[1]
    for stack in sorted(sums):
        out.write(f"{stack} {_format_time(round(sums[stack], 6))}\n")


def fold_flamegraph(path: Path, bucket_bytes: int = FOLD_BUCKET_BYTES) -> bool:
    """
    Merge identical stacks of a `-eva-flamegraph` file in place: one `stack <summed time>` line per
    distinct stack, sorted by stack. Lines no reader uses (no time, negative time) are dropped. Reads
    as a stream; a file over `bucket_bytes` is first split into buckets by a hash of the stack, so
    memory stays bounded. Returns False when the file is missing or cannot be rewritten (left as is).
    """
    path = Path(path)
    try:
        size = path.stat().st_size
    except OSError:
        return False
    n = max(1, min(FOLD_MAX_BUCKETS, -(-size // max(1, bucket_bytes))))
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp_fold_")
    buckets: list[Path] = []
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as out:
            if n == 1:
                with path.open(encoding="utf-8", errors="replace") as handle:
                    _fold_lines(handle, out)
            else:
                handles = []
                try:
                    for _ in range(n):
                        bfd, bname = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp_fold_bucket_")
                        buckets.append(Path(bname))
                        handles.append(os.fdopen(bfd, "w", encoding="utf-8", newline="\n"))
                    with path.open(encoding="utf-8", errors="replace") as handle:
                        for line in handle:
                            sample = _parse_sample(line)
                            if sample is None:
                                continue
                            k = zlib.crc32(sample[0].encode("utf-8")) % n
                            handles[k].write(f"{sample[0]} {line.rstrip().rpartition(' ')[2]}\n")
                finally:
                    for h in handles:
                        h.close()
                for bpath in buckets:
                    with bpath.open(encoding="utf-8") as handle:
                        _fold_lines(handle, out)
        os.replace(tmp, path)
    except OSError:
        Path(tmp).unlink(missing_ok=True)
        return False
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    finally:
        for bpath in buckets:
            bpath.unlink(missing_ok=True)
    return True


def _fold(
    lines: Iterable[str],
    own: defaultdict[str, float],
    inclusive: defaultdict[str, float],
    roots: set[str],
) -> None:
    """Add each `root;caller;callee <time>` sample to the self and inclusive times."""
    for line in lines:
        stack, _, raw = line.rstrip().rpartition(" ")
        try:
            t = float(raw)
        except ValueError:
            continue
        frames = [f for f in stack.split(";") if f]
        if not frames or t < 0:
            continue
        roots.add(frames[0])
        own[frames[-1]] += t
        for f in set(frames):  # a recursive function counts once per sample
            inclusive[f] += t


def cost_profile(flamegraph_txt: Path, top: int = COST_PROFILE_TOP) -> dict[str, Any] | None:
    """
    The functions that cost Eva the most, from a `-eva-flamegraph` file (folded stacks, one
    `root;caller;callee <time>` line per sample). `self`: time spent in the function itself;
    `inclusive`: with its callees, the root left out since it is the whole run. Each entry gives the
    function and its share of the run's total time. None when the file is missing, unreadable or
    empty. A run killed at its time limit still leaves a usable file: Eva writes it as it goes.
    """
    own: defaultdict[str, float] = defaultdict(float)
    inclusive: defaultdict[str, float] = defaultdict(float)
    roots: set[str] = set()
    try:
        # Read line by line: a long run writes gigabytes (2.5 GB for QCBOR run-5's base run).
        with flamegraph_txt.open(encoding="utf-8", errors="replace") as handle:
            _fold(handle, own, inclusive, roots)
    except OSError:
        return None
    total = sum(own.values())
    if total <= 0:
        return None

    def ranked(times: dict[str, float]) -> list[dict[str, Any]]:
        best = sorted(times.items(), key=lambda kv: (-kv[1], kv[0]))[:top]
        return [{"function": f, "share": round(t / total, 3)} for f, t in best]

    return {
        "self": ranked(own),
        "inclusive": ranked({f: t for f, t in inclusive.items() if f not in roots}),
    }


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
