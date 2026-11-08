#!/usr/bin/env python3
"""
CodeQL trust facts (docs/phase0-implementation-plan.md step I7), optional. Stdlib only.

    codeql_trust.py run [--target /target] [--scratch DIR] [--recipe-file FILE]
                        [--out workspace/reports/codeql_trust.json] [--timeout 1800]
    codeql_trust.py selftest

Off by default. It runs only when run-metadata.json enables it (`run_metadata.py set-codeql --enable
--open-source`): the CodeQL licence allows it on open-source code only, so the user declares the
target open-source. It runs in the CodeQL image (the wrapper's -CodeQL, sh: --codeql), which is the
target's build image plus the CodeQL CLI and its C/C++ packs, with the network off:

  1. copy the read-only target to <scratch>/codeql/tree and create a CodeQL database by replaying the
     run's build recipe (run-metadata.json `build`, or --recipe-file's `build`) under CodeQL's tracer,
     through sandbox_exec.py (rlimits, environment allowlist, timeout), as build_capture.py runs it;
  2. run templates/codeql/trust/untrusted_functions.ql: taint from CodeQL's local and remote flow
     sources (argv, environment, standard input and file reads, sockets) to every function parameter,
     plus the functions that hold a source;
  3. write workspace/reports/codeql_trust.json: one fact per (function, source), the function as the
     model names it (`file#name`, relative to the target root). Functions outside the target (libc,
     packages) are dropped.

scripts/trust.py turns the facts into `codeql` marks. They only add untrusted marks: a fact never makes
a function trusted, and never overrides a threat-model decision. Run `trust.py run` afterwards, then
rebuild the DAG.

`selftest` creates a database for a 10-line program and checks the facts: argv and fgets reach the
expected functions, and an unrelated function gets none.

Exit codes: 0 facts written; 1 CodeQL failed (status in the report); 2 not enabled for this run, or no
CodeQL CLI here (nothing written).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from framac_common import atomic_write_json, load_json_optional, utc_now  # noqa: E402

SCHEMA_VERSION = 1
DEFAULT_OUT = Path("workspace/reports/codeql_trust.json")
LOG_DIR = Path("workspace/reports/codeql")
METADATA = Path("run-metadata.json")
DEFAULT_TIMEOUT_S = 1800
QUERY_TIMEOUT_S = 1800
QUERY_NAME = "untrusted_functions.ql"
COLUMNS = ("function", "file", "line", "kind", "parameter", "source_type", "source_file", "source_line")

_SELFTEST_SOURCE = """#include <stdio.h>
#include <string.h>
static int helper(const char *s) { return (int)strlen(s); }
int parse(const char *line) { return helper(line) + 1; }
int unrelated(int x) { return x * 2; }
int main(int argc, char **argv) {
    char buf[128];
    if (fgets(buf, sizeof buf, stdin)) parse(buf);
    return unrelated(argc > 1 ? (int)strlen(argv[1]) : 0) > 0 ? 0 : unrelated(1);
}
"""


def query_pack_dir() -> Path | None:
    here = Path(__file__).resolve().parent
    for cand in (here.parent / "templates", Path("/opt/framac-pipeline/templates")):
        path = cand / "codeql" / "trust"
        if (path / QUERY_NAME).is_file():
            return path
    return None


def codeql_binary() -> str | None:
    return shutil.which("codeql")


def run_tool(cmd: list[str], cwd: Path | None = None, timeout: int = 600) -> tuple[int, str]:
    """A trusted command (the CodeQL CLI on its own database): (rc, combined output). Never raises."""
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {timeout} s: {shlex.join(cmd)[:300]}"
    except OSError as exc:
        return 127, str(exc)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _budget() -> tuple[int, int | None]:
    """Threads and RAM (MB) for CodeQL, from the broker's grant."""
    try:
        from resources import job_budget

        b = job_budget()
        # CodeQL's --ram bounds its JVM heap and caches: leave a quarter for the rest of the process.
        return max(1, int(b.cpus)), max(1024, int(b.mem_mb) * 3 // 4)
    except Exception:  # sizing only
        return max(1, os.cpu_count() or 1), None


def rel_to(path: str, root: str) -> str | None:
    """`path` relative to `root` (POSIX), or None outside it."""
    root = root.rstrip("/") + "/"
    return path[len(root) :] if path.startswith(root) else None


def facts_from_rows(rows: list[list[Any]], tree: str) -> tuple[list[dict], int]:
    """Query rows -> (facts on functions inside `tree`, rows dropped as outside it)."""
    facts: dict[tuple, dict] = {}
    dropped = 0
    for row in rows:
        rec = dict(zip(COLUMNS, row, strict=False))
        rel = rel_to(str(rec.get("file") or ""), tree)
        if rel is None:
            dropped += 1
            continue
        src_rel = rel_to(str(rec.get("source_file") or ""), tree)
        source: dict[str, Any] = {
            "type": rec.get("source_type") or "",
            "file": src_rel if src_rel is not None else rec.get("source_file"),
            "line": int(rec["source_line"]) if str(rec.get("source_line") or "").isdigit() else None,
        }
        fact: dict[str, Any] = {
            "function": f"{rel}#{rec['function']}",
            "kind": rec.get("kind") or "parameter",
            "parameter": rec.get("parameter") or None,
            "source": source,
        }
        key = (fact["function"], fact["kind"], fact["parameter"], source["file"], source["line"])
        facts.setdefault(key, fact)
    return [facts[k] for k in sorted(facts, key=lambda k: tuple(str(x) for x in k))], dropped


def decode_bqrs(codeql: str, bqrs: Path, timeout: int = 600) -> tuple[list[list[Any]], str]:
    rc, out = run_tool([codeql, "bqrs", "decode", "--format=json", "--result-set=#select", str(bqrs)], timeout=timeout)
    if rc != 0:
        return [], out
    try:
        data = json.loads(out)
    except ValueError as exc:
        return [], f"bqrs decode: {exc}"
    if isinstance(data, dict) and isinstance(data.get("#select"), dict):
        data = data["#select"]  # without --result-set, the sets are keyed by name
    tuples = data.get("tuples") if isinstance(data, dict) else None
    rows = []
    for t in tuples or []:
        rows.append([c.get("label", c) if isinstance(c, dict) else c for c in t])
    return rows, ""


def create_database(
    codeql: str, tree: Path, workdir: Path, db: Path, command: str, env: dict[str, str], scratch: Path, timeout: int
) -> tuple[int, bool, str]:
    """Replay the build recipe under CodeQL's tracer, sandboxed: (rc, timed out, log)."""
    from sandbox_exec import Limits, run_sandboxed

    threads, ram = _budget()
    script = scratch / "build.sh"
    script.write_bytes(f"set -e\n{command}\n".encode())
    argv = [
        codeql,
        "database",
        "create",
        str(db),
        "--language=cpp",
        f"--source-root={tree}",
        f"--working-dir={workdir}",
        f"--command=sh {script}",
        f"--threads={threads}",
        "--overwrite",
    ]
    if ram:
        argv.append(f"--ram={ram}")
    limits = Limits(cpu_seconds=timeout * max(1, threads), processes=4096, file_size_mb=4096, open_files=8192)
    res = run_sandboxed(argv, [scratch], timeout, cwd=workdir, limits=limits, extra_env=env)
    return res.returncode, res.timed_out, (res.stdout or "") + (res.stderr or "")


def run_query(codeql: str, db: Path, scratch: Path) -> tuple[list[list[Any]], dict, str]:
    """Copy the query pack where CodeQL may write its cache, run it, decode the rows."""
    pack = query_pack_dir()
    if pack is None:
        return [], {}, "templates/codeql/trust not found"
    work = scratch / "query"
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(pack, work)
    query = work / QUERY_NAME
    threads, _ = _budget()
    info: dict[str, Any] = {
        "path": f"templates/codeql/trust/{QUERY_NAME}",
        "sha256": hashlib.sha256(query.read_bytes()).hexdigest(),
    }
    bqrs = scratch / "results.bqrs"
    t0 = time.monotonic()
    rc, out = run_tool(
        [codeql, "query", "run", f"--database={db}", f"--output={bqrs}", f"--threads={threads}", str(query)],
        cwd=work,
        timeout=QUERY_TIMEOUT_S,
    )
    info["seconds"] = round(time.monotonic() - t0, 2)
    if rc != 0:
        return [], info, out
    rows, err = decode_bqrs(codeql, bqrs)
    return rows, info, err


def _metadata_gate(metadata: dict | None) -> str | None:
    """Why CodeQL may not run for this run, or None."""
    block = (metadata or {}).get("codeql") or {}
    if not block.get("enabled"):
        return "CodeQL is off for this run (run_metadata.py set-codeql --enable --open-source)"
    if not block.get("open_source"):
        return "the target is not declared open-source (CodeQL's licence covers open-source code only)"
    return None


def _recipe(recipe_file: Path | None, metadata: dict | None) -> dict | None:
    from run_metadata import normalize_build_recipe

    raw = None
    if recipe_file is not None:
        data = load_json_optional(recipe_file, None)
        raw = data.get("build") if isinstance(data, dict) else None
    if raw is None:
        raw = (metadata or {}).get("build")
    if not isinstance(raw, dict) or not raw.get("command"):
        return None
    return normalize_build_recipe(dict(raw))


def collect(target: Path, scratch_root: Path, recipe: dict, timeout: int, codeql: str, logs: Path) -> tuple[dict, int]:
    """Database, query and facts for one target: (report, exit code)."""
    import build_capture as bc

    started = time.monotonic()
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "status": "error",
        "codeql_version": None,
        "recipe": {"command": recipe["command"], "workdir": recipe["workdir"]},
        "facts": [],
        "warnings": [],
    }
    rc, out = run_tool([codeql, "version", "--format=terse"], timeout=120)
    report["codeql_version"] = out.strip() if rc == 0 else None
    scratch = scratch_root / "codeql"
    if scratch.exists():
        shutil.rmtree(scratch)
    scratch.mkdir(parents=True)
    tree = scratch / "tree"
    bc.copy_target(target, tree)
    workdir = tree / recipe["workdir"]
    db = scratch / "db"
    env = {**bc.build_env(recipe, bc.job_count())}
    t0 = time.monotonic()
    rc, timed_out, log = create_database(codeql, tree, workdir, db, recipe["command"], env, scratch, timeout)
    logs.mkdir(parents=True, exist_ok=True)
    (logs / "database.log").write_bytes(log.encode("utf-8", errors="replace"))
    report["database"] = {"returncode": rc, "timed_out": timed_out, "seconds": round(time.monotonic() - t0, 2)}
    if rc != 0 or timed_out:
        report["status"] = "database_failed"
        report["error"] = log.strip().splitlines()[-1][:400] if log.strip() else f"rc={rc}"
        report["seconds"] = round(time.monotonic() - started, 2)
        return report, 1
    rows, query, err = run_query(codeql, db, scratch)
    report["query"] = query
    if err:
        (logs / "query.log").write_bytes(err.encode("utf-8", errors="replace"))
        report["status"] = "query_failed"
        report["error"] = err.strip().splitlines()[-1][:400] if err.strip() else "query failed"
        report["seconds"] = round(time.monotonic() - started, 2)
        return report, 1
    facts, dropped = facts_from_rows(rows, str(tree))
    report.update(
        status="ok",
        tree=str(tree),
        rows=len(rows),
        rows_outside_target=dropped,
        facts=facts,
        functions=len({f["function"] for f in facts}),
        seconds=round(time.monotonic() - started, 2),
    )
    return report, 0


def cmd_run(args: argparse.Namespace) -> int:
    metadata = load_json_optional(METADATA, None)
    metadata = metadata if isinstance(metadata, dict) else None
    why = _metadata_gate(metadata)
    if why:
        print(json.dumps({"ok": False, "status": "disabled", "error": why}))
        return 2
    codeql = codeql_binary()
    if codeql is None:
        print(json.dumps({"ok": False, "status": "codeql_missing", "error": "no codeql CLI: run in the CodeQL image"}))
        return 2
    recipe = _recipe(args.recipe_file, metadata)
    if recipe is None:
        print(json.dumps({"ok": False, "status": "no_recipe", "error": "no build recipe (run_metadata.py set-build)"}))
        return 2
    scratch = Path(args.scratch) if args.scratch else None
    if scratch is None:
        scratch = Path("/framac-scratch") if os.access("/framac-scratch", os.W_OK) else None
    tmp = None
    if scratch is None:
        tmp = tempfile.mkdtemp(prefix="framac-codeql-")
        scratch = Path(tmp)
    try:
        report, rc = collect(Path(args.target), scratch, recipe, args.timeout, codeql, LOG_DIR)
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
    atomic_write_json(args.out, report)
    print(
        json.dumps(
            {k: report.get(k) for k in ("status", "error", "codeql_version", "rows", "functions", "seconds")}, indent=1
        )
    )
    return rc


def selftest() -> dict:
    codeql = codeql_binary()
    if codeql is None:
        return {"ok": False, "status": "codeql_missing", "reason": "no codeql CLI"}
    with tempfile.TemporaryDirectory(prefix="framac-codeql-selftest-") as tmp:
        root = Path(tmp)
        target = root / "target"
        target.mkdir()
        (target / "t.c").write_bytes(_SELFTEST_SOURCE.encode())
        recipe: dict[str, Any] = {
            "command": "cc -c t.c -o t.o",
            "workdir": ".",
            "env": {},
            "packages": [],
            "test_command": None,
        }
        report, rc = collect(target, root / "scratch", recipe, 600, codeql, root / "logs")
    if rc != 0:
        return {"ok": False, "status": report.get("status"), "reason": report.get("error")}
    got = {f["function"] for f in report["facts"]}
    want = {"t.c#main", "t.c#parse", "t.c#helper"}
    problems = []
    if not want <= got:
        problems.append(f"missing facts for {sorted(want - got)}")
    if "t.c#unrelated" in {f["function"] for f in report["facts"] if f["kind"] == "source_site"}:
        problems.append("unrelated holds no source")
    return {
        "ok": not problems,
        "status": "ok" if not problems else "unexpected_facts",
        "reason": "; ".join(problems),
        "codeql_version": report.get("codeql_version"),
        "functions": sorted(got),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="CodeQL trust facts (optional, open-source targets only)")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="Create the CodeQL database from the build recipe and write the facts")
    r.add_argument("--target", default="/target")
    r.add_argument("--scratch", default=None, help="writable work directory (default /framac-scratch, else /tmp)")
    r.add_argument("--recipe-file", type=Path, default=None, help="JSON file whose `build` block is the recipe")
    r.add_argument("--out", type=Path, default=DEFAULT_OUT)
    r.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_S)
    sub.add_parser("selftest", help="Check CodeQL and the query on a 10-line program")
    a = p.parse_args(argv)
    if a.cmd == "selftest":
        res = selftest()
        print(json.dumps(res, indent=2))
        return 0 if res["ok"] else 1
    return cmd_run(a)


if __name__ == "__main__":
    sys.exit(main())
