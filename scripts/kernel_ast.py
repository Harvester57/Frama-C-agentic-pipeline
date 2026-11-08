#!/usr/bin/env python3
"""
Facts from the Frama-C kernel AST of a set of sources, as plain Python data (stdlib only).

scripts/kernel_ast_dump.ml is compiled into a private temporary directory and loaded into a
`frama-c -no-annot` run over the same sources and flags as the module's Eva run. It reports what
the C/ACSL lexer cannot see: the code after macro expansion, resolved types and call targets.

This is the shared kernel entry point: function_facts.py builds per-function prover facts on it,
and call_graph() is what an authoritative kernel call graph (v2-design M4) can replace the lexer's
`callgraph_source: regex` with. Functions are identified by (file, original name) because the
kernel renames same-named statics (`helper`, `helper_0`).

A failure here is never an analysis failure: every problem comes back as a `status`, and consumers
fall back to running without kernel facts. The compiled module is never stored in the run
directory: target code run by earlier jobs can write there, and this module loads into trusted
Frama-C runs.

CLI: `kernel_ast.py selftest` says whether the dump still compiles and loads against this kernel.
A failure only degrades briefs, so nothing else would notice it after a Frama-C upgrade.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from framac_common import augment_framac_cppflags  # noqa: E402

DUMP_SOURCE = Path(__file__).resolve().parent / "kernel_ast_dump.ml"
OUT_ENV = "FRAMAC_AST_DUMP_OUT"
COMPILE_TIMEOUT_S = 120
# Parsing and normalizing only: far below any Eva or WP limit. It decides nothing but hints.
DUMP_TIMEOUT_S = 600

# Fileloc.pretty: `file:12`, `file:12-15`, `file:12:3-9`, `file:12-15:3-9`, or a generated location.
_LOC_RE = re.compile(r"^(?P<file>.+?):(?P<line>\d+)(?:-(?P<end>\d+))?(?::\d+(?:-\d+)?)?$")
_NOTE_LIMIT = 2000
_SELFTEST_SOURCE = """int total(const int *a, int n) {
  int s = 0;
  for (int i = 0; i < n; i++) s += a[i];
  return s;
}
"""


def parse_location(text: str | None) -> dict:
    """{file, line, end_line} of a kernel location string; empty values when it has none."""
    m = _LOC_RE.match((text or "").strip())
    if not m:
        return {"file": "", "line": 0, "end_line": 0}
    line = int(m.group("line"))
    return {"file": m.group("file"), "line": line, "end_line": int(m.group("end") or line)}


def _failed(status: str, reason: str) -> dict:
    return {"status": status, "reason": reason[-_NOTE_LIMIT:], "functions": []}


def compile_dump_module(
    work_dir: Path,
    runner: Callable | None = None,
    dump_source: Path = DUMP_SOURCE,
    packages: Iterable[str] = ("frama-c.kernel",),
) -> tuple[Path | None, str]:
    """
    (path of the .cmxs, "") or (None, reason). `work_dir` must be private to this process. `packages`
    are the findlib packages the module compiles against (a plugin's API, `unix`).
    """
    run = runner or subprocess.run
    source = work_dir / dump_source.name
    shutil.copyfile(dump_source, source)
    target = source.with_suffix(".cmxs")
    # Alerts and warnings stay off: a deprecation in a future kernel must not stop the dump.
    cmd = [
        "ocamlfind",
        "ocamlopt",
        "-shared",
        "-alert",
        "-deprecated",
        "-w",
        "-a",
        "-package",
        ",".join(packages),
        source.name,
        "-o",
        target.name,
    ]
    try:
        proc = run(
            cmd,
            cwd=work_dir,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=COMPILE_TIMEOUT_S,
        )
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        return None, f"cannot run ocamlfind: {exc}"
    if proc.returncode != 0 or not target.is_file():
        return None, f"{dump_source.name} does not compile against this kernel: {proc.stdout or ''}{proc.stderr or ''}"
    return target, ""


def dump_kernel_ast(
    sources: Iterable[str],
    cppflags: str = "-I.",
    machdep: str = "gcc_x86_64",
    main: str | None = None,
    cwd: Path | None = None,
    timeout: int | None = DUMP_TIMEOUT_S,
    runner: Callable | None = None,
) -> dict:
    """
    {"status": "ok", "functions": [...]} with one entry per defined function (kernel_ast_dump.ml),
    or {"status": "tool_missing" | "compile_failed" | "parse_failed" | "timeout", "reason": ..., "functions": []}.
    """
    run = runner or subprocess.run
    srcs = [str(s) for s in sources]
    if not srcs:
        return _failed("parse_failed", "no sources")
    with tempfile.TemporaryDirectory(prefix="framac-kernel-ast-") as tmp:
        work_dir = Path(tmp)
        module, why = compile_dump_module(work_dir, runner=run)
        if module is None:
            return _failed("compile_failed", why)
        out = work_dir / "ast.json"
        cmd = [
            "frama-c",
            "-no-unicode",
            "-no-annot",  # facts describe the code: a speculative ACSL error must not lose them
            "-keep-unused-functions",
            "all",
            "-machdep",
            machdep,
            f"-cpp-extra-args={augment_framac_cppflags(cppflags)}",
            *srcs,
        ]
        if main:
            cmd += ["-main", main]
        cmd += ["-load-module", str(module)]
        env = dict(os.environ)
        env[OUT_ENV] = str(out)
        try:
            proc = run(
                cmd,
                cwd=cwd,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return _failed("timeout", f"frama-c did not finish parsing within {timeout} s")
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            return _failed("tool_missing", f"cannot run frama-c: {exc}")
        if proc.returncode != 0 or not out.is_file():
            return _failed("parse_failed", f"{proc.stdout or ''}{proc.stderr or ''}")
        try:
            doc = json.loads(out.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return _failed("parse_failed", f"unreadable dump: {exc}")
    functions = doc.get("functions") if isinstance(doc, dict) else None
    if not isinstance(functions, list):
        return _failed("parse_failed", "dump has no 'functions' list")
    return {"status": "ok", "reason": None, "functions": functions, "command": shlex.join(cmd[:-2])}


def direct_call_edges(functions: Iterable[dict]) -> dict[str, list[str]]:
    """Kernel name -> kernel names called directly, over the definitions in `functions`."""
    functions = list(functions)
    defined = {str(fn.get("kernel_name")) for fn in functions}
    edges: dict[str, list[str]] = {}
    for fn in functions:
        targets = {
            str(call.get("kernel_name"))
            for call in fn.get("calls") or []
            if not call.get("indirect") and str(call.get("kernel_name")) in defined
        }
        edges[str(fn.get("kernel_name"))] = sorted(targets)
    return edges


def recursion_cycles(edges: dict[str, list[str]]) -> list[list[str]]:
    """Strongly connected components with a cycle (self-loops included), iterative Tarjan."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    cycles: list[list[str]] = []
    counter = 0
    for root in sorted(edges):
        if root in index:
            continue
        work: list[tuple[str, int]] = [(root, 0)]
        while work:
            node, child_pos = work.pop()
            if child_pos == 0:
                index[node] = low[node] = counter
                counter += 1
                stack.append(node)
                on_stack.add(node)
            advanced = False
            children = edges.get(node) or []
            for pos in range(child_pos, len(children)):
                child = children[pos]
                if child not in index:
                    work.append((node, pos + 1))
                    work.append((child, 0))
                    advanced = True
                    break
                if child in on_stack:
                    low[node] = min(low[node], index[child])
            if advanced:
                continue
            if low[node] == index[node]:
                component = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    component.append(member)
                    if member == node:
                        break
                if len(component) > 1 or node in (edges.get(node) or []):
                    cycles.append(sorted(component))
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
    return sorted(cycles)


def call_graph(functions: Iterable[dict]) -> dict:
    """
    The kernel's call graph over these definitions: direct edges, indirect call sites (no resolved
    target: that takes Eva) and recursion cycles. Names are kernel names; each function record
    carries `name` and its location for mapping them back to (file, original name).
    """
    functions = list(functions)
    edges = direct_call_edges(functions)
    indirect = {
        fn.get("kernel_name"): [call.get("expr") for call in fn.get("calls") or [] if call.get("indirect")]
        for fn in functions
    }
    return {
        "callgraph_source": "frama-c-kernel",
        "edges": edges,
        "indirect_calls": {name: sites for name, sites in indirect.items() if sites},
        "recursion_cycles": recursion_cycles(edges),
    }


def selftest(runner: Callable | None = None) -> dict:
    """Compile and load the dump, and check it on one known loop."""
    with tempfile.TemporaryDirectory(prefix="framac-kernel-ast-selftest-") as tmp:
        source = Path(tmp) / "selftest.c"
        source.write_text(_SELFTEST_SOURCE, encoding="utf-8")
        res = dump_kernel_ast([str(source)], cwd=Path(tmp), runner=runner)
    functions = res.get("functions") or []
    loops = (functions[0].get("loops") or []) if functions else []
    ok = res.get("status") == "ok" and len(loops) == 1 and loops[0].get("guard") == "i < n"
    return {"ok": ok, "status": res.get("status"), "reason": res.get("reason") or ("" if ok else "unexpected dump")}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Frama-C kernel AST facts.")
    parser.add_subparsers(dest="cmd", required=True).add_parser("selftest", help="Check the dump against this kernel")
    parser.parse_args(argv)
    res = selftest()
    print(json.dumps(res, indent=2))
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
