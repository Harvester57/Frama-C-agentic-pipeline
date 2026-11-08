#!/usr/bin/env python3
"""
Phase 0 model (docs/phase0-implementation-plan.md step I3): the inventory and the call graph of the
target, from one Frama-C parse per link unit of the build capture, named as Eva and WP will name them.
Stdlib only.

    phase0_model.py run [--capture workspace/reports/build_capture.json]
                        [--out workspace/reports/phase0_model.json] [--jobs N] [--no-broker]
                        [--alias | --no-alias]
                        [--threat-model PATH]
    phase0_model.py selftest

`run` reads the build capture (scripts/build_capture.py), the scratch tree it names and the run's
snapshot (scripts/target_env.py), so it runs in a container started with the wrapper's -Scratch
(sh: --scratch), in the analysis image:

  1. parse jobs: one per link unit that is not a test unit, over the unit's own sources with each file's
     own flags. Units that compile the same sources with the same flags share one parse. Jobs run in
     parallel, each under a `parse` lease of the container broker (resources.py run --class parse);
  2. each parse loads scripts/phase0_dump.ml: defined functions (kernel name, source name, definition
     line span, storage, signature, loops, cyclomatic complexity), direct calls, indirect call sites
     with the called signature, and the functions whose address is taken;
  3. the target's headers outside the project come from the snapshot (`-idirafter <snapshot>/<dir>`,
     after Frama-C's own libc), the generated headers from the build tree, so no target package is
     needed where the parse runs;
  4. a job Frama-C cannot parse falls back to GCC `-fcallgraph-info` on its compile commands: functions
     and direct edges, with indirect call sites left unresolved, flagged with Frama-C's first error;
  5. model-wide resolution, as the linker sees it:
     - a call to a function the unit does not define resolves to a global of the same name in a unit
       it links, else in a unit that links it, else it is an external (kept per caller under
       `external_calls`: the input readers it calls decide its trust);
     - an indirect call site resolves to every address-taken function of the same signature in the
       programs (executables, shared libraries, unconsumed static libraries) that contain the unit;
     - a project function passed to pthread_create/thrd_create is a thread entry, and its unit is
       concurrent; one passed to another external (qsort, signal) is a callback;
  6. macro aliases: `cc -E -dD` per translation unit, keeping each object-like `#define a b` written in
     a project file whose value resolves (through other such aliases) to a defined function;
  7. entry points, link units and the test marking come from the build capture;
  8. trust (step I7, scripts/trust.py): each function's `trust` (untrusted or trusted, the deciding rule,
     whether it is on the trust boundary) from the library API, the input readers' call graph and the
     structured threat model (THREAT_MODEL.md, --threat-model); a missing one records `no_threat_model`.
     `trust.py run` redoes it after a CodeQL run.

With `--alias` (plan step I4; off by default, see docs/phase0-redesign.md §7 "Alias narrowing"), each
parse also loads scripts/phase0_alias.ml, which runs Frama-C's Alias plugin on the same AST and reports,
per indirect call site, the functions the called pointer may point to. A site's type-match candidates
are then intersected with them. A site keeps its full type match, with the reason recorded, when Alias
fails, times out (ALIAS_TIMEOUT_S), crashes, has no state there, finds no function in the pointer's
target, or names only functions outside the type match. Every site records which narrowing applied
(`narrowing`, `narrowing_reason`, `dropped`), and the edges a narrowed site keeps carry the source
`alias` next to `type-match`. Alias is flow-sensitive within a function but starts each function from
the global initializers only, so a function pointer reassigned in another function or another unit is
narrowed to its initializer: that is why it stays off by default.

Functions are identified as `file#name` (paths relative to the target root): same-named statics stay
apart, and a function defined in a project header (static inline) belongs to every unit compiling it.
Every function, edge and alias carries its source. The output is workspace/reports/phase0_model.json
(schemas/phase0_model.schema.json). A failure is a status in the model, never a crash: the command exits
0 when the model was written, 1 when no model could be built (missing capture, dump module error), and
4 when Frama-C parsed none of the units (status `no_unit_parsed`: the model is written for its errors,
and Phase 0 stops there).

`selftest` compiles the dump module and checks it on a two-file program (a static collision, a
callback, an indirect call); the image build runs it, so a kernel upgrade that breaks the dump fails
there.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import re
import shlex
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_capture as bc  # noqa: E402
import target_env  # noqa: E402
from framac_common import atomic_write_json, augment_framac_cppflags, load_json_optional, utc_now  # noqa: E402
from kernel_ast import compile_dump_module  # noqa: E402

SCHEMA_VERSION = 1
DUMP_SOURCE = Path(__file__).resolve().parent / "phase0_dump.ml"
DUMP_OUT_ENV = "FRAMAC_P0_DUMP_OUT"
DEFAULT_CAPTURE = "workspace/reports/build_capture.json"
DEFAULT_OUT = "workspace/reports/phase0_model.json"
LOG_DIR = "workspace/reports/phase0_model"
MACHDEP = "gcc_x86_64"
GCC_TIMEOUT_S = 300
ERROR_CHARS = 400
# Exit code when Frama-C parsed no unit (build_capture.py uses 3 for needs_build_recipe).
NO_UNIT_PARSED_RC = 4
THREAD_SPAWNERS = {"pthread_create": 2, "thrd_create": 1}
SOURCE_FRAMAC = "frama-c-kernel"
SOURCE_GCC = "gcc-callgraph-info"
SOURCE_ALIAS = "alias"
ALIAS_SOURCE = Path(__file__).resolve().parent / "phase0_alias.ml"
ALIAS_PACKAGES = ("frama-c.kernel", "frama-c-alias.core", "unix")
ALIAS_OUT_ENV = "FRAMAC_P0_ALIAS_OUT"
ALIAS_TIMEOUT_ENV = "FRAMAC_P0_ALIAS_TIMEOUT"
# Fixed, not sized from the machine: it decides which sites are narrowed.
ALIAS_TIMEOUT_S = 300
ALIAS_DEFAULT = False  # I4: measured, not adopted (docs/phase0-redesign.md §7)

_LOC_RE = re.compile(r"^(?P<file>.+?):(?P<line>\d+)(?:-\d+)?(?::\d+(?:-\d+)?)?$")
_LINE_MARKER_RE = re.compile(r'^#\s*(?:line\s+)?\d+\s+"(?P<file>[^"]*)"')
_OBJECT_DEFINE_RE = re.compile(r"^#define\s+(?P<name>[A-Za-z_]\w*)\s+(?P<value>[A-Za-z_]\w*)\s*$")
_CI_NODE = re.compile(r'node: \{ title: "([^"]+)" label: "([^"\\]+)(?:\\n([^":]+):(\d+))?')
_CI_EDGE = re.compile(r'edge: \{ sourcename: "([^"]+)" targetname: "([^"]+)"')
_ERROR_RE = re.compile(r"\b(?:User Error|Error|error|Failure|fatal)\b")

_SELFTEST_FILES = {
    "a.c": (
        "static int helper(int x) { return x + 1; }\n"
        "int twice(int x) { return 2 * x; }\n"
        "int apply(int (*f)(int), int x) { return f(x); }\n"
        "int run_a(int x) { return apply(twice, helper(x)); }\n"
        "int counter;\n"
        "void fill(int *p, int n) { for (int i = 0; i < n; i++) p[i] = 0; counter++; }\n"
    ),
    "b.c": (
        "static int helper(int x) { return x - 1; }\n"
        "int apply(int (*f)(int), int x);\n"
        "int run_b(int x) { int s = 0; for (int i = 0; i < x; i++) s += helper(i); return s; }\n"
    ),
}


# ---------------------------------------------------------------------------------------------------
# Paths and flags
# ---------------------------------------------------------------------------------------------------


def tree_rel(path: str, tree: str) -> str | None:
    """
    A Frama-C or gcc location path relative to the tree (absolute, or relative to the tree, where the
    tools run), or None. Frama-C prints its own files under symbolic roots (`FRAMAC_SHARE/libc/...`).
    """
    if not path or path.startswith(("FRAMAC_", "<")):
        return None
    p = path if posixpath.isabs(path) else posixpath.join(tree, path)
    return bc.tree_rel(posixpath.normpath(p), tree)


def _body_facts(fn: dict) -> dict:
    """The dump's formals and writes (schema 3, step I9), when the dump module recorded them."""
    out: dict[str, Any] = {}
    if isinstance(fn.get("formals"), list):
        out["formals"] = fn["formals"]
    w = fn.get("writes")
    if isinstance(w, dict):
        out["writes"] = {
            "pointer": int(w.get("pointer") or 0),
            "params": list(w.get("params") or []),
            "globals": list(w.get("globals") or []),
        }
    return out


def parse_location(loc: str) -> tuple[str, int] | None:
    m = _LOC_RE.match((loc or "").strip())
    return (m.group("file"), int(m.group("line"))) if m else None


def snapshot_dirs(snapshot_root: str | None, system_flags: Iterable[str]) -> list[str]:
    """
    `-idirafter` options for the target's system headers, read from the snapshot: the include
    directories the compile named outside the tree, then gcc's default system directories, each only
    when the snapshot has it. Searched after Frama-C's libc, so a libc header never comes from there.
    """
    return target_env.include_flags(snapshot_root, system_flags)


def framac_file_flags(flags: list[str], tree: str) -> list[str]:
    """
    Per-file preprocessing flags for Frama-C: project paths absolute, flags Frama-C's libc rejects
    dropped (C89 refuses the `//` comments of its headers), each token quoted for the cpp command line.
    """
    out: list[str] = []
    for tok in bc.absolute_flags(flags, tree):
        if tok in ("-std=c89", "-std=c90", "-std=gnu89", "-std=gnu90", "-std=iso9899:1990"):
            continue
        out.append(shlex.quote(tok))
    return out


def job_key(compiles: list[dict]) -> str:
    """Units that compile the same sources with the same flags share one parse."""
    material = json.dumps(sorted([c["source"], c["flags"], c["system_flags"]] for c in compiles))
    return hashlib.sha256(material.encode()).hexdigest()[:16]


def first_error(log: str) -> str:
    """The first error line and the line after it (Frama-C puts the message there), else the last line."""
    lines = (log or "").splitlines()
    for i, line in enumerate(lines):
        if _ERROR_RE.search(line) and "warning" not in line.lower():
            return " ".join(s.strip() for s in lines[i : i + 2] if s.strip())[:ERROR_CHARS]
    tail = (log or "").strip().splitlines()
    return tail[-1][:ERROR_CHARS] if tail else ""


# ---------------------------------------------------------------------------------------------------
# Running tools
# ---------------------------------------------------------------------------------------------------

Runner = Callable[..., Any]


def run_tool(
    cmd: list[str], cwd: str | None, timeout: int, env: dict[str, str] | None = None, runner: Runner | None = None
) -> tuple[int, str]:
    try:
        proc = (runner or subprocess.run)(
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
        return 124, f"timeout after {timeout} s: {shlex.join(cmd)[:300]}"
    except OSError as exc:
        return 127, f"cannot run {cmd[0]}: {exc}"
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def parse_timeout() -> int:
    from resources import CLASSES

    return CLASSES["parse"].wall_timeout_s or 1800


def leased(cmd: list[str], key: str, broker: bool) -> list[str]:
    """`cmd` under a `parse` lease of the container broker, as Make runs its jobs."""
    if not broker:
        return cmd
    script = Path(__file__).resolve().parent / "resources.py"
    return [sys.executable, str(script), "run", "--class", "parse", "--key", key, "--", *cmd]


# ---------------------------------------------------------------------------------------------------
# One parse
# ---------------------------------------------------------------------------------------------------


def framac_parse(
    job: dict,
    tree: str,
    snapshot_root: str | None,
    module: Path,
    log_dir: Path,
    broker: bool,
    runner: Runner | None = None,
    alias_module: Path | None = None,
) -> dict:
    """
    {status: ok, dump, seconds} or {status: parse_failed, error, seconds}. With `alias_module`, the
    same run loads it and `alias` holds its report, or {status: crashed, error} when the run produced
    the dump but no Alias report.
    """
    compiles = job["compiles"]
    with tempfile.TemporaryDirectory(prefix="framac-p0-") as tmp:
        out = Path(tmp) / "dump.json"
        alias_out = Path(tmp) / "alias.json"
        spec = []
        system: list[str] = []
        for c in compiles:
            flags = framac_file_flags(c["flags"], tree)
            if flags:
                spec.append(f"{posixpath.join(tree, c['source'])}:{' '.join(f for f in flags if ',' not in f)}")
            system += c["system_flags"]
        extra = augment_framac_cppflags(" ".join(snapshot_dirs(snapshot_root, system)))
        cmd = [
            "frama-c",
            "-no-unicode",
            "-no-annot",  # the code, not its annotations: a bad ACSL comment must not lose the model
            "-keep-unused-functions",
            "all",
            "-machdep",
            MACHDEP,
            f"-cpp-extra-args={extra}",
        ]
        if spec:
            cmd.append("-cpp-extra-args-per-file=" + ",".join(spec))
        cmd += sorted({posixpath.join(tree, c["source"]) for c in compiles})
        env = dict(os.environ, **{DUMP_OUT_ENV: str(out)})
        if alias_module is None:
            cmd += ["-load-module", str(module)]
        else:
            # The dump's extension runs first and writes its file before Alias starts.
            cmd += ["-load-module", f"{module},{alias_module}"]
            env.update({ALIAS_OUT_ENV: str(alias_out), ALIAS_TIMEOUT_ENV: str(ALIAS_TIMEOUT_S)})
        t0 = time.monotonic()
        rc, log = run_tool(leased(cmd, f"p0-{job['key']}", broker), tree, parse_timeout(), env, runner)
        seconds = round(time.monotonic() - t0, 2)
        _write_log(log_dir, job["key"], "framac", cmd, log)
        # A run that crashed in Alias after the dump was written still parsed: the dump is complete
        # (written to a temporary name, then renamed).
        if not out.is_file() or (rc != 0 and alias_module is None):
            return {"status": "parse_failed", "error": first_error(log), "seconds": seconds}
        try:
            dump = json.loads(out.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return {"status": "parse_failed", "error": f"unreadable dump: {exc}", "seconds": seconds}
        res: dict[str, Any] = {"status": "ok", "dump": dump, "seconds": seconds}
        if alias_module is not None:
            res["alias"] = read_alias_report(alias_out, rc, log)
    return res


def read_alias_report(path: Path, rc: int, log: str) -> dict:
    """The Alias module's report, or {status: crashed, error} when the run ended without one."""
    if path.is_file():
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(doc, dict):
                return doc
        except (OSError, ValueError) as exc:
            return {"status": "crashed", "error": f"unreadable Alias report: {exc}"}
    reason = first_error(log) if rc != 0 else "no Alias report"
    return {"status": "crashed", "error": f"exit {rc}: {reason}"[:ERROR_CHARS]}


def gcc_callgraph(job: dict, tree: str, snapshot_root: str | None, log_dir: Path, runner: Runner | None = None) -> dict:
    """
    GCC fallback: per compile, `-fcallgraph-info` nodes and edges. {status, errors, functions, edges,
    indirect}: functions by id, edges as (caller id, callee id or None for an undefined callee, callee
    name), indirect call sites by caller id.
    """
    functions: dict[str, dict] = {}
    edges: list[tuple[str, str | None, str]] = []
    indirect: list[str] = []
    errors: list[str] = []
    logs: list[str] = []
    with tempfile.TemporaryDirectory(prefix="framac-p0-gcc-") as tmp:
        for n, c in enumerate(job["compiles"]):
            base = f"{tmp}/{n}"
            argv = bc.compile_argv(c["arguments"], posixpath.join(tree, c["source"]), f"{base}.o")
            cmd = ["gcc", *argv[1:-4], *snapshot_dirs(snapshot_root, c["system_flags"]), *argv[-4:]]
            cmd += ["-fcallgraph-info", "-dumpbase", base]
            rc, log = run_tool(cmd, bc.absolute(c["cwd"], tree), GCC_TIMEOUT_S, runner=runner)
            logs.append(f"$ {shlex.join(cmd)}\n{log}")
            ci = Path(f"{base}.ci")
            if rc != 0 or not ci.is_file():
                errors.append(first_error(log) or f"gcc exited {rc}")
                continue
            text = ci.read_text(encoding="utf-8", errors="replace")
            labels: dict[str, str] = {}
            ids: dict[str, str] = {}  # node title -> id, for the functions defined in this translation unit
            for title, label, file, line in _CI_NODE.findall(text):
                labels[title] = label
                rel = tree_rel(file, tree) if file else None
                if rel is not None:
                    ids[title] = f"{rel}#{label}"
                    functions[ids[title]] = {"file": rel, "name": label, "line": int(line), "static": ":" in title}
            for src, dst in _CI_EDGE.findall(text):
                if src not in ids:
                    continue
                if labels.get(dst) == "Indirect Call Placeholder":
                    indirect.append(ids[src])
                else:
                    edges.append((ids[src], ids.get(dst), labels.get(dst, dst)))
    _write_log(log_dir, job["key"], "gcc", None, "\n".join(logs))
    status = "ok" if not errors else ("partial" if functions else "failed")
    return {"status": status, "errors": errors, "functions": functions, "edges": edges, "indirect": indirect}


def macro_aliases(compile: dict, tree: str, snapshot_root: str | None, runner: Runner | None = None) -> list[dict]:
    """Object-like `#define a b` (b an identifier) written in a project file, from `gcc -E -dD`."""
    argv = bc.compile_argv(compile["arguments"], posixpath.join(tree, compile["source"]), "/dev/null")
    cmd = ["gcc", *argv[1:-4], *snapshot_dirs(snapshot_root, compile["system_flags"]), "-E", "-dD", argv[-3]]
    rc, out = run_tool(cmd, bc.absolute(compile["cwd"], tree), GCC_TIMEOUT_S, runner=runner)
    if rc != 0:
        return []
    return parse_defines(out, tree)


def parse_defines(text: str, tree: str) -> list[dict]:
    found: list[dict] = []
    current: str | None = None
    for line in text.splitlines():
        m = _LINE_MARKER_RE.match(line)
        if m:
            current = tree_rel(m.group("file"), tree) if not m.group("file").startswith("<") else None
            continue
        if current is None:
            continue
        d = _OBJECT_DEFINE_RE.match(line)
        if d and d.group("name") != d.group("value"):
            found.append({"alias": d.group("name"), "value": d.group("value"), "file": current})
    return found


def _write_log(log_dir: Path, key: str, tool: str, cmd: list[str] | None, log: str) -> None:
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        head = shlex.join(cmd) + "\n\n" if cmd else ""
        (log_dir / f"{key}.{tool}.log").write_text(head + log, encoding="utf-8")
    except OSError:
        pass


# ---------------------------------------------------------------------------------------------------
# The model
# ---------------------------------------------------------------------------------------------------


def plan_jobs(capture: dict) -> tuple[list[dict], dict[str, str]]:
    """Parse jobs over the non-test units, and each unit's job key."""
    by_object = {c["object"]: c for c in capture.get("compiles") or []}
    jobs: dict[str, dict] = {}
    unit_job: dict[str, str] = {}
    for name, u in sorted((capture.get("units") or {}).items()):
        if u.get("test"):
            continue
        own = [by_object[o] for o in u.get("objects") or [] if o in by_object]
        if not own:
            continue
        key = job_key(own)
        unit_job[name] = key
        jobs.setdefault(key, {"key": key, "compiles": own, "units": []})["units"].append(name)
    return list(jobs.values()), unit_job


def alias_site_queues(alias: dict | None) -> dict[str, list[dict]]:
    """An Alias report's sites per caller kernel name, in the dump's order."""
    if not alias or alias.get("status") != "ok":
        return {}
    return {f["kernel_name"]: list(f.get("sites") or []) for f in alias.get("functions") or []}


def match_alias_site(alias: dict, queues: dict[str, list[dict]], caller: str, call: dict, kmap: dict) -> dict:
    """
    Alias's answer for one indirect call of the dump: {status, ids, names}. `status` is the site's
    (`targets`, `no_state`, `no_targets`, `error`), `alias_<status>` when the analysis itself did not
    finish, or `unmatched` when the report has no site at that location. Targets defined in the parse
    are ids; the others are names, resolved like an undefined callee.
    """
    if alias.get("status") != "ok":
        return {"status": f"alias_{alias.get('status') or 'missing'}"}
    queue = queues.get(caller) or []
    for i, s in enumerate(queue):
        if s.get("loc") == call.get("loc") and s.get("expr") == call.get("expr"):
            queue.pop(i)
            break
    else:
        return {"status": "unmatched"}
    out: dict[str, Any] = {"status": s.get("status") or "error"}
    if out["status"] == "targets":
        names = s.get("targets") or []
        out["ids"] = sorted({kmap[n] for n in names if n in kmap})
        out["names"] = sorted({n for n in names if n not in kmap})
    return out


def closures(units: dict) -> dict[str, set[str]]:
    """Each unit with the project libraries it links, transitively."""
    out: dict[str, set[str]] = {}
    for name in units:
        seen = {name}
        stack = list(units[name].get("links") or [])
        while stack:
            lk = stack.pop()
            if lk in seen or lk not in units:
                continue
            seen.add(lk)
            stack += units[lk].get("links") or []
        out[name] = seen
    return out


def reconcile_api_ids(units: dict[str, dict], functions: dict[str, dict]) -> list[str]:
    """
    Map each unit's `entry_points` and `embedded_api` ids to the model's, in place; returns warnings.

    The capture names a function by its compiled source (or the header `nm -l` gives), the model
    by where Frama-C places its definition. They differ for a function defined in a `#include`d
    `.c`, or in a header when the build has no `-g`. Such an id matches no model function, and
    trust, the unit view and the reach gate would then drop that API function without a word. It
    is mapped to the unit's only external function of that name, or kept with a warning.
    """
    by_unit_name: dict[tuple[str, str], list[str]] = defaultdict(list)
    for fid, f in functions.items():
        for unit in f.get("units") or []:
            if not f.get("static"):
                by_unit_name[(unit, str(f.get("name")))].append(fid)
    warnings: list[str] = []
    for name, rec in units.items():
        if rec.get("test") or (rec.get("parse") or {}).get("status") not in ("ok", "gcc_fallback"):
            continue
        for field in ("entry_points", "embedded_api"):
            ids = rec.get(field)
            if not ids:
                continue
            fixed: list[str] = []
            for fid in ids:
                hits = [fid] if fid in functions else sorted(by_unit_name.get((name, fid.rsplit("#", 1)[-1]), []))
                if len(hits) == 1:
                    if hits[0] != fid:
                        warnings.append(f"{name}: {field} {fid} is {hits[0]} in the model")
                    fixed.append(hits[0])
                else:
                    warnings.append(
                        f"{name}: {field} {fid} names no function of the model"
                        + (f" (candidates: {', '.join(hits)})" if hits else "")
                        + "; trust, tiers and the reach gate leave it out"
                    )
                    fixed.append(fid)
            rec[field] = list(dict.fromkeys(fixed))
    return warnings


class ModelBuilder:
    """Merges the parse results of all jobs into one model, resolving across units as the linker does."""

    def __init__(self, capture: dict, tree: str):
        self.tree = tree
        self.units = {n: u for n, u in (capture.get("units") or {}).items() if not u.get("test")}
        self.closure = closures(self.units)
        roots = {n for n in self.units if not any(n in (u.get("links") or []) for u in self.units.values())}
        self.programs = [self.closure[r] for r in sorted(roots)]
        self.functions: dict[str, dict] = {}
        self.edges: dict[tuple[str, str, str], set[str]] = defaultdict(set)
        self.indirect_sites: list[dict] = []
        self.externals: set[str] = set()
        self.external_calls: dict[str, set[str]] = defaultdict(set)  # caller id -> external names it calls
        self.thread_entries: set[str] = set()
        self.concurrent: set[str] = set()
        # Per unit: kernel name -> id, source name -> id of its globals, address-taken ids with signatures.
        self.kmap: dict[str, dict[str, str]] = {}
        self.globals: dict[str, dict[str, str]] = defaultdict(dict)
        self.taken: dict[str, set[str]] = defaultdict(set)
        self.pending_calls: list[tuple[str, str, dict]] = []  # (unit, caller id, call)
        # Step I9: defined global variables (`file#name`) and the formals of declared functions.
        self.global_vars: dict[str, dict] = {}
        self.declared_formals: dict[str, list] = {}
        # Callee id -> (caller id, call location, argument index, bytes): what the callers pass.
        self.arg_sites: dict[str, set[tuple[str, str, str, int]]] = defaultdict(set)

    def _record_arg_sizes(self, caller: str, callee: str, call: dict) -> None:
        sizes = call.get("arg_sizes")
        if not isinstance(sizes, dict):
            return
        for idx, n in sizes.items():
            if isinstance(n, int) and n > 0:
                self.arg_sites[callee].add((caller, str(call.get("loc") or ""), str(idx), n))

    def param_sizes(self, fid: str) -> dict[str, dict]:
        """Per argument index: the smallest and largest object the callers pass, and over how many sites."""
        by_idx: dict[str, list[int]] = defaultdict(list)
        for _caller, _loc, idx, n in self.arg_sites.get(fid, ()):
            by_idx[idx].append(n)
        return {
            i: {"min": min(v), "max": max(v), "sites": len(v)}
            for i, v in sorted(by_idx.items(), key=lambda kv: int(kv[0]))
        }

    def add_function(self, fid: str, unit: str, record: dict) -> None:
        rec = self.functions.get(fid)
        if rec is None:
            rec = self.functions[fid] = {**record, "units": [], "kernel_names": {}}
        elif rec.get("source") == SOURCE_GCC and record.get("source") == SOURCE_FRAMAC:
            # A function compiled by a unit on the GCC fallback and by one Frama-C parsed (a shared
            # source, a header function): the parse knows its signature, formals, loops, writes and
            # last line, which the fallback cannot. Its record wins, whichever job came first.
            keep = {"units": rec["units"], "kernel_names": rec["kernel_names"]}
            address_taken = bool(rec.get("address_taken"))
            rec.clear()
            rec.update(record, **keep)
            rec["address_taken"] = address_taken or bool(record.get("address_taken"))
        if unit not in rec["units"]:
            rec["units"].append(unit)
        if record.get("kernel_name"):
            rec["kernel_names"][unit] = record["kernel_name"]
        rec.pop("kernel_name", None)

    def add_dump(self, units: list[str], dump: dict, alias: dict | None = None) -> None:
        """
        One parse's dump. `alias` is that parse's Alias report (scripts/phase0_alias.ml) when the
        model runs with Alias, else None: its sites match the dump's indirect calls in order.
        """
        own_files = {u: set(self.units[u].get("files") or []) for u in units}
        alias_sites = alias_site_queues(alias)
        kmap: dict[str, str] = {}
        sig: dict[str, str] = {}
        for fn in dump.get("functions") or []:
            loc = parse_location(fn.get("loc", ""))
            rel = tree_rel(loc[0], self.tree) if loc else None
            if loc is None or rel is None:
                continue  # Frama-C's libc, the stubs, a snapshot header: not the project's code
            fid = f"{rel}#{fn['name']}"
            kmap[fn["kernel_name"]] = fid
            sig[fn["kernel_name"]] = fn.get("signature") or ""
            first, last = int(fn.get("first_line") or loc[1]), int(fn.get("last_line") or loc[1])
            for u in units:
                header = rel.endswith(".h")
                self.add_function(
                    fid,
                    u,
                    {
                        "file": rel,
                        "name": fn["name"],
                        "kernel_name": fn["kernel_name"],
                        "line": first,
                        "end_line": last,
                        "lines": max(1, last - first + 1),
                        "static": bool(fn.get("static")),
                        "inline": bool(fn.get("inline")),
                        "header": header,
                        "included": not header and rel not in own_files[u],
                        "signature": fn.get("signature") or "",
                        "loops": int(fn.get("loops") or 0),
                        "cyclomatic": int(fn.get("cyclomatic") or 1),
                        "address_taken": False,
                        "source": SOURCE_FRAMAC,
                        **_body_facts(fn),
                    },
                )
                if not fn.get("static"):
                    self.globals[u].setdefault(fn["name"], fid)
        for g in dump.get("globals") or []:
            gloc = parse_location(g.get("loc", ""))
            grel = tree_rel(gloc[0], self.tree) if gloc else None
            # `__fc_*`: Frama-C's own globals (string literals), not the project's.
            if grel is not None and g.get("name") and not str(g["name"]).startswith("__fc_"):
                rec = self.global_vars.setdefault(
                    f"{grel}#{g['name']}",
                    {
                        "name": g["name"],
                        "file": grel,
                        "static": bool(g.get("static")),
                        "type": str(g.get("type") or ""),
                        "units": [],
                    },
                )
                rec["units"] = sorted(set(rec["units"]) | set(units))
        for d in dump.get("declared") or []:
            if d.get("name") and d.get("formals") is not None:
                self.declared_formals.setdefault(d["name"], d["formals"])
        for k in dump.get("address_taken") or []:
            if k in kmap:
                self.functions[kmap[k]]["address_taken"] = True
                for u in units:
                    self.taken[u].add(kmap[k])
        for u in units:
            self.kmap[u] = kmap
        for fn in dump.get("functions") or []:
            caller = kmap.get(fn["kernel_name"])
            if not caller:
                continue
            for call in fn.get("calls") or []:
                if call.get("indirect"):
                    site: dict[str, Any] = {
                        "unit": units[0],
                        "units": list(units),
                        "caller": caller,
                        "expr": call.get("expr"),
                        "signature": call.get("signature"),
                        "loc": call.get("loc"),
                        "candidates": [],
                    }
                    if alias is not None:
                        site["_alias"] = match_alias_site(alias, alias_sites, fn["kernel_name"], call, kmap)
                    self.indirect_sites.append(site)
                    continue
                callee = kmap.get(call.get("kernel_name", ""))
                if callee:
                    # A project function passed to a project function is called through a pointer
                    # there: that indirect site's type match covers it.
                    self.edges[(caller, callee, "direct")].add(SOURCE_FRAMAC)
                    self._record_arg_sizes(caller, callee, call)
                    continue
                args = [kmap.get(a) for a in call.get("function_args") or []]
                for u in units:
                    self.pending_calls.append((u, caller, {**call, "resolved_args": args}))

    def add_gcc(self, units: list[str], g: dict) -> None:
        for fid, info in g["functions"].items():
            for u in units:
                self.add_function(
                    fid,
                    u,
                    {
                        "file": info["file"],
                        "name": info["name"],
                        "line": info["line"],
                        "end_line": info["line"],
                        "lines": None,
                        "static": info["static"],
                        "inline": False,
                        "header": info["file"].endswith(".h"),
                        "included": False,
                        "signature": "",
                        "loops": None,
                        "cyclomatic": None,
                        "address_taken": False,
                        "source": SOURCE_GCC,
                    },
                )
                if not info["static"]:
                    self.globals[u].setdefault(info["name"], fid)
        for caller in g["indirect"]:
            # No call-site type in -fcallgraph-info: the site stays unresolved.
            self.indirect_sites.append(
                {"unit": units[0], "units": list(units), "caller": caller, "expr": None, "signature": None,
                 "loc": None, "candidates": []}
            )  # fmt: skip
        for caller, callee, callee_name in g["edges"]:
            if callee:
                self.edges[(caller, callee, "direct")].add(SOURCE_GCC)
                continue
            # Defined in another translation unit: of this unit (GCC sees one file at a time), or linked.
            for u in units:
                self.pending_calls.append(
                    (u, caller, {"name": callee_name, "function_args": [], "resolved_args": [], "gcc": True})
                )

    def _lookup_global(self, unit: str, name: str) -> str | None:
        """A global of that name in a unit this one links, else in a unit that links this one."""
        for other in sorted(self.closure.get(unit, set()) - {unit}):
            if name in self.globals.get(other, {}):
                return self.globals[other][name]
        for other, clos in sorted(self.closure.items()):
            if other != unit and unit in clos and name in self.globals.get(other, {}):
                return self.globals[other][name]
        return None

    def resolve(self) -> None:
        for unit, caller, call in self.pending_calls:
            name = call.get("name") or ""
            own = self.globals.get(unit, {}).get(name) if call.get("gcc") else None
            callee = own or self._lookup_global(unit, name)
            source = SOURCE_GCC if call.get("gcc") else SOURCE_FRAMAC
            if callee:
                self.edges[(caller, callee, "direct")].add(source)
                self._record_arg_sizes(caller, callee, call)
                continue
            self.externals.add(name)
            if name:
                self.external_calls[caller].add(name)
            for fid in call.get("resolved_args") or []:
                if not fid:
                    continue
                if name in THREAD_SPAWNERS:
                    self.thread_entries.add(fid)
                    self.concurrent.add(unit)
                    self.edges[(caller, fid, "indirect")].add("thread-spawn")
                else:
                    self.edges[(caller, fid, "indirect")].add("callback-arg")
        for site in self.indirect_sites:
            alias = site.pop("_alias", None)
            if site.get("signature") is None:
                site.update(narrowing="none", narrowing_reason="gcc_fallback", dropped=[])
                continue
            pool: set[str] = set()
            for prog in self.programs:
                if any(u in prog for u in site["units"]):
                    for u in prog:
                        pool |= self.taken.get(u, set())
            cands = sorted(f for f in pool if self.functions[f]["signature"] == site["signature"])
            kept, reason = self._narrow(site, cands, alias)
            site["candidates"] = kept
            site.update(
                narrowing="alias" if reason == "alias" else "none",
                narrowing_reason=reason,
                dropped=sorted(set(cands) - set(kept)),
            )
            for c in kept:
                sources = self.edges[(site["caller"], c, "indirect")]
                sources.add("type-match")
                if reason == "alias":
                    sources.add(SOURCE_ALIAS)

    def _narrow(self, site: dict, cands: list[str], alias: dict | None) -> tuple[list[str], str]:
        """
        The candidates a site keeps and why: `alias` when Alias's targets narrowed the type match,
        else the reason the full type match stays (`disabled`, `alias_<status>`, `no_targets`, ...).
        """
        if alias is None:
            return cands, "disabled"
        if not cands:
            return cands, "no_candidates"
        if alias["status"] != "targets":
            return cands, alias["status"]
        targets: set[str] = set(alias.get("ids") or [])
        for name in alias.get("names") or []:
            fid = self._lookup_global(site["unit"], name) or self.globals.get(site["unit"], {}).get(name)
            if fid:
                targets.add(fid)
        kept = [c for c in cands if c in targets]
        if not kept:
            # Alias names functions, none of the call's type: a cast. Trust the type match.
            return cands, "disjoint"
        return kept, "alias"

    def aliases(self, defines: Iterable[dict]) -> dict[str, dict]:
        """Macro aliases whose value resolves, through other aliases, to defined functions."""
        raw: dict[str, dict] = {}
        for d in defines:
            raw.setdefault(d["alias"], d)
        by_name: dict[str, list[str]] = defaultdict(list)
        for fid, f in self.functions.items():
            by_name[f["name"]].append(fid)
        out: dict[str, dict] = {}
        for alias, d in sorted(raw.items()):
            chain = [d["value"]]
            while chain[-1] in raw and chain[-1] not in by_name and len(chain) < 16 and chain[-1] != alias:
                chain.append(raw[chain[-1]]["value"])
            target = chain[-1]
            if target in by_name and alias not in by_name:
                out[alias] = {
                    "function": target,
                    "ids": sorted(by_name[target]),
                    "via": chain[:-1],
                    "defined_in": d["file"],
                    "source": "preprocessor",
                }
        return out


def build_model(
    capture_path: Path,
    out_path: Path,
    jobs_n: int | None = None,
    broker: bool = True,
    runner: Runner | None = None,
    alias: bool = ALIAS_DEFAULT,
) -> tuple[dict, int]:
    t0 = time.monotonic()
    model: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "status": "error",
        "capture": str(capture_path),
        "warnings": [],
    }
    capture = load_json_optional(capture_path, None)
    if not isinstance(capture, dict) or capture.get("status") != "ok":
        status = capture.get("status") if isinstance(capture, dict) else "missing"
        model["error"] = f"no usable build capture ({status}): run build_capture.py first"
        return model, 1
    tree = str((capture.get("scratch") or {}).get("tree") or "")
    snapshot_root = (capture.get("snapshot") or {}).get("root")
    if not tree or not os.path.isdir(tree):
        model["error"] = f"the capture's scratch tree {tree or '(none)'} is not mounted: run with -Scratch"
        return model, 1
    model.update(
        tree=tree,
        snapshot={"root": snapshot_root, "digest": (capture.get("snapshot") or {}).get("digest")},
        capture_generated_at=capture.get("generated_at"),
    )
    log_dir = out_path.parent / Path(LOG_DIR).name
    jobs, unit_job = plan_jobs(capture)
    builder = ModelBuilder(capture, tree)
    with tempfile.TemporaryDirectory(prefix="framac-p0-module-") as tmp:
        module, why = compile_dump_module(Path(tmp), runner=runner, dump_source=DUMP_SOURCE)
        if module is None:
            model["error"] = why[-2000:]
            model["dump_module"] = {"status": "compile_failed"}
            return model, 1
        model["dump_module"] = {"status": "ok"}
        alias_module: Path | None = None
        alias_info: dict[str, Any] = {"enabled": alias}
        if alias:
            alias_module, why = compile_dump_module(
                Path(tmp), runner=runner, dump_source=ALIAS_SOURCE, packages=ALIAS_PACKAGES
            )
            alias_info.update(module="ok" if alias_module else "compile_failed", timeout_s=ALIAS_TIMEOUT_S)
            if alias_module is None:
                alias_info["error"] = why[-ERROR_CHARS:]
                model["warnings"].append("Alias module does not compile: indirect sites keep their type match")
        model["alias"] = alias_info
        workers = max(1, jobs_n or _default_jobs())

        def one(job: dict) -> dict:
            res = framac_parse(job, tree, snapshot_root, module, log_dir, broker, runner, alias_module)
            if res["status"] != "ok":
                res["gcc"] = gcc_callgraph(job, tree, snapshot_root, log_dir, runner)
            return res

        unique_compiles = {(c["source"], json.dumps(c["flags"])): c for j in jobs for c in j["compiles"]}
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(one, jobs))
            defines = [
                d
                for found in pool.map(lambda c: macro_aliases(c, tree, snapshot_root, runner), unique_compiles.values())
                for d in found
            ]
    parse_jobs = []
    for job, res in zip(jobs, results, strict=True):
        entry: dict[str, Any] = {
            "key": job["key"],
            "units": job["units"],
            "sources": sorted({c["source"] for c in job["compiles"]}),
            "status": res["status"],
            "seconds": res["seconds"],
        }
        if res["status"] == "ok":
            report = res.get("alias") or ({"status": "unavailable"} if alias else None)
            if report is not None:
                entry["alias"] = {
                    k: report[k] for k in ("status", "error", "seconds") if report.get(k) not in (None, "")
                }
                if report.get("status") not in ("ok", "unavailable"):
                    model["warnings"].append(
                        f"{', '.join(job['units'])}: Alias {report.get('status')} ({report.get('error', '')}); "
                        "its indirect sites keep their type match"
                    )
            builder.add_dump(job["units"], res["dump"], report)
        else:
            entry["error"] = res["error"]
            g = res["gcc"]
            entry["gcc_fallback"] = {"status": g["status"], "errors": g["errors"][:5]}
            builder.add_gcc(job["units"], g)
            model["warnings"].append(f"{', '.join(job['units'])}: Frama-C cannot parse ({res['error']}); GCC fallback")
        parse_jobs.append(entry)
    builder.resolve()
    if alias:
        reasons = Counter(s["narrowing_reason"] for s in builder.indirect_sites)
        model["alias"].update(
            sites=dict(sorted(reasons.items())),
            dropped_candidates=sum(len(s["dropped"]) for s in builder.indirect_sites),
            seconds=round(sum((j.get("alias") or {}).get("seconds") or 0 for j in parse_jobs), 3),
        )
    by_key = {j["key"]: j for j in parse_jobs}
    units_out: dict[str, dict] = {}
    for name, u in sorted((capture.get("units") or {}).items()):
        rec = {k: u.get(k) for k in ("kind", "test", "files", "links", "cppflags", "entry_points", "embedded_api")}
        if u.get("test"):
            rec["parse"] = {"status": "skipped_test"}
        elif name not in unit_job:
            rec["parse"] = {"status": "no_sources"}
        else:
            j = by_key[unit_job[name]]
            rec["parse"] = {
                "status": "ok" if j["status"] == "ok" else "gcc_fallback",
                "job": j["key"],
                "seconds": j["seconds"],
            }
            if j["status"] != "ok":
                rec["parse"]["error"] = j["error"]
        rec["concurrent"] = name in builder.concurrent
        units_out[name] = rec
    for fid, f in builder.functions.items():
        f["external_calls"] = sorted(builder.external_calls.get(fid, ()))
        f["units"] = sorted(f["units"])
        f["kernel_names"] = dict(sorted(f["kernel_names"].items()))
        sizes = builder.param_sizes(fid)
        if sizes:
            # Fixed-size buffers passed without a length (keys, nonces): the harness and the seed
            # recorder size them from what the project's own callers pass.
            f["param_sizes"] = sizes
    model["warnings"].extend(reconcile_api_ids(units_out, builder.functions))
    # Phase 0 stops when Frama-C parses no unit: every later phase but fuzzing needs its AST. The
    # model is still written whole, so the fallback errors can be shown to the user.
    parsed = [n for n, u in units_out.items() if u["parse"]["status"] == "ok"]
    rc, status = 0, "ok"
    if not parsed:
        rc, status = NO_UNIT_PARSED_RC, "no_unit_parsed"
        failed = sorted(n for n, u in units_out.items() if u["parse"]["status"] == "gcc_fallback")
        model["error"] = (
            f"Frama-C parsed none of the units ({', '.join(failed)}): see each unit's parse.error"
            if failed
            else "the capture has no non-test unit with sources to parse"
        )
    model.update(
        status=status,
        units=units_out,
        functions=dict(sorted(builder.functions.items())),
        edges=[
            {"caller": a, "callee": b, "kind": k, "sources": sorted(s)}
            for (a, b, k), s in sorted(builder.edges.items())
        ],
        indirect_sites=sorted(builder.indirect_sites, key=lambda s: (s["caller"], s.get("loc") or "")),
        externals=sorted(builder.externals),
        external_formals={
            n: builder.declared_formals[n] for n in sorted(builder.externals) if n in builder.declared_formals
        },
        global_variables=dict(sorted(builder.global_vars.items())),
        macro_aliases=builder.aliases(defines),
        entry_points=sorted({e for u in units_out.values() if not u.get("test") for e in u.get("entry_points") or []}),
        entry_points_source="build_capture",
        thread_entries=sorted(builder.thread_entries),
        parse_jobs=parse_jobs,
        seconds=round(time.monotonic() - t0, 2),
    )
    return model, rc


def annotate_trust(model: dict, threat_model: Path | None = None) -> None:
    """Each function's trust (scripts/trust.py, step I7), without CodeQL: `trust.py run` adds it later."""
    try:
        import trust

        trust.annotate_model(model, threat_model)
    except Exception as exc:  # noqa: BLE001 - the inventory stands without the trust annotation
        model["warnings"].append(f"trust: not annotated ({type(exc).__name__}: {exc})")


def _default_jobs() -> int:
    try:
        from resources import job_budget

        return max(1, int(job_budget().cpus))
    except Exception:  # sizing only: never stop the model for it
        return max(1, os.cpu_count() or 1)


def validate_model(model: dict) -> list[str]:
    from minischema import Validator, load_schema

    here = Path(__file__).resolve().parent
    for cand in (here.parent / "schemas", Path("/opt/framac-pipeline/schemas")):
        path = cand / "phase0_model.schema.json"
        if path.is_file():
            return Validator(load_schema(path)).errors(model)
    return ["schemas/phase0_model.schema.json not found"]


# ---------------------------------------------------------------------------------------------------
# Selftest and CLI
# ---------------------------------------------------------------------------------------------------


def selftest(runner: Runner | None = None) -> dict:
    """Compile the dump module and check it on a known two-file program."""
    with tempfile.TemporaryDirectory(prefix="framac-p0-selftest-") as tmp:
        root = Path(tmp)
        for name, text in _SELFTEST_FILES.items():
            (root / name).write_text(text, encoding="utf-8")
        module, why = compile_dump_module(root, runner=runner, dump_source=DUMP_SOURCE)
        if module is None:
            return {"ok": False, "status": "compile_failed", "reason": why[-2000:]}
        job = {
            "key": "selftest",
            "compiles": [{"source": n, "flags": [], "system_flags": []} for n in sorted(_SELFTEST_FILES)],
        }
        res = framac_parse(job, str(root), None, module, root / "logs", broker=False, runner=runner)
        if res["status"] != "ok":
            return {"ok": False, "status": res["status"], "reason": res.get("error", "")}
        builder = ModelBuilder(
            {"units": {"selftest": {"kind": "static_lib", "files": sorted(_SELFTEST_FILES), "links": []}}}, str(root)
        )
        builder.add_dump(["selftest"], res["dump"])
        builder.resolve()
    want_fns = {"a.c#helper", "b.c#helper", "a.c#twice", "a.c#apply", "a.c#run_a", "b.c#run_b", "a.c#fill"}
    edges = {(a, b, k) for (a, b, k) in builder.edges}
    want_edges = {
        ("a.c#run_a", "a.c#helper", "direct"),
        ("b.c#run_b", "b.c#helper", "direct"),
        ("a.c#apply", "a.c#twice", "indirect"),
    }
    loops = builder.functions.get("b.c#run_b", {}).get("loops")
    problems = []
    if set(builder.functions) != want_fns:
        problems.append(f"functions {sorted(builder.functions)}")
    if not want_edges <= edges:
        problems.append(f"edges missing {sorted(want_edges - edges)}")
    if loops != 1:
        problems.append(f"run_b loops {loops}")
    writes = builder.functions.get("a.c#fill", {}).get("writes") or {}
    if writes.get("params") != ["p"] or writes.get("globals") != ["counter"] or not writes.get("pointer"):
        problems.append(f"fill writes {writes}")
    if "a.c#counter" not in builder.global_vars:
        problems.append(f"globals {sorted(builder.global_vars)}")
    return {"ok": not problems, "status": "ok" if not problems else "unexpected_dump", "reason": "; ".join(problems)}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Phase 0 model: inventory and call graph from Frama-C parses")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="Build workspace/reports/phase0_model.json from the build capture")
    r.add_argument("--capture", type=Path, default=Path(DEFAULT_CAPTURE))
    r.add_argument("--out", type=Path, default=Path(DEFAULT_OUT))
    r.add_argument("--jobs", type=int, default=None, help="Parallel parses (default: this container's CPUs)")
    r.add_argument("--no-broker", action="store_true", help="Run Frama-C without a parse lease (tests, debugging)")
    r.add_argument(
        "--alias",
        action=argparse.BooleanOptionalAction,
        default=ALIAS_DEFAULT,
        help="Narrow indirect sites' type match with Frama-C's Alias plugin (default: %(default)s)",
    )
    r.add_argument("--threat-model", type=Path, default=None, help="THREAT_MODEL.md (default: trust.py's search order)")
    sub.add_parser("selftest", help="Check the dump module against this kernel")
    a = p.parse_args(argv)
    if a.cmd == "selftest":
        res = selftest()
        print(json.dumps(res, indent=2))
        return 0 if res["ok"] else 1
    model, rc = build_model(a.capture, a.out, a.jobs, broker=not a.no_broker, alias=a.alias)
    if model.get("status") == "ok":
        annotate_trust(model, a.threat_model)
    problems = validate_model(model)
    if problems:
        model["warnings"].append(f"schema: {problems[:5]}")
    atomic_write_json(a.out, model)
    summary = {
        "status": model["status"],
        "error": model.get("error"),
        "units": {n: u["parse"]["status"] for n, u in (model.get("units") or {}).items()},
        "functions": len(model.get("functions") or {}),
        "edges": len(model.get("edges") or []),
        "macro_aliases": len(model.get("macro_aliases") or {}),
        "alias": {k: v for k, v in (model.get("alias") or {}).items() if k in ("enabled", "module", "sites")},
        "seconds": model.get("seconds"),
        "warnings": model["warnings"][:10],
    }
    print(json.dumps(summary, indent=1))
    return rc


if __name__ == "__main__":
    sys.exit(main())
