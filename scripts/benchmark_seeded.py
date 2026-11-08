#!/usr/bin/env python3
"""
The benchmark's `phase0` set: the seeded-bug projects of poc/phase0/seeded/ (step I5b). Each project is a
small library with one verified bug that Phases 1-2 find only when Phase 0 reports the right sources,
flags and entry points, and decoys that a wrong Phase 0 turns into false positives (see that
directory's README and each project's truth.json). Acceptance: 7/7 bugs found, 0 decoys fired.

    benchmark_seeded.py run [--project sNN_name ...] [--fuzz-budget 30] [--work-dir DIR] [--run-id ID]
                            [--corpus DIR] [--dry-run]
    benchmark_seeded.py score RESULTS.json [--work-dir DIR] [--corpus DIR]   # re-score existing run dirs
    benchmark_seeded.py inner --repo NAME [--fuzz-budget 30]                 # container side, from `run`

Host side (`run`), per project, every stage through the real wrapper (scripts/benchmark.py `run_stage`):

  1. the project, without `repro/` and `truth.json`, is copied to <work-dir>/runs/<run-id>/<project>/target
     (the read-only mount); the run directory is <work-dir>/runs/<run-id>/<project>/run-1;
  2. the build capture and the Phase 0 model (benchmark.run_capture: build_capture.py, phase0_model.py),
     with the project's `build` command from truth.json as the recipe;
  3. `inner` (below) in the analysis image;
  4. pipeline_make.py build-check, run fuzz, run eva, run ingest, as `benchmark.py run` does.

Container side (`inner`): Phase 0 as `benchmark.py inner-phase0` runs it (run metadata, overlay, DAG from
the model, so its modules are link units, reach gate, ledger seed, validation, checkpoints, Make
generation), with the manifest's pinned harnesses replaced by the fixed mechanical harness policy below,
so only what Phase 0 reports decides what gets fuzzed and analysed.

Harness policy (deterministic; a function of the DAG and the overlay's sources only):

  - one harness module per DAG module (a link unit with the model, a lexer module without it), named as
    the module: a `dispatch` harness with one case per callable entry point (the module's
    `candidate_entry_points`, minus `main` and static functions), at most MAX_CASES cases;
  - a link unit the DAG split (step I8, scripts/unit_split.py) gets one sub-module per cluster (named as
    the cluster, `--unit` the unit), each with the callable entry points the cluster is anchored on;
  - otherwise, when a link unit has more than MAX_CASES callable entry points, it is split into
    sub-modules, one per lexer module holding some of them (named as that lexer module, `--unit` the
    unit), each with its own entry points (still at most MAX_CASES; the rest are recorded as excluded);
  - every harness compiles the unit's `required_sources` (C files only, minus the files defining `main`)
    with the unit's DAG `cppflags` (paths moved under workspace/work/);
  - each case's arguments come from the function's prototype (its declaring header in the overlay, else
    its sources): leading scalars from the first input bytes, then `(const T *, len)` input pairs,
    NUL-terminated `const char *` strings, `(T *, cap)` output buffers, or a zeroed output struct; any
    other parameter makes the entry point unsupported;
  - every entry point the policy does not call is exempted at the reachability gate with the policy's
    reason (in its harness sidecar, or the whole module when it got no harness), so the gate only fails
    on a harness that does not reach what it calls.

Scoring (per project, from workspace/reports/{fuzz,eva}): each bug is found by fuzzing (a fuzz artifact
in its file and function), found by Eva (an Invalid alarm there), flagged by Eva (an Unknown obligation at
its line) or missed; each decoy fired (a fuzz artifact or Eva Invalid at it) or not. A bug and a decoy
in the same function (two #if bodies) are told apart by line. Kernel-renamed statics (`at_1`) count as
their source name.

Results: <work-dir>/results/<run-id>.{json,md} (work dir: --work-dir, else FRAMAC_BENCH_DIR, else
~/framac-pipeline/benchmark, as benchmark.py). Run directories are recorded relative to the work dir.
Exit status of `run`: 0 when every bug is found and no decoy fired, 1 otherwise, 2 on a usage error.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import benchmark  # noqa: E402

SCRIPTS_DIR = Path(__file__).resolve().parent
CORPUS = benchmark.PIPELINE_ROOT / "poc" / "phase0" / "seeded"
CONTAINER_SELF = f"{benchmark.CONTAINER_SCRIPTS}/benchmark_seeded.py"
PM = f"python3 {benchmark.CONTAINER_SCRIPTS}/pipeline_make.py"
DEFAULT_FUZZ_BUDGET = 30
MAX_CASES = 64
PROFILE = "standard"
TARGET_EXCLUDES = ("repro", "truth.json")  # the reproducers and the answers stay out of the target

DAG = Path("workspace/reports/callgraph_dag.json")
HARNESS_DIR = Path("workspace/harnesses")
WORK = "workspace/work"
_PATH_OPTS = ("-iquote", "-isystem", "-idirafter", "-include", "-imacros", "-I")
_SCALAR_RE = re.compile(
    r"^(?:const\s+)?(?:(?:unsigned|signed)(?:\s+(?:int|long|short|char))?|int|long|short|char|size_t|ssize_t"
    r"|u?int(?:8|16|32|64)_t)$"
)
_LEN_RE = re.compile(r"\b(size_t|unsigned|int|long|u?int(?:16|32|64)_t)\b")
_RENAMED_RE = re.compile(r"(.+)_\d+")

# Host-side stages after Phase 0, as `benchmark.py run` runs them (no replay, gate or queue: the seeded
# set has no manifest reproducers and stops at Phase 2).
POST_STAGES = (
    ("build", f"{PM} build-check"),
    ("fuzz", f"{PM} run fuzz"),
    ("eva", f"{PM} run eva"),
    ("ingest", f"{PM} run ingest"),
)


# ---------------------------------------------------------------------------
# Harness policy (pure parts)
# ---------------------------------------------------------------------------


def harness_cppflags(flags: list[str] | str) -> str:
    """DAG cppflags (paths relative to the target root, `-I dir` or `-Idir`) as harness flags on the overlay."""
    if isinstance(flags, str):
        toks = shlex.split(flags)
    else:  # argv tokens already; only a `-I dir` written as one item is split
        toks = []
        for f in flags:
            head, _, rest = str(f).strip().partition(" ")
            toks += [head, rest.strip()] if head in _PATH_OPTS and rest.strip() else [str(f).strip()]
    out: list[str] = []
    i = 0
    while i < len(toks):
        tok = toks[i]
        opt = next((o for o in _PATH_OPTS if tok == o or (o == "-I" and tok.startswith("-I"))), None)
        if opt is not None:
            if tok == opt:
                if i + 1 >= len(toks):
                    break  # a dangling path option: drop it rather than swallow the next argument
                val = toks[i + 1]
                i += 1
            else:
                val = tok[len(opt) :]
            already = val.startswith("/") or val == WORK or val.startswith(f"{WORK}/")
            path = val if already else f"{WORK}/{val.removeprefix('./')}".rstrip("/")
            item = shlex.quote(f"-I{path}") if opt == "-I" else f"{opt} {shlex.quote(path)}"
        else:
            item = shlex.quote(tok)
        if item not in out:
            out.append(item)
        i += 1
    return " ".join(out) or "-I."


def _fn_name(key: str, rec: dict) -> str:
    return str(rec.get("name") or key.rsplit("#", 1)[-1])


def module_sources(dag: dict, rec: dict) -> list[str]:
    """The overlay C sources a module's harness compiles: its required sources minus files defining `main`."""
    fns = dag.get("functions") or {}
    main_files = {str(f.get("file")) for k, f in fns.items() if _fn_name(k, f) == "main"}
    return [
        f"{WORK}/{s}"
        for s in rec.get("required_sources") or rec.get("files") or []
        if str(s).endswith(".c") and s not in main_files
    ]


def plan_harnesses(dag: dict, max_cases: int = MAX_CASES) -> dict[str, dict]:
    """
    The policy's harness modules, before prototypes are read: harness module -> {unit, submodule, entries
    (DAG keys, in DAG order), excluded {key: reason}, sources, cppflags, run flags}. Deterministic.
    """
    fns: dict[str, dict] = dag.get("functions") or {}
    modules: dict[str, dict] = dag.get("modules") or {}
    link_units = dag.get("module_kind") == "link_unit"
    plans: dict[str, dict] = {}
    for unit, rec in sorted(modules.items()):
        callable_keys: list[str] = []
        excluded: dict[str, str] = {}
        for key in dict.fromkeys(rec.get("candidate_entry_points") or []):
            f = fns.get(key) or {}
            if _fn_name(key, f) == "main":
                excluded[key] = "main: the harness has its own entry"
            elif f.get("is_static"):
                excluded[key] = "static: not callable from the harness"
            else:
                callable_keys.append(key)
        groups: dict[str, list[str]] = {unit: callable_keys}
        clusters = {
            n: c
            for n, c in (dag.get("submodules") or {}).items()
            if isinstance(c, dict) and c.get("unit") == unit and link_units
        }
        by_cluster = {n: [k for k in c.get("anchors") or [] if k in callable_keys] for n, c in clusters.items()}
        if any(by_cluster.values()):
            groups = {n: keys for n, keys in by_cluster.items() if keys}
        elif link_units and len(callable_keys) > max_cases:
            groups = {}
            for key in callable_keys:
                lexer = str((fns.get(key) or {}).get("lexer_module") or "")
                # A lexer module named as a DAG module would collide with it: such entries stay with the unit.
                owner = lexer if lexer and lexer not in modules else unit
                groups.setdefault(owner, []).append(key)
        base = {
            "unit": unit,
            "sources": module_sources(dag, rec),
            "cppflags": harness_cppflags(rec.get("cppflags") or []),
            "run_flags": {k: bool(rec.get(k)) for k in ("run_eva", "run_eacsl_fuzz")},
        }
        for module, keys in sorted(groups.items()):
            own_excluded = dict(excluded) if module == unit else {}
            for key in keys[max_cases:]:
                own_excluded[key] = f"beyond the policy's {max_cases}-case limit"
            cluster_rec = clusters.get(module)
            plans[module] = {
                **base,
                **(
                    {"run_flags": {k: bool(cluster_rec.get(k)) for k in ("run_eva", "run_eacsl_fuzz")}}
                    if cluster_rec
                    else {}
                ),
                "submodule": module != unit,
                "entries": keys[:max_cases],
                "excluded": own_excluded,
            }
        if unit not in groups and excluded:
            # Split unit: main/static exclusions are recorded on the unit (its first sub-module's sidecar).
            plans[sorted(groups)[0]]["excluded"].update(excluded)
    return plans


def synthesize_case(fn: str, params: list[dict]) -> str | None:
    """One dispatch-case statement calling `fn` on the fuzz input, or None for an unsupported signature."""
    params = [p for p in params if " ".join(str(p.get("type") or "").split()) not in ("", "void")]
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
            v = f"r{i}"  # an output struct: a zeroed local, passed by address
            stmts.append(f"{typ.replace('*', '').strip()} {v}; memset(&{v}, 0, sizeof {v});")
            args.append(f"&{v}")
        else:
            return None
        i += 1
    return " ".join(stmts + [f"(void){fn}({', '.join(args)});"])


def declaring_headers(names: list[str], root: Path = Path(WORK)) -> dict[str, str]:
    """name -> the first header (sorted path order) under `root` declaring a prototype of it."""
    found: dict[str, str] = {}
    for h in sorted(root.rglob("*.h")):
        try:
            text = h.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for n in names:
            if n not in found and re.search(rf"\b{re.escape(n)}\s*\([^;{{]*\)\s*;", text):
                found[n] = h.as_posix()
    return found


def build_cases(
    plan: dict, fns: dict[str, dict], header_root: Path = Path(WORK)
) -> tuple[list[tuple[str, str, str]], dict[str, str], dict[str, str]]:
    """(cases as (key, name, statement), newly excluded {key: reason}, headers {name: path}) of one plan."""
    import generate_harness

    names = {key: _fn_name(key, fns.get(key) or {}) for key in plan["entries"]}
    headers = declaring_headers(sorted(set(names.values())), header_root)
    cases: list[tuple[str, str, str]] = []
    excluded: dict[str, str] = {}
    for key, name in names.items():
        try:
            params = generate_harness.extract_function_prototype(
                name, headers.get(name), plan["sources"], plan["cppflags"]
            )
        except ValueError as exc:
            excluded[key] = f"no prototype: {exc}"[:200]
            continue
        case = synthesize_case(name, params)
        if case is None:
            excluded[key] = "unsupported signature"
        else:
            cases.append((key, name, case))
    return cases, excluded, headers


def generate_argv(module: str, plan: dict, cases: list[tuple[str, str, str]], headers: dict[str, str]) -> list[str]:
    """generate_harness.py arguments of one planned harness (flag values with `=`, as benchmark.py does)."""
    hdrs = sorted({headers[n] for _, n, _ in cases if n in headers})
    argv = [
        sys.executable,
        str(SCRIPTS_DIR / "generate_harness.py"),
        "--module",
        module,
        "--sources",
        *plan["sources"],
        "--header",
        hdrs[0] if hdrs else "none",
        "--entry-fn",
        cases[0][1],
        "--entry-style",
        "dispatch",
        f"--cppflags={plan['cppflags']}",
        "--max-size",
        "1500",
        "--out-dir",
        str(HARNESS_DIR),
        "--no-auto-prelude",
    ]
    if plan.get("submodule"):
        argv.append(f"--unit={plan['unit']}")
    for h in hdrs[1:]:
        argv += ["--extra-include", h]
    argv += [f"--dispatch-case={c}" for _, _, c in cases]
    return argv


# ---------------------------------------------------------------------------
# Container side
# ---------------------------------------------------------------------------


def apply_policy(dag: dict, step: Any) -> dict:
    """Generate the policy's harnesses and record its exemptions; the policy report per harness module."""
    import harness_reach

    fns: dict[str, dict] = dag.get("functions") or {}
    report: dict[str, dict] = {}
    for module, plan in plan_harnesses(dag).items():
        excluded = dict(plan["excluded"])
        info: dict[str, Any] = {
            "unit": plan["unit"],
            "submodule": plan["submodule"],
            "sources": plan["sources"],
            "cppflags": plan["cppflags"],
            "run_flags": plan["run_flags"],
        }
        cases: list[tuple[str, str, str]] = []
        if not plan["entries"]:
            reason = "no callable entry point"
        elif not plan["sources"]:
            reason = "no sources"
        else:
            cases, more, headers = build_cases(plan, fns)
            excluded.update(more)
            reason = "no supported entry point" if not cases else ""
            if cases and not step(f"harness:{module}", generate_argv(module, plan, cases, headers)):
                reason = "generate_harness.py failed"
        info["harness"] = not reason
        info["cases"] = [n for _, n, _ in cases] if not reason else []
        info["excluded"] = excluded
        if reason:
            info["reason"] = reason
            harness_reach.record_exempt(HARNESS_DIR, module, None, f"seeded harness policy: {reason}")
        else:
            for key, why in sorted(excluded.items()):
                harness_reach.record_exempt(HARNESS_DIR, module, key, f"seeded harness policy: {why}", DAG)
        report[module] = info
    return report


def inner(repo: str, fuzz_budget: int) -> int:
    """Phase 0 with the seeded harness policy, from the run directory in the container (bench/phase0.json)."""
    import pipeline_make  # the container step needs the Make layer; the host never does

    bench = Path(benchmark.BENCH_SUBDIR)
    steps: list[dict] = []
    result: dict[str, Any] = {"ok": False, "steps": steps}
    log_path = bench / "logs" / "phase0-steps.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    py = sys.executable

    def script(name: str) -> str:
        return str(SCRIPTS_DIR / name)

    with open(log_path, "w", encoding="utf-8", errors="replace") as log:

        def step(name: str, argv: list[str]) -> bool:
            started = time.monotonic()
            log.write(f"\n$ {' '.join(argv)}\n")
            log.flush()
            proc = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, check=False)
            steps.append({"name": name, "rc": proc.returncode, "wall_s": round(time.monotonic() - started, 2)})
            return proc.returncode == 0

        ok = step("run_metadata", [py, script("run_metadata.py"), "init", "--repo", repo, "--profile", PROFILE])
        ok = ok and step(
            "overlay", [py, script("workspace_overlay.py"), "init", "--target", "/target", "--overlay", "workspace"]
        )
        ok = ok and step(
            "dag",
            [
                py,
                script("build_callgraph_dag.py"),
                "--target",
                WORK,
                "--out",
                str(DAG),
                "--emit-compile-commands",
                "workspace/reports/compile_commands.json",
            ],
        )
        if ok:
            dag = benchmark.read_json(DAG, {}) or {}
            result["module_kind"] = dag.get("module_kind") or "lexer"
            result["dag_warnings"] = [w for w in dag.get("warnings") or [] if "model" in str(w).lower()]
            try:
                result["policy"] = apply_policy(dag, step)
            except (ValueError, RuntimeError, OSError) as exc:  # includes framac_common.ArtifactError
                steps.append({"name": "policy", "rc": 1, "error": str(exc)})
                ok = False
        if ok:
            for module, info in sorted((result.get("policy") or {}).items()):
                if not info.get("harness"):
                    continue
                try:
                    pipeline_make.params_set(Path("."), module, fuzz_budget=fuzz_budget)
                except (ValueError, RuntimeError) as exc:
                    steps.append({"name": f"params:{module}", "rc": 1, "error": str(exc)})
                    ok = False
            ok = step("reach_gate", [py, script("harness_reach.py"), "check"]) and ok
        if ok:
            ok = (
                step("seed", [py, script("ledger.py"), "seed", "--dag", str(DAG), "--profile", PROFILE])
                and step("validate", [py, script("validate_artifacts.py"), "run-dir", "."])
                and step("checkpoint", [py, script("checkpoint.py"), "init", "state", "--target", "/target"])
                and step(
                    "checkpoint_phase0",
                    [py, script("checkpoint.py"), "save-phase", "state", "--phase", "0", "--from-file", str(DAG)],
                )
                and step("make_gen", [py, script("pipeline_make.py"), "gen"])
            )
    result["ok"] = bool(ok)
    benchmark.write_json(bench / "phase0.json", result)
    harnessed = sorted(m for m, i in (result.get("policy") or {}).items() if i.get("harness"))
    print(json.dumps({"ok": result["ok"], "module_kind": result.get("module_kind"), "harnessed": harnessed}))
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def _rel(path: str) -> str:
    path = benchmark.normalize_file(path or "")
    for prefix in ("workspace/work/", "/target/"):
        path = path.removeprefix(prefix)
    return path


def _join(row: dict) -> str:
    """An Eva row's file with its directory, as the report splits them."""
    directory, name = str(row.get("directory") or ""), str(row.get("file") or "")
    return f"{directory}/{name}" if directory and directory != "." else name


def _same_file(file_a: str, file_b: str) -> bool:
    a, b = _rel(file_a), _rel(file_b)
    return bool(a) and (a == b or a.endswith("/" + b) or b.endswith("/" + a))


def _same_function(reported: str, wanted: str) -> bool:
    """A reported function is the wanted one, or Frama-C's rename of a static (`at_1`)."""
    if reported == wanted:
        return True
    m = _RENAMED_RE.fullmatch(reported or "")
    return bool(m and m.group(1) == wanted)


def collect_findings(run_dir: Path) -> dict[str, Any]:
    """Fuzz artifacts, Eva Invalid alarms and Eva Unknown obligations of a run directory, with locations."""
    reports = run_dir / "workspace" / "reports"
    fuzz_hits: list[dict] = []
    fuzz_status: dict[str, str] = {}
    for f in sorted((reports / "fuzz").glob("*.json")):
        rep = benchmark.read_json(f, {}) or {}
        fuzz_status[f.stem] = rep.get("status", "?")
        for art in rep.get("artifacts") or []:
            fail = art.get("failure") or {}
            file_fn = str(art.get("fingerprint") or "").split("::", 1)[0]
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
            if isinstance(row, dict):
                eva_invalid.append({**row, "file": _join(row)})
        for fn, rows in (rep.get("unknown_obligations_by_function") or {}).items():
            for row in rows or []:
                if isinstance(row, dict):
                    eva_unknown.append({"function": fn, **row, "file": _join(row)})
    return {
        "fuzz_hits": fuzz_hits,
        "fuzz_status": fuzz_status,
        "eva_invalid": eva_invalid,
        "eva_unknown": eva_unknown,
        "eva_status": eva_status,
    }


def _hit(rows: list[dict], file: str, function: str, line: int | None = None) -> bool:
    return any(
        _same_function(str(r.get("function") or ""), function)
        and _same_file(str(r.get("file") or ""), file)
        and (line is None or str(r.get("line") or "") == str(line))
        for r in rows
    )


def score_findings(found: dict[str, Any], truth: dict) -> dict[str, Any]:
    """Each bug found (fuzz, Eva Invalid), flagged (Eva Unknown at its line) or missed; each decoy fired or not."""
    fuzz_hits, eva_invalid, eva_unknown = found["fuzz_hits"], found["eva_invalid"], found["eva_unknown"]
    bugs_truth = truth.get("bugs") or []
    decoys_truth = truth.get("decoys") or []
    items = bugs_truth + decoys_truth
    # A bug and a decoy in the same function (two #if bodies of one function) are told apart by line.
    pairs = [(i["file"], i["function"]) for i in items]
    shared = {p for p in pairs if pairs.count(p) > 1}

    def at(item: dict) -> int | None:
        return item.get("line") if (item["file"], item["function"]) in shared else None

    bugs: dict[str, dict] = {}
    for b in bugs_truth:
        by_fuzz = _hit(fuzz_hits, b["file"], b["function"], at(b))
        by_eva = _hit(eva_invalid, b["file"], b["function"], at(b))
        flagged = _hit(eva_unknown, b["file"], b["function"], b.get("line"))
        bugs[b["id"]] = {
            "mechanism": b.get("mechanism"),
            "function": f"{b['file']}#{b['function']}",
            "fuzz": by_fuzz,
            "eva_invalid": by_eva,
            "eva_unknown_at_line": flagged,
            "found": by_fuzz or by_eva,
            "outcome": "fuzz" if by_fuzz else "eva_invalid" if by_eva else "eva_unknown" if flagged else "missed",
        }
    decoys: dict[str, dict] = {}
    for d in decoys_truth:
        decoys[d["id"]] = {
            "kind": d.get("kind"),
            "function": f"{d['file']}#{d['function']}",
            "fired": _hit(fuzz_hits, d["file"], d["function"], at(d))
            or _hit(eva_invalid, d["file"], d["function"], at(d)),
        }
    other = sorted(
        {
            f"{_rel(str(r.get('file')))}#{r.get('function')}"
            for r in fuzz_hits + eva_invalid
            if not any(
                _same_function(str(r.get("function") or ""), fn) and _same_file(str(r.get("file") or ""), fl)
                for fl, fn in pairs
            )
        }
    )
    return {
        "bugs": bugs,
        "decoys": decoys,
        "other_findings": other,
        "fuzz_status": found["fuzz_status"],
        "eva_status": found["eva_status"],
    }


def score(run_dir: Path, truth: dict) -> dict[str, Any]:
    """A project's score from its run directory: the findings, plus what Phase 0 and the policy did."""
    out = score_findings(collect_findings(run_dir), truth)
    phase0 = benchmark.read_json(run_dir / benchmark.BENCH_SUBDIR / "phase0.json", {}) or {}
    policy: dict[str, dict] = phase0.get("policy") or {}
    out.update(
        phase0_ok=phase0.get("ok"),
        module_kind=phase0.get("module_kind"),
        harnesses={m: i.get("cases") for m, i in sorted(policy.items()) if i.get("harness")},
        not_harnessed={m: i.get("reason") for m, i in sorted(policy.items()) if not i.get("harness")},
        excluded={m: i.get("excluded") for m, i in sorted(policy.items()) if i.get("excluded")},
        builds={
            f.name.removesuffix(".build.json"): (benchmark.read_json(f, {}) or {}).get("status", "?")
            for f in sorted((run_dir / "workspace" / "build").glob("*.build.json"))
        },
    )
    return out


def totals(projects: dict[str, dict]) -> dict[str, Any]:
    """Bugs found, decoys fired and the acceptance verdict (every bug found, no decoy fired) over a run."""
    t = {"bugs": 0, "found": 0, "eva_unknown_only": 0, "decoys": 0, "decoys_fired": 0, "other_findings": 0}
    for p in projects.values():
        s = p.get("score") or {}
        bugs = list((s.get("bugs") or {}).values())
        decoys = list((s.get("decoys") or {}).values())
        t["bugs"] += max(len(p.get("truth_bugs") or []), len(bugs))
        t["found"] += sum(1 for b in bugs if b["found"])
        t["eva_unknown_only"] += sum(1 for b in bugs if not b["found"] and b["eva_unknown_at_line"])
        t["decoys"] += len(decoys)
        t["decoys_fired"] += sum(1 for d in decoys if d["fired"])
        t["other_findings"] += len(s.get("other_findings") or [])
    return {**t, "passed": t["bugs"] > 0 and t["found"] == t["bugs"] and t["decoys_fired"] == 0}


def render(doc: dict) -> str:
    projects: dict[str, dict] = doc.get("projects") or {}
    tot = doc.get("totals") or totals(projects)
    lines = [
        f"# Phase 0 seeded-bug set: {doc.get('run_id', '')}",
        "",
        f"Bugs found {tot['found']}/{tot['bugs']}, decoys fired {tot['decoys_fired']}/{tot['decoys']}: "
        f"**{'PASS' if tot['passed'] else 'FAIL'}** (acceptance: every bug found, no decoy fired). "
        f"Fuzz budget {doc.get('fuzz_budget')} CPU-s per harness.",
        "",
        "| Project | Mechanism | Phase 0 | Harness cases | Bugs found | Eva Unknown at bug line | Decoys fired | Other findings |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    for name, p in projects.items():
        s = p.get("score") or {}
        if not s:
            lines.append(f"| `{name}` | {p.get('mechanism', '')} | {p.get('status', '?')} | | | | | |")
            continue
        bugs = s.get("bugs") or {}
        decoys = s.get("decoys") or {}
        cases = sum(len(c or []) for c in (s.get("harnesses") or {}).values())
        lines.append(
            f"| `{name}` | {p.get('mechanism', '')} | {s.get('module_kind') or '?'}"
            f"{'' if s.get('phase0_ok') else ' (failed)'} | {cases} | "
            f"{sum(1 for b in bugs.values() if b['found'])}/{len(bugs)} | "
            f"{sum(1 for b in bugs.values() if b['eva_unknown_at_line'])}/{len(bugs)} | "
            f"{sum(1 for d in decoys.values() if d['fired'])}/{len(decoys)} | {len(s.get('other_findings') or [])} |"
        )
    lines += [
        "",
        "## Per bug and decoy",
        "",
        "| Project | Item | Function | Outcome |",
        "| :--- | :--- | :--- | :--- |",
    ]
    for name, p in projects.items():
        s = p.get("score") or {}
        for bid, b in (s.get("bugs") or {}).items():
            lines.append(f"| `{name}` | {bid} ({b.get('mechanism')}) | `{b['function']}` | {b['outcome']} |")
        for did, d in (s.get("decoys") or {}).items():
            lines.append(
                f"| `{name}` | {did} (decoy, {d.get('kind')}) | `{d['function']}` | {'FIRED' if d['fired'] else 'quiet'} |"
            )
    lines += ["", "## Details", ""]
    for name, p in projects.items():
        s = p.get("score") or {}
        stages = ", ".join(f"{k} rc={v.get('rc')}" for k, v in (p.get("stages") or {}).items())
        lines.append(
            f"- `{name}`: stages {stages or p.get('error') or '-'}; harnesses {s.get('harnesses')}; "
            f"not harnessed {s.get('not_harnessed')}; builds {s.get('builds')}; fuzz {s.get('fuzz_status')}; "
            f"eva {s.get('eva_status')}; other {s.get('other_findings')}"
        )
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Host side
# ---------------------------------------------------------------------------


def projects_in(corpus: Path, only: list[str] | None = None) -> list[Path]:
    projects = [d for d in sorted(corpus.iterdir()) if (d / "truth.json").is_file()]
    if only:
        unknown = sorted(set(only) - {d.name for d in projects})
        if unknown:
            raise benchmark.BenchmarkError(f"unknown seeded project(s): {', '.join(unknown)}")
        projects = [d for d in projects if d.name in only]
    return projects


def project_spec(proj: Path, truth: dict, seeds: bool = True) -> dict:
    """
    bench/spec.json for one project: what build_capture.py reads (`--recipe-file`), no host path. The
    project's `test` command (truth.json) becomes the recipe's test command, from which seed_harvest.py
    records seeds (step I6), unless `seeds` is off.
    """
    test = truth.get("test") if seeds else None
    return {
        "id": proj.name,
        "repo": repo_name(proj),
        "profile": PROFILE,
        "scope": [],
        "modules": [],
        "assets": [],
        "compile_commands": None,
        "reach_exempt_modules": {},
        "build": {"command": truth.get("build") or "make", "test_command": test, "origin": "benchmark"},
        "replays": [],
    }


def repo_name(proj: Path) -> str:
    return proj.name.replace("_", "-")


def stage_plan(proj: Path, fuzz_budget: int) -> list[tuple[str, str, str | None]]:
    """(stage, container command, class) after the capture, in order."""
    return [
        ("phase0", f"python3 {CONTAINER_SELF} inner --repo {repo_name(proj)} --fuzz-budget {fuzz_budget}", "eva"),
        *((name, cmd, None) for name, cmd in POST_STAGES),
    ]


def run_project(proj: Path, work_dir: Path, run_id: str, fuzz_budget: int, seeds: bool = True) -> dict:
    truth = json.loads((proj / "truth.json").read_text(encoding="utf-8"))
    base = work_dir / "runs" / run_id / proj.name
    mount = (base / "target").resolve()
    run_dir = (base / benchmark.RUN_DIR_NAME).resolve()
    if run_dir.exists() or mount.exists():
        raise benchmark.BenchmarkError(f"{base} already exists: pass a new --run-id")
    shutil.copytree(proj, mount, ignore=shutil.ignore_patterns(*TARGET_EXCLUDES))
    (run_dir / benchmark.BENCH_SUBDIR).mkdir(parents=True)
    spec = project_spec(proj, truth, seeds)
    benchmark.write_json(run_dir / benchmark.BENCH_SUBDIR / "spec.json", spec)
    repo = spec["repo"]
    stages: dict[str, dict] = {}
    started = time.monotonic()
    benchmark._say(f"{proj.name}: {truth.get('mechanism')}")
    capture = benchmark.run_capture(spec, mount, run_dir, repo, "", stages)
    ok = capture.get("status") == "ok" and (capture.get("model") or {}).get("status") == "ok"
    if ok:
        for name, command, cls in stage_plan(proj, fuzz_budget):
            stages[name] = benchmark.run_stage(name, command, mount, run_dir, repo, cls=cls)
            if name == "phase0" and stages[name]["rc"] != 0:
                break
    return {
        "mechanism": truth.get("mechanism"),
        "truth_bugs": [b["id"] for b in truth.get("bugs") or []],
        "run_dir": run_dir.relative_to(work_dir.resolve()).as_posix(),
        "status": "ok" if ok and stages.get("phase0", {}).get("rc") == 0 else "failed",
        "build_capture": capture,
        "stages": stages,
        "wall_s": round(time.monotonic() - started, 1),
        "score": score(run_dir, truth),
    }


def dry_run(projects: list[Path], work_dir: Path, run_id: str, fuzz_budget: int) -> None:
    """Print what `run` would do, wrapper command lines included; starts no container and writes nothing."""
    print(f"run id {run_id}; results {work_dir / 'results' / (run_id + '.json')}")
    for proj in projects:
        truth = json.loads((proj / "truth.json").read_text(encoding="utf-8"))
        base = work_dir / "runs" / run_id / proj.name
        mount, run_dir, repo = base / "target", base / benchmark.RUN_DIR_NAME, repo_name(proj)
        print(
            f"\n== {proj.name} ({truth.get('mechanism')}): copy {proj} -> {mount} without {', '.join(TARGET_EXCLUDES)}"
        )
        print(f"  spec: {json.dumps(project_spec(proj, truth)['build'])}")
        print(f"  capture: python3 {benchmark.CONTAINER_SCRIPTS}/build_capture.py run --recipe-file bench/spec.json")
        print(f"  model:   python3 {benchmark.CONTAINER_SCRIPTS}/phase0_model.py run")
        for name, command, cls in stage_plan(proj, fuzz_budget):
            argv = benchmark.wrapper_argv(mount, run_dir, repo, cls=cls)
            print(f"  {name}: {command}\n    via {' '.join(argv)}")


def run_seeded(
    work_dir: Path,
    run_id: str | None = None,
    projects: list[str] | None = None,
    fuzz_budget: int = DEFAULT_FUZZ_BUDGET,
    corpus: Path = CORPUS,
    seeds: bool = True,
) -> dict:
    """Run the set; write and return the results document (<work-dir>/results/<run-id>.{json,md})."""
    work_dir = work_dir.resolve()
    run_id = run_id or datetime.now(timezone.utc).strftime("seeded-%Y%m%dT%H%M%SZ")
    selected = projects_in(corpus, projects)
    out = work_dir / "results" / f"{run_id}.json"
    doc: dict[str, Any] = {
        "kind": "phase0_seeded",
        "run_id": run_id,
        "started_at": benchmark.utc_now(),
        "pipeline": benchmark.pipeline_identity(),
        "fuzz_budget": fuzz_budget,
        "max_cases": MAX_CASES,
        "seeds": seeds,
        "projects": {},
    }
    for proj in selected:
        try:
            doc["projects"][proj.name] = run_project(proj, work_dir, run_id, fuzz_budget, seeds)
        except (benchmark.BenchmarkError, OSError, ValueError) as exc:  # one project failing keeps the others
            truth = json.loads((proj / "truth.json").read_text(encoding="utf-8"))
            doc["projects"][proj.name] = {
                "mechanism": truth.get("mechanism"),
                "truth_bugs": [b["id"] for b in truth.get("bugs") or []],
                "status": "error",
                "error": f"{type(exc).__name__}: {exc}",
            }
        doc["totals"] = totals(doc["projects"])
        benchmark.write_json(out, doc)
    doc["finished_at"] = benchmark.utc_now()
    doc["totals"] = totals(doc["projects"])
    benchmark.write_json(out, doc)
    out.with_suffix(".md").write_bytes(render(doc).encode("utf-8"))
    return doc


def rescore(results: Path, work_dir: Path, corpus: Path = CORPUS) -> dict:
    doc = json.loads(results.read_text(encoding="utf-8"))
    for name, p in (doc.get("projects") or {}).items():
        if not p.get("run_dir"):
            continue
        truth = json.loads((corpus / name / "truth.json").read_text(encoding="utf-8"))
        p["score"] = score(work_dir.resolve() / p["run_dir"], truth)
    doc["totals"] = totals(doc.get("projects") or {})
    benchmark.write_json(results, doc)
    results.with_suffix(".md").write_bytes(render(doc).encode("utf-8"))
    return doc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Phase 0 seeded-bug set of the pipeline benchmark")
    sub = parser.add_subparsers(dest="cmd", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--work-dir", type=Path, default=None, help="Default: FRAMAC_BENCH_DIR or ~/framac-pipeline/benchmark"
        )
        p.add_argument(
            "--corpus", type=Path, default=CORPUS, help=f"Default: {CORPUS.relative_to(benchmark.PIPELINE_ROOT)}"
        )

    p_run = sub.add_parser("run", help="Run the seeded projects through the pipeline and score them")
    common(p_run)
    p_run.add_argument("--project", action="append", default=[], help="Only this project (repeatable)")
    p_run.add_argument("--fuzz-budget", type=int, default=DEFAULT_FUZZ_BUDGET, help="CPU-seconds per fuzz campaign")
    p_run.add_argument("--run-id", default=None)
    p_run.add_argument("--no-seeds", action="store_true", help="Do not record seeds from the projects' tests")
    p_run.add_argument("--dry-run", action="store_true", help="Print the stages and wrapper commands; run nothing")
    p_score = sub.add_parser("score", help="Re-score an existing results file from its run directories")
    common(p_score)
    p_score.add_argument("results", type=Path)
    p_inner = sub.add_parser("inner", help="Container-side Phase 0 with the seeded harness policy (started by run)")
    p_inner.add_argument("--repo", required=True)
    p_inner.add_argument("--fuzz-budget", type=int, default=DEFAULT_FUZZ_BUDGET)

    args = parser.parse_args(argv)
    if args.cmd == "inner":
        return inner(args.repo, args.fuzz_budget)
    work_dir = args.work_dir or benchmark.default_work_dir()
    try:
        if args.cmd == "score":
            doc = rescore(args.results, work_dir, args.corpus)
            print(args.results.with_suffix(".md"))
        elif args.dry_run:
            run_id = args.run_id or datetime.now(timezone.utc).strftime("seeded-%Y%m%dT%H%M%SZ")
            dry_run(projects_in(args.corpus, args.project), work_dir.resolve(), run_id, args.fuzz_budget)
            return 0
        else:
            doc = run_seeded(work_dir, args.run_id, args.project, args.fuzz_budget, args.corpus, not args.no_seeds)
            print(f"Results: {work_dir.resolve() / 'results' / (doc['run_id'] + '.md')}")
    except (benchmark.BenchmarkError, OSError, ValueError) as exc:
        print(f"benchmark_seeded: {exc}", file=sys.stderr)
        return 2
    t = doc["totals"]
    print(f"bugs found {t['found']}/{t['bugs']}, decoys fired {t['decoys_fired']}/{t['decoys']}")
    return 0 if t["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
