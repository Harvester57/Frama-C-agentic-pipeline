#!/usr/bin/env python3
"""
Phase-3 scheduler: a deterministic ready queue for the WP agent swarm.

The parent orchestrator spawns only what this script hands out and reports each completion.
Dependencies, gates, merge micro-batches, contract negotiation and retries are bookkeeping done
here, never by an LLM.

Subcommands (run with the run directory as working directory; each prints one JSON object):
  init           [--reconcile]                  build the task graph, write workspace/reports/wp_queue.json
  next           [--slots auto|N] [--prepare] [--max-agents N]
                                                hand out the highest-priority ready tasks
  step           [--complete ID...] [--slots auto|N] [--prepare] [--max-agents N] [--force-merge] [--module M]
                                                atomically complete, eager merge, and dispatch next
  complete       --agent-id ID                  validate one agent result and dispatch it by role
  merge-pending  [--module M] [--force]         merge finished provers in micro-batches, run re-checks
  refresh        [--module M]                   re-sync after a harness repair or a module re-run
  requeue        --agent-id ID | --stale-minutes N
  status

Tasks: verify:<fingerprint>, repair:<module> (parent work), arch:<module> (one per harness header:
arch:<harness> for a unit's further headers), prove:<file>#<function>, breaker:<file>#<function>,
negotiate:<file>#<callee>, plus virtual gate:<module> nodes.

State lives in state/wp_schedule.json and is only read and written under the run-wide `ledger`
lock. Merges run outside that lock: they take the `merge` lock themselves, and the lock order is
always ledger -> merge. FRAMAC_SCHEDULER=waves restores wave-by-wave dispatch with barriers.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import fnmatch
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import acsl_ast  # noqa: E402
import checkpoint  # noqa: E402
import contract_negotiator  # noqa: E402
import ledger  # noqa: E402
import phase0_gates  # noqa: E402
import prover_candidates  # noqa: E402
import resources  # noqa: E402
import workspace_overlay  # noqa: E402
from framac_common import (  # noqa: E402
    PROVER_WALL_BUDGET_S,
    ArtifactError,
    RunLockTimeout,
    atomic_write_json,
    eva_alarm_in_file,
    load_agent_result_json,
    load_json_optional,
    load_json_strict,
    run_lock,
    utc_now,
)
from module_map import ModuleMap  # noqa: E402
from promote_artifact import promote_file  # noqa: E402
from validate_artifacts import validate_agent_result  # noqa: E402

SCHEDULE = Path("state/wp_schedule.json")
WP_QUEUE = Path("workspace/reports/wp_queue.json")
WP_BASELINE = Path("workspace/reports/wp_baseline.json")
DAG_PATH = Path("workspace/reports/callgraph_dag.json")
REQUESTS = Path("workspace/reports/strengthen_requests.json")
HARNESS_DIR = Path("workspace/harnesses")
EVA_DIR = Path("workspace/reports/eva")
REPLAY_DIR = Path("workspace/reports/replay")
SCRIPTS = "/opt/framac-pipeline/scripts"

SCHEMA_VERSION = 1
TERMINAL = frozenset({"done", "blocked", "skipped"})
LIVE = frozenset({"running", "merge_queued", "merging"})
AGENT_KINDS = frozenset({"verify", "arch", "prove", "breaker", "negotiate"})
PROVER_KINDS = frozenset({"prove", "negotiate"})
# Role passed to workspace_overlay.prepare_agent, and the role the returned result must carry.
ROLE_BY_KIND = {
    "verify": "verifier",
    "arch": "architect",
    "prove": "prover",
    "breaker": "breaker",
    "negotiate": "prover",
    "repair": "parent",
}
RESULT_ROLE = {
    "verify": "crash_verifier",
    "arch": "architect",
    "prove": "prover",
    "breaker": "breaker",
    "negotiate": "prover",
}
NO_TOUCH = ledger.NO_TOUCH

MAX_NEGOTIATIONS_PER_PAIR = 2  # negotiation rounds per (caller, callee) pair
# Dispatches of one callee's negotiation task: many callers can each ask for a stronger contract the callee cannot
# be proved to give, and every round costs an agent run for the same stall.
MAX_NEGOTIATION_ROUNDS_PER_CALLEE = 3
MAX_MERGE_ATTEMPTS = 2  # a prover whose merge fails twice is blocked
MAX_ANALYSIS_ERRORS = 2  # a WP analysis_error is retried once, then the units are blocked
MAX_INVALID_RESULTS = 2  # a malformed result is re-run once with a fresh agent
MAX_PREPARE_ERRORS = 3
MAX_INGEST_ERRORS = 2  # a verifier result refused by ingest-verifier is re-run once
MERGE_BATCH_TRIGGER = 4  # queued results of one module that fire a merge
MERGE_MAX_WAIT_S = 300.0  # the oldest queued result never waits longer than this
HISTORY_LIMIT = 400
REOPENABLE_SKIPS = frozenset({"candidate", "no_open_units"})
DEFAULT_WALL_BUDGET_S = PROVER_WALL_BUDGET_S


def _agent_wall_budget_s() -> int:
    env_wall = (os.environ.get("FRAMAC_PROVER_WALL_BUDGET_S") or "").strip()
    if env_wall.isdigit() and int(env_wall) > 0:
        return int(env_wall)
    meta = load_json_optional(Path("run-metadata.json"), {}) or {}
    profile = str(meta.get("profile") or "standard").strip().lower()
    return DEFAULT_WALL_BUDGET_S.get(profile, 900)


def _over_budget_tasks(state: dict, now: float | None = None) -> list[dict]:
    now_ts = DEPS.now() if now is None else now
    over: list[dict] = []
    for _, t in sorted(state["tasks"].items()):
        if t["state"] != "running" or t["kind"] not in AGENT_KINDS:
            continue
        assigned = float(t.get("assigned_ts") or now_ts)
        budget_s = int(t.get("wall_budget_s") or _agent_wall_budget_s())
        age_s = round(now_ts - assigned, 1)
        if age_s >= budget_s:
            over.append(
                {
                    "task": t["id"],
                    "kind": t["kind"],
                    "agent_id": t.get("agent_id"),
                    "age_s": age_s,
                    "wall_budget_s": budget_s,
                    "action": "FINALIZE NOW: inject 'FINALIZE NOW — write agents/<agent-id>/scratch/result.json immediately' or run wp_scheduler.py requeue --agent-id "
                    + str(t.get("agent_id") or ""),
                }
            )
    return over


_PLACEHOLDER_RE = re.compile(
    r"\{(agent_id|module_name|header_file|c_file|function_name|wave_index|scratch_module_sources|module_sources|"
    r"cppflags|scratch_cppflags|ldflags|security_properties_json|untrusted_entry_functions_json|coverage_ids_json|"
    r"unknown_obligations_json|reachability|max_retries|unproven_goals_json|candidate_fingerprint|candidate_short|"
    r"candidate_json|target_dir|run_dir)\}"
)
_SCRATCH_PREFIX_RE = re.compile(r"^(?:.*/)?agents/[A-Za-z0-9_-]+/scratch/(?:work|base)/")
_WORK_PREFIX_RE = re.compile(r"^(?:.*/)?workspace/(?:work|baseline)/")
_TOLERATED = (ledger.LedgerError, ArtifactError, KeyError, OSError, ValueError)


class SchedulerError(RuntimeError):
    """A scheduler command was used inconsistently (unknown agent id, bad arguments, foreign state file)."""


# ---------------------------------------------------------------------------
# Collaborators (replaced by fakes in tests)
# ---------------------------------------------------------------------------


def _save_shard(shard_id: str, report: Path) -> dict:
    """Phase-3 checkpoint shard; checkpoint.py prints its own JSON, which must not mix with ours."""
    sink = io.StringIO()
    try:
        with contextlib.redirect_stdout(sink):
            checkpoint.cmd_save_shard(Path("state"), 3, shard_id, report)
    except RuntimeError as exc:  # state/progress.json missing (checkpoint init never ran) or unreadable
        return {"saved": False, "shard": shard_id, "reason": str(exc)}
    return {"saved": True, "shard": shard_id}


def _default_recheck(run_dir: Path, agent_id: str, file: str, function: str, module: str | None) -> dict:
    """
    Re-run the parent WP check of one already-merged function on the current workspace/work/ tree
    (its callee contracts changed). Holds the `merge` lock so no merge splices files underneath it.
    """
    # A link unit's flags: the union over its harnesses' sidecars (workspace_overlay.merged_sidecar).
    mm = workspace_overlay.module_map_for(run_dir / "workspace")
    side = workspace_overlay.merged_sidecar(mm, module) if module else {}
    cppflags = side.get("cppflags") or "-I."
    report = run_dir / "agents" / agent_id / "scratch" / "parent_wp" / f"{function}.json"
    report.parent.mkdir(parents=True, exist_ok=True)
    extra_sources = None
    if module:
        params_file = run_dir / "workspace" / "build" / "params.json"
        if not params_file.is_file():
            params_file = run_dir / "build" / "params.json"
        if params_file.is_file():
            try:
                pdata = json.loads(params_file.read_text(encoding="utf-8"))
                extra_sources = workspace_overlay.module_param(pdata.get("modules", {}), mm, module, "wp_extra_sources")
            except Exception:
                pass
    with run_lock("merge", run_dir):
        ok, reason = workspace_overlay._run_parent_reverify(
            run_dir=run_dir,
            agent_id=agent_id,
            role="prover",
            overlay_dir=run_dir / "workspace",
            c_file=file,
            function=function,
            module=module,
            sources=None,
            cppflags=cppflags,
            wp_extra_sources=extra_sources,
        )
    return {"ok": ok, "reason": reason, "report": report.relative_to(run_dir).as_posix() if report.is_file() else None}


class Deps:
    """Everything the scheduler calls outside itself; tests replace attributes with fakes."""

    def __init__(self) -> None:
        self.prepare_agent: Callable[..., dict] = workspace_overlay.prepare_agent
        self.merge_agent_batch: Callable[..., dict] = workspace_overlay.merge_agent_batch
        self.merge_agent_overlay: Callable[..., dict] = workspace_overlay.merge_agent_overlay
        self.recheck_function: Callable[..., dict] = _default_recheck
        self.recommend: Callable[..., dict] = resources.recommend
        self.transition: Callable[..., dict] = ledger.cmd_transition
        self.transition_many: Callable[[list[dict]], list[dict]] = ledger.cmd_transition_many
        self.ingest_wp: Callable[..., dict] = ledger.cmd_ingest_wp
        self.audit_hypotheses: Callable[..., dict] = ledger.cmd_audit_hypotheses
        self.ingest_agent_hypothesis: Callable[..., dict] = ledger.cmd_ingest_agent_hypothesis
        self.record_boundary_assumptions: Callable[..., dict] = ledger.cmd_record_boundary_assumptions
        self.ingest_verifier: Callable[..., dict] = ledger.cmd_ingest_verifier
        self.resolve_request: Callable[..., dict] = contract_negotiator.cmd_resolve
        self.save_shard: Callable[[str, Path], dict] = _save_shard
        self.restore_best: Callable[[Path], dict | None] = prover_candidates.restore_best
        self.now: Callable[[], float] = time.time
        self.run_cmd: Callable[..., Any] = subprocess.run


DEPS = Deps()


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def norm_path(value: str | None) -> str:
    """Repository-relative, forward-slash form of a source path seen from any pipeline view."""
    text = (value or "").replace("\\", "/").strip()
    text = _SCRATCH_PREFIX_RE.sub("", text)
    text = _WORK_PREFIX_RE.sub("", text)
    for prefix in ("/framac-run/", "/target/"):
        if text.startswith(prefix):
            text = text[len(prefix) :]
    while text.startswith("./"):
        text = text[2:]
    return re.sub(r"/+", "/", text).strip("/")


def _short_hash(text: str, n: int = 6) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:n]


def _slugify(text: str, limit: int = 40) -> str:
    return re.sub(r"[^a-z0-9_]+", "_", (text or "").lower()).strip("_")[:limit] or "task"


def _fp_slug(fingerprint: str) -> str:
    """File name stem of a candidate's replay report: workspace/reports/replay/<slug>.json."""
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", fingerprint).strip("_")


def _try(errors: list, label: str, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """Run one bookkeeping step; a refusal is recorded instead of aborting the whole command."""
    try:
        return fn(*args, **kwargs)
    except _TOLERATED as exc:
        errors.append(f"{label}: {exc}")
        return None


def _load_report(path: Path | str | None) -> dict | None:
    if not path:
        return None
    try:
        data = load_json_optional(Path(path), None)
    except ArtifactError:
        return None
    return data if isinstance(data, dict) else None


def _deps(task: dict) -> list[str]:
    return list(task.get("deps") or []) + list(task.get("extra_deps") or [])


def _key(task: dict) -> str:
    return f"{task.get('file')}#{task.get('function')}"


def scheduler_mode() -> str:
    return "waves" if (os.environ.get("FRAMAC_SCHEDULER") or "").strip().lower() == "waves" else "ready_queue"


def _tarjan(nodes: Iterable[str], succ: dict[str, list[str]]) -> list[list[str]]:
    """
    Strongly connected components, iteratively (deep call chains must not hit the recursion
    limit). A component is emitted only after every component reachable from it.
    """
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    comps: list[list[str]] = []
    counter = 0
    for root in nodes:
        if root in index:
            continue
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack.add(root)
        work = [(root, iter(succ.get(root, ())))]
        while work:
            node, it = work[-1]
            descended = False
            for nxt in it:
                if nxt not in index:
                    index[nxt] = low[nxt] = counter
                    counter += 1
                    stack.append(nxt)
                    on_stack.add(nxt)
                    work.append((nxt, iter(succ.get(nxt, ()))))
                    descended = True
                    break
                if nxt in on_stack:
                    low[node] = min(low[node], index[nxt])
            if descended:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
            if low[node] == index[node]:
                comp = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    comp.append(member)
                    if member == node:
                        break
                comps.append(sorted(comp))
    return comps


# ---------------------------------------------------------------------------
# State file
# ---------------------------------------------------------------------------


def _empty_state() -> dict:
    now = utc_now()
    return {
        "schema_version": SCHEMA_VERSION,
        "created_at": now,
        "updated_at": now,
        "tasks": {},
        "agents": {},
        "rechecks": {},
        "negotiation_counts": {},
        "gates": {},
        "history": [],
    }


def load_schedule() -> dict:
    data = load_json_optional(SCHEDULE, None)
    if data is None:
        return _empty_state()
    if not isinstance(data, dict) or not isinstance(data.get("tasks"), dict):
        raise SchedulerError(f"{SCHEDULE} is not a scheduler state file")
    state = _empty_state()
    state.update(data)
    return state


def save_schedule(state: dict) -> None:
    state["updated_at"] = utc_now()
    atomic_write_json(SCHEDULE, state)


def _event(state: dict, event: str, task_id: str | None = None, **detail: Any) -> None:
    entry: dict[str, Any] = {"at": utc_now(), "event": event}
    if task_id:
        entry["task"] = task_id
    entry.update({k: v for k, v in detail.items() if v is not None})
    history = state.setdefault("history", [])
    history.append(entry)
    if len(history) > HISTORY_LIMIT:
        del history[: len(history) - HISTORY_LIMIT]


def _make_slug(state: dict, kind: str, text: str, tid: str) -> str:
    """Agent-id stem: readable, unique per kind (same-named statics get a short hash)."""
    base = _slugify(text)
    taken = {t.get("slug") for t in state["tasks"].values() if t["kind"] == kind}
    if base not in taken:
        return base
    slug = f"{base[:33]}_{_short_hash(tid)}"
    n = 2
    while slug in taken:
        slug = f"{base[:30]}_{_short_hash(tid)}_{n}"
        n += 1
    return slug


def _new_task(state: dict, tid: str, kind: str, slug_text: str, **fields: Any) -> dict:
    task: dict[str, Any] = {
        "id": tid,
        "kind": kind,
        "state": "pending",
        "outcome": None,
        "module": fields.pop("module", None) or "unknown",
        "deps": [],
        "extra_deps": [],
        "height": 0,
        "eva_unknowns": 0,
        "wave": 0,
        "scc": None,
        "dispatches": 0,
        "agent_id": None,
        "agents": [],
        "created_at": utc_now(),
        "assigned_at": None,
        "assigned_ts": None,
        "completed_at": None,
        "last_reason": None,
    }
    task.update(fields)
    task["slug"] = _make_slug(state, kind, slug_text, tid)
    state["tasks"][tid] = task
    _event(state, "created", tid)
    return task


def _finish(state: dict, task: dict, new_state: str, outcome: str, reason: str | None = None) -> None:
    task["state"] = new_state
    task["outcome"] = outcome
    task["completed_at"] = utc_now()
    if reason:
        task["last_reason"] = str(reason)[:500]
    _event(state, f"{new_state}:{outcome}", task["id"], agent_id=task.get("agent_id"))


def _reopen(state: dict, task: dict, reason: str) -> None:
    """Back to pending; the next dispatch gets a fresh agent id (<kind>-<slug>-<n>)."""
    task.update(
        state="pending",
        outcome=None,
        agent_id=None,
        assigned_at=None,
        assigned_ts=None,
        completed_at=None,
        last_reason=str(reason)[:500],
    )
    task["reopened"] = int(task.get("reopened") or 0) + 1
    task.pop("merge", None)
    _event(state, "reopened", task["id"], reason=str(reason)[:200])


def _assign_agent(state: dict, task: dict) -> str:
    base = f"{task['kind']}-{task['slug']}"
    n = int(task.get("dispatches") or 0) + 1
    while True:
        aid = base if n == 1 else f"{base}-{n}"
        # Never reuse an id (or the agents/<id>/ directory of an earlier run): its scratch/result.json
        # would be read as this agent's answer.
        if aid not in state["agents"] and not (Path("agents") / aid).exists():
            break
        n += 1
    now_iso = utc_now()
    now_ts = DEPS.now()
    task.update(
        dispatches=n,
        agent_id=aid,
        state="running",
        assigned_at=now_iso,
        assigned_ts=now_ts,
        dispatched_at=now_iso,
        wall_budget_s=_agent_wall_budget_s(),
    )
    task.pop("requeued_from", None)
    task.setdefault("agents", []).append(aid)
    state["agents"][aid] = task["id"]
    _event(state, "assigned", task["id"], agent_id=aid)
    return aid


def _assign_parent(state: dict, task: dict) -> None:
    task.update(state="running", agent_id="parent", assigned_at=utc_now(), assigned_ts=DEPS.now())
    task["dispatches"] = int(task.get("dispatches") or 0) + 1
    _event(state, "assigned", task["id"], agent_id="parent")


# ---------------------------------------------------------------------------
# Inputs: call graph, ledger, candidates, harness sidecars, Eva reports
# ---------------------------------------------------------------------------


class Ctx:
    """The read-only inputs of one scheduling decision, loaded once per command."""

    def __init__(self) -> None:
        dag = load_json_optional(DAG_PATH, {})
        self.dag: dict = dag if isinstance(dag, dict) else {}
        meta = load_json_optional(Path("run-metadata.json"), {}) or {}
        self.profile: str = (
            str(meta.get("profile") or "standard").strip().lower() if isinstance(meta, dict) else "standard"
        )
        self.units, self.candidates = ledger.load_state()
        self.modules: dict[str, dict] = {
            str(k): v for k, v in (self.dag.get("modules") or {}).items() if isinstance(v, dict)
        }
        self.sidecars = self._load_sidecars()
        # Link units (step I5b): a DAG module's harnesses may be sub-modules with their own sidecars.
        self.mm = ModuleMap(self.dag, self.sidecars)
        self.eva_unknowns, self._eva_items_by_fn = self._load_eva()

        # DAG function records, by (file, name) and by bare name. `functions` is keyed by the bare name,
        # or by `file#name` when several functions share the name (build_callgraph_dag): both key forms
        # land under the record's own file and name.
        self.dag_by_key: dict[tuple[str, str], dict] = {}
        self.dag_by_name: dict[str, list[dict]] = defaultdict(list)
        for key, rec in sorted((self.dag.get("functions") or {}).items()):
            if not isinstance(rec, dict):
                continue
            name = str(rec.get("name") or str(key).rsplit("#", 1)[-1])
            file = norm_path(rec.get("file") or (str(key).rsplit("#", 1)[0] if "#" in str(key) else ""))
            self.dag_by_key[(file, name)] = rec
            self.dag_by_name[name].append(rec)

        self.module_files: dict[str, set[str]] = defaultdict(set)
        self.file_module: dict[str, str] = {}
        self.unit_tier: dict[str, str] = {}
        self.units_by_fn: dict[tuple[str, str], list[dict]] = defaultdict(list)
        for mod, rec in sorted(self.modules.items()):
            for f in rec.get("files") or []:
                nf = norm_path(f)
                self.module_files[mod].add(nf)
                self.file_module.setdefault(nf, mod)
        for (file, _name), rec in sorted(self.dag_by_key.items()):
            raw_mod = rec.get("module")
            if raw_mod and file:
                self.module_files[str(raw_mod)].add(file)
                self.file_module.setdefault(file, str(raw_mod))
        for cid in sorted(self.units):
            u = self.units[cid]
            nf = norm_path(u["file"])
            self.units_by_fn[(nf, u["function"])].append(u)
            raw_mod = u.get("module")
            if raw_mod:
                mod_str = str(raw_mod)
                self.module_files[mod_str].add(nf)
                self.file_module.setdefault(nf, mod_str)
                if u.get("tier"):
                    self.unit_tier.setdefault(mod_str, str(u["tier"]))

        # Every definition of a name: {name: {file: module}}, from the ledger and the DAG. The DAG keeps
        # one record per definition (`file#name` keys when a name collides) and lists each colliding
        # name's files in `name_collisions`, which also places a definition no record or unit covers.
        self.defs: dict[str, dict[str, str]] = defaultdict(dict)
        for (file, fn), fn_units in sorted(self.units_by_fn.items()):
            self.defs[fn].setdefault(file, fn_units[0].get("module") or self.file_module.get(file, ""))
        for (file, name), rec in sorted(self.dag_by_key.items()):
            if file:
                self.defs[name].setdefault(file, str(rec.get("module") or self.file_module.get(file, "")))
        for col in self.dag.get("name_collisions") or []:
            if isinstance(col, dict) and col.get("function"):
                for f in col.get("files") or []:
                    nf = norm_path(f)
                    self.defs[str(col["function"])].setdefault(nf, self.file_module.get(nf, ""))

        # Files compiled by each module's fuzz/Eva slice (DAG required_sources, the sidecar's sources).
        all_modules = set(self.modules) | set(self.module_files) | set(self.sidecars)
        all_modules |= {str(c.get("module")) for c in self.candidates.values() if c.get("module")}
        self.slice_files: dict[str, set[str]] = {}
        for mod in sorted(all_modules):
            files = set(self.module_files.get(mod, set()))
            files |= {norm_path(f) for f in (self.modules.get(mod) or {}).get("required_sources") or []}
            # A unit's slice: the sources of every harness of the unit.
            for src in self.sidecar(mod).get("sources") or []:
                nf = norm_path(str(src))
                if nf and not nf.startswith("workspace/") and not Path(nf).name.startswith("harness_"):
                    files.add(nf)
            self.slice_files[mod] = files

    @staticmethod
    def _load_sidecars() -> dict[str, dict]:
        out: dict[str, dict] = {}
        if HARNESS_DIR.is_dir():
            for path in sorted(HARNESS_DIR.glob("harness_*.json")):
                try:
                    data = load_json_strict(path)
                except ArtifactError:
                    continue
                if isinstance(data, dict):
                    out[str(data.get("module") or path.stem[len("harness_") :])] = data
        return out

    @staticmethod
    def _load_eva() -> tuple[dict[str, int], dict[str, list[Any]]]:
        counts: dict[str, int] = {}
        items_by_fn: dict[str, list[Any]] = defaultdict(list)
        if EVA_DIR.is_dir():
            for path in sorted(EVA_DIR.glob("*.json")):
                try:
                    data = load_json_strict(path)
                except ArtifactError:
                    continue
                by_fn = data.get("unknown_obligations_by_function") if isinstance(data, dict) else None
                if isinstance(by_fn, dict):
                    for fn, items in by_fn.items():
                        n = len(items) if isinstance(items, list) else int(bool(items))
                        counts[fn] = max(counts.get(fn, 0), n)
                        items_by_fn[fn].append(items)
        return counts, dict(items_by_fn)

    def eva_unknown_count(self, file: str | None, fn: str) -> int:
        if not fn:
            return 0
        if not file:
            return self.eva_unknowns.get(fn, 0)
        slices = self._eva_items_by_fn.get(fn)
        if not slices:
            return self.eva_unknowns.get(fn, 0)
        best = 0
        for items in slices:
            if isinstance(items, list):
                n = sum(1 for a in items if not (isinstance(a, dict) and a.get("file")) or eva_alarm_in_file(a, file))
            else:
                n = int(bool(items))
            best = max(best, n)
        return best

    def tier(self, mod: str) -> str:
        return str((self.modules.get(mod) or {}).get("tier") or self.unit_tier.get(mod) or "")

    def inert(self, mod: str) -> bool:
        """
        Tier-3 modules, and modules with neither fuzz nor Eva, run no slice of their own: their gate
        work counts as done. A sub-module answers from its own record (its path module's or its
        split cluster's, scripts/module_map.py), else from its unit's.
        """
        if self.mm.is_submodule(mod):
            rec = self.mm.submodule_record(mod) or self.mm.unit_record(mod)
            tier = self.mm.tier_of(mod) or ""
        else:
            rec = self.modules.get(mod) or {}
            tier = self.tier(mod)
        if tier.startswith("Tier 3"):
            return True
        return rec.get("run_eacsl_fuzz") is False and rec.get("run_eva") is False

    def harness_modules(self, mod: str) -> list[str]:
        """The harness modules (sidecars) standing for `mod`: a unit's harnesses, or `mod` itself."""
        return workspace_overlay.harness_modules_of(self.mm, mod)

    def sidecar(self, mod: str) -> dict:
        """`mod`'s sidecar; for a link unit, its harnesses' merged (sources and flags: their union)."""
        return workspace_overlay.merged_sidecar(self.mm, mod)

    def harness_module(self, mod: str | None, file: str | None = None, fn: str | None = None) -> str | None:
        """The harness to build, repair or replay for `mod` (for a unit: the one answering for `fn`)."""
        return workspace_overlay.harness_module_for_function(self.mm, mod, file, fn)

    def headers(self, mod: str) -> list[tuple[str, str]]:
        """
        (harness module, header) for each distinct `header` among `mod`'s harness sidecars, in
        harness order: each one gets its own architect (defect 13). The DAG carries no header.
        """
        out: list[tuple[str, str]] = []
        seen: set[str] = set()
        for harness in self.harness_modules(mod):
            value = (self.sidecars.get(harness) or {}).get("header")
            if not value:
                continue
            header = norm_path(str(value))
            if header and header not in seen:
                seen.add(header)
                out.append((harness, header))
        return out

    def header(self, mod: str) -> str | None:
        """`mod`'s first header (see `headers`)."""
        found = self.headers(mod)
        return found[0][1] if found else None

    def harness_scope(self, harness: str) -> set[tuple[str, str]] | None:
        """(file, function) a sub-module harness answers for; None for a whole unit (module_map scope)."""
        cache: dict[str, set[tuple[str, str]] | None] = self.__dict__.setdefault("_harness_scopes", {})
        if harness not in cache:
            scope = workspace_overlay.scope_keys(self.mm, harness)
            cache[harness] = None if scope is None else {(norm_path(f), fn) for f, fn in scope}
        return cache[harness]

    def contributors(self, mod: str) -> list[str]:
        """Modules whose fuzz/Eva slice compiles one of `mod`'s files (their candidates gate `mod`)."""
        files = self.module_files.get(mod, set())
        # A unit's own harnesses (sub-modules) always contribute: their candidates are its functions'.
        out = {mod, *self.harness_modules(mod)}
        for other, slice_files in self.slice_files.items():
            if other != mod and not self.inert(other) and slice_files & files:
                out.add(other)
        return sorted(out)

    def callees(self, file: str, fn: str) -> list[str]:
        rec = self.dag_by_key.get((file, fn))
        if rec is None:
            # A function with no DAG record of its own (a ledger unit from an older DAG, or a path
            # spelled differently): over-approximate with the first record of that name.
            recs = self.dag_by_name.get(fn) or []
            rec = recs[0] if recs else {}
        return sorted({str(c) for c in rec.get("internal_callees") or [] if c})

    def _fn_dag_rec(self, file: str, fn: str) -> dict:
        rec = self.dag_by_key.get((file, fn))
        if rec is None:
            recs = self.dag_by_name.get(fn) or []
            rec = recs[0] if recs else {}
        return rec if isinstance(rec, dict) else {}

    def verifiability(self, file: str, fn: str) -> str:
        rec = self._fn_dag_rec(file, fn)
        if rec.get("verifiability"):
            return str(rec["verifiability"])
        for u in self.fn_units(file, fn):
            bk = u.get("bookkeeping") or {}
            if bk.get("verifiability"):
                return str(bk["verifiability"])
        return "core_provable"

    def wp_blockers(self, file: str, fn: str) -> list[str]:
        rec = self._fn_dag_rec(file, fn)
        if rec.get("wp_blockers"):
            return [str(b) for b in rec["wp_blockers"] if b]
        for u in self.fn_units(file, fn):
            bk = u.get("bookkeeping") or {}
            if bk.get("wp_blockers"):
                return [str(b) for b in bk["wp_blockers"] if b]
        return []

    def resolve(self, callee: str, caller_file: str) -> list[tuple[str, str, str]]:
        """(file, name, module) definitions a call may reach. A definition in the caller's own file wins
        (a static there shadows every other); an ambiguous name reaches every same-named function."""
        if "#" in callee:
            cfile, name = callee.rsplit("#", 1)
            cfile = norm_path(cfile)
            return [(cfile, name, (self.defs.get(name) or {}).get(cfile) or self.file_module.get(cfile, ""))]
        defs = self.defs.get(callee) or {}
        if caller_file in defs:
            return [(caller_file, callee, defs[caller_file])]
        return [(f, callee, m) for f, m in sorted(defs.items())]

    def fn_units(self, file: str, fn: str) -> list[dict]:
        return [u for u in self.units_by_fn.get((file, fn), []) if u["status"] not in NO_TOUCH]

    def key_module(self, key: str) -> str:
        file, name = key.rsplit("#", 1)
        return (self.defs.get(name) or {}).get(file) or self.file_module.get(file, "")

    def quick_entry_chain(self, planned: list[tuple[str, str]]) -> set[tuple[str, str]]:
        """
        Under `--profile quick`, WP restricts prove tasks to Tier 1A entry functions and their
        transitive callees (docs/v2-design.md Section 9). If no Tier 1A function exists in the
        run, all `planned` functions remain eligible so `quick` is never vacuous.
        """
        all_fns = set(self.units_by_fn) | set(self.dag_by_key)
        seeds: list[tuple[str, str]] = []
        for file, fn in sorted(all_fns):
            fn_units = self.fn_units(file, fn)
            mod = next((u["module"] for u in fn_units if u.get("module")), None) or self.file_module.get(file, "")
            tier = next((str(u["tier"]) for u in fn_units if u.get("tier")), "") or self.tier(str(mod))
            if tier.startswith("Tier 1A"):
                seeds.append((file, fn))
        if not seeds:
            return set(planned)
        reachable: set[tuple[str, str]] = set(seeds)
        queue = list(seeds)
        while queue:
            cur_file, cur_fn = queue.pop()
            for callee in self.callees(cur_file, cur_fn):
                for cfile, cname, _cmod in self.resolve(callee, cur_file):
                    pair = (cfile, cname)
                    if pair not in reachable:
                        reachable.add(pair)
                        queue.append(pair)
        return set(planned) & reachable


# ---------------------------------------------------------------------------
# Graph: synchronisation with the ledger, dependencies, recursion groups, priorities
# ---------------------------------------------------------------------------


def _open_units(task: dict, fn_units: list[dict]) -> list[dict]:
    """Units a dispatch would claim: planned ones, plus blocked ones this task worked on before."""
    mine = set(task.get("units") or [])
    return [u for u in fn_units if u["status"] == "planned" or (u["status"] == "blocked" and u["coverage_id"] in mine)]


def _skip_verdict(
    task: dict, fn_units: list[dict], open_verify: set[str], verifiability: str | None = None
) -> str | None:
    """
    Why a prove task must not run: a unit of its function is a candidate whose verification is over
    (never prove broken code), the function is statically classified as `shell_unverifiable_wp`,
    or nothing is left to prove. A candidate still being verified only keeps the task waiting
    behind its gate.
    """
    cand_units = [u for u in fn_units if u["status"] == "candidate"]
    if cand_units and not any(fp in open_verify for u in cand_units for fp in u.get("result_fingerprints") or []):
        return "candidate"
    verif = verifiability or task.get("verifiability")
    if verif == "shell_unverifiable_wp":
        return "shell_unverifiable_wp"
    if not _open_units(task, fn_units):
        return "no_open_units"
    return None


def _negotiate_skip_verdict(
    fn_units: list[dict], open_verify: set[str], verifiability: str | None = None
) -> str | None:
    """Why a negotiate task must not run: its callee has a confirmed/unverified candidate unit or is shell_unverifiable_wp."""
    cand_units = [u for u in fn_units if u["status"] == "candidate"]
    if cand_units:
        return "candidate"
    if verifiability == "shell_unverifiable_wp":
        return "shell_unverifiable_wp"
    return None


def _park_shell_unverifiable_units(task: dict, fn_units: list[dict], wp_blockers: list[str], errors: list) -> None:
    """
    Park planned units of a `shell_unverifiable_wp` function without dispatching a prover:
    - Harness entrypoints (`fuzz_or_eva_harness_entrypoint`) with no evidence become `not_applicable`
      (or `blocked` if they already carry fuzz/Eva evidence).
    - Other `shell_unverifiable_wp` functions become `blocked` (if they carry evidence) or `deferred`
      (if no evidence is recorded yet) with the `shell_unverifiable_wp` blocker reason.
    """
    is_harness_entry = "fuzz_or_eva_harness_entrypoint" in wp_blockers
    blocker_detail = ", ".join(wp_blockers) if wp_blockers else "unsupported C construct"
    reason = f"shell_unverifiable_wp ({blocker_detail}): skipped WP prover dispatch"
    specs: list[dict] = []
    for u in fn_units:
        if u["status"] != "planned":
            continue
        if u.get("evidence"):
            target_status = "blocked"
        elif is_harness_entry:
            target_status = "not_applicable"
        else:
            target_status = "deferred"
        specs.append(
            {
                "id": u["coverage_id"],
                "status": target_status,
                "agent_id": None,
                "reason": reason,
                "expected": ["planned"],
            }
        )
    if specs:
        _batch_or_individual_transitions(specs, errors=errors, tag="shell_unverifiable_wp")


QUICK_OFF_CHAIN_REASON = "quick_profile_wp_not_scheduled: outside the Tier 1A entry chain WP covers in quick"


def _park_quick_off_chain(ctx: Ctx, off_chain: list[tuple[str, str]], changes: dict) -> None:
    """
    Close the planned units of functions `quick` never gives a prover (docs/v2-design.md Section 9),
    so the run can reach `done` instead of `stuck`: units with earlier evidence become `blocked`,
    the others `deferred`, both with the reason, as `ledger.py close-remaining` does.
    """
    specs: list[dict] = []
    for file, fn in off_chain:
        for u in ctx.fn_units(file, fn):
            if u["status"] != "planned":
                continue
            specs.append(
                {
                    "id": u["coverage_id"],
                    "status": "blocked" if u.get("evidence") else "deferred",
                    "agent_id": None,
                    "reason": QUICK_OFF_CHAIN_REASON,
                    "expected": ["planned"],
                }
            )
    errors: list[str] = []
    done = set(_batch_or_individual_transitions(specs, errors=errors, tag="quick_off_chain"))
    for spec in specs:
        if spec["id"] in done and spec["id"] in ctx.units:
            ctx.units[spec["id"]]["status"] = spec["status"]
    if done:
        changes.setdefault("parked", []).extend(sorted(done))
    if errors:
        changes.setdefault("errors", []).extend(errors)


def _arch_task_id(tasks: dict, mod: str, harness: str, header: str) -> str:
    """`arch:<module>` for a module's first architect (the id before defect 13), then `arch:<harness>`."""
    for tid in (f"arch:{mod}", f"arch:{harness}"):
        if tid not in tasks:
            return tid
    return f"arch:{mod}#{_short_hash(header)}"


def _sync_architects(state: dict, ctx: Ctx, mod: str, changes: dict[str, list[str]]) -> None:
    """
    One architect per header of `mod`'s harness sidecars (a unit with two harnesses and two headers
    gets two). A pending architect whose header left the sidecars takes a new header, or is skipped.
    """
    tasks = state["tasks"]
    wanted = ctx.headers(mod)
    if not wanted:
        return
    mine = [tasks[tid] for tid in sorted(tasks) if tasks[tid]["kind"] == "arch" and tasks[tid]["module"] == mod]
    by_header = {t.get("header"): t for t in mine}
    missing = [(h, hdr) for h, hdr in wanted if hdr not in by_header]
    wanted_headers = {hdr for _, hdr in wanted}
    for task in mine:
        if task["state"] != "pending" or task.get("header") in wanted_headers:
            continue
        if missing:
            harness, header = missing.pop(0)
            task.update(header=header, harness_module=harness)
            by_header[header] = task
        else:
            _finish(
                state, task, "skipped", "header_gone", reason=f"no harness sidecar of {mod} names {task.get('header')}"
            )
            changes["skipped"].append(task["id"])
    for harness, header in wanted:
        task = by_header.get(header)
        if task is None:
            tid = _arch_task_id(tasks, mod, harness, header)
            _new_task(
                state,
                tid,
                "arch",
                tid[len("arch:") :],
                module=mod,
                header=header,
                harness_module=harness,
                invalid_results=0,
            )
            changes["created"].append(tid)
        elif task["state"] == "pending":
            task["harness_module"] = harness


def _sync(state: dict, ctx: Ctx) -> dict:
    """
    Bring the task set in line with the ledger and candidates (idempotent): a verify task per
    unverified candidate, a prove task per function with planned units, an architect per module
    with prove work and a header; then recompute dependencies, gates, recursion groups, waves and
    priorities.
    """
    tasks = state["tasks"]
    changes: dict[str, list[str]] = {"created": [], "reopened": [], "skipped": [], "closed": []}

    for fp, cand in sorted(ctx.candidates.items()):
        tid = f"verify:{fp}"
        task = tasks.get(tid)
        if cand.get("status") == "unverified":
            if task is None:
                loc = cand.get("location") or {}
                loc_file = norm_path(loc.get("file") or "")
                fn = str(loc.get("function") or fp.split("#", 1)[-1].split("::", 1)[0])
                _new_task(
                    state,
                    tid,
                    "verify",
                    f"{fn[:28]}_{fp.rsplit('::', 1)[-1]}",
                    module=cand.get("module") or ctx.file_module.get(loc_file) or "unknown",
                    fingerprint=fp,
                    location_file=loc_file,
                    location_function=fn,
                    ingest_errors=0,
                    invalid_results=0,
                )
                changes["created"].append(tid)
        elif task is not None and task["state"] == "pending":
            _finish(state, task, "done", "verified_elsewhere")
            changes["closed"].append(tid)
    open_verify = {t["fingerprint"] for t in tasks.values() if t["kind"] == "verify" and t["state"] not in TERMINAL}

    planned = sorted({(norm_path(u["file"]), u["function"]) for u in ctx.units.values() if u["status"] == "planned"})
    if ctx.profile == "quick":
        allowed_quick = ctx.quick_entry_chain(planned)
        _park_quick_off_chain(ctx, [pair for pair in planned if pair not in allowed_quick], changes)
        planned = [pair for pair in planned if pair in allowed_quick]
    for file, fn in planned:
        tid = f"prove:{file}#{fn}"
        task = tasks.get(tid)
        fn_units = ctx.fn_units(file, fn)
        planned_ids = [u["coverage_id"] for u in fn_units if u["status"] == "planned"]
        verifiability = ctx.verifiability(file, fn)
        wp_blockers = ctx.wp_blockers(file, fn)
        if task is None:
            module = next((u["module"] for u in fn_units if u.get("module")), None) or ctx.file_module.get(file)
            _new_task(
                state,
                tid,
                "prove",
                fn,
                module=module,
                file=file,
                function=fn,
                units=planned_ids,
                callees=[],
                verifiability=verifiability,
                wp_blockers=wp_blockers,
                merge_attempts=0,
                analysis_errors=0,
                invalid_results=0,
            )
            changes["created"].append(tid)
        elif task["state"] in TERMINAL:
            # A skip that no longer applies, or units this task never held becoming planned (a rejected
            # candidate, a unit added later): prove the function again. Units the task itself left
            # planned (no evidence to block them with) never reopen it.
            fresh = bool(set(planned_ids) - set(task.get("units") or [])) or any(
                bool(u.get("attempts") and u["attempts"][-1].get("phase") == "verifier")
                for u in fn_units
                if u["coverage_id"] in planned_ids
            )
            reopenable = task["state"] == "skipped" and task.get("outcome") in REOPENABLE_SKIPS
            merged_units = sorted(set(task.get("units") or []) | set(planned_ids))
            if (reopenable or fresh) and _skip_verdict(
                {**task, "units": merged_units, "verifiability": verifiability}, fn_units, open_verify, verifiability
            ) is None:
                task["units"] = merged_units
                task["verifiability"] = verifiability
                task["wp_blockers"] = wp_blockers
                _reopen(state, task, "units are planned again")
                changes["reopened"].append(tid)

    for tid in sorted(tasks):
        task = tasks[tid]
        if task["state"] != "pending":
            continue
        if task["kind"] == "prove":
            fn_units = ctx.fn_units(task["file"], task["function"])
            verifiability = ctx.verifiability(task["file"], task["function"])
            wp_blockers = ctx.wp_blockers(task["file"], task["function"])
            task["verifiability"] = verifiability
            task["wp_blockers"] = wp_blockers
            verdict = _skip_verdict(task, fn_units, open_verify, verifiability)
            if verdict:
                if verdict == "shell_unverifiable_wp":
                    _park_shell_unverifiable_units(task, fn_units, wp_blockers, [])
                    blocker_str = ", ".join(wp_blockers) if wp_blockers else "unsupported C construct"
                    _finish(
                        state,
                        task,
                        "skipped",
                        verdict,
                        reason=f"not dispatched: {verdict} ({blocker_str})",
                    )
                    eva_unk = ctx.eva_unknown_count(task.get("file"), task["function"])
                    if eva_unk > 0 and "fuzz_or_eva_harness_entrypoint" not in wp_blockers:
                        _ensure_breaker(
                            state,
                            task,
                            "scheduler",
                            None,
                            {"new_tasks": changes["created"], "errors": []},
                        )
                else:
                    _finish(state, task, "skipped", verdict, reason=f"not dispatched ({verdict})")
                changes["skipped"].append(tid)
        elif task["kind"] == "negotiate":
            fn_units = ctx.fn_units(task["file"], task["function"])
            verifiability = ctx.verifiability(task["file"], task["function"])
            neg_verdict = _negotiate_skip_verdict(fn_units, open_verify, verifiability)
            if neg_verdict:
                note = f"not dispatched: callee unit is {neg_verdict}"
                for rid in task.get("requests") or []:
                    _resolve_request([], str(rid), "rejected_by_callee", note)
                _finish(state, task, "skipped", neg_verdict, reason=note)
                changes["skipped"].append(tid)

    prove_modules = sorted({t["module"] for t in tasks.values() if t["kind"] == "prove" and t["state"] != "skipped"})
    for mod in prove_modules:
        _sync_architects(state, ctx, mod, changes)

    gate_modules = sorted({t["module"] for t in tasks.values() if t["kind"] in ("prove", "arch")})
    state["gates"] = {
        f"gate:{mod}": {
            "module": mod,
            "contributors": ctx.contributors(mod),
            "files": sorted(ctx.module_files.get(mod, set())),
            "harness_modules": ctx.harness_modules(mod),
        }
        for mod in gate_modules
    }
    _compute_deps(state, ctx)
    _compute_graph(state)
    return changes


# ---------------------------------------------------------------------------
# Contract-first speculative dispatch helpers & call-cone reachability
# ---------------------------------------------------------------------------

# Cache for file-level ACSL function contract checks:
# Key: (resolved_path_str, st_mtime, st_size, function_name, is_header) -> bool
_FILE_CONTRACT_CACHE: dict[tuple[str, float, int, str, bool], bool] = {}


def _file_has_contract(path: Path, fn_name: str, is_header: bool) -> bool:
    """Check if `path` contains an ACSL contract for `fn_name`, with mtime/size caching."""
    try:
        st = path.stat()
    except OSError:
        return False
    key = (str(path.resolve()), st.st_mtime, st.st_size, fn_name, is_header)
    if key in _FILE_CONTRACT_CACHE:
        return _FILE_CONTRACT_CACHE[key]
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    res = acsl_ast.has_function_contract(text, fn_name, is_header=is_header, path=str(path))
    _FILE_CONTRACT_CACHE[key] = res
    return res


def callee_has_contract(
    ctx: Ctx,
    cfile: str,
    cname: str,
    cmod: str | None,
    work_dir: Path | None = None,
) -> bool:
    """
    Check whether `cname` in `cfile` (module `cmod`) has an ACSL function contract in workspace/work/.
    Inspects:
    1. Sibling header: workspace/work/<stem>.h (both prototype and inline definition)
    2. Module header(s): workspace/work/<header> for each harness sidecar's `header` and `headers`
    3. C source definition / prototype: workspace/work/<cfile>
    """
    cfile_norm = norm_path(cfile)
    work_root = Path(work_dir) if work_dir is not None else Path("workspace/work")
    if not work_root.is_dir():
        return False

    # Check per-command Ctx cache
    cache: dict[tuple[str, str, str | None, str], bool] = getattr(ctx, "_callee_contract_cache", None)  # type: ignore[assignment]
    if cache is None:
        cache = ctx._callee_contract_cache = {}  # type: ignore[attr-defined]
    cache_key = (cfile_norm, cname, cmod, str(work_root.resolve()))
    if cache_key in cache:
        return cache[cache_key]

    # 1. Check sibling header (<stem>.h)
    c_p = Path(cfile_norm)
    if c_p.suffix.lower() in (".c", ".i"):
        sib_path = work_root / c_p.with_suffix(".h")
        if sib_path.is_file():
            if _file_has_contract(sib_path, cname, is_header=True) or _file_has_contract(
                sib_path, cname, is_header=False
            ):
                cache[cache_key] = True
                return True
    elif cfile_norm.endswith(".h"):
        h_path = work_root / cfile_norm
        if h_path.is_file():
            if _file_has_contract(h_path, cname, is_header=True) or _file_has_contract(h_path, cname, is_header=False):
                cache[cache_key] = True
                return True

    # 2. Check module header(s)
    mod = cmod or ctx.file_module.get(cfile_norm)
    if mod:
        # Every harness's header and the headers its sidecar lists (the DAG carries none).
        cand_headers: set[str] = {header for _, header in ctx.headers(mod)}
        for h in ctx.sidecar(mod).get("headers") or []:
            cand_headers.add(norm_path(str(h)))

        for h_rel in sorted(cand_headers):
            hdr_path = work_root / h_rel
            if hdr_path.is_file():
                if _file_has_contract(hdr_path, cname, is_header=True) or _file_has_contract(
                    hdr_path, cname, is_header=False
                ):
                    cache[cache_key] = True
                    return True

    # 3. Check C source definition or prototype
    src_path = work_root / cfile_norm
    if src_path.is_file():
        if _file_has_contract(src_path, cname, is_header=False) or _file_has_contract(src_path, cname, is_header=True):
            cache[cache_key] = True
            return True

    cache[cache_key] = False
    return False


def touches_module_header(
    ctx: Ctx,
    file: str,
    fn: str,
    module: str | None,
    work_dir: Path | None = None,
) -> bool:
    """Check whether `fn` has a prototype or declaration in one of the module's harness headers."""
    if not module:
        return False
    cand_headers = [header for _, header in ctx.headers(module)]
    if not cand_headers:
        return False

    root = Path(work_dir) if work_dir is not None else Path.cwd()
    for hdr_rel in cand_headers:
        hdr_path = root / "workspace" / "work" / hdr_rel
        if not hdr_path.is_file():
            hdr_path = root / hdr_rel
        if not hdr_path.is_file():
            # Conservative fallback if configured header file does not exist on disk
            return True
        try:
            hdr_text = hdr_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return True
        if not re.search(r"\b" + re.escape(fn) + r"\b", hdr_text):
            continue
        span = acsl_ast.locate_function_span(hdr_text, fn, is_header=True, path=hdr_rel)
        if span is not None:
            return True
    return False


def is_static_fn(ctx: Ctx, file: str, fn: str, work_dir: Path | None = None) -> bool:
    """Check whether `fn` in `file` is an internal static function."""
    rec = ctx.dag_by_key.get((norm_path(file), fn))
    if rec and rec.get("is_static"):
        return True
    root = Path(work_dir) if work_dir is not None else Path.cwd()
    c_path = root / "workspace" / "work" / file
    if not c_path.is_file():
        c_path = root / file
    if c_path.is_file():
        try:
            c_text = c_path.read_text(encoding="utf-8", errors="replace")
            span = acsl_ast.locate_function_span(c_text, fn, is_header=False, path=file)
            if span:
                brace_off = acsl_ast._find_body_brace_offset(span.text, path=file)
                decl_part = span.text[:brace_off] if brace_off is not None else span.text
                if re.search(r"\bstatic\b", decl_part):
                    return True
        except OSError:
            pass
    return False


def _call_cone(file: str, fn: str, ctx: Ctx | None = None) -> set[tuple[str, str]]:
    """
    Compute the reachable set of functions (file, fn) in the call graph DAG starting from (file, fn).
    Includes (file, fn) itself and all transitive callees.
    """
    start = (norm_path(file), fn)
    cone: set[tuple[str, str]] = {start}
    if ctx is None:
        return cone
    queue = [start]
    while queue:
        cur_file, cur_fn = queue.pop()
        for callee in ctx.callees(cur_file, cur_fn):
            for cfile, cname, _cmod in ctx.resolve(callee, cur_file):
                pair = (norm_path(cfile), cname)
                if pair not in cone:
                    cone.add(pair)
                    queue.append(pair)
    return cone


def _compute_deps(state: dict, ctx: Ctx) -> None:
    tasks = state["tasks"]
    prove_by_key = {_key(t): tid for tid, t in tasks.items() if t["kind"] == "prove"}
    # A module's architects: one per header of its harnesses (defect 13).
    arch_of: dict[str, list[str]] = defaultdict(list)
    for tid in sorted(tasks):
        if tasks[tid]["kind"] == "arch" and tasks[tid]["state"] != "skipped":
            arch_of[tasks[tid]["module"]].append(tid)
    for tid in sorted(tasks):
        task = tasks[tid]
        if task["kind"] == "prove":
            own = _key(task)
            deps: set[str] = {f"gate:{task['module']}"}

            callees: set[str] = set()
            for callee in ctx.callees(task["file"], task["function"]):
                for cfile, cname, cmod in ctx.resolve(callee, task["file"]):
                    key = f"{cfile}#{cname}"
                    if key == own:
                        continue  # self-recursion
                    callees.add(key)
                    # Speculative contract-first dispatch (Option A):
                    # If callee already has a contract in workspace/work/, caller does not wait
                    # for the callee's body proof or callee module architect.
                    has_contract = callee_has_contract(ctx, cfile, cname, cmod)
                    if not has_contract:
                        if key in prove_by_key:
                            deps.add(prove_by_key[key])
                        if cmod:
                            deps.update(arch_of.get(cmod, ()))

            # Omit the module's architects for leaf and static functions that do not touch a module header
            touches_hdr = touches_module_header(ctx, task["file"], task["function"], task.get("module"))
            is_leaf = len(callees) == 0
            is_static = is_static_fn(ctx, task["file"], task["function"])
            if not ((is_leaf or is_static) and not touches_hdr):
                deps.update(arch_of.get(task["module"], ()))

            task["deps"] = sorted(deps)
            task["callees"] = sorted(callees)
            task["eva_unknowns"] = ctx.eva_unknown_count(task.get("file"), task["function"])
            task["verifiability"] = ctx.verifiability(task["file"], task["function"])
            task["wp_blockers"] = ctx.wp_blockers(task["file"], task["function"])
        elif task["kind"] == "arch":
            task["deps"] = [f"gate:{task['module']}"]
        elif task["kind"] in ("breaker", "negotiate"):
            task["eva_unknowns"] = ctx.eva_unknown_count(task.get("file"), task.get("function") or "")
    # Architects of modules sharing a header run one after the other: the second merge would
    # otherwise see a concurrent edit of the header and be refused.
    by_header: dict[str, list[str]] = defaultdict(list)
    for tid in sorted(tasks):
        if tasks[tid]["kind"] == "arch" and tasks[tid].get("header"):
            by_header[tasks[tid]["header"]].append(tid)
    for ids in by_header.values():
        for i in range(1, len(ids)):
            tasks[ids[i]]["deps"] = sorted(set(tasks[ids[i]]["deps"]) | {ids[i - 1]})


def _compute_graph(state: dict) -> None:
    """Recursion groups (SCCs of the prove graph), waves over the condensed graph, and heights."""
    tasks = state["tasks"]
    prove_ids = sorted(tid for tid, t in tasks.items() if t["kind"] == "prove")
    prove_by_key = {_key(t): tid for tid, t in tasks.items() if t["kind"] == "prove"}
    # Tarjan call graph SCCs are computed from the full call graph, decoupled from pruned execution deps
    succ = {
        tid: sorted(
            {prove_by_key[c] for c in tasks[tid].get("callees", []) if c in prove_by_key and prove_by_key[c] != tid}
        )
        for tid in prove_ids
    }
    comps = _tarjan(prove_ids, succ)
    comp_of: dict[str, int] = {}
    for i, comp in enumerate(comps):
        scc = f"scc:{comp[0]}" if len(comp) > 1 else None
        for member in comp:
            comp_of[member] = i
            tasks[member]["scc"] = scc
    waves = [0] * len(comps)
    for i, comp in enumerate(comps):  # callees' components are emitted first
        wave = 0
        for member in comp:
            for dep in succ[member]:
                if comp_of[dep] != i:
                    wave = max(wave, waves[comp_of[dep]] + 1)
        waves[i] = wave
    for member, i in comp_of.items():
        tasks[member]["wave"] = waves[i]
    heights, _ = _chain_heights(state, open_only=False)
    for tid, height in heights.items():
        tasks[tid]["height"] = height


def _blocker_index(
    state: dict,
) -> tuple[dict[str, set[str]], dict[str, set[str]], dict[tuple[str, str], set[str]]]:
    by_module: dict[str, set[str]] = defaultdict(set)
    by_file: dict[str, set[str]] = defaultdict(set)
    by_fn: dict[tuple[str, str], set[str]] = defaultdict(set)
    for tid, task in state["tasks"].items():
        if task["kind"] in ("verify", "repair"):
            by_module[task.get("module") or ""].add(tid)
        if task["kind"] == "verify":
            loc_file = norm_path(task.get("location_file") or "")
            if loc_file:
                by_file[loc_file].add(tid)
            loc_fn = task.get("location_function") or task.get("function") or ""
            if not loc_fn and task.get("fingerprint"):
                fp = task["fingerprint"]
                if "#" in fp and "::" in fp:
                    loc_fn = fp.split("#", 1)[-1].split("::", 1)[0]
            if loc_file and loc_fn:
                by_fn[(loc_file, loc_fn)].add(tid)
    return by_module, by_file, by_fn


def _gate_blockers(
    state: dict,
    module: str,
    index: tuple[Any, ...],
    task: dict | None = None,
    ctx: Ctx | None = None,
) -> set[str]:
    """
    Verify and repair tasks blocking a gate or a task.
    When task is None (or neither prove nor arch): coarse module gating for _chain_heights and cmd_status.
    When task has kind == 'prove': fine-grained gating blocking only on verify tasks in task's call cone,
    external contributor slices, and the verify and repair tasks of the module's harnesses whose scope
    meets the call cone (a sub-module's candidates do not hold another sub-module's functions).
    When task has kind == 'arch': the repairs of its own harness and of the unit.
    """
    by_module = index[0]
    by_file = index[1]
    by_fn = index[2] if len(index) > 2 else {}
    gate_rec = state.get("gates", {}).get(f"gate:{module}") or {}
    # The module and its harnesses: a link unit's verify and repair tasks name its sub-modules.
    own = {module, *(gate_rec.get("harness_modules") or [])}

    def repairs(mods: Iterable[str]) -> set[str]:
        tasks = state["tasks"]
        return {tid for mod in mods for tid in by_module.get(mod, set()) if tasks.get(tid, {}).get("kind") == "repair"}

    if task is not None and task.get("kind") == "arch":
        # An architect waits for the repair of its own harness (and of the unit's), not of its siblings.
        harness = task.get("harness_module")
        return repairs({module, harness} if harness else own)

    # Active repair tasks on the module always block
    active_repairs = repairs(own)

    if task is None or task.get("kind") != "prove":
        # Coarse module gate for _chain_heights, and cmd_status reporting
        gate = state.get("gates", {}).get(f"gate:{module}") or {"contributors": [module], "files": []}
        out = set(active_repairs)
        for mod in set(gate.get("contributors") or []) | own:
            out |= by_module.get(mod, set())
        for file in gate.get("files") or []:
            out |= by_file.get(file, set())
        return out

    # Fine-grained gate for prove:<fn>
    fn_file, fn_name = str(task.get("file") or ""), str(task.get("function") or "")
    cone_memo: list[set[tuple[str, str]]] = []

    def cone() -> set[tuple[str, str]]:
        if not cone_memo:
            cone_memo.append(_call_cone(fn_file, fn_name, ctx))
        return cone_memo[0]

    def in_cone() -> set[str]:
        return {tid for cfile, cfn in cone() for tid in by_fn.get((cfile, cfn), ())}

    # Sub-module scope (defect 13): a sub-module harness answers for its own functions, so its
    # candidates and repairs hold only the provers whose call cone meets that scope. The unit's own
    # harness answers for the whole unit. Without the inputs (no ctx), every harness counts.
    relevant = set(own)
    if ctx is not None:
        relevant = {module}
        for mod in own - {module}:
            scope = ctx.harness_scope(mod)
            if scope is None or scope & cone():
                relevant.add(mod)
    out = repairs(relevant)

    # 1. External contributor slices covering this module's files:
    # If another slice compiles this module's sources, verify tasks from that contributor slice hold the gate.
    external_contributors = set(gate_rec.get("contributors") or []) - own
    for ext_mod in external_contributors:
        out |= by_module.get(ext_mod, set())

    # 2. Harness-induced candidates:
    # If the module has a harness sidecar (harness_<module>.json, or a relevant sub-module's for a link
    # unit), any candidate of that harness may trigger a harness rejection and repair:<harness>, holding
    # the gate.
    if any((HARNESS_DIR / f"harness_{mod}.json").is_file() for mod in relevant):
        for mod in relevant:
            out |= by_module.get(mod, set())
        # An out-of-scope sub-module's candidate still holds the provers whose call cone it lies in.
        if own - relevant:
            out |= {tid for tid in in_cone() if state["tasks"][tid].get("module") in own - relevant}
    else:
        # Fine-grained: only verify tasks whose candidate belongs to this function or its transitive callees
        out |= in_cone()

    return out


def _chain_heights(state: dict, open_only: bool) -> tuple[dict[str, int], int]:
    """
    Longest chain of tasks waiting on each task (gates weigh nothing; a recursion group counts once),
    and the longest chain overall. With `open_only`, only non-terminal tasks count: the remaining
    critical path.
    """
    tasks = state["tasks"]
    live = {tid for tid, t in tasks.items() if not open_only or t["state"] not in TERMINAL}
    index = _blocker_index(state)
    waiters: dict[str, set[str]] = defaultdict(set)
    gates: set[str] = set()
    for tid in live:
        task = tasks[tid]
        for dep in _deps(task):
            if dep.startswith("gate:"):
                waiters[dep].add(tid)
                gates.add(dep)
            elif dep in live:
                waiters[dep].add(tid)
        if task["kind"] == "negotiate":
            for caller in task.get("callers") or []:
                if caller in live:  # the caller is requeued once the negotiation resolves
                    waiters[tid].add(caller)
    for gate in gates:
        for blocker in _gate_blockers(state, gate[len("gate:") :], index):
            if blocker in live:
                waiters[blocker].add(gate)
    nodes = sorted(live | gates)
    comps = _tarjan(nodes, {n: sorted(waiters.get(n, ())) for n in nodes})
    comp_of = {n: i for i, comp in enumerate(comps) for n in comp}
    weight = [1 if any(n in tasks for n in comp) else 0 for comp in comps]
    height = [0] * len(comps)
    for i, comp in enumerate(comps):  # waiters' components are emitted first
        best = 0
        for node in comp:
            for waiter in waiters.get(node, ()):
                j = comp_of[waiter]
                if j != i:
                    best = max(best, height[j] + weight[j])
        height[i] = best
    longest = max((height[i] + weight[i] for i in range(len(comps)) if weight[i]), default=0)
    return {tid: height[comp_of[tid]] for tid in live}, longest


# ---------------------------------------------------------------------------
# Readiness
# ---------------------------------------------------------------------------


class _View:
    """Readiness queries over one loaded state; `assume_terminal` asks "ready if these were done?"."""

    def __init__(self, state: dict, assume_terminal: Iterable[str] = (), ctx: Ctx | None = None) -> None:
        self.state = state
        self.tasks = state["tasks"]
        if ctx is None:
            try:
                ctx = Ctx()
            except Exception:
                ctx = None
        self.ctx = ctx
        self.index = _blocker_index(state)
        self.assume = frozenset(assume_terminal)
        self.scc: dict[str, list[str]] = defaultdict(list)
        for tid in sorted(self.tasks):
            if self.tasks[tid].get("scc"):
                self.scc[self.tasks[tid]["scc"]].append(tid)
        self._gates: dict[tuple[str, str | None], bool] = {}
        self._group_done: dict[str, bool] = {}
        self._group_ready: dict[str, bool] = {}

    def terminal(self, tid: str) -> bool:
        task = self.tasks.get(tid)
        return task is None or task["state"] in TERMINAL or tid in self.assume

    def gate_open(self, module: str, task: dict | None = None) -> bool:
        task_id = task["id"] if task else None
        key = (module, task_id)
        if key not in self._gates:
            blockers = _gate_blockers(self.state, module, self.index, task=task, ctx=self.ctx)
            self._gates[key] = all(self.terminal(b) for b in blockers)
        return self._gates[key]

    def group(self, tid: str) -> list[str]:
        task = self.tasks.get(tid)
        return self.scc[task["scc"]] if task and task.get("scc") else [tid]

    def dep_ok(self, dep: str, task: dict | None = None) -> bool:
        if dep.startswith("gate:"):
            return self.gate_open(dep[len("gate:") :], task=task)
        # A callee inside a recursion group is done only when the whole group is.
        scc = (self.tasks.get(dep) or {}).get("scc")
        if not scc:
            if self.terminal(dep):
                return True
            # Dynamic contract unblocking: if callee acquired a contract in workspace/work/, caller proceeds
            if dep.startswith("prove:"):
                t = self.tasks.get(dep)
                if t:
                    cctx = self.ctx or Ctx()
                    if callee_has_contract(cctx, t["file"], t["function"], t.get("module")):
                        return True
            return False
        if scc not in self._group_done:
            self._group_done[scc] = all(self.terminal(m) for m in self.scc[scc])
        return self._group_done[scc]

    def ready(self, task: dict) -> bool:
        if task["state"] != "pending":
            return False
        scc = task.get("scc")
        if scc and scc in self._group_ready:
            return self._group_ready[scc]
        members = self.group(task["id"])
        inside = set(members)
        # Recursion-group members become ready together: the group waits on every member's
        # outside dependencies, never on its own members.
        ok = all(
            dep in inside or self.dep_ok(dep, task=self.tasks[member])
            for member in members
            for dep in _deps(self.tasks[member])
        )
        if scc:
            self._group_ready[scc] = ok
        return ok


def _priority_key(task: dict) -> tuple:
    # Leaf/unverifiable shell tasks (height == 0 and shell_unverifiable_wp) are scheduled after
    # core_provable tasks so a single-agent queue does not stall behind a known WP limitation.
    shell_leaf = (
        1
        if (
            task.get("kind") == "prove"
            and task.get("verifiability") == "shell_unverifiable_wp"
            and int(task.get("height") or 0) == 0
        )
        else 0
    )
    return (shell_leaf, -int(task.get("height") or 0), -int(task.get("eva_unknowns") or 0), task["id"])


def _waves_filter(state: dict) -> Callable[[dict], bool]:
    """FRAMAC_SCHEDULER=waves: verification, then architects, then prove waves 0..K with barriers."""
    open_tasks = [t for t in state["tasks"].values() if t["state"] not in TERMINAL]
    verify_open = any(t["kind"] in ("verify", "repair") for t in open_tasks)
    arch_open = any(t["kind"] == "arch" for t in open_tasks)
    waves = [int(t.get("wave") or 0) for t in open_tasks if t["kind"] == "prove"]
    current = min(waves) if waves else None

    def allowed(task: dict) -> bool:
        if task["kind"] == "arch":
            return not verify_open
        if task["kind"] == "prove":
            return not verify_open and not arch_open and int(task.get("wave") or 0) == current
        return True

    return allowed


def _ready(state: dict, mode: str, ctx: Ctx | None = None) -> list[dict]:
    view = _View(state, ctx=ctx)
    allowed = _waves_filter(state) if mode == "waves" else (lambda _task: True)
    return sorted((t for t in state["tasks"].values() if view.ready(t) and allowed(t)), key=_priority_key)


# ---------------------------------------------------------------------------
# Ledger unit handling (always under the ledger lock)
# ---------------------------------------------------------------------------


def _unit_ids(task: dict, units: dict[str, dict]) -> list[str]:
    ids = set(task.get("units") or [])
    for cid, u in units.items():
        if u["function"] == task.get("function") and norm_path(u["file"]) == task.get("file"):
            ids.add(cid)
    return sorted(cid for cid in ids if cid in units)


def _can_batch_transitions() -> bool:
    return DEPS.transition is ledger.cmd_transition and callable(DEPS.transition_many)


def _batch_or_individual_transitions(
    specs: list[dict],
    *,
    errors: list | None = None,
    tag: str = "transition",
) -> list[str]:
    """
    Attempt DEPS.transition_many(specs) first; on failure, fall back to individual
    DEPS.transition calls. Returns the IDs of successfully transitioned units.
    """
    if not specs:
        return []
    if _can_batch_transitions():
        try:
            DEPS.transition_many(specs)
            return [s["id"] for s in specs]
        except (ledger.LedgerError, Exception) as exc:
            if errors is not None:
                errors.append(f"{tag} batch failed, falling back to individual: {exc}")
    succeeded: list[str] = []
    for s in specs:
        cid = s["id"]
        try:
            DEPS.transition(
                cid,
                s["status"],
                s.get("agent_id"),
                s.get("reason"),
                expected=s.get("expected"),
            )
            succeeded.append(cid)
        except (ledger.LedgerError, Exception) as exc:
            if errors is not None:
                errors.append(f"{tag} {cid}: {exc}")
    return succeeded


def _release_units(task: dict) -> list[str]:
    """in_progress units held by this task's agents go back to planned (compare-and-set)."""
    if task["kind"] != "prove":
        return []
    units, _ = ledger.load_state()
    mine = set(task.get("agents") or [])
    cids = [
        cid
        for cid in _unit_ids(task, units)
        if units[cid]["status"] == "in_progress" and units[cid].get("agent_id") in mine
    ]
    specs = [
        {"id": cid, "status": "planned", "agent_id": None, "reason": None, "expected": ["in_progress"]} for cid in cids
    ]
    return _batch_or_individual_transitions(specs)


def _park_units(task: dict, agent_id: str, reason: str) -> dict:
    """
    A terminal prove outcome: units this task still holds (in_progress, or planned ones it owns)
    become blocked with the reason. A unit without any evidence cannot be blocked (state table), so it
    returns to planned instead. No unit is ever left in_progress.
    """
    out: dict[str, list[str]] = {"blocked": [], "planned": [], "errors": []}
    if task["kind"] != "prove":
        return out
    units, _ = ledger.load_state()
    mine = set(task.get("agents") or []) | {agent_id}
    owned = set(task.get("units") or [])
    eligible: list[tuple[str, dict, str]] = []
    for cid in _unit_ids(task, units):
        u = units[cid]
        status = u["status"]
        if (status == "in_progress" and u.get("agent_id") in mine) or (status == "planned" and cid in owned):
            eligible.append((cid, u, status))
    if not eligible:
        return out
    has_reason = bool((reason or "").strip())
    if _can_batch_transitions():
        batch_items: list[dict] = []
        planned_blocked: list[str] = []
        planned_planned: list[str] = []
        for cid, u, status in eligible:
            if u.get("evidence") and has_reason:
                batch_items.append(
                    {"id": cid, "status": "blocked", "agent_id": None, "reason": reason, "expected": [status]}
                )
                planned_blocked.append(cid)
            elif status == "planned":
                planned_planned.append(cid)
            else:
                batch_items.append(
                    {"id": cid, "status": "planned", "agent_id": None, "reason": None, "expected": ["in_progress"]}
                )
                planned_planned.append(cid)
        try:
            if batch_items:
                DEPS.transition_many(batch_items)
            out["blocked"].extend(planned_blocked)
            out["planned"].extend(planned_planned)
            return out
        except ledger.LedgerError:
            pass
    for cid, _u, status in eligible:
        try:
            DEPS.transition(cid, "blocked", None, reason, expected=[status])
            out["blocked"].append(cid)
        except ledger.LedgerError:
            if status == "planned":
                out["planned"].append(cid)
                continue
            try:
                DEPS.transition(cid, "planned", None, None, expected=["in_progress"])
                out["planned"].append(cid)
            except ledger.LedgerError as exc:
                out["errors"].append(f"{cid}: {exc}")
    return out


def _block_covered_units(task: dict, reason: str) -> list[str]:
    """A failed contract re-check: the function's covered units are no longer credited."""
    units, _ = ledger.load_state()
    cids = [cid for cid in _unit_ids(task, units) if units[cid]["status"] == "covered"]
    specs = [
        {"id": cid, "status": "blocked", "agent_id": None, "reason": reason, "expected": ["covered"]} for cid in cids
    ]
    return _batch_or_individual_transitions(specs)


def _restore_unit(cid: str, previous: str, unresolved: list[str]) -> None:
    if previous == "blocked":
        DEPS.transition(
            cid, "blocked", None, "; ".join(unresolved) or "restored after a refused claim", expected=["in_progress"]
        )
    else:
        DEPS.transition(cid, "planned", None, None, expected=["in_progress"])


def _prove_dispatch_check(task: dict, fn_units: list[dict]) -> str | None:
    if any(u["status"] == "candidate" for u in fn_units):
        return "candidate"
    if not _open_units(task, fn_units):
        return "no_open_units"
    return None


def _claim_units(state: dict, task: dict) -> str | None:
    """
    Move the prove task's open units to in_progress with a compare-and-set. A unit that became a
    candidate in the meantime is never overwritten: the task is skipped instead. Returns the refusal.
    """
    units, _ = ledger.load_state()
    fn_units = [units[cid] for cid in _unit_ids(task, units) if units[cid]["status"] not in NO_TOUCH]
    refusal = _prove_dispatch_check(task, fn_units)
    if refusal:
        _finish(state, task, "skipped", refusal, reason=f"claim refused at dispatch ({refusal})")
        return refusal
    open_list = _open_units(task, fn_units)
    if _can_batch_transitions():
        try:
            DEPS.transition_many(
                [
                    {
                        "id": u["coverage_id"],
                        "status": "in_progress",
                        "agent_id": task["agent_id"],
                        "reason": None,
                        "expected": ["planned", "blocked"],
                    }
                    for u in open_list
                ]
            )
        except ledger.LedgerError as exc:
            refusal = "candidate" if "'candidate'" in str(exc) else "cas_refused"
            _finish(state, task, "skipped", refusal, reason=str(exc))
            return refusal
        task["units"] = [u["coverage_id"] for u in open_list]
        return None
    claimed: list[tuple[str, str, list[str]]] = []
    try:
        for u in open_list:
            DEPS.transition(u["coverage_id"], "in_progress", task["agent_id"], None, expected=["planned", "blocked"])
            claimed.append((u["coverage_id"], u["status"], list(u.get("unresolved") or [])))
    except ledger.LedgerError as exc:
        for cid, previous, unresolved in claimed:
            _try([], "restore", _restore_unit, cid, previous, unresolved)
        refusal = "candidate" if "'candidate'" in str(exc) else "cas_refused"
        _finish(state, task, "skipped", refusal, reason=str(exc))
        return refusal
    task["units"] = [cid for cid, _, _ in claimed]
    return None


# ---------------------------------------------------------------------------
# Descriptions handed to the parent
# ---------------------------------------------------------------------------


def _requests() -> list[dict]:
    data = contract_negotiator.load_ledger(REQUESTS)
    return [r for r in (data.get("requests") or []) if isinstance(r, dict)]


def _replay_reports(fingerprint: str, cand: dict) -> list[str]:
    """Deterministic replay reports for a candidate: replay/<fingerprint slug>.json, replay/<module>.json,
    or any replay report that names the fingerprint."""
    if not REPLAY_DIR.is_dir():
        return []
    names = {f"{_fp_slug(fingerprint)}.json"}
    if cand.get("module"):
        names.add(f"{cand['module']}.json")
    found = []
    for path in sorted(REPLAY_DIR.glob("*.json")):
        if path.name in names:
            found.append(path.as_posix())
            continue
        data = _load_report(path)
        if not data:
            continue
        raw_arts = data.get("artifacts")
        arts: list[Any] = raw_arts if isinstance(raw_arts, list) else []
        if (
            data.get("fingerprint") == fingerprint
            # run_eacsl_fuzz.py replay-candidates names its reports <slug>-<hash>.json and records
            # the candidate here, whatever fingerprint the replay itself produced.
            or data.get("candidate_fingerprint") == fingerprint
            or fingerprint in (data.get("fingerprints") or [])
            or fingerprint in (data.get("candidates") or [])
            or any(isinstance(a, dict) and a.get("fingerprint") == fingerprint for a in arts)
        ):
            found.append(path.as_posix())
    return found


def _prepare_kwargs(task: dict) -> dict:
    kind = task["kind"]
    module = task.get("module") if task.get("module") != "unknown" else None
    if kind == "prove":
        return {"module": module, "function": task["function"], "c_file": task["file"]}
    if kind == "breaker":  # the stalled prover's report, not the stale workspace/reports/wp/<fn>.json
        return {
            "module": module,
            "function": task["function"],
            "c_file": task["file"],
            "wp_report": task.get("wp_report"),
        }
    if kind == "negotiate":
        by_id = {r.get("id"): r for r in _requests()}
        return {
            "module": module,
            "function": task["function"],
            "c_file": task["file"],
            "header_file": task.get("header"),
            "requests": [by_id[r] for r in task.get("requests") or [] if r in by_id],
        }
    if kind == "arch":
        return {"module": module, "header_file": task.get("header")}
    return {"module": module, "candidate_fp": task["fingerprint"]}


def _describe(task: dict, ctx: Ctx | None = None) -> dict:
    out: dict[str, Any] = {
        "task": task["id"],
        "kind": task["kind"],
        "agent_id": task.get("agent_id"),
        "role": ROLE_BY_KIND.get(task["kind"]),
        "module": task.get("module"),
        "attempt": int(task.get("dispatches") or 0),
        "priority": {"height": int(task.get("height") or 0), "eva_unknowns": int(task.get("eva_unknowns") or 0)},
    }
    for field in ("file", "function", "header", "fingerprint"):
        if task.get(field):
            out[field] = task[field]
    if task["kind"] == "prove":
        out["coverage_ids"] = list(task.get("units") or [])
    elif task["kind"] == "verify":
        cand = (ctx.candidates.get(task["fingerprint"]) if ctx else None) or {}
        out["candidate_fingerprint"] = task["fingerprint"]
        out["replay_reports"] = _replay_reports(task["fingerprint"], cand)
        meta = HARNESS_DIR / f"harness_{_verify_harness_module(task, ctx)}.json"
        out["harness_meta"] = meta.as_posix() if meta.is_file() else None
    elif task["kind"] == "negotiate":
        by_id = {r.get("id"): r for r in _requests()}
        out["requests"] = [by_id[r] for r in task.get("requests") or [] if r in by_id]
        out["callers"] = list(task.get("callers") or [])
    elif task["kind"] == "breaker" and task.get("wp_report"):
        out["wp_report"] = task["wp_report"]  # the stalled prover's promoted WP report (unproven goals)
    if task.get("brief_file"):
        out["brief_file"] = task["brief_file"]
    if task.get("wall_budget_s") is not None:
        out["wall_budget_s"] = int(task["wall_budget_s"])
    return out


def _verify_harness_module(task: dict, ctx: Ctx | None = None) -> str:
    """
    The harness module a verify task's candidate runs through: the task's module (the candidate's
    harness module); a link unit recorded on an older candidate resolves to its harness.
    """
    mod = str(task.get("module") or "unknown")
    mm = ctx.mm if ctx is not None else workspace_overlay.module_map_for(Path("workspace"))
    return (
        workspace_overlay.harness_module_for_function(
            mm, mod, task.get("location_file"), task.get("location_function") or task.get("function")
        )
        or mod
    )


def _describe_repair(task: dict) -> dict:
    mod = task["module"]
    actions = []
    if any(str(r).startswith("harness_induced") for r in task.get("reasons") or []):
        actions.append(
            f'python3 {SCRIPTS}/generate_harness.py --record-repair workspace/harnesses/harness_{mod}.json --reason "<reason>"'
        )
        actions.append(
            f"repair workspace/harnesses/harness_{mod}.c (or regenerate it with --auto-args / --entry-style auto_prototype)"
        )
    # A repaired harness has a new digest, so `build-`/`fuzz-<mod>` refuse it until the reach gate
    # records it again; build-check needs no re-run (the gate reads the current build report).
    actions.append(f"python3 {SCRIPTS}/pipeline_make.py run reach-gate")
    actions.append(f"python3 {SCRIPTS}/pipeline_make.py run module-{mod}")
    actions.append(f"python3 {SCRIPTS}/wp_scheduler.py refresh --module {mod}")
    return {
        "task": task["id"],
        "kind": "repair",
        "role": "parent",
        "module": mod,
        "reasons": list(task.get("reasons") or []),
        "actions": actions,
    }


# ---------------------------------------------------------------------------
# init / next
# ---------------------------------------------------------------------------


def _reconcile_units(state: dict, errors: list) -> list[dict]:
    """in_progress units whose agent holds no live task go back to planned (compare-and-set)."""
    live = {t.get("agent_id") for t in state["tasks"].values() if t["state"] in LIVE and t.get("agent_id")}
    units, _ = ledger.load_state()
    to_reset = [
        (cid, units[cid].get("agent_id"))
        for cid in sorted(units)
        if units[cid]["status"] == "in_progress" and units[cid].get("agent_id") not in live
    ]
    if not to_reset:
        return []
    specs = [
        {"id": cid, "status": "planned", "agent_id": None, "reason": None, "expected": ["in_progress"]}
        for cid, _ in to_reset
    ]
    aid_map = dict(to_reset)
    succeeded = _batch_or_individual_transitions(specs, errors=errors, tag="reconcile")
    return [{"coverage_id": cid, "agent_id": aid_map[cid]} for cid in succeeded]


def _newest_template_mtime() -> float | None:
    newest = None
    here = Path(__file__).resolve().parent
    for base in (here.parent / "skills" / "framac-wp", Path("/opt/framac-pipeline/skills/framac-wp")):
        if base.is_dir():
            for tpl in base.glob("*_brief.md"):
                with contextlib.suppress(OSError):
                    mtime = tpl.stat().st_mtime
                    newest = mtime if newest is None else max(newest, mtime)
    return newest


def _stale_briefs(state: dict) -> list[dict]:
    """Rendered briefs that predate their template or still carry unrendered placeholders."""
    agents_dir = Path("agents")
    if not agents_dir.is_dir():
        return []
    template_mtime = _newest_template_mtime()
    out = []
    for brief in sorted(agents_dir.glob("*/brief.md")):
        try:
            text = brief.read_text(encoding="utf-8", errors="replace")
            mtime = brief.stat().st_mtime
        except OSError:
            continue
        reasons = []
        left = sorted(set(_PLACEHOLDER_RE.findall(text)))
        if left:
            reasons.append("unrendered placeholders: " + ", ".join("{" + p + "}" for p in left))
        if template_mtime is not None and mtime < template_mtime:
            reasons.append("older than the brief templates")
        if reasons:
            aid = brief.parent.name
            task = state["tasks"].get(state["agents"].get(aid, ""))
            live = bool(task and task["state"] in LIVE and task.get("agent_id") == aid)
            out.append(
                {
                    "brief": brief.as_posix(),
                    "agent_id": aid,
                    "live": live,
                    "reasons": reasons,
                    "action": "re-render with next --prepare" if not live else "let the running agent finish",
                }
            )
    return out


def _adopt_merged_architects(state: dict) -> list[str]:
    """
    A run started before the scheduler already merged some architects (agent id arch-<module>): their
    merge left agents/arch-<module>/artifacts/<header stem>.patch. Those modules are not re-architected.
    """
    adopted = []
    for tid, task in sorted(state["tasks"].items()):
        if task["kind"] != "arch" or task["state"] != "pending" or not task.get("header"):
            continue
        patch = Path("agents") / f"arch-{task['slug']}" / "artifacts" / f"{Path(task['header']).stem}.patch"
        if patch.is_file():
            _finish(state, task, "done", "merged_before_scheduler", reason=patch.as_posix())
            adopted.append(tid)
    return adopted


def _write_wp_queue(state: dict) -> None:
    """workspace/reports/wp_queue.json: the ordered prove queue and its waves (compatibility view)."""
    tasks = state["tasks"]
    prove = sorted((t for t in tasks.values() if t["kind"] == "prove" and t["state"] != "skipped"), key=_priority_key)
    waves: dict[int, list[str]] = defaultdict(list)
    groups: dict[str, list[str]] = defaultdict(list)
    for task in sorted(prove, key=lambda t: (int(t.get("wave") or 0), t["id"])):
        waves[int(task.get("wave") or 0)].append(_key(task))
        if task.get("scc"):
            groups[task["scc"]].append(_key(task))
    atomic_write_json(
        WP_QUEUE,
        {
            "generated_by": "wp_scheduler.py init",
            "generated_at": utc_now(),
            "scheduler": "ready_queue (FRAMAC_SCHEDULER=waves for the wave procedure)",
            "queue": [
                {
                    "task": t["id"],
                    "file": t["file"],
                    "function": t["function"],
                    "module": t["module"],
                    "wave": int(t.get("wave") or 0),
                    "height": int(t.get("height") or 0),
                    "eva_unknowns": int(t.get("eva_unknowns") or 0),
                    "coverage_ids": list(t.get("units") or []),
                    "state": t["state"],
                }
                for t in prove
            ],
            "waves": [{"wave": w, "count": len(waves[w]), "functions": waves[w]} for w in sorted(waves)],
            "recursion_groups": [sorted(v) for _, v in sorted(groups.items())],
            "architects": [
                {"task": t["id"], "module": t["module"], "header": t.get("header")}
                for t in sorted(tasks.values(), key=lambda x: x["id"])
                if t["kind"] == "arch"
            ],
            "verify": sorted(
                t["fingerprint"] for t in tasks.values() if t["kind"] == "verify" and t["state"] not in TERMINAL
            ),
        },
    )


def _summary(state: dict) -> dict:
    tasks = state["tasks"]
    by_kind: dict[str, dict[str, int]] = defaultdict(dict)
    for task in tasks.values():
        by_kind[task["kind"]][task["state"]] = by_kind[task["kind"]].get(task["state"], 0) + 1
    prove = [t for t in tasks.values() if t["kind"] == "prove"]
    return {
        "counts": dict(Counter(t["state"] for t in tasks.values())),
        "by_kind": {k: by_kind[k] for k in sorted(by_kind)},
        "waves": 1 + max((int(t.get("wave") or 0) for t in prove), default=-1),
        "recursion_groups": len({t["scc"] for t in prove if t.get("scc")}),
        "gate_count": len(state.get("gates") or {}),
    }


def cmd_init(reconcile: bool = False) -> dict:
    """
    Build (or re-sync, idempotently) the task graph from planned units and unverified candidates and
    write wp_queue.json. --reconcile adopts an existing run: in_progress units whose agent holds no
    live task return to planned, and briefs that need re-rendering are reported.
    """
    with run_lock("ledger"):
        state = load_schedule()
        out: dict[str, Any] = {"ok": True, "mode": scheduler_mode(), "errors": []}
        if reconcile:
            out["reconciled_units"] = _reconcile_units(state, out["errors"])
            out["stale_briefs"] = _stale_briefs(state)
            rechecks_reclaimed = []
            for rid, entry in list((state.get("rechecks") or {}).items()):
                if entry.get("state") == "running":
                    entry["state"] = "queued"
                    rechecks_reclaimed.append(rid)
            if rechecks_reclaimed:
                out["rechecks_reclaimed"] = rechecks_reclaimed
        out["sync"] = _sync(state, Ctx())
        if reconcile:
            out["adopted_architects"] = _adopt_merged_architects(state)
        _write_wp_queue(state)
        save_schedule(state)
        out["schedule"] = SCHEDULE.as_posix()
        out["wp_queue"] = WP_QUEUE.as_posix()
        out.update(_summary(state))
    return out


def _prepare_failed(state: dict, task: dict, error: str) -> None:
    task["prepare_errors"] = int(task.get("prepare_errors") or 0) + 1
    if task["prepare_errors"] >= MAX_PREPARE_ERRORS:
        _finish(state, task, "blocked", "prepare_failed", reason=error)
    else:
        _reopen(state, task, f"prepare-agent failed: {error}")


def _is_done(state: dict, ctx: Ctx | None = None) -> bool:
    if state.get("rechecks"):
        return False
    if not all(t["state"] in TERMINAL for t in state["tasks"].values()):
        return False
    if ctx is not None:
        units: list[dict] = list(ctx.units.values())
    else:
        try:
            raw_units, _ = ledger.load_state()
            units = list(raw_units.values())
        except Exception:
            units = []
    return not any(u.get("status") in ("planned", "in_progress") for u in units)


def cmd_next(slots: str = "auto", prepare: bool = False, max_agents: int | None = None) -> dict:
    """
    Hand out the highest-priority ready tasks. `auto` slots = recommend().max_agents minus the agent
    tasks already running; a number hands out at most that many. Repair tasks go to the parent and
    take no slot. With --prepare, every agent gets its scratch overlay and brief, and a prover's units
    move to in_progress with a compare-and-set.
    """
    mode = scheduler_mode()
    out: dict[str, Any] = {
        "ok": True,
        "mode": mode,
        "tasks": [],
        "parent_tasks": [],
        "skipped": [],
        "errors": [],
        "briefs": [],
    }
    with run_lock("ledger"):
        state = load_schedule()
        ctx = Ctx()
        out["sync"] = _sync(state, ctx)
        running = sum(1 for t in state["tasks"].values() if t["state"] == "running" and t["kind"] in AGENT_KINDS)
        if slots == "auto":
            limit = int(DEPS.recommend(max_agents).get("max_agents") or 1)
            budget = max(0, limit - running)
            out["slots"] = {"mode": "auto", "max_agents": limit, "running": running, "available": budget}
        else:
            budget = max(0, int(slots))
            out["slots"] = {"mode": "fixed", "running": running, "available": budget}
        picked: list[str] = []
        for task in _ready(state, mode, ctx=ctx):
            if task["kind"] == "repair":
                _assign_parent(state, task)
                out["parent_tasks"].append(_describe_repair(task))
                continue
            if len(picked) >= budget:
                continue
            if task["kind"] == "prove":
                refusal = _prove_dispatch_check(task, ctx.fn_units(task["file"], task["function"]))
                if refusal:
                    _finish(state, task, "skipped", refusal, reason=f"not dispatched ({refusal})")
                    out["skipped"].append({"task": task["id"], "reason": refusal})
                    continue
            elif task["kind"] == "negotiate":
                neg_refusal = _negotiate_skip_verdict(
                    ctx.fn_units(task["file"], task["function"]),
                    set(),
                    ctx.verifiability(task["file"], task["function"]),
                )
                if neg_refusal:
                    note = f"not dispatched: callee unit is {neg_refusal}"
                    for rid in task.get("requests") or []:
                        _resolve_request(out["errors"], str(rid), "rejected_by_callee", note)
                    _finish(state, task, "skipped", neg_refusal, reason=note)
                    out["skipped"].append({"task": task["id"], "reason": neg_refusal})
                    continue
            _assign_agent(state, task)
            picked.append(task["id"])
        over_budget = _over_budget_tasks(state)
        if over_budget:
            out["over_budget_tasks"] = over_budget
        save_schedule(state)
        snapshot = {tid: json.loads(json.dumps(state["tasks"][tid])) for tid in picked}
        if not prepare:
            out["tasks"] = [_describe(snapshot[tid], ctx) for tid in picked]
            out["pending"] = sum(1 for t in state["tasks"].values() if t["state"] == "pending")
            out["done"] = _is_done(state, ctx)
            return out

    # Scratch overlays are snapshotted under the `merge` lock: never while holding the ledger lock.
    prepared: dict[str, dict] = {}
    failures: dict[str, str] = {}
    if picked:
        worker_cap = min(len(picked), os.cpu_count() or 4, 16)

        def _do_prepare(tid: str) -> tuple[str, dict | None, str | None]:
            task = snapshot[tid]
            try:
                res = DEPS.prepare_agent(
                    Path.cwd(), task["agent_id"], ROLE_BY_KIND[task["kind"]], **_prepare_kwargs(task)
                )
                return tid, res, None
            except Exception as exc:  # any failure leaves the task re-dispatchable, never stuck running
                return tid, None, f"{type(exc).__name__}: {exc}"

        with run_lock("merge"):
            with concurrent.futures.ThreadPoolExecutor(max_workers=worker_cap) as executor:
                for tid, res, err in executor.map(_do_prepare, picked):
                    if err is not None:
                        failures[tid] = err
                    elif res is not None:
                        prepared[tid] = res

    with run_lock("ledger"):
        state = load_schedule()
        ready_tids: list[str] = []
        prove_tasks: list[dict] = []
        for tid in picked:
            task = state["tasks"].get(tid)
            aid = snapshot[tid]["agent_id"]
            if task is None or task["state"] != "running" or task.get("agent_id") != aid:
                out["errors"].append({"task": tid, "agent_id": aid, "error": "task changed while preparing"})
                continue
            if tid in failures:
                _prepare_failed(state, task, failures[tid])
                out["errors"].append({"task": tid, "agent_id": aid, "error": failures[tid]})
                continue
            ready_tids.append(tid)
            if task["kind"] == "prove":
                prove_tasks.append(task)

        prove_refusals: dict[str, str | None] = {}
        if prove_tasks and _can_batch_transitions():
            units, _ = ledger.load_state()
            batch_items: list[dict] = []
            task_open_cids: dict[str, list[str]] = {}
            for task in prove_tasks:
                fn_units = [units[cid] for cid in _unit_ids(task, units) if units[cid]["status"] not in NO_TOUCH]
                refusal = _prove_dispatch_check(task, fn_units)
                if refusal:
                    _finish(state, task, "skipped", refusal, reason=f"claim refused at dispatch ({refusal})")
                    prove_refusals[task["id"]] = refusal
                    continue
                open_list = _open_units(task, fn_units)
                task_open_cids[task["id"]] = [u["coverage_id"] for u in open_list]
                for u in open_list:
                    batch_items.append(
                        {
                            "id": u["coverage_id"],
                            "status": "in_progress",
                            "agent_id": task["agent_id"],
                            "reason": None,
                            "expected": ["planned", "blocked"],
                        }
                    )
            if batch_items:
                try:
                    DEPS.transition_many(batch_items)
                    for p_tid, cids in task_open_cids.items():
                        state["tasks"][p_tid]["units"] = cids
                        prove_refusals[p_tid] = None
                except ledger.LedgerError:
                    for p_tid in task_open_cids:
                        prove_refusals[p_tid] = _claim_units(state, state["tasks"][p_tid])

        units_for_neg: dict[str, dict] | None = None
        for tid in ready_tids:
            task = state["tasks"][tid]
            aid = snapshot[tid]["agent_id"]
            if task["kind"] == "prove":
                refusal = prove_refusals[tid] if tid in prove_refusals else _claim_units(state, task)
                if refusal:
                    out["skipped"].append({"task": tid, "agent_id": aid, "reason": refusal})
                    continue
            elif task["kind"] == "negotiate":
                if units_for_neg is None:
                    units_for_neg, _ = ledger.load_state()
                neg_units = [
                    units_for_neg[cid]
                    for cid in _unit_ids(task, units_for_neg)
                    if units_for_neg[cid]["status"] not in NO_TOUCH
                ]
                neg_refusal = _negotiate_skip_verdict(neg_units, set(), task.get("verifiability"))
                if neg_refusal:
                    note = f"claim refused at dispatch: callee unit is {neg_refusal}"
                    for rid in task.get("requests") or []:
                        _resolve_request(out["errors"], str(rid), "rejected_by_callee", note)
                    _finish(state, task, "skipped", neg_refusal, reason=note)
                    out["skipped"].append({"task": tid, "agent_id": aid, "reason": neg_refusal})
                    continue
            task["brief_file"] = prepared[tid].get("brief_file")
            out["tasks"].append(_describe(task, ctx))
            if task["brief_file"]:
                out["briefs"].append(task["brief_file"])
        out["pending"] = sum(1 for t in state["tasks"].values() if t["state"] == "pending")
        out["done"] = _is_done(state, ctx)
        save_schedule(state)
    return out


# ---------------------------------------------------------------------------
# complete
# ---------------------------------------------------------------------------


def _load_result(path: Path, task: dict, agent_id: str) -> tuple[dict | None, list[str]]:
    try:
        res = load_agent_result_json(path)
    except ArtifactError as exc:
        return None, [str(exc)]
    if not isinstance(res, dict):
        return None, ["the result is not a JSON object"]
    errors = list(validate_agent_result(res))[:10]
    if errors:
        return res, errors
    if res.get("agent_id") != agent_id:
        errors.append(f"agent_id is {res.get('agent_id')!r}, expected {agent_id!r}")
    if res.get("role") != RESULT_ROLE[task["kind"]]:
        errors.append(f"role is {res.get('role')!r}, expected {RESULT_ROLE[task['kind']]!r}")
    if task["kind"] in ("prove", "negotiate", "breaker"):
        if res.get("function") != task["function"] or norm_path(res.get("file")) != task["file"]:
            errors.append(f"result is for {res.get('file')}#{res.get('function')}, expected {_key(task)}")
    if task["kind"] == "verify" and res.get("candidate_fingerprint") != task["fingerprint"]:
        errors.append(
            f"candidate_fingerprint is {res.get('candidate_fingerprint')!r}, expected {task['fingerprint']!r}"
        )
    return res, errors


def _find_agent_wp_report(agent_id: str, res: dict, function: str) -> str | None:
    prefix = f"agents/{agent_id}/scratch/"
    paths = []
    for ev in res.get("evidence") or []:
        p = str((ev or {}).get("tool_output") or "").replace("\\", "/")
        if p.startswith(prefix) and p.endswith(".json") and p not in paths:
            paths.append(p)
    default = f"{prefix}wp_{function}.json"
    if default not in paths:
        paths.append(default)
    for p in paths:
        path = Path(p)
        if path.is_symlink() or not path.is_file():
            continue
        data = _load_report(path)
        if data and "status" in data and data.get("function") == function and data.get("mode") != "guardrail":
            return p
    return None


def _promote_agent_wp(task: dict, agent_id: str, res: dict, errors: list) -> tuple[str | None, dict | None]:
    """
    Promote the agent's own WP report into agents/<id>/artifacts/ (symlink, size and TOCTOU checks),
    rewriting its `file` to the repository path so ingestion matches the right unit even when
    same-named static functions exist.
    """
    src = _find_agent_wp_report(agent_id, res, task["function"])
    if src is None:
        return None, None
    promoted = _try(
        errors,
        f"promote {src}",
        promote_file,
        Path.cwd(),
        agent_id,
        src,
        kind="artifact",
        dest_name=f"wp_{task['function']}.json",
    )
    if not promoted:
        return None, None
    dest = Path(promoted["dest"])
    report = _load_report(dest)
    if report is None:
        errors.append(f"{dest.as_posix()}: unreadable WP report")
        return None, None
    if report.get("file") != task["file"]:
        report["agent_file"] = report.get("file")
        report["file"] = task["file"]
        atomic_write_json(dest, report)
    return dest.as_posix(), report


def _resolve_request(errors: list, rid: str, status: str, note: str) -> None:
    _try(errors, f"resolve {rid}", DEPS.resolve_request, REQUESTS, rid, status, note)


def _emit_negotiations(state: dict, ctx: Ctx, caller: dict, new_requests: list[dict], out: dict) -> None:
    """Each new strengthening request becomes (or joins) negotiate:<callee> right away, capped per pair."""
    tasks = state["tasks"]
    caller_key = _key(caller)
    for req in new_requests:
        rid = str(req.get("id"))
        name = str(req.get("callee_function") or "")
        cfile = norm_path(req.get("callee_file") or "")
        defs = ctx.resolve(name, caller["file"]) if name else []
        match = [d for d in defs if d[0] == cfile] or defs
        if not match and cfile and name:
            match = [(cfile, name, ctx.file_module.get(cfile, ""))]
        if not match:
            _resolve_request(
                out["errors"],
                rid,
                "rejected_by_callee",
                "not dispatched: callee not found in the ledger or the call graph",
            )
            continue
        cfile, cname, cmod = match[0]
        key = f"{cfile}#{cname}"
        if key == caller_key:
            _resolve_request(
                out["errors"],
                rid,
                "rejected_by_callee",
                "not dispatched: a function cannot strengthen its own contract by request",
            )
            continue
        neg_verdict = _negotiate_skip_verdict(ctx.fn_units(cfile, cname), set(), ctx.verifiability(cfile, cname))
        if neg_verdict:
            _resolve_request(
                out["errors"],
                rid,
                "rejected_by_callee",
                f"not dispatched: callee {key} is {neg_verdict}",
            )
            out.setdefault("negotiations_skipped", []).append({"request": rid, "callee": key, "reason": neg_verdict})
            continue
        settled = tasks.get(f"negotiate:{key}")
        if (
            settled is not None
            and settled["state"] in TERMINAL
            and settled.get("outcome") != "applied"
            and int(settled.get("dispatches") or 0) >= MAX_NEGOTIATION_ROUNDS_PER_CALLEE
        ):
            _resolve_request(
                out["errors"],
                rid,
                "rejected_by_callee",
                f"not dispatched: callee {key} went through {settled['dispatches']} negotiation rounds "
                f"(cap {MAX_NEGOTIATION_ROUNDS_PER_CALLEE}) without an accepted contract",
            )
            out.setdefault("negotiations_capped", []).append({"request": rid, "callee": key})
            continue
        pair = f"{caller['id']}|{key}"
        count = int(state["negotiation_counts"].get(pair, 0))
        if count >= MAX_NEGOTIATIONS_PER_PAIR:
            _resolve_request(
                out["errors"],
                rid,
                "rejected_by_callee",
                f"not dispatched: negotiation cap ({MAX_NEGOTIATIONS_PER_PAIR}) reached for {caller_key} -> {key}",
            )
            out.setdefault("negotiations_capped", []).append({"request": rid, "callee": key})
            continue
        state["negotiation_counts"][pair] = count + 1
        tid = f"negotiate:{key}"
        header = norm_path(req.get("header_file") or "") or None
        task = tasks.get(tid)
        if task is None:
            task = _new_task(
                state,
                tid,
                "negotiate",
                cname,
                module=cmod,
                file=cfile,
                function=cname,
                header=header,
                requests=[rid],
                callers=[caller["id"]],
                followup_requests=[],
                followup_callers=[],
                merge_attempts=0,
                analysis_errors=0,
                invalid_results=0,
            )
            if f"prove:{key}" in tasks:
                task["deps"] = [f"prove:{key}"]  # never strengthen a contract still being proved
        elif task["state"] == "pending":
            task["requests"] = list(dict.fromkeys([*task.get("requests", []), rid]))
            task["callers"] = list(dict.fromkeys([*task.get("callers", []), caller["id"]]))
            task["header"] = header or task.get("header")
        elif task["state"] in TERMINAL:
            task.update(requests=[rid], callers=[caller["id"]], header=header or task.get("header"))
            _reopen(state, task, f"new strengthening request {rid}")
        else:  # running or merging: the next round handles it
            task.setdefault("followup_requests", []).append(rid)
            task.setdefault("followup_callers", []).append(caller["id"])
        out.setdefault("new_tasks", []).append(tid)


def _requeue_caller(state: dict, caller_id: str) -> bool:
    caller = state["tasks"].get(caller_id)
    if caller is None or caller["kind"] != "prove":
        return False
    caller["extra_deps"] = sorted(
        tid
        for tid, t in state["tasks"].items()
        if t["kind"] == "negotiate" and t["state"] not in TERMINAL and caller_id in (t.get("callers") or [])
    )
    if caller["state"] == "blocked":
        _reopen(state, caller, "a callee contract was strengthened on request")
        return True
    return False


def _resolve_negotiation(state: dict, task: dict, applied: bool, note: str, out: dict) -> None:
    """Close a negotiation round: resolve its requests, requeue the callers whose request was applied."""
    status = "verified_and_applied" if applied else "rejected_by_callee"
    for rid in task.get("requests") or []:
        _resolve_request(out["errors"], rid, status, note)
    _finish(state, task, "done", "applied" if applied else "rejected", reason=note)
    requeued = [c for c in (task.get("callers") or []) if applied and _requeue_caller(state, c)]
    out.setdefault("negotiation", []).append({"task": task["id"], "status": status, "requeued_callers": requeued})
    if task.get("followup_requests"):
        task["requests"] = list(dict.fromkeys(task["followup_requests"]))
        task["callers"] = list(dict.fromkeys(task.get("followup_callers") or []))
        task["followup_requests"], task["followup_callers"] = [], []
        _reopen(state, task, "follow-up strengthening requests")


def _ensure_breaker(state: dict, prove_task: dict, agent_id: str, wp_report: str | None, out: dict) -> None:
    tid = f"breaker:{_key(prove_task)}"
    task = state["tasks"].get(tid)
    if task is None:
        task = _new_task(
            state,
            tid,
            "breaker",
            prove_task["function"],
            module=prove_task["module"],
            file=prove_task["file"],
            function=prove_task["function"],
            invalid_results=0,
        )
    elif task["state"] in TERMINAL:
        _reopen(state, task, "the prover stalled again")
    else:
        return
    task["origin_agent"] = agent_id
    task["wp_report"] = wp_report
    out.setdefault("new_tasks", []).append(tid)


def _ensure_repair(state: dict, module: str, reason: str, out: dict) -> None:
    tid = f"repair:{module}"
    task = state["tasks"].get(tid)
    if task is None:
        task = _new_task(state, tid, "repair", module, module=module, reasons=[reason])
    elif task["state"] in TERMINAL:
        task["reasons"] = [reason]
        _reopen(state, task, reason)
    elif task["state"] == "running":  # the parent is repairing already: one more round afterwards
        task.setdefault("followup_reasons", []).append(reason)
    elif reason not in task.setdefault("reasons", []):
        task["reasons"].append(reason)
    out.setdefault("new_tasks", []).append(tid)


def _on_invalid_result(state: dict, task: dict, agent_id: str, errors: list[str], out: dict) -> None:
    """Malformed results are discarded, never repaired: one re-run with a fresh agent, then blocked."""
    task["invalid_results"] = int(task.get("invalid_results") or 0) + 1
    out["validation_errors"] = errors
    if task["invalid_results"] < MAX_INVALID_RESULTS:
        out["units_released"] = _release_units(task)
        _reopen(state, task, "invalid agent result")
        out["action"] = "requeued_invalid_result"
        return
    out["units"] = _park_units(task, agent_id, f"agent result invalid {task['invalid_results']} times")
    if task["kind"] == "negotiate":
        _resolve_negotiation(state, task, False, "the callee prover returned invalid results", out)
    else:
        _finish(state, task, "blocked", "invalid_result", reason="; ".join(errors)[:400])
    out["action"] = "blocked_invalid_result"


def _on_analysis_error(state: dict, task: dict, agent_id: str, report_rel: str, report: dict, out: dict) -> None:
    """WP was killed or timed out: retried once with a fresh agent (a larger lease), then blocked."""
    reason = str(report.get("reason") or "unknown")
    _try(out["errors"], "ingest-wp", DEPS.ingest_wp, [Path(report_rel)])  # evidence only, no status change
    task["analysis_errors"] = int(task.get("analysis_errors") or 0) + 1
    out["reason"] = reason
    if task["analysis_errors"] < MAX_ANALYSIS_ERRORS:
        out["units_released"] = _release_units(task)
        _reopen(state, task, f"analysis_error ({reason}): retried once")
        out["action"] = "retry_analysis_error"
        return
    out["units"] = _park_units(task, agent_id, f"analysis_error: WP did not complete twice ({reason})")
    if task["kind"] == "negotiate":
        _resolve_negotiation(state, task, False, f"WP did not complete twice ({reason})", out)
    else:
        _finish(state, task, "blocked", "analysis_error", reason=reason)
    out["action"] = "blocked_analysis_error"


def _eva_has_invalid(file: str, fn: str) -> bool:
    """Whether any module's Eva report holds an Invalid alarm for the function."""
    if not EVA_DIR.is_dir():
        return False
    for path in sorted(EVA_DIR.glob("*.json")):
        data = load_json_optional(path, {}) or {}
        for alarm in (data.get("invalid_alarms") if isinstance(data, dict) else None) or []:
            if isinstance(alarm, dict) and alarm.get("function") == fn and eva_alarm_in_file(alarm, file):
                return True
    return False


# Kinds of the RTE goals WP generates for a body (Frama-C RTE plugin names), as opposed to contract goals
# (`postcondition`, `precondition`, `assigns clause`, loop goals), which only a proof discharges.
_RTE_GOAL_KINDS = frozenset(
    {
        "pointer_value",
        "mem_access",
        "index_bound",
        "initialization",
        "pointer_alignment",
        "dangling_pointer",
        "signed_overflow",
        "unsigned_overflow",
        "signed_downcast",
        "unsigned_downcast",
        "division_by_zero",
        "shift",
        "float_to_int",
        "function_pointer",
    }
)


def _unproven_rte_goals(report: dict) -> list[dict] | None:
    """The unproven goals when every one is an RTE goal of the body; None when any is a contract goal.

    The kind decides, not WP's bucket: an RTE goal on a `return` expression lands in the postcondition bucket.
    """
    goals = report.get("unproven_goals")
    if not isinstance(goals, list) or not goals:
        return None
    if any(not isinstance(g, dict) or g.get("kind") not in _RTE_GOAL_KINDS for g in goals):
        return None
    return goals


def _eva_backs_unproven_rte(ctx: Ctx, file: str, fn: str, goals: list[dict]) -> bool:
    """
    Whether Eva discharged every RTE kind that WP left unproven for the function, and found no Invalid alarm in it.
    A negotiated contract is merged without a proof of its body only when this holds: the unproven goals are then
    memory-model limits of WP (e.g. pointer casts), with Eva and the dynamic oracle as the evidence behind them.
    """
    if _eva_has_invalid(file, fn):
        return False
    kinds = {str(g.get("kind") or "") for g in goals}
    if not goals or "" in kinds:
        return False
    for items in ctx._eva_items_by_fn.get(fn) or []:
        for alarm in items if isinstance(items, list) else []:
            if isinstance(alarm, dict) and alarm.get("kind") in kinds and eva_alarm_in_file(alarm, file):
                return False
    return True


def _partial_contract_merge_job(task: dict, aid: str, report: dict | None, ctx: Ctx | None = None) -> dict | None:
    """
    Return a partial-merge spec when a stalled `prove` task has a sound, assigns-verified
    contract in its scratch overlay that did not fail the E-ACSL dynamic oracle, so callers
    can verify against the callee's contract while the callee itself remains `blocked`.

    A stalled `negotiate` task qualifies only on stronger evidence, because its contract was strengthened on a
    caller's request: the dynamic oracle must have passed, every unproven goal must be an RTE goal of the body
    (by kind, whatever bucket WP put it in), and Eva must have discharged those RTE kinds. A strengthened
    postcondition WP could not prove never merges.
    """
    kind = task.get("kind")
    if kind not in PROVER_KINDS or not isinstance(report, dict):
        return None
    if report.get("status") != "unproven_goals_remain":
        return None
    if not bool((report.get("soundness") or {}).get("ok")):
        return None
    if not workspace_overlay.assigns_verified_for_partial_merge(report):
        return None
    fn = str(task.get("function") or "")
    c_rel = norm_path(str(task.get("file") or ""))
    if not fn or not c_rel:
        return None
    guard_path = Path("agents") / aid / "scratch" / f"guard_{fn}.json"
    if kind == "negotiate":
        rte_goals = _unproven_rte_goals(report)
        if rte_goals is None or ctx is None or not _eva_backs_unproven_rte(ctx, c_rel, fn, rte_goals):
            return None
        guard_data = load_json_optional(guard_path, {}) or {} if guard_path.is_file() else {}
        if not isinstance(guard_data, dict) or guard_data.get("status") != "passed_dynamic_oracle":
            return None
        # A guardrail that never executed the function says nothing about its contract.
        reach = guard_data.get("reach") or {}
        if not reach.get("measured") or int((reach.get("functions") or {}).get(fn) or 0) <= 0:
            return None
    elif guard_path.is_file():
        guard_data = load_json_optional(guard_path, {}) or {}
        if isinstance(guard_data, dict) and guard_data.get("status") not in (None, "passed_dynamic_oracle"):
            return None
    scratch_c = Path("agents") / aid / "scratch" / "work" / c_rel
    if not scratch_c.is_file():
        return None
    try:
        c_text = scratch_c.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    has_contract = acsl_ast.has_function_contract(c_text, fn, is_header=False, path=c_rel)
    header_rel = norm_path(str(task.get("header") or ""))
    scratch_h = Path("agents") / aid / "scratch" / "work" / header_rel if header_rel else None
    if not has_contract and scratch_h is not None and scratch_h.is_file():
        # Public functions carry their contract on the header prototype.
        try:
            h_text = scratch_h.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        has_contract = acsl_ast.has_function_contract(h_text, fn, is_header=True, path=header_rel)
    if not has_contract:
        return None
    return {
        "task": task["id"],
        "prove_task": f"prove:{c_rel}#{fn}",
        "requeue_callers": list(task.get("callers") or []) if kind == "negotiate" else [],
        "agent_id": aid,
        "file": task["file"],
        "function": fn,
        "header": task.get("header"),
        "module": task["module"],
    }


def _job_sidecar(module: str | None) -> dict:
    """The sidecar a merge of `module` builds with (a link unit's: its harnesses' merged)."""
    return workspace_overlay.merged_sidecar(workspace_overlay.module_map_for(Path("workspace")), module)


def _merge_partial_prover(job: dict) -> dict:
    side = _job_sidecar(job["module"])
    try:
        return DEPS.merge_agent_overlay(
            Path.cwd(),
            job["agent_id"],
            "prover",
            c_file=job["file"],
            function=job["function"],
            header_file=job.get("header"),
            module=job["module"],
            sources=side.get("sources") or None,
            cppflags=side.get("cppflags") or "-I.",
            ldflags=side.get("ldflags") or "",
            allow_partial_wp=True,
        )
    except Exception as exc:
        return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}


def _restore_best_candidate(aid: str, out: dict) -> dict | None:
    """Put a stalled prover's best candidate back into its scratch tree; a failure never blocks its completion."""
    out["best_candidate"] = None
    try:
        out["best_candidate"] = DEPS.restore_best(Path("agents") / aid / "scratch")
    except Exception as exc:
        out["errors"].append(f"restore best candidate: {type(exc).__name__}: {exc}")
    return out["best_candidate"]


def _analysis_error_will_retry(task: dict, aid: str, res: dict) -> bool:
    """Whether the prover's last WP report is an analysis_error that still gets its retry."""
    if int(task.get("analysis_errors") or 0) + 1 >= MAX_ANALYSIS_ERRORS:
        return False
    src = _find_agent_wp_report(aid, res, task["function"])
    report = _load_report(src) if src is not None else None
    return report is not None and report.get("status") == "analysis_error"


def _complete_prover(
    state: dict, ctx: Ctx, task: dict, aid: str, res: dict, result_path: Path, out: dict
) -> dict | None:
    status = res["status"]
    out["result_status"] = status
    if status == "all_proven":
        # Never restored: the parent re-verifies on merge, and a last iteration that skipped the guardrail must not
        # be replaced by an older partial.
        task["state"] = "merge_queued"
        task["merge"] = {"agent_id": aid, "queued_at": utc_now(), "queued_ts": DEPS.now(), "analysis_retries": 0}
        _event(state, "merge_queued", task["id"], agent_id=aid)
        out["action"] = "queued_for_merge"
        return None
    # The retry comes first: exceeding the WP job limit is an analysis_error, so settling for the best candidate here
    # would make results depend on machine speed. The best candidate is for a task that ends without a proof.
    # Then the promoted report and the partial contract merge below come from it. Its report is at the default path,
    # so the result's evidence, which may name a report of the last iteration, must not take precedence.
    out["best_candidate"] = None
    restored = None if _analysis_error_will_retry(task, aid, res) else _restore_best_candidate(aid, out)
    report_rel, report = _promote_agent_wp(task, aid, {**res, "evidence": []} if restored else res, out["errors"])
    if report is not None and report_rel and report.get("status") == "analysis_error":
        _on_analysis_error(state, task, aid, report_rel, report, out)
        return None
    if task["kind"] == "negotiate":
        if res.get("fault_hypothesis"):
            # The callee's fault hypothesis is still worth verifying; its own strengthening requests are
            # not chained into further negotiations.
            copy = Path("agents") / aid / "artifacts" / "result.hypothesis.json"
            atomic_write_json(copy, {**res, "strengthening_requests": []})
            out["hypothesis"] = _try(
                out["errors"], "ingest-agent-hypothesis", DEPS.ingest_agent_hypothesis, copy, task["module"]
            )
        _resolve_negotiation(state, task, False, f"callee prover {aid} returned {status}", out)
        out["action"] = "negotiation_rejected"
        return _partial_contract_merge_job(task, aid, report, ctx)
    # A stalled report that claims all_proven is not parent-verified: never credit it.
    if report_rel and report and report.get("status") != "all_proven":
        out["ingest_wp"] = _try(out["errors"], "ingest-wp", DEPS.ingest_wp, [Path(report_rel)])
    before = {r.get("id") for r in _requests()}
    out["hypothesis"] = _try(
        out["errors"], "ingest-agent-hypothesis", DEPS.ingest_agent_hypothesis, result_path, task["module"]
    )
    _emit_negotiations(state, ctx, task, [r for r in _requests() if r.get("id") not in before], out)
    if not (report and report.get("wp_allocation_limitation") is True):
        _ensure_breaker(state, task, aid, report_rel, out)
    reason = f"prover {aid} returned {status}"
    if report and report.get("wp_cast_limitation"):
        # Goals only the unsound `Typed+cast` model discharges: a WP memory-model limit, not a weak contract.
        reason = f"wp_typed_cast_limit: remaining goals are not provable in WP Typed (pointer casts); {reason}"
    out["units"] = _park_units(task, aid, reason)
    _finish(state, task, "blocked", status, reason=reason)  # terminal: its callers are released
    out["action"] = "blocked"
    # A restored best candidate can be fully proved while the prover stalled on a later, stronger contract. It is not
    # credited above, but its callers still get its contract: the partial merge re-verifies it on the merged tree.
    if restored and report and report.get("status") == "all_proven":
        report = {**report, "status": "unproven_goals_remain"}
    return _partial_contract_merge_job(task, aid, report, ctx)


def _complete_architect(state: dict, task: dict, aid: str, res: dict, out: dict) -> dict | None:
    if res["status"] != "passed":
        _finish(state, task, "done", "failed", reason=res.get("notes"))
        out["action"] = "architect_failed"  # provers still proceed, with whatever contracts exist
        return None
    task["state"] = "merging"
    task["merge"] = {"agent_id": aid, "started_at": utc_now(), "started_ts": DEPS.now()}
    out["action"] = "merging"
    return {
        "task": task["id"],
        "agent_id": aid,
        "module": task["module"],
        "header": task.get("header") or res.get("header"),
    }


def _is_architect_analysis_error(merged: dict, task: dict, aid: str) -> bool:
    if merged.get("analysis_error") or merged.get("status") == "analysis_error":
        return True
    reason = str(merged.get("reason") or "").lower()
    if any(
        k in reason
        for k in (
            "analysis_error",
            "timed out",
            "timeout",
            "oom",
            "memory limit",
            "killed",
            "sandbox_unavailable",
            "rc=-9",
            "rc=137",
        )
    ):
        return True
    mod = task.get("module") or ""
    rep_path = Path("agents") / aid / "scratch" / f"parent_guard_{mod}.json"
    if rep_path.is_file():
        rep = load_json_optional(rep_path, {}) or {}
        if rep.get("status") in ("analysis_error", "sandbox_unavailable") or rep.get("timed_out"):
            return True
        if "analysis_error" in str(rep.get("reason") or "").lower():
            return True
    return False


def _merge_architect(job: dict) -> dict:
    side = _job_sidecar(job["module"])
    try:
        return DEPS.merge_agent_overlay(
            Path.cwd(),
            job["agent_id"],
            "architect",
            header_file=job["header"],
            module=job["module"],
            sources=side.get("sources") or None,
            cppflags=side.get("cppflags") or "-I.",
            ldflags=side.get("ldflags") or "",
        )
    except Exception as exc:  # a refused or crashed merge is an outcome, never a stuck task
        return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}


def _parent_replay(fp: str, cand: dict, out: dict) -> list[str]:
    """
    The parent's own replay reports for a candidate. Phase 2 replays only the candidates known then,
    so a Phase 3 candidate (breaker crash, reproduced hypothesis) gets its replay here, before its
    verdict is ingested: `ingest-verifier` confirms only reproducers the parent itself replayed.
    """
    replays = _replay_reports(fp, cand)
    if replays or not cand.get("reproducers"):
        return replays
    cmd = [
        sys.executable or "python3",
        str(Path(__file__).resolve().parent / "run_eacsl_fuzz.py"),
        "replay-candidates",
        "--candidates",
        "candidates.json",
        "--harness-dir",
        HARNESS_DIR.as_posix(),
        "--out-dir",
        REPLAY_DIR.as_posix(),
    ]
    try:
        proc = DEPS.run_cmd(cmd, capture_output=True, text=True, check=False, timeout=3600)
        out["parent_replay"] = {"returncode": getattr(proc, "returncode", None)}
    except (OSError, subprocess.SubprocessError) as exc:
        out["parent_replay"] = {"error": f"{type(exc).__name__}: {exc}"}
    return _replay_reports(fp, cand)


def _complete_verifier(state: dict, ctx: Ctx, task: dict, res: dict, result_path: Path, out: dict) -> None:
    fp = task["fingerprint"]
    replays = _parent_replay(fp, ctx.candidates.get(fp) or {}, out)
    harness_mod = _verify_harness_module(task, ctx)
    meta = HARNESS_DIR / f"harness_{harness_mod}.json"
    out["replay_reports"] = replays
    try:
        ing = DEPS.ingest_verifier(result_path, [Path(p) for p in replays], meta if meta.is_file() else None)
    except _TOLERATED as exc:
        task["ingest_errors"] = int(task.get("ingest_errors") or 0) + 1
        out["error"] = str(exc)
        if task["ingest_errors"] < MAX_INGEST_ERRORS:
            _reopen(state, task, f"ingest-verifier refused the result: {exc}")
            out["action"] = "requeued_ingest_error"
        else:
            # The candidate stays unverified (the run will be incomplete), but its gate opens.
            _finish(state, task, "blocked", "ingest_failed", reason=str(exc))
            out["action"] = "blocked_ingest_error"
        return
    records = [res.get("record") or {}, *(res.get("additional_records") or [])]
    harness_induced = any(
        r.get("verdict") == "rejected" and r.get("rejection_class") == "harness_induced" for r in records
    )
    if harness_induced and not ing.get("harness_exhausted"):
        # The harness to repair (`pipeline_make.py run module-<harness>`), never a bare link unit.
        _ensure_repair(state, harness_mod, f"harness_induced: {fp}", out)
    _finish(state, task, "done", str(ing.get("decision")))
    out.update(action="ingested", decision=ing.get("decision"), harness_exhausted=ing.get("harness_exhausted"))


def _complete_breaker(state: dict, task: dict, aid: str, res: dict, result_path: Path, out: dict) -> None:
    out["hypothesis"] = _try(
        out["errors"], "ingest-agent-hypothesis", DEPS.ingest_agent_hypothesis, result_path, task["module"]
    )
    if res["status"] == "crash_found":
        artifact = res.get("crash_artifact")
        if artifact and artifact not in (res.get("seeds") or []):
            # Promote the crashing input into the module corpus; repair:<module> is only created
            # when a verifier rejects a candidate as harness_induced.
            _try(
                out["errors"],
                "promote crash seed",
                promote_file,
                Path.cwd(),
                aid,
                artifact,
                kind="seed",
                # The corpus of the harness answering for the function (a link unit has several).
                module=workspace_overlay.harness_module_for_function(
                    workspace_overlay.module_map_for(Path("workspace")),
                    task["module"],
                    task.get("file"),
                    task.get("function"),
                ),
            )
    _finish(state, task, "done", res["status"])
    out["action"] = "ingested"
    out["result_status"] = res["status"]


def cmd_complete(agent_id: str) -> dict:
    """Validate agents/<id>/scratch/result.json and dispatch it by role (ledger functions in-process)."""
    merge_job: dict | None = None
    partial_merge_job: dict | None = None
    with run_lock("ledger"):
        state = load_schedule()
        tid = state["agents"].get(agent_id)
        task = state["tasks"].get(tid) if tid else None
        if task is None:
            raise SchedulerError(f"unknown agent id {agent_id!r}: it was not handed out by this scheduler")
        out: dict[str, Any] = {"ok": True, "agent_id": agent_id, "task": tid, "kind": task["kind"], "errors": []}
        if task["state"] == "pending" and task.get("requeued_from") == agent_id:
            # Requeued as stale but not re-dispatched yet: the late result is still welcome.
            task.update(state="running", agent_id=agent_id)
            task.pop("requeued_from", None)
            out["late_result"] = True
        elif task.get("agent_id") != agent_id:
            out.update(action="stale_agent", current_agent=task.get("agent_id"))
            return out
        elif task["state"] != "running":
            out.update(action="already_completed", state=task["state"])
            return out
        result_path = Path("agents") / agent_id / "scratch" / "result.json"
        res, errors = _load_result(result_path, task, agent_id)
        ctx = Ctx()
        if errors or res is None:
            _on_invalid_result(state, task, agent_id, errors or ["unreadable result"], out)
        elif task["kind"] in PROVER_KINDS:
            partial_merge_job = _complete_prover(state, ctx, task, agent_id, res, result_path, out)
        elif task["kind"] == "arch":
            merge_job = _complete_architect(state, task, agent_id, res, out)
        elif task["kind"] == "verify":
            _complete_verifier(state, ctx, task, res, result_path, out)
        else:
            _complete_breaker(state, task, agent_id, res, result_path, out)
        out["sync"] = _sync(state, Ctx())
        save_schedule(state)
    if partial_merge_job is not None:
        pmerged = _merge_partial_prover(partial_merge_job)
        out["partial_merge"] = pmerged
        if pmerged.get("ok"):
            with run_lock("ledger"):
                state = load_schedule()
                ptask = state["tasks"].get(partial_merge_job["task"])
                if ptask is not None and ptask["kind"] == "negotiate":
                    # The contract belongs to the callee's prove task, whose callers are already released.
                    ptask = state["tasks"].get(partial_merge_job.get("prove_task") or "") or ptask
                if ptask is not None:
                    ptask["partial_contract_merged"] = True
                    ptask["partial_merged_at"] = utc_now()
                    if pmerged.get("modified_files"):
                        out["rechecks_queued"] = _queue_rechecks_for(
                            state, ptask, f"partial contract of {_key(ptask)} merged from {agent_id}"
                        )
                    out["requeued_callers"] = [
                        c for c in partial_merge_job.get("requeue_callers") or [] if _requeue_caller(state, c)
                    ]
                    save_schedule(state)
    if merge_job is None:
        return out

    while merge_job is not None:
        merged = _merge_architect(merge_job)
        retry_needed = False
        with run_lock("ledger"):
            state = load_schedule()
            task = state["tasks"].get(merge_job["task"])
            if (
                task is None
                or task["state"] not in ("merging", "merge_queued")
                or (task.get("merge") or {}).get("agent_id") != agent_id
            ):
                out["errors"].append("the architect task changed while it was being merged")
                break
            if merged.get("ok"):
                _finish(state, task, "done", "merged")
                out.update(action="merged", modified_files=merged.get("modified_files") or [])
                arch_result = Path("agents") / agent_id / "scratch" / "result.json"
                if arch_result.is_file():
                    out["boundary_assumptions"] = _try(
                        out["errors"],
                        f"record-boundary-assumptions {task['id']}",
                        DEPS.record_boundary_assumptions,
                        arch_result,
                    )
                if merged.get("modified_files"):
                    out["rechecks_queued"] = _queue_rechecks_for_module(
                        state, Ctx(), task["module"], f"architect {agent_id} changed module contracts"
                    )
                out["sync"] = _sync(state, Ctx())
                save_schedule(state)
                break

            retries = int(task.get("analysis_retries") or (task.get("merge") or {}).get("analysis_retries") or 0)
            if _is_architect_analysis_error(merged, task, agent_id) and retries < MAX_ANALYSIS_ERRORS - 1:
                task["analysis_retries"] = retries + 1
                if task.get("merge"):
                    task["merge"]["analysis_retries"] = task["analysis_retries"]
                task["state"] = "merge_queued"
                out["action"] = "retry_merge"
                save_schedule(state)
                retry_needed = True

            if not retry_needed:
                _finish(state, task, "done", "merge_failed", reason=merged.get("reason"))
                out.update(action="merge_failed", reason=merged.get("reason"))
                out["sync"] = _sync(state, Ctx())
                save_schedule(state)
                break

        if retry_needed:
            with run_lock("ledger"):
                state = load_schedule()
                task = state["tasks"].get(merge_job["task"])
                if task:
                    task["state"] = "merging"
                    save_schedule(state)
            continue
    return out


# ---------------------------------------------------------------------------
# merge-pending and contract re-checks
# ---------------------------------------------------------------------------


def _add_recheck(state: dict, caller: dict, reason: str) -> str:
    rid = f"recheck:{_key(caller)}"
    entry = state["rechecks"].get(rid)
    if entry is not None and entry.get("state") == "running":
        entry["again"] = True  # the change landed after the running check read the tree
    elif entry is None:
        state["rechecks"][rid] = {
            "id": rid,
            "task": caller["id"],
            "reason": reason,
            "queued_at": utc_now(),
            "queued_ts": DEPS.now(),
            "retries": 0,
            "state": "queued",
        }
    return rid


def _merged_provers(state: dict) -> list[dict]:
    return [
        t
        for _, t in sorted(state["tasks"].items())
        if t["kind"] == "prove" and t["state"] == "done" and t.get("outcome") == "merged"
    ]


def _queue_rechecks_for(state: dict, merged: dict, reason: str) -> list[str]:
    """A merged contract changed: re-check the already-merged callers and recursion-group peers."""
    key = _key(merged)
    skip = {merged["id"], f"prove:{key}"}
    scc = merged.get("scc") if merged["kind"] == "prove" else None
    return [
        _add_recheck(state, c, reason)
        for c in _merged_provers(state)
        if c["id"] not in skip and (key in (c.get("callees") or []) or (scc and c.get("scc") == scc))
    ]


def _queue_rechecks_for_module(state: dict, ctx: Ctx, module: str, reason: str) -> list[str]:
    """An architect rewrote a module header: re-check merged functions of the module and their callers."""
    return [
        _add_recheck(state, c, reason)
        for c in _merged_provers(state)
        if c["module"] == module or any(ctx.key_module(k) == module for k in c.get("callees") or [])
    ]


def _waiting_caller_modules(state: dict, queued: set[str]) -> set[str]:
    """Modules with a queued result that a pending task would be ready without."""
    now_view = _View(state)
    if_merged = _View(state, assume_terminal=queued)
    tasks = state["tasks"]
    modules: set[str] = set()
    for task in tasks.values():
        if task["state"] != "pending" or now_view.ready(task) or not if_merged.ready(task):
            continue
        for member in now_view.group(task["id"]):
            for dep in _deps(tasks[member]):
                for other in now_view.group(dep) if dep in tasks else []:
                    if other in queued:
                        modules.add(tasks[other]["module"])
    return modules


def _merge_entry(task: dict) -> dict:
    entry = {
        "agent_id": task["merge"]["agent_id"],
        "role": "prover",
        "file": task["file"],
        "function": task["function"],
        "module": task["module"],
    }
    if task.get("header"):
        entry["header"] = task["header"]
    return entry


def _on_merged(state: dict, task: dict, aid: str, merged: dict, out: dict) -> None:
    rep = merged.get("parent_wp_report") or f"agents/{aid}/scratch/parent_wp/{task['function']}.json"
    rep_path = Path(rep)
    entry: dict[str, Any] = {"task": task["id"], "agent_id": aid}
    if rep_path.is_file():
        _try(out["errors"], f"ingest-wp {rep}", DEPS.ingest_wp, [rep_path])
        # The environment facts the merged proof relies on become assumptions of its units.
        result_path = Path("agents") / aid / "scratch" / "result.json"
        if result_path.is_file():
            _try(
                out["errors"],
                f"record-boundary-assumptions {task['id']}",
                DEPS.record_boundary_assumptions,
                result_path,
            )
        if any(state["tasks"].get(f"prove:{c}", {}).get("state") == "blocked" for c in (task.get("callees") or [])):
            _try(out["errors"], f"audit-hypotheses {task['id']}", DEPS.audit_hypotheses)
        entry["checkpoint"] = _try(out["errors"], f"checkpoint {task['id']}", DEPS.save_shard, task["slug"], rep_path)
        entry["parent_wp_report"] = rep_path.as_posix()
    else:
        out["errors"].append(f"{task['id']}: merged without a parent WP report")
    parked = _park_units(task, aid, "merged, but no WP goal was credited to this obligation class")
    entry["units_not_credited"] = parked["blocked"] + parked["planned"]
    task["merged_at"] = utc_now()
    task["parent_wp_report"] = entry.get("parent_wp_report")
    if task["kind"] == "negotiate":
        _resolve_negotiation(state, task, True, f"applied by {aid}; the parent WP re-check passed", out)
    else:
        _finish(state, task, "done", "merged")
    if merged.get("modified_files"):
        entry["rechecks_queued"] = _queue_rechecks_for(state, task, f"contract of {_key(task)} changed by {aid}")
    out["merged"].append(entry)


def _on_merge_failed(state: dict, task: dict, aid: str, failure: dict, out: dict) -> None:
    reason = str(failure.get("reason") or "merge failed")
    rep_path = Path(f"agents/{aid}/scratch/parent_wp/{task['function']}.json")
    report = _load_report(rep_path) if rep_path.is_file() else None
    entry: dict[str, Any] = {"task": task["id"], "agent_id": aid, "reason": reason}
    if report and report.get("status") == "analysis_error":
        if int(task["merge"].get("analysis_retries") or 0) < MAX_ANALYSIS_ERRORS - 1:
            # Retried by the next merge-pending call, in a fresh container with a larger lease.
            task["merge"]["analysis_retries"] = int(task["merge"].get("analysis_retries") or 0) + 1
            task["state"] = "merge_queued"
            entry["action"] = "retry_merge"
        else:
            _try(out["errors"], "ingest-wp", DEPS.ingest_wp, [rep_path])
            entry["units"] = _park_units(
                task, aid, f"analysis_error: the parent WP re-check did not complete twice ({report.get('reason')})"
            )
            if task["kind"] == "negotiate":
                _resolve_negotiation(
                    state, task, False, f"parent WP re-check did not complete ({report.get('reason')})", out
                )
            else:
                _finish(state, task, "blocked", "analysis_error", reason=reason)
            entry["action"] = "blocked_analysis_error"
        out["failed"].append(entry)
        return
    task["merge_attempts"] = int(task.get("merge_attempts") or 0) + 1
    if task["merge_attempts"] < MAX_MERGE_ATTEMPTS:
        entry["units_released"] = _release_units(task)
        _reopen(state, task, f"merge failed: {reason}")
        entry["action"] = "requeued"
    else:
        if report:
            _try(out["errors"], "ingest-wp", DEPS.ingest_wp, [rep_path])
        entry["units"] = _park_units(task, aid, f"merge_failed: {reason[:160]}")
        if task["kind"] == "negotiate":
            _resolve_negotiation(state, task, False, f"merge failed: {reason}", out)
        else:
            _finish(state, task, "blocked", "merge_failed", reason=reason)
        entry["action"] = "blocked"
    out["failed"].append(entry)


def _apply_merge_result(state: dict, entries: list[dict], res: dict, out: dict) -> None:
    tasks = state["tasks"]
    if res.get("error"):
        for e in entries:
            task = tasks.get(state["agents"].get(e["agent_id"], ""))
            if task and task["state"] == "merging":
                task["state"] = "merge_queued"
        out["errors"].append(res["error"])
        return
    merged = {m.get("agent_id"): m for m in res.get("merged") or []}
    failed = {f.get("agent_id"): f for f in res.get("failed") or []}
    for e in entries:
        aid = e["agent_id"]
        task = tasks.get(state["agents"].get(aid, ""))
        if task is None or task["state"] != "merging" or (task.get("merge") or {}).get("agent_id") != aid:
            continue
        if aid in merged:
            _on_merged(state, task, aid, merged[aid], out)
        else:
            _on_merge_failed(state, task, aid, failed.get(aid) or {"reason": "missing from the merge result"}, out)


def _apply_recheck(state: dict, job: dict, result: dict, out: dict) -> None:
    entry_state = state["rechecks"].get(job["id"])
    caller = state["tasks"].get(job["task"])
    if entry_state is None or caller is None:
        return
    rep = result.get("report")
    report = _load_report(rep) if rep else None
    entry: dict[str, Any] = {"recheck": job["id"], "task": caller["id"], "reason": result.get("reason")}
    if result.get("ok"):
        if rep:
            _try(out["errors"], f"ingest-wp {rep}", DEPS.ingest_wp, [Path(rep)])
        entry["action"] = "ok"
        if entry_state.get("again"):
            entry_state.update(state="queued", again=False)
        else:
            del state["rechecks"][job["id"]]
    elif (report is None or report.get("status") == "analysis_error") and int(entry_state.get("retries") or 0) < 1:
        entry_state.update(state="queued", retries=int(entry_state.get("retries") or 0) + 1)
        entry["action"] = "retry"
    else:
        if rep:
            _try(out["errors"], f"ingest-wp {rep}", DEPS.ingest_wp, [Path(rep)])
        del state["rechecks"][job["id"]]
        if caller["state"] == "done":
            entry["units"] = _block_covered_units(caller, f"recheck_failed: {str(result.get('reason') or '')[:160]}")
            _reopen(state, caller, f"contract re-check failed: {result.get('reason')}")
            entry["action"] = "reprove"
        else:
            entry["action"] = "dropped"
    out["rechecks"].setdefault(entry["action"], []).append(entry)


def _run_rechecks(module: str | None, out: dict) -> None:
    with run_lock("ledger"):
        state = load_schedule()
        now = DEPS.now()
        for entry in (state.get("rechecks") or {}).values():
            if entry.get("state") == "running" and (now - float(entry.get("started_ts") or now) >= 1800.0):
                entry["state"] = "queued"
        jobs = []
        for rid, entry in sorted(state["rechecks"].items()):
            caller = state["tasks"].get(entry.get("task", ""))
            if caller is None or caller["state"] != "done" or caller.get("outcome") != "merged":
                del state["rechecks"][rid]  # the function is being re-proved anyway
                continue
            if entry.get("state") != "queued" or (module and caller["module"] != module):
                continue
            entry.update(state="running", started_ts=now)
            jobs.append(
                {
                    "id": rid,
                    "task": caller["id"],
                    "file": caller["file"],
                    "function": caller["function"],
                    "module": caller["module"],
                    "agent_id": f"recheck-{caller['slug']}",
                }
            )
        save_schedule(state)
    if not jobs:
        return
    results = {}
    worker_cap = min(len(jobs), os.cpu_count() or 4, 16)
    with run_lock("merge"):
        with concurrent.futures.ThreadPoolExecutor(max_workers=worker_cap) as executor:
            future_to_job = {
                executor.submit(
                    DEPS.recheck_function,
                    Path.cwd().resolve(),
                    job["agent_id"],
                    job["file"],
                    job["function"],
                    job["module"],
                ): job
                for job in jobs
            }
            for fut in concurrent.futures.as_completed(future_to_job):
                job = future_to_job[fut]
                try:
                    results[job["id"]] = fut.result()
                except Exception as exc:  # treated like an analysis error: retried once, then a re-proof
                    results[job["id"]] = {"ok": False, "reason": f"{type(exc).__name__}: {exc}", "report": None}
    with run_lock("ledger"):
        state = load_schedule()
        for job in jobs:
            _apply_recheck(state, job, results[job["id"]], out)
        out["sync"] = _sync(state, Ctx())
        save_schedule(state)


def cmd_merge_pending(module: str | None = None, force: bool = False) -> dict:
    """
    Merge queued prover results per module when the module has no running prover, a ready caller waits
    on a queued callee, MERGE_BATCH_TRIGGER results are queued, the oldest waited MERGE_MAX_WAIT_S,
    or --force. Then ingest each parent WP report, save checkpoint shards and run contract re-checks.
    """
    out: dict[str, Any] = {
        "ok": True,
        "fired": [],
        "waiting": [],
        "merged": [],
        "failed": [],
        "rechecks": {},
        "errors": [],
    }
    jobs: list[tuple[str, list[dict]]] = []
    with run_lock("ledger"):
        state = load_schedule()
        tasks = state["tasks"]
        queued_all = {tid for tid, t in tasks.items() if t["state"] == "merge_queued"}
        by_module: dict[str, list[dict]] = defaultdict(list)
        for tid in sorted(queued_all):
            if module is None or tasks[tid]["module"] == module:
                by_module[tasks[tid]["module"]].append(tasks[tid])
        running_modules = {t["module"] for t in tasks.values() if t["state"] == "running" and t["kind"] in PROVER_KINDS}
        waiting_modules = _waiting_caller_modules(state, queued_all) if by_module else set()
        now = DEPS.now()
        for mod in sorted(by_module):
            items = sorted(by_module[mod], key=lambda t: (float(t["merge"].get("queued_ts") or now), t["id"]))
            oldest = now - float(items[0]["merge"].get("queued_ts") or now)
            reasons = [
                name
                for name, hit in (
                    ("forced", force),
                    ("no_running_provers", mod not in running_modules),
                    ("caller_waiting", mod in waiting_modules),
                    ("batch_full", len(items) >= MERGE_BATCH_TRIGGER),
                    ("max_wait", oldest >= MERGE_MAX_WAIT_S),
                )
                if hit
            ]
            if not reasons:
                out["waiting"].append({"module": mod, "queued": len(items), "oldest_s": round(oldest, 1)})
                continue
            for task in items:
                task["state"] = "merging"
                task["merge"].update(started_at=utc_now(), started_ts=now)
            jobs.append((mod, [_merge_entry(t) for t in items]))
            out["fired"].append({"module": mod, "reasons": reasons, "agents": [t["merge"]["agent_id"] for t in items]})
        save_schedule(state)

    results: dict[str, dict] = {}
    for mod, entries in jobs:  # outside the ledger lock: merges take the `merge` lock themselves
        try:
            results[mod] = DEPS.merge_agent_batch(Path.cwd(), entries)
        except Exception as exc:  # the results go back to the queue; nothing is lost
            results[mod] = {"error": f"merge-batch for {mod} raised {type(exc).__name__}: {exc}"}
    if jobs:
        with run_lock("ledger"):
            state = load_schedule()
            for mod, entries in jobs:
                _apply_merge_result(state, entries, results[mod], out)
            out["sync"] = _sync(state, Ctx())
            save_schedule(state)
    _run_rechecks(module, out)
    return out


def cmd_step(
    complete_ids: list[str] | None = None,
    slots: str | int = "auto",
    prepare: bool = False,
    max_agents: int | None = None,
    force_merge: bool = False,
    module: str | None = None,
) -> dict:
    """
    Atomically complete finished agents, eagerly merge pending provers, and dispatch next tasks.
    Enables a continuous reactive sliding-window loop without waiting for batch barriers.
    """
    completed: list[dict] = []
    errors: list[Any] = []
    for aid in complete_ids or []:
        try:
            res = cmd_complete(aid)
            completed.append(res)
            if res.get("errors"):
                errors.extend(res["errors"])
        except Exception as exc:
            errors.append(f"complete {aid} failed: {type(exc).__name__}: {exc}")
            completed.append({"ok": False, "agent_id": aid, "error": str(exc)})

    merge_out = cmd_merge_pending(module=module, force=force_merge)
    if merge_out.get("errors"):
        errors.extend(merge_out["errors"])

    next_out = cmd_next(slots=str(slots), prepare=prepare, max_agents=max_agents)
    if next_out.get("errors"):
        errors.extend(next_out["errors"])

    ok = not errors and merge_out.get("ok", True) and next_out.get("ok", True)
    return {
        "ok": ok,
        "completed": completed,
        "merge_pending": merge_out,
        "next": next_out,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# refresh / requeue / status
# ---------------------------------------------------------------------------


def cmd_refresh(module: str | None = None) -> dict:
    """After the parent repaired a harness (or re-ran a module): close repair:<module> and re-sync."""
    with run_lock("ledger"):
        state = load_schedule()
        out: dict[str, Any] = {"ok": True, "repair": None}
        task = state["tasks"].get(f"repair:{module}") if module else None
        if task is not None and task["state"] not in TERMINAL:
            if task.get("followup_reasons"):
                task["reasons"] = task.pop("followup_reasons")
                _reopen(state, task, "new reasons arrived during the repair")
                out["repair"] = "reopened"
            else:
                _finish(state, task, "done", "refreshed")
                out["repair"] = "done"
        out["sync"] = _sync(state, Ctx())
        save_schedule(state)
    return out


def cmd_requeue(agent_id: str | None = None, stale_minutes: float | None = None) -> dict:
    """Tasks whose agents never returned go back to ready; their units return to planned (CAS)."""
    with run_lock("ledger"):
        state = load_schedule()
        tasks = state["tasks"]
        now = DEPS.now()
        out: dict[str, Any] = {"ok": True, "requeued": [], "merges_requeued": []}
        if agent_id is not None:
            task = tasks.get(state["agents"].get(agent_id, ""))
            if task is None:
                raise SchedulerError(f"unknown agent id {agent_id!r}")
            if task.get("agent_id") != agent_id or task["state"] not in ("running", "merging"):
                out["note"] = f"{task['id']} is {task['state']} (agent {task.get('agent_id')}); nothing to requeue"
                return out
            targets = [task]
        else:
            limit = float(stale_minutes or 0) * 60.0
            targets = [
                t
                for _, t in sorted(tasks.items())
                if (t["state"] == "running" and now - float(t.get("assigned_ts") or now) >= limit)
                or (t["state"] == "merging" and now - float((t.get("merge") or {}).get("started_ts") or now) >= limit)
            ]
        for task in targets:
            if task["state"] == "merging":  # a merge-pending or complete that died mid-merge
                task["state"] = "merge_queued" if task["kind"] in PROVER_KINDS else "running"
                out["merges_requeued"].append(
                    {"task": task["id"], "agent_id": (task.get("merge") or {}).get("agent_id")}
                )
                continue
            released = _release_units(task)
            previous = task.get("agent_id")
            _reopen(state, task, f"requeued: agent {previous} never returned")
            task["requeued_from"] = previous  # its result, should it still arrive, is accepted
            out["requeued"].append({"task": task["id"], "agent_id": previous, "units_released": released})
        limit = float(stale_minutes or 0) * 60.0
        rechecks_requeued = []
        for rid, entry in list((state.get("rechecks") or {}).items()):
            if entry.get("state") == "running" and (now - float(entry.get("started_ts") or now) >= limit):
                entry["state"] = "queued"
                rechecks_requeued.append(rid)
        if rechecks_requeued:
            out["rechecks_requeued"] = rechecks_requeued
        save_schedule(state)
    return out


def cmd_status() -> dict:
    """Counts by state, ready and running tasks, the merge queue, gates and the remaining critical path."""
    with run_lock("ledger"):
        state = load_schedule()
        ctx = Ctx()
        _sync(state, ctx)  # in memory only: what `next` would see
    mode = scheduler_mode()
    tasks = state["tasks"]
    now = DEPS.now()
    ready = _ready(state, mode, ctx=ctx)
    view = _View(state, ctx=ctx)
    running = [
        {
            "task": t["id"],
            "kind": t["kind"],
            "agent_id": t.get("agent_id"),
            "age_s": round(now - float(t.get("assigned_ts") or now), 1),
            "wall_budget_s": int(t.get("wall_budget_s") or _agent_wall_budget_s()),
        }
        for _, t in sorted(tasks.items())
        if t["state"] == "running"
    ]
    over_budget = _over_budget_tasks(state, now)
    merge_queue = [
        {
            "task": t["id"],
            "state": t["state"],
            "module": t["module"],
            "agent_id": (t.get("merge") or {}).get("agent_id"),
            "age_s": round(now - float((t.get("merge") or {}).get("queued_ts") or now), 1),
        }
        for _, t in sorted(tasks.items())
        if t["state"] in ("merge_queued", "merging")
    ]
    gates = {}
    for gate_id, gate in sorted((state.get("gates") or {}).items()):
        mod = gate["module"]
        if not any(
            t["kind"] in ("prove", "arch") and t["module"] == mod and t["state"] not in TERMINAL for t in tasks.values()
        ):
            continue
        waiting_on = sorted(b for b in _gate_blockers(state, mod, view.index) if tasks[b]["state"] not in TERMINAL)
        gates[gate_id] = {"open": not waiting_on, "waiting_on": waiting_on}
    _, critical = _chain_heights(state, open_only=True)
    done = _is_done(state, ctx)
    out = {
        "ok": True,
        "mode": mode,
        **_summary(state),
        "ready": [
            {
                "task": t["id"],
                "kind": t["kind"],
                "height": int(t.get("height") or 0),
                "eva_unknowns": int(t.get("eva_unknowns") or 0),
            }
            for t in ready
        ],
        "running": running,
        "over_budget_tasks": over_budget,
        "merge_queue": merge_queue,
        "rechecks": sorted(state.get("rechecks") or {}),
        "gates": gates,
        "critical_path": critical,
        "done": done,
    }
    out["stuck"] = not done and not ready and not running and not merge_queue and not state.get("rechecks")
    return out


def _matches_exclude(file_path: str, patterns: list[str]) -> bool:
    norm_file = norm_path(file_path)
    file_name = Path(norm_file).name
    for pat in patterns:
        norm_pat = norm_path(pat)
        if norm_file == norm_pat or norm_file.endswith("/" + norm_pat.lstrip("/")):
            return True
        if fnmatch.fnmatch(norm_file, norm_pat) or fnmatch.fnmatch(file_name, norm_pat):
            return True
        if fnmatch.fnmatch(norm_file, f"*/{norm_pat}"):
            return True
    return False


def cmd_baseline(
    run_dir: Path | str = ".",
    jobs: int | None = None,
    recheck_all: bool = False,
) -> dict:
    """
    Mechanical Phase-3 WP baseline wave using a rolling ThreadPoolExecutor pool.
    Pulls tasks from workspace/reports/wp_queue.json (or state/wp_schedule.json),
    filters tasks matching module wp_exclude_files, skips already proven tasks (unless recheck_all),
    runs each task via resources.py run --class wp --key <module>:<file>#<fn> -- run_wp_function.py ...,
    passes wp_extra_sources if configured, and incrementally ingests results into ledger under run_lock("ledger").
    """
    run_dir = Path(run_dir).resolve()
    scripts_dir = Path(__file__).resolve().parent
    py = sys.executable or "python3"
    resources_py = str(scripts_dir / "resources.py")
    run_wp_py = str(scripts_dir / "run_wp_function.py")
    work_dir = run_dir / "workspace" / "work"

    rec_jobs = DEPS.recommend().get("make_jobs") or DEPS.recommend().get("max_agents") or 4
    max_workers = int(jobs) if jobs and int(jobs) > 0 else int(rec_jobs)
    max_workers = max(1, max_workers)

    raw_tasks: list[dict] = []
    if (run_dir / WP_QUEUE).is_file():
        q_data = load_json_strict(run_dir / WP_QUEUE)
        raw_tasks = list(q_data.get("queue") or [])
    elif (run_dir / SCHEDULE).is_file():
        s_data = load_json_strict(run_dir / SCHEDULE)
        raw_tasks = [t for t in s_data.get("tasks", {}).values() if t.get("kind") == "prove"]
    else:
        with run_lock("ledger", run_dir):
            cmd_init()
        if (run_dir / WP_QUEUE).is_file():
            raw_tasks = list(load_json_strict(run_dir / WP_QUEUE).get("queue") or [])

    params_doc = load_json_optional(run_dir / "workspace" / "build" / "params.json", None)
    if params_doc is None:
        params_doc = load_json_optional(run_dir / "build" / "params.json", {})
    modules_params = params_doc.get("modules", {}) if isinstance(params_doc, dict) else {}
    sweep_mm = workspace_overlay.module_map_for(run_dir / "workspace")

    filtered: list[dict] = []
    skipped_proven: list[dict] = []
    to_run: list[dict] = []

    for t in raw_tasks:
        tid = t.get("task") or t.get("id") or ""
        c_file = t.get("file")
        fn = t.get("function")
        mod = t.get("module") or "unknown"
        if not c_file or not fn:
            continue

        mod_params = dict(modules_params.get(mod) or {})
        for key in ("wp_exclude_files", "wp_extra_sources"):
            if key not in mod_params:  # a link unit: its harnesses' entries
                vals = workspace_overlay.module_param(modules_params, sweep_mm, mod, key)
                if vals is not None:
                    mod_params[key] = vals
        exclude_pats = mod_params.get("wp_exclude_files", [])
        if _matches_exclude(c_file, exclude_pats):
            filtered.append({"task": tid, "file": c_file, "function": fn, "module": mod, "reason": "wp_exclude_files"})
            continue

        if not recheck_all:
            wp_rep_path = run_dir / "workspace" / "reports" / "wp" / f"{fn}.json"
            if not wp_rep_path.is_file():
                wp_rep_path = run_dir / "reports" / "wp" / f"{fn}.json"
            is_proven = False
            if wp_rep_path.is_file():
                try:
                    rdata = json.loads(wp_rep_path.read_text(encoding="utf-8"))
                    if rdata.get("status") == "all_proven":
                        is_proven = True
                except Exception:
                    pass
            if not is_proven and t.get("state") == "done" and t.get("outcome") in ("all_proven", "merged"):
                is_proven = True
            if is_proven:
                skipped_proven.append(
                    {"task": tid, "file": c_file, "function": fn, "module": mod, "reason": "already_proven"}
                )
                continue

        to_run.append(
            {
                "task_id": tid,
                "file": c_file,
                "function": fn,
                "module": mod,
                "mod_params": mod_params,
            }
        )

    # Update filtered tasks in state if any
    if filtered:
        with run_lock("ledger", run_dir):
            state = load_schedule()
            changed = False
            for f_item in filtered:
                t_obj = state.get("tasks", {}).get(f_item["task"])
                if t_obj and t_obj.get("state") != "skipped":
                    _finish(state, t_obj, "skipped", "wp_exclude_files", reason="filtered by wp_exclude_files")
                    changed = True
            if changed:
                save_schedule(state)
                _write_wp_queue(state)

    task_plans: list[dict] = []
    for item in to_run:
        tid = item["task_id"]
        c_file = item["file"]
        fn = item["function"]
        mod = item["module"]
        mod_params = item["mod_params"]

        norm_c = norm_path(c_file)
        c_file_path = (work_dir / norm_c) if (work_dir / norm_c).is_file() else (run_dir / norm_c)
        hmeta = workspace_overlay.merged_sidecar(sweep_mm, mod)
        if not hmeta:
            hmeta = load_json_optional(run_dir / "harnesses" / f"harness_{mod}.json", {})
        cppflags = (hmeta.get("cppflags") if isinstance(hmeta, dict) else None) or "-I."
        extra_sources = mod_params.get("wp_extra_sources", [])

        slug = _slugify(c_file)
        out_dir = run_dir / "workspace" / "reports" / "wp" / "work" / f"{slug}_{fn}"
        out_json = run_dir / "workspace" / "reports" / "wp" / f"{fn}.json"
        key = f"{mod}:{c_file}#{fn}"

        cmd = [
            py,
            resources_py,
            "run",
            "--class",
            "wp",
            "--key",
            key,
            "--output",
            str(out_json),
            "--",
            py,
            run_wp_py,
            "--file",
            str(c_file_path),
            "--function",
            fn,
            "--out-dir",
            str(out_dir),
            f"--cppflags={cppflags}",
            "--wp-par",
            "auto",
            "--sarif",
            "--out-json",
            str(out_json),
        ]
        if extra_sources:
            cmd.extend(["--extra-sources", *extra_sources])

        task_plans.append(
            {
                "task_id": tid,
                "file": c_file,
                "function": fn,
                "module": mod,
                "out_dir": out_dir,
                "out_json": out_json,
                "cmd": cmd,
            }
        )

    def _run_single(plan: dict) -> dict:
        plan["out_dir"].mkdir(parents=True, exist_ok=True)
        if plan["out_json"].is_file():
            try:
                plan["out_json"].unlink()
            except OSError:
                pass
        proc = DEPS.run_cmd(
            plan["cmd"],
            cwd=str(run_dir),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        report = load_json_optional(plan["out_json"], None)
        status = (report.get("status") if isinstance(report, dict) else None) or (
            "failed" if getattr(proc, "returncode", 0) != 0 else "no_report"
        )
        return {
            "task_id": plan["task_id"],
            "function": plan["function"],
            "file": plan["file"],
            "module": plan["module"],
            "out_json": plan["out_json"],
            "returncode": getattr(proc, "returncode", 0),
            "status": status,
            "report": report,
        }

    results: list[dict] = []
    if task_plans:
        workers = min(max_workers, len(task_plans))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_to_plan = {pool.submit(_run_single, p): p for p in task_plans}
            for future in as_completed(future_to_plan):
                res = future.result()
                results.append(res)
                out_json_path = res["out_json"]

                with run_lock("ledger", run_dir):
                    # Only a full proof reaches the ledger: a baseline that fails on code without
                    # contracts is the prover's starting point, not a verdict that blocks its units.
                    if out_json_path.is_file() and res["status"] == "all_proven":
                        try:
                            DEPS.ingest_wp([out_json_path])
                        except Exception as exc:
                            res["ingest_error"] = str(exc)

                    state = load_schedule()
                    task_obj = state.get("tasks", {}).get(res["task_id"])
                    if task_obj:
                        status_str = res["status"]
                        raw_rep = res.get("report")
                        rep_dict: dict[str, Any] = raw_rep if isinstance(raw_rep, dict) else {}
                        rep_reason = rep_dict.get("reason")
                        if status_str == "analysis_error":
                            task_obj["analysis_errors"] = int(task_obj.get("analysis_errors") or 0) + 1
                            if task_obj["analysis_errors"] >= MAX_ANALYSIS_ERRORS:
                                _finish(
                                    state, task_obj, "blocked", "analysis_error", reason=rep_reason or "analysis_error"
                                )
                            else:
                                task_obj["state"] = "pending"
                        elif status_str == "all_proven" and not res.get("ingest_error"):
                            # The work tree itself is proven, as after a merge: the outcome keeps the
                            # function in the re-check set when a callee contract changes later.
                            _finish(state, task_obj, "done", "merged", reason="baseline: all_proven")
                        else:
                            # Not proven by the baseline: the task stays open for a prover.
                            task_obj["state"] = "pending"
                            task_obj["baseline"] = {"status": status_str, "report": out_json_path.as_posix()}
                        save_schedule(state)
                        _write_wp_queue(state)

    proven_count = sum(1 for r in results if r["status"] == "all_proven")
    unproven_count = sum(1 for r in results if r["status"] in ("unproven", "partial_proof"))
    errors_count = sum(
        1
        for r in results
        if r["status"] in ("analysis_error", "failed", "no_report", "wp_aborted", "acsl_syntax_error")
    )

    summary = {
        "ok": True,
        "total_tasks": len(raw_tasks),
        "filtered": len(filtered),
        "already_proven": len(skipped_proven),
        "executed": len(results),
        "proven": proven_count,
        "unproven": unproven_count,
        "errors": errors_count,
        "filtered_tasks": filtered,
        "already_proven_tasks": skipped_proven,
        "results": [
            {
                "task": r["task_id"],
                "file": r["file"],
                "function": r["function"],
                "module": r["module"],
                "status": r["status"],
                "returncode": r["returncode"],
            }
            for r in results
        ],
    }
    (run_dir / WP_BASELINE).parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(run_dir / WP_BASELINE, summary)
    return summary


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Phase-3 ready-queue scheduler (run from the run directory).")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_init = sub.add_parser("init", help="Build the task graph and write workspace/reports/wp_queue.json")
    p_init.add_argument(
        "--reconcile",
        action="store_true",
        help="Adopt an existing run: orphaned in_progress units back to planned; report stale briefs",
    )
    p_base = sub.add_parser("baseline", help="Mechanical Phase-3 WP baseline wave using a rolling worker pool")
    p_base.add_argument("--run-dir", type=Path, default=Path("."), help="Run directory (default: .)")
    p_base.add_argument("--jobs", type=int, default=None, help="Number of concurrent workers (default: recommend)")
    p_base.add_argument("--recheck-all", action="store_true", help="Recheck tasks already proven")
    p_next = sub.add_parser("next", help="Hand out the highest-priority ready tasks")
    p_next.add_argument("--slots", default="auto", help="'auto' (recommend().max_agents minus running) or a number")
    p_next.add_argument("--prepare", action="store_true", help="Prepare overlays and briefs, claim prover units (CAS)")
    p_next.add_argument("--max-agents", type=int, default=None, help="Cap for --slots auto (else FRAMAC_MAX_AGENTS)")
    p_step = sub.add_parser(
        "step", help="Atomically complete agents, eagerly merge pending provers, and dispatch next tasks"
    )
    p_step.add_argument("--complete", nargs="*", default=None, help="Agent IDs to complete")
    p_step.add_argument("--slots", default="auto", help="'auto' (recommend().max_agents minus running) or a number")
    p_step.add_argument("--prepare", action="store_true", help="Prepare overlays and briefs, claim prover units (CAS)")
    p_step.add_argument("--max-agents", type=int, default=None, help="Cap for --slots auto (else FRAMAC_MAX_AGENTS)")
    p_step.add_argument("--force-merge", action="store_true", help="Force immediate merge of queued provers")
    p_step.add_argument("--module", default=None, help="Restrict merge-pending to this module")
    p_comp = sub.add_parser("complete", help="Validate one agent result and dispatch it by role")
    p_comp.add_argument("--agent-id", required=True)
    p_merge = sub.add_parser("merge-pending", help="Merge queued prover results in micro-batches; run re-checks")
    p_merge.add_argument("--module", default=None)
    p_merge.add_argument("--force", action="store_true")
    p_ref = sub.add_parser("refresh", help="Re-sync after a harness repair or module re-run")
    p_ref.add_argument("--module", default=None)
    p_req = sub.add_parser("requeue", help="Put tasks whose agents never returned back in the queue")
    group = p_req.add_mutually_exclusive_group(required=True)
    group.add_argument("--agent-id", default=None)
    group.add_argument("--stale-minutes", type=float, default=None)
    sub.add_parser("status", help="Counts, ready/running tasks, gates and the remaining critical path")
    args = parser.parse_args(argv)

    try:
        if args.cmd == "init":
            # Phase 3 never starts on a failed or stale Phase 0 gate, whoever calls init (wp-queue
            # checks it too, with the plan's module lists).
            gate_reasons = phase0_gates.check(Path("."))
            if gate_reasons:
                print(json.dumps({"ok": False, "error": "Phase 0 gate", "reasons": gate_reasons}, indent=2))
                return 1
            out = cmd_init(args.reconcile)
        elif args.cmd == "baseline":
            out = cmd_baseline(run_dir=args.run_dir, jobs=args.jobs, recheck_all=args.recheck_all)
        elif args.cmd == "next":
            slots = str(args.slots).strip().lower()
            if slots != "auto" and not slots.isdigit():
                raise SchedulerError(f"--slots must be 'auto' or a non-negative integer, got {args.slots!r}")
            out = cmd_next(slots, args.prepare, args.max_agents)
        elif args.cmd == "step":
            slots = str(args.slots).strip().lower()
            if slots != "auto" and not slots.isdigit():
                raise SchedulerError(f"--slots must be 'auto' or a non-negative integer, got {args.slots!r}")
            out = cmd_step(
                complete_ids=args.complete,
                slots=slots,
                prepare=args.prepare,
                max_agents=args.max_agents,
                force_merge=args.force_merge,
                module=args.module,
            )
        elif args.cmd == "complete":
            out = cmd_complete(args.agent_id)
        elif args.cmd == "merge-pending":
            out = cmd_merge_pending(args.module, args.force)
        elif args.cmd == "refresh":
            out = cmd_refresh(args.module)
        elif args.cmd == "requeue":
            out = cmd_requeue(args.agent_id, args.stale_minutes)
        else:
            out = cmd_status()
    except (SchedulerError, ledger.LedgerError, ArtifactError, RunLockTimeout) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        return 1
    print(json.dumps(out, indent=2))
    return 0 if out.get("ok", True) else 1


if __name__ == "__main__":
    sys.exit(main())
