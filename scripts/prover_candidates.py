#!/usr/bin/env python3
"""
A Function Prover keeps its best candidate, not its last iteration.

Every prover iteration runs two oracles on agents/<id>/scratch/work/: WP (run_wp_function.py, report
scratch/wp_<fn>.json) and the E-ACSL guardrail (run_eacsl_fuzz.py guardrail, report scratch/guard_<fn>.json).
The oracles record themselves here, so nothing relies on an LLM remembering what it tried, and the parent
(wp_scheduler.py complete) restores the best candidate of a prover that did not finish.

A candidate is identified by the sha256 of the tracked files in scratch/work/: the `file` and the optional
`header` of scratch/.prover_budget.json. It is evaluated once both oracles have reported on the same digest, in
either order or in parallel. Only candidates that pass the guardrail are compared, because a stronger `requires`
can raise the proof ratio by excluding inputs. The rank is (failed goals, invalid invariants, trivial clauses added,
-effective proved goals), lower is better: a clause the prover added that holds whatever the code does (`\\true`,
`x == x`, `1 <= 2`; acsl_ast.is_trivial_predicate) earns no credit, so it can neither win a tie nor count as progress.
FRAMAC_CANDIDATE_RANK=legacy restores the earlier (failed, invalid, -proved) rank and progress test.

State, under agents/<id>/scratch/candidates/:
  state.json   the best candidate, the candidates seen, and one history entry per recorded oracle run
  c<n>/        the latest report of each oracle on candidate n
  best/        work/<rel>, wp_<fn>.json and guard_<fn>.json of the best candidate
  last/        what restore_best replaced in scratch/ (for example the code_fault report of the last iteration)

CLI (run from the run directory; each prints one JSON object):
  restore-best --agent-id ID    put the best candidate back into scratch/
  status       --agent-id ID    the best candidate and the history
"""

from __future__ import annotations

import argparse
import contextlib
import difflib
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from acsl_ast import (  # noqa: E402
    _parse_acsl_inner_segments,
    added_top_level_acsl_declarations,
    is_trivial_predicate,
    tokenize_c_acsl,
)
from framac_common import (  # noqa: E402
    ArtifactError,
    atomic_write_json,
    is_safe_agent_id,
    is_safe_relative_path,
    load_json_optional,
    run_lock,
    utc_now,
)

SCHEMA_VERSION = 1
BUDGET_FILE = ".prover_budget.json"
CANDIDATES_DIR = "candidates"
STATE_FILE = f"{CANDIDATES_DIR}/state.json"
BEST_DIR = f"{CANDIDATES_DIR}/best"
LAST_DIR = f"{CANDIDATES_DIR}/last"
STAGED_DIR = f"{CANDIDATES_DIR}/.best.new"
RETIRED_DIR = f"{CANDIDATES_DIR}/.best.old"

GUARDRAIL_PASSED = "passed_dynamic_oracle"
COMPARABLE_WP_STATUSES = frozenset({"all_proven", "unproven_goals_remain"})
# Verdicts against the annotations themselves. An oracle that merely failed to run (killed, compile error,
# no sandbox) decides nothing about them.
GUARDRAIL_REFUTATIONS = frozenset({"rejected_overconstrained", "code_fault"})
WP_STATUSES_WITH_SOUNDNESS_VERDICT = frozenset({"unsound_proof", "unproven_goals_remain"})
NO_PROGRESS_FOCUS = "no_progress_restore_best_and_finish"
# The candidate adds top-level ACSL declarations outside the function: merge-agent refuses the whole patch.
SCOPE_VIOLATION_FOCUS = "remove_top_level_acsl_declarations"
DROP_TRIVIAL_FOCUS = "drop_trivial_clauses"

# A/B switch for the rank: "legacy" restores (failed, invalid, -proved); anything else is trivial-aware.
RANK_MODE_ENV = "FRAMAC_CANDIDATE_RANK"
LEGACY_RANK = "legacy"
# Clauses whose goals inflate `proved` when their predicate holds whatever the code does. `requires` is left out: a
# trivial precondition adds no goal of the function's own, and dropping it changes nothing.
TRIVIAL_CANDIDATE_KINDS = frozenset({"ensures", "assert", "check", "invariant", "loop invariant"})
MAX_TRIVIAL_CLAUSES_KEPT = 20
_CLAUSE_HEAD_RE = re.compile(
    r"^\s*(?P<kind>loop\s+invariant|ensures|assert|check|invariant)\b\s*"
    r"(?:[A-Za-z_][A-Za-z0-9_]*\s*:(?!:)\s*)*(?P<pred>.*?)\s*;?\s*$",
    re.DOTALL,
)

# Far above what a holder needs (milliseconds), and above the 120 s after which run_lock breaks a dead holder's lock.
LOCK_TIMEOUT_S = 300.0
LOCK_NAME = "candidates"
# run_wp_function.py rewrites the budget file in place at the start of a run; a parallel oracle can read it torn.
BUDGET_READ_ATTEMPTS = 5
BUDGET_READ_RETRY_S = 0.05

_FUNCTION_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_REPORT_PREFIX = {"wp": "wp", "guardrail": "guard"}

# run_lock is reentrant within a process, so it does not separate threads.
_thread_lock = threading.Lock()


@contextlib.contextmanager
def _locked(scratch: Path) -> Iterator[None]:
    with _thread_lock, run_lock(LOCK_NAME, run_dir=scratch, timeout=LOCK_TIMEOUT_S):
        yield


def _report_name(oracle: str, function: str) -> str:
    return f"{_REPORT_PREFIX[oracle]}_{function}.json"


def _scratch_of(out_json: Path | str) -> Path | None:
    """The agents/<id>/scratch directory that directly contains `out_json`, or None."""
    scratch = Path(os.path.abspath(out_json)).parent
    if scratch.name != "scratch" or scratch.parent.parent.name != "agents":
        return None
    return scratch if is_safe_agent_id(scratch.parent.name) else None


def _load_budget(scratch: Path) -> dict | None:
    path = scratch / BUDGET_FILE
    for attempt in range(BUDGET_READ_ATTEMPTS):
        if attempt:
            time.sleep(BUDGET_READ_RETRY_S)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            continue
        return data if isinstance(data, dict) else None
    return None


def _tracked_rels(budget: dict) -> list[str] | None:
    """The budget's `file` and optional `header`, relative to scratch/work; None when they are not safe paths."""
    rels: list = [budget.get("file")]
    if budget.get("header"):
        rels.append(budget["header"])
    if not all(is_safe_relative_path(rel) for rel in rels):
        return None
    return sorted(set(rels))


def _has_symlink(scratch: Path, rel: str) -> bool:
    path = scratch
    for part in rel.split("/"):
        path = path / part
        if path.is_symlink():
            return True
    return False


def _read_regular(scratch: Path, rel: str) -> bytes | None:
    """The bytes of scratch/<rel>; None when it is absent, not a regular file, or reached through a symlink."""
    path = scratch / rel
    if _has_symlink(scratch, rel) or not path.is_file():
        return None
    try:
        return path.read_bytes()
    except OSError:
        return None


def _refuse_symlinked_parents(scratch: Path, rel: str) -> None:
    parent_rel = rel.rpartition("/")[0]
    if parent_rel and _has_symlink(scratch, parent_rel):
        raise ArtifactError(f"symlink along {rel} under {scratch}")


def _write_under(scratch: Path, rel: str, blob: bytes) -> None:
    """Write scratch/<rel> atomically. restore_best runs as the parent: a symlink is replaced, never followed."""
    _refuse_symlinked_parents(scratch, rel)
    dest = scratch / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    # Not a source suffix: a leftover temporary must not read as a new file of the overlay.
    fd, tmp = tempfile.mkstemp(dir=str(dest.parent), prefix=".tmp_", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(blob)
        os.replace(tmp, dest)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _report_bytes(report: dict) -> bytes:
    """The bytes the oracles write for a report."""
    return (json.dumps(report, indent=2) + "\n").encode("utf-8")


def _read_tracked(scratch: Path, budget: dict) -> dict[str, bytes | None] | None:
    """The tracked files in scratch/work; None when no candidate can be identified (a missing header is a state)."""
    rels = _tracked_rels(budget)
    if rels is None:
        return None
    contents = {rel: _read_regular(scratch, f"work/{rel}") for rel in rels}
    return contents if contents[str(budget["file"])] is not None else None


def _digest(contents: dict[str, bytes | None]) -> str:
    h = hashlib.sha256()
    for rel in sorted(contents):
        data = contents[rel]
        h.update(rel.encode("utf-8") + b"\0")
        h.update(b"absent\0" if data is None else b"%d\0" % len(data) + data)
    return h.hexdigest()


def tracked_digest(scratch: Path) -> str | None:
    """Identity of the candidate currently in scratch/work; None without a budget or the tracked source file."""
    scratch = Path(scratch)
    budget = _load_budget(scratch)
    contents = _read_tracked(scratch, budget) if budget is not None else None
    return _digest(contents) if contents is not None else None


def digest_before_run(out_json: Path | str) -> str | None:
    """For an oracle to call before running: the digest of the prover scratch `out_json` is in. Never raises."""
    try:
        scratch = _scratch_of(out_json)
        return tracked_digest(scratch) if scratch is not None else None
    except Exception:
        return None


def top_level_additions(scratch: Path, budget: dict) -> list[str]:
    """
    `"<kind> <name>"` for each top-level ACSL declaration (ghost function, predicate, lemma, ...) that scratch/work
    adds over the pristine scratch/base in the tracked files. merge-agent refuses such a patch (prover brief, Step B: Inductive Lemmas).
    Fail-open: any error gives [].
    """
    try:
        rels = _tracked_rels(budget)
        if rels is None:
            return []
        pending: list[str] = []
        for rel in rels:
            work = _read_regular(scratch, f"work/{rel}")
            if work is None:
                continue
            base = _read_regular(scratch, f"base/{rel}") or b""
            pending.extend(
                added_top_level_acsl_declarations(
                    base.decode("utf-8", "surrogateescape"), work.decode("utf-8", "surrogateescape"), path=rel
                )
            )
        return pending
    except Exception:
        return []


def _new_state(scratch: Path, function: str | None) -> dict:
    return {
        "schema": SCHEMA_VERSION,
        "agent_id": scratch.parent.name,
        "function": function,
        "next_id": 1,
        "best": None,
        "best_digest": None,
        "best_rank": None,
        "best_files": None,
        "candidates": {},
        "history": [],
    }


def _load_state(scratch: Path) -> dict | None:
    state = load_json_optional(scratch / STATE_FILE, None)
    if state is None:
        return None
    if not isinstance(state, dict) or state.get("schema") != SCHEMA_VERSION:
        raise ArtifactError(f"{scratch / STATE_FILE}: not a schema {SCHEMA_VERSION} candidates state")
    return state


# What state.json keeps of a refuting guardrail's `failure` (run_eacsl_fuzz.parse_eacsl_failure): no file paths.
FAILURE_KEYS = ("function", "line", "kind", "label", "predicate", "annotation_rte", "is_rte")


def _trim_failure(failure: object) -> dict | None:
    if not isinstance(failure, dict):
        return None
    return {k: failure[k] for k in FAILURE_KEYS if k in failure}


def _oracle_summary(oracle: str, report: dict) -> dict:
    if oracle == "guardrail":
        if report.get("status") in GUARDRAIL_REFUTATIONS:
            return {
                "status": report.get("status"),
                "reason": report.get("reason"),
                "failure": _trim_failure(report.get("failure")),
            }
        return {"status": report.get("status")}
    summary = {
        "status": report.get("status"),
        "failed": None,
        "proved": None,
        "soundness_ok": (report.get("soundness") or {}).get("ok") is True,
    }
    failed, proven = report.get("unproven_count"), report.get("proven_count")
    under_hyp = report.get("proven_under_hyp_count")
    if isinstance(failed, int) and isinstance(proven, int) and isinstance(under_hyp, int):
        summary.update(failed=failed, proved=proven + under_hyp)
    # Goals failing establishment/preservation are INVALID invariants (SESpec's largest-valid-
    # subset rule): a candidate whose failures are only provability is closer to done than one
    # carrying invalid invariants, so count them for the rank tiebreak.
    summary["invalid"] = sum(
        1
        for g in report.get("unproven_goals") or []
        if re.search(r"_(established|preserved)$", str(g.get("annotation") or ""), re.IGNORECASE)
    )
    return summary


def _acsl_tokens(data: bytes | None) -> list[tuple[str, int]]:
    """(text, line) of every ACSL annotation token in `data`; raises on a tokenizer error."""
    if data is None:
        return []
    source = data.decode("utf-8", "surrogateescape")
    return [(t.text, t.line) for t in tokenize_c_acsl(source) if t.kind in ("acsl_block", "acsl_line")]


def _added_acsl_texts(base: bytes | None, work: bytes | None) -> list[tuple[str, int]]:
    """
    (text, line) of the ACSL tokens of `work` whose text is not an ACSL token of `base`: the annotations the prover
    added or changed (the baseline idea of verify_acsl_only). Fail-open: a tokenizer error means none.
    """
    try:
        base_texts = {text for text, _ in _acsl_tokens(base)}
        return [(text, line) for text, line in _acsl_tokens(work) if text not in base_texts]
    except Exception:
        return []


def _acsl_inner(text: str) -> str:
    if text.startswith("/*@"):
        return text[3:-2] if text.endswith("*/") else text[3:]
    return text[3:] if text.startswith("//@") else text


def trivial_added_clauses(scratch: Path, budget: dict, contents: dict[str, bytes | None]) -> list[dict]:
    """
    The clauses the prover added to its tracked files (scratch/work vs the pristine scratch/base) whose predicate holds
    whatever the code does: [{"file", "line", "kind", "predicate"}]. Syntactic, like trivial_layer_clauses in the WP
    report: semantic tautologies are missed, and anything the detector cannot see through counts as real.
    """
    del budget  # the tracked files are the keys of `contents`; kept for symmetry with the other budget readers
    found: list[dict] = []
    for rel in sorted(contents):
        if not is_safe_relative_path(rel):
            continue
        for text, line in _added_acsl_texts(_read_regular(scratch, f"base/{rel}"), contents[rel]):
            try:
                segments = _parse_acsl_inner_segments(_acsl_inner(text), line)
            except Exception:
                continue
            for seg in segments:
                # Continuation lines of a block may start with `@`, which is not part of the predicate.
                raw = " ".join(seg.raw_text.replace("@", " ").split())
                m = _CLAUSE_HEAD_RE.match(raw)
                if m is None:
                    continue
                kind = " ".join(m.group("kind").split())
                predicate = m.group("pred")
                if kind in TRIVIAL_CANDIDATE_KINDS and predicate and is_trivial_predicate(predicate):
                    found.append({"file": rel, "line": seg.line, "kind": kind, "predicate": predicate})
    return found


def _legacy_rank() -> bool:
    return os.environ.get(RANK_MODE_ENV, "trivial_aware").strip().lower() == LEGACY_RANK


def _effective_proved(wp: dict) -> int:
    """
    The proved goals the rank credits. Trivial-aware mode drops one goal per trivial clause added: an under-estimate
    for a `loop invariant`, which yields two (established and preserved), accepted to keep the count conservative.
    """
    if _legacy_rank():
        return int(wp["proved"])
    return max(0, int(wp["proved"]) - int(wp.get("trivial_added") or 0))


def _is_eligible(wp: dict, guard: dict) -> bool:
    """
    Whether a candidate may be compared at all. A candidate with no goals is not: it describes no proof state, and
    its (0, 0) would outrank every candidate that still has a failed goal.
    """
    return (
        guard["status"] == GUARDRAIL_PASSED
        and wp["status"] in COMPARABLE_WP_STATUSES
        and wp["soundness_ok"]
        and wp["failed"] is not None
        and wp["failed"] + wp["proved"] > 0
        # Unmergeable: merge-agent refuses top-level declarations outside the function. Absent in older states.
        and wp.get("scope_ok", True)
    )


def _is_refuted(wp: dict, guard: dict) -> bool:
    if guard["status"] in GUARDRAIL_REFUTATIONS:
        return True
    return wp["status"] in WP_STATUSES_WITH_SOUNDNESS_VERDICT and not wp["soundness_ok"]


def _rank_key(rank: dict) -> tuple[int, ...]:
    # Fewer failed goals first; among equals, fewer INVALID invariants (establishment/preservation
    # failures, which must be dropped/regenerated) before more proved goals. Trivial-aware mode then
    # prefers fewer trivial clauses added and credits only the proved goals they did not add. A rank
    # written before trivial-aware mode existed has neither field: it counts as no trivial clause.
    if _legacy_rank():
        return (rank["failed"], rank.get("invalid", 0), -rank["proved"])
    effective = rank.get("effective_proved")
    return (
        rank["failed"],
        rank.get("invalid", 0),
        rank.get("trivial_added") or 0,
        -(rank["proved"] if effective is None else effective),
    )


def _highest_proved(state: dict) -> int | None:
    """
    The highest proved count of any eligible evaluation so far, unless later runs refuted those files. Trivial-aware
    mode uses the effective count where the history entry has one (entries written before it have only `proved`).
    """
    refuted = {digest for digest, cand in state["candidates"].items() if cand["refuted"]}
    key = "proved" if _legacy_rank() else "effective_proved"
    return max(
        (
            h["proved"] if h.get(key) is None else h[key]
            for h in state["history"]
            if h["eligible"] and h["digest"] not in refuted
        ),
        default=None,
    )


def _install_best(scratch: Path, state: dict, cand: dict, contents: dict[str, bytes | None]) -> None:
    """Build the snapshot aside and swap it in; a killed swap fails restore_best's digest check, nothing else."""
    function = state["function"]
    for leftover in (STAGED_DIR, RETIRED_DIR):
        shutil.rmtree(scratch / leftover, ignore_errors=True)
    for rel, data in contents.items():
        if data is not None:
            _write_under(scratch, f"{STAGED_DIR}/work/{rel}", data)
    for oracle in _REPORT_PREFIX:
        name = _report_name(oracle, function)
        report = _read_regular(scratch, f"{CANDIDATES_DIR}/c{cand['id']}/{name}")
        if report is None:
            raise ArtifactError(f"candidate {cand['id']} has lost its {name}")
        _write_under(scratch, f"{STAGED_DIR}/{name}", report)
    if (scratch / BEST_DIR).exists():
        os.replace(scratch / BEST_DIR, scratch / RETIRED_DIR)
    os.replace(scratch / STAGED_DIR, scratch / BEST_DIR)
    shutil.rmtree(scratch / RETIRED_DIR, ignore_errors=True)


def _drop_best(scratch: Path, state: dict) -> None:
    shutil.rmtree(scratch / BEST_DIR, ignore_errors=True)
    state.update(best=None, best_digest=None, best_rank=None, best_files=None)


def _evaluate(scratch: Path, state: dict, digest: str, contents: dict[str, bytes | None]) -> dict:
    """Both oracles have reported on `digest`: judge the candidate and update the best one."""
    cand = state["candidates"][digest]
    wp, guard = cand["wp"], cand["guardrail"]
    # A later run on the same files can still refute them, for example a failed --smoke-tests after all_proven.
    cand["refuted"] = _is_refuted(wp, guard)
    if cand["refuted"] and state["best_digest"] == digest:
        _drop_best(scratch, state)
    if not _is_eligible(wp, guard):
        # Never compared, and not a stall: the prover must fix it (a false annotation on a real input), and the
        # existing retry budget bounds that.
        return {"eligible": False, "rank": None, "progress": None, "next_action": "continue"}

    trivial_added = wp.get("trivial_added") or 0
    rank = {
        "failed": wp["failed"],
        "proved": wp["proved"],
        "invalid": wp.get("invalid") or 0,
        "trivial_added": trivial_added,
        "effective_proved": _effective_proved(wp),
    }
    ranks_higher = state["best_rank"] is None or _rank_key(rank) < _rank_key(state["best_rank"])
    # New annotations add goals, so an iteration can raise both the failed and the proved count and is still moving,
    # while one that improves neither number is a stall. The rank alone still decides which candidate is best. Goals
    # of trivial clauses are not counted: adding `assert \true;` is not a move.
    highest = _highest_proved(state)
    progress = ranks_higher or highest is None or rank["effective_proved"] > highest
    if ranks_higher:
        _install_best(scratch, state, cand, contents)
        state.update(best=cand["id"], best_digest=digest, best_rank=rank, best_files=sorted(contents))
    if wp["status"] == "all_proven":
        next_action = "finished"
    else:
        next_action = "continue" if progress else "restore_best_and_finish"
    verdict = {"eligible": True, "rank": rank, "progress": progress, "next_action": next_action}
    if trivial_added and wp["status"] != "all_proven" and not _legacy_rank():
        verdict["next_synthesis_focus"] = DROP_TRIVIAL_FOCUS
    return verdict


def _not_recorded(state: dict | None, reason: str) -> dict:
    return {
        "recorded": False,
        "reason": reason,
        "candidate": None,
        "evaluated": False,
        "eligible": None,
        "rank": None,
        "best": state["best"] if state else None,
        "best_rank": state["best_rank"] if state else None,
        "progress": None,
        "next_action": "continue",
        "trivial_added": None,
    }


def note_oracle(out_json: Path, oracle: str, report: dict, digest_before: str | None) -> dict | None:
    """
    Record one finished oracle run, already written to `out_json`, and evaluate its candidate if the other oracle has
    reported on the same digest. Returns the block for the oracle's stdout summary, or None when this report is not a
    whole-run report of the prover owning that scratch directory.
    """
    if oracle not in _REPORT_PREFIX:
        raise ValueError(f"unknown oracle: {oracle!r}")
    scratch = _scratch_of(out_json)
    budget = _load_budget(scratch) if scratch is not None else None
    if scratch is None or budget is None or not isinstance(report, dict) or report.get("budget_exhausted"):
        return None
    function = budget.get("function")
    if not isinstance(function, str) or not _FUNCTION_RE.match(function):
        return None
    if Path(os.path.abspath(out_json)).name != _report_name(oracle, function):
        return None
    if oracle == "wp" and report.get("function") not in (None, function):
        return None

    with _locked(scratch):
        state = _load_state(scratch)
        contents = _read_tracked(scratch, budget)
        if contents is None or digest_before is None:
            return _not_recorded(state, "the tracked files could not be read: this report identifies no candidate")
        digest = _digest(contents)
        if digest != digest_before:
            return _not_recorded(
                state, "the tracked files changed while the oracle ran: re-run it on the current files to record them"
            )
        reported_file = report.get("file") if oracle == "wp" else None
        tracked_file = scratch / "work" / str(budget["file"])
        if reported_file and Path(str(reported_file)).resolve() != tracked_file.resolve():
            return _not_recorded(state, f"this report is for {reported_file}, not the tracked {budget['file']}")

        if state is None:
            state = _new_state(scratch, function)
        cand = state["candidates"].get(digest)
        if cand is None:
            cand = {"id": state["next_id"], "wp": None, "guardrail": None, "refuted": False}
            state["candidates"][digest] = cand
            state["next_id"] += 1
        name = _report_name(oracle, function)
        _write_under(scratch, f"{CANDIDATES_DIR}/c{cand['id']}/{name}", _report_bytes(report))
        cand[oracle] = _oracle_summary(oracle, report)
        if oracle == "wp":
            # Recorded in both rank modes, so an A/B comparison can count them.
            trivial = trivial_added_clauses(scratch, budget, contents)
            cand["wp"]["trivial_added"] = len(trivial)
            cand["wp"]["trivial_clauses"] = trivial[:MAX_TRIVIAL_CLAUSES_KEPT]
        pending = top_level_additions(scratch, budget)
        if cand["wp"] is not None:
            cand["wp"]["scope_ok"] = not pending

        evaluated = cand["wp"] is not None and cand["guardrail"] is not None
        if evaluated:
            verdict = _evaluate(scratch, state, digest, contents)
            if pending:
                # Even an all_proven candidate cannot be merged: the prover must remove the declarations.
                verdict["next_action"] = "continue"
        else:
            verdict = {"eligible": None, "rank": None, "progress": None, "next_action": "wait_for_other_oracle"}
        wp, guard = cand["wp"] or {}, cand["guardrail"] or {}
        entry = {
            "id": cand["id"],
            "digest": digest,
            "oracle": oracle,
            "at": utc_now(),
            "wp_status": wp.get("status"),
            "guardrail_status": guard.get("status"),
            "failed": wp.get("failed"),
            "proved": wp.get("proved"),
            "trivial_added": wp.get("trivial_added"),
            "effective_proved": verdict["rank"]["effective_proved"] if verdict["rank"] else None,
            "evaluated": evaluated,
            "eligible": verdict["eligible"],
            "progress": verdict["progress"],
        }
        if pending:
            entry["scope_violation_pending"] = pending
        state["history"].append(entry)
        atomic_write_json(scratch / STATE_FILE, state)
        block = {
            "recorded": True,
            "candidate": cand["id"],
            "evaluated": evaluated,
            "eligible": verdict["eligible"],
            "rank": verdict["rank"],
            "best": state["best"],
            "best_rank": state["best_rank"],
            "progress": verdict["progress"],
            "next_action": verdict["next_action"],
            "trivial_added": wp.get("trivial_added"),
        }
        if "next_synthesis_focus" in verdict:
            block["next_synthesis_focus"] = verdict["next_synthesis_focus"]
        if pending:
            block["scope_violation_pending"] = pending
            block["next_synthesis_focus"] = SCOPE_VIOLATION_FOCUS
        return block


def add_candidate_block(summary: dict, out_json: Path, oracle: str, report: dict, digest_before: str | None) -> None:
    """The oracles' hook: bookkeeping failures become a note, and never change the oracle's result or exit code."""
    try:
        block = note_oracle(out_json, oracle, report, digest_before)
    except Exception as exc:
        summary["candidate_note"] = f"candidate not recorded: {type(exc).__name__}: {exc}"
        return
    if block is None:
        return
    summary["candidate"] = block
    if block.get("scope_violation_pending"):
        summary["next_synthesis_focus"] = SCOPE_VIOLATION_FOCUS
    elif block["next_action"] == "restore_best_and_finish":
        summary["next_synthesis_focus"] = NO_PROGRESS_FOCUS


def _diff_lines(data: bytes | None) -> list[str]:
    # Only \n ends a line here: str.splitlines also splits on form feeds, which C sources do contain.
    text = (data or b"").decode("utf-8", "surrogateescape")
    return [line for line in re.split(r"(?<=\n)", text) if line]


def _patch_bytes(scratch: Path, rels: list[str]) -> bytes:
    """The annotation diff the brief asks for: scratch/base vs scratch/work on the tracked files."""
    chunks: list[str] = []
    for rel in rels:
        before = _diff_lines(_read_regular(scratch, f"base/{rel}"))
        after = _diff_lines(_read_regular(scratch, f"work/{rel}"))
        for line in difflib.unified_diff(before, after, fromfile=f"a/{rel}", tofile=f"b/{rel}"):
            chunks.append(line if line.endswith("\n") else f"{line}\n\\ No newline at end of file\n")
    return "".join(chunks).encode("utf-8", "surrogateescape")


def _restore_file(scratch: Path, rel: str, data: bytes | None) -> bool:
    """Make scratch/<rel> hold `data` (None: absent), keeping what it replaces in candidates/last/. True if it changed."""
    current = _read_regular(scratch, rel)
    if current == data and (data is not None or not os.path.lexists(scratch / rel)):
        return False
    if current is not None:
        _write_under(scratch, f"{LAST_DIR}/{rel}", current)
    if data is not None:
        _write_under(scratch, rel, data)
    else:
        _refuse_symlinked_parents(scratch, rel)
        (scratch / rel).unlink()
    return True


def restore_best(scratch: Path) -> dict | None:
    """
    Put the best candidate back into scratch/: its tracked files (only when they differ), its two reports and the
    patch. Idempotent. None when no candidate state or no best exists. `restored` says whether anything was replaced.
    """
    scratch = Path(scratch)
    if not (scratch / STATE_FILE).is_file():
        return None
    with _locked(scratch):
        state = _load_state(scratch)
        if state is None or state.get("best") is None:
            return None
        function, rels = state["function"], state["best_files"]
        # The state lives in the agent's own directory, and this may run as the parent.
        if not _FUNCTION_RE.match(function) or not all(is_safe_relative_path(rel) for rel in rels):
            raise ArtifactError(f"{scratch / STATE_FILE}: unsafe best candidate paths")
        snapshot = {rel: _read_regular(scratch, f"{BEST_DIR}/work/{rel}") for rel in rels}
        if _digest(snapshot) != state["best_digest"]:
            raise ArtifactError(f"{scratch / BEST_DIR}: does not hold candidate {state['best']}")
        reports = {}
        for oracle in _REPORT_PREFIX:
            name = _report_name(oracle, function)
            reports[name] = _read_regular(scratch, f"{BEST_DIR}/{name}")
            if reports[name] is None:
                raise ArtifactError(f"{scratch / BEST_DIR}: missing {name}")

        changed = [_restore_file(scratch, f"work/{rel}", data) for rel, data in snapshot.items()]
        changed += [_restore_file(scratch, name, data) for name, data in reports.items()]
        patch_rel, patch = f"{function}.patch", _patch_bytes(scratch, rels)
        if _read_regular(scratch, patch_rel) != patch:
            _write_under(scratch, patch_rel, patch)
        return {"restored": any(changed), "best": state["best"], "rank": state["best_rank"]}


def refuted_clauses(scratch: Path) -> list[dict]:
    """
    The clauses the E-ACSL guardrail refuted on this prover's candidates (`rejected_overconstrained` with a
    predicate), one per distinct (predicate, annotation_rte), ordered by candidate id. A `code_fault` is a code defect
    candidate, never evidence against the contract, so it is not listed. Never raises: a missing or malformed state
    gives [].
    """
    try:
        scratch = Path(scratch)
        state = _load_state(scratch)
        if state is None:
            return []
        function = state.get("function")
        cands = sorted(
            (
                c
                for c in (state.get("candidates") or {}).values()
                if isinstance(c, dict) and isinstance(c.get("id"), int)
            ),
            key=lambda c: c["id"],
        )
        out: list[dict] = []
        seen: set[tuple[str, bool]] = set()
        for cand in cands:
            guard = cand.get("guardrail")
            if not isinstance(guard, dict) or guard.get("status") != "rejected_overconstrained":
                continue
            if "failure" in guard:
                failure = guard.get("failure")
            elif isinstance(function, str) and _FUNCTION_RE.match(function):
                # A summary recorded before the failure was kept: read the candidate's own report.
                report = load_json_optional(
                    scratch / CANDIDATES_DIR / f"c{cand['id']}" / _report_name("guardrail", function), {}
                )
                failure = report.get("failure") if isinstance(report, dict) else None
            else:
                failure = None
            if not isinstance(failure, dict):
                continue
            predicate = str(failure.get("predicate") or "").strip()
            if not predicate:
                continue
            key = (predicate, failure.get("annotation_rte") is True)
            if key in seen:
                continue
            seen.add(key)
            out.append(
                {
                    "predicate": predicate,
                    "label": failure.get("label"),
                    "line": failure.get("line"),
                    "kind": failure.get("kind"),
                    "annotation_rte": key[1],
                    "candidate": cand["id"],
                }
            )
        return out
    except Exception:
        return []


def status(scratch: Path) -> dict:
    """What a later analysis needs: the best candidate and the history of recorded oracle runs."""
    scratch = Path(scratch)
    state = _load_state(scratch) or _new_state(scratch, None)
    return {
        "agent_id": state["agent_id"],
        "function": state["function"],
        "iterations": len(state["candidates"]),
        "best": state["best"],
        "best_rank": state["best_rank"],
        "highest_proved": _highest_proved(state),
        "history": state["history"],
        "refuted_clauses": refuted_clauses(scratch),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A Function Prover's best candidate (run from the run directory).")
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name, text in (
        ("restore-best", "Put the best candidate back into agents/<id>/scratch/"),
        ("status", "Print the best candidate and the history"),
    ):
        sub.add_parser(name, help=text).add_argument("--agent-id", required=True)
    args = parser.parse_args(argv)
    if not is_safe_agent_id(args.agent_id):
        print(json.dumps({"ok": False, "error": f"invalid agent id: {args.agent_id!r}"}, indent=2))
        return 1
    scratch = Path("agents") / args.agent_id / "scratch"
    try:
        if args.cmd == "status":
            out = status(scratch)
        else:
            out = restore_best(scratch) or {
                "restored": False,
                "best": None,
                "rank": None,
                "reason": "no eligible candidate was recorded",
            }
    except Exception as exc:
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}, indent=2))
        return 1
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
