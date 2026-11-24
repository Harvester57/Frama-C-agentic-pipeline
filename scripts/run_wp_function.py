#!/usr/bin/env python3
"""
Drives Frama-C WP + RTE deductive verification on a single C function (-wp-fct).
1. Runs WP with the verified flag set (-wp-model Typed -wp-check-memory-model
   -wp-rte -warn-invalid-pointer -warn-unsigned-overflow -warn-unsigned-downcast
   -wp-split) and parallel SMT solvers (Alt-Ergo, Z3, CVC5). The ACSL syntax/type
   check is folded into this run (-kernel-warn-key annot-error=abort): a kernel
   parse or annotation error still yields status `acsl_syntax_error`. A failed
   preprocessor run (`gcc -E`: missing header, wrong include flags) is a build
   configuration error, reported as `analysis_error` with reason
   `preprocessing_failed: <first cpp error>` and the messages in `preprocess_errors`.
2. Sizes itself from the job budget (scripts/resources.py): `--wp-par auto` scales the
   number of concurrent provers with CPUs and memory, while `-wp-memlimit` stays fixed
   at 1000 MB so a proof never depends on the machine.
3. Reuses prover results through Frama-C's WP cache (`--cache-dir auto`:
   `-wp-cache update -wp-cache-dir <run>/state/cache/wp` inside a run directory).
4. Scans the WP log for Tier-A aborts (Non-natural loop, User Error) and Tier-B
   silent unsoundness (Statement specifications skipped, union field access under
   Typed model, missing default assigns, reads nothing, failed smoke tests,
   indirect calls without `calls` while `\\valid_function` is skipped).
5. Supports single-clause raw VC drill-down (--prop <name> --dump-goal) and
   static vacuity smoke tests (--smoke-tests). SARIF (and the `-save` it needs) is
   produced only with --sarif; goal files only with --keep-goals or --dump-goal.
6. Classifies unproven goals into Step A/B/C buckets and maps every goal to a
   coverage-ledger obligation class (rte, l2_termination, l3_frame, and the MetAcsl
   classes l3_isolation, l4_auth_state, l4_auth_required, l4_invariant, l4_call_rule,
   l5_sanitized, l6_wiped, l6_no_leak). A hand-named L3_*/L4_*/L5_*/L6_* clause supports
   those properties and takes the class of its kind, like any other contract clause.
7. Loads the MetAcsl security properties with an instance in the function (step I9,
   scripts/security_props.py): `--security-props` (default: $FRAMAC_SECURITY_PROPS, else
   workspace/reports/security_props.json when it exists; `none` turns it off) writes them to a
   meta file parsed with the sources, plus the files defining the globals they name, and runs
   `-meta -then-last -wp ...`. The report's `security_props` names them.
8. Open-world callbacks (apply_open_callback_boundary): when the call-graph DAG marks an indirect
   call of the function as one no function of the program can be the target of
   (`open_indirect_calls`), the report gets `open_callback_boundary` (the goals that depend on the
   call), the focus `open_callback_boundary_stop_now` once nothing else is open, and a `calls`
   annotation naming a non-target there is Tier-B unsound.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import math
import os
import posixpath
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cache  # noqa: E402
import contract_refinement  # noqa: E402
import function_facts  # noqa: E402
import prover_candidates  # noqa: E402
import spec_kb  # noqa: E402
from acsl_ast import (  # noqa: E402
    SHAPE_UNKNOWN,
    AcslError,
    contract_shape,
    find_named_clause,
    find_target_unsound_axioms_or_admits,
    find_top_level_lemmas,
    find_unsound_recursive_logic,
    is_trivial_predicate,
    locate_function_span,
    mask_comments_and_literals,
)
from framac_common import (  # noqa: E402
    _CPP_ERROR_RE,
    STATUS_ASSUMED,
    STATUS_DEAD,
    STATUS_INCONSISTENT,
    STATUS_INVALID,
    STATUS_INVALID_UNDER_HYP,
    STATUS_NEVER_TRIED,
    STATUS_UNKNOWN,
    STATUS_VALID,
    STATUS_VALID_UNDER_HYP,
    WP_UNSOUND_MODEL_ISSUE,
    augment_framac_cppflags,
    failure_reason,
    fold_messages,
    kernel_parse_errors,
    missing_spec_messages,
    normalize_flag_args,
    parse_missing_spec,
    read_report_csv,
    resolve_fc_stubs_dir,
    scan_undeclared_functions,
    stub_repair_action,
    utc_now,
    wp_model_problem,
)
from resources import CLASSES, FRAMAC_KERNEL_RESERVE_MB, WP_MEMLIMIT_MB, enforced_memory_mb, wp_parallelism  # noqa: E402

# Below this, one prover cannot have its fixed -wp-memlimit next to the Frama-C kernel: goals would
# fail from starvation and read as "unproven", a result that depends on the machine.
WP_MIN_MEMORY_MB = FRAMAC_KERNEL_RESERVE_MB + WP_MEMLIMIT_MB
# The second name of Eva's taint assertions (security_props.py --eva-taint), which WP never proves.
WP_PROP_EXCLUDE = "-eva_taint"

_LAYER_NAME_RE = re.compile(r"\bL([3-6])_[A-Za-z0-9_]+")
# MetAcsl properties generated by scripts/security_props.py (step I9): `L6_wiped_<secret>: meta: ...`.
# The kinds of docs/plans/metacsl-exploitation-plan.md, section 3.3, carry their layer in the name
# (`L3_writers_<asset>`, `L3_readers_<asset>`, `L4_invariant_<name>`, `L4_call_<callee>`). No kind is
# the prefix of another, and `L3_frame` (the plain assigns obligation) is none of them.
_META_NAME_RE = re.compile(
    r"\bL(?:[4-6]_(auth_state|auth_required|sanitized|wiped|no_leak)|3_(writers|readers)|4_(invariant|call))"
    r"_[A-Za-z0-9_]+"
)
_META_CLASS = {
    "auth_state": "l4_auth_state",
    "auth_required": "l4_auth_required",
    "sanitized": "l5_sanitized",
    "wiped": "l6_wiped",
    "no_leak": "l6_no_leak",
    "writers": "l3_isolation",
    "readers": "l3_isolation",
    "invariant": "l4_invariant",
    "call": "l4_call_rule",
}
LAYER_CLASSES = frozenset(_META_CLASS.values())
SECURITY_PROPS_ENV = "FRAMAC_SECURITY_PROPS"
DEFAULT_SECURITY_PROPS = Path("workspace/reports/security_props.json")

# Tier A: WP refused or aborted analysis of the function
_TIER_A_RE = re.compile(
    r"([^\n]*user error[^\n]*|[^\n]*Non-natural loop detected[^\n]*|[^\n]*Main entry point function [^\n]* is \(potentially\) recursive[^\n]*)",
    re.IGNORECASE,
)

# Tier B: Silent unsoundness where goals may still report Valid
_TIER_B_PATTERNS = (
    "might be unsound",
    "Missing RTE guards",
    "Missing assigns clause",
    "Ignoring ",
    "Incompatible ",
    "not yet supported (skipped)",
    "interpreted as reads nothing",
    "using unguarded behavior assigns",
    "using complete behaviors assigns",
    "Failed smoke-test",
)
_MISSING_SPEC_RE = re.compile(r"Neither code nor specification for function ([A-Za-z_][A-Za-z0-9_]*)")
# Only a doomed `requires` makes a proof vacuous. Doomed dead_code / dead_call goals also fire on
# correct defensive code (`if (p == NULL)` under `requires \valid(p)`), so they are only counted.
_DOOMED_REQUIRES_RE = re.compile(r"\(Doomed\)\s+[A-Za-z0-9_]*?_wp_smoke_([A-Za-z0-9_]+)_requires\b")
_DOOMED_DEAD_RE = re.compile(r"\(Doomed\)\s+([A-Za-z0-9_]*?_wp_smoke_dead_[a-z_]+_[A-Za-z0-9_]+)")
_ANY_DOOMED_RE = re.compile(r"\(Doomed\)\s+([A-Za-z_]\w*)")
_SMOKE_COUNT_RE = re.compile(r"Smoke Tests\s*:\s*(\d+)\s*/\s*(\d+)")
VACUITY_GOAL_TIMEOUT_S = 1
VACUITY_SMOKE_TIMEOUT_S = 5
VACUITY_WALL_TIMEOUT_S = 300
_TIER_B_RE = re.compile(r"[^\n]*(?:" + "|".join(re.escape(p) for p in _TIER_B_PATTERNS) + r")[^\n]*")
_SMOKE_FAIL_RE = re.compile(
    r"(Failed smoke-test[^\n]*|Unsuccess[^\n]*smoke[^\n]*|[^\n]*Smoke Tests\s*:\s*0\s*/\s*\d+[^\n]*)",
    re.IGNORECASE,
)
_MM_HYP_RE = re.compile(r"Memory model hypotheses for function '([^']+)'")
_MM_HYP_BLOCK_RE = re.compile(r"Memory model hypotheses for function '([^']+)':\s*/\*@(.*?)\*/", re.DOTALL)
_MM_REQ_CLAUSE_RE = re.compile(r"\brequires\s+([^;]+);")
_WHY3_ANOMALY_RE = re.compile(r"\[Why3 Error\]\s*anomaly:\s*([^\n]+)", re.IGNORECASE)
_SKIPPED_RTE_RE = re.compile(
    r"(?:Skipped RTE guards:\s*([^\n)]+\))|([^\n]*Through function pointer[^\n]*cannot generate[^\n]*))"
)
_INDIRECT_CALL_UNSOUND_RE = re.compile(r"Missing 'calls'|Unknown callee")
CALLS_ANNOTATION_HINT = (
    "Indirect call through a function pointer without a 'calls' annotation: place "
    "'//@ calls f1, f2;' immediately above the indirect call statement."
)
# An open-world callback (the DAG's `open_indirect_calls`): WP's own warning gives the line of each call
# it could not resolve, and `calls` annotations name the targets a prover wrote.
_MISSING_CALLS_LINE_RE = re.compile(
    r"^\[wp\]\s+(?P<file>\S+?):(?P<line>\d+):\s+Warning:\s+Missing 'calls'", re.MULTILINE
)
_ACSL_COMMENT_RE = re.compile(r"//@[^\n]*|/\*@.*?\*/", re.DOTALL)
_ACSL_CALLS_RE = re.compile(r"(?<![\w\\])calls\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*;")
OPEN_CALLBACK_FOCUS = "open_callback_boundary_stop_now"
# Goal kinds of the function's own contract: after an unresolved call WP havocs memory and assumes the
# callee may recurse, so these depend on the callback wherever they sit.
_CONTRACT_GOAL_KINDS = ("termination", "assigns clause", "from", "postcondition", "exit")
_FPV_DEGEN_RE = re.compile(
    r"^\[wp\] \[(?:Timeout|Unknown|Failed|Failure|Stepout)\] ([A-Za-z0-9_]+_assert_rte_pointer_value[A-Za-z0-9_]*) .*\(Degenerated(?:, [^)]*)?\)",
    re.MULTILINE,
)
# With -wp-counter-examples, failed goals carry a witness model: "[wp] [Unsuccess] <goal> (<prover>) (Model)"
# (upstream plugins/wp/tests/wp_ce oracle format), or with Frama-C 34's tags
# "[wp] [Unknown] <goal> (Qed 2ms) (CVC5) (Cached) (Model)".
_MODEL_GOAL_RE = re.compile(
    r"^\[wp\] \[(?:Unsuccess|Unknown|Failed|Failure|Timeout|Stepout)\] ([A-Za-z_]\w*)((?: \([^)\n]*\))*?) \(Model\)",
    re.MULTILINE,
)
# Every goal WP reports as not proved, with or without a model.
_FAILED_GOAL_RE = re.compile(
    r"^\[wp\] \[(?:Unsuccess|Unknown|Failed|Failure|Timeout|Stepout|Incorrect|Invalid)\] ([A-Za-z_]\w*)", re.MULTILINE
)
_PAREN_TAG_RE = re.compile(r"\(([^)\n]*)\)")
# Artifact suffix of the -wp-counter-examples pass (run_wp_on_function): it never decides a status.
_MODEL_PASS_SUFFIX = "_cex"


def parse_model_goals(log: str) -> list[dict[str, str]]:
    """The goals of a -wp-counter-examples log that carry a model, with the prover that produced it."""
    goals: list[dict[str, str]] = []
    for m in _MODEL_GOAL_RE.finditer(log):
        tags = [t.strip() for t in _PAREN_TAG_RE.findall(m.group(2))]
        provers = [t for t in tags if t and t != "Cached" and not re.match(r"Qed\b", t)]
        goals.append({"goal": m.group(1), "prover": provers[-1] if provers else ""})
    return goals


def parse_failed_wp_goals(log: str) -> set[str]:
    """Names of the goals a WP log reports as not proved."""
    return set(_FAILED_GOAL_RE.findall(log))


# Per-goal solver cost (Tier 1 of docs/plans/proof-papers-generalization-plan.md). Source: WP's own JSON
# report (`-wp-report-json`, Frama-C 34), which names each goal, its property, its verdict, a `cached`
# count and the prover entries with their time in seconds, paired with `-wp-status` for per-prover
# verdicts on multi-prover runs. Measured in framac-analysis:latest (2026-11-16..20): a proved goal
# carries the time of the prover that proved it; an unproved goal in `-wp-report-json` carries ONE
# merged prover entry whose time is a 0 placeholder, and WP ranks a Timeout above an Unknown when it
# merges provers (z3 Timeout + cvc5 Unknown reads `[Timeout] (Alt-Ergo)`). `-wp-status` prints every
# pending goal in Wpo.iter order with one `Prover <name> <ver> returns <verdict> ...` line per prover,
# giving exact `per_prover_verdicts` on multi-prover runs. Without `-wp-status` (legacy reports),
# "every prover timed out" falls back to single-prover runs only. The log tags are the fallback when
# the JSON is missing: they carry no solver time at all (the `Qed 2ms` tag is the simplifier's), and
# `(Cached)` also appears on a first run under `-wp-cache update`, so a log-sourced entry never has a
# time either.
GOAL_COSTS_ENV = "FRAMAC_WP_GOAL_COSTS"
_VERDICT_KINDS = {
    "timeout": "timeout",
    "stepout": "stepout",
    "unknown": "unknown",
    "failed": "failed",
    "failure": "failed",
}
SLOWEST_PROVED_MAX = 5
# "Well under the timeout" for an Unknown, and "at the timeout" for a Timeout, as fractions of -wp-timeout.
UNKNOWN_FAST_FRACTION = 0.5
TIMEOUT_REACHED_FRACTION = 0.9
_COST_LINE_RE = re.compile(r"^\[wp\] \[(Timeout|Stepout|Unknown|Failed|Failure)\] ([A-Za-z_]\w*)(.*)$", re.MULTILINE)
_COST_TAGS_RE = re.compile(r"(?:[ \t]+\([^()\n]*\))*[ \t]*")
_PROVER_TAG_RE = re.compile(r"^(?:Alt-Ergo|Z3|CVC4|CVC5|Colibri2?|Vampire|Eprover|Coq|Rocq|Script)$", re.IGNORECASE)
_WP_STATUS_SEP_RE = re.compile(r"^-{20,}\s*$")
_WP_STATUS_FN_RE = re.compile(r"^\s+Function\s+([A-Za-z_]\w*)\s*$")
_WP_STATUS_SECTION_RE = re.compile(r"^\s+(?:Global|Axiomatic\b|Lemma\b)")
_WP_STATUS_PROVER_RE = re.compile(
    r"^Prover\s+(?P<prover>.+?)\s+returns\s+"
    r"(?P<verdict>Step\s+limit|Timeout|Unknown|Failed|Failure|Valid|Invalid|Stepout|NoResult)\b(?P<tail>.*)$"
)
_WP_STATUS_VERDICT_MAP = {
    "timeout": "timeout",
    "step limit": "stepout",
    "stepout": "stepout",
    "unknown": "unknown",
    "failed": "failed",
    "failure": "failed",
    "valid": "valid",
    "invalid": "invalid",
}
_WP_STATUS_TIME_TAG_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(ms|s)\s*$")
_WP_STATUS_PART_RE = re.compile(r"\((\d+)/(\d+)\)\s*$")
_WP_STATUS_LINE_RE = re.compile(r",\s*line\s+(\d+)\)")
_WP_STATUS_HEADER_FN_RE = re.compile(r"\bin\s+'([A-Za-z_]\w*)'")


def _wp_status_prover_name(raw: str) -> str | None:
    """`Alt-Ergo 2.4.3` -> `Alt-Ergo`, `Z3 4.13.3 (counterexample)` -> `Z3`, `Qed` -> `Qed`."""
    cleaned = re.sub(r"\s+\([^)]*\)\s*$", "", raw.strip()).strip()
    cleaned = re.sub(r"\s+\d+(?:\.\d+)*(?:[A-Za-z0-9._+-]*)?$", "", cleaned).strip()
    return cleaned or None


def _parse_wp_status_tail(tail: str) -> tuple[int | None, bool]:
    """(prover time in ms or None, cached) from parenthesised tags on a `Prover ... returns ...` line."""
    time_ms: int | None = None
    cached = False
    for raw_tag in _PAREN_TAG_RE.findall(tail or ""):
        tag = raw_tag.strip()
        low = tag.lower()
        if low == "cached":
            cached = True
            continue
        if low.startswith("qed:") or low == "qed" or low == "model":
            continue
        m_time = _WP_STATUS_TIME_TAG_RE.match(tag)
        if m_time:
            val = float(m_time.group(1))
            unit = m_time.group(2)
            ms = round(val if unit == "ms" else val * 1000.0)
            if ms > 0:
                time_ms = ms
    return time_ms, cached


def _parse_wp_status_blocks(log_text: str) -> list[dict[str, Any]]:
    """
    Extract pending goal blocks from Frama-C WP `-wp-status` (or `-wp-print`) output.
    Each block holds `function`, `header`, and `per_prover` ({prover: {verdict, time_ms, cached}})
    for non-Qed provers. Blocks proved Valid are skipped (only unproved goals matter for residual costs).
    """
    lines = (log_text or "").splitlines()
    n = len(lines)
    i = 0
    current_fn: str | None = None
    blocks: list[dict[str, Any]] = []

    while i < n:
        line = lines[i]
        if line.startswith("[report] ") or line.startswith("--- Properties of Function "):
            break
        if _WP_STATUS_SEP_RE.match(line) and i + 2 < n and _WP_STATUS_SEP_RE.match(lines[i + 2]):
            m_fn = _WP_STATUS_FN_RE.match(lines[i + 1])
            if m_fn:
                current_fn = m_fn.group(1)
                i += 3
                continue
            if _WP_STATUS_SECTION_RE.match(lines[i + 1]):
                current_fn = None
                i += 3
                continue
        if line.startswith("Goal "):
            header_parts = [line[len("Goal ") :].strip()]
            j = i + 1
            while j < n and not header_parts[-1].endswith(":"):
                nxt = lines[j].strip()
                if (
                    not nxt
                    or _WP_STATUS_SEP_RE.match(lines[j])
                    or nxt.startswith(("Assume", "Let ", "Tags:", "Prove:", "Prover ", "Goal "))
                ):
                    break
                header_parts.append(nxt)
                j += 1
            header = " ".join(header_parts).rstrip(":").strip()
            per_prover: dict[str, dict[str, Any]] = {}
            has_valid = False
            while j < n:
                cur = lines[j]
                if (
                    _WP_STATUS_SEP_RE.match(cur)
                    or cur.startswith("Goal ")
                    or cur.startswith("[report] ")
                    or cur.startswith("--- Properties of Function ")
                ):
                    break
                m_p = _WP_STATUS_PROVER_RE.match(cur)
                if m_p:
                    pname = _wp_status_prover_name(m_p.group("prover"))
                    raw_v = " ".join(m_p.group("verdict").lower().split())
                    verdict = _WP_STATUS_VERDICT_MAP.get(raw_v)
                    if verdict == "valid":
                        has_valid = True
                    elif pname and pname.lower() != "qed" and verdict in _VERDICT_KINDS:
                        t_ms, is_cached = _parse_wp_status_tail(m_p.group("tail"))
                        per_prover[pname] = {"verdict": verdict, "time_ms": t_ms, "cached": is_cached}
                j += 1
            block_fn = current_fn
            if block_fn is None:
                fn_matches = _WP_STATUS_HEADER_FN_RE.findall(header)
                if fn_matches:
                    block_fn = fn_matches[-1]
            if per_prover and not has_valid:
                blocks.append({"function": block_fn, "header": header, "per_prover": per_prover})
            i = j
            continue
        i += 1
    return blocks


def _sanitize_label(raw: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", raw).strip("_")


def _status_header_matches_goal(header: str, goal: str, fn_name: str | None, cost_line: int | None) -> bool:
    """Whether a `-wp-status` `Goal <header>:` description is structurally compatible with `goal`."""
    rest = goal
    if fn_name:
        marker = f"_{fn_name}_"
        idx = goal.find(marker)
        if idx >= 0:
            rest = goal[idx + len(marker) :]

    # Split part suffix `(k/m)` <-> `_part<k>`
    m_part = _WP_STATUS_PART_RE.search(header)
    if m_part:
        if not rest.endswith(f"_part{m_part.group(1)}"):
            return False

    # Single source line `("file", line N)` (not `lines N-M`): last occurrence matches JSON line
    if cost_line is not None:
        line_hits = _WP_STATUS_LINE_RE.findall(header)
        if line_hits and int(line_hits[-1]) != cost_line:
            return False

    # Kind + optional label compatibility against the goal name suffix
    m_post = re.match(r"^Post-condition(?:\s+'([^']+)')?", header)
    if m_post:
        if "ensures" not in rest:
            return False
        lbl = _sanitize_label(m_post.group(1) or "")
        return not lbl or lbl in rest

    m_assert = re.match(r"^Assertion(?:\s+'([^']+)')?", header)
    if m_assert:
        if "assert" not in rest:
            return False
        lbl = _sanitize_label(m_assert.group(1) or "")
        if lbl:
            return f"assert_{lbl}" in rest or lbl in rest
        return "assert_rte_" not in rest

    m_check = re.match(r"^Check(?:\s+'([^']+)')?", header)
    if m_check:
        if "check" not in rest:
            return False
        lbl = _sanitize_label(m_check.group(1) or "")
        return not lbl or lbl in rest

    m_inv_est = re.match(r"^Establishment of Invariant(?:\s+'([^']+)')?", header)
    if m_inv_est:
        if "loop_invariant" not in rest or "established" not in rest:
            return False
        lbl = _sanitize_label(m_inv_est.group(1) or "")
        return not lbl or lbl in rest

    m_inv_pre = re.match(r"^Preservation of Invariant(?:\s+'([^']+)')?", header)
    if m_inv_pre:
        if "loop_invariant" not in rest or "preserved" not in rest:
            return False
        lbl = _sanitize_label(m_inv_pre.group(1) or "")
        return not lbl or lbl in rest

    if header.startswith("Positivity of Loop variant"):
        return "loop_variant" in rest and "positive" in rest
    if header.startswith("Decreasing of Loop variant"):
        return "loop_variant" in rest and "decrease" in rest
    if header.startswith(("Positivity of Variant", "Decreasing of Variant", "Recursion variant")):
        return "variant" in rest or "decreases" in rest
    if header.startswith("Termination-condition"):
        return "terminates" in rest
    if header.startswith("Exit-condition"):
        return "exits" in rest
    if header.startswith("Loop assigns"):
        return "loop_assigns" in rest
    if header.startswith("Assigns"):
        return "assigns" in rest
    if header.startswith("Instance of 'Pre-condition"):
        m_callee = re.search(r"in\s+'([A-Za-z_]\w*)'", header)
        if m_callee and f"call_{m_callee.group(1)}" in rest:
            return True
        return "requires" in rest
    m_cp = re.match(r"^Call point\s+([A-Za-z_]\w*)\b", header)
    if m_cp:
        return f"call_point_{m_cp.group(1)}" in rest
    if header.startswith("Complete behaviors"):
        return "complete" in rest
    if header.startswith("Disjoint behaviors"):
        return "disjoint" in rest
    return True


def _status_block_matches_cost(block: dict[str, Any], cost: dict[str, Any], fn_name: str | None) -> bool:
    """Whether a `-wp-status` block is compatible with an unproven goal cost record."""
    goal = str(cost.get("goal") or "")
    if not goal:
        return False
    bfn = block.get("function")
    effective_fn = fn_name or bfn
    if fn_name and bfn and bfn != fn_name:
        return False
    if bfn and f"_{bfn}_" not in goal:
        return False
    per_prover: dict[str, dict[str, Any]] = block.get("per_prover") or {}
    if not per_prover:
        return False
    verdict_kind = cost.get("verdict_kind")
    if isinstance(verdict_kind, str) and verdict_kind:
        by_prover_lower = {p.lower(): str(info.get("verdict") or "") for p, info in per_prover.items()}
        if verdict_kind not in by_prover_lower.values():
            return False
        for cp in cost.get("provers") or []:
            if isinstance(cp, str) and cp.lower() in by_prover_lower:
                if by_prover_lower[cp.lower()] != verdict_kind:
                    return False
    raw_line = cost.get("line")
    cost_line = raw_line if isinstance(raw_line, int) and not isinstance(raw_line, bool) and raw_line > 0 else None
    return _status_header_matches_goal(str(block.get("header") or ""), goal, effective_fn, cost_line)


def parse_wp_status_per_prover(
    log_text: str,
    goals: list[dict[str, Any]] | None = None,
    fn_name: str | None = None,
) -> dict[str, dict[str, dict[str, Any]]]:
    """
    Parse Frama-C 34 `-wp-status` output into `{goal_name: {prover_name: {"verdict", "time_ms", "cached"}}}`.

    `-wp-status` iterates pending goals in deterministic `Wpo.iter` order (matching `-wp-report-json`),
    printing every prover's `Prover <Name> <Version> returns <Verdict> ...` line under each goal.
    When `goals` (from `-wp-report-json` or `goal_costs_from_log`) aligns 1-to-1 in order and every
    pair passes structural + verdict consistency checks, all goals bind directly (including multiple
    identical same-line RTE headers). Otherwise falls back to iterative unique-match peeling and fails
    closed on ambiguity.
    """
    blocks = _parse_wp_status_blocks(log_text)
    if fn_name:
        blocks = [b for b in blocks if not b.get("function") or b["function"] == fn_name]
    if not blocks:
        return {}

    targets: list[dict[str, Any]]
    if goals is not None:
        targets = [g for g in goals if isinstance(g, dict) and isinstance(g.get("goal"), str)]
    else:
        targets = goal_costs_from_log(log_text)
        if fn_name:
            targets = [t for t in targets if f"_{fn_name}_" in str(t.get("goal") or "")]
    if not targets:
        return {}

    # Pass 1: exact Wpo.iter 1-to-1 order match verified per pair.
    if len(blocks) == len(targets) and all(
        _status_block_matches_cost(b, t, fn_name) for b, t in zip(blocks, targets, strict=True)
    ):
        return {str(t["goal"]): dict(b["per_prover"]) for b, t in zip(blocks, targets, strict=True)}

    # Pass 2: iterative unique-match peeling (handles out-of-order console lines under -wp-par).
    rem_b = set(range(len(blocks)))
    rem_t = set(range(len(targets)))
    compat: dict[int, set[int]] = {
        bi: {ti for ti in rem_t if _status_block_matches_cost(blocks[bi], targets[ti], fn_name)} for bi in rem_b
    }
    matched: dict[str, dict[str, dict[str, Any]]] = {}
    changed = True
    while changed and rem_b and rem_t:
        changed = False
        for bi in list(rem_b):
            cands = compat[bi] & rem_t
            if len(cands) == 1:
                ti = next(iter(cands))
                matched[str(targets[ti]["goal"])] = dict(blocks[bi]["per_prover"])
                rem_b.remove(bi)
                rem_t.remove(ti)
                changed = True
        for ti in list(rem_t):
            cands_b = [bi for bi in rem_b if ti in compat[bi]]
            if len(cands_b) == 1:
                bi = cands_b[0]
                matched[str(targets[ti]["goal"])] = dict(blocks[bi]["per_prover"])
                rem_b.remove(bi)
                rem_t.remove(ti)
                changed = True

    # Remaining ambiguous targets: bind only when every candidate block agrees on the exact verdict map.
    for ti in list(rem_t):
        cands_b = [bi for bi in rem_b if ti in compat[bi]]
        if not cands_b:
            continue
        verdict_maps = [
            tuple(sorted((p, str(info["verdict"])) for p, info in blocks[bi]["per_prover"].items())) for bi in cands_b
        ]
        if len(set(verdict_maps)) == 1:
            matched[str(targets[ti]["goal"])] = dict(blocks[cands_b[0]]["per_prover"])
    return matched


def goal_costs_enabled() -> bool:
    """FRAMAC_WP_GOAL_COSTS=off drops the goal-cost hints (the fields stay), for A/B comparisons."""
    return os.environ.get(GOAL_COSTS_ENV, "on").strip().lower() not in ("off", "0", "false", "no", "disabled")


def _prover_name(raw: object) -> str | None:
    """`Alt-Ergo:2.4.3` -> `Alt-Ergo`; None for anything that is not a non-empty string."""
    if not isinstance(raw, str) or not raw.strip():
        return None
    return raw.split(":", 1)[0].strip() or None


def _positive_ms(raw: object) -> int | None:
    """A JSON time in seconds as whole milliseconds; None for a missing, non-numeric or zero placeholder."""
    if isinstance(raw, bool) or not isinstance(raw, (int, float)) or raw <= 0:
        return None
    ms = round(raw * 1000)
    return ms if ms > 0 else None


def parse_wp_report_json(text: str) -> list[dict] | None:
    """The goal entries of a `-wp-report-json` file, or None when it is not a JSON list of objects."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, list):
        return None
    return [e for e in data if isinstance(e, dict)]


def goal_costs_from_report(entries: list[dict], fn_name: str) -> tuple[list[dict], list[dict]]:
    """
    (unproven_goal_costs, slowest_proved_goals) from `-wp-report-json` entries. Fails closed: an entry
    without a goal name, a smoke goal, another function's goal, or an unproved verdict outside
    timeout/stepout/unknown/failed is left out; a time is kept only when it is a positive measurement.
    A cached proved goal never enters the slowest list.
    """
    unproven: list[dict] = []
    proved: list[dict] = []
    seen: set[str] = set()
    for e in entries:
        goal = e.get("goal")
        if not isinstance(goal, str) or not re.fullmatch(r"[A-Za-z_]\w*", goal) or goal in seen:
            continue
        if e.get("smoke") is True:
            continue
        fn = e.get("function")
        if isinstance(fn, str) and fn and fn != fn_name:
            continue
        seen.add(goal)
        cached_raw = e.get("cached")
        cached = isinstance(cached_raw, int) and not isinstance(cached_raw, bool) and cached_raw > 0
        raw_provers = e.get("provers")
        provers = [p for p in raw_provers if isinstance(p, dict)] if isinstance(raw_provers, list) else []
        if e.get("passed") is True:
            if e.get("verdict") != "valid" or cached:
                continue
            for p in provers:
                name, ms = _prover_name(p.get("prover")), _positive_ms(p.get("time"))
                if p.get("success") == 1 and name and ms is not None:
                    proved.append({"goal": goal, "prover": "Qed" if name.lower() == "qed" else name, "time_ms": ms})
                    break
            continue
        if e.get("passed") is not False:
            continue
        kind = _VERDICT_KINDS.get(str(e.get("verdict") or ""))
        if kind is None:
            continue
        smt = [p for p in provers if (_prover_name(p.get("prover")) or "").lower() != "qed"]
        names = [n for n in (_prover_name(p.get("prover")) for p in smt) if n]
        times = [t for t in (_positive_ms(p.get("time")) for p in smt) if t is not None]
        prop = e.get("property")
        src, line = e.get("file"), e.get("line")
        unproven.append(
            {
                "goal": goal,
                "property": prop if isinstance(prop, str) and prop else None,
                # Where WP reports the goal, as it writes them (the file is a path of the analysis
                # run). With `property` they pair a goal with its row in `unproven_goals`, which has
                # no goal name (scripts/wp_residual_census.py).
                "file": src if isinstance(src, str) and src else None,
                "line": line if isinstance(line, int) and not isinstance(line, bool) and line > 0 else None,
                "verdict_kind": kind,
                "provers": list(dict.fromkeys(names)),
                "time_ms": max(times) if times else None,
                "cached": cached,
            }
        )
    proved.sort(key=lambda g: (-g["time_ms"], g["goal"]))
    return unproven, proved[:SLOWEST_PROVED_MAX]


def goal_costs_from_log(log: str) -> list[dict]:
    """
    unproven_goal_costs from the log tags, when no JSON report is available. Only a line that is exactly
    `[wp] [<Verdict>] <goal>` followed by parenthesised tags yields provers and the cached mark; any other
    tail leaves them empty. The log carries no solver time, so `time_ms` is always null, and so are
    `property` (not reliably encoded in the goal name), `file` and `line`.
    """
    costs: list[dict] = []
    seen: set[str] = set()
    for m in _COST_LINE_RE.finditer(log):
        goal = m.group(2)
        if goal in seen:  # WP prints a goal twice under -wp-cache update or -wp-steps
            continue
        seen.add(goal)
        tail = m.group(3)
        provers: list[str] = []
        cached = False
        if _COST_TAGS_RE.fullmatch(tail):
            tags = [t.strip() for t in _PAREN_TAG_RE.findall(tail)]
            provers = list(dict.fromkeys(t for t in tags if _PROVER_TAG_RE.match(t)))
            cached = "Cached" in tags
        costs.append(
            {
                "goal": goal,
                "property": None,
                "file": None,
                "line": None,
                "verdict_kind": _VERDICT_KINDS.get(m.group(1).lower(), m.group(1).lower()),
                "provers": provers,
                "time_ms": None,
                "cached": cached,
            }
        )
    return costs


def _merge_wp_status_per_prover(unproven: list[dict], log: str, fn_name: str) -> None:
    """Attach `per_prover_verdicts` (and non-cached `per_prover_time_ms`) from `-wp-status` onto `unproven`."""
    if not unproven or not log:
        return
    per_goal = parse_wp_status_per_prover(log, goals=unproven, fn_name=fn_name)
    if not per_goal:
        return
    for cost in unproven:
        goal = cost.get("goal")
        if not isinstance(goal, str) or goal not in per_goal:
            continue
        details = per_goal[goal]
        verdicts = {p: str(info["verdict"]) for p, info in details.items() if info.get("verdict")}
        if verdicts:
            cost["per_prover_verdicts"] = verdicts
        times = {
            p: info["time_ms"]
            for p, info in details.items()
            if isinstance(info.get("time_ms"), int)
            and not isinstance(info.get("time_ms"), bool)
            and not info.get("cached")
        }
        if times:
            cost["per_prover_time_ms"] = times


def collect_goal_costs(json_path: Path, log: str, fn_name: str) -> tuple[list[dict], list[dict], str | None]:
    """(unproven_goal_costs, slowest_proved_goals, source): the JSON report first, else the log tags."""
    entries: list[dict] | None = None
    if json_path.exists():
        entries = parse_wp_report_json(json_path.read_text(encoding="utf-8", errors="replace"))
    if entries is not None:
        unproven, slowest = goal_costs_from_report(entries, fn_name)
        _merge_wp_status_per_prover(unproven, log, fn_name)
        return unproven, slowest, "report_json"
    unproven = goal_costs_from_log(log)
    _merge_wp_status_per_prover(unproven, log, fn_name)
    return unproven, [], ("log" if unproven else None)


def _goal_list(names: list[str]) -> str:
    shown = ", ".join(f"`{n}`" for n in names[:5])
    return shown + (f" and {len(names) - 5} more" if len(names) > 5 else "")


def _normalized_per_prover_verdicts(cost: dict) -> dict[str, str]:
    """Lowercased `{prover: verdict}` from `cost['per_prover_verdicts']`, skipping Qed and invalid entries."""
    raw = cost.get("per_prover_verdicts")
    if not isinstance(raw, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in raw.items():
        if not isinstance(k, str) or not isinstance(v, str):
            continue
        pname, verdict = k.strip().lower(), v.strip().lower()
        if pname and pname != "qed" and verdict:
            out[pname] = verdict
    return out


def goal_cost_hints(res: dict) -> list[str]:
    """
    The two verdict-kind hints. Each needs every unproven goal (the Degenerated function-pointer goals the
    result assumes are left out) to agree, and the run's -wp-timeout; a cached time is never used, and an
    Unknown/Timeout with a measured time on the wrong side of the threshold blocks the hint. Not on a
    counter-example run, whose merged verdicts differ (an Unknown with a Model beats a Timeout there).
    With `per_prover_verdicts` (from `-wp-status`), multi-prover runs also detect when every configured
    prover timed out or stepped out versus when a fast Unknown was masked by another prover's Timeout.
    """
    costs = res.get("unproven_goal_costs")
    timeout_s = res.get("wp_timeout_s")
    if not isinstance(costs, list) or not costs or res.get("counter_examples"):
        return []
    if isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float)) or timeout_s <= 0:
        return []
    assumed = set((res.get("soundness") or {}).get("assumed_function_pointer_goals") or [])
    goals = [c for c in costs if isinstance(c, dict) and c.get("goal") not in assumed]
    if not goals:
        return []
    timeout_ms = timeout_s * 1000
    provers = [p for p in (res.get("wp_provers") or []) if isinstance(p, str) and p]
    configured_lower = {p.lower() for p in provers}

    def measured(c: dict) -> int | None:
        t = c.get("time_ms")
        return t if isinstance(t, int) and not isinstance(t, bool) and not c.get("cached") else None

    def prover_times_lower(c: dict) -> dict[str, int]:
        if c.get("cached"):
            return {}
        raw = c.get("per_prover_time_ms")
        if not isinstance(raw, dict):
            return {}
        return {
            k.strip().lower(): v
            for k, v in raw.items()
            if isinstance(k, str) and isinstance(v, int) and not isinstance(v, bool) and v > 0
        }

    def gave_up_early(c: dict) -> bool:
        ppv = _normalized_per_prover_verdicts(c)
        if ppv and any(v != "unknown" for v in ppv.values()):
            return False
        t = measured(c)
        return c.get("verdict_kind") == "unknown" and (t is None or t <= UNKNOWN_FAST_FRACTION * timeout_ms)

    def ran_out(c: dict) -> bool:
        t = measured(c)
        ppv = _normalized_per_prover_verdicts(c)
        if len(provers) > 1:
            if not ppv or not (configured_lower <= set(ppv)):
                return False
            if any(v not in ("timeout", "stepout") for v in ppv.values()):
                return False
            if t is not None and c.get("verdict_kind") == "timeout" and t < TIMEOUT_REACHED_FRACTION * timeout_ms:
                return False
            ptimes = prover_times_lower(c)
            for pname, verdict in ppv.items():
                if verdict == "timeout":
                    pt = ptimes.get(pname)
                    if pt is not None and pt < TIMEOUT_REACHED_FRACTION * timeout_ms:
                        return False
            return True
        if len(provers) == 1:
            if ppv:
                if provers[0].lower() not in ppv or any(v not in ("timeout", "stepout") for v in ppv.values()):
                    return False
                ptimes = prover_times_lower(c)
                pt = ptimes.get(provers[0].lower())
                if (
                    ppv[provers[0].lower()] == "timeout"
                    and pt is not None
                    and pt < TIMEOUT_REACHED_FRACTION * timeout_ms
                ):
                    return False
            if c.get("verdict_kind") == "stepout":
                return True
            return c.get("verdict_kind") == "timeout" and (t is None or t >= TIMEOUT_REACHED_FRACTION * timeout_ms)
        return False

    names = [str(c.get("goal")) for c in goals]
    hints: list[str] = []
    if all(gave_up_early(c) for c in goals):
        hints.append(
            f"Every unproven goal ({_goal_list(names)}) got Unknown, not Timeout: the provers gave up before the "
            f"{timeout_s}s limit (WP reports a Timeout over an Unknown, so none of them ran out of time). The goal is "
            "probably false or missing a fact: read its sequent with `--prop <clause> --dump-goal` and check the "
            "claim with the E-ACSL guardrail before strengthening anything."
        )
    if provers and all(ran_out(c) for c in goals):
        if len(provers) == 1:
            hints.append(
                f"Every unproven goal ({_goal_list(names)}) ran out of time or steps with the only configured prover "
                f"({provers[0]}, {timeout_s}s limit): the goal may be true and too large. Isolate it (`--prop <clause>`) "
                "and reduce what it depends on (split the clause, add an intermediate `assert`, drop facts it does not "
                "need) before weakening it."
            )
        else:
            prover_list = ", ".join(provers)
            hints.append(
                f"Every unproven goal ({_goal_list(names)}) ran out of time or steps on all configured provers "
                f"({prover_list}, {timeout_s}s limit): the goal may be true and too large. Isolate it (`--prop <clause>`) "
                "and reduce what it depends on (split the clause, add an intermediate `assert`, drop facts it does not "
                "need) before weakening it."
            )
    return hints


_VC_DUMP_RE = re.compile(
    r"-{20,}\n(\s*Goal [^\n]+:.*?)(?=\n-{20,}|\Z)",
    re.DOTALL,
)


def goal_obligation_class(item: dict) -> str:
    """
    Map a WP goal to a coverage-ledger obligation class (naming convention in docs/guides/v2-design.md):
    MetAcsl-generated L4_auth_state_*, L4_auth_required_*, L5_sanitized_*, L6_wiped_*,
    L6_no_leak_* -> their property class; L3_writers_*, L3_readers_* -> l3_isolation;
    L4_invariant_* -> l4_invariant; L4_call_* -> l4_call_rule; loop variant/decreases ->
    l2_termination; assigns/separated/frees/allocates -> l3_frame; everything else -> rte. The
    property name is looked up first: a writers property's predicate is a `\\separated`, and its goal
    is no l3_frame goal. A hand-named L3_*/L4_*/L5_*/L6_* clause is a supporting contract clause: no
    ledger unit has a class of its own for it (the pre-I9 classes l4_auth, l5_output, l6_secret are
    gone), so it falls through.

    `l2_termination` matches the report kind (`loop variant`, `loop_variant`, `variant`, `decreases`,
    `decreases clause`), never a substring inside a precondition/postcondition label such as
    `ensures decreases_len: ...` (libmodbus run-1: 133 postcondition rows with a `decreases` label).
    For unlabeled items (`kind` empty or `assertion`, as `ledger.py` builds for a prover's
    `proof_gap`/`fault_hypothesis`), only an annotation starting with `loop variant` or `decreases`
    followed by whitespace or end-of-string (not `:` or `_`) maps to `l2_termination`.
    `termination clause` (`terminates \\true;`) stays `rte`: the kernel emits it on loop-free
    functions too.

    A `\\separated` in the predicate of a precondition or a postcondition (the report kinds
    `precondition`, `precondition of <callee>`, `postcondition`) is not a frame goal: it says nothing
    about what the function writes. libmodbus run-1: the one "proven l3_frame goal" of
    `modbus_write_register`, whose contract had no `assigns` clause, was WP's memory-model hypothesis of
    its callee, `precondition of write_single: \\separated(ctx + (..), &__fc_errno)`.
    """
    text = f"{item.get('kind', '')} {item.get('annotation', '')}"
    meta = _META_NAME_RE.search(text)
    if meta:
        return _META_CLASS[next(g for g in meta.groups() if g)]
    kind = str(item.get("kind") or "").strip().lower()
    ann = str(item.get("annotation") or "").strip().lower()
    if _TERMINATION_KIND_RE.match(kind) or (kind in ("", "assertion") and _TERMINATION_CLAUSE_RE.match(ann)):
        return "l2_termination"
    low = text.lower()
    if "assigns" in low or "frees" in low or "allocates" in low:
        return "l3_frame"
    if "\\separated" in low and not kind.startswith(_PREDICATE_CLAUSE_KINDS):
        return "l3_frame"
    return "rte"


# The report kinds of a contract's predicates: `precondition`, `precondition of <callee>`, `postcondition`.
_PREDICATE_CLAUSE_KINDS = ("precondition", "postcondition")
# Whole-word termination kinds at the start of the report `kind` (`loop variant`, `loop_variant`,
# `variant`, `decreases`, `decreases clause`); never matches `loop invariant` or `termination clause`.
_TERMINATION_KIND_RE = re.compile(r"^(?:(?:loop[\s_]+)?variant|decreases)\b")
# For unlabeled / synthetic `assertion` items (e.g. ledger proof_gap/fault_hypothesis predicates):
# requires whitespace or end-of-string after the keyword so clause labels (`decreases:` / `decreases_len:`)
# are not misclassified.
_TERMINATION_CLAUSE_RE = re.compile(r"^(?:loop[\s_]+variant|decreases)(?:\s|$)")


_BITWISE_GOAL_RE = re.compile(
    r"\b(?:shift|lsr|lsl|land|lor|lxor|bit_test|bw_)\b|(?:<<|>>|\^|~\s*[A-Za-z0-9_(])",
    re.IGNORECASE,
)
_BITWISE_LOG_RE = re.compile(
    r"\b(?:lsr|lsl|land|lor|lxor|bit_test|shift_left|shift_right|rte_shift)\b",
    re.IGNORECASE,
)
_WP_ALLOC_UNSUPPORTED_RE = re.compile(
    r"\\(?:freeable|fresh|allocable|allocation)\b|\b(?:freeable|allocates|frees)\b",
    re.IGNORECASE,
)
_WP_WARN_FN_RE = re.compile(
    r"\b(?:(?:for|in|of)\s+function|specification\s+for)\s+'?(?P<fn>[A-Za-z_]\w*)'?(?=[\s.,;:)]|$)"
)
_LIBC_ALLOC_FNS = frozenset({"malloc", "calloc", "realloc", "free", "aligned_alloc", "valloc", "pvalloc"})
_PROJECT_HEADER_SUFFIXES = (".h", ".hh", ".hpp", ".hxx", ".h++", ".inc")


def _is_alloc_limitation_goal(item: dict) -> bool:
    text = f"{item.get('kind') or ''} {item.get('annotation') or ''}"
    return bool(_WP_ALLOC_UNSUPPORTED_RE.search(text))


def _is_libc_header(path: str) -> bool:
    norm = posixpath.normpath(path.replace("\\", "/")).lower()
    return (
        posixpath.basename(norm) == "stdlib.h"
        or "/libc/" in norm
        or norm.startswith("framac_share/libc/")
        or norm.startswith("/usr/include/")
    )


def _warn_file_matches_target(msg_file: str, target_file: str) -> bool:
    if not msg_file or not target_file:
        return True
    m_norm = posixpath.normpath(msg_file.replace("\\", "/"))
    t_norm = posixpath.normpath(target_file.replace("\\", "/"))
    if m_norm == t_norm or t_norm.endswith("/" + m_norm) or m_norm.endswith("/" + t_norm):
        return True
    if posixpath.basename(m_norm) == posixpath.basename(t_norm):
        return True
    # A function's contract may live in a project header rather than its .c file.
    return posixpath.splitext(m_norm)[1].lower() in _PROJECT_HEADER_SUFFIXES


def _is_alloc_warning_for_function(msg_plugin: str, msg_file: str, folded: str, res: dict) -> bool:
    """True when a WP skipped/ignored allocation warning is tied to the function under proof."""
    if msg_plugin not in ("wp", "") or not _WP_ALLOC_UNSUPPORTED_RE.search(folded):
        return False
    fn = str(res.get("function") or "").strip()
    fn_m = _WP_WARN_FN_RE.search(folded)
    if fn_m:
        named_fn = fn_m.group("fn")
        return named_fn == fn if fn else named_fn not in _LIBC_ALLOC_FNS
    if msg_file and _is_libc_header(msg_file):
        return False
    return _warn_file_matches_target(msg_file, str(res.get("file") or "").strip())


def _classify_skipped_spec_messages(res: dict, log_text: str) -> tuple[list[str], list[str]]:
    """
    Partition skipped/ignored specification warnings in `soundness.tier_b_unsound` and the WP log
    into `(alloc_skipped_for_fn, other_skipped)`.

    - `alloc_skipped_for_fn`: WP `not yet supported (skipped)` / `Ignoring` warnings about dynamic
      allocation clauses tied to the function under proof (not unrelated `stdlib.h` / libc mentions).
    - `other_skipped`: non-allocation `not yet supported (skipped)` / `Ignoring` warnings.
    """
    soundness = res.get("soundness") or {}
    raw_chunks = [*(soundness.get("tier_b_unsound") or []), log_text or "", res.get("wp_log_tail") or ""]
    alloc_skipped: list[str] = []
    other_skipped: list[str] = []
    seen: set[str] = set()
    for chunk in raw_chunks:
        for m in fold_messages(str(chunk or "")):
            if m.folded in seen:
                continue
            seen.add(m.folded)
            if "not yet supported (skipped)" not in m.folded and "Ignoring " not in m.folded:
                continue
            if m.plugin in ("wp", "") and _WP_ALLOC_UNSUPPORTED_RE.search(m.folded):
                if _is_alloc_warning_for_function(m.plugin, m.file, m.folded, res):
                    alloc_skipped.append(m.folded)
            else:
                other_skipped.append(m.folded)
    return alloc_skipped, other_skipped


_POINTER_CAST_RE = re.compile(
    r"\(\s*(?:const\s+)?(?:struct\s+|union\s+|enum\s+)?[A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)*\s*\*+\s*\)"
)


def _is_pointer_cast_goal(item: dict) -> bool:
    """An unproven goal whose annotation casts between pointer types, e.g. `(void *)attr + 4`."""
    return bool(_POINTER_CAST_RE.search(str(item.get("annotation") or "")))


# The automatic retry under WP's byte-level model (run_wp_on_function, retry_bytes). QCBOR run-6: the
# `memcpy` type puns and union-writing decoders that stall or are unsound under `Typed` proved under it.
BYTES_RETRY_MODEL = "Bytes"
_BYTES_RETRY_SUFFIX = "_bytes"
_UNION_UNSOUND_RE = re.compile(r"Accessing union fields with \w+ model might be unsound", re.IGNORECASE)
_INCOMPATIBLE_CAST_RE = re.compile(r"Cast with incompatible pointers types")
_MEM_BUILTIN_PRECOND_RE = re.compile(r"precondition of (?:memcpy|memmove|memcmp|memset)\b", re.IGNORECASE)


def _bytes_retry_trigger(res: dict, log_text: str) -> str | None:
    """
    Why a `Typed` verdict that is not all_proven is worth one retry under `Bytes`, or None. Only for the
    obstacles `Bytes` can remove: `union` when soundness fails solely on WP's union warning, or
    `pointer_cast` when the run is sound (or aborted solely on a Why3 anomaly during Typed pointer-cast
    translation) and the unproven/failed goals come from byte-wise casts (the cast probe proved everything,
    WP warned `Cast with incompatible pointers types`, or every unproven goal is a `memcpy`-style builtin
    precondition or a pointer-cast annotation).
    """
    soundness = res.get("soundness") or {}
    if res.get("budget_exhausted"):
        return None
    tier_a = list(soundness.get("tier_a_aborts") or [])
    if tier_a and not all(_WHY3_ANOMALY_RE.search(msg) for msg in tier_a):
        return None
    unsound = list(soundness.get("tier_b_unsound") or [])
    if unsound:
        if tier_a:
            return None
        return "union" if all(_UNION_UNSOUND_RE.search(msg) for msg in unsound) else None
    goals = res.get("unproven_goals") or []
    if not goals and not tier_a:
        return None
    if (
        res.get("wp_cast_limitation")
        or _INCOMPATIBLE_CAST_RE.search(log_text or "")
        or (
            goals
            and all(_MEM_BUILTIN_PRECOND_RE.search(str(g.get("kind") or "")) or _is_pointer_cast_goal(g) for g in goals)
        )
    ):
        return "pointer_cast"
    return None


def decide_bytes_retry(typed_status: str, typed_unproven: int, typed_sound: bool, bytes_res: dict) -> tuple[bool, str]:
    """(kept, reason): the `Bytes` result replaces the `Typed` one only when it is sound and strictly better."""
    status = bytes_res.get("status")
    soundness = bytes_res.get("soundness") or {}
    union = [m for m in soundness.get("tier_b_unsound") or [] if _UNION_UNSOUND_RE.search(m)]
    if union:
        return False, f"union access still unsound under Bytes: {union[0]}"
    if status not in ("all_proven", "unproven_goals_remain", "unsound_proof"):
        reason = f": {bytes_res['reason']}" if bytes_res.get("reason") else ""
        return False, f"the Bytes run decided nothing (status {status!r}{reason})"
    if not soundness.get("ok", False):
        return False, "the Bytes run is not sound: " + "; ".join(
            [*(soundness.get("tier_a_aborts") or []), *(soundness.get("tier_b_unsound") or [])]
        )[:300]
    bytes_unproven = int(bytes_res.get("unproven_count") or 0)
    if bytes_unproven < typed_unproven:
        return True, f"Bytes leaves {bytes_unproven} goal(s) unproven, Typed {typed_unproven}"
    if not typed_sound:
        return True, f"Bytes is sound where Typed was not ({typed_status})"
    return False, f"Bytes is not better: {bytes_unproven} goal(s) unproven, Typed {typed_unproven}"


def _locate_agent_scratch_dir(c_file: Path, out_dir: Path) -> Path | None:
    """If `c_file` or `out_dir` is inside `.../agents/<agent_id>/scratch/...`, return that `scratch` dir."""
    for candidate in (c_file, out_dir):
        parts = candidate.parts
        for idx, part in enumerate(parts):
            if part == "agents" and idx + 2 < len(parts) and parts[idx + 2] == "scratch":
                return Path(*parts[: idx + 3])
    return None


def _is_synthetic_probe_file(c_file: Path, scratch_dir: Path | None) -> bool:
    """True when `c_file` is a synthetic `probe_*.c` file or sits in `agents/<id>/scratch` outside `scratch/work`."""
    if c_file.name.lower().startswith("probe_"):
        return True
    if scratch_dir is None:
        return False
    try:
        rel = c_file.resolve(strict=False).relative_to(scratch_dir.resolve(strict=False))
    except ValueError:
        return False
    return not rel.parts or rel.parts[0] != "work"


def _lease_wait_from_env() -> tuple[str, float] | None:
    """(lease id, queued seconds) of the host lease this container runs under, or None when unknown.

    `resources.py exec` passes FRAMAC_LEASE_ID and FRAMAC_LEASE_WAITED_S into the container. Without
    both (no broker, an older wrapper, a garbled value) the wait is unknown and nothing is credited.
    """
    lease_id = (os.environ.get("FRAMAC_LEASE_ID") or "").strip()
    raw = (os.environ.get("FRAMAC_LEASE_WAITED_S") or "").strip()
    if not lease_id or not raw:
        return None
    try:
        waited = float(raw)
    except ValueError:
        return None
    if not math.isfinite(waited) or waited < 0:
        return None
    return lease_id, waited


# Lease ids already credited to a prover budget are kept to this many, newest last.
_CREDITED_LEASES_KEPT = 64


def _prover_budget_lease_wait(budget_data: dict, since_first_s: float, first_call: bool) -> float:
    """Seconds queued for WP leases since `first_wp_at`, to leave out of the prover's wall budget.

    Accumulates `lease_wait_s` in `budget_data` (the `.prover_budget.json` payload, updated in
    place). The first call's lease wait came before `first_wp_at` and is never credited; each lease
    is credited once (`lease_wait_credited`), even if one container runs the script twice. The
    total never exceeds the time since `first_wp_at`.
    """
    stored = budget_data.get("lease_wait_s")
    total = 0.0
    if isinstance(stored, (int, float)) and not isinstance(stored, bool) and math.isfinite(stored) and stored > 0:
        total = float(stored)
    raw_credited = budget_data.get("lease_wait_credited")
    credited = [x for x in raw_credited if isinstance(x, str)] if isinstance(raw_credited, list) else []
    lease = _lease_wait_from_env()
    if lease is not None and lease[0] not in credited:
        if not first_call:
            total += lease[1]
        credited = [*credited, lease[0]][-_CREDITED_LEASES_KEPT:]
        budget_data["lease_wait_credited"] = credited
    total = min(total, max(0.0, since_first_s))
    if total > 0 or "lease_wait_s" in budget_data:
        budget_data["lease_wait_s"] = round(total, 1)
    return total


# soundness.reduced_checks of a run with --waive-signed-downcast. workspace_overlay replays the flag for
# a reduced check containing `-warn-signed-downcast OFF`, and the ledger records it as an assumption.
SIGNED_DOWNCAST_WAIVED = "-warn-signed-downcast OFF on declared wrap lines"


def scan_wp_log_soundness(
    log_text: str,
    check_memory_model: bool = True,
    unsigned_reduced: bool = False,
    warn_invalid_pointer: bool = True,
    warn_unsigned_downcast: bool = True,
    warn_signed_downcast: bool = True,
) -> dict:
    """
    Scan Frama-C WP log output for Tier-A aborts, Tier-B silent unsoundness,
    memory-model separation hypotheses, skipped RTE guards, and degenerated
    function-pointer value goals (`\\valid_function`).
    """
    messages = fold_messages(log_text)
    tier_a_set = {m.folded for m in messages if _TIER_A_RE.search(m.folded) or _WHY3_ANOMALY_RE.search(m.folded)}
    if not any(_WHY3_ANOMALY_RE.search(msg) for msg in tier_a_set):
        for m_anom in _WHY3_ANOMALY_RE.finditer(log_text or ""):
            tier_a_set.add(m_anom.group(0).strip())
    tier_a_aborts = sorted(tier_a_set)
    tier_b_unsound_set = {m.folded for m in messages if any(p in m.folded for p in _TIER_B_PATTERNS)}
    for m in messages:
        specs = parse_missing_spec(m.folded)
        if any(not s.benign for s in specs):
            tier_b_unsound_set.add(m.folded)
    for m in messages:
        if _SMOKE_FAIL_RE.search(m.folded):
            tier_b_unsound_set.add(m.folded)
    for m_smoke in _SMOKE_FAIL_RE.finditer(log_text):
        tier_b_unsound_set.add(m_smoke.group(1).strip())

    mm_functions = sorted({m.group(1) for msg in messages for m in _MM_HYP_RE.finditer(msg.folded)})
    mm_reqs_by_fn: dict[str, list[str]] = {fn: [] for fn in mm_functions}
    for msg in messages:
        for m_blk in _MM_HYP_BLOCK_RE.finditer(msg.folded):
            fn_name = m_blk.group(1)
            bucket = mm_reqs_by_fn.setdefault(fn_name, [])
            for req in _MM_REQ_CLAUSE_RE.findall(m_blk.group(2)):
                cleaned = " ".join(req.split())
                if cleaned and cleaned not in bucket:
                    bucket.append(cleaned)
    checked_mm_hyps = [{"function": fn, "requires": mm_reqs_by_fn.get(fn, [])} for fn in mm_functions]
    if mm_functions and not check_memory_model:
        tier_b_unsound_set.add(
            f"Memory model hypotheses for function(s) {', '.join(mm_functions)} unchecked (-wp-no-check-memory-model)"
        )

    skipped_rte = sorted(
        {
            (m.group(1) or m.group(2) or "").strip()
            for msg in messages
            for m in _SKIPPED_RTE_RE.finditer(msg.folded)
            if (m.group(1) or m.group(2))
        }
    )
    if skipped_rte and _INDIRECT_CALL_UNSOUND_RE.search(log_text):
        tier_b_unsound_set.add(
            "indirect call present without '//@ calls' while \\valid_function RTE guards are skipped"
        )

    fpv_goals = sorted({m.group(1) for m in _FPV_DEGEN_RE.finditer(log_text)})

    reduced_checks: list[str] = []
    if unsigned_reduced:
        reduced_checks.append("-warn-unsigned-overflow / -warn-unsigned-downcast OFF")
    elif not warn_unsigned_downcast:
        reduced_checks.append("-no-warn-unsigned-downcast")
    if not warn_invalid_pointer:
        reduced_checks.append("-warn-invalid-pointer OFF")
    if not warn_signed_downcast:
        reduced_checks.append(SIGNED_DOWNCAST_WAIVED)

    tier_b_unsound = sorted(tier_b_unsound_set)
    return {
        "ok": len(tier_a_aborts) == 0 and len(tier_b_unsound) == 0,
        "tier_a_aborts": tier_a_aborts,
        "tier_b_unsound": tier_b_unsound,
        "checked_memory_model_functions": mm_functions if check_memory_model else [],
        "checked_memory_model_hypotheses": checked_mm_hyps if check_memory_model else [],
        "skipped_rte_guards": skipped_rte,
        "assumed_function_pointer_goals": fpv_goals,
        "reduced_checks": reduced_checks,
    }


def _is_excluded_target_scan_path(path: Path) -> bool:
    """True when `path` sits in Frama-C's `share/libc`, `/usr/`, or `templates/fc_stubs/`."""
    for candidate in (path, path.resolve(strict=False)):
        norm = candidate.as_posix().lower()
        if (
            norm.startswith("/usr/")
            or "/share/libc/" in norm
            or "/share/frama-c/libc/" in norm
            or "/frama-c/libc/" in norm
            or "/templates/fc_stubs/" in norm
            or norm.startswith("templates/fc_stubs/")
            or norm.startswith("framac_share/libc/")
        ):
            return True
    fc_stubs = resolve_fc_stubs_dir()
    if fc_stubs is not None:
        with contextlib.suppress(ValueError, OSError):
            path.resolve(strict=False).relative_to(fc_stubs.resolve(strict=False))
            return True
    return False


def _extract_target_include_dirs(cppflags: str) -> list[Path]:
    """Extract `-iquote` and `-I` include directories from `cppflags` in search order."""
    if not cppflags or not cppflags.strip():
        return []
    try:
        tokens = shlex.split(cppflags, posix=(os.name != "nt"))
    except ValueError:
        tokens = cppflags.split()
    if os.name == "nt":
        tokens = [t[1:-1] if len(t) >= 2 and t[0] == t[-1] and t[0] in ("'", '"') else t for t in tokens]
    iquote_dirs: list[Path] = []
    inc_dirs: list[Path] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok == "-iquote" and i + 1 < len(tokens):
            iquote_dirs.append(Path(tokens[i + 1]))
            i += 2
        elif tok.startswith("-iquote") and len(tok) > len("-iquote"):
            iquote_dirs.append(Path(tok[len("-iquote") :]))
            i += 1
        elif tok == "-I" and i + 1 < len(tokens):
            inc_dirs.append(Path(tokens[i + 1]))
            i += 2
        elif tok.startswith("-I") and len(tok) > 2:
            inc_dirs.append(Path(tok[2:]))
            i += 1
        else:
            i += 1
    return iquote_dirs + inc_dirs


def collect_target_sources_in_scope(
    c_file: Path,
    extra_sources: list[str] | None = None,
    cppflags: str = "",
    max_files: int = 512,
) -> list[Path]:
    """
    Collect target source files in scope for `-wp-fct`: `c_file`, `extra_sources`, plus recursively
    resolved local quoted `#include "..."` headers inside the target tree, strictly excluding
    Frama-C's `share/libc`, `/usr/`, and `templates/fc_stubs/`.
    """
    include_dirs = [d for d in _extract_target_include_dirs(cppflags) if not _is_excluded_target_scan_path(d)]
    queue: list[Path] = [Path(c_file), *(Path(s) for s in (extra_sources or []))]
    seen: set[Path] = set()
    collected: list[Path] = []

    while queue and len(collected) < max_files:
        cur = queue.pop(0)
        if _is_excluded_target_scan_path(cur):
            continue
        if not cur.is_file():
            continue
        resolved = cur.resolve(strict=False)
        if resolved in seen:
            continue
        seen.add(resolved)
        collected.append(cur)
        try:
            raw = cur.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        masked = mask_comments_and_literals(raw, acsl="blank", literals=False, on_error="mask")
        for inc in _QUOTED_INCLUDE_RE.findall(masked):
            search_roots = [cur.parent, *include_dirs]
            for root in search_roots:
                cand = root / inc
                if cand.is_file() and not _is_excluded_target_scan_path(cand):
                    if cand.resolve(strict=False) not in seen:
                        queue.append(cand)
                    break
    return collected


def scan_target_sources_soundness(
    c_file: Path,
    extra_sources: list[str] | None = None,
    cppflags: str = "",
) -> tuple[list[str], list[str]]:
    """
    Scan target source files in scope for constructs that Frama-C 34 `-wp-fct` silently assumes
    without emitting `-report-csv` rows:
    1. Top-level global `lemma` declarations (never proved by `-wp-fct`, yet assumed as axioms).
    2. Target-file `axiom` / `axiomatic` / `admit` constructs.
    3. Non-well-founded recursive `logic` / `predicate` definitions.
    Returns `(tier_b_issues, target_lemma_names)`.
    """
    tier_b_issues: list[str] = []
    target_lemmas: list[str] = []
    for path in collect_target_sources_in_scope(c_file, extra_sources=extra_sources, cppflags=cppflags):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        path_str = str(path)
        with contextlib.suppress(AcslError):
            target_lemmas.extend(find_top_level_lemmas(text, path=path_str))
        with contextlib.suppress(AcslError):
            tier_b_issues.extend(find_target_unsound_axioms_or_admits(text, path=path_str))
        with contextlib.suppress(AcslError):
            tier_b_issues.extend(find_unsound_recursive_logic(text, path=path_str))
    unique_lemmas = list(dict.fromkeys(target_lemmas))
    if unique_lemmas:
        shown = ", ".join(unique_lemmas[:10])
        suffix = f" (+{len(unique_lemmas) - 10} more)" if len(unique_lemmas) > 10 else ""
        tier_b_issues.append(
            f"Unproven lemma(s) in scope ({shown}{suffix}): "
            "-wp-fct does not prove global lemmas yet WP assumes them as hypotheses"
        )
    return list(dict.fromkeys(tier_b_issues)), unique_lemmas


def extract_vc_goal_dumps(log_text: str, max_dumps: int = 5) -> list[str]:
    """Extract raw verification condition (`Assume` / `Prove`) dumps from `-wp-print` output."""
    dumps = [m.group(1).strip() for m in _VC_DUMP_RE.finditer(log_text)]
    return dumps[:max_dumps]


_PLUGIN_USER_ERROR_RE = re.compile(
    r"^\[(?!kernel\b)[A-Za-z][\w-]*(?::[^\]]*)?\][^\n]*user error", re.IGNORECASE | re.MULTILINE
)


# The kernel's message when the preprocessor command itself fails (missing header, bad include path).
_PREPROCESS_FAILED_RE = re.compile(r"^\[kernel\][^\n]*User Error: failed to run:", re.IGNORECASE | re.MULTILINE)
PREPROCESSING_FAILED = "preprocessing_failed"
# A comment (an annotation, in practice) without its closing `*/`: the main `gcc -E` fails, but the
# file's own text is at fault, not the build configuration.
_UNTERMINATED_COMMENT_RE = re.compile(r"\berror:\s*unterminated comment\b", re.IGNORECASE)


def _cpp_error_lines(log_text: str) -> list[str]:
    """The preprocessor's own `file:line:col: [fatal] error:` lines, in order."""
    return [line.strip() for line in (log_text or "").splitlines() if _CPP_ERROR_RE.match(line)]


def _preprocess_failure(
    log_text: str, returncode: int | None, timed_out: bool, report_exists: bool
) -> tuple[str, list[str]] | None:
    """
    (reason, errors) when the run stopped because `gcc -E` failed, else None. A build-configuration
    error (wrong or missing --cppflags), never an ACSL syntax error: the annotations were not read.
    An unterminated comment is the exception: it is a typo in the source (an annotation missing its
    `*/`), so it stays an ACSL syntax error (None here).
    """
    if timed_out or returncode in (0, None) or report_exists or not _PREPROCESS_FAILED_RE.search(log_text or ""):
        return None
    cpp_lines = _cpp_error_lines(log_text)
    if cpp_lines and _UNTERMINATED_COMMENT_RE.search(cpp_lines[0]):
        return None
    errors = list(dict.fromkeys([*cpp_lines, *kernel_parse_errors(log_text)]))
    first = cpp_lines[0] if cpp_lines else "the C preprocessor (gcc -E) failed"
    return f"{PREPROCESSING_FAILED}: {first}"[:300], errors


def _folded_syntax_errors(
    log_text: str, returncode: int | None, timed_out: bool, report_exists: bool
) -> list[str] | None:
    """Errors when the run stopped in the kernel (parsing/typing) before WP started, else None."""
    if timed_out or returncode in (0, None) or report_exists:
        return None
    if _PLUGIN_USER_ERROR_RE.search(log_text or ""):
        return None  # WP (or another plug-in) refused the function: a Tier-A abort, not a syntax error
    errors = kernel_parse_errors(log_text)
    if errors and _PREPROCESS_FAILED_RE.search(log_text or ""):
        # The preprocessor's own message names the file and line; the kernel's only the command.
        errors = list(dict.fromkeys([*_cpp_error_lines(log_text), *errors]))
    return errors or None


def resolve_wp_par(value: int | str | None) -> int:
    """`auto` (or None/0): concurrent provers sized from this job's budget; otherwise the given count."""
    if value is None or (isinstance(value, str) and value.strip().lower() == "auto"):
        return wp_parallelism()
    count = int(value)
    return count if count > 0 else wp_parallelism()


def resolve_wp_cache_dir(value: str | Path | None) -> Path | None:
    """`auto`: <run>/state/cache/wp when caching is enabled; `off`/None: no cache; else that directory."""
    if value is None or cache.forced_off():
        return None
    text = str(value).strip()
    if text.lower() == "off" or not text:
        return None
    if text.lower() == "auto":
        return cache.wp_cache_dir()
    path = Path(text)
    path.mkdir(parents=True, exist_ok=True)
    return path


def default_wall_timeout(cli_value: int | None) -> int | None:
    """--wall-timeout, else FRAMAC_WP_WALL_TIMEOUT, else the `wp` job class limit; 0 means none."""
    if cli_value is not None:
        return cli_value or None
    raw = (os.environ.get("FRAMAC_WP_WALL_TIMEOUT") or "").strip()
    if raw:
        try:
            return int(float(raw)) or None
        except ValueError:
            pass
    return CLASSES["wp"].wall_timeout_s


def classify_unproven_goal(row: dict) -> str:
    prop = ((row.get("kind") or "") + " " + (row.get("annotation") or "")).lower()
    if "assigns" in prop:
        return "step_a_assigns"
    if "invariant" in prop or "variant" in prop or "decreases" in prop:
        return "step_b_loop_invariant"
    if "rte:" in prop:
        return "step_c_rte_obligation"
    if "requires" in prop or "precondition" in prop:
        return "step_c_caller_precondition"
    return "step_c_contract_postcondition"


def _has_bitwise_unproven_goals(unproven_goals: list[dict], combined_log: str) -> bool:
    for g in unproven_goals:
        text = f"{g.get('kind') or ''} {g.get('annotation') or ''}"
        if _BITWISE_GOAL_RE.search(text):
            return True
    if _BITWISE_LOG_RE.search(combined_log):
        return True
    return False


_EATEN_BACKSLASH_RE = re.compile(
    r"unbound logic variable\s+(?:alse|rue|orall|xists|alid|alid_read|esult|othing|eparated|ld|t|nitialized)\b"
    r"|invalid character|unexpected token.*\\x0",
    re.IGNORECASE,
)
_CLAUSE_ORDER_ERR_RE = re.compile(
    r"wrong order of clause|"
    r"(?:syntax error|unexpected token).*?\b(?:terminates|decreases|exits|assigns|ensures|requires|behavior|loop\s+variant|loop\s+assigns|loop\s+invariant)\b",
    re.IGNORECASE,
)
# Frama-C 34+ rejects `behavior b: ;` with: Failure: unexpected token ';'
_EMPTY_BEHAVIOR_ERR_RE = re.compile(r"unexpected token\s+';'", re.IGNORECASE)
_C_TYPE_OR_CALL_ERR_RE = re.compile(
    r"unbound logic function|not a logic type|C functions cannot be called|"
    r"\\(?:forall|exists)\s+(?:int|unsigned|size_t|long|short|char|uint\d+_t|int\d+_t)\b",
    re.IGNORECASE,
)
_BOOL_PRED_ERR_RE = re.compile(
    r"expected a (?:predicate|boolean|term)|invalid implicit conversion from .* to boolean",
    re.IGNORECASE,
)
_LOOP_ESTABLISHED_FAIL_RE = re.compile(
    r"^\[wp\]\s*\[(?:Timeout|Unknown|Failed|Stepout)\][^\n]*loop_invariant[^\n]*established",
    re.IGNORECASE | re.MULTILINE,
)
_LOOP_PRESERVED_FAIL_RE = re.compile(
    r"^\[wp\]\s*\[(?:Timeout|Unknown|Failed|Stepout)\][^\n]*loop_invariant[^\n]*preserved",
    re.IGNORECASE | re.MULTILINE,
)
_VARIADIC_CALLEE_RE = re.compile(
    r"(?:variadic|varargs|variable argument|\bva_list\b|unframed\s+variadic)",
    re.IGNORECASE,
)
_WHY3_MEMADDR_ERR_RE = re.compile(
    r"\[Why3 Error\]\s*Type mismatch between\s+frama_c_wp\.memaddr\.MemAddr\.addr\s+and\s+int",
    re.IGNORECASE,
)
_PTR_DIFF_EQ_RE = re.compile(
    r"(?:-\s*[A-Za-z_]\w*\s*==\s*0\s*==>\s*[A-Za-z_]\w*\s*==|"
    r"[A-Za-z_]\w*\s*!=\s*[A-Za-z_]\w*\s*==>\s*[A-Za-z_]\w*\s*-\s*[A-Za-z_]\w*\s*>\s*0|"
    r"\\base_addr\s*\()"
)
_MISSING_ASSIGNS_LINE_RE = re.compile(
    r"(?<![\w./-])([^\s:]+\.[ch]):(\d+):(?:\d+:)?\s*Warning:\s*Missing assigns clause"
)
# WP's own word that a function has no frame: `[wp:pedantic-assigns] f.c:12: Warning: No 'assigns' specification
# for function 'f'. Callers assumptions might be imprecise.` It is printed for the function under proof and for
# each defined callee in that state, so it is matched by name.
_NO_ASSIGNS_SPEC_RE = re.compile(r"No 'assigns' specification for function '([^']+)'")
# One function's section of the `-report` output and its function-level assigns properties: `Assigns nothing`,
# `Assigns ("f.c", line 3)`, `Assigns for 'b' ...`. `Loop assigns` is the frame of a loop, not of the function.
_REPORT_SECTION_RE = re.compile(
    r"^--- Properties of Function '([^'\n]+)'\n-+\n(.*?)(?=^-{20,}\n--- |\Z)", re.MULTILINE | re.DOTALL
)
_REPORT_ASSIGNS_RE = re.compile(r"^\[[^\]\n]*\] Assigns\b(?: for '([^']+)')?", re.MULTILINE)
ASSIGNS_PRESENT = "present"
ASSIGNS_BEHAVIORS_ONLY = "behaviors_only"
ASSIGNS_ABSENT = "absent"
ASSIGNS_UNKNOWN = "unknown"
_WP_PROVED_GOALS_RE = re.compile(r"^\s*(?:\[wp\]\s*)?Proved goals:\s*(\d+)\s*/\s*(\d+)", re.MULTILINE)
_WP_TIMEOUT_COUNT_RE = re.compile(r"^(?:\[wp\])?\s*Timeout:\s*(\d+)", re.MULTILINE)
_WP_GOALS_SCHEDULED_RE = re.compile(r"^\[wp\]\s+(\d+)\s+goals?\s+scheduled\b", re.MULTILINE)
_PARTIAL_WP_GOAL_COLON_RE = re.compile(
    r"^\[wp\]\s+\[[^\]\n]+\]\s+Goal\s+([A-Za-z_]\w*)\s*:\s*"
    r"(Valid|Proved|Timeout|Stepout|Step\s+limit|Unknown|Failed|Failure|Invalid|Unsuccess|Incorrect)\b(.*)$"
)
_PARTIAL_WP_BRACKET_RE = re.compile(
    r"^\[wp\]\s+\[(Valid|Proved|Timeout|Stepout|Step\s+limit|Unknown|Failed|Failure|Invalid|Unsuccess|Incorrect)\]\s+"
    r"([A-Za-z_]\w*)(.*)$"
)
_PARTIAL_VERDICT_CATEGORY: dict[str, str] = {
    "valid": "proved",
    "proved": "proved",
    "timeout": "timed_out",
    "stepout": "timed_out",
    "step limit": "timed_out",
    "unknown": "unknown",
    "failed": "failed",
    "failure": "failed",
    "invalid": "failed",
    "unsuccess": "failed",
    "incorrect": "failed",
}
_PARTIAL_VERDICT_PRIORITY: dict[str, int] = {
    "unknown": 1,
    "timed_out": 2,
    "failed": 3,
    "proved": 4,
}
_PARTIAL_VERDICTS_MAX_GOALS = 25


def parse_partial_wp_log_verdicts(log_text: str) -> dict[str, Any] | None:
    """
    Salvage incremental VC verdicts logged by Frama-C WP before the process was killed (e.g. timeout
    or OOM) and never wrote `-report-csv`.

    Returns None when neither `[wp] N goals scheduled` nor any per-VC verdict line appears in `log_text`.
    All counts reflect VCs (not CSV properties) and carry `incomplete: True` so downstream ledger
    ingestion never mistakes them for a verified proof report.
    """
    if not log_text:
        return None

    scheduled_vcs: int | None = None
    for m in _WP_GOALS_SCHEDULED_RE.finditer(log_text):
        scheduled_vcs = int(m.group(1))

    verdicts_by_goal: dict[str, tuple[str, bool]] = {}
    for line in log_text.splitlines():
        if not line.startswith("[wp]"):
            continue
        goal: str | None = None
        raw_verdict: str | None = None
        tail = ""
        m_colon = _PARTIAL_WP_GOAL_COLON_RE.match(line)
        if m_colon:
            goal = m_colon.group(1)
            raw_verdict = m_colon.group(2)
            tail = m_colon.group(3)
        else:
            m_bracket = _PARTIAL_WP_BRACKET_RE.match(line)
            if m_bracket:
                raw_verdict = m_bracket.group(1)
                goal = m_bracket.group(2)
                tail = m_bracket.group(3)
        if not goal or not raw_verdict:
            continue
        norm_verdict = re.sub(r"\s+", " ", raw_verdict.strip().lower())
        category = _PARTIAL_VERDICT_CATEGORY.get(norm_verdict)
        if category is None:
            continue
        tags = [t.strip() for t in _PAREN_TAG_RE.findall(tail)]
        cached = "Cached" in tags
        prev = verdicts_by_goal.get(goal)
        if prev is None:
            verdicts_by_goal[goal] = (category, cached)
        else:
            prev_cat, prev_cached = prev
            if _PARTIAL_VERDICT_PRIORITY[category] > _PARTIAL_VERDICT_PRIORITY[prev_cat]:
                verdicts_by_goal[goal] = (category, cached)
            elif category == prev_cat:
                verdicts_by_goal[goal] = (prev_cat, prev_cached or cached)

    proved_vcs = 0
    timed_out_vcs = 0
    unknown_vcs = 0
    failed_vcs = 0
    cached_vcs = 0
    cached_timed_out_vcs = 0
    timed_out_goals: list[str] = []
    unknown_goals: list[str] = []
    failed_goals: list[str] = []

    for goal, (category, cached) in verdicts_by_goal.items():
        if cached:
            cached_vcs += 1
        if category == "proved":
            proved_vcs += 1
        elif category == "timed_out":
            timed_out_vcs += 1
            if cached:
                cached_timed_out_vcs += 1
            if len(timed_out_goals) < _PARTIAL_VERDICTS_MAX_GOALS:
                timed_out_goals.append(goal)
        elif category == "unknown":
            unknown_vcs += 1
            if len(unknown_goals) < _PARTIAL_VERDICTS_MAX_GOALS:
                unknown_goals.append(goal)
        elif category == "failed":
            failed_vcs += 1
            if len(failed_goals) < _PARTIAL_VERDICTS_MAX_GOALS:
                failed_goals.append(goal)

    # If WP finished proving and printed its summary right before being killed during `-report-csv`,
    # recover the proved count (Frama-C 34 does not print individual `[Valid]` lines in batch mode).
    proved_m = _WP_PROVED_GOALS_RE.search(log_text)
    if proved_m:
        summary_proved = int(proved_m.group(1))
        summary_total = int(proved_m.group(2))
        if summary_proved > proved_vcs:
            proved_vcs = summary_proved
        if scheduled_vcs is None or summary_total > scheduled_vcs:
            scheduled_vcs = summary_total

    completed_vcs = proved_vcs + timed_out_vcs + unknown_vcs + failed_vcs
    if scheduled_vcs is None and completed_vcs == 0:
        return None

    return {
        "incomplete": True,
        "scheduled_vcs": scheduled_vcs,
        "completed_vcs": completed_vcs,
        "proved_vcs": proved_vcs,
        "timed_out_vcs": timed_out_vcs,
        "unknown_vcs": unknown_vcs,
        "failed_vcs": failed_vcs,
        "cached_vcs": cached_vcs,
        "cached_timed_out_vcs": cached_timed_out_vcs,
        "timed_out_goals": timed_out_goals,
        "unknown_goals": unknown_goals,
        "failed_goals": failed_goals,
    }


def frame_clause_state(log_text: str, fn_name: str) -> dict:
    """
    Whether the contract WP proved for `fn_name` has an `assigns` clause, read from Frama-C's own output and
    never from the source, so a contract on a header prototype or merged from several declarations counts as
    Frama-C sees it. `assigns_clause` is:

    - `absent`: WP printed `No 'assigns' specification for function '<fn_name>'` and the function's section of
      the `-report` output lists no assigns property (no contract, or a contract without `assigns`);
    - `behaviors_only`: WP printed that warning and the report lists `Assigns for '<behavior>'` properties: the
      named behaviors that have a clause (`assigns_behaviors`) do not cover the function, either because they
      are not `complete` or because one of the complete behaviors has none;
    - `present`: no such warning, and the report lists an assigns property of the function (`assigns \\nothing`
      is one; so are complete behaviors that each have a clause, which WP takes as the function's frame);
    - `unknown`: neither. WP prints the warning whenever it generates at least one goal for the function, also
      under a `-wp-prop` filter, and `-report` leaves out a property nothing tried. So a filter that selects no
      goal, a filtered run that left out the assigns goals of a function that has a clause, and a log without
      a report end here.

    `assigns_clause_basis` names the output the answer rests on.
    """
    warned = any(m.plugin == "wp" and fn_name in _NO_ASSIGNS_SPEC_RE.findall(m.text) for m in fold_messages(log_text))
    section = next((m.group(2) for m in _REPORT_SECTION_RE.finditer(log_text or "") if m.group(1) == fn_name), "")
    listed = [m.group(1) for m in _REPORT_ASSIGNS_RE.finditer(section)]
    behaviors = sorted({name for name in listed if name})
    if warned:
        state, basis = (ASSIGNS_BEHAVIORS_ONLY if behaviors else ASSIGNS_ABSENT), "wp_no_assigns_warning"
    elif listed:
        state, basis = ASSIGNS_PRESENT, "property_report"
    else:
        state, basis = ASSIGNS_UNKNOWN, None
    return {"assigns_clause": state, "assigns_clause_basis": basis, "assigns_behaviors": behaviors}


# WP gives a `void` object the size of an `int` (plugins/wp/src/ctypes.ml) and says so where a term needs that
# size: `[wp] f.c:17: Warning: void object`. A goal that depends on it can be proved although it is false.
_VOID_OBJECT_WARNING = "void object"
# Properties listed per warned line in the report: enough to see what sits there.
_VOID_OBJECT_ROWS_KEPT = 8


def void_object_sites(log_text: str) -> list[tuple[str, int]]:
    """
    The (file, line) of each `Warning: void object` WP printed, once each, in log order; ("", 0) for one without
    a location. The line is that of the annotation, the alarm or the callee declaration whose translation needed
    the size of a `void` object. It is not always the line of the goal that depends on it: for a libc contract
    (`mempcpy`: `\\result == dest + n`) it is the contract's line, and the goals after the call use it.
    """
    sites: list[tuple[str, int]] = []
    for m in fold_messages(log_text):
        if m.plugin == "wp" and m.kind == "Warning" and m.text.strip() == _VOID_OBJECT_WARNING:
            if (m.file, m.line) not in sites:
                sites.append((m.file, m.line))
    return sites


def _report_row_path(row: dict) -> str:
    """The path of a report CSV row as a WP message writes it: directory and file joined."""
    directory = str(row.get("directory") or "")
    name = str(row.get("file") or "")
    return posixpath.normpath(f"{directory}/{name}") if directory else name


def _find_macro_loop_lines(c_file: Path, fn_name: str) -> dict[int, str]:
    """Return `{line: macro_name}` for loop-bearing `#define` macro invocations inside `fn_name`."""
    if not c_file.is_file():
        return {}
    try:
        from c_definitions import extract_functions_from_code, extract_macro_definitions

        raw_code = c_file.read_text(encoding="utf-8", errors="replace")
        macros = extract_macro_definitions(raw_code, path=str(c_file))
        loop_macros = {k for k, v in macros.items() if int(v.get("loop_count") or 0) > 0}
        if not loop_macros:
            return {}
        lines: dict[int, str] = {}
        for item in extract_functions_from_code(raw_code, path=str(c_file)):
            if item["name"] == fn_name:
                for tok in item["body_tokens"]:
                    if tok.text in loop_macros:
                        lines.setdefault(tok.line, tok.text)
        return lines
    except Exception:
        return {}


def _facts_record_for(res: dict, facts_dir: Path | None) -> dict | None:
    """The function's facts record from `<facts_dir>/*.json`, or None (fail-open)."""
    if facts_dir is None:
        facts_dir = Path("workspace/reports/facts")
    fn = res.get("function") or ""
    rel = function_facts.work_relative(str(res.get("file") or "")) or str(res.get("file") or "")
    key = function_facts.function_key(rel, fn)
    try:
        for path in sorted(Path(facts_dir).glob("*.json")):
            doc = json.loads(path.read_text(encoding="utf-8"))
            if doc.get("schema") != function_facts.FACTS_SCHEMA:
                continue
            rec = (doc.get("functions") or {}).get(key)
            if isinstance(rec, dict):
                return rec
    except (OSError, ValueError):
        return None
    return None


def _innermost_loop_at(record: dict, line: int) -> dict | None:
    loops = record.get("loops") or []
    cands = [lp for lp in loops if isinstance(lp.get("line"), int) and lp["line"] <= line]
    if not cands:
        return None
    return max(cands, key=lambda lp: (lp.get("parent") is not None, lp["line"]))


def _goal_failure_strategy(goal: dict) -> tuple[str, str]:
    """SESpec-style failure kind -> repair strategy for one unproven goal (by its WP name)."""
    ann = f"{goal.get('kind') or ''} {goal.get('annotation') or ''}".lower()
    if "established" in ann:
        return "weaken", "fails establishment"
    if "preserved" in ann:
        return "adjust", "fails preservation"
    if "loop_variant" in ann or "loop variant" in ann or "decreases" in ann:
        return "progress", "termination"
    if "loop_invariant" in ann:
        return "strengthen", "provability"
    return "regenerate", "unclassified"


def _loop_goal_strategies(unproven_goals: list[dict]) -> str | None:
    """
    One hint mapping each unproven loop goal to its repair strategy (SESpec Alg. 4):
    established -> weaken, preserved -> adjust, both -> regenerate (invalid invariant,
    largest valid subset), provability-only -> strengthen, variant/decreases -> progress fix.
    """
    per_inv: dict[str, set[str]] = {}
    variant_goals: list[str] = []
    for g in unproven_goals:
        kind = str(g.get("kind") or "")
        ann = str(g.get("annotation") or "")
        text = f"{kind} {ann}".lower()
        if "loop_variant" in text or "loop variant" in text or "decreases" in text:
            variant_goals.append(ann or kind)
            continue
        if "loop_invariant" not in text:
            continue
        strat, _ = _goal_failure_strategy(g)
        base = re.sub(r"_(established|preserved)$", "", ann, flags=re.IGNORECASE) or ann or kind
        per_inv.setdefault(base, set()).add(strat)
    if not per_inv and not variant_goals:
        return None
    parts: list[str] = []
    for base, strats in sorted(per_inv.items()):
        if "weaken" in strats and "adjust" in strats:
            parts.append(
                f"regenerate `{base}` (fails BOTH establishment and preservation: invalid, not just weak — drop it)"
            )
        elif "weaken" in strats:
            parts.append(
                f"weaken `{base}` (fails establishment: false before the first iteration — relax it or add a 'requires' holding at loop entry)"
            )
        elif "adjust" in strats:
            parts.append(
                f"adjust `{base}` (fails preservation: not inductive across one iteration, or 'loop assigns' missing/too broad)"
            )
        else:
            parts.append(f"strengthen `{base}` (holds but too weak to imply the postcondition at loop exit)")
    for v in sorted(set(variant_goals)):
        parts.append(
            f"fix progress for `{v}` (variant/measure does not strictly decrease — fix the measure, add the "
            "missing progress fact via a 'loop invariant' or 'requires' (e.g. from a callee's 'ensures' "
            "guaranteeing positive progress), or stop and report a 'proof_gap' / termination finding if the "
            "loop can legitimately fail to progress)"
        )
    return "Failure-kind repair strategy: " + "; ".join(parts) + "."


def _loop_dependency_slice_hint(res: dict, facts_dir: Path | None) -> str | None:
    """InvWeaver-style dependency slice: name the inner/predecessor loop whose exit summary is
    the likely missing fact when a loop preservation goal fails."""
    rec = _facts_record_for(res, facts_dir)
    if not rec:
        return None
    loops = rec.get("loops") or []
    goals = [
        g
        for g in (res.get("unproven_goals") or [])
        if "preserv" in f"{g.get('kind') or ''} {g.get('annotation') or ''}".lower()
        or str(g.get("kind") or "") == "loop_invariant"
    ]
    for g in goals:
        line = g.get("line")
        if not isinstance(line, int):
            continue
        loop = _innermost_loop_at(rec, line)
        if loop is None:
            continue
        children = [lp for lp in loops if lp.get("parent") == loop.get("index")]
        preds = (loop.get("assumption_context") or {}).get("predecessors") or []
        if children:
            inner = ", ".join(f"L{lp['line']}" for lp in children)
            return (
                f"Dependency slice: preservation of the loop at L{loop['line']} fails and it has inner loop(s) "
                f"{inner}; the missing fact is often the inner loop's exit summary — strengthen the inner "
                "loop's invariant first, not just the failing one."
            )
        if preds:
            return (
                f"Dependency slice: the loop at L{loop['line']} assumes from {', '.join(preds)}; check the "
                "predecessor loop's exit summary covers what this loop needs."
            )
    return None


def _report_field_hints(res: dict) -> list[str]:
    """Hints read from report fields, not from failed goals: they hold for a proof that stands, too."""
    hints: list[str] = []
    frame = res.get("frame_summary") or {}
    fn = res.get("function") or "the function"
    if frame.get("assigns_clause") == ASSIGNS_ABSENT:
        hints.append(
            f"The contract of {fn} has no 'assigns' clause (WP: \"No 'assigns' specification for function\"): "
            "nothing was proved about what it writes, so 'assigns_vcs_proven' is false although no goal failed, "
            "and callers must assume it writes everything. Add an 'assigns' clause ('assigns \\nothing;' for a "
            "function that writes no caller-visible memory); do not delete one to make a proof pass."
        )
    elif frame.get("assigns_clause") == ASSIGNS_BEHAVIORS_ONLY:
        named = ", ".join(frame.get("assigns_behaviors") or [])
        hints.append(
            f"The 'assigns' clauses of {fn} sit only in named behaviors ({named}) that do not cover the function "
            "(WP: \"No 'assigns' specification for function\"): outside them nothing was proved about what it "
            "writes, so 'assigns_vcs_proven' is false. Add an 'assigns' clause to the default behavior, or give "
            "every behavior one and state 'complete behaviors;'."
        )
    void_sites = [w for w in res.get("void_object_warnings") or [] if isinstance(w, dict)]
    if void_sites:
        shown = ", ".join(
            f"{w.get('file')}:{w.get('line')}" if w.get("file") else "no location" for w in void_sites[:5]
        )
        more = f" and {len(void_sites) - 5} more" if len(void_sites) > 5 else ""
        hints.append(
            f"WP printed 'Warning: void object' at {shown}{more}: it gives a 'void' object the size of an 'int', "
            "so '\\block_length', pointer arithmetic or '\\object_pointer' on a 'void *' on that line is computed "
            "with the wrong size, and a goal that depends on it can be proved although it is false "
            "('\\block_length(p) == 32' for 'char buf[8]; void *p = buf;'). In your own annotations cast first: "
            "'\\block_length((char *)p)', '(char *)p + n'. Where the line is a libc or callee contract, or C code "
            "that only loads a 'void *', there is nothing to change there: do not build a clause on the size or "
            "the offset it yields. This warning does not change the status."
        )
    return hints


def derive_wp_diagnostic_hints(
    res: dict, log_text: str = "", facts_dir: Path | None = None, kb_dir: Path | None = None
) -> list[str]:
    """
    Generate concise, actionable diagnostic hints for ACSL syntax errors, WP soundness
    aborts, and unproven goal buckets. When status == 'all_proven', returns only the hints
    about what that proof does not cover (_report_field_hints), usually [].
    `facts_dir` (default workspace/reports/facts) enables loop dependency-slice hints;
    `kb_dir` (default workspace/reports/kb) enables repair-pattern hints from the
    evolved specification knowledge base (spec_kb).
    """
    status = res.get("status")
    if status == "all_proven":
        return _report_field_hints(res)

    hints: list[str] = []

    def _add(msg: str) -> None:
        if msg not in hints:
            hints.append(msg)

    if status == "acsl_syntax_error":
        sc = res.get("syntax_check") or {}
        err_blob = "\n".join(sc.get("errors") or []) + "\n" + (sc.get("raw_log") or "") + "\n" + (log_text or "")
        if _UNTERMINATED_COMMENT_RE.search(err_blob):
            _add(
                "An annotation or comment is missing its closing '*/': the C preprocessor stopped with "
                "'unterminated comment' at the line where it opens (see syntax_check.errors). Close that "
                "'/*@ ... */' block; this is an edit in the source, not a missing include path."
            )
        if _EATEN_BACKSLASH_RE.search(err_blob):
            _add(
                "Backslash in an ACSL keyword was eaten by string escaping (e.g. \\false -> form-feed + 'alse', "
                "\\forall -> form-feed + 'orall', \\valid -> '\\v' + 'alid', \\t -> tab). Use a Python raw string "
                "r'''...''' or double backslashes when writing ACSL annotations."
            )
        if _CLAUSE_ORDER_ERR_RE.search(err_blob):
            _add(
                "Check Frama-C clause ordering: function contracts follow "
                "'requires -> terminates/decreases -> exits -> assigns -> ensures -> behavior' "
                "(since Frama-C 34, terminates/decreases may sit anywhere between requires and behaviors, "
                "and ACSL extensions may precede requires; the exits/assigns/ensures order is still enforced). "
                "Loop annotations MUST sit immediately above 'for'/'while'/'do' in order: "
                "'loop invariant -> loop assigns -> loop variant' ('loop variant' must be last)."
            )
        if _EMPTY_BEHAVIOR_ERR_RE.search(err_blob):
            _add(
                "Since Frama-C 34 an empty named behavior ('behavior b: ;') is a fatal annot-error "
                "(\"unexpected token ';'\") in function and statement contracts: give the behavior at least "
                "one clause (assumes/assigns/ensures/...) or remove it."
            )
        if re.search(r"\binvariant\b", err_blob, re.IGNORECASE) and "loop invariant" not in err_blob.lower():
            _add(
                "Loop invariants require the 'loop' keyword ('loop invariant ...;') and must be placed "
                "immediately BEFORE the 'for'/'while'/'do' statement, never inside the loop body '{ ... }'."
            )
        if _C_TYPE_OR_CALL_ERR_RE.search(err_blob):
            _add(
                "In ACSL quantifiers and logic/predicate definitions, use mathematical 'integer' instead of C types "
                "('int', 'size_t'), chain quantifier bounds as '\\forall integer k; 0 <= k < n ==> ...', and never "
                "call C functions inside ACSL (inline the struct/pointer condition instead)."
            )
        if _BOOL_PRED_ERR_RE.search(err_blob):
            _add(
                "ACSL separates terms (values) from predicates (formulas): write 'x == 0' instead of '!x' on C "
                "integers, and use '==>' or '(p1 ==> p2) && (p2 ==> p1)' instead of '? :' when combining predicates."
            )
        if not hints:
            _add(
                "ACSL syntax/typing error: check that every clause ends with ';', backslashes are intact "
                "(\\result, \\old, \\valid, \\valid_read, \\separated, \\forall, \\nothing), and function/loop "
                "clause order is respected."
            )
        return hints

    if status == "analysis_error" and str(res.get("reason") or "").startswith(PREPROCESSING_FAILED):
        _add(
            "The C preprocessor (gcc -E) failed before any annotation was read: a missing header or wrong "
            "include path, not an ACSL error and not something a re-run fixes. Re-run with the module's preprocessor "
            "flags: pass --cppflags with the module sidecar's cppflags, as the scheduler's command does (for "
            "workspace_overlay merge-agent, --module takes --cppflags and --sources from the module sidecar "
            "when they are not passed), and leave the contract unchanged."
        )
        return hints

    if status == "analysis_error" and res.get("reason") == METACSL_SET_ASSIGNS:
        failure = res.get("metacsl_failure") or {}
        callees = ", ".join(failure.get("callees") or [])
        named = (
            f"The contract(s) of {callees} in the parsed sources hold such an `assigns`."
            if callees
            else "No such contract was found in the parsed sources or the headers they include with quotes: "
            "look for it in the other headers of the function's file."
        )
        _add(
            "MetAcsl stopped before WP ran (meta_annotate.ml, line 675): a function whose `assigns` holds a set "
            f"(\\union(...), \\inter(...) or {{a, b}}) is called where a \\writing property applies. {named} This "
            "is not a proof problem and a re-run does not fix it: rewrite that contract with one `assigns` term per "
            "location, then re-run `security_props.py run` (it leaves the callers of a set-valued contract it can "
            "read out of the property's targets) and this proof."
        )
        return hints

    if status == "analysis_error" and res.get("reason") == OUT_DIR_LOCKED_REASON:
        _add(
            "Another Frama-C WP run is already writing to this --out-dir (exclusive lock held). "
            "Wait for the active run to finish or invoke run_wp_function.py with a separate --out-dir; "
            "do not run concurrent WP invocations against the same directory."
        )
        return hints

    if status == "analysis_error":
        reason = res.get("reason") or "unknown"
        partial = res.get("partial_verdicts")
        if isinstance(partial, dict) and (
            partial.get("scheduled_vcs") is not None or int(partial.get("completed_vcs") or 0) > 0
        ):
            scheduled = partial.get("scheduled_vcs")
            completed = int(partial.get("completed_vcs") or 0)
            proved = int(partial.get("proved_vcs") or 0)
            timed_out = int(partial.get("timed_out_vcs") or 0)
            unknown = int(partial.get("unknown_vcs") or 0)
            failed = int(partial.get("failed_vcs") or 0)
            cached_to = int(partial.get("cached_timed_out_vcs") or 0)
            breakdown: list[str] = []
            if proved > 0:
                breakdown.append(f"{proved} proved")
            if timed_out > 0:
                to_text = f"{timed_out} timed out"
                if cached_to > 0:
                    to_text += f" ({cached_to} cached)"
                breakdown.append(to_text)
            if unknown > 0:
                breakdown.append(f"{unknown} unknown")
            if failed > 0:
                breakdown.append(f"{failed} failed")

            if completed > 0:
                if proved > 0:
                    progress = (
                        f"after deciding {completed}/{scheduled} VCs"
                        if scheduled is not None
                        else f"after deciding {completed} {'VC' if completed == 1 else 'VCs'}"
                    )
                else:
                    unproved_unit = "VC" if completed == 1 else "VCs"
                    progress = (
                        f"with {scheduled} {'VC' if scheduled == 1 else 'VCs'} scheduled and {completed} unproved {unproved_unit} logged"
                        if scheduled is not None
                        else f"after logging {completed} unproved {unproved_unit}"
                    )
                summary_part = f"WP stopped before writing its report ({reason}) {progress}"
                if breakdown:
                    summary_part += f": {', '.join(breakdown)}"
            else:
                summary_part = (
                    f"WP stopped before writing its report ({reason}) after scheduling "
                    f"{scheduled} {'VC' if scheduled == 1 else 'VCs'} (no per-VC verdicts logged yet)"
                )

            remedies: list[str] = []
            if cached_to > 0:
                remedies.append(
                    "raise --timeout (e.g. --timeout 10 or --timeout 15) to bypass cached Timeout verdicts "
                    "instead of replaying them at the same timeout"
                )
            remedies.append("give the WP call dedicated wall time without running the guardrail concurrently")
            remedies.append("or narrow with --prop <clause> / simplify heavy invariants before re-running")
            _add(
                f"{summary_part}; {'; '.join(remedies)}. "
                "If it repeats, report status 'blocked' with this reason rather than weakening contracts."
            )
        else:
            _add(
                f"Frama-C WP terminated before producing a report (reason: {reason}). Re-run once; if it repeats, "
                "report status 'blocked' with this reason rather than weakening contracts."
            )
        unframed_var = res.get("unframed_variadic_callees") or []
        if (
            unframed_var
            or bool(_VARIADIC_CALLEE_RE.search(log_text or ""))
            or bool(_VARIADIC_CALLEE_RE.search(res.get("wp_log_tail") or ""))
        ):
            var_targets = f" ({', '.join(unframed_var)})" if unframed_var else ""
            _add(
                f"Frama-C WP does not support variadic function specifications or proof through unframed variadic callees{var_targets}. "
                "Introduce a non-variadic framing stub/contract or isolate the variadic callee in an unverified shell wrapper."
            )
        return hints

    soundness = res.get("soundness") or {}
    aborts_and_unsound = "\n".join(
        list(soundness.get("tier_a_aborts") or [])
        + list(soundness.get("tier_b_unsound") or [])
        + [log_text or "", res.get("wp_log_tail") or ""]
    )
    alloc_skipped, other_skipped = _classify_skipped_spec_messages(res, log_text)
    mm_sep_hint = (
        "WP emitted Typed memory-model separation hypotheses: add explicit "
        "'requires \\separated(p1 + (0 .. n1 - 1), p2 + (0 .. n2 - 1));' preconditions for distinct "
        "pointer parameters."
    )
    has_mm_hyp = bool(
        "Memory model hypotheses" in aborts_and_unsound or soundness.get("checked_memory_model_functions")
    )
    if not soundness.get("ok", True) or status in ("wp_aborted", "unsound_proof"):
        if "Missing assigns clause" in aborts_and_unsound or "using unguarded behavior assigns" in aborts_and_unsound:
            _add(
                "WP reported a missing 'assigns' or 'loop assigns' clause: every loop and every called function "
                "must have an explicit 'loop assigns ...;' / 'assigns ...;' clause (use 'assigns \\nothing;' for "
                "pure functions)."
            )
        if has_mm_hyp:
            _add(mm_sep_hint)
        indirect_call_text = "\n".join(
            [aborts_and_unsound, *(str(s) for s in (soundness.get("skipped_rte_guards") or []))]
        )
        if (
            _INDIRECT_CALL_UNSOUND_RE.search(indirect_call_text)
            or "Through function pointer" in indirect_call_text
            or "No 'calls' specification" in indirect_call_text
            or "indirect call present without '//@ calls'" in indirect_call_text
        ):
            _add(CALLS_ANNOTATION_HINT)
        if "unproven lemma" in aborts_and_unsound.lower():
            lemma_names = [
                str(g.get("annotation") or "").split(":", 1)[0].strip()
                for g in (res.get("unproven_goals") or [])
                if "lemma" in str(g.get("kind") or "").lower()
            ]
            lemma_names.extend(
                str(n).strip() for n in (soundness.get("unproven_global_lemmas") or []) if str(n).strip()
            )
            lemma_names = [n for n in dict.fromkeys(lemma_names) if n]
            named = f" ({', '.join(lemma_names[:5])})" if lemma_names else ""
            _add(
                f"Unproven global ACSL lemma in scope{named}: WP assumes an unproven lemma without proof for "
                "sibling goals, making the proof unsound. Remove the unproven 'lemma' and do NOT work around "
                "it with a file-scope ghost function (forbidden by the brief and refused at merge); if the "
                "goal requires induction WP cannot prove inline, stop with status 'stalled_after_k_retries' "
                "and proof_gap (reason: 'inductive lemma required: ...')."
            )
        if res.get("wp_why3_anomaly") or _WHY3_ANOMALY_RE.search(aborts_and_unsound):
            _add(
                "Why3 backend anomaly during WP goal translation ([Why3 Error] anomaly, e.g. "
                'Invalid_argument("missing free variable") or "unbound variable in of_term" on incompatible '
                "pointer casts): the SMT provers aborted before evaluating the failed goal(s), so this is a "
                "WP/Why3 backend failure rather than a missing precondition. Retry with `--wp-model Bytes` "
                "if pointer casts are present, or report status 'blocked' if the anomaly persists."
            )
        if _SMOKE_FAIL_RE.search(aborts_and_unsound):
            _add(
                "Vacuous proof detected (--wp-smoke-tests proved \\false): your 'requires' clauses or loop "
                "invariants are mutually contradictory. Inspect and relax conflicting preconditions."
            )
        missing_spec_set = {
            s.function
            for msg in (soundness.get("tier_b_unsound") or [])
            for s in parse_missing_spec(msg)
            if not s.benign and s.function
        }
        for s in missing_spec_messages(aborts_and_unsound):
            if not s.benign and s.function:
                missing_spec_set.add(s.function)
        missing_spec = sorted(missing_spec_set)
        if missing_spec:
            _add(
                f"Callee(s) without any contract: {', '.join(missing_spec)}. Frama-C generated a default contract "
                "that WP then trusted, so this proof does not hold. A contract is needed on one of its declarations: "
                "request it through `strengthening_requests` for a project function, unless the brief lists the "
                "callee under 'Calls Without a Contract'; for an external function, "
                + "; ".join(stub_repair_action(fn) for fn in missing_spec)
                + "."
            )
        if alloc_skipped:
            _add(
                "Frama-C WP does not support dynamic allocation clauses ('\\freeable', '\\fresh', "
                "'\\allocable', 'allocates', 'frees') from <stdlib.h> ('not yet supported (skipped)'). "
                "Do NOT write synthetic probe_*.c programs to investigate this limitation; once all "
                "non-allocation goals are proven and the E-ACSL guardrail passes, stop and write "
                "result.json with status 'stalled_after_k_retries'."
            )
        if other_skipped:
            _add(
                "Frama-C ignored part of a specification (see 'soundness.tier_b_unsound'): rewrite the unsupported "
                "or misplaced clause so WP checks it."
            )

    if res.get("budget_exhausted"):
        _add(
            "Prover iteration or wall-clock budget is exhausted for this function. Stop running WP or writing "
            "probe files immediately and write agents/<id>/scratch/result.json with status 'stalled_after_k_retries' "
            "recording the remaining unproven_goals."
        )

    if res.get("wp_why3_memaddr_limitation") or _WHY3_MEMADDR_ERR_RE.search(aborts_and_unsound):
        _add(
            "Why3 failed with 'Type mismatch between frama_c_wp.memaddr.MemAddr.addr and int' (typically caused by "
            '`assert(!"string_literal")` where WP\'s Cstring table types string literals as `int` IDs against '
            '`MemAddr.null`). When `assert(!"...")` sits on an unreachable default/switch branch, place '
            '`/*@ assert unreachable_branch: \\false; */` immediately BEFORE `assert(!"...");` and bound the '
            'switch variable via `requires` / `loop invariant` so Qed proves `\\false` and prunes the `assert(!"...")` '
            "goal before Why3 translation."
        )

    if res.get("wp_macro_loop_limitation") or soundness.get("macro_loop_warnings"):
        _add(
            "Function expands a file-scope `#define` macro containing an unannotatable C loop (`while`/`for`). "
            "Preprocessor macros cannot carry `/*@ loop invariant */` or `/*@ loop assigns */` at invocation sites "
            "without modifying C code. Prove the function's `assigns` and contract obligations that do not depend "
            "on the macro loop, run the E-ACSL guardrail, and report status 'stalled_after_k_retries' so callers "
            "can still verify against this function's contract."
        )

    if status == "unproven_goals_remain":
        buckets = res.get("unproven_by_bucket") or {}
        unproven_goals = res.get("unproven_goals") or []
        full_log = (log_text or "") + "\n" + (res.get("wp_log_tail") or "")
        if has_mm_hyp:
            _add(mm_sep_hint)
        alloc_goals = [g for g in unproven_goals if _is_alloc_limitation_goal(g)]
        if alloc_goals or alloc_skipped:
            _add(
                "Frama-C WP does not support dynamic allocation predicates ('\\freeable', '\\fresh', "
                "'\\allocable', 'allocates', 'frees') on malloc/calloc/realloc/free in <stdlib.h>. "
                "These goals cannot be discharged by WP and cannot be worked around in user annotations. "
                "Do NOT create synthetic probe_*.c test files; once all non-allocation goals are proven and "
                "the E-ACSL guardrail passes, stop immediately and write result.json with status "
                "'stalled_after_k_retries'."
            )
        goal_annot_blob = " ".join(f"{g.get('kind') or ''} {g.get('annotation') or ''}" for g in unproven_goals)
        if _PTR_DIFF_EQ_RE.search(goal_annot_blob) or _PTR_DIFF_EQ_RE.search(full_log):
            _add(
                r"Pointer-walk anchoring (`p_end - p == 0 ==> p == p_end` or `\base_addr(p) == \base_addr(p_end)`): "
                r"use the ghost-index idiom rather than `p == base + (p - base)` (which breaks E-matching and fails "
                r"on stride > 1 / `Bytes`). Capture an unmodified base pointer (`base`, or "
                r"`/*@ ghost const T *base = p; */`), add `requires \base_addr(base) == \base_addr(p_end);`, "
                r"introduce `/*@ ghost size_t idx = 0; */`, state `loop invariant idx_bound: 0 <= idx <= p_end - base;` "
                r"and `loop invariant ptr_idx: p == base + idx;`, include `idx` in `loop assigns`, and increment "
                r"`/*@ ghost idx++; */`. For pointer-advancing helpers, export "
                r"`ensures res_base: \result != \null ==> \base_addr(\result) == \base_addr(\old(buf));` and "
                r"`ensures res_bound: \result != \null ==> 0 <= \result - \old(buf) <= \old(buf_end) - \old(buf);` "
                r"(callers resynchronize via `/*@ ghost idx = (size_t)(p - buf); */`)."
            )

        if buckets.get("step_a_assigns"):
            _add(
                "Step A (Frame Conditions) has unproven 'assigns' / 'loop assigns' goals: fix 'assigns' and "
                "'loop assigns' FIRST before editing loop invariants or postconditions. List every variable "
                "(including loop counter 'i' and accumulators) and memory range modified in the loop or function."
            )
        if buckets.get("step_b_loop_invariant"):
            if _LOOP_ESTABLISHED_FAIL_RE.search(full_log):
                _add(
                    "Loop invariant ESTABLISHMENT failed: the invariant is false before the first iteration. "
                    "Check initial variable values at loop entry or add a 'requires' precondition "
                    "(e.g. 'requires n >= 0;' for 'loop invariant 0 <= i <= n;')."
                )
            if _LOOP_PRESERVED_FAIL_RE.search(full_log):
                _add(
                    "Loop invariant PRESERVATION failed: the invariant is not inductive across an iteration, "
                    "or 'loop assigns' is missing/too broad, or the upper bound uses '< n' instead of '<= n' "
                    "(at loop exit 'i == n', so write 'loop invariant 0 <= i <= n;')."
                )
            slice_hint = _loop_dependency_slice_hint(res, facts_dir)
            if slice_hint:
                _add(slice_hint)
            strategy_hint = _loop_goal_strategies(unproven_goals)
            if strategy_hint:
                _add(strategy_hint)
            if not _LOOP_ESTABLISHED_FAIL_RE.search(full_log) and not _LOOP_PRESERVED_FAIL_RE.search(full_log):
                _add(
                    "Step B (Loops) has unproven goals: ensure 'loop invariant 0 <= i <= n;' uses '<= n' "
                    "(not '< n'), bound any accumulator or pointer offset modified in the loop, and place "
                    "'loop variant n - i;' AFTER 'loop assigns'."
                )
        if (
            buckets.get("step_c_rte_obligation")
            or buckets.get("step_c_caller_precondition")
            or buckets.get("step_c_contract_postcondition")
        ):
            goal_text = " ".join(f"{g.get('kind') or ''} {g.get('annotation') or ''}".lower() for g in unproven_goals)
            if any(k in goal_text for k in ("mem_access", "index_bound")):
                _add(
                    "Unproven pointer/array access ('mem_access' / 'index_bound'): add 'requires \\valid(p);' or "
                    "'requires n > 0 ==> \\valid_read(buf + (0 .. n - 1));' (guarding 'n > 0' so (NULL, 0) passes "
                    "E-ACSL) and bound loop indices with 'loop invariant 0 <= i <= n;'."
                )
            has_data_pointer_value = any(
                "pointer_value" in f"{g.get('kind') or ''} {g.get('annotation') or ''}".lower()
                and "\\valid_function" not in str(g.get("annotation") or "").lower()
                for g in unproven_goals
            )
            if has_data_pointer_value:
                _add(
                    r"Unproven pointer formation ('pointer_value' under -warn-invalid-pointer, e.g. "
                    r"`\object_pointer(p + n)`): WP checks pointer arithmetic at the formation site (such as "
                    r"`end = buf + len`), BEFORE any later NULL or empty-window guard runs; "
                    r"`requires len > 0 ==> \valid_read(buf + (0 .. len - 1));` alone does not discharge `buf + len` "
                    r"when `buf == \null` or on an empty window. Pure-ACSL triage (never edit C code): (1) if the API "
                    r"contract forbids NULL and the corpus never passes it, require `buf != \null` (with "
                    r"`len > 0 ==> \valid_read(buf + (0 .. len - 1))` or `\object_pointer(buf + len)`); (2) if "
                    r"reachable callers or corpus inputs pass `(NULL, 0)` (so `buf != \null` triggers "
                    r"`rejected_overconstrained` or violates Rule 3 on an untrusted entry), classify it as a "
                    r"`fault_hypothesis` (invalid pointer formation before NULL/empty-window check) or `proof_gap`."
                )
            if any(k in goal_text for k in ("signed_overflow", "unsigned_overflow", "division_by_zero", "shift")):
                _add(
                    "Unproven arithmetic RTE ('overflow' / 'division_by_zero' / 'shift'): bound the inputs or loop "
                    "accumulators via 'requires' / 'loop invariant' so the C expression cannot overflow or divide by 0."
                )
            if "initialization" in goal_text or "\\initialized" in goal_text:
                _add(
                    "Unproven 'initialization' goal: ensure local buffers are initialized on all paths, add "
                    "'requires n > 0 ==> \\initialized(in_buf + (0 .. n - 1));' for caller inputs, or add "
                    "'loop invariant \\initialized(out_buf + (0 .. i - 1));' for loops that populate an output buffer."
                )
        if goal_costs_enabled():
            for cost_hint in goal_cost_hints(res):
                _add(cost_hint)
    unframed_var = res.get("unframed_variadic_callees") or []
    has_variadic_err = bool(_VARIADIC_CALLEE_RE.search(aborts_and_unsound)) or bool(
        _VARIADIC_CALLEE_RE.search(log_text or "")
    )
    if unframed_var or has_variadic_err:
        var_targets = f" ({', '.join(unframed_var)})" if unframed_var else ""
        _add(
            f"Frama-C WP does not support variadic function specifications or proof through unframed variadic callees{var_targets}. "
            "Introduce a non-variadic framing stub/contract or isolate the variadic callee in an unverified shell wrapper."
        )

    for repair in spec_kb.repair_hints_for_goals(res, kb_dir or Path("workspace/reports/kb")):
        _add(repair)
    for field_hint in _report_field_hints(res):
        _add(field_hint)

    return hints


def _decode_output(data) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return str(data)


def _analysis_error_result(
    fn_name: str,
    c_file: Path,
    reason: str,
    returncode: int | None,
    soundness: dict,
    combined_log: str,
    metacsl_failure: dict | None = None,
    partial_verdicts: dict[str, Any] | None = None,
) -> dict:
    res: dict[str, Any] = {
        "status": "analysis_error",
        "reason": reason,
        "returncode": returncode,
        "function": fn_name,
        "file": str(c_file),
        "total_goals": 0,
        "proven_count": 0,
        "proven_under_hyp_count": 0,
        "unproven_count": 0,
        "dead_count": 0,
        "soundness": soundness,
        "undeclared_functions": scan_undeclared_functions(combined_log),
        "by_obligation_class": {},
        "next_synthesis_focus": "analysis_error_rerun_required",
        "unproven_by_bucket": {},
        "unproven_goals": [],
        "proven_under_hyp_goals": [],
        "goal_dumps": [],
        "sarif_file": None,
        "wp_log_tail": combined_log[-3000:],
    }
    if metacsl_failure is not None:
        res["metacsl_failure"] = metacsl_failure
    if partial_verdicts is not None:
        res["partial_verdicts"] = partial_verdicts
    res["diagnostic_hints"] = derive_wp_diagnostic_hints(res, combined_log)
    return res


def _find_and_load_dag(c_file: Path, out_dir: Path) -> dict | None:
    candidates = [
        out_dir / "reports" / "callgraph_dag.json",
        out_dir.parent / "reports" / "callgraph_dag.json",
        out_dir.parent / "workspace" / "reports" / "callgraph_dag.json",
        c_file.parent / "reports" / "callgraph_dag.json",
        c_file.parent.parent / "reports" / "callgraph_dag.json",
        c_file.parent.parent.parent / "reports" / "callgraph_dag.json",
        Path("workspace/reports/callgraph_dag.json"),
    ]
    for p in candidates:
        if p.is_file():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(data, dict) and "functions" in data:
                    return data
            except Exception:
                pass
    return None


def _dag_function_record(dag: dict, c_file: Path, fn_name: str) -> dict | None:
    """The DAG record of `fn_name`: under its plain key, else the record of that name whose file `c_file` ends with."""
    functions = dag.get("functions") or {}
    fn_data = functions.get(fn_name)
    if isinstance(fn_data, dict) and fn_data.get("name", fn_name) == fn_name:
        return fn_data
    c_str = str(c_file).replace("\\", "/")
    for v in functions.values():
        if isinstance(v, dict) and v.get("name") == fn_name:
            v_file = str(v.get("file") or "").replace("\\", "/")
            if v_file and (v_file == c_str or c_str.endswith("/" + v_file)):
                return v
    return None


def _check_internal_variadic(
    c_file: Path,
    fn_name: str,
    out_dir: Path,
    wp_blockers: list[str] | None = None,
) -> tuple[bool, str]:
    if wp_blockers is not None and "internal_variadic" in wp_blockers:
        return True, "Target function explicitly marked with wp_blocker 'internal_variadic'"

    dag = _find_and_load_dag(c_file, out_dir)
    if dag:
        fn_data = _dag_function_record(dag, c_file, fn_name)
        if fn_data and "internal_variadic" in fn_data.get("wp_blockers", []):
            return (
                True,
                f"Target function '{fn_name}' in '{c_file}' is marked with wp_blocker 'internal_variadic' in callgraph DAG",
            )

    if c_file.is_file():
        try:
            from c_definitions import extract_functions_from_code

            raw_code = c_file.read_text(encoding="utf-8", errors="replace")
            for item in extract_functions_from_code(raw_code, path=str(c_file)):
                if item["name"] == fn_name:
                    # `...` may come as one token or as three `.` tokens.
                    params = "".join(t.text for t in item["param_tokens"] if t.text.strip())
                    if "..." in params:
                        return True, f"Target function '{fn_name}' in '{c_file}' has variadic parameter '...'"
        except Exception:
            pass

    return False, ""


def _find_unframed_variadic_callees(c_file: Path, fn_name: str, out_dir: Path) -> list[str]:
    dag = _find_and_load_dag(c_file, out_dir)
    variadic_callees: list[str] = []
    if dag:
        fn_data = dag.get("functions", {}).get(fn_name)
        if not fn_data:
            c_str = str(c_file).replace("\\", "/")
            for v in dag.get("functions", {}).values():
                if v.get("name") == fn_name:
                    v_file = v.get("file", "").replace("\\", "/")
                    if v_file == c_str or c_str.endswith("/" + v_file) or c_str == v_file:
                        fn_data = v
                        break
        if fn_data:
            for callee in fn_data.get("internal_callees", []):
                callee_data = dag.get("functions", {}).get(callee, {})
                if "internal_variadic" in callee_data.get("wp_blockers", []):
                    variadic_callees.append(callee)
    return variadic_callees


def _sources_hold_eva_taint(sources: list[str]) -> bool:
    """True when a source holds an assertion named `eva_taint` (security_props.py --eva-taint)."""
    for src in sources:
        try:
            if WP_PROP_EXCLUDE[1:] + ":" in Path(src).read_text(encoding="utf-8", errors="replace"):
                return True
        except OSError:
            continue
    return False


def _prove_then_collect_models(call_args: dict[str, Any]) -> dict:
    """--counter-examples: prove without -wp-counter-examples, then take models for the goals still failing.

    Frama-C 34 WP builds weaker goals under -wp-counter-examples (the model probes keep memory variables
    apart, and the frame equalities Qed uses are lost: `ensures p->ptr == \\old(p->ptr)` for an untouched
    pointer field is `Prove: true` normally, `Prove: Mptr_0[a] = Mptr_1[a]` with nothing relating the two
    memories in counter-example mode). So the verdict, counts, report CSV and SARIF all come from the normal
    proof pass, retries included; the model pass runs only when goals fail, writes its own `_cex` artifacts,
    and only contributes `counter_example_goals` for goals the proof pass also failed. Its models are hints
    for the crash verifiers, not proofs that a clause is false.
    """
    res = run_wp_on_function(**{**call_args, "counter_examples": False})
    return collect_counter_example_models(res, call_args)


def needs_model_pass(res: dict) -> bool:
    """Whether a verdict leaves failed goals a counter-example pass could give models for."""
    return res.get("status") == "unproven_goals_remain" and bool(res.get("unproven_goals"))


def collect_counter_example_models(res: dict, call_args: dict[str, Any]) -> dict:
    """The -wp-counter-examples pass for the verdict `res` of a proof run with `call_args`.

    It never changes the verdict. It is skipped when no goal failed, and when the verdict pass found the
    prover budget exhausted: the model pass ignores the budget (it is no proof iteration), so starting it
    then would be a full WP run the budget had just refused.
    """
    res["counter_examples"] = True
    res["counter_example_goals"] = []
    if not needs_model_pass(res):
        res.pop("counter_example_pass", None)
        return res
    if res.get("budget_exhausted"):
        res["counter_example_pass"] = {
            "status": "skipped",
            "reason": "prover budget exhausted: the verdict pass ran no WP, so no model pass either",
        }
        return res
    out_dir = Path(call_args["out_dir"])
    fn_name = str(call_args["fn_name"])
    base_suffix = str(call_args.get("artifact_suffix") or "")
    suffix = base_suffix
    if res.get("bitwise_retry"):
        suffix += "_retry"
    elif res.get("tail_retry"):
        suffix += "_tail"
    elif (res.get("bytes_retry") or {}).get("kept"):
        suffix += _BYTES_RETRY_SUFFIX
    proof_log = out_dir / f"wp_{fn_name}{suffix}.log"
    try:
        failed = parse_failed_wp_goals(proof_log.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        failed = set()
    model_suffix = f"{base_suffix}{_MODEL_PASS_SUFFIX}"
    try:
        model_res = run_wp_on_function(
            **{
                **call_args,
                "counter_examples": True,
                "wp_model": res.get("wp_model") or call_args.get("wp_model") or "Typed",
                "artifact_suffix": model_suffix,
                "retry_bitwise": False,
                "retry_tail": False,
                "retry_cast_probe": False,
                "retry_bytes": False,
                "smoke_tests": False,
                "sarif": False,
                "keep_goals": False,
                "dump_goal": False,
                "session_dir": None,
                "ignore_prover_budget": True,
            }
        )
    except Exception as exc:  # a failed model pass never changes the proof result
        model_res = {"status": "model_pass_error", "reason": f"{type(exc).__name__}: {exc}"}
    res["counter_example_goals"] = [g for g in model_res.get("counter_example_goals") or [] if g.get("goal") in failed]
    res["counter_example_pass"] = {
        "status": model_res.get("status"),
        "log": str(out_dir / f"wp_{fn_name}{model_suffix}.log"),
        "models_dropped_for_proved_goals": len(model_res.get("counter_example_goals") or [])
        - len(res["counter_example_goals"]),
    }
    return res


OUT_DIR_LOCK_NAME = ".wp_out_dir.lock"
OUT_DIR_LOCK_STALE_ENV = "FRAMAC_WP_OUT_DIR_LOCK_STALE"
OUT_DIR_LOCK_STALE_DEFAULT_S = 180.0
OUT_DIR_LOCKED_REASON = "out_dir_locked"

# Resolved out_dir -> (owner_thread_id, reentrancy_depth) for same-thread nested WP retries/checks.
_HELD_OUT_DIR_LOCKS: dict[str, tuple[int, int]] = {}
_HELD_OUT_DIR_GUARD = threading.Lock()


class OutDirLockedError(RuntimeError):
    """Another active WP run already holds the exclusive lock on `out_dir`."""

    def __init__(self, out_dir: Path, owner: dict[str, Any]) -> None:
        self.out_dir = out_dir
        self.owner = owner
        parts: list[str] = []
        if owner.get("pid") is not None:
            parts.append(f"pid={owner['pid']}")
        if owner.get("host"):
            parts.append(f"host={owner['host']}")
        if owner.get("function"):
            parts.append(f"function={owner['function']}")
        if owner.get("started_at"):
            parts.append(f"started_at={owner['started_at']}")
        holder = ", ".join(parts) if parts else "unknown holder"
        super().__init__(
            f"WP output directory '{out_dir}' is already locked by another active run ({holder}); "
            "wait for it to finish or pass a separate --out-dir."
        )


def _pid_is_alive(pid: int) -> bool:
    """Return True if process `pid` currently exists on this host."""
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return False
    if os.name == "nt":
        import ctypes

        win_dll = getattr(ctypes, "WinDLL", None)
        if win_dll is None:
            return True
        kernel32 = win_dll("kernel32", use_last_error=True)
        process_query_limited_info = 0x1000
        still_active = 259
        handle = kernel32.OpenProcess(process_query_limited_info, False, pid)
        if not handle:
            # ERROR_ACCESS_DENIED (5): process exists, caller lacks permission to query it.
            get_last_error = getattr(ctypes, "get_last_error", None)
            return get_last_error is not None and int(get_last_error()) == 5
        try:
            exit_code = ctypes.c_ulong()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return True
            return int(exit_code.value) == still_active
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _out_dir_lock_stale_seconds(stale_after: float | None) -> float:
    if stale_after is not None:
        return max(0.0, float(stale_after))
    raw = (os.environ.get(OUT_DIR_LOCK_STALE_ENV) or "").strip()
    if raw:
        try:
            val = float(raw)
            if math.isfinite(val) and val > 0:
                return val
        except ValueError:
            pass
    return OUT_DIR_LOCK_STALE_DEFAULT_S


def _read_lock_owner(lock_dir: Path, wait_s: float = 0.25) -> dict[str, Any]:
    """Read `lock_dir/owner.json`, waiting briefly if the creator is mid-write."""
    owner_file = lock_dir / "owner.json"
    deadline = time.monotonic() + wait_s
    while True:
        try:
            data = json.loads(owner_file.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
            return {}
        except (OSError, ValueError):
            if not lock_dir.exists() or time.monotonic() >= deadline:
                return {}
            time.sleep(0.02)


def _out_dir_lock_age(lock_dir: Path) -> float | None:
    for probe in (lock_dir / "owner.json", lock_dir):
        try:
            return time.time() - probe.stat().st_mtime
        except OSError:
            continue
    return None


def _is_out_dir_lock_stale(lock_dir: Path, owner: dict[str, Any], stale_s: float) -> bool:
    pid = owner.get("pid")
    host = owner.get("host")
    if host and host == socket.gethostname() and isinstance(pid, int) and not isinstance(pid, bool):
        if not _pid_is_alive(pid):
            return True
    age = _out_dir_lock_age(lock_dir)
    return age is not None and age > stale_s


def _break_stale_out_dir_lock(lock_dir: Path) -> None:
    tomb = lock_dir.with_name(f"{lock_dir.name}.stale-{os.getpid()}-{time.time_ns()}")
    try:
        os.replace(lock_dir, tomb)
    except OSError:
        return
    shutil.rmtree(tomb, ignore_errors=True)


@contextlib.contextmanager
def _out_dir_lock(out_dir: Path, fn_name: str, stale_after: float | None = None) -> Iterator[Path]:
    """Non-blocking exclusive cross-process lock on `out_dir`, re-entrant on the holding thread."""
    out_path = Path(out_dir)
    key = str(out_path.resolve())
    tid = threading.get_ident()
    with _HELD_OUT_DIR_GUARD:
        held = _HELD_OUT_DIR_LOCKS.get(key)
        if held is not None:
            owner_tid, depth = held
            if owner_tid == tid:
                _HELD_OUT_DIR_LOCKS[key] = (owner_tid, depth + 1)
            else:
                lock_dir = out_path / OUT_DIR_LOCK_NAME
                owner = (
                    _read_lock_owner(lock_dir, wait_s=0.05)
                    if lock_dir.exists()
                    else {"pid": os.getpid(), "host": socket.gethostname()}
                )
                raise OutDirLockedError(out_path, owner)
    if held is not None:
        try:
            yield out_path / OUT_DIR_LOCK_NAME
        finally:
            with _HELD_OUT_DIR_GUARD:
                cur = _HELD_OUT_DIR_LOCKS.get(key)
                if cur is not None:
                    if cur[1] > 1:
                        _HELD_OUT_DIR_LOCKS[key] = (cur[0], cur[1] - 1)
                    else:
                        _HELD_OUT_DIR_LOCKS.pop(key, None)
        return

    stale_s = _out_dir_lock_stale_seconds(stale_after)
    out_path.mkdir(parents=True, exist_ok=True)
    lock_dir = out_path / OUT_DIR_LOCK_NAME
    stale_breaks = 0
    transient_deadline = time.monotonic() + 1.0
    while True:
        try:
            os.mkdir(lock_dir)
            break
        except FileNotFoundError:
            out_path.mkdir(parents=True, exist_ok=True)
            continue
        except PermissionError:
            # Windows: lock_dir may be pending delete while a releasing holder removes it.
            if time.monotonic() >= transient_deadline:
                raise
            time.sleep(0.02)
            continue
        except FileExistsError:
            owner = _read_lock_owner(lock_dir)
            if not lock_dir.exists():
                continue
            if stale_breaks < 3 and _is_out_dir_lock_stale(lock_dir, owner, stale_s):
                _break_stale_out_dir_lock(lock_dir)
                stale_breaks += 1
                continue
            raise OutDirLockedError(out_path, owner) from None

    owner_file = lock_dir / "owner.json"
    try:
        payload = (
            json.dumps(
                {
                    "pid": os.getpid(),
                    "host": socket.gethostname(),
                    "started_at": utc_now(),
                    "function": fn_name,
                },
                indent=2,
            )
            + "\n"
        )
        tmp_owner = lock_dir / f"owner.json.tmp.{os.getpid()}.{tid}"
        tmp_owner.write_text(payload, encoding="utf-8")
        os.replace(tmp_owner, owner_file)
    except Exception:
        shutil.rmtree(lock_dir, ignore_errors=True)
        raise

    stop = threading.Event()

    def _heartbeat() -> None:
        interval = max(1.0, min(15.0, stale_s / 4)) if stale_s > 0 else 15.0
        while not stop.wait(interval):
            try:
                os.utime(owner_file)
            except OSError:
                return

    beat = threading.Thread(target=_heartbeat, name=f"wp-out-lock-{fn_name}", daemon=True)
    beat.start()
    with _HELD_OUT_DIR_GUARD:
        _HELD_OUT_DIR_LOCKS[key] = (tid, 1)
    try:
        yield lock_dir
    finally:
        with _HELD_OUT_DIR_GUARD:
            _HELD_OUT_DIR_LOCKS.pop(key, None)
        stop.set()
        beat.join(timeout=5)
        shutil.rmtree(lock_dir, ignore_errors=True)


_VERDICT_STATUS_ORDER = {"timeout": 3, "stepout": 2, "failed": 1, "unknown": 0}
_VERDICT_STATUS_LABEL = {"timeout": "Timeout", "stepout": "Stepout", "failed": "Failed", "unknown": "Unknown"}


def _variant_goal_info(goal: str, prop: str | None, fn_name: str) -> tuple[str, str] | None:
    """
    If `goal`/`prop` is a WP loop-variant or recursion-decreases VC for `fn_name`, return
    `(kind, group_key)` with `kind` in `{"loop variant", "decreases"}`; else None.

    Frama-C 34 `-report-csv` omits `loop variant` and recursion `decreases` (`Recursion variant`)
    rows completely, leaving only a `Partially proven` `termination clause` row even when the
    variant timed out (`[wp] [Timeout] typed_<fn>_loop_variant_positive`).
    """
    fn_esc = re.escape(fn_name)
    if prop:
        m_prop = re.fullmatch(rf"{fn_esc}_(loop_variant|variant|decreases)(?:_(\d+))?", prop)
        if m_prop:
            kind = "loop variant" if m_prop.group(1) == "loop_variant" else "decreases"
            return kind, prop
    m_goal = re.search(
        rf"_{fn_esc}_(loop_variant|variant|decreases)(?:_(\d+))?(?:_(?:positive|decrease))?(?:_part\d+)?$",
        goal,
    )
    if m_goal:
        raw_kind, idx = m_goal.group(1), m_goal.group(2)
        kind = "loop variant" if raw_kind == "loop_variant" else "decreases"
        base = f"{fn_name}_{raw_kind}" + (f"_{idx}" if idx else "")
        return kind, base
    return None


def _infer_kind_from_wp_goal(goal: str, fn_name: str) -> str:
    """Best-effort property kind from a WP goal name when `-report-csv` omitted the property."""
    fn_esc = re.escape(fn_name)
    m = re.search(rf"_{fn_esc}_(.+)$", goal)
    suffix = (m.group(1) if m else goal).lower()
    if re.match(r"^loop_variant\b", suffix):
        return "loop variant"
    if re.match(r"^(?:variant|decreases)\b", suffix):
        return "decreases"
    if "loop_assigns" in suffix or re.match(r"^assigns\b", suffix) or "_assigns" in suffix:
        return "assigns clause"
    if "loop_invariant" in suffix:
        return "loop invariant"
    m_rte = re.search(r"assert_rte_([a-z_]+?)(?:_\d+)?(?:_part\d+)?$", suffix)
    if m_rte:
        return f"rte: {m_rte.group(1)}"
    if "_requires" in suffix or suffix.startswith("requires"):
        return "precondition"
    if "terminates" in suffix:
        return "termination clause"
    if "ensures" in suffix or "exits" in suffix:
        return "postcondition"
    return "wp_goal"


def _reconcile_unreported_wp_goals(
    *,
    fn_name: str,
    c_file: Path,
    goal_costs: list[dict],
    combined_log: str,
    assumed_fpv: set[str],
    all_vcs_cleanly_proved: bool,
    has_vc_deficit: bool,
    unproven_goals: list[dict],
    buckets: dict[str, list[dict]],
    by_class: dict[str, dict[str, int]],
) -> None:
    """
    Surface failed/timed-out WP VCs that Frama-C `-report-csv` omitted from the CSV:
    1. Loop-variant and recursion-variant (`decreases`) goals are omitted from `-report-csv`
       in Frama-C 34 (leaving only `termination clause | Partially proven`), so any unproved
       variant VC in `goal_costs` (or the WP log) is grouped per property and added unless
       `unproven_goals` already has an `l2_termination` row for that line.
    2. If `unproven_goals` is still empty despite `vc_timeouts > 0` or `vc_proved < vc_total`,
       any remaining non-assumed failed VCs are synthesized so counts, buckets, obligation
       classes, and diagnostic hints never contradict `status == 'unproven_goals_remain'`.

    Never modifies clean `all_proven` runs (`all_vcs_cleanly_proved` True).
    """
    if all_vcs_cleanly_proved:
        return

    def _active_cost(c: dict) -> bool:
        goal = str(c.get("goal") or "")
        return bool(goal) and goal not in assumed_fpv and "_wp_smoke_" not in goal

    def _add_synthesized(
        kind: str,
        file_name: str,
        line: int,
        verdicts: list[str],
        goal_names: list[str],
    ) -> None:
        best_v = max(verdicts, key=lambda v: _VERDICT_STATUS_ORDER.get(v, -1), default="unknown")
        item: dict[str, Any] = {
            "file": file_name,
            "function": fn_name,
            "line": line,
            "kind": kind,
            "status": _VERDICT_STATUS_LABEL.get(best_v, "Unknown"),
            "annotation": ", ".join(goal_names),
            "wp_goals": goal_names,
        }
        cls = goal_obligation_class(item)
        item["obligation_class"] = cls
        bkey = classify_unproven_goal(item)
        item["diagnostic_bucket"] = bkey
        unproven_goals.append(item)
        buckets[bkey].append(item)
        counts = by_class.setdefault(cls, {"proven": 0, "proven_under_hyp": 0, "unproven": 0})
        counts["unproven"] += 1

    # 1. Reconcile omitted variant / decreases goals (even when other CSV goals also failed).
    existing_term_lines = {
        int(g.get("line") or 0) for g in unproven_goals if g.get("obligation_class") == "l2_termination"
    }
    has_existing_term = bool(existing_term_lines)
    variant_groups: dict[tuple[str, str], dict[str, Any]] = {}
    matched_goals: set[str] = set()
    for c in goal_costs:
        if not _active_cost(c):
            continue
        goal = str(c["goal"])
        info = _variant_goal_info(goal, c.get("property"), fn_name)
        if info is None:
            continue
        matched_goals.add(goal)
        kind, group_key = info
        line = int(c["line"]) if isinstance(c.get("line"), int) and not isinstance(c.get("line"), bool) else 0
        raw_file = c.get("file")
        file_name = Path(str(raw_file)).name if isinstance(raw_file, str) and raw_file else c_file.name
        grp = variant_groups.setdefault(
            (kind, group_key),
            {"file": file_name, "line": line, "verdicts": [], "goals": []},
        )
        if grp["line"] == 0 and line > 0:
            grp["line"] = line
        grp["verdicts"].append(str(c.get("verdict_kind") or "unknown"))
        if goal not in grp["goals"]:
            grp["goals"].append(goal)

    for (kind, _group_key), grp in variant_groups.items():
        line = int(grp["line"])
        if (line > 0 and line in existing_term_lines) or (line == 0 and has_existing_term):
            continue
        _add_synthesized(kind, str(grp["file"]), line, list(grp["verdicts"]), list(grp["goals"]))

    # 2. General fallback when CSV + variant reconciliation still left `unproven_goals` empty
    #    despite WP reporting unproved or timed-out VCs.
    if unproven_goals or not has_vc_deficit:
        return

    other_groups: dict[str, dict[str, Any]] = {}
    for c in goal_costs:
        if not _active_cost(c):
            continue
        goal = str(c["goal"])
        if goal in matched_goals:
            continue
        group_key = str(c.get("property") or goal)
        line = int(c["line"]) if isinstance(c.get("line"), int) and not isinstance(c.get("line"), bool) else 0
        raw_file = c.get("file")
        file_name = Path(str(raw_file)).name if isinstance(raw_file, str) and raw_file else c_file.name
        grp = other_groups.setdefault(
            group_key,
            {
                "kind": _infer_kind_from_wp_goal(goal, fn_name),
                "file": file_name,
                "line": line,
                "verdicts": [],
                "goals": [],
            },
        )
        if grp["line"] == 0 and line > 0:
            grp["line"] = line
        grp["verdicts"].append(str(c.get("verdict_kind") or "unknown"))
        if goal not in grp["goals"]:
            grp["goals"].append(goal)

    if not other_groups:
        # Handle log-only `[Unsuccess]` / `[Incorrect]` / `[Invalid]` goals outside `goal_costs`.
        for goal in sorted(parse_failed_wp_goals(combined_log)):
            if goal in assumed_fpv or goal in matched_goals or "_wp_smoke_" in goal:
                continue
            other_groups[goal] = {
                "kind": _infer_kind_from_wp_goal(goal, fn_name),
                "file": c_file.name,
                "line": 0,
                "verdicts": ["unknown"],
                "goals": [goal],
            }

    for grp in other_groups.values():
        _add_synthesized(
            str(grp["kind"]),
            str(grp["file"]),
            int(grp["line"]),
            list(grp["verdicts"]),
            list(grp["goals"]),
        )


def run_wp_on_function(
    c_file: Path,
    fn_name: str,
    out_dir: Path,
    machdep: str = "gcc_x86_64",
    cppflags: str = "-I.",
    provers: str = "alt-ergo,z3,cvc5",
    wp_par: int | str = "auto",
    timeout: int = 15,
    wp_steps: int = 0,
    wp_model: str = "Typed",
    check_memory_model: bool = True,
    warn_invalid_pointer: bool = True,
    unsigned_reduced: bool = False,
    warn_unsigned_downcast: bool = True,
    retry_bitwise: bool = True,
    retry_tail: bool = True,
    smoke_tests: bool = False,
    counter_examples: bool = False,
    prop: str | None = None,
    dump_goal: bool = False,
    session_dir: Path | None = None,
    extra_sources: list[str] | None = None,
    wall_timeout: int | None = None,
    artifact_suffix: str = "",
    cache_dir: str | Path | None = "auto",
    sarif: bool = False,
    keep_goals: bool = False,
    wp_blockers: list[str] | None = None,
    ignore_prover_budget: bool = False,
    retry_cast_probe: bool = True,
    security_meta: dict | None = None,
    retry_bytes: bool = False,
    warn_signed_downcast: bool = True,
) -> dict:
    call_args: dict[str, Any] = dict(locals())  # first statement: exactly this call's arguments
    try:
        with _out_dir_lock(out_dir, fn_name):
            return _run_wp_on_function_locked(call_args)
    except OutDirLockedError as exc:
        err_res = _analysis_error_result(
            fn_name,
            c_file,
            OUT_DIR_LOCKED_REASON,
            None,
            scan_wp_log_soundness(""),
            str(exc),
        )
        err_res["error_summary"] = [str(exc)]
        err_res["lock_owner"] = exc.owner
        err_res["sizing"] = {
            "wp_par": resolve_wp_par(wp_par),
            "wp_memlimit_mb": WP_MEMLIMIT_MB,
            "wall_timeout_s": wall_timeout,
            "wp_cache_dir": None,
        }
        return err_res


def _run_wp_on_function_locked(call_args: dict[str, Any]) -> dict:
    c_file: Path = call_args["c_file"]
    fn_name: str = call_args["fn_name"]
    out_dir: Path = call_args["out_dir"]
    machdep: str = call_args["machdep"]
    cppflags: str = call_args["cppflags"]
    provers: str = call_args["provers"]
    wp_par: int | str = call_args["wp_par"]
    timeout: int = call_args["timeout"]
    wp_steps: int = call_args["wp_steps"]
    wp_model: str = call_args["wp_model"]
    check_memory_model: bool = call_args["check_memory_model"]
    warn_invalid_pointer: bool = call_args["warn_invalid_pointer"]
    unsigned_reduced: bool = call_args["unsigned_reduced"]
    warn_unsigned_downcast: bool = call_args["warn_unsigned_downcast"]
    retry_bitwise: bool = call_args["retry_bitwise"]
    retry_tail: bool = call_args["retry_tail"]
    smoke_tests: bool = call_args["smoke_tests"]
    counter_examples: bool = call_args["counter_examples"]
    prop: str | None = call_args["prop"]
    dump_goal: bool = call_args["dump_goal"]
    session_dir: Path | None = call_args["session_dir"]
    extra_sources: list[str] | None = call_args["extra_sources"]
    wall_timeout: int | None = call_args["wall_timeout"]
    artifact_suffix: str = call_args["artifact_suffix"]
    cache_dir: str | Path | None = call_args["cache_dir"]
    sarif: bool = call_args["sarif"]
    keep_goals: bool = call_args["keep_goals"]
    wp_blockers: list[str] | None = call_args["wp_blockers"]
    ignore_prover_budget: bool = call_args["ignore_prover_budget"]
    retry_cast_probe: bool = call_args["retry_cast_probe"]
    security_meta: dict | None = call_args["security_meta"]
    retry_bytes: bool = call_args["retry_bytes"]
    warn_signed_downcast: bool = call_args["warn_signed_downcast"]
    if counter_examples and not artifact_suffix.endswith(_MODEL_PASS_SUFFIX):
        return _prove_then_collect_models(call_args)
    out_dir.mkdir(parents=True, exist_ok=True)
    par = resolve_wp_par(wp_par)
    wp_cache = resolve_wp_cache_dir(cache_dir)
    # The counter-example pass proves weaker goals: none of its results may reach the shared prover cache.
    model_pass = counter_examples and artifact_suffix.endswith(_MODEL_PASS_SUFFIX)
    use_wp_cache = wp_cache is not None and not dump_goal and not model_pass
    sizing = {
        "wp_par": par,
        "wp_memlimit_mb": WP_MEMLIMIT_MB,
        "wall_timeout_s": wall_timeout,
        "wp_cache_dir": str(wp_cache) if use_wp_cache else None,
    }
    scratch_dir = _locate_agent_scratch_dir(c_file, out_dir)
    if not artifact_suffix.endswith(("_retry", "_tail", "_castprobe", _BYTES_RETRY_SUFFIX, _MODEL_PASS_SUFFIX)):
        if _is_synthetic_probe_file(c_file, scratch_dir):
            probe_msg = (
                f"Refused to run Frama-C WP on synthetic probe file '{c_file}'. "
                "Prover subagents may only run run_wp_function.py on the assigned target source file under "
                "agents/<id>/scratch/work/. Do not write probe_*.c files to investigate Frama-C WP limitations "
                "(such as \\freeable or \\fresh); write result.json with status 'stalled_after_k_retries' instead."
            )
            soundness = scan_wp_log_soundness("")
            soundness["ok"] = False
            soundness["tier_a_aborts"] = [probe_msg]
            probe_res = {
                "status": "wp_aborted",
                "function": fn_name,
                "file": str(c_file),
                "total_goals": 0,
                "proven_count": 0,
                "proven_under_hyp_count": 0,
                "unproven_count": 0,
                "dead_count": 0,
                "soundness": soundness,
                "undeclared_functions": [],
                "by_obligation_class": {},
                "next_synthesis_focus": "forbidden_synthetic_probe_file_stop_now",
                "unproven_by_bucket": {
                    "step_a_assigns": [],
                    "step_b_loop_invariant": [],
                    "step_c_rte_obligation": [],
                    "step_c_caller_precondition": [],
                    "step_c_contract_postcondition": [],
                },
                "unproven_goals": [],
                "proven_under_hyp_goals": [],
                "goal_dumps": [],
                "sarif_file": None,
                "wp_log_tail": probe_msg,
                "sizing": sizing,
                "diagnostic_hints": [probe_msg],
            }
            return probe_res

        is_var, var_reason = _check_internal_variadic(c_file, fn_name, out_dir, wp_blockers=wp_blockers)
        if is_var:
            variadic_msg = (
                f"Refused to run Frama-C WP on internal variadic function '{fn_name}' ({var_reason}). "
                "Frama-C WP does not support variadic function specifications or proof. "
                "The function is marked with wp_blocker 'internal_variadic' and verifiability "
                "'shell_unverifiable_wp'. Isolate variadic functions behind non-variadic framing "
                "stubs or verify them via E-ACSL / Eva instead."
            )
            soundness = scan_wp_log_soundness("")
            soundness["ok"] = False
            soundness["tier_a_aborts"] = [variadic_msg]
            variadic_res = {
                "status": "wp_aborted",
                "function": fn_name,
                "file": str(c_file),
                "total_goals": 0,
                "proven_count": 0,
                "proven_under_hyp_count": 0,
                "unproven_count": 0,
                "dead_count": 0,
                "soundness": soundness,
                "undeclared_functions": [],
                "by_obligation_class": {},
                "next_synthesis_focus": "internal_variadic_unsupported_by_wp",
                "unproven_by_bucket": {
                    "step_a_assigns": [],
                    "step_b_loop_invariant": [],
                    "step_c_rte_obligation": [],
                    "step_c_caller_precondition": [],
                    "step_c_contract_postcondition": [],
                },
                "unproven_goals": [],
                "proven_under_hyp_goals": [],
                "goal_dumps": [],
                "sarif_file": None,
                "wp_log_tail": variadic_msg,
                "sizing": sizing,
                "diagnostic_hints": [variadic_msg],
                "wp_blockers": ["internal_variadic"],
            }
            return variadic_res

        if scratch_dir is not None and not ignore_prover_budget:
            budget_path = scratch_dir / ".prover_budget.json"
            if budget_path.is_file():
                try:
                    budget_data = json.loads(budget_path.read_text(encoding="utf-8"))
                except Exception:
                    budget_data = None
                if isinstance(budget_data, dict):
                    now_ts = time.time()
                    stored_first = budget_data.get("first_wp_at")
                    first_call = True
                    first_wp_at = now_ts
                    if isinstance(stored_first, (int, float)) and stored_first > 0:
                        first_call, first_wp_at = False, float(stored_first)
                    if first_call:
                        budget_data["first_wp_at"] = first_wp_at
                    invocations = int(budget_data.get("wp_invocations") or 0) + 1
                    budget_data["wp_invocations"] = invocations
                    since_first_s = max(0.0, now_ts - float(first_wp_at))
                    queued_s = _prover_budget_lease_wait(budget_data, since_first_s, first_call)
                    try:
                        budget_path.write_text(json.dumps(budget_data, indent=2) + "\n", encoding="utf-8")
                    except Exception:
                        pass
                    max_inv = int(budget_data.get("max_wp_invocations") or 0)
                    max_wall_s = int(budget_data.get("max_wall_clock_s") or 0)
                    # Effort budget: time queued for WP leases in the host broker is not the prover's time.
                    elapsed_s = max(0.0, since_first_s - queued_s)
                    inv_exceeded = max_inv > 0 and invocations > max_inv
                    wall_exceeded = invocations > 1 and max_wall_s > 0 and elapsed_s > max_wall_s
                    if inv_exceeded or wall_exceeded:
                        prior_report_path = scratch_dir / f"wp_{fn_name}.json"
                        prior_report: dict = {}
                        if prior_report_path.is_file():
                            try:
                                loaded = json.loads(prior_report_path.read_text(encoding="utf-8"))
                                if isinstance(loaded, dict):
                                    prior_report = loaded
                            except Exception:
                                prior_report = {}
                        exhausted_msg = (
                            f"Prover budget exhausted for '{fn_name}' "
                            f"(wp_invocations={invocations}/{max_inv or 'unlimited'}, "
                            f"elapsed={int(elapsed_s)}s/{max_wall_s or 'unlimited'}s, "
                            f"excluding {int(queued_s)}s queued for WP leases). "
                            "Stop immediately and write agents/<id>/scratch/result.json with "
                            "status 'stalled_after_k_retries'."
                        )
                        cap_res = {
                            "status": "unproven_goals_remain",
                            "function": fn_name,
                            "file": str(c_file),
                            "total_goals": int(prior_report.get("total_goals") or 0),
                            "proven_count": int(prior_report.get("proven_count") or 0),
                            "proven_under_hyp_count": int(prior_report.get("proven_under_hyp_count") or 0),
                            "unproven_count": int(prior_report.get("unproven_count") or 0),
                            "dead_count": int(prior_report.get("dead_count") or 0),
                            "soundness": prior_report.get("soundness") or scan_wp_log_soundness(""),
                            "undeclared_functions": prior_report.get("undeclared_functions") or [],
                            "by_obligation_class": prior_report.get("by_obligation_class") or {},
                            "next_synthesis_focus": "budget_exhausted_write_result_json_now",
                            "unproven_by_bucket": prior_report.get("unproven_by_bucket")
                            or {
                                "step_a_assigns": [],
                                "step_b_loop_invariant": [],
                                "step_c_rte_obligation": [],
                                "step_c_caller_precondition": [],
                                "step_c_contract_postcondition": [],
                            },
                            "unproven_goals": prior_report.get("unproven_goals") or [],
                            "proven_under_hyp_goals": prior_report.get("proven_under_hyp_goals") or [],
                            "goal_dumps": [],
                            "sarif_file": None,
                            "wp_log_tail": prior_report.get("wp_log_tail") or exhausted_msg,
                            "sizing": sizing,
                            "budget_exhausted": True,
                        }
                        if prior_report.get("wp_allocation_limitation"):
                            cap_res["wp_allocation_limitation"] = True
                        # What the last run said about the frame stays said: readers take a missing
                        # `assigns_vcs_proven` as "not false".
                        for frame_key in ("assigns_vcs_proven", "frame_summary"):
                            if frame_key in prior_report:
                                cap_res[frame_key] = prior_report[frame_key]
                        cap_res["diagnostic_hints"] = derive_wp_diagnostic_hints(
                            cap_res, str(cap_res.get("wp_log_tail") or "")
                        )
                        return cap_res
                    if max_wall_s > 0:
                        rem_s = max(15, int(max_wall_s - elapsed_s))
                        wall_timeout = min(wall_timeout, rem_s) if wall_timeout else rem_s
                        sizing["wall_timeout_s"] = wall_timeout
    mem_limit = enforced_memory_mb()
    if mem_limit is not None and mem_limit < WP_MIN_MEMORY_MB:
        note = (
            f"this job may use {mem_limit} MiB, but WP needs at least {WP_MIN_MEMORY_MB} MiB "
            f"({FRAMAC_KERNEL_RESERVE_MB} MiB for Frama-C plus the fixed {WP_MEMLIMIT_MB} MiB -wp-memlimit of one prover)"
        )
        error_res = _analysis_error_result(
            fn_name, c_file, "insufficient_memory", None, scan_wp_log_soundness(""), note
        )
        error_res["error_summary"] = [note]
        error_res["sizing"] = {**sizing, "memory_limit_mb": mem_limit}
        return error_res

    unframed_var_callees = _find_unframed_variadic_callees(c_file, fn_name, out_dir)

    stem = f"wp_{fn_name}{artifact_suffix}"
    csv_path = out_dir / f"{stem}.csv"
    log_path = out_dir / f"{stem}.log"
    sarif_path = out_dir / f"{stem}.sarif"
    sav_path = out_dir / f"{stem}.sav"
    # Not `.json`: spec_kb (`wp_*.json`) and mutation_check (`*.json`) read every such file next to the
    # result as a WP result object, and this one is a JSON list.
    goals_json_path = out_dir / f"{stem}.wp-report-json"
    # A report left over from an earlier run must never be read as this run's result.
    for stale in (csv_path, sarif_path, sav_path, goals_json_path):
        if stale.exists():
            stale.unlink()
    # Goal files are only kept when asked for (or for a VC dump); otherwise WP writes them to a
    # private temporary directory that is removed after the run.
    tmp_goals: Path | None = None
    if keep_goals or dump_goal:
        wp_out_dir = out_dir / f"wp_goals_{fn_name}{artifact_suffix}"
    else:
        tmp_goals = Path(tempfile.mkdtemp(prefix=f"wp_goals_{fn_name}_"))
        wp_out_dir = tmp_goals

    effective_cppflags = augment_framac_cppflags(cppflags)
    sources = [str(c_file)] + (extra_sources or [])
    meta_stage: list[str] = []
    if security_meta and security_meta.get("meta_file"):
        sources += [s for s in security_meta.get("extra_sources") or [] if s not in sources]
        sources.append(str(security_meta["meta_file"]))
        # MetAcsl translates the meta-properties into a new project; every analysis runs on it
        # (`-then-last`). A name the parse lacks (a gate defined elsewhere) leaves no instance here.
        meta_stage = ["-meta", "-meta-warn-key", "unknown-func=inactive", "-then-last"]
    cmd = [
        "frama-c",
        "-pp-annot",
        "-no-unicode",
        "-machdep",
        machdep,
        # The ACSL syntax/type check, folded into this run: an annotation error aborts parsing.
        "-kernel-warn-key",
        "annot-error=abort",
        "-warn-signed-overflow",
        "-warn-left-shift-negative",
        "-warn-right-shift-negative",
        "-warn-pointer-downcast",
    ]
    if warn_signed_downcast:
        # Off only with --waive-signed-downcast, whose check pass (check_declared_wraps) limits it to the
        # declared wrap lines.
        cmd.insert(cmd.index("-warn-signed-overflow") + 1, "-warn-signed-downcast")
    if warn_invalid_pointer:
        cmd.append("-warn-invalid-pointer")
    if not unsigned_reduced:
        cmd.append("-warn-unsigned-overflow")
        if warn_unsigned_downcast:
            cmd.append("-warn-unsigned-downcast")

    cmd.extend(
        [
            f"-cpp-extra-args={effective_cppflags}",
            *sources,
            *meta_stage,
            "-wp",
            "-wp-rte",
            "-wp-split",
            "-wp-fct",
            fn_name,
            "-wp-model",
            wp_model,
        ]
    )
    if check_memory_model:
        cmd.append("-wp-check-memory-model")
    for p in [p.strip() for p in provers.split(",") if p.strip()]:
        cmd.extend(["-wp-prover", p])
    cmd.extend(
        [
            "-wp-par",
            str(par),
            "-wp-timeout",
            str(timeout),
            # Fixed per prover, whatever the machine: hardware changes how many provers run, never
            # what one may use (scripts/resources.py).
            "-wp-memlimit",
            str(WP_MEMLIMIT_MB),
            "-wp-out",
            str(wp_out_dir),
            # Per-goal verdict, provers and times (unproven_goal_costs, slowest_proved_goals): an output
            # option only, it changes no proof.
            "-wp-report-json",
            str(goals_json_path),
        ]
    )
    if wp_steps > 0:
        cmd.extend(["-wp-steps", str(wp_steps)])
    if session_dir is not None:
        session_dir.mkdir(parents=True, exist_ok=True)
        cmd.extend(["-wp-session", str(session_dir)])
    if use_wp_cache:
        # Frama-C's own goal digests: unchanged goals are not re-proved across iterations.
        cmd.extend(["-wp-cache", "update", "-wp-cache-dir", str(wp_cache)])
    else:
        # Without an explicit mode WP still reads and writes its default cache (`--cache-dir off`,
        # FRAMAC_CACHE=off, a VC dump, the counter-example pass).
        cmd.extend(["-wp-cache", "none"])
    if smoke_tests:
        cmd.extend(["-wp-smoke-tests", "-wp-smoke-timeout", str(min(timeout, 5))])
    if counter_examples:
        # Witness models for failed goals (upstream wp_ce tests): the report's
        # counter_example_goals list names them, and crash verifiers use them as witnesses.
        cmd.append("-wp-counter-examples")
    # Eva's taint checks (security_props.py --eva-taint) carry the second name `eva_taint`: WP cannot
    # prove `\tainted`, so a run whose sources hold one leaves them out. Only then: any -wp-prop, even
    # a purely negative one, also drops the kernel-generated Exit- and Termination-conditions (checked
    # in the analysis image), so it is never passed when there is nothing to exclude.
    exclude_taint = _sources_hold_eva_taint(sources)
    if prop:
        cmd.append(f"-wp-prop={prop},{WP_PROP_EXCLUDE}" if exclude_taint else f"-wp-prop={prop}")
    elif exclude_taint:
        cmd.append(f"-wp-prop={WP_PROP_EXCLUDE}")
    if dump_goal:
        cmd.extend(["-wp-print", "-wp-no-qed"])
    else:
        # Per-prover verdicts for every pending goal (`Prover <Name> <Ver> returns <Verdict>`):
        # WP's `-wp-report-json` keeps only one merged prover per unproved goal. Omitted with
        # `--dump-goal` because `-wp-status` hides Valid goals under `-wp-print`, and `-wp-print`
        # already emits the same per-prover lines.
        cmd.append("-wp-status")

    cmd.extend(["-then-last" if meta_stage else "-then", "-report", "-report-csv", str(csv_path)])
    if sarif:
        cmd.extend(["-save", str(sav_path)])

    timed_out = False
    returncode: int | None
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=wall_timeout,
        )
        returncode, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out, returncode = True, None
        stdout, stderr = _decode_output(exc.stdout), _decode_output(exc.stderr)
    finally:
        if tmp_goals is not None:
            shutil.rmtree(tmp_goals, ignore_errors=True)
    combined_log = (stdout or "") + "\n" + (stderr or "")
    log_path.write_text(combined_log, encoding="utf-8")

    preprocess = _preprocess_failure(combined_log, returncode, timed_out, csv_path.exists())
    if preprocess is not None:
        pp_reason, pp_errors = preprocess
        pp_res = _analysis_error_result(
            fn_name,
            c_file,
            pp_reason,
            returncode,
            scan_wp_log_soundness(
                combined_log,
                check_memory_model=check_memory_model,
                unsigned_reduced=unsigned_reduced,
                warn_invalid_pointer=warn_invalid_pointer,
                warn_unsigned_downcast=warn_unsigned_downcast,
                warn_signed_downcast=warn_signed_downcast,
            ),
            combined_log,
        )
        pp_res["preprocess_errors"] = pp_errors
        if unframed_var_callees:
            pp_res["unframed_variadic_callees"] = unframed_var_callees
        pp_res["sizing"] = sizing
        return pp_res

    meta_failure = metacsl_set_assigns_failure(combined_log, sources) if meta_stage else None
    if meta_failure is not None:
        # Deterministic, not a crash a re-run fixes: the contract of the named callee must change.
        meta_res = _analysis_error_result(
            fn_name,
            c_file,
            METACSL_SET_ASSIGNS,
            returncode,
            scan_wp_log_soundness(
                combined_log,
                check_memory_model=check_memory_model,
                unsigned_reduced=unsigned_reduced,
                warn_invalid_pointer=warn_invalid_pointer,
                warn_unsigned_downcast=warn_unsigned_downcast,
                warn_signed_downcast=warn_signed_downcast,
            ),
            combined_log,
            metacsl_failure=meta_failure,
        )
        meta_res["sizing"] = sizing
        return meta_res

    syntax_errors = _folded_syntax_errors(combined_log, returncode, timed_out, csv_path.exists())
    if syntax_errors is not None:
        syn_res = {
            "status": "acsl_syntax_error",
            "function": fn_name,
            "file": str(c_file),
            "syntax_check": {
                "syntax_ok": False,
                "returncode": returncode,
                "errors": syntax_errors,
                "raw_log": combined_log[-3000:],
            },
        }
        if unframed_var_callees:
            syn_res["unframed_variadic_callees"] = unframed_var_callees
        syn_res["diagnostic_hints"] = derive_wp_diagnostic_hints(syn_res, combined_log)
        return syn_res

    soundness = scan_wp_log_soundness(
        combined_log,
        check_memory_model=check_memory_model,
        unsigned_reduced=unsigned_reduced,
        warn_invalid_pointer=warn_invalid_pointer,
        warn_unsigned_downcast=warn_unsigned_downcast,
        warn_signed_downcast=warn_signed_downcast,
    )
    macro_loop_lines = _find_macro_loop_lines(c_file, fn_name)
    if macro_loop_lines and soundness.get("tier_b_unsound"):
        kept_tier_b: list[str] = []
        macro_loop_warns: list[str] = []
        for msg in soundness["tier_b_unsound"]:
            m_line = _MISSING_ASSIGNS_LINE_RE.search(msg)
            if m_line and int(m_line.group(2)) in macro_loop_lines:
                macro_loop_warns.append(msg)
            else:
                kept_tier_b.append(msg)
        if macro_loop_warns:
            soundness["tier_b_unsound"] = kept_tier_b
            soundness["macro_loop_warnings"] = macro_loop_warns
            soundness["ok"] = len(soundness["tier_a_aborts"]) == 0 and len(soundness["tier_b_unsound"]) == 0
    if not csv_path.exists() and not soundness["tier_a_aborts"]:
        # Killed (OOM, wall-clock limit) or crashed before the report step: nothing was decided
        # into a verified CSV report, which must never read as "unproven goals remain" or "all_proven",
        # while any incremental VC verdicts already logged are preserved under `partial_verdicts`.
        error_res = _analysis_error_result(
            fn_name,
            c_file,
            failure_reason(returncode, timed_out),
            returncode,
            soundness,
            combined_log,
            partial_verdicts=parse_partial_wp_log_verdicts(combined_log),
        )
        if unframed_var_callees:
            error_res["unframed_variadic_callees"] = unframed_var_callees
            error_res["diagnostic_hints"] = derive_wp_diagnostic_hints(error_res, combined_log)
        error_res["sizing"] = sizing
        return error_res
    goal_dumps = extract_vc_goal_dumps(combined_log) if dump_goal else []

    # Frama-C 34 `-wp-fct` never schedules global lemmas and `-report-csv` omits global lemmas and axioms
    # completely, while WP still feeds them (and non-well-founded recursive logic/predicates) to provers.
    target_source_issues, target_lemmas = scan_target_sources_soundness(
        c_file, extra_sources=extra_sources, cppflags=cppflags
    )
    if target_lemmas:
        soundness["unproven_global_lemmas"] = target_lemmas
    if target_source_issues:
        for issue in target_source_issues:
            if issue not in soundness["tier_b_unsound"]:
                soundness["tier_b_unsound"].append(issue)
        soundness["ok"] = False

    if sarif and sav_path.exists():
        subprocess.run(
            [
                "frama-c",
                "-load",
                str(sav_path),
                "-mdr-gen",
                "sarif",
                "-mdr-no-print-libc",
                "-mdr-out",
                str(sarif_path),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

    proven_goals: list[dict] = []
    under_hyp_goals: list[dict] = []
    unproven_goals: list[dict] = []
    unproven_lemmas: list[dict] = []
    dead_goals: list[dict] = []
    partially_proven_count = 0
    buckets: dict[str, list[dict]] = {
        "step_a_assigns": [],
        "step_b_loop_invariant": [],
        "step_c_rte_obligation": [],
        "step_c_caller_precondition": [],
        "step_c_contract_postcondition": [],
    }
    by_class: dict[str, dict[str, int]] = {}
    layer_goals: list[dict] = []
    # One Degenerated goal in the log excuses one unproved `\valid_function` row, never a data-pointer
    # `\object_pointer` alarm: the report CSV carries no goal name, so the rows are matched by predicate and count.
    fpv_assumed_left = len(soundness["assumed_function_pointer_goals"])
    # What the property report has at each line WP warned `void object` on, whichever function it belongs to.
    void_sites = [
        (file, line, (posixpath.normpath(file) if file else "", line)) for file, line in void_object_sites(combined_log)
    ]
    void_rows: dict[tuple[str, int], list[dict]] = {key: [] for _, _, key in void_sites}

    code_checks_unnamed: list[dict[str, int]] = []
    code_rows_named: list[dict] = []
    if csv_path.exists():
        rows = read_report_csv(csv_path)
        check_names, code_checks_unnamed = code_check_rows(
            rows, list((security_meta or {}).get("row_named_checks") or []), fn_name
        )
        code_rows_named = [{"line": rows[i]["line"], "property": name} for i, name in check_names.items()]
        for pos, row in enumerate(rows):
            row_fn = row["function"]
            at_void_site = void_rows.get((_report_row_path(row), row["line"])) if void_rows else None
            if at_void_site is not None and len(at_void_site) < _VOID_OBJECT_ROWS_KEPT:
                at_void_site.append(
                    {
                        "function": row_fn,
                        "kind": row["kind"],
                        "status": row["status_raw"],
                        "annotation": row["property"],
                    }
                )
            if row_fn and row_fn != fn_name:
                continue
            st = row["status"]
            item = {
                "file": row["file"],
                "function": row_fn or fn_name,
                "line": row["line"],
                "kind": row["kind"],
                "status": row["status_raw"],
                "annotation": row["property"],
            }
            name_meta_goal(item, security_meta)
            name_code_goal(item, security_meta, c_file)
            name_code_check(item, check_names.get(pos))
            cls = goal_obligation_class(item)
            item["obligation_class"] = cls
            counts = by_class.setdefault(cls, {"proven": 0, "proven_under_hyp": 0, "unproven": 0})
            if st == STATUS_VALID:
                proven_goals.append(item)
                counts["proven"] += 1
                if str(row["status_raw"]).strip().lower() == "partially proven":
                    partially_proven_count += 1
                if cls in LAYER_CLASSES:
                    layer_goals.append(item)
            elif st == STATUS_VALID_UNDER_HYP:
                # Expected under -wp-fct: callee contracts are hypotheses proven in their own
                # sessions. Kept separate so the proof audit can resolve every hypothesis.
                under_hyp_goals.append(item)
                counts["proven_under_hyp"] += 1
                if cls in LAYER_CLASSES:
                    layer_goals.append(item)
            elif st in (STATUS_UNKNOWN, STATUS_INVALID, STATUS_INVALID_UNDER_HYP, STATUS_NEVER_TRIED):
                # Under -warn-invalid-pointer, loading a function pointer from memory yields a
                # Degenerated \valid_function goal that WP cannot prove; count it as an explicit assumption.
                annot_low = (item.get("annotation") or "").lower()
                kind_low = (item.get("kind") or "").lower()
                if fpv_assumed_left > 0 and "\\valid_function" in annot_low and "\\object_pointer" not in annot_low:
                    fpv_assumed_left -= 1
                    under_hyp_goals.append(item)
                    counts["proven_under_hyp"] += 1
                    continue
                if "unsigned_downcast" in kind_low or "unsigned_downcast" in annot_low:
                    item["c11_modulo_candidate"] = True
                if _is_alloc_limitation_goal(item):
                    item["wp_allocation_limitation"] = True
                if not row_fn or "lemma" in kind_low:
                    unproven_lemmas.append(item)
                bkey = classify_unproven_goal(item)
                item["diagnostic_bucket"] = bkey
                unproven_goals.append(item)
                buckets[bkey].append(item)
                counts["unproven"] += 1
            elif st == STATUS_DEAD:
                dead_goals.append(item)
            elif st == STATUS_INCONSISTENT:
                soundness["tier_b_unsound"].append(
                    f"Inconsistent property status in report CSV for '{item['function']}' "
                    f"({item['kind']} at line {item['line']}: {item['annotation'][:160]})"
                )
                soundness["ok"] = False
                bkey = classify_unproven_goal(item)
                item["diagnostic_bucket"] = bkey
                unproven_goals.append(item)
                buckets[bkey].append(item)
                counts["unproven"] += 1
            elif st == STATUS_ASSUMED:
                # Rows with `row_fn != fn_name` (extern libc/stub contracts) were already skipped above.
                # Ignore any global libc/stub row if Frama-C emits empty-fn axioms in future releases;
                # an assumed (`Considered valid`) property on `fn_name` itself is unsound.
                row_path = _report_row_path(row)
                if (
                    not row_fn
                    and row_path
                    and (_is_libc_header(row_path) or _is_excluded_target_scan_path(Path(row_path)))
                ):
                    continue
                soundness["tier_b_unsound"].append(
                    f"Assumed ('Considered valid') property in report CSV for '{item['function']}' "
                    f"({item['kind']} at line {item['line']}: {item['annotation'][:160]})"
                )
                soundness["ok"] = False
                bkey = classify_unproven_goal(item)
                item["diagnostic_bucket"] = bkey
                unproven_goals.append(item)
                buckets[bkey].append(item)
                counts["unproven"] += 1
            else:
                # Fail closed on STATUS_OTHER or any unrecognised future Frama-C status.
                bkey = classify_unproven_goal(item)
                item["diagnostic_bucket"] = bkey
                unproven_goals.append(item)
                buckets[bkey].append(item)
                counts["unproven"] += 1

    if unproven_lemmas:
        soundness["tier_b_unsound"].append(
            f"{len(unproven_lemmas)} unproven lemma(s) in scope (WP offers unproven lemmas as hypotheses to sibling goals)"
        )
        soundness["ok"] = False

    proved_m = _WP_PROVED_GOALS_RE.search(combined_log)
    timeout_m = _WP_TIMEOUT_COUNT_RE.search(combined_log)
    vc_proved = int(proved_m.group(1)) if proved_m else 0
    vc_total = int(proved_m.group(2)) if proved_m else 0
    vc_timeouts = int(timeout_m.group(1)) if timeout_m else 0
    goal_costs, slowest_proved, goal_costs_source = collect_goal_costs(goals_json_path, combined_log, fn_name)
    all_vcs_cleanly_proved = proved_m is not None and vc_total > 0 and vc_proved == vc_total and vc_timeouts == 0
    has_vc_deficit = vc_timeouts > 0 or (vc_total > 0 and vc_proved < vc_total)
    _reconcile_unreported_wp_goals(
        fn_name=fn_name,
        c_file=c_file,
        goal_costs=goal_costs,
        combined_log=combined_log,
        assumed_fpv=set(soundness["assumed_function_pointer_goals"]),
        all_vcs_cleanly_proved=all_vcs_cleanly_proved,
        has_vc_deficit=has_vc_deficit,
        unproven_goals=unproven_goals,
        buckets=buckets,
        by_class=by_class,
    )

    # Workstream 3: Automatic bitwise/shift solver retry with Typed+ref+int and extended timeout
    model_parts = {m.strip().lower() for m in re.split(r"[+,]", wp_model) if m.strip()}
    model_problem = wp_model_problem(wp_model)
    if model_problem:
        # Whoever chose the model, a proof under one outside the allowlist (`cast`, `Hoare`, `Region`,
        # `nat`, ...) never counts: all_proven becomes unsound_proof, with the reason.
        soundness["tier_b_unsound"].append(model_problem)
        soundness["ok"] = False
    if (
        retry_bitwise
        and len(unproven_goals) > 0
        and not soundness["tier_a_aborts"]
        and "int" not in model_parts
        and _has_bitwise_unproven_goals(unproven_goals, combined_log)
    ):
        retry_model = "Typed+ref+int"
        retry_timeout = max(timeout, 30)
        try:
            retry_res = run_wp_on_function(
                c_file=c_file,
                fn_name=fn_name,
                out_dir=out_dir,
                machdep=machdep,
                cppflags=cppflags,
                provers=provers,
                wp_par=par,
                timeout=retry_timeout,
                wp_steps=wp_steps,
                wp_model=retry_model,
                check_memory_model=check_memory_model,
                warn_invalid_pointer=warn_invalid_pointer,
                unsigned_reduced=unsigned_reduced,
                warn_unsigned_downcast=warn_unsigned_downcast,
                warn_signed_downcast=warn_signed_downcast,
                retry_bitwise=False,
                retry_tail=False,
                retry_cast_probe=False,
                security_meta=security_meta,
                smoke_tests=smoke_tests,
                counter_examples=counter_examples,
                prop=prop,
                dump_goal=dump_goal,
                session_dir=session_dir,
                extra_sources=extra_sources,
                wall_timeout=wall_timeout,
                artifact_suffix=f"{artifact_suffix}_retry",
                # The same prover cache: goals unchanged by the model switch are not re-proved.
                cache_dir=wp_cache if wp_cache is not None else "off",
                sarif=sarif,
                keep_goals=keep_goals,
            )
            if (
                retry_res.get("status") not in ("analysis_error", "acsl_syntax_error")
                and retry_res.get("soundness", {}).get("ok", False)
                and retry_res.get("unproven_count", len(unproven_goals)) < len(unproven_goals)
            ):
                retry_res["bitwise_retry"] = {
                    "triggered": True,
                    "wp_model": retry_model,
                    "timeout": retry_timeout,
                    "initial_unproven_count": len(unproven_goals),
                }
                return retry_res
        except Exception:
            pass

    # Automatic focused tail retry when >=90% of VCs are proven (or >=5 proven properties and <=6
    # unproven properties with >=3:1 ratio) and 1..30 VCs timed out on SMT solvers.
    if (
        retry_tail
        and not prop
        and not dump_goal
        and len(unproven_goals) > 0
        and soundness["ok"]
        and not _WHY3_MEMADDR_ERR_RE.search(combined_log)
    ):
        proven_props = len(proven_goals) + len(under_hyp_goals)
        high_vc_ratio = vc_total >= 10 and (vc_proved / vc_total) >= 0.90
        high_prop_ratio = (
            proven_props >= 5
            and len(unproven_goals) <= 6
            and (proven_props / max(1, proven_props + len(unproven_goals))) >= 0.75
        )
        has_timeout_tail = (1 <= vc_timeouts <= 30) or (vc_total == 0 and high_prop_ratio)
        if (high_vc_ratio or high_prop_ratio) and has_timeout_tail:
            tail_timeout = max(timeout * 2, 45)
            # Never introduce a -wp-steps cap when wp_steps == 0 (unbounded steps up to timeout);
            # capping at 50k steps causes [Stepout] regressions on heavy goals that otherwise
            # finish within the extended timeout.
            tail_steps = max(wp_steps * 2, 50000) if wp_steps > 0 else 0
            if tail_timeout > timeout or tail_steps > wp_steps:
                try:
                    tail_res = run_wp_on_function(
                        c_file=c_file,
                        fn_name=fn_name,
                        out_dir=out_dir,
                        machdep=machdep,
                        cppflags=cppflags,
                        provers=provers,
                        wp_par=par,
                        timeout=tail_timeout,
                        wp_steps=tail_steps,
                        wp_model=wp_model,
                        check_memory_model=check_memory_model,
                        warn_invalid_pointer=warn_invalid_pointer,
                        unsigned_reduced=unsigned_reduced,
                        warn_unsigned_downcast=warn_unsigned_downcast,
                        warn_signed_downcast=warn_signed_downcast,
                        retry_bitwise=False,
                        retry_tail=False,
                        retry_cast_probe=False,
                        security_meta=security_meta,
                        smoke_tests=smoke_tests,
                        counter_examples=counter_examples,
                        prop=prop,
                        dump_goal=dump_goal,
                        session_dir=session_dir,
                        extra_sources=extra_sources,
                        wall_timeout=wall_timeout,
                        artifact_suffix=f"{artifact_suffix}_tail",
                        cache_dir=wp_cache if wp_cache is not None else "off",
                        sarif=sarif,
                        keep_goals=keep_goals,
                    )
                    tail_unproven = tail_res.get("unproven_count", len(unproven_goals))
                    tail_vc_proved = int((tail_res.get("wp_vc_stats") or {}).get("proved") or 0)
                    improved = (tail_unproven < len(unproven_goals)) or (
                        tail_unproven == len(unproven_goals) and vc_total > 0 and tail_vc_proved > vc_proved
                    )
                    if (
                        tail_res.get("status") not in ("analysis_error", "acsl_syntax_error")
                        and tail_res.get("soundness", {}).get("ok", False)
                        and improved
                    ):
                        tail_res["tail_retry"] = {
                            "triggered": True,
                            "timeout": tail_timeout,
                            "wp_steps": tail_steps,
                            "initial_unproven_count": len(unproven_goals),
                            "initial_vc_proved": vc_proved,
                        }
                        return tail_res
                except Exception:
                    pass

    total_goals = len(proven_goals) + len(under_hyp_goals) + len(unproven_goals)
    vc_proved_valid = (
        (proved_m is not None and vc_total > 0 and vc_proved == vc_total)
        if csv_path.exists()
        else (vc_total == 0 or vc_proved == vc_total)
    )
    all_valid = (
        (total_goals > 0)
        and (len(unproven_goals) == 0)
        and vc_proved_valid
        and (vc_timeouts == 0)
        and (returncode == 0)
        and soundness["ok"]
    )
    # A contract without an `assigns` clause has no assigns goal that could fail: zero unproven assigns goals is
    # then not a proven frame (libmodbus run-1, modbus_write_register). `unknown` keeps the goal count's answer.
    frame_clause = frame_clause_state(combined_log, fn_name)
    no_frame = frame_clause["assigns_clause"] in (ASSIGNS_ABSENT, ASSIGNS_BEHAVIORS_ONLY)
    assigns_vcs_proven = len(buckets["step_a_assigns"]) == 0 and not no_frame

    if soundness["tier_a_aborts"]:
        status = "wp_aborted"
    elif not soundness["ok"] and len(unproven_goals) == 0:
        status = "unsound_proof"
    elif all_valid:
        status = "all_proven"
    else:
        status = "unproven_goals_remain"

    all_unproven_are_alloc = bool(unproven_goals) and all(
        bool(g.get("wp_allocation_limitation")) for g in unproven_goals
    )
    if all_unproven_are_alloc:
        soundness["tier_b_unsound"] = [
            msg
            for msg in soundness["tier_b_unsound"]
            if not ("not yet supported (skipped)" in msg and _WP_ALLOC_UNSUPPORTED_RE.search(msg))
        ]
        soundness["ok"] = len(soundness["tier_a_aborts"]) == 0 and len(soundness["tier_b_unsound"]) == 0

    # Determine next recommended synthesis focus for the Prover Subagent
    if soundness["tier_a_aborts"]:
        next_focus = "tier_a_abort_restructure_required"
    elif soundness["tier_b_unsound"]:
        next_focus = "tier_b_soundness_fix_required"
    elif all_unproven_are_alloc:
        next_focus = "wp_dynamic_allocation_limitation_stop_now"
    elif buckets["step_a_assigns"]:
        next_focus = "step_a_assigns"
    elif buckets["step_b_loop_invariant"]:
        next_focus = "step_b_loop_invariant"
    elif buckets["step_c_rte_obligation"]:
        next_focus = "step_c_rte_obligation"
    elif buckets["step_c_caller_precondition"]:
        next_focus = "step_c_caller_precondition"
    elif buckets["step_c_contract_postcondition"]:
        next_focus = "step_c_contract_postcondition"
    else:
        next_focus = "complete"

    model_goals = parse_model_goals(combined_log) if counter_examples else []

    res = {
        "status": status,
        "function": fn_name,
        "file": str(c_file),
        "wp_model": wp_model,
        "counter_examples": counter_examples,
        "counter_example_goals": model_goals,
        "total_goals": total_goals,
        "proven_count": len(proven_goals),
        "partially_proven_count": partially_proven_count,
        "proven_under_hyp_count": len(under_hyp_goals),
        "unproven_count": len(unproven_goals),
        "dead_count": len(dead_goals),
        "assigns_vcs_proven": assigns_vcs_proven,
        # Frame-error-free breakdown (AutoFraming criterion): a missing/incomplete assigns
        # warning, unproven assigns/loop-assigns goals, or unproven \separated goals all
        # count against the l3_frame unit even when the overall proof succeeds. So does a contract
        # without an `assigns` clause (frame_clause_state): its proof says nothing about the frame.
        "frame_summary": {
            "missing_assigns_warning": bool(_MISSING_ASSIGNS_LINE_RE.search(combined_log)) or no_frame,
            "assigns_vcs_proven": assigns_vcs_proven,
            **frame_clause,
            "l3_frame_goals": by_class.get("l3_frame", {}),
        },
        "soundness": soundness,
        # The lines WP warned `void object` on (void_object_sites), each with what the property report has
        # there. Reported only: WP prints it on correct code too (the `pointer_value` alarm on a loaded
        # `void *`, the libc declaration of a callee with a `void *` formal), so it changes no status.
        "void_object_warnings": [
            {"file": file, "line": line, "properties": void_rows[key]} for file, line, key in void_sites
        ],
        # Non-empty means Frama-C invented `int f()` prototypes: fix the stubs before trusting results.
        "undeclared_functions": scan_undeclared_functions(combined_log),
        "by_obligation_class": by_class,
        "next_synthesis_focus": next_focus,
        "unproven_by_bucket": buckets,
        "unproven_goals": unproven_goals,
        # Keyed by WP goal name (the CSV rows above carry none): verdict kind, provers, time, cached.
        "unproven_goal_costs": goal_costs,
        "slowest_proved_goals": slowest_proved,
        "goal_costs_source": goal_costs_source,
        "wp_timeout_s": timeout,
        "wp_provers": [p.strip() for p in provers.split(",") if p.strip()],
        "proven_under_hyp_goals": under_hyp_goals,
        "layer_goals": layer_goals,
        "goal_dumps": goal_dumps,
        "sarif_file": str(sarif_path) if sarif and sarif_path.exists() else None,
        "wp_log_tail": combined_log[-3000:],
        "sizing": sizing,
    }
    if security_meta:
        hidden = ("meta_file", "line_names", "code_line_names", "code_check_lines", "row_named_checks")
        meta_out: dict[str, Any] = {k: v for k, v in security_meta.items() if k not in hidden}
        # In the report `code_checks` is what this run named, not what security_props.json placed.
        meta_out.pop("code_checks", None)
        named_checks = [*(security_meta.get("code_check_lines") or []), *code_rows_named]
        if named_checks:
            meta_out["code_checks"] = sorted(named_checks, key=lambda c: (int(c["line"]), str(c["property"])))
        if code_checks_unnamed:
            # Their goals stay under `rte`: ledger.py does not credit the property from them.
            meta_out["code_checks_unnamed"] = [*(meta_out.get("code_checks_unnamed") or []), *code_checks_unnamed]
        res["security_props"] = meta_out
    if prop:
        # Counted as proven above, but pending on some other property (check_declared_wraps needs them).
        res["partially_proven_goals"] = [
            g for g in proven_goals if str(g.get("status") or "").strip().lower() == "partially proven"
        ]
    if vc_total > 0:
        res["wp_vc_stats"] = {"proved": vc_proved, "total": vc_total, "timeouts": vc_timeouts}
    if unframed_var_callees:
        res["unframed_variadic_callees"] = unframed_var_callees
    if all_unproven_are_alloc:
        res["wp_allocation_limitation"] = True
    if (
        retry_cast_probe
        and status == "unproven_goals_remain"
        and not prop
        and not dump_goal
        and soundness["ok"]
        and not model_parts & {"cast", "nocast", "bytes"}
        and any(_is_pointer_cast_goal(g) for g in unproven_goals)
    ):
        # Diagnostic only: `cast` is the unsound model (WP manual, Section Memory models), so its result is never
        # promoted. It tells a memory-model limit from a contract that is simply too weak.
        try:
            probe: dict = run_wp_on_function(
                c_file=c_file,
                fn_name=fn_name,
                out_dir=out_dir,
                machdep=machdep,
                cppflags=cppflags,
                provers=provers,
                wp_par=par,
                timeout=timeout,
                wp_steps=wp_steps,
                wp_model="Typed+cast",
                check_memory_model=check_memory_model,
                warn_invalid_pointer=warn_invalid_pointer,
                unsigned_reduced=unsigned_reduced,
                warn_unsigned_downcast=warn_unsigned_downcast,
                warn_signed_downcast=warn_signed_downcast,
                retry_bitwise=False,
                retry_tail=False,
                retry_cast_probe=False,
                security_meta=security_meta,
                smoke_tests=False,
                extra_sources=extra_sources,
                wall_timeout=wall_timeout,
                artifact_suffix=f"{artifact_suffix}_castprobe",
                cache_dir="off",
            )
        except Exception as exc:  # a failed probe never changes the real result
            probe = {"status": "probe_error", "reason": f"{type(exc).__name__}: {exc}"}
        # The probe's own model is the unsound one, so its only expected soundness issue is that.
        probe_soundness = probe.get("soundness") or {}
        proves_all = probe.get("status") == "all_proven" or (
            probe.get("status") == "unsound_proof"
            and probe.get("unproven_count") == 0
            and list(probe_soundness.get("tier_b_unsound") or []) == [WP_UNSOUND_MODEL_ISSUE]
            and not probe_soundness.get("tier_a_aborts")
        )
        res["cast_model_probe"] = {
            "wp_model": "Typed+cast",
            "status": probe.get("status"),
            "unproven_count": probe.get("unproven_count"),
            "proves_all": proves_all,
            "evidence": False,  # unsound model: never credited as a proof
        }
        if proves_all:
            res["wp_cast_limitation"] = True
            res["next_synthesis_focus"] = "wp_typed_cast_limitation_stop_now"
    bytes_trigger = (
        _bytes_retry_trigger(res, combined_log)
        if retry_bytes and not prop and not dump_goal and status != "all_proven" and model_parts == {"typed"}
        else None
    )
    if bytes_trigger:
        try:
            bytes_res: dict = run_wp_on_function(
                c_file=c_file,
                fn_name=fn_name,
                out_dir=out_dir,
                machdep=machdep,
                cppflags=cppflags,
                provers=provers,
                wp_par=par,
                timeout=timeout,
                wp_steps=wp_steps,
                wp_model=BYTES_RETRY_MODEL,
                check_memory_model=check_memory_model,
                warn_invalid_pointer=warn_invalid_pointer,
                unsigned_reduced=unsigned_reduced,
                warn_unsigned_downcast=warn_unsigned_downcast,
                warn_signed_downcast=warn_signed_downcast,
                retry_bitwise=False,
                retry_tail=False,
                retry_cast_probe=False,
                retry_bytes=False,
                security_meta=security_meta,
                smoke_tests=smoke_tests,
                session_dir=session_dir,
                extra_sources=extra_sources,
                wall_timeout=wall_timeout,
                artifact_suffix=f"{artifact_suffix}{_BYTES_RETRY_SUFFIX}",
                cache_dir=wp_cache if wp_cache is not None else "off",
                sarif=sarif,
                keep_goals=keep_goals,
            )
        except Exception as exc:  # a failed retry never changes the Typed result
            bytes_res = {"status": "retry_error", "reason": f"{type(exc).__name__}: {exc}"}
        kept, why = decide_bytes_retry(status, len(unproven_goals), soundness["ok"], bytes_res)
        record = {
            "triggered": True,
            "trigger": bytes_trigger,
            "kept": kept,
            "reason": why,
            "wp_model": BYTES_RETRY_MODEL,
            "typed_status": status,
            "typed_unproven_count": len(unproven_goals),
            "bytes_status": bytes_res.get("status"),
            "bytes_unproven_count": bytes_res.get("unproven_count"),
        }
        if kept:
            # The report's wp_model is Bytes, so the parent's merge check, the sweep and the ledger replay
            # and record it (framac_common.wp_model_assumption).
            bytes_res["bytes_retry"] = record
            return bytes_res
        res["bytes_retry"] = record
    if _WHY3_MEMADDR_ERR_RE.search(combined_log):
        res["wp_why3_memaddr_limitation"] = True
    if _WHY3_ANOMALY_RE.search(combined_log):
        res["wp_why3_anomaly"] = True
    if soundness.get("macro_loop_warnings"):
        res["wp_macro_loop_limitation"] = True
    res["diagnostic_hints"] = derive_wp_diagnostic_hints(res, combined_log)
    return res


def run_vacuity_check(
    c_file: Path,
    fn_name: str,
    out_dir: Path,
    machdep: str = "gcc_x86_64",
    cppflags: str = "-I.",
    provers: str = "alt-ergo,z3,cvc5",
    wp_model: str = "Typed",
    wp_par: int | str | None = None,
    extra_sources: list[str] | None = None,
) -> dict:
    """
    Ask WP whether the contract of `fn_name` can hold at all.

    A separate pass, so smoke goals never mix with the proof's own counts. It needs no RTE goals,
    and contract goals get a short timeout: only the smoke goals matter here. A prover that cannot
    refute a `requires` within the timeout leaves it `consistent`, meaning "not refuted".
    """
    cmd = [
        "frama-c",
        "-pp-annot",
        "-no-unicode",
        "-machdep",
        machdep,
        f"-cpp-extra-args={augment_framac_cppflags(cppflags)}",
        str(c_file),
        *(extra_sources or []),
        "-wp",
        "-wp-fct",
        fn_name,
        "-wp-model",
        wp_model,
    ]
    for p in [p.strip() for p in provers.split(",") if p.strip()]:
        cmd.extend(["-wp-prover", p])
    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="vacuity_", dir=out_dir) as wp_out:
        cmd.extend(
            [
                "-wp-par",
                str(resolve_wp_par(wp_par)),
                "-wp-timeout",
                str(VACUITY_GOAL_TIMEOUT_S),
                "-wp-memlimit",
                str(WP_MEMLIMIT_MB),
                "-wp-out",
                wp_out,
                "-wp-cache",
                "none",
                "-wp-smoke-tests",
                "-wp-smoke-timeout",
                str(VACUITY_SMOKE_TIMEOUT_S),
            ]
        )
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=VACUITY_WALL_TIMEOUT_S,
            )
        except subprocess.TimeoutExpired:
            return {"status": "inconclusive", "reason": f"timed out after {VACUITY_WALL_TIMEOUT_S}s", "doomed": []}
        except OSError as exc:
            return {"status": "inconclusive", "reason": str(exc), "doomed": []}
    return classify_vacuity_log(proc.stdout + proc.stderr, proc.returncode)


def classify_vacuity_log(log_text: str, returncode: int | None = 0) -> dict:
    doomed = sorted(set(_DOOMED_REQUIRES_RE.findall(log_text)))
    dead_matches = _DOOMED_DEAD_RE.findall(log_text)
    dead = sorted(set(dead_matches))
    if doomed:
        return {"status": "contradictory", "doomed": doomed, "dead_goals": len(dead)}
    if returncode != 0:
        return {
            "status": "inconclusive",
            "reason": f"smoke pass produced no result (rc={returncode})",
            "doomed": [],
            "dead_goals": len(dead),
        }
    if "Smoke Tests" not in log_text:
        # Clean leaf functions without `requires`, branches, loops, or calls emit `Proved goals:` with
        # 0 smoke goals and no `Smoke Tests:` line. Treat a clean rc=0 pass with no failures or doomed
        # goals as consistent (`smoke_goals: 0`) rather than inconclusive.
        has_failed = bool(
            "[wp] [Failed]" in log_text
            or "[wp] [Failure]" in log_text
            or re.search(r"^\s*Failed\s*:", log_text, re.MULTILINE)
        )
        if "Proved goals:" in log_text and not _ANY_DOOMED_RE.search(log_text) and not has_failed:
            return {"status": "consistent", "doomed": [], "dead_goals": 0, "smoke_goals": 0}
        unknown_no_summary = sorted({g for g in _ANY_DOOMED_RE.findall(log_text) if g not in set(dead)})
        out: dict[str, Any] = {
            "status": "inconclusive",
            "reason": f"smoke pass produced no result (rc={returncode})",
            "doomed": [],
            "dead_goals": len(dead),
        }
        if unknown_no_summary:
            out["unknown_doomed"] = unknown_no_summary
        return out
    m_count = _SMOKE_COUNT_RE.search(log_text)
    if not m_count:
        return {
            "status": "inconclusive",
            "reason": "malformed smoke test results line",
            "doomed": [],
            "dead_goals": len(dead),
        }
    k, n = int(m_count.group(1)), int(m_count.group(2))
    if n <= 0 or k > n or k < 0:
        return {
            "status": "inconclusive",
            "reason": f"invalid smoke test counts ({k}/{n})",
            "doomed": [],
            "dead_goals": len(dead),
        }
    dead_set = set(dead)
    unknown_doomed = sorted({g for g in _ANY_DOOMED_RE.findall(log_text) if g not in dead_set})
    # Frama-C 34 WP with P configured provers prints `[Failed] (Doomed) <goal>` once per prover
    # and counts each report in the `Smoke Tests: k / n` denominator (e.g. 1 dead_code goal under
    # alt-ergo,z3,cvc5 prints 3 lines and `Smoke Tests: 2 / 5`), so match `n - k` against the raw
    # recognised dead-goal occurrences while keeping `dead_goals` as the unique goal count.
    unexplained_fails = (n - k) - len(dead_matches)
    if unknown_doomed or (k < n and not dead) or (unexplained_fails > 0):
        return {
            "status": "inconclusive",
            "reason": f"smoke test failure ({k}/{n}) without recognised doomed goals",
            "doomed": [],
            "dead_goals": len(dead),
            "unknown_doomed": unknown_doomed,
            "unexplained_fails": max(0, unexplained_fails),
        }
    return {"status": "consistent", "doomed": [], "dead_goals": len(dead), "smoke_goals": n}


def _read_goal_source(goal: dict, c_file: Path) -> str | None:
    """The file a goal was reported in (contracts often live in a header), or None if it cannot be read."""
    rel = str(goal.get("file") or "")
    for cand in (Path(rel), c_file.parent / rel, c_file.parent / Path(rel).name, c_file):
        with contextlib.suppress(OSError):
            if rel and cand.is_file():
                return cand.read_text(encoding="utf-8", errors="replace")
    return None


def layer_clause_limits(goals: list[dict], c_file: Path) -> dict:
    """
    Classify the proven goals of the MetAcsl classes (LAYER_CLASSES) whose name is an L3-L6 clause
    name by reading their source. A class whose every clause says
    nothing about the function (`\\true`, `x == x`) lands in `classes_without_real_clause`.
    The check is syntactic: a tautology it cannot see stays credited.
    """
    by_class: dict[str, set[str]] = {}
    trivial: set[str] = set()
    unchecked: set[str] = set()
    for goal in goals:
        m = _LAYER_NAME_RE.search(f"{goal.get('kind', '')} {goal.get('annotation', '')}")
        if not m:
            continue
        name = m.group(0)
        by_class.setdefault(goal["obligation_class"], set()).add(name)
        source = _read_goal_source(goal, c_file)
        predicate = find_named_clause(source, name) if source is not None else None
        annotation = str(goal.get("annotation") or "")
        if predicate is None and "check" in str(goal.get("kind") or "").lower() and annotation.startswith(f"{name}:"):
            # An in-code check (name_code_goal): the report row itself carries the predicate WP proved.
            predicate = annotation[len(name) + 1 :].strip()
        if predicate is None:
            unchecked.add(name)
        elif is_trivial_predicate(predicate):
            trivial.add(name)
    return {
        "trivial_layer_clauses": sorted(trivial),
        "unchecked_layer_clauses": sorted(unchecked),
        "classes_without_real_clause": sorted(cls for cls, names in by_class.items() if names <= trivial),
    }


def _read_contract(c_file: Path, fn_name: str, cppflags: str) -> contract_refinement.FunctionContract | None:
    try:
        return contract_refinement.read_function_contract(c_file, fn_name, cppflags)
    except (OSError, AcslError):
        return None


def contract_shape_limit(
    c_file: Path, fn_name: str, cppflags: str = "", contract: contract_refinement.FunctionContract | None = None
) -> str:
    """
    The shape of the contract WP proved for `fn_name` (acsl_ast.contract_shape): `functional`,
    `safety_only` or `not_applicable`. The contract is read where Frama-C takes it from: in front of
    the definition in `c_file`, and on the function's declarations in the headers `c_file` includes
    directly, merged (contract_refinement.read_function_contract). A header is looked up beside `c_file`
    and in the `-I` directories of `cppflags`, a relative one against the working directory as the
    preprocessor does; a header that is not found there (a system header, the Frama-C libc) is skipped.
    `unknown` when no contract is found or the source cannot be read: a contract that was not read is
    never reported as `safety_only`. A contract on a header reached only through another header is not read.
    """
    contract = contract or _read_contract(c_file, fn_name, cppflags)
    if contract is None:
        return SHAPE_UNKNOWN
    return contract_shape(contract.text(), returns_void=bool(contract.returns_void))


def frame_only_ensures_limit(
    c_file: Path,
    fn_name: str,
    cppflags: str = "",
    machdep: str = "gcc_x86_64",
    contract: contract_refinement.FunctionContract | None = None,
    work_dir: Path | None = None,
) -> dict:
    """
    Which `ensures` of the proved contract follow from its `requires` and `assigns` alone (use 2 of
    scripts/contract_refinement.py): `{status, ensures, frame_only, not_frame_only, undecided,
    all_frame_only, ...}`. `status` `decided` with `all_frame_only` true means every postcondition
    holds for any body, so the proof is reported with the safety-only ones. `undecided` when the
    contract cannot be read or the probe cannot decide; `not_applicable` without `ensures`.
    """
    contract = contract or _read_contract(c_file, fn_name, cppflags)
    if contract is None or not contract.pieces:
        return {"status": contract_refinement.FRAME_UNDECIDED, "reason": "no contract found", "all_frame_only": False}
    return contract_refinement.frame_only_ensures(contract, c_file, cppflags, machdep, work_dir=work_dir)


def _function_text(c_file: Path, fn_name: str) -> tuple[str, int]:
    """The definition of `fn_name` in `c_file` with its contract, and its first line; ('', 0) when not found."""
    try:
        text = c_file.read_text(encoding="utf-8", errors="replace")
        span = locate_function_span(text, fn_name, path=str(c_file))
    except (OSError, AcslError):
        return "", 0
    if span is None:
        return "", 0
    return span.text, span.start_line


def calls_targets(fn_text: str) -> list[str]:
    """The functions named by `//@ calls f, g;` annotations in a function's text, in order."""
    names: list[str] = []
    for comment in _ACSL_COMMENT_RE.findall(fn_text):
        for m in _ACSL_CALLS_RE.finditer(comment):
            names.extend(n.strip() for n in m.group(1).split(","))
    return list(dict.fromkeys(names))


def _open_call_lines(log_text: str, fn_text: str, fn_line: int, exprs: list[str]) -> list[int]:
    """
    Lines of the indirect calls WP could not resolve (its `Missing 'calls'` warning), else the lines of the
    function's text where an open site's expression is called (`p->cb(` or `(*p->cb)(`).
    """
    lines = sorted({int(m.group("line")) for m in _MISSING_CALLS_LINE_RE.finditer(log_text or "")})
    if lines or not fn_text:
        return lines
    code = mask_comments_and_literals(fn_text, acsl="blank", literals=True, on_error="mask")
    found: set[int] = set()
    for expr in exprs:
        spaced = r"\s*".join(re.escape(part) for part in re.split(r"\s+", expr.strip()) if part)
        for m in re.finditer(rf"(?:\(\s*\*\s*)?{spaced}\s*\)?\s*\(", code):
            found.add(fn_line + code.count("\n", 0, m.start()))
    return sorted(found)


def _downstream_of_open_call(goal: dict, call_lines: list[int]) -> bool:
    """
    A goal of the function's own contract, or one on a line after the first open call of the body. A goal on
    the call's own line is not: it is usually about the call's arguments (`\\object_pointer(p->ctx)`), which
    are evaluated before the call and can be proved.
    """
    kind = str(goal.get("kind") or "").strip().lower()
    if "loop" not in kind and kind.startswith(_CONTRACT_GOAL_KINDS):
        return True
    line = goal.get("line")
    return bool(call_lines) and isinstance(line, int) and line > min(call_lines)


def _open_callback_hint(sites: list[dict], downstream: int, other: int) -> str:
    shown = ", ".join(f"`{s.get('expr')}` (type `{s.get('signature')}`)" for s in sites[:3])
    hint = (
        f"Open-world callback: {shown} has no target in the program (no function of that type has its address "
        "taken), so no '//@ calls' or 'assert fp \\in {...}' can name one and WP cannot frame the call: it havocs "
        "memory and may not terminate. Do not name any function in 'calls' at this site. "
    )
    if other:
        return hint + (
            f"{other} unproven goal(s) do not depend on the callback (before the call, not in the contract): prove "
            "those, then finish as below. "
            f"The {downstream} goal(s) in 'open_callback_boundary.downstream_goals' cannot be proved: keep the "
            "contract callers need (never delete 'assigns' or 'ensures'), list them in 'unproven_goals', record the "
            "callback in 'boundary_assumptions' and 'proof_gap', and finish with 'stalled_after_k_retries'."
        )
    return hint + (
        f"Every unproven goal ({downstream}) depends on the callback: stop now. Keep the contract callers need "
        "(never delete 'assigns' or 'ensures'), list these goals in 'unproven_goals', record the callback in "
        "'boundary_assumptions' and 'proof_gap', and finish with 'stalled_after_k_retries'."
    )


def apply_open_callback_boundary(
    res: dict, c_file: Path, fn_name: str, out_dir: Path, dag: dict | None = None, log_text: str | None = None
) -> dict:
    """
    An open-world callback in `fn_name` (the DAG's `open_indirect_calls`, from the Phase 0 model: no function
    of the called pointer's type has its address taken in the program). No `calls` target exists, so WP
    cannot frame the call and the goals after it stay Unknown whatever the contract says. Records
    `open_callback_boundary` in the report; when every unproven goal depends on the call, the focus becomes
    OPEN_CALLBACK_FOCUS so the prover stops instead of spending its retries. A `calls` annotation naming a
    function that is not a type-matched target of the function's call sites is tier-B unsound: that
    function is never the target, and WP would use its contract as an unrecorded assumption about the
    user's callback. Never makes a proof pass: `soundness.ok` and the status only ever get worse.
    """
    if res.get("status") not in ("all_proven", "unproven_goals_remain", "unsound_proof"):
        return res
    dag = dag if dag is not None else _find_and_load_dag(c_file, out_dir)
    rec = _dag_function_record(dag, c_file, fn_name) if dag else None
    sites = [s for s in (rec or {}).get("open_indirect_calls") or [] if isinstance(s, dict) and s.get("expr")]
    if not sites:
        return res
    functions = (dag or {}).get("functions") or {}
    allowed_keys = (rec or {}).get("indirect_callees")
    if allowed_keys is None:
        allowed_keys = (rec or {}).get("internal_callees") or []
    allowed = {str((functions.get(k) or {}).get("name") or str(k).rpartition("#")[2]) for k in allowed_keys}
    fn_text, fn_line = _function_text(c_file, fn_name)
    named = calls_targets(fn_text)
    foreign = [t for t in named if t not in allowed]
    if log_text is None:
        try:
            log_text = (out_dir / f"wp_{fn_name}.log").read_text(encoding="utf-8", errors="replace")
        except OSError:
            log_text = str(res.get("wp_log_tail") or "")
    call_lines = _open_call_lines(log_text, fn_text, fn_line, [str(s["expr"]) for s in sites])
    unproven = list(res.get("unproven_goals") or [])
    downstream = [g for g in unproven if _downstream_of_open_call(g, call_lines)]
    other = [g for g in unproven if not _downstream_of_open_call(g, call_lines)]
    res["open_callback_boundary"] = {
        "sites": sites,
        "call_lines": call_lines,
        "calls_targets": named,
        "foreign_calls_targets": foreign,
        "downstream_goals": [
            {"file": g.get("file"), "line": g.get("line"), "kind": g.get("kind"), "annotation": g.get("annotation")}
            for g in downstream
        ],
        "other_unproven": len(other),
    }
    soundness = res.setdefault("soundness", {})
    hints = [h for h in res.get("diagnostic_hints") or [] if h != CALLS_ANNOTATION_HINT]
    if foreign:
        exprs = ", ".join(str(s["expr"]) for s in sites)
        soundness.setdefault("tier_b_unsound", []).append(
            f"'//@ calls {', '.join(foreign)}' in {fn_name}, which has an open-world callback ({exprs}): no "
            "function of the pointer's type has its address taken in the program, so that function is never the "
            "target and WP would assume its contract for the user's callback without recording it"
        )
        soundness["ok"] = False
        if res.get("status") == "all_proven":
            res["status"] = "unsound_proof"
        res["next_synthesis_focus"] = "tier_b_soundness_fix_required"
        hints.insert(
            0,
            f"Remove '//@ calls {', '.join(foreign)}': {exprs} is an open-world callback (no function of the program has its type and its address taken), so no "
            "function is its target, the 'Call point' goal can never be proved, and the other goals would rest on "
            "that function's unchecked contract. Leave the call without 'calls' and follow the open-world callback "
            "recipe of the brief (Step A).",
        )
    else:
        if unproven and not other:
            res["next_synthesis_focus"] = OPEN_CALLBACK_FOCUS
        hints.insert(0, _open_callback_hint(sites, len(downstream), len(other)))
    res["diagnostic_hints"] = list(dict.fromkeys(hints))
    return res


def apply_verdict_limits(
    res: dict,
    c_file: Path,
    vacuity: dict | None,
    cppflags: str = "",
    machdep: str = "gcc_x86_64",
    semantic: bool = True,
    work_dir: Path | None = None,
) -> dict:
    """
    Record what this verdict covered in `res["limits"]`. `coverage-ledger` credits a proof only when
    the limits are recorded (scripts/ledger.py), and a contradictory contract fails the proof here.
    `vacuity` is None when the check did not run. A proof that stands also records
    `limits.contract_shape` (syntactic) and, with `semantic`, `limits.frame_only_ensures` (the probe of
    scripts/contract_refinement.py, one WP run without RTE): both reported only, they change no status
    and no credit.
    """
    soundness = res.get("soundness") or {}
    missing_spec = sorted(
        {
            s.function
            for msg in soundness.get("tier_b_unsound") or []
            for s in parse_missing_spec(msg)
            if not s.benign and s.function
        }
    )
    res["limits"] = {
        "vacuity": vacuity or {"status": "not_run", "doomed": []},
        "missing_spec_callees": missing_spec,
        **layer_clause_limits(res.get("layer_goals") or [], c_file),
    }
    mm_hyps = list(soundness.get("checked_memory_model_hypotheses") or [])
    if not mm_hyps:
        mm_fns = [str(fn).strip() for fn in (soundness.get("checked_memory_model_functions") or []) if str(fn).strip()]
        if mm_fns:
            mm_hyps = [{"function": fn, "requires": []} for fn in mm_fns]
    if mm_hyps:
        res["limits"]["memory_model_hypotheses"] = mm_hyps

    unknown_doomed = list(vacuity.get("unknown_doomed") or []) if isinstance(vacuity, dict) else []
    raw_unexplained = vacuity.get("unexplained_fails") if isinstance(vacuity, dict) else 0
    unexplained_fails = (
        raw_unexplained if isinstance(raw_unexplained, int) and not isinstance(raw_unexplained, bool) else 0
    )
    if vacuity and vacuity["status"] == "contradictory":
        names = ", ".join(vacuity["doomed"])
        soundness.setdefault("tier_b_unsound", []).append(f"Failed smoke-test: contract is contradictory ({names})")
        soundness["ok"] = False
        res["soundness"] = soundness
        res["status"] = "unsound_proof"
        res["next_synthesis_focus"] = "tier_b_soundness_fix_required"
        res["diagnostic_hints"] = derive_wp_diagnostic_hints(res, "")
    elif vacuity and (unknown_doomed or unexplained_fails > 0):
        parts: list[str] = []
        if unknown_doomed:
            parts.append(f"unrecognised doomed smoke goals: {', '.join(str(g) for g in unknown_doomed[:5])}")
        if unexplained_fails > 0:
            parts.append(f"{unexplained_fails} unexplained smoke test failure(s)")
        soundness.setdefault("tier_b_unsound", []).append(f"Failed smoke-test: {'; '.join(parts)}")
        soundness["ok"] = False
        res["soundness"] = soundness
        res["status"] = "unsound_proof"
        res["next_synthesis_focus"] = "tier_b_soundness_fix_required"
        res["diagnostic_hints"] = derive_wp_diagnostic_hints(res, "")
    if res.get("status") == "all_proven" and res.get("function"):
        fn_name = str(res["function"])
        contract = _read_contract(c_file, fn_name, cppflags)
        res["limits"]["contract_shape"] = contract_shape_limit(c_file, fn_name, cppflags, contract=contract)
        if semantic:
            res["limits"]["frame_only_ensures"] = frame_only_ensures_limit(
                c_file, fn_name, cppflags, machdep, contract=contract, work_dir=work_dir
            )
    return res


def _line_list(raw: str) -> list[int]:
    """`--wrap-lines 193,194`: positive line numbers, or argparse rejects the option."""
    try:
        values = [int(item) for item in raw.split(",") if item.strip()]
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected comma-separated line numbers, got {raw!r}") from None
    if any(value < 0 for value in values):
        raise argparse.ArgumentTypeError(f"line numbers cannot be negative: {raw!r}")
    return values


# The RTE properties a declared wrap line may leave unproved, in the order the check names them; the
# second only with --waive-signed-downcast. Also the -wp-prop names of the check pass.
WAIVABLE_WRAP_PROPERTIES = ("unsigned_overflow", "signed_downcast")
_SIGNED_DOWNCAST_KIND_RE = re.compile(r"(?<![a-z])signed_downcast")


def _wrap_property(goal: dict) -> str | None:
    """The waivable property a goal checks (by its report kind), or None."""
    kind = str(goal.get("kind") or "").lower()
    if "unsigned_overflow" in kind:
        return "unsigned_overflow"
    if _SIGNED_DOWNCAST_KIND_RE.search(kind):
        return "signed_downcast"
    return None


def check_declared_wraps(
    res: dict,
    c_file: Path,
    fn_name: str,
    out_dir: Path,
    wrap_lines: list[int] | None = None,
    wrap_code_lines: list[int] | None = None,
    waive_signed_downcast: bool = False,
    **wp_options,
) -> dict:
    """
    `--no-warn-unsigned` turns the unsigned overflow checks off for a whole function, so that a run proves
    nothing about them. This second run, with them on, limits the opt-out to the lines a prover declared
    as deliberate wraps: an `unsigned_overflow` goal elsewhere that is not fully proved leaves the
    function unproven. `--waive-signed-downcast` adds `signed_downcast` (the proof run left
    `-warn-signed-downcast` off): an implementation-defined narrowing of a deliberate wrap, such as
    `(int)(u64 - BIAS)`, is waived on a declared line and fails anywhere else, the same way.

    The proof stays the run with the checks off. Goals cannot be waived inside this one, because WP takes
    each RTE assertion as a hypothesis for what follows, so a false wrap assertion would support later
    proofs. For the same reason only `Valid` clears a goal here: one that is `Partially proven` may rest on
    a declared wrap above it.

    Declarations are stored as positions among the function's code lines (function_facts.code_lines),
    which ACSL merges do not move, so a parent re-check on the merged tree finds the same lines.
    """
    if res.get("status") not in ("all_proven", "unproven_goals_remain") or res.get("budget_exhausted"):
        return res
    text = Path(c_file).read_text(encoding="utf-8", errors="replace")
    code_lines = function_facts.code_lines(text, fn_name, path=str(c_file))
    declared = {position for position in wrap_code_lines or () if 0 <= position < len(code_lines)}
    unknown_lines = []
    for line in wrap_lines or ():
        if line in code_lines:
            declared.add(code_lines.index(line))
        else:
            unknown_lines.append(line)

    waived = WAIVABLE_WRAP_PROPERTIES if waive_signed_downcast else WAIVABLE_WRAP_PROPERTIES[:1]
    check = run_wp_on_function(
        c_file,
        fn_name,
        out_dir,
        unsigned_reduced=False,
        warn_unsigned_downcast=False,
        warn_signed_downcast=True,
        retry_bitwise=False,
        retry_tail=False,
        prop=",".join(waived),
        artifact_suffix="_wrapcheck",
        ignore_prover_budget=True,
        **wp_options,
    )
    if check.get("status") not in ("all_proven", "unproven_goals_remain"):
        res.update(
            status="analysis_error",
            reason=check.get("reason") or "unsigned_wrap_check_failed",
            next_synthesis_focus="analysis_error_rerun_required",
            unsigned_wraps={"status": "check_failed", "check_status": check.get("status")},
        )
        return res

    used: dict[int, dict] = {}
    undeclared: list[dict] = []
    not_fully_proved = [
        *(check.get("unproven_goals") or []),
        *(check.get("proven_under_hyp_goals") or []),
        *(check.get("partially_proven_goals") or []),
    ]
    for goal in not_fully_proved:
        prop_kind = _wrap_property(goal)
        if prop_kind not in waived:
            continue
        try:
            line = int(goal.get("line"))
        except (TypeError, ValueError):
            line = -1
        same_file = Path(str(goal.get("file") or "")).name == Path(c_file).name
        position = code_lines.index(line) if same_file and line in code_lines else None
        if position in declared:
            entry = used.setdefault(
                position, {"line": line, "code_line": position, "annotations": [], "properties": []}
            )
            entry["annotations"].append(goal.get("annotation"))
            if prop_kind not in entry["properties"]:
                entry["properties"].append(prop_kind)
        else:
            undeclared.append(
                {
                    **goal,
                    "diagnostic_bucket": "step_c_rte_obligation",
                    "undeclared_unsigned_wrap": True,
                    "waivable_property": prop_kind,
                }
            )

    declared_entries = [used[position] for position in sorted(used)]
    res["unsigned_wraps"] = {
        "status": "undeclared" if undeclared else "ok",
        "declared": declared_entries,
        "declared_code_lines": [entry["code_line"] for entry in declared_entries],
        "undeclared": [
            {"line": goal.get("line"), "status": goal.get("status"), "annotation": goal.get("annotation")}
            for goal in undeclared
        ],
        "unused_code_lines": sorted(declared - set(used)),
        "unknown_lines": unknown_lines,
    }
    if declared_entries:
        lines = ", ".join(f"L{entry['line']}" for entry in declared_entries)
        kinds = [p for p in waived if any(p in entry["properties"] for entry in declared_entries)]
        res.setdefault("soundness", {}).setdefault("reduced_checks", []).append(
            f"{' and '.join(k.replace('_', ' ') for k in kinds)} left unproved on declared deliberate wraps at {lines}"
        )
    if undeclared:
        res.setdefault("unproven_goals", []).extend(undeclared)
        res.setdefault("unproven_by_bucket", {}).setdefault("step_c_rte_obligation", []).extend(undeclared)
        counts = res.setdefault("by_obligation_class", {}).setdefault(
            "rte", {"proven": 0, "proven_under_hyp": 0, "unproven": 0}
        )
        counts["unproven"] += len(undeclared)
        res["unproven_count"] = int(res.get("unproven_count") or 0) + len(undeclared)
        res["total_goals"] = int(res.get("total_goals") or 0) + len(undeclared)
        res["status"] = "unproven_goals_remain"
        if res.get("next_synthesis_focus") == "complete":
            res["next_synthesis_focus"] = "step_c_rte_obligation"
        lines = ", ".join(sorted({str(goal.get("line")) for goal in undeclared}))
        kinds_text = "/".join(sorted({str(goal["waivable_property"]) for goal in undeclared}))
        res.setdefault("diagnostic_hints", []).append(
            f"With the checks on, {kinds_text} goals are not fully proved on line(s) {lines}, which "
            "--wrap-lines does not declare. Prove them, or declare a line in --wrap-lines only if its wrap is "
            "deliberate. A 'Partially proven' goal below a declared wrap may rest on that wrap's false assertion."
        )
    return res


_ANNOTATION_WORD_RE = re.compile(r"\b(?:check|assert|admit)\b")
_CALLED_TARGET_RE = re.compile(r"\\called\s*==\s*([A-Za-z_]\w*)")
_PRECOND_TARGET_RE = re.compile(r"\\targets\s*\(\s*\{\s*([A-Za-z_]\w*)\s*\}\s*\)\s*,\s*\\context\s*\(\s*\\precond\s*\)")


def code_check_names(props: dict, fid: str, c_file: Path) -> tuple[dict[str, str], list[dict]]:
    """
    The in-code checks security_props.py wrote into this function's file (`code` properties, plan steps
    M6/M7 and the wrapper hand-off), as (line -> property name, checks left unnamed with the reason).

    Frama-C's report gives such a check as a `user check` row with its predicate only. The name is read
    back from the source at the row's line, never from the line `code_checks` recorded: a prover's
    annotations move the check. A name is accepted only when it is a `code` property with an instance in
    this function, the file holds as many `check <name>:` as security_props.py placed for this function
    (a deleted or an added one makes every row of the property unnamed), a property whose check text
    is fixed has that text, and the line holds no other annotation. An unnamed row stays an `rte` goal:
    it credits no L4-L6 unit. The predicate of a check built from a call's arguments (hand-off, return)
    is not compared.
    """
    import security_props

    wanted = {str(p["name"]): p for p in security_props.properties_for(props, fid) if p.get("code")}
    if not wanted:
        return {}, []
    placed: dict[str, int] = dict.fromkeys(wanted, 0)
    for c in props.get("code_checks") or []:
        if isinstance(c, dict) and c.get("function") == fid and str(c.get("property")) in placed:
            placed[str(c.get("property"))] += 1
    try:
        lines = c_file.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return {}, [{"property": n, "reason": f"source not read: {exc}"} for n in sorted(wanted)]
    names: dict[str, str] = {}
    unnamed: list[dict] = []
    for name, prop in sorted(wanted.items()):
        mark = re.compile(rf"\bcheck\s+{re.escape(name)}\s*:")
        found = [(i, line) for i, line in enumerate(lines, start=1) for _ in mark.findall(line)]
        fixed = str((prop.get("code") or {}).get("check") or "")
        reason = None
        if not placed[name]:
            reason = "security_props.json records no placed check of it in this function (`code_checks`)"
        elif len(found) != placed[name]:
            reason = f"{placed[name]} check(s) placed, {len(found)} `check {name}:` in the source"
        elif fixed and "${" not in fixed and any(" ".join(fixed.split()) not in " ".join(t.split()) for _, t in found):
            reason = "the check in the source is not the text security_props.py placed"
        if reason:
            unnamed.append({"property": name, "reason": reason})
            continue
        for i, line in found:
            if len(_ANNOTATION_WORD_RE.findall(line)) != len(mark.findall(line)) or names.get(str(i), name) != name:
                unnamed.append({"property": name, "line": i, "reason": "the line holds another annotation"})
                names.pop(str(i), None)
            else:
                names[str(i)] = name
    return names, unnamed


def call_targets(props: dict, names: list[str], sources: list[Path]) -> dict[str, dict]:
    """
    For each loaded property stated on a call (`\\called == f`) or as the precondition of one function
    (`\\targets({f}), \\context(\\precond)`, proved at the calls of `f`): {function: f, seen: whether the
    name `f` occurs in the code of a file handed to Frama-C (comments and literals aside)}.

    MetAcsl says nothing when `f` is not in the parse: it translates the property, generates no
    instance and reports success, exactly as when it decided every instance statically (Frama-C
    34.0~beta, with `-meta-warn-key unknown-func` inactive or active). libmodbus run-1: `send_msg`
    reaches `_modbus_tcp_send` through `ctx->backend->send`, and modbus.c does not declare it. `seen`
    is read from the text, not from the parse: a name declared only in an included header is not seen,
    and a use in a disabled `#if` branch is.
    """
    from acsl_ast import mask_comments_and_literals

    code = ""
    for src in sources:
        with contextlib.suppress(OSError):
            text = src.read_text(encoding="utf-8", errors="replace")
            code += mask_comments_and_literals(text, acsl="blank", literals=True, on_error="mask") + "\n"
    out: dict[str, dict] = {}
    for p in props.get("properties") or []:
        acsl = str(p.get("acsl") or "")
        m = _CALLED_TARGET_RE.search(acsl) or _PRECOND_TARGET_RE.search(acsl)
        if m and str(p.get("name")) in names:
            seen = re.search(rf"(?<![\w.>]){re.escape(m.group(1))}\b", code) is not None
            out[str(p["name"])] = {"function": m.group(1), "seen": seen}
    return out


def resolve_security_meta(spec: str | None, c_file: Path, fn_name: str, out_dir: Path) -> dict | None:
    """
    The MetAcsl properties (scripts/security_props.py) with an instance in this function: writes their
    meta file under `out_dir` and returns {props, function_id, properties, meta_file, extra_sources,
    call_targets}, or None when there are none. `spec` is a path, `none`/`off`, or None for
    $FRAMAC_SECURITY_PROPS, else workspace/reports/security_props.json when it exists.

    The in-code checks of the function (`code` properties) are no MetAcsl property: they are listed
    apart (`code_properties`, `code_checks`, `code_checks_unnamed`), never in `properties`, and a
    function that has only those gets no meta file and no `-meta` stage.
    """
    import security_props

    if spec is not None and spec.strip().lower() in ("none", "off", ""):
        return None
    path = Path(spec) if spec else Path(os.environ.get(SECURITY_PROPS_ENV) or DEFAULT_SECURITY_PROPS)
    if not path.is_file():
        if spec:
            return {"props": str(path), "error": "security properties file not found", "properties": []}
        return None
    try:
        props = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {"props": str(path), "error": f"unreadable: {exc}", "properties": []}
    match = security_props.match_function(props, str(c_file), fn_name)
    if match is None:
        return None
    fid, root = match
    code_names, code_unnamed = code_check_names(props, fid, c_file)
    # The checks security_props.py wrote into this function. Those of a `code` property are audited against
    # the source (code_check_names). Those of a property that keeps its MetAcsl text (package E's checks at
    # calls placed in initializers) are named row by row (code_check_rows).
    audited = {str(p.get("name")) for p in props.get("properties") or [] if isinstance(p, dict) and p.get("code")}
    checks = [c for c in props.get("code_checks") or [] if isinstance(c, dict) and c.get("function") == fid]
    code: dict[str, Any] = {}
    if checks:
        code = {"code_checks": checks, "row_named_checks": [c for c in checks if str(c.get("property")) not in audited]}
    if code_names or code_unnamed:
        code |= {
            "code_properties": sorted(set(code_names.values())),
            "code_check_lines": [{"line": int(line), "property": name} for line, name in sorted(code_names.items())],
            "code_checks_unnamed": code_unnamed,
            "code_line_names": code_names,
        }
    found = security_props.meta_file_text(props, fid)
    if found is None:
        return {"props": str(path), "function_id": fid, "properties": [], **code} if code else None
    text, names, sources = found
    out_dir.mkdir(parents=True, exist_ok=True)
    meta_file = out_dir / f"security_meta_{fn_name}.c"
    meta_file.write_text(text, encoding="utf-8", newline="\n")
    extra = []
    for src in sources:
        cand = f"{root}{src}"
        if Path(cand).is_file() and Path(cand).resolve() != c_file.resolve():
            extra.append(cand)
    return {
        "props": str(path),
        "function_id": fid,
        "properties": names,
        "meta_file": str(meta_file),
        "extra_sources": extra,
        "line_names": {str(k): v for k, v in security_props.meta_line_names(text).items()},
        "call_targets": call_targets(props, names, [c_file, *map(Path, extra)]),
        **code,
    }


def code_check_rows(rows: list[dict], checks: list[dict], fn_name: str) -> tuple[dict[int, str], list[dict[str, int]]]:
    """
    Name the rows of the in-code checks security_props.py wrote into `fn_name` (`checks`: those of
    a property that keeps its MetAcsl text; code_check_names audits the others against the source). Frama-C's report gives a code `check` its file, line and predicate, not
    its name, and one line may hold several (one initializer, two properties). Within a line the
    rows come in source order, which is the order of `index` (absent: the only check of its line).
    Returns (row position -> property name, the lines left unnamed: {line, checks, rows}). A line is
    named only when its check rows in this function and file are exactly as many as the checks
    written there; otherwise (a prover's own check on the line, a stale tree) nothing on it is
    named, so no goal is credited to the wrong property.
    """
    by_line: dict[int, list[dict]] = {}
    for c in checks:
        by_line.setdefault(int(c.get("line") or 0), []).append(c)
    named: dict[int, str] = {}
    unnamed: list[dict[str, int]] = []
    for line, placed in sorted(by_line.items()):
        files = {Path(str(c.get("file") or "")).name for c in placed}
        found = [
            i
            for i, r in enumerate(rows)
            if int(r.get("line") or 0) == line
            and "check" in str(r.get("kind") or "").lower()
            and str(r.get("function") or fn_name) == fn_name
            and Path(str(r.get("file") or "").replace("\\", "/")).name in files
        ]
        order = sorted(placed, key=lambda c: int(c["index"]) if isinstance(c.get("index"), int) else 0)
        if len(found) != len(order) or len({str(c.get("index", 0)) for c in order}) != len(order):
            unnamed.append({"line": line, "checks": len(order), "rows": len(found)})
            continue
        for i, c in zip(found, order, strict=True):
            named[i] = str(c.get("property"))
    return named, unnamed


def name_code_check(item: dict, name: str | None) -> None:
    """Put a code check's property name in front of its predicate (`<property>: <predicate>`), as for a meta goal."""
    if name and name not in str(item.get("annotation") or ""):
        item["annotation"] = f"{name}: {item.get('annotation') or ''}"


METACSL_SET_ASSIGNS = "metacsl_set_assigns"
_META_675_RE = re.compile(r'Unexpected error \(File "meta_annotate\.ml", line 675\b[^\n]*')
_ACSL_THEN_DECL_RE = re.compile(r"/\*@((?:(?!\*/).)*)\*/([^;{}()]*?)\b([A-Za-z_]\w*)\s*\(", re.DOTALL)
_QUOTED_INCLUDE_RE = re.compile(r'^\s*#\s*include\s+"([^"]+)"', re.MULTILINE)


def _set_assigns_functions(paths: list[str]) -> list[str]:
    """
    The functions whose contract, in `paths` or a file they include with quotes (one level), has an
    `assigns` that holds a set (`\\union(...)`, `\\inter(...)`, `{a, b}`). Read from the text, as
    security_props.contract_assigns does.
    """
    seen: set[Path] = set()
    files: list[Path] = []
    for p in paths:
        path = Path(p)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        files.append(path)
        files += [path.parent / inc for inc in _QUOTED_INCLUDE_RE.findall(text)]
    found: set[str] = set()
    for path in files:
        if path in seen:
            continue
        seen.add(path)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _ACSL_THEN_DECL_RE.finditer(text):
            for clause in re.findall(r"\bassigns\b([^;]*);", m.group(1)):
                lhs = clause.split("\\from")[0]
                if "\\union" in lhs or "\\inter" in lhs or "{" in lhs:
                    found.add(m.group(3))
    return sorted(found)


def metacsl_set_assigns_failure(log_text: str, sources: list[str]) -> dict | None:
    """
    MetAcsl 0.12's `Unexpected error (File "meta_annotate.ml", line 675, ...: Assertion failed)`:
    `writing_visitor#external_assigns` asserts that each `assigns` term of a called function is one
    lvalue, so a function declared with a set-valued `assigns` (`\\union(*a, *b)`, `{*a, *b}`) and
    called by any function a \\writing property targets stops the whole parse. The log names no
    function; the callees are read from the contracts of the parsed sources. None for another log.
    """
    m = _META_675_RE.search(log_text or "")
    if not m:
        return None
    return {
        "message": m.group(0).strip(),
        "cause": (
            "MetAcsl stops on a called function whose `assigns` holds a set (\\union(...), \\inter(...) or "
            "{a, b}) when a \\writing property targets one of its callers (meta_annotate.ml, line 675)"
        ),
        "callees": _set_assigns_functions(sources),
    }


def name_code_goal(item: dict, security_meta: dict | None, c_file: Path) -> None:
    """
    Put the property name back on the `user check` row of an in-code check security_props.py placed
    (`<property>: <predicate>`), so the goal maps to the property's class. Only the lines
    `code_check_names` accepted are named.
    """
    names = (security_meta or {}).get("code_line_names")
    if not names or "check" not in str(item.get("kind") or "").lower():
        return
    if Path(str(item.get("file") or "")).name != c_file.name:
        return
    name = names.get(str(item.get("line")))
    if name and name not in str(item.get("annotation") or ""):
        item["annotation"] = f"{name}: {item.get('annotation') or ''}"


def name_meta_goal(item: dict, security_meta: dict | None) -> None:
    """
    Frama-C's report gives a MetAcsl-generated assertion without its name, located at its property's
    line in the meta file: put the name back (`<property>: meta: <predicate>`) so the goal maps to the
    property's class.
    """
    if not security_meta or not security_meta.get("meta_file"):
        return
    if Path(str(item.get("file") or "")).name != Path(str(security_meta["meta_file"])).name:
        return
    name = (security_meta.get("line_names") or {}).get(str(item.get("line")))
    if name and name not in str(item.get("annotation") or ""):
        item["annotation"] = f"{name}: meta: {item.get('annotation') or ''}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Frama-C WP + RTE on a single C function.")
    parser.add_argument("--file", type=Path, required=True, help="Target C file containing the function")
    parser.add_argument("--function", required=True, help="Function name (-wp-fct)")
    parser.add_argument("--extra-sources", nargs="*", default=[], help="Optional extra C files if needed")
    parser.add_argument("--out-dir", type=Path, default=Path("workspace/wp"))
    parser.add_argument("--session-dir", type=Path, default=None, help="Optional WP session cache directory")
    parser.add_argument("--machdep", default="gcc_x86_64")
    parser.add_argument("--cppflags", default="-I.")
    parser.add_argument("--provers", default="alt-ergo,z3,cvc5")
    parser.add_argument(
        "--wp-par",
        default="auto",
        help="Concurrent provers: 'auto' (from this job's CPUs and memory at -wp-memlimit 1000) or a positive integer",
    )
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--wp-steps", type=int, default=0, help="Optional deterministic solver step budget")
    parser.add_argument(
        "--wp-model",
        default=None,
        help="WP memory model (default: Typed, retried once under Bytes when only union or byte-wise cast "
        "obstacles remain; an explicit model is never retried)",
    )
    parser.add_argument(
        "--no-retry-bytes",
        action="store_true",
        help="Disable the automatic retry under -wp-model Bytes (report field bytes_retry)",
    )
    parser.add_argument("--no-check-memory-model", action="store_true", help="Disable -wp-check-memory-model")
    parser.add_argument("--no-warn-invalid-pointer", action="store_true", help="Disable -warn-invalid-pointer")
    parser.add_argument(
        "--no-warn-unsigned",
        action="store_true",
        help="Prove with -warn-unsigned-overflow / -warn-unsigned-downcast off, then re-run with overflow checks on: "
        "a goal not fully proved on a line outside --wrap-lines leaves the function unproven",
    )
    parser.add_argument(
        "--wrap-lines",
        type=_line_list,
        default=None,
        help="With --no-warn-unsigned: comma-separated file lines holding deliberate unsigned wraps",
    )
    parser.add_argument(
        "--wrap-code-lines",
        type=_line_list,
        default=None,
        help="As --wrap-lines, as positions among the function's code lines, which ACSL merges do not move "
        "(what parent re-checks pass, from the prover's report)",
    )
    parser.add_argument(
        "--waive-signed-downcast",
        action="store_true",
        help="With --no-warn-unsigned and declared wrap lines: prove with -warn-signed-downcast off too; the "
        "check run (checks on) then fails the function on any signed_downcast goal not fully proved outside "
        "the declared lines (an implementation-defined narrowing of a deliberate wrap)",
    )
    parser.add_argument(
        "--no-warn-unsigned-downcast",
        action="store_true",
        help="Disable -warn-unsigned-downcast only (C11 modulo narrowing; keeps -warn-unsigned-overflow enabled)",
    )
    parser.add_argument(
        "--no-retry-bitwise",
        action="store_true",
        help="Disable automatic retry with -wp-model Typed+ref+int when bitwise/shift goals remain unproven",
    )
    parser.add_argument(
        "--no-retry-tail",
        action="store_true",
        help="Disable automatic focused tail retry when >=90%% of VCs are proven and only a timeout tail remains",
    )
    parser.add_argument("--smoke-tests", action="store_true", help="Run -wp-smoke-tests vacuity check in this pass")
    parser.add_argument(
        "--counter-examples",
        action="store_true",
        help="Add -wp-counter-examples: witness models for failed goals, listed in the report's counter_example_goals (crash-verifier input)",
    )
    parser.add_argument("--prop", default=None, help="Isolate a single named clause (-wp-prop=<name>)")
    parser.add_argument("--dump-goal", action="store_true", help="Dump unsimplified raw VC (-wp-print -wp-no-qed)")
    parser.add_argument(
        "--wall-timeout",
        type=int,
        default=None,
        help="Wall-clock limit for the whole Frama-C run in seconds (0: none; default: FRAMAC_WP_WALL_TIMEOUT, "
        "else the wp job class limit); exceeding it yields analysis_error",
    )
    parser.add_argument(
        "--cache-dir",
        default="auto",
        help="WP prover cache: 'auto' (-wp-cache update -wp-cache-dir <run>/state/cache/wp inside a run directory), "
        "'off', or a directory",
    )
    parser.add_argument("--sarif", action="store_true", help="Also save the project (-save) and export SARIF")
    parser.add_argument("--keep-goals", action="store_true", help="Keep WP's goal files (-wp-out) under --out-dir")
    parser.add_argument(
        "--ignore-prover-budget",
        action="store_true",
        help=(
            "Do not read/enforce agents/<id>/scratch/.prover_budget.json. Parent re-checks on the "
            "merged tree use this so an exhausted agent budget cannot mask an all-proven result."
        ),
    )
    parser.add_argument(
        "--wp-blockers",
        nargs="*",
        default=None,
        help="Optional list of known WP blockers for the target function (e.g. internal_variadic)",
    )
    parser.add_argument(
        "--security-props",
        default=None,
        help=(
            "MetAcsl security properties (scripts/security_props.py) to load for this function: a path, or "
            f"`none`. Default: ${SECURITY_PROPS_ENV}, else {DEFAULT_SECURITY_PROPS} when it exists."
        ),
    )
    parser.add_argument("--out-json", type=Path, required=True)
    raw_argv = normalize_flag_args(list(argv) if argv is not None else sys.argv[1:], ("--cppflags",))
    args = parser.parse_args(raw_argv)
    if str(args.wp_par).strip().lower() != "auto":
        try:
            if int(args.wp_par) < 1:
                raise ValueError
        except ValueError:
            parser.error(f"--wp-par must be 'auto' or a positive integer (got {args.wp_par!r})")
    if (args.wrap_lines or args.wrap_code_lines) and not args.no_warn_unsigned:
        parser.error("--wrap-lines and --wrap-code-lines only apply with --no-warn-unsigned")
    if args.waive_signed_downcast and not (args.no_warn_unsigned and (args.wrap_lines or args.wrap_code_lines)):
        parser.error(
            "--waive-signed-downcast only applies with --no-warn-unsigned and --wrap-lines / --wrap-code-lines"
        )

    # --prop and --dump-goal are partial runs: they say nothing about the candidate as a whole.
    whole_run = not (args.prop or args.dump_goal)
    try:
        with _out_dir_lock(args.out_dir, args.function):
            digest_before = prover_candidates.digest_before_run(args.out_json) if whole_run else None
            security_meta = resolve_security_meta(args.security_props, args.file, args.function, args.out_dir)
            wp_kwargs: dict[str, Any] = {
                "c_file": args.file,
                "fn_name": args.function,
                "out_dir": args.out_dir,
                "machdep": args.machdep,
                "cppflags": args.cppflags,
                "provers": args.provers,
                "wp_par": args.wp_par,
                "timeout": args.timeout,
                "wp_steps": args.wp_steps,
                "wp_model": args.wp_model or "Typed",
                # Only when the caller left the model to us: a chosen model (a parent re-check replaying the
                # prover's) is the configuration under test.
                "retry_bytes": args.wp_model is None and not args.no_retry_bytes,
                "check_memory_model": not args.no_check_memory_model,
                "warn_invalid_pointer": not args.no_warn_invalid_pointer,
                "unsigned_reduced": args.no_warn_unsigned,
                "warn_unsigned_downcast": not args.no_warn_unsigned_downcast,
                "warn_signed_downcast": not args.waive_signed_downcast,
                "retry_bitwise": not args.no_retry_bitwise,
                "retry_tail": not args.no_retry_tail,
                "smoke_tests": args.smoke_tests,
                "prop": args.prop,
                "dump_goal": args.dump_goal,
                "session_dir": args.session_dir,
                "extra_sources": args.extra_sources,
                "wall_timeout": default_wall_timeout(args.wall_timeout),
                "cache_dir": args.cache_dir,
                "sarif": args.sarif,
                "keep_goals": args.keep_goals,
                "wp_blockers": args.wp_blockers,
                "ignore_prover_budget": args.ignore_prover_budget,
                "security_meta": security_meta,
            }
            # --counter-examples: the verdict pass first; its report is written before the model pass starts
            # (below), so a kill during that second full WP run never loses the verdict.
            res = run_wp_on_function(**wp_kwargs, counter_examples=False)
            if args.no_warn_unsigned and whole_run:
                res = check_declared_wraps(
                    res,
                    args.file,
                    args.function,
                    args.out_dir,
                    wrap_lines=args.wrap_lines,
                    wrap_code_lines=args.wrap_code_lines,
                    waive_signed_downcast=args.waive_signed_downcast,
                    machdep=args.machdep,
                    cppflags=args.cppflags,
                    provers=args.provers,
                    wp_par=args.wp_par,
                    timeout=args.timeout,
                    wp_steps=args.wp_steps,
                    wp_model=res.get("wp_model") or wp_kwargs["wp_model"],
                    check_memory_model=not args.no_check_memory_model,
                    warn_invalid_pointer=not args.no_warn_invalid_pointer,
                    session_dir=args.session_dir,
                    extra_sources=args.extra_sources,
                    wall_timeout=default_wall_timeout(args.wall_timeout),
                    cache_dir=args.cache_dir,
                )
            # Before the verdict limits: a `calls` naming a non-target at an open site makes the proof unsound.
            res = apply_open_callback_boundary(res, args.file, args.function, args.out_dir)
            vacuity = None
            # A filtered or goal-dump run is not a whole proof: nothing is credited from it.
            if res.get("status") == "all_proven" and not args.prop and not args.dump_goal:
                vacuity = run_vacuity_check(
                    args.file,
                    args.function,
                    args.out_dir,
                    machdep=args.machdep,
                    cppflags=args.cppflags,
                    provers=args.provers,
                    wp_model=res.get("wp_model") or wp_kwargs["wp_model"],
                    wp_par=args.wp_par,
                    extra_sources=args.extra_sources,
                )
            apply_verdict_limits(res, args.file, vacuity, cppflags=args.cppflags, machdep=args.machdep)
            args.out_json.parent.mkdir(parents=True, exist_ok=True)
            if args.counter_examples:
                res["counter_examples"] = True
                res["counter_example_goals"] = []
                if needs_model_pass(res) and not res.get("budget_exhausted"):
                    res["counter_example_pass"] = {"status": "pending"}
                    args.out_json.write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")
                res = collect_counter_example_models(res, wp_kwargs)
            args.out_json.write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")
            summary = {
                "status": res["status"],
                "function": res["function"],
                "proven_count": res.get("proven_count", 0),
                "proven_under_hyp_count": res.get("proven_under_hyp_count", 0),
                "unproven_count": res.get("unproven_count", 0),
                "soundness_ok": res.get("soundness", {}).get("ok", False),
                "next_synthesis_focus": res.get("next_synthesis_focus", "syntax_error"),
            }
            if res.get("diagnostic_hints"):
                summary["diagnostic_hints"] = res["diagnostic_hints"]
            if res.get("partial_verdicts"):
                summary["partial_verdicts"] = res["partial_verdicts"]
            if res.get("unsigned_wraps"):
                summary["unsigned_wraps"] = res["unsigned_wraps"]
            if whole_run and not res.get("budget_exhausted"):
                prover_candidates.add_candidate_block(summary, args.out_json, "wp", res, digest_before)
            print(json.dumps(summary, indent=2))
            return 0
    except OutDirLockedError as exc:
        err_res = _analysis_error_result(
            args.function,
            args.file,
            OUT_DIR_LOCKED_REASON,
            None,
            scan_wp_log_soundness(""),
            str(exc),
        )
        summary = {
            "status": err_res["status"],
            "reason": OUT_DIR_LOCKED_REASON,
            "function": args.function,
            "out_dir": str(args.out_dir),
            "error": str(exc),
            "lock_owner": exc.owner,
            "proven_count": 0,
            "proven_under_hyp_count": 0,
            "unproven_count": 0,
            "soundness_ok": False,
            "next_synthesis_focus": err_res["next_synthesis_focus"],
            "diagnostic_hints": err_res["diagnostic_hints"],
        }
        print(json.dumps(summary, indent=2))
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
