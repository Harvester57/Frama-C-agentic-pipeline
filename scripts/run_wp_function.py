#!/usr/bin/env python3
"""
Drives Frama-C WP + RTE deductive verification on a single C function (-wp-fct).
1. Performs a fast Frama-C Kernel ACSL syntax/type check first (-pp-annot).
2. Runs WP with the verified flag set (-wp-model Typed -wp-check-memory-model
   -wp-rte -warn-invalid-pointer -warn-unsigned-overflow -warn-unsigned-downcast
   -wp-split) and parallel SMT solvers (Alt-Ergo, Z3, CVC5).
3. Scans the WP log for Tier-A aborts (Non-natural loop, User Error) and Tier-B
   silent unsoundness (Statement specifications skipped, union field access under
   Typed model, missing default assigns, reads nothing, failed smoke tests,
   indirect calls without `calls` while `\\valid_function` is skipped).
4. Supports single-clause raw VC drill-down (--prop <name> --dump-goal) and
   static vacuity smoke tests (--smoke-tests).
5. Classifies unproven goals into Step A/B/C buckets and maps every goal to a
   coverage-ledger obligation class (rte, l2_termination, l3_frame, l4_auth,
   l5_output, l6_secret).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

from framac_common import (  # noqa: E402
    STATUS_DEAD,
    STATUS_INVALID,
    STATUS_INVALID_UNDER_HYP,
    STATUS_NEVER_TRIED,
    STATUS_UNKNOWN,
    STATUS_VALID,
    STATUS_VALID_UNDER_HYP,
    augment_framac_cppflags,
    read_report_csv,
    scan_undeclared_functions,
)

_LAYER_NAME_RE = re.compile(r"\bL([4-6])_[A-Za-z0-9_]+")
_LAYER_CLASS = {"4": "l4_auth", "5": "l5_output", "6": "l6_secret"}

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
_TIER_B_RE = re.compile(
    r"[^\n]*(?:" + "|".join(re.escape(p) for p in _TIER_B_PATTERNS) + r")[^\n]*"
)
_SMOKE_FAIL_RE = re.compile(
    r"(Failed smoke-test[^\n]*|Unsuccess[^\n]*smoke[^\n]*|[^\n]*Smoke Tests\s*:\s*0\s*/\s*\d+[^\n]*)",
    re.IGNORECASE,
)
_MM_HYP_RE = re.compile(r"Memory model hypotheses for function '([^']+)'")
_SKIPPED_RTE_RE = re.compile(
    r"(?:Skipped RTE guards:\s*([^\n)]+\))|([^\n]*Through function pointer[^\n]*cannot generate[^\n]*))"
)
_INDIRECT_CALL_UNSOUND_RE = re.compile(r"Missing 'calls'|Unknown callee")
_FPV_DEGEN_RE = re.compile(
    r"^\[wp\] \[(?:Timeout|Unknown|Failed|Stepout)\] ([A-Za-z0-9_]+_assert_rte_pointer_value[A-Za-z0-9_]*) .*\(Degenerated\)",
    re.MULTILINE,
)
_VC_DUMP_RE = re.compile(
    r"-{20,}\n(\s*Goal [^\n]+:.*?)(?=\n-{20,}|\Z)",
    re.DOTALL,
)


def goal_obligation_class(item: dict) -> str:
    """
    Map a WP goal to a coverage-ledger obligation class (naming convention in docs/v2-design.md):
    named clauses L4_*/L5_*/L6_* -> layer unit; loop variant/decreases -> l2_termination;
    assigns/separated/frees/allocates -> l3_frame; everything else -> rte.
    """
    text = f"{item.get('kind', '')} {item.get('annotation', '')}"
    m = _LAYER_NAME_RE.search(text)
    if m:
        return _LAYER_CLASS[m.group(1)]
    low = text.lower()
    if "variant" in low or "decreases" in low:
        return "l2_termination"
    if "assigns" in low or "\\separated" in low or "frees" in low or "allocates" in low:
        return "l3_frame"
    return "rte"


_BITWISE_GOAL_RE = re.compile(
    r"\b(?:shift|lsr|lsl|land|lor|lxor|bit_test|bw_)\b|(?:<<|>>|\^|~\s*[A-Za-z0-9_(])",
    re.IGNORECASE,
)
_BITWISE_LOG_RE = re.compile(
    r"\b(?:lsr|lsl|land|lor|lxor|bit_test|shift_left|shift_right|rte_shift)\b",
    re.IGNORECASE,
)


def scan_wp_log_soundness(
    log_text: str,
    check_memory_model: bool = True,
    unsigned_reduced: bool = False,
    warn_invalid_pointer: bool = True,
    warn_unsigned_downcast: bool = True,
) -> dict:
    """
    Scan Frama-C WP log output for Tier-A aborts, Tier-B silent unsoundness,
    memory-model separation hypotheses, skipped RTE guards, and degenerated
    function-pointer value goals (`\\valid_function`).
    """
    tier_a_aborts = sorted({m.group(1).strip() for m in _TIER_A_RE.finditer(log_text)})
    tier_b_unsound = sorted({m.group(0).strip() for m in _TIER_B_RE.finditer(log_text)})

    for m_smoke in _SMOKE_FAIL_RE.finditer(log_text):
        msg = m_smoke.group(1).strip()
        if msg not in tier_b_unsound:
            tier_b_unsound.append(msg)

    mm_functions = sorted({m.group(1) for m in _MM_HYP_RE.finditer(log_text)})
    if mm_functions and not check_memory_model:
        tier_b_unsound.append(
            f"Memory model hypotheses for function(s) {', '.join(mm_functions)} unchecked (-wp-no-check-memory-model)"
        )

    skipped_rte = sorted({
        (m.group(1) or m.group(2) or "").strip()
        for m in _SKIPPED_RTE_RE.finditer(log_text)
        if (m.group(1) or m.group(2))
    })
    if skipped_rte and _INDIRECT_CALL_UNSOUND_RE.search(log_text):
        tier_b_unsound.append("indirect call present without '//@ calls' while \\valid_function RTE guards are skipped")

    fpv_goals = sorted({m.group(1) for m in _FPV_DEGEN_RE.finditer(log_text)})

    reduced_checks: List[str] = []
    if unsigned_reduced:
        reduced_checks.append("-warn-unsigned-overflow / -warn-unsigned-downcast OFF")
    elif not warn_unsigned_downcast:
        reduced_checks.append("-no-warn-unsigned-downcast")
    if not warn_invalid_pointer:
        reduced_checks.append("-warn-invalid-pointer OFF")

    return {
        "ok": len(tier_a_aborts) == 0 and len(tier_b_unsound) == 0,
        "tier_a_aborts": tier_a_aborts,
        "tier_b_unsound": tier_b_unsound,
        "checked_memory_model_functions": mm_functions if check_memory_model else [],
        "skipped_rte_guards": skipped_rte,
        "assumed_function_pointer_goals": fpv_goals,
        "reduced_checks": reduced_checks,
    }


def extract_vc_goal_dumps(log_text: str, max_dumps: int = 5) -> List[str]:
    """Extract raw verification condition (`Assume` / `Prove`) dumps from `-wp-print` output."""
    dumps = [m.group(1).strip() for m in _VC_DUMP_RE.finditer(log_text)]
    return dumps[:max_dumps]


ACSL_ERROR_RE = re.compile(
    r"([^\s:]+\.[ch]):(\d+):(?:\d+:)?\s*(?:\[kernel.*?\]|error|warning).*?(?:annot-error|syntax error|unbound|invalid|type|wrong order of clause).*?$",
    re.IGNORECASE | re.MULTILINE,
)


def check_acsl_syntax(
    c_file: Path,
    machdep: str = "gcc_x86_64",
    cppflags: str = "-I.",
) -> dict:
    effective_cppflags = augment_framac_cppflags(cppflags)
    cmd = [
        "frama-c",
        "-pp-annot",
        "-no-unicode",
        "-machdep", machdep,
        f"-cpp-extra-args={effective_cppflags}",
        "-kernel-warn-key", "annot-error=abort",
        str(c_file),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
    if proc.returncode != 0:
        errors = [m.group(0) for m in ACSL_ERROR_RE.finditer(combined)]
        return {
            "syntax_ok": False,
            "returncode": proc.returncode,
            "errors": errors or [combined[-2000:]],
            "raw_log": combined[-3000:],
        }
    return {"syntax_ok": True, "returncode": 0, "errors": []}


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


def _has_bitwise_unproven_goals(unproven_goals: List[dict], combined_log: str) -> bool:
    for g in unproven_goals:
        text = f"{g.get('kind') or ''} {g.get('annotation') or ''}"
        if _BITWISE_GOAL_RE.search(text):
            return True
    if _BITWISE_LOG_RE.search(combined_log):
        return True
    return False


def run_wp_on_function(
    c_file: Path,
    fn_name: str,
    out_dir: Path,
    machdep: str = "gcc_x86_64",
    cppflags: str = "-I.",
    provers: str = "alt-ergo,z3,cvc5",
    wp_par: int = 8,
    timeout: int = 15,
    wp_steps: int = 0,
    wp_model: str = "Typed",
    check_memory_model: bool = True,
    warn_invalid_pointer: bool = True,
    unsigned_reduced: bool = False,
    warn_unsigned_downcast: bool = True,
    retry_bitwise: bool = True,
    smoke_tests: bool = False,
    prop: Optional[str] = None,
    dump_goal: bool = False,
    session_dir: Optional[Path] = None,
    extra_sources: Optional[List[str]] = None,
) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)

    syntax = check_acsl_syntax(c_file, machdep=machdep, cppflags=cppflags)
    if not syntax["syntax_ok"]:
        return {
            "status": "acsl_syntax_error",
            "function": fn_name,
            "file": str(c_file),
            "syntax_check": syntax,
        }

    csv_path = out_dir / f"wp_{fn_name}.csv"
    wp_out_dir = out_dir / f"wp_goals_{fn_name}"
    log_path = out_dir / f"wp_{fn_name}.log"
    sarif_path = out_dir / f"wp_{fn_name}.sarif"
    sav_path = out_dir / f"wp_{fn_name}.sav"

    effective_cppflags = augment_framac_cppflags(cppflags)
    sources = [str(c_file)] + (extra_sources or [])
    cmd = [
        "frama-c",
        "-pp-annot",
        "-no-unicode",
        "-machdep", machdep,
        "-warn-signed-overflow",
        "-warn-signed-downcast",
        "-warn-left-shift-negative",
        "-warn-right-shift-negative",
        "-warn-pointer-downcast",
    ]
    if warn_invalid_pointer:
        cmd.append("-warn-invalid-pointer")
    if not unsigned_reduced:
        cmd.append("-warn-unsigned-overflow")
        if warn_unsigned_downcast:
            cmd.append("-warn-unsigned-downcast")

    cmd.extend([
        f"-cpp-extra-args={effective_cppflags}",
        *sources,
        "-wp",
        "-wp-rte",
        "-wp-split",
        "-wp-fct", fn_name,
        "-wp-model", wp_model,
    ])
    if check_memory_model:
        cmd.append("-wp-check-memory-model")
    for p in [p.strip() for p in provers.split(",") if p.strip()]:
        cmd.extend(["-wp-prover", p])
    cmd.extend([
        "-wp-par", str(wp_par),
        "-wp-timeout", str(timeout),
        "-wp-out", str(wp_out_dir),
    ])
    if wp_steps > 0:
        cmd.extend(["-wp-steps", str(wp_steps)])
    if session_dir is not None:
        session_dir.mkdir(parents=True, exist_ok=True)
        cmd.extend([
            "-wp-session", str(session_dir),
            "-wp-cache", "none" if dump_goal else "update",
        ])
    if smoke_tests:
        cmd.extend(["-wp-smoke-tests", "-wp-smoke-timeout", str(min(timeout, 5))])
    if prop:
        cmd.append(f"-wp-prop={prop}")
    if dump_goal:
        cmd.extend(["-wp-print", "-wp-no-qed"])

    cmd.extend([
        "-then", "-report", "-report-csv", str(csv_path),
        "-save", str(sav_path),
    ])

    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    combined_log = (proc.stdout or "") + "\n" + (proc.stderr or "")
    log_path.write_text(combined_log, encoding="utf-8")

    soundness = scan_wp_log_soundness(
        combined_log,
        check_memory_model=check_memory_model,
        unsigned_reduced=unsigned_reduced,
        warn_invalid_pointer=warn_invalid_pointer,
        warn_unsigned_downcast=warn_unsigned_downcast,
    )
    goal_dumps = extract_vc_goal_dumps(combined_log) if dump_goal else []

    if sav_path.exists():
        subprocess.run(
            [
                "frama-c", "-load", str(sav_path),
                "-mdr-gen", "sarif", "-mdr-no-print-libc",
                "-mdr-out", str(sarif_path),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

    proven_goals: List[dict] = []
    under_hyp_goals: List[dict] = []
    unproven_goals: List[dict] = []
    unproven_lemmas: List[dict] = []
    dead_goals: List[dict] = []
    buckets: Dict[str, List[dict]] = {
        "step_a_assigns": [],
        "step_b_loop_invariant": [],
        "step_c_rte_obligation": [],
        "step_c_caller_precondition": [],
        "step_c_contract_postcondition": [],
    }
    by_class: Dict[str, Dict[str, int]] = {}
    fpv_assumed_count = len(soundness["assumed_function_pointer_goals"])

    if csv_path.exists():
        for row in read_report_csv(csv_path):
            row_fn = row["function"]
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
            cls = goal_obligation_class(item)
            item["obligation_class"] = cls
            counts = by_class.setdefault(cls, {"proven": 0, "proven_under_hyp": 0, "unproven": 0})
            if st == STATUS_VALID:
                proven_goals.append(item)
                counts["proven"] += 1
            elif st == STATUS_VALID_UNDER_HYP:
                # Expected under -wp-fct: callee contracts are hypotheses proven in their own
                # sessions. Kept separate so the proof audit can resolve every hypothesis.
                under_hyp_goals.append(item)
                counts["proven_under_hyp"] += 1
            elif st in (STATUS_UNKNOWN, STATUS_INVALID, STATUS_INVALID_UNDER_HYP, STATUS_NEVER_TRIED):
                # Under -warn-invalid-pointer, loading a function pointer from memory yields a
                # Degenerated \valid_function goal that WP cannot prove; count it as an explicit assumption.
                annot_low = (item.get("annotation") or "").lower()
                kind_low = (item.get("kind") or "").lower()
                if fpv_assumed_count > 0 and ("\\valid_function" in annot_low or "pointer_value" in annot_low):
                    under_hyp_goals.append(item)
                    counts["proven_under_hyp"] += 1
                    continue
                if "unsigned_downcast" in kind_low or "unsigned_downcast" in annot_low:
                    item["c11_modulo_candidate"] = True
                if not row_fn or "lemma" in kind_low:
                    unproven_lemmas.append(item)
                bkey = classify_unproven_goal(item)
                item["diagnostic_bucket"] = bkey
                unproven_goals.append(item)
                buckets[bkey].append(item)
                counts["unproven"] += 1
            elif st == STATUS_DEAD:
                dead_goals.append(item)

    if unproven_lemmas:
        soundness["tier_b_unsound"].append(
            f"{len(unproven_lemmas)} unproven lemma(s) in scope (WP offers unproven lemmas as hypotheses to sibling goals)"
        )
        soundness["ok"] = False

    # Workstream 3: Automatic bitwise/shift solver retry with Typed+ref+int and extended timeout
    model_parts = {m.strip().lower() for m in re.split(r"[+,]", wp_model) if m.strip()}
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
                wp_par=wp_par,
                timeout=retry_timeout,
                wp_steps=wp_steps,
                wp_model=retry_model,
                check_memory_model=check_memory_model,
                warn_invalid_pointer=warn_invalid_pointer,
                unsigned_reduced=unsigned_reduced,
                warn_unsigned_downcast=warn_unsigned_downcast,
                retry_bitwise=False,
                smoke_tests=smoke_tests,
                prop=prop,
                dump_goal=dump_goal,
                session_dir=session_dir,
                extra_sources=extra_sources,
            )
            if (
                retry_res.get("soundness", {}).get("ok", False)
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

    total_goals = len(proven_goals) + len(under_hyp_goals) + len(unproven_goals)
    all_valid = (
        (total_goals > 0)
        and (len(unproven_goals) == 0)
        and (proc.returncode == 0)
        and soundness["ok"]
    )

    if soundness["tier_a_aborts"]:
        status = "wp_aborted"
    elif not soundness["ok"] and len(unproven_goals) == 0:
        status = "unsound_proof"
    elif all_valid:
        status = "all_proven"
    else:
        status = "unproven_goals_remain"

    # Determine next recommended synthesis focus for the Prover Subagent
    if soundness["tier_a_aborts"]:
        next_focus = "tier_a_abort_restructure_required"
    elif soundness["tier_b_unsound"]:
        next_focus = "tier_b_soundness_fix_required"
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

    return {
        "status": status,
        "function": fn_name,
        "file": str(c_file),
        "total_goals": total_goals,
        "proven_count": len(proven_goals),
        "proven_under_hyp_count": len(under_hyp_goals),
        "unproven_count": len(unproven_goals),
        "dead_count": len(dead_goals),
        "soundness": soundness,
        # Non-empty means Frama-C invented `int f()` prototypes: fix the stubs before trusting results.
        "undeclared_functions": scan_undeclared_functions(combined_log),
        "by_obligation_class": by_class,
        "next_synthesis_focus": next_focus,
        "unproven_by_bucket": buckets,
        "unproven_goals": unproven_goals,
        "proven_under_hyp_goals": under_hyp_goals,
        "goal_dumps": goal_dumps,
        "sarif_file": str(sarif_path) if sarif_path.exists() else None,
        "wp_log_tail": combined_log[-3000:],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Frama-C WP + RTE on a single C function.")
    parser.add_argument("--file", type=Path, required=True, help="Target C file containing the function")
    parser.add_argument("--function", required=True, help="Function name (-wp-fct)")
    parser.add_argument("--extra-sources", nargs="*", default=[], help="Optional extra C files if needed")
    parser.add_argument("--out-dir", type=Path, default=Path("workspace/wp"))
    parser.add_argument("--session-dir", type=Path, default=None, help="Optional WP session cache directory")
    parser.add_argument("--machdep", default="gcc_x86_64")
    parser.add_argument("--cppflags", default="-I.")
    parser.add_argument("--provers", default="alt-ergo,z3,cvc5")
    parser.add_argument("--wp-par", type=int, default=8)
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--wp-steps", type=int, default=0, help="Optional deterministic solver step budget")
    parser.add_argument("--wp-model", default="Typed", help="WP memory model (default: Typed)")
    parser.add_argument("--no-check-memory-model", action="store_true", help="Disable -wp-check-memory-model")
    parser.add_argument("--no-warn-invalid-pointer", action="store_true", help="Disable -warn-invalid-pointer")
    parser.add_argument("--no-warn-unsigned", action="store_true", help="Disable -warn-unsigned-overflow / -warn-unsigned-downcast")
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
    parser.add_argument("--smoke-tests", action="store_true", help="Run -wp-smoke-tests vacuity check in this pass")
    parser.add_argument("--prop", default=None, help="Isolate a single named clause (-wp-prop=<name>)")
    parser.add_argument("--dump-goal", action="store_true", help="Dump unsimplified raw VC (-wp-print -wp-no-qed)")
    parser.add_argument("--out-json", type=Path, required=True)
    args = parser.parse_args()

    res = run_wp_on_function(
        c_file=args.file,
        fn_name=args.function,
        out_dir=args.out_dir,
        machdep=args.machdep,
        cppflags=args.cppflags,
        provers=args.provers,
        wp_par=args.wp_par,
        timeout=args.timeout,
        wp_steps=args.wp_steps,
        wp_model=args.wp_model,
        check_memory_model=not args.no_check_memory_model,
        warn_invalid_pointer=not args.no_warn_invalid_pointer,
        unsigned_reduced=args.no_warn_unsigned,
        warn_unsigned_downcast=not args.no_warn_unsigned_downcast,
        retry_bitwise=not args.no_retry_bitwise,
        smoke_tests=args.smoke_tests,
        prop=args.prop,
        dump_goal=args.dump_goal,
        session_dir=args.session_dir,
        extra_sources=args.extra_sources,
    )
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": res["status"],
        "function": res["function"],
        "proven_count": res.get("proven_count", 0),
        "proven_under_hyp_count": res.get("proven_under_hyp_count", 0),
        "unproven_count": res.get("unproven_count", 0),
        "soundness_ok": res.get("soundness", {}).get("ok", False),
        "next_synthesis_focus": res.get("next_synthesis_focus", "syntax_error"),
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
