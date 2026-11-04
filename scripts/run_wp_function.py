#!/usr/bin/env python3
"""
Drives Frama-C WP + RTE deductive verification on a single C function (-wp-fct).
1. Runs WP with the verified flag set (-wp-model Typed -wp-check-memory-model
   -wp-rte -warn-invalid-pointer -warn-unsigned-overflow -warn-unsigned-downcast
   -wp-split) and parallel SMT solvers (Alt-Ergo, Z3, CVC5). The ACSL syntax/type
   check is folded into this run (-kernel-warn-key annot-error=abort): a kernel
   parse or annotation error still yields status `acsl_syntax_error`.
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
   coverage-ledger obligation class (rte, l2_termination, l3_frame, l4_auth,
   l5_output, l6_secret).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cache  # noqa: E402
from framac_common import (  # noqa: E402
    STATUS_DEAD,
    STATUS_INVALID,
    STATUS_INVALID_UNDER_HYP,
    STATUS_NEVER_TRIED,
    STATUS_UNKNOWN,
    STATUS_VALID,
    STATUS_VALID_UNDER_HYP,
    augment_framac_cppflags,
    failure_reason,
    normalize_flag_args,
    read_report_csv,
    scan_undeclared_functions,
)
from resources import CLASSES, FRAMAC_KERNEL_RESERVE_MB, WP_MEMLIMIT_MB, enforced_memory_mb, wp_parallelism  # noqa: E402

# Below this, one prover cannot have its fixed -wp-memlimit next to the Frama-C kernel: goals would
# fail from starvation and read as "unproven", a result that depends on the machine.
WP_MIN_MEMORY_MB = FRAMAC_KERNEL_RESERVE_MB + WP_MEMLIMIT_MB

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
_TIER_B_RE = re.compile(r"[^\n]*(?:" + "|".join(re.escape(p) for p in _TIER_B_PATTERNS) + r")[^\n]*")
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
_WP_ALLOC_UNSUPPORTED_RE = re.compile(
    r"\\(?:freeable|fresh|allocable|allocation)\b|\b(?:freeable|allocates|frees)\b",
    re.IGNORECASE,
)


def _is_alloc_limitation_goal(item: dict) -> bool:
    text = f"{item.get('kind') or ''} {item.get('annotation') or ''}"
    return bool(_WP_ALLOC_UNSUPPORTED_RE.search(text))


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

    skipped_rte = sorted(
        {
            (m.group(1) or m.group(2) or "").strip()
            for m in _SKIPPED_RTE_RE.finditer(log_text)
            if (m.group(1) or m.group(2))
        }
    )
    if skipped_rte and _INDIRECT_CALL_UNSOUND_RE.search(log_text):
        tier_b_unsound.append("indirect call present without '//@ calls' while \\valid_function RTE guards are skipped")

    fpv_goals = sorted({m.group(1) for m in _FPV_DEGEN_RE.finditer(log_text)})

    reduced_checks: list[str] = []
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


def extract_vc_goal_dumps(log_text: str, max_dumps: int = 5) -> list[str]:
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
        "-machdep",
        machdep,
        f"-cpp-extra-args={effective_cppflags}",
        "-kernel-warn-key",
        "annot-error=abort",
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


_FC_MESSAGE_RE = re.compile(r"^\[(?P<plugin>[A-Za-z][\w-]*)(?::[^\]]*)?\]")
_CPP_ERROR_RE = re.compile(r"^\S+\.[ch]:\d+(?::\d+)?:\s*(?:fatal )?error:", re.IGNORECASE)
_KERNEL_ERROR_HINT_RE = re.compile(r"user error|syntax error|annot-error|failure|fatal error|error:", re.IGNORECASE)
_PLUGIN_USER_ERROR_RE = re.compile(
    r"^\[(?!kernel\b)[A-Za-z][\w-]*(?::[^\]]*)?\][^\n]*user error", re.IGNORECASE | re.MULTILINE
)


def kernel_parse_errors(log_text: str) -> list[str]:
    """
    Kernel-phase errors of a Frama-C log (preprocessing, C syntax, ACSL parsing and typing),
    one string per message with its indented continuation lines folded in, e.g.
    `[kernel:annot-error] f.c:1: Failure: unbound logic variable alse. ...`.
    """
    blocks: list[tuple[str, list[str]]] = []
    for line in (log_text or "").splitlines():
        m = _FC_MESSAGE_RE.match(line)
        if m:
            blocks.append((m.group("plugin"), [line.strip()]))
        elif _CPP_ERROR_RE.match(line):
            blocks.append(("cpp", [line.strip()]))
        elif blocks and line[:1].isspace() and line.strip():
            blocks[-1][1].append(line.strip())
    errors: list[str] = []
    for plugin, lines in blocks:
        text = " ".join(lines)
        if plugin in ("kernel", "cpp") and _KERNEL_ERROR_HINT_RE.search(text) and "Frama-C aborted" not in text:
            errors.append(text)
    return errors


def _folded_syntax_errors(
    log_text: str, returncode: int | None, timed_out: bool, report_exists: bool
) -> list[str] | None:
    """Errors when the run stopped in the kernel (parsing/typing) before WP started, else None."""
    if timed_out or returncode in (0, None) or report_exists:
        return None
    if _PLUGIN_USER_ERROR_RE.search(log_text or ""):
        return None  # WP (or another plug-in) refused the function: a Tier-A abort, not a syntax error
    return kernel_parse_errors(log_text) or None


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
_MISSING_ASSIGNS_LINE_RE = re.compile(r"([^\s:]+\.[ch]):(\d+):(?:\d+:)?\s*Warning:\s*Missing assigns clause")
_WP_PROVED_GOALS_RE = re.compile(r"^\[wp\]\s*Proved goals:\s*(\d+)\s*/\s*(\d+)", re.MULTILINE)
_WP_TIMEOUT_COUNT_RE = re.compile(r"^(?:\[wp\])?\s*Timeout:\s*(\d+)", re.MULTILINE)
_ASSIGN_VC_FAIL_RE = re.compile(
    r"^\[wp\]\s*\[(?:Timeout|Unknown|Failed|Stepout)\][^\n]*\bassigns\b",
    re.IGNORECASE | re.MULTILINE,
)


def _find_macro_loop_lines(c_file: Path, fn_name: str) -> dict[int, str]:
    """Return `{line: macro_name}` for loop-bearing `#define` macro invocations inside `fn_name`."""
    if not c_file.is_file():
        return {}
    try:
        from build_callgraph_dag import extract_functions_from_code, extract_macro_definitions

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


def derive_wp_diagnostic_hints(res: dict, log_text: str = "") -> list[str]:
    """
    Generate concise, actionable diagnostic hints for ACSL syntax errors, WP soundness
    aborts, and unproven goal buckets. Returns [] when status == 'all_proven'.
    """
    status = res.get("status")
    if status == "all_proven":
        return []

    hints: list[str] = []

    def _add(msg: str) -> None:
        if msg not in hints:
            hints.append(msg)

    if status == "acsl_syntax_error":
        sc = res.get("syntax_check") or {}
        err_blob = "\n".join(sc.get("errors") or []) + "\n" + (sc.get("raw_log") or "") + "\n" + (log_text or "")
        if _EATEN_BACKSLASH_RE.search(err_blob):
            _add(
                "Backslash in an ACSL keyword was eaten by string escaping (e.g. \\false -> form-feed + 'alse', "
                "\\forall -> form-feed + 'orall', \\valid -> '\\v' + 'alid', \\t -> tab). Use a Python raw string "
                "r'''...''' or double backslashes when writing ACSL annotations."
            )
        if _CLAUSE_ORDER_ERR_RE.search(err_blob):
            _add(
                "Check Frama-C clause ordering: function contracts MUST follow "
                "'requires -> terminates/decreases -> exits -> assigns -> ensures -> behavior'; "
                "loop annotations MUST sit immediately above 'for'/'while'/'do' in order: "
                "'loop invariant -> loop assigns -> loop variant' ('loop variant' must be last)."
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
                "integers, and use '==>' or '<==>' instead of '? :' when combining predicates."
            )
        if not hints:
            _add(
                "ACSL syntax/typing error: check that every clause ends with ';', backslashes are intact "
                "(\\result, \\old, \\valid, \\valid_read, \\separated, \\forall, \\nothing), and function/loop "
                "clause order is respected."
            )
        return hints

    if status == "analysis_error":
        reason = res.get("reason") or "unknown"
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
    if not soundness.get("ok", True) or status in ("wp_aborted", "unsound_proof"):
        if "Missing assigns clause" in aborts_and_unsound or "using unguarded behavior assigns" in aborts_and_unsound:
            _add(
                "WP reported a missing 'assigns' or 'loop assigns' clause: every loop and every called function "
                "must have an explicit 'loop assigns ...;' / 'assigns ...;' clause (use 'assigns \\nothing;' for "
                "pure functions)."
            )
        if "Memory model hypotheses" in aborts_and_unsound or soundness.get("checked_memory_model_functions"):
            _add(
                "WP emitted Typed memory-model separation hypotheses: add explicit "
                "'requires \\separated(p1 + (0 .. n1 - 1), p2 + (0 .. n2 - 1));' preconditions for distinct "
                "pointer parameters."
            )
        if (
            soundness.get("skipped_rte_guards")
            or "Missing 'calls'" in aborts_and_unsound
            or "Through function pointer" in aborts_and_unsound
        ):
            _add(
                "Indirect call through a function pointer without a 'calls' annotation: place "
                "'//@ calls f1, f2;' immediately above the indirect call statement."
            )
        if "unproven lemma" in aborts_and_unsound.lower():
            _add(
                "Unproven global ACSL lemma in scope: replace global 'lemma' declarations with a recursive "
                "'/*@ ghost ... */' C function with 'decreases n; assigns \\nothing;' so WP proves induction."
            )
        if _SMOKE_FAIL_RE.search(aborts_and_unsound):
            _add(
                "Vacuous proof detected (--wp-smoke-tests proved \\false): your 'requires' clauses or loop "
                "invariants are mutually contradictory. Inspect and relax conflicting preconditions."
            )
        if "Ignoring " in aborts_and_unsound or "not yet supported (skipped)" in aborts_and_unsound:
            if _WP_ALLOC_UNSUPPORTED_RE.search(aborts_and_unsound):
                _add(
                    "Frama-C WP does not support dynamic allocation clauses ('\\freeable', '\\fresh', "
                    "'\\allocable', 'allocates', 'frees') from <stdlib.h> ('not yet supported (skipped)'). "
                    "Do NOT write synthetic probe_*.c programs to investigate this limitation; once all "
                    "non-allocation goals are proven and the E-ACSL guardrail passes, stop and write "
                    "result.json with status 'stalled_after_k_retries'."
                )
            else:
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
        alloc_goals = [g for g in unproven_goals if _is_alloc_limitation_goal(g)]
        if alloc_goals or _WP_ALLOC_UNSUPPORTED_RE.search(full_log):
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
                "Pointer-difference equality bridge (`p_end - p == 0 ==> p == p_end` or `\\base_addr(p) == \\base_addr(p_end)`): "
                "Frama-C WP's Typed model does not export `b1 == b2 ==> (ofs1 - ofs2 == 0 ==> p1 == p2)` for two "
                "symbolic pointers even with `\\base_addr`. Anchor BOTH pointers to the same base `\\at(p, Pre)` via "
                "explicit offset invariants (`loop invariant 0 <= p - \\at(p, Pre) <= p_end - \\at(p, Pre);` and "
                "`loop invariant p == \\at(p, Pre) + (p - \\at(p, Pre));` plus `/*@ assert p_end == \\at(p, Pre) + (p_end - \\at(p, Pre)); */`) "
                "so Qed reduces `p == p_end` to integer offset equality."
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
            if any(k in goal_text for k in ("mem_access", "index_bound", "pointer_value")):
                _add(
                    "Unproven pointer/array access ('mem_access' / 'index_bound'): add 'requires \\valid(p);' or "
                    "'requires n > 0 ==> \\valid_read(buf + (0 .. n - 1));' (guarding 'n > 0' so (NULL, 0) passes "
                    "E-ACSL) and bound loop indices with 'loop invariant 0 <= i <= n;'."
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
) -> dict:
    res = {
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
        fn_data = dag.get("functions", {}).get(fn_name)
        if not fn_data:
            c_str = str(c_file).replace("\\", "/")
            for v in dag.get("functions", {}).values():
                if v.get("name") == fn_name:
                    v_file = v.get("file", "").replace("\\", "/")
                    if v_file == c_str or c_str.endswith("/" + v_file) or c_str == v_file:
                        fn_data = v
                        break
        if fn_data and "internal_variadic" in fn_data.get("wp_blockers", []):
            return (
                True,
                f"Target function '{fn_name}' in '{c_file}' is marked with wp_blocker 'internal_variadic' in callgraph DAG",
            )

    if c_file.is_file():
        try:
            from build_callgraph_dag import analyze_body, analyze_signature, extract_functions_from_code

            raw_code = c_file.read_text(encoding="utf-8", errors="replace")
            for item in extract_functions_from_code(raw_code, path=str(c_file)):
                if item["name"] == fn_name:
                    sig = analyze_signature(item["decl_tokens"], item["param_tokens"])
                    body = analyze_body(fn_name, item["body_tokens"], sig)
                    if "internal_variadic" in body.get("wp_blockers", []):
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
) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    par = resolve_wp_par(wp_par)
    wp_cache = resolve_wp_cache_dir(cache_dir)
    use_wp_cache = wp_cache is not None and not dump_goal
    sizing = {
        "wp_par": par,
        "wp_memlimit_mb": WP_MEMLIMIT_MB,
        "wall_timeout_s": wall_timeout,
        "wp_cache_dir": str(wp_cache) if use_wp_cache else None,
    }
    scratch_dir = _locate_agent_scratch_dir(c_file, out_dir)
    if not artifact_suffix.endswith(("_retry", "_tail")):
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
                    first_wp_at = budget_data.get("first_wp_at")
                    if not isinstance(first_wp_at, (int, float)) or first_wp_at <= 0:
                        first_wp_at = now_ts
                        budget_data["first_wp_at"] = first_wp_at
                    invocations = int(budget_data.get("wp_invocations") or 0) + 1
                    budget_data["wp_invocations"] = invocations
                    try:
                        budget_path.write_text(json.dumps(budget_data, indent=2) + "\n", encoding="utf-8")
                    except Exception:
                        pass
                    max_inv = int(budget_data.get("max_wp_invocations") or 0)
                    max_wall_s = int(budget_data.get("max_wall_clock_s") or 0)
                    elapsed_s = max(0.0, now_ts - float(first_wp_at))
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
                            f"elapsed={int(elapsed_s)}s/{max_wall_s or 'unlimited'}s). "
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
    # A report left over from an earlier run must never be read as this run's result.
    for stale in (csv_path, sarif_path, sav_path):
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

    cmd.extend(
        [
            f"-cpp-extra-args={effective_cppflags}",
            *sources,
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
        ]
    )
    if wp_steps > 0:
        cmd.extend(["-wp-steps", str(wp_steps)])
    if session_dir is not None:
        session_dir.mkdir(parents=True, exist_ok=True)
        cmd.extend(
            [
                "-wp-session",
                str(session_dir),
                "-wp-cache",
                "none" if dump_goal else "update",
            ]
        )
        if use_wp_cache:
            cmd.extend(["-wp-cache-dir", str(wp_cache)])
    elif use_wp_cache:
        # Frama-C's own goal digests: unchanged goals are not re-proved across iterations.
        cmd.extend(["-wp-cache", "update", "-wp-cache-dir", str(wp_cache)])
    if smoke_tests:
        cmd.extend(["-wp-smoke-tests", "-wp-smoke-timeout", str(min(timeout, 5))])
    if prop:
        cmd.append(f"-wp-prop={prop}")
    if dump_goal:
        cmd.extend(["-wp-print", "-wp-no-qed"])

    cmd.extend(["-then", "-report", "-report-csv", str(csv_path)])
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
        # Killed (OOM, wall-clock limit) or crashed before the report step: nothing was decided,
        # which must never read as "unproven goals remain" with nothing left to synthesize.
        error_res = _analysis_error_result(
            fn_name,
            c_file,
            failure_reason(returncode, timed_out),
            returncode,
            soundness,
            combined_log,
        )
        if unframed_var_callees:
            error_res["unframed_variadic_callees"] = unframed_var_callees
            error_res["diagnostic_hints"] = derive_wp_diagnostic_hints(error_res, combined_log)
        error_res["sizing"] = sizing
        return error_res
    goal_dumps = extract_vc_goal_dumps(combined_log) if dump_goal else []

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
    buckets: dict[str, list[dict]] = {
        "step_a_assigns": [],
        "step_b_loop_invariant": [],
        "step_c_rte_obligation": [],
        "step_c_caller_precondition": [],
        "step_c_contract_postcondition": [],
    }
    by_class: dict[str, dict[str, int]] = {}
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
                wp_par=par,
                timeout=retry_timeout,
                wp_steps=wp_steps,
                wp_model=retry_model,
                check_memory_model=check_memory_model,
                warn_invalid_pointer=warn_invalid_pointer,
                unsigned_reduced=unsigned_reduced,
                warn_unsigned_downcast=warn_unsigned_downcast,
                retry_bitwise=False,
                retry_tail=False,
                smoke_tests=smoke_tests,
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

    proved_m = _WP_PROVED_GOALS_RE.search(combined_log)
    timeout_m = _WP_TIMEOUT_COUNT_RE.search(combined_log)
    vc_proved = int(proved_m.group(1)) if proved_m else 0
    vc_total = int(proved_m.group(2)) if proved_m else 0
    vc_timeouts = int(timeout_m.group(1)) if timeout_m else 0

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
                        retry_bitwise=False,
                        retry_tail=False,
                        smoke_tests=smoke_tests,
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
    all_valid = (
        (total_goals > 0)
        and (len(unproven_goals) == 0)
        and (vc_total == 0 or vc_proved == vc_total)
        and (vc_timeouts == 0)
        and (returncode == 0)
        and soundness["ok"]
    )
    assigns_vcs_proven = (len(buckets["step_a_assigns"]) == 0) and not bool(_ASSIGN_VC_FAIL_RE.search(combined_log))

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

    res = {
        "status": status,
        "function": fn_name,
        "file": str(c_file),
        "wp_model": wp_model,
        "total_goals": total_goals,
        "proven_count": len(proven_goals),
        "proven_under_hyp_count": len(under_hyp_goals),
        "unproven_count": len(unproven_goals),
        "dead_count": len(dead_goals),
        "assigns_vcs_proven": assigns_vcs_proven,
        "soundness": soundness,
        # Non-empty means Frama-C invented `int f()` prototypes: fix the stubs before trusting results.
        "undeclared_functions": scan_undeclared_functions(combined_log),
        "by_obligation_class": by_class,
        "next_synthesis_focus": next_focus,
        "unproven_by_bucket": buckets,
        "unproven_goals": unproven_goals,
        "proven_under_hyp_goals": under_hyp_goals,
        "goal_dumps": goal_dumps,
        "sarif_file": str(sarif_path) if sarif and sarif_path.exists() else None,
        "wp_log_tail": combined_log[-3000:],
        "sizing": sizing,
    }
    if vc_total > 0:
        res["wp_vc_stats"] = {"proved": vc_proved, "total": vc_total, "timeouts": vc_timeouts}
    if unframed_var_callees:
        res["unframed_variadic_callees"] = unframed_var_callees
    if all_unproven_are_alloc:
        res["wp_allocation_limitation"] = True
    if _WHY3_MEMADDR_ERR_RE.search(combined_log):
        res["wp_why3_memaddr_limitation"] = True
    if soundness.get("macro_loop_warnings"):
        res["wp_macro_loop_limitation"] = True
    res["diagnostic_hints"] = derive_wp_diagnostic_hints(res, combined_log)
    return res


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
    parser.add_argument("--wp-model", default="Typed", help="WP memory model (default: Typed)")
    parser.add_argument("--no-check-memory-model", action="store_true", help="Disable -wp-check-memory-model")
    parser.add_argument("--no-warn-invalid-pointer", action="store_true", help="Disable -warn-invalid-pointer")
    parser.add_argument(
        "--no-warn-unsigned", action="store_true", help="Disable -warn-unsigned-overflow / -warn-unsigned-downcast"
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
    parser.add_argument("--out-json", type=Path, required=True)
    raw_argv = normalize_flag_args(list(argv) if argv is not None else sys.argv[1:], ("--cppflags",))
    args = parser.parse_args(raw_argv)
    if str(args.wp_par).strip().lower() != "auto":
        try:
            if int(args.wp_par) < 1:
                raise ValueError
        except ValueError:
            parser.error(f"--wp-par must be 'auto' or a positive integer (got {args.wp_par!r})")

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
        retry_tail=not args.no_retry_tail,
        smoke_tests=args.smoke_tests,
        prop=args.prop,
        dump_goal=args.dump_goal,
        session_dir=args.session_dir,
        extra_sources=args.extra_sources,
        wall_timeout=default_wall_timeout(args.wall_timeout),
        cache_dir=args.cache_dir,
        sarif=args.sarif,
        keep_goals=args.keep_goals,
        wp_blockers=args.wp_blockers,
        ignore_prover_budget=args.ignore_prover_budget,
    )
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
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
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
