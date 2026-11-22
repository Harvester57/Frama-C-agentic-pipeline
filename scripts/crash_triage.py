"""Pure, deterministic crash clustering, probe selection, and verifier circuit-breaker logic.

Used by Phase-3 scheduling (``wp_scheduler.py``) when ``FRAMAC_VERIFIER_BREAKER`` is enabled
to avoid dispatching dozens of redundant crash-verifier agents against a broken harness
(e.g. a 38-fingerprint NULL-deref burst caused by a single uninitialized harness input).

All functions in this module are pure and side-effect free (no filesystem I/O, no mutation
of caller inputs).
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from typing import Any

VERIFIER_BREAKER_ENV = "FRAMAC_VERIFIER_BREAKER"
DEFAULT_FANOUT_THRESHOLD = 3
DEFAULT_MAX_PROBES = 2
DEFAULT_MIN_HARNESS_INDUCED = 2
DEFAULT_MIN_RATIO = 2 / 3
TINY_INPUT_THRESHOLD_BYTES = 4

_TRUTHY_FLAG_VALUES = frozenset({"on", "1", "true"})
_RATIO_EPS = 1e-9

# Known RTE / E-ACSL alarm kinds (aligned with scripts/fingerprint.py).
_KNOWN_ALARM_KINDS = frozenset(
    {
        "mem_access",
        "index_bound",
        "pointer_value",
        "ptr_value",
        "signed_overflow",
        "unsigned_overflow",
        "signed_downcast",
        "unsigned_downcast",
        "division_by_zero",
        "shift",
        "initialization",
        "dangling_pointer",
        "float_to_int",
        "is_nan_or_infinite",
        "is_nan",
        "function_pointer",
        "bool_value",
        "separation",
        "overlap",
        "differing_blocks",
        "pointer_comparison",
        "pointer_downcast",
        "freeable",
        "valid_string",
    }
)

_ACSL_CONTRACT_KINDS = frozenset(
    {
        "assertion",
        "precondition",
        "postcondition",
        "loop_invariant",
        "loop_variant",
        "assigns",
    }
)

_PENDING_STATES = frozenset({"pending", "queued"})
_ACTIVE_STATES = frozenset({"running", "active", "in_progress", "dispatched", "merge_queued", "merging"})
_IGNORED_STATES = frozenset({"blocked", "skipped", "cancelled", "canceled", "error"})
_NON_VERDICT_OUTCOMES = frozenset(
    {
        "",
        "none",
        "null",
        "pending",
        "queued",
        "running",
        "active",
        "in_progress",
        "dispatched",
        "unverified",
        "ingest_failed",
        "blocked",
        "skipped",
        "cancelled",
        "canceled",
        "error",
        "unknown",
    }
)

_HARNESS_MARKER_RE = re.compile(
    r"\bharness_[A-Za-z0-9_]*|\bLLVMFuzzerTestOneInput\b|__framac_target_embedded_|\bharness\b",
    re.IGNORECASE,
)
_RTE_LABEL_RE = re.compile(r"\brte(?:/|\s*:\s*)([a-z][a-z0-9_]+)\b", re.IGNORECASE)
_FP_KIND_RE = re.compile(r"::([A-Za-z0-9_]+)::[0-9a-f]{10}$")
_SIGNAL_RE = re.compile(r"\b(SIG(?:SEGV|ABRT|FPE|BUS|ILL|TRAP|SYS))\b", re.IGNORECASE)


def verifier_breaker_enabled() -> bool:
    """Return True iff ``FRAMAC_VERIFIER_BREAKER`` is ``on``, ``1``, or ``true`` (default ``off``)."""
    raw = (os.environ.get(VERIFIER_BREAKER_ENV) or "").strip().lower()
    return raw in _TRUTHY_FLAG_VALUES


def _slug(value: str, default: str = "unknown") -> str:
    cleaned = re.sub(r"[^a-z0-9_]+", "_", (value or "").strip().lower()).strip("_")
    return cleaned or default


def _fingerprint(entry: dict[str, Any]) -> str:
    for key in ("fingerprint", "candidate_fingerprint"):
        val = entry.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    tid = entry.get("id")
    if isinstance(tid, str) and tid.startswith("verify:"):
        return tid[len("verify:") :].strip()
    return ""


def _fingerprint_kind(fp: str) -> str:
    m = _FP_KIND_RE.search(fp or "")
    return m.group(1).lower() if m else ""


def _is_unverified(candidate: dict[str, Any]) -> bool:
    status = candidate.get("status")
    if status is None or status == "":
        return True
    return str(status).strip().lower() == "unverified"


def _parse_int_size(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, (bytes, bytearray)):
        return len(value)
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.isdigit():
            return int(stripped)
    return None


def _input_bytes(candidate: dict[str, Any]) -> int | None:
    """Extract the smallest known reproducer input size in bytes from a candidate dict, or None."""
    sizes: list[int] = []
    for key in ("input_bytes", "size_bytes", "input_size"):
        parsed = _parse_int_size(candidate.get(key))
        if parsed is not None:
            sizes.append(parsed)

    artifact = candidate.get("artifact")
    if isinstance(artifact, dict):
        for key in ("input_bytes", "size_bytes", "size", "len", "bytes"):
            parsed = _parse_int_size(artifact.get(key))
            if parsed is not None:
                sizes.append(parsed)
    else:
        parsed = _parse_int_size(artifact)
        if parsed is not None:
            sizes.append(parsed)

    reproducers = candidate.get("reproducers")
    if isinstance(reproducers, list):
        for rep in reproducers:
            if isinstance(rep, dict):
                for key in ("size_bytes", "input_bytes", "size"):
                    parsed = _parse_int_size(rep.get(key))
                    if parsed is not None:
                        sizes.append(parsed)

    return min(sizes) if sizes else None


def _input_bytes_sort_key(candidate: dict[str, Any]) -> tuple[int, int]:
    """Known non-negative sizes sort ascending before unknown sizes."""
    size = _input_bytes(candidate)
    if size is None:
        return (1, 0)
    return (0, size)


def _has_null_page_address(text: str) -> bool:
    """True when sanitizer output references a NULL-page address (< 0x1000)."""
    if not text:
        return False
    low = text.lower()
    if "address 0x" not in low:
        return False
    for m in re.finditer(r"address\s+0x([0-9a-f]+)", low):
        try:
            if int(m.group(1), 16) < 0x1000:
                return True
        except ValueError:
            continue
    return False


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _extract_signals(candidate: dict[str, Any]) -> dict[str, str]:
    """Collect normalized text signals from flat or schema-shaped candidate dicts."""
    prop = _as_dict(candidate.get("property"))
    loc = _as_dict(candidate.get("location"))
    failure = _as_dict(candidate.get("failure"))
    observations = _as_list(candidate.get("observations"))

    obs_kinds: list[str] = []
    obs_engines: list[str] = []
    obs_msgs: list[str] = []
    for obs in observations:
        if not isinstance(obs, dict):
            continue
        ok = obs.get("kind")
        if isinstance(ok, str) and ok.strip():
            obs_kinds.append(ok.strip())
        oe = obs.get("engine")
        if isinstance(oe, str) and oe.strip():
            obs_engines.append(oe.strip())
        om = obs.get("message")
        if isinstance(om, str) and om.strip():
            obs_msgs.append(om.strip())

    fp = _fingerprint(candidate)
    alarm_kind = str(
        candidate.get("alarm_kind")
        or failure.get("alarm_kind")
        or (prop.get("kind") if str(prop.get("kind") or "").lower() in _KNOWN_ALARM_KINDS else "")
        or _fingerprint_kind(fp)
        or ""
    ).strip()
    kind = str(
        candidate.get("kind") or failure.get("kind") or (obs_kinds[0] if obs_kinds else "") or prop.get("kind") or ""
    ).strip()
    predicate = str(candidate.get("predicate") or failure.get("predicate") or prop.get("predicate") or "").strip()
    summary = str(candidate.get("summary") or "").strip()
    message = str(candidate.get("message") or failure.get("message") or "").strip()
    engine = str(candidate.get("engine") or (obs_engines[0] if obs_engines else "") or "").strip()
    file_ = str(candidate.get("file") or loc.get("file") or failure.get("file") or "").strip()
    function = str(candidate.get("function") or loc.get("function") or failure.get("function") or "").strip()
    meta_property = str(candidate.get("meta_property") or failure.get("meta_property") or "").strip()
    stack = str(candidate.get("stack") or candidate.get("caller") or "").strip()

    text_parts = [
        kind,
        alarm_kind,
        engine,
        predicate,
        summary,
        message,
        *obs_kinds,
        *obs_engines,
        *obs_msgs,
        stack,
    ]
    combined = " ".join(p for p in text_parts if p)
    location_text = " ".join(p for p in (file_, function, stack, predicate, summary, message, *obs_msgs) if p)

    return {
        "alarm_kind": alarm_kind,
        "kind": kind,
        "predicate": predicate,
        "summary": summary,
        "message": message,
        "engine": engine,
        "file": file_,
        "function": function,
        "meta_property": meta_property,
        "combined": combined,
        "location_text": location_text,
    }


def failure_family(candidate: dict[str, Any]) -> str:
    """Extract a normalized root-cause failure family from a candidate dictionary.

    Inspects ``alarm_kind``, ``kind``, ``predicate``, ``summary``/``message``, nested
    ``property``/``observations``/``location``, and ``fingerprint`` to produce a stable
    ``<engine>:<subfamily>`` string such as:

    - ``ubsan:null_member_access``
    - ``asan:non_malloc_free``
    - ``asan:stack_oob_harness``
    - ``lsan:direct_leak``
    - ``eacsl:mem_access``
    - ``toolchain:startup``
    """
    sig = _extract_signals(candidate)
    low_kind = sig["kind"].lower()
    low_alarm = sig["alarm_kind"].lower()
    low_engine = sig["engine"].lower()
    low_text = sig["combined"].lower()
    loc_text = sig["location_text"]

    # 1. Toolchain, link-stub, startup, and resource-limit failures.
    if "framac_link_stub_called" in low_text or "link_stub" in low_kind or "link_stub" in low_text:
        return "toolchain:link_stub"
    if (
        "toolchain_artifact" in low_kind
        or ("toolchain" in low_kind and "startup" in low_text)
        or low_kind in {"toolchain_startup", "startup_error", "startup", "loader_error"}
        or any(
            marker in low_text
            for marker in (
                "cannot open shared object",
                "error while loading shared libraries",
                "symbol lookup error",
                "undefined symbol",
                "exec format error",
                "failed to start",
                "startup error",
                "startup crash",
                "toolchain:startup",
                "init_array",
                "global constructors",
                "__libc_start_main",
            )
        )
    ):
        return "toolchain:startup"
    if low_kind == "asan_requested_allocation_size" or any(
        marker in low_text
        for marker in (
            "exceeded heap allocation limit",
            "shadow copy failed",
            "requested allocation size",
            "allocation-size-too-big",
            "out-of-memory",
            "out of memory",
        )
    ):
        return "toolchain:resource_limit"
    if "toolchain" in low_kind or low_engine == "toolchain":
        sub = _slug(low_kind.removeprefix("toolchain_"), default="error")
        return f"toolchain:{sub}"

    # 2. LeakSanitizer failures.
    if (
        low_kind.startswith("lsan_")
        or low_engine == "lsan"
        or low_alarm == "memory_leak"
        or "leaksanitizer" in low_text
    ):
        if "indirect_leak" in low_kind or "indirect leak" in low_text:
            return "lsan:indirect_leak"
        if re.search(r"(?:^|_)direct_leak\b", low_kind) or re.search(r"\bdirect leak\b", low_text):
            return "lsan:direct_leak"
        return "lsan:memory_leak"

    # 3. AddressSanitizer failures.
    is_asan = (
        low_kind.startswith("asan_")
        or low_engine == "asan"
        or "addresssanitizer" in low_text
        or any(
            marker in low_text
            for marker in (
                "attempting free on address which was not malloc",
                "not malloc()-ed",
                "bad-free",
                "double-free",
                "stack-buffer-overflow",
                "stack-buffer-underflow",
                "heap-buffer-overflow",
                "heap-buffer-underflow",
                "global-buffer-overflow",
                "heap-use-after-free",
                "stack-use-after-return",
                "stack-use-after-scope",
                "alloc-dealloc-mismatch",
                "memcpy-param-overlap",
                "negative-size-param",
            )
        )
    )
    if is_asan:
        if (
            "not_malloc" in low_kind
            or "not malloc" in low_text
            or "bad-free" in low_text
            or "bad_free" in low_kind
            or "non_malloc_free" in low_text
        ):
            return "asan:non_malloc_free"
        if "double-free" in low_text or "double_free" in low_kind or "double_free" in low_text:
            return "asan:double_free"
        if (
            "stack-buffer-overflow" in low_text
            or "stack_buffer_overflow" in low_kind
            or "stack-buffer-underflow" in low_text
            or "stack_buffer_underflow" in low_kind
            or "stack_oob" in low_text
        ):
            if _HARNESS_MARKER_RE.search(loc_text) or "stack_oob_harness" in low_text:
                return "asan:stack_oob_harness"
            return "asan:stack_oob"
        if (
            "heap-buffer-overflow" in low_text
            or "heap_buffer_overflow" in low_kind
            or "heap-buffer-underflow" in low_text
            or "heap_buffer_underflow" in low_kind
        ):
            return "asan:heap_oob"
        if "global-buffer-overflow" in low_text or "global_buffer_overflow" in low_kind:
            return "asan:global_oob"
        if "use-after-free" in low_text or "use_after_free" in low_kind:
            return "asan:use_after_free"
        if "use-after-return" in low_text or "use_after_return" in low_kind:
            return "asan:use_after_return"
        if "use-after-scope" in low_text or "use_after_scope" in low_kind:
            return "asan:use_after_scope"
        if "alloc-dealloc-mismatch" in low_text or "alloc_dealloc_mismatch" in low_kind:
            return "asan:alloc_dealloc_mismatch"
        if "param-overlap" in low_text or "param_overlap" in low_kind:
            return "asan:param_overlap"
        if "negative-size-param" in low_text or "negative_size_param" in low_kind:
            return "asan:negative_size_param"
        if "stack-overflow" in low_text or "stack_overflow" in low_kind:
            return "asan:stack_overflow"
        if "segv" in low_kind or re.search(r"\bsegv\b", low_text):
            if "null" in low_text or _has_null_page_address(low_text):
                return "asan:segv_null"
            return "asan:segv"
        sub = _slug(low_kind.removeprefix("asan_"), default="") or _slug(low_alarm, default="error")
        return f"asan:{sub}"

    # 4. UndefinedBehaviorSanitizer failures.
    is_ubsan = (
        low_kind.startswith("ubsan_")
        or low_engine == "ubsan"
        or "undefinedbehaviorsanitizer" in low_text
        or any(
            marker in low_text
            for marker in (
                "member access within null pointer",
                "member call on null pointer",
                "load of null pointer",
                "store to null pointer",
                "reference binding to null pointer",
                "null pointer passed as argument",
                "applying zero offset to null pointer",
                "applying non-zero offset to null pointer",
                "misaligned address",
                "out of bounds for type",
                "signed integer overflow",
                "unsigned integer overflow",
                "cannot be represented in type",
                "shift exponent",
                "left shift of",
                "right shift of",
                "not a valid value for type 'bool'",
                "outside the range of representable values",
                "through pointer to incorrect function type",
                "variable length array bound evaluates to non-positive",
                "insufficient space for an object of type",
                "execution reached an unreachable",
            )
        )
    )
    if is_ubsan:
        if (
            "member access within null pointer" in low_text
            or "member call on null pointer" in low_text
            or "null_member_access" in low_text
        ):
            return "ubsan:null_member_access"
        if "null pointer" in low_text or "null_pointer" in low_text:
            return "ubsan:null_pointer"
        if "misaligned address" in low_text or "misaligned" in low_text:
            return "ubsan:misaligned_access"
        if "out of bounds" in low_text:
            return "ubsan:index_oob"
        if (
            "signed integer overflow" in low_text
            or "cannot be represented in type" in low_text
            or low_alarm == "signed_overflow"
        ):
            return "ubsan:signed_overflow"
        if "unsigned integer overflow" in low_text or low_alarm == "unsigned_overflow":
            return "ubsan:unsigned_overflow"
        if "shift" in low_text or low_alarm == "shift":
            return "ubsan:shift"
        if "division by zero" in low_text or "divide by zero" in low_text or low_alarm == "division_by_zero":
            return "ubsan:division_by_zero"
        if "not a valid value for type 'bool'" in low_text or low_alarm == "bool_value":
            return "ubsan:invalid_bool"
        if "outside the range of representable values" in low_text or low_alarm == "float_to_int":
            return "ubsan:float_cast_overflow"
        if "incorrect function type" in low_text or low_alarm == "function_pointer":
            return "ubsan:function_pointer_mismatch"
        if "variable length array bound" in low_text:
            return "ubsan:vla_bound"
        if "insufficient space for an object of type" in low_text:
            return "ubsan:object_size"
        if "reached an unreachable" in low_text:
            return "ubsan:unreachable"
        if low_kind == "ubsan_segv" or re.search(r"\bsegv\b", low_text):
            if "null" in low_text or _has_null_page_address(low_text):
                return "ubsan:segv_null"
            return "ubsan:segv"
        if low_kind.startswith("ubsan_") and low_kind != "ubsan_runtime_error":
            return f"ubsan:{_slug(low_kind.removeprefix('ubsan_'), default='runtime_error')}"
        if low_alarm:
            return f"ubsan:{_slug(low_alarm, default='runtime_error')}"
        return "ubsan:runtime_error"

    # 5. E-ACSL / RTE / MetAcsl failures.
    if low_kind == "eacsl_format_error":
        return "eacsl:format_error"
    if sig["meta_property"] or low_alarm.startswith("meta_"):
        meta_slug = _slug(low_alarm if low_alarm.startswith("meta_") else f"meta_{sig['meta_property']}", "meta")
        return f"eacsl:{meta_slug}"

    inferred_alarm = ""
    if low_alarm in _KNOWN_ALARM_KINDS:
        inferred_alarm = low_alarm
    elif low_kind in _KNOWN_ALARM_KINDS:
        inferred_alarm = low_kind
    else:
        rte_m = _RTE_LABEL_RE.search(sig["predicate"])
        if rte_m and rte_m.group(1).lower() in _KNOWN_ALARM_KINDS:
            inferred_alarm = rte_m.group(1).lower()
        elif "\\valid_read" in sig["predicate"] or "\\valid(" in sig["predicate"]:
            inferred_alarm = "mem_access"
        elif "\\initialized" in sig["predicate"]:
            inferred_alarm = "initialization"
        elif "\\separated" in sig["predicate"]:
            inferred_alarm = "separation"
        elif "\\freeable" in sig["predicate"]:
            inferred_alarm = "freeable"

    if inferred_alarm:
        if inferred_alarm == "pointer_value":
            inferred_alarm = "ptr_value"
        return f"eacsl:{inferred_alarm}"

    if low_kind in _ACSL_CONTRACT_KINDS:
        return f"eacsl:{low_kind}"
    if low_kind.startswith("eacsl_") or low_engine in {"eacsl", "e-acsl"} or "e-acsl" in low_text:
        sub = _slug(low_kind.removeprefix("eacsl_"), default="runtime_error")
        return f"eacsl:{sub}"

    # 6. OS signals and fuzzer timeouts.
    sig_m = _SIGNAL_RE.search(sig["combined"])
    if sig_m:
        sig_name = sig_m.group(1).lower()
        if sig_name == "sigsegv" and ("null" in low_text or _has_null_page_address(low_text)):
            return "signal:sigsegv_null"
        return f"signal:{sig_name}"
    if re.search(r"\bsegv\b", low_text):
        if "null" in low_text or _has_null_page_address(low_text):
            return "signal:sigsegv_null"
        return "signal:sigsegv"
    if "timeout" in low_kind or "fuzz_timeout" in low_text:
        return "fuzz:timeout"

    # 7. Deterministic fallback.
    if low_kind:
        return f"other:{_slug(low_kind, default='crash')}"
    if low_alarm:
        return f"other:{_slug(low_alarm, default='crash')}"
    return "unknown:crash"


def _dispatch_case_or_entry(candidate: dict[str, Any]) -> str:
    """Extract a normalized dispatch case or harness entry identifier for clustering.

    Falls back to ``"default"`` (never the crash site's callee function) when neither
    ``dispatch_case`` nor ``entry``/``entry_function`` is present, so a single broken
    harness crashing across many callee functions stays grouped into one cluster.
    """
    artifact = _as_dict(candidate.get("artifact"))
    harness = _as_dict(candidate.get("harness"))

    for container in (candidate, artifact, harness):
        raw_case = container.get("dispatch_case")
        if raw_case is not None and not isinstance(raw_case, bool):
            if isinstance(raw_case, int):
                return f"case_{raw_case}"
            text = str(raw_case).strip()
            if text:
                if text.isdigit():
                    return f"case_{text}"
                return text

    for container in (candidate, harness, artifact):
        for key in ("entry", "entry_function"):
            raw_entry = container.get(key)
            if isinstance(raw_entry, str) and raw_entry.strip():
                return raw_entry.strip()

    return "default"


def cluster_candidates(
    candidates: list[dict[str, Any]],
    module_of: Callable[[dict[str, Any]], str],
) -> dict[str, list[dict[str, Any]]]:
    """Group unverified candidates by ``(module, dispatch_case_or_entry, failure_family)``.

    Returns an insertion-ordered ``dict[str, list[dict]]`` keyed by
    ``f"{module}::{case_or_entry}::{family}"``.

    - Candidates with an explicit non-``"unverified"`` ``status`` (e.g. ``"verified"``) are skipped.
    - Candidates inside each cluster are sorted by ``(input_bytes asc, fingerprint asc)``
      (candidates without a known ``input_bytes`` sort after known sizes).
    - Clusters are sorted by ``(cluster_size desc, smallest_input_bytes asc, smallest_fingerprint asc, key asc)``.
    """
    grouped: dict[str, list[dict[str, Any]]] = {}
    for cand in candidates:
        if not isinstance(cand, dict) or not _is_unverified(cand):
            continue
        mod = str(module_of(cand) or "").strip() or "unknown"
        case_or_entry = _dispatch_case_or_entry(cand)
        fam = failure_family(cand)
        key = f"{mod}::{case_or_entry}::{fam}"
        grouped.setdefault(key, []).append(cand)

    sorted_clusters: list[tuple[tuple[Any, ...], str, list[dict[str, Any]]]] = []
    for key, members in grouped.items():
        ordered_members = sorted(members, key=lambda c: (_input_bytes_sort_key(c), _fingerprint(c)))
        smallest_size = _input_bytes_sort_key(ordered_members[0])
        smallest_fp = min(_fingerprint(c) for c in ordered_members)
        cluster_sort_key = (-len(ordered_members), smallest_size, smallest_fp, key)
        sorted_clusters.append((cluster_sort_key, key, ordered_members))

    sorted_clusters.sort(key=lambda item: item[0])
    return {key: members for _, key, members in sorted_clusters}


def _classify_verdict(entry: dict[str, Any]) -> tuple[str, str | None]:
    """Classify a verdict or task-state dict into ``(lifecycle, normalized_verdict)``.

    ``lifecycle`` is one of:
    - ``"pending"``: not started yet (ignored by circuit breaker).
    - ``"active"``: currently in flight (counts as an active probe, ignored by circuit breaker).
    - ``"done"``: completed terminal verdict (counted by circuit breaker).
    - ``"ignored"``: non-verdict terminal error/skip state (e.g. ``blocked``/``ingest_failed``).
    """
    if not isinstance(entry, dict):
        return ("ignored", None)

    state = str(entry.get("state") or entry.get("status") or "").strip().lower()
    if state in _PENDING_STATES:
        return ("pending", None)
    if state in _ACTIVE_STATES:
        return ("active", None)
    if state in _IGNORED_STATES:
        return ("ignored", None)

    record = _as_dict(entry.get("record"))
    raw_verdict = (
        str(entry.get("verdict") or entry.get("outcome") or entry.get("decision") or record.get("verdict") or "")
        .strip()
        .lower()
    )
    rejection_class = str(entry.get("rejection_class") or record.get("rejection_class") or "").strip().lower()

    if raw_verdict in _PENDING_STATES:
        return ("pending", None)
    if raw_verdict in _ACTIVE_STATES:
        return ("active", None)

    if raw_verdict == "harness_induced":
        return ("done", "harness_induced")
    if rejection_class == "harness_induced" and raw_verdict in ("", "rejected"):
        return ("done", "harness_induced")
    if entry.get("harness_induced") is True and raw_verdict not in _NON_VERDICT_OUTCOMES - {""}:
        return ("done", "harness_induced")

    if raw_verdict and raw_verdict not in _NON_VERDICT_OUTCOMES:
        return ("done", raw_verdict)

    return ("ignored", None)


def evaluate_circuit_breaker(
    module_verdicts: list[dict[str, Any]],
    *,
    min_harness_induced: int = DEFAULT_MIN_HARNESS_INDUCED,
    min_ratio: float = DEFAULT_MIN_RATIO,
) -> dict[str, Any]:
    """Evaluate whether a module's verifier circuit breaker has tripped.

    Counts only completed verdicts (ignoring ``pending``/``running``/``active``/``blocked``
    entries). A verdict counts as ``harness_induced`` when its ``verdict``/``outcome``/``decision``
    is ``"harness_induced"`` or when it is ``"rejected"`` with ``rejection_class == "harness_induced"``.

    Uses a small floating-point tolerance (``1e-9``) so exact fractions like ``2/3`` reliably
    satisfy ``min_ratio = 2 / 3`` without precision drift.

    Returns ``{"tripped": bool, "harness_induced": int, "verified": int, "ratio": float, "reason": str}``.
    """
    verified = 0
    harness_induced = 0
    for entry in module_verdicts:
        lifecycle, verdict = _classify_verdict(entry)
        if lifecycle != "done" or verdict is None:
            continue
        verified += 1
        if verdict == "harness_induced":
            harness_induced += 1

    if verified == 0:
        return {
            "tripped": False,
            "harness_induced": 0,
            "verified": 0,
            "ratio": 0.0,
            "reason": "no completed verdicts",
        }

    ratio = harness_induced / verified
    tripped = harness_induced >= min_harness_induced and (ratio + _RATIO_EPS) >= min_ratio
    if tripped:
        reason = (
            f"tripped: {harness_induced}/{verified} ({ratio:.1%}) harness_induced "
            f">= min_harness_induced={min_harness_induced} and min_ratio={min_ratio:.3f}"
        )
    elif harness_induced < min_harness_induced:
        reason = (
            f"below count threshold: {harness_induced}/{verified} ({ratio:.1%}) harness_induced "
            f"< min_harness_induced={min_harness_induced}"
        )
    else:
        reason = (
            f"below ratio threshold: {harness_induced}/{verified} ({ratio:.1%}) harness_induced "
            f"< min_ratio={min_ratio:.3f}"
        )

    return {
        "tripped": tripped,
        "harness_induced": harness_induced,
        "verified": verified,
        "ratio": ratio,
        "reason": reason,
    }


def _is_harness_signal_family(family: str) -> bool:
    """True for failure families strongly correlated with broken harness setup."""
    low = family.lower()
    return (
        "null" in low
        or low in {"asan:non_malloc_free", "asan:double_free", "eacsl:freeable"}
        or low in {"asan:stack_oob_harness", "toolchain:startup", "toolchain:link_stub"}
    )


def _is_tiny_input(candidate: dict[str, Any]) -> bool:
    size = _input_bytes(candidate)
    return size is not None and size <= TINY_INPUT_THRESHOLD_BYTES


def _cluster_probe_rank(
    cluster_key: str,
    members: list[dict[str, Any]],
) -> tuple[int, int, int, tuple[int, int], str, str]:
    """Deterministic probe priority for a non-empty cluster.

    Prioritizes clusters with high-signal broken-harness indicators (``<= 4``-byte input,
    NULL dereference, non-malloc/bad free, harness-stack OOB, or startup failure) first,
    then largest cluster size, smallest input size, and smallest fingerprint.
    """
    best = members[0]
    fam = failure_family(best)
    has_tiny = _is_tiny_input(best)
    has_harness_fam = _is_harness_signal_family(fam)
    high_signal = has_tiny or has_harness_fam
    both_signals = has_tiny and has_harness_fam
    return (
        0 if high_signal else 1,
        0 if both_signals else 1,
        -len(members),
        _input_bytes_sort_key(best),
        min(_fingerprint(c) for c in members),
        cluster_key,
    )


def select_probe_batch(
    module_candidates: list[dict[str, Any]],
    active_or_done_verdicts: list[dict[str, Any]],
    *,
    fanout_threshold: int = DEFAULT_FANOUT_THRESHOLD,
    max_probes: int = DEFAULT_MAX_PROBES,
) -> list[str]:
    """Select which pending candidate fingerprints for a module may be dispatched now.

    Return contract (for ``wp_scheduler.py`` / W2-D):
    - Every returned fingerprint is guaranteed to be an unverified candidate from
      ``module_candidates`` that is **not** currently active or already completed in
      ``active_or_done_verdicts`` (so callers can directly allow pending ``verify:<fp>``
      tasks whose fingerprint is in the returned list).
    - If ``evaluate_circuit_breaker(active_or_done_verdicts)["tripped"]`` is True,
      returns ``[]`` (halt further verification for this module).
    - If the module's total scope (distinct unverified + active + completed candidates)
      is ``<= fanout_threshold``, returns all pending fingerprints immediately (zero
      added latency on small/clean modules).
    - Otherwise (``> fanout_threshold``):
      - Once at least ``min(max_probes, total_scope)`` probe verdicts have completed
        without tripping the circuit breaker, releases **all** remaining pending
        fingerprints (in deterministic probe-priority order).
      - While the initial probe batch has not yet completed, returns up to
        ``max(0, probe_target - completed - active)`` pending fingerprints, preferring
        the highest-priority distinct failure-family clusters (prioritizing ``<= 4``-byte,
        NULL, non-malloc/double free, and harness-stack/startup crashes first), then
        distinct dispatch-case/entry clusters, then remaining candidates in priority order.
    """
    # 1. Inspect active and completed verdicts.
    breaker = evaluate_circuit_breaker(active_or_done_verdicts)
    if breaker["tripped"]:
        return []

    done_fps: set[str] = set()
    active_fps: set[str] = set()
    sampled_families: set[str] = set()
    active_without_fp = 0

    for entry in active_or_done_verdicts:
        lifecycle, _ = _classify_verdict(entry)
        if lifecycle not in ("active", "done"):
            continue
        fp = _fingerprint(entry)
        if lifecycle == "done":
            if fp:
                done_fps.add(fp)
        else:
            if fp:
                active_fps.add(fp)
            else:
                active_without_fp += 1
        explicit_fam = entry.get("failure_family")
        if isinstance(explicit_fam, str) and explicit_fam.strip():
            sampled_families.add(explicit_fam.strip())
        elif any(entry.get(k) for k in ("kind", "alarm_kind", "predicate", "summary", "message", "property")):
            fam = failure_family(entry)
            if fam != "unknown:crash":
                sampled_families.add(fam)

    active_fps -= done_fps

    # 2. Deduplicate unverified candidates in module_candidates.
    seen_fps: set[str] = set()
    unverified: list[dict[str, Any]] = []
    for cand in module_candidates:
        if not isinstance(cand, dict) or not _is_unverified(cand):
            continue
        fp = _fingerprint(cand)
        if not fp or fp in seen_fps:
            continue
        seen_fps.add(fp)
        unverified.append(cand)
        if fp in active_fps or fp in done_fps:
            sampled_families.add(failure_family(cand))

    pending = [c for c in unverified if _fingerprint(c) not in active_fps and _fingerprint(c) not in done_fps]
    if not pending:
        return []

    # Cluster ALL unverified candidates in this single module so cluster sizes reflect the full
    # module burst even after the first probe is dispatched or completed.
    all_clusters = cluster_candidates(unverified, lambda _: "module")
    ranked_clusters: list[tuple[str, str, list[dict[str, Any]]]] = []
    for key, members in all_clusters.items():
        pending_members = [c for c in members if _fingerprint(c) not in active_fps and _fingerprint(c) not in done_fps]
        if not pending_members:
            continue
        ranked_clusters.append((key, failure_family(members[0]), pending_members))

    # Rank clusters by the full cluster size (including active/done members) + probe signal priority.
    ranked_clusters.sort(key=lambda item: _cluster_probe_rank(item[0], all_clusters[item[0]]))

    all_pending_ordered = [_fingerprint(c) for _, _, members in ranked_clusters for c in members]

    # Total module candidate scope across unverified + active + completed verdicts.
    completed_count = int(breaker["verified"])
    active_count = len(active_fps) + active_without_fp
    distinct_scope_fps = seen_fps | active_fps | done_fps
    total_scope = max(len(distinct_scope_fps), len(pending) + active_count + completed_count)

    # 3. Small/clean module passthrough: zero added latency.
    if total_scope <= fanout_threshold:
        return all_pending_ordered

    # 4. Large module: check whether initial probe batch has already cleared.
    probe_target = min(max(0, max_probes), total_scope)
    if completed_count >= probe_target:
        return all_pending_ordered

    # 5. Still in probe phase: fill remaining probe slots up to probe_target.
    slots = max(0, probe_target - completed_count - active_count)
    if slots == 0:
        return []

    selected: list[str] = []
    selected_set: set[str] = set()
    used_families = set(sampled_families)
    used_clusters: set[str] = set()

    # Pass 1: one representative per distinct unsampled failure family, highest-priority cluster first.
    for cluster_key, fam, pending_members in ranked_clusters:
        if len(selected) >= slots:
            break
        if fam in used_families:
            continue
        fp = _fingerprint(pending_members[0])
        if fp not in selected_set:
            selected.append(fp)
            selected_set.add(fp)
            used_families.add(fam)
            used_clusters.add(cluster_key)

    # Pass 2: one representative per distinct cluster not yet picked from (e.g. different dispatch case).
    if len(selected) < slots:
        for cluster_key, _, pending_members in ranked_clusters:
            if len(selected) >= slots:
                break
            if cluster_key in used_clusters:
                continue
            fp = _fingerprint(pending_members[0])
            if fp not in selected_set:
                selected.append(fp)
                selected_set.add(fp)
                used_clusters.add(cluster_key)

    # Pass 3: fill any remaining probe slots from the highest-priority remaining pending candidates.
    if len(selected) < slots:
        for fp in all_pending_ordered:
            if len(selected) >= slots:
                break
            if fp not in selected_set:
                selected.append(fp)
                selected_set.add(fp)

    return selected
