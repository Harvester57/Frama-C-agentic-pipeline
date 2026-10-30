#!/usr/bin/env python3
"""
Stable, source-derived finding fingerprints.

Format: <rel-file>#<function>::<property-kind>::<hash10>

- <rel-file> is repository-relative (overlay/container prefixes stripped).
- <property-kind> is the RTE/alarm kind when one can be recognized in the
  predicate (mem_access, signed_overflow, ...) or the normalized ACSL kind
  (precondition, loop_invariant, ...).
- <hash10> is the first 10 hex digits of SHA-256 over the normalized failing
  predicate (labels, whitespace and trailing punctuation removed).

Fingerprints never contain line numbers, input bytes, wave, agent or verdict,
so the same root cause keeps the same identity across tools, states and runs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys

FINGERPRINT_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._/@+-]*#[A-Za-z_][A-Za-z0-9_]*::[A-Za-z0-9_]+::[0-9a-f]{10}$"
)

# Alarm / RTE kinds emitted by RTE, Eva and E-ACSL.
KNOWN_ALARM_KINDS = (
    "mem_access", "index_bound", "pointer_value", "ptr_value",
    "signed_overflow", "unsigned_overflow", "signed_downcast", "unsigned_downcast",
    "division_by_zero", "shift", "initialization", "dangling_pointer",
    "float_to_int", "is_nan_or_infinite", "is_nan", "function_pointer",
    "bool_value", "separation", "overlap", "differing_blocks",
    "pointer_comparison", "pointer_downcast", "freeable", "valid_string",
)

_PATH_PREFIXES = (
    "/framac-run/workspace/work/",
    "/framac-run/workspace/baseline/",
    "/framac-run/",
    "/target/",
    "/workspace/.framac-workspace/work/",
    "/workspace/",
    "workspace/work/",
    "workspace/baseline/",
    ".framac-workspace/work/",
    "./",
)

_LABEL_RE = re.compile(
    r"^\s*(?:(?:assert|check|admit)\s+|(?:assert|check|admit|rte|eva|e-acsl|wp)\s*:\s*)+",
    re.IGNORECASE,
)
_KIND_LABEL_RE = re.compile(r"^\s*(?:rte/)?(?:" + "|".join(KNOWN_ALARM_KINDS) + r")\s*:\s*", re.IGNORECASE)
# Frama-C prints ACSL with Unicode symbols unless -no-unicode; E-ACSL reports and Eva/WP CSVs differ.
_UNICODE_ACSL = {
    "≤": "<=", "≥": ">=", "≢": "!=", "≠": "!=", "≡": "==", "⇒": "==>", "⇔": "<==>",
    "∧": "&&", "∨": "||", "¬": "!", "⊕": "^^", "∀": "\\forall", "∃": "\\exists", "∈": "\\in",
    "ℤ": "integer", "ℝ": "real", "𝔹": "boolean",
}


# Anchored anywhere in the path: an agent's scratch overlay, and a run directory seen from the host
# (`/home/u/framac-pipeline/repo/run-3/workspace/work/...`, `C:/.../run-3/workspace/work/...`).
_OVERLAY_ROOT_RES = (
    re.compile(r"^(?:.*/)?agents/[A-Za-z0-9_-]+/scratch/(?:work|base)/"),
    re.compile(r"^(?:.*/)?workspace/(?:work|baseline)/"),
)


def normalize_file(path: str) -> str:
    """
    Repository-relative path of a source file, whichever copy of it a tool saw: the container's
    work tree, an agent's scratch overlay, or the run directory as seen from the host. The same
    file must always give the same fingerprint and match the same ledger units.
    """
    p = (path or "").replace("\\", "/").strip()
    for rx in _OVERLAY_ROOT_RES:
        p = rx.sub("", p, count=1)
    changed = True
    while changed:
        changed = False
        for prefix in _PATH_PREFIXES:
            if p.startswith(prefix):
                p = p[len(prefix):]
                changed = True
    p = re.sub(r"/+", "/", p).strip("/")
    return p or "unknown"


def detect_alarm_kind(predicate: str) -> str:
    text = (predicate or "").lower()
    for kind in KNOWN_ALARM_KINDS:
        if re.search(r"(?<![a-z_])" + re.escape(kind) + r"(?![a-z_])", text):
            return kind
    return ""


def normalize_kind(kind: str, predicate: str = "") -> str:
    alarm = detect_alarm_kind(predicate) or detect_alarm_kind(kind)
    if alarm:
        return "ptr_value" if alarm == "pointer_value" else alarm
    k = re.sub(r"[^a-z0-9]+", "_", (kind or "").lower()).strip("_")
    aliases = {
        "assertion": "assertion",
        "assert": "assertion",
        "precondition": "precondition",
        "requires": "precondition",
        "postcondition": "postcondition",
        "ensures": "postcondition",
        "loop_invariant": "loop_invariant",
        "invariant": "loop_invariant",
        "loop_variant": "loop_variant",
        "variant": "loop_variant",
        "assigns": "assigns",
    }
    return aliases.get(k, k or "property")


def normalize_predicate(predicate: str) -> str:
    text = (predicate or "").strip()
    for symbol, ascii_form in _UNICODE_ACSL.items():
        text = text.replace(symbol, ascii_form)
    previous = None
    while previous != text:
        previous = text
        text = _LABEL_RE.sub("", text)
        # Drop a leading alarm-kind label such as "mem_access:".
        text = _KIND_LABEL_RE.sub("", text)
    text = text.strip().rstrip(";.").strip()
    return re.sub(r"\s+", "", text)


def _sanitize(value: str, allowed: str) -> str:
    return re.sub(r"[^" + allowed + r"]", "_", value)


def make_fingerprint(file: str, function: str, kind: str, predicate: str) -> str:
    rel = _sanitize(normalize_file(file), r"A-Za-z0-9._/@+-")
    fn = _sanitize((function or "").strip() or "unknown_function", r"A-Za-z0-9_")
    pkind = normalize_kind(kind, predicate)
    digest = hashlib.sha256(normalize_predicate(predicate).encode("utf-8")).hexdigest()[:10]
    fp = f"{rel}#{fn}::{pkind}::{digest}"
    if not fp[0].isalnum():
        fp = "x" + fp
    return fp


def is_valid_fingerprint(value: str) -> bool:
    return isinstance(value, str) and bool(FINGERPRINT_RE.match(value)) and "::" in value and "#" in value


def main() -> int:
    parser = argparse.ArgumentParser(description="Compute a stable finding fingerprint.")
    parser.add_argument("--file", required=True)
    parser.add_argument("--function", required=True)
    parser.add_argument("--kind", default="")
    parser.add_argument("--predicate", required=True)
    args = parser.parse_args()
    print(json.dumps({"fingerprint": make_fingerprint(args.file, args.function, args.kind, args.predicate)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
