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

FINGERPRINT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@+-]*#[A-Za-z_][A-Za-z0-9_]*::[A-Za-z0-9_]+::[0-9a-f]{10}$")

# Alarm / RTE kinds emitted by RTE, Eva and E-ACSL.
KNOWN_ALARM_KINDS = (
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
# Longest first, so `is_nan_or_infinite` is never read as `is_nan`.
_KINDS_ALT = "|".join(sorted(KNOWN_ALARM_KINDS, key=len, reverse=True))
_KIND_LABEL_RE = re.compile(r"^\s*(?:rte/)?(?:" + _KINDS_ALT + r")\s*:(?!:)\s*", re.IGNORECASE)
# Frama-C prints ACSL with Unicode symbols unless -no-unicode; E-ACSL reports and Eva/WP CSVs differ.
_UNICODE_ACSL = {
    "≤": "<=",
    "≥": ">=",
    "≢": "!=",
    "≠": "!=",
    "≡": "==",
    "⇒": "==>",
    "⇔": "<==>",
    "∧": "&&",
    "∨": "||",
    "¬": "!",
    "⊕": "^^",
    "∀": "\\forall",
    "∃": "\\exists",
    "∈": "\\in",
    "ℤ": "integer",
    "ℝ": "real",
    "𝔹": "boolean",
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
    p = re.sub(r"^[A-Za-z]:/+", "", p)
    changed = True
    while changed:
        changed = False
        for prefix in _PATH_PREFIXES:
            if p.startswith(prefix):
                p = p[len(prefix) :]
                changed = True
    p = re.sub(r"/+", "/", p).strip("/")
    return p or "unknown"


def detect_alarm_kind(predicate: str) -> str:
    """
    The first known alarm kind named anywhere in a short label or kind string (`rte/mem_access`,
    `Assertion rte/index_bound`). Not for a predicate body: an identifier such as `shift` matches.
    """
    text = (predicate or "").lower()
    for kind in KNOWN_ALARM_KINDS:
        if re.search(r"(?<![a-z0-9_])" + re.escape(kind) + r"(?![a-z0-9_])", text):
            return kind
    return ""


# A kind used as a label inside a predicate: `rte/shift` anywhere, or `shift:` (not `::`, not `?:`).
_LABELLED_KIND_RE = re.compile(
    r"(?:(?<![A-Za-z0-9_])rte/(" + _KINDS_ALT + r")(?![A-Za-z0-9_]))"
    r"|(?:(?<![A-Za-z0-9_\\])(" + _KINDS_ALT + r")\s*:(?!:))",
    re.IGNORECASE,
)


def _strip_generic_labels(text: str) -> str:
    previous = None
    while previous != text:
        previous = text
        text = _LABEL_RE.sub("", text)
    return text


def leading_alarm_kind(predicate: str) -> str:
    """The alarm kind of a leading `<kind>:` label (after `assert`, `rte:` ...), or ''."""
    text = _strip_generic_labels((predicate or "").strip())
    m = re.match(r"^\s*(?:rte/)?(" + _KINDS_ALT + r")\s*:(?!:)", text, re.IGNORECASE)
    return m.group(1).lower() if m else ""


def detect_predicate_alarm_kind(predicate: str) -> str:
    """
    An alarm kind found in a predicate only where it is used as a label (`rte/<kind>`, `<kind>:`),
    never a C identifier that happens to share its name (`p + shift`, `index`, `overlap(a, b)`).
    """
    leading = leading_alarm_kind(predicate)
    if leading:
        return leading
    text = predicate or ""
    for m in _LABELLED_KIND_RE.finditer(text):
        if m.group(1):
            return m.group(1).lower()
        # `c ? shift : 0` and `f(a, overlap: ...)`-like operands are expressions, not labels.
        before = text[: m.start()].rstrip()
        if not before or before[-1] not in "?+-*/%<>=!&|^,([{~":
            return m.group(2).lower()
    return ""


def normalize_kind(kind: str, predicate: str = "") -> str:
    """
    The property kind of a fingerprint, in order of reliability: an explicit `<kind>:` label on the
    predicate, then the caller's kind when it names a known alarm kind, then a kind used as a label
    inside the predicate, then the normalized ACSL kind. Fuzz passes the predicate without its label
    and Eva with it, so the label and the kind argument must win over words inside the predicate.
    """
    alarm = leading_alarm_kind(predicate) or detect_alarm_kind(kind) or detect_predicate_alarm_kind(predicate)
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
    # Labels go before hashing, whichever side kept them: E-ACSL reports the label apart from the
    # predicate, Eva's annotation carries it (`mem_access: \valid_read(p)`).
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
    digest = hashlib.sha256(normalize_predicate(predicate).encode()).hexdigest()[:10]
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
