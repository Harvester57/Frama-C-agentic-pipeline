#!/usr/bin/env python3
"""
Shared helpers for the Frama-C pipeline scripts (stdlib only).

- Atomic JSON writes and strict JSON loads (no silent fallback to {}).
- Normalization of Frama-C property statuses and `-report-csv` columns, which
  differ between Frama-C releases ("property kind" vs "kind", "Valid under hyp."
  vs "Valid_under_hyp").
- Safe run-relative path checks used by validators and ingestion.
"""

from __future__ import annotations

import csv
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

# Canonical status buckets used across Eva and WP parsing.
STATUS_VALID = "valid"
STATUS_VALID_UNDER_HYP = "valid_under_hyp"
STATUS_UNKNOWN = "unknown"
STATUS_INVALID = "invalid"
STATUS_INVALID_UNDER_HYP = "invalid_under_hyp"
STATUS_DEAD = "dead"
STATUS_ASSUMED = "assumed"
STATUS_NEVER_TRIED = "never_tried"
STATUS_INCONSISTENT = "inconsistent"
STATUS_OTHER = "other"

_STATUS_MAP = {
    "valid": STATUS_VALID,
    "valid_under_hyp": STATUS_VALID_UNDER_HYP,
    "valid_under_hypotheses": STATUS_VALID_UNDER_HYP,
    "unknown": STATUS_UNKNOWN,
    "invalid": STATUS_INVALID,
    "invalid_under_hyp": STATUS_INVALID_UNDER_HYP,
    "invalid_under_hypotheses": STATUS_INVALID_UNDER_HYP,
    # "... but dead": the property sits in code that is unreachable under the
    # analysis context. Never a bug, never a proof.
    "invalid_but_dead": STATUS_DEAD,
    "valid_but_dead": STATUS_DEAD,
    "unknown_but_dead": STATUS_DEAD,
    # Considered valid: an assumption (e.g. a libc or stub specification), not
    # something this run established.
    "considered_valid": STATUS_ASSUMED,
    "never_tried": STATUS_NEVER_TRIED,
    "inconsistent": STATUS_INCONSISTENT,
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_status(raw: str | None) -> str:
    """Map any Frama-C status spelling onto a canonical bucket."""
    key = re.sub(r"[^a-z0-9]+", "_", (raw or "").strip().lower()).strip("_")
    return _STATUS_MAP.get(key, STATUS_OTHER)


def atomic_write_json(path: Path, data) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp_", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            json.dump(data, f, indent=2, sort_keys=False, ensure_ascii=False)
            f.write("\n")
        os.replace(tmp_path, path)
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


class ArtifactError(RuntimeError):
    """Raised when a required pipeline artifact is missing or malformed."""


def load_json_strict(path: Path, max_bytes: int = 64 * 1024 * 1024):
    """Load JSON and fail loudly. Callers must decide explicitly how to treat absence."""
    path = Path(path)
    if not path.is_file():
        raise ArtifactError(f"missing artifact: {path}")
    size = path.stat().st_size
    if size > max_bytes:
        raise ArtifactError(f"artifact exceeds {max_bytes} bytes: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArtifactError(f"malformed JSON in {path}: {exc}") from exc


def load_json_optional(path: Path, default):
    """Load JSON if present; a present-but-malformed file still raises."""
    path = Path(path)
    if not path.exists():
        return default
    return load_json_strict(path)


_UNESCAPED_ACSL_IN_JSON_RE = re.compile(
    r"(?<!\\)\\("
    r"valid_read|valid_function|valid|separated|result|old|initialized|at|"
    r"forall|exists|lambda|let|null|true|false|base_addr|block_length|offset|"
    r"allocation|freeable|fresh|subset|empty|union|inter|is_NaN|is_finite|"
    r"tainted|nothing|exact|round_error"
    r")\b"
)
_INVALID_JSON_ESCAPE_RE = re.compile(r'(?<!\\)\\(?![/\"\\bfnrtu])')
_CTRL_ACSL_SUBS = (
    (re.compile(r"(?:\x07|(?<!\\)\\u0007)(?=t\b)"), r"\\a"),
    (re.compile(r"(?:\x08|(?<!\\)\\u0008)(?=(?:ase_addr|lock_length)\b)"), r"\\b"),
    (re.compile(r"(?:\x0b|(?<!\\)\\u000[bB])(?=alid(?:_read|_function)?\b)"), r"\\v"),
    (re.compile(r"(?:\x0c|(?<!\\)\\u000[cC])(?=(?:orall|alse|reeable|resh)\b)"), r"\\f"),
)


def repair_acsl_json_text(raw: str) -> tuple[str, bool]:
    """
    Repair unescaped ACSL backslash keywords (e.g. `\\valid`, `\\forall`, `\\false`, `\\at`)
    and control-character-corrupted ACSL keywords inside raw JSON text.
    """
    repaired = raw
    for rx, repl in _CTRL_ACSL_SUBS:
        repaired = rx.sub(repl, repaired)
    repaired = _UNESCAPED_ACSL_IN_JSON_RE.sub(r"\\\\\1", repaired)
    repaired = _INVALID_JSON_ESCAPE_RE.sub(r"\\\\", repaired)
    return repaired, (repaired != raw)


def load_agent_result_json(path: Path, max_bytes: int = 64 * 1024 * 1024) -> dict:
    """
    Load an agent result JSON file, repairing unescaped ACSL backslashes (`\\valid`,
    `\\forall`, `\\false`, `\\at`, etc.) if present and persisting the sanitized JSON.
    """
    path = Path(path)
    if not path.is_file():
        raise ArtifactError(f"missing artifact: {path}")
    size = path.stat().st_size
    if size > max_bytes:
        raise ArtifactError(f"artifact exceeds {max_bytes} bytes: {path}")
    try:
        raw = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ArtifactError(f"malformed UTF-8 in {path}: {exc}") from exc

    repaired_raw, changed = repair_acsl_json_text(raw)
    try:
        data = json.loads(repaired_raw)
    except json.JSONDecodeError as exc:
        raise ArtifactError(f"malformed JSON in {path}: {exc}") from exc

    if changed and isinstance(data, dict):
        try:
            atomic_write_json(path, data)
        except OSError:
            pass
    return data


# Frama-C `-report-csv` header: directory, file, line, function, property kind,
# status, property. Older scripts assumed "kind"/"annotation"; accept all.
_CSV_ALIASES = {
    "directory": ("directory", "dir"),
    "file": ("file",),
    "line": ("line",),
    "function": ("function",),
    "kind": ("property kind", "property_kind", "kind"),
    "status": ("status",),
    "property": ("property", "annotation"),
}


def _pick(row: dict[str, str], names) -> str:
    lowered = {(k or "").strip().lower(): v for k, v in row.items()}
    for name in names:
        if name in lowered and lowered[name] is not None:
            return str(lowered[name]).strip()
    return ""


def read_report_csv(csv_path: Path) -> list[dict]:
    """Parse a Frama-C report CSV into normalized property rows."""
    rows: list[dict] = []
    with open(csv_path, encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        for raw in reader:
            line_txt = _pick(raw, _CSV_ALIASES["line"])
            try:
                line_no = int(line_txt) if line_txt else 0
            except ValueError:
                line_no = 0
            status_raw = _pick(raw, _CSV_ALIASES["status"])
            rows.append({
                "directory": _pick(raw, _CSV_ALIASES["directory"]),
                "file": _pick(raw, _CSV_ALIASES["file"]),
                "line": line_no,
                "function": _pick(raw, _CSV_ALIASES["function"]),
                "kind": _pick(raw, _CSV_ALIASES["kind"]),
                "status_raw": status_raw,
                "status": normalize_status(status_raw),
                "property": _pick(raw, _CSV_ALIASES["property"]),
            })
    return rows


_WINDOWS_DEVICE = re.compile(r"^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$", re.IGNORECASE)


def is_safe_relative_path(value: str) -> bool:
    """True for a non-empty, forward-slash, relative path without traversal."""
    if not isinstance(value, str) or not value or value != value.strip():
        return False
    if "\\" in value or "\x00" in value or value.startswith("/") or re.match(r"^[A-Za-z]:", value):
        return False
    parts = value.split("/")
    for part in parts:
        if part in ("", ".", "..") or _WINDOWS_DEVICE.match(part):
            return False
    return True


AGENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def is_safe_agent_id(value: str) -> bool:
    return isinstance(value, str) and bool(AGENT_ID_RE.match(value)) and not _WINDOWS_DEVICE.match(value)


def to_run_relative(path: Path, run_dir: Path) -> str:
    """Express a path relative to the run directory using forward slashes."""
    p = Path(path)
    if not p.is_absolute():
        p = (Path.cwd() / p)
    try:
        return p.resolve().relative_to(Path(run_dir).resolve()).as_posix()
    except ValueError:
        return Path(path).as_posix()


def resolve_fc_stubs_dir() -> Path | None:
    """Locate the pipeline's templates/fc_stubs directory (container or local checkout)."""
    container_dir = Path("/opt/framac-pipeline/templates/fc_stubs")
    if container_dir.is_dir():
        return container_dir
    local_dir = Path(__file__).resolve().parent.parent / "templates" / "fc_stubs"
    if local_dir.is_dir():
        return local_dir
    return None


def augment_framac_cppflags(cppflags: str) -> str:
    """
    Append `-I<fc_stubs>` and `-include <fc_compat_types.h>` for Frama-C `-nostdinc` runs
    (Eva and WP) so third-party headers (`bsd/string.h`, `json-c/json.h`, `netinet/ip_icmp.h`)
    and glibc internal integer typedefs (`__int32_t`, etc.) resolve cleanly without
    shadowing `__fc_libc`.
    """
    base = (cppflags or "-I.").strip()
    fc_stubs = resolve_fc_stubs_dir()
    if fc_stubs is None:
        return base
    stubs_posix = fc_stubs.as_posix()
    compat_hdr = (fc_stubs / "fc_compat_types.h").as_posix()
    parts = [base] if base else []
    if f"-I{stubs_posix}" not in base:
        parts.append(f"-I{stubs_posix}")
    if "fc_compat_types.h" not in base and (fc_stubs / "fc_compat_types.h").is_file():
        parts.append(f"-include {compat_hdr}")
    return " ".join(parts)


# Frama-C: "Calling undeclared function X. Old style K&R code?" (it then invents `int X()`,
# which is unsound for Eva/WP). Clang: "call to undeclared function 'X'" /
# "implicit declaration of function 'X'".
_UNDECLARED_FN_RES = (
    re.compile(r"Calling undeclared function\s+'?(?P<fn>[A-Za-z_]\w*)'?"),
    re.compile(r"call to undeclared (?:library )?function '(?P<fn>[A-Za-z_]\w*)'"),
    re.compile(r"implicit declaration of function '(?P<fn>[A-Za-z_]\w*)'"),
)


def scan_undeclared_functions(log_text: str) -> list[str]:
    """Functions called without a prototype (missing stub/header declaration), sorted and unique."""
    found: set[str] = set()
    for rx in _UNDECLARED_FN_RES:
        for m in rx.finditer(log_text or ""):
            found.add(m.group("fn"))
    return sorted(found)
