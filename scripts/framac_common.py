#!/usr/bin/env python3
"""
Shared helpers for the Frama-C pipeline scripts (stdlib only).

- Atomic JSON writes and strict JSON loads (no silent fallback to {}).
- Normalization of Frama-C property statuses and `-report-csv` columns, which
  differ between Frama-C releases ("property kind" vs "kind", "Valid under hyp."
  vs "Valid_under_hyp").
- Safe run-relative path checks used by validators and ingestion.
- `scratch_first_flags()`: preprocessor flags that read an agent's scratch copy of the source tree.
- `run_lock()`: an exclusive lock on run-dir state shared by every container of a run.
"""

from __future__ import annotations

import contextlib
import csv
import json
import os
import posixpath
import re
import shlex
import shutil
import socket
import tempfile
import threading
import time
from collections.abc import Iterable, Iterator, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple

from fingerprint import normalize_file

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
    # In Frama-C 33+ -report-csv (src/plugins/report/csv.ml), "Partially proven" is
    # Consolidation.Pending ("Locally validated"): 100% of the property's own VCs are Valid,
    # and it only depends on assumed function preconditions, callee contracts, or other
    # properties in the consolidation graph. Properties with >=1 unproven sub-VC are emitted
    # as Consolidation.Unknown ("Unknown").
    "partially_proven": STATUS_VALID,
    "invalid": STATUS_INVALID,
    # Eva's red alarm in Frama-C 33 reports: the property fails whenever its statement is
    # reached, and reachability is not established. Still a candidate needing a witness.
    "invalid_or_unreachable": STATUS_INVALID,
    "invalid_under_hyp": STATUS_INVALID_UNDER_HYP,
    "invalid_under_hypotheses": STATUS_INVALID_UNDER_HYP,
    # "Dead" and "... but dead": the property sits in code that is unreachable under the
    # analysis context. Never a bug, never a proof.
    "dead": STATUS_DEAD,
    "invalid_but_dead": STATUS_DEAD,
    "valid_but_dead": STATUS_DEAD,
    "unknown_but_dead": STATUS_DEAD,
    # Considered valid: an assumption (e.g. a libc or stub specification), not
    # something this run established.
    "considered_valid": STATUS_ASSUMED,
    "never_tried": STATUS_NEVER_TRIED,
    "inconsistent": STATUS_INCONSISTENT,
}

# The formal Frama-C gives a variadic definition's `...`: `f(int n, ...)` is in the model as
# `f(int n, void * const *__va_params)`, with a signature that no longer ends in `...`.
VA_PARAMS = "__va_params"

# A prover's wall-clock budget per profile (docs/guides/v2-design.md Section 9): the brief states it and the
# scheduler enforces it, so both read it here. FRAMAC_PROVER_WALL_BUDGET_S overrides it.
PROVER_WALL_BUDGET_S = {"quick": 600, "standard": 900, "deep": 1800}

# Merged or legacy Eva reports on large modules can exceed the default 64 MiB artifact cap.
DEFAULT_JSON_MAX_BYTES = 64 * 1024 * 1024
EVA_REPORT_MAX_BYTES = 768 * 1024 * 1024
FLOWS_INLINE_MAX_BYTES = 2 * 1024 * 1024
MAX_FLOW_LOCATION_CHARS = 240

# The WP manual (Section "Memory models") calls the `cast` model option "unlimited casts (unsound)":
# a proof under it is a diagnostic, never evidence.
WP_UNSOUND_MODEL_ISSUE = "WP memory model with 'cast' (unlimited casts) is unsound; the proof is not evidence"


def wp_model_parts(model: object) -> frozenset[str]:
    """The lower-cased options of a WP memory model string: `Typed+ref,int` gives {typed, ref, int}."""
    if not isinstance(model, str):
        return frozenset()
    return frozenset(part.strip().lower() for part in model.replace(",", "+").split("+") if part.strip())


def wp_model_unsound(model: object) -> bool:
    """Whether a WP memory model string (for example `Typed+cast`) includes the unsound `cast` option."""
    return "cast" in wp_model_parts(model)


# The WP memory models a proof may be credited under (`frama-c -wp-h`, Frama-C 34). `Typed` is the
# default. `Bytes` is listed there as experimental: accepted, but the proof records it as an
# assumption (wp_model_assumption). `Hoare` has no pointers, `Region` is experimental and depends on
# the region plug-in: neither is evidence. Options: `nocast`, `raw`, `ref`, `int` and `float` keep
# machine semantics; `cast` (unlimited casts), `nat` (integers without overflow) and `real` (floats
# as reals) do not.
WP_MODEL_BASES_ALLOWED = frozenset({"typed", "bytes"})
WP_MODEL_OPTIONS_ALLOWED = frozenset({"nocast", "raw", "ref", "int", "float"})
WP_EXPERIMENTAL_MODEL_ASSUMPTION = (
    "proved under the experimental WP memory model 'Bytes' (low-level, little-endian layout)"
)


def wp_model_problem(model: object) -> str | None:
    """
    Why a proof under this WP memory model is not evidence, or None when the model is accepted.
    No model (None or an empty string) is the default `Typed` and is accepted. Every reader that
    credits or replays a model (the parent merge check, the ledger, the WP runner) asks this.
    """
    parts = wp_model_parts(model)
    if not parts:
        return None
    if "cast" in parts:
        return WP_UNSOUND_MODEL_ISSUE
    rejected = sorted(parts - WP_MODEL_BASES_ALLOWED - WP_MODEL_OPTIONS_ALLOWED)
    if rejected:
        return (
            f"WP memory model {model!r} is not accepted as evidence (not allowed: {', '.join(rejected)}; "
            f"allowed: {', '.join(sorted(WP_MODEL_BASES_ALLOWED))} with "
            f"{', '.join(sorted(WP_MODEL_OPTIONS_ALLOWED))})"
        )
    if len(parts & WP_MODEL_BASES_ALLOWED) > 1:
        return f"WP memory model {model!r} names more than one base model"
    return None


def wp_model_assumption(model: object) -> str | None:
    """The assumption a proof under an accepted, non-default memory model rests on, or None."""
    if wp_model_problem(model) is None and "bytes" in wp_model_parts(model):
        return WP_EXPERIMENTAL_MODEL_ASSUMPTION
    return None


def wp_limits_problem(limits: object) -> str | None:
    """Why the verdict limits of a WP report (run_wp_function.py) do not allow crediting its proof, or None."""
    if not isinstance(limits, dict):
        return "the WP report records no verdict limits"
    vacuity = (limits.get("vacuity") or {}).get("status")
    if vacuity not in ("consistent", "inconclusive"):
        return f"the contract consistency check did not pass (status: {vacuity})"
    return None


# A run directory holds run-metadata.json and coverage-ledger.json at its top, and its overlay root
# (workspace/) holds overlay_meta.json. A directory with one of them is pipeline output that someone
# copied into a target (a results folder kept next to the source), never target source: scanning it
# would add a phantom module and put a previous run's annotated headers on the include path.
PIPELINE_OUTPUT_MARKERS = ("run-metadata.json", "coverage-ledger.json", "overlay_meta.json")


def is_pipeline_output_dir(path: Path | str) -> bool:
    """True when `path` is the top of a pipeline run directory or overlay copied into a target."""
    p = Path(path)
    return any((p / marker).is_file() for marker in PIPELINE_OUTPUT_MARKERS)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def failure_reason(returncode: int | None, timed_out: bool) -> str:
    """Why Frama-C produced no report: wall-clock limit, SIGKILL (the cgroup OOM killer), a signal, or a crash."""
    if timed_out:
        return "timeout"
    if returncode in (-9, 137):
        return "oom_killed"
    if returncode is not None and returncode < 0:
        return f"signal_{-returncode}"
    return "crashed" if returncode else "no_report"


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


def load_json_strict(path: Path, max_bytes: int = DEFAULT_JSON_MAX_BYTES):
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


# Header files: a slice's `sources` may list one (a target that defines functions in its headers, such
# as mpack's MPACK_INLINE, has them mapped to the header), but a compiler never takes one as an input.
HEADER_SUFFIXES = (".h", ".hh", ".hpp", ".hxx", ".h++", ".inc")


def compile_inputs(sources: Iterable[str]) -> list[str]:
    """
    The translation units among a slice's `sources`, for a clang command line: every header left out.
    `clang a.c a.h -o bin` treats the header as a precompiled-header output and fails with "cannot
    specify -o when generating multiple output files" (mpack run-3). Frama-C parses a header as a file
    of its own, and the header stays in `sources` for the tools that read it as data (E-ACSL's function
    discovery, the module scope).
    """
    return [s for s in sources if posixpath.splitext(str(s).replace("\\", "/"))[1].lower() not in HEADER_SUFFIXES]


def load_json_optional(path: Path, default, max_bytes: int = DEFAULT_JSON_MAX_BYTES):
    """Load JSON if present; a present-but-malformed file still raises."""
    path = Path(path)
    if not path.exists():
        return default
    return load_json_strict(path, max_bytes=max_bytes)


def bound_flow_location(loc: str, max_chars: int = MAX_FLOW_LOCATION_CHARS) -> str:
    """
    Bound Frama-C `-deps`/`-inout` location strings before storing or merging them.
    String literals collapse to `<string literal>` and oversized struct bit-range expansions
    are capped while keeping normal C lvalues intact for `function_facts.py`.
    """
    if not isinstance(loc, str):
        return str(loc)
    if loc.startswith('"'):
        return "<string literal>"
    if len(loc) > max_chars:
        return loc[: max_chars - 3] + "..."
    return loc


def _infer_run_root_from_report(report_path: Path | None) -> Path | None:
    if report_path is None:
        return None
    resolved = Path(report_path).resolve()
    parts = list(resolved.parts)
    for idx in range(len(parts) - 1, -1, -1):
        if parts[idx] == "workspace" and idx > 0:
            return Path(*parts[:idx])
    return None


def spill_large_flows(
    report: dict,
    flows_dest: Path,
    report_path: Path | None = None,
    max_bytes: int | None = None,
) -> dict:
    """
    When `report["flows"]` exceeds `max_bytes` serialized, write the full flows payload to
    `flows_dest` (never directly inside `.../reports/eva/`, where `*.json` is scanned as a
    module report) and replace `report["flows"]` with a lightweight `flows_file` pointer dict.
    Returns a shallow copy when spilled so callers holding `report` in memory stay unchanged.
    """
    if not isinstance(report, dict):
        return report
    flows = report.get("flows")
    if not isinstance(flows, dict) or "by_function" not in flows:
        return report
    limit = FLOWS_INLINE_MAX_BYTES if max_bytes is None else max_bytes
    encoded = json.dumps(flows, ensure_ascii=False).encode("utf-8")
    if len(encoded) <= limit:
        return report

    dest = Path(flows_dest)
    dest_resolved = dest.resolve() if dest.is_absolute() else (Path.cwd() / dest).resolve()
    if dest_resolved.parent.as_posix().rstrip("/").endswith("/reports/eva"):
        mod = str(report.get("module") or (Path(report_path).stem if report_path else dest.stem) or "module")
        dest_resolved = dest_resolved.parent.parent / "eva-flows" / f"{mod}.json"

    run_root = _infer_run_root_from_report(report_path) or Path.cwd()
    ref = to_run_relative(dest_resolved, run_root)
    if not flows_ref_is_run_relative(ref):
        # resolve_flows only follows a pointer inside the run directory: keep the flows inline.
        return report
    atomic_write_json(dest_resolved, flows)
    return {
        **report,
        "flows": {
            "status": flows.get("status"),
            "reason": flows.get("reason"),
            "flows_file": ref,
        },
    }


def flows_ref_is_run_relative(ref: object) -> bool:
    """A `flows_file` pointer is a relative POSIX path that stays inside the run directory (no `..`)."""
    if not isinstance(ref, str) or not ref or "\\" in ref:
        return False
    if ref.startswith("/") or re.match(r"^[A-Za-z]:", ref):
        return False
    return all(part not in ("..", "") for part in ref.split("/"))


def resolve_flows(
    flows: object,
    report_path: Path | None = None,
    run_dir: Path | None = None,
    max_bytes: int = EVA_REPORT_MAX_BYTES,
    strict: bool = False,
) -> dict | None:
    """
    Resolve inline `flows` or a spilled `flows_file` pointer back to the full flows dict. The pointer
    must be run-relative (flows_ref_is_run_relative) and is looked up under `run_dir`, the run directory
    the report is in, then the current directory. A pointer that is not run-relative, or a side file that
    is missing, oversized, malformed or not an object, gives a `status: failed` flows dict, or, with
    `strict`, an ArtifactError naming the file.
    """
    if not isinstance(flows, dict):
        return None
    ref = flows.get("flows_file")
    if not isinstance(ref, str) or not ref or "by_function" in flows:
        return flows

    def _failed(reason: str) -> dict:
        if strict:
            raise ArtifactError(reason)
        return {"status": "failed", "reason": reason, "by_function": {}, "call_edges": {}}

    where = f"Eva report {report_path}: " if report_path is not None else ""
    if not flows_ref_is_run_relative(ref):
        return _failed(f"{where}flows_file {ref!r} is not a run-relative path inside the run directory")
    roots: list[Path] = []
    if run_dir is not None:
        roots.append(Path(run_dir))
    inferred_root = _infer_run_root_from_report(report_path)
    if inferred_root is not None:
        roots.append(inferred_root)
    roots.append(Path.cwd())
    for root in roots:
        cand = root / ref
        if cand.is_file():
            try:
                loaded = load_json_strict(cand, max_bytes=max_bytes)
            except ArtifactError as exc:
                return _failed(f"{where}spilled flows file {ref} is unreadable: {exc}")
            if isinstance(loaded, dict):
                return loaded
            return _failed(f"{where}spilled flows file {ref} is not a JSON object")
    return _failed(f"{where}missing spilled flows file: {ref}")


_UNESCAPED_ACSL_IN_JSON_RE = re.compile(
    r"(?<!\\)\\("
    r"valid_read|valid_function|valid|separated|result|old|initialized|at|"
    r"forall|exists|lambda|let|null|true|false|base_addr|block_length|offset|"
    r"allocation|freeable|fresh|subset|empty|union|inter|is_NaN|is_finite|"
    r"tainted|nothing|exact|round_error"
    r")\b"
)
_INVALID_JSON_ESCAPE_RE = re.compile(r"(?<!\\)\\(?![/\"\\bfnrtu])")
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
            rows.append(
                {
                    "directory": _pick(raw, _CSV_ALIASES["directory"]),
                    "file": _pick(raw, _CSV_ALIASES["file"]),
                    "line": line_no,
                    "function": _pick(raw, _CSV_ALIASES["function"]),
                    "kind": _pick(raw, _CSV_ALIASES["kind"]),
                    "status_raw": status_raw,
                    "status": normalize_status(status_raw),
                    "property": _pick(raw, _CSV_ALIASES["property"]),
                }
            )
    return rows


def eva_alarm_in_file(alarm: dict, unit_file: str) -> bool:
    """
    Match an Eva report row's (directory, file) against a repository-relative `unit_file`
    so same-named `static` functions in different `.c` files of a slice do not collide.
    Rows without a `file` field match unconditionally (for legacy/synthetic fixtures).
    """
    raw_file = (alarm.get("file") or "").replace("\\", "/").strip()
    while raw_file.startswith("./"):
        raw_file = raw_file[2:]
    if not raw_file:
        return True
    raw_dir = (alarm.get("directory") or "").replace("\\", "/").strip().rstrip("/")
    while raw_dir.startswith("./"):
        raw_dir = raw_dir[2:]
    joined = f"{raw_dir}/{raw_file}" if raw_dir and raw_dir != "." and not raw_file.startswith("/") else raw_file
    u = (unit_file or "").replace("\\", "/").strip()
    while u.startswith("./"):
        u = u[2:]
    if not u:
        return True
    return normalize_file(joined) == normalize_file(u)


def normalize_flag_args(
    argv: Sequence[str],
    options: Iterable[str] = ("--cppflags", "--ldflags"),
) -> list[str]:
    """
    Bind flag-valued options (`--cppflags -I.`, `--ldflags -lm`, `--fuzz-dict -x`) with `=`
    so `argparse` does not treat a leading `-` in their value as another option.
    """
    opt_set = frozenset(options)
    out: list[str] = []
    i = 0
    n = len(argv)
    while i < n:
        tok = argv[i]
        if tok == "--":
            out.extend(argv[i:])
            break
        if tok in opt_set and i + 1 < n:
            next_tok = argv[i + 1]
            if next_tok.startswith("--"):
                out.append(tok)
                i += 1
            else:
                out.append(f"{tok}={next_tok}")
                i += 2
        else:
            out.append(tok)
            i += 1
    return out


_WINDOWS_DEVICE = re.compile(r"^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$", re.IGNORECASE)


def is_safe_relative_path(value: str) -> bool:
    """True for a non-empty, forward-slash, relative path without traversal."""
    if not isinstance(value, str) or not value or value != value.strip():
        return False
    if "\\" in value or "\x00" in value or value.startswith("/") or re.match(r"^[A-Za-z]:", value):
        return False
    parts = value.split("/")
    for part in parts:
        if part in ("", ".", ".."):
            return False
    return True


AGENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def is_safe_agent_id(value: str) -> bool:
    # fullmatch: `$` also matches before a trailing newline, which must never reach a path.
    return isinstance(value, str) and bool(AGENT_ID_RE.fullmatch(value)) and not _WINDOWS_DEVICE.match(value)


def to_run_relative(path: Path, run_dir: Path) -> str:
    """Express a path relative to the run directory using forward slashes."""
    p = Path(path)
    if not p.is_absolute():
        p = Path.cwd() / p
    try:
        return p.resolve().relative_to(Path(run_dir).resolve()).as_posix()
    except ValueError:
        return Path(path).as_posix()


# ---------------------------------------------------------------------------
# Preprocessor flags for a scratch copy of the source tree
# ---------------------------------------------------------------------------

_INCLUDE_DIR_OPTIONS = ("-I", "-iquote", "-isystem", "-idirafter")
_FORCE_INCLUDE_OPTIONS = ("-include", "-imacros")
_ABSOLUTE_PATH_RE = re.compile(r"^(?:/|[A-Za-z]:/)")
_TREE_TAIL_RE = re.compile(r"^(?:workspace/work|agents/[^/]+/scratch/work)/(.+)$")
_SHELL_WORD_RE = re.compile(r"""(?:[^\s"'\\]|\\.|'[^']*'|"(?:[^"\\]|\\.)*")+""", re.DOTALL)


def source_tree_relpath(path: str, run_dir: Path, work_dir: Path) -> str | None:
    """
    `path` relative to the source tree it is in: `work_dir`, the shared `workspace/work`, any agent's
    `scratch/work`, or `/target`. None when it is outside them (`workspace/stubs`, libc, tool headers).
    A relative path is read from the run directory, where the pipeline's commands run.
    """
    run_posix = Path(run_dir).as_posix().rstrip("/")
    work_posix = Path(work_dir).as_posix().rstrip("/")
    norm = path.replace("\\", "/")
    if not _ABSOLUTE_PATH_RE.match(norm):
        norm = f"{run_posix}/{norm}"
    norm = posixpath.normpath(norm)
    if norm.startswith(f"{work_posix}/"):
        return norm[len(work_posix) + 1 :]
    for root in (run_posix, "/framac-run"):
        if norm.startswith(f"{root}/"):
            m = _TREE_TAIL_RE.match(norm[len(root) + 1 :])
            if m:
                return m.group(1)
    if norm.startswith("/target/"):
        return norm[len("/target/") :]
    return None


def scratch_first_flags(flags: list[str], run_dir: Path, work_dir: Path) -> list[str]:
    """
    Preprocessor flags for tools that run on the scratch copy `work_dir`, so that what an agent
    wrote in its scratch headers is what they read:

    - An include directory of a source tree gets its twin in `work_dir` just before it, with the same
      option: the search order goes by option (`-iquote` comes before every `-I`). Both copies hold
      the same files, so the same directory wins as with the original flags, only in `work_dir`.
    - A `-include` or `-imacros` file under a source tree is replaced by its twin. Adding the twin
      would read both copies, and the first one's include guard would hide the other.

    Everything else keeps its place and spelling. A path with no twin in `work_dir` stays as it is.
    """
    run_dir = Path(run_dir)
    work_dir = Path(work_dir)
    out: list[str] = []
    seen: set[str] = set()
    i = 0
    while i < len(flags):
        word = flags[i]
        option = next((o for o in (*_INCLUDE_DIR_OPTIONS, *_FORCE_INCLUDE_OPTIONS) if word.startswith(o)), None)
        joined = option is not None and len(word) > len(option)
        if option is None or (not joined and i + 1 >= len(flags)):
            out.append(word)
            i += 1
            continue
        path = word[len(option) :] if joined else flags[i + 1]
        spelled = flags[i : i + (1 if joined else 2)]
        i += len(spelled)
        if option in _FORCE_INCLUDE_OPTIONS:
            rel = source_tree_relpath(path, run_dir, work_dir)
            twin = work_dir / rel if rel is not None else None
            if twin is None or not twin.is_file():
                out.extend(spelled)
            else:
                twin_arg = to_run_relative(twin, run_dir)
                out.extend([f"{option}{twin_arg}"] if joined else [option, twin_arg])
            continue
        # The `/_` keeps a flag naming the root of a tree inside that tree.
        rel = source_tree_relpath(f"{path.rstrip('/')}/_", run_dir, work_dir)
        twin = work_dir / rel[:-1] if rel is not None else None
        if twin is not None and twin.is_dir():
            twin_arg = to_run_relative(twin, run_dir)
            twin_flag = f"{option}{twin_arg}"
            if twin_flag not in seen and posixpath.normpath(path) != posixpath.normpath(twin_arg):
                out.append(twin_flag)
            seen.add(twin_flag)
        out.extend(spelled)
    return out


def scratch_first_cppflags(cppflags: str, run_dir: Path, work_dir: Path) -> str:
    """
    `scratch_first_flags` for a flag string that goes into a shell command. Words it keeps stay as
    written, because a brief embeds the string in single quotes: re-quoting `-DNAME=\\"x\\"` would
    change what it means there. A string whose quoting does not parse stays as it is.
    """
    try:
        tokens = shlex.split(cppflags)
    except ValueError:
        return cppflags
    words = _SHELL_WORD_RE.findall(cppflags)
    if len(words) != len(tokens):
        return cppflags
    written = dict(zip(tokens, words, strict=True))

    def spell(token: str) -> str:
        if token in written:
            return written[token]
        return token if shlex.quote(token) == token else '"' + re.sub(r'(["\\$`])', r"\\\1", token) + '"'

    return " ".join(spell(token) for token in scratch_first_flags(tokens, run_dir, work_dir))


def resolve_fc_stubs_dir() -> Path | None:
    """Locate the pipeline's templates/fc_stubs directory (container or local checkout)."""
    container_dir = Path("/opt/framac-pipeline/templates/fc_stubs")
    if container_dir.is_dir():
        return container_dir
    local_dir = Path(__file__).resolve().parent.parent / "templates" / "fc_stubs"
    if local_dir.is_dir():
        if os.name == "nt" and " " in str(local_dir):
            try:
                import ctypes

                parts = list(local_dir.parts)
                buf = ctypes.create_unicode_buffer(500)
                short_parts: list[str] = [parts[0]]
                cur = parts[0]
                for part in parts[1:]:
                    cur = os.path.join(cur, part)
                    if " " in part:
                        ctypes.windll.kernel32.GetShortPathNameW(cur, buf, 500)
                        part = Path(buf.value).name
                    short_parts.append(part)
                return Path(*short_parts)
            except Exception:
                pass
        return local_dir
    return None


def framac_cpp_wrapper(path: Path | None = None) -> str | None:
    """
    scripts/fc_cpp_wrapper.py (or `path`) as a gcc `-wrapper` program for Frama-C's preprocessor, or None
    where gcc could not run it (not POSIX, not executable, or a path `-wrapper` and e-acsl-gcc would split).
    """
    path = path or Path(__file__).resolve().parent / "fc_cpp_wrapper.py"
    text = path.as_posix()
    if os.name != "posix" or not os.access(path, os.X_OK) or any(c.isspace() or c == "," for c in text):
        return None
    return text


# The run's stub overlay (docs/plans/templates-and-stubs-improvement-plan.md S2, scripts/stub_gen.py): contracts for
# external functions only a host header declares, one header per included library header. It is searched
# before templates/fc_stubs, so the pipeline's own templates are never edited for one target.
STUB_OVERLAY_REL = "workspace/stubs"
CONTAINER_STUB_OVERLAY_DIR = f"/framac-run/{STUB_OVERLAY_REL}"
STUB_REPORT_REL = "workspace/reports/stubs.json"


def stub_overlay_dir() -> Path | None:
    """The run's stub overlay: FRAMAC_STUB_OVERLAY_DIR (tests, host runs), else the run mount's; None when absent."""
    d = Path(os.environ.get("FRAMAC_STUB_OVERLAY_DIR") or CONTAINER_STUB_OVERLAY_DIR)
    return d if d.is_dir() else None


def stub_header_for(function: str, report: Path | None = None) -> str | None:
    """The overlay header holding `function`'s stub (workspace/reports/stubs.json, from the cwd), or None."""
    data = load_json_optional(report or Path(STUB_REPORT_REL), {})
    if not isinstance(data, dict):
        return None
    for header, rec in sorted((data.get("headers") or {}).items()):
        if isinstance(rec, dict) and function in (rec.get("functions") or {}):
            return str(header)
    return None


def stub_repair_action(function: str) -> str:
    """Where a missing contract of an external `function` goes: its overlay header (S2)."""
    header = stub_header_for(function)
    if header:
        return (
            f"fill {function!r}'s contract in {header} (the stub-author brief: `stub_gen.py brief --header {header}`), "
            "then `pipeline_make.py run stubs stub-check`"
        )
    return (
        f"give {function!r} a contract in {STUB_OVERLAY_REL}/<lib>.h, the run's stub overlay: "
        "`pipeline_make.py run stubs` writes the skeleton for every external a host header declares "
        "(a prototype in a project header takes its contract in the work tree instead)"
    )


# The language standards older than C99 (`-ansi` is `-std=c90` for C). Harness code is ours and C99, and
# Frama-C prints C99 (`restrict` in glibc prototypes), so no harness or E-ACSL compile may use them.
PRE_C99_STD_FLAGS = frozenset(
    {
        "-ansi",
        "-std=c89",
        "-std=c90",
        "-std=gnu89",
        "-std=gnu90",
        "-std=iso9899:1990",
        "-std=iso9899:199409",
    }
)


def is_pre_c99_std(flag: str) -> bool:
    """True for a compiler flag that selects a C standard older than C99 (`-std=gnu90`, `-ansi`)."""
    return flag in PRE_C99_STD_FLAGS


def augment_framac_cppflags(cppflags: str) -> str:
    """
    Prepend the run's stub overlay (`-I<workspace/stubs>`, when it exists), then
    `-I<fc_stubs>` and `-include <fc_compat_types.h>` for Frama-C `-nostdinc` runs
    (Eva and WP) so third-party headers (`bsd/string.h`, `json-c/json.h`, `netinet/ip_icmp.h`)
    and glibc internal integer typedefs (`__int32_t`, etc.) resolve cleanly without
    shadowing `__fc_libc`, ensuring stubs and compatibility headers precede target headers.
    The build's generated headers (`config.h`) and the target's system headers come last, in that order,
    from the run's snapshot (scripts/target_env.py), then the image's own system directories for the
    headers Frama-C's libc lacks (`elf.h`, `linux/*`). Last, `-wrapper` runs gcc's preprocessor under
    scripts/fc_cpp_wrapper.py, which repairs `offsetof` with a non-constant index (`framac_cpp_wrapper`).
    """
    from target_env import with_include_flags

    base = with_include_flags((cppflags or "-I.").strip())
    overlay = stub_overlay_dir()
    overlay_flag = [f"-I{overlay.as_posix()}"] if overlay is not None and f"-I{overlay.as_posix()}" not in base else []
    fc_stubs = resolve_fc_stubs_dir()
    if fc_stubs is None:
        return " ".join([*overlay_flag, base]) if base else " ".join(overlay_flag)
    stubs_posix = fc_stubs.as_posix()
    compat_hdr = (fc_stubs / "fc_compat_types.h").as_posix()
    prefix: list[str] = list(overlay_flag)
    if f"-I{stubs_posix}" not in base:
        prefix.append(f"-I{stubs_posix}")
    if "fc_compat_types.h" not in base and (fc_stubs / "fc_compat_types.h").is_file():
        prefix.append(f"-include {compat_hdr}")
    if base:
        prefix.append(base)
    for d in ("/usr/include/x86_64-linux-gnu", "/usr/include"):
        if os.path.isdir(d) and f"-idirafter {d}" not in base and f"-idirafter {d}" not in prefix:
            prefix.append(f"-idirafter {d}")
    wrapper = framac_cpp_wrapper()
    if wrapper and "-wrapper" not in base.split():
        prefix.append(f"-wrapper {wrapper}")
    return " ".join(prefix)


# ---------------------------------------------------------------------------
# Run-dir locks
# ---------------------------------------------------------------------------
#
# The run directory is shared by every container of a run (one per wrapper call), so a
# lock must work across PID namespaces and on bind mounts where flock is unreliable
# (NFS, 9p, virtiofs, Docker Desktop). A lock is a directory created with an atomic
# mkdir; its owner refreshes `owner.json` as a heartbeat, and a lock whose heartbeat is
# older than `stale_after` belongs to a dead holder and is broken. Locks are reentrant
# within one process.

LOCKS_DIR = ".framac-locks"


class RunLockTimeout(RuntimeError):
    """Another holder kept the run lock longer than the caller was willing to wait."""


_held_locks: dict[str, int] = {}
_held_guard = threading.Lock()


def _env_seconds(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "") or default)
    except ValueError:
        return default


def _lock_age(lock_dir: Path) -> float | None:
    for probe in (lock_dir / "owner.json", lock_dir):
        try:
            return time.time() - probe.stat().st_mtime
        except OSError:
            continue
    return None


def _break_stale_lock(lock_dir: Path) -> None:
    tomb = lock_dir.with_name(f"{lock_dir.name}.stale-{os.getpid()}-{time.time_ns()}")
    try:
        os.replace(lock_dir, tomb)
    except OSError:
        return
    shutil.rmtree(tomb, ignore_errors=True)


# How long a Windows pending-delete directory may keep failing mkdir before we give up. A
# directory another holder is removing lingers in that state until its last handle closes:
# mkdir on it (or inside it) fails with FileExistsError or PermissionError instead of
# FileNotFoundError, and pathlib's exist_ok re-raises because is_dir() is already false.
_TRANSIENT_FS_WINDOW = 5.0


def _ensure_lock_parent(parent: Path) -> None:
    """Create `parent`, riding out a concurrent release that is removing it right now."""
    give_up = time.monotonic() + _TRANSIENT_FS_WINDOW
    while True:
        try:
            parent.mkdir(parents=True, exist_ok=True)
            return
        except (FileExistsError, PermissionError):
            if time.monotonic() >= give_up:
                raise
            time.sleep(0.01)


@contextlib.contextmanager
def run_lock(
    name: str = "ledger",
    run_dir: Path | None = None,
    timeout: float | None = None,
    stale_after: float | None = None,
) -> Iterator[Path]:
    """
    Hold the run-wide lock `name` (`ledger` guards coverage-ledger.json, candidates.json,
    findings.json, strengthen_requests.json and the WP schedule; `merge` guards writes to
    workspace/work/). Waits up to `timeout` seconds (FRAMAC_LOCK_TIMEOUT, default 1800).
    """
    lock_dir = (Path(run_dir) if run_dir is not None else Path.cwd()) / LOCKS_DIR / f"{name}.lock"
    key = str(lock_dir.resolve())
    with _held_guard:
        depth = _held_locks.get(key, 0)
        if depth:
            _held_locks[key] = depth + 1
    if depth:
        try:
            yield lock_dir
        finally:
            with _held_guard:
                _held_locks[key] -= 1
        return

    wait_limit = timeout if timeout is not None else _env_seconds("FRAMAC_LOCK_TIMEOUT", 1800.0)
    stale = stale_after if stale_after is not None else _env_seconds("FRAMAC_LOCK_STALE", 120.0)
    _ensure_lock_parent(lock_dir.parent)
    deadline = time.monotonic() + wait_limit
    delay = 0.02
    denied_since: float | None = None
    while True:
        try:
            os.mkdir(lock_dir)
            break
        except FileNotFoundError:
            # A releasing holder removed the empty .framac-locks/ parent between our calls.
            denied_since = None
            _ensure_lock_parent(lock_dir.parent)
            continue
        except PermissionError:
            # Windows: lock_dir or its parent is pending delete by a releasing holder.
            now = time.monotonic()
            denied_since = denied_since if denied_since is not None else now
            if now - denied_since >= _TRANSIENT_FS_WINDOW:
                raise
            time.sleep(0.01)
            continue
        except FileExistsError:
            denied_since = None
            age = _lock_age(lock_dir)
            if age is not None and age > stale:
                _break_stale_lock(lock_dir)
                continue
            if time.monotonic() >= deadline:
                owner = load_json_optional(lock_dir / "owner.json", {}) if (lock_dir / "owner.json").is_file() else {}
                raise RunLockTimeout(
                    f"run lock {lock_dir} still held after {wait_limit:.0f}s by {owner or 'an unknown holder'}"
                ) from None
            time.sleep(delay)
            delay = min(delay * 2, 0.5)

    owner_file = lock_dir / "owner.json"
    owner_file.write_text(
        json.dumps({"pid": os.getpid(), "host": socket.gethostname(), "acquired_at": utc_now()}) + "\n",
        encoding="utf-8",
    )
    stop = threading.Event()

    def _heartbeat() -> None:
        interval = max(1.0, min(15.0, stale / 4))
        while not stop.wait(interval):
            try:
                os.utime(owner_file)
            except OSError:
                return

    beat = threading.Thread(target=_heartbeat, name=f"run-lock-{name}", daemon=True)
    beat.start()
    with _held_guard:
        _held_locks[key] = 1
    try:
        yield lock_dir
    finally:
        with _held_guard:
            _held_locks.pop(key, None)
        stop.set()
        beat.join(timeout=5)
        shutil.rmtree(lock_dir, ignore_errors=True)
        try:
            lock_dir.parent.rmdir()  # leave no empty .framac-locks/ behind
        except OSError:
            pass


# Frama-C: "Calling undeclared function X. Old style K&R code?" (it then invents `int X()`,
# which is unsound for Eva/WP). Clang: "call to undeclared function 'X'" /
# "implicit declaration of function 'X'". GCC quotes the name with U+2018/U+2019 under a UTF-8
# locale and with ASCII quotes under LANG=C, so both are accepted.
_QUOTE_OPEN = "['`\\u2018]"
_QUOTE_CLOSE = "['\\u2019]"
_UNDECLARED_FN_RES = (
    re.compile(rf"Calling undeclared function\s+{_QUOTE_OPEN}?(?P<fn>[A-Za-z_]\w*){_QUOTE_CLOSE}?"),
    re.compile(rf"call to undeclared (?:library )?function {_QUOTE_OPEN}(?P<fn>[A-Za-z_]\w*){_QUOTE_CLOSE}"),
    re.compile(rf"implicit declaration of function {_QUOTE_OPEN}(?P<fn>[A-Za-z_]\w*){_QUOTE_CLOSE}"),
)


def scan_undeclared_functions(log_text: str) -> list[str]:
    """Functions called without a prototype (missing stub/header declaration), sorted and unique."""
    found: set[str] = set()
    for rx in _UNDECLARED_FN_RES:
        for m in rx.finditer(log_text or ""):
            found.add(m.group("fn"))
    return sorted(found)


# ---------------------------------------------------------------------------
# Frama-C log messages
# ---------------------------------------------------------------------------
#
# Frama-C wraps a message at about 80 columns, and breaks right after the kind when the text does
# not fit on the head line (captured on Frama-C 35, framac-analysis image, 2026-11-11):
#
#   [wp] a2.c:34: Warning: Missing assigns clause (assigns 'everything' instead)
#   [wp] macro_test.c:3: Warning:
#     Missing assigns clause (assigns 'everything' instead)
#   [kernel:annot:missing-spec] a1.c:15: Warning:
#     Neither code nor explicit exits, assigns and terminates for function
#     only_ensures, generating default clauses.
#
# A pattern applied to one line therefore sees the location or the text, never both, and a name can
# sit on the line after the words that introduce it. Every reader of such messages goes through
# fold_messages().

_FC_HEAD_RE = re.compile(r"^\[(?P<plugin>[A-Za-z][\w-]*)(?::(?P<category>[^\]]*))?\]\s*(?P<rest>.*)$")
_FC_LOCATION_RE = re.compile(r"^(?P<file>\S+?):(?P<line>\d+):(?:\d+:)?\s*(?P<rest>.*)$")
_FC_KIND_RE = re.compile(
    r"^(?P<kind>warning|user error|failure|fatal error|internal error|error)\s*:\s*(?P<rest>.*)$", re.IGNORECASE
)
_CPP_ERROR_RE = re.compile(r"^\S+\.[ch]:\d+(?::\d+)?:\s*(?:fatal )?error:", re.IGNORECASE)
_KERNEL_ERROR_HINT_RE = re.compile(
    r"user error|syntax error|annot-error|failure|fatal error|error:|unbound|invalid", re.IGNORECASE
)


class FcMessage(NamedTuple):
    """One message of a Frama-C log, with its indented continuation lines folded in."""

    plugin: str  # `kernel`, `wp`, `eva`...; `cpp` for a compiler diagnostic; "" for any other line
    file: str  # "" when the message carries no location
    line: int  # 0 when the message carries no location
    kind: str  # `Warning`, `User Error`, `Failure`... or ""
    text: str  # the message after its kind, on one line
    category: str = ""  # `annot:missing-spec` of `[kernel:annot:missing-spec]`
    folded: str = ""  # the whole message on one line, head included


def fold_messages(log_text: str | None) -> list[FcMessage]:
    """
    The messages of a Frama-C log, in order. A message starts at a `[plugin]` head, at a compiler
    diagnostic (`f.c:3:1: error: ...`) or at any other unindented line, and takes the indented
    lines that follow it. No non-blank line is dropped: a line that belongs to no plug-in message
    is a message with an empty `plugin`, so that a reader can tell it from Frama-C's own output.
    """
    blocks: list[tuple[str, str, list[str]]] = []
    for raw in (log_text or "").splitlines():
        if not raw.strip():
            continue
        head = _FC_HEAD_RE.match(raw)
        if head:
            blocks.append((head.group("plugin"), head.group("category") or "", [head.group("rest").strip()]))
        elif blocks and raw[:1].isspace():
            blocks[-1][2].append(raw.strip())
        else:
            blocks.append(("cpp" if _CPP_ERROR_RE.match(raw) else "", "", [raw.strip()]))
    messages: list[FcMessage] = []
    for plugin, category, lines in blocks:
        rest = lines[0]
        file, line_no, kind = "", 0, ""
        location = _FC_LOCATION_RE.match(rest)
        if location:
            file, line_no, rest = location.group("file"), int(location.group("line")), location.group("rest")
        kind_m = _FC_KIND_RE.match(rest)
        if kind_m:
            kind, rest = kind_m.group("kind").title(), kind_m.group("rest")
        text = " ".join(part for part in [rest.strip(), *lines[1:]] if part)
        tag = f"[{plugin}:{category}]" if category else f"[{plugin}]"
        whole = [tag, *lines] if plugin not in ("", "cpp") else lines
        folded = " ".join(part for part in whole if part)
        messages.append(FcMessage(plugin, file, line_no, kind, text, category, folded))
    return messages


def kernel_parse_errors(log_text: str | None) -> list[str]:
    """
    Kernel-phase errors of a Frama-C log (preprocessing, C syntax, ACSL parsing and typing),
    one string per message with its indented continuation lines folded in, e.g.
    `[kernel:annot-error] f.c:1: Failure: unbound logic variable alse. ...`.
    """
    return [
        m.folded
        for m in fold_messages(log_text)
        if m.plugin in ("kernel", "cpp")
        and _KERNEL_ERROR_HINT_RE.search(m.folded)
        and "Frama-C aborted" not in m.folded
    ]


# The kernel's message for a called function without a body (`[kernel:annot:missing-spec]`). The
# words between `nor` and `for function` say what it had to invent, as captured on Frama-C 35:
#   Neither code nor specification for function f, generating default exits, assigns and terminates.
#   Neither code nor explicit exits and terminates for function f, generating default clauses.
#   Neither code nor explicit exits, assigns and terminates for function f, ...
#   Neither code nor explicit assigns for function f, ...          (and `exits`, `terminates` alone)
# Only invented `exits` and `terminates` clauses are harmless: an invented `assigns` (no write to a
# global) is a frame the caller's proof or analysis then rests on.
_MISSING_SPEC_RE = re.compile(r"Neither code nor (?P<what>.+?) for function (?P<fn>[A-Za-z_]\w*)")
_MISSING_SPEC_PREFIX = "Neither code nor "
_BENIGN_GENERATED_CLAUSES = frozenset({"exits", "terminates"})


class MissingSpec(NamedTuple):
    function: str  # "" when the message could not be read
    missing: tuple[str, ...]  # (`specification`,), the clause names, or () for a wording not recognised
    message: str

    @property
    def benign(self) -> bool:
        """Only `exits` / `terminates` were generated. An unrecognised wording is never benign."""
        return bool(self.missing) and set(self.missing) <= _BENIGN_GENERATED_CLAUSES


def parse_missing_spec(message: str) -> list[MissingSpec]:
    """The `Neither code nor ...` statements of one folded message (see fold_messages)."""
    found: list[MissingSpec] = []
    for m in _MISSING_SPEC_RE.finditer(message):
        what = " ".join(m.group("what").split())
        if what == "specification":
            missing: tuple[str, ...] = ("specification",)
        elif what.startswith("explicit "):
            parts = re.split(r"\s*,\s*|\s+and\s+", what[len("explicit ") :])
            missing = tuple(part.strip() for part in parts if part.strip())
        else:
            missing = ()
        found.append(MissingSpec(m.group("fn"), missing, message))
    if not found and _MISSING_SPEC_PREFIX in message:
        found.append(MissingSpec("", (), message))
    return found


def missing_spec_messages(log_text: str | None) -> list[MissingSpec]:
    """Every `Neither code nor ...` statement Frama-C printed in a log, harmless ones included."""
    return [spec for m in fold_messages(log_text) if m.plugin != "" for spec in parse_missing_spec(m.folded)]
