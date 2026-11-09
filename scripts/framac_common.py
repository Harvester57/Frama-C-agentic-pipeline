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


# A prover's wall-clock budget per profile (docs/v2-design.md Section 9): the brief states it and the
# scheduler enforces it, so both read it here. FRAMAC_PROVER_WALL_BUDGET_S overrides it.
PROVER_WALL_BUDGET_S = {"quick": 600, "standard": 900, "deep": 1800}

# The WP manual (Section "Memory models") calls the `cast` model option "unlimited casts (unsound)":
# a proof under it is a diagnostic, never evidence.
WP_UNSOUND_MODEL_ISSUE = "WP memory model with 'cast' (unlimited casts) is unsound; the proof is not evidence"


def wp_model_unsound(model: object) -> bool:
    """Whether a WP memory model string (for example `Typed+cast`) includes the unsound `cast` option."""
    if not isinstance(model, str):
        return False
    return "cast" in {m.strip().lower() for m in re.split(r"[+,]", model) if m.strip()}


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
    return isinstance(value, str) and bool(AGENT_ID_RE.match(value)) and not _WINDOWS_DEVICE.match(value)


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


def augment_framac_cppflags(cppflags: str) -> str:
    """
    Prepend `-I<fc_stubs>` and `-include <fc_compat_types.h>` for Frama-C `-nostdinc` runs
    (Eva and WP) so third-party headers (`bsd/string.h`, `json-c/json.h`, `netinet/ip_icmp.h`)
    and glibc internal integer typedefs (`__int32_t`, etc.) resolve cleanly without
    shadowing `__fc_libc`, ensuring stubs and compatibility headers precede target headers.
    The build's generated headers (`config.h`) and the target's system headers come last, in that order,
    from the run's snapshot (scripts/target_env.py).
    """
    from target_env import with_include_flags

    base = with_include_flags((cppflags or "-I.").strip())
    fc_stubs = resolve_fc_stubs_dir()
    if fc_stubs is None:
        return base
    stubs_posix = fc_stubs.as_posix()
    compat_hdr = (fc_stubs / "fc_compat_types.h").as_posix()
    prefix: list[str] = []
    if f"-I{stubs_posix}" not in base:
        prefix.append(f"-I{stubs_posix}")
    if "fc_compat_types.h" not in base and (fc_stubs / "fc_compat_types.h").is_file():
        prefix.append(f"-include {compat_hdr}")
    if base:
        prefix.append(base)
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
