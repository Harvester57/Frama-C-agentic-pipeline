#!/usr/bin/env python3
"""
Content-addressed caches for the Frama-C pipeline (stdlib only).

Stores:
  run     <run>/state/cache/<ns>/<key[:2]>/<key>/{meta.json, key.json, files/<name>}
  shared  $FRAMAC_SHARED_CACHE_DIR (default /framac-cache when it exists), same layout. Looked up
          after the run store when FRAMAC_CACHE_MODE is `ro` or `rw`; written only with `rw`.
Namespaces: `eacsl-build` (E-ACSL and sanitizer builds), `eva` (Eva reports), `facts` (per-function
prover facts), `slice-index` (parsed translation units for reading slices), `guardrail` (run-local
dynamic oracle verdicts) and `wp`, which is Frama-C's own `-wp-cache-dir` (counted and collected
here, never read or written by this module).

Enablement: FRAMAC_CACHE=off disables every cache. Otherwise caches are on when the working
directory is a run directory (it holds run-metadata.json) or FRAMAC_CACHE=on, so unit tests and
ad-hoc runs outside a run never read or write one.

Keys hash CACHE_SCHEMA_VERSION, the toolchain identity (FRAMAC_IMAGE_ID, else a memoized tuple of
tool versions), a digest of scripts/ and templates/ (bind-mounted, so the image ID does not cover
them), the effective flags, output paths and cwd, and a dependency manifest: the union of the
include sets `gcc -M -MG` (with Frama-C-like defines) and `clang -M -MG` report for the effective
preprocessor flags, each file content-hashed. A build whose manifest cannot be computed is never
cached.

Entries are published atomically (temp dir + os.replace), builds of one key are single-flight
(a thread lock plus the cross-container run lock), and least-recently-used entries are collected
once a store exceeds min(FRAMAC_CACHE_MAX, default 20 GiB; 25 % of the free disk).

CLI: cache.py stats|gc|clear [--ns NS] [--root DIR | --shared]
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from acsl_ast import AcslSyntaxError, Token, tokenize_c_acsl  # noqa: E402
from build_callgraph_dag import C_KEYWORDS  # noqa: E402
from framac_common import RunLockTimeout, run_lock, utc_now  # noqa: E402

CACHE_SCHEMA_VERSION = 1
DEFAULT_MAX_BYTES = 20 * 1024**3
DISK_FRACTION = 0.25
GC_INTERVAL_S = 600
DEPS_TIMEOUT_S = 120
SHARED_DEFAULT_DIR = Path("/framac-cache")
# Frama-C preprocesses with these defined; headers guarded by them belong in the manifest.
FRAMAC_DEP_DEFINES = ("-D__FRAMAC__", "-D__FC_MACHDEP_X86_64")
NAMESPACES = ("eacsl-build", "eva", "facts", "slice-index", "guardrail", "wp")
CORPUS_MAX_FILES = 256
CORPUS_MAX_FILE_BYTES = 64 * 1024
CORPUS_MAX_TOTAL_BYTES = 4 * 1024 * 1024

_SCRIPTS_DIR = Path(__file__).resolve().parent
_TEMPLATES_DIR = _SCRIPTS_DIR.parent / "templates"
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_KEY_RE = re.compile(r"^[0-9a-f]{64}$")
_LINE_DIRECTIVE_RE = re.compile(r'^\s*#\s*(?:line\s+)?(\d+)(?:\s+"([^"]*)")?')
_ACSL_BLOCK_RE = re.compile(r"/\*@.*?\*/|//@[^\n]*", re.DOTALL)
_GLOBAL_ACSL_DECL_RE = re.compile(r"\b(?:predicate|logic|axiomatic|lemma|inductive|type|ghost|model)\b")
_FN_DECL_NAME_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_OFF = ("off", "0", "false", "no", "disabled")
_ON = ("on", "1", "true", "yes", "enabled")


# ---------------------------------------------------------------------------
# Enablement and store locations
# ---------------------------------------------------------------------------


def _env(name: str) -> str:
    return (os.environ.get(name) or "").strip().lower()


def forced_off() -> bool:
    """FRAMAC_CACHE=off: no cache at all, even an explicitly named one (A/B comparisons)."""
    return _env("FRAMAC_CACHE") in _OFF


def enabled(cwd: Path | None = None) -> bool:
    mode = _env("FRAMAC_CACHE")
    if mode in _OFF:
        return False
    if mode in _ON:
        return True
    return (Path(cwd) if cwd else Path.cwd()).joinpath("run-metadata.json").is_file()


def run_cache_root(cwd: Path | None = None) -> Path:
    return (Path(cwd) if cwd else Path.cwd()) / "state" / "cache"


def shared_mode() -> str:
    """`ro` or `rw` from FRAMAC_CACHE_MODE; anything else means the shared store is not used."""
    mode = _env("FRAMAC_CACHE_MODE")
    return mode if mode in ("ro", "rw") else "off"


def shared_cache_root() -> Path | None:
    if shared_mode() == "off":
        return None
    raw = (os.environ.get("FRAMAC_SHARED_CACHE_DIR") or "").strip()
    if raw.lower() in _OFF:
        return None
    root = Path(raw) if raw else SHARED_DEFAULT_DIR
    return root if root.is_dir() else None


def wp_cache_dir(cwd: Path | None = None) -> Path | None:
    """Frama-C's `-wp-cache-dir` for this run (`<run>/state/cache/wp`), or None when caching is off."""
    if not enabled(cwd):
        return None
    path = run_cache_root(cwd) / "wp"
    path.mkdir(parents=True, exist_ok=True)
    return path


def shared_corpus_dir(module: str) -> Path | None:
    """`<shared_cache_root>/corpora/<module>` when the shared cache is active and `module` is a safe name."""
    if forced_off() or not module or not _NAME_RE.match(module):
        return None
    root = shared_cache_root()
    if root is None:
        return None
    return root / "corpora" / module


def _scan_corpus_candidates(dir_path: Path, max_file_bytes: int) -> list[tuple[int, str, Path]]:
    """Return (size, name, path) for valid non-empty files <= max_file_bytes in dir_path."""
    candidates: list[tuple[int, str, Path]] = []
    if not dir_path.is_dir():
        return candidates
    for p in dir_path.iterdir():
        if not p.is_file() or p.is_symlink() or p.name.startswith("."):
            continue
        with contextlib.suppress(OSError):
            size = p.stat().st_size
            if 0 < size <= max_file_bytes:
                candidates.append((size, p.name, p))
    return candidates


def warm_start_corpus(
    module: str,
    corpus_dir: Path,
    *,
    max_files: int = CORPUS_MAX_FILES,
    max_bytes: int = CORPUS_MAX_TOTAL_BYTES,
) -> int:
    """
    Seed `corpus_dir` from `$FRAMAC_SHARED_CACHE_DIR/corpora/<module>` when shared caching (`ro` or `rw`)
    is enabled. Existing corpus inputs are never overwritten or duplicated. Returns the count of copied files.
    """
    if not enabled():
        return 0
    src_dir = shared_corpus_dir(module)
    if src_dir is None or not src_dir.is_dir():
        return 0
    corpus_dir = Path(corpus_dir)
    corpus_dir.mkdir(parents=True, exist_ok=True)
    existing_digests: set[str] = set()
    for p in corpus_dir.iterdir():
        if p.is_file() and not p.is_symlink() and not p.name.startswith("."):
            with contextlib.suppress(OSError):
                existing_digests.add(_sha256_path(p))
    candidates = _scan_corpus_candidates(src_dir, CORPUS_MAX_FILE_BYTES)
    copied = 0
    total_bytes = 0
    for size, name, src in sorted(candidates):
        if copied >= max_files or total_bytes + size > max_bytes:
            break
        try:
            digest = _sha256_path(src)
        except OSError:
            continue
        if digest in existing_digests:
            continue
        dst = corpus_dir / name
        if dst.exists():
            dst = corpus_dir / digest
        try:
            shutil.copy2(src, dst)
        except OSError:
            continue
        existing_digests.add(digest)
        copied += 1
        total_bytes += size
    return copied


def publish_corpus(
    module: str,
    corpus_dir: Path,
    *,
    max_files: int = CORPUS_MAX_FILES,
    max_file_bytes: int = CORPUS_MAX_FILE_BYTES,
    max_bytes: int = CORPUS_MAX_TOTAL_BYTES,
) -> int:
    """
    Mirror coverage-increasing inputs from `corpus_dir` into `$FRAMAC_SHARED_CACHE_DIR/corpora/<module>`
    when `FRAMAC_CACHE_MODE=rw`. Inputs are content-addressed by sha256; returns the count of newly published files.
    """
    if not enabled() or shared_mode() != "rw":
        return 0
    dest_dir = shared_corpus_dir(module)
    corpus_dir = Path(corpus_dir)
    if dest_dir is None or not corpus_dir.is_dir():
        return 0
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return 0
    candidates = _scan_corpus_candidates(corpus_dir, max_file_bytes)
    published = 0
    total_bytes = 0
    for count, (size, _, src) in enumerate(sorted(candidates)):
        if count >= max_files or total_bytes + size > max_bytes:
            break
        try:
            digest = _sha256_path(src)
        except OSError:
            continue
        target = dest_dir / digest
        total_bytes += size
        if target.is_file():
            continue
        tmp_name: str | None = None
        try:
            fd, tmp_name = tempfile.mkstemp(prefix=f".{digest[:12]}.", suffix=".seed", dir=dest_dir)
            os.close(fd)
            tmp = Path(tmp_name)
            shutil.copy2(src, tmp)
            os.replace(tmp, target)
            published += 1
            tmp_name = None
        except OSError:
            if tmp_name:
                with contextlib.suppress(OSError):
                    Path(tmp_name).unlink(missing_ok=True)
    return published


# ---------------------------------------------------------------------------
# Stores
# ---------------------------------------------------------------------------


def _sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _remove_tree(path: Path) -> None:
    """Make a directory disappear atomically (rename to a tomb), then delete it."""
    tomb = path.with_name(f".tomb-{path.name}-{os.getpid()}-{time.time_ns()}")
    try:
        os.replace(path, tomb)
    except OSError:
        tomb = path
    shutil.rmtree(tomb, ignore_errors=True)


@dataclass
class Entry:
    store: Store
    ns: str
    key: str
    path: Path
    meta: dict

    @property
    def data(self) -> dict:
        return self.meta.get("data") or {}


class Store:
    """One cache root (`<run>/state/cache` or the shared store)."""

    def __init__(self, root: Path, writable: bool = True, scope: str = "run") -> None:
        self.root = Path(root)
        self.writable = writable
        self.scope = scope

    def entry_dir(self, ns: str, key: str) -> Path:
        return self.root / ns / key[:2] / key

    def get(self, ns: str, key: str) -> Entry | None:
        path = self.entry_dir(ns, key)
        try:
            meta = json.loads((path / "meta.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(meta, dict) or meta.get("schema") != CACHE_SCHEMA_VERSION or meta.get("key") != key:
            return None
        if self.writable:
            with contextlib.suppress(OSError):
                os.utime(path / "meta.json")  # LRU clock
        return Entry(self, ns, key, path, meta)

    def put(self, ns: str, key: str, files: dict[str, Path], data: dict, key_material: dict | None = None) -> bool:
        """Publish an entry atomically; True when it exists afterwards (ours or a concurrent publisher's)."""
        if not self.writable:
            return False
        final = self.entry_dir(ns, key)
        if (final / "meta.json").is_file():
            return True
        ns_dir = self.root / ns
        ns_dir.mkdir(parents=True, exist_ok=True)
        tmp = Path(tempfile.mkdtemp(prefix=f".tmp-{key[:12]}-", dir=ns_dir))
        try:
            (tmp / "files").mkdir()
            manifest: dict[str, dict] = {}
            total = 0
            for name, src in files.items():
                if not _NAME_RE.match(name):
                    raise ValueError(f"invalid cache file name {name!r}")
                dst = tmp / "files" / name
                shutil.copy2(src, dst)
                size = dst.stat().st_size
                manifest[name] = {"source": Path(src).as_posix(), "sha256": _sha256_path(dst), "size": size}
                total += size
            meta = {
                "schema": CACHE_SCHEMA_VERSION,
                "ns": ns,
                "key": key,
                "created_at": utc_now(),
                "bytes": total,
                "files": manifest,
                "data": data,
            }
            (tmp / "meta.json").write_text(json.dumps(meta, indent=1, sort_keys=True) + "\n", encoding="utf-8")
            if key_material is not None:
                (tmp / "key.json").write_text(
                    json.dumps(key_material, indent=1, sort_keys=True, default=str) + "\n", encoding="utf-8"
                )
            final.parent.mkdir(parents=True, exist_ok=True)
            return _publish_dir(tmp, final)
        finally:
            if tmp.exists():
                shutil.rmtree(tmp, ignore_errors=True)

    # -- inventory ----------------------------------------------------------

    def namespaces(self) -> list[str]:
        if not self.root.is_dir():
            return []
        return sorted(p.name for p in self.root.iterdir() if p.is_dir() and not p.name.startswith("."))

    def _items(self, ns: str) -> list[tuple[float, int, Path, bool]]:
        """(last_used, bytes, path, is_entry) for every entry (or foreign file, e.g. Frama-C's WP cache)."""
        base = self.root / ns
        items: list[tuple[float, int, Path, bool]] = []
        if not base.is_dir():
            return items
        for shard in base.iterdir():
            if shard.name.startswith("."):
                continue
            if shard.is_file():
                with contextlib.suppress(OSError):
                    st = shard.stat()
                    items.append((st.st_mtime, st.st_size, shard, False))
                continue
            for child in shard.iterdir():
                if child.name.startswith("."):
                    continue  # temp dirs, tombs and locks
                meta_file = child / "meta.json"
                if child.is_dir() and _KEY_RE.match(child.name) and meta_file.is_file():
                    try:
                        meta = json.loads(meta_file.read_text(encoding="utf-8"))
                        items.append((meta_file.stat().st_mtime, int(meta.get("bytes") or 0), child, True))
                    except (OSError, ValueError):
                        continue
                elif child.is_dir():
                    for root, _, names in os.walk(child):
                        for fname in names:
                            p = Path(root) / fname
                            with contextlib.suppress(OSError):
                                st = p.stat()
                                items.append((st.st_mtime, st.st_size, p, False))
                elif child.is_file():
                    with contextlib.suppress(OSError):
                        st = child.stat()
                        items.append((st.st_mtime, st.st_size, child, False))
        return items

    def stats(self, ns: str | None = None) -> dict:
        out: dict = {"root": str(self.root), "scope": self.scope, "namespaces": {}, "entries": 0, "bytes": 0}
        for name in [ns] if ns else self.namespaces():
            items = self._items(name)
            entries = sum(1 for it in items if it[3])
            size = sum(it[1] for it in items)
            out["namespaces"][name] = {
                "entries": entries,
                "files": sum(1 for it in items if not it[3]),
                "bytes": size,
                "oldest_use": min((it[0] for it in items), default=None),
                "newest_use": max((it[0] for it in items), default=None),
            }
            out["entries"] += entries
            out["bytes"] += size
        return out

    def budget_bytes(self, current: int = 0) -> int:
        cap = DEFAULT_MAX_BYTES
        raw = (os.environ.get("FRAMAC_CACHE_MAX") or "").strip()
        if raw:
            parsed = _parse_size(raw)
            if parsed is not None:
                cap = parsed
        try:
            free = shutil.disk_usage(self.root if self.root.exists() else self.root.parent).free
        except OSError:
            return cap
        # 25 % of the disk that would be free without this cache, so collecting never chases itself.
        return min(cap, int(DISK_FRACTION * (free + current)))

    def gc(self, max_bytes: int | None = None, ns: str | None = None) -> dict:
        """Delete least-recently-used entries until the store fits its budget."""
        items: list[tuple[float, int, Path, bool]] = []
        for name in [ns] if ns else self.namespaces():
            items.extend(self._items(name))
        total = sum(it[1] for it in items)
        budget = self.budget_bytes(total) if max_bytes is None else max_bytes
        removed, freed = 0, 0
        for _, size, path, is_entry in sorted(items, key=lambda it: it[0]):
            if total <= budget:
                break
            if is_entry:
                _remove_tree(path)
            else:
                with contextlib.suppress(OSError):
                    path.unlink()
            total -= size
            freed += size
            removed += 1
        if self.writable:
            with contextlib.suppress(OSError):
                self.root.mkdir(parents=True, exist_ok=True)
                (self.root / ".gc-stamp").write_text(utc_now() + "\n", encoding="utf-8")
        return {
            "root": str(self.root),
            "budget_bytes": budget,
            "removed": removed,
            "freed_bytes": freed,
            "bytes": total,
        }

    def maybe_gc(self) -> dict | None:
        stamp = self.root / ".gc-stamp"
        try:
            if time.time() - stamp.stat().st_mtime < GC_INTERVAL_S:
                return None
        except OSError:
            pass
        return self.gc()

    def clear(self, ns: str | None = None) -> dict:
        cleared = []
        for name in [ns] if ns else self.namespaces():
            path = self.root / name
            if path.is_dir():
                _remove_tree(path)
                cleared.append(name)
        return {"root": str(self.root), "cleared": cleared}


def _parse_size(raw: str) -> int | None:
    m = re.fullmatch(r"\s*([0-9]+(?:\.[0-9]+)?)\s*([kKmMgGtT]?)(?:i?[bB])?\s*", raw)
    if not m:
        return None
    factor = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}[m.group(2).lower()]
    return int(float(m.group(1)) * factor)


def _publish_dir(tmp: Path, final: Path) -> bool:
    for attempt in range(8):
        try:
            os.replace(tmp, final)
            return True
        except OSError:
            if (final / "meta.json").is_file():
                return True  # a concurrent publisher won; its entry is equivalent
            if os.name != "nt" or attempt == 7:
                return False
            time.sleep(0.05 * (attempt + 1))  # Windows: a scanner may briefly hold a handle
    return False


def run_store(cwd: Path | None = None) -> Store:
    return Store(run_cache_root(cwd), writable=True, scope="run")


def shared_store() -> Store | None:
    root = shared_cache_root()
    if root is None:
        return None
    return Store(root, writable=shared_mode() == "rw", scope="shared")


def stores(cwd: Path | None = None, *, include_run: bool = True) -> list[Store]:
    """Lookup order: the run store (when `include_run` is True), then the shared store."""
    found = [run_store(cwd)] if include_run else []
    shared = shared_store()
    if shared is not None:
        found.append(shared)
    return found


def lookup(ns: str, key: str, cwd: Path | None = None, *, include_run: bool = True) -> Entry | None:
    for store in stores(cwd, include_run=include_run):
        entry = store.get(ns, key)
        if entry is not None:
            return entry
    return None


def publish(
    ns: str, key: str, files: dict[str, Path], data: dict, key_material: dict | None = None, cwd: Path | None = None
) -> bool:
    """Publish to the run store, and to the shared store when FRAMAC_CACHE_MODE=rw."""
    ok = False
    for store in stores(cwd):
        if not store.writable:
            continue
        try:
            published = store.put(ns, key, files, data, key_material)
        except (OSError, ValueError):
            published = False
        ok = ok or published
        if published:
            with contextlib.suppress(OSError):
                store.maybe_gc()
    return ok


def restore(entry: Entry, dest: dict[str, Path] | None = None) -> bool:
    """
    Copy the entry's files to `dest` (name -> path; default: where they were published from).
    Each file is staged next to its destination, checked against its digest, then renamed into
    place, so a running executable is never overwritten in place. False on any problem.
    """
    files = entry.meta.get("files") or {}
    targets = dest if dest is not None else {name: Path(info["source"]) for name, info in files.items()}
    staged: list[tuple[Path, Path]] = []
    try:
        for name, target in targets.items():
            info = files.get(name)
            if info is None:
                continue
            target = Path(target)
            target.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".restore", dir=target.parent)
            os.close(fd)
            tmp = Path(tmp_name)
            staged.append((tmp, target))
            shutil.copy2(entry.path / "files" / name, tmp)
            if _sha256_path(tmp) != info.get("sha256"):
                raise OSError(f"cache entry {entry.key} file {name} does not match its digest")
        for tmp, target in staged:
            os.replace(tmp, target)
        return True
    except OSError:
        for tmp, _ in staged:
            with contextlib.suppress(OSError):
                tmp.unlink()
        return False


_flight_guard = threading.Lock()
_flight_locks: dict[str, threading.RLock] = {}


@contextlib.contextmanager
def single_flight(store: Store, ns: str, key: str) -> Iterator[bool]:
    """
    Hold the build lock of one key: threads of this process and other containers wait, then find
    the published entry. Yields False when the lock could not be taken (the caller builds
    without it).
    """
    lock_root = store.root / ns
    ident = os.path.abspath(lock_root / key)
    with _flight_guard:
        tlock = _flight_locks.setdefault(ident, threading.RLock())
    with tlock, contextlib.ExitStack() as stack:
        held = True
        try:
            lock_root.mkdir(parents=True, exist_ok=True)
            stack.enter_context(run_lock(f"flight-{key}", lock_root))
        except (RunLockTimeout, OSError):
            held = False
        yield held


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------

_toolchain_memo: str | None = None
_scripts_memo: str | None = None
_digest_memo: dict[tuple, str] = {}
_memo_guard = threading.Lock()
# Version probes never go through a test's monkeypatched subprocess.run.
_REAL_SUBPROCESS_RUN = subprocess.run


def toolchain_id(runner: Callable | None = None) -> str:
    """
    The image (or tool versions) plus the digest of the run's target snapshot (scripts/target_env.py):
    the analysis image is the same for every target, and the snapshot is what it links against.
    """
    from target_env import snapshot_digest

    snap = snapshot_digest()
    base = _image_or_tools_id(runner)
    return f"{base}+snapshot:{snap}" if snap else base


def _image_or_tools_id(runner: Callable | None = None) -> str:
    """FRAMAC_IMAGE_ID when set, else a digest of the tool versions (memoized per process)."""
    image = (os.environ.get("FRAMAC_IMAGE_ID") or "").strip()
    if image:
        return f"image:{image}"
    global _toolchain_memo
    with _memo_guard:
        if _toolchain_memo is not None:
            return _toolchain_memo
    run = runner or _REAL_SUBPROCESS_RUN
    parts = [f"python:{platform.python_version()}", f"machine:{platform.machine()}"]
    for cmd in (["frama-c", "-version"], ["clang", "--version"], ["gcc", "--version"]):
        try:
            proc = run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
            text = ((proc.stdout or "") + (proc.stderr or "")).strip().splitlines()
            parts.append(f"{cmd[0]}:{proc.returncode}:{text[0] if text else ''}")
        except (OSError, subprocess.SubprocessError, ValueError):
            parts.append(f"{cmd[0]}:missing")
    value = "tools:" + hashlib.sha256("\n".join(parts).encode()).hexdigest()
    with _memo_guard:
        _toolchain_memo = value
    return value


def scripts_digest() -> str:
    """sha256 of every file under scripts/ and templates/ (memoized per process)."""
    global _scripts_memo
    with _memo_guard:
        if _scripts_memo is not None:
            return _scripts_memo
    h = hashlib.sha256()
    for base in (_SCRIPTS_DIR, _TEMPLATES_DIR):
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            rel = f"{base.name}/{path.relative_to(base).as_posix()}"
            h.update(rel.encode() + b"\0" + _sha256_path(path).encode("ascii") + b"\n")
    value = h.hexdigest()
    with _memo_guard:
        _scripts_memo = value
    return value


def file_digest(path: str | Path) -> str | None:
    """Content sha256 of a regular file, or None. Memoized unless the file changed in the last 2 s."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode):
        return None
    memo_key = (os.path.abspath(path), st.st_mtime_ns, st.st_size, st.st_ino)
    with _memo_guard:
        if memo_key in _digest_memo:
            return _digest_memo[memo_key]
    try:
        value = _sha256_path(Path(path))
    except OSError:
        return None
    if time.time() - st.st_mtime > 2.0:  # a same-tick rewrite could otherwise keep a stale digest
        with _memo_guard:
            _digest_memo[memo_key] = value
    return value


def _find_matching_delim(tokens: list[Token], open_idx: int, open_ch: str, close_ch: str) -> int:
    depth = 0
    for idx in range(open_idx, len(tokens)):
        tok = tokens[idx]
        if tok.kind == "c_token":
            if tok.text == open_ch:
                depth += 1
            elif tok.text == close_ch:
                depth -= 1
                if depth == 0:
                    return idx
    return -1


def _find_matching_backward(tokens: list[Token], close_idx: int, open_ch: str, close_ch: str) -> int:
    depth = 0
    for idx in range(close_idx, -1, -1):
        tok = tokens[idx]
        if tok.kind == "c_token":
            if tok.text == close_ch:
                depth += 1
            elif tok.text == open_ch:
                depth -= 1
                if depth == 0:
                    return idx
    return -1


def _prev_meaningful(tokens: list[Token], idx: int, min_idx: int = -1) -> int:
    cursor = idx
    while cursor > min_idx and tokens[cursor].kind in ("whitespace", "c_comment", "acsl_block", "acsl_line"):
        cursor -= 1
    return cursor


def _has_preceding_fn_sig(tokens: list[Token], idx: int, min_idx: int) -> bool:
    """True when `idx` is preceded by `...(params)` with a function name and return type before `(`."""
    before = _prev_meaningful(tokens, idx, min_idx)
    while before > min_idx:
        tok = tokens[before]
        if tok.kind == "c_token" and tok.text == ")":
            open_p = _find_matching_backward(tokens, before, "(", ")")
            if open_p <= min_idx:
                return False
            prev_fn = _prev_meaningful(tokens, open_p - 1, min_idx)
            if prev_fn > min_idx and tokens[prev_fn].kind == "c_token":
                if (
                    tokens[prev_fn].text not in C_KEYWORDS
                    and re.match(r"^[A-Za-z_]\w*$", tokens[prev_fn].text)
                    and _prev_meaningful(tokens, prev_fn - 1, min_idx) > min_idx
                ):
                    return True
            before = _prev_meaningful(tokens, open_p - 1, min_idx)
            continue
        if tok.kind == "c_token" and re.match(r"^[A-Za-z_]\w*$", tok.text) and tok.text not in C_KEYWORDS:
            before = _prev_meaningful(tokens, before - 1, min_idx)
            continue
        break
    return False


def _strip_trailing_attrs_backward(tokens: list[Token], end_idx: int, min_idx: int) -> int:
    cursor = end_idx - 1
    while cursor > min_idx:
        tok = tokens[cursor]
        if tok.kind in ("whitespace", "c_comment", "acsl_block", "acsl_line"):
            cursor -= 1
            continue
        if tok.kind == "c_token" and tok.text == ")":
            open_p = _find_matching_backward(tokens, cursor, "(", ")")
            if open_p > min_idx:
                p_c = _prev_meaningful(tokens, open_p - 1, min_idx)
                if p_c > min_idx:
                    if tokens[p_c].text in {
                        "__attribute__",
                        "__attribute",
                        "__declspec",
                        "asm",
                        "__asm",
                        "__asm__",
                    }:
                        cursor = p_c - 1
                        continue
                    if (
                        tokens[p_c].kind == "c_token"
                        and re.match(r"^[A-Za-z_]\w*$", tokens[p_c].text)
                        and tokens[p_c].text not in C_KEYWORDS
                        and _has_preceding_fn_sig(tokens, p_c - 1, min_idx)
                    ):
                        cursor = p_c - 1
                        continue
        elif tok.kind == "c_token":
            if tok.text in {"const", "volatile", "__const", "__const__"}:
                cursor -= 1
                continue
            if (
                re.match(r"^[A-Za-z_]\w*$", tok.text)
                and tok.text not in C_KEYWORDS
                and _has_preceding_fn_sig(tokens, cursor - 1, min_idx)
            ):
                cursor -= 1
                continue
        break
    return cursor


def _resolve_fn_name(tokens: list[Token], min_idx: int, open_params_idx: int) -> str | None:
    prev_idx = _prev_meaningful(tokens, open_params_idx - 1, min_idx)
    if prev_idx <= min_idx:
        return None
    prev = tokens[prev_idx]
    if prev.kind == "c_token" and prev.text not in C_KEYWORDS and re.match(r"^[A-Za-z_]\w*$", prev.text):
        return prev.text
    # Function-pointer returning declarator: `ret (*fn(params))(fp_params)`
    if prev.kind == "c_token" and prev.text == ")":
        inner_open = _find_matching_backward(tokens, prev_idx, "(", ")")
        if inner_open > min_idx:
            inner_close_p = _strip_trailing_attrs_backward(tokens, prev_idx, inner_open)
            if inner_close_p > inner_open and tokens[inner_close_p].text == ")":
                inner_open_p = _find_matching_backward(tokens, inner_close_p, "(", ")")
                if inner_open_p > inner_open:
                    cand_idx = _prev_meaningful(tokens, inner_open_p - 1, inner_open)
                    if cand_idx > inner_open:
                        cand = tokens[cand_idx]
                        if (
                            cand.kind == "c_token"
                            and cand.text not in C_KEYWORDS
                            and re.match(r"^[A-Za-z_]\w*$", cand.text)
                        ):
                            return cand.text
    return None


def _identify_unrelated_acsl_tokens(tokens: list[Token], target_functions: set[str]) -> set[int]:
    unrelated_indices: set[int] = set()
    n = len(tokens)
    idx = 0
    brace_depth = 0
    paren_depth = 0
    last_top_boundary = -1

    while idx < n:
        tok = tokens[idx]
        if tok.kind == "c_token":
            if tok.text == "(":
                paren_depth += 1
                idx += 1
                continue
            if tok.text == ")":
                paren_depth = max(0, paren_depth - 1)
                idx += 1
                continue
            if tok.text == ";" and brace_depth == 0 and paren_depth == 0:
                # Top-level prototype / declaration
                before_semi = _strip_trailing_attrs_backward(tokens, idx, last_top_boundary)
                if before_semi > last_top_boundary and tokens[before_semi].text == ")":
                    open_p = _find_matching_backward(tokens, before_semi, "(", ")")
                    if open_p > last_top_boundary:
                        fn_name = _resolve_fn_name(tokens, last_top_boundary, open_p)
                        if fn_name:
                            for c_idx in range(last_top_boundary + 1, open_p):
                                t = tokens[c_idx]
                                if t.kind in ("acsl_block", "acsl_line"):
                                    if not _GLOBAL_ACSL_DECL_RE.search(t.text):
                                        if fn_name not in target_functions:
                                            unrelated_indices.add(c_idx)
                last_top_boundary = idx
                idx += 1
                continue
            if tok.text == "}" and paren_depth == 0:
                brace_depth = max(0, brace_depth - 1)
                if brace_depth == 0:
                    last_top_boundary = idx
                idx += 1
                continue
            if tok.text == "{" and brace_depth == 0 and paren_depth == 0:
                # Check if extern "C" linkage block
                header_tokens = [
                    t
                    for t in tokens[last_top_boundary + 1 : idx]
                    if t.kind not in ("whitespace", "c_comment", "acsl_block", "acsl_line")
                ]
                if (
                    len(header_tokens) >= 2
                    and header_tokens[-2].text == "extern"
                    and header_tokens[-1].text in ('"C"', '"C++"')
                ) or (len(header_tokens) == 1 and header_tokens[-1].text == "extern"):
                    last_top_boundary = idx
                    idx += 1
                    continue

                close_brace = _find_matching_delim(tokens, idx, "{", "}")
                if close_brace == -1:
                    break

                # Function definition header
                before_brace = _strip_trailing_attrs_backward(tokens, idx, last_top_boundary)
                if before_brace > last_top_boundary and tokens[before_brace].text == ")":
                    open_p = _find_matching_backward(tokens, before_brace, "(", ")")
                    if open_p > last_top_boundary:
                        fn_name = _resolve_fn_name(tokens, last_top_boundary, open_p)
                        if fn_name:
                            # Preceding contract tokens
                            for c_idx in range(last_top_boundary + 1, open_p):
                                t = tokens[c_idx]
                                if t.kind in ("acsl_block", "acsl_line"):
                                    if not _GLOBAL_ACSL_DECL_RE.search(t.text):
                                        if fn_name not in target_functions:
                                            unrelated_indices.add(c_idx)
                            # Body ACSL tokens
                            if fn_name not in target_functions:
                                for b_idx in range(idx + 1, close_brace):
                                    t = tokens[b_idx]
                                    if t.kind in ("acsl_block", "acsl_line"):
                                        if not _GLOBAL_ACSL_DECL_RE.search(t.text):
                                            unrelated_indices.add(b_idx)
                last_top_boundary = close_brace
                idx = close_brace + 1
                continue
        idx += 1

    return unrelated_indices


def _strip_unrelated_acsl(text: str, target_functions: set[str]) -> str:
    """
    Remove ACSL function contracts and statement annotations attached to functions not in
    `target_functions`, while preserving global ACSL declarations (`predicate`, `axiomatic`, etc.)
    and all annotations on `target_functions`.
    """
    if not target_functions:
        return text
    try:
        tokens = tokenize_c_acsl(text)
    except AcslSyntaxError:
        return text  # Fail closed
    unrelated = _identify_unrelated_acsl_tokens(tokens, target_functions)
    if not unrelated:
        return text
    parts: list[str] = []
    last_end = 0
    for idx, tok in enumerate(tokens):
        if idx in unrelated:
            parts.append(text[last_end : tok.start])
            last_end = tok.end
    parts.append(text[last_end:])
    return "".join(parts)


def normalized_source_digest(path: str | Path, target_functions: Iterable[str] | None = None) -> str | None:
    """
    L2 content digest of a source or header file: strips same-file `#line` directives, blank lines,
    horizontal whitespace, and (when `target_functions` is given) ACSL annotations on functions outside
    `target_functions`. Line-number shifts and unrelated annotations do not alter the L2 key when
    executable code and relevant annotations are unchanged.
    """
    try:
        st = os.stat(path)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode):
        return None
    try:
        raw_bytes = Path(path).read_bytes()
    except OSError:
        return None
    raw_text = raw_bytes.decode("utf-8", errors="surrogateescape")
    try:
        tokens = tokenize_c_acsl(raw_text, path=str(path))
    except AcslSyntaxError:
        return hashlib.sha256(raw_bytes).hexdigest()

    target_set = {f.strip() for f in (target_functions or ()) if f and f.strip()}
    unrelated: set[int] = _identify_unrelated_acsl_tokens(tokens, target_set) if target_set else set()

    cur_name = Path(path).name
    parts: list[str] = []
    for idx, tok in enumerate(tokens):
        if idx in unrelated:
            continue
        if tok.kind in ("acsl_block", "acsl_line"):
            parts.append(tok.text.strip())
        elif tok.kind == "pp_directive":
            m = _LINE_DIRECTIVE_RE.match(tok.text)
            if m:
                fname = m.group(2)
                if fname is None or Path(fname).name == cur_name:
                    continue
            parts.append(tok.text.strip())
        elif tok.kind in ("string", "char"):
            parts.append(tok.text)
        elif tok.kind == "c_token":
            parts.append(tok.text)
        elif tok.kind == "c_comment":
            parts.append(tok.text.strip())
        elif tok.kind == "whitespace":
            continue
    payload = "\n".join(parts)
    return hashlib.sha256(payload.encode("utf-8", errors="surrogateescape")).hexdigest()


def normalized_dependency_manifest(
    deps: list[list[str]],
    target_functions: Iterable[str] | None = None,
) -> list[list[str]]:
    """Replace each dependency's raw file digest with `normalized_source_digest` for L2 key computation."""
    return [
        [
            dep,
            (normalized_source_digest(dep, target_functions=target_functions) or "missing")
            if digest != "missing"
            else "missing",
        ]
        for dep, digest in deps
    ]


def _split_make_words(text: str) -> list[str]:
    words: list[str] = []
    cur: list[str] = []
    i = 0
    while i < len(text):
        c = text[i]
        if c == "\\" and i + 1 < len(text) and text[i + 1] in " #\\":
            cur.append(text[i + 1])
            i += 2
            continue
        if c == "$" and text[i + 1 : i + 2] == "$":
            cur.append("$")
            i += 2
            continue
        if c.isspace():
            if cur:
                words.append("".join(cur))
                cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    if cur:
        words.append("".join(cur))
    return words


_RULE_RE = re.compile(r"^((?:[^:\\]|\\.)+?):(?=\s|$)(.*)$")


def parse_make_deps(text: str) -> list[str]:
    """Prerequisites of every rule in `gcc -M` / `clang -M` output."""
    deps: list[str] = []
    joined = re.sub(r"\\\r?\n", " ", text or "")
    for line in joined.splitlines():
        m = _RULE_RE.match(line.strip())
        if m:
            deps.extend(_split_make_words(m.group(2)))
    return deps


_PRE_SEPARATE = frozenset({"-I", "-D", "-U", "-include", "-imacros", "-isystem", "-idirafter", "-iquote"})
_PRE_JOINED = ("-I", "-D", "-U", "-isystem", "-idirafter", "-iquote", "-std=")


def preprocessor_args(tokens: Iterable[str]) -> list[str]:
    """The tokens of a flag list that change what the preprocessor includes."""
    toks = list(tokens)
    out: list[str] = []
    i = 0
    while i < len(toks):
        tok = toks[i]
        if tok in _PRE_SEPARATE and i + 1 < len(toks):
            out.extend([tok, toks[i + 1]])
            i += 2
            continue
        if tok.startswith(_PRE_JOINED) or tok == "-nostdinc":
            out.append(tok)
        i += 1
    return out


def dependency_manifest(
    sources: Iterable[str | Path], flags: Iterable[str], runner: Callable | None = None, timeout: float = DEPS_TIMEOUT_S
) -> list[list[str]] | None:
    """
    [[path, sha256 | "missing"], ...] for the sources and every file `gcc -M -MG` (with Frama-C's
    defines) or `clang -M -MG` includes under `flags`. None when either tool fails: an incomplete
    manifest would make the key unsound, so the caller must not cache.
    """
    run = runner or subprocess.run
    srcs = [str(s) for s in sources]
    if not srcs:
        return None
    pre = preprocessor_args(flags)
    deps: set[str] = set(srcs)
    for tool, extra in (("gcc", FRAMAC_DEP_DEFINES), ("clang", ())):
        cmd = [tool, "-M", "-MG", *extra, *pre, *srcs]
        try:
            proc = run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        except (OSError, subprocess.SubprocessError, ValueError):
            return None
        if proc.returncode != 0:
            return None
        found = parse_make_deps(proc.stdout or "")
        if not found:
            return None
        deps.update(found)
    return [[dep, file_digest(dep) or "missing"] for dep in sorted(deps)]


def make_key(ns: str, material: dict) -> str:
    doc = {
        "schema": CACHE_SCHEMA_VERSION,
        "ns": ns,
        "toolchain": toolchain_id(),
        "scripts": scripts_digest(),
        "material": material,
    }
    blob = json.dumps(doc, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Memoized builds
# ---------------------------------------------------------------------------


def memoize(
    ns: str,
    material: dict,
    *,
    sources: Iterable[str | Path],
    dep_flags: Iterable[str],
    build: Callable[[], dict],
    outputs: Callable[[dict], dict[str, Path]],
    ok: Callable[[dict], bool],
    runner: Callable | None = None,
    restore_map: Callable[[Entry], dict[str, Path] | None] | None = None,
    on_restore: Callable[[dict, Entry], dict] | None = None,
    enable_l2: bool = False,
    l2_target_functions: Iterable[str] | None = None,
) -> dict:
    """
    Return `build()`'s result, or the cached result of an identical earlier build with its output
    files restored. The result always carries `cache: {"hit": bool, "key": str | None}`; the key
    is None when caching is off or the dependency manifest is unavailable. When `enable_l2` is
    True, an L1 miss falls back to a secondary L2 key built from `normalized_dependency_manifest`
    (stripped `#line` directives, blank lines, and unrelated-function ACSL comments). Only results
    for which `ok(result)` holds are published, together with the files `outputs(result)` names.
    """

    def _uncached(key: str | None = None) -> dict:
        res = build()
        res["cache"] = {"hit": False, "key": key}
        return res

    if not enabled():
        return _uncached()
    deps = dependency_manifest(sources, dep_flags, runner=runner)
    if deps is None:
        return _uncached()
    cwd_posix = Path.cwd().as_posix()
    full = dict(material, cwd=cwd_posix, deps=deps)
    key = make_key(ns, full)
    l2_full: dict | None = None
    l2_key: str | None = None
    with single_flight(run_store(), ns, key):
        entry = lookup(ns, key)
        if entry is not None and restore(entry, restore_map(entry) if restore_map else None):
            result = copy.deepcopy(entry.data.get("result") or {})
            if on_restore is not None:
                result = on_restore(result, entry)
            result["cache"] = {"hit": True, "key": key}
            return result
        if enable_l2:
            l2_deps = normalized_dependency_manifest(deps, target_functions=l2_target_functions)
            l2_full = dict(material, cwd=cwd_posix, deps=l2_deps, tier="l2")
            l2_key = make_key(ns, l2_full)
            l2_entry = lookup(ns, l2_key)
            if l2_entry is not None and restore(l2_entry, restore_map(l2_entry) if restore_map else None):
                result = copy.deepcopy(l2_entry.data.get("result") or {})
                if on_restore is not None:
                    result = on_restore(result, l2_entry)
                files = {name: Path(p) for name, p in outputs(result).items() if Path(p).is_file()}
                # Finding A7: Only promote within the store where the L2 entry was found,
                # never promote an entry from an untrusted run_store to the shared_store!
                if l2_entry.store.writable:
                    l2_entry.store.put(
                        ns, key, files, {"result": {k: v for k, v in result.items() if k != "cache"}}, key_material=full
                    )
                result["cache"] = {"hit": True, "key": key, "l2_key": l2_key, "tier": "l2"}
                return result
        res = build()
        res_cache: dict = {"hit": False, "key": key}
        if ok(res):
            # An input rewritten during the build (a merge into workspace/work, say) would file this
            # result under the key of content it was not built from: such a result is not published.
            changed = [path for path, digest in deps if (file_digest(path) or "missing") != digest]
            if changed:
                res_cache["not_published"] = f"inputs changed during the build: {', '.join(changed[:5])}"
            else:
                data = {"result": {k: v for k, v in res.items() if k != "cache"}}
                files = {name: Path(p) for name, p in outputs(res).items() if Path(p).is_file()}
                publish(ns, key, files, data, key_material=full)
                if enable_l2:
                    if l2_key is None:
                        l2_deps = normalized_dependency_manifest(deps, target_functions=l2_target_functions)
                        l2_full = dict(material, cwd=cwd_posix, deps=l2_deps, tier="l2")
                        l2_key = make_key(ns, l2_full)
                    if l2_full is not None:
                        publish(ns, l2_key, files, data, key_material=l2_full)
        res["cache"] = res_cache
        return res


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect and collect the pipeline caches.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name, help_text in (
        ("stats", "Entries and bytes per namespace"),
        ("gc", "Delete least-recently-used entries over the size budget"),
        ("clear", "Delete every entry (of one namespace with --ns)"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--ns", default=None, help=f"Namespace ({', '.join(NAMESPACES)})")
        where = p.add_mutually_exclusive_group()
        where.add_argument("--root", type=Path, default=None, help="Cache root (default: ./state/cache)")
        where.add_argument("--shared", action="store_true", help="Operate on the shared store")
        if name == "gc":
            p.add_argument(
                "--max-bytes", default=None, help="Budget, e.g. 5G (default: FRAMAC_CACHE_MAX / 25 %% of free disk)"
            )
    args = parser.parse_args(argv)

    if args.shared:
        raw = (os.environ.get("FRAMAC_SHARED_CACHE_DIR") or "").strip()
        root = Path(raw) if raw else SHARED_DEFAULT_DIR
        store = Store(root, writable=True, scope="shared")
    else:
        store = Store(args.root or run_cache_root(), writable=True, scope="run")

    if args.cmd == "stats":
        out = store.stats(args.ns)
        out["budget_bytes"] = store.budget_bytes(out["bytes"])
        out["enabled"] = enabled()
    elif args.cmd == "gc":
        max_bytes = _parse_size(args.max_bytes) if args.max_bytes else None
        if args.max_bytes and max_bytes is None:
            parser.error(f"invalid --max-bytes {args.max_bytes!r}")
        out = store.gc(max_bytes, args.ns)
    else:
        out = store.clear(args.ns)
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
