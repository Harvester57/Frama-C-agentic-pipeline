#!/usr/bin/env python3
"""
The target's own fuzz targets and fuzz corpora (Phase 0 discovery and import, Phase 1 per-module corpus).

    fuzz_assets.py discover [--target /target] [--inputs inputs/corpora] [--out workspace/reports/fuzz_assets.json]
    fuzz_assets.py map --corpus ID (--fuzzer ID | --function FN [FN ...] | --ignore --reason TEXT)
    fuzz_assets.py import [--target /target]
    fuzz_assets.py write [--module MOD ...]

Run from the run directory. Every command prints one JSON summary; exit 0 on success, 2 on a usage error.

`discover` walks the target read-only (never following a symlink; skipping `.git`, a top-level
`workspace/` and the pipeline's own output directories) for:

  - fuzzers: C/C++ files that define `LLVMFuzzerTestOneInput`, with the names of its `(data, size)`
    parameters and the functions the source calls with an argument that mentions one of them
    (`direct_api_calls`). C++ fuzzers are recorded as unsupported (reason `cxx`): their corpora still
    feed the generated harnesses through those functions;
  - libFuzzer files next to a fuzzer: `<name>.dict`, `<name>.options` (`[libfuzzer]` max_len, dict).
    The valid entries of a fuzzer's dictionaries are copied to workspace/fuzz_assets/dicts/<id>.dict;
  - corpora: `*_seed_corpus.zip` files, and directories named like a corpus (`corpus`, `seed`, `fuzz`
    in their name or their parent's) that directly hold mostly data files; plus each directory the
    user dropped into the run directory's inputs/corpora/ (kind run_input).

Corpora are paired with fuzzers automatically only by OSS-Fuzz naming (`<fuzzer>_seed_corpus.zip`,
`corpus/<fuzzer>/`, `<fuzzer>_corpus/`, a run input named as the fuzzer). Everything else stays
unmapped: pairing it is a judgment call for the Phase 0 agent (`map`), which can also pair a corpus
with API functions or ignore it. Re-running `discover` keeps the agent's mappings.

`import` copies every mapped corpus, content-addressed, to workspace/fuzz_assets/corpora/<id>/ under
fixed limits (they decide results, so they are not sized from the machine): MAX_INPUT_BYTES per input,
MAX_INPUTS_PER_CORPUS and MAX_CORPUS_BYTES per corpus. Symlinks and special files are never read; a
zip entry's name is never used as a path; each drop is counted by reason.

`write` gives each harness module its imported inputs, in workspace/imported_corpus/<mod>/imp-<sha16>
(never `seed-*`: guardrails replay every seed file without limit), with a report in
workspace/reports/imported_corpus/<mod>.json:

  - a target fuzz module (sidecar `target_fuzzer`) gets the corpora mapped to its fuzzer, verbatim;
  - any other module gets each corpus whose functions (the mapping's, else its fuzzer's
    `direct_api_calls`) a harness case passes its whole input to, behind that case's selector byte.

Inputs longer than the module's `max_input_size` are dropped. A module whose fuzzer ships a
dictionary also gets workspace/dicts/<mod>.extra.dict. Fuzz assets are an improvement, never a
requirement: without fuzz_assets.json, `write` records the reason and exits 0.
"""

from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import os
import posixpath
import re
import shutil
import stat
import sys
import tempfile
import zipfile
import zlib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from framac_common import atomic_write_json, load_json_optional, utc_now  # noqa: E402

SCHEMA_VERSION = 1
REPORT_JSON = Path("workspace/reports/fuzz_assets.json")
ASSETS_DIR = Path("workspace/fuzz_assets")
CORPORA_DIR = ASSETS_DIR / "corpora"
FUZZER_DICTS_DIR = ASSETS_DIR / "dicts"
IMPORTED_DIR = Path("workspace/imported_corpus")
IMPORTED_REPORTS_DIR = Path("workspace/reports/imported_corpus")
DICTS_DIR = Path("workspace/dicts")
HARNESS_DIR = Path("workspace/harnesses")
WORK_DIR = "workspace/work"
DEFAULT_TARGET = "/target"
DEFAULT_INPUTS = Path("inputs/corpora")

# Fixed limits: they decide which inputs a campaign starts from, so they never depend on the machine.
MAX_INPUT_BYTES = 1024 * 1024
MAX_INPUTS_PER_CORPUS = 20000
MAX_CORPUS_BYTES = 256 * 1024 * 1024
MAX_INPUTS_PER_MODULE = 20000
MAX_SOURCE_BYTES = 4 * 1024 * 1024  # a fuzzer source read for discovery
MAX_DICT_BYTES = 1024 * 1024
MIN_SUGGESTED_SIZE = 4096
MAX_SUGGESTED_SIZE = 1024 * 1024
DEFAULT_MAX_INPUT_SIZE = 1500  # generate_harness.py --max-size default (template: `size > MAX_INPUT_SIZE` returns)
IMPORTED_PREFIX = "imp-"

C_SUFFIXES = {".c": "c", ".cc": "cxx", ".cpp": "cxx", ".cxx": "cxx"}
_ID_RE = re.compile(r"^[A-Za-z0-9_.+-]{1,120}$")
_MODULE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.+-]{0,127}$")  # pipeline_make.MODULE_RE
_FUZZER_ENTRY_DEF_RE = re.compile(r"\bLLVMFuzzerTestOneInput\s*\(([^;{)]*)\)\s*\{")  # generate_harness's
_FUZZER_INIT_DEF_RE = re.compile(r"\bLLVMFuzzerInitialize\s*\([^;{)]*\)\s*\{")
_COMMENT_OR_LITERAL_RE = re.compile(r"//[^\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'", re.S)
_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_NOT_CALLS = {
    "if",
    "while",
    "for",
    "switch",
    "return",
    "sizeof",
    "do",
    "else",
    "case",
    "goto",
    "defined",
    "_Alignof",
    "alignof",
    "_Static_assert",
    "static_assert",
    "_Generic",
    "__typeof__",
    "typeof",
    "__attribute__",
    "__asm__",
    "asm",
    "LLVMFuzzerTestOneInput",
    "LLVMFuzzerInitialize",
}
_TYPE_WORDS = {"const", "volatile", "restrict", "__restrict", "__restrict__", "unsigned", "signed", "struct"}
_CORPUS_WORDS = ("corpus", "seed", "fuzz")
_CORPUS_PARENTS = {"corpus", "corpora"}
# Files a corpus directory may hold that are not inputs (build and fuzzer configuration, docs).
_NOT_INPUT_SUFFIXES = (
    ".dict",
    ".options",
    ".md",
    ".rst",
    ".yaml",
    ".yml",
    ".zip",
    ".cc",
    ".cpp",
    ".cxx",
    ".hh",
    ".hpp",
    ".toml",
)
_NOT_INPUT_NAMES = ("dockerfile", "readme", "license", "copying", "authors", "changelog")
_DICT_ENTRY_RE = re.compile(r'^(?:[A-Za-z0-9_][A-Za-z0-9_.@-]*\s*=\s*)?"(?:[^"\\]|\\\\|\\"|\\x[0-9A-Fa-f]{2})*"$')


class UsageError(ValueError):
    """A command-line mistake: unknown id, missing report. Exit code 2."""


# ---------------------------------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------------------------------


def sanitize_id(name: str, fallback: str) -> str:
    out = re.sub(r"[^A-Za-z0-9_.+-]", "_", name)[:100]
    if not out.strip("."):
        out = f"_{out}" if out else fallback
    return out


def unique_ids(names: list[str], fallback: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for name in names:
        base = sanitize_id(name, fallback)
        cand, n = base, 1
        while cand in seen:
            n += 1
            cand = f"{base}-{n}"
        seen.add(cand)
        out.append(cand)
    return out


def _atomic_write_bytes(dest: Path, blob: bytes) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{dest.name}.", suffix=".tmp", dir=str(dest.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(blob)
        os.replace(tmp, dest)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _clear_dir(path: Path) -> None:
    """Remove a pipeline-owned directory (a symlink in its place is removed, never followed)."""
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)


def _no_symlink_path(base: Path, rel: str) -> os.stat_result | None:
    """lstat of base/rel when no component of rel is a symlink (promote_artifact's walk), else None."""
    current = base
    st: os.stat_result | None = None
    for part in rel.split("/"):
        if part in ("", ".", ".."):
            return None
        current = current / part
        try:
            st = os.lstat(current)
        except OSError:
            return None
        if stat.S_ISLNK(st.st_mode):
            return None
    return st


def _read_regular(path: Path, limit: int) -> bytes:
    """At most `limit` bytes of a regular file, refusing a symlink (O_NOFOLLOW where it exists)."""
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode):
        raise OSError(f"{path}: not a regular file")
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as fh:
        return fh.read(limit)


def strip_c(text: str) -> str:
    """Comments removed, string and character literals emptied (so neither can fake a call)."""

    def repl(m: re.Match[str]) -> str:
        s = m.group(0)
        if s.startswith("/"):
            return " "
        return s[0] * 2

    return _COMMENT_OR_LITERAL_RE.sub(repl, text)


def _match_paren(text: str, start: int) -> int:
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _split_args(text: str) -> list[str]:
    out: list[str] = []
    cur, depth = "", 0
    for ch in text:
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def _param_name(param: str) -> str | None:
    """The declared name of one parameter (`const uint8_t *data` -> data; `size_t` -> None)."""
    p = re.sub(r"\[[^\]]*\]", " ", param)
    tokens = re.findall(r"[A-Za-z_]\w*|\*", p)
    if len(tokens) < 2 or tokens[-1] == "*" or tokens[-1] in _TYPE_WORDS:
        return None
    before = [t for t in tokens[:-1] if t not in _TYPE_WORDS]
    return tokens[-1] if before else None


# ---------------------------------------------------------------------------------------------------
# discover
# ---------------------------------------------------------------------------------------------------


def analyse_fuzzer_source(text: str) -> dict[str, Any] | None:
    """{data_param, size_param, direct_api_calls, defines_initialize} of a fuzzer source, None if it defines none."""
    code = strip_c(text)
    m = _FUZZER_ENTRY_DEF_RE.search(code)
    if not m:
        return None
    params = _split_args(m.group(1))
    data_param = _param_name(params[0]) if len(params) == 2 else None
    size_param = _param_name(params[1]) if len(params) == 2 else None
    names = [n for n in (data_param, size_param) if n]
    calls: set[str] = set()
    if names:
        mention = re.compile(r"\b(?:" + "|".join(re.escape(n) for n in names) + r")\b")
        for c in _CALL_RE.finditer(code):
            fn = c.group(1)
            if fn in _NOT_CALLS:
                continue
            close = _match_paren(code, c.end() - 1)
            if close < 0:
                continue
            if re.match(r"\s*\{", code[close + 1 :]):
                continue  # a function definition, not a call
            if any(mention.search(a) for a in _split_args(code[c.end() : close])):
                calls.add(fn)
    return {
        "data_param": data_param,
        "size_param": size_param,
        "direct_api_calls": sorted(calls),
        "defines_initialize": bool(_FUZZER_INIT_DEF_RE.search(code)),
    }


def parse_options(text: str) -> dict[str, Any] | None:
    """The `[libfuzzer]` section of a `.options` file: {max_len, dict}; None without one."""
    cp = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        cp.read_string(text)
    except configparser.Error:
        return None
    if not cp.has_section("libfuzzer"):
        return None
    sec = cp["libfuzzer"]
    max_len: int | None = None
    try:
        v = int(str(sec.get("max_len", "")).strip())
        max_len = v if v > 0 else None
    except ValueError:
        max_len = None
    d = str(sec.get("dict", "") or "").strip() or None
    return {"max_len": max_len, "dict": d}


def dict_entries(text: str) -> list[str]:
    """The lines of a libFuzzer dictionary that are valid entries (comments and blank lines dropped)."""
    out: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if s and not s.startswith("#") and _DICT_ENTRY_RE.match(s):
            out.append(s)
    return out


def _is_input_file(path: Path, tree: Path) -> bool:
    from seed_harvest import is_data_file

    low = path.name.lower()
    if low.endswith(_NOT_INPUT_SUFFIXES) or any(low.startswith(n) for n in _NOT_INPUT_NAMES):
        return False
    return is_data_file(path, tree)


def _corpus_like(rel_dir: str) -> bool:
    parts = rel_dir.lower().split("/")
    name = parts[-1]
    parent = parts[-2] if len(parts) > 1 else ""
    return any(w in name for w in _CORPUS_WORDS) or parent in _CORPUS_PARENTS


def scan_dir(root: Path) -> Iterator[tuple[str, str, int]]:
    """(relative posix path, kind, size) of everything under root, sorted, never following a symlink.
    kind: 'file' (regular), 'symlink', 'other'."""

    def walk(d: Path, prefix: str) -> Iterator[tuple[str, str, int]]:
        try:
            entries = sorted(os.scandir(d), key=lambda e: e.name)
        except OSError:
            return
        for e in entries:
            rel = f"{prefix}{e.name}"
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                yield rel, "other", 0
                continue
            if stat.S_ISLNK(st.st_mode) or _is_junction(Path(e.path)):
                yield rel, "symlink", 0
            elif stat.S_ISDIR(st.st_mode):
                yield from walk(Path(e.path), rel + "/")
            elif stat.S_ISREG(st.st_mode):
                yield rel, "file", st.st_size
            else:
                yield rel, "other", 0

    yield from walk(root, "")


def _zip_counts(path: Path) -> tuple[int, int, str | None]:
    try:
        with zipfile.ZipFile(path) as zf:
            infos = [i for i in zf.infolist() if not i.is_dir()]
            return len(infos), sum(max(0, i.file_size) for i in infos), None
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        return 0, 0, f"{type(exc).__name__}: {exc}"


def _skipped_dirs(target: Path) -> set[str]:
    try:
        from build_callgraph_dag import find_pipeline_output_dirs

        return set(find_pipeline_output_dirs(target))
    except Exception:  # noqa: BLE001 - discovery must not fail on the skip list
        return set()


def _walk_target(target: Path) -> tuple[list[str], list[str], list[str]]:
    """(source files, corpus-like directories, all regular files) relative to the target, posix, sorted."""
    skipped = _skipped_dirs(target)
    sources: list[str] = []
    corpus_dirs: list[str] = []
    files_all: list[str] = []
    for root, dirs, files in os.walk(target, topdown=True, followlinks=False):
        rp = Path(root)
        rel_root = "" if rp == target else rp.relative_to(target).as_posix()
        kept: list[str] = []
        for d in sorted(dirs):
            rel = f"{rel_root}/{d}" if rel_root else d
            if d == ".git" or (not rel_root and d == "workspace") or rel in skipped:
                continue
            if os.path.islink(rp / d) or _is_junction(rp / d):
                continue
            kept.append(d)
        dirs[:] = kept
        regular: list[str] = []
        for f in sorted(files):
            p = rp / f
            try:
                if not stat.S_ISREG(os.lstat(p).st_mode):
                    continue
            except OSError:
                continue
            regular.append(f)
            rel = f"{rel_root}/{f}" if rel_root else f
            files_all.append(rel)
            if Path(f).suffix in C_SUFFIXES:
                sources.append(rel)
        if rel_root and _corpus_like(rel_root) and not any(rel_root.startswith(c + "/") for c in corpus_dirs):
            data = sum(1 for f in regular if _is_input_file(rp / f, target))
            if data and data > len(regular) - data:
                corpus_dirs.append(rel_root)
    return sorted(sources), sorted(corpus_dirs), sorted(files_all)


def _is_junction(path: Path) -> bool:
    fn = getattr(os.path, "isjunction", None)
    return bool(fn(path)) if fn else False


def _resolve_options_dict(target: Path, fuzzer_rel: str, value: str, dict_files: list[str]) -> str | None:
    if value.startswith("/") or "\\" in value:
        value = value.replace("\\", "/").rsplit("/", 1)[-1]
    rel = posixpath.normpath(posixpath.join(posixpath.dirname(fuzzer_rel), value))
    if not rel.startswith("../") and rel != ".." and (st := _no_symlink_path(target, rel)) and stat.S_ISREG(st.st_mode):
        return rel
    base = posixpath.basename(value)
    hits = [d for d in dict_files if posixpath.basename(d) == base]
    return hits[0] if hits else None


def _corpus_base(path: str, kind: str) -> str:
    name = posixpath.basename(path)
    if kind == "zip":
        name = name[: -len(".zip")]
    for suffix in ("_seed_corpus", "_corpus"):
        if name.endswith(suffix) and len(name) > len(suffix):
            return name[: -len(suffix)]
    return name


def _auto_fuzzer(corpus: dict[str, Any], fuzzers: list[dict[str, Any]], stems: dict[str, str]) -> str | None:
    """The fuzzer id a corpus pairs with by OSS-Fuzz naming, else None."""
    path, kind = corpus["path"], corpus["kind"]
    name = posixpath.basename(path)
    if kind == "run_input":
        return next((f["id"] for f in fuzzers if f["id"] == name), None)
    if kind == "zip":
        if not name.endswith("_seed_corpus.zip"):
            return None
        want = name[: -len("_seed_corpus.zip")]
    else:
        parent = posixpath.basename(posixpath.dirname(path)).lower()
        if parent in _CORPUS_PARENTS:
            want = name
        elif name.endswith("_seed_corpus"):
            want = name[: -len("_seed_corpus")]
        elif name.endswith("_corpus"):
            want = name[: -len("_corpus")]
        else:
            return None
    hits = [f for f in fuzzers if stems[f["id"]] == want]
    if not hits:
        return None
    corpus_dir = posixpath.dirname(path)
    hits.sort(key=lambda f: (not corpus_dir.startswith(posixpath.dirname(f["path"])), f["path"]))
    return str(hits[0]["id"])


def suggest_sizes(doc: dict[str, Any]) -> None:
    """Recompute each fuzzer's suggested_max_input_size from its options and its imported corpora."""
    by_id = {c["id"]: c for c in doc.get("corpora") or []}
    for f in doc.get("fuzzers") or []:
        opts = f.get("options") or {}
        size = opts.get("max_len") if isinstance(opts, dict) else None
        if not size:
            biggest = 0
            for m in doc.get("mappings") or []:
                if m.get("ignored") or m.get("fuzzer") != f["id"]:
                    continue
                imp = (by_id.get(m.get("corpus")) or {}).get("imported")
                if isinstance(imp, dict):
                    biggest = max(biggest, int(imp.get("max_input_bytes") or 0))
            size = biggest or MIN_SUGGESTED_SIZE
        f["suggested_max_input_size"] = max(MIN_SUGGESTED_SIZE, min(MAX_SUGGESTED_SIZE, int(size)))


def discover(target: Path, inputs: Path, target_label: str, previous: dict[str, Any] | None) -> dict[str, Any]:
    warnings: list[str] = []
    sources, corpus_dirs, files_all = _walk_target(target)
    dict_files = [f for f in files_all if f.endswith(".dict")]

    # fuzzers
    found: list[tuple[str, dict[str, Any]]] = []
    for rel in sources:
        try:
            text = _read_regular(target / rel, MAX_SOURCE_BYTES).decode("utf-8", errors="replace")
        except OSError as exc:
            warnings.append(f"{rel}: unreadable: {exc}")
            continue
        info = analyse_fuzzer_source(text)
        if info is not None:
            found.append((rel, info))
    fuzzer_ids = unique_ids([posixpath.splitext(posixpath.basename(r))[0] for r, _ in found], "fuzzer")
    _clear_dir(FUZZER_DICTS_DIR)
    fuzzers: list[dict[str, Any]] = []
    stems: dict[str, str] = {}
    for fid, (rel, info) in zip(fuzzer_ids, found, strict=True):
        stem_rel = posixpath.splitext(rel)[0]
        stems[fid] = posixpath.basename(stem_rel)
        language = C_SUFFIXES[posixpath.splitext(rel)[1]]
        options: dict[str, Any] | None = None
        if f"{stem_rel}.options" in files_all:
            try:
                options = parse_options(
                    _read_regular(target / f"{stem_rel}.options", 65536).decode("utf-8", errors="replace")
                )
            except OSError as exc:
                warnings.append(f"{stem_rel}.options: unreadable: {exc}")
            if options is None:
                warnings.append(f"{stem_rel}.options: no [libfuzzer] section")
        dicts: list[str] = []
        if f"{stem_rel}.dict" in dict_files:
            dicts.append(f"{stem_rel}.dict")
        if options and options.get("dict"):
            resolved = _resolve_options_dict(target, rel, str(options["dict"]), dict_files)
            if resolved is None:
                warnings.append(f"{stem_rel}.options: dictionary {options['dict']!r} not found in the target")
            elif resolved not in dicts:
                dicts.append(resolved)
        entries: list[str] = []
        for d in dicts:
            try:
                text = _read_regular(target / d, MAX_DICT_BYTES).decode("utf-8", errors="replace")
            except OSError as exc:
                warnings.append(f"{d}: unreadable: {exc}")
                continue
            entries += [e for e in dict_entries(text) if e not in entries]
        if entries:
            _atomic_write_bytes(FUZZER_DICTS_DIR / f"{fid}.dict", ("\n".join(entries) + "\n").encode("utf-8"))
        fuzzers.append(
            {
                "id": fid,
                "path": rel,
                "work_path": f"{WORK_DIR}/{rel}",
                "language": language,
                "defines_initialize": info["defines_initialize"],
                "data_param": info["data_param"],
                "size_param": info["size_param"],
                "direct_api_calls": info["direct_api_calls"],
                "dict": dicts[0] if dicts else None,
                "options": options,
                "status": "usable" if language == "c" else "unsupported",
                "reason": None if language == "c" else "cxx",
                "suggested_max_input_size": MIN_SUGGESTED_SIZE,
            }
        )

    # corpora
    rows: list[dict[str, Any]] = []
    for rel in files_all:
        if rel.endswith("_seed_corpus.zip"):
            n, size, err = _zip_counts(target / rel)
            if err:
                warnings.append(f"{rel}: unreadable zip: {err}")
            rows.append({"path": rel, "kind": "zip", "files": n, "bytes": size})
    for rel in corpus_dirs:
        regs = [s for _, k, s in scan_dir(target / rel) if k == "file"]
        rows.append({"path": rel, "kind": "dir", "files": len(regs), "bytes": sum(regs)})
    rows.sort(key=lambda r: r["path"])
    if inputs.is_dir() and not inputs.is_symlink():
        with os.scandir(inputs) as it:
            dir_entries = sorted(it, key=lambda e: e.name)
        for e in dir_entries:
            if e.is_symlink() or _is_junction(Path(e.path)) or not e.is_dir(follow_symlinks=False):
                continue
            regs = [s for _, k, s in scan_dir(Path(e.path)) if k == "file"]
            rows.append(
                {"path": (inputs / e.name).as_posix(), "kind": "run_input", "files": len(regs), "bytes": sum(regs)}
            )
    corpus_ids = unique_ids([_corpus_base(r["path"], r["kind"]) for r in rows], "corpus")
    prev_corpora = {c.get("id"): c for c in (previous or {}).get("corpora") or [] if isinstance(c, dict)}
    corpora: list[dict[str, Any]] = []
    for cid, r in zip(corpus_ids, rows, strict=True):
        old = prev_corpora.get(cid) or {}
        same = all(old.get(k) == r[k] for k in ("path", "kind", "files", "bytes"))
        keep = same and isinstance(old.get("imported"), dict) and (CORPORA_DIR / cid).is_dir()
        corpora.append(
            {
                "id": cid,
                **r,
                "imported": old["imported"] if keep else None,
                "dir": old.get("dir") if keep else None,
            }
        )

    # mappings: the agent's (kept while their ids exist), then OSS-Fuzz naming for the rest
    ids_c = {c["id"] for c in corpora}
    ids_f = {f["id"] for f in fuzzers}
    mappings: list[dict[str, Any]] = []
    for m in (previous or {}).get("mappings") or []:
        if not isinstance(m, dict) or m.get("source") != "agent":
            continue
        if m.get("corpus") not in ids_c:
            warnings.append(f"agent mapping of corpus {m.get('corpus')!r} dropped: the corpus is gone")
            continue
        if m.get("fuzzer") and m["fuzzer"] not in ids_f:
            warnings.append(f"agent mapping of corpus {m['corpus']!r} dropped: fuzzer {m['fuzzer']!r} is gone")
            continue
        mappings.append(m)
    mapped = {m["corpus"] for m in mappings}
    for c in corpora:
        if c["id"] in mapped:
            continue
        auto = _auto_fuzzer(c, fuzzers, stems)
        if auto:
            mappings.append(
                {"corpus": c["id"], "fuzzer": auto, "functions": [], "ignored": False, "reason": None, "source": "auto"}
            )
    mappings.sort(key=lambda m: m["corpus"])
    doc: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "target": target_label,
        "fuzzers": fuzzers,
        "corpora": corpora,
        "mappings": mappings,
        "warnings": warnings,
    }
    suggest_sizes(doc)
    return doc


# ---------------------------------------------------------------------------------------------------
# map
# ---------------------------------------------------------------------------------------------------


def set_mapping(
    doc: dict[str, Any],
    corpus: str,
    fuzzer: str | None = None,
    functions: list[str] | None = None,
    ignore_reason: str | None = None,
) -> dict[str, Any]:
    if corpus not in {c["id"] for c in doc.get("corpora") or []}:
        raise UsageError(f"unknown corpus id {corpus!r}")
    if fuzzer is not None and fuzzer not in {f["id"] for f in doc.get("fuzzers") or []}:
        raise UsageError(f"unknown fuzzer id {fuzzer!r}")
    fns = [f for f in (functions or []) if f]
    if functions is not None and not fns:
        raise UsageError("--function needs at least one function name")
    if functions is not None and any(not re.fullmatch(r"[A-Za-z_]\w*", f) for f in fns):
        raise UsageError(f"not C identifiers: {fns}")
    row = {
        "corpus": corpus,
        "fuzzer": fuzzer,
        "functions": sorted(set(fns)),
        "ignored": ignore_reason is not None,
        "reason": ignore_reason,
        "source": "agent",
    }
    doc["mappings"] = sorted(
        [m for m in doc.get("mappings") or [] if m.get("corpus") != corpus] + [row], key=lambda m: m["corpus"]
    )
    suggest_sizes(doc)
    return row


# ---------------------------------------------------------------------------------------------------
# import
# ---------------------------------------------------------------------------------------------------


class _Importer:
    def __init__(self, out_dir: Path) -> None:
        self.out_dir = out_dir
        self.digests: set[str] = set()
        self.bytes = 0
        self.max_input = 0
        self.dropped = {k: 0 for k in ("too_large", "over_cap", "empty", "symlink", "not_regular", "unreadable")}

    def full(self, size: int) -> bool:
        return len(self.digests) >= MAX_INPUTS_PER_CORPUS or self.bytes + size > MAX_CORPUS_BYTES

    def precheck(self, size: int) -> bool:
        """False (and counted) when a declared size already rules the input out."""
        if size == 0:
            self.dropped["empty"] += 1
        elif size > MAX_INPUT_BYTES:
            self.dropped["too_large"] += 1
        elif self.full(size):
            self.dropped["over_cap"] += 1
        else:
            return True
        return False

    def add(self, data: bytes) -> None:
        if not data:
            self.dropped["empty"] += 1
            return
        if len(data) > MAX_INPUT_BYTES:
            self.dropped["too_large"] += 1
            return
        digest = hashlib.sha256(data).hexdigest()
        if digest in self.digests:
            return
        if self.full(len(data)):
            self.dropped["over_cap"] += 1
            return
        _atomic_write_bytes(self.out_dir / digest[:16], data)
        self.digests.add(digest)
        self.bytes += len(data)
        self.max_input = max(self.max_input, len(data))

    def summary(self) -> dict[str, Any]:
        return {
            "kept": len(self.digests),
            "bytes": self.bytes,
            "max_input_bytes": self.max_input,
            "dropped": dict(self.dropped),
        }


def _import_dir(src: Path, imp: _Importer) -> None:
    for rel, kind, size in scan_dir(src):
        if kind == "symlink":
            imp.dropped["symlink"] += 1
        elif kind == "other":
            imp.dropped["not_regular"] += 1
        elif imp.precheck(size):
            try:
                imp.add(_read_regular(src / rel, MAX_INPUT_BYTES + 1))
            except OSError:
                imp.dropped["unreadable"] += 1


def _import_zip(src: Path, imp: _Importer, warnings: list[str], label: str) -> None:
    try:
        zf = zipfile.ZipFile(src)
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        warnings.append(f"corpus {label}: unreadable zip: {type(exc).__name__}: {exc}")
        imp.dropped["unreadable"] += 1
        return
    with zf:
        for info in sorted(zf.infolist(), key=lambda i: i.filename):
            if info.is_dir():
                continue
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                imp.dropped["symlink"] += 1
                continue
            if info.create_system == 3 and stat.S_IFMT(mode) and not stat.S_ISREG(mode):
                imp.dropped["not_regular"] += 1
                continue
            if not imp.precheck(info.file_size):
                continue
            try:
                with zf.open(info) as fh:
                    data = fh.read(MAX_INPUT_BYTES + 1)  # the declared size may lie: bounded read
            except (zipfile.BadZipFile, OSError, ValueError, NotImplementedError, RuntimeError, zlib.error, EOFError):
                imp.dropped["unreadable"] += 1
                continue
            imp.add(data)


def import_corpora(doc: dict[str, Any], target: Path) -> dict[str, Any]:
    warnings = [w for w in doc.get("warnings") or [] if not w.startswith(("unmapped corpora", "corpus "))]
    active = {m["corpus"] for m in doc.get("mappings") or [] if not m.get("ignored")}
    unmapped = sorted(
        c["id"] for c in doc.get("corpora") or [] if c["id"] not in {m["corpus"] for m in doc["mappings"]}
    )
    summary: dict[str, Any] = {}
    for c in doc.get("corpora") or []:
        cid = c["id"]
        if not _ID_RE.match(cid) or cid in (".", ".."):
            warnings.append(f"corpus {cid!r}: invalid id, not imported")
            continue
        out_dir = CORPORA_DIR / cid
        _clear_dir(out_dir)
        if cid not in active:
            c["imported"], c["dir"] = None, None
            continue
        out_dir.mkdir(parents=True, exist_ok=True)
        base = Path(".") if c["kind"] == "run_input" else target
        imp = _Importer(out_dir)
        st = _no_symlink_path(base, c["path"])
        if st is None:
            warnings.append(f"corpus {cid}: {c['path']} missing or behind a symlink")
            imp.dropped["unreadable"] += 1
        elif c["kind"] == "zip":
            if stat.S_ISREG(st.st_mode):
                _import_zip(base / c["path"], imp, warnings, cid)
            else:
                imp.dropped["not_regular"] += 1
        elif stat.S_ISDIR(st.st_mode):
            _import_dir(base / c["path"], imp)
        else:
            imp.dropped["not_regular"] += 1
        c["imported"] = imp.summary()
        c["dir"] = out_dir.as_posix()
        summary[cid] = c["imported"]["kept"]
    if unmapped:
        warnings.append(
            f"unmapped corpora not imported: {', '.join(unmapped)} (pair them with fuzz_assets.py map, or ignore them)"
        )
    doc["warnings"] = warnings
    suggest_sizes(doc)
    return {"imported": summary, "unmapped": unmapped}


# ---------------------------------------------------------------------------------------------------
# write
# ---------------------------------------------------------------------------------------------------


def _corpus_inputs(cid: str) -> list[bytes]:
    d = CORPORA_DIR / cid
    out: list[bytes] = []
    if not _ID_RE.match(cid) or d.is_symlink() or not d.is_dir():
        return out
    for rel, kind, _ in scan_dir(d):
        if kind == "file" and "/" not in rel and not rel.startswith("."):
            try:
                out.append(_read_regular(d / rel, MAX_INPUT_BYTES + 1))
            except OSError:
                continue
    return out


def _whole_input_selectors(sidecar: dict[str, Any], harness_c: str, functions: set[str]) -> list[int | None]:
    """The cases of a harness that pass their whole input to one of `functions` (selector, or None)."""
    if sidecar.get("api_cases"):
        sels: list[int | None] = []
        for lay in sidecar.get("api_cases") or []:
            if not isinstance(lay, dict) or not isinstance(lay.get("selector"), int):
                continue
            rest, calls = lay.get("rest"), list(lay.get("calls") or [])
            if lay.get("slots") or not isinstance(rest, dict) or not 0 <= lay["selector"] <= 255:
                continue
            k = rest.get("call")
            if isinstance(k, int) and 0 <= k < len(calls) and calls[k] in functions:
                sels.append(lay["selector"])
        return sels
    from seed_harvest import case_bindings, harness_cases, whole_input_cases

    bindings = [(sel, case_bindings(stmt, functions)) for sel, stmt in harness_cases(harness_c)]
    return [s for s in whole_input_cases(bindings) if s is None or 0 <= s <= 255]


def write_module(module: str, sidecar: dict[str, Any], harness_c: str, doc: dict[str, Any] | None) -> dict[str, Any]:
    out_dir = IMPORTED_DIR / module
    _clear_dir(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    max_size = int(sidecar.get("max_input_size") or 0) or DEFAULT_MAX_INPUT_SIZE
    tf = sidecar.get("target_fuzzer") if isinstance(sidecar.get("target_fuzzer"), dict) else None
    tf_id = str(tf["id"]) if tf and tf.get("id") else None
    report: dict[str, Any] = {
        "module": module,
        "generated_at": utc_now(),
        "target_fuzzer": tf_id,
        "inputs": 0,
        "dropped_too_large": 0,
        "dropped_over_cap": 0,
        "max_input_size": max_size,
        "cases": {},
        "dir": out_dir.as_posix(),
    }
    extra_dict = DICTS_DIR / f"{module}.extra.dict"
    if doc is None:
        report["reason"] = f"no {REPORT_JSON.as_posix()} (fuzz_assets.py discover has not run)"
        _clear_dir(extra_dict)
        return _store_report(module, report)
    corpora = {c["id"]: c for c in doc.get("corpora") or [] if isinstance(c, dict)}
    fuzzers = {f["id"]: f for f in doc.get("fuzzers") or [] if isinstance(f, dict)}
    seeds: dict[str, bytes] = {}
    used_fuzzers: list[str] = []

    def take(label: str, cid: str, prefix: bytes, functions: list[str]) -> None:
        case = report["cases"].setdefault(label, {"corpora": [], "functions": [], "inputs": 0})
        if cid not in case["corpora"]:
            case["corpora"].append(cid)
        case["functions"] = sorted(set(case["functions"]) | set(functions))
        for data in _corpus_inputs(cid):
            s = prefix + data
            if len(s) > max_size:
                report["dropped_too_large"] += 1
                continue
            digest = hashlib.sha256(s).hexdigest()
            if digest not in seeds:
                seeds[digest] = s
                case["inputs"] += 1

    active = [
        m
        for m in doc.get("mappings") or []
        if isinstance(m, dict)
        and not m.get("ignored")
        and isinstance((corpora.get(m.get("corpus")) or {}).get("imported"), dict)
    ]
    if tf_id is not None:
        for m in active:
            if m.get("fuzzer") == tf_id:
                take("all", m["corpus"], b"", [])
        if tf_id in fuzzers:
            used_fuzzers.append(tf_id)
    else:
        for m in active:
            fid = m.get("fuzzer")
            fns = list(m.get("functions") or []) or list((fuzzers.get(fid) or {}).get("direct_api_calls") or [])
            if not fns:
                continue
            for sel in _whole_input_selectors(sidecar, harness_c, set(fns)):
                prefix = bytes([sel]) if sel is not None else b""
                take("all" if sel is None else str(sel), m["corpus"], prefix, fns)
                if fid and fid in fuzzers and fid not in used_fuzzers:
                    used_fuzzers.append(fid)
    kept = list(seeds.items())[:MAX_INPUTS_PER_MODULE]
    report["dropped_over_cap"] = max(0, len(seeds) - MAX_INPUTS_PER_MODULE)
    report["inputs"] = len(kept)
    for digest, data in kept:
        _atomic_write_bytes(out_dir / f"{IMPORTED_PREFIX}{digest[:16]}", data)
    if not kept and not report["cases"]:
        report["reason"] = (
            f"no imported corpus is mapped to fuzzer {tf_id}"
            if tf_id
            else "no imported corpus feeds a harness case that takes the whole input"
        )
    entries: list[str] = []
    for fid in used_fuzzers:
        p = FUZZER_DICTS_DIR / f"{fid}.dict"
        if p.is_file() and not p.is_symlink():
            entries += [e for e in dict_entries(p.read_text(encoding="utf-8", errors="replace")) if e not in entries]
    if entries:
        _atomic_write_bytes(extra_dict, ("\n".join(entries) + "\n").encode("utf-8"))
    else:
        _clear_dir(extra_dict)
    return _store_report(module, report)


def _store_report(module: str, report: dict[str, Any]) -> dict[str, Any]:
    atomic_write_json(IMPORTED_REPORTS_DIR / f"{module}.json", report)
    return report


def write(modules: list[str]) -> dict[str, Any]:
    raw = load_json_optional(REPORT_JSON, None) if REPORT_JSON.is_file() else None
    doc = raw if isinstance(raw, dict) else None
    out: dict[str, Any] = {"fuzz_assets": doc is not None, "modules": {}}
    paths = sorted(HARNESS_DIR.glob("harness_*.json")) if HARNESS_DIR.is_dir() else []
    for sidecar_path in paths:
        module = sidecar_path.stem[len("harness_") :]
        if (modules and module not in modules) or not _MODULE_RE.match(module):
            continue
        sidecar = load_json_optional(sidecar_path, {}) or {}
        if not isinstance(sidecar, dict):
            continue
        c_path = sidecar_path.with_suffix(".c")
        harness_c = c_path.read_text(encoding="utf-8", errors="replace") if c_path.is_file() else ""
        rep = write_module(module, sidecar, harness_c, doc)
        out["modules"][module] = {
            k: rep[k] for k in ("inputs", "dropped_too_large", "dropped_over_cap", "reason") if k in rep
        }
    return out


# ---------------------------------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------------------------------


def save(doc: dict[str, Any], path: Path = REPORT_JSON) -> None:
    from validate_artifacts import SCHEMA_WARNING_PREFIX, schema_warning

    doc["warnings"] = [w for w in doc.get("warnings") or [] if not w.startswith(SCHEMA_WARNING_PREFIX)]
    problem = schema_warning("fuzz_assets", doc)  # R5: recorded; `validate_artifacts run-dir` fails on it
    if problem:
        doc["warnings"].append(problem)
    atomic_write_json(path, doc)


def _load_doc(path: Path) -> dict[str, Any]:
    raw = load_json_optional(path, None) if path.is_file() else None
    if not isinstance(raw, dict) or not isinstance(raw.get("corpora"), list):
        raise UsageError(f"{path.as_posix()} missing or unreadable: run fuzz_assets.py discover first")
    raw.setdefault("mappings", [])
    raw.setdefault("fuzzers", [])
    raw.setdefault("warnings", [])
    return raw


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="The target's own fuzz targets and fuzz corpora.")
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("discover", help="Find the target's fuzzers, dictionaries, options and corpora")
    d.add_argument("--target", default=DEFAULT_TARGET)
    d.add_argument("--inputs", type=Path, default=DEFAULT_INPUTS, help="run-dir drop-in for external corpora")
    d.add_argument("--out", type=Path, default=REPORT_JSON)
    m = sub.add_parser("map", help="Pair a corpus with a fuzzer or API functions, or ignore it")
    m.add_argument("--corpus", required=True)
    g = m.add_mutually_exclusive_group(required=True)
    g.add_argument("--fuzzer")
    g.add_argument("--function", nargs="+")
    g.add_argument("--ignore", action="store_true")
    m.add_argument("--reason")
    m.add_argument("--report", type=Path, default=REPORT_JSON)
    i = sub.add_parser("import", help="Copy the mapped corpora, content-addressed, under fixed limits")
    i.add_argument("--target", default=None, help="default: the report's target")
    i.add_argument("--report", type=Path, default=REPORT_JSON)
    w = sub.add_parser("write", help="Write each harness module's imported inputs")
    w.add_argument("--module", nargs="+", action="extend", default=[])
    a = p.parse_args(argv)
    try:
        if a.cmd == "discover":
            target = Path(a.target)
            if not target.is_dir():
                raise UsageError(f"target {a.target} is not a directory")
            prev = load_json_optional(a.out, None) if a.out.is_file() else None
            doc = discover(target, a.inputs, Path(a.target).as_posix(), prev if isinstance(prev, dict) else None)
            save(doc, a.out)
            mapped = {mm["corpus"] for mm in doc["mappings"]}
            summary: dict[str, Any] = {
                "fuzzers": len(doc["fuzzers"]),
                "usable_fuzzers": sum(1 for f in doc["fuzzers"] if f["status"] == "usable"),
                "corpora": len(doc["corpora"]),
                "mapped": sorted(mapped),
                "unmapped": sorted(c["id"] for c in doc["corpora"] if c["id"] not in mapped),
                "warnings": len(doc["warnings"]),
                "out": a.out.as_posix(),
            }
        elif a.cmd == "map":
            if a.ignore and not a.reason:
                raise UsageError("--ignore needs --reason")
            doc = _load_doc(a.report)
            row = set_mapping(
                doc,
                a.corpus,
                fuzzer=a.fuzzer,
                functions=a.function,
                ignore_reason=a.reason if a.ignore else None,
            )
            save(doc, a.report)
            summary = {"mapping": row}
        elif a.cmd == "import":
            doc = _load_doc(a.report)
            target = Path(a.target or doc.get("target") or DEFAULT_TARGET)
            summary = import_corpora(doc, target)
            save(doc, a.report)
            summary["warnings"] = len(doc["warnings"])
        else:
            bad = [mod for mod in a.module if not _MODULE_RE.match(mod)]
            if bad:
                raise UsageError(f"invalid module names: {bad}")
            summary = write(a.module)
    except UsageError as exc:
        print(json.dumps({"error": str(exc)}, indent=1))
        return 2
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
