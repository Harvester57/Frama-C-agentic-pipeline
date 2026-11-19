"""
The target's environment in the analysis image (plan step I3b).

The build image's capture (scripts/build_capture.py) exports the headers and libraries the target
needs from outside the project and libc to the run's snapshot, <run>/workspace/snapshot/:
`root/<absolute path>` plus `manifest.json` (`digest`, `files`: path -> sha256). The analysis image
has none of the target's packages; every Frama-C parse, E-ACSL, sanitizer and coverage build reads
them from there instead:

  - headers: `-idirafter <root>/<dir>` for the include directories a compile names outside the tree
    and for gcc's default system directories, searched last, so Frama-C's libc and the image's own
    headers always win;
  - generated headers: the headers the build generated in its tree (`config.h`), which the target
    does not have, under `generated/<tree-relative path>` with the manifest's `generated_dirs`;
    `-idirafter <snapshot>/generated/<dir>` for each, before the system directories;
  - generated C sources: the translation units the build generated and compiled (nginx's
    `objs/ngx_modules.c`), under `generated/<tree-relative path>` with the manifest's
    `generated_sources` (path -> sha256). They are not read from the snapshot:
    `install_generated_sources` copies them into the overlay's `baseline/` and `work/` at their tree
    path, so every consumer finds them where it finds the target's own files (`workspace/work/<path>`);
  - Frama-C's libc gaps (Frama-C parses only, `nostdinc=True`): the build image's copies of the
    libc headers Frama-C's libc lacks (`linux-libc-dev`'s `linux/*` and `asm/*`, glibc's `elf.h`),
    under `libc/<absolute path>` with the manifest's `libc`; `-idirafter <snapshot>/libc/<dir>` for
    gcc's default system directories, after the target's system headers. The analysis image's own
    `/usr/include/x86_64-linux-gnu` and `/usr/include` come last, as the fallback for an older capture
    and for the libc headers the export does not hold (what a Frama-C parse reaches beyond the build's
    dependency lists). Directories are matched as whole `-idirafter <dir>` tokens, so a unit's
    `-idirafter /usr/include/foo` does not stand for `/usr/include`;
  - libraries: `-L <root>/<dir>` with an RPATH (not RUNPATH: it also serves the libraries' own
    dependencies), so fuzzing, replay and the guardrail run the binaries without installed packages.

The snapshot is found at FRAMAC_SNAPSHOT_DIR (tests and host runs), else at the run directory's
fixed mount point. Without a snapshot every helper is the identity.
"""

from __future__ import annotations

import json
import os
import posixpath
import shlex
from collections.abc import Iterable
from pathlib import Path

SNAPSHOT_REL = "workspace/snapshot"
CONTAINER_SNAPSHOT_DIR = f"/framac-run/{SNAPSHOT_REL}"
# The build's generated headers and C sources, by tree-relative path, inside the snapshot directory.
GENERATED_REL = "generated"
# The manifest key of the generated C sources (tree-relative path -> sha256).
GENERATED_SOURCES_KEY = "generated_sources"
# The overlay's metadata file (scripts/workspace_overlay.py init), which records the installed ones.
OVERLAY_META = "overlay_meta.json"
# The build image's copies of the libc headers Frama-C's libc lacks, by absolute path, inside the snapshot.
LIBC_REL = "libc"
# System include directories gcc searches by default: their target headers come from the snapshot.
DEFAULT_SYSTEM_DIRS = ("/usr/local/include", "/usr/include/x86_64-linux-gnu", "/usr/include")
# The analysis image's own system directories, searched last by a Frama-C parse (`-nostdinc`).
IMAGE_SYSTEM_DIRS = ("/usr/include/x86_64-linux-gnu", "/usr/include")
_IDIRAFTER = "-idirafter"
_INCLUDE_DIR_OPTIONS = ("-I", "-isystem", "-idirafter", "-iquote")
_LIBRARY_SUFFIXES = (".so", ".a")


def snapshot_dir() -> Path | None:
    """The run's snapshot directory when it holds a manifest, else None."""
    d = Path(os.environ.get("FRAMAC_SNAPSHOT_DIR") or CONTAINER_SNAPSHOT_DIR)
    return d if (d / "manifest.json").is_file() else None


def _manifest(d: Path) -> dict:
    try:
        data = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def snapshot_digest() -> str | None:
    d = snapshot_dir()
    return (_manifest(d).get("digest") or None) if d else None


def include_flags(root: str | None, flags: Iterable[str]) -> list[str]:
    """
    `-idirafter` options for the target's system headers in the snapshot rooted at `root`: the include
    directories `flags` name outside the project, then gcc's default system directories, each only
    when the snapshot has it.
    """
    if not root:
        return []
    toks = list(flags)
    dirs: list[str] = []
    for i, tok in enumerate(toks):
        if tok in _INCLUDE_DIR_OPTIONS and i + 1 < len(toks):
            dirs.append(toks[i + 1])
        else:
            dirs += [tok[len(o) :] for o in _INCLUDE_DIR_OPTIONS if tok.startswith(o) and len(tok) > len(o)][:1]
    dirs += list(DEFAULT_SYSTEM_DIRS)
    out: list[str] = []
    for d in dirs:
        if not posixpath.isabs(d) or d.startswith(root):
            continue
        snap = posixpath.join(root, d.lstrip("/"))
        if snap not in out[1::2] and os.path.isdir(snap):
            out += ["-idirafter", snap]
    return out


def generated_include_flags(d: Path | None = None) -> list[str]:
    """`-idirafter` options for the build's generated-header directories in the snapshot (manifest order)."""
    d = d or snapshot_dir()
    if d is None:
        return []
    base = d / GENERATED_REL
    out: list[str] = []
    for rel in _manifest(d).get("generated_dirs") or []:
        if not isinstance(rel, str) or posixpath.isabs(rel) or ".." in rel.split("/"):
            continue
        path = base if rel in ("", ".") else base / rel
        if path.is_dir() and path.as_posix() not in out[1::2]:
            out += ["-idirafter", path.as_posix()]
    return out


def _tree_relative(rel: object) -> bool:
    """A path inside the tree: relative, forward slashes, no `..` component."""
    return (
        isinstance(rel, str)
        and bool(rel)
        and "\\" not in rel
        and not posixpath.isabs(rel)
        and ".." not in rel.split("/")
    )


def generated_source_paths(d: Path | None = None) -> dict[str, str]:
    """
    Tree-relative path -> sha256 of the C sources the build generated, from the snapshot manifest
    (`generated_sources`); {} without a snapshot or for a capture that kept none.
    """
    d = d or snapshot_dir()
    if d is None:
        return {}
    data = _manifest(d).get(GENERATED_SOURCES_KEY)
    if not isinstance(data, dict):
        return {}
    return {rel: digest for rel, digest in data.items() if _tree_relative(rel) and isinstance(digest, str)}


def install_generated_sources(overlay: Path, snapshot: Path | None = None) -> dict[str, list[str]]:
    """
    Copy the C sources the build generated from the snapshot (`<snapshot>/generated/<path>`, manifest
    `generated_sources`) into the overlay `overlay` (the run's `workspace/`) at the same tree-relative
    path, in both `baseline/` and `work/`, so the one path rule every consumer uses (`workspace/work/
    <path>`) finds them after the scratch volume is gone, and the ACSL-only checks and apply-in-place
    compare `work/` against a baseline. `snapshot` defaults to `<overlay>/snapshot`.

    Per path, the result lists it under `installed` (copied now), `current` (both copies already equal
    to the snapshot's), `annotated` (`work/` differs from `baseline/`: merged ACSL, left alone) or
    `missing` (named by the manifest, absent from the snapshot). The overlay's metadata records the
    installed set as `generated_sources` (path -> sha256), which apply-in-place never writes into the
    target. Nothing happens without an initialized overlay (`baseline/` and `work/`) or a snapshot that
    kept generated sources: a target whose build generates none keeps its overlay as it was.
    """
    overlay = Path(overlay)
    snapshot = Path(snapshot) if snapshot is not None else overlay / Path(SNAPSHOT_REL).name
    out: dict[str, list[str]] = {"installed": [], "current": [], "annotated": [], "missing": []}
    work, base = overlay / "work", overlay / "baseline"
    sources = generated_source_paths(snapshot)
    if not sources or not work.is_dir() or not base.is_dir():
        return out
    kept: dict[str, str] = {}
    for rel in sorted(sources):
        src = snapshot / GENERATED_REL / rel
        if not src.is_file():
            out["missing"].append(rel)
            continue
        data = src.read_bytes()
        kept[rel] = sources[rel]
        work_file, base_file = work / rel, base / rel
        work_bytes = work_file.read_bytes() if work_file.is_file() else None
        base_bytes = base_file.read_bytes() if base_file.is_file() else None
        if work_bytes is not None and work_bytes != (base_bytes if base_bytes is not None else data):
            out["annotated"].append(rel)
            continue
        if work_bytes == data and base_bytes == data:
            out["current"].append(rel)
            continue
        for dest in (base_file, work_file):
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
        out["installed"].append(rel)
    meta_path = overlay / OVERLAY_META
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.is_file() else {}
    except (OSError, ValueError):
        meta = {}
    meta = meta if isinstance(meta, dict) else {}
    if meta.get(GENERATED_SOURCES_KEY) != kept:
        meta[GENERATED_SOURCES_KEY] = kept
        tmp = meta_path.with_name(f".{meta_path.name}.{os.getpid()}.tmp")
        tmp.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8", newline="\n")
        os.replace(tmp, meta_path)
    return out


def library_dirs(d: Path | None = None) -> list[str]:
    """Snapshot directories holding a library, in manifest order (`/lib/...` and `/usr/lib/...` alike)."""
    d = d or snapshot_dir()
    if d is None:
        return []
    root = (d / "root").as_posix()
    out: list[str] = []
    for path in _manifest(d).get("files") or {}:
        name = posixpath.basename(path)
        if name.endswith(_LIBRARY_SUFFIXES) or ".so." in name:
            lib_dir = posixpath.join(root, posixpath.dirname(path).lstrip("/"))
            if lib_dir not in out:
                out.append(lib_dir)
    return out


def link_flags(d: Path | None = None) -> list[str]:
    """`-L` and RPATH options for the snapshot's libraries (empty without a snapshot or libraries)."""
    dirs = library_dirs(d)
    if not dirs:
        return []
    out: list[str] = []
    for lib_dir in dirs:
        out += ["-L", lib_dir, f"-Wl,-rpath,{lib_dir}", f"-Wl,-rpath-link,{lib_dir}"]
    return [*out, "-Wl,--disable-new-dtags"]


def libc_include_flags(d: Path | None = None) -> list[str]:
    """
    `-idirafter` options for the build image's copies of the libc headers Frama-C's libc lacks
    (`libc/` in the snapshot): gcc's default system directories that hold one, in gcc's order. Empty
    for a capture without the export (manifest key `libc` absent or empty).
    """
    d = d or snapshot_dir()
    if d is None or not _manifest(d).get("libc"):
        return []
    base = d / LIBC_REL
    out: list[str] = []
    for sys_dir in DEFAULT_SYSTEM_DIRS:
        path = base / sys_dir.lstrip("/")
        if path.is_dir():
            out += [_IDIRAFTER, path.as_posix()]
    return out


def image_system_dirs() -> list[str]:
    """The analysis image's own system include directories that exist here."""
    return [d for d in IMAGE_SYSTEM_DIRS if os.path.isdir(d)]


def idirafter_dirs(words: Iterable[str]) -> set[str]:
    """The directories `words` name with `-idirafter`, as whole tokens (`-idirafter DIR` or `-idirafterDIR`)."""
    toks = list(words)
    out: set[str] = set()
    for i, tok in enumerate(toks):
        if tok == _IDIRAFTER and i + 1 < len(toks):
            out.add(toks[i + 1])
        elif tok.startswith(_IDIRAFTER) and len(tok) > len(_IDIRAFTER):
            out.add(tok[len(_IDIRAFTER) :])
    return out


def with_include_flags(cppflags: str, *, nostdinc: bool = False) -> str:
    """
    `cppflags` followed by the snapshot's `-idirafter` options for them: the build's generated headers
    first, then the target's system headers. With `nostdinc` (a Frama-C parse, which searches no system
    directory of its own), then the build image's copies of the headers Frama-C's libc lacks, and last
    the analysis image's own system directories. A directory `cppflags` already names with `-idirafter`
    (the exact directory, not a prefix of it) is not added again.
    """
    d = snapshot_dir()
    if d is None and not nostdinc:
        return cppflags
    try:
        words = shlex.split(cppflags or "")
    except ValueError:
        return cppflags
    candidates: list[str] = []
    if d is not None:
        candidates += generated_include_flags(d)
        candidates += include_flags((d / "root").as_posix(), words)
        if nostdinc:
            candidates += libc_include_flags(d)
    if nostdinc:
        for sys_dir in image_system_dirs():
            candidates += [_IDIRAFTER, sys_dir]
    present = idirafter_dirs(words)
    extra: list[str] = []
    for i in range(0, len(candidates), 2):
        directory = candidates[i + 1]
        if directory not in present:
            present.add(directory)
            extra += [_IDIRAFTER, directory]
    return f"{cppflags} {shlex.join(extra)}".strip() if extra else cppflags


def with_link_flags(ldflags: str) -> str:
    """`ldflags` followed by the snapshot's library options."""
    extra = link_flags()
    return f"{ldflags} {shlex.join(extra)}".strip() if extra else ldflags
