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
# The build's generated headers, by tree-relative path, inside the snapshot directory.
GENERATED_REL = "generated"
# System include directories gcc searches by default: their target headers come from the snapshot.
DEFAULT_SYSTEM_DIRS = ("/usr/local/include", "/usr/include/x86_64-linux-gnu", "/usr/include")
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


def with_include_flags(cppflags: str) -> str:
    """
    `cppflags` followed by the snapshot's `-idirafter` options for them: the build's generated headers
    first, then the target's system headers.
    """
    d = snapshot_dir()
    if d is None:
        return cppflags
    try:
        words = shlex.split(cppflags or "")
    except ValueError:
        return cppflags
    present = {words[i + 1] for i, w in enumerate(words[:-1]) if w == "-idirafter"}
    gen = generated_include_flags(d)
    extra = [t for i in range(0, len(gen), 2) if gen[i + 1] not in present for t in gen[i : i + 2]]
    extra += include_flags((d / "root").as_posix(), words)
    return f"{cppflags} {shlex.join(extra)}".strip() if extra else cppflags


def with_link_flags(ldflags: str) -> str:
    """`ldflags` followed by the snapshot's library options."""
    extra = link_flags()
    return f"{ldflags} {shlex.join(extra)}".strip() if extra else ldflags
