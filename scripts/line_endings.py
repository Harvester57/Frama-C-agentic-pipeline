#!/usr/bin/env python3
"""
Scripts a Linux shell cannot run because of CRLF line endings (stdlib only).

A target checked out on Windows with `core.autocrlf=true` has CRLF in its working tree while its git
index is LF (`git ls-files --eol`: `i/lf w/crlf`). In the Linux build container a script with a
shebang then does not start: the kernel looks for the interpreter `/bin/sh\\r`, and `sh -c
tools/unit.sh` says `tools/unit.sh: not found` (exit 127). A shell reading a CRLF script itself fails
on its first `\\r`: `/bin/sh: 0: Illegal option -`, `configure: error: cannot run /bin/bash
./config.sub`.

`scan_crlf_scripts()` lists them: files whose first line starts with `#!` and holds a `\\r` before its
`\\n`, and the shell scripts the build runs by name without a shebang (`configure`, `config.sub`,
`*.sh`, ...) holding CRLF. It is bounded: no `.git` or pipeline output, symlinks not followed, files
with a known non-script extension, binary files (a NUL in the head) and files over MAX_FILE_BYTES
skipped, MAX_HEAD_BYTES read per file, at most `max_files` files opened.

`workspace_overlay.py init` reports them as an early warning; build_capture.py and seed_harvest.py
turn a failed build or test command (exit 126/127, `not found`, `Illegal option -`, `cannot run`)
into a hint naming them (`failure_hint()`).

    line_endings.py <dir>     # print the scan's summary as JSON (read-only)
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MAX_HEAD_BYTES = 4096
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_FILES = 20000  # files opened by one scan
MAX_HITS = 1000  # CRLF scripts kept by one scan
LISTED = 20  # paths in a summary
NAMED = 3  # paths in a warning or hint

SKIP_DIRS = frozenset({".git", ".hg", ".svn", "node_modules", "__pycache__", "build_framac"})
# Shell scripts a build runs by name (`sh config.sub`, `. ltmain.sh`), with or without a shebang.
SHELL_SCRIPT_NAMES = frozenset(
    {"configure", "config.sub", "config.guess", "config.status", "autogen.sh", "bootstrap", "install-sh",
     "ltmain.sh", "depcomp", "missing", "compile", "libtool"}
)  # fmt: skip
# Never run as scripts: not opened.
SKIP_SUFFIXES = frozenset(
    {".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx", ".inc", ".s", ".asm", ".o", ".obj",
     ".a", ".so", ".dll", ".dylib", ".exe", ".lib", ".pyc", ".class", ".jar", ".wasm", ".png",
     ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".pdf", ".gz", ".bz2", ".xz", ".zst", ".zip",
     ".tar", ".tgz", ".7z", ".json", ".xml", ".html", ".htm", ".css", ".md", ".rst", ".txt",
     ".cmake", ".der", ".pem", ".crt", ".bin", ".dat", ".ttf", ".woff", ".woff2"}
)  # fmt: skip

FIX = (
    "the target was probably checked out on Windows with core.autocrlf=true. Check it out again with LF endings "
    "(`git config --local core.autocrlf false`, `git config --local core.eol lf`, then "
    "`git rm -r --cached -q . && git reset --hard`, which discards uncommitted changes), or strip the "
    "CRs in the build recipe before they run (`sed -i 's/\\r$//' <script>...`); see "
    "docs/troubleshooting/phase0-build-and-model.md (Windows checkout)"
)
# A shell's own messages on a CRLF script, or a CR before a closing quote: bash's
# `$'\r': command not found`, env's `'python3\r': No such file or directory`.
_STRONG_RE = re.compile(r"Illegal option -\s*$|bad interpreter|cannot run /bin/(?:ba)?sh|\r'", re.MULTILINE)
_WEAK_RE = re.compile(r"not found|cannot run|No such file or directory")


@dataclass(frozen=True)
class Hit:
    path: str  # POSIX, relative to the scanned root
    first_line: str | None  # the shebang line, `\r` spelled as backslash-r; None without a shebang


@dataclass
class Scan:
    hits: list[Hit] = field(default_factory=list)
    complete: bool = True  # False: the file budget or the hit cap stopped the scan


def _is_pipeline_output_dir(path: Path) -> bool:
    try:
        from framac_common import is_pipeline_output_dir
    except ImportError:  # run as a standalone tool
        return False
    return is_pipeline_output_dir(path)


def check_file(path: Path, name: str) -> Hit | None:
    """A Hit when the file at `path` is a CRLF script (its relative POSIX path is `name`)."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(MAX_HEAD_BYTES)
    except OSError:
        return None
    if b"\0" in head:
        return None
    if head.startswith(b"#!"):
        end = head.find(b"\n")
        first = head if end < 0 else head[:end]
        if b"\r" not in first:
            return None
        text = first.decode("utf-8", errors="replace").replace("\r", "\\r")
        return Hit(name, text[:120])
    base = name.rsplit("/", 1)[-1]
    if (base in SHELL_SCRIPT_NAMES or base.endswith(".sh")) and b"\r\n" in head:
        return Hit(name, None)
    return None


def scan_crlf_scripts(root: Path | str, max_files: int = MAX_FILES) -> Scan:
    """The CRLF scripts under `root`, in sorted walk order (see the module docstring for the bounds)."""
    scan = Scan()
    opened = 0
    stack: list[tuple[Path, str]] = [(Path(root), "")]
    while stack:
        directory, rel = stack.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda e: e.name)
        except OSError:
            continue
        subdirs: list[tuple[Path, str]] = []
        for entry in entries:
            name = f"{rel}{entry.name}"
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir():
                    if entry.name in SKIP_DIRS or entry.name.startswith(".framac"):
                        continue
                    if not _is_pipeline_output_dir(Path(entry.path)):
                        subdirs.append((Path(entry.path), f"{name}/"))
                    continue
                if not entry.is_file() or os.path.splitext(entry.name)[1].lower() in SKIP_SUFFIXES:
                    continue
                if entry.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            if opened >= max_files or len(scan.hits) >= MAX_HITS:
                scan.complete = False
                return scan
            opened += 1
            hit = check_file(Path(entry.path), name)
            if hit is not None:
                scan.hits.append(hit)
        stack.extend(reversed(subdirs))
    return scan


def summary(scan: Scan, limit: int = LISTED) -> dict[str, Any]:
    """The JSON form: `count`, the first `limit` `paths`, and whether the scan saw the whole tree."""
    return {"count": len(scan.hits), "paths": [h.path for h in scan.hits[:limit]], "complete": scan.complete}


def _describe(hit: Hit) -> str:
    return f"{hit.path} ({hit.first_line})" if hit.first_line else hit.path


def _mentioned(hit: Hit, text: str) -> bool:
    parts = hit.path.split("/")
    return any("/".join(parts[i:]) in text for i in range(len(parts)))


def named(scan: Scan, text: str = "", limit: int = NAMED) -> str:
    """The first `limit` hits, those `text` (a log, a command) names first, and how many more."""
    ordered = sorted(scan.hits, key=lambda h: not _mentioned(h, text))
    listed = ", ".join(_describe(h) for h in ordered[:limit])
    more = len(scan.hits) - limit
    return f"{listed} and {more}{'+' if not scan.complete else ''} more" if more > 0 else listed


def overlay_warning(scan: Scan) -> str | None:
    """The early warning of `workspace_overlay.py init`, or None."""
    if not scan.hits:
        return None
    count = f"{len(scan.hits)}{'+' if not scan.complete else ''}"
    return (
        f"the target checkout has CRLF line endings: {count} script(s) a Linux shell cannot run as they "
        f"are ({named(scan)}); a build or test command that runs one fails with `not found` (exit 127), "
        f"`Illegal option -` or `cannot run`: {FIX}"
    )


def looks_like_crlf_failure(returncode: int | None, log: str, scan: Scan, command: str = "") -> bool:
    if not scan.hits or returncode in (0, None):
        return False
    if returncode in (126, 127) or _STRONG_RE.search(log):
        return True
    return bool(_WEAK_RE.search(log)) and any(_mentioned(h, log + "\n" + command) for h in scan.hits)


def failure_hint(what: str, returncode: int | None, log: str, scan: Scan, command: str = "") -> str | None:
    """`<what> exited <rc>; <scripts> has CRLF line endings ...`, or None when nothing points at CRLF."""
    if not looks_like_crlf_failure(returncode, log, scan, command):
        return None
    text = log + "\n" + command
    if not any(_mentioned(h, text) for h in scan.hits):
        # Nothing names one (a missing tool exits 127 too): no culprit is singled out.
        count = f"{len(scan.hits)}{'+' if not scan.complete else ''}"
        return (
            f"{what} exited {returncode}; the tree has {count} script(s) with CRLF line endings that cannot "
            f"run in the Linux container ({named(scan)}): if the command runs one, {FIX}"
        )
    first = sorted(scan.hits, key=lambda h: not _mentioned(h, text))[0]
    shebang = f" ({first.first_line})" if first.first_line else ""
    others = Scan([h for h in scan.hits if h != first], scan.complete)
    also = f"; so do {named(others, text)}" if others.hits else ""
    return (
        f"{what} exited {returncode}; {first.path} has CRLF line endings{shebang} and cannot run in the "
        f"Linux container{also}: {FIX}"
    )


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: line_endings.py <dir>", file=sys.stderr)
        return 2
    scan = scan_crlf_scripts(args[0])
    print(json.dumps({**summary(scan), "warning": overlay_warning(scan)}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
