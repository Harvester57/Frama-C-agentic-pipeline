"""
Keep the harness skill mirrors identical to `skills/` (stdlib only).

`skills/` is the only place skills are edited. `.agents/skills/` (harnesses that read AGENTS.md) and
`.claude/skills/` (Claude Code) are plain tracked copies of it: no symlinks, which do not survive a
Windows checkout.

    python tools/sync_skill_mirrors.py            # copy skills/ into both mirrors
    python tools/sync_skill_mirrors.py --check    # exit 1 and list the differences (pre-commit, CI)
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = "skills"
MIRRORS = (".agents/skills", ".claude/skills")
IGNORED_PARTS = frozenset({"__pycache__", ".DS_Store"})


def _files(base: Path) -> dict[str, bytes]:
    """Every regular file under `base`, by POSIX path relative to it. Symlinked entries are not followed."""
    out: dict[str, bytes] = {}
    if not base.is_dir():
        return out
    for entry in sorted(base.iterdir()):
        if entry.is_symlink() or entry.name in IGNORED_PARTS:
            continue
        if entry.is_file():
            out[entry.name] = entry.read_bytes()
        elif entry.is_dir():
            for rel, data in _files(entry).items():
                out[f"{entry.name}/{rel}"] = data
    return out


def _not_copies(mirror: Path) -> list[Path]:
    """Top-level mirror entries that are not directory copies: symlinks, or git's plain-file form of one."""
    if not mirror.is_dir():
        return []
    return [e for e in sorted(mirror.iterdir()) if e.is_symlink() or not e.is_dir()]


def mirror_drift(root: Path = ROOT) -> list[str]:
    """One line per difference between `skills/` and each mirror; empty when they are identical."""
    expected = _files(root / SOURCE)
    problems: list[str] = []
    for rel in MIRRORS:
        mirror = root / rel
        if not mirror.is_dir():
            problems.append(f"{rel}: missing")
            continue
        problems += [f"{rel}/{e.name}: not a directory copy (symlink or plain file)" for e in _not_copies(mirror)]
        actual = _files(mirror)
        problems += [f"{rel}/{k}: missing" for k in sorted(expected.keys() - actual.keys())]
        problems += [f"{rel}/{k}: not in {SOURCE}/" for k in sorted(actual.keys() - expected.keys())]
        problems += [
            f"{rel}/{k}: differs from {SOURCE}/{k}"
            for k in sorted(expected.keys() & actual.keys())
            if expected[k] != actual[k]
        ]
    return problems


def sync(root: Path = ROOT) -> list[str]:
    """Make both mirrors identical to `skills/`. Returns the mirror paths written or removed."""
    expected = _files(root / SOURCE)
    changed: list[str] = []
    for rel in MIRRORS:
        mirror = root / rel
        mirror.mkdir(parents=True, exist_ok=True)
        for entry in _not_copies(mirror):
            entry.unlink()
            changed.append(f"{rel}/{entry.name}")
        actual = _files(mirror)
        for key in sorted(actual.keys() - expected.keys()):
            (mirror / key).unlink()
            changed.append(f"{rel}/{key}")
        for key, data in sorted(expected.items()):
            if actual.get(key) != data:
                target = mirror / key
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                changed.append(f"{rel}/{key}")
        wanted_dirs = {Path(k).parts[0] for k in expected}
        for entry in sorted(mirror.iterdir()):
            if entry.is_dir() and not entry.is_symlink() and entry.name not in wanted_dirs:
                shutil.rmtree(entry)
                changed.append(f"{rel}/{entry.name}/")
    return changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="report differences and exit 1; change nothing")
    parser.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.check:
        problems = mirror_drift(args.root)
        for line in problems:
            print(line)
        if problems:
            print(
                f"{len(problems)} difference(s). Edit skills only under {SOURCE}/, "
                "then run: python tools/sync_skill_mirrors.py",
                file=sys.stderr,
            )
            return 1
        return 0
    for line in sync(args.root):
        print(f"synced {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
