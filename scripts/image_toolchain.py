#!/usr/bin/env python3
"""
Toolchain identity of the image this runs in, as JSON (stdlib only).

The build image (`framac-build`) and the analysis image (`framac-analysis`) must agree on the
Debian release, gcc and glibc: flags captured by the build mean the same thing to the analysis
side's preprocessor, and binaries built against the build's libraries link and run on the
analysis side (docs/phase0-implementation-plan.md, decision "Images").

    image_toolchain.py                       print this image's identity
    image_toolchain.py compare A.json B.json  exit 1 unless the shared fields are equal
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

# The fields both images must share; clang is reported but may differ (the build image's clang
# compiles targets that ask for it, the analysis image's builds the instrumented binaries).
SHARED = ("debian", "gcc", "glibc")


def _out(cmd: list[str]) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
    except OSError:
        return ""
    return proc.stdout.strip() if proc.returncode == 0 else ""


def identity() -> dict:
    debian = Path("/etc/debian_version")
    return {
        "debian": debian.read_text(encoding="utf-8").strip() if debian.is_file() else "",
        "gcc": _out(["gcc", "-dumpfullversion"]),
        "glibc": _out(["dpkg-query", "-W", "-f=${Version}", "libc6"]),
        "gcc_package": _out(["dpkg-query", "-W", "-f=${Version}", "gcc-14"]),
        "clang": (_out(["clang", "--version"]).splitlines() or [""])[0],
    }


def compare(a: dict, b: dict) -> list[str]:
    """Shared fields that differ (or are missing) between two identities."""
    return [f"{k}: {a.get(k)!r} != {b.get(k)!r}" for k in SHARED if not a.get(k) or a.get(k) != b.get(k)]


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[0] == "compare":
        a, b = (json.loads(Path(p).read_text(encoding="utf-8")) for p in argv[1:])
        problems = compare(a, b)
        print(json.dumps({"ok": not problems, "differences": problems}))
        return 1 if problems else 0
    print(json.dumps(identity()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
