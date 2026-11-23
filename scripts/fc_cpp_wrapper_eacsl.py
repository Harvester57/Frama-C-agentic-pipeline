#!/usr/bin/env python3
"""
gcc `-wrapper` for the E-ACSL frontend only: fc_cpp_wrapper.py plus two E-ACSL-only rewrites.

1. `<==>`. E-ACSL in Frama-C 35 aborts on `p1 <==> p2` when an operand holds a labelled term (`\\old`, `\\at`,
   or a formal in an `ensures`): "labels pre-analysis was not performed on construct \\old(b)"
   (docs/upstream/frama-c/frama-c-eacsl-iff-labelled-term.md). This wrapper writes every `<==>` in an
   annotation as `((p1) ==> (p2)) && ((p2) ==> (p1))` in the preprocessed text, so contracts already proved
   with `<==>` (merged, carried forward, or in the target's headers) still build.

2. `static const union`. With full memory tracking, E-ACSL passes the value of a monitored const global to
   `__e_acsl_mark_readonly` instead of its address; for a union the kernel rejects the generated cast
   (`implicit cast: cast from union u to void *`, pub/frama-c#2795, Issues 23 and 27 of
   docs/upstream/frama-c/README.md). This wrapper drops `const` from every object declared `static const union`
   (local or at file scope, initialized or not), replacing the keyword with blanks so lines and columns stay put.
   E-ACSL then no longer treats the object as read-only, and the E-ACSL binary, compiled from that text, holds
   it as writable data: a write to it through a cast pointer is not caught in that binary. The sanitizer and
   coverage builds compile the original source, and Eva and WP read it. A pointer (`static const union u *p`)
   or a function returning a union is left alone:
   neither is a const union object. Each rewrite is reported on stderr like the others
   (`[fc-cpp] <file>:<line>: static const union rewritten: ...`); fuzz_build counts those lines into the build
   report (`const_union_rewrites`). Set REWRITE_STATIC_CONST_UNIONS to False once the analysis image carries
   the upstream fix (it is part of every build cache key, as the whole scripts/ directory is).

WP and Eva use fc_cpp_wrapper.py and read the source as written. A separate script rather than a
`-wrapper prog,arg` argument: e-acsl-gcc splits flag values on commas. FRAMAC_CPP_REWRITE=off turns off every
rewrite, these two included.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from collections.abc import Callable, Sequence

from fc_cpp_wrapper import DISABLE_ENV, LOG_PREFIX, _locator, is_preprocessing, output_path, run

# The switch: False now that the analysis image carries the fix of pub/frama-c#2795 (merge request pub/frama-c!26)
# via opam/packages/frama-c/frama-c.34.0~beta/files/27-eacsl-readonly-scalar-global-address.patch.
REWRITE_STATIC_CONST_UNIONS = False
CONST_UNION_KIND = "static const union"

# Comments, string and character literals and directive lines are matched whole (and so skipped); group 1 is
# `static const union` or `const static union`, group 2 the `const` keyword in it.
_CONST_UNION_SCAN_RE = re.compile(
    r"//[^\n]*"
    r"|/\*.*?\*/"
    r'|"(?:\\.|[^"\\\n])*"'
    r"|'(?:\\.|[^'\\\n])*'"
    r"|^[ \t]*#(?:[^\n\\]|\\.)*"
    r"|(?<![\w$])((?:static\s+(const)|(const)\s+static)\s+union)(?![\w$])",
    re.DOTALL | re.MULTILINE,
)
_WORD_RE = re.compile(r"\s*([A-Za-z_]\w*)")
# One `[fc-cpp]` report of this rewrite in a build log: `<prefix> <file>:<line>: static const union rewritten: ...`.
_CONST_UNION_LOG_RE = re.compile(
    r"^" + re.escape(LOG_PREFIX) + r" (?P<where>.+?:\d+): " + re.escape(CONST_UNION_KIND) + r" rewritten:",
    re.MULTILINE,
)


def _skip_ws(text: str, i: int) -> int:
    while i < len(text) and text[i].isspace():
        i += 1
    return i


def _declares_object(text: str, after_union: int) -> bool:
    """
    Whether the `static const union` ending at `after_union` declares a union object: not a pointer to one
    (`static const union u *p`) and not a function returning one (`static const union u f(void)`).
    """
    i = _skip_ws(text, after_union)
    tag = _WORD_RE.match(text, i)
    if tag is not None:
        i = _skip_ws(text, tag.end())
    if i < len(text) and text[i] == "{":  # an inline member list: skip it
        depth = 0
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        if i >= len(text):
            return False
        i = _skip_ws(text, i + 1)
    if i >= len(text) or text[i] in "*(":
        return False
    name = _WORD_RE.match(text, i)
    if name is None:
        return False
    j = _skip_ws(text, name.end())
    return j < len(text) and text[j] != "("


def rewrite_const_union_text(text: str) -> tuple[str, list[dict]]:
    """The preprocessed text with `const` blanked out of every `static const union` object, and one note each."""
    if "union" not in text or "const" not in text or "static" not in text:
        return text, []
    out: list[str] = []
    notes: list[dict] = []
    last = 0
    where: Callable[[int], tuple[str, int]] | None = None
    for m in _CONST_UNION_SCAN_RE.finditer(text):
        if m.group(1) is None or not _declares_object(text, m.end(1)):
            continue
        kw = 2 if m.group(2) is not None else 3
        out += [text[last : m.start(kw)], " " * len("const")]
        last = m.end(kw)
        where = where or _locator(text)
        file, line = where(m.start())
        end = text.find(";", m.end())
        end = min(end if end >= 0 else len(text), m.end() + 160)
        original = " ".join(text[m.start() : end].split())
        notes.append(
            {
                "file": file,
                "line": line,
                "kind": CONST_UNION_KIND,
                "original": original,
                "rewritten": " ".join((text[m.start() : m.start(kw)] + text[m.end(kw) : end]).split()),
            }
        )
    if not notes:
        return text, []
    out.append(text[last:])
    return "".join(out), notes


def rewrite_const_union_file(path: str) -> list[dict]:
    """Rewrite one preprocessed file in place; fail open (the file stays as it was)."""
    try:
        with open(path, "rb") as fh:
            text = fh.read().decode("latin-1")  # byte-preserving
        new, notes = rewrite_const_union_text(text)
        if notes:
            tmp = f"{path}.fc-cpp-eacsl"
            with open(tmp, "wb") as fh:
                fh.write(new.encode("latin-1"))
            os.replace(tmp, path)
        for n in notes:
            print(
                f"{LOG_PREFIX} {n['file']}:{n['line']}: {n['kind']} rewritten: {n['original']} -> {n['rewritten']}"
                " (E-ACSL only: E-ACSL no longer checks the object as read-only)",
                file=sys.stderr,
            )
        return notes
    except Exception as exc:  # noqa: BLE001 - the wrapper must never fail a parse the preprocessor passed
        print(f"{LOG_PREFIX} warning: static const union rewrite skipped for {path}: {exc}", file=sys.stderr)
        return []


def count_const_union_rewrites(log: str) -> int:
    """
    The `static const union` declarations the wrapper rewrote, from the `[fc-cpp]` lines of one E-ACSL
    frontend run: one per source location, as a header that several sources include is preprocessed once each.
    """
    return len({m.group("where") for m in _CONST_UNION_LOG_RE.finditer(log)})


def const_union_rewrite_active(frontend_flags: str) -> bool:
    """Whether an E-ACSL frontend run with `frontend_flags` gets the `static const union` rewrite."""
    return (
        REWRITE_STATIC_CONST_UNIONS
        and os.path.basename(__file__) in frontend_flags
        and os.environ.get(DISABLE_ENV, "").lower() not in ("0", "off", "false", "no")
    )


def run_eacsl(
    cmd: Sequence[str],
    call: Callable[[list[str]], int] = subprocess.call,
    const_unions: bool | None = None,
) -> int:
    """fc_cpp_wrapper.run with the `<==>` rewrite, then the `static const union` one on the preprocessed file."""
    rc = run(cmd, call=call, iff=True)
    enabled = REWRITE_STATIC_CONST_UNIONS if const_unions is None else const_unions
    if rc != 0 or not enabled or not is_preprocessing(cmd):
        return rc
    if os.environ.get(DISABLE_ENV, "").lower() in ("0", "off", "false", "no"):
        return rc
    out = output_path(cmd)
    if out is not None and out != "-":
        rewrite_const_union_file(out)
    return rc


if __name__ == "__main__":
    sys.exit(run_eacsl(sys.argv[1:]))
