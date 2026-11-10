#!/usr/bin/env python3
"""
gcc `-wrapper` for Frama-C's preprocessor: repairs `offsetof` with a non-constant array index.

GCC accepts `offsetof(type, member[i])` with a run-time index `i`; Frama-C stops on it ("Unable to
compute offset .member[i] in type ...: Index is not constant", libseccomp `src/arch.c:54`). Redefining
`offsetof` as `((size_t)&((type *)0)->member)` is no way out: Frama-C then keeps a null-pointer
expression where `__builtin_offsetof` gives a constant, Eva (`-warn-invalid-pointer`) reports it
invalid and cuts the path, WP loses the value, and `_Static_assert` on an offset no longer parses.

`framac_common.augment_framac_cppflags` (every model, Eva, WP and kernel-AST parse) and the E-ACSL
frontend flags (`eacsl_toolchain.build_eacsl_flag_sets`) pass `-wrapper <this script>`, so gcc runs
each subcommand as `<this script> <subcommand> <args...>`. The script runs it unchanged. When it was
the preprocessor (`cc1 -E` writing a file), it rewrites in that file only the `__builtin_offsetof(T, D)`
whose member designator D has an index that is not an integer literal:

    __builtin_offsetof(T, m[i])
      -> (__builtin_offsetof(T, m) + (__typeof__(sizeof(0)))(i) * sizeof(((( T *)0)->m)[0]))

`__builtin_offsetof(T, m)` still folds to a constant and the `sizeof` operand is never evaluated, so
Eva and WP see integer arithmetic on the index; every other `offsetof` is left as it was. Nested
designators (`a.b[i].c`, `a[i][j]`) go through `__typeof__` of the element. Comments, string and
character literals and directive lines (`#define` from `-dD`, line markers) are never touched, and
the rewrite keeps the line count. Each rewrite is reported on stderr (`[fc-cpp] <file>:<line>: ...`),
which Frama-C copies to its log. Any failure leaves the output as the preprocessor wrote it.

It also rewrites the null-pointer offset idiom behind an integer cast, as gperf writes its string-pool
tables (libseccomp `syscalls.perf.c`) and older code defines its own `offsetof`:

    (int)(size_t)&((struct stringpool_t *)0)->str5  ->  (int)(size_t)__builtin_offsetof(struct stringpool_t, str5)

GCC computes the same number; Frama-C otherwise keeps an address computed from a null pointer, which Eva
reports as an invalid pointer creation (`-warn-invalid-pointer`, a pipeline default) and, in a global
initializer, refuses to start on ("globals initialization is not computable"). Only `(I)&((T *)0)->D`
with an identifier-only cast `(I)` and a null pointer `0`, `(0)` or `((void *)0)` is touched; a pointer
cast, a further `->` or a call leaves the expression alone.

For the E-ACSL frontend only, fc_cpp_wrapper_eacsl.py runs this script with `iff=True`, which also writes
every `<==>` in an ACSL annotation as two implications (E-ACSL 35 aborts on `<==>` over a labelled term;
see `rewrite_iff_text`). Eva and WP read the annotations as written.

FRAMAC_CPP_REWRITE=off runs the subcommand without any rewrite.
"""

from __future__ import annotations

import bisect
import os
import re
import subprocess
import sys
from collections.abc import Callable, Sequence

BUILTIN = "__builtin_offsetof"
DISABLE_ENV = "FRAMAC_CPP_REWRITE"
LOG_PREFIX = "[fc-cpp]"
SIZE_T = "__typeof__(sizeof(0))"  # size_t on every machdep, without needing <stddef.h> in scope

# One pass over the preprocessed text: comments, string and character literals and directive lines are
# matched whole (and so skipped); group 1 is the builtin's name where it stands in code.
_SCAN_RE = re.compile(
    r"//[^\n]*"
    r"|/\*.*?\*/"
    r'|"(?:\\.|[^"\\\n])*"'
    r"|'(?:\\.|[^'\\\n])*'"
    r"|^[ \t]*#(?:[^\n\\]|\\.)*"
    r"|\b(" + BUILTIN + r")\b"
    r"|(?<!&)(&)(?!&)",
    re.DOTALL | re.MULTILINE,
)
# Cheap pre-filters: some call of the builtin with a `[` before the end of its statement; some member
# access through a null pointer.
_CANDIDATE_RE = re.compile(re.escape(BUILTIN) + r"\s*\([^;{}]*?\[")
_NULL_MEMBER_RE = re.compile(r"\*\s*\)\s*(?:0|\(\s*0\s*\)|\(\s*\(\s*void\s*\*\s*\)\s*0\s*\))\s*\)\s*->")
# `&` + `(`s + `((T *)0)->`: T is a struct, union or typedef name; the null pointer is `0`, `(0)` or
# `((void *)0)` (the expansion of NULL).
_NULL_HEAD_RE = re.compile(
    r"&((?:\s*\()*)\s*\(\s*\(\s*((?:(?:struct|union)\s+)?[A-Za-z_]\w*)\s*\*\s*\)\s*"
    r"(?:0|\(\s*0\s*\)|\(\s*\(\s*void\s*\*\s*\)\s*0\s*\))\s*\)\s*->"
)
# The cast in front of the `&`: an integer type, written as identifiers only (`size_t`, `unsigned long`).
_INT_CAST_RE = re.compile(r"\(\s*(?:[A-Za-z_]\w*\s+)*[A-Za-z_]\w*\s*\)\s*$")
_NOT_TYPES = frozenset({"void", "sizeof", "return", "_Alignof", "__alignof__", "typeof", "__typeof__"})
_LITERAL_RE = re.compile(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'')
_IDENT_RE = re.compile(r"\s*([A-Za-z_]\w*)")
_INT_LITERAL_RE = re.compile(r"\(*(?:0[xX][0-9A-Fa-f]+|0[bB][01]+|[0-9]+)[uUlL]*\)*")
_DIRECTIVE_RE = re.compile(r"^[ \t]*#[^\n]*", re.MULTILINE)
_MARKER_RE = re.compile(r'^[ \t]*#[ \t]*(?:line[ \t]+)?(\d+)[ \t]+"((?:[^"\\\n]|\\.)*)"', re.MULTILINE)

Segment = tuple[str, str]  # ("field", name) or ("index", expression)


def _call_span(text: str, start: int) -> tuple[int, str, str] | None:
    """(end after `)`, type text, designator text) of the builtin's call at `start`, or None."""
    i = start + len(BUILTIN)
    n = len(text)
    while i < n and text[i] in " \t\r\n":
        i += 1
    if i >= n or text[i] != "(":
        return None
    depth, comma, j = 0, -1, i
    while j < n:
        c = text[j]
        if c == "#" and not text[text.rfind("\n", 0, j) + 1 : j].strip():
            # A line marker inside the call: gcc writes them around the arguments of a macro defined in
            # a system header (the host `<stddef.h>` of E-ACSL builds). Not part of the call's text.
            nl = text.find("\n", j)
            j = n if nl < 0 else nl
            continue
        if c in "\"'":
            m = _LITERAL_RE.match(text, j)
            if m is None:
                return None
            j = m.end()
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                if c != ")" or comma < 0:
                    return None
                return j + 1, _DIRECTIVE_RE.sub("", text[i + 1 : comma]), _DIRECTIVE_RE.sub("", text[comma + 1 : j])
        elif c == "," and depth == 1 and comma < 0:
            comma = j
        j += 1
    return None


def parse_designator(designator: str) -> list[Segment] | None:
    """`m.f[i][2]` as [field m, field f, index i, index 2]; None for anything that is not a designator."""
    m = _IDENT_RE.match(designator)
    if m is None:
        return None
    segs: list[Segment] = [("field", m.group(1))]
    i, n = m.end(), len(designator)
    while i < n:
        c = designator[i]
        if c.isspace():
            i += 1
        elif c == ".":
            m = _IDENT_RE.match(designator, i + 1)
            if m is None:
                return None
            segs.append(("field", m.group(1)))
            i = m.end()
        elif c == "[":
            depth, j = 0, i
            while j < n:
                if designator[j] in "([":
                    depth += 1
                elif designator[j] in ")]":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            if j >= n or designator[j] != "]" or not designator[i + 1 : j].strip():
                return None
            # One line: the rewrite re-adds the call's newlines after it, so the line count holds.
            segs.append(("index", " ".join(designator[i + 1 : j].split())))
            i = j + 1
        else:
            return None
    return segs


def is_int_literal(expr: str) -> bool:
    """An integer literal, possibly parenthesized: the indices `__builtin_offsetof` folds itself."""
    e = "".join(expr.split())
    return bool(_INT_LITERAL_RE.fullmatch(e)) and e.count("(") == e.count(")")


def _path(segs: Sequence[Segment]) -> str:
    """Designator text of segments that start with a field."""
    out = segs[0][1]
    for kind, val in segs[1:]:
        out += f".{val}" if kind == "field" else f"[{val}]"
    return out


def offset_expression(type_text: str, segs: Sequence[Segment]) -> str | None:
    """
    The offset of `segs` in `type_text` as a sum Frama-C folds or evaluates, or None when every index
    is an integer literal (`__builtin_offsetof` then folds it as is).
    """
    if all(kind != "index" or is_int_literal(val) for kind, val in segs):
        return None
    terms: list[str] = []
    typ = " ".join(type_text.split())
    cur = ""
    i = 0
    while i < len(segs):
        if segs[i][0] == "field":
            run: list[Segment] = []
            while i < len(segs) and not (segs[i][0] == "index" and not is_int_literal(segs[i][1])):
                run.append(segs[i])
                i += 1
            path = _path(run)
            terms.append(f"{BUILTIN}({typ}, {path})")
            cur = f"(({typ} *)0)->{path}"
        else:
            terms.append(f"({SIZE_T})({segs[i][1]}) * sizeof(({cur})[0])")
            cur = f"({cur})[0]"
            i += 1
        if i < len(segs) and segs[i][0] == "field":
            typ = f"__typeof__({cur})"
    return "(" + " + ".join(terms) + ")"


def _locator(text: str) -> Callable[[int], tuple[str, int]]:
    """Position in the preprocessed text -> (source file, line), from the line markers."""
    marks = [(m.start(), m.end(), int(m.group(1)), m.group(2)) for m in _MARKER_RE.finditer(text)]
    starts = [mk[0] for mk in marks]

    def where(pos: int) -> tuple[str, int]:
        k = bisect.bisect_right(starts, pos) - 1
        if k < 0:
            return "<preprocessed>", text.count("\n", 0, pos) + 1
        _, end, line, name = marks[k]
        nl = text.find("\n", end)
        return name, line + (text.count("\n", nl + 1, pos) if 0 <= nl < pos else 0)

    return where


def _null_member_span(text: str, start: int) -> tuple[int, str] | None:
    """
    (end, replacement) for the null-pointer offset idiom `(I)&((T *)0)->D` whose `&` is at `start`, or
    None. Only behind an integer cast `(I)`: there the value is the offset of D in T, which
    `__builtin_offsetof` gives as a constant instead of an address computed from a null pointer.
    """
    cast = _INT_CAST_RE.search(text, max(0, start - 200), start)
    if cast is None or not set(re.findall(r"\w+", cast.group(0))).isdisjoint(_NOT_TYPES):
        return None
    head = _NULL_HEAD_RE.match(text, start)
    if head is None:
        return None
    opens = head.group(1).count("(")
    # The member designator: the postfix chain `m.f[i]` up to the first token that is not part of it.
    m = _IDENT_RE.match(text, head.end())
    if m is None:
        return None
    i, n = m.end(), len(text)
    while True:
        j = i
        while j < n and text[j] in " \t\r\n":
            j += 1
        if text.startswith(".", j) and not text.startswith("...", j):
            f = _IDENT_RE.match(text, j + 1)
            if f is None:
                return None
            i = f.end()
        elif text.startswith("[", j):
            depth, k = 0, j
            while k < n:
                if text[k] in "([":
                    depth += 1
                elif text[k] in ")]":
                    depth -= 1
                    if depth == 0:
                        break
                k += 1
            if k >= n or text[k] != "]":
                return None
            i = k + 1
        else:
            break
    if text.startswith(("->", "(", "++", "--"), j):  # a further dereference, call or update: not an offset
        return None
    designator = text[head.end() : i]
    for _ in range(opens):
        while i < n and text[i] in " \t\r\n":
            i += 1
        if i >= n or text[i] != ")":
            return None
        i += 1
    if re.search(r"\n[ \t]*#", text[start:i]):
        return None  # a line marker inside: leave it as the preprocessor wrote it
    segs = parse_designator(designator)
    if not segs:
        return None
    typ = " ".join(head.group(2).split())
    new = offset_expression(typ, segs) or f"{BUILTIN}({typ}, {_path(segs)})"
    return i, new


def rewrite_text(text: str) -> tuple[str, list[dict]]:
    """
    The preprocessed text with every `__builtin_offsetof` on a non-constant index and every null-pointer
    offset idiom rewritten, and one note per rewrite.
    """
    calls = BUILTIN in text and _CANDIDATE_RE.search(text) is not None
    nulls = _NULL_MEMBER_RE.search(text) is not None
    if not (calls or nulls):
        return text, []
    out: list[str] = []
    notes: list[dict] = []
    last = 0
    where: Callable[[int], tuple[str, int]] | None = None
    for m in _SCAN_RE.finditer(text):
        if m.start() < last:
            continue
        if calls and m.group(1) is not None:
            kind = "offsetof with a non-constant index"
            span = _call_span(text, m.start())
            if span is None:
                continue
            end, type_text, designator = span
            segs = parse_designator(designator)
            new = offset_expression(type_text, segs) if segs else None
        elif nulls and m.group(2) is not None:
            kind = "null-pointer offset idiom"
            null_span = _null_member_span(text, m.start())
            if null_span is None:
                continue
            end, new = null_span
        else:
            continue
        if new is None:
            continue
        original = text[m.start() : end]
        out += [text[last : m.start()], new + "\n" * original.count("\n")]
        last = end
        where = where or _locator(text)
        file, line = where(m.start())
        notes.append(
            {"file": file, "line": line, "kind": kind, "original": " ".join(original.split()), "rewritten": new}
        )
    if not notes:
        return text, []
    out.append(text[last:])
    return "".join(out), notes


# ---------------------------------------------------------------------------------------------------
# E-ACSL only: `p1 <==> p2` -> `((p1) ==> (p2)) && ((p2) ==> (p1))` inside ACSL annotations
# ---------------------------------------------------------------------------------------------------
#
# E-ACSL in Frama-C 35 aborts on a `<==>` whose operands hold a labelled term (`\old`, `\at`, or a formal
# in an `ensures`): "labels pre-analysis was not performed on construct \old(b)" (docs/upstream/
# frama-c-eacsl-iff-labelled-term.md). Two implications are the same predicate and build on 34 and 35.
# Only the E-ACSL frontend asks for this (fc_cpp_wrapper_eacsl.py): WP and Eva read the contract as written.
#
# ACSL precedence, tightest first: ... `&&`, `^^`, `||`, `==>` (right), `<==>` (left), `? :`, then binders
# (`\forall`, `\exists`, `\let`, `\lambda`), whose body runs as far right as it can. So an operand of `<==>`
# ends, at its own nesting depth, at a bracket that closes its group, `,`, `;`, `?`, `:`, `=`, another
# `<==>` or the end of the annotation; on the left it also starts after the clause keywords
# (`ensures`, `loop invariant`, ...). On the right, a binder's own `;` does not end the operand.

IFF = "<==>"
_ANNOT_RE = re.compile(
    r"/\*@(?P<block>.*?)\*/"
    r"|//@(?P<line>[^\n]*)"
    r"|//[^\n]*"
    r"|/\*.*?\*/"
    r'|"(?:\\.|[^"\\\n])*"'
    r"|'(?:\\.|[^'\\\n])*'"
    r"|^[ \t]*#(?:[^\n\\]|\\.)*",
    re.DOTALL | re.MULTILINE,
)
_ACSL_TOKEN_RE = re.compile(
    r"(?P<ws>(?:\s|@)+)"
    r"|(?P<comment>//[^\n]*)"
    r'|(?P<lit>"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\')'
    r"|(?P<word>\\?[A-Za-z_]\w*)"
    r"|(?P<op><==>|<-->|==>|-->|==|<=|>=|!=|&&|\|\||\^\^|->|\.\.|::|[^\s@])",
)
_CLAUSE_KEYWORDS = frozenset(
    {
        "requires", "ensures", "assumes", "assert", "check", "admit", "invariant", "variant", "decreases",
        "terminates", "exits", "breaks", "continues", "returns", "assigns", "allocates", "frees", "loop",
        "strong", "weak", "behavior", "reads", "lemma", "axiom", "global", "type",
    }
)  # fmt: skip
_BINDERS = frozenset({"\\forall", "\\exists", "\\let", "\\lambda"})
_LEFT_STOPS = frozenset({",", ";", "?", ":", "=", IFF})
_RIGHT_STOPS = frozenset({",", ";", "?", ":", "=", IFF})
_OPENERS, _CLOSERS = frozenset("([{"), frozenset(")]}")
_MAX_IFF_REWRITES = 256  # per annotation: `a <==> (b <==> c)` copies the inner one; bound the growth


def _acsl_tokens(body: str) -> list[tuple[str, int, int]] | None:
    """(kind, start, end) of every token of an annotation body, or None if some text does not lex."""
    toks: list[tuple[str, int, int]] = []
    pos = 0
    while pos < len(body):
        m = _ACSL_TOKEN_RE.match(body, pos)
        if m is None or m.end() == pos:
            return None
        toks.append((m.lastgroup or "op", m.start(), m.end()))
        pos = m.end()
    return toks


def _iff_operands(body: str, toks: list[tuple[str, int, int]], k: int) -> tuple[int, int, int, int] | None:
    """Token index bounds (first, last) of the left and right operands of the `<==>` at token `k`."""
    sig = [i for i, t in enumerate(toks) if t[0] not in ("ws", "comment")]
    at = sig.index(k)
    text = [body[toks[i][1] : toks[i][2]] for i in sig]

    depth, j = 0, at - 1
    while j >= 0:
        t = text[j]
        if t in _CLOSERS:
            depth += 1
        elif t in _OPENERS:
            if depth == 0:
                break
            depth -= 1
        elif depth == 0 and t in _LEFT_STOPS:
            break
        j -= 1
    lo = j + 1
    while lo < at and text[lo] in _CLAUSE_KEYWORDS:
        lo += 1

    depth, j, binder = 0, at + 1, False
    while j < len(text):
        t = text[j]
        if t in _OPENERS:
            depth += 1
        elif t in _CLOSERS:
            if depth == 0:
                break
            depth -= 1
        elif depth == 0 and t in _BINDERS:
            binder = True
        elif depth == 0 and binder and t == ";":
            binder = False  # the binder's own `;`: its body follows, still part of the operand
        elif depth == 0 and not binder and t in _RIGHT_STOPS:
            break
        j += 1
    hi = j - 1
    if lo >= at or hi <= at:
        return None
    return sig[lo], sig[at - 1], sig[at + 1], sig[hi]


def _flat(body: str, toks: list[tuple[str, int, int]], first: int, last: int) -> str:
    """The operand on one line, without comments or `@` blanks, so the copy adds no line."""
    return "".join(" " if kind in ("ws", "comment") else body[s:e] for kind, s, e in toks[first : last + 1])


def rewrite_iff_body(body: str) -> tuple[str, int]:
    """An annotation body with every `<==>` written as two implications, and the number rewritten."""
    count = 0
    while IFF in body and count < _MAX_IFF_REWRITES:
        toks = _acsl_tokens(body)
        if toks is None:
            break
        k = next((i for i, t in enumerate(toks) if body[t[1] : t[2]] == IFF), None)
        if k is None:
            break
        bounds = _iff_operands(body, toks, k)
        if bounds is None:
            break  # malformed: leave it for the kernel to report
        l0, l1, r0, r1 = bounds
        left = body[toks[l0][1] : toks[l1][2]]
        right = body[toks[r0][1] : toks[r1][2]]
        # The text around the operator keeps any newline (and comment) where it was.
        arrow = body[toks[l1][2] : toks[k][1]] + "==>" + body[toks[k][2] : toks[r0][1]]
        new = f"((({left}){arrow}({right})) && (({_flat(body, toks, r0, r1)}) ==> ({_flat(body, toks, l0, l1)})))"
        body = body[: toks[l0][1]] + new + body[toks[r1][2] :]
        count += 1
    return body, count


def rewrite_iff_text(text: str) -> tuple[str, list[dict]]:
    """The preprocessed text with every `<==>` in an ACSL annotation rewritten, and one note per annotation."""
    if IFF not in text:
        return text, []
    out: list[str] = []
    notes: list[dict] = []
    last = 0
    where: Callable[[int], tuple[str, int]] | None = None
    for m in _ANNOT_RE.finditer(text):
        group = "block" if m.group("block") is not None else "line" if m.group("line") is not None else None
        if group is None or IFF not in m.group(group):
            continue
        new_body, n = rewrite_iff_body(m.group(group))
        if not n:
            continue
        out += [text[last : m.start(group)], new_body]
        last = m.end(group)
        where = where or _locator(text)
        file, line = where(m.start())
        notes.append(
            {
                "file": file,
                "line": line,
                "kind": f"{n} `<==>` in an annotation (E-ACSL: two implications)",
                "original": " ".join(m.group(group).split())[:240],
                "rewritten": " ".join(new_body.split())[:480],
            }
        )
    if not notes:
        return text, []
    out.append(text[last:])
    return "".join(out), notes


def rewrite_file(path: str, iff: bool = False) -> list[dict]:
    """Rewrite one preprocessed file in place; fail open (the file stays as the preprocessor wrote it)."""
    try:
        with open(path, "rb") as fh:
            text = fh.read().decode("latin-1")  # byte-preserving: the C text round-trips unchanged
        new, notes = rewrite_text(text)
        if iff:
            new, iff_notes = rewrite_iff_text(new)
            notes += iff_notes
        if notes:
            tmp = f"{path}.fc-cpp"
            with open(tmp, "wb") as fh:
                fh.write(new.encode("latin-1"))
            os.replace(tmp, path)
        for n in notes:
            print(
                f"{LOG_PREFIX} {n['file']}:{n['line']}: {n['kind']} rewritten: {n['original']} -> {n['rewritten']}",
                file=sys.stderr,
            )
        return notes
    except Exception as exc:  # noqa: BLE001 - the wrapper must never fail a parse the preprocessor passed
        print(f"{LOG_PREFIX} warning: rewrite skipped for {path}: {exc}", file=sys.stderr)
        return []


def is_preprocessing(cmd: Sequence[str]) -> bool:
    """gcc's preprocessor subcommand (`cc1 -E`), not a dependency listing (`-M`/`-MM`)."""
    if not cmd or os.path.basename(cmd[0]) not in ("cc1", "cc1.exe"):
        return False
    args = set(cmd[1:])
    return "-E" in args and not args & {"-M", "-MM"}


def output_path(cmd: Sequence[str]) -> str | None:
    for i, arg in enumerate(cmd[1:], 1):
        if arg == "-o" and i + 1 < len(cmd):
            return cmd[i + 1]
        if arg.startswith("-o") and len(arg) > 2:
            return arg[2:]
    return None


def run(cmd: Sequence[str], call: Callable[[list[str]], int] = subprocess.call, iff: bool = False) -> int:
    """
    Run gcc's subcommand `cmd`; after a successful preprocessing into a file, rewrite that file. `iff`
    (the E-ACSL frontend, fc_cpp_wrapper_eacsl.py) also rewrites `<==>` in annotations.
    """
    if not cmd:
        print(f"usage: {os.path.basename(sys.argv[0])} <subcommand> [args...] (a gcc -wrapper)", file=sys.stderr)
        return 2
    rc = call(list(cmd))
    if rc != 0 or not is_preprocessing(cmd) or os.environ.get(DISABLE_ENV, "").lower() in ("0", "off", "false", "no"):
        return rc
    out = output_path(cmd)
    if out is not None and out != "-":
        rewrite_file(out, iff=iff)
    return rc


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
