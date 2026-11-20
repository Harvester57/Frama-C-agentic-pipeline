#!/usr/bin/env python3
"""
Deterministic C/ACSL lexical analyzer, annotation-only verifier, and function span splicer.

Used by scripts/workspace_overlay.py to enforce Milestone 2 isolation guarantees:
1. Subagents may only add or modify ACSL comments (/*@ ... */ and //@ ...);
   every executable C token, literal, normal comment, and preprocessor directive
   must match workspace/baseline/ identically.
2. Unsound ACSL directives (admit, axiom, axiomatic) are rejected in agent patches.
3. A Function Prover assigned to function F may only modify ACSL within F's
   contract+body span in its .c file and F's contract+prototype span in its .h file,
   enabling conflict-free structural splicing when same-wave provers annotate
   different functions in the same file.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path


class AcslError(RuntimeError):
    """Base exception for ACSL lexical, annotation-only, or scope errors."""


class AcslSyntaxError(AcslError):
    """
    Raised when a C/H file contains an unclosed comment or string/char literal.

    The message keeps its `path:line: unclosed ...` text. Callers that need the position read the
    attributes instead of parsing it:
    - `line`: 1-based line of the construct that does not close, or None;
    - `kind`: `acsl_block_comment`, `c_block_comment`, `string_literal` or `char_literal`, or None;
    - `offset`: offset in the tokenized text of the first character of that construct, or None.
    """

    def __init__(
        self, message: str = "", *, line: int | None = None, kind: str | None = None, offset: int | None = None
    ) -> None:
        super().__init__(message)
        self.line = line
        self.kind = kind
        self.offset = offset


class ScopeViolationError(AcslError):
    """Raised when an agent modifies tokens outside its assigned function or header scope."""


class ConflictingProfileError(AcslError):
    """Raised when an ACSL predicate or logic declaration conflicts with an existing declaration profile."""


@dataclass(slots=True, frozen=True)
class Token:
    """A single lexical token in a C/ACSL source file."""

    kind: str  # whitespace | acsl_block | acsl_line | c_comment | pp_directive | string | char | c_token
    text: str
    start: int
    end: int
    line: int


@dataclass(slots=True, frozen=True)
class Span:
    """Byte and line span of a function definition or prototype declaration (including its ACSL contract)."""

    function: str
    start_byte: int
    end_byte: int
    start_line: int
    end_line: int
    text: str


_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_NUMBER_RE = re.compile(r"[0-9][A-Za-z0-9_.]*")
_UNSOUND_ACSL_RE = re.compile(r"\b(admit|axiom|axiomatic|inductive)\b")
_C_INT_TYPE_CORE = (
    r"(?:(?:(?:unsigned|signed)\s+)*(?:int|long|short|char)|unsigned|signed|"
    r"size_t|ssize_t|ptrdiff_t|u?int(?:8|16|32|64|ptr)_t)"
)
_LOGIC_C_INT_RE = re.compile(rf"\blogic\s+(?:const\s+)?{_C_INT_TYPE_CORE}\b")
_LOGIC_DECL_RE = re.compile(
    r"\blogic\s+[A-Za-z_][A-Za-z0-9_*\s]*?\b[A-Za-z_][A-Za-z0-9_]*(?:\s*\{[^}]*\})?\s*\(([^)]*)\)"
)
_C_INT_PARAM_RE = re.compile(rf"^\s*(?:const\s+)?{_C_INT_TYPE_CORE}\s+[A-Za-z_][A-Za-z0-9_]*\s*$")
_INVARIANT_CLAUSE_RE = re.compile(r"(?:(loop|type|global|strong)\s+)?\binvariant\b(?!\s*:)")
_VACUOUS_CLAUSE_HEAD_RE = re.compile(r"(?<![\\\w])(requires|assumes|loop\s+invariant)\b")
_EMPTY_BEHAVIOR_RE = re.compile(r"\bbehavior\s+[A-Za-z_][A-Za-z0-9_]*\s*:\s*;")
_COMMENT_IN_ACSL_RE = re.compile(r"//(?![@])[^\n]*")
# A backslash that ends a line: cpp joins the next line to it (it accepts blanks after the backslash).
_SPLICED_LINE_RE = re.compile(r"\\[ \t\r]*(?:\n|\Z)")
# A ghost function's own contract, written `/@ ... @/` inside a `/*@ ghost ... */` block.
_GHOST_CONTRACT_RE = re.compile(r"/@.*?@/", re.DOTALL)
_ESCAPED_CTRL_IN_ACSL_RE = re.compile(r"[\x07\x08\x0c]")


def tokenize_c_acsl(source: str, path: str = "<input>") -> list[Token]:
    """Tokenize C source with ACSL annotations into a complete, lossless token stream."""
    tokens: list[Token] = []
    n = len(source)
    i = 0
    line = 1
    at_line_start = True

    while i < n:
        ch = source[i]

        # 1. Whitespace
        if ch in " \t\r\n\f\v":
            start = i
            start_line = line
            while i < n and source[i] in " \t\r\n\f\v":
                if source[i] == "\n":
                    line += 1
                    at_line_start = True
                elif source[i] not in " \t\r":
                    at_line_start = False
                i += 1
            tokens.append(Token("whitespace", source[start:i], start, i, start_line))
            continue

        # 2. Block comments: /*@ ... */ (ACSL) vs /* ... */ (normal C comment)
        if ch == "/" and i + 1 < n and source[i + 1] == "*":
            start = i
            start_line = line
            is_acsl = i + 2 < n and source[i + 2] == "@" and (i + 3 >= n or source[i + 3] != "/")
            i += 2
            closed = False
            while i < n:
                if source[i] == "\n":
                    line += 1
                if source[i] == "*" and i + 1 < n and source[i + 1] == "/":
                    i += 2
                    closed = True
                    break
                i += 1
            if not closed:
                raise AcslSyntaxError(
                    f"{path}:{start_line}: unclosed {'ACSL' if is_acsl else 'C'} block comment",
                    line=start_line,
                    kind="acsl_block_comment" if is_acsl else "c_block_comment",
                    offset=start,
                )
            at_line_start = False
            tokens.append(Token("acsl_block" if is_acsl else "c_comment", source[start:i], start, i, start_line))
            continue

        # 3. Line comments: //@ ... (ACSL) vs // ... (normal C comment)
        if ch == "/" and i + 1 < n and source[i + 1] == "/":
            start = i
            start_line = line
            is_acsl = i + 2 < n and source[i + 2] == "@"
            i += 2
            while i < n and source[i] != "\n":
                i += 1
            at_line_start = False
            tokens.append(Token("acsl_line" if is_acsl else "c_comment", source[start:i], start, i, start_line))
            continue

        # 4. Preprocessor directive (# at start of logical line)
        if ch == "#" and at_line_start:
            start = i
            start_line = line
            while i < n:
                if source[i] == "\\" and i + 1 < n and source[i + 1] == "\n":
                    line += 1
                    i += 2
                    continue
                if source[i] == "\\" and i + 2 < n and source[i + 1] == "\r" and source[i + 2] == "\n":
                    line += 1
                    i += 3
                    continue
                if source[i] == "\n":
                    break
                i += 1
            at_line_start = False
            tokens.append(Token("pp_directive", source[start:i], start, i, start_line))
            continue

        at_line_start = False

        # 5. String or character literal
        if ch in ('"', "'"):
            quote = ch
            start = i
            start_line = line
            i += 1
            closed = False
            while i < n:
                c = source[i]
                if c == "\\":
                    if i + 1 < n and source[i + 1] == "\n":
                        line += 1
                    i += 2
                    continue
                if c == "\n":
                    break
                if c == quote:
                    i += 1
                    closed = True
                    break
                i += 1
            if not closed:
                lit_kind = "string" if quote == '"' else "character"
                raise AcslSyntaxError(
                    f"{path}:{start_line}: unclosed {lit_kind} literal",
                    line=start_line,
                    kind="string_literal" if quote == '"' else "char_literal",
                    offset=start,
                )
            tokens.append(Token("string" if quote == '"' else "char", source[start:i], start, i, start_line))
            continue

        # 6. Identifier
        m_id = _IDENT_RE.match(source, i)
        if m_id:
            end = m_id.end()
            tokens.append(Token("c_token", source[i:end], i, end, line))
            i = end
            continue

        # 7. Number
        m_num = _NUMBER_RE.match(source, i)
        if m_num:
            end = m_num.end()
            tokens.append(Token("c_token", source[i:end], i, end, line))
            i = end
            continue

        # 8. Single punctuation / operator character
        tokens.append(Token("c_token", ch, i, i + 1, line))
        i += 1

    return tokens


# ---------------------------------------------------------------------------
# Comment and literal masking (one lexer for every "strip the comments" need)
# ---------------------------------------------------------------------------

_LEXICAL_SPAN_KINDS = frozenset({"c_comment", "acsl_block", "acsl_line", "string", "char"})
_UNCLOSED_LABELS = {
    "acsl_block_comment": "ACSL block comment",
    "c_block_comment": "C block comment",
    "string_literal": "string literal",
    "char_literal": "character literal",
}
_NOT_LINE_END_RE = re.compile(r"[^\r\n]")
# The kernel's lexer enters ghost code when an annotation starts with `ghost`, after blanks and `@` only.
_GHOST_ANNOTATION_RE = re.compile(r"[ \t\r\n@]*ghost")


def _directive_comment_spans(text: str, start: int, end: int) -> tuple[list[tuple[str, int, int]], int | None]:
    """
    Comments inside the preprocessor directive `text[start:end]` (one token for the tokenizer), and the offset
    of a block comment the directive leaves open (it then continues on the following lines), or None. A quote
    that does not close on the directive (`#error don't`) is an ordinary character.
    """
    spans: list[tuple[str, int, int]] = []
    i = start
    while i < end:
        ch = text[i]
        if ch in "\"'":
            j = i + 1
            closed = False
            while j < end:
                c = text[j]
                if c == "\\":
                    j += 2
                    continue
                if c == "\n":
                    break
                if c == ch:
                    closed = True
                    break
                j += 1
            i = j + 1 if closed else i + 1
            continue
        if ch == "/" and i + 1 < end and text[i + 1] == "/":
            spans.append(("c_comment", i, end))
            return spans, None
        if ch == "/" and i + 1 < end and text[i + 1] == "*":
            close = text.find("*/", i + 2, end)
            if close == -1:
                return spans, i
            spans.append(("c_comment", i, close + 2))
            i = close + 2
            continue
        i += 1
    return spans, None


def comment_and_literal_spans(
    text: str, *, on_error: str = "raise", path: str = "<input>"
) -> list[tuple[str, int, int]]:
    """
    The comments and literals of C/ACSL `text` as `(kind, start, end)`, in source order and never overlapping.
    `kind` is `c_comment`, `acsl_block`, `acsl_line`, `string` or `char`; `text[start:end]` is the whole
    construct with its delimiters. The lexer is `tokenize_c_acsl`, with two additions:

    - Preprocessor directives. The tokenizer returns a directive as one token; its `/* */` and `//` comments
      are reported here as `c_comment` (an annotation-looking `/*@` in a directive is a plain comment), a block
      comment opened on a directive and closed on a later line is followed to its `*/`, and string and
      character literals inside a directive are NOT reported (`#include "x.h"` stays readable).
    - Text the tokenizer rejects (`on_error`). `"raise"`, the default, raises `AcslSyntaxError`. `"mask"`
      never raises: an unclosed block comment is reported up to the end of the text, an unclosed string or
      character literal from its quote up to the end of its line (the newline is not included), and lexing
      resumes on the next line. Use `"mask"` only where the old regex was already a best-effort reading; a
      caller that guards a verdict should keep `"raise"` and treat the error as "unknown".

    Use this instead of `mask_comments_and_literals` when the comments must be deleted or replaced by
    something of another length.
    """
    if on_error not in ("raise", "mask"):
        raise ValueError(f"on_error must be 'raise' or 'mask', not {on_error!r}")
    spans: list[tuple[str, int, int]] = []
    n = len(text)
    pos = 0

    def unclosed(kind: str, at: int) -> AcslSyntaxError:
        line = text.count("\n", 0, at) + 1
        return AcslSyntaxError(f"{path}:{line}: unclosed {_UNCLOSED_LABELS[kind]}", line=line, kind=kind, offset=at)

    while pos < n:
        chunk = text[pos:] if pos else text
        failure: AcslSyntaxError | None = None
        try:
            tokens = tokenize_c_acsl(chunk, path=path)
        except AcslSyntaxError as exc:
            if exc.offset is None or exc.kind not in _UNCLOSED_LABELS:
                raise
            if on_error == "raise":
                raise unclosed(exc.kind, pos + exc.offset) from None
            failure = exc
            tokens = tokenize_c_acsl(chunk[: exc.offset], path=path)
        resume: int | None = None
        for tok in tokens:
            if tok.kind in _LEXICAL_SPAN_KINDS:
                spans.append((tok.kind, pos + tok.start, pos + tok.end))
            elif tok.kind == "pp_directive":
                inner, open_at = _directive_comment_spans(text, pos + tok.start, pos + tok.end)
                spans.extend(inner)
                if open_at is None:
                    continue
                close = text.find("*/", pos + tok.end)
                if close == -1:
                    if on_error == "raise":
                        raise unclosed("c_block_comment", open_at)
                    spans.append(("c_comment", open_at, n))
                    return spans
                spans.append(("c_comment", open_at, close + 2))
                resume = close + 2
                break
        if resume is None:
            if failure is None or failure.offset is None:
                break
            at = pos + failure.offset
            if failure.kind in ("acsl_block_comment", "c_block_comment"):
                spans.append(("acsl_block" if failure.kind == "acsl_block_comment" else "c_comment", at, n))
                break
            eol = text.find("\n", at)
            eol = n if eol == -1 else eol
            spans.append(("string" if failure.kind == "string_literal" else "char", at, eol))
            resume = eol
        pos = resume
    return spans


def _blank(text: str) -> str:
    """`text` with every character but its line ends replaced by a space."""
    return _NOT_LINE_END_RE.sub(" ", text)


def _is_doxygen_comment(annotation: str) -> bool:
    """
    Whether a token the tokenizer calls an annotation is a plain comment for Frama-C: its lexer skips
    `/*@{`, `/*@}`, `/*@*` and `//@{`, `//@}`, `//@*` as doxygen comments (clexer.mll, rule `initial`).
    """
    return annotation[3:4] in ("{", "}", "*")


def _blank_literal(literal: str) -> str:
    """A string or character literal with its content blanked and its quotes kept."""
    closed = len(literal) >= 2 and literal[-1] == literal[0]
    return literal[0] + _blank(literal[1:-1] if closed else literal[1:]) + (literal[-1] if closed else "")


def mask_comments_and_literals(
    text: str, *, acsl: str = "keep", literals: bool = True, on_error: str = "raise", path: str = "<input>"
) -> str:
    """
    `text` with its comments and literal contents replaced by spaces, for a regex that must not match in them.

    The result has the length of `text` and the same line ends (`\\n` and `\\r` are never replaced), so every
    offset, line and column of a match in the result is valid in `text`. Nothing is deleted.

    - C comments (`/* */`, `//`), also those inside a preprocessor directive: blanked, delimiters included.
    - String and character literals in code: content blanked, quotes kept (`"a;b"` becomes `"   "`), so a
      literal is still one literal. `literals=False` leaves them as written. Literals inside a preprocessor
      directive are always left as written (`#include "x.h"`, `#define S "..."`).
    - ACSL annotations (`/*@ */`, `//@`), by `acsl`:
        `"keep"` (default): left as written, with their own `//` comments and literals;
        `"mask"`: kept, but what the Frama-C kernel reads as a comment inside them is blanked, and their
            literal contents too (when `literals`). A `//@` inside an annotation is such a comment (the
            kernel does not read it as a nested annotation, whatever the ACSL manual says), except in
            `/*@ ghost` code, which is C: there it is an annotation, kept and masked the same way. A
            doxygen-style `/*@{`, `/*@}`, `/*@*` (or `//@` form) is no annotation for the kernel: blanked;
        `"blank"`: blanked like any comment. This is what the old `re.sub(r"/\\*.*?\\*/", " ", ...)` did.
    - Text the tokenizer rejects, by `on_error` (see `comment_and_literal_spans`): `"raise"` (default)
      raises `AcslSyntaxError`; `"mask"` blanks an unclosed block comment up to the end of the text, and an
      unclosed literal from its quote up to the end of its line (with `literals=False` that line is left as
      written, and a `/*` on it does not open a comment).

    The drop-in for a regex that stripped every comment from a file it had not validated is
    `mask_comments_and_literals(text, acsl="blank", literals=False, on_error="mask")`. Limits, all inherited
    from `tokenize_c_acsl`: no trigraphs, no raw strings, `<...>` include names are not literals (a `//` in
    one reads as a comment), and a `#` that follows a comment on its line is not a directive.
    """
    if acsl not in ("keep", "mask", "blank"):
        raise ValueError(f"acsl must be 'keep', 'mask' or 'blank', not {acsl!r}")
    out: list[str] = []
    last = 0
    for kind, start, end in comment_and_literal_spans(text, on_error=on_error, path=path):
        piece = text[start:end]
        if kind == "c_comment" or (acsl == "blank" and kind in ("acsl_block", "acsl_line")):
            piece = _blank(piece)
        elif kind in ("acsl_block", "acsl_line"):
            if acsl == "mask" and _is_doxygen_comment(piece):
                piece = _blank(piece)
            elif acsl == "mask":
                closed = kind == "acsl_block" and len(piece) >= 5 and piece.endswith("*/")
                body_end = len(piece) - 2 if closed else len(piece)
                body = piece[3:body_end]
                nested = "mask" if _GHOST_ANNOTATION_RE.match(body) else "blank"
                body = mask_comments_and_literals(body, acsl=nested, literals=literals, on_error="mask", path=path)
                piece = piece[:3] + body + piece[body_end:]
        elif literals:
            piece = _blank_literal(piece)
        out.append(text[last:start])
        out.append(piece)
        last = end
    out.append(text[last:])
    return "".join(out)


def _kernel_views(text: str) -> tuple[str, str]:
    """
    Two readings of C/ACSL `text` that leave out what the Frama-C kernel does not read inside an annotation,
    both with the length and line ends of `text`, so an offset in one is valid in the other and in `text`:

    - `shape`: comments and literal contents blanked (`mask_comments_and_literals(acsl="mask")`) and every
      `@` replaced by a space. For the structure of a clause: keywords, brackets, `;`.
    - `visible`: the same with the literals as written (an `@` in a literal stays). For the text of a clause.

    The kernel reads `@` as white space anywhere in an annotation, not only in the margin, so
    `requires @ \\false;` is `requires \\false;`. Neither reading can be tokenized again: the `/*@` and `//@`
    openers lose their `@` too. Never raises (`on_error="mask"`).
    """
    masked = mask_comments_and_literals(text, acsl="mask", on_error="mask")
    visible = mask_comments_and_literals(text, acsl="mask", literals=False, on_error="mask")
    if "@" not in masked:
        return masked, visible
    return masked.replace("@", " "), "".join(" " if m == "@" else c for c, m in zip(visible, masked, strict=True))


def _check_unsound_acsl(tokens: list[Token], baseline_acsl_texts: set[str], path: str) -> list[str]:
    """
    Flag newly added ACSL annotations that introduce unsound or silently dropped constructs:
    - admit, axiom, axiomatic, inductive (unverified trust anchors / no consistency check)
    - C integer types in logic signatures (e.g. `logic int f(...)` instead of `logic integer`)
    - statement-level `invariant` without `loop`/`type`/`global`/`strong` (silently dropped by WP)
    """
    errors: list[str] = []
    for tok in tokens:
        if tok.kind not in ("acsl_block", "acsl_line"):
            continue
        if tok.text in baseline_acsl_texts:
            continue
        m_ctrl = _ESCAPED_CTRL_IN_ACSL_RE.search(tok.text)
        if m_ctrl:
            ctrl_map = {"\x07": r"\a", "\x08": r"\b", "\x0c": r"\f"}
            esc = ctrl_map.get(m_ctrl.group(0), repr(m_ctrl.group(0)))
            errors.append(
                f"{path}:{tok.line}: syntax hazard: control character {m_ctrl.group(0)!r} ({esc}) found in ACSL "
                "annotation (likely caused by unescaped \\false, \\forall, \\at, or \\base_addr in a Python/shell string)"
            )
        m_splice = _SPLICED_LINE_RE.search(tok.text)
        if m_splice:
            errors.append(
                f"{path}:{tok.line + tok.text.count(chr(10), 0, m_splice.start())}: syntax hazard: a line of an ACSL "
                "annotation ends with a backslash (the preprocessor joins the next line to it: after a `//@` "
                "annotation the C code that follows becomes part of the comment, and in a `//` comment inside an "
                "annotation the next clause does); remove the backslash"
            )
        if _is_doxygen_comment(tok.text):
            errors.append(
                f"{path}:{tok.line}: syntax hazard: '{tok.text[:4]}' opens a plain comment for Frama-C, not an "
                "annotation (its lexer skips `/*@{`, `/*@}`, `/*@*` and the `//@` forms as doxygen comments, and "
                "after `/*@*` it looks for a later `*/`); write the annotation as `/*@ ... */` or `//@ ...`"
            )
            continue
        scrubbed = _scrub_acsl_literals(tok.text)
        # `@` is white space for the kernel: `logic @ int f(...)` is `logic int f(...)`.
        flat = scrubbed.replace("@", " ")
        m = _UNSOUND_ACSL_RE.search(flat)
        if m:
            errors.append(
                f"{path}:{tok.line}: forbidden unsound ACSL construct '{m.group(1)}' introduced in annotation"
            )
        m_logic = _LOGIC_C_INT_RE.search(flat)
        if m_logic:
            errors.append(
                f"{path}:{tok.line}: forbidden C integer type in ACSL logic signature '{m_logic.group(0)}' "
                "(use unbounded 'integer' or 'real'; C integer types introduce wraparound into logic)"
            )
        else:
            for m_decl in _LOGIC_DECL_RE.finditer(flat):
                for param in m_decl.group(1).split(","):
                    if "*" not in param and "[" not in param and _C_INT_PARAM_RE.match(param):
                        errors.append(
                            f"{path}:{tok.line}: forbidden C integer parameter '{param.strip()}' in ACSL logic signature "
                            "(use unbounded 'integer' instead of C integer types)"
                        )
                        break
        for m_inv in _INVARIANT_CLAUSE_RE.finditer(flat):
            if m_inv.group(1) is None:
                errors.append(
                    f"{path}:{tok.line}: forbidden statement-level 'invariant' in annotation "
                    "(WP silently drops statement invariants; use 'loop invariant' or 'assert')"
                )
                break
        vacuous = _first_vacuous_clause(scrubbed)
        if vacuous:
            errors.append(
                f"{path}:{tok.line}: forbidden vacuous '{vacuous}' in annotation "
                "(assuming \\false or 0 makes all WP obligations vacuously true)"
            )
    return errors


def _scrub_acsl_literals(text: str) -> str:
    """
    One ACSL annotation (with its `/*@ */` or `//@`) with the contents of its literals and what the kernel
    reads as a comment inside it blanked, at the same length: `mask_comments_and_literals(acsl="mask")`.
    Its `@` are kept, so the result is still one annotation for `iter_clauses`; a regex that must read
    `@` as white space searches the result with `.replace("@", " ")`.
    """
    return mask_comments_and_literals(text, acsl="mask", on_error="mask")


def _first_vacuous_clause(scrubbed: str) -> str | None:
    """The first `requires` / `assumes` / `loop invariant` clause whose predicate is false by its form, or None."""
    for kind, _label, pred, (start, end) in iter_clauses(scrubbed):
        if kind in ("requires", "assumes", "loop invariant") and is_trivially_false_predicate(pred):
            return " ".join(scrubbed[start:end].split())
    return None


def find_empty_named_behaviors(tokens: list[Token], path: str = "<input>") -> list[str]:
    """
    Frama-C 34+ forbids empty named behaviors (`behavior b: ;`) in function and statement
    contracts: the kernel aborts with a fatal annot-error ("unexpected token ';'"). Flag them
    before splicing so a candidate fails the mechanical check instead of the kernel parse.
    """
    errors: list[str] = []
    for tok in tokens:
        if tok.kind not in ("acsl_block", "acsl_line"):
            continue
        scrubbed = _scrub_acsl_literals(tok.text).replace("@", " ")
        for m in _EMPTY_BEHAVIOR_RE.finditer(scrubbed):
            errors.append(
                f"{path}:{tok.line}: empty named behavior '{m.group(0).strip()}' is forbidden since Frama-C 34 "
                "(fatal annot-error: unexpected token ';'); give the behavior at least one clause or remove it"
            )
    return errors


_ALIGNED_RE = re.compile(r"\\aligned\s*\(")


def _aligned_requires(tokens: list[Token]) -> list[tuple[int, str]]:
    """(line, whitespace-normalised clause) of every `requires` clause using `\\aligned(...)`."""
    out: list[tuple[int, str]] = []
    for tok in tokens:
        if tok.kind not in ("acsl_block", "acsl_line") or "aligned" not in tok.text:
            continue
        for kind, _label, pred, _span in iter_clauses(_scrub_acsl_literals(tok.text)):
            if kind == "requires" and _ALIGNED_RE.search(pred):
                out.append((tok.line, " ".join(pred.split())))
    return out


def _added_aligned_requires(base_tokens: list[Token], work_tokens: list[Token], path: str) -> list[str]:
    """
    `requires` clauses using `\\aligned(...)` that `work_tokens` adds to `base_tokens`. WP implements
    `\\aligned` under no memory model (`\\aligned not yet implemented`), so no caller can discharge
    such a precondition and every call site keeps an Unknown goal. A clause already in the baseline
    is the target's, not the agent's: compared per clause, so extending a baseline block keeps it.
    """
    known = Counter(clause for _line, clause in _aligned_requires(base_tokens))
    errors: list[str] = []
    for line, clause in _aligned_requires(work_tokens):
        if known[clause] > 0:
            known[clause] -= 1
            continue
        errors.append(
            f"{path}:{line}: forbidden 'requires {clause}': WP implements \\aligned under no memory model, "
            "so no caller can discharge it; state the alignment in the result's boundary_assumptions instead"
        )
    return errors


def find_unsound_acsl_keywords(tokens: list[Token], path: str = "<input>") -> list[str]:
    """Check all ACSL tokens in `tokens` for unsound or hazardous ACSL constructs."""
    return (
        _check_unsound_acsl(tokens, set(), path)
        + find_empty_named_behaviors(tokens, path)
        + _find_unsound_recursive_logic_tokens(tokens, path)
        + _find_in_body_ghost_declarations_tokens(tokens, path)
    )


def verify_acsl_only(
    baseline_text: str,
    work_text: str,
    path: str = "<input>",
    check_unsound: bool = True,
) -> list[str]:
    """Verify that work_text differs from baseline_text only in ACSL comments (/*@ ... */ and //@ ...)."""
    try:
        base_tokens = tokenize_c_acsl(baseline_text, path=path)
        work_tokens = tokenize_c_acsl(work_text, path=path)
    except AcslSyntaxError as exc:
        return [str(exc)]

    errors: list[str] = []
    errors.extend(find_empty_named_behaviors(work_tokens, path))
    if check_unsound:
        base_acsl = {t.text for t in base_tokens if t.kind in ("acsl_block", "acsl_line")}
        errors.extend(_check_unsound_acsl(work_tokens, base_acsl, path))
        errors.extend(_added_aligned_requires(base_tokens, work_tokens, path))
        base_rec_keys = {key for key, _msg in _find_unsound_recursive_logic_entries(base_tokens, path)}
        errors.extend(
            msg for key, msg in _find_unsound_recursive_logic_entries(work_tokens, path) if key not in base_rec_keys
        )
        errors.extend(_added_in_body_ghost_declarations(base_tokens, work_tokens, path))

    base_c = [t for t in base_tokens if t.kind not in ("whitespace", "acsl_block", "acsl_line")]
    work_c = [t for t in work_tokens if t.kind not in ("whitespace", "acsl_block", "acsl_line")]

    _pp_hint = (
        " (Preprocessor directives are C tokens and cannot be added by ACSL overlays; "
        "shared ACSL logic/predicate declarations across headers are deduplicated automatically by merge-agent.)"
    )
    limit = min(len(base_c), len(work_c))
    for idx in range(limit):
        bt = base_c[idx]
        wt = work_c[idx]
        if bt.kind != wt.kind or bt.text != wt.text:
            hint = _pp_hint if wt.kind == "pp_directive" or bt.kind == "pp_directive" else ""
            errors.append(
                f"{path}:{wt.line}: non-ACSL token modified: expected {bt.text!r} "
                f"(baseline line {bt.line}), got {wt.text!r}{hint}"
            )
            return errors

    if len(work_c) > len(base_c):
        extra = work_c[limit]
        hint = _pp_hint if extra.kind == "pp_directive" else ""
        errors.append(f"{path}:{extra.line}: non-ACSL token added: {extra.text!r}{hint}")
    elif len(base_c) > len(work_c):
        missing = base_c[limit]
        hint = _pp_hint if missing.kind == "pp_directive" else ""
        errors.append(f"{path}:{missing.line}: non-ACSL token removed: {missing.text!r}{hint}")

    return errors


def _next_meaningful(tokens: list[Token], idx: int, include_acsl: bool = False) -> int:
    """Return index of next token at or after idx that is not whitespace/comment."""
    skip = {"whitespace", "c_comment"} if include_acsl else {"whitespace", "c_comment", "acsl_block", "acsl_line"}
    while idx < len(tokens) and tokens[idx].kind in skip:
        idx += 1
    return idx


_DECL_SUFFIX_KWS = frozenset({"__attribute__", "__attribute", "__asm__", "__asm", "asm"})


def _skip_paren_group(tokens: list[Token], idx: int) -> int:
    """The index after the parenthesized group opening at tokens[idx] (len(tokens) when it never closes)."""
    depth = 0
    while idx < len(tokens):
        tok = tokens[idx]
        if tok.kind == "c_token" and tok.text == "(":
            depth += 1
        elif tok.kind == "c_token" and tok.text == ")":
            depth -= 1
            if depth == 0:
                return idx + 1
        idx += 1
    return idx


def _next_after_params(tokens: list[Token], idx: int) -> int:
    """
    The next meaningful token after a parameter list; a conditional may stand between it and the body,
    and so may GCC attributes and an asm label (`... ) __attribute__((__leaf__));`, as Frama-C prints
    a glibc prototype and scripts/stub_gen.py copies it into a stub).
    """
    idx = _next_meaningful(tokens, idx)
    while idx < len(tokens):
        tok = tokens[idx]
        if tok.kind == "pp_directive":
            idx = _next_meaningful(tokens, idx + 1)
            continue
        if tok.kind == "c_token" and tok.text in _DECL_SUFFIX_KWS:
            paren = _next_meaningful(tokens, idx + 1)
            if paren < len(tokens) and tokens[paren].kind == "c_token" and tokens[paren].text == "(":
                idx = _next_meaningful(tokens, _skip_paren_group(tokens, paren))
                continue
        break
    return idx


_COND_DIRECTIVE_RE = re.compile(r"#\s*(ifdef|ifndef|if|elif|else|endif)\b")
_DIRECTIVE_NOISE_RE = re.compile(r"/\*.*?\*/|//[^\n]*|\\\r?\n", re.DOTALL)
_DEFINED_OPERAND_RE = re.compile(r"\bdefined\s*(?:\(\s*([A-Za-z_]\w*)\s*\)|([A-Za-z_]\w*))")
_SINGLE_OPERAND_RE = re.compile(r"[A-Za-z_]\w*|defined\([A-Za-z_]\w*\)")
_DELIM_KIND = {"{": "{", "}": "{", "(": "(", ")": "("}


@dataclass(slots=True)
class _CondArm:
    """One arm of a conditional: the delimiters it leaves unmatched, per kind, and whether it is the arm read."""

    selected: bool
    opens: dict[str, list[int]] = field(default_factory=lambda: {"{": [], "(": []})
    closes: dict[str, list[int]] = field(default_factory=lambda: {"{": [], "(": []})

    def close(self, kind: str, idx: int) -> None:
        if self.opens[kind]:
            self.opens[kind].pop()
        else:
            self.closes[kind].append(idx)


@dataclass(slots=True, frozen=True)
class _ConditionalDelims:
    """
    `ignored`: the delimiters of the arms not read. `close_alias`: a closing delimiter of the arm read, mapped to
    the last one that plays the same part in another arm, so that a span ends after every arm.
    """

    ignored: frozenset[int] = frozenset()
    close_alias: Mapping[int, int] = field(default_factory=dict)


def _condition_of(word: str, directive: str) -> tuple[str, bool]:
    """(canonical condition, whether the directive negates it): `#ifndef A` and `#if !defined(A)` name one condition."""
    rest = _COND_DIRECTIVE_RE.sub("", _DIRECTIVE_NOISE_RE.sub(" ", directive), count=1).strip()
    if word in ("ifdef", "ifndef"):
        return f"defined({rest})", word == "ifndef"
    text = re.sub(r"\s+", "", _DEFINED_OPERAND_RE.sub(lambda m: f"defined({m.group(1) or m.group(2)})", rest))
    negated = False
    while True:
        text = _strip_outer_parens(text)
        operand = _strip_outer_parens(text[1:])
        if not text.startswith("!") or not (operand != text[1:] or _SINGLE_OPERAND_RE.fullmatch(operand)):
            return text, negated
        text, negated = operand, not negated


def _conditional_delims(tokens: list[Token]) -> _ConditionalDelims:
    """
    Read one configuration of the file's conditionals, so that a block both arms open is counted once
    (libmodbus: `#ifdef W` / `if (a) {` / `#else` / `if (b) {` / `#endif` / ... / `}`).

    The first arm is read unless an earlier conditional settled its condition: the same condition is answered the
    same way all through the file, and `#if 0` is false. Only what an arm not read leaves unmatched is ignored, so
    the functions and blocks complete inside any arm stay visible, and balanced arms change nothing. A file this
    reading leaves unbalanced, when plain counting balances it (conditions related in a way not seen here), is counted.
    """
    known: dict[str, bool] = {}
    ignored: set[int] = set()
    alias: dict[int, int] = {}
    root = _CondArm(selected=True)
    arm = root
    frames: list[tuple[_CondArm, list[_CondArm]]] = []  # (the arm holding the conditional, its arms so far)
    counts = {"{": 0, "(": 0}
    plain_balanced = True

    def read(word: str, directive: str, taken: bool) -> bool:
        if taken:
            return False
        condition, negated = _condition_of(word, directive)
        if condition.isdigit():
            return (int(condition) != 0) != negated
        return known.setdefault(condition, not negated) != negated

    def end_conditional() -> _CondArm:
        parent, arms = frames.pop()
        chosen = next((a for a in arms if a.selected), None)
        for other in arms:
            if other.selected:
                continue
            for kind in ("{", "("):
                ignored.update(other.opens[kind], other.closes[kind])
                if chosen is not None:
                    for own, theirs in zip(chosen.closes[kind], other.closes[kind], strict=False):
                        alias[own] = max(alias.get(own, own), theirs)
        if chosen is not None:
            for kind in ("{", "("):
                for idx in chosen.closes[kind]:
                    parent.close(kind, idx)
                parent.opens[kind].extend(chosen.opens[kind])
        return parent

    for idx, tok in enumerate(tokens):
        if tok.kind == "pp_directive":
            m = _COND_DIRECTIVE_RE.match(tok.text)
            word = m.group(1) if m else ""
            if word in ("if", "ifdef", "ifndef"):
                parent = arm
                arm = _CondArm(selected=read(word, tok.text, False))
                frames.append((parent, [arm]))
            elif word in ("elif", "else") and frames:
                arms = frames[-1][1]
                taken = any(a.selected for a in arms)
                arm = _CondArm(selected=not taken if word == "else" else read(word, tok.text, taken))
                arms.append(arm)
            elif word == "endif" and frames:
                arm = end_conditional()
        elif tok.kind == "c_token" and tok.text in _DELIM_KIND:
            kind = _DELIM_KIND[tok.text]
            if tok.text == kind:
                arm.opens[kind].append(idx)
                counts[kind] += 1
            else:
                arm.close(kind, idx)
                counts[kind] -= 1
                plain_balanced = plain_balanced and counts[kind] >= 0
    while frames:  # a fragment may end inside a conditional
        arm = end_conditional()
    balanced = not any(root.opens[k] or root.closes[k] for k in ("{", "("))
    if not balanced and plain_balanced and not any(counts.values()):
        return _ConditionalDelims()
    return _ConditionalDelims(frozenset(ignored), alias)


def _find_matching_delim(
    tokens: list[Token], open_idx: int, open_ch: str, close_ch: str, delims: _ConditionalDelims | None = None
) -> int:
    """Find the token index of the matching closing delimiter starting at open_idx, reading one configuration."""
    delims = _conditional_delims(tokens) if delims is None else delims
    depth = 0
    for idx in range(open_idx, len(tokens)):
        tok = tokens[idx]
        if tok.kind == "c_token" and (idx == open_idx or idx not in delims.ignored):
            if tok.text == open_ch:
                depth += 1
            elif tok.text == close_ch:
                depth -= 1
                if depth == 0:
                    return delims.close_alias.get(idx, idx)
    return -1


def _linkage_block_braces(tokens: list[Token], delims: _ConditionalDelims | None = None) -> frozenset[int]:
    """
    Indices of the `{` and `}` of every `extern "C" { ... }` block.

    The braces of a linkage specification only group declarations: a C library header wraps its whole
    API in one under `#ifdef __cplusplus`, and counting it as nesting would hide every prototype
    and top-level ACSL declaration in the file.
    """
    delims = _conditional_delims(tokens) if delims is None else delims
    skip: set[int] = set()
    for i, tok in enumerate(tokens):
        if tok.kind != "c_token" or tok.text != "{":
            continue
        j = i - 1
        while j >= 0 and tokens[j].kind in ("whitespace", "c_comment"):
            j -= 1
        if j < 0 or tokens[j].kind != "string" or tokens[j].text not in ('"C"', '"C++"'):
            continue
        j -= 1
        while j >= 0 and tokens[j].kind in ("whitespace", "c_comment"):
            j -= 1
        if j < 0 or tokens[j].kind != "c_token" or tokens[j].text != "extern":
            continue
        close = _find_matching_delim(tokens, i, "{", "}", delims)
        skip.add(i)
        if close != -1:
            skip.add(close)
    return frozenset(skip)


_PTR_QUAL_TOKENS = frozenset({"*", "const", "volatile", "restrict", "__restrict", "__restrict__", "_Atomic"})
_NOT_FUNC_NAMES = frozenset(
    {
        "typedef",
        "extern",
        "static",
        "inline",
        "struct",
        "enum",
        "union",
        "__attribute__",
        "__attribute",
        "__asm__",
        "__asm",
        "asm",
        "sizeof",
        "typeof",
        "__typeof__",
        "_Alignas",
        "_Static_assert",
        "return",
        "if",
        "else",
        "for",
        "while",
        "switch",
        "do",
    }
)
_KR_FORBIDDEN_DECL_TOKENS = frozenset(
    {
        "typedef",
        "extern",
        "static",
        "inline",
        "return",
        "if",
        "while",
        "for",
        "switch",
        "do",
        "case",
        "default",
        "goto",
        "break",
        "continue",
    }
)


def _has_top_level_token(
    tokens: list[Token], start: int, end: int, wanted: frozenset[str], ignored: frozenset[int]
) -> bool:
    """Whether any c_token at paren/brace depth 0 in `tokens[start:end]` has text in `wanted`."""
    p_depth = 0
    b_depth = 0
    for k in range(max(0, start), end):
        if k in ignored:
            continue
        t = tokens[k]
        if t.kind != "c_token":
            continue
        if t.text == "(":
            p_depth += 1
        elif t.text == ")":
            p_depth = max(0, p_depth - 1)
        elif t.text == "{":
            b_depth += 1
        elif t.text == "}":
            b_depth = max(0, b_depth - 1)
        elif p_depth == 0 and b_depth == 0 and t.text in wanted:
            return True
    return False


def _is_nested_decl_prefix(
    tokens: list[Token],
    last_top_boundary_idx: int,
    open_parens: list[int],
    fn_idx: int,
    delims: _ConditionalDelims,
) -> bool:
    """
    Whether `open_parens` wraps a nested C function declarator for `tokens[fn_idx]` (such as
    `int (*f(int x))(int)` or `int (*(*f(int x))(int y))(int z)`), rather than another function's
    parameter list or a parenthesised expression.
    """
    outer = open_parens[0]
    has_return_spec = any(
        k not in delims.ignored and tokens[k].kind == "c_token" for k in range(max(0, last_top_boundary_idx + 1), outer)
    )
    if not has_return_spec:
        return False
    if _has_top_level_token(tokens, last_top_boundary_idx + 1, outer, frozenset({"="}), delims.ignored):
        return False
    boundaries = [*open_parens, fn_idx]
    for p_idx, next_idx in zip(boundaries, boundaries[1:], strict=False):
        saw_star = False
        k = p_idx + 1
        while k < next_idx:
            if k in delims.ignored:
                k += 1
                continue
            t = tokens[k]
            if t.kind in ("whitespace", "c_comment", "acsl_block", "acsl_line", "pp_directive"):
                k += 1
                continue
            if t.kind == "c_token" and t.text in _DECL_SUFFIX_KWS:
                paren = _next_meaningful(tokens, k + 1)
                if paren < next_idx and tokens[paren].kind == "c_token" and tokens[paren].text == "(":
                    k = _skip_paren_group(tokens, paren)
                    continue
            if t.kind != "c_token" or t.text not in _PTR_QUAL_TOKENS:
                return False
            if t.text == "*":
                saw_star = True
            k += 1
        if not saw_star:
            return False
    return True


def _unwind_nested_declarator(tokens: list[Token], pos: int, depth: int, delims: _ConditionalDelims) -> int:
    """
    Close `depth` enclosing declarator `)` levels starting at `pos`, each followed by at least one
    `(...)` or `[...]` declarator suffix (the return type's parameters or array dimensions).
    Returns the token index after the outermost suffix, or -1 if the shape does not match.
    """
    n = len(tokens)
    for _ in range(depth):
        pos = _next_after_params(tokens, pos)
        if pos >= n or tokens[pos].kind != "c_token" or tokens[pos].text != ")":
            return -1
        pos = _next_after_params(tokens, pos + 1)
        saw_suffix = False
        while pos < n and tokens[pos].kind == "c_token" and tokens[pos].text in ("(", "["):
            open_ch = tokens[pos].text
            close_ch = ")" if open_ch == "(" else "]"
            close_idx = _find_matching_delim(tokens, pos, open_ch, close_ch, delims)
            if close_idx == -1:
                return -1
            saw_suffix = True
            pos = _next_after_params(tokens, close_idx + 1)
        if not saw_suffix:
            return -1
    return pos


def _kr_param_identifiers(
    tokens: list[Token], open_paren_idx: int, close_paren_idx: int, delims: _ConditionalDelims
) -> set[str] | None:
    """
    If `tokens[open_paren_idx + 1 : close_paren_idx]` is a non-empty K&R identifier list (`a, b`),
    return the parameter names; otherwise None.
    """
    inner = [
        tokens[k].text
        for k in range(open_paren_idx + 1, close_paren_idx)
        if k not in delims.ignored and tokens[k].kind == "c_token"
    ]
    if not inner or len(inner) % 2 == 0:
        return None
    idents: set[str] = set()
    for i, text in enumerate(inner):
        if i % 2 == 1:
            if text != ",":
                return None
        else:
            if not _IDENT_RE.fullmatch(text) or text in _C_PARAM_KEYWORDS:
                return None
            idents.add(text)
    return idents


def _kr_body_brace_idx(tokens: list[Token], start_idx: int, kr_idents: set[str], delims: _ConditionalDelims) -> int:
    """
    Scan K&R parameter declarations (`int a; char *b;`) starting at `start_idx` and return the token
    index of the function body's opening `{`, or -1 if `start_idx` is not a K&R declaration list.
    """
    n = len(tokens)
    cur = start_idx
    decl_count = 0
    while cur < n:
        cur = _next_after_params(tokens, cur)
        if cur >= n:
            return -1
        if tokens[cur].kind == "c_token" and tokens[cur].text == "{":
            return cur if decl_count >= 1 else -1
        # Scan a single `;`-terminated K&R parameter declaration.
        p_depth = 0
        tag_state = 0  # 1 right after struct/union/enum, 2 right after tag name
        decl_idents: set[str] = set()
        found_semi = False
        while cur < n:
            if cur in delims.ignored:
                cur += 1
                continue
            t = tokens[cur]
            if t.kind in ("whitespace", "c_comment", "acsl_block", "acsl_line", "pp_directive"):
                cur += 1
                continue
            if t.kind != "c_token":
                tag_state = 0
                cur += 1
                continue
            text = t.text
            if text == "(":
                p_depth += 1
                tag_state = 0
            elif text == ")":
                if p_depth == 0:
                    return -1
                p_depth -= 1
                tag_state = 0
            elif text == "{" and p_depth == 0:
                if tag_state not in (1, 2):
                    return -1
                close_b = _find_matching_delim(tokens, cur, "{", "}", delims)
                if close_b == -1:
                    return -1
                cur = close_b + 1
                tag_state = 0
                continue
            elif text == "}" and p_depth == 0:
                return -1
            elif text == ";" and p_depth == 0:
                if not (decl_idents & kr_idents):
                    return -1
                decl_count += 1
                cur += 1
                found_semi = True
                break
            elif p_depth == 0 and (text == "=" or text in _KR_FORBIDDEN_DECL_TOKENS):
                return -1
            else:
                if p_depth == 0 and text in ("struct", "union", "enum"):
                    tag_state = 1
                elif p_depth == 0 and tag_state == 1 and _IDENT_RE.fullmatch(text):
                    tag_state = 2
                else:
                    tag_state = 0
                if _IDENT_RE.fullmatch(text):
                    decl_idents.add(text)
            cur += 1
        if not found_semi:
            return -1
    return -1


def _match_declaration_at(
    tokens: list[Token],
    idx: int,
    last_top_boundary_idx: int,
    open_parens: list[int],
    delims: _ConditionalDelims,
) -> tuple[str, int, int] | None:
    """
    If `tokens[idx]` names a top-level function declaration (ordinary, nested declarator such as
    `int (*f(int x))(int)`, or K&R definition `int f(a, b) int a; char *b; { ... }`), return
    `(kind, start_idx, end_idx)` where `kind` is `"prototype"` or `"definition"`; else None.
    """
    n = len(tokens)
    if open_parens:
        if not _is_nested_decl_prefix(tokens, last_top_boundary_idx, open_parens, idx, delims):
            return None
        decl_anchor_idx = open_parens[0]
    else:
        if _has_top_level_token(tokens, last_top_boundary_idx + 1, idx, frozenset({"="}), delims.ignored):
            return None
        decl_anchor_idx = idx

    open_paren_idx = _next_meaningful(tokens, idx + 1)
    if open_paren_idx >= n or tokens[open_paren_idx].kind != "c_token" or tokens[open_paren_idx].text != "(":
        return None
    close_paren_idx = _find_matching_delim(tokens, open_paren_idx, "(", ")", delims)
    if close_paren_idx == -1:
        return None

    pos = close_paren_idx + 1
    if open_parens:
        pos = _unwind_nested_declarator(tokens, pos, len(open_parens), delims)
        if pos == -1:
            return None

    after_idx = _next_after_params(tokens, pos)
    if after_idx >= n or tokens[after_idx].kind != "c_token":
        return None

    next_text = tokens[after_idx].text
    if next_text == "{":
        end_idx = _find_matching_delim(tokens, after_idx, "{", "}", delims)
        if end_idx != -1:
            return ("definition", _compute_span_start(tokens, last_top_boundary_idx, decl_anchor_idx), end_idx)
        return None
    if next_text == ";":
        if _has_top_level_token(
            tokens, last_top_boundary_idx + 1, decl_anchor_idx, frozenset({"typedef"}), delims.ignored
        ):
            return None
        return ("prototype", _compute_span_start(tokens, last_top_boundary_idx, decl_anchor_idx), after_idx)

    # K&R function definition: identifier list in `(...)`, parameter declarations ending in `;`, then `{ ... }`.
    kr_idents = _kr_param_identifiers(tokens, open_paren_idx, close_paren_idx, delims)
    if kr_idents:
        body_brace_idx = _kr_body_brace_idx(tokens, after_idx, kr_idents, delims)
        if body_brace_idx != -1:
            end_idx = _find_matching_delim(tokens, body_brace_idx, "{", "}", delims)
            if end_idx != -1:
                return ("definition", _compute_span_start(tokens, last_top_boundary_idx, decl_anchor_idx), end_idx)
    return None


def _iter_declaration_spans(
    source: str,
    path: str = "<input>",
    *,
    target_name: str | None = None,
    allow_prototype: bool = True,
    allow_definition: bool = True,
) -> Iterator[DeclSpan]:
    """Yield top-level function declarations in `source` in source order."""
    tokens = tokenize_c_acsl(source, path=path)
    delims = _conditional_delims(tokens)
    linkage = _linkage_block_braces(tokens, delims) | delims.ignored
    brace_depth = 0
    paren_depth = 0
    bracket_depth = 0
    open_parens: list[int] = []
    last_top_boundary_idx = -1
    idx = 0
    n = len(tokens)
    while idx < n:
        tok = tokens[idx]
        if idx in linkage:
            idx += 1
            continue
        if tok.kind == "pp_directive" and brace_depth == 0 and paren_depth == 0 and bracket_depth == 0:
            last_top_boundary_idx = idx
        elif tok.kind == "c_token":
            if tok.text == "{":
                brace_depth += 1
            elif tok.text == "}":
                brace_depth = max(0, brace_depth - 1)
                if brace_depth == 0 and paren_depth == 0 and bracket_depth == 0:
                    last_top_boundary_idx = idx
            elif tok.text == "(":
                paren_depth += 1
                if brace_depth == 0 and bracket_depth == 0:
                    open_parens.append(idx)
            elif tok.text == ")":
                paren_depth = max(0, paren_depth - 1)
                if brace_depth == 0 and bracket_depth == 0 and open_parens:
                    open_parens.pop()
            elif tok.text == "[":
                bracket_depth += 1
            elif tok.text == "]":
                bracket_depth = max(0, bracket_depth - 1)
            elif tok.text == ";" and brace_depth == 0 and paren_depth == 0 and bracket_depth == 0:
                last_top_boundary_idx = idx
            elif (
                brace_depth == 0
                and bracket_depth == 0
                and _IDENT_RE.fullmatch(tok.text)
                and tok.text not in _NOT_FUNC_NAMES
            ):
                matched = _match_declaration_at(tokens, idx, last_top_boundary_idx, open_parens, delims)
                if matched is not None:
                    kind, start_idx, end_idx = matched
                    if (target_name is None or tok.text == target_name) and (
                        (kind == "prototype" and allow_prototype) or (kind == "definition" and allow_definition)
                    ):
                        start_tok = tokens[start_idx]
                        end_tok = tokens[end_idx]
                        yield DeclSpan(
                            kind=kind,
                            span=Span(
                                function=tok.text,
                                start_byte=start_tok.start,
                                end_byte=end_tok.end,
                                start_line=start_tok.line,
                                end_line=end_tok.line,
                                text=source[start_tok.start : end_tok.end],
                            ),
                        )
                    last_top_boundary_idx = end_idx
                    paren_depth = 0
                    open_parens.clear()
                    idx = end_idx + 1
                    continue
        idx += 1


def locate_function_span(
    source: str, function_name: str, is_header: bool = False, path: str = "<input>"
) -> Span | None:
    """
    Locate the byte and line span of `function_name` (including any immediately preceding
    ACSL contract block) in a C source file (`is_header=False`) or header file (`is_header=True`).
    """
    for decl in _iter_declaration_spans(
        source,
        path=path,
        target_name=function_name,
        allow_prototype=is_header,
        allow_definition=not is_header,
    ):
        return decl.span
    return None


@dataclass(slots=True, frozen=True)
class DeclSpan:
    """One top-level declaration of a function: `kind` is `prototype` (ends with `;`) or `definition`."""

    kind: str
    span: Span


def function_declaration_spans(source: str, function_name: str, path: str = "<input>") -> list[DeclSpan]:
    """
    Every top-level declaration of `function_name` in `source`, in source order: its prototypes and
    its definition, each span including the ACSL contract in front of it. A header commonly declares
    a `static inline` function twice (QCBOR's `UsefulBuf.h`), and ACSL accepts a contract on either
    declaration (Frama-C merges them), so every reader of a header function's contract uses this.
    """
    return list(_iter_declaration_spans(source, path=path, target_name=function_name))


def contract_declaration_spans(
    source: str, function_name: str, is_header: bool = False, path: str = "<input>"
) -> list[DeclSpan]:
    """
    The declarations of `function_name` whose contract the pipeline reads and merges: in a header,
    every one (`function_declaration_spans`); in a source file, its first definition only.
    """
    spans = function_declaration_spans(source, function_name, path=path)
    if is_header:
        return spans
    return [d for d in spans if d.kind == "definition"][:1]


def _span_contract_part(decl: DeclSpan, path: str = "<input>") -> str:
    """The text of a declaration span up to its body `{` (the whole span for a prototype)."""
    if decl.kind != "definition":
        return decl.span.text
    brace = _find_body_brace_offset(decl.span.text, path=path)
    return decl.span.text if brace is None else decl.span.text[:brace]


def _is_top_level_acsl_token(tok: Token) -> bool:
    """Return True if an ACSL block or line token contains a top-level logic declaration keyword."""
    if tok.kind not in ("acsl_block", "acsl_line"):
        return False
    inner = tok.text[3:-2] if tok.kind == "acsl_block" else tok.text[3:]
    for seg in _parse_acsl_inner_segments(inner, tok.line):
        if seg.kind in _TOP_DECL_KWS:
            return True
    return False


def _compute_span_start(tokens: list[Token], last_top_boundary_idx: int, fn_name_idx: int) -> int:
    """
    Walk backward from fn_name_idx (stopping after last_top_boundary_idx) to include
    the return type/declarator tokens and any immediately preceding ACSL contract comments,
    while leaving normal C comments and top-level ACSL declarations outside the span.
    """
    # Step 1: walk back across the return type / storage class / pointer tokens of this declaration
    start_idx = fn_name_idx
    cursor = fn_name_idx - 1
    while cursor > last_top_boundary_idx:
        t = tokens[cursor]
        if t.kind in ("acsl_block", "acsl_line"):
            if _is_top_level_acsl_token(t):
                # Stop: this is a top-level logic declaration (predicate, logic, etc.), not a function contract
                break
            start_idx = cursor
            cursor -= 1
            continue
        if t.kind == "c_token":
            start_idx = cursor
            cursor -= 1
            continue
        if t.kind == "whitespace":
            cursor -= 1
            continue
        # Stop at a normal C comment (e.g., /* Parse header magic */) before the contract/declarator
        break
    return start_idx


def locate_all_prototype_spans(source: str, path: str = "<input>") -> list[Span]:
    """Locate all function prototype spans in a header source file in source order."""
    return [d.span for d in _iter_declaration_spans(source, path=path, allow_prototype=True, allow_definition=False)]


def locate_all_definition_spans(source: str, path: str = "<input>") -> dict[str, Span]:
    """Spans of every function definition in `source`, in one pass; the first one when a name repeats."""
    spans: dict[str, Span] = {}
    for decl in _iter_declaration_spans(source, path=path, allow_prototype=False, allow_definition=True):
        spans.setdefault(decl.span.function, decl.span)
    return spans


def _find_body_brace_offset(span_text: str, path: str = "<input>") -> int | None:
    """Return the byte offset of the function body's opening `{` inside `span_text`, or None."""
    tokens = tokenize_c_acsl(span_text, path=path)
    ignored = _conditional_delims(tokens).ignored
    paren_depth = 0
    brace_depth = 0
    last_top_brace: int | None = None
    for idx, tok in enumerate(tokens):
        if tok.kind == "c_token" and idx not in ignored:
            if tok.text == "(":
                paren_depth += 1
            elif tok.text == ")":
                paren_depth = max(0, paren_depth - 1)
            elif tok.text == "{":
                if paren_depth == 0 and brace_depth == 0:
                    last_top_brace = tok.start
                brace_depth += 1
            elif tok.text == "}":
                brace_depth = max(0, brace_depth - 1)
    return last_top_brace


def has_function_contract(
    source: str,
    function_name: str,
    is_header: bool = False,
    path: str = "<input>",
) -> bool:
    """
    Return True when one of `function_name`'s declarations in `source` (its definition; in a
    header any of them, `contract_declaration_spans`) has at least one function-level ACSL
    contract clause (`requires`, `terminates`, `decreases`, `exits`, `assigns`, `ensures`,
    `behavior`, `assumes`, `allocates`, `frees`, `complete`, `disjoint`) before its body `{`
    (or `;` for a prototype).
    """
    for decl in contract_declaration_spans(source, function_name, is_header=is_header, path=path):
        tokens = tokenize_c_acsl(_span_contract_part(decl, path=path), path=path)
        for tok in tokens:
            if tok.kind in ("acsl_block", "acsl_line") and not _is_doxygen_comment(tok.text):
                inner = tok.text[3:-2] if tok.kind == "acsl_block" else tok.text[3:]
                for seg in _parse_acsl_inner_segments(inner, tok.line):
                    if seg.kind in _CONTRACT_KWS:
                        return True
    return False


def splice_prover_changes(
    base_work_text: str,
    agent_work_text: str,
    current_work_text: str,
    function_name: str,
    is_header: bool = False,
    path: str = "<input>",
    contract_only: bool = False,
) -> str:
    """
    Validate that the prover only modified ACSL annotations inside `function_name`'s
    declarations (comparing `agent_work_text` against `base_work_text`), then splice the
    updated declarations into `current_work_text`. In a source file that is the definition;
    in a header it is every declaration (`contract_declaration_spans`: the prototype, the
    `static inline` definition, or both). When `contract_only=True`, only the contract before
    a definition's `{` is taken from `agent_work_text`; its body `{ ... }` is kept from
    `base_work_text`.
    """
    acsl_errors = verify_acsl_only(base_work_text, agent_work_text, path=path)
    if acsl_errors:
        raise AcslError(f"ACSL-only check failed on {path}:\n  " + "\n  ".join(acsl_errors))

    base_decls = contract_declaration_spans(base_work_text, function_name, is_header=is_header, path=path)
    agent_decls = contract_declaration_spans(agent_work_text, function_name, is_header=is_header, path=path)
    curr_decls = contract_declaration_spans(current_work_text, function_name, is_header=is_header, path=path)

    if not base_decls or not agent_decls or not curr_decls:
        raise ScopeViolationError(
            f"{path}: could not locate {'a declaration' if is_header else 'definition'} of function '{function_name}'"
        )

    # Verify the agent did not modify anything outside function_name's declarations: the text
    # between them (and before the first, after the last) must be unchanged. The ACSL-only check
    # above keeps every C token, so base and agent have the same declarations in the same order.
    def _gaps(text: str, decls: list[DeclSpan]) -> list[str]:
        out: list[str] = []
        last = 0
        for d in decls:
            out.append(text[last : d.span.start_byte])
            last = d.span.end_byte
        out.append(text[last:])
        return out

    kinds = [d.kind for d in base_decls]
    if [d.kind for d in agent_decls] != kinds or _gaps(base_work_text, base_decls) != _gaps(
        agent_work_text, agent_decls
    ):
        added = added_top_level_acsl_declarations(base_work_text, agent_work_text, path=path)
        if added:
            raise ScopeViolationError(
                f"{path}: agent added top-level ACSL declaration(s) outside '{function_name}': "
                f"{', '.join(added)}; file-scope ghost functions, predicates and lemmas are not "
                "mergeable by a prover (see the prover brief, Step B: Inductive Lemmas)"
            )
        raise ScopeViolationError(f"{path}: agent modified content outside assigned function '{function_name}'")

    # Verify that in current_work_text, none of function_name's declarations has been concurrently altered
    if [d.kind for d in curr_decls] != kinds or any(
        c.span.text != b.span.text for c, b in zip(curr_decls, base_decls, strict=True)
    ):
        raise ScopeViolationError(
            f"{path}: function '{function_name}' in workspace/work/ diverged from agent base snapshot"
        )

    spliced = current_work_text
    # Replace from the last declaration backwards so the earlier byte offsets stay valid.
    for curr, base, agent in reversed(list(zip(curr_decls, base_decls, agent_decls, strict=True))):
        replacement_span = agent.span.text
        if contract_only and agent.kind == "definition":
            agent_brace = _find_body_brace_offset(agent.span.text, path=path)
            base_brace = _find_body_brace_offset(base.span.text, path=path)
            if agent_brace is not None and base_brace is not None:
                replacement_span = agent.span.text[:agent_brace] + base.span.text[base_brace:]
        spliced = spliced[: curr.span.start_byte] + replacement_span + spliced[curr.span.end_byte :]
    post_errors = verify_acsl_only(current_work_text, spliced, path=path)
    if post_errors:
        raise AcslError(f"Post-splice ACSL-only check failed on {path}:\n  " + "\n  ".join(post_errors))
    return spliced


# ---------------------------------------------------------------------------
# Comment- & quantifier-aware ACSL top-level declaration parser & deduplicator
# ---------------------------------------------------------------------------

_TOP_DECL_KWS = frozenset({"predicate", "logic", "lemma", "type", "axiomatic", "inductive", "ghost"})
_CONTRACT_KWS = frozenset(
    {
        "requires",
        "terminates",
        "decreases",
        "exits",
        "assigns",
        "ensures",
        "behavior",
        "assumes",
        "allocates",
        "frees",
        "complete",
        "disjoint",
    }
)
_C_TYPE_KEYWORDS = frozenset(
    {
        "int",
        "char",
        "short",
        "long",
        "float",
        "double",
        "void",
        "signed",
        "unsigned",
        "bool",
        "_bool",
        "integer",
        "real",
        "boolean",
        "size_t",
        "ssize_t",
        "uint8_t",
        "uint16_t",
        "uint32_t",
        "uint64_t",
        "int8_t",
        "int16_t",
        "int32_t",
        "int64_t",
        "uintptr_t",
        "intptr_t",
        "ptrdiff_t",
    }
)
_CHAR_LIT_RE = re.compile(r"'(?:\\.|[^'\\\n]){1,4}'")
_STR_LIT_RE = re.compile(r'"(?:\\.|[^"\\\n])*"')


@dataclass(slots=True, frozen=True)
class _AcslSegment:
    kind: str | None  # top-level declaration keyword, contract keyword, or None for trailing trivia
    name: str | None  # declared identifier name when kind in _TOP_DECL_KWS
    raw_text: str
    line: int
    arity: int | None = None
    param_types: tuple[str, ...] | None = None


def _normalize_acsl_type(type_str: str) -> str:
    """Normalize whitespace and type aliases in ACSL parameter type strings."""
    t = mask_comments_and_literals(type_str, acsl="blank", literals=False, on_error="mask").strip()
    t = re.sub(r"\s*\*\s*", " *", t)
    t = re.sub(r"\s+", " ", t).strip()
    t = re.sub(r"\buint8_t\b", "unsigned char", t)
    t = re.sub(r"\bint8_t\b", "signed char", t)
    t = re.sub(r"\buint16_t\b", "unsigned short", t)
    t = re.sub(r"\bint16_t\b", "short", t)
    t = re.sub(r"\buint32_t\b", "unsigned int", t)
    t = re.sub(r"\bint32_t\b", "int", t)
    t = re.sub(r"\buint64_t\b", "unsigned long", t)
    t = re.sub(r"\bint64_t\b", "long", t)
    return t


def _extract_decl_param_types(
    kind: str,
    body_after_kw: str,
    decl_name: str | None,
) -> tuple[str, ...] | None:
    """Return the normalized parameter types for `predicate`/`logic`/`inductive` declarations, or None."""
    if kind not in ("predicate", "logic", "inductive") or not decl_name:
        return None
    scrubbed = _COMMENT_IN_ACSL_RE.sub(" ", body_after_kw)
    pos = -1
    for m in re.finditer(rf"\b{re.escape(decl_name)}\b", scrubbed):
        pos = m.end()
        tail_preview = scrubbed[pos:].lstrip()
        if not tail_preview or tail_preview[0] in "({=;":
            break
    if pos == -1:
        return None
    i = pos
    n = len(scrubbed)
    # Skip optional `{L1, L2}` label list after the declaration name
    while i < n and scrubbed[i].isspace():
        i += 1
    if i < n and scrubbed[i] == "{":
        b_depth = 1
        i += 1
        while i < n and b_depth > 0:
            if scrubbed[i] == "{":
                b_depth += 1
            elif scrubbed[i] == "}":
                b_depth -= 1
            i += 1
    while i < n and scrubbed[i].isspace():
        i += 1
    if i >= n or scrubbed[i] != "(":
        return ()

    # Scan parameter list `( ... )`
    p_depth = 1
    i += 1
    param_start = i
    raw_params: list[str] = []
    while i < n and p_depth > 0:
        ch = scrubbed[i]
        if ch in "([<":
            p_depth += 1
        elif ch in ")]>":
            p_depth -= 1
            if p_depth == 0:
                raw_params.append(scrubbed[param_start:i])
                break
        elif ch == "," and p_depth == 1:
            raw_params.append(scrubbed[param_start:i])
            param_start = i + 1
        i += 1

    parsed_types: list[str] = []
    for raw in raw_params:
        cleaned = raw.strip()
        if not cleaned or cleaned == "void":
            continue
        star_pos = cleaned.rfind("*")
        if star_pos != -1:
            after = cleaned[star_pos + 1 :].strip()
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", after):
                type_part = cleaned[: star_pos + 1]
            else:
                type_part = cleaned
        else:
            words = cleaned.split()
            if len(words) > 1:
                # Disambiguate anonymous parameter from named parameter:
                # If the last word is a known type keyword, or if the declaration
                # is an anonymous struct/union/enum (e.g. "struct token", "const struct token"),
                # the last word is part of the type, not a variable name.
                has_tag = False
                for tag_kw in ("struct", "union", "enum"):
                    if tag_kw in words:
                        idx = words.index(tag_kw)
                        if idx == len(words) - 2:
                            has_tag = True
                        break

                if words[-1].lower() in _C_TYPE_KEYWORDS or has_tag:
                    type_part = cleaned
                elif re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", words[-1]):
                    type_part = " ".join(words[:-1])
                else:
                    type_part = cleaned
            else:
                type_part = cleaned
        parsed_types.append(_normalize_acsl_type(type_part))

    return tuple(parsed_types)


def _is_acsl_comment_or_whitespace_only(inner: str) -> bool:
    """Return True if the ACSL annotation interior contains only whitespace and/or comments."""
    no_comments = mask_comments_and_literals(inner, acsl="blank", literals=False, on_error="mask")
    remainder = re.sub(r"[\s*@]", "", no_comments)
    return len(remainder) == 0


def _extract_decl_arity(kind: str, body_after_kw: str, decl_name: str | None) -> int | None:
    """Return the parameter count for `predicate`/`logic`/`inductive` declarations, or None."""
    if kind not in ("predicate", "logic", "inductive") or not decl_name:
        return None
    scrubbed = _COMMENT_IN_ACSL_RE.sub(" ", body_after_kw)
    # Find the last occurrence of decl_name before `(`, `=`, `;`, or `reads`
    pos = -1
    for m in re.finditer(rf"\b{re.escape(decl_name)}\b", scrubbed):
        pos = m.end()
        tail_preview = scrubbed[pos:].lstrip()
        if not tail_preview or tail_preview[0] in "({=;":
            break
    if pos == -1:
        return None
    i = pos
    n = len(scrubbed)
    # Skip optional `{L1, L2}` label list after the declaration name
    while i < n and scrubbed[i].isspace():
        i += 1
    if i < n and scrubbed[i] == "{":
        b_depth = 1
        i += 1
        while i < n and b_depth > 0:
            if scrubbed[i] == "{":
                b_depth += 1
            elif scrubbed[i] == "}":
                b_depth -= 1
            i += 1
    while i < n and scrubbed[i].isspace():
        i += 1
    if i >= n or scrubbed[i] != "(":
        return 0
    # Scan parameter list `( ... )` and count top-level commas
    p_depth = 1
    i += 1
    param_start = i
    commas = 0
    while i < n and p_depth > 0:
        ch = scrubbed[i]
        if ch in "([<":
            p_depth += 1
        elif ch in ")]>":
            p_depth -= 1
            if p_depth == 0:
                break
        elif ch == "," and p_depth == 1:
            commas += 1
        i += 1
    inner_params = scrubbed[param_start:i].strip()
    if not inner_params:
        return 0
    return commas + 1


def _extract_decl_name(kind: str, body_after_kw: str) -> str | None:
    """Extract the declared identifier name from the body following `kind`."""
    scrubbed = _COMMENT_IN_ACSL_RE.sub(" ", body_after_kw)
    if kind in ("predicate", "lemma", "axiomatic", "inductive"):
        m = _IDENT_RE.search(scrubbed)
        return m.group(0) if m else None
    if kind == "type":
        ids = _IDENT_RE.findall(scrubbed)
        if not ids:
            return None
        if ids[0] == "invariant" and len(ids) >= 2:
            return ids[1]
        return ids[0]
    if kind in ("logic", "ghost"):
        # Scan up to the parameter list `(`, label `{`, array `[`, initializer `=`, `;`, or `reads`
        angle_depth = 0
        last_id: str | None = None
        i = 0
        n = len(scrubbed)
        while i < n:
            ch = scrubbed[i]
            if ch == "<":
                angle_depth += 1
                i += 1
                continue
            if ch == ">":
                angle_depth = max(0, angle_depth - 1)
                i += 1
                continue
            if angle_depth == 0 and ch in "({=[;":
                break
            if ch == "\\":
                m_bs = _IDENT_RE.match(scrubbed, i + 1)
                i = m_bs.end() if m_bs else (i + 1)
                continue
            m_id = _IDENT_RE.match(scrubbed, i)
            if m_id:
                word = m_id.group(0)
                if angle_depth == 0:
                    if word == "reads" and last_id is not None:
                        break
                    last_id = word
                i = m_id.end()
                continue
            i += 1
        return last_id
    return None


def _consume_line_tail(inner: str, pos: int) -> tuple[int, int]:
    """Consume trailing horizontal whitespace, optional inline `//...` comment, and one newline."""
    n = len(inner)
    i = pos
    while i < n and inner[i] in " \t\r":
        i += 1
    if i + 1 < n and inner[i] == "/" and inner[i + 1] == "/":
        while i < n and inner[i] != "\n":
            i += 1
    if i < n and inner[i] == "\n":
        return i + 1, 1
    return pos, 0


def _parse_acsl_inner_segments(inner: str, base_line: int) -> list[_AcslSegment]:
    """
    Partition the interior of a top-level `/*@ ... */` or `//@ ...` token into
    clauses/declarations while tracking `//` comments, string/char literals,
    `(...)`/`{...}`/`[...]` nesting, and `\\forall`/`\\exists`/`\\let` binder semicolons.
    """
    segments: list[_AcslSegment] = []
    n = len(inner)
    i = 0
    seg_start = 0
    line = base_line
    seg_line = base_line
    line_start_offset = 0
    at_line_start = True

    p_depth = 0
    b_depth = 0
    k_depth = 0
    binder_stack: list[tuple[int, int, int]] = []
    current_kw: str | None = None
    kw_end_offset: int = -1
    seen_paren_after_kw = False

    def _flush(end_pos: int) -> None:
        nonlocal seg_start, current_kw, kw_end_offset, seen_paren_after_kw
        if end_pos <= seg_start:
            return
        decl_name: str | None = None
        decl_arity: int | None = None
        decl_param_types: tuple[str, ...] | None = None
        if current_kw in _TOP_DECL_KWS and kw_end_offset != -1 and kw_end_offset <= end_pos:
            body_slice = inner[kw_end_offset:end_pos]
            if current_kw == "ghost":
                body_slice = _GHOST_CONTRACT_RE.sub(" ", body_slice)
            decl_name = _extract_decl_name(current_kw, body_slice)
            decl_arity = _extract_decl_arity(current_kw, body_slice, decl_name)
            decl_param_types = _extract_decl_param_types(current_kw, body_slice, decl_name)
        segments.append(
            _AcslSegment(
                kind=current_kw,
                name=decl_name,
                raw_text=inner[seg_start:end_pos],
                line=seg_line,
                arity=decl_arity,
                param_types=decl_param_types,
            )
        )
        seg_start = end_pos
        current_kw = None
        kw_end_offset = -1
        seen_paren_after_kw = False
        binder_stack.clear()

    while i < n:
        ch = inner[i]

        if ch == "\n":
            line += 1
            i += 1
            line_start_offset = i
            at_line_start = True
            continue

        if ch in " \t\r\f\v":
            i += 1
            continue

        # Single-line comment inside ACSL block: skip completely
        if ch == "/" and i + 1 < n and inner[i + 1] == "/":
            i += 2
            while i < n and inner[i] != "\n":
                i += 1
            at_line_start = False
            continue

        # A ghost function's `/@ ... @/` contract: its `;` and keywords belong to the ghost
        # declaration, not to new top-level segments
        if current_kw == "ghost" and ch == "/" and i + 1 < n and inner[i + 1] == "@":
            close = inner.find("@/", i + 2)
            end = n if close == -1 else close + 2
            nl = inner.count("\n", i, end)
            if nl:
                line += nl
                line_start_offset = inner.rfind("\n", i, end) + 1
            at_line_start = False
            i = end
            continue

        # Leading `*` bullet on continuation line inside /*@ ... */
        if at_line_start and ch == "*":
            at_line_start = False
            i += 1
            continue

        # String or character literal
        if ch == '"':
            m_str = _STR_LIT_RE.match(inner, i)
            at_line_start = False
            i = m_str.end() if m_str else (i + 1)
            continue
        if ch == "'":
            m_chr = _CHAR_LIT_RE.match(inner, i)
            at_line_start = False
            i = m_chr.end() if m_chr else (i + 1)
            continue

        # Backslash ACSL keyword (\forall, \exists, \let, etc.)
        if ch == "\\":
            at_line_start = False
            m_bs = _IDENT_RE.match(inner, i + 1)
            if m_bs:
                bs_word = m_bs.group(0)
                if bs_word in ("forall", "exists", "let"):
                    binder_stack.append((p_depth, b_depth, k_depth))
                i = m_bs.end()
                continue
            i += 1
            continue

        # Identifier
        m_id = _IDENT_RE.match(inner, i)
        if m_id:
            word = m_id.group(0)
            if p_depth == 0 and b_depth == 0 and k_depth == 0:
                if current_kw is None:
                    current_kw = word
                    kw_end_offset = m_id.end()
                    seg_line = line
                elif at_line_start and (word in _TOP_DECL_KWS or word in _CONTRACT_KWS):
                    # A new top-level declaration/clause keyword started at line start at depth 0
                    if line_start_offset > seg_start:
                        _flush(line_start_offset)
                    current_kw = word
                    kw_end_offset = m_id.end()
                    seg_line = line
            at_line_start = False
            i = m_id.end()
            continue

        at_line_start = False

        if ch == "(":
            if current_kw is not None and b_depth == 0:
                seen_paren_after_kw = True
            p_depth += 1
            i += 1
            continue
        if ch == ")":
            p_depth = max(0, p_depth - 1)
            while binder_stack and binder_stack[-1][0] > p_depth:
                binder_stack.pop()
            i += 1
            continue
        if ch == "{":
            b_depth += 1
            i += 1
            continue
        if ch == "}":
            b_depth = max(0, b_depth - 1)
            while binder_stack and binder_stack[-1][1] > b_depth:
                binder_stack.pop()
            i += 1
            if b_depth == 0 and p_depth == 0 and k_depth == 0:
                if current_kw in ("axiomatic", "inductive") or (current_kw == "ghost" and seen_paren_after_kw):
                    while i < n and inner[i] in " \t":
                        i += 1
                    if i < n and inner[i] == ";":
                        i += 1
                    next_i, nl_inc = _consume_line_tail(inner, i)
                    _flush(next_i)
                    if nl_inc:
                        line += nl_inc
                        line_start_offset = next_i
                        at_line_start = True
                    i = next_i
            continue
        if ch == "[":
            k_depth += 1
            i += 1
            continue
        if ch == "]":
            k_depth = max(0, k_depth - 1)
            while binder_stack and binder_stack[-1][2] > k_depth:
                binder_stack.pop()
            i += 1
            continue
        if ch == ";":
            i += 1
            if binder_stack and binder_stack[-1] == (p_depth, b_depth, k_depth):
                binder_stack.pop()
            elif p_depth == 0 and b_depth == 0 and k_depth == 0 and current_kw is not None:
                next_i, nl_inc = _consume_line_tail(inner, i)
                _flush(next_i)
                if nl_inc:
                    line += nl_inc
                    line_start_offset = next_i
                    at_line_start = True
                i = next_i
            continue

        i += 1

    if seg_start < n:
        _flush(n)

    return segments


def extract_top_level_acsl_declarations(source: str, path: str = "<input>") -> list[dict]:
    """
    Return all top-level ACSL declarations (`predicate`, `logic`, `lemma`, `type`,
    `axiomatic`, `inductive`, `ghost`) outside C `{ ... }` blocks in `source`.
    """
    tokens = tokenize_c_acsl(source, path=path)
    delims = _conditional_delims(tokens)
    linkage = _linkage_block_braces(tokens, delims) | delims.ignored
    brace_depth = 0
    paren_depth = 0
    decls: list[dict] = []

    for tok_idx, tok in enumerate(tokens):
        if tok_idx in linkage:
            continue
        if tok.kind == "c_token":
            if tok.text == "{":
                brace_depth += 1
            elif tok.text == "}":
                brace_depth = max(0, brace_depth - 1)
            elif tok.text == "(":
                paren_depth += 1
            elif tok.text == ")":
                paren_depth = max(0, paren_depth - 1)
            continue

        if brace_depth == 0 and paren_depth == 0 and tok.kind in ("acsl_block", "acsl_line"):
            inner = tok.text[3:-2] if tok.kind == "acsl_block" else tok.text[3:]
            for seg in _parse_acsl_inner_segments(inner, tok.line):
                if seg.kind in _TOP_DECL_KWS and seg.name:
                    profile_key = f"{seg.name}/{seg.arity}" if seg.arity is not None else seg.name
                    param_types = seg.param_types
                    full_profile = (
                        f"{seg.name}(" + ", ".join(param_types) + ")" if param_types is not None else profile_key
                    )
                    decls.append(
                        {
                            "kind": seg.kind,
                            "name": seg.name,
                            "arity": seg.arity,
                            "param_types": param_types,
                            "profile_key": profile_key,
                            "full_profile": full_profile,
                            "text": seg.raw_text.strip(),
                            "line": seg.line,
                        }
                    )

    return decls


_TARGET_UNSOUND_AXIOM_ADMIT_RE = re.compile(r"\b(admit|axiom|axiomatic)\b")
_MODIFIED_LEMMA_RE = re.compile(r"^\s*(?:admit|check)\s+lemma\s+([A-Za-z_][A-Za-z0-9_]*)\b")
_SENTINEL_INDEX_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*([^\]]+)\s*\]$")
_SENTINEL_DEREF_RE = re.compile(r"^\*\s*([A-Za-z_][A-Za-z0-9_]*)$")
_POS_INT_RE = re.compile(r"^(\d+)[uUlL]*$")
_CMP_OP_RE = re.compile(r"<=|>=|==|!=|<(?!=)|>(?!=)")


def _classify_wp_inactive_cond(word: str, directive: str) -> tuple[bool, bool]:
    """
    Classify a preprocessor conditional arm for WP visibility.
    Returns `(arm_inactive_for_wp, else_inactive_for_wp)`:
    - `#if defined(__FRAMAC_EACSL__)` / `#ifdef __FRAMAC_EACSL__` / `#if 0` -> `(True, False)`
    - `#ifndef __FRAMAC_EACSL__` / `#if !defined(__FRAMAC_EACSL__)` / `#if 1` -> `(False, True)`
    - Any other directive -> `(False, False)`
    """
    rest = _COND_DIRECTIVE_RE.sub("", _DIRECTIVE_NOISE_RE.sub(" ", directive), count=1).strip()
    if word == "ifdef":
        return (rest == "__FRAMAC_EACSL__", False)
    if word == "ifndef":
        return (False, rest == "__FRAMAC_EACSL__")
    cond = re.sub(r"\s+", "", _DEFINED_OPERAND_RE.sub(lambda m: f"defined({m.group(1) or m.group(2)})", rest))
    cond = _strip_outer_parens(cond)
    if cond == "0":
        return (True, False)
    if cond == "1":
        return (False, True)
    if cond in ("defined(__FRAMAC_EACSL__)", "__FRAMAC_EACSL__"):
        return (True, False)
    if cond.startswith("!"):
        inner = _strip_outer_parens(cond[1:])
        if inner in ("defined(__FRAMAC_EACSL__)", "__FRAMAC_EACSL__"):
            return (False, True)
    if len(_split_top_level(cond, "||")) == 1:
        for part in _split_top_level(cond, "&&"):
            atom = _strip_outer_parens(part)
            if atom in ("0", "defined(__FRAMAC_EACSL__)", "__FRAMAC_EACSL__"):
                return (True, False)
    return (False, False)


def _eacsl_only_token_indices(tokens: list[Token]) -> set[int]:
    """Token indices inside `#if defined(__FRAMAC_EACSL__)` (or `#if 0`) blocks that WP never parses."""
    skipped: set[int] = set()
    # Each frame: [parent_inactive, current_inactive, else_inactive]
    stack: list[list[bool]] = []
    for idx, tok in enumerate(tokens):
        if tok.kind == "pp_directive":
            m = _COND_DIRECTIVE_RE.match(tok.text.lstrip())
            if m:
                word = m.group(1)
                if word in ("if", "ifdef", "ifndef"):
                    parent_in = bool(stack and (stack[-1][0] or stack[-1][1]))
                    cur_in, else_in = _classify_wp_inactive_cond(word, tok.text)
                    stack.append([parent_in, cur_in, else_in])
                elif word == "elif" and stack:
                    parent_in, _old_cur, old_else = stack[-1]
                    cur_in, new_else = _classify_wp_inactive_cond(word, tok.text)
                    stack[-1] = [parent_in, True if old_else else cur_in, old_else or new_else]
                elif word == "else" and stack:
                    parent_in, _old_cur, old_else = stack[-1]
                    stack[-1] = [parent_in, old_else, False]
                elif word == "endif" and stack:
                    stack.pop()
                continue
        if stack and (stack[-1][0] or stack[-1][1]):
            skipped.add(idx)
    return skipped


def _iter_wp_top_level_acsl_segments(tokens: list[Token]) -> Iterator[_AcslSegment]:
    """
    Yield top-level ACSL segments visible to WP, ignoring C comments, string/char literals,
    doxygen comments (`/*@{`, `/*@}`, `/*@*`, `//@{`, ...), `/*@ ghost ... */` blocks, and
    `#if defined(__FRAMAC_EACSL__)` conditional blocks. Expands `axiomatic { ... }` bodies.
    """
    delims = _conditional_delims(tokens)
    linkage = _linkage_block_braces(tokens, delims) | delims.ignored
    eacsl_skipped = _eacsl_only_token_indices(tokens)
    brace_depth = 0
    paren_depth = 0

    def _yield_segments(inner_text: str, start_line: int) -> Iterator[_AcslSegment]:
        for seg in _parse_acsl_inner_segments(inner_text, start_line):
            yield seg
            if seg.kind == "axiomatic":
                open_b = seg.raw_text.find("{")
                close_b = seg.raw_text.rfind("}")
                if open_b != -1 and close_b > open_b:
                    ax_line = seg.line + seg.raw_text.count("\n", 0, open_b)
                    yield from _yield_segments(seg.raw_text[open_b + 1 : close_b], ax_line)

    for tok_idx, tok in enumerate(tokens):
        if tok_idx in linkage:
            continue
        if tok.kind == "c_token":
            if tok.text == "{":
                brace_depth += 1
            elif tok.text == "}":
                brace_depth = max(0, brace_depth - 1)
            elif tok.text == "(":
                paren_depth += 1
            elif tok.text == ")":
                paren_depth = max(0, paren_depth - 1)
            continue

        if tok_idx in eacsl_skipped:
            continue
        if brace_depth == 0 and paren_depth == 0 and tok.kind in ("acsl_block", "acsl_line"):
            if _is_doxygen_comment(tok.text):
                continue
            raw_inner = tok.text[3:-2] if tok.kind == "acsl_block" else tok.text[3:]
            if _GHOST_ANNOTATION_RE.match(raw_inner):
                continue
            _shape, visible = _kernel_views(tok.text)
            vis_inner = visible[3:-2] if tok.kind == "acsl_block" else visible[3:]
            yield from _yield_segments(vis_inner, tok.line)


def find_top_level_lemmas(source: str, path: str = "<input>") -> list[str]:
    """
    Return names of top-level ACSL `lemma` declarations (standalone or inside `axiomatic`) in `source`,
    ignoring C/ACSL comments, string/char literals, doxygen comments, and `#if defined(__FRAMAC_EACSL__)` blocks.
    """
    tokens = tokenize_c_acsl(source, path=path)
    lemmas: list[str] = []
    for seg in _iter_wp_top_level_acsl_segments(tokens):
        if seg.kind == "lemma" and seg.name:
            lemmas.append(seg.name)
        elif seg.kind in ("admit", "check"):
            m_mod = _MODIFIED_LEMMA_RE.match(seg.raw_text)
            if m_mod:
                lemmas.append(m_mod.group(1))
    return list(dict.fromkeys(lemmas))


def find_target_unsound_axioms_or_admits(source: str, path: str = "<input>") -> list[str]:
    """
    Return soundness errors for any `axiom`, `axiomatic`, or `admit` ACSL construct in `source`
    (ignoring C/ACSL comments, string/char literals, doxygen comments, and `#if defined(__FRAMAC_EACSL__)` blocks).
    """
    tokens = tokenize_c_acsl(source, path=path)
    eacsl_skipped = _eacsl_only_token_indices(tokens)
    errors: list[str] = []
    for idx, tok in enumerate(tokens):
        if idx in eacsl_skipped or tok.kind not in ("acsl_block", "acsl_line"):
            continue
        if _is_doxygen_comment(tok.text):
            continue
        flat = _scrub_acsl_literals(tok.text).replace("@", " ")
        seen_kws = list(dict.fromkeys(m.group(1) for m in _TARGET_UNSOUND_AXIOM_ADMIT_RE.finditer(flat)))
        for kw in seen_kws:
            errors.append(f"{path}:{tok.line}: forbidden unsound ACSL construct '{kw}' in target source")
    return errors


@dataclass(slots=True, frozen=True)
class _LogicDef:
    kind: str  # "logic" | "predicate"
    name: str
    params: tuple[str, ...]
    body: str
    line: int


def _mask_expr_literals(expr: str) -> str:
    """Blank string and char literal contents in an ACSL expression while keeping exact length."""
    return mask_comments_and_literals(expr, acsl="keep", literals=True, on_error="mask")


def _extract_logic_param_names(header: str, decl_name: str) -> tuple[str, ...]:
    """Extract parameter identifier names from a `logic` / `predicate` header before `=`."""
    masked = _mask_expr_literals(header)
    pos = -1
    for m in re.finditer(rf"\b{re.escape(decl_name)}\b", masked):
        pos = m.end()
        tail = masked[pos:].lstrip()
        if not tail or tail[0] in "(<{":
            break
    if pos == -1:
        return ()
    i = pos
    n = len(masked)
    while i < n:
        while i < n and masked[i].isspace():
            i += 1
        if i < n and masked[i] in "<{":
            open_ch = masked[i]
            close_ch = ">" if open_ch == "<" else "}"
            depth = 1
            i += 1
            while i < n and depth > 0:
                if masked[i] == open_ch:
                    depth += 1
                elif masked[i] == close_ch:
                    depth -= 1
                i += 1
            continue
        break
    if i >= n or masked[i] != "(":
        return ()
    depth = 1
    i += 1
    p_start = i
    raw_params: list[str] = []
    while i < n and depth > 0:
        ch = masked[i]
        if ch in "([<":
            depth += 1
        elif ch in ")]>":
            depth -= 1
            if depth == 0:
                raw_params.append(header[p_start:i])
                break
        elif ch == "," and depth == 1:
            raw_params.append(header[p_start:i])
            p_start = i + 1
        i += 1
    names: list[str] = []
    for raw in raw_params:
        cleaned = re.sub(r"\[[^\]]*\]", "", raw).strip()
        if not cleaned or cleaned == "void":
            continue
        ids = _IDENT_RE.findall(cleaned)
        if not ids:
            continue
        candidate = ids[-1]
        if candidate.lower() in _C_TYPE_KEYWORDS:
            continue
        names.append(candidate)
    return tuple(names)


def _extract_logic_def(seg: _AcslSegment) -> _LogicDef | None:
    """Parse a `logic ... = body;` or `predicate ... = body;` segment; None when it has no `=` body."""
    if seg.kind not in ("logic", "predicate") or not seg.name:
        return None
    raw = seg.raw_text
    masked = _mask_expr_literals(raw)
    depth = 0
    eq_pos = -1
    n = len(masked)
    i = 0
    while i < n:
        ch = masked[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        elif depth == 0 and ch == "=":
            prev_ch = masked[i - 1] if i > 0 else ""
            next_ch = masked[i + 1] if i + 1 < n else ""
            if prev_ch not in ("=", "!", "<", ">") and next_ch != "=":
                eq_pos = i
                break
        i += 1
    if eq_pos == -1:
        return None
    header = raw[:eq_pos]
    body = raw[eq_pos + 1 :].strip()
    if body.endswith(";"):
        body = body[:-1].strip()
    if not body:
        return None
    params = _extract_logic_param_names(header, seg.name)
    return _LogicDef(kind=seg.kind, name=seg.name, params=params, body=body, line=seg.line)


def _split_call_args(args_text: str) -> list[str]:
    """Split a comma-separated ACSL call argument list respecting brackets and literals."""
    if not args_text.strip():
        return []
    masked = _mask_expr_literals(args_text)
    depth = 0
    parts: list[str] = []
    start = 0
    for i, ch in enumerate(masked):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            parts.append(args_text[start:i].strip())
            start = i + 1
    parts.append(args_text[start:].strip())
    return parts


def _extract_logic_calls(body: str, zero_arg_names: frozenset[str]) -> list[tuple[str, int, list[str]]]:
    """
    Extract all logic/predicate calls `(name, arity, args)` occurring in `body` (including nested calls
    inside arguments and `\\at(...)`), skipping literals, backslash builtins, and struct member accesses.
    """
    masked = _mask_expr_literals(body)
    n = len(masked)
    calls: list[tuple[str, int, list[str]]] = []
    i = 0
    while i < n:
        ch = masked[i]
        if ch == "\\":
            m_bs = _IDENT_RE.match(masked, i + 1)
            i = m_bs.end() if m_bs else (i + 1)
            continue
        m_id = _IDENT_RE.match(masked, i)
        if not m_id:
            i += 1
            continue
        name = m_id.group(0)
        prev_idx = i - 1
        while prev_idx >= 0 and masked[prev_idx].isspace():
            prev_idx -= 1
        is_member = prev_idx >= 0 and (
            masked[prev_idx] == "." or (masked[prev_idx] == ">" and prev_idx > 0 and masked[prev_idx - 1] == "-")
        )
        j = m_id.end()
        if not is_member:
            k = j
            while k < n and masked[k].isspace():
                k += 1
            # Skip optional `{L1, L2}` label arguments on a logic/predicate call
            if k < n and masked[k] == "{":
                b_depth = 1
                k += 1
                while k < n and b_depth > 0:
                    if masked[k] == "{":
                        b_depth += 1
                    elif masked[k] == "}":
                        b_depth -= 1
                    k += 1
                while k < n and masked[k].isspace():
                    k += 1
            if k < n and masked[k] == "(":
                p_depth = 1
                m_pos = k + 1
                while m_pos < n and p_depth > 0:
                    if masked[m_pos] == "(":
                        p_depth += 1
                    elif masked[m_pos] == ")":
                        p_depth -= 1
                    m_pos += 1
                if p_depth == 0:
                    args = _split_call_args(body[k + 1 : m_pos - 1])
                    calls.append((name, len(args), args))
                    # Advance only past the identifier so nested calls inside arguments are also scanned.
            elif name in zero_arg_names:
                calls.append((name, 0, []))
        i = j
    return calls


def _split_top_level_masked(expr: str, op: str) -> list[str]:
    """Split `expr` on top-level `op` outside brackets and string/char literals."""
    masked = _mask_expr_literals(expr)
    top = _top_level_positions(masked)
    parts: list[str] = []
    start = i = 0
    while i < len(masked):
        if top[i] and masked.startswith(op, i) and not (op == "==>" and i > 0 and masked[i - 1] == "<"):
            parts.append(expr[start:i].strip())
            i += len(op)
            start = i
        else:
            i += 1
    parts.append(expr[start:].strip())
    return parts


def _split_top_level_ternary(expr: str) -> tuple[str, str, str] | None:
    """If `expr` is a top-level `cond ? then_expr : else_expr`, return `(cond, then_expr, else_expr)`."""
    masked = _mask_expr_literals(expr)
    top = _top_level_positions(masked)
    q_pos = -1
    for i, ch in enumerate(masked):
        if top[i] and ch == "?":
            q_pos = i
            break
    if q_pos == -1:
        return None
    q_depth = 1
    for j in range(q_pos + 1, len(masked)):
        if not top[j]:
            continue
        if masked[j] == "?":
            q_depth += 1
        elif masked[j] == ":":
            q_depth -= 1
            if q_depth == 0:
                return expr[:q_pos].strip(), expr[q_pos + 1 : j].strip(), expr[j + 1 :].strip()
    return None


def _strip_outer_parens_masked(expr: str) -> str:
    """Strip balanced outer parentheses from `expr`, ignoring parentheses inside literals."""
    text = expr.strip()
    while text.startswith("(") and text.endswith(")"):
        masked = _mask_expr_literals(text)
        depth = 0
        closes_early = False
        for i, ch in enumerate(masked):
            depth += (ch == "(") - (ch == ")")
            if depth == 0 and i < len(masked) - 1:
                closes_early = True
                break
        if closes_early or depth != 0:
            return text
        text = text[1:-1].strip()
    return text


def _record_rel_constraint(
    out: dict[str, list[tuple[str, str | None]]],
    lhs: str,
    op: str,
    rhs: str,
    polarity: str,
    param_set: frozenset[str],
) -> None:
    """
    Record guarded descent/advance directions from one atomic relation `lhs op rhs`.
    `polarity == 'base_when_true'` means the relation triggers the base case (its negation holds in recursion);
    `polarity == 'rec_when_true'` means the relation holds in the recursive branch.
    """
    if polarity == "rec_when_true":
        flip = {"<=": ">", "<": ">=", ">=": "<", ">": "<=", "==": "!=", "!=": "=="}
        op = flip[op]
    lhs = _strip_outer_parens_masked(lhs)
    rhs = _strip_outer_parens_masked(rhs)

    def _add(p: str, direction: str, partner: str | None = None) -> None:
        entry = (direction, partner)
        lst = out.setdefault(p, [])
        if entry not in lst:
            lst.append(entry)

    # Sentinel base checks: `s[0] == '\0'`, `*s == '\0'`, `buf[i] == '\0'` (or symmetric)
    if op == "==":
        for side in (lhs, rhs):
            m_idx = _SENTINEL_INDEX_RE.match(side)
            if m_idx:
                base_id, idx_expr = m_idx.group(1), _strip_outer_parens_masked(m_idx.group(2))
                if base_id in param_set and _POS_INT_RE.match(idx_expr):
                    _add(base_id, "up")
                elif idx_expr in param_set:
                    _add(idx_expr, "up")
            m_deref = _SENTINEL_DEREF_RE.match(side)
            if m_deref and m_deref.group(1) in param_set:
                _add(m_deref.group(1), "up")

    lhs_is_p = lhs in param_set
    rhs_is_p = rhs in param_set
    if op in ("<=", "<"):
        # Base `lhs <= rhs`: in recursion `lhs > rhs` (lhs bounded below -> down; rhs bounded above -> up)
        if lhs_is_p:
            _add(lhs, "down", rhs if rhs_is_p else None)
        if rhs_is_p:
            _add(rhs, "up", lhs if lhs_is_p else None)
    elif op in (">=", ">"):
        # Base `lhs >= rhs`: in recursion `lhs < rhs` (lhs bounded above -> up; rhs bounded below -> down)
        if lhs_is_p:
            _add(lhs, "up", rhs if rhs_is_p else None)
        if rhs_is_p:
            _add(rhs, "down", lhs if lhs_is_p else None)
    elif op == "==":
        if lhs_is_p and rhs_is_p and lhs != rhs:
            _add(lhs, "down", rhs)
            _add(lhs, "up", rhs)
            _add(rhs, "down", lhs)
            _add(rhs, "up", lhs)
        elif lhs_is_p:
            m_lit = _POS_INT_RE.match(rhs)
            if m_lit and int(m_lit.group(1)) in (0, 1):
                _add(lhs, "down")
        elif rhs_is_p:
            m_lit = _POS_INT_RE.match(lhs)
            if m_lit and int(m_lit.group(1)) in (0, 1):
                _add(rhs, "down")


def _extract_guard_constraints(
    cond: str, polarity: str, param_set: frozenset[str], out: dict[str, list[tuple[str, str | None]]]
) -> None:
    """Populate `out` with guarded parameter directions guaranteed to hold in the recursive branch."""
    cur = _strip_outer_parens_masked(cond)
    if not cur:
        return
    if cur.startswith("!") and not cur.startswith("!="):
        inner = cur[1:].strip()
        if inner.startswith("(") and _strip_outer_parens_masked(inner) != inner:
            flipped = "rec_when_true" if polarity == "base_when_true" else "base_when_true"
            _extract_guard_constraints(inner, flipped, param_set, out)
            return
    # Boolean duality: base(A || B) => rec(!A && !B); rec(A && B) => rec(A) and rec(B).
    split_op = "||" if polarity == "base_when_true" else "&&"
    parts = _split_top_level_masked(cur, split_op)
    if len(parts) > 1:
        for part in parts:
            _extract_guard_constraints(part, polarity, param_set, out)
        return
    # Reject the dual connective (base(A && B) or rec(A || B) does not guarantee both hold).
    dual_op = "&&" if polarity == "base_when_true" else "||"
    if len(_split_top_level_masked(cur, dual_op)) > 1:
        return
    masked = _mask_expr_literals(cur)
    top = _top_level_positions(masked)
    ops = [
        m
        for m in _CMP_OP_RE.finditer(masked)
        if top[m.start()]
        and not (m.group(0) == "==" and m.end() < len(masked) and masked[m.end()] == ">")
        and not (m.group(0) == "<=" and m.end() < len(masked) and masked[m.end()] == "=")
    ]
    if len(ops) == 1:
        m = ops[0]
        _record_rel_constraint(out, cur[: m.start()], m.group(0), cur[m.end() :], polarity, param_set)
    elif len(ops) == 2 and polarity == "rec_when_true":
        # Chained ACSL comparison `0 <= lo < hi` is a conjunction in rec_when_true.
        m1, m2 = ops
        _record_rel_constraint(out, cur[: m1.start()], m1.group(0), cur[m1.end() : m2.start()], polarity, param_set)
        _record_rel_constraint(out, cur[m1.end() : m2.start()], m2.group(0), cur[m2.end() :], polarity, param_set)


def _match_param_step(arg: str, param: str) -> tuple[str, int] | None:
    """
    Classify how `arg` changes `param`:
    - `param` -> `("same", 0)`
    - `param - c` (integer `c > 0`) -> `("down", c)`
    - `param + c` or `c + param` (integer `c > 0`) -> `("up", c)`
    - anything else -> `None`
    """
    cur = _strip_outer_parens_masked(arg)
    if cur == param:
        return ("same", 0)
    masked = _mask_expr_literals(cur)
    top = _top_level_positions(masked)
    ops: list[tuple[int, str]] = []
    for idx, ch in enumerate(masked):
        if top[idx] and ch in "+-" and idx > 0:
            # Skip `->` pointer arrow
            if ch == "-" and idx + 1 < len(masked) and masked[idx + 1] == ">":
                continue
            ops.append((idx, ch))
    if len(ops) != 1:
        return None
    op_idx, op = ops[0]
    lhs = _strip_outer_parens_masked(cur[:op_idx])
    rhs = _strip_outer_parens_masked(cur[op_idx + 1 :])
    if op == "-" and lhs == param:
        m_c = _POS_INT_RE.match(rhs)
        if m_c and int(m_c.group(1)) > 0:
            return ("down", int(m_c.group(1)))
    elif op == "+":
        if lhs == param:
            m_c = _POS_INT_RE.match(rhs)
            if m_c and int(m_c.group(1)) > 0:
                return ("up", int(m_c.group(1)))
        elif rhs == param:
            m_c = _POS_INT_RE.match(lhs)
            if m_c and int(m_c.group(1)) > 0:
                return ("up", int(m_c.group(1)))
    return None


def _is_well_founded_self_recursion(d: _LogicDef, self_calls: list[list[str]]) -> bool:
    """
    Return True iff direct self-recursion in `d` has BOTH:
    (a) a terminating base-case guard on a parameter (`? :`, `==>`, `||`, or `&&`), AND
    (b) every recursive call strictly descends/advances on that guarded parameter in the guarded direction.
    """
    if not d.params or not self_calls:
        return False
    arity = len(d.params)
    param_set = frozenset(d.params)
    param_index = {p: idx for idx, p in enumerate(d.params)}
    zero_names = frozenset({d.name}) if arity == 0 else frozenset()

    def _has_self_call(expr: str) -> bool:
        return any(name == d.name and ca == arity for name, ca, _args in _extract_logic_calls(expr, zero_names))

    constraints: dict[str, list[tuple[str, str | None]]] = {}
    found_base_split = False
    cur = _strip_outer_parens_masked(d.body)
    # Descend through chained base-case guards (e.g. `p == \null ? 0 : n <= 0 ? 0 : f(p, n - 1)`)
    for _ in range(16):
        tern = _split_top_level_ternary(cur)
        if tern is not None:
            cond, then_e, else_e = tern
            then_rec, else_rec = _has_self_call(then_e), _has_self_call(else_e)
            if not then_rec and else_rec:
                found_base_split = True
                _extract_guard_constraints(cond, "base_when_true", param_set, constraints)
                cur = _strip_outer_parens_masked(else_e)
                continue
            if then_rec and not else_rec:
                found_base_split = True
                _extract_guard_constraints(cond, "rec_when_true", param_set, constraints)
                cur = _strip_outer_parens_masked(then_e)
                continue
            break
        imp = _split_top_level_masked(cur, "==>")
        if len(imp) >= 2:
            lhs = imp[0]
            rhs = " ==> ".join(imp[1:])
            if not _has_self_call(lhs) and _has_self_call(rhs):
                found_base_split = True
                _extract_guard_constraints(lhs, "rec_when_true", param_set, constraints)
                cur = _strip_outer_parens_masked(rhs)
                continue
        disj = _split_top_level_masked(cur, "||")
        if len(disj) >= 2:
            non_rec = [p for p in disj if not _has_self_call(p)]
            rec = [p for p in disj if _has_self_call(p)]
            if non_rec and rec:
                found_base_split = True
                for g in non_rec:
                    _extract_guard_constraints(g, "base_when_true", param_set, constraints)
                if len(rec) == 1:
                    cur = _strip_outer_parens_masked(rec[0])
                    continue
                break
        conj = _split_top_level_masked(cur, "&&")
        if len(conj) >= 2:
            non_rec = [p for p in conj if not _has_self_call(p)]
            rec = [p for p in conj if _has_self_call(p)]
            if non_rec and rec:
                found_base_split = True
                for g in non_rec:
                    _extract_guard_constraints(g, "rec_when_true", param_set, constraints)
                if len(rec) == 1:
                    cur = _strip_outer_parens_masked(rec[0])
                    continue
                break
        break

    if not found_base_split or not constraints:
        return False

    for p, dirs in constraints.items():
        p_idx = param_index[p]
        for direction, partner in dirs:
            opposite = "up" if direction == "down" else "down"
            ok = True
            for args in self_calls:
                if len(args) != arity:
                    ok = False
                    break
                step = _match_param_step(args[p_idx], p)
                if step is None or step[0] != direction:
                    ok = False
                    break
                if partner is not None and partner in param_index:
                    q_idx = param_index[partner]
                    q_step = _match_param_step(args[q_idx], partner)
                    if q_step is None or q_step[0] not in ("same", opposite):
                        ok = False
                        break
            if ok:
                return True
    return False


def _tarjan_scc(
    nodes: list[tuple[str, int]], edges: dict[tuple[str, int], set[tuple[str, int]]]
) -> list[list[tuple[str, int]]]:
    """Tarjan's strongly connected components algorithm over directed graph `(nodes, edges)`."""
    index_counter = 0
    indices: dict[tuple[str, int], int] = {}
    lowlink: dict[tuple[str, int], int] = {}
    stack: list[tuple[str, int]] = []
    on_stack: set[tuple[str, int]] = set()
    sccs: list[list[tuple[str, int]]] = []

    def strongconnect(v: tuple[str, int]) -> None:
        nonlocal index_counter
        indices[v] = index_counter
        lowlink[v] = index_counter
        index_counter += 1
        stack.append(v)
        on_stack.add(v)
        for w in sorted(edges.get(v, ())):
            if w not in indices:
                strongconnect(w)
                lowlink[v] = min(lowlink[v], lowlink[w])
            elif w in on_stack:
                lowlink[v] = min(lowlink[v], indices[w])
        if lowlink[v] == indices[v]:
            comp: list[tuple[str, int]] = []
            while True:
                w = stack.pop()
                on_stack.remove(w)
                comp.append(w)
                if w == v:
                    break
            sccs.append(comp)

    for node in nodes:
        if node not in indices:
            strongconnect(node)
    return sccs


def _find_unsound_recursive_logic_entries(tokens: list[Token], path: str = "<input>") -> list[tuple[str, str]]:
    """
    Detect mutually recursive or non-well-founded self-recursive top-level `logic`/`predicate` definitions.
    Returns `[(stable_key, error_message), ...]` so callers can diff against baseline without line-shift noise.
    """
    defs: list[_LogicDef] = []
    for seg in _iter_wp_top_level_acsl_segments(tokens):
        d = _extract_logic_def(seg)
        if d is not None:
            defs.append(d)
    if not defs:
        return []

    defs_by_key: dict[tuple[str, int], list[_LogicDef]] = {}
    for d in defs:
        defs_by_key.setdefault((d.name, len(d.params)), []).append(d)
    nodes = list(defs_by_key.keys())
    node_set = set(nodes)
    zero_arg_names = frozenset(name for name, arity in nodes if arity == 0)

    edges: dict[tuple[str, int], set[tuple[str, int]]] = {k: set() for k in nodes}
    self_calls_by_def: dict[int, list[list[str]]] = {}
    for d_idx, d in enumerate(defs):
        src_key = (d.name, len(d.params))
        calls = _extract_logic_calls(d.body, zero_arg_names)
        sc: list[list[str]] = []
        for cname, carity, cargs in calls:
            dst_key = (cname, carity)
            if dst_key in node_set:
                edges[src_key].add(dst_key)
                if dst_key == src_key:
                    sc.append(cargs)
        self_calls_by_def[d_idx] = sc

    mutual_nodes: dict[tuple[str, int], list[str]] = {}
    for comp in _tarjan_scc(nodes, edges):
        if len(comp) > 1:
            names = sorted({n for n, _a in comp})
            for k in comp:
                mutual_nodes[k] = names

    entries: list[tuple[str, str]] = []
    for d_idx, d in enumerate(defs):
        key = (d.name, len(d.params))
        if key in mutual_nodes:
            cycle_txt = ", ".join(mutual_nodes[key])
            entries.append(
                (
                    f"mutual:{d.kind}:{d.name}/{len(d.params)}",
                    f"{path}:{d.line}: unsound mutually recursive ACSL {d.kind} '{d.name}' "
                    f"(cycle: {cycle_txt}); recursive ACSL definitions without well-founded termination "
                    "make WP hypotheses inconsistent",
                )
            )
            continue
        sc = self_calls_by_def[d_idx]
        if sc and not _is_well_founded_self_recursion(d, sc):
            entries.append(
                (
                    f"self:{d.kind}:{d.name}/{len(d.params)}",
                    f"{path}:{d.line}: unsound non-well-founded recursive ACSL {d.kind} '{d.name}' "
                    "(requires both a terminating base-case guard and strict descent/advance on a guarded parameter)",
                )
            )
    return entries


def _find_unsound_recursive_logic_tokens(tokens: list[Token], path: str = "<input>") -> list[str]:
    return [msg for _key, msg in _find_unsound_recursive_logic_entries(tokens, path=path)]


def find_unsound_recursive_logic(source: str, path: str = "<input>") -> list[str]:
    """
    Detect non-well-founded recursive or mutually recursive top-level ACSL `logic`/`predicate`
    definitions in `source` (skipping comments, literals, doxygen comments, and
    `#if defined(__FRAMAC_EACSL__)` conditional blocks).
    """
    tokens = tokenize_c_acsl(source, path=path)
    return _find_unsound_recursive_logic_tokens(tokens, path=path)


# ---------------------------------------------------------------------------
# In-body (block-scope) ghost function / extern / contract declaration check
# ---------------------------------------------------------------------------

_GHOST_BLOCK_START_RE = re.compile(r"[ \t\r\n@]*ghost\b")
_GHOST_CONTRACT_CLAUSE_RE = re.compile(
    r"(?<![\\\w])(?:(loop)\s+)?(requires|terminates|decreases|exits|assigns|ensures|behavior|assumes|"
    r"allocates|frees|(?:complete|disjoint)\s+behaviors)\b(?!\s*:)"
)
_GHOST_STORAGE_KWS = frozenset({"extern", "static", "auto", "register", "_Thread_local"})
_GHOST_FUNC_SPEC_KWS = frozenset({"inline", "__inline", "__inline__", "_Noreturn", "__extension__"})
_GHOST_TYPE_QUAL_KWS = frozenset(
    {
        "const",
        "__const",
        "__const__",
        "volatile",
        "__volatile",
        "__volatile__",
        "restrict",
        "__restrict",
        "__restrict__",
        "_Atomic",
    }
)
_GHOST_BUILTIN_TYPE_KWS = frozenset(
    {
        "void",
        "char",
        "short",
        "int",
        "long",
        "float",
        "double",
        "signed",
        "__signed",
        "__signed__",
        "unsigned",
        "_Bool",
        "_Complex",
        "__complex__",
        "_Imaginary",
        "__int128",
        "__uint128_t",
        "__int128_t",
        "_Float128",
    }
)
_GHOST_KNOWN_TYPEDEFS = frozenset(
    {
        "bool",
        "size_t",
        "ssize_t",
        "ptrdiff_t",
        "intptr_t",
        "uintptr_t",
        "int8_t",
        "int16_t",
        "int32_t",
        "int64_t",
        "uint8_t",
        "uint16_t",
        "uint32_t",
        "uint64_t",
    }
)
_GHOST_TAG_KWS = frozenset({"struct", "union", "enum"})
_GHOST_TYPEOF_KWS = frozenset({"typeof", "__typeof", "__typeof__"})
_GHOST_ATTR_SPEC_KWS = frozenset({"__attribute__", "__attribute", "_Alignas"})
_GHOST_DECL_SPEC_KWS = (
    _GHOST_STORAGE_KWS
    | _GHOST_FUNC_SPEC_KWS
    | _GHOST_TYPE_QUAL_KWS
    | _GHOST_BUILTIN_TYPE_KWS
    | _GHOST_TAG_KWS
    | _GHOST_TYPEOF_KWS
    | _GHOST_ATTR_SPEC_KWS
)
_GHOST_NOT_TYPE_KWS = frozenset(
    {
        "if",
        "else",
        "while",
        "for",
        "do",
        "switch",
        "case",
        "default",
        "return",
        "goto",
        "break",
        "continue",
        "sizeof",
        "_Alignof",
        "__alignof",
        "__alignof__",
        "_Generic",
        "_Static_assert",
        "asm",
        "__asm",
        "__asm__",
        "typedef",
    }
)
_GHOST_PARAM_BAD_OPS = frozenset(
    {
        "+",
        "-",
        "/",
        "%",
        "=",
        "==",
        "!=",
        "<",
        ">",
        "<=",
        ">=",
        "&&",
        "||",
        "&",
        "|",
        "^",
        "!",
        "~",
        "->",
        ".",
        "++",
        "--",
        "?",
        ":",
        "+=",
        "-=",
        "*=",
        "/=",
        "%=",
        "&=",
        "|=",
        "^=",
        "<<",
        ">>",
        "<<=",
        ">>=",
    }
)
_GHOST_TWO_CHAR_OPS = frozenset(
    {"->", "++", "--", "==", "!=", "<=", ">=", "&&", "||", "<<", ">>", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^="}
)
_GHOST_THREE_CHAR_OPS = frozenset({"...", "<<=", ">>="})
_GHOST_DECL_REASON = (
    "(block-scope ghost function declarations, extern declarations, and embedded contracts are forbidden "
    "inside function bodies)"
)


@dataclass(slots=True, frozen=True)
class _GhostToken:
    """A lexical token inside an ACSL ghost block (`/*@ ghost ... */` or `//@ ghost ...`)."""

    kind: str  # ident | number | literal | punct | ghost_annot | ghost_line_annot
    text: str
    line: int


def _has_ghost_contract_clause(annot_text: str) -> bool:
    """Return True if an embedded ghost annotation (`/@ ... @/` or `//@ ...`) contains a non-loop contract clause."""
    if annot_text.startswith("/@"):
        inner = annot_text[2:-2] if annot_text.endswith("@/") else annot_text[2:]
    elif annot_text.startswith("/*@"):
        inner = annot_text[3:-2] if annot_text.endswith("*/") else annot_text[3:]
    elif annot_text.startswith("//@"):
        inner = annot_text[3:]
    else:
        inner = annot_text
    flat = mask_comments_and_literals(inner, acsl="blank", literals=True, on_error="mask").replace("@", " ")
    return any(m.group(1) is None for m in _GHOST_CONTRACT_CLAUSE_RE.finditer(flat))


def _tokenize_ghost_body(body: str, base_line: int) -> list[_GhostToken]:
    """Tokenize the C body of an ACSL ghost annotation, preserving embedded `/@ ... @/` and `//@ ...` annotations."""
    tokens: list[_GhostToken] = []
    n = len(body)
    i = 0
    line = base_line

    while i < n:
        ch = body[i]
        # Whitespace and `@` margins (Frama-C treats `@` as whitespace inside annotations)
        if ch in " \t\r\n\f\v@":
            if ch == "\n":
                line += 1
            i += 1
            continue

        # Embedded `/@ ... @/` block annotation inside `/*@ ghost ... */`
        if ch == "/" and i + 1 < n and body[i + 1] == "@":
            start = i
            start_line = line
            close = body.find("@/", i + 2)
            end = n if close == -1 else close + 2
            text = body[start:end]
            line += text.count("\n")
            tokens.append(_GhostToken("ghost_annot", text, start_line))
            i = end
            continue

        # Line comment `// ...` or nested line annotation `//@ ...`
        if ch == "/" and i + 1 < n and body[i + 1] == "/":
            start = i
            start_line = line
            nl = body.find("\n", i + 2)
            end = n if nl == -1 else nl
            text = body[start:end]
            if text.startswith("//@") and not _is_doxygen_comment(text):
                tokens.append(_GhostToken("ghost_line_annot", text, start_line))
            i = end
            continue

        # Inline `/* ... */` comment (possible inside `//@ ghost ...`)
        if ch == "/" and i + 1 < n and body[i + 1] == "*":
            start = i
            start_line = line
            is_acsl = i + 2 < n and body[i + 2] == "@" and (i + 3 >= n or body[i + 3] != "/")
            close = body.find("*/", i + 2)
            end = n if close == -1 else close + 2
            text = body[start:end]
            line += text.count("\n")
            if is_acsl and not _is_doxygen_comment(text):
                tokens.append(_GhostToken("ghost_annot", text, start_line))
            i = end
            continue

        # String or character literal
        if ch in ('"', "'"):
            quote = ch
            start = i
            start_line = line
            i += 1
            while i < n:
                c = body[i]
                if c == "\\":
                    if i + 1 < n and body[i + 1] == "\n":
                        line += 1
                    i += 2
                    continue
                if c == "\n":
                    break
                if c == quote:
                    i += 1
                    break
                i += 1
            tokens.append(_GhostToken("literal", body[start:i], start_line))
            continue

        m_id = _IDENT_RE.match(body, i)
        if m_id:
            tokens.append(_GhostToken("ident", m_id.group(0), line))
            i = m_id.end()
            continue

        m_num = _NUMBER_RE.match(body, i)
        if m_num:
            tokens.append(_GhostToken("number", m_num.group(0), line))
            i = m_num.end()
            continue

        if body[i : i + 3] in _GHOST_THREE_CHAR_OPS:
            tokens.append(_GhostToken("punct", body[i : i + 3], line))
            i += 3
            continue

        if body[i : i + 2] in _GHOST_TWO_CHAR_OPS:
            tokens.append(_GhostToken("punct", body[i : i + 2], line))
            i += 2
            continue

        tokens.append(_GhostToken("punct", ch, line))
        i += 1

    return tokens


def _skip_ghost_delim(gtoks: list[_GhostToken], open_idx: int, open_ch: str, close_ch: str) -> int:
    """Return index immediately after matching `close_ch` for `gtoks[open_idx] == open_ch`, or `len(gtoks)`."""
    depth = 0
    n = len(gtoks)
    i = open_idx
    while i < n:
        tok = gtoks[i]
        if tok.kind == "punct":
            if tok.text == open_ch:
                depth += 1
            elif tok.text == close_ch:
                depth -= 1
                if depth == 0:
                    return i + 1
        i += 1
    return n


def _skip_ghost_attrs(gtoks: list[_GhostToken], idx: int) -> int:
    """Skip consecutive GCC attribute / asm / alignment specifiers starting at `idx`."""
    n = len(gtoks)
    cur = idx
    while cur < n and gtoks[cur].kind == "ident" and gtoks[cur].text in (_DECL_SUFFIX_KWS | _GHOST_ATTR_SPEC_KWS):
        nxt = cur + 1
        if nxt < n and gtoks[nxt].text == "(":
            cur = _skip_ghost_delim(gtoks, nxt, "(", ")")
            continue
        break
    return cur


def _is_ghost_plausible_param_list(
    gtoks: list[_GhostToken],
    open_paren: int,
    close_paren: int,
    *,
    require_typed: bool = False,
) -> bool:
    """Return True if `gtoks[open_paren + 1 : close_paren]` looks like a C function parameter list."""
    inner = [t for t in gtoks[open_paren + 1 : close_paren] if t.kind not in ("ghost_annot", "ghost_line_annot")]
    if not inner:
        return not require_typed
    parts: list[list[_GhostToken]] = [[]]
    depth = 0
    for tok in inner:
        if tok.kind == "punct" and tok.text in ("(", "[", "{"):
            depth += 1
        elif tok.kind == "punct" and tok.text in (")", "]", "}"):
            depth = max(0, depth - 1)
        elif tok.kind == "punct" and tok.text == "," and depth == 0:
            parts.append([])
            continue
        parts[-1].append(tok)

    has_explicit_type = False
    for part in parts:
        if not part:
            return False
        if len(part) == 1 and part[0].text in ("...", "void"):
            has_explicit_type = True
            continue
        depth = 0
        ident_count = 0
        for tok in part:
            if tok.kind == "punct" and tok.text in ("(", "[", "{"):
                depth += 1
                continue
            if tok.kind == "punct" and tok.text in (")", "]", "}"):
                depth = max(0, depth - 1)
                continue
            if depth > 0:
                continue
            if tok.kind in ("literal", "number"):
                return False
            if tok.kind == "punct":
                if tok.text == "*":
                    has_explicit_type = True
                elif tok.text in _GHOST_PARAM_BAD_OPS:
                    return False
                continue
            if tok.kind == "ident":
                if tok.text in _GHOST_NOT_TYPE_KWS:
                    return False
                ident_count += 1
                if tok.text in _GHOST_DECL_SPEC_KWS or tok.text in _GHOST_KNOWN_TYPEDEFS:
                    has_explicit_type = True
        if ident_count == 0:
            return False
        if ident_count >= 2:
            has_explicit_type = True

    return has_explicit_type if require_typed else True


def _parse_ghost_declarator(
    gtoks: list[_GhostToken], idx: int
) -> tuple[str, str | None, int, int, tuple[int, int] | None, list[tuple[int, int]]] | None:
    """
    Parse a C declarator at `idx` inside ghost tokens.
    Returns `(name, kind, name_line, end_idx, func_paren_span, all_paren_spans)` where `kind` is
    `"func"`, `"pointer"`, `"array"`, or `None` (plain identifier), or `None` if not a declarator.
    """
    n = len(gtoks)
    cur = idx
    has_ptr = False
    while cur < n:
        cur = _skip_ghost_attrs(gtoks, cur)
        if cur < n and gtoks[cur].kind == "punct" and gtoks[cur].text == "*":
            has_ptr = True
            cur += 1
            while cur < n:
                cur = _skip_ghost_attrs(gtoks, cur)
                if cur < n and gtoks[cur].kind == "ident" and gtoks[cur].text in _GHOST_TYPE_QUAL_KWS:
                    cur += 1
                else:
                    break
            continue
        break

    if cur >= n:
        return None

    inner_kind: str | None = None
    func_paren: tuple[int, int] | None = None
    all_parens: list[tuple[int, int]] = []
    if gtoks[cur].kind == "ident" and gtoks[cur].text not in (_GHOST_DECL_SPEC_KWS | _GHOST_NOT_TYPE_KWS):
        name = gtoks[cur].text
        name_line = gtoks[cur].line
        cur += 1
    elif gtoks[cur].kind == "punct" and gtoks[cur].text == "(":
        inner = _parse_ghost_declarator(gtoks, cur + 1)
        if inner is None:
            return None
        name, inner_kind, name_line, inner_end, func_paren, inner_parens = inner
        all_parens.extend(inner_parens)
        inner_end = _skip_ghost_attrs(gtoks, inner_end)
        if inner_end >= n or gtoks[inner_end].kind != "punct" or gtoks[inner_end].text != ")":
            return None
        cur = inner_end + 1
    else:
        return None

    first_suffix_kind: str | None = None
    first_paren_span: tuple[int, int] | None = None
    while cur < n:
        cur = _skip_ghost_attrs(gtoks, cur)
        if cur >= n:
            break
        if gtoks[cur].kind == "punct" and gtoks[cur].text == "(":
            after = _skip_ghost_delim(gtoks, cur, "(", ")")
            if after > n or after == cur + 1 or gtoks[after - 1].text != ")":
                return None
            span = (cur, after - 1)
            all_parens.append(span)
            if first_suffix_kind is None:
                first_suffix_kind = "func"
                first_paren_span = span
            cur = after
        elif gtoks[cur].kind == "punct" and gtoks[cur].text == "[":
            after = _skip_ghost_delim(gtoks, cur, "[", "]")
            if after > n or after == cur + 1 or gtoks[after - 1].text != "]":
                return None
            if first_suffix_kind is None:
                first_suffix_kind = "array"
            cur = after
        else:
            break

    cur = _skip_ghost_attrs(gtoks, cur)
    if inner_kind is not None:
        kind: str | None = inner_kind
    elif first_suffix_kind is not None:
        kind = first_suffix_kind
        if kind == "func":
            func_paren = first_paren_span
    elif has_ptr:
        kind = "pointer"
    else:
        kind = None

    return (name, kind, name_line, cur, func_paren, all_parens)


def _looks_like_paren_declarator_after(gtoks: list[_GhostToken], open_paren_idx: int) -> bool:
    """Whether `gtoks[open_paren_idx:]` is a parenthesized declarator followed by `(...)` or `[...]`."""
    after = _skip_ghost_delim(gtoks, open_paren_idx, "(", ")")
    if after >= len(gtoks) or gtoks[after - 1].text != ")":
        return False
    after = _skip_ghost_attrs(gtoks, after)
    return after < len(gtoks) and gtoks[after].kind == "punct" and gtoks[after].text in ("(", "[")


def _parse_ghost_decl_specifiers(gtoks: list[_GhostToken], idx: int) -> tuple[int, list[int], bool] | None:
    """
    Parse C declaration specifiers at `idx`.
    Returns `(end_idx, extern_indices, has_decl_kw)` if at least one specifier was consumed, else None.
    """
    n = len(gtoks)
    cur = idx
    extern_indices: list[int] = []
    has_decl_kw = False
    has_type_spec = False
    consumed_any = False

    while cur < n:
        tok = gtoks[cur]
        if tok.kind != "ident":
            break
        word = tok.text
        if word in _GHOST_NOT_TYPE_KWS:
            break
        if word in _GHOST_STORAGE_KWS:
            if word == "extern":
                extern_indices.append(cur)
            has_decl_kw = True
            consumed_any = True
            cur += 1
            continue
        if word in _GHOST_FUNC_SPEC_KWS or word in _GHOST_TYPE_QUAL_KWS:
            has_decl_kw = True
            consumed_any = True
            cur += 1
            continue
        if word in _GHOST_ATTR_SPEC_KWS:
            has_decl_kw = True
            consumed_any = True
            cur += 1
            if cur < n and gtoks[cur].text == "(":
                cur = _skip_ghost_delim(gtoks, cur, "(", ")")
            continue
        if word in _GHOST_TYPEOF_KWS:
            has_decl_kw = True
            has_type_spec = True
            consumed_any = True
            cur += 1
            if cur < n and gtoks[cur].text == "(":
                cur = _skip_ghost_delim(gtoks, cur, "(", ")")
            continue
        if word in _GHOST_BUILTIN_TYPE_KWS:
            has_decl_kw = True
            has_type_spec = True
            consumed_any = True
            cur += 1
            continue
        if word in _GHOST_TAG_KWS:
            has_decl_kw = True
            has_type_spec = True
            consumed_any = True
            cur += 1
            cur = _skip_ghost_attrs(gtoks, cur)
            if (
                cur < n
                and gtoks[cur].kind == "ident"
                and gtoks[cur].text not in (_GHOST_DECL_SPEC_KWS | _GHOST_NOT_TYPE_KWS)
            ):
                cur += 1
            cur = _skip_ghost_attrs(gtoks, cur)
            if cur < n and gtoks[cur].text == "{":
                cur = _skip_ghost_delim(gtoks, cur, "{", "}")
            continue
        if not has_type_spec:
            nxt = cur + 1
            while nxt < n and gtoks[nxt].kind == "ident":
                nw = gtoks[nxt].text
                if nw in (_GHOST_STORAGE_KWS | _GHOST_FUNC_SPEC_KWS | _GHOST_TYPE_QUAL_KWS):
                    nxt += 1
                elif nw in _GHOST_ATTR_SPEC_KWS:
                    nxt += 1
                    if nxt < n and gtoks[nxt].text == "(":
                        nxt = _skip_ghost_delim(gtoks, nxt, "(", ")")
                else:
                    break
            if nxt < n and (
                gtoks[nxt].text == "*"
                or (gtoks[nxt].kind == "ident" and gtoks[nxt].text not in (_GHOST_DECL_SPEC_KWS | _GHOST_NOT_TYPE_KWS))
                or (
                    gtoks[nxt].text == "("
                    and _looks_like_paren_declarator_after(gtoks, nxt)
                    and _parse_ghost_declarator(gtoks, nxt) is not None
                )
            ):
                has_type_spec = True
                if word in _GHOST_KNOWN_TYPEDEFS:
                    has_decl_kw = True
                consumed_any = True
                cur += 1
                continue
        break

    if not consumed_any:
        return None
    return (cur, extern_indices, has_decl_kw)


def _ghost_kr_body_brace(gtoks: list[_GhostToken], start_idx: int, open_paren: int, close_paren: int) -> int:
    """Return index of body `{` for a K&R function definition (`int f(x) int x; { ... }`), or -1."""
    inner = [t for t in gtoks[open_paren + 1 : close_paren] if t.kind not in ("ghost_annot", "ghost_line_annot")]
    if not inner or len(inner) % 2 == 0:
        return -1
    kr_idents: set[str] = set()
    for i, tok in enumerate(inner):
        if i % 2 == 1:
            if tok.text != ",":
                return -1
        else:
            if tok.kind != "ident" or tok.text in (_GHOST_DECL_SPEC_KWS | _GHOST_NOT_TYPE_KWS):
                return -1
            kr_idents.add(tok.text)

    n = len(gtoks)
    cur = start_idx
    decl_count = 0
    while cur < n:
        cur = _skip_ghost_attrs(gtoks, cur)
        if cur >= n:
            return -1
        if gtoks[cur].text == "{":
            return cur if decl_count >= 1 else -1
        p_depth = 0
        decl_idents: set[str] = set()
        found_semi = False
        while cur < n:
            tok = gtoks[cur]
            if tok.kind in ("ghost_annot", "ghost_line_annot"):
                cur += 1
                continue
            if tok.text == "(":
                p_depth += 1
            elif tok.text == ")":
                if p_depth == 0:
                    return -1
                p_depth -= 1
            elif tok.text == "{" and p_depth == 0:
                cur = _skip_ghost_delim(gtoks, cur, "{", "}")
                continue
            elif tok.text == "}" and p_depth == 0:
                return -1
            elif tok.text == ";" and p_depth == 0:
                if not (decl_idents & kr_idents):
                    return -1
                decl_count += 1
                cur += 1
                found_semi = True
                break
            elif p_depth == 0 and (tok.text == "=" or tok.text in _KR_FORBIDDEN_DECL_TOKENS):
                return -1
            elif tok.kind == "ident":
                decl_idents.add(tok.text)
            cur += 1
        if not found_semi:
            return -1
    return -1


def _scan_ghost_tokens(
    gtoks: list[_GhostToken],
    path: str,
    entries: list[tuple[tuple[str, str, bool, bool], str]],
) -> None:
    """Scan a token stream from in-body ghost block(s) for forbidden prototypes, definitions, externs, and contracts."""
    n = len(gtoks)
    handled_extern_indices: set[int] = set()

    def _skip_expr_until(start: int, stop_texts: frozenset[str]) -> int:
        p_depth = 0
        b_depth = 0
        k_depth = 0
        cur = start
        while cur < n:
            tok = gtoks[cur]
            if tok.kind == "punct":
                if p_depth == 0 and b_depth == 0 and k_depth == 0 and tok.text in stop_texts:
                    return cur
                if tok.text == "(":
                    if cur + 1 < n and gtoks[cur + 1].kind == "punct" and gtoks[cur + 1].text == "{":
                        # GNU statement-expression `({ ... })`: scan its compound body recursively.
                        after_brace = _skip_ghost_delim(gtoks, cur + 1, "{", "}")
                        body_end = (
                            after_brace - 1
                            if after_brace > cur + 2 and gtoks[after_brace - 1].text == "}"
                            else after_brace
                        )
                        _scan_ghost_tokens(gtoks[cur + 2 : body_end], path, entries)
                        handled_extern_indices.update(range(cur + 2, body_end))
                        p_depth += 1
                        cur = after_brace
                        continue
                    p_depth += 1
                elif tok.text == ")":
                    p_depth = max(0, p_depth - 1)
                elif tok.text == "{":
                    b_depth += 1
                elif tok.text == "}":
                    b_depth = max(0, b_depth - 1)
                elif tok.text == "[":
                    k_depth += 1
                elif tok.text == "]":
                    k_depth = max(0, k_depth - 1)
            cur += 1
        return n

    def _emit_func_violation(
        decl_kind: str,
        name: str,
        line: int,
        has_extern: bool,
        has_contract: bool,
    ) -> None:
        ext_txt = "'extern' " if has_extern else ""
        contract_txt = " with embedded contract '/@ ... @/'" if has_contract else ""
        entries.append(
            (
                (decl_kind, name, has_extern, has_contract),
                f"{path}:{line}: forbidden in-body ghost {ext_txt}function {decl_kind} '{name}'{contract_txt} "
                f"{_GHOST_DECL_REASON}",
            )
        )

    pos = 0
    pending_contract: _GhostToken | None = None
    while pos < n:
        tok = gtoks[pos]

        # Compound delimiters and empty statements reset pending contract
        if tok.kind == "punct" and tok.text in ("{", "}", ";"):
            pending_contract = None
            pos += 1
            continue

        # Embedded `/@ ... @/` or nested `//@ ...` annotation
        if tok.kind in ("ghost_annot", "ghost_line_annot"):
            if _has_ghost_contract_clause(tok.text) and pending_contract is None:
                pending_contract = tok
            pos += 1
            continue

        # Control-flow statements & labels
        if tok.kind == "ident":
            w = tok.text
            if w in ("if", "while", "for", "switch"):
                pending_contract = None
                pos += 1
                if pos < n and gtoks[pos].text == "(":
                    after_paren = _skip_ghost_delim(gtoks, pos, "(", ")")
                    # Check any GNU statement-expressions `({ ... })` inside the condition/header
                    inner_cur = pos + 1
                    inner_end = (
                        after_paren - 1 if after_paren > pos + 1 and gtoks[after_paren - 1].text == ")" else after_paren
                    )
                    while inner_cur < inner_end:
                        if (
                            gtoks[inner_cur].text == "("
                            and inner_cur + 1 < inner_end
                            and gtoks[inner_cur + 1].text == "{"
                        ):
                            ab = _skip_ghost_delim(gtoks, inner_cur + 1, "{", "}")
                            be = ab - 1 if ab > inner_cur + 2 and gtoks[ab - 1].text == "}" else ab
                            _scan_ghost_tokens(gtoks[inner_cur + 2 : be], path, entries)
                            handled_extern_indices.update(range(inner_cur + 2, be))
                            inner_cur = ab
                        else:
                            inner_cur += 1
                    pos = after_paren
                continue
            if w in ("else", "do"):
                pending_contract = None
                pos += 1
                continue
            if w == "default":
                pending_contract = None
                pos += 1
                if pos < n and gtoks[pos].text == ":":
                    pos += 1
                continue
            if w == "case":
                pending_contract = None
                pos += 1
                p_depth = 0
                k_depth = 0
                q_depth = 0
                while pos < n:
                    ct = gtoks[pos]
                    if ct.kind == "punct":
                        if ct.text == "(":
                            p_depth += 1
                        elif ct.text == ")":
                            p_depth = max(0, p_depth - 1)
                        elif ct.text == "[":
                            k_depth += 1
                        elif ct.text == "]":
                            k_depth = max(0, k_depth - 1)
                        elif ct.text == "?" and p_depth == 0 and k_depth == 0:
                            q_depth += 1
                        elif ct.text == ":" and p_depth == 0 and k_depth == 0:
                            if q_depth > 0:
                                q_depth -= 1
                            else:
                                pos += 1
                                break
                        elif ct.text in ("{", "}", ";") and p_depth == 0 and k_depth == 0:
                            break
                    pos += 1
                continue
            if w in ("return", "goto", "break", "continue"):
                pending_contract = None
                pos = _skip_expr_until(pos + 1, frozenset({";", "}"}))
                if pos < n and gtoks[pos].text == ";":
                    pos += 1
                continue
            if pos + 1 < n and gtoks[pos + 1].kind == "punct" and gtoks[pos + 1].text == ":":
                pending_contract = None
                pos += 2
                continue
            if w == "typedef":
                if pending_contract is not None:
                    entries.append(
                        (
                            ("contract", "typedef", False, True),
                            f"{path}:{pending_contract.line}: forbidden embedded ghost contract '/@ ... @/' "
                            f"attached to in-body ghost typedef declaration {_GHOST_DECL_REASON}",
                        )
                    )
                pending_contract = None
                pos = _skip_expr_until(pos + 1, frozenset({";", "}"}))
                if pos < n and gtoks[pos].text == ";":
                    pos += 1
                continue

        # Attempt to parse a C declaration starting at `pos`
        decl_spec = _parse_ghost_decl_specifiers(gtoks, pos)
        if decl_spec is not None:
            spec_end, extern_indices, has_decl_kw = decl_spec
            has_extern = bool(extern_indices)
            if spec_end < n and gtoks[spec_end].text == ";":
                if has_extern:
                    handled_extern_indices.update(extern_indices)
                    entries.append(
                        (
                            ("extern", "", True, pending_contract is not None),
                            f"{path}:{gtoks[extern_indices[0]].line}: forbidden in-body ghost 'extern' declaration "
                            f"{_GHOST_DECL_REASON}",
                        )
                    )
                elif pending_contract is not None:
                    entries.append(
                        (
                            ("contract", "", False, True),
                            f"{path}:{pending_contract.line}: forbidden embedded ghost contract '/@ ... @/' "
                            f"attached to in-body ghost declaration {_GHOST_DECL_REASON}",
                        )
                    )
                pending_contract = None
                pos = spec_end + 1
                continue

            # Parse comma-separated declarator list (or function definition)
            cur = spec_end
            parsed_any_decl = False
            reported_func = False
            first_decl_name = ""
            first_decl_line = gtoks[pos].line
            parsed_ok = False
            next_pos = pos
            func_hits: list[tuple[str, str, int]] = []  # (decl_kind, name, line)

            while cur < n:
                decl_start = cur
                decl = _parse_ghost_declarator(gtoks, cur)
                if decl is None:
                    break
                name, kind, name_line, after_decl, func_paren, all_parens = decl
                if not parsed_any_decl:
                    first_decl_name = name
                    first_decl_line = name_line
                parsed_any_decl = True

                # Function definition `{ ... }`
                if after_decl < n and gtoks[after_decl].text == "{":
                    if kind == "func":
                        func_hits.append(("definition", name, name_line))
                        reported_func = True
                        parsed_ok = True
                        # Step inside `{` so any nested declarations/externs inside the body are scanned too.
                        next_pos = after_decl + 1
                        break
                    break

                # K&R function definition (`int f(x) int x; { ... }`)
                if (
                    kind == "func"
                    and func_paren is not None
                    and after_decl < n
                    and gtoks[after_decl].text not in (";", ",", "=")
                ):
                    kr_brace = _ghost_kr_body_brace(gtoks, after_decl, func_paren[0], func_paren[1])
                    if kr_brace != -1:
                        func_hits.append(("definition", name, name_line))
                        reported_func = True
                        parsed_ok = True
                        next_pos = kr_brace + 1
                        break

                # Optional initializer `= expr` (only for non-function declarators)
                if after_decl < n and gtoks[after_decl].text == "=":
                    after_decl = _skip_expr_until(after_decl + 1, frozenset({",", ";", "}"}))

                if after_decl < n and gtoks[after_decl].text in (";", ","):
                    if kind == "func":
                        is_real_proto = has_decl_kw
                        if not is_real_proto:
                            if gtoks[decl_start].text == "(":
                                is_real_proto = any(
                                    _is_ghost_plausible_param_list(gtoks, p_o, p_c, require_typed=True)
                                    for p_o, p_c in all_parens
                                )
                            elif gtoks[decl_start].text == "*":
                                is_real_proto = func_paren is not None and _is_ghost_plausible_param_list(
                                    gtoks, func_paren[0], func_paren[1], require_typed=False
                                )
                            else:
                                # Adjacent identifiers (`my_t fake(...)`) cannot be a C expression.
                                is_real_proto = True
                        if is_real_proto:
                            func_hits.append(("prototype", name, name_line))
                            reported_func = True
                    if gtoks[after_decl].text == ";":
                        parsed_ok = True
                        next_pos = after_decl + 1
                        break
                    cur = after_decl + 1
                    continue
                break

            if parsed_ok:
                if has_extern:
                    handled_extern_indices.update(extern_indices)
                has_contract = pending_contract is not None
                if reported_func:
                    for decl_kind, fname, fline in func_hits:
                        _emit_func_violation(decl_kind, fname, fline, has_extern, has_contract)
                elif has_extern:
                    contract_txt = " with embedded contract '/@ ... @/'" if has_contract else ""
                    entries.append(
                        (
                            ("extern", first_decl_name, True, has_contract),
                            f"{path}:{first_decl_line}: forbidden in-body ghost 'extern' declaration "
                            f"'{first_decl_name}'{contract_txt} {_GHOST_DECL_REASON}",
                        )
                    )
                elif pending_contract is not None:
                    entries.append(
                        (
                            ("contract", first_decl_name, False, True),
                            f"{path}:{pending_contract.line}: forbidden embedded ghost contract '/@ ... @/' "
                            f"attached to in-body ghost declaration '{first_decl_name}' {_GHOST_DECL_REASON}",
                        )
                    )
                pending_contract = None
                pos = next_pos
                continue

        # Not a declaration: skip expression statement up to `;` or `}`
        pending_contract = None
        end_expr = _skip_expr_until(pos, frozenset({";", "}"}))
        if end_expr < n and gtoks[end_expr].text == ";":
            pos = end_expr + 1
        elif end_expr > pos:
            pos = end_expr
        else:
            pos += 1

    # Fallback: flag any remaining `extern` keyword inside the ghost block not already handled above.
    for idx, tok in enumerate(gtoks):
        if tok.kind == "ident" and tok.text == "extern" and idx not in handled_extern_indices:
            entries.append(
                (
                    ("extern", "", True, False),
                    f"{path}:{tok.line}: forbidden in-body ghost 'extern' declaration {_GHOST_DECL_REASON}",
                )
            )


def _find_in_body_ghost_declarations_entries(
    tokens: list[Token], path: str = "<input>"
) -> list[tuple[tuple[str, str, bool, bool], str]]:
    """
    Find forbidden block-scope (`brace_depth > 0`) ghost function prototypes, definitions, `extern`
    declarations, and embedded `/@ ... @/` contracts attached to declarations inside in-body ghost blocks.
    Returns `[(stable_key, error_message), ...]` for line-shift-insensitive baseline diffing.
    """
    delims = _conditional_delims(tokens)
    linkage = _linkage_block_braces(tokens, delims) | delims.ignored
    eacsl_skipped = _eacsl_only_token_indices(tokens)
    brace_depth = 0
    entries: list[tuple[tuple[str, str, bool, bool], str]] = []
    group: list[_GhostToken] = []

    def _flush_group() -> None:
        if group:
            _scan_ghost_tokens(group, path, entries)
            group.clear()

    for tok_idx, tok in enumerate(tokens):
        if tok_idx in linkage:
            if tok.kind not in ("whitespace", "c_comment"):
                _flush_group()
            continue
        if tok_idx in eacsl_skipped:
            _flush_group()
            continue
        if tok.kind in ("whitespace", "c_comment"):
            continue
        if tok.kind == "c_token":
            _flush_group()
            if tok.text == "{":
                brace_depth += 1
            elif tok.text == "}":
                brace_depth = max(0, brace_depth - 1)
            continue
        if tok.kind in ("acsl_block", "acsl_line") and brace_depth > 0:
            if _is_doxygen_comment(tok.text):
                continue
            raw_inner = tok.text[3:-2] if tok.kind == "acsl_block" else tok.text[3:]
            m_ghost = _GHOST_BLOCK_START_RE.match(raw_inner)
            if m_ghost is not None:
                body = raw_inner[m_ghost.end() :]
                body_line = tok.line + raw_inner.count("\n", 0, m_ghost.end())
                group.extend(_tokenize_ghost_body(body, body_line))
                continue
        _flush_group()

    _flush_group()
    return entries


def _find_in_body_ghost_declarations_tokens(tokens: list[Token], path: str = "<input>") -> list[str]:
    return [msg for _key, msg in _find_in_body_ghost_declarations_entries(tokens, path=path)]


def _added_in_body_ghost_declarations(base_tokens: list[Token], work_tokens: list[Token], path: str) -> list[str]:
    """In-body ghost declarations introduced by `work_tokens` relative to `base_tokens` (line-shift insensitive)."""
    known = Counter(key for key, _msg in _find_in_body_ghost_declarations_entries(base_tokens, path=path))
    errors: list[str] = []
    for key, msg in _find_in_body_ghost_declarations_entries(work_tokens, path=path):
        if known[key] > 0:
            known[key] -= 1
            continue
        errors.append(msg)
    return errors


def find_in_body_ghost_declarations(source: str, path: str = "<input>") -> list[str]:
    """
    Detect block-scope (`brace_depth > 0`) ghost function prototypes, ghost function definitions,
    `extern` declarations, and embedded ACSL contracts (`/@ ... @/`) attached to declarations inside
    in-body ghost blocks (`/*@ ghost ... */`, `//@ ghost ...`), ignoring C comments, string/char
    literals, doxygen comments, and `#if defined(__FRAMAC_EACSL__)` / `#if 0` blocks.
    """
    tokens = tokenize_c_acsl(source, path=path)
    return _find_in_body_ghost_declarations_tokens(tokens, path=path)


def added_top_level_acsl_declarations(base_text: str, agent_text: str, path: str = "<input>") -> list[str]:
    """
    Return `"<kind> <name>"` for each top-level ACSL declaration present in `agent_text`
    but not in `base_text`, in source order (compared on `(kind, name)`, counting repeats).
    """
    remaining = Counter((d["kind"], d["name"]) for d in extract_top_level_acsl_declarations(base_text, path=path))
    added: list[str] = []
    for d in extract_top_level_acsl_declarations(agent_text, path=path):
        key = (d["kind"], d["name"])
        if remaining[key] > 0:
            remaining[key] -= 1
        else:
            added.append(f"{d['kind']} {d['name']}")
    return added


def dedup_acsl_declarations(
    target_text: str,
    existing_names: set[str],
    baseline_text: str | None = None,
    path: str = "<input>",
) -> tuple[str, list[str]]:
    """
    Remove duplicate top-level ACSL declarations (`predicate`, `logic`, `lemma`, `type`,
    `axiomatic`, `inductive`, `ghost`) from `target_text` whose identifier name,
    `name/arity` profile, or full signature is already in `existing_names` (or duplicated
    earlier in `target_text`), while preserving overloaded declarations with different
    signatures and any declarations already present in `baseline_text`. Strips ACSL
    annotation blocks that contain only whitespace and/or comments to prevent empty-annotation
    errors.
    """
    baseline_profiles: set[str] = set()
    if baseline_text:
        for d in extract_top_level_acsl_declarations(baseline_text, path=path):
            baseline_profiles.add(d["profile_key"])
            baseline_profiles.add(d["name"])
            if d.get("full_profile"):
                baseline_profiles.add(d["full_profile"])

    seen: set[str] = set(existing_names)
    removed: list[str] = []

    tokens = tokenize_c_acsl(target_text, path=path)
    delims = _conditional_delims(tokens)
    linkage = _linkage_block_braces(tokens, delims) | delims.ignored
    brace_depth = 0
    paren_depth = 0
    out_parts: list[str] = []
    idx = 0
    total = len(tokens)

    while idx < total:
        tok = tokens[idx]
        if idx in linkage:
            out_parts.append(tok.text)
            idx += 1
            continue
        if tok.kind == "c_token":
            if tok.text == "{":
                brace_depth += 1
            elif tok.text == "}":
                brace_depth = max(0, brace_depth - 1)
            elif tok.text == "(":
                paren_depth += 1
            elif tok.text == ")":
                paren_depth = max(0, paren_depth - 1)
            out_parts.append(tok.text)
            idx += 1
            continue

        if brace_depth == 0 and paren_depth == 0 and tok.kind in ("acsl_block", "acsl_line"):
            inner = tok.text[3:-2] if tok.kind == "acsl_block" else tok.text[3:]
            segments = _parse_acsl_inner_segments(inner, tok.line)
            kept_segments: list[_AcslSegment] = []
            removed_in_block = False

            for seg in segments:
                if seg.kind in _TOP_DECL_KWS and seg.name:
                    profile_key = f"{seg.name}/{seg.arity}" if seg.arity is not None else seg.name
                    full_profile = (
                        f"{seg.name}(" + ", ".join(seg.param_types) + ")"
                        if seg.param_types is not None
                        else profile_key
                    )
                    if (
                        full_profile in baseline_profiles
                        or profile_key in baseline_profiles
                        or seg.name in baseline_profiles
                    ):
                        seen.add(full_profile)
                        seen.add(profile_key)
                        kept_segments.append(seg)
                    elif full_profile in seen or profile_key in seen or seg.name in seen:
                        removed.append(seg.name)
                        removed_in_block = True
                    else:
                        seen.add(full_profile)
                        kept_segments.append(seg)
                else:
                    kept_segments.append(seg)

            is_empty_or_comments = False
            rebuilt_inner: str = ""
            if not removed_in_block:
                if _is_acsl_comment_or_whitespace_only(inner):
                    is_empty_or_comments = True
                else:
                    out_parts.append(tok.text)
            else:
                rebuilt_inner = "".join(s.raw_text for s in kept_segments)
                if _is_acsl_comment_or_whitespace_only(rebuilt_inner):
                    is_empty_or_comments = True
                else:
                    if tok.kind == "acsl_block":
                        out_parts.append(f"/*@{rebuilt_inner}*/")
                    else:
                        out_parts.append(f"//@{rebuilt_inner}")

            if is_empty_or_comments:
                if out_parts and out_parts[-1].isspace() and "\n" not in out_parts[-1]:
                    if len(out_parts) == 1 or "\n" in out_parts[-2]:
                        out_parts.pop()
                if idx + 1 < total and tokens[idx + 1].kind == "whitespace":
                    ws_text = tokens[idx + 1].text
                    if ws_text.startswith("\r\n"):
                        tokens[idx + 1] = Token(
                            "whitespace",
                            ws_text[2:],
                            tokens[idx + 1].start + 2,
                            tokens[idx + 1].end,
                            tokens[idx + 1].line + 1,
                        )
                    elif ws_text.startswith("\n"):
                        tokens[idx + 1] = Token(
                            "whitespace",
                            ws_text[1:],
                            tokens[idx + 1].start + 1,
                            tokens[idx + 1].end,
                            tokens[idx + 1].line + 1,
                        )
            idx += 1
            continue

        out_parts.append(tok.text)
        idx += 1

    return "".join(out_parts), removed


def _normalize_text_whitespace(text: str) -> str:
    """Normalize whitespace within code or contract snippets for equality checking."""
    return " ".join(text.split())


def splice_architect_header(
    base_text: str,
    agent_text: str,
    current_text: str,
    path: str = "<input>",
) -> str:
    """
    Tolerantly merge an Interface Architect's header modifications into current_text
    when current_text was concurrently updated by a leaf/static prover or peer architect.
    """
    acsl_errors = verify_acsl_only(base_text, agent_text, path=path)
    if acsl_errors:
        raise AcslError(f"ACSL-only check failed on {path}:\n  " + "\n  ".join(acsl_errors))

    curr_errors = verify_acsl_only(base_text, current_text, path=path)
    if curr_errors:
        raise AcslError(f"Current workspace has ACSL-only check errors on {path}:\n  " + "\n  ".join(curr_errors))

    if current_text == base_text:
        return agent_text
    if agent_text == base_text or agent_text == current_text:
        return current_text

    base_proto_spans = locate_all_prototype_spans(base_text, path=path)
    agent_proto_spans = locate_all_prototype_spans(agent_text, path=path)
    curr_proto_spans = locate_all_prototype_spans(current_text, path=path)

    base_spans = {s.function: s for s in base_proto_spans}
    agent_spans = {s.function: s for s in agent_proto_spans}
    curr_spans = {s.function: s for s in curr_proto_spans}

    if set(base_spans.keys()) != set(agent_spans.keys()) or set(base_spans.keys()) != set(curr_spans.keys()):
        raise ScopeViolationError(f"{path}: function prototype mismatch between base, agent, and current")

    # Step 1: Detect prototype contract conflicts and record replacements
    replacements: list[tuple[int, int, str]] = []  # (start_byte, end_byte, replacement_text)
    for fn, b_s in base_spans.items():
        a_s = agent_spans[fn]
        c_s = curr_spans[fn]
        a_mod = _normalize_text_whitespace(a_s.text) != _normalize_text_whitespace(b_s.text)
        c_mod = _normalize_text_whitespace(c_s.text) != _normalize_text_whitespace(b_s.text)

        if a_mod and c_mod:
            if _normalize_text_whitespace(a_s.text) != _normalize_text_whitespace(c_s.text):
                raise ScopeViolationError(
                    f"{path}: conflicting concurrent modification to prototype contract of '{fn}'"
                )
        elif a_mod and not c_mod:
            replacements.append((c_s.start_byte, c_s.end_byte, a_s.text))

    # Step 2: Extract and reconcile top-level ACSL declarations
    b_decls = {d["profile_key"]: d for d in extract_top_level_acsl_declarations(base_text, path=path)}
    a_decls = {d["profile_key"]: d for d in extract_top_level_acsl_declarations(agent_text, path=path)}
    c_decls = {d["profile_key"]: d for d in extract_top_level_acsl_declarations(current_text, path=path)}

    for k, a_d in a_decls.items():
        if k in c_decls:
            if _normalize_text_whitespace(a_d["text"]) != _normalize_text_whitespace(c_decls[k]["text"]):
                raise ScopeViolationError(f"{path}: conflicting concurrent declaration of '{a_d['name']}'")

    for k, b_d in b_decls.items():
        if k not in a_decls and k in c_decls:
            if _normalize_text_whitespace(c_decls[k]["text"]) != _normalize_text_whitespace(b_d["text"]):
                raise ScopeViolationError(
                    f"{path}: conflicting concurrent modification/deletion of declaration '{b_d['name']}'"
                )

    # Step 3: Apply prototype replacements in current_text in reverse order
    spliced = current_text
    for start, end, rep in sorted(replacements, key=lambda x: x[0], reverse=True):
        spliced = spliced[:start] + rep + spliced[end:]

    # Step 4: Splice new top-level ACSL declarations introduced by the architect
    new_decls = [d for k, d in a_decls.items() if k not in b_decls and k not in c_decls]
    if new_decls:
        agent_tokens = tokenize_c_acsl(agent_text, path=path)
        blocks_to_insert: list[tuple[str | None, str]] = []  # (anchor_fn, block_text)
        for t in agent_tokens:
            if t.kind in ("acsl_block", "acsl_line"):
                inner = t.text[3:-2] if t.kind == "acsl_block" else t.text[3:]
                segs = _parse_acsl_inner_segments(inner, t.line)
                if any(s.name and any(d["name"] == s.name for d in new_decls) for s in segs):
                    # Identify anchor: find next function prototype in agent_proto_spans
                    anchor_fn = None
                    for span in agent_proto_spans:
                        if span.start_byte >= t.end:
                            anchor_fn = span.function
                            break
                    blocks_to_insert.append((anchor_fn, t.text))

        for anchor_fn, blk_text in blocks_to_insert:
            fresh_spans = {s.function: s for s in locate_all_prototype_spans(spliced, path=path)}
            if anchor_fn and anchor_fn in fresh_spans:
                pos = fresh_spans[anchor_fn].start_byte
                spliced = spliced[:pos] + blk_text + "\n\n" + spliced[pos:]
            else:
                pos = spliced.rfind("#endif")
                if pos == -1:
                    pos = len(spliced)
                spliced = spliced[:pos] + blk_text + "\n\n" + spliced[pos:]

    # Deduplicate intra-file declarations
    spliced, _ = dedup_acsl_declarations(spliced, set(), baseline_text=base_text, path=path)

    # Step 5: Post-splice verification
    post_errors = verify_acsl_only(base_text, spliced, path=path)
    if post_errors:
        raise AcslError(f"Post-splice ACSL-only check failed on {path}:\n  " + "\n  ".join(post_errors))

    return spliced


_INT_LITERAL_RE = re.compile(r"^[0-9]+$")
_RELATION_RE = re.compile(r"==|!=|<=|>=|<|(?<!-)>")


def find_named_clause(source: str, name: str) -> str | None:
    """Predicate of the ACSL clause labelled `name` (`ensures L5_x: <predicate>;`), or None if absent."""
    for _kind, label, predicate, _span in iter_clauses(source):
        labels = [item.strip() for item in label.split(",") if item.strip()]
        if name in labels:
            return " ".join(predicate.split())
    return None


def _top_level_positions(text: str) -> list[bool]:
    """For each character of `text`, whether it sits outside every bracket."""
    depth = 0
    out = []
    for ch in text:
        if ch in ")]}":
            depth -= 1
        out.append(depth == 0)
        if ch in "([{":
            depth += 1
    return out


def _split_top_level(text: str, op: str) -> list[str]:
    top = _top_level_positions(text)
    parts: list[str] = []
    start = i = 0
    while i < len(text):
        # `<==>` contains `==>`: it is split on first and must not read as an implication here.
        if top[i] and text.startswith(op, i) and not (op == "==>" and i > 0 and text[i - 1] == "<"):
            parts.append(text[start:i])
            i += len(op)
            start = i
        else:
            i += 1
    parts.append(text[start:])
    return [p.strip() for p in parts]


def _strip_outer_parens(text: str) -> str:
    text = text.strip()
    while text.startswith("(") and text.endswith(")"):
        depth = 0
        for i, ch in enumerate(text):
            depth += (ch == "(") - (ch == ")")
            if depth == 0 and i < len(text) - 1:
                return text
        text = text[1:-1].strip()
    return text


def _is_trivial_relation(text: str) -> bool:
    top = _top_level_positions(text)
    found = [m for m in _RELATION_RE.finditer(text) if top[m.start()]]
    if len(found) != 1:
        return False
    op = found[0].group(0)
    lhs = _strip_outer_parens(text[: found[0].start()])
    rhs = _strip_outer_parens(text[found[0].end() :])
    if lhs == rhs:
        return op in ("==", "<=", ">=")
    if _INT_LITERAL_RE.match(lhs) and _INT_LITERAL_RE.match(rhs):
        a, b = int(lhs), int(rhs)
        return {"==": a == b, "!=": a != b, "<=": a <= b, ">=": a >= b, "<": a < b, ">": a > b}[op]
    return False


def is_trivial_predicate(text: str) -> bool:
    """
    True when an ACSL predicate holds whatever the program does: `\\true`, a nonzero literal, `x == x`,
    `1 <= 2`, or a connective built from those. Conservative and syntactic: it answers False for
    anything it cannot see through, such as a predicate call or a quantifier.
    """
    text = _strip_outer_parens(" ".join(text.split()))
    if text == "\\true" or (_INT_LITERAL_RE.match(text) and int(text) != 0):
        return True
    if len(parts := _split_top_level(text, "<==>")) > 1:
        return len({_strip_outer_parens(p) for p in parts}) == 1
    if len(parts := _split_top_level(text, "==>")) > 1:
        lhs, rhs = _strip_outer_parens(parts[0]), _strip_outer_parens(" ==> ".join(parts[1:]))
        return is_trivial_predicate(rhs) or lhs == rhs or lhs == "\\false"
    if len(parts := _split_top_level(text, "||")) > 1:
        return any(is_trivial_predicate(p) for p in parts)
    if len(parts := _split_top_level(text, "&&")) > 1:
        return all(is_trivial_predicate(p) for p in parts)
    return _is_trivial_relation(text)


_ZERO_LITERAL_RE = re.compile(r"^(?:0+|0[xX]0+)[uUlL]*$")


def _is_false_relation(text: str) -> bool:
    top = _top_level_positions(text)
    found = [m for m in _RELATION_RE.finditer(text) if top[m.start()]]
    if len(found) != 1:
        return False
    op = found[0].group(0)
    lhs = _strip_outer_parens(text[: found[0].start()])
    rhs = _strip_outer_parens(text[found[0].end() :])
    if not lhs or not rhs:
        return False
    if lhs == rhs:
        return op in ("!=", "<", ">")
    if _INT_LITERAL_RE.match(lhs) and _INT_LITERAL_RE.match(rhs):
        a, b = int(lhs), int(rhs)
        return not {"==": a == b, "!=": a != b, "<=": a <= b, ">=": a >= b, "<": a < b, ">": a > b}[op]
    return False


def is_trivially_false_predicate(text: str) -> bool:
    """
    True when an ACSL predicate is false whatever the program does: `\\false`, a zero literal, `x != x`,
    `1 == 0`, `!\\true`, or a connective built from those. The twin of `is_trivial_predicate`, and as
    conservative: it answers False for anything it cannot see through.
    """
    text = _strip_outer_parens(" ".join(text.split()))
    if text == "\\false" or _ZERO_LITERAL_RE.match(text):
        return True
    if len(_split_top_level(text, "<==>")) > 1:
        return False
    if len(parts := _split_top_level(text, "==>")) > 1:
        rhs = " ==> ".join(parts[1:])
        return is_trivial_predicate(parts[0]) and is_trivially_false_predicate(rhs)
    if len(parts := _split_top_level(text, "||")) > 1:
        return all(is_trivially_false_predicate(p) for p in parts)
    if len(parts := _split_top_level(text, "&&")) > 1:
        return any(is_trivially_false_predicate(p) for p in parts)
    if text.startswith("!") and not text.startswith("!="):
        return is_trivial_predicate(text[1:])
    return _is_false_relation(text)


# ---------------------------------------------------------------------------
# Frame-skeleton preservation (AutoFraming-style projected frame clauses)
# ---------------------------------------------------------------------------

_SEPARATED_RE = re.compile(r"\\separated\s*\(")
_ASSIGNS_RE = re.compile(r"\bassigns\b")
_LOOP_ASSIGNS_PREFIX_RE = re.compile(r"\bloop\s*$")
_FROM_RE = re.compile(r"\\from\b")
_LEADING_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _paren_group_at(text: str, open_idx: int) -> tuple[str, int]:
    """Inner text of the paren group opening at `open_idx`, and the index after its close."""
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1 : i], i + 1
    return text[open_idx + 1 :], len(text)


def _scan_to_semicolon(text: str, start: int) -> int:
    """Index of the first top-level `;` at or after `start` (ACSL clauses end there)."""
    top = _top_level_positions(text)
    for i in range(start, len(text)):
        if top[i] and text[i] == ";":
            return i
    return len(text)


def extract_frame_clauses(acsl_text: str) -> dict:
    """
    Parse the frame clauses of one ACSL contract text:
    `\\separated(...)` argument lists and function-level `assigns ... [\\from ...];` clauses
    (`loop assigns` is not a function frame clause and is skipped). Purely syntactic, on the text the
    kernel reads (`_kernel_views`): a location or a `\\separated(...)` written in a comment or in a
    literal is not one.
    """
    separated: list[list[str]] = []
    masked, visible = _kernel_views(acsl_text)
    for m in _SEPARATED_RE.finditer(masked):
        inner, _ = _paren_group_at(masked, m.end() - 1)
        separated.append(_split_top_level(visible[m.end() : m.end() + len(inner)], ","))
    assigns = [_split_assigns(clause) for kind, _label, clause, _span in iter_clauses(acsl_text) if kind == "assigns"]
    return {"separated": separated, "assigns": assigns}


def _split_assigns(clause: str) -> dict:
    """The locations and the `\\from` sources of one `assigns` clause (its text after the keyword and label)."""
    from_m = _FROM_RE.search(clause)
    if from_m:
        locs_text, from_text = clause[: from_m.start()], clause[from_m.end() :]
    else:
        locs_text, from_text = clause, ""
    from_parts = _split_top_level(from_text, ",") if from_text.strip() else []
    return {
        "locs": _split_top_level(locs_text, ","),
        "from": from_parts,
        "from_nothing": bool(from_parts) and all(p == "\\nothing" for p in from_parts),
    }


def _norm_clause(text: str) -> str:
    return re.sub(r"\s+", "", text or "")


def check_frame_preserved(skeleton: dict, acsl_text: str, path: str = "<input>") -> list[str]:
    """
    Verify that a candidate contract preserves a projected frame skeleton
    (frame_skeleton.compute output): every `\\separated` pair must appear in some
    `\\separated` clause of the candidate (matched on the roots, so a stronger region is
    accepted), and every skeleton `assigns L \\from S` must be covered by a candidate
    `assigns` clause listing L with a `\\from` superset of S. Strengthening is allowed;
    deleting or weakening a projected clause is an error. A disabled/missing skeleton
    checks nothing (fail-open).
    """
    if not isinstance(skeleton, dict) or skeleton.get("status") not in ("ok", "partial"):
        return []
    errors: list[str] = []
    clauses = extract_frame_clauses(acsl_text)
    for sep in skeleton.get("separated") or []:
        want = {_norm_clause(r) for r in sep.get("roots") or []}
        if not want:
            continue
        covered = False
        for args in clauses["separated"]:
            leading = set()
            for arg in args:
                m = _LEADING_IDENT_RE.match(arg.strip())
                if m:
                    leading.add(_norm_clause(m.group(0)))
            if want <= leading:
                covered = True
                break
        if not covered:
            errors.append(
                f"{path}: projected frame clause missing or weakened: {sep.get('clause')!r} "
                f"(no \\separated clause over roots {sorted(sep.get('roots') or [])})"
            )
    for a in skeleton.get("assigns") or []:
        loc = _norm_clause(a.get("loc") or "")
        want_from = {_norm_clause(f) for f in a.get("from") or []}
        if not loc:
            continue
        covered = False
        for cl in clauses["assigns"]:
            locs = {_norm_clause(x) for x in cl["locs"]}
            if loc not in locs:
                continue
            if loc == "\\nothing":
                covered = True
                break
            have = {_norm_clause(x) for x in cl["from"]}
            if cl["from_nothing"] and not want_from:
                covered = True
                break
            if want_from <= have:
                covered = True
                break
        if not covered:
            errors.append(
                f"{path}: projected frame clause missing or weakened: {a.get('clause')!r} "
                f"(no assigns clause covering location {a.get('loc')!r} with \\from superset of {sorted(a.get('from') or [])})"
            )
    return errors


_CANONICAL_OVERLOADS_CACHE: dict[tuple[str, str, int], set[tuple[str, ...]]] | None = None


def _get_canonical_vocabulary_overloads() -> dict[tuple[str, str, int], set[tuple[str, ...]]]:
    """Return map of (kind, name, arity) -> set of normalized param_types tuples for canonical ACSL overloads."""
    global _CANONICAL_OVERLOADS_CACHE
    if _CANONICAL_OVERLOADS_CACHE is not None:
        return _CANONICAL_OVERLOADS_CACHE

    overloads: dict[tuple[str, str, int], set[tuple[str, ...]]] = {}
    fallback: dict[tuple[str, str, int], set[tuple[str, ...]]] = {
        ("predicate", "valid_read_buffer", 2): {
            ("char *", "integer"),
            ("unsigned char *", "integer"),
        },
        ("predicate", "valid_write_buffer", 2): {
            ("char *", "integer"),
            ("unsigned char *", "integer"),
        },
    }

    vocab_paths = [
        Path("/opt/framac-pipeline/templates/acsl/acsl_vocabulary.h"),
        Path(__file__).resolve().parent.parent / "templates" / "acsl" / "acsl_vocabulary.h",
    ]
    extracted = False
    for vp in vocab_paths:
        if vp.is_file():
            try:
                content = vp.read_text(encoding="utf-8", errors="replace")
                decls = extract_top_level_acsl_declarations(content, path=vp.name)
                grouped: dict[tuple[str, str, int], set[tuple[str, ...]]] = {}
                for d in decls:
                    k = d.get("kind")
                    n = d.get("name")
                    a = d.get("arity")
                    pt = d.get("param_types")
                    if k and n and a is not None and pt is not None:
                        key = (k, n, a)
                        grouped.setdefault(key, set()).add(pt)
                for key, sig_set in grouped.items():
                    if len(sig_set) > 1:
                        overloads[key] = sig_set
                extracted = True
                break
            except Exception:
                pass

    if not extracted or not overloads:
        overloads = fallback
    else:
        for key, sigs in fallback.items():
            overloads.setdefault(key, set()).update(sigs)

    _CANONICAL_OVERLOADS_CACHE = overloads
    return _CANONICAL_OVERLOADS_CACHE


def check_conflicting_acsl_profiles(
    new_decls: list[dict],
    existing_decls: list[dict],
    source_path: str = "<input>",
) -> list[str]:
    """
    Detect conflicting predicate or logic function profiles (e.g. `char*` vs `unsigned char*`).
    Returns a list of diagnostic error strings if conflicts are found.
    """
    conflicts: list[str] = []
    canonical_overloads = _get_canonical_vocabulary_overloads()

    # 1. Compare new declarations against existing declarations
    for new_d in new_decls:
        kind = new_d.get("kind")
        name = new_d.get("name")
        arity = new_d.get("arity")
        param_types = new_d.get("param_types")
        if kind not in ("predicate", "logic", "inductive") or not name or arity is None or param_types is None:
            continue

        matching_existing = [
            d
            for d in existing_decls
            if d.get("name") == name
            and d.get("kind") == kind
            and d.get("arity") == arity
            and d.get("param_types") is not None
        ]
        if matching_existing:
            if not any(d["param_types"] == param_types for d in matching_existing):
                canon_key = (kind, name, arity)
                if canon_key in canonical_overloads:
                    valid_sigs = canonical_overloads[canon_key]
                    if param_types in valid_sigs and all(d["param_types"] in valid_sigs for d in matching_existing):
                        continue

                first = matching_existing[0]
                first_loc = f"{first.get('path', '<existing>')}:{first.get('line', '?')}"
                new_loc = f"{source_path}:{new_d.get('line', '?')}"
                first_prof = first.get("full_profile") or f"{name}/{arity}"
                new_prof = new_d.get("full_profile") or f"{name}/{arity}"
                conflicts.append(
                    f"Conflicting profile for {kind} '{name}': '{new_prof}' at {new_loc} "
                    f"conflicts with existing declaration '{first_prof}' at {first_loc}"
                )

    # 2. Compare declarations within new_decls themselves
    existing_sigs: set[tuple[str, str, int, tuple[str, ...]]] = {
        (d["kind"], d["name"], d["arity"], d["param_types"])
        for d in existing_decls
        if d.get("kind") and d.get("name") and d.get("arity") is not None and d.get("param_types") is not None
    }

    n = len(new_decls)
    for i in range(n):
        d1 = new_decls[i]
        kind1 = d1.get("kind")
        name1 = d1.get("name")
        arity1 = d1.get("arity")
        param_types1 = d1.get("param_types")
        if kind1 not in ("predicate", "logic", "inductive") or not name1 or arity1 is None or param_types1 is None:
            continue
        for j in range(i + 1, n):
            d2 = new_decls[j]
            if (
                d2.get("name") == name1
                and d2.get("kind") == kind1
                and d2.get("arity") == arity1
                and d2.get("param_types") is not None
            ):
                param_types2 = d2["param_types"]
                if param_types2 != param_types1:
                    sig1 = (kind1, name1, arity1, param_types1)
                    sig2 = (kind1, name1, arity1, param_types2)
                    # Do not flag as conflict if both are known overloads in existing_decls:
                    if sig1 in existing_sigs and sig2 in existing_sigs:
                        continue
                    # Do not flag as conflict if both match canonical vocabulary overloads:
                    canon_key = (kind1, name1, arity1)
                    if canon_key in canonical_overloads:
                        valid_sigs = canonical_overloads[canon_key]
                        if param_types1 in valid_sigs and param_types2 in valid_sigs:
                            continue

                    loc1 = f"{source_path}:{d1.get('line', '?')}"
                    loc2 = f"{source_path}:{d2.get('line', '?')}"
                    prof1 = d1.get("full_profile") or f"{name1}/{arity1}"
                    prof2 = d2.get("full_profile") or f"{name1}/{arity1}"
                    conflicts.append(
                        f"Conflicting profile for {kind1} '{name1}': '{prof1}' at {loc1} "
                        f"conflicts with '{prof2}' at {loc2}"
                    )

    return conflicts


# ---------------------------------------------------------------------------
# Trust boundary: preconditions of an untrusted_surface entry function
# ---------------------------------------------------------------------------


class TrustBoundaryError(AcslError):
    """Raised when an untrusted_surface entry contract constrains attacker-controlled values."""


# Built-ins that state memory shape only. Anything inside their argument list is a location, not a value.
_SHAPE_BUILTINS = (
    "valid",
    "valid_read",
    "separated",
    "initialized",
    "freeable",
    "allocable",
    "block_length",
    "offset",
    "base_addr",
    "valid_function",
)
# Predicates of templates/acsl/acsl_vocabulary.h that state shape only (validity of a range, with
# the `len >= 0` / `len == 0` guards that come with it). The others (is_printable_ascii,
# no_crlf_or_nul, no_crlf_string, buffer_is_zeroed) constrain byte values.
SHAPE_VOCABULARY_PREDICATES = frozenset({"valid_read_buffer", "valid_write_buffer"})
# valid_read_string(s) (canonical, plan step S8) and its old alias valid_c_string(s) also say that s
# holds a NUL: a recorded environment fact only when the harness NUL-terminates the input
# (entry_style c_string / argv, or null_terminate).
_NUL_TERMINATION_PREDICATES = frozenset({"valid_read_string", "valid_c_string"})
_SHAPE_CALL_RE = re.compile(
    r"\\(?:" + "|".join(_SHAPE_BUILTINS) + r")\b(?:\{[^}]*\})?\s*\(|\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:\{[^}]*\})?\s*\("
)
_BINDER_RE = re.compile(r"\\(?:forall|exists|let)\b")
_REQUIRES_RE = re.compile(r"(?<![\\\w])requires\b")
_CLAUSE_LABEL_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:(?!:)")
_NULL_CMP_RE = re.compile(r"^(?:([A-Za-z_][A-Za-z0-9_]*)\s*!=\s*\\null|\\null\s*!=\s*([A-Za-z_][A-Za-z0-9_]*))$")
_NONNEG_RE = re.compile(r"^(?:([A-Za-z_][A-Za-z0-9_]*)\s*>=\s*0|0\s*<=\s*([A-Za-z_][A-Za-z0-9_]*))$")
_CAPACITY_RE = re.compile(r"\\(?:block_length|offset)\b")
_C_PARAM_KEYWORDS = frozenset(
    {
        "const",
        "volatile",
        "restrict",
        "__restrict",
        "__restrict__",
        "unsigned",
        "signed",
        "int",
        "long",
        "short",
        "char",
        "void",
        "float",
        "double",
        "struct",
        "union",
        "enum",
        "register",
        "_Bool",
        "bool",
    }
)


def _acsl_comment_body(text: str) -> str:
    """
    The inside of one ACSL comment as the kernel reads it (`_kernel_views`): no `/*@`, `*/` or `//@`, and
    its comments and `@` blanked. Line ends are kept, so a line counted in the result is a line of `text`.
    """
    body = _kernel_views(text)[1]
    if text.startswith("/*@"):
        return body[3:-2] if text.endswith("*/") else body[3:]
    return body[3:] if text.startswith("//@") else body


def _first_top_level_binder(text: str) -> int:
    top = _top_level_positions(text)
    for m in _BINDER_RE.finditer(text):
        if top[m.start()]:
            return m.start()
    return len(text)


def _scan_clause_end(text: str, start: int) -> int:
    """End of the ACSL clause starting at `start`: the first top-level `;` not closing a binder."""
    top = _top_level_positions(text)
    binders = {m.start() for m in _BINDER_RE.finditer(text, start) if top[m.start()]}
    pending = 0
    for i in range(start, len(text)):
        if i in binders:
            pending += 1
        elif top[i] and text[i] == ";":
            if pending:
                pending -= 1
            else:
                return i
    return len(text)


_CLAUSE_HEAD_RE = re.compile(
    r"(?<![\\\w])(?:(loop\s+(?:invariant|assigns|variant|allocates|frees))|"
    r"(requires|ensures|assumes|assigns|allocates|frees|terminates|exits|breaks|continues|returns|decreases|invariant|variant))\b"
)


def iter_clauses(annotation: str) -> Iterator[tuple[str, str, str, tuple[int, int]]]:
    """
    Iterate parsed ACSL clauses (kind, label, predicate, span) across annotation text.

    The clauses are those the Frama-C kernel reads (`_kernel_views`): a `//` comment inside an annotation,
    a `//@` nested in one (outside ghost code) and an `@` are white space in the label and the predicate, and
    cannot start, end or extend a clause. `span` is an offset pair in `annotation`.
    """
    masked, visible = _kernel_views(annotation)
    i = 0
    n = len(annotation)
    while i < n:
        m = _CLAUSE_HEAD_RE.search(masked, i)
        if m is None:
            break
        kind = " ".join((m.group(1) or m.group(2)).split())
        end = _scan_clause_end(masked, m.end())
        if end >= n:
            i = m.end()
            continue
        raw = visible[m.end() : end]
        labels: list[str] = []
        while (lab := _CLAUSE_LABEL_RE.match(raw)) is not None:
            labels.append(lab.group(1))
            raw = raw[lab.end() :]
        label = ", ".join(labels)
        pred = raw.strip()
        span = (m.start(), end + 1)
        yield (kind, label, pred, span)
        i = end + 1


def extract_requires_clauses(contract_text: str) -> list[str]:
    """The predicates of every `requires` clause (function and behavior level) in ACSL contract text."""
    return [pred for kind, _label, pred, _span in iter_clauses(contract_text) if kind == "requires" and pred]


def _split_unbound(text: str, op: str) -> list[str]:
    """`_split_top_level`, but a top-level binder (`\\forall`, `\\exists`, `\\let`) extends to the end."""
    limit = _first_top_level_binder(text)
    parts = _split_top_level(text[:limit], op)
    if limit < len(text):
        parts[-1] = (parts[-1] + " " + text[limit:]).strip()
    return parts


def _strip_shape_calls(text: str, shape_names: frozenset[str]) -> str:
    """`text` with every shape built-in / shape predicate call (name and arguments) removed."""
    out: list[str] = []
    i = 0
    while i < len(text):
        m = _SHAPE_CALL_RE.search(text, i)
        if m is None:
            out.append(text[i:])
            break
        name = m.group(1)
        if name is not None and name not in shape_names:
            out.append(text[i : m.end()])
            i = m.end()
            continue
        out.append(text[i : m.start()])
        _, i = _paren_group_at(text, m.end() - 1)
        out.append(" ")
    return "".join(out).replace("\\null", " ")


def _value_refs(text: str, attackers: frozenset[str], shape_names: frozenset[str]) -> set[str]:
    """Attacker parameters `text` reads as values (outside shape calls, not as `s.field` / `p->field`)."""
    rest = _strip_shape_calls(text, shape_names)
    refs: set[str] = set()
    for m in _IDENT_RE.finditer(rest):
        before = rest[: m.start()].rstrip()
        member = before.endswith(("->", "\\")) or (before.endswith(".") and not before.endswith(".."))
        if m.group(0) in attackers and not member:
            refs.add(m.group(0))
    return refs


def _is_single_shape_call(text: str, shape_names: frozenset[str]) -> bool:
    m = _SHAPE_CALL_RE.match(text)
    if m is None or (m.group(1) is not None and m.group(1) not in shape_names):
        return False
    _, end = _paren_group_at(text, m.end() - 1)
    return end == len(text)


def _constrained_params(pred: str, attackers: frozenset[str], shape_names: frozenset[str]) -> set[str]:
    """Attacker parameters whose value `pred` constrains (empty when it states memory shape only)."""
    text = _strip_outer_parens(" ".join(pred.split()))
    if not text:
        return set()
    binder = _BINDER_RE.match(text)
    if binder is not None:
        if text.startswith("\\let"):
            return _value_refs(text, attackers, shape_names)  # a bound name can carry an attacker value
        end = _scan_clause_end(text, binder.end())
        return _constrained_params(text[end + 1 :], attackers, shape_names)
    for op in ("<==>", "^^"):
        if len(_split_unbound(text, op)) > 1:
            return _value_refs(text, attackers, shape_names)
    parts = _split_unbound(text, "==>")
    if len(parts) > 1:
        # The antecedents only guard: `len > 0 ==> \valid_read(buf + (0 .. len - 1))` states shape.
        return _constrained_params(parts[-1], attackers, shape_names)
    parts = _split_unbound(text, "||")
    if len(parts) > 1:
        per_part = [_constrained_params(p, attackers, shape_names) for p in parts]
        # `len == 0 || \valid_read(...)` states shape: a disjunction constrains only if every disjunct does.
        return set().union(*per_part) if all(per_part) else set()
    parts = _split_unbound(text, "&&")
    if len(parts) > 1:
        return set().union(*(_constrained_params(p, attackers, shape_names) for p in parts))
    if _is_single_shape_call(text, shape_names) or text == "\\true":
        return set()
    m = _NULL_CMP_RE.match(text) or _NONNEG_RE.match(text)
    if m is not None:
        return set()
    if _CAPACITY_RE.search(text) and _RELATION_RE.search(text):
        # `\block_length(buf) >= len`: the capacity of a block, a shape fact.
        return set()
    return _value_refs(text, attackers, shape_names)


def function_trust_records(workspace: Path | str) -> dict:
    """
    The run's function records carrying `trust` (scripts/trust.py, plan step I7): the DAG's
    (`<workspace>/reports/callgraph_dag.json`, keyed by plain name, or `file#name` when the name
    collides), else the Phase 0 model's (keyed `file#name`). Each record has its `name` and `file`, so
    same-named functions keep their own trust. Empty when neither has trust.
    """
    import json

    reports = Path(workspace) / "reports"
    for path in (reports / "callgraph_dag.json", reports / "phase0_model.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        records = data.get("functions") if isinstance(data, dict) else None
        if isinstance(records, dict) and any(isinstance(r, dict) and "trust" in r for r in records.values()):
            return records
    return {}


def is_trust_boundary(records: dict, function: str, file: str | None = None) -> bool | None:
    """
    Whether attacker data reaches `function`'s parameters directly (its trust is `untrusted` with
    `boundary`): then its `requires` may state memory shape only (`entry_requires_violations`).
    With `file`, the record of `function` in that file decides, so a same-named static elsewhere
    keeps its own trust; a file no record names falls back to every same-named record (untrusted
    wins). None when the run has no trust for it.
    """
    from trust import function_trust

    trust = function_trust(records, function, file) if file else None
    if trust is None:
        trust = function_trust(records, function)
    if trust is None:
        return None
    return trust.get("value") == "untrusted" and bool(trust.get("boundary"))


def entry_requires_violations(
    contract_text: str,
    attacker_params: list[str] | set[str] | frozenset[str],
    *,
    nul_terminated: bool = False,
) -> list[str]:
    """
    Trust-boundary check of an untrusted_surface entry function's contract (docs/guides/v2-design.md §6):
    its `requires` may state memory shape only (`\\valid`, `\\valid_read`, `\\separated`,
    `\\initialized`, `p != \\null`, `\\block_length`, shape-only vocabulary predicates) and facts
    that do not involve attacker-controlled parameters. A clause that constrains the value of an
    attacker parameter or of the bytes it points to (`len <= 64`, `buf[0] == 0x30`,
    `\\forall integer i; ... ==> buf[i] != 0`, an unknown predicate over `buf`) is a violation.

    Lexical and conservative: what it cannot classify as shape is flagged. Implication antecedents
    only guard and are not checked; a disjunction violates only if each disjunct does.
    `nul_terminated`: the harness NUL-terminates the input, so `valid_read_string` (or `valid_c_string`) is shape here.
    """
    attackers = frozenset(p for p in attacker_params if p)
    if not attackers:
        return []
    shape_names = SHAPE_VOCABULARY_PREDICATES | (_NUL_TERMINATION_PREDICATES if nul_terminated else frozenset())
    out: list[str] = []
    for pred in extract_requires_clauses(contract_text):
        params = _constrained_params(pred, attackers, shape_names)
        if params:
            out.append(
                f"requires {pred}; constrains attacker-controlled {', '.join(sorted(params))} "
                "(an untrusted_surface entry may only state memory shape)"
            )
    return out


def function_param_names(source: str, function: str, is_header: bool = False, path: str = "<input>") -> list[str]:
    """
    Parameter names of `function`'s definition (in a header: of its first prototype, else of its
    definition); unnamed parameters are skipped. The declarations of one function may name their
    formals differently: `declaration_param_names` reads one declaration.
    """
    decls = contract_declaration_spans(source, function, is_header=is_header, path=path)
    decls = [d for d in decls if d.kind == "prototype"][:1] or decls
    return declaration_param_names(decls[0], path=path) if decls else []


def declaration_param_names(decl: DeclSpan, path: str = "<input>") -> list[str]:
    """Parameter names of one declaration of a function; unnamed parameters are skipped."""
    function = decl.span.function
    toks = [t for t in tokenize_c_acsl(_span_contract_part(decl, path=path), path=path) if t.kind == "c_token"]
    for k, tok in enumerate(toks):
        if tok.text != function or k + 1 >= len(toks) or toks[k + 1].text != "(":
            continue
        depth = 0
        close_idx = len(toks)
        params: list[list[str]] = [[]]
        for offset, t in enumerate(toks[k + 1 :], start=k + 1):
            if t.text in "([":
                depth += 1
                if depth == 1 and t.text == "(":
                    continue
            elif t.text in ")]":
                depth -= 1
                if depth == 0:
                    close_idx = offset
                    break
            if depth == 1 and t.text == ",":
                params.append([])
                continue
            params[-1].append(t.text)
        # In a K&R definition (`int f(a, b) int a; char *b; { ... }`), parameter type declarations
        # ending with `;` follow the parameter list before `{`, so single-identifier items in `(...)`
        # are parameter names rather than unnamed type names.
        is_kr = decl.kind == "definition" and any(t.text == ";" for t in toks[close_idx + 1 :])
        names: list[str] = []
        for p in params:
            if not p or p in (["void"], ["..."]):
                continue
            if is_kr and len(p) == 1 and _IDENT_RE.fullmatch(p[0]) and p[0] not in _C_PARAM_KEYWORDS:
                names.append(p[0])
                continue
            ptr = [i for i in range(len(p) - 2) if p[i] == "(" and p[i + 1] == "*" and _IDENT_RE.fullmatch(p[i + 2])]
            if ptr:
                names.append(p[ptr[0] + 2])
                continue
            while p and p[-1] == "]" and "[" in p:
                p = p[: len(p) - 1 - p[::-1].index("[")]
            if len(p) >= 2 and _IDENT_RE.fullmatch(p[-1]) and p[-1] not in _C_PARAM_KEYWORDS:
                names.append(p[-1])
        return names
    return []


def function_contract_text(source: str, function: str, is_header: bool = False, path: str = "<input>") -> str:
    """
    The ACSL contract in front of `function`'s definition, without body annotations. In a header,
    the contracts in front of every declaration (prototype and definition), joined in source order:
    Frama-C merges them into one contract.
    """
    parts = [
        declaration_contract_text(d, path=path)
        for d in contract_declaration_spans(source, function, is_header=is_header, path=path)
    ]
    return "\n".join(p for p in parts if p)


def declaration_contract_text(decl: DeclSpan, path: str = "<input>") -> str:
    """The ACSL contract in front of one declaration of a function, without body annotations."""
    return "\n".join(
        t.text
        for t in tokenize_c_acsl(_span_contract_part(decl, path=path), path=path)
        if t.kind in ("acsl_block", "acsl_line")
    )


# ---------------------------------------------------------------------------
# Contract shape: does a proved contract say what the function computes?
# ---------------------------------------------------------------------------

SHAPE_FUNCTIONAL = "functional"
SHAPE_SAFETY_ONLY = "safety_only"
SHAPE_NOT_APPLICABLE = "not_applicable"
# No contract text was found for the function, so nothing can be said about its shape.
SHAPE_UNKNOWN = "unknown"
CONTRACT_SHAPES = (SHAPE_FUNCTIONAL, SHAPE_SAFETY_ONLY, SHAPE_NOT_APPLICABLE, SHAPE_UNKNOWN)

_BEHAVIOR_HEAD_RE = re.compile(r"(?<![\\\w])behavior\s+[A-Za-z_][A-Za-z0-9_]*\s*:")
_PRE_STATE_RE = re.compile(r"\\(old|at)\s*\(")
# `\at(t, L)` reads the post-state under these labels and the pre-state under any other.
_POST_LABELS = frozenset({"Post", "Here"})
_BINDER_DECL_RE = re.compile(r"\\(?:forall|exists)\b([^;]*);")
_LET_RE = re.compile(r"\\let\s+([A-Za-z_][A-Za-z0-9_]*)\s*=")
# `(type) term`: a parenthesised type name directly in front of a term.
_CAST_RE = re.compile(r"\(\s*(?:[A-Za-z_][A-Za-z0-9_]*\s+)*[A-Za-z_][A-Za-z0-9_]*\s*\**\s*\)(?=\s*[\w\\(])")
# An all-capitals name is read as a constant (a macro or an enumerator), not as a program value.
_CONSTANT_NAME_RE = re.compile(r"[A-Z_][A-Z0-9_]*")
_NOT_A_VALUE = frozenset(
    {"sizeof", "integer", "real", "boolean", "Pre", "Post", "Old", "Here", "LoopEntry", "LoopCurrent"}
)
_SHAPE_ONLY_NAMES = SHAPE_VOCABULARY_PREDICATES | _NUL_TERMINATION_PREDICATES


def _split_pre_state(text: str) -> tuple[str, str]:
    """(`text` without its `\\old(...)` / `\\at(..., Pre)` terms, the text of those terms)."""
    post: list[str] = []
    pre: list[str] = []
    i = 0
    while (m := _PRE_STATE_RE.search(text, i)) is not None:
        inner, end = _paren_group_at(text, m.end() - 1)
        post.append(text[i : m.start()])
        if m.group(1) == "at":
            parts = _split_top_level(inner, ",")
            label = parts[-1] if len(parts) > 1 else ""
            inner = ",".join(parts[:-1]) if len(parts) > 1 else inner
            (post if label in _POST_LABELS else pre).append(f" ({inner}) ")
        else:
            pre.append(f" ({inner}) ")
        i = end
    post.append(text[i:])
    return "".join(post), " ".join(pre)


def _value_names(text: str, bound: frozenset[str]) -> set[str]:
    """Program values `text` names: not a member, a call name, a bound variable, a type or a constant."""
    names: set[str] = set()
    for m in _IDENT_RE.finditer(text):
        name = m.group(0)
        before = text[: m.start()].rstrip()
        after = text[m.end() :].lstrip()
        if before.endswith(("->", "\\")) or (before.endswith(".") and not before.endswith("..")):
            continue
        if before[-1:].isdigit() or after.startswith("(") or name in bound or name in _NOT_A_VALUE:
            continue
        if _CONSTANT_NAME_RE.fullmatch(name):
            continue
        names.add(name)
    return names


def _relates_output(predicate: str, roots: frozenset[str] | None, guarded: bool) -> bool:
    """
    Whether an `ensures` predicate relates an output to another value. Outputs are `\\result` and the
    roots of the assigned locations in the post-state (`roots` None: no `assigns` clause, so any
    post-state value may be one). The other value is a second output, a value the function does not
    assign, or anything in the pre-state (`\\old`). Arguments of the validity, initialization and
    separation built-ins are locations, not values, and are left out, so `\\valid(\\result)` and the
    constant range `\\result >= 0` relate nothing. `guarded` (the clause sits in a behavior with an
    `assumes`) makes the assumption the other value.
    """
    text = _strip_shape_calls(" ".join(predicate.split()), _SHAPE_ONLY_NAMES)
    bound: set[str] = set(_LET_RE.findall(text))
    for decl in _BINDER_DECL_RE.findall(text):
        # `\forall integer i, j;`: the last identifier of each part is the bound name.
        bound.update(ids[-1] for part in _split_top_level(decl, ",") if (ids := _IDENT_RE.findall(part)))
    text = _CAST_RE.sub(" ", _BINDER_DECL_RE.sub(" ", text))
    post_text, pre_text = _split_pre_state(text)
    post = _value_names(post_text, frozenset(bound))
    outputs = (post if roots is None else post & roots) | ({"\\result"} if "\\result" in post_text else set())
    if not outputs:
        return False
    others = _value_names(pre_text, frozenset(bound)) | (post - outputs)
    return guarded or bool(others) or len(outputs) > 1


def contract_shape(contract_text: str, returns_void: bool = False) -> str:
    """
    What a function contract says beyond the absence of runtime errors:

    - `functional`: at least one `ensures` that is not trivial (`is_trivial_predicate`) relates an
      output (`\\result`, or the content of a location an `assigns` clause names) to another value:
      an input, the pre-state (`\\old`), a second output, or the `assumes` of its behavior.
    - `not_applicable`: a `void` function whose every `assigns` clause is `assigns \\nothing`: it has
      no output a postcondition could describe.
    - `safety_only`: anything else. The postconditions, if any, state validity, initialization,
      separation or a constant range only, so a caller learns nothing about the result.
    - `unknown`: no contract text.

    Syntactic, like `is_trivial_predicate`: it reads names, not meaning. A postcondition through a
    logic function or predicate counts by its arguments (`\\result == sum(a, n)` is functional), an
    all-capitals name counts as a constant, and a tautology the trivial check cannot see through may
    count as functional.
    """
    if not contract_text.strip():
        return SHAPE_UNKNOWN
    locs = [loc.strip() for a in extract_frame_clauses(contract_text)["assigns"] for loc in a["locs"] if loc.strip()]
    roots: frozenset[str] | None = None
    if locs:
        found: set[str] = set()
        for loc in locs:
            for m in _IDENT_RE.finditer(loc):
                if not loc[: m.start()].endswith("\\"):
                    found.add(m.group(0))
                    break
        roots = frozenset(found)
    masked = _kernel_views(contract_text)[0]
    clauses = list(iter_clauses(contract_text))
    for kind, _label, predicate, span in clauses:
        if kind != "ensures" or not predicate or is_trivial_predicate(predicate):
            continue
        heads = [m.start() for m in _BEHAVIOR_HEAD_RE.finditer(masked, 0, span[0])]
        guarded = bool(heads) and any(
            k == "assumes" and heads[-1] < s[0] < span[0] and not is_trivial_predicate(p) for k, _l, p, s in clauses
        )
        if _relates_output(predicate, roots, guarded):
            return SHAPE_FUNCTIONAL
    if returns_void and locs and all(loc == "\\nothing" for loc in locs):
        return SHAPE_NOT_APPLICABLE
    return SHAPE_SAFETY_ONLY


def function_returns_void(source: str, function: str, is_header: bool = False, path: str = "<input>") -> bool | None:
    """
    Whether `function` is declared `void` (and not `void *`), read from the first declaration the
    pipeline takes its contract from. None when the function is not declared in `source`.
    """
    decls = contract_declaration_spans(source, function, is_header=is_header, path=path)
    if not decls:
        return None
    head = mask_comments_and_literals(_span_contract_part(decls[0], path=path), acsl="blank", on_error="mask")
    m = re.search(rf"(?<![A-Za-z0-9_]){re.escape(function)}\s*\(", head)
    if m is None:
        return None
    prefix = head[: m.start()]
    return "*" not in prefix and "void" in _IDENT_RE.findall(prefix)


# ---------------------------------------------------------------------------
# Contract comparison: which clauses of a function's contract a candidate removed
# ---------------------------------------------------------------------------

# Frama-C's own name for the behavior holding the clauses written outside every `behavior`; not an identifier,
# so no named behavior can collide with it.
DEFAULT_BEHAVIOR = "default!"
# The clause kinds every behavior of a comparison reports, in this order.
CONTRACT_CLAUSE_KINDS = (
    "requires",
    "assumes",
    "assigns",
    "ensures",
    "terminates",
    "exits",
    "decreases",
    "allocates",
    "frees",
)

_BEHAVIOR_NAME_RE = re.compile(r"(?<![\\\w])behavior\s+([A-Za-z_][A-Za-z0-9_]*)\s*:")
_COMPLETENESS_RE = re.compile(r"(?<![\\\w])(?:complete|disjoint)\s+behaviors\b[^;]*")
_CLAUSE_MODIFIER_RE = re.compile(r"(?<![\\\w])(check|admit)\s+$")
_FORMAL_REF_RE = re.compile(r"(?<![\w\\])[A-Za-z_][A-Za-z0-9_]*")


class _NoComparison(Exception):
    """Why `compare_function_contracts` has no comparison to give."""


def _empty_contract_comparison(function: object) -> dict:
    return {
        "available": False,
        "reason": "",
        "function": function if isinstance(function, str) else "",
        "declarations": {"baseline": [], "candidate": []},
        "formals_unified": False,
        "had_contract": False,
        "has_contract": False,
        "behaviors": {},
        "completeness": {"baseline": [], "candidate": [], "removed": [], "added": []},
        "summary": {"assigns_removed_in": [], "ensures_removed_in": [], "behaviors_removed": []},
    }


def _read_declaration_contract(decl: DeclSpan, path: str) -> dict:
    """
    The contract in front of one declaration: its clauses as `(behavior, kind, text)`, the named behaviors and
    the `complete` / `disjoint` clauses in source order, and the declaration's C tokens. `text` is the clause
    without keyword and label, white space collapsed; a `check` or `admit` clause keeps that word in front.
    A contract is one annotation, so each annotation starts in the default behavior. Ghost code is skipped.
    """
    tokens = tokenize_c_acsl(_span_contract_part(decl, path=path), path=path)
    clauses: list[tuple[str, str, str]] = []
    behaviors: list[str] = []
    completeness: list[str] = []
    for tok in tokens:
        if tok.kind not in ("acsl_block", "acsl_line") or _GHOST_ANNOTATION_RE.match(tok.text, 3):
            continue
        shape = _kernel_views(tok.text)[0]
        heads = [(m.start(), m.group(1)) for m in _BEHAVIOR_NAME_RE.finditer(shape)]
        behaviors.extend(name for _pos, name in heads)
        completeness.extend(" ".join(m.group(0).split()) for m in _COMPLETENESS_RE.finditer(shape))
        for kind, _label, pred, (start, _end) in iter_clauses(tok.text):
            text = " ".join(pred.split())
            if kind != "assigns":
                text = _strip_outer_parens(text)
            if not text:
                continue
            modifier = _CLAUSE_MODIFIER_RE.search(shape, 0, start)
            if modifier is not None:
                text = f"{modifier.group(1)} {text}"
            behavior = DEFAULT_BEHAVIOR
            for pos, name in heads:
                if pos < start:
                    behavior = name
            clauses.append((behavior, kind, text))
    signature = [t.text for t in tokens if t.kind not in ("whitespace", "c_comment", "acsl_block", "acsl_line")]
    return {"clauses": clauses, "behaviors": behaviors, "completeness": completeness, "signature": signature}


def _contract_declarations(texts: Mapping[str, str], function: str, side: str) -> list[tuple[str, DeclSpan, dict]]:
    """`(file, declaration, its contract)` for every declaration of `function` in `texts`, in the given file order."""
    found: list[tuple[str, DeclSpan, dict]] = []
    for rel, text in texts.items():
        if not isinstance(rel, str) or not isinstance(text, str):
            raise _NoComparison(f"{rel} ({side}): a file name and its text must both be strings")
        try:
            for decl in function_declaration_spans(text, function, path=rel):
                found.append((rel, decl, _read_declaration_contract(decl, rel)))
        except AcslError as exc:
            raise _NoComparison(f"{side} text cannot be read: {exc}") from None
    if not found:
        raise _NoComparison(f"no declaration of '{function}' in the {side} text of {', '.join(texts)}")
    return found


def _positional_formals(text: str, positions: Mapping[str, str]) -> str:
    """`text` with each formal of `positions` replaced by its position, except where the name is a field."""
    if not positions:
        return text

    def replace(m: re.Match[str]) -> str:
        position = positions.get(m.group(0))
        before = text[: m.start()].rstrip()
        if position is None or before.endswith("->") or (before.endswith(".") and not before.endswith("..")):
            return m.group(0)
        return position

    return _FORMAL_REF_RE.sub(replace, text)


def _pooled_clauses(decls: list[tuple[str, DeclSpan, dict]], formals: list[dict[str, str]]) -> dict[str, dict]:
    """
    The clauses of every declaration, per behavior then per kind, as `(key, text, location keys)`. Frama-C
    merges the contracts of a function's declarations behavior by behavior, so they are pooled the same way.
    `key` is what two clauses are compared on: no white space, formals by position, and for `assigns` the
    locations and the `\\from` sources each in sorted order.
    """
    pooled: dict[str, dict] = {DEFAULT_BEHAVIOR: {}}
    for (_rel, _decl, contract), positions in zip(decls, formals, strict=True):
        for name in contract["behaviors"]:
            pooled.setdefault(name, {})
        for behavior, kind, text in contract["clauses"]:
            loc_keys: list[str] = []
            key = _norm_clause(_positional_formals(text, positions))
            if kind == "assigns":
                parts = _split_assigns(text)
                loc_keys = [_norm_clause(_positional_formals(loc, positions)) for loc in parts["locs"]]
                from_keys = sorted(_norm_clause(_positional_formals(src, positions)) for src in parts["from"])
                key = ",".join(sorted(loc_keys)) + ("\\from" + ",".join(from_keys) if from_keys else "")
            pooled.setdefault(behavior, {}).setdefault(kind, []).append((key, text, loc_keys))
    return pooled


def _gone(left: list[tuple[str, str]], right: list[tuple[str, str]]) -> list[str]:
    """The texts of `left` whose key no entry of `right` has, once each, in order."""
    have = {key for key, _text in right}
    out: dict[str, str] = {}
    for key, text in left:
        if key not in have:
            out.setdefault(key, text)
    return list(out.values())


def _clause_delta(base: list, cand: list) -> dict:
    base_pairs = [(key, text) for key, text, _locs in base]
    cand_pairs = [(key, text) for key, text, _locs in cand]
    return {
        "baseline": [text for _key, text in base_pairs],
        "candidate": [text for _key, text in cand_pairs],
        "removed": _gone(base_pairs, cand_pairs),
        "added": _gone(cand_pairs, base_pairs),
    }


def _assigns_delta(base: list, cand: list) -> dict:
    delta = _clause_delta(base, cand)
    if not base and not cand:
        status = "none"
    elif not cand:
        status = "removed"
    elif not base:
        status = "added"
    else:
        status = "same" if {key for key, _t, _l in base} == {key for key, _t, _l in cand} else "changed"

    def locations(clauses: list) -> list[tuple[str, str]]:
        return [
            (k, loc) for _key, text, keys in clauses for k, loc in zip(keys, _split_assigns(text)["locs"], strict=True)
        ]

    base_locs, cand_locs = locations(base), locations(cand)
    return {
        "baseline": [{"text": text, **_split_assigns(text)} for _key, text, _locs in base],
        "candidate": [{"text": text, **_split_assigns(text)} for _key, text, _locs in cand],
        "status": status,
        "removed": delta["removed"],
        "added": delta["added"],
        "locations_removed": _gone(base_locs, cand_locs),
        "locations_added": _gone(cand_locs, base_locs),
    }


def _compare_contracts(result: dict, baseline: Mapping[str, str], candidate: Mapping[str, str], function: str) -> None:
    if not isinstance(function, str) or not function:
        raise _NoComparison("no function name given")
    if not isinstance(baseline, Mapping) or not isinstance(candidate, Mapping):
        raise _NoComparison("TypeError: baseline and candidate must each map a file name to its text")
    if set(baseline) != set(candidate):
        only_base = sorted(str(k) for k in set(baseline) - set(candidate))
        only_cand = sorted(str(k) for k in set(candidate) - set(baseline))
        raise _NoComparison(
            "baseline and candidate do not cover the same files "
            f"(only in baseline: {only_base}; only in candidate: {only_cand})"
        )
    if not baseline:
        raise _NoComparison("no file to compare")
    base = _contract_declarations(baseline, function, "baseline")
    cand = _contract_declarations({rel: candidate[rel] for rel in baseline}, function, "candidate")
    if [(rel, d.kind, c["signature"]) for rel, d, c in base] != [(rel, d.kind, c["signature"]) for rel, d, c in cand]:
        raise _NoComparison(
            f"the declarations of '{function}' differ between baseline and candidate "
            "(one was added or removed, or its C text changed)"
        )
    # The declarations of one function may name their formals differently. A clause moved from one to the
    # other is rewritten for the other's names, so clauses are compared with formals by position. That needs
    # every declaration to name the same number of formals; otherwise the names are compared as written.
    names = [declaration_param_names(decl, path=rel) for rel, decl, _contract in base]
    unified = len({len(n) for n in names}) == 1
    formals = [{name: f"${k}" for k, name in enumerate(n)} if unified else {} for n in names]
    pooled_base = _pooled_clauses(base, formals)
    pooled_cand = _pooled_clauses(cand, formals)

    result["formals_unified"] = unified
    for side, decls in (("baseline", base), ("candidate", cand)):
        result["declarations"][side] = [
            {"file": rel, "kind": decl.kind, "clauses": len(contract["clauses"])} for rel, decl, contract in decls
        ]
    result["had_contract"] = any(c["clauses"] or c["behaviors"] or c["completeness"] for _r, _d, c in base)
    result["has_contract"] = any(c["clauses"] or c["behaviors"] or c["completeness"] for _r, _d, c in cand)
    for name in dict.fromkeys([*pooled_base, *pooled_cand]):
        in_base, in_cand = pooled_base.get(name), pooled_cand.get(name)
        kinds = dict.fromkeys([*CONTRACT_CLAUSE_KINDS, *sorted({*(in_base or {}), *(in_cand or {})})])
        entry: dict = {
            "in_baseline": bool(in_base) if name == DEFAULT_BEHAVIOR else in_base is not None,
            "in_candidate": bool(in_cand) if name == DEFAULT_BEHAVIOR else in_cand is not None,
        }
        for kind in kinds:
            delta = _assigns_delta if kind == "assigns" else _clause_delta
            entry[kind] = delta((in_base or {}).get(kind, []), (in_cand or {}).get(kind, []))
        result["behaviors"][name] = entry
    completeness: list[list[tuple[str, str, list[str]]]] = [
        [(_norm_clause(text), text, []) for _r, _d, c in decls for text in c["completeness"]] for decls in (base, cand)
    ]
    result["completeness"] = _clause_delta(completeness[0], completeness[1])
    behaviors = result["behaviors"]
    result["summary"] = {
        "assigns_removed_in": [n for n, e in behaviors.items() if e["assigns"]["status"] == "removed"],
        "ensures_removed_in": [n for n, e in behaviors.items() if e["ensures"]["removed"]],
        "behaviors_removed": [n for n, e in behaviors.items() if e["in_baseline"] and not e["in_candidate"]],
    }


def compare_function_contracts(baseline: Mapping[str, str], candidate: Mapping[str, str], function: str) -> dict:
    """
    What a candidate changed in the contract of `function`, clause by clause: text in, data out.

    `baseline` and `candidate` map a file name to the whole text of that file, before and after. Both must
    hold the same files: every file that can carry the contract (the source, the declaring header), the
    unchanged ones included, or a contract in a file left out reads as absent on both sides. The function's
    contract is the contract in front of every declaration of it in those files, prototypes and definition
    (`function_declaration_spans`), pooled behavior by behavior as Frama-C merges them. So a clause moved from
    the prototype to the definition is not removed, and a clause written on both is removed only when both
    copies go. Annotations inside the body are not part of the contract.

    Never raises. The result is JSON-serialisable and always has these keys:

    - `available` (bool), `reason` (str): False with the reason when there is no comparison: the two sides
      hold different files, the function is declared in neither side's text, a text does not tokenize
      (`reason` carries the tokenizer's `file:line: unclosed ...`), or the declarations themselves differ
      (a declaration added or removed, or its C tokens changed). Every other key then has its empty value.
      A function declared without any contract IS a comparison (`had_contract` False).
    - `function`; `declarations`: `{"baseline": [...], "candidate": [...]}`, one
      `{"file", "kind": "prototype" | "definition", "clauses": <count>}` per declaration.
    - `had_contract`, `has_contract` (bool): the baseline / candidate has at least one contract clause.
    - `formals_unified` (bool): True when every declaration names the same number of formals; clauses are
      then compared with formals by position (the header may say `reg_addr` where the definition says
      `addr`). False: an unnamed formal somewhere, names compared as written.
    - `behaviors`: `{name: entry}`, the default behavior first under `DEFAULT_BEHAVIOR` (`"default!"`, always
      present), then each named behavior in order of first appearance. An entry has `in_baseline` and
      `in_candidate` (for the default behavior: it has a clause there) and one value per clause kind of
      `CONTRACT_CLAUSE_KINDS` (plus any other kind met):
        - every kind but `assigns`: `{"baseline": [text], "candidate": [text], "removed": [text],
          "added": [text]}`. `removed` are the baseline clauses no candidate clause of the same behavior
          and kind equals, `added` the reverse, once each.
        - `assigns`: the same four keys, where `baseline` and `candidate` hold
          `{"text", "locs": [...], "from": [...], "from_nothing": bool}` per clause, plus
          `status`: `"none"` (no assigns clause on either side), `"removed"` (had one, has none),
          `"added"`, `"same"` or `"changed"` (both have one and they differ: narrowed, widened or
          rewritten), and `locations_removed` / `locations_added`: the locations listed on one side only,
          whatever their `\\from`.
    - `completeness`: the four keys again, for `complete behaviors ...` / `disjoint behaviors ...`.
    - `summary`: `assigns_removed_in` (behaviors whose `assigns` status is `"removed"`),
      `ensures_removed_in` (behaviors with a removed `ensures`), `behaviors_removed` (named behaviors the
      candidate no longer has).

    How clauses are compared. Two clauses are equal when their text is, with the clause label dropped,
    comments and `@` left out as the kernel does (`iter_clauses`), white space ignored, outer parentheses
    ignored (not for `assigns`), and formals by position. For `assigns`, the order of the locations and of
    the `\\from` sources is ignored too, and the `\\from` part belongs to the clause: `assigns x \\from a;`
    against `assigns x;` is `"changed"` with no location removed. `check` and `admit` clauses are kept apart
    from plain ones (`ensures P;` replaced by `check ensures P;` removes `P` and adds `check P`).

    What is not judged. Nothing here says whether a change weakens the contract. `requires`, `assumes`,
    `terminates`, `exits`, `decreases`, `allocates` and `frees` are reported exactly like `ensures` (a
    removed `requires` strengthens the contract for callers, a removed `assumes` widens its behavior; the
    caller decides). An `assigns` clause is not matched semantically (`*ctx` against `ctx->debug` is one
    location removed and one added), and a named behavior without `assigns` is reported `"removed"` or
    `"none"` although the default behavior's clause still frames it.
    """
    result = _empty_contract_comparison(function)
    try:
        _compare_contracts(result, baseline, candidate, function)
    except _NoComparison as exc:
        reason = str(exc)
    except Exception as exc:  # text this cannot parse must give a result, not an exception: the gate decides
        reason = f"{type(exc).__name__}: {exc}"
    else:
        result["available"] = True
        return result
    return {**_empty_contract_comparison(function), "reason": reason}


_COMPLETE_BEHAVIORS_RE = re.compile(r"^complete\s+behaviors(?:\s+(.*))?$")


def contract_has_whole_frame(comparison: Mapping[str, object], side: str) -> bool:
    """
    Whether `side` (`"baseline"` or `"candidate"`) of a `compare_function_contracts` result frames
    the whole function: either the default behavior (`DEFAULT_BEHAVIOR`) has an `assigns` clause,
    or a `complete behaviors` clause covers a non-empty set of named behaviors (all named behaviors
    when no explicit list is given) and every behavior in that set has an `assigns` clause.
    """
    if not comparison.get("available"):
        return False
    raw_behaviors = comparison.get("behaviors")
    if not isinstance(raw_behaviors, Mapping):
        return False
    default = raw_behaviors.get(DEFAULT_BEHAVIOR)
    if isinstance(default, Mapping):
        default_assigns = default.get("assigns")
        if isinstance(default_assigns, Mapping) and default_assigns.get(side):
            return True
    in_side_key = f"in_{side}"
    named: list[str] = []
    assigns_in: set[str] = set()
    for name, entry in raw_behaviors.items():
        if name == DEFAULT_BEHAVIOR or not isinstance(entry, Mapping):
            continue
        if entry.get(in_side_key):
            named.append(str(name))
        assigns = entry.get("assigns")
        if isinstance(assigns, Mapping) and assigns.get(side):
            assigns_in.add(str(name))
    raw_comp = comparison.get("completeness")
    clauses = raw_comp.get(side) if isinstance(raw_comp, Mapping) else None
    if not isinstance(clauses, list):
        return False
    for clause in clauses:
        if not isinstance(clause, str):
            continue
        m = _COMPLETE_BEHAVIORS_RE.match(" ".join(clause.split()))
        if m is None:
            continue
        rest = (m.group(1) or "").strip()
        bset = [part.strip() for part in rest.split(",") if part.strip()] if rest else named
        if bset and all(name in assigns_in for name in bset):
            return True
    return False
