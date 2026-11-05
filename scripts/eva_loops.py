#!/usr/bin/env python3
"""
Per-loop unrolling for Eva, on a scratch mirror of the sources (stdlib only).

A kept `loop unroll` annotation is a tuning decision, not a change to the target, so it never goes
into workspace/work: that would reach the E-ACSL builds and every proof, and invalidate their cache
keys. Instead each annotated run gets a mirror of the module's include closure with the annotations
inserted, and the report's paths are mapped back to the originals.

- An annotation is written on the loop's own line (`/*@ loop unroll N; */ for ...`), so line numbers,
  and with them the identity of every obligation, stay the same as in the unannotated run. A loop with
  an annotation already gets the clause inside it, first: the kernel rejects a second annotation comment
  on a loop, and a `loop unroll` after `loop variant`, but accepts it first in all forms (tried on this
  image: invariants, assigns, variants, `for b:`, block and line comments).
- A loop is named by (file, function, ordinal of its keyword in the function), not by its line, so a
  recorded decision still applies after ACSL lands above it.
- The Eva manual (section 6.4.1) states that the unrolling level never affects correctness, only
  precision and cost, so an annotated run is a tuning variant of the same analysis.
"""

from __future__ import annotations

import hashlib
import os
import re
import shlex
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import cache
from acsl_ast import AcslSyntaxError, Token, locate_function_span, tokenize_c_acsl
from framac_common import is_safe_relative_path

MAX_LOOP_UNROLL = 1_000_000
_LOOP_FILE_RE = re.compile(r"[^-#=\s][^#=\s]*")
_LOOP_REF_RE = re.compile(r"^(?P<file>[^#=\s]+)#(?P<function>[A-Za-z_][A-Za-z0-9_]*)#(?P<ordinal>\d+)=(?P<unroll>\d+)$")
_LOOP_KEYWORDS = ("for", "while", "do")
_LOOP_ANNOTATION_RE = re.compile(r"(?:/\*@|//@)\s*(?:for\b[^:]*:\s*)?loop\b")
_SKIPPED_KINDS = ("whitespace", "c_comment", "pp_directive")
# Flags whose value is a path; the same list resolve includes for cache.preprocessor_args.
_PATH_FLAGS_SEPARATE = ("-I", "-include", "-imacros", "-isystem", "-iquote", "-idirafter")
_PATH_FLAGS_JOINED = ("-include", "-imacros", "-isystem", "-iquote", "-idirafter", "-I")
_RUN_DIR_PREFIX = "/framac-run/"
_MIRRORED_TREE = "workspace/"


@dataclass(frozen=True, order=True)
class LoopRef:
    """One loop to unroll: the `ordinal`-th loop keyword of `function` in the run-relative `file`."""

    file: str
    function: str
    ordinal: int
    unroll: int

    def to_arg(self) -> str:
        return f"{self.file}#{self.function}#{self.ordinal}={self.unroll}"

    def to_json(self) -> dict:
        return {"file": self.file, "function": self.function, "ordinal": self.ordinal, "unroll": self.unroll}


def loop_ref_problem(file: object, function: object, ordinal: object, unroll: object) -> str | None:
    if not isinstance(file, str) or not is_safe_relative_path(file) or not _LOOP_FILE_RE.fullmatch(file):
        return f"file {file!r} must be a safe run-relative path a loop reference can name"
    if not isinstance(function, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", function):
        return f"function {function!r} must be a C identifier"
    if isinstance(ordinal, bool) or not isinstance(ordinal, int) or ordinal < 0:
        return f"ordinal {ordinal!r} must be a non-negative integer"
    if isinstance(unroll, bool) or not isinstance(unroll, int) or not 0 <= unroll <= MAX_LOOP_UNROLL:
        return f"unroll {unroll!r} must be between 0 and {MAX_LOOP_UNROLL}"
    return None


def parse_loop_ref(text: str) -> LoopRef:
    """`file#function#ordinal=N` from a command line. ValueError on anything else."""
    m = _LOOP_REF_RE.match(text or "")
    if not m:
        raise ValueError(f"{text!r} is not of the form file#function#ordinal=N")
    ref = LoopRef(m["file"], m["function"], int(m["ordinal"]), int(m["unroll"]))
    problem = loop_ref_problem(ref.file, ref.function, ref.ordinal, ref.unroll)
    if problem:
        raise ValueError(problem)
    return ref


def loop_ref_from_json(item: object) -> LoopRef:
    if not isinstance(item, dict):
        raise ValueError(f"expected an object describing a loop, got {item!r}")
    problem = loop_ref_problem(item.get("file"), item.get("function"), item.get("ordinal"), item.get("unroll"))
    if problem:
        raise ValueError(problem)
    return LoopRef(str(item["file"]), str(item["function"]), int(item["ordinal"]), int(item["unroll"]))


# ---------------------------------------------------------------------------
# Finding loops
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LoopSite:
    ordinal: int
    keyword: str
    line: int
    offset: int
    end_offset: int  # end of the loop's body, for nesting
    parent: int | None  # ordinal of the closest enclosing loop
    annotated: bool  # already carries a `loop unroll`, which must not be overridden
    annotation_at: int | None = None  # where a clause joins the loop's existing annotation, if it has one


def _next_code(tokens: list[Token], idx: int) -> int:
    while idx < len(tokens) and (tokens[idx].kind in _SKIPPED_KINDS or tokens[idx].kind.startswith("acsl")):
        idx += 1
    return idx


def _match_delim(tokens: list[Token], open_idx: int, open_ch: str, close_ch: str) -> int:
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
    return len(tokens) - 1


def _statement_end(tokens: list[Token], idx: int) -> int:
    """Index of the token ending the statement that starts at `idx` (approximate for `if`/`else` chains)."""
    idx = _next_code(tokens, idx)
    if idx >= len(tokens):
        return len(tokens) - 1
    if tokens[idx].text == "{":
        return _match_delim(tokens, idx, "{", "}")
    parens = 0
    for i in range(idx, len(tokens)):
        tok = tokens[i]
        if tok.kind != "c_token":
            continue
        if tok.text == "(":
            parens += 1
        elif tok.text == ")":
            parens -= 1
        elif tok.text == "{" and parens == 0:
            return _match_delim(tokens, i, "{", "}")
        elif tok.text == ";" and parens == 0:
            return i
    return len(tokens) - 1


def _has_unroll_annotation(tokens: list[Token], idx: int) -> bool:
    i = idx - 1
    while i >= 0 and tokens[i].kind in ("whitespace", "c_comment", "acsl_block", "acsl_line"):
        if tokens[i].kind.startswith("acsl") and "loop unroll" in tokens[i].text:
            return True
        i -= 1
    return False


def _existing_annotation_at(tokens: list[Token], idx: int) -> int | None:
    """Where a clause goes in the loop annotation right before token `idx`: just after its `/*@` or `//@`."""
    i = idx - 1
    while i >= 0 and tokens[i].kind in ("whitespace", "c_comment"):
        i -= 1
    if i >= 0 and tokens[i].kind.startswith("acsl") and _LOOP_ANNOTATION_RE.match(tokens[i].text):
        return tokens[i].start + 3
    return None


def find_loops(source: str, function: str, path: str = "<input>") -> list[LoopSite]:
    """The loops of `function`'s definition, in source order; empty when it has no definition here."""
    try:
        span = locate_function_span(source, function, is_header=False, path=path)
        tokens = tokenize_c_acsl(source, path=path)
    except AcslSyntaxError:
        return []
    if span is None:
        return []
    do_tails: set[int] = set()
    found: list[tuple[int, Token, int]] = []
    for idx, tok in enumerate(tokens):
        if tok.kind != "c_token" or not span.start_byte <= tok.start < span.end_byte:
            continue
        if tok.text not in _LOOP_KEYWORDS or idx in do_tails:
            continue
        if tok.text == "do":
            end = _statement_end(tokens, idx + 1)
            tail = _next_code(tokens, end + 1)
            if tail < len(tokens) and tokens[tail].text == "while":
                do_tails.add(tail)
            found.append((idx, tok, tokens[end].end))
            continue
        open_paren = _next_code(tokens, idx + 1)
        if open_paren >= len(tokens) or tokens[open_paren].text != "(":
            continue
        close_paren = _match_delim(tokens, open_paren, "(", ")")
        end = _statement_end(tokens, close_paren + 1)
        found.append((idx, tok, tokens[end].end))
    sites: list[LoopSite] = []
    for ordinal, (idx, tok, end_offset) in enumerate(found):
        parent = None
        for site in reversed(sites):
            if site.offset < tok.start < site.end_offset:
                parent = site.ordinal
                break
        sites.append(
            LoopSite(
                ordinal=ordinal,
                keyword=tok.text,
                line=tok.line,
                offset=tok.start,
                end_offset=end_offset,
                parent=parent,
                annotated=_has_unroll_annotation(tokens, idx),
                annotation_at=_existing_annotation_at(tokens, idx),
            )
        )
    return sites


def loop_nests(sites: list[LoopSite]) -> list[list[LoopSite]]:
    """Each top-level loop with the loops inside it: nested loops only help when unrolled together."""
    nests: dict[int, list[LoopSite]] = {}
    roots: dict[int, int] = {}
    for site in sites:
        root = roots[site.parent] if site.parent is not None else site.ordinal
        roots[site.ordinal] = root
        nests.setdefault(root, []).append(site)
    return [nests[root] for root in sorted(nests)]


# ---------------------------------------------------------------------------
# Annotating a mirror of the sources
# ---------------------------------------------------------------------------


def annotate_source(
    source: str, refs: Iterable[LoopRef], path: str = "<input>"
) -> tuple[str, list[LoopRef], list[LoopRef]]:
    """`source` with `refs` annotated on their loops' lines, then the refs applied and those not found."""
    inserts: list[tuple[int, str]] = []
    applied: list[LoopRef] = []
    dropped: list[LoopRef] = []
    by_function: dict[str, dict[int, LoopSite]] = {}
    for ref in sorted(set(refs)):
        sites = by_function.setdefault(ref.function, {s.ordinal: s for s in find_loops(source, ref.function, path)})
        site = sites.get(ref.ordinal)
        if site is None or site.annotated:
            dropped.append(ref)
            continue
        if site.annotation_at is not None:
            inserts.append((site.annotation_at, f" loop unroll {ref.unroll};"))
        else:
            inserts.append((site.offset, f"/*@ loop unroll {ref.unroll}; */ "))
        applied.append(ref)
    for offset, text in sorted(inserts, reverse=True):
        source = source[:offset] + text + source[offset:]
    return source, applied, dropped


def mirror_id(refs: Iterable[LoopRef]) -> str:
    """A short name fixed by the annotation set, so the same set always gets the same mirror and cache key."""
    blob = "\n".join(ref.to_arg() for ref in sorted(set(refs)))
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def _run_relative(path: str) -> str | None:
    """`path` relative to the run directory when it lies inside the mirrored tree, else None."""
    text = path.replace("\\", "/")
    if text.startswith(_RUN_DIR_PREFIX):
        text = text[len(_RUN_DIR_PREFIX) :]
    if text.startswith("/"):
        return None
    text = os.path.normpath(text).replace("\\", "/")
    return text if text.startswith(_MIRRORED_TREE) else None


def _mirror_path(value: str, root: str) -> str:
    if value == ".":
        return root
    rel = _run_relative(value)
    return f"{root}/{rel}" if rel is not None else value


def mirror_flags(tokens: list[str], root: str) -> list[str]:
    """Preprocessor flags with every path into the run's tree redirected to the mirror at `root`."""
    out: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in _PATH_FLAGS_SEPARATE and i + 1 < len(tokens):
            out.extend([tok, _mirror_path(tokens[i + 1], root)])
            i += 2
            continue
        for flag in _PATH_FLAGS_JOINED:
            if tok.startswith(flag) and len(tok) > len(flag):
                tok = flag + _mirror_path(tok[len(flag) :], root)
                break
        out.append(tok)
        i += 1
    return out


def _write_if_changed(path: Path, data: bytes) -> None:
    try:
        if path.read_bytes() == data:
            return
    except OSError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".tmp-{os.getpid()}-{path.name}")
    tmp.write_bytes(data)
    os.replace(tmp, path)


@dataclass(frozen=True)
class Mirror:
    root: str
    sources: list[str]
    cppflags: str
    applied: list[LoopRef]
    dropped: list[LoopRef]


def prepare_mirror(
    mirror_root: str,
    sources: list[str],
    cppflags: str,
    dep_flags: list[str],
    refs: Iterable[LoopRef],
    runner=None,
) -> Mirror | None:
    """
    Copy the include closure of `sources` inside the run's tree to `mirror_root`, keeping relative
    paths, with `refs` annotated. None when the closure cannot be computed.
    """
    manifest = cache.dependency_manifest(sources, dep_flags, runner=runner)
    if manifest is None:
        return None
    root = mirror_root.rstrip("/")
    by_file: dict[str, list[LoopRef]] = {}
    for ref in refs:
        by_file.setdefault(os.path.normpath(ref.file).replace("\\", "/"), []).append(ref)
    applied: list[LoopRef] = []
    dropped: list[LoopRef] = []
    seen: set[str] = set()
    for dep, digest in manifest:
        rel = _run_relative(dep)
        if rel is None or digest == "missing" or rel in seen or PurePosixPath(rel).is_relative_to(root):
            continue
        seen.add(rel)
        data = Path(rel).read_bytes()
        if rel in by_file:
            text, done, missing = annotate_source(data.decode("utf-8", "surrogateescape"), by_file[rel], rel)
            data = text.encode("utf-8", "surrogateescape")
            applied.extend(done)
            dropped.extend(missing)
        _write_if_changed(Path(root) / rel, data)
    for file, group in by_file.items():
        if file not in seen:
            dropped.extend(group)
    mirrored_sources = [_mirror_path(src, root) for src in sources]
    return Mirror(
        root=root,
        sources=mirrored_sources,
        cppflags=shlex.join(mirror_flags(shlex.split(cppflags), root)),
        applied=sorted(applied),
        dropped=sorted(dropped),
    )


def strip_mirror(directory: str, root: str | None) -> str:
    """A report's `directory` column with the mirror's prefix removed."""
    if not root:
        return directory
    text = directory.replace("\\", "/")
    if text == root:
        return "."
    return text[len(root) + 1 :] if text.startswith(root + "/") else directory
