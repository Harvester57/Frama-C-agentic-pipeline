#!/usr/bin/env python3
"""
Convert the Frama-C reference manuals under docs/references/ into greppable Markdown.

Host-side maintenance tool; it is not used inside the container. Converting
needs poppler's ``pdftotext`` on PATH and the ``pypdf`` package (for the PDF
bookmarks); ``--check`` needs neither.

For every ``docs/references/<tool>/<name>.pdf`` it writes ``<name>.md`` next to it:

- page text from ``pdftotext -layout`` (code listings keep their indentation),
  with running headers, page-number footers and table-of-contents leader lines
  removed, and typographic quotes, dashes and minus signs folded to ASCII so
  that ``grep -- '-wp-timeout'`` or ``grep "'swap'"`` match;
- a ``<!-- page N -->`` marker before each page (N is the physical PDF page,
  the number the Read tool's ``pages`` argument expects);
- one Markdown heading per PDF bookmark (depth 0 -> ``##``, 1 -> ``###``,
  2 -> ``####``), so ``grep -n '^#' <name>.md`` prints the outline with line
  numbers. Body lines that start with ``#`` (shell prompts, ``#include``) are
  indented by one space to keep that grep exact.

It also writes ``docs/references/INDEX.md``: one line per section of every
manual, ``<tool>/<name>.md:<first>-<last>  <title>  (p. N)``, indented by
depth. It is meant to be grepped for a topic, not read whole.

The outputs are deterministic and carry the SHA-256 of their source PDF;
``--check`` fails when a PDF has no Markdown, the Markdown is stale, or a
generated Markdown file has lost its PDF (converting deletes such orphans).
"""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

DEFAULT_ROOT = Path(__file__).resolve().parent.parent / "docs" / "references"
INDEX_NAME = "INDEX.md"
GENERATOR = "scripts/extract_references.py"

_HASH_RE = re.compile(r"<!-- source: (?P<pdf>\S+) sha256:(?P<sha>[0-9a-f]{64}) ")

# Typographic characters that break plain-ASCII greps for options, code and quotes.
_ASCII_FOLD = str.maketrans({
    "‘": "'", "’": "'", "′": "'",
    "“": '"', "”": '"',
    "–": "-", "−": "-",
    "∗": "*",
    "…": "...",
    " ": " ",
    "ﬁ": "fi", "ﬂ": "fl", "ﬀ": "ff", "ﬃ": "ffi", "ﬄ": "ffl",
    "": None,  # private-use brace fragment emitted for multi-line math
})

_TOC_LEADER_RE = re.compile(r"(?:\s?\.){4,}\s*\d+\s*$")
_PAGE_NUMBER_RE = re.compile(r"^\s*(?:\d+|[ivxlcdm]+)\s*$", re.IGNORECASE)
# LaTeX running headers: "2.4. COMMAND LINE OPTIONS", "CHAPTER 3. KNOWN LIMITATIONS", "A.1. CHANGES", "CONTENTS".
_RUNNING_HEADER_RE = re.compile(
    r"^(?:(?:CHAPTER|APPENDIX)\s+[A-Z0-9]+\.\s+|[A-Z0-9]+(?:\.[0-9]+)*\.\s+)[^a-z]+$"
    r"|^(?:CONTENTS|BIBLIOGRAPHY|INDEX|LIST OF (?:FIGURES|TABLES|LISTINGS))$"
)
_SECTION_NUMBER_RE = re.compile(r"^(?:[A-Z]|\d+)(?:\.\d+)*\.?\s+")
_CHAPTER_NUMBER_RE = re.compile(r"^([A-Z]|\d+)\s+\S")
_CHAPTER_LINE_RE = re.compile(r"^\s*(?:chapter|appendix)\s+[A-Z0-9]+\s*$", re.IGNORECASE)
# Bookmarks of unnumbered back matter (Bibliography, Index) can point a few pages before the heading.
_MAX_FORWARD_PAGES = 5


@dataclass
class Section:
    title: str
    depth: int
    page: int  # 1-based physical PDF page
    line: int = 0  # 1-based line of the heading in the generated Markdown
    end: int = 0  # last line of the section (before the next heading of same or lower depth)


def fold_ascii(text: str) -> str:
    return text.translate(_ASCII_FOLD)


def _norm(text: str) -> str:
    return re.sub(r"[\s.]+$", "", re.sub(r"\s+", " ", text).strip()).lower()


def _strip_number(text: str) -> str:
    return _SECTION_NUMBER_RE.sub("", text, count=1)


def clean_page(text: str, *, first_page: bool = False) -> list[str]:
    """Return the page's lines without running header, page-number footer and TOC leader lines."""
    lines = [line.rstrip() for line in fold_ascii(text).splitlines()]
    nonblank = [i for i, line in enumerate(lines) if line.strip()]
    drop: set[int] = set()
    if nonblank and _PAGE_NUMBER_RE.match(lines[nonblank[-1]]):
        drop.add(nonblank[-1])
    if nonblank and not first_page and _RUNNING_HEADER_RE.match(lines[nonblank[0]].strip()):
        drop.add(nonblank[0])
    kept = [line for i, line in enumerate(lines) if i not in drop and not _TOC_LEADER_RE.search(line)]
    # Shell prompts and preprocessor lines must not look like Markdown headings.
    return [" " + line if line.startswith("#") else line for line in kept]


def _heading_matches(line: str, title: str, *, columns: bool = False) -> bool:
    if columns:  # two-column pages (Index): "Index        contract, 24, 32"
        return any(_heading_matches(col, title) for col in re.split(r"\s{3,}", line.strip()))
    text = _norm(line)
    if not text:
        return False
    full = _norm(title)
    bare = _norm(_strip_number(title))
    if text in (full, bare) or _norm(_strip_number(line)) == bare:
        return True
    # Book-class chapter titles put the number after the title: "Introduction     1", "Appendices  A".
    chapter = _CHAPTER_NUMBER_RE.match(title)
    if chapter and text == f"{bare} {chapter.group(1).lower()}":
        return True
    # A long title wrapped over two lines: the first line is a prefix of the title.
    return len(text) >= 20 and (full.startswith(text) or bare.startswith(text))


def _locate(pages: list[list[str]], page: int, title: str, start: int, last_page: int) -> tuple[int, int] | None:
    """Return (page, line index) of a section heading, or None when it is not found.

    Searches the bookmark ``page`` from line ``start``, then the first lines of
    that page and of up to ``_MAX_FORWARD_PAGES`` following pages (never past
    ``last_page``) column by column.
    """
    if not 0 < page <= len(pages):
        return None
    lines = pages[page - 1]
    hit = next((i for i in range(start, len(lines)) if _heading_matches(lines[i], title)), None)
    if hit is not None:
        return page, hit
    for candidate in range(page, min(page + _MAX_FORWARD_PAGES, last_page, len(pages)) + 1):
        lines = pages[candidate - 1]
        head = [i for i, line in enumerate(lines) if line.strip()][:3]
        hit = next((i for i in head if i >= (start if candidate == page else 0)
                    and _heading_matches(lines[i], title, columns=True)), None)
        if hit is not None:
            return candidate, hit
    return None


def place_headings(pages: list[list[str]], sections: list[Section]) -> tuple[list[str], int]:
    """Interleave page markers and headings with the page text.

    Each heading replaces the first matching line on its page, searching after
    the previous heading so that the outline order is kept. A heading that is
    not found is inserted at its bookmark page, after the previous heading when
    that one is on the same page. ``Section.page`` is updated to the page the
    heading was found on. Returns the lines and the number of misses.
    """
    replaced: dict[tuple[int, int], Section] = {}
    inserted: dict[tuple[int, int], list[Section]] = {}  # headings emitted before (page, line index)
    misses = 0
    cursor = (0, 0)  # (page, next line index) after the previous heading
    for n, sec in enumerate(sections):
        page = max(sec.page, cursor[0])
        start = cursor[1] if cursor[0] == page else 0
        last_page = max(sections[n + 1].page if n + 1 < len(sections) else len(pages), page)
        found = _locate(pages, page, sec.title, start, last_page)
        if found is None:
            misses += 1
            sec.page = page
            inserted.setdefault((page, start), []).append(sec)
            cursor = (page, start)
            continue
        sec.page, hit = found
        replaced[found] = sec
        cursor = (sec.page, hit + 1)

    out: list[str] = []
    for page_no, lines in enumerate(pages, start=1):
        out.extend(["", f"<!-- page {page_no} -->", ""])
        for i in range(len(lines) + 1):
            for sec in inserted.get((page_no, i), []):
                sec.line = len(out) + 1
                out.extend([_heading(sec), ""])
            if i == len(lines):
                break
            heading = replaced.get((page_no, i))
            if heading is None:
                out.append(lines[i])
                continue
            prev = next((k for k in range(len(out) - 1, -1, -1) if out[k].strip()), None)
            if heading.depth == 0 and prev is not None and _CHAPTER_LINE_RE.match(out[prev]):
                del out[prev:]  # "Appendix A" line above the chapter title
                out.append("")
            heading.line = len(out) + 1
            out.append(_heading(heading))
    return _squeeze_blank(out, sections), misses


def _heading(sec: Section) -> str:
    return "#" * min(sec.depth + 2, 4) + " " + sec.title


def _squeeze_blank(lines: list[str], sections: list[Section]) -> list[str]:
    """Collapse blank-line runs to one blank line and renumber the section lines accordingly."""
    out: list[str] = []
    new_line: dict[int, int] = {}
    for old, line in enumerate(lines, start=1):
        if not line.strip() and (not out or not out[-1]):
            new_line[old] = len(out)
            continue
        out.append(line if line.strip() else "")
        new_line[old] = len(out)
    for sec in sections:
        sec.line = new_line.get(sec.line, sec.line)
    while out and not out[-1]:
        out.pop()
    return out


def assign_ends(sections: list[Section], total_lines: int) -> None:
    ordered = sorted(sections, key=lambda s: s.line)
    for i, sec in enumerate(ordered):
        nxt = next((s.line for s in ordered[i + 1:] if s.depth <= sec.depth), total_lines + 1)
        sec.end = nxt - 1


def read_outline(pdf: Path) -> list[Section]:
    try:
        from pypdf import PdfReader
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise SystemExit("extract_references.py: converting needs the 'pypdf' package (pip install pypdf)") from exc
    reader = PdfReader(str(pdf))
    sections: list[Section] = []

    def walk(items: list, depth: int) -> None:
        for item in items:
            if isinstance(item, list):
                walk(item, depth + 1)
                continue
            try:
                index = reader.get_destination_page_number(item)
            except Exception:  # noqa: BLE001 - malformed bookmark, skip it
                continue
            title = fold_ascii(re.sub(r"\s+", " ", str(item.title)).strip())
            if title and index is not None and index >= 0:
                sections.append(Section(title=title, depth=depth, page=index + 1))

    walk(reader.outline, 0)
    return sections


def read_pages(pdf: Path) -> list[str]:
    exe = shutil.which("pdftotext")
    if exe is None:  # pragma: no cover - environment dependent
        raise SystemExit("extract_references.py: converting needs poppler's 'pdftotext' on PATH")
    proc = subprocess.run([exe, "-enc", "UTF-8", "-layout", str(pdf), "-"], capture_output=True, check=True)
    pages = proc.stdout.decode("utf-8", errors="replace").split("\f")
    if pages and not pages[-1].strip():
        pages.pop()
    return pages


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _doc_title(first_page: list[str]) -> str:
    """Title-page lines up to the version line ("For Frama-C 33.0", "Version 1.24 ..."), without authors."""
    lines = [re.sub(r"\s+", " ", line).strip() for line in first_page if line.strip()][:3]
    versioned = [n for n, line in enumerate(lines) if re.search(r"\b(?:Version|For Frama-C|Implementation in)\b", line)]
    if versioned:
        return " ".join(lines[: versioned[-1] + 1])
    return lines[0] if lines else "Untitled"


def convert(pdf: Path, root: Path) -> tuple[Path, list[Section], int]:
    raw_pages = read_pages(pdf)
    pages = [clean_page(text, first_page=(i == 0)) for i, text in enumerate(raw_pages)]
    sections = read_outline(pdf)
    body, misses = place_headings(pages, sections)
    rel_pdf = pdf.relative_to(root).as_posix()
    header = [
        f"# {_doc_title(pages[0] if pages else [])}",
        "",
        f"<!-- source: {rel_pdf} sha256:{sha256(pdf)} pages:{len(raw_pages)} -->",
        f"<!-- generated by {GENERATOR}; do not edit. Outline: grep -n '^#' this file. -->",
    ]
    offset = len(header)
    for sec in sections:
        sec.line += offset
    lines = header + body
    assign_ends(sections, len(lines))
    out = pdf.with_suffix(".md")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return out, sections, misses


def render_index(entries: list[tuple[str, str, list[Section]]]) -> str:
    out = [
        "# Reference manual section index",
        "",
        f"<!-- generated by {GENERATOR}; do not edit. -->",
        "",
        "Grep this file for a topic; do not read it whole. Each line is",
        "`<path>:<first>-<last>  <section title>  (p. <pdf page>)`, with paths relative to",
        "`docs/references/`. Read that line range of the Markdown file (Read with",
        "`offset=<first>` and `limit=<last>-<first>+1`, at most ~200 lines at a time).",
    ]
    for md_rel, title, sections in entries:
        out.extend(["", f"## {md_rel}: {title}", ""])
        for sec in sorted(sections, key=lambda s: s.line):
            loc = f"{md_rel}:{sec.line}-{sec.end}"
            out.append(f"{loc:<48}{'  ' * sec.depth}{sec.title}  (p. {sec.page})")
    return "\n".join(out) + "\n"


def find_pdfs(root: Path) -> list[Path]:
    return sorted(root.glob("*/*.pdf"))


def _source_hash(md: Path) -> str | None:
    """SHA-256 recorded in a generated Markdown file, or None when the file was not generated by this tool."""
    with md.open(encoding="utf-8") as fh:
        head = "".join(fh.readline() for _ in range(5))
    m = _HASH_RE.search(head)
    return m.group("sha") if m else None


def orphan_outputs(root: Path) -> list[Path]:
    """Generated Markdown files whose PDF was moved or deleted."""
    return [md for md in sorted(root.glob("*/*.md"))
            if not md.with_suffix(".pdf").is_file() and _source_hash(md) is not None]


def stale_outputs(root: Path) -> list[str]:
    """Return a description of every PDF whose Markdown is missing or stale, and of every orphaned Markdown."""
    problems: list[str] = []
    for pdf in find_pdfs(root):
        md = pdf.with_suffix(".md")
        if not md.is_file():
            problems.append(f"{pdf.relative_to(root).as_posix()}: missing {md.name}")
        elif _source_hash(md) != sha256(pdf):
            problems.append(f"{pdf.relative_to(root).as_posix()}: {md.name} is stale")
    for md in orphan_outputs(root):
        problems.append(f"{md.relative_to(root).as_posix()}: orphan, its PDF was moved or deleted")
    if find_pdfs(root) and not (root / INDEX_NAME).is_file():
        problems.append(f"missing {INDEX_NAME}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT, help="references directory (default: docs/references)")
    parser.add_argument("--check", action="store_true", help="only verify that every PDF has an up-to-date .md")
    args = parser.parse_args(argv)
    root: Path = args.root.resolve()

    if args.check:
        problems = stale_outputs(root)
        for problem in problems:
            print(problem, file=sys.stderr)
        if problems:
            print(f"run: python {GENERATOR}", file=sys.stderr)
        return 1 if problems else 0

    for md in orphan_outputs(root):
        md.unlink()
        print(f"{md.relative_to(root).as_posix()}: removed (its PDF was moved or deleted)")
    entries: list[tuple[str, str, list[Section]]] = []
    for pdf in find_pdfs(root):
        md, sections, misses = convert(pdf, root)
        title = md.read_text(encoding="utf-8").splitlines()[0].removeprefix("# ")
        entries.append((md.relative_to(root).as_posix(), title, sections))
        note = f", {misses} heading(s) placed at page top" if misses else ""
        print(f"{md.relative_to(root).as_posix()}: {len(sections)} sections{note}")
    (root / INDEX_NAME).write_text(render_index(entries), encoding="utf-8", newline="\n")
    print(f"{INDEX_NAME}: {sum(len(s) for _, _, s in entries)} entries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
