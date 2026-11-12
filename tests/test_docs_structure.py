"""Structural and link-integrity guardrails for docs/ (see docs/AGENTS.md)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from conftest import ROOT

DOCS_DIR = ROOT / "docs"
REQUIRED_DOCS_ROOT_FILES = frozenset({"README.md", "AGENTS.md"})
REQUIRED_DOCS_CATEGORIES = frozenset(
    {
        "guides",
        "troubleshooting",
        "plans",
        "runs",
        "bugs-found",
        "upstream",
        "references",
    }
)
OPTIONAL_GITIGNORED_DIRS = frozenset({"papers", "lessons"})
REQUIRED_SUBDIR_READMES = (
    "upstream/frama-c/README.md",
    "upstream/qcbor/README.md",
    "upstream/sources/README.md",
)
INLINE_CODE_RE = re.compile(r"`[^`\n]+`")
MARKDOWN_LINK_RE = re.compile(r"(?<!!)\[([^\]]+)\]\(([^)]+)\)")
RUN_LOG_NAME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}-[a-z0-9-]+\.md$")
EXTERNAL_SCHEMES = ("http://", "https://", "mailto:", "#")


def _is_generated_reference_manual(md_path: Path) -> bool:
    """Return True for PDF-extracted manuals under docs/references/<tool>/<name>.md."""
    rel = md_path.relative_to(DOCS_DIR)
    if len(rel.parts) != 3 or rel.parts[0] != "references":
        return False
    head = "\n".join(md_path.read_text(encoding="utf-8").splitlines()[:5])
    return "<!-- source:" in head


def _iter_checked_markdown_files() -> list[Path]:
    """Return top-level and hand-written docs/ Markdown files subject to link checks."""
    files: list[Path] = []
    for name in ("README.md", "AGENTS.md", "CLAUDE.md"):
        top = ROOT / name
        if top.is_file():
            files.append(top)

    for md_path in sorted(DOCS_DIR.rglob("*.md")):
        rel_parts = md_path.relative_to(DOCS_DIR).parts
        if rel_parts[0] in OPTIONAL_GITIGNORED_DIRS:
            continue
        if _is_generated_reference_manual(md_path):
            continue
        files.append(md_path)
    return files


@pytest.mark.unit
def test_docs_root_contains_only_index_agents_and_category_dirs() -> None:
    assert DOCS_DIR.is_dir(), "docs/ directory is missing"
    root_files = {p.name for p in DOCS_DIR.iterdir() if p.is_file()}
    root_dirs = {p.name for p in DOCS_DIR.iterdir() if p.is_dir()}

    assert root_files == REQUIRED_DOCS_ROOT_FILES, (
        f"docs/ root must contain only {sorted(REQUIRED_DOCS_ROOT_FILES)}; "
        f"found {sorted(root_files)} (place guides, plans, or run logs in their category folders)"
    )
    missing_dirs = REQUIRED_DOCS_CATEGORIES - root_dirs
    assert not missing_dirs, f"docs/ is missing required category folders: {sorted(missing_dirs)}"

    unexpected_dirs = root_dirs - REQUIRED_DOCS_CATEGORIES - OPTIONAL_GITIGNORED_DIRS
    assert not unexpected_dirs, f"docs/ root has unexpected folders: {sorted(unexpected_dirs)}"


@pytest.mark.unit
def test_every_docs_category_has_readme_and_agents_guides() -> None:
    missing: list[str] = []
    for category in sorted(REQUIRED_DOCS_CATEGORIES):
        readme = DOCS_DIR / category / "README.md"
        if not readme.is_file():
            missing.append(readme.relative_to(ROOT).as_posix())
    for rel_readme in REQUIRED_SUBDIR_READMES:
        readme = DOCS_DIR / rel_readme
        if not readme.is_file():
            missing.append(readme.relative_to(ROOT).as_posix())
    if not (DOCS_DIR / "troubleshooting" / "AGENTS.md").is_file():
        missing.append("docs/troubleshooting/AGENTS.md")

    assert not missing, f"Missing required documentation index/maintenance files: {missing}"


@pytest.mark.unit
def test_runs_logs_follow_date_slug_naming() -> None:
    runs_dir = DOCS_DIR / "runs"
    bad = [
        p.name
        for p in sorted(runs_dir.iterdir())
        if p.is_file() and p.name != "README.md" and not RUN_LOG_NAME_RE.match(p.name)
    ]
    assert not bad, f"Files in docs/runs/ must follow YYYY-MM-DD-<slug>.md naming: {bad}"


@pytest.mark.unit
def test_markdown_links_are_explicit_relative_and_resolve() -> None:
    non_explicit: list[str] = []
    broken: list[str] = []

    for md_path in _iter_checked_markdown_files():
        rel_doc = md_path.relative_to(ROOT).as_posix()
        in_fence = False
        for lineno, line in enumerate(md_path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.lstrip()
            if stripped.startswith(("```", "~~~")):
                in_fence = not in_fence
                continue
            if in_fence:
                continue

            cleaned = INLINE_CODE_RE.sub("CODE", line)
            for match in MARKDOWN_LINK_RE.finditer(cleaned):
                raw_target = match.group(2).strip()
                if not raw_target:
                    continue
                target = raw_target.split()[0]
                if target.startswith(EXTERNAL_SCHEMES):
                    continue
                path_part = target.split("#", 1)[0]
                if not path_part:
                    continue
                if not path_part.startswith(("./", "../")):
                    non_explicit.append(f"{rel_doc}:{lineno} -> {target} (must start with ./ or ../)")
                resolved = (md_path.parent / path_part).resolve()
                if not resolved.exists():
                    broken.append(f"{rel_doc}:{lineno} -> {target}")

    assert not non_explicit, "Non-explicit relative Markdown links:\n" + "\n".join(non_explicit)
    assert not broken, "Broken Markdown links:\n" + "\n".join(broken)
