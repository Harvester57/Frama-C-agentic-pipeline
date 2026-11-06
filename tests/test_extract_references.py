from pathlib import Path

from extract_references import (
    DEFAULT_ROOT,
    Section,
    assign_ends,
    clean_page,
    fold_ascii,
    main,
    orphan_outputs,
    place_headings,
    render_index,
    stale_outputs,
)


def test_fold_ascii_makes_options_and_quotes_greppable():
    assert fold_ascii("−wp−timeout ‘swap’ “x” a∗b ﬁle") == "-wp-timeout 'swap' \"x\" a*b file"


def test_clean_page_drops_running_header_footer_and_toc_leaders():
    page = "\n".join(
        [
            "                              2.4. COMMAND LINE OPTIONS",
            "",
            "2.4.3 Model Selection . . . . . . . . . . . . 33",
            "-wp-timeout <t> sets the timeout",
            "# frama-c -wp -wp-rte swap.c",
            "",
            "                                      32",
        ]
    )
    assert clean_page(page) == ["", "-wp-timeout <t> sets the timeout", " # frama-c -wp -wp-rte swap.c", ""]


def test_clean_page_keeps_all_caps_chapter_title_and_title_page():
    assert clean_page("FAQ  10\nWell, for some value of...") == ["FAQ  10", "Well, for some value of..."]
    assert clean_page("RTE\nRuntime Error Annotation Generation", first_page=True)[0] == "RTE"


def test_place_headings_matches_numbered_trailing_and_relocated_titles():
    pages = [
        ["Introduction     1", "", "1.1 First contact", "text"],
        ["more text", "1.2 Details", "x"],
        ["end of chapter"],
        ["Bibliography", "[1] ref"],
    ]
    sections = [
        Section("1 Introduction", 0, 1),
        Section("1.1 First contact", 1, 1),
        Section("1.2 Details", 1, 2),
        Section("Bibliography", 0, 2),  # bookmark points two pages early
    ]
    lines, misses = place_headings(pages, sections)
    assert misses == 0
    assert [lines[s.line - 1] for s in sections] == [
        "## 1 Introduction",
        "### 1.1 First contact",
        "### 1.2 Details",
        "## Bibliography",
    ]
    assert sections[3].page == 4
    assert lines.count("<!-- page 1 -->") == 1 and "<!-- page 4 -->" in lines
    assert not any(a == b == "" for a, b in zip(lines, lines[1:], strict=False))


def test_missing_heading_is_inserted_after_previous_heading_on_same_page():
    pages = [["2.1 Found", "body", "unrelated"]]
    sections = [Section("2.1 Found", 1, 1), Section("2.2 Not on page", 1, 1)]
    lines, misses = place_headings(pages, sections)
    assert misses == 1
    assert sections[0].line < sections[1].line
    assert lines[sections[1].line - 1] == "### 2.2 Not on page"


def test_section_ends_and_index_lines():
    sections = [Section("1 A", 0, 1, line=10), Section("1.1 B", 1, 1, line=12), Section("2 C", 0, 2, line=20)]
    assign_ends(sections, 30)
    assert [(s.line, s.end) for s in sections] == [(10, 19), (12, 19), (20, 30)]
    index = render_index([("wp/m.md", "WP", sections)])
    assert "wp/m.md:12-19" in index and "  1.1 B  (p. 1)" in index


def test_check_flags_missing_and_stale_markdown(tmp_path: Path):
    tool = tmp_path / "wp"
    tool.mkdir()
    pdf = tool / "m.pdf"
    pdf.write_bytes(b"%PDF-1.4 fake")
    assert stale_outputs(tmp_path) == ["wp/m.pdf: missing m.md", "missing INDEX.md"]
    (tool / "m.md").write_text("# T\n\n<!-- source: wp/m.pdf sha256:" + "0" * 64 + " pages:1 -->\n", encoding="utf-8")
    (tmp_path / "INDEX.md").write_text("# index\n", encoding="utf-8")
    assert stale_outputs(tmp_path) == ["wp/m.pdf: m.md is stale"]
    assert main(["--root", str(tmp_path), "--check"]) == 1


def test_moved_pdf_leaves_an_orphan_but_hand_written_markdown_is_ignored(tmp_path: Path):
    (tmp_path / "eacsl").mkdir()
    (tmp_path / "eacsl" / "old.md").write_text(
        "# T\n\n<!-- source: eacsl/old.pdf sha256:" + "0" * 64 + " pages:1 -->\n", encoding="utf-8"
    )
    (tmp_path / "eacsl" / "notes.md").write_text("# Hand-written notes\n", encoding="utf-8")
    assert orphan_outputs(tmp_path) == [tmp_path / "eacsl" / "old.md"]
    assert stale_outputs(tmp_path) == ["eacsl/old.md: orphan, its PDF was moved or deleted"]


def test_committed_reference_markdown_is_up_to_date():
    # Regenerate with `python scripts/extract_references.py` after adding or replacing a PDF.
    assert stale_outputs(DEFAULT_ROOT) == []


def test_framac_skills_mirror_is_in_sync():
    # Every harness mirror (.agents/skills, .claude/skills) must hold one symlink per skill,
    # pointing at ../skills/<name>: skills are edited once in skills/ and shared everywhere.
    repo_root = DEFAULT_ROOT.parent.parent
    skills_dir = repo_root / "skills"
    primary = {
        p.relative_to(skills_dir).as_posix(): p.read_bytes() for p in sorted(skills_dir.rglob("*")) if p.is_file()
    }
    skill_names = sorted({Path(k).parts[0] for k in primary})
    for mirror in (repo_root / ".agents" / "skills", repo_root / ".claude" / "skills"):
        if not mirror.is_dir():
            continue
        entries = sorted(p.name for p in mirror.iterdir())
        assert entries == skill_names, f"{mirror} must contain exactly the skills/ entries as symlinks"
        symlinks = 0
        for name in skill_names:
            link = mirror / name
            if link.is_symlink():
                symlinks += 1
                assert link.resolve() == (skills_dir / name).resolve(), f"{link} must point at skills/{name}"
            else:
                # core.symlinks=false (the Windows default): git checks a symlink out as a plain file
                # holding its target path, which is still what the repository records.
                assert link.is_file(), f"{link} must be a symlink to skills/{name}"
                target = link.read_text(encoding="utf-8").strip()
                assert target == f"../../skills/{name}", f"{link} must point at skills/{name}"
        if symlinks != len(skill_names):
            continue  # no real links to walk: the targets were checked above
        # Content through the links matches the primary (rglob does not follow symlinked dirs,
        # so walk each link's target explicitly).
        mirrored = {}
        for name in skill_names:
            for p in sorted((mirror / name).rglob("*")):
                if p.is_file():
                    mirrored[p.resolve().relative_to(skills_dir).as_posix()] = p.read_bytes()
        assert primary.keys() == mirrored.keys()
        for rel_path, content in primary.items():
            assert mirrored[rel_path] == content, f"Skill mirror drift in {rel_path}"
