"""Validation tests for upstream Frama-C/MetAcsl bug reporting enforcement and the upstream-bug-report skill."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from conftest import ROOT
from upstream_audit import file_upstream as fu

pytestmark = pytest.mark.unit

GUIDELINES_URL = "https://git.frama-c.com/pub/frama-c/-/wikis/Guidelines-for-reporting-bugs"
UPSTREAM_SKILL = ROOT / "skills" / "upstream-bug-report" / "SKILL.md"
VALID_ISSUE = """\
# [E-ACSL] Example defect in instrumentation

<!-- Everything below this line is the issue description. -->

### Summary

E-ACSL rejects a valid annotation on a small C program.

### Steps to reproduce the issue

`repro.c`:

```c
int main(void) {
  int x = 1;
  /*@ assert x == 1; */
  return 0;
}
```

```sh
frama-c -e-acsl repro.c
```

### Expected behaviour

The annotation is translated without error.

### Actual behaviour

```text
[e-acsl] repro.c:3: Error: unexpected failure
```

### Contextual information

- Frama-C installation mode: from source (`master`)
- Frama-C version: 35.0~~dev (Bromine), `master` at b80fcac74f; also 34.0~beta (Selenium)
- Plug-in used: E-ACSL
- OS name: Debian GNU/Linux
- OS version: 13 (trixie; glibc 2.41, gcc 14.2.0)

### Additional information (optional)

**Cause.** Example diagnosis.
"""


def _write_issue(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_bytes(content.encode("utf-8"))
    return path


class TestRepositoryFilingDrafts:
    def test_all_filed_issues_pass_guidelines_check(self) -> None:
        led = fu.ledger()
        filing_dir = ROOT / "docs" / "upstream" / "frama-c" / "filing"
        filed_files = [
            p
            for p in sorted(filing_dir.glob("*-issue.md"))
            if p.name.split("-", 1)[0] not in {"00", "43", "44", "45", "46", "47", "48", "49"}
        ]
        assert len(filed_files) >= 39
        failures: dict[str, list[str]] = {}
        for path in filed_files:
            errs, _ = fu.check_issue_file(path, led, allow_placeholders=False)
            if errs:
                failures[path.name] = errs
        assert failures == {}

    def test_ready_unfiled_drafts_pass_guidelines_check(self) -> None:
        led = fu.ledger()
        filing_dir = ROOT / "docs" / "upstream" / "frama-c" / "filing"
        ready_nns = ("43", "44", "45", "47", "48", "49")
        failures: dict[str, list[str]] = {}
        for nn in ready_nns:
            matches = list(filing_dir.glob(f"{nn}-*-issue.md"))
            assert len(matches) == 1, f"expected one issue file for {nn}, got {matches}"
            errs, _ = fu.check_issue_file(matches[0], led, allow_placeholders=True)
            if errs:
                failures[matches[0].name] = errs
        assert failures == {}

    def test_overview_issue_is_accepted(self) -> None:
        overview = ROOT / "docs" / "upstream" / "frama-c" / "filing" / "00-reports-overview-issue.md"
        errs, _ = fu.check_issue_file(overview, fu.ledger(), allow_placeholders=False)
        assert errs == []


class TestValidateIssueRules:
    def test_valid_issue_has_no_errors_or_warnings(self, tmp_path: Path) -> None:
        path = _write_issue(tmp_path, "99-example-issue.md", VALID_ISSUE)
        errs, warns = fu.check_issue_file(path, {}, allow_placeholders=False)
        assert errs == []
        assert warns == []

    def test_missing_title_tag_rejected_for_pub_framac(self) -> None:
        desc = VALID_ISSUE.split("-->\n", 1)[1].strip()
        errs, _ = fu.validate_issue("No bracket tag here", desc, tracker="pub/frama-c")
        assert any("category/plug-in tag" in e for e in errs)

    def test_missing_title_tag_allowed_for_pub_meta(self) -> None:
        desc = VALID_ISSUE.split("-->\n", 1)[1].strip()
        errs, warns = fu.validate_issue("MetAcsl issue without tag", desc, tracker="pub/meta")
        assert errs == []
        assert warns == []

    @pytest.mark.parametrize(
        "heading",
        [
            "### Summary",
            "### Steps to reproduce the issue",
            "### Expected behaviour",
            "### Actual behaviour",
            "### Contextual information",
        ],
    )
    def test_missing_required_section_rejected(self, heading: str) -> None:
        desc = VALID_ISSUE.split("-->\n", 1)[1].strip()
        broken = desc.replace(heading, "### Renamed")
        errs, _ = fu.validate_issue("[E-ACSL] Missing section", broken)
        assert any(heading in e for e in errs)

    @pytest.mark.parametrize(
        "bullet",
        [
            "Frama-C installation mode",
            "Frama-C version",
            "Plug-in used",
            "OS name",
            "OS version",
        ],
    )
    def test_missing_contextual_bullet_rejected(self, bullet: str) -> None:
        desc = VALID_ISSUE.split("-->\n", 1)[1].strip()
        broken = "\n".join(line for line in desc.splitlines() if not line.startswith(f"- {bullet}:"))
        errs, _ = fu.validate_issue("[E-ACSL] Missing context", broken)
        assert any(bullet in e for e in errs)

    def test_unclosed_code_fence_rejected(self) -> None:
        desc = VALID_ISSUE.split("-->\n", 1)[1].strip() + "\n```text\nunclosed\n"
        errs, _ = fu.validate_issue("[E-ACSL] Unclosed fence", desc)
        assert any("unclosed Markdown code fence" in e for e in errs)

    def test_relative_repo_link_and_phantom_attachment_rejected(self) -> None:
        desc = VALID_ISSUE.split("-->\n", 1)[1].strip()
        desc += "\nSee [notes](../frama-c-notes.md) and line 14 in the attached file.\n"
        errs, _ = fu.validate_issue("[E-ACSL] Bad refs", desc)
        assert any("relative repository link" in e for e in errs)
        assert any("attached file" in e for e in errs)

    def test_inline_reproducer_line_mismatch_rejected(self) -> None:
        desc = VALID_ISSUE.split("-->\n", 1)[1].strip()
        broken = desc.replace("repro.c:3:", "repro.c:14:")
        errs, _ = fu.validate_issue("[E-ACSL] Line mismatch", broken)
        assert any("repro.c:14" in e for e in errs)

    def test_crlf_and_placeholders_enforced(self, tmp_path: Path) -> None:
        text = VALID_ISSUE.replace("Example diagnosis.", "Related to #ISSUE-98.").replace("\n", "\r\n")
        path = _write_issue(tmp_path, "99-crlf-issue.md", text)
        errs, warns = fu.check_issue_file(path, {}, allow_placeholders=True)
        assert any("CRLF" in e for e in errs)
        assert any("unresolved placeholder" in w for w in warns)

        errs_strict, _ = fu.check_issue_file(path, {}, allow_placeholders=False)
        assert any("unresolved placeholder" in e for e in errs_strict)

    def test_crash_backtrace_warning_clears_with_frames(self) -> None:
        desc = VALID_ISSUE.split("-->\n", 1)[1].strip()
        crash_no_bt = desc.replace(
            "[e-acsl] repro.c:3: Error: unexpected failure",
            "[kernel] Unexpected error (Failure).\nPlease report as 'crash'",
        )
        errs, warns = fu.validate_issue("[E-ACSL] Crash", crash_no_bt)
        assert errs == []
        assert any("OCaml backtrace" in w for w in warns)

        crash_with_bt = crash_no_bt.replace(
            "Please report as 'crash'",
            "Please report as 'crash'\nCalled from E_ACSL__Typing.get in file \"typing.ml\", line 10",
        )
        errs2, warns2 = fu.validate_issue("[E-ACSL] Crash", crash_with_bt)
        assert errs2 == []
        assert not any("OCaml backtrace" in w for w in warns2)

    def test_host_header_warning_clears_with_glibc_version(self) -> None:
        desc = VALID_ISSUE.split("-->\n", 1)[1].strip()
        with_hdr = desc.replace(
            "int main(void) {",
            "#include <stdio.h>\nint main(void) {",
        ).replace("frama-c -e-acsl repro.c", "e-acsl-gcc -c repro.c")
        no_glibc = with_hdr.replace("; glibc 2.41, gcc 14.2.0", "")
        errs, warns = fu.validate_issue("[E-ACSL] Host hdr", no_glibc)
        assert errs == []
        assert any("stdio.h" in w for w in warns)

        errs2, warns2 = fu.validate_issue("[E-ACSL] Host hdr", with_hdr)
        assert errs2 == []
        assert not any("stdio.h" in w for w in warns2)

    def test_do_issue_refuses_pub_meta_without_api_call(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        meta_issue = VALID_ISSUE.replace(
            "# [E-ACSL] Example defect in instrumentation",
            "# MetAcsl defect",
        ).replace(
            "<!-- Everything below this line is the issue description. -->",
            "<!-- Everything below this line is the issue description. Tracker: pub/meta (MetAcsl), not pub/frama-c. -->",
        )
        _write_issue(tmp_path, "99-meta-issue.md", meta_issue)
        monkeypatch.setattr(fu, "FILING", tmp_path)
        monkeypatch.setattr(fu, "LEDGER", tmp_path / "ledger.json")

        def fail_api(*args: Any, **kwargs: Any) -> Any:
            raise AssertionError("API should not be called for pub/meta")

        monkeypatch.setattr(fu, "api", fail_api)
        with pytest.raises(SystemExit, match="pub/meta"):
            fu.do_issue("99")


class TestSkillAndDocsIntegration:
    def test_upstream_bug_report_skill_frontmatter_and_links(self) -> None:
        assert UPSTREAM_SKILL.is_file()
        text = UPSTREAM_SKILL.read_text(encoding="utf-8")
        front = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
        assert front and re.search(r"^name:\s*upstream-bug-report$", front.group(1), re.M)
        assert GUIDELINES_URL in text
        assert "file_upstream.py check" in text

        # Every relative markdown link outside fenced blocks resolves.
        in_fence = False
        fence_len = 0
        for line in text.splitlines():
            fm = re.match(r"^\s*(`{3,})", line)
            if fm:
                if not in_fence:
                    in_fence, fence_len = True, len(fm.group(1))
                elif len(fm.group(1)) >= fence_len and line.strip() == fm.group(1):
                    in_fence, fence_len = False, 0
                continue
            if in_fence:
                continue
            cleaned = re.sub(r"`[^`\n]+`", "CODE", line)
            for match in re.finditer(r"(?<!!)\[([^\]]+)\]\(([^)]+)\)", cleaned):
                target = match.group(2).strip().split()[0]
                if target.startswith(("http://", "https://", "#")):
                    continue
                path_part = target.split("#", 1)[0]
                assert path_part.startswith(("./", "../")), f"non-explicit link: {target}"
                assert (UPSTREAM_SKILL.parent / path_part).resolve().exists(), f"broken link: {target}"

    @pytest.mark.parametrize(
        "rel_path",
        [
            "docs/upstream/README.md",
            "docs/upstream/frama-c/README.md",
            "docs/upstream/frama-c/filing/README.md",
            "skills/run-supervisor/SKILL.md",
        ],
    )
    def test_docs_and_supervisor_reference_guidelines_and_skill(self, rel_path: str) -> None:
        text = (ROOT / rel_path).read_text(encoding="utf-8")
        assert GUIDELINES_URL in text
        assert "upstream-bug-report" in text
        assert "file_upstream.py" in text
