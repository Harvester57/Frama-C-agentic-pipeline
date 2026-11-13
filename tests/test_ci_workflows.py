from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"

USES_LINE_RE = re.compile(r"^\s*(?:-\s+)?uses:\s*(.+)$")
PINNED_ACTION_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}\s+#\s+v\d+\.\d+(?:\.\d+)?$")


@pytest.mark.unit
def test_workflow_files_exist_and_have_least_privilege_permissions() -> None:
    workflows = sorted(WORKFLOWS_DIR.glob("*.yml"))
    assert len(workflows) >= 3, "Expected CI, Security, and CD workflows in .github/workflows/"

    for wf in workflows:
        text = wf.read_text(encoding="utf-8")
        assert "\npermissions: {}\n" in text, f"{wf.name} must declare top-level 'permissions: {{}}'"
        assert "pull_request_target" not in text, f"{wf.name} must not use pull_request_target"


@pytest.mark.unit
def test_all_github_actions_are_pinned_to_full_commit_sha_with_version_comment() -> None:
    workflows = sorted(WORKFLOWS_DIR.glob("*.yml"))
    seen_uses = 0

    for wf in workflows:
        for lineno, line in enumerate(wf.read_text(encoding="utf-8").splitlines(), start=1):
            m = USES_LINE_RE.match(line)
            if not m:
                continue
            seen_uses += 1
            spec = m.group(1).strip()
            assert PINNED_ACTION_RE.match(spec), (
                f"{wf.name}:{lineno}: action '{spec}' must be pinned to a 40-char commit SHA "
                "with a '# vX.Y.Z' version comment"
            )

    assert seen_uses > 0


@pytest.mark.unit
def test_checkout_steps_disable_persist_credentials_and_jobs_set_timeouts() -> None:
    workflows = sorted(WORKFLOWS_DIR.glob("*.yml"))

    for wf in workflows:
        lines = wf.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            if "uses: actions/checkout@" in line:
                window = "\n".join(lines[i : i + 5])
                assert "persist-credentials: false" in window, (
                    f"{wf.name}:{i + 1}: actions/checkout must set 'persist-credentials: false'"
                )

        job_lines = _job_bodies(lines)
        assert job_lines, f"{wf.name}: expected at least one job"
        assert _jobs_missing(job_lines, "timeout-minutes:") == [], f"{wf.name}: every job must set timeout-minutes"
        assert _jobs_missing(job_lines, "permissions:") == [], f"{wf.name}: every job must declare job permissions"


def _job_bodies(lines: list[str]) -> dict[str, list[str]]:
    """
    The lines of each job of a workflow, by job id. The jobs are the keys one level under `jobs:`, at
    whatever indent the file uses there (the first key's), with or without a trailing comment.
    """
    in_jobs = False
    job_indent: int | None = None
    current_job: str | None = None
    job_lines: dict[str, list[str]] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            in_jobs = re.fullmatch(r"jobs:\s*(#.*)?", line) is not None
            continue
        if not in_jobs:
            continue
        if job_indent is None:
            job_indent = indent
        if indent == job_indent:
            m_job = re.fullmatch(r"([A-Za-z0-9_-]+):\s*(#.*)?", stripped)
            assert m_job is not None, f"unreadable job line: {line!r}"
            current_job = m_job.group(1)
            assert current_job not in job_lines, f"job {current_job} defined twice"
            job_lines[current_job] = []
        else:
            assert indent > job_indent and current_job is not None, f"line outside a job: {line!r}"
            job_lines[current_job].append(line)
    return job_lines


def _jobs_missing(job_lines: dict[str, list[str]], key: str) -> list[str]:
    """The jobs none of whose lines sets `key`."""
    return [name for name, body in job_lines.items() if not any(line.strip().startswith(key) for line in body)]


WORKFLOW_SAMPLE = """\
name: sample
permissions: {}
jobs:
  first:
    timeout-minutes: 5
    permissions:
      contents: read
    steps:
      - run: echo one
  second:
    timeout-minutes: 5
    permissions: {}
    steps:
      - run: echo two
"""


@pytest.mark.unit
@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("  second:\n", "  second:  # nightly\n"),  # the old `^  (name):\s*$` did not see this job
        ("  second:\n", "  second: \n"),
    ],
)
def test_a_job_without_a_timeout_is_found_however_its_line_is_written(old: str, new: str) -> None:
    text = WORKFLOW_SAMPLE.replace(old, new)
    assert text != WORKFLOW_SAMPLE
    assert list(_job_bodies(text.splitlines())) == ["first", "second"]
    assert _jobs_missing(_job_bodies(text.splitlines()), "timeout-minutes:") == []
    mutated = text.replace("    timeout-minutes: 5\n    permissions: {}\n", "    permissions: {}\n")
    assert _jobs_missing(_job_bodies(mutated.splitlines()), "timeout-minutes:") == ["second"]


@pytest.mark.unit
def test_jobs_are_found_at_the_indent_the_file_uses() -> None:
    wide = "\n".join(
        " " * (2 * (len(line) - len(line.lstrip(" ")))) + line.lstrip(" ") for line in WORKFLOW_SAMPLE.splitlines()
    )
    bodies = _job_bodies(wide.splitlines())
    assert list(bodies) == ["first", "second"]
    assert _jobs_missing(bodies, "timeout-minutes:") == [] and _jobs_missing(bodies, "retries:") == ["first", "second"]


# A block scalar header: `|` or `>`, then the chomping (`+`, `-`) and indentation (1-9) indicators in either
# order, then an optional comment.
BLOCK_SCALAR_HEADER_RE = re.compile(r"[|>](?:[+-]?[1-9]?|[1-9][+-]?)(?:\s+#.*)?")


def _run_interpolations(lines: list[str]) -> list[int]:
    """
    The numbers of the lines that put a `${{ ... }}` expression in a `run:` script: on the `run:` line,
    in the body of its block scalar (whatever its header), or on the continuation lines of a plain or
    quoted scalar. The script ends at the first line indented no deeper than the `run:` key.
    """
    found: list[int] = []
    in_run_block = False
    key_column = 0
    for lineno, line in enumerate(lines, start=1):
        stripped = line.lstrip(" ")
        indent = len(line) - len(stripped)

        if in_run_block:
            if stripped and not stripped.startswith("#") and indent <= key_column:
                in_run_block = False
            elif "${{" in line:
                found.append(lineno)

        m_run = re.match(r"^(\s*(?:-\s+)?)run:(?:\s+(.*))?$", line)
        if m_run and not in_run_block:
            rhs = (m_run.group(2) or "").strip()
            if "${{" in rhs:
                found.append(lineno)
            # Whatever follows the key, the deeper-indented lines below it belong to the script. A header
            # this test cannot read is an error, not a script it skips.
            assert not rhs.startswith(("|", ">")) or BLOCK_SCALAR_HEADER_RE.fullmatch(rhs), (
                f"line {lineno}: unreadable block scalar header {rhs!r}"
            )
            in_run_block = True
            key_column = len(m_run.group(1))
    return found


@pytest.mark.unit
def test_no_expression_interpolation_in_run_blocks() -> None:
    for wf in sorted(WORKFLOWS_DIR.glob("*.yml")):
        found = _run_interpolations(wf.read_text(encoding="utf-8").splitlines())
        assert found == [], f"{wf.name}:{found}: avoid '${{{{ ... }}}}' inside run: to prevent script injection"


@pytest.mark.unit
@pytest.mark.parametrize(
    "header", ["|", ">", "|-", ">-", "|+", ">+", "|2", "|2-", "|-2", ">+1", "| # note", "|-  # note"]
)
def test_an_expression_in_a_run_block_is_found_under_every_block_header(header: str) -> None:
    # The old test knew `|`, `>`, `|-` and `>-` only, and skipped the body under any other header.
    lines = [
        "steps:",
        f"  - run: {header}",
        "      echo ${{ github.event.issue.title }}",
        "    env:",
        "      A: ${{ x }}",
    ]
    assert _run_interpolations(lines) == [3]
    lines[2] = "      echo safe"
    assert _run_interpolations(lines) == []


@pytest.mark.unit
def test_an_expression_in_a_run_line_or_its_continuation_is_found() -> None:
    assert _run_interpolations(["  run: echo ${{ x }}"]) == [1]
    assert _run_interpolations(["  - run: echo a", "      ${{ x }}", "    shell: bash"]) == [2]
    assert _run_interpolations(["  - run:", "      echo ${{ x }}"]) == [2]
    assert _run_interpolations(["  - name: ${{ x }}", "    run: echo a", "    env:", "      A: ${{ x }}"]) == []


@pytest.mark.unit
def test_dependabot_config_tracks_github_actions_and_docker() -> None:
    dependabot = REPO_ROOT / ".github" / "dependabot.yml"
    assert dependabot.is_file(), "Expected .github/dependabot.yml to exist"
    text = dependabot.read_text(encoding="utf-8")
    assert 'package-ecosystem: "github-actions"' in text
    assert 'package-ecosystem: "docker"' in text
