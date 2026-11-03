from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"

USES_LINE_RE = re.compile(r"^\s*(?:-\s+)?uses:\s*(.+)$")
PINNED_ACTION_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}\s+#\s+v\d+\.\d+(?:\.\d+)?$")
JOB_HEADER_RE = re.compile(r"^  ([a-zA-Z0-9_-]+):\s*$")


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
        in_jobs = False
        current_job: str | None = None
        job_lines: dict[str, list[str]] = {}

        for i, line in enumerate(lines):
            if line.startswith("jobs:"):
                in_jobs = True
                continue
            if in_jobs and line and not line.startswith(" ") and not line.startswith("#"):
                in_jobs = False
            if in_jobs:
                m_job = JOB_HEADER_RE.match(line)
                if m_job:
                    current_job = m_job.group(1)
                    job_lines[current_job] = []
                elif current_job is not None:
                    job_lines[current_job].append(line)

            if "uses: actions/checkout@" in line:
                window = "\n".join(lines[i : i + 5])
                assert "persist-credentials: false" in window, (
                    f"{wf.name}:{i + 1}: actions/checkout must set 'persist-credentials: false'"
                )

        assert job_lines, f"{wf.name}: expected at least one job"
        for job_name, body in job_lines.items():
            joined = "\n".join(body)
            assert "timeout-minutes:" in joined, f"{wf.name}: job '{job_name}' must set timeout-minutes"
            assert "permissions:" in joined, f"{wf.name}: job '{job_name}' must declare explicit job permissions"


@pytest.mark.unit
def test_no_expression_interpolation_in_run_blocks() -> None:
    workflows = sorted(WORKFLOWS_DIR.glob("*.yml"))

    for wf in workflows:
        lines = wf.read_text(encoding="utf-8").splitlines()
        in_run_block = False
        run_indent = 0

        for lineno, line in enumerate(lines, start=1):
            stripped = line.lstrip(" ")
            indent = len(line) - len(stripped)

            if in_run_block:
                if stripped and not stripped.startswith("#") and indent <= run_indent:
                    in_run_block = False
                else:
                    assert "${{" not in line, (
                        f"{wf.name}:{lineno}: avoid '${{{{ ... }}}}' inside run: block to prevent script injection"
                    )

            m_run = re.match(r"^(\s*(?:-\s+)?)run:\s*(.*)$", line)
            if m_run:
                rhs = m_run.group(2).strip()
                assert "${{" not in rhs, (
                    f"{wf.name}:{lineno}: avoid '${{{{ ... }}}}' inside run: command to prevent script injection"
                )
                if rhs in ("|", ">", "|-", ">-"):
                    in_run_block = True
                    run_indent = len(line) - len(line.lstrip(" "))


@pytest.mark.unit
def test_dependabot_config_tracks_github_actions_and_docker() -> None:
    dependabot = REPO_ROOT / ".github" / "dependabot.yml"
    assert dependabot.is_file(), "Expected .github/dependabot.yml to exist"
    text = dependabot.read_text(encoding="utf-8")
    assert 'package-ecosystem: "github-actions"' in text
    assert 'package-ecosystem: "docker"' in text
