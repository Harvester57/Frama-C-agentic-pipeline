"""tools/sync_skill_mirrors.py: skills/ is the source of truth, the two harness mirrors are plain copies."""

from __future__ import annotations

from pathlib import Path

import pytest

import sync_skill_mirrors as ssm

pytestmark = pytest.mark.unit


def _tree(root: Path) -> Path:
    (root / "skills" / "alpha" / "references").mkdir(parents=True)
    (root / "skills" / "alpha" / "SKILL.md").write_bytes(b"alpha\n")
    (root / "skills" / "alpha" / "references" / "notes.md").write_bytes(b"notes\n")
    (root / "skills" / "beta").mkdir()
    (root / "skills" / "beta" / "SKILL.md").write_bytes(b"beta\n")
    return root


def test_repository_mirrors_are_copies_of_skills() -> None:
    # The check the pre-commit hook and CI run. Fix: edit under skills/, then run the tool without --check.
    assert ssm.mirror_drift() == []


def test_sync_creates_both_mirrors_and_check_passes(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    assert ssm.mirror_drift(root) == [".agents/skills: missing", ".claude/skills: missing"]
    changed = ssm.sync(root)
    assert ".claude/skills/alpha/references/notes.md" in changed
    assert ssm.mirror_drift(root) == []
    assert (root / ".agents" / "skills" / "beta" / "SKILL.md").read_bytes() == b"beta\n"
    assert ssm.sync(root) == []


def test_check_names_an_edit_made_in_a_mirror(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    ssm.sync(root)
    (root / ".claude" / "skills" / "alpha" / "SKILL.md").write_bytes(b"edited in the mirror\n")
    assert ssm.mirror_drift(root) == [".claude/skills/alpha/SKILL.md: differs from skills/alpha/SKILL.md"]
    assert ssm.main(["--check", "--root", str(root)]) == 1
    ssm.sync(root)
    assert (root / ".claude" / "skills" / "alpha" / "SKILL.md").read_bytes() == b"alpha\n"


def test_check_names_missing_and_extra_files(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    ssm.sync(root)
    (root / ".agents" / "skills" / "beta" / "SKILL.md").unlink()
    (root / ".agents" / "skills" / "gone").mkdir()
    (root / ".agents" / "skills" / "gone" / "SKILL.md").write_bytes(b"removed from skills\n")
    assert ssm.mirror_drift(root) == [
        ".agents/skills/beta/SKILL.md: missing",
        ".agents/skills/gone/SKILL.md: not in skills/",
    ]
    ssm.sync(root)
    assert not (root / ".agents" / "skills" / "gone").exists()
    assert ssm.mirror_drift(root) == []


def test_plain_file_form_of_a_symlink_is_replaced_by_a_copy(tmp_path: Path) -> None:
    # What a Windows checkout with core.symlinks=false leaves for a tracked symlink.
    root = _tree(tmp_path)
    mirror = root / ".claude" / "skills"
    mirror.mkdir(parents=True)
    (mirror / "alpha").write_text("../../skills/alpha", encoding="utf-8")
    assert ".claude/skills/alpha: not a directory copy (symlink or plain file)" in ssm.mirror_drift(root)
    ssm.sync(root)
    assert (mirror / "alpha" / "SKILL.md").read_bytes() == b"alpha\n"
    assert ssm.mirror_drift(root) == []


def test_real_symlink_is_replaced_by_a_copy(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    mirror = root / ".agents" / "skills"
    mirror.mkdir(parents=True)
    try:
        (mirror / "alpha").symlink_to(Path("..") / ".." / "skills" / "alpha", target_is_directory=True)
    except OSError:
        pytest.skip("symlinks are not available on this platform")
    assert ".agents/skills/alpha: not a directory copy (symlink or plain file)" in ssm.mirror_drift(root)
    ssm.sync(root)
    assert not (mirror / "alpha").is_symlink()
    assert (root / "skills" / "alpha" / "SKILL.md").read_bytes() == b"alpha\n"
    assert ssm.mirror_drift(root) == []


def test_pre_commit_and_ci_run_the_check() -> None:
    assert "tools/sync_skill_mirrors.py --check" in (ssm.ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    assert "tools/sync_skill_mirrors.py --check" in (ssm.ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
