"""Tests for the curated opam patch queue, cache fallback digest, and run-metadata provenance."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

import cache
import run_metadata
import sync_opam_patches


@pytest.mark.unit
def test_opam_patch_queue_is_in_sync() -> None:
    assert sync_opam_patches.check_sync() == []


@pytest.mark.unit
def test_opam_patch_files_are_source_only_and_lf() -> None:
    manifest = json.loads(sync_opam_patches.MANIFEST_PATH.read_text(encoding="utf-8"))
    assert manifest["schema_version"] == 1
    assert len(manifest["frama_c"]) == len(sync_opam_patches.FRAMAC_PATCHES)
    assert len(manifest["metacsl"]) == len(sync_opam_patches.METACSL_PATCHES)
    assert re.fullmatch(r"[0-9a-f]{64}", manifest["digest"])

    for pkg_key, pkg_dir in (
        ("frama_c", sync_opam_patches.FRAMAC_PKG_DIR),
        ("metacsl", sync_opam_patches.METACSL_PKG_DIR),
    ):
        files_dir = pkg_dir / "files"
        for entry in manifest[pkg_key]:
            patch_path = files_dir / entry["filename"]
            raw = patch_path.read_bytes()
            assert b"\r\n" not in raw, f"CRLF in {patch_path}"
            assert hashlib.sha256(raw).hexdigest() == entry["sha256"]
            text = raw.decode("utf-8")
            touched = re.findall(r"^diff --git a/(.+?) b/", text, re.MULTILINE)
            assert touched == entry["files"]
            assert touched, f"No diff hunks in {patch_path}"
            for rel in touched:
                assert "/tests/" not in rel and not rel.startswith("tests/"), rel
                assert not rel.endswith("Changelog") and rel not in ("CHANGELOG.md", "README.md"), rel


@pytest.mark.unit
def test_opam_files_list_patches_and_checksums_in_order() -> None:
    manifest = json.loads(sync_opam_patches.MANIFEST_PATH.read_text(encoding="utf-8"))
    for pkg_key, pkg_dir in (
        ("frama_c", sync_opam_patches.FRAMAC_PKG_DIR),
        ("metacsl", sync_opam_patches.METACSL_PKG_DIR),
    ):
        opam_text = (pkg_dir / "opam").read_text(encoding="utf-8")
        assert sync_opam_patches.BEGIN_MARKER in opam_text
        assert sync_opam_patches.END_MARKER in opam_text
        expected_names = [e["filename"] for e in manifest[pkg_key]]
        m_patches = re.search(r"patches:\s*\[(.*?)\]", opam_text, re.DOTALL)
        assert m_patches is not None
        actual_names = re.findall(r'"([^"]+)"', m_patches.group(1))
        assert actual_names == expected_names
        for entry in manifest[pkg_key]:
            assert f'["{entry["filename"]}" "sha256={entry["sha256"]}"]' in opam_text


@pytest.mark.unit
def test_cache_tools_fallback_includes_patch_manifest_digest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FRAMAC_IMAGE_ID", raising=False)
    monkeypatch.setenv("FRAMAC_SHARE", str(tmp_path))

    def fake_run(cmd: list[str], **_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(returncode=0, stdout=f"{cmd[0]} 1.0\n", stderr="")

    monkeypatch.setattr(cache, "_toolchain_memo", None)
    unpatched_id = cache._image_or_tools_id(fake_run)

    manifest_file = tmp_path / "pipeline-patches.json"
    manifest_file.write_text(json.dumps({"digest": "a" * 64}), encoding="utf-8")
    monkeypatch.setattr(cache, "_toolchain_memo", None)
    patched_a = cache._image_or_tools_id(fake_run)

    manifest_file.write_text(json.dumps({"digest": "b" * 64}), encoding="utf-8")
    monkeypatch.setattr(cache, "_toolchain_memo", None)
    patched_b = cache._image_or_tools_id(fake_run)

    assert unpatched_id != patched_a
    assert patched_a != patched_b


@pytest.mark.unit
def test_run_metadata_toolchain_reports_patch_manifest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FRAMAC_SHARE", str(tmp_path))
    monkeypatch.setattr(run_metadata, "_run", lambda cmd, cwd=None: f"{cmd[0]} 1.0")

    without_manifest = run_metadata.toolchain()
    assert "frama-c-patches" not in without_manifest

    (tmp_path / "pipeline-patches.json").write_text(
        json.dumps(
            {
                "digest": "c" * 64,
                "frama_c": [{"filename": "01-a.patch"}, {"filename": "02-b.patch"}],
                "metacsl": [{"filename": "45-m.patch"}],
            }
        ),
        encoding="utf-8",
    )
    with_manifest = run_metadata.toolchain()
    assert with_manifest["frama-c-patches"] == {
        "digest": "c" * 64,
        "frama_c_count": 2,
        "metacsl_count": 1,
        "frama_c": ["01-a.patch", "02-b.patch"],
        "metacsl": ["45-m.patch"],
    }
