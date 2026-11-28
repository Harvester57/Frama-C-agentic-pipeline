"""Unit tests verifying that run_guardrail_check selects replay inputs before hashing corpus files."""

from __future__ import annotations

from pathlib import Path

import pytest

import cache
import run_eacsl_fuzz as R
import sandbox_exec
from sandbox_exec import SandboxResult

pytestmark = pytest.mark.unit


def _make_corpus(corpus: Path, count: int = 50) -> list[str]:
    corpus.mkdir(parents=True, exist_ok=True)
    names: list[str] = []
    for i in range(count):
        name = f"{i:040x}"
        (corpus / name).write_bytes(f"unit-{i}".encode())
        names.append(name)
    # Hidden file and subdirectory must be ignored.
    (corpus / ".hidden").write_bytes(b"ignore-me")
    (corpus / "subdir").mkdir()
    return names


def _stub_passing_guardrail(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    calls: list[list[str]] = []
    monkeypatch.setattr(R, "is_eacsl_instrumented", lambda _b: True)

    def fake_run(cmd: list[str], **_kw: object) -> SandboxResult:
        calls.append(list(cmd))
        return SandboxResult(0, "stat::number_of_executed_units: 4\n", "", False, "rlimits", list(cmd))

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_run)
    return calls


def _spy_corpus_hashing(monkeypatch: pytest.MonkeyPatch, corpus: Path) -> list[str]:
    hashed_in_corpus: list[str] = []
    corpus_resolved = corpus.resolve()
    orig_file_digest = cache.file_digest
    orig_sha256_file = R.sha256_file

    def tracked_file_digest(path: Path) -> str | None:
        resolved = Path(path).resolve()
        if resolved.parent == corpus_resolved:
            hashed_in_corpus.append(resolved.name)
        return orig_file_digest(path)

    def tracked_sha256_file(path: Path) -> str:
        resolved = Path(path).resolve()
        if resolved.parent == corpus_resolved:
            hashed_in_corpus.append(resolved.name)
        return orig_sha256_file(path)

    monkeypatch.setattr(cache, "file_digest", tracked_file_digest)
    monkeypatch.setattr(R, "sha256_file", tracked_sha256_file)
    return hashed_in_corpus


def test_corpus_manifest_with_names_matches_full_manifest_subset(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    all_names = _make_corpus(corpus, count=20)
    chosen, _ = R.select_replay_inputs(all_names, 4)

    full = R.corpus_manifest(corpus)
    subset = R.corpus_manifest(corpus, names=chosen)

    assert len(full) == 20
    assert subset == [entry for entry in full if entry[0] in set(chosen)]


def _enable_run_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "run-metadata.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FRAMAC_IMAGE_ID", "sha256:test-image")
    monkeypatch.delenv("FRAMAC_CACHE", raising=False)
    monkeypatch.delenv("FRAMAC_CACHE_MODE", raising=False)
    monkeypatch.delenv("FRAMAC_SHARED_CACHE_DIR", raising=False)


def test_guardrail_only_hashes_selected_corpus_inputs_when_cache_enabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _enable_run_cache(tmp_path, monkeypatch)
    assert cache.enabled()
    calls = _stub_passing_guardrail(monkeypatch)

    corpus = tmp_path / "workspace" / "corpus"
    all_names = _make_corpus(corpus, count=50)
    binary = tmp_path / "workspace" / "harnesses" / "guard.e-acsl"
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_bytes(b"instrumented-binary")
    scratch = tmp_path / "workspace" / "harnesses" / "scratch"

    hashed = _spy_corpus_hashing(monkeypatch, corpus)
    verdict = R.run_guardrail_check(
        binary,
        corpus,
        scratch,
        runs=0,
        module="mod",
        seed=1,
        use_cache=True,
        max_corpus_inputs=4,
    )

    expected_chosen, _ = R.select_replay_inputs(all_names, 4)
    assert verdict["status"] == "passed_dynamic_oracle"
    assert verdict["corpus_total"] == 50
    assert verdict["corpus_replayed"] == 4
    assert verdict["corpus_sampled"] is True
    assert verdict["cache"]["hit"] is False and verdict["cache"]["key"]
    assert len(calls) == 1
    assert len(hashed) <= 4
    assert sorted(hashed) == expected_chosen

    # Second call hits the verdict cache and still hashes at most 4 files.
    hashed.clear()
    second = R.run_guardrail_check(
        binary,
        corpus,
        scratch,
        runs=0,
        module="mod",
        seed=1,
        use_cache=True,
        max_corpus_inputs=4,
    )
    assert second["status"] == "passed_dynamic_oracle"
    assert second["cache"] == {"hit": True, "key": verdict["cache"]["key"]}
    assert len(calls) == 1
    assert len(hashed) <= 4
    assert sorted(hashed) == expected_chosen


def test_guardrail_skips_corpus_hashing_when_cache_disabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    _stub_passing_guardrail(monkeypatch)

    corpus = tmp_path / "corpus"
    _make_corpus(corpus, count=50)
    binary = tmp_path / "guard.e-acsl"
    binary.write_bytes(b"instrumented-binary")
    scratch = tmp_path / "scratch"

    hashed = _spy_corpus_hashing(monkeypatch, corpus)
    verdict = R.run_guardrail_check(
        binary,
        corpus,
        scratch,
        runs=0,
        module="mod",
        seed=1,
        use_cache=False,
        max_corpus_inputs=4,
    )

    assert verdict["status"] == "passed_dynamic_oracle"
    assert verdict["corpus_total"] == 50
    assert verdict["corpus_replayed"] == 4
    assert verdict["corpus_sampled"] is True
    assert verdict["cache"] == {"hit": False, "key": None}
    assert hashed == []


def test_guardrail_skips_corpus_hashing_when_verdict_cache_disabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _enable_run_cache(tmp_path, monkeypatch)
    assert cache.enabled()
    _stub_passing_guardrail(monkeypatch)

    corpus = tmp_path / "corpus"
    _make_corpus(corpus, count=50)
    binary = tmp_path / "guard.e-acsl"
    binary.write_bytes(b"instrumented-binary")
    scratch = tmp_path / "scratch"

    hashed = _spy_corpus_hashing(monkeypatch, corpus)
    verdict = R.run_guardrail_check(
        binary,
        corpus,
        scratch,
        runs=0,
        module="mod",
        seed=1,
        use_cache=True,
        use_verdict_cache=False,
        max_corpus_inputs=4,
    )

    assert verdict["status"] == "passed_dynamic_oracle"
    assert verdict["corpus_total"] == 50
    assert verdict["corpus_replayed"] == 4
    assert verdict["cache"] == {"hit": False, "key": None}
    assert hashed == []


def test_guardrail_lazy_manifest_excludes_hanging_input_without_hashing_whole_corpus(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(R, "is_eacsl_instrumented", lambda _b: True)

    corpus = tmp_path / "corpus"
    all_names = _make_corpus(corpus, count=50)
    chosen, _ = R.select_replay_inputs(all_names, 4)
    hanging_name = chosen[0]
    hanging_bytes = (corpus / hanging_name).read_bytes()

    binary = tmp_path / "guard.e-acsl"
    binary.write_bytes(b"instrumented-binary")
    scratch = tmp_path / "scratch"

    attempt = {"n": 0}

    def fake_run(cmd: list[str], **_kw: object) -> SandboxResult:
        attempt["n"] += 1
        if attempt["n"] == 1:
            artifact = scratch / "timeout-deadbeef"
            artifact.write_bytes(hanging_bytes)
            out = (
                "ALARM: working on the last Unit for 10 seconds\n"
                "==1== ERROR: libFuzzer: timeout after 10 seconds\n"
                f"artifact_prefix='{scratch}/'; Test unit written to {artifact}\n"
            )
            return SandboxResult(70, "", out, False, "rlimits", list(cmd))
        return SandboxResult(0, "stat::number_of_executed_units: 3\n", "", False, "rlimits", list(cmd))

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_run)
    hashed = _spy_corpus_hashing(monkeypatch, corpus)

    verdict = R.run_guardrail_check(
        binary,
        corpus,
        scratch,
        runs=0,
        module="mod",
        seed=1,
        use_cache=False,
        max_corpus_inputs=4,
    )

    assert verdict["status"] == "passed_dynamic_oracle"
    assert verdict["corpus_total"] == 50
    assert verdict["corpus_replayed"] == 3
    assert [e["input"] for e in verdict["excluded_inputs"]] == [hanging_name]
    assert len(hashed) <= 4
    assert sorted(hashed) == chosen
