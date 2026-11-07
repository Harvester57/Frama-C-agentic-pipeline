"""Remediation plan M1 (campaign auto-dictionary), M16 (guardrail crash_input), M18 (sidecar globals)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import fuzz_dictionary
import generate_harness
import run_eacsl_fuzz as R
from sandbox_exec import SandboxResult

EACSL_MARKER_BYTES = b"\x7fELF...__e_acsl_assert...eacsl_store_block"
EACSL_RTE_FAILURE = (
    "src/snmp/ber.c: In function 'ber_decode_len'\n"
    "src/snmp/ber.c:42: Error: Assertion failed:\n"
    "\tThe failing predicate is:\n"
    "\tmem_access: \\valid_read(buf + off).\n"
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# M1: auto-dictionary
# ---------------------------------------------------------------------------


def _slice(root: Path) -> tuple[Path, Path]:
    src = root / "src" / "mod.c"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text("int f(const char *s) { return s[0] == 'x' && !strcmp(s, \"MAGIC\"); }\n", encoding="utf-8")
    harness = root / "harness_mod.c"
    harness.write_text('static const char *h = "HARNESS_ONLY";\n', encoding="utf-8")
    return src, harness


def test_auto_dictionary_extracts_target_literals_excludes_harness_and_is_deterministic(tmp_path):
    src, harness = _slice(tmp_path)
    out = tmp_path / "dicts" / "mod.dict"
    first = R.build_auto_dictionary([str(src), str(harness)], out)
    text = out.read_text(encoding="utf-8")
    assert first["auto"] is True and first["path"] == out.as_posix()
    assert first["entries"] == len(fuzz_dictionary.build_dictionary(sources=[src])) > 0
    assert first["source_files"] == 1
    assert '"MAGIC"' in text and "HARNESS_ONLY" not in text
    # Same sources, given in another order: byte-identical dictionary.
    second = R.build_auto_dictionary([str(harness), str(src), str(src)], out)
    assert second == first and out.read_text(encoding="utf-8") == text
    assert not list(out.parent.glob(".tmp_*"))


def test_auto_dictionary_without_target_sources_proceeds_without_dict(tmp_path):
    _, harness = _slice(tmp_path)
    out = tmp_path / "dicts" / "mod.dict"
    info = R.build_auto_dictionary([str(harness), str(tmp_path / "missing.c")], out)
    assert info["path"] is None and info["entries"] == 0 and "no readable target sources" in info["reason"]
    assert not out.exists()


def test_auto_dictionary_failed_extraction_never_raises(tmp_path, monkeypatch):
    src, _ = _slice(tmp_path)

    def boom(**kwargs):
        raise RuntimeError("tokenizer exploded")

    monkeypatch.setattr(fuzz_dictionary, "build_dictionary", boom)
    info = R.build_auto_dictionary([str(src)], tmp_path / "d.dict")
    assert info["path"] is None and "tokenizer exploded" in info["reason"]

    monkeypatch.setattr(fuzz_dictionary, "build_dictionary", lambda **k: [])
    info = R.build_auto_dictionary([str(src)], tmp_path / "d.dict")
    assert info["path"] is None and info["reason"] == "extraction produced no tokens"


def test_auto_dictionary_path_is_per_module_else_next_to_corpus(tmp_path):
    assert R.auto_dictionary_path("snmp", tmp_path / "c") == Path("workspace/dicts/snmp.dict")
    assert R.auto_dictionary_path("a/b c", tmp_path / "c") == Path("workspace/dicts/a_b_c.dict")
    assert R.auto_dictionary_path("", tmp_path / "corpus" / "x") == tmp_path / "corpus" / "x.auto.dict"


def _run_campaign(tmp_path, monkeypatch, *extra) -> tuple[dict, dict]:
    monkeypatch.chdir(tmp_path)
    src, harness = _slice(tmp_path)
    instrumented = tmp_path / "fuzz_mod.e-acsl"
    monkeypatch.setattr(
        R,
        "compile_eacsl_binary",
        lambda *a, **k: {"engine": "eacsl", "returncode": 0, "binary": str(instrumented), "reduced_checks": []},
    )
    monkeypatch.setattr(R, "enforced_memory_mb", lambda: None)
    seen: dict = {}

    def fake_campaign(binary, corpus, artifacts, max_time, dict_file, *a, **k):
        seen["dict_file"] = dict_file
        seen["dict_text"] = Path(dict_file).read_text(encoding="utf-8") if dict_file else None
        return {"status": "clean", "artifacts": []}

    monkeypatch.setattr(R, "run_fuzz_campaign", fake_campaign)
    out_json = tmp_path / "out.json"
    argv = [
        "campaign",
        "--module",
        "mod",
        "--sources",
        "src/mod.c",
        "harness_mod.c",
        "--out-bin",
        "fuzz_mod",
        "--corpus-dir",
        "corpus",
        "--artifacts-dir",
        "crashes",
        "--workers",
        "1",
        "--max-time",
        "5",
        "--no-cache",
        "--no-attribution-replay",
        "--selftest-json",
        str(tmp_path / "selftest.json"),
        "--out-json",
        str(out_json),
        *extra,
    ]
    assert R.main(argv) == 0
    return json.loads(out_json.read_text(encoding="utf-8")), seen


def test_campaign_writes_and_uses_auto_dictionary(tmp_path, monkeypatch):
    report, seen = _run_campaign(tmp_path, monkeypatch)
    d = report["dictionary"]
    assert d["auto"] is True and d["path"] == "workspace/dicts/mod.dict" and d["entries"] > 0
    assert seen["dict_file"] == Path("workspace/dicts/mod.dict")
    assert '"MAGIC"' in seen["dict_text"] and "HARNESS_ONLY" not in seen["dict_text"]


def test_campaign_no_auto_dict_disables_extraction(tmp_path, monkeypatch):
    report, seen = _run_campaign(tmp_path, monkeypatch, "--no-auto-dict")
    assert seen["dict_file"] is None
    assert report["dictionary"] == {"path": None, "auto": False, "reason": "disabled by --no-auto-dict"}
    assert not (tmp_path / "workspace" / "dicts").exists()


def test_campaign_explicit_dict_wins(tmp_path, monkeypatch):
    mine = tmp_path / "mine.dict"
    mine.write_text('"X"\n', encoding="utf-8")
    report, seen = _run_campaign(tmp_path, monkeypatch, f"--dict={mine}")
    assert seen["dict_file"] == mine
    assert report["dictionary"] == {"path": mine.as_posix(), "auto": False, "exists": True}
    assert not (tmp_path / "workspace" / "dicts").exists()


def test_run_fuzz_campaign_passes_dictionary_to_libfuzzer(tmp_path, monkeypatch):
    calls: list[list[str]] = []

    def fake(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        calls.append(list(cmd))
        return SandboxResult(0, "", "", False, "rlimits", list(cmd))

    monkeypatch.setattr(R, "run_sandboxed", fake)
    monkeypatch.setattr(R, "enforced_memory_mb", lambda: None)
    src, _ = _slice(tmp_path)
    info = R.build_auto_dictionary([str(src)], tmp_path / "d" / "mod.dict")
    binary = tmp_path / "fuzz.e-acsl"
    binary.write_bytes(EACSL_MARKER_BYTES)
    R.run_fuzz_campaign(binary, tmp_path / "corpus", tmp_path / "arts", 5, Path(info["path"]))
    assert any(a.startswith("-dict=") for a in calls[0])


def test_fuzz_dictionary_render_matches_write(tmp_path):
    out = tmp_path / "x.dict"
    fuzz_dictionary.write_dictionary(out, ["a", "b"])
    assert out.read_bytes().decode("utf-8") == fuzz_dictionary.render_dictionary(["a", "b"])


# ---------------------------------------------------------------------------
# M16: guardrail crash_input
# ---------------------------------------------------------------------------


def _guard_setup(tmp_path, monkeypatch) -> tuple[Path, Path, Path]:
    monkeypatch.chdir(tmp_path)
    binary = tmp_path / "agents" / "a1" / "scratch" / "guard_mod.e-acsl"
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_bytes(EACSL_MARKER_BYTES)
    corpus = tmp_path / "workspace" / "corpus" / "mod"
    corpus.mkdir(parents=True, exist_ok=True)
    (corpus / "seed1").write_bytes(b"hello")
    return binary, corpus, Path("agents/a1/scratch/guard")


def _prefix(cmd: list[str]) -> str:
    return next(a for a in cmd if a.startswith("-artifact_prefix=")).split("=", 1)[1]


def test_guardrail_code_fault_records_crash_input(tmp_path, monkeypatch):
    binary, corpus, scratch = _guard_setup(tmp_path, monkeypatch)

    def fake(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        prefix = _prefix(cmd)
        Path(prefix + "crash-abc").write_bytes(b"CRASH")
        out = EACSL_RTE_FAILURE + f"artifact_prefix='{prefix}'; Test unit written to {prefix}crash-abc\n"
        return SandboxResult(1, "", out, False, "rlimits", list(cmd))

    monkeypatch.setattr(R, "run_sandboxed", fake)
    res = R.run_guardrail_check(binary, corpus, scratch, runs=5, module="mod", use_cache=False)
    assert res["status"] == "code_fault"
    assert res["crash_input"] == "agents/a1/scratch/guard/crash-abc"


def test_guardrail_crash_input_from_listing_without_log_line(tmp_path, monkeypatch):
    binary, corpus, scratch = _guard_setup(tmp_path, monkeypatch)
    scratch.mkdir(parents=True, exist_ok=True)
    (scratch / "crash-old").write_bytes(b"OLD")  # stale artifact from an earlier replay

    def fake(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        prefix = _prefix(cmd)
        Path(prefix + "timeout-zzz").write_bytes(b"T")
        Path(prefix + "crash-new").write_bytes(b"NEW")
        # A runtime_trace truncated past the "Test unit written" line.
        return SandboxResult(1, "", EACSL_RTE_FAILURE, False, "rlimits", list(cmd))

    monkeypatch.setattr(R, "run_sandboxed", fake)
    res = R.run_guardrail_check(binary, corpus, scratch, runs=5, module="mod", use_cache=False)
    assert res["status"] == "code_fault"
    assert res["crash_input"] == "agents/a1/scratch/guard/crash-new"


def test_guardrail_ignores_stale_artifacts_and_passing_runs(tmp_path, monkeypatch):
    binary, corpus, scratch = _guard_setup(tmp_path, monkeypatch)
    scratch.mkdir(parents=True, exist_ok=True)
    (scratch / "crash-old").write_bytes(b"OLD")

    rc = {"value": 1}

    def fake(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        return SandboxResult(rc["value"], "", EACSL_RTE_FAILURE if rc["value"] else "", False, "rlimits", list(cmd))

    monkeypatch.setattr(R, "run_sandboxed", fake)
    res = R.run_guardrail_check(binary, corpus, scratch, runs=5, module="mod", use_cache=False)
    assert res["status"] == "code_fault" and res["crash_input"] is None
    rc["value"] = 0
    res = R.run_guardrail_check(binary, corpus, scratch, runs=5, module="mod", use_cache=False)
    assert res["status"] == "passed_dynamic_oracle" and res["crash_input"] is None


def test_guardrail_crash_input_is_absolute_outside_the_run_dir(tmp_path, monkeypatch):
    prefix_dir = tmp_path / "elsewhere"
    prefix_dir.mkdir()
    (prefix_dir / "crash-x").write_bytes(b"x")
    (tmp_path / "run").mkdir()
    monkeypatch.chdir(tmp_path / "run")
    got = R.guardrail_crash_input(prefix_dir, {}, "")
    assert got == (prefix_dir / "crash-x").resolve().as_posix()


def test_guardrail_error_reports_carry_crash_input(tmp_path, monkeypatch):
    plain = tmp_path / "plain_bin"
    plain.write_bytes(b"\x7fELF plain")
    assert R.run_guardrail_check(plain, tmp_path / "c", tmp_path / "s")["crash_input"] is None

    monkeypatch.setattr(R, "compile_eacsl_binary", lambda *a, **k: {"returncode": 1, "reason": "boom"})
    out_json = tmp_path / "g.json"
    R.main(
        [
            "guardrail",
            "--sources",
            "m.c",
            "--out-bin",
            str(tmp_path / "gbin"),
            "--corpus-dir",
            str(tmp_path / "c"),
            "--out-json",
            str(out_json),
        ]
    )
    report = json.loads(out_json.read_text(encoding="utf-8"))
    assert report["status"] == "compile_error" and report["crash_input"] is None


# ---------------------------------------------------------------------------
# M18: sidecar records global_buffer globals
# ---------------------------------------------------------------------------


def test_sidecar_records_global_buffer_globals(tmp_path):
    out_dir = tmp_path / "harnesses"
    generate_harness.generate_module_harness(
        module_name="sync",
        sources=["src/SyncMem.c"],
        header_include="SyncMem.h",
        entry_fn="UpdateSyncMem",
        max_input_size=1500,
        cppflags="-Isrc",
        out_dir=out_dir,
        entry_style="global_buffer",
        global_buf="g_rx_buf",
        global_len="g_rx_len",
        include_source=True,
    )
    meta = json.loads((out_dir / "harness_sync.json").read_text(encoding="utf-8"))
    assert meta["global_buf"] == "g_rx_buf" and meta["global_len"] == "g_rx_len"

    generate_harness.generate_module_harness(
        module_name="nolen",
        sources=["src/SyncMem.c"],
        header_include="SyncMem.h",
        entry_fn="UpdateSyncMem",
        max_input_size=1500,
        cppflags="-Isrc",
        out_dir=out_dir,
        entry_style="global_buffer",
        global_buf="g_rx_buf",
        include_source=True,
    )
    meta = json.loads((out_dir / "harness_nolen.json").read_text(encoding="utf-8"))
    assert meta["global_buf"] == "g_rx_buf" and meta["global_len"] is None


def test_sidecar_globals_are_null_for_other_entry_styles(tmp_path):
    out_dir = tmp_path / "harnesses"
    generate_harness.generate_module_harness(
        module_name="msg",
        sources=["src/PtfMsg.c"],
        header_include="PtfMsg.h",
        entry_fn="CheckMessageValidity",
        max_input_size=1500,
        cppflags="-Isrc",
        out_dir=out_dir,
        entry_style="struct_arg",
        struct_type="T_PtfMsg",
        global_buf="ignored",
    )
    meta = json.loads((out_dir / "harness_msg.json").read_text(encoding="utf-8"))
    assert meta["global_buf"] is None and meta["global_len"] is None
