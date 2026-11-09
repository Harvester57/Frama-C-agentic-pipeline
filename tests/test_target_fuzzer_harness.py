"""Target fuzz modules: generate_harness.py --target-fuzzer and the run_eacsl_fuzz.py pieces that serve them."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

import generate_harness as G
import run_eacsl_fuzz as R
from sandbox_exec import SandboxResult
from validate_artifacts import schema_warning

pytestmark = pytest.mark.unit

FUZZER_SRC = "workspace/work/fuzz/fuzz_parse.c"
LIB_SRC = "workspace/work/src/parse.c"

FUZZER_BOTH_HOOKS = (
    "#include <stdint.h>\n#include <stddef.h>\n"
    "int parse(const uint8_t *buf, size_t len);\n"
    "static int ready;\n"
    "int LLVMFuzzerInitialize(int *argc, char ***argv) { (void)argc; (void)argv; ready = 1; return 0; }\n"
    "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
    "    if (ready) { parse(data, size); }\n"
    "    return 0;\n"
    "}\n"
)
FUZZER_ENTRY_ONLY = (
    "#include <stdint.h>\n#include <stddef.h>\n"
    "int parse(const uint8_t *buf, size_t len);\n"
    "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { return parse(data, size); }\n"
)


@pytest.fixture
def run_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "workspace/work/fuzz").mkdir(parents=True)
    (tmp_path / "workspace/work/src").mkdir(parents=True)
    (tmp_path / LIB_SRC).write_text(
        "#include <stdint.h>\n#include <stddef.h>\n"
        "int parse(const uint8_t *buf, size_t len) { return len > 0 ? buf[0] : 0; }\n",
        encoding="utf-8",
    )
    (tmp_path / FUZZER_SRC).write_text(FUZZER_BOTH_HOOKS, encoding="utf-8")
    return tmp_path


def _generate(*extra: str) -> int:
    return G.main(
        [
            "--module",
            "tf_fuzz_parse",
            "--unit",
            "libparse",
            "--sources",
            LIB_SRC,
            "--target-fuzzer",
            FUZZER_SRC,
            "--cppflags",
            "-Iworkspace/work/src",
            "--no-auto-prelude",
            *extra,
        ]
    )


def _sidecar(run_dir: Path, module: str = "tf_fuzz_parse") -> dict:
    return json.loads((run_dir / f"workspace/harnesses/harness_{module}.json").read_text(encoding="utf-8"))


def _harness(run_dir: Path, module: str = "tf_fuzz_parse") -> str:
    return (run_dir / f"workspace/harnesses/harness_{module}.c").read_text(encoding="utf-8")


def _eva_main(text: str) -> str:
    return text[text.index("int eva_main(void)") : text.index("#endif /* defined(__FRAMAC__)")]


def _fuzz_entry(text: str) -> str:
    return text[text.index("int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {") :]


# --- generate_harness.py --target-fuzzer ------------------------------------------------------


def test_target_fuzzer_renames_both_hooks_and_calls_them_on_the_copy(run_dir: Path) -> None:
    assert _generate() == 0
    side = _sidecar(run_dir)
    text = _harness(run_dir)

    # Both hooks are renamed in every build of the module; the harness keeps the real entry name.
    assert f"-DLLVMFuzzerTestOneInput={G.TARGET_EMBEDDED_ENTRY}" in side["cppflags"]
    assert f"-DLLVMFuzzerInitialize={G.TARGET_EMBEDDED_INIT}" in side["cppflags"]
    assert "#undef LLVMFuzzerTestOneInput\nint LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {" in text
    assert text.count("int LLVMFuzzerTestOneInput(") == 1
    # The harness never defines LLVMFuzzerInitialize (the E-ACSL init hook does); it declares the renamed one.
    assert "int LLVMFuzzerInitialize(" not in text
    assert f"int {G.TARGET_EMBEDDED_ENTRY}(const uint8_t *data, size_t size);" in text
    assert f"int {G.TARGET_EMBEDDED_INIT}(int *argc, char ***argv);" in text

    # libFuzzer path: size check, copy into the harness's own buffer, init once, then the call on fuzz_buf.
    fuzz = _fuzz_entry(text)
    assert "size > MAX_INPUT_SIZE" in fuzz
    assert fuzz.index("memcpy(bounded_buf, data, size);") < fuzz.index("__framac_target_initialize_once();")
    assert fuzz.index("__framac_target_initialize_once();") < fuzz.index(f"(void){G.TARGET_EMBEDDED_ENTRY}(fuzz_buf")
    assert f"(void){G.TARGET_EMBEDDED_ENTRY}(fuzz_buf, fuzz_len);" in fuzz
    assert "(data," not in fuzz.split("memcpy(bounded_buf, data, size);", 1)[1]
    # Eva path: the same run-once init and call.
    eva = _eva_main(text)
    assert eva.index("__framac_target_initialize_once();") < eva.index(f"{G.TARGET_EMBEDDED_ENTRY}(fuzz_buf")
    # The run-once flag: one call of the renamed LLVMFuzzerInitialize, guarded by a static flag.
    assert text.count(f"(void){G.TARGET_EMBEDDED_INIT}(") == 1
    assert "static int __framac_target_initialized = 0;" in text
    assert "if (__framac_target_initialized) {" in text

    assert side["target_fuzzer"] == {"id": "fuzz_parse", "source": FUZZER_SRC, "initialize": True}
    assert side["entry_fn"] == G.TARGET_EMBEDDED_ENTRY
    assert side["entry_style"] == "buffer_len"
    assert side["scope_files"] == ["fuzz/fuzz_parse.c"]
    assert side["sources"] == [LIB_SRC, FUZZER_SRC]
    assert side["unit"] == "libparse"
    assert side["self_harnessed"] is False
    assert side["reachability"] == "untrusted_surface"
    assert side["max_input_size"] == G.TARGET_FUZZER_DEFAULT_MAX_INPUT_SIZE
    assert "warnings" not in side
    assert schema_warning("harness_sidecar", side) is None


def test_target_fuzzer_without_initialize_calls_the_entry_only(run_dir: Path) -> None:
    (run_dir / FUZZER_SRC).write_text(FUZZER_ENTRY_ONLY, encoding="utf-8")
    assert _generate("--target-fuzzer-id", "parse-1", "--sources", FUZZER_SRC) == 0
    side = _sidecar(run_dir)
    text = _harness(run_dir)
    assert side["target_fuzzer"] == {"id": "parse-1", "source": FUZZER_SRC, "initialize": False}
    assert "-DLLVMFuzzerInitialize=" not in side["cppflags"]
    assert "initialize_once" not in text and G.TARGET_EMBEDDED_INIT not in text
    assert f"(void){G.TARGET_EMBEDDED_ENTRY}(fuzz_buf, fuzz_len);" in _fuzz_entry(text)
    # A fuzzer already among --sources is not added twice.
    assert side["sources"].count(FUZZER_SRC) == 1


def test_target_fuzzer_requires_unit_and_excludes_self_harnessed(run_dir: Path) -> None:
    base = ["--module", "tf_x", "--sources", LIB_SRC, "--target-fuzzer", FUZZER_SRC, "--no-auto-prelude"]
    with pytest.raises(SystemExit):
        G.main(base)
    with pytest.raises(SystemExit):
        G.main([*base, "--unit", "libparse", "--self-harnessed"])
    with pytest.raises(SystemExit):
        G.main([*base, "--unit", "libparse", "--target-fuzzer-id", "bad id"])
    with pytest.raises(ValueError, match="requires --unit"):
        G.generate_module_harness(
            "tf_x", [LIB_SRC], None, "f", 64, "-I.", Path("workspace/harnesses"), target_fuzzer=FUZZER_SRC
        )
    assert not (run_dir / "workspace/harnesses/harness_tf_x.json").exists()


def test_target_fuzzer_must_define_the_fuzz_entry(run_dir: Path) -> None:
    (run_dir / FUZZER_SRC).write_text("int not_a_fuzzer(void) { return 0; }\n", encoding="utf-8")
    assert _generate() == 1
    assert _generate_with_src("workspace/work/fuzz/missing.c") == 1


def _generate_with_src(src: str) -> int:
    return G.main(
        ["--module", "tf_m", "--unit", "u", "--sources", LIB_SRC, "--target-fuzzer", src, "--no-auto-prelude"]
    )


def test_target_fuzzer_max_input_size_from_fuzz_assets(run_dir: Path) -> None:
    reports = run_dir / "workspace/reports"
    reports.mkdir(parents=True)
    assets: dict[str, list[dict[str, Any]]] = {
        "fuzzers": [
            {"id": "other", "path": "fuzz/other.c", "work_path": "workspace/work/fuzz/other.c"},
            {
                "id": "fuzz_parse",
                "path": "fuzz/fuzz_parse.c",
                "work_path": FUZZER_SRC,
                "language": "c",
                "defines_initialize": True,
                "suggested_max_input_size": 12345,
            },
        ]
    }
    (reports / "fuzz_assets.json").write_text(json.dumps(assets), encoding="utf-8")
    assert _generate() == 0
    assert _sidecar(run_dir)["max_input_size"] == 12345
    assert "#define MAX_INPUT_SIZE 12345" in _harness(run_dir)

    # Explicit --max-size wins over fuzz_assets.json.
    assert _generate("--max-size", "77") == 0
    assert _sidecar(run_dir)["max_input_size"] == 77

    # Matched by id when the work path differs.
    assets["fuzzers"][1]["work_path"] = "elsewhere/fuzz_parse.c"
    (reports / "fuzz_assets.json").write_text(json.dumps(assets), encoding="utf-8")
    assert _generate() == 0
    assert _sidecar(run_dir)["max_input_size"] == 12345

    # No matching row: the target fuzzer default.
    assets["fuzzers"][1]["id"] = "renamed"
    (reports / "fuzz_assets.json").write_text(json.dumps(assets), encoding="utf-8")
    assert _generate() == 0
    assert _sidecar(run_dir)["max_input_size"] == G.TARGET_FUZZER_DEFAULT_MAX_INPUT_SIZE


def test_plain_harness_keeps_default_max_size(run_dir: Path) -> None:
    rc = G.main(
        [
            "--module",
            "plain",
            "--sources",
            LIB_SRC,
            "--entry-fn",
            "parse",
            "--header",
            "none",
            "--no-auto-prelude",
        ]
    )
    assert rc == 0
    side = _sidecar(run_dir, "plain")
    assert side["max_input_size"] == G.DEFAULT_MAX_INPUT_SIZE
    assert "target_fuzzer" not in side


def test_resolve_target_fuzzer_id() -> None:
    assert G.resolve_target_fuzzer_id("a/b/fuzz parse!.c") == "fuzz_parse_"
    assert G.resolve_target_fuzzer_id("x.c", "ok.id+1-2") == "ok.id+1-2"
    with pytest.raises(ValueError):
        G.resolve_target_fuzzer_id("x.c", "a/b")


@pytest.mark.skipif(shutil.which("clang") is None, reason="clang not installed")
def test_target_fuzzer_harness_compiles_with_its_sources(run_dir: Path) -> None:
    assert _generate() == 0
    side = _sidecar(run_dir)
    harness = run_dir / "workspace/harnesses/harness_tf_fuzz_parse.c"
    flags = side["cppflags"].split()
    for src in [str(harness), *side["sources"]]:
        proc = subprocess.run(
            ["clang", "-fsyntax-only", "-Wall", "-Werror", *flags, src],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert proc.returncode == 0, proc.stderr


# --- run_eacsl_fuzz.py ------------------------------------------------------------------------


def test_embedded_hooks_are_never_rte_selected(tmp_path: Path) -> None:
    src = tmp_path / "fuzz_parse.c"
    src.write_text(
        "int helper(int x) { return x; }\n"
        f"int {G.TARGET_EMBEDDED_ENTRY}(const unsigned char *d, unsigned long n) {{ return helper((int)n); }}\n"
        f"int {G.TARGET_EMBEDDED_INIT}(int *argc, char ***argv) {{ return 0; }}\n"
        "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { return 0; }\n",
        encoding="utf-8",
    )
    assert R._discover_slice_functions([str(src)]) == ["helper"]
    assert R.is_harness_fuzz_function(G.TARGET_EMBEDDED_INIT)
    assert not R.is_harness_fuzz_function("parse")


def test_embedded_entry_frame_is_skipped_in_sanitizer_reports() -> None:
    text = (
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000011\n"
        "READ of size 1 at 0x602000000011 thread T0\n"
        f"    #0 0x4f in {G.TARGET_EMBEDDED_ENTRY} /framac-run/workspace/work/fuzz/fuzz_parse.c:9:5\n"
        "    #1 0x50 in parse_body /framac-run/workspace/work/src/parse.c:12:3\n"
        "    #2 0x51 in LLVMFuzzerTestOneInput /framac-run/workspace/harnesses/harness_tf.c:100:5\n"
    )
    failure = R.parse_sanitizer_failure(text)
    assert failure is not None
    assert failure["function"] == "parse_body" and failure["line"] == 12


def test_embedded_entry_frame_is_skipped_in_eacsl_segment_reports() -> None:
    text = (
        "Invalid read\n"
        f"    #0 0x1 in {G.TARGET_EMBEDDED_ENTRY} /w/fuzz/fuzz_parse.c:9:5\n"
        "    #1 0x2 in parse_body /w/src/parse.c:12:3\n"
    )
    failure = R.parse_eacsl_failure(text)
    assert failure is not None
    assert failure["function"] == "parse_body" and failure["line"] == 12


# --- dictionary merge ------------------------------------------------------------------------


def _fake_auto(content: str | None):
    def build(sources, out_path, cppflags=None):
        if content is None:
            return {"path": None, "auto": True, "entries": 0, "reason": "extraction produced no tokens"}
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(content, encoding="utf-8")
        return {"path": out_path.as_posix(), "auto": True, "entries": len(content.splitlines())}

    return build


def test_extra_dictionary_is_merged_into_the_auto_dictionary(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(R, "build_auto_dictionary", _fake_auto('"GET"\n"PUT"\n'))
    extra = tmp_path / "workspace/dicts/mod.extra.dict"
    extra.parent.mkdir(parents=True)
    extra.write_text('# shipped\n"PUT"\nkw1="HEAD"\n\n"PUT"\n', encoding="utf-8")
    path, info = R.resolve_campaign_dictionary(None, ["a.c"], "mod", tmp_path / "corpus")
    assert path == Path("workspace/dicts/mod.dict")
    assert path.read_text(encoding="utf-8") == '"GET"\n"PUT"\nkw1="HEAD"\n'
    assert info["extra_entries"] == 1 and info["entries"] == 3


def test_extra_dictionary_alone_when_extraction_fails(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(R, "build_auto_dictionary", _fake_auto(None))
    extra = tmp_path / "workspace/dicts/mod.extra.dict"
    extra.parent.mkdir(parents=True)
    extra.write_text('"A"\n"B"\n', encoding="utf-8")
    path, info = R.resolve_campaign_dictionary(None, ["a.c"], "mod", tmp_path / "corpus")
    assert path == Path("workspace/dicts/mod.extra.dict")
    assert info["extra_entries"] == 2 and info["entries"] == 2


def test_explicit_dictionary_is_never_merged(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(R, "build_auto_dictionary", _fake_auto('"GET"\n'))
    extra = tmp_path / "workspace/dicts/mod.extra.dict"
    extra.parent.mkdir(parents=True)
    extra.write_text('"A"\n', encoding="utf-8")
    mine = tmp_path / "mine.dict"
    mine.write_text('"X"\n', encoding="utf-8")
    path, info = R.resolve_campaign_dictionary(mine, ["a.c"], "mod", tmp_path / "corpus")
    assert path == mine and "extra_entries" not in info
    assert mine.read_text(encoding="utf-8") == '"X"\n'
    # Without an extra dictionary the auto-dictionary record is unchanged.
    extra.unlink()
    _, info = R.resolve_campaign_dictionary(None, ["a.c"], "mod", tmp_path / "corpus")
    assert "extra_entries" not in info


# --- extra corpus directories ----------------------------------------------------------------


def test_campaign_passes_extra_corpus_dirs_in_order_and_skips_missing(tmp_path: Path, monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        calls.append(list(cmd))
        return SandboxResult(0, "", "", False, "rlimits", list(cmd))

    monkeypatch.setattr(R, "run_sandboxed", fake)
    monkeypatch.setattr(R, "enforced_memory_mb", lambda: None)
    binary = tmp_path / "fuzz_mod"
    binary.write_bytes(b"\x7fELF")
    seeds = tmp_path / "workspace/seeds/mod"
    imported = tmp_path / "workspace/imported_corpus/mod"
    missing = tmp_path / "workspace/nowhere/mod"
    for d in (seeds, imported):
        d.mkdir(parents=True)
    R.run_fuzz_campaign(binary, tmp_path / "corpus", tmp_path / "arts", 5, extra_corpus=[seeds, missing, imported])
    cmd = calls[0]
    corpus_args = cmd[cmd.index(str((tmp_path / "corpus").resolve())) :]
    assert corpus_args == [str((tmp_path / "corpus").resolve()), str(seeds.resolve()), str(imported.resolve())]
    assert str(missing.resolve()) not in cmd
