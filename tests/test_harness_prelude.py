"""Tests for automatic harness prelude resolution in scripts/generate_harness.py (WS4)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

import generate_harness
from generate_harness import (
    _header_defines_symbol,
    _include_dirs_from_cppflags,
    _parse_symbol_diagnostics,
    generate_module_harness,
    resolve_prelude_headers,
)

HARNESS_TEXT = (
    "#include <stdint.h>\n"
    "#include <stddef.h>\n"
    "\n"
    "/* Include module header and external boundary stubs */\n"
    '#include "Events.h"\n'
    "\n"
    "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { (void)data; (void)size; return 0; }\n"
)


class ScriptedClang:
    """Fake subprocess runner returning scripted clang stderr outputs, then clean runs."""

    def __init__(self, outputs: list[str] | None = None, dynamic=None) -> None:
        self.outputs = list(outputs or [])
        self.dynamic = dynamic
        self.calls: list[list[str]] = []
        self.harness_snapshots: list[str] = []

    def __call__(self, cmd, **kwargs):
        self.calls.append(list(cmd))
        harness_text = Path(cmd[-1]).read_text(encoding="utf-8")
        self.harness_snapshots.append(harness_text)
        if self.dynamic is not None:
            stderr = self.dynamic(len(self.calls) - 1, harness_text)
        else:
            stderr = self.outputs.pop(0) if self.outputs else ""
        return subprocess.CompletedProcess(cmd, 1 if stderr.strip() else 0, stdout="", stderr=stderr)


def diag(path: Path, kind: str, sym: str, suffix: str = "") -> str:
    msg = "unknown type name" if kind == "type" else "use of undeclared identifier"
    return f"{path.as_posix()}:12:5: error: {msg} '{sym}'{suffix}\n"


@pytest.fixture()
def tree(tmp_path: Path) -> dict[str, Path]:
    src = tmp_path / "src"
    src.mkdir()
    out = tmp_path / "harnesses"
    out.mkdir()
    events_h = src / "Events.h"
    events_h.write_text(
        "#ifndef EVENTS_H\n#define EVENTS_H\n"
        "Boolean_T SendEvent(const char *name, GST_CHAIN_MODE_T mode, char buf[CMD_NAME_MAX_LEN]);\n"
        "#endif\n",
        encoding="utf-8",
    )
    harness = out / "harness_events.c"
    harness.write_text(HARNESS_TEXT, encoding="utf-8")
    return {"root": tmp_path, "src": src, "out": out, "events_h": events_h, "harness": harness}


def _include_index(text: str, header: str) -> int:
    for idx, line in enumerate(text.splitlines()):
        if line.strip().startswith(f'#include "{header}"'):
            return idx
    raise AssertionError(f"{header} not included in harness:\n{text}")


class TestResolvePreludeHeaders:
    def test_typedef_resolved_and_inserted_before_module_header(self, tree: dict[str, Path]) -> None:
        """(a) Boolean_T is found as a typedef in PtfUtil.h and included before Events.h."""
        (tree["src"] / "PtfUtil.h").write_text("typedef unsigned char Boolean_T;\n", encoding="utf-8")
        runner = ScriptedClang([diag(tree["events_h"], "type", "Boolean_T")])

        res = resolve_prelude_headers(
            tree["harness"], f"-I{tree['src'].as_posix()}", "Events.h", clang="clang", runner=runner
        )

        assert res["status"] == "resolved"
        assert res["prelude_headers"] == ["PtfUtil.h"]
        assert res["unresolved_symbols"] == []
        assert res["iterations"] == 2
        text = tree["harness"].read_text(encoding="utf-8")
        assert _include_index(text, "PtfUtil.h") < _include_index(text, "Events.h")
        cmd = runner.calls[0]
        assert cmd[0] == "clang"
        assert "-fsyntax-only" in cmd
        assert cmd[cmd.index("-x") + 1] == "c"
        assert not any(tok.startswith("-D__FRAMAC__") for tok in cmd)
        assert cmd[-1] == str(tree["harness"])
        assert f"-I{tree['src'].as_posix()}" in cmd

    def test_enum_constant_resolution_ignores_references(self, tree: dict[str, Path]) -> None:
        """(b) An enum constant is resolved from the header whose enum body defines it, not one that references it."""
        (tree["src"] / "A.h").write_text(
            "enum Other { OTHER_A = GST_CHAIN_B, OTHER_B };\nint use_it(void) { return GST_CHAIN_B; }\n",
            encoding="utf-8",
        )
        (tree["src"] / "PtfUtil.h").write_text(
            "typedef enum {\n    GST_CHAIN_A = 0,\n    GST_CHAIN_B\n} GST_CHAIN_MODE_T;\n", encoding="utf-8"
        )
        runner = ScriptedClang([diag(tree["harness"], "ident", "GST_CHAIN_B", "; did you mean 'GST_CHAIN_A'?")])

        res = resolve_prelude_headers(
            tree["harness"], f"-I{tree['src'].as_posix()}", "Events.h", clang="clang", runner=runner
        )

        assert res["status"] == "resolved"
        assert res["prelude_headers"] == ["PtfUtil.h"]

    def test_define_resolution_ignores_comments(self, tree: dict[str, Path]) -> None:
        """(c) A #define is resolved; a commented-out #define in another header is ignored."""
        (tree["src"] / "A.h").write_text(
            "/* #define CMD_NAME_MAX_LEN 64 */\n// #define CMD_NAME_MAX_LEN 1\n", encoding="utf-8"
        )
        (tree["src"] / "Limits.h").write_text("#  define CMD_NAME_MAX_LEN 32\n", encoding="utf-8")
        runner = ScriptedClang([diag(tree["events_h"], "ident", "CMD_NAME_MAX_LEN")])

        res = resolve_prelude_headers(
            tree["harness"], f"-I{tree['src'].as_posix()}", "Events.h", clang="clang", runner=runner
        )

        assert res["status"] == "resolved"
        assert res["prelude_headers"] == ["Limits.h"]

    def test_iteration_discovers_second_header(self, tree: dict[str, Path]) -> None:
        """(d) A second clang run reveals another symbol defined in a different header."""
        (tree["src"] / "PtfUtil.h").write_text("typedef unsigned char Boolean_T;\n", encoding="utf-8")
        (tree["src"] / "Modes.h").write_text("typedef struct {\n  int m;\n} Mode_T, *PMode_T;\n", encoding="utf-8")
        runner = ScriptedClang(
            [
                diag(tree["events_h"], "type", "Boolean_T"),
                diag(tree["events_h"], "type", "Mode_T"),
            ]
        )

        res = resolve_prelude_headers(
            tree["harness"], f"-I{tree['src'].as_posix()}", "Events.h", clang="clang", runner=runner
        )

        assert res["status"] == "resolved"
        assert res["prelude_headers"] == ["PtfUtil.h", "Modes.h"]
        assert res["iterations"] == 3
        text = tree["harness"].read_text(encoding="utf-8")
        assert _include_index(text, "PtfUtil.h") < _include_index(text, "Modes.h") < _include_index(text, "Events.h")
        # Second run already saw the first prelude include.
        assert '#include "PtfUtil.h"' in runner.harness_snapshots[1]

    def test_dependency_of_prelude_header_is_inserted_before_it(self, tree: dict[str, Path]) -> None:
        """A symbol failing inside an earlier prelude header is satisfied by a header placed before it."""
        ptf = tree["src"] / "PtfUtil.h"
        ptf.write_text("typedef Base_T Boolean_T;\n", encoding="utf-8")
        (tree["src"] / "Types.h").write_text("typedef unsigned char Base_T;\n", encoding="utf-8")
        runner = ScriptedClang([diag(tree["events_h"], "type", "Boolean_T"), diag(ptf, "type", "Base_T")])

        res = resolve_prelude_headers(
            tree["harness"], f"-I{tree['src'].as_posix()}", "Events.h", clang="clang", runner=runner
        )

        assert res["status"] == "resolved"
        assert res["prelude_headers"] == ["Types.h", "PtfUtil.h"]
        text = tree["harness"].read_text(encoding="utf-8")
        assert _include_index(text, "Types.h") < _include_index(text, "PtfUtil.h") < _include_index(text, "Events.h")

    def test_iteration_cap_reached_is_unresolved(self, tree: dict[str, Path]) -> None:
        """(e) A new symbol keeps appearing; after max_iterations rewrite rounds the result is unresolved."""
        for i in range(5):
            (tree["src"] / f"H{i}.h").write_text(f"typedef int Sym{i}_T;\n", encoding="utf-8")
        runner = ScriptedClang(dynamic=lambda n, _text: diag(tree["events_h"], "type", f"Sym{n}_T"))

        res = resolve_prelude_headers(
            tree["harness"],
            f"-I{tree['src'].as_posix()}",
            "Events.h",
            max_iterations=2,
            clang="clang",
            runner=runner,
        )

        assert res["status"] == "unresolved"
        assert res["prelude_headers"] == ["H0.h", "H1.h"]
        assert res["unresolved_symbols"] == ["Sym2_T"]
        assert res["iterations"] == 3

    def test_symbol_without_definition_is_unresolved(self, tree: dict[str, Path]) -> None:
        """(e) No header defines the symbol: unresolved after a single clang run, harness unchanged."""
        runner = ScriptedClang([diag(tree["events_h"], "type", "Nowhere_T")])

        res = resolve_prelude_headers(
            tree["harness"], f"-I{tree['src'].as_posix()}", "Events.h", clang="clang", runner=runner
        )

        assert res["status"] == "unresolved"
        assert res["unresolved_symbols"] == ["Nowhere_T"]
        assert res["prelude_headers"] == []
        assert res["iterations"] == 1
        assert tree["harness"].read_text(encoding="utf-8") == HARNESS_TEXT

    def test_module_header_is_not_its_own_prelude(self, tree: dict[str, Path]) -> None:
        """The failing module header mentions the symbol but must never be picked for it."""
        tree["events_h"].write_text("typedef Boolean_T Flag_T;\n} Boolean_T;\n", encoding="utf-8")
        (tree["src"] / "PtfUtil.h").write_text("typedef unsigned char Boolean_T;\n", encoding="utf-8")
        runner = ScriptedClang([diag(tree["events_h"], "type", "Boolean_T")])

        res = resolve_prelude_headers(
            tree["harness"], f"-I{tree['src'].as_posix()}", "Events.h", clang="clang", runner=runner
        )

        assert res["prelude_headers"] == ["PtfUtil.h"]

    def test_clang_missing_is_skipped(self, tree: dict[str, Path], monkeypatch: pytest.MonkeyPatch) -> None:
        """(f) Without clang on PATH the resolver is skipped and never invokes the runner."""
        monkeypatch.setattr(generate_harness.shutil, "which", lambda _name: None)
        runner = ScriptedClang([diag(tree["events_h"], "type", "Boolean_T")])

        res = resolve_prelude_headers(tree["harness"], f"-I{tree['src'].as_posix()}", "Events.h", runner=runner)

        assert res == {
            "status": "skipped",
            "reason": "clang not found",
            "prelude_headers": [],
            "unresolved_symbols": [],
            "iterations": 0,
        }
        assert runner.calls == []
        assert tree["harness"].read_text(encoding="utf-8") == HARNESS_TEXT

    def test_clean_run_leaves_harness_unchanged(self, tree: dict[str, Path]) -> None:
        """(g) No diagnostics: status clean and the harness is byte-identical."""
        before = tree["harness"].read_bytes()
        runner = ScriptedClang([""])

        res = resolve_prelude_headers(
            tree["harness"], f"-I{tree['src'].as_posix()}", "Events.h", clang="clang", runner=runner
        )

        assert res["status"] == "clean"
        assert res["prelude_headers"] == []
        assert res["iterations"] == 1
        assert tree["harness"].read_bytes() == before

    def test_fatal_error_without_symbols_is_skipped(self, tree: dict[str, Path]) -> None:
        """A missing module header (fatal error) cannot be fixed by a prelude: report skipped, not clean."""
        runner = ScriptedClang([f"{tree['harness'].as_posix()}:5:10: fatal error: 'Events.h' file not found\n"])

        res = resolve_prelude_headers(tree["harness"], "-Inowhere", "Events.h", clang="clang", runner=runner)

        assert res["status"] == "skipped"
        assert "file not found" in res["reason"]

    def test_clang_finds_the_headers_the_build_generated(
        self, tree: dict[str, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """libpng's png.h includes the generated pnglibconf.h, which only the run snapshot has."""
        snap = tree["root"] / "snapshot"
        (snap / "generated/build").mkdir(parents=True)
        (snap / "generated/build/pnglibconf.h").write_text("#define PNG_LIBCONF 1\n", encoding="utf-8")
        (snap / "manifest.json").write_text(json.dumps({"digest": "d", "files": {}, "generated_dirs": ["build"]}))
        monkeypatch.setenv("FRAMAC_SNAPSHOT_DIR", str(snap))
        runner = ScriptedClang([])
        cppflags = f"-I{tree['src'].as_posix()}"

        res = resolve_prelude_headers(tree["harness"], cppflags, "Events.h", clang="clang", runner=runner)

        assert res["status"] == "clean"
        cmd = runner.calls[0]
        assert cmd[cmd.index("-idirafter") + 1] == (snap / "generated/build").as_posix()
        assert cmd[-1] == str(tree["harness"])

    def test_separated_include_flag_is_parsed(self, tree: dict[str, Path]) -> None:
        """(i) `-I dir` (separate token) is searched just like `-Idir`."""
        other = tree["root"] / "inc dir"
        other.mkdir()
        (other / "PtfUtil.h").write_text("typedef unsigned char Boolean_T;\n", encoding="utf-8")
        cppflags = f'-DFOO=1 -I "{other.as_posix()}" -I{tree["src"].as_posix()}'
        assert _include_dirs_from_cppflags(cppflags) == [Path(other.as_posix()), Path(tree["src"].as_posix())]

        runner = ScriptedClang([diag(tree["events_h"], "type", "Boolean_T")])
        res = resolve_prelude_headers(tree["harness"], cppflags, "Events.h", clang="clang", runner=runner)

        assert res["status"] == "resolved"
        assert res["prelude_headers"] == ["PtfUtil.h"]
        assert other.as_posix() in runner.calls[0]

    def test_most_covering_header_is_preferred(self, tree: dict[str, Path]) -> None:
        """When several headers define a symbol, the one defining the most unresolved symbols wins."""
        (tree["src"] / "A.h").write_text("typedef unsigned char Boolean_T;\n", encoding="utf-8")
        (tree["src"] / "PtfUtil.h").write_text(
            "typedef unsigned char Boolean_T;\n#define CMD_NAME_MAX_LEN 32\n", encoding="utf-8"
        )
        runner = ScriptedClang(
            [diag(tree["events_h"], "type", "Boolean_T") + diag(tree["events_h"], "ident", "CMD_NAME_MAX_LEN")]
        )

        res = resolve_prelude_headers(
            tree["harness"], f"-I{tree['src'].as_posix()}", "Events.h", clang="clang", runner=runner
        )

        assert res["prelude_headers"] == ["PtfUtil.h"]


class TestDefinitionHeuristics:
    @pytest.mark.parametrize(
        ("text", "symbol", "expected"),
        [
            ("typedef unsigned char Boolean_T;", "Boolean_T", True),
            ("typedef uint8_t Buf_T[16];", "Buf_T", True),
            ("typedef void (*Handler_T)(int);", "Handler_T", True),
            ("typedef struct { int a; } Pair_T, *PPair_T;", "Pair_T", True),
            ("typedef struct { int a; } Pair_T, *PPair_T;", "PPair_T", True),
            ("#define CMD_NAME_MAX_LEN 32", "CMD_NAME_MAX_LEN", True),
            ("enum E { A, B = 2, C };", "C", True),
            ("typedef Boolean_T Flag_T;", "Boolean_T", False),
            ("#define CMD_NAME_MAX_LEN_EXTRA 1", "CMD_NAME_MAX_LEN", False),
            ("enum E { A = C, B };", "C", False),
        ],
    )
    def test_header_defines_symbol(self, text: str, symbol: str, expected: bool) -> None:
        assert _header_defines_symbol(text, symbol) is expected

    def test_parse_diagnostics_variants(self) -> None:
        out = (
            "C:/w/src/Events.h:3:1: error: unknown type name 'Boolean_T'\n"
            "C:/w/harness.c:9:3: error: use of undeclared identifier 'GST_B'; did you mean 'GST_A'?\n"
            "C:/w/src/Events.h:4:1: error: unknown type name 'Boolean_T'\n"
            "C:/w/harness.c:10:3: warning: unused variable 'x'\n"
        )
        assert _parse_symbol_diagnostics(out) == {
            "Boolean_T": ["C:/w/src/Events.h"],
            "GST_B": ["C:/w/harness.c"],
        }


class TestGenerateModuleHarnessPrelude:
    def _gen(self, tree: dict[str, Path], **kw):
        return generate_module_harness(
            module_name="events",
            sources=[str(tree["src"] / "Events.c")],
            header_include=str(tree["events_h"]),
            entry_fn="SendEvent",
            max_input_size=256,
            cppflags="-I.",
            out_dir=tree["out"],
            entry_style="custom",
            call_expr='SendEvent("EVT", 0, (char *)fuzz_buf);',
            null_terminate=True,
            **kw,
        )

    def test_sidecar_records_prelude_fields(self, tree: dict[str, Path]) -> None:
        """(h) generate_module_harness auto-resolves the prelude and records it in the sidecar and result."""
        (tree["src"] / "PtfUtil.h").write_text("typedef unsigned char Boolean_T;\n", encoding="utf-8")
        runner = ScriptedClang([diag(tree["events_h"], "type", "Boolean_T")])

        res = self._gen(tree, prelude_clang="clang", prelude_runner=runner)

        assert res["prelude_status"] == "resolved"
        assert res["prelude_headers"] == ["PtfUtil.h"]
        assert res["prelude_unresolved"] == []
        sidecar = json.loads((tree["out"] / "harness_events.json").read_text(encoding="utf-8"))
        assert sidecar["prelude_headers"] == ["PtfUtil.h"]
        assert sidecar["prelude_status"] == "resolved"
        assert sidecar["prelude_unresolved"] == []
        text = (tree["out"] / "harness_events.c").read_text(encoding="utf-8")
        assert _include_index(text, "PtfUtil.h") < _include_index(text, "Events.h")
        # The clang probe used the normalized cppflags (module header dir added via -I).
        assert f"-I{tree['src'].as_posix()}" in runner.calls[0]

    def test_without_header_the_prelude_precedes_the_synthesized_declaration(self, tree: dict[str, Path]) -> None:
        """libpng `--api` without --header: `png_uint_32 f(void);` needs pngconf.h above it."""
        (tree["src"] / "png.c").write_text("png_uint_32 png_access_version_number(void) { return 1; }\n")
        (tree["src"] / "pngconf.h").write_text("typedef unsigned int png_uint_32;\n", encoding="utf-8")
        harness = tree["out"] / "harness_png.c"
        decl = "png_uint_32 png_access_version_number(void);"

        def clang(_: int, text: str) -> str:
            lines = [line.strip() for line in text.splitlines()]
            inc = next((i for i, line in enumerate(lines) if line.startswith('#include "pngconf.h"')), None)
            return "" if inc is not None and inc < lines.index(decl) else diag(harness, "type", "png_uint_32")

        res = generate_module_harness(
            module_name="png",
            sources=[str(tree["src"] / "png.c")],
            header_include=None,
            entry_fn="png_access_version_number",
            max_input_size=256,
            cppflags=f"-I{tree['src'].as_posix()}",
            out_dir=tree["out"],
            entry_style="void_call",
            prelude_clang="clang",
            prelude_runner=ScriptedClang(dynamic=clang),
        )

        assert res["prelude_status"] == "resolved" and res["prelude_headers"] == ["pngconf.h"]
        text = harness.read_text(encoding="utf-8")
        assert _include_index(text, "pngconf.h") < text.splitlines().index(decl)

    def test_unresolved_raises_after_writing_sidecar(self, tree: dict[str, Path]) -> None:
        runner = ScriptedClang([diag(tree["events_h"], "type", "Nowhere_T")])

        with pytest.raises(ValueError) as excinfo:
            self._gen(tree, prelude_clang="clang", prelude_runner=runner)

        msg = str(excinfo.value)
        assert "Nowhere_T" in msg
        assert "--extra-include" in msg
        assert "--no-auto-prelude" in msg
        sidecar = json.loads((tree["out"] / "harness_events.json").read_text(encoding="utf-8"))
        assert sidecar["prelude_status"] == "unresolved"
        assert sidecar["prelude_unresolved"] == ["Nowhere_T"]

    def test_auto_prelude_disabled(self, tree: dict[str, Path]) -> None:
        runner = ScriptedClang([diag(tree["events_h"], "type", "Nowhere_T")])

        res = self._gen(tree, auto_prelude=False, prelude_clang="clang", prelude_runner=runner)

        assert runner.calls == []
        assert res["prelude_status"] == "disabled"
        assert res["prelude_headers"] == []

    def test_cli_no_auto_prelude_flag(self, tree: dict[str, Path], monkeypatch: pytest.MonkeyPatch) -> None:
        def _boom(*_a, **_kw):
            raise AssertionError("clang must not run with --no-auto-prelude")

        monkeypatch.setattr(generate_harness.subprocess, "run", _boom)
        rc = generate_harness.main(
            [
                "--module",
                "events",
                "--sources",
                str(tree["src"] / "Events.c"),
                "--header",
                str(tree["events_h"]),
                "--entry-fn",
                "SendEvent",
                "--out-dir",
                str(tree["out"]),
                "--no-auto-prelude",
            ]
        )
        assert rc == 0
        sidecar = json.loads((tree["out"] / "harness_events.json").read_text(encoding="utf-8"))
        assert sidecar["prelude_status"] == "disabled"

    def test_non_symbol_clang_error_reports_prelude_status_error(self, tree: dict[str, Path]) -> None:
        """Duplicate definition or syntax error with non-zero clang return code reports prelude_status='error'."""
        runner = ScriptedClang(
            [f"{tree['harness'].as_posix()}:18:5: error: redefinition of 'LLVMFuzzerTestOneInput'\n"]
        )
        res = resolve_prelude_headers(
            tree["harness"], f"-I{tree['src'].as_posix()}", "Events.h", clang="clang", runner=runner
        )
        assert res["status"] == "error"
        assert "redefinition of 'LLVMFuzzerTestOneInput'" in res["reason"]

    def test_self_harnessed_optional_header_and_static_shim(self, tmp_path: Path) -> None:
        """Self-harnessed single-TU target with no --header, --include-source, and --static-analysis-include."""
        work = tmp_path / "workspace" / "work"
        work.mkdir(parents=True)
        canary_c = work / "canary.c"
        canary_c.write_text(
            "#include <stdint.h>\n#include <stddef.h>\n"
            "int canary_process(const uint8_t *data, size_t len) { return (int)len; }\n"
            "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
            "    return canary_process(data, size);\n"
            "}\n",
            encoding="utf-8",
        )
        shim_h = tmp_path / "workspace" / "headers" / "framac_shim.h"
        shim_h.parent.mkdir(parents=True)
        shim_h.write_text("typedef int __int32_t;\n", encoding="utf-8")
        out_dir = tmp_path / "workspace" / "harnesses"

        # Case 1: entry_fn == LLVMFuzzerTestOneInput -> emits only eva_main, no duplicate fuzzer entry
        res1 = generate_module_harness(
            module_name="canary_self",
            sources=[str(canary_c)],
            header_include=None,
            entry_fn="LLVMFuzzerTestOneInput",
            max_input_size=64,
            cppflags="",
            out_dir=out_dir,
            include_source=True,
            static_analysis_includes=[str(shim_h)],
            auto_prelude=False,
        )
        assert res1["self_harnessed"] is True
        h1_text = (out_dir / "harness_canary_self.c").read_text(encoding="utf-8")
        assert "int eva_main(void)" in h1_text
        assert h1_text.count("LLVMFuzzerTestOneInput(") == 1  # only the call inside eva_main
        assert "__int32_t" in h1_text  # inline Frama-C shim in template
        sidecar1 = json.loads((out_dir / "harness_canary_self.json").read_text(encoding="utf-8"))
        assert "-include" in sidecar1["cppflags"]
        assert shim_h.as_posix() in sidecar1["cppflags"]

        # Case 2: entry_fn == canary_process on a source that also defines LLVMFuzzerTestOneInput
        # -> auto-renames the embedded LLVMFuzzerTestOneInput around #include "canary.c"
        res2 = generate_module_harness(
            module_name="canary_wrap",
            sources=[str(canary_c)],
            header_include="none",
            entry_fn="canary_process",
            max_input_size=64,
            cppflags="",
            out_dir=out_dir,
            include_source=True,
            auto_prelude=False,
        )
        assert res2["self_harnessed"] is False
        h2_text = (out_dir / "harness_canary_wrap.c").read_text(encoding="utf-8")
        assert "#define LLVMFuzzerTestOneInput __framac_target_embedded_LLVMFuzzerTestOneInput" in h2_text
        assert "#undef LLVMFuzzerTestOneInput" in h2_text

    def test_embedded_fuzzer_initialize_is_renamed_too(self, tmp_path: Path) -> None:
        """A source's own LLVMFuzzerInitialize is renamed like its LLVMFuzzerTestOneInput (E-ACSL init hook)."""
        work = tmp_path / "workspace" / "work"
        work.mkdir(parents=True)
        canary_c = work / "canary.c"
        canary_c.write_text(
            "#include <stdint.h>\n#include <stddef.h>\n"
            "int canary_process(const uint8_t *data, size_t len) { return (int)len; }\n"
            "int LLVMFuzzerInitialize(int *argc, char ***argv) { (void)argc; (void)argv; return 0; }\n"
            "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { return canary_process(data, size); }\n",
            encoding="utf-8",
        )
        out_dir = tmp_path / "workspace" / "harnesses"
        common: dict[str, Any] = {
            "sources": [str(canary_c)],
            "header_include": "none",
            "entry_fn": "canary_process",
            "max_input_size": 64,
            "cppflags": "",
            "out_dir": out_dir,
            "auto_prelude": False,
        }
        generate_module_harness(module_name="inc", include_source=True, **common)
        inc_text = (out_dir / "harness_inc.c").read_text(encoding="utf-8")
        assert "#define LLVMFuzzerInitialize __framac_target_embedded_LLVMFuzzerInitialize" in inc_text
        assert "#undef LLVMFuzzerInitialize" in inc_text
        assert inc_text.index('#include "canary.c"') < inc_text.index("#undef LLVMFuzzerInitialize")

        res = generate_module_harness(module_name="sep", include_source=False, **common)
        assert "-DLLVMFuzzerInitialize=__framac_target_embedded_LLVMFuzzerInitialize" in res["cppflags"]
        assert "-DLLVMFuzzerTestOneInput=__framac_target_embedded_LLVMFuzzerTestOneInput" in res["cppflags"]
        assert "int LLVMFuzzerInitialize(" not in (out_dir / "harness_sep.c").read_text(encoding="utf-8")
