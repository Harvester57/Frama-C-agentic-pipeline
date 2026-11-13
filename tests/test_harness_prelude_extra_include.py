"""
The automatic prelude and `--extra-include` (scripts/generate_harness.py): an extra include that
defines what the module header needs is moved before it, by clang's verdict.

The fixture is the shape seen on PTF's xmlhandler: the module header uses a type that a header in a
subdirectory of an -I directory defines (`sub/types.h`, as `libxml/tree.h`), and the `--extra-include`
header includes that one. The definition search reads only the `*.h` files directly in the -I
directories, so it finds nothing; the extra include comes after the module header, so it is too late.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from generate_harness import EXTRA_INCLUDE_FIRST_MARK, generate_module_harness, resolve_prelude_headers

pytestmark = pytest.mark.unit


def _line_of(text: str, header: str) -> int:
    for idx, line in enumerate(text.splitlines()):
        if line.strip().startswith(f'#include "{header}"'):
            return idx
    raise AssertionError(f"{header} not included in:\n{text}")


class OrderClang:
    """
    A stand-in for `clang -fsyntax-only` that knows one thing about the fixture: `needs` (a header) uses
    `symbols`, which are declared only once `provider` (another header) has been included before it.
    """

    def __init__(self, needs: Path, provider: str, symbols: tuple[str, ...] = ("node_ptr",), always: str = "") -> None:
        self.needs, self.provider, self.symbols, self.always = needs, provider, symbols, always
        self.snapshots: list[str] = []

    def __call__(self, cmd, **kwargs):
        text = Path(cmd[-1]).read_text(encoding="utf-8")
        self.snapshots.append(text)
        stderr = self.always
        try:
            ok = _line_of(text, self.provider) < _line_of(text, self.needs.name)
        except AssertionError:
            ok = False
        if not ok:
            stderr += "".join(
                f"{self.needs.as_posix()}:3:5: error: unknown type name '{sym}'\n" for sym in self.symbols
            )
        return subprocess.CompletedProcess(cmd, 1 if stderr else 0, stdout="", stderr=stderr)


@pytest.fixture()
def xml_tree(tmp_path: Path) -> dict[str, Path]:
    src = tmp_path / "src"
    (src / "sub").mkdir(parents=True)
    out = tmp_path / "harnesses"
    out.mkdir()
    (src / "sub" / "types.h").write_text(
        "#ifndef SUB_TYPES_H\n#define SUB_TYPES_H\ntypedef struct node *node_ptr;\n#endif\n", encoding="utf-8"
    )
    (src / "mod_prelude.h").write_text('#include "sub/types.h"\n', encoding="utf-8")
    mod_h = src / "mod.h"
    mod_h.write_text(
        "#ifndef MOD_H\n#define MOD_H\nint handle_node(node_ptr n, const unsigned char *buf, unsigned long len);\n#endif\n",
        encoding="utf-8",
    )
    harness = out / "harness_mod.c"
    harness.write_text(
        '#include <stdint.h>\n#include <stddef.h>\n\n#include "mod.h"\n#include "mod_prelude.h"\n\n'
        "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { (void)data; (void)size; return 0; }\n",
        encoding="utf-8",
    )
    return {"src": src, "out": out, "mod_h": mod_h, "harness": harness}


def _generate(xml_tree: dict[str, Path], **kw):
    return generate_module_harness(
        module_name="mod",
        sources=[str(xml_tree["src"] / "mod.c")],
        header_include=str(xml_tree["mod_h"]),
        entry_fn="handle_node",
        max_input_size=64,
        cppflags="-I.",
        out_dir=xml_tree["out"],
        entry_style="custom",
        call_expr="(void)handle_node(0, fuzz_buf, fuzz_len);",
        extra_includes=[str(xml_tree["src"] / "mod_prelude.h")],
        **kw,
    )


def test_the_search_alone_leaves_the_identifier_unresolved(xml_tree: dict[str, Path]) -> None:
    """The reported failure: the definition is in a subdirectory, and the extra include comes too late."""
    before = xml_tree["harness"].read_text(encoding="utf-8")
    res = resolve_prelude_headers(
        xml_tree["harness"],
        f"-I{xml_tree['src'].as_posix()}",
        "mod.h",
        clang="clang",
        runner=OrderClang(xml_tree["mod_h"], "mod_prelude.h"),
    )

    assert res["status"] == "unresolved" and res["unresolved_symbols"] == ["node_ptr"]
    assert res["reason"] == "no defining header found in -I directories"
    assert xml_tree["harness"].read_text(encoding="utf-8") == before


def test_an_extra_include_that_defines_the_identifier_moves_before_the_module_header(
    xml_tree: dict[str, Path],
) -> None:
    runner = OrderClang(xml_tree["mod_h"], "mod_prelude.h")
    res = resolve_prelude_headers(
        xml_tree["harness"],
        f"-I{xml_tree['src'].as_posix()}",
        "mod.h",
        clang="clang",
        runner=runner,
        extra_includes=["mod_prelude.h"],
    )

    assert res["status"] == "resolved" and res["unresolved_symbols"] == []
    assert res["extra_includes_first"] == ["mod_prelude.h"] and res["prelude_headers"] == []
    assert res["iterations"] == 2  # the failing compile, then the one with the header moved
    text = xml_tree["harness"].read_text(encoding="utf-8")
    assert _line_of(text, "mod_prelude.h") < _line_of(text, "mod.h")
    assert text.count('#include "mod_prelude.h"') == 1 and EXTRA_INCLUDE_FIRST_MARK in text


def test_a_move_that_resolves_nothing_is_undone(xml_tree: dict[str, Path]) -> None:
    """The decision is clang's: an extra include that does not define the identifier stays where it was."""
    before = xml_tree["harness"].read_text(encoding="utf-8")
    runner = OrderClang(xml_tree["mod_h"], "some_other.h")
    res = resolve_prelude_headers(
        xml_tree["harness"],
        f"-I{xml_tree['src'].as_posix()}",
        "mod.h",
        clang="clang",
        runner=runner,
        extra_includes=["mod_prelude.h"],
    )

    assert res["status"] == "unresolved" and res["unresolved_symbols"] == ["node_ptr"]
    assert res["extra_includes_first"] == []
    assert len(runner.snapshots) == 2 and runner.snapshots[1] != before  # the move was tried
    assert xml_tree["harness"].read_text(encoding="utf-8") == before


def test_a_move_that_trades_the_identifier_for_another_error_is_undone(xml_tree: dict[str, Path]) -> None:
    before = xml_tree["harness"].read_text(encoding="utf-8")

    class Trading(OrderClang):
        def __call__(self, cmd, **kwargs):
            proc = super().__call__(cmd, **kwargs)
            if proc.returncode == 0:
                err = f"{Path(cmd[-1]).as_posix()}:4:1: error: redefinition of 'x'\n"
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr=err)
            return proc

    res = resolve_prelude_headers(
        xml_tree["harness"],
        f"-I{xml_tree['src'].as_posix()}",
        "mod.h",
        clang="clang",
        runner=Trading(xml_tree["mod_h"], "mod_prelude.h"),
        extra_includes=["mod_prelude.h"],
    )

    assert res["status"] == "unresolved" and res["extra_includes_first"] == []
    assert xml_tree["harness"].read_text(encoding="utf-8") == before


def test_the_move_is_also_tried_when_the_rewrite_rounds_are_spent(xml_tree: dict[str, Path]) -> None:
    """The search finds `Flag_T` in a project header (one round, the cap here); `node_ptr` is left for the move."""
    (xml_tree["src"] / "flags.h").write_text("typedef unsigned char Flag_T;\n", encoding="utf-8")
    order = OrderClang(xml_tree["mod_h"], "mod_prelude.h")

    def runner(cmd, **kwargs):
        proc = order(cmd, **kwargs)
        if '#include "flags.h"' in order.snapshots[-1]:
            return proc
        err = proc.stderr + f"{xml_tree['mod_h'].as_posix()}:4:1: error: unknown type name 'Flag_T'\n"
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr=err)

    res = resolve_prelude_headers(
        xml_tree["harness"],
        f"-I{xml_tree['src'].as_posix()}",
        "mod.h",
        max_iterations=1,
        clang="clang",
        runner=runner,
        extra_includes=["mod_prelude.h"],
    )

    assert res["status"] == "resolved" and res["unresolved_symbols"] == []
    assert res["prelude_headers"] == ["flags.h"] and res["extra_includes_first"] == ["mod_prelude.h"]
    text = xml_tree["harness"].read_text(encoding="utf-8")
    assert _line_of(text, "flags.h") < _line_of(text, "mod_prelude.h") < _line_of(text, "mod.h")


def test_the_sidecar_records_the_extra_include_that_comes_first(xml_tree: dict[str, Path]) -> None:
    res = _generate(xml_tree, prelude_clang="clang", prelude_runner=OrderClang(xml_tree["mod_h"], "mod_prelude.h"))

    assert res["prelude_status"] == "resolved" and res["prelude_unresolved"] == []
    assert res["extra_includes"] == ["mod_prelude.h"] and res["extra_includes_first"] == ["mod_prelude.h"]
    sidecar = json.loads((xml_tree["out"] / "harness_mod.json").read_text(encoding="utf-8"))
    assert sidecar["header"] == "mod.h" and sidecar["extra_includes"] == ["mod_prelude.h"]
    assert sidecar["extra_includes_first"] == ["mod_prelude.h"] and sidecar["prelude_headers"] == []
    text = (xml_tree["out"] / "harness_mod.c").read_text(encoding="utf-8")
    assert _line_of(text, "mod_prelude.h") < _line_of(text, "mod.h")


def test_nothing_unresolved_keeps_the_extra_include_after_the_module_header(xml_tree: dict[str, Path]) -> None:
    """`--header <root>.h --extra-include <mod>.h`: the documented order stays when the harness compiles."""

    def clean(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    for kw in ({"prelude_clang": "clang", "prelude_runner": clean}, {"auto_prelude": False}):
        res = _generate(xml_tree, **kw)
        text = (xml_tree["out"] / "harness_mod.c").read_text(encoding="utf-8")
        assert _line_of(text, "mod.h") < _line_of(text, "mod_prelude.h")
        assert EXTRA_INCLUDE_FIRST_MARK not in text
        sidecar = json.loads((xml_tree["out"] / "harness_mod.json").read_text(encoding="utf-8"))
        assert "extra_includes_first" not in sidecar and "extra_includes_first" not in res
        assert sidecar["extra_includes"] == ["mod_prelude.h"]


def test_an_identifier_failing_in_an_earlier_extra_include_gets_the_later_one_first(
    xml_tree: dict[str, Path],
) -> None:
    """Two extra includes, the first needing the second: the second moves up, the first stays in place."""
    uses_h = xml_tree["src"] / "uses.h"
    uses_h.write_text("node_ptr first_node(void);\n", encoding="utf-8")
    xml_tree["mod_h"].write_text("int handle_node(void *n);\n", encoding="utf-8")
    xml_tree["harness"].write_text(
        '#include <stdint.h>\n\n#include "mod.h"\n#include "uses.h"\n#include "mod_prelude.h"\n', encoding="utf-8"
    )
    res = resolve_prelude_headers(
        xml_tree["harness"],
        f"-I{xml_tree['src'].as_posix()}",
        "mod.h",
        clang="clang",
        runner=OrderClang(uses_h, "mod_prelude.h"),
        extra_includes=["uses.h", "mod_prelude.h"],
    )

    assert res["status"] == "resolved" and res["extra_includes_first"] == ["mod_prelude.h"]
    text = xml_tree["harness"].read_text(encoding="utf-8")
    assert _line_of(text, "mod_prelude.h") < _line_of(text, "mod.h") < _line_of(text, "uses.h")


@pytest.mark.skipif(shutil.which("clang") is None, reason="needs clang")
def test_with_clang_the_generated_harness_compiles_once_the_extra_include_is_first(
    xml_tree: dict[str, Path],
) -> None:
    res = _generate(xml_tree)

    assert res["prelude_status"] == "resolved" and res["extra_includes_first"] == ["mod_prelude.h"]
    proc = subprocess.run(
        ["clang", "-fsyntax-only", "-x", "c", *res["cppflags"].split(), res["harness_file"]],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
