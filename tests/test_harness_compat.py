"""Regression tests for generate_harness.py fixes from the libssh2 onboarding run:
PB-4/PB-5 source-side compat includes, declaring-header auto-detection, and
call_expr arity validation against the definition."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from generate_harness import generate_module_harness


def _mini_target(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    """include/pub.h (public, no entry decl), include/priv.h (declares entry), src/mod.c, compat.h."""
    inc = tmp_path / "include"
    src = tmp_path / "src"
    inc.mkdir(parents=True)
    src.mkdir(parents=True)
    pub = inc / "pub.h"
    pub.write_text("#ifndef PUB_H\n#define PUB_H\nint public_api(int x);\n#endif\n", encoding="utf-8")
    priv = inc / "priv.h"
    priv.write_text(
        "#ifndef PRIV_H\n#define PRIV_H\nint my_entry(int a, int b, int c);\n#endif\n", encoding="utf-8"
    )
    mod = src / "mod.c"
    mod.write_text("int my_entry(int a, int b, int c) { return a + b + c; }\n", encoding="utf-8")
    compat = tmp_path / "compat.h"
    compat.write_text("struct opaque_st { void *fz_dummy; };\n", encoding="utf-8")
    return pub, priv, mod, compat


def test_compat_include_is_source_side_not_force_include(tmp_path: Path) -> None:
    pub, _priv, mod, compat = _mini_target(tmp_path)
    out_dir = tmp_path / "harnesses"
    res = generate_module_harness(
        module_name="mod",
        sources=[str(mod)],
        header_include=str(pub),
        entry_fn="my_entry",
        max_input_size=64,
        cppflags=f"-I{tmp_path / 'include'}",
        out_dir=out_dir,
        entry_style="buffer_len",
        compat_includes=[str(compat)],
        auto_prelude=False,
    )
    harness_text = (out_dir / "harness_mod.c").read_text(encoding="utf-8")
    sidecar = json.loads((out_dir / "harness_mod.json").read_text(encoding="utf-8"))
    # Source-side include in the harness, after the module header...
    assert '#include "compat.h"' in harness_text
    assert harness_text.index('#include "pub.h"') < harness_text.index('#include "compat.h"')
    # ...and never a -include force-include in cppflags (PB-4 kernel crash trigger).
    assert "-include" not in sidecar["cppflags"]
    assert sidecar["compat_includes"] == ["compat.h"]
    assert res["compat_includes"] == ["compat.h"]


def test_declaring_header_autodetected_when_module_header_lacks_entry(tmp_path: Path) -> None:
    pub, priv, mod, _compat = _mini_target(tmp_path)
    out_dir = tmp_path / "harnesses"
    res = generate_module_harness(
        module_name="mod",
        sources=[str(mod)],
        header_include=str(pub),  # public header does NOT declare my_entry
        entry_fn="my_entry",
        max_input_size=64,
        cppflags=f"-I{tmp_path / 'include'}",
        out_dir=out_dir,
        entry_style="buffer_len",
        auto_prelude=False,
    )
    assert "priv.h" in res["extra_includes"]
    harness_text = (out_dir / "harness_mod.c").read_text(encoding="utf-8")
    assert '#include "priv.h"' in harness_text


def test_call_expr_arity_validated_against_definition(tmp_path: Path) -> None:
    pub, _priv, mod, _compat = _mini_target(tmp_path)
    out_dir = tmp_path / "harnesses"
    # my_entry takes 3 parameters; a 1-argument call must be rejected early.
    with pytest.raises(ValueError, match="argument"):
        generate_module_harness(
            module_name="mod",
            sources=[str(mod)],
            header_include=str(pub),
            entry_fn="my_entry",
            max_input_size=64,
            cppflags=f"-I{tmp_path / 'include'}",
            out_dir=out_dir,
            entry_style="custom",
            call_expr="my_entry(fuzz_buf);",
            auto_prelude=False,
        )
    # The correct arity passes.
    res = generate_module_harness(
        module_name="mod",
        sources=[str(mod)],
        header_include=str(pub),
        entry_fn="my_entry",
        max_input_size=64,
        cppflags=f"-I{tmp_path / 'include'}",
        out_dir=out_dir,
        entry_style="custom",
        call_expr="my_entry(fuzz_buf, fuzz_len, 3);",
        auto_prelude=False,
    )
    assert res["module"] == "mod"
