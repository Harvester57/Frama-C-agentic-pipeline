"""The API harness cases of functions defined in a public header (docs/plans/header-entry-points-plan.md,
H1 step 4): a case after every other generated one, built only when the layout probe saw the function."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

import api_harness as ah

pytestmark = pytest.mark.unit

HDR_FILE = "inc/lib.h"
HDR_SIG = {"signature": "int(int)", "formals": [{"name": "p0", "kind": "value"}]}


def _hdr_dag(names: list[str], header: list[str], static: list[str] = ()) -> dict:  # type: ignore[assignment]
    functions: dict[str, dict] = {}
    for n in names:
        is_header = n in header
        functions[n] = {
            "name": n,
            "file": HDR_FILE if is_header else "lib.c",
            "is_static": is_header or n in static,
            "header": is_header,
            "module": "lib",
        }
    return {
        "module_kind": "link_unit",
        "modules": {"lib": {"candidate_entry_points": names, "functions": names}},
        "functions": functions,
    }


def _hdr_model(dag: dict) -> dict:
    return {
        "status": "ok",
        "functions": {
            f"{rec['file']}#{n}": {
                **HDR_SIG,
                "name": n,
                "file": rec["file"],
                "static": rec["is_static"],
                "header": rec["header"],
            }
            for n, rec in dag["functions"].items()
        },
    }


def test_the_header_function_gets_a_case_after_the_exported_one() -> None:
    dag = _hdr_dag(["lib_decode", "lib_get_int", "decode_one"], header=["lib_get_int"], static=["decode_one"])
    model = _hdr_model(dag)
    visible = ah.Declared({"lib_decode", "lib_get_int"})
    p = ah.plan(dag, model, "lib", "lib", 64, struct_layouts={}, visible=visible)
    assert [(lay["selector"], lay["calls"], lay["entry"]) for lay in p["layouts"]] == [
        (0, ["lib_decode"], "lib_decode"),
        (1, ["lib_get_int"], "lib_get_int"),
    ]
    assert p["entries"] == ["lib_decode", "lib_get_int"]
    # A static function of a source file is still skipped.
    assert p["skipped"] == {"decode_one": "static: not callable from the harness"}
    # The exported function's case is the one it had without the header function.
    alone = ah.plan(_hdr_dag(["lib_decode"], header=[]), model, "lib", "lib", 64, struct_layouts={}, visible=visible)
    assert alone["cases"] == p["cases"][:1] and alone["layouts"] == p["layouts"][:1]


def test_without_the_layout_probe_the_header_function_is_skipped() -> None:
    dag = _hdr_dag(["lib_decode", "lib_get_int"], header=["lib_get_int"])
    model = _hdr_model(dag)
    p = ah.plan(dag, model, "lib", "lib", 64)
    assert [lay["calls"] for lay in p["layouts"]] == [["lib_decode"]]
    assert p["skipped"] == {"lib_get_int": ah.HEADER_NOT_VISIBLE}
    # The probe ran but the harness does not declare it (another header).
    p = ah.plan(dag, model, "lib", "lib", 64, struct_layouts={}, visible=ah.Declared({"lib_decode"}))
    assert p["skipped"] == {"lib_get_int": ah.HEADER_NOT_VISIBLE}


def _box_trace() -> list[dict]:
    return [
        {"fn": "keypair", "args": {}, "addrs": {"0": "100", "1": "200"}},
        {"fn": "box", "args": {"1": [["b", 0, "6869"]]}, "addrs": {"0": "300", "1": "301", "3": "100", "4": "200"}},
    ]


def test_header_cases_come_after_the_sequence_cases_which_keep_their_bodies() -> None:
    names = ["keypair", "box", "h_get"]
    dag = _hdr_dag(names, header=["h_get"])
    model = _hdr_model(dag)
    model["functions"]["lib.c#keypair"].update(
        signature="int(unsigned char *,unsigned char *)",
        formals=[{"name": "p0", "kind": "pointer"}, {"name": "p1", "kind": "pointer"}],
    )
    model["functions"]["lib.c#box"].update(
        signature="int(unsigned char *,unsigned char *,unsigned long long,unsigned char *,unsigned char *)",
        formals=None,
    )
    visible = ah.Declared(set(names))
    p = ah.plan(dag, model, "lib", "lib", 64, [_box_trace()], struct_layouts={}, visible=visible)
    assert [lay["kind"] for lay in p["layouts"]] == ["single", "single", "sequence", "single"]
    assert p["layouts"][-1]["entry"] == "h_get"
    before = ah.plan(
        _hdr_dag(["keypair", "box"], header=[]), model, "lib", "lib", 64, [_box_trace()], struct_layouts={},
        visible=visible,
    )  # fmt: skip
    assert p["cases"][:3] == before["cases"] and p["layouts"][:3] == before["layouts"]


def test_header_functions_go_first_over_the_case_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    names = ["a", "h_one", "b", "h_two"]
    dag = _hdr_dag(names, header=["h_one", "h_two"])
    model = _hdr_model(dag)
    monkeypatch.setattr(ah, "MAX_CASES", 3)
    p = ah.plan(dag, model, "lib", "lib", 64, struct_layouts={}, visible=ah.Declared(set(names)))
    assert [lay["entry"] for lay in p["layouts"]] == ["a", "b", "h_one"]
    assert p["skipped"] == {"h_two": f"more than {ah.MAX_CASES} cases"}


def test_a_variadic_header_function_is_skipped() -> None:
    dag = _hdr_dag(["a", "h_log"], header=["h_log"])
    model = _hdr_model(dag)
    model["functions"][f"{HDR_FILE}#h_log"]["signature"] = "int(char *,...)"
    p = ah.plan(dag, model, "lib", "lib", 64, struct_layouts={}, visible=ah.Declared({"a", "h_log"}))
    assert p["skipped"] == {"h_log": ah.HEADER_VARIADIC}


# --- generate(): sources and the hand-written cases (HD4) ------------------------------------------------


def _hdr_generate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    header: list[str],
    exported: tuple[str, ...] = (),
) -> tuple[Path, list[dict]]:
    """`exported`: the functions of `header` with a global symbol (an inline the library also emits)."""
    import generate_harness

    monkeypatch.chdir(tmp_path)
    out = tmp_path / "workspace" / "harnesses"
    out.mkdir(parents=True)
    names = ["a", *header]
    dag = _hdr_dag(names, header=header)
    for n in exported:
        dag["functions"][n]["is_static"] = False
    (tmp_path / "dag.json").write_text(json.dumps(dag))
    (tmp_path / "model.json").write_text(json.dumps(_hdr_model(dag)))
    calls: list[dict] = []

    def fake_generate(**kw: Any) -> dict:
        calls.append(kw)
        cases = list(kw["dispatch_cases"])
        harness = out / f"harness_{kw['module_name']}.c"
        harness.write_text("".join(f"    case {i}U: {{ {c} }} break;\n" for i, c in enumerate(cases)))
        meta = out / f"harness_{kw['module_name']}.json"
        meta.write_text(json.dumps({"module": kw["module_name"], "dispatch_cases": cases}))
        return {"harness_file": str(harness), "harness_meta": str(meta), "cppflags": ""}

    monkeypatch.setattr(generate_harness, "generate_module_harness", fake_generate)
    monkeypatch.setattr(ah, "probe_layouts", lambda *a, **k: ({}, ah.Declared(set(names))))
    monkeypatch.setattr(ah, "probe_cases", lambda h, c, clang=None: ({}, []))
    ah.generate(
        "lib",
        None,
        64,
        "",
        out,
        unit="lib",
        dag_path=Path("dag.json"),
        model_path=Path("model.json"),
        traces_path=Path("none/traces.jsonl"),
        dispatch_cases=["(void)hand();"],
        variadic={},
    )
    return out, calls


def test_hand_written_cases_move_behind_the_header_cases(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out, calls = _hdr_generate(tmp_path, monkeypatch, header=["h_get"])
    meta = json.loads((out / "harness_lib.json").read_text())
    assert [(lay["selector"], lay["kind"], lay.get("entry")) for lay in meta["api_cases"]] == [
        (0, "single", "a"),
        (1, "single", "h_get"),
        (2, "custom", None),
    ]
    # The header is compiled through the harness's include, not as a source.
    assert all(not str(s).endswith(".h") for s in calls[-1]["sources"])
    assert "lib.c" in calls[-1]["sources"]


def test_an_exported_function_a_header_defines_keeps_its_header_in_the_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    mpack's MPACK_INLINE functions have a global symbol and are defined in a header. Their header
    stays in the harness's sources (E-ACSL's function discovery and the module scope read it; the
    clang builds leave it out, tests/test_clang_build_inputs.py). Only a `static` header function,
    which fuzz_build names from the sidecar's cases, adds no source.
    """
    out, calls = _hdr_generate(tmp_path, monkeypatch, header=["h_inline"], exported=("h_inline",))
    assert calls[-1]["sources"] == [HDR_FILE, "lib.c"]
    meta = json.loads((out / "harness_lib.json").read_text())
    assert [(lay["kind"], lay.get("entry")) for lay in meta["api_cases"]] == [
        ("single", "a"),
        ("single", "h_inline"),
        ("custom", None),
    ]


def test_without_header_cases_the_hand_written_case_follows_the_exported_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out, _ = _hdr_generate(tmp_path, monkeypatch, header=[])
    meta = json.loads((out / "harness_lib.json").read_text())
    assert [(lay["selector"], lay["kind"]) for lay in meta["api_cases"]] == [(0, "single"), (1, "custom")]


# --- a real compile ---------------------------------------------------------------------------------------

HDR_LIB_H = "int lib_decode(int x);\nstatic inline int lib_get_int(int x) { return lib_decode(x) + 1; }\n"


@pytest.mark.skipif(shutil.which("clang") is None, reason="needs clang")
def test_the_probe_sees_the_header_function_and_its_case_compiles(tmp_path: Path) -> None:
    (tmp_path / "lib.h").write_text(HDR_LIB_H)
    harness = tmp_path / "harness_lib.c"
    prologue = (
        '#include <stddef.h>\n#include <string.h>\n#include "lib.h"\n'
        "#define FRAMAC_FUZZ_COPY(buf, off) ((buf) + (off))\n"
        "void run(const unsigned char *fuzz_buf, size_t fuzz_len) {\n    size_t fuzz_off = 0;\n"
        "    switch (fuzz_len % 2U) {\n"
    )
    harness.write_text(prologue + "    }\n}\n")
    probed = ah.probe_layouts(harness, f"-I{tmp_path.as_posix()}")
    assert probed is not None
    layouts, visible = probed
    assert {"lib_decode", "lib_get_int"} <= set(visible)

    dag = _hdr_dag(["lib_decode", "lib_get_int"], header=["lib_get_int"])
    p = ah.plan(dag, _hdr_model(dag), "lib", "lib", 64, struct_layouts=layouts, visible=visible)
    assert [lay["entry"] for lay in p["layouts"]] == ["lib_decode", "lib_get_int"]
    body = "".join(f"    case {i}U: {{ {c} }} break;\n" for i, c in enumerate(p["cases"]))
    harness.write_text(prologue + body + "    }\n}\n")
    proc = subprocess.run(
        ["clang", "-fsyntax-only", "-x", "c", f"-I{tmp_path.as_posix()}", str(harness)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
