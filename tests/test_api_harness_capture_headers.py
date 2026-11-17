"""
`--api` without `--header` takes the unit's headers from the build capture (step O4 of
docs/plans/open-topics-remediation-plan.md). On nettle, `--header none` made 22 of 35 libnettle
clusters fail: the harness declared only its first entry point and the compile probe dropped every
other case as `call to undeclared function`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import api_harness as ah

pytestmark = pytest.mark.unit

PUB_H = "include/x/pub.h"
INTERNAL_H = "src/x-internal.h"
CONFIG_H = "src/config.h"
# nettle's style: the internal header renames the function with a macro and declares the short name.
HEADER_TEXT = {
    PUB_H: "#ifndef PUB_H\n#define PUB_H\nint a(int x);\nint b(int x);\n#endif\n",
    INTERNAL_H: "#define c_impl _nettle_c\nint c_impl(int x);\n",
    CONFIG_H: "#define HAVE_X 1\n",
}
ENTRIES = ["a", "b", "_nettle_c"]


def _capture(public: list[str] | None = None, units: bool = True) -> dict[str, Any]:
    cap: dict[str, Any] = {
        "public_headers": {
            "method": "install",
            "files": public if public is not None else ["/framac-scratch/install/include/x/pub.h"],
        },
        "compiles": [
            {
                "source": "src/a.c",
                "object": "src/a.o",
                "headers": [CONFIG_H, PUB_H, INTERNAL_H, "/usr/include/stdio.h"],
            },
            # Another unit's compile: its header is no header of this unit.
            {"source": "tools/t.c", "object": "tools/t.o", "headers": ["tools/tool.h"]},
        ],
    }
    if units:
        cap["units"] = {"libx.a": {"kind": "static_lib", "objects": ["src/a.o"]}}
    return cap


def _setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capture: dict | None, target_dir: str | None = None
) -> tuple[Path, list[dict]]:
    """A DAG module `lib` of link unit `libx.a`, its headers on disk, and a logging fake harness writer."""
    import generate_harness

    tmp_path.mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(tmp_path)
    root = Path(target_dir[len("/framac-run/") :]) if target_dir else Path(".")
    for rel, text in HEADER_TEXT.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8", newline="\n")
    out = tmp_path / "workspace" / "harnesses"
    out.mkdir(parents=True)
    functions = {f"src/a.c#{n}": {"name": n, "file": "src/a.c", "is_static": False, "module": "lib"} for n in ENTRIES}
    dag: dict[str, Any] = {
        "module_kind": "link_unit",
        "modules": {
            "lib": {
                "unit": "libx.a",
                "files": ["src/a.c"],
                "candidate_entry_points": list(functions),
                "functions": list(functions),
            }
        },
        "functions": functions,
    }
    if target_dir:
        dag["target_dir"] = target_dir
    model = {
        "status": "ok",
        "functions": {k: {"signature": "int(int)", "formals": [{"name": "p0", "kind": "value"}]} for k in functions},
    }
    (tmp_path / "dag.json").write_text(json.dumps(dag), encoding="utf-8")
    (tmp_path / "model.json").write_text(json.dumps(model), encoding="utf-8")
    if capture is not None:
        (tmp_path / "build_capture.json").write_text(json.dumps(capture), encoding="utf-8")
    calls: list[dict] = []

    def fake_generate(**kw: Any) -> dict:
        calls.append(kw)
        cases = list(kw["dispatch_cases"])
        harness = out / f"harness_{kw['module_name']}.c"
        # The cases first (line i is case i), then the headers the harness includes, for the fake probes.
        includes = [h for h in [kw["header_include"], *(kw["extra_includes"] or [])] if h]
        harness.write_text(
            "".join(f"    case {i}U: {{ {c} }} break;\n" for i, c in enumerate(cases))
            + "".join(f'#include "{h}"\n' for h in includes)
        )
        meta = out / f"harness_{kw['module_name']}.json"
        sidecar = {
            "module": kw["module_name"],
            "harness_file": harness.as_posix(),
            "sources": list(kw["sources"]),
            "cppflags": "",
            "entry_fn": kw["entry_fn"],
            "entry_style": "dispatch",
            "dispatch_cases": cases,
        }
        meta.write_text(json.dumps(sidecar))
        return {"harness_file": str(harness), "harness_meta": str(meta), "cppflags": ""}

    monkeypatch.setattr(generate_harness, "generate_module_harness", fake_generate)
    monkeypatch.setattr(ah, "probe_layouts", lambda *a, **k: None)
    monkeypatch.setattr(ah, "probe_cases", lambda *a, **k: ({}, []))
    return out, calls


def _run(out: Path, header: str | None = None, **kw: Any) -> dict:
    return ah.generate(
        "lib",
        header,
        64,
        "",
        out,
        unit="lib",
        dag_path=Path("dag.json"),
        model_path=Path("model.json"),
        traces_path=Path("none/traces.jsonl"),
        variadic={},
        **kw,
    )


def _sidecar(out: Path) -> dict:
    return json.loads((out / "harness_lib.json").read_text(encoding="utf-8"))


def test_the_capture_gives_the_public_header_and_the_internal_one_declaring_an_entry_point(tmp_path, monkeypatch):
    out, calls = _setup(tmp_path, monkeypatch, _capture())
    res = _run(out)

    # The installed header maps back to its tree header; the internal one declares `_nettle_c`
    # through its renaming macro; config.h declares nothing and another unit's header is not taken.
    assert calls[-1]["header_include"] == PUB_H
    assert calls[-1]["extra_includes"] == [INTERNAL_H]
    assert "api_warnings" not in res
    meta = _sidecar(out)
    assert meta["api_headers"] == {
        "source": "capture",
        "why": meta["api_headers"]["why"],
        "unit": "libx.a",
        "public": [PUB_H],
        "internal": [{"header": INTERNAL_H, "declares": ["_nettle_c"]}],
    }
    assert "--header not given" in meta["api_headers"]["why"]
    from validate_artifacts import schema_problems

    assert not [p for p in schema_problems("harness_sidecar", meta) if "api_headers" in p]
    assert [p for p in schema_problems("harness_sidecar", {**meta, "api_headers": {"source": "guess", "why": "x"}})]


def test_a_given_extra_include_comes_after_the_chosen_headers(tmp_path, monkeypatch):
    out, calls = _setup(tmp_path, monkeypatch, _capture())
    _run(out, extra_includes=["mine.h"])
    assert calls[-1]["header_include"] == PUB_H
    assert calls[-1]["extra_includes"] == [INTERNAL_H, "mine.h"]


def test_the_headers_are_rooted_where_the_dag_cppflags_are(tmp_path, monkeypatch):
    out, calls = _setup(tmp_path, monkeypatch, _capture(), target_dir="/framac-run/workspace/work")
    _run(out)
    assert calls[-1]["header_include"] == f"workspace/work/{PUB_H}"
    assert calls[-1]["extra_includes"] == [f"workspace/work/{INTERNAL_H}"]
    # The sidecar records the tree paths.
    assert _sidecar(out)["api_headers"]["internal"] == [{"header": INTERNAL_H, "declares": ["_nettle_c"]}]


def test_header_none_still_means_none(tmp_path, monkeypatch):
    out, calls = _setup(tmp_path, monkeypatch, _capture())
    res = _run(out, "none")
    assert calls[-1]["header_include"] == "none"
    assert not calls[-1]["extra_includes"]
    assert "api_warnings" not in res
    assert _sidecar(out)["api_headers"] == {"source": "none", "why": "--header none"}


def test_a_given_header_is_kept_and_recorded(tmp_path, monkeypatch):
    out, calls = _setup(tmp_path, monkeypatch, _capture())
    _run(out, "pub.h")
    assert calls[-1]["header_include"] == "pub.h" and not calls[-1]["extra_includes"]
    assert _sidecar(out)["api_headers"] == {"source": "given", "why": "--header pub.h"}


@pytest.mark.parametrize("capture", [None, _capture(units=False)], ids=["no capture", "no unit record"])
def test_a_unit_without_capture_data_keeps_todays_behavior(tmp_path, monkeypatch, capsys, capture):
    out, calls = _setup(tmp_path, monkeypatch, capture)
    res = _run(out)
    assert calls[-1]["header_include"] is None
    assert not calls[-1]["extra_includes"]
    assert len(res["api_warnings"]) == 1 and "--api without --header" in res["api_warnings"][0]
    assert "api_harness: warning: --api without --header" in capsys.readouterr().err
    side = _sidecar(out)["api_headers"]
    assert side["source"] == "not_found" and side["why"]


def test_no_public_header_and_no_declaring_header_finds_nothing(tmp_path, monkeypatch):
    cap = _capture(public=[])
    cap["compiles"][0]["headers"] = [CONFIG_H]
    out, calls = _setup(tmp_path, monkeypatch, cap)
    res = _run(out)
    assert calls[-1]["header_include"] is None and "api_warnings" in res
    side = _sidecar(out)["api_headers"]
    assert side["source"] == "not_found" and side["public"] == [] and side["internal"] == []


def test_a_second_header_of_the_same_file_name_is_dropped(tmp_path, monkeypatch):
    cap = _capture(public=[PUB_H, "other/pub.h"])
    cap["compiles"][0]["headers"].append("other/pub.h")
    out, calls = _setup(tmp_path, monkeypatch, cap)
    _run(out)
    assert calls[-1]["header_include"] == PUB_H
    assert "other/pub.h" not in calls[-1]["extra_includes"]
    dropped = _sidecar(out)["api_headers"]["dropped"]
    assert dropped == [{"header": "other/pub.h", "why": f"same file name as {PUB_H}, which the harness includes"}]


def test_header_declares_reads_renaming_macros_and_ignores_calls(tmp_path):
    h = tmp_path / "h.h"
    h.write_text(
        "#define set_key _nettle_set_key\nvoid set_key(int);\nstatic inline int f(void) { return g(1); }\n",
        encoding="utf-8",
        newline="\n",
    )
    assert ah.header_declares(h, {"_nettle_set_key", "g", "f"}) == {"_nettle_set_key", "f"}
    assert ah.header_declares(tmp_path / "missing.h", {"f"}) == set()


def test_a_freely_named_sub_module_looks_for_the_entry_points_of_its_scope_files(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch, _capture())
    dag = json.loads(Path("dag.json").read_text(encoding="utf-8"))
    dag["functions"]["src/a.c#_nettle_c"]["file"] = "src/c.c"
    capture = Path("build_capture.json")

    in_c = ah.capture_headers(dag, "mysub", "lib", capture, ["src/c.c"])
    assert in_c["internal"] == [{"header": INTERNAL_H, "declares": ["_nettle_c"]}]
    assert in_c["header"] == INTERNAL_H  # it declares the sub-module's first entry point
    # The public header declares every entry point of src/a.c: no internal header is needed.
    in_a = ah.capture_headers(dag, "mysub", "lib", capture, ["src/a.c"])
    assert in_a["internal"] == [] and in_a["header"] == PUB_H and in_a["extra_includes"] == []


# --- an automatic choice never fails a module: it degrades in steps -----------------------------------


def _broken_by(monkeypatch: pytest.MonkeyPatch, *broken: str) -> list[list[str]]:
    """A probe whose harness does not compile outside its cases while it includes a `broken` header."""
    seen: list[list[str]] = []

    def probe(harness_c: Any, cppflags: str, clang: str | None = None) -> tuple[dict[int, str], list[str]]:
        included = [ln.split('"')[1] for ln in Path(harness_c).read_text().splitlines() if ln.startswith("#include")]
        seen.append(included)
        bad = [h for h in included if h in broken]
        return {}, [f"{h}:1:1: error: unknown type name 'gmp_t'" for h in bad]

    monkeypatch.setattr(ah, "probe_cases", probe)
    return seen


def test_a_broken_internal_header_falls_back_to_the_public_ones(tmp_path, monkeypatch):
    out, calls = _setup(tmp_path, monkeypatch, _capture())
    seen = _broken_by(monkeypatch, INTERNAL_H)
    layout_probes: list[str] = []
    monkeypatch.setattr(ah, "probe_layouts", lambda h, c, *a, **k: layout_probes.append(Path(h).read_text()))
    res = _run(out)

    assert seen == [[PUB_H, INTERNAL_H], [PUB_H]]
    # Each attempt probes its own struct layouts: none comes from the harness with the dropped header.
    assert len(layout_probes) == 2 and INTERNAL_H not in layout_probes[1]
    assert calls[-1]["header_include"] == PUB_H and calls[-1]["extra_includes"] == []
    assert res["api_cases"] == 3 and "api_warnings" not in res  # every case kept
    side = _sidecar(out)["api_headers"]
    assert side["source"] == "capture"
    assert side["public"] == [PUB_H] and side["internal"] == []
    assert side["fallbacks"] == [
        {"dropped": [INTERNAL_H], "errors": [f"{INTERNAL_H}:1:1: error: unknown type name 'gmp_t'"]}
    ]
    assert "public header(s) only" in side["why"]
    from validate_artifacts import schema_problems

    assert not [p for p in schema_problems("harness_sidecar", _sidecar(out)) if "api_headers" in p]


@pytest.mark.parametrize("internal", [True, False], ids=["internal header", "public only"])
def test_when_every_capture_header_breaks_the_harness_is_the_no_header_one(tmp_path, monkeypatch, capsys, internal):
    # The harness without any header, as before the capture was used.
    ref_out, ref_calls = _setup(tmp_path / "ref", monkeypatch, None)
    ref = _run(ref_out)
    ref_side = _sidecar(ref_out)
    capsys.readouterr()

    cap = _capture()
    if not internal:
        cap["compiles"][0]["headers"] = [CONFIG_H, PUB_H]
    out, calls = _setup(tmp_path / "cap", monkeypatch, cap)
    _broken_by(monkeypatch, PUB_H, INTERNAL_H)
    res = _run(out)

    assert calls[-1]["header_include"] is None and calls[-1]["extra_includes"] == []
    assert calls[-1]["dispatch_cases"] == ref_calls[-1]["dispatch_cases"]
    # The warning of the old behaviour, which with a capture names its public headers.
    assert len(ref["api_warnings"]) == 1
    assert res["api_warnings"] == [ah.no_header_warning(Path("build_capture.json"))]
    assert "pub.h" in res["api_warnings"][0]
    assert "api_harness: warning: --api without --header" in capsys.readouterr().err
    side = _sidecar(out)
    for key in ("api_cases", "api_skipped", "dispatch_cases"):
        assert side[key] == ref_side[key]
    headers = side["api_headers"]
    assert headers["source"] == "capture_failed" and headers["public"] == [] and headers["internal"] == []
    if internal:
        assert [f["dropped"] for f in headers["fallbacks"]] == [[INTERNAL_H], [PUB_H]]
    else:
        assert [f["dropped"] for f in headers["fallbacks"]] == [[PUB_H]]
    from validate_artifacts import schema_problems

    assert not [p for p in schema_problems("harness_sidecar", side) if "api_headers" in p]


def test_a_broken_given_header_still_fails_the_module(tmp_path, monkeypatch):
    out, _ = _setup(tmp_path, monkeypatch, _capture())
    (out / "harness_lib.json").write_text('{"previous": true}')
    _broken_by(monkeypatch, "pub.h")
    with pytest.raises(ah.ApiHarnessError, match="does not compile outside its cases"):
        _run(out, "pub.h")
    assert (out / "harness_lib.json").read_text() == '{"previous": true}'


def test_a_clean_compile_records_no_fallback(tmp_path, monkeypatch):
    out, _ = _setup(tmp_path, monkeypatch, _capture())
    seen = _broken_by(monkeypatch)
    _run(out)
    assert seen == [[PUB_H, INTERNAL_H]]
    assert "fallbacks" not in _sidecar(out)["api_headers"]


def test_a_rooted_header_is_included_by_file_name_with_its_directory_on_the_include_path():
    """The real consumer of the rooted paths (generate_harness), which the fakes above stand in for."""
    import generate_harness as gh

    name, flags = gh._normalize_header_include(f"workspace/work/{PUB_H}", "")
    assert name == "pub.h"
    assert "-Iworkspace/work/include/x" in flags.split()
