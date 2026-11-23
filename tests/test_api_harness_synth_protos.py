"""Reactive `extern` prototype synthesis for exported functions not declared in any header."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

import api_harness as ah
from validate_artifacts import schema_problems

pytestmark = pytest.mark.unit

PUB_H = "include/pub.h"


def _write_synth_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    header_text: str,
    model_fns: dict[str, dict[str, Any]],
    dag_fns: dict[str, dict[str, Any]],
    visible: ah.Declared | None = None,
) -> tuple[Path, list[dict[str, Any]]]:
    import generate_harness

    monkeypatch.chdir(tmp_path)
    (tmp_path / PUB_H).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / PUB_H).write_text(header_text, encoding="utf-8", newline="\n")
    out = tmp_path / "workspace" / "harnesses"
    out.mkdir(parents=True)
    entry_ids = [fid for fid, rec in dag_fns.items() if not rec.get("is_static")]
    dag = {
        "module_kind": "link_unit",
        "modules": {
            "lib": {
                "unit": "libx.so",
                "files": ["src/a.c"],
                "candidate_entry_points": entry_ids,
                "functions": list(dag_fns),
            }
        },
        "functions": dag_fns,
        "units": {"libx.so": {"kind": "shared_lib", "functions": list(dag_fns), "entry_points": entry_ids}},
    }
    model = {"status": "ok", "functions": model_fns, "entry_points": entry_ids}
    (tmp_path / "dag.json").write_text(json.dumps(dag), encoding="utf-8")
    (tmp_path / "model.json").write_text(json.dumps(model), encoding="utf-8")
    calls: list[dict[str, Any]] = []

    def fake_generate(**kw: Any) -> dict[str, str]:
        calls.append(kw)
        cases = list(kw["dispatch_cases"])
        harness = out / f"harness_{kw['module_name']}.c"
        file_scope = list(kw.get("file_scope") or [])
        body = [f'#include "{kw["header_include"]}"'] if kw.get("header_include") else []
        body.extend(file_scope)
        body.extend(f"    case {i}U: {{ {c} }} break;" for i, c in enumerate(cases))
        harness.write_text("\n".join(body) + "\n", encoding="utf-8", newline="\n")
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
        meta.write_text(json.dumps(sidecar), encoding="utf-8")
        return {"harness_file": str(harness), "harness_meta": str(meta), "cppflags": ""}

    monkeypatch.setattr(generate_harness, "generate_module_harness", fake_generate)
    monkeypatch.setattr(ah, "probe_layouts", lambda *a, **k: ({}, visible if visible is not None else ah.Declared()))
    return out, calls


def test_synthesize_extern_prototype_handles_const_void_opaque_anon_and_rejects_unsupported() -> None:
    anon_tags = {"struct __anonstruct_my_rec_t_77": "my_rec_t"}

    # Restores `const` on const_pointer formals, translates CIL anon tag, emits forward decl for opaque struct.
    res = ah.synthesize_extern_prototype(
        "hidden_fn",
        {
            "signature": "int(unsigned char *,struct __anonstruct_my_rec_t_77 *,struct opaque_s **)",
            "formals": [
                {"name": "buf", "kind": "const_pointer"},
                {"name": "rec", "kind": "pointer"},
                {"name": "out", "kind": "pointer"},
            ],
        },
        anon_tags=anon_tags,
        known_structs={"struct known_s"},
    )
    assert res is not None
    marked_line, clean_decl = res
    assert clean_decl == "extern int hidden_fn(unsigned char const *, my_rec_t *, struct opaque_s **);"
    assert marked_line.startswith("struct opaque_s; " + clean_decl)
    assert f"/* {ah.SYNTH_PROTO_MARKER} hidden_fn */" in marked_line

    # Empty `()` becomes `(void)`.
    empty = ah.synthesize_extern_prototype("no_args", {"signature": "void()", "formals": []})
    assert empty is not None
    assert empty[1] == "extern void no_args(void);"

    # Static, variadic, function-pointer return, and unresolved `__anonstruct_` are rejected cleanly.
    assert ah.synthesize_extern_prototype("st_fn", {"signature": "int(int)", "formals": [], "static": True}) is None
    assert ah.synthesize_extern_prototype("var_fn", {"signature": "int(char *, ...)", "formals": []}) is None
    assert ah.synthesize_extern_prototype("ret_fp", {"signature": "int(*)(int)()", "formals": []}) is None
    assert (
        ah.synthesize_extern_prototype(
            "anon_fn",
            {"signature": "int(struct __anonstruct_missing_1 *)", "formals": [{"name": "p", "kind": "pointer"}]},
            anon_tags=anon_tags,
        )
        is None
    )


def test_anon_record_tags_falls_back_to_visible_anon_typedef_name() -> None:
    vis = ah.Declared(anon_records={"my_cfg_t": {"what": "struct"}})
    model_fns = {
        "src/a.c#f": {
            "signature": "int(struct __anonstruct_my_cfg_t_42 *)",
            "formals": [{"name": "p", "kind": "pointer"}],
        }
    }
    tags = ah.anon_record_tags(model_fns, vis)
    assert tags["struct __anonstruct_my_cfg_t_42"] == "my_cfg_t"


@pytest.mark.parametrize(
    "probe_msg",
    [
        "error: call to undeclared function 'hidden_api'; ISO C99 and later do not support implicit function declarations",
        "error: implicit declaration of function 'hidden_api' is invalid in C99",
    ],
)
def test_generate_synthesizes_extern_prototype_for_undeclared_exported_function(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, probe_msg: str
) -> None:
    model_fns: dict[str, dict[str, Any]] = {
        "src/a.c#pub_api": {"name": "pub_api", "signature": "int(int)", "formals": [{"name": "x", "kind": "scalar"}]},
        "src/a.c#hidden_api": {
            "name": "hidden_api",
            "signature": "int(unsigned char *,unsigned long)",
            "formals": [{"name": "buf", "kind": "const_pointer"}, {"name": "len", "kind": "scalar"}],
        },
        "src/a.c#internal_static": {
            "name": "internal_static",
            "signature": "int(int)",
            "formals": [{"name": "x", "kind": "scalar"}],
            "static": True,
        },
    }
    dag_fns = {
        "src/a.c#pub_api": {"name": "pub_api", "file": "src/a.c", "is_static": False, "module": "lib"},
        "src/a.c#hidden_api": {"name": "hidden_api", "file": "src/a.c", "is_static": False, "module": "lib"},
        "src/a.c#internal_static": {"name": "internal_static", "file": "src/a.c", "is_static": True, "module": "lib"},
    }
    out, _ = _write_synth_fixture(
        tmp_path,
        monkeypatch,
        header_text="int pub_api(int x);\n",
        model_fns=model_fns,
        dag_fns=dag_fns,
    )

    def fake_probe(harness_c: Path, _cppflags: str, clang: str | None = None) -> tuple[dict[int, str], list[str]]:
        text = Path(harness_c).read_text(encoding="utf-8")
        has_proto = "extern int hidden_api(" in text
        case_errs: dict[int, str] = {}
        for ln in text.splitlines():
            m = re.match(r"\s*case (\d+)U:.*hidden_api\(", ln)
            if m and not has_proto:
                case_errs[int(m.group(1))] = probe_msg
        return case_errs, []

    monkeypatch.setattr(ah, "probe_cases", fake_probe)
    res = ah.generate(
        "lib",
        PUB_H,
        64,
        "",
        out,
        unit="lib",
        dag_path=Path("dag.json"),
        model_path=Path("model.json"),
        traces_path=Path("none/traces.jsonl"),
        variadic={},
    )
    assert res["api_cases"] == 2
    assert res["api_skipped"] == {}
    harness_text = (out / "harness_lib.c").read_text(encoding="utf-8")
    assert ah.SYNTH_PROTO_MARKER in harness_text
    assert "extern int hidden_api(unsigned char const *, unsigned long);" in harness_text
    sidecar = json.loads((out / "harness_lib.json").read_text(encoding="utf-8"))
    assert sidecar["api_headers"]["synthesized_prototypes"] == {
        "hidden_api": "extern int hidden_api(unsigned char const *, unsigned long);"
    }
    assert schema_problems("harness_sidecar", sidecar) == []


def test_generate_rolls_back_broken_synthesized_prototype_and_keeps_valid_ones(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    model_fns = {
        "src/a.c#pub_api": {"name": "pub_api", "signature": "int(int)", "formals": [{"name": "x", "kind": "scalar"}]},
        "src/a.c#good_hidden": {
            "name": "good_hidden",
            "signature": "int(int)",
            "formals": [{"name": "x", "kind": "scalar"}],
        },
        "src/a.c#bad_hidden": {
            "name": "bad_hidden",
            "signature": "int(int)",
            "formals": [{"name": "x", "kind": "scalar"}],
        },
    }
    dag_fns = {
        fid: {"name": rec["name"], "file": "src/a.c", "is_static": False, "module": "lib"}
        for fid, rec in model_fns.items()
    }
    out, _ = _write_synth_fixture(
        tmp_path,
        monkeypatch,
        header_text="int pub_api(int x);\n",
        model_fns=model_fns,
        dag_fns=dag_fns,
    )
    saw_bad_proto = False

    def fake_probe(harness_c: Path, _cppflags: str, clang: str | None = None) -> tuple[dict[int, str], list[str]]:
        nonlocal saw_bad_proto
        lines = Path(harness_c).read_text(encoding="utf-8").splitlines()
        other: list[str] = []
        case_errs: dict[int, str] = {}
        has_good = any("extern int good_hidden(" in ln for ln in lines)
        has_bad = any("extern int bad_hidden(" in ln for ln in lines)
        for lineno, ln in enumerate(lines, start=1):
            if "extern int bad_hidden(" in ln:
                saw_bad_proto = True
                other.append(f"{harness_c}:{lineno}:16: error: conflicting types for 'bad_hidden'")
            m = re.match(r"\s*case (\d+)U:.*(good_hidden|bad_hidden)\(", ln)
            if m:
                cid, fn = int(m.group(1)), m.group(2)
                if fn == "good_hidden" and not has_good:
                    case_errs[cid] = "error: call to undeclared function 'good_hidden'"
                elif fn == "bad_hidden" and not has_bad:
                    case_errs[cid] = "error: call to undeclared function 'bad_hidden'"
        return case_errs, other

    monkeypatch.setattr(ah, "probe_cases", fake_probe)
    res = ah.generate(
        "lib",
        PUB_H,
        64,
        "",
        out,
        unit="lib",
        dag_path=Path("dag.json"),
        model_path=Path("model.json"),
        traces_path=Path("none/traces.jsonl"),
        variadic={},
    )
    # `bad_hidden` was synthesized, erred on its own prototype line, and was rolled back while `good_hidden` survived.
    assert saw_bad_proto is True
    assert res["api_cases"] == 2
    assert list(res["api_skipped"]) == ["src/a.c#bad_hidden"]
    sidecar = json.loads((out / "harness_lib.json").read_text(encoding="utf-8"))
    assert sidecar["api_headers"]["synthesized_prototypes"] == {
        "good_hidden": "extern int good_hidden(int);",
    }
    assert schema_problems("harness_sidecar", sidecar) == []
