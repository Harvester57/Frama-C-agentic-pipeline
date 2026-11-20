"""
A property over an lvalue that hangs off a parameter (`stream->bytes_written`) names the parameter
with MetAcsl's `\\formal(stream)`. The name alone does not say the parameter holds the asset's
object: nanopb's decoders also take a `stream`, of another struct type without the field, and
Frama-C stops on `\\formal(stream)->bytes_written` there ("Cannot find field bytes_written in type
struct pb_istream_s"). security_props.py must leave those functions out of the property's targets
and instances, and record them (`param_type`), while still guarding the functions whose parameter
has the asset's type.
"""

from __future__ import annotations

import pytest

import security_props as sp

OUT_T = "struct out_s *"
IN_T = "struct in_s *"


def _func(name: str, file: str, sig: str, params: list[str], unit: str = "liba.a", **extra) -> dict:
    rec = {
        "name": name,
        "file": file,
        "units": [unit],
        "source": "frama-c-kernel",
        "external_calls": [],
        "signature": sig,
        "formals": [{"name": p, "kind": "pointer"} for p in params],
        "writes": {"pointer": 1, "params": list(params[:1]), "globals": []},
    }
    rec.update(extra)
    return rec


def _stream_model(**more: dict) -> dict:
    """Two writers through a `stream`: one of the asset's type (`out_s`), one of another (`in_s`)."""
    functions = {
        "out.c#flush": _func("flush", "out.c", f"void({OUT_T})", ["stream"]),
        "out.c#emit": _func("emit", "out.c", f"void({OUT_T},int)", ["stream", "n"]),
        "in.c#take": _func("take", "in.c", f"int({IN_T})", ["stream"]),
        **more,
    }
    return {
        "status": "ok",
        "units": {"liba.a": {"kind": "static_lib", "test": False}, "tests": {"kind": "executable", "test": True}},
        "functions": functions,
        "edges": [],
    }


def _threat_block(**lists) -> dict:
    block = {"schema_version": 1, "input_sources": [], "secrets": [], "auth_gates": [], "output_sinks": []}
    block.update(lists)
    return {"status": "ok", "block": block}


def _props(model: dict, **lists) -> dict:
    doc = sp.generate(model, _threat_block(**lists))
    assert sp.validate(doc) == [], sp.validate(doc)
    return doc


def _prop(doc: dict, name: str) -> dict:
    found = [p for p in doc["properties"] if p["name"] == name]
    assert found, [p["name"] for p in doc["properties"]]
    return found[0]


def _units_of(doc: dict, fid: str, prop_name: str) -> list[dict]:
    return [o for o in doc["obligations"].get(fid) or [] if o["property"] == prop_name]


def _excluded(prop: dict) -> set[str]:
    return {e["function"] for e in (prop.get("param_type") or {}).get("excluded") or []}


ASSET = {"name": "out_count", "lvalue": "stream->bytes_written", "writers": ["flush"], "description": "d"}


@pytest.mark.unit
def test_writers_property_leaves_out_a_parameter_of_another_type():
    doc = _props(_stream_model(), assets=[ASSET])
    prop = _prop(doc, "L3_writers_out_count")
    # The function whose `stream` is an in_s leaves the targets and the instances ...
    assert "\\targets(\\diff(\\ALL, {flush, take}))" in prop["acsl"]
    assert prop["instances"] == ["out.c#emit"]
    assert not _units_of(doc, "in.c#take", prop["name"])
    # ... and is recorded, with the type the asset was matched against.
    assert prop["param_type"]["type"] == OUT_T
    assert _excluded(prop) == {"in.c#take"}
    assert any("take" in n and IN_T in n for n in prop["notes"]), prop["notes"]
    # The out_s function is still guarded.
    assert "\\tguard(\\separated(\\written, &\\formal(stream)->bytes_written))" in prop["acsl"]
    assert not prop.get("unchecked")


@pytest.mark.unit
def test_asset_type_from_the_unanimous_name_when_there_are_no_writers():
    """nanopb's `ostream_max_size`: no writer; `ostream` is an out_s everywhere, `stream` is both."""
    model = _stream_model(**{"out.c#sub": _func("sub", "out.c", f"void({OUT_T})", ["ostream"])})
    asset = {"name": "out_max", "lvalue": "stream->max_size", "params": ["ostream"], "writers": [], "description": "d"}
    doc = _props(model, assets=[asset])
    prop = _prop(doc, "L3_writers_out_max")
    assert prop["param_type"]["type"] == OUT_T
    assert "\\targets(\\diff(\\ALL, {take}))" in prop["acsl"]
    assert set(prop["instances"]) == {"out.c#emit", "out.c#flush", "out.c#sub"}
    assert _excluded(prop) == {"in.c#take"}


@pytest.mark.unit
def test_undetermined_type_keeps_every_function_and_warns():
    asset = {"name": "out_max", "lvalue": "stream->max_size", "writers": [], "description": "d"}
    doc = _props(_stream_model(), assets=[asset])
    prop = _prop(doc, "L3_writers_out_max")
    assert "in.c#take" in prop["instances"]
    assert "param_type" not in prop
    assert any("out_max" in w and "type" in w and IN_T in w and OUT_T in w for w in doc["warnings"]), doc["warnings"]


@pytest.mark.unit
def test_one_type_for_the_name_changes_nothing():
    model = _stream_model()
    model["functions"]["in.c#take"]["signature"] = f"int({OUT_T})"
    doc = _props(model, assets=[ASSET])
    prop = _prop(doc, "L3_writers_out_count")
    assert "\\targets(\\diff(\\ALL, {flush}))" in prop["acsl"]
    assert set(prop["instances"]) == {"out.c#emit", "in.c#take"}
    assert "param_type" not in prop
    assert not [w for w in doc["warnings"] if "out_count" in w]


@pytest.mark.unit
def test_readers_property_leaves_out_a_parameter_of_another_type():
    asset = {**ASSET, "readers": ["flush"]}
    doc = _props(_stream_model(), assets=[asset])
    prop = _prop(doc, "L3_readers_out_count")
    assert "\\targets(\\diff(\\ALL, {flush, take}))" in prop["acsl"]
    assert prop["instances"] == ["out.c#emit"]
    assert _excluded(prop) == {"in.c#take"}


@pytest.mark.unit
def test_a_function_also_taking_the_asset_under_another_name_is_unchecked():
    """`mix(struct in_s *stream, struct out_s *ostream)`: the stream clause would stop Frama-C there."""
    model = _stream_model(**{"mix.c#mix": _func("mix", "mix.c", f"void({IN_T},{OUT_T})", ["stream", "ostream"])})
    asset = {**ASSET, "params": ["ostream"]}
    doc = _props(model, assets=[asset])
    prop = _prop(doc, "L3_writers_out_count")
    assert "take" in prop["acsl"].split("\\diff(\\ALL, {")[1].split("}")[0]
    assert "mix" in prop["acsl"].split("\\diff(\\ALL, {")[1].split("}")[0]
    assert "mix.c#mix" not in prop["instances"]
    assert {u["function"] for u in prop.get("unchecked") or []} == {"mix.c#mix"}
    # Its unit exists and cannot be credited; the in_s-only function has none.
    assert [o.get("unchecked") for o in _units_of(doc, "mix.c#mix", prop["name"])] == [prop["unchecked"][0]["reason"]]
    assert not _units_of(doc, "in.c#take", prop["name"])


@pytest.mark.unit
def test_a_right_typed_function_sharing_a_c_name_is_unchecked():
    """MetAcsl targets by C name: two statics `take`, only one of the wrong type."""
    model = _stream_model(**{"out.c#take": _func("take", "out.c", f"int({OUT_T})", ["stream"])})
    doc = _props(model, assets=[ASSET])
    prop = _prop(doc, "L3_writers_out_count")
    assert "\\targets(\\diff(\\ALL, {flush, take}))" in prop["acsl"]
    assert "out.c#take" not in prop["instances"]
    assert {u["function"] for u in prop.get("unchecked") or []} == {"out.c#take"}


@pytest.mark.unit
def test_a_test_unit_function_of_another_type_leaves_the_targets_too():
    """A whole-module parse (Eva, E-ACSL, a parent's re-check) holds test-unit functions as well."""
    model = _stream_model(**{"t.c#probe": _func("probe", "t.c", f"int({IN_T})", ["stream"], unit="tests")})
    doc = _props(model, assets=[ASSET])
    prop = _prop(doc, "L3_writers_out_count")
    assert "\\targets(\\diff(\\ALL, {flush, probe, take}))" in prop["acsl"]
    assert prop["instances"] == ["out.c#emit"]


@pytest.mark.unit
def test_unknown_signature_keeps_the_function():
    model = _stream_model(**{"u.c#odd": _func("odd", "u.c", "", ["stream"])})
    doc = _props(model, assets=[ASSET])
    prop = _prop(doc, "L3_writers_out_count")
    assert "u.c#odd" in prop["instances"]
    assert "odd" not in prop["acsl"].split("\\diff(\\ALL, {")[1].split("}")[0]


@pytest.mark.unit
def test_meta_files_hold_no_guard_for_the_excluded_function():
    doc = _props(_stream_model(), assets=[ASSET])
    assert sp.meta_file_text(doc, "in.c#take") is None
    text, names, _ = sp.meta_file_text(doc, "out.c#emit") or ("", [], [])
    assert "L3_writers_out_count" in names
    assert "&\\formal(stream)->bytes_written" in text


@pytest.mark.unit
def test_formal_auth_state_leaves_out_a_parameter_of_another_type():
    model = _stream_model(
        **{
            "g.c#check": _func("check", "g.c", f"int({OUT_T})", ["stream"]),
            "g.c#act": _func("act", "g.c", f"void({OUT_T})", ["stream"]),
        }
    )
    gate = {"function": "check", "state": "stream->ok", "protects": ["act"], "description": "d"}
    doc = _props(model, auth_gates=[gate])
    state = _prop(doc, "L4_auth_state_check")
    assert "\\targets(\\diff(\\ALL, {check, take}))" in state["acsl"]
    assert "in.c#take" not in state["instances"]
    assert _excluded(state) == {"in.c#take"}
    assert state["param_type"]["type"] == OUT_T


@pytest.mark.unit
def test_auth_required_leaves_out_a_protected_function_of_another_type():
    model = _stream_model(
        **{
            "g.c#check": _func("check", "g.c", f"int({OUT_T})", ["stream"]),
            "g.c#act": _func("act", "g.c", f"void({OUT_T})", ["stream"]),
        }
    )
    gate = {"function": "check", "state": "stream->ok", "protects": ["act", "take"], "description": "d"}
    doc = _props(model, auth_gates=[gate])
    req = _prop(doc, "L4_auth_required_check")
    assert "\\targets({act})" in req["acsl"]
    assert _excluded(req) == {"in.c#take"}
    assert any("take" in w and "L4_auth_required_check" in w for w in doc["warnings"]), doc["warnings"]


@pytest.mark.unit
def test_monotonic_formal_invariant_types_its_scope():
    """A scope of one type leaves the other out; over every function the type is unknown: warn."""
    inv = {"name": "count_up", "variant": "monotonic", "lvalue": "stream->bytes_written", "description": "d"}
    model = _stream_model(**{"out.c#sub": _func("sub", "out.c", f"void({OUT_T})", ["stream"])})
    doc = _props(model, invariants=[{**inv, "scope": ["flush", "emit"]}])
    prop = _prop(doc, "L4_invariant_count_up")
    assert "\\targets({flush, emit})" in prop["acsl"]
    assert "param_type" not in prop
    assert not [w for w in doc["warnings"] if "count_up" in w]
    # Over every function nothing tells which `stream` holds the lvalue: today's behaviour, warned.
    doc = _props(model, invariants=[inv])
    prop = _prop(doc, "L4_invariant_count_up")
    assert "in.c#take" in prop["instances"]
    assert any("count_up" in w and IN_T in w for w in doc["warnings"]), doc["warnings"]
    # A scope that mixes both types leaves out the minority? No: nothing tells which one: warned too.
    doc = _props(model, invariants=[{**inv, "scope": ["flush", "emit", "sub", "take"]}])
    assert any("count_up" in w and IN_T in w for w in doc["warnings"]), doc["warnings"]


@pytest.mark.unit
def test_param_types_split_nested_parentheses():
    m = sp._Model(
        {
            "functions": {
                "a.c#f": {
                    "name": "f",
                    "signature": "int(struct s const *,int (*)(int, char *),unsigned long)",
                    "formals": [{"name": "s"}, {"name": "cb"}, {"name": "n"}],
                },
                "a.c#g": {"name": "g", "signature": "int(int)", "formals": [{"name": "a"}, {"name": "b"}]},
            }
        }
    )
    assert m.param_types("a.c#f") == {"s": "struct s *", "cb": "int (*)(int, char *)", "n": "unsigned long"}
    assert m.param_types("a.c#g") is None
