import pytest

from minischema import SchemaError, check_schema, validate


def test_types_required_and_additional_properties():
    schema = {"type": "object", "properties": {"a": {"type": "integer", "minimum": 1}}, "required": ["a"], "additionalProperties": False}
    assert validate({"a": 2}, schema) == []
    assert any("missing required" in e for e in validate({}, schema))
    assert any("unexpected property" in e for e in validate({"a": 2, "b": 1}, schema))
    assert any("below minimum" in e for e in validate({"a": 0}, schema))
    assert any("expected type" in e for e in validate({"a": True}, schema))


def test_one_of_uses_const_discriminator_for_precise_errors():
    schema = {
        "oneOf": [{"$ref": "#/definitions/a"}, {"$ref": "#/definitions/b"}],
        "definitions": {
            "a": {"type": "object", "properties": {"kind": {"const": "a"}, "x": {"type": "string"}}, "required": ["kind", "x"], "additionalProperties": False},
            "b": {"type": "object", "properties": {"kind": {"const": "b"}, "y": {"type": "integer"}}, "required": ["kind", "y"], "additionalProperties": False},
        },
    }
    assert validate({"kind": "a", "x": "s"}, schema) == []
    errs = validate({"kind": "b", "x": "s"}, schema)
    assert any("missing required property 'y'" in e for e in errs)
    assert any("must be one of" in e for e in validate({"kind": "c"}, schema))


def test_any_of_required_and_visible_content():
    schema = {"type": "object", "properties": {"l": {"type": "string", "visibleContent": True}, "o": {"type": "string"}},
              "anyOf": [{"required": ["l"]}, {"required": ["o"]}]}
    assert validate({"o": "x"}, schema) == []
    assert any("any allowed shape" in e for e in validate({}, schema))
    assert any("visible text" in e for e in validate({"l": "   "}, schema))


def test_unique_items_and_pattern():
    schema = {"type": "array", "uniqueItems": True, "items": {"type": "string", "pattern": "^[a-z]+$"}}
    assert validate(["a", "b"], schema) == []
    assert any("duplicate" in e for e in validate(["a", "a"], schema))
    assert any("pattern" in e for e in validate(["A"], schema))


def test_unknown_keyword_is_rejected():
    with pytest.raises(SchemaError):
        check_schema({"type": "object", "propertiez": {}})
