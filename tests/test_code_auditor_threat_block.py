"""
The code-auditor skill's Frama-C threat-model reference (skills/code-auditor/references/framac-threat-model.md)
stays in step with schemas/threat_model.schema.json: it names every field and enum value the schema has,
and its example block passes scripts/trust.py's own extraction and validation.
"""

import json
import re

import pytest

import trust as T
from conftest import ROOT

pytestmark = pytest.mark.unit

AUDITOR_REFERENCE = ROOT / "skills" / "code-auditor" / "references" / "framac-threat-model.md"
THREAT_SCHEMA = ROOT / "schemas" / "threat_model.schema.json"


def _schema_names(schema: dict) -> set[str]:
    """Every property name and string enum value of the threat-model schema."""
    names: set[str] = set()

    def walk(node: object) -> None:
        if isinstance(node, dict):
            for key, value in (node.get("properties") or {}).items():
                names.add(key)
                walk(value)
            names.update(v for v in node.get("enum") or [] if isinstance(v, str))
            walk(node.get("items"))
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(schema)
    return names


def _example_object() -> dict:
    text = AUDITOR_REFERENCE.read_text(encoding="utf-8")
    bodies = re.findall(r"^```json\n(.*?)^```$", text, re.MULTILINE | re.DOTALL)
    assert len(bodies) == 1, "the reference holds exactly one ```json example"
    data = json.loads(bodies[0])
    assert isinstance(data, dict)
    return data


def test_reference_names_every_schema_field_and_enum():
    text = AUDITOR_REFERENCE.read_text(encoding="utf-8")
    schema = json.loads(THREAT_SCHEMA.read_text(encoding="utf-8"))
    missing = sorted(n for n in _schema_names(schema) if f"`{n}`" not in text)
    assert not missing, f"framac-threat-model.md does not mention schema names: {missing}"


def test_reference_names_every_required_key():
    text = AUDITOR_REFERENCE.read_text(encoding="utf-8")
    schema = json.loads(THREAT_SCHEMA.read_text(encoding="utf-8"))
    assert all(f"`{key}`" in text for key in schema["required"])


def test_reference_example_validates():
    example = _example_object()
    assert T.validate_block(example) == []
    # Every list kind is shown, so the example teaches each item shape.
    for key in ("input_sources", "trusted_callers", "secrets", "auth_gates", "output_sinks"):
        assert example[key], key


def test_reference_example_extracts_from_the_documented_fence():
    example = _example_object()
    doc = "# Threat Model\n\n## Frama-C Threat Model Block\n\n```json framac-threat-model\n"
    doc += json.dumps(example, indent=2) + "\n```\n"
    block, errors = T.extract_block(doc)
    assert errors == []
    assert block == example


def test_reference_itself_is_not_read_as_a_threat_model():
    """The illustration uses a plain ```json fence, so pointing --threat-model at the reference finds no block."""
    block, errors = T.extract_block(AUDITOR_REFERENCE.read_text(encoding="utf-8"))
    assert block is None and errors == []
