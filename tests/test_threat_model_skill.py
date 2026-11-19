"""
The threat-model skill (skills/threat-model) stays in step with the pipeline and with itself.

- Its Frama-C block reference (references/framac-threat-model.md) names every field and enum value of
  schemas/threat_model.schema.json, and its example block passes scripts/trust.py's own extraction and
  validation.
- Its model reference (references/threat-model.md) maps every list of the schema to a table of the
  ThreatModel.md contract, and every table another reference names exists in that contract.
- SKILL.md links every reference file, and nothing of the audit workflow it was derived from is left.
"""

import json
import re

import pytest

import trust as T
from conftest import ROOT

pytestmark = pytest.mark.unit

SKILL_DIR = ROOT / "skills" / "threat-model"
SKILL = SKILL_DIR / "SKILL.md"
REFERENCES = SKILL_DIR / "references"
BLOCK_REFERENCE = REFERENCES / "framac-threat-model.md"
MODEL_REFERENCE = REFERENCES / "threat-model.md"
THREAT_SCHEMA = ROOT / "schemas" / "threat_model.schema.json"

# Phases of the audit workflow the skill no longer has.
AUDIT_ONLY = ("discovery", "exploit", "remediation", "reporting", "rating-rubrics", "tool-analysis", "validation")


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
    text = BLOCK_REFERENCE.read_text(encoding="utf-8")
    bodies = re.findall(r"^```json\n(.*?)^```$", text, re.MULTILINE | re.DOTALL)
    assert len(bodies) == 1, "the reference holds exactly one ```json example"
    data = json.loads(bodies[0])
    assert isinstance(data, dict)
    return data


def _contract_headings() -> list[str]:
    """The `## ` headings of the ThreatModel.md contract (the first ```markdown fence of the model reference)."""
    text = MODEL_REFERENCE.read_text(encoding="utf-8")
    fences = re.findall(r"^```markdown\n(.*?)^```$", text, re.MULTILINE | re.DOTALL)
    assert fences, "threat-model.md holds the ThreatModel.md contract in a ```markdown fence"
    return re.findall(r"^## (.+)$", fences[0], re.MULTILINE)


def test_reference_names_every_schema_field_and_enum():
    text = BLOCK_REFERENCE.read_text(encoding="utf-8")
    schema = json.loads(THREAT_SCHEMA.read_text(encoding="utf-8"))
    missing = sorted(n for n in _schema_names(schema) if f"`{n}`" not in text)
    assert not missing, f"framac-threat-model.md does not mention schema names: {missing}"


def test_reference_names_every_required_key():
    text = BLOCK_REFERENCE.read_text(encoding="utf-8")
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
    block, errors = T.extract_block(BLOCK_REFERENCE.read_text(encoding="utf-8"))
    assert block is None and errors == []


def test_model_reference_maps_every_schema_list_to_a_table():
    """A list the schema gains must get its table and its mapping line, or the block could extend the model."""
    text = MODEL_REFERENCE.read_text(encoding="utf-8")
    mapping = text.split("## Machine-readable block", 1)[1].split("\n## ", 1)[0]
    schema = json.loads(THREAT_SCHEMA.read_text(encoding="utf-8"))
    lists = sorted(k for k, v in schema["properties"].items() if v.get("type") == "array")
    assert lists, "the schema has list properties"
    missing = [name for name in lists if f"`{name}`" not in mapping]
    assert not missing, f"threat-model.md maps no table to the schema lists: {missing}"


def test_tables_named_by_the_references_exist_in_the_contract():
    headings = set(_contract_headings())
    assert "Frama-C Threat Model Block" in headings
    assert _contract_headings()[-1] == "Frama-C Threat Model Block", "the block is the last section"
    # The tables the block is built from.
    for name in ("API Classification", "Entry Points And Readers", "Secrets", "Authorization Gates", "Output Sinks"):
        assert name in headings, name
    # A reference names a table of ThreatModel.md as `the "<heading>" table`.
    for ref in (BLOCK_REFERENCE, MODEL_REFERENCE, REFERENCES / "review.md"):
        quoted = set(re.findall(r'"([^"\n]+)" table', ref.read_text(encoding="utf-8")))
        unknown = sorted(quoted - headings)
        assert not unknown, f"{ref.name} names tables the ThreatModel.md contract lacks: {unknown}"


def test_skill_links_every_reference_and_every_link_resolves():
    text = SKILL.read_text(encoding="utf-8")
    front = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
    assert front and re.search(r"^name: threat-model$", front.group(1), re.MULTILINE)
    linked = set(re.findall(r"\]\((references/[^)#]+)\)", text))
    on_disk = {f"references/{p.name}" for p in REFERENCES.glob("*.md")}
    assert linked == on_disk
    for ref in sorted(REFERENCES.glob("*.md")):
        for target in re.findall(r"\]\(([^)#:]+\.md)(?:#[^)]*)?\)", ref.read_text(encoding="utf-8")):
            assert (ref.parent / target).is_file(), f"{ref.name} links {target}, which does not exist"


def test_nothing_of_the_audit_workflow_is_left():
    names = {p.stem for p in REFERENCES.glob("*.md")}
    assert not [n for n in names if any(n.startswith(a) for a in AUDIT_ONLY)]
    assert not (ROOT / "skills" / "code-auditor").exists()
    for path in [SKILL, *sorted(REFERENCES.glob("*.md"))]:
        text = path.read_text(encoding="utf-8").lower()
        for word in ("proof of concept", "poc/", "patches/", "findings.md", "severity-nnn"):
            assert word not in text, f"{path.name} still mentions {word!r}"
