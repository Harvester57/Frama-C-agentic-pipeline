#!/usr/bin/env python3
"""
Minimal, dependency-free JSON Schema interpreter for the pipeline contracts.

Supported keywords: $ref (local #/definitions or #/$defs), type, enum, const,
properties, required, additionalProperties, pattern, minLength, maxLength,
minimum, maximum, minItems, maxItems, uniqueItems, items, oneOf, anyOf, and the
custom keyword `visibleContent` (string must contain non-whitespace).

Unknown keywords are rejected when loading a schema so that a typo in a contract
cannot silently disable a check.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

SUPPORTED = {
    "$schema", "$id", "$comment", "title", "description", "definitions", "$defs",
    "$ref", "type", "enum", "const", "properties", "required",
    "additionalProperties", "pattern", "minLength", "maxLength", "minimum",
    "maximum", "minItems", "maxItems", "uniqueItems", "items", "oneOf", "anyOf",
    "visibleContent", "default", "examples",
}

MAX_ERRORS = 100


class SchemaError(ValueError):
    pass


def load_schema(path: Path) -> dict:
    schema = json.loads(Path(path).read_text(encoding="utf-8"))
    check_schema(schema)
    return schema


def check_schema(schema: Any, where: str = "schema") -> None:
    if isinstance(schema, bool):
        return
    if not isinstance(schema, dict):
        raise SchemaError(f"{where}: schema node must be an object")
    for key, value in schema.items():
        if key not in SUPPORTED:
            raise SchemaError(f"{where}: unsupported keyword {key!r}")
        if key in ("properties", "definitions", "$defs"):
            for name, sub in value.items():
                check_schema(sub, f"{where}.{key}.{name}")
        elif key in ("items", "additionalProperties") and isinstance(value, (dict, bool)):
            check_schema(value, f"{where}.{key}")
        elif key in ("oneOf", "anyOf"):
            for idx, sub in enumerate(value):
                check_schema(sub, f"{where}.{key}[{idx}]")
        elif key == "pattern":
            re.compile(value)


def _type_ok(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    raise SchemaError(f"unknown type {expected!r}")


def _canon(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


class Validator:
    def __init__(self, root: dict):
        self.root = root

    def resolve(self, ref: str) -> dict:
        if not ref.startswith("#/"):
            raise SchemaError(f"only local refs are supported: {ref}")
        node: Any = self.root
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(node, dict) or part not in node:
                raise SchemaError(f"unresolvable ref {ref}")
            node = node[part]
        return node

    def errors(self, value: Any, schema: Any = None, path: str = "$") -> list[str]:
        out: list[str] = []
        self._validate(value, self.root if schema is None else schema, path, out)
        return out[:MAX_ERRORS]

    def _validate(self, value: Any, schema: Any, path: str, out: list[str]) -> None:
        if len(out) >= MAX_ERRORS:
            return
        if schema is True:
            return
        if schema is False:
            out.append(f"{path}: no value is allowed here")
            return
        if "$ref" in schema:
            self._validate(value, self.resolve(schema["$ref"]), path, out)
            return

        if "type" in schema:
            types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
            if not any(_type_ok(value, t) for t in types):
                out.append(f"{path}: expected type {'/'.join(types)}")
                return

        if "const" in schema and _canon(value) != _canon(schema["const"]):
            out.append(f"{path}: must equal {schema['const']!r}")
        if "enum" in schema and _canon(value) not in {_canon(v) for v in schema["enum"]}:
            out.append(f"{path}: must be one of {schema['enum']!r}")

        if isinstance(value, str):
            if "minLength" in schema and len(value) < schema["minLength"]:
                out.append(f"{path}: shorter than {schema['minLength']}")
            if "maxLength" in schema and len(value) > schema["maxLength"]:
                out.append(f"{path}: longer than {schema['maxLength']}")
            if "pattern" in schema and not re.search(schema["pattern"], value):
                out.append(f"{path}: does not match pattern {schema['pattern']!r}")
            if schema.get("visibleContent") and not value.strip():
                out.append(f"{path}: must contain visible text")

        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if "minimum" in schema and value < schema["minimum"]:
                out.append(f"{path}: below minimum {schema['minimum']}")
            if "maximum" in schema and value > schema["maximum"]:
                out.append(f"{path}: above maximum {schema['maximum']}")

        if isinstance(value, list):
            if "minItems" in schema and len(value) < schema["minItems"]:
                out.append(f"{path}: fewer than {schema['minItems']} items")
            if "maxItems" in schema and len(value) > schema["maxItems"]:
                out.append(f"{path}: more than {schema['maxItems']} items")
            if schema.get("uniqueItems"):
                seen = set()
                for idx, item in enumerate(value):
                    key = _canon(item)
                    if key in seen:
                        out.append(f"{path}[{idx}]: duplicate item")
                    seen.add(key)
            if "items" in schema:
                for idx, item in enumerate(value):
                    self._validate(item, schema["items"], f"{path}[{idx}]", out)

        if isinstance(value, dict):
            props: dict[str, Any] = schema.get("properties", {})
            for name in schema.get("required", []):
                if name not in value:
                    out.append(f"{path}: missing required property {name!r}")
            for name, item in value.items():
                child = f"{path}.{name}"
                if name in props:
                    self._validate(item, props[name], child, out)
                else:
                    extra = schema.get("additionalProperties", True)
                    if extra is False:
                        out.append(f"{child}: unexpected property")
                    elif isinstance(extra, dict):
                        self._validate(item, extra, child, out)

        if "anyOf" in schema:
            if not any(not self.errors(value, sub, path) for sub in schema["anyOf"]):
                out.append(f"{path}: does not match any allowed shape")

        if "oneOf" in schema:
            self._one_of(value, schema["oneOf"], path, out)

    def _one_of(self, value: Any, branches: list, path: str, out: list[str]) -> None:
        resolved = [self.resolve(b["$ref"]) if "$ref" in b else b for b in branches]
        # Prefer a discriminator: a property carrying a distinct `const` in every branch.
        if isinstance(value, dict) and resolved:
            for name in resolved[0].get("properties", {}):
                consts = []
                for b in resolved:
                    sub = b.get("properties", {}).get(name)
                    if not (isinstance(sub, dict) and "const" in sub):
                        break
                    consts.append(_canon(sub["const"]))
                else:
                    if len(set(consts)) == len(consts):
                        key = _canon(value.get(name))
                        if key in consts:
                            self._validate(value, resolved[consts.index(key)], path, out)
                        else:
                            out.append(f"{path}.{name}: must be one of {[json.loads(c) for c in consts]!r}")
                        return
        matches = [b for b in resolved if not self.errors(value, b, path)]
        if len(matches) != 1:
            out.append(f"{path}: must match exactly one allowed shape (matched {len(matches)})")


def validate(value: Any, schema: dict) -> list[str]:
    return Validator(schema).errors(value)
