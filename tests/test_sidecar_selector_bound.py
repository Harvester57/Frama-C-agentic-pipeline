"""
The sidecar's `api_cases[*].selector` bound (nginx 1.31.9 run-3, 2026-11-19): `validate_artifacts.py
run-dir` failed with `$.api_cases[255].selector: above maximum 254` on nginx__ngx_event_openssl, an
`--api` harness of 498 cases that selects its case with two input bytes (`identity16`, D7). The
schema still held the one-byte bound of the time when `--api` stopped at 255 cases. The bound is
the generator's: `api_harness.MAX_CASES` cases at most, so selectors up to `MAX_CASES - 1` with
`identity16`; a one-byte selector (`identity`, or the older modulo one) selects at most
`DISPATCH_MAX_CASES` cases, which `validate_sidecar` checks against `dispatch_selector`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import api_harness as ah
import generate_harness as gh
import validate_artifacts as va

pytestmark = pytest.mark.unit

SSB_SCHEMA = Path(__file__).resolve().parents[1] / "schemas" / "harness_sidecar.schema.json"
SSB_CASE_KINDS = ("single_case", "sequence_case", "lifecycle_case", "custom_case", "variadic_case")


def _ssb_sidecar(n: int, selector: str | None) -> dict:
    cases = [
        {"selector": k, "kind": "single", "calls": [f"f{k}"], "slots": [], "rest": None, "entry": f"lib.c#f{k}"}
        for k in range(n)
    ]
    out: dict = {
        "module": "lib",
        "harness_file": "workspace/harnesses/harness_lib.c",
        "sources": ["lib.c"],
        "cppflags": "-I.",
        "entry_fn": "f0",
        "entry_style": "dispatch",
        "dispatch_cases": [f"(void)f{k}();" for k in range(n)],
        "dispatch_case_count": n,
        "api_harness": True,
        "api_cases": cases,
    }
    if selector is not None:
        out["dispatch_selector"] = selector
    return out


def test_an_identity16_api_sidecar_above_255_cases_validates():
    """nginx run-3's shape: 498 cases, selectors 0..497, two selector bytes."""
    n = 498
    assert gh.dispatch_selector_for(n) == gh.DISPATCH_SELECTOR_IDENTITY16
    assert va.validate_sidecar(_ssb_sidecar(n, "identity16"), "lib") == []


def test_the_generator_records_no_schema_warning_above_255_cases(tmp_path):
    """
    generate_harness.write_sidecar checks its own sidecar and records schema problems in `warnings`,
    which `run-dir` fails on. Run-3's sidecar carries the old bound's warning; a rewrite drops it.
    """
    stale = _ssb_sidecar(498, "identity16")
    stale["warnings"] = ["schema: ['$.api_cases[255].selector: above maximum 254']"]
    written = gh.write_sidecar(tmp_path / "harness_lib.json", stale)
    assert "warnings" not in written
    on_disk = json.loads((tmp_path / "harness_lib.json").read_text(encoding="utf-8"))
    assert va.validate_sidecar(on_disk, "lib") == []


def test_the_largest_api_harness_validates():
    n = ah.MAX_CASES
    assert va.validate_sidecar(_ssb_sidecar(n, "identity16"), "lib") == []
    errors = va.validate_sidecar(_ssb_sidecar(n + 1, "identity16"), "lib")
    assert any(f"$.api_cases[{n}].selector: above maximum {n - 1}" in e for e in errors), errors


def test_one_selector_byte_holds_at_most_256_cases():
    n = gh.DISPATCH_MAX_CASES
    assert gh.dispatch_selector_for(n) == gh.DISPATCH_SELECTOR_IDENTITY
    assert va.validate_sidecar(_ssb_sidecar(n, "identity"), "lib") == []
    for selector in ("identity", None):  # None: the older modulo selector, one byte too
        errors = va.validate_sidecar(_ssb_sidecar(n + 1, selector), "lib")
        assert any("identity16" in e and "one selector byte" in e for e in errors), (selector, errors)


def test_the_schema_bound_is_the_generators():
    schema = json.loads(SSB_SCHEMA.read_text(encoding="utf-8"))
    for kind in SSB_CASE_KINDS:
        assert schema["definitions"][kind]["properties"]["selector"] == {"$ref": "#/definitions/case_selector"}, kind
    assert schema["definitions"]["case_selector"]["maximum"] == ah.MAX_CASES - 1
    assert schema["properties"]["dispatch_case_count"]["maximum"] == gh.DISPATCH_MAX_CASES_WIDE
    assert schema["properties"]["dispatch_cases"]["maxItems"] == gh.DISPATCH_MAX_CASES_WIDE
    assert va.ONE_BYTE_SELECTOR_CASES == gh.DISPATCH_MAX_CASES
