"""Public header functions as API entry points (docs/plans/header-entry-points-plan.md, H1): the Phase 0
model's per-unit `header_api`, the DAG's `candidate_entry_points` and `model_api()`."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import phase0_model as pm  # noqa: E402
from minischema import Validator, load_schema  # noqa: E402

pytestmark = pytest.mark.unit

HEP_EXPORTED = "src/lib.c#lib_decode"
HEP_PUBLIC = "inc/lib/lib.h#lib_get_int"
HEP_PRIVATE = "src/priv.h#priv_helper"
HEP_SOURCE_STATIC = "src/lib.c#decode_one"


def _hep_fn(file: str, name: str, **kw: object) -> dict:
    rec: dict = {
        "file": file,
        "name": name,
        "line": 1,
        "end_line": 1,
        "lines": 1,
        "static": False,
        "inline": False,
        "header": file.endswith(".h"),
        "signature": "int (void)",
        "loops": 0,
        "cyclomatic": 1,
        "address_taken": False,
        "source": "frama-c-kernel",
        "units": ["liblib.a"],
        "kernel_names": {},
    }
    rec.update(kw)
    return rec


def _hep_functions() -> dict[str, dict]:
    return {
        HEP_EXPORTED: _hep_fn("src/lib.c", "lib_decode"),
        HEP_PUBLIC: _hep_fn("inc/lib/lib.h", "lib_get_int", static=True, inline=True),
        HEP_PRIVATE: _hep_fn("src/priv.h", "priv_helper", static=True, inline=True),
        HEP_SOURCE_STATIC: _hep_fn("src/lib.c", "decode_one", static=True),
    }


def _hep_units() -> dict[str, dict]:
    return {
        "liblib.a": {
            "kind": "static_lib",
            "test": False,
            "files": ["src/lib.c"],
            "links": [],
            "entry_points": [HEP_EXPORTED],
            "embedded_api": [],
            "parse": {"status": "ok"},
            "concurrent": False,
        },
        "tests/run": {
            "kind": "executable",
            "test": True,
            "files": ["tests/run.c"],
            "links": ["liblib.a"],
            "entry_points": [],
            "embedded_api": [],
            "parse": {"status": "skipped_test"},
            "concurrent": False,
        },
        "tool": {
            "kind": "executable",
            "test": False,
            "files": ["tool/main.c"],
            "links": ["liblib.a"],
            "entry_points": [],
            "embedded_api": [],
            "parse": {"status": "ok"},
            "concurrent": False,
        },
    }


def _hep_with_tool_and_test_compiling_header(functions: dict[str, dict]) -> dict[str, dict]:
    # The executable and the test unit include the public header too: the function is theirs as well.
    functions[HEP_PUBLIC]["units"] = ["liblib.a", "tests/run", "tool"]
    return functions


def test_only_the_public_header_function_is_header_api() -> None:
    functions = _hep_with_tool_and_test_compiling_header(_hep_functions())
    public = {"method": "outside_source_dirs", "files": ["inc/lib/lib.h"]}
    got = pm.header_api(_hep_units(), functions, public)
    # A library unit only: no executable, no test unit.
    assert got == {"liblib.a": [HEP_PUBLIC]}


def test_installed_public_headers_map_back_to_the_tree() -> None:
    public = {"method": "install", "files": ["/framac-scratch/install/usr/local/include/lib/lib.h"]}
    got = pm.header_api(_hep_units(), _hep_functions(), public)
    assert got == {"liblib.a": [HEP_PUBLIC]}


def test_an_installed_header_maps_to_the_tree_header_with_the_longest_common_path() -> None:
    headers = ["inc/lib/lib.h", "src/lib.h", "inc/lib/other.h"]
    staged = {"method": "install", "files": ["/s/install/include/lib/lib.h"]}
    assert pm.public_header_files(staged, headers) == {"inc/lib/lib.h"}
    # A tie keeps every tied header.
    flat = {"method": "install", "files": ["/s/install/include/lib.h"]}
    assert pm.public_header_files(flat, headers) == {"inc/lib/lib.h", "src/lib.h"}


def test_a_public_header_defining_no_function_is_not_matched_to_a_private_one() -> None:
    # Tree-relative public headers are taken as they are: `inc/lib/priv.h` is not `src/priv.h`.
    public = {"method": "outside_source_dirs", "files": ["inc/lib/lib.h", "inc/lib/priv.h"]}
    assert pm.header_api(_hep_units(), _hep_functions(), public) == {"liblib.a": [HEP_PUBLIC]}
    # A staged header stands for the project header it was installed from, even one that defines no
    # function, not for a private header of the same name.
    staged = {"method": "install", "files": ["/s/install/include/lib/lib.h", "/s/install/include/lib/priv.h"]}
    included = ["inc/lib/lib.h", "inc/lib/priv.h", "src/priv.h"]
    assert pm.header_api(_hep_units(), _hep_functions(), staged, included) == {"liblib.a": [HEP_PUBLIC]}


def test_no_public_headers_no_header_api() -> None:
    assert pm.header_api(_hep_units(), _hep_functions(), None) == {"liblib.a": []}
    assert pm.header_api(_hep_units(), _hep_functions(), {"method": None, "files": []}) == {"liblib.a": []}


def test_a_shared_library_gets_header_api_too() -> None:
    units = _hep_units()
    units["liblib.a"]["kind"] = "shared_lib"
    public = {"method": "outside_source_dirs", "files": ["inc/lib/lib.h"]}
    assert pm.header_api(units, _hep_functions(), public) == {"liblib.a": [HEP_PUBLIC]}


def test_the_model_schema_accepts_header_api() -> None:
    schema = load_schema(SCRIPTS.parent / "schemas" / "phase0_model.schema.json")
    unit_schema = {**schema["properties"]["units"], "definitions": schema["definitions"]}
    units = _hep_units()
    units["liblib.a"]["header_api"] = [HEP_PUBLIC]
    assert Validator(unit_schema).errors(units) == []
    units["liblib.a"]["header_api"] = [""]
    assert Validator(unit_schema).errors(units)
