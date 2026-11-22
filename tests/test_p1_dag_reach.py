"""
Unit tests for Wave 2 / P1 Trust, Call-Graph DAG & Reachability Gate (W2-A):
  - scripts/trust.py: FRAMAC_HARNESS_SCOPE_V2 feature flag, input_role / attacker_params
    propagation, visibility-aware Rule 1 (public_lib + plugin_so vtable callbacks only),
    and active threat-model missing-entry warnings.
  - scripts/build_callgraph_dag.py: const/has_init/raw_type propagation on global_variables,
    unit_visibility on modules, and FRAMAC_HARNESS_SCOPE_V2 candidate_entry_points scoping
    across executable, plugin_so, internal_convenience, and public_lib units.
  - scripts/harness_reach.py: first-class tf_* static and dynamic reach credit, P2A
    api_auto_exempt reasons, and batch repeatable `exempt --function a --function b`.
  - Schema validation against phase0_model, callgraph_dag, harness_reach, and
    harness_reach_dynamic schemas.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import build_callgraph_dag as bcd
import harness_reach as hr
import phase0_gates
import trust as T
from minischema import Validator, load_schema
from phase0_model import validate_model

pytestmark = pytest.mark.unit

SCHEMAS_DIR = Path(__file__).resolve().parents[1] / "schemas"
TIER_1A = "Tier 1A (Untrusted Binary / Network Parser)"


def _fn(
    name: str,
    file: str,
    *,
    units: list[str],
    static: bool = False,
    header: bool = False,
    signature: str = "int(const char *,unsigned long)",
    external_calls: list[str] | None = None,
    line: int = 10,
) -> dict[str, Any]:
    return {
        "name": name,
        "file": file,
        "kernel_names": {u: name for u in units},
        "units": list(units),
        "line": line,
        "end_line": line + 5,
        "lines": 6,
        "static": static,
        "inline": False,
        "header": header,
        "signature": signature,
        "loops": 0,
        "cyclomatic": 1,
        "address_taken": False,
        "source": "frama-c-kernel",
        "external_calls": list(external_calls or []),
    }


def _sudo_shaped_model() -> dict[str, Any]:
    """
    Sudo-shaped multi-unit Phase 0 model with all 4 unit_visibility classes:
      - build/sudo (executable): main(argc, argv) -> parse_args -> conv_helper; unused_internal
        (embedded_api includes parse_args and unused_internal)
      - build/sudoers.so (plugin_so): exported_data_symbols = [sudoers_policy, sudoers_io],
        entry_points = [], static vtable callbacks policy_open / io_log_tty + helper sudoers_util
      - build/libsudo_conv.a (internal_convenience): linked by build/sudo, conv_helper & conv_unused
      - build/libsudo_util.so (public_lib): exported util_parse, util_read_cfg, util_format_log,
        util_trusted_init + public header inline util_hdr_check
    """
    fns: dict[str, dict[str, Any]] = {
        # executable: build/sudo
        "src/sudo.c#main": _fn("main", "src/sudo.c", units=["build/sudo"], signature="int(int,char **)"),
        "src/parse_args.c#parse_args": _fn("parse_args", "src/parse_args.c", units=["build/sudo"]),
        "src/internal.c#unused_internal": _fn("unused_internal", "src/internal.c", units=["build/sudo"]),
        "src/net.c#read_net_cmd": _fn("read_net_cmd", "src/net.c", units=["build/sudo"], external_calls=["recv"]),
        # plugin_so: build/sudoers.so
        "plugins/sudoers/policy.c#policy_open": _fn(
            "policy_open", "plugins/sudoers/policy.c", units=["build/sudoers.so"], static=True
        ),
        "plugins/sudoers/policy.c#policy_check": _fn(
            "policy_check", "plugins/sudoers/policy.c", units=["build/sudoers.so"], static=True
        ),
        "plugins/sudoers/iolog.c#io_log_tty": _fn(
            "io_log_tty", "plugins/sudoers/iolog.c", units=["build/sudoers.so"], static=True
        ),
        "plugins/sudoers/util.c#sudoers_nonstatic_helper": _fn(
            "sudoers_nonstatic_helper", "plugins/sudoers/util.c", units=["build/sudoers.so"]
        ),
        # internal_convenience: build/libsudo_conv.a
        "lib/conv/conv.c#conv_helper": _fn("conv_helper", "lib/conv/conv.c", units=["build/libsudo_conv.a"]),
        "lib/conv/conv.c#conv_unused": _fn("conv_unused", "lib/conv/conv.c", units=["build/libsudo_conv.a"]),
        # public_lib: build/libsudo_util.so
        "lib/util/parse.c#util_parse": _fn("util_parse", "lib/util/parse.c", units=["build/libsudo_util.so"]),
        "lib/util/parse.c#util_read_cfg": _fn(
            "util_read_cfg",
            "lib/util/parse.c",
            units=["build/libsudo_util.so"],
            external_calls=["fgets"],
        ),
        "lib/util/log.c#util_format_log": _fn("util_format_log", "lib/util/log.c", units=["build/libsudo_util.so"]),
        "lib/util/init.c#util_trusted_init": _fn(
            "util_trusted_init", "lib/util/init.c", units=["build/libsudo_util.so"]
        ),
        "include/sudo_util.h#util_hdr_check": _fn(
            "util_hdr_check",
            "include/sudo_util.h",
            units=["build/libsudo_util.so"],
            static=True,
            header=True,
        ),
    }
    return {
        "schema_version": 2,
        "generated_at": "2026-11-22T00:00:00Z",
        "status": "ok",
        "capture": "workspace/reports/build_capture.json",
        "warnings": [],
        "units": {
            "build/sudo": {
                "kind": "executable",
                "test": False,
                "files": ["src/sudo.c", "src/parse_args.c", "src/internal.c", "src/net.c"],
                "links": ["build/libsudo_conv.a"],
                "cppflags": [],
                "entry_points": ["src/sudo.c#main"],
                "embedded_api": ["src/parse_args.c#parse_args", "src/internal.c#unused_internal"],
                "embedded_api_source": "header_declared_internal",
                "exported_data_symbols": [],
                "unit_visibility": "executable",
                "parse": {"status": "ok"},
                "concurrent": False,
            },
            "build/sudoers.so": {
                "kind": "shared_lib",
                "test": False,
                "files": [
                    "plugins/sudoers/policy.c",
                    "plugins/sudoers/iolog.c",
                    "plugins/sudoers/util.c",
                ],
                "links": [],
                "cppflags": [],
                "entry_points": [],
                "embedded_api": [],
                "exported_data_symbols": ["sudoers_policy", "sudoers_io"],
                "unit_visibility": "plugin_so",
                "parse": {"status": "ok"},
                "concurrent": False,
            },
            "build/libsudo_conv.a": {
                "kind": "static_lib",
                "test": False,
                "files": ["lib/conv/conv.c"],
                "links": [],
                "cppflags": [],
                "entry_points": ["lib/conv/conv.c#conv_helper", "lib/conv/conv.c#conv_unused"],
                "embedded_api": [],
                "exported_data_symbols": [],
                "unit_visibility": "internal_convenience",
                "parse": {"status": "ok"},
                "concurrent": False,
            },
            "build/libsudo_util.so": {
                "kind": "shared_lib",
                "test": False,
                "files": ["lib/util/parse.c", "lib/util/log.c", "lib/util/init.c"],
                "links": [],
                "cppflags": [],
                "entry_points": [
                    "lib/util/parse.c#util_parse",
                    "lib/util/parse.c#util_read_cfg",
                    "lib/util/log.c#util_format_log",
                    "lib/util/init.c#util_trusted_init",
                ],
                "header_api": ["include/sudo_util.h#util_hdr_check"],
                "embedded_api": [],
                "exported_data_symbols": ["util_schema_desc"],
                "unit_visibility": "public_lib",
                "parse": {"status": "ok"},
                "concurrent": False,
            },
        },
        "functions": fns,
        "edges": [
            {
                "caller": "src/sudo.c#main",
                "callee": "src/parse_args.c#parse_args",
                "kind": "direct",
                "sources": ["frama-c-kernel"],
            },
            {
                "caller": "src/parse_args.c#parse_args",
                "callee": "lib/conv/conv.c#conv_helper",
                "kind": "direct",
                "sources": ["frama-c-kernel"],
            },
        ],
        "global_variables": {
            "plugins/sudoers/policy.c#sudoers_policy": {
                "name": "sudoers_policy",
                "file": "plugins/sudoers/policy.c",
                "static": False,
                "type": "struct policy_plugin",
                "const": False,
                "has_init": True,
                "raw_type": "struct policy_plugin",
                "size": 128,
                "units": ["build/sudoers.so"],
                "init_functions": ["plugins/sudoers/policy.c#policy_open"],
                "init_globals": ["plugins/sudoers/policy.c#policy_sub_ops"],
            },
            "plugins/sudoers/policy.c#policy_sub_ops": {
                "name": "policy_sub_ops",
                "file": "plugins/sudoers/policy.c",
                "static": True,
                "type": "struct policy_ops",
                "const": True,
                "has_init": True,
                "raw_type": "const struct policy_ops",
                "size": 32,
                "units": ["build/sudoers.so"],
                "init_functions": ["plugins/sudoers/policy.c#policy_check"],
                "init_globals": [],
            },
            "plugins/sudoers/iolog.c#sudoers_io": {
                "name": "sudoers_io",
                "file": "plugins/sudoers/iolog.c",
                "static": False,
                "type": "struct io_plugin",
                "const": True,
                "has_init": True,
                "raw_type": "const struct io_plugin",
                "size": 64,
                "units": ["build/sudoers.so"],
                "init_functions": ["plugins/sudoers/iolog.c#io_log_tty"],
                "init_globals": [],
            },
            "lib/util/parse.c#util_schema_desc": {
                "name": "util_schema_desc",
                "file": "lib/util/parse.c",
                "static": False,
                "type": "struct util_desc",
                "const": True,
                "has_init": True,
                "raw_type": "util_desc_t const",
                "size": 96,
                "units": ["build/libsudo_util.so"],
                "init_functions": [],
                "init_globals": [],
            },
        },
        "externals": ["recv", "fgets"],
        "entry_points": [
            "src/sudo.c#main",
            "lib/util/parse.c#util_parse",
            "lib/util/parse.c#util_read_cfg",
            "lib/util/log.c#util_format_log",
            "lib/util/init.c#util_trusted_init",
        ],
        "macro_aliases": {},
    }


def _tm_block(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "schema_version": 1,
        "input_sources": [],
        "secrets": [],
        "auth_gates": [],
        "output_sinks": [],
    }
    base.update(kw)
    return base


# ---------------------------------------------------------------------------------------------------
# Feature flag & trust.py
# ---------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        (None, True),
        ("", True),
        ("off", False),
        ("0", False),
        ("false", False),
        ("no", False),
        ("on", True),
        ("1", True),
        ("true", True),
        ("YES", True),
        (" True ", True),
    ],
)
def test_harness_scope_v2_flag_parsing(raw: str | None, expected: bool) -> None:
    env = {} if raw is None else {T.HARNESS_SCOPE_V2_ENV: raw}
    assert T.harness_scope_v2_enabled(env) is expected


def test_trust_rule1_scoping_off_vs_on(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    With FRAMAC_HARNESS_SCOPE_V2=off: legacy Rule 1 marks executable embedded_api and
    internal_convenience static_lib exports as boundary untrusted:default.
    With FRAMAC_HARNESS_SCOPE_V2=on: only public_lib exports and plugin_so vtable callbacks
    receive boundary untrusted:default; executable embedded_api and internal_convenience
    still get untrusted:call_graph when reached from main/readers.
    """
    model = _sudo_shaped_model()

    # Legacy mode (flag off).
    monkeypatch.setenv(T.HARNESS_SCOPE_V2_ENV, "off")
    res_off = T.compute_trust(model)
    f_off = res_off["functions"]
    assert f_off["src/internal.c#unused_internal"]["boundary"] is True
    assert f_off["src/internal.c#unused_internal"]["source"] == "default"
    assert f_off["lib/conv/conv.c#conv_unused"]["boundary"] is True
    assert f_off["lib/conv/conv.c#conv_unused"]["source"] == "default"
    # Plugin static vtable callbacks are NOT auto-marked in legacy mode.
    assert f_off["plugins/sudoers/policy.c#policy_open"]["value"] == "trusted"

    # V2 mode (flag on).
    monkeypatch.setenv(T.HARNESS_SCOPE_V2_ENV, "on")
    res_on = T.compute_trust(model)
    f_on = res_on["functions"]

    # Executable embedded_api: NOT boundary untrusted:default.
    # parse_args IS reached from main -> untrusted:call_graph (non-boundary).
    assert f_on["src/parse_args.c#parse_args"]["value"] == "untrusted"
    assert f_on["src/parse_args.c#parse_args"]["source"] == "call_graph"
    assert f_on["src/parse_args.c#parse_args"]["boundary"] is False
    # unused_internal is NOT reached from main/readers -> trusted:default.
    assert f_on["src/internal.c#unused_internal"]["value"] == "trusted"
    assert f_on["src/internal.c#unused_internal"]["boundary"] is False
    # main with argv stays boundary untrusted.
    assert f_on["src/sudo.c#main"]["value"] == "untrusted"
    assert f_on["src/sudo.c#main"]["boundary"] is True

    # internal_convenience .a: NOT boundary untrusted:default.
    # conv_helper IS reached from main -> parse_args -> conv_helper -> untrusted:call_graph.
    assert f_on["lib/conv/conv.c#conv_helper"]["value"] == "untrusted"
    assert f_on["lib/conv/conv.c#conv_helper"]["source"] == "call_graph"
    assert f_on["lib/conv/conv.c#conv_helper"]["boundary"] is False
    assert f_on["lib/conv/conv.c#conv_unused"]["value"] == "trusted"

    # plugin_so: vtable callbacks resolved from exported_data_symbols (including transitive init_globals)
    # are boundary untrusted:default; unrelated non-static helper is NOT auto-marked.
    for cb in (
        "plugins/sudoers/policy.c#policy_open",
        "plugins/sudoers/policy.c#policy_check",
        "plugins/sudoers/iolog.c#io_log_tty",
    ):
        assert f_on[cb]["value"] == "untrusted"
        assert f_on[cb]["source"] == "default"
        assert f_on[cb]["boundary"] is True
    assert f_on["plugins/sudoers/util.c#sudoers_nonstatic_helper"]["value"] == "trusted"

    # public_lib exports remain boundary untrusted:default.
    assert f_on["lib/util/parse.c#util_parse"]["value"] == "untrusted"
    assert f_on["lib/util/parse.c#util_parse"]["source"] == "default"
    assert f_on["lib/util/parse.c#util_parse"]["boundary"] is True


def test_trust_propagates_input_role_attacker_params_and_missing_warnings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    input_role and attacker_params propagate from THREAT_MODEL.md input_sources (and validate
    against phase0_model.schema.json). Under FRAMAC_HARNESS_SCOPE_V2=on, missing public_lib
    exports and missing input_reader roots emit warnings.
    """
    model = _sudo_shaped_model()
    block = _tm_block(
        input_sources=[
            {
                "function": "util_parse",
                "role": "entry",
                "params": ["buf", "len"],
                "description": "untrusted buffer parser",
            },
            {
                "function": "util_read_cfg",
                "role": "reader",
                "description": "reads untrusted config file",
            },
        ],
        trusted_callers=[
            {
                "functions": ["util_trusted_init"],
                "reason": "called only once with static defaults",
            }
        ],
    )
    threat = {"status": T.STATUS_OK, "block": block, "path": "THREAT_MODEL.md", "sha256": "a" * 64, "errors": []}

    # Always safe to populate input_role / attacker_params even with flag off.
    monkeypatch.setenv(T.HARNESS_SCOPE_V2_ENV, "off")
    res_off = T.compute_trust(model, threat)
    assert res_off["functions"]["lib/util/parse.c#util_parse"]["input_role"] == "entry"
    assert res_off["functions"]["lib/util/parse.c#util_parse"]["attacker_params"] == ["buf", "len"]
    assert res_off["functions"]["lib/util/parse.c#util_read_cfg"]["input_role"] == "reader"
    assert res_off["functions"]["lib/util/parse.c#util_read_cfg"]["attacker_params"] is None
    assert "input_role" not in res_off["functions"]["lib/util/log.c#util_format_log"]
    assert not any("missing from" in w for w in res_off["warnings"])

    # With flag on: annotate_model validates against phase0_model.schema.json and emits missing warnings.
    monkeypatch.setenv(T.HARNESS_SCOPE_V2_ENV, "on")
    T.annotate_model(model, threat=threat)
    assert validate_model(model) == []

    warnings = model["trust"]["warnings"]
    # util_format_log is a public_lib export missing from input_sources (and not in trusted_callers).
    assert any("util_format_log" in w and "missing from" in w for w in warnings)
    # read_net_cmd is an input_reader root (calls recv) missing from input_sources.
    assert any("read_net_cmd" in w and "missing from" in w for w in warnings)
    # util_trusted_init is in trusted_callers, util_parse and util_read_cfg are in input_sources -> no warning.
    assert not any("util_trusted_init" in w for w in warnings)
    assert not any("util_parse" in w for w in warnings)
    assert not any("util_read_cfg" in w for w in warnings)


# ---------------------------------------------------------------------------------------------------
# build_callgraph_dag.py
# ---------------------------------------------------------------------------------------------------


def test_dag_propagates_globals_and_visibility_and_scopes_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    DAG always propagates const/has_init/raw_type on global_variables and unit_visibility on
    modules. Under FRAMAC_HARNESS_SCOPE_V2=on, candidate_entry_points follows the 4 visibility
    rules and validates against callgraph_dag.schema.json.
    """
    block = _tm_block(
        input_sources=[
            {
                "function": "src/net.c#read_net_cmd",
                "role": "reader",
                "description": "network command reader",
            },
            {
                "function": "util_parse",
                "role": "entry",
                "params": ["buf", "len"],
                "description": "untrusted buffer parser",
            },
            {
                "function": "util_read_cfg",
                "role": "reader",
                "description": "reads untrusted config",
            },
        ],
        trusted_callers=[
            {
                "functions": ["util_trusted_init"],
                "reason": "called only with trusted constants",
            }
        ],
    )
    threat = {"status": T.STATUS_OK, "block": block, "path": "THREAT_MODEL.md", "sha256": "b" * 64, "errors": []}

    # --- Flag OFF: legacy candidate_entry_points + additive metadata ---
    monkeypatch.setenv(T.HARNESS_SCOPE_V2_ENV, "off")
    model_off = _sudo_shaped_model()
    T.annotate_model(model_off, threat=threat)
    dag_off = bcd.build_dag(tmp_path, model_off)
    dag_schema = load_schema(SCHEMAS_DIR / "callgraph_dag.schema.json")
    assert Validator(dag_schema).errors(dag_off) == []

    # Additive global metadata propagated even when flag is off.
    g_desc = dag_off["global_variables"]["lib/util/parse.c#util_schema_desc"]
    assert g_desc["const"] is True
    assert g_desc["has_init"] is True
    assert g_desc["raw_type"] == "util_desc_t const"
    assert g_desc["type"] == "struct util_desc"

    # Additive unit_visibility propagated even when flag is off.
    assert dag_off["modules"]["sudo"]["unit_visibility"] == "executable"
    assert dag_off["modules"]["sudoers_so"]["unit_visibility"] == "plugin_so"
    assert dag_off["modules"]["libsudo_conv_a"]["unit_visibility"] == "internal_convenience"
    assert dag_off["modules"]["libsudo_util_so"]["unit_visibility"] == "public_lib"

    # Legacy behavior preserved: executable dumps embedded_api; plugin_so dumps non-static helper;
    # internal_convenience dumps its archive exports.
    assert set(dag_off["modules"]["sudo"]["candidate_entry_points"]) == {
        "main",
        "parse_args",
        "unused_internal",
    }
    assert dag_off["modules"]["sudoers_so"]["candidate_entry_points"] == ["sudoers_nonstatic_helper"]
    assert set(dag_off["modules"]["libsudo_conv_a"]["candidate_entry_points"]) == {
        "conv_helper",
        "conv_unused",
    }

    # --- Flag ON: P1 visibility-scoped candidate_entry_points ---
    monkeypatch.setenv(T.HARNESS_SCOPE_V2_ENV, "on")
    model_on = _sudo_shaped_model()
    T.annotate_model(model_on, threat=threat)
    dag_on = bcd.build_dag(tmp_path, model_on)
    assert Validator(dag_schema).errors(dag_on) == []

    # 1. executable: [main] + explicit THREAT_MODEL input_sources only (never embedded_api!).
    sudo_mod = dag_on["modules"]["sudo"]
    assert sudo_mod["candidate_entry_points"] == ["main", "read_net_cmd"]
    assert "parse_args" not in sudo_mod["candidate_entry_points"]
    assert "unused_internal" not in sudo_mod["candidate_entry_points"]
    assert sudo_mod["threat_model_entries"] == ["read_net_cmd"]

    # 2. plugin_so: exact vtable callbacks from exported_data_symbols -> init_functions (including
    #    transitive init_globals), NOT non-static helper!
    plugin_mod = dag_on["modules"]["sudoers_so"]
    assert set(plugin_mod["candidate_entry_points"]) == {"policy_open", "policy_check", "io_log_tty"}
    assert "sudoers_nonstatic_helper" not in plugin_mod["candidate_entry_points"]

    # 3. internal_convenience: empty when no threat-model entry targets it directly, with note.
    conv_mod = dag_on["modules"]["libsudo_conv_a"]
    assert conv_mod["candidate_entry_points"] == []
    assert conv_mod["harness_scope_note"] == "internal_convenience_covered_by_consumers"

    # 4. public_lib with active THREAT_MODEL: threat_model_entries attached; trusted_callers &
    #    non-attacker entries filtered into deferred_non_attacker_entries while kept in functions for WP.
    pub_mod = dag_on["modules"]["libsudo_util_so"]
    assert pub_mod["candidate_entry_points"] == ["util_parse", "util_read_cfg"]
    assert pub_mod["threat_model_entries"] == ["util_parse", "util_read_cfg"]
    assert set(pub_mod["deferred_non_attacker_entries"]) == {
        "util_format_log",
        "util_trusted_init",
        "util_hdr_check",
    }
    # All functions remain in DAG for WP ledger.
    for fn_name in ("util_format_log", "util_trusted_init", "util_hdr_check"):
        assert fn_name in dag_on["functions"]
        assert fn_name in pub_mod["functions"]

    # Per-function trust record carries input_role & attacker_params into the DAG.
    assert dag_on["functions"]["util_parse"]["trust"]["input_role"] == "entry"
    assert dag_on["functions"]["util_parse"]["trust"]["attacker_params"] == ["buf", "len"]
    assert dag_on["functions"]["util_read_cfg"]["trust"]["input_role"] == "reader"


def test_dag_internal_convenience_with_direct_threat_model_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An internal_convenience unit directly targeted by THREAT_MODEL input_sources keeps only that entry."""
    monkeypatch.setenv(T.HARNESS_SCOPE_V2_ENV, "on")
    model = _sudo_shaped_model()
    block = _tm_block(
        input_sources=[
            {"function": "conv_helper", "role": "entry", "description": "direct fuzz target"},
        ]
    )
    threat = {"status": T.STATUS_OK, "block": block, "path": "THREAT_MODEL.md", "sha256": "c" * 64, "errors": []}
    T.annotate_model(model, threat=threat)
    dag = bcd.build_dag(tmp_path, model)
    conv_mod = dag["modules"]["libsudo_conv_a"]
    assert conv_mod["candidate_entry_points"] == ["conv_helper"]
    assert "harness_scope_note" not in conv_mod


# ---------------------------------------------------------------------------------------------------
# harness_reach.py: tf_* static + dynamic reach credit, auto-exempt, batch exempt
# ---------------------------------------------------------------------------------------------------


def _tf_dag() -> dict[str, Any]:
    fns = {
        "policy_open": {
            "name": "policy_open",
            "file": "plugins/sudoers/policy.c",
            "module": "sudoers_so",
            "lexer_module": "sudoers",
            "is_static": True,
            "internal_callees": ["policy_helper"],
            "internal_callers": [],
            "tier": TIER_1A,
        },
        "policy_check": {
            "name": "policy_check",
            "file": "plugins/sudoers/policy.c",
            "module": "sudoers_so",
            "lexer_module": "sudoers",
            "is_static": True,
            "internal_callees": [],
            "internal_callers": [],
            "tier": TIER_1A,
        },
        "policy_helper": {
            "name": "policy_helper",
            "file": "plugins/sudoers/policy.c",
            "module": "sudoers_so",
            "lexer_module": "sudoers",
            "is_static": True,
            "internal_callees": [],
            "internal_callers": ["policy_open"],
            "tier": TIER_1A,
        },
        "conv_helper": {
            "name": "conv_helper",
            "file": "lib/conv/conv.c",
            "module": "libsudo_conv_a",
            "lexer_module": "conv",
            "is_static": False,
            "internal_callees": [],
            "internal_callers": [],
            "tier": TIER_1A,
        },
    }
    return {
        "schema_version": 1,
        "module_kind": "link_unit",
        "callgraph_source": "frama_c",
        "warnings": [],
        "modules": {
            "sudoers_so": {
                "module": "sudoers_so",
                "unit": "build/sudoers.so",
                "kind": "shared_lib",
                "unit_visibility": "plugin_so",
                "tier": TIER_1A,
                "functions": ["policy_open", "policy_check", "policy_helper"],
                "candidate_entry_points": ["policy_open", "policy_check"],
                "lexer_modules": ["sudoers"],
            },
            "libsudo_conv_a": {
                "module": "libsudo_conv_a",
                "unit": "build/libsudo_conv.a",
                "kind": "static_lib",
                "unit_visibility": "internal_convenience",
                "harness_scope_note": "internal_convenience_covered_by_consumers",
                "tier": TIER_1A,
                "functions": ["conv_helper"],
                "candidate_entry_points": [],
                "lexer_modules": ["conv"],
            },
        },
        "lexer_modules": {
            "sudoers": {
                "module": "sudoers",
                "tier": TIER_1A,
                "functions": ["policy_open", "policy_check", "policy_helper"],
            },
            "conv": {
                "module": "conv",
                "tier": TIER_1A,
                "functions": ["conv_helper"],
            },
        },
        "unit_of_lexer_module": {"sudoers": "sudoers_so", "conv": "libsudo_conv_a"},
        "functions": fns,
    }


def _setup_tf_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fuzzer_body: str) -> tuple[Path, Path, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "workspace" / "work" / "fuzz").mkdir(parents=True)
    fuzzer_src = tmp_path / "workspace" / "work" / "fuzz" / "fuzz_sudoers.c"
    fuzzer_src.write_text(fuzzer_body, encoding="utf-8")

    reports = tmp_path / "workspace" / "reports"
    reports.mkdir(parents=True)
    dag_path = reports / "callgraph_dag.json"
    dag_path.write_text(json.dumps(_tf_dag(), indent=2), encoding="utf-8")

    hdir = tmp_path / "workspace" / "harnesses"
    hdir.mkdir(parents=True)
    tf_harness = hdir / "harness_tf_sudoers.c"
    tf_harness.write_text(
        "int __framac_target_embedded_LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n);\n"
        "void drive(const unsigned char *d, unsigned long n) {\n"
        "  __framac_target_embedded_LLVMFuzzerTestOneInput(d, n);\n"
        "}\n",
        encoding="utf-8",
    )
    tf_sidecar = {
        "module": "tf_sudoers",
        "unit": "sudoers_so",
        "harness_file": "workspace/harnesses/harness_tf_sudoers.c",
        "sources": ["workspace/work/fuzz/fuzz_sudoers.c"],
        "cppflags": "-Iworkspace/work",
        "entry_fn": "__framac_target_embedded_LLVMFuzzerTestOneInput",
        "entry_style": "buffer_len",
        "target_fuzzer": {
            "id": "sudoers",
            "source": "fuzz/fuzz_sudoers.c",
            "initialize": False,
        },
    }
    (hdir / "harness_tf_sudoers.json").write_text(json.dumps(tf_sidecar, indent=2), encoding="utf-8")
    return tmp_path, dag_path, hdir


def test_tf_static_reach_credit_off_vs_on_and_schema(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    With FRAMAC_HARNESS_SCOPE_V2=off: tf_sudoers is additive only; sudoers_so still fails no_harness.
    With FRAMAC_HARNESS_SCOPE_V2=on: passing tf_sudoers credits policy_open and policy_check to
    sudoers_so via covered_by_target_fuzzers, internal_convenience passes via its scope note,
    and the report validates against harness_reach.schema.json.
    """
    run_dir, dag_path, hdir = _setup_tf_run(
        tmp_path,
        monkeypatch,
        "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) {\n"
        "  policy_open(d, n);\n"
        "  policy_check(d, n);\n"
        "  return 0;\n"
        "}\n",
    )
    reach_schema = load_schema(SCHEMAS_DIR / "harness_reach.schema.json")

    # Flag OFF: sudoers_so fails no_harness, internal_convenience fails no_harness.
    monkeypatch.setenv(T.HARNESS_SCOPE_V2_ENV, "off")
    rep_off = hr.run_check(dag_path, hdir, None, run_dir=run_dir)
    assert Validator(reach_schema).errors(rep_off) == []
    assert rep_off["passed"] is False
    by_mod_off = {r["module"]: r for r in rep_off["modules"]}
    assert by_mod_off["tf_sudoers"]["passed"] is True
    assert by_mod_off["sudoers_so"]["passed"] is False
    assert by_mod_off["sudoers_so"]["error"] == "no_harness"
    assert by_mod_off["libsudo_conv_a"]["passed"] is False

    # Flag ON: passing tf_sudoers covers both entry points of sudoers_so; internal_convenience passes.
    monkeypatch.setenv(T.HARNESS_SCOPE_V2_ENV, "on")
    rep_on = hr.run_check(dag_path, hdir, None, run_dir=run_dir)
    assert Validator(reach_schema).errors(rep_on) == []
    assert rep_on["passed"] is True
    by_mod_on = {r["module"]: r for r in rep_on["modules"]}
    assert by_mod_on["sudoers_so"]["passed"] is True
    assert by_mod_on["sudoers_so"]["gaps"] == []
    assert by_mod_on["sudoers_so"]["covered_by_target_fuzzers"] == {
        "policy_check": ["tf_sudoers"],
        "policy_open": ["tf_sudoers"],
    }
    assert by_mod_on["libsudo_conv_a"]["passed"] is True
    assert by_mod_on["libsudo_conv_a"]["exempt"] == "internal_convenience_covered_by_consumers"

    # Filtered --module sudoers_so STILL aggregates tf_sudoers credit.
    rep_filtered = hr.run_check(dag_path, hdir, ["sudoers_so"], run_dir=run_dir)
    assert Validator(reach_schema).errors(rep_filtered) == []
    assert rep_filtered["passed"] is True
    assert rep_filtered["modules"][0]["covered_by_target_fuzzers"] == {
        "policy_check": ["tf_sudoers"],
        "policy_open": ["tf_sudoers"],
    }


def test_tf_partial_and_failing_credit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Partial tf_* leaves uncovered entry points as gaps; failing tf_* grants zero credit."""
    monkeypatch.setenv(T.HARNESS_SCOPE_V2_ENV, "on")

    # Partial: only policy_open reached -> policy_check stays a gap.
    run_dir, dag_path, hdir = _setup_tf_run(
        tmp_path / "partial",
        monkeypatch,
        "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) {\n  policy_open(d, n);\n  return 0;\n}\n",
    )
    rep = hr.run_check(dag_path, hdir, ["sudoers_so"], run_dir=run_dir)
    assert rep["passed"] is False
    row = rep["modules"][0]
    assert row["covered_by_target_fuzzers"] == {"policy_open": ["tf_sudoers"]}
    assert row["gaps"] == ["policy_check"]

    # Failing tf_*: reaches nothing -> grants no credit at all.
    run_dir2, dag_path2, hdir2 = _setup_tf_run(
        tmp_path / "failing",
        monkeypatch,
        "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { return (int)n; }\n",
    )
    rep2 = hr.run_check(dag_path2, hdir2, None, run_dir=run_dir2)
    by_mod = {r["module"]: r for r in rep2["modules"]}
    assert by_mod["tf_sudoers"]["passed"] is False
    assert by_mod["tf_sudoers"]["error"] == "target_fuzzer_reaches_nothing"
    assert by_mod["sudoers_so"]["passed"] is False
    assert "covered_by_target_fuzzers" not in by_mod["sudoers_so"]
    assert set(by_mod["sudoers_so"]["gaps"]) == {"policy_open", "policy_check"}


def test_tf_dynamic_reach_credit_and_schema(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Under FRAMAC_HARNESS_SCOPE_V2=on, run_dynamic aggregates dynamically executed functions from
    passing tf_* modules of the same unit, credits them via covered_by_target_fuzzers, and
    validates against harness_reach_dynamic.schema.json.
    """
    run_dir, dag_path, hdir = _setup_tf_run(
        tmp_path,
        monkeypatch,
        "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) {\n"
        "  policy_open(d, n);\n"
        "  policy_check(d, n);\n"
        "  return 0;\n"
        "}\n",
    )
    cov_dir = run_dir / "workspace" / "reports" / "coverage"
    cov_dir.mkdir(parents=True)
    (cov_dir / "tf_sudoers.json").write_text(
        json.dumps(
            {
                "status": "ok",
                "inputs": {"total": 10, "replayed": 10, "failed": 0, "not_replayed": 0},
                "functions": [
                    {"function": "policy_open", "file": "plugins/sudoers/policy.c", "executions": 10},
                    {"function": "policy_check", "file": "plugins/sudoers/policy.c", "executions": 7},
                ],
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv(T.HARNESS_SCOPE_V2_ENV, "on")
    dyn = hr.run_dynamic(dag_path, hdir, None, coverage_dir=cov_dir)
    by_mod = {r["module"]: r for r in dyn["modules"]}
    assert "sudoers_so" in by_mod
    sudo_row = by_mod["sudoers_so"]
    assert sudo_row["passed"] is True
    assert sudo_row["entry_points"] == 2
    assert sudo_row["entry_points_executed"] == 2
    assert sudo_row["gaps"] == []
    assert sudo_row["covered_by_target_fuzzers"] == {
        "policy_check": ["tf_sudoers"],
        "policy_open": ["tf_sudoers"],
    }

    # Record to harness_reach_dynamic.json and validate against harness_reach_dynamic.schema.json.
    out_dyn = run_dir / "workspace" / "reports" / "harness_reach_dynamic.json"
    hr.record_dynamic(run_dir, dyn, out_dyn, dag_path=dag_path, harness_dir=hdir)
    dyn_doc = json.loads(out_dyn.read_text(encoding="utf-8"))
    dyn_schema = load_schema(SCHEMAS_DIR / "harness_reach_dynamic.schema.json")
    assert Validator(dyn_schema).errors(dyn_doc) == []
    assert "warnings" not in dyn_doc

    # Incomplete tf_* coverage (not_replayed > 0) grants NO dynamic reach credit.
    (cov_dir / "tf_sudoers.json").write_text(
        json.dumps(
            {
                "status": "partial",
                "inputs": {"total": 10, "replayed": 5, "failed": 0, "not_replayed": 5},
                "functions": [
                    {"function": "policy_open", "file": "plugins/sudoers/policy.c", "executions": 5},
                    {"function": "policy_check", "file": "plugins/sudoers/policy.c", "executions": 5},
                ],
            }
        ),
        encoding="utf-8",
    )
    dyn_partial = hr.run_dynamic(dag_path, hdir, ["sudoers_so"], coverage_dir=cov_dir)
    assert dyn_partial["modules"][0]["passed"] is None


def test_auto_exempt_reasons_static_and_dynamic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Under FRAMAC_HARNESS_SCOPE_V2=on, api_auto_exempt accepts the three P2A automatic reasons and
    rejects arbitrary unapproved reasons; under flag=off, api_auto_exempt is ignored.
    """
    monkeypatch.chdir(tmp_path)
    fns = {
        "fn_reached": {
            "name": "fn_reached",
            "file": "src/api.c",
            "module": "libapi_a",
            "is_static": False,
            "internal_callees": [],
            "internal_callers": [],
        },
        "fn_no_attacker": {
            "name": "fn_no_attacker",
            "file": "src/api.c",
            "module": "libapi_a",
            "is_static": False,
            "internal_callees": [],
            "internal_callers": [],
        },
        "fn_trusted_param": {
            "name": "fn_trusted_param",
            "file": "src/api.c",
            "module": "libapi_a",
            "is_static": False,
            "internal_callees": [],
            "internal_callers": [],
        },
        "fn_refcount": {
            "name": "fn_refcount",
            "file": "src/api.c",
            "module": "libapi_a",
            "is_static": False,
            "internal_callees": [],
            "internal_callers": [],
        },
        "fn_unapproved": {
            "name": "fn_unapproved",
            "file": "src/api.c",
            "module": "libapi_a",
            "is_static": False,
            "internal_callees": [],
            "internal_callers": [],
        },
    }
    dag = {
        "schema_version": 1,
        "module_kind": "link_unit",
        "callgraph_source": "frama_c",
        "warnings": [],
        "modules": {
            "libapi_a": {
                "module": "libapi_a",
                "unit": "libapi.a",
                "kind": "static_lib",
                "unit_visibility": "public_lib",
                "tier": TIER_1A,
                "functions": list(fns),
                "candidate_entry_points": list(fns),
            }
        },
        "functions": fns,
    }
    reports = tmp_path / "workspace" / "reports"
    reports.mkdir(parents=True)
    dag_path = reports / "callgraph_dag.json"
    dag_path.write_text(json.dumps(dag), encoding="utf-8")

    hdir = tmp_path / "workspace" / "harnesses"
    hdir.mkdir(parents=True)
    (hdir / "harness_libapi_a.c").write_text("void drive(void) { fn_reached(); }\n", encoding="utf-8")
    sidecar = {
        "module": "libapi_a",
        "unit": "libapi_a",
        "harness_file": "workspace/harnesses/harness_libapi_a.c",
        "sources": ["src/api.c"],
        "cppflags": "-I.",
        "entry_fn": "fn_reached",
        "entry_style": "dispatch",
        "reach_exempt": {},
        "api_auto_exempt": {
            "fn_no_attacker": "no attacker data per the threat model",
            "fn_trusted_param": "trusted parameter fields has no instance",
            "fn_refcount": "refcount helper requires producer-allocated object",
            "fn_unapproved": "unrecognized custom skip reason",
        },
    }
    (hdir / "harness_libapi_a.json").write_text(json.dumps(sidecar), encoding="utf-8")

    # Flag OFF: none of api_auto_exempt are honored.
    monkeypatch.setenv(T.HARNESS_SCOPE_V2_ENV, "off")
    rep_off = hr.run_check(dag_path, hdir, ["libapi_a"], run_dir=tmp_path)
    assert rep_off["passed"] is False
    assert set(rep_off["modules"][0]["gaps"]) == {
        "fn_no_attacker",
        "fn_trusted_param",
        "fn_refcount",
        "fn_unapproved",
    }

    # Flag ON: the 3 approved reasons pass; the unapproved reason stays a gap.
    monkeypatch.setenv(T.HARNESS_SCOPE_V2_ENV, "on")
    rep_on = hr.run_check(dag_path, hdir, ["libapi_a"], run_dir=tmp_path)
    row = rep_on["modules"][0]
    assert row["gaps"] == ["fn_unapproved"]
    assert row["exempt"] == {
        "fn_no_attacker": "no attacker data per the threat model",
        "fn_refcount": "refcount helper requires producer-allocated object",
        "fn_trusted_param": "trusted parameter fields has no instance",
    }

    # Dynamic check also honors the 3 approved reasons under flag ON.
    cov_dir = reports / "coverage"
    cov_dir.mkdir(parents=True)
    (cov_dir / "libapi_a.json").write_text(
        json.dumps(
            {
                "status": "ok",
                "inputs": {"total": 1, "replayed": 1, "failed": 0, "not_replayed": 0},
                "functions": [{"function": "fn_reached", "file": "src/api.c", "executions": 1}],
            }
        ),
        encoding="utf-8",
    )
    dyn = hr.run_dynamic(dag_path, hdir, ["libapi_a"], coverage_dir=cov_dir)
    assert dyn["modules"][0]["gaps"] == ["fn_unapproved"]


def test_batch_exempt_repeatable_function_runs_regate_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """
    `harness_reach.py exempt --module M --function a --function b --reason R` records both in
    reach_exempt and invokes regate_after_exempt exactly ONCE, while single `--function a`
    remains backwards-compatible.
    """
    monkeypatch.chdir(tmp_path)
    fns = {
        "fn_a": {
            "name": "fn_a",
            "file": "src/a.c",
            "module": "mod_a",
            "is_static": False,
            "internal_callees": [],
            "internal_callers": [],
        },
        "fn_b": {
            "name": "fn_b",
            "file": "src/a.c",
            "module": "mod_a",
            "is_static": False,
            "internal_callees": [],
            "internal_callers": [],
        },
        "fn_c": {
            "name": "fn_c",
            "file": "src/a.c",
            "module": "mod_a",
            "is_static": False,
            "internal_callees": [],
            "internal_callers": [],
        },
    }
    dag = {
        "schema_version": 1,
        "module_kind": "link_unit",
        "callgraph_source": "frama_c",
        "warnings": [],
        "modules": {
            "mod_a": {
                "module": "mod_a",
                "unit": "liba.a",
                "kind": "static_lib",
                "tier": TIER_1A,
                "functions": list(fns),
                "candidate_entry_points": list(fns),
            }
        },
        "functions": fns,
    }
    reports = tmp_path / "workspace" / "reports"
    reports.mkdir(parents=True)
    dag_path = reports / "callgraph_dag.json"
    dag_path.write_text(json.dumps(dag), encoding="utf-8")

    hdir = tmp_path / "workspace" / "harnesses"
    hdir.mkdir(parents=True)
    (hdir / "harness_mod_a.c").write_text("void drive(void) { fn_c(); }\n", encoding="utf-8")
    sidecar = {
        "module": "mod_a",
        "unit": "mod_a",
        "harness_file": "workspace/harnesses/harness_mod_a.c",
        "sources": ["src/a.c"],
        "cppflags": "-I.",
        "entry_fn": "fn_c",
        "entry_style": "dispatch",
        "reach_exempt": {},
    }
    (hdir / "harness_mod_a.json").write_text(json.dumps(sidecar), encoding="utf-8")

    # Seed the reach gate so regate_after_exempt actually runs.
    initial = hr.run_check(dag_path, hdir, None, run_dir=tmp_path)
    phase0_gates.record_reach(tmp_path, initial, partial=False, dag_path=dag_path)
    assert phase0_gates.load_gates(tmp_path)["reach"]["passed"] is False

    regate_calls: list[str] = []
    orig_regate = hr.regate_after_exempt

    def spy_regate(run_dir: Path, d_path: Path, har_dir: Path, mod: str) -> dict[str, Any]:
        regate_calls.append(mod)
        return orig_regate(run_dir, d_path, har_dir, mod)

    monkeypatch.setattr(hr, "regate_after_exempt", spy_regate)

    # Batch exempt two functions in a single invocation.
    rc = hr.main(
        [
            "exempt",
            "--dag",
            str(dag_path),
            "--harness-dir",
            str(hdir),
            "--module",
            "mod_a",
            "--function",
            "fn_a",
            "--function",
            "fn_b",
            "--reason",
            "CLI-only debug helpers",
        ]
    )
    assert rc == 0
    assert regate_calls == ["mod_a"]  # regate ran exactly ONCE for the batch
    out = json.loads(capsys.readouterr().out)
    assert out["function"] == ["fn_a", "fn_b"]
    assert out["reach_exempt"] == {
        "fn_a": "CLI-only debug helpers",
        "fn_b": "CLI-only debug helpers",
    }
    assert phase0_gates.load_gates(tmp_path)["reach"]["passed"] is True

    # Single --function remains backwards-compatible (returns scalar string).
    rc_single = hr.main(
        [
            "exempt",
            "--dag",
            str(dag_path),
            "--harness-dir",
            str(hdir),
            "--module",
            "mod_a",
            "--function",
            "fn_a",
            "--reason",
            "updated reason",
        ]
    )
    assert rc_single == 0
    out_single = json.loads(capsys.readouterr().out)
    assert out_single["function"] == "fn_a"
    assert len(regate_calls) == 2


def test_static_reader_auto_exempt_and_reach_v2_off_vs_on(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Under FRAMAC_HARNESS_SCOPE_V2=on, file-local `static` required roots (like nanopb's `buf_read` and
    `pb_readbyte`) are auto-exempted when:
      (a) statically reached from at least one reached non-static harness root, OR
      (b) explicitly recorded as `static: not callable from the harness` in `api_auto_exempt` while
          having at least one public caller in the unit.
    Genuinely unreachable public functions (even if transitively reached or falsely listed as static)
    and uncalled static functions without any public caller MUST stay gaps.
    Under FRAMAC_HARNESS_SCOPE_V2=off, behavior is 100% unchanged.
    """
    monkeypatch.chdir(tmp_path)
    fns = {
        "pb_read": {
            "name": "pb_read",
            "file": "pb_decode.c",
            "module": "libprotobuf_nanopb_a",
            "is_static": False,
            "header": False,
            "internal_callees": ["buf_read", "public_transitive_only"],
            "internal_callers": [],
        },
        "pb_decode_tag": {
            "name": "pb_decode_tag",
            "file": "pb_decode.c",
            "module": "libprotobuf_nanopb_a",
            "is_static": False,
            "header": False,
            "internal_callees": ["pb_decode_varint32_eof"],
            "internal_callers": [],
        },
        "pb_decode_varint32_eof": {
            "name": "pb_decode_varint32_eof",
            "file": "pb_decode.c",
            "module": "libprotobuf_nanopb_a",
            "is_static": True,
            "header": False,
            "internal_callees": ["pb_readbyte"],
            "internal_callers": ["pb_decode_tag"],
        },
        "buf_read": {
            "name": "buf_read",
            "file": "pb_decode.c",
            "module": "libprotobuf_nanopb_a",
            "is_static": True,
            "header": False,
            "internal_callees": [],
            "internal_callers": ["pb_read"],
        },
        "pb_readbyte": {
            "name": "pb_readbyte",
            "file": "pb_decode.c",
            "module": "libprotobuf_nanopb_a",
            "is_static": True,
            "header": False,
            "internal_callees": [],
            "internal_callers": ["pb_decode_varint32_eof"],
        },
        "orphan_static": {
            "name": "orphan_static",
            "file": "pb_decode.c",
            "module": "libprotobuf_nanopb_a",
            "is_static": True,
            "header": False,
            "internal_callees": [],
            "internal_callers": [],
        },
        "public_transitive_only": {
            "name": "public_transitive_only",
            "file": "pb_decode.c",
            "module": "libprotobuf_nanopb_a",
            "is_static": False,
            "header": False,
            "internal_callees": [],
            "internal_callers": ["pb_read"],
        },
    }
    dag = {
        "schema_version": 1,
        "module_kind": "link_unit",
        "callgraph_source": "frama_c",
        "warnings": [],
        "modules": {
            "libprotobuf_nanopb_a": {
                "module": "libprotobuf_nanopb_a",
                "unit": "build/libprotobuf-nanopb.a",
                "kind": "static_lib",
                "unit_visibility": "public_lib",
                "tier": TIER_1A,
                "functions": list(fns),
                "candidate_entry_points": [
                    "pb_read",
                    "pb_decode_tag",
                    "buf_read",
                    "pb_readbyte",
                    "orphan_static",
                    "public_transitive_only",
                ],
            }
        },
        "functions": fns,
    }
    reports = tmp_path / "workspace" / "reports"
    reports.mkdir(parents=True)
    dag_path = reports / "callgraph_dag.json"
    dag_path.write_text(json.dumps(dag), encoding="utf-8")

    hdir = tmp_path / "workspace" / "harnesses"
    hdir.mkdir(parents=True)
    # Harness calls only `pb_read` (not `pb_decode_tag`, not `buf_read`, not `pb_readbyte`).
    (hdir / "harness_libprotobuf_nanopb_a.c").write_text("void drive(void) { pb_read(); }\n", encoding="utf-8")
    sidecar = {
        "module": "libprotobuf_nanopb_a",
        "unit": "libprotobuf_nanopb_a",
        "harness_file": "workspace/harnesses/harness_libprotobuf_nanopb_a.c",
        "sources": ["pb_decode.c"],
        "cppflags": "-I.",
        "entry_fn": "pb_read",
        "entry_style": "dispatch",
        "reach_exempt": {},
        "api_auto_exempt": {
            "pb_decode_tag": "trusted parameter fields has no instance",
            # Static reader with transitive public caller (pb_decode_tag -> pb_decode_varint32_eof -> pb_readbyte):
            "pb_readbyte": hr.AUTO_EXEMPT_STATIC_REASON,
            # Static function with ZERO public callers: MUST NOT be auto-exempted!
            "orphan_static": hr.AUTO_EXEMPT_STATIC_REASON,
            # Non-static public function wrongly marked static: MUST NOT be auto-exempted!
            "public_transitive_only": hr.AUTO_EXEMPT_STATIC_REASON,
        },
    }
    (hdir / "harness_libprotobuf_nanopb_a.json").write_text(json.dumps(sidecar), encoding="utf-8")

    reach_schema = load_schema(SCHEMAS_DIR / "harness_reach.schema.json")

    # Flag OFF: none of the v2 static-reader rules or api_auto_exempt apply.
    monkeypatch.setenv(T.HARNESS_SCOPE_V2_ENV, "off")
    rep_off = hr.run_check(dag_path, hdir, ["libprotobuf_nanopb_a"], run_dir=tmp_path)
    assert Validator(reach_schema).errors(rep_off) == []
    assert rep_off["passed"] is False
    assert set(rep_off["modules"][0]["gaps"]) == {
        "pb_decode_tag",
        "buf_read",
        "pb_readbyte",
        "orphan_static",
        "public_transitive_only",
    }

    # Flag ON:
    # - buf_read is satisfied via non-static harness root `pb_read` (even without api_auto_exempt!)
    # - pb_readbyte is satisfied via api_auto_exempt ("static: not callable from the harness") + public caller
    # - pb_decode_tag is satisfied via trusted-parameter api_auto_exempt
    # - orphan_static (no public caller) and public_transitive_only (non-static) stay GAPS!
    monkeypatch.setenv(T.HARNESS_SCOPE_V2_ENV, "on")
    rep_on = hr.run_check(dag_path, hdir, ["libprotobuf_nanopb_a"], run_dir=tmp_path)
    assert Validator(reach_schema).errors(rep_on) == []
    row = rep_on["modules"][0]
    assert row["passed"] is False
    assert row["gaps"] == ["orphan_static", "public_transitive_only"]
    assert row["exempt"]["pb_readbyte"] == hr.AUTO_EXEMPT_STATIC_REASON
    assert row["exempt"]["buf_read"] == "static: reached via non-static harness root(s) pb_read"
    assert row["exempt"]["pb_decode_tag"] == "trusted parameter fields has no instance"

    # Dynamic check under V2=on mirrors sidecar static-with-public-caller exemption and keeps
    # orphan_static + public_transitive_only as gaps.
    cov_dir = reports / "coverage"
    cov_dir.mkdir(parents=True)
    (cov_dir / "libprotobuf_nanopb_a.json").write_text(
        json.dumps(
            {
                "status": "ok",
                "inputs": {"total": 1, "replayed": 1, "failed": 0, "not_replayed": 0},
                "functions": [
                    {"function": "pb_read", "file": "pb_decode.c", "executions": 1},
                    {"function": "buf_read", "file": "pb_decode.c", "executions": 1},
                ],
            }
        ),
        encoding="utf-8",
    )
    dyn = hr.run_dynamic(dag_path, hdir, ["libprotobuf_nanopb_a"], coverage_dir=cov_dir)
    assert dyn["modules"][0]["gaps"] == ["orphan_static", "public_transitive_only"]


def test_check_unit_static_reader_from_submodule_harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    In `check_unit()` under FRAMAC_HARNESS_SCOPE_V2=on, unharnessed static required roots in a link
    unit are satisfied when reached from a non-static root of a sub-module harness OR recorded as
    `static: not callable from the harness` with a public caller in the unit, while an uncalled
    static root without a public caller stays a gap.
    """
    monkeypatch.chdir(tmp_path)
    fns = {
        "pub_entry": {
            "name": "pub_entry",
            "file": "src/api.c",
            "module": "libdemo_a",
            "lexer_module": "api",
            "is_static": False,
            "header": False,
            "internal_callees": ["static_reached"],
            "internal_callers": [],
            "tier": TIER_1A,
        },
        "pub_other": {
            "name": "pub_other",
            "file": "src/io.c",
            "module": "libdemo_a",
            "lexer_module": "io",
            "is_static": False,
            "header": False,
            "internal_callees": ["static_with_caller"],
            "internal_callers": [],
            "tier": TIER_1A,
        },
        "static_reached": {
            "name": "static_reached",
            "file": "src/io.c",
            "module": "libdemo_a",
            "lexer_module": "io",
            "is_static": True,
            "header": False,
            "internal_callees": [],
            "internal_callers": ["pub_entry"],
            "tier": TIER_1A,
        },
        "static_with_caller": {
            "name": "static_with_caller",
            "file": "src/io.c",
            "module": "libdemo_a",
            "lexer_module": "io",
            "is_static": True,
            "header": False,
            "internal_callees": [],
            "internal_callers": ["pub_other"],
            "tier": TIER_1A,
        },
        "static_orphan": {
            "name": "static_orphan",
            "file": "src/io.c",
            "module": "libdemo_a",
            "lexer_module": "io",
            "is_static": True,
            "header": False,
            "internal_callees": [],
            "internal_callers": [],
            "tier": TIER_1A,
        },
    }
    dag = {
        "schema_version": 1,
        "module_kind": "link_unit",
        "callgraph_source": "frama_c",
        "warnings": [],
        "modules": {
            "libdemo_a": {
                "module": "libdemo_a",
                "unit": "build/libdemo.a",
                "kind": "static_lib",
                "unit_visibility": "public_lib",
                "tier": TIER_1A,
                "functions": list(fns),
                "candidate_entry_points": [
                    "pub_entry",
                    "static_reached",
                    "static_with_caller",
                    "static_orphan",
                ],
                "lexer_modules": ["api", "io"],
            }
        },
        "lexer_modules": {
            "api": {"module": "api", "tier": TIER_1A, "functions": ["pub_entry"]},
            "io": {
                "module": "io",
                "tier": TIER_1A,
                "functions": ["pub_other", "static_reached", "static_with_caller", "static_orphan"],
            },
        },
        "unit_of_lexer_module": {"api": "libdemo_a", "io": "libdemo_a"},
        "functions": fns,
    }
    reports = tmp_path / "workspace" / "reports"
    reports.mkdir(parents=True)
    dag_path = reports / "callgraph_dag.json"
    dag_path.write_text(json.dumps(dag), encoding="utf-8")

    hdir = tmp_path / "workspace" / "harnesses"
    hdir.mkdir(parents=True)
    (hdir / "harness_api.c").write_text("void drive(void) { pub_entry(); }\n", encoding="utf-8")
    sidecar = {
        "module": "api",
        "unit": "libdemo_a",
        "harness_file": "workspace/harnesses/harness_api.c",
        "sources": ["src/api.c", "src/io.c"],
        "scope_files": ["src/api.c"],
        "cppflags": "-I.",
        "entry_fn": "pub_entry",
        "entry_style": "dispatch",
        "reach_exempt": {},
        "api_auto_exempt": {
            "static_with_caller": hr.AUTO_EXEMPT_STATIC_REASON,
            "static_orphan": hr.AUTO_EXEMPT_STATIC_REASON,
        },
    }
    (hdir / "harness_api.json").write_text(json.dumps(sidecar), encoding="utf-8")

    reach_schema = load_schema(SCHEMAS_DIR / "harness_reach.schema.json")

    # Flag OFF: all three unharnessed static roots remain gaps on the unit row.
    monkeypatch.setenv(T.HARNESS_SCOPE_V2_ENV, "off")
    rep_off = hr.run_check(dag_path, hdir, None, run_dir=tmp_path)
    by_mod_off = {r["module"]: r for r in rep_off["modules"]}
    assert set(by_mod_off["libdemo_a"]["gaps"]) == {
        "static_reached",
        "static_with_caller",
        "static_orphan",
    }

    # Flag ON (unfiltered and filtered --module libdemo_a): static_reached and static_with_caller are
    # auto-exempted; static_orphan (zero public callers) stays a gap.
    monkeypatch.setenv(T.HARNESS_SCOPE_V2_ENV, "on")
    for mod_filter in (None, ["libdemo_a"]):
        rep_on = hr.run_check(dag_path, hdir, mod_filter, run_dir=tmp_path)
        assert Validator(reach_schema).errors(rep_on) == []
        by_mod_on = {r["module"]: r for r in rep_on["modules"]}
        unit_row = by_mod_on["libdemo_a"]
        assert unit_row["gaps"] == ["static_orphan"]
        assert unit_row["exempt"]["static_reached"] == "static: reached via non-static harness root(s) pub_entry"
        assert unit_row["exempt"]["static_with_caller"] == hr.AUTO_EXEMPT_STATIC_REASON
