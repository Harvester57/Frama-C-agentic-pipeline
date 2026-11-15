"""Regression tests for large/sharded Eva reports, flow deduplication/spilling, and Phase-3 prepare scalability."""

from __future__ import annotations

import hashlib
import json
import subprocess
import threading
from pathlib import Path
from typing import Any

import pytest

import eva_shards as es
import framac_common as fc
import function_facts as ff
import ledger as L
import run_eva_slice as res_mod
import workspace_overlay as WO
import wp_scheduler as S
from conftest import unit, write_json
from test_eva_tuning import COMPLETE_LOG

pytestmark = pytest.mark.unit

TIER1 = "Tier 1A (Untrusted Binary / Network Parser)"


# ---------------------------------------------------------------------------
# Defect A: `flows` bloat, `writes` merge-by-`loc`, location bounding & spilling
# ---------------------------------------------------------------------------


def test_merge_flows_deduplicates_writes_by_loc_and_bounds_strings():
    giant_loc = "Item{.uDataType; .val{" + "; ".join(f".field_{k}[bits 0 to 127]" for k in range(300)) + "}}"
    giant_from = "Ctx{.cursor; .buf{" + "; ".join(f".slot_{k}[0..63]" for k in range(300)) + "}}"
    assert len(giant_loc) > 6000 and len(giant_from) > 5000

    shard_flows = []
    for shard_idx in range(9):
        shard_flows.append(
            {
                "status": "ok",
                "by_function": {
                    "QCBORDecode_GetNext": {
                        "writes": [
                            {
                                "loc": giant_loc,
                                "and_self": shard_idx == 7,
                                "from": [giant_from, f"case_input_{shard_idx}", '"literal_a;b"[0..4]'],
                            },
                            {
                                "loc": "me->lastError",
                                "and_self": False,
                                "from": [f"err_src_{shard_idx % 2}", '"err_msg"[0..2]'],
                            },
                        ],
                        "inputs": [giant_from, '"hello"[0..5]', f"in_{shard_idx}"],
                        "out_external": [giant_loc, "me->lastError"],
                        "result_from": [f"res_{shard_idx % 3}", giant_from],
                        "sure_outputs": ["me->lastError", "only_zero"] if shard_idx == 0 else ["me->lastError"],
                        "no_effects": False,
                        "non_terminating": False,
                    }
                },
                "call_edges": {"QCBORDecode_GetNext": ["UsefulInputBuf_GetBytes"]},
            }
        )

    merged = es.merge_flows(shard_flows)
    assert merged["status"] == "ok"
    fn_info = merged["by_function"]["QCBORDecode_GetNext"]

    # Exactly 2 `writes` entries (one per unique bounded `loc`), never 9 * 2 = 18.
    assert len(fn_info["writes"]) == 2
    by_loc = {w["loc"]: w for w in fn_info["writes"]}
    bounded_giant_loc = fc.bound_flow_location(giant_loc)
    bounded_giant_from = fc.bound_flow_location(giant_from)
    assert len(bounded_giant_loc) == fc.MAX_FLOW_LOCATION_CHARS
    assert bounded_giant_loc.endswith("...")
    assert bounded_giant_loc in by_loc

    w_item = by_loc[bounded_giant_loc]
    assert w_item["and_self"] is True
    assert w_item["from"] == [
        bounded_giant_from,
        "case_input_0",
        "<string literal>",
        *[f"case_input_{i}" for i in range(1, 9)],
    ]

    w_err = by_loc["me->lastError"]
    assert w_err["and_self"] is False
    assert w_err["from"] == ["err_src_0", "<string literal>", "err_src_1"]

    assert fn_info["sure_outputs"] == ["me->lastError"]
    assert "<string literal>" in fn_info["inputs"]
    assert all(len(s) <= fc.MAX_FLOW_LOCATION_CHARS for s in fn_info["inputs"])
    assert all(len(s) <= fc.MAX_FLOW_LOCATION_CHARS for s in fn_info["out_external"])
    assert all(len(s) <= fc.MAX_FLOW_LOCATION_CHARS for s in fn_info["result_from"])


def test_parse_deps_and_inout_logs_bound_composite_bitranges_and_preserve_continuations():
    bit_expansion = "Item{.uDataType; .val{" + "; ".join(f".u_{i}[bits 0 to 127]" for i in range(250)) + "}}"
    deps_log = "\n".join(
        [
            "[from] ====== DEPENDENCIES COMPUTED ======",
            "[from] Function decode:",
            '  r.len FROM p; "lit;1"[0..3] (and SELF)',
            "   .buf[0..4] FROM q",
            f"  {bit_expansion}",
            f"      FROM {bit_expansion}; x",
            f"  {bit_expansion} FROM y (and SELF)",
            '  \\result FROM r.len; "lit;2"[0..1]',
            "[from] ====== END OF DEPENDENCIES ======",
        ]
    )
    parsed_deps = res_mod.parse_deps_log(deps_log)
    dec = parsed_deps["decode"]
    by_loc = {w["loc"]: w for w in dec["writes"]}
    # Continuation indentation (`r.len` -> `   .buf[0..4]` -> `r.buf[0..4]`) stays intact.
    assert by_loc["r.len"] == {"loc": "r.len", "and_self": True, "from": ["p", "<string literal>"]}
    assert by_loc["r.buf[0..4]"] == {"loc": "r.buf[0..4]", "and_self": False, "from": ["q"]}

    bounded = fc.bound_flow_location(bit_expansion)
    assert len(bounded) == fc.MAX_FLOW_LOCATION_CHARS
    # Duplicate bounded `loc` rows within the same function merge cleanly.
    assert len(dec["writes"]) == 3
    assert by_loc[bounded] == {"loc": bounded, "and_self": True, "from": [bounded, "x", "y"]}
    assert dec["result_from"] == ["r.len", "<string literal>"]

    inout_log = "\n".join(
        [
            "[inout] InOut (internal) for function decode:",
            "  Sure outputs:",
            f'      r.len; "str"[0..2]; {bit_expansion}',
            "[inout] Inputs for function decode:",
            f'    p; {bit_expansion}; "str"[0..2]',
        ]
    )
    parsed_inout = res_mod.parse_inout_log(inout_log)
    assert parsed_inout["decode"]["sure_outputs"] == ["r.len", "<string literal>", bounded]
    assert parsed_inout["decode"]["inputs"] == ["p", bounded, "<string literal>"]

    # Downstream `function_facts._eva_record` still consumes bounded flows identically.
    rec = ff._eva_record({**dec, **parsed_inout["decode"]}, "ok")
    assert rec["status"] == "reached"
    write_locs = {w["loc"] for w in rec["writes"]}
    assert "r.len" in write_locs and "r.buf[0..4]" in write_locs
    assert all(len(loc) <= ff.MAX_LOCATION_CHARS + 3 for loc in rec["reads"])


def test_oversized_flows_spill_outside_eva_reports_dir_and_resolve_in_function_facts(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(fc, "FLOWS_INLINE_MAX_BYTES", 256)

    shard_dir = tmp_path / "workspace" / "reports" / "eva-shards" / "m"
    eva_work_dir = tmp_path / "workspace" / "eva" / "m"
    eva_reports_dir = tmp_path / "workspace" / "reports" / "eva"
    out_json = eva_reports_dir / "m.json"

    write_json(
        shard_dir / "plan.json",
        {
            "format": es.SHARD_FORMAT,
            "module": "m",
            "k": 2,
            "cases": [0, 1],
            "shards": [[0], [1]],
            "predicted_makespan_s": 10.0,
            "predicted_total_s": 20.0,
        },
    )
    for idx in (0, 1):
        csv_p = shard_dir / f"s{idx}.csv"
        log_p = shard_dir / f"s{idx}.log"
        csv_p.parent.mkdir(parents=True, exist_ok=True)
        csv_p.write_text(
            "directory\tfile\tline\tfunction\tproperty kind\tstatus\tproperty\n"
            "workspace/work\tsrc/m.c\t4\tf\tmem_access\tValid\t\\valid(p)\n",
            encoding="utf-8",
        )
        log_p.write_text(
            COMPLETE_LOG.replace("7 functions", "1 functions")
            + "[metrics:eva:reached-stmts] \n  Statements analyzed by Eva\n  --------------------------\n  f: 3 stmts out of 3 (100.0%)\n",
            encoding="utf-8",
        )
        raw_shard = {
            "status": "ok",
            "main_fn": "eva_main",
            "sources": ["src/m.c"],
            "input_digest": f"d{idx}",
            "csv_file": csv_p.as_posix(),
            "log_file": log_p.as_posix(),
            "elapsed_s": 5.0,
            "reduced_checks": [],
            "eva_options": {},
            "flows": {
                "status": "ok",
                "reason": None,
                "by_function": {
                    "f": {
                        "writes": [
                            {"loc": f"*out_{j}", "and_self": False, "from": [f"in_{idx}_{j}"]} for j in range(8)
                        ],
                        "inputs": [f"in_{idx}_{j}" for j in range(8)],
                        "out_external": [f"*out_{j}" for j in range(8)],
                        "sure_outputs": ["*out_0"],
                        "result_from": ["in_0_0"],
                        "no_effects": False,
                        "non_terminating": False,
                    }
                },
                "call_edges": {"f": []},
            },
        }
        # Even if an individual shard spilled its own flows, `load_report` resolves it before merging.
        spilled_shard = fc.spill_large_flows(
            raw_shard,
            shard_dir / f"shard{idx}_flows.json",
            report_path=shard_dir / f"shard{idx}.json",
            max_bytes=256,
        )
        write_json(shard_dir / f"shard{idx}.json", spilled_shard)

    # In-memory `es.merge()` still returns inline `flows["by_function"]`.
    plan = fc.load_json_strict(shard_dir / "plan.json")
    loaded_shards = [es.load_report(es.shard_report_path(shard_dir, i)) for i in range(2)]
    in_mem = es.merge("m", plan, loaded_shards, "eva_main", eva_work_dir / "alarms.csv", None)
    assert "by_function" in in_mem["flows"]

    # CLI `eva_shards.py merge` spills oversized `flows` to `<eva_work_dir>/flows.json`, NOT `reports/eva/*.json`.
    rc = es.main(
        [
            "merge",
            "--module",
            "m",
            "--shard-dir",
            str(shard_dir),
            "--entry-fn",
            "eva_main",
            "--csv-out",
            str(eva_work_dir / "alarms.csv"),
            "--out-json",
            str(out_json),
        ]
    )
    assert rc == 0
    assert [p.name for p in eva_reports_dir.glob("*.json")] == ["m.json"]
    on_disk = json.loads(out_json.read_text(encoding="utf-8"))
    assert "by_function" not in on_disk["flows"]
    assert on_disk["flows"]["flows_file"] == "workspace/eva/m/flows.json"
    assert (eva_work_dir / "flows.json").is_file()

    # Guardrail: even if a caller passes a `flows_dest` inside `reports/eva`, `spill_large_flows` redirects out of it.
    redirected = fc.spill_large_flows(
        in_mem,
        eva_reports_dir / "bad_flows.json",
        report_path=out_json,
        max_bytes=256,
    )
    assert [p.name for p in eva_reports_dir.glob("*.json")] == ["m.json"]
    assert redirected["flows"]["flows_file"] == "workspace/reports/eva-flows/m.json"

    # `function_facts.generate` transparently resolves `flows_file` from `m.json`.
    src_c = tmp_path / "workspace" / "work" / "src" / "m.c"
    src_c.parent.mkdir(parents=True, exist_ok=True)
    src_c.write_text("int f(int *out_0, int in_0_0) { *out_0 = in_0_0; return *out_0; }\n", encoding="utf-8")

    captured_flows: list[dict | None] = []

    def fake_build_module_facts(module, sources, cppflags, flows, machdep="gcc_x86_64", runner=None):
        captured_flows.append(flows)
        fn_flow = (flows.get("by_function") or {}).get("f") if isinstance(flows, dict) else None
        status = str(flows.get("status") or "") if isinstance(flows, dict) else ""
        return {
            "schema": ff.FACTS_SCHEMA,
            "module": module,
            "status": "ok",
            "ast": {"status": "ok"},
            "eva": {"status": status or "missing"},
            "functions": {"src/m.c#f": {"eva": ff._eva_record(fn_flow, status)}},
        }

    monkeypatch.setattr(ff, "build_module_facts", fake_build_module_facts)
    monkeypatch.setenv("FRAMAC_CACHE_DIR", "off")
    facts_out = tmp_path / "workspace" / "reports" / "facts" / "m.json"
    res = ff.generate("m", [str(src_c)], "-I.", out_json, facts_out)
    assert res["status"] == "ok"
    assert len(captured_flows) == 1 and isinstance(captured_flows[0], dict)
    assert "f" in captured_flows[0]["by_function"]
    facts_doc = json.loads(facts_out.read_text(encoding="utf-8"))
    assert "*out_0" in {w["loc"] for w in facts_doc["functions"]["src/m.c#f"]["eva"]["writes"]}


def test_run_eva_slice_cli_spills_oversized_flows_while_keeping_in_memory_dict_intact(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(fc, "FLOWS_INLINE_MAX_BYTES", 256)
    monkeypatch.setattr(res_mod, "phase0_gate_reasons", lambda module: [])

    fake_res: dict[str, Any] = {
        "status": "ok",
        "reason": None,
        "error_summary": [],
        "undeclared_functions": [],
        "valid_count": 3,
        "unknown_count": 0,
        "invalid_count": 0,
        "dead_count": 0,
        "assumed_count": 0,
        "discharged_percentage": 100.0,
        "surviving_unknown_functions": [],
        "flows": {
            "status": "ok",
            "reason": None,
            "by_function": {
                "f": {
                    "writes": [{"loc": f"arr[{k}]", "and_self": False, "from": [f"src_{k}"]} for k in range(12)],
                    "inputs": [f"src_{k}" for k in range(12)],
                }
            },
            "call_edges": {},
        },
    }
    monkeypatch.setattr(res_mod, "run_eva_on_slice", lambda **kwargs: fake_res)

    eva_work = tmp_path / "workspace" / "eva" / "m"
    eva_out = tmp_path / "workspace" / "reports" / "eva" / "m.json"
    rc = res_mod.main(
        [
            "--module",
            "m",
            "--sources",
            "src/m.c",
            "--main",
            "eva_main",
            "--out-dir",
            str(eva_work),
            "--out-json",
            str(eva_out),
        ]
    )
    assert rc == 0
    # In-memory `fake_res` returned by `run_eva_on_slice()` retains inline `by_function`.
    assert isinstance(fake_res["flows"], dict) and "by_function" in fake_res["flows"]
    # Disk report `workspace/reports/eva/m.json` holds the lightweight `flows_file` pointer.
    written = json.loads(eva_out.read_text(encoding="utf-8"))
    assert "by_function" not in written["flows"]
    assert written["flows"]["flows_file"] == "workspace/eva/m/flows.json"
    assert (eva_work / "flows.json").is_file()
    assert [p.name for p in eva_out.parent.glob("*.json")] == ["m.json"]


# ---------------------------------------------------------------------------
# Defect B: `EVA_REPORT_MAX_BYTES` honored across all Eva report readers
# ---------------------------------------------------------------------------


def test_eva_report_max_bytes_constant_and_load_json_optional_forwarding(tmp_path):
    assert fc.EVA_REPORT_MAX_BYTES == 768 * 1024 * 1024
    p = tmp_path / "sample.json"
    p.write_text(json.dumps({"pad": "x" * 2048}), encoding="utf-8")

    with pytest.raises(fc.ArtifactError, match="artifact exceeds 512 bytes"):
        fc.load_json_optional(p, {}, max_bytes=512)
    loaded = fc.load_json_optional(p, {}, max_bytes=fc.EVA_REPORT_MAX_BYTES)
    assert loaded["pad"] == "x" * 2048
    assert fc.load_json_optional(tmp_path / "missing.json", {"ok": True}, max_bytes=512) == {"ok": True}


def _install_tiny_default_json_cap(monkeypatch, tiny_default: int = 1500) -> list[tuple[str, int]]:
    """Fail any Eva report read > `tiny_default` bytes UNLESS the caller explicitly passed `EVA_REPORT_MAX_BYTES`."""
    real_strict = fc.load_json_strict
    seen_eva_reads: list[tuple[str, int]] = []

    def checked_strict(path: Path, max_bytes: int = fc.DEFAULT_JSON_MAX_BYTES):
        p = Path(path)
        is_eva_report = p.name == "m.json" and "eva" in p.as_posix()
        effective = (
            (tiny_default if max_bytes == fc.DEFAULT_JSON_MAX_BYTES else max_bytes) if is_eva_report else max_bytes
        )
        if is_eva_report:
            seen_eva_reads.append((p.as_posix(), effective))
        return real_strict(p, max_bytes=effective)

    def checked_optional(path: Path, default: Any, max_bytes: int = fc.DEFAULT_JSON_MAX_BYTES):
        p = Path(path)
        if not p.exists():
            return default
        return checked_strict(p, max_bytes=max_bytes)

    for mod in (fc, ff, L, WO, S):
        if hasattr(mod, "load_json_strict"):
            monkeypatch.setattr(mod, "load_json_strict", checked_strict)
        if hasattr(mod, "load_json_optional"):
            monkeypatch.setattr(mod, "load_json_optional", checked_optional)
    return seen_eva_reads


def test_readers_accept_eva_report_above_default_cap_and_handle_corrupt_eva_gracefully(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FRAMAC_CACHE_DIR", "off")

    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "m.c").write_text("int f(int *p) { return *p; }\n", encoding="utf-8")
    WO.init_overlay(target, tmp_path / "workspace")
    write_json(tmp_path / "run-metadata.json", {"profile": "standard"})

    dag = {
        "modules": {"m": {"tier": TIER1, "files": ["src/m.c"]}},
        "functions": {"f": {"name": "f", "file": "src/m.c", "module": "m", "wave": 0, "callees": []}},
    }
    write_json(tmp_path / "workspace" / "reports" / "callgraph_dag.json", dag)
    write_json(
        tmp_path / "workspace" / "harnesses" / "harness_m.json",
        {"module": "m", "sources": ["workspace/work/src/m.c"], "cppflags": "-I."},
    )
    write_json(
        tmp_path / "coverage-ledger.json",
        [unit("src/m.c", "f", "rte", module="m", tier=TIER1)],
    )
    write_json(tmp_path / "candidates.json", [])

    # Build an Eva report well over the 600-byte synthetic default cap (~3 KB).
    eva_path = tmp_path / "workspace" / "reports" / "eva" / "m.json"
    write_json(
        eva_path,
        {
            "status": "ok",
            "module": "m",
            "sources": ["workspace/work/src/m.c"],
            "valid_count": 1,
            "unknown_count": 1,
            "invalid_count": 1,
            "dead_count": 1,
            "assumed_count": 0,
            "discharged_percentage": 50.0,
            "surviving_unknown_functions": ["f"],
            "unknown_obligations_by_function": {
                "f": [
                    {
                        "directory": "workspace/work",
                        "file": "src/m.c",
                        "line": 1,
                        "function": "f",
                        "kind": "mem_access",
                        "status": "unknown",
                        "property": "\\valid_read(p)",
                    }
                ]
            },
            "invalid_alarms": [
                {
                    "directory": "workspace/work",
                    "file": "src/m.c",
                    "line": 9,
                    "function": "f",
                    "kind": "mem_access",
                    "status": "invalid",
                    "property": "\\valid_read(p)",
                }
            ],
            "dead_alarms": [
                {
                    "directory": "workspace/work",
                    "file": "src/m.c",
                    "line": 42,
                    "function": "f",
                    "kind": "mem_access",
                    "status": "dead",
                    "property": "\\valid_read(p)",
                }
            ],
            "flows": {"status": "ok", "by_function": {"f": {"inputs": ["*p"], "writes": []}}, "call_edges": {}},
            "padding": "Z" * 2400,
        },
    )
    assert eva_path.stat().st_size > 2400

    seen_reads = _install_tiny_default_json_cap(monkeypatch, tiny_default=600)

    # 1. `function_facts.generate`
    monkeypatch.setattr(
        ff,
        "build_module_facts",
        lambda module, sources, cppflags, flows, machdep="gcc_x86_64", runner=None: {
            "schema": ff.FACTS_SCHEMA,
            "module": module,
            "status": "ok",
            "ast": {"status": "ok"},
            "eva": {"status": "ok"},
            "functions": {},
        },
    )
    ff_res = ff.generate("m", ["workspace/work/src/m.c"], "-I.", eva_path, tmp_path / "facts.json")
    assert ff_res["status"] == "ok"

    # 2. `ledger.cmd_ingest_eva`
    ing = L.cmd_ingest_eva([eva_path])
    assert ing["reports"] == 1 and ing["candidates"] == 1

    # 3. `ledger._dead_code_on_disk`
    dead_ev = L._dead_code_on_disk(tmp_path, "m", {"file": "src/m.c", "function": "f", "line": 42})
    assert dead_ev is not None and dead_ev["source"] == "eva_dead"

    # 4. `wp_scheduler.Ctx._load_eva`
    ctx = S.Ctx()
    assert ctx.eva_unknown_count("src/m.c", "f") == 1
    assert len(ctx.eva_unknown_obligations("m", "src/m.c", "f")) == 1

    # 5. `wp_scheduler._eva_has_invalid`
    assert S._eva_has_invalid("src/m.c", "f") is True

    # 6. `workspace_overlay.prepare_agent`
    prep = WO.prepare_agent(
        run_dir=tmp_path, agent_id="prove-f", role="prover", module="m", function="f", c_file="src/m.c"
    )
    brief_text = (tmp_path / prep["brief_file"]).read_text(encoding="utf-8")
    assert "valid_read(p)" in brief_text

    assert len(seen_reads) >= 6
    assert all(limit == fc.EVA_REPORT_MAX_BYTES for _, limit in seen_reads)

    # Also verify `_eva_has_invalid` and `prepare_agent` survive a malformed/truncated Eva report without crashing.
    (tmp_path / "workspace" / "reports" / "eva" / "corrupt.json").write_text("{not-valid-json", encoding="utf-8")
    assert S._eva_has_invalid("src/m.c", "f") is True
    WO.prepare_agent(run_dir=tmp_path, agent_id="prove-f-2", role="prover", module="m", function="f", c_file="src/m.c")


# ---------------------------------------------------------------------------
# Defect C: Concurrent `step --prepare` memory spike & unprepared-task recovery
# ---------------------------------------------------------------------------


def test_prepare_agent_skips_eva_disk_reads_when_obligations_passed_or_non_function_role(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "m.c").write_text("int f(int x) { return x; }\n", encoding="utf-8")
    (target / "src" / "m.h").write_text("int f(int x);\n", encoding="utf-8")
    WO.init_overlay(target, tmp_path / "workspace")
    write_json(tmp_path / "run-metadata.json", {"profile": "standard"})
    write_json(
        tmp_path / "workspace" / "reports" / "callgraph_dag.json",
        {
            "modules": {"m": {"tier": TIER1, "files": ["src/m.c"]}},
            "functions": {"f": {"name": "f", "file": "src/m.c", "module": "m", "wave": 0, "callees": []}},
        },
    )
    write_json(
        tmp_path / "workspace" / "harnesses" / "harness_m.json",
        {"module": "m", "header": "src/m.h", "sources": ["workspace/work/src/m.c"], "cppflags": "-I."},
    )
    eva_file = tmp_path / "workspace" / "reports" / "eva" / "m.json"
    write_json(eva_file, {"status": "ok", "module": "m", "unknown_obligations_by_function": {"f": [{"line": 1}]}})

    eva_reads: list[str] = []
    real_opt = WO.load_json_optional

    def spy_load_optional(path: Path, default: Any, max_bytes: int = fc.DEFAULT_JSON_MAX_BYTES):
        p = Path(path)
        if "reports/eva/" in p.as_posix():
            eva_reads.append(p.name)
        return real_opt(p, default, max_bytes=max_bytes)

    monkeypatch.setattr(WO, "load_json_optional", spy_load_optional)

    # 1. `architect` (no `function`) never reads `reports/eva/*.json`.
    WO.prepare_agent(run_dir=tmp_path, agent_id="arch-m", role="architect", module="m", header_file="src/m.h")
    assert eva_reads == []

    # 2. `verifier` without `function` never reads `reports/eva/*.json`.
    WO.prepare_agent(run_dir=tmp_path, agent_id="verify-cand", role="verifier", module="m", candidate_fp="fp-1")
    assert eva_reads == []

    # 3. `prover` with pre-extracted `eva_unknown_obligations` never reads `reports/eva/*.json`.
    pre_obs = [
        {"file": "src/m.c", "line": 7, "function": "f", "kind": "signed_overflow", "property": "x + 1 <= INT_MAX"}
    ]
    res = WO.prepare_agent(
        run_dir=tmp_path,
        agent_id="prove-f",
        role="prover",
        module="m",
        function="f",
        c_file="src/m.c",
        eva_unknown_obligations=pre_obs,
    )
    assert eva_reads == []
    assert "x + 1 <= INT_MAX" in (tmp_path / res["brief_file"]).read_text(encoding="utf-8")


def test_wp_scheduler_cmd_next_prepare_loads_eva_once_across_worker_threads(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    fns = [f"fn_{i}" for i in range(6)]
    (target / "src" / "m.c").write_text(
        "\n".join(f"int {fn}(int x) {{ return x + {i}; }}" for i, fn in enumerate(fns)) + "\n",
        encoding="utf-8",
    )
    WO.init_overlay(target, tmp_path / "workspace")
    write_json(tmp_path / "run-metadata.json", {"profile": "standard"})

    dag_fns = {fn: {"name": fn, "file": "src/m.c", "module": "m", "wave": 0, "callees": []} for fn in fns}
    write_json(
        tmp_path / "workspace" / "reports" / "callgraph_dag.json",
        {"modules": {"m": {"tier": TIER1, "files": ["src/m.c"], "run_eacsl_fuzz": False}}, "functions": dag_fns},
    )
    write_json(
        tmp_path / "workspace" / "harnesses" / "harness_m.json",
        {"module": "m", "sources": ["workspace/work/src/m.c"], "cppflags": "-I."},
    )
    write_json(
        tmp_path / "coverage-ledger.json",
        [unit("src/m.c", fn, "rte", module="m", tier=TIER1) for fn in fns],
    )
    write_json(tmp_path / "candidates.json", [])
    write_json(
        tmp_path / "workspace" / "reports" / "eva" / "m.json",
        {
            "status": "ok",
            "module": "m",
            "unknown_obligations_by_function": {
                fn: [
                    {
                        "file": "src/m.c",
                        "line": i + 1,
                        "function": fn,
                        "kind": "signed_overflow",
                        "property": f"goal_{fn}",
                    }
                ]
                for i, fn in enumerate(fns)
            },
        },
    )

    monkeypatch.setattr(S.DEPS, "recommend", lambda max_agents=None: {"max_agents": 6})
    S.cmd_init()

    lock = threading.Lock()
    eva_load_calls: list[str] = []
    real_strict = S.load_json_strict
    real_wo_opt = WO.load_json_optional

    def spy_sched_strict(path: Path, max_bytes: int = fc.DEFAULT_JSON_MAX_BYTES):
        p = Path(path)
        if p.name == "m.json" and "reports/eva" in p.as_posix():
            with lock:
                eva_load_calls.append("sched")
        return real_strict(p, max_bytes=max_bytes)

    def spy_wo_optional(path: Path, default: Any, max_bytes: int = fc.DEFAULT_JSON_MAX_BYTES):
        p = Path(path)
        if p.name == "m.json" and "reports/eva" in p.as_posix():
            with lock:
                eva_load_calls.append("worker")
        return real_wo_opt(p, default, max_bytes=max_bytes)

    monkeypatch.setattr(S, "load_json_strict", spy_sched_strict)
    monkeypatch.setattr(WO, "load_json_optional", spy_wo_optional)

    out = S.cmd_next("6", prepare=True)
    assert len(out["tasks"]) == 6
    # `Ctx._load_eva` read `m.json` once; the 6 concurrent `prepare_agent` worker threads read it 0 times!
    assert eva_load_calls == ["sched"]
    for fn in fns:
        brief = (tmp_path / "agents" / f"prove-{fn}" / "brief.md").read_text(encoding="utf-8")
        assert f"goal_{fn}" in brief


def test_requeue_recovers_killed_prepare_without_burning_dispatches(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "m.c").write_text("int f(int x) { return x; }\n", encoding="utf-8")
    WO.init_overlay(target, tmp_path / "workspace")
    write_json(tmp_path / "run-metadata.json", {"profile": "standard"})
    write_json(
        tmp_path / "workspace" / "reports" / "callgraph_dag.json",
        {
            "modules": {"m": {"tier": TIER1, "files": ["src/m.c"], "run_eacsl_fuzz": False, "run_eva": False}},
            "functions": {"f": {"name": "f", "file": "src/m.c", "module": "m", "wave": 0, "callees": []}},
        },
    )
    write_json(tmp_path / "coverage-ledger.json", [unit("src/m.c", "f", "rte", module="m", tier=TIER1)])
    write_json(tmp_path / "candidates.json", [])
    monkeypatch.setattr(S.DEPS, "recommend", lambda max_agents=None: {"max_agents": 4})

    S.cmd_init()
    # Simulate a `step --prepare` that saved `running` (`prove-f`, `dispatches=1`) and created `scratch/`
    # before OOM-killer SIGKILLed the process prior to writing `agents/prove-f/brief.md`.
    nxt_no_prep = S.cmd_next("1", prepare=False)
    assert nxt_no_prep["tasks"][0]["agent_id"] == "prove-f"
    assert nxt_no_prep["tasks"][0]["attempt"] == 1
    (tmp_path / "agents" / "prove-f" / "scratch").mkdir(parents=True, exist_ok=True)
    assert not (tmp_path / "agents" / "prove-f" / "brief.md").exists()

    rq = S.cmd_requeue(stale_minutes=0)
    assert len(rq["requeued"]) == 1
    assert rq["requeued"][0]["task"] == "prove:src/m.c#f"
    assert rq["requeued"][0]["agent_id"] == "prove-f"
    assert rq["requeued"][0]["unprepared"] is True

    sched = json.loads((tmp_path / "state" / "wp_schedule.json").read_text(encoding="utf-8"))
    t_after_rq = sched["tasks"]["prove:src/m.c#f"]
    assert t_after_rq["state"] == "pending"
    assert t_after_rq["dispatches"] == 0
    assert "requeued_from" not in t_after_rq

    # Next dispatch gets a fresh unused directory (`prove-f-2`) while `attempt`/`dispatches` is still 1!
    nxt_recovered = S.cmd_next("1", prepare=True)
    assert len(nxt_recovered["tasks"]) == 1
    assert nxt_recovered["tasks"][0]["agent_id"] == "prove-f-2"
    assert nxt_recovered["tasks"][0]["attempt"] == 1
    assert (tmp_path / "agents" / "prove-f-2" / "brief.md").is_file()


# ---------------------------------------------------------------------------
# Follow-Up 1: Hold `repair:<module>` until all `verify:*` of `<module>` finish
# ---------------------------------------------------------------------------


def test_repair_waits_for_all_open_verifiers_of_module_and_accumulates_reasons(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "target"
    (target / "src" / "mod_a").mkdir(parents=True)
    (target / "src" / "mod_b").mkdir(parents=True)
    for fn in ("f1", "f2", "f3", "h"):
        (target / "src" / "mod_a" / f"{fn}.c").write_text(f"int {fn}(int *p) {{ return *p; }}\n", encoding="utf-8")
    (target / "src" / "mod_b" / "g.c").write_text("int g(int *p) { return *p; }\n", encoding="utf-8")

    WO.init_overlay(target, tmp_path / "workspace")
    write_json(tmp_path / "run-metadata.json", {"profile": "standard"})
    write_json(
        tmp_path / "workspace" / "reports" / "callgraph_dag.json",
        {
            "schema_version": 1,
            "module_kind": "link_unit",
            "callgraph_source": "frama_c",
            "warnings": [],
            "modules": {
                "mod_a": {
                    "tier": TIER1,
                    "files": [f"src/mod_a/{fn}.c" for fn in ("f1", "f2", "f3", "h")],
                    "functions": ["f1", "f2", "f3", "h"],
                },
                "mod_b": {
                    "tier": TIER1,
                    "files": ["src/mod_b/g.c"],
                    "functions": ["g"],
                },
            },
            "functions": {
                **{
                    fn: {
                        "name": fn,
                        "file": f"src/mod_a/{fn}.c",
                        "module": "mod_a",
                        "wave": 0,
                        "callees": [],
                    }
                    for fn in ("f1", "f2", "f3", "h")
                },
                "g": {"name": "g", "file": "src/mod_b/g.c", "module": "mod_b", "wave": 0, "callees": []},
            },
        },
    )
    for mod in ("mod_a", "mod_b"):
        write_json(
            tmp_path / "workspace" / "harnesses" / f"harness_{mod}.json",
            {
                "module": mod,
                "unit": mod,
                "sources": [],
                "cppflags": "-I.",
                "repair_attempts": 1,
                "max_repair_attempts": 2,
            },
        )
    write_json(
        tmp_path / "coverage-ledger.json",
        sorted(
            [
                *[unit(f"src/mod_a/{fn}.c", fn, "rte", module="mod_a", tier=TIER1) for fn in ("f1", "f2", "f3", "h")],
                unit("src/mod_b/g.c", "g", "rte", module="mod_b", tier=TIER1),
            ],
            key=lambda u: u["coverage_id"],
        ),
    )
    write_json(tmp_path / "candidates.json", [])

    eva_a = tmp_path / "workspace" / "reports" / "eva" / "mod_a.json"
    write_json(
        eva_a,
        {
            "status": "ok",
            "module": "mod_a",
            "unknown_obligations_by_function": {},
            "invalid_alarms": [
                {"file": f"src/mod_a/{fn}.c", "function": fn, "line": 1, "kind": "mem_access", "annotation": "p != 0"}
                for fn in ("f1", "f2", "f3")
            ],
            "dead_alarms": [],
            "assumed_properties": [],
            "functions_with_properties": ["f1", "f2", "f3", "h"],
        },
    )
    eva_b = tmp_path / "workspace" / "reports" / "eva" / "mod_b.json"
    write_json(
        eva_b,
        {
            "status": "ok",
            "module": "mod_b",
            "unknown_obligations_by_function": {},
            "invalid_alarms": [
                {"file": "src/mod_b/g.c", "function": "g", "line": 1, "kind": "mem_access", "annotation": "p != 0"}
            ],
            "dead_alarms": [],
            "assumed_properties": [],
            "functions_with_properties": ["g"],
        },
    )
    L.cmd_ingest_eva([eva_a, eva_b])

    # Give `f3`'s candidate a parent-replayed crash artifact so `v3` can complete as `confirmed`.
    crash_bytes = b"crash-f3"
    crash_file = tmp_path / "workspace" / "crashes" / "mod_a" / "crash-f3"
    crash_file.parent.mkdir(parents=True, exist_ok=True)
    crash_file.write_bytes(crash_bytes)
    cands = json.loads((tmp_path / "candidates.json").read_text(encoding="utf-8"))
    by_fn = {c["location"]["function"]: c for c in cands}
    fp1, fp2, fp3, fp_b = (
        by_fn["f1"]["fingerprint"],
        by_fn["f2"]["fingerprint"],
        by_fn["f3"]["fingerprint"],
        by_fn["g"]["fingerprint"],
    )
    by_fn["f3"]["reproducers"] = ["workspace/crashes/mod_a/crash-f3"]
    write_json(tmp_path / "candidates.json", cands)
    write_json(
        tmp_path / "workspace" / "reports" / "replay" / f"{S._fp_slug(fp3)}.json",
        {
            "status": "ok",
            "candidate_fingerprint": fp3,
            "artifacts": [{"sha256": hashlib.sha256(crash_bytes).hexdigest(), "reproducible": True}],
        },
    )

    monkeypatch.setattr(S.DEPS, "recommend", lambda max_agents=None: {"max_agents": 4})
    monkeypatch.setattr(
        S.DEPS,
        "prepare_agent",
        lambda run_dir, aid, role, **kw: {
            "agent_id": aid,
            "brief_file": f"agents/{aid}/brief.md",
            "scratch": f"agents/{aid}/scratch",
        },
    )

    S.cmd_init()
    # Batch 1: dispatch 2 of the 4 verifiers (`f1` and `f2` on `mod_a`, sorted by task id).
    batch1 = S.cmd_next("2", prepare=False)
    assert batch1["parent_tasks"] == []
    dispatched1 = {t["candidate_fingerprint"]: t["agent_id"] for t in batch1["tasks"]}
    assert set(dispatched1) == {fp1, fp2}

    # `v1` rejects as `harness_induced` while `v2` is `running` and `v3` is still `pending`.
    aid1 = dispatched1[fp1]
    L.cmd_scaffold_verifier(fp1, "rejected", aid1, out_path=tmp_path / f"agents/{aid1}/scratch/result.json")
    comp1 = S.cmd_complete(aid1)
    assert comp1["decision"] == "rejected"
    assert "repair:mod_a" in comp1["new_tasks"]

    sched1 = json.loads((tmp_path / "state" / "wp_schedule.json").read_text(encoding="utf-8"))
    assert sched1["tasks"]["repair:mod_a"]["state"] == "pending"
    assert sched1["tasks"]["repair:mod_a"]["reasons"] == [f"harness_induced: {fp1}"]
    assert sorted(sched1["tasks"]["repair:mod_a"]["deps"]) == sorted(
        [f"verify:{fp1}", f"verify:{fp2}", f"verify:{fp3}"]
    )
    assert "repair:mod_a" not in {r["task"] for r in S.cmd_status()["ready"]}

    # `cmd_next` MUST hold `repair:mod_a` and dispatch remaining verifiers (`v3` and `v_b`) instead!
    batch2 = S.cmd_next("2", prepare=False)
    assert batch2["parent_tasks"] == []
    dispatched2 = {t["candidate_fingerprint"]: t["agent_id"] for t in batch2["tasks"]}
    assert set(dispatched2) == {fp3, fp_b}

    # `v2` also rejects as `harness_induced` while `v3` is still `running`: reason is appended, still held!
    aid2 = dispatched1[fp2]
    L.cmd_scaffold_verifier(fp2, "rejected", aid2, out_path=tmp_path / f"agents/{aid2}/scratch/result.json")
    comp2 = S.cmd_complete(aid2)
    assert comp2["decision"] == "rejected"

    sched2 = json.loads((tmp_path / "state" / "wp_schedule.json").read_text(encoding="utf-8"))
    assert sched2["tasks"]["repair:mod_a"]["state"] == "pending"
    assert sched2["tasks"]["repair:mod_a"]["reasons"] == [
        f"harness_induced: {fp1}",
        f"harness_induced: {fp2}",
    ]
    assert S.cmd_next("2", prepare=False)["parent_tasks"] == []

    # `v3` finishes `confirmed` while unrelated `mod_b` verifier `v_b` is STILL running:
    # all `verify:*` tasks of `mod_a` are now terminal, so `repair:mod_a` dispatches ONCE with BOTH reasons!
    aid3 = dispatched2[fp3]
    L.cmd_scaffold_verifier(fp3, "confirmed", aid3, out_path=tmp_path / f"agents/{aid3}/scratch/result.json")
    comp3 = S.cmd_complete(aid3)
    assert comp3["decision"] == "confirmed"

    nxt_repair = S.cmd_next("2", prepare=False)
    assert [p["task"] for p in nxt_repair["parent_tasks"]] == ["repair:mod_a"]
    assert nxt_repair["parent_tasks"][0]["reasons"] == [
        f"harness_induced: {fp1}",
        f"harness_induced: {fp2}",
    ]


# ---------------------------------------------------------------------------
# Follow-Up 2: Preserve 5-domain base timeout `flamegraph.txt` across fallbacks
# ---------------------------------------------------------------------------


def test_base_timeout_flamegraph_preserved_across_timed_out_and_completed_fallbacks(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(res_mod, "_input_digest", lambda sources, flags: "d")
    src = tmp_path / "a.c"
    src.write_text("int eva_main(void) { return 0; }\n", encoding="utf-8")

    # Case 1 (QCBOR run-6): 5-domain base times out at 7200 s after writing `flamegraph.txt`,
    # then both 900 s cvalue fallbacks ALSO time out. `flamegraph.txt` must retain the 5-domain profile!
    out_all_to = tmp_path / "eva_all_timeout"
    seen_cmds_all_to: list[list[str]] = []

    def fake_run_all_timeout(cmd, **kwargs):
        if cmd and cmd[0] == "frama-c":
            seen_cmds_all_to.append(list(cmd))
        out_all_to.mkdir(parents=True, exist_ok=True)
        if "-eva-flamegraph" in cmd:
            fg_dest = Path(cmd[cmd.index("-eva-flamegraph") + 1])
            domains = cmd[cmd.index("-eva-domains") + 1]
            if "equality" in domains:
                fg_dest.write_text("eva_main;five_domain_heavy 500\neva_main;helper 100\n", encoding="utf-8")
            else:
                fg_dest.write_text("eva_main;degraded_cvalue_only 10\n", encoding="utf-8")
        raise subprocess.TimeoutExpired(cmd, float(kwargs.get("timeout") or 0), output="", stderr="")

    monkeypatch.setattr(res_mod.subprocess, "run", fake_run_all_timeout)
    res_to = res_mod.run_eva_on_slice([str(src)], "eva_main", out_all_to, timeout=7200, use_cache=False)
    assert res_to["status"] == "analysis_timeout"
    assert [t["tier"] for t in res_to["timeout_fallback_tried"]] == ["cvalue_fast", "cvalue_imprecise_alloc"]
    assert len(seen_cmds_all_to) == 3
    # Base run requested `-eva-flamegraph`; fallback tiers omitted `-eva-flamegraph` once base profile existed.
    assert "-eva-flamegraph" in seen_cmds_all_to[0]
    assert "-eva-flamegraph" not in seen_cmds_all_to[1]
    assert "-eva-flamegraph" not in seen_cmds_all_to[2]
    fg_text = (out_all_to / "flamegraph.txt").read_text(encoding="utf-8")
    assert "five_domain_heavy" in fg_text and "degraded_cvalue_only" not in fg_text
    assert not (out_all_to / "flamegraph.timed_out.txt").exists()
    assert res_to["flamegraph_file"] == str(out_all_to / "flamegraph.txt")
    assert res_to["cost_profile"]["self"][0]["function"] == "five_domain_heavy"

    # Case 2: 5-domain base times out with non-empty `flamegraph.txt`, and `cvalue_fast` completes (`status == "ok"`).
    # Because `pipeline_make._plan_shards` still shards `timeout_fallback` modules using `report["flamegraph_file"]`,
    # `out_dir / "flamegraph.txt"` must still hold the 5-domain base profile even if a fallback wrote over it!
    out_fb_ok = tmp_path / "eva_fb_ok"
    calls_fb_ok = 0

    def fake_execute_fb_ok(cmd, sources, main_fn, out_dir, reduced_checks, timeout, path_root=None):
        nonlocal calls_fb_ok
        calls_fb_ok += 1
        fg = Path(out_dir) / "flamegraph.txt"
        if calls_fb_ok == 1:
            fg.write_text("eva_main;five_domain_heavy 400\n", encoding="utf-8")
            return {
                "status": "analysis_timeout",
                "error_summary": ["exceeded limit"],
                "sources": sources,
                "reduced_checks": reduced_checks,
                "flamegraph_file": str(fg),
                "cost_profile": {
                    "run": "timed_out",
                    "self": [{"function": "five_domain_heavy", "share": 1.0}],
                    "inclusive": [],
                },
            }
        # Even if a fallback writes `flamegraph.txt`, `_restore_timed_out_flamegraph` restores the 5-domain one.
        fg.write_text("eva_main;cvalue_fallback_fast 5\n", encoding="utf-8")
        return {"status": "ok", "sources": sources, "reduced_checks": reduced_checks, "flamegraph_file": str(fg)}

    monkeypatch.setattr(res_mod, "_execute_eva", fake_execute_fb_ok)
    res_ok = res_mod.run_eva_on_slice([str(src)], "eva_main", out_fb_ok, timeout=7200, use_cache=False)
    assert res_ok["status"] == "ok" and res_ok["timeout_fallback"] == "cvalue_fast"
    assert (out_fb_ok / "flamegraph.txt").read_text(encoding="utf-8") == "eva_main;five_domain_heavy 400\n"
    assert not (out_fb_ok / "flamegraph.timed_out.txt").exists()
    assert res_ok["flamegraph_file"] == str(out_fb_ok / "flamegraph.txt")
