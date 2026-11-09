"""
Eva sharding (eva_shards.py, docs/eva-sharding.md): a module's dispatch cases split over k Eva runs, a
plan that never moves once recorded, and a merge that calls an obligation Valid only when no shard
reaching it leaves it Unknown or Invalid.
"""

from __future__ import annotations

import copy
import json
import shutil
import subprocess
from pathlib import Path

import pytest

import eva_shards as es
import pipeline_make as pm
from conftest import write_json
from framac_common import read_report_csv
from generate_harness import _build_dispatch_invocation
from test_eva_tuning import ACSL, COMPLETE_LOG
from test_pipeline_make import SIDECARS, _make_run

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# The harness: one guard per case
# ---------------------------------------------------------------------------


def test_each_dispatch_case_is_guarded_for_the_shards():
    stmt = _build_dispatch_invocation(["f(fuzz_buf, fuzz_len);", "g(1);", "h();"])
    for k in range(3):
        assert f"#if !defined(FRAMAC_EVA_SHARD) || defined(FRAMAC_EVA_SHARD_CASE_{k})" in stmt
    assert stmt.count("#endif") == 3 + 1  # the cases, and the fuzz skip mask
    assert es.harness_shardable(stmt)
    assert not es.harness_shardable("    case 0U: { f(); } break;\n")
    assert es.shard_cppflags([3, 1]) == ["-DFRAMAC_EVA_SHARD", "-DFRAMAC_EVA_SHARD_CASE_1", "-DFRAMAC_EVA_SHARD_CASE_3"]


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc not available")
def test_a_shard_keeps_only_its_cases_and_every_line_number(tmp_path):
    body = _build_dispatch_invocation(["f(fuzz_buf, fuzz_len);", "g(1);", "h();"])
    src = tmp_path / "h.c"
    src.write_text(
        "typedef unsigned char uint8_t;\nvoid f(const uint8_t*, unsigned long); void g(int); void h(void);\n"
        "void eva_main(const uint8_t *fuzz_buf, unsigned long fuzz_len) {\n    " + body + "\n}\n",
        encoding="utf-8",
    )

    def cpp(*defines: str) -> str:
        proc = subprocess.run(["gcc", "-E", "-P", *defines, str(src)], capture_output=True, text=True, check=True)
        return proc.stdout

    def line_of(call: str, *defines: str) -> int:
        proc = subprocess.run(["gcc", "-E", *defines, str(src)], capture_output=True, text=True, check=True)
        line = None
        for text in proc.stdout.splitlines():
            if text.startswith("# "):
                line = int(text.split()[1]) - 1
            elif line is not None:
                line += 1
                if call in text:
                    return line
        raise AssertionError(call)

    whole = cpp()
    assert all(c in whole for c in ("f(fuzz_buf", "g(1)", "h()"))
    shard = cpp("-DFRAMAC_EVA_SHARD", "-DFRAMAC_EVA_SHARD_CASE_1")
    assert "g(1)" in shard and "f(fuzz_buf" not in shard and "h()" not in shard
    assert line_of("g(1)") == line_of("g(1)", "-DFRAMAC_EVA_SHARD", "-DFRAMAC_EVA_SHARD_CASE_1")


# ---------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------


def _flamegraph(path: Path, lines: list[str]) -> Path:
    path.write_text("".join(line + "\n" for line in lines), encoding="utf-8")
    return path


def test_case_costs_split_shared_callees_and_eva_mains_own_time(tmp_path):
    fg = _flamegraph(
        tmp_path / "fg.txt",
        [
            "eva_main 4.0",  # shared by the 2 cases
            "eva_main;f 6.0",
            "eva_main;f;inner 2.0",
            "eva_main;shared 10.0",  # called by both cases
            "eva_main;init 2.0",  # no case calls it: shared
            "other_root;f 100.0",  # not eva_main
            "garbage line",
        ],
    )
    costs, basis = es.case_costs(["f(buf); shared(1);", "if (x) shared(2);"], fg)
    assert basis == "flamegraph"
    assert costs == pytest.approx([8.0 + 5.0 + 3.0, 5.0 + 3.0])
    assert es.case_costs(["f();", "g();"], tmp_path / "missing.txt") == ([1.0, 1.0], "uniform")
    assert es.case_costs(["f();", "g();"], None) == ([1.0, 1.0], "uniform")


def test_packing_is_longest_first_deterministic_and_covers_every_case_once():
    costs = [5.0, 1.0, 1.0, 4.0, 2.0, 2.0]
    shards = es.pack(costs, 3)
    assert shards == es.pack(list(costs), 3)
    assert sorted(c for s in shards for c in s) == list(range(6))
    loads = sorted(sum(costs[c] for c in s) for s in shards)
    assert loads == [5.0, 5.0, 5.0]
    assert es.pack([1.0, 1.0], 5) == [[0], [1]]  # never an empty shard


def test_the_shard_count_stops_where_the_costliest_case_bounds_the_makespan():
    # QCBOR run-5: 179 cases, case 171 alone 12% of the time, 6,964 s in one run.
    costs = [1.0] * 179
    costs[171] = 0.12 * 179 / 0.88
    k = es.choose_shard_count(costs, 6964.0, 5760.0)
    assert 7 <= k <= 9
    # Equal cases keep growing until one more shard saves less than SHARD_GAIN: 8 shards of at most 13
    # cases, where 9 would still hold 12 (8% less).
    assert es.choose_shard_count([1.0] * 100, 10_000.0, 5760.0) == 8
    # Never more than MAX_SHARDS or than cases.
    assert es.choose_shard_count([1.0] * 3, 1e9, 1.0) == 3
    assert es.choose_shard_count([1.0] * 500, 1e9, 1.0) <= es.MAX_SHARDS


def test_a_recorded_plan_holds_only_for_the_same_settings_cases_and_count():
    plan = es.make_plan(["f();", "g();", "h();"], None, 9000.0, 5760.0, "dig")
    assert plan["k"] == 3 and es.plan_problem(plan, 3, "dig") is None
    assert plan["predicted_makespan_s"] == 3000.0 and plan["basis"]["costs"] == "uniform"
    assert "settings" in str(es.plan_problem(plan, 3, "other"))
    assert "case count" in str(es.plan_problem(plan, 4, "dig"))
    assert "params.json asks for 2" in str(es.plan_problem(plan, 3, "dig", forced=2))
    bad = {**plan, "shards": [[0, 1], [1, 2]]}
    assert "exactly once" in str(es.plan_problem(bad, 3, "dig"))
    forced = es.make_plan(["f();", "g();", "h();"], None, 1.0, 5760.0, "dig", forced=2)
    assert forced["k"] == 2 and es.plan_problem(forced, 3, "dig", forced=2) is None
    assert "removed" in str(es.plan_problem(forced, 3, "dig"))
    assert es.plan_problem(None, 3, "dig") is not None


def _sharded_run(tmp_path: Path, cases: int = 4, guards: bool = True) -> Path:
    sidecars = copy.deepcopy(SIDECARS)
    sidecars["snmp"]["entry_style"] = "dispatch"
    sidecars["snmp"]["dispatch_cases"] = [f"snmp_call_{k}(fuzz_buf, fuzz_len);" for k in range(cases)]
    run = _make_run(tmp_path, sidecars=sidecars)
    body = _build_dispatch_invocation(sidecars["snmp"]["dispatch_cases"]) if guards else "case 0U: {}"
    (run / pm.HARNESS_DIR / "harness_snmp.c").write_text(body + "\n", encoding="utf-8")
    return run


def _single_run(run: Path, elapsed_s: float, flamegraph: list[str] | None = None, **fields) -> None:
    report = {"status": "ok", "elapsed_s": elapsed_s, "unknown_obligations_by_function": {}, **fields}
    if flamegraph is not None:
        fg = run / "workspace/eva/snmp/tune/base/flamegraph.txt"
        fg.parent.mkdir(parents=True, exist_ok=True)
        _flamegraph(fg, flamegraph)
        report["flamegraph_file"] = "workspace/eva/snmp/tune/base/flamegraph.txt"
    write_json(run / pm.TUNE_REPORT_DIR / "snmp" / "base.json", report)


def _mk(run: Path) -> tuple[str, dict]:
    res = pm.generate(run, templates_dir=ACSL)
    return (run / pm.MODULES_MK).read_text(encoding="utf-8"), res


def test_a_module_too_slow_to_tune_runs_as_shards_with_a_recorded_plan(tmp_path):
    run = _sharded_run(tmp_path)
    _single_run(run, 6963.6, ["eva_main;snmp_call_0 9000.0", "eva_main;snmp_call_1 10.0", "eva_main;snmp_call_2 10.0"])
    text, res = _mk(run)
    shards_line = next(line for line in text.splitlines() if line.startswith("EVA_SHARDS_snmp :="))
    k = len(shards_line.split(":=")[1].split())
    assert k >= 2
    plan = json.loads((run / es.SHARD_DIR / "snmp" / "plan.json").read_text(encoding="utf-8"))
    assert plan["k"] == k and plan["basis"]["costs"] == "flamegraph"
    assert [0] in plan["shards"]  # the costly case alone
    flags = next(line for line in text.splitlines() if line.startswith("EVA_SHARD_CPPFLAGS_snmp__0 :="))
    assert "-DDEBUG=2" in flags and "-DFRAMAC_EVA_SHARD " in flags and "-DFRAMAC_EVA_SHARD_CASE_" in flags
    # No ladder: a sharded module is not tuned (yet), and says so.
    assert "EVA_TUNE_RUNGS_snmp :=\n" in text and "EVA_TUNE_SKIP_snmp :=\n" in text
    assert any(w.startswith(f"snmp: Eva sharding: eva-snmp runs as {k} shards") for w in res["warnings"])
    assert pm.build_plan(run, templates_dir=ACSL).modules["snmp"].to_json()["eva_shards"] == plan["shards"]

    # A faster base run later does not move the shards: the plan holds while settings and cases do.
    _single_run(run, 50.0)
    text2, _ = _mk(run)
    assert shards_line in text2


def test_a_module_fast_enough_to_tune_is_not_sharded(tmp_path):
    run = _sharded_run(tmp_path)
    _single_run(run, 900.0, unknown_obligations_by_function={"parse": [{"directory": "w", "file": "a.c"}]})
    text, _ = _mk(run)
    assert "EVA_SHARDS_snmp :=\n" in text and not (run / es.SHARD_DIR / "snmp" / "plan.json").exists()
    assert "EVA_TUNE_RUNGS_snmp := " in text and "EVA_TUNE_RUNGS_snmp :=\n" not in text


def test_params_force_or_forbid_sharding(tmp_path):
    run = _sharded_run(tmp_path)
    pm.params_set(run, "snmp", eva_shards=3)
    text, _ = _mk(run)
    assert "EVA_SHARDS_snmp := 0 1 2\n" in text  # forced, even without any measured run
    _single_run(run, 6963.6)
    pm.params_set(run, "snmp", eva_shards=1)
    text, _ = _mk(run)
    assert "EVA_SHARDS_snmp :=\n" in text
    with pytest.raises(ValueError):
        pm.params_set(run, "snmp", eva_shards=es.MAX_SHARDS + 1)


def test_the_params_cli_sets_and_clears_the_shard_count(tmp_path, capsys):
    run = _sharded_run(tmp_path)
    base = ["--run-dir", str(run), "params", "set", "--module", "snmp"]
    assert pm.main([*base, "--eva-shards", "4"]) == 0
    assert json.loads(capsys.readouterr().out)["overrides"] == {"eva_shards": 4}
    assert pm.main([*base, "--eva-shards", "0"]) == 0  # back to automatic
    assert "eva_shards" not in json.loads(capsys.readouterr().out)["overrides"]


def test_a_harness_without_guards_is_never_sharded(tmp_path):
    run = _sharded_run(tmp_path, guards=False)
    _single_run(run, 6963.6)
    pm.params_set(run, "snmp", eva_shards=2)
    text, res = _mk(run)
    assert "EVA_SHARDS_snmp :=\n" in text
    assert any("predates sharding" in w for w in res["warnings"])


@pytest.mark.skipif(shutil.which("make") is None, reason="GNU make not available")
def test_make_dry_run_of_a_sharded_module(tmp_path):
    run = _sharded_run(tmp_path)
    pm.params_set(run, "snmp", eva_shards=2)
    pm.generate(run, templates_dir=ACSL)
    scripts = f"S={(REPO / 'scripts').as_posix()}"

    def make(*args: str) -> str:
        proc = subprocess.run(
            ["make", "-f", pm.MAKEFILE, scripts, "-n", *args], cwd=run, capture_output=True, text=True, check=False
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        return proc.stdout

    for target in ("eva-snmp", "evabase-snmp", "evatune-snmp"):
        out = make(target)
        assert "--key snmp:shard0" in out and "--key snmp:shard1" in out
        assert "-DFRAMAC_EVA_SHARD_CASE_" in out and "eva_shards.py merge --module snmp" in out
        assert "eva_tuning.py finish" not in out and "tune/base" not in out


# ---------------------------------------------------------------------------
# Merging
# ---------------------------------------------------------------------------


def _row(line: int, status: str, function: str = "parse") -> dict:
    return {
        "directory": "workspace/work",
        "file": "a.c",
        "line": line,
        "function": function,
        "kind": "mem_access",
        "status_raw": status,
        "property": f"\\valid(p+{line})",
    }


def _log(reached: dict[str, int]) -> str:
    metrics = "[metrics:eva:reached-stmts] \n  Statements analyzed by Eva\n  --------------------------\n"
    metrics += "".join(f"  {fn}: {n} stmts out of {n} (100.0%)\n" for fn, n in reached.items())
    return COMPLETE_LOG.replace("7 functions", f"{len(reached)} functions") + metrics


def _shard(run: Path, index: int, rows: list[dict], reached: dict[str, int], **report) -> None:
    out = run / f"workspace/eva/m/shards/{index}"
    out.mkdir(parents=True, exist_ok=True)
    header = "directory\tfile\tline\tfunction\tproperty kind\tstatus\tproperty\n"
    lines = [
        "\t".join([r["directory"], r["file"], str(r["line"]), r["function"], r["kind"], r["status_raw"], r["property"]])
        for r in rows
    ]
    (out / "alarms.csv").write_text(header + "".join(x + "\n" for x in lines), encoding="utf-8")
    (out / "eva.log").write_text(_log(reached), encoding="utf-8")
    (out / "flamegraph.txt").write_text(f"eva_main;shard{index} 1.0\n", encoding="utf-8")
    write_json(
        run / es.SHARD_DIR / "m" / f"shard{index}.json",
        {
            "status": "ok",
            "main_fn": "eva_main",
            "sources": ["a.c"],
            "input_digest": f"d{index}",
            "reduced_checks": [],
            "eva_options": {},
            "elapsed_s": 10.0 * (index + 1),
            "csv_file": (out / "alarms.csv").as_posix(),
            "log_file": (out / "eva.log").as_posix(),
            "flamegraph_file": (out / "flamegraph.txt").as_posix(),
            **report,
        },
    )


def _merge(run: Path, k: int = 2) -> tuple[int, dict]:
    write_json(run / es.SHARD_DIR / "m" / "plan.json", {"format": 1, "k": k, "shards": [[i] for i in range(k)]})
    rc = es.main(
        [
            "merge",
            "--module",
            "m",
            "--shard-dir",
            str(run / es.SHARD_DIR / "m"),
            "--entry-fn",
            "parse",
            "--csv-out",
            str(run / "workspace/eva/m/alarms.csv"),
            "--flamegraph-out",
            str(run / "workspace/eva/m/flamegraph.txt"),
            "--out-json",
            str(run / "workspace/reports/eva/m.json"),
        ]
    )
    return rc, json.loads((run / "workspace/reports/eva/m.json").read_text(encoding="utf-8"))


def _statuses(report: dict) -> dict[int, str]:
    """Merged status per line, read back from the merged alarms.csv."""
    return {r["line"]: r["status_raw"] for r in read_report_csv(Path(report["csv_file"]))}


def test_an_obligation_is_valid_only_when_no_reaching_shard_doubts_it(tmp_path, capsys):
    run = tmp_path
    reached0 = {"parse": 5, "eva_main": 3}
    reached1 = {"parse": 5, "eva_main": 3, "dec": 4}
    _shard(
        run,
        0,
        [
            _row(1, "Valid"),
            _row(2, "Valid"),
            _row(3, "Dead"),
            _row(4, "Valid"),
            _row(5, "Unknown"),
            _row(6, "Never tried", "dec"),  # not here: shard 0 never reaches dec
            _row(7, "Never tried", "unused"),
        ],
        reached0,
    )
    _shard(
        run,
        1,
        [
            _row(1, "Unknown"),  # Valid in shard 0, Unknown here: Unknown
            _row(2, "Dead"),  # Valid + Dead: Valid
            _row(3, "Dead"),
            _row(4, "Invalid"),
            _row(6, "Valid", "dec"),
            _row(7, "Never tried", "unused"),  # no shard reaches it: Never tried, as one run says
            _row(8, "Unknown"),  # an alarm only shard 1 emits
        ],
        reached1,
    )
    rc, report = _merge(run)
    capsys.readouterr()
    assert rc == 0 and report["status"] == "ok"
    statuses = _statuses(report)
    assert statuses == {
        1: "Unknown",
        2: "Valid",
        3: "Dead",
        4: "Invalid",
        5: "Unknown",
        6: "Valid",
        7: "Never tried",
        8: "Unknown",
    }
    assert report["invalid_count"] == 1 and report["valid_count"] == 2 and report["dead_count"] == 1
    assert report["unknown_count"] == 4  # 1, 5, 7 (never tried) and 8
    merge = report["eva_shards"]["merge"]
    assert merge["not_reached_anywhere"] == 1 and report["eva_shards"]["k"] == 2
    assert report["eva_shards"]["makespan_s"] == 20.0 and report["eva_shards"]["total_s"] == 30.0
    assert report["elapsed_s"] == 20.0 and report["entry_reached"] is True
    assert report["eva_coverage"]["functions_analyzed"] == 3
    assert report["tuning"]["mode"] == "skipped" and report["module"] == "m"
    # Every shard's profile, concatenated and folded: their sum is the module's Eva work.
    fg = (run / "workspace/eva/m/flamegraph.txt").read_text(encoding="utf-8")
    assert fg.splitlines() == ["eva_main;shard0 1", "eva_main;shard1 1"]
    assert report["flamegraph_file"].endswith("flamegraph.txt") and report["log_file"] is None


def test_a_shard_that_did_not_complete_makes_the_report_incomplete(tmp_path, capsys):
    run = tmp_path
    _shard(run, 0, [_row(1, "Valid")], {"parse": 5})
    write_json(
        run / es.SHARD_DIR / "m" / "shard1.json",
        {"status": "analysis_timeout", "elapsed_s": 7200.0, "error_summary": ["Eva timed out after 7200 s"]},
    )
    rc, report = _merge(run)
    capsys.readouterr()
    assert rc == 1 and report["status"] == "analysis_timeout"
    assert report["reason"].startswith("shard1 of 2 (cases [1]) did not complete")
    assert report["error_summary"][0].startswith("Eva shard shard1 of 2") and "valid_count" not in report


def test_a_missing_shard_report_or_plan_is_an_error(tmp_path, capsys):
    run = tmp_path
    _shard(run, 0, [_row(1, "Valid")], {"parse": 5})
    rc, report = _merge(run)
    assert rc == 1 and report["status"] == "analysis_error" and "shard1" in report["reason"]
    rc = es.main(
        [
            "merge",
            "--module",
            "m",
            "--shard-dir",
            str(run / "nowhere"),
            "--csv-out",
            str(run / "a.csv"),
            "--out-json",
            str(run / "m.json"),
        ]
    )
    capsys.readouterr()
    assert rc == 1 and "no shard plan" in json.loads((run / "m.json").read_text(encoding="utf-8"))["reason"]


def test_shards_of_different_analyses_are_refused(tmp_path, capsys):
    run = tmp_path
    _shard(run, 0, [_row(1, "Valid")], {"parse": 5})
    _shard(run, 1, [_row(1, "Valid")], {"parse": 5}, reduced_checks=["-no-warn-invalid-pointer"])
    rc, report = _merge(run)
    capsys.readouterr()
    assert rc == 1 and "not the same analysis" in report["reason"]


def test_flows_merge_as_hints_over_the_shards():
    a = {
        "status": "ok",
        "by_function": {"f": {"inputs": ["x"], "sure_outputs": ["r", "s"], "non_terminating": False}},
        "call_edges": {"f": ["g"]},
    }
    b = {
        "status": "ok",
        "by_function": {
            "f": {"inputs": ["y"], "sure_outputs": ["r"], "non_terminating": True},
            "h": {"inputs": []},
        },
        "call_edges": {"f": ["k"]},
    }
    merged = es.merge_flows([a, b])
    f = merged["by_function"]["f"]
    assert f["inputs"] == ["x", "y"] and f["sure_outputs"] == ["r"] and f["non_terminating"] is False
    assert "h" in merged["by_function"] and merged["call_edges"]["f"] == ["g", "k"]
    assert merged["status"] == "ok"
    assert es.merge_flows([a, {"status": "timeout", "reason": "flows timed out"}])["status"] == "partial"
    assert es.merge_flows([None, None])["status"] == "not_run"
