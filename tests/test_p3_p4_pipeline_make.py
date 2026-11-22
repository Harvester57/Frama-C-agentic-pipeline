"""
Unit tests for P2b, P3, P4, and P7f Makefile and pipeline stage orchestration
in `scripts/pipeline_make.py` and `templates/pipeline.mk`.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

import pipeline_make as pm
from conftest import makefile_rule, metadata, write_json

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parent.parent
PIPELINE_MK = REPO / "templates" / "pipeline.mk"
ACSL = REPO / "templates"


class _FakeMake:
    """In-memory Make runner recording invoked stage target lists."""

    def __init__(self, writes: dict[str, str] | None = None, failing: dict[str, int] | None = None) -> None:
        self.calls: list[list[str]] = []
        self.writes = writes or {}
        self.failing = failing or {}

    def __call__(self, cmd: list[str], cwd: Path, sink) -> int:
        self.calls.append(list(cmd))
        for rel, body in self.writes.items():
            dest = cwd / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(body, encoding="utf-8")
        for target, code in self.failing.items():
            sink(f"make: *** [templates/pipeline.mk:1: {target}] Error {code}")
        return 2 if self.failing else 0


class _FakeScripts:
    """In-memory script runner recording `ledger.py` and `validate_artifacts.py` calls."""

    def __init__(self, fail: set[str] | None = None) -> None:
        self.calls: list[tuple[str, list[str]]] = []
        self.fail = fail or set()

    def __call__(self, script: str, args: list[str]) -> tuple[int, str]:
        self.calls.append((script, list(args)))
        cmd = args[0] if args else ""
        ok = cmd not in self.fail
        return (0 if ok else 1), json.dumps({"ok": ok})


def _make_run(
    run: Path,
    *,
    profile: str = "standard",
    cases_by_mod: dict[str, int] | None = None,
    params: dict | None = None,
) -> Path:
    cases_by_mod = cases_by_mod or {"mod_a": 1, "mod_b": 4}
    dag_modules: dict[str, dict] = {}
    for mod in cases_by_mod:
        src = f"src/{mod}.c"
        src_path = run / "workspace/work" / src
        src_path.parent.mkdir(parents=True, exist_ok=True)
        src_path.write_text(f"int {mod}_fn(void) {{ return 0; }}\n", encoding="utf-8")
        dag_modules[mod] = {
            "tier": "Tier 1 (High Risk)",
            "run_eacsl_fuzz": True,
            "run_eva": True,
            "required_sources": [src],
            "cppflags": ["-I."],
        }
        n_cases = cases_by_mod[mod]
        sidecar: dict = {
            "module": mod,
            "sources": [src],
            "cppflags": "-I.",
            "ldflags": "",
            "include_source": False,
            "entry_fn": f"{mod}_fn",
        }
        if n_cases > 1:
            sidecar["dispatch_cases"] = [f"(void)case_{i}();" for i in range(n_cases)]
        write_json(run / pm.HARNESS_DIR / f"harness_{mod}.json", sidecar)
        (run / pm.HARNESS_DIR / f"harness_{mod}.c").write_text("int harness;\n", encoding="utf-8")

    write_json(run / "run-metadata.json", {**metadata(), "profile": profile, "scope_paths": ["src"]})
    write_json(run / pm.DAG_JSON, {"modules": dag_modules})
    if params is not None:
        write_json(run / pm.PARAMS_JSON, params)
    return run


# ---------------------------------------------------------------------------
# 1. Stage ordering and P4 non-overlap
# ---------------------------------------------------------------------------


def test_stage_of_target_strict_ordering_and_p4_separation():
    st = pm.STAGE_OF_TARGET
    assert (
        st["build"]
        < st["smoke"]
        < st["fuzz"]
        < st["judge"]
        == st["coverage"]
        < st["reach-dynamic"]
        == st["eacsl-fuzz"]
        < st["eva"]
        == st["eva-tune-base"]
        < st["eva-tune"]
        < st["facts"]
        == st["ingest"]
        == st["replay"]
        == st["minimize"]
        == st["wp-replay"]
        == st["wp-queue"]
        == st["wp-baseline"]
        == st["flamegraph"]
        < st["wp-sweep"]
        < st["report"]
    )
    assert st["build"] == 4
    assert st["smoke"] == 5
    assert st["fuzz"] == 6
    assert st["judge"] == 7 and st["coverage"] == 7
    assert st["reach-dynamic"] == 8 and st["eacsl-fuzz"] == 8
    assert st["eva"] == 9 and st["eva-tune-base"] == 9
    assert st["eva-tune"] == 10
    assert st["ingest"] == 11
    assert st["wp-sweep"] == 12
    assert st["report"] == 13

    # Per-module targets follow their base target stage.
    assert pm._stage("build-mod_a") == st["build"]
    assert pm._stage("smoke-mod_a") == st["smoke"]
    assert pm._stage("fuzz-mod_a") == st["fuzz"]
    assert pm._stage("judge-mod_a") == st["judge"]
    assert pm._stage("coverage-mod_a") == st["coverage"]
    assert pm._stage("reach-dynamic-mod_a") == st["reach-dynamic"]
    assert pm._stage("eacsl-fuzz-mod_a") == st["eacsl-fuzz"]
    assert pm._stage("eva-mod_a") == st["eva"]
    assert pm._stage("facts-mod_a") == st["facts"]
    assert pm._stage("flamegraph-mod_a") == st["flamegraph"]

    # P4: Fuzz and Eva never share a stage.
    assert pm._stage("fuzz") != pm._stage("eva")
    assert pm._stage("fuzz-mod_a") != pm._stage("eva-mod_a")
    s_smoke = pm._stage("smoke")
    s_fuzz = pm._stage("fuzz")
    s_eacsl_fuzz = pm._stage("eacsl-fuzz")
    s_eva = pm._stage("eva")
    assert s_smoke is not None and s_fuzz is not None and s_eacsl_fuzz is not None and s_eva is not None
    assert s_eacsl_fuzz < s_eva
    # P3: smoke runs strictly before both fuzz and Eva.
    assert s_smoke < s_fuzz
    assert s_smoke < s_eva


def test_run_targets_enforces_strict_stage_order_when_flags_enabled(tmp_path, monkeypatch):
    monkeypatch.setenv("FRAMAC_HARNESS_SMOKE", "on")
    monkeypatch.setenv("FRAMAC_FUZZ_EXPLORE_JUDGE", "on")
    run = _make_run(tmp_path, profile="deep")
    pm.generate(run, templates_dir=ACSL)
    fake = _FakeMake()

    rc, out = pm.run_targets(
        [
            "report",
            "wp-sweep",
            "ingest",
            "eva-tune",
            "eva",
            "eacsl-fuzz",
            "reach-dynamic",
            "coverage",
            "judge",
            "fuzz",
            "smoke",
            "build",
        ],
        run,
        jobs=2,
        make_runner=fake,
        templates_dir=ACSL,
    )
    assert rc == 0 and out["ok"] is True
    assert [c[7:] for c in fake.calls] == [
        ["build"],
        ["smoke"],
        ["fuzz"],
        ["coverage", "judge"],
        ["eacsl-fuzz", "reach-dynamic"],
        ["eva-tune-base", "eva"],
        ["eva-tune"],
        ["ingest"],
        ["wp-sweep"],
        ["report"],
    ]


def test_run_targets_never_overlaps_fuzz_and_eva_under_flags(tmp_path, monkeypatch):
    monkeypatch.setenv("FRAMAC_FUZZ_EXPLORE_JUDGE", "1")
    run = _make_run(tmp_path)
    pm.generate(run, templates_dir=ACSL)
    fake = _FakeMake()

    rc, _ = pm.run_targets(
        ["eva", "fuzz", "eva-mod_a", "fuzz-mod_a"], run, jobs=2, make_runner=fake, templates_dir=ACSL
    )
    assert rc == 0
    assert [c[7:] for c in fake.calls] == [["fuzz", "fuzz-mod_a"], ["eva", "eva-mod_a"]]


def test_run_targets_smoke_before_fuzz_and_eva_under_smoke_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("FRAMAC_HARNESS_SMOKE", "true")
    monkeypatch.delenv("FRAMAC_FUZZ_EXPLORE_JUDGE", raising=False)
    run = _make_run(tmp_path)
    pm.generate(run, templates_dir=ACSL)
    fake = _FakeMake()

    rc, _ = pm.run_targets(["eva", "fuzz", "smoke", "build"], run, jobs=2, make_runner=fake, templates_dir=ACSL)
    assert rc == 0
    assert [c[7:] for c in fake.calls] == [["build"], ["smoke"], ["fuzz"], ["eva"]]


def test_run_targets_preserves_legacy_grouping_when_flags_off(tmp_path, monkeypatch):
    monkeypatch.delenv("FRAMAC_HARNESS_SMOKE", raising=False)
    monkeypatch.delenv("FRAMAC_FUZZ_EXPLORE_JUDGE", raising=False)
    run = _make_run(tmp_path)
    pm.generate(run, templates_dir=ACSL)
    fake = _FakeMake()

    rc, _ = pm.run_targets(["ingest", "fuzz", "eva", "report"], run, jobs=1, make_runner=fake, templates_dir=ACSL)
    assert rc == 0
    assert [c[7:] for c in fake.calls] == [["fuzz", "eva"], ["ingest"], ["report"]]


# ---------------------------------------------------------------------------
# 2. Makefile targets and flag-conditional wiring
# ---------------------------------------------------------------------------


def test_pipeline_mk_new_targets_and_flag_wiring():
    mk = PIPELINE_MK.read_text(encoding="utf-8")
    phony = set(makefile_rule(mk, ".PHONY").prerequisites)
    for required in (
        "smoke",
        "judge",
        "eacsl-fuzz",
        "$(SMOKE_TARGETS)",
        "$(JUDGE_TARGETS)",
        "$(EACSL_FUZZ_TARGETS)",
    ):
        assert required in phony, required

    # smoke-%: --class replay, harness_smoke.py run + phase0_gates.py record-smoke
    smoke_rule = makefile_rule(mk, "$(SMOKE_TARGETS)")
    assert smoke_rule.pattern == "smoke-%"
    assert smoke_rule.recipe[0] == "$(GATE) --module $* --need reach"
    smoke_text = "\n".join(smoke_rule.recipe)
    assert "--class replay" in smoke_text
    assert "harness_smoke.py run --module $*" in smoke_text
    assert "--build-json workspace/build/$*.build.json" in smoke_text
    assert "--out-json workspace/reports/smoke/$*.json" in smoke_text
    assert "phase0_gates.py record-smoke --module $* --report workspace/reports/smoke/$*.json" in smoke_text

    # judge-%: --class replay, run_eacsl_fuzz.py judge, no phony fuzz-% prerequisite
    judge_rule = makefile_rule(mk, "$(JUDGE_TARGETS)")
    assert judge_rule.pattern == "judge-%"
    assert "fuzz-%" not in judge_rule.prerequisites
    judge_text = "\n".join(judge_rule.recipe)
    assert "--class replay" in judge_text
    assert "run_eacsl_fuzz.py judge --module $*" in judge_text
    assert "--build-json workspace/build/$*.build.json" in judge_text
    assert "--explore-report workspace/reports/fuzz/$*.json" in judge_text
    assert "--out-json workspace/reports/judge/$*.json" in judge_text

    # eacsl-fuzz-%: --class fuzz, deep profile only, run_eacsl_fuzz.py eacsl-fuzz
    ef_rule = makefile_rule(mk, "$(EACSL_FUZZ_TARGETS)")
    assert ef_rule.pattern == "eacsl-fuzz-%"
    ef_text = "\n".join(ef_rule.recipe)
    assert "--class fuzz" in ef_text
    assert "run_eacsl_fuzz.py eacsl-fuzz --module $*" in ef_text
    assert "--judge-report workspace/reports/judge/$*.json" in ef_text
    assert "--out-json workspace/reports/eacsl-fuzz/$*.json" in ef_text
    assert "ifneq ($(PROFILE),deep)" in mk
    assert "eacsl-fuzz: $(if $(filter deep,$(PROFILE)),$(EACSL_FUZZ_TARGETS))" in mk

    # fuzz-%: gated build-% prerequisite under FUZZ_EXPLORE_JUDGE + --build-json + optional --smoke-report
    fuzz_rule = makefile_rule(mk, "$(FUZZ_TARGETS)")
    fuzz_text = "\n".join(fuzz_rule.recipe)
    assert "$(if $(FUZZ_EXPLORE_JUDGE),--build-json workspace/build/$*.build.json --profile $(PROFILE))" in fuzz_text
    assert "$(if $(HARNESS_SMOKE),--smoke-report workspace/reports/smoke/$*.json)" in fuzz_text
    assert "$(GATE) --module $* --need smoke" in fuzz_text
    assert "ifndef FUZZ_EXPLORE_JUDGE\n$(FUZZ_TARGETS): fuzz-%: build-%\nendif" in mk

    # eva-% checks smoke gate under HARNESS_SMOKE
    eva_rule = makefile_rule(mk, "$(EVA_TARGETS)")
    assert any("--need smoke" in line for line in eva_rule.recipe)


def test_modules_mk_emits_flag_variables_only_when_enabled(tmp_path, monkeypatch):
    monkeypatch.delenv("FRAMAC_HARNESS_SMOKE", raising=False)
    monkeypatch.delenv("FRAMAC_FUZZ_EXPLORE_JUDGE", raising=False)
    run = _make_run(tmp_path)
    pm.generate(run, templates_dir=ACSL)
    mk_off = (run / pm.MODULES_MK).read_text(encoding="utf-8")
    assert "HARNESS_SMOKE" not in mk_off
    assert "FUZZ_EXPLORE_JUDGE" not in mk_off

    monkeypatch.setenv("FRAMAC_HARNESS_SMOKE", "on")
    monkeypatch.setenv("FRAMAC_FUZZ_EXPLORE_JUDGE", "on")
    pm.generate(run, templates_dir=ACSL)
    mk_on = (run / pm.MODULES_MK).read_text(encoding="utf-8")
    assert "HARNESS_SMOKE := 1\n" in mk_on
    assert "FUZZ_EXPLORE_JUDGE := 1\n" in mk_on


def test_node_deps_and_outputs_reflect_flags_and_profile(tmp_path, monkeypatch):
    monkeypatch.delenv("FRAMAC_HARNESS_SMOKE", raising=False)
    monkeypatch.delenv("FRAMAC_FUZZ_EXPLORE_JUDGE", raising=False)
    run = _make_run(tmp_path, profile="standard")
    plan_off = pm.build_plan(run, templates_dir=ACSL)
    assert pm._node_deps("fuzz-mod_a", plan_off) == ["selftest", "build-mod_a"]
    assert pm._node_deps("module-mod_a", plan_off) == ["fuzz-mod_a", "eva-mod_a"]
    assert pm._target_nodes("eacsl-fuzz", plan_off) == []
    assert pm._node_output("eacsl-fuzz-mod_a", plan_off) is None

    monkeypatch.setenv("FRAMAC_HARNESS_SMOKE", "on")
    monkeypatch.setenv("FRAMAC_FUZZ_EXPLORE_JUDGE", "on")
    run_deep = _make_run(tmp_path / "deep", profile="deep")
    plan_on = pm.build_plan(run_deep, templates_dir=ACSL)
    assert pm._node_deps("fuzz-mod_a", plan_on) == ["selftest"]
    assert pm._node_deps("module-mod_a", plan_on) == [
        "build-mod_a",
        "smoke-mod_a",
        "fuzz-mod_a",
        "judge-mod_a",
        "eacsl-fuzz-mod_a",
        "eva-mod_a",
    ]
    assert pm._target_nodes("smoke", plan_on) == ["smoke-mod_a", "smoke-mod_b"]
    assert pm._target_nodes("judge", plan_on) == ["judge-mod_a", "judge-mod_b"]
    assert pm._target_nodes("eacsl-fuzz", plan_on) == ["eacsl-fuzz-mod_a", "eacsl-fuzz-mod_b"]
    assert pm._node_output("smoke-mod_a", plan_on) == "workspace/reports/smoke/mod_a.json"
    assert pm._node_output("judge-mod_a", plan_on) == "workspace/reports/judge/mod_a.json"
    assert pm._node_output("eacsl-fuzz-mod_a", plan_on) == "workspace/reports/eacsl-fuzz/mod_a.json"


def test_ingest_handles_optional_judge_and_eacsl_fuzz_reports_in_order(tmp_path):
    run = _make_run(tmp_path, profile="deep", cases_by_mod={"mod_a": 2})
    write_json(run / "workspace/reports/fuzz/mod_a.json", {"mode": "campaign", "module": "mod_a", "status": "clean"})
    write_json(run / "workspace/reports/judge/mod_a.json", {"mode": "judge", "module": "mod_a", "status": "clean"})
    write_json(
        run / "workspace/reports/eacsl-fuzz/mod_a.json",
        {"mode": "eacsl-fuzz", "module": "mod_a", "status": "clean"},
    )
    write_json(run / "workspace/reports/eva/mod_a.json", {"module": "mod_a", "status": "ok"})

    fake = _FakeScripts()
    res = pm.ingest(run, runner=fake)
    assert res["ok"] is True
    ledger_calls = [(args[0], args[1:]) for script, args in fake.calls if script == "ledger.py"]
    assert ledger_calls == [
        ("ingest-fuzz", ["workspace/reports/fuzz/mod_a.json"]),
        ("ingest-judge", ["workspace/reports/judge/mod_a.json"]),
        ("ingest-fuzz", ["workspace/reports/eacsl-fuzz/mod_a.json"]),
        ("ingest-eva", ["workspace/reports/eva/mod_a.json"]),
    ]

    # Idempotent second ingest.
    again = _FakeScripts()
    res2 = pm.ingest(run, runner=again)
    assert res2["ok"] is True
    assert [c for c in again.calls if c[0] == "ledger.py"] == []
    assert res2["already_ingested"]["judge"] == 1
    assert res2["already_ingested"]["eacsl-fuzz"] == 1


# ---------------------------------------------------------------------------
# 3. P3 sublinear fuzz budgets & worker clamping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("profile", "base_cap", "per_case"),
    [
        ("quick", 480, 60),
        ("standard", 7200, 600),
        ("deep", 43200, 3600),
    ],
)
@pytest.mark.parametrize("cases", [1, 12, 40, 182])
def test_p3_sublinear_budget_formula_across_profiles_and_case_counts(
    tmp_path, monkeypatch, profile, base_cap, per_case, cases
):
    expected_cap = min(3 * base_cap, round(base_cap * math.sqrt(max(1.0, cases / 12))))
    expected_budget = min(per_case * cases, expected_cap)

    assert pm.sublinear_unit_cap(profile, cases) == expected_cap
    assert pm.sublinear_fuzz_budget(profile, cases) == expected_budget

    monkeypatch.setenv("FRAMAC_FUZZ_EXPLORE_JUDGE", "on")
    run = _make_run(tmp_path / f"{profile}_{cases}", profile=profile, cases_by_mod={"mod_a": cases})
    plan = pm.build_plan(run, templates_dir=ACSL)
    mod_params = plan.modules["mod_a"].params
    assert mod_params["fuzz_cases"] == cases
    assert mod_params["fuzz_budget"] == expected_budget
    assert mod_params["fuzz_workers_cap"] == pm.clamp_fuzz_workers(expected_budget, expected_budget)


def test_p3_sublinear_exact_reference_values():
    # Design doc reference points (docs/plans/fuzz-budget-design.md P3):
    assert pm.sublinear_fuzz_budget("standard", 1) == 600
    assert pm.sublinear_fuzz_budget("standard", 12) == 7200
    assert pm.sublinear_fuzz_budget("standard", 40) == 13145
    assert pm.sublinear_fuzz_budget("standard", 182) == 21600

    assert pm.sublinear_fuzz_budget("quick", 1) == 60
    assert pm.sublinear_fuzz_budget("quick", 12) == 480
    assert pm.sublinear_fuzz_budget("quick", 40) == 876
    assert pm.sublinear_fuzz_budget("quick", 182) == 1440

    assert pm.sublinear_fuzz_budget("deep", 1) == 3600
    assert pm.sublinear_fuzz_budget("deep", 12) == 43200
    assert pm.sublinear_fuzz_budget("deep", 40) == 78872
    assert pm.sublinear_fuzz_budget("deep", 182) == 129600


def test_p3_worker_clamping_prevents_wall_floor_cpu_inflation():
    # 30 CPU-s budget on 9 lease workers -> clamped to 1 worker (30 s wall = 30 CPU-s, not 270 CPU-s).
    assert pm.clamp_fuzz_workers(9, 30) == 1
    assert pm.clamp_fuzz_workers(9, 60) == 2
    assert pm.clamp_fuzz_workers(9, 120) == 4
    assert pm.clamp_fuzz_workers(9, 600) == 9
    assert pm.clamp_fuzz_workers(15, 13145) == 15
    assert pm.clamp_fuzz_workers(15, 10) == 1

    # Invariant: for any budget >= MIN_FUZZ_WALL_S, wall floor never inflates CPU spent past budget.
    for lease in (1, 4, 9, 15, 32):
        for budget in (30, 45, 60, 90, 120, 270, 600, 7200):
            eff = pm.clamp_fuzz_workers(lease, budget)
            assert 1 <= eff <= lease
            assert eff * pm.MIN_FUZZ_WALL_S <= budget


def test_legacy_budgets_preserved_when_explore_judge_flag_off(tmp_path, monkeypatch):
    monkeypatch.delenv("FRAMAC_FUZZ_EXPLORE_JUDGE", raising=False)
    for profile in ("quick", "standard", "deep"):
        run = _make_run(tmp_path / f"legacy_{profile}", profile=profile, cases_by_mod={"mod_a": 40})
        plan = pm.build_plan(run, templates_dir=ACSL)
        mod_params = plan.modules["mod_a"].params
        assert mod_params["fuzz_budget"] == pm.FUZZ_UNIT_CAP_BY_PROFILE[profile]
        assert mod_params["fuzz_budget_source"] == "unit_cap"
        assert "fuzz_workers_cap" not in mod_params


def test_explicit_params_fuzz_budget_overrides_p3_calculation(tmp_path, monkeypatch):
    monkeypatch.setenv("FRAMAC_FUZZ_EXPLORE_JUDGE", "on")
    run = _make_run(
        tmp_path,
        profile="standard",
        cases_by_mod={"mod_a": 40},
        params={"version": 1, "modules": {"mod_a": {"fuzz_budget": 1500}}},
    )
    plan = pm.build_plan(run, templates_dir=ACSL)
    assert plan.modules["mod_a"].params["fuzz_budget"] == 1500
    assert plan.modules["mod_a"].params["fuzz_budget_source"] == "params"
    # 1500 is well below the 40-case P3 cap (13145), so no over-cap warning is emitted.
    assert not any("fuzz budget:" in w for w in plan.warnings)


# ---------------------------------------------------------------------------
# 4. P2b warning on `params set --fuzz-engine eacsl`
# ---------------------------------------------------------------------------


def test_params_set_fuzz_engine_eacsl_emits_dual_engine_warning(tmp_path, capsys):
    run = _make_run(tmp_path)

    res = pm.params_set(run, "mod_a", fuzz_engine="eacsl")
    assert res["ok"] is True
    assert res["overrides"]["fuzz_engine"] == "eacsl"
    assert any("sanitizer" in w.lower() and "--fuzz-engine auto" in w for w in res["warnings"]), res["warnings"]

    # CLI path emits the warning on stderr AND keeps valid JSON (with warnings) on stdout.
    rc = pm.main(["--run-dir", str(run), "params", "set", "--module", "mod_a", "--fuzz-engine", "eacsl"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "--fuzz-engine auto" in captured.err
    assert "sanitizer" in captured.err.lower()
    payload = json.loads(captured.out)
    assert payload["overrides"]["fuzz_engine"] == "eacsl"
    assert any("--fuzz-engine auto" in w for w in payload["warnings"])

    # Switching back to `auto` emits no dual-engine loss warning.
    rc_auto = pm.main(["--run-dir", str(run), "params", "set", "--module", "mod_a", "--fuzz-engine", "auto"])
    assert rc_auto == 0
    captured_auto = capsys.readouterr()
    assert captured_auto.err == ""
    payload_auto = json.loads(captured_auto.out)
    assert not any("--fuzz-engine auto" in w for w in payload_auto["warnings"])


# ---------------------------------------------------------------------------
# 5. Wave 5 regression tests: module-<mod> ordering & smoke-% record-smoke
# ---------------------------------------------------------------------------


def test_run_targets_module_target_orders_stages_strictly_under_flags(tmp_path, monkeypatch):
    # Deep profile + both flags: build -> smoke -> fuzz -> judge -> eacsl-fuzz -> eva -> module (ingest+facts).
    monkeypatch.setenv("FRAMAC_HARNESS_SMOKE", "on")
    monkeypatch.setenv("FRAMAC_FUZZ_EXPLORE_JUDGE", "on")
    run_deep = _make_run(tmp_path / "deep", profile="deep")
    pm.generate(run_deep, templates_dir=ACSL)
    fake_deep = _FakeMake()
    rc, out = pm.run_targets(["module-mod_a"], run_deep, jobs=4, make_runner=fake_deep, templates_dir=ACSL)
    assert rc == 0 and out["ok"] is True
    assert [c[7:] for c in fake_deep.calls] == [
        ["build-mod_a"],
        ["smoke-mod_a"],
        ["fuzz-mod_a"],
        ["judge-mod_a"],
        ["eacsl-fuzz-mod_a"],
        ["eva-mod_a"],
        ["MODULE_STAGES_DONE=1", "module-mod_a"],
    ]

    # Standard profile + HARNESS_SMOKE only: build -> smoke -> fuzz -> eva -> module.
    monkeypatch.setenv("FRAMAC_HARNESS_SMOKE", "on")
    monkeypatch.delenv("FRAMAC_FUZZ_EXPLORE_JUDGE", raising=False)
    run_smoke = _make_run(tmp_path / "smoke_only", profile="standard")
    pm.generate(run_smoke, templates_dir=ACSL)
    fake_smoke = _FakeMake()
    rc_s, out_s = pm.run_targets(["module-mod_a"], run_smoke, jobs=2, make_runner=fake_smoke, templates_dir=ACSL)
    assert rc_s == 0 and out_s["ok"] is True
    assert [c[7:] for c in fake_smoke.calls] == [
        ["build-mod_a"],
        ["smoke-mod_a"],
        ["fuzz-mod_a"],
        ["eva-mod_a"],
        ["MODULE_STAGES_DONE=1", "module-mod_a"],
    ]

    # Standard profile + FUZZ_EXPLORE_JUDGE only: build -> fuzz -> judge -> eva -> module.
    monkeypatch.delenv("FRAMAC_HARNESS_SMOKE", raising=False)
    monkeypatch.setenv("FRAMAC_FUZZ_EXPLORE_JUDGE", "on")
    run_ej = _make_run(tmp_path / "ej_only", profile="standard")
    pm.generate(run_ej, templates_dir=ACSL)
    fake_ej = _FakeMake()
    rc_e, out_e = pm.run_targets(["module-mod_a"], run_ej, jobs=2, make_runner=fake_ej, templates_dir=ACSL)
    assert rc_e == 0 and out_e["ok"] is True
    assert [c[7:] for c in fake_ej.calls] == [
        ["build-mod_a"],
        ["fuzz-mod_a"],
        ["judge-mod_a"],
        ["eva-mod_a"],
        ["MODULE_STAGES_DONE=1", "module-mod_a"],
    ]

    # Failure in an earlier expanded stage (smoke-mod_a) propagates to module-mod_a.
    monkeypatch.setenv("FRAMAC_HARNESS_SMOKE", "on")
    monkeypatch.setenv("FRAMAC_FUZZ_EXPLORE_JUDGE", "on")
    fake_fail = _FakeMake(failing={"smoke-mod_a": 1})
    rc_f, out_f = pm.run_targets(["module-mod_a"], run_deep, jobs=2, make_runner=fake_fail, templates_dir=ACSL)
    assert rc_f == 1 and out_f["ok"] is False
    assert out_f["targets"]["smoke-mod_a"]["status"] == "failed"
    assert out_f["targets"]["module-mod_a"]["status"] == "failed"

    # Legacy flags off: single-stage module-mod_a invocation preserved unchanged.
    monkeypatch.delenv("FRAMAC_HARNESS_SMOKE", raising=False)
    monkeypatch.delenv("FRAMAC_FUZZ_EXPLORE_JUDGE", raising=False)
    run_leg = _make_run(tmp_path / "legacy", profile="standard")
    pm.generate(run_leg, templates_dir=ACSL)
    fake_leg = _FakeMake()
    rc_l, out_l = pm.run_targets(["module-mod_a"], run_leg, jobs=2, make_runner=fake_leg, templates_dir=ACSL)
    assert rc_l == 0 and out_l["ok"] is True
    assert [c[7:] for c in fake_leg.calls] == [["module-mod_a"]]


def test_pipeline_mk_module_target_orders_direct_make_and_smoke_records_on_failure():
    mk = PIPELINE_MK.read_text(encoding="utf-8")

    # BLOCKER-3: direct `make module-<m>` under HARNESS_SMOKE/FUZZ_EXPLORE_JUDGE runs stages sequentially via $(MAKE).
    mod_rule = makefile_rule(mk, "$(MODULE_TARGETS)")
    assert mod_rule.pattern == "module-%"
    mod_text = "\n".join(mod_rule.recipe)
    assert "build-$*" in mod_text
    assert "smoke-$*" in mod_text
    assert "fuzz-$*" in mod_text
    assert "judge-$*" in mod_text
    assert "eacsl-fuzz-$*" in mod_text
    assert "eva-$*" in mod_text
    assert "ingest --module $*" in mod_text
    assert (
        mod_text.index("build-$*")
        < mod_text.index("smoke-$*")
        < mod_text.index("fuzz-$*")
        < mod_text.index("judge-$*")
        < mod_text.index("eacsl-fuzz-$*")
        < mod_text.index("eva-$*")
        < mod_text.index("ingest --module $*")
        < mod_text.index("$(call FACTS_RECIPE,$*)")
    )
    # Legacy flags=off prerequisite evaluation stays intact and guarded.
    assert "ifeq ($(or $(HARNESS_SMOKE),$(FUZZ_EXPLORE_JUDGE)),)" in mk
    assert "ifndef MODULE_STAGES_DONE" in mk

    # MINOR-6: smoke-% captures exit code, records the smoke report even on non-zero exit, and propagates exit $$rc.
    smoke_rule = makefile_rule(mk, "$(SMOKE_TARGETS)")
    smoke_text = "\n".join(smoke_rule.recipe)
    assert "--output workspace/reports/smoke/$*.json" not in smoke_text
    assert "rm -f workspace/reports/smoke/$*.json" in smoke_text
    assert "rc=0;" in smoke_text
    assert "|| rc=$$?" in smoke_text
    assert "if [ -f workspace/reports/smoke/$*.json ]; then" in smoke_text
    assert "phase0_gates.py record-smoke --module $* --report workspace/reports/smoke/$*.json" in smoke_text
    assert "exit $$rc" in smoke_text
    assert smoke_text.index("harness_smoke.py run") < smoke_text.index("record-smoke") < smoke_text.index("exit $$rc")
