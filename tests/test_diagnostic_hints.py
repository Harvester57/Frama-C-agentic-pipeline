from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from run_eacsl_fuzz import derive_eacsl_diagnostic_hints  # noqa: E402
from run_wp_function import derive_wp_diagnostic_hints, run_wp_on_function  # noqa: E402
from workspace_overlay import init_overlay, prepare_agent  # noqa: E402
from wp_scheduler import _PLACEHOLDER_RE  # noqa: E402


def test_wp_hints_clean_run_is_empty() -> None:
    res = {"status": "all_proven", "soundness": {"ok": True}}
    assert derive_wp_diagnostic_hints(res) == []


def test_wp_hints_syntax_eaten_backslash_and_clause_order() -> None:
    res = {
        "status": "acsl_syntax_error",
        "syntax_check": {
            "syntax_ok": False,
            "errors": [
                "[kernel:annot-error] foo.c:4: Failure: unbound logic variable alse.",
                "[kernel:annot-error] foo.c:8: wrong order of clause in contract: terminates after assigns.",
            ],
            "raw_log": "",
        },
    }
    hints = derive_wp_diagnostic_hints(res)
    assert any("Backslash in an ACSL keyword" in h for h in hints)
    assert any("clause ordering" in h for h in hints)


def test_wp_hints_syntax_c_type_in_quantifier_and_bool() -> None:
    res = {
        "status": "acsl_syntax_error",
        "syntax_check": {
            "syntax_ok": False,
            "errors": [
                r"[kernel:annot-error] foo.c:10: syntax error near \forall int k; k >= 0",
                "[kernel:annot-error] foo.c:12: invalid implicit conversion from int to boolean",
            ],
            "raw_log": "",
        },
    }
    hints = derive_wp_diagnostic_hints(res)
    assert any("mathematical 'integer'" in h for h in hints)
    assert any("terms (values) from predicates" in h for h in hints)


def test_wp_hints_soundness_aborts_and_unsoundness() -> None:
    res = {
        "status": "unsound_proof",
        "soundness": {
            "ok": False,
            "tier_a_aborts": [],
            "tier_b_unsound": [
                "[wp] warning: Missing assigns clause (assigns 'everything' instead)",
                "Failed smoke-test in function foo",
                "1 unproven lemma(s) in scope",
            ],
            "checked_memory_model_functions": ["foo"],
            "skipped_rte_guards": ["Through function pointer: cannot generate"],
        },
    }
    hints = derive_wp_diagnostic_hints(res)
    assert any("missing 'assigns'" in h for h in hints)
    assert any("separation hypotheses" in h for h in hints)
    assert any("function pointer" in h for h in hints)
    assert any("Unproven global ACSL lemma" in h for h in hints)
    assert any("Vacuous proof" in h for h in hints)


def test_wp_hints_unproven_buckets_and_loop_established_preserved() -> None:
    res = {
        "status": "unproven_goals_remain",
        "soundness": {"ok": True},
        "unproven_by_bucket": {
            "step_a_assigns": [{"kind": "assigns", "annotation": "assigns *out"}],
            "step_b_loop_invariant": [{"kind": "loop_invariant", "annotation": "bound"}],
            "step_c_rte_obligation": [
                {"kind": "rte", "annotation": "rte: mem_access: \\valid_read(p)"},
                {"kind": "rte", "annotation": "rte: signed_overflow: a + b <= 2147483647"},
                {"kind": "rte", "annotation": "rte: initialization: \\initialized(&x)"},
            ],
        },
        "unproven_goals": [
            {"kind": "rte", "annotation": "rte: mem_access: \\valid_read(p)"},
            {"kind": "rte", "annotation": "rte: signed_overflow: a + b <= 2147483647"},
            {"kind": "rte", "annotation": "rte: initialization: \\initialized(&x)"},
        ],
    }
    log = (
        "[wp] [Timeout] typed_foo_loop_invariant_bound_established (Alt-Ergo)\n"
        "[wp] [Timeout] typed_foo_loop_invariant_bound_preserved (Z3)\n"
    )
    hints = derive_wp_diagnostic_hints(res, log)
    assert any("Step A (Frame Conditions)" in h for h in hints)
    assert any("ESTABLISHMENT failed" in h for h in hints)
    assert any("PRESERVATION failed" in h for h in hints)
    assert any("pointer/array access" in h for h in hints)
    assert any("arithmetic RTE" in h for h in hints)
    assert any("initialization" in h for h in hints)


def test_eacsl_hints_clean_and_failure_modes() -> None:
    assert derive_eacsl_diagnostic_hints({"status": "passed_dynamic_oracle"}) == []

    over = {
        "status": "rejected_overconstrained",
        "failure": {
            "file": "parser.c",
            "line": 22,
            "function": "parse_msg",
            "kind": "precondition",
            "label": "requires_valid",
            "predicate": "\\valid_read(buf + (0 .. len - 1))",
        },
    }
    over_hints = derive_eacsl_diagnostic_hints(over)
    assert any("stronger than the actual runtime behavior" in h for h in over_hints)
    assert any("len > 0 ==>" in h for h in over_hints)
    assert any("Precondition failed" in h for h in over_hints)

    fault = {
        "status": "code_fault",
        "failure": {
            "file": "parser.c",
            "line": 44,
            "function": "parse_msg",
            "kind": "assertion",
            "is_rte": True,
            "predicate": "rte: index_bound: idx < 16",
        },
    }
    fault_hints = derive_eacsl_diagnostic_hints(fault)
    assert any("code defect candidate" in h and "blocked" in h for h in fault_hints)

    comp_err = {
        "status": "compile_error",
        "compile": {
            "stderr": "[e-acsl] user error: unbounded quantification over integer k; axiomatic block not yet supported",
        },
    }
    comp_hints = derive_eacsl_diagnostic_hints(comp_err)
    assert any("bounded integer quantifications" in h for h in comp_hints)
    assert any("unsupported ACSL construct" in h for h in comp_hints)
    assert any("field-by-field scalar comparisons" in h for h in comp_hints)

    annot_rte_over = {
        "status": "rejected_overconstrained",
        "annotation_rte": True,
        "failure": {
            "file": "parser.c",
            "line": 18,
            "function": "parse_msg",
            "kind": "rte",
            "annotation_rte": True,
            "label": "rte",
            "predicate": "division_by_zero: denom != 0 && \\initialized(out_hdr)",
        },
    }
    annot_rte_hints = derive_eacsl_diagnostic_hints(annot_rte_over)
    assert any("3-valued partial logic" in h for h in annot_rte_hints)
    assert any("flat shadow memory" in h and "\\initialized(&p->field)" in h for h in annot_rte_hints)


def test_brief_templates_synced_and_render_cleanly(tmp_path: Path) -> None:
    for p in (ROOT / "skills").rglob("*.md"):
        agent_copy = ROOT / ".agents" / p.relative_to(ROOT)
        if agent_copy.parent.is_dir():
            assert p.read_text(encoding="utf-8") == agent_copy.read_text(encoding="utf-8"), (
                f"{p} out of sync with {agent_copy}"
            )
    for fname in ("prover_brief.md", "header_architect_brief.md"):
        canonical = (ROOT / "skills" / "framac-wp" / fname).read_text(encoding="utf-8")
        assert "WRONG" in canonical and "RIGHT" in canonical

    target = tmp_path / "target"
    target.mkdir()
    (target / "mod.h").write_text("int sum_clamped(const int *src, int n, int *out_sum);\n", encoding="utf-8")
    (target / "mod.c").write_text(
        '#include "mod.h"\nint sum_clamped(const int *src, int n, int *out_sum) { *out_sum = 0; return 0; }\n',
        encoding="utf-8",
    )
    run_dir = tmp_path / "run"
    init_overlay(target, run_dir / "workspace")

    prover_prep = prepare_agent(
        run_dir=run_dir,
        agent_id="prover_sum_clamped",
        role="prover",
        module="mod",
        function="sum_clamped",
        c_file="mod.c",
        header_file="mod.h",
    )
    prover_brief = (run_dir / prover_prep["brief_file"]).read_text(encoding="utf-8")
    assert not _PLACEHOLDER_RE.search(prover_brief)
    assert "{references_dir}" not in prover_brief
    assert "Canonical C + ACSL Annotated Function Template" in prover_brief

    arch_prep = prepare_agent(
        run_dir=run_dir,
        agent_id="arch_mod",
        role="architect",
        module="mod",
        header_file="mod.h",
    )
    arch_brief = (run_dir / arch_prep["brief_file"]).read_text(encoding="utf-8")
    assert not _PLACEHOLDER_RE.search(arch_brief)
    assert "Common Header Contract Traps" in arch_brief


def test_wp_hints_and_guard_for_dynamic_allocation_and_probe_files(tmp_path: Path) -> None:
    import json

    # 1. Dynamic allocation limitation hint on \freeable / \fresh / allocates
    res = {
        "status": "unproven_goals_remain",
        "soundness": {
            "ok": False,
            "tier_a_aborts": [],
            "tier_b_unsound": ["[wp] warning: \\freeable not yet supported (skipped)"],
        },
        "unproven_by_bucket": {
            "step_c_caller_precondition": [{"kind": "precondition", "annotation": "free_ptr: \\freeable(p)"}],
        },
        "unproven_goals": [
            {"kind": "precondition", "annotation": "free_ptr: \\freeable(p)", "wp_allocation_limitation": True},
        ],
        "wp_allocation_limitation": True,
    }
    hints = derive_wp_diagnostic_hints(res, "[wp] warning: \\freeable not yet supported (skipped)")
    assert any("dynamic allocation" in h and "stalled_after_k_retries" in h for h in hints)
    assert not any("rewrite the unsupported" in h for h in hints)

    # 2. Synthetic probe_*.c files in agents/<id>/scratch/ are rejected immediately without invoking frama-c
    scratch_dir = tmp_path / "agents" / "prove_foo" / "scratch"
    scratch_dir.mkdir(parents=True)
    probe_c = scratch_dir / "probe_freeable.c"
    probe_c.write_text("void f(void) {}\n", encoding="utf-8")
    probe_res = run_wp_on_function(c_file=probe_c, fn_name="f", out_dir=scratch_dir / "wp")
    assert probe_res["status"] == "wp_aborted"
    assert probe_res["next_synthesis_focus"] == "forbidden_synthetic_probe_file_stop_now"
    assert any("synthetic probe file" in h for h in probe_res["diagnostic_hints"])

    # 3. Prover budget exhaustion short-circuits run_wp_on_function without invoking frama-c
    work_c = scratch_dir / "work" / "mod.c"
    work_c.parent.mkdir(parents=True, exist_ok=True)
    work_c.write_text("int foo(int x) { return x; }\n", encoding="utf-8")
    (scratch_dir / ".prover_budget.json").write_text(
        json.dumps(
            {
                "agent_id": "prove_foo",
                "function": "foo",
                "file": "mod.c",
                "max_retries": 2,
                "max_wp_invocations": 2,
                "max_wall_clock_s": 300,
                "wp_invocations": 2,
                "first_wp_at": 1000.0,
            }
        ),
        encoding="utf-8",
    )
    (scratch_dir / "wp_foo.json").write_text(
        json.dumps(
            {
                "status": "unproven_goals_remain",
                "total_goals": 10,
                "proven_count": 5,
                "unproven_count": 5,
                "unproven_goals": [{"kind": "precondition", "annotation": "\\freeable(p)"}],
                "wp_allocation_limitation": True,
            }
        ),
        encoding="utf-8",
    )
    cap_res = run_wp_on_function(c_file=work_c, fn_name="foo", out_dir=scratch_dir / "wp")
    assert cap_res["status"] == "unproven_goals_remain"
    assert cap_res["budget_exhausted"] is True
    assert cap_res["next_synthesis_focus"] == "budget_exhausted_write_result_json_now"
    assert cap_res["proven_count"] == 5 and cap_res["unproven_count"] == 5
    assert any("budget is exhausted" in h for h in cap_res["diagnostic_hints"])


def test_wp_fast_fail_on_internal_variadic(tmp_path: Path) -> None:
    work_c = tmp_path / "work" / "mod.c"
    work_c.parent.mkdir(parents=True, exist_ok=True)
    work_c.write_text("int f(int x) { return x; }\n", encoding="utf-8")

    # 1. Fast-fail via explicit wp_blockers parameter
    res1 = run_wp_on_function(
        c_file=work_c,
        fn_name="f",
        out_dir=tmp_path / "wp1",
        wp_blockers=["internal_variadic"],
    )
    assert res1["status"] == "wp_aborted"
    assert res1["next_synthesis_focus"] == "internal_variadic_unsupported_by_wp"
    assert res1["soundness"]["ok"] is False
    assert any("internal variadic function" in h for h in res1["diagnostic_hints"])
    assert res1["wp_blockers"] == ["internal_variadic"]

    # 2. Fast-fail via C source inspection of variadic function
    var_c = tmp_path / "work" / "var.c"
    var_c.write_text(
        "#include <stdarg.h>\nint my_printf(const char *fmt, ...) { return 0; }\n",
        encoding="utf-8",
    )
    res2 = run_wp_on_function(
        c_file=var_c,
        fn_name="my_printf",
        out_dir=tmp_path / "wp2",
    )
    assert res2["status"] == "wp_aborted"
    assert res2["next_synthesis_focus"] == "internal_variadic_unsupported_by_wp"
    assert any("internal variadic function" in h for h in res2["diagnostic_hints"])
    assert res2["wp_blockers"] == ["internal_variadic"]

    # 3. Fast-fail via callgraph_dag.json lookup
    dag_dir = tmp_path / "workspace" / "reports"
    dag_dir.mkdir(parents=True, exist_ok=True)
    import json

    (dag_dir / "callgraph_dag.json").write_text(
        json.dumps(
            {
                "functions": {
                    "dag_var_fn": {
                        "name": "dag_var_fn",
                        "file": "work/mod.c",
                        "wp_blockers": ["internal_variadic"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    res3 = run_wp_on_function(
        c_file=work_c,
        fn_name="dag_var_fn",
        out_dir=tmp_path / "workspace" / "wp",
    )
    assert res3["status"] == "wp_aborted"
    assert res3["next_synthesis_focus"] == "internal_variadic_unsupported_by_wp"
    assert any("internal variadic function" in h for h in res3["diagnostic_hints"])


def test_wp_hints_for_unframed_variadic_callees() -> None:
    # 1. Unframed variadic callee in unproven_goals_remain
    res = {
        "status": "unproven_goals_remain",
        "soundness": {"ok": True},
        "unframed_variadic_callees": ["minmea_scan"],
    }
    hints = derive_wp_diagnostic_hints(res, "Missing assigns clause on minmea_scan")
    assert any("unframed variadic callees (minmea_scan)" in h for h in hints)
    assert any("framing stub" in h for h in hints)

    # 2. Abort on call to variadic function in log
    res2 = {
        "status": "wp_aborted",
        "soundness": {
            "ok": False,
            "tier_a_aborts": ["Call to variadic function minmea_scan not supported"],
        },
    }
    hints2 = derive_wp_diagnostic_hints(res2)
    assert any("variadic function specifications" in h for h in hints2)
    assert any("framing stub" in h for h in hints2)

    # 3. Analysis error with unframed variadic callees
    res3 = {
        "status": "analysis_error",
        "reason": "kernel_crash",
        "unframed_variadic_callees": ["minmea_scan"],
    }
    hints3 = derive_wp_diagnostic_hints(res3)
    assert any("unframed variadic callees (minmea_scan)" in h for h in hints3)
