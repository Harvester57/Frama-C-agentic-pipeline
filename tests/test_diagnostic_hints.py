from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from run_eacsl_fuzz import derive_eacsl_diagnostic_hints  # noqa: E402
from run_wp_function import derive_wp_diagnostic_hints, run_wp_on_function, scan_wp_log_soundness  # noqa: E402
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


def test_wp_hints_unproven_lemma_forbids_ghost_function_and_points_to_stop_rule() -> None:
    res = {
        "status": "unsound_proof",
        "soundness": {
            "ok": False,
            "tier_a_aborts": [],
            "tier_b_unsound": ["1 unproven lemma(s) in scope"],
        },
        "unproven_goals": [
            {"kind": "lemma", "annotation": "sum_step: \\forall integer n; n >= 0 ==> n >= 0"},
        ],
    }
    hints = derive_wp_diagnostic_hints(res)
    lemma_hint = next((h for h in hints if "Unproven global ACSL lemma" in h), None)
    assert lemma_hint is not None, hints
    assert "sum_step" in lemma_hint
    assert "unsound" in lemma_hint.lower()
    assert "stalled_after_k_retries" in lemma_hint
    assert "proof_gap" in lemma_hint
    assert "inductive lemma required" in lemma_hint
    assert "/*@ ghost" not in lemma_hint
    assert "ghost C function" not in lemma_hint
    assert "replace global 'lemma'" not in lemma_hint


def test_wp_hints_indirect_call_not_triggered_by_valid_function_skipped_rte_only() -> None:
    # Frama-C 34 always prints these two Skipped RTE guards lines even on functions without indirect calls.
    log = (
        "[wp] Running WP plugin...\n"
        "[wp] Warning: Skipped RTE guards: unaligned pointers (\\aligned not supported)\n"
        "[wp] Warning: Skipped RTE guards: invalid function pointer calls (\\valid_function not supported)\n"
        "[wp] src/u.c:12: Warning: Accessing union fields with Typed model might be unsound\n"
    )
    soundness = scan_wp_log_soundness(log)
    assert soundness["ok"] is False
    assert soundness["skipped_rte_guards"]
    for status in ("unsound_proof", "wp_aborted"):
        res = {"status": status, "soundness": soundness, "wp_log_tail": log}
        hints = derive_wp_diagnostic_hints(res, log)
        assert not any("Indirect call through a function pointer" in h for h in hints), (status, hints)
        assert not any("//@ calls" in h for h in hints), (status, hints)


@pytest.mark.parametrize(
    ("status", "soundness", "log"),
    [
        (
            "unsound_proof",
            {"ok": False, "tier_a_aborts": [], "tier_b_unsound": [], "skipped_rte_guards": []},
            "[wp] src/cb.c:9: Warning: Missing 'calls' specification for indirect call\n",
        ),
        (
            "unsound_proof",
            {"ok": False, "tier_a_aborts": [], "tier_b_unsound": [], "skipped_rte_guards": []},
            "[wp] src/cb.c:9: Warning: Unknown callee for indirect call\n",
        ),
        (
            "unsound_proof",
            {
                "ok": False,
                "tier_a_aborts": [],
                "tier_b_unsound": [],
                "skipped_rte_guards": ["Through function pointer (*cb): cannot generate validity guard"],
            },
            "",
        ),
        (
            "wp_aborted",
            {
                "ok": False,
                "tier_a_aborts": ["[wp] user error: No 'calls' specification for function pointer call"],
                "tier_b_unsound": [],
                "skipped_rte_guards": [],
            },
            "",
        ),
        (
            "unsound_proof",
            {
                "ok": False,
                "tier_a_aborts": [],
                "tier_b_unsound": [
                    "indirect call present without '//@ calls' while \\valid_function RTE guards are skipped"
                ],
                "skipped_rte_guards": ["invalid function pointer calls (\\valid_function not supported)"],
            },
            "",
        ),
    ],
)
def test_wp_hints_indirect_call_triggered_by_actual_indirect_call_diagnostics(
    status: str, soundness: dict, log: str
) -> None:
    res = {"status": status, "soundness": soundness}
    hints = derive_wp_diagnostic_hints(res, log)
    assert any("Indirect call through a function pointer" in h for h in hints), hints


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


def test_wp_hints_loop_dependency_slice_names_the_inner_loop(tmp_path: Path) -> None:
    """InvWeaver-style: a preservation failure on an outer loop names the inner loop whose
    exit summary is the likely missing fact. Fail-open without facts."""
    import json

    import function_facts as ff

    facts_dir = tmp_path / "facts"
    facts_dir.mkdir()
    record = {
        "loops": [
            {
                "index": 0,
                "parent": None,
                "line": 5,
                "assumption_context": {"predecessors": ["entry"]},
                "obligation_context": {"successors": ["L1", "exit"], "inner_loops": ["L1"], "written": ["up"]},
            },
            {
                "index": 1,
                "parent": 0,
                "line": 8,
                "assumption_context": {"predecessors": ["L0"]},
                "obligation_context": {"successors": [], "inner_loops": [], "written": ["down"]},
            },
        ]
    }
    (facts_dir / "m.json").write_text(
        json.dumps({"schema": ff.FACTS_SCHEMA, "module": "m", "functions": {"m.c#bubble_sort": record}}),
        encoding="utf-8",
    )
    res = {
        "status": "unproven_goals_remain",
        "soundness": {"ok": True},
        "file": "m.c",
        "function": "bubble_sort",
        "unproven_by_bucket": {"step_b_loop_invariant": [{"kind": "loop_invariant", "annotation": "I_2"}]},
        "unproven_goals": [{"kind": "loop_invariant", "annotation": "I_2 preserved", "line": 6, "status": "Unknown"}],
    }
    hints = derive_wp_diagnostic_hints(res, facts_dir=facts_dir)
    assert any("Dependency slice" in h and "L8" in h and "L5" in h for h in hints), hints
    # Without facts the hint is absent but nothing breaks.
    assert not any("Dependency slice" in h for h in derive_wp_diagnostic_hints(res, facts_dir=tmp_path / "empty"))


def test_wp_hints_failure_kind_strategy_taxonomy() -> None:
    """SESpec Alg. 4: each unproven loop goal maps to a repair strategy by its WP name."""
    res = {
        "status": "unproven_goals_remain",
        "soundness": {"ok": True},
        "unproven_by_bucket": {"step_b_loop_invariant": [{"kind": "loop_invariant"}]},
        "unproven_goals": [
            {"kind": "loop_invariant", "annotation": "typed_f_loop_invariant_bound_established", "line": 4},
            {"kind": "loop_invariant", "annotation": "typed_f_loop_invariant_acc_preserved", "line": 4},
            {"kind": "loop_invariant", "annotation": "typed_f_loop_invariant_bad_established", "line": 4},
            {"kind": "loop_invariant", "annotation": "typed_f_loop_invariant_bad_preserved", "line": 4},
            {"kind": "loop_invariant", "annotation": "typed_f_loop_invariant_range", "line": 4},
            {"kind": "loop_variant", "annotation": "typed_f_loop_variant_decreases", "line": 4},
        ],
    }
    hints = derive_wp_diagnostic_hints(res)
    strat = next((h for h in hints if "Failure-kind repair strategy" in h), None)
    assert strat is not None, hints
    assert "weaken `typed_f_loop_invariant_bound`" in strat
    assert "adjust `typed_f_loop_invariant_acc`" in strat
    assert "regenerate `typed_f_loop_invariant_bad`" in strat and "BOTH" in strat
    assert "strengthen `typed_f_loop_invariant_range`" in strat
    assert "fix progress for `typed_f_loop_variant_decreases`" in strat
    assert "return -1" not in strat
    assert "if (" not in strat
    assert "progress guard" not in strat


def test_wp_hints_variant_strategy_never_recommends_c_code() -> None:
    res = {
        "status": "unproven_goals_remain",
        "soundness": {"ok": True},
        "unproven_by_bucket": {"step_b_loop_invariant": [{"kind": "loop_variant", "annotation": "n - i"}]},
        "unproven_goals": [
            {"kind": "loop_variant", "annotation": "typed_parse_loop_variant_decreases", "line": 14},
        ],
    }
    hints = derive_wp_diagnostic_hints(res)
    strat = next((h for h in hints if "Failure-kind repair strategy" in h), None)
    assert strat is not None, hints
    assert "fix progress for `typed_parse_loop_variant_decreases`" in strat
    assert "loop invariant" in strat and "requires" in strat and "proof_gap" in strat
    for forbidden in ("if (", "return -1", "consumed == 0", "progress guard"):
        assert all(forbidden not in h for h in hints), (forbidden, hints)


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


@pytest.mark.parametrize(
    "log_text",
    [
        (
            "[kernel] Parsing FRAMAC_SHARE/libc/stdlib.h (with preprocessing)\n"
            "--- Properties of Function 'free' ---\n"
            "[ Unknown ] Pre-condition 'freeable' (\"FRAMAC_SHARE/libc/stdlib.h\", line 502)\n"
            '[ Unknown ] Frees ("FRAMAC_SHARE/libc/stdlib.h", line 503)\n'
            "--- Properties of Function 'malloc' ---\n"
            '[ Unknown ] Allocates ("FRAMAC_SHARE/libc/stdlib.h", line 490)\n'
        ),
        "[wp] [Unknown] typed_parse_header_ensures_ok (Qed 1ms) (CVC5)\n/* helper frees nothing; allocates none */\n",
        "[wp] FRAMAC_SHARE/libc/stdlib.h:502: Warning: frees not yet supported (skipped)\n",
        "[wp] src/other.c:10: Warning: allocates not yet supported (skipped)\n",
        "[wp] src/parser.c:10: Warning: Ignoring allocates specification for other_fn\n",
    ],
)
def test_wp_hints_no_spurious_dynamic_allocation_hint_from_stdlib_log(log_text: str) -> None:
    res = {
        "status": "unproven_goals_remain",
        "function": "parse_header",
        "file": "workspace/work/src/parser.c",
        "soundness": {"ok": True, "tier_a_aborts": [], "tier_b_unsound": []},
        "unproven_by_bucket": {
            "step_c_contract_postcondition": [{"kind": "postcondition", "annotation": "\\result >= 0"}],
        },
        "unproven_goals": [
            {"kind": "postcondition", "annotation": "\\result >= 0"},
        ],
    }
    hints = derive_wp_diagnostic_hints(res, log_text)
    assert not any("dynamic allocation" in h for h in hints), hints


def test_wp_hints_ignored_non_alloc_spec_not_masked_by_stdlib_mentions() -> None:
    res = {
        "status": "unsound_proof",
        "function": "parse_header",
        "file": "src/parser.c",
        "soundness": {
            "ok": False,
            "tier_a_aborts": [],
            "tier_b_unsound": ["[wp] warning: Ignoring terminates specification for parse_header"],
        },
    }
    log = "--- Properties of Function 'free' ---\n[ Unknown ] Frees (\"FRAMAC_SHARE/libc/stdlib.h\", line 503)\n"
    hints = derive_wp_diagnostic_hints(res, log)
    assert any("Frama-C ignored part of a specification" in h for h in hints), hints
    assert not any("dynamic allocation" in h for h in hints), hints


@pytest.mark.parametrize(
    ("unproven_goals", "log_text"),
    [
        (
            [{"kind": "precondition of free", "annotation": "freeable: p == \\null || \\freeable(p)"}],
            "[wp] [Unknown] typed_make_buf_call_free_requires_freeable (Alt-Ergo)\n",
        ),
        (
            [{"kind": "postcondition", "annotation": "\\result != \\null"}],
            "[wp] src/alloc_wrap.c:12: Warning: allocates not yet supported (skipped)\n",
        ),
        (
            [{"kind": "postcondition", "annotation": "\\result != \\null"}],
            "[wp] src/alloc_wrap.h:4: Warning: Ignoring allocates specification for make_buf\n",
        ),
        (
            [{"kind": "postcondition", "annotation": "\\result != \\null"}],
            "[wp] warning: \\fresh not yet supported (skipped)\n",
        ),
    ],
)
def test_wp_hints_dynamic_allocation_hint_for_actual_alloc_goal_or_fn_warning(
    unproven_goals: list[dict], log_text: str
) -> None:
    res = {
        "status": "unproven_goals_remain",
        "function": "make_buf",
        "file": "workspace/work/src/alloc_wrap.c",
        "soundness": {"ok": True, "tier_a_aborts": [], "tier_b_unsound": []},
        "unproven_by_bucket": {"step_c_contract_postcondition": unproven_goals},
        "unproven_goals": unproven_goals,
    }
    hints = derive_wp_diagnostic_hints(res, log_text)
    assert any("dynamic allocation" in h and "stalled_after_k_retries" in h for h in hints), hints


@pytest.mark.unit
def test_wp_hints_analysis_error_with_partial_verdicts_and_cached_timeouts() -> None:
    # 1. With proved + timed out + cached timeouts: summarizes progress and advises raising --timeout.
    res_cached = {
        "status": "analysis_error",
        "reason": "timeout",
        "partial_verdicts": {
            "incomplete": True,
            "scheduled_vcs": 540,
            "completed_vcs": 316,
            "proved_vcs": 190,
            "timed_out_vcs": 126,
            "unknown_vcs": 0,
            "failed_vcs": 0,
            "cached_vcs": 94,
            "cached_timed_out_vcs": 94,
            "timed_out_goals": ["typed_recv_assert_1"],
            "unknown_goals": [],
            "failed_goals": [],
        },
    }
    hints_cached = derive_wp_diagnostic_hints(res_cached)
    assert len(hints_cached) == 1
    h = hints_cached[0]
    assert "WP stopped before writing its report (timeout)" in h
    assert "after deciding 316/540 VCs: 190 proved, 126 timed out (94 cached)" in h
    assert "raise --timeout" in h and "cached Timeout verdicts" in h
    assert "dedicated wall time" in h and "guardrail" in h
    assert "--prop" in h

    # 2. Frama-C 34 batch shape (proved_vcs == 0, uncached timeouts only): no cached-timeout advice.
    res_uncached = {
        "status": "analysis_error",
        "reason": "timeout",
        "partial_verdicts": {
            "incomplete": True,
            "scheduled_vcs": 22,
            "completed_vcs": 4,
            "proved_vcs": 0,
            "timed_out_vcs": 4,
            "unknown_vcs": 0,
            "failed_vcs": 0,
            "cached_vcs": 0,
            "cached_timed_out_vcs": 0,
            "timed_out_goals": ["typed_f_slow2"],
            "unknown_goals": [],
            "failed_goals": [],
        },
    }
    hints_uncached = derive_wp_diagnostic_hints(res_uncached)
    assert len(hints_uncached) == 1
    assert "with 22 VCs scheduled and 4 unproved VCs logged: 4 timed out" in hints_uncached[0]
    assert "cached Timeout" not in hints_uncached[0]
    assert "dedicated wall time" in hints_uncached[0]

    # 3. Scheduled VCs only (killed before any VC verdict printed).
    res_sched = {
        "status": "analysis_error",
        "reason": "oom_killed",
        "partial_verdicts": {
            "incomplete": True,
            "scheduled_vcs": 400,
            "completed_vcs": 0,
            "proved_vcs": 0,
            "timed_out_vcs": 0,
            "unknown_vcs": 0,
            "failed_vcs": 0,
            "cached_vcs": 0,
            "cached_timed_out_vcs": 0,
            "timed_out_goals": [],
            "unknown_goals": [],
            "failed_goals": [],
        },
    }
    hints_sched = derive_wp_diagnostic_hints(res_sched)
    assert len(hints_sched) == 1
    assert "after scheduling 400 VCs (no per-VC verdicts logged yet)" in hints_sched[0]

    # 4. Without partial_verdicts, falls back to the generic analysis_error hint.
    hints_plain = derive_wp_diagnostic_hints({"status": "analysis_error", "reason": "crashed"})
    assert len(hints_plain) == 1
    assert "Frama-C WP terminated before producing a report (reason: crashed)" in hints_plain[0]


@pytest.mark.unit
def test_wp_hints_checked_memory_model_functions_emitted_on_unproven_goals_remain() -> None:
    # 1. Default -wp-check-memory-model: soundness.ok is True and status is unproven_goals_remain.
    res_checked = {
        "status": "unproven_goals_remain",
        "soundness": {
            "ok": True,
            "tier_a_aborts": [],
            "tier_b_unsound": [],
            "checked_memory_model_functions": ["foo"],
        },
        "unproven_goals": [
            {"kind": "precondition", "annotation": r"Pre-condition for 'wp_typed': \separated(p, q)"},
        ],
    }
    hints_checked = derive_wp_diagnostic_hints(res_checked)
    sep_hints = [h for h in hints_checked if "separation hypotheses" in h]
    assert len(sep_hints) == 1, hints_checked
    assert r"\separated" in sep_hints[0]

    # 2. Log-only Memory model hypotheses on unproven_goals_remain also emits once.
    mm_log = "[wp] src/foo.c:10: Warning:\n  Memory model hypotheses for function 'foo':\n"
    res_log = {
        "status": "unproven_goals_remain",
        "soundness": {"ok": True, "tier_a_aborts": [], "tier_b_unsound": [], "checked_memory_model_functions": []},
    }
    hints_log = derive_wp_diagnostic_hints(res_log, mm_log)
    assert sum("separation hypotheses" in h for h in hints_log) == 1, hints_log

    # 3. Unsound + unproven_goals_remain does not duplicate the separation hint.
    res_both = {
        "status": "unproven_goals_remain",
        "soundness": {
            "ok": False,
            "tier_a_aborts": [],
            "tier_b_unsound": ["[wp] warning: Missing assigns clause"],
            "checked_memory_model_functions": ["foo"],
        },
    }
    hints_both = derive_wp_diagnostic_hints(res_both, mm_log)
    assert sum("separation hypotheses" in h for h in hints_both) == 1, hints_both

    # 4. Never emitted on all_proven, even when checked_memory_model_functions is populated.
    res_proven = {
        "status": "all_proven",
        "soundness": {"ok": True, "checked_memory_model_functions": ["foo"]},
    }
    assert derive_wp_diagnostic_hints(res_proven, mm_log) == []

    # 5. Not emitted on unproven_goals_remain without memory-model hypotheses.
    res_plain = {
        "status": "unproven_goals_remain",
        "soundness": {"ok": True, "checked_memory_model_functions": []},
    }
    assert not any("separation hypotheses" in h for h in derive_wp_diagnostic_hints(res_plain))


@pytest.mark.unit
@pytest.mark.parametrize(
    "error_line",
    [
        "[kernel:annot-error] foo.c:12: invalid implicit conversion from int to boolean",
        "[kernel:annot-error] foo.c:14: expected a predicate",
    ],
)
def test_wp_hints_bool_pred_syntax_hint_recommends_implications_not_iff(error_line: str) -> None:
    res = {
        "status": "acsl_syntax_error",
        "syntax_check": {
            "syntax_ok": False,
            "errors": [error_line],
            "raw_log": "",
        },
    }
    hints = derive_wp_diagnostic_hints(res)
    bool_hint = next((h for h in hints if "terms (values) from predicates" in h), None)
    assert bool_hint is not None, hints
    assert "'==>'" in bool_hint
    assert "(p1 ==> p2) && (p2 ==> p1)" in bool_hint
    assert all("<==>" not in h for h in hints), hints


@pytest.mark.unit
@pytest.mark.parametrize(
    ("unproven_goals", "log_text"),
    [
        ([{"kind": "assertion", "annotation": "p_end - p == 0 ==> p == p_end"}], ""),
        ([{"kind": "loop_invariant", "annotation": "p != p_end ==> p_end - p > 0"}], ""),
        ([{"kind": "requires", "annotation": r"\base_addr(p) == \base_addr(p_end)"}], ""),
        ([], r"[wp] Goal typed_f_assert: Unknown (\base_addr(p) == \base_addr(p_end))"),
    ],
)
def test_wp_hints_pointer_walk_recommends_ghost_index_not_ptr_anchor(unproven_goals: list[dict], log_text: str) -> None:
    res = {
        "status": "unproven_goals_remain",
        "soundness": {"ok": True},
        "unproven_goals": unproven_goals,
    }
    hints = derive_wp_diagnostic_hints(res, log_text)
    ptr_hint = next((h for h in hints if "Pointer-walk anchoring" in h), None)
    assert ptr_hint is not None, hints
    for expected in (
        "/*@ ghost size_t idx = 0; */",
        "loop invariant idx_bound: 0 <= idx <= p_end - base;",
        "loop invariant ptr_idx: p == base + idx;",
        r"requires \base_addr(base) == \base_addr(p_end);",
        "/*@ ghost idx++; */",
        r"ensures res_base: \result != \null ==> \base_addr(\result) == \base_addr(\old(buf));",
        r"ensures res_bound: \result != \null ==> 0 <= \result - \old(buf) <= \old(buf_end) - \old(buf);",
        "/*@ ghost idx = (size_t)(p - buf); */",
    ):
        assert expected in ptr_hint, expected
    for forbidden in (
        "ptr_anchor",
        "end_anchor",
        "res_anchor",
        "ofs1 - ofs2",
        r"p == \at(p, Pre) + (p - \at(p, Pre))",
        r"p_end == \at(p, Pre) + (p_end - \at(p, Pre))",
        "Pointer-difference equality bridge",
    ):
        assert all(forbidden not in h for h in hints), (forbidden, hints)


@pytest.mark.unit
@pytest.mark.parametrize(
    "anomaly_line",
    [
        '[wp] Warning: Goal Property: running prover Z3:4.13.3 failed ([Why3 Error] anomaly: Invalid_argument("missing free variable"))',
        '[wp] Warning: Goal Property: running prover Alt-Ergo failed ([Why3 Error] anomaly: Invalid_argument("unbound variable in of_term"))',
    ],
)
def test_wp_hints_why3_anomaly_emits_backend_hint_without_valid_p(anomaly_line: str) -> None:
    res = {
        "status": "wp_aborted",
        "wp_why3_anomaly": True,
        "soundness": {"ok": False, "tier_a_aborts": [anomaly_line], "tier_b_unsound": []},
        "unproven_goals": [{"kind": "mem_access", "annotation": r"\valid_read(&b->header)"}],
        "unproven_by_bucket": {"step_c_rte_obligation": [{"kind": "mem_access"}]},
    }
    hints = derive_wp_diagnostic_hints(res, anomaly_line)
    assert any("Why3 backend anomaly" in h for h in hints), hints
    assert all(r"requires \valid(p)" not in h for h in hints), hints


@pytest.mark.unit
def test_wp_hints_unproven_global_lemmas_named_from_soundness() -> None:
    res = {
        "status": "unsound_proof",
        "soundness": {
            "ok": False,
            "tier_a_aborts": [],
            "tier_b_unsound": [
                "Unproven lemma(s) in scope (unprovable, provable): -wp-fct does not prove global lemmas yet WP assumes them as hypotheses"
            ],
            "unproven_global_lemmas": ["unprovable", "provable"],
        },
        "unproven_goals": [],
    }
    hints = derive_wp_diagnostic_hints(res)
    lemma_hint = next((h for h in hints if "Unproven global ACSL lemma in scope" in h), None)
    assert lemma_hint is not None, hints
    assert "(unprovable, provable)" in lemma_hint
    assert "inductive lemma required" in lemma_hint
