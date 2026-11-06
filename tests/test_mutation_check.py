"""Mutation-based specification quality (scripts/mutation_check.py): spec mutants
(completeness, C@All-style), implementation mutants (REJECT-style precision),
run-dir driver, report section, and the prover/spec-limited classification."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import generate_report as gr  # noqa: E402
import mutation_check as mc  # noqa: E402

SRC = """\
/*@
  requires n >= 0;
  requires \\valid_read(buf + (0 .. n - 1));
  assigns *out;
  ensures *out >= 0;
  ensures *out <= n;
*/
int sum(const int *buf, int n, int *out) {
  int i, acc = 0;
  for (i = 0; i < n; i++) acc += buf[i];
  *out = acc;
  return 0;
}
"""


def test_spec_mutants_drop_and_weaken_ensures() -> None:
    contract = "/*@ requires n >= 0; ensures *out >= 0; ensures *out <= n; */"
    mutants = dict(mc.spec_mutants(contract, 6))
    assert any("ensures *out >= 0;" not in m for m in mutants.values())  # dropped clause
    assert any("*out < n" in m for m in mutants.values())  # weakened <=
    assert "ensures-true" in mutants and "true;" in mutants["ensures-true"]
    assert len(mutants) <= 6


def test_impl_mutants_flip_operators_and_return_constants() -> None:
    body = "int f(int n) { for (int i = 0; i < n; i++) ; return 0; }"
    mutants = dict(mc.impl_mutants(body, 6))
    assert any("i <= n" in m for m in mutants.values())
    assert any("return 1;" in m for m in mutants.values())
    assert len(mutants) <= 6


def test_rejection_and_equivalence_classification() -> None:
    assert mc._is_rejection({"unproven_goals": [{"kind": "ensures", "status": "Invalid"}]}) is True
    assert mc._is_rejection({"unproven_goals": [{"kind": "rte", "status": "Invalid"}]}) is False
    assert mc._is_rejection({"unproven_goals": [{"kind": "ensures", "status": "Unknown"}]}) is False
    assert mc._is_equivalent({"status": "all_proven"}) is True
    assert mc._is_equivalent({"status": "unproven_goals_remain"}) is False


def test_classify_open_unit_prover_vs_spec_limited() -> None:
    assert mc.classify_open_unit({"status": "analysis_error"}) == "prover_limited"
    assert mc.classify_open_unit({"wp_allocation_limitation": True}) == "prover_limited"
    assert mc.classify_open_unit({"unproven_goals": [{"status": "Timeout"}]}) == "prover_limited"
    assert mc.classify_open_unit({"frame_summary": {"missing_assigns_warning": True}}) == "spec_limited"
    assert mc.classify_open_unit({"unproven_goals": [{"kind": "ensures", "status": "Unknown"}]}) == "spec_limited"
    assert mc.classify_open_unit(None) == "unknown"


def _fake_run(tmp_path: Path) -> Path:
    run_dir = tmp_path / "run"
    (run_dir / "workspace" / "work").mkdir(parents=True)
    (run_dir / "workspace" / "work" / "m.c").write_text(SRC, encoding="utf-8")
    wp_dir = run_dir / "workspace" / "reports" / "wp"
    wp_dir.mkdir(parents=True)
    (wp_dir / "sum.json").write_text(
        json.dumps({"status": "all_proven", "function": "sum", "file": "m.c"}), encoding="utf-8"
    )
    return run_dir


def test_run_mutation_check_with_injected_runner(tmp_path: Path) -> None:
    run_dir = _fake_run(tmp_path)
    calls = []

    def fake_runner(c_file, fn, out_dir, cppflags="-I."):
        calls.append((c_file.name, fn))
        text = Path(c_file).read_text(encoding="utf-8")
        if "ensures \\true;" in text or "*out < n" in text or "ensures *out >= 0;" not in text or "ensures *out <= n;" not in text:
            return {"status": "unproven_goals_remain"}  # spec mutant not equivalent
        if "i <= n" in text or "return 1;" in text:
            return {"status": "unproven_goals_remain", "unproven_goals": [{"kind": "ensures", "status": "Invalid"}]}
        return {"status": "all_proven"}

    doc = mc.run_mutation_check(run_dir, wp_runner=fake_runner)
    assert doc["totals"]["functions"] == 1
    f = doc["functions"]["sum"]
    assert f["spec_mutants"] > 0 and f["equivalent"] == 0 and f["completeness"] == 1.0
    assert f["impl_mutants"] > 0 and f["rejected"] == f["impl_mutants"] and f["precision"] == 1.0
    assert len(calls) == f["spec_mutants"] + f["impl_mutants"]
    out = run_dir / "workspace" / "reports" / "mutation.json"
    assert json.loads(out.read_text(encoding="utf-8"))["schema"] == mc.MUTATION_SCHEMA
    assert mc.summarize_mutation(out)["functions"] == 1


def test_run_mutation_check_skips_non_proven(tmp_path: Path) -> None:
    run_dir = _fake_run(tmp_path)
    (run_dir / "workspace" / "reports" / "wp" / "sum.json").write_text(
        json.dumps({"status": "unproven_goals_remain", "function": "sum", "file": "m.c"}), encoding="utf-8"
    )
    doc = mc.run_mutation_check(run_dir, wp_runner=lambda *a, **k: {"status": "all_proven"})
    assert doc["totals"]["functions"] == 0


def test_report_spec_quality_section(tmp_path: Path) -> None:
    run_dir = _fake_run(tmp_path)
    doc = mc.run_mutation_check(
        run_dir,
        wp_runner=lambda c, fn, out, cppflags="-I.": {"status": "all_proven"},
    )
    data = {
        "run_dir": run_dir,
        "meta": {"run_id": "r", "repo": "x", "target": "t", "source_ref": {"vcs": "git", "commit": "c"},
                 "run_status": "complete", "profile": "default", "scope_paths": [], "budget": None,
                 "sandbox": {"outer": "o", "inner": "i"}, "prior_runs": []},
        "ledger": [
            {"coverage_id": "m.c#sum::rte", "status": "open", "function": "sum", "assumptions": []},
            {"coverage_id": "m.c#g::rte", "status": "open", "function": "g", "assumptions": []},
        ],
        "findings": [],
        "candidates": [],
        "coverage": [],
        "mutation": doc,
    }
    (run_dir / "workspace" / "reports" / "wp" / "g.json").write_text(
        json.dumps({"status": "analysis_error", "function": "g"}), encoding="utf-8"
    )
    section = "\n".join(gr.spec_quality_section(data))
    assert "Specification quality (mutation check)" in section
    assert "completeness" in section and "precision" in section
    assert "prover_limited" in section and "spec_limited" in section
    # No mutation report -> only the duality split (or nothing when no open units).
    data2 = {**data, "mutation": None}
    section2 = "\n".join(gr.spec_quality_section(data2))
    assert "mutation check" not in section2 and "prover_limited" in section2
