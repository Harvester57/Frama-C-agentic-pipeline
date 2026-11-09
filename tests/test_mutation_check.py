"""Mutation-based specification quality (scripts/mutation_check.py): spec mutants
(completeness, C@All-style), implementation mutants (REJECT-style precision),
run-dir driver, report section, and the prover/spec-limited classification."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import pytest  # noqa: E402

import generate_report as gr  # noqa: E402
import mutation_check as mc  # noqa: E402
from acsl_ast import _find_body_brace_offset  # noqa: E402

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


@pytest.fixture(autouse=True)
def _stub_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every test starts with FRAMAC_MUTATION_STUB unset (default on)."""
    monkeypatch.delenv("FRAMAC_MUTATION_STUB", raising=False)


def _unproven(*goals: tuple[str, str]) -> dict:
    return {
        "status": "unproven_goals_remain",
        "unproven_goals": [{"kind": kind, "status": status} for kind, status in goals],
    }


def test_rejection_and_equivalence_classification() -> None:
    assert mc._is_rejection(_unproven(("ensures", "Invalid"))) == (True, "invalid")
    assert mc._is_rejection(_unproven(("ensures", "Invalid under hyp"))) == (True, "invalid")
    # A false postcondition usually comes back Unknown: that is a rejection too.
    assert mc._is_rejection(_unproven(("ensures", "Unknown"))) == (True, "unknown")
    assert mc._is_rejection(_unproven(("ensures", "Unknown"), ("behavior", "Invalid"))) == (True, "invalid")
    assert mc._is_rejection(_unproven(("rte_mem_access", "Invalid"), ("rte", "Unknown"))) == (False, "rte_only")
    assert mc._is_rejection({"status": "all_proven"}) == (False, "proved")
    for status in ("error", "analysis_error", "acsl_syntax_error", "wp_aborted", None):
        assert mc._is_rejection({"status": status}) == (False, "not_applicable"), status
    assert mc._is_equivalent({"status": "all_proven"}) is True
    assert mc._is_equivalent({"status": "unproven_goals_remain"}) is False


def _stub(src: str) -> tuple[str, str] | None:
    return mc.trivial_stub_mutant(src, _find_body_brace_offset(src))


def test_trivial_stub_mutant_by_return_type() -> None:
    noop = ("trivial-noop-body", "{ }")
    zero = ("trivial-zero-body", "{ return 0; }")
    assert _stub("void f(int *p) { *p = 1; }") == noop
    assert _stub("static void f(void) { }") == noop
    assert _stub("static inline int g(void) { return 3; }") == zero
    assert _stub('char *h(void) { return "x"; }') == zero
    assert _stub("void *v(void) { return 0; }") == zero
    assert _stub("unsigned long long u(int x) { return x; }") == zero
    assert _stub("_Bool b(int x) { return x > 0; }") == zero
    assert _stub("struct s k(void) { struct s r = {0}; return r; }") is None
    assert _stub("union u k2(void) { union u r; return r; }") is None
    assert _stub("struct s *m(void) { return 0; }") == zero
    assert _stub("__attribute__((nonnull(1))) int a(int *p) { return *p; }") == zero
    assert _stub("extern int __attribute__((pure)) a2(const int *p) { return *p; }") == zero
    # The span starts with the contract; its ACSL tokens are not part of the return type.
    assert _stub("/*@ requires \\valid(p); assigns *p; ensures *p == 0; */\nvoid z(int *p) { *p = 0; }") == noop
    assert _stub("//@ ensures \\result == 1;\nint one(void) { return 1; }") == zero
    assert mc.trivial_stub_mutant("int f(void) { }", None) is None
    assert mc.trivial_stub_mutant("f(void) { }", 8) is None  # implicit int: no return type to read


VOID_SRC = """\
/*@
  requires \\valid(p);
  assigns *p;
*/
void clamp(int *p) {
  if (*p < 0) *p = 0;
}
"""

ADD_SRC = """\
/*@ ensures \\result == a + b; */
int add(int a, int b) {
  return a + b;
}
"""


def _write(tmp_path: Path, name: str, src: str) -> Path:
    path = tmp_path / name
    path.write_text(src, encoding="utf-8")
    return path


def test_check_function_assigns_only_void_accepts_the_stub(tmp_path: Path) -> None:
    c_file = _write(tmp_path, "c.c", VOID_SRC)
    seen: list[str] = []

    def runner(c_file, fn, out_dir, cppflags="-I."):
        seen.append(Path(c_file).read_text(encoding="utf-8"))
        return {"status": "all_proven"}  # assigns goals are trivially valid for a body that writes nothing

    f = mc.check_function(c_file, "clamp", "-I.", tmp_path / "out", wp_runner=runner)
    assert f["trivial_body_rejected"] is False
    stub = next(d for d in f["details"] if d["mutant"] == "trivial-noop-body")
    assert stub == {
        "mutant": "trivial-noop-body",
        "kind": "impl",
        "rejected": False,
        "verdict": "proved",
        "status": "all_proven",
    }
    assert any("void clamp(int *p) { }" in text for text in seen)
    assert all("verdict" in d for d in f["details"])
    # The stub comes first and does not count against max_mutants.
    f1 = mc.check_function(c_file, "clamp", "-I.", tmp_path / "out", wp_runner=runner, max_mutants=1)
    assert [d["mutant"] for d in f1["details"] if d["kind"] == "impl"] == ["trivial-noop-body", "flip-<"]


def test_check_function_stub_rejected_with_unknown_verdict(tmp_path: Path) -> None:
    c_file = _write(tmp_path, "a.c", ADD_SRC)

    def runner(c_file, fn, out_dir, cppflags="-I."):
        if "{ return 0; }" in Path(c_file).read_text(encoding="utf-8"):
            return _unproven(("ensures", "Unknown"))
        return {"status": "all_proven"}

    f = mc.check_function(c_file, "add", "-I.", tmp_path / "out", wp_runner=runner)
    assert f["trivial_body_rejected"] is True
    stub = next(d for d in f["details"] if d["mutant"] == "trivial-zero-body")
    assert stub["rejected"] is True and stub["verdict"] == "unknown"
    # No relational operator and no constant return: the stub is the only impl mutant,
    # so this function now gets a precision at all.
    assert f["impl_mutants"] == 1 and f["rejected"] == 1 and f["precision"] == 1.0


def test_check_function_failed_runs_are_not_applicable(tmp_path: Path) -> None:
    c_file = _write(tmp_path, "m.c", SRC)

    def runner(c_file, fn, out_dir, cppflags="-I."):
        text = Path(c_file).read_text(encoding="utf-8")
        if "{ return 0; }" in text:
            raise RuntimeError("frama-c: parse error")
        if "ensures \\true;" in text:
            return {"status": "analysis_error"}
        if "i <= n" in text:
            return _unproven(("ensures", "Invalid"))
        return _unproven(("rte_signed_overflow", "Unknown"))

    f = mc.check_function(c_file, "sum", "-I.", tmp_path / "out", wp_runner=runner)
    assert f["trivial_body_rejected"] is None
    assert f["impl_not_applicable"] == 1 and f["spec_not_applicable"] == 1
    stub = next(d for d in f["details"] if d["mutant"] == "trivial-zero-body")
    assert stub["verdict"] == "not_applicable" and stub["rejected"] is False
    impl = [d for d in f["details"] if d["kind"] == "impl" and d["verdict"] != "not_applicable"]
    assert f["impl_mutants"] == len(impl) and f["rejected"] == 1
    assert f["precision"] == round(1 / len(impl), 4)
    spec_na = next(d for d in f["details"] if d["mutant"] == "ensures-true")
    assert spec_na["verdict"] == "not_applicable" and spec_na["equivalent"] is False


def test_struct_return_records_a_not_applicable_stub(tmp_path: Path) -> None:
    src = (
        "struct s { int x; };\n/*@ ensures \\result.x == 0; */\nstruct s mk(void) { struct s r; r.x = 0; return r; }\n"
    )
    c_file = _write(tmp_path, "s.c", src)
    calls: list[str] = []

    def runner(c_file, fn, out_dir, cppflags="-I."):
        calls.append(Path(c_file).read_text(encoding="utf-8"))
        return {"status": "all_proven"}

    f = mc.check_function(c_file, "mk", "-I.", tmp_path / "out", wp_runner=runner)
    assert f["trivial_body_rejected"] is None
    stub = next(d for d in f["details"] if d["mutant"] == "trivial-stub")
    assert stub["verdict"] == "not_applicable"
    assert f["impl_not_applicable"] == 0  # no WP run for it
    assert not any("{ return 0; }" in text for text in calls)


def test_stub_switch_off_drops_only_the_stub(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FRAMAC_MUTATION_STUB", "OFF")
    c_file = _write(tmp_path, "a.c", ADD_SRC)
    f = mc.check_function(
        c_file, "add", "-I.", tmp_path / "out", wp_runner=lambda *a, **k: _unproven(("ensures", "Unknown"))
    )
    assert "trivial_body_rejected" not in f
    assert not any(d["mutant"].startswith("trivial") for d in f["details"])
    assert f["impl_mutants"] == 0 and f["precision"] is None
    # The corrected criterion still applies to the other mutants.
    v = mc.check_function(
        _write(tmp_path, "c.c", VOID_SRC),
        "clamp",
        "-I.",
        tmp_path / "o2",
        wp_runner=lambda *a, **k: _unproven(("ensures", "Unknown")),
    )
    assert v["rejected"] == v["impl_mutants"] == 1
    run_dir = _fake_run(tmp_path)
    totals = mc.run_mutation_check(run_dir, wp_runner=lambda *a, **k: {"status": "all_proven"})["totals"]
    assert "trivial_body_checked" not in totals


def test_run_mutation_check_trivial_body_totals(tmp_path: Path) -> None:
    run_dir = _fake_run(tmp_path)
    work = run_dir / "workspace" / "work"
    wp_dir = run_dir / "workspace" / "reports" / "wp"
    (work / "c.c").write_text(VOID_SRC, encoding="utf-8")
    (work / "a.c").write_text(ADD_SRC, encoding="utf-8")
    for fn, name in (("clamp", "c.c"), ("add", "a.c")):
        (wp_dir / f"{fn}.json").write_text(
            json.dumps({"status": "all_proven", "function": fn, "file": name}), encoding="utf-8"
        )

    def runner(c_file, fn, out_dir, cppflags="-I."):
        text = Path(c_file).read_text(encoding="utf-8")
        if fn == "clamp":
            return {"status": "all_proven"}
        if "{ return 0; }" in text and fn == "add":
            return _unproven(("ensures", "Unknown"))
        if "{ return 0; }" in text:
            return {"status": "analysis_error"}  # sum: stub not applicable
        return _unproven(("ensures", "Invalid"))

    totals = mc.run_mutation_check(run_dir, wp_runner=runner)["totals"]
    assert totals["functions"] == 3
    assert totals["trivial_body_checked"] == 2
    assert totals["trivial_body_accepted"] == 1
    assert totals["trivial_body_accepted_functions"] == ["clamp"]
    assert totals["impl_not_applicable"] == 1


def test_default_runner_requests_counter_examples(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    seen: dict = {}

    def fake(c_file, fn_name, out_dir, cppflags="-I.", counter_examples=False):
        seen["counter_examples"] = counter_examples
        return {"status": "all_proven"}

    monkeypatch.setattr(mc.run_wp_function, "run_wp_on_function", fake)
    mc._default_runner()(tmp_path / "x.c", "f", tmp_path, cppflags="-I.")
    assert seen["counter_examples"] is True

    def old(c_file, fn_name, out_dir, cppflags="-I."):
        return {"status": "all_proven"}

    monkeypatch.setattr(mc.run_wp_function, "run_wp_on_function", old)
    assert mc._default_runner() is old


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
        if (
            "ensures \\true;" in text
            or "*out < n" in text
            or "ensures *out >= 0;" not in text
            or "ensures *out <= n;" not in text
        ):
            return {"status": "unproven_goals_remain"}  # spec mutant not equivalent
        if "i <= n" in text or "return 1;" in text or "*out = acc;" not in text:  # last: the trivial stub
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
        "meta": {
            "run_id": "r",
            "repo": "x",
            "target": "t",
            "source_ref": {"vcs": "git", "commit": "c"},
            "run_status": "complete",
            "profile": "default",
            "scope_paths": [],
            "budget": None,
            "sandbox": {"outer": "o", "inner": "i"},
            "prior_runs": [],
        },
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
