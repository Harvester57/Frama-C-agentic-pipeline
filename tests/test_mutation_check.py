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
from acsl_ast import (  # noqa: E402
    Span,
    _find_body_brace_offset,
    function_declaration_spans,
    locate_function_span,
)

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


def test_impl_mutants_flip_only_whole_relational_operators() -> None:
    # libmnl A/B: plain substring flips produced `attr->=nla_len`, `<==` and `>==`, which WP cannot parse.
    body = '{ if ((int)attr->nla_len <= len && (x >> 2) > 1) return 0; /* a < b */ s = "p<q"; return y >= z; }'
    mutants = dict(mc.impl_mutants(body, 6))
    assert mutants["flip-<="] == body.replace("nla_len <= len", "nla_len < len")
    assert mutants["flip->="] == body.replace("y >= z", "y > z")
    assert mutants["flip->"] == body.replace(") > 1)", ") >= 1)")
    assert "flip-<" not in mutants  # the only `<` is in a comment and a string
    for text in mutants.values():
        assert "->" in text and ">>" in text and "<==" not in text and ">==" not in text
    assert mc.impl_mutants("{ return attr->nla_len; }", 6) == []


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
        text = Path(c_file).read_text(encoding="utf-8")
        if any(body in text for body in ("{ return 0; }", "{ return a; }", "{ return b; }")):
            return _unproven(("ensures", "Unknown"))
        return {"status": "all_proven"}

    f = mc.check_function(c_file, "add", "-I.", tmp_path / "out", wp_runner=runner)
    assert f["trivial_body_rejected"] is True
    by_name = {d["mutant"]: d for d in f["details"] if d["kind"] == "impl"}
    assert list(by_name) == ["trivial-zero-body", "trivial-param-a-body", "trivial-param-b-body"]
    for name in ("trivial-zero-body", "trivial-param-a-body", "trivial-param-b-body"):
        assert by_name[name]["rejected"] is True and by_name[name]["verdict"] == "unknown"
    # No relational operator and no constant return: the 3 trivial stubs are the only impl mutants,
    # so this function now gets a precision at all.
    assert f["impl_mutants"] == 3 and f["rejected"] == 3 and f["precision"] == 1.0


def test_check_function_failed_runs_are_not_applicable(tmp_path: Path) -> None:
    c_file = _write(tmp_path, "m.c", SRC)

    def runner(c_file, fn, out_dir, cppflags="-I."):
        text = Path(c_file).read_text(encoding="utf-8")
        if "{ return 0; }" in text or "{ return n; }" in text:
            raise RuntimeError("frama-c: parse error")
        if "ensures \\true;" in text:
            return {"status": "analysis_error"}
        if "i <= n" in text:
            return _unproven(("ensures", "Invalid"))
        return _unproven(("rte_signed_overflow", "Unknown"))

    f = mc.check_function(c_file, "sum", "-I.", tmp_path / "out", wp_runner=runner)
    assert f["trivial_body_rejected"] is None
    assert f["impl_not_applicable"] == 2 and f["spec_not_applicable"] == 1
    for stub_name in ("trivial-zero-body", "trivial-param-n-body"):
        stub = next(d for d in f["details"] if d["mutant"] == stub_name)
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
        if fn == "clamp":
            return {"status": "all_proven"}
        if fn == "add" and "wp-impl-trivial-" in Path(out_dir).name:
            return _unproven(("ensures", "Unknown"))
        if fn == "sum" and "wp-impl-trivial-" in Path(out_dir).name:
            return {"status": "analysis_error"}  # sum: stubs not applicable
        return _unproven(("ensures", "Invalid"))

    totals = mc.run_mutation_check(run_dir, wp_runner=runner)["totals"]
    assert totals["functions"] == 3
    assert totals["trivial_body_checked"] == 2
    assert totals["trivial_body_accepted"] == 1
    assert totals["trivial_body_accepted_functions"] == ["clamp"]
    assert totals["impl_not_applicable"] == 2


def test_default_runner_requests_no_counter_examples(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # Nothing reads the models, and since F5 each failing mutant would pay a second full WP pass for them.
    seen: dict = {}

    def fake(c_file, fn_name, out_dir, **kwargs):
        seen.update(kwargs)
        return {"status": "all_proven"}

    monkeypatch.setattr(mc.run_wp_function, "run_wp_on_function", fake)
    mc._default_runner()(tmp_path / "x.c", "f", tmp_path, cppflags="-I.")
    assert seen == {"cppflags": "-I."}
    mc._default_runner({"wp_model": "Bytes"})(tmp_path / "x.c", "f", tmp_path, cppflags="-I.")
    assert seen["wp_model"] == "Bytes" and not seen.get("counter_examples")


@pytest.mark.parametrize(
    "flags,options",
    [
        (["--no-warn-unsigned-downcast"], {"warn_unsigned_downcast": False}),
        (
            ["--no-warn-unsigned", "--wrap-code-lines=1,4", "--wp-model", "Bytes"],
            {"unsigned_reduced": True, "wp_model": "Bytes"},
        ),
        (
            ["--no-warn-invalid-pointer", "--wp-model=Typed+ref+int"],
            {"warn_invalid_pointer": False, "wp_model": "Typed+ref+int"},
        ),
        (["--no-warn-unsigned", "--waive-signed-downcast"], {"unsigned_reduced": True, "warn_signed_downcast": False}),
    ],
)
def test_proof_flags_map_onto_the_runner_options(flags, options) -> None:
    got, ignored = mc.wp_options_from_flags(flags)
    assert got == options
    assert ignored == [f for f in flags if f.startswith("--wrap-code-lines")]


def _proof_report(**extra) -> dict:
    return {"status": "all_proven", "function": "sum", "file": "m.c", **extra}


def test_mutants_replay_the_model_and_checks_the_proof_used(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    run_dir = _fake_run(tmp_path)
    report = _proof_report(
        wp_model="Bytes",
        soundness={"ok": True, "reduced_checks": ["-warn-unsigned-overflow / -warn-unsigned-downcast OFF"]},
        unsigned_wraps={"declared_code_lines": [2]},
    )
    (run_dir / "workspace" / "reports" / "wp" / "sum.json").write_text(json.dumps(report), encoding="utf-8")
    seen: list[dict] = []

    def fake(c_file, fn_name, out_dir, **kwargs):
        seen.append(kwargs)
        return {"status": "all_proven"}

    monkeypatch.setattr(mc.run_wp_function, "run_wp_on_function", fake)
    doc = mc.run_mutation_check(run_dir)
    assert seen, "the default runner ran the mutants"
    for kwargs in seen:
        assert kwargs["wp_model"] == "Bytes" and kwargs["unsigned_reduced"] is True
        assert not kwargs.get("counter_examples")
    f = doc["functions"]["sum"]
    assert f["wp_options"] == {"unsigned_reduced": True, "wp_model": "Bytes"}
    assert f["wp_flags"] == ["--no-warn-unsigned", "--wrap-code-lines=2", "--wp-model", "Bytes"]


def test_mutants_of_a_default_proof_keep_the_parent_check_flags(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen: list[dict] = []

    def fake(c_file, fn_name, out_dir, **kwargs):
        seen.append(kwargs)
        return {"status": "all_proven"}

    monkeypatch.setattr(mc.run_wp_function, "run_wp_on_function", fake)
    mc.run_mutation_check(_fake_run(tmp_path))
    assert seen and all(k == {"cppflags": "-I.", "warn_unsigned_downcast": False} for k in seen)


@pytest.mark.parametrize(
    "report,expected",
    [
        ({"status": "analysis_error"}, "prover_limited"),
        ({"status": "analysis_error", "reason": "timeout"}, "prover_limited"),
        ({"status": "analysis_error", "reason": "insufficient_memory"}, "prover_limited"),
        ({"status": "analysis_error", "reason": "preprocessing_failed: m.c:1:10: fatal error: x.h"}, "unknown"),
        ({"status": "analysis_error", "reason": "unsigned_wrap_check_failed"}, "unknown"),
    ],
)
def test_classify_open_unit_tells_setup_errors_from_prover_limits(report, expected) -> None:
    # A missing header or a failed wrap check says nothing about the prover or the contract.
    assert mc.classify_open_unit(report) == expected


def test_classify_open_unit_prover_vs_spec_limited() -> None:
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


def _ledger_run(tmp_path: Path, module: str | None) -> Path:
    run_dir = _fake_run(tmp_path)
    units = [{"file": "m.c", "function": "sum", "module": module}] if module else []
    (run_dir / "coverage-ledger.json").write_text(json.dumps(units), encoding="utf-8")
    return run_dir


class _FakePlan:
    def wp_cppflags_for(self, module):
        return (["-Iinclude", "-DX=1"], "") if module == "m" else (None, "no sidecar")


def test_run_mutation_check_uses_the_modules_wp_cppflags(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # libmnl A/B: the hard-coded `-I.` made every mutant fail on `libmnl/libmnl.h: No such file or directory`.
    import pipeline_make

    monkeypatch.setattr(pipeline_make, "build_plan", lambda run_dir: _FakePlan())
    seen: set[str] = set()

    def runner(c_file, fn, out_dir, cppflags="-I."):
        seen.add(cppflags)
        return {"status": "all_proven"}

    doc = mc.run_mutation_check(_ledger_run(tmp_path, "m"), wp_runner=runner)
    assert seen == {"-Iinclude -DX=1"}
    assert doc["functions"]["sum"]["cppflags_source"] == "module m"


def test_run_mutation_check_skips_a_function_whose_flags_are_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import pipeline_make

    monkeypatch.setattr(pipeline_make, "build_plan", lambda run_dir: _FakePlan())
    doc = mc.run_mutation_check(_ledger_run(tmp_path, "other"), wp_runner=lambda *a, **k: {"status": "all_proven"})
    assert doc["functions"] == {}
    assert doc["skipped"] == [{"function": "sum", "file": "m.c", "reason": "module other: no sidecar"}]


def test_run_mutation_check_without_a_ledger_keeps_the_default_flags(tmp_path: Path) -> None:
    seen: set[str] = set()

    def runner(c_file, fn, out_dir, cppflags="-I."):
        seen.add(cppflags)
        return {"status": "all_proven"}

    doc = mc.run_mutation_check(_fake_run(tmp_path), wp_runner=runner)
    assert seen == {"-I."}
    assert doc["functions"]["sum"]["cppflags_source"].startswith("default")


def _cpp_failure() -> dict:
    return {
        "status": "acsl_syntax_error",
        "syntax_check": {
            "syntax_ok": False,
            "errors": [
                "m.c:1:10: fatal error: libmnl/libmnl.h: No such file or directory",
                "[kernel] User Error: failed to run: gcc -E -C -I. m.c",
            ],
        },
    }


def test_a_preprocessing_failure_is_named_and_leaves_the_function_unscored(tmp_path: Path) -> None:
    c_file = _write(tmp_path, "m.c", SRC)
    f = mc.check_function(c_file, "sum", "-I.", tmp_path / "out", wp_runner=lambda *a, **k: _cpp_failure())
    tried = [d for d in f["details"] if d.get("status") is not None]
    assert tried and all(d["failure"] == "preprocessing_failed" for d in tried)
    assert f["preprocessing_failed"] == len(tried)
    assert f["completeness"] is None and f["precision"] is None
    assert f["error"].startswith("preprocessing failed for every mutant: m.c:1:10: fatal error")


def test_a_preprocessing_analysis_error_is_named_and_leaves_the_function_unscored(tmp_path: Path) -> None:
    # run_wp_function.py now reports a failed `gcc -E` as analysis_error with a preprocessing_failed reason.
    fatal = "m.c:1:10: fatal error: libmnl/libmnl.h: No such file or directory"
    report = {
        "status": "analysis_error",
        "reason": f"preprocessing_failed: {fatal}",
        "preprocess_errors": [fatal, "[kernel] User Error: failed to run: gcc -E -C -I. m.c"],
    }
    c_file = _write(tmp_path, "m.c", SRC)
    f = mc.check_function(c_file, "sum", "-I.", tmp_path / "out", wp_runner=lambda *a, **k: dict(report))
    tried = [d for d in f["details"] if d.get("status") is not None]
    assert tried and all(d["failure"] == "preprocessing_failed" for d in tried)
    assert f["error"].startswith("preprocessing failed for every mutant: m.c:1:10: fatal error")


def test_an_acsl_error_is_not_a_preprocessing_failure(tmp_path: Path) -> None:
    c_file = _write(tmp_path, "m.c", SRC)

    def runner(c_file, fn, out_dir, cppflags="-I."):
        if "ensures \\true;" in Path(c_file).read_text(encoding="utf-8"):
            return {
                "status": "acsl_syntax_error",
                "syntax_check": {"errors": ["[kernel:annot-error] m.c:2: unbound logic variable x"]},
            }
        return {"status": "all_proven"}

    f = mc.check_function(c_file, "sum", "-I.", tmp_path / "out", wp_runner=runner)
    na = next(d for d in f["details"] if d["mutant"] == "ensures-true")
    assert na["failure"] == "acsl_syntax_error"
    assert f["preprocessing_failed"] == 0 and "error" not in f


def test_report_lists_functions_whose_mutants_failed_to_preprocess(tmp_path: Path) -> None:
    run_dir = _fake_run(tmp_path)
    doc = mc.run_mutation_check(run_dir, wp_runner=lambda *a, **k: _cpp_failure())
    assert doc["totals"]["preprocessing_failed"] > 0
    section = "\n".join(gr.spec_quality_section({"run_dir": run_dir, "ledger": [], "mutation": doc}))
    assert "failed to preprocess (setup, not the contract)" in section
    assert "not checked: `sum`" in section


BODY_ANNOTS_SRC = """\
/*@
  requires n >= 0;
  ensures \\result >= 0;
*/
int count_up(int n) {
  int i = 0;
  /*@ loop invariant 0 <= i <= n;
      loop assigns i;
  */
  for (; i < n; i++) {}
  /*@ requires i == n;
      ensures i >= 0;
  */
  { i = n; }
  //@ assert i == n;
  return i;
}
"""

BODY_ONLY_ANNOTS_SRC = """\
int clamp_body_only(int x) {
  /*@ requires x < 0 || x >= 0;
      ensures x >= 0;
  */
  if (x < 0) x = 0;
  //@ assert x >= 0;
  return x;
}
"""


def test_acsl_text_of_span_ignores_body_annotations() -> None:
    span = locate_function_span(BODY_ANNOTS_SRC, "count_up", is_header=False, path="c.c")
    assert span is not None
    contract = mc._acsl_text_of_span(span)
    assert contract == "/*@\n  requires n >= 0;\n  ensures \\result >= 0;\n*/"
    assert "loop invariant" not in contract
    assert "ensures i >= 0;" not in contract
    assert "assert" not in contract

    mutants = dict(mc.spec_mutants(contract, 6))
    assert list(mutants) == ["drop-ensures-0", "weaken-ensures-0", "ensures-true"]
    assert "ensures \\result > 0;" in mutants["weaken-ensures-0"]

    body_only_span = locate_function_span(BODY_ONLY_ANNOTS_SRC, "clamp_body_only", is_header=False, path="c.c")
    assert body_only_span is not None
    assert mc._acsl_text_of_span(body_only_span) == ""
    assert mc.spec_mutants(mc._acsl_text_of_span(body_only_span), 6) == []


def test_check_function_keeps_body_annotations_intact_across_spec_mutants(tmp_path: Path) -> None:
    c_file = _write(tmp_path, "count.c", BODY_ANNOTS_SRC)
    orig_body = BODY_ANNOTS_SRC[BODY_ANNOTS_SRC.index("{") :]
    spec_texts: dict[str, str] = {}

    def runner(mut_file, fn, out_dir, cppflags="-I."):
        name = Path(out_dir).name
        if name.startswith("wp-spec-"):
            spec_texts[name] = Path(mut_file).read_text(encoding="utf-8")
        return {"status": "all_proven"}

    res = mc.check_function(c_file, "count_up", "-I.", tmp_path / "out", wp_runner=runner)
    assert res["spec_mutants"] == 3
    assert sorted(spec_texts) == ["wp-spec-drop-ensures-0", "wp-spec-ensures-true", "wp-spec-weaken-ensures-0"]
    for name, text in spec_texts.items():
        brace = text.index("{")
        header, body = text[:brace], text[brace:]
        assert body == orig_body, f"{name} altered body annotations"
        assert "loop invariant" not in header and "ensures i >= 0;" not in header and "assert" not in header
        assert "requires n >= 0;" in header
    assert "ensures \\result >= 0;" not in spec_texts["wp-spec-drop-ensures-0"]
    assert "ensures \\result > 0;" in spec_texts["wp-spec-weaken-ensures-0"]
    assert "ensures \\true;" in spec_texts["wp-spec-ensures-true"]

    body_only_file = _write(tmp_path, "body_only.c", BODY_ONLY_ANNOTS_SRC)
    body_only_res = mc.check_function(
        body_only_file,
        "clamp_body_only",
        "-I.",
        tmp_path / "out2",
        wp_runner=lambda *a, **k: {"status": "all_proven"},
    )
    assert body_only_res["spec_mutants"] == 0
    assert body_only_res["completeness"] is None


def test_check_function_multi_block_indented_contract_keeps_body_annotations(tmp_path: Path) -> None:
    src = (
        "  //@ requires n >= 0;\n"
        "  //@ ensures \\result >= 0;\n"
        "  //@ ensures \\result <= n;\n"
        "  int f(int n) {\n"
        "    int i = 0;\n"
        "    /*@ loop invariant 0 <= i <= n; */\n"
        "    for (; i < n; i++) {}\n"
        "    /*@ ensures i >= 0; */\n"
        "    { i = n; }\n"
        "    //@ assert i == n;\n"
        "    return i;\n"
        "  }\n"
    )
    c_file = _write(tmp_path, "multi.c", src)
    orig_body = src[src.index("{") :]
    spec_texts: dict[str, str] = {}

    def runner(mut_file, fn, out_dir, cppflags="-I."):
        name = Path(out_dir).name
        if name.startswith("wp-spec-"):
            spec_texts[name] = Path(mut_file).read_text(encoding="utf-8")
        return {"status": "all_proven"}

    res = mc.check_function(c_file, "f", "-I.", tmp_path / "out", wp_runner=runner)
    # 2 ensures clauses -> 2 drops + 2 weakens + 1 ensures-true = 5 spec mutants (none from body's ensures i >= 0).
    assert res["spec_mutants"] == 5
    for name, text in spec_texts.items():
        brace = text.index("{")
        header, body = text[:brace], text[brace:]
        assert body == orig_body, f"{name} dropped or altered body annotations"
        assert "requires n >= 0;" in header
        assert "loop invariant" not in header and "ensures i >= 0;" not in header
    assert "ensures \\result > 0;" in spec_texts["wp-spec-weaken-ensures-0"]
    assert "ensures \\result < n;" in spec_texts["wp-spec-weaken-ensures-1"]


def test_acsl_text_of_span_contract_shapes() -> None:
    # 1. Single-block contract
    single = "/*@ requires x >= 0; ensures \\result >= x; */\nint id(int x) { return x; }\n"
    single_span = locate_function_span(single, "id", is_header=False, path="s.c")
    assert single_span is not None
    assert mc._acsl_text_of_span(single_span) == "/*@ requires x >= 0; ensures \\result >= x; */"

    # 2. Multi-block contract (two /*@ ... */ blocks) with a body statement contract
    multi = (
        "/*@ requires x >= 0; */\n\n"
        "/*@ ensures \\result >= x; */\n"
        "int id2(int x) {\n"
        "  /*@ ensures x >= 0; */\n"
        "  return x;\n"
        "}\n"
    )
    multi_span = locate_function_span(multi, "id2", is_header=False, path="m.c")
    assert multi_span is not None
    assert mc._acsl_text_of_span(multi_span) == "/*@ requires x >= 0; */\n/*@ ensures \\result >= x; */"

    # 3. Prototype + static inline definition in a header (both Span and DeclSpan)
    hdr = (
        "/*@ requires x >= 0; ensures \\result >= 0; */\n"
        "static inline int inc(int x);\n\n"
        "/*@ ensures \\result == x + 1; */\n"
        "static inline int inc(int x) {\n"
        "  /*@ ensures x >= 0; */\n"
        "  return x + 1;\n"
        "}\n"
    )
    proto_span = locate_function_span(hdr, "inc", is_header=True, path="h.h")
    def_span = locate_function_span(hdr, "inc", is_header=False, path="h.h")
    assert proto_span is not None and def_span is not None
    assert mc._acsl_text_of_span(proto_span) == "/*@ requires x >= 0; ensures \\result >= 0; */"
    assert mc._acsl_text_of_span(def_span) == "/*@ ensures \\result == x + 1; */"
    decls = function_declaration_spans(hdr, "inc", path="h.h")
    assert [d.kind for d in decls] == ["prototype", "definition"]
    assert mc._acsl_text_of_span(decls[0]) == "/*@ requires x >= 0; ensures \\result >= 0; */"
    assert mc._acsl_text_of_span(decls[1]) == "/*@ ensures \\result == x + 1; */"

    # 4. Continuation `@` markers, `//` comment, and string literal inside the contract + body statement contract
    cont = (
        "/*@\n"
        "  @ // ensures \\result == 999;\n"
        '  @ requires p != "ensures x <= 0;";\n'
        "  @ requires x >= 0;\n"
        "  @ ensures \\result >= x;\n"
        "  @*/\n"
        "int cont_fn(const char *p, int x) {\n"
        "  /*@ ensures x >= 0; */\n"
        "  return x;\n"
        "}\n"
    )
    cont_span = locate_function_span(cont, "cont_fn", is_header=False, path="c.c")
    assert cont_span is not None
    cont_contract = mc._acsl_text_of_span(cont_span)
    assert "ensures \\result >= x;" in cont_contract
    assert "ensures x >= 0;" not in cont_contract
    cont_muts = dict(mc.spec_mutants(cont_contract, 6))
    assert list(cont_muts) == ["drop-ensures-0", "weaken-ensures-0", "ensures-true"]
    assert "// ensures \\result == 999;" in cont_muts["weaken-ensures-0"]
    assert '"ensures x <= 0;"' in cont_muts["weaken-ensures-0"]
    assert "ensures \\result > x;" in cont_muts["weaken-ensures-0"]
    spliced = mc._replace_contract_in_span(cont_span.text, cont_contract, cont_muts["weaken-ensures-0"])
    assert "ensures \\result > x;" in spliced and "/*@ ensures x >= 0; */" in spliced

    # 5. Malformed span (unclosed ACSL comment) returns empty string cleanly
    bad = Span(function="bad", start_byte=0, end_byte=10, start_line=1, end_line=1, text="/*@ unclosed")
    assert mc._acsl_text_of_span(bad) == ""


STATIC_A_SRC = """\
/*@
  ensures \\result == x;
*/
static int helper(int x) {
  return x;
}
"""

STATIC_B_SRC = """\
/*@
  requires \\valid(p);
  assigns *p;
*/
static void helper(int *p) {
  if (*p < 0) *p = 0;
}
"""


def test_run_mutation_check_discovers_same_named_static_functions_under_work(tmp_path: Path) -> None:
    import workspace_overlay as wo

    run_dir = tmp_path / "run"
    work = run_dir / "workspace" / "work"
    (work / "src" / "a").mkdir(parents=True)
    (work / "src" / "b").mkdir(parents=True)
    (work / "src" / "a" / "x.c").write_text(STATIC_A_SRC, encoding="utf-8")
    (work / "src" / "b" / "y.c").write_text(STATIC_B_SRC, encoding="utf-8")

    rep_a = run_dir / "workspace" / wo.baseline_wp_report_rel("src/a/x.c", "helper")
    rep_b = run_dir / "workspace" / wo.baseline_wp_report_rel("src/b/y.c", "helper")
    rep_a.parent.mkdir(parents=True, exist_ok=True)
    rep_a.write_text(
        json.dumps({"status": "all_proven", "function": "helper", "file": "workspace/work/src/a/x.c"}),
        encoding="utf-8",
    )
    rep_b.write_text(
        json.dumps({"status": "all_proven", "function": "helper", "file": "/framac-run/workspace/work/src/b/y.c"}),
        encoding="utf-8",
    )
    assert not (run_dir / "workspace" / "reports" / "wp" / "helper.json").exists()

    seen_files: set[str] = set()

    def runner(c_file, fn, out_dir, cppflags="-I."):
        text = Path(c_file).read_text(encoding="utf-8")
        seen_files.add(Path(c_file).name)
        if "{ return 0; }" in text:
            return _unproven(("ensures", "Unknown"))
        return {"status": "all_proven"}

    doc = mc.run_mutation_check(run_dir, wp_runner=runner)
    assert sorted(doc["functions"]) == ["src/a/x.c#helper", "src/b/y.c#helper"]
    assert doc["totals"]["functions"] == 2
    assert seen_files == {"x.c", "y.c"}
    assert doc["functions"]["src/a/x.c#helper"]["function"] == "helper"
    assert doc["functions"]["src/b/y.c#helper"]["function"] == "helper"
    assert doc["functions"]["src/a/x.c#helper"]["trivial_body_rejected"] is True
    assert doc["functions"]["src/b/y.c#helper"]["trivial_body_rejected"] is False
    assert doc["totals"]["trivial_body_accepted_functions"] == ["src/b/y.c#helper"]


def test_run_mutation_check_deduplicates_canonical_over_work_baseline(tmp_path: Path) -> None:
    import workspace_overlay as wo

    run_dir = _fake_run(tmp_path)
    # Write the canonical report first and the older baseline report afterwards to verify
    # precedence relies on canonical location rather than filesystem mtime order.
    canonical = run_dir / "workspace" / "reports" / "wp" / "sum.json"
    work_rep = run_dir / "workspace" / wo.baseline_wp_report_rel("m.c", "sum")
    work_rep.parent.mkdir(parents=True, exist_ok=True)
    canonical.write_text(
        json.dumps({"status": "all_proven", "function": "sum", "file": "m.c"}),
        encoding="utf-8",
    )
    work_rep.write_text(
        json.dumps({"status": "unproven_goals_remain", "function": "sum", "file": "/framac-run/workspace/work/m.c"}),
        encoding="utf-8",
    )

    checked_calls = 0

    def runner(c_file, fn, out_dir, cppflags="-I."):
        nonlocal checked_calls
        checked_calls += 1
        return {"status": "all_proven"}

    doc = mc.run_mutation_check(run_dir, wp_runner=runner)
    assert list(doc["functions"]) == ["sum"]
    assert doc["totals"]["functions"] == 1
    assert checked_calls == doc["functions"]["sum"]["spec_mutants"] + doc["functions"]["sum"]["impl_mutants"]

    # Conversely, if the canonical top-level report is no longer all_proven, the older
    # all_proven baseline under work/ must not cause the function to be checked.
    canonical.write_text(
        json.dumps({"status": "unproven_goals_remain", "function": "sum", "file": "m.c"}),
        encoding="utf-8",
    )
    work_rep.write_text(
        json.dumps({"status": "all_proven", "function": "sum", "file": "m.c"}),
        encoding="utf-8",
    )
    doc2 = mc.run_mutation_check(run_dir, wp_runner=runner)
    assert doc2["totals"]["functions"] == 0


def test_run_mutation_check_ignores_non_report_artifacts_under_work(tmp_path: Path) -> None:
    import workspace_overlay as wo

    run_dir = tmp_path / "run"
    (run_dir / "workspace" / "work").mkdir(parents=True)
    (run_dir / "workspace" / "work" / "m.c").write_text(SRC, encoding="utf-8")
    wp_work = run_dir / "workspace" / "reports" / "wp" / "work"
    wp_work.mkdir(parents=True)

    valid = run_dir / "workspace" / wo.baseline_wp_report_rel("m.c", "sum")
    valid.write_text(json.dumps({"status": "all_proven", "function": "sum", "file": "m.c"}), encoding="utf-8")

    # Non-report artifacts that must be ignored cleanly.
    (wp_work / "m_c_sum.wp-report-json").write_text(
        json.dumps({"status": "all_proven", "function": "bogus", "file": "m.c"}),
        encoding="utf-8",
    )
    (wp_work / "summary.json").write_text(json.dumps({"results": [{"status": "all_proven"}]}), encoding="utf-8")
    (wp_work / "no_file.json").write_text(json.dumps({"status": "all_proven", "function": "other"}), encoding="utf-8")
    (wp_work / "guardrail.json").write_text(
        json.dumps({"mode": "guardrail", "status": "all_proven", "function": "other", "file": "m.c"}),
        encoding="utf-8",
    )
    (wp_work / "corrupt.json").write_text("{not json", encoding="utf-8")
    nested = wp_work / "m_c_sum"
    nested.mkdir()
    (nested / "wp_sum.json").write_text(
        json.dumps({"status": "all_proven", "function": "nested", "file": "m.c"}),
        encoding="utf-8",
    )

    doc = mc.run_mutation_check(run_dir, wp_runner=lambda *a, **k: {"status": "all_proven"})
    assert list(doc["functions"]) == ["sum"]
    assert doc["totals"]["functions"] == 1


def _param_stubs(src: str, *, max_stubs: int = mc.DEFAULT_MAX_PARAM_STUBS) -> list[tuple[str, str]]:
    return mc.param_stub_mutants(src, _find_body_brace_offset(src), max_stubs=max_stubs)


def _all_stubs(src: str, *, max_param_stubs: int = mc.DEFAULT_MAX_PARAM_STUBS) -> list[tuple[str, str]]:
    return mc.trivial_stub_mutants(src, _find_body_brace_offset(src), max_param_stubs=max_param_stubs)


@pytest.mark.unit
def test_param_stub_mutants_type_matching_and_normalization() -> None:
    # Basic multi-param match
    assert _param_stubs("int max(int a, int b) { return a > b ? a : b; }") == [
        ("trivial-param-a-body", "{ return a; }"),
        ("trivial-param-b-body", "{ return b; }"),
    ]
    # Qualifiers, storage specifiers, and multi-token integer permutations
    assert _param_stubs(
        "static inline unsigned long int f(const long unsigned x, register unsigned long y, unsigned long z) { return 0; }"
    ) == [
        ("trivial-param-x-body", "{ return x; }"),
        ("trivial-param-y-body", "{ return y; }"),
    ]
    assert _param_stubs("signed f(int a, __signed__ int b) { return 0; }") == [
        ("trivial-param-a-body", "{ return a; }"),
        ("trivial-param-b-body", "{ return b; }"),
    ]
    assert _param_stubs("unsigned f(unsigned int a, int unsigned b) { return 0; }") == [
        ("trivial-param-a-body", "{ return a; }"),
        ("trivial-param-b-body", "{ return b; }"),
    ]
    assert _param_stubs("long long int f(signed long long a, long int long b) { return 0; }") == [
        ("trivial-param-a-body", "{ return a; }"),
        ("trivial-param-b-body", "{ return b; }"),
    ]
    assert _param_stubs("unsigned long long f(long unsigned long int a) { return 0; }") == [
        ("trivial-param-a-body", "{ return a; }"),
    ]
    assert _param_stubs("short int f(signed short a, short b) { return 0; }") == [
        ("trivial-param-a-body", "{ return a; }"),
        ("trivial-param-b-body", "{ return b; }"),
    ]
    assert _param_stubs("unsigned short f(short unsigned int a) { return 0; }") == [
        ("trivial-param-a-body", "{ return a; }"),
    ]
    # Boolean and floating-point / complex canonicalization
    assert _param_stubs("_Bool f(bool a, const _Bool b) { return 0; }") == [
        ("trivial-param-a-body", "{ return a; }"),
        ("trivial-param-b-body", "{ return b; }"),
    ]
    assert _param_stubs("long double f(double long a, const long double b) { return 0; }") == [
        ("trivial-param-a-body", "{ return a; }"),
        ("trivial-param-b-body", "{ return b; }"),
    ]
    assert _param_stubs("float _Complex f(_Complex float a, __complex__ float b) { return 0; }") == [
        ("trivial-param-a-body", "{ return a; }"),
        ("trivial-param-b-body", "{ return b; }"),
    ]
    # Pointer depths, void *, and const/volatile/restrict qualifiers on pointers (accepted by Frama-C 34)
    assert _param_stubs("char *pick_ptr(const char *a, char * restrict b) { return 0; }") == [
        ("trivial-param-a-body", "{ return a; }"),
        ("trivial-param-b-body", "{ return b; }"),
    ]
    assert _param_stubs("void *f(void *p, int *q) { return 0; }") == [
        ("trivial-param-p-body", "{ return p; }"),
    ]
    assert _param_stubs("int * const *f(const int * volatile *p, int *q) { return 0; }") == [
        ("trivial-param-p-body", "{ return p; }"),
    ]
    # Single-dimension array decay (including static qualifier, sizeof bound, and char *argv[])
    assert _param_stubs("int *find(const int arr[], int n, int buf[16]) { return 0; }") == [
        ("trivial-param-arr-body", "{ return arr; }"),
        ("trivial-param-buf-body", "{ return buf; }"),
    ]
    assert _param_stubs("const char *f(const char b[static 4], char c[sizeof(int)]) { return 0; }") == [
        ("trivial-param-b-body", "{ return b; }"),
        ("trivial-param-c-body", "{ return c; }"),
    ]
    assert _param_stubs("char **shift(char *argv[], int argc) { return 0; }") == [
        ("trivial-param-argv-body", "{ return argv; }"),
    ]
    # Tag types (struct/union/enum) by value and by pointer
    assert _all_stubs("struct s inc_s(const struct s a) { struct s r = a; return r; }") == [
        ("trivial-param-a-body", "{ return a; }"),
    ]
    assert _all_stubs("union u f(union u x) { union u r = x; return r; }") == [
        ("trivial-param-x-body", "{ return x; }"),
    ]
    assert _param_stubs("enum color f(const enum color c, int n) { return 0; }") == [
        ("trivial-param-c-body", "{ return c; }"),
    ]
    assert _param_stubs("struct s *f(const struct s *p, struct other *q) { return 0; }") == [
        ("trivial-param-p-body", "{ return p; }"),
    ]
    # Matching typedefs
    assert _param_stubs("size_t f(const size_t n, unsigned long m) { return 0; }") == [
        ("trivial-param-n-body", "{ return n; }"),
    ]
    assert _all_stubs("Box inc_box(Box b) { Box r = b; return r; }") == [
        ("trivial-zero-body", "{ return 0; }"),
        ("trivial-param-b-body", "{ return b; }"),
    ]
    # Attributes on return type, parameters, and post-parameter suffix
    assert _param_stubs(
        "__attribute__((nonnull(1))) char *f(char *p __attribute__((unused))) __attribute__((pure)) { return 0; }"
    ) == [
        ("trivial-param-p-body", "{ return p; }"),
    ]


@pytest.mark.unit
def test_param_stub_mutants_skips_non_matching_and_unsupported() -> None:
    # void return, void param list, empty ()
    assert _param_stubs("void f(int x, void *p) { (void)x; (void)p; }") == []
    assert _param_stubs("int f(void) { return 1; }") == []
    assert _param_stubs("int f() { return 1; }") == []
    # Unnamed parameters (including qualified typedefs, struct tags, pointers, arrays)
    assert _param_stubs("int f(int, const size_t, struct s, int * const, int[], const int[]) { return 1; }") == []
    assert _param_stubs("size_t f(size_t, const size_t) { return 1; }") == []
    assert _param_stubs("struct s f(struct s) { struct s r = {0}; return r; }") == []
    # Multi-dimensional arrays (>= 2 dims decay to pointer-to-array, not T **)
    assert _param_stubs("int **mat(int m[][4], int n[3][4], int **p) { return 0; }") == [
        ("trivial-param-p-body", "{ return p; }"),
    ]
    # Function-pointer params, pointer-to-array params, parenthesized declarator, variadics
    assert _param_stubs("int f(int (*cb)(int), int a, ...) { return 0; }") == [
        ("trivial-param-a-body", "{ return a; }"),
    ]
    assert _param_stubs("int *f(int (*a)[10], int *p) { return 0; }") == [
        ("trivial-param-p-body", "{ return p; }"),
    ]
    assert _param_stubs("int f(int (a)) { return 0; }") == []
    # char, signed char, and unsigned char stay distinct
    assert _param_stubs("char *f(unsigned char *u, signed char *s, char *c) { return 0; }") == [
        ("trivial-param-c-body", "{ return c; }"),
    ]
    assert _param_stubs("signed char f(char c, unsigned char u, signed char s) { return 0; }") == [
        ("trivial-param-s-body", "{ return s; }"),
    ]
    assert _param_stubs("unsigned char f(char c, signed char s, unsigned char u) { return 0; }") == [
        ("trivial-param-u-body", "{ return u; }"),
    ]
    # Typedef alias mismatches are skipped conservatively
    assert _param_stubs("size_t f(unsigned long x) { return 0; }") == []
    # K&R definitions: base zero stub still works, parameter stubs skipped cleanly
    kr_src = "int kr(a, b) int a; int b; { return a + b; }"
    assert _stub(kr_src) == ("trivial-zero-body", "{ return 0; }")
    assert _param_stubs(kr_src) == []
    # Nested function-pointer and pointer-to-array returns: both base and param stubs return None / []
    for nested in (
        "unsigned int (*get_cb(int x))(int) { return 0; }",
        "int (*get_cb2(int x))(int) { return 0; }",
        "my_t (*get_cb3(int x))(int) { return 0; }",
        "struct s (*get_cb4(int x))(int) { return 0; }",
        "my_t (*get_arr(int x))[4] { return 0; }",
    ):
        assert _stub(nested) is None, nested
        assert _param_stubs(nested) == [], nested
    # Inline anonymous struct/union in param list or return type
    assert _param_stubs("int f(struct { int x, y; } s, int a) { return 0; }") == [
        ("trivial-param-a-body", "{ return a; }"),
    ]
    assert _all_stubs("struct { int x; } f(int a) { return a; }") == []
    # Macro-decorated return type: base zero stub still works, param stubs skipped cleanly
    macro_src = "EXPORT_API int f(int a) { return a + 1; }"
    assert _stub(macro_src) == ("trivial-zero-body", "{ return 0; }")
    assert _param_stubs(macro_src) == []
    # Invalid specifier mixes in _normalize_type
    for bad in (
        ["signed", "unsigned", "int"],
        ["short", "long"],
        ["char", "int"],
        ["long", "long", "long"],
        ["float", "double"],
        ["long", "long", "double"],
        ["void", "int"],
        ["int", "*", "int"],
        ["struct"],
    ):
        assert mc._normalize_type(bad) is None, bad


@pytest.mark.unit
def test_param_stub_mutants_cap_and_order(tmp_path: Path) -> None:
    src = """\
/*@ ensures \\result == a + b + c + d; */
int sum4(int a, int b, int c, int d) {
  if (a < b) return 0;
  return a + b + c + d;
}
"""
    assert _param_stubs(src) == [
        ("trivial-param-a-body", "{ return a; }"),
        ("trivial-param-b-body", "{ return b; }"),
    ]
    assert _param_stubs(src, max_stubs=0) == []
    assert [name for name, _ in _param_stubs(src, max_stubs=3)] == [
        "trivial-param-a-body",
        "trivial-param-b-body",
        "trivial-param-c-body",
    ]
    # Trivial stubs (base + capped param stubs) come first and do not consume max_mutants.
    c_file = _write(tmp_path, "sum4.c", src)
    f = mc.check_function(
        c_file, "sum4", "-I.", tmp_path / "out", wp_runner=lambda *a, **k: {"status": "all_proven"}, max_mutants=1
    )
    assert [d["mutant"] for d in f["details"] if d["kind"] == "impl"] == [
        "trivial-zero-body",
        "trivial-param-a-body",
        "trivial-param-b-body",
        "flip-<",
    ]


@pytest.mark.unit
def test_param_stub_skips_body_identical_return(tmp_path: Path) -> None:
    id_src = "/*@ ensures \\result == x; */\nint id(int x) { return x; }\n"
    id_paren_src = "int id_p(int x) { /*@ assert x >= 0; */ // comment\n return ((x)); }\n"
    first_src = "int first(int a, int b, int c) { return a; }\n"

    assert _param_stubs(id_src) == []
    assert _all_stubs(id_src) == [("trivial-zero-body", "{ return 0; }")]
    assert _param_stubs(id_paren_src) == []
    # Cap is applied AFTER filtering the body-identical parameter `a`, so both `b` and `c` are kept.
    assert _param_stubs(first_src) == [
        ("trivial-param-b-body", "{ return b; }"),
        ("trivial-param-c-body", "{ return c; }"),
    ]
    # Non-identical bodies are NOT filtered out.
    assert _param_stubs("int f(int x) { return x + 0; }") == [("trivial-param-x-body", "{ return x; }")]
    assert _param_stubs("int f(int x) { return (int)x; }") == [("trivial-param-x-body", "{ return x; }")]
    assert _param_stubs('const char *f(const char *x) { return "x"; }') == [
        ("trivial-param-x-body", "{ return x; }"),
    ]
    # End-to-end check_function on an identity function: only trivial-zero-body runs.
    c_file = _write(tmp_path, "id.c", id_src)
    res = mc.check_function(
        c_file,
        "id",
        "-I.",
        tmp_path / "out",
        wp_runner=lambda *a, **k: _unproven(("ensures", "Unknown")),
    )
    assert [d["mutant"] for d in res["details"] if d["kind"] == "impl"] == ["trivial-zero-body"]
    assert res["trivial_body_rejected"] is True


@pytest.mark.unit
@pytest.mark.parametrize(
    "outcomes,expected_rejected,expected_impl_mutants,expected_na",
    [
        # (a) all 3 stubs rejected -> True
        (
            {
                "trivial-zero-body": _unproven(("ensures", "Unknown")),
                "trivial-param-a-body": _unproven(("ensures", "Invalid")),
                "trivial-param-b-body": _unproven(("ensures", "Unknown")),
            },
            True,
            3,
            0,
        ),
        # (b) zero rejected + one param survives (proved) -> False
        (
            {
                "trivial-zero-body": _unproven(("ensures", "Unknown")),
                "trivial-param-a-body": {"status": "all_proven"},
                "trivial-param-b-body": _unproven(("ensures", "Unknown")),
            },
            False,
            3,
            0,
        ),
        # (c) zero rejected + one param survives (rte_only) -> False
        (
            {
                "trivial-zero-body": _unproven(("ensures", "Unknown")),
                "trivial-param-a-body": _unproven(("rte_signed_overflow", "Unknown")),
                "trivial-param-b-body": _unproven(("ensures", "Invalid")),
            },
            False,
            3,
            0,
        ),
        # (d) zero survives + both params rejected -> False
        (
            {
                "trivial-zero-body": {"status": "all_proven"},
                "trivial-param-a-body": _unproven(("ensures", "Invalid")),
                "trivial-param-b-body": _unproven(("ensures", "Invalid")),
            },
            False,
            3,
            0,
        ),
        # (e) zero not_applicable + params rejected -> True (e.g. typedef struct Box)
        (
            {
                "trivial-zero-body": {"status": "acsl_syntax_error"},
                "trivial-param-a-body": _unproven(("ensures", "Unknown")),
                "trivial-param-b-body": _unproven(("ensures", "Invalid")),
            },
            True,
            2,
            1,
        ),
        # (f) zero not_applicable + one param survives -> False
        (
            {
                "trivial-zero-body": {"status": "acsl_syntax_error"},
                "trivial-param-a-body": {"status": "all_proven"},
                "trivial-param-b-body": _unproven(("ensures", "Invalid")),
            },
            False,
            2,
            1,
        ),
        # (g) all stubs not_applicable -> None
        (
            {
                "trivial-zero-body": {"status": "analysis_error"},
                "trivial-param-a-body": {"status": "analysis_error"},
                "trivial-param-b-body": {"status": "analysis_error"},
            },
            None,
            0,
            3,
        ),
    ],
)
def test_trivial_body_rejected_aggregation(
    tmp_path: Path,
    outcomes: dict[str, dict],
    expected_rejected: bool | None,
    expected_impl_mutants: int,
    expected_na: int,
) -> None:
    c_file = _write(tmp_path, "add.c", ADD_SRC)

    def runner(mut_file, fn, out_dir, cppflags="-I."):
        name = Path(out_dir).name
        if name.startswith("wp-impl-"):
            return outcomes[name[len("wp-impl-") :]]
        return {"status": "all_proven"}

    res = mc.check_function(c_file, "add", "-I.", tmp_path / "out", wp_runner=runner)
    assert res["trivial_body_rejected"] is expected_rejected
    assert res["impl_mutants"] == expected_impl_mutants
    assert res["impl_not_applicable"] == expected_na


@pytest.mark.unit
@pytest.mark.parametrize(
    "param_report,expected", [(_unproven(("ensures", "Unknown")), True), ({"status": "all_proven"}, False)]
)
def test_by_value_struct_runs_param_stub_without_synthetic_na(
    tmp_path: Path, param_report: dict, expected: bool
) -> None:
    src = (
        "struct s { int x; };\n"
        "/*@ ensures \\result.x == a.x + 1; */\n"
        "struct s inc_s(const struct s a) { struct s r = a; r.x += 1; return r; }\n"
    )
    c_file = _write(tmp_path, "s.c", src)
    seen_impl: list[str] = []

    def runner(mut_file, fn, out_dir, cppflags="-I."):
        name = Path(out_dir).name
        if name.startswith("wp-impl-"):
            seen_impl.append(name[len("wp-impl-") :])
            return param_report
        return {"status": "all_proven"}

    res = mc.check_function(c_file, "inc_s", "-I.", tmp_path / "out", wp_runner=runner)
    assert seen_impl == ["trivial-param-a-body"]
    assert [d["mutant"] for d in res["details"] if d["kind"] == "impl"] == ["trivial-param-a-body"]
    assert res["trivial_body_rejected"] is expected
    assert res["impl_mutants"] == 1 and res["impl_not_applicable"] == 0
    assert res["precision"] == (1.0 if expected else 0.0)


@pytest.mark.unit
def test_stub_switch_off_drops_param_stubs_too(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FRAMAC_MUTATION_STUB", "off")
    add_file = _write(tmp_path, "a.c", ADD_SRC)
    res_add = mc.check_function(
        add_file, "add", "-I.", tmp_path / "out_add", wp_runner=lambda *a, **k: _unproven(("ensures", "Unknown"))
    )
    assert "trivial_body_rejected" not in res_add
    assert not any(d["mutant"].startswith("trivial") for d in res_add["details"])
    assert res_add["impl_mutants"] == 0 and res_add["precision"] is None

    sum_file = _write(tmp_path, "m.c", SRC)
    res_sum = mc.check_function(
        sum_file, "sum", "-I.", tmp_path / "out_sum", wp_runner=lambda *a, **k: _unproven(("ensures", "Invalid"))
    )
    assert "trivial_body_rejected" not in res_sum
    assert [d["mutant"] for d in res_sum["details"] if d["kind"] == "impl"] == ["flip-<", "return-0-to-1"]
    assert res_sum["impl_mutants"] == 2 and res_sum["rejected"] == 2 and res_sum["precision"] == 1.0


@pytest.mark.unit
def test_spec_quality_renders_function_accepting_param_stub(tmp_path: Path) -> None:
    max_weak_src = """\
/*@ ensures \\result >= a; */
int max_weak(int a, int b) {
  return a >= b ? a : b;
}
"""
    run_dir = tmp_path / "run"
    (run_dir / "workspace" / "work").mkdir(parents=True)
    (run_dir / "workspace" / "work" / "m.c").write_text(max_weak_src, encoding="utf-8")
    wp_dir = run_dir / "workspace" / "reports" / "wp"
    wp_dir.mkdir(parents=True)
    (wp_dir / "max_weak.json").write_text(
        json.dumps({"status": "all_proven", "function": "max_weak", "file": "m.c"}),
        encoding="utf-8",
    )

    def runner(mut_file, fn, out_dir, cppflags="-I."):
        name = Path(out_dir).name
        if name == "wp-impl-trivial-param-a-body":
            return {"status": "all_proven"}  # weak contract accepts `{ return a; }`
        return _unproven(("ensures", "Unknown"))

    doc = mc.run_mutation_check(run_dir, wp_runner=runner)
    assert doc["functions"]["max_weak"]["trivial_body_rejected"] is False
    assert doc["totals"]["trivial_body_checked"] == 1
    assert doc["totals"]["trivial_body_accepted"] == 1
    assert doc["totals"]["trivial_body_accepted_functions"] == ["max_weak"]

    section = "\n".join(gr.spec_quality_section({"run_dir": run_dir, "ledger": [], "mutation": doc}))
    assert "1 accept a body that does nothing: `max_weak`" in section
    assert "trivial stub rejected: no" in section


@pytest.mark.unit
def test_validate_run_accepts_mutation_totals_with_param_stubs(tmp_path: Path) -> None:
    import benchmark

    run_dir = _fake_run(tmp_path)
    doc = mc.run_mutation_check(run_dir, wp_runner=lambda *a, **k: _unproven(("ensures", "Unknown")))
    out = run_dir / "workspace" / "reports" / "mutation.json"
    summary = mc.summarize_mutation(out)
    assert summary == doc["totals"]

    zero_rate = {"passed": 0, "failed": 0, "undecided": 0, "over_decided": None, "strict": None}
    bench_run = {
        "schema_version": 1,
        "run_id": "tier5-check",
        "created_at": "2026-11-20T00:00:00Z",
        "mode": "deterministic",
        "pipeline": {"commit": "abc1234", "dirty": False, "content_digest": "0" * 64},
        "toolchain": {},
        "machine": {},
        "limits": {"wp_memlimit_mb": 1000, "fuzz_rss_limit_mb": 512, "replay_per_input_timeout_s": 5},
        "selection": {},
        "targets": {
            "t": {
                "set": "comparison",
                "revision": "a" * 40,
                "harness_digest": "b" * 64,
                "status": "ok",
                "problems": [],
                "stages": {},
                "wall_s": 1.0,
                "cpu_s": 1.0,
                "dag": {},
                "modules": {},
                "functions_with_unknown": [],
                "functions_with_unknown_count": 0,
                "functions_with_unknown_no_unit": [],
                "prover_tasks": {},
                "units": {"total": zero_rate, "by_wave": {}, "by_class": {}, "covered": [], "candidate": []},
                "mutation": summary,
                "candidates": {},
            }
        },
        "recall": benchmark.recall_block({}),
        "briefs": None,
        "totals": {"wall_s": 1.0, "cpu_s": 1.0},
    }
    assert benchmark.validate_run(bench_run) == []
