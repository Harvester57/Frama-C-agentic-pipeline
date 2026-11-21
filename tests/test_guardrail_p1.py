"""H9: guardrail corpus sampling, reach on the batch merge path, and the untrusted-entry trust boundary."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import crash_replay
import fuzz_build
import run_eacsl_fuzz as R
import sandbox_exec
import workspace_overlay
from acsl_ast import (
    TrustBoundaryError,
    entry_requires_violations,
    extract_requires_clauses,
    function_contract_text,
    function_param_names,
)
from sandbox_exec import SandboxResult

pytestmark = pytest.mark.unit

ATTACKER = ["buf", "len"]

# ---------------------------------------------------------------------------
# Part 1: corpus selection
# ---------------------------------------------------------------------------


def test_selection_keeps_every_seed_and_crash_and_samples_the_rest():
    hexes = [f"{i:040x}" for i in range(200)]
    targeted = [f"seed-{i:016x}" for i in range(10)] + ["crash-abc", "minimized-from-1234"]
    chosen, sampled = R.select_replay_inputs(hexes + targeted, 64)
    assert sampled
    assert set(targeted) <= set(chosen)
    assert len(chosen) == 64
    assert chosen == sorted(chosen)
    # Not simply the first names in sort order: the sample spreads over the corpus.
    others = [n for n in chosen if n in hexes]
    assert others != sorted(hexes)[: len(others)]


def test_selection_is_deterministic_and_order_independent():
    names = [f"{i:040x}" for i in range(300)] + ["seed-1", "seed-2"]
    first, _ = R.select_replay_inputs(names, 50)
    second, _ = R.select_replay_inputs(list(reversed(names)), 50)
    assert first == second


def test_selection_targeted_files_exceed_the_limit():
    names = [f"seed-{i:04d}" for i in range(10)] + ["aa", "bb"]
    chosen, sampled = R.select_replay_inputs(names, 4)
    assert chosen == [f"seed-{i:04d}" for i in range(10)] and sampled


@pytest.mark.parametrize("limit", [None, 0, -1, 100])
def test_selection_without_effective_limit_keeps_all(limit):
    names = ["b", "a", "seed-x"]
    assert R.select_replay_inputs(names, limit) == (["a", "b", "seed-x"], False)


def _instrumented(monkeypatch, captured: list) -> None:
    monkeypatch.setattr(R, "is_eacsl_instrumented", lambda b: True)
    monkeypatch.setattr(fuzz_build, "is_eacsl_instrumented", lambda b: True)
    monkeypatch.setattr(crash_replay, "is_eacsl_instrumented", lambda b: True)

    def fake_run(cmd, **kw):
        captured.append(list(cmd))
        return SandboxResult(0, "stat::number_of_executed_units: 5\n", "", False, "rlimits", list(cmd))

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_run)


def test_guardrail_replays_seeds_and_reports_the_sample(tmp_path, monkeypatch):
    captured: list = []
    _instrumented(monkeypatch, captured)
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    for i in range(20):
        (corpus / f"{i:040x}").write_bytes(b"x%d" % i)
    for i in range(3):
        (corpus / f"seed-{i:016x}").write_bytes(b"s%d" % i)
    binary = tmp_path / "guard.e-acsl"
    binary.write_bytes(b"bin")
    verdict = R.run_guardrail_check(
        binary, corpus, tmp_path / "scratch", 0, use_cache=False, max_corpus_inputs=8, module="m", seed=1
    )
    assert verdict["status"] == "passed_dynamic_oracle"
    assert verdict["corpus_total"] == 23 and verdict["corpus_replayed"] == 8
    assert verdict["corpus_sampled"] is True and verdict["corpus_empty"] is False
    replay_dir = Path(captured[0][-1])
    replayed = sorted(p.name for p in replay_dir.iterdir())
    assert len(replayed) == 8 and {f"seed-{i:016x}" for i in range(3)} <= set(replayed)


def test_guardrail_reports_an_empty_corpus(tmp_path, monkeypatch):
    captured: list = []
    _instrumented(monkeypatch, captured)
    binary = tmp_path / "guard.e-acsl"
    binary.write_bytes(b"bin")
    verdict = R.run_guardrail_check(binary, tmp_path / "corpus", tmp_path / "scratch", 50, use_cache=False, seed=1)
    assert verdict["status"] == "passed_dynamic_oracle"  # non-blocking ...
    assert verdict["corpus_empty"] is True and verdict["corpus_total"] == 0  # ... but recorded
    assert verdict["corpus_sampled"] is False
    assert any("corpus is empty" in h for h in verdict["diagnostic_hints"])


def test_guardrail_cli_reach_functions_do_not_narrow_instrumentation(tmp_path, monkeypatch):
    seen: dict = {}

    def compile_ok(sources, out_bin, *a, functions=None, **k):
        seen["instrumented"] = functions
        return {"returncode": 0, "binary": str(out_bin)}

    def guard(binary, corpus, scratch, runs, **k):
        seen["reach"] = k.get("functions")
        return {"status": "passed_dynamic_oracle", "corpus_dir": str(corpus)}

    monkeypatch.setattr(fuzz_build, "compile_eacsl_binary", compile_ok)
    monkeypatch.setattr(R, "run_guardrail_check", guard)
    monkeypatch.setattr(R.prover_candidates, "add_candidate_block", lambda *a, **k: None)
    out = tmp_path / "g.json"
    rc = R.main(
        [
            "guardrail",
            "--sources",
            "m.c",
            "--out-bin",
            str(tmp_path / "bin"),
            "--corpus-dir",
            str(tmp_path / "c"),
            "--reach-functions",
            "f",
            "g",
            "--out-json",
            str(out),
        ]
    )
    assert rc == 0
    assert seen == {"instrumented": None, "reach": ["f", "g"]}


# ---------------------------------------------------------------------------
# Part 2: limits recorded from the guardrail, single and batch paths
# ---------------------------------------------------------------------------


def _guard(reach_fns: dict, empty: bool = False) -> dict:
    return {
        "status": "passed_dynamic_oracle",
        "reach": {
            "measured": True,
            "executed_inputs": 7,
            "functions": reach_fns,
            "unreached": sorted(f for f, n in reach_fns.items() if n == 0),
        },
        "corpus_total": 0 if empty else 100,
        "corpus_replayed": 0 if empty else 64,
        "corpus_sampled": not empty,
        "corpus_empty": empty,
    }


def test_apply_guard_limits_records_reach_and_corpus():
    rep: dict = {}
    assert workspace_overlay._apply_guard_limits(rep, "f", _guard({"f": 3}))
    # `unchecked_clauses` None: this fake guardrail report does not say what E-ACSL ignored.
    oracle = {"exercised": True, "hits": 3, "executed_inputs": 7, "unchecked_clauses": None}
    assert rep["limits"]["dynamic_oracle"] == oracle
    assert rep["limits"]["guardrail_corpus"] == {"total": 100, "replayed": 64, "sampled": True, "empty": False}


def test_apply_guard_limits_empty_corpus_is_never_exercised():
    rep: dict = {}
    workspace_overlay._apply_guard_limits(rep, "f", _guard({"f": 3}, empty=True))
    assert rep["limits"]["dynamic_oracle"]["exercised"] is False
    assert rep["limits"]["guardrail_corpus"]["empty"] is True
    rep2: dict = {}
    workspace_overlay._apply_guard_limits(rep2, "f", {"status": "passed_dynamic_oracle", "corpus_empty": True})
    assert rep2["limits"]["dynamic_oracle"]["exercised"] is False


BASE_C = """int parse(const unsigned char *buf, unsigned long len) {
    return len > 0 ? buf[0] : 0;
}

int helper(int x) {
    return x;
}

int other(int x) {
    return x + 1;
}
"""


def _run(tmp_path: Path, edits: dict[str, tuple[str, str]], sidecar: dict | None = None) -> tuple[Path, Path]:
    target = tmp_path / "target"
    target.mkdir()
    (target / "m.c").write_text(BASE_C, encoding="utf-8")
    run_dir = (tmp_path / "run").resolve()
    overlay = run_dir / "workspace"
    workspace_overlay.init_overlay(target, overlay)
    meta = {
        "module": "m",
        "sources": ["workspace/work/m.c"],
        "cppflags": "-I.",
        "entry_fn": "parse",
        "entry_style": "buffer_len",
        "reachability": "untrusted_surface",
    }
    meta.update(sidecar or {})
    (overlay / "harnesses").mkdir(parents=True, exist_ok=True)
    (overlay / "harnesses" / "harness_m.json").write_text(json.dumps(meta), encoding="utf-8")
    for agent_id, (old, new) in edits.items():
        workspace_overlay.init_agent_overlay(run_dir, agent_id, overlay)
        path = run_dir / "agents" / agent_id / "scratch" / "work" / "m.c"
        text = path.read_text(encoding="utf-8")
        assert old in text
        path.write_text(text.replace(old, new), encoding="utf-8")
    return run_dir, overlay


def test_batch_merge_measures_reach_of_its_provers(tmp_path, monkeypatch):
    edits = {
        "prover-helper": ("    return x;", "    //@ assert h: x == x;\n    return x;"),
        "prover-other": ("    return x + 1;", "    //@ assert o: x == x;\n    return x + 1;"),
    }
    run_dir, overlay = _run(tmp_path, edits)
    calls: list[dict] = []

    def fake_reverify(run_dir, agent_id, role, overlay_dir, c_file, function, module, sources, cppflags, **kw):
        calls.append({"function": function, "module": module, **kw})
        if module and not function:
            path = workspace_overlay._parent_guard_json(run_dir, agent_id, None, module)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(_guard({"helper": 2, "other": 0})), encoding="utf-8")
        if function:
            path = run_dir / workspace_overlay._parent_wp_report_rel(agent_id, function)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"status": "all_proven", "function": function}), encoding="utf-8")
        return True, "verified"

    monkeypatch.setattr(workspace_overlay, "_run_parent_reverify", fake_reverify)
    entries = [
        {"agent_id": "prover-helper", "role": "prover", "file": "m.c", "function": "helper", "module": "m"},
        {"agent_id": "prover-other", "role": "prover", "file": "m.c", "function": "other", "module": "m"},
    ]
    res = workspace_overlay.merge_agent_batch(run_dir, entries)
    assert res["ok"], res
    module_calls = [c for c in calls if c["module"] and not c["function"]]
    assert module_calls and module_calls[0]["reach_functions"] == ["helper", "other"]
    for fn, exercised, hits in (("helper", True, 2), ("other", False, 0)):
        rep = json.loads(
            (run_dir / workspace_overlay._parent_wp_report_rel(f"prover-{fn}", fn)).read_text(encoding="utf-8")
        )
        oracle = {"exercised": exercised, "hits": hits, "executed_inputs": 7, "unchecked_clauses": None}
        assert rep["limits"]["dynamic_oracle"] == oracle
        assert rep["limits"]["guardrail_corpus"]["sampled"] is True
        canonical = json.loads((overlay / "reports" / "wp" / f"{fn}.json").read_text(encoding="utf-8"))
        assert canonical["limits"]["dynamic_oracle"]["exercised"] is exercised


def test_module_guardrail_passes_reach_functions_to_the_cli(tmp_path, monkeypatch):
    run_dir, overlay = _run(tmp_path, {})
    argv: list = []

    def fake_run(cmd, **kw):
        argv.append(list(cmd))
        out = Path(cmd[cmd.index("--out-json") + 1])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps({"status": "passed_dynamic_oracle"}), encoding="utf-8")
        import subprocess

        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(workspace_overlay.subprocess, "run", fake_run)
    ok, why = workspace_overlay._run_parent_reverify(
        run_dir,
        "prover-x",
        "architect",
        overlay,
        None,
        None,
        "m",
        ["workspace/work/m.c"],
        "-I.",
        reach_functions=["b", "a"],
    )
    assert ok, why
    cmd = argv[0]
    assert "--functions" not in cmd
    i = cmd.index("--reach-functions")
    assert cmd[i + 1 : i + 3] == ["a", "b"]


# ---------------------------------------------------------------------------
# Part 3: trust boundary of untrusted_surface entry contracts
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "contract",
    [
        "/*@ requires len <= 64; */",
        "/*@ requires buf[0] == 0x30; */",
        "/*@ requires L: \\forall integer i; 0 <= i < len ==> buf[i] != 0; */",
        "/*@ requires \\valid_read(buf + (0 .. len - 1)) && len < 4096; */",
        "/*@ requires len > 0 ==> *buf == 1; */",
        "/*@ requires len <= 64 && \\forall integer i; 0 <= i < len ==> \\valid_read(buf + i); */",
        "/*@ requires is_printable_ascii(buf[0]); */",
        "/*@ requires no_crlf_or_nul((char *)buf, len); */",
        "/*@ requires valid_c_string((char *)buf); */",
        "/*@ requires !(len > 10); */",
        "/*@ requires \\exists integer i; 0 <= i < len && buf[i] == 0; */",
        "/*@ behavior big: assumes len > 8; requires buf[8] == 0; */",
        "//@ requires len != 3;",
        "/*@ requires len < 2 || len > 10; */",
    ],
)
def test_entry_requires_value_constraints_are_flagged(contract):
    assert entry_requires_violations(contract, ATTACKER), contract


@pytest.mark.parametrize(
    "contract",
    [
        "/*@ requires \\valid_read(buf + (0 .. len - 1)); */",
        "/*@ requires len > 0 ==> \\valid_read(buf + (0 .. len - 1)); */",
        "/*@ requires len == 0 || \\valid_read(buf + (0 .. len - 1)); */",
        "/*@ requires buf != \\null;\n  @ requires \\separated(buf + (0 .. len - 1), &g_state); */",
        "/*@ requires \\initialized(buf + (0 .. len - 1)); */",
        "/*@ requires \\block_length(buf) >= len; */",
        "/*@ requires valid_read_buffer(buf, len); */",
        "/*@ requires len >= 0; requires 0 <= len; */",
        "/*@ requires \\forall integer i; 0 <= i < len ==> \\valid_read(buf + i); */",
        "/*@ requires env_ok: g_mode == 1;\n    ensures \\result >= 0;\n    assigns \\nothing; */",
        "/*@ requires \\valid_read(&s->len) && s->len >= 0; */",  # s is not an attacker parameter here
        "/*@ ensures \\result <= len; */",
    ],
)
def test_entry_requires_shape_is_allowed(contract):
    assert entry_requires_violations(contract, ATTACKER) == [], contract


@pytest.mark.parametrize("name", ["valid_read_string", "valid_c_string"])
def test_a_string_predicate_is_shape_only_when_the_harness_nul_terminates(name):
    c = f"/*@ requires {name}(s); */"
    assert entry_requires_violations(c, ["s"])
    assert entry_requires_violations(c, ["s"], nul_terminated=True) == []


def test_no_attacker_params_checks_nothing():
    assert entry_requires_violations("/*@ requires len <= 4; */", []) == []


def test_requires_extraction_handles_binders_and_labels():
    text = "/*@ requires a: \\forall integer i; 0 <= i < n ==> p[i] == 0;\n  @ requires q != \\null; */"
    assert extract_requires_clauses(text) == ["\\forall integer i; 0 <= i < n ==> p[i] == 0", "q != \\null"]


def test_param_names_and_contract_text():
    src = (
        "/*@ requires \\valid(p); */\n"
        "int f(const char *p, unsigned long n, int (*cb)(int), char tag[16], void *) {\n"
        "  /*@ assert n == n; */\n  return 0;\n}\n"
    )
    assert function_param_names(src, "f") == ["p", "n", "cb", "tag"]
    contract = function_contract_text(src, "f")
    assert "requires" in contract and "assert" not in contract


def test_merge_rejects_value_constraint_on_entry(tmp_path):
    edit = {"prover-parse": ("int parse(", "/*@ requires len <= 64; */\nint parse(")}
    run_dir, overlay = _run(tmp_path, edit)
    with pytest.raises(TrustBoundaryError) as exc:
        workspace_overlay.merge_agent_overlay(
            run_dir, "prover-parse", "prover", overlay, c_file="m.c", function="parse", module="m", skip_reverify=True
        )
    assert workspace_overlay.TRUST_BOUNDARY_REASON in str(exc.value) and "len" in str(exc.value)
    assert "requires" not in (overlay / "work" / "m.c").read_text(encoding="utf-8")


def test_merge_accepts_shape_contract_on_entry(tmp_path):
    edit = {
        "prover-parse": ("int parse(", "/*@ requires len > 0 ==> \\valid_read(buf + (0 .. len - 1)); */\nint parse(")
    }
    run_dir, overlay = _run(tmp_path, edit)
    res = workspace_overlay.merge_agent_overlay(
        run_dir, "prover-parse", "prover", overlay, c_file="m.c", function="parse", module="m", skip_reverify=True
    )
    assert res["ok"]


@pytest.mark.parametrize(
    "sidecar",
    [{"reachability": "internal_api"}, {"entry_fn": "other"}],
)
def test_merge_does_not_check_internal_api_or_non_entry(tmp_path, sidecar):
    edit = {"prover-parse": ("int parse(", "/*@ requires len <= 64; */\nint parse(")}
    run_dir, overlay = _run(tmp_path, edit, sidecar)
    res = workspace_overlay.merge_agent_overlay(
        run_dir, "prover-parse", "prover", overlay, c_file="m.c", function="parse", module="m", skip_reverify=True
    )
    assert res["ok"]


def test_merge_ignores_constraints_already_in_the_target_baseline(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "m.c").write_text("/*@ requires len <= 64; */\n" + BASE_C, encoding="utf-8")
    run_dir = (tmp_path / "run").resolve()
    overlay = run_dir / "workspace"
    workspace_overlay.init_overlay(target, overlay)
    (overlay / "harnesses").mkdir(parents=True, exist_ok=True)
    (overlay / "harnesses" / "harness_m.json").write_text(
        json.dumps({"module": "m", "entry_fn": "parse", "reachability": "untrusted_surface"}), encoding="utf-8"
    )
    workspace_overlay.init_agent_overlay(run_dir, "prover-parse", overlay)
    path = run_dir / "agents" / "prover-parse" / "scratch" / "work" / "m.c"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "requires len <= 64; */", "requires len <= 64;\n    requires \\valid_read(buf + (0 .. len - 1)); */"
        ),
        encoding="utf-8",
    )
    res = workspace_overlay.merge_agent_overlay(
        run_dir, "prover-parse", "prover", overlay, c_file="m.c", function="parse", module="m", skip_reverify=True
    )
    assert res["ok"]


def test_batch_merge_rejects_entry_violation_and_keeps_the_rest(tmp_path):
    edits = {
        "prover-parse": ("int parse(", "/*@ requires buf[0] == 0x30; */\nint parse("),
        "prover-helper": ("    return x;", "    //@ assert h: x == x;\n    return x;"),
    }
    run_dir, overlay = _run(tmp_path, edits)
    entries = [
        {"agent_id": "prover-parse", "role": "prover", "file": "m.c", "function": "parse", "module": "m"},
        {"agent_id": "prover-helper", "role": "prover", "file": "m.c", "function": "helper", "module": "m"},
    ]
    res = workspace_overlay.merge_agent_batch(run_dir, entries, skip_reverify=True)
    assert not res["ok"]
    (failed,) = res["failed"]
    assert failed["agent_id"] == "prover-parse" and workspace_overlay.TRUST_BOUNDARY_REASON in failed["reason"]
    assert [m["agent_id"] for m in res["merged"]] == ["prover-helper"]


def test_architect_header_violation_on_entry_prototype(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "m.c").write_text('#include "m.h"\n' + BASE_C, encoding="utf-8")
    (target / "m.h").write_text("int parse(const unsigned char *data, unsigned long size);\n", encoding="utf-8")
    run_dir = (tmp_path / "run").resolve()
    overlay = run_dir / "workspace"
    workspace_overlay.init_overlay(target, overlay)
    (overlay / "harnesses").mkdir(parents=True, exist_ok=True)
    (overlay / "harnesses" / "harness_m.json").write_text(
        json.dumps({"module": "m", "entry_fn": "parse", "reachability": "untrusted_surface"}), encoding="utf-8"
    )
    workspace_overlay.init_agent_overlay(run_dir, "arch-m", overlay)
    path = run_dir / "agents" / "arch-m" / "scratch" / "work" / "m.h"
    path.write_text("/*@ requires size < 100; */\n" + path.read_text(encoding="utf-8"), encoding="utf-8")
    # The refusal names the file, the entry and the clause, not just any text with "size" in it.
    with pytest.raises(TrustBoundaryError, match=r"(?s)m\.h: parse: requires size < 100;") as refused:
        workspace_overlay.merge_agent_overlay(
            run_dir, "arch-m", "architect", overlay, header_file="m.h", module="m", skip_reverify=True
        )
    assert str(refused.value).startswith(workspace_overlay.TRUST_BOUNDARY_REASON)


# ---------------------------------------------------------------------------
# Inputs that crash outside the checked functions (libmnl Tier 6 A/B, 2026-11-09)
# ---------------------------------------------------------------------------

# Trimmed from the real replay: the corpus seed `seed-ext-parse-offset-2pow31` reproduces a known bug in
# `mnl_attr_parse`, and every guardrail of module `attr` stopped on it with `guardrail_error`.
_G = "/framac-run/state/parent_guard/attr-7457e160cb/guard_attr_mnl_attr_get_len.instrumented.c"
SEGV_ELSEWHERE = f"""INFO: Running with entropic power schedule (0xFF, 100).
UndefinedBehaviorSanitizer:DEADLYSIGNAL
==7==ERROR: UndefinedBehaviorSanitizer: SEGV on unknown address 0x76a8a3763c30 (pc 0x5fd4a2ce31af T7)
==7==The signal is caused by a READ memory access.
    #0 0x5fd4a2ce31af in mnl_attr_ok {_G}:874:30
    #1 0x5fd4a2ce3c04 in mnl_attr_parse {_G}:1139:13
    #2 0x5fd4a2ce9a55 in ext_attr_parse_offset {_G}:3662:3
    #3 0x5fd4a2ce9a55 in LLVMFuzzerTestOneInput {_G}:3927:3
    #4 0x5fd4a2c9b8ea in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/w/guard.bin+0x368ea)
UndefinedBehaviorSanitizer can not provide additional info.
SUMMARY: UndefinedBehaviorSanitizer: SEGV {_G}:874:30 in mnl_attr_ok
==7==ABORTING
"""
COVERAGE_DUMP = "COVERAGE:\n" + "".join(
    f"COVERED_FUNC: hits: 1 edges: 1/2 f{i} /x.c:{i}\n  UNCOVERED_PC: /x.c:{i + 1}\n" for i in range(300)
)


def test_crash_outside_the_checked_functions_is_named():
    why = R.crash_outside_checked_functions(SEGV_ELSEWHERE, ["mnl_attr_get_len"])
    assert why is not None and "SEGV" in why and "mnl_attr_ok" in why


@pytest.mark.parametrize("checked", [["mnl_attr_parse"], ["mnl_attr_ok"], []])
def test_crash_through_a_checked_function_or_unknown_scope_is_not_excused(checked):
    assert R.crash_outside_checked_functions(SEGV_ELSEWHERE, checked) is None


def test_a_crash_in_the_e_acsl_wrapper_is_not_excused():
    out = SEGV_ELSEWHERE.replace("in mnl_attr_parse ", "in __gen_e_acsl_mnl_attr_get_len ")
    assert R.crash_outside_checked_functions(out, ["mnl_attr_get_len"]) is None


def test_timeouts_and_stackless_crashes_are_not_excused():
    timeout = "==9== ERROR: libFuzzer: timeout after 30 seconds\n    #0 0x1 in other /x.c:3:1\n"
    assert R.crash_outside_checked_functions(timeout, ["f"]) is None
    assert R.crash_outside_checked_functions("==9==ERROR: UndefinedBehaviorSanitizer: SEGV\n", ["f"]) is None


def test_coverage_dump_no_longer_hides_the_crash_report():
    _, stripped = R.parse_guardrail_reach(SEGV_ELSEWHERE + COVERAGE_DUMP, ["mnl_attr_get_len"])
    assert "UNCOVERED_PC" not in stripped
    assert "SUMMARY: UndefinedBehaviorSanitizer: SEGV" in stripped[-4000:]


@pytest.fixture
def chdir_tmp(tmp_path, monkeypatch):
    """crash_input paths are run-relative: run from tmp_path as the run directory."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _crashing_replays(monkeypatch, crasher: bytes, calls: list, report: str = SEGV_ELSEWHERE) -> None:
    """A fake libFuzzer that stops on the first replayed file whose content is `crasher`, printing `report`."""
    monkeypatch.setattr(R, "is_eacsl_instrumented", lambda b: True)
    monkeypatch.setattr(fuzz_build, "is_eacsl_instrumented", lambda b: True)
    monkeypatch.setattr(crash_replay, "is_eacsl_instrumented", lambda b: True)

    def fake_run(cmd, **kw):
        calls.append(list(cmd))
        prefix = Path(next(a for a in cmd if a.startswith("-artifact_prefix=")).split("=", 1)[1])
        replayed = sorted(Path(cmd[-1]).iterdir())
        if any(p.read_bytes() == crasher for p in replayed):
            (prefix / "crash-0123").write_bytes(crasher)
            out = report + f"Test unit written to {prefix}/crash-0123\n" + COVERAGE_DUMP
            return SandboxResult(1, "", out, False, "rlimits", list(cmd))
        stats = f"COVERED_FUNC: hits: 2 edges: 1/1 mnl_attr_get_len {_G}:686\n"
        return SandboxResult(
            0, stats + f"stat::number_of_executed_units: {len(replayed)}\n", "", False, "rlimits", list(cmd)
        )

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_run)


def _corpus(tmp_path: Path) -> Path:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    for i in range(5):
        (corpus / f"{i:040x}").write_bytes(b"ok%d" % i)
    (corpus / "seed-ext-parse-offset-2pow31").write_bytes(b"\x030\x04\x00\x01\x00\x80\x00")
    return corpus


def test_guardrail_drops_an_input_that_crashes_elsewhere_and_replays_the_rest(tmp_path, monkeypatch, chdir_tmp):
    calls: list = []
    corpus = _corpus(tmp_path)
    _crashing_replays(monkeypatch, b"\x030\x04\x00\x01\x00\x80\x00", calls)
    binary = tmp_path / "guard.e-acsl"
    binary.write_bytes(b"bin")
    verdict = R.run_guardrail_check(
        binary, corpus, tmp_path / "scratch", 0, use_cache=False, module="attr", seed=1, functions=["mnl_attr_get_len"]
    )
    assert verdict["status"] == "passed_dynamic_oracle"
    assert [e["input"] for e in verdict["excluded_inputs"]] == ["seed-ext-parse-offset-2pow31"]
    assert "mnl_attr_ok" in verdict["excluded_inputs"][0]["crash"]
    assert len(calls) == 2
    assert verdict["reach"]["functions"] == {"mnl_attr_get_len": 2}
    assert sorted(p.name for p in corpus.iterdir())[-1] == "seed-ext-parse-offset-2pow31"  # shared corpus untouched


def test_guardrail_keeps_the_error_when_the_crash_is_in_a_checked_function(tmp_path, monkeypatch, chdir_tmp):
    calls: list = []
    corpus = _corpus(tmp_path)
    _crashing_replays(monkeypatch, b"\x030\x04\x00\x01\x00\x80\x00", calls)
    binary = tmp_path / "guard.e-acsl"
    binary.write_bytes(b"bin")
    verdict = R.run_guardrail_check(
        binary, corpus, tmp_path / "scratch", 0, use_cache=False, module="attr", seed=1, functions=["mnl_attr_parse"]
    )
    assert verdict["status"] == "guardrail_error" and verdict["excluded_inputs"] == []
    assert len(calls) == 1
    assert "SUMMARY: UndefinedBehaviorSanitizer: SEGV" in verdict["runtime_trace"]


def test_guardrail_gives_up_after_too_many_crashing_inputs(tmp_path, monkeypatch, chdir_tmp):
    monkeypatch.setattr(R, "GUARDRAIL_MAX_EXCLUDED_INPUTS", 1)
    calls: list = []
    corpus = _corpus(tmp_path)
    (corpus / "seed-other").write_bytes(b"\x030\x04\x00\x01\x00\x80\x00")  # same bytes, second crasher
    _crashing_replays(monkeypatch, b"\x030\x04\x00\x01\x00\x80\x00", calls)
    binary = tmp_path / "guard.e-acsl"
    binary.write_bytes(b"bin")
    verdict = R.run_guardrail_check(
        binary, corpus, tmp_path / "scratch", 0, use_cache=False, module="attr", seed=1, functions=["mnl_attr_get_len"]
    )
    assert verdict["status"] == "guardrail_error"
    assert len(verdict["excluded_inputs"]) == 1 and "More than 1 replayed inputs" in verdict["reason"]


# ---------------------------------------------------------------------------
# E-ACSL failures outside the checked functions (minmea run-1, Phase 3, 2026-11-14)
# ---------------------------------------------------------------------------

# `minmea_tocoord` is a header `static inline` Frama-C does not know (`rte_select_dropped`), so the guardrail
# build instrumented the whole module and every replay stopped on the known signed overflow of `minmea_scan`.
# The stack and the values are the run's `runtime_trace` (frames trimmed); the trace is cut to its last 4000
# characters, so the four lines before the values follow the layout of a Docker replay of the same build.
_MINMEA_C = "agents/prove-minmea_tocoord/scratch/work/minmea.c"
_MINMEA_I = "/framac-run/agents/prove-minmea_tocoord/scratch/guard_minmea_tocoord.instrumented.c"
_MINMEA_STACK = f"""==131== ERROR: libFuzzer: deadly signal
    #0 0x5aff4df7c758 in __sanitizer_print_stack_trace (/framac-run/guard_minmea_tocoord.e-acsl+0x7f758)
    #1 0x5aff4df4f32c in fuzzer::PrintStackTrace() (/framac-run/guard_minmea_tocoord.e-acsl+0x5232c)
    #2 0x5aff4df342a7 in fuzzer::Fuzzer::CrashCallback() (/framac-run/guard_minmea_tocoord.e-acsl+0x372a7)
    #3 0x7b00d5d3ed6f  (/lib/x86_64-linux-gnu/libc.so.6+0x3fd6f)
    #4 0x7b00d5d9369b  (/lib/x86_64-linux-gnu/libc.so.6+0x9469b)
    #5 0x7b00d5d3ec41 in raise (/lib/x86_64-linux-gnu/libc.so.6+0x3fc41)
    #6 0x5aff4df8644d in minmea_scan {_MINMEA_I}:8593:25
    #7 0x5aff4dfa440f in minmea_parse_gll {_MINMEA_I}:29292:9
    #8 0x5aff4dfaf079 in LLVMFuzzerTestOneInput {_MINMEA_I}:36924:5
    #9 0x5aff4df359aa in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/w/g+0x389aa)
NOTE: libFuzzer has rudimentary signal handlers.
SUMMARY: libFuzzer: deadly signal
"""
EACSL_RTE_ELSEWHERE = (
    "INFO: Running with entropic power schedule (0xFF, 100).\n"
    f"{_MINMEA_C}: In function 'minmea_scan'\n"
    f"{_MINMEA_C}:186: Error: Assertion failed:\n"
    "\tThe failing predicate is:\n"
    "\trte/signed_overflow:\n"
    "\t\tscale * 10 ≤ 2147483647.\n"
    "\tWith values at failure point:\n"
    "\t- scale: 1000000000\n" + _MINMEA_STACK
)
# The same build at HEAD in Docker (2026-11-14): an annotation-side failure in the same unchecked function.
EACSL_ANNOTATION_ELSEWHERE = (
    f"{_MINMEA_C}: In function 'minmea_scan'\n"
    f"{_MINMEA_C}:224: Error: E-ACSL RTE failed:\n"
    "\tThe failing predicate is:\n"
    "\tuninitialized:\n"
    "\t\t\\initialized(&endptr).\n"
    "\tWith values at failure point:\n"
    "\t- uninitialized: \\initialized(&endptr): 0\n" + _MINMEA_STACK.replace("minmea_parse_gll", "minmea_parse_gsa")
)
# A precondition of the checked function itself, failing in its E-ACSL wrapper.
EACSL_CONTRACT_OF_CHECKED = (
    f"{_MINMEA_C}: In function 'minmea_tocoord'\n"
    f"{_MINMEA_C}:95: Error: Precondition failed:\n"
    "\tThe failing predicate is:\n"
    "\tf->scale > 0.\n"
    + _MINMEA_STACK.replace("in minmea_scan ", "in __gen_e_acsl_minmea_tocoord ").replace(
        "in minmea_parse_gll ", "in minmea_parse_rmc "
    )
)
MINMEA_CRASHER = b"$GPGLL,.0000000000"


def _minmea_guardrail(
    tmp_path: Path, monkeypatch, report: str, functions: list[str], calls: list, crashers: int = 1
) -> dict:
    corpus = _corpus(tmp_path)
    for i in range(crashers):
        (corpus / ("seed-gll-scale" + f"-{i}" * (i > 0))).write_bytes(MINMEA_CRASHER)
    _crashing_replays(monkeypatch, MINMEA_CRASHER, calls, report)
    binary = tmp_path / "guard.e-acsl"
    binary.write_bytes(b"bin")
    return R.run_guardrail_check(
        binary, corpus, tmp_path / "scratch", 0, use_cache=False, module="minmea", seed=1, functions=functions
    )


def test_eacsl_failure_outside_the_checked_functions_is_named():
    failure = R.parse_eacsl_failure(EACSL_RTE_ELSEWHERE)
    assert failure == {  # the `failure` of the run's guard_minmea_tocoord.json
        "file": _MINMEA_C,
        "line": 186,
        "function": "minmea_scan",
        "kind": "assertion",
        "alarm_kind": "signed_overflow",
        "is_rte": True,
        "label": "rte/signed_overflow",
        "predicate": "scale * 10 ≤ 2147483647",
    }
    why = R.failure_outside_checked_functions(failure, EACSL_RTE_ELSEWHERE, ["minmea_tocoord"])
    assert why is not None and "rte/signed_overflow" in why and why.endswith(f"{_MINMEA_C}:186 in minmea_scan")


@pytest.mark.parametrize("checked", [["minmea_scan"], ["minmea_parse_gll"], ["__no_such__", "minmea_scan"], [], None])
def test_eacsl_failure_in_or_below_a_checked_function_or_unknown_scope_is_not_excused(checked):
    failure = R.parse_eacsl_failure(EACSL_RTE_ELSEWHERE)
    assert R.failure_outside_checked_functions(failure, EACSL_RTE_ELSEWHERE, checked) is None


def test_eacsl_failure_without_a_stack_or_a_named_function_is_not_excused():
    failure = R.parse_eacsl_failure(EACSL_RTE_ELSEWHERE)
    stackless = EACSL_RTE_ELSEWHERE.split("==131==")[0]
    assert R.failure_outside_checked_functions(failure, stackless, ["minmea_tocoord"]) is None
    assert failure is not None
    unnamed = {**failure, "function": "unknown_function"}
    assert R.failure_outside_checked_functions(unnamed, EACSL_RTE_ELSEWHERE, ["minmea_tocoord"]) is None
    assert R.failure_outside_checked_functions(None, EACSL_RTE_ELSEWHERE, ["minmea_tocoord"]) is None
    wrapper = EACSL_RTE_ELSEWHERE.replace("in minmea_parse_gll ", "in __gen_e_acsl_minmea_tocoord ")
    assert R.failure_outside_checked_functions(failure, wrapper, ["minmea_tocoord"]) is None


@pytest.mark.parametrize(
    ("report", "label"),
    [(EACSL_RTE_ELSEWHERE, "rte/signed_overflow"), (EACSL_ANNOTATION_ELSEWHERE, "uninitialized")],
    ids=["code_fault", "rejected_overconstrained"],
)
def test_guardrail_drops_an_input_whose_eacsl_failure_is_in_another_function(
    tmp_path, monkeypatch, chdir_tmp, report, label
):
    # Before the fix: `code_fault` / `rejected_overconstrained` against the contract of minmea_tocoord.
    assert R.classify_guardrail(77, False, report)["status"] in ("code_fault", "rejected_overconstrained")
    calls: list = []
    verdict = _minmea_guardrail(tmp_path, monkeypatch, report, ["minmea_tocoord"], calls)
    assert verdict["status"] == "passed_dynamic_oracle"
    assert len(calls) == 2
    (dropped,) = verdict["excluded_inputs"]
    assert dropped["input"] == "seed-gll-scale" and "in minmea_scan" in dropped["crash"]
    # The failure stays visible in the report, with the fingerprint a code fault has.
    assert dropped["failure"]["function"] == "minmea_scan" and dropped["failure"]["label"] == label
    assert ("fingerprint" in dropped) == (label == "rte/signed_overflow")
    assert any("outside the checked functions" in h and "minmea_scan" in h for h in verdict["diagnostic_hints"])


@pytest.mark.parametrize("checked", [["minmea_scan"], ["minmea_parse_gll"]], ids=["inside", "callee_of_checked"])
def test_guardrail_keeps_the_code_fault_in_or_below_a_checked_function(tmp_path, monkeypatch, chdir_tmp, checked):
    calls: list = []
    verdict = _minmea_guardrail(tmp_path, monkeypatch, EACSL_RTE_ELSEWHERE, checked, calls)
    assert verdict["status"] == "code_fault" and verdict["excluded_inputs"] == []
    assert verdict["failure"]["function"] == "minmea_scan" and len(calls) == 1
    assert "outside_checked_functions" not in verdict


def test_guardrail_keeps_a_contract_violation_of_the_checked_function(tmp_path, monkeypatch, chdir_tmp):
    calls: list = []
    verdict = _minmea_guardrail(tmp_path, monkeypatch, EACSL_CONTRACT_OF_CHECKED, ["minmea_tocoord"], calls)
    assert verdict["status"] == "rejected_overconstrained" and verdict["excluded_inputs"] == []
    assert verdict["failure"]["function"] == "minmea_tocoord" and len(calls) == 1


@pytest.mark.parametrize(
    ("report", "status", "replays"),
    [(EACSL_RTE_ELSEWHERE, "passed_dynamic_oracle", 2), (EACSL_ANNOTATION_ELSEWHERE, "rejected_overconstrained", 1)],
    ids=["rte_dropped", "annotation_kept"],
)
def test_module_wide_guardrail_never_excuses_a_failed_annotation(
    tmp_path, monkeypatch, chdir_tmp, report, status, replays
):
    # `--reach-functions` (batch merge): every annotation of the module is checked, so the reach list is
    # no contract scope. An RTE failure of other code is still no evidence about any contract.
    corpus = _corpus(tmp_path)
    (corpus / "seed-gll-scale").write_bytes(MINMEA_CRASHER)
    calls: list = []
    _crashing_replays(monkeypatch, MINMEA_CRASHER, calls, report)
    binary = tmp_path / "guard.e-acsl"
    binary.write_bytes(b"bin")
    verdict = R.run_guardrail_check(
        binary, corpus, tmp_path / "scratch", 0, use_cache=False, seed=1, functions=["f"], contract_functions=[]
    )
    assert verdict["status"] == status and len(calls) == replays


def test_guardrail_never_blames_the_contract_past_the_exclusion_limit(tmp_path, monkeypatch, chdir_tmp):
    monkeypatch.setattr(R, "GUARDRAIL_MAX_EXCLUDED_INPUTS", 1)
    calls: list = []
    verdict = _minmea_guardrail(tmp_path, monkeypatch, EACSL_RTE_ELSEWHERE, ["minmea_tocoord"], calls, crashers=2)
    assert verdict["status"] == "guardrail_error" and verdict["failure"] is None and len(calls) == 2
    assert len(verdict["excluded_inputs"]) == 1 and "More than 1 replayed inputs" in verdict["reason"]
    assert verdict["outside_checked_functions"]["failure"]["function"] == "minmea_scan"


def _mutation_guardrail(
    tmp_path: Path,
    monkeypatch,
    functions: list[str],
    calls: list,
    always: bool = False,
    report: str = EACSL_RTE_ELSEWHERE,
    returncode: int = 77,
) -> dict:
    """
    A guardrail whose fake libFuzzer stops on an input no corpus file holds, with `report` (by default the
    minmea_scan overflow): a mutation of the `--extra-runs` burst (only when `-runs` is not 0), or with `always`
    on every replay. This is the minmea case: 64 of 223 corpus inputs replayed, and the fault came from a
    generated unit.
    """
    corpus = _corpus(tmp_path)
    monkeypatch.setattr(R, "is_eacsl_instrumented", lambda b: True)
    monkeypatch.setattr(fuzz_build, "is_eacsl_instrumented", lambda b: True)
    monkeypatch.setattr(crash_replay, "is_eacsl_instrumented", lambda b: True)

    def fake_run(cmd, **kw):
        calls.append(list(cmd))
        if always or "-runs=0" not in cmd:
            prefix = Path(next(a for a in cmd if a.startswith("-artifact_prefix=")).split("=", 1)[1])
            (prefix / "crash-0123").write_bytes(MINMEA_CRASHER)
            out = report + f"Test unit written to {prefix}/crash-0123\n"
            return SandboxResult(returncode, "", out, False, "rlimits", list(cmd))
        return SandboxResult(0, "stat::number_of_executed_units: 6\n", "", False, "rlimits", list(cmd))

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_run)
    binary = tmp_path / "guard.e-acsl"
    binary.write_bytes(b"bin")
    return R.run_guardrail_check(
        binary, corpus, tmp_path / "scratch", 100, use_cache=False, module="minmea", seed=1, functions=functions
    )


def test_guardrail_skips_the_mutation_burst_when_a_mutation_fails_in_another_function(tmp_path, monkeypatch, chdir_tmp):
    calls: list = []
    verdict = _mutation_guardrail(tmp_path, monkeypatch, ["minmea_tocoord"], calls)
    assert verdict["status"] == "passed_dynamic_oracle" and verdict["excluded_inputs"] == []
    assert ["-runs=100" in c for c in calls] == [True, False] and "-runs=0" in calls[1]
    skipped = verdict["mutations_skipped"]
    assert skipped["crash_input"] == "scratch/crash-0123" and "in minmea_scan" in skipped["crash"]
    assert skipped["failure"]["label"] == "rte/signed_overflow" and skipped["fingerprint"]
    assert any("mutation burst was skipped" in h for h in verdict["diagnostic_hints"])


def test_guardrail_keeps_the_code_fault_of_a_mutation_in_a_checked_function(tmp_path, monkeypatch, chdir_tmp):
    calls: list = []
    verdict = _mutation_guardrail(tmp_path, monkeypatch, ["minmea_scan"], calls)
    assert verdict["status"] == "code_fault" and len(calls) == 1
    assert "mutations_skipped" not in verdict and "outside_checked_functions" not in verdict


def test_guardrail_never_blames_the_contract_for_an_input_it_cannot_drop(tmp_path, monkeypatch, chdir_tmp):
    # Still failing elsewhere without mutations, on an input that is no replayed corpus file: nothing to drop.
    calls: list = []
    verdict = _mutation_guardrail(tmp_path, monkeypatch, ["minmea_tocoord"], calls, always=True)
    assert verdict["status"] == "guardrail_error" and verdict["failure"] is None and len(calls) == 2
    assert verdict["excluded_inputs"] == [] and "cannot be dropped" in verdict["reason"]
    outside = verdict["outside_checked_functions"]
    assert outside["failure"]["label"] == "rte/signed_overflow" and outside["fingerprint"]
    assert len(verdict["diagnostic_hints"]) == 1 and "NOT a code_fault" in verdict["diagnostic_hints"][0]


# nanopb run-1 (2026-11-20): the header guardrail's burst stopped on a mutation (`MS: 1 CrossOver-`) with a
# UBSan SEGV in `advance_iterator` <- `pb_field_iter_find_extension`, no E-ACSL report and no checked function
# on the stack, and reported `guardrail_error` after 64 of 773 corpus inputs. SEGV_ELSEWHERE has the same shape.


def test_guardrail_skips_the_mutation_burst_when_a_mutation_crashes_in_another_function(
    tmp_path, monkeypatch, chdir_tmp
):
    calls: list = []
    verdict = _mutation_guardrail(
        tmp_path, monkeypatch, ["mnl_attr_get_len"], calls, report=SEGV_ELSEWHERE, returncode=1
    )
    assert verdict["status"] == "passed_dynamic_oracle" and verdict["excluded_inputs"] == []
    assert ["-runs=100" in c for c in calls] == [True, False] and "-runs=0" in calls[1]
    skipped = verdict["mutations_skipped"]
    assert skipped["crash_input"] == "scratch/crash-0123" and "in mnl_attr_ok" in skipped["crash"]
    assert "failure" not in skipped and "kind" not in skipped
    assert any("mutation burst was skipped" in h for h in verdict["diagnostic_hints"])


def test_guardrail_keeps_the_sanitizer_crash_of_a_mutation_in_a_checked_function(tmp_path, monkeypatch, chdir_tmp):
    calls: list = []
    verdict = _mutation_guardrail(tmp_path, monkeypatch, ["mnl_attr_parse"], calls, report=SEGV_ELSEWHERE, returncode=1)
    assert verdict["status"] == "guardrail_error" and len(calls) == 1
    assert "mutations_skipped" not in verdict and "outside_checked_functions" not in verdict
    assert "SUMMARY: UndefinedBehaviorSanitizer: SEGV" in verdict["runtime_trace"]


def test_guardrail_stops_when_a_sanitizer_crash_elsewhere_survives_the_skipped_burst(tmp_path, monkeypatch, chdir_tmp):
    # Still crashing elsewhere without mutations, on an input that is no replayed corpus file: nothing to drop.
    calls: list = []
    verdict = _mutation_guardrail(
        tmp_path, monkeypatch, ["mnl_attr_get_len"], calls, always=True, report=SEGV_ELSEWHERE, returncode=1
    )
    assert verdict["status"] == "guardrail_error" and verdict["failure"] is None and len(calls) == 2
    assert verdict["excluded_inputs"] == [] and "in mnl_attr_ok" in verdict["mutations_skipped"]["crash"]


# ---------------------------------------------------------------------------
# Stage-1 Frama-C OOM / kill classification (`eacsl_stage_killed`, c-ares run-1)
# ---------------------------------------------------------------------------


def test_guardrail_classifies_silent_aborted_by_frama_c_as_eacsl_stage_killed(tmp_path, monkeypatch):
    """
    c-ares run-1 (`adig`, 98 TUs): stage-1 Frama-C was OOM-killed under 2048 MiB. `e-acsl-gcc`
    exited 1 with `aborted by Frama-C` and no Frama-C diagnostic message, and the report previously
    labeled it `eacsl_instrumentation_failed` with a false struct-comparison hint (triggered by
    `with` inside `(with preprocessing)`).
    """
    import subprocess

    src = tmp_path / "adig.c"
    src.write_text("int config_defaults(int x) { return x; }\n", encoding="utf-8")
    monkeypatch.setattr(fuzz_build, "_resolve_eacsl_gcc", lambda: ("e-acsl-gcc", True))
    monkeypatch.setattr(R.prover_candidates, "add_candidate_block", lambda *a, **k: None)

    stage1_stdout = (
        "[kernel] Parsing adig.c (with preprocessing)\n"
        "[kernel] Parsing src/error.c (with preprocessing)\n"
        "[e-acsl] beginning translation.\n"
    )
    stage1_stderr = (
        "++ /home/opam/.opam/5.5/bin/frama-c -no-frama-c-stdlib -kernel-warn-key annot-error=abort adig.c\n"
        "e-acsl-gcc: fatal error: aborted by Frama-C\n"
    )

    def fake_run_tool(cmd, runner=subprocess.run, timeout=None):
        return 1, stage1_stdout, stage1_stderr

    monkeypatch.setattr(fuzz_build, "_run_tool", fake_run_tool)

    out_json = tmp_path / "guard_config_defaults.json"
    rc = R.main(
        [
            "guardrail",
            "--sources",
            str(src),
            "--functions",
            "config_defaults",
            "--out-bin",
            str(tmp_path / "guard_config_defaults"),
            "--corpus-dir",
            str(tmp_path / "corpus"),
            "--no-cache",
            "--out-json",
            str(out_json),
        ]
    )
    assert rc == 0
    rep = json.loads(out_json.read_text(encoding="utf-8"))
    assert rep["status"] == "compile_error"
    assert rep["reason"] == "eacsl_stage_killed"
    assert rep["compile"]["reason"] == "eacsl_stage_killed"
    assert rep["compile"].get("killed_suspected") is True
    hints = rep["diagnostic_hints"]
    assert any("memory" in h.lower() and "oom" in h.lower() and "docker events" in h for h in hints), hints
    assert not any("unsupported ACSL construct" in h for h in hints), hints
    assert not any("ACSL syntax/typing error" in h for h in hints), hints


@pytest.mark.parametrize(
    ("rc", "stdout", "stderr", "expected_reason", "expected_flag"),
    [
        (137, "[kernel] Parsing a.c (with preprocessing)\n", "", "eacsl_stage_killed", "killed"),
        (-9, "", "", "eacsl_stage_killed", "killed"),
        (
            1,
            "[kernel] Parsing a.c (with preprocessing)\n",
            "bash: line 1: 42 Killed frama-c\ne-acsl-gcc: fatal error: aborted by Frama-C\n",
            "eacsl_stage_killed",
            "killed",
        ),
        (
            1,
            "[kernel] Parsing a.c (with preprocessing)\n[kernel] User Error: bad token\n",
            "e-acsl-gcc: fatal error: aborted by Frama-C\n",
            "eacsl_instrumentation_failed",
            None,
        ),
        (
            1,
            "[e-acsl] Failure: unbound logic variable foo\n",
            "e-acsl-gcc: fatal error: aborted by Frama-C\n",
            "eacsl_instrumentation_failed",
            None,
        ),
    ],
)
def test_compile_eacsl_binary_distinguishes_stage_kill_from_frama_c_error(
    tmp_path, monkeypatch, rc, stdout, stderr, expected_reason, expected_flag
):
    import subprocess

    src = tmp_path / "m.c"
    src.write_text("int f(int x) { return x; }\n", encoding="utf-8")
    monkeypatch.setattr(fuzz_build, "_resolve_eacsl_gcc", lambda: ("e-acsl-gcc", True))

    def fake_runner(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, rc, stdout=stdout, stderr=stderr)

    res = fuzz_build.compile_eacsl_binary([str(src)], tmp_path / "guard_m", runner=fake_runner, use_cache=False)
    assert res["returncode"] == rc
    assert res["reason"] == expected_reason
    if expected_flag:
        assert res.get(expected_flag) is True
    else:
        assert not res.get("killed") and not res.get("killed_suspected")
