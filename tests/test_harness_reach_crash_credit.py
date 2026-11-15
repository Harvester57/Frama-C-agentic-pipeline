"""
Crash-credited dynamic reach (harness_reach.py `_crashed_entry_points`) credits an entry point only when
the crash proves the entry's body ran under the current harness. Regression tests for the post-run review
of QCBOR run-6 (scenarios A-G of the review, re-expressed where the review's own fixture could not tell).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

import harness_reach
import phase0_gates
from test_harness_reach import (
    _coverage,
    _dag,
    _dynamic_doc,
    _harness_identity,
    _run_dir,
    _write_fuzz_report,
    _write_harness,
)

pytestmark = pytest.mark.unit

TWO_CASES = [
    {"selector": 0, "kind": "single", "entry": "rec_parse", "calls": ["rec_parse"], "inits": []},
    {"selector": 1, "kind": "single", "entry": "rec_put", "calls": ["rec_put"], "inits": []},
]


def _row(run: Path, hdir: Path, fdir: Path, dag: dict | None = None) -> dict:
    dag = dag or _dag()
    mm = harness_reach.ModuleMap(dag, harness_reach.load_sidecars(hdir))
    cov = json.loads((run / "workspace/reports/coverage/api.json").read_text(encoding="utf-8"))
    return harness_reach.check_dynamic("api", dag, mm, cov, fuzz_dir=fdir, harnesses_dir=hdir)


def _crash(run: Path, name: str, data: bytes) -> str:
    p = run / "workspace" / "crashes" / "api" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return f"workspace/crashes/api/{name}"


def _dispatch(run: Path, api_cases: list[dict]) -> Path:
    hdir = _write_harness(
        run,
        "rec_parse(fuzz_buf, fuzz_len); rec_put(fuzz_buf, fuzz_len, 1);",
        reach_exempt={"rec_print": "debug output"},
        entry_style="dispatch",
        dispatch_case_count=len(api_cases),
        api_cases=api_cases,
    )
    harness_reach.record_exempt(hdir, "tools", None, "examples")
    assert harness_reach.main(["check", "--harness-dir", str(hdir)]) == 0
    return hdir


def _crash_art(art: str, function: str | None, **extra: Any) -> dict[str, Any]:
    failure = {"function": function, "file": "workspace/work/src/api.c", "line": 4} if function else None
    return {"artifact": art, "reproducible": True, "kind": "crash", "failure": failure, **extra}


def _set_mtime(path: Path, when: float) -> None:
    os.utime(path, (when, when))


# --- A: the harness body ------------------------------------------------------------------------


def test_a_crash_in_the_harness_body_before_the_call_is_not_reach(tmp_path, monkeypatch):
    # The harness's own argument preparation crashes before the call. parse_sanitizer_failure falls
    # back to the harness frame: LLVMFuzzerTestOneInput, in the harness file.
    run = _run_dir(tmp_path, monkeypatch)
    hdir = _dispatch(run, TWO_CASES)
    art = _crash(run, "crash-harness", b"\x01\x00")  # case 1: rec_put, no inits
    _coverage(run, {"rec_parse": 10, "rec_put": 0})
    failure = {"function": "LLVMFuzzerTestOneInput", "file": "workspace/harnesses/harness_api.c", "line": 12}
    fdir = _write_fuzz_report(run, "api", [{**_crash_art(art, None), "failure": failure}])
    row = _row(run, hdir, fdir)
    assert row["crashed_entry_points"] == [], row
    assert row["gaps"] == ["rec_put"]


# --- B: init helpers ------------------------------------------------------------------------------


def test_b_crash_in_an_init_helper_shared_with_the_entry_closure_is_not_reach(tmp_path, monkeypatch):
    # rec_ok is an init helper of the case AND a callee of rec_parse: the crash may be in the init call.
    run = _run_dir(tmp_path, monkeypatch)
    cases = [
        {"selector": 0, "kind": "single", "entry": "rec_put", "calls": ["rec_put"], "inits": []},
        {
            "selector": 1,
            "kind": "single",
            "entry": "rec_parse",
            "calls": ["rec_parse"],
            "inits": [{"fn": "rec_ok", "call": 1, "for": {"call": 0, "param": 0}}],
        },
    ]
    hdir = _dispatch(run, cases)
    art = _crash(run, "crash-init", b"\x01\x00")
    _coverage(run, {"rec_parse": 0, "rec_put": 10})
    fdir = _write_fuzz_report(run, "api", [_crash_art(art, "rec_ok")])
    assert _row(run, hdir, fdir)["crashed_entry_points"] == []

    # A callee only the entry reaches still credits it, inits or not.
    fdir = _write_fuzz_report(run, "api", [_crash_art(art, "rec_check")])
    assert _row(run, hdir, fdir)["crashed_entry_points"] == ["rec_parse"]


# --- C: another harness / case count --------------------------------------------------------------


def _three_case_run(tmp_path: Path, monkeypatch) -> tuple[Path, Path, dict]:
    # The campaign ran a 2-case harness: byte 0x02 selected case 0 (rec_put). A case was appended
    # (3 cases, as run-6 went 181 -> 182): the same file now selects case 2 (rec_parse), and the
    # recorded failure function (rec_ok) is in rec_parse's closure.
    run = _run_dir(tmp_path, monkeypatch)
    dag = _dag()
    dag["functions"]["rec_put"]["internal_callees"] = ["rec_ok"]
    (run / "workspace/reports/callgraph_dag.json").write_text(json.dumps(dag), encoding="utf-8")
    hdir = _dispatch(
        run,
        [
            {"selector": 0, "kind": "single", "entry": "rec_put", "calls": ["rec_put"], "inits": []},
            {"selector": 1, "kind": "single", "entry": "rec_put", "calls": ["rec_put"], "inits": []},
            {"selector": 2, "kind": "single", "entry": "rec_parse", "calls": ["rec_parse"], "inits": []},
        ],
    )
    _coverage(run, {"rec_parse": 0, "rec_put": 10})
    return run, hdir, dag


def test_c_crash_recorded_under_another_case_count_is_not_reach(tmp_path, monkeypatch):
    run, hdir, dag = _three_case_run(tmp_path, monkeypatch)
    art = _crash(run, "crash-old", b"\x02\x00")  # 2 % 2 == 0 when recorded; 2 % 3 == 2 now
    fdir = _write_fuzz_report(run, "api", [_crash_art(art, "rec_ok", dispatch_case_count=2)])
    row = _row(run, hdir, fdir, dag)
    assert row["crashed_entry_points"] == [], row
    note = " ".join(row["crash_notes"])
    assert "crash-old" in note and "2 dispatch cases" in note and "case 0" in note, note

    # Even a crash in the entry itself is not credited from another harness.
    fdir = _write_fuzz_report(run, "api", [_crash_art(art, "rec_parse", harness_digest="0" * 64)])
    row = _row(run, hdir, fdir, dag)
    assert row["crashed_entry_points"] == []
    assert any("another harness" in n for n in row["crash_notes"]), row["crash_notes"]


def test_c_an_unstamped_report_counts_only_when_newer_than_the_harness(tmp_path, monkeypatch):
    run, hdir, dag = _three_case_run(tmp_path, monkeypatch)
    art = _crash(run, "crash-legacy", b"\x02\x00")
    fdir = _write_fuzz_report(run, "api", [_crash_art(art, "rec_ok")], stamp=False)
    report = fdir / "api.json"
    harness = hdir / "harness_api.c"
    sidecar = hdir / "harness_api.json"
    now = report.stat().st_mtime

    # Written before the harness was last changed (the case was appended after the campaign).
    _set_mtime(report, now - 100)
    for p in (harness, sidecar):
        _set_mtime(p, now)
    row = _row(run, hdir, fdir, dag)
    assert row["crashed_entry_points"] == []
    assert any("older than the harness" in n for n in row["crash_notes"]), row["crash_notes"]

    # Written after: the campaign fuzzed this harness.
    _set_mtime(report, now + 100)
    assert _row(run, hdir, fdir, dag)["crashed_entry_points"] == ["rec_parse"]

    # An artifact without the fields in a report that has them (a carried-over crash of unknown origin).
    doc = json.loads(report.read_text(encoding="utf-8"))
    doc.update(_harness_identity(run, "api"))
    report.write_text(json.dumps(doc), encoding="utf-8")
    _set_mtime(report, now + 100)
    assert _row(run, hdir, fdir, dag)["crashed_entry_points"] == []


# --- D: unchanged, the seed-only repair path --------------------------------------------------------


def test_d_seed_only_repair_clears_the_gate_end_to_end(tmp_path, monkeypatch):
    run = _run_dir(tmp_path, monkeypatch)
    hdir = _write_harness(
        run,
        "rec_parse(fuzz_buf, fuzz_len); rec_put(fuzz_buf, fuzz_len, 1);",
        reach_exempt={"rec_print": "debug output"},
    )
    harness_reach.record_exempt(hdir, "tools", None, "examples")
    assert harness_reach.main(["check", "--harness-dir", str(hdir)]) == 0
    _coverage(run, {"rec_parse": 20, "rec_put": 0})
    assert harness_reach.main(["dynamic", "--module", "api"]) == 1
    gate = ["check", "--run-dir", str(run), "--module", "api", "--need", "reach"]
    assert phase0_gates.main(gate) == 1
    assert phase0_gates.main([*gate, "--allow-dynamic-gap"]) == 0
    _coverage(run, {"rec_parse": 20, "rec_put": 3})
    assert harness_reach.main(["dynamic", "--module", "api"]) == 0
    assert phase0_gates.main(gate) == 0
    assert phase0_gates.check(run, None, ("reach",)) == []
    assert _dynamic_doc(run)["modules"]["api"]["gaps"] == []


# --- E: custom and sequence cases -------------------------------------------------------------------


def test_e_custom_or_sequence_case_is_credited_only_on_direct_evidence(tmp_path, monkeypatch):
    # A repair case added with --dispatch-case is `custom` (no calls); a stateful case is `sequence`.
    run = _run_dir(tmp_path, monkeypatch)
    cases = [
        {"selector": 0, "kind": "single", "entry": "rec_put", "calls": ["rec_put"], "inits": []},
        {"selector": 1, "kind": "custom", "calls": [], "slots": [], "rest": None},
        {"selector": 2, "kind": "sequence", "calls": ["rec_put", "rec_parse"], "inits": []},
    ]
    hdir = _dispatch(run, cases)
    custom = _crash(run, "crash-custom", b"\x01\x00")
    seq = _crash(run, "crash-seq", b"\x02\x00")
    _coverage(run, {"rec_parse": 0, "rec_put": 10})

    # A callee of rec_parse: which call of the case reached it is unknown, so the gap stays and says why.
    fdir = _write_fuzz_report(run, "api", [_crash_art(custom, "rec_check"), _crash_art(seq, "rec_check")])
    row = _dynamic_row(run, hdir, fdir)
    assert row["crashed_entry_points"] == [] and row["gaps"] == ["rec_parse"]
    notes = " ".join(row["crash_notes"])
    assert "custom case 1" in notes and "sequence case 2" in notes, notes

    # The failure in the entry itself is direct evidence.
    fdir = _write_fuzz_report(run, "api", [_crash_art(custom, "rec_parse")])
    assert _row(run, hdir, fdir)["crashed_entry_points"] == ["rec_parse"]


def _dynamic_row(run: Path, hdir: Path, fdir: Path) -> dict:
    """The row `harness_reach.py dynamic` records (schema-checked) for module api."""
    harness_reach.main(["dynamic", "--module", "api", "--harnesses", str(hdir), "--fuzz-dir", str(fdir)])
    doc = _dynamic_doc(run)
    assert "warnings" not in doc, doc.get("warnings")
    return doc["modules"]["api"]


# --- F: stack evidence in the real report shape ------------------------------------------------------


def _plain_harness(run: Path) -> Path:
    hdir = _write_harness(
        run,
        "rec_parse(fuzz_buf, fuzz_len); rec_put(fuzz_buf, fuzz_len, 1);",
        reach_exempt={"rec_print": "debug output"},
    )
    harness_reach.record_exempt(hdir, "tools", None, "examples")
    assert harness_reach.main(["check", "--harness-dir", str(hdir)]) == 0
    return hdir


TAIL = (
    "==12==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000011\n"
    "    #0 0x1 in rec_check /framac-run/workspace/work/src/api.c:4:40\n"
    "    #1 0x2 in rec_parse /framac-run/workspace/work/src/api.c:8:38\n"
    "    #2 0x3 in LLVMFuzzerTestOneInput /framac-run/workspace/harnesses/harness_api.c:3:1\n"
    "    #3 0x4 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/framac-run/fuzz_api+0x7b53a)\n"
)


def test_f_non_dispatch_harness_callee_crash_counts_from_the_replay_stack(tmp_path, monkeypatch):
    # Reports written before `frames` carry the replay's stack in `replay_log_tail`.
    run = _run_dir(tmp_path, monkeypatch)
    hdir = _plain_harness(run)
    art = _crash(run, "crash-plain", b"\x00\x00")
    _coverage(run, {"rec_parse": 0, "rec_put": 0})
    fdir = _write_fuzz_report(run, "api", [_crash_art(art, "rec_check", replay_log_tail=TAIL)])
    assert _row(run, hdir, fdir)["crashed_entry_points"] == ["rec_parse"]

    # A campaign records the frames themselves; a frame of the E-ACSL wrapper is not the body.
    frames = [
        {"function": "rec_check", "file": "/framac-run/workspace/work/src/api.c", "line": 4},
        {"function": "__gen_e_acsl_rec_put", "file": "/framac-run/fuzz_api.instrumented.c", "line": 90},
        {"function": "rec_parse", "file": "/framac-run/workspace/work/src/api.c", "line": 8},
    ]
    fdir = _write_fuzz_report(run, "api", [_crash_art(art, "rec_check", frames=frames, replay_log_tail="")])
    assert _row(run, hdir, fdir)["crashed_entry_points"] == ["rec_parse"]

    # A name that merely contains the entry's name is not a frame of it.
    tail = TAIL.replace(" rec_parse ", " rec_parse_all ")
    fdir = _write_fuzz_report(run, "api", [_crash_art(art, "rec_check", replay_log_tail=tail)])
    assert _row(run, hdir, fdir)["crashed_entry_points"] == []


# --- G: E-ACSL preconditions ------------------------------------------------------------------------


def test_g_eacsl_precondition_failure_is_not_body_execution(tmp_path, monkeypatch):
    # E-ACSL checks a contract's `requires` in __gen_e_acsl_<fn>, before it calls <fn>. The runtime
    # names the function by its source name (`.fct`), so the report says rec_put / precondition.
    run = _run_dir(tmp_path, monkeypatch)
    hdir = _dispatch(run, TWO_CASES)
    art = _crash(run, "crash-pre", b"\x01\x00")
    _coverage(run, {"rec_parse": 10, "rec_put": 0})
    wrapper = {"function": "__gen_e_acsl_rec_put", "file": "unknown", "line": 0, "kind": "eacsl_runtime_error"}
    for failure in (
        wrapper,
        {"function": "rec_put", "file": "src/api.c", "line": 44, "kind": "precondition"},
    ):
        fdir = _write_fuzz_report(run, "api", [{**_crash_art(art, None), "failure": failure}])
        assert _row(run, hdir, fdir)["crashed_entry_points"] == [], failure

    # The wrapper's own RTE checks before the call (`\initialized` of a formal) also carry the source
    # name; the replay stack shows the wrapper and no frame of the body.
    rte = {"function": "rec_put", "file": "src/api.c", "line": 44, "kind": "e-acsl_rte"}
    wrapper_stack = [
        {"function": "__gen_e_acsl_rec_put", "file": "/framac-run/fuzz_api.instrumented.c", "line": 90},
        {"function": "rec_parse_all", "file": "/framac-run/workspace/work/src/api.c", "line": 9},
    ]
    fdir = _write_fuzz_report(run, "api", [{**_crash_art(art, None), "failure": rte, "frames": wrapper_stack}])
    assert _row(run, hdir, fdir)["crashed_entry_points"] == []
    body_stack = [{"function": "rec_put", "file": "/framac-run/workspace/work/src/api.c", "line": 45}, *wrapper_stack]
    fdir = _write_fuzz_report(run, "api", [{**_crash_art(art, None), "failure": rte, "frames": body_stack}])
    assert _row(run, hdir, fdir)["crashed_entry_points"] == ["rec_put"]

    # A postcondition is checked after the body returned.
    post = {"function": "rec_put", "file": "src/api.c", "line": 44, "kind": "postcondition"}
    fdir = _write_fuzz_report(run, "api", [{**_crash_art(art, None), "failure": post}])
    assert _row(run, hdir, fdir)["crashed_entry_points"] == ["rec_put"]

    # The precondition of a callee fails inside the entry's body: the entry ran.
    cases = [
        {"selector": 0, "kind": "single", "entry": "rec_put", "calls": ["rec_put"], "inits": []},
        {"selector": 1, "kind": "single", "entry": "rec_parse", "calls": ["rec_parse"], "inits": []},
    ]
    hdir = _dispatch(run, cases)
    _coverage(run, {"rec_parse": 0, "rec_put": 10})
    pre = {"function": "rec_check", "file": "src/api.c", "line": 37, "kind": "precondition"}
    fdir = _write_fuzz_report(run, "api", [{**_crash_art(art, None), "failure": pre}])
    assert _row(run, hdir, fdir)["crashed_entry_points"] == ["rec_parse"]


# --- replay on QCBOR run-6 data ----------------------------------------------------------------------

RUN6 = Path(__file__).parent / "fixtures" / "qcbor_run6_reach"
RUN6_MODULE = "libqcbor_a"
# What the F2 gate credited on run-6 with the right case count (182); each is a frame of an artifact's
# replay stack or the failure function itself (post-run review, 2026-11-15).
RUN6_CORRECT = [
    "QCBORDecode_GetBool",
    "QCBORDecode_GetInt64ConvertAll",
    "QCBORDecode_GetNextTagNumber",
    "QCBORDecode_GetTBigFloatBigMantissa",
    "QCBORDecode_GetTBigNumberRaw",
    "QCBORDecode_GetTEpochDate",
    "QCBORDecode_GetTEpochDays",
    "QCBORDecode_GetUInt64ConvertAll",
    "QCBORDecode_Private_ConsumeItem",
    "QCBORDecode_Private_EnterBoundedMapOrArray",
    "QCBORDecode_Private_GetArrayOrMap",
    "QCBORDecode_Private_GetDoubleConvert",
    "QCBORDecode_Private_GetInt64Convert",
    "QCBORDecode_Private_GetString",
    "QCBORDecode_Private_ProcessTagItem",
    "QCBORDecode_VGetNext",
    "QCBORDecode_VGetNextConsume",
    "QCBOREncode_EncodeHead",
    "QCBOREncode_Private_AddPreferredDouble",
    "QCBOREncode_Private_AddPreferredFloat",
    "QCBOREncode_Private_AddTBigNumberMain",
    "QCBOREncode_Private_AddTExpBigMantissa",
    "QCBOREncode_Private_AppendCBORHead",
    "UsefulOutBuf_AppendUsefulBuf",
    "UsefulOutBuf_Compare",
]


def _run6(tmp_path: Path, monkeypatch, n_cases: int = 182, stamp: bool = True) -> tuple[list[str], list[str], dict]:
    """
    A run dir holding the trimmed run-6 DAG, sidecar and fuzz report, the crash files (first byte as
    recorded, the rest irrelevant) and a harness of `n_cases` cases. With `stamp`, the report is the
    one a campaign on the 182-case harness writes. Returns the gate's credits over every entry point.
    """
    tmp_path.mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(tmp_path)
    hdir = tmp_path / "workspace" / "harnesses"
    fdir = tmp_path / "workspace" / "reports" / "fuzz"
    hdir.mkdir(parents=True)
    fdir.mkdir(parents=True)
    dag = json.loads((RUN6 / "callgraph_dag.json").read_text(encoding="utf-8"))
    sidecar = json.loads((RUN6 / f"harness_{RUN6_MODULE}.json").read_text(encoding="utf-8"))
    report = json.loads((RUN6 / f"fuzz_{RUN6_MODULE}.json").read_text(encoding="utf-8"))

    def write_harness(n: int) -> str | None:
        side = {**sidecar, "dispatch_case_count": n, "api_cases": sidecar["api_cases"][:n]}
        (hdir / f"harness_{RUN6_MODULE}.json").write_text(json.dumps(side), encoding="utf-8")
        (hdir / f"harness_{RUN6_MODULE}.c").write_text(f"/* {n} cases */\n", encoding="utf-8")
        return phase0_gates.harness_digest(tmp_path, RUN6_MODULE, ignore_exempt=True)

    found_digest = write_harness(182)
    for art in report["artifacts"]:
        path = tmp_path / art["artifact"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(bytes([art.pop("first_byte")]) + b"\x00")
        if stamp:
            art.update(harness_digest=found_digest, dispatch_case_count=182)
    if stamp:
        report.update(harness_digest=found_digest, dispatch_case_count=182)
    (fdir / f"{RUN6_MODULE}.json").write_text(json.dumps(report), encoding="utf-8")
    when = (fdir / f"{RUN6_MODULE}.json").stat().st_mtime
    if n_cases != 182:
        write_harness(n_cases)
        _set_mtime(hdir / f"harness_{RUN6_MODULE}.c", when + 60)  # the case changed after the campaign
    else:
        _set_mtime(hdir / f"harness_{RUN6_MODULE}.c", when - 60)  # the campaign fuzzed this harness

    current = json.loads((hdir / f"harness_{RUN6_MODULE}.json").read_text(encoding="utf-8"))
    mm = harness_reach.ModuleMap(dag, {RUN6_MODULE: current})
    entries = harness_reach._module_entries(RUN6_MODULE, dag, mm)
    credited, notes = harness_reach._crashed_entry_points(
        RUN6_MODULE,
        entries,
        dag,
        current,
        fdir,
        harness_reach._candidate_roots(fdir, hdir),
        harness_digest=phase0_gates.harness_digest(tmp_path, RUN6_MODULE, ignore_exempt=True),
        harness_file=hdir / f"harness_{RUN6_MODULE}.c",
    )
    return credited, notes, report


def test_run6_crashes_credit_the_entries_they_ran_under_182_cases(tmp_path, monkeypatch):
    credited, _, report = _run6(tmp_path, monkeypatch)
    assert set(RUN6_CORRECT) <= set(credited), sorted(set(RUN6_CORRECT) - set(credited))
    # Every further credit is an entry point on some artifact's replay stack (exact name).
    on_stack = {
        m.group("function")
        for art in report["artifacts"]
        for m in harness_reach._STACK_FRAME_RE.finditer(art.get("replay_log_tail") or "")
    }
    assert set(credited) - set(RUN6_CORRECT) <= on_stack, sorted(set(credited) - set(RUN6_CORRECT) - on_stack)


def test_run6_crashes_credit_nothing_once_the_harness_has_181_cases(tmp_path, monkeypatch):
    credited, notes, _ = _run6(tmp_path, monkeypatch, n_cases=181)
    assert credited == []
    assert any("found under 182 dispatch cases, case 57; the harness now has 181 dispatch cases, case 58" in n for n in notes), notes[:3]


def test_run6_unstamped_report_older_than_the_harness_credits_nothing(tmp_path, monkeypatch):
    credited, notes, _ = _run6(tmp_path, monkeypatch, n_cases=181, stamp=False)
    assert credited == []
    assert all("older than the harness" in n for n in notes[:-1]), notes[:3]
    # The same report, newer than the (182-case) harness it was written for, still counts.
    credited, _, _ = _run6(tmp_path / "again", monkeypatch, stamp=False)
    assert set(RUN6_CORRECT) <= set(credited)


# --- reproducibility ---------------------------------------------------------------------------------


def test_an_artifact_without_a_reproducible_verdict_is_not_reach(tmp_path, monkeypatch):
    run = _run_dir(tmp_path, monkeypatch)
    hdir = _dispatch(run, TWO_CASES)
    art = _crash(run, "crash-unreplayed", b"\x01\x00")
    _coverage(run, {"rec_parse": 10, "rec_put": 0})
    unreplayed = {k: v for k, v in _crash_art(art, "rec_put").items() if k != "reproducible"}
    fdir = _write_fuzz_report(run, "api", [unreplayed])
    assert _row(run, hdir, fdir)["crashed_entry_points"] == []
    fdir = _write_fuzz_report(run, "api", [{**unreplayed, "reproducible": None}])
    assert _row(run, hdir, fdir)["crashed_entry_points"] == []
