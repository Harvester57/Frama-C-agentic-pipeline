"""
The recursion fallback of run_eva_slice.py (`-eva-warn-key assigns:missing=warning`) is for recursive
calls and callback cycles without an assigns clause. The same warning key also fires on a contract
(a stub) whose assigns clause has no \\from, where Eva assumes `\\from \\nothing`; that must fail the run
with the function and the clause named, never be retried and recorded under the recursion label.

The logs under tests/fixtures/eva_assigns/ are Eva's own output (Frama-C in framac-analysis:latest, the
pipeline's command line from run_eva_slice._eva_command) on the sources in tests/fixtures/eva_assigns/src/:
  a_stub   a spec-only stub `assigns *p, \\result;` called from eva_main
  b_rec    a recursive function without any ACSL
  c_both   both
  d_cycle  a recursion cycle through a function pointer
  e_epoll  the epoll_wait clause of the c-ares run-1 overlay (a range) and a second stub called twice
`*_default.log` is the run that aborts, `*_downgraded.log` the run with the warning key downgraded
(a, b, c and d).
The Docker test (FRAMAC_DOCKER_TESTS=1) runs run_eva_slice.py itself on those sources.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess

import pytest

import run_eva_slice
from conftest import ANALYSIS_IMAGE, ROOT, require_docker_images

ASSIGNS_FIXTURES = ROOT / "tests" / "fixtures" / "eva_assigns"
RECURSION_LABEL = "-eva-warn-key assigns:missing=warning (recursive calls use kernel-inferred assigns)"


def _log(name: str) -> str:
    return (ASSIGNS_FIXTURES / f"{name}.log").read_text(encoding="utf-8")


def _fake_execute(default_log: str, downgraded_log: str, calls: list):
    """An _execute_eva that writes the captured log of the default or the downgraded run."""

    def fake(cmd, sources, main_fn, out_dir, reduced_checks, timeout, path_root=None):
        calls.append((list(cmd), list(reduced_checks)))
        downgraded = "-eva-warn-key" in cmd
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "eva.log").write_text(_log(downgraded_log if downgraded else default_log), encoding="utf-8")
        if downgraded:
            return {"status": "ok", "reason": None, "error_summary": [], "reduced_checks": reduced_checks}
        return {
            "status": "analysis_error",
            "reason": "exit_1",
            "error_summary": ["[kernel] Plug-in eva aborted: invalid user input."],
            "reduced_checks": reduced_checks,
        }

    return fake


@pytest.fixture
def eva_no_cache(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(run_eva_slice, "_input_digest", lambda sources, flags: "d")
    return tmp_path


# ---------------------------------------------------------------------------------------------------
# Log classification on Eva's captured messages
# ---------------------------------------------------------------------------------------------------


def test_classifies_eva_assigns_missing_messages():
    kinds = {
        name: [(e["kind"], e["location"], e["function"], e["clause"]) for e in
               run_eva_slice.missing_assigns_messages(_log(name))]
        for name in ("a_stub_default", "b_rec_default", "c_both_default", "c_both_downgraded", "d_cycle_default")
    }  # fmt: skip
    stub = ("stub_from", "/target/stub.h:4", "fill", "assigns *p;")
    assert kinds["a_stub_default"] == [stub]
    assert kinds["b_rec_default"] == [("recursion", "/target/b_rec.c:5", "depth", None)]
    both = [stub, ("recursion", "/target/c_both.c:7", "depth", None)]
    assert kinds["c_both_default"] == both
    assert kinds["c_both_downgraded"] == both
    # A cycle through a function pointer prints the same message as direct recursion.
    assert kinds["d_cycle_default"] == [("recursion", "/target/d_cycle.c:13", "walk", None)]


def test_range_clause_and_a_stub_called_twice_are_each_named_once():
    entries = run_eva_slice.missing_assigns_messages(_log("e_epoll_default"))
    assert [(e["kind"], e["location"], e["function"], e["clause"]) for e in entries] == [
        ("stub_from", "/target/epoll_stub.h:22", "fill_two", "assigns *out;"),
        ("stub_from", "/target/epoll_stub.h:14", "epoll_wait", "assigns *(__events + (0 .. __maxevents - 1));"),
    ]


def test_function_name_is_read_from_the_declaration_when_the_file_is_there(tmp_path):
    header = tmp_path / "epoll.h"
    header.write_text(
        "/*@\n  requires positive_maxevents: __maxevents > 0;\n"
        "  assigns __events[0 .. __maxevents - 1], \\result;\n*/\n"
        "extern __attribute__((__nothrow__)) int epoll_wait(int __epfd, struct epoll_event *__events,\n"
        "    int __maxevents, int __timeout) __attribute__(( __access__(__write_only__,2,3)));\n",
        encoding="utf-8",
    )
    log = (
        "[eva] using specification for function something_else\n"
        "[eva] Analyzing an unrelated call\n"
        f"[eva:assigns:missing] {header.as_posix()}:3: User Error: \n"
        "  no \\from part for clause 'assigns *(__events + (0 .. __maxevents - 1));'.\n"
        "  Assuming \\from \\nothing so that the analysis can continue, but be aware this is probably incorrect.\n"
    )
    (entry,) = run_eva_slice.missing_assigns_messages(log)
    assert entry["function"] == "epoll_wait"
    # A line contract names the prototype right below it, not one after a later `*/`.
    line_header = tmp_path / "line.h"
    line_header.write_text(
        "//@ assigns *out;\nvoid first(int *out);\n/*@ assigns \\nothing; */\nvoid second(void);\n",
        encoding="utf-8",
    )
    line_log = (
        f"[eva:assigns:missing] {line_header.as_posix()}:1: User Error: \n"
        "  no \\from part for clause 'assigns *out;'.\n"
    )
    (entry,) = run_eva_slice.missing_assigns_messages(line_log)
    assert entry["function"] == "first"
    # Without the file and without an adjacent `using specification` line, no name is guessed.
    log_elsewhere = log.replace(header.as_posix(), "/nowhere/epoll.h")
    (entry,) = run_eva_slice.missing_assigns_messages(log_elsewhere)
    assert entry["function"] is None
    assert run_eva_slice.stub_from_defect_message(entry).startswith("stub contract at /nowhere/epoll.h:3 lacks")


# ---------------------------------------------------------------------------------------------------
# The retry and the failure, through run_eva_on_slice
# ---------------------------------------------------------------------------------------------------


def test_stub_without_from_fails_instead_of_retrying_under_the_recursion_label(eva_no_cache):
    calls: list = []
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(run_eva_slice, "_execute_eva", _fake_execute("a_stub_default", "a_stub_downgraded", calls))
        res = run_eva_slice.run_eva_on_slice(["a.c"], "eva_main", eva_no_cache / "out", use_cache=False)
    assert len(calls) == 1, "a contract without \\from must not be retried with the recursion downgrade"
    assert res["status"] == "analysis_error"
    assert res["reason"] == "stub_assigns_without_from"
    assert RECURSION_LABEL not in res["reduced_checks"]
    assert not res.get("auto_recursion_fallback")
    first = res["error_summary"][0]
    assert first.startswith("stub contract of fill at /target/stub.h:4 lacks \\from for 'assigns *p;'")
    assert "add a \\from clause" in first
    assert res["stub_assigns_without_from"] == [
        {"function": "fill", "location": "/target/stub.h:4", "clause": "assigns *p;"}
    ]


@pytest.mark.parametrize("case", ["b_rec", "d_cycle"])
def test_recursion_and_callback_cycles_are_still_retried(eva_no_cache, case):
    calls: list = []
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(run_eva_slice, "_execute_eva", _fake_execute(f"{case}_default", f"{case}_downgraded", calls))
        res = run_eva_slice.run_eva_on_slice(["a.c"], "eva_main", eva_no_cache / "out", use_cache=False)
    assert len(calls) == 2
    assert "-eva-warn-key" in calls[1][0]
    assert res["status"] == "ok"
    assert res["auto_recursion_fallback"] is True
    assert RECURSION_LABEL in res["reduced_checks"]


def test_recursion_downgrade_does_not_hide_a_stub_defect_in_the_same_run(eva_no_cache):
    calls: list = []
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(run_eva_slice, "_execute_eva", _fake_execute("c_both_default", "c_both_downgraded", calls))
        res = run_eva_slice.run_eva_on_slice(["a.c"], "eva_main", eva_no_cache / "out", use_cache=False)
    assert len(calls) == 1
    assert res["status"] == "analysis_error"
    assert res["reason"] == "stub_assigns_without_from"
    assert "stub contract of fill at /target/stub.h:4" in res["error_summary"][0]
    assert any("depth" in line and "recursion fallback" in line for line in res["error_summary"])


def test_explicit_recursion_fallback_still_fails_on_a_stub_without_from(eva_no_cache):
    calls: list = []
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(run_eva_slice, "_execute_eva", _fake_execute("c_both_default", "c_both_downgraded", calls))
        res = run_eva_slice.run_eva_on_slice(
            ["a.c"], "eva_main", eva_no_cache / "out", allow_incomplete_recursion_specs=True, use_cache=False
        )
    assert len(calls) == 1 and "-eva-warn-key" in calls[0][0]
    assert res["status"] == "analysis_error"
    assert res["reason"] == "stub_assigns_without_from"


def test_unknown_assigns_missing_message_is_not_retried(eva_no_cache):
    calls: list = []
    unknown = "[eva:assigns:missing] /target/x.c:3: User Error: \n  some future message about assigns.\n"
    with pytest.MonkeyPatch.context() as mp:
        fake = _fake_execute("b_rec_default", "b_rec_default", calls)

        def fake_unknown(cmd, sources, main_fn, out_dir, reduced_checks, timeout, path_root=None):
            res = fake(cmd, sources, main_fn, out_dir, reduced_checks, timeout, path_root)
            (out_dir / "eva.log").write_text(unknown, encoding="utf-8")
            return res

        mp.setattr(run_eva_slice, "_execute_eva", fake_unknown)
        res = run_eva_slice.run_eva_on_slice(["a.c"], "eva_main", eva_no_cache / "out", use_cache=False)
    assert len(calls) == 1
    assert res["status"] == "analysis_error"


def test_repair_hint_names_the_stub_clause():
    hints = [
        h for h in run_eva_slice.extract_repair_hints(_log("c_both_default")) if h["pattern"] == "stub_missing_from"
    ]
    assert len(hints) == 1
    assert hints[0]["function"] == "fill" and hints[0]["location"] == "/target/stub.h:4"
    assert "workspace/stubs/" in hints[0]["action"]


# ---------------------------------------------------------------------------------------------------
# The second retry site: the cvalue tiers after a timeout
# ---------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("case", ["a_stub", "c_both"])
def test_timeout_fallback_tiers_do_not_downgrade_a_stub_defect(eva_no_cache, case):
    calls: list = []
    with pytest.MonkeyPatch.context() as mp:
        fake = _fake_execute(f"{case}_default", f"{case}_downgraded", calls)

        def fake_timeout_first(cmd, sources, main_fn, out_dir, reduced_checks, timeout, path_root=None):
            res = fake(cmd, sources, main_fn, out_dir, reduced_checks, timeout, path_root)
            if len(calls) == 1:  # the base run: Eva prints the message at once, then runs out of time
                return {**res, "status": "analysis_timeout", "reason": "timeout", "error_summary": ["limit"]}
            return res

        mp.setattr(run_eva_slice, "_execute_eva", fake_timeout_first)
        res = run_eva_slice.run_eva_on_slice(["a.c"], "eva_main", eva_no_cache / "out", timeout=300, use_cache=False)
    assert len(calls) >= 2, "the cvalue tiers ran"
    assert not any("-eva-warn-key" in cmd for cmd, _ in calls), "no tier was retried with the downgrade"
    assert not res.get("auto_recursion_fallback")
    # No tier completed: the result is the timed-out base run's, which names the stub defect too.
    assert res["status"] == "analysis_timeout"
    assert any(line.startswith("stub contract of fill at /target/stub.h:4") for line in res["error_summary"])
    assert res["stub_assigns_without_from"][0]["function"] == "fill"


# ---------------------------------------------------------------------------------------------------
# Docker: run_eva_slice.py itself on the fixture sources, in the analysis image
# ---------------------------------------------------------------------------------------------------


def test_run_eva_slice_in_docker_retries_only_recursion(tmp_path):
    require_docker_images(ANALYSIS_IMAGE)
    work = tmp_path / "w"
    shutil.copytree(ASSIGNS_FIXTURES / "src", work)
    script = "; ".join(
        f"timeout 600 python3 /opt/framac-pipeline/scripts/run_eva_slice.py --sources {src} --main eva_main "
        f"--out-dir out/{case} --out-json out/{case}.json --cppflags=-I/w --timeout 300 --no-timeout-fallback "
        "> /dev/null 2>&1"
        for case, src in (
            ("a", "a_stub.c"),
            ("b", "b_rec.c"),
            ("c", "c_both.c"),
            ("d", "d_cycle.c"),
            ("e", "e_epoll.c"),
        )
    )
    proc = subprocess.run(
        [
            "docker", "run", "--rm", "--network", "none",
            "-v", f"{work}:/w",
            "-v", f"{ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
            "-v", f"{ROOT / 'templates'}:/opt/framac-pipeline/templates:ro",
            "-e", "FRAMAC_CACHE=off",
            "--entrypoint", "bash", ANALYSIS_IMAGE, "-c", f"cd /w; {script}",
        ],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=3600, check=False,
    )  # fmt: skip
    reports = {}
    for case in "abcde":
        path = work / "out" / f"{case}.json"
        assert path.is_file(), proc.stdout + proc.stderr
        reports[case] = json.loads(path.read_text(encoding="utf-8"))
    for case in "ace":
        assert reports[case]["status"] == "analysis_error", case
        assert reports[case]["reason"] == "stub_assigns_without_from", case
        assert RECURSION_LABEL not in reports[case]["reduced_checks"], case
    # Frama-C prints the header relative to the working directory (/w) here.
    assert re.match(r"stub contract of fill at (/w/)?stub\.h:4 lacks ", reports["a"]["error_summary"][0])
    assert {d["function"] for d in reports["e"]["stub_assigns_without_from"]} == {"fill_two", "epoll_wait"}
    for case in "bd":
        assert reports[case]["status"] == "ok", case
        assert reports[case]["auto_recursion_fallback"] is True, case
        assert RECURSION_LABEL in reports[case]["reduced_checks"], case
