r"""Seams between the scripts that write a verdict's limits and the scripts that read them.

The writers (workspace_overlay.py, wp_scheduler.py, crash_replay.py, run_wp_function.py) and the readers
(ledger.py, generate_report.py) were changed by different sessions, each tested against shapes of the other
side written by hand. Here the reader gets what the writer really wrote: every test drives the writer's own
entry point (`merge_agent_overlay`, `merge_agent_batch` under `wp_scheduler.cmd_merge_pending`, `_default_recheck`,
`replay_identity`) and hands the file it left to the reader's own entry point (`ledger.cmd_ingest_wp`,
`ledger.cmd_ingest_verifier`, `generate_report.load_merge_notes`, `verdict_limits_section`).

What stands for tool output is recorded tool output:

- WP: the logs and report CSVs under tests/fixtures/wp_frame_clause/ (see test_wp_frame_clause.py) and under
  tests/fixtures/seam_probe_wp/. The latter are Frama-C's own output (34.0~beta, framac-analysis:latest) for
  `run_wp_function.py --file /target/eacsl_ignored/probe.c --function <fn> --timeout 5 --cache-dir off
  --security-props none`, one run per function (`unb_requires`, `plain`, `via_pred`), cut like the
  wp_frame_clause ones: the log keeps everything up to `[report] Computing properties status...`, the function's
  own section of the `-report` output and the `Status Report Summary`; the CSV keeps the header and the
  function's rows. `run_wp_function.py` is run in-process on them (`main`, with the parent's own command line).
- E-ACSL: the stage 1 captures under tests/fixtures/eacsl_ignored/ (see test_eacsl_ignored_annotations.py),
  read by the guardrail's own functions, on top of the guardrail report recorded there (`unb_requires.json`).
  That report's `reach` is the one of `unb_requires`: for another function it holds no hit count.
- Replays: tests/fixtures/replay_identity/ (see test_verifier_replay_identity.py).

Two things are set by hand, because no recording of them exists: the result of the contract consistency check
(`run_vacuity_check`, another Frama-C run: `consistent`), and the prover's own `result.json` in the scheduler
tests (an agent's output, written by test_wp_scheduler.Sim).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

import crash_replay as C
import eacsl_toolchain as T
import generate_report as G
import ledger as L
import proof_carry
import prover_candidates
import run_eacsl_fuzz as R
import run_wp_function as W
import test_verifier_replay_identity as tvr
import workspace_overlay
import wp_scheduler as S
from conftest import metadata, unit, write_json
from test_wp_scheduler import Sim, tasks

pytestmark = pytest.mark.unit

SEAM_FIXTURES = Path(__file__).resolve().parent / "fixtures"
SEAM_PROBE = SEAM_FIXTURES / "eacsl_ignored"
SEAM_PROBE_WP = SEAM_FIXTURES / "seam_probe_wp"
SEAM_FRAME = SEAM_FIXTURES / "wp_frame_clause"
SEAM_GUARD_PASS = json.loads((SEAM_PROBE / "unb_requires.json").read_text(encoding="utf-8"))
SEAM_VACUITY = {"status": "consistent", "doomed": [], "dead_goals": 0}
SEAM_MODULE = "m"
SEAM_SRC_PROBE = "src/probe.c"
SEAM_SRC_FRAME = "src/frame.c"
SEAM_HDR_FRAME = "src/frame.h"

# The last `ensures` of each probe function's contract: a baseline without it is a contract the prover adds
# a clause to, a baseline with one more clause after it is a contract the prover removes a clause from.
SEAM_LAST_CLAUSES = {
    "unb_requires": "    ensures small: \\result <= 16;\n",
    "plain": "    ensures \\result <= 255 * 16;\n",
    "via_pred": "    requires via: tail_nonneg(n);\n    assigns \\nothing;\n    ensures \\result == (int)n;\n",
}
SEAM_EXTRA_ENSURES = "    ensures seam_extra: \\result >= 0;\n"


def _probe_text(name: str = "probe.c") -> str:
    return (SEAM_PROBE / name).read_text(encoding="utf-8")


def _probe_baseline(fn: str, how: str) -> str:
    """probe.c as the shared tree holds it before the prover of `fn` merges the recorded contract."""
    text, anchor = _probe_text(), SEAM_LAST_CLAUSES[fn]
    assert text.count(anchor) == 1
    if how == "adds_ensures":
        kept = anchor[: anchor.rstrip("\n").rfind("\n") + 1]  # the anchor without its last line, the `ensures`
        return text.replace(anchor, kept)
    assert how == "drops_ensures"
    return text.replace(anchor, anchor + SEAM_EXTRA_ENSURES)


def _contract_swapped(text: str, fn: str, contract: str | None) -> str:
    """`text` with the contract in front of the declaration of `fn` replaced by `contract` (None: none)."""
    lines = text.split("\n")
    at = next(i for i, line in enumerate(lines) if re.match(rf"^\w[\w \*]*\b{fn}\(", line))
    start = at
    if lines[at - 1].rstrip().endswith("*/"):
        start = at - 1
        while not lines[start].lstrip().startswith("/*@"):
            start -= 1
    return "\n".join(lines[:start] + (contract.rstrip("\n").split("\n") if contract else []) + lines[at:])


def _stage(run_dir: Path, texts: dict[str, str], units: list[dict], sources: list[str] | None) -> Path:
    """A run directory with a real overlay of `texts`; `sources`: the harness sidecar's (None: it names none)."""
    target = run_dir.parent / "target"
    for rel_path, text in texts.items():
        path = target / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    overlay = run_dir / "workspace"
    workspace_overlay.init_overlay(target, overlay)
    sidecar = {"module": SEAM_MODULE, "cppflags": "-Isrc", "ldflags": "", **({"sources": sources} if sources else {})}
    write_json(overlay / "harnesses" / f"harness_{SEAM_MODULE}.json", sidecar)
    write_json(run_dir / "run-metadata.json", metadata("in_progress"))
    write_json(run_dir / "coverage-ledger.json", sorted(units, key=lambda u: u["coverage_id"]))
    return overlay


def _agent(run_dir: Path, agent_id: str, texts: dict[str, str]) -> None:
    """The agent's scratch overlay, with `texts` as its result."""
    workspace_overlay.init_agent_overlay(run_dir, agent_id, run_dir / "workspace")
    for rel_path, text in texts.items():
        path = run_dir / "agents" / agent_id / "scratch" / "work" / rel_path
        path.write_text(text, encoding="utf-8", newline="\n")


def _units_of(file: str, fn: str, *classes: str) -> list[dict]:
    return [unit(file, fn, cls, module=SEAM_MODULE) for cls in classes or ("rte", "l3_frame")]


def _ledger() -> list[dict]:
    return json.loads(Path("coverage-ledger.json").read_text(encoding="utf-8"))


def _unit_of(fn: str, cls: str) -> dict:
    return next(u for u in _ledger() if u["function"] == fn and u["obligation_class"] == cls)


def _assumptions(fn: str, cls: str = "rte") -> list[str]:
    """The unit's assumptions, without the one every WP result of these runs carries (its RTE flags)."""
    notes = [a["description"] for a in _unit_of(fn, cls)["assumptions"]]
    return [n for n in notes if not n.startswith("WP run with reduced RTE check flags")]


def _options(argv: list[str], name: str) -> list[str]:
    """The values of `name` in a command line: everything up to the next option."""
    if name not in argv:
        return []
    values: list[str] = []
    for arg in argv[argv.index(name) + 1 :]:
        if arg.startswith("--"):
            break
        values.append(arg)
    return values


class SeamTools:
    """
    What `subprocess.run` answers in these tests, for the three tools a parent re-check starts:

    - `run_wp_function.py ...`: its `main`, in-process, with the same command line (and no cache);
    - Frama-C's WP run inside it: the recorded log and report CSV of the function;
    - `run_eacsl_fuzz.py guardrail ...`: the recorded pass, with the fields the guardrail computes from the
      E-ACSL capture `guard_tag` (`guard_fields=False`: the report as recorded, before it had them;
      `guard_instrumented`: the capture's instrumented file is given to the attribution, as the build gives it;
      `guard_reach=False`: the replay printed no coverage, read by the guardrail's own parser).
    """

    def __init__(
        self,
        monkeypatch: pytest.MonkeyPatch,
        run_dir: Path,
        guard_tag: str | None = None,
        *,
        guard_fields: bool = True,
        guard_instrumented: bool = False,
        guard_reach: bool = True,
    ) -> None:
        self.run_dir = run_dir
        self.guard_tag = guard_tag
        self.guard_fields = guard_fields
        self.guard_instrumented = guard_instrumented
        self.guard_reach = guard_reach
        self.ran: list[str] = []
        self.guard_reports: list[dict] = []
        # One patch: run_wp_function and workspace_overlay share the `subprocess` module.
        monkeypatch.setattr(subprocess, "run", self)
        monkeypatch.setattr(W, "run_vacuity_check", lambda *a, **kw: dict(SEAM_VACUITY))

    def __call__(self, cmd, **_kwargs) -> subprocess.CompletedProcess[str]:
        argv = [str(c) for c in cmd]
        script = next((Path(a).name for a in argv if a.endswith(".py")), "")
        if script == "run_wp_function.py":
            self.ran.append(script)
            rest = argv[argv.index(next(a for a in argv if a.endswith("run_wp_function.py"))) + 1 :]
            code = W.main([*rest, "--cache-dir", "off", "--no-retry-tail", "--no-retry-bitwise", "--no-retry-bytes"])
            return subprocess.CompletedProcess(cmd, code, stdout="", stderr="")
        if script == "run_eacsl_fuzz.py":
            self.ran.append(script)
            report = self.guard_report(_options(argv, "--functions"), _options(argv, "--reach-functions"))
            self.guard_reports.append(report)
            out = Path(argv[argv.index("--out-json") + 1])
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(report), encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        if "-wp" in argv and "-report-csv" in argv:
            fn = argv[argv.index("-wp-fct") + 1]
            recorded = next(d for d in (SEAM_FRAME, SEAM_PROBE_WP) if (d / f"{fn}.log").is_file())
            shutil.copyfile(recorded / f"{fn}.csv", argv[argv.index("-report-csv") + 1])
            log = (recorded / f"{fn}.log").read_text(encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout=log, stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    def ignored(self) -> list[dict]:
        """The build's `ignored_annotations` for the capture, attributed on the run's own work tree."""
        record = (SEAM_PROBE / f"{self.guard_tag}.stage1.log").read_text(encoding="utf-8")
        output = record.split("--- STDOUT ---\n", 1)[1].split("\n--- STDERR ---", 1)[0]
        entries, _frame = T.parse_ignored_annotations(output)
        instrumented = SEAM_PROBE / f"{self.guard_tag}.instrumented.c" if self.guard_instrumented else None
        return T.attribute_ignored_annotations(entries, instrumented, cwd=self.run_dir)

    def guard_report(self, functions: list[str], reach_functions: list[str]) -> dict:
        assert self.guard_tag is not None, "a guardrail ran in a test that expects none"
        report = dict(SEAM_GUARD_PASS)
        if self.guard_fields:
            # run_eacsl_fuzz.main: `checked = [*reach_functions, *functions]`.
            report.update(R.dynamic_oracle_fields(self.ignored(), [*reach_functions, *functions]))
        if not self.guard_reach:
            report["reach"] = R.parse_guardrail_reach("", [*reach_functions, *functions])[0]
        return report


def _merge_probe(run_dir: Path, fn: str, **kwargs) -> dict:
    """The single merge of the recorded contract of `fn` (probe.c), by `prove-<fn>`."""
    return workspace_overlay.merge_agent_overlay(
        run_dir=run_dir,
        agent_id=f"prove-{fn}",
        role="prover",
        overlay_dir=run_dir / "workspace",
        c_file=SEAM_SRC_PROBE,
        function=fn,
        module=SEAM_MODULE,
        sources=None,
        cppflags="-Isrc",
        **kwargs,
    )


def _merged_probe(run_dir: Path, monkeypatch, fn: str, sources: list[str] | None = None, **tool_kw) -> tuple:
    """Stage, merge `fn` and ingest its parent WP report: (merge result, the report, the tools)."""
    _stage(run_dir, {SEAM_SRC_PROBE: _probe_baseline(fn, "adds_ensures"), "src/probe.h": _probe_text("probe.h")},
           _units_of(SEAM_SRC_PROBE, fn), [SEAM_SRC_PROBE] if sources is None else sources)  # fmt: skip
    _agent(run_dir, f"prove-{fn}", {SEAM_SRC_PROBE: _probe_text()})
    tools = SeamTools(monkeypatch, run_dir, **tool_kw)
    res = _merge_probe(run_dir, fn)
    assert res["ok"] is True, res
    # The splice left the recorded source: the captures' line numbers are the tree's.
    assert (run_dir / "workspace" / "work" / SEAM_SRC_PROBE).read_text(encoding="utf-8") == _probe_text()
    report_path = run_dir / res["parent_wp_report"]
    L.cmd_ingest_wp([report_path])
    return res, json.loads(report_path.read_text(encoding="utf-8")), tools


# ---------------------------------------------------------------------------
# Constants and status strings both sides spell
# ---------------------------------------------------------------------------


def test_the_guardrail_pass_status_is_one_string_on_every_side() -> None:
    recorded = SEAM_GUARD_PASS["status"]  # what run_eacsl_fuzz.py wrote
    assert workspace_overlay.GUARDRAIL_PASSED == recorded
    assert L.GUARDRAIL_PASSED_STATUS == recorded and G.GUARDRAIL_PASSED_STATUS is L.GUARDRAIL_PASSED_STATUS
    assert prover_candidates.GUARDRAIL_PASSED == recorded
    assert R.classify_guardrail(0, False, "")["status"] == recorded
    passed = {"status": recorded, "report": "agents/x/scratch/parent_guard_f.json"}
    assert S._merge_notes({"ok": True, "guardrail": passed}) == {}
    assert L.guardrail_limit_note({"guardrail": passed}, "f") is None
    assert proof_carry.carried_guardrail({"ok": True, "guardrail": passed}) == passed


def test_not_run_as_the_overlay_writes_it_is_the_ledgers_and_the_reports_not_run() -> None:
    """`ledger.py` and `generate_report.py` spell `not_run` inline: the branch they take is what is pinned."""
    not_run = workspace_overlay.guardrail_not_run("module m names no sources")
    assert not_run["status"] == workspace_overlay.GUARDRAIL_NOT_RUN
    note = L.guardrail_limit_note({"guardrail": not_run}, "f")
    assert note is not None and note.startswith("No E-ACSL guardrail ran for the WP result credited for f (module m")
    other = L.guardrail_limit_note({"guardrail": {"status": "guardrail_error", "reason": "r"}}, "f")
    assert other is not None and "did not pass (status `guardrail_error`, r)" in other
    assert S._merge_notes({"ok": True, "guardrail": not_run}) == {"guardrail": not_run}
    wp_evidence = {"phase": "wp", "details": {"limits": {"guardrail": not_run}}}
    lines = G.verdict_limits_section([{"file": "a.c", "function": "f", "evidence": [wp_evidence]}])
    assert "  - `a.c#f`: module m names no sources" in lines  # no `status ...` prefix: the not_run branch


def test_the_frame_states_are_one_vocabulary() -> None:
    states = {W.ASSIGNS_PRESENT, W.ASSIGNS_BEHAVIORS_ONLY, W.ASSIGNS_ABSENT, W.ASSIGNS_UNKNOWN}
    assert states == {"present", "behaviors_only", "absent", "unknown"}
    assert set(workspace_overlay.NO_FRAME_STATES) == {W.ASSIGNS_ABSENT, W.ASSIGNS_BEHAVIORS_ONLY}
    expected = {
        W.ASSIGNS_PRESENT: None,
        W.ASSIGNS_ABSENT: "wp_no_frame_clause",
        W.ASSIGNS_BEHAVIORS_ONLY: "wp_no_frame_clause",
        W.ASSIGNS_UNKNOWN: "wp_frame_not_shown",
    }
    for state, result in expected.items():
        frame = {"assigns_clause": state, "assigns_vcs_proven": True, "assigns_behaviors": []}
        problem = L.wp_frame_problem({"function": "f", "frame_summary": frame})
        assert (problem[0] if problem else None) == result, state
        # The scheduler keeps a note for exactly the states the ledger does not credit.
        noted = S._merge_notes({"ok": True, "frame_state": {"assigns_clause": state}})
        assert bool(noted) is (result is not None), state
        # A state the merge refuses (when the replaced contract had a frame) is one the ledger does not credit.
        if state in workspace_overlay.NO_FRAME_STATES:
            assert result == "wp_no_frame_clause"


def test_the_contract_change_keys_are_the_ones_the_scheduler_and_the_report_read(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / SEAM_SRC_PROBE).write_text(_probe_baseline("plain", "drops_ensures"), encoding="utf-8", newline="\n")
    change = workspace_overlay.contract_change(tmp_path, [SEAM_SRC_PROBE], {SEAM_SRC_PROBE: _probe_text()}, "plain")
    assert set(S.CONTRACT_REMOVAL_KEYS) <= set(change)
    report_keys = {key for key, _label in G.MERGE_NOTE_REMOVALS} | {"behaviors_removed", "completeness_removed"}
    assert report_keys == set(S.CONTRACT_REMOVAL_KEYS)
    assert change["ensures_removed"][0]["behavior"] == workspace_overlay.DEFAULT_BEHAVIOR == "default!"
    # `default!` is the behavior name the report reads as "outside named behaviors".
    assert G._removed_clauses(change["ensures_removed"]).startswith("the contract outside named behaviors: ")
    assert G.WP_SCHEDULE == S.SCHEDULE


def test_the_identity_note_is_one_string() -> None:
    assert G.IDENTITY_NOT_COMPARED is L.IDENTITY_NOT_COMPARED
    assert L.IDENTITY_NOT_COMPARED.startswith("Failure identity not compared")
    assert "_judge_reproducer" in C.IDENTITY_RULE and callable(L._judge_reproducer)


# ---------------------------------------------------------------------------
# limits.guardrail / limits.dynamic_oracle: merge -> ingest-wp -> the report's verdict limits
# ---------------------------------------------------------------------------


def test_unchecked_clauses_reach_the_ledger_and_the_report(run_dir, monkeypatch) -> None:
    res, report, tools = _merged_probe(run_dir, monkeypatch, "unb_requires", guard_tag="unb_requires")
    assert tools.ran == ["run_eacsl_fuzz.py", "run_wp_function.py"]
    assert res["guardrail"]["status"] == L.GUARDRAIL_PASSED_STATUS
    limits = report["limits"]
    assert limits["guardrail"] == {"status": L.GUARDRAIL_PASSED_STATUS}
    oracle = limits["dynamic_oracle"]
    assert (oracle["exercised"], oracle["hits"], oracle["executed_inputs"]) == (True, 4, 3)
    written = [(c["kind"], c["label"], c["line"]) for c in oracle["unchecked_clauses"]]
    assert written == [("loop variant", "", 23), ("requires", "unb_pre", 13)]
    # The ledger: one open assumption per clause on every credited unit, and the limits kept with the evidence.
    for cls in ("rte", "l3_frame"):
        credited = _unit_of("unb_requires", cls)
        assert credited["status"] == "covered"
        assert credited["evidence"][-1]["details"]["limits"]["dynamic_oracle"] == oracle
        notes = _assumptions("unb_requires", cls)
        assert len(notes) == 2 and all("The dynamic oracle never executed the " in n for n in notes)
        assert any(
            "requires `unb_pre: " in n and f"at workspace/work/{SEAM_SRC_PROBE}:13 of unb_requires" in n for n in notes
        )
        assert any(f"loop variant `n - i` at workspace/work/{SEAM_SRC_PROBE}:23" in n for n in notes)
    # The report: the same two clauses, once (one proof is the evidence of both units).
    lines = G.verdict_limits_section(_ledger())
    head = next(line for line in lines if "the dynamic oracle never executed" in line)
    assert "never executed 2 clause(s) of 1 function(s)" in head
    rows = [line for line in lines if line.startswith(f"  - `{SEAM_SRC_PROBE}#unb_requires`: ")]
    assert len(rows) == 2 and any("requires `unb\\_pre: " in r or "requires `unb_pre: " in r for r in rows)
    assert not any("did not report which clauses" in line or "no E-ACSL guardrail pass" in line for line in lines)
    assert not any("no guardrail input reached" in line for line in lines)


def test_an_empty_list_of_unchecked_clauses_says_nothing(run_dir, monkeypatch) -> None:
    _res, report, _tools = _merged_probe(run_dir, monkeypatch, "plain", guard_tag="plain")
    oracle = report["limits"]["dynamic_oracle"]
    assert oracle["unchecked_clauses"] == [] and "unattributed" not in oracle
    assert _unit_of("plain", "rte")["status"] == "covered" and _assumptions("plain") == []
    lines = G.verdict_limits_section(_ledger())
    assert lines and not any("never executed" in line or "did not report" in line for line in lines)
    assert not any("could not be tied to a function" in line for line in lines)


@pytest.mark.parametrize("guard_fields", [False, True])
def test_a_guardrail_that_does_not_know_its_unchecked_clauses_is_an_assumption(
    run_dir, monkeypatch, guard_fields
) -> None:
    """The report as recorded before the fields existed, and a guardrail whose build gave it no list (None)."""
    tools = {"guard_tag": "unb_requires", "guard_fields": guard_fields}
    if guard_fields:
        monkeypatch.setattr(SeamTools, "ignored", lambda self: None)
    _res, report, seam = _merged_probe(run_dir, monkeypatch, "unb_requires", **tools)
    assert ("unchecked_clauses" in seam.guard_reports[0]) is guard_fields
    assert report["limits"]["dynamic_oracle"]["unchecked_clauses"] is None
    (note,) = [n for n in _assumptions("unb_requires") if "did not report which clauses" in n]
    assert "is not known" in note
    lines = G.verdict_limits_section(_ledger())
    (line,) = [line for line in lines if "did not report which clauses E-ACSL generated no check for" in line]
    assert line.endswith(f"(1): `{SEAM_SRC_PROBE}#unb_requires`")
    assert not any("never executed" in line for line in lines)


def test_unattributed_ignored_annotations_reach_the_ledger_and_the_report(run_dir, monkeypatch) -> None:
    """`via_pred` uses a predicate E-ACSL rejected at its definition; without the instrumented file no clause is tied to it."""
    _res, report, _tools = _merged_probe(run_dir, monkeypatch, "via_pred", guard_tag="via_pred")
    oracle = report["limits"]["dynamic_oracle"]
    assert oracle["unchecked_clauses"] == [] and len(oracle["unattributed"]) == 1
    assert oracle["unattributed"][0]["function"] is None and oracle["unattributed"][0]["line"] == 7
    (note,) = _assumptions("via_pred")
    assert note.startswith("E-ACSL ignored 1 annotation(s) in via_pred's guardrail build that could not be tied to")
    assert f"(first: workspace/work/{SEAM_SRC_PROBE}:7, invalid E-ACSL construct" in note
    lines = G.verdict_limits_section(_ledger())
    (line,) = [line for line in lines if "could not be tied to a function" in line]
    assert line.endswith(f"(1): `{SEAM_SRC_PROBE}#via_pred` (1)")


def test_a_clause_ignored_through_a_predicate_names_the_predicate(run_dir, monkeypatch) -> None:
    """The same build with its instrumented file: the `requires` that uses the predicate is the unchecked clause."""
    _res, report, _tools = _merged_probe(
        run_dir, monkeypatch, "via_pred", guard_tag="via_pred", guard_instrumented=True
    )
    (clause,) = report["limits"]["dynamic_oracle"]["unchecked_clauses"]
    assert (clause["kind"], clause["label"], clause["via"]) == ("requires", "via", "tail_nonneg")
    (note,) = _assumptions("via_pred")
    assert "requires `via: tail_nonneg(n)` at " in note and ", through `tail_nonneg` of via_pred" in note
    lines = G.verdict_limits_section(_ledger())
    assert any("through `tail\\_nonneg`" in line or "through `tail_nonneg`" in line for line in lines)


def test_a_merge_without_guardrail_is_an_assumption_and_a_report_line(run_dir, monkeypatch) -> None:
    """The sidecar names no sources: `_run_parent_reverify` writes `limits.guardrail` itself."""
    res, report, tools = _merged_probe(run_dir, monkeypatch, "plain", sources=[])
    assert tools.ran == ["run_wp_function.py"]
    written = report["limits"]["guardrail"]
    assert written == res["guardrail"] and written["status"] == "not_run"
    assert f"module {SEAM_MODULE} has no harness sidecar with sources" in written["reason"]
    assert "dynamic_oracle" not in report["limits"]
    (note,) = _assumptions("plain")
    assert note.startswith("No E-ACSL guardrail ran for the WP result credited for plain (module m has no harness")
    assert _unit_of("plain", "rte")["status"] == "covered"  # a proof on WP alone is still credited, and says so
    lines = G.verdict_limits_section(_ledger())
    assert (
        "- Proven, but the latest credited WP result had no E-ACSL guardrail pass (1): "
        + ("these proofs stand on WP alone, not exercised at runtime.")
        in lines
    )
    (row,) = [line for line in lines if line.startswith(f"  - `{SEAM_SRC_PROBE}#plain`: ")]
    assert "has no harness sidecar with sources" in row and "status `" not in row


def test_a_guardrail_that_measured_no_reach_claims_no_exercise(run_dir, monkeypatch) -> None:
    """
    The replay printed no coverage: `limits.dynamic_oracle` has the clause list and no `exercised`.
    Neither reader takes the missing key for "not exercised", and neither says the function was reached.
    """
    _res, report, tools = _merged_probe(run_dir, monkeypatch, "unb_requires", guard_tag="plain", guard_reach=False)
    assert tools.guard_reports[0]["reach"]["measured"] is False
    oracle = report["limits"]["dynamic_oracle"]
    assert oracle == {"unchecked_clauses": []}
    assert _unit_of("unb_requires", "rte")["status"] == "covered" and _assumptions("unb_requires") == []
    lines = G.verdict_limits_section(_ledger())
    assert lines and not any("no guardrail input reached" in line for line in lines)
    assert not any("did not report which clauses" in line for line in lines)


def test_a_contract_recheck_writes_a_not_run_the_ledger_reads(run_dir, monkeypatch) -> None:
    """wp_scheduler's re-check of a merged function (a callee's contract changed) runs WP only, and says so."""
    _stage(
        run_dir,
        {SEAM_SRC_PROBE: _probe_text(), "src/probe.h": _probe_text("probe.h")},
        _units_of(SEAM_SRC_PROBE, "plain"),
        [SEAM_SRC_PROBE],
    )
    tools = SeamTools(monkeypatch, run_dir)
    out = S._default_recheck(run_dir, "prove-plain", SEAM_SRC_PROBE, "plain", SEAM_MODULE)
    assert out["ok"] is True and tools.ran == ["run_wp_function.py"]
    report = json.loads((run_dir / out["report"]).read_text(encoding="utf-8"))
    assert report["limits"]["guardrail"] == workspace_overlay.guardrail_not_run(S.RECHECK_NO_GUARDRAIL)
    L.cmd_ingest_wp([run_dir / out["report"]])
    (note,) = _assumptions("plain")
    assert "No E-ACSL guardrail ran" in note and "a contract re-check runs WP only" in note


# ---------------------------------------------------------------------------
# wp_scheduler: merge-pending writes state/wp_schedule.json, the report reads it
# ---------------------------------------------------------------------------


def _scheduled(run_dir: Path, monkeypatch, fn: str, how: str, sources: list[str], **tool_kw) -> tuple[Sim, SeamTools]:
    """A scheduler run whose one prover task merges through the real batch merge of the real overlay."""
    target = run_dir.parent / "target"
    (target / "src").mkdir(parents=True)
    (target / SEAM_SRC_PROBE).write_text(_probe_baseline(fn, how), encoding="utf-8", newline="\n")
    (target / "src/probe.h").write_text(_probe_text("probe.h"), encoding="utf-8", newline="\n")
    workspace_overlay.init_overlay(target, run_dir / "workspace")
    write_json(run_dir / "run-metadata.json", metadata("in_progress"))
    sim = Sim(run_dir, monkeypatch)
    sim.build(
        {fn: (SEAM_SRC_PROBE, SEAM_MODULE, [])},
        units=_units_of(SEAM_SRC_PROBE, fn),
        sidecars={SEAM_MODULE: {"sources": sources, "cppflags": "-Isrc"}},
    )
    monkeypatch.setattr(S.DEPS, "merge_agent_batch", workspace_overlay.merge_agent_batch)
    tools = SeamTools(monkeypatch, run_dir, **tool_kw)
    S.cmd_init()
    return sim, tools


def _prove_and_merge(sim: Sim, fn: str) -> tuple[str, dict]:
    out = S.cmd_next("auto", prepare=True)
    (aid,) = [t["agent_id"] for t in out["tasks"] if t.get("kind") == "prove"]
    _agent(sim.run_dir, aid, {SEAM_SRC_PROBE: _probe_text()})
    sim.prover(aid, fn, SEAM_SRC_PROBE)
    assert S.cmd_complete(aid)["action"] == "queued_for_merge"
    return aid, S.cmd_merge_pending(force=True)


def test_a_removed_ensures_is_on_the_task_and_in_the_report(run_dir, monkeypatch) -> None:
    sim, tools = _scheduled(run_dir, monkeypatch, "plain", "drops_ensures", [SEAM_SRC_PROBE], guard_tag="module")
    aid, out = _prove_and_merge(sim, "plain")
    assert sorted(tools.ran) == ["run_eacsl_fuzz.py", "run_wp_function.py"]
    (merged,) = out["merged"]
    task = tasks()[f"prove:{SEAM_SRC_PROBE}#plain"]
    assert (task["state"], task["outcome"]) == ("done", "merged")
    notes = task["merge_notes"]
    assert set(notes) == {"contract_changes"} and merged["merge_notes"] == notes
    assert notes["contract_changes"]["ensures_removed"] == [{"behavior": "default!", "clauses": ["\\result >= 0"]}]
    loaded = G.load_merge_notes(run_dir)
    assert [(n["function"], n["state"], n["outcome"]) for n in loaded] == [("plain", "done", "merged")]
    lines = G.merge_notes_lines(loaded)
    assert lines[0].startswith(
        "Merges accepted with a note (1; `merge_notes` of the tasks in `state/wp_schedule.json`)"
    )
    (row,) = [line for line in lines if line.startswith("- `plain`: ")]
    assert "`ensures` removed in the contract outside named behaviors: `" in row and ">= 0`" in row
    assert "no guardrail pass" not in row and "does not show a frame" not in row
    # The batch's module guardrail passed: its limits are in the report the scheduler ingested.
    assert _unit_of("plain", "rte")["status"] == "covered"
    limits = _unit_of("plain", "rte")["evidence"][-1]["details"]["limits"]
    assert limits["guardrail"] == {"status": L.GUARDRAIL_PASSED_STATUS}
    assert limits["dynamic_oracle"]["unchecked_clauses"] == [] and len(limits["dynamic_oracle"]["unattributed"]) == 2
    assert aid == "prove-plain"


def test_a_batch_merge_without_guardrail_is_on_the_task_in_the_ledger_and_in_the_report(run_dir, monkeypatch) -> None:
    sim, tools = _scheduled(run_dir, monkeypatch, "plain", "adds_ensures", [])
    _aid, out = _prove_and_merge(sim, "plain")
    assert tools.ran == ["run_wp_function.py"]
    notes = tasks()[f"prove:{SEAM_SRC_PROBE}#plain"]["merge_notes"]
    assert set(notes) == {"guardrail"} and notes["guardrail"]["status"] == "not_run"
    reason = notes["guardrail"]["reason"]
    assert f"module {SEAM_MODULE} has no harness sidecar with sources" in reason
    (row,) = [line for line in G.merge_notes_lines(G.load_merge_notes(run_dir)) if line.startswith("- `plain`: ")]
    assert row.startswith("- `plain`: no guardrail pass (`not\\_run`: module m") or row.startswith(
        "- `plain`: no guardrail pass (`not_run`: module m"
    )
    # The same reason, from the same merge, in the WP report the scheduler ingested.
    credited = _unit_of("plain", "rte")
    assert credited["status"] == "covered"
    assert credited["evidence"][-1]["details"]["limits"]["guardrail"] == notes["guardrail"]
    assert any(n.startswith("No E-ACSL guardrail ran") and "no harness sidecar" in n for n in _assumptions("plain"))
    assert any("had no E-ACSL guardrail pass (1)" in line for line in G.verdict_limits_section(_ledger()))
    assert out["merged"][0]["merge_notes"] == notes


def test_a_clean_merge_leaves_no_note(run_dir, monkeypatch) -> None:
    sim, _tools = _scheduled(run_dir, monkeypatch, "plain", "adds_ensures", [SEAM_SRC_PROBE], guard_tag="plain")
    _aid, out = _prove_and_merge(sim, "plain")
    assert "merge_notes" not in out["merged"][0]
    task = tasks()[f"prove:{SEAM_SRC_PROBE}#plain"]
    assert (task["state"], task["outcome"]) == ("done", "merged") and "merge_notes" not in task
    assert G.load_merge_notes(run_dir) == [] and G.merge_notes_lines(G.load_merge_notes(run_dir)) == []
    assert _unit_of("plain", "l3_frame")["status"] == "covered" and _assumptions("plain") == []


# ---------------------------------------------------------------------------
# The frame: the merge's refusal and the ledger's credit, on the same WP report
# ---------------------------------------------------------------------------

SEAM_IN_HEADER = ("on_header", "on_header_post_only")
SEAM_WAS_NONE = "no contract"
SEAM_WAS_DEFAULT = "an assigns clause of its own"
SEAM_WAS_SAME_FRAME = "the same assigns clauses"
# (function, what the shared tree held) -> what the merge does and why.
#   merged            the merge stands and the ledger credits the frame
#   merged_no_frame   the merge stands, the ledger does not credit the frame: both record why
#   refused_contract  the contract comparison refuses it (an `assigns` clause is gone)
#   refused_frame     the parent WP report shows no frame and the replaced contract had `assigns`
#   refused_status    WP did not prove every goal
SEAM_MERGE_CASES = {
    ("pure_ok", SEAM_WAS_NONE): "merged",
    ("pure_ok", SEAM_WAS_DEFAULT): "merged",
    ("on_header", SEAM_WAS_NONE): "merged",
    ("on_header", SEAM_WAS_DEFAULT): "merged",
    ("guarded_all", SEAM_WAS_NONE): "merged",
    ("guarded_all", SEAM_WAS_DEFAULT): "refused_contract",
    ("guarded_all", SEAM_WAS_SAME_FRAME): "merged",
    ("post_only", SEAM_WAS_NONE): "merged_no_frame",
    ("post_only", SEAM_WAS_DEFAULT): "refused_contract",
    ("on_header_post_only", SEAM_WAS_NONE): "merged_no_frame",
    ("on_header_post_only", SEAM_WAS_DEFAULT): "refused_contract",
    ("guarded_some", SEAM_WAS_NONE): "merged_no_frame",
    ("guarded_some", SEAM_WAS_DEFAULT): "refused_contract",
    ("guarded_some", SEAM_WAS_SAME_FRAME): "refused_frame",
    ("guarded_gap", SEAM_WAS_NONE): "merged_no_frame",
    ("guarded_gap", SEAM_WAS_DEFAULT): "refused_contract",
    ("guarded_gap", SEAM_WAS_SAME_FRAME): "refused_frame",
    ("pure_broken", SEAM_WAS_NONE): "refused_status",
    ("calls_post_only", SEAM_WAS_NONE): "refused_status",
}


def _frame_texts(fn: str, baseline: str) -> tuple[dict[str, str], dict[str, str]]:
    """(the shared tree, the prover's result) for a merge of the recorded contract of `fn` (frame.c)."""
    result = {SEAM_SRC_FRAME: (SEAM_FRAME / SEAM_SRC_FRAME).read_text(encoding="utf-8"),
              SEAM_HDR_FRAME: (SEAM_FRAME / SEAM_HDR_FRAME).read_text(encoding="utf-8")}  # fmt: skip
    holder = SEAM_HDR_FRAME if fn in SEAM_IN_HEADER else SEAM_SRC_FRAME
    if baseline == SEAM_WAS_NONE:
        contract = None
    elif baseline == SEAM_WAS_DEFAULT:
        contract = "/*@ assigns g; */"
    else:  # the recorded contract without its first `ensures`: the same behaviors, the same `assigns` clauses
        recorded = result[holder]
        block = recorded[: recorded.index(f" {fn}(")]
        block = block[block.rindex("/*@") : block.rindex("*/") + 2]
        contract = re.sub(r"\n\s*ensures [^;]*;", "", block, count=1)
        assert contract != block and contract.count("assigns") == block.count("assigns")
    shared = {**result, holder: _contract_swapped(result[holder], fn, contract)}
    assert shared[holder] != result[holder]
    return shared, {holder: result[holder]}


@pytest.mark.parametrize(("fn", "baseline"), sorted(SEAM_MERGE_CASES))
def test_the_merge_and_the_ledger_agree_on_the_frame(run_dir, monkeypatch, fn, baseline) -> None:
    expected = SEAM_MERGE_CASES[(fn, baseline)]
    shared, result = _frame_texts(fn, baseline)
    _stage(run_dir, shared, _units_of(SEAM_SRC_FRAME, fn), None)
    aid = f"prove-{fn}"
    _agent(run_dir, aid, result)
    SeamTools(monkeypatch, run_dir)
    report_path = run_dir / "agents" / aid / "scratch" / "parent_wp" / f"{fn}.json"
    header = {"header_file": SEAM_HDR_FRAME} if fn in SEAM_IN_HEADER else {}
    try:
        res = workspace_overlay.merge_agent_overlay(
            run_dir=run_dir, agent_id=aid, role="prover", overlay_dir=run_dir / "workspace", c_file=SEAM_SRC_FRAME,
            function=fn, module=SEAM_MODULE, sources=None, cppflags="-Isrc", **header,
        )  # fmt: skip
    except workspace_overlay.AcslError as exc:
        # Refused on the text, before any WP run: nothing was proved, so there is nothing the ledger could credit.
        assert expected == "refused_contract", exc
        assert workspace_overlay.FRAME_REFUSAL in str(exc) and "leaves no `assigns` clause there" in str(exc)
        assert not report_path.exists()
        return
    report = json.loads(report_path.read_text(encoding="utf-8"))
    problem = L.wp_frame_problem(report) if report["status"] == "all_proven" else ("not all_proven", "")
    if not res["ok"]:
        assert res["rolled_back"] is True
        for rel_path, text in shared.items():  # the shared tree is what it was
            assert (run_dir / "workspace" / "work" / rel_path).read_text(encoding="utf-8") == text
        if "frame_summary.assigns_clause" in res["reason"]:
            # A refusal for the frame is never of a report the ledger would credit a frame from.
            assert expected == "refused_frame" and problem is not None and problem[0] == "wp_no_frame_clause"
        else:
            assert expected == "refused_status" and report["status"] != "all_proven"
        return
    assert report["status"] == "all_proven"
    L.cmd_ingest_wp([report_path])
    frame_unit = _unit_of(fn, "l3_frame")
    noted = S._merge_notes(res).get("frame_state")
    if problem is None:
        assert expected == "merged"
        assert frame_unit["status"] == "covered" and noted is None
    else:
        # The merge accepted a proof the ledger does not credit a frame for: both sides say why.
        assert expected == "merged_no_frame"
        assert frame_unit["status"] == "planned"
        last = frame_unit["evidence"][-1]
        assert last["result"] == problem[0] and last["discharging"] is False and problem[1] in last["summary"]
        assert noted == res["frame_state"] and noted["assigns_clause"] == report["frame_summary"]["assigns_clause"]
        assert noted["baseline_had_assigns"] is False
        item = {"function": fn, "task": f"prove:{SEAM_SRC_FRAME}#{fn}", "notes": S._merge_notes(res)}
        (row,) = [line for line in G.merge_notes_lines([item]) if line.startswith(f"- `{fn}`: ")]
        assert "does not show a frame for the whole function" in row
    assert _unit_of(fn, "rte")["status"] == "covered"


def test_a_recheck_refuses_nothing_and_the_ledger_still_withholds_the_frame(run_dir, monkeypatch) -> None:
    """`baseline_had_assigns` is None for a re-check of a merged function: the ledger is the only gate there."""
    texts = {SEAM_SRC_FRAME: (SEAM_FRAME / SEAM_SRC_FRAME).read_text(encoding="utf-8"),
             SEAM_HDR_FRAME: (SEAM_FRAME / SEAM_HDR_FRAME).read_text(encoding="utf-8")}  # fmt: skip
    _stage(run_dir, texts, _units_of(SEAM_SRC_FRAME, "post_only"), None)
    SeamTools(monkeypatch, run_dir)
    out = S._default_recheck(run_dir, "prove-post_only", SEAM_SRC_FRAME, "post_only", SEAM_MODULE)
    assert out["ok"] is True
    L.cmd_ingest_wp([run_dir / out["report"]])
    assert _unit_of("post_only", "rte")["status"] == "covered"
    frame_unit = _unit_of("post_only", "l3_frame")
    assert frame_unit["status"] == "planned" and frame_unit["evidence"][-1]["result"] == "wp_no_frame_clause"


def _refused_twice(run_dir: Path, monkeypatch, fn: str, baseline: str, why: str) -> tuple[dict, list[dict]]:
    """Two scheduler rounds whose merge of `fn` is refused for `why`: (the shared tree's texts, the WP reports)."""
    shared, result = _frame_texts(fn, baseline)
    target = run_dir.parent / "target"
    for rel_path, text in shared.items():
        (target / rel_path).parent.mkdir(parents=True, exist_ok=True)
        (target / rel_path).write_text(text, encoding="utf-8", newline="\n")
    workspace_overlay.init_overlay(target, run_dir / "workspace")
    write_json(run_dir / "run-metadata.json", metadata("in_progress"))
    sim = Sim(run_dir, monkeypatch)
    sim.build({fn: (SEAM_SRC_FRAME, SEAM_MODULE, [])}, units=_units_of(SEAM_SRC_FRAME, fn),
              sidecars={SEAM_MODULE: {"sources": [], "cppflags": "-Isrc"}})  # fmt: skip
    monkeypatch.setattr(S.DEPS, "merge_agent_batch", workspace_overlay.merge_agent_batch)
    SeamTools(monkeypatch, run_dir)
    S.cmd_init()
    actions, reports = [], []
    for _attempt in range(S.MAX_MERGE_ATTEMPTS):
        out = S.cmd_next("auto", prepare=True)
        (aid,) = [t["agent_id"] for t in out["tasks"] if t.get("kind") == "prove"]
        _agent(run_dir, aid, result)
        sim.prover(aid, fn, SEAM_SRC_FRAME)
        assert S.cmd_complete(aid)["action"] == "queued_for_merge"
        (failed,) = S.cmd_merge_pending(force=True)["failed"]
        assert why in failed["reason"]
        actions.append(failed["action"])
        reports.append(json.loads((run_dir / f"agents/{aid}/scratch/parent_wp/{fn}.json").read_text("utf-8")))
    assert actions == ["requeued", "blocked"]
    task = tasks()[f"prove:{SEAM_SRC_FRAME}#{fn}"]
    assert (task["state"], task["outcome"]) == ("blocked", "merge_failed")
    return shared, reports


def test_a_merge_refused_for_its_frame_credits_nothing(run_dir, monkeypatch) -> None:
    """
    The refused merge leaves a parent WP report that says `all_proven`, of a contract that was rolled back.
    When the scheduler gives the task up (second refusal), no unit may be covered from that report.
    """
    fn = "guarded_some"
    shared, reports = _refused_twice(run_dir, monkeypatch, fn, SEAM_WAS_SAME_FRAME, "frame_summary.assigns_clause")
    assert [r["status"] for r in reports] == ["all_proven", "all_proven"]  # the refusal is the merge's, not WP's
    assert (run_dir / "workspace" / "work" / SEAM_SRC_FRAME).read_text(encoding="utf-8") == shared[SEAM_SRC_FRAME]
    for cls in ("rte", "l3_frame"):
        credited = _unit_of(fn, cls)
        assert credited["status"] != "covered", (cls, credited["status"], credited["evidence"][-1:])
        assert not any(e.get("discharging") for e in credited["evidence"]), cls


def test_a_merge_refused_for_unproven_goals_still_records_them(run_dir, monkeypatch) -> None:
    """The control: the report of a merge WP did not prove is ingested when the task is given up, and credits nothing."""
    fn = "pure_broken"
    _shared, reports = _refused_twice(run_dir, monkeypatch, fn, SEAM_WAS_NONE, "returned status=")
    assert all(r["status"] == "unproven_goals_remain" for r in reports)
    evidence = [e for cls in ("rte", "l3_frame") for e in _unit_of(fn, cls)["evidence"] if e.get("phase") == "wp"]
    assert evidence and not any(e.get("discharging") for e in evidence)
    assert all(_unit_of(fn, cls)["status"] != "covered" for cls in ("rte", "l3_frame"))


# ---------------------------------------------------------------------------
# crash_replay.replay_identity -> ledger.cmd_ingest_verifier, per input
# ---------------------------------------------------------------------------


def _identity_cases(fixture: str) -> list[tuple[str, str, int]]:
    """
    (report file, candidate fingerprint, input index): every reproducible input of every recorded replay
    report, held against every recorded candidate (its own, and the ones it is not the failure of).
    """
    recorded = sorted(
        c["fingerprint"] for c in json.loads((tvr.REPLAY_IDENTITY / fixture / "candidates.json").read_text("utf-8"))
    )
    cases: list[tuple[str, str, int]] = []
    for path in sorted((tvr.REPLAY_IDENTITY / fixture / "replay").glob("*.json")):
        report = json.loads(path.read_text(encoding="utf-8"))
        shas = list(
            dict.fromkeys(a["sha256"] for a in report["artifacts"] if a.get("reproducible") is True and a.get("sha256"))
        )
        cases += [(path.name, fp, i) for fp in recorded for i in range(len(shas))]
    return cases


SEAM_IDENTITY_CASES = [(f, *case) for f in (tvr.MODBUS, tvr.MPACK) for case in _identity_cases(f)]


def test_the_fixtures_hold_inputs_of_every_identity_outcome(run_dir) -> None:
    """The cases below are not all acceptances: every (outcome, counts) pair the rule can give is among them."""
    candidates = tvr._stage(run_dir, tvr.MODBUS)
    seen = set()
    for fixture, report_name, cand_fp, index in SEAM_IDENTITY_CASES:
        if fixture != tvr.MODBUS:
            continue
        path = f"{tvr.REPLAY_DIR}/{report_name}"
        report = json.loads((run_dir / path).read_text(encoding="utf-8"))
        item = C.replay_identity(report, candidates[cand_fp], list(candidates.values()), path, run_dir)["inputs"][index]
        seen.add((item["outcome"], item["counts"]))
    assert seen == {("match", True), ("mismatch", False), ("uncompared", True), ("uncompared", False)}


@pytest.mark.parametrize(("fixture", "report_name", "cand_fp", "index"), SEAM_IDENTITY_CASES)
def test_identity_counts_is_what_ingest_verifier_does_with_the_input(
    run_dir, fixture, report_name, cand_fp, index
) -> None:
    """
    `identity.inputs[].counts` of a replay report, against `ledger.py ingest-verifier` for a `confirmed` record
    on the report's candidate that lists that one input and cites that report.
    """
    candidates = tvr._stage(run_dir, fixture)
    path = f"{tvr.REPLAY_DIR}/{report_name}"
    report = json.loads((run_dir / path).read_text(encoding="utf-8"))
    cand = candidates[cand_fp]
    identity = C.replay_identity(report, cand, list(candidates.values()), path, run_dir)
    assert identity["compared"] is True
    item = identity["inputs"][index]
    arts = [a for a in report["artifacts"] if a.get("sha256") == item["sha256"]]
    input_path = next(
        (str(a["artifact"]).replace("\\", "/") for a in arts if (run_dir / str(a.get("artifact"))).is_file()), None
    )
    if input_path is None:
        pytest.skip(f"the fixture does not hold the bytes of input {item['sha256'][:12]} ({item['outcome']})")
    # A candidate without a line or a predicate (a hypothesis, a hang) is not a valid finding as it stands:
    # its verifier writes both. The fingerprint, file, function and kind stay the candidate's.
    location = {**cand["location"], "line": max(1, int(cand["location"].get("line") or 0))}
    prop = {**cand["property"], "predicate": str(cand["property"].get("predicate") or "").strip() or "the replay fails"}
    changed: dict = {"location": location, "property": prop}
    reason, found_fp = None, cand_fp
    if cand_fp == tvr.HANG:
        # The hang candidate names the harness, not a function of the target: its verifier re-fingerprints it,
        # as in test_verifier_replay_identity.
        found_fp, reason = tvr.SEND_MSG, "The hang is the retry loop of send_msg."
        changed = {
            "fingerprint": found_fp,
            "location": {"file": "src/modbus.c", "line": 210, "function": "send_msg"},
            "property": {"kind": "timeout", "predicate": "send_msg does not terminate when the send keeps failing"},
        }
    rec = tvr._record(run_dir, cand, report_name, input_path, **changed)
    assert rec["reproducers"][0]["sha256"] == item["sha256"]
    try:
        out = tvr._ingest(run_dir, cand_fp, rec, [report_name], reason=reason)
    except L.LedgerError as exc:
        accepted, said = False, str(exc)
    else:
        accepted, said = out["decision"] == "confirmed", ""
    assert accepted is item["counts"], (item, said)
    if not accepted:
        wanted = "on another failure" if item["outcome"] == "mismatch" else "cannot be compared"
        assert wanted in said, (item, said)
    else:
        # What the ledger records beside the verdict is what `identity` said of the input.
        not_compared = out.get("reproducers_not_compared") or []
        assert (item["sha256"] in not_compared) is (item["outcome"] == "uncompared")
        finding = tvr._findings(run_dir)[found_fp]
        assert bool(G.identity_not_compared(finding)) is (item["outcome"] == "uncompared")
