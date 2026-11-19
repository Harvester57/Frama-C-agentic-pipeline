"""
The annotations E-ACSL ignores (`... Ignoring annotation.`) and what the guardrail says about them.

E-ACSL does not fail on a clause it cannot translate: it warns, keeps the clause as a comment and
checks nothing. The guardrail used to report `passed_dynamic_oracle` all the same, with no mention of
the clause. Now the build report lists the ignored annotations with the function each belongs to, and
the guardrail report says which clauses of the checked functions were not executed
(`unchecked_clauses`, `dynamic_oracle_incomplete`).

Every log, report and instrumented file under tests/fixtures/eacsl_ignored comes from one run of
scenario.sh in the analysis image (Frama-C 34.0~beta), on probe.c, probe.h, violation.c and extras.c
of that directory. The two reports were captured before the fix.
"""

from __future__ import annotations

import functools
import json
import shutil
import subprocess
from pathlib import Path

import pytest

import cache
import eacsl_toolchain as T
import fuzz_build
import run_eacsl_fuzz as R
import sandbox_exec
from sandbox_exec import SandboxResult

IGNORED_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "eacsl_ignored"
IGNORED_SRC_DIR = Path("workspace") / "work" / "src"
PROBE_C = "workspace/work/src/probe.c"
PROBE_H = "workspace/work/src/probe.h"
IGNORED_MARKER_BYTES = b"\x7fELF __e_acsl_assert"


def _stage1_output(tag: str) -> str:
    record = (IGNORED_FIXTURE / f"{tag}.stage1.log").read_text(encoding="utf-8")
    return record.split("--- STDOUT ---\n", 1)[1].split("\n--- STDERR ---", 1)[0]


class CapturedEacsl:
    """`e-acsl-gcc` replaying one capture: stage 1 prints the captured output of `tag`, stage 2 writes the binaries."""

    def __init__(self, tag: str, stage1_rc: int = 0):
        self.stdout = _stage1_output(tag)
        captured = IGNORED_FIXTURE / f"{tag}.instrumented.c"
        self.instrumented = captured.read_text(encoding="utf-8") if captured.is_file() else "int stub(void);\n"
        self.stage1_rc = stage1_rc
        self.calls: list[list[str]] = []

    def stage1_runs(self) -> int:
        return sum(1 for c in self.calls if c[0] == "e-acsl-gcc" and "-C" not in c)

    def __call__(self, cmd, **kwargs):
        self.calls.append(list(cmd))
        if "-M" in cmd:  # the build cache's dependency scan
            deps = "".join(f"{Path(c).stem}.o: {c}\n" for c in cmd if c.endswith(".c"))
            return subprocess.CompletedProcess(cmd, 0, stdout=deps, stderr="")
        if cmd[0] == "clang":
            if "-c" in cmd:
                Path(cmd[cmd.index("-o") + 1]).write_bytes(b"obj")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        if "-C" in cmd:
            out = Path(cmd[cmd.index("-O") + 1])
            out.write_bytes(b"plain")
            out.with_name(out.name + ".e-acsl").write_bytes(IGNORED_MARKER_BYTES)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        Path(cmd[cmd.index("-o") + 1]).write_text(self.instrumented, encoding="utf-8")
        return subprocess.CompletedProcess(cmd, self.stage1_rc, stdout=self.stdout, stderr="")


@pytest.fixture
def probe_run(tmp_path, monkeypatch):
    """A run directory holding the probe sources where the captured logs name them, and a corpus."""
    run = tmp_path / "run"
    (run / IGNORED_SRC_DIR).mkdir(parents=True)
    for name in ("probe.c", "probe.h", "violation.c", "extras.c"):
        shutil.copy(IGNORED_FIXTURE / name, run / IGNORED_SRC_DIR / name)
    corpus = run / "workspace" / "corpus" / "probe"
    corpus.mkdir(parents=True)
    (corpus / "seed-ab").write_bytes(b"AB")
    monkeypatch.chdir(run)
    monkeypatch.delenv("FRAMAC_CACHE", raising=False)
    monkeypatch.setattr(fuzz_build, "_resolve_eacsl_gcc", lambda: ("e-acsl-gcc", True))
    monkeypatch.setattr(T.shutil, "which", lambda name: None)
    monkeypatch.setattr(R.prover_candidates, "add_candidate_block", lambda *a, **k: None)
    return run


def _attributed(tag: str, run: Path) -> list[dict]:
    entries, _frame = T.parse_ignored_annotations(_stage1_output(tag))
    captured = IGNORED_FIXTURE / f"{tag}.instrumented.c"
    return T.attribute_ignored_annotations(entries, captured if captured.is_file() else None, cwd=run)


def _clean_replay(monkeypatch, calls: list | None = None) -> None:
    def fake_run(cmd, **kw):
        if calls is not None:
            calls.append(list(cmd))
        return SandboxResult(0, "stat::number_of_executed_units: 3\n", "", False, "rlimits", list(cmd))

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_run)


def _guardrail_report(monkeypatch, tag: str, extra: list[str], source: str = "probe.c", stage1_rc: int = 0) -> dict:
    """The report of `run_eacsl_fuzz.py guardrail` on a build that prints the captured stage 1 output of `tag`."""
    fake = CapturedEacsl(tag, stage1_rc=stage1_rc)
    monkeypatch.setattr(fuzz_build, "compile_eacsl_binary", functools.partial(R.compile_eacsl_binary, runner=fake))
    out = Path("state") / "guard" / tag / f"guard_{tag}"
    argv = [
        "guardrail", "--sources", (IGNORED_SRC_DIR / source).as_posix(), "--out-bin", out.as_posix(),
        "--corpus-dir", "workspace/corpus/probe", "--module", "probe", "--extra-runs", "0", "--no-cache",
        "--out-json", f"{out.as_posix()}.json", *extra,
    ]  # fmt: skip
    assert R.main(argv) == 0
    return json.loads(Path(f"{out.as_posix()}.json").read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# The warning lines
# ---------------------------------------------------------------------------


def test_parser_joins_a_warning_wrapped_over_several_lines():
    entries, frame = T.parse_ignored_annotations(_stage1_output("unb_requires"))
    assert frame == 2  # the contract's `assigns clause` and the loop's `assigns`, both at the function's line
    assert [(e["file"], e["line"], e["construct"], e["expected_check"]) for e in entries] == [
        (PROBE_C, 23, "loop variant using GMP", True),
        (PROBE_C, 13, None, True),
    ]
    quantifier = entries[1]["reason"]
    assert quantifier.startswith("invalid E-ACSL construct `invalid guard i + n")
    assert "in quantification unb_pre:" in quantifier and "Missing upper bound for i." in quantifier
    assert "\n" not in quantifier and "Ignoring annotation" not in quantifier


@pytest.mark.parametrize(
    ("tag", "line", "construct", "expected_check"),
    [
        ("extra_at", 15, r"\at with logic variable linked to C variable", True),
        ("extra_struct", 28, "comparison between two structs or unions", True),
        ("extra_with", 110, "update", True),
        ("extra_fresh", 78, r"\fresh", True),
        ("extra_axiomatic", 95, "logic functions or predicates performing read accesses", True),
        ("extra_exists", 66, None, True),
        ("extra_behavior", 124, None, True),
        ("extra_decreases", 43, "decreases clause", False),
        ("extra_terminates", 56, "terminates clause", False),
        ("extra_exits", 140, "abnormal termination case in behavior", False),
    ],
)
def test_parser_lists_the_other_constructs_eacsl_ignores(tag, line, construct, expected_check):
    entries, _frame = T.parse_ignored_annotations(_stage1_output(tag))
    assert [(e["file"], e["line"], e["construct"], e["expected_check"]) for e in entries] == [
        ("workspace/work/src/extras.c", line, construct, expected_check)
    ]


def test_frame_clauses_are_counted_not_listed():
    # `frees p; allocates \nothing; assigns \nothing;`: E-ACSL warns for the `assigns` only.
    assert T.parse_ignored_annotations(_stage1_output("extra_allocates")) == ([], 1)
    assert T.parse_ignored_annotations(_stage1_output("plain")) == ([], 2)


def test_a_warning_that_ignores_nothing_is_not_listed():
    # `walk` uses the prelude's valid_read_string: E-ACSL warns at fc_compat_types.h (`no assigns clause
    # generated for function __fc_eacsl_read_nul_at ...`), which drops no annotation.
    log = _stage1_output("walk")
    assert "fc_compat_types.h:510: Warning:" in log
    entries, _frame = T.parse_ignored_annotations(log)
    assert [(e["file"], e["line"], e["construct"]) for e in entries] == [(PROBE_C, 50, "loop variant using GMP")]


def test_a_repeated_warning_is_listed_once():
    # Two functions use predicates built on `tail_nonneg`: the module build warns twice at its definition.
    log = _stage1_output("module")
    assert log.count(f"[e-acsl] {PROBE_C}:7: Warning:") == 2
    entries, _frame = T.parse_ignored_annotations(log)
    assert sum(1 for e in entries if (e["file"], e["line"]) == (PROBE_C, 7)) == 1


# ---------------------------------------------------------------------------
# Which function an ignored annotation belongs to
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tag", "expected"),
    [
        (
            "unb_requires",
            [
                (PROBE_C, 23, "unb_requires", "definition", "loop variant", "", 23),
                (PROBE_C, 13, "unb_requires", "definition", "requires", "unb_pre", 13),
            ],
        ),
        ("unb_ensures", [(PROBE_C, 33, "unb_ensures", "definition", "ensures", "unb_post", 33)]),
        # The contract is on the prototype, in the header.
        ("hdr_fn", [(PROBE_H, 11, "hdr_fn", "prototype", "requires", "hdr_unb", 11)]),
        ("body_assert", [(PROBE_C, 115, "body_assert", "definition", "assert", "unb_assert", 115)]),
        # E-ACSL names a line inside a clause written over several lines, not its first one.
        (
            "multi_line",
            [
                (PROBE_C, 131, "multi_line", "definition", "loop invariant", "unb_inv", 130),
                (PROBE_C, 121, "multi_line", "definition", "requires", "split", 120),
            ],
        ),
        # The prelude's recursive `logic integer strlen` is reported where it is used.
        ("walk", [(PROBE_C, 50, "walk", "definition", "loop variant", "", 50)]),
    ],
)
def test_an_ignored_clause_belongs_to_the_function_whose_declaration_holds_it(probe_run, tag, expected):
    got = [
        (
            e["file"],
            e["line"],
            e["function"],
            e["declaration"],
            e["clause"]["kind"],
            e["clause"]["label"],
            e["clause"]["line"],
        )
        for e in _attributed(tag, probe_run)
    ]
    assert got == expected
    assert {e["attribution"] for e in _attributed(tag, probe_run)} == {"line_in_function"}


def test_a_clause_keeps_its_source_text(probe_run):
    (variant, requires) = _attributed("unb_requires", probe_run)
    assert requires["clause"]["text"] == r"\forall integer i; 0 <= i ==> i + n >= 0"
    assert variant["clause"]["text"] == "n - i"


@pytest.mark.parametrize(
    ("tag", "file", "line", "name", "user"),
    [
        ("via_pred", PROBE_C, 7, "tail_nonneg", ("via_pred", "requires", "via", "tail_nonneg(n)", "tail_nonneg")),
        # `wraps_tail` is defined with `tail_nonneg`: E-ACSL warns at `tail_nonneg` only.
        (
            "via_wrapped",
            PROBE_C,
            7,
            "tail_nonneg",
            ("via_wrapped", "requires", "wrapped", "wraps_tail(n)", "wraps_tail"),
        ),
        (
            "via_hdr_pred",
            PROBE_H,
            8,
            "hdr_tail_nonneg",
            ("via_hdr_pred", "requires", "from_hdr", "hdr_tail_nonneg(n)", "hdr_tail_nonneg"),
        ),
    ],
)
def test_an_ignored_logic_definition_is_tied_to_the_clauses_that_use_it(probe_run, tag, file, line, name, user):
    """E-ACSL warns at the definition and drops the clauses that use it without another word."""
    (entry,) = _attributed(tag, probe_run)
    assert (entry["file"], entry["line"], entry["function"]) == (file, line, None)
    assert entry["attribution"] == "logic_definition" and entry["logic_names"] == [name]
    users = [
        (u["function"], u["clause"]["kind"], u["clause"]["label"], u["clause"]["text"], u["via"])
        for u in entry["used_by"]
    ]
    assert user in users
    # The instrumented file really has no check for the clause: only the definition was warned about.
    assert f"requires {user[2]}: {user[3]};" in (IGNORED_FIXTURE / f"{tag}.instrumented.c").read_text(encoding="utf-8")


def test_an_unused_logic_definition_is_never_reported():
    # probe.h defines `hdr_unused_unbounded` like `hdr_tail_nonneg`; no contract uses it and E-ACSL says nothing.
    assert "hdr_unused_unbounded" in (IGNORED_FIXTURE / "probe.h").read_text(encoding="utf-8")
    entries, _frame = T.parse_ignored_annotations(_stage1_output("module"))
    assert [e["line"] for e in entries if e["file"] == PROBE_H] == [8, 11]


def test_what_cannot_be_attributed_says_why(probe_run):
    entries: list[dict] = [
        {"file": "workspace/work/src/gone.c", "line": 4, "construct": None, "reason": "r", "expected_check": True},
        {"file": PROBE_C, "line": 3, "construct": None, "reason": "r", "expected_check": True},
        {"file": None, "line": None, "construct": None, "reason": "r", "expected_check": True},
        {"file": PROBE_C, "line": 7, "construct": None, "reason": "r", "expected_check": True},
    ]
    got = T.attribute_ignored_annotations(entries, None, cwd=probe_run)
    assert [(e["attribution"], e["function"]) for e in got] == [
        ("file_not_readable", None),
        ("outside_any_function", None),
        ("no_location", None),
        ("logic_definition", None),
    ]
    assert got[3]["used_by"] is None  # no instrumented file to read the uses from


# ---------------------------------------------------------------------------
# The build report
# ---------------------------------------------------------------------------


def test_build_report_lists_the_ignored_annotations(probe_run):
    fake = CapturedEacsl("unb_requires")
    res = R.compile_eacsl_binary([PROBE_C], Path("state/guard/b/guard_b"), functions=["unb_requires"], runner=fake)
    assert res["returncode"] == 0, res
    assert [(e["file"], e["line"], e["function"], e["clause"]["label"]) for e in res["ignored_annotations"]] == [
        (PROBE_C, 23, "unb_requires", ""),
        (PROBE_C, 13, "unb_requires", "unb_pre"),
    ]
    assert res["ignored_frame_clauses"] == 2


def test_a_build_without_ignored_annotations_says_so(probe_run):
    res = R.compile_eacsl_binary(
        [PROBE_C], Path("state/guard/p/guard_p"), functions=["plain"], runner=CapturedEacsl("plain")
    )
    assert res["ignored_annotations"] == [] and res["ignored_frame_clauses"] == 2


def test_a_cached_build_still_carries_the_list(probe_run, monkeypatch):
    (probe_run / "run-metadata.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setenv("FRAMAC_IMAGE_ID", "sha256:test-image")
    fake = CapturedEacsl("unb_requires")
    out = Path("state/guard/c/guard_c")
    built = R.compile_eacsl_binary([PROBE_C], out, functions=["unb_requires"], runner=fake)
    hit = R.compile_eacsl_binary([PROBE_C], out, functions=["unb_requires"], runner=fake)
    assert built["cache"]["hit"] is False and hit["cache"]["hit"] is True and fake.stage1_runs() == 1
    assert hit["ignored_annotations"] == built["ignored_annotations"] and len(hit["ignored_annotations"]) == 2
    assert hit["ignored_frame_clauses"] == 2


# ---------------------------------------------------------------------------
# The guardrail report
# ---------------------------------------------------------------------------


def test_guardrail_report_names_the_clauses_eacsl_did_not_execute(probe_run, monkeypatch):
    """Regression: the replay is clean, and the report used to say nothing of the two ignored clauses."""
    before = (IGNORED_FIXTURE / "unb_requires.json").read_text(encoding="utf-8")
    assert json.loads(before)["status"] == "passed_dynamic_oracle"
    assert "unb_pre" not in before and "Ignoring annotation" not in before  # the report captured before the fix

    _clean_replay(monkeypatch)
    rep = _guardrail_report(monkeypatch, "unb_requires", ["--functions", "unb_requires"])
    assert rep["status"] == "passed_dynamic_oracle"  # the status values keep their meaning for their readers
    assert rep["dynamic_oracle_incomplete"] is True
    assert rep["dynamic_oracle_incomplete_functions"] == ["unb_requires"]
    assert [(c["function"], c["kind"], c["label"], c["file"], c["line"]) for c in rep["unchecked_clauses"]] == [
        ("unb_requires", "loop variant", "", PROBE_C, 23),
        ("unb_requires", "requires", "unb_pre", PROBE_C, 13),
    ]
    assert rep["unchecked_clauses"][1]["clause"] == r"\forall integer i; 0 <= i ==> i + n >= 0"
    assert rep["ignored_annotations"] == rep["compile"]["ignored_annotations"]
    assert rep["unattributed_ignored_annotations"] == []
    hints = "\n".join(rep["diagnostic_hints"])
    assert "unb_requires" in hints and "requires unb_pre" in hints and f"{PROBE_C}:13" in hints
    assert "0 <= k < n" in hints  # the usual remedy: explicit integer bounds
    assert "loop variant" in hints


def test_guardrail_report_of_a_fully_translated_function_is_complete(probe_run, monkeypatch):
    _clean_replay(monkeypatch)
    rep = _guardrail_report(monkeypatch, "plain", ["--functions", "plain"])
    assert rep["status"] == "passed_dynamic_oracle"
    assert rep["dynamic_oracle_incomplete"] is False
    assert rep["unchecked_clauses"] == [] and rep["dynamic_oracle_incomplete_functions"] == []
    assert rep["ignored_annotations"] == [] and rep["ignored_frame_clauses"] == 2
    assert rep["diagnostic_hints"] == []


def test_guardrail_report_counts_a_use_of_the_prelude_strlen_against_its_function(probe_run, monkeypatch):
    """`loop variant strlen(s) + 0`: the prelude's `logic integer strlen` makes E-ACSL drop the variant."""
    _clean_replay(monkeypatch)
    rep = _guardrail_report(monkeypatch, "walk", ["--functions", "walk"])
    assert rep["dynamic_oracle_incomplete"] is True
    (clause,) = rep["unchecked_clauses"]
    assert (clause["function"], clause["kind"], clause["clause"], clause["line"]) == (
        "walk",
        "loop variant",
        "strlen(s) + 0",
        50,
    )
    assert "loop variant using GMP" in clause["reason"]
    assert any("termination" in h for h in rep["diagnostic_hints"])


def test_ignored_annotations_of_other_functions_do_not_touch_a_checked_function(probe_run, monkeypatch):
    """A module-wide build: every function's warnings are in the log; `plain` has none of its own."""
    _clean_replay(monkeypatch)
    rep = _guardrail_report(monkeypatch, "module", ["--reach-functions", "plain", "unb_requires"])
    assert rep["status"] == "passed_dynamic_oracle"
    assert len(rep["ignored_annotations"]) == 10  # all of them are listed, with their function
    assert {e["function"] for e in rep["ignored_annotations"]} >= {"walk", "body_assert", "multi_line", "hdr_fn"}
    assert rep["dynamic_oracle_incomplete_functions"] == ["unb_requires"]
    assert {c["function"] for c in rep["unchecked_clauses"]} == {"unb_requires"}


def test_reach_functions_do_not_hide_the_ignored_clause_of_the_contract_function(probe_run, monkeypatch):
    """`--functions f --reach-functions g`: the build holds f's annotations, and f's ignored clause still counts."""
    _clean_replay(monkeypatch)
    rep = _guardrail_report(monkeypatch, "unb_requires", ["--functions", "unb_requires", "--reach-functions", "plain"])
    assert rep["status"] == "passed_dynamic_oracle"
    assert rep["dynamic_oracle_incomplete"] is True
    assert rep["dynamic_oracle_incomplete_functions"] == ["unb_requires"]
    assert [c["label"] for c in rep["unchecked_clauses"]] == ["", "unb_pre"]


def test_an_ignored_header_definition_counts_only_against_the_function_that_uses_it(probe_run):
    """
    The nearest real case to an ignored annotation in a prelude: a `predicate` of a header that
    E-ACSL cannot translate. It counts against the function whose clause uses it and against no other.
    """
    ignored = _attributed("via_hdr_pred", probe_run)
    assert [(e["file"], e["function"]) for e in ignored] == [(PROBE_H, None)]
    fields = R.dynamic_oracle_fields(ignored, ["plain", "via_hdr_pred"])
    assert fields["dynamic_oracle_incomplete_functions"] == ["via_hdr_pred"]
    (clause,) = fields["unchecked_clauses"]
    assert (clause["function"], clause["kind"], clause["label"], clause["via"]) == (
        "via_hdr_pred",
        "requires",
        "from_hdr",
        "hdr_tail_nonneg",
    )
    assert (clause["file"], clause["line"]) == (PROBE_H, 8)  # where E-ACSL gave up: the definition
    alone = R.dynamic_oracle_fields(ignored, ["plain"])
    assert alone["dynamic_oracle_incomplete"] is False and alone["unchecked_clauses"] == []
    assert len(alone["ignored_annotations"]) == 1  # still listed


def test_guardrail_report_through_a_predicate_names_the_clause(probe_run, monkeypatch):
    _clean_replay(monkeypatch)
    rep = _guardrail_report(monkeypatch, "via_wrapped", ["--functions", "via_wrapped"])
    assert rep["dynamic_oracle_incomplete_functions"] == ["via_wrapped"]
    (clause,) = rep["unchecked_clauses"]
    assert (clause["kind"], clause["label"], clause["clause"], clause["via"]) == (
        "requires",
        "wrapped",
        "wraps_tail(n)",
        "wraps_tail",
    )
    assert any("requires wrapped" in h and "wraps_tail" in h for h in rep["diagnostic_hints"])


def test_a_real_contract_violation_is_still_rejected(probe_run, monkeypatch):
    """Control: a false `ensures` beside an ignored `requires` keeps its status; the fields are added to it."""
    captured = json.loads((IGNORED_FIXTURE / "violation.json").read_text(encoding="utf-8"))
    assert captured["status"] == "rejected_overconstrained" and captured["returncode"] == 77

    def failing_replay(cmd, **kw):
        return SandboxResult(captured["returncode"], "", captured["runtime_trace"], False, "rlimits", list(cmd))

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", failing_replay)
    rep = _guardrail_report(monkeypatch, "violation", ["--functions", "wrong_post"], source="violation.c")
    assert rep["status"] == "rejected_overconstrained"
    assert (rep["failure"]["function"], rep["failure"]["label"]) == ("wrong_post", "wrong")
    assert rep["failure"] == captured["failure"]
    assert rep["dynamic_oracle_incomplete"] is True
    assert [(c["function"], c["label"]) for c in rep["unchecked_clauses"]] == [("wrong_post", "unb_pre")]
    assert any("stronger than the actual runtime behavior" in h for h in rep["diagnostic_hints"])


def test_a_failed_build_reports_the_fields_too(probe_run, monkeypatch):
    rep = _guardrail_report(monkeypatch, "unb_requires", ["--functions", "unb_requires"], stage1_rc=1)
    assert rep["status"] == "compile_error"
    assert rep["dynamic_oracle_incomplete"] is True
    assert [c["label"] for c in rep["unchecked_clauses"]] == ["", "unb_pre"]


def test_a_logic_definition_whose_uses_cannot_be_read_is_reported_unattributed(probe_run):
    entries, _frame = T.parse_ignored_annotations(_stage1_output("via_pred"))
    ignored = T.attribute_ignored_annotations(entries, None, cwd=probe_run)  # no instrumented file
    fields = R.dynamic_oracle_fields(ignored, ["via_pred"])
    assert fields["dynamic_oracle_incomplete"] is False and fields["unchecked_clauses"] == []
    (lost,) = fields["unattributed_ignored_annotations"]
    assert (lost["file"], lost["line"], lost["attribution"]) == (PROBE_C, 7, "logic_definition")
    hints = R.derive_eacsl_diagnostic_hints({"status": "passed_dynamic_oracle", **fields})
    assert any("could not be tied to a function" in h and f"{PROBE_C}:7" in h for h in hints)


def test_clause_kinds_eacsl_never_executes_do_not_make_the_oracle_incomplete(probe_run):
    for tag in ("extra_decreases", "extra_terminates", "extra_exits"):
        ignored = _attributed(tag, probe_run)
        assert [e["function"] for e in ignored] == ["probe_fn"]
        fields = R.dynamic_oracle_fields(ignored, ["probe_fn"])
        assert fields["dynamic_oracle_incomplete"] is False and fields["unchecked_clauses"] == []
        assert len(fields["ignored_annotations"]) == 1


# ---------------------------------------------------------------------------
# run_guardrail_check and its verdict cache
# ---------------------------------------------------------------------------


def _guard_binary(run: Path) -> tuple[Path, Path, Path]:
    binary = run / "workspace" / "harnesses" / "guard_probe.e-acsl"
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_bytes(IGNORED_MARKER_BYTES)
    return binary, run / "workspace" / "corpus" / "probe", run / "workspace" / "harnesses" / "scratch"


def test_a_guardrail_without_its_build_report_does_not_claim_a_complete_oracle(probe_run, monkeypatch):
    _clean_replay(monkeypatch)
    binary, corpus, scratch = _guard_binary(probe_run)
    verdict = R.run_guardrail_check(binary, corpus, scratch, 0, module="probe", use_cache=False, functions=["plain"])
    assert verdict["status"] == "passed_dynamic_oracle"
    assert verdict["dynamic_oracle_incomplete"] is None and verdict["ignored_annotations"] is None


def test_a_cached_verdict_carries_the_fields_of_the_build_it_is_asked_about(probe_run, monkeypatch):
    (probe_run / "run-metadata.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setenv("FRAMAC_IMAGE_ID", "sha256:test-image")
    replays: list = []
    _clean_replay(monkeypatch, replays)
    materials: list[dict] = []
    real_make_key = cache.make_key

    def recording_make_key(ns, material):
        if ns == "guardrail":
            materials.append(material)
        return real_make_key(ns, material)

    monkeypatch.setattr(cache, "make_key", recording_make_key)
    binary, corpus, scratch = _guard_binary(probe_run)
    ignored = _attributed("unb_requires", probe_run)

    def check(ignored_annotations):
        return R.run_guardrail_check(
            binary,
            corpus,
            scratch,
            0,
            module="probe",
            functions=["unb_requires"],
            ignored_annotations=ignored_annotations,
        )

    first = check(ignored)
    second = check(ignored)
    assert first["cache"]["hit"] is False and second["cache"]["hit"] is True and len(replays) == 1
    for verdict in (first, second):
        assert verdict["dynamic_oracle_incomplete"] is True
        assert [c["label"] for c in verdict["unchecked_clauses"]] == ["", "unb_pre"]
        assert any("requires unb_pre" in h for h in verdict["diagnostic_hints"])
    # The fields describe the build the caller passes, never the one the verdict was stored with.
    third = check([])
    assert third["cache"]["hit"] is True and third["dynamic_oracle_incomplete"] is False
    assert third["unchecked_clauses"] == [] and third["diagnostic_hints"] == []
    # A verdict stored before these fields existed has another key.
    assert materials and all(m["verdict_fields"] == R.GUARDRAIL_VERDICT_FIELDS for m in materials)


def test_the_build_cache_key_names_the_ignored_annotation_list():
    material = fuzz_build._eacsl_cache_material(
        ["m.c"], Path("bin/fuzz_m"), "gcc_x86_64", "-I.", "all", True, None, "", True, False, True, concurrency=False
    )
    assert material is not None and material["ignored_annotations"] == fuzz_build.IGNORED_ANNOTATIONS_VERSION
