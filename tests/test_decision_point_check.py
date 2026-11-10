"""Decision point checked by patch and replay (decision_point_check.py) and its basis in the ledger.

The builds and replays are mocked: the test decides which binary fails on which input. Everything
else (patch parsing, the scratch copy, the report, ledger.py ingest-verifier, the reports) is real.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import decision_point_check as dpc
import ledger
from conftest import FP_REJ, needs_validation_record, write_json
from fingerprint import make_fingerprint
from generate_report import generate
from test_verifier_decision_basis import TAG_RTE, _result, _seed_run
from validate_artifacts import validate_findings, validate_run_dir

pytestmark = pytest.mark.unit

AID = "verifier-4"
SOURCE = """\
#include <stddef.h>

static int ber_decode_len(const unsigned char *buf, size_t len)
{
    size_t n = buf[0];
    return (int)n;
}

int ber_decode_tag(const unsigned char *p, size_t len)
{
    size_t off = ber_decode_len(p, len);
    return p[off];
}
"""
DP = {"file": "src/snmp/ber.c", "line": 5, "function": "ber_decode_len"}
OTHER_FP = make_fingerprint("src/snmp/ber.c", "ber_decode_len", "mem_access", r"\valid_read(buf)")
CRASH = "workspace/crashes/snmp/crash-1"

GOOD_PATCH = """\
--- workspace/work/src/snmp/ber.c
+++ agents/verifier-4/scratch/ber.c
@@ -3,5 +3,7 @@
 static int ber_decode_len(const unsigned char *buf, size_t len)
 {
     size_t n = buf[0];
+    if (n >= len)
+        return 0;
     return (int)n;
 }
"""
SINK_PATCH = """\
--- a/src/snmp/ber.c
+++ b/src/snmp/ber.c
@@ -11,3 +11,3 @@
     size_t off = ber_decode_len(p, len);
-    return p[off];
+    return off < len ? p[off] : 0;
 }
"""


def _setup(run_dir: Path, reproducers: bool = True) -> Path:
    _seed_run(run_dir)
    src = run_dir / "workspace/work/src/snmp/ber.c"
    src.parent.mkdir(parents=True)
    src.write_text(SOURCE, encoding="utf-8", newline="\n")
    (run_dir / "workspace/harnesses").mkdir(parents=True)
    (run_dir / "workspace/harnesses/harness_snmp.c").write_text("int h;\n", encoding="utf-8")
    cands = json.loads((run_dir / "candidates.json").read_text(encoding="utf-8"))
    if reproducers:
        crash = run_dir / CRASH
        crash.parent.mkdir(parents=True)
        crash.write_bytes(b"\xff")
        cands[0]["reproducers"] = [CRASH]
    write_json(run_dir / "candidates.json", cands)
    return src


def _patch(run_dir: Path, text: str = GOOD_PATCH) -> Path:
    path = run_dir / "agents" / AID / "scratch" / "x.dp.patch"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


@pytest.fixture
def tools(monkeypatch):
    """Mocked build and replay. `fails` maps a build name to the fingerprint its replay fails with."""
    state: dict = {"builds": [], "fails": {"unpatched": FP_REJ, "patched": None}, "compile_fails": None}

    def build_spec(module, file, function):
        return {
            "sources": ["workspace/work/src/snmp/ber.c", "workspace/harnesses/harness_snmp.c"],
            "cppflags": "-Iworkspace/work/src -DX=1",
            "ldflags": "",
        }

    def build_binary(module, spec, out_bin, engine):
        name = "patched" if out_bin.name.endswith("_patched") else "unpatched"
        state["builds"].append({"name": name, "spec": spec, "engine": engine, "out_bin": out_bin})
        if state["compile_fails"] == name:
            return {"binary": None, "engine_used": "eacsl", "reason": "compile_error (returncode 1)", "compile": {}}
        return {"binary": out_bin, "engine_used": "eacsl", "compile": {"returncode": 0}}

    def replay(module, inputs, scratch, prepared, per_input_timeout):
        name = "patched" if Path(prepared["binary"]).name.endswith("_patched") else "unpatched"
        fp = state["fails"][name]
        arts = [
            {
                "artifact": p.as_posix(),
                "sha256": "0" * 64,
                "reproducible": fp is not None,
                "timed_out": False,
                "returncode": 1 if fp else 0,
                "fingerprint": fp if fp != "unparsed" else None,
                "failure": {"file": "src/snmp/ber.c", "line": 12, "function": "ber_decode_tag"} if fp else None,
            }
            for p in inputs
        ]
        return {
            "status": "reproduced" if fp else "not_reproduced",
            "binary": str(prepared["binary"]),
            "artifacts": arts,
        }

    monkeypatch.setattr(dpc, "build_spec", build_spec)
    monkeypatch.setattr(dpc, "build_binary", build_binary)
    monkeypatch.setattr(dpc, "replay", replay)
    monkeypatch.setattr(dpc, "candidate_engine", lambda cand: "eacsl")
    return state


def _check(run_dir: Path, patch: Path, dp: dict = DP, **kw) -> dict:
    return dpc.run_check(FP_REJ, patch, AID, dp, run_dir=run_dir, **kw)


# ------------------------------------------------------------------ the patch


def test_parse_and_apply_tolerates_a_shifted_hunk_and_keeps_crlf():
    text = "a\r\nb\r\nc\r\nd\r\n"
    (section,) = dpc.parse_unified_diff("--- a/x.c\n+++ b/x.c\n@@ -7,2 +7,3 @@\n c\n+new\n d\n")
    out = dpc.apply_hunks(text.splitlines(keepends=True), section.hunks, "x.c")
    assert "".join(out) == "a\r\nb\r\nc\r\nnew\r\nd\r\n"


def test_a_hunk_that_matches_nothing_does_not_apply():
    (section,) = dpc.parse_unified_diff("--- a/x.c\n+++ b/x.c\n@@ -1,1 +1,1 @@\n-zzz\n+y\n")
    with pytest.raises(dpc.PatchError) as exc:
        dpc.apply_hunks(["a\n"], section.hunks, "x.c")
    assert exc.value.status == "patch_does_not_apply"


def test_changed_ranges_are_in_unpatched_line_numbers():
    old = SOURCE.splitlines(keepends=True)
    new = old[:5] + ["    if (n >= len)\n", "        return 0;\n"] + old[5:]
    (rng,) = dpc.changed_ranges(old, new, dpc.function_spans(SOURCE))
    assert (rng["kind"], rng["start"], rng["end"], rng["added"], rng["removed"]) == ("insert", 5, 6, 2, 0)
    assert rng["functions"] == ["ber_decode_len"]
    replaced = old[:11] + ["    return 0;\n"] + old[12:]
    (rng,) = dpc.changed_ranges(old, replaced, dpc.function_spans(SOURCE))
    assert (rng["kind"], rng["start"], rng["end"], rng["functions"]) == ("replace", 12, 12, ["ber_decode_tag"])


# ------------------------------------------------------------------ the check


def test_checked_when_only_the_unpatched_build_fails(run_dir, tools):
    src = _setup(run_dir)
    report = _check(run_dir, _patch(run_dir))
    assert report["status"] == "checked"
    assert report["fingerprint"] == FP_REJ and report["decision_point"] == DP
    assert report["sink"] == {"file": "src/snmp/ber.c", "line": 12, "function": "ber_decode_tag"}
    assert report["replay"]["unpatched"]["fails_with_candidate"] is True
    assert report["replay"]["patched"]["fails"] is False
    assert report["inputs"] == [CRASH]

    patch = report["patch"]
    (entry,) = patch["files"]
    assert entry["file"] == "src/snmp/ber.c"
    assert entry["sha256_before"] == hashlib.sha256(SOURCE.encode()).hexdigest()
    assert [(r["kind"], r["start"], r["end"], r["functions"]) for r in entry["ranges"]] == [
        ("insert", 5, 6, ["ber_decode_len"])
    ]
    assert patch["at_decision_point"] is True
    assert patch["touches_sink_line"] is False and patch["outside_decision_function"] is False
    canonical = run_dir / patch["canonical"]
    assert hashlib.sha256(canonical.read_bytes()).hexdigest() == patch["sha256"]
    assert "+    if (n >= len)" in canonical.read_text(encoding="utf-8")

    # On disk, where ingest-verifier reads it; nothing written to the work tree or the harnesses.
    on_disk = json.loads((run_dir / dpc.report_path(FP_REJ)).read_text(encoding="utf-8"))
    assert on_disk == report
    assert dpc.report_path(FP_REJ).as_posix().startswith("workspace/reports/decision_point/")
    assert src.read_text(encoding="utf-8") == SOURCE
    assert sorted(p.name for p in (run_dir / "workspace/harnesses").iterdir()) == ["harness_snmp.c"]

    base, patched = tools["builds"]
    assert base["name"] == "unpatched" and base["spec"]["sources"][0] == "workspace/work/src/snmp/ber.c"
    overlay = f"agents/{AID}/scratch/decision_point/{dpc.candidate_slug(FP_REJ)}/workspace/work"
    assert patched["spec"]["sources"] == [f"{overlay}/src/snmp/ber.c", "workspace/harnesses/harness_snmp.c"]
    flags = patched["spec"]["cppflags"].split()
    assert flags.index(f"-I{overlay}/src") < flags.index("-Iworkspace/work/src") and "-DX=1" in flags
    assert patched["engine"] == "eacsl"
    for build in (base, patched):
        assert f"agents/{AID}/scratch/" in build["out_bin"].as_posix()
    assert not (run_dir / overlay).exists()  # the copy is removed unless --keep-scratch


def test_keep_scratch_leaves_the_patched_copy(run_dir, tools):
    _setup(run_dir)
    _check(run_dir, _patch(run_dir), keep_scratch=True)
    copy = run_dir / f"agents/{AID}/scratch/decision_point/{dpc.candidate_slug(FP_REJ)}/workspace/work/src/snmp/ber.c"
    assert "if (n >= len)" in copy.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("fails", "status"),
    [
        ({"unpatched": FP_REJ, "patched": FP_REJ}, "not_removed"),
        ({"unpatched": FP_REJ, "patched": OTHER_FP}, "other_failure"),
        ({"unpatched": FP_REJ, "patched": "unparsed"}, "other_failure"),
        ({"unpatched": None, "patched": None}, "baseline_not_reproduced"),
        ({"unpatched": OTHER_FP, "patched": None}, "baseline_not_reproduced"),
    ],
    ids=["still-fails", "fails-differently", "fails-unparsed", "baseline-clean", "baseline-other-failure"],
)
def test_every_other_outcome_leaves_the_claim_unchecked(run_dir, tools, fails, status):
    _setup(run_dir)
    tools["fails"] = fails
    report = _check(run_dir, _patch(run_dir))
    assert report["status"] == status and report["reason"]
    assert dpc.agreeing_report(run_dir, FP_REJ, FP_REJ, DP) is None


def test_the_record_fingerprint_may_differ_from_the_candidate(run_dir, tools):
    _setup(run_dir)
    tools["fails"] = {"unpatched": OTHER_FP, "patched": None}
    report = _check(run_dir, _patch(run_dir), failure_fingerprint=OTHER_FP)
    assert report["status"] == "checked" and report["failure_fingerprint"] == OTHER_FP
    assert dpc.agreeing_report(run_dir, FP_REJ, OTHER_FP, DP) is not None


@pytest.mark.parametrize(
    "header",
    [
        "--- workspace/harnesses/harness_snmp.c\n+++ workspace/harnesses/harness_snmp.c\n",
        "--- a/../../etc/passwd\n+++ b/../../etc/passwd\n",
        "--- /dev/null\n+++ b/src/snmp/new.c\n",
        "--- a/src/snmp/missing.c\n+++ b/src/snmp/missing.c\n",
    ],
    ids=["harness", "traversal", "new-file", "not-in-work"],
)
def test_a_patch_outside_the_target_sources_is_refused(run_dir, tools, header):
    _setup(run_dir)
    report = _check(run_dir, _patch(run_dir, GOOD_PATCH + header + "@@ -1,1 +1,1 @@\n-int h;\n+int g;\n"))
    assert report["status"] == "patch_refused"
    assert tools["builds"] == []
    assert (run_dir / "workspace/harnesses/harness_snmp.c").read_text(encoding="utf-8") == "int h;\n"
    assert json.loads((run_dir / dpc.report_path(FP_REJ)).read_text(encoding="utf-8"))["status"] == "patch_refused"


def test_a_patch_on_the_sink_line_is_recorded(run_dir, tools):
    _setup(run_dir)
    report = _check(run_dir, _patch(run_dir, SINK_PATCH))
    assert report["status"] == "checked"
    assert report["patch"]["touches_sink_line"] is True
    assert report["patch"]["outside_decision_function"] is True  # ber_decode_tag, not ber_decode_len
    assert report["patch"]["at_decision_point"] is False  # line 12 is not within 5 lines of line 5
    assert dpc.agreeing_report(run_dir, FP_REJ, FP_REJ, DP) is None
    assert "not within" in dpc.disagreement(run_dir, FP_REJ, FP_REJ, DP)

    # The verifier names the sink as the decision point: it agrees, and the report says what the patch did.
    sink_dp = {"file": "src/snmp/ber.c", "line": 12, "function": "ber_decode_tag"}
    _check(run_dir, _patch(run_dir, SINK_PATCH), dp=sink_dp)
    agrees = dpc.agreeing_report(run_dir, FP_REJ, FP_REJ, sink_dp)
    assert agrees is not None and agrees["flags"]["decision_point_patch_touches_sink_line"] is True
    assert "rewrites the sink line itself" in agrees["description"]


@pytest.mark.parametrize(
    ("patch", "status"),
    [
        ("no diff here\n", "empty_patch"),
        (
            "--- a/src/snmp/ber.c\n+++ b/src/snmp/ber.c\n@@ -5,1 +5,1 @@\n-    nothing like this\n+    x\n",
            "patch_does_not_apply",
        ),
        ("--- a/src/snmp/ber.c\n+++ b/src/snmp/ber.c\n@@ -5,1 +5,1 @@\n     size_t n = buf[0];\n", "empty_patch"),
    ],
    ids=["no-section", "no-match", "no-change"],
)
def test_unusable_patches(run_dir, tools, patch, status):
    _setup(run_dir)
    assert _check(run_dir, _patch(run_dir, patch))["status"] == status
    assert tools["builds"] == []


def test_no_reproducer_and_build_errors(run_dir, tools):
    _setup(run_dir, reproducers=False)
    assert _check(run_dir, _patch(run_dir))["status"] == "no_reproducers"
    assert tools["builds"] == []

    crash = run_dir / CRASH
    crash.parent.mkdir(parents=True)
    crash.write_bytes(b"\xff")
    tools["compile_fails"] = "patched"
    report = _check(run_dir, _patch(run_dir), extra_inputs=[Path(CRASH)])
    assert report["status"] == "build_error" and "patched build failed" in report["reason"]
    assert report["inputs"] == [CRASH]


def test_cli_reads_the_decision_point_from_the_result(run_dir, tools, capsys):
    _setup(run_dir)
    rec = _nv_record({**DP, "controlled_by": "attacker_input", "description": "Unchecked length."})
    res = _result(run_dir, rec, "needs_validation")
    patch = _patch(run_dir)
    rc = dpc.main(["--fingerprint", FP_REJ, "--agent-id", AID, "--patch", str(patch), "--result", str(res)])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0 and out["status"] == "checked" and out["report"] == dpc.report_path(FP_REJ).as_posix()
    assert dpc.main(["--fingerprint", "nope", "--agent-id", AID, "--patch", str(patch), "--result", str(res)]) == 2


# ------------------------------------------------------------------ ledger: the basis


def _nv_record(dp: dict | None) -> dict:
    rec = needs_validation_record(FP_REJ)
    rec["location"] = {"file": "src/snmp/ber.c", "line": 12, "function": "ber_decode_tag"}
    rec["property"] = {"kind": "mem_access", "predicate": r"\valid_read(p)"}
    rec["trace"] = [
        {"kind": "sink", "file": "src/snmp/ber.c", "line": 12, "function": "ber_decode_tag", "description": "*p"}
    ]
    rec["linked_units"] = [TAG_RTE]
    if dp is not None:
        rec["decision_point"] = dp
    return rec


def _dp(**kw) -> dict:
    return {**DP, "controlled_by": "attacker_input", "description": "The length byte is not compared with len.", **kw}


def _ingest(run_dir: Path, dp: dict | None) -> tuple[dict, dict]:
    ledger.cmd_ingest_verifier(_result(run_dir, _nv_record(dp), "needs_validation"))
    unit = json.loads((run_dir / "coverage-ledger.json").read_text(encoding="utf-8"))[0]
    finding = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))[0]
    return unit, finding


@pytest.mark.parametrize("basis", ["checked", "located", "model"])
def test_schema_accepts_a_decision_point_basis(basis):
    assert validate_findings([{**_nv_record(_dp(basis=basis))}]) == []
    assert validate_findings([{**_nv_record(_dp(basis="proven"))}])


@pytest.mark.parametrize("stated", [None, "model", "located", "checked"])
def test_an_agreeing_report_raises_the_basis_to_checked(run_dir, tools, stated):
    _setup(run_dir)
    _check(run_dir, _patch(run_dir))
    unit, finding = _ingest(run_dir, _dp(**({"basis": stated} if stated else {})))
    assert finding["decision_point"]["basis"] == "checked"
    cited = [e for e in finding["evidence"] if e["tool_output"] == dpc.report_path(FP_REJ).as_posix()]
    assert len(cited) == 1 and "removes the failure for 1 recorded reproducer(s)" in cited[0]["description"]
    attempt = unit["attempts"][-1]
    assert attempt["decision"] == "needs_validation" and attempt["decision_point_basis"] == "checked"
    assert attempt["decision_point_basis_source"] == "patch_replay"
    assert attempt["decision_point_patch_touches_sink_line"] is False
    assert attempt.get("decision_point_basis_stated") == (None if stated == "checked" else stated or "unstated")
    assert unit["status"] == "candidate"
    assert validate_run_dir(run_dir) == []


def test_a_stated_checked_without_a_report_is_lowered_to_located(run_dir):
    _setup(run_dir)
    unit, finding = _ingest(run_dir, _dp(basis="checked"))
    assert finding["decision_point"]["basis"] == "located"
    assert len(finding["evidence"]) == 1
    attempt = unit["attempts"][-1]
    assert attempt["decision_point_basis"] == "located" and attempt["decision_point_basis_stated"] == "checked"
    assert attempt["decision_point_basis_lowered"].startswith("no decision point report")
    assert "decision_point_basis_source" not in attempt
    assert validate_run_dir(run_dir) == []


@pytest.mark.parametrize(
    ("change", "why"),
    [
        ({"line": 40}, "another decision point"),
        ({"function": "ber_decode_tag"}, "another decision point"),
        ({"file": "src/snmp/pdu.c"}, "another decision point"),
    ],
    ids=["other-line", "other-function", "other-file"],
)
def test_a_report_for_another_decision_point_does_not_agree(run_dir, tools, change, why):
    _setup(run_dir)
    _check(run_dir, _patch(run_dir))
    unit, finding = _ingest(run_dir, _dp(basis="checked", **change))
    assert finding["decision_point"]["basis"] == "located"
    assert why in unit["attempts"][-1]["decision_point_basis_lowered"]


@pytest.mark.parametrize("tamper", ["status", "patch", "replay", "fingerprint"])
def test_a_report_that_does_not_hold_together_does_not_agree(run_dir, tools, tamper):
    _setup(run_dir)
    report = _check(run_dir, _patch(run_dir))
    path = run_dir / dpc.report_path(FP_REJ)
    if tamper == "status":
        tools["fails"] = {"unpatched": FP_REJ, "patched": FP_REJ}
        _check(run_dir, _patch(run_dir))
    elif tamper == "patch":
        (run_dir / report["patch"]["canonical"]).write_text("--- other\n", encoding="utf-8")
    elif tamper == "replay":
        report["replay"]["patched"]["fails"] = True
        write_json(path, report)
    else:
        report["fingerprint"] = OTHER_FP
        write_json(path, report)
    _, finding = _ingest(run_dir, _dp(basis="checked"))
    assert finding["decision_point"]["basis"] == "located"


@pytest.mark.parametrize("stated", [None, "model", "located"])
def test_without_a_report_the_stated_basis_stays_and_no_status_depends_on_it(run_dir, stated):
    _setup(run_dir)
    unit, finding = _ingest(run_dir, _dp(**({"basis": stated} if stated else {})))
    assert finding["decision_point"].get("basis") == stated
    assert unit["status"] == "candidate" and unit["result_fingerprints"] == [FP_REJ]
    if stated is None:
        assert unit["attempts"] == []
    else:
        assert unit["attempts"][-1]["decision_point_basis"] == stated
        assert "decision_point_basis_stated" not in unit["attempts"][-1]
    assert validate_run_dir(run_dir) == []


def test_scaffold_states_the_weakest_basis(run_dir):
    _seed_run(run_dir)
    for decision in ("confirmed", "needs_validation"):
        assert (
            ledger.cmd_scaffold_verifier(FP_REJ, decision, "verifier-1")["record"]["decision_point"]["basis"] == "model"
        )


def test_reports_print_the_basis(run_dir, tools):
    _setup(run_dir)
    _check(run_dir, _patch(run_dir))
    _ingest(run_dir, _dp())
    generate(run_dir, run_dir)
    nv = (run_dir / "NEEDS-VALIDATION.md").read_text(encoding="utf-8")
    assert "`src/snmp/ber.c:5` in `ber_decode_len`, controlled by `attacker_input` (basis `checked`): " in nv
    report = (run_dir / "REPORT.md").read_text(encoding="utf-8")
    assert "Decision points by basis: 1 `checked` (`checked`: a patch at that location removes the failure" in report
