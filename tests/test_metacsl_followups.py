"""
Package F of docs/plans/metacsl-exploitation-plan.md, three follow-ups of the E-ACSL wiring:

1. REPORT.md says what the fuzz build did with the MetAcsl properties (scripts/generate_report.py);
2. a replay with `--binary` from another directory finds the build's sidecar next to the binary, so
   the violation keeps the campaign's fingerprint (scripts/failure_identity.py, scripts/crash_replay.py);
3. tools/check_generated_text.py does not read the ACSL keyword backslash-name( in a shell file as a
   literal backslash-n.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

import check_generated_text as cgt
import crash_replay
import failure_identity
import generate_report
import run_eacsl_fuzz as R
from conftest import write_json
from test_metacsl_eacsl import (
    OUT_BIN,
    WRITE_FRAMES,
    built_meta,  # noqa: F401  (fixture)
    eacsl_report,
    run_dir,  # noqa: F401  (fixture)
)
from test_report import build_run

pytestmark = pytest.mark.unit

# ---------------------------------------------------------------------------------------------------
# 1. REPORT.md and the fuzz build's MetAcsl properties
# ---------------------------------------------------------------------------------------------------

# sha256 of the REPORT.md of test_report.build_run before package F (commit a91be3e), with LF line
# endings (generate_report.py writes the platform's). A run without the engine must keep these bytes;
# when the report changes for another reason, update the value.
ENGINE_OFF_REPORT_SHA256 = "7139836118174b9e01b6260df66fef1b31327534f5480b0a493fd60845698fb0"
SNMP_CAMPAIGN = "workspace/reports/fuzz/snmp.json"
LOG_BUILD = "workspace/build/log.build.json"
META_LOG = "workspace/harnesses/fuzz_snmp.security_meta.log"
DROPPED_REASON = "the E-ACSL build failed with the properties (compile_error)"


def campaign(module: str, record: dict | None = None, **extra) -> dict:
    """A campaign report as run_eacsl_fuzz.py writes it: the record and its warnings through note_security_props."""
    res: dict = {
        "mode": "campaign",
        "module": module,
        "status": "no_crash",
        "engine_used": "eacsl",
        "compile": {"engine": "eacsl", "returncode": 0, "binary": f"workspace/harnesses/fuzz_{module}.e-acsl"},
        "artifacts": [],
        **extra,
    }
    R.note_security_props(res, record)
    return res


def build_report(module: str, record: dict | None = None) -> dict:
    res = {**campaign(module, record), "mode": "build", "status": "built"}
    del res["artifacts"]
    return res


def report_text(run: Path) -> str:
    generate_report.generate(run, run)
    return (run / "REPORT.md").read_text(encoding="utf-8")


def test_without_the_engine_the_report_is_todays_byte_for_byte(tmp_path):
    plain, with_reports = tmp_path / "plain", tmp_path / "with_reports"
    build_run(plain)
    build_run(with_reports)
    # Engine off: the campaign, build and replay reports hold none of the three fields.
    write_json(with_reports / SNMP_CAMPAIGN, campaign("snmp"))
    write_json(with_reports / LOG_BUILD, build_report("log"))
    write_json(with_reports / "workspace/reports/fuzz/bench-replay-snmp-eacsl.json", {"mode": "replay"})
    for key in ("security_props", "security_props_warnings", "security_props_harness_induced"):
        assert key not in campaign("snmp") and key not in build_report("log")
    text = report_text(plain)
    assert "MetAcsl run-time checks" not in text
    assert hashlib.sha256(text.encode("utf-8")).hexdigest() == ENGINE_OFF_REPORT_SHA256
    report_text(with_reports)
    assert (with_reports / "REPORT.md").read_bytes() == (plain / "REPORT.md").read_bytes()


def test_a_dropped_campaign_build_is_a_warning_in_the_first_section(tmp_path, capsys):
    build_run(tmp_path)
    record = {
        "status": "dropped",
        "props": "workspace/reports/security_props.json",
        "left_out": [],
        "reason": DROPPED_REASON,
        "properties": ["L4_auth_state_login", "L6_wiped_session_key"],
        "log": META_LOG,
    }
    write_json(tmp_path / SNMP_CAMPAIGN, campaign("snmp", record))
    text = report_text(tmp_path)
    first_section = text.split("## 2.")[0]
    assert (
        "> [!WARNING]\n"
        f"> MetAcsl run-time checks: NOT ACTIVE for module snmp ({DROPPED_REASON}). "
        f"No Layer 3-6 property was checked by fuzzing; see {META_LOG}.\n"
    ) in first_section
    # The module's warning repeats it: it is not printed a second time.
    assert "MetAcsl run-time checks, snmp" not in text
    assert text.count("NOT ACTIVE") == 1


def test_a_build_that_lost_the_properties_without_a_log_names_its_report(tmp_path, capsys):
    build_run(tmp_path)
    rejected_all = {"status": "dropped", "props": "p.json", "left_out": [], "reason": "MetAcsl rejected every property"}
    unreadable = {"status": "error", "props": "p.json", "reason": "security properties file not found"}
    write_json(tmp_path / SNMP_CAMPAIGN, campaign("snmp", rejected_all))
    # No campaign report for `log`: its build report speaks.
    write_json(tmp_path / LOG_BUILD, build_report("log", unreadable))
    first_section = report_text(tmp_path).split("## 2.")[0]
    assert (
        "> MetAcsl run-time checks: NOT ACTIVE for module log (security properties file not found). "
        f"No Layer 3-6 property was checked by fuzzing; see {LOG_BUILD}.\n"
    ) in first_section
    assert (
        "> MetAcsl run-time checks: NOT ACTIVE for module snmp (MetAcsl rejected every property). "
        f"No Layer 3-6 property was checked by fuzzing; see {SNMP_CAMPAIGN}.\n"
    ) in first_section


def test_each_warning_of_a_build_that_kept_the_properties_is_a_line(tmp_path, capsys):
    build_run(tmp_path)
    record = {
        "status": "loaded",
        "props": "workspace/reports/security_props.json",
        "left_out": [{"property": "L4_auth_required_login", "reason": "the harness calls admin"}],
        "rejected": [{"property": "L6_wiped_session_key", "reason": "unbound logic variable key"}],
        "properties": ["L4_auth_state_login"],
        "not_translated": ["L5_sanitized_emit"],
        "unplanned_instances": {"L4_auth_state_login": ["helper"]},
    }
    written = campaign("snmp", record)
    warnings = written["security_props_warnings"]
    assert [w.split(":")[0] for w in warnings] == ["rejected", "left out", "not translated", "unplanned instances"]
    write_json(tmp_path / SNMP_CAMPAIGN, written)
    text = report_text(tmp_path)
    assert "NOT ACTIVE" not in text
    lines = [line for line in text.splitlines() if "MetAcsl run-time checks, snmp" in line]
    assert lines == [f"- MetAcsl run-time checks, snmp: {w}" for w in warnings]
    assert text.index(lines[0]) < text.index("## 2.")


def test_a_toolchain_that_cannot_take_the_properties_is_a_warning_line(tmp_path, capsys):
    build_run(tmp_path)
    skipped = {"status": "skipped", "props": "p.json", "left_out": [], "reason": "this frontend has no -meta"}
    no_instance = {**skipped, "reason": R._SECURITY_PROPS_NO_INSTANCE}
    write_json(tmp_path / SNMP_CAMPAIGN, campaign("snmp", skipped))
    write_json(tmp_path / LOG_BUILD, build_report("log", no_instance))
    text = report_text(tmp_path)
    assert (
        "- MetAcsl run-time checks, snmp: skipped: this binary checks no MetAcsl property at run time "
        "(this frontend has no -meta)"
    ) in text
    # A module no property has an instance in: nothing to say.
    assert "MetAcsl run-time checks, log" not in text and "NOT ACTIVE" not in text


def test_a_harness_induced_failure_is_named_as_no_finding(tmp_path, capsys):
    build_run(tmp_path)
    artifacts = [
        {
            "artifact": "workspace/crashes/snmp/crash-9",
            "fingerprint": "src/prog.c#admin::meta_l4_auth_required_login::b67973b196",
            "failure": {
                "meta_property": "L4_auth_required_login",
                "function": "admin",
                "caller": "LLVMFuzzerTestOneInput",
                "harness_induced": True,
            },
        }
    ]
    written = campaign("snmp", {"status": "loaded", "props": "p.json", "left_out": []}, artifacts=artifacts)
    written["security_props_harness_induced"] = R.harness_induced_failures(artifacts)
    assert len(written["security_props_harness_induced"]) == 1
    write_json(tmp_path / SNMP_CAMPAIGN, written)
    text = report_text(tmp_path)
    assert (
        "- L4_auth_required_login failed in admin, called by harness function LLVMFuzzerTestOneInput: "
        "not a finding against the target."
    ) in text
    assert "NOT ACTIVE" not in text


def test_the_campaign_report_wins_over_the_build_report_and_replays_are_not_read(tmp_path, capsys):
    build_run(tmp_path)
    dropped = {"status": "dropped", "props": "p.json", "left_out": [], "reason": "old build", "log": META_LOG}
    # The campaign rebuilt the module and kept the properties: the older build report is not the news.
    write_json(tmp_path / SNMP_CAMPAIGN, campaign("snmp", {"status": "loaded", "props": "p.json", "left_out": []}))
    write_json(tmp_path / "workspace/build/snmp.build.json", build_report("snmp", dropped))
    replay = {**campaign("snmp", dropped), "mode": "replay"}
    write_json(tmp_path / "workspace/reports/fuzz/bench-replay-snmp-eacsl.json", replay)
    text = report_text(tmp_path)
    assert "MetAcsl run-time checks" not in text
    # An unreadable or odd report is no reason to fail the report.
    (tmp_path / LOG_BUILD).write_text("[1, 2", encoding="utf-8")
    write_json(tmp_path / "workspace/build/glue.build.json", {"module": "glue", "security_props": "loaded"})
    assert "MetAcsl run-time checks" not in report_text(tmp_path)


# ---------------------------------------------------------------------------------------------------
# 2. The sidecar next to a replayed binary
# ---------------------------------------------------------------------------------------------------

CAMPAIGN_FINGERPRINT = "src/prog.c#backdoor::meta_l4_auth_state_login::dd581c3f76"


@pytest.fixture
def replayed_elsewhere(built_meta, run_dir, tmp_path_factory, monkeypatch):  # noqa: F811
    """
    The layout of `run_eacsl_fuzz.py replay --binary <run>/<out>.e-acsl` started in another directory:
    (the absolute path of the binary, the output of its run). The binary names its meta file as the
    build was given it, relative to the run directory.
    """
    assert not Path(built_meta).is_absolute()
    binary = run_dir / OUT_BIN.with_name(OUT_BIN.name + ".e-acsl")
    binary.write_bytes(b"\x7fELF")
    output = eacsl_report(
        built_meta, "backdoor", 9, "Assertion", "L4_auth_state_login/meta", r"\separated(state, &auth_ok)", WRITE_FRAMES
    )
    monkeypatch.chdir(tmp_path_factory.mktemp("elsewhere"))
    failure_identity._META_SIDECARS.clear()
    return binary, output


def fake_sandbox(monkeypatch, output: str) -> None:
    ran = SimpleNamespace(stdout="", stderr=output, returncode=77, timed_out=False, sandbox="none")
    monkeypatch.setattr(crash_replay.sandbox_exec, "run_sandboxed", lambda *a, **k: ran)


def test_a_binary_replayed_from_another_directory_keeps_the_campaigns_fingerprint(
    replayed_elsewhere, monkeypatch, tmp_path
):
    binary, output = replayed_elsewhere
    # What the parser knows without the binary: the property, not the file of the function.
    alone = failure_identity.parse_runtime_failure(output)
    assert failure_identity.failure_fingerprint(alone) == CAMPAIGN_FINGERPRINT.replace("src/prog.c", "unknown")
    fake_sandbox(monkeypatch, output)
    crash = tmp_path / "crash-1"
    crash.write_bytes(b"B")
    replay = crash_replay.replay_artifact(binary, crash, tmp_path / "scratch", seed=1)
    assert replay["reproduced"] and replay["failure"]["file"] == "src/prog.c"
    assert failure_identity.failure_fingerprint(replay["failure"]) == CAMPAIGN_FINGERPRINT
    # The report of the replay subcommand carries it.
    monkeypatch.setattr(crash_replay, "is_eacsl_instrumented", lambda path: True)
    report = crash_replay.replay_report("prog", [crash], tmp_path / "scratch", binary=binary)
    assert report["status"] == "reproduced", report
    assert [a["fingerprint"] for a in report["artifacts"]] == [CAMPAIGN_FINGERPRINT]


def test_a_guard_failure_replayed_from_another_directory_is_still_mapped_to_its_property(replayed_elsewhere):
    binary, output = replayed_elsewhere
    meta_file = output.splitlines()[1].split(":")[0]
    sidecar = json.loads((binary.parent / Path(meta_file).with_suffix(".json").name).read_text(encoding="utf-8"))
    line = next(int(k) for k, v in sidecar["line_names"].items() if v == "L5_sanitized_logmsg")
    guard = eacsl_report(meta_file, "process", line, "E-ACSL RTE", "memory access", r"\valid_read(s + i)", "")
    assert "meta_property" not in failure_identity.parse_runtime_failure(guard)
    for parse in (failure_identity.parse_runtime_failure, failure_identity.parse_eacsl_failure):
        failure = parse(guard, binary=binary)
        assert failure["meta_property"] == "L5_sanitized_logmsg" and failure["meta_guard"] == "memory access"
        assert failure["file"] == "src/prog.c"


def test_the_sidecar_next_to_the_binary_is_the_one_of_the_binary(replayed_elsewhere):
    binary, output = replayed_elsewhere
    meta_file = Path(output.splitlines()[1].split(":")[0])
    # The other directory holds a build of its own at the same relative path, of another module.
    stale = failure_identity.meta_sidecar_path(meta_file)
    stale.parent.mkdir(parents=True)
    shutil.copy(binary.parent / meta_file.name, meta_file)
    stale.write_text(json.dumps({"functions": {"backdoor": ["other/module.c"]}}), encoding="utf-8")
    assert failure_identity.parse_runtime_failure(output)["file"] == "other/module.c"
    assert failure_identity.parse_runtime_failure(output, binary=binary)["file"] == "src/prog.c"
    # A binary without a sidecar beside it (a copy): the path the binary printed is still looked up.
    copy = binary.parent.parent / "copy" / binary.name
    copy.parent.mkdir()
    shutil.copy(binary, copy)
    assert failure_identity.parse_runtime_failure(output, binary=copy)["file"] == "other/module.c"


# ---------------------------------------------------------------------------------------------------
# 3. check_generated_text.py: ACSL keywords that start with backslash-n in a shell file
# ---------------------------------------------------------------------------------------------------

BACKSLASH = chr(92)


def sh_rules(tmp_path: Path, text: str) -> list[tuple[int, str]]:
    path = tmp_path / "script.sh"
    path.write_bytes(text.encode("utf-8"))
    assert BACKSLASH + "n" in text and "\r" not in text
    return [(v.line, v.rule) for v in cgt.check_file(path, root=tmp_path)]


def meta_property(name: str = "L4_auth_state_login") -> str:
    text = r"/*@ meta \prop, \name(NAME), \targets(\ALL), \context(\writing), \separated(\written, &auth_ok); */"
    return text.replace("NAME", name)


def test_the_metacsl_name_keyword_in_a_shell_file_is_no_literal_newline(tmp_path):
    text = "cat > meta.c <<'EOF'\n" + meta_property() + "\nEOF\n"
    assert BACKSLASH + "name(L4_auth_state_login)" in text
    assert sh_rules(tmp_path, text) == []
    spaced = text.replace("name(", "name (")
    assert sh_rules(tmp_path, spaced) == []


@pytest.mark.parametrize("keyword", ["nothing;", "null;", "numof(0, n, f)", "name(p)"])
def test_the_acsl_keywords_that_start_with_backslash_n_are_fine(tmp_path, keyword):
    assert sh_rules(tmp_path, "x='" + BACKSLASH + keyword + "'\n") == []


@pytest.mark.parametrize(
    "line",
    [
        'echo "a' + BACKSLASH + 'nb" > out',
        'echo "first' + BACKSLASH + 'nameless second"',
        'echo "first' + BACKSLASH + 'name second"',
        'echo "x' + BACKSLASH + 'nullify"',
        'echo "x' + BACKSLASH + 'nothings"',
        # The keyword does not excuse a real one on the same line.
        'echo "' + meta_property() + BACKSLASH + 'nint x;" > meta.c',
        'echo "int x;' + BACKSLASH + "n" + meta_property() + '" > meta.c',
    ],
)
def test_a_literal_backslash_n_in_a_shell_string_is_still_flagged(tmp_path, line):
    assert sh_rules(tmp_path, line + "\n") == [(1, "sh-literal-newline")]
