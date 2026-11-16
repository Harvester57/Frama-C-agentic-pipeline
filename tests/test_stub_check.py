"""Checks of stub contracts (docs/plans/templates-and-stubs-improvement-plan.md S3): scripts/stub_check.py."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

import ledger as L
import phase0_gates
import pipeline_make
import stub_check
from conftest import ANALYSIS_IMAGE, ROOT, require_docker_images, write_json

HASH = "int ml_hash(ml_ctx *ctx, unsigned char const *data, size_t len, unsigned char out[32])"
NAME = "char const *ml_name(ml_ctx const *ctx)"
HEADER = "workspace/stubs/mylib/mylib.h"
FIXTURE = ROOT / "tests" / "fixtures" / "stub_check"
# Shipped stubs that still diverge from the real header: header -> member (S4 repaired ip_icmp.h).
KNOWN_SHIPPED_DIVERGENCES: dict[str, str] = {}


def _docker(*args: str, mounts: dict[Path, str], timeout: int = 900) -> str:
    vols = [x for host, guest in mounts.items() for x in ("-v", f"{host}:{guest}")]
    proc = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", *vols,
         "-v", f"{ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
         "-v", f"{ROOT / 'templates'}:/opt/framac-pipeline/templates:ro",
         "--entrypoint", args[0], ANALYSIS_IMAGE, *args[1:]],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, check=False,
    )  # fmt: skip
    return proc.stdout + proc.stderr


def _sig(proto: str) -> dict:
    sig = stub_check.parse_proto(proto)
    assert sig is not None
    return sig


# ---------------------------------------------------------------------------
# Signatures and generated programs
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_parse_proto_reads_the_models_prototype():
    sig = stub_check.parse_proto(HASH)
    assert sig is not None
    assert sig["name"] == "ml_hash" and not sig["returns_void"]
    assert [(p["name"], p["type"], p["array"]) for p in sig["params"]] == [
        ("ctx", "ml_ctx *", None),
        ("data", "unsigned char const *", None),
        ("len", "size_t", None),
        ("out", "unsigned char *", 32),
    ]
    assert stub_check.parse_proto("void f(void)") == {"name": "f", "returns_void": True, "params": []}
    unnamed = _sig("int g(int, char *, unsigned long, struct ctx)")
    assert [(p["name"], p["type"]) for p in unnamed["params"]] == [
        ("a0", "int"),
        ("a1", "char *"),
        ("a2", "unsigned long"),
        ("a3", "struct ctx"),
    ]


@pytest.mark.unit
@pytest.mark.parametrize(
    "proto",
    ["int printf(char const *fmt, ...)", "void (*signal(int sig, void (*h)(int)))(int)", "int x", ""],
)
def test_parse_proto_refuses_what_cannot_be_called_generically(proto):
    assert stub_check.parse_proto(proto) is None


@pytest.mark.unit
def test_smoke_program_has_a_valid_and_a_short_call_per_bounded_function():
    sigs = [_sig(HASH), _sig(NAME)]
    text, lines_of = stub_check.smoke_source("mylib/mylib.h", sigs)
    lines = text.splitlines()
    assert lines[0] == "#include <mylib/mylib.h>"
    assert sorted(lines_of.values()) == [("ml_hash", "ok"), ("ml_hash", "short"), ("ml_name", "ok")]
    for line_no, (fn, _kind) in lines_of.items():
        assert f"{fn}(" in lines[line_no - 1]
    short = next(n for n, w in lines_of.items() if w == ("ml_hash", "short"))
    ok = next(n for n, w in lines_of.items() if w == ("ml_hash", "ok"))
    # The short call passes a length one past its buffer and a fixed array one element short.
    assert f"(size_t)({stub_check.BUF} + 1)" in lines[short - 1]
    assert "v_3[31]" in "\n".join(lines[ok:short])
    assert "fc_stub_smoke_main" in text


@pytest.mark.unit
def test_driver_runs_one_function_per_process():
    text = stub_check.driver_source("mylib/mylib.h", [_sig(HASH)], trials=5)
    assert "case 0: fc_drive_0(t, n); break;" in text
    assert "for (unsigned t = 0; t < 5u; t++)" in text
    assert "(size_t)(n)" in text


# ---------------------------------------------------------------------------
# Blocking and the gate
# ---------------------------------------------------------------------------

DAG = {
    "modules": {
        "liba": {"external_callees": ["ml_hash"], "lexer_modules": ["liba_lex"], "ldflags": ["-lmylib"]},
        "big": {"external_callees": ["ml_name"], "split": {"submodules": ["big__1", "big__2"]}},
        "other": {"external_callees": ["strlen"], "ldflags": ["-lz"]},
    }
}


@pytest.mark.unit
def test_a_failed_header_blocks_its_callers_with_their_lexer_and_sub_modules():
    assert stub_check.blocked_modules(DAG, {HEADER: ["ml_hash"]}) == {"liba": [HEADER], "liba_lex": [HEADER]}
    assert sorted(stub_check.blocked_modules(DAG, {HEADER: ["ml_hash", "ml_name"]})) == [
        "big",
        "big__1",
        "big__2",
        "liba",
        "liba_lex",
    ]
    assert stub_check.blocked_modules(DAG, {}) == {}
    assert stub_check.module_ldflags(DAG, ["ml_hash", "strlen"]) == ["-lmylib", "-lz"]


def _check_report(status: str = "failed", digest: str = "d1") -> dict:
    return {
        "schema_version": 1,
        "headers": {
            HEADER: {
                "digest": digest,
                "status": status,
                "reasons": ["ml_hash: postcondition failed against the real library"] if status == "failed" else [],
                "dynamic": {"status": "ok", "functions": {"ml_hash": {"status": "violated" if status == "failed" else "passed"}}},
                "eva": {"status": "ok", "functions": {"ml_hash": {"status": "passed"}}},
            }
        },
        "blocked_modules": {"liba": [HEADER], "liba_lex": [HEADER]} if status == "failed" else {},
    }  # fmt: skip


@pytest.mark.unit
def test_the_phase0_gate_refuses_the_blocked_modules(run_dir):
    assert stub_check.gate_reasons(run_dir, "liba") == []  # no stub-check yet: nothing to block
    write_json(run_dir / stub_check.STUB_CHECK_REL, _check_report())
    reasons = phase0_gates.check(run_dir, "liba_lex", need=())
    assert len(reasons) == 1
    assert f"stub-check failed for {HEADER}" in reasons[0]
    assert "postcondition failed" in reasons[0] and "pipeline_make.py run stubs stub-check" in reasons[0]
    assert phase0_gates.check(run_dir, "other", need=()) == []
    assert len(phase0_gates.check(run_dir, None, need=())) == 2
    write_json(run_dir / stub_check.STUB_CHECK_REL, _check_report("passed"))
    assert phase0_gates.check(run_dir, "liba", need=()) == []


@pytest.mark.unit
def test_a_header_left_out_keeps_its_result_only_while_unchanged(run_dir):
    other = "workspace/stubs/other.h"
    write_json(run_dir / stub_check.STUB_CHECK_REL, _check_report())
    write_json(run_dir / "workspace/reports/callgraph_dag.json", DAG)

    def run(digest: str) -> dict:
        stubs = {"headers": {HEADER: {"digest": digest, "functions": {"ml_hash": {"state": "filled"}}},
                             other: {"digest": "x", "functions": {}}}}  # fmt: skip
        write_json(run_dir / "workspace/reports/stubs.json", stubs)
        stub_check.main(["run", "--header", other, "--checks", ""])
        return json.loads((run_dir / stub_check.STUB_CHECK_REL).read_text(encoding="utf-8"))

    kept = run("d1")
    assert kept["headers"][HEADER]["status"] == "failed"
    assert sorted(kept["blocked_modules"]) == ["liba", "liba_lex"]
    dropped = run("d2")
    assert HEADER not in dropped["headers"]
    assert dropped["blocked_modules"] == {}


@pytest.mark.unit
def test_the_ledger_records_what_stub_check_found_for_the_same_content():
    report = {
        "headers": {HEADER: {"digest": "d1", "functions": {"ml_hash": {"state": "filled", "callers": ["src/a.c#use"]}}}}
    }
    texts = L.stub_contract_descriptions(report, _check_report())
    assert texts[("src/a.c", "use")] == [
        f"Overlay stub contract of ml_hash in {HEADER} (sha256 d1, filled) is assumed, not proven; "
        "stub-check: dynamic violated, header failed."
    ]
    stale = L.stub_contract_descriptions(report, _check_report(digest="d0"))
    assert stale[("src/a.c", "use")][0].endswith("is assumed, not proven.")
    assert L.stub_check_status(_check_report("passed"), HEADER, "d1", "ml_hash") == "dynamic passed"


# ---------------------------------------------------------------------------
# Diagnostics: the fatal message and the logs kept for the agent (c-ares run-1, 2026-11-16)
# ---------------------------------------------------------------------------

EPOLL_HDR = "workspace/stubs/sys/epoll.h"
EPOLL_CREATE1 = "extern  __attribute__((__nothrow__)) int epoll_create1(int __flags) __attribute__(( __leaf__))"
EPOLL_LOGS = "workspace/reports/stub_check/sys__epoll.h"


@pytest.mark.unit
def test_the_reason_is_the_fatal_message_with_its_text():
    """
    Eva prints `[eva:assigns:missing] <file>:18: User Error:` and the message on the next, indented line;
    stub_check used to report the first line alone, so the agent never saw "no \\from part".
    """
    eva = (FIXTURE / "eva_assigns_missing.log").read_text(encoding="utf-8")
    reason = stub_check._first_error(eva)
    assert reason.startswith("[eva:assigns:missing] "), reason
    assert "User Error: no \\from part for clause 'assigns __fc_errno;'" in reason, reason
    eacsl = (FIXTURE / "eacsl_unbound_fc_errno.log").read_text(encoding="utf-8")
    reason = stub_check._first_error(eacsl)
    assert "Failure: unbound logic variable __fc_errno" in reason, reason
    assert stub_check.header_annot_error({"status": "build_failed", "reason": reason}, EPOLL_HDR)
    assert not stub_check.header_annot_error({"status": "build_failed", "reason": reason}, "workspace/stubs/zlib.h")
    # cpp's `warning: "__errordecl" redefined` merely contains "error": the fatal message wins wherever it is.
    noisy = (
        'x.h:431:9: warning: "__errordecl" redefined\n'
        "[eva] analyzing\n"
        "[kernel] x.h:3: User Error:\n  bad annotation\n"
        "[kernel] Plug-in eva aborted: invalid user input.\n"
    )
    assert stub_check._first_error(noisy) == "[kernel] x.h:3: User Error: bad annotation"
    assert stub_check._first_error("cc1: some note\nlast line\n") == "last line"


def _epoll_inputs() -> None:
    write_json(Path("workspace/reports/stubs.json"), {"headers": {EPOLL_HDR: {
        "include_name": "sys/epoll.h", "digest": "e1", "problems": [],
        "functions": {"epoll_create1": {"state": "filled"}}}}})  # fmt: skip
    write_json(Path("workspace/reports/phase0_model.json"), {"external_decls": {"epoll_create1": {"proto": EPOLL_CREATE1}}})
    write_json(Path("workspace/reports/callgraph_dag.json"), {"modules": {"m": {"external_callees": ["epoll_create1"]}}})


@pytest.mark.unit
def test_run_keeps_each_headers_logs_and_names_them(run_dir, monkeypatch):
    """The Eva log, the smoke program and the reason's `(see <log>)` survive the run; the gate names them."""
    eva = (FIXTURE / "eva_assigns_missing.log").read_text(encoding="utf-8")
    monkeypatch.setattr(stub_check, "_run", lambda cmd, cwd, **_: (1, eva) if cmd[0] == "frama-c" else (0, ""))
    _epoll_inputs()
    stale = run_dir / EPOLL_LOGS / "run7.log"
    stale.parent.mkdir(parents=True)
    stale.write_text("from an older check", encoding="utf-8")
    assert stub_check.main(["run", "--checks", "eva"]) == 1
    rec = json.loads((run_dir / stub_check.STUB_CHECK_REL).read_text(encoding="utf-8"))["headers"][EPOLL_HDR]
    assert rec["eva"]["status"] == "error"
    assert rec["eva"]["log"] == f"{EPOLL_LOGS}/eva.log"
    assert rec["artifacts"] == {"dir": EPOLL_LOGS, "files": ["fc_stub_smoke.c", "eva.log"]}
    assert rec["reasons"] == [
        f"Frama-C: {stub_check._first_error(eva)} (see {EPOLL_LOGS}/eva.log)"
    ]
    assert "no \\from part for clause" in rec["reasons"][0]
    kept = (run_dir / EPOLL_LOGS / "eva.log").read_text(encoding="utf-8")
    assert kept.startswith("$ frama-c ") and "Deferred error" in kept
    assert "epoll_create1(" in (run_dir / EPOLL_LOGS / "fc_stub_smoke.c").read_text(encoding="utf-8")
    assert not stale.exists()  # the header was re-checked: its old artifacts went
    gate = phase0_gates.check(run_dir, "m", need=())
    assert len(gate) == 1 and f"logs and generated programs in {EPOLL_LOGS}/" in gate[0], gate
    # A header left out of the next run keeps its result and its artifacts.
    stub_check.main(["run", "--header", "workspace/stubs/other.h", "--checks", "eva"])
    assert (run_dir / EPOLL_LOGS / "eva.log").is_file()


@pytest.mark.unit
def test_an_eacsl_annotation_error_in_the_header_blocks_it(run_dir, monkeypatch):
    """`__fc_errno` is unbound under E-ACSL: every fuzz build including the header would abort."""
    eacsl = (FIXTURE / "eacsl_unbound_fc_errno.log").read_text(encoding="utf-8")
    monkeypatch.setattr(stub_check, "_run", lambda cmd, cwd, **_: (1, eacsl) if cmd[0] == "e-acsl-gcc" else (0, ""))
    _epoll_inputs()
    assert stub_check.main(["run", "--checks", "dynamic"]) == 1
    data = json.loads((run_dir / stub_check.STUB_CHECK_REL).read_text(encoding="utf-8"))
    rec = data["headers"][EPOLL_HDR]
    assert rec["dynamic"]["status"] == "build_failed"
    assert rec["reasons"] == [
        f"E-ACSL: {stub_check._first_error(eacsl)} (see {EPOLL_LOGS}/eacsl_instrument.log)"
    ]
    assert data["blocked_modules"] == {"m": [EPOLL_HDR]}


# The c-ares run-1 overlay wrapper for glibc's <sys/epoll.h> (its parse aids), then the header stub_gen.py
# writes (`#include <errno.h>`), then one contract whose `assigns` each case varies.
_EPOLL_OVERLAY = """#pragma once
#include <time.h>
#include <bits/types/__sigset_t.h>
#include <sys/cdefs.h>
#ifndef _STRUCT_TIMESPEC
#  define _STRUCT_TIMESPEC 1
#endif
#include_next <sys/epoll.h>
#include <errno.h>
/* fc-stub: epoll_create1 */
/*@
  terminates \\true;
  exits \\false;
  ASSIGNS
  ensures result_fd_or_error: \\result >= 0 || \\result == -1;
*/
extern int epoll_create1(int __flags);
"""


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize(
    "assigns, eva, dynamic",
    [
        # c-ares run-1's stub authors: no \from on errno. Eva aborts (Phase 2 Eva would too).
        ("assigns errno, \\result;", "no \\from part for clause 'assigns __fc_errno;'", "passed"),
        # The old brief's spelling: Eva parses it, the E-ACSL build does not.
        ("assigns __fc_errno \\from \\nothing; assigns \\result \\from indirect:__flags;", None,
         "unbound logic variable __fc_errno"),
        ("assigns errno \\from \\nothing; assigns \\result \\from indirect:__flags;", None, "passed"),
    ],
)  # fmt: skip
def test_errno_in_a_stub_contract_against_eva_and_eacsl(tmp_path, assigns, eva, dynamic):
    require_docker_images(ANALYSIS_IMAGE)
    run = tmp_path / "run"
    hdr = run / EPOLL_HDR
    hdr.parent.mkdir(parents=True)
    hdr.write_text(_EPOLL_OVERLAY.replace("ASSIGNS", assigns), encoding="utf-8", newline="\n")
    reports = {
        "stubs.json": {"headers": {EPOLL_HDR: {"include_name": "sys/epoll.h", "problems": [],
                                               "functions": {"epoll_create1": {"state": "filled"}}}}},
        "phase0_model.json": {"external_decls": {"epoll_create1": {"proto": EPOLL_CREATE1}}},
        "callgraph_dag.json": {"modules": {"m": {"external_callees": ["epoll_create1"]}}},
    }  # fmt: skip
    for name, data in reports.items():
        write_json(run / "workspace" / "reports" / name, data)
    out = _docker(
        "sh", "-c",
        "cd /w && FRAMAC_STUB_OVERLAY_DIR=/w/workspace/stubs FRAMAC_CACHE=off timeout 900 "
        "python3 /opt/framac-pipeline/scripts/stub_check.py run --trials 2",
        mounts={run: "/w"},
    )  # fmt: skip
    rec = json.loads((run / stub_check.STUB_CHECK_REL).read_text(encoding="utf-8"))["headers"][EPOLL_HDR]
    if eva is None:
        assert rec["eva"]["status"] == "ok", out
    else:
        assert rec["eva"]["status"] == "error" and eva in rec["eva"]["reason"], out
        assert (run / EPOLL_LOGS / "eva.log").is_file(), out
    if dynamic == "passed":
        assert rec["dynamic"]["functions"]["epoll_create1"]["status"] == "passed", out
    else:
        assert rec["dynamic"]["status"] == "build_failed" and dynamic in rec["dynamic"]["reason"], out
    assert rec["status"] == ("passed" if eva is None and dynamic == "passed" else "failed"), out


# ---------------------------------------------------------------------------
# Make and the stage order
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_stub_check_runs_between_stubs_and_seed():
    stage = pipeline_make.STAGE_OF_TARGET
    assert stage["stubs"] < stage["stub-check"] < stage["seed"] == stage["reach-gate"] < stage["build"]
    assert pipeline_make._TARGET_OUTPUTS["stub-check"] == stub_check.STUB_CHECK_REL
    mk = (ROOT / "templates" / "pipeline.mk").read_text(encoding="utf-8")
    phony = mk.split(".PHONY:", 1)[1].split("\n\n", 1)[0]
    help_line = next(line for line in mk.splitlines() if "@echo 'Targets:" in line)
    assert " stub-check " in phony and " stub-check " in help_line
    assert "\nstub-check:\n" in mk and "--class replay --key stub-check" in mk


# ---------------------------------------------------------------------------
# Shipped stubs
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_struct_members_include_the_member_macros():
    text = (ROOT / "templates" / "fc_stubs" / "netinet" / "ip_icmp.h").read_text(encoding="utf-8")
    members = stub_check.struct_members(text)
    assert members["icmphdr"] == ["type", "code", "checksum", "un"]
    assert {"icmp_hun", "icmp_dun", "icmp_ip", "icmp_id"} <= set(members["icmp"])
    assert stub_check.struct_members("struct a { int x; unsigned f : 3; char *p[4]; };") == {"a": ["x", "p"]}
    probe = stub_check.layout_probe_source("netinet/ip_icmp.h", {"icmp": ["icmp_ip"]})
    assert "offsetof(struct icmp, icmp_ip)" in probe and "__builtin_classify_type" in probe


@pytest.mark.unit
def test_shipped_prototypes_drop_the_contracts():
    text = "/*@ requires \\valid(p);\n    assigns *p; */\nint f(int *p);\n// note\nvoid g(void);\n"
    assert stub_check.shipped_prototypes(text, "x.h") == ["int f(int *p);", "void g(void);"]


@pytest.mark.integration
@pytest.mark.slow
def test_shipped_check_finds_a_type_divergence_and_a_wrong_prototype(tmp_path):
    require_docker_images(ANALYSIS_IMAGE)
    real = tmp_path / "real" / "fake"
    stubs = tmp_path / "stubs" / "fake"
    real.mkdir(parents=True)
    stubs.mkdir(parents=True)
    (real / "hdr.h").write_text(
        "#pragma once\nstruct inner { int a, b; };\n"
        "struct s { int x; union { struct inner in; char raw[8]; } u; };\n#define s_in u.in\n"
        "long fk(int x);\n",
        encoding="utf-8",
    )
    (stubs / "hdr.h").write_text(
        "#pragma once\nstruct s { int x; union { unsigned char in[8]; char raw[8]; } u;\n#define s_in u.in\n};\n"
        "/*@ assigns \\result \\from x; */\nint fk(int x);\n",
        encoding="utf-8",
    )
    out = _docker(
        "python3", "/opt/framac-pipeline/scripts/stub_check.py", "shipped", "--stubs-dir", "/w/stubs",
        "--isystem", "/w/real",
        mounts={tmp_path: "/w:ro"},
    )  # fmt: skip
    data = json.loads(out[out.index("{") :])
    rec = data["headers"]["fake/hdr.h"]
    assert rec["status"] == "failed", out
    assert "prototypes:" in rec["reason"] and "conflicting types" in rec["reason"], out
    assert "s.s_in: real '4 8 12', stub '4 8 5'" in rec["reason"], out


@pytest.mark.integration
@pytest.mark.slow
def test_shipped_stubs_match_the_real_headers_of_the_image():
    """Every divergence is a known one (S4 repairs them); a new one fails here."""
    require_docker_images(ANALYSIS_IMAGE)
    out = _docker("python3", "/opt/framac-pipeline/scripts/stub_check.py", "shipped", mounts={})
    data = json.loads(out[out.index("{") :])
    assert data["headers"], out
    for header, rec in data["headers"].items():
        if rec["status"] == "failed":
            assert header in KNOWN_SHIPPED_DIVERGENCES, out
            assert KNOWN_SHIPPED_DIVERGENCES[header] in rec["reason"], out


# ---------------------------------------------------------------------------
# The overlay against a real library
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize("mode", ["good", "bad"])
def test_stub_check_against_the_real_library(mode):
    """
    tests/fixtures/stub_check/scenario.sh: a snapshot with libmylib, the overlay stub_gen.py writes for it,
    filled by hand. `good` contracts pass all three checks; `bad` promises a result the library does not
    return, so the dynamic check finds it violated and the gate blocks the module and its lexer module.
    """
    require_docker_images(ANALYSIS_IMAGE)
    out = _docker("sh", "/fixture/scenario.sh", mode, mounts={FIXTURE: "/fixture:ro"})
    report = json.loads(out.split("REPORT-BEGIN", 1)[1].split("REPORT-END", 1)[0])
    rec = report["headers"][HEADER]
    assert rec["abi"]["status"] == "passed", out
    assert rec["eva"]["functions"]["ml_hash"]["status"] == "passed", out
    assert rec["eva"]["functions"]["ml_hash"]["short_call_alarms"], out
    dyn = rec["dynamic"]["functions"]
    assert dyn["ml_name"]["status"] == "passed", out
    if mode == "good":
        assert "rc=0" in out, out
        assert dyn["ml_hash"]["status"] == "passed", out
        assert report["blocked_modules"] == {}, out
        assert "stub-check failed" not in out, out
    else:
        assert "rc=1" in out, out
        assert dyn["ml_hash"]["status"] == "violated", out
        assert "\\result: 0" in dyn["ml_hash"]["report"], out
        assert report["blocked_modules"] == {"liba": [HEADER], "liba_lex": [HEADER]}, out
        assert f"stub-check failed for {HEADER}" in out, out
