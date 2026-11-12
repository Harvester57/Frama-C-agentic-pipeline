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
