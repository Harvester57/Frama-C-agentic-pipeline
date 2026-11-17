"""
E-ACSL runtime resource aborts (mpack run-3, 2026-11-17): the segment model's tracked heap is a fixed
zone (128 MiB upstream), and a target that allocates an input-sized block aborts the runtime with
"Exceeded heap allocation limit of 128MB". No target check failed, so no failure parses; before the
fix each such input became a `::unparsed_crash::` candidate that cost a Crash Verifier.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import crash_replay
import fuzz_build
import ledger as L
import run_eacsl_fuzz as R
import sandbox_exec
from conftest import write_json
from eacsl_toolchain import EACSL_HEAP_ZONE_MB, eacsl_zone_size_options
from failure_identity import parse_eacsl_resource_abort, parse_runtime_failure
from sandbox_exec import SandboxResult

_SHARE = "/framac-run/workspace/harnesses/eacsl_share/format-runtime-1-a0dcfc7c8028/e-acsl"

# Verbatim from workspace/reports/fuzz/libmpack_a__mpack_expect_2.json `log_tail` (mpack run-3).
_RUN3_CAMPAIGN_LOG = (
    f"{_SHARE}/observation_model/segment_model/e_acsl_segment_tracking.c:532: Exceeded heap allocation limit "
    "of 128MB -- heap memory space moved. \n"
    "artifact_prefix='/framac-run/workspace/crashes/libmpack_a__mpack_expect_2/'; Test unit written to "
    "/framac-run/workspace/crashes/libmpack_a__mpack_expect_2/crash-edf8f8c27705a7eb56ab90518632274d9bf80c47\n"
    f"{_SHARE}/observation_model/segment_model/e_acsl_segment_tracking.c:532: Exceeded heap allocation limit "
    "of 128MB -- heap memory space moved. \n"
    "Base64: CwAAAABA29vb29vb29vb\n"
    "stat::number_of_executed_units: 35518\n"
)

# Verbatim frames of that report's first artifact `replay_log_tail`: the 3000-character tail starts
# mid-stack, after the runtime's message.
_RUN3_REPLAY_TAIL = (
    "    #5 0x7ccb12493c41 in raise (/lib/x86_64-linux-gnu/libc.so.6+0x3fc41) (BuildId: 5e5b51f4c39af9ac)\n"
    f"    #6 0x5e51c27a9a05 in raise_abort {_SHARE}/internals/e_acsl_private_assert.c:26:3\n"
    f"    #7 0x5e51c27a9a05 in private_assert_fail {_SHARE}/internals/e_acsl_private_assert.c:57:5\n"
    f"    #8 0x5e51c27b89cb in set_heap_segment {_SHARE}/observation_model/segment_model/e_acsl_segment_tracking.c:528:3\n"
    f"    #9 0x5e51c27b08fe in unsafe_malloc {_SHARE}/observation_model/segment_model/e_acsl_segment_tracking.c:589:5\n"
    f"    #10 0x5e51c27b08fe in malloc {_SHARE}/observation_model/segment_model/e_acsl_segment_observation_model.c:38:18\n"
    "    #11 0x5e51c26060e2 in mpack_read_bytes_alloc_impl "
    "/framac-run/workspace/harnesses/fuzz_libmpack_a__mpack_expect_2.instrumented.c:44085:16\n"
    "    #12 0x5e51c2745ec5 in LLVMFuzzerTestOneInput "
    "/framac-run/workspace/harnesses/fuzz_libmpack_a__mpack_expect_2.instrumented.c:342806:11\n"
    "\nNOTE: libFuzzer has rudimentary signal handlers.\n"
    "SUMMARY: libFuzzer: deadly signal\n"
)


def test_heap_limit_message_is_a_resource_abort_not_a_target_failure():
    assert parse_runtime_failure(_RUN3_CAMPAIGN_LOG) is None
    abort = parse_eacsl_resource_abort(_RUN3_CAMPAIGN_LOG)
    assert abort is not None
    assert abort["resource"] == "heap" and abort["limit_mb"] == 128
    assert abort["message"] == "Exceeded heap allocation limit of 128MB -- heap memory space moved."
    # The second assertion of set_heap_segment (block end past the zone) is the same limit.
    other = parse_eacsl_resource_abort(
        f"{_SHARE}/x/e_acsl_segment_tracking.c:538: Exceeded heap allocation limit of 1024MB\n"
    )
    assert other is not None and other["limit_mb"] == 1024


def test_heap_limit_stack_signature_without_the_message():
    """run-3's replay tails lost the message: the runtime's assert in set_heap_segment says the same."""
    abort = parse_eacsl_resource_abort(_RUN3_REPLAY_TAIL)
    assert abort is not None and abort["resource"] == "heap" and abort["limit_mb"] is None
    assert abort["caller"] == "mpack_read_bytes_alloc_impl"


def test_target_output_is_not_a_resource_abort():
    assert parse_eacsl_resource_abort("log: Exceeded heap allocation limit of 128MB in my allocator\n") is None
    assert parse_eacsl_resource_abort("") is None
    # A real E-ACSL report keeps parsing as a failure and is no resource abort.
    real = "foo.c: In function 'parse'\nfoo.c:42: Error: Assertion failed:\n  The failing predicate is:\n  rte/mem_access:\n    \\valid_read(p).\n"
    assert parse_runtime_failure(real) is not None


def test_replay_artifact_reads_the_message_from_the_full_output(tmp_path, monkeypatch):
    stack = _RUN3_REPLAY_TAIL * 20  # pushes the message out of the 3000-character tail
    out = _RUN3_CAMPAIGN_LOG.splitlines()[0] + "\n==1== ERROR: libFuzzer: deadly signal\n" + stack

    def fake_run(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        return SandboxResult(77, "", out, False, "rlimits", list(cmd))

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_run)
    art = tmp_path / "crash-1"
    art.write_bytes(b"\x0b")
    rep = crash_replay.replay_artifact(tmp_path / "fuzz.e-acsl", art, tmp_path / "scratch")
    assert "Exceeded heap" not in rep["log_tail"]
    assert rep["failure"] is None
    assert rep["resource_abort"]["limit_mb"] == 128


def _campaign(tmp_path, monkeypatch, sanitizer_out: str | None):
    eacsl_bin = tmp_path / "fuzz.e-acsl"
    eacsl_bin.write_bytes(b"\x7fELF...__e_acsl_assert...eacsl_store_block")
    san_bin = tmp_path / "fuzz.sanreplay"
    san_bin.write_bytes(b"san")
    artifacts = tmp_path / "artifacts"

    def fake_run(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        if "-runs=1" in cmd:
            if cmd[0].endswith("sanreplay"):
                return SandboxResult(1 if sanitizer_out else 0, "", sanitizer_out or "", False, "rlimits", list(cmd))
            return SandboxResult(77, "", _RUN3_CAMPAIGN_LOG + _RUN3_REPLAY_TAIL, False, "rlimits", list(cmd))
        (artifacts / "crash-abc").write_bytes(b"\x0b\x00\x00\x00")
        return SandboxResult(77, "", _RUN3_CAMPAIGN_LOG, False, "rlimits", list(cmd))

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_run)
    builder = (lambda: san_bin) if sanitizer_out is not None else (lambda: None)
    return R.run_fuzz_campaign(eacsl_bin, tmp_path / "corpus", artifacts, attribution_builder=builder)


def test_campaign_marks_the_artifact_and_keeps_it_a_crash(tmp_path, monkeypatch):
    res = _campaign(tmp_path, monkeypatch, None)
    art = res["artifacts"][0]
    assert art["kind"] == "crash" and art["failure"] is None and art["fingerprint"] is None
    assert art["eacsl_resource_abort"]["resource"] == "heap"
    assert art["eacsl_resource_abort"]["sanitizer_replay"] == "unavailable"


@pytest.mark.parametrize(
    ("sanitizer_out", "outcome"),
    [("", "not_reproduced"), ("==1== ERROR: libFuzzer: deadly signal\n", "no_failure")],
)
def test_campaign_sanitizer_replay_without_failure_stays_a_resource_abort(
    tmp_path, monkeypatch, sanitizer_out, outcome
):
    art = _campaign(tmp_path, monkeypatch, sanitizer_out)["artifacts"][0]
    assert art["failure"] is None and art["eacsl_resource_abort"]["sanitizer_replay"] == outcome


def test_campaign_sanitizer_failure_wins_over_the_resource_abort(tmp_path, monkeypatch):
    ubsan = (
        "src/mpack.c:91:28: runtime error: signed integer overflow: 2147483640 + 100 cannot be represented in type 'int'\n"
        "    #0 0x5 in mpack_read_bytes_alloc_impl /framac-run/workspace/work/src/mpack.c:91:28\n"
    )
    art = _campaign(tmp_path, monkeypatch, ubsan)["artifacts"][0]
    assert art["failure_source"] == "sanitizer_replay" and art["fingerprint"]
    assert "eacsl_resource_abort" not in art


def test_campaign_unlocated_sanitizer_failure_keeps_the_crash_for_a_verifier(tmp_path, monkeypatch):
    """The sanitizer build saw a failure it could not locate: not dropped as an E-ACSL limit."""
    asan = "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000011\n"
    art = _campaign(tmp_path, monkeypatch, asan)["artifacts"][0]
    assert art["attribution"]["failure"] is not None and art["failure"] is None
    assert "eacsl_resource_abort" not in art


# mpack run-4 (2026-11-17): ASan's own allocation cap (1 TiB) on the sanitizer replay of an input that
# made the E-ACSL runtime abort on its heap zone. Verbatim from a probe in framac-analysis:latest
# (clang -fsanitize=fuzzer,address,undefined, ASAN_OPTIONS=abort_on_error=1), stack shortened.
_ASAN_SIZE_TOO_BIG = (
    "==17==ERROR: AddressSanitizer: requested allocation size 0x7fffffffffff (0x800000001000 after adjustments "
    "for alignment, red zones etc.) exceeds maximum supported size of 0x10000000000 (thread T0)\n"
    "    #0 0x64ece7bf3713 in malloc (/tmp/probe+0x108713) (BuildId: 453a5dbfcc2ee17f)\n"
    "    #1 0x64ece7c34ebf in mpack_read_bytes_alloc_impl /framac-run/workspace/work/src/mpack.c:527:15\n"
    "==17==HINT: if you don't care about these errors you may set allocator_may_return_null=1\n"
    "SUMMARY: AddressSanitizer: allocation-size-too-big (/tmp/probe+0x108713) in malloc\n"
    "==17==ABORTING\n"
)


def _asan_options(env: dict | None) -> set[str]:
    return set(str((env or {}).get("ASAN_OPTIONS", "")).split(":"))


def test_sanitizer_runs_let_asan_return_null_on_requests_past_its_cap(tmp_path, monkeypatch):
    """
    run-4: ASan aborted on `malloc(<2^40+)` instead of returning NULL, so the target's own check of
    malloc's result (mpack-reader.c:527-531) never ran and the abort hid the E-ACSL heap-limit marker.
    Campaigns and replays run with allocator_may_return_null=1, keeping abort_on_error=1.
    """
    envs: list[tuple[str, dict | None]] = []
    artifacts = tmp_path / "artifacts"

    def fake_run(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        envs.append(("replay" if "-runs=1" in cmd else "campaign", extra_env))
        if "-runs=1" in cmd:
            return SandboxResult(77, "", _RUN3_CAMPAIGN_LOG + _RUN3_REPLAY_TAIL, False, "rlimits", list(cmd))
        (artifacts / "crash-abc").write_bytes(b"\x0b")
        return SandboxResult(77, "", _RUN3_CAMPAIGN_LOG, False, "rlimits", list(cmd))

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_run)
    san_bin = tmp_path / "fuzz.sanreplay"
    san_bin.write_bytes(b"san")
    R.run_fuzz_campaign(tmp_path / "fuzz.e-acsl", tmp_path / "corpus", artifacts, attribution_builder=lambda: san_bin)
    assert {k for k, _ in envs} == {"campaign", "replay"}
    for _, env in envs:
        assert {"abort_on_error=1", "allocator_may_return_null=1"} <= _asan_options(env)


def test_asan_null_return_warning_is_no_failure_and_an_unchecked_null_still_is():
    """With the option, the refused request is a WARNING only; a target that writes through NULL still fails."""
    assert parse_runtime_failure("==29==WARNING: AddressSanitizer failed to allocate 0x7fffffffffff bytes\n") is None
    unchecked = (
        "==35==WARNING: AddressSanitizer failed to allocate 0x7fffffffffff bytes\n"
        "probe.c:19:5: runtime error: applying zero offset to null pointer\n"
        "    #0 0x59ac0d122f98 in consume /probe/probe.c:19:10\n"
        "    #1 0x59ac0d122f98 in LLVMFuzzerTestOneInput /probe/probe.c:33:3\n"
        "SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior probe.c:19:5 \n"
    )
    failure = parse_runtime_failure(unchecked)
    assert failure is not None and failure["function"] == "consume" and failure["line"] == 19


def test_campaign_asan_size_cap_on_the_sanitizer_replay_keeps_the_resource_abort(tmp_path, monkeypatch):
    """run-4 crash-05589b85...: a report written before the option. ASan's cap is the same tool limit."""
    art = _campaign(tmp_path, monkeypatch, _ASAN_SIZE_TOO_BIG)["artifacts"][0]
    assert art["failure"] is None and art["fingerprint"] is None
    assert art["attribution"]["failure"]["kind"] == "asan_requested_allocation_size"
    assert art["eacsl_resource_abort"]["sanitizer_replay"] == "allocation_size_too_big"


_DAG_ONE_FN = {
    "callgraph_source": "frama_c",
    "modules": {"mp": {"tier": "Tier 1A (Untrusted Binary / Network Parser)"}},
    "functions": {
        "mpack_read_bytes_alloc_impl": {
            "name": "mpack_read_bytes_alloc_impl",
            "file": "src/mpack.c",
            "module": "mp",
            "wave": 0,
            "has_loops": False,
            "security_properties": [],
        }
    },
}


def _run3_artifact(**extra) -> dict:
    art = {
        "artifact": "workspace/crashes/mp/crash-1bc025ad562b12fbd113efff209511b71d63122f",
        "kind": "crash",
        "sha256": "b3cde2bbdd54f30a632710a4356dfda38bf372e930460489dadcb71f81f0dcd1",
        "size_bytes": 17,
        "failure": None,
        "fingerprint": None,
        "reproducible": True,
        "replay_log_tail": _RUN3_REPLAY_TAIL,
        "engine": "eacsl",
    }
    art.update(extra)
    return art


@pytest.mark.parametrize("marked", [True, False], ids=["marked_by_campaign", "run3_report_unmarked"])
def test_ingest_resource_abort_is_no_candidate(run_dir, marked):
    write_json(run_dir / "workspace/reports/callgraph_dag.json", _DAG_ONE_FN)
    L.cmd_seed(run_dir / "workspace/reports/callgraph_dag.json", [], "frama_c")
    extra = (
        {"eacsl_resource_abort": parse_eacsl_resource_abort(_RUN3_CAMPAIGN_LOG + _RUN3_REPLAY_TAIL)} if marked else {}
    )
    report = {"mode": "campaign", "module": "mp", "status": "crash_found", "artifacts": [_run3_artifact(**extra)]}
    write_json(run_dir / "workspace/reports/fuzz/mp.json", report)
    stats = L.cmd_ingest_fuzz([run_dir / "workspace/reports/fuzz/mp.json"])
    cands = (
        json.loads((run_dir / "candidates.json").read_text(encoding="utf-8"))
        if (run_dir / "candidates.json").exists()
        else []
    )
    assert [c["fingerprint"] for c in cands if "unparsed_crash" in c["fingerprint"]] == []
    assert stats["eacsl_resource_aborts"] == 1 and stats["candidates"] == 0
    units = json.loads((run_dir / "coverage-ledger.json").read_text(encoding="utf-8"))
    ev = [e for u in units for e in u["evidence"] if e["result"] == "fuzz_eacsl_resource_limit"]
    assert ev and all(e["discharging"] is False and "heap" in e["summary"] for e in ev)


def test_ingest_run4_report_with_asan_size_cap_attribution_is_no_candidate(run_dir):
    """run-4's unmarked reports (crash-05589b85..., -8e6bf00d..., -999ff5f0...) ingest as resource aborts."""
    write_json(run_dir / "workspace/reports/callgraph_dag.json", _DAG_ONE_FN)
    L.cmd_seed(run_dir / "workspace/reports/callgraph_dag.json", [], "frama_c")
    san_failure = parse_runtime_failure(_ASAN_SIZE_TOO_BIG)
    art = _run3_artifact(attribution={"source": "sanitizer_replay", "reproduced": True, "failure": san_failure})
    report = {"mode": "campaign", "module": "mp", "status": "crash_found", "artifacts": [art]}
    write_json(run_dir / "workspace/reports/fuzz/mp.json", report)
    stats = L.cmd_ingest_fuzz([run_dir / "workspace/reports/fuzz/mp.json"])
    cands = (
        json.loads((run_dir / "candidates.json").read_text(encoding="utf-8"))
        if (run_dir / "candidates.json").exists()
        else []
    )
    assert cands == [] and stats["candidates"] == 0 and stats["eacsl_resource_aborts"] == 1


def test_zone_size_option_is_fixed_and_bounded():
    assert eacsl_zone_size_options() == ["--zone-sizes", f"heap:{EACSL_HEAP_ZONE_MB}"]
    assert 128 < EACSL_HEAP_ZONE_MB < 2048
    with pytest.raises(ValueError):
        eacsl_zone_size_options(2048)  # E_ACSL_HEAP_SIZE * MB overflows int: the binary segfaults
    with pytest.raises(ValueError):
        eacsl_zone_size_options(32)


def test_zone_size_reaches_stage_two_and_the_cache_key(tmp_path, monkeypatch):
    monkeypatch.setattr(fuzz_build, "_resolve_eacsl_gcc", lambda: ("e-acsl-gcc", True))
    material = fuzz_build._eacsl_cache_material(
        [str(tmp_path / "a.c")], tmp_path / "fuzz_a", "gcc_x86_64", "-I.", "all", True, None, "", True, False, True
    )
    assert material is not None and material["zone_sizes"] == eacsl_zone_size_options()
    # A build with another zone is another cache entry: a cached 128 MiB binary is never reused.
    monkeypatch.setattr(fuzz_build, "EACSL_HEAP_ZONE_MB", 512)
    other = fuzz_build._eacsl_cache_material(
        [str(tmp_path / "a.c")], tmp_path / "fuzz_a", "gcc_x86_64", "-I.", "all", True, None, "", True, False, True
    )
    assert other is not None and other["zone_sizes"] != material["zone_sizes"]
    monkeypatch.setattr(fuzz_build, "EACSL_HEAP_ZONE_MB", EACSL_HEAP_ZONE_MB)
    calls: list[list[str]] = []

    class _Proc:
        returncode = 1
        stdout = ""
        stderr = "stop"

    def fake_runner(cmd, **kw):
        calls.append(list(cmd))
        if "-n" in cmd:
            Path(cmd[cmd.index("-o") + 1]).write_text("int LLVMFuzzerTestOneInput(void){return 0;}\n", encoding="utf-8")
            p = _Proc()
            p.returncode = 0
            return p
        return _Proc()

    monkeypatch.setattr(fuzz_build, "_resolve_eacsl_gcc", lambda: ("e-acsl-gcc", True))
    src = tmp_path / "a.c"
    src.write_text("int f(void) { return 0; }\n", encoding="utf-8")
    res = fuzz_build.compile_eacsl_binary([str(src)], tmp_path / "fuzz_a", runner=fake_runner, use_cache=False)
    stage2 = [c for c in calls if "-C" in c]
    assert stage2, calls
    i = stage2[0].index("--zone-sizes")
    assert stage2[0][i + 1] == f"heap:{EACSL_HEAP_ZONE_MB}"
    assert res["eacsl_zone_sizes"] == {"heap_mb": EACSL_HEAP_ZONE_MB}
    assert not [c for c in calls if "-n" in c and "--zone-sizes" in c]  # stage 1 needs no runtime size
