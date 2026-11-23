"""
Regression tests for:
- non-reproducing crashes never skipping innocent dispatch cases in `run_campaign_rounds`;
- isolated per-invocation / per-batch working directories across `crash_replay`, `fuzz_coverage`,
  `harness_smoke`, and `run_eacsl_fuzz.run_judge`;
- automatic per-input cwd isolation fallback in `run_judge` when a target writes files into cwd;
- deterministic setup-prefix blinding in `run_judge` (recording the candidate once while blinding
  only cases whose confirmed standalone abort happens inside their deterministic setup prefix).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

import crash_replay
import fuzz_coverage
import harness_smoke
import minischema
import run_eacsl_fuzz as R
import sandbox_exec
from generate_harness import _build_invocations
from sandbox_exec import SandboxResult

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parent.parent
JUDGE_REPORT_SCHEMA = REPO_ROOT / "schemas" / "judge_report.schema.json"


def _write_dispatch_harness_and_sidecar(
    tmp_path: Path,
    *,
    module: str,
    api_cases: list[dict[str, Any]],
) -> tuple[Path, Path]:
    harnesses = tmp_path / "workspace" / "harnesses"
    harnesses.mkdir(parents=True, exist_ok=True)
    cases_code = [f"/* case {i} */ (void)fuzz_buf;" for i in range(len(api_cases))]
    _, fuzz = _build_invocations("f", "dispatch", dispatch_cases=cases_code)
    harness_c = harnesses / f"harness_{module}.c"
    harness_c.write_text(
        "#include <stddef.h>\n#include <stdint.h>\n#include <stdlib.h>\n"
        "static inline int framac_fuzz_skip_case(unsigned int c) { return (int)(c == 9999U); }\n"
        "#ifndef FRAMAC_FUZZ_REJECT\n#define FRAMAC_FUZZ_REJECT() ((void)0)\n#endif\n"
        f"int run(uint8_t *fuzz_buf, size_t fuzz_len) {{\n    {fuzz}\n    return 0;\n}}\n",
        encoding="utf-8",
        newline="\n",
    )
    sidecar = {
        "module": module,
        "harness_file": harness_c.as_posix(),
        "sources": ["src/a.c"],
        "cppflags": "",
        "entry_fn": "f",
        "entry_style": "dispatch",
        "api_harness": True,
        "api_cases": api_cases,
        "dispatch_cases": cases_code,
    }
    (harnesses / f"harness_{module}.json").write_text(json.dumps(sidecar, indent=2), encoding="utf-8")
    eacsl_bin = tmp_path / f"fuzz_{module}.e-acsl"
    eacsl_bin.write_bytes(b"#!/bin/sh\nexit 0\n")
    bdoc = {
        "mode": "build",
        "module": module,
        "status": "built",
        "engine_used": "eacsl",
        "binary": str(eacsl_bin),
        "sources": ["src/a.c", str(harness_c)],
        "binaries": {"sanitizers": None, "eacsl": str(eacsl_bin)},
        "compile": {"returncode": 0, "binary": str(eacsl_bin), "engine": "eacsl"},
    }
    bjson = tmp_path / f"{module}.build.json"
    bjson.write_text(json.dumps(bdoc, indent=2), encoding="utf-8")
    return bjson, harness_c


def _eacsl_assert_log(file_: str, line: int, fn: str, pred: str = "\\separated(dst, src)") -> str:
    return (
        f"{file_}: In function '{fn}'\n"
        f"{file_}:{line}: Error: Assertion failed:\n"
        "        The failing predicate is:\n"
        "        rte/separation:\n"
        f"            {pred}.\n"
        "SUMMARY: libFuzzer: deadly signal\n"
    )


# --- 1. Non-reproducing crashes must not skip innocent dispatch cases -------------------------


def test_rounds_do_not_skip_case_on_non_reproducing_crash_and_keep_case_active(tmp_path: Path) -> None:
    """A `reproducible: False` crash artifact (e.g. poisoned state from another case) must not skip the case."""
    art_nonrepro = tmp_path / "crash-nonrepro"
    art_nonrepro.write_bytes(b"\x01payload")
    art_real = tmp_path / "crash-real"
    art_real.write_bytes(b"\x01realbug")

    round_num = 0
    seen_skips: list[str] = []

    def campaign(_binary: Path, _seconds: int, _fork: bool, *, extra_env: dict[str, str] | None = None) -> dict:
        nonlocal round_num
        round_num += 1
        seen_skips.append((extra_env or {}).get("FRAMAC_FUZZ_SKIP_CASES", ""))
        if round_num == 1:
            return {
                "status": "crash_found",
                "returncode": 1,
                "artifacts": [
                    {
                        "artifact": str(art_nonrepro),
                        "kind": "crash",
                        "sha256": "aa",
                        "fingerprint": "fp-poison",
                        "reproducible": False,
                    }
                ],
                "_raw_crashes": [{"artifact": str(art_nonrepro), "reproducible": False}],
            }
        if round_num == 2:
            return {
                "status": "crash_found",
                "returncode": 1,
                "artifacts": [
                    {
                        "artifact": str(art_real),
                        "kind": "crash",
                        "sha256": "bb",
                        "fingerprint": "fp-real",
                        "reproducible": True,
                    }
                ],
                "_raw_crashes": [{"artifact": str(art_real), "reproducible": True}],
            }
        return {"status": "clean", "returncode": 0, "artifacts": []}

    res = R.run_campaign_rounds(
        tmp_path / "bin",
        120,
        campaign=campaign,
        rebuild=lambda _m: pytest.fail("runtime_skip must not rebuild"),
        n_cases=3,
        runtime_skip=True,
        selector="identity",
    )
    # Round 1 did NOT skip case 1, so round 2 still fuzzed case 1 and found the real reproducible bug.
    assert seen_skips == ["", "", "1"]
    assert res["keep_going"]["skipped_cases"] == [1]
    assert res["keep_going"]["rounds"][0]["crashed_cases"] == []
    assert res["keep_going"]["rounds"][0]["non_reproducing_cases"] == [1]
    assert res["keep_going"]["rounds"][1]["crashed_cases"] == [1]
    assert "fp-real" in {a["fingerprint"] for a in res["artifacts"]}


def test_rounds_stop_cleanly_after_persistent_non_reproducing_crashes(tmp_path: Path) -> None:
    """When every round produces only non-reproducing crashes, the loop caps retries and stops cleanly."""
    art = tmp_path / "crash-flaky"
    art.write_bytes(b"\x02data")
    calls = 0

    def campaign(_binary: Path, _seconds: int, _fork: bool, *, extra_env: dict[str, str] | None = None) -> dict:
        nonlocal calls
        calls += 1
        return {
            "status": "crash_found",
            "returncode": 1,
            "artifacts": [
                {
                    "artifact": str(art),
                    "kind": "crash",
                    "sha256": f"s{calls}",
                    "fingerprint": None,
                    "reproducible": False,
                }
            ],
        }

    res = R.run_campaign_rounds(
        tmp_path / "bin",
        120,
        campaign=campaign,
        rebuild=lambda _m: pytest.fail("runtime_skip must not rebuild"),
        n_cases=3,
        runtime_skip=True,
        selector="identity",
    )
    assert calls == 3
    assert res["keep_going"]["skipped_cases"] == []
    assert res["keep_going"]["rounds"][-1]["stopped"] == "non_reproducing_crashes"


# --- 2. Isolated per-invocation working directories -------------------------------------------


def test_replay_coverage_and_smoke_each_use_fresh_isolated_cwd_and_clean_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed_cwds: list[Path] = []

    def fake_sandbox(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        assert cwd is not None
        cwd_p = Path(cwd)
        assert cwd_p.is_dir()
        assert list(cwd_p.iterdir()) == [], "fresh cwd must be empty before invocation"
        # Simulate target creating a side-effect file in cwd.
        (cwd_p / "target_state.bin").write_bytes(b"state")
        observed_cwds.append(cwd_p)
        return SandboxResult(returncode=0, stdout="", stderr="Executed\n", timed_out=False, sandbox="fake")

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_sandbox)
    binary = tmp_path / "fuzz_bin"
    binary.write_bytes(b"bin")
    inp = tmp_path / "in0"
    inp.write_bytes(b"abc")
    scratch = tmp_path / "scratch"

    # 1. crash_replay.replay_artifact: fresh cwd per call, cleaned up, art_dir preserved.
    crash_replay.replay_artifact(binary, inp, scratch)
    crash_replay.replay_artifact(binary, inp, scratch)
    assert crash_replay.replay_artifact_dir(scratch).is_dir()

    # 2. fuzz_coverage.replay_for_coverage: fresh cwd per batch, cleaned up.
    prof_dir = tmp_path / "prof"
    fuzz_coverage.replay_for_coverage(binary, [inp], prof_dir, scratch, module="m")

    # 3. harness_smoke._run_probe_files: fresh cwd per probe call, cleaned up.
    harness_smoke._run_probe_files(binary, [inp], scratch, timeout_s=5, module="m")

    assert len(observed_cwds) == 4
    assert len(set(observed_cwds)) == 4
    host_cwd = Path(os.getcwd()).resolve()
    for d in observed_cwds:
        assert d.resolve() != host_cwd
        assert not d.exists(), f"isolated cwd {d} was not removed"


# --- 3. run_judge: cwd side-effect detection -> order-independent per-input isolation --------


def test_run_judge_detects_cwd_side_effects_and_produces_order_independent_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Input `a_writer` writes `state.bin` into cwd and passes; `b_reader` aborts in an empty cwd
    but passes if `state.bin` exists. Regardless of input order (`[a_writer, b_reader]` vs
    `[b_reader, a_writer]`), `run_judge` must detect the cwd write in the first batch, switch to
    per-input isolated cwds, re-run `b_reader` in an empty directory, and report identical results.
    """
    bjson, _ = _write_dispatch_harness_and_sidecar(
        tmp_path,
        module="stateful",
        api_cases=[
            {"selector": 0, "kind": "single", "calls": ["write_state"], "function": "write_state", "slots": []},
            {"selector": 1, "kind": "single", "calls": ["read_state"], "function": "read_state", "slots": []},
        ],
    )

    def run_for_order(order_name: str, files: list[tuple[str, bytes]]) -> dict[str, Any]:
        corpus = tmp_path / f"corpus_{order_name}"
        corpus.mkdir()
        for fname, data in files:
            (corpus / fname).write_bytes(data)

        def stateful_sandbox(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
            assert cwd is not None
            cwd_p = Path(cwd)
            inputs_in_cmd = [Path(a) for a in cmd[1:] if not a.startswith("-")]
            lines: list[str] = []
            for p in inputs_in_cmd:
                raw = p.read_bytes()
                lines.append(f"Running: {p.resolve()}")
                if raw[:1] == b"\x00":
                    # Case 0 creates a persistent state file in cwd and succeeds.
                    (cwd_p / "state.bin").write_bytes(b"\x00" * 16)
                    lines.append(f"Executed {p.resolve()} in 1 ms")
                elif raw[:1] == b"\x01":
                    # Case 1 aborts when cwd is empty, but passes if state.bin was left behind!
                    if not (cwd_p / "state.bin").exists():
                        lines.append(_eacsl_assert_log("src/a.c", 19, "read_state", "\\valid(p)"))
                        return SandboxResult(
                            returncode=134, stdout="", stderr="\n".join(lines), timed_out=False, sandbox="fake"
                        )
                    lines.append(f"Executed {p.resolve()} in 1 ms")
            return SandboxResult(returncode=0, stdout="", stderr="\n".join(lines), timed_out=False, sandbox="fake")

        monkeypatch.setattr(sandbox_exec, "run_sandboxed", stateful_sandbox)
        return R.run_judge("stateful", bjson, corpus, batch_size=4)

    # Order 1: writer first, reader second in the same batch!
    rep_wr = run_for_order("wr", [("01_writer", b"\x00w"), ("02_reader", b"\x01r")])
    # Order 2: reader first, writer second!
    rep_rw = run_for_order("rw", [("01_reader", b"\x01r"), ("02_writer", b"\x00w")])

    for rep in (rep_wr, rep_rw):
        assert rep["status"] == "crash_found", rep
        assert rep["inputs"]["passed"] == 1
        assert rep["inputs"]["failed"] == 1
        assert len(rep["artifacts"]) == 1
        assert rep["artifacts"][0]["failure"]["function"] == "read_state"
        assert "state.bin" in rep["telemetry"]["cwd_side_effects"]
        assert any("working-directory file(s)" in h for h in rep.get("diagnostic_hints") or [])
        assert minischema.validate(rep, minischema.load_schema(JUDGE_REPORT_SCHEMA)) == []
    # In writer-first order, batch[1:] (`02_reader`) was re-run in per-input isolation after detecting `state.bin`.
    assert rep_wr["telemetry"]["cwd_isolated_inputs"] >= 1


# --- 4. run_judge: deterministic setup-prefix blinding vs real target crashes -----------------


def test_run_judge_blinds_deterministic_setup_abort_once_without_blinding_target_body_crashes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Case 0: sequence with `setup_calls: ["lib_init"]` -> aborts inside `lib_init` -> blinded after 1st abort,
            candidate recorded once, remaining 4 inputs skipped as `blinded`.
    Case 1: legacy sequence with only `"global setup call: legacy_init"` note -> also blinded after 1st abort.
    Case 2: zero-input single global-setup case (`lib_init`) -> blinded after 1st abort.
    Case 3: sequence with `setup_calls: ["lib_init"]` and target `lib_proc`, aborting inside `lib_proc` ->
            NOT blinded after 1st abort (all 3 inputs judged normally).
    Case 4: sequence with `setup_calls: ["lib_init"]` that passes on input 0 and aborts in `lib_init` on
            input 1 -> NOT deterministic setup blinding because `passes > 0`.
    """
    bjson, _ = _write_dispatch_harness_and_sidecar(
        tmp_path,
        module="setupblind",
        api_cases=[
            {
                "selector": 0,
                "kind": "sequence",
                "calls": ["lib_init", "lib_proc"],
                "setup_calls": ["lib_init"],
                "slots": [],
                "rest": {"call": 1, "param": 0, "kind": "bytes"},
            },
            {
                "selector": 1,
                "kind": "sequence",
                "calls": ["legacy_init", "lib_proc"],
                "slots": [],
                "rest": {"call": 1, "param": 0, "kind": "bytes"},
                "notes": ["global setup call: legacy_init"],
            },
            {
                "selector": 2,
                "kind": "single",
                "function": "lib_init",
                "calls": ["lib_init"],
                "slots": [],
                "rest": None,
            },
            {
                "selector": 3,
                "kind": "sequence",
                "calls": ["lib_init", "lib_proc"],
                "setup_calls": ["lib_init"],
                "slots": [],
                "rest": {"call": 1, "param": 0, "kind": "bytes"},
            },
            {
                "selector": 4,
                "kind": "sequence",
                "calls": ["lib_init", "lib_proc"],
                "setup_calls": ["lib_init"],
                "slots": [],
                "rest": {"call": 1, "param": 0, "kind": "bytes"},
            },
        ],
    )
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    for i in range(5):
        (corpus / f"c0_{i}").write_bytes(bytes([0, i]))
    for i in range(4):
        (corpus / f"c1_{i}").write_bytes(bytes([1, i]))
    for i in range(3):
        (corpus / f"c2_{i}").write_bytes(bytes([2, i]))
    for i in range(3):
        (corpus / f"c3_{i}").write_bytes(bytes([3, i]))
    # Case 4: input 0 passes (`b"\x04\x00"`) via mandatory seed dir so it runs first,
    # then inputs 1 and 2 abort in `lib_init`.
    seeds = tmp_path / "seeds"
    seeds.mkdir()
    (seeds / "c4_0").write_bytes(bytes([4, 0]))
    for i in (1, 2):
        (corpus / f"c4_{i}").write_bytes(bytes([4, i]))

    def fake_sandbox(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        inputs_in_cmd = [Path(a) for a in cmd[1:] if not a.startswith("-")]
        lines: list[str] = []
        for p in inputs_in_cmd:
            raw = p.read_bytes()
            cid, payload = raw[0], raw[1]
            lines.append(f"Running: {p.resolve()}")
            if cid == 4 and payload == 0:
                lines.append(f"Executed {p.resolve()} in 1 ms")
                continue
            if cid in (0, 2, 4):
                lines.append(_eacsl_assert_log("src/init.c", 50, "helper_copy"))
                lines.append("    #0 0x100 in helper_copy src/init.c:50:3")
                lines.append("    #1 0x200 in lib_init src/init.c:90:5")
                lines.append("    #2 0x300 in LLVMFuzzerTestOneInput harness_setupblind.c:12:3")
                return SandboxResult(
                    returncode=134, stdout="", stderr="\n".join(lines), timed_out=False, sandbox="fake"
                )
            if cid == 1:
                lines.append(_eacsl_assert_log("src/init.c", 60, "legacy_copy"))
                lines.append("    #0 0x100 in legacy_copy src/init.c:60:3")
                lines.append("    #1 0x200 in __gen_e_acsl_legacy_init src/init.c:95:5")
                lines.append("    #2 0x300 in LLVMFuzzerTestOneInput harness_setupblind.c:12:3")
                return SandboxResult(
                    returncode=134, stdout="", stderr="\n".join(lines), timed_out=False, sandbox="fake"
                )
            # Case 3: crashes inside target `lib_proc`, NOT inside setup `lib_init`.
            lines.append(_eacsl_assert_log("src/proc.c", 77, "lib_proc", "\\valid_read(p)"))
            lines.append("    #0 0x100 in lib_proc src/proc.c:77:3")
            lines.append("    #1 0x300 in LLVMFuzzerTestOneInput harness_setupblind.c:12:3")
            return SandboxResult(returncode=134, stdout="", stderr="\n".join(lines), timed_out=False, sandbox="fake")
        return SandboxResult(returncode=0, stdout="", stderr="\n".join(lines), timed_out=False, sandbox="fake")

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_sandbox)
    rep = R.run_judge("setupblind", bjson, corpus, extra_corpus=[seeds], batch_size=2)
    assert minischema.validate(rep, minischema.load_schema(JUDGE_REPORT_SCHEMA)) == []

    blinded = {b["case"]: b for b in rep["blinded_cases"]}
    assert set(blinded) == {0, 1, 2}
    assert blinded[0]["reason"] == "deterministic_setup_abort"
    assert blinded[0]["setup_function"] == "lib_init"
    assert blinded[0]["crashes"] == 1
    assert blinded[1]["reason"] == "deterministic_setup_abort"
    assert blinded[1]["setup_function"] == "legacy_init"
    assert blinded[2]["reason"] == "deterministic_setup_abort"
    assert blinded[2]["setup_function"] == "lib_init"

    # Remaining inputs skipped: 4 (case 0) + 3 (case 1) + 2 (case 2) = 9 blinded inputs.
    assert rep["inputs"]["not_judged_breakdown"]["blinded"] == 9
    # Case 3 (3 target crashes) and Case 4 (1 pass + 2 crashes) all ran completely!
    assert rep["inputs"]["passed"] == 1
    assert rep["inputs"]["failed"] == 1 + 1 + 1 + 3 + 2
    # Candidate artifacts include both the setup abort (recorded once) and the target crash!
    funcs = {a["failure"]["function"] for a in rep["artifacts"]}
    assert {"helper_copy", "legacy_copy", "lib_proc"} <= funcs
