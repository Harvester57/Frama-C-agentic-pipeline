"""
P11 (QCBOR run-2, 2026-11-24): the guardrail's exclusion limit counts distinct root causes, not inputs.

The module-wide parent guardrail of `libqcbor_a` replayed 64 sampled inputs. Nine of them stopped on one known
target defect (`GetItemInMapNoCheck` leaves `*puOffset` unwritten on an error path), reported in several unchecked
callers as `\\initialized(&uOffset)`: the same `initialization::c132f24cbe` root cause. Counting inputs, the ninth
one passed GUARDRAIL_MAX_EXCLUDED_INPUTS and the guardrail ended `guardrail_error`, so every merge of the module
paid for a second, function-scoped guardrail.
"""

from __future__ import annotations

import json
import os
import subprocess
import uuid
from pathlib import Path

import pytest

import crash_replay
import fuzz_build
import run_eacsl_fuzz as R
import sandbox_exec
from sandbox_exec import SandboxResult

pytestmark = pytest.mark.unit

_RC_INSTR = "/framac-run/state/parent_guard/libqcbor_a-d5e9c28fc2/guard_libqcbor_a.instrumented.c"
_RC_CHECKED = "UsefulOutBuf_Reset"
_RC_UOFFSET = "\\initialized(&uOffset)"
_RC_TAGS = "\\initialized(&pDecodedItem->auTagNumbers[0])"
# The functions the run's eight `c132f24cbe` exclusions failed in, plus one more caller of the same helper.
_RC_CALLERS = [
    "QCBORDecode_Private_GetItemInMap",
    "QCBORDecode_GetTBigFloatInMapN",
    "QCBORDecode_GetTBigFloatBigMantissaInMapN",
    "QCBORDecode_GetTBigFloatBigMantissaRawInMapN",
    "QCBORDecode_GetTDecimalFractionInMapN",
    "QCBORDecode_GetTEpochDateInMapN",
    "QCBORDecode_GetTDecimalFractionBigMantissaInMapSZ",
    "QCBORDecode_GetTMIMEMessageInMapN",
    "QCBORDecode_GetTEpochDaysInMapSZ",
]


def _rc_report(function: str, predicate: str, caller: str = "QCBORDecode_GetItemInMapSZ", line: int = 517) -> str:
    """An E-ACSL RTE failure in `function` with the libFuzzer stack of the run's replay (frames trimmed)."""
    src = "workspace/work/src/qcbor_spiffy_decode.c"
    return (
        f"{src}: In function '{function}'\n"
        f"{src}:{line}: Error: Assertion failed:\n"
        "\tThe failing predicate is:\n"
        "\trte/initialization:\n"
        f"\t\t{predicate}.\n"
        "\tWith values at failure point:\n"
        "\t- uOffset: <uninitialized>\n"
        "==131== ERROR: libFuzzer: deadly signal\n"
        "    #0 0x4402f8 in __sanitizer_print_stack_trace (/w/guard.e-acsl+0x4402f8)\n"
        "    #5 0x7ead027acc41 in raise (/lib/x86_64-linux-gnu/libc.so.6+0x3fc41)\n"
        f"    #6 0x52032f in {function} {_RC_INSTR}:148875:5\n"
        f"    #7 0x4d46f6 in {caller} {_RC_INSTR}:149274:3\n"
        f"    #8 0x591247 in LLVMFuzzerTestOneInput {_RC_INSTR}:202011:11\n"
        "    #9 0x426aaa in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/w/g+0x426aaa)\n"
        "NOTE: libFuzzer has rudimentary signal handlers.\n"
        "SUMMARY: libFuzzer: deadly signal\n"
    )


@pytest.fixture
def run_cwd(tmp_path, monkeypatch):
    """crash_input paths are run-relative: run from tmp_path as the run directory."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _rc_guardrail(
    tmp_path: Path,
    monkeypatch,
    crashers: dict[bytes, str],
    calls: list,
    *,
    clean: int = 3,
    functions: list[str] | None = None,
    **kwargs,
) -> dict:
    """
    A module-wide guardrail (reach `functions`, no contract scope) whose fake libFuzzer replays the staged files in
    name order and stops on the first one whose bytes are a key of `crashers`, printing that key's report.
    """
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    for i in range(clean):
        (corpus / f"{i:040x}").write_bytes(b"clean-%d" % i)
    for i, data in enumerate(crashers):
        (corpus / f"seed-crash-{i:02d}").write_bytes(data)
    monkeypatch.setattr(R, "is_eacsl_instrumented", lambda b: True)
    monkeypatch.setattr(fuzz_build, "is_eacsl_instrumented", lambda b: True)
    monkeypatch.setattr(crash_replay, "is_eacsl_instrumented", lambda b: True)

    def fake_run(cmd, **kw):
        calls.append(list(cmd))
        prefix = Path(next(a for a in cmd if a.startswith("-artifact_prefix=")).split("=", 1)[1])
        replayed = sorted(Path(cmd[-1]).iterdir())
        for p in replayed:
            data = p.read_bytes()
            if data in crashers:
                (prefix / f"crash-{data.hex()}").write_bytes(data)
                out = crashers[data] + f"Test unit written to {prefix}/crash-{data.hex()}\n"
                return SandboxResult(77, "", out, False, "rlimits", list(cmd))
        stats = f"COVERED_FUNC: hits: 2 edges: 1/1 {_RC_CHECKED} {_RC_INSTR}:686\n"
        return SandboxResult(
            0, stats + f"stat::number_of_executed_units: {len(replayed)}\n", "", False, "rlimits", list(cmd)
        )

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_run)
    binary = tmp_path / "guard.e-acsl"
    binary.write_bytes(b"bin")
    return R.run_guardrail_check(
        binary,
        corpus,
        tmp_path / "scratch",
        0,
        use_cache=False,
        module="libqcbor_a",
        seed=1,
        functions=functions if functions is not None else [_RC_CHECKED],
        contract_functions=[],
        **kwargs,
    )


def _same_root_cause(n: int) -> dict[bytes, str]:
    return {b"uoff-%d" % i: _rc_report(_RC_CALLERS[i % len(_RC_CALLERS)], _RC_UOFFSET) for i in range(n)}


def test_one_root_cause_reached_by_nine_inputs_does_not_exhaust_the_limit(tmp_path, monkeypatch, run_cwd):
    # Before the fix: `guardrail_error`, "More than 8 replayed inputs crash outside the checked functions".
    assert R.GUARDRAIL_MAX_EXCLUDED_INPUTS == 8
    calls: list = []
    verdict = _rc_guardrail(tmp_path, monkeypatch, _same_root_cause(9), calls)
    assert verdict["status"] == "passed_dynamic_oracle", verdict.get("reason")
    # Every dropped input stays in the evidence, with its own failure and fingerprint.
    assert [e["input"] for e in verdict["excluded_inputs"]] == [f"seed-crash-{i:02d}" for i in range(9)]
    assert {e["fingerprint"].rsplit("::", 1)[1] for e in verdict["excluded_inputs"]} == {"c132f24cbe"}
    assert len({e["failure"]["function"] for e in verdict["excluded_inputs"]}) == 9
    (cause,) = verdict["excluded_root_causes"]
    assert cause["root_cause"] == "initialization::c132f24cbe" and "uOffset" in cause["crash"]
    assert cause["inputs"] == [f"seed-crash-{i:02d}" for i in range(9)]
    assert verdict["corpus_replayed"] == 3 and len(calls) == 10
    assert verdict["reach"]["functions"] == {_RC_CHECKED: 2}


def test_the_qcbor_run2_shape_passes_on_two_root_causes(tmp_path, monkeypatch, run_cwd):
    crashers = _same_root_cause(8)
    crashers[b"tags"] = _rc_report("QCBORDecode_Private_GetItemChecks", _RC_TAGS, line=2330)
    calls: list = []
    verdict = _rc_guardrail(tmp_path, monkeypatch, crashers, calls)
    assert verdict["status"] == "passed_dynamic_oracle", verdict.get("reason")
    assert len(verdict["excluded_inputs"]) == 9
    causes = {c["root_cause"]: len(c["inputs"]) for c in verdict["excluded_root_causes"]}
    assert causes == {"initialization::c132f24cbe": 8, "initialization::d2eda762d7": 1}


def test_more_distinct_root_causes_than_the_limit_still_give_up(tmp_path, monkeypatch, run_cwd):
    crashers = {b"distinct-%d" % i: _rc_report(_RC_CALLERS[i], f"\\initialized(&uOffset{i})") for i in range(9)}
    calls: list = []
    verdict = _rc_guardrail(tmp_path, monkeypatch, crashers, calls)
    assert verdict["status"] == "guardrail_error" and verdict["failure"] is None
    assert len(verdict["excluded_inputs"]) == 8 and len(verdict["excluded_root_causes"]) == 8
    assert "More than 8 root causes" in verdict["reason"] and "uOffset8" in verdict["reason"]
    assert verdict["outside_checked_functions"]["failure"]["function"] == _RC_CALLERS[8]


def test_inputs_without_a_fingerprint_count_one_each(tmp_path, monkeypatch, run_cwd):
    # A sanitizer crash elsewhere has no predicate to group by: each input keeps its own slot.
    monkeypatch.setattr(R, "GUARDRAIL_MAX_EXCLUDED_INPUTS", 2)
    segv = (
        "==7==ERROR: UndefinedBehaviorSanitizer: SEGV on unknown address 0x10 (pc 0x5 T7)\n"
        f"    #0 0x5 in QCBORDecode_Private_GetItemInMap {_RC_INSTR}:874:30\n"
        f"    #1 0x6 in LLVMFuzzerTestOneInput {_RC_INSTR}:3927:3\n"
        f"SUMMARY: UndefinedBehaviorSanitizer: SEGV {_RC_INSTR}:874:30 in QCBORDecode_Private_GetItemInMap\n"
    )
    calls: list = []
    verdict = _rc_guardrail(tmp_path, monkeypatch, {b"segv-%d" % i: segv for i in range(3)}, calls)
    assert verdict["status"] == "guardrail_error" and len(verdict["excluded_inputs"]) == 2
    assert "More than 2 root causes" in verdict["reason"]


def test_a_known_root_cause_reached_through_a_checked_function_is_never_excused(tmp_path, monkeypatch, run_cwd):
    # The second input fails on the same predicate, but its stack goes through the checked function.
    crashers = {
        b"a-elsewhere": _rc_report("QCBORDecode_Private_GetItemInMap", _RC_UOFFSET),
        b"b-through-checked": _rc_report("QCBORDecode_GetTBigFloatInMapN", _RC_UOFFSET, caller=_RC_CHECKED),
    }
    calls: list = []
    verdict = _rc_guardrail(tmp_path, monkeypatch, crashers, calls)
    assert verdict["status"] == "code_fault" and len(calls) == 2
    assert [e["input"] for e in verdict["excluded_inputs"]] == ["seed-crash-00"]
    assert verdict["failure"]["function"] == "QCBORDecode_GetTBigFloatInMapN"


def test_dropping_every_replayed_input_passes_on_no_real_input(tmp_path, monkeypatch, run_cwd):
    # The briefs' "passed on no real input: all inputs excluded" case: a pass, with `corpus_replayed` 0 and a hint.
    calls: list = []
    verdict = _rc_guardrail(tmp_path, monkeypatch, _same_root_cause(4), calls, clean=0)
    assert verdict["status"] == "passed_dynamic_oracle" and not verdict["corpus_empty"]
    assert len(verdict["excluded_inputs"]) == 4 and verdict["corpus_replayed"] == 0
    assert len(calls) == 5
    assert any("passed on no real input: all inputs excluded" in h for h in verdict["diagnostic_hints"])


@pytest.mark.parametrize(
    ("entry", "key"),
    [
        ({"fingerprint": "src/a.c#f::initialization::c132f24cbe"}, "initialization::c132f24cbe"),
        ({"fingerprint": "src/b.c#g::initialization::c132f24cbe"}, "initialization::c132f24cbe"),
        ({"fingerprint": "src/a.c#f::mem_access::0123456789"}, "mem_access::0123456789"),
        ({"fingerprint": "not-a-fingerprint"}, "input::x"),
        ({"crash": "UndefinedBehaviorSanitizer: SEGV"}, "input::x"),
        ({"kind": "timeout", "crash": "libFuzzer: timeout"}, "input::x"),
    ],
)
def test_root_cause_key(entry, key):
    assert R.exclusion_root_cause({"input": "x", **entry}) == key


# ---------------------------------------------------------------------------
# The same case on a real E-ACSL build in the analysis image
# ---------------------------------------------------------------------------

# One out-parameter left unwritten on an error path (QCBOR's GetItemInMapNoCheck), read in two unchecked callers; the
# checked function is correct and never on the failing stack. E-ACSL reports `\initialized(&uOffset)`, the predicate
# (hence the `c132f24cbe` hash) of the QCBOR run.
_RC_FIXTURE_C = r"""
#include <stddef.h>
#include <stdint.h>

static int get_offset(const uint8_t *d, size_t n, unsigned *off)
{
  if (n < 3 || d[2] != 'X')
    return -1;
  *off = d[1];
  return 0;
}

static unsigned in_map_a(const uint8_t *d, size_t n)
{
  unsigned uOffset;
  (void)get_offset(d, n, &uOffset);
  return uOffset;
}

static unsigned in_map_b(const uint8_t *d, size_t n)
{
  unsigned uOffset;
  (void)get_offset(d, n, &uOffset);
  return uOffset + 1u;
}

/*@ assigns \nothing;
    ensures \result == a; */
int checked(int a) { return a; }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  uint8_t buf[16];
  size_t n = size < sizeof buf ? size : sizeof buf;
  unsigned v = 0;
  for (size_t i = 0; i < n; i++)
    buf[i] = data[i];
  if (n >= 2 && buf[0] == 'B')
    v = (buf[1] & 1u) ? in_map_a(buf, n) : in_map_b(buf, n);
  return checked((int)(v & 1u) + (int)(n & 1u)) < 0;
}
"""

# The parent re-check's form (workspace_overlay): module-wide, `--reach-functions`, no `--functions`.
_RC_FIXTURE_PY = r"""
import json, os, shutil, sys
shutil.copytree("/fixture", "/tmp/w")
os.chdir("/tmp/w")
os.makedirs("corpus")
os.makedirs("agents/prove-checked/scratch")
for i in range(12):
    open(f"corpus/seed-defect-{i:02d}", "wb").write(b"B" + bytes([0x30 + i]) + b"q" * (i + 1))
for i in range(5):
    open(f"corpus/seed-clean-{i:02d}", "wb").write(b"A" + bytes([0x30 + i]) * (i + 1))
open("corpus/seed-clean-bx", "wb").write(b"B1X")
sys.path.insert(0, "/repo/scripts")
import run_eacsl_fuzz as R
out = "agents/prove-checked/scratch/guard_mod"
rc = R.main(["guardrail", "--sources", "mod.c", "--out-bin", out, "--corpus-dir", "corpus",
             "--reach-functions", "checked", "--extra-runs", "0", "--no-cache", "--out-json", out + ".json"])
rep = json.load(open(out + ".json"))
keep = {k: rep.get(k) for k in ("status", "reason", "corpus_replayed", "excluded_root_causes")}
keep["fingerprints"] = sorted({e.get("fingerprint") for e in rep.get("excluded_inputs") or []})
keep["excluded"] = len(rep.get("excluded_inputs") or [])
print("GUARD " + json.dumps(keep), flush=True)
"""


@pytest.mark.integration
def test_module_wide_guardrail_passes_past_twelve_inputs_of_one_defect_in_the_analysis_image(tmp_path):
    from conftest import ANALYSIS_IMAGE, require_docker_images

    require_docker_images(ANALYSIS_IMAGE)
    (tmp_path / "mod.c").write_text(_RC_FIXTURE_C, encoding="utf-8", newline="\n")
    (tmp_path / "repro.py").write_text(_RC_FIXTURE_PY, encoding="utf-8", newline="\n")
    repo = Path(__file__).resolve().parent.parent
    tag = os.environ.get("FRAMAC_RUN_TAG") or f"test-p11-{uuid.uuid4().hex[:8]}"
    name = f"framac-test-p11-{uuid.uuid4().hex[:8]}"
    argv = ["docker", "run", "--rm", "--name", name, "--label", f"framac.run={tag}", "--network", "none"]
    argv += ["-v", f"{tmp_path}:/fixture:ro", "-v", f"{repo}:/repo:ro", ANALYSIS_IMAGE]
    argv += ["timeout 1200 python3 /fixture/repro.py"]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1500)
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
    out = proc.stdout + proc.stderr
    line = next((ln for ln in proc.stdout.splitlines() if ln.startswith("GUARD ")), None)
    assert line is not None, out[-6000:]
    rep = json.loads(line[len("GUARD ") :])
    # Before the fix: `guardrail_error`, "More than 8 replayed inputs crash outside the checked functions".
    assert rep["status"] == "passed_dynamic_oracle", out[-6000:]
    assert rep["excluded"] == 12 and rep["corpus_replayed"] == 6, rep
    assert {fp.rsplit("::", 1)[1] for fp in rep["fingerprints"]} == {"c132f24cbe"}, rep
    assert len(rep["fingerprints"]) == 2, rep  # in_map_a and in_map_b
    assert [(c["root_cause"], len(c["inputs"])) for c in rep["excluded_root_causes"]] == [
        ("initialization::c132f24cbe", 12)
    ], rep
