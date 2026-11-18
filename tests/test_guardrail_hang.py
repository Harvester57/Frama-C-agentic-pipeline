"""A replayed input that hangs says nothing about the contract: libmodbus run-1, Phase 3, every guardrail from 09:10."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import cache
import crash_replay
import eacsl_toolchain
import fuzz_build
import promote_artifact as P
import run_eacsl_fuzz as R
import sandbox_exec
from sandbox_exec import SandboxResult
from test_guardrail_p1 import EACSL_RTE_ELSEWHERE

pytestmark = pytest.mark.unit

HANG_A = b"B127.0.0.1\x00hang-fd1023"
HANG_B = b"B127.0.0.1\x00hang-fd1000"
CHECKED = "modbus_rtu_get_rts"
REACHED = f"COVERED_FUNC: hits: 3 edges: 1/1 {CHECKED} /framac-run/src/modbus-rtu.c:10\n"


def timeout_report(prefix: Path, data: bytes, frame: str = "_modbus_tcp_select") -> str:
    """What libFuzzer prints when its per-input alarm fires, as in the libmodbus reports."""
    name = f"timeout-{hashlib.sha1(data).hexdigest()}"  # noqa: S324
    (prefix / name).write_bytes(data)
    return (
        "ALARM: working on the last Unit for 31 seconds\n"
        "       and the timeout value is 30 (use -timeout=N to change)\n"
        f"artifact_prefix='{prefix}/'; Test unit written to {prefix}/{name}\n"
        "==11== ERROR: libFuzzer: timeout after 30 seconds\n"
        "    #7 0x73eb6d80dfc6 in select (/lib/x86_64-linux-gnu/libc.so.6+0x10dfc6)\n"
        "    #8 0x5ce85d8f17d5 in __wrap_select (/framac-run/guard.e-acsl+0xc67d5)\n"
        f"    #9 0x5ce85d8bc98a in {frame} /framac-run/guard.instrumented.c:6198:12\n"
        "    #13 0x6469b4d76fe4 in LLVMFuzzerTestOneInput /framac-run/guard.instrumented.c:16281:51\n"
        "SUMMARY: libFuzzer: timeout\n"
    )


class FakeFuzzer:
    """A libFuzzer that stops on the first replayed file whose content hangs, and passes when none does."""

    def __init__(self, monkeypatch, hangs: set[bytes], frame: str = "_modbus_tcp_select"):
        self.hangs = hangs
        self.frame = frame
        self.calls: list[list[str]] = []
        self.walls: list[int] = []
        self.replayed: list[list[str]] = []
        self.mutation_hang: bytes | None = None
        self.violation: bytes | None = None
        self.wall_limit_on_call: int | None = None
        self.clock = 0.0
        self.hang_cost = 31.0
        monkeypatch.setattr(R, "is_eacsl_instrumented", lambda b: True)
        monkeypatch.setattr(fuzz_build, "is_eacsl_instrumented", lambda b: True)
        monkeypatch.setattr(crash_replay, "is_eacsl_instrumented", lambda b: True)
        monkeypatch.setattr(sandbox_exec, "run_sandboxed", self.run)
        monkeypatch.setattr(R.time, "monotonic", lambda: self.clock)

    def run(self, cmd, **kw):
        self.calls.append(list(cmd))
        self.walls.append(int(kw["timeout_s"]))
        prefix = Path(next(a for a in cmd if a.startswith("-artifact_prefix=")).split("=", 1)[1])
        files = sorted(p for p in Path(cmd[-1]).iterdir() if p.is_file())
        self.replayed.append([p.name for p in files])
        if self.wall_limit_on_call == len(self.calls):
            self.clock += kw["timeout_s"]
            return SandboxResult(-9, "", "killed at the wall limit\n", True, "rlimits", list(cmd))
        for path in files:
            if path.read_bytes() in self.hangs:
                self.clock += self.hang_cost
                out = timeout_report(prefix, path.read_bytes(), self.frame)
                return SandboxResult(70, "", out, False, "rlimits", list(cmd))
            if path.read_bytes() == self.violation:
                (prefix / "crash-0123").write_bytes(path.read_bytes())
                out = EACSL_RTE_ELSEWHERE + f"Test unit written to {prefix}/crash-0123\n"
                return SandboxResult(1, "", out, False, "rlimits", list(cmd))
        if self.mutation_hang is not None and "-runs=0" not in cmd:
            self.clock += self.hang_cost
            out = timeout_report(prefix, self.mutation_hang, self.frame)
            return SandboxResult(70, "", out, False, "rlimits", list(cmd))
        self.clock += 1.0
        stats = REACHED + f"stat::number_of_executed_units: {len(files)}\n"
        return SandboxResult(0, stats, "", False, "rlimits", list(cmd))


@pytest.fixture
def run(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FRAMAC_CACHE", "off")
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    for i in range(4):
        (corpus / f"{i:040x}").write_bytes(b"ok%d" % i)
    (corpus / "seed-hang-a").write_bytes(HANG_A)
    (corpus / "seed-hang-b").write_bytes(HANG_B)
    binary = tmp_path / "guard.e-acsl"
    binary.write_bytes(b"bin")

    def check(runs: int = 0, **kw):
        kw.setdefault("use_cache", False)
        kw.setdefault("functions", [CHECKED])
        return R.run_guardrail_check(binary, corpus, tmp_path / "scratch", runs, module="m", seed=1, **kw)

    check.corpus = corpus  # type: ignore[attr-defined]
    return check


def test_hanging_seeds_are_dropped_and_the_verdict_comes_from_the_rest(run, monkeypatch):
    fuzzer = FakeFuzzer(monkeypatch, {HANG_A, HANG_B})
    verdict = run()
    assert verdict["status"] == "passed_dynamic_oracle"
    assert sorted(e["input"] for e in verdict["excluded_inputs"]) == ["seed-hang-a", "seed-hang-b"]
    assert {e["kind"] for e in verdict["excluded_inputs"]} == {"timeout"}
    assert all("libFuzzer: timeout" in e["crash"] for e in verdict["excluded_inputs"])
    assert verdict["crash_input"] is None and verdict["returncode"] == 0
    assert len(fuzzer.calls) == 3


def test_a_pass_reports_what_really_ran(run, monkeypatch):
    fuzzer = FakeFuzzer(monkeypatch, {HANG_A, HANG_B})
    verdict = run()
    assert verdict["corpus_total"] == 6 and verdict["corpus_replayed"] == 4
    assert len(fuzzer.replayed[-1]) == 4 and not any(n.startswith("seed-hang") for n in fuzzer.replayed[-1])
    assert verdict["reach"]["functions"] == {CHECKED: 3} and verdict["reach"]["executed_inputs"] == 4
    assert any("hung" in h and "seed-hang" in h for h in verdict["diagnostic_hints"])


def test_identical_hanging_files_cost_one_replay(run, monkeypatch):
    (run.corpus / ("f" * 40)).write_bytes(HANG_A)
    fuzzer = FakeFuzzer(monkeypatch, {HANG_A})
    verdict = run()
    assert verdict["status"] == "passed_dynamic_oracle" and len(fuzzer.calls) == 2
    assert sorted(e["input"] for e in verdict["excluded_inputs"]) == ["f" * 40, "seed-hang-a"]


def test_the_wall_budget_is_shared_by_every_replay(run, monkeypatch):
    fuzzer = FakeFuzzer(monkeypatch, {HANG_A, HANG_B})
    run(timeout_s=100)
    assert fuzzer.walls == [100, 69, 38]


def test_a_budget_spent_on_hangs_is_an_error_and_never_a_pass(run, monkeypatch):
    fuzzer = FakeFuzzer(monkeypatch, {HANG_A, HANG_B})
    verdict = run(timeout_s=40)
    assert verdict["status"] == "guardrail_error"
    assert "wall" in verdict["reason"] and "not tested" in verdict["reason"]
    assert verdict["failure"] is None and len(fuzzer.calls) == 2


def test_the_wall_limit_after_a_drop_says_the_contract_was_not_tested(run, monkeypatch):
    fuzzer = FakeFuzzer(monkeypatch, {HANG_A})
    fuzzer.wall_limit_on_call = 2
    verdict = run()
    assert verdict["status"] == "guardrail_error" and verdict["timed_out"] is True
    assert "wall" in verdict["reason"] and "not tested" in verdict["reason"]
    assert [e["input"] for e in verdict["excluded_inputs"]] == ["seed-hang-a"]


def test_a_corpus_where_everything_hangs_is_no_pass(tmp_path, run, monkeypatch):
    for p in run.corpus.iterdir():
        p.unlink()
    (run.corpus / "seed-hang-a").write_bytes(HANG_A)
    fuzzer = FakeFuzzer(monkeypatch, {HANG_A})
    verdict = run()
    assert verdict["status"] == "guardrail_error" and verdict["corpus_replayed"] == 0
    assert "every replayed input" in verdict["reason"]
    assert len(fuzzer.calls) == 1


def test_more_hanging_inputs_than_the_limit_stop_the_replay(run, monkeypatch):
    monkeypatch.setattr(R, "GUARDRAIL_MAX_EXCLUDED_INPUTS", 1)
    FakeFuzzer(monkeypatch, {HANG_A, HANG_B})
    verdict = run()
    assert verdict["status"] == "guardrail_error" and len(verdict["excluded_inputs"]) == 1
    assert "hang" in verdict["reason"] and "not tested" in verdict["reason"]


def test_a_hanging_mutation_skips_the_burst_and_the_corpus_decides(run, monkeypatch):
    fuzzer = FakeFuzzer(monkeypatch, set())
    fuzzer.mutation_hang = b"a mutation, not a corpus file"
    verdict = run(runs=200)
    assert verdict["status"] == "passed_dynamic_oracle" and verdict["excluded_inputs"] == []
    assert verdict["mutations_skipped"]["kind"] == "timeout"
    assert "-runs=200" in fuzzer.calls[0] and "-runs=0" in fuzzer.calls[1]


def test_a_hang_that_cannot_be_dropped_stays_an_error(run, monkeypatch):
    fuzzer = FakeFuzzer(monkeypatch, set())
    fuzzer.mutation_hang = b"not in the corpus"
    original = fuzzer.run

    def always_hang(cmd, **kw):  # a unit of the scratch corpus: it hangs without mutations too
        return original([a if a != "-runs=0" else "-runs=1" for a in cmd], **kw)

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", always_hang)
    verdict = run()
    assert verdict["status"] == "guardrail_error" and verdict["excluded_inputs"] == []
    assert "not tested" in verdict["reason"]


def test_a_hang_is_never_a_code_fault_or_a_rejected_contract(run, monkeypatch):
    FakeFuzzer(monkeypatch, {HANG_A, HANG_B} | {p.read_bytes() for p in run.corpus.iterdir()})
    verdict = run()
    assert verdict["status"] == "guardrail_error" and "fingerprint" not in verdict
    assert not any("unsupported ACSL" in h for h in verdict["diagnostic_hints"])


def test_a_hang_in_the_checked_function_is_named(run, monkeypatch):
    FakeFuzzer(monkeypatch, {HANG_A}, frame=f"__gen_e_acsl_{CHECKED}")
    verdict = run()
    assert verdict["status"] == "passed_dynamic_oracle"
    assert verdict["excluded_inputs"][0]["in_checked_function"] is True


def test_a_real_failure_behind_a_hanging_seed_is_still_reported(run, monkeypatch):
    (run.corpus / "seed-violation").write_bytes(b"breaks a check of the function under proof")
    fuzzer = FakeFuzzer(monkeypatch, {HANG_A, HANG_B})
    fuzzer.violation = b"breaks a check of the function under proof"
    verdict = run(functions=["minmea_scan"])
    assert verdict["status"] == "code_fault" and verdict["failure"]["function"] == "minmea_scan"
    assert sorted(e["input"] for e in verdict["excluded_inputs"]) == ["seed-hang-a", "seed-hang-b"]


def test_an_eacsl_failure_is_not_taken_for_a_hang(run, monkeypatch):
    monkeypatch.setattr(R, "parse_eacsl_failure", lambda out: {"function": CHECKED, "is_rte": True})
    prefix = Path("scratch")
    prefix.mkdir(exist_ok=True)
    assert R.replay_hang(timeout_report(prefix, HANG_A), f"scratch/timeout-{'0' * 40}") is None


def test_only_a_timeout_artifact_counts_as_a_hang(tmp_path):
    out = timeout_report(tmp_path, HANG_A)
    assert R.replay_hang(out, "scratch/crash-0123") is None
    assert R.replay_hang(out, None) is None
    assert "libFuzzer: timeout" in str(R.replay_hang(out, f"scratch/timeout-{'0' * 40}"))
    assert R.replay_hang("==1== ERROR: libFuzzer: deadly signal\n", f"scratch/timeout-{'0' * 40}") is None


def test_a_pass_that_dropped_a_hang_is_not_cached(run, monkeypatch, tmp_path):
    monkeypatch.delenv("FRAMAC_CACHE", raising=False)
    stored: list = []
    monkeypatch.setattr(cache, "enabled", lambda: True)
    monkeypatch.setattr(cache, "file_digest", lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest())
    monkeypatch.setattr(cache, "lookup", lambda *a, **k: None)
    monkeypatch.setattr(cache, "publish", lambda *a, **k: stored.append(a))
    FakeFuzzer(monkeypatch, {HANG_A})
    assert run(use_cache=True)["status"] == "passed_dynamic_oracle"
    assert stored == []  # whether an input hangs depends on the machine


def test_a_cached_pass_keeps_the_count_of_inputs_it_replayed(run, monkeypatch):
    class Entry:
        data = {"verdict": {"status": "passed_dynamic_oracle", "excluded_inputs": [{"input": "seed-hang-a"}]}}

    monkeypatch.setattr(cache, "enabled", lambda: True)
    monkeypatch.setattr(cache, "file_digest", lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest())
    monkeypatch.setattr(cache, "lookup", lambda *a, **k: Entry())
    FakeFuzzer(monkeypatch, set())
    verdict = run(use_cache=True)
    assert verdict["cache"]["hit"] is True and verdict["corpus_replayed"] == 5


# ---------------------------------------------------------------------------
# A target that closes the process's stdio (seed-66-select-fd2-timeout: modbus_set_socket(ctx, 2), then modbus_close)
# ---------------------------------------------------------------------------


def _close_wrapper() -> str:
    src = eacsl_toolchain.generate_errno_shim_source(["close"])
    body = src[src.index("int __wrap_close(") :]
    return body[: body.index("}")]


def test_the_close_shim_keeps_the_process_stdio_open():
    body = _close_wrapper()
    assert body.index("if (a0 >= 0 && a0 <= 2) return 0;") < body.index("__real_close(a0)")


def test_only_close_gets_the_stdio_guard():
    assert "a0 <= 2" not in eacsl_toolchain.generate_errno_shim_source(["read", "dup"])


def test_a_changed_shim_does_not_restore_a_cached_binary(tmp_path, monkeypatch):
    monkeypatch.setattr(fuzz_build, "_resolve_eacsl_gcc", lambda: ("e-acsl-gcc.sh", True))
    monkeypatch.setattr(fuzz_build, "slice_has_pthread", lambda sources: False)

    def material() -> dict:
        args = ("gcc_x86_64", "-I.", "all", True, None, "", True, False, True)
        found = fuzz_build._eacsl_cache_material(["a.c"], tmp_path / "fuzz_mod", *args)
        assert found is not None
        return found

    before = material()["libc_shim"]
    monkeypatch.setattr(fuzz_build, "generate_errno_shim_source", lambda names: "another shim")
    assert material()["libc_shim"] != before


# ---------------------------------------------------------------------------
# Promotion
# ---------------------------------------------------------------------------


@pytest.fixture
def breaker(tmp_path):
    scratch = tmp_path / "agents" / "breaker-1" / "scratch"
    (scratch / "seeds").mkdir(parents=True)
    (scratch / "crashes").mkdir()
    (scratch / "seeds" / "hang").write_bytes(HANG_A)
    (scratch / "seeds" / "fine").write_bytes(b"fine")
    return tmp_path


SEEDS = ["agents/breaker-1/scratch/seeds/hang", "agents/breaker-1/scratch/seeds/fine"]


def test_a_seed_the_breaker_saw_hang_is_not_promoted(breaker):
    sha1 = hashlib.sha1(HANG_A).hexdigest()  # noqa: S324
    (breaker / "agents/breaker-1/scratch/crashes" / f"timeout-{sha1}").write_bytes(HANG_A)
    out = P.promote_seeds(breaker, "breaker-1", "m", SEEDS)
    assert [p["src"] for p in out["promoted"]] == [SEEDS[1]]
    assert out["refused_hanging"] == [{"src": SEEDS[0], "artifact": f"agents/breaker-1/scratch/crashes/timeout-{sha1}"}]
    names = [p.name for p in (breaker / "workspace/corpus/m").iterdir()]
    assert names == [f"seed-{hashlib.sha256(b'fine').hexdigest()[:16]}"]


def test_seeds_without_a_timeout_artifact_are_promoted(breaker):
    (breaker / "agents/breaker-1/scratch/crashes" / f"timeout-{'0' * 40}").write_bytes(b"another input")
    out = P.promote_seeds(breaker, "breaker-1", "m", SEEDS)
    assert len(out["promoted"]) == 2 and out["refused_hanging"] == []


def test_the_cli_reports_a_refused_seed(breaker, capsys):
    sha1 = hashlib.sha1(HANG_A).hexdigest()  # noqa: S324
    (breaker / "agents/breaker-1/scratch/crashes" / f"timeout-{sha1}").write_bytes(HANG_A)
    assert P.main(["--run-dir", str(breaker), "promote-seeds", "--agent-id", "breaker-1", "--module", "m", *SEEDS]) == 0
    assert len(json.loads(capsys.readouterr().out)["refused_hanging"]) == 1
