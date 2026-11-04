"""Hardware changes parallelism, never tool limits: WP, fuzz, guardrail/replay, Eva and parallel merge re-checks."""

from __future__ import annotations

import json
import subprocess
import threading
from pathlib import Path
from typing import Any

import pytest

import resources
import run_eacsl_fuzz as R
import run_eva_slice
import run_wp_function as W
import workspace_overlay
from resources import CLASSES, Budget
from sandbox_exec import SandboxResult

CSV_HEADER = "directory\tfile\tfunction\tline\tkind\tstatus\tproperty\n"
EACSL_MARKER_BYTES = b"\x7fELF...__e_acsl_assert...eacsl_store_block"


def _budget(monkeypatch, cpus: int, mem_mb: int) -> None:
    monkeypatch.setattr(resources, "job_budget", lambda root="/": Budget(cpus=cpus, mem_mb=mem_mb, source="test"))


def _flag(cmd: list[str], name: str) -> str:
    return cmd[cmd.index(name) + 1]


class FakeFramaC:
    """Records WP runs; writes the report CSV it is asked for (all goals Valid by default)."""

    def __init__(self, status: str = "Valid", rc: int = 0, log: str = "[wp] 1 goal scheduled\n"):
        self.calls: list[tuple[list[str], dict]] = []
        self.status, self.rc, self.log = status, rc, log

    def wp_calls(self) -> list[list[str]]:
        return [c for c, _ in self.calls if "-wp" in c]

    def __call__(self, cmd, **kwargs):
        self.calls.append((list(cmd), kwargs))
        if "-wp" in cmd:
            self.goal_dir_existed = Path(_flag(cmd, "-wp-out")).is_dir()
            if self.rc == 0:
                fn = _flag(cmd, "-wp-fct")
                Path(_flag(cmd, "-report-csv")).write_text(
                    CSV_HEADER + f".\tf.c\t{fn}\t1\trte: mem_access\t{self.status}\tx\n", encoding="utf-8"
                )
            if "-save" in cmd:
                Path(_flag(cmd, "-save")).write_bytes(b"sav")
        elif "-mdr-gen" in cmd:
            Path(_flag(cmd, "-mdr-out")).write_text("{}", encoding="utf-8")
        return subprocess.CompletedProcess(cmd, self.rc, stdout=self.log, stderr="")


def _c_file(tmp_path: Path) -> Path:
    c = tmp_path / "f.c"
    c.write_text("int f(int x) { return x; }\n", encoding="utf-8")
    return c


# ---------------------------------------------------------------------------
# WP
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cpus,mem_mb,expected", [(2, 65536, 2), (16, 65536, 16), (16, 2600, 1), (8, 4800, 4)])
def test_wp_par_scales_with_the_budget_while_memlimit_stays_fixed(tmp_path, monkeypatch, cpus, mem_mb, expected):
    _budget(monkeypatch, cpus, mem_mb)
    fake = FakeFramaC()
    monkeypatch.setattr(W.subprocess, "run", fake)
    res = W.run_wp_on_function(_c_file(tmp_path), "f", tmp_path / "wp", retry_bitwise=False)
    (cmd,) = fake.wp_calls()
    assert _flag(cmd, "-wp-par") == str(expected) and res["sizing"]["wp_par"] == expected
    assert _flag(cmd, "-wp-memlimit") == "1000" and res["sizing"]["wp_memlimit_mb"] == resources.WP_MEMLIMIT_MB
    assert res["status"] == "all_proven"


def test_explicit_wp_par_is_honored(tmp_path, monkeypatch):
    _budget(monkeypatch, 16, 65536)
    fake = FakeFramaC()
    monkeypatch.setattr(W.subprocess, "run", fake)
    W.run_wp_on_function(_c_file(tmp_path), "f", tmp_path / "wp", wp_par=3, retry_bitwise=False)
    assert _flag(fake.wp_calls()[0], "-wp-par") == "3"


def test_wp_argv_in_a_run_dir_cache_temp_goals_and_no_save(tmp_path, monkeypatch):
    run = tmp_path / "run"
    run.mkdir()
    (run / "run-metadata.json").write_text("{}", encoding="utf-8")
    monkeypatch.chdir(run)
    monkeypatch.delenv("FRAMAC_CACHE", raising=False)
    fake = FakeFramaC()
    monkeypatch.setattr(W.subprocess, "run", fake)
    out = run / "agents/p-1/scratch/wp"
    res = W.run_wp_on_function(_c_file(run), "f", out, retry_bitwise=False)
    assert len(fake.calls) == 1  # the syntax check is folded into the single Frama-C run
    cmd = fake.calls[0][0]
    assert _flag(cmd, "-kernel-warn-key") == "annot-error=abort"
    assert _flag(cmd, "-wp-cache") == "update"
    assert Path(_flag(cmd, "-wp-cache-dir")) == run / "state" / "cache" / "wp"
    goals = Path(_flag(cmd, "-wp-out"))
    assert fake.goal_dir_existed and out not in goals.parents and not goals.exists()  # private, removed after the run
    assert "-save" not in cmd and not any("-mdr-gen" in c for c, _ in fake.calls)
    assert res["sarif_file"] is None and res["sizing"]["wp_cache_dir"] == str(run / "state" / "cache" / "wp")
    assert not list(out.glob("wp_goals_*"))


def test_wp_sarif_and_kept_goals_only_on_request(tmp_path, monkeypatch):
    fake = FakeFramaC()
    monkeypatch.setattr(W.subprocess, "run", fake)
    out = tmp_path / "wp"
    res = W.run_wp_on_function(_c_file(tmp_path), "f", out, retry_bitwise=False, sarif=True, keep_goals=True)
    wp_cmd = fake.wp_calls()[0]
    assert Path(_flag(wp_cmd, "-save")) == out / "wp_f.sav"
    assert Path(_flag(wp_cmd, "-wp-out")) == out / "wp_goals_f"
    mdr = [c for c, _ in fake.calls if "-mdr-gen" in c]
    assert len(mdr) == 1 and res["sarif_file"] == str(out / "wp_f.sarif")
    assert "-wp-cache-dir" not in wp_cmd  # not a run directory: no cache


def test_wp_cache_dir_off_explicit_and_forced_off(tmp_path, monkeypatch):
    fake = FakeFramaC()
    monkeypatch.setattr(W.subprocess, "run", fake)
    monkeypatch.delenv("FRAMAC_CACHE", raising=False)
    explicit = tmp_path / "wpcache"
    W.run_wp_on_function(_c_file(tmp_path), "f", tmp_path / "wp", retry_bitwise=False, cache_dir=explicit)
    assert Path(_flag(fake.wp_calls()[-1], "-wp-cache-dir")) == explicit
    W.run_wp_on_function(_c_file(tmp_path), "f", tmp_path / "wp", retry_bitwise=False, cache_dir="off")
    assert "-wp-cache" not in fake.wp_calls()[-1]
    monkeypatch.setenv("FRAMAC_CACHE", "off")
    W.run_wp_on_function(_c_file(tmp_path), "f", tmp_path / "wp", retry_bitwise=False, cache_dir=explicit)
    assert "-wp-cache-dir" not in fake.wp_calls()[-1]
    monkeypatch.setenv("FRAMAC_CACHE", "on")
    W.run_wp_on_function(_c_file(tmp_path), "f", tmp_path / "wp", retry_bitwise=False, dump_goal=True)
    assert "-wp-cache-dir" not in fake.wp_calls()[-1]  # a VC dump always runs the provers


def test_bitwise_retry_reuses_the_cache_dir_and_sizing(tmp_path, monkeypatch):
    _budget(monkeypatch, 4, 65536)
    monkeypatch.setenv("FRAMAC_CACHE", "on")
    monkeypatch.chdir(tmp_path)
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        status = "Unknown" if _flag(cmd, "-wp-model") == "Typed" else "Valid"
        Path(_flag(cmd, "-report-csv")).write_text(
            CSV_HEADER + f".\tf.c\tf\t1\trte: shift\t{status}\tx << 3\n", encoding="utf-8"
        )
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(W.subprocess, "run", fake_run)
    res = W.run_wp_on_function(_c_file(tmp_path), "f", tmp_path / "wp")
    first, retry = calls
    assert res["status"] == "all_proven" and res["bitwise_retry"]["triggered"]
    assert _flag(retry, "-wp-model") == "Typed+ref+int"
    assert _flag(retry, "-wp-cache-dir") == _flag(first, "-wp-cache-dir")
    assert _flag(retry, "-wp-par") == _flag(first, "-wp-par") == "4"
    assert _flag(retry, "-wp-memlimit") == "1000"


ANNOT_ERROR_LOG = (
    "[kernel] Parsing f.c (with preprocessing)\n"
    "[kernel:annot-error] f.c:1: Failure: \n"
    "  unbound logic variable alse. Ignoring logic specification of function f\n"
    "[kernel] User Error: warning annot-error treated as fatal error.\n"
    "[kernel] Frama-C aborted: invalid user input.\n"
)
C_SYNTAX_LOG = (
    "[kernel] Parsing f.c (with preprocessing)\n"
    "[kernel] f.c:1: \n"
    "  syntax error:\n"
    '  Location: "f.c", line 1, before or at token: ;\n'
    "[kernel] Frama-C aborted: invalid user input.\n"
)


@pytest.mark.parametrize(
    "log,needle", [(ANNOT_ERROR_LOG, "unbound logic variable alse"), (C_SYNTAX_LOG, "syntax error")]
)
def test_folded_syntax_check_still_reports_acsl_syntax_error(tmp_path, monkeypatch, log, needle):
    fake = FakeFramaC(rc=1, log=log)
    monkeypatch.setattr(W.subprocess, "run", fake)
    res = W.run_wp_on_function(_c_file(tmp_path), "f", tmp_path / "wp")
    assert res["status"] == "acsl_syntax_error" and res["function"] == "f"
    check = res["syntax_check"]
    assert check["syntax_ok"] is False and check["returncode"] == 1 and needle in check["raw_log"]
    assert any(needle in e for e in check["errors"])
    assert not any("Frama-C aborted" in e for e in check["errors"])
    assert len(fake.calls) == 1


def test_a_wp_user_error_is_a_tier_a_abort_not_a_syntax_error(tmp_path, monkeypatch):
    log = (
        "[kernel] Parsing f.c\n[wp] User Error: Main entry point function 'f' is (potentially) recursive.\n"
        "[kernel] Frama-C aborted: invalid user input.\n"
    )
    monkeypatch.setattr(W.subprocess, "run", FakeFramaC(rc=1, log=log))
    res = W.run_wp_on_function(_c_file(tmp_path), "f", tmp_path / "wp")
    assert res["status"] == "wp_aborted"


def test_wp_cli_defaults(tmp_path, monkeypatch):
    _budget(monkeypatch, 6, 65536)
    fake = FakeFramaC()
    monkeypatch.setattr(W.subprocess, "run", fake)
    monkeypatch.delenv("FRAMAC_WP_WALL_TIMEOUT", raising=False)
    base = [
        "--file",
        str(_c_file(tmp_path)),
        "--function",
        "f",
        "--out-dir",
        str(tmp_path / "wp"),
        "--out-json",
        str(tmp_path / "wp.json"),
        "--no-retry-bitwise",
    ]
    assert W.main(base) == 0
    cmd, kwargs = fake.calls[-1]
    assert kwargs["timeout"] == CLASSES["wp"].wall_timeout_s and _flag(cmd, "-wp-par") == "6"
    monkeypatch.setenv("FRAMAC_WP_WALL_TIMEOUT", "0")
    W.main(base)
    assert fake.calls[-1][1]["timeout"] is None
    W.main(base + ["--wall-timeout", "7", "--wp-par", "2"])
    assert fake.calls[-1][1]["timeout"] == 7 and _flag(fake.calls[-1][0], "-wp-par") == "2"
    with pytest.raises(SystemExit):
        W.main(base + ["--wp-par", "0"])
    report = json.loads((tmp_path / "wp.json").read_text(encoding="utf-8"))
    assert report["sizing"]["wall_timeout_s"] == 7


# ---------------------------------------------------------------------------
# Fuzz campaigns, guardrails, replays, builds
# ---------------------------------------------------------------------------


def _campaign(monkeypatch, tmp_path, *extra):
    seen: dict[str, Any] = {}
    binary = tmp_path / "fuzz_mod.e-acsl"
    monkeypatch.setattr(
        R, "compile_eacsl_binary", lambda *a, **k: {"engine": "eacsl", "returncode": 0, "binary": str(binary)}
    )

    def fake_campaign(binary, corpus, artifacts, max_time, *a, **k):
        seen.update(max_time=max_time, jobs=k["jobs"], workers=k["workers"])
        return {"status": "clean", "artifacts": []}

    monkeypatch.setattr(R, "run_fuzz_campaign", fake_campaign)
    out = tmp_path / "out.json"
    R.main(
        [
            "campaign",
            "--sources",
            "mod.c",
            "--out-bin",
            str(tmp_path / "fuzz_mod"),
            "--corpus-dir",
            str(tmp_path / "c"),
            "--artifacts-dir",
            str(tmp_path / "a"),
            "--selftest-json",
            str(tmp_path / "none.json"),
            "--out-json",
            str(out),
            *extra,
        ]
    )
    return seen, json.loads(out.read_text(encoding="utf-8"))


@pytest.mark.parametrize("cpus,mem_mb,workers", [(8, 65536, 8), (8, 4096, 1), (16, 30000, 11), (1, 65536, 1)])
def test_fuzz_workers_auto_scale_with_cpus_and_memory(tmp_path, monkeypatch, cpus, mem_mb, workers):
    _budget(monkeypatch, cpus, mem_mb)
    seen, out = _campaign(monkeypatch, tmp_path)
    assert seen["workers"] == seen["jobs"] == workers
    assert seen["max_time"] == 60  # no budget, no --max-time: the historical default
    assert out["sizing"]["rss_limit_mb"] == 2048 and out["sizing"]["workers"] == workers


def test_fuzz_budget_turns_cpu_seconds_into_wall_time(tmp_path, monkeypatch):
    _budget(monkeypatch, 4, 65536)
    seen, out = _campaign(monkeypatch, tmp_path, "--fuzz-budget", "900")
    assert seen["max_time"] == 225 and out["sizing"]["fuzz_budget_cpu_s"] == 900
    seen, _ = _campaign(monkeypatch, tmp_path, "--fuzz-budget", "60")
    assert seen["max_time"] == 30  # floor
    seen, _ = _campaign(monkeypatch, tmp_path, "--fuzz-budget", "900", "--max-time", "45")
    assert seen["max_time"] == 45  # explicit wall time wins
    seen, _ = _campaign(monkeypatch, tmp_path, "--workers", "2", "--jobs", "6", "--fuzz-budget", "120")
    assert (seen["workers"], seen["jobs"], seen["max_time"]) == (2, 6, 60)
    with pytest.raises(SystemExit):
        _campaign(monkeypatch, tmp_path, "--workers", "zero")


@pytest.mark.parametrize("workers", [1, 4, 16])
def test_campaign_rss_limit_is_fixed_whatever_the_worker_count(tmp_path, monkeypatch, workers):
    captured = {}

    def fake_sandbox(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        captured["cmd"] = list(cmd)
        return SandboxResult(0, "", "", False, "rlimits", list(cmd))

    monkeypatch.setattr(R, "run_sandboxed", fake_sandbox)
    binary = tmp_path / "bin"
    binary.write_bytes(b"x")
    R.run_fuzz_campaign(binary, tmp_path / "corpus", tmp_path / "crashes", max_time=30, workers=workers)
    assert "-rss_limit_mb=2048" in captured["cmd"] and "-timeout=10" in captured["cmd"]


def test_guardrail_and_replay_use_fixed_limits_and_a_deterministic_seed(tmp_path, monkeypatch):
    calls = []

    def fake_sandbox(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        calls.append(list(cmd))
        return SandboxResult(0, "", "", False, "rlimits", list(cmd))

    monkeypatch.setattr(R, "run_sandboxed", fake_sandbox)
    binary = tmp_path / "guard_f.e-acsl"
    binary.write_bytes(EACSL_MARKER_BYTES)
    verdict = R.run_guardrail_check(binary, tmp_path / "corpus", tmp_path / "scratch", runs=50)
    guard = calls[-1]
    seed = R.derive_seed(binary)
    assert verdict["status"] == "passed_dynamic_oracle" and verdict["seed"] == seed
    assert "-runs=50" in guard and "-timeout=30" in guard and "-rss_limit_mb=2048" in guard and f"-seed={seed}" in guard
    R.run_guardrail_check(binary, tmp_path / "corpus", tmp_path / "scratch", runs=50)
    assert calls[-1] == guard  # same build, same command: same mutations

    inp = tmp_path / "crash-1"
    inp.write_bytes(b"x")
    rep = R.replay_artifact(binary, inp, tmp_path / "scratch", module="mod")
    assert rep["seed"] == R.derive_seed(binary, "mod") != seed
    assert "-timeout=10" in calls[-1] and "-rss_limit_mb=2048" in calls[-1] and f"-seed={rep['seed']}" in calls[-1]


def test_compile_stages_get_the_build_class_timeout(tmp_path, monkeypatch):
    monkeypatch.setattr(R, "_resolve_eacsl_gcc", lambda: ("e-acsl-gcc", True))
    monkeypatch.setattr(R.shutil, "which", lambda name: None)
    import eacsl_toolchain as T

    monkeypatch.setattr(T.shutil, "which", lambda name: None)
    timeouts = []
    src = tmp_path / "mod.c"
    src.write_text("int entry(int x) { return x; }\n", encoding="utf-8")

    def runner(cmd, **kwargs):
        timeouts.append(kwargs.get("timeout"))
        if "-C" in cmd:
            raise subprocess.TimeoutExpired(cmd, float(kwargs.get("timeout") or 0), output=b"linking", stderr=None)
        Path(cmd[cmd.index("-o") + 1]).write_text("int f(void) { return 0; }\n", encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    res = R.compile_eacsl_binary([str(src)], tmp_path / "fuzz_mod", runner=runner, use_cache=False)
    assert timeouts == [CLASSES["build"].wall_timeout_s] * 2
    assert res["returncode"] == 124 and res["reason"] == "eacsl_compile_failed"
    assert "build time limit" in Path(res["compile_log"]).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Eva
# ---------------------------------------------------------------------------


def test_eva_timeout_default_and_extra_domains(tmp_path, monkeypatch):
    seen = []

    def fake_run(cmd, **kwargs):
        seen.append((list(cmd), kwargs.get("timeout")))
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")

    monkeypatch.setattr(run_eva_slice.subprocess, "run", fake_run)
    base = [
        "--sources",
        str(_c_file(tmp_path)),
        "--main",
        "eva_main",
        "--out-dir",
        str(tmp_path / "eva"),
        "--out-json",
        str(tmp_path / "eva.json"),
    ]
    run_eva_slice.main(base)
    cmd, timeout = seen[-1]
    assert timeout == CLASSES["eva"].wall_timeout_s
    assert _flag(cmd, "-eva-domains") == "cvalue,equality,symbolic-locations,octagon,gauges"
    assert "-eva-mlevel" not in cmd
    run_eva_slice.main(
        base
        + ["--timeout", "0", "--extra-domains", "taint,octagon", "--mlevel", "4", "--allow-incomplete-recursion-specs"]
    )
    cmd, timeout = seen[-1]
    assert timeout is None and _flag(cmd, "-eva-domains") == "cvalue,equality,symbolic-locations,octagon,gauges,taint"
    assert _flag(cmd, "-eva-mlevel") == "4"
    assert _flag(cmd, "-eva-warn-key") == "assigns:missing=warning"
    # Both -eva-mlevel and -eva-warn-key must appear inside the -eva option group (before the next -then).
    eva_idx = cmd.index("-eva")
    next_then_idx = cmd.index("-then", eva_idx)
    assert eva_idx < cmd.index("-eva-mlevel") < next_then_idx
    assert eva_idx < cmd.index("-eva-warn-key") < next_then_idx
    with pytest.raises(SystemExit):
        run_eva_slice.main(base + ["--extra-domains", "taint;rm"])
    with pytest.raises(SystemExit):
        run_eva_slice.main(base + ["--mlevel", "-1"])


# ---------------------------------------------------------------------------
# merge-batch: parallel re-checks and the fixpoint
# ---------------------------------------------------------------------------

BASE_C = """\
int callee(int x) {
    return x;
}

int caller(int x) {
    return callee(x);
}

int other(int x) {
    return x + 1;
}
"""


def _batch_run(tmp_path: Path, edits: dict[str, tuple[str, str]], module: bool = True) -> tuple[Path, Path]:
    target = tmp_path / "target"
    target.mkdir()
    (target / "m.c").write_text(BASE_C, encoding="utf-8")
    run_dir = (tmp_path / "run").resolve()
    overlay = run_dir / "workspace"
    workspace_overlay.init_overlay(target, overlay)
    if module:
        (overlay / "harnesses").mkdir(parents=True, exist_ok=True)
        (overlay / "harnesses" / "harness_m.json").write_text(
            json.dumps({"module": "m", "sources": ["workspace/work/m.c"], "cppflags": "-I."}), encoding="utf-8"
        )
    for agent_id, (old, new) in edits.items():
        workspace_overlay.init_agent_overlay(run_dir, agent_id, overlay)
        path = run_dir / "agents" / agent_id / "scratch" / "work" / "m.c"
        path.write_text(path.read_text(encoding="utf-8").replace(old, new), encoding="utf-8")
    return run_dir, overlay


EDITS = {
    "prover-callee": (
        "    return x;\n}\n\nint caller",
        "    //@ assert callee_ok: x == x;\n    return x;\n}\n\nint caller",
    ),
    "prover-caller": ("    return callee(x);", "    //@ assert caller_ok: x == x;\n    return callee(x);"),
    "prover-other": ("    return x + 1;", "    //@ assert other_ok: x == x;\n    return x + 1;"),
}
SPECS = [
    {"agent_id": "prover-callee", "role": "prover", "file": "m.c", "function": "callee"},
    {"agent_id": "prover-caller", "role": "prover", "file": "m.c", "function": "caller"},
    {"agent_id": "prover-other", "role": "prover", "file": "m.c", "function": "other"},
]


def test_parent_recheck_argv_is_accepted_by_the_real_clis(tmp_path, monkeypatch):
    """Single-token flags (`-I.`, `-lm`) must reach the child CLIs as `--opt=value`, or argparse rejects them."""
    run_dir, overlay = _batch_run(tmp_path, {})
    (overlay / "harnesses" / "harness_m.c").write_text(
        "int LLVMFuzzerTestOneInput(void) { return 0; }\n", encoding="utf-8"
    )
    real_run = subprocess.run
    children = []

    def compile_ok(sources, out_bin, *a, **k):
        binary = Path(str(out_bin) + ".e-acsl")
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(EACSL_MARKER_BYTES)
        return {"engine": "eacsl", "returncode": 0, "binary": str(binary), "cache": {"hit": False, "key": None}}

    def fake_run(cmd, **kwargs):
        if cmd[0] == "frama-c":
            return FakeFramaC()(cmd, **kwargs)
        script = Path(cmd[1]).name
        children.append((script, list(cmd[2:])))
        rc = (W.main if script == "run_wp_function.py" else R.main)(list(cmd[2:]))  # the real parsers
        return subprocess.CompletedProcess(cmd, rc, stdout="", stderr="")

    monkeypatch.setattr(workspace_overlay.subprocess, "run", fake_run)
    monkeypatch.setattr(R, "compile_eacsl_binary", compile_ok)
    monkeypatch.setattr(R, "run_sandboxed", lambda cmd, **k: SandboxResult(0, "", "", False, "rlimits", list(cmd)))
    monkeypatch.chdir(run_dir)
    try:
        ok, why = workspace_overlay._run_parent_reverify(
            run_dir,
            "prover-1",
            "prover",
            overlay,
            "m.c",
            "callee",
            "m",
            ["workspace/work/m.c"],
            "-I.",
            ldflags="-lm",
            wp_par=3,
        )
    finally:
        monkeypatch.setattr(workspace_overlay.subprocess, "run", real_run)
    assert ok, why
    (guard_script, guard_argv), (wp_script, wp_argv) = children
    assert guard_script == "run_eacsl_fuzz.py" and "--cppflags=-I." in guard_argv and "--ldflags=-lm" in guard_argv
    guard_bin = Path(guard_argv[guard_argv.index("--out-bin") + 1])
    assert run_dir / "state" / "parent_guard" in guard_bin.parents  # outside agents/*/scratch: cacheable
    assert wp_script == "run_wp_function.py" and "--cppflags=-I." in wp_argv and "--sarif" in wp_argv
    assert wp_argv[wp_argv.index("--wp-par") + 1] == "3"
    report = json.loads((run_dir / "agents/prover-1/scratch/parent_wp/callee.json").read_text(encoding="utf-8"))
    assert report["status"] == "all_proven" and report["sizing"]["wp_par"] == 3 and report["sarif_file"]


def test_merge_batch_rechecks_run_in_parallel_and_share_the_budget(tmp_path, monkeypatch):
    run_dir, overlay = _batch_run(tmp_path, EDITS)
    monkeypatch.setattr(workspace_overlay, "job_budget", lambda: Budget(cpus=8, mem_mb=65536, source="test"))
    barrier = threading.Barrier(4)  # 1 module guardrail + 3 WP checks must all be running at once
    seen = []

    def fake_reverify(
        run_dir, agent_id, role, overlay_dir, c_file, function, module, sources, cppflags, ldflags="", wp_par=None
    ):
        barrier.wait(timeout=10)
        seen.append((role, function, module, wp_par))
        return True, "ok"

    monkeypatch.setattr(workspace_overlay, "_run_parent_reverify", fake_reverify)
    res = workspace_overlay.merge_agent_batch(run_dir, SPECS, overlay_dir=overlay, default_module="m")
    assert res["ok"] and not res["bisected"] and res["rounds"] == 1 and len(res["merged"]) == 3
    assert sorted(s[1] or "" for s in seen) == ["", "callee", "caller", "other"]
    assert [s for s in seen if s[0] == "architect"] == [("architect", None, "m", 2)]  # one guardrail per module
    assert {s[3] for s in seen} == {2}  # 8 CPUs / 4 workers
    merged = (overlay / "work" / "m.c").read_text(encoding="utf-8")
    assert all(f"{n}_ok" in merged for n in ("callee", "caller", "other"))
    assert {r["parent_wp_report"] for r in res["merged"]} == {
        f"agents/{s['agent_id']}/scratch/parent_wp/{s['function']}.json" for s in SPECS
    }


def test_merge_batch_fixpoint_rejects_a_caller_that_needed_a_rejected_callee(tmp_path, monkeypatch):
    run_dir, overlay = _batch_run(tmp_path, EDITS, module=False)
    monkeypatch.setattr(workspace_overlay, "job_budget", lambda: Budget(cpus=4, mem_mb=65536, source="test"))
    work = overlay / "work" / "m.c"

    def fake_reverify(
        run_dir, agent_id, role, overlay_dir, c_file, function, module, sources, cppflags, ldflags="", wp_par=None
    ):
        tree = work.read_text(encoding="utf-8")
        if function == "callee":
            return False, "callee WP failed"
        if function == "caller" and "callee_ok" not in tree:
            return False, "caller WP needs the callee contract"
        return True, "ok"

    monkeypatch.setattr(workspace_overlay, "_run_parent_reverify", fake_reverify)
    res = workspace_overlay.merge_agent_batch(run_dir, SPECS, overlay_dir=overlay)
    assert res["bisected"] and res["batch_failure_reason"] == "callee WP failed"
    assert res["rounds"] == 3  # all three -> {caller, other} (caller now fails) -> {other} passes
    assert [r["agent_id"] for r in res["merged"]] == ["prover-other"]
    assert {r["agent_id"]: r["reason"] for r in res["failed"]} == {
        "prover-callee": "callee WP failed",
        "prover-caller": "caller WP needs the callee contract",
    }
    tree = work.read_text(encoding="utf-8")
    assert "other_ok" in tree and "callee_ok" not in tree and "caller_ok" not in tree
    assert (run_dir / "agents/prover-other/artifacts/other.patch").is_file()
    assert not (run_dir / "agents/prover-callee/artifacts/callee.patch").exists()
    assert not (run_dir / "agents/prover-caller/artifacts/caller.patch").exists()
    assert not (run_dir / "state/merge-journal.json").exists()


def test_merge_batch_shared_guardrail_failure_retries_overlays_one_by_one(tmp_path, monkeypatch):
    edits = {k: EDITS[k] for k in ("prover-callee", "prover-other")}
    run_dir, overlay = _batch_run(tmp_path, edits)
    monkeypatch.setattr(workspace_overlay, "job_budget", lambda: Budget(cpus=2, mem_mb=65536, source="test"))
    work = overlay / "work" / "m.c"
    guardrails = []

    def fake_reverify(
        run_dir, agent_id, role, overlay_dir, c_file, function, module, sources, cppflags, ldflags="", wp_par=None
    ):
        if module:
            guardrails.append(agent_id)
            if "other_ok" in work.read_text(encoding="utf-8"):
                return False, "parent guardrail returned status='rejected_overconstrained'"
        return True, "ok"

    monkeypatch.setattr(workspace_overlay, "_run_parent_reverify", fake_reverify)
    specs = [s for s in SPECS if s["agent_id"] in edits]
    res = workspace_overlay.merge_agent_batch(run_dir, specs, overlay_dir=overlay, default_module="m")
    assert res["bisected"] and [r["agent_id"] for r in res["merged"]] == ["prover-callee"]
    assert [r["agent_id"] for r in res["failed"]] == ["prover-other"]
    assert res["failed"][0]["batch_failure_reason"].startswith("parent guardrail")
    tree = work.read_text(encoding="utf-8")
    assert "callee_ok" in tree and "other_ok" not in tree
    assert len(guardrails) == 3  # the shared check, then one per overlay


def test_fuzz_campaign_refuses_when_memory_below_minimum(tmp_path, monkeypatch):
    monkeypatch.setattr(R, "enforced_memory_mb", lambda: 2048)
    monkeypatch.setattr(
        R,
        "build_module_binary",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not build when memory is insufficient")),
    )
    out = tmp_path / "fuzz.json"
    rc = R.main(
        [
            "campaign",
            "--module",
            "m",
            "--sources",
            "m.c",
            "--out-bin",
            str(tmp_path / "fuzz_m"),
            "--corpus-dir",
            str(tmp_path / "c"),
            "--artifacts-dir",
            str(tmp_path / "a"),
            "--out-json",
            str(out),
        ]
    )
    assert rc == 0
    rep = json.loads(out.read_text(encoding="utf-8"))
    assert rep["status"] == "insufficient_memory"
    assert rep["min_memory_mb"] == R.fuzz_required_memory_mb(rep["sizing"]["workers"])
    assert R.FUZZ_MIN_MEMORY_MB == 3072


def test_merge_batch_bounds_workers_and_wp_par_by_memory(tmp_path, monkeypatch):
    run_dir, overlay = _batch_run(tmp_path, EDITS, module=False)
    # 8 CPUs, but 4000 MiB only fits 2 WP workers (2 * 1768 = 3536 MiB), each with wp_par=1 (2000 - 768 >= 1000).
    monkeypatch.setattr(workspace_overlay, "job_budget", lambda: Budget(cpus=8, mem_mb=4000, source="test"))
    seen_wp_par = []

    def fake_reverify(
        run_dir, agent_id, role, overlay_dir, c_file, function, module, sources, cppflags, ldflags="", wp_par=None
    ):
        seen_wp_par.append(wp_par)
        return True, "ok"

    monkeypatch.setattr(workspace_overlay, "_run_parent_reverify", fake_reverify)
    res = workspace_overlay.merge_agent_batch(run_dir, SPECS, overlay_dir=overlay)
    assert res["ok"] and len(res["merged"]) == 3
    assert set(seen_wp_par) == {1}
