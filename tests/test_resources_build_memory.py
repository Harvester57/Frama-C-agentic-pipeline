"""
Container-broker sizing of the first E-ACSL build of a module, and OOM evidence (nginx 1.31.9 run-3,
2026-11-19). `pipeline_make.py build-check` ran `resources.py run --class build` for two modules whose
source lists cover nearly the whole nginx link unit (163 and 161 of its 165 files). With no build
history for either key, the broker granted the class model, 2 GiB each, and admitted both into a
17 GiB container; each whole-program Frama-C (E-ACSL) grew past 8 GB and the cgroup OOM killer took
one at 15:01:48. Phase 0 had already measured the unit's parse: 10471 MiB (the model container's
`phase-static` record). Under engine `auto` the killed E-ACSL compile fell back to the sanitizer
build, so the job exited 1, not 137, and the broker neither retried nor flagged the OOM.

Fixtures are copies of run-3's records (null key, container scope) and of the model's fields.
"""

from __future__ import annotations

import json
import math
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import resources as R
from test_resources import SCRIPT, Harness, _isolated_env, _run_cli, wait_for  # noqa: F401  (autouse fixture)

POOL_MEM_MB = 17408  # the build-check container: HostConfig.Memory 18253611008 B = 17 GiB
POOL_CPUS = 30
UNIT_FILES = [f"src/core/ngx_unit_{i:03d}.c" for i in range(165)]  # objs/nginx: 165 files, one parse job
JOB_KEY = "8e61d9631d20a21d"
OPENSSL_UNIT_FILES = 163  # SOURCES_nginx__ngx_event_openssl: 163 unit files + the harness
FILES_UNIT_FILES = 161  # SOURCES_nginx__ngx_files: 161 unit files + the harness

# workspace/reports/phase0_model.json of run-3 (fields the sizing reads).
RUN3_MODEL = {
    "schema_version": 2,
    "generated_at": "2026-11-19T11:55:52.537225+00:00",
    "status": "ok",
    "tree": "/framac-scratch/tree",
    "units": {"objs/nginx": {"kind": "executable", "files": UNIT_FILES, "parse": {"status": "ok", "job": JOB_KEY}}},
    "parse_jobs": [
        {"key": JOB_KEY, "units": ["objs/nginx"], "sources": UNIT_FILES, "status": "ok", "seconds": 1207.88}
    ],
    "seconds": 1217.42,
}


def _phase_static(ts: str, peak: int, mem_mb: int = 17408, oom: int = 0, cpu: float = 1.0) -> dict:
    return {
        "class": "phase-static",
        "cpu_seconds": cpu,
        "cpus": 15.0,
        "key": None,
        "mem_mb": mem_mb,
        "oom_killed": bool(oom),
        "oom_kills": oom,
        "peak_mb": peak,
        "rc": 1 if oom else 0,
        "scope": "container",
        "source": "cgroup",
        "ts": ts,
    }


# state/resource-history/phase-static of run-3: the model container (12:16:11), then decoys: the next
# containers (23 and 113 MiB), the build-check container itself (OOM-killed at the 17 GiB limit), a later one.
RUN3_PHASE_STATIC = {
    "20261119T121611091611Z-0b01b5a0.json": _phase_static("2026-11-19T12:16:11.089293+00:00", 10471, cpu=309.571),
    "20261119T121619493316Z-00aa8b58.json": _phase_static("2026-11-19T12:16:19.489880+00:00", 23),
    "20261119T122332136851Z-a54b49cc.json": _phase_static("2026-11-19T12:23:32.133652+00:00", 113),
    "20261119T141531340121Z-5e3fd0aa.json": _phase_static("2026-11-19T14:15:31.337644+00:00", 17408, oom=2),
    "20261119T141655823104Z-77b2c9e1.json": _phase_static("2026-11-19T14:16:55.820135+00:00", 148, mem_mb=34816),
}


def _run3_dir(root: Path, model: dict | None = None, records: dict | None = None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "run-metadata.json").write_text("{}", encoding="utf-8")
    reports = root / "workspace" / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "phase0_model.json").write_text(json.dumps(model or RUN3_MODEL), encoding="utf-8")
    hist = root / "state" / "resource-history" / "phase-static"
    hist.mkdir(parents=True, exist_ok=True)
    for name, rec in (RUN3_PHASE_STATIC if records is None else records).items():
        (hist / name).write_text(json.dumps(rec), encoding="utf-8")
    return root


def _build_cmd(module: str, unit_files: int) -> list[str]:
    sources = [f"workspace/work/{s}" for s in UNIT_FILES[:unit_files]] + [f"workspace/harnesses/harness_{module}.c"]
    return [
        "python3",
        "/opt/framac-pipeline/scripts/run_eacsl_fuzz.py",
        "build",
        "--module",
        module,
        "--sources",
        *sources,
        f"--out-bin=workspace/harnesses/fuzz_{module}",
        "--engine=auto",
    ]


def _expected(unit_files: int, peak: float = 10471, total: int = 165) -> int:
    """1.25 x the unit's measured parse peak x the share of its sources the build compiles."""
    return math.ceil(1.25 * peak * unit_files / total)


# ---------------------------------------------------------------------------
# The estimate (pure)
# ---------------------------------------------------------------------------


def test_first_build_estimate_scales_the_model_containers_parse_peak(tmp_path):
    run = _run3_dir(tmp_path / "run-3")
    openssl = R.first_build_estimate(run, _build_cmd("nginx__ngx_event_openssl", OPENSSL_UNIT_FILES))
    files = R.first_build_estimate(run, _build_cmd("nginx__ngx_files", FILES_UNIT_FILES))
    assert openssl is not None and files is not None
    assert openssl[0] == _expected(OPENSSL_UNIT_FILES) == 12931
    assert files[0] == _expected(FILES_UNIT_FILES) == 12772
    assert "10471" in openssl[1] and "163/165" in openssl[1]
    # Two of them never fit the 17 GiB container together; either one fits alone.
    assert openssl[0] + files[0] > POOL_MEM_MB and max(openssl[0], files[0]) < POOL_MEM_MB
    # Records outside the model's window (build-check's own OOM record at the limit, later containers) never count.
    later_only = {k: v for k, v in RUN3_PHASE_STATIC.items() if k.startswith("20261119T14")}
    no_record = _run3_dir(tmp_path / "no-model-record", records=later_only)
    assert R.first_build_estimate(no_record, _build_cmd("m", 163)) is None


def test_first_build_estimate_is_none_without_measurements_or_sources(tmp_path):
    run = _run3_dir(tmp_path / "run")
    assert R.first_build_estimate(run, ["python3", "run_eacsl_fuzz.py", "build", "--module", "m"]) is None
    assert R.first_build_estimate(run, ["x", "--sources", "workspace/harnesses/harness_m.c"]) is None
    assert R.first_build_estimate(tmp_path / "elsewhere", _build_cmd("m", 163)) is None
    (run / "workspace" / "reports" / "phase0_model.json").write_text("{not json", encoding="utf-8")
    assert R.first_build_estimate(run, _build_cmd("m", 163)) is None


def test_first_build_estimate_prefers_the_parse_jobs_own_history(tmp_path):
    """A parse lease records `parse/p0-<job>` (rusage of that Frama-C alone): it wins over the container record."""
    run = _run3_dir(tmp_path / "run")
    R.write_history(run, {"class": "parse", "key": f"p0-{JOB_KEY}", "peak_mb": 9000, "oom_killed": False})
    est = R.first_build_estimate(run, _build_cmd("m", 165))
    assert est is not None and est[0] == math.ceil(1.25 * 9000) and f"p0-{JOB_KEY}" in est[1]


def test_first_build_estimate_splits_a_shared_container_record_across_parse_jobs(tmp_path):
    """With several parse jobs in the model's container, each job gets the record's peak by its share of sources."""
    a = [f"src/a/{i}.c" for i in range(30)]
    b = [f"src/b/{i}.c" for i in range(10)]
    model = dict(
        RUN3_MODEL,
        parse_jobs=[
            {"key": "ja", "units": ["a"], "sources": a, "status": "ok", "seconds": 10.0},
            {"key": "jb", "units": ["b"], "sources": b, "status": "ok", "seconds": 10.0},
        ],
    )
    run = _run3_dir(tmp_path / "run", model=model)
    cmd = ["x", "--sources", *(f"workspace/work/{s}" for s in a[:15]), "--engine=auto"]
    est = R.first_build_estimate(run, cmd)
    assert est is not None and est[0] == math.ceil(1.25 * 10471 * 30 / 40 * 15 / 30)


def test_small_unit_builds_keep_the_class_lease_and_their_concurrency(tmp_path):
    """No regression for small targets: a 300 MiB parse peak gives a floor below the class model."""
    small = {"20261119T121611091611Z-0b01b5a0.json": _phase_static("2026-11-19T12:16:11.089293+00:00", 300)}
    run = _run3_dir(tmp_path / "run", records=small)
    est = R.first_build_estimate(run, _build_cmd("m", 165))
    assert est is not None and est[0] < R.CLASSES["build"].mem_base_mb
    broker = R.Broker(tmp_path / "broker", lambda: R.Budget(4, 5120, "t"), history_fn=lambda c, k: est[0])
    a, b = broker.acquire("build", "a"), broker.acquire("build", "b", timeout=2)
    assert (a.mem_mb, b.mem_mb) == (2048, 2048)
    broker.release(a)
    broker.release(b)


def test_two_whole_unit_builds_are_not_planned_together():
    first, second = _expected(OPENSSL_UNIT_FILES), _expected(FILES_UNIT_FILES)

    def ticket(lid: str, seq: int, floor: int) -> dict[str, Any]:
        demand = {"min_cpus": 1, "max_cpus": 4, "mem_base_mb": 2048, "mem_per_cpu_mb": 0, "mem_floor_mb": floor}
        return {"id": lid, "class": "build", "seq": seq, "state": "waiting", "gated": True, "demand": demand}

    a, b = ticket("a", 1, first), ticket("b", 2, second)
    grant = R.plan_grant(a, [a, b], POOL_CPUS, POOL_MEM_MB)
    assert grant is not None and grant.mem_mb == first
    granted = dict(a, state="granted", cpus=grant.cpus, mem_mb=grant.mem_mb)
    assert R.plan_grant(b, [granted, b], POOL_CPUS, POOL_MEM_MB) is None


def test_a_first_build_larger_than_the_pool_is_granted_alone_with_the_clamp_warning(tmp_path):
    msgs: list[str] = []

    class _Log:
        def write(self, text: str) -> None:
            msgs.append(text)

        def flush(self) -> None:
            pass

    broker = R.Broker(tmp_path / "broker", lambda: R.Budget(30, 8192, "t"), history_fn=lambda c, k: 12931, log=_Log())
    lease = broker.acquire("build", "nginx__ngx_event_openssl")
    assert lease.mem_mb == 8192 and any("clamped to the pool" in w for w in lease.warnings), lease.warnings
    with pytest.raises(TimeoutError):
        broker.acquire("build", "nginx__ngx_files", timeout=0.3)
    broker.release(lease)


# ---------------------------------------------------------------------------
# The container broker end to end (real `resources.py run` processes)
# ---------------------------------------------------------------------------


@pytest.fixture
def build_harness(tmp_path):
    h = Harness(tmp_path)
    yield h
    h.cleanup()


def _start_build(h: Harness, name: str, unit_files: int, hold: float, gate: Path | None = None) -> None:
    sources = [f"workspace/work/{s}" for s in UNIT_FILES[:unit_files]] + [f"workspace/harnesses/harness_{name}.c"]
    cmd = [
        sys.executable,
        str(SCRIPT),
        "run",
        "--class",
        "build",
        "--key",
        name,
        "--",
        sys.executable,
        str(h.child),
        str(h.logs),
        name,
        str(hold),
        str(gate) if gate else "",  # the child's gate argument; the build arguments follow
        "--sources",
        *sources,
    ]
    with open(h.logs / f"{name}.broker.txt", "w", encoding="utf-8") as out:
        h.procs.append(subprocess.Popen(cmd, cwd=h.cwd, env=h.env, stdout=out, stderr=subprocess.STDOUT))
    h.names.append(name)


def test_first_builds_of_two_whole_unit_modules_run_one_at_a_time(build_harness):
    """Run-3 regression: both used to be admitted at 2048 MiB and ran together into the OOM killer."""
    h = build_harness
    h.set_pool(POOL_CPUS, POOL_MEM_MB)
    _run3_dir(h.cwd)
    _start_build(h, "nginx__ngx_event_openssl", OPENSSL_UNIT_FILES, hold=2.0)
    wait_for(lambda: h.record("nginx__ngx_event_openssl"))
    _start_build(h, "nginx__ngx_files", FILES_UNIT_FILES, hold=0.2)
    h.finish()
    assert all(p.returncode == 0 for p in h.procs), h.output()
    first, second = h.record("nginx__ngx_event_openssl", "end"), h.record("nginx__ngx_files", "end")
    assert (first["mem"], second["mem"]) == (_expected(OPENSSL_UNIT_FILES), _expected(FILES_UNIT_FILES)), h.output()
    assert second["start"] >= first["end"], h.output()
    assert "first build" in h.output()


OOM_GRANDCHILD = """
import json, os, sys
state, events, peak = sys.argv[1], sys.argv[2], sys.argv[3]
runs = json.load(open(state)) if os.path.exists(state) else []
runs.append(int(os.environ["FRAMAC_JOB_MEM_MB"]))
json.dump(runs, open(state, "w"))
if len(runs) == 1:
    # The cgroup OOM killer took a grandchild (Frama-C) at 9000 MiB; the build then fell back and failed.
    open(peak, "w").write(str(9000 * 1024 * 1024))
    open(events, "w").write("low 0\\nhigh 0\\nmax 3\\noom 1\\noom_kill 1\\n")
    sys.exit(1)
sys.exit(0)
"""


def test_an_oom_kill_below_the_job_is_retried_from_its_observed_peak_and_recorded(build_harness):
    h = build_harness
    h.set_pool(POOL_CPUS, POOL_MEM_MB)
    cg = h.root / "sys/fs/cgroup"
    (cg / "memory.events").write_text("low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n", encoding="utf-8")
    (cg / "memory.peak").write_text(str(100 * 1024 * 1024), encoding="utf-8")
    (h.cwd / "run-metadata.json").write_text("{}", encoding="utf-8")
    child = h.tmp / "oom_grandchild.py"
    child.write_text(OOM_GRANDCHILD, encoding="utf-8")
    state = h.tmp / "runs.json"
    proc = _run_cli(
        h,
        [
            "run",
            "--class",
            "build",
            "--key",
            "mod1",
            "--",
            sys.executable,
            str(child),
            str(state),
            str(cg / "memory.events"),
            str(cg / "memory.peak"),
        ],
        h.cwd,
    )
    runs = json.loads(state.read_text(encoding="utf-8"))
    # max(2 x 2048, 1.25 x 9000): the lease was far below what the job needed.
    assert proc.returncode == 0 and runs == [2048, 11250], proc.stderr
    assert "retrying once with 11250 MiB" in proc.stderr
    recs = [
        json.loads(p.read_text(encoding="utf-8"))
        for p in sorted((h.cwd / "state/resource-history/build").glob("*.json"))
    ]
    assert [(r["rc"], r["oom_killed"], r.get("oom_evidence")) for r in recs] == [(1, True, "alone"), (0, False, None)]
    assert recs[0]["peak_mb"] == 9000 and recs[0]["oom_kills_during"] == 1
    assert R.history_estimate(h.cwd, "build", "mod1") == 18000  # the next lease doubles the OOM-killed peak


@pytest.mark.parametrize(
    ("rc", "kills", "single", "peak", "lease", "evidence"),
    [
        (137, 1, False, None, 2048, "sigkill"),
        (-9, 1, False, 500, 2048, "sigkill"),
        (1, 1, True, None, 2048, "alone"),
        (1, 1, False, 8760, 2048, "overran_lease"),  # run-3: 8.76 GB under a 2 GiB lease
        (1, 1, False, 1500, 2048, None),  # stayed within its lease: the neighbour's OOM, not this job's
        (1, 1, False, None, 2048, None),  # no peak of its own (no rusage) and not alone: unknown
        (137, 0, True, 9000, 2048, None),  # SIGKILL without an OOM kill in the cgroup: not an OOM
        (0, None, True, 9000, 2048, None),  # no memory.events (cgroup v1 without oom_kill, macOS)
    ],
)
def test_oom_evidence_is_charged_only_to_a_job_that_could_have_caused_it(rc, kills, single, peak, lease, evidence):
    before = {"oom_kill": 0 if kills is not None else None}
    after = {"oom_kill": kills}
    assert R.oom_evidence(rc, before, after, single=single, peak_mb=peak, lease_mb=lease) == evidence


def test_retry_memory_is_grounded_in_the_observed_peak_and_capped_at_the_pool():
    lease = R.Lease("x", "build", "k", 4.0, 2048, None, True, 1, True, POOL_CPUS, POOL_MEM_MB)
    assert R.retry_memory(lease, None) == 4096
    assert R.retry_memory(lease, 1000) == 4096
    assert R.retry_memory(lease, 8760) == 10950
    assert R.retry_memory(lease, 17173) == POOL_MEM_MB


def test_history_run_dir_falls_back_to_the_container_run_dir(tmp_path, monkeypatch):
    """A parse lease runs with the scratch tree as its cwd; its record still lands in the run dir."""
    run = tmp_path / "framac-run"
    run.mkdir()
    tree = tmp_path / "tree"
    tree.mkdir()
    monkeypatch.setattr(R, "CONTAINER_RUN_DIR", run)
    monkeypatch.chdir(tree)
    assert R.history_run_dir() is None
    (run / "run-metadata.json").write_text("{}", encoding="utf-8")
    assert R.history_run_dir() == run
    (tree / "run-metadata.json").write_text("{}", encoding="utf-8")
    assert R.history_run_dir() == tree
