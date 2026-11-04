"""Contract tests for the stable resources.py API that the other pipeline scripts depend on."""

from __future__ import annotations

from pathlib import Path

import resources as R


def _cgroup_tree(
    root: Path,
    cpu_max: str | None = None,
    mem_max: str | None = None,
    cpuset: str | None = None,
    mem_available_kb: int | None = None,
) -> Path:
    cg = root / "sys/fs/cgroup"
    cg.mkdir(parents=True, exist_ok=True)
    if cpu_max is not None:
        (cg / "cpu.max").write_text(cpu_max + "\n", encoding="utf-8")
    if mem_max is not None:
        (cg / "memory.max").write_text(mem_max + "\n", encoding="utf-8")
    if cpuset is not None:
        (cg / "cpuset.cpus.effective").write_text(cpuset + "\n", encoding="utf-8")
    if mem_available_kb is not None:
        (root / "proc").mkdir(parents=True, exist_ok=True)
        (root / "proc/meminfo").write_text(
            f"MemTotal:       {mem_available_kb * 2} kB\nMemAvailable:   {mem_available_kb} kB\n",
            encoding="utf-8",
        )
    return root


def test_parse_helpers():
    assert R.parse_mem("8g") == 8192 and R.parse_mem("512m") == 512 and R.parse_mem("1024") == 1024
    assert R.parse_mem("2GiB") == 2048 and R.parse_mem("bogus") is None and R.parse_mem(None) is None
    assert R.parse_cpu_list("0-3,8,10-11") == [0, 1, 2, 3, 8, 10, 11]
    assert R.parse_cpu_list("") == []


def test_job_budget_is_the_minimum_of_grant_cgroup_and_os(tmp_path, monkeypatch):
    monkeypatch.delenv("FRAMAC_JOB_CPUS", raising=False)
    monkeypatch.delenv("FRAMAC_JOB_MEM_MB", raising=False)
    root = _cgroup_tree(tmp_path, cpu_max="250000 100000", mem_max=str(3 * 1024**3), mem_available_kb=16 * 1024 * 1024)
    b = R.job_budget(root)
    assert (b.cpus, b.mem_mb) == (2, 3072) and "cgroup" in b.source

    # The broker's grant wins when it is smaller...
    monkeypatch.setenv("FRAMAC_JOB_CPUS", "1")
    monkeypatch.setenv("FRAMAC_JOB_MEM_MB", "1500")
    assert (R.job_budget(root).cpus, R.job_budget(root).mem_mb) == (1, 1500)
    # ...but a stale, larger grant can never exceed what the cgroup now allows.
    monkeypatch.setenv("FRAMAC_JOB_CPUS", "16")
    monkeypatch.setenv("FRAMAC_JOB_MEM_MB", "64000")
    assert (R.job_budget(root).cpus, R.job_budget(root).mem_mb) == (2, 3072)


def test_job_budget_without_limits_uses_cpuset_and_meminfo(tmp_path, monkeypatch):
    monkeypatch.delenv("FRAMAC_JOB_CPUS", raising=False)
    monkeypatch.delenv("FRAMAC_JOB_MEM_MB", raising=False)
    root = _cgroup_tree(tmp_path, cpu_max="max 100000", mem_max="max", cpuset="0-2", mem_available_kb=4 * 1024 * 1024)
    b = R.job_budget(root)
    assert b.cpus <= 3 and b.mem_mb == 4096


def test_parallelism_scales_with_budget_while_limits_stay_fixed():
    assert R.WP_MEMLIMIT_MB == 1000 and R.FUZZ_RSS_LIMIT_MB == 2048
    small, big = R.Budget(2, 3072, "t"), R.Budget(64, 256_000, "t")
    assert R.wp_parallelism(small) == 2 and R.wp_parallelism(big) == 64
    assert R.wp_parallelism(R.Budget(16, 2048, "t")) == 1  # memory-bound, never oversubscribed
    assert R.fuzz_workers(small) == 1 and R.fuzz_workers(big) == 64
    assert R.fuzz_workers(R.Budget(32, 8192, "t")) == 3


def test_recommend_derives_agents_and_make_jobs_from_the_pool(monkeypatch):
    monkeypatch.delenv("FRAMAC_MAX_AGENTS", raising=False)
    rec = R.recommend(pool=R.Budget(12, 32_000, "t"))
    # 12 CPUs x duty 2 / 4 CPUs per WP job = 6 agents; memory would allow 13.
    assert rec["make_jobs"] == 12 and rec["max_agents"] == 6
    # Memory-bound: 4 GB only supports one WP job at a time even with many CPUs.
    assert R.recommend(pool=R.Budget(64, 4_000, "t"))["max_agents"] == 1
    assert rec["fixed_limits"] == {"wp_memlimit_mb": 1000, "fuzz_rss_limit_mb": 2048}
    assert set(rec["classes"]) == set(R.CLASSES)
    assert R.recommend(pool=R.Budget(16, 64_000, "t"))["max_agents"] == 16
    assert R.recommend(pool=R.Budget(32, 128_000, "t"))["max_agents"] == 32
    assert R.recommend(pool=R.Budget(128, 512_000, "t"))["max_agents"] == 64  # scaled cap on >=64 CPUs
    assert R.recommend(max_agents=3, pool=R.Budget(128, 512_000, "t"))["max_agents"] == 3
    assert R.recommend(pool=R.Budget(1, 1024, "t"))["max_agents"] == 1


def test_recommend_reads_the_pool_passed_by_the_host_broker(monkeypatch, tmp_path):
    monkeypatch.setenv("FRAMAC_POOL_CPUS", "24")
    monkeypatch.setenv("FRAMAC_POOL_MEM_MB", "96000")
    rec = R.recommend()
    assert rec["pool"]["cpus"] == 24 and rec["make_jobs"] == 24

    # Inside a light container (1 CPU / 1024 MiB lease) when FRAMAC_POOL_* is absent, pool_budget()
    # falls back to run-metadata.json's resources.pool so max_agents is not clamped to 1.
    monkeypatch.delenv("FRAMAC_POOL_CPUS", raising=False)
    monkeypatch.delenv("FRAMAC_POOL_MEM_MB", raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "run-metadata.json").write_text(
        '{"resources": {"cpus": 1, "mem_mb": 1024, "pool": {"cpus": 12, "mem_mb": 32000, "source": "host broker"}}}',
        encoding="utf-8",
    )
    monkeypatch.setattr(R, "in_container", lambda root=Path("/"): True)
    assert R.pool_budget().cpus == 12 and R.pool_budget().mem_mb == 32000
    assert R.recommend()["max_agents"] == 6


def test_broker_granted_light_container_does_not_emit_false_cgroup_throttle_warnings(tmp_path, monkeypatch):
    root = _cgroup_tree(
        tmp_path,
        cpu_max="100000 100000",
        mem_max=str(1024 * 1024**2),
        mem_available_kb=12 * 1024 * 1024,
    )
    monkeypatch.setattr(R, "machine_cpus", lambda _root=Path("/"): (12, list(range(12))))
    monkeypatch.setenv("FRAMAC_POOL_CPUS", "11")
    monkeypatch.setenv("FRAMAC_POOL_MEM_MB", "20480")

    # 1. With matching broker grant (FRAMAC_JOB_CPUS=1, FRAMAC_JOB_MEM_MB=1024), cgroup == grant is expected.
    monkeypatch.setenv("FRAMAC_JOB_CPUS", "1")
    monkeypatch.setenv("FRAMAC_JOB_MEM_MB", "1024")
    p_granted = R.probe("container", root=root, fresh=True)
    assert not any("throttled to" in w or "capped at" in w for w in p_granted.warnings)

    # 2. Without a broker grant (unbrokered container throttled to 1 CPU / 1024 MiB on a 12-CPU / 24-GiB host), warn.
    monkeypatch.delenv("FRAMAC_JOB_CPUS", raising=False)
    monkeypatch.delenv("FRAMAC_JOB_MEM_MB", raising=False)
    p_unbrokered = R.probe("container", root=root, fresh=True)
    assert any("cgroup CPU limit (1 CPUs) is much smaller" in w for w in p_unbrokered.warnings)
    assert any("cgroup memory limit (1024 MiB) is much smaller" in w for w in p_unbrokered.warnings)

    # 3. If an external cgroup throttles a container below its broker grant, warn.
    monkeypatch.setenv("FRAMAC_JOB_CPUS", "4")
    monkeypatch.setenv("FRAMAC_JOB_MEM_MB", "4096")
    p_throttled = R.probe("container", root=root, fresh=True)
    assert any("cgroup CPU limit (1 CPUs) is much smaller" in w for w in p_throttled.warnings)
    assert any("cgroup memory limit (1024 MiB) is much smaller" in w for w in p_throttled.warnings)


def test_infer_class_maps_commands_to_classes():
    S = "python3 /opt/framac-pipeline/scripts"
    cases = {
        f"{S}/run_wp_function.py --file a.c --function f --out-json x.json": "wp",
        f"{S}/run_eva_slice.py --sources a.c --main eva_main --out-dir o --out-json x": "eva",
        f"{S}/run_eacsl_fuzz.py campaign --module m --sources a.c": "fuzz",
        f"{S}/run_eacsl_fuzz.py guardrail --sources a.c": "guardrail",
        f"{S}/run_eacsl_fuzz.py build --module m": "build",
        f"{S}/run_eacsl_fuzz.py replay-candidates --candidates candidates.json": "replay",
        f"{S}/run_eacsl_fuzz.py selftest": "selftest",
        f"{S}/workspace_overlay.py merge-batch --agents a b": "verify",
        f"{S}/wp_scheduler.py merge-pending": "verify",
        f"{S}/wp_scheduler.py next --slots auto --prepare": "light",
        f"{S}/pipeline_make.py run build eva": "phase-static",
        f"{S}/pipeline_make.py run fuzz": "phase-dynamic",
        f"{S}/pipeline_make.py run fuzz-snmp": "phase-dynamic",
        f"{S}/pipeline_make.py run --jobs 4 build-snmp eva-snmp": "phase-static",
        f"{S}/pipeline_make.py --run-dir . run fuzz-snmp": "phase-dynamic",
        f"{S}/pipeline_make.py --run-dir . run build-snmp": "phase-static",
        f"{S}/pipeline_make.py sweep --jobs 4": "phase-static",
        f"{S}/pipeline_make.py run module-snmp": "phase-dynamic",
        f"{S}/build_callgraph_dag.py --root workspace/work": "eva",
        f"{S}/extract_references.py --check": "build",
        "python3 $S/run_wp_function.py --file a.c --function f --out-json x.json": "wp",
        "python3 ${S}/pipeline_make.py run build": "phase-static",
        "e-acsl-gcc.sh -c -o a.i.c -O a.e-acsl a.c": "build",
        "clang -fsanitize=fuzzer,address,undefined harness.c -o fuzz_m": "build",
        f"{S}/ledger.py ingest-wp workspace/reports/wp/f.json": "light",
        # Ad-hoc heavy commands are not left in the 1-CPU light class.
        f"{S}/sandbox_exec.py run --writable workspace/build-scratch --cwd workspace/build-scratch -- bear -- make -j8": "phase-dynamic",
        f"{S}/sandbox_exec.py run --cwd b -- /usr/bin/cmake --build build": "phase-dynamic",
        f"{S}/sandbox_exec.py run --cwd s -- ./fuzz_m crash-1": "replay",
        "frama-c -machdep gcc_x86_64 -kernel-warn-key annot-error=abort agents/a/scratch/work/m.c": "eva",
        "cd /framac-run && /usr/local/bin/frama-c -print a.c": "eva",
        "cat /opt/frama-c/share/README": "light",
    }
    for cmd, expected in cases.items():
        assert R.infer_class(cmd) == expected, cmd
    assert all(not R.CLASSES[c].runs_target_code for c in ("light", "wp", "eva", "build", "phase-static"))
    assert all(
        R.CLASSES[c].runs_target_code for c in ("fuzz", "guardrail", "replay", "selftest", "verify", "phase-dynamic")
    )
