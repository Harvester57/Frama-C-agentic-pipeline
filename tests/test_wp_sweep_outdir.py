"""
`pipeline_make.sweep` runs one `run_wp_function.py` per swept function in parallel. Since
run_wp_function takes an exclusive lock on its `--out-dir` (reason `out_dir_locked`, rc=1, no
report), two functions of the same source file must never share an out-dir: on nanopb run-1 the
shared per-file `wp-sweep/work/pb_encode.c` made all but one function of the file come back with no
report, the sweep went `incomplete` and the ledger turned proved units `blocked`.
"""

from __future__ import annotations

import threading
from pathlib import Path, PurePosixPath

import pipeline_make as pm
from conftest import unit, write_json
from test_pipeline_make import ACSL, _make_run, _wp_ev

# Two WP-covered functions of the same file, plus a same-named (static) function in another file.
_SWEPT = [
    ("src/snmp/ber.c", "ber_decode"),
    ("src/snmp/ber.c", "ber_length"),
    ("src/snmp/pdu.c", "ber_length"),
]


def _same_file_ledger(run: Path) -> None:
    write_json(
        run / "coverage-ledger.json",
        [unit(f, fn, "rte", status="covered", module="snmp", evidence=[_wp_ev()]) for f, fn in _SWEPT],
    )


def _arg(cmd: list[str], flag: str) -> str:
    return cmd[cmd.index(flag) + 1]


def _no_ledger(script: str, args: list[str]) -> tuple[int, str]:
    return 0, "{}"


def test_sweep_gives_each_function_its_own_out_dir(tmp_path):
    run = _make_run(tmp_path)
    _same_file_ledger(run)
    out_dirs: dict[tuple[str, str], str] = {}
    guard = threading.Lock()

    def fake(cmd, log_rel):
        out_json = _arg(cmd, "--out-json")
        fn = _arg(cmd, "--function")
        src = _arg(cmd, "--file").removeprefix(f"{pm.WORK_DIR}/")
        with guard:
            out_dirs[(src, fn)] = _arg(cmd, "--out-dir")
        write_json(run / out_json, {"function": fn, "status": "all_proven"})
        return 0

    summary = pm.sweep(run, jobs=1, runner=fake, plan=pm.build_plan(run, templates_dir=ACSL), script_runner=_no_ledger)

    assert sorted(out_dirs) == sorted(_SWEPT), summary
    # Same file, different functions: different out-dirs (run_wp_function locks its out-dir).
    assert out_dirs[("src/snmp/ber.c", "ber_decode")] != out_dirs[("src/snmp/ber.c", "ber_length")]
    # Same function name in two files (statics): the file slug still separates them.
    assert out_dirs[("src/snmp/ber.c", "ber_length")] != out_dirs[("src/snmp/pdu.c", "ber_length")]
    assert len(set(out_dirs.values())) == len(_SWEPT)
    for d in out_dirs.values():
        assert PurePosixPath(d).is_relative_to(f"{pm.SWEEP_DIR}/work")
    # No out-dir nests inside another one.
    for a in out_dirs.values():
        for b in out_dirs.values():
            assert a == b or not PurePosixPath(a).is_relative_to(b)


def test_parallel_sweep_survives_the_out_dir_lock(tmp_path):
    # A runner that behaves like run_wp_function's out-dir lock: a second live job on a held
    # out-dir fails with rc=1 and writes no report. Every job holds its lock until all jobs started,
    # so the jobs overlap deterministically.
    run = _make_run(tmp_path)
    _same_file_ledger(run)
    guard = threading.Lock()
    held: set[str] = set()
    started = [0]
    all_started = threading.Event()
    refused: list[str] = []

    def locking_runner(cmd, log_rel):
        out_dir = _arg(cmd, "--out-dir")
        with guard:
            started[0] += 1
            if started[0] == len(_SWEPT):
                all_started.set()
            if out_dir in held:
                refused.append(_arg(cmd, "--function"))
                return 1  # reason: out_dir_locked, no report
            held.add(out_dir)
        try:
            all_started.wait(timeout=5)
            write_json(run / _arg(cmd, "--out-json"), {"function": _arg(cmd, "--function"), "status": "all_proven"})
            return 0
        finally:
            with guard:
                held.discard(out_dir)

    summary = pm.sweep(
        run,
        jobs=len(_SWEPT),
        runner=locking_runner,
        plan=pm.build_plan(run, templates_dir=ACSL),
        script_runner=_no_ledger,
    )

    assert refused == []
    assert summary["missing"] == [] and summary["status"] == "ok" and summary["ok"] is True
    assert summary["total"] == summary["proven"] == len(_SWEPT)
    assert not (run / pm.SWEEP_DIR / "missing").exists()
