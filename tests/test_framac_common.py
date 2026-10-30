from framac_common import (
    STATUS_ASSUMED,
    STATUS_DEAD,
    STATUS_INVALID,
    STATUS_OTHER,
    STATUS_UNKNOWN,
    STATUS_VALID,
    STATUS_VALID_UNDER_HYP,
    is_safe_agent_id,
    is_safe_relative_path,
    normalize_status,
    read_report_csv,
)


def test_status_spellings_from_different_frama_c_releases():
    assert normalize_status("Valid") == STATUS_VALID
    assert normalize_status("Valid under hyp.") == STATUS_VALID_UNDER_HYP
    assert normalize_status("Valid_under_hyp") == STATUS_VALID_UNDER_HYP
    assert normalize_status("Unknown") == STATUS_UNKNOWN
    assert normalize_status("Invalid") == STATUS_INVALID
    # Frama-C 33's report CSV spells Eva's red alarm and plain dead code this way.
    assert normalize_status("Invalid or unreachable") == STATUS_INVALID
    assert normalize_status("Dead") == STATUS_DEAD
    assert normalize_status("Invalid but dead") == STATUS_DEAD
    assert normalize_status("Invalid_but_dead") == STATUS_DEAD
    assert normalize_status("Considered valid") == STATUS_ASSUMED
    assert normalize_status("weird") == STATUS_OTHER


def test_report_csv_with_current_and_legacy_headers(tmp_path):
    current = tmp_path / "current.csv"
    current.write_text(
        "directory\tfile\tline\tfunction\tproperty kind\tstatus\tproperty\n"
        "src\tber.c\t42\tber_len\tassertion\tUnknown\tmem_access: \\valid_read(p)\n"
        "src\tber.c\t50\tber_len\tassertion\tInvalid but dead\tdivision_by_zero: d != 0\n",
        encoding="utf-8",
    )
    rows = read_report_csv(current)
    assert rows[0]["kind"] == "assertion"
    assert rows[0]["property"].startswith("mem_access")
    assert rows[0]["status"] == STATUS_UNKNOWN and rows[0]["line"] == 42
    assert rows[1]["status"] == STATUS_DEAD

    legacy = tmp_path / "legacy.csv"
    legacy.write_text("file\tline\tfunction\tkind\tstatus\tannotation\nx.c\t1\tf\tassigns\tValid\tassigns \\nothing\n", encoding="utf-8")
    row = read_report_csv(legacy)[0]
    assert row["kind"] == "assigns" and row["property"] == "assigns \\nothing" and row["status"] == STATUS_VALID


def test_safe_paths_and_agent_ids():
    assert is_safe_relative_path("workspace/reports/eva/x.json")
    for bad in ("", "/abs", "C:/x", "a/../b", "a\\b", "./a", "aux/x", " a"):
        assert not is_safe_relative_path(bad), bad
    assert is_safe_agent_id("prover-ber-len-1")
    assert not is_safe_agent_id("Prover")
    assert not is_safe_agent_id("con")


def test_run_lock_excludes_other_processes_and_breaks_stale_locks(tmp_path):
    import os
    import subprocess
    import sys
    import time

    import pytest

    from conftest import ROOT
    from framac_common import RunLockTimeout, run_lock

    marker = tmp_path / "holder_has_lock"
    holder = subprocess.Popen(
        [sys.executable, "-c",
         "import pathlib, sys, time\n"
         "from framac_common import run_lock\n"
         "with run_lock('ledger', pathlib.Path(sys.argv[1])):\n"
         "    pathlib.Path(sys.argv[2]).write_text('1')\n"
         "    time.sleep(1.5)\n",
         str(tmp_path), str(marker)],
        env={**os.environ, "PYTHONPATH": str(ROOT / "scripts")},
    )
    try:
        deadline = time.time() + 30
        while not marker.exists() and time.time() < deadline:
            time.sleep(0.05)
        assert marker.exists(), "holder never acquired the lock"
        with pytest.raises(RunLockTimeout):
            with run_lock("ledger", tmp_path, timeout=0.3):
                pass
        with run_lock("ledger", tmp_path, timeout=30):
            assert holder.poll() is not None  # acquired only after the holder released it
    finally:
        holder.wait(timeout=30)

    # A lock whose heartbeat stopped long ago belongs to a dead holder and is broken.
    stale = tmp_path / ".framac-locks" / "merge.lock"
    stale.mkdir(parents=True)
    (stale / "owner.json").write_text("{}", encoding="utf-8")
    old = time.time() - 3600
    os.utime(stale / "owner.json", (old, old))
    with run_lock("merge", tmp_path, timeout=1, stale_after=60) as lock_dir:
        assert lock_dir == stale and (lock_dir / "owner.json").stat().st_mtime > old
    assert not (tmp_path / ".framac-locks").exists()
