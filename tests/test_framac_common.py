import shlex

import pytest

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
    scratch_first_cppflags,
    scratch_first_flags,
    source_tree_relpath,
)


def test_status_spellings_from_different_frama_c_releases():
    assert normalize_status("Valid") == STATUS_VALID
    assert normalize_status("Partially proven") == STATUS_VALID
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
    legacy.write_text(
        "file\tline\tfunction\tkind\tstatus\tannotation\nx.c\t1\tf\tassigns\tValid\tassigns \\nothing\n",
        encoding="utf-8",
    )
    row = read_report_csv(legacy)[0]
    assert row["kind"] == "assigns" and row["property"] == "assigns \\nothing" and row["status"] == STATUS_VALID


def test_safe_paths_and_agent_ids():
    assert is_safe_relative_path("workspace/reports/eva/x.json")
    for bad in ("", "/abs", "C:/x", "a/../b", "a\\b", "./a", " a"):
        assert not is_safe_relative_path(bad), bad
    assert is_safe_relative_path("aux/x")
    assert is_safe_agent_id("prover-ber-len-1")
    assert not is_safe_agent_id("Prover")
    assert not is_safe_agent_id("con")
    assert not is_safe_agent_id("aux")


@pytest.fixture
def scratch_tree(tmp_path):
    """(run_dir, work_dir) of an agent whose scratch copy holds inc/, inc/nest/ and src/."""
    run_dir = tmp_path / "run"
    work = run_dir / "agents" / "a1" / "scratch" / "work"
    (work / "inc" / "nest").mkdir(parents=True)
    (work / "src").mkdir()
    (work / "inc" / "cfg.h").write_text("", encoding="utf-8")
    return run_dir, work


@pytest.mark.parametrize(
    "path, expected",
    [
        ("workspace/work/inc/a.h", "inc/a.h"),
        ("./workspace/work/src/../inc/a.h", "inc/a.h"),
        ("/framac-run/workspace/work/inc/a.h", "inc/a.h"),
        ("/framac-run/workspace/work/src/../inc/a.h", "inc/a.h"),
        ("agents/a1/scratch/work/inc/a.h", "inc/a.h"),
        ("agents/other/scratch/work/inc/a.h", "inc/a.h"),
        ("/target/inc/a.h", "inc/a.h"),
        ("workspace/stubs/a.h", None),
        ("workspace/work/../stubs/a.h", None),
        ("workspace/baseline/inc/a.h", None),
        ("agents/a1/scratch/base/inc/a.h", None),
        ("/usr/include/stdio.h", None),
        ("a.h", None),
        ("<built-in>", None),
        ("", None),
    ],
)
def test_source_tree_relpath(scratch_tree, path, expected):
    run_dir, work = scratch_tree
    assert source_tree_relpath(path, run_dir, work) == expected


def test_source_tree_relpath_of_an_absolute_path_in_the_scratch_copy(scratch_tree):
    run_dir, work = scratch_tree
    assert source_tree_relpath((work / "inc" / "a.h").as_posix(), run_dir, work) == "inc/a.h"


SCRATCH = "agents/a1/scratch/work"


@pytest.mark.parametrize(
    "flags, expected",
    [
        # Every shared include directory gets its twin right before it; the rest keeps its place.
        (
            ["-I.", "-Iworkspace/work/inc/nest", "-Iworkspace/work/inc", "-Iworkspace/stubs", "-Iworkspace/work/src"],
            [
                "-I.",
                f"-I{SCRATCH}/inc/nest",
                "-Iworkspace/work/inc/nest",
                f"-I{SCRATCH}/inc",
                "-Iworkspace/work/inc",
                "-Iworkspace/stubs",
                f"-I{SCRATCH}/src",
                "-Iworkspace/work/src",
            ],
        ),
        (
            ["-I", "workspace/work/src", "-DX", "-Iworkspace/work/gone"],
            [f"-I{SCRATCH}/src", "-I", "workspace/work/src", "-DX", "-Iworkspace/work/gone"],
        ),
        # The search order goes by option, so a twin keeps the option of its directory.
        (["-iquote", "workspace/work/inc"], [f"-iquote{SCRATCH}/inc", "-iquote", "workspace/work/inc"]),
        (["-iquoteworkspace/work/inc"], [f"-iquote{SCRATCH}/inc", "-iquoteworkspace/work/inc"]),
        (["-isystem", "workspace/work/inc"], [f"-isystem{SCRATCH}/inc", "-isystem", "workspace/work/inc"]),
        (["-isystemworkspace/work/inc"], [f"-isystem{SCRATCH}/inc", "-isystemworkspace/work/inc"]),
        (["-idirafter", "workspace/work/inc"], [f"-idirafter{SCRATCH}/inc", "-idirafter", "workspace/work/inc"]),
        (["-idirafterworkspace/work/inc"], [f"-idirafter{SCRATCH}/inc", "-idirafterworkspace/work/inc"]),
        # Every spelling of a shared directory that real sidecars and DAGs use.
        (["-I/framac-run/workspace/work/inc"], [f"-I{SCRATCH}/inc", "-I/framac-run/workspace/work/inc"]),
        (["-I/framac-run/workspace/work/src/../inc"], [f"-I{SCRATCH}/inc", "-I/framac-run/workspace/work/src/../inc"]),
        (["-Iworkspace/work/src/../inc"], [f"-I{SCRATCH}/inc", "-Iworkspace/work/src/../inc"]),
        (["-I./workspace/work/inc/"], [f"-I{SCRATCH}/inc", "-I./workspace/work/inc/"]),
        (["-I/target/inc"], [f"-I{SCRATCH}/inc", "-I/target/inc"]),
        (["-Iworkspace/work"], [f"-I{SCRATCH}", "-Iworkspace/work"]),
        # One twin is enough; a flag that already names the scratch copy needs none.
        (
            ["-I/framac-run/workspace/work/inc", "-Iworkspace/work/inc"],
            [f"-I{SCRATCH}/inc", "-I/framac-run/workspace/work/inc", "-Iworkspace/work/inc"],
        ),
        ([f"-I{SCRATCH}", "-I.", "-Iworkspace/work"], [f"-I{SCRATCH}", "-I.", "-Iworkspace/work"]),
        ([f"-I{SCRATCH}/inc", "-Iworkspace/work/inc"], [f"-I{SCRATCH}/inc", "-Iworkspace/work/inc"]),
        (
            ["-iquoteworkspace/work/inc", "-Iworkspace/work/inc"],
            [f"-iquote{SCRATCH}/inc", "-iquoteworkspace/work/inc", f"-I{SCRATCH}/inc", "-Iworkspace/work/inc"],
        ),
        # Force-included files are replaced: both copies would be read otherwise.
        (["-include", "workspace/work/inc/cfg.h"], ["-include", f"{SCRATCH}/inc/cfg.h"]),
        (["-includeworkspace/work/inc/cfg.h"], [f"-include{SCRATCH}/inc/cfg.h"]),
        (["-imacros", "workspace/work/inc/cfg.h"], ["-imacros", f"{SCRATCH}/inc/cfg.h"]),
        (["-imacrosworkspace/work/inc/cfg.h"], [f"-imacros{SCRATCH}/inc/cfg.h"]),
        (["-include", "/framac-run/workspace/work/src/../inc/cfg.h"], ["-include", f"{SCRATCH}/inc/cfg.h"]),
        (["-include", "/target/inc/cfg.h"], ["-include", f"{SCRATCH}/inc/cfg.h"]),
        # Not under a source tree, found through the search chain, or with no twin: as written.
        (["-include", "workspace/harnesses/compat.h"], ["-include", "workspace/harnesses/compat.h"]),
        (["-include", "cfg.h"], ["-include", "cfg.h"]),
        (["-include", "workspace/work/inc/gone.h"], ["-include", "workspace/work/inc/gone.h"]),
        (["-imacros", "/opt/x.h"], ["-imacros", "/opt/x.h"]),
        # Options with no value, and options the walk does not know.
        (["-Iworkspace/work/inc", "-I"], [f"-I{SCRATCH}/inc", "-Iworkspace/work/inc", "-I"]),
        (["-include"], ["-include"]),
        (["-DPATH=workspace/work/inc", "-std=c11", "-O2"], ["-DPATH=workspace/work/inc", "-std=c11", "-O2"]),
    ],
)
def test_scratch_first_flags(scratch_tree, flags, expected):
    run_dir, work = scratch_tree
    assert scratch_first_flags(flags, run_dir, work) == expected


def test_scratch_first_flags_is_idempotent_and_a_no_op_on_the_shared_tree(scratch_tree):
    run_dir, work = scratch_tree
    flags = ["-Iworkspace/work/inc", "-iquote", "workspace/work/src", "-include", "workspace/work/inc/cfg.h"]
    once = scratch_first_flags(flags, run_dir, work)
    assert scratch_first_flags(once, run_dir, work) == once

    shared = run_dir / "workspace" / "work"
    (shared / "inc").mkdir(parents=True)
    (shared / "inc" / "cfg.h").write_text("", encoding="utf-8")
    assert scratch_first_flags(["-Iworkspace/work/inc", "-Iworkspace/work"], run_dir, shared) == [
        "-Iworkspace/work/inc",
        "-Iworkspace/work",
    ]
    assert scratch_first_flags(["-include", "workspace/work/inc/cfg.h"], run_dir, shared) == [
        "-include",
        "workspace/work/inc/cfg.h",
    ]


def test_scratch_first_cppflags_keeps_the_words_it_does_not_change(scratch_tree):
    run_dir, work = scratch_tree
    # Re-quoting these would change what they mean inside the brief's single-quoted --cppflags.
    flags = r"""-DNAME=\"x\" -DTITLE="a b" -DEMPTY="" -Iworkspace/work/inc -include workspace/harnesses/c.h"""
    assert scratch_first_cppflags(flags, run_dir, work) == (
        r"""-DNAME=\"x\" -DTITLE="a b" -DEMPTY="" """
        f"-I{SCRATCH}/inc -Iworkspace/work/inc -include workspace/harnesses/c.h"
    )
    assert scratch_first_cppflags("", run_dir, work) == ""
    assert scratch_first_cppflags("-I.  \t -DX", run_dir, work) == "-I. -DX"


def test_scratch_first_cppflags_reads_a_quoted_include_flag(scratch_tree):
    run_dir, work = scratch_tree
    assert scratch_first_cppflags('"-Iworkspace/work/inc"', run_dir, work) == (
        f'-I{SCRATCH}/inc "-Iworkspace/work/inc"'
    )
    assert scratch_first_cppflags("-iquote 'workspace/work/inc'", run_dir, work) == (
        f"-iquote{SCRATCH}/inc -iquote 'workspace/work/inc'"
    )
    # A twin that needs quoting stays one word, and double quotes survive the brief's single quotes.
    (work / "my dir").mkdir()
    flags = '-I"workspace/work/my dir"'
    rendered = scratch_first_cppflags(flags, run_dir, work)
    assert rendered == f'"-I{SCRATCH}/my dir" {flags}'
    assert shlex.split(rendered) == [f"-I{SCRATCH}/my dir", "-Iworkspace/work/my dir"]


@pytest.mark.parametrize(
    "flags", ['-Iworkspace/work/inc -DX="oops', "-Iworkspace/work/inc -DX=\\", "-Iworkspace/work/inc 'a"]
)
def test_scratch_first_cppflags_leaves_broken_quoting_alone(scratch_tree, flags):
    run_dir, work = scratch_tree
    assert scratch_first_cppflags(flags, run_dir, work) == flags


def test_run_lock_excludes_other_processes_and_breaks_stale_locks(tmp_path):
    import os
    import subprocess
    import sys
    import time

    from conftest import ROOT
    from framac_common import RunLockTimeout, run_lock

    marker = tmp_path / "holder_has_lock"
    holder = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import pathlib, sys, time\n"
            "from framac_common import run_lock\n"
            "with run_lock('ledger', pathlib.Path(sys.argv[1])):\n"
            "    pathlib.Path(sys.argv[2]).write_text('1')\n"
            "    time.sleep(1.5)\n",
            str(tmp_path),
            str(marker),
        ],
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
            holder.wait(timeout=10)
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


def test_augment_framac_cppflags_prepends_fc_stubs_and_compat_types(monkeypatch, tmp_path):
    from framac_common import augment_framac_cppflags

    stubs = tmp_path / "templates" / "fc_stubs"
    stubs.mkdir(parents=True)
    compat = stubs / "fc_compat_types.h"
    compat.write_text("/* compat */", encoding="utf-8")

    import framac_common

    monkeypatch.setattr(framac_common, "resolve_fc_stubs_dir", lambda: stubs)

    user_flags = "-Iworkspace/include -DDEBUG_LEVEL=2 -Ianother/dir"
    augmented = augment_framac_cppflags(user_flags)

    stubs_posix = stubs.as_posix()
    compat_posix = compat.as_posix()

    assert f"-I{stubs_posix}" in augmented
    assert f"-include {compat_posix}" in augmented
    assert user_flags in augmented

    # Verify prepending: stubs and compat header must appear BEFORE user flags
    stubs_idx = augmented.index(f"-I{stubs_posix}")
    compat_idx = augmented.index(f"-include {compat_posix}")
    user_idx = augmented.index("-Iworkspace/include")

    assert stubs_idx < user_idx, "fc_stubs must precede user include flags"
    assert compat_idx < user_idx, "fc_compat_types.h must precede user include flags"
    assert stubs_idx < compat_idx

    # Idempotent when already present
    aug_again = augment_framac_cppflags(augmented)
    assert aug_again.count(f"-I{stubs_posix}") == 1
    assert aug_again.count("fc_compat_types.h") == 1


def test_fc_compat_types_guards_and_float_fallbacks():
    from conftest import ROOT

    compat_path = ROOT / "templates" / "fc_stubs" / "fc_compat_types.h"
    assert compat_path.is_file()
    text = compat_path.read_text(encoding="utf-8")

    # Guard check
    assert "#ifndef __FC_COMPAT_INT_TYPES_DEFINED" in text
    assert "#define __FC_COMPAT_INT_TYPES_DEFINED 1" in text

    # Float fallback checks under __FRAMAC__
    for flt in ("_Float32", "_Float64", "_Float32x", "_Float64x", "_Float128"):
        assert f"#ifndef {flt}" in text, f"Missing guard for {flt}"
        expected_type = "float" if flt == "_Float32" else "double"
        assert f"#define {flt} {expected_type}" in text, f"Missing define for {flt}"


def test_bsd_string_contracts_include_from_dependencies():
    from conftest import ROOT

    bsd_path = ROOT / "templates" / "fc_stubs" / "bsd" / "string.h"
    assert bsd_path.is_file()
    text = bsd_path.read_text(encoding="utf-8")

    # strlcpy contract checks
    assert "assigns dst[0 .. size - 1] \\from src[0 .. size - 1], size;" in text
    assert "assigns \\result \\from src[0 .. size - 1], size;" in text

    # strlcat contract checks
    assert "assigns dst[0 .. size - 1] \\from dst[0 .. size - 1], src[0 .. size - 1], size;" in text
    assert "assigns \\result \\from dst[0 .. size - 1], src[0 .. size - 1], size;" in text
