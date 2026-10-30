"""Per-run caches (scripts/cache.py): keys, atomic publish, restores, LRU gc, and the E-ACSL / Eva users."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

import cache
import eacsl_toolchain as T
import run_eacsl_fuzz as R
import run_eva_slice

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
EACSL_MARKER_BYTES = b"\x7fELF...__e_acsl_assert...eacsl_store_block"
KEY_A = "a" * 64
KEY_B = "b" * 64
KEY_C = "c" * 64


def _cp(cmd, rc=0, out="", err=""):
    return subprocess.CompletedProcess(cmd, rc, stdout=out, stderr=err)


@pytest.fixture
def run(tmp_path, monkeypatch):
    """A run directory as the working directory, caches on, a fixed toolchain identity."""
    d = tmp_path / "run-1"
    d.mkdir()
    (d / "run-metadata.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.chdir(d)
    monkeypatch.setenv("FRAMAC_IMAGE_ID", "sha256:test-image")
    monkeypatch.delenv("FRAMAC_CACHE", raising=False)
    monkeypatch.delenv("FRAMAC_CACHE_MODE", raising=False)
    monkeypatch.delenv("FRAMAC_SHARED_CACHE_DIR", raising=False)
    return d


# ---------------------------------------------------------------------------
# Enablement
# ---------------------------------------------------------------------------

def test_enabled_only_in_a_run_dir_unless_forced(tmp_path, monkeypatch):
    monkeypatch.delenv("FRAMAC_CACHE", raising=False)
    monkeypatch.chdir(tmp_path)
    assert not cache.enabled()
    monkeypatch.setenv("FRAMAC_CACHE", "on")
    assert cache.enabled() and cache.wp_cache_dir() == tmp_path / "state" / "cache" / "wp"
    monkeypatch.delenv("FRAMAC_CACHE")
    (tmp_path / "run-metadata.json").write_text("{}", encoding="utf-8")
    assert cache.enabled()
    monkeypatch.setenv("FRAMAC_CACHE", "off")
    assert not cache.enabled() and cache.forced_off() and cache.wp_cache_dir() is None


# ---------------------------------------------------------------------------
# Keys: dependency manifests
# ---------------------------------------------------------------------------

def test_parse_make_deps_handles_continuations_and_escapes():
    text = "a.o: a.c /usr/include/stdio.h \\\n  inc/my\\ hdr.h gen$$.h\nb.o: b.c \\\r\n inc/b.h\n"
    assert cache.parse_make_deps(text) == ["a.c", "/usr/include/stdio.h", "inc/my hdr.h", "gen$.h", "b.c", "inc/b.h"]


def test_preprocessor_args_keep_only_what_changes_includes():
    toks = ["-fsanitize=fuzzer", "-Iinc", "-I", "other", "-DX=1", "-include", "pre.h", "-O1",
            "-imacros", "m.h", "-isystem", "sys", "-std=gnu99", "-nostdinc", "-Wall", "-UY"]
    assert cache.preprocessor_args(toks) == ["-Iinc", "-I", "other", "-DX=1", "-include", "pre.h",
                                             "-imacros", "m.h", "-isystem", "sys", "-std=gnu99", "-nostdinc", "-UY"]


def test_dependency_manifest_unions_gcc_with_framac_defines_and_clang(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for name in ("a.c", "fc_only.h", "clang_only.h"):
        (tmp_path / name).write_text(f"/* {name} */\n", encoding="utf-8")
    seen = []

    def runner(cmd, **kwargs):
        seen.append(list(cmd))
        assert kwargs["timeout"] == cache.DEPS_TIMEOUT_S
        if cmd[0] == "gcc":
            return _cp(cmd, 0, "a.o: a.c fc_only.h generated.h\n")
        return _cp(cmd, 0, "a.o: a.c clang_only.h\n")

    deps = cache.dependency_manifest(["a.c"], ["-Iinc", "-fsanitize=fuzzer"], runner=runner)
    gcc, clang = seen
    assert gcc[:3] == ["gcc", "-M", "-MG"] and "-D__FRAMAC__" in gcc and "-D__FC_MACHDEP_X86_64" in gcc
    assert clang[:3] == ["clang", "-M", "-MG"] and "-D__FRAMAC__" not in clang
    assert "-fsanitize=fuzzer" not in gcc and "-Iinc" in gcc
    files = dict(deps)
    assert set(files) == {"a.c", "fc_only.h", "clang_only.h", "generated.h"}
    assert files["generated.h"] == "missing" and len(files["fc_only.h"]) == 64
    # An incomplete manifest would make the key unsound: no manifest at all.
    assert cache.dependency_manifest(["a.c"], [], runner=lambda cmd, **kw: _cp(cmd, 1, "", "boom")) is None

    def missing_tool(cmd, **kw):
        raise FileNotFoundError(cmd[0])

    assert cache.dependency_manifest(["a.c"], [], runner=missing_tool) is None


# ---------------------------------------------------------------------------
# Store: publish, restore, single flight, gc
# ---------------------------------------------------------------------------

def _src_files(base: Path, payload: bytes) -> dict[str, Path]:
    base.mkdir(parents=True, exist_ok=True)
    binary = base / "prog"
    binary.write_bytes(payload)
    os.chmod(binary, 0o755)
    log = base / "prog.log"
    log.write_text("built\n", encoding="utf-8")
    return {"binary": binary, "compile.log": log}


def test_publish_lookup_and_restore_roundtrip(tmp_path):
    store = cache.Store(tmp_path / "cache")
    files = _src_files(tmp_path / "out", b"\x7fELF payload")
    assert store.put("eacsl-build", KEY_A, files, {"result": {"returncode": 0}}, key_material={"x": 1})
    entry = store.get("eacsl-build", KEY_A)
    assert entry is not None and entry.data == {"result": {"returncode": 0}}
    assert (entry.path / "key.json").is_file()
    assert store.get("eacsl-build", KEY_B) is None

    dest = tmp_path / "restored"
    assert cache.restore(entry, {"binary": dest / "prog", "compile.log": dest / "prog.log"})
    assert (dest / "prog").read_bytes() == b"\x7fELF payload"
    assert (dest / "prog.log").read_text(encoding="utf-8") == "built\n"
    if os.name == "posix":
        assert os.access(dest / "prog", os.X_OK)
    # Default destinations: where the files were published from.
    files["binary"].unlink()
    assert cache.restore(entry) and files["binary"].read_bytes() == b"\x7fELF payload"
    assert not list(dest.glob(".*.restore"))


def test_restore_refuses_a_corrupted_entry(tmp_path):
    store = cache.Store(tmp_path / "cache")
    store.put("eacsl-build", KEY_A, _src_files(tmp_path / "out", b"good"), {})
    entry = store.get("eacsl-build", KEY_A)
    (entry.path / "files" / "binary").write_bytes(b"evil")
    target = tmp_path / "dest" / "prog"
    target.parent.mkdir()
    target.write_bytes(b"previous")
    assert not cache.restore(entry, {"binary": target})
    assert target.read_bytes() == b"previous"
    assert not list(target.parent.glob(".*.restore"))


def test_concurrent_publish_from_threads_leaves_one_entry(tmp_path):
    store = cache.Store(tmp_path / "cache")
    barrier = threading.Barrier(8)
    results = []

    def publisher(i):
        files = _src_files(tmp_path / f"out{i}", b"same build")
        barrier.wait(timeout=10)
        results.append(store.put("eacsl-build", KEY_A, files, {"publisher": i}))

    threads = [threading.Thread(target=publisher, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert results == [True] * 8
    shard = tmp_path / "cache" / "eacsl-build" / KEY_A[:2]
    assert [p.name for p in shard.iterdir()] == [KEY_A]
    assert not [p for p in (tmp_path / "cache" / "eacsl-build").iterdir() if p.name.startswith(".tmp-")]
    assert store.get("eacsl-build", KEY_A).data["publisher"] in range(8)


def test_concurrent_publish_from_processes_leaves_one_entry(tmp_path):
    go = tmp_path / "go"
    code = (
        "import sys, time, pathlib\n"
        f"sys.path.insert(0, {str(SCRIPTS)!r})\n"
        "import cache\n"
        "base = pathlib.Path(sys.argv[1]); go = pathlib.Path(sys.argv[2]); i = sys.argv[3]\n"
        "src = base / f'src{i}'; src.mkdir(parents=True)\n"
        "(src / 'bin').write_bytes(b'same build')\n"
        "while not go.exists(): time.sleep(0.01)\n"
        f"ok = cache.Store(base / 'cache').put('eacsl-build', {KEY_A!r}, {{'binary': src / 'bin'}}, {{'p': i}})\n"
        "sys.exit(0 if ok else 1)\n"
    )
    procs = [subprocess.Popen([sys.executable, "-c", code, str(tmp_path), str(go), str(i)]) for i in range(3)]
    time.sleep(0.3)
    go.write_text("go", encoding="utf-8")
    assert [p.wait(timeout=60) for p in procs] == [0, 0, 0]
    entries = list((tmp_path / "cache" / "eacsl-build").glob("*/*"))
    assert [e.name for e in entries] == [KEY_A]


def test_single_flight_builds_each_key_once(run):
    calls = []
    out = run / "out.bin"

    def build():
        calls.append(1)
        time.sleep(0.2)
        out.write_bytes(b"built once")
        return {"returncode": 0, "binary": str(out)}

    def runner(cmd, **kwargs):
        return _cp(cmd, 0, "x.o: x.c\n")

    (run / "x.c").write_text("int x;\n", encoding="utf-8")
    results = []

    def worker():
        results.append(cache.memoize(
            "eacsl-build", {"kind": "test"}, sources=["x.c"], dep_flags=[], build=build,
            outputs=lambda r: {"binary": out}, ok=lambda r: r["returncode"] == 0, runner=runner,
        ))

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert calls == [1]
    assert sorted(r["cache"]["hit"] for r in results) == [False, True, True, True]
    assert len({r["cache"]["key"] for r in results}) == 1


def test_a_build_whose_inputs_changed_meanwhile_is_not_published(run):
    out = run / "out.bin"
    src = run / "x.c"
    src.write_text("int x;\n", encoding="utf-8")

    def build_during_merge():
        src.write_text("int x = 1;\n", encoding="utf-8")  # e.g. a merge lands in workspace/work mid-build
        out.write_bytes(b"built from the new content")
        return {"returncode": 0, "binary": str(out)}

    def memo(build):
        return cache.memoize(
            "eacsl-build", {"kind": "test"}, sources=["x.c"], dep_flags=[], build=build,
            outputs=lambda r: {"binary": out}, ok=lambda r: r["returncode"] == 0,
            runner=lambda cmd, **kw: _cp(cmd, 0, "x.o: x.c\n"),
        )

    first = memo(build_during_merge)
    assert first["cache"]["hit"] is False and "x.c" in first["cache"]["not_published"]
    assert not list((run / "state" / "cache" / "eacsl-build").glob("*/*"))
    again = memo(lambda: {"returncode": 0, "binary": str(out)})  # unchanged inputs now: published
    assert "not_published" not in again["cache"] and memo(lambda: {"returncode": 1})["cache"]["hit"] is True


def test_gc_removes_least_recently_used_entries_first(tmp_path):
    store = cache.Store(tmp_path / "cache")
    now = time.time()
    for i, key in enumerate((KEY_A, KEY_B, KEY_C)):
        blob = tmp_path / f"blob{i}"
        blob.write_bytes(b"x" * 1000)
        store.put("eacsl-build", key, {"binary": blob}, {})
        meta = store.entry_dir("eacsl-build", key) / "meta.json"
        os.utime(meta, (now - 300 + i * 100, now - 300 + i * 100))  # A oldest, C newest
    wp_file = tmp_path / "cache" / "wp" / "ab" / "goal.json"  # Frama-C's own WP cache layout
    wp_file.parent.mkdir(parents=True)
    wp_file.write_bytes(b"y" * 500)
    os.utime(wp_file, (now - 1000, now - 1000))
    store.get("eacsl-build", KEY_A)  # a hit refreshes the LRU clock: A becomes the newest

    stats = store.stats()
    assert stats["entries"] == 3 and stats["bytes"] == 3500
    assert stats["namespaces"]["wp"]["files"] == 1

    res = store.gc(max_bytes=2100)
    assert res["removed"] == 2 and res["bytes"] == 2000
    assert not wp_file.exists() and store.get("eacsl-build", KEY_B) is None
    assert store.get("eacsl-build", KEY_A) is not None and store.get("eacsl-build", KEY_C) is not None


def test_budget_is_capped_by_env_and_free_disk(tmp_path, monkeypatch):
    store = cache.Store(tmp_path)
    monkeypatch.setenv("FRAMAC_CACHE_MAX", "1M")
    assert store.budget_bytes() == 1024 * 1024
    monkeypatch.setenv("FRAMAC_CACHE_MAX", "100T")
    free = __import__("shutil").disk_usage(tmp_path).free
    assert store.budget_bytes() == int(0.25 * free)


def test_cli_stats_gc_and_clear(run, capsys):
    store = cache.run_store()
    store.put("eacsl-build", KEY_A, _src_files(run / "o", b"x" * 100), {})
    store.put("eva", KEY_B, _src_files(run / "e", b"y" * 100), {})
    assert cache.main(["stats"]) == 0
    stats = json.loads(capsys.readouterr().out)
    assert stats["enabled"] and stats["entries"] == 2 and set(stats["namespaces"]) == {"eacsl-build", "eva"}
    assert cache.main(["clear", "--ns", "eva"]) == 0
    assert json.loads(capsys.readouterr().out)["cleared"] == ["eva"]
    assert cache.main(["gc", "--max-bytes", "0"]) == 0
    assert json.loads(capsys.readouterr().out)["removed"] == 1
    assert store.stats()["entries"] == 0


def test_shared_store_is_read_after_the_run_store_and_written_only_rw(run, tmp_path, monkeypatch):
    shared_root = tmp_path / "shared"
    shared_root.mkdir()
    cache.Store(shared_root, scope="shared").put("eva", KEY_A, _src_files(tmp_path / "s", b"shared"), {"from": "shared"})
    assert cache.lookup("eva", KEY_A) is None  # FRAMAC_CACHE_MODE unset: the shared store is not used
    monkeypatch.setenv("FRAMAC_SHARED_CACHE_DIR", str(shared_root))
    monkeypatch.setenv("FRAMAC_CACHE_MODE", "ro")
    hit = cache.lookup("eva", KEY_A)
    assert hit is not None and hit.store.scope == "shared" and hit.data == {"from": "shared"}

    assert cache.publish("eva", KEY_B, _src_files(tmp_path / "r", b"run"), {"from": "run"})
    assert cache.run_store().get("eva", KEY_B) is not None
    assert cache.Store(shared_root).get("eva", KEY_B) is None  # ro: never written
    monkeypatch.setenv("FRAMAC_CACHE_MODE", "rw")
    assert cache.publish("eva", KEY_C, _src_files(tmp_path / "w", b"rw"), {"from": "run"})
    assert cache.Store(shared_root).get("eva", KEY_C) is not None


# ---------------------------------------------------------------------------
# E-ACSL and sanitizer builds
# ---------------------------------------------------------------------------

INSTRUMENTED_WITH_FALLBACK = (
    "typedef unsigned int mode_t;\n"
    "int open_fallback_1(char const *filename, int flags, mode_t mode);\n"
    "int f(char const *p) { return open_fallback_1(p, 0, 0); }\n"
)


class FakeToolchain:
    """e-acsl-gcc stages, the fallback-object compile, and `gcc -M` / `clang -M` dependency scans."""

    def __init__(self, deps=(), instrumented_text="int f(void) { return 0; }\n", undefined_fallback=False):
        self.calls: list[list[str]] = []
        self.deps = list(deps)
        self.instrumented_text = instrumented_text
        self.undefined_fallback = undefined_fallback

    def builds(self) -> list[list[str]]:
        return [c for c in self.calls if "-M" not in c]

    def __call__(self, cmd, **kwargs):
        self.calls.append(list(cmd))
        if "-M" in cmd:
            srcs = [c for c in cmd if c.endswith(".c")]
            return _cp(cmd, 0, "".join(f"{Path(s).stem}.o: {s} {' '.join(self.deps)}\n" for s in srcs))
        if cmd[0] == "clang" and "-c" in cmd:
            Path(cmd[cmd.index("-o") + 1]).write_bytes(b"fallback object")
            return _cp(cmd)
        if cmd[0] == "clang":  # sanitizer build
            Path(cmd[cmd.index("-o") + 1]).write_bytes(b"\x7fELF asan build")
            return _cp(cmd)
        if "-C" in cmd:
            linking_fallbacks = any(a.endswith("eacsl_fallbacks.o") for a in cmd[cmd.index("-l") + 1].split()) if "-l" in cmd else False
            if self.undefined_fallback and not linking_fallbacks:
                return _cp(cmd, 1, "", "/usr/bin/ld: x.o: undefined reference to `open_fallback_1'\n")
            out = Path(cmd[cmd.index("-O") + 1])
            out.write_bytes(b"plain build")
            out.with_name(out.name + ".e-acsl").write_bytes(EACSL_MARKER_BYTES)
            return _cp(cmd)
        Path(cmd[cmd.index("-o") + 1]).write_text(self.instrumented_text, encoding="utf-8")
        return _cp(cmd)


@pytest.fixture
def modern_cli(monkeypatch):
    monkeypatch.setattr(R, "_resolve_eacsl_gcc", lambda: ("e-acsl-gcc", True))
    monkeypatch.setattr(T.shutil, "which", lambda name: None)


def _module(run: Path) -> Path:
    (run / "inc").mkdir(exist_ok=True)
    (run / "inc" / "mod.h").write_text("int entry(int x);\n", encoding="utf-8")
    src = run / "mod.c"
    src.write_text('#include "mod.h"\nint entry(int x) { return x; }\n', encoding="utf-8")
    return src


def _strip_cache(res: dict) -> dict:
    return {k: v for k, v in res.items() if k != "cache"}


def test_eacsl_key_tracks_headers_and_output_path(run, modern_cli):
    _module(run)
    fake = FakeToolchain(deps=["inc/mod.h"])
    first = R.compile_eacsl_binary(["mod.c"], Path("bin/fuzz_mod"), cppflags="-Iinc", runner=fake)
    assert first["returncode"] == 0 and first["cache"]["hit"] is False and first["cache"]["key"]
    builds = len(fake.builds())

    again = R.compile_eacsl_binary(["mod.c"], Path("bin/fuzz_mod"), cppflags="-Iinc", runner=fake)
    assert again["cache"] == {"hit": True, "key": first["cache"]["key"]}
    assert len(fake.builds()) == builds  # nothing was compiled

    (run / "inc" / "mod.h").write_text("int entry(int x); /* changed */\n", encoding="utf-8")
    edited = R.compile_eacsl_binary(["mod.c"], Path("bin/fuzz_mod"), cppflags="-Iinc", runner=fake)
    assert edited["cache"]["hit"] is False and edited["cache"]["key"] != first["cache"]["key"]

    moved = R.compile_eacsl_binary(["mod.c"], Path("bin/other_mod"), cppflags="-Iinc", runner=fake)
    assert moved["cache"]["hit"] is False and moved["cache"]["key"] != edited["cache"]["key"]

    flags = R.compile_eacsl_binary(["mod.c"], Path("bin/fuzz_mod"), cppflags="-Iinc -DEXTRA", runner=fake)
    assert flags["cache"]["key"] not in (edited["cache"]["key"], first["cache"]["key"])


def test_eacsl_hit_restores_every_output(run, modern_cli):
    _module(run)
    fake = FakeToolchain(deps=["inc/mod.h"], instrumented_text=INSTRUMENTED_WITH_FALLBACK, undefined_fallback=True)
    out_bin = Path("workspace/harnesses/fuzz_mod")
    built = R.compile_eacsl_binary(["mod.c"], out_bin, cppflags="-Iinc", runner=fake)
    assert built["returncode"] == 0 and built["variadic_fallbacks"]
    outputs = [
        Path(built["binary"]),
        out_bin.with_suffix(".instrumented.c"),
        out_bin.with_suffix(".compile.log"),
        out_bin.parent / "fuzz_mod_fallbacks" / "eacsl_fallbacks.o",
        out_bin.parent / "fuzz_mod_fallbacks" / "eacsl_fallbacks.c",
    ]
    original = {p: p.read_bytes() for p in outputs}
    for p in outputs:
        p.unlink()

    hit = R.compile_eacsl_binary(["mod.c"], out_bin, cppflags="-Iinc", runner=fake)
    assert hit["cache"]["hit"] is True
    assert _strip_cache(hit) == _strip_cache(built)
    for p, data in original.items():
        if p.name.endswith(".compile.log"):
            restored = p.read_bytes()
            assert restored.startswith(data)  # the original log, then a note naming the entry
            assert f"eacsl-build/{hit['cache']['key']}".encode() in restored[len(data):]
        else:
            assert p.read_bytes() == data, p
    assert T.is_eacsl_instrumented(Path(hit["binary"]))


def test_cache_on_and_off_give_identical_results(run, modern_cli, monkeypatch):
    _module(run)
    out_bin = Path("bin/fuzz_mod")
    monkeypatch.setenv("FRAMAC_CACHE", "off")
    off = R.compile_eacsl_binary(["mod.c"], out_bin, cppflags="-Iinc", runner=FakeToolchain(deps=["inc/mod.h"]))
    off_bytes = Path(off["binary"]).read_bytes()
    assert off["cache"] == {"hit": False, "key": None}
    assert not (run / "state" / "cache").exists()

    monkeypatch.delenv("FRAMAC_CACHE")
    miss = R.compile_eacsl_binary(["mod.c"], out_bin, cppflags="-Iinc", runner=FakeToolchain(deps=["inc/mod.h"]))
    hit = R.compile_eacsl_binary(["mod.c"], out_bin, cppflags="-Iinc", runner=FakeToolchain(deps=["inc/mod.h"]))
    assert hit["cache"]["hit"] and not miss["cache"]["hit"]
    assert _strip_cache(off) == _strip_cache(miss) == _strip_cache(hit)
    assert Path(hit["binary"]).read_bytes() == off_bytes


def test_agent_scratch_and_selftest_builds_are_never_cached(run, modern_cli, monkeypatch):
    _module(run)
    fake = FakeToolchain(deps=["inc/mod.h"])
    res = R.compile_eacsl_binary(["mod.c"], Path("agents/prover-1/scratch/guard_entry"), cppflags="-Iinc", runner=fake)
    assert res["returncode"] == 0 and res["cache"] == {"hit": False, "key": None}
    assert not any("-M" in c for c in fake.calls)

    monkeypatch.setattr(R, "framac_version", lambda runner=None: "33.0")
    selftest = R.run_selftest(Path("workspace/eacsl_selftest"), runner=FakeToolchain(),
                              replay=lambda *a, **k: {"reproduced": False, "failure": None})
    assert selftest["checks"]["compiled"]
    assert not (run / "state" / "cache" / "eacsl-build").exists()


def test_sanitizer_build_is_cached(run):
    _module(run)
    fake = FakeToolchain(deps=["inc/mod.h"])
    out_bin = Path("bin/fuzz_mod.sanreplay")
    first = R.compile_sanitizer_binary(["mod.c"], out_bin, "-Iinc", True, runner=fake)
    assert first["returncode"] == 0 and first["cache"]["hit"] is False
    out_bin.unlink()
    second = R.compile_sanitizer_binary(["mod.c"], out_bin, "-Iinc", True, runner=fake)
    assert second["cache"]["hit"] is True and out_bin.read_bytes() == b"\x7fELF asan build"
    assert sum(1 for c in fake.calls if c[0] == "clang" and "-M" not in c) == 1


def test_failed_build_is_not_cached(run, modern_cli):
    _module(run)

    class Broken(FakeToolchain):
        def __call__(self, cmd, **kwargs):
            if "-M" in cmd:
                return super().__call__(cmd, **kwargs)
            self.calls.append(list(cmd))
            return _cp(cmd, 1, "", "[kernel] User Error: boom\n")

    fake = Broken(deps=["inc/mod.h"])
    for _ in range(2):
        res = R.compile_eacsl_binary(["mod.c"], Path("bin/fuzz_mod"), cppflags="-Iinc", runner=fake)
        assert res["returncode"] != 0 and res["cache"]["hit"] is False
    assert len(fake.builds()) == 2
    assert cache.run_store().stats()["entries"] == 0


# ---------------------------------------------------------------------------
# Eva reports
# ---------------------------------------------------------------------------

EVA_CSV = (
    "directory\tfile\tline\tfunction\tproperty kind\tstatus\tproperty\n"
    ".\tmod.c\t2\tentry\tassertion\tValid\tmem_access\n"
    ".\tmod.c\t3\tentry\tassertion\tUnknown\tsigned_overflow\n"
)


def _fake_frama_c(calls: list, status: int = 0):
    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        if "-M" in cmd:
            return _cp(cmd, 0, "mod.o: mod.c inc/mod.h\n")
        if "-load" in cmd:
            Path(cmd[cmd.index("-mdr-out") + 1]).write_text('{"runs": []}\n', encoding="utf-8")
            return _cp(cmd)
        if status == 0:
            Path(cmd[cmd.index("-report-csv") + 1]).write_text(EVA_CSV, encoding="utf-8")
            Path(cmd[cmd.index("-eva-report-red-statuses") + 1]).write_text("red\n", encoding="utf-8")
            Path(cmd[cmd.index("-save") + 1]).write_bytes(b"sav")
        return _cp(cmd, status, "[eva] analysis done\n", "")
    return fake_run


def test_eva_hit_restores_reports_and_rewrites_paths(run, monkeypatch):
    _module(run)
    calls: list = []
    monkeypatch.setattr(run_eva_slice.subprocess, "run", _fake_frama_c(calls))
    out = Path("workspace/eva/mod")
    first = run_eva_slice.run_eva_on_slice(["mod.c"], "eva_main", out, cppflags="-Iinc")
    assert first["status"] == "ok" and first["cache"]["hit"] is False
    frama_c_runs = sum(1 for c in calls if c[0] == "frama-c")
    produced = {name: (out / name).read_bytes() for name in ("alarms.csv", "red_alarms.csv", "eva.log", "slice.sarif")}

    second = run_eva_slice.run_eva_on_slice(["mod.c"], "eva_main", out, cppflags="-Iinc")
    assert second["cache"] == {"hit": True, "key": first["cache"]["key"]}
    assert sum(1 for c in calls if c[0] == "frama-c") == frama_c_runs
    for name, data in produced.items():
        assert (out / name).read_bytes() == data
    assert second["sav_file"] is None and not (out / "framac.sav").exists()  # the .sav is never cached
    assert second["csv_file"] == str(out / "alarms.csv") and second["sarif_file"] == str(out / "slice.sarif")
    assert second["log_file"] == str(out / "eva.log")
    keep = lambda r: {k: v for k, v in r.items() if k not in ("cache", "sav_file")}  # noqa: E731
    assert keep(second) == keep(first)

    third = run_eva_slice.run_eva_on_slice(["mod.c"], "eva_main", out, cppflags="-Iinc", extra_domains="taint")
    assert third["cache"]["hit"] is False  # other domains, other key


def test_eva_failures_are_never_cached(run, monkeypatch):
    _module(run)
    calls: list = []
    monkeypatch.setattr(run_eva_slice.subprocess, "run", _fake_frama_c(calls, status=1))
    for _ in range(2):
        res = run_eva_slice.run_eva_on_slice(["mod.c"], "eva_main", Path("workspace/eva/mod"))
        assert res["status"] == "analysis_error" and res["cache"]["hit"] is False
    assert sum(1 for c in calls if c[0] == "frama-c" and "-load" not in c) == 2
