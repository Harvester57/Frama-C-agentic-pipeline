"""Build capture (plan step I2): recorded bear events, recipe, checkpoint, wrappers, and Docker-backed runs."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import benchmark
import build_capture as bc
import checkpoint
import run_metadata
from conftest import BUILD_IMAGE, PHASE0_FIXTURES, ROOT, require_docker_images
from framac_common import ArtifactError
from test_sandbox_and_overlay import _engine_run_args, _fake_engine

FIXTURES = ROOT / "tests" / "fixtures" / "build_capture"
TREE = "/s/tree"


def capture_of(name: str) -> dict:
    return bc.classify_executions(bc.read_executions(FIXTURES / f"{name}.jsonl"), TREE)


def units_of(name: str) -> dict:
    return bc.derive_units(capture_of(name), TREE)


def shape(units: dict) -> dict:
    return {n: (u["kind"], u["files"], u["links"]) for n, u in units.items()}


# --------------------------------------------------------------------------- recorded bear events


@pytest.mark.unit
class TestRecordedEvents:
    def test_reads_started_executions_once(self):
        execs = bc.read_executions(FIXTURES / "one_command.jsonl")
        assert [e["args"][0] for e in execs][:2] == ["sh", "cc"]
        assert len(execs) == 5  # the `terminated` event is not an execution

    def test_compile_and_link_in_one_command(self):
        cap = capture_of("one_command")
        assert set(cap["compiles"]) == {"app::main.c", "app::util.c"}
        main = cap["compiles"]["app::main.c"]
        assert main["implicit"] and main["source"] == "main.c" and main["cwd"] == "."
        assert main["flags"] == ["-I", "include", "-DFEATURE=1"]
        units = bc.derive_units(cap, TREE)
        assert shape(units) == {"app": ("executable", ["main.c", "util.c"], [])}
        assert units["app"]["external_libs"] == [{"ref": "-lm", "libdirs": []}]

    def test_compiler_internals_are_not_compiles(self):
        cap = capture_of("one_command")  # cc1, as and collect2 are in the events
        assert all(c["compiler"] == "cc" for c in cap["compiles"].values())

    def test_archives_follow_members_and_minus_l_resolves_to_produced_artifacts(self):
        units = units_of("archive")
        assert shape(units) == {
            "lib/libextra.a": ("static_lib", ["src/c.c"], []),
            "libab.a": ("static_lib", ["src/a.c", "src/b.c"], []),
            "tool": ("executable", ["tools/t.c"], ["lib/libextra.a", "libab.a"]),
            "unlinked:extra": ("unlinked", ["extra/orphan.c"], []),
        }
        assert units["tool"]["external_libs"] == []

    def test_object_without_minus_o_lands_in_the_working_directory(self):
        cap = capture_of("archive")
        b = cap["compiles"]["src/b.o"]
        assert b["source"] == "src/b.c" and b["cwd"] == "src" and b["flags"] == ["-std=c99", "-I", "include"]

    def test_gcc_ar_with_plugin_and_listing_calls(self):
        assert bc.parse_ar(["gcc-ar", "--plugin", "/p.so", "rcs", "lib.a", "a.o"]) == ("lib.a", ["a.o"])
        assert bc.parse_ar(["ar", "t", "lib.a"]) is None
        assert bc.parse_ar(["ar", "-rcs", "x.a", "a.o", "b.o"]) == ("x.a", ["a.o", "b.o"])
        assert bc.parse_ar(["ar", "rb", "a.o", "x.a", "c.o"]) == ("x.a", ["c.o"])  # positional modifier
        assert bc._AR_RE.match("x86_64-linux-gnu-gcc-ar-14") and bc._AR_RE.match("llvm-ar")
        assert not bc._AR_RE.match("tar")

    def test_shared_library_minus_l_and_paths(self):
        units = units_of("shared")
        assert shape(units) == {
            "app": ("executable", ["app.c"], ["libx.so"]),
            "app2": ("executable", ["app.c"], ["libx.so"]),
            "bin/app3": ("executable", ["app.c"], ["libx.so"]),
            "libx.so": ("shared_lib", ["lib/x.c"], []),
        }
        assert units["app"]["external_libs"] == [{"ref": "-lvendor", "libdirs": ["/opt/vendor/lib"]}]

    def test_shared_library_with_a_non_numeric_version_suffix_is_linked(self):
        # libpng's CMake build: a development version names the library `libpng18.so.18.0.git`, and the
        # executables link it by that name from the build directory.
        def cc(*args: str) -> dict:
            return {"exe": "/usr/bin/cc", "args": ["cc", *args], "cwd": f"{TREE}/build"}

        execs = [
            cc("-fPIC", "-I", TREE, "-c", "-o", "CMakeFiles/png.dir/png.c.o", f"{TREE}/png.c"),
            cc("-fPIC", "-shared", "-o", "libpng18.so.18.0.git", "CMakeFiles/png.dir/png.c.o"),
            cc("-I", TREE, "-c", "-o", "CMakeFiles/pngfix.dir/pngfix.c.o", f"{TREE}/contrib/tools/pngfix.c"),
            cc("CMakeFiles/pngfix.dir/pngfix.c.o", "-o", "pngfix", "libpng18.so.18.0.git", "-lm"),
        ]
        units = bc.derive_units(bc.classify_executions(execs, TREE), TREE)
        assert shape(units) == {
            "build/libpng18.so.18.0.git": ("shared_lib", ["png.c"], []),
            "build/pngfix": ("executable", ["contrib/tools/pngfix.c"], ["build/libpng18.so.18.0.git"]),
        }
        for name in ("libx.so", "libx.so.1", "libx.so.1.2.3", "libpng18.so.18.0.git", "libx.so.1.0-rc1"):
            assert bc._SHARED_RE.search(name), name
        for name in ("x.c", "x.o", "libx.a", "x.sock", "libso.c"):
            assert not bc._SHARED_RE.search(name), name

    def test_build_system_probes_are_dropped(self):
        cap = capture_of("probes")
        assert list(cap["compiles"]) == ["build/CMakeFiles/foo.dir/foo.c.o"]
        assert cap["compiles"]["build/CMakeFiles/foo.dir/foo.c.o"]["source"] == "foo.c"
        assert cap["probes_dropped"] >= 6
        assert shape(bc.derive_units(cap, TREE)) == {"build/libfoo.a": ("static_lib", ["foo.c"], [])}

    def test_probe_paths(self):
        for p in (
            "build/CMakeFiles/CMakeScratch/TryCompile-x/src.c",
            "build/CMakeFiles/3.31.6/CompilerIdC/CMakeCCompilerId.c",
            "build/CMakeFiles/CMakeTmp/a.c",
            "build/CMakeFiles/feature_tests.c",
            "conftest.c",
            "build/meson-private/sanitycheckc.c",
        ):
            assert bc.is_probe_path(p), p
        for p in ("build/CMakeFiles/foo.dir/foo.c.o", "src/a.c", ".", "contest.c"):
            assert not bc.is_probe_path(p), p

    def test_joined_and_separate_flags(self):
        cap = capture_of("flags")
        f = cap["compiles"]["src/f.o"]
        assert f["flags"] == [
            "-I",
            "include",
            "-I",
            "src",
            "-DA",
            "-DB=2",
            "-UC",
            "-UD",
            "-include",
            "config.h",
            "-imacros",
            "macros.h",
            "-iquote",
            "src/internal",
            "-isystem",
            "vendor/inc",
            "-std=gnu11",
        ]
        assert f["system_flags"] == [
            "-isystem",
            "/usr/include/libxml2",
            "-I",
            "/usr/include/glib-2.0",
            "-idirafter",
            "/s/outside",
        ]
        units = bc.derive_units(cap, TREE)
        merged = bc.unit_cppflags(cap["compiles"][o] for o in units["libfg.a"]["objects"])
        assert merged[-1] == "-DONLY_G" and merged.count("-DB=2") == 1 and merged.count("include") == 1

    def test_test_units_are_marked(self):
        units = units_of("tests")
        marked = {n: u["test_reason"] for n, u in units.items() if u["test"]}
        assert marked == {
            "tests/runner": "directory",
            "unit_test": "name",
            "projtest": "name_and_sources",
            "harness": "test_sources",
        }
        assert not units["latest"]["test"] and not units["tool"]["test"] and not units["libp.a"]["test"]

    def test_driver_parsing_modes(self):
        assert bc.parse_driver(["cc", "-E", "a.c"])["mode"] == "other"
        assert bc.parse_driver(["cc", "-M", "a.c"])["mode"] == "other"
        assert bc.parse_driver(["cc", "-c", "-MD", "-MF", "a.d", "a.c"])["mode"] == "compile"
        assert bc.parse_driver(["cc", "-print-file-name=libz.so"])["mode"] == "other"
        d = bc.parse_driver(["cc", "-oapp", "a.c", "-L", "lib", "-lz", "-shared"])
        assert d["output"] == "app" and d["libdirs"] == ["lib"] and d["libs"] == ["z"] and d["shared"]

    def test_dependency_and_symbol_commands_drop_link_and_output_options(self):
        args = ["cc", "-Iinc", "-MD", "-MF", "x.d", "-o", "app", "a.c", "b.c", "x.o", "-Wl,-z,now", "-L.", "-lm"]
        assert bc.deps_argv(args, "/t/a.c") == ["cc", "-Iinc", "-M", "/t/a.c"]
        assert bc.compile_argv(args, "/t/b.c", "/tmp/o.o") == ["cc", "-Iinc", "-c", "/t/b.c", "-o", "/tmp/o.o"]


# ------------------------------------------------------------------------- symbols and headers


@pytest.mark.unit
class TestSymbolsAndHeaders:
    def test_parse_nm_with_and_without_debug_locations(self):
        text = (
            "0000000000000000 T csv_init\t/s/tree/src/csv.c:12\n"
            "0000000000000040 t helper\t/s/tree/src/csv.c:5\n"
            "0000000000000080 W weak_fn\n"
            "0000000000000000 D table\n"
            "                 U memcpy\n"
            "0000000000000100 T get_x\t/s/tree/include/inline.h:3\n"
        )
        syms = bc.parse_nm(text)
        assert syms["csv_init"] == ("T", "/s/tree/src/csv.c") and syms["weak_fn"] == ("W", None)
        assert "memcpy" not in syms
        entry = {"source": "src/csv.c", "cwd": "."}
        ids = bc.function_ids(entry, syms, TREE)
        assert ids["csv_init"] == {"id": "src/csv.c#csv_init", "global": True}
        assert ids["helper"] == {"id": "src/csv.c#helper", "global": False}
        assert ids["get_x"]["id"] == "include/inline.h#get_x"  # a global defined in a header
        assert "table" not in ids

    def test_parse_make_deps(self):
        text = "src/a.o: src/a.c /usr/include/stdio.h \\\n include/a.h ../gen/cfg.h \\\n /usr/include/my\\ dir/x.h\n"
        assert bc.parse_make_deps(text, "/s/tree") == [
            "/s/tree/src/a.c",
            "/usr/include/stdio.h",
            "/s/tree/include/a.h",
            "/s/gen/cfg.h",
            "/usr/include/my dir/x.h",
        ]

    def test_declared_names_after_preprocessing(self):
        text = "int rec_get_version(const struct rec *r);\nstatic int helper (void);\nint other;\n"
        assert bc.declared_names(text, {"rec_get_version", "helper", "other", "absent"}) == {
            "rec_get_version",
            "helper",
        }

    def test_headers_outside_source_dirs(self):
        headers = ["include/a.h", "src/internal/b.h", "config.h", "vendor/include/c.h", "src/d.h"]
        assert bc.outside_source_dirs(headers, {"src", "tools"}) == ["config.h", "include/a.h", "vendor/include/c.h"]
        assert bc.outside_source_dirs(headers, {"."}) == []

    def test_absolute_flags(self):
        flags = ["-I", "include", "-include", "missing_cfg.h", "-DX"]
        out = bc.absolute_flags(flags, TREE)
        assert out[:2] == ["-I", "/s/tree/include"]
        assert out[2:] == ["-include", "missing_cfg.h", "-DX"]


# --------------------------------------------------------------------------------- snapshot


@pytest.mark.unit
class TestSnapshotClassification:
    def test_parse_dpkg_s(self):
        text = (
            "libc6-dev:amd64: /usr/include/stdio.h\n"
            "zlib1g-dev:amd64: /usr/include/zlib.h\n"
            "diversion by dash from: /bin/sh\n"
            "libgcc-14-dev:amd64, other:amd64: /usr/lib/gcc/x86_64-linux-gnu/14/include/stddef.h\n"
            "linux-libc-dev: /usr/include/linux/types.h\n"
        )
        owners = bc.parse_dpkg_s(text)
        assert owners == {
            "/usr/include/stdio.h": "libc6-dev",
            "/usr/include/zlib.h": "zlib1g-dev",
            "/usr/lib/gcc/x86_64-linux-gnu/14/include/stddef.h": "libgcc-14-dev",
            "/usr/include/linux/types.h": "linux-libc-dev",
        }

    def test_libc_toolchain_and_packages_are_told_apart(self):
        owners = {
            "/usr/include/stdio.h": "libc6-dev",
            "/usr/include/linux/types.h": "linux-libc-dev",
            "/usr/lib/gcc/x86_64-linux-gnu/14/include/stddef.h": "libgcc-14-dev",
            "/usr/include/gcrypt.h": "libgcrypt20-dev",
            "/usr/lib/x86_64-linux-gnu/libgcrypt.so.20": "libgcrypt20",
        }
        seen: list[list[str]] = []

        def lookup(paths):
            seen.append(sorted(paths))
            return {p: owners[p] for p in paths if p in owners}

        classes = bc.classify_system_paths([*owners, "/usr/local/include/vendor.h"], lookup)
        assert len(seen) == 1  # one batched lookup
        assert {p: c["class"] for p, c in classes.items()} == {
            "/usr/include/stdio.h": "libc",
            "/usr/include/linux/types.h": "libc",
            "/usr/lib/gcc/x86_64-linux-gnu/14/include/stddef.h": "toolchain",
            "/usr/include/gcrypt.h": "package",
            "/usr/lib/x86_64-linux-gnu/libgcrypt.so.20": "package",
            "/usr/local/include/vendor.h": "unowned",
        }
        assert bc.owner_class("libgcc-s1") == "toolchain" and bc.owner_class("libstdc++-14-dev") == "toolchain"

    def test_ldconfig_and_needed(self):
        ld = (
            "304 libs found in cache `/etc/ld.so.cache'\n"
            "\tlibz.so.1 (libc6,x86-64) => /lib/x86_64-linux-gnu/libz.so.1\n"
            "\tlibgcrypt.so.20 (libc6,x86-64) => /lib/x86_64-linux-gnu/libgcrypt.so.20\n"
        )
        assert bc.parse_ldconfig(ld)["libz.so.1"] == "/lib/x86_64-linux-gnu/libz.so.1"
        readelf = " 0x0000000000000001 (NEEDED)             Shared library: [libgcrypt.so.20]\n"
        assert bc.parse_needed(readelf) == ["libgcrypt.so.20"]

    def test_export_snapshot_digest_is_content_addressed(self, tmp_path):
        a = tmp_path / "usr" / "include" / "a.h"
        a.parent.mkdir(parents=True)
        a.write_text("int a(void);\n", encoding="utf-8")
        snap = tmp_path / "snap"
        first = bc.export_snapshot(snap, {str(a): {}})
        assert first["files"] == 1 and (snap / "root" / a.relative_to(a.anchor)).is_file()
        assert bc.export_snapshot(snap, {str(a): {}})["digest"] == first["digest"]
        a.write_text("int a(int);\n", encoding="utf-8")
        assert bc.export_snapshot(snap, {str(a): {}})["digest"] != first["digest"]


# ------------------------------------------------------------------------------ stop and ask


@pytest.mark.unit
class TestDiagnostics:
    def test_missing_header_gives_first_error_and_candidates(self):
        log = (
            "cc -O0 -g -std=c99 -Iinclude -c -o src/demo.o src/demo.c\n"
            "src/a.c:3:10: warning: unused variable\n"
            "tests/test_demo.c:1:10: fatal error: check.h: No such file or directory\n"
            "    1 | #include <check.h>\n"
            "compilation terminated.\n"
            "src/x.c:2:10: fatal error: openssl/ssl.h: No such file or directory\n"
            "src/y.c:2:10: fatal error: foo/bar.h: No such file or directory\n"
            "make: *** [Makefile:18: tests/test_demo.o] Error 1\n"
        )
        d = bc.diagnose(log, ["libfoo-dev"])
        assert d["first_error"].startswith("tests/test_demo.c:1:10: fatal error: check.h")
        assert d["context"][0].strip().startswith("1 | #include")
        assert d["missing_headers"] == ["check.h", "openssl/ssl.h", "foo/bar.h"]
        assert d["candidate_packages"] == ["check", "libssl-dev", "libfoo-dev"]
        assert d["packages_not_installed"] == ["libfoo-dev"]

    def test_pkgconfig_cmake_linker_and_command_failures(self):
        log = (
            "-- Checking for module 'check'\n"
            "--   Package 'check', required by 'virtual:world', not found\n"
            "CMake Error at CMakeLists.txt:5 (find_package):\n"
            "  Could NOT find OpenSSL (missing: OPENSSL_CRYPTO_LIBRARY)\n"
            "/usr/bin/ld: cannot find -lmnl: No such file or directory\n"
            "sh: 1: autoreconf: not found\n"
            "No package 'libxml-2.0' found\n"
        )
        d = bc.diagnose(log)
        assert d["candidate_packages"] == ["check", "libxml2-dev", "libssl-dev", "libmnl-dev", "autoconf"]
        assert d["missing_commands"] == ["autoreconf"]
        assert "Package 'check'" in d["first_error"]

    def test_propose_recipe_from_build_files(self, tmp_path):
        assert bc.propose_recipe(tmp_path) is None
        (tmp_path / "Makefile").write_text("all:\n", encoding="utf-8")
        assert (bc.propose_recipe(tmp_path) or {})["command"] == "make"
        (tmp_path / "CMakeLists.txt").write_text("project(x C)\n", encoding="utf-8")
        assert (bc.propose_recipe(tmp_path) or {})["command"].startswith("cmake -S . -B build")


# ------------------------------------------------------------------------------ recipe block


@pytest.mark.unit
class TestRecipe:
    def test_normalize_fills_defaults_and_validates(self):
        r = run_metadata.normalize_build_recipe({"command": "make", "packages": "check libssl-dev"})
        assert r == {
            "command": "make",
            "workdir": ".",
            "packages": ["check", "libssl-dev"],
            "env": {},
            "test_command": None,
            "install_command": None,
            "snapshot_extra": [],
            "origin": "user",
        }
        for bad in (
            {"command": ""},
            {"command": "make", "workdir": "../up"},
            {"command": "make", "packages": ["Bad Pkg"]},
            {"command": "make", "env": {"LD_PRELOAD": "x"}},
            {"command": "make", "env": {"1X": "x"}},
            {"command": "make", "snapshot_extra": ["relative/path"]},
            {"command": "make", "origin": "guess"},
        ):
            with pytest.raises(ArtifactError):
                run_metadata.normalize_build_recipe(bad)

    def test_set_build_records_a_valid_block(self, tmp_path, monkeypatch):
        run = tmp_path / "run-7"
        run.mkdir()
        monkeypatch.chdir(run)
        monkeypatch.setattr(run_metadata, "toolchain", lambda: {})
        monkeypatch.setattr(run_metadata, "resources_summary", lambda: None)
        run_metadata.cmd_init("demo", str(tmp_path), "standard", [], None, [], "run-7")
        rc = run_metadata.main(
            ["set-build", "--command", "make lib", "--package", "check", "--env", "CFLAGS=-O0", "--origin", "user"]
        )
        assert rc == 0
        meta = json.loads((run / "run-metadata.json").read_text(encoding="utf-8"))
        assert meta["build"]["command"] == "make lib" and meta["build"]["env"] == {"CFLAGS": "-O0"}
        assert not run_metadata.validate_metadata(meta)
        assert run_metadata.main(["set-build", "--command", "make", "--env", "NOEQUALS"]) == 1

    def test_recipe_file_and_command_line_precedence(self, tmp_path):
        spec = tmp_path / "spec.json"
        spec.write_text(json.dumps({"build": {"command": "make", "origin": "benchmark"}}), encoding="utf-8")
        ns = argparse.Namespace(
            recipe_file=str(spec), command=None, workdir=None, package=[], env=[], test_command=None
        )
        assert (bc.load_recipe(ns) or {})["origin"] == "benchmark"
        ns.command, ns.env = "make lib", ["CFLAGS=-O1"]
        r = bc.load_recipe(ns) or {}
        assert r["command"] == "make lib" and r["origin"] == "user" and r["env"] == {"CFLAGS": "-O1"}
        ns.recipe_file, ns.command = str(tmp_path / "absent.json"), None
        assert bc.load_recipe(ns) is None

    def test_every_benchmark_target_has_a_valid_recipe(self):
        manifest = benchmark.load_manifest()
        for target in manifest["targets"]:
            spec = benchmark.target_spec(target, manifest, fuzz_budget=None, eva_timeout=None)
            recipe = run_metadata.normalize_build_recipe(spec["build"])
            assert recipe["origin"] == "benchmark", target["id"]
        cryptolib = next(t for t in manifest["targets"] if t["id"] == "cryptolib")
        assert set(cryptolib["build"]["packages"]) == set(cryptolib["target_packages"].split())


@pytest.mark.unit
class TestCheckpointStatus:
    def test_blocked_status_keeps_the_phase_and_clears_on_success(self, tmp_path):
        state = tmp_path / "state"
        checkpoint.cmd_save_phase(state, 0, None)
        p = checkpoint.mark_blocked(state, "needs_build_recipe", {"first_error": "boom"})
        assert p["status"] == "needs_build_recipe" and p["phase_done"] == 0 and p["blocked"]["first_error"] == "boom"
        assert checkpoint.clear_blocked(state, "other") is None
        cleared = checkpoint.clear_blocked(state, "needs_build_recipe")
        assert cleared is not None and cleared["status"] == "running" and "blocked" not in cleared

    def test_mark_creates_a_full_progress_file(self, tmp_path):
        p = checkpoint.mark_blocked(tmp_path / "state", "needs_build_recipe", {})
        assert p["phase_done"] == -1 and p["mode"] == "verify" and p["target_dir"] == "/target"

    def test_report_is_recorded_in_the_checkpoint(self, tmp_path):
        report = {"status": "needs_build_recipe", "diagnostics": {"first_error": "fatal error: x.h"}}
        bc.record_checkpoint(tmp_path, report)
        assert json.loads((tmp_path / "progress.json").read_text(encoding="utf-8"))["status"] == "needs_build_recipe"
        bc.record_checkpoint(tmp_path, {"status": "ok"})
        assert json.loads((tmp_path / "progress.json").read_text(encoding="utf-8"))["status"] == "running"


@pytest.mark.unit
def test_report_schema_accepts_the_three_statuses():
    base = {"schema_version": 1, "generated_at": "t", "target": "/target", "warnings": []}
    assert not bc.validate_report({**base, "status": "error", "error": "x"})
    diag = {**bc.diagnose("x.c:1:1: fatal error: a.h: No such file or directory\n"), "proposed_recipe": None}
    assert not bc.validate_report({**base, "status": "needs_build_recipe", "diagnostics": diag, "recipe": None})
    assert bc.validate_report({**base, "status": "maybe"})


# ----------------------------------------------------------------------------- wrappers, benchmark


@pytest.mark.unit
class TestWrappersAndBenchmark:
    def test_benchmark_wrapper_flags(self, monkeypatch, tmp_path):
        monkeypatch.setattr(benchmark, "_is_windows", lambda: False)
        argv = benchmark.wrapper_argv(tmp_path, tmp_path, "r", packages="check", build_image=True, scratch=True)
        assert "--build-image" in argv and "--scratch" in argv and "--target-packages" in argv
        monkeypatch.setattr(benchmark, "_is_windows", lambda: True)
        monkeypatch.setattr(benchmark.shutil, "which", lambda name: f"C:/bin/{name}.exe" if name == "pwsh" else None)
        argv = benchmark.wrapper_argv(tmp_path, tmp_path, "r", build_image=True, scratch=True)
        assert "-BuildImage" in argv and "-Scratch" in argv
        assert "-BuildImage" not in benchmark.wrapper_argv(tmp_path, tmp_path, "r")

    def test_capture_summary(self):
        ok = {
            "status": "ok",
            "units": {"a": {"kind": "static_lib", "test": False}, "t": {"kind": "executable", "test": True}},
            "compiles": [{}, {}],
            "entry_points": ["a.c#f"],
            "snapshot": {"files": 3, "digest": "d"},
            "build": {"seconds": 1.0},
            "seconds": 2.0,
        }
        s = benchmark.summarize_capture(ok)
        assert s["units"] == 2 and s["test_units"] == 1 and s["kinds"] == {"static_lib": 1}
        bad = benchmark.summarize_capture({"status": "needs_build_recipe", "diagnostics": {"first_error": "e"}})
        assert bad == {"status": "needs_build_recipe", "first_error": "e", "candidate_packages": []}
        assert benchmark.summarize_capture(None) == {"status": "no_report"}

    def test_wrappers_declare_the_options(self):
        sh = (ROOT / "wrappers" / "framac-docker.sh").read_text(encoding="utf-8")
        ps1 = (ROOT / "wrappers" / "framac-docker.ps1").read_text(encoding="utf-8")
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        for flag in ("--build-image", "--scratch", "--remove-scratch", "--target framac-build", "/framac-scratch"):
            assert flag in sh, flag
        for flag in ("$BuildImage", "$Scratch", "$RemoveScratch", '"framac-build"', "/framac-scratch"):
            assert flag in ps1, flag
        assert "target: framac-build" in compose and "scratch:/framac-scratch" in compose
        # The monolithic image is gone (plan step I10): no wrapper names or derives it (compose keeps the
        # service name framac-pipeline, which runs the analysis image).
        for text in (sh, ps1, compose):
            assert not re.search(r"framac-pipeline:[\w$<{]", text)

    def test_ps1_runs_build_steps_in_the_build_image_with_the_scratch_volume(self, tmp_path):
        pwsh = shutil.which("pwsh") or shutil.which("powershell")
        if not pwsh:
            pytest.skip("pwsh/powershell not available")
        log_file, env = _fake_engine(tmp_path)
        base = [
            pwsh,
            "-NoProfile",
            "-File",
            str(ROOT / "wrappers/framac-docker.ps1"),
            "-TargetDir",
            str(tmp_path / "target_repo"),
            "-RunDir",
            str(tmp_path / "run_1"),
        ]
        cases: tuple[tuple[list[str], str, bool], ...] = (
            ([], "framac-analysis:latest", False),
            (["-BuildImage", "-Scratch"], "framac-build:latest", True),
            (["-BuildImage", "-TargetPackages", "check", "-NoBroker"], "framac-build:target_repo-", False),
            # The analysis image never gets target packages, under its default name or another one.
            (["-TargetPackages", "check", "-NoBroker"], "framac-analysis:latest", False),
            (
                ["-Image", "framac-analysis:other", "-TargetPackages", "check", "-NoBroker"],
                "framac-analysis:other",
                False,
            ),
        )
        for extra, image, scratch in cases:
            proc = subprocess.run([*base, *extra, "true"], env=env, capture_output=True, text=True)
            assert proc.returncode == 0, proc.stderr or proc.stdout
            args, _ = _engine_run_args(log_file)
            # A derived image is tagged with the repo key (<repo>-<12 hex of the target path hash>).
            if image.endswith("-"):
                assert any(re.fullmatch(re.escape(image) + "[0-9a-f]{12}", a) for a in args), (extra, args)
            else:
                assert image in args, (extra, args)
            mounts = [a for a in args if a.endswith(":/framac-scratch")]
            assert bool(mounts) == scratch, extra
            if scratch:
                assert mounts[0].startswith("framac-scratch-target_repo-run_1-")
        proc = subprocess.run([*base, "-RemoveScratch"], env=env, capture_output=True, text=True)
        assert proc.returncode == 0 and "removed scratch volume framac-scratch-target_repo-run_1-" in proc.stderr


# ---------------------------------------------------------------------- Docker-backed integration


@pytest.fixture
def build_image_run():
    """
    Run build_capture.py in the build image on a fixture mounted read-only at /target (network off),
    as `run(fixture, run_dir, shell_command) -> CompletedProcess`. Opt-in: FRAMAC_DOCKER_TESTS=1.
    """
    require_docker_images(BUILD_IMAGE)

    def run(fixture: Path, run_dir: Path, command: str, timeout: int = 600) -> subprocess.CompletedProcess:
        run_dir.mkdir(parents=True, exist_ok=True)
        argv = [
            "docker", "run", "--rm", "--network", "none",
            "-v", f"{fixture.resolve()}:/target:ro",
            "-v", f"{run_dir.resolve()}:/framac-run",
            "-v", f"{ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
            "-v", f"{ROOT / 'schemas'}:/opt/framac-pipeline/schemas:ro",
            "-w", "/framac-run", BUILD_IMAGE, command,
        ]  # fmt: skip
        return subprocess.run(
            argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, check=False
        )

    return run


REPRODUCERS = sorted(p.name for p in (PHASE0_FIXTURES / "reproducers").iterdir() if (p / "truth.json").is_file())
CAPTURE = "python3 /opt/framac-pipeline/scripts/build_capture.py run --scratch /tmp/scratch"


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize("name", REPRODUCERS)
def test_reproducer_units_and_entry_points_match_the_truth(build_image_run, tmp_path, name):
    fixture = PHASE0_FIXTURES / "reproducers" / name
    truth = json.loads((fixture / "truth.json").read_text(encoding="utf-8"))
    proc = build_image_run(fixture, tmp_path / "run", f"{CAPTURE} --recipe-file '' --command '{truth['build']}'")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    report = json.loads((tmp_path / "run" / "workspace/reports/build_capture.json").read_text(encoding="utf-8"))
    assert not bc.validate_report(report)
    got = {
        n: {"kind": u["kind"], "files": sorted(u["files"]), "links": sorted(u["links"])}
        for n, u in report["units"].items()
    }
    want = {
        n: {"kind": u["kind"], "files": sorted(u["files"]), "links": sorted(u["links"])}
        for n, u in truth["units"].items()
    }
    assert got == want
    assert sorted(report["entry_points"]) == sorted(truth["entry_points"])
    assert report["snapshot"]["files"] == 0  # the reproducers use only libc


@pytest.mark.integration
@pytest.mark.slow
def test_compiles_record_setjmp_h_and_the_functions_the_build_defines(build_image_run, tmp_path):
    """libpng's two blind spots: setjmp.h (E-ACSL cannot build it) and code only the compiler's macros enable."""
    fixture = tmp_path / "target"
    fixture.mkdir()
    (fixture / "jump.c").write_text(
        "#include <setjmp.h>\nstatic jmp_buf env;\nint jump(void) { return setjmp(env); }\n", encoding="utf-8"
    )
    (fixture / "simd.c").write_text(
        "int plain(int x) { return x; }\n#ifdef __SSE2__\nint filter_sse2(int x) { return x + 1; }\n#endif\n",
        encoding="utf-8",
    )
    build = "cc -c jump.c -o jump.o && cc -c simd.c -o simd.o && ar rcs libk.a jump.o simd.o"
    proc = build_image_run(fixture, tmp_path / "run", f"{CAPTURE} --recipe-file '' --command '{build}'")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    report = json.loads((tmp_path / "run" / "workspace/reports/build_capture.json").read_text(encoding="utf-8"))
    assert not bc.validate_report(report)
    by_source = {c["source"]: c for c in report["compiles"]}
    assert by_source["jump.c"]["includes_setjmp_h"] is True
    assert by_source["simd.c"]["includes_setjmp_h"] is False
    assert by_source["jump.c"]["defined_functions"] == ["jump.c#jump"]
    assert by_source["simd.c"]["defined_functions"] == ["simd.c#filter_sse2", "simd.c#plain"]


@pytest.mark.integration
@pytest.mark.slow
def test_broken_build_stops_with_a_diagnostic_and_resumes_after_the_recipe_is_fixed(build_image_run, tmp_path):
    fixture = FIXTURES / "broken"
    run = tmp_path / "run-1"
    py = "python3 /opt/framac-pipeline/scripts"
    script = (
        f"{py}/run_metadata.py init --repo broken --run-id run-1 >/dev/null && "
        f"{py}/run_metadata.py set-build --command make >/dev/null && "
        f"{{ {py}/build_capture.py run --scratch /tmp/scratch; echo rc=$?; }} && "
        f"cp workspace/reports/build_capture.json first.json && cp state/progress.json first-progress.json && "
        f"{py}/run_metadata.py set-build --command 'make lib' --origin agent_confirmed >/dev/null && "
        f"{py}/build_capture.py run --scratch /tmp/scratch"
    )
    proc = build_image_run(fixture, run, script)
    assert "rc=3" in proc.stdout, proc.stdout + proc.stderr
    first = json.loads((run / "first.json").read_text(encoding="utf-8"))
    assert first["status"] == "needs_build_recipe"
    assert "check.h" in first["diagnostics"]["first_error"]
    assert first["diagnostics"]["missing_headers"] == ["check.h"]
    assert first["diagnostics"]["candidate_packages"] == ["check"]
    blocked = json.loads((run / "first-progress.json").read_text(encoding="utf-8"))
    assert blocked["status"] == "needs_build_recipe" and blocked["phase_done"] == -1
    assert proc.returncode == 0, proc.stdout + proc.stderr
    report = json.loads((run / "workspace/reports/build_capture.json").read_text(encoding="utf-8"))
    assert report["status"] == "ok" and report["recipe"]["command"] == "make lib"
    assert report["units"]["libdemo.a"]["entry_points"] == ["src/demo.c#demo_sum"]
    assert json.loads((run / "state/progress.json").read_text(encoding="utf-8"))["status"] == "running"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
