"""Build capture (plan step I2): recorded bear events, recipe, checkpoint, wrappers, and Docker-backed runs."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Literal

import pytest

import benchmark
import build_capture as bc
import checkpoint
import run_metadata
from conftest import ANALYSIS_IMAGE, BUILD_IMAGE, PHASE0_FIXTURES, ROOT, require_docker_images
from framac_common import ArtifactError
from test_acsl_ast_conditionals import AFTER, ARMS
from test_sandbox_and_overlay import _engine_run_args, _fake_engine

FIXTURES = ROOT / "tests" / "fixtures" / "build_capture"
TREE = "/s/tree"


def capture_of(name: str) -> dict:
    return bc.classify_executions(bc.read_executions(FIXTURES / f"{name}.jsonl"), TREE)


def units_of(name: str) -> dict:
    return bc.derive_units(capture_of(name), TREE)


def shape(units: dict) -> dict:
    return {n: (u["kind"], u["files"], u["links"]) for n, u in units.items()}


def _tree_with(tmp_path: Path, *files: str) -> str:
    """A real tree holding `files` after the build, as the posix path the capture's executions use."""
    tree = tmp_path / "tree"
    for f in files:
        (tree / f).parent.mkdir(parents=True, exist_ok=True)
        (tree / f).write_text("x", encoding="utf-8")
    tree.mkdir(exist_ok=True)
    return tree.as_posix()


def _cc(tree: str, *args: str) -> dict:
    return {"exe": "/usr/bin/cc", "args": ["cc", *args], "cwd": tree}


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

    def test_config_guess_temp_dir_probe_is_dropped(self):
        # libmodbus run-1: GNU config.guess compiles $TMPDIR/cgXXXXXX/dummy.c to detect the libc; it became
        # a product unit `unlinked:/tmp/cg7zzCGG` whose source phase0_model could not find.
        execs = [
            {
                "exe": "/usr/bin/cc",
                "args": ["cc", "-c", "-o", "/tmp/cg7zzCGG/dummy.o", "/tmp/cg7zzCGG/dummy.c"],
                "cwd": TREE,
            },
            {"exe": "/usr/bin/cc", "args": ["cc", "-c", "/var/tmp/cgAbCdEf/dummy.c"], "cwd": TREE},
            {"exe": "/usr/bin/cc", "args": ["cc", "-c", "-o", "src/a.o", "src/a.c"], "cwd": TREE},
            # an out-of-tree source that is not in a temp dir stays
            {"exe": "/usr/bin/cc", "args": ["cc", "-c", "-o", "src/b.o", "/s/shared/b.c"], "cwd": TREE},
        ]
        cap = bc.classify_executions(execs, TREE)
        assert sorted(cap["compiles"]) == ["src/a.o", "src/b.o"]
        assert cap["probes_dropped"] == 2
        units = bc.derive_units(cap, TREE)
        assert not [n for n in units if "/tmp/" in n], units
        assert bc.is_temp_probe("/tmp/cg7zzCGG/dummy.c")
        for p in ("src/a.c", "/s/shared/b.c", "/tmpfoo/x.c", "tmp/x.c"):
            assert not bc.is_temp_probe(p), p

    def test_a_probe_whose_source_and_output_are_gone_after_the_build_is_dropped(self, tmp_path):
        # nginx-1.31.9 run-1: nginx's hand-written configure (auto/feature) compiles and links each probe as
        # `cc ... -o objs/autotest objs/autotest.c -lz` and deletes both files afterwards. The capture made it
        # a link unit `objs/autotest` whose source phase0_model could not find. The rule is that the files
        # are gone after the build, not the name: the generated objs/ngx_modules.c, still there, is kept.
        tree = _tree_with(
            tmp_path, "src/main.c", "objs/ngx_modules.c", "objs/main.o", "objs/ngx_modules.o", "objs/nginx"
        )
        execs = [
            _cc(tree, "-D_GNU_SOURCE", "-D_FILE_OFFSET_BITS=64", "-o", "objs/autotest", "objs/autotest.c", "-lz"),
            _cc(tree, "-D_GNU_SOURCE", "-o", "objs/autotest", "objs/autotest.c", "-lcrypt"),
            _cc(tree, "-c", "-o", "objs/probe.o", "objs/probe.c"),  # a compile-only probe, linked by nothing
            _cc(tree, "-c", "-o", "objs/main.o", "src/main.c"),
            _cc(tree, "-c", "-I", "objs", "-o", "objs/ngx_modules.o", "objs/ngx_modules.c"),
            _cc(tree, "-o", "objs/nginx", "objs/main.o", "objs/ngx_modules.o", "-lz"),
        ]
        cap = bc.classify_executions(execs, tree)
        dropped = bc.drop_vanished_probes(cap, tree)
        assert dropped == [
            {"output": "objs/autotest", "sources": ["objs/autotest.c"]},
            {"output": "objs/probe.o", "sources": ["objs/probe.c"]},
        ]
        assert cap["vanished_probes"] == dropped and cap["probes_dropped"] == 2
        assert sorted(cap["compiles"]) == ["objs/main.o", "objs/ngx_modules.o"]
        assert shape(bc.derive_units(cap, tree)) == {
            "objs/nginx": ("executable", ["objs/ngx_modules.c", "src/main.c"], [])
        }

    def test_a_generated_source_the_build_deleted_is_kept_when_its_output_survives(self, tmp_path):
        # make deletes intermediate files (a yacc/lex chain): the object, the executable or the archive
        # built from the source is still there, so the compile is the project's, not a probe.
        tree = _tree_with(tmp_path, "parse.o", "tool", "libm.a", "kept.c", "bin/main.o")
        execs = [
            _cc(tree, "-c", "-o", "parse.o", "parse.c"),  # source gone, object there
            _cc(tree, "-o", "tool", "gen.c"),  # compile-and-link: source gone, executable there
            _cc(tree, "-c", "-o", "member.o", "member.c"),  # both gone, but a member of a surviving archive
            {"exe": "/usr/bin/ar", "args": ["ar", "rcs", "libm.a", "member.o"], "cwd": tree},
            _cc(tree, "-o", "gone", "kept.c"),  # output gone, source there
            _cc(tree, "-c", "-o", "bin/main.o", "main.c"),  # source gone, object there and linked below
            _cc(tree, "-o", "bin/app", "bin/main.o", "parse.o"),  # app removed after the build; its objects stay
        ]
        cap = bc.classify_executions(execs, tree)
        before = (sorted(cap["compiles"]), sorted(cap["artifacts"]))
        assert bc.drop_vanished_probes(cap, tree) == []
        assert (sorted(cap["compiles"]), sorted(cap["artifacts"])) == before
        assert cap["probes_dropped"] == 0 and cap["vanished_probes"] == []

    def test_the_capture_drops_vanished_probes_before_the_analysis(self, tmp_path, monkeypatch):
        # The whole capture, with the build replaced by its recorded executions: the nginx probe never
        # reaches the architecture check or the analysis, and the warnings say what was dropped.
        target = tmp_path / "target"
        target.mkdir()
        (target / "src").mkdir()
        (target / "src/main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
        scratch = tmp_path / "scratch"
        seen: dict = {}

        def run_sandboxed_shell(command, cwd, scratch_, timeout, env_, wrap):
            tree = (Path(scratch_) / "tree").as_posix()
            for f in ("objs/main.o", "objs/nginx"):
                (Path(tree) / f).parent.mkdir(parents=True, exist_ok=True)
                (Path(tree) / f).write_text("x", encoding="utf-8")
            execs = [
                ["cc", "-o", "objs/autotest", "objs/autotest.c", "-lz"],
                ["cc", "-c", "-o", "objs/main.o", "src/main.c"],
                ["cc", "-o", "objs/nginx", "objs/main.o"],
            ]
            events = "".join(
                json.dumps(
                    {"started": {"execution": {"executable": "/usr/bin/cc", "arguments": a, "working_dir": tree}}}
                )
                + "\n"
                for a in execs
            )
            (Path(scratch_) / "events.jsonl").write_text(events, encoding="utf-8")
            return argparse.Namespace(returncode=0, timed_out=False, stdout="", stderr="")

        def check_architecture(compiles, artifacts, tree):
            seen["artifacts"] = sorted(artifacts)
            return {"files": len(artifacts), "unknown": 0, "unsupported_total": 0, "unsupported": []}

        recipe: dict = {"command": "make", "workdir": ".", "packages": [], "env": {}, "test_command": None,
                  "install_command": None, "snapshot_extra": [], "origin": "user"}  # fmt: skip
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(bc, "host_machine", lambda: bc.SUPPORTED_ARCH)
        monkeypatch.setattr(bc, "load_recipe", lambda args: dict(recipe))
        monkeypatch.setattr(bc, "packages_missing", lambda pkgs: [])
        monkeypatch.setattr(bc, "job_count", lambda: 1)
        monkeypatch.setattr(bc, "run_sandboxed_shell", run_sandboxed_shell)
        monkeypatch.setattr(bc, "check_architecture", check_architecture)
        monkeypatch.setattr(bc, "analyse", lambda report, cap, *a: seen.update(cap=cap))
        ns = argparse.Namespace(target=str(target), scratch=str(scratch), timeout=30)
        report, code = bc.capture(ns)
        assert code == 0, report

        def rel(p: str) -> str:
            # On a Windows host str(tree) has backslashes, so the capture keeps the paths absolute.
            return p.rsplit("/tree/", 1)[-1]

        assert [rel(a) for a in seen["artifacts"]] == ["objs/nginx"]
        assert [rel(c) for c in sorted(seen["cap"]["compiles"])] == ["objs/main.o"]
        dropped = seen["cap"]["vanished_probes"]
        assert [(rel(d["output"]), [rel(s) for s in d["sources"]]) for d in dropped] == [
            ("objs/autotest", ["objs/autotest.c"])
        ]
        assert any("objs/autotest" in w and "vanished_probes" in w for w in report["warnings"]), report["warnings"]

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
        }
        assert not units["latest"]["test"] and not units["tool"]["test"] and not units["libp.a"]["test"]
        # Built from `check_parser.c` outside a test directory: `check` in a file name no longer marks a
        # test (`check_http.c` is product code), so the unit is analysed rather than dropped.
        assert not units["harness"]["test"]

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

    @pytest.mark.parametrize("name", sorted(ARMS))
    def test_declared_names_finds_functions_after_split_conditional_arms(self, name):
        source = ARMS[name] + AFTER + "int proto(int a);\n"
        first_fn = source[: source.index("(")].split()[-1]
        names = {first_fn, "after", "last", "proto", "select", "call", "other", "connect", "close"}
        assert bc.declared_names(source, names) == {first_fn, "after", "last", "proto"}

    def test_declared_names_handles_split_params_cplusplus_linkage_and_balanced_conditionals(self):
        split_params = "int f(int a,\n#ifdef A\n      int b)\n#else\n      long b)\n#endif\n{\n    return inner(a);\n}\nint after(void);\n"
        assert bc.declared_names(split_params, {"f", "inner", "after"}) == {"f", "after"}

        linkage = (
            "#ifdef __cplusplus\n"
            'extern "C" {\n'
            "#endif\n"
            "int api(int a);\n"
            "static inline int wrap(int x) { return helper_call(x); }\n"
            "#ifdef __cplusplus\n"
            "}\n"
            "#endif\n"
            "int more(void);\n"
        )
        assert bc.declared_names(linkage, {"api", "wrap", "helper_call", "more"}) == {"api", "wrap", "more"}

        balanced = (
            "#ifdef A\nint win(void) { return 1; }\n#else\nint posix(void) { return 2; }\n#endif\nint tail(void);\n"
        )
        assert bc.declared_names(balanced, {"win", "posix", "tail"}) == {"win", "posix", "tail"}

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


# ------------------------------------------------------------------------------ architecture guard


def elf_head(bits: int, machine: int, big: bool = False) -> bytes:
    """The first 20 bytes of an ELF file: class, data encoding, e_type (relocatable) and e_machine."""
    order: Literal["big", "little"] = "big" if big else "little"
    ident = b"\x7fELF" + bytes([1 if bits == 32 else 2, 2 if big else 1, 1, 0]) + b"\0" * 8
    return ident + (1).to_bytes(2, order) + machine.to_bytes(2, order)


X86_64 = elf_head(64, 62)


def cc(*args: str, compiler: str = "cc", cwd: str = TREE) -> dict:
    return {"exe": f"/usr/bin/{compiler}", "args": [compiler, *args], "cwd": cwd}


def guard(execs: list[dict], heads: dict[str, bytes]) -> dict:
    """check_architecture on intercepted executions, with the files' headers given by tree-relative path."""
    cap = bc.classify_executions(execs, TREE)
    return bc.check_architecture(cap["compiles"], cap["artifacts"], TREE, lambda p: heads.get(p[len(TREE) + 1 :]))


@pytest.mark.unit
class TestArchitectureGuard:
    def test_only_elf64_little_endian_x86_64_is_supported(self):
        assert bc.object_format(X86_64) == (True, "ELF64 x86-64")

    @pytest.mark.parametrize(
        ("head", "found"),
        [
            (elf_head(32, 3), "ELF32 i386"),
            (elf_head(32, 62), "ELF32 x86-64 (x32 ABI)"),
            (elf_head(64, 183), "ELF64 aarch64"),
            (elf_head(32, 40), "ELF32 arm"),
            (elf_head(64, 243), "ELF64 riscv"),
            (elf_head(32, 243), "ELF32 riscv"),
            (elf_head(64, 21, big=True), "ELF64 big-endian ppc64"),
            (elf_head(64, 21), "ELF64 ppc64"),
            (elf_head(64, 22, big=True), "ELF64 big-endian s390"),
            (elf_head(32, 8, big=True), "ELF32 big-endian mips"),
            (elf_head(64, 247), "ELF64 bpf"),
            (elf_head(64, 258), "ELF64 loongarch"),
            (elf_head(64, 9999), "ELF64 machine 9999"),
            (b"MZ\x90\0" + b"\0" * 16, "PE (Windows)"),
            (b"\x64\x86" + b"\0" * 18, "COFF x86-64 (Windows)"),
            (b"\xcf\xfa\xed\xfe" + b"\0" * 16, "Mach-O (macOS)"),
            (b"\0asm\x01\0\0\0", "WebAssembly"),
        ],
    )
    def test_other_architectures_and_formats_are_unsupported(self, head, found):
        assert bc.object_format(head) == (False, found)

    @pytest.mark.parametrize(
        ("head", "found"),
        [
            (b"BC\xc0\xde" + b"\0" * 16, "LLVM bitcode (LTO)"),
            (b"!<arch>\n" + b"\0" * 12, "archive"),
            (b"\x7fELF\x02\x01", "truncated or malformed ELF header"),
            (b"#!/bin/sh\n", "unrecognised file format"),
            (b"", "empty file"),
        ],
    )
    def test_a_header_that_does_not_say_gives_no_verdict(self, head, found):
        assert bc.object_format(head) == (None, found)

    @pytest.mark.parametrize(
        ("argv", "hint"),
        [
            (["cc", "-O2", "-c", "a.c"], None),
            (["x86_64-linux-gnu-gcc-14", "-c", "a.c"], None),
            (["/usr/bin/x86_64-pc-linux-gnu-gcc", "-c", "a.c"], None),
            (["afl-gcc", "-c", "a.c"], None),
            (["musl-gcc", "-c", "a.c"], None),
            (["clang", "--target=x86_64-pc-linux-gnu", "-c", "a.c"], None),
            (["gcc", "-m32", "-m64", "-c", "a.c"], None),
            (["gcc", "-m32", "-c", "a.c"], "-m32"),
            (["gcc", "-m64", "-mx32", "-c", "a.c"], "-mx32"),
            (["gcc", "-m16", "-c", "boot.c"], "-m16"),
            (["arm-linux-gnueabihf-gcc", "-c", "a.c"], "cross compiler arm-linux-gnueabihf-gcc"),
            (["/opt/x/bin/aarch64-linux-gnu-gcc-13", "-c", "a.c"], "cross compiler aarch64-linux-gnu-gcc-13"),
            (["i686-linux-gnu-gcc", "-c", "a.c"], "cross compiler i686-linux-gnu-gcc"),
            (["riscv64-unknown-elf-gcc", "-c", "a.c"], "cross compiler riscv64-unknown-elf-gcc"),
            (["x86_64-w64-mingw32-gcc", "-c", "a.c"], "cross compiler x86_64-w64-mingw32-gcc"),
            (["x86_64-linux-gnux32-gcc", "-c", "a.c"], "cross compiler x86_64-linux-gnux32-gcc"),
            (["clang", "--target=aarch64-linux-gnu", "-c", "a.c"], "--target=aarch64-linux-gnu"),
            (["clang", "-target", "bpf", "-c", "a.c"], "--target=bpf"),
            (["clang", "--target=wasm32", "-c", "a.c"], "--target=wasm32"),
            (["clang", "--target=x86_64-apple-darwin", "-c", "a.c"], "--target=x86_64-apple-darwin"),
            (["clang", "--target=i386-linux-gnu", "-m32", "-c", "a.c"], "--target=i386-linux-gnu, -m32"),
        ],
    )
    def test_command_line_hints(self, argv, hint):
        assert bc.arch_hint(argv) == hint

    def test_host_machine_folds_the_amd64_spellings(self, monkeypatch):
        for raw, want in (("x86_64", "x86_64"), ("AMD64", "x86_64"), ("aarch64", "aarch64"), ("arm64", "arm64")):
            monkeypatch.setattr(bc.platform, "machine", lambda raw=raw: raw)
            assert bc.host_machine() == want
        monkeypatch.setattr(bc.platform, "machine", lambda: "")
        assert bc.host_machine() == "unknown"

    def test_a_native_build_passes(self):
        execs = [
            cc("-c", "src/a.c", "-o", "src/a.o"),
            cc("-c", "src/b.c", "-o", "src/b.o"),
            {"exe": "/usr/bin/ar", "args": ["ar", "rcs", "libk.a", "src/a.o", "src/b.o"], "cwd": TREE},
            cc("-shared", "src/a.o", "-o", "libk.so"),
            cc("main.c", "-L.", "-lk", "-o", "prog"),
        ]
        heads = {"src/a.o": X86_64, "src/b.o": X86_64, "libk.so": X86_64, "prog": X86_64}
        assert guard(execs, heads) == {"files": 4, "unknown": 0, "unsupported_total": 0, "unsupported": []}

    def test_a_32_bit_object_is_listed_with_its_source_and_flag(self):
        execs = [cc("-c", "src/a.c", "-o", "src/a.o"), cc("-m32", "-c", "src/b.c", "-o", "src/b.o")]
        res = guard(execs, {"src/a.o": X86_64, "src/b.o": elf_head(32, 3)})
        assert res["files"] == 2 and res["unsupported_total"] == 1
        assert res["unsupported"] == [
            {"file": "src/b.o", "sources": ["src/b.c"], "found": "ELF32 i386", "why": "-m32", "decided_by": "header"}
        ]
        assert bc.describe_unsupported(res["unsupported"][0]) == "src/b.o is ELF32 i386 (built with -m32)"

    def test_the_header_wins_over_the_command_line(self):
        # A cross-named compiler that writes x86_64 code is supported; a plain `cc` that does not is not.
        execs = [
            cc("-m64", "-c", "a.c", "-o", "a.o", compiler="i686-linux-gnu-gcc"),
            cc("-c", "b.c", "-o", "b.o"),
        ]
        res = guard(execs, {"a.o": X86_64, "b.o": elf_head(64, 183)})
        assert [(e["file"], e["found"], e["why"]) for e in res["unsupported"]] == [("b.o", "ELF64 aarch64", None)]
        assert bc.describe_unsupported(res["unsupported"][0]) == "b.o is ELF64 aarch64"

    def test_a_compile_and_link_command_is_judged_by_the_file_it_linked(self):
        res = guard([cc("-mx32", "main.c", "util.c", "-o", "bin/prog")], {"bin/prog": elf_head(32, 62)})
        assert res["files"] == 1
        assert res["unsupported"][0] == {
            "file": "bin/prog",
            "sources": ["main.c", "util.c"],
            "found": "ELF32 x86-64 (x32 ABI)",
            "why": "-mx32",
            "decided_by": "header",
        }

    def test_an_unreadable_output_is_decided_by_its_command_line(self):
        execs = [
            cc("-c", "a.c", "-o", "a.o", compiler="arm-linux-gnueabihf-gcc"),  # object removed by the build
            cc("-flto", "--target=aarch64-linux-gnu", "-c", "b.c", "-o", "b.o", compiler="clang"),
            cc("-flto", "-c", "c.c", "-o", "c.o", compiler="clang"),  # bitcode, nothing names another target
            cc("-c", "d.c", "-o", "d.o"),  # removed, native command line
        ]
        res = guard(execs, {"b.o": b"BC\xc0\xde" + b"\0" * 16, "c.o": b"BC\xc0\xde" + b"\0" * 16})
        assert res["files"] == 4 and res["unknown"] == 2 and res["unsupported_total"] == 2
        assert [(e["file"], e["decided_by"]) for e in res["unsupported"]] == [
            ("a.o", "command_line"),
            ("b.o", "command_line"),
        ]
        assert bc.describe_unsupported(res["unsupported"][0]) == (
            "a.o is built with cross compiler arm-linux-gnueabihf-gcc (not found after the build)"
        )

    def test_the_list_is_capped_and_the_total_is_kept(self):
        n = bc.ARCH_LIST_CAP + 7
        execs = [cc("-m32", "-c", f"f{i}.c", "-o", f"f{i}.o") for i in range(n)]
        res = guard(execs, {f"f{i}.o": elf_head(32, 3) for i in range(n)})
        assert res["unsupported_total"] == n and len(res["unsupported"]) == bc.ARCH_LIST_CAP

    def test_target_diagnostics_name_the_first_file_and_give_the_instructions(self):
        execs = [cc("-c", "a.c", "-o", "a.o"), cc("-m32", "-c", "b.c", "-o", "b.o")]
        arch = guard(execs, {"a.o": X86_64, "b.o": elf_head(32, 3)})
        diag = bc.target_diagnostics(arch)
        assert diag["first_error"] == (
            "1 of 2 build output(s) are not x86_64 Linux code (ELF64, little-endian): "
            "b.o is ELF32 i386 (built with -m32)"
        )
        text = " ".join(diag["instructions"])
        for word in ("-m32", "set-build", "cross compiler", "--host=", "CMAKE_TOOLCHAIN_FILE", "out of scope"):
            assert word in text, word
        assert diag["candidate_packages"] == [] and diag["missing_headers"] == []

    def test_a_foreign_host_stops_the_capture_before_anything_is_copied_or_built(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(bc.platform, "machine", lambda: "aarch64")

        def never(*a, **k):
            raise AssertionError("the capture went on after the host check")

        for name in ("load_recipe", "copy_target", "run_sandboxed_shell"):
            monkeypatch.setattr(bc, name, never)
        ns = argparse.Namespace(target=str(tmp_path / "target"), scratch=str(tmp_path / "scratch"), timeout=10)
        report, code = bc.capture(ns)
        assert code == bc.EXIT_UNSUPPORTED_ARCH == 5
        assert report["status"] == "unsupported_architecture"
        assert report["architecture"] == {"supported": "x86_64", "host": "aarch64", "rule": bc.ARCH_RULE}
        assert report["diagnostics"]["first_error"] == (
            "unsupported host architecture aarch64: the pipeline runs on x86_64 Linux only"
        )
        text = " ".join(report["diagnostics"]["instructions"])
        assert "x86_64 Linux container host" in text and "linux/amd64" in text and "not supported" in text
        assert not bc.validate_report(report)

    def test_cmd_run_writes_the_report_blocks_the_checkpoint_and_prints_the_instructions(
        self, tmp_path, monkeypatch, capsys
    ):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(bc.platform, "machine", lambda: "riscv64")
        out = tmp_path / "workspace" / "reports" / "build_capture.json"
        rc = bc.main(["run", "--target", str(tmp_path), "--scratch", str(tmp_path / "s"), "--out", str(out)])
        assert rc == 5
        report = json.loads(out.read_text(encoding="utf-8"))
        assert report["status"] == "unsupported_architecture" and not report["warnings"]
        progress = json.loads((tmp_path / "state" / "progress.json").read_text(encoding="utf-8"))
        assert progress["status"] == "unsupported_architecture"
        assert progress["blocked"]["resume_at"] == "build_capture.py run"
        assert "riscv64" in progress["blocked"]["first_error"]
        assert any("riscv64" in line for line in checkpoint.blocked_lines(progress))
        summary = json.loads(capsys.readouterr().out)
        assert summary["status"] == "unsupported_architecture" and summary["host"] == "riscv64"
        assert summary["instructions"] == list(bc.HOST_INSTRUCTIONS) and summary["unsupported"] == []

    def test_the_checkpoint_records_the_status_and_a_good_capture_clears_it(self, tmp_path):
        assert checkpoint.BLOCKING_STEPS["unsupported_architecture"] == "build_capture.py run"
        report = {"status": "unsupported_architecture", "diagnostics": {"first_error": "a.o is ELF32 i386"}}
        bc.record_checkpoint(tmp_path, report)
        progress = json.loads((tmp_path / "progress.json").read_text(encoding="utf-8"))
        assert progress["status"] == "unsupported_architecture"
        assert progress["blocked"]["first_error"] == "a.o is ELF32 i386"
        # A recipe that then fails to build replaces the status; a capture that succeeds clears either.
        bc.record_checkpoint(tmp_path, {"status": "needs_build_recipe", "diagnostics": {"first_error": "boom"}})
        assert json.loads((tmp_path / "progress.json").read_text(encoding="utf-8"))["status"] == "needs_build_recipe"
        bc.record_checkpoint(tmp_path, report)
        bc.record_checkpoint(tmp_path, {"status": "ok"})
        cleared = json.loads((tmp_path / "progress.json").read_text(encoding="utf-8"))
        assert cleared["status"] == "running" and "blocked" not in cleared

    def test_report_schema_accepts_the_status_and_the_architecture_block(self):
        base = {"schema_version": 1, "generated_at": "t", "target": "/target", "warnings": []}
        execs = [cc("-m32", "-c", "b.c", "-o", "b.o")]
        arch = {"supported": "x86_64", "host": "x86_64", "rule": bc.ARCH_RULE, **guard(execs, {})}
        blocked = {
            **base,
            "status": "unsupported_architecture",
            "architecture": arch,
            "diagnostics": bc.target_diagnostics(arch),
        }
        assert not bc.validate_report(blocked)
        assert bc.validate_report({**blocked, "architecture": {**arch, "supported": "aarch64"}})
        assert bc.validate_report({**blocked, "architecture": {"supported": "x86_64"}})
        entry = {**arch["unsupported"][0], "decided_by": "guess"}
        assert bc.validate_report({**blocked, "architecture": {**arch, "unsupported": [entry]}})

    def test_benchmark_summary_carries_the_first_error(self):
        report = {
            "status": "unsupported_architecture",
            "diagnostics": {"first_error": "b.o is ELF32 i386", "candidate_packages": []},
        }
        assert benchmark.summarize_capture(report) == {
            "status": "unsupported_architecture",
            "first_error": "b.o is ELF32 i386",
            "candidate_packages": [],
        }


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


@pytest.mark.parametrize(
    ("deps", "expected"),
    [
        # c-ares run-1: glibc's <pthread.h> pulls in <bits/setjmp.h> for `__jmp_buf`; E-ACSL builds it.
        (["/usr/include/pthread.h", "/usr/include/x86_64-linux-gnu/bits/setjmp.h"], False),
        (["/usr/include/bits/setjmp.h", "/usr/include/x86_64-linux-gnu/bits/setjmp2.h"], False),
        (["/usr/include/x86_64-linux-gnu/bits/types/struct___jmp_buf_tag.h"], False),
        (["/usr/include/setjmp.h", "/usr/include/x86_64-linux-gnu/bits/setjmp.h"], True),
        (["/framac-run/workspace/snapshot/sysroot/usr/include/setjmp.h"], True),
        ([], False),
    ],
)
def test_only_the_top_level_setjmp_h_counts(deps: list[str], expected: bool) -> None:
    assert bc.includes_setjmp_h(deps) is expected


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
    # c-ares: <pthread.h> includes glibc's <bits/setjmp.h>, not <setjmp.h>.
    (fixture / "lock.c").write_text(
        "#include <pthread.h>\nstatic pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;\n"
        "int lock(void) { return pthread_mutex_lock(&m); }\n",
        encoding="utf-8",
    )
    build = (
        "cc -c jump.c -o jump.o && cc -c simd.c -o simd.o && cc -c lock.c -o lock.o"
        " && ar rcs libk.a jump.o simd.o lock.o"
    )
    proc = build_image_run(fixture, tmp_path / "run", f"{CAPTURE} --recipe-file '' --command '{build}'")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    report = json.loads((tmp_path / "run" / "workspace/reports/build_capture.json").read_text(encoding="utf-8"))
    assert not bc.validate_report(report)
    by_source = {c["source"]: c for c in report["compiles"]}
    assert by_source["jump.c"]["includes_setjmp_h"] is True
    assert by_source["simd.c"]["includes_setjmp_h"] is False
    assert by_source["lock.c"]["includes_setjmp_h"] is False
    assert by_source["jump.c"]["defined_functions"] == ["jump.c#jump"]
    assert by_source["simd.c"]["defined_functions"] == ["simd.c#filter_sse2", "simd.c#plain"]


_EACSL_PROBE_BODY = """#include <stddef.h>
#include <stdint.h>
static int counter;
int bump(const uint8_t *data, size_t size) { if (size > 0) counter += data[0]; return counter; }
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { bump(data, size); return 0; }
"""


@pytest.mark.integration
@pytest.mark.slow
def test_eacsl_builds_pthread_h_and_rejects_setjmp_h(tmp_path):
    """
    The ground truth behind `includes_setjmp_h`: the pipeline's E-ACSL build of a source including
    <pthread.h> (glibc's <bits/setjmp.h>, `__sigsetjmp`) succeeds; one including <setjmp.h> stops on MSC38-C.
    """
    require_docker_images(ANALYSIS_IMAGE)
    (tmp_path / "pthread_only.c").write_text(
        "#include <pthread.h>\n" + _EACSL_PROBE_BODY, encoding="utf-8", newline="\n"
    )
    (tmp_path / "setjmp_h.c").write_text("#include <setjmp.h>\n" + _EACSL_PROBE_BODY, encoding="utf-8", newline="\n")
    build = (
        "timeout 300 python3 /opt/framac-pipeline/scripts/run_eacsl_fuzz.py build --engine eacsl --no-cache "
        "--sources /w/{0}.c --cppflags=-I/w --out-bin /w/out/{0} --out-json /w/out/{0}.json > /w/{0}.out 2>&1; "
    )
    script = "cd /w; mkdir -p out; " + build.format("pthread_only") + build.format("setjmp_h") + "true"
    proc = subprocess.run(
        [
            "docker", "run", "--rm", "--network", "none",
            "-v", f"{tmp_path}:/w",
            "-v", f"{ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
            "-v", f"{ROOT / 'templates'}:/opt/framac-pipeline/templates:ro",
            "--entrypoint", "bash", ANALYSIS_IMAGE, "-c", script,
        ],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900, check=False,
    )  # fmt: skip
    assert proc.returncode == 0, proc.stdout + proc.stderr
    pthread_only = json.loads((tmp_path / "out" / "pthread_only.json").read_text(encoding="utf-8"))
    setjmp_h = json.loads((tmp_path / "out" / "setjmp_h.json").read_text(encoding="utf-8"))
    assert (pthread_only["status"], pthread_only["engine_used"]) == ("built", "eacsl"), pthread_only
    assert setjmp_h["status"] == "compile_error", setjmp_h
    log = (tmp_path / "out" / "setjmp_h.compile.log").read_text(encoding="utf-8")
    assert "Attempt to declare setjmp as external identifier" in log and "MSC38-C" in log


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


FOREIGN_BUILDS = {
    "m32": ("cc -m32 -c demo.c -o demo.o", "demo.o is ELF32 i386 (built with -m32)"),
    "mx32": ("cc -mx32 -c demo.c -o demo.o", "demo.o is ELF32 x86-64 (x32 ABI) (built with -mx32)"),
    "aarch64": (
        "clang --target=aarch64-linux-gnu -c demo.c -o demo.o",
        "demo.o is ELF64 aarch64 (built with --target=aarch64-linux-gnu)",
    ),
    "bpf": ("clang -target bpf -c demo.c -o demo.o", "demo.o is ELF64 bpf (built with --target=bpf)"),
}


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize("name", sorted(FOREIGN_BUILDS))
def test_a_build_for_another_architecture_stops_and_resumes_after_a_native_recipe(build_image_run, tmp_path, name):
    """The guard on real objects: a mixed build (one native object, one foreign) stops with exit code 5."""
    foreign, described = FOREIGN_BUILDS[name]
    fixture = tmp_path / "target"
    fixture.mkdir()
    # No #include: the build image has no 32-bit or cross libc headers, and needs none to compile these.
    (fixture / "demo.c").write_text("int demo_sum(int a, int b) { return a + b; }\n", encoding="utf-8")
    (fixture / "host.c").write_text("int host_id(void) { return 7; }\n", encoding="utf-8")
    run = tmp_path / "run-1"
    py = "python3 /opt/framac-pipeline/scripts"
    mixed = f"cc -c host.c -o host.o && {foreign} && ar rcs libdemo.a host.o demo.o"
    native = "cc -c host.c -o host.o && cc -c demo.c -o demo.o && ar rcs libdemo.a host.o demo.o"
    script = (
        f"{py}/run_metadata.py init --repo demo --run-id run-1 >/dev/null && "
        f"{py}/run_metadata.py set-build --command '{mixed}' >/dev/null && "
        f"{{ {py}/build_capture.py run --scratch /tmp/scratch > first-summary.json; echo rc=$?; }} && "
        f"cp workspace/reports/build_capture.json first.json && cp state/progress.json first-progress.json && "
        f"{py}/run_metadata.py set-build --command '{native}' --origin agent_confirmed >/dev/null && "
        f"{py}/build_capture.py run --scratch /tmp/scratch"
    )
    proc = build_image_run(fixture, run, script)
    assert "rc=5" in proc.stdout, proc.stdout + proc.stderr
    first = json.loads((run / "first.json").read_text(encoding="utf-8"))
    assert not bc.validate_report(first)
    assert first["status"] == "unsupported_architecture"
    arch = first["architecture"]
    assert arch["host"] == "x86_64" and arch["files"] == 2 and arch["unknown"] == 0
    assert [e["file"] for e in arch["unsupported"]] == ["demo.o"] and arch["unsupported_total"] == 1
    assert arch["unsupported"][0]["sources"] == ["demo.c"] and arch["unsupported"][0]["decided_by"] == "header"
    assert first["diagnostics"]["first_error"].endswith(described)
    assert first["diagnostics"]["instructions"] == list(bc.TARGET_INSTRUCTIONS)
    assert first["units"] == {} and first["snapshot"] is None  # stopped before any analysis of the build
    summary = json.loads((run / "first-summary.json").read_text(encoding="utf-8"))
    assert summary["unsupported"] == [described] and summary["instructions"] == list(bc.TARGET_INSTRUCTIONS)
    blocked = json.loads((run / "first-progress.json").read_text(encoding="utf-8"))
    assert blocked["status"] == "unsupported_architecture" and blocked["phase_done"] == -1
    assert blocked["blocked"]["resume_at"] == "build_capture.py run"
    assert proc.returncode == 0, proc.stdout + proc.stderr
    report = json.loads((run / "workspace/reports/build_capture.json").read_text(encoding="utf-8"))
    assert not bc.validate_report(report)
    assert report["status"] == "ok" and report["architecture"]["unsupported"] == []
    assert report["architecture"]["files"] == 2 and report["architecture"]["unknown"] == 0
    assert report["units"]["libdemo.a"]["files"] == ["demo.c", "host.c"]
    assert json.loads((run / "state/progress.json").read_text(encoding="utf-8"))["status"] == "running"


# ---------------------------------------------------- test drivers that compile the library again

# mpack run-2's shape: `libmpack.a` from src/mpack/*.c, and the unit-test driver `runner` (no test word,
# not in a test directory) compiling the same sources again next to test/unit/src/test*.c, whose
# test.c holds `main`. A product CLI does the same with its `main` in tools/.
_DRIVER_SYMBOLS = {
    "src/mpack/mpack-reader.c": {"mpack_read": ("T", None)},
    "src/mpack/mpack-writer.c": {"mpack_write": ("T", None)},
    "test/unit/src/test.c": {"main": ("T", None)},
    "test/unit/src/test-reader.c": {"test_reader": ("T", None)},
    "tools/cli.c": {"main": ("T", None)},
    "examples/sax-example.c": {"main": ("T", None)},
}
_DRIVER_HEADERS = {
    "src/mpack/mpack.h": "int mpack_read(int fd);\nint mpack_write(int fd);\n",
    # Outside every source directory, and not the library's: before the fix the only public header.
    "examples/sax-example.h": "void sax_example(void);\n",
    "test/unit/src/test.h": "void test_reader(void);\n",
}


def _driver_execs(with_cli: bool, with_lib: bool = True, with_example: bool = False) -> list[dict]:
    lib = ["src/mpack/mpack-reader.c", "src/mpack/mpack-writer.c"]
    tests = ["test/unit/src/test.c", "test/unit/src/test-reader.c"]
    execs: list[dict] = []

    def compile_all(srcs: list[str], out_dir: str) -> list[str]:
        objs = [f"{out_dir}/{Path(s).stem}.o" for s in srcs]
        execs.extend(cc("-Isrc/mpack", "-c", "-o", o, s) for s, o in zip(srcs, objs, strict=True))
        return objs

    if with_lib:
        lib_objs = compile_all(lib, ".build/mpack-lib")
        execs.append(
            {"exe": "/usr/bin/ar", "args": ["ar", "rcs", ".build/mpack-lib/libmpack.a", *lib_objs], "cwd": TREE}
        )
    if with_example:
        example_objs = compile_all(["examples/sax-example.c", *lib], "examples/obj")
        execs.append(cc("-o", "examples/sax-example", *example_objs))
    runner_objs = compile_all(lib + tests, ".build/unit/everything-debug/obj")
    execs.append(cc("-o", ".build/unit/everything-debug/runner", *runner_objs))
    if with_cli:
        cli_objs = compile_all([*lib, "tools/cli.c"], ".build/cli")
        execs.append(cc("-o", ".build/mpack-cli", *cli_objs))
    return execs


def _driver_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    with_cli: bool = False,
    headers: dict[str, str] | None = None,
    with_lib: bool = True,
    with_example: bool = False,
) -> dict:
    """analyse() on the mpack-shaped build, with the probes (cc -M, nm, install, snapshot) stubbed."""
    tree = tmp_path / "tree"
    for rel, text in (headers or _DRIVER_HEADERS).items():
        (tree / rel).parent.mkdir(parents=True, exist_ok=True)
        (tree / rel).write_text(text, encoding="utf-8")

    def deps(c: dict, t: str) -> tuple[list[str], None]:
        header = "test/unit/src/test.h" if c["source"].startswith("test/") else "src/mpack/mpack.h"
        return [c["object"], f"{t}/{header}"], None

    monkeypatch.setattr(bc, "compile_deps", deps)
    monkeypatch.setattr(bc, "compile_symbols", lambda c, t, tmp, i: (_DRIVER_SYMBOLS[c["source"]], None))
    monkeypatch.setattr(bc, "try_install", lambda *a: ([], "no install target"))
    monkeypatch.setattr(bc, "generated_headers", lambda *a: [])
    monkeypatch.setattr(bc, "build_snapshot", lambda *a, **k: {"files": 0})
    cap = bc.classify_executions(_driver_execs(with_cli, with_lib, with_example), TREE)
    report: dict = {"warnings": [], "build": {}, "target": str(tmp_path / "target")}
    bc.analyse(report, cap, tree, tmp_path / "scratch", {}, 60, 1)
    return report


@pytest.mark.unit
def test_a_test_driver_compiling_the_library_again_is_a_test_unit(tmp_path, monkeypatch):
    report = _driver_capture(tmp_path, monkeypatch, with_cli=True)
    units = report["units"]
    runner = units[".build/unit/everything-debug/runner"]
    assert (runner["test"], runner["test_reason"]) == (True, "main_in_test_source")
    # The CLI compiles the same library sources, but its `main` is product code.
    assert (units[".build/mpack-cli"]["test"], units[".build/mpack-cli"]["test_reason"]) == (False, None)
    assert not units[".build/mpack-lib/libmpack.a"]["test"]
    assert "test/unit/src/test.c#main" not in report["entry_points"]


def _driver_plans(report: dict) -> list[str]:
    import seed_harvest as sh

    functions = {
        f"{src}#{name}": {"name": name, "signature": "int(int)"}
        for src, syms in _DRIVER_SYMBOLS.items()
        for name in syms
    }
    model = {"entry_points": report["entry_points"], "units": report["units"], "functions": functions}
    plans, _ = sh.plan_recorder(model)
    return sorted(p["name"] for p in plans)


@pytest.mark.unit
def test_the_seed_recorder_no_longer_wraps_the_test_drivers_functions(tmp_path, monkeypatch):
    # Before the fix the runner was a product unit: its embedded API (test_reader, from test.h)
    # was wrapped, and only the outermost call is recorded, so no library call reached calls.jsonl.
    assert _driver_plans(_driver_capture(tmp_path, monkeypatch, with_cli=True)) == ["mpack_read", "mpack_write"]
    assert _driver_plans(_driver_capture(tmp_path, monkeypatch)) == ["mpack_read", "mpack_write"]


@pytest.mark.unit
def test_a_test_driver_whose_product_sources_an_example_program_holds_is_a_test_unit(tmp_path, monkeypatch):
    # mpack run-3: `make -C examples sax-example` and the unit tests, no library. The product sources
    # are held by examples/sax-example, a non-test executable whose `main` is in examples/.
    report = _driver_capture(tmp_path, monkeypatch, with_lib=False, with_example=True)
    units = report["units"]
    runner = units[".build/unit/everything-debug/runner"]
    assert (runner["test"], runner["test_reason"]) == (True, "main_in_test_source")
    assert (units["examples/sax-example"]["test"], units["examples/sax-example"]["test_reason"]) == (False, None)
    assert any("runner: a test driver" in w and "in a non-test unit" in w for w in report["warnings"])
    assert not any(e.startswith("test/") for e in report["entry_points"])
    assert _driver_plans(report) == ["mpack_read", "mpack_write"]


@pytest.mark.unit
def test_a_stray_header_outside_the_sources_does_not_hide_a_static_librarys_api(tmp_path, monkeypatch):
    # mpack run-2: the only headers outside the source directories were examples/sax-example.h and
    # test/fuzz/fuzz-config.h, so libmpack.a had no entry point (PUBLIC_FALLBACK_RULE).
    report = _driver_capture(tmp_path, monkeypatch)
    assert report["public_headers"]["method"] == "outside_source_dirs"
    lib = report["units"][".build/mpack-lib/libmpack.a"]
    assert lib["entry_points"] == ["src/mpack/mpack-reader.c#mpack_read", "src/mpack/mpack-writer.c#mpack_write"]
    assert any("libmpack.a: the outside_source_dirs public headers declare none" in w for w in report["warnings"])
    assert report["entry_points"] == lib["entry_points"]
    assert _driver_plans(report) == ["mpack_read", "mpack_write"]


@pytest.mark.unit
def test_public_headers_that_declare_the_librarys_functions_are_kept(tmp_path, monkeypatch):
    # include/mpack.h, outside the sources, declares only mpack_read: that is the public API, and the
    # internal src/mpack/mpack.h (declaring mpack_write too) must not be read in its place.
    headers = {**_DRIVER_HEADERS, "include/mpack.h": "int mpack_read(int fd);\n"}
    report = _driver_capture(tmp_path, monkeypatch, headers=headers)
    assert report["public_headers"]["files"] == ["examples/sax-example.h", "include/mpack.h"]
    assert report["units"][".build/mpack-lib/libmpack.a"]["entry_points"] == ["src/mpack/mpack-reader.c#mpack_read"]
    assert not any("public headers declare none" in w for w in report["warnings"])


def _unit(kind: str, files: list[str], test: bool = False) -> dict:
    return {"kind": kind, "files": files, "test": test, "test_reason": "name" if test else None}


@pytest.mark.unit
@pytest.mark.parametrize(
    ("files", "main", "marked"),
    [
        # mpack's runner: library sources again, plus the tests holding `main`.
        (["src/a.c", "test/t.c"], "test/t.c", True),
        # A product CLI over the library sources: `main` in tools/.
        (["src/a.c", "tools/cli.c"], "tools/cli.c", False),
        # A test driver compiling product code no library holds: dropping it would lose that code.
        (["src/a.c", "src/only_here.c", "test/t.c"], "test/t.c", False),
        # Library sources only, `main` among them: no test source at all.
        (["src/a.c", "src/main.c"], "src/main.c", False),
        # `main` not found (the symbol probe failed): left as it is.
        (["src/a.c", "test/t.c"], None, False),
    ],
)
def test_only_drivers_with_main_in_a_test_source_over_library_sources_are_marked(files, main, marked):
    units = {
        "libx.a": _unit("static_lib", ["src/a.c", "src/main.c"]),
        "libtestonly.a": _unit("static_lib", ["src/only_here.c"], test=True),
        "app": _unit("executable", files),
    }
    got = bc.mark_test_drivers(units, {"app": main} if main else {})
    assert (got == ["app"]) is marked
    assert units["app"]["test"] is marked
    assert units["app"]["test_reason"] == ("main_in_test_source" if marked else None)
    assert not units["libx.a"]["test"]


@pytest.mark.unit
@pytest.mark.parametrize(
    ("others", "marked"),
    [
        # mpack run-3: an example program holds the product sources, no library.
        ({"examples/ex": _unit("executable", ["examples/ex.c", "src/a.c"])}, True),
        # Objects linked into nothing are analysed as product code: they hold their sources too.
        ({"unlinked:src": _unit("unlinked", ["src/a.c"])}, True),
        # A shared library holds them like a static one.
        ({"libx.so": _unit("shared_lib", ["src/a.c"])}, True),
        # A test unit is not analysed: it holds nothing.
        ({"testlib.a": _unit("static_lib", ["src/a.c"], test=True)}, False),
        # A second driver over the same product code: neither may drop it for the other.
        ({"runner2": _unit("executable", ["src/a.c", "test/t2.c"])}, False),
        # The same two drivers next to a library holding the code: both are marked.
        (
            {
                "runner2": _unit("executable", ["src/a.c", "test/t2.c"]),
                "liba.a": _unit("static_lib", ["src/a.c"]),
            },
            True,
        ),
    ],
)
def test_a_driver_is_marked_only_when_another_product_unit_holds_its_sources(others, marked):
    units = {"app": _unit("executable", ["src/a.c", "test/t.c"]), **others}
    mains = {"app": "test/t.c", "runner2": "test/t2.c", "examples/ex": "examples/ex.c"}
    got = bc.mark_test_drivers(units, {n: m for n, m in mains.items() if n in units})
    assert units["app"]["test"] is marked
    assert ("app" in got) is marked
    if "runner2" in units:
        assert units["runner2"]["test"] is marked
    assert all(not u["test"] for n, u in units.items() if n not in ("app", "runner2", "testlib.a"))


# ---------------------------------------------------------------- semantic compiler flags (Tier 2 Part A)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (["cc", "-fwrapv", "-c", "a.c"], ["-fwrapv"]),
        (["cc", "-fno-strict-overflow", "-c", "a.c"], ["-fno-strict-overflow"]),
        (["cc", "-funsigned-char", "-c", "a.c"], ["-funsigned-char"]),
        (["cc", "-fno-signed-char", "-c", "a.c"], ["-funsigned-char"]),
        (["cc", "-fshort-enums", "-c", "a.c"], ["-fshort-enums"]),
        (["cc", "-fpack-struct", "-c", "a.c"], ["-fpack-struct"]),
        (["cc", "-fpack-struct=1", "-c", "a.c"], ["-fpack-struct=1"]),
        (["cc", "-fpack-struct=4", "-c", "a.c"], ["-fpack-struct=4"]),
        (["cc", "-fshort-wchar", "-c", "a.c"], ["-fshort-wchar"]),
        (["cc", "-funsigned-bitfields", "-c", "a.c"], ["-funsigned-bitfields"]),
        (["cc", "-fno-signed-bitfields", "-c", "a.c"], ["-funsigned-bitfields"]),
        # Negating pairs: last flag wins in both directions.
        (["cc", "-fwrapv", "-fno-wrapv", "-c", "a.c"], []),
        (["cc", "-fno-wrapv", "-fwrapv", "-c", "a.c"], ["-fwrapv"]),
        (["cc", "-fno-strict-overflow", "-fstrict-overflow", "-c", "a.c"], []),
        (["cc", "-fstrict-overflow", "-fno-strict-overflow", "-c", "a.c"], ["-fno-strict-overflow"]),
        (["cc", "-funsigned-char", "-fsigned-char", "-c", "a.c"], []),
        (["cc", "-funsigned-char", "-fno-unsigned-char", "-c", "a.c"], []),
        (["cc", "-fsigned-char", "-fno-signed-char", "-c", "a.c"], ["-funsigned-char"]),
        (["cc", "-fshort-enums", "-fno-short-enums", "-c", "a.c"], []),
        (["cc", "-fno-short-enums", "-fshort-enums", "-c", "a.c"], ["-fshort-enums"]),
        (["cc", "-fshort-wchar", "-fno-short-wchar", "-c", "a.c"], []),
        (["cc", "-fno-short-wchar", "-fshort-wchar", "-c", "a.c"], ["-fshort-wchar"]),
        (["cc", "-funsigned-bitfields", "-fsigned-bitfields", "-c", "a.c"], []),
        (["cc", "-funsigned-bitfields", "-fno-unsigned-bitfields", "-c", "a.c"], []),
        (["cc", "-fsigned-bitfields", "-fno-signed-bitfields", "-c", "a.c"], ["-funsigned-bitfields"]),
        # -fpack-struct prefix/value precedence.
        (["cc", "-fpack-struct=2", "-fpack-struct=4", "-c", "a.c"], ["-fpack-struct=4"]),
        (["cc", "-fpack-struct=4", "-fpack-struct", "-c", "a.c"], ["-fpack-struct"]),
        (["cc", "-fpack-struct=1", "-fno-pack-struct", "-c", "a.c"], []),
        (["cc", "-fpack-struct=2", "-fpack-struct=0", "-c", "a.c"], []),
        (["cc", "-fpack-struct", "-fpack-struct=0", "-c", "a.c"], []),
        (["cc", "-fpack-struct=0", "-fpack-struct=8", "-c", "a.c"], ["-fpack-struct=8"]),
        # Option-argument immunity (_ARG_OPTS operands are skipped).
        (["cc", "-D", "FOO=-fwrapv", "-o", "-fwrapv", "-I", "-fshort-enums", "-c", "a.c"], []),
        (["cc", "-DFOO=-funsigned-char", "-c", "a.c"], []),
        # Canonical ordering across multiple active families.
        (
            ["cc", "-funsigned-bitfields", "-fpack-struct=2", "-fwrapv", "-fno-signed-char", "-c", "a.c"],
            ["-fwrapv", "-funsigned-char", "-fpack-struct=2", "-funsigned-bitfields"],
        ),
    ],
)
def test_extract_semantic_flags(args: list[str], expected: list[str]):
    assert bc.extract_semantic_flags(args) == expected


@pytest.mark.unit
def test_response_file_expansion_propagates_semantic_flags(tmp_path):
    tree = tmp_path / "tree"
    tree.mkdir()
    rsp = tree / "flags.rsp"
    rsp.write_text("-fwrapv -fpack-struct=2 -fno-signed-char\n", encoding="utf-8")
    execs = [
        {"exe": "/usr/bin/cc", "args": ["cc", "@flags.rsp", "-c", "a.c", "-o", "a.o"], "cwd": tree.as_posix()},
    ]
    cap = bc.classify_executions(execs, tree.as_posix())
    assert cap["compiles"]["a.o"]["semantic_flags"] == ["-fwrapv", "-funsigned-char", "-fpack-struct=2"]


@pytest.mark.unit
def test_unit_semantic_flags_uniform_partial_and_conflicting():
    # Uniform across all compiles -> scope: "all".
    uniform = bc.unit_semantic_flags(
        [
            {"source": "a.c", "semantic_flags": ["-fwrapv"]},
            {"source": "b.c", "semantic_flags": ["-fwrapv"]},
        ]
    )
    assert uniform == [
        {"flag": "-fwrapv", "family": "wrapv", "category": "overflow", "scope": "all", "files": ["a.c", "b.c"]}
    ]

    # Partial -> only affected files listed, scope: "partial".
    partial = bc.unit_semantic_flags(
        [
            {"source": "a.c", "semantic_flags": ["-fwrapv"]},
            {"source": "b.c", "semantic_flags": []},
        ]
    )
    assert partial == [
        {"flag": "-fwrapv", "family": "wrapv", "category": "overflow", "scope": "partial", "files": ["a.c"]}
    ]

    # Conflicting values in one link unit -> two separate entries, both scope: "partial".
    conflicting = bc.unit_semantic_flags(
        [
            {"source": "a.c", "semantic_flags": ["-fpack-struct=1"]},
            {"source": "b.c", "semantic_flags": ["-fpack-struct=4"]},
        ]
    )
    assert conflicting == [
        {
            "flag": "-fpack-struct=1",
            "family": "pack_struct",
            "category": "layout",
            "scope": "partial",
            "files": ["a.c"],
        },
        {
            "flag": "-fpack-struct=4",
            "family": "pack_struct",
            "category": "layout",
            "scope": "partial",
            "files": ["b.c"],
        },
    ]
    assert bc.unit_semantic_flags([]) == []


@pytest.mark.unit
def test_analyse_and_cmd_run_semantic_flags_warnings_schema_and_snapshot_digest(tmp_path, monkeypatch, capsys):
    snap_src = tmp_path / "ext.h"
    snap_src.write_text("#define EXT 1\n", encoding="utf-8")

    def _run_case(prod_flags_a: list[str], prod_flags_b: list[str], test_flags: list[str], subdir: str):
        base = tmp_path / subdir
        base.mkdir(parents=True, exist_ok=True)
        tree = base / "tree"
        target = base / "target"
        for f in ("src/a.c", "src/b.c", "tests/t.c"):
            (tree / f).parent.mkdir(parents=True, exist_ok=True)
            (tree / f).write_text("int f(void) { return 0; }\n", encoding="utf-8")
            (target / f).parent.mkdir(parents=True, exist_ok=True)
            (target / f).write_text("int f(void) { return 0; }\n", encoding="utf-8")
        t_posix = tree.as_posix()
        execs = [
            _cc(t_posix, *prod_flags_a, "-c", "-o", "a.o", "src/a.c"),
            _cc(t_posix, *prod_flags_b, "-c", "-o", "b.o", "src/b.c"),
            {"exe": "/usr/bin/ar", "args": ["ar", "rcs", "libdemo.a", "a.o", "b.o"], "cwd": t_posix},
            _cc(t_posix, *test_flags, "-o", "tests/runner", "tests/t.c"),
        ]
        cap = bc.classify_executions(execs, t_posix)
        monkeypatch.chdir(base)
        monkeypatch.setattr(bc, "compile_deps", lambda c, t: ([c["object"], snap_src.as_posix()], None))
        monkeypatch.setattr(bc, "compile_symbols", lambda c, t, tmp, i: ({"f": ("T", None)}, None))
        monkeypatch.setattr(bc, "try_install", lambda *a: ([], "no install"))
        monkeypatch.setattr(bc, "run_tool", lambda *a, **k: (0, "", ""))
        monkeypatch.setattr(
            bc,
            "classify_system_paths",
            lambda paths: {p: {"package": "libext-dev", "class": "package"} for p in paths},
        )
        report: dict = {
            "schema_version": bc.SCHEMA_VERSION,
            "generated_at": "2026-11-20T00:00:00Z",
            "status": bc.STATUS_OK,
            "target": target.as_posix(),
            "build": {
                "returncode": 0,
                "timed_out": False,
                "seconds": 0.1,
                "executions": len(execs),
                "log": "build.log",
                "events": "events.jsonl",
            },
            "warnings": [],
            "seconds": 0.2,
        }
        bc.analyse(report, cap, tree, base / "scratch", {}, 60, 1)
        assert bc.validate_report(report) == []

        monkeypatch.setattr(bc, "capture", lambda a: (report, 0))
        out_path = base / "out.json"
        ns = argparse.Namespace(target=target.as_posix(), out=str(out_path), state="")
        rc = bc.cmd_run(ns)
        assert rc == 0
        summary = json.loads(capsys.readouterr().out)
        return report, summary

    clean_rep, clean_sum = _run_case([], [], [], "clean")
    assert all(c["semantic_flags"] == [] for c in clean_rep["compiles"])
    assert all(u["semantic_flags"] == [] for u in clean_rep["units"].values())
    assert "semantic_flags" not in clean_sum
    assert not any("semantic compiler flag" in w for w in clean_rep["warnings"])

    # Test-only flags: recorded on test unit, no top-level warning, absent from cmd_run summary.
    testonly_rep, testonly_sum = _run_case([], [], ["-fshort-enums"], "testonly")
    assert testonly_rep["units"]["tests/runner"]["test"] is True
    assert testonly_rep["units"]["tests/runner"]["semantic_flags"] == [
        {"flag": "-fshort-enums", "family": "short_enums", "category": "layout", "scope": "all", "files": ["tests/t.c"]}
    ]
    assert not any("semantic compiler flag" in w for w in testonly_rep["warnings"])
    assert "semantic_flags" not in testonly_sum

    # Non-test unit with partial + uniform flags: warning emitted, cmd_run summary populated, snapshot digest unchanged.
    flagged_rep, flagged_sum = _run_case(["-fwrapv", "-fpack-struct=2"], ["-fwrapv"], ["-fshort-enums"], "flagged")
    lib = flagged_rep["units"]["libdemo.a"]
    assert lib["semantic_flags"] == [
        {"flag": "-fwrapv", "family": "wrapv", "category": "overflow", "scope": "all", "files": ["src/a.c", "src/b.c"]},
        {
            "flag": "-fpack-struct=2",
            "family": "pack_struct",
            "category": "layout",
            "scope": "partial",
            "files": ["src/a.c"],
        },
    ]
    assert any(
        "libdemo.a: built with semantic compiler flag(s) -fwrapv, -fpack-struct=2 (partial: 1/2 files)" in w
        for w in flagged_rep["warnings"]
    )
    assert flagged_sum["semantic_flags"] == {"libdemo.a": ["-fwrapv", "-fpack-struct=2"]}
    assert flagged_rep["snapshot"]["digest"] == clean_rep["snapshot"]["digest"]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
