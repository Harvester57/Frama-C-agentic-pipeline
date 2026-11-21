"""
The files a harness pulls in for the names its code uses (generate_harness._merge_dag_harness_sources).

sudo run-1, Phase 0 build-check #4: the imported fuzzer `lib/util/regress/fuzz/fuzz_sudo_conf.c` of the
library unit `libsudo_util_so_0_0_0` pulled the sudo front end (`src/*.c`) into its harness (51 sources
became 165), and the link repair then compiled `src/sudo.c` with the library's flags ("use of undeclared
identifier 'LOCALEDIR'"). Three names did it:

- `disable_coredump`, only inside the string literal "Set disable_coredump %s", resolved to sudo's
  `src/limits.c`; `output`, only in the comment `/* no output for fuzzers */`, to `plugins/sudoers`.
  Names in comments and literals are no reference.
- `getenv`, a real call to libc's, resolved to the interposer sudo's own program defines in
  `src/env_hooks.c`. A system function (declared by the fuzzer's system headers, or called by a unit of
  the target as an external function) resolves only to a definition the harness's link can hold: its
  unit, what the unit links, and, for a library, the project libraries a program links alongside it.
  Any other name still resolves wherever it is defined: sudo's fuzz_sudoers links visudo's
  check_aliases.o, and fuzz_sudoers_ldif cvtsudoers' parse_ldif.o.
"""

from __future__ import annotations

import json
from pathlib import Path

import generate_harness as G

TFS_DRIVER = "lib/io/regress/fuzz/fuzz_json.c"

# Two libraries a program links together (no links of their own, as static archives record), a program
# that links the utility library and interposes libc's getenv and putenv, a log daemon linking the
# libraries and calling libc's getenv, and a tool whose own file defines a project function.
TFS_DAG: dict = {
    "module_kind": "link_unit",
    "target_dir": "/framac-run/workspace/work",
    "modules": {
        "libio_a": {
            "unit": "lib/io/.libs/libio.a",
            "kind": "static_lib",
            "files": ["lib/io/json.c"],
            "required_sources": ["lib/io/json.c"],
            "linked_modules": [],
        },
        "libev_a": {
            "unit": "lib/ev/.libs/libev.a",
            "kind": "static_lib",
            "files": ["lib/ev/free.c", "lib/ev/reset.c"],
            "required_sources": ["lib/ev/free.c", "lib/ev/reset.c"],
            "linked_modules": [],
        },
        "libutil_so": {
            "unit": "lib/util/.libs/libutil.so",
            "kind": "shared_lib",
            "files": ["lib/util/progname.c", "lib/util/fmt.c"],
            "required_sources": ["lib/util/progname.c", "lib/util/fmt.c"],
            "linked_modules": [],
        },
        "prog": {
            "unit": "src/.libs/prog",
            "kind": "executable",
            "files": ["src/main.c", "src/env_hooks.c", "src/limits.c", "src/fmt.c", "lib/compat/strlcpy.c"],
            "required_sources": [
                "src/main.c",
                "src/env_hooks.c",
                "src/limits.c",
                "src/fmt.c",
                "lib/compat/strlcpy.c",
                "lib/util/progname.c",
                "lib/util/fmt.c",
            ],
            "linked_modules": ["libutil_so"],
        },
        "logd": {
            "unit": "logd/.libs/logd",
            "kind": "executable",
            "files": ["logd/logd.c"],
            "required_sources": ["logd/logd.c", "lib/io/json.c", "lib/ev/free.c", "lib/ev/reset.c"],
            "linked_modules": ["libio_a", "libev_a", "libutil_so"],
            "external_callees": ["getenv", "memcpy"],
        },
        "tool": {
            "unit": "tools/.libs/tool",
            "kind": "executable",
            "files": ["tools/check.c"],
            "required_sources": ["tools/check.c", "lib/util/progname.c", "lib/util/fmt.c"],
            "linked_modules": ["libutil_so"],
        },
        # An archive nothing links in the project, calling back what its users define (sudo's fuzz stubs).
        "libcb_a": {
            "unit": "lib/cb/.libs/libcb.a",
            "kind": "static_lib",
            "files": ["lib/cb/cb.c"],
            "required_sources": ["lib/cb/cb.c"],
            "linked_modules": [],
            "external_callees": ["progname_init"],
        },
    },
    "macro_aliases": {"strdup": "alias_check"},
    "functions": {
        "json_parse": {"name": "json_parse", "file": "lib/io/json.c", "module": "libio_a", "lexer_module": "io"},
        "ev_free": {"name": "ev_free", "file": "lib/ev/free.c", "module": "libev_a", "lexer_module": "evfree"},
        "ev_reset": {"name": "ev_reset", "file": "lib/ev/reset.c", "module": "libev_a", "lexer_module": "evreset"},
        "progname_init": {
            "name": "progname_init",
            "file": "lib/util/progname.c",
            "module": "libutil_so",
            "lexer_module": "progname",
        },
        "getenv": {"name": "getenv", "file": "src/env_hooks.c", "module": "prog", "lexer_module": "src"},
        "putenv": {"name": "putenv", "file": "src/env_hooks.c", "module": "prog", "lexer_module": "src"},
        "disable_coredump": {
            "name": "disable_coredump",
            "file": "src/limits.c",
            "module": "prog",
            "lexer_module": "src",
        },
        # Compiled into the program and the I/O library (its `units`), owned by the program.
        "strlcpy": {
            "name": "strlcpy",
            "file": "lib/compat/strlcpy.c",
            "module": "prog",
            "units": ["src/.libs/prog", "lib/io/.libs/libio.a"],
            "lexer_module": "compat",
        },
        "lib/util/fmt.c#fmt": {"name": "fmt", "file": "lib/util/fmt.c", "module": "libutil_so", "lexer_module": "fmt"},
        "src/fmt.c#fmt": {"name": "fmt", "file": "src/fmt.c", "module": "prog", "lexer_module": "src"},
        "alias_check": {"name": "alias_check", "file": "tools/check.c", "module": "tool", "lexer_module": "tools"},
        "logd_main": {"name": "logd_main", "file": "logd/logd.c", "module": "logd", "lexer_module": "logd"},
    },
    "lexer_modules": {
        "io": {"required_sources": ["lib/io/json.c"]},
        "evfree": {"required_sources": ["lib/ev/free.c"]},
        "evreset": {"required_sources": ["lib/ev/reset.c"]},
        "progname": {"required_sources": ["lib/util/progname.c"]},
        "fmt": {"required_sources": ["lib/util/fmt.c"]},
        "compat": {"required_sources": ["lib/compat/strlcpy.c"]},
        "src": {"required_sources": ["src/main.c", "src/env_hooks.c", "src/limits.c", "src/fmt.c"]},
        "tools": {"required_sources": ["tools/check.c"]},
        "logd": {"required_sources": ["logd/logd.c"]},
    },
}

TFS_IO_SOURCES = ["lib/io/json.c"]
TFS_PROG_SOURCES = ["src/main.c", "src/env_hooks.c", "src/limits.c", "src/fmt.c"]
TFS_UTIL_SOURCES = ["lib/util/progname.c", "lib/util/fmt.c"]


def _tfs_run(tmp_path: Path) -> Path:
    (tmp_path / "workspace/reports").mkdir(parents=True)
    (tmp_path / "workspace/reports/callgraph_dag.json").write_text(json.dumps(TFS_DAG), encoding="utf-8")
    (tmp_path / "workspace/harnesses").mkdir(parents=True)
    return tmp_path


def _tfs_merge(run: Path, snippet: str, **kw) -> list[str]:
    return G._merge_dag_harness_sources(run / "workspace/harnesses", list(TFS_IO_SOURCES), False, snippet, **kw)


def test_names_in_comments_and_literals_pull_in_nothing(tmp_path):
    run = _tfs_run(tmp_path)
    driver = (
        "/* disable_coredump is never called here */\n"
        "// nor ev_reset\n"
        "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {\n"
        "    log_line(\"Set ev_free %s\", 'x');\n"
        "    return json_parse(data, size);\n"
        "}\n"
    )
    # Without a unit too: what the code does not name is no reference, whatever the link.
    assert _tfs_merge(run, driver, module_name="tf_fuzz_json") == TFS_IO_SOURCES
    assert _tfs_merge(run, driver, module_name="tf_fuzz_json", unit="libio_a") == TFS_IO_SOURCES
    # The same names in code do pull their files in.
    merged = _tfs_merge(run, "ev_free(e); ev_reset(e);", module_name="tf_fuzz_json")
    assert merged == [*TFS_IO_SOURCES, "lib/ev/free.c", "lib/ev/reset.c"]


def test_a_system_function_another_program_interposes_pulls_in_nothing(tmp_path):
    run = _tfs_run(tmp_path)
    driver = 'int f(void) { const char *h = getenv("HOME"); putenv("A=1"); return h != 0; }\n'
    meta: dict = {}
    # getenv: the log daemon calls it as libc's (an external callee its link defines nowhere).
    # putenv: the fuzzer's system headers declare it.
    merged = _tfs_merge(
        run, driver, module_name="tf_fuzz_json", unit="libio_a", flow_meta=meta, system_names={"putenv", "memcpy"}
    )
    assert merged == TFS_IO_SOURCES
    assert meta["names_outside_link"] == [
        {"name": "getenv", "definitions": ["getenv"]},
        {"name": "putenv", "definitions": ["putenv"]},
    ]
    # The unit given by its path, not its key, is the same link.
    assert _tfs_merge(run, driver, module_name="h", unit="lib/io/.libs/libio.a", system_names={"putenv"}) == (
        TFS_IO_SOURCES
    )


def test_a_project_function_of_another_program_still_resolves(tmp_path):
    # sudo's fuzz_sudoers links visudo's check_aliases.o: a project name is meant wherever it is defined.
    run = _tfs_run(tmp_path)
    meta: dict = {}
    merged = _tfs_merge(run, "alias_check(t); disable_coredump();", module_name="h", unit="libio_a", flow_meta=meta)
    assert merged == [*TFS_IO_SOURCES, "tools/check.c", *TFS_UTIL_SOURCES, *TFS_PROG_SOURCES]
    assert "names_outside_link" not in meta


def test_what_an_archive_calls_is_no_system_function(tmp_path):
    # Only a final link (a program, a shared library) says a name is resolved outside the project.
    run = _tfs_run(tmp_path)
    out = run / "workspace/harnesses"
    merged = G._merge_dag_harness_sources(
        out, ["lib/cb/cb.c"], False, "progname_init()", module_name="h", unit="libcb_a"
    )
    assert merged == ["lib/cb/cb.c", "lib/util/progname.c"]


def test_a_macro_alias_is_judged_by_the_function_it_names(tmp_path):
    # `strdup` is a system name, but the build makes it the tool's project function alias_check.
    run = _tfs_run(tmp_path)
    merged = _tfs_merge(run, "strdup(s)", module_name="h", unit="libio_a", system_names={"strdup"})
    assert merged == [*TFS_IO_SOURCES, "tools/check.c", *TFS_UTIL_SOURCES]


def test_a_library_harness_keeps_the_libraries_a_program_links_with_it(tmp_path):
    run = _tfs_run(tmp_path)
    merged = _tfs_merge(
        run,
        'progname_init(); ev_free(e); getenv("X");',
        module_name="tf_fuzz_json",
        unit="libio_a",
        system_names={"progname_init", "ev_free"},
    )
    assert merged == [*TFS_IO_SOURCES, "lib/ev/free.c", "lib/util/progname.c"]


def test_a_definition_compiled_into_the_unit_is_its_own(tmp_path):
    # strlcpy's file is the program's, but the I/O library compiles it too (`units`).
    run = _tfs_run(tmp_path)
    merged = _tfs_merge(run, "strlcpy(d, s, n)", module_name="h", unit="libio_a", system_names={"strlcpy"})
    assert merged == [*TFS_IO_SOURCES, "lib/compat/strlcpy.c", *TFS_UTIL_SOURCES]


def test_the_unit_itself_and_what_it_links_still_resolve(tmp_path):
    run = _tfs_run(tmp_path)
    out = run / "workspace/harnesses"
    # The program's own interposer is its getenv (with the library the program links, as before).
    merged = G._merge_dag_harness_sources(
        out, ["src/main.c"], False, "getenv", module_name="h", unit="prog", system_names={"getenv"}
    )
    assert merged == [*TFS_PROG_SOURCES, *TFS_UTIL_SOURCES]


def test_a_name_defined_in_several_programs_resolves_to_the_one_the_link_holds(tmp_path):
    run = _tfs_run(tmp_path)
    # Two external `fmt`: ambiguous without a unit, the library's for a harness of a library.
    assert _tfs_merge(run, "fmt(b)", module_name="tf_fuzz_json") == TFS_IO_SOURCES
    assert _tfs_merge(run, "fmt(b)", module_name="tf_fuzz_json", unit="libio_a") == [
        *TFS_IO_SOURCES,
        "lib/util/fmt.c",
    ]


def test_without_a_unit_a_name_resolves_as_before(tmp_path):
    run = _tfs_run(tmp_path)
    merged = _tfs_merge(run, "getenv", module_name="tf_fuzz_json", system_names={"getenv"})
    assert merged == [*TFS_IO_SOURCES, *TFS_PROG_SOURCES, *TFS_UTIL_SOURCES]


def test_system_names_are_what_system_headers_declare():
    pre = (
        '# 1 "fuzz.c"\n'
        '# 1 "/usr/include/stdlib.h" 1 3 4\n'
        "extern char *getenv (const char *__name) __attribute__ ((__nothrow__));\n"
        '# 3 "fuzz.c" 2\n'
        '# 1 "include/util.h" 1\n'
        "void progname_init(const char *n);\n"
        '# 5 "fuzz.c" 2\n'
        "int f(void) { return helper(1); }\n"
    )
    names = G._system_declared_names(pre)
    assert "getenv" in names
    assert not names & {"progname_init", "helper", "f"}


def test_the_target_fuzzer_sidecar_holds_no_other_program_and_says_what_it_left(tmp_path, monkeypatch):
    from validate_artifacts import schema_warning

    run = _tfs_run(tmp_path)
    monkeypatch.chdir(run)
    driver = f"workspace/work/{TFS_DRIVER}"
    # What `gcc -E` of the driver gives: putenv from a system header, the driver's own lines after.
    preprocessed = (
        f'# 1 "{driver}"\n'
        '# 1 "/usr/include/stdlib.h" 1 3 4\n'
        "extern int putenv (char *__string);\n"
        f'# 2 "{driver}" 2\n'
        "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return 0; }\n"
    )
    monkeypatch.setattr(G, "_preprocess_driver", lambda path, cppflags: preprocessed)
    files = {
        "lib/io/json.c": "int json_parse(const unsigned char *b, unsigned long n) { return n ? b[0] : 0; }\n",
        "lib/ev/free.c": "void ev_free(void *e) { (void)e; }\n",
        "lib/ev/reset.c": "void ev_reset(void *e) { (void)e; }\n",
        "lib/util/progname.c": "void progname_init(const char *n) { (void)n; }\n",
        "lib/util/fmt.c": "int fmt(int b) { return b; }\n",
        "lib/compat/strlcpy.c": "unsigned long strlcpy(char *d, const char *s, unsigned long n) { return 0; }\n",
        "src/main.c": "int main(void) { return 0; }\n",
        "src/env_hooks.c": "char *getenv(const char *n) { (void)n; return 0; }\nint putenv(char *s) { return 0; }\n",
        "src/limits.c": "void disable_coredump(void) { }\n",
        "src/fmt.c": "int fmt(int b) { return -b; }\n",
        "tools/check.c": "int alias_check(void *t) { return t != 0; }\n",
        "logd/logd.c": "int logd_main(void) { return 0; }\n",
        TFS_DRIVER: (
            "#include <stdint.h>\n#include <stddef.h>\n#include <stdlib.h>\n#include <stdio.h>\n"
            "int json_parse(const uint8_t *b, size_t n);\nvoid progname_init(const char *n);\n"
            "/* no output, ev_reset is not called */\n"
            "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
            '    if (getenv("FUZZ_VERBOSE")) printf("Set disable_coredump %d\\n", 1);\n'
            '    putenv("FUZZ=1");\n'
            '    progname_init("fuzz");\n'
            "    return json_parse(data, size);\n"
            "}\n"
        ),
    }
    for rel, text in files.items():
        p = run / "workspace/work" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    argv = ["--module", "tf_fuzz_json", "--unit", "libio_a", "--target-fuzzer", driver]
    argv += ["--no-auto-prelude", "--sources", "workspace/work/lib/io/json.c", "--cppflags", "-Iworkspace/work/lib/io"]
    assert G.main(argv) == 0
    side = json.loads((run / "workspace/harnesses/harness_tf_fuzz_json.json").read_text(encoding="utf-8"))
    assert sorted(side["sources"]) == sorted(
        ["workspace/work/lib/io/json.c", driver, "workspace/work/lib/util/progname.c"]
    )
    assert side["names_outside_link"] == [
        {"name": "getenv", "definitions": ["getenv"]},
        {"name": "putenv", "definitions": ["putenv"]},
    ]
    assert schema_warning("harness_sidecar", side) is None
