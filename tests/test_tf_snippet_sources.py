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
  `src/env_hooks.c`. A name resolves only to a definition the harness's link can hold: its unit, what the
  unit links, and, for a library, the project libraries a program links alongside it (a static archive
  records no links of its own: `libsudo_iolog_a`'s fuzzers call `libsudo_util` and `libsudo_eventlog`).
"""

from __future__ import annotations

import json
from pathlib import Path

import generate_harness as G

TFS_DRIVER = "lib/io/regress/fuzz/fuzz_json.c"

# Two libraries a program links together (no links of their own, as static archives record), a program
# that links the utility library and defines an interposer of libc's getenv, and a log daemon linking all.
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
            "files": ["src/main.c", "src/env_hooks.c", "src/limits.c", "src/fmt.c"],
            "required_sources": [
                "src/main.c",
                "src/env_hooks.c",
                "src/limits.c",
                "src/fmt.c",
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
        },
    },
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
        "disable_coredump": {
            "name": "disable_coredump",
            "file": "src/limits.c",
            "module": "prog",
            "lexer_module": "src",
        },
        "lib/util/fmt.c#fmt": {"name": "fmt", "file": "lib/util/fmt.c", "module": "libutil_so", "lexer_module": "fmt"},
        "src/fmt.c#fmt": {"name": "fmt", "file": "src/fmt.c", "module": "prog", "lexer_module": "src"},
        "logd_main": {"name": "logd_main", "file": "logd/logd.c", "module": "logd", "lexer_module": "logd"},
    },
    "lexer_modules": {
        "io": {"required_sources": ["lib/io/json.c"]},
        "evfree": {"required_sources": ["lib/ev/free.c"]},
        "evreset": {"required_sources": ["lib/ev/reset.c"]},
        "progname": {"required_sources": ["lib/util/progname.c"]},
        "fmt": {"required_sources": ["lib/util/fmt.c"]},
        "src": {"required_sources": ["src/main.c", "src/env_hooks.c", "src/limits.c", "src/fmt.c"]},
        "logd": {"required_sources": ["logd/logd.c"]},
    },
}

TFS_IO_SOURCES = ["lib/io/json.c"]
TFS_PROG_SOURCES = ["src/main.c", "src/env_hooks.c", "src/limits.c", "src/fmt.c"]


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
        "/* ev_free is never called here */\n"
        "// nor ev_reset\n"
        "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {\n"
        "    log_line(\"Set ev_reset %s\", 'x');\n"
        "    return json_parse(data, size);\n"
        "}\n"
    )
    # Without a unit too: what the code does not name is no reference, whatever the link.
    assert _tfs_merge(run, driver, module_name="tf_fuzz_json") == TFS_IO_SOURCES
    # The same names in code do pull their files in (both libraries are linked together by logd).
    merged = _tfs_merge(run, "ev_free(e); ev_reset(e);", module_name="tf_fuzz_json")
    assert merged == [*TFS_IO_SOURCES, "lib/ev/free.c", "lib/ev/reset.c"]


def test_a_name_defined_only_by_another_program_pulls_in_nothing(tmp_path):
    run = _tfs_run(tmp_path)
    driver = 'int f(void) { const char *h = getenv("HOME"); disable_coredump(); return h != 0; }\n'
    meta: dict = {}
    merged = _tfs_merge(run, driver, module_name="tf_fuzz_json", unit="libio_a", flow_meta=meta)
    assert merged == TFS_IO_SOURCES
    assert meta["names_outside_link"] == [
        {"name": "disable_coredump", "definitions": ["disable_coredump"]},
        {"name": "getenv", "definitions": ["getenv"]},
    ]


def test_a_library_harness_keeps_the_libraries_a_program_links_with_it(tmp_path):
    run = _tfs_run(tmp_path)
    merged = _tfs_merge(run, 'progname_init(); ev_free(e); getenv("X");', module_name="tf_fuzz_json", unit="libio_a")
    assert merged == [*TFS_IO_SOURCES, "lib/ev/free.c", "lib/util/progname.c"]


def test_the_unit_itself_and_what_it_links_still_resolve(tmp_path):
    run = _tfs_run(tmp_path)
    out = run / "workspace/harnesses"
    # The program's own interposer is its getenv (with the library the program links, as before).
    merged = G._merge_dag_harness_sources(out, ["src/main.c"], False, "getenv", module_name="h", unit="prog")
    assert merged == [*TFS_PROG_SOURCES, "lib/util/progname.c", "lib/util/fmt.c"]
    # The program does not link the event library, nor does anything link it with the program.
    merged = G._merge_dag_harness_sources(out, ["src/main.c"], False, "ev_free", module_name="h", unit="prog")
    assert merged == ["src/main.c"]


def test_a_name_defined_in_several_units_resolves_to_the_one_the_link_holds(tmp_path):
    run = _tfs_run(tmp_path)
    # Two external `fmt`: ambiguous without a unit, the library's for a harness of a library.
    assert _tfs_merge(run, "fmt(b)", module_name="tf_fuzz_json") == TFS_IO_SOURCES
    assert _tfs_merge(run, "fmt(b)", module_name="tf_fuzz_json", unit="libio_a") == [
        *TFS_IO_SOURCES,
        "lib/util/fmt.c",
    ]


def test_without_a_unit_a_name_resolves_as_before(tmp_path):
    run = _tfs_run(tmp_path)
    merged = _tfs_merge(run, "getenv", module_name="tf_fuzz_json")
    assert merged == [*TFS_IO_SOURCES, *TFS_PROG_SOURCES, "lib/util/progname.c", "lib/util/fmt.c"]


def test_the_target_fuzzer_sidecar_holds_no_other_program_and_says_what_it_left(tmp_path, monkeypatch):
    from validate_artifacts import schema_warning

    run = _tfs_run(tmp_path)
    monkeypatch.chdir(run)
    monkeypatch.setattr(G, "_preprocess_driver", lambda driver, cppflags: None)
    files = {
        "lib/io/json.c": "int json_parse(const unsigned char *b, unsigned long n) { return n ? b[0] : 0; }\n",
        "lib/ev/free.c": "void ev_free(void *e) { (void)e; }\n",
        "lib/ev/reset.c": "void ev_reset(void *e) { (void)e; }\n",
        "lib/util/progname.c": "void progname_init(const char *n) { (void)n; }\n",
        "lib/util/fmt.c": "int fmt(int b) { return b; }\n",
        "src/main.c": "int main(void) { return 0; }\n",
        "src/env_hooks.c": "char *getenv(const char *n) { (void)n; return 0; }\n",
        "src/limits.c": "void disable_coredump(void) { }\n",
        "src/fmt.c": "int fmt(int b) { return -b; }\n",
        "logd/logd.c": "int logd_main(void) { return 0; }\n",
        TFS_DRIVER: (
            "#include <stdint.h>\n#include <stddef.h>\n#include <stdlib.h>\n#include <stdio.h>\n"
            "int json_parse(const uint8_t *b, size_t n);\nvoid progname_init(const char *n);\n"
            "/* no output, ev_reset is not called */\n"
            "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
            '    if (getenv("FUZZ_VERBOSE")) printf("Set disable_coredump %d\\n", 1);\n'
            '    progname_init("fuzz");\n'
            "    return json_parse(data, size);\n"
            "}\n"
        ),
    }
    for rel, text in files.items():
        p = run / "workspace/work" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    argv = ["--module", "tf_fuzz_json", "--unit", "libio_a", "--target-fuzzer", f"workspace/work/{TFS_DRIVER}"]
    argv += ["--no-auto-prelude", "--sources", "workspace/work/lib/io/json.c", "--cppflags", "-Iworkspace/work/lib/io"]
    assert G.main(argv) == 0
    side = json.loads((run / "workspace/harnesses/harness_tf_fuzz_json.json").read_text(encoding="utf-8"))
    assert sorted(side["sources"]) == sorted(
        [
            "workspace/work/lib/io/json.c",
            f"workspace/work/{TFS_DRIVER}",
            "workspace/work/lib/util/progname.c",
        ]
    )
    assert side["names_outside_link"] == [{"name": "getenv", "definitions": ["getenv"]}]
    assert schema_warning("harness_sidecar", side) is None
