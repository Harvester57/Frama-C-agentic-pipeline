"""
Harness and build gaps sudo run-1 showed (E-ACSL Stage 2, other units' include directories, the prelude
above `config.h`, the target fuzzers' links).

1. The Frama-C kernel prints `unsigned int sudoers_subsystem_ids[sizeof(sudoers_subsystem_names) / ...]`
   at the header's `extern` declaration, before the static table its size reads: clang stops on "use of
   undeclared identifier 'sudoers_subsystem_names'" (eacsl_toolchain.rewrite_forward_array_sizes).
2. A link repair adds `lib/eventlog/parse_json.c` to `libsudo_iolog_a`, whose flags lack `lib/eventlog`:
   "parse_json.h: No such file or directory" (include_context.source_include_dirs).
3. The harness prelude put `sudo_iolog.h` above `config.h`: its `HAVE_ZLIB_H` union member was lost and
   Frama-C found "Definitions of struct iolog_file are not isomorphic" (generate_harness prelude roots).
4. A target fuzzer linked with its whole unit redefines what it overrides: "multiple definition" and
   "has different initializer" (generate_harness.target_fuzzer_link_sources).
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

import eacsl_toolchain as T
import fuzz_build
import generate_harness as G
import include_context as ic
import run_eacsl_fuzz as R
from test_eacsl_toolchain import FakeEacslGcc, _src, modern_cli  # noqa: F401 - modern_cli is a fixture

SHG_REPO = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# 1. A global array printed before the object its size reads
# ---------------------------------------------------------------------------

SHG_SIZE = "sizeof(sudoers_subsystem_names) / sizeof(sudoers_subsystem_names[0]) - (unsigned long)1"

# As the kernel prints sudo's tsdump (instrumented lines 2462, 8323, 8326; shortened).
SHG_PRINTED = f"""struct sudo_debug_file;
unsigned int sudoers_subsystem_ids[{SHG_SIZE}];
int sudoers_debug_register(char const *program);
/* sudoers_subsystem_names in a comment */
char const *note = "sudoers_subsystem_names";
static int sudoers_debug_instance = -1;
unsigned int sudoers_subsystem_ids[{SHG_SIZE}];
static char const * const sudoers_subsystem_names[3] =
  {{"alias", "audit", (char const *)0}};
int sudoers_debug_register(char const *program)
{{
  sudoers_subsystem_ids[0] = 1U;
  return sudoers_debug_instance;
}}
"""


def test_an_array_sized_from_a_later_table_is_declared_incomplete_until_the_table():
    new, info = T.rewrite_forward_array_sizes(SHG_PRINTED)
    assert new.count("\n") == SHG_PRINTED.count("\n")  # the compile log's line numbers stay meaningful
    lines = new.split("\n")
    assert lines[1] == "extern unsigned int sudoers_subsystem_ids[];"
    assert lines[6] == "extern unsigned int sudoers_subsystem_ids[];"
    # The sized definition, unchanged, right after the `;` that ends the table.
    assert lines[8] == f'  {{"alias", "audit", (char const *)0}}; unsigned int sudoers_subsystem_ids[{SHG_SIZE}];'
    assert lines[3] == "/* sudoers_subsystem_names in a comment */"
    assert info == [
        {
            "name": "sudoers_subsystem_ids",
            "size": SHG_SIZE,
            "operands": ["sudoers_subsystem_names"],
            "declarations": 2,
            "line": 2,
        }
    ]


def test_only_extern_declarations_stay_extern_after_the_table():
    text = "extern int ids[sizeof(tab) / sizeof(tab[0])];\nstatic int const tab[4] = {1, 2, 3, 4};\n"
    new, info = T.rewrite_forward_array_sizes(text)
    assert (
        new
        == "extern int ids[];\nstatic int const tab[4] = {1, 2, 3, 4}; extern int ids[sizeof(tab) / sizeof(tab[0])];\n"
    )
    assert info[0]["declarations"] == 1


@pytest.mark.parametrize(
    "text",
    [
        # The table comes first: nothing to move.
        "static int const tab[2] = {1, 2};\nunsigned int ids[sizeof(tab) / sizeof(tab[0])];\n",
        # A literal size, a static array, a typedef.
        "unsigned int ids[18UL];\nstatic int const tab[2] = {1, 2};\n",
        "static unsigned int ids[sizeof(tab)];\nstatic int const tab[2] = {1, 2};\n",
        "typedef unsigned int ids_t[sizeof(tab)];\nstatic int const tab[2] = {1, 2};\n",
        # A size read from a name no file-scope declaration defines.
        "unsigned int ids[sizeof(tab)];\nint f(void)\n{\n  int tab[2];\n  return 0;\n}\n",
        "unsigned int ids[sizeof(nowhere)];\n",
    ],
)
def test_other_array_declarations_are_left_alone(text):
    assert T.rewrite_forward_array_sizes(text) == (text, [])


@pytest.mark.usefixtures("modern_cli")
def test_the_build_rewrites_the_printed_array_and_records_it(tmp_path):
    fake = FakeEacslGcc(instrumented_text=SHG_PRINTED)
    res = R.compile_eacsl_binary([str(_src(tmp_path))], tmp_path / "fuzz_mod", runner=fake, use_cache=False)
    assert res["returncode"] == 0, res
    (rec,) = res["forward_array_sizes"]
    assert rec["name"] == "sudoers_subsystem_ids" and rec["operands"] == ["sudoers_subsystem_names"]
    instrumented = Path(res["instrumented_source"]).read_text(encoding="utf-8")
    assert instrumented.split("\n")[1] == "extern unsigned int sudoers_subsystem_ids[];"
    log = Path(res["compile_log"]).read_text(encoding="utf-8")
    assert "sudoers_subsystem_ids (sized from sudoers_subsystem_names)" in log
    plain = R.compile_eacsl_binary([str(_src(tmp_path))], tmp_path / "plain", runner=FakeEacslGcc(), use_cache=False)
    assert "forward_array_sizes" not in plain


# End to end in the analysis image (FRAMAC_DOCKER_TESTS=1): sudo_debug's shape in two files.
SHG_DBG_H = """#define nitems(a) (sizeof((a)) / sizeof((a)[0]))
/* As sudoers_debug.h: filled in at registration time. */
extern unsigned int sub_ids[];
#define SUB_MAIN (sub_ids[1])
int dbg_register(void);
unsigned int dbg_id(unsigned int i);
"""

SHG_DBG_C = """#include <stddef.h>
#include "dbg.h"

static int dbg_instance = -1;

static const char *const sub_names[] = {
    "alias",
    "main",
    "util",
    NULL
};

#define NUM_SUBSYSTEMS (nitems(sub_names) - 1)

unsigned int sub_ids[NUM_SUBSYSTEMS];

int dbg_register(void)
{
    unsigned int i;
    for (i = 0; sub_names[i] != NULL; i++)
        sub_ids[i] = i + 1;
    dbg_instance = 0;
    return dbg_instance;
}

unsigned int dbg_id(unsigned int i)
{
    return sub_ids[i];
}
"""

SHG_USER_C = """#include <stddef.h>
#include <stdint.h>
#include "dbg.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0)
        return 0;
    dbg_register();
    /* Index 3 is past the 3-element array: the check on sub_ids[i] in dbg_id must stop it (E-ACSL
       reports it as \\initialized, the 12-byte block it registered for the array ending before it). */
    return (int)dbg_id(data[0] % 4) + (int)SUB_MAIN == 1000;
}
"""

SHG_DRIVE_PY = """import json, shutil, sys
from pathlib import Path
sys.path.insert(0, "/repo/scripts")
import run_eacsl_fuzz as R
work = Path("/tmp/w")
shutil.copytree("/fixture", work)
res = R.compile_eacsl_binary(
    [str(work / "user.c"), str(work / "dbg.c")], work / "out" / "fuzz_mod", cppflags=f"-I{work}", use_cache=False
)
keys = ("returncode", "reason", "binary", "forward_array_sizes")
print("SHG_RESULT " + json.dumps({k: res.get(k) for k in keys}))
"""

SHG_DOCKER_SCRIPT = """set -e
timeout 900 python3 /fixture/drive.py
bin=/tmp/w/out/fuzz_mod.e-acsl
[ -x "$bin" ] || exit 0
printf '\\001' > /tmp/in_bounds && printf '\\003' > /tmp/past_end
if timeout 120 "$bin" /tmp/in_bounds > /tmp/a.log 2>&1; then echo SHG_IN_BOUNDS_OK; else tail -5 /tmp/a.log; fi
if timeout 120 "$bin" /tmp/past_end > /tmp/b.log 2>&1; then echo SHG_PAST_END_PASSED; else
  grep -q 'sub_ids\\[i\\]' /tmp/b.log && grep -q 'In function .dbg_id' /tmp/b.log && echo SHG_PAST_END_CAUGHT \\
    || head -12 /tmp/b.log
fi
"""


@pytest.mark.integration
def test_the_printed_forward_array_builds_under_eacsl_and_keeps_its_bounds(tmp_path):
    from conftest import ANALYSIS_IMAGE, require_docker_images

    require_docker_images(ANALYSIS_IMAGE)
    for name, text in (("dbg.h", SHG_DBG_H), ("dbg.c", SHG_DBG_C), ("user.c", SHG_USER_C), ("drive.py", SHG_DRIVE_PY)):
        (tmp_path / name).write_text(text, encoding="utf-8", newline="\n")
    tag = os.environ.get("FRAMAC_RUN_TAG", "pytest-sudo-harness-gaps")
    name = f"framac-test-shg-{tmp_path.name}".lower()
    argv = ["docker", "run", "--rm", "--name", name, "--label", f"framac.run={tag}", "--network", "none"]
    argv += ["-v", f"{tmp_path}:/fixture:ro", "-v", f"{SHG_REPO}:/repo:ro", ANALYSIS_IMAGE, SHG_DOCKER_SCRIPT]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1200)
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
        raise
    out = proc.stdout + proc.stderr
    lines = [ln for ln in proc.stdout.splitlines() if ln.startswith("SHG_RESULT ")]
    assert lines, out[-4000:]
    res = json.loads(lines[-1].split(" ", 1)[1])
    assert res["returncode"] == 0, out[-4000:]
    assert res["binary"].endswith(".e-acsl")
    assert [a["name"] for a in res["forward_array_sizes"]] == ["sub_ids"]
    assert "SHG_IN_BOUNDS_OK" in proc.stdout, out[-4000:]
    assert "SHG_PAST_END_CAUGHT" in proc.stdout, out[-4000:]


# ---------------------------------------------------------------------------
# 2. The include directories of another unit's source
# ---------------------------------------------------------------------------

# As sudo's capture records them: tree-relative flags per compile.
SHG_CAPTURE = {
    "compiles": [
        {
            "source": "lib/iolog/iolog_json.c",
            "flags": ["-I", "include", "-I", ".", "-I", "lib/iolog", "-DHAVE_CONFIG_H"],
        },
        {
            "source": "lib/eventlog/parse_json.c",
            "flags": ["-I", "include", "-I", ".", "-I", "lib/eventlog", "-iquote", "lib/eventlog/q", "-DLOCAL=1"],
        },
        {"source": "lib/util/strlcpy.c", "flags": ["-I", "include", "-I", "/usr/include/sys", "-I", "lib/util"]},
    ],
    "units": {},
}
SHG_IOLOG_FLAGS = "-I. -Iworkspace/work/include -Iworkspace/work -Iworkspace/work/lib/iolog"


def test_a_source_of_another_unit_brings_its_include_directories():
    sources = [
        "workspace/work/lib/iolog/iolog_json.c",
        "workspace/work/lib/eventlog/parse_json.c",
        "lib/util/strlcpy.c",
    ]
    flags, added = ic.source_include_dirs(SHG_IOLOG_FLAGS, sources, SHG_CAPTURE, "/framac-run/workspace/work")
    # Only search directories the flags lack, after them, in the capture's order; never a -D, never a
    # directory outside the tree.
    assert added == [
        "-Iworkspace/work/lib/eventlog",
        "-iquote workspace/work/lib/eventlog/q",
        "-Iworkspace/work/lib/util",
    ]
    assert flags == f"{SHG_IOLOG_FLAGS} {' '.join(added)}"
    assert ic.source_include_dirs(flags, sources, SHG_CAPTURE, "/framac-run/workspace/work") == (flags, [])


def test_a_host_path_to_the_tree_is_spelled_run_relative():
    host = "C:/runs/sudo/run-1/workspace/work"
    _flags, added = ic.source_include_dirs(
        "-Iworkspace/work/lib/eventlog", ["lib/eventlog/parse_json.c"], SHG_CAPTURE, host
    )
    assert added == ["-Iworkspace/work/include", "-Iworkspace/work", "-iquote workspace/work/lib/eventlog/q"]


def _shg_run(tmp_path: Path, capture: dict, dag: dict | None = None) -> Path:
    reports = tmp_path / "workspace/reports"
    reports.mkdir(parents=True)
    (reports / "build_capture.json").write_text(json.dumps(capture), encoding="utf-8")
    dag = dag if dag is not None else {"target_dir": "/framac-run/workspace/work", "functions": {}}
    (reports / "callgraph_dag.json").write_text(json.dumps(dag), encoding="utf-8")
    (tmp_path / "workspace/harnesses").mkdir(parents=True)
    return tmp_path


@pytest.mark.usefixtures("modern_cli")
def test_the_eacsl_build_adds_and_records_the_directories_a_link_repair_needs(tmp_path, monkeypatch):
    _shg_run(tmp_path, SHG_CAPTURE)
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "workspace/work/lib/eventlog/parse_json.c"
    src.parent.mkdir(parents=True)
    src.write_text("int parse(void) { return 0; }\n", encoding="utf-8")
    fake = FakeEacslGcc()
    res = R.compile_eacsl_binary(
        ["workspace/work/lib/eventlog/parse_json.c"],
        tmp_path / "out" / "fuzz_libsudo_iolog_a",
        cppflags=SHG_IOLOG_FLAGS,
        runner=fake,
        use_cache=False,
    )
    assert res["returncode"] == 0, res
    assert res["source_include_dirs"] == ["-Iworkspace/work/lib/eventlog", "-iquote workspace/work/lib/eventlog/q"]
    assert any("-Iworkspace/work/lib/eventlog" in " ".join(call) for call in fake.calls)


def test_the_sanitizer_build_adds_and_records_them_too(tmp_path, monkeypatch):
    _shg_run(tmp_path, SHG_CAPTURE)
    monkeypatch.chdir(tmp_path)
    calls: list[list[str]] = []

    def fake_clang(cmd, **kwargs):
        calls.append(list(cmd))
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    res = fuzz_build.compile_sanitizer_binary(
        ["workspace/work/lib/eventlog/parse_json.c"],
        tmp_path / "out" / "fuzz_libsudo_iolog_a",
        cppflags=SHG_IOLOG_FLAGS,
        runner=fake_clang,
        use_cache=False,
    )
    assert res["source_include_dirs"] == ["-Iworkspace/work/lib/eventlog", "-iquote workspace/work/lib/eventlog/q"]
    assert "-Iworkspace/work/lib/eventlog" in calls[0]


def test_harness_generation_adds_them_to_the_sidecar_flags(tmp_path):
    run = _shg_run(tmp_path, SHG_CAPTURE)
    flags = G._capture_source_include_dirs(
        "libsudo_iolog_a", run / "workspace/harnesses", ["lib/eventlog/parse_json.c"], SHG_IOLOG_FLAGS
    )
    assert flags == f"{SHG_IOLOG_FLAGS} -Iworkspace/work/lib/eventlog -iquote workspace/work/lib/eventlog/q"


# ---------------------------------------------------------------------------
# 3. The prelude goes before the include that needs it, never above config.h
# ---------------------------------------------------------------------------

SHG_LOGSRVD_HARNESS = """#include <stdint.h>
#include <stddef.h>

/* Include module header and external boundary stubs */
#include "config.h"
#include "sudo_compat.h"
#include "logsrvd.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { (void)data; (void)size; return 0; }
"""


class ShgClang:
    """A clang that reports `iolog_fd_t` unknown in logsrvd.h, reached from the harness's `logsrvd.h` include."""

    def __init__(self, harness: Path, header: Path) -> None:
        self.harness, self.header = harness, header
        self.calls = 0

    def __call__(self, cmd, **kwargs):
        self.calls += 1
        text = self.harness.read_text(encoding="utf-8")
        lines = text.splitlines()
        if any("sudo_iolog.h" in ln for ln in lines):
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        at = next(i for i, ln in enumerate(lines) if ln.strip() == '#include "logsrvd.h"') + 1
        stderr = (
            f"In file included from {self.harness.as_posix()}:{at}:\n"
            f"{self.header.as_posix()}:3:5: error: unknown type name 'iolog_fd_t'\n"
        )
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr=stderr)


def test_a_prelude_header_goes_before_the_include_that_needs_it_not_above_config_h(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "config.h").write_text("#define HAVE_ZLIB_H 1\n", encoding="utf-8")
    (src / "sudo_compat.h").write_text("int sudo_compat(void);\n", encoding="utf-8")
    logsrvd_h = src / "logsrvd.h"
    logsrvd_h.write_text("struct conn {\n  int fd;\n    iolog_fd_t files[3];\n};\n", encoding="utf-8")
    (src / "sudo_iolog.h").write_text(
        "union io_fd {\n#ifdef HAVE_ZLIB_H\n  void *g;\n#endif\n  void *f;\n};\ntypedef union io_fd iolog_fd_t;\n",
        encoding="utf-8",
    )
    harness = tmp_path / "harness_sudo_logsrvd.c"
    harness.write_text(SHG_LOGSRVD_HARNESS, encoding="utf-8")
    res = G.resolve_prelude_headers(
        harness,
        f"-I{src.as_posix()}",
        "config.h",
        clang="clang",
        runner=ShgClang(harness, logsrvd_h),
        extra_includes=["sudo_compat.h", "logsrvd.h"],
    )
    assert res["status"] == "resolved" and res["prelude_headers"] == ["sudo_iolog.h"]
    order = [ln.split('"')[1] for ln in harness.read_text(encoding="utf-8").splitlines() if ln.startswith('#include "')]
    assert order == ["config.h", "sudo_compat.h", "sudo_iolog.h", "logsrvd.h"]


def test_an_error_in_the_harness_itself_keeps_the_module_header_as_the_place(tmp_path):
    harness = tmp_path / "harness.c"
    lines = SHG_LOGSRVD_HARNESS.splitlines()
    out = (
        f"In file included from {harness.as_posix()}:7:\n/src/logsrvd.h:3:5: error: unknown type name 'iolog_fd_t'\n"
        f"{harness.as_posix()}:9:5: error: unknown type name 'iolog_fd_t'\n"
        f"In file included from {harness.as_posix()}:6:\n/src/sudo_compat.h:1:1: error: unknown type name 'bool'\n"
        "    1 | bool sudo_compat(void);\n      | ^\n"
        # clang prints the chain only when it changed: this one is still reached through sudo_compat.h.
        "/src/sudo_compat.h:2:1: error: unknown type name 'bool'\n"
        f"In file included from {harness.as_posix()}:7:\nIn file included from /src/logsrvd.h:2:\n"
        "/src/logsrv_util.h:5:1: error: unknown type name 'bool'\n"
    )
    roots = G._diagnostic_roots(out, harness, lines)
    assert roots == {"iolog_fd_t": None, "bool": {'#include "sudo_compat.h"', '#include "logsrvd.h"'}}


# ---------------------------------------------------------------------------
# 4. A target fuzzer is not linked with the files defining what it overrides
# ---------------------------------------------------------------------------

SHG_DRIVER = "workspace/work/plugins/sudoers/regress/fuzz/fuzz_policy.c"
SHG_DRIVER_TEXT = """#include <stddef.h>
#include <stdint.h>
#include "sudoers.h"

static int fuzz_quiet;
char *audit_msg;
static struct iolog_path_escape path_escapes[] = { { 0, NULL } };
const struct iolog_path_escape *sudoers_iolog_path_escapes = path_escapes;
extern int sudo_mode;
struct fuzz_state { int x; };
typedef int fuzz_int;
int sudo_auth_begin_session(void *ctx, char *tty, char **user_env[]);

bool
user_is_exempt(const struct sudoers_context *ctx)
{
    return false;
}

static int helper(void) { return 0; }

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    return helper();
}
"""

SHG_TF_DAG = {
    "target_dir": "/framac-run/workspace/work",
    "functions": {
        "plugins/sudoers/check.c#user_is_exempt": {"name": "user_is_exempt", "file": "plugins/sudoers/check.c"},
        "plugins/sudoers/stubs.c#user_is_exempt": {"name": "user_is_exempt", "file": "plugins/sudoers/stubs.c"},
        "plugins/sudoers/policy.c#helper": {"name": "helper", "file": "plugins/sudoers/policy.c", "is_static": True},
        "include/sudoers.h#user_is_exempt": {"name": "user_is_exempt", "file": "include/sudoers.h", "header": True},
        "plugins/sudoers/policy.c#sudoers_policy_main": {
            "name": "sudoers_policy_main",
            "file": "plugins/sudoers/policy.c",
        },
    },
}
SHG_TF_MODEL = {
    "global_variables": {
        "plugins/sudoers/audit.c#audit_msg": {"name": "audit_msg", "file": "plugins/sudoers/audit.c"},
        "plugins/sudoers/iolog.c#sudoers_iolog_path_escapes": {
            "name": "sudoers_iolog_path_escapes",
            "file": "plugins/sudoers/iolog.c",
        },
        "plugins/sudoers/sudoers.c#sudo_mode": {"name": "sudo_mode", "file": "plugins/sudoers/sudoers.c"},
    }
}
SHG_TF_SOURCES = [
    "plugins/sudoers/audit.c",
    "plugins/sudoers/check.c",
    "plugins/sudoers/iolog.c",
    "plugins/sudoers/policy.c",
    "plugins/sudoers/sudoers.c",
    SHG_DRIVER,
]


def _shg_tf_run(tmp_path: Path, monkeypatch, capture: dict) -> Path:
    run = _shg_run(tmp_path, capture, SHG_TF_DAG)
    (run / "workspace/reports/phase0_model.json").write_text(json.dumps(SHG_TF_MODEL), encoding="utf-8")
    driver = run / SHG_DRIVER
    driver.parent.mkdir(parents=True)
    driver.write_text(SHG_DRIVER_TEXT, encoding="utf-8")
    monkeypatch.chdir(run)
    monkeypatch.setattr(G, "_preprocess_driver", lambda driver, cppflags: None)
    return run


def test_the_variables_a_driver_defines_are_its_external_ones():
    assert G._top_level_variable_names(SHG_DRIVER_TEXT) == ["audit_msg", "sudoers_iolog_path_escapes"]
    assert G._top_level_variable_names("int a, *b = 0, c[2] = {1, 2};\nvoid (*hook)(int) = 0;\n") == [
        "a",
        "b",
        "c",
        "hook",
    ]


def test_the_files_defining_what_the_driver_overrides_are_left_out(tmp_path, monkeypatch):
    run = _shg_tf_run(tmp_path, monkeypatch, {"compiles": [], "units": {}})
    kept, link = G.target_fuzzer_link_sources(run / "workspace/harnesses", SHG_DRIVER, SHG_TF_SOURCES, "-I.")
    assert kept == ["plugins/sudoers/policy.c", "plugins/sudoers/sudoers.c", SHG_DRIVER]
    assert link == {
        "from": "unit",
        "definitions": "source_text",
        "excluded_sources": [
            {"source": "plugins/sudoers/audit.c", "symbols": ["audit_msg"]},
            {"source": "plugins/sudoers/check.c", "symbols": ["user_is_exempt"]},
            {"source": "plugins/sudoers/iolog.c", "symbols": ["sudoers_iolog_path_escapes"]},
        ],
    }


def test_only_the_branch_the_build_compiles_counts_when_the_driver_preprocesses(tmp_path, monkeypatch):
    run = _shg_tf_run(tmp_path, monkeypatch, {"compiles": [], "units": {}})
    pre = (
        '# 1 "workspace/work/include/sudoers.h"\nbool user_is_exempt(const struct sudoers_context *);\nint audit_msg_len;\n'
        f'# 5 "{SHG_DRIVER}"\nchar *audit_msg;\n'
        f"int {G.TARGET_EMBEDDED_ENTRY}(const unsigned char *data, unsigned long size) {{ return 0; }}\n"
    )
    monkeypatch.setattr(G, "_preprocess_driver", lambda driver, cppflags: pre)
    assert G.target_fuzzer_definitions(SHG_DRIVER, "-I.") == ({"audit_msg"}, "preprocessed")
    kept, link = G.target_fuzzer_link_sources(run / "workspace/harnesses", SHG_DRIVER, SHG_TF_SOURCES, "-I.")
    assert link is not None and link["definitions"] == "preprocessed"
    assert [e["source"] for e in link["excluded_sources"]] == ["plugins/sudoers/audit.c"]
    assert "plugins/sudoers/check.c" in kept


def test_the_capture_link_of_the_driver_wins(tmp_path, monkeypatch):
    capture = {
        "compiles": [],
        "units": {
            "plugins/sudoers/fuzz_policy": {
                "files": ["plugins/sudoers/regress/fuzz/fuzz_policy.c", "plugins/sudoers/policy.c"],
                "links": [],
            }
        },
    }
    run = _shg_tf_run(tmp_path, monkeypatch, capture)
    kept, link = G.target_fuzzer_link_sources(run / "workspace/harnesses", SHG_DRIVER, SHG_TF_SOURCES, "-I.")
    assert kept == [SHG_DRIVER, "plugins/sudoers/policy.c"]
    assert link == {"from": "build_capture", "unit": "plugins/sudoers/fuzz_policy"}


def test_without_a_dag_nothing_is_decided(tmp_path):
    kept, link = G.target_fuzzer_link_sources(tmp_path / "harnesses", SHG_DRIVER, SHG_TF_SOURCES, "-I.")
    assert kept == SHG_TF_SOURCES and link is None
