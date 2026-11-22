"""
Build gaps sudo run-1 showed in Phase 0 build-check #5 (2026-11-22).

A. Link repair added a file that defines what the build already defines (fuzz_build.repair_sources_for_link):
   tf_fuzz_sudoers_ldif needed log_warnx and the global filters, which only cvtsudoers.c defines; cvtsudoers.c
   also defines open_sudoers, which the target fuzzer fuzz_sudoers_ldif.c defines itself: "multiple definition
   of `open_sudoers'".
B. The Frama-C printer drops a forward tag declaration (`struct passwd;` in sudo_nss.h) and prints the
   definition after a struct whose member names the tag in a parameter list: there it has prototype scope,
   and clang stops on "incompatible function pointer types initializing 'int (*)(..., struct passwd *)' with
   an expression of type 'int (*)(..., struct passwd *)'" (eacsl_toolchain.rewrite_forward_tag_declarations).
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

import eacsl_toolchain as T
import fuzz_build
import run_eacsl_fuzz as R
from test_eacsl_toolchain import FakeEacslGcc, _src, modern_cli  # noqa: F401 - modern_cli is a fixture

SLR_REPO = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# A. A file link repair would add defines what the build already defines
# ---------------------------------------------------------------------------

SLR_PLUGIN_UNIT = "plugin/.libs/plugin.so"
SLR_CVT_UNIT = "plugin/.libs/cvt"

SLR_FILES = {
    # The unit's files the fuzzer links (sudo's cvtsudoers_merge.c and friends call log_warnx, read filters).
    "plugin/merge.c": "int log_warn(const char *m);\nextern int *filt;\nint merge(void) { return log_warn(0) + *filt; }\n",
    "plugin/util.c": "int verbose;\nint helper(void) { return 0; }\n",
    # The unit's file the fuzzer's link leaves out: it defines open_cfg, which the fuzzer defines itself.
    "plugin/main_impl.c": "int open_cfg(const char *p) { return 0; }\n",
    # A program of the target (sudo's cvtsudoers.c): the only definer of log_warn and filt, and its own open_cfg.
    "progs/cvt.c": (
        "int *filt;\nint log_warn(const char *m) { return 1; }\n"
        "int open_cfg(const char *p) { return 2; }\nint main(void) { return open_cfg(0); }\n"
    ),
    # Defines a name the unit's util.c defines too.
    "progs/other.c": "int other_only(void) { return 1; }\nint helper(void) { return 3; }\n",
    # Defines only what nothing in the build defines.
    "progs/clean.c": "int verbose;\nint clean_only(void) { return 1; }\nint main(void) { return clean_only(); }\n",
    # sudo's plugins/sudoers/regress/fuzz/fuzz_sudoers_ldif.c: no DAG record (the build does not capture it).
    "plugin/fuzz/fuzz_ldif.c": (
        "int open_cfg(const char *p) { return 9; }\n"
        "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { return merge(); }\n"
    ),
}


def _slr_fn(name: str, file: str, module: str, unit: str) -> tuple[str, dict]:
    return f"{file}#{name}", {"name": name, "file": file, "module": module, "units": [unit], "is_static": False}


def _slr_run(tmp_path: Path, excluded_symbols: list[str] | None = None) -> Path:
    """The plugin unit, the cvt program and a target fuzzer generate_harness linked without main_impl.c."""
    work = tmp_path / "workspace" / "work"
    for rel, text in SLR_FILES.items():
        (work / rel).parent.mkdir(parents=True, exist_ok=True)
        (work / rel).write_text(text, encoding="utf-8", newline="\n")
    reports = tmp_path / "workspace" / "reports"
    reports.mkdir(parents=True)
    harnesses = tmp_path / "workspace" / "harnesses"
    harnesses.mkdir(parents=True)
    functions = dict(
        [
            _slr_fn("merge", "plugin/merge.c", "plugin_so", SLR_PLUGIN_UNIT),
            _slr_fn("helper", "plugin/util.c", "plugin_so", SLR_PLUGIN_UNIT),
            _slr_fn("open_cfg", "plugin/main_impl.c", "plugin_so", SLR_PLUGIN_UNIT),
            _slr_fn("log_warn", "progs/cvt.c", "cvt", SLR_CVT_UNIT),
            _slr_fn("open_cfg", "progs/cvt.c", "cvt", SLR_CVT_UNIT),
            _slr_fn("main", "progs/cvt.c", "cvt", SLR_CVT_UNIT),
            _slr_fn("other_only", "progs/other.c", "other", "progs/.libs/other"),
            _slr_fn("helper", "progs/other.c", "other", "progs/.libs/other"),
            _slr_fn("clean_only", "progs/clean.c", "clean", "progs/.libs/clean"),
            _slr_fn("main", "progs/clean.c", "clean", "progs/.libs/clean"),
        ]
    )
    dag = {
        "functions": functions,
        "module_kind": "link_unit",
        "modules": {
            "plugin_so": {
                "module": "plugin_so",
                "unit": SLR_PLUGIN_UNIT,
                "files": ["plugin/merge.c", "plugin/util.c", "plugin/main_impl.c"],
                "required_sources": [],
                "linked_modules": [],
            },
        },
    }
    (reports / "callgraph_dag.json").write_text(json.dumps(dag), encoding="utf-8")
    globs = [
        {"name": "filt", "file": "progs/cvt.c", "type": "int *", "units": [SLR_CVT_UNIT]},
        # An uninitialized global two files define: one object under -fcommon.
        {"name": "verbose", "file": "plugin/util.c", "type": "int", "units": [SLR_PLUGIN_UNIT]},
        {"name": "verbose", "file": "progs/clean.c", "type": "int", "units": ["progs/.libs/clean"]},
    ]
    model = {"global_variables": {f"{g['file']}#{g['name']}": {**g, "static": False} for g in globs}}
    (reports / "phase0_model.json").write_text(json.dumps(model), encoding="utf-8")
    excluded = [{"source": "plugin/main_impl.c", "symbols": excluded_symbols}] if excluded_symbols else []
    sidecar = {
        "module": "tf_fuzz_ldif",
        "unit": "plugin_so",
        "cppflags": "",
        "target_fuzzer": {
            "id": "fuzz_ldif",
            "source": "workspace/work/plugin/fuzz/fuzz_ldif.c",
            "link": {"from": "unit", "excluded_sources": excluded},
        },
    }
    (harnesses / "harness_tf_fuzz_ldif.json").write_text(json.dumps(sidecar), encoding="utf-8")
    return reports / "callgraph_dag.json"


SLR_TF_SOURCES = [
    "workspace/work/plugin/merge.c",
    "workspace/work/plugin/util.c",
    "workspace/work/plugin/fuzz/fuzz_ldif.c",
]


def _slr_undef(*syms: str) -> str:
    return "".join(f"/usr/bin/ld: x.o: undefined reference to `{s}'\n" for s in syms)


def _slr_stub_dir(module: str) -> Path:
    return Path(f"workspace/harnesses/fuzz_{module}_link_globals")


@pytest.mark.parametrize("excluded_symbols", [["open_cfg"], None], ids=["sidecar_lists_it", "driver_text_only"])
def test_a_file_that_redefines_the_fuzzers_own_function_is_not_added(tmp_path, monkeypatch, excluded_symbols):
    """tf_fuzz_sudoers_ldif: cvtsudoers.c (log_warnx, filters) also defines open_sudoers, the fuzzer's own."""
    dag = _slr_run(tmp_path, excluded_symbols)
    monkeypatch.chdir(tmp_path)
    stub_dir = _slr_stub_dir("tf_fuzz_ldif")
    repaired, info = fuzz_build.repair_sources_for_link(
        SLR_TF_SOURCES, _slr_undef("log_warn", "filt"), dag, tmp_path, module="tf_fuzz_ldif", stub_dir=stub_dir
    )
    assert "workspace/work/progs/cvt.c" not in repaired
    assert sorted(info["symbols"]) == ["filt", "log_warn"]
    (fn,) = info["stubbed_functions"]
    assert fn["name"] == "log_warn" and fn["file"] == "progs/cvt.c"
    assert "linking progs/cvt.c would define a second time what the build already defines" in fn["reason"]
    assert "open_cfg (defined in the target fuzzer plugin/fuzz/fuzz_ldif.c)" in fn["reason"]
    (glob,) = info["stubbed_globals"]
    assert glob["name"] == "filt" and "open_cfg" in glob["reason"]
    assert (stub_dir / fuzz_build.LINK_STUBS_FILE).as_posix() in repaired
    assert "int *filt;" in (stub_dir / fuzz_build.LINK_GLOBALS_FILE).read_text(encoding="utf-8")


def test_without_a_build_directory_both_are_recorded_unresolved(tmp_path, monkeypatch):
    dag = _slr_run(tmp_path, ["open_cfg"])
    monkeypatch.chdir(tmp_path)
    fns: list[dict] = []
    globs: list[dict] = []
    repaired, info = fuzz_build.repair_sources_for_link(
        SLR_TF_SOURCES,
        _slr_undef("log_warn", "filt"),
        dag,
        tmp_path,
        module="tf_fuzz_ldif",
        unresolved=globs,
        unresolved_functions=fns,
    )
    assert repaired == SLR_TF_SOURCES and info == {}
    assert [u["name"] for u in fns] == ["log_warn"] and "open_cfg" in fns[0]["reason"]
    assert [u["name"] for u in globs] == ["filt"] and "no build directory was given" in globs[0]["reason"]


def test_a_file_that_redefines_a_linked_files_function_is_not_added(tmp_path, monkeypatch):
    """Any module: other.c, the only definer of other_only, also defines util.c's helper."""
    dag = _slr_run(tmp_path)
    monkeypatch.chdir(tmp_path)
    sources = ["workspace/work/plugin/merge.c", "workspace/work/plugin/util.c"]
    repaired, info = fuzz_build.repair_sources_for_link(
        sources, _slr_undef("other_only"), dag, tmp_path, module="plugin_so", stub_dir=_slr_stub_dir("plugin_so")
    )
    assert "workspace/work/progs/other.c" not in repaired
    (fn,) = info["stubbed_functions"]
    assert fn["name"] == "other_only" and "helper (defined in plugin/util.c)" in fn["reason"]


def test_a_file_redefining_nothing_the_build_has_is_still_added(tmp_path, monkeypatch):
    """
    clean.c defines a main too: no file of the build does, so it links (main is renamed by -Dmain=). It
    shares the global verbose with util.c: uninitialized, one object under -fcommon, so no clash either.
    """
    dag = _slr_run(tmp_path)
    monkeypatch.chdir(tmp_path)
    sources = ["workspace/work/plugin/merge.c", "workspace/work/plugin/util.c"]
    repaired, info = fuzz_build.repair_sources_for_link(
        sources, _slr_undef("clean_only"), dag, tmp_path, module="plugin_so", stub_dir=_slr_stub_dir("plugin_so")
    )
    assert repaired == [*sources, "workspace/work/progs/clean.c"]
    assert "stubbed_functions" not in info


def test_a_second_main_is_a_redefinition(tmp_path, monkeypatch):
    """-Dmain= renames every unit's main to one name: two linked mains still collide."""
    dag = _slr_run(tmp_path)
    monkeypatch.chdir(tmp_path)
    sources = ["workspace/work/progs/cvt.c"]
    repaired, info = fuzz_build.repair_sources_for_link(
        sources, _slr_undef("clean_only"), dag, tmp_path, module="cvt", stub_dir=_slr_stub_dir("cvt")
    )
    assert "workspace/work/progs/clean.c" not in repaired
    (fn,) = info["stubbed_functions"]
    assert "main (defined in progs/cvt.c)" in fn["reason"]


def test_a_file_the_same_round_adds_counts_as_defined(tmp_path, monkeypatch):
    """cvt.c joins for log_warn; clean.c, wanted next, would bring a second main: it is stubbed instead."""
    dag = _slr_run(tmp_path)
    monkeypatch.chdir(tmp_path)
    sources = ["workspace/work/plugin/merge.c"]
    repaired, info = fuzz_build.repair_sources_for_link(
        sources,
        _slr_undef("log_warn", "clean_only"),
        dag,
        tmp_path,
        module="plugin_so",
        stub_dir=_slr_stub_dir("plugin_so"),
    )
    assert "workspace/work/progs/cvt.c" in repaired
    assert "workspace/work/progs/clean.c" not in repaired
    (fn,) = info["stubbed_functions"]
    assert fn["name"] == "clean_only" and "main (defined in progs/cvt.c)" in fn["reason"]


def test_link_repair_rounds_end_without_a_redefinition(tmp_path, monkeypatch):
    """End to end over the rounds: one round, cvt.c never linked, the stubs recorded with their reasons."""
    dag = _slr_run(tmp_path, ["open_cfg"])
    monkeypatch.chdir(tmp_path)
    first = {"returncode": 1, "stdout": "", "stderr": _slr_undef("log_warn", "filt")}
    calls: list[list[str]] = []

    def rebuild(srcs: list[str]) -> dict:
        calls.append(list(srcs))
        return {"returncode": 0, "stdout": "", "stderr": ""}

    out_bin = Path("workspace/harnesses/fuzz_tf_fuzz_ldif")
    comp, current, record = fuzz_build.repair_link_rounds(
        first, SLR_TF_SOURCES, rebuild, dag, out_bin, link_module="tf_fuzz_ldif"
    )
    assert comp["returncode"] == 0 and len(calls) == 1
    assert record is not None and not any("progs/" in s for s in current)
    assert [s["name"] for s in record["stubbed_functions"]] == ["log_warn"]
    assert [s["name"] for s in record["stubbed_globals"]] == ["filt"]


# ---------------------------------------------------------------------------
# B. A forward tag declaration the printer drops
# ---------------------------------------------------------------------------

# What `frama-c -print a.c b.c` prints (Frama-C 34) for a.c including a header with `struct passwd;` and
# `struct S { int (*q)(struct passwd *pw); };`, and b.c defining struct passwd before including it.
SLR_PRINTED = """/* Generated by Frama-C */
struct S {
   int (*q)(struct passwd *pw) ;
};
struct passwd {
   int uid ;
};
int f(struct passwd *pw);

struct S s;

struct S s = {.q = & f};
int f(struct passwd *pw)
{
  int __retres;
  __retres = pw->uid;
  return __retres;
}
"""


def test_a_tag_first_named_in_a_parameter_list_is_declared_at_the_start():
    new, info = T.rewrite_forward_tag_declarations(SLR_PRINTED)
    assert info == {"count": 1, "tags": ["struct passwd"], "lines_added": 0}
    assert new.split("\n", 1)[0] == "struct passwd; /* Generated by Frama-C */"
    assert new.count("\n") == SLR_PRINTED.count("\n")
    assert new.split("\n", 1)[1] == SLR_PRINTED.split("\n", 1)[1]


def test_a_tag_first_named_in_a_function_body_is_declared():
    text = "int g(void)\n{\n  struct node *p = 0;\n  return p != 0;\n}\nstruct node {\n  int v ;\n};\n"
    new, info = T.rewrite_forward_tag_declarations(text)
    assert info["tags"] == ["struct node"]
    assert new.startswith("struct node; int g(void)\n")


def test_a_union_is_declared_as_a_union():
    text = "/* x */\ntypedef int (*cb)(union val *v);\nunion val {\n   int i ;\n};\n"
    new, info = T.rewrite_forward_tag_declarations(text)
    assert info["tags"] == ["union val"] and new.startswith("union val; /* x */\n")


def test_a_file_starting_with_a_directive_gets_a_line_of_its_own():
    text = '#line 1 "x.c"\n' + SLR_PRINTED
    new, info = T.rewrite_forward_tag_declarations(text)
    assert info["lines_added"] == 1
    assert new.startswith('struct passwd;\n#line 1 "x.c"\n')


@pytest.mark.parametrize(
    "text",
    [
        # The forward declaration is there (what the sources have; Frama-C prints it for one file).
        "struct passwd;\nstruct S {\n   int (*q)(struct passwd *pw) ;\n};\nstruct passwd {\n   int uid ;\n};\n",
        # First named by a member at file scope: that declares it at file scope.
        "struct S {\n   struct passwd *p ;\n   int (*q)(struct passwd *pw) ;\n};\nstruct passwd {\n   int uid ;\n};\n",
        # Defined before any mention.
        "struct passwd {\n   int uid ;\n};\nstruct S {\n   int (*q)(struct passwd *pw) ;\n};\n",
        # Named before its definition only in a comment or a string.
        '/*@ requires \\valid((struct passwd *)p); */\nchar const *s = "(struct passwd *)";\n'
        "struct passwd {\n   int uid ;\n};\n",
        # An opaque tag (never defined): nothing to join.
        "int f(struct opaque *o);\n",
        "int f(void) { return 0; }\n",
    ],
)
def test_other_tags_are_left_alone(text):
    assert T.rewrite_forward_tag_declarations(text) == (text, {"count": 0, "tags": [], "lines_added": 0})


@pytest.mark.usefixtures("modern_cli")
def test_the_build_declares_the_tag_and_records_it(tmp_path):
    fake = FakeEacslGcc(instrumented_text=SLR_PRINTED)
    res = R.compile_eacsl_binary([str(_src(tmp_path))], tmp_path / "fuzz_mod", runner=fake, use_cache=False)
    assert res["returncode"] == 0, res
    assert res["forward_tag_declarations"] == {"count": 1, "tags": ["struct passwd"], "lines_added": 0}
    instrumented = Path(res["instrumented_source"]).read_text(encoding="utf-8")
    assert instrumented.startswith("struct passwd; /* Generated by Frama-C */\n")
    log = Path(res["compile_log"]).read_text(encoding="utf-8")
    assert "Declared 1 struct/union tag(s) at the start of the file (struct passwd)" in log
    plain = R.compile_eacsl_binary([str(_src(tmp_path))], tmp_path / "plain", runner=FakeEacslGcc(), use_cache=False)
    assert "forward_tag_declarations" not in plain


# End to end in the analysis image (FRAMAC_DOCKER_TESTS=1): sudo_nss.h's shape over two files.
SLR_HEADER_H = """struct passwd;
struct S {
  int (*q)(struct passwd *pw);
};
int f(struct passwd *pw);
extern struct S s;
"""

SLR_A_C = """#include "common.h"
struct S s = { .q = &f };
"""

SLR_B_C = """#include <stddef.h>
#include <stdint.h>
struct passwd {
  int uid;
};
#include "common.h"
int f(struct passwd *pw) { return pw->uid; }
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  struct passwd p = { 0 };
  if (size < 1)
    return 0;
  p.uid = data[0];
  return s.q(&p) == 1000;
}
"""

SLR_DRIVE_PY = """import json, shutil, sys
from pathlib import Path
sys.path.insert(0, "/repo/scripts")
import run_eacsl_fuzz as R
work = Path("/tmp/w")
shutil.copytree("/fixture", work)
srcs = [str(work / "a.c"), str(work / "b.c")]
res = R.compile_eacsl_binary(srcs, work / "out" / "fuzz_mod", cppflags=f"-I{work}", use_cache=False)
keys = ("returncode", "reason", "binary", "forward_tag_declarations")
print("SLR_RESULT " + json.dumps({k: res.get(k) for k in keys}))
"""


@pytest.mark.integration
def test_the_printed_tag_order_builds_under_eacsl(tmp_path):
    from conftest import ANALYSIS_IMAGE, require_docker_images

    require_docker_images(ANALYSIS_IMAGE)
    files = (("common.h", SLR_HEADER_H), ("a.c", SLR_A_C), ("b.c", SLR_B_C), ("drive.py", SLR_DRIVE_PY))
    for name, text in files:
        (tmp_path / name).write_text(text, encoding="utf-8", newline="\n")
    tag = os.environ.get("FRAMAC_RUN_TAG", "pytest-sudo-link-redef-fwdtags")
    name = f"framac-test-slr-{tmp_path.name}".lower()
    argv = ["docker", "run", "--rm", "--name", name, "--label", f"framac.run={tag}", "--network", "none"]
    argv += ["-v", f"{tmp_path}:/fixture:ro", "-v", f"{SLR_REPO}:/repo:ro", ANALYSIS_IMAGE]
    argv += ["timeout 900 python3 /fixture/drive.py"]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1200)
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
        raise
    out = proc.stdout + proc.stderr
    lines = [ln for ln in proc.stdout.splitlines() if ln.startswith("SLR_RESULT ")]
    assert lines, out[-4000:]
    res = json.loads(lines[-1].split(" ", 1)[1])
    assert res["returncode"] == 0, out[-4000:]
    assert res["binary"].endswith(".e-acsl")
    assert res["forward_tag_declarations"]["tags"] == ["struct passwd"]
