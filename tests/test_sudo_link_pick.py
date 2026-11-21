"""
Build gaps sudo run-1 showed in Phase 0 build-check #4 (2026-11-21).

A. The Frama-C printer puts a goto label before `default:` (fmtsudoers.c: `FALLTHROUGH; default:
   print_word:` printed `__attribute__((__fallthrough__)); print_word: default:`): clang stops on
   "fallthrough annotation does not directly precede switch label" (eacsl_toolchain.rewrite_misplaced_fallthrough).
B. Link repair resolved `open_sudoers`, which four programs define and the archive libparsesudoers.a does
   not, by linking cvtsudoers.c: nine more rounds pulled in the whole program (fuzz_build.repair_sources_for_link).
C. Link repair added back a file the target fuzzer generator left out (sidecar
   `target_fuzzer.link.excluded_sources`): "global var audit_msg ... has different initializer".
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

SLP_REPO = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# A. A fallthrough attribute the printer leaves before `label: default:`
# ---------------------------------------------------------------------------

# As the E-ACSL frontend printed sudo's fmtsudoers.c (fuzz_libparsesudoers_a.instrumented.c:2911023; shortened).
SLP_PRINTED = """int sudoers_format_member_int(int type, int negated)
{
  switch (type) {
    case 1:
    {
      alias_put(a);
      break;
    }
     __attribute__((__fallthrough__));
    print_word: default:
    __e_acsl_store_block_duplicate((void *)(& tmp_0),8UL);
    ;
  }
  return 0;
}
"""


def test_a_fallthrough_before_a_goto_label_is_removed_and_its_semicolon_kept():
    new, info = T.rewrite_misplaced_fallthrough(SLP_PRINTED)
    assert info == {"rewrites": 1, "lines": [9]}
    lines = new.split("\n")
    assert lines[8] == "     ;"
    assert lines[9] == "    print_word: default:"
    assert new.count("\n") == SLP_PRINTED.count("\n")
    assert "fallthrough" not in new


@pytest.mark.parametrize(
    "text",
    [
        # Directly before a switch label (comments and annotations aside): what clang accepts.
        "switch (k) {\n  case 1: r = 1;\n  __attribute__((__fallthrough__));\n  case 2: r++;\n}\n",
        "switch (k) {\n  case 1: r = 1;\n  __attribute__((fallthrough));\n  default: r++;\n}\n",
        "switch (k) {\n  case 1: r = 1;\n  __attribute__((__fallthrough__));\n  /*@ assert r == 1; */\n  case 2: ;\n}\n",
        # No attribute at all, or in a string.
        "int f(void) { return 0; }\n",
        'char const *s = "x"; char const *t = "__attribute__((__fallthrough__));";\n',
    ],
)
def test_other_fallthrough_attributes_are_left_alone(text):
    assert T.rewrite_misplaced_fallthrough(text) == (text, {"rewrites": 0, "lines": []})


def test_a_labelled_fallthrough_at_the_end_of_a_block_keeps_its_statement():
    text = "switch (k) {\n  case 1:\n  {\n    if (v) goto out;\n    out: __attribute__((__fallthrough__));\n  }\n  default: ;\n}\n"
    new, info = T.rewrite_misplaced_fallthrough(text)
    assert info["rewrites"] == 1
    assert "    out: ;\n" in new


@pytest.mark.usefixtures("modern_cli")
def test_the_build_removes_the_misplaced_fallthrough_and_records_it(tmp_path):
    fake = FakeEacslGcc(instrumented_text=SLP_PRINTED)
    res = R.compile_eacsl_binary([str(_src(tmp_path))], tmp_path / "fuzz_mod", runner=fake, use_cache=False)
    assert res["returncode"] == 0, res
    assert res["misplaced_fallthrough"] == {"rewrites": 1, "lines": [9]}
    instrumented = Path(res["instrumented_source"]).read_text(encoding="utf-8")
    assert "fallthrough" not in instrumented
    log = Path(res["compile_log"]).read_text(encoding="utf-8")
    assert "Removed 1 __attribute__((__fallthrough__))" in log
    plain = R.compile_eacsl_binary([str(_src(tmp_path))], tmp_path / "plain", runner=FakeEacslGcc(), use_cache=False)
    assert "misplaced_fallthrough" not in plain


# End to end in the analysis image (FRAMAC_DOCKER_TESTS=1): fmtsudoers.c's shape.
SLP_FT_C = """#include <stddef.h>
#include <stdint.h>
#define FALLTHROUGH __attribute__((__fallthrough__))

static int pick(int k, int v)
{
    int r = 0;
    switch (k) {
    case 1:
        if (v > 3)
            goto print_word;
        r = 1;
        FALLTHROUGH;
    default:
    print_word:
        r += v;
        break;
    }
    return r;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2)
        return 0;
    return pick(data[0] % 3, data[1]) == 1000;
}
"""

SLP_FT_DRIVE_PY = """import json, shutil, sys
from pathlib import Path
sys.path.insert(0, "/repo/scripts")
import run_eacsl_fuzz as R
work = Path("/tmp/w")
shutil.copytree("/fixture", work)
res = R.compile_eacsl_binary([str(work / "ft.c")], work / "out" / "fuzz_mod", cppflags=f"-I{work}", use_cache=False)
keys = ("returncode", "reason", "binary", "misplaced_fallthrough")
print("SLP_RESULT " + json.dumps({k: res.get(k) for k in keys}))
"""


@pytest.mark.integration
def test_the_printed_fallthrough_builds_under_eacsl(tmp_path):
    from conftest import ANALYSIS_IMAGE, require_docker_images

    require_docker_images(ANALYSIS_IMAGE)
    for name, text in (("ft.c", SLP_FT_C), ("drive.py", SLP_FT_DRIVE_PY)):
        (tmp_path / name).write_text(text, encoding="utf-8", newline="\n")
    tag = os.environ.get("FRAMAC_RUN_TAG", "pytest-sudo-link-pick")
    name = f"framac-test-slp-{tmp_path.name}".lower()
    argv = ["docker", "run", "--rm", "--name", name, "--label", f"framac.run={tag}", "--network", "none"]
    argv += ["-v", f"{tmp_path}:/fixture:ro", "-v", f"{SLP_REPO}:/repo:ro", ANALYSIS_IMAGE]
    argv += ["timeout 900 python3 /fixture/drive.py"]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1200)
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
        raise
    out = proc.stdout + proc.stderr
    lines = [ln for ln in proc.stdout.splitlines() if ln.startswith("SLP_RESULT ")]
    assert lines, out[-4000:]
    res = json.loads(lines[-1].split(" ", 1)[1])
    assert res["returncode"] == 0, out[-4000:]
    assert res["binary"].endswith(".e-acsl")
    assert res["misplaced_fallthrough"]["rewrites"] == 1


# ---------------------------------------------------------------------------
# B. A function several programs define, none of them in the module's link
# ---------------------------------------------------------------------------

SLP_PARSE_UNIT = "parse/.libs/libparse.a"
SLP_UTIL_UNIT = "util/.libs/libutil.so"
SLP_OPEN_UNIT = "open/.libs/libopen.a"
SLP_MID_UNIT = "mid/.libs/libmid.a"

SLP_FILES = {
    # The parser library calls open_cfg, which each program defines for itself (sudo's open_sudoers).
    "parse/gram.c": "int open_cfg(const char *p);\nint util_fn(void);\nint parse(void) { return open_cfg(0) + util_fn(); }\n",
    "util/util.c": "int util_fn(void) { return 0; }\n",
    "progs/cvt.c": "int open_cfg(const char *p) { return p != 0; }\nint main(void) { return open_cfg(0); }\n",
    "progs/visudo.c": "int open_cfg(const char *p) { return 2; }\nint main(void) { return open_cfg(0); }\n",
    # A library that links the one defining it: that one is linked.
    "open/open.c": "int open_cfg(const char *p) { return 3; }\n",
    "mid/mid.c": "int open_cfg(const char *p);\nint mid(void) { return open_cfg(0); }\n",
}


def _slp_fn(name: str, file: str, module: str, unit: str) -> tuple[str, dict]:
    rec = {"name": name, "file": file, "module": module, "units": [unit], "is_static": False}
    return f"{file}#{name}", rec


def _slp_unit(module: str, unit: str, files: list[str], linked: list[str] | None = None) -> dict:
    return {"module": module, "unit": unit, "files": files, "required_sources": files, "linked_modules": linked or []}


def _slp_run(tmp_path: Path) -> Path:
    """sudo's shape: a parser archive, a utility library, two programs and two more libraries."""
    work = tmp_path / "workspace" / "work"
    for rel, text in SLP_FILES.items():
        (work / rel).parent.mkdir(parents=True, exist_ok=True)
        (work / rel).write_text(text, encoding="utf-8", newline="\n")
    reports = tmp_path / "workspace" / "reports"
    reports.mkdir(parents=True)
    (tmp_path / "workspace" / "harnesses").mkdir(parents=True)
    functions = dict(
        [
            _slp_fn("parse", "parse/gram.c", "libparse_a", SLP_PARSE_UNIT),
            _slp_fn("util_fn", "util/util.c", "libutil_so", SLP_UTIL_UNIT),
            # cvt.c first: the definer the DAG lists first, which the repair used to link.
            _slp_fn("open_cfg", "progs/cvt.c", "cvt", "progs/.libs/cvt"),
            _slp_fn("main", "progs/cvt.c", "cvt", "progs/.libs/cvt"),
            _slp_fn("open_cfg", "progs/visudo.c", "visudo", "progs/.libs/visudo"),
            _slp_fn("main", "progs/visudo.c", "visudo", "progs/.libs/visudo"),
            _slp_fn("open_cfg", "open/open.c", "libopen_a", SLP_OPEN_UNIT),
            _slp_fn("mid", "mid/mid.c", "libmid_a", SLP_MID_UNIT),
        ]
    )
    dag = {
        "functions": functions,
        "module_kind": "link_unit",
        "modules": {
            "libparse_a": _slp_unit("libparse_a", SLP_PARSE_UNIT, ["parse/gram.c"]),
            "libutil_so": _slp_unit("libutil_so", SLP_UTIL_UNIT, ["util/util.c"]),
            "cvt": _slp_unit("cvt", "progs/.libs/cvt", ["progs/cvt.c"], ["libparse_a"]),
            "visudo": _slp_unit("visudo", "progs/.libs/visudo", ["progs/visudo.c"], ["libparse_a"]),
            "libopen_a": _slp_unit("libopen_a", SLP_OPEN_UNIT, ["open/open.c"]),
            "libmid_a": _slp_unit("libmid_a", SLP_MID_UNIT, ["mid/mid.c"], ["libopen_a"]),
        },
    }
    (reports / "callgraph_dag.json").write_text(json.dumps(dag), encoding="utf-8")
    (reports / "phase0_model.json").write_text(json.dumps({"global_variables": {}}), encoding="utf-8")
    return reports / "callgraph_dag.json"


def _slp_undef(*syms: str) -> str:
    return "".join(f"/usr/bin/ld: x.o: undefined reference to `{s}'\n" for s in syms)


def _slp_stub_dir(module: str) -> Path:
    return Path(f"workspace/harnesses/fuzz_{module}_link_globals")


def test_a_function_several_programs_define_is_stubbed_not_linked_from_the_first(tmp_path, monkeypatch):
    """libparsesudoers_a: open_sudoers is cvtsudoers.c's, sudoers.c's, testsudoers.c's and visudo.c's."""
    dag = _slp_run(tmp_path)
    monkeypatch.chdir(tmp_path)
    stub_dir = _slp_stub_dir("libparse_a")
    sources = ["workspace/work/parse/gram.c"]
    repaired, info = fuzz_build.repair_sources_for_link(
        sources, _slp_undef("open_cfg", "util_fn"), dag, tmp_path, module="libparse_a", stub_dir=stub_dir
    )
    stubs_file = (stub_dir / fuzz_build.LINK_STUBS_FILE).as_posix()
    # The one definer of util_fn is still linked from its file (another unit's: the general behaviour).
    assert repaired == [*sources, "workspace/work/util/util.c", stubs_file]
    assert "workspace/work/progs/cvt.c" not in repaired
    (stub,) = info["stubbed_functions"]
    assert stub["name"] == "open_cfg"
    assert stub["definers"] == ["progs/cvt.c", "progs/visudo.c", "open/open.c"]
    assert "none of them in the module's link unit parse/.libs/libparse.a" in stub["reason"]
    text = Path(stubs_file).read_text(encoding="utf-8")
    assert ".globl open_cfg" in text and "3 files define it" in text


def test_the_definer_of_a_linked_unit_is_linked(tmp_path, monkeypatch):
    dag = _slp_run(tmp_path)
    monkeypatch.chdir(tmp_path)
    sources = ["workspace/work/mid/mid.c"]
    repaired, info = fuzz_build.repair_sources_for_link(
        sources, _slp_undef("open_cfg"), dag, tmp_path, module="libmid_a", stub_dir=_slp_stub_dir("libmid_a")
    )
    assert repaired == [*sources, "workspace/work/open/open.c"]
    assert "stubbed_functions" not in info


def test_a_definer_the_build_already_compiles_adds_nothing_else(tmp_path, monkeypatch):
    """The build compiles visudo.c and open_cfg is still undefined (an #ifdef): no other program joins."""
    dag = _slp_run(tmp_path)
    monkeypatch.chdir(tmp_path)
    sources = ["workspace/work/parse/gram.c", "workspace/work/progs/visudo.c"]
    repaired, info = fuzz_build.repair_sources_for_link(
        sources, _slp_undef("open_cfg"), dag, tmp_path, module="visudo", stub_dir=_slp_stub_dir("visudo")
    )
    assert repaired == sources and info == {}


def test_without_a_build_directory_the_function_is_recorded_unresolved(tmp_path, monkeypatch):
    dag = _slp_run(tmp_path)
    monkeypatch.chdir(tmp_path)
    left: list[dict] = []
    sources = ["workspace/work/parse/gram.c"]
    repaired, info = fuzz_build.repair_sources_for_link(
        sources, _slp_undef("open_cfg"), dag, tmp_path, module="libparse_a", unresolved_functions=left
    )
    assert repaired == sources and info == {}
    assert [u["name"] for u in left] == ["open_cfg"]


def test_link_repair_rounds_stub_it_and_stop(tmp_path, monkeypatch):
    """End to end over the rounds: one round, no program pulled in, the stub recorded with its reason."""
    dag = _slp_run(tmp_path)
    monkeypatch.chdir(tmp_path)
    first = {"returncode": 1, "stdout": "", "stderr": _slp_undef("open_cfg")}
    calls: list[list[str]] = []

    def rebuild(srcs: list[str]) -> dict:
        calls.append(list(srcs))
        return {"returncode": 0, "stdout": "", "stderr": ""}

    out_bin = Path("workspace/harnesses/fuzz_libparse_a")
    comp, current, record = fuzz_build.repair_link_rounds(
        first, ["workspace/work/parse/gram.c"], rebuild, dag, out_bin, link_module="libparse_a"
    )
    assert comp["returncode"] == 0 and len(calls) == 1
    assert record is not None
    assert [s["name"] for s in record["stubbed_functions"]] == ["open_cfg"]
    assert record["functions_file"].endswith("fuzz_libparse_a_link_globals/link_stubs.c")
    assert not any("progs/" in s for s in current)


# ---------------------------------------------------------------------------
# C. A file the target fuzzer's link leaves out is never linked back
# ---------------------------------------------------------------------------

SLP_PLUGIN_UNIT = "plugin/.libs/plugin.so"

SLP_TF_FILES = {
    "plugin/audit.h": "extern char *audit_msg;\nextern int audit_count;\nint audit_success(void);\nint audit_failure(void);\n",
    "plugin/audit.c": (
        '#include "audit.h"\nchar *audit_msg = "real";\nint audit_count;\n'
        "int audit_success(void) { return ++audit_count; }\nint audit_failure(void) { return 0; }\n"
    ),
    "plugin/policy.c": '#include "audit.h"\nint policy_check(void) { return audit_success() + audit_count; }\n',
    # sudo's regress/fuzz/fuzz_policy.c: overrides audit_msg and audit_failure.
    "plugin/fuzz/fuzz_pol.c": (
        '#include "../audit.h"\nchar *audit_msg = "fuzz";\nint audit_failure(void) { return 1; }\n'
        "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { return policy_check(); }\n"
    ),
}


def _slp_tf_run(tmp_path: Path) -> Path:
    """A plugin unit and the target fuzzer generate_harness linked without plugin/audit.c."""
    work = tmp_path / "workspace" / "work"
    for rel, text in SLP_TF_FILES.items():
        (work / rel).parent.mkdir(parents=True, exist_ok=True)
        (work / rel).write_text(text, encoding="utf-8", newline="\n")
    reports = tmp_path / "workspace" / "reports"
    reports.mkdir(parents=True)
    harnesses = tmp_path / "workspace" / "harnesses"
    harnesses.mkdir(parents=True)
    functions = dict(
        [
            _slp_fn("audit_success", "plugin/audit.c", "plugin_so", SLP_PLUGIN_UNIT),
            _slp_fn("audit_failure", "plugin/audit.c", "plugin_so", SLP_PLUGIN_UNIT),
            _slp_fn("policy_check", "plugin/policy.c", "plugin_so", SLP_PLUGIN_UNIT),
            _slp_fn("audit_failure", "plugin/fuzz/fuzz_pol.c", "fuzz_pol", "plugin/fuzz_pol"),
        ]
    )
    files = ["plugin/audit.c", "plugin/policy.c"]
    dag = {
        "functions": functions,
        "module_kind": "link_unit",
        "modules": {"plugin_so": _slp_unit("plugin_so", SLP_PLUGIN_UNIT, files)},
    }
    (reports / "callgraph_dag.json").write_text(json.dumps(dag), encoding="utf-8")
    globs = [
        {"name": "audit_msg", "file": "plugin/audit.c", "type": "char *", "units": [SLP_PLUGIN_UNIT]},
        {"name": "audit_count", "file": "plugin/audit.c", "type": "int", "units": [SLP_PLUGIN_UNIT]},
        {"name": "audit_msg", "file": "plugin/fuzz/fuzz_pol.c", "type": "char *", "units": ["plugin/fuzz_pol"]},
    ]
    model = {"global_variables": {f"{g['file']}#{g['name']}": {**g, "static": False} for g in globs}}
    (reports / "phase0_model.json").write_text(json.dumps(model), encoding="utf-8")
    sidecar = {
        "module": "tf_fuzz_pol",
        "unit": "plugin_so",
        "target_fuzzer": {
            "id": "fuzz_pol",
            "source": "workspace/work/plugin/fuzz/fuzz_pol.c",
            "link": {
                "from": "unit",
                "excluded_sources": [{"source": "plugin/audit.c", "symbols": ["audit_failure", "audit_msg"]}],
            },
        },
    }
    (harnesses / "harness_tf_fuzz_pol.json").write_text(json.dumps(sidecar), encoding="utf-8")
    return reports / "callgraph_dag.json"


SLP_TF_SOURCES = ["workspace/work/plugin/policy.c", "workspace/work/plugin/fuzz/fuzz_pol.c"]


def test_an_excluded_source_is_not_linked_back_its_function_and_global_are_stubbed(tmp_path, monkeypatch):
    """tf_fuzz_policy: policy.c calls into audit.c, which the fuzzer's link leaves out (audit_msg)."""
    dag = _slp_tf_run(tmp_path)
    monkeypatch.chdir(tmp_path)
    stub_dir = _slp_stub_dir("tf_fuzz_pol")
    repaired, info = fuzz_build.repair_sources_for_link(
        SLP_TF_SOURCES,
        _slp_undef("audit_success", "audit_count"),
        dag,
        tmp_path,
        module="tf_fuzz_pol",
        stub_dir=stub_dir,
    )
    assert "workspace/work/plugin/audit.c" not in repaired
    assert sorted(info["symbols"]) == ["audit_count", "audit_success"]
    (fn,) = info["stubbed_functions"]
    assert fn["name"] == "audit_success" and fn["file"] == "plugin/audit.c"
    assert "the target fuzzer's link leaves plugin/audit.c out" in fn["reason"]
    (glob,) = info["stubbed_globals"]
    assert glob["name"] == "audit_count" and "target_fuzzer.link.excluded_sources" in glob["reason"]
    assert (stub_dir / fuzz_build.LINK_STUBS_FILE).as_posix() in repaired
    assert (stub_dir / fuzz_build.LINK_GLOBALS_FILE).as_posix() in repaired
    assert "int audit_count;" in (stub_dir / fuzz_build.LINK_GLOBALS_FILE).read_text(encoding="utf-8")


def test_an_excluded_source_is_recorded_unresolved_without_a_build_directory(tmp_path, monkeypatch):
    dag = _slp_tf_run(tmp_path)
    monkeypatch.chdir(tmp_path)
    fns: list[dict] = []
    globs: list[dict] = []
    repaired, info = fuzz_build.repair_sources_for_link(
        SLP_TF_SOURCES,
        _slp_undef("audit_success", "audit_count"),
        dag,
        tmp_path,
        module="tf_fuzz_pol",
        unresolved=globs,
        unresolved_functions=fns,
    )
    assert repaired == SLP_TF_SOURCES and info == {}
    assert [u["name"] for u in fns] == ["audit_success"]
    assert [u["name"] for u in globs] == ["audit_count"]
    assert "leaves plugin/audit.c out" in globs[0]["reason"]


def test_the_unit_harness_still_links_the_file_the_target_fuzzer_leaves_out(tmp_path, monkeypatch):
    """The exclusion is the target fuzz module's own: the unit's harness links audit.c as before."""
    dag = _slp_tf_run(tmp_path)
    monkeypatch.chdir(tmp_path)
    sources = ["workspace/work/plugin/policy.c"]
    repaired, info = fuzz_build.repair_sources_for_link(
        sources, _slp_undef("audit_success"), dag, tmp_path, module="plugin_so", stub_dir=_slp_stub_dir("plugin_so")
    )
    assert repaired == [*sources, "workspace/work/plugin/audit.c"]
    assert "stubbed_functions" not in info
