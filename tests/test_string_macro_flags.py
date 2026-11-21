"""
String-valued -D macros of the target's build (sudo: `-DLOCALEDIR="/usr/local/share/locale"`,
`-DDEFAULT_TEXT_DOMAIN="sudo"`) reach every compile of a fuzz build with their quotes.

Seen on sudo run-1 (Phase 0 build-check): 15 of 21 modules failed with `use of undeclared identifier
'LOCALEDIR'`, `Cannot resolve variable LOCALEDIR` (the harness flags dropped the macro), `expected
expression` and `use of undeclared identifier 'sudo'` (the macro arrived without its quotes). The tests
assert at the consumers: the clang argv of the sanitizer build and the words the shell Frama-C runs its
preprocessor through makes of the E-ACSL frontend flags.
"""

from __future__ import annotations

import json
import shlex
import subprocess
from pathlib import Path

import pytest

import eacsl_toolchain
import fuzz_build
import generate_harness
import pipeline_make
from conftest import ANALYSIS_IMAGE, ROOT, require_docker_images

_LOCALEDIR = '-DLOCALEDIR="/usr/share/locale"'
_DOMAIN = '-DTEXT_DOMAIN="sudo"'


def _write_dag(run: Path, cppflags: list[str]) -> None:
    dag = {
        "module_kind": "link_unit",
        "modules": {"libdemo_a": {"required_sources": ["demo.c"], "cppflags": cppflags}},
        "functions": {},
    }
    (run / "workspace/reports").mkdir(parents=True, exist_ok=True)
    (run / "workspace/reports/callgraph_dag.json").write_text(json.dumps(dag), encoding="utf-8")


@pytest.fixture
def demo_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    _write_dag(tmp_path, ["-Iworkspace/work", _LOCALEDIR, _DOMAIN, "-DPIC"])
    return tmp_path


def _sanitizer_argv(cppflags: str, tmp_path: Path) -> list[str]:
    seen: dict = {}

    def runner(cmd, **kwargs):
        seen["cmd"] = cmd
        return type("P", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    fuzz_build.compile_sanitizer_binary(["demo.c"], tmp_path / "bin", cppflags, True, runner=runner, use_cache=False)
    return list(seen["cmd"])


def _frontend_words(cppflags: str) -> list[str]:
    """The words /bin/sh makes of the E-ACSL frontend flags (Frama-C's `-cpp-extra-args`)."""
    front = eacsl_toolchain.build_eacsl_flag_sets(cppflags, fc_stubs=None)["frontend"]
    return shlex.split(front)


def test_unit_harness_flags_carry_the_builds_string_macros(demo_run: Path) -> None:
    flags = generate_harness._merge_dag_module_cppflags("libdemo_a", demo_run / "workspace/harnesses", "-I.")
    argv = _sanitizer_argv(flags, demo_run)
    assert _LOCALEDIR in argv and _DOMAIN in argv
    words = _frontend_words(flags)
    assert _LOCALEDIR in words and _DOMAIN in words


def test_target_fuzzer_flags_typed_from_the_dag_list_get_their_quotes_back(demo_run: Path) -> None:
    # SKILL.md: --cppflags='<the unit's cppflags>'; the DAG list joined with spaces loses its quotes
    # in shlex, as `-DLOCALEDIR=/usr/share/locale`.
    typed = '-Iworkspace/work -DLOCALEDIR="/usr/share/locale" -DTEXT_DOMAIN="sudo" -DPIC'
    flags = generate_harness._merge_dag_module_cppflags(
        "tf_demo", demo_run / "workspace/harnesses", typed, unit="libdemo_a"
    )
    tokens = generate_harness._split_cppflags(flags)
    assert tokens == ["-Iworkspace/work", _LOCALEDIR, _DOMAIN, "-DPIC"]
    argv = _sanitizer_argv(flags, demo_run)
    assert "-DLOCALEDIR=/usr/share/locale" not in argv and _LOCALEDIR in argv


def test_a_callers_own_value_for_the_macro_is_not_rewritten(demo_run: Path) -> None:
    flags = generate_harness._merge_dag_module_cppflags(
        "tf_demo", demo_run / "workspace/harnesses", "-DLOCALEDIR=other", unit="libdemo_a"
    )
    assert generate_harness._split_cppflags(flags)[0] == "-DLOCALEDIR=other"


def test_eacsl_frontend_flags_survive_the_preprocessor_shell() -> None:
    cppflags = shlex.join(["-Iinc", _LOCALEDIR, "-D__attribute__(x)=", "-include", "cfg.h"])
    words = _frontend_words(cppflags)
    assert _LOCALEDIR in words and "-D__attribute__(x)=" in words
    assert words[words.index("-include") + 1] == "cfg.h"
    # The -e/-l values reach clang through an unquoted expansion (no quote removal): left bare.
    assert eacsl_toolchain.normalize_passthrough(shlex.join(["-lz", _LOCALEDIR])) == f"-lz {_LOCALEDIR}"


def test_make_recipes_pass_the_sidecar_macro_through_one_shell_layer() -> None:
    value = pipeline_make.mk_quote(shlex.join(["-Iinc", _LOCALEDIR]))
    (cppflags,) = shlex.split(f"--cppflags={value}".split("=", 1)[1])
    assert shlex.split(cppflags) == ["-Iinc", _LOCALEDIR]


def test_link_repair_prefers_the_defining_source_over_a_header_prototype(tmp_path: Path) -> None:
    # sudo: the GCC call graph records sudo_warn_gettext_v1 at its prototype in include/sudo_fatal.h
    # too; linking that header as a source parsed it without config.h (`sudo_dso_public`).
    (tmp_path / "workspace/work/lib/util").mkdir(parents=True)
    (tmp_path / "workspace/work/include").mkdir(parents=True)
    (tmp_path / "workspace/work/lib/util/fatal.c").write_text("int sudo_warn_gettext_v1;\n", encoding="utf-8")
    (tmp_path / "workspace/work/include/sudo_fatal.h").write_text("int sudo_warn_gettext_v1(void);\n", encoding="utf-8")
    dag_path = tmp_path / "callgraph_dag.json"
    fns = {
        "include/sudo_fatal.h#sudo_warn_gettext_v1": {
            "name": "sudo_warn_gettext_v1",
            "file": "include/sudo_fatal.h",
            "module": "libparsesudoers_a",
            "header": True,
        },
        "lib/util/fatal.c#sudo_warn_gettext_v1": {
            "name": "sudo_warn_gettext_v1",
            "file": "lib/util/fatal.c",
            "module": "libsudo_util_so",
        },
        "include/only.h#only_in_header": {"name": "only_in_header", "file": "include/only.h", "header": True},
    }
    dag_path.write_text(json.dumps({"functions": fns}), encoding="utf-8")
    parsed, _ = fuzz_build._dag_symbol_tables(dag_path)
    assert parsed["sudo_warn_gettext_v1"] == ("lib/util/fatal.c", "libsudo_util_so")
    assert parsed["only_in_header"][0] == "include/only.h"  # no other record: unchanged
    log = "undefined reference to `sudo_warn_gettext_v1'\n"
    repaired, info = fuzz_build.repair_sources_for_link(["workspace/work/a.c"], log, dag_path, tmp_path)
    assert repaired == ["workspace/work/a.c", "workspace/work/lib/util/fatal.c"]
    assert info["added_sources"] == ["workspace/work/lib/util/fatal.c"]


_DEMO_C = """#include <stddef.h>
#include <string.h>
const char *demo_localedir(void) { return LOCALEDIR; }
int demo_parse(const unsigned char *data, size_t size)
{
    if (size == 0)
        return 0;
    return (int)(strlen(LOCALEDIR) + strlen(TEXT_DOMAIN)) + data[0];
}
"""

_DEMO_SH = """set -u
S=/opt/framac-pipeline/scripts
gen() { timeout 120 python3 $S/generate_harness.py --sources demo.c --header none --entry-fn demo_parse \\
  --out-dir workspace/harnesses "$@" >/dev/null 2>&1 || echo "GEN_FAILED $*"; }
gen --module libdemo_a --cppflags=-I.
gen --module tf_demo --unit libdemo_a \\
  '--cppflags=-Iworkspace/work -DLOCALEDIR="/usr/share/locale" -DTEXT_DOMAIN="sudo" -DPIC'
for mod in libdemo_a tf_demo; do
  flags=$(python3 -c "import json;print(json.load(open('workspace/harnesses/harness_$mod.json'))['cppflags'])")
  for engine in sanitizers eacsl; do
    timeout 600 python3 $S/run_eacsl_fuzz.py build --no-cache --engine $engine --module $mod \\
      --sources workspace/work/demo.c workspace/harnesses/harness_$mod.c "--cppflags=$flags" \\
      --out-bin workspace/out/fuzz_${mod}_$engine --out-json workspace/out/${mod}_$engine.json >/dev/null 2>&1
    echo "BUILD $mod $engine rc=$?"
  done
done
"""


def test_docker_fuzz_builds_with_string_macros(tmp_path: Path) -> None:
    require_docker_images(ANALYSIS_IMAGE)
    _write_dag(tmp_path, ["-Iworkspace/work", _LOCALEDIR, _DOMAIN, "-DPIC"])
    (tmp_path / "workspace/work").mkdir(parents=True)
    (tmp_path / "workspace/harnesses").mkdir(parents=True)
    (tmp_path / "workspace/out").mkdir(parents=True)
    (tmp_path / "workspace/work/demo.c").write_text(_DEMO_C, encoding="utf-8", newline="\n")
    (tmp_path / "repro.sh").write_text(_DEMO_SH, encoding="utf-8", newline="\n")
    argv = [
        "docker", "run", "--rm", "--network", "none", "--label", "framac.run=test-string-macros",
        "-v", f"{tmp_path.resolve()}:/framac-run",
        "-v", f"{ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
        "-v", f"{ROOT / 'templates'}:/opt/framac-pipeline/templates:ro",
        "-v", f"{ROOT / 'schemas'}:/opt/framac-pipeline/schemas:ro",
        "-w", "/framac-run", "--entrypoint", "/bin/bash", ANALYSIS_IMAGE, "-c", "timeout 1500 bash repro.sh",
    ]  # fmt: skip
    proc = subprocess.run(
        argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1600, check=False
    )
    out = proc.stdout + proc.stderr
    assert "GEN_FAILED" not in out, out
    for mod in ("libdemo_a", "tf_demo"):
        for engine in ("sanitizers", "eacsl"):
            assert f"BUILD {mod} {engine} rc=0" in out, out
