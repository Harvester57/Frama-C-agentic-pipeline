"""
The feature-test macros a target sets before its first system header reach the harness's compiles.

nginx 1.31.9 run-3 (2026-11-19): `generate_harness.py --api --module nginx__ngx_files --header ngx_config.h ...`
failed with "the harness does not compile outside its cases: workspace/work/src/event/ngx_event_udp.h:46:27:
error: field has incomplete type 'struct in6_pktinfo'". The harness includes <stdint.h> and friends before
ngx_config.h, so glibc's <features.h> ran without the `_GNU_SOURCE` nginx defines in
src/os/unix/ngx_linux_config.h, and `struct in6_pktinfo` (netinet/in.h, under __USE_GNU) stayed undeclared.
The E-ACSL frontend force-includes fc_compat_types.h, which includes host <stdint.h> before any line of the
harness or of the target's sources, so the macros have to be on the command line (`-D`), not in the harness.

`fm` stands for nginx: its config header defines `_GNU_SOURCE` and `_FILE_OFFSET_BITS` before its first system
include, and its API header declares a struct with a `struct in6_pktinfo` field.
"""

from __future__ import annotations

import json
import shlex
import subprocess
from pathlib import Path
from typing import Any

import pytest

import generate_harness as gh
import include_context as ic
import pipeline_make
from conftest import ANALYSIS_IMAGE, ROOT, require_docker_images, write_json

FM_CONFIG_H = """#ifndef FM_CONFIG_H_INCLUDED
#define FM_CONFIG_H_INCLUDED
#define FM_HAVE_PKTINFO 1
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define _FILE_OFFSET_BITS 64
#include <stddef.h>
#include <sys/types.h>
#include <netinet/in.h>
#endif
"""
FM_H = """#ifndef FM_H_INCLUDED
#define FM_H_INCLUDED
#include "fm_config.h"
struct fm_pkt {
  struct in6_pktinfo info;
  size_t len;
};
int fm_parse(const unsigned char *buf, size_t len);
#endif
"""
FM_C = """#include "fm_config.h"
#include "fm.h"
int fm_parse(const unsigned char *buf, size_t len) {
  struct fm_pkt pkt;
  if (len == 0)
    return -1;
  pkt.len = len;
  pkt.info.ipi6_ifindex = buf[0];
  return (int)pkt.info.ipi6_ifindex + (int)(pkt.len & 1u);
}
"""
# The same target without a feature-test macro: its harness and sidecar must not change.
FM_PLAIN_CONFIG_H = """#ifndef FM_CONFIG_H_INCLUDED
#define FM_CONFIG_H_INCLUDED
#define FM_HAVE_PKTINFO 1
#include <stddef.h>
#endif
"""
FM_PLAIN_H = """#ifndef FM_H_INCLUDED
#define FM_H_INCLUDED
#include "fm_config.h"
int fm_parse(const unsigned char *buf, size_t len);
#endif
"""
FM_PLAIN_C = """#include "fm_config.h"
#include "fm.h"
int fm_parse(const unsigned char *buf, size_t len) { return len ? buf[0] : -1; }
"""
FM_KEY = "src/fm.c#fm_parse"


def _fm_run(run: Path, work_in: str, plain: bool = False) -> None:
    """A run directory whose target is `fm`: work tree, build capture, Phase 0 model and DAG."""
    src = run / "workspace" / "work" / "src"
    src.mkdir(parents=True)
    for name, text in (
        ("fm_config.h", FM_PLAIN_CONFIG_H if plain else FM_CONFIG_H),
        ("fm.h", FM_PLAIN_H if plain else FM_H),
        ("fm.c", FM_PLAIN_C if plain else FM_C),
    ):
        (src / name).write_text(text, encoding="utf-8", newline="\n")
    reports = run / "workspace" / "reports"
    write_json(reports / "build_capture.json", {
        "status": "ok",
        "compiles": [{"source": "src/fm.c", "object": "src/fm.o", "cwd": ".", "flags": ["-I", "src"],
                      "system_flags": [], "headers": ["src/fm.h", "src/fm_config.h"]}],
        "units": {"fm": {"objects": ["src/fm.o"]}},
    })  # fmt: skip
    write_json(reports / "phase0_model.json", {
        "status": "ok",
        "functions": {FM_KEY: {"signature": "int(unsigned char *,unsigned long)",
                               "formals": [{"name": "buf", "kind": "const_pointer"}, {"name": "len", "kind": "value"}]}},
    })  # fmt: skip
    write_json(reports / "callgraph_dag.json", {
        "module_kind": "link_unit",
        "target_dir": work_in,
        "modules": {"fm": {"candidate_entry_points": [FM_KEY], "functions": [FM_KEY], "cppflags": [], "files": ["src/fm.c"]}},
        "functions": {FM_KEY: {"name": "fm_parse", "file": "src/fm.c", "is_static": False, "module": "fm"}},
    })  # fmt: skip


# ---------------------------------------------------------------------------
# What `gcc -E -dD` of src/fm.c prints (trimmed; the analysis image's gcc layout)
# ---------------------------------------------------------------------------


def _fm_dd_output(tree: str, sysroot: str, plain: bool = False) -> str:
    """The `-dD` text of src/fm.c: the command line's stdc-predef.h, fm_config.h, then the system headers."""
    stddef = f"{sysroot}/gcc/stddef.h"
    types = f"{sysroot}/usr/include/sys/types.h"
    features = f"{sysroot}/usr/include/features.h"
    config = (
        f'# 1 "{tree}/src/fm_config.h" 1\n#define FM_CONFIG_H_INCLUDED \n#define FM_HAVE_PKTINFO 1\n'
        + ("" if plain else "#define _GNU_SOURCE \n#define _FILE_OFFSET_BITS 64\n")
        + f'# 1 "{stddef}" 1 3 4\n#define _STDDEF_H \ntypedef long unsigned int size_t;\n'
        f'# 9 "{tree}/src/fm_config.h" 2\n'
        + (
            ""
            if plain
            else f'# 1 "{types}" 1 3 4\n# 1 "{features}" 1 3 4\n#define _FEATURES_H 1\n#define __USE_GNU 1\n'
            f'# 2 "{types}" 2 3 4\n# 10 "{tree}/src/fm_config.h" 2\n'
        )
        + f'# 2 "{tree}/src/fm.c" 2\n'
    )
    return (
        f'# 0 "{tree}/src/fm.c"\n# 0 "<built-in>"\n#define __STDC__ 1\n#define __GNUC__ 14\n'
        f'# 0 "<command-line>"\n# 1 "/usr/include/stdc-predef.h" 1 3 4\n#define _STDC_PREDEF_H 1\n'
        f'# 0 "<command-line>" 2\n# 1 "{tree}/src/fm.c"\n{config}'
        f'# 1 "{tree}/src/fm.h" 1\n#define FM_H_INCLUDED \n# 3 "{tree}/src/fm.c" 2\n'
        "int fm_parse(const unsigned char *buf, size_t len) { return 0; }\n"
    )


def _fm_system_headers(sysroot: Path) -> None:
    """The system headers the `-dD` text enters: features.h tests the two feature-test macros."""
    (sysroot / "gcc").mkdir(parents=True)
    (sysroot / "gcc" / "stddef.h").write_text("#ifndef _STDDEF_H\n#define _STDDEF_H\n#endif\n", encoding="utf-8")
    inc = sysroot / "usr" / "include"
    (inc / "sys").mkdir(parents=True)
    (inc / "sys" / "types.h").write_text("#include <features.h>\n", encoding="utf-8")
    (inc / "features.h").write_text(
        "#ifndef _FEATURES_H\n#define _FEATURES_H 1\n#ifdef _GNU_SOURCE\n# define __USE_GNU 1\n#endif\n"
        "#if defined _FILE_OFFSET_BITS && _FILE_OFFSET_BITS == 64\n# define __USE_FILE_OFFSET64 1\n#endif\n"
        "/* FM_HAVE_PKTINFO in a comment is not a test */\n#endif\n",
        encoding="utf-8",
    )


@pytest.fixture
def fm_host(run_dir, monkeypatch):
    """The `fm` run on the host, with `gcc -E -dD` replaced by `_fm_dd_output` (no compiler on the host)."""
    tree = run_dir / "workspace" / "work"
    _fm_run(run_dir, tree.as_posix())
    sysroot = run_dir / "sysroot"
    _fm_system_headers(sysroot)
    calls: list[list[str]] = []
    state: dict[str, Any] = {"plain": False}

    def fake(cmd: list[str], cwd: Path, timeout: int) -> tuple[int, str]:
        calls.append(list(cmd))
        return 0, _fm_dd_output(tree.as_posix(), sysroot.as_posix(), state["plain"])

    monkeypatch.setattr(ic, "run_preprocessor", fake)
    ic.clear_cache()
    return run_dir, calls, state


def _gen_plain_harness(run: Path, cppflags: str = "-I.") -> dict[str, Any]:
    return gh.generate_module_harness(
        module_name="fm",
        sources=["src/fm.c"],
        header_include="workspace/work/src/fm.h",
        entry_fn="fm_parse",
        max_input_size=64,
        cppflags=cppflags,
        out_dir=run / "workspace" / "harnesses",
        unit="fm",
        auto_prelude=False,
    )


# ---------------------------------------------------------------------------
# Host tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_the_scan_keeps_what_the_target_defines_before_its_first_system_header(tmp_path):
    """
    Only the macros the target's own files (or its command line) define before the compile first enters a
    system header, and that a system header tests in a conditional: not stdc-predef.h's (entered from the
    command line), not an include guard, not a config macro no system header tests.
    """
    tree = (tmp_path / "t").as_posix()
    sysroot = tmp_path / "sys"
    _fm_system_headers(sysroot)
    scan = ic.scan_feature_macros(_fm_dd_output(tree, sysroot.as_posix()), tree, generated=None)
    assert scan["first_system"] == f"{sysroot.as_posix()}/gcc/stddef.h"
    assert set(scan["defines"]) == {"FM_CONFIG_H_INCLUDED", "FM_HAVE_PKTINFO", "_GNU_SOURCE", "_FILE_OFFSET_BITS"}
    assert ic.select_feature_macros(scan) == {
        "_FILE_OFFSET_BITS": "#define _FILE_OFFSET_BITS 64",
        "_GNU_SOURCE": "#define _GNU_SOURCE",
    }
    plain = ic.scan_feature_macros(_fm_dd_output(tree, sysroot.as_posix(), plain=True), tree, generated=None)
    assert ic.select_feature_macros(plain) == {}


@pytest.mark.unit
@pytest.mark.parametrize(
    "line,flag",
    [
        ("#define _GNU_SOURCE", "-D_GNU_SOURCE="),
        ("#define _GNU_SOURCE ", "-D_GNU_SOURCE="),
        ("#define _FILE_OFFSET_BITS 64", "-D_FILE_OFFSET_BITS=64"),
        ("#define _POSIX_C_SOURCE 200809L", "-D_POSIX_C_SOURCE=200809L"),
        ("#define F(x) x", None),  # function-like
        ("#define X 1 + 2", None),  # e-acsl-gcc splits flag values on spaces
    ],
)
def test_a_macro_becomes_the_flag_that_defines_it_identically(line, flag):
    assert ic.macro_flag(line) == flag


@pytest.mark.unit
def test_the_harness_flags_get_the_targets_feature_macros(fm_host):
    """Every compile of the harness reads its sidecar's cppflags: the macros are there, with their source."""
    run, calls, _ = fm_host
    res = _gen_plain_harness(run)
    flags = shlex.split(res["cppflags"])
    assert "-D_GNU_SOURCE=" in flags and "-D_FILE_OFFSET_BITS=64" in flags, flags
    assert not [f for f in flags if "FM_HAVE_PKTINFO" in f or "INCLUDED" in f], flags
    assert pipeline_make.check_flags(flags) == [], "the Make builds' flag allowlist takes a valueless -DX="
    pre =[c for c in calls if c[:3] == ["gcc", "-E", "-dD"]]
    assert len(pre) == 1 and pre[0][-1].endswith("workspace/work/src/fm.c"), calls
    meta = json.loads((run / "workspace" / "harnesses" / "harness_fm.json").read_text(encoding="utf-8"))
    fm = meta["feature_macros"]
    assert fm["flags"] == ["-D_FILE_OFFSET_BITS=64", "-D_GNU_SOURCE="], fm
    assert fm["macros"] == {"_FILE_OFFSET_BITS": "#define _FILE_OFFSET_BITS 64", "_GNU_SOURCE": "#define _GNU_SOURCE"}
    assert fm["source"] == "build_capture" and fm["compiles"] == ["src/fm.c"], fm
    assert "gcc -E -dD" in fm["command"], fm
    # The harness text itself is unchanged: the macros live on the command line only.
    assert "_GNU_SOURCE" not in Path(res["harness_file"]).read_text(encoding="utf-8")


@pytest.mark.unit
def test_a_given_flag_is_kept_and_a_conflicting_one_is_reported(fm_host, capsys):
    """
    run-3 passed `--cppflags -D_GNU_SOURCE`: a valueless -D agrees with an empty or `1` body, so it is
    neither repeated nor reported. A different value is the user's call: kept, recorded and said on stderr.
    """
    run, _, _ = fm_host
    res = _gen_plain_harness(run, cppflags="-D_GNU_SOURCE -D_FILE_OFFSET_BITS=32 -I.")
    flags = shlex.split(res["cppflags"])
    assert flags.count("-D_GNU_SOURCE") == 1 and "-D_GNU_SOURCE=" not in flags, flags
    assert "-D_FILE_OFFSET_BITS=32" in flags and "-D_FILE_OFFSET_BITS=64" not in flags, flags
    meta = json.loads((run / "workspace" / "harnesses" / "harness_fm.json").read_text(encoding="utf-8"))
    fm = meta["feature_macros"]
    assert fm["flags"] == [] and fm["given"] == ["_GNU_SOURCE"], fm
    assert fm["conflicts"] == [
        {"macro": "_FILE_OFFSET_BITS", "given": "-D_FILE_OFFSET_BITS=32", "derived": "#define _FILE_OFFSET_BITS 64"}
    ], fm
    assert "_FILE_OFFSET_BITS" in capsys.readouterr().err


def _fm_with_bpf(run: Path, headers: list[str]) -> None:
    """A second source, src/bpf.c, in the capture (its dependency list is `headers`)."""
    (run / "workspace" / "work" / "src" / "bpf.c").write_text("#include <stddef.h>\n", encoding="utf-8")
    cap_path = run / "workspace" / "reports" / "build_capture.json"
    cap = json.loads(cap_path.read_text(encoding="utf-8"))
    cap["compiles"].append({"source": "src/bpf.c", "object": "src/bpf.o", "cwd": ".", "flags": ["-I", "src"],
                            "system_flags": [], "headers": headers})  # fmt: skip
    write_json(cap_path, cap)


def _gen_with_bpf(run: Path, header: str | None) -> tuple[list[str], dict[str, Any]]:
    out = run / "workspace" / "harnesses"
    res = gh.generate_module_harness(
        module_name="fm", sources=["src/fm.c", "src/bpf.c"], header_include=header,
        entry_fn="fm_parse", max_input_size=64, cppflags="-I.", out_dir=out, unit="fm", auto_prelude=False,
    )  # fmt: skip
    return shlex.split(res["cppflags"]), json.loads((out / "harness_fm.json").read_text(encoding="utf-8"))


@pytest.mark.unit
def test_only_the_compiles_that_include_the_harness_headers_decide(fm_host, monkeypatch):
    """
    A source that includes no header of the harness (bpf.c: <stddef.h> only) defines neither macro. The
    compiles that include the harness's headers decide, the other one is listed (the flags reach its compile
    too). Without a header to match, every compile counts, they disagree, and nothing is carried.
    """
    run, calls, _ = fm_host
    _fm_with_bpf(run, [])
    tree = (run / "workspace" / "work").as_posix()
    sysroot = (run / "sysroot").as_posix()
    bpf_out = f'# 0 "{tree}/src/bpf.c"\n# 1 "{tree}/src/bpf.c"\n# 1 "{sysroot}/gcc/stddef.h" 1 3 4\n# 2 "{tree}/src/bpf.c" 2\n'

    def fake(cmd: list[str], cwd: Path, timeout: int) -> tuple[int, str]:
        calls.append(list(cmd))
        return 0, bpf_out if cmd[-1].endswith("/bpf.c") else _fm_dd_output(tree, sysroot)

    monkeypatch.setattr(ic, "run_preprocessor", fake)
    flags, meta = _gen_with_bpf(run, "workspace/work/src/fm.h")
    fm = meta["feature_macros"]
    assert "-D_GNU_SOURCE=" in flags, flags
    assert fm["compiles"] == ["src/fm.c"] and fm["headers"] == ["fm.h"] and fm["other_sources"] == ["src/bpf.c"], fm
    assert not [c for c in calls if c[-1].endswith("/bpf.c")], calls

    flags, meta = _gen_with_bpf(run, None)
    fm = meta["feature_macros"]
    assert "-D_GNU_SOURCE=" not in flags, flags
    assert fm["flags"] == [] and fm["macros"] == {}, fm
    assert sorted(d["macro"] for d in fm["differing"]) == ["_FILE_OFFSET_BITS", "_GNU_SOURCE"], fm
    assert fm["differing"][0]["compiles"] == {"src/bpf.c": None}, fm
    assert fm["differing"][0]["values"] == {"#define _FILE_OFFSET_BITS 64": 1, ic.UNDEFINED: 1}, fm


@pytest.mark.unit
def test_a_source_that_defines_them_after_a_system_header_agrees(fm_host, monkeypatch):
    """
    nginx run-3's src/event/quic/ngx_event_quic_bpf_code.c (generated) includes <stddef.h> and <stdint.h>
    before ngx_bpf.h, which includes ngx_config.h: it defines `_GNU_SOURCE` too, only after its first
    system header, like the harness. The value agrees, so the macro is carried; `late` names the source.
    """
    run, calls, _ = fm_host
    _fm_with_bpf(run, ["src/fm.h", "src/fm_config.h"])
    tree = (run / "workspace" / "work").as_posix()
    sysroot = (run / "sysroot").as_posix()
    bpf_out = (
        f'# 0 "{tree}/src/bpf.c"\n# 1 "{tree}/src/bpf.c"\n# 1 "{sysroot}/gcc/stddef.h" 1 3 4\n'
        f'# 2 "{tree}/src/bpf.c" 2\n# 1 "{tree}/src/fm_config.h" 1\n#define FM_CONFIG_H_INCLUDED \n'
        f'#define _GNU_SOURCE \n#define _FILE_OFFSET_BITS 64\n# 1 "{sysroot}/usr/include/features.h" 1 3 4\n'
        f'# 2 "{tree}/src/fm_config.h" 2\n# 3 "{tree}/src/bpf.c" 2\n'
    )

    def fake(cmd: list[str], cwd: Path, timeout: int) -> tuple[int, str]:
        calls.append(list(cmd))
        return 0, bpf_out if cmd[-1].endswith("/bpf.c") else _fm_dd_output(tree, sysroot)

    monkeypatch.setattr(ic, "run_preprocessor", fake)
    flags, meta = _gen_with_bpf(run, "workspace/work/src/fm.h")
    fm = meta["feature_macros"]
    assert "-D_GNU_SOURCE=" in flags and "-D_FILE_OFFSET_BITS=64" in flags, flags
    assert fm["compiles"] == ["src/bpf.c", "src/fm.c"] and "other_sources" not in fm, fm
    assert fm["late"] == {"_FILE_OFFSET_BITS": ["src/bpf.c"], "_GNU_SOURCE": ["src/bpf.c"]}, fm
    assert "differing" not in fm, fm


@pytest.mark.unit
def test_a_compile_that_cannot_be_preprocessed_is_said_and_recorded(fm_host, monkeypatch, capsys):
    """
    No gcc, or a failing `gcc -E`, must not look like a target without feature macros: the generator says it
    on stderr and the sidecar lists it under `failed`. When some compiles succeed, their macros are carried.
    """
    run, calls, _ = fm_host
    _fm_with_bpf(run, ["src/fm.h", "src/fm_config.h"])
    tree = (run / "workspace" / "work").as_posix()
    sysroot = (run / "sysroot").as_posix()
    fail_all = {"on": True}

    def fake(cmd: list[str], cwd: Path, timeout: int) -> tuple[int, str]:
        calls.append(list(cmd))
        if fail_all["on"] or cmd[-1].endswith("/bpf.c"):
            return 1, "src/bpf.c:1:10: fatal error: missing.h: No such file or directory"
        return 0, _fm_dd_output(tree, sysroot)

    monkeypatch.setattr(ic, "run_preprocessor", fake)
    flags, meta = _gen_with_bpf(run, "workspace/work/src/fm.h")
    fm = meta["feature_macros"]
    assert "-D_GNU_SOURCE=" not in flags, flags
    assert fm["compiles"] == [] and fm["macros"] == {} and fm["flags"] == [], fm
    assert [f["source"] for f in fm["failed"]] == ["src/bpf.c", "src/fm.c"], fm
    assert "missing.h" in fm["failed"][0]["error"], fm
    assert "could not be preprocessed" in capsys.readouterr().err

    fail_all["on"] = False
    ic.clear_cache()
    flags, meta = _gen_with_bpf(run, "workspace/work/src/fm.h")
    fm = meta["feature_macros"]
    assert "-D_GNU_SOURCE=" in flags and "-D_FILE_OFFSET_BITS=64" in flags, flags
    assert fm["compiles"] == ["src/fm.c"] and [f["source"] for f in fm["failed"]] == ["src/bpf.c"], fm


@pytest.mark.unit
def test_a_target_without_feature_macros_gets_the_same_harness_and_sidecar(fm_host):
    """No macro derived: the harness and its sidecar are byte for byte those of a run without a capture."""
    run, calls, state = fm_host
    state["plain"] = True
    _gen_plain_harness(run)
    out = run / "workspace" / "harnesses"
    with_capture = ((out / "harness_fm.c").read_bytes(), (out / "harness_fm.json").read_bytes())
    assert calls, "the capture's compile was preprocessed"
    (run / "workspace" / "reports" / "build_capture.json").unlink()
    ic.clear_cache()
    for f in out.iterdir():
        f.unlink()
    _gen_plain_harness(run)
    assert ((out / "harness_fm.c").read_bytes(), (out / "harness_fm.json").read_bytes()) == with_capture
    assert b"feature_macros" not in with_capture[1]


# ---------------------------------------------------------------------------
# Docker: the analysis image's own compilers and libc
# ---------------------------------------------------------------------------


FM_DOCKER_SCRIPT = r"""cd /w && export FRAMAC_CACHE=off
timeout 600 python3 /opt/framac-pipeline/scripts/generate_harness.py --api --module fm --unit fm \
  --header workspace/work/src/fm.h > gen.json 2> gen.err
echo gen_rc=$?
cat gen.json gen.err
[ -f workspace/harnesses/harness_fm.json ] || exit 0
python3 fm_flags.py
H=workspace/harnesses/harness_fm.c
timeout 120 clang -fsyntax-only -x c $(cat harness.flags) $H; echo clang_rc=$?
timeout 120 gcc -E -D__FRAMAC__ $(cat frontend.flags) $H > eacsl.i; echo eacsl_cpp_rc=$?
echo eacsl_pktinfo=$(grep -c 'ipi6_ifindex;' eacsl.i)
timeout 300 frama-c -no-unicode -machdep gcc_x86_64 -cpp-extra-args="$(cat eva.flags)" $H > eva.log 2>&1
echo eva_parse_rc=$?
tail -5 eva.log
"""
# The flags each consumer compiles the harness with, from its sidecar: the clang probes and the LibFuzzer
# build, the E-ACSL frontend (without its cpp wrapper) and Eva.
FM_FLAGS_PY = """import json, shlex, sys
sys.path.insert(0, "/opt/framac-pipeline/scripts")
from eacsl_toolchain import build_eacsl_flag_sets
from framac_common import augment_framac_cppflags
from target_env import with_include_flags
flags = json.load(open("workspace/harnesses/harness_fm.json"))["cppflags"]
front = shlex.split(build_eacsl_flag_sets(with_include_flags(flags), fuzzer=False)["frontend"])
drop = {i for i, t in enumerate(front) if t == "-wrapper"}
front = [t for i, t in enumerate(front) if i not in drop and i - 1 not in drop]
open("frontend.flags", "w").write(shlex.join(front))
open("eva.flags", "w").write(augment_framac_cppflags(flags))
open("harness.flags", "w").write(with_include_flags(flags))
"""


def _fm_docker(run: Path, script: str) -> str:
    (run / "fm_flags.py").write_text(FM_FLAGS_PY, encoding="utf-8", newline="\n")
    tag = "pytest-harness-feature-macros"
    proc = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "--label", f"framac.run={tag}",
         "-v", f"{run}:/w",
         "-v", f"{ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
         "-v", f"{ROOT / 'templates'}:/opt/framac-pipeline/templates:ro",
         "-v", f"{ROOT / 'schemas'}:/opt/framac-pipeline/schemas:ro",
         "--entrypoint", "sh", ANALYSIS_IMAGE, "-c", script],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1200, check=False,
    )  # fmt: skip
    return proc.stdout + proc.stderr


@pytest.mark.integration
@pytest.mark.slow
def test_an_api_harness_compiles_when_the_target_defines_gnu_source_in_its_config_header(tmp_path):
    """
    nginx run-3 in miniature: without the target's `_GNU_SOURCE` before the harness's first system include,
    `struct fm_pkt`'s `struct in6_pktinfo` field is incomplete and the --api generation fails. With it on the
    harness's command line, the clang probes, the E-ACSL frontend (host glibc behind fc_compat_types.h) and
    the Eva parse (Frama-C's libc) all see the struct.
    """
    require_docker_images(ANALYSIS_IMAGE)
    run = tmp_path / "run"
    _fm_run(run, "/w/workspace/work")
    out = _fm_docker(run, FM_DOCKER_SCRIPT)
    assert "incomplete type 'struct in6_pktinfo'" not in out, out
    assert "gen_rc=0" in out, out
    meta = json.loads((run / "workspace" / "harnesses" / "harness_fm.json").read_text(encoding="utf-8"))
    flags = shlex.split(meta["cppflags"])
    assert "-D_GNU_SOURCE=" in flags and "-D_FILE_OFFSET_BITS=64" in flags, meta["cppflags"]
    assert meta["feature_macros"]["compiles"] == ["src/fm.c"], meta["feature_macros"]
    assert sorted(meta["feature_macros"]["macros"]) == ["_FILE_OFFSET_BITS", "_GNU_SOURCE"], meta["feature_macros"]
    assert meta["dispatch_case_count"] == 1, meta
    assert "clang_rc=0" in out, out
    assert "eacsl_cpp_rc=0" in out and "eacsl_pktinfo=0" not in out, out
    assert "eva_parse_rc=0" in out, out


@pytest.mark.integration
@pytest.mark.slow
def test_an_api_harness_of_a_target_without_feature_macros_gets_no_flag(tmp_path):
    require_docker_images(ANALYSIS_IMAGE)
    run = tmp_path / "run"
    _fm_run(run, "/w/workspace/work", plain=True)
    out = _fm_docker(run, FM_DOCKER_SCRIPT)
    assert "gen_rc=0" in out, out
    meta = json.loads((run / "workspace" / "harnesses" / "harness_fm.json").read_text(encoding="utf-8"))
    assert "feature_macros" not in meta and "-D" not in meta["cppflags"], meta
