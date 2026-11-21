"""
stub_gen.py on a variadic external declared in a header that refuses direct inclusion (sudo run-1, glibc 2.41):
`ptrace` is declared in <bits/ptrace-shared.h>, whose `#error` demands <sys/ptrace.h>, and the Phase 0 dump
prints it after the Variadic plugin's translation, `ptrace(enum __ptrace_request __request, void * const
*__va_params)`. The overlay must shadow <sys/ptrace.h> and redeclare `ptrace(enum __ptrace_request, ...)`.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

import framac_common
import phase0_model
import stub_gen
from conftest import ANALYSIS_IMAGE, ROOT, require_docker_images, write_json

VA_SNAP = "/framac-run/workspace/snapshot/root"
VA_MULTIARCH = "usr/include/x86_64-linux-gnu"
# The shape of glibc 2.41's headers: the declaration in the bits/ header, behind its direct-include guard.
VA_BITS_PTRACE_H = """\
#ifndef _SYS_PTRACE_H
# error "Never use <bits/ptrace-shared.h> directly; include <sys/ptrace.h> instead."
#endif
enum __ptrace_request { PTRACE_TRACEME = 0 };
extern long int ptrace (enum __ptrace_request __request, ...) __THROW;
"""
VA_SYS_PTRACE_H = """\
#ifndef _SYS_PTRACE_H
#define _SYS_PTRACE_H 1
#include <bits/ptrace-shared.h>
#endif
"""
VA_TRANSLATED = "extern long ptrace(enum __ptrace_request __request, void * const *__va_params)"
VA_FORMALS = [{"name": "__request", "kind": "value"}, {"name": "__va_params", "kind": "const_pointer"}]
# The draft the unfixed generator wrote in sudo run-1 (workspace/stubs/bits/ptrace-shared.h).
VA_STALE_DRAFT = (
    "#pragma once\n#include_next <bits/ptrace-shared.h>\n#include <errno.h>\n\n"
    "/* fc-stub: ptrace */\n"
    "/* TODO(stub-author): write ptrace's contract from the library's documentation, then delete this line, "
    "the #ifdef FC_STUB_DRAFT line and its #endif. */\n"
    "#ifdef FC_STUB_DRAFT\n/*@\n  assigns \\result \\from __request, __va_params;\n*/\n"
    f"{VA_TRANSLATED};\n#endif\n"
)


def _va_model(decl: str = f"{VA_SNAP}/{VA_MULTIARCH}/bits/ptrace-shared.h:152") -> dict:
    return {
        "status": "ok",
        "functions": {"src/exec_ptrace.c#ptrace_getregs": {"external_calls": ["ptrace"]}},
        "externals": ["ptrace"],
        "external_formals": {"ptrace": VA_FORMALS},
        "external_decls": {
            "ptrace": {"decl": decl, "proto": VA_TRANSLATED, "signature": "long(enum __ptrace_request,void **)"}
        },
    }


@pytest.fixture
def va_run(run_dir, monkeypatch):
    """A run directory with the ptrace model and a fake snapshot of glibc 2.41's two headers."""
    root = run_dir / "fs"
    inc = root / VA_SNAP.lstrip("/") / VA_MULTIARCH
    (inc / "bits").mkdir(parents=True)
    (inc / "sys").mkdir(parents=True)
    (inc / "bits" / "ptrace-shared.h").write_text(VA_BITS_PTRACE_H, encoding="utf-8", newline="\n")
    (inc / "sys" / "ptrace.h").write_text(VA_SYS_PTRACE_H, encoding="utf-8", newline="\n")
    write_json(run_dir / stub_gen.DEFAULT_MODEL, _va_model())
    monkeypatch.setenv("FRAMAC_STUB_OVERLAY_DIR", str(run_dir / "workspace" / "stubs"))

    def run() -> dict:
        rc = stub_gen.cmd_run(
            Path(stub_gen.DEFAULT_MODEL),
            Path(stub_gen.DEFAULT_CAPTURE),
            Path(framac_common.STUB_OVERLAY_REL),
            Path(framac_common.STUB_REPORT_REL),
            read_root=root.as_posix(),
        )
        assert rc == 0
        return json.loads((run_dir / framac_common.STUB_REPORT_REL).read_text(encoding="utf-8"))

    return run


@pytest.mark.unit
@pytest.mark.parametrize(
    "printed, source",
    [
        (VA_TRANSLATED, "extern long ptrace(enum __ptrace_request __request, ...)"),
        ("void warnx(char const *fmt, void * const *__va_params)", "void warnx(char const *fmt, ...)"),
        (
            "_Bool ( /* format attribute */ f)(char const * restrict fmt, void * const *__va_params) "
            "__attribute__(( __nonnull__(1)))",
            "_Bool ( /* format attribute */ f)(char const * restrict fmt, ...) __attribute__(( __nonnull__(1)))",
        ),
        ("int g(void * const *__va_params)", "int g(...)"),
        (
            "extern int printf(char const * restrict format , ...)",
            "extern int printf(char const * restrict format , ...)",
        ),
        ("int h(void * const *p, int n)", "int h(void * const *p, int n)"),
    ],
)
def test_restore_variadic_proto_gives_back_the_ellipsis(printed, source):
    assert framac_common.restore_variadic_proto(printed) == source
    assert framac_common.restore_variadic_proto(source) == source


@pytest.mark.unit
def test_the_model_records_the_source_prototype_of_a_translated_declaration():
    dumped = {
        "name": "ptrace",
        "decl": "/usr/include/x86_64-linux-gnu/bits/ptrace-shared.h:152",
        "proto": VA_TRANSLATED,
        "signature": "long(enum __ptrace_request,void **)",
        "formals": VA_FORMALS,
    }
    rec = phase0_model.declared_record(dumped)
    assert rec["proto"] == "extern long ptrace(enum __ptrace_request __request, ...)"
    # The signature stays the kernel's: its `void **` (with the `__va_params` formal) marks a variadic function.
    assert rec["signature"] == "long(enum __ptrace_request,void **)" and rec["decl"] == dumped["decl"]


@pytest.mark.unit
def test_a_header_that_refuses_direct_inclusion_is_never_shadowed(va_run, run_dir):
    report = va_run()
    stubs = run_dir / "workspace" / "stubs"
    assert not (stubs / "bits" / "ptrace-shared.h").exists()
    text = (stubs / "sys" / "ptrace.h").read_text(encoding="utf-8")
    assert "#include_next <sys/ptrace.h>\n" in text
    rec = report["headers"]["workspace/stubs/sys/ptrace.h"]
    assert rec["include_name"] == "sys/ptrace.h"
    assert rec["real"] == f"/{VA_MULTIARCH}/sys/ptrace.h"
    # Where the function is declared is still recorded as Frama-C saw it.
    assert rec["functions"]["ptrace"]["declared_in"] == f"/{VA_MULTIARCH}/bits/ptrace-shared.h"


@pytest.mark.unit
def test_a_variadic_skeleton_redeclares_the_ellipsis_and_names_fixed_parameters_only(va_run, run_dir):
    va_run()
    text = (run_dir / "workspace" / "stubs" / "sys" / "ptrace.h").read_text(encoding="utf-8")
    block = stub_gen.split_blocks(text)["ptrace"]
    assert "extern long ptrace(enum __ptrace_request __request, ...);" in block
    assert "__va_params" not in block
    assert "assigns \\result \\from __request;" in block
    assert "variadic (`...`)" in block


@pytest.mark.unit
def test_public_header_name_reads_the_guards_of_glibc_and_glib(tmp_path):
    glib = tmp_path / "gtypes.h"
    glib.write_text(
        '#if !defined (__GLIB_H_INSIDE__)\n#error "Only <glib.h> can be included directly."\n#endif\n', encoding="utf-8"
    )
    assert stub_gen.public_header_name(glib, "/usr/include/glib-2.0/glib/gtypes.h") == "glib.h"
    bits = tmp_path / "ptrace-shared.h"
    bits.write_text(VA_BITS_PTRACE_H, encoding="utf-8")
    assert stub_gen.public_header_name(bits, "/usr/include/x86_64-linux-gnu/bits/ptrace-shared.h") == "sys/ptrace.h"
    plain = tmp_path / "plain.h"
    plain.write_text('#ifndef X\n#error "X must be defined: see <config.h>"\n#endif\nint f(int);\n', encoding="utf-8")
    assert stub_gen.public_header_name(plain, "/usr/include/plain.h") is None


@pytest.mark.unit
def test_rerun_retires_the_stale_draft_of_a_guarded_header(va_run, run_dir):
    stale = run_dir / "workspace" / "stubs" / "bits" / "ptrace-shared.h"
    stale.parent.mkdir(parents=True)
    stale.write_text(VA_STALE_DRAFT, encoding="utf-8", newline="\n")
    report = va_run()
    assert not stale.exists()
    assert report["removed"] == {"workspace/stubs/bits/ptrace-shared.h": {"ptrace": "sys/ptrace.h"}}
    assert sorted(report["headers"]) == ["workspace/stubs/sys/ptrace.h"]


@pytest.mark.unit
def test_rerun_keeps_a_filled_contract_in_the_stale_header(va_run, run_dir):
    stale = run_dir / "workspace" / "stubs" / "bits" / "ptrace-shared.h"
    stale.parent.mkdir(parents=True)
    drop = ("TODO(stub-author)", "FC_STUB_DRAFT", "#endif")
    filled = "\n".join(line for line in VA_STALE_DRAFT.splitlines() if not any(d in line for d in drop)) + "\n"
    stale.write_text(filled, encoding="utf-8", newline="\n")
    report = va_run()
    assert stale.read_text(encoding="utf-8") == filled
    assert report["removed"] == {}
    assert report["headers"]["workspace/stubs/bits/ptrace-shared.h"]["functions"]["ptrace"]["state"] == "filled"


@pytest.mark.unit
def test_rerun_rewrites_a_translated_draft_but_never_a_filled_block(va_run, run_dir, monkeypatch):
    # The header is right (no guard), the draft came from a model that kept the translation.
    model = _va_model(decl=f"{VA_SNAP}/{VA_MULTIARCH}/sys/ptrace.h:4")
    write_json(run_dir / stub_gen.DEFAULT_MODEL, model)
    header = run_dir / "workspace" / "stubs" / "sys" / "ptrace.h"
    header.parent.mkdir(parents=True)
    header.write_text(VA_STALE_DRAFT.replace("bits/ptrace-shared.h", "sys/ptrace.h"), encoding="utf-8", newline="\n")
    va_run()
    text = header.read_text(encoding="utf-8")
    assert "__va_params" not in text and text.count("/* fc-stub: ptrace */") == 1
    assert "extern long ptrace(enum __ptrace_request __request, ...);" in text
    # An author's active block is never touched, even with the translated formal.
    active = (
        "#pragma once\n#include_next <sys/ptrace.h>\n\n/* fc-stub: ptrace */\n"
        f"/*@ assigns \\result \\from __request; */\n{VA_TRANSLATED};\n"
    )
    header.write_text(active, encoding="utf-8", newline="\n")
    va_run()
    assert header.read_text(encoding="utf-8") == active


# The Docker check mirrors the reproduction: the real glibc 2.41 of the analysis image, Frama-C's dump, the
# model's record, stub_gen, stub_check's ABI probe on the draft, then Eva and gcc on the filled overlay.
VA_MAIN_C = """\
#define _GNU_SOURCE 1
#include <sys/ptrace.h>
#include <vlib/vlib.h>
int main(void)
{
    long r = ptrace(PTRACE_TRACEME, 0, 0, 0);
    r += vl_log(1, "x=%d", 3);
    return (int)(r + vl_ctl(2, (void *)0, 4));
}
"""
VA_VLIB_H = """\
#ifndef VLIB_H
#define VLIB_H
int vl_log(int level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
long vl_ctl(int op, ...);
#endif
"""
VA_MKMODEL_PY = """\
import json, sys
sys.path.insert(0, "/opt/framac-pipeline/scripts")
import phase0_model
dump = json.load(open("dump.json"))
names = ["ptrace", "vl_log", "vl_ctl"]
declared = {d["name"]: d for d in dump["declared"]}
model = {"status": "ok", "functions": {"a.c#main": {"external_calls": names}}, "externals": names,
         "external_formals": {n: declared[n]["formals"] for n in names},
         "external_decls": {n: phase0_model.declared_record(declared[n]) for n in names}}
json.dump(model, open("model.json", "w"))
"""
VA_FILL_PY = """\
import sys
for p in sys.argv[1:]:
    lines = open(p).read().splitlines()
    keep = [ln for ln in lines if "TODO(stub-author)" not in ln and "FC_STUB_DRAFT" not in ln and ln != "#endif"]
    open(p, "w").write("\\n".join(keep) + "\\n")
"""
VA_SCRIPT = """\
set -e
rm -rf /tmp/w /tmp/vinc && cp -r /w /tmp/w && cp -r /w/inc /tmp/vinc && cd /tmp/w
S=/opt/framac-pipeline/scripts
SYS='-I/tmp/vinc -idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include'
cp $S/phase0_dump.ml . && timeout 300 ocamlfind ocamlopt -shared -w -a -package frama-c.kernel phase0_dump.ml -o d.cmxs
FRAMAC_P0_DUMP_OUT=/tmp/w/dump.json timeout 300 frama-c -no-annot -cpp-extra-args="$SYS" a.c -load-module ./d.cmxs >/dev/null
timeout 60 python3 mkmodel.py
mkdir -p workspace/reports
echo '{"compiles": [{"system_flags": ["-I/tmp/vinc"]}]}' > workspace/reports/build_capture.json
CAP=workspace/reports/build_capture.json
timeout 120 python3 $S/stub_gen.py run --model model.json --capture $CAP --overlay workspace/stubs --out workspace/reports/stubs.json
cat workspace/stubs/sys/ptrace.h
export FRAMAC_STUB_OVERLAY_DIR=/tmp/w/workspace/stubs
OUT=workspace/reports/stub_check.json
timeout 300 python3 $S/stub_check.py run --checks abi --model model.json --out $OUT || true
python3 -c "import json; print('abi=' + json.load(open('$OUT'))['headers']['workspace/stubs/sys/ptrace.h']['abi']['status'])"
timeout 60 python3 fill.py workspace/stubs/sys/ptrace.h workspace/stubs/vlib/vlib.h
EVA="-eva -eva-no-alloc-returns-null"
FC="frama-c -no-unicode -machdep gcc_x86_64"
timeout 300 $FC -cpp-extra-args="-I/tmp/w/workspace/stubs $SYS" a.c $EVA > eva.log 2>&1 && echo eva_exit=0 || { echo "eva_exit=$?"; tail -40 eva.log; }
grep "Neither code nor specification" eva.log || true
timeout 60 gcc -fsyntax-only -I/tmp/w/workspace/stubs -I/tmp/vinc a.c && echo gcc_ok
"""


@pytest.mark.integration
@pytest.mark.slow
def test_ptrace_overlay_passes_abi_eva_and_gcc_in_the_image(tmp_path):
    require_docker_images(ANALYSIS_IMAGE)
    (tmp_path / "inc" / "vlib").mkdir(parents=True)
    files = {
        "a.c": VA_MAIN_C,
        "inc/vlib/vlib.h": VA_VLIB_H,
        "mkmodel.py": VA_MKMODEL_PY,
        "fill.py": VA_FILL_PY,
        "run.sh": VA_SCRIPT,
    }
    for rel, text in files.items():
        (tmp_path / rel).write_text(text, encoding="utf-8", newline="\n")
    proc = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "--label", "framac.run=pytest-stub-gen-variadic",
         "-v", f"{tmp_path}:/w:ro", "-v", f"{ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
         "-v", f"{ROOT / 'templates'}:/opt/framac-pipeline/templates:ro",
         "--entrypoint", "sh", ANALYSIS_IMAGE, "-c", "timeout 1200 sh /w/run.sh"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1500, check=False,
    )  # fmt: skip
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert "#include_next <sys/ptrace.h>" in out and "extern long ptrace(enum __ptrace_request __request, ...);" in out
    assert "abi=passed" in out, out
    assert "eva_exit=0" in out, out
    assert "Neither code nor specification for function ptrace" not in out, out
    assert "Neither code nor specification for function vl_" not in out, out
    assert "gcc_ok" in out, out
