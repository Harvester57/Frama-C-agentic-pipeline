"""
--api cases for callbacks and zero-terminated arrays (QCBOR run-6 open bug #9, dispatch case 166):
a function-pointer parameter gets a benign stub of its prototype, spelled from clang's AST with the
headers' own typedefs, instead of NULL; an input byte array whose call sites pass several sizes and no
length is zero-terminated.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

import api_harness as A

pytestmark = pytest.mark.unit


def _fn(name: str, *params: str) -> dict[str, Any]:
    return {
        "kind": "FunctionDecl",
        "name": name,
        "type": {"qualType": "void (...)"},
        "inner": [{"kind": "ParmVarDecl", "name": f"p{i}", "type": {"qualType": t}} for i, t in enumerate(params)],
    }


def _typedef(name: str, qual: str) -> dict[str, Any]:
    return {"kind": "TypedefDecl", "name": name, "type": {"qualType": qual}}


def test_callback_prototypes_follow_typedefs_without_desugaring():
    tree = {
        "kind": "TranslationUnitDecl",
        "inner": [
            _typedef("QCBORError", "enum QCBORError"),
            _typedef("QCBORTagContentCallBack", "QCBORError (QCBORDecodeContext *, void *, uint64_t, QCBORItem *)"),
            _typedef("plain_cb", "int (*)(int, const char *)"),
            _typedef("bad_cb", "void (*)(int (*)(int))"),
            _typedef("anon_cb", "enum (unnamed at x.h:3:9) (*)(void)"),
            _fn(
                "QCBORDecode_Private_ProcessTagItem",
                "QCBORDecodeContext *",
                "QCBORTagContentCallBack *",
                "void *",
                "plain_cb",
                "void (*)(void)",
                "bad_cb",
                "anon_cb",
                "const plain_cb",
            ),
        ],
    }
    got = A.callback_prototypes(tree)["QCBORDecode_Private_ProcessTagItem"]
    assert got[1] == {"ret": "QCBORError", "params": ["QCBORDecodeContext *", "void *", "uint64_t", "QCBORItem *"]}
    assert got[3] == {"ret": "int", "params": ["int", "const char *"]}
    assert got[4] == {"ret": "void", "params": []}
    assert got[7] == got[3]
    assert 0 not in got and 2 not in got  # not function pointers
    assert 5 not in got and 6 not in got  # a nested function pointer, an unnamed type: not spellable


def test_callback_stub_writes_nothing_and_returns_zero():
    stub = A.callback_stub("framac_cb_f_1", {"ret": "const struct r", "params": ["void *", "unsigned long"]})
    assert stub.startswith("static const struct r framac_cb_f_1(void * fc_p0, unsigned long fc_p1) {")
    assert "struct r fc_r; memset(&fc_r, 0, sizeof(fc_r)); return fc_r;" in stub
    assert "const struct r fc_r" not in stub
    void_stub = A.callback_stub("s", {"ret": "void", "params": []})
    assert void_stub.startswith("static void s(void) {") and "return" not in void_stub
    assert void_stub.endswith(f"/* {A.CALLBACK_STUB_MARKER} */") and "\n" not in void_stub


WALK_SIG = "int(unsigned char *,int (*)(void *ctx, unsigned long v),void *)"


def _walk_rec(sizes: dict[str, int] | None = None) -> dict[str, Any]:
    rec: dict[str, Any] = {
        "signature": WALK_SIG,
        "formals": [
            {"name": "types", "kind": "const_pointer"},
            {"name": "cb", "kind": "pointer"},
            {"name": "ctx", "kind": "pointer"},
        ],
    }
    if sizes:
        rec["param_sizes"] = {"0": {**sizes, "sites": 3}}
    return rec


CALLBACKS = {"walk": {1: {"ret": "int", "params": ["void *", "unsigned long"]}}}


def test_function_pointer_gets_a_stub_when_its_prototype_is_known():
    api = A.ApiInfo(callbacks=CALLBACKS)
    stmt, layout, why = A.single_case("walk", _walk_rec(), 4096, api)
    assert why is None and stmt is not None and layout is not None
    assert "(unsigned char *)c0a0, framac_cb_walk_1, (void *)c0a2)" in stmt
    assert set(api.stubs) == {"framac_cb_walk_1"}
    assert A.stubs_used([stmt], api.stubs) == [api.stubs["framac_cb_walk_1"]]
    assert any("framac_cb_walk_1" in n for n in layout["notes"])

    # Without the probe's prototype: NULL, and the notes say so.
    api = A.ApiInfo()
    stmt, layout, _ = A.single_case("walk", _walk_rec(), 4096, api)
    assert stmt is not None and layout is not None
    assert "(unsigned char *)c0a0, 0, (void *)" in stmt and api.stubs == {}
    assert any("function pointer: NULL" in n for n in layout["notes"])


def test_byte_array_of_several_call_site_sizes_is_zero_terminated():
    stmt, layout, _ = A.single_case("walk", _walk_rec({"min": 2, "max": 6}), 4096, A.ApiInfo())
    assert stmt is not None and layout is not None
    fill = stmt.index("memcpy(c0a0,")
    term = stmt.index("c0a0[sizeof(c0a0) - 1] = 0;")
    call = stmt.index("walk(")
    assert fill < term < call
    # The slot layout (what seeds fill) is unchanged: 6 input bytes.
    assert layout["slots"] == [{"call": 0, "param": 0, "size": 6, "kind": "bytes"}]
    assert any("zero-terminated" in n for n in layout["notes"])


def test_fixed_size_byte_array_is_not_terminated():
    stmt, _, _ = A.single_case("walk", _walk_rec({"min": 6, "max": 6}), 4096, A.ApiInfo())
    assert stmt is not None and "sizeof(c0a0) - 1] = 0" not in stmt


def test_wider_sentinel_array_is_left_as_read_with_a_note():
    rec = {
        "signature": "int(unsigned long *)",
        "formals": [{"name": "tags", "kind": "const_pointer"}],
        "param_sizes": {"0": {"min": 16, "max": 24, "sites": 8}},
    }
    stmt, layout, _ = A.single_case("tags", rec, 4096, A.ApiInfo())
    assert stmt is not None and layout is not None
    assert "- 1] = 0" not in stmt
    assert any("sentinel the generator does not know" in n for n in layout["notes"])


def test_stub_errors_only_recognises_errors_on_stub_lines(tmp_path):
    h = tmp_path / "harness_m.c"
    h.write_text(f"int x;\nstatic int s(void) {{ return 0; }} /* {A.CALLBACK_STUB_MARKER} */\nint y;\n")
    # As the compiler in the analysis image prints them (POSIX paths).
    p = "/framac-run/workspace/harnesses/harness_m.c"
    assert A._stub_errors_only(h, [f"{p}:2:8: error: unknown type name 'T'"]) is True
    assert A._stub_errors_only(h, [f"{p}:2:8: error: x", f"{p}:3:1: error: y"]) is False
    assert A._stub_errors_only(h, []) is False


def test_generate_writes_the_stub_after_the_headers(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    src_dir = tmp_path / "workspace" / "work" / "src"
    src_dir.mkdir(parents=True)
    (src_dir / "walk.c").write_text(WALK_C, encoding="utf-8")
    (src_dir / "walk.h").write_text(WALK_H, encoding="utf-8")
    key = "workspace/work/src/walk.c#walk"
    reports = tmp_path / "workspace" / "reports"
    reports.mkdir(parents=True)
    dag = {
        "module_kind": "link_unit",
        "modules": {"m": {"candidate_entry_points": [key], "functions": [key]}},
        "functions": {key: {"name": "walk", "file": "workspace/work/src/walk.c", "is_static": False, "module": "m"}},
    }
    (reports / "callgraph_dag.json").write_text(json.dumps(dag), encoding="utf-8")
    (reports / "phase0_model.json").write_text(
        json.dumps({"status": "ok", "functions": {key: _walk_rec({"min": 2, "max": 6})}}), encoding="utf-8"
    )
    out_dir = tmp_path / "workspace" / "harnesses"
    A.generate(
        module="m",
        header="workspace/work/src/walk.h",
        max_input_size=64,
        cppflags="",
        out_dir=out_dir,
        auto_prelude=False,
        probe=False,
        dag_path=reports / "callgraph_dag.json",
        model_path=reports / "phase0_model.json",
        struct_layouts={},
        visible=A.Declared({"walk"}, {}, CALLBACKS),
    )
    text = (out_dir / "harness_m.c").read_text(encoding="utf-8")
    stub_at = text.index("static int framac_cb_walk_1(void * fc_p0, unsigned long fc_p1)")
    assert text.index('walk.h"') < stub_at < text.index("case 0U:")
    assert text.count("static int framac_cb_walk_1(") == 1
    assert "c0a0[sizeof(c0a0) - 1] = 0;" in text
    sidecar = json.loads((out_dir / "harness_m.json").read_text(encoding="utf-8"))
    assert "warnings" not in sidecar, sidecar.get("warnings")


# --- compiled and run ---------------------------------------------------------------------------------

WALK_H = "typedef int (walk_cb)(void *ctx, unsigned long v);\nint walk(const unsigned char *types, walk_cb *cb, void *ctx);\n"
WALK_C = (
    '#include "walk.h"\n'
    "int walk(const unsigned char *types, walk_cb *cb, void *ctx) {\n"
    "    int n = 0;\n"
    "    while (*types) { n += cb(ctx, *types); types++; }\n"
    "    return n;\n"
    "}\n"
)


def _docker(tmp_path: Path, script: str) -> subprocess.CompletedProcess[str]:
    from conftest import ANALYSIS_IMAGE

    argv = [
        "docker", "run", "--rm", "--network", "none", "--memory", "2g",
        "-v", f"{tmp_path}:/fixture:ro", ANALYSIS_IMAGE, script,
    ]  # fmt: skip
    return subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)


def test_generated_case_with_stub_and_terminator_runs_clean_under_asan(tmp_path):
    """
    The stub and the terminator, generated from clang's real AST of the header, compiled with ASan and
    run on an all-0xff input: the case returns. The same case with NULL (or without the terminator)
    crashes, so the test bites. Host clang, else the analysis image under FRAMAC_DOCKER_TESTS=1.
    """
    (tmp_path / "walk.h").write_text(WALK_H, encoding="utf-8")
    (tmp_path / "walk.c").write_text(WALK_C, encoding="utf-8")
    (tmp_path / "probe.c").write_text('#include "walk.h"\n', encoding="utf-8")
    clang = shutil.which("clang")
    if clang:
        ast = subprocess.run(
            [clang, "-fsyntax-only", "-Xclang", "-ast-dump=json", "-x", "c", str(tmp_path / "probe.c")],
            capture_output=True, text=True, check=True,
        ).stdout  # fmt: skip
    else:
        from conftest import ANALYSIS_IMAGE, require_docker_images

        require_docker_images(ANALYSIS_IMAGE)
        proc = _docker(tmp_path, "timeout 60 clang -fsyntax-only -Xclang -ast-dump=json -x c /fixture/probe.c")
        assert proc.returncode == 0, proc.stderr[-2000:]
        ast = proc.stdout
    callbacks = A.callback_prototypes(json.loads(ast))
    assert callbacks["walk"] == {1: {"ret": "int", "params": ["void *", "unsigned long"]}}

    api = A.ApiInfo(callbacks=callbacks)
    stmt, _, _ = A.single_case("walk", _walk_rec({"min": 2, "max": 6}), 64, api)
    assert stmt is not None
    null_stmt, _, _ = A.single_case("walk", _walk_rec({"min": 2, "max": 6}), 64, A.ApiInfo())
    assert null_stmt is not None
    unterminated = stmt.replace("c0a0[sizeof(c0a0) - 1] = 0;", "")
    for name, body, stubs in (
        ("good", stmt, A.stubs_used([stmt], api.stubs)),
        ("null", null_stmt, []),
        ("unterm", unterminated, A.stubs_used([stmt], api.stubs)),
    ):
        (tmp_path / f"drv_{name}.c").write_text(
            "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n"
            '#include "walk.h"\n'
            "#define FRAMAC_FUZZ_COPY(b, o) ((b) + (o))\n"
            + "\n".join(stubs)
            + "\nstatic void run_case(const uint8_t *fuzz_buf, size_t fuzz_len) { "
            + body
            + " }\nint main(void) { uint8_t in[64]; memset(in, 0xff, sizeof(in)); run_case(in, sizeof(in));"
            ' puts("returned"); return 0; }\n',
            encoding="utf-8",
        )
    script = " ; ".join(
        f"clang -g -O0 -Wall -Werror -fsanitize=address -I/fixture /fixture/drv_{n}.c /fixture/walk.c -o /tmp/{n}"
        f" && (timeout 30 /tmp/{n} >/dev/null 2>&1; echo {n}=$?)"
        for n in ("good", "null", "unterm")
    )
    if clang:
        run_env = os.environ.copy()
        if os.name == "nt":
            # Windows Clang ASan binaries link dynamically against clang_rt.asan_dynamic-*.dll.
            rt_dirs = [str(Path(clang).resolve().parent)]
            for flag in ("-print-runtime-dir", "-print-resource-dir"):
                probe = subprocess.run([clang, flag], capture_output=True, text=True, check=False)
                if probe.returncode == 0 and probe.stdout.strip():
                    base = Path(probe.stdout.strip())
                    rt_dirs.append(str(base))
                    win_lib = base / "lib" / "windows"
                    if win_lib.is_dir():
                        rt_dirs.append(str(win_lib))
            run_env["PATH"] = os.pathsep.join(rt_dirs) + os.pathsep + run_env.get("PATH", "")
        out = []
        for n in ("good", "null", "unterm"):
            exe = tmp_path / f"{n}.exe"
            cc = subprocess.run(
                [clang, "-g", "-O0", "-Wall", "-Werror", "-fsanitize=address", f"-I{tmp_path}",
                 str(tmp_path / f"drv_{n}.c"), str(tmp_path / "walk.c"), "-o", str(exe)],
                capture_output=True, text=True, check=False,
            )  # fmt: skip
            assert cc.returncode == 0, cc.stderr
            out.append(f"{n}={subprocess.run([str(exe)], env=run_env, capture_output=True, check=False).returncode}")
        stdout = "\n".join(out)
    else:
        proc = _docker(tmp_path, script)
        stdout = proc.stdout
        assert "good=" in stdout, proc.stdout[-2000:] + proc.stderr[-2000:]
    results = dict(line.split("=") for line in stdout.split() if "=" in line)
    assert results["good"] == "0", stdout
    assert results["null"] != "0" and results["unterm"] != "0", stdout
