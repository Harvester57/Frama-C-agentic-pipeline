"""
sudo run-1 seed recording: zero seeds, for two pipeline bugs in seed_harvest.py.

1. A model signature carrying `__attribute__((__visibility__("default")))` (sudo's `sudo_dso_public`)
   lost only its first `))` to the non-greedy attribute regex: the stray `)` left the return type
   `int )` and 166 of the 609 planned API functions were skipped.
2. Every relinked libtool `.libs/<prog>` exited 127 (`libsudo_util.so.0: cannot open shared object
   file`): the executables carry only the install rpath, and the run had no library path for the
   tree's own shared libraries.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

import security_props as sp
import seed_harvest as sh
from conftest import ANALYSIS_IMAGE, ROOT, require_docker_images

VISIBILITY = '__attribute__((__visibility__("default")))'

# Real signatures of the run-1 model (phase0_model.json `functions[...].signature`).
SUDO_SIGNATURES = {
    "sudo_base64_decode_v1": f"unsigned long {VISIBILITY}(char *,unsigned char *,unsigned long)",
    "sudo_arc4random": f"unsigned int {VISIBILITY}()",
    "sudo_arc4random_buf": f"void {VISIBILITY}(void *,unsigned long)",
    "main": f"int {VISIBILITY}(int,char **)",
}


# ---------------------------------------------------------------------------------------------------
# Bug 1: attributes in a model signature
# ---------------------------------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize(
    ("sig", "expected"),
    [
        (SUDO_SIGNATURES["sudo_base64_decode_v1"], ("unsigned long", ["char *", "unsigned char *", "unsigned long"])),
        (SUDO_SIGNATURES["sudo_arc4random"], ("unsigned int", [])),
        (SUDO_SIGNATURES["sudo_arc4random_buf"], ("void", ["void *", "unsigned long"])),
        (SUDO_SIGNATURES["main"], ("int", ["int", "char * *"])),  # _norm_type's spelling of `char **`
        # A pointer result: the attribute sits between the type and its `*`.
        (f"char {VISIBILITY} *(char *)", ("char *", ["char *"])),
        # Nested parentheses and a `)` inside a string argument.
        ('int __attribute__((__deprecated__("use g() (or h)")))(int)', ("int", ["int"])),
        ("int __attribute__((__aligned__((8) * 2)))(int)", ("int", ["int"])),
        # Several attributes in a row, with and without a space between them.
        (
            f"_Bool {VISIBILITY} __attribute__((__warn_unused_result__))__attribute__((__nonnull__(1, 2)))(char *,char *)",
            ("_Bool", ["char *", "char *"]),
        ),
        # An attribute on a parameter type.
        (
            "int(char * __attribute__((__nonnull__)),unsigned long __attribute__((__unused__)))",
            ("int", ["char *", "unsigned long"]),
        ),
    ],
)
def test_split_signature_drops_whole_attributes(sig: str, expected: tuple[str, list[str]]) -> None:
    parts = sh.split_signature(sig)
    assert parts is not None
    ret, params, variadic = parts
    assert not variadic
    assert sh._norm_type(ret) == expected[0]
    assert [sh._norm_type(p) for p in params] == expected[1]
    assert ")" not in ret and "__attribute__" not in ret


@pytest.mark.unit
@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f"unsigned long {VISIBILITY}", "unsigned long"),
        (f"char const {VISIBILITY} *", "char *"),
        ("struct s __attribute__((__aligned__((16))))__attribute__((__may_alias__)) *", "struct s *"),
        ('int __attribute__((__section__(".text)x")))', "int"),
    ],
)
def test_norm_type_drops_whole_attributes(text: str, expected: str) -> None:
    assert sh._norm_type(text) == expected


@pytest.mark.unit
def test_plan_function_accepts_sudo_dso_public_functions() -> None:
    plan = sh.plan_function(
        "sudo_base64_decode_v1", SUDO_SIGNATURES["sudo_base64_decode_v1"], names=["str", "dst", "dsize"]
    )
    assert plan["supported"], plan
    assert plan["ret"] == {"kind": "int", "ctype": "unsigned long"}
    assert [p.get("record") for p in plan["params"]] == ["s", "b", "i"]
    for name in ("sudo_arc4random", "sudo_arc4random_buf"):
        assert sh.plan_function(name, SUDO_SIGNATURES[name])["supported"], name


@pytest.mark.unit
def test_an_unbalanced_attribute_is_not_understood() -> None:
    plan = sh.plan_function("f", 'int __attribute__((__visibility__("default"))(int)')
    assert not plan["supported"]


@pytest.mark.unit
def test_security_props_reads_the_parameters_of_an_attributed_signature() -> None:
    """The same model signatures: `_split_params` started at the attribute's own `(`."""
    assert sp._split_params(SUDO_SIGNATURES["sudo_base64_decode_v1"]) == ["char *", "unsigned char *", "unsigned long"]
    assert sp._split_params(f"char {VISIBILITY} *(char *,int)") == ["char *", "int"]
    model = {
        "functions": {
            "lib/util/b64_decode.c#sudo_base64_decode_v1": {
                "name": "sudo_base64_decode_v1",
                "signature": SUDO_SIGNATURES["sudo_base64_decode_v1"],
                "formals": [
                    {"name": "str", "kind": "pointer"},
                    {"name": "dst", "kind": "pointer"},
                    {"name": "dsize", "kind": "scalar"},
                ],
            }
        }
    }
    m = sp._Model(model)
    assert m.param_types("lib/util/b64_decode.c#sudo_base64_decode_v1") == {
        "str": "char *",
        "dst": "unsigned char *",
        "dsize": "unsigned long",
    }
    assert m.arg_refs("sudo_base64_decode_v1") == {
        "str": "((char *)${arg0})",
        "dst": "((unsigned char *)${arg1})",
        "dsize": "${arg2}",
    }


@pytest.mark.unit
def test_security_props_pointer_result_behind_an_attribute_is_no_pointer_parameter() -> None:
    """A GCC-fallback function (no write facts): only a `*` in the parameter list counts."""
    gcc = {"source": "gcc-callgraph-info"}
    model = {
        "functions": {
            "a.c#sudo_getenv": {"name": "sudo_getenv", "signature": f"char {VISIBILITY} *(void)", **gcc},
            "a.c#sudo_setenv": {"name": "sudo_setenv", "signature": f"int {VISIBILITY}(char *,int)", **gcc},
        }
    }
    assert set(sp._Model(model).pointer_writers()) == {"a.c#sudo_setenv"}


# ---------------------------------------------------------------------------------------------------
# Bug 2: the relinked executables run with the tree's shared-library directories
# ---------------------------------------------------------------------------------------------------

SUDO_EXES = ("src/.libs/sudo", "plugins/sudoers/.libs/visudo")
SUDO_UTIL = "lib/util/.libs/libsudo_util.so.0.0.0"


def _sudo_record_fixture(tmp_path: Path, monkeypatch, recipe: dict, units: dict) -> tuple[Path, list[dict]]:
    """sudo's layout: libtool executables in `.libs/`, libsudo_util in lib/util/.libs. Running is stubbed."""
    monkeypatch.chdir(tmp_path)
    reports = tmp_path / "workspace" / "reports"
    reports.mkdir(parents=True)
    tree = tmp_path / "scratch" / "tree"
    for name, unit in units.items():
        (tree / name).parent.mkdir(parents=True, exist_ok=True)
        (tree / name).write_bytes(b"\x7fELF")
        if unit["kind"] == "shared_lib":
            # libtool's soname link beside the real file (a plain file here: no symlinks on Windows).
            (tree / name).with_name(Path(name).name.rsplit(".", 2)[0]).write_bytes(b"\x7fELF")
    (tmp_path / "run-metadata.json").write_text(json.dumps({"build": recipe}))
    model = {
        "status": "ok",
        "entry_points": ["lib/util/b64_decode.c#sudo_base64_decode_v1"],
        "functions": {
            "lib/util/b64_decode.c#sudo_base64_decode_v1": {
                "name": "sudo_base64_decode_v1",
                # Without the attribute: these tests hold the library path apart from bug 1.
                "signature": "unsigned long(char *,unsigned char *,unsigned long)",
            }
        },
        "units": {},
    }
    (reports / "phase0_model.json").write_text(json.dumps(model))
    capture = {"status": "ok", "scratch": {"tree": str(tree)}, "units": units, "compiles": []}
    (reports / "build_capture.json").write_text(json.dumps(capture))
    calls: list[dict] = []

    class Res:
        returncode = 0
        timed_out = False
        stdout = stderr = ""

    def sandboxed(argv, cwd, scratch, timeout, env):
        calls.append({"argv": [str(a) for a in argv], "env": dict(env)})
        return Res()

    exes = [n for n, u in units.items() if u["kind"] == "executable"]
    monkeypatch.setattr(sh, "link_commands", lambda ev, t: {n: {"args": ["cc", "-o", n], "cwd": str(t)} for n in exes})
    monkeypatch.setattr(sh, "defined_functions", lambda exe: set())
    monkeypatch.setattr(sh, "undefined_functions", lambda exe: {"sudo_base64_decode_v1"})
    monkeypatch.setattr(sh, "_run", lambda argv, cwd, timeout: (0, ""))
    monkeypatch.setattr(sh, "_compile_wrappers", lambda cc, fl, plans, where, c, o, w: (True, plans, ""))
    monkeypatch.setattr(sh, "_sandboxed", sandboxed)
    monkeypatch.setattr(sh.shutil, "which", lambda name: None)
    return tree, calls


def _sudo_units() -> dict:
    units: dict = {n: {"kind": "executable", "objects": []} for n in SUDO_EXES}
    units[SUDO_UTIL] = {"kind": "shared_lib", "objects": []}
    units["plugins/sudoers/.libs/libparsesudoers.a"] = {"kind": "static_lib", "objects": []}
    return units


@pytest.mark.unit
def test_executables_run_with_the_trees_shared_library_directories(tmp_path, monkeypatch):
    recipe = {"command": "make", "env": {"LD_LIBRARY_PATH": "/opt/user/lib", "FOO": "1"}}
    tree, calls = _sudo_record_fixture(tmp_path, monkeypatch, recipe, _sudo_units())
    assert sh.main(["record", "--scratch", str(tmp_path / "scratch")]) == 0
    report = json.loads((tmp_path / "workspace" / "reports" / "seed_harvest.json").read_text())
    assert {n: i["status"] for n, i in report["relink"].items()} == dict.fromkeys(SUDO_EXES, "relinked")
    runs = [c for c in calls if c["argv"][0] != "cc"]
    assert [r["argv"] for r in runs] == [[str(tree / n)] for n in sorted(SUDO_EXES)]
    lib_dir = str(tree / "lib" / "util" / ".libs")
    for r in runs:
        # The tree's libraries first, then the recipe's own path; the rest of the recipe env kept.
        assert r["env"]["LD_LIBRARY_PATH"] == f"{lib_dir}:/opt/user/lib"
        assert r["env"]["FOO"] == "1"
    assert report["library_path"] == [lib_dir]
    # The relink keeps the build's own environment: a library path there could shadow the toolchain's.
    relinks = [c for c in calls if c["argv"][0] == "cc"]
    assert relinks and all("LD_LIBRARY_PATH" not in c["env"] for c in relinks)


@pytest.mark.unit
def test_the_test_command_runs_with_the_trees_shared_library_directories(tmp_path, monkeypatch):
    recipe = {"command": "make", "test_command": "make check"}
    tree, calls = _sudo_record_fixture(tmp_path, monkeypatch, recipe, _sudo_units())
    assert sh.main(["record", "--scratch", str(tmp_path / "scratch")]) == 0
    assert calls[-1]["argv"] == ["sh", "-c", "make check"]
    # No recipe path: no empty element (which the loader reads as the current directory).
    assert calls[-1]["env"]["LD_LIBRARY_PATH"] == str(tree / "lib" / "util" / ".libs")


@pytest.mark.unit
def test_without_a_captured_shared_library_the_tree_is_scanned(tmp_path, monkeypatch):
    """A shared library the capture did not see link (built by a script): found in the tree."""
    units = {n: {"kind": "executable", "objects": []} for n in SUDO_EXES}
    tree, calls = _sudo_record_fixture(tmp_path, monkeypatch, {"command": "make"}, units)
    for rel in ("lib/x/.libs/libx.so.0", "lib/y/.libs/liby.so", "lib/z/.libs/libz.a", ".git/objects/libg.so"):
        (tree / rel).parent.mkdir(parents=True, exist_ok=True)
        (tree / rel).write_bytes(b"\x7fELF")
    assert sh.main(["record", "--scratch", str(tmp_path / "scratch")]) == 0
    runs = [c for c in calls if c["argv"][0] != "cc"]
    expected = ":".join(str(tree / d) for d in ("lib/x/.libs", "lib/y/.libs"))
    assert runs and all(r["env"]["LD_LIBRARY_PATH"] == expected for r in runs)


@pytest.mark.unit
def test_no_shared_library_leaves_the_recipe_env_alone(tmp_path, monkeypatch):
    units = {n: {"kind": "executable", "objects": []} for n in SUDO_EXES}
    _, calls = _sudo_record_fixture(tmp_path, monkeypatch, {"command": "make", "env": {"FOO": "1"}}, units)
    assert sh.main(["record", "--scratch", str(tmp_path / "scratch")]) == 0
    runs = [c for c in calls if c["argv"][0] != "cc"]
    assert runs and all(r["env"] == {"FOO": "1"} for r in runs)


# ---------------------------------------------------------------------------------------------------
# Docker: a libtool layout recorded end to end by `seed_harvest.py record` in the analysis image
# ---------------------------------------------------------------------------------------------------

LT_LIB_C = """\
int x_add(int a, int b) { return a + b; }
int x_mul(int a, int b) { return a * b; }
"""

LT_PROG_C = """\
int x_add(int a, int b);
int x_mul(int a, int b);
int main(void) { return x_add(2, 3) + x_mul(4, 5) == 25 ? 0 : 1; }
"""

# Builds the layout libtool leaves (lib/.libs/libx.so.0.0.0 with its soname links, src/.libs/prog with
# the install rpath only), writes the capture, the bear event of the link and a model whose x_mul
# signature carries sudo_dso_public's attribute, then runs `seed_harvest.py record` as the pipeline does.
LT_DRIVE_PY = """\
import json, os, shutil, subprocess, sys
sys.path.insert(0, "/opt/framac-pipeline/scripts")
W = "/tmp/w"
shutil.rmtree(W, ignore_errors=True)
shutil.copytree("/w", W)
os.chdir(W)
tree = W + "/scratch/tree"
os.makedirs(tree + "/lib/.libs")
os.makedirs(tree + "/src/.libs")
shutil.copy("lib.c", tree + "/lib/lib.c")
shutil.copy("prog.c", tree + "/src/prog.c")

def sh(argv, cwd):
    subprocess.run(argv, cwd=cwd, check=True, timeout=120)

sh(["gcc", "-c", "-fPIC", "-O1", "lib.c", "-o", ".libs/lib.o"], tree + "/lib")
sh(["gcc", "-shared", "-Wl,-soname,libx.so.0", ".libs/lib.o", "-o", ".libs/libx.so.0.0.0"], tree + "/lib")
os.symlink("libx.so.0.0.0", tree + "/lib/.libs/libx.so.0")
os.symlink("libx.so.0.0.0", tree + "/lib/.libs/libx.so")
sh(["gcc", "-c", "-O1", "prog.c", "-o", "prog.o"], tree + "/src")
link = ["gcc", "-O1", "-o", ".libs/prog", "prog.o", "../lib/.libs/libx.so", "-Wl,-rpath", "-Wl,/usr/local/lib"]
sh(link, tree + "/src")

os.makedirs("workspace/reports/build_capture")
event = {"started": {"execution": {"executable": "/usr/bin/gcc", "arguments": link, "working_dir": tree + "/src"}}}
with open("workspace/reports/build_capture/events.jsonl", "w") as fh:
    fh.write(json.dumps(event) + "\\n")
units = {
    "src/.libs/prog": {"kind": "executable", "objects": ["src/prog.o"]},
    "lib/.libs/libx.so.0.0.0": {"kind": "shared_lib", "objects": ["lib/.libs/lib.o"]},
}
capture = {"status": "ok", "scratch": {"tree": tree}, "units": units, "compiles": []}
json.dump(capture, open("workspace/reports/build_capture.json", "w"))
vis = '__attribute__((__visibility__("default")))'
model = {
    "status": "ok",
    "entry_points": ["lib/lib.c#x_add", "lib/lib.c#x_mul"],
    "functions": {
        "lib/lib.c#x_add": {"name": "x_add", "signature": "int(int,int)"},
        "lib/lib.c#x_mul": {"name": "x_mul", "signature": "int " + vis + "(int,int)"},
    },
    "units": {},
}
json.dump(model, open("workspace/reports/phase0_model.json", "w"))
json.dump({"build": {"command": "make"}}, open("run-metadata.json", "w"))

import seed_harvest
rc = seed_harvest.main(["record", "--scratch", W + "/scratch", "--timeout", "60"])
report = json.load(open("workspace/reports/seed_harvest.json"))
# The relinked program with the build's environment only: what every run-1 executable met.
from sandbox_exec import run_sandboxed
bare = run_sandboxed([tree + "/src/.libs/prog"], [W + "/scratch"], 30, extra_env={})
calls = open("workspace/seed_records/calls.jsonl").read().splitlines()
print("RESULT " + json.dumps({
    "rc": rc,
    "status": report["status"],
    "skipped": report["functions"]["skipped"],
    "relink": report["relink"],
    "runs": report.get("runs"),
    "library_path": report.get("library_path"),
    "by_function": report["calls"]["by_function"],
    "calls": calls,
    "bare_returncode": bare.returncode,
    "bare_stderr": bare.stderr[-300:],
}))
"""


@pytest.mark.integration
@pytest.mark.slow
def test_record_runs_a_libtool_executable_against_the_trees_shared_library_in_the_image(tmp_path):
    require_docker_images(ANALYSIS_IMAGE)
    for rel, text in {"lib.c": LT_LIB_C, "prog.c": LT_PROG_C, "drive.py": LT_DRIVE_PY}.items():
        (tmp_path / rel).write_text(text, encoding="utf-8", newline="\n")
    tag = os.environ.get("FRAMAC_RUN_TAG", "pytest-seed-harvest-sudo")
    proc = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "--label", f"framac.run={tag}",
         "-v", f"{tmp_path}:/w:ro", "-v", f"{ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
         "--entrypoint", "sh", ANALYSIS_IMAGE, "-c", "timeout 600 python3 /w/drive.py"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900, check=False,
    )  # fmt: skip
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    line = next((ln for ln in proc.stdout.splitlines() if ln.startswith("RESULT ")), None)
    assert line is not None, out
    res = json.loads(line[len("RESULT ") :])
    # Without the tree's library directory the loader cannot find libx.so.0: run-1's exit 127.
    assert res["bare_returncode"] == 127 and "libx.so.0" in res["bare_stderr"], res
    assert "x_mul" not in res["skipped"], res
    assert res["relink"]["src/.libs/prog"] == {"status": "relinked", "wrapped": ["x_add", "x_mul"]}, res
    assert res["runs"]["src/.libs/prog"]["returncode"] == 0, res
    assert res["library_path"] == ["/tmp/w/scratch/tree/lib/.libs"], res
    assert res["status"] == "ok" and res["by_function"] == {"x_add": 1, "x_mul": 1}, res
