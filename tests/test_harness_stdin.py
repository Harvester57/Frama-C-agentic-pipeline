"""
The `stdin` harness entry style (O10 of docs/plans/open-topics-remediation-plan.md): a command-line
program that reads its input from stdin is driven through its `main`. The fuzz side makes each input
the whole of fd 0 (read(0, ...) and stdio alike, also on later inputs of one process); the Eva side
calls main against Frama-C's libc model of stdin; the reach gate treats it like `argv`.

The compiled tests use the host C compiler on a POSIX host, else the analysis image under
FRAMAC_DOCKER_TESTS=1. The E-ACSL build and the Eva parse need the analysis image.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

import generate_harness
import harness_reach
from generate_harness import _build_invocations, generate_module_harness

REPO_ROOT = Path(__file__).resolve().parents[1]

# A program reading lines with fgets until EOF or a STOP line (which leaves the rest of its input in
# stdio's buffer). `parse_line` is the parser the input has to reach.
STDIN_FGETS_C = """\
#include <stdio.h>
#include <string.h>
#if defined(__FRAMAC__) && !defined(__FRAMAC_EACSL__)
#include "__fc_builtin.h"
#endif

static void parse_line(const char *line) {
#if defined(__FRAMAC__) && !defined(__FRAMAC_EACSL__)
    Frama_C_show_each_parse_line_reached(line);
#endif
    printf("PARSE:%s", line);
}

int main(void) {
    char line[64];
    while (fgets(line, sizeof line, stdin) != NULL) {
        if (strcmp(line, "STOP\\n") == 0) {
            break;
        }
        parse_line(line);
    }
    fflush(stdout);
    return 0;
}
"""

# A program reading fd 0 with read(2) until end of file.
STDIN_READ_C = """\
#include <stdio.h>
#include <unistd.h>
#if defined(__FRAMAC__) && !defined(__FRAMAC_EACSL__)
#include "__fc_builtin.h"
#endif

/* `buf` holds n bytes and a NUL (E-ACSL's printf check takes no `%.*s`: its `*` shifts the arguments). */
static void parse_record(const char *buf, size_t n) {
#if defined(__FRAMAC__) && !defined(__FRAMAC_EACSL__)
    Frama_C_show_each_parse_record_reached(n);
#endif
    printf("RECORD:%s\\n", buf);
}

int main(int argc, char **argv) {
    char buf[129];
    size_t total = 0;
    ssize_t n;
    (void)argv;
    if (argc != 1) {
        return 2;
    }
    while (total < sizeof buf - 1 && (n = read(0, buf + total, sizeof buf - 1 - total)) > 0) {
        total += (size_t)n;
    }
    buf[total] = 0;
    parse_record(buf, total);
    fflush(stdout);
    return 0;
}
"""

# Inputs fed one after another to one process, and the parser lines they must print. The first fgets
# input leaves "stale" buffered behind its STOP line and the second reaches end of file: neither may
# show in a later input.
STDIN_PROGRAMS: dict[str, tuple[str, list[str], list[str]]] = {
    "fgets_tool": (
        STDIN_FGETS_C,
        ["alpha\nSTOP\nstale\n", "beta\n", "gamma\n"],
        ["PARSE:alpha", "PARSE:beta", "PARSE:gamma"],
    ),
    "read_tool": (
        STDIN_READ_C,
        ["one", "two-longer", "x"],
        ["RECORD:one", "RECORD:two-longer", "RECORD:x"],
    ),
}


def _stdin_harness(run: Path, module: str, source: str) -> dict[str, Any]:
    work = run / "workspace" / "work"
    work.mkdir(parents=True, exist_ok=True)
    (work / f"{module}.c").write_text(source, encoding="utf-8")
    return generate_module_harness(
        module_name=module,
        sources=[f"workspace/work/{module}.c"],
        header_include="none",
        entry_fn="main",
        max_input_size=256,
        cppflags="-Iworkspace/work",
        out_dir=run / "workspace" / "harnesses",
        entry_style="stdin",
        auto_prelude=False,
    )


def _c_driver(inputs: list[str]) -> str:
    """A main that feeds `inputs` to LLVMFuzzerTestOneInput in one process, as libFuzzer does."""
    # JSON string literals of ASCII text are valid C string literals.
    items = ", ".join(json.dumps(s) for s in inputs)
    return (
        "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n"
        "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);\n"
        f"static const char *const inputs[] = {{{items}}};\n"
        "int main(void) {\n"
        "    for (size_t i = 0; i < sizeof inputs / sizeof inputs[0]; i++) {\n"
        "        int rc = LLVMFuzzerTestOneInput((const uint8_t *)inputs[i], strlen(inputs[i]));\n"
        '        printf("RC:%d\\n", rc);\n'
        "        fflush(stdout);\n"
        "    }\n"
        "    return 0;\n"
        "}\n"
    )


def _docker(mount: Path, script: str, timeout: int) -> subprocess.CompletedProcess[str]:
    from conftest import ANALYSIS_IMAGE

    argv = [
        "docker", "run", "--rm", "--network", "none", "--memory", "4g",
        "-v", f"{mount}:/fixture:ro",
        "-v", f"{REPO_ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
        "-v", f"{REPO_ROOT / 'templates'}:/opt/framac-pipeline/templates:ro",
        ANALYSIS_IMAGE, script,
    ]  # fmt: skip
    return subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)


def _host_cc() -> str | None:
    # pipe(), dup2() and fcntl() are POSIX: a Windows host compiler cannot build the fuzz side.
    if os.name == "nt":
        return None
    return shutil.which("clang") or shutil.which("gcc")


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_stdin_is_an_entry_style_of_the_generator_and_the_sidecar_schema():
    assert "stdin" in generate_harness.VALID_ENTRY_STYLES
    assert "stdin" in generate_harness.MAIN_ENTRY_STYLES
    schema = json.loads((REPO_ROOT / "schemas" / "harness_sidecar.schema.json").read_text(encoding="utf-8"))
    assert "stdin" in schema["properties"]["entry_style"]["enum"]


@pytest.mark.unit
@pytest.mark.parametrize(
    ("arity", "call"),
    [(0, "main();"), (2, "main(1, argv);"), (None, "main(1, argv);"), (3, "main(1, argv, envp);")],
)
def test_stdin_invocations_call_main_by_its_arity(arity, call):
    eva_call, fuzz_call = _build_invocations("main", "stdin", main_arity=arity)
    # Eva: main reads Frama-C's libc model of stdin; the harness's own input is unused.
    assert eva_call.startswith("(void)input_buf; (void)input_len;")
    assert call in eva_call and "framac_stdin_feed" not in eva_call
    # Fuzz: the input becomes stdin first; one that cannot be fed is rejected, main is not called.
    assert fuzz_call.startswith("if (framac_stdin_feed(bounded_buf, size) != 0) {")
    assert fuzz_call.index("FRAMAC_FUZZ_REJECT();") < fuzz_call.index(call)
    assert ("argv" in fuzz_call) is (arity != 0)


@pytest.mark.unit
def test_stdin_harness_for_a_main_without_parameters(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    res = _stdin_harness(tmp_path, "fgets_tool", STDIN_FGETS_C)
    assert res["entry_style"] == "stdin"
    assert "-Dmain=__framac_target_main" in res["cppflags"]
    assert res["null_terminate"] is False
    sidecar = json.loads((tmp_path / "workspace/harnesses/harness_fgets_tool.json").read_text(encoding="utf-8"))
    assert sidecar["entry_style"] == "stdin" and "warnings" not in sidecar
    text = (tmp_path / "workspace/harnesses/harness_fgets_tool.c").read_text(encoding="utf-8")
    # main's declaration from the target's definition, then the fuzz-side feed helper, then the calls.
    decl_at = text.index("int main(void);")
    feed_at = text.index("static int framac_stdin_feed(")
    assert decl_at < feed_at < text.index("int eva_main(void)")
    assert generate_harness.STDIN_FEED_PRELUDE in text
    assert text.count("main();") == 2


@pytest.mark.unit
def test_stdin_harness_for_main_argc_argv(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _stdin_harness(tmp_path, "read_tool", STDIN_READ_C)
    text = (tmp_path / "workspace/harnesses/harness_read_tool.c").read_text(encoding="utf-8")
    assert "int main(int argc, char **argv);" in text
    assert text.count("main(1, argv);") == 2


@pytest.mark.unit
def test_other_entry_styles_leave_the_stdin_helper_off(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    work = tmp_path / "workspace" / "work"
    work.mkdir(parents=True)
    (work / "read_tool.c").write_text(STDIN_READ_C, encoding="utf-8")
    generate_module_harness(
        module_name="read_tool",
        sources=["workspace/work/read_tool.c"],
        header_include="none",
        entry_fn="main",
        max_input_size=256,
        cppflags="-Iworkspace/work",
        out_dir=tmp_path / "workspace" / "harnesses",
        entry_style="argv",
        auto_prelude=False,
    )
    text = (tmp_path / "workspace/harnesses/harness_read_tool.c").read_text(encoding="utf-8")
    assert "framac_stdin_feed" not in text and "#include <unistd.h>" not in text


@pytest.mark.unit
def test_argv_refusal_of_main_void_points_to_the_stdin_style(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    work = tmp_path / "workspace" / "work"
    work.mkdir(parents=True)
    (work / "fgets_tool.c").write_text(STDIN_FGETS_C, encoding="utf-8")
    with pytest.raises(ValueError, match="--entry-style stdin") as exc:
        generate_module_harness(
            module_name="fgets_tool",
            sources=["workspace/work/fgets_tool.c"],
            header_include="none",
            entry_fn="main",
            max_input_size=256,
            cppflags="-Iworkspace/work",
            out_dir=tmp_path / "workspace" / "harnesses",
            entry_style="argv",
            auto_prelude=False,
        )
    assert "no stdin entry style yet" not in str(exc.value)


@pytest.mark.unit
def test_cli_accepts_the_stdin_entry_style(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    work = tmp_path / "workspace" / "work"
    work.mkdir(parents=True)
    (work / "fgets_tool.c").write_text(STDIN_FGETS_C, encoding="utf-8")
    rc = generate_harness.main(
        [
            "--module", "fgets_tool", "--sources", "workspace/work/fgets_tool.c", "--header", "none",
            "--entry-fn", "main", "--entry-style", "stdin", "--cppflags", "-Iworkspace/work",
            "--out-dir", "workspace/harnesses", "--no-auto-prelude",
        ]
    )  # fmt: skip
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["entry_style"] == "stdin"


# ---------------------------------------------------------------------------
# Reach gate
# ---------------------------------------------------------------------------


def _stdin_dag() -> dict[str, Any]:
    def fn(name: str, callees: list[str] | None = None) -> dict[str, Any]:
        return {"name": name, "module": "tool", "file": "tool.c", "is_static": False, "internal_callees": callees or []}

    functions = {
        "main": fn("main", ["read_input", "emit"]),
        "read_input": fn("read_input", ["parse_token"]),
        "parse_token": fn("parse_token"),
        "emit": fn("emit"),
        "unused_helper": fn("unused_helper"),
    }
    entries = ["emit", "parse_token", "read_input", "unused_helper"]
    module = {"module": "tool", "tier": "Tier 1A", "functions": list(functions), "candidate_entry_points": entries}
    return {"modules": {"tool": module}, "functions": functions}


@pytest.mark.unit
def test_reach_gate_treats_a_stdin_harness_like_argv():
    dag_doc = _stdin_dag()
    text = "int main(void);\nvoid drive(void) { main(); }\n"
    rows = {
        style: harness_reach.check_module("tool", dag_doc, {"entry_style": style}, text, [])
        for style in ("argv", "stdin", "custom")
    }
    for key in ("roots", "entry_points_reached", "gaps", "reached_only_through", "passed"):
        assert rows["stdin"][key] == rows["argv"][key], key
    assert rows["stdin"]["roots"] == ["main"] and rows["stdin"]["gaps"] == ["unused_helper"]
    # A non-program style holds the same harness to direct calls.
    assert rows["custom"]["entry_points_reached"] == 0


# ---------------------------------------------------------------------------
# Compiled: the fuzz side reaches the parser on every input of one process
# ---------------------------------------------------------------------------


def _write_programs(run: Path) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for module, (source, inputs, expected) in STDIN_PROGRAMS.items():
        res = _stdin_harness(run, module, source)
        (run / f"driver_{module}.c").write_text(_c_driver(inputs), encoding="utf-8")
        out[module] = {"cppflags": res["cppflags"], "inputs": inputs, "expected": expected}
    return out


def _parser_lines(stdout: str, module: str) -> list[str]:
    marker = "PARSE:" if module == "fgets_tool" else "RECORD:"
    return [ln.rstrip("\r") for ln in stdout.splitlines() if ln.startswith((marker, "RC:"))]


def _expected_lines(expected: list[str]) -> list[str]:
    lines: list[str] = []
    for exp in expected:
        lines += [exp, "RC:0"]
    return lines


@pytest.mark.integration
def test_stdin_fuzz_side_reaches_the_parser_on_consecutive_inputs(tmp_path, monkeypatch):
    """fgets and read(0) programs, three inputs in one process: each input is the parser's whole stdin."""
    monkeypatch.chdir(tmp_path)
    programs = _write_programs(tmp_path)
    cc = _host_cc()
    outputs: dict[str, str] = {}
    if cc:
        for module, prog in programs.items():
            flags = prog["cppflags"].split()
            harness = f"workspace/harnesses/harness_{module}.c"
            exe = tmp_path / f"drv_{module}"
            for cmd in (
                # The feed helper's declarations are there under a strict standard too, as many targets
                # compile (-Wall alone warns there about the template's unused skip-case helper).
                [cc, "-std=c99", "-Werror=implicit-function-declaration", *flags, "-fsyntax-only", harness],
                # -Wno-unused-function: the template's skip-case helper is unused outside dispatch harnesses.
                [cc, "-Wall", "-Werror", "-Wno-unused-function", *flags, "-c", harness, "-o", f"h_{module}.o"],
                [cc, *flags, "-c", f"workspace/work/{module}.c", "-o", f"t_{module}.o"],
                # The driver is not renamed: its main is the process's.
                [cc, f"driver_{module}.c", f"h_{module}.o", f"t_{module}.o", "-o", str(exe)],
            ):
                proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
                assert proc.returncode == 0, proc.stderr
            outputs[module] = subprocess.run(
                [str(exe)], capture_output=True, text=True, check=True, timeout=60, stdin=subprocess.DEVNULL
            ).stdout
    else:
        from conftest import ANALYSIS_IMAGE, require_docker_images

        require_docker_images(ANALYSIS_IMAGE)  # skips without FRAMAC_DOCKER_TESTS=1
        steps = ["cp -r /fixture /tmp/w && cd /tmp/w"]
        for module, prog in programs.items():
            flags = prog["cppflags"]
            steps += [
                f"clang -Wall -Werror -Wno-unused-function {flags} -c workspace/harnesses/harness_{module}.c"
                f" -o h_{module}.o",
                f"clang -std=c99 -Werror=implicit-function-declaration {flags} -fsyntax-only "
                f"workspace/harnesses/harness_{module}.c",
                f"clang {flags} -c workspace/work/{module}.c -o t_{module}.o",
                f"clang driver_{module}.c h_{module}.o t_{module}.o -o drv_{module}",
                f"echo BEGIN:{module}",
                f"timeout 60 ./drv_{module} </dev/null",
            ]
        proc = _docker(tmp_path, " && ".join(steps), timeout=300)
        assert proc.returncode == 0, proc.stdout[-3000:] + proc.stderr[-3000:]
        chunks = proc.stdout.split("BEGIN:")
        outputs = {chunk.split("\n", 1)[0].strip(): chunk.split("\n", 1)[1] for chunk in chunks[1:]}
    for module, prog in programs.items():
        assert _parser_lines(outputs[module], module) == _expected_lines(prog["expected"]), outputs[module]
        assert "stale" not in outputs[module]


EACSL_BUILD_SCRIPT = r"""cp -r /fixture /tmp/w && cd /tmp/w
cat > build.py <<'EOF'
import json, sys
from pathlib import Path
sys.path.insert(0, "/opt/framac-pipeline/scripts")
import fuzz_build as FB
programs = json.loads(Path("programs.json").read_text())
for module, prog in programs.items():
    res = FB.compile_eacsl_binary(
        [f"workspace/harnesses/harness_{module}.c", f"workspace/work/{module}.c"],
        Path(f"/tmp/w/bin/{module}"),
        cppflags=prog["cppflags"],
        use_cache=False,
    )
    print("BUILD " + json.dumps({"module": module, "returncode": res["returncode"], "binary": res["binary"]}))
    if res["returncode"] != 0:
        print(Path(res["compile_log"]).read_text()[-4000:])
    else:
        Path(f"bin/{module}.path").write_text(res["binary"])
EOF
python3 build.py
for m in fgets_tool read_tool; do
  echo BEGIN:$m
  [ -f bin/$m.path ] && timeout 120 "$(cat bin/$m.path)" inputs_$m/in0 inputs_$m/in1 inputs_$m/in2 </dev/null 2>&1
  echo EXIT:$?
done
"""


@pytest.mark.integration
def test_stdin_harness_under_the_eacsl_fuzz_build(tmp_path, monkeypatch):
    """The pipeline's E-ACSL libFuzzer build of both programs, run on three input files in one process."""
    from conftest import ANALYSIS_IMAGE, require_docker_images

    require_docker_images(ANALYSIS_IMAGE)
    monkeypatch.chdir(tmp_path)
    programs = _write_programs(tmp_path)
    for module, prog in programs.items():
        idir = tmp_path / f"inputs_{module}"
        idir.mkdir()
        for i, data in enumerate(prog["inputs"]):
            (idir / f"in{i}").write_bytes(data.encode("ascii"))
    (tmp_path / "programs.json").write_text(json.dumps(programs), encoding="utf-8")
    proc = _docker(tmp_path, EACSL_BUILD_SCRIPT, timeout=1800)
    out = proc.stdout + proc.stderr
    builds = [json.loads(ln[len("BUILD ") :]) for ln in proc.stdout.splitlines() if ln.startswith("BUILD ")]
    assert [b["returncode"] for b in builds] == [0, 0], out[-6000:]
    chunks = proc.stdout.split("BEGIN:")
    outputs = {chunk.split("\n", 1)[0].strip(): chunk.split("\n", 1)[1] for chunk in chunks[1:]}
    for module, prog in programs.items():
        lines = [ln for ln in outputs[module].splitlines() if ln.startswith(("PARSE:", "RECORD:"))]
        assert lines == prog["expected"], outputs[module][-4000:]
        assert "stale" not in outputs[module]
        # No E-ACSL alarm: the harness's own feeding code is clean under the runtime checks.
        assert "Assertion failed" not in outputs[module] and "deadly signal" not in outputs[module], outputs[module]


EVA_SCRIPT = r"""cp -r /fixture /tmp/w && cd /tmp/w
for m in fgets_tool read_tool; do
  echo BEGIN:$m
  flags=$(python3 -c "import json,sys; print(json.load(open('programs.json'))[sys.argv[1]]['cppflags'])" $m)
  timeout 600 frama-c -machdep gcc_x86_64 -cpp-extra-args="$flags" \
    -kernel-warn-key annot-error=abort \
    workspace/harnesses/harness_$m.c workspace/work/$m.c \
    -eva -main eva_main -eva-no-show-progress 2>&1
  echo RC:$?
done
"""


@pytest.mark.integration
def test_stdin_eva_harness_parses_and_reaches_the_parser(tmp_path, monkeypatch):
    """Frama-C parses the Eva side, and Eva reaches each parser through the libc model of stdin."""
    from conftest import ANALYSIS_IMAGE, require_docker_images

    require_docker_images(ANALYSIS_IMAGE)
    monkeypatch.chdir(tmp_path)
    programs = _write_programs(tmp_path)
    (tmp_path / "programs.json").write_text(json.dumps(programs), encoding="utf-8")
    proc = _docker(tmp_path, EVA_SCRIPT, timeout=1500)
    chunks = proc.stdout.split("BEGIN:")
    outputs = {chunk.split("\n", 1)[0].strip(): chunk.split("\n", 1)[1] for chunk in chunks[1:]}
    assert set(outputs) == set(programs), proc.stdout[-3000:] + proc.stderr[-3000:]
    for module, marker in (("fgets_tool", "parse_line_reached"), ("read_tool", "parse_record_reached")):
        text = outputs[module]
        assert "RC:0" in text, text[-4000:]
        assert f"Frama_C_show_each_{marker}" in text, text[-4000:]
