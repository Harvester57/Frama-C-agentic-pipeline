"""Link repair of globals on sudo (run-1, 2026-11-21): the generated link_globals.c must not define a
global that a file the same repair links also defines, and must not include a project header that
does not parse without the includes its own includers bring first (config.h, sys/queue.h).

- liblogsrv_a: log_server.pb-c.c needs protobuf_c_message_* and protobuf_c_empty_string, all of
  protobuf-c.c, in one round. The functions added protobuf-c.c, and the global was stubbed anyway:
  Frama-C refused `global var protobuf_c_empty_string ... has different initializer`.
- cvtsudoers: client_closure stubbed in the round that added log_client.c, through a bare
  `#include "log_client.h"`, which needs sys/queue.h first (`TAILQ_ENTRY` syntax error).
- libparsesudoers_a: sudo_printf stubbed through a bare `#include "sudoers.h"`, which needs config.h
  first (`unknown type name 'sudo_dso_public'`).
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

import fuzz_build as FB

LRS_PARSE_UNIT = "parse/.libs/libparse.a"
LRS_PLUGIN_UNIT = "plugin/.libs/plugin.so"
LRS_PROTO_UNIT = "proto/.libs/libproto.a"
LRS_LOG_UNIT = "logsrv/.libs/liblog.a"
LRS_CPPFLAGS = "-Iworkspace/work/include -Iworkspace/work"

LRS_FILES = {
    # config.h defines what the project headers use (sudo's sudo_dso_public).
    "config.h": '#define plug_public __attribute__((visibility("default")))\n#define HAVE_PLUG 1\n',
    "include/plug.h": (
        "#ifndef PLUG_H\n#define PLUG_H\n"
        "typedef int (*printf_t)(int msg_type, const char *fmt, ...);\n"
        "plug_public int plug_init(void);\n"
        "extern printf_t plug_printf;\n"
        "#endif\n"
    ),
    "include/plug_queue.h": ("#define TAILQ_ENTRY(type) struct { struct type *tqe_next; struct type **tqe_prev; }\n"),
    # Parses only after plug_queue.h, as sudo's log_client.h after sudo_queue.h.
    "plugin/client.h": (
        "struct conn_buf {\n    TAILQ_ENTRY(conn_buf) entries;\n    char *data;\n};\n"
        "extern struct client *client_ptr;\nint client_send(void);\n"
    ),
    "proto/proto.h": "extern const char proto_empty[];\nint proto_pack(void);\n",
    "parse/alias.c": (
        "/* The library's own file: see the #include notes in plug.h. */\n"
        "#include <config.h>\n\n#include <stdio.h>\n"
        "#ifdef HAVE_PLUG\n# include <plug.h>\n#endif\n"
        "#define ALIAS_MAX \\\n    16\n"
        "int alias_add(void)\n{\n#ifdef HAVE_PLUG\n    return plug_printf != 0;\n#endif\n}\n"
    ),
    "parse/user.c": (
        '#include <plug_queue.h>\n#include "../plugin/client.h"\nint alias_client(void) { return client_ptr != 0; }\n'
    ),
    "plugin/policy.c": (
        "#include <config.h>\n#include <plug.h>\nprintf_t plug_printf;\nint policy_check(void) { return 0; }\n"
    ),
    "plugin/client.c": (
        '#include <plug_queue.h>\n#include "client.h"\nstruct client *client_ptr;\n'
        "int client_send(void) { return 0; }\n"
    ),
    "proto/proto.c": (
        '#include "proto.h"\nconst char proto_empty[] = "";\nint proto_pack(void) { return proto_empty[0]; }\n'
    ),
    "logsrv/msg.c": '#include "../proto/proto.h"\nint msg_pack(void) { return proto_pack() + proto_empty[0]; }\n',
}


def _unit(module: str, unit: str, files: list[str], fns: list[str]) -> dict:
    return {"module": module, "unit": unit, "files": files, "required_sources": files, "functions": fns}


def _lrs_run(tmp_path: Path) -> Path:
    """Four link units shaped like sudo's; returns the DAG path."""
    work = tmp_path / "workspace" / "work"
    for rel, text in LRS_FILES.items():
        (work / rel).parent.mkdir(parents=True, exist_ok=True)
        (work / rel).write_text(text, encoding="utf-8", newline="\n")
    reports = tmp_path / "workspace" / "reports"
    reports.mkdir(parents=True)
    functions = {
        "alias_add": {"name": "alias_add", "file": "parse/alias.c", "module": "libparse_a"},
        "alias_client": {"name": "alias_client", "file": "parse/user.c", "module": "libparse_a"},
        "policy_check": {"name": "policy_check", "file": "plugin/policy.c", "module": "plugin_so"},
        "client_send": {"name": "client_send", "file": "plugin/client.c", "module": "plugin_so"},
        "proto_pack": {"name": "proto_pack", "file": "proto/proto.c", "module": "libproto_a"},
        "msg_pack": {"name": "msg_pack", "file": "logsrv/msg.c", "module": "liblog_a"},
    }
    dag = {
        "functions": functions,
        "module_kind": "link_unit",
        "modules": {
            "libparse_a": _unit("libparse_a", LRS_PARSE_UNIT, ["parse/alias.c", "parse/user.c"], ["alias_add"]),
            "plugin_so": _unit(
                "plugin_so", LRS_PLUGIN_UNIT, ["plugin/policy.c", "plugin/client.c"], ["policy_check", "client_send"]
            ),
            "libproto_a": _unit("libproto_a", LRS_PROTO_UNIT, ["proto/proto.c"], ["proto_pack"]),
            # A static archive links nothing: its unit does not list protobuf-c.c.
            "liblog_a": _unit("liblog_a", LRS_LOG_UNIT, ["logsrv/msg.c"], ["msg_pack"]),
        },
    }
    (reports / "callgraph_dag.json").write_text(json.dumps(dag), encoding="utf-8")
    records = [
        # Frama-C's printing of the model: `1UL`, the variadic translation, no qualifiers.
        {"name": "proto_empty", "file": "proto/proto.c", "type": "char [1UL]", "units": [LRS_PROTO_UNIT]},
        {
            "name": "plug_printf",
            "file": "plugin/policy.c",
            "type": "int (*)(int msg_type, char *fmt, void **__va_params)",
            "units": [LRS_PLUGIN_UNIT],
        },
        {"name": "client_ptr", "file": "plugin/client.c", "type": "struct client *", "units": [LRS_PLUGIN_UNIT]},
    ]
    model = {"global_variables": {f"{r['file']}#{r['name']}": {**r, "static": False} for r in records}}
    (reports / "phase0_model.json").write_text(json.dumps(model), encoding="utf-8")
    return reports / "callgraph_dag.json"


def _undef(*syms: str) -> str:
    return "".join(f"/usr/bin/ld: x.o: undefined reference to `{s}'\n" for s in syms)


def _stub_dir(module: str) -> Path:
    return Path(f"workspace/harnesses/fuzz_{module}_link_globals")


def test_a_global_whose_file_the_same_round_adds_is_not_stubbed(tmp_path: Path, monkeypatch) -> None:
    """liblogsrv_a: the function adds proto.c, which defines the global too."""
    dag = _lrs_run(tmp_path)
    monkeypatch.chdir(tmp_path)
    sources = ["workspace/work/logsrv/msg.c"]
    stub_dir = _stub_dir("liblog_a")
    # The global first, as the linker printed it on sudo: its placement must not depend on the order.
    for log in (_undef("proto_empty", "proto_pack"), _undef("proto_pack", "proto_empty")):
        repaired, info = FB.repair_sources_for_link(sources, log, dag, tmp_path, module="liblog_a", stub_dir=stub_dir)
        assert repaired == [*sources, "workspace/work/proto/proto.c"]
        assert "stubbed_globals" not in info
        assert info["added_sources"] == ["workspace/work/proto/proto.c"]
        assert sorted(info["symbols"]) == ["proto_empty", "proto_pack"]
        assert not (stub_dir / FB.LINK_GLOBALS_FILE).exists()


def test_a_global_still_undefined_beside_its_compiled_file_is_stubbed(tmp_path: Path, monkeypatch) -> None:
    """The build already compiles the defining file and the global is still undefined: the file does
    not define it under these flags (an #ifdef), so only a definition of its own can link it."""
    dag = _lrs_run(tmp_path)
    monkeypatch.chdir(tmp_path)
    sources = ["workspace/work/logsrv/msg.c", "workspace/work/proto/proto.c"]
    stub_dir = _stub_dir("liblog_a")
    _, info = FB.repair_sources_for_link(
        sources, _undef("proto_empty"), dag, tmp_path, module="liblog_a", stub_dir=stub_dir
    )
    assert [s["name"] for s in info["stubbed_globals"]] == ["proto_empty"]


def test_a_later_round_that_adds_the_defining_file_drops_the_stub(tmp_path: Path, monkeypatch) -> None:
    """Round 1 stubs proto_empty; round 2 adds proto.c for proto_pack: the stub must go, and with it
    link_globals.c, or Frama-C refuses the two definitions (`has different initializer`)."""
    dag = _lrs_run(tmp_path)
    monkeypatch.chdir(tmp_path)
    out_bin = Path("workspace/harnesses/fuzz_liblog_a")
    stub_file = (_stub_dir("liblog_a") / FB.LINK_GLOBALS_FILE).as_posix()
    calls: list[list[str]] = []

    def rebuild(srcs: list[str]) -> dict:
        calls.append(list(srcs))
        if stub_file in srcs and "workspace/work/proto/proto.c" in srcs:
            return {"returncode": 1, "stderr": "[kernel] User Error: global var proto_empty has different initializer"}
        if "workspace/work/proto/proto.c" not in srcs:
            return {"returncode": 1, "stderr": _undef("proto_pack")}
        return {"returncode": 0}

    first = {"returncode": 1, "stderr": _undef("proto_empty")}
    comp, current, record = FB.repair_link_rounds(
        first, ["workspace/work/logsrv/msg.c"], rebuild, dag, out_bin, link_module="liblog_a"
    )
    assert comp["returncode"] == 0, calls
    assert current == ["workspace/work/logsrv/msg.c", "workspace/work/proto/proto.c"]
    assert record is not None
    assert "stubbed_globals" not in record and "globals_file" not in record
    assert record["rounds"][1]["unstubbed_globals"] == ["proto_empty"]


def test_a_typedef_global_includes_its_header_after_an_includers_prefix(tmp_path: Path, monkeypatch) -> None:
    """libparsesudoers_a's sudo_printf (a sudo_printf_t): sudoers.h needs config.h first."""
    dag = _lrs_run(tmp_path)
    monkeypatch.chdir(tmp_path)
    stub_dir = _stub_dir("libparse_a")
    sources = ["workspace/work/parse/alias.c"]
    _, info = FB.repair_sources_for_link(
        sources, _undef("plug_printf"), dag, tmp_path, module="libparse_a", stub_dir=stub_dir
    )
    (stub,) = info["stubbed_globals"]
    assert stub["definition"] == "printf_t plug_printf;"
    assert stub["declared_in"] == "workspace/work/include/plug.h"
    assert stub["prelude_from"] == "workspace/work/parse/alias.c"
    text = (stub_dir / FB.LINK_GLOBALS_FILE).read_text(encoding="utf-8")
    lines = [ln for ln in text.splitlines() if ln.startswith("#")]
    assert lines == [
        "#include <config.h>",
        "#include <stdio.h>",
        "#ifdef HAVE_PLUG",
        '# include "../../work/include/plug.h"',
        "#endif",
    ]
    assert text.index("#endif") < text.index("printf_t plug_printf;")
    assert "alias_add" not in text and "ALIAS_MAX" not in text


def test_a_pointer_global_is_defined_without_its_header(tmp_path: Path, monkeypatch) -> None:
    """cvtsudoers' client_closure: log_client.h does not parse alone, and a pointer to a struct
    needs no definition of the struct."""
    dag = _lrs_run(tmp_path)
    monkeypatch.chdir(tmp_path)
    stub_dir = _stub_dir("libparse_a")
    _, info = FB.repair_sources_for_link(
        ["workspace/work/parse/user.c"], _undef("client_ptr"), dag, tmp_path, module="libparse_a", stub_dir=stub_dir
    )
    (stub,) = info["stubbed_globals"]
    assert stub["definition"] == "struct client *client_ptr;"
    assert "include" not in stub
    text = (stub_dir / FB.LINK_GLOBALS_FILE).read_text(encoding="utf-8")
    assert "#include" not in text
    assert "struct client;\n" in text and "struct client *client_ptr;\n" in text


LRS_DOCKER_SCRIPT = f"""set -e
cd /fixture
clang -fsyntax-only -Wall -Werror=implicit-int {LRS_CPPFLAGS} workspace/harnesses/fuzz_libparse_a_link_globals/link_globals.c
frama-c -cpp-extra-args="{LRS_CPPFLAGS}" workspace/work/parse/alias.c workspace/work/parse/user.c \\
  workspace/harnesses/fuzz_libparse_a_link_globals/link_globals.c -print -ocode /tmp/linked.c > /tmp/fc.log 2>&1 \\
  || {{ tail -30 /tmp/fc.log; exit 1; }}
grep -q "plug_printf" /tmp/linked.c
echo LINK_GLOBALS_OK
"""


@pytest.mark.integration
def test_generated_definitions_compile_with_clang_and_link_in_frama_c(tmp_path: Path, monkeypatch) -> None:
    """The definitions beside the real declarations: clang compiles link_globals.c with the module's
    flags, and Frama-C links it with the files that declare both globals."""
    from conftest import ANALYSIS_IMAGE, require_docker_images

    require_docker_images(ANALYSIS_IMAGE)
    dag = _lrs_run(tmp_path)
    monkeypatch.chdir(tmp_path)
    stub_dir = _stub_dir("libparse_a")
    sources = ["workspace/work/parse/alias.c", "workspace/work/parse/user.c"]
    stubbed: list[dict] = []
    for sym in ("plug_printf", "client_ptr"):
        _, info = FB.repair_sources_for_link(
            sources, _undef(sym), dag, tmp_path, module="libparse_a", stub_dir=stub_dir, stubbed=stubbed
        )
        stubbed += info["stubbed_globals"]
    tag = os.environ.get("FRAMAC_RUN_TAG", "pytest-link-repair-sudo")
    argv = [
        "docker", "run", "--rm", "--network", "none", "--label", f"framac.run={tag}",
        "-v", f"{tmp_path}:/fixture:ro", ANALYSIS_IMAGE, LRS_DOCKER_SCRIPT,
    ]  # fmt: skip
    proc = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600)
    assert "LINK_GLOBALS_OK" in proc.stdout, (proc.stdout + proc.stderr)[-4000:]
