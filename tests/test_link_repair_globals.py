"""Link repair for undefined global variables (scripts/run_eacsl_fuzz.py): a global of the
module's own link unit adds its defining file, one of another link unit is defined in the
generated link_globals.c, and one without a usable type stays unresolved."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import fuzz_build
import run_eacsl_fuzz as R

LIB_UNIT = "lib/libkv.a"
DAEMON_UNIT = "daemon/kvd"
LIB_FILES = ["lib/a.c", "lib/b.c", "lib/table.c"]
DAEMON_FILES = ["daemon/main.c", "daemon/state.c"]
STUB_DIR = Path("workspace/build/fuzz_libkv_a_link_globals")


def _global(file: str, name: str, type_text: str, unit: str, static: bool = False) -> dict:
    return {"name": name, "file": file, "static": static, "type": type_text, "units": [unit]}


def _run_dir(tmp_path: Path, link_units: bool = True) -> Path:
    """A run directory with a library unit and a daemon unit; returns the DAG path."""
    work = tmp_path / "workspace" / "work"
    for rel in [*LIB_FILES, *DAEMON_FILES]:
        (work / rel).parent.mkdir(parents=True, exist_ok=True)
        (work / rel).write_text("int x;\n", encoding="utf-8")
    (work / "daemon" / "state.h").write_text(
        "typedef struct { int fd; } Server_T;\nextern Server_T G_Server;\nvoid server_start(void);\n",
        encoding="utf-8",
    )
    reports = tmp_path / "workspace" / "reports"
    reports.mkdir(parents=True)
    functions = {
        "kv_get": {"name": "kv_get", "file": "lib/a.c", "module": "libkv_a"},
        "kv_put": {"name": "kv_put", "file": "lib/b.c", "module": "libkv_a"},
        "main": {"name": "main", "file": "daemon/main.c", "module": "kvd"},
        "server_start": {"name": "server_start", "file": "daemon/state.c", "module": "kvd"},
    }
    dag: dict = {"functions": functions}
    if link_units:
        dag.update(
            module_kind="link_unit",
            modules={
                "libkv_a": {
                    "module": "libkv_a",
                    "unit": LIB_UNIT,
                    "files": LIB_FILES,
                    "required_sources": LIB_FILES,
                    "functions": ["kv_get", "kv_put"],
                },
                "kvd": {
                    "module": "kvd",
                    "unit": DAEMON_UNIT,
                    "files": DAEMON_FILES,
                    "required_sources": [*DAEMON_FILES, *LIB_FILES],
                    "functions": ["main", "server_start"],
                },
            },
            submodules={"libkv_a__c1": {"unit": "libkv_a", "functions": ["kv_get"]}},
        )
    (reports / "callgraph_dag.json").write_text(json.dumps(dag), encoding="utf-8")
    records = [
        _global("lib/table.c", "kv_table", "unsigned int [256]", LIB_UNIT),
        _global("lib/a.c", "kv_private", "int", LIB_UNIT, static=True),
        _global("daemon/main.c", "G_Terminate", "int", DAEMON_UNIT),
        _global("daemon/state.c", "G_Conn", "struct conn *", DAEMON_UNIT),
        _global("daemon/state.c", "G_Server", "struct __anonstruct_Server_T_1", DAEMON_UNIT),
        _global("daemon/state.c", "G_Hidden", "struct hidden", DAEMON_UNIT),
        _global("daemon/state.c", "G_NoType", "", DAEMON_UNIT),
    ]
    model = {"global_variables": {f"{r['file']}#{r['name']}": r for r in records}}
    (reports / "phase0_model.json").write_text(json.dumps(model), encoding="utf-8")
    return reports / "callgraph_dag.json"


def _undefined(*syms: str) -> str:
    return "".join(f"/usr/bin/ld: x.o: undefined reference to `{s}'\n" for s in syms)


@pytest.mark.parametrize("module", ["libkv_a", "libkv_a__c1"])
def test_global_of_the_same_unit_adds_its_file(tmp_path: Path, monkeypatch, module: str) -> None:
    """nettle's _nettle_aes_encrypt_table: a table in a file that defines no function."""
    dag_path = _run_dir(tmp_path)
    monkeypatch.chdir(tmp_path)
    sources = ["workspace/work/lib/a.c"]
    repaired, info = R.repair_sources_for_link(
        sources, _undefined("kv_table"), dag_path, tmp_path, module=module, stub_dir=STUB_DIR
    )
    assert repaired == [*sources, "workspace/work/lib/table.c"]
    assert info == {"symbols": ["kv_table"], "added_sources": ["workspace/work/lib/table.c"]}
    assert not STUB_DIR.exists()


def test_global_of_a_linked_library_adds_its_file(tmp_path: Path) -> None:
    """The daemon links the library: the library's files are among its unit's sources."""
    dag_path = _run_dir(tmp_path)
    repaired, info = R.repair_sources_for_link(
        ["workspace/work/daemon/state.c"], _undefined("kv_table"), dag_path, tmp_path, module="kvd"
    )
    assert repaired[-1] == "workspace/work/lib/table.c" and info["symbols"] == ["kv_table"]


def test_global_of_another_unit_is_defined_in_the_generated_file(tmp_path: Path, monkeypatch) -> None:
    """ptf's G_TerminateProgram: defined next to a daemon's main, which must not be linked."""
    dag_path = _run_dir(tmp_path)
    monkeypatch.chdir(tmp_path)
    sources = ["workspace/work/lib/a.c"]
    repaired, info = R.repair_sources_for_link(
        sources, _undefined("G_Terminate", "G_Conn"), dag_path, tmp_path, module="libkv_a", stub_dir=STUB_DIR
    )
    stub_file = (STUB_DIR / R.LINK_GLOBALS_FILE).as_posix()
    assert repaired == [*sources, stub_file]
    assert info["symbols"] == ["G_Terminate", "G_Conn"] and info["added_sources"] == [stub_file]
    assert info["stubbed_globals"] == [
        {
            "name": "G_Terminate",
            "file": "daemon/main.c",
            "type": "int",
            "units": [DAEMON_UNIT],
            "assumption": "starts zero-initialized, as in a fresh process",
            "definition": "int G_Terminate;",
        },
        {
            "name": "G_Conn",
            "file": "daemon/state.c",
            "type": "struct conn *",
            "units": [DAEMON_UNIT],
            "assumption": "starts zero-initialized, as in a fresh process",
            "definition": "struct conn *G_Conn;",
        },
    ]
    lines = Path(stub_file).read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("/* Generated by run_eacsl_fuzz.py (link repair)")
    assert lines[3:] == [
        "struct conn;",
        "/* G_Terminate: defined in daemon/main.c (daemon/kvd) */",
        "int G_Terminate;",
        "/* G_Conn: defined in daemon/state.c (daemon/kvd) */",
        "struct conn *G_Conn;",
    ]
    assert b"\r" not in Path(stub_file).read_bytes()


def test_struct_held_by_value_takes_its_type_from_the_declaring_header(tmp_path: Path, monkeypatch) -> None:
    """ptf's G_ServerDGlad (a DestinationGlad_T): the model's type text alone cannot define it."""
    dag_path = _run_dir(tmp_path)
    monkeypatch.chdir(tmp_path)
    _, info = R.repair_sources_for_link(
        ["workspace/work/lib/a.c"], _undefined("G_Server"), dag_path, tmp_path, module="libkv_a", stub_dir=STUB_DIR
    )
    (stub,) = info["stubbed_globals"]
    # The header's own declaration without `extern`: its typedef name, not the model's unrolled type.
    assert stub["definition"] == "Server_T G_Server;"
    assert stub["declared_in"] == "workspace/work/daemon/state.h"
    assert stub["include"] == "../../work/daemon/state.h"
    text = (STUB_DIR / R.LINK_GLOBALS_FILE).read_text(encoding="utf-8")
    assert '#include "../../work/daemon/state.h"\n' in text
    assert "struct __anonstruct" not in text
    assert text.index("#include") < text.index("Server_T G_Server;")


def test_a_declaring_header_gives_the_definition_its_qualifiers(tmp_path: Path, monkeypatch) -> None:
    """
    The model's type text drops qualifiers. `int G_Terminate;` after a header declaring it
    `extern volatile int` is refused by clang and by Frama-C, and so is `__typeof__(G) G;` by
    Frama-C 35, which drops the `volatile` (checked in framac-analysis:latest, 2026-11-11).
    """
    dag_path = _run_dir(tmp_path)
    monkeypatch.chdir(tmp_path)
    flags = tmp_path / "workspace/work/daemon/flags.h"
    flags.write_text("extern volatile\n    int G_Terminate;\n", encoding="utf-8", newline="\n")
    _, info = R.repair_sources_for_link(
        ["workspace/work/lib/a.c"], _undefined("G_Terminate"), dag_path, tmp_path, module="libkv_a", stub_dir=STUB_DIR
    )
    (stub,) = info["stubbed_globals"]
    assert stub["definition"] == "volatile int G_Terminate;"
    assert stub["declared_in"] == "workspace/work/daemon/flags.h"

    # A declaration of several variables would define the others too: the type alone is taken.
    flags.write_text("extern int G_Other, G_Terminate;\n", encoding="utf-8", newline="\n")
    _, info = R.repair_sources_for_link(
        ["workspace/work/lib/a.c"], _undefined("G_Terminate"), dag_path, tmp_path, module="libkv_a", stub_dir=STUB_DIR
    )
    assert info["stubbed_globals"][0]["definition"] == "__typeof__(G_Terminate) G_Terminate;"


def test_global_without_a_usable_type_is_left_unresolved(tmp_path: Path, monkeypatch) -> None:
    dag_path = _run_dir(tmp_path)
    monkeypatch.chdir(tmp_path)
    sources = ["workspace/work/lib/a.c"]
    left: list[dict] = []
    repaired, info = R.repair_sources_for_link(
        sources,
        _undefined("G_NoType", "G_Hidden", "kv_private", "not_in_model"),
        dag_path,
        tmp_path,
        module="libkv_a",
        stub_dir=STUB_DIR,
        unresolved=left,
    )
    assert repaired == sources and info == {}  # a round that repairs nothing keeps the empty info
    by_name = {u["name"]: u for u in left}
    assert sorted(by_name) == ["G_Hidden", "G_NoType"]  # a static and an unknown symbol are no globals to place
    assert by_name["G_NoType"]["file"] == "daemon/state.c" and by_name["G_NoType"]["units"] == [DAEMON_UNIT]
    assert by_name["G_NoType"]["reason"] == (
        "the model records no type for it, and no header of the project declares it"
    )
    assert "held by value" in by_name["G_Hidden"]["reason"]
    assert not STUB_DIR.exists()


def test_unknown_unit_adds_the_file_unless_it_defines_main(tmp_path: Path, monkeypatch) -> None:
    """No module, a module the DAG does not place, or a DAG without link units: rule 1 only."""
    dag_path = _run_dir(tmp_path)
    monkeypatch.chdir(tmp_path)
    log = _undefined("G_Conn", "G_Terminate")
    for module in (None, "stranger"):
        left: list[dict] = []
        repaired, info = R.repair_sources_for_link(
            [], log, dag_path, tmp_path, module=module, stub_dir=STUB_DIR, unresolved=left
        )
        assert repaired == ["workspace/work/daemon/state.c"]
        assert info == {"symbols": ["G_Conn"], "added_sources": ["workspace/work/daemon/state.c"]}
        assert [u["name"] for u in left] == ["G_Terminate"] and "defines a main" in left[0]["reason"]
    old_dag = _run_dir(tmp_path / "old", link_units=False)
    repaired, info = R.repair_sources_for_link([], log, old_dag, tmp_path / "old", module="libkv_a", stub_dir=STUB_DIR)
    assert repaired == ["workspace/work/daemon/state.c"] and info["symbols"] == ["G_Conn"]
    assert not STUB_DIR.exists()


def test_functions_still_repair_as_before(tmp_path: Path, monkeypatch) -> None:
    """A function of another unit adds its file, with or without the model next to the DAG."""
    dag_path = _run_dir(tmp_path)
    monkeypatch.chdir(tmp_path)
    sources = ["workspace/work/lib/a.c"]
    log = _undefined("kv_put", "server_start")
    want = [*sources, "workspace/work/lib/b.c", "workspace/work/daemon/state.c"]
    repaired, info = R.repair_sources_for_link(sources, log, dag_path, tmp_path, module="libkv_a", stub_dir=STUB_DIR)
    assert repaired == want
    assert info == {"symbols": ["kv_put", "server_start"], "added_sources": want[1:]}
    (dag_path.parent / "phase0_model.json").unlink()
    assert R.repair_sources_for_link(sources, log, dag_path, tmp_path) == (want, info)
    assert R.repair_sources_for_link(sources, _undefined("kv_table"), dag_path, tmp_path) == (sources, {})


@pytest.mark.parametrize(
    ("type_text", "definition"),
    [
        ("int", "int g;"),
        ("unsigned char [16]", "unsigned char g[16];"),
        ("char *[4][2]", "char *g[4][2];"),
        ("struct conn *", "struct conn *g;"),
        ("void (*)(int )", "void (*g)(int );"),
        ("int (*[4])(struct conn *c, char *s)", "int (*g[4])(struct conn *c, char *s);"),
        ("int (*)[3]", "int (*g)[3];"),
    ],
)
def test_global_definition_text(type_text: str, definition: str) -> None:
    assert R.global_definition_text("g", type_text) == (definition, "")


@pytest.mark.parametrize(
    "type_text", ["", "struct server", "union u [2]", "enum mode", "struct __anonstruct_s_3 *", "int []", "int; x"]
)
def test_global_definition_text_refuses_what_it_cannot_declare(type_text: str) -> None:
    definition, reason = R.global_definition_text("g", type_text)
    assert definition is None and reason


def test_build_module_binary_records_stubbed_and_unresolved_globals(tmp_path: Path, monkeypatch) -> None:
    """Two rounds: the second global only shows once the first is defined; the file holds both."""
    dag_path = _run_dir(tmp_path)
    monkeypatch.chdir(tmp_path)
    out_bin = Path("workspace/build/fuzz_libkv_a")
    stub_file = (STUB_DIR / R.LINK_GLOBALS_FILE).as_posix()
    calls: list[list[str]] = []

    def fake_compile(srcs, out, *a, **k):
        calls.append(list(srcs))
        text = Path(stub_file).read_text(encoding="utf-8") if stub_file in srcs else ""
        missing = next((s for s in ("G_Terminate", "G_Conn") if f"{s};" not in text), None)
        if missing:
            return {"engine": "sanitizers", "returncode": 1, "stderr": _undefined(missing, "G_NoType")}
        return {"engine": "sanitizers", "returncode": 0, "binary": str(out)}

    monkeypatch.setattr(fuzz_build, "compile_sanitizer_binary", fake_compile)
    out = R.build_module_binary(
        ["workspace/work/lib/a.c"], out_bin, engine="sanitizers", dag_path=dag_path, link_module="libkv_a"
    )
    assert out["compile"]["returncode"] == 0 and len(calls) == 3
    assert out["sources"] == ["workspace/work/lib/a.c", stub_file]
    repair = out["link_repair"]
    assert repair["symbols"] == ["G_Terminate", "G_Conn"] and repair["added_sources"] == [stub_file]
    assert [r["added_sources"] for r in repair["rounds"]] == [[stub_file], []]
    assert [g["name"] for g in repair["stubbed_globals"]] == ["G_Terminate", "G_Conn"]
    assert repair["globals_file"] == stub_file
    assert [u["name"] for u in repair["unresolved_globals"]] == ["G_NoType"]
    assert all("unresolved_globals" not in r for r in repair["rounds"])
    text = Path(stub_file).read_text(encoding="utf-8")
    assert "int G_Terminate;" in text and "struct conn *G_Conn;" in text


def test_build_module_binary_reports_a_global_it_cannot_define(tmp_path: Path, monkeypatch) -> None:
    """Nothing repaired: `link_repair` still says why the global stays undefined."""
    dag_path = _run_dir(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        fuzz_build,
        "compile_sanitizer_binary",
        lambda srcs, out, *a, **k: {"engine": "sanitizers", "returncode": 1, "stderr": _undefined("G_NoType")},
    )
    out = R.build_module_binary(
        ["workspace/work/lib/a.c"],
        Path("workspace/build/fuzz_libkv_a"),
        engine="sanitizers",
        dag_path=dag_path,
        link_module="libkv_a",
    )
    assert out["compile"]["returncode"] == 1 and out["sources"] == ["workspace/work/lib/a.c"]
    assert out["link_repair"]["rounds"] == [] and out["link_repair"]["symbols"] == []
    assert [u["name"] for u in out["link_repair"]["unresolved_globals"]] == ["G_NoType"]
