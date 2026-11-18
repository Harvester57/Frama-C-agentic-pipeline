"""
MetAcsl under Eva (docs/plans/metacsl-exploitation-plan.md, package B): run_eva_slice.py
--security-props, what the tuning, shard and Make entry points do with it, and how `ledger.py
ingest-eva` files the result.

The fixture (tests/fixtures/metacsl_eva) is an auth gate, a protected command and a network sink;
-DVIOLATE plants a write of the auth state outside the gate and an uninitialized sink byte, and the
harness's -DHARNESS_DIRECT calls the protected function before the gate. Its security_props.json is the
one security_props.py generates for the -DVIOLATE build (so `backdoor` is in it), with `eva` in
`meta_engines`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

import eva_tuning as et
import ledger as L
import pipeline_make as pm
import run_eva_slice as rs
import security_props as sp
import trust
from conftest import ANALYSIS_IMAGE, ROOT, metadata, write_json
from framac_common import normalize_status
from test_eva_tuning import _finish_args, _write_trial
from test_phase0_model import model_run  # noqa: F401  (Docker fixture)

MB_FIXTURES = ROOT / "tests" / "fixtures" / "metacsl_eva"
MB_PROPS = "workspace/reports/security_props.json"
MB_SOURCES = ["workspace/work/prog.c", "workspace/harnesses/harness_prog.c"]
MB_MODULE = "libprog.a"
MB_AUTH_STATE = "L4_auth_state_login"
MB_AUTH_REQUIRED = "L4_auth_required_login"
MB_SANITIZED = "L5_sanitized_send_bytes"
MB_STAGE = ["-meta", "-meta-checks", "-meta-warn-key", "unknown-func=inactive", "-then-last", "-set-project-as-default"]


def props_doc(engines: tuple[str, ...] | None = ("eva",)) -> dict:
    doc = json.loads((MB_FIXTURES / "security_props.json").read_text(encoding="utf-8"))
    if engines is None:
        doc.pop("meta_engines", None)
    else:
        doc["meta_engines"] = list(engines)
    return doc


def prop_of(doc: dict, name: str) -> dict:
    return next(p for p in doc["properties"] if p["name"] == name)


def fake_manifest(*included: str):
    """cache.dependency_manifest without a compiler: the sources and `included`, each hashed."""

    def manifest(sources, flags, runner=None, timeout=0.0):
        paths = sorted({str(s).replace("\\", "/") for s in sources} | set(included))
        return [
            [p, hashlib.sha256(Path(p).read_bytes()).hexdigest() if Path(p).is_file() else "missing"] for p in paths
        ]

    return manifest


@pytest.fixture
def meta_run(tmp_path, monkeypatch):
    """A scratch run directory (the cwd) holding the fixture's work tree and harness; no cache, no compiler."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("FRAMAC_CACHE", raising=False)
    monkeypatch.delenv(rs.SECURITY_PROPS_ENV, raising=False)
    work = tmp_path / "workspace/work"
    work.mkdir(parents=True)
    for name in ("prog.c", "prog.h"):
        shutil.copy(MB_FIXTURES / "target" / name, work / name)
    (tmp_path / "workspace/harnesses").mkdir(parents=True)
    shutil.copy(MB_FIXTURES / "harness_prog.c", tmp_path / "workspace/harnesses/harness_prog.c")
    monkeypatch.setattr(rs.cache, "dependency_manifest", fake_manifest("workspace/work/prog.h"))
    return tmp_path


def static_section(doc: dict | None = None, sources: list[str] | None = None) -> dict:
    write_json(Path(MB_PROPS), doc or props_doc())
    section = rs.load_security_meta(MB_PROPS, sources or MB_SOURCES, [], "prog", "eva_main")
    assert section is not None and section.get("meta_file"), section
    return section


def row(directory: str, file: str, line: int, function: str, kind: str, status: str, text: str) -> dict:
    return {
        "directory": directory,
        "file": file,
        "line": line,
        "function": function,
        "kind": kind,
        "status": normalize_status(status),
        "status_raw": status,
        "property": text,
    }


def meta_row(section: dict, name: str, function: str, status: str = "Valid", kind: str = "user check") -> dict:
    """A check MetAcsl generated: in the meta file, at the property's line, the name dropped."""
    line = next(int(n) for n, found in section["line_names"].items() if found == name)
    meta = Path(section["meta_file"])
    return row(meta.parent.as_posix(), meta.name, line, function, kind, status, f"\\generated_from({function})")


def call_site_row(function: str = "handle", status: str = "Valid", line: int = 32) -> dict:
    """A generated precondition of admin, reported at a call site in the caller's own file."""
    harness = function == "eva_main"
    return row(
        "workspace/harnesses" if harness else "workspace/work",
        "harness_prog.c" if harness else "prog.c",
        line,
        function,
        "precondition of admin",
        status,
        f"{MB_AUTH_REQUIRED}: meta: auth_ok != 0",
    )


def rte_row(function: str, status: str = "Valid", line: int = 1) -> dict:
    return row("workspace/work", "prog.c", line, function, "mem_access", status, f"\\valid(p_{function}_{line})")


def instance(section: dict, name: str, fid: str) -> dict:
    return next(e for e in section["instances"] if e["property"] == name and e["instance"] == fid)


# ---------------------------------------------------------------------------------------------------
# The command line and the report with the engine off, and with it on
# ---------------------------------------------------------------------------------------------------


@pytest.mark.unit
def test_resolve_security_props_follows_the_wp_runner(meta_run, monkeypatch):
    assert rs.resolve_security_props(None) is None  # no file in the run
    assert rs.resolve_security_props("x/props.json") == "x/props.json"
    write_json(Path(MB_PROPS), props_doc())
    assert rs.resolve_security_props(None) == MB_PROPS
    for off in ("none", "off", "NONE"):
        assert rs.resolve_security_props(off) is None
    monkeypatch.setenv(rs.SECURITY_PROPS_ENV, "elsewhere.json")
    assert rs.resolve_security_props(None) is None  # the environment names a file that is not there
    write_json(Path("elsewhere.json"), props_doc())
    assert rs.resolve_security_props(None) == "elsewhere.json"


def _main_args(out_json: str = "workspace/reports/eva/prog.json") -> list[str]:
    return [
        "--module", "prog", "--sources", *MB_SOURCES, "--main", "eva_main", "--out-dir", "workspace/eva/prog",
        "--out-json", out_json, "--no-warn-unsigned-downcast", "--timeout", "300", "--cppflags=-Iworkspace/work",
    ]  # fmt: skip


@pytest.mark.unit
def test_engine_off_the_command_and_the_report_are_todays(meta_run, monkeypatch, capsys):
    """
    Without `eva` in `meta_engines` (no file, an empty list, the key absent, another engine, `none` on
    the command line) the Frama-C command is the one this literal pins, _execute_eva is called with
    today's arguments (the fake takes no other) and the report file is the same, byte for byte.
    """
    commands: list[list[str]] = []

    def fake_execute(cmd, sources, main_fn, out_dir, reduced_checks, timeout, path_root=None):
        commands.append(list(cmd))
        return {
            "status": "ok",
            "reason": None,
            "error_summary": [],
            "undeclared_functions": [],
            "main_fn": main_fn,
            "sources": list(sources),
            **rs.summarize_rows([rte_row("admin")]),
            "elapsed_s": 1.0,
            "reduced_checks": reduced_checks,
        }

    monkeypatch.setattr(rs, "_execute_eva", fake_execute)
    monkeypatch.setattr(rs, "_input_digest", lambda sources, flags: "d")
    reports: list[bytes] = []
    out_json = meta_run / "workspace/reports/eva/prog.json"
    variants = [(None, []), (props_doc(()), []), (props_doc(None), []), (props_doc(("eacsl",)), [])]
    variants.append((props_doc(("eva",)), ["--security-props", "none"]))
    for doc, extra in variants:
        if doc is None:
            Path(MB_PROPS).unlink(missing_ok=True)
        else:
            write_json(Path(MB_PROPS), doc)
        assert rs.main([*_main_args(), *extra]) == 0
        reports.append(out_json.read_bytes())
        assert "security_props" not in json.loads(capsys.readouterr().out)
    out = Path("workspace/eva/prog")
    assert commands[0] == [
        "frama-c", "-pp-annot", "-no-unicode", "-machdep", "gcc_x86_64",
        "-warn-signed-overflow", "-warn-signed-downcast", "-warn-left-shift-negative",
        "-warn-right-shift-negative", "-warn-pointer-downcast", "-warn-invalid-pointer", "-warn-unsigned-overflow",
        f"-cpp-extra-args={rs.augment_framac_cppflags('-Iworkspace/work')}",
        "workspace/work/prog.c", "workspace/harnesses/harness_prog.c",
        "-main", "eva_main", "-rte", "-then", "-eva",
        "-eva-domains", "cvalue,equality,symbolic-locations,octagon,gauges",
        "-eva-slevel", "100", "-eva-auto-loop-unroll", "32",
        "-eva-report-red-statuses", str(out / "red_alarms.csv"), "-eva-flamegraph", str(out / "flamegraph.txt"),
        "-then", "-metrics", "-metrics-eva-cover",
        "-then", "-report", "-report-csv", str(out / "alarms.csv"), "-save", str(out / "framac.sav"),
        "-then", "-nonterm", "-nonterm-log", f"a:{out / 'nonterm.log'}",
    ]  # fmt: skip
    assert all(cmd == commands[0] for cmd in commands) and len(commands) == len(variants)
    assert all(report == reports[0] for report in reports)
    assert b"security_props" not in reports[0] and b"security_meta" not in reports[0]
    assert not (meta_run / "workspace/reports" / rs.SECURITY_META_DIR).exists()


def _capture_runs(monkeypatch, rows_for=None, fail_with_meta: bool = False) -> list[dict]:
    """Replace _execute_eva; each call is recorded as {cmd, security_meta}."""
    calls: list[dict] = []

    def fake_execute(cmd, sources, main_fn, out_dir, reduced_checks, timeout, path_root=None, security_meta=None):
        calls.append({"cmd": list(cmd), "security_meta": security_meta})
        if fail_with_meta and "-meta" in cmd:
            (out_dir / "eva.log").write_text("[meta] User Error: Error during the typing of a HILARE!\n", "utf-8")
            return {
                "status": "analysis_error",
                "reason": "exit_1",
                "error_summary": ["[meta] User Error: Error during the typing of a HILARE!"],
                "sources": list(sources),
                "reduced_checks": reduced_checks,
            }
        (out_dir / "eva.log").write_text("ok\n", "utf-8")
        rows = rows_for(security_meta) if rows_for else []
        return {
            "status": "ok",
            "sources": list(sources),
            "reduced_checks": reduced_checks,
            **rs.summarize_report(rows, security_meta),
        }

    monkeypatch.setattr(rs, "_execute_eva", fake_execute)
    monkeypatch.setattr(rs, "_input_digest", lambda sources, flags: "d")
    return calls


@pytest.mark.unit
def test_engine_on_the_meta_file_follows_the_sources_and_metacsl_runs_before_rte(meta_run, monkeypatch):
    doc = props_doc()
    write_json(Path(MB_PROPS), doc)
    calls = _capture_runs(monkeypatch, lambda s: [meta_row(s, MB_SANITIZED, "emit"), rte_row("emit")])
    res = rs.run_eva_on_slice(
        MB_SOURCES, "eva_main", Path("workspace/eva/prog"), use_cache=False, security_props=MB_PROPS, module="prog"
    )
    section = res["security_props"]
    cmd = calls[0]["cmd"]
    meta_file = section["meta_file"]
    start = cmd.index("workspace/work/prog.c")
    assert cmd[start : cmd.index("-eva")] == [*MB_SOURCES, meta_file, "-main", "eva_main", *MB_STAGE, "-rte", "-then"]
    assert tuple(MB_STAGE) == rs.META_STAGE
    # Apart from the meta file and the stage, the command is the one of a run without properties.
    plain, _ = rs._eva_command(
        MB_SOURCES, "eva_main", Path("workspace/eva/prog"), "gcc_x86_64", "-I.", 100, True, True, True, None
    )
    assert [t for t in cmd if t != meta_file and t not in MB_STAGE] == plain
    # The file: named after its text, and the text security_props.py gives for this module's functions.
    path = Path(meta_file)
    ids = {"prog.c#" + fn for fn in ("backdoor", "emit", "get_level", "handle")}
    text = sp.module_meta_file_text(doc, functions=ids)[0]
    assert path.read_text(encoding="utf-8") == text
    assert path.parent.name == hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
    assert path.parent.parent.as_posix() == f"workspace/reports/{rs.SECURITY_META_DIR}"
    assert path.name == "security_meta_prog.c" and b"\r" not in path.read_bytes()
    assert section["properties"] == [MB_AUTH_STATE, MB_AUTH_REQUIRED, MB_SANITIZED]
    assert set(section["line_names"].values()) == set(section["properties"])
    assert section["planned"] == {
        MB_AUTH_STATE: ["prog.c#backdoor", "prog.c#get_level"],
        MB_AUTH_REQUIRED: ["prog.c#handle"],
        MB_SANITIZED: ["prog.c#emit"],
    }
    assert section["classes"][MB_SANITIZED] == "l5_sanitized" and section["roots"] == ["workspace/work/"]
    assert section["outside_functions"] == ["eva_main"] and section["extra_sources"] == []
    # The check is the property's, not an RTE obligation of emit.
    assert instance(section, MB_SANITIZED, "prog.c#emit")["valid"] == 1
    assert res["valid_count"] == 1 and res["functions_with_properties"] == ["emit"]


@pytest.mark.unit
def test_a_harness_that_includes_the_source_gets_the_properties_through_its_dependencies(meta_run, monkeypatch):
    write_json(Path(MB_PROPS), props_doc())
    harness = ["workspace/harnesses/harness_prog.c"]
    monkeypatch.setattr(rs.cache, "dependency_manifest", fake_manifest("workspace/work/prog.c"))
    section = rs.load_security_meta(MB_PROPS, harness, [], "prog", "eva_main")
    assert section["properties"] == [MB_AUTH_STATE, MB_AUTH_REQUIRED, MB_SANITIZED]
    # Nothing of the module in the parse: no meta file, and the run is the plain run plus a note.
    monkeypatch.setattr(rs.cache, "dependency_manifest", lambda *a, **k: None)
    assert rs.load_security_meta(MB_PROPS, harness, [], "prog", "eva_main") == {
        "props": MB_PROPS,
        "properties": [],
        "meta_file": None,
    }
    calls = _capture_runs(monkeypatch)
    res = rs.run_eva_on_slice(
        harness, "eva_main", Path("workspace/eva/prog"), use_cache=False, security_props=MB_PROPS, module="prog"
    )
    assert "-meta" not in calls[0]["cmd"] and calls[0]["security_meta"] is None
    assert res["security_props"] == {"props": MB_PROPS, "properties": [], "meta_file": None}


@pytest.mark.unit
def test_an_unreadable_file_is_reported_and_the_run_is_the_plain_one(meta_run, monkeypatch):
    Path(MB_PROPS).parent.mkdir(parents=True, exist_ok=True)
    Path(MB_PROPS).write_text("{not json", encoding="utf-8")
    calls = _capture_runs(monkeypatch)
    res = rs.run_eva_on_slice(
        MB_SOURCES, "eva_main", Path("workspace/eva/prog"), use_cache=False, security_props=MB_PROPS, module="prog"
    )
    assert "-meta" not in calls[0]["cmd"] and res["status"] == "ok"
    assert res["security_props"]["error"].startswith("unreadable: ") and res["security_props"]["properties"] == []


@pytest.mark.unit
def test_a_propertys_sources_join_the_parse_or_the_property_is_skipped(meta_run, monkeypatch):
    doc = props_doc()
    prop_of(doc, MB_AUTH_STATE)["sources"] = ["state.c"]
    write_json(Path(MB_PROPS), doc)
    # The file that defines the global is not in the work tree: MetAcsl could not type the property.
    section = rs.load_security_meta(MB_PROPS, MB_SOURCES, [], "prog", "eva_main")
    assert section["properties"] == [MB_AUTH_REQUIRED, MB_SANITIZED]
    assert section["skipped"] == [
        {
            "property": MB_AUTH_STATE,
            "reason": "its source state.c is neither in this parse nor under workspace/work/",
        }
    ]
    assert MB_AUTH_STATE not in section["planned"]
    # Present: it is parsed, after the module's sources and before the meta file.
    Path("workspace/work/state.c").write_text("int auth_ok;\n", encoding="utf-8")
    calls = _capture_runs(monkeypatch)
    res = rs.run_eva_on_slice(
        MB_SOURCES, "eva_main", Path("workspace/eva/prog"), use_cache=False, security_props=MB_PROPS, module="prog"
    )
    section = res["security_props"]
    assert section["extra_sources"] == ["workspace/work/state.c"] and "skipped" not in section
    cmd = calls[0]["cmd"]
    start = cmd.index("workspace/work/prog.c")
    assert cmd[start : cmd.index("-main")] == [*MB_SOURCES, "workspace/work/state.c", section["meta_file"]]
    # A source the parse already has (prog.c for the two other properties) is not added again.
    assert cmd.count("workspace/work/prog.c") == 1


@pytest.mark.unit
def test_frama_c_failing_with_the_properties_falls_back_to_the_run_without_them(meta_run, monkeypatch):
    write_json(Path(MB_PROPS), props_doc())
    calls = _capture_runs(monkeypatch, lambda s: [rte_row("emit")], fail_with_meta=True)
    out = Path("workspace/eva/prog")
    res = rs.run_eva_on_slice(MB_SOURCES, "eva_main", out, use_cache=False, security_props=MB_PROPS, module="prog")
    assert [("-meta" in c["cmd"], c["security_meta"] is not None) for c in calls] == [(True, True), (False, False)]
    assert res["status"] == "ok" and res["valid_count"] == 1
    section = res["security_props"]
    assert section["error"] == "Frama-C failed with the security properties loaded; this is the run without them"
    assert section["error_summary"] == ["[meta] User Error: Error during the typing of a HILARE!"]
    assert section["properties"] == [] and "meta_file" not in section
    assert Path(section["failed_meta_file"]).is_file()
    kept = Path(section["failed_log"])
    assert kept.name == "eva.meta_failed.log" and "HILARE" in kept.read_text(encoding="utf-8")
    assert (out / "eva.log").read_text(encoding="utf-8") == "ok\n"


# ---------------------------------------------------------------------------------------------------
# Filing the rows: instances, unplanned instances, harness code
# ---------------------------------------------------------------------------------------------------


@pytest.mark.unit
def test_rows_are_filed_by_property_and_function(meta_run):
    static = static_section()
    rows = [
        meta_row(static, MB_AUTH_STATE, "get_level"),
        meta_row(static, MB_AUTH_STATE, "backdoor", "Invalid"),
        meta_row(static, MB_SANITIZED, "emit", "Unknown"),
        call_site_row("handle"),
        # The consolidated status of the generated precondition: its call sites have rows of their own.
        meta_row(static, MB_AUTH_REQUIRED, "admin", "Unknown", kind="precondition"),
        # The harness calls the protected function before the gate.
        call_site_row("eva_main", "Invalid", line=12),
        # A target function that is no instance of the property (the model and MetAcsl disagree).
        meta_row(static, MB_AUTH_STATE, "handle", "Invalid or unreachable"),
        meta_row(static, MB_SANITIZED, "eva_main"),
        rte_row("admin", "Unknown"),
    ]
    assert [rs.is_meta_row(r, static) for r in rows] == [True] * 8 + [False]
    report = rs.summarize_report(rows, static)
    section = report["security_props"]
    assert {
        (e["property"], e["instance"]): {b: e[b] for b in rs.META_BUCKETS if e[b]} for e in section["instances"]
    } == {
        (MB_AUTH_REQUIRED, "prog.c#handle"): {"valid": 1},
        (MB_AUTH_STATE, "prog.c#backdoor"): {"invalid": 1},
        (MB_AUTH_STATE, "prog.c#get_level"): {"valid": 1},
        (MB_SANITIZED, "prog.c#emit"): {"unknown": 1},
    }
    assert instance(section, MB_SANITIZED, "prog.c#emit")["class"] == "l5_sanitized"
    assert instance(section, MB_SANITIZED, "prog.c#emit")["function"] == "emit"
    assert [(e["property"], e["function"], e["invalid"]) for e in section["unplanned_instances"]] == [
        (MB_AUTH_STATE, "prog.c#handle", 1)
    ]
    assert [(e["property"], e["function"], e["invalid"], e["valid"]) for e in section["outside_instances"]] == [
        (MB_AUTH_REQUIRED, "eva_main", 1, 0),
        (MB_SANITIZED, "eva_main", 0, 1),
    ]
    assert section["counts"] == {"valid": 3, "unknown": 1, "invalid": 3, "dead": 0, "assumed": 0, "other": 0}
    assert [(r["status_bucket"], r["role"], r["property"], r["function"]) for r in section["open_rows"]] == [
        ("invalid", "outside", MB_AUTH_REQUIRED, "eva_main"),
        ("invalid", "instance", MB_AUTH_STATE, "backdoor"),
        ("invalid", "unplanned", MB_AUTH_STATE, "handle"),
        ("unknown", "instance", MB_SANITIZED, "emit"),
    ]
    by_fn = {r["function"]: r for r in section["open_rows"]}
    assert by_fn["backdoor"]["instance"] == "prog.c#backdoor" and by_fn["handle"]["instance"] is None
    # A row in the meta file gets its property's name back; a call-site row already has it.
    assert by_fn["backdoor"]["annotation"] == f"{MB_AUTH_STATE}: meta: \\generated_from(backdoor)"
    assert by_fn["eva_main"]["annotation"] == f"{MB_AUTH_REQUIRED}: meta: auth_ok != 0"
    assert by_fn["eva_main"]["file"] == "harness_prog.c" and by_fn["eva_main"]["line"] == 12
    # None of MetAcsl's rows is an RTE obligation: the status lists hold the one RTE row.
    assert report["unknown_count"] == 1 and report["invalid_count"] == 0 and report["valid_count"] == 0
    assert report["invalid_alarms"] == [] and report["surviving_unknown_functions"] == ["admin"]
    assert report["functions_with_properties"] == ["admin"]
    assert {k: v for k, v in report.items() if k != "security_props"} == rs.summarize_rows([rows[-1]])


@pytest.mark.unit
def test_without_a_meta_file_the_summary_is_summarize_rows(meta_run):
    static = static_section()
    rows = [meta_row(static, MB_SANITIZED, "emit", "Unknown"), rte_row("admin", "Unknown")]
    plain = rs.summarize_rows(rows)
    for section in (None, {}, {"props": MB_PROPS, "properties": [], "meta_file": None}, {"error": "x"}):
        assert rs.summarize_report(rows, section) == plain
        assert not rs.is_meta_row(rows[0], section)
    assert rs.split_meta_rows(rows, static) == ([rows[1]], [rows[0]])


@pytest.mark.unit
def test_an_instance_without_a_row_is_listed_with_zeros(meta_run):
    section = rs.summarize_report([rte_row("emit")], static_section())["security_props"]
    assert len(section["instances"]) == 4
    assert all(not any(e[b] for b in rs.META_BUCKETS) for e in section["instances"])
    assert section["unplanned_instances"] == [] and section["outside_instances"] == [] and section["open_rows"] == []


@pytest.mark.unit
def test_a_decided_instance_is_no_unplanned_instance(meta_run):
    doc = props_doc()
    sanitized = prop_of(doc, MB_SANITIZED)
    sanitized["decided"] = [{"function": "prog.c#handle", "verdict": "satisfied", "reason": "a literal"}]
    static = static_section(doc)
    assert static["decided"] == {MB_SANITIZED: ["prog.c#handle"]}
    section = rs.security_section([meta_row(static, MB_SANITIZED, "handle", "Unknown")], static)
    assert section["unplanned_instances"] == [] and section["open_rows"] == []
    assert section["counts"]["unknown"] == 1
    assert not any(instance(section, MB_SANITIZED, "prog.c#emit")[b] for b in rs.META_BUCKETS)


@pytest.mark.unit
def test_a_function_two_files_define_is_not_credited_from_a_meta_file_row(meta_run):
    """A row in the meta file only names its function: with two `get_level`, it proves neither instance."""
    doc = props_doc()
    doc["obligations"]["other.c#get_level"] = [{"class": "l3_frame", "property": "L3_frame", "reason": "r"}]
    Path("workspace/work/other.c").write_text("static void get_level(unsigned char *o) { *o = 0; }\n", "utf-8")
    static = static_section(doc, [*MB_SOURCES, "workspace/work/other.c"])
    assert static["functions"]["get_level"] == ["other.c#get_level", "prog.c#get_level"]
    section = rs.security_section([meta_row(static, MB_AUTH_STATE, "get_level")], static)
    entry = instance(section, MB_AUTH_STATE, "prog.c#get_level")
    assert entry["valid"] == 0 and entry["other"] == 1
    assert section["open_rows"][0]["role"] == "ambiguous"
    assert section["open_rows"][0]["candidates"] == ["other.c#get_level", "prog.c#get_level"]
    # The kernel's renamed copy (`get_level_0`) does not say which file it is either.
    section = rs.security_section([meta_row(static, MB_AUTH_STATE, "get_level_0")], static)
    assert instance(section, MB_AUTH_STATE, "prog.c#get_level")["other"] == 1
    # A call-site row is in its function's own file: no doubt there.
    static = static_section(props_doc())
    section = rs.security_section([call_site_row("handle")], static)
    assert instance(section, MB_AUTH_REQUIRED, "prog.c#handle")["valid"] == 1


# ---------------------------------------------------------------------------------------------------
# The cache key and the input digest
# ---------------------------------------------------------------------------------------------------


def _cache_material(monkeypatch, doc: dict | None) -> tuple[dict, list[str], list[str]]:
    """(cache material, the sources memoize hashes, the sources of the input digest) of one run."""
    seen: dict = {}

    def fake_memoize(ns, material, **kwargs):
        seen.update(material=material, sources=[str(s) for s in kwargs["sources"]])
        return {"status": "ok"}

    def fake_digest(sources, flags):
        seen["digest_sources"] = list(sources)
        return "d"

    monkeypatch.setattr(rs.cache, "memoize", fake_memoize)
    monkeypatch.setattr(rs, "_input_digest", fake_digest)
    if doc is None:
        Path(MB_PROPS).unlink(missing_ok=True)
    else:
        write_json(Path(MB_PROPS), doc)
    props = rs.resolve_security_props(None)
    rs.run_eva_on_slice(
        MB_SOURCES,
        "eva_main",
        Path("workspace/eva/prog"),
        **({"security_props": props, "module": "prog"} if props else {}),
    )
    return seen["material"], seen["sources"], seen["digest_sources"]


@pytest.mark.unit
def test_the_cache_key_follows_the_meta_file_and_the_engine_switch(meta_run, monkeypatch):
    plain, plain_sources, plain_digest = _cache_material(monkeypatch, None)
    off, off_sources, off_digest = _cache_material(monkeypatch, props_doc(()))
    assert off == plain and off_sources == plain_sources == MB_SOURCES and off_digest == plain_digest == MB_SOURCES
    assert "security_props" not in plain

    on, on_sources, on_digest = _cache_material(monkeypatch, props_doc())
    meta_file = on_sources[-1]
    assert on_sources == [*MB_SOURCES, meta_file] == on["sources"] == on_digest
    assert Path(meta_file).name == "security_meta_prog.c" and "-meta" in on["command"] and meta_file in on["command"]
    assert on["security_props"] and on != plain

    # Another property text is another meta file (its directory is named after the text): the
    # dependency manifest hashes it, and the path is in the command.
    changed = props_doc()
    sanitized = prop_of(changed, MB_SANITIZED)
    sanitized["acsl"] = sanitized["acsl"].replace("\\initialized", "\\valid_read")
    other, other_sources, _ = _cache_material(monkeypatch, changed)
    assert other_sources[-1] != meta_file and other["command"] != on["command"]

    # The same text filed differently (a function the model decided): only the digest of the filing changes.
    decided = props_doc()
    prop_of(decided, MB_SANITIZED)["decided"] = [{"function": "prog.c#handle", "verdict": "satisfied"}]
    filed, filed_sources, _ = _cache_material(monkeypatch, decided)
    assert filed_sources == on_sources and filed["command"] == on["command"]
    assert filed["security_props"] != on["security_props"]


# ---------------------------------------------------------------------------------------------------
# Tuning rungs, loop trials, shards
# ---------------------------------------------------------------------------------------------------


@pytest.mark.unit
def test_runs_put_together_must_have_loaded_the_same_meta_file(meta_run):
    static = static_section()
    rows = [meta_row(static, MB_SANITIZED, "emit"), rte_row("emit", "Unknown")]
    full = rs.summarize_report(rows, static)
    section = full["security_props"]
    assert rs.summarize_runs(rows, [section, static]) == full
    assert rs.summarize_runs(rows, [None, None]) == rs.summarize_rows(rows)
    # One run fell back to the run without the properties: no instance gets a status from the others.
    failed = {"props": MB_PROPS, "error": "Frama-C failed with the security properties loaded", "properties": []}
    merged = rs.summarize_runs(rows, [section, failed])
    assert merged["security_props"]["properties"] == [] and "instances" not in merged["security_props"]
    assert merged["security_props"]["error"].startswith("one of the runs ran without the properties (Frama-C failed")
    assert merged["valid_count"] == 0 and merged["unknown_count"] == 1  # MetAcsl's row is no RTE row either
    # Different meta files (a rung started before security_props.json changed).
    other = {**static, "meta_file": "workspace/reports/security_meta/000000000000/security_meta_prog.c"}
    merged = rs.summarize_runs(rows, [section, other])
    assert merged["security_props"]["error"].startswith("the runs did not load the same meta file (")
    assert merged["valid_count"] == 0 and merged["unknown_count"] == 1
    # Every run failed: the report says so, and its rows are all RTE rows.
    assert rs.summarize_runs([rows[1]], [failed, failed])["security_props"] == failed


@pytest.mark.unit
def test_tuning_does_not_work_on_metacsl_unknowns(meta_run):
    static = static_section()
    meta_unknown = meta_row(static, MB_SANITIZED, "emit", "Unknown")
    rte_unknown = rte_row("emit", "Unknown")
    rows = [meta_unknown, rte_unknown, rte_row("admin")]
    assert et.tuning_unknown_rows(rows, {"security_props": static}) == [rte_unknown]
    assert et.tuning_unknown_rows(rows, {}) == [meta_unknown, rte_unknown]
    run = et.EvaRun("base", {"status": "ok", "security_props": static}, rows=rows, log_text="", entry_fn="emit")
    assert run.unknown_rows == [rte_unknown]


@pytest.mark.unit
def test_finish_files_the_combined_rows_and_a_metacsl_unknown_alone_starts_no_tuning(meta_run, capsys):
    (meta_run / "workspace/build").mkdir(parents=True)
    static = static_section()
    parse = [row("workspace/work", "a.c", 1, "parse", "mem_access", "Valid", "\\valid(p+1)")]
    base_rows = [*parse, meta_row(static, MB_SANITIZED, "emit", "Unknown")]
    _write_trial(
        meta_run, "m", "base", base_rows, security_props=rs.summarize_report(base_rows, static)["security_props"]
    )
    assert et.main(_finish_args(meta_run, [])) == 0
    capsys.readouterr()
    report = json.loads((meta_run / "workspace/reports/eva/m.json").read_text(encoding="utf-8"))
    # Nothing to tune: the module's report is the base run's, with the section the base run wrote.
    assert report["tuning"] == {"mode": "skipped", "reason": "the base run left no Unknown obligations"}
    assert instance(report["security_props"], MB_SANITIZED, "prog.c#emit")["unknown"] == 1

    # With an RTE Unknown the ladder runs; a rung that also proves the check shows in the section.
    base_rows = [
        row("workspace/work", "a.c", 1, "parse", "mem_access", "Unknown", "\\valid(p+1)"),
        row("workspace/work", "a.c", 2, "parse", "mem_access", "Unknown", "\\valid(p+2)"),
        meta_row(static, MB_SANITIZED, "emit", "Unknown"),
    ]
    rung_rows = [
        row("workspace/work", "a.c", 1, "parse", "mem_access", "Valid", "\\valid(p+1)"),
        row("workspace/work", "a.c", 2, "parse", "mem_access", "Unknown", "\\valid(p+2)"),
        meta_row(static, MB_SANITIZED, "emit", "Valid"),
    ]
    _write_trial(
        meta_run, "m", "base", base_rows, security_props=rs.summarize_report(base_rows, static)["security_props"]
    )
    _write_trial(
        meta_run,
        "m",
        "slevel",
        rung_rows,
        eva_options={"slevel": 1000},
        security_props=rs.summarize_report(rung_rows, static)["security_props"],
    )
    assert et.main(_finish_args(meta_run, ["slevel"])) == 0
    capsys.readouterr()
    report = json.loads((meta_run / "workspace/reports/eva/m.json").read_text(encoding="utf-8"))
    assert report["tuning"]["selected"] == "slevel" and report["unknown_count"] == 1
    assert report["tuning"]["after"]["unknown_count"] == 1  # the RTE row at line 2, not MetAcsl's
    entry = instance(report["security_props"], MB_SANITIZED, "prog.c#emit")
    assert entry["valid"] == 1 and entry["unknown"] == 0
    assert report["surviving_unknown_functions"] == ["parse"]


@pytest.mark.unit
def test_loop_trials_load_the_same_properties(meta_run, monkeypatch):
    seen: list[dict] = []

    def fake_run(**kwargs):
        seen.append(kwargs)
        return {"status": "analysis_error", "reason": "exit_1"}

    monkeypatch.setattr(et, "run_eva_on_slice", fake_run)
    args = argparse.Namespace(
        sources=MB_SOURCES, main="eva_main", cppflags="-I.", slevel=100, mlevel=0, timeout=60, extra_domains="",
        allow_incomplete_recursion_specs=False, no_warn_unsigned_downcast=True, module="prog", entry_fn="handle",
        report_dir="workspace/reports/eva-tuning/prog", work_dir="workspace/eva/prog/tune", security_props=None,
    )  # fmt: skip
    et.Tuner(args).run_trial("t0", {}, [])
    assert "security_props" not in seen[-1] and "module" not in seen[-1]  # no file: called as before
    write_json(Path(MB_PROPS), props_doc())
    et.Tuner(args).run_trial("t1", {}, [])
    assert seen[-1]["security_props"] == MB_PROPS and seen[-1]["module"] == "prog"
    args.security_props = "none"
    et.Tuner(args).run_trial("t2", {}, [])
    assert "security_props" not in seen[-1]


# ---------------------------------------------------------------------------------------------------
# pipeline_make.py: modules.mk, the settings digest, the Eva recipes
# ---------------------------------------------------------------------------------------------------

MB_TEMPLATES = "/opt/framac-pipeline/templates"


def _plan_run(run: Path, doc: dict | None) -> Path:
    write_json(run / "run-metadata.json", {**metadata(), "profile": "quick"})
    module = {
        "tier": "Tier 1A (Untrusted Binary / Network Parser)",
        "run_eacsl_fuzz": True,
        "run_eva": True,
        "required_sources": ["prog.c"],
        "cppflags": [],
    }
    write_json(run / pm.DAG_JSON, {"modules": {"prog": module}})
    sidecar = {"module": "prog", "sources": ["workspace/work/prog.c"], "cppflags": "-I. -Iworkspace/work"}
    write_json(run / pm.HARNESS_DIR / "harness_prog.json", {**sidecar, "include_source": False, "entry_fn": "handle"})
    shutil.copy(MB_FIXTURES / "harness_prog.c", run / pm.HARNESS_DIR / "harness_prog.c")
    (run / "workspace/work").mkdir(parents=True, exist_ok=True)
    shutil.copy(MB_FIXTURES / "target/prog.c", run / "workspace/work/prog.c")
    props = run / pm.SECURITY_PROPS_JSON
    if doc is None:
        props.unlink(missing_ok=True)
    else:
        write_json(props, doc)
    return run


@pytest.mark.unit
def test_modules_mk_names_the_file_only_with_the_engine_on(tmp_path):
    run = _plan_run(tmp_path, None)
    assert pm.eva_security_props(run) is None
    pm.generate(run, templates_dir=MB_TEMPLATES)
    without = (run / pm.MODULES_MK).read_text(encoding="utf-8")
    digest_without = pm.build_plan(run, templates_dir=MB_TEMPLATES).modules["prog"].settings_digest
    assert "EVA_SECURITY_PROPS" not in without

    # The file is there and Eva is not among its engines: modules.mk and the settings digest do not move.
    for doc in (props_doc(()), props_doc(None), props_doc(("eacsl",))):
        _plan_run(run, doc)
        assert pm.eva_security_props(run) is None
        assert pm.generate(run, templates_dir=MB_TEMPLATES)["changed"] is False
        plan = pm.build_plan(run, templates_dir=MB_TEMPLATES)
        assert plan.modules["prog"].settings_digest == digest_without
        assert "eva_security_props" not in plan.modules["prog"].to_json()

    _plan_run(run, props_doc())
    found = pm.eva_security_props(run)
    assert found is not None and found[0] == pm.SECURITY_PROPS_JSON
    pm.generate(run, templates_dir=MB_TEMPLATES)
    with_props = (run / pm.MODULES_MK).read_text(encoding="utf-8")
    line = f"EVA_SECURITY_PROPS_prog := {pm.SECURITY_PROPS_JSON}\n"
    assert with_props.replace(line, "") != with_props
    plan = pm.build_plan(run, templates_dir=MB_TEMPLATES)
    module = plan.modules["prog"]
    assert module.eva_security == found and module.to_json()["eva_security_props"] == pm.SECURITY_PROPS_JSON
    # Turning the engine on is a new analysis for a recorded tuning decision; nothing else of modules.mk moves.
    assert module.settings_digest != digest_without
    assert with_props.replace(line, "").replace(module.settings_digest, digest_without) == without


@pytest.mark.unit
def test_the_settings_digest_follows_what_a_meta_file_is_built_from(tmp_path):
    run = _plan_run(tmp_path, props_doc())
    first = pm.eva_security_props(run)
    regenerated = props_doc()
    regenerated["generated_at"] = "2027-01-01T00:00:00+00:00"
    regenerated["warnings"] = ["a note"]
    _plan_run(run, regenerated)
    assert pm.eva_security_props(run) == first  # the same properties, written again
    for change in ("acsl", "instances", "decided", "preamble"):
        doc = props_doc()
        sanitized = prop_of(doc, MB_SANITIZED)
        if change == "acsl":
            sanitized["acsl"] = sanitized["acsl"].replace("\\initialized", "\\valid_read")
        elif change == "instances":
            sanitized["instances"] = [*sanitized["instances"], "prog.c#handle"]
        elif change == "decided":
            sanitized["decided"] = [{"function": "prog.c#handle", "verdict": "satisfied"}]
        else:
            doc["preamble"] += "\n/*@ predicate another(integer x) = x == 0; */"
        _plan_run(run, doc)
        found = pm.eva_security_props(run)
        assert found is not None and found[0] == first[0] and found[1] != first[1], change
    (run / pm.SECURITY_PROPS_JSON).write_text("{not json", encoding="utf-8")
    assert pm.eva_security_props(run) is None


@pytest.mark.unit
def test_every_eva_recipe_gets_the_option_through_eva_args():
    text = (ROOT / "templates" / "pipeline.mk").read_text(encoding="utf-8")
    logical = text.replace("\\\n", " ")
    eva_args = next(line for line in logical.splitlines() if line.startswith("eva_args = "))
    assert "$(if $(EVA_SECURITY_PROPS_$(1)),--security-props=$(EVA_SECURITY_PROPS_$(1)))" in eva_args
    # The plain run, the base run, the rungs, the shards and `finish` (loop trials, replay) all use it.
    runners = [
        line
        for line in logical.splitlines()
        if ("run_eva_slice.py" in line or "eva_tuning.py finish" in line) and not line.lstrip().startswith("#")
    ]
    assert len(runners) >= 5
    assert all("call eva_args," in line for line in runners), runners


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("make") is None, reason="GNU make not available")
@pytest.mark.parametrize("engine_on", [False, True])
def test_make_passes_the_option_to_the_eva_runs(tmp_path, engine_on):
    run = _plan_run(tmp_path, props_doc() if engine_on else props_doc(()))
    pm.generate(run, templates_dir=MB_TEMPLATES)
    proc = subprocess.run(
        ["make", "-f", pm.MAKEFILE, f"S={(ROOT / 'scripts').as_posix()}", "-n", "eva-prog", "evabase-prog"],
        cwd=run,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    runs = [line for line in proc.stdout.replace("\\\n", " ").splitlines() if "run_eva_slice.py" in line]
    assert runs
    option = f"--security-props={pm.SECURITY_PROPS_JSON}"
    assert all((option in line) is engine_on for line in runs), runs


# ---------------------------------------------------------------------------------------------------
# ledger.py ingest-eva
# ---------------------------------------------------------------------------------------------------

MB_FUNCTIONS = ("login", "admin", "handle", "backdoor", "get_level", "emit")
MB_EVA_REPORT = f"workspace/reports/eva/{MB_MODULE}.json"


def _seed(run: Path, doc: dict, functions: tuple[str, ...] = MB_FUNCTIONS) -> None:
    dag = {
        "callgraph_source": "frama_c",
        "modules": {MB_MODULE: {"tier": "Tier 1A (Untrusted Binary / Network Parser)"}},
        "functions": {
            name: {"name": name, "file": "prog.c", "module": MB_MODULE, "wave": 0, "has_loops": False}
            for name in functions
        },
    }
    write_json(run / MB_PROPS, doc)
    write_json(run / "workspace/reports/callgraph_dag.json", dag)
    L.cmd_seed(run / "workspace/reports/callgraph_dag.json", [], "frama_c")


def _units() -> dict[str, dict]:
    return L.load_state()[0]


def _ingest(rows: list[dict], static: dict, module: str = MB_MODULE, **extra) -> dict:
    report = {
        "status": "ok",
        "module": module,
        "sources": list(MB_SOURCES),
        "reduced_checks": [],
        **rs.summarize_report(rows, static),
        **extra,
    }
    path = Path(f"workspace/reports/eva/{module}.json")
    write_json(path, report)
    return L.cmd_ingest_eva([path])


def _correct_rows(static: dict) -> list[dict]:
    """The correct program: every check MetAcsl generated is Valid, and so is every RTE row."""
    return [
        meta_row(static, MB_AUTH_STATE, "get_level"),
        call_site_row("handle"),
        meta_row(static, MB_SANITIZED, "emit"),
        *(rte_row(fn) for fn in MB_FUNCTIONS if fn != "backdoor"),
    ]


@pytest.fixture
def ledger_run(meta_run):
    static = static_section()
    _seed(meta_run, props_doc())
    return static


@pytest.mark.unit
def test_valid_checks_cover_the_units_of_their_properties(ledger_run):
    static = ledger_run
    stats = _ingest(_correct_rows(static), static)
    units = _units()
    for cid in ("prog.c#handle::l4_auth_required", "prog.c#get_level::l4_auth_state", "prog.c#emit::l5_sanitized"):
        unit = units[cid]
        assert unit["status"] == "covered", unit
        assert unit["bookkeeping"]["eva_verdicts"] == {MB_MODULE: "valid"}
        last = unit["evidence"][-1]
        assert last["result"] == "eva_meta_valid" and last["discharging"] and last["phase"] == "eva"
        assert last["tool_output"] == MB_EVA_REPORT
        assert any(a["description"].startswith("Eva result holds") for a in unit["assumptions"])
    # MetAcsl generated no check in backdoor (not compiled in this build): not credited, WP's to decide.
    backdoor = units["prog.c#backdoor::l4_auth_state"]
    assert backdoor["status"] == "planned" and backdoor["bookkeeping"]["eva_verdicts"] == {MB_MODULE: "none"}
    assert backdoor["evidence"][-1]["result"] == "eva_meta_no_instance"
    # The frame unit of get_level is no MetAcsl class: Eva's checks say nothing about it.
    frame = units["prog.c#get_level::l3_frame"]
    assert frame["status"] == "planned" and not frame["evidence"]
    assert stats["meta_units"] == 4 and stats["candidates"] == 0
    assert units["prog.c#emit::rte"]["bookkeeping"]["eva_verdicts"] == {MB_MODULE: "valid"}
    assert not L.validate_ledger(list(units.values()))


@pytest.mark.unit
def test_invalid_checks_are_candidates_on_the_right_units_and_harness_rows_touch_none(ledger_run):
    static = ledger_run
    rows = [
        meta_row(static, MB_AUTH_STATE, "get_level"),
        meta_row(static, MB_AUTH_STATE, "backdoor", "Invalid"),
        call_site_row("handle"),
        meta_row(static, MB_SANITIZED, "emit", "Invalid"),
        # Induced by the harness, and a target function that is no instance: listed, never filed.
        call_site_row("eva_main", "Invalid", line=12),
        meta_row(static, MB_AUTH_STATE, "handle", "Invalid"),
        *(rte_row(fn) for fn in MB_FUNCTIONS),
    ]
    stats = _ingest(rows, static)
    units, candidates = L.load_state()
    backdoor = units["prog.c#backdoor::l4_auth_state"]
    emit = units["prog.c#emit::l5_sanitized"]
    for unit, name in ((backdoor, MB_AUTH_STATE), (emit, MB_SANITIZED)):
        assert unit["status"] == "candidate", unit
        assert unit["bookkeeping"]["eva_verdicts"] == {MB_MODULE: "invalid"}
        assert unit["evidence"][-1]["result"] == "eva_meta_invalid" and not unit["evidence"][-1]["discharging"]
        assert name in unit["evidence"][-1]["summary"]
    assert stats["candidates"] == 2 and len(candidates) == 2
    linked = sorted(cid for c in candidates.values() for cid in c["linked_units"])
    assert linked == ["prog.c#backdoor::l4_auth_state", "prog.c#emit::l5_sanitized"]
    # The units the correct rows speak for are covered; no other unit heard of the two rows above.
    assert units["prog.c#handle::l4_auth_required"]["status"] == "covered"
    assert units["prog.c#get_level::l4_auth_state"]["status"] == "covered"
    for cid, unit in units.items():
        if cid.endswith("::rte"):
            assert unit["status"] == "covered" and unit["bookkeeping"]["eva_verdicts"] == {MB_MODULE: "valid"}, cid
            assert not unit["result_fingerprints"], cid
    assert not L.validate_ledger(list(units.values()))


@pytest.mark.unit
@pytest.mark.parametrize(
    ("status", "verdict", "result"),
    [
        ("Unknown", "unknown", "eva_meta_unknown"),
        ("Dead", "dead", "eva_meta_dead"),
        ("Inconsistent", "other", "eva_meta_unclassified"),
    ],
)
def test_a_check_eva_does_not_prove_leaves_the_unit_to_wp(ledger_run, status, verdict, result):
    static = ledger_run
    rows = [r for r in _correct_rows(static) if r["function"] != "emit" or r["kind"] != "user check"]
    stats = _ingest([*rows, meta_row(static, MB_SANITIZED, "emit", status)], static)
    unit = _units()["prog.c#emit::l5_sanitized"]
    assert unit["status"] == "planned" and unit["bookkeeping"]["eva_verdicts"] == {MB_MODULE: verdict}
    assert unit["evidence"][-1]["result"] == result and not unit["evidence"][-1]["discharging"]
    assert stats["candidates"] == 0
    # The check is the property's: emit's RTE unit is covered whatever its status.
    assert _units()["prog.c#emit::rte"]["status"] == "covered"


@pytest.mark.unit
def test_a_later_blocking_verdict_withdraws_an_eva_only_cover(ledger_run):
    static = ledger_run
    _ingest(_correct_rows(static), static)
    assert _units()["prog.c#emit::l5_sanitized"]["status"] == "covered"
    # The module's next report (a repaired harness reaching more contexts) leaves the check open.
    rows = [r for r in _correct_rows(static) if r["function"] != "emit" or r["kind"] != "user check"]
    stats = _ingest([*rows, meta_row(static, MB_SANITIZED, "emit", "Unknown")], static)
    unit = _units()["prog.c#emit::l5_sanitized"]
    assert unit["status"] == "planned" and stats["reopened"] == 1
    assert unit["evidence"][-1]["result"] == "eva_cover_withdrawn"
    assert "check of this unit's properties" in unit["evidence"][-1]["summary"]
    assert not any(a["description"].startswith("Eva result holds") for a in unit["assumptions"])
    assert _units()["prog.c#handle::l4_auth_required"]["status"] == "covered"
    # And valid again: covered again.
    _ingest(_correct_rows(static), static)
    assert _units()["prog.c#emit::l5_sanitized"]["status"] == "covered"
    assert not L.validate_ledger(list(_units().values()))


@pytest.mark.unit
def test_a_report_without_filed_rows_gives_no_verdict(ledger_run):
    static = ledger_run
    failed = {
        "props": MB_PROPS,
        "error": "Frama-C failed with the security properties loaded; this is the run without them",
        "properties": [],
    }
    report = {"status": "ok", "module": MB_MODULE, "sources": list(MB_SOURCES), "reduced_checks": []}
    report.update(rs.summarize_rows([rte_row(fn) for fn in MB_FUNCTIONS]))
    for section in (failed, {"props": MB_PROPS, "properties": [], "meta_file": None}):
        write_json(Path(MB_EVA_REPORT), {**report, "security_props": section})
        stats = L.cmd_ingest_eva([Path(MB_EVA_REPORT)])
        assert "meta_units" not in stats
        unit = _units()["prog.c#emit::l5_sanitized"]
        assert unit["status"] == "planned" and not unit["evidence"]
    # A valid section after a cover, then a report that lost it: the module's verdict goes with it.
    _ingest(_correct_rows(static), static)
    assert _units()["prog.c#emit::l5_sanitized"]["status"] == "covered"
    write_json(Path(MB_EVA_REPORT), {**report, "security_props": failed})
    L.cmd_ingest_eva([Path(MB_EVA_REPORT)])
    unit = _units()["prog.c#emit::l5_sanitized"]
    assert unit["status"] == "planned" and unit["evidence"][-1]["result"] == "eva_cover_withdrawn"


@pytest.mark.unit
def test_a_metacsl_row_in_the_status_lists_is_no_rte_verdict(ledger_run):
    """Defensive: a report whose writer left MetAcsl's rows in the status lists (not run_eva_slice.py)."""
    static = ledger_run
    rows = [*_correct_rows(static)[:2], meta_row(static, MB_SANITIZED, "emit", "Unknown"), rte_row("emit")]
    report = {"status": "ok", "module": MB_MODULE, "sources": list(MB_SOURCES), "reduced_checks": []}
    report.update(rs.summarize_rows(rows))
    report["security_props"] = rs.summarize_report(rows, static)["security_props"]
    assert report["surviving_unknown_functions"] == ["emit"]
    write_json(Path(MB_EVA_REPORT), report)
    L.cmd_ingest_eva([Path(MB_EVA_REPORT)])
    units = _units()
    assert units["prog.c#emit::rte"]["bookkeeping"]["eva_verdicts"] == {MB_MODULE: "valid"}
    assert units["prog.c#emit::rte"]["status"] == "covered"
    assert units["prog.c#emit::l5_sanitized"]["bookkeeping"]["eva_verdicts"] == {MB_MODULE: "unknown"}


@pytest.mark.unit
def test_an_open_taint_check_or_a_decided_violation_bars_the_cover(ledger_run):
    static = ledger_run
    ledger = json.loads(Path("coverage-ledger.json").read_text(encoding="utf-8"))
    for unit in ledger:
        if unit["coverage_id"] == "prog.c#emit::l5_sanitized":
            unit.setdefault("bookkeeping", {})["eva_taint"] = {"another_module": "unknown"}
    write_json(Path("coverage-ledger.json"), ledger)
    _ingest(_correct_rows(static), static)
    units = _units()
    emit = units["prog.c#emit::l5_sanitized"]
    assert emit["status"] != "covered" and emit["bookkeeping"]["eva_verdicts"] == {MB_MODULE: "valid"}
    assert units["prog.c#handle::l4_auth_required"]["status"] == "covered"


def _wp_report(function: str, properties: list[str]) -> Path:
    """A WP run of `function` that ended all_proven with RTE goals only: no goal of an L4-L6 class."""
    report = json.loads((ROOT / "tests/fixtures/security_props/wp_close_wiped.json").read_text(encoding="utf-8"))
    report.update(function=function, file="prog.c", layer_goals=[], total_goals=4, proven_count=4)
    report["by_obligation_class"] = {"rte": {"proven": 4, "proven_under_hyp": 0, "unproven": 0}}
    report["frame_summary"]["l3_frame_goals"] = {"proven": 0, "proven_under_hyp": 0, "unproven": 0}
    report["security_props"] = {
        "props": MB_PROPS,
        "function_id": f"prog.c#{function}",
        "properties": properties,
        "extra_sources": [],
    }
    report["limits"]["unchecked_layer_clauses"] = []
    path = Path(f"workspace/reports/wp/{function}.json")
    write_json(path, report)
    return path


@pytest.mark.unit
@pytest.mark.parametrize("loaded", [[], [MB_SANITIZED]], ids=["not_loaded", "simplified"])
def test_ingest_wp_keeps_an_eva_verdict_it_has_no_goal_for(ledger_run, loaded):
    static = ledger_run
    # Covered by Eva: a WP run of the function without a goal of the class leaves it covered.
    _ingest(_correct_rows(static), static)
    L.cmd_ingest_wp([_wp_report("emit", loaded)])
    unit = _units()["prog.c#emit::l5_sanitized"]
    assert unit["status"] == "covered", unit["evidence"][-1]
    assert unit["bookkeeping"]["eva_verdicts"] == {MB_MODULE: "valid"}
    assert any(e["result"] == "eva_meta_valid" for e in unit["evidence"])
    # Invalid under Eva: the candidate stays one, whatever the WP run says.
    rows = [r for r in _correct_rows(static) if r["function"] != "emit" or r["kind"] != "user check"]
    _ingest([*rows, meta_row(static, MB_SANITIZED, "emit", "Invalid")], static)
    assert _units()["prog.c#emit::l5_sanitized"]["status"] == "candidate"
    L.cmd_ingest_wp([_wp_report("emit", loaded)])
    unit = _units()["prog.c#emit::l5_sanitized"]
    assert unit["status"] == "candidate" and unit["bookkeeping"]["eva_verdicts"] == {MB_MODULE: "invalid"}
    assert not L.validate_ledger(list(_units().values()))


# ---------------------------------------------------------------------------------------------------
# Acceptance (Docker): the fixture under Frama-C, then the ledger
# ---------------------------------------------------------------------------------------------------

MB_ACCEPTANCE = {
    # variant: (build command, extra cppflags of the Eva run)
    "correct": ("make", ""),
    "violate": ("make DEFS=-DVIOLATE", " -DVIOLATE"),
    "harness_direct": ("make", " -DHARNESS_DIRECT"),
}


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize("variant", sorted(MB_ACCEPTANCE))
def test_acceptance_in_the_image(model_run, tmp_path, monkeypatch, variant):  # noqa: F811
    """
    Plan acceptance: with `eva` in `meta_engines`, the planted L4 write and the uninitialized sink byte
    end as blocking verdicts on their units, the correct program's units are covered by Eva evidence,
    and a precondition failure the harness induces touches no unit.
    """
    build, defs = MB_ACCEPTANCE[variant]
    target = MB_FIXTURES / "target"
    run = tmp_path / "run"
    model = model_run(target, run, build)
    assert model["status"] == "ok", model.get("error")
    doc = sp.generate(model, trust.load_threat_model(target / "THREAT_MODEL.md"))
    assert not sp.validate(doc)
    doc["meta_engines"] = ["eva"]
    for name in ("prog.c", "prog.h"):
        (run / "workspace/work").mkdir(parents=True, exist_ok=True)
        shutil.copy(target / name, run / "workspace/work" / name)
    (run / "workspace/harnesses").mkdir(parents=True, exist_ok=True)
    shutil.copy(MB_FIXTURES / "harness_prog.c", run / "workspace/harnesses/harness_prog.c")
    write_json(run / MB_PROPS, doc)
    cmd = [
        "docker", "run", "--rm", "--network", "none", "--entrypoint", "sh",
        "-v", f"{run.resolve()}:/framac-run", "-w", "/framac-run",
        "-v", f"{ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
        "-v", f"{ROOT / 'schemas'}:/opt/framac-pipeline/schemas:ro",
        "-v", f"{ROOT / 'templates'}:/opt/framac-pipeline/templates:ro",
        "-e", "FRAMAC_CACHE=off",
        ANALYSIS_IMAGE, "-c",
        f"python3 /opt/framac-pipeline/scripts/run_eva_slice.py --module {MB_MODULE} --sources {' '.join(MB_SOURCES)} "
        f"--main eva_main --out-dir workspace/eva/prog --out-json {MB_EVA_REPORT} --timeout 300 "
        f"--no-warn-unsigned-downcast '--cppflags=-Iworkspace/work{defs}'",
    ]  # fmt: skip
    res = subprocess.run(
        cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900, check=False
    )
    assert res.returncode == 0, res.stdout + res.stderr
    report = json.loads((run / MB_EVA_REPORT).read_text(encoding="utf-8"))
    assert report["status"] == "ok", report.get("error_summary")
    section = report["security_props"]
    assert "error" not in section and section["meta_file"], section
    log = (run / "workspace/eva/prog/eva.log").read_text(encoding="utf-8", errors="replace")
    assert "[meta] Successful translation" in log
    # The flows step read the saved session without running Eva again on a project without the checks.
    flows_log = run / "workspace/eva/prog/flows.log"
    assert "Analyzing a complete application" not in flows_log.read_text(encoding="utf-8", errors="replace")
    # MetAcsl's rows are in the section only.
    assert report["invalid_alarms"] == [] and not any(
        "meta" in str(r.get("annotation")) for rows in report["unknown_obligations_by_function"].values() for r in rows
    )
    assert section["unplanned_instances"] == [], section["unplanned_instances"]

    monkeypatch.chdir(run)
    _seed(run, doc, tuple(f["name"] for f in model["functions"].values()))
    stats = L.cmd_ingest_eva([run / MB_EVA_REPORT])
    units, candidates = L.load_state()
    detail = json.dumps({"section": section, "stats": stats}, indent=1)
    status = {cid: u["status"] for cid, u in units.items() if u["obligation_class"] in L.METACSL_CLASSES}
    covered = {"prog.c#handle::l4_auth_required": "covered", "prog.c#get_level::l4_auth_state": "covered"}
    if variant == "violate":
        assert status == {
            **covered,
            "prog.c#backdoor::l4_auth_state": "candidate",
            "prog.c#emit::l5_sanitized": "candidate",
        }, detail
        linked = sorted(cid for c in candidates.values() for cid in c["linked_units"])
        assert linked == ["prog.c#backdoor::l4_auth_state", "prog.c#emit::l5_sanitized"], detail
        assert units["prog.c#emit::l5_sanitized"]["evidence"][-1]["result"] == "eva_meta_invalid"
        assert "\\initialized" in units["prog.c#emit::l5_sanitized"]["evidence"][-1]["summary"]
    else:
        assert status == {**covered, "prog.c#emit::l5_sanitized": "covered"}, detail
        assert candidates == {}, detail
        for cid in status:
            assert units[cid]["evidence"][-1]["result"] == "eva_meta_valid", units[cid]
    outside = [(e["property"], e["function"], e["invalid"]) for e in section["outside_instances"] if e["invalid"]]
    if variant == "harness_direct":
        # eva_main calls admin before the gate: Invalid at that call, listed, and no unit hears of it.
        assert outside == [(MB_AUTH_REQUIRED, "eva_main", 1)], detail
        assert any(r["role"] == "outside" and r["file"] == "harness_prog.c" for r in section["open_rows"])
        assert all(not u["result_fingerprints"] for u in units.values()), detail
    else:
        assert outside == [], detail
    assert not L.validate_ledger(list(units.values()))
