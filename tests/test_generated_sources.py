"""
C sources the target's build generates (nginx's `./configure` writes objs/ngx_modules.c), unit side.

nginx 1.31.9 run-3 (2026-11-19) stopped at Phase 0 `build-check`: link repair added
`workspace/work/objs/ngx_modules.c` from the DAG, a file the build generated in the scratch tree. The
snapshot kept only generated headers, the overlay is a copy of the read-only target, and the scratch
volume is gone after Phase 0, so E-ACSL failed with `source file 'workspace/work/objs/ngx_modules.c'
does not exist` and clang with `no such file or directory`.

Here: the capture keeps the generated sources in the snapshot (digest and manifest), installs them in
the overlay's baseline/ and work/ at their tree path, overlay init does the same from an existing
snapshot, apply-in-place never writes one into the target, link repair never adds a file that does not
exist (and names the Phase 0 step that should have kept it), and the build keeps every attempt's
failure. The Docker side is tests/test_generated_sources_docker.py.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import build_capture as bc
import fuzz_build
import run_eacsl_fuzz as R
import target_env
import workspace_overlay as wo

_GEN_C = "gen/modules.c"
_GEN_TEXT = "int gen_modules[] = { 1, 2, 3 };\nint gen_module_count(void) { return 3; }\n"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tree_and_target(tmp_path: Path) -> tuple[Path, Path]:
    """A target with main.c only, and the build tree after the build: main.c plus the generated gen/modules.c."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    tree = tmp_path / "tree"
    (tree / "gen").mkdir(parents=True)
    (tree / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    (tree / _GEN_C).write_bytes(_GEN_TEXT.encode())  # bytes: no CRLF on a Windows host
    return tree, target


# ------------------------------------------------------------------------------ capture and snapshot


@pytest.mark.unit
def test_generated_sources_are_compiled_sources_only_the_build_tree_has(tmp_path):
    tree, target = _tree_and_target(tmp_path)
    compiles = [
        {"source": "main.c"},  # in the target
        {"source": _GEN_C},  # generated, still in the tree
        {"source": "parse.c"},  # generated and deleted by the build (a yacc output)
        {"source": "/usr/share/foo/extra.c"},  # outside the tree
        {"source": "../outside.c"},
        {"source": _GEN_C},  # compiled twice: listed once
    ]
    kept, gone = bc.generated_sources(compiles, target, tree)
    assert kept == [_GEN_C]
    assert gone == ["parse.c"]


@pytest.mark.unit
def test_the_snapshot_keeps_generated_sources_with_their_digest(tmp_path):
    tree, _ = _tree_and_target(tmp_path)
    snap = tmp_path / "run" / "workspace" / "snapshot"
    plain = bc.export_snapshot(snap, {})
    summary = bc.export_snapshot(snap, {}, sources={_GEN_C: tree / _GEN_C})
    assert (snap / "generated" / _GEN_C).read_text(encoding="utf-8") == _GEN_TEXT
    manifest = target_env._manifest(snap)
    assert manifest["generated_sources"] == {_GEN_C: _sha(_GEN_TEXT.encode())}
    # Not an include directory: only the headers' directories are searched.
    assert "generated_dirs" not in manifest
    assert summary["digest"] != plain["digest"]
    assert summary["files"] == 1 and summary["generated_sources"] == 1
    want = hashlib.sha256(f"generated/{_GEN_C}\0{_sha(_GEN_TEXT.encode())}\n".encode()).hexdigest()
    assert summary["digest"] == want
    assert target_env.generated_source_paths(snap) == {_GEN_C: _sha(_GEN_TEXT.encode())}


@pytest.mark.unit
def test_a_snapshot_without_generated_sources_keeps_its_digest_and_manifest(tmp_path):
    """Requirement 4: a target whose build generates headers only (or nothing) gets the digest it always had."""
    tree = tmp_path / "tree"
    (tree / "build").mkdir(parents=True)
    (tree / "build/config.h").write_bytes(b"#define X 1\n")
    snap = tmp_path / "snap"
    summary = bc.export_snapshot(snap, {}, {"build/config.h": tree / "build/config.h"}, ["build"])
    material = f"generated/build/config.h\0{_sha(b'#define X 1' + bytes([10]))}\n"
    assert summary == {"digest": hashlib.sha256(material.encode()).hexdigest(), "files": 1, "generated": 1}
    assert set(target_env._manifest(snap)) == {"digest", "files", "generated", "generated_dirs"}
    assert bc.export_snapshot(snap, {}, sources={})["digest"] == bc.export_snapshot(snap, {})["digest"]


# ------------------------------------------------------------------------------ the overlay


def _overlay(tmp_path: Path) -> Path:
    """An initialized overlay of the target (main.c) and a snapshot holding the generated gen/modules.c."""
    tree, target = _tree_and_target(tmp_path)
    overlay = tmp_path / "run" / "workspace"
    wo.init_overlay(target, overlay)
    bc.export_snapshot(overlay / "snapshot", {}, sources={_GEN_C: tree / _GEN_C})
    return overlay


@pytest.mark.unit
def test_generated_sources_are_installed_in_work_and_baseline(tmp_path):
    overlay = _overlay(tmp_path)
    assert not (overlay / "work" / _GEN_C).exists()
    out = target_env.install_generated_sources(overlay)
    assert out["installed"] == [_GEN_C]
    for side in ("work", "baseline"):
        assert (overlay / side / _GEN_C).read_text(encoding="utf-8") == _GEN_TEXT
    meta = json.loads((overlay / "overlay_meta.json").read_text(encoding="utf-8"))
    assert meta["generated_sources"] == {_GEN_C: _sha(_GEN_TEXT.encode())}
    # Idempotent.
    again = target_env.install_generated_sources(overlay)
    assert again["installed"] == [] and again["current"] == [_GEN_C]


@pytest.mark.unit
def test_an_annotated_generated_source_is_left_alone(tmp_path):
    overlay = _overlay(tmp_path)
    target_env.install_generated_sources(overlay)
    annotated = "/*@ requires \\true; */\n" + _GEN_TEXT
    (overlay / "work" / _GEN_C).write_text(annotated, encoding="utf-8")
    out = target_env.install_generated_sources(overlay)
    assert out["annotated"] == [_GEN_C] and out["installed"] == []
    assert (overlay / "work" / _GEN_C).read_text(encoding="utf-8") == annotated


@pytest.mark.unit
def test_without_an_overlay_or_a_snapshot_nothing_is_installed(tmp_path):
    tree, _ = _tree_and_target(tmp_path)
    workspace = tmp_path / "ws"
    bc.export_snapshot(workspace / "snapshot", {}, sources={_GEN_C: tree / _GEN_C})
    assert target_env.install_generated_sources(workspace)["installed"] == []
    assert not (workspace / "work").exists()
    assert target_env.install_generated_sources(tmp_path / "nothing")["installed"] == []


@pytest.mark.unit
def test_overlay_init_installs_the_generated_sources_of_an_existing_snapshot(tmp_path):
    overlay = _overlay(tmp_path)
    meta = wo.init_overlay(tmp_path / "target", overlay)
    assert (overlay / "work" / _GEN_C).is_file() and (overlay / "baseline" / _GEN_C).is_file()
    assert meta["generated_sources"] == {_GEN_C: _sha(_GEN_TEXT.encode())}


@pytest.mark.unit
def test_apply_in_place_never_writes_a_generated_source_into_the_target(tmp_path):
    overlay = _overlay(tmp_path)
    target = tmp_path / "target"
    target_env.install_generated_sources(overlay)
    (overlay / "work" / _GEN_C).write_text("/*@ ghost int g; */\n" + _GEN_TEXT, encoding="utf-8")
    out = wo.apply_in_place(overlay, target)
    assert not (target / _GEN_C).exists()
    assert out["skipped_generated"] == [_GEN_C] and out["applied_in_place"] == []


@pytest.mark.unit
def test_the_capture_installs_generated_sources_in_the_overlay(tmp_path, monkeypatch):
    """analyse() with the probes stubbed: the snapshot keeps gen/modules.c and the overlay gets it."""
    tree, target = _tree_and_target(tmp_path)
    run = tmp_path / "run"
    wo.init_overlay(target, run / "workspace")
    monkeypatch.chdir(run)
    t = tree.as_posix()
    execs = [
        {"exe": "/usr/bin/cc", "args": ["cc", "-c", "-o", "main.o", "main.c"], "cwd": t},
        {"exe": "/usr/bin/cc", "args": ["cc", "-c", "-o", "gen/modules.o", _GEN_C], "cwd": t},
        {"exe": "/usr/bin/cc", "args": ["cc", "-o", "app", "main.o", "gen/modules.o"], "cwd": t},
    ]
    symbols = {"main.c": {"main": ("T", None)}, _GEN_C: {"gen_module_count": ("T", None), "gen_modules": ("D", None)}}

    def build_snapshot(snapshot, tree_, units, system_headers, recipe, warnings, **kw):
        sources = kw.get("generated_sources") or []
        summary = bc.export_snapshot(snapshot, {}, sources={s: tree_ / s for s in sources})
        return {"files": summary["files"], "generated": {"sources": sources}}

    monkeypatch.setattr(bc, "compile_deps", lambda c, t_: ([c["object"]], None))
    monkeypatch.setattr(bc, "compile_symbols", lambda c, t_, tmp, i: (symbols[c["source"]], None))
    monkeypatch.setattr(bc, "build_snapshot", build_snapshot)
    cap = bc.classify_executions(execs, t)
    report: dict = {"warnings": [], "build": {}, "target": str(target)}
    bc.analyse(report, cap, tree, tmp_path / "scratch", {}, 60, 1)
    assert report["snapshot"]["generated"]["sources"] == [_GEN_C]
    assert (run / "workspace/work" / _GEN_C).read_text(encoding="utf-8") == _GEN_TEXT
    assert (run / "workspace/baseline" / _GEN_C).is_file()
    assert not (target / _GEN_C).exists()


# ------------------------------------------------------------------------------ link repair


def _repair_run(tmp_path: Path, *, captured: bool) -> Path:
    """nginx's shape: main.c in the overlay, `gen_module_count` defined in gen/modules.c, absent from it."""
    work = tmp_path / "workspace" / "work"
    work.mkdir(parents=True)
    (work / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    reports = tmp_path / "workspace" / "reports"
    reports.mkdir(parents=True)
    dag = {
        "functions": {
            "main.c#main": {"name": "main", "file": "main.c"},
            f"{_GEN_C}#gen_module_count": {"name": "gen_module_count", "file": _GEN_C},
        }
    }
    (reports / "callgraph_dag.json").write_text(json.dumps(dag), encoding="utf-8")
    if captured:
        capture = {"compiles": [{"source": "main.c"}, {"source": _GEN_C}]}
        (reports / "build_capture.json").write_text(json.dumps(capture), encoding="utf-8")
    return reports / "callgraph_dag.json"


@pytest.mark.unit
def test_link_repair_never_adds_a_source_that_does_not_exist(tmp_path):
    dag = _repair_run(tmp_path, captured=True)
    missing: list[dict] = []
    log = "/usr/bin/ld: main.o: undefined reference to `gen_module_count'\n"
    sources, info = fuzz_build.repair_sources_for_link(["workspace/work/main.c"], log, dag, tmp_path, missing=missing)
    assert sources == ["workspace/work/main.c"] and info == {}
    assert len(missing) == 1
    m = missing[0]
    assert (m["file"], m["path"], m["symbols"]) == (_GEN_C, f"workspace/work/{_GEN_C}", ["gen_module_count"])
    assert m["kind"] == "generated_source_missing"
    # Names the file and the Phase 0 step that should have kept it.
    assert _GEN_C in m["reason"] and "build_capture.py" in m["reason"] and "snapshot" in m["reason"]


@pytest.mark.unit
def test_link_repair_names_an_uninstalled_snapshot_copy(tmp_path):
    dag = _repair_run(tmp_path, captured=True)
    snap_file = tmp_path / "workspace" / "snapshot" / "generated" / _GEN_C
    snap_file.parent.mkdir(parents=True)
    snap_file.write_bytes(_GEN_TEXT.encode())
    manifest = {"digest": "d", "files": {}, "generated_sources": {_GEN_C: _sha(_GEN_TEXT.encode())}}
    (tmp_path / "workspace" / "snapshot" / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    missing: list[dict] = []
    fuzz_build.repair_sources_for_link(
        ["workspace/work/main.c"], "undefined reference to `gen_module_count'", dag, tmp_path, missing=missing
    )
    assert "install-generated" in missing[0]["reason"]


@pytest.mark.unit
def test_the_build_reports_the_missing_source_instead_of_compiling_it(tmp_path, monkeypatch):
    dag = _repair_run(tmp_path, captured=True)
    monkeypatch.chdir(tmp_path)
    calls: list[list[str]] = []

    def fake_sanitizer(srcs, out_bin, *a, **k):
        calls.append(list(srcs))
        assert all((tmp_path / s).is_file() for s in srcs), srcs
        return {"engine": "sanitizers", "returncode": 1, "stderr": "undefined reference to `gen_module_count'\n"}

    monkeypatch.setattr(fuzz_build, "compile_sanitizer_binary", fake_sanitizer)
    out = fuzz_build.build_module_binary(["workspace/work/main.c"], tmp_path / "bin", engine="sanitizers", dag_path=dag)
    assert out["compile"]["returncode"] == 1 and len(calls) == 1
    missing = out["link_repair"]["missing_sources"]
    assert [m["file"] for m in missing] == [_GEN_C]
    res = {"mode": "build", "status": "compile_error", "link_repair": out["link_repair"], "compile": out["compile"]}
    hints = R.derive_eacsl_diagnostic_hints(res)
    assert any(_GEN_C in h and "build_capture.py" in h for h in hints), hints


# ------------------------------------------------------------------------------ every attempt is reported


@pytest.mark.unit
def test_the_build_keeps_every_attempts_failure(tmp_path, monkeypatch):
    """
    nginx run-3: the first E-ACSL attempt was OOM-killed, link repair added files, and the report kept only
    the post-repair attempt's `eacsl_instrumentation_failed`. Each attempt's failure and logs stay visible.
    """
    dag = _repair_run(tmp_path, captured=True)
    (tmp_path / "workspace/work" / _GEN_C).parent.mkdir(parents=True)
    (tmp_path / "workspace/work" / _GEN_C).write_bytes(_GEN_TEXT.encode())
    monkeypatch.chdir(tmp_path)
    out_bin = tmp_path / "workspace/harnesses/fuzz_m"
    eacsl_results = [
        {"returncode": 137, "reason": "eacsl_instrumentation_failed", "stderr": "Killed\n"},
        {"returncode": 1, "reason": "eacsl_instrumentation_failed", "stderr": "[kernel] User Error: x\n"},
    ]

    def fake_eacsl(srcs, out, *a, **k):
        log = Path(out).with_suffix(".compile.log")
        log.parent.mkdir(parents=True, exist_ok=True)
        res = eacsl_results.pop(0)
        log.write_text(f"attempt rc={res['returncode']}\n", encoding="utf-8")
        return {"engine": "eacsl", "compile_log": str(log), **res}

    def fake_sanitizer(srcs, out, *a, **k):
        log = Path(out).with_suffix(".sanitizer_compile.log")
        log.write_text(f"sources={len(srcs)}\n", encoding="utf-8")
        linked = any(s.endswith(_GEN_C) for s in srcs)
        if linked:
            return {"engine": "sanitizers", "returncode": 0, "binary": str(out), "compile_log": str(log)}
        err = "undefined reference to `gen_module_count'\n"
        return {"engine": "sanitizers", "returncode": 1, "stderr": err, "compile_log": str(log)}

    monkeypatch.setattr(fuzz_build, "compile_eacsl_binary", fake_eacsl)
    monkeypatch.setattr(fuzz_build, "compile_sanitizer_binary", fake_sanitizer)
    monkeypatch.setattr(fuzz_build, "resolve_security_meta", lambda *a, **k: None)
    out = fuzz_build.build_module_binary(
        ["workspace/work/main.c"], out_bin, engine="auto", apply_selftest=False, dag_path=dag
    )
    assert out["compile"]["returncode"] == 0 and out["engine_used"] == "sanitizers"
    attempts = out["attempts"]
    assert [a["attempt"] for a in attempts] == [1, 2]
    assert attempts[0]["eacsl"]["returncode"] == 137 and "Killed" in attempts[0]["eacsl"]["stderr_tail"]
    assert attempts[0]["returncode"] == 1 and attempts[1]["returncode"] == 0
    assert attempts[1]["eacsl"]["returncode"] == 1
    # The first attempt's logs are kept beside the last ones.
    first_logs = [Path(p) for p in attempts[0]["logs"]]
    assert any(p.read_text(encoding="utf-8") == "attempt rc=137\n" for p in first_logs), first_logs
    assert Path(out_bin).with_suffix(".compile.log").read_text(encoding="utf-8") == "attempt rc=1\n"
