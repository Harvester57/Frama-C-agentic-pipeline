"""
`generate_harness.py --record-repair <sidecar> --reason ... <generation flags>` rolls back on any failure:
whatever stage fails, the harness directory is byte for byte as before and no repair attempt is consumed.
Each test injects one failure through `main()` and compares the whole directory.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import api_harness as ah
import generate_harness as gh
from framac_common import ArtifactError

pytestmark = pytest.mark.unit


def _snapshot(d: Path) -> dict[str, bytes]:
    return {p.relative_to(d).as_posix(): p.read_bytes() for p in sorted(d.rglob("*")) if p.is_file()}


def _std_setup(tmp_path: Path, capsys) -> tuple[Path, list[str]]:
    src = tmp_path / "mod.c"
    src.write_text(
        "int entry_v1(const unsigned char *p, unsigned long n) { return 0; }\n"
        "int entry_v2(const unsigned char *p, unsigned long n) { return 1; }\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "workspace" / "harnesses"
    base = ["--module", "mod", "--sources", str(src), "--header", "none", "--no-auto-prelude"]
    assert gh.main([*base, "--entry-fn", "entry_v1", "--out-dir", str(out_dir)]) == 0
    capsys.readouterr()
    repair = [*base, "--entry-fn", "entry_v2", "--record-repair", str(out_dir / "harness_mod.json"), "--reason", "r"]
    return out_dir, repair


def _fail_on_write_sidecar(monkeypatch, nth: int, exc: BaseException, when: Callable[[dict], bool] | None = None):
    """Make the `nth` call of write_sidecar (1-based) raise `exc` after writing, or the first one `when` accepts."""
    real = gh.write_sidecar
    calls = {"n": 0}

    def fake(path: Path, sidecar: dict[str, Any]) -> dict[str, Any]:
        calls["n"] += 1
        out = real(path, sidecar)
        if (when is not None and when(sidecar)) or (when is None and calls["n"] == nth):
            raise exc
        return out

    monkeypatch.setattr(gh, "write_sidecar", fake)
    return calls


def _assert_rolled_back(out_dir: Path, before: dict[str, bytes]) -> None:
    assert _snapshot(out_dir) == before
    meta = json.loads((out_dir / "harness_mod.json").read_text(encoding="utf-8")) if (
        out_dir / "harness_mod.json"
    ).is_file() else None
    if meta is not None:
        assert meta.get("repair_attempts", 0) == 0


def test_oserror_writing_the_harness_c_rolls_back(tmp_path, monkeypatch, capsys):
    out_dir, repair = _std_setup(tmp_path, capsys)
    before = _snapshot(out_dir)
    real_write_text = Path.write_text

    def fake_write_text(self: Path, *a: Any, **k: Any) -> int:
        if self.name == "harness_mod.c":
            raise PermissionError(13, "Permission denied", str(self))
        return real_write_text(self, *a, **k)

    monkeypatch.setattr(Path, "write_text", fake_write_text)
    assert gh.main(repair) == 1
    err = json.loads(capsys.readouterr().out)
    assert err["ok"] is False and "Permission denied" in err["error"]
    _assert_rolled_back(out_dir, before)


def test_artifact_error_during_generation_rolls_back(tmp_path, monkeypatch, capsys):
    out_dir, repair = _std_setup(tmp_path, capsys)
    before = _snapshot(out_dir)

    def boom(*a: Any, **k: Any) -> Any:
        raise ArtifactError("unreadable DAG")

    monkeypatch.setattr(gh, "_merge_dag_harness_sources", boom)
    assert gh.main(repair) == 1
    assert "unreadable DAG" in json.loads(capsys.readouterr().out)["error"]
    _assert_rolled_back(out_dir, before)


def test_value_error_after_the_new_sidecar_is_written_rolls_back(tmp_path, monkeypatch, capsys):
    # Call 1 records the attempt, call 2 is the regenerated sidecar: both files are new when it fails.
    out_dir, repair = _std_setup(tmp_path, capsys)
    before = _snapshot(out_dir)
    calls = _fail_on_write_sidecar(monkeypatch, 2, ValueError("unresolved identifiers after prelude"))
    assert gh.main(repair) == 1
    assert calls["n"] == 2
    assert "unresolved identifiers" in json.loads(capsys.readouterr().out)["error"]
    _assert_rolled_back(out_dir, before)


def test_unexpected_exception_rolls_back_and_reports(tmp_path, monkeypatch, capsys):
    out_dir, repair = _std_setup(tmp_path, capsys)
    before = _snapshot(out_dir)
    _fail_on_write_sidecar(monkeypatch, 2, RuntimeError("disk full"))
    assert gh.main(repair) == 1
    assert "disk full" in json.loads(capsys.readouterr().out)["error"]
    _assert_rolled_back(out_dir, before)


@pytest.mark.parametrize("exc", [SystemExit(2), KeyboardInterrupt()])
def test_exit_or_interrupt_rolls_back_and_propagates(tmp_path, monkeypatch, capsys, exc):
    out_dir, repair = _std_setup(tmp_path, capsys)
    before = _snapshot(out_dir)
    _fail_on_write_sidecar(monkeypatch, 2, exc)
    with pytest.raises(type(exc)):
        gh.main(repair)
    _assert_rolled_back(out_dir, before)


def test_failure_in_the_attempt_write_itself_rolls_back(tmp_path, monkeypatch, capsys):
    out_dir, repair = _std_setup(tmp_path, capsys)
    before = _snapshot(out_dir)
    _fail_on_write_sidecar(monkeypatch, 1, OSError(28, "No space left on device"))
    assert gh.main(repair) == 1
    _assert_rolled_back(out_dir, before)


def test_a_successful_repair_still_records_the_attempt(tmp_path, capsys):
    out_dir, repair = _std_setup(tmp_path, capsys)
    assert gh.main(repair) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["repair_attempts"] == 1
    assert "entry_v2(" in (out_dir / "harness_mod.c").read_text(encoding="utf-8")


def test_without_record_repair_unexpected_errors_still_propagate(tmp_path, monkeypatch, capsys):
    out_dir, repair = _std_setup(tmp_path, capsys)
    _fail_on_write_sidecar(monkeypatch, 1, RuntimeError("disk full"))
    with pytest.raises(RuntimeError, match="disk full"):
        gh.main([a for a in repair if a not in ("--record-repair", str(out_dir / "harness_mod.json"), "--reason", "r")])


# --- --api ------------------------------------------------------------------------------------------


def _api_setup(tmp_path: Path, monkeypatch, capsys) -> tuple[Path, list[str]]:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(ah, "probe_layouts", lambda *a, **k: None)
    src_dir = tmp_path / "workspace" / "work" / "src"
    src_dir.mkdir(parents=True)
    (src_dir / "lib.c").write_text("int lib_decode(const unsigned char *p, unsigned long n) { return (int)n; }\n")
    (src_dir / "lib.h").write_text("int lib_decode(const unsigned char *p, unsigned long n);\n")
    key = "workspace/work/src/lib.c#lib_decode"
    reports = tmp_path / "workspace" / "reports"
    reports.mkdir(parents=True)
    (reports / "callgraph_dag.json").write_text(
        json.dumps(
            {
                "module_kind": "link_unit",
                "modules": {"mod": {"candidate_entry_points": [key], "functions": [key]}},
                "functions": {
                    key: {"name": "lib_decode", "file": "workspace/work/src/lib.c", "is_static": False, "module": "mod"}
                },
            }
        )
    )
    (reports / "phase0_model.json").write_text(
        json.dumps(
            {
                "status": "ok",
                "functions": {
                    key: {
                        "signature": "int(unsigned char *,unsigned long)",
                        "formals": [{"name": "p", "kind": "const_pointer"}, {"name": "n", "kind": "value"}],
                    }
                },
            }
        )
    )
    monkeypatch.setattr(ah, "probe_cases", lambda *a, **k: None)
    base = ["--module", "mod", "--header", "workspace/work/src/lib.h", "--api", "--no-auto-prelude"]
    assert gh.main(base) == 0
    capsys.readouterr()
    sidecar = tmp_path / "workspace" / "harnesses" / "harness_mod.json"
    repair = [*base, "--dispatch-case", "(void)lib_decode(fuzz_buf, 0);", "--record-repair", str(sidecar), "--reason", "r"]
    return sidecar.parent, repair


def test_api_probe_failure_rolls_back(tmp_path, monkeypatch, capsys):
    out_dir, repair = _api_setup(tmp_path, monkeypatch, capsys)
    before = _snapshot(out_dir)

    def probe(*a: Any, **k: Any) -> Any:
        raise OSError("clang vanished")

    monkeypatch.setattr(ah, "probe_cases", probe)
    assert gh.main(repair) == 1
    assert "clang vanished" in json.loads(capsys.readouterr().out)["error"]
    _assert_rolled_back(out_dir, before)


def test_api_final_sidecar_write_failure_rolls_back(tmp_path, monkeypatch, capsys):
    out_dir, repair = _api_setup(tmp_path, monkeypatch, capsys)
    before = _snapshot(out_dir)
    # Call 1 records the attempt, call 2 is generate_module_harness's sidecar, call 3 api_harness's final one.
    calls = _fail_on_write_sidecar(monkeypatch, 3, OSError("read-only"))
    assert gh.main(repair) == 1
    assert calls["n"] == 3
    _assert_rolled_back(out_dir, before)
