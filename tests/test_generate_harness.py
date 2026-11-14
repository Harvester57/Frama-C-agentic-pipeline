"""Tests for generate_harness.py CLI --record-repair standalone and combined with regeneration."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import api_harness as ah
import generate_harness as gh
import validate_artifacts as va

pytestmark = pytest.mark.unit


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def test_record_repair_standalone_behaviour_and_validation(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    src = tmp_path / "mod.c"
    src.write_text("int parse_buf(const unsigned char *p, unsigned long n) { return (int)n; }\n", encoding="utf-8")
    out_dir = tmp_path / "workspace" / "harnesses"

    assert (
        gh.main(
            [
                "--module",
                "mod",
                "--sources",
                str(src),
                "--header",
                "none",
                "--entry-fn",
                "parse_buf",
                "--out-dir",
                str(out_dir),
                "--no-auto-prelude",
            ]
        )
        == 0
    )
    capsys.readouterr()

    sidecar = out_dir / "harness_mod.json"
    assert gh.main(["--record-repair", str(sidecar), "--reason", "   "]) == 1
    err = json.loads(capsys.readouterr().out)
    assert err["ok"] is False and "--reason" in err["error"]

    assert gh.main(["--record-repair", str(tmp_path / "missing.json"), "--reason", "fix"]) == 1
    err_missing = json.loads(capsys.readouterr().out)
    assert err_missing["ok"] is False

    assert gh.main(["--record-repair", str(sidecar), "--reason", "bound length"]) == 0
    r1 = json.loads(capsys.readouterr().out)
    assert r1 == {
        "module": "mod",
        "repair_attempts": 1,
        "max_repair_attempts": 2,
        "exhausted": False,
    }
    assert list(va.validate_sidecar(json.loads(sidecar.read_text(encoding="utf-8")), "mod")) == []

    assert gh.main(["--record-repair", str(sidecar), "--reason", "null check"]) == 0
    r2 = json.loads(capsys.readouterr().out)
    assert r2["repair_attempts"] == 2 and r2["exhausted"] is True


def test_record_repair_combined_with_standard_regeneration(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    src = tmp_path / "mod.c"
    src.write_text(
        "int entry_v1(const unsigned char *p, unsigned long n) { return 0; }\n"
        "int entry_v2(const unsigned char *p, unsigned long n) { return 1; }\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "workspace" / "harnesses"
    assert (
        gh.main(
            [
                "--module",
                "mod",
                "--sources",
                str(src),
                "--header",
                "none",
                "--entry-fn",
                "entry_v1",
                "--max-size",
                "128",
                "--out-dir",
                str(out_dir),
                "--no-auto-prelude",
            ]
        )
        == 0
    )
    capsys.readouterr()

    sidecar = out_dir / "harness_mod.json"
    harness_c = out_dir / "harness_mod.c"
    assert "entry_v1(" in harness_c.read_text(encoding="utf-8")

    # Combined --record-repair + regeneration (without explicit --out-dir: inferred from sidecar path).
    rc = gh.main(
        [
            "--module",
            "mod",
            "--sources",
            str(src),
            "--header",
            "none",
            "--entry-fn",
            "entry_v2",
            "--max-size",
            "512",
            "--no-auto-prelude",
            "--record-repair",
            str(sidecar),
            "--reason",
            "switch to entry_v2 and raise max_size",
        ]
    )
    assert rc == 0
    out1 = json.loads(capsys.readouterr().out)
    assert out1["entry_fn"] == "entry_v2"
    assert out1["max_input_size"] == 512
    assert out1["repair_attempts"] == 1
    assert out1["exhausted"] is False
    assert out1["repair_recorded"]["repair_attempts"] == 1

    c_text = harness_c.read_text(encoding="utf-8")
    assert "entry_v2(" in c_text and "entry_v1(" not in c_text
    assert "#define MAX_INPUT_SIZE 512" in c_text

    meta1 = json.loads(sidecar.read_text(encoding="utf-8"))
    assert meta1["entry_fn"] == "entry_v2"
    assert meta1["max_input_size"] == 512
    assert meta1["repair_attempts"] == 1
    assert len(meta1["repair_history"]) == 1
    assert meta1["repair_history"][0]["reason"] == "switch to entry_v2 and raise max_size"
    assert list(va.validate_sidecar(meta1, "mod")) == []

    # Second combined repair succeeds and marks exhausted=True.
    rc2 = gh.main(
        [
            "--module",
            "mod",
            "--sources",
            str(src),
            "--header",
            "none",
            "--entry-fn",
            "entry_v2",
            "--max-size",
            "1024",
            "--no-auto-prelude",
            "--record-repair",
            str(sidecar),
            "--reason",
            "widen max_size again",
        ]
    )
    assert rc2 == 0
    out2 = json.loads(capsys.readouterr().out)
    assert out2["repair_attempts"] == 2 and out2["exhausted"] is True
    assert "#define MAX_INPUT_SIZE 1024" in harness_c.read_text(encoding="utf-8")

    # Third combined repair is refused once the repair cap (2) is already exhausted.
    rc3 = gh.main(
        [
            "--module",
            "mod",
            "--sources",
            str(src),
            "--header",
            "none",
            "--entry-fn",
            "entry_v1",
            "--max-size",
            "2048",
            "--no-auto-prelude",
            "--record-repair",
            str(sidecar),
            "--reason",
            "over cap attempt",
        ]
    )
    assert rc3 == 1
    err3 = json.loads(capsys.readouterr().out)
    assert err3["ok"] is False and err3["exhausted"] is True
    assert "#define MAX_INPUT_SIZE 1024" in harness_c.read_text(encoding="utf-8")
    assert json.loads(sidecar.read_text(encoding="utf-8"))["repair_attempts"] == 2


def test_record_repair_combined_with_api_regeneration_and_dispatch_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Reproduces QCBOR run-6: --api --dispatch-case ... --record-repair ... --reason ... in one call."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(ah, "probe_layouts", lambda *a, **k: None)
    monkeypatch.setattr(ah, "probe_cases", lambda *a, **k: None)

    src_dir = tmp_path / "workspace" / "work" / "src"
    src_dir.mkdir(parents=True)
    src = src_dir / "qcbor.c"
    src.write_text(
        "int qcbor_decode(const unsigned char *p, unsigned long n) { return (int)n; }\n"
        "int qcbor_custom(const unsigned char *p, unsigned long n) { return (int)n; }\n",
        encoding="utf-8",
    )
    hdr = src_dir / "qcbor.h"
    hdr.write_text(
        "int qcbor_decode(const unsigned char *p, unsigned long n);\n"
        "int qcbor_custom(const unsigned char *p, unsigned long n);\n",
        encoding="utf-8",
    )

    _write_json(
        tmp_path / "workspace" / "reports" / "callgraph_dag.json",
        {
            "module_kind": "link_unit",
            "modules": {
                "libqcbor_a": {
                    "candidate_entry_points": ["workspace/work/src/qcbor.c#qcbor_decode"],
                    "functions": ["workspace/work/src/qcbor.c#qcbor_decode"],
                }
            },
            "functions": {
                "workspace/work/src/qcbor.c#qcbor_decode": {
                    "name": "qcbor_decode",
                    "file": "workspace/work/src/qcbor.c",
                    "is_static": False,
                    "module": "libqcbor_a",
                }
            },
        },
    )
    _write_json(
        tmp_path / "workspace" / "reports" / "phase0_model.json",
        {
            "status": "ok",
            "functions": {
                "workspace/work/src/qcbor.c#qcbor_decode": {
                    "signature": "int(unsigned char *,unsigned long)",
                    "formals": [
                        {"name": "p", "kind": "const_pointer"},
                        {"name": "n", "kind": "value"},
                    ],
                }
            },
        },
    )

    assert (
        gh.main(
            [
                "--module",
                "libqcbor_a",
                "--header",
                "workspace/work/src/qcbor.h",
                "--api",
                "--no-auto-prelude",
            ]
        )
        == 0
    )
    capsys.readouterr()

    sidecar = tmp_path / "workspace" / "harnesses" / "harness_libqcbor_a.json"
    harness_c = tmp_path / "workspace" / "harnesses" / "harness_libqcbor_a.c"
    assert "qcbor_custom(" not in harness_c.read_text(encoding="utf-8")

    custom_stmt = "(void)qcbor_custom(fuzz_buf, fuzz_len);"
    rc = gh.main(
        [
            "--module",
            "libqcbor_a",
            "--header",
            "workspace/work/src/qcbor.h",
            "--api",
            "--no-auto-prelude",
            "--dispatch-case",
            custom_stmt,
            "--record-repair",
            str(sidecar),
            "--reason",
            "append custom case for skipped API function",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["api_custom"] == 1
    assert out["repair_attempts"] == 1
    assert out["repair_recorded"]["repair_attempts"] == 1
    assert custom_stmt in harness_c.read_text(encoding="utf-8")

    meta = json.loads(sidecar.read_text(encoding="utf-8"))
    assert meta["repair_attempts"] == 1
    assert meta["repair_history"][0]["reason"] == "append custom case for skipped API function"
    assert meta["dispatch_case_count"] == 2
    assert list(va.validate_sidecar(meta, "libqcbor_a")) == []
