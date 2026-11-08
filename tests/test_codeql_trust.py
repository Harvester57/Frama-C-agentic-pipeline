"""
Optional CodeQL trust facts (plan step I7): scripts/codeql_trust.py. Unit tests cover the row
parsing, the bqrs decoding and the run-metadata gate; the opt-in selftest runs the query in the
CodeQL image (framac-codeql:latest).
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import codeql_trust as C

ROOT = Path(__file__).resolve().parent.parent
TREE = "/framac-scratch/codeql/tree"


@pytest.mark.unit
def test_facts_from_rows_keeps_the_tree_and_dedups():
    rows = [
        ["parse", f"{TREE}/src/p.c", 10, "parameter", "buf", "remote", f"{TREE}/src/net.c", 4],
        ["parse", f"{TREE}/src/p.c", 10, "parameter", "buf", "remote", f"{TREE}/src/net.c", 4],
        ["main", f"{TREE}/tools/t.c", 3, "source_site", "", "local", f"{TREE}/tools/t.c", 5],
        ["memcpy", "/usr/include/string.h", 1, "parameter", "dst", "remote", f"{TREE}/src/net.c", 4],
        ["helper", f"{TREE}/src/h.c", 2, "parameter", "n", "local", "/usr/include/stdio.h", "x"],
    ]
    facts, dropped = C.facts_from_rows(rows, TREE)
    assert dropped == 1
    assert [f["function"] for f in facts] == ["src/h.c#helper", "src/p.c#parse", "tools/t.c#main"]
    by = {f["function"]: f for f in facts}
    assert by["src/p.c#parse"] == {
        "function": "src/p.c#parse",
        "kind": "parameter",
        "parameter": "buf",
        "source": {"type": "remote", "file": "src/net.c", "line": 4},
    }
    assert by["tools/t.c#main"]["parameter"] is None and by["tools/t.c#main"]["kind"] == "source_site"
    assert by["src/h.c#helper"]["source"] == {"type": "local", "file": "/usr/include/stdio.h", "line": None}
    assert C.rel_to(f"{TREE}/a.c", TREE + "/") == "a.c" and C.rel_to("/x/a.c", TREE) is None


@pytest.mark.unit
@pytest.mark.parametrize("keyed", [False, True])
def test_decode_bqrs_reads_the_select_set(monkeypatch, tmp_path, keyed):
    body = {"columns": [], "tuples": [["f", "/t/a.c", 1, {"label": "parameter"}, "p", "remote", "/t/a.c", 2]]}
    out = json.dumps({"#select": body} if keyed else body)
    monkeypatch.setattr(C, "run_tool", lambda cmd, cwd=None, timeout=600: (0, out))
    rows, err = C.decode_bqrs("codeql", tmp_path / "r.bqrs")
    assert err == "" and rows == [["f", "/t/a.c", 1, "parameter", "p", "remote", "/t/a.c", 2]]
    monkeypatch.setattr(C, "run_tool", lambda cmd, cwd=None, timeout=600: (0, "not json"))
    assert C.decode_bqrs("codeql", tmp_path / "r.bqrs")[0] == []
    monkeypatch.setattr(C, "run_tool", lambda cmd, cwd=None, timeout=600: (2, "boom"))
    assert C.decode_bqrs("codeql", tmp_path / "r.bqrs") == ([], "boom")


@pytest.mark.unit
def test_run_is_gated_by_run_metadata(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert C._metadata_gate(None) and C._metadata_gate({"codeql": {"enabled": False}})
    assert "open-source" in (C._metadata_gate({"codeql": {"enabled": True, "open_source": False}}) or "")
    assert C._metadata_gate({"codeql": {"enabled": True, "open_source": True}}) is None
    assert C.main(["run"]) == 2 and json.loads(capsys.readouterr().out)["status"] == "disabled"
    (tmp_path / "run-metadata.json").write_text(json.dumps({"codeql": {"enabled": True, "open_source": True}}))
    monkeypatch.setattr(C, "codeql_binary", lambda: None)
    assert C.main(["run"]) == 2 and json.loads(capsys.readouterr().out)["status"] == "codeql_missing"
    monkeypatch.setattr(C, "codeql_binary", lambda: "/opt/codeql/codeql")
    assert C.main(["run"]) == 2 and json.loads(capsys.readouterr().out)["status"] == "no_recipe"
    assert not (tmp_path / "workspace").exists()


@pytest.mark.unit
def test_query_pack_is_shipped():
    pack = C.query_pack_dir()
    assert pack is not None and (pack / C.QUERY_NAME).is_file() and (pack / "qlpack.yml").is_file()
    assert "codeql/cpp-all" in (pack / "qlpack.yml").read_text(encoding="utf-8")


@pytest.mark.integration
@pytest.mark.slow
def test_selftest_in_the_codeql_image():
    if os.environ.get("FRAMAC_DOCKER_TESTS") != "1":
        pytest.skip("Docker-backed test: set FRAMAC_DOCKER_TESTS=1")
    if not shutil.which("docker"):
        pytest.skip("docker not found")
    image = "framac-codeql:latest"
    if subprocess.run(["docker", "image", "inspect", image], capture_output=True, check=False).returncode:
        pytest.skip(f"image {image} not built (wrappers: -CodeQL -BuildIfMissing, needs the network once)")
    proc = subprocess.run(
        ["docker", "run", "--rm", "--network", "none",
         "-v", f"{ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
         "-v", f"{ROOT / 'templates'}:/opt/framac-pipeline/templates:ro",
         "--entrypoint", "sh", image, "-c", "python3 /opt/framac-pipeline/scripts/codeql_trust.py selftest"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1800, check=False,
    )  # fmt: skip
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert json.loads(proc.stdout)["ok"] is True


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
