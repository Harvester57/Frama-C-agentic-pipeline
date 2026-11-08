"""
The Phase 0 recipes of templates/pipeline.mk run as written (defects 1 and 5 of
docs/phase0-downstream-effects.md): `slice-init` (the overlay), `dag` (the call-graph DAG from the
Phase 0 model) and `security-props` (the MetAcsl properties), which `seed` depends on. Each recipe's
command is taken from the template and run, so a flag a script no longer accepts fails here.
"""

from __future__ import annotations

import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "scripts"
TEMPLATE = REPO / "templates" / "pipeline.mk"

pytestmark = pytest.mark.unit


def recipe_commands(target: str) -> list[str]:
    """The logical recipe lines of `target` (backslash continuations joined)."""
    text = TEMPLATE.read_text(encoding="utf-8")
    m = re.search(rf"^{re.escape(target)}:[^\n]*\n((?:\t[^\n]*\n)+)", text, re.MULTILINE)
    assert m is not None, f"no recipe for {target}"
    body = re.sub(r"\\\n\t*", " ", m.group(1))
    return [line.strip() for line in body.splitlines() if line.strip()]


def argv_of(recipe: str, target_dir: Path) -> list[str]:
    """The command a recipe runs through $(RUN), with the Makefile variables filled in."""
    run, sep, cmd = recipe.partition(" -- ")
    assert sep and run.startswith("$(RUN) "), recipe
    out = []
    for word in shlex.split(cmd):
        if word == "$(PY)":
            out.append(sys.executable)
        elif word.startswith("$(S)/"):
            out.append(str(SCRIPTS / word[len("$(S)/") :]))
        elif word == "$(TARGET_DIR)":
            out.append(str(target_dir))
        else:
            assert "$(" not in word, f"unexpected Make variable in {recipe!r}"
            out.append(word)
    return out


def run_target(target: str, run_dir: Path, target_dir: Path) -> None:
    for recipe in recipe_commands(target):
        proc = subprocess.run(
            argv_of(recipe, target_dir), cwd=run_dir, capture_output=True, text=True, timeout=300, check=False
        )
        assert proc.returncode == 0, f"{target}: {recipe}\n{proc.stdout}\n{proc.stderr}"


def model(target_dir: Path) -> dict:
    def fn(name: str, line: int, **kw: object) -> dict:
        rec = {
            "file": "src/a.c",
            "name": name,
            "line": line,
            "end_line": line,
            "lines": 1,
            "static": False,
            "inline": False,
            "header": False,
            "loops": 0,
            "cyclomatic": 1,
            "source": "frama-c-kernel",
            "units": ["libdemo.a"],
            "signature": "int(int *)",
            "formals": [{"name": "p", "kind": "pointer"}],
            "writes": {"pointer": 1, "params": ["p"], "globals": []},
        }
        rec.update(kw)
        return rec

    return {
        "status": "ok",
        "generated_at": "2026-11-08T00:00:00Z",
        "tree": str(target_dir),
        "functions": {"src/a.c#api_set": fn("api_set", 1), "src/a.c#helper": fn("helper", 2, static=True)},
        "edges": [{"caller": "src/a.c#api_set", "callee": "src/a.c#helper", "kind": "direct", "sources": ["frama-c"]}],
        "units": {
            "libdemo.a": {
                "kind": "static_lib",
                "test": False,
                "files": ["src/a.c"],
                "entry_points": ["src/a.c#api_set"],
                "parse": {"status": "ok"},
            }
        },
        "macro_aliases": {},
        "entry_points": ["src/a.c#api_set"],
        "thread_entries": [],
        "warnings": [],
    }


def test_phase0_recipes_run_as_written(tmp_path: Path) -> None:
    target_dir = tmp_path / "target"
    (target_dir / "src").mkdir(parents=True)
    (target_dir / "src" / "a.c").write_text(
        "int helper(int *p) { *p = 1; return 0; }\nint api_set(int *p) { return helper(p); }\n", encoding="utf-8"
    )
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    run_target("slice-init", run_dir, target_dir)
    assert (run_dir / "workspace" / "work" / "src" / "a.c").is_file()

    # The build capture and the Phase 0 model run outside Make, between the overlay and the DAG.
    reports = run_dir / "workspace" / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "phase0_model.json").write_text(json.dumps(model(target_dir)), encoding="utf-8")

    run_target("dag", run_dir, target_dir)
    dag = json.loads((reports / "callgraph_dag.json").read_text(encoding="utf-8"))
    assert dag["module_kind"] == "link_unit" and set(dag["functions"]) == {"api_set", "helper"}

    run_target("security-props", run_dir, target_dir)
    props = json.loads((reports / "security_props.json").read_text(encoding="utf-8"))
    assert props["threat_model"]["status"] == "no_threat_model"
    assert any(ob["class"] == "l3_frame" for obs in props["obligations"].values() for ob in obs)


def test_seed_runs_after_the_security_properties() -> None:
    text = TEMPLATE.read_text(encoding="utf-8")
    m = re.search(r"^seed:([^\n]*)$", text, re.MULTILINE)
    assert m is not None and "security-props" in m.group(1).split()
