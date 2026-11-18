"""
Brief gaps: the stub author brief's wrapper invocation, the shared "How to run commands" block's Docker rules, and the
prover brief's guardrail cases (outside_checked_functions, excluded_inputs, mutations_skipped, a pass on no real input).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import function_facts
import stub_gen
from conftest import ROOT, write_json
from framac_common import STUB_REPORT_REL

_STUB_HEADER = "workspace/stubs/mylib/mylib.h"
_STUB_REPORT = {
    "headers": {
        _STUB_HEADER: {
            "include_name": "mylib/mylib.h",
            "real": "/usr/include/mylib/mylib.h",
            "functions": {
                "ml_hash": {"state": "draft", "callers": ["src/a.c#f"]},
                "ml_free": {"state": "filled", "callers": []},
            },
        }
    }
}
_HOST_ENV = {
    "FRAMAC_TARGET_HOST": "C:/src/target",
    "FRAMAC_RUN_HOST": "C:/Users/u/framac-pipeline/demo/run-1",
    "FRAMAC_REFERENCES_HOST": "C:\\pipe\\frama-c/docs/references",
}
_BRIEF_KEYS = (
    "header",
    "include_name",
    "real_header",
    "functions",
    "callers",
    "agent_id",
    "target_dir",
    "run_dir",
    "pipeline_dir",
    "references_dir",
)
_PROVER_BRIEF = ROOT / "skills" / "framac-wp" / "prover_brief.md"
_RUN_COMMANDS = ROOT / "skills" / "framac-wp" / "run_commands.md"


def _unreplaced(text: str) -> list[str]:
    return re.findall(r"\{(" + "|".join(_BRIEF_KEYS) + r")\}", text)


def _render_stub_brief(capsys, *args: str) -> str:
    write_json(Path(STUB_REPORT_REL), _STUB_REPORT)
    assert stub_gen.main(["brief", "--header", _STUB_HEADER, *args]) == 0
    return capsys.readouterr().out


@pytest.mark.unit
def test_stub_brief_gives_the_wrapper_invocation_with_host_paths(run_dir, monkeypatch, capsys):
    for key, value in _HOST_ENV.items():
        monkeypatch.setenv(key, value)
    brief = _render_stub_brief(capsys)
    aid = "stub-mylib_mylib_h"
    ps1 = (
        'C:\\pipe\\frama-c/wrappers/framac-docker.ps1" -TargetDir "C:/src/target" '
        '-RunDir "C:/Users/u/framac-pipeline/demo/run-1"'
    )
    sh = (
        'C:\\pipe\\frama-c/wrappers/framac-docker.sh" --target "C:/src/target" '
        '--run-dir "C:/Users/u/framac-pipeline/demo/run-1"'
    )
    assert ps1 in brief and sh in brief
    assert f'-ScriptFile "C:/Users/u/framac-pipeline/demo/run-1/agents/{aid}/scratch/cmd.sh"' in brief
    assert "## How to run commands" in brief and "<!-- run-commands -->" not in brief
    # Host path for the edit, container-relative path in the commands.
    assert f"`C:/Users/u/framac-pipeline/demo/run-1/{_STUB_HEADER}`" in brief
    assert f"agents/{aid}/result.json" in brief and "<your agent id>" not in brief
    assert "from `/framac-run`" not in brief
    assert "ml_hash" in brief and "src/a.c#f" in brief
    assert not _unreplaced(brief), _unreplaced(brief)
    container = next(line for line in brief.splitlines() if "container path" in line)
    assert "/framac-run" in container and "/opt/framac-pipeline" in container
    assert (run_dir / "agents" / aid / "scratch").is_dir()


@pytest.mark.unit
def test_stub_brief_falls_back_to_run_metadata_for_host_paths(run_dir, monkeypatch, capsys):
    for key in ("FRAMAC_TARGET_HOST", "FRAMAC_RUN_HOST"):
        monkeypatch.delenv(key, raising=False)
    write_json(run_dir / "run-metadata.json", {"target": "D:/t/lib", "run_dir_host": "D:/runs/lib/run-2"})
    brief = _render_stub_brief(capsys, "--agent-id", "stub-a1")
    assert '-TargetDir "D:/t/lib" -RunDir "D:/runs/lib/run-2"' in brief
    assert "D:/runs/lib/run-2/agents/stub-a1/scratch/cmd.sh" in brief
    assert not _unreplaced(brief)
    assert (run_dir / "agents" / "stub-a1" / "scratch").is_dir()


@pytest.mark.unit
def test_stub_brief_refuses_an_agent_id_that_is_not_a_path_component(run_dir, capsys):
    write_json(Path(STUB_REPORT_REL), _STUB_REPORT)
    with pytest.raises(SystemExit):
        stub_gen.main(["brief", "--header", _STUB_HEADER, "--agent-id", "../x"])
    assert not (run_dir / "agents").exists()


@pytest.mark.unit
@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("workspace/stubs/json-c/json.h", "stub-json-c_json_h"),
        ("workspace/stubs/zlib.h", "stub-zlib_h"),
    ],
)
def test_default_stub_agent_id_is_a_path_component(header, expected):
    assert stub_gen.default_agent_id(header) == expected
    assert re.fullmatch(r"[A-Za-z0-9_-]+", expected)


@pytest.mark.unit
def test_run_commands_block_forbids_raw_docker_and_a_zero_core_limit():
    text = _RUN_COMMANDS.read_text(encoding="utf-8")
    assert "only way to reach Docker" in text
    for cmd in ("`docker run`", "`docker exec`", "`docker inspect`", "`ulimit -c 0`"):
        assert cmd in text, cmd
    # test_robustness reads the first line naming "container path": it must stay the paths line.
    first = next(line for line in text.splitlines() if "container path" in line)
    assert "/framac-run" in first and "/opt/framac-pipeline" in first


@pytest.mark.unit
def test_prover_brief_typo_is_fixed():
    text = _PROVER_BRIEF.read_text(encoding="utf-8")
    assert "return_only" not in text and "to return only a single JSON result" in text


@pytest.mark.unit
def test_prover_brief_explains_the_guardrail_cases_the_script_reports():
    text = _PROVER_BRIEF.read_text(encoding="utf-8")
    script = (ROOT / "scripts" / "run_eacsl_fuzz.py").read_text(encoding="utf-8")
    for field in (
        "outside_checked_functions",
        "excluded_inputs",
        "mutations_skipped",
        "corpus_empty",
        "corpus_replayed",
        "replay_hang",
        "reach.unreached",
    ):
        assert field in text, field
        assert field.split(".")[-1] in script, field
    oracle1 = text.split("1. **Oracle 1", 1)[1].split("2. **Oracle 2", 1)[0]
    assert "`guardrail_error` with `outside_checked_functions`" in oracle1
    assert "status `blocked`" in oracle1 and "untested: failure outside {function_name}" in oracle1
    assert "passed on no real input" in oracle1


@pytest.mark.unit
@pytest.mark.parametrize("pointer_params", [True, False])
def test_prover_brief_void_pointer_row_follows_pointer_params(pointer_params):
    text = _PROVER_BRIEF.read_text(encoding="utf-8")
    assert text.count("<!-- if:") == text.count("<!-- endif -->")
    rendered = function_facts.render_conditionals(text, {"pointer_params": pointer_params})
    assert "<!-- if:" not in rendered and "<!-- endif -->" not in rendered
    row = "\\block_length((char *)p)"
    assert (row in rendered) is pointer_params
