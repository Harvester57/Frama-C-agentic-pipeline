import copy
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from fingerprint import make_fingerprint  # noqa: E402

PHASE0_FIXTURES = ROOT / "tests" / "fixtures" / "phase0"
# The images the Docker-backed tests (FRAMAC_DOCKER_TESTS=1) run in: the analysis image (Frama-C, the
# provers, E-ACSL; stage framac-analysis) and the build image (the target's own build and tests; stage
# framac-build). Override either name with FRAMAC_TEST_IMAGE / FRAMAC_TEST_BUILD_IMAGE.
ANALYSIS_IMAGE = os.environ.get("FRAMAC_TEST_IMAGE", "framac-analysis:latest")
BUILD_IMAGE = os.environ.get("FRAMAC_TEST_BUILD_IMAGE", "framac-build:latest")


def require_docker_images(*images: str) -> None:
    """Skip unless FRAMAC_DOCKER_TESTS=1, Docker is on PATH and every image is built."""
    if os.environ.get("FRAMAC_DOCKER_TESTS") != "1":
        pytest.skip("Docker-backed test: set FRAMAC_DOCKER_TESTS=1")
    if not shutil.which("docker"):
        pytest.skip("docker not found")
    for image in images:
        if subprocess.run(["docker", "image", "inspect", image], capture_output=True, check=False).returncode:
            pytest.skip(f"image {image} not built")


@pytest.fixture
def docker_fixture_run():
    """
    Run a shell command in the build image on a copy of a fixture project (mounted read-only, network
    off), as `run(fixture_dir, command) -> CompletedProcess`: the fixtures are targets, built by their own
    Makefile. Opt-in, as these tests start containers: set FRAMAC_DOCKER_TESTS=1. Skipped when Docker or
    the image is missing.
    """
    require_docker_images(BUILD_IMAGE)

    def run(fixture: Path, command: str, timeout: int = 600) -> subprocess.CompletedProcess:
        argv = [
            "docker", "run", "--rm", "--network", "none",
            "-v", f"{fixture.resolve()}:/fixture:ro",
            "--entrypoint", "sh", BUILD_IMAGE,
            "-c", f"cp -r /fixture /tmp/p && cd /tmp/p && {command}",
        ]  # fmt: skip
        return subprocess.run(
            argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, check=False
        )

    return run


@pytest.fixture(autouse=True)
def _no_inherited_git_location(monkeypatch):
    """
    Git exports these to hooks (GIT_DIR always, in a linked worktree). A test that runs git, with the
    pre-commit hook running pytest, would otherwise act on the real repository instead of its own.
    """
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY", "GIT_PREFIX"):
        monkeypatch.delenv(name, raising=False)


FP_PARSE = make_fingerprint("src/snmp/ber.c", "ber_decode_len", "mem_access", r"\valid_read(buf + off)")
FP_EVA = make_fingerprint("src/log/emit.c", "emit_field", "signed_overflow", "pos + n <= 2147483647")
FP_REJ = make_fingerprint("src/snmp/ber.c", "ber_decode_tag", "mem_access", r"\valid_read(p)")


def unit(file, function, cls, status="planned", **kw):
    u = {
        "coverage_id": f"{file}#{function}::{cls}",
        "file": file,
        "function": function,
        "obligation_class": cls,
        "module": kw.pop("module", "snmp"),
        "tier": kw.pop("tier", "Tier 1A (Untrusted Binary / Network Parser)"),
        "wave": kw.pop("wave", 0),
        "callgraph_source": "frama_c",
        "status": status,
        "agent_id": None,
        "evidence": [],
        "result_fingerprints": [],
        "unresolved": [],
        "assumptions": [],
        "attempts": [],
    }
    u.update(kw)
    return u


def evidence(phase="eva", result="eva_all_valid", discharging=True, tool_output="workspace/reports/eva/snmp.json"):
    return {
        "phase": phase,
        "producer": "run_eva_slice.py",
        "result": result,
        "discharging": discharging,
        "tool_output": tool_output,
        "summary": "summary text",
    }


def verifier():
    return {"agent_id": "verifier-1", "method": "reproduced_and_source_review", "notes": "Re-ran and traced."}


def confirmed_record(fp=FP_PARSE):
    return {
        "verdict": "confirmed",
        "fingerprint": fp,
        "title": "Out-of-bounds read in BER length decoder",
        "description": "Long-form length bytes are read past the end of the input buffer.",
        "location": {"file": "src/snmp/ber.c", "line": 42, "function": "ber_decode_len"},
        "property": {"kind": "mem_access", "predicate": r"\valid_read(buf + off)"},
        "root_cause": "Length-of-length byte count is not checked against remaining input.",
        "intended_behavior": "Reject encodings whose length field exceeds the remaining buffer.",
        "trace": [
            {
                "kind": "entrypoint",
                "file": "src/snmp/pdu.c",
                "line": 10,
                "function": "snmp_parse_pdu",
                "description": "Untrusted UDP payload enters.",
            },
            {
                "kind": "propagation",
                "file": "src/snmp/ber.c",
                "line": 30,
                "function": "ber_decode_tlv",
                "description": "Calls length decoder.",
            },
            {
                "kind": "sink",
                "file": "src/snmp/ber.c",
                "line": 42,
                "function": "ber_decode_len",
                "description": "Reads buf[off] past len.",
            },
        ],
        "evidence": [
            {
                "phase": "fuzz",
                "tool_output": "workspace/reports/fuzz/snmp.json",
                "description": "E-ACSL mem_access failure.",
            }
        ],
        "reachability": "untrusted_surface",
        "harness": {
            "file": "workspace/harnesses/harness_snmp.c",
            "entry_function": "snmp_parse_pdu",
            "contract_respected": True,
            "notes": "Exact-size buffer, len within documented max.",
        },
        "reproducers": [
            {
                "input": "workspace/crashes/snmp/crash-1",
                "sha256": "0" * 64,
                "size_bytes": 3,
                "command": "fuzz_snmp crash-1",
                "observed_result": "E-ACSL: mem_access failed at ber.c:42",
            }
        ],
        "severity": "high",
        "severity_rationale": "Unauthenticated out-of-bounds read; no write shown.",
        "remediation": {
            "summary": "Check length-of-length against remaining bytes.",
            "invariant": "off + nbytes <= len",
            "fix_patch": None,
        },
        "linked_units": ["src/snmp/ber.c#ber_decode_len::rte"],
        "verifier": verifier(),
    }


def needs_validation_record(fp=FP_EVA):
    return {
        "verdict": "needs_validation",
        "fingerprint": fp,
        "title": "Possible signed overflow in cursor advance",
        "description": "Eva reports Invalid for pos + n without a witness.",
        "location": {"file": "src/log/emit.c", "line": 77, "function": "emit_field"},
        "property": {"kind": "signed_overflow", "predicate": "pos + n <= 2147483647"},
        "origin": "eva_invalid_no_witness",
        "claimed_root_cause": "snprintf would-have-written length added to pos.",
        "trace": [
            {"kind": "sink", "file": "src/log/emit.c", "line": 77, "function": "emit_field", "description": "pos += n"}
        ],
        "evidence": [
            {"phase": "eva", "tool_output": "workspace/reports/eva/log.json", "description": "Invalid status."}
        ],
        "reachability": "unknown",
        "blockers": ["No input reaching n > cap - pos found by the breaker within budget."],
        "validation_plan": {"local": "Craft a field longer than cap and replay through harness_log."},
        "linked_units": ["src/log/emit.c#emit_field::rte"],
        "verifier": {"agent_id": "verifier-2", "method": "source_review", "notes": "Path plausible."},
    }


def rejected_record(fp=FP_REJ):
    return {
        "verdict": "rejected",
        "fingerprint": fp,
        "title": "Harness passed NULL to tag decoder",
        "description": "Crash caused by the harness violating the documented non-NULL contract.",
        "location": {"file": "src/snmp/ber.c", "line": 12, "function": "ber_decode_tag"},
        "property": {"kind": "mem_access", "predicate": r"\valid_read(p)"},
        "claimed_root_cause": "NULL dereference.",
        "evidence": [
            {"phase": "verifier", "tool_output": "agents/verifier-3/artifacts/notes.txt", "description": "Harness bug."}
        ],
        "rejection_class": "harness_induced",
        "reason": "ber_decode_tag documents p != NULL; all real callers check it.",
        "linked_units": ["src/snmp/ber.c#ber_decode_tag::rte"],
        "verifier": {"agent_id": "verifier-3", "method": "source_review", "notes": "Harness bug."},
    }


def sorted_findings(*records):
    return sorted(records, key=lambda r: r["fingerprint"])


def metadata(status="in_progress", reason=None):
    return {
        "schema_version": 1,
        "run_id": "run-1",
        "repo": "demo",
        "target": "/target",
        "source_ref": {"vcs": "git", "commit": "abc123", "dirty": False},
        "profile": "standard",
        "scope_paths": [],
        "budget": None,
        "execution_policy": "sandboxed-local-only",
        "sandbox": {"outer": "docker-hardened", "inner": "rlimits"},
        "prior_runs": [],
        "toolchain": {},
        "run_status": status,
        "incomplete_reason": reason,
        "created_at": "2026-10-29T00:00:00+00:00",
        "updated_at": "2026-10-29T00:00:00+00:00",
    }


def write_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


@pytest.fixture
def run_dir(tmp_path, monkeypatch):
    d = tmp_path / "run-1"
    d.mkdir()
    monkeypatch.chdir(d)
    return d


@pytest.fixture
def deep():
    return copy.deepcopy


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return ROOT


# ------------------------------------------------------------------ parsers for the tests that guard text files
#
# The tests that guard a Dockerfile, the Makefile template or a WP log read them through these, so a guard
# sees whole commands and whole rules instead of whatever one regex happens to match on one line.

# Spacing as loose as production's run_wp_function._WP_PROVED_GOALS_RE (not imported: conftest stays light).
_WP_PROVED_GOALS_LINE_RE = re.compile(r"Proved goals:\s*(\d+)\s*/\s*(\d+)")


def wp_proved_goals(log: str) -> list[tuple[int, int]]:
    """
    (proved, total) of every `Proved goals: p / t` summary line of a WP log, in order. Fails when the log
    has no summary line, or when one counts no goal: `0 / 0` proves nothing, though proved == total.
    """
    goals = [(int(p), int(t)) for p, t in _WP_PROVED_GOALS_LINE_RE.findall(log)]
    assert goals, f"no 'Proved goals' line in:\n{log}"
    assert all(total > 0 for _, total in goals), f"a WP run with no goal: {goals}\n{log}"
    return goals


class DockerStage(NamedTuple):
    """One build stage: the image it starts from, its name ("" when unnamed) and its instructions as text."""

    base: str
    name: str
    text: str


_DOCKER_FROM_RE = re.compile(r"(?:--\S+\s+)*(?P<base>\S+)(?:\s+[Aa][Ss]\s+(?P<name>\S+))?")


def dockerfile_instructions(text: str) -> list[tuple[str, str]]:
    """
    (KEYWORD, arguments) of every instruction of a Dockerfile (or of one stage's text): comment lines are
    dropped, also inside a continued instruction, and backslash continuations are joined with one space.
    """
    out: list[tuple[str, str]] = []
    pending: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        continued = line.endswith("\\")
        pending.append(line[:-1].strip() if continued else line)
        if not continued:
            keyword, _, args = " ".join(pending).partition(" ")
            out.append((keyword.upper(), args.strip()))
            pending = []
    if pending:
        keyword, _, args = " ".join(pending).partition(" ")
        out.append((keyword.upper(), args.strip()))
    return out


def dockerfile_stages(text: str) -> list[DockerStage]:
    """Every `FROM` of a Dockerfile, in order, named or not (`--platform=...` flags allowed)."""
    stages: list[DockerStage] = []
    for keyword, args in dockerfile_instructions(text):
        if keyword == "FROM":
            m = _DOCKER_FROM_RE.fullmatch(args)
            assert m is not None, f"unparsable FROM: {args!r}"
            stages.append(DockerStage(m.group("base"), m.group("name") or "", ""))
        elif stages:
            last = stages[-1]
            stages[-1] = last._replace(text=f"{last.text}{keyword} {args}\n")
    return stages


def dockerfile_commands(text: str) -> list[list[str]]:
    """
    The argv of every simple command of the shell-form `RUN` instructions of a Dockerfile (or of one
    stage's text): each RUN is tokenised as the shell would (quotes kept together) and split at the
    control operators (`&&`, `||`, `;`, `|`, parentheses, redirections).
    """
    commands: list[list[str]] = []
    for keyword, args in dockerfile_instructions(text):
        if keyword != "RUN":
            continue
        lexer = shlex.shlex(args, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        lexer.commenters = ""
        argv: list[str] = []
        for token in lexer:
            if token and all(ch in lexer.punctuation_chars for ch in token):
                if argv:
                    commands.append(argv)
                argv = []
            else:
                argv.append(token)
        if argv:
            commands.append(argv)
    return commands


def dockerfile_command_args(text: str, *command: str) -> set[str]:
    """
    The arguments, over all RUN instructions, of the commands that start with the words `command`:
    `dockerfile_command_args(text, "chmod", "1777")` is the set of paths made world-writable and sticky,
    whatever their order and whichever line they are on. A path of another mode is not in it.
    """
    n = len(command)
    return {arg for argv in dockerfile_commands(text) if tuple(argv[:n]) == command for arg in argv[n:]}


class MakeRule(NamedTuple):
    """
    One rule of a Makefile: `targets: prerequisites` or, for a static pattern rule,
    `targets: pattern: prerequisites`. `recipe` holds the logical recipe lines (continuations joined with
    one space, the leading tab removed). The tab-led body of a `define NAME` that has no rule line of its
    own is a rule with the one target `define NAME`.
    """

    targets: tuple[str, ...]
    pattern: str
    prerequisites: tuple[str, ...]
    recipe: tuple[str, ...]


def _make_split_top(text: str, sep: str | None) -> list[str]:
    """Split at `sep` (None: at whitespace) outside `$(...)` and `${...}`."""
    parts: list[str] = [""]
    depth = 0
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "$" and text[i + 1 : i + 2] in ("(", "{"):
            depth += 1
            parts[-1] += text[i : i + 2]
            i += 2
            continue
        if ch in ")}" and depth:
            depth -= 1
        if depth == 0 and (ch.isspace() if sep is None else ch == sep):
            parts.append("")
        else:
            parts[-1] += ch
        i += 1
    return [p for p in parts if p] if sep is None else parts


def _make_rule_header(line: str) -> tuple[tuple[str, ...], str, tuple[str, ...]] | None:
    """(targets, pattern, prerequisites) of a rule line, or None for an assignment, a directive or a call."""
    fields = _make_split_top(line, ":")
    if len(fields) < 2:
        return None  # no colon outside $(...)
    if len(_make_split_top(fields[0], "=")) > 1:
        return None  # `NAME = a:b`, `NAME ?= a:b`
    if fields[1].startswith("=") or (len(fields) > 2 and not fields[1] and fields[2].startswith("=")):
        return None  # `NAME := value`, `NAME ::= value`
    targets = tuple(_make_split_top(fields[0], None))
    if not targets:
        return None
    pattern = fields[1].strip() if len(fields) > 2 else ""
    prerequisites = _make_split_top(_make_split_top(fields[-1], ";")[0], None)
    return targets, pattern, tuple(p for p in prerequisites if p != "|")


def makefile_rules(text: str) -> list[MakeRule]:
    """
    Every rule of a Makefile, in order. A blank line or a comment line inside a recipe does not end it;
    another rule, an assignment, `define` and `endef` do. Rules written inside a `define` are returned as
    written (`evashard-$(1)--$(2)`); rules made by `$(eval ...)` in a `$(foreach ...)` are not.
    """
    logical: list[str] = []
    pending = ""
    for raw in text.splitlines():
        # A continuation's own leading whitespace is part of the join, not a new recipe line.
        line = pending + raw.lstrip() if pending else raw
        if line.endswith("\\"):
            pending = line[:-1].rstrip() + " "
            continue
        pending = ""
        logical.append(line)
    if pending:
        logical.append(pending)

    rules: list[MakeRule] = []
    current: MakeRule | None = None  # the rule the next tab-led line belongs to

    def close() -> None:
        nonlocal current
        if current is not None:
            rules.append(current)
        current = None

    for line in logical:
        if line.startswith("\t"):
            assert current is not None, f"recipe line outside a rule: {line!r}"
            if line.strip():
                current = current._replace(recipe=(*current.recipe, line[1:].strip()))
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        words = stripped.split()
        if words[0] == "define":
            close()
            current = MakeRule((f"define {words[1]}",), "", (), ())
            continue
        if words[0] == "endef":
            close()
            continue
        if words[0] in ("ifeq", "ifneq", "ifdef", "ifndef", "else", "endif"):
            continue  # a conditional may sit inside a recipe
        close()
        header = _make_rule_header(stripped)
        if header is not None:
            current = MakeRule(header[0], header[1], header[2], ())
    close()
    return [r for r in rules if not (r.targets[0].startswith("define ") and not r.recipe)]


def makefile_rule(text: str, target: str) -> MakeRule:
    """
    The rule of `target` (spelled as in the Makefile: `seed`, `$(BUILD_TARGETS)`, `define FACTS_RECIPE`).
    Several rule lines for one target are merged as Make does: prerequisites added up, one recipe.
    """
    found = [r for r in makefile_rules(text) if target in r.targets]
    assert found, f"no rule for {target}"
    with_recipe = [r for r in found if r.recipe]
    assert len(with_recipe) <= 1, f"{target} has {len(with_recipe)} recipes"
    patterns = {r.pattern for r in found if r.pattern}
    assert len(patterns) <= 1, f"{target} has several target patterns: {sorted(patterns)}"
    prerequisites = tuple(dict.fromkeys(p for r in found for p in r.prerequisites))
    recipe = with_recipe[0].recipe if with_recipe else ()
    return MakeRule((target,), next(iter(patterns), ""), prerequisites, recipe)
