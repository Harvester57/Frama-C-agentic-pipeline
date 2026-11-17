#!/usr/bin/env python3
"""
Check a verifier's decision point by patch and replay (Crash Verifier, Case A).

A `decision_point` in a verdict record is the verifier's claim: "the failure became inevitable
here". This script tests the claim with the candidate's own reproducers. The verifier writes a
small patch that neutralises the decision point (for example the missing bounds check); the script

  1. copies workspace/work/ into the agent's scratch and applies the patch there;
  2. builds the module's fuzz binary twice with the same engine and flags, once from
     workspace/work/ and once from the patched copy (both binaries in the agent's scratch);
  3. replays the candidate's reproducers on both, in the sandbox.

Status `checked` means exactly: the unpatched build fails with the candidate's failure on at least
one reproducer, and the patched build fails on none of them. It says nothing about other inputs,
and it does not say the patch is the right fix. Every other status leaves the claim unchecked:

  not_removed              the patched build still fails with the candidate's failure
  other_failure            the patched build fails, but not with the candidate's failure
  baseline_not_reproduced  the unpatched build does not show the candidate's failure
  patch_refused            the patch touches a file outside the target sources (workspace/work/)
  patch_does_not_apply | empty_patch | no_reproducers | build_error | error

Usage (from the run directory):
  decision_point_check.py --fingerprint FP --agent-id ID --patch agents/ID/scratch/x.dp.patch
                          (--result agents/ID/scratch/result.json
                           | --dp-file F --dp-line N --dp-function FN)
                          [--failure-fingerprint FP2] [--inputs FILE ...] [--engine eacsl|sanitizers]
                          [--per-input-timeout S] [--keep-scratch]

The patch is a unified diff against workspace/work/ (`diff -u workspace/work/<file> <edited copy>`).
Nothing is written to the target, workspace/work/ or workspace/harnesses/. The report goes to
workspace/reports/decision_point/<fingerprint-slug>.json with the patch as it was applied next to it
(`.patch`); `ledger.py ingest-verifier` reads the report itself and sets `decision_point.basis` to
`checked` only when it agrees with the record (agreeing_report). The report records, and does not
hide, a patch that touches the sink line itself or lies outside the decision point's function.
"""

from __future__ import annotations

import argparse
import contextlib
import difflib
import hashlib
import json
import os
import re
import shlex
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fingerprint import normalize_file  # noqa: E402
from framac_common import (  # noqa: E402
    ArtifactError,
    atomic_write_json,
    is_safe_agent_id,
    is_safe_relative_path,
    load_agent_result_json,
    load_json_optional,
    scratch_first_flags,
    source_tree_relpath,
    to_run_relative,
    utc_now,
)

REPORT_DIR = Path("workspace/reports/decision_point")
WORK_DIR = Path("workspace/work")
HARNESS_DIR = Path("workspace/harnesses")
CANDIDATES = Path("candidates.json")
# A patch "at" a decision point changes its file within this many lines of its line: the missing
# check is written just before or after the step that lacks it.
LINE_SLACK = 5
MAX_PATCH_BYTES = 256 * 1024
DEFAULT_PER_INPUT_TIMEOUT_S = 10
FILE_SCOPE = "<file scope>"

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_TREE_PREFIX_RE = re.compile(
    r"^(?:/framac-run/)?(?:workspace/(?:work|baseline)|agents/[^/]+/scratch/(?:[^/]+/)*work|/target)/"
)


class PatchError(ValueError):
    """A patch that cannot be used; `status` is the report status it leads to."""

    def __init__(self, status: str, message: str):
        super().__init__(message)
        self.status = status


@dataclass
class Hunk:
    old_start: int
    old: list[str] = field(default_factory=list)
    new: list[str] = field(default_factory=list)


@dataclass
class FilePatch:
    old_path: str
    new_path: str
    hunks: list[Hunk] = field(default_factory=list)


def atomic_write_bytes(path: Path, blob: bytes) -> None:
    """Write through a temporary sibling and os.replace, as atomic_write_json does."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp_", suffix=path.suffix)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(blob)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _obj(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def candidate_slug(fingerprint: str) -> str:
    """File stem of a candidate's report: the naming of the replay reports (workspace/reports/replay/)."""
    base = re.sub(r"[^A-Za-z0-9_.-]+", "_", fingerprint).strip("._")[:80] or "candidate"
    return f"{base}-{hashlib.sha256(fingerprint.encode()).hexdigest()[:10]}"


def report_path(fingerprint: str) -> Path:
    """Run-relative path of a candidate's decision point report."""
    return REPORT_DIR / f"{candidate_slug(fingerprint)}.json"


# ---------------------------------------------------------------- the patch


def _header_path(line: str) -> str:
    return line[4:].split("\t", 1)[0].strip()


def parse_unified_diff(text: str) -> list[FilePatch]:
    """The file sections and hunks of a unified diff. Lines outside a section (`diff`, `index`) are skipped."""
    lines = text.splitlines(keepends=True)
    files: list[FilePatch] = []
    i = 0
    while i < len(lines):
        if not (lines[i].startswith("--- ") and i + 1 < len(lines) and lines[i + 1].startswith("+++ ")):
            i += 1
            continue
        patch = FilePatch(_header_path(lines[i]), _header_path(lines[i + 1]))
        i += 2
        while i < len(lines) and (m := _HUNK_RE.match(lines[i])):
            old_n = int(m.group(2)) if m.group(2) is not None else 1
            new_n = int(m.group(4)) if m.group(4) is not None else 1
            hunk = Hunk(int(m.group(1)))
            last: list[list[str]] = []
            i += 1
            while i < len(lines) and (len(hunk.old) < old_n or len(hunk.new) < new_n):
                line = lines[i]
                tag, body = line[:1], line[1:]
                if tag == " " or line in ("\n", "\r\n"):  # an editor may strip the space of an empty context line
                    hunk.old.append(body or line)
                    hunk.new.append(body or line)
                    last = [hunk.old, hunk.new]
                elif tag == "-":
                    hunk.old.append(body)
                    last = [hunk.old]
                elif tag == "+":
                    hunk.new.append(body)
                    last = [hunk.new]
                elif tag == "\\":  # "\ No newline at end of file"
                    for side in last:
                        side[-1] = side[-1].rstrip("\r\n")
                else:
                    raise PatchError("patch_does_not_apply", f"malformed hunk line in {patch.old_path}: {line!r}")
                i += 1
            if i < len(lines) and lines[i].startswith("\\"):
                for side in last:
                    side[-1] = side[-1].rstrip("\r\n")
                i += 1
            if len(hunk.old) != old_n or len(hunk.new) != new_n:
                raise PatchError("patch_does_not_apply", f"truncated hunk in {patch.old_path} at line {hunk.old_start}")
            patch.hunks.append(hunk)
        files.append(patch)
    return files


def target_relpath(raw: str, work_dir: Path) -> str | None:
    """
    The file of the target sources a diff header names, relative to `work_dir`, or None when it names
    none. A header may spell the work tree (`workspace/work/src/x.c`) or use git's `a/`, `b/` prefixes.
    """
    norm = (raw or "").replace("\\", "/").strip()
    if not norm or norm == "/dev/null":
        return None
    spellings = [_TREE_PREFIX_RE.sub("", norm, count=1)]
    if re.match(r"^[ab]/", norm):
        spellings.append(_TREE_PREFIX_RE.sub("", norm[2:], count=1))
    for rel in spellings:
        while rel.startswith("./"):
            rel = rel[2:]
        if not is_safe_relative_path(rel):
            continue
        path = work_dir / rel
        if path.is_file() and not path.is_symlink():
            return rel
    return None


def apply_hunks(lines: list[str], hunks: list[Hunk], name: str = "") -> list[str]:
    """
    `lines` (with line ends) after `hunks`. A hunk is placed where its old lines match, nearest to
    the line it names; line ends are not compared, and added lines take the file's line end.
    """
    eol = "\r\n" if sum(1 for ln in lines if ln.endswith("\r\n")) * 2 > len(lines) else "\n"
    out = list(lines)
    offset = 0
    for hunk in sorted(hunks, key=lambda h: h.old_start):
        old = [ln.rstrip("\r\n") for ln in hunk.old]
        new = [ln.rstrip("\r\n") + (eol if ln.endswith(("\n", "\r")) else "") for ln in hunk.new]
        if old:
            want = hunk.old_start - 1 + offset
            stripped = [ln.rstrip("\r\n") for ln in out]
            places = [p for p in range(len(out) - len(old) + 1) if stripped[p : p + len(old)] == old]
            if not places:
                raise PatchError(
                    "patch_does_not_apply", f"{name}: the hunk at line {hunk.old_start} does not match the file"
                )
            pos = min(places, key=lambda p: abs(p - want))
        else:
            pos = min(max(hunk.old_start + offset, 0), len(out))
        out[pos : pos + len(old)] = new
        offset += len(new) - len(old)
    return out


def function_spans(text: str, path: str = "<input>") -> list[tuple[int, int, str]]:
    """(first line, last line, name) of the function definitions in `text`."""
    from c_definitions import TYPE_MODIFIERS_AND_PRIMITIVES, extract_functions_from_code

    spans: list[tuple[int, int, str]] = []
    try:
        found = extract_functions_from_code(text, path=path)
    except Exception:  # a file the tokenizer cannot read has no spans: every range is file scope
        return spans
    for fn in found:
        name = str(fn.get("name") or "")
        if name and name not in TYPE_MODIFIERS_AND_PRIMITIVES:
            spans.append((int(fn.get("line") or 0), int(fn.get("end_line") or 0), name))
    return spans


def changed_ranges(old: list[str], new: list[str], spans: list[tuple[int, int, str]]) -> list[dict]:
    """
    What a patch changes, in line numbers of the unpatched file. A `replace` or `delete` range covers
    the lines `start..end` it rewrites; an `insert` adds lines between `start` and `end` (= start + 1)
    and rewrites none. `functions` are the definitions the range lies in (`<file scope>` outside any).
    """
    ranges: list[dict] = []
    matcher = difflib.SequenceMatcher(a=old, b=new, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        start, end = (i1, i1 + 1) if tag == "insert" else (i1 + 1, i2)
        lo, hi = max(start, 1), max(min(end, len(old)), 1)
        names = sorted({name for first, last, name in spans if first <= hi and lo <= last})
        ranges.append(
            {
                "kind": tag,
                "start": start,
                "end": end,
                "removed": i2 - i1,
                "added": j2 - j1,
                "functions": names or [FILE_SCOPE],
            }
        )
    return ranges


def _rewrites_line(rng: dict, line: int) -> bool:
    return rng["kind"] != "insert" and rng["start"] <= line <= rng["end"]


def patch_at(files: list[dict], file: str, line: int, slack: int = LINE_SLACK) -> bool:
    """True when the recorded patch changes `file` within `slack` lines of `line`."""
    want = normalize_file(file)
    for entry in files or []:
        if not isinstance(entry, dict) or normalize_file(str(entry.get("file") or "")) != want:
            continue
        for rng in entry.get("ranges") or []:
            try:
                if int(rng["start"]) - slack <= line <= int(rng["end"]) + slack:
                    return True
            except (KeyError, TypeError, ValueError):
                continue
    return False


def describe_patch(files: list[dict], decision_point: dict, sink: dict) -> dict:
    """Where the patch lies relative to the decision point and to the sink (recorded, never hidden)."""
    dp_file = normalize_file(str(decision_point.get("file") or ""))
    dp_fn = str(decision_point.get("function") or "")
    sink_file = normalize_file(str(sink.get("file") or ""))
    sink_line = int(sink.get("line") or 0)
    outside = False
    touches_sink: bool | None = False if sink_line > 0 else None
    for entry in files:
        same_file = normalize_file(entry["file"]) == dp_file
        for rng in entry["ranges"]:
            if not same_file or rng["functions"] != [dp_fn]:
                outside = True
            if sink_line > 0 and normalize_file(entry["file"]) == sink_file and _rewrites_line(rng, sink_line):
                touches_sink = True
    return {
        "at_decision_point": patch_at(files, dp_file, int(decision_point.get("line") or 0)),
        "touches_sink_line": touches_sink,
        "outside_decision_function": outside,
    }


def stage_patch(patch_text: str, work_dir: Path) -> tuple[list[dict], str, dict[str, bytes]]:
    """
    Apply the patch to the files of `work_dir` in memory. Returns the changed files with their ranges,
    the patch as applied (a diff computed from the old and new contents, so its digest and line
    ranges do not depend on how the verifier wrote the hunk headers), and the new contents by file.
    """
    sections = parse_unified_diff(patch_text)
    if not sections:
        raise PatchError("empty_patch", "the patch has no file section (`--- ` / `+++ ` and `@@` hunks)")
    refused: list[str] = []
    by_file: dict[str, list[Hunk]] = {}
    for section in sections:
        if "/dev/null" in (section.old_path, section.new_path):
            refused.append(f"{section.new_path or section.old_path}: creates or deletes a file")
            continue
        rel = target_relpath(section.old_path, work_dir) or target_relpath(section.new_path, work_dir)
        if rel is None:
            refused.append(f"{section.old_path}: not a file of the target sources (workspace/work/)")
            continue
        by_file.setdefault(rel, []).extend(section.hunks)
    if refused:
        raise PatchError("patch_refused", "; ".join(refused))

    files: list[dict] = []
    canonical: list[str] = []
    contents: dict[str, bytes] = {}
    for rel in sorted(by_file):
        raw = (work_dir / rel).read_bytes()
        old = raw.decode("utf-8", errors="surrogateescape").splitlines(keepends=True)
        new = apply_hunks(old, by_file[rel], rel)
        if new == old:
            continue
        contents[rel] = "".join(new).encode("utf-8", errors="surrogateescape")
        ranges = changed_ranges(old, new, function_spans("".join(old), rel))
        files.append({"file": rel, "sha256_before": hashlib.sha256(raw).hexdigest(), "ranges": ranges})
        diff = list(difflib.unified_diff(old, new, fromfile=f"a/{rel}", tofile=f"b/{rel}"))
        canonical.extend(ln if ln.endswith("\n") else ln + "\n\\ No newline at end of file\n" for ln in diff)
    if not files:
        raise PatchError("empty_patch", "the patch changes nothing in the target sources")
    return files, "".join(canonical), contents


# ------------------------------------------------------------ build and replay


def _copy_work_tree(src: Path, dest: Path) -> None:
    """A private copy of workspace/work/ (the copy provers get, see workspace_overlay.init_agent_overlay)."""
    from workspace_overlay import _copy_tree

    if dest.exists():
        shutil.rmtree(dest)
    _copy_tree(src, dest)


def patched_build_spec(spec: dict, run_dir: Path, overlay_work: Path) -> dict:
    """The module's build spec with every source and include directory of the work tree read from the copy."""
    sources: list[str] = []
    for src in spec["sources"]:
        rel = source_tree_relpath(str(src), run_dir, run_dir / WORK_DIR)
        twin = overlay_work / rel if rel is not None else None
        sources.append(to_run_relative(twin, run_dir) if twin is not None and twin.is_file() else str(src))
    flags = scratch_first_flags(shlex.split(spec.get("cppflags") or ""), run_dir, overlay_work)
    return {**spec, "sources": sources, "cppflags": shlex.join(flags)}


def build_binary(module: str, spec: dict, out_bin: Path, engine: str) -> dict:
    """Build a module binary for replays (crash_replay.prepare_replay_binary; never cached in agent scratch)."""
    import crash_replay

    return crash_replay.prepare_replay_binary(
        module,
        list(spec["sources"]),
        out_bin,
        attribution=False,
        engine=engine,
        cppflags=spec.get("cppflags") or "-I.",
        ldflags=spec.get("ldflags") or "",
        rte_initialized=bool(spec.get("rte_initialized", True)),
        libc_checks=bool(spec.get("libc_checks", True)),
    )


def replay(module: str, inputs: list[Path], scratch: Path, prepared: dict, per_input_timeout: int) -> dict:
    """Replay `inputs` once each in the sandbox (crash_replay.replay_report)."""
    import crash_replay

    return crash_replay.replay_report(module, inputs, scratch, prepared=prepared, per_input_timeout=per_input_timeout)


def build_spec(module: str, file: str | None, function: str | None) -> dict:
    import crash_replay

    return crash_replay.replay_build_spec(module, HARNESS_DIR, file, function)


def candidate_engine(cand: dict) -> str:
    import crash_replay

    return crash_replay._candidate_engine(cand)


def _outcome(report: dict, expected: set[str]) -> dict:
    """One build's replay, reduced to what the status rests on."""
    rows = []
    for art in report.get("artifacts") or []:
        failure = art.get("failure") if isinstance(art.get("failure"), dict) else None
        rows.append(
            {
                "input": art.get("artifact"),
                "sha256": art.get("sha256"),
                "failed": bool(art.get("reproducible")),
                "timed_out": bool(art.get("timed_out")),
                "returncode": art.get("returncode"),
                "fingerprint": art.get("fingerprint"),
                "failure": (
                    {k: failure.get(k) for k in ("file", "line", "function", "kind", "alarm_kind", "predicate")}
                    if failure
                    else None
                ),
            }
        )
    out = {
        "status": report.get("status"),
        "binary": report.get("binary"),
        "engine_used": report.get("engine_used"),
        "fails": any(r["failed"] for r in rows),
        "fails_with_candidate": any(r["failed"] and r["fingerprint"] in expected for r in rows),
        "inputs": rows,
    }
    if report.get("reason"):
        out["reason"] = report["reason"]
    return out


def decide(unpatched: dict, patched: dict) -> tuple[str, str]:
    """The status of a completed pair of replays, and the sentence that explains it."""
    if not unpatched["fails_with_candidate"]:
        return "baseline_not_reproduced", "the unpatched build does not fail with the candidate's failure"
    if patched["fails_with_candidate"]:
        return "not_removed", "the patched build still fails with the candidate's failure"
    if patched["fails"]:
        return "other_failure", "the patched build fails on a reproducer, with another failure"
    return "checked", "the unpatched build fails with the candidate's failure and the patched build does not"


def run_check(
    fingerprint: str,
    patch_file: Path,
    agent_id: str,
    decision_point: dict,
    *,
    run_dir: Path = Path("."),
    failure_fingerprint: str | None = None,
    extra_inputs: list[Path] | None = None,
    engine: str | None = None,
    per_input_timeout: int = DEFAULT_PER_INPUT_TIMEOUT_S,
    keep_scratch: bool = False,
) -> dict:
    """
    Run the check and write its report. `run_dir` must be the working directory: the build and replay
    helpers resolve sources, flags and reproducers from it, as every pipeline command does.
    """
    run_dir = Path(run_dir).resolve()
    if not is_safe_agent_id(agent_id):
        raise ArtifactError(f"invalid canonical agent_id: {agent_id!r}")
    candidates = load_json_optional(run_dir / CANDIDATES, [])
    cand = next((c for c in candidates if isinstance(c, dict) and c.get("fingerprint") == fingerprint), None)
    if cand is None:
        raise ArtifactError(f"unknown candidate fingerprint: {fingerprint}")
    loc = _obj(cand.get("location"))
    sink: dict[str, Any] = {
        "file": str(loc.get("file") or ""),
        "line": int(loc.get("line") or 0),
        "function": str(loc.get("function") or ""),
    }
    dp = {
        "file": normalize_file(str(decision_point["file"])),
        "line": int(decision_point["line"]),
        "function": str(decision_point["function"]),
    }
    module = str(cand.get("module") or "")
    slug = candidate_slug(fingerprint)
    scratch = run_dir / "agents" / agent_id / "scratch" / "decision_point" / slug
    # Named workspace/work so a failure in the copy normalizes to the same file, hence the same fingerprint.
    overlay_work = scratch / "workspace" / "work"
    out_path = run_dir / report_path(fingerprint)
    canonical_path = out_path.with_suffix(".patch")

    report: dict[str, Any] = {
        "mode": "decision_point_check",
        "schema_version": 1,
        "generated_at": utc_now(),
        "fingerprint": fingerprint,
        "failure_fingerprint": failure_fingerprint or fingerprint,
        "module": module,
        "agent_id": agent_id,
        "decision_point": dp,
        "sink": sink,
        "patch": {"source": to_run_relative(Path(patch_file).resolve(), run_dir), "sha256": None, "files": []},
        "inputs": [],
        "replay": {"unpatched": None, "patched": None},
        "status": "error",
        "reason": "",
    }

    def finish(status: str, reason: str) -> dict:
        report["status"] = status
        report["reason"] = reason
        if not keep_scratch and scratch.is_dir():
            shutil.rmtree(scratch, ignore_errors=True)
        atomic_write_json(out_path, report)
        return report

    try:
        raw_patch = Path(patch_file).read_bytes()
    except OSError as exc:
        return finish("error", f"cannot read the patch: {exc}")
    if len(raw_patch) > MAX_PATCH_BYTES:
        return finish("patch_refused", f"the patch is larger than {MAX_PATCH_BYTES} bytes")
    work_dir = run_dir / WORK_DIR
    if not work_dir.is_dir():
        return finish("error", f"{WORK_DIR.as_posix()} does not exist")

    try:
        files, canonical, contents = stage_patch(raw_patch.decode("utf-8", errors="surrogateescape"), work_dir)
    except PatchError as exc:
        return finish(exc.status, str(exc))
    canonical_blob = canonical.encode("utf-8", errors="surrogateescape")
    atomic_write_bytes(canonical_path, canonical_blob)
    report["patch"].update(
        {
            "canonical": to_run_relative(canonical_path, run_dir),
            "sha256": hashlib.sha256(canonical_blob).hexdigest(),
            "files": files,
            **describe_patch(files, dp, sink),
        }
    )

    inputs: list[Path] = []
    for raw in [*(cand.get("reproducers") or []), *(str(p) for p in extra_inputs or [])]:
        path = Path(raw["input"] if isinstance(raw, dict) else raw)
        if (run_dir / path).is_file() and path not in inputs:
            inputs.append(path)
    report["inputs"] = [p.as_posix() for p in inputs]
    if not inputs:
        return finish("no_reproducers", "the candidate has no reproducer file to replay")

    try:
        spec = build_spec(module, sink["file"] or None, sink["function"] or None)
    except (OSError, ValueError, RuntimeError) as exc:
        return finish("build_error", f"no build spec for module {module!r}: {exc}")
    _copy_work_tree(work_dir, overlay_work)
    for rel, blob in contents.items():
        (overlay_work / rel).write_bytes(blob)
    harness_module = str(spec.get("harness_module") or module)
    report["harness_module"] = harness_module
    expected = {fingerprint, failure_fingerprint or fingerprint}

    base = build_binary(
        harness_module, spec, scratch / "bin" / f"fuzz_{harness_module}_unpatched", engine or candidate_engine(cand)
    )
    report["engine_used"] = base.get("engine_used")
    if base.get("binary") is None:
        report["replay"]["unpatched"] = {
            "status": "error",
            "reason": base.get("reason"),
            "compile": base.get("compile"),
        }
        return finish("build_error", f"the unpatched build failed: {base.get('reason')}")
    # The same engine for both builds: the two binaries differ by the patch only.
    patched_engine = base["engine_used"] if base.get("engine_used") in ("eacsl", "sanitizers") else (engine or "auto")
    patched = build_binary(
        harness_module,
        patched_build_spec(spec, run_dir, overlay_work),
        scratch / "bin" / f"fuzz_{harness_module}_patched",
        patched_engine,
    )
    if patched.get("binary") is None:
        report["replay"]["patched"] = {
            "status": "error",
            "reason": patched.get("reason"),
            "compile": patched.get("compile"),
        }
        return finish("build_error", f"the patched build failed: {patched.get('reason')}")
    if patched.get("engine_used") != base.get("engine_used"):
        return finish(
            "build_error",
            f"the builds used different engines ({base.get('engine_used')} and {patched.get('engine_used')})",
        )

    outcomes = {}
    for name, prepared in (("unpatched", base), ("patched", patched)):
        outcomes[name] = _outcome(
            replay(harness_module, inputs, scratch / f"replay_{name}", prepared, per_input_timeout), expected
        )
        report["replay"][name] = outcomes[name]
        if outcomes[name]["status"] == "error":
            return finish("error", f"the {name} replay did not run: {outcomes[name].get('reason')}")
    return finish(*decide(outcomes["unpatched"], outcomes["patched"]))


# ------------------------------------------------------------- reading a report


def _compare(run_dir: Path, cand_fp: str, record_fp: str, decision_point: dict) -> tuple[dict | None, str]:
    """The report of `cand_fp` when it agrees with a record's decision point, else None and why not."""
    rel = report_path(cand_fp)
    try:
        report = load_json_optional(Path(run_dir) / rel, None)
    except ArtifactError:
        return None, f"{rel.as_posix()} is not readable"
    if not isinstance(report, dict):
        return None, f"no decision point report ({rel.as_posix()})"
    if report.get("mode") != "decision_point_check" or report.get("fingerprint") != cand_fp:
        return None, "the report is for another candidate"
    if record_fp not in (report.get("fingerprint"), report.get("failure_fingerprint")):
        return None, "the report was run for another failure fingerprint than the record's"
    if report.get("status") != "checked":
        return None, f"the report's status is {report.get('status')!r}"
    replays = _obj(report.get("replay"))
    unpatched, patched = replays.get("unpatched"), replays.get("patched")
    if not (
        isinstance(unpatched, dict)
        and isinstance(patched, dict)
        and unpatched.get("fails_with_candidate") is True
        and patched.get("fails") is False
    ):
        return None, "the report's replay outcomes do not support its status"
    seen = _obj(report.get("decision_point"))
    try:
        line = int(decision_point.get("line") or 0)
        same = (
            normalize_file(str(seen.get("file") or "")) == normalize_file(str(decision_point.get("file") or ""))
            and int(seen.get("line") or 0) == line
            and seen.get("function") == decision_point.get("function")
        )
    except (TypeError, ValueError):
        return None, "the decision point is malformed"
    if not same:
        return None, "the report checked another decision point than the record's"
    patch = _obj(report.get("patch"))
    files = [f for f in patch.get("files") or [] if isinstance(f, dict)] if isinstance(patch.get("files"), list) else []
    if not patch_at(files, str(decision_point.get("file") or ""), line):
        return None, f"the patch is not within {LINE_SLACK} lines of the decision point"
    canonical = str(patch.get("canonical") or "")
    try:
        digest = (
            hashlib.sha256((Path(run_dir) / canonical).read_bytes()).hexdigest()
            if is_safe_relative_path(canonical)
            else None
        )
    except OSError:
        digest = None
    if digest is None or digest != patch.get("sha256"):
        return None, "the recorded patch is missing or does not match its digest"
    notes = []
    if patch.get("touches_sink_line"):
        notes.append("the patch rewrites the sink line itself")
    if patch.get("outside_decision_function"):
        notes.append("the patch also changes code outside the decision point's function")
    n_inputs = len(unpatched.get("inputs") or [])
    description = (
        f"Patch and replay: a patch at {normalize_file(str(decision_point.get('file')))}:{line} removes the failure "
        f"for {n_inputs} recorded reproducer(s) (patch sha256 {str(patch.get('sha256'))[:12]})"
        + (f"; {'; '.join(notes)}" if notes else "")
        + "."
    )
    return {
        "tool_output": rel.as_posix(),
        "description": description,
        "flags": {
            "decision_point_patch_touches_sink_line": patch.get("touches_sink_line"),
            "decision_point_patch_outside_function": bool(patch.get("outside_decision_function")),
        },
    }, ""


def agreeing_report(run_dir: Path, cand_fp: str, record_fp: str, decision_point: dict) -> dict | None:
    """
    The report on disk that makes a record's decision point `checked`: same candidate, same failure,
    same decision point, status `checked` with replay outcomes that support it, the patch within
    LINE_SLACK lines of the decision point, and the recorded patch matching its digest. Returns
    {tool_output, description, flags} for the record's evidence and the units' attempt entry.
    """
    return _compare(run_dir, cand_fp, record_fp, decision_point)[0]


def disagreement(run_dir: Path, cand_fp: str, record_fp: str, decision_point: dict) -> str:
    """Why no report agrees with the record's decision point (empty when one does)."""
    return _compare(run_dir, cand_fp, record_fp, decision_point)[1]


# ------------------------------------------------------------------------- CLI


def _decision_point_from_result(path: Path) -> dict:
    res = load_agent_result_json(path)
    record = res.get("record") if isinstance(res, dict) else None
    dp = record.get("decision_point") if isinstance(record, dict) else None
    if not isinstance(dp, dict) or not all(k in dp for k in ("file", "line", "function")):
        raise ArtifactError(f"{path}: record.decision_point with file, line and function is required")
    return dp


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check a decision point by patch and replay.")
    parser.add_argument("--fingerprint", required=True, help="candidate fingerprint (candidates.json)")
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--patch", required=True, type=Path, help="unified diff against workspace/work/")
    parser.add_argument("--result", type=Path, help="verifier result.json: its record.decision_point is checked")
    parser.add_argument("--dp-file")
    parser.add_argument("--dp-line", type=int)
    parser.add_argument("--dp-function")
    parser.add_argument("--failure-fingerprint", help="the record's fingerprint when it differs from the candidate's")
    parser.add_argument("--inputs", nargs="*", type=Path, default=[], help="reproducers besides the candidate's")
    parser.add_argument("--engine", choices=("eacsl", "sanitizers"), default=None)
    parser.add_argument("--per-input-timeout", type=int, default=DEFAULT_PER_INPUT_TIMEOUT_S)
    parser.add_argument("--keep-scratch", action="store_true", help="keep the patched copy and both binaries")
    args = parser.parse_args(argv)

    try:
        if args.result is not None:
            dp = _decision_point_from_result(args.result)
        elif args.dp_file and args.dp_line and args.dp_function:
            dp = {"file": args.dp_file, "line": args.dp_line, "function": args.dp_function}
        else:
            parser.error("give --result, or --dp-file, --dp-line and --dp-function")
        report = run_check(
            args.fingerprint,
            args.patch,
            args.agent_id,
            dp,
            failure_fingerprint=args.failure_fingerprint,
            extra_inputs=list(args.inputs),
            engine=args.engine,
            per_input_timeout=args.per_input_timeout,
            keep_scratch=args.keep_scratch,
        )
    except (ArtifactError, OSError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        return 2
    summary = {
        "mode": report["mode"],
        "status": report["status"],
        "reason": report["reason"],
        "report": report_path(args.fingerprint).as_posix(),
        "patch": {k: v for k, v in report["patch"].items() if k != "files"},
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
