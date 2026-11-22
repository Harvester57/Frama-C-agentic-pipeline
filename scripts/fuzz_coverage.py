"""
Coverage of the fuzz corpus: each input replayed on the coverage build, the llvm-cov export summarized per
target function, and the coverage report of a module (D3, moved out of run_eacsl_fuzz).

Callers reach these functions as `fuzz_coverage.<name>` (D12), so a test patch on this module applies to
every caller. No module here imports run_eacsl_fuzz.
"""

from __future__ import annotations

import contextlib
import json
import os
import posixpath
import re
import shlex
import shutil
import subprocess
import time
from collections import Counter, deque
from pathlib import Path

import fuzz_build
import sandbox_exec
from fingerprint import normalize_file
from framac_common import utc_now
from fuzz_common import (
    DEFAULT_PER_INPUT_TIMEOUT_S,
    _collect_inputs,
    derive_seed,
    replay_artifact_dir,
    sha256_file,
)
from resources import FUZZ_RSS_LIMIT_MB
from sandbox_exec import Limits

# `coverage` mode. Time limits only cut a replay short, and the report then says `partial`.
COVERAGE_BATCH_SIZE = 256
# Failing inputs never end the replay (only COVERAGE_MAX_TIME_S does); this many are listed in
# `failed_inputs` with their log tail, the rest only counted. Fixed, never derived from the machine.
COVERAGE_LISTED_FAILED_INPUTS = 16
COVERAGE_MAX_TIME_S = 1200
COVERAGE_TOOL_TIMEOUT_S = 300
COVERAGE_MAX_UNCOVERED_RANGES = 32
# The build capture's snapshot of the build image's libraries and headers (build_capture.py) is not
# target code either: under the run directory's mount, or relative to it.
COVERAGE_SNAPSHOT_ROOT = "workspace/snapshot/root/"
COVERAGE_EXTERNAL_PREFIXES = ("/usr/", "/lib/", "/opt/framac-pipeline/", f"/framac-run/{COVERAGE_SNAPSHOT_ROOT}")
LLVM_COV_CODE_REGION = 0


def _written_profiles(profile_dir: Path) -> list[str]:
    """
    Raw profiles under `profile_dir` that hold data. The profile runtime creates its file empty at
    process start and fills it at exit, so a target that calls `_exit(0)` returns 0 and leaves an
    empty file behind.
    """
    return sorted(str(f.resolve()) for f in profile_dir.rglob("*.profraw") if f.stat().st_size > 0)


def replay_for_coverage(
    binary: Path,
    inputs: list[Path],
    profile_dir: Path,
    scratch: Path,
    *,
    module: str = "",
    per_input_timeout: int = DEFAULT_PER_INPUT_TIMEOUT_S,
    max_time: int = COVERAGE_MAX_TIME_S,
    batch_size: int = COVERAGE_BATCH_SIZE,
    listed_failed: int = COVERAGE_LISTED_FAILED_INPUTS,
    last_inputs: list[Path] | None = None,
) -> dict:
    """
    Replay each input once on a coverage build, in batches. A process that dies writes no profile,
    so the failing input is taken out of its batch and the rest of the batch runs again: libFuzzer
    prints `Running: <input>` before each input and `Executed <input>` after, so the input it was
    running when it died is known, and one rerun per failure suffices. When the output does not name
    it, the batch is split in two until the failing input stands alone. Failures never end the
    replay; only `max_time` does, and what is left is reported as not replayed. The first
    `listed_failed` failures are listed with their log tail, the rest only counted (`failed`).
    `last_inputs` (inputs expected to fail) replay after every other input, in batches of their own.
    """
    seed = derive_seed(binary, module)
    pending = deque(
        group[i : i + batch_size] for group in (inputs, last_inputs or []) for i in range(0, len(group), batch_size)
    )
    deadline = time.monotonic() + max_time
    min_wall = 2 * int(per_input_timeout) + 10
    replayed = 0
    failed: list[dict] = []
    n_failed = 0
    batch_no = 0

    def _fail(path: Path, res) -> None:
        nonlocal n_failed
        n_failed += 1
        if len(failed) < listed_failed:
            failed.append(
                {
                    "input": path.as_posix(),
                    "sha256": sha256_file(path),
                    "returncode": res.returncode,
                    "timed_out": res.timed_out,
                    "log_tail": (res.stdout + "\n" + res.stderr)[-1000:],
                }
            )

    while pending:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        batch = pending.popleft()
        batch_no += 1
        batch_dir = profile_dir / f"batch-{batch_no}"
        wall = min(int(per_input_timeout) * len(batch) + 30, max(int(remaining), min_wall))
        res = sandbox_exec.run_sandboxed(
            [
                str(Path(binary).resolve()),
                f"-timeout={per_input_timeout}",
                f"-rss_limit_mb={FUZZ_RSS_LIMIT_MB}",
                f"-seed={seed}",
                f"-artifact_prefix={replay_artifact_dir(scratch)}/",
                *[str(Path(f).resolve()) for f in batch],
            ],
            writable=[scratch, batch_dir],
            timeout_s=wall,
            limits=Limits(cpu_seconds=wall * 2, ignore_sigpipe=True),
            extra_env={"LLVM_PROFILE_FILE": f"{batch_dir.resolve()}/%p.profraw"},
        )
        if res.returncode == 0 and not res.timed_out and _written_profiles(batch_dir):
            replayed += len(batch)
            continue
        shutil.rmtree(batch_dir, ignore_errors=True)
        if len(batch) == 1:
            _fail(batch[0], res)
            continue
        culprit = _input_running_at_exit(res.stdout + "\n" + res.stderr, batch)
        if culprit is not None:
            _fail(batch[culprit], res)
            rest = batch[:culprit] + batch[culprit + 1 :]
            if rest:
                pending.appendleft(rest)
            continue
        middle = len(batch) // 2
        pending.appendleft(batch[middle:])
        pending.appendleft(batch[:middle])
    return {
        "seed": seed,
        "replayed": replayed,
        "failed_inputs": failed,
        "failed": n_failed,
        "not_replayed": sum(len(b) for b in pending),
    }


_RUNNING_RE = re.compile(r"^(?:Running: (?P<run>.+?)|Executed (?P<done>.+?) in \d+ ms)\s*$", re.MULTILINE)


def _input_running_at_exit(output: str, batch: list[Path]) -> int | None:
    """
    The index in `batch` of the input libFuzzer was running when its process ended (its last
    `Running: <input>` line has no `Executed <input>` after it), or None when the output does not say.
    """
    last_running: str | None = None
    for m in _RUNNING_RE.finditer(output or ""):
        if m.group("run") is not None:
            last_running = m.group("run")
        elif m.group("done") == last_running:
            last_running = None
    if last_running is None:
        return None
    for i, path in enumerate(batch):
        if str(Path(path).resolve()) == last_running:
            return i
    return None


COVERAGE_TRUNCATED_MAPPING = "truncated coverage data"
_INCLUDE_RE = re.compile(r'^\s*#\s*include\s*([<"])([^>"]+)[>"]')


def _includes_inside_braces(text: str) -> list[tuple[str, str]]:
    """(delimiter, header) of every `#include` written inside braces, comments and literals skipped."""
    found: list[tuple[str, str]] = []
    depth = 0
    in_comment = False
    for line in text.splitlines():
        if not in_comment and depth > 0:
            m = _INCLUDE_RE.match(line)
            if m:
                found.append((m.group(1), m.group(2)))
                continue
        i, n = 0, len(line)
        while i < n:
            if in_comment:
                end = line.find("*/", i)
                if end < 0:
                    break
                in_comment, i = False, end + 2
                continue
            c = line[i]
            if line.startswith("//", i):
                break
            if line.startswith("/*", i):
                in_comment, i = True, i + 2
                continue
            if c in "\"'":
                i += 1
                while i < n and line[i] != c:
                    i += 2 if line[i] == "\\" else 1
            elif c == "{":
                depth += 1
            elif c == "}":
                depth = max(0, depth - 1)
            i += 1
    return found


def in_function_includes(sources: list[str], cppflags: str = "") -> list[str]:
    """
    The headers the sources include inside a function body, as `-include` operands: a quoted one by
    its path next to its source, an angle one by name. A header that does not preprocess on its own
    with `cppflags` (one for another platform, under an #if not taken) is left out.
    """
    out: list[str] = []
    probed: set[str] = set()
    for src in sources:
        try:
            text = Path(src).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for delim, header in _includes_inside_braces(text):
            name = header
            if delim == '"' and (Path(src).parent / header).is_file():
                name = (Path(src).parent / header).as_posix()
            if name in probed:
                continue
            probed.add(name)
            probe = subprocess.run(
                ["clang", "-E", "-x", "c", *shlex.split(cppflags), "-include", name, "-o", os.devnull, "-"],
                input="",
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if probe.returncode == 0:
                out.append(name)
    return out


def _export_coverage(binary: Path, profile_dir: Path, scratch: Path) -> tuple[dict | None, str | None]:
    """
    Merge the raw profiles and export them as llvm-cov JSON: (export, None) or (None, error). The
    LLVM tools run in the sandbox because the target's own process wrote the profiles they parse.
    """
    merged = (scratch / "merged.profdata").resolve()
    export_path = (scratch / "export.json").resolve()
    limits = Limits(cpu_seconds=COVERAGE_TOOL_TIMEOUT_S * 2)
    res = sandbox_exec.run_sandboxed(
        ["llvm-profdata", "merge", "-sparse", "-o", str(merged), *_written_profiles(profile_dir)],
        writable=[scratch],
        timeout_s=COVERAGE_TOOL_TIMEOUT_S,
        limits=limits,
    )
    if res.returncode != 0 or res.timed_out:
        return None, f"llvm-profdata merge failed ({res.returncode}): {res.stderr[-1000:]}"
    # llvm-cov export only writes to stdout, which the sandbox truncates, so redirect it to a file.
    res = sandbox_exec.run_sandboxed(
        [
            "/bin/sh",
            "-c",
            'exec "$@" > "$0"',
            str(export_path),
            "llvm-cov",
            "export",
            "-skip-expansions",
            "-skip-branches",
            f"-instr-profile={merged}",
            str(Path(binary).resolve()),
        ],
        writable=[scratch],
        timeout_s=COVERAGE_TOOL_TIMEOUT_S,
        limits=limits,
    )
    if res.returncode != 0 or res.timed_out:
        return None, f"llvm-cov export failed ({res.returncode}): {res.stderr[-1000:]}"
    try:
        return json.loads(export_path.read_text(encoding="utf-8")), None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, f"llvm-cov export is unreadable: {exc}"


def _coverage_file_role(path: str) -> str:
    """
    `target`, `harness` (the generated entry point or link-repair stub files) or `external`
    (system and pipeline headers, and the build capture's snapshot of the build image, wherever
    the run directory is mounted).
    """
    norm = path.replace("\\", "/")
    if norm.startswith(COVERAGE_EXTERNAL_PREFIXES) or f"/{COVERAGE_SNAPSHOT_ROOT}" in f"/{norm}":
        return "external"
    base = posixpath.basename(norm)
    if (
        "/workspace/harnesses/" in f"/{norm}"
        or base.startswith("harness_")
        or base in (fuzz_build.LINK_STUBS_FILE, fuzz_build.LINK_GLOBALS_FILE)
        or "_link_globals/" in f"/{norm}"
    ):
        return "harness"
    return "target"


def _merge_line_ranges(ranges: list[tuple[int, int]]) -> list[list[int]]:
    merged: list[list[int]] = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return merged


def summarize_coverage_export(export: dict) -> dict:
    """
    Per-function reach of the target's own code from an `llvm-cov export` document. Copies of a
    header's static function in several translation units count as one function: their executions
    add up, and a region is covered when any copy ran it. Functions are keyed by file as well,
    because same-named statics in different files are different functions.
    """
    merged: dict[tuple[str, int, str], dict] = {}
    excluded: Counter[str] = Counter()
    for fn in export["data"][0].get("functions") or []:
        regions = fn.get("regions") or []
        filenames = fn.get("filenames") or []
        if not regions or not filenames:
            continue
        main_id = regions[0][5]
        path = posixpath.normpath(filenames[main_id])
        role = _coverage_file_role(path)
        if role != "target":
            excluded[role] += 1
            continue
        name = str(fn.get("name") or "").rpartition(":")[2]
        entry = merged.setdefault(
            (normalize_file(path), regions[0][0], name),
            {"executions": 0, "regions": {}, "main_regions": set()},
        )
        entry["executions"] += int(fn.get("count") or 0)
        # Distinct regions can share a span: each macro expansion has its own file id with the same
        # file and span, and zero-width regions repeat a point. The ordinal keeps those apart, while
        # the copies of a function in other translation units still line up region by region.
        seen: Counter[tuple] = Counter()
        for line_start, col_start, line_end, col_end, count, file_id, _expanded, kind in regions:
            if kind == LLVM_COV_CODE_REGION:
                span = (file_id, filenames[file_id], line_start, col_start, line_end, col_end)
                key = (*span, seen[span])
                seen[span] += 1
                entry["regions"][key] = entry["regions"].get(key, 0) + count
                if file_id == main_id:
                    entry["main_regions"].add(key)

    functions: list[dict] = []
    for (file_, line, name), entry in sorted(merged.items()):
        covered = sum(1 for count in entry["regions"].values() if count > 0)
        record: dict = {
            "function": name,
            "file": file_,
            "line": line,
            "executions": entry["executions"],
            "regions": {"total": len(entry["regions"]), "covered": covered},
        }
        if entry["executions"] > 0:
            # Only for functions that ran: an unreached one is uncovered from its first line to its last.
            missed = [(k[2], k[4]) for k in entry["main_regions"] if entry["regions"][k] == 0]
            record["uncovered_lines"] = _merge_line_ranges(missed)[:COVERAGE_MAX_UNCOVERED_RANGES]
        functions.append(record)
    return {
        "totals": {
            "functions": {"total": len(functions), "reached": sum(1 for f in functions if f["executions"] > 0)},
            "regions": {
                "total": sum(f["regions"]["total"] for f in functions),
                "covered": sum(f["regions"]["covered"] for f in functions),
            },
        },
        "functions": functions,
        "excluded_functions": dict(sorted(excluded.items())),
    }


def coverage_report(
    module: str,
    sources: list[str],
    out_bin: Path,
    corpus_dirs: list[Path],
    scratch: Path,
    *,
    cppflags: str = "-I.",
    ldflags: str = "",
    per_input_timeout: int = DEFAULT_PER_INPUT_TIMEOUT_S,
    max_time: int = COVERAGE_MAX_TIME_S,
    use_cache: bool = True,
    known_crash_dirs: list[Path] | None = None,
    dag_path: Path | str | None = None,
    link_module: str | None = None,
) -> dict:
    """
    Which target functions and regions the corpus executes. `partial` means some inputs failed or
    were not replayed, so reached counts are lower bounds. The report says what the corpus reached;
    it decides no verdict and nothing in the ledger reads it.

    The build gets the link repair of the fuzz builds (`fuzz_build.build_coverage_binary`, driven by
    `dag_path`, globals placed for harness module `link_module`): a module whose sources alone do not
    link (nginx run-5, ngx_core_module in src/core/nginx.c) is measured on the sources that link.
    `sources` in the report is what was compiled last, and `link_repair` says what the repair added.

    Corpus directories replay in the order given. An input whose content is a file under
    `known_crash_dirs` (the campaign's crash artifacts) replays last, in batches of its own, so
    inputs that crash the fuzz binary cannot use up the time of the rest (`inputs.known_crash`
    counts them). They still replay: a crash an E-ACSL or sanitizer check caught can run to the end
    on the plain coverage build and add coverage.
    """
    files, _missing = _collect_inputs(corpus_dirs)
    known = _known_crash_digests(known_crash_dirs or [])
    known_files = [f for f in files if known and sha256_file(f) in known]
    if known_files:
        known_set = set(known_files)
        files = [f for f in files if f not in known_set]
    report: dict = {
        "mode": "coverage",
        "module": module,
        "status": "coverage_error",
        "engine": "clang-source-coverage",
        "generated_at": utc_now(),
        "sources": list(sources),
        "corpus_dirs": [Path(d).as_posix() for d in corpus_dirs],
        "per_input_timeout": per_input_timeout,
        "rss_limit_mb": FUZZ_RSS_LIMIT_MB,
        "inputs": {
            "total": len(files) + len(known_files),
            "replayed": 0,
            "failed": 0,
            "not_replayed": len(files) + len(known_files),
            "known_crash": len(known_files),
        },
    }
    if known_crash_dirs:
        report["known_crash_dirs"] = [Path(d).as_posix() for d in known_crash_dirs]
    if not files and not known_files:
        report.update(status="no_inputs", reason="the corpus has no inputs: nothing was measured")
        return report
    pre_included: list[str] = []
    while True:
        flags = " ".join([cppflags, *(f"-include {shlex.quote(h)}" for h in pre_included)])
        built = fuzz_build.build_coverage_binary(
            sources, out_bin, flags, ldflags, use_cache=use_cache, dag_path=dag_path, link_module=link_module
        )
        comp = built["compile"]
        report["compile"] = comp
        # A rebuild below starts from the sources that linked, so it never repeats the failing link.
        sources = built["sources"]
        report["sources"] = list(sources)
        if built.get("link_repair"):
            report["link_repair"] = built["link_repair"]
        if comp["returncode"] != 0:
            report.update(status="compile_error", reason="the coverage build failed")
            return report
        binary = Path(comp["binary"])
        report["binary"] = str(binary)

        # Target code writes into this directory: start empty so that old files are never merged.
        profile_dir = scratch / "profiles"
        shutil.rmtree(profile_dir, ignore_errors=True)
        profile_dir.mkdir(parents=True, exist_ok=True)
        replay = replay_for_coverage(
            binary,
            files,
            profile_dir,
            scratch,
            module=module,
            per_input_timeout=per_input_timeout,
            max_time=max_time,
            last_inputs=known_files,
        )
        report["seed"] = replay["seed"]
        report["failed_inputs"] = replay["failed_inputs"]
        # `failed_inputs` lists the first failures only; the counts below are complete.
        report["failed_inputs_unlisted"] = replay["failed"] - len(replay["failed_inputs"])
        report["inputs"] = {
            "total": len(files) + len(known_files),
            "replayed": replay["replayed"],
            "failed": replay["failed"],
            "not_replayed": replay["not_replayed"],
            "known_crash": len(known_files),
        }
        if not replay["replayed"]:
            report["reason"] = "no input replayed to completion, so there is no profile"
            return report
        export, error = _export_coverage(binary, profile_dir, scratch)
        if export is not None:
            break
        report["reason"] = error
        if pre_included or COVERAGE_TRUNCATED_MAPPING not in str(error):
            return report
        # LLVM 19 writes a coverage mapping llvm-cov cannot read when a header is included inside a
        # function body (cryptolib: `#include <malloc.h>` in Crypto_check_buffer_size). Including those
        # headers first makes the in-body include expand to nothing behind its include guard.
        pre_included = in_function_includes(sources, cppflags)
        if not pre_included:
            return report
        report["pre_included"] = pre_included
    report.pop("reason", None)
    try:
        summary = summarize_coverage_export(export)
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        report["reason"] = f"unexpected llvm-cov export shape: {exc!r}"
        return report
    if not summary["functions"]:
        report["reason"] = "the coverage mapping lists no function of the target"
        return report
    report.update(summary)
    report["status"] = "partial" if replay["failed"] or replay["not_replayed"] else "ok"
    return report


def _known_crash_digests(dirs: list[Path]) -> set[str]:
    """sha256 of every file under `dirs` (crash artifacts: workspace/crashes/<module>/); missing dirs give none."""
    digests: set[str] = set()
    for d in dirs:
        root = Path(d)
        if not root.is_dir():
            continue
        for f in root.rglob("*"):
            with contextlib.suppress(OSError):
                if f.is_file():
                    digests.add(sha256_file(f))
    return digests
