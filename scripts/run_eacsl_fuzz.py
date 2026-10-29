#!/usr/bin/env python3
"""
Drives Frama-C RTE + E-ACSL source-to-source instrumentation and Clang LibFuzzer execution.

Modes:
1. `campaign`: zero-ACSL dynamic bug hunting on a module slice (`--rte=all` + `-fsanitize=fuzzer`).
   Outcomes: crash_found | timeout_found | oom_found | clean | fuzzer_error | compile_error.
   Each crash artifact is replayed once to check reproducibility and to extract the
   E-ACSL failing predicate, which yields a stable fingerprint (scripts/fingerprint.py).
2. `guardrail`: the dynamic anti-hallucination oracle used inside `/framac-wp`.
   Replays the module corpus (plus a short mutation burst) against a binary compiled with
   the proposed ACSL contract. Outcomes:
     - passed_dynamic_oracle
     - rejected_overconstrained : an agent-written annotation (requires/ensures/invariant/assert)
                                  failed on a real input
     - code_fault               : an RTE assertion failed; this is a code defect candidate,
                                  not evidence against the contract
     - guardrail_error / compile_error

All fuzzer, replay and guardrail executions run through scripts/sandbox_exec.py. The shared
corpus is never written by the guardrail: new units go to a scratch corpus directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fingerprint import detect_alarm_kind, make_fingerprint  # noqa: E402
from sandbox_exec import Limits, SandboxUnavailable, run_sandboxed  # noqa: E402

ARTIFACT_KINDS = (
    ("crash-", "crash"),
    ("oom-", "oom"),
    ("timeout-", "timeout"),
    ("leak-", "leak"),
    ("slow-unit-", "slow_unit"),
)

# Frama-C >= 26 style:
#   foo.c: In function 'parse'
#   foo.c:42: Error: Assertion failed:
#           The failing predicate is:
#           mem_access: \valid_read(p + i).
_FN_RE = re.compile(r"(?P<file>[^\s:'\"]+\.[ch]):\s*In function '(?P<function>[^']+)'")
_ERR_RE = re.compile(r"(?P<file>[^\s:'\"]+\.[ch]):(?P<line>\d+):\s*Error:\s*(?P<kind>[A-Za-z][A-Za-z _-]*?)\s+failed:?", re.IGNORECASE)
# Older style: "Assertion failed at line 42 in file foo.c." / "... in function parse."
_OLD_RE = re.compile(
    r"(?P<kind>[A-Za-z][A-Za-z _-]*?)\s+failed at line (?P<line>\d+)"
    r"(?:\s+in\s+file\s+(?P<file>[^\s]+?\.[ch]))?(?:\s+in\s+function\s+(?P<function>\w+))?",
    re.IGNORECASE,
)
_PRED_RE = re.compile(r"The failing predicate is:\s*\n?\s*(?P<pred>[^\n]+)", re.IGNORECASE)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_eacsl_failure(text: str) -> dict | None:
    """Extract the first E-ACSL failure (file, line, function, kind, predicate) from runtime output."""
    if not text:
        return None
    err = _ERR_RE.search(text)
    old = None if err else _OLD_RE.search(text)
    hit = err or old
    if not hit:
        return None
    file_ = hit.group("file") or ""
    function = hit.groupdict().get("function") or ""
    if not function:
        fns = [m for m in _FN_RE.finditer(text) if m.start() <= hit.start()]
        if fns:
            function = fns[-1].group("function")
            file_ = file_ or fns[-1].group("file")
    pred_m = _PRED_RE.search(text, hit.end())
    predicate = pred_m.group("pred").strip().rstrip(".") if pred_m else ""
    kind = hit.group("kind").strip().lower().replace(" ", "_")
    alarm = detect_alarm_kind(predicate)
    return {
        "file": file_ or "unknown",
        "line": int(hit.group("line")),
        "function": function or "unknown_function",
        "kind": kind,
        "alarm_kind": alarm or None,
        "is_rte": bool(alarm) or predicate.lower().startswith("rte"),
        "predicate": predicate,
    }


def compile_eacsl_binary(
    sources: list[str],
    out_bin: Path,
    machdep: str = "gcc_x86_64",
    cppflags: str = "-I.",
    rte_flags: str = "all",
    fuzzer_flag: bool = True,
) -> dict:
    out_bin.parent.mkdir(parents=True, exist_ok=True)
    instrumented_c = out_bin.with_suffix(".instrumented.c")

    cflags = f"-g -O1 {cppflags}"
    ldflags = ""
    if fuzzer_flag:
        cflags = f"-fsanitize=fuzzer {cflags}"
        ldflags = "-fsanitize=fuzzer"

    cmd = [
        "e-acsl-gcc.sh",
        "--compiler=clang",
        f"--machdep={machdep}",
        f"--rte={rte_flags}",
        f"--cflag={cflags}",
        "-o", str(out_bin),
        "-O", str(instrumented_c),
    ]
    if ldflags:
        cmd.append(f"--ldflag={ldflags}")
    cmd.extend(sources)

    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    return {
        "returncode": proc.returncode,
        "command": " ".join(cmd),
        "binary": str(out_bin),
        "instrumented_source": str(instrumented_c),
        "stdout": proc.stdout[-4000:],
        "stderr": proc.stderr[-4000:],
    }


def _artifact_kind(name: str) -> str | None:
    for prefix, kind in ARTIFACT_KINDS:
        if name.startswith(prefix):
            return kind
    return None


def replay_artifact(binary: Path, artifact: Path, scratch: Path, timeout_s: int = 60) -> dict:
    """Replay one input in the sandbox; report the parsed failure and whether it reproduced."""
    res = run_sandboxed(
        [str(binary.resolve()), "-runs=1", str(artifact.resolve())],
        writable=[scratch],
        timeout_s=timeout_s,
        limits=Limits(cpu_seconds=timeout_s * 2),
    )
    out = res.stdout + "\n" + res.stderr
    return {
        "reproduced": res.returncode != 0 or res.timed_out,
        "returncode": res.returncode,
        "timed_out": res.timed_out,
        "failure": parse_eacsl_failure(out),
        "sandbox": res.sandbox,
        "log_tail": out[-3000:],
    }


def classify_campaign(returncode: int, timed_out: bool, artifacts: list[dict]) -> str:
    kinds = {a["kind"] for a in artifacts}
    if "crash" in kinds or "leak" in kinds:
        return "crash_found"
    if "timeout" in kinds:
        return "timeout_found"
    if "oom" in kinds:
        return "oom_found"
    if timed_out:
        return "fuzzer_error"
    if returncode == 0:
        return "clean"
    return "fuzzer_error"


def run_fuzz_campaign(
    binary: Path,
    corpus_dir: Path,
    artifacts_dir: Path,
    max_time: int = 60,
    dict_file: Path | None = None,
    per_input_timeout: int = 10,
    rss_limit_mb: int = 2048,
    extra_corpus: list[Path] | None = None,
) -> dict:
    """
    `corpus_dir` receives new units (writable); `extra_corpus` directories are read-only
    seed inputs (e.g. the shared module corpus when a breaker works in its own scratch).
    """
    corpus_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    scratch = artifacts_dir.parent / f".scratch_{artifacts_dir.name}"
    scratch.mkdir(parents=True, exist_ok=True)
    before = {p.name for p in artifacts_dir.iterdir()}

    cmd = [
        str(binary.resolve()),
        f"-max_total_time={max_time}",
        f"-timeout={per_input_timeout}",
        f"-rss_limit_mb={rss_limit_mb}",
        f"-artifact_prefix={artifacts_dir.resolve()}/",
        "-print_final_stats=1",
        str(corpus_dir.resolve()),
    ]
    cmd += [str(Path(d).resolve()) for d in (extra_corpus or []) if Path(d).is_dir()]
    if dict_file and dict_file.exists():
        cmd.insert(1, f"-dict={dict_file.resolve()}")

    res = run_sandboxed(
        cmd,
        writable=[scratch, corpus_dir, artifacts_dir],
        timeout_s=max_time + 180,
        limits=Limits(cpu_seconds=(max_time + 180) * 2),
    )
    combined_out = res.stdout + "\n" + res.stderr

    artifacts: list[dict] = []
    for p in sorted(artifacts_dir.iterdir()):
        kind = _artifact_kind(p.name)
        if not kind or p.name in before or p.is_symlink() or not p.is_file():
            continue
        entry = {
            "artifact": str(p),
            "kind": kind,
            "sha256": sha256_file(p),
            "size_bytes": p.stat().st_size,
            "failure": None,
            "fingerprint": None,
            "reproducible": None,
        }
        if kind in ("crash", "leak"):
            replay = replay_artifact(binary, p, scratch)
            failure = replay["failure"] or parse_eacsl_failure(combined_out)
            entry["reproducible"] = replay["reproduced"]
            entry["replay_log_tail"] = replay["log_tail"]
            entry["failure"] = failure
            if failure:
                entry["fingerprint"] = make_fingerprint(
                    failure["file"], failure["function"], failure["alarm_kind"] or failure["kind"], failure["predicate"]
                )
        artifacts.append(entry)

    status = classify_campaign(res.returncode, res.timed_out, artifacts)
    return {
        "status": status,
        "returncode": res.returncode,
        "timed_out": res.timed_out,
        "sandbox": res.sandbox,
        "artifacts": artifacts,
        "log_tail": combined_out[-4000:],
    }


def classify_guardrail(returncode: int, timed_out: bool, output: str) -> dict:
    if returncode == 0 and not timed_out:
        return {"status": "passed_dynamic_oracle"}
    failure = parse_eacsl_failure(output)
    if failure is None:
        return {"status": "guardrail_error", "reason": "Binary failed without a recognizable E-ACSL failure report.", "failure": None}
    if failure["is_rte"]:
        return {
            "status": "code_fault",
            "reason": "An RTE assertion failed on a real input: code defect candidate, not evidence against the proposed contract.",
            "fingerprint": make_fingerprint(failure["file"], failure["function"], failure["alarm_kind"] or failure["kind"], failure["predicate"]),
            "failure": failure,
        }
    return {
        "status": "rejected_overconstrained",
        "reason": "A proposed ACSL annotation failed at runtime on a real corpus/test input.",
        "failure": failure,
    }


def run_guardrail_check(binary: Path, corpus_dir: Path, scratch_dir: Path, runs: int = 0, timeout_s: int = 600) -> dict:
    """
    Replay the shared corpus (read-only) plus `runs` mutations. New units land in a scratch
    corpus and crash artifacts in scratch, so the guardrail never mutates shared state.
    """
    scratch_dir.mkdir(parents=True, exist_ok=True)
    scratch_corpus = scratch_dir / "new_units"
    scratch_corpus.mkdir(parents=True, exist_ok=True)
    corpus_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        str(binary.resolve()),
        f"-runs={runs}",
        f"-artifact_prefix={scratch_dir.resolve()}/",
        str(scratch_corpus.resolve()),
        str(corpus_dir.resolve()),
    ]
    res = run_sandboxed(cmd, writable=[scratch_dir], timeout_s=timeout_s, limits=Limits(cpu_seconds=timeout_s * 2))
    combined_out = res.stdout + "\n" + res.stderr
    verdict = classify_guardrail(res.returncode, res.timed_out, combined_out)
    verdict.update({"returncode": res.returncode, "timed_out": res.timed_out, "sandbox": res.sandbox, "corpus_dir": str(corpus_dir)})
    if verdict["status"] != "passed_dynamic_oracle":
        verdict["runtime_trace"] = combined_out[-4000:]
    return verdict


def main() -> int:
    parser = argparse.ArgumentParser(description="Run E-ACSL + LibFuzzer Campaign or Dynamic Contract Guardrail.")
    sub = parser.add_subparsers(dest="mode", required=True)

    p_camp = sub.add_parser("campaign")
    p_camp.add_argument("--sources", nargs="+", required=True)
    p_camp.add_argument("--out-bin", type=Path, required=True)
    p_camp.add_argument("--corpus-dir", type=Path, required=True, help="Writable corpus directory (receives new units)")
    p_camp.add_argument("--extra-corpus", type=Path, nargs="*", default=[], help="Read-only seed corpus directories")
    p_camp.add_argument("--artifacts-dir", type=Path, required=True)
    p_camp.add_argument("--max-time", type=int, default=60)
    p_camp.add_argument("--per-input-timeout", type=int, default=10)
    p_camp.add_argument("--dict", type=Path, default=None)
    p_camp.add_argument("--machdep", default="gcc_x86_64")
    p_camp.add_argument("--cppflags", default="-I.")
    p_camp.add_argument("--rte", default="all")
    p_camp.add_argument("--module", default="")
    p_camp.add_argument("--out-json", type=Path, required=True)

    p_guard = sub.add_parser("guardrail")
    p_guard.add_argument("--sources", nargs="+", required=True)
    p_guard.add_argument("--out-bin", type=Path, required=True)
    p_guard.add_argument("--corpus-dir", type=Path, required=True)
    p_guard.add_argument("--scratch-dir", type=Path, default=None, help="Agent scratch dir (default: next to --out-bin)")
    p_guard.add_argument("--extra-runs", type=int, default=200)
    p_guard.add_argument("--machdep", default="gcc_x86_64")
    p_guard.add_argument("--cppflags", default="-I.")
    p_guard.add_argument("--out-json", type=Path, required=True)

    args = parser.parse_args()

    try:
        if args.mode == "campaign":
            comp = compile_eacsl_binary(args.sources, args.out_bin, args.machdep, args.cppflags, args.rte, True)
            if comp["returncode"] != 0:
                res = {"mode": "campaign", "module": args.module, "status": "compile_error", "compile": comp}
            else:
                fuzz = run_fuzz_campaign(args.out_bin, args.corpus_dir, args.artifacts_dir, args.max_time, args.dict,
                                         args.per_input_timeout, extra_corpus=args.extra_corpus)
                res = {"mode": "campaign", "module": args.module, "sources": args.sources, "compile": comp, **fuzz}
        else:
            comp = compile_eacsl_binary(args.sources, args.out_bin, args.machdep, args.cppflags, "all", True)
            if comp["returncode"] != 0:
                res = {"mode": "guardrail", "status": "compile_error", "compile": comp}
            else:
                scratch = args.scratch_dir or args.out_bin.parent / f"{args.out_bin.name}_guard_scratch"
                guard = run_guardrail_check(args.out_bin, args.corpus_dir, scratch, args.extra_runs)
                res = {"mode": "guardrail", "compile": comp, **guard}
    except SandboxUnavailable as exc:
        res = {"mode": args.mode, "status": "sandbox_unavailable", "reason": str(exc)}

    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in res.items() if k not in ("compile", "log_tail", "runtime_trace")}, indent=2))
    return 3 if res.get("status") == "sandbox_unavailable" else 0


if __name__ == "__main__":
    sys.exit(main())
