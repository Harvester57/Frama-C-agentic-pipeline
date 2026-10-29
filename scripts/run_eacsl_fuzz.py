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
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from build_callgraph_dag import extract_functions_from_code  # noqa: E402
from fingerprint import detect_alarm_kind, make_fingerprint, normalize_file  # noqa: E402
from sandbox_exec import Limits, SandboxUnavailable, run_sandboxed  # noqa: E402

SANITIZER_RUNTIME_ENV = {
    "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1",
    "ASAN_OPTIONS": "abort_on_error=1",
}
_TEST_UNIT_WRITTEN_RE = re.compile(r"Test unit written to\s+(?P<path>\S+)")

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

# UBSan format:
#   SyncMem.c:819:9: runtime error: index 1025 out of bounds for type 'char[1024]'
_UBSAN_RE = re.compile(
    r"(?P<file>[^\s:'\"]+\.[ch]):(?P<line>\d+)(?::\d+)?:\s*runtime error:\s*(?P<pred>[^\n]+)",
    re.IGNORECASE,
)

# ASan header:
#   ==123==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x...
_ASAN_ERR_RE = re.compile(
    r"ERROR:\s*AddressSanitizer:\s*(?P<kind>[A-Za-z0-9_-]+)",
    re.IGNORECASE,
)
_ASAN_OP_RE = re.compile(
    r"^(?P<op>(?:READ|WRITE)\s+of\s+size\s+\d+)",
    re.MULTILINE,
)
# Sanitizer stack frame:
#   #0 0x555555 in UpdateSyncMem /path/to/SyncMem.c:827:5
_STACK_FRAME_RE = re.compile(
    r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+(?P<function>[A-Za-z_][A-Za-z0-9_]*)\s+(?P<file>[^\s():]+\.[ch]):(?P<line>\d+)"
)


def _map_sanitizer_alarm_kind(kind_or_msg: str) -> str:
    low = (kind_or_msg or "").lower()
    if "out of bounds" in low:
        return "index_bound"
    if "signed integer overflow" in low or "cannot be represented in type" in low:
        return "signed_overflow"
    if "unsigned integer overflow" in low:
        return "unsigned_overflow"
    if "shift" in low:
        return "shift"
    if "division by zero" in low or "divide by zero" in low or "fpe" in low:
        return "division_by_zero"
    if "overlap" in low:
        return "separation"
    if "use-after-free" in low or "use-after-scope" in low or "use-after-return" in low:
        return "dangling_pointer"
    if "bad-free" in low or "attempting free" in low:
        return "freeable"
    if "bool" in low:
        return "bool_value"
    if "nan" in low or "inf" in low:
        return "is_nan_or_infinite"
    return "mem_access"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _resolve_function_at_line(file_path: str, line: int) -> str:
    """Resolve the enclosing C function at `file_path:line` using token-based span extraction."""
    if not file_path or line <= 0:
        return "unknown_function"
    norm = normalize_file(file_path)
    candidates: list[Path] = []
    for cand in (
        Path(file_path),
        Path(norm),
        Path("workspace/work") / norm,
        Path("workspace/baseline") / norm,
    ):
        if cand.is_file() and cand not in candidates:
            candidates.append(cand)
    if not candidates and Path("workspace/work").is_dir():
        bname = Path(norm).name
        matches = list(Path("workspace/work").rglob(bname))
        if len(matches) == 1:
            candidates.append(matches[0])
    for cpath in candidates:
        try:
            raw = cpath.read_text(encoding="utf-8", errors="replace")
            for fn in extract_functions_from_code(raw, path=str(cpath)):
                if int(fn.get("line", 0)) <= line <= int(fn.get("end_line", 0)):
                    return fn.get("name") or "unknown_function"
        except Exception:
            continue
    return "unknown_function"


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
    line_ = int(hit.group("line"))
    function = hit.groupdict().get("function") or ""
    if not function:
        fns = [m for m in _FN_RE.finditer(text) if m.start() <= hit.start()]
        if fns:
            function = fns[-1].group("function")
            file_ = file_ or fns[-1].group("file")
    if not function or function == "unknown_function":
        function = _resolve_function_at_line(file_, line_)
    pred_m = _PRED_RE.search(text, hit.end())
    predicate = pred_m.group("pred").strip().rstrip(".") if pred_m else ""
    kind = hit.group("kind").strip().lower().replace(" ", "_")
    alarm = detect_alarm_kind(predicate)
    return {
        "file": file_ or "unknown",
        "line": line_,
        "function": function or "unknown_function",
        "kind": kind,
        "alarm_kind": alarm or None,
        "is_rte": bool(alarm) or predicate.lower().startswith("rte"),
        "predicate": predicate,
    }


def parse_sanitizer_failure(text: str) -> dict | None:
    """Extract the first UBSan or ASan runtime failure from LibFuzzer/sanitizer output."""
    if not text:
        return None

    frames = list(_STACK_FRAME_RE.finditer(text))
    non_harness_frames = [
        m for m in frames
        if not Path(m.group("file")).name.startswith("harness_")
        and not m.group("function").startswith(("__interceptor_", "__asan_", "LLVMFuzzerTestOneInput"))
    ]
    best_frame = (non_harness_frames or frames or [None])[0]

    ub = _UBSAN_RE.search(text)
    if ub:
        file_ = ub.group("file")
        line_ = int(ub.group("line"))
        pred = ub.group("pred").strip().rstrip(".")
        fn = "unknown_function"
        for m in frames:
            if Path(m.group("file")).name == Path(file_).name and int(m.group("line")) == line_:
                fn = m.group("function")
                break
        if fn == "unknown_function" and best_frame is not None:
            fn = best_frame.group("function")
        if fn == "unknown_function":
            fn = _resolve_function_at_line(file_, line_)
        alarm = _map_sanitizer_alarm_kind(pred)
        return {
            "file": file_,
            "line": line_,
            "function": fn,
            "kind": "ubsan_runtime_error",
            "alarm_kind": alarm,
            "is_rte": True,
            "predicate": f"rte: {alarm}: {pred}",
        }

    asan = _ASAN_ERR_RE.search(text)
    if asan:
        asan_kind = asan.group("kind").strip()
        op_m = _ASAN_OP_RE.search(text, asan.end())
        op_txt = f" ({op_m.group('op')})" if op_m else ""
        alarm = _map_sanitizer_alarm_kind(asan_kind)
        file_ = best_frame.group("file") if best_frame else "unknown"
        line_ = int(best_frame.group("line")) if best_frame else 0
        fn = best_frame.group("function") if best_frame else "unknown_function"
        if fn == "unknown_function" and file_ != "unknown" and line_ > 0:
            fn = _resolve_function_at_line(file_, line_)
        pred = f"AddressSanitizer: {asan_kind}{op_txt}"
        return {
            "file": file_,
            "line": line_,
            "function": fn,
            "kind": "asan_" + asan_kind.lower().replace("-", "_"),
            "alarm_kind": alarm,
            "is_rte": True,
            "predicate": f"rte: {alarm}: {pred}",
        }

    return None


def parse_runtime_failure(text: str) -> dict | None:
    """Parse an E-ACSL failure report, falling back to ASan/UBSan runtime failure parsing."""
    return parse_eacsl_failure(text) or parse_sanitizer_failure(text)


def _discover_slice_functions(sources: list[str], explicit_functions: list[str] | None = None) -> list[str]:
    """Extract target function names defined in `sources` (excluding harness entry points)."""
    if explicit_functions:
        return sorted({f.strip() for f in explicit_functions if f.strip()})
    discovered: set[str] = set()
    for src in sources:
        p = Path(src)
        if not p.is_file() or p.name.startswith("harness_"):
            continue
        try:
            raw = p.read_text(encoding="utf-8", errors="replace")
            for fn in extract_functions_from_code(raw, path=str(p)):
                name = fn.get("name", "")
                if name and name not in ("eva_main", "LLVMFuzzerTestOneInput", "main"):
                    discovered.add(name)
        except Exception:
            continue
    return sorted(discovered)


def _resolve_eacsl_gcc() -> tuple[str, bool]:
    """
    Return (binary_path, is_modern_cli).
    Frama-C <= 32 installs `e-acsl-gcc.sh` (long-option CLI).
    Frama-C 33+ installs `e-acsl-gcc` (short-option CLI: -G, -F, -E, -e, -l, -o instrumented.c, -O binary).
    """
    modern = shutil.which("e-acsl-gcc")
    legacy = shutil.which("e-acsl-gcc.sh")
    if modern and not modern.endswith(".sh"):
        return modern, True
    if legacy:
        return legacy, False
    return "e-acsl-gcc.sh", False


def compile_eacsl_binary(
    sources: list[str],
    out_bin: Path,
    machdep: str = "gcc_x86_64",
    cppflags: str = "-I.",
    rte_flags: str = "all",
    fuzzer_flag: bool = True,
    functions: list[str] | None = None,
    ldflags_extra: str = "",
) -> dict:
    out_bin.parent.mkdir(parents=True, exist_ok=True)
    instrumented_c = out_bin.with_suffix(".instrumented.c")
    compile_log = out_bin.with_suffix(".compile.log")

    target_fns = _discover_slice_functions(sources, functions)
    eacsl_bin, is_modern = _resolve_eacsl_gcc()
    eacsl_defs = "-D__FRAMAC_EACSL__ -D_Float128=double"
    eacsl_cppflags = f"{eacsl_defs} {cppflags}".strip()

    if not is_modern:
        cflags = f"-g -O1 {eacsl_cppflags}"
        ldflags = ldflags_extra.strip()
        if fuzzer_flag:
            cflags = f"-fsanitize=fuzzer {cflags}"
            ldflags = f"-fsanitize=fuzzer {ldflags}".strip()

        cmd = [
            eacsl_bin,
            "--compiler=clang",
            f"--machdep={machdep}",
            f"--rte={rte_flags}",
            f"--cflag={cflags}",
            "-o", str(out_bin),
            "-O", str(instrumented_c),
        ]
        if target_fns:
            cmd.append(f"--rte-select={','.join(target_fns)}")
            cmd.append(f"--e-acsl-extra=-e-acsl-functions={','.join(target_fns)}")
        if ldflags:
            cmd.append(f"--ldflag={ldflags}")
        cmd.extend(sources)
    else:
        compile_only = "-fsanitize=fuzzer -g -O1 -fcommon" if fuzzer_flag else "-g -O1 -fcommon"
        ldflags = f"-fsanitize=fuzzer {ldflags_extra}".strip() if fuzzer_flag else ldflags_extra.strip()
        fc_flags = ["-rte", f"-machdep {machdep}"]
        if target_fns:
            fn_csv = ",".join(target_fns)
            fc_flags.append(f"-rte-select {fn_csv}")
            fc_flags.append(f"-e-acsl-functions {fn_csv}")
        cmd = [
            eacsl_bin,
            "-G", "clang",
            "-F", " ".join(fc_flags),
            "-E", eacsl_cppflags,
            "-e", f"{compile_only} {eacsl_cppflags}",
            "-o", str(instrumented_c),
            "-O", str(out_bin),
        ]
        if ldflags:
            cmd.extend(["-l", ldflags])
        cmd.extend(sources)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        rc = proc.returncode
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
    except OSError as exc:
        rc = 127
        stdout = ""
        stderr = str(exc)

    compile_log.write_text(
        f"Command: {' '.join(cmd)}\nReturncode: {rc}\n--- STDOUT ---\n{stdout}\n--- STDERR ---\n{stderr}\n",
        encoding="utf-8",
    )
    return {
        "engine": "eacsl",
        "returncode": rc,
        "command": " ".join(cmd),
        "binary": str(out_bin),
        "instrumented_source": str(instrumented_c),
        "compile_log": str(compile_log),
        "stdout": stdout[-16000:],
        "stderr": stderr[-16000:],
    }


def compile_sanitizer_binary(
    sources: list[str],
    out_bin: Path,
    cppflags: str = "-I.",
    fuzzer_flag: bool = True,
    ldflags_extra: str = "",
) -> dict:
    """Compile a slice directly with Clang + LibFuzzer + ASan + UBSan when E-ACSL cannot instrument."""
    out_bin.parent.mkdir(parents=True, exist_ok=True)
    compile_log = out_bin.with_suffix(".sanitizer_compile.log")
    san_flags = "-fsanitize=fuzzer,address,undefined" if fuzzer_flag else "-fsanitize=address,undefined"
    cmd = [
        "clang",
        "-g",
        "-O1",
        "-fcommon",
        san_flags,
        "-fno-sanitize-recover=all",
        *shlex.split(cppflags),
        *sources,
        "-o",
        str(out_bin),
        *shlex.split(ldflags_extra),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        rc = proc.returncode
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
    except OSError as exc:
        rc = 127
        stdout = ""
        stderr = str(exc)

    compile_log.write_text(
        f"Command: {' '.join(cmd)}\nReturncode: {rc}\n--- STDOUT ---\n{stdout}\n--- STDERR ---\n{stderr}\n",
        encoding="utf-8",
    )
    return {
        "engine": "sanitizers",
        "returncode": rc,
        "command": " ".join(cmd),
        "binary": str(out_bin),
        "instrumented_source": None,
        "compile_log": str(compile_log),
        "stdout": stdout[-16000:],
        "stderr": stderr[-16000:],
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
        extra_env=SANITIZER_RUNTIME_ENV,
    )
    out = res.stdout + "\n" + res.stderr
    return {
        "reproduced": res.returncode != 0 or res.timed_out,
        "returncode": res.returncode,
        "timed_out": res.timed_out,
        "failure": parse_runtime_failure(out),
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
    before_meta = {
        p.name: (p.stat().st_mtime_ns, sha256_file(p))
        for p in artifacts_dir.iterdir()
        if p.is_file() and not p.is_symlink()
    }

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
        extra_env=SANITIZER_RUNTIME_ENV,
    )
    combined_out = res.stdout + "\n" + res.stderr
    written_names = {
        Path(m.group("path").strip()).name
        for m in _TEST_UNIT_WRITTEN_RE.finditer(combined_out)
    }

    all_artifact_files = [
        p for p in sorted(artifacts_dir.iterdir())
        if _artifact_kind(p.name) and p.is_file() and not p.is_symlink()
    ]
    selected_files: list[tuple[Path, bool]] = []
    for p in all_artifact_files:
        if p.name not in before_meta:
            selected_files.append((p, False))
        else:
            old_mtime, old_sha = before_meta[p.name]
            new_mtime = p.stat().st_mtime_ns
            new_sha = sha256_file(p)
            if new_mtime != old_mtime or new_sha != old_sha or p.name in written_names:
                selected_files.append((p, False))

    # If the fuzzer exited non-zero and hit an identical content-addressed crash artifact
    # within the same filesystem timestamp granularity, collect existing artifacts rather
    # than reporting fuzzer_error with an empty artifacts list.
    if not selected_files and res.returncode != 0 and all_artifact_files:
        selected_files = [(p, True) for p in all_artifact_files]

    artifacts: list[dict] = []
    for p, pre_existing in selected_files:
        kind = _artifact_kind(p.name)
        if not kind:
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
        if pre_existing:
            entry["pre_existing"] = True
        if kind in ("crash", "leak"):
            replay = replay_artifact(binary, p, scratch)
            failure = replay["failure"] or parse_runtime_failure(combined_out)
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
    p_camp.add_argument("--ldflags", default="", help="Extra linker flags (e.g. '-lbsd -lm')")
    p_camp.add_argument("--rte", default="all")
    p_camp.add_argument(
        "--engine",
        choices=["auto", "eacsl", "sanitizers"],
        default="auto",
        help="Instrumentation engine: 'auto' tries E-ACSL first and falls back to Clang ASan+UBSan on compile error",
    )
    p_camp.add_argument("--functions", nargs="*", default=None, help="Explicit target functions to instrument in E-ACSL")
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
    p_guard.add_argument("--ldflags", default="", help="Extra linker flags")
    p_guard.add_argument("--functions", nargs="*", default=None, help="Explicit target functions to instrument in E-ACSL")
    p_guard.add_argument("--out-json", type=Path, required=True)

    args = parser.parse_args()

    try:
        if args.mode == "campaign":
            eacsl_attempt = None
            if args.engine in ("auto", "eacsl"):
                comp = compile_eacsl_binary(
                    args.sources,
                    args.out_bin,
                    args.machdep,
                    args.cppflags,
                    args.rte,
                    True,
                    functions=args.functions,
                    ldflags_extra=args.ldflags,
                )
                if comp["returncode"] != 0 and args.engine == "auto":
                    eacsl_attempt = comp
                    comp = compile_sanitizer_binary(
                        args.sources,
                        args.out_bin,
                        args.cppflags,
                        True,
                        ldflags_extra=args.ldflags,
                    )
            else:
                comp = compile_sanitizer_binary(
                    args.sources,
                    args.out_bin,
                    args.cppflags,
                    True,
                    ldflags_extra=args.ldflags,
                )

            if comp["returncode"] != 0:
                res = {
                    "mode": "campaign",
                    "module": args.module,
                    "status": "compile_error",
                    "engine_used": comp.get("engine", args.engine),
                    "compile": comp,
                }
                if eacsl_attempt is not None:
                    res["eacsl_compile_attempt"] = eacsl_attempt
            else:
                fuzz = run_fuzz_campaign(args.out_bin, args.corpus_dir, args.artifacts_dir, args.max_time, args.dict,
                                         args.per_input_timeout, extra_corpus=args.extra_corpus)
                res = {
                    "mode": "campaign",
                    "module": args.module,
                    "sources": args.sources,
                    "engine_used": comp.get("engine", args.engine),
                    "compile": comp,
                    **fuzz,
                }
                if eacsl_attempt is not None:
                    res["eacsl_compile_attempt"] = eacsl_attempt
        else:
            comp = compile_eacsl_binary(
                args.sources,
                args.out_bin,
                args.machdep,
                args.cppflags,
                "all",
                True,
                functions=args.functions,
                ldflags_extra=args.ldflags,
            )
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
