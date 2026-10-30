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
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from build_callgraph_dag import extract_functions_from_code  # noqa: E402
from eacsl_toolchain import (  # noqa: E402
    EACSL_FC_EXTRA_FLAGS,
    EACSL_RTE_INITIALIZED_FLAG,
    UnsafePassthroughError,
    build_eacsl_flag_sets,
    build_fallback_object,
    defines_fuzzer_initialize,
    is_eacsl_instrumented,
    normalize_passthrough,
    parse_missing_functions,
    parse_undefined_fallbacks,
    preprocess_source,
    resolve_fuzz_init_source,
    select_eacsl_binary,
)
from fingerprint import detect_alarm_kind, make_fingerprint, normalize_file  # noqa: E402
from framac_common import scan_undeclared_functions  # noqa: E402
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
# E-ACSL segment memory model runtime messages, e.g.
#   Use of invalid address 0x7f... in unsafe_initialize
_SEGMENT_RE = re.compile(
    r"(?P<msg>Use of invalid address|Invalid (?:read|write|access)|Out of bounds access)[^\n]*?"
    r"(?:\bin\s+(?:function\s+)?'?(?P<function>[A-Za-z_]\w*)'?)?\s*$",
    re.IGNORECASE | re.MULTILINE,
)
# Functions that belong to the E-ACSL runtime or sanitizer runtimes, never to the target.
_RUNTIME_FN_PREFIXES = ("__e_acsl", "eacsl_", "__eacsl", "e_acsl_", "unsafe_", "__asan", "__ubsan", "__sanitizer",
                        "__interceptor", "__lsan", "fuzzer::")
_RUNTIME_FILE_MARKERS = ("e-acsl/", "e_acsl", "/share/frama-c/", "compiler-rt", "libfuzzer")


def is_runtime_function(name: str | None, file_: str | None = None) -> bool:
    """True if `name`/`file_` belongs to the E-ACSL RTL or a sanitizer runtime."""
    if name and name.startswith(_RUNTIME_FN_PREFIXES):
        return True
    low = (file_ or "").replace("\\", "/").lower()
    return any(marker in low for marker in _RUNTIME_FILE_MARKERS)

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


def _parse_segment_failure(text: str) -> dict | None:
    """E-ACSL segment-model runtime message; location from the first non-runtime stack frame, if any."""
    seg = _SEGMENT_RE.search(text)
    if not seg:
        return None
    msg = seg.group("msg").strip()
    reported_fn = seg.group("function") or ""
    file_, line_, function = "unknown", 0, "unknown_function"
    for m in _STACK_FRAME_RE.finditer(text):
        fn, fpath = m.group("function"), m.group("file")
        if is_runtime_function(fn, fpath) or Path(fpath).name.startswith("harness_") or fn == "LLVMFuzzerTestOneInput":
            continue
        file_, line_, function = fpath, int(m.group("line")), fn
        break
    if function == "unknown_function" and reported_fn and not is_runtime_function(reported_fn):
        function = reported_fn
    detail = f" in {reported_fn}" if reported_fn else ""
    return {
        "file": file_,
        "line": line_,
        "function": function,
        "kind": "eacsl_runtime_error",
        "alarm_kind": "mem_access",
        "is_rte": True,
        "predicate": f"rte: mem_access: {msg}{detail}",
    }


def parse_eacsl_failure(text: str) -> dict | None:
    """Extract the first E-ACSL failure (file, line, function, kind, predicate) from runtime output."""
    if not text:
        return None
    err = _ERR_RE.search(text)
    old = None if err else _OLD_RE.search(text)
    hit = err or old
    if not hit:
        return _parse_segment_failure(text)
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


def needs_attribution(failure: dict | None) -> bool:
    """True when a failure has no usable target location (missing, line 0, unknown or runtime-internal function)."""
    if not failure:
        return True
    fn = failure.get("function") or ""
    return (
        int(failure.get("line") or 0) <= 0
        or fn in ("", "unknown_function")
        or is_runtime_function(fn, failure.get("file"))
    )


def _discover_slice_functions(
    sources: list[str],
    explicit_functions: list[str] | None = None,
    cppflags: str | None = None,
    runner=subprocess.run,
) -> list[str]:
    """
    Extract target function names defined in `sources` (excluding harness entry points).

    When `cppflags` is given and clang is available, each source is preprocessed first and only
    the lines that originate from that source are scanned, so functions disabled by `#if` are not
    passed to `-rte-select` / `-e-acsl-functions` (Frama-C aborts on unknown names). Raw-text
    scanning remains the fallback.
    """
    if explicit_functions:
        return sorted({f.strip() for f in explicit_functions if f.strip()})
    discovered: set[str] = set()
    for src in sources:
        p = Path(src)
        if not p.is_file() or p.name.startswith("harness_"):
            continue
        try:
            raw = None
            if cppflags is not None:
                raw = preprocess_source(p, cppflags, runner=runner)
            if raw is None:
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


def _run_tool(cmd: list[str], runner=subprocess.run) -> tuple[int, str, str]:
    try:
        proc = runner(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except OSError as exc:
        return 127, "", str(exc)


def compile_eacsl_binary(
    sources: list[str],
    out_bin: Path,
    machdep: str = "gcc_x86_64",
    cppflags: str = "-I.",
    rte_flags: str = "all",
    fuzzer_flag: bool = True,
    functions: list[str] | None = None,
    ldflags_extra: str = "",
    variadic_translation: bool = True,
    warn_unsigned_downcast: bool = False,
    rte_initialized: bool = True,
    runner=subprocess.run,
) -> dict:
    """
    Instrument and compile a slice with E-ACSL.

    Modern CLI (Frama-C 33+) runs in two explicit stages so preprocessor flags never reach the
    compile of the self-contained instrumented file:
      1. instrument: `e-acsl-gcc -n -G clang -F <frama-c flags> -E <frontend> -o <out>.instrumented.c <sources>`
      2. compile:    `e-acsl-gcc -C -G clang -e <backend> -l <ldflags> -O <out> [fuzz_init.c] <out>.instrumented.c`
    `-n` matters: without it `e-acsl-gcc` also links the original sources, which fails on a
    main-less fuzz harness. Fuzz builds use full memory tracking and link
    templates/eacsl_runtime/fuzz_init.c, whose LLVMFuzzerInitialize initializes the runtime that
    an instrumented main() would. Uninitialized reads are checked (`-rte-initialized @all`)
    unless `rte_initialized` is False, which is recorded in `reduced_checks`. Stage 1 is retried
    once without functions Frama-C reports as unknown; stage 2 is retried once with a generated
    link-only object when Variadic `<fn>_fallback_<N>` symbols are undefined.
    On success the result's `binary` is the E-ACSL-instrumented executable (`<out>.e-acsl` when
    present) and is guaranteed to contain E-ACSL instrumentation.
    """
    out_bin = Path(out_bin)
    out_bin.parent.mkdir(parents=True, exist_ok=True)
    instrumented_c = out_bin.with_suffix(".instrumented.c")
    compile_log = out_bin.with_suffix(".compile.log")
    log_parts: list[str] = []
    commands: list[str] = []
    result: dict = {
        "engine": "eacsl",
        "returncode": 0,
        "command": "",
        "binary": str(out_bin),
        "instrumented_source": str(instrumented_c),
        "compile_log": str(compile_log),
        "stdout": "",
        "stderr": "",
        "variadic_fallbacks": [],
        "rte_select_dropped": [],
        "reduced_checks": [] if rte_initialized else ["-no-rte-initialized"],
    }

    def _record(cmd: list[str], rc: int, out: str, err: str) -> None:
        commands.append(" ".join(cmd))
        log_parts.append(f"Command: {' '.join(cmd)}\nReturncode: {rc}\n--- STDOUT ---\n{out}\n--- STDERR ---\n{err}\n")
        result["stdout"] = out[-16000:]
        result["stderr"] = err[-16000:]

    def _finish(rc: int, reason: str | None = None) -> dict:
        result["returncode"] = rc
        result["command"] = " && ".join(commands)
        result["undeclared_functions"] = scan_undeclared_functions("\n".join(log_parts))
        if reason:
            result["reason"] = reason
        compile_log.write_text("\n".join(log_parts) or f"Returncode: {rc}\nReason: {reason}\n", encoding="utf-8")
        return result

    eacsl_bin, is_modern = _resolve_eacsl_gcc()
    try:
        flags = build_eacsl_flag_sets(cppflags, fuzzer=fuzzer_flag)
        ldflags = normalize_passthrough(f"-fsanitize=fuzzer {ldflags_extra}" if fuzzer_flag else ldflags_extra)
    except UnsafePassthroughError as exc:
        result["stderr"] = str(exc)
        log_parts.append(f"Refusing to call e-acsl-gcc: {exc}\n")
        return _finish(2, "eacsl_argv_unsafe")
    result["frontend_flags"] = flags["frontend"]
    result["backend_flags"] = flags["backend"]
    target_fns = _discover_slice_functions(sources, functions, cppflags=cppflags, runner=runner)

    if not is_modern:
        cmd = [
            eacsl_bin,
            "--compiler=clang",
            f"--machdep={machdep}",
            f"--rte={rte_flags}",
            f"--cflag={flags['backend']} {flags['frontend']}",
            "-o", str(out_bin),
            "-O", str(instrumented_c),
        ]
        if warn_unsigned_downcast:
            cmd.append("--frama-c-extra=-warn-unsigned-downcast")
        if target_fns:
            cmd.append(f"--rte-select={','.join(target_fns)}")
            cmd.append(f"--e-acsl-extra=-e-acsl-functions={','.join(target_fns)}")
        if ldflags:
            cmd.append(f"--ldflag={ldflags}")
        cmd.extend(sources)
        rc, out, err = _run_tool(cmd, runner)
        _record(cmd, rc, out, err)
        if rc != 0:
            return _finish(rc, "eacsl_compile_failed")
    else:
        def _stage1(fns: list[str]) -> tuple[list[str], int, str, str]:
            fc_flags = ["-rte", f"-machdep {machdep}", *EACSL_FC_EXTRA_FLAGS]
            if rte_initialized:
                fc_flags.append(EACSL_RTE_INITIALIZED_FLAG)
            if warn_unsigned_downcast:
                fc_flags.append("-warn-unsigned-downcast")
            if not variadic_translation:
                fc_flags.append("-variadic-no-translation")
            if fns:
                fn_csv = ",".join(fns)
                fc_flags.append(f"-rte-select {fn_csv}")
                fc_flags.append(f"-e-acsl-functions {fn_csv}")
            cmd1 = [eacsl_bin, "-n", "-G", "clang", "-F", " ".join(fc_flags), "-E", flags["frontend"],
                    "-o", str(instrumented_c), *sources]
            return (cmd1, *_run_tool(cmd1, runner))

        cmd1, rc, out, err = _stage1(target_fns)
        _record(cmd1, rc, out, err)
        if rc != 0 and target_fns:
            missing = [f for f in parse_missing_functions(out + "\n" + err) if f in target_fns]
            if missing:
                result["rte_select_dropped"] = missing
                cmd1, rc, out, err = _stage1([f for f in target_fns if f not in missing])
                _record(cmd1, rc, out, err)
        if rc != 0:
            return _finish(rc, "eacsl_instrumentation_failed")

        init_hook: list[str] = []
        if fuzzer_flag:
            instrumented_text = instrumented_c.read_text(encoding="utf-8", errors="replace") if instrumented_c.is_file() else ""
            if defines_fuzzer_initialize(instrumented_text):
                log_parts.append(
                    "The slice defines LLVMFuzzerInitialize, which the E-ACSL runtime init hook "
                    "(templates/eacsl_runtime/fuzz_init.c) also defines; remove it from the harness.\n"
                )
                return _finish(1, "eacsl_init_hook_conflict")
            init_hook = [resolve_fuzz_init_source().as_posix()]
            result["init_hook"] = init_hook[0]

        def _stage2(link: str) -> tuple[list[str], int, str, str]:
            cmd2 = [eacsl_bin, "-C", "-G", "clang", "-e", flags["backend"], "-O", str(out_bin)]
            if link:
                cmd2.extend(["-l", link])
            cmd2.extend(init_hook)
            cmd2.append(str(instrumented_c))
            return (cmd2, *_run_tool(cmd2, runner))

        cmd2, rc, out, err = _stage2(ldflags)
        _record(cmd2, rc, out, err)
        if rc != 0 and parse_undefined_fallbacks(out + "\n" + err):
            fb = build_fallback_object(instrumented_c, out_bin.parent / f"{out_bin.name}_fallbacks", runner=runner)
            result["variadic_fallbacks"] = fb.get("fallbacks", [])
            if fb.get("status") != "built":
                log_parts.append(f"Variadic fallback generation failed: {fb.get('reason')}\n")
                return _finish(rc, "eacsl_variadic_fallbacks_failed")
            try:
                link_with_fallbacks = normalize_passthrough(f"{ldflags} {shlex.quote(Path(fb['object']).as_posix())}")
            except UnsafePassthroughError as exc:
                log_parts.append(f"Refusing to link fallback object: {exc}\n")
                return _finish(2, "eacsl_argv_unsafe")
            cmd2, rc, out, err = _stage2(link_with_fallbacks)
            _record(cmd2, rc, out, err)
        if rc != 0:
            return _finish(rc, "eacsl_compile_failed")

    binary = select_eacsl_binary(out_bin)
    result["binary"] = str(binary)
    if not is_eacsl_instrumented(binary):
        log_parts.append(f"Binary {binary} does not contain E-ACSL instrumentation; refusing to label it engine=eacsl.\n")
        return _finish(1, "eacsl_binary_not_instrumented")
    return _finish(0)


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
    attribution_builder=None,
    jobs: int = 1,
    workers: int = 1,
) -> dict:
    """
    `corpus_dir` receives new units (writable); `extra_corpus` directories are read-only
    seed inputs (e.g. the shared module corpus when a breaker works in its own scratch).

    `attribution_builder` is an optional zero-argument callable returning the path of a
    Clang ASan+UBSan build of the same slice (or None). It is called at most once, only when
    an E-ACSL crash has no usable location (failure missing, line 0, or a runtime-internal
    function), and the crash input is replayed on that build to attribute file:line.
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
    eff_jobs = max(1, int(jobs or 1))
    eff_workers = max(1, int(workers or 1))
    if eff_workers > 1 and eff_jobs == 1:
        eff_jobs = eff_workers
    elif eff_jobs > 1 and eff_workers == 1:
        eff_workers = eff_jobs

    if eff_workers > 1:
        cmd.insert(1, f"-workers={eff_workers}")
    if eff_jobs > 1:
        cmd.insert(1, f"-jobs={eff_jobs}")
    if dict_file and dict_file.exists():
        cmd.insert(1, f"-dict={dict_file.resolve()}")

    waves = max(1, (eff_jobs + eff_workers - 1) // eff_workers)
    wall_timeout = max_time * waves + 180
    cpu_mult = max(2, eff_workers + 1)
    res = run_sandboxed(
        cmd,
        writable=[scratch, corpus_dir, artifacts_dir],
        timeout_s=wall_timeout,
        limits=Limits(cpu_seconds=wall_timeout * cpu_mult),
        extra_env=SANITIZER_RUNTIME_ENV,
    )
    worker_logs: list[str] = []
    for log_path in sorted(scratch.glob("fuzz-*.log")):
        if log_path.is_file():
            try:
                worker_logs.append(log_path.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                pass
    combined_out = "\n".join([res.stdout, res.stderr, *worker_logs])
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
    attribution_state: dict = {"built": False, "binary": None}

    def _attribution_binary() -> Path | None:
        if attribution_builder is None:
            return None
        if not attribution_state["built"]:
            attribution_state["built"] = True
            try:
                attribution_state["binary"] = attribution_builder()
            except Exception:
                attribution_state["binary"] = None
        return attribution_state["binary"]

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
            entry["failure_source"] = "primary" if failure else None
            if needs_attribution(failure):
                san_bin = _attribution_binary()
                if san_bin is not None:
                    san_replay = replay_artifact(Path(san_bin), p, scratch)
                    entry["attribution"] = {
                        "source": "sanitizer_replay",
                        "binary": str(san_bin),
                        "reproduced": san_replay["reproduced"],
                        "failure": san_replay["failure"],
                    }
                    if san_replay["failure"] and not needs_attribution(san_replay["failure"]):
                        failure = san_replay["failure"]
                        entry["failure_source"] = "sanitizer_replay"
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

    The binary must be E-ACSL-instrumented: replaying an uninstrumented build would return 0
    for any contract and produce a vacuous `passed_dynamic_oracle`.
    """
    if not is_eacsl_instrumented(binary):
        return {
            "status": "guardrail_error",
            "reason": f"{binary} is not E-ACSL-instrumented; refusing to report a vacuous dynamic-oracle pass.",
            "failure": None,
            "corpus_dir": str(corpus_dir),
        }
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


CANARY_INPUT = b"FC33" + b"P" * 12
# Reaches neither the open() branch nor the overflow; must run clean (no false alarm, no runtime crash).
CANARY_BENIGN_INPUT = b"BENIGN" + b"P" * 10
# Reaches canary_pick with data[4] != 'S': an uninitialized read that -rte-initialized must report.
CANARY_UNINIT_INPUT = b"UNINX" + b"P" * 11
DEFAULT_SELFTEST_JSON = Path("workspace/reports/eacsl_selftest.json")


def resolve_canary_source() -> Path:
    for base in (Path("/opt/framac-pipeline/templates"), Path(__file__).resolve().parent.parent / "templates"):
        cand = base / "eacsl_canary" / "canary.c"
        if cand.is_file():
            return cand
    raise FileNotFoundError("templates/eacsl_canary/canary.c not found")


def framac_version(runner=subprocess.run) -> str:
    rc, out, err = _run_tool(["frama-c", "-version"], runner)
    return (out or err).strip().splitlines()[0] if rc == 0 and (out or err).strip() else "unknown"


def run_selftest(
    work_dir: Path,
    machdep: str = "gcc_x86_64",
    variadic_translation: bool = True,
    runner=subprocess.run,
    replay=None,
) -> dict:
    """
    Build the canary through the production E-ACSL path and check the toolchain contract:
    compile succeeds, gmp-only mode was not triggered, the binary is instrumented, a benign
    input runs clean, the known overflow input is detected (and, ideally, attributed to the
    CANARY_OOB line), and the known uninitialized read is reported as `initialization`. The
    benign run matters because replay counts any non-zero exit as reproduced: a binary that
    crashes on every input would otherwise pass.
    """
    replay = replay or replay_artifact
    src = resolve_canary_source()
    expected_line = next(
        (i for i, line in enumerate(src.read_text(encoding="utf-8").splitlines(), start=1) if "/* CANARY_OOB */" in line), 0
    )
    work_dir.mkdir(parents=True, exist_ok=True)
    comp = compile_eacsl_binary(
        [str(src)], work_dir / "canary", machdep, cppflags=f"-I{src.parent.as_posix()}",
        variadic_translation=variadic_translation, runner=runner,
    )
    log_path = Path(comp["compile_log"])
    log_text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.is_file() else ""
    checks = {
        "compiled": comp["returncode"] == 0,
        "no_gmp_only": "-e-acsl-gmp-only" not in log_text,
        "instrumented_binary": comp["returncode"] == 0 and is_eacsl_instrumented(Path(comp["binary"])),
        "benign_input_clean": False,
        "detects_overflow": False,
        "detects_uninitialized": False,
        "attributes_line": False,
    }
    failure = None
    benign_failure = None
    uninit_failure: dict = {}
    if checks["instrumented_binary"]:
        benign = work_dir / "canary_benign.bin"
        benign.write_bytes(CANARY_BENIGN_INPUT)
        benign_rep = replay(Path(comp["binary"]), benign, work_dir / "scratch")
        checks["benign_input_clean"] = not benign_rep.get("reproduced")
        benign_failure = None if checks["benign_input_clean"] else (benign_rep.get("failure") or benign_rep.get("log_tail"))
        inp = work_dir / "canary_input.bin"
        inp.write_bytes(CANARY_INPUT)
        rep = replay(Path(comp["binary"]), inp, work_dir / "scratch")
        failure = rep.get("failure")
        checks["detects_overflow"] = bool(rep.get("reproduced"))
        checks["attributes_line"] = bool(failure) and int(failure.get("line") or 0) == expected_line
        uninit = work_dir / "canary_uninit.bin"
        uninit.write_bytes(CANARY_UNINIT_INPUT)
        uninit_rep = replay(Path(comp["binary"]), uninit, work_dir / "scratch")
        uninit_failure = uninit_rep.get("failure") or {}
        checks["detects_uninitialized"] = bool(uninit_rep.get("reproduced")) and uninit_failure.get("alarm_kind") == "initialization"
    required = ("compiled", "no_gmp_only", "instrumented_binary", "benign_input_clean", "detects_overflow", "detects_uninitialized")
    ok = all(checks[k] for k in required)
    return {
        "mode": "selftest",
        "ok": ok,
        "checks": checks,
        "warnings": [] if checks["attributes_line"] or not ok else ["E-ACSL detected the canary overflow but did not attribute the CANARY_OOB line; crashes will rely on sanitizer_replay attribution."],
        "frama_c_version": framac_version(runner),
        "eacsl_gcc": _resolve_eacsl_gcc()[0],
        "variadic_translation": variadic_translation,
        "variadic_fallbacks": comp.get("variadic_fallbacks", []),
        "expected_line": expected_line,
        "failure": failure,
        "benign_failure": benign_failure,
        "uninitialized_failure": uninit_failure or None,
        "compile": {k: comp.get(k) for k in ("returncode", "reason", "compile_log", "binary", "frontend_flags", "backend_flags", "init_hook", "reduced_checks")},
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def selftest_blocks_eacsl(selftest_json: Path | None, runner=subprocess.run) -> str | None:
    """Return a reason string if a cached selftest for the current Frama-C version failed."""
    if not selftest_json or not Path(selftest_json).is_file():
        return None
    try:
        data = json.loads(Path(selftest_json).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if data.get("ok", True):
        return None
    if data.get("frama_c_version") != framac_version(runner):
        return None
    failed = sorted(k for k, v in (data.get("checks") or {}).items() if not v and k != "attributes_line")
    return f"eacsl_selftest_failed: {', '.join(failed) or 'unknown'}"


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
    p_camp.add_argument("--no-variadic-translation", action="store_true",
                        help="Pass -variadic-no-translation to Frama-C (no <fn>_fallback_<N> symbols are emitted)")
    p_camp.add_argument("--warn-unsigned-downcast", action="store_true",
                        help="Enable -warn-unsigned-downcast in Frama-C E-ACSL instrumentation")
    p_camp.add_argument("--no-rte-initialized", action="store_true",
                        help="Do not check uninitialized reads (-rte-initialized); recorded in reduced_checks")
    p_camp.add_argument("--jobs", type=int, default=1, help="LibFuzzer -jobs=<N> (default: 1)")
    p_camp.add_argument("--workers", type=int, default=1, help="LibFuzzer -workers=<N> (default: 1)")
    p_camp.add_argument("--selftest-json", type=Path, default=DEFAULT_SELFTEST_JSON,
                        help="Cached selftest result; with --engine auto a failed selftest for this Frama-C version skips E-ACSL")
    p_camp.add_argument("--no-attribution-replay", action="store_true",
                        help="Do not replay unattributed E-ACSL crashes on a sanitizer build")
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
    p_guard.add_argument("--no-variadic-translation", action="store_true")
    p_guard.add_argument("--warn-unsigned-downcast", action="store_true",
                         help="Enable -warn-unsigned-downcast in Frama-C E-ACSL instrumentation")
    p_guard.add_argument("--no-rte-initialized", action="store_true",
                         help="Do not check uninitialized reads (-rte-initialized); recorded in reduced_checks")
    p_guard.add_argument("--out-json", type=Path, required=True)

    p_self = sub.add_parser("selftest", help="Verify the E-ACSL toolchain contract on the bundled canary")
    p_self.add_argument("--work-dir", type=Path, default=Path("workspace/eacsl_selftest"))
    p_self.add_argument("--machdep", default="gcc_x86_64")
    p_self.add_argument("--no-variadic-translation", action="store_true")
    p_self.add_argument("--out-json", type=Path, default=DEFAULT_SELFTEST_JSON)

    args = parser.parse_args()

    try:
        if args.mode == "selftest":
            res = run_selftest(args.work_dir, args.machdep, variadic_translation=not args.no_variadic_translation)
        elif args.mode == "campaign":
            res = _run_campaign_mode(args)
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
                variadic_translation=not args.no_variadic_translation,
                warn_unsigned_downcast=args.warn_unsigned_downcast,
                rte_initialized=not args.no_rte_initialized,
            )
            if comp["returncode"] != 0:
                res = {"mode": "guardrail", "status": "compile_error", "reason": comp.get("reason"), "compile": comp}
            else:
                scratch = args.scratch_dir or args.out_bin.parent / f"{args.out_bin.name}_guard_scratch"
                guard = run_guardrail_check(Path(comp["binary"]), args.corpus_dir, scratch, args.extra_runs)
                res = {"mode": "guardrail", "compile": comp, **guard, "reduced_checks": comp.get("reduced_checks", [])}
    except SandboxUnavailable as exc:
        res = {"mode": args.mode, "status": "sandbox_unavailable", "reason": str(exc)}

    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in res.items() if k not in ("compile", "log_tail", "runtime_trace")}, indent=2))
    if args.mode == "selftest":
        return 0 if res.get("ok") else 1
    return 3 if res.get("status") == "sandbox_unavailable" else 0


def _run_campaign_mode(args) -> dict:
    eacsl_attempt = None
    fallback_reason = None
    comp = None
    if args.engine in ("auto", "eacsl"):
        blocked = selftest_blocks_eacsl(args.selftest_json) if args.engine == "auto" else None
        if blocked:
            fallback_reason = blocked
        else:
            comp = compile_eacsl_binary(
                args.sources,
                args.out_bin,
                args.machdep,
                args.cppflags,
                args.rte,
                True,
                functions=args.functions,
                ldflags_extra=args.ldflags,
                variadic_translation=not args.no_variadic_translation,
                warn_unsigned_downcast=args.warn_unsigned_downcast,
                rte_initialized=not args.no_rte_initialized,
            )
            if comp["returncode"] != 0 and args.engine == "auto":
                eacsl_attempt = comp
                fallback_reason = comp.get("reason") or "eacsl_compile_failed"
                comp = None
    if comp is None:
        comp = compile_sanitizer_binary(args.sources, args.out_bin, args.cppflags, True, ldflags_extra=args.ldflags)

    engine_used = comp.get("engine", args.engine)
    res: dict = {"mode": "campaign", "module": args.module}
    if comp["returncode"] != 0:
        res.update({"status": "compile_error", "engine_used": engine_used, "compile": comp})
    else:
        attribution_builder = None
        if engine_used == "eacsl" and not args.no_attribution_replay:
            def attribution_builder() -> Path | None:
                san_out = args.out_bin.with_name(args.out_bin.name + ".sanreplay")
                san = compile_sanitizer_binary(args.sources, san_out, args.cppflags, True, ldflags_extra=args.ldflags)
                return Path(san["binary"]) if san["returncode"] == 0 else None

        fuzz = run_fuzz_campaign(
            Path(comp["binary"]),
            args.corpus_dir,
            args.artifacts_dir,
            args.max_time,
            args.dict,
            args.per_input_timeout,
            extra_corpus=args.extra_corpus,
            attribution_builder=attribution_builder,
            jobs=args.jobs,
            workers=args.workers,
        )
        res.update({"sources": args.sources, "engine_used": engine_used, "compile": comp, **fuzz})
        if engine_used == "eacsl" and comp.get("reduced_checks"):
            res["reduced_checks"] = comp["reduced_checks"]
    if fallback_reason:
        res["engine_fallback_reason"] = fallback_reason
    if eacsl_attempt is not None:
        res["eacsl_compile_attempt"] = eacsl_attempt
    return res


if __name__ == "__main__":
    sys.exit(main())
