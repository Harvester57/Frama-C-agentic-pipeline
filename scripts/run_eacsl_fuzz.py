#!/usr/bin/env python3
"""
Drives Frama-C RTE + E-ACSL source-to-source instrumentation and Clang LibFuzzer execution.

Modes:
1. `campaign`: zero-ACSL dynamic bug hunting on a module slice (`--rte=all` + `-fsanitize=fuzzer`).
   Outcomes: crash_found | timeout_found | oom_found | clean | fuzzer_error | compile_error.
   Each crash artifact is replayed once to check reproducibility and to extract the
   E-ACSL failing predicate, which yields a stable fingerprint (scripts/fingerprint.py).
   Without `--dict` (and unless `--no-auto-dict`), the target sources' literals plus fixed numeric
   boundary tokens (scripts/fuzz_dictionary.py) become workspace/dicts/<module>.dict, passed as
   `-dict=`; the report's `dictionary` records `{path, auto, entries}` or why there is none.
   A campaign keeps going after a crash (unless `--stop-on-first-crash`): a `dispatch` harness
   reruns for the time left with the crashed cases skipped (-DFRAMAC_FUZZ_SKIP_CASES=<mask> for
   cases 0..63, -DFRAMAC_FUZZ_SKIP_CASES_<k> for 64k..64k+63), any other harness runs in libFuzzer
   fork mode with `-ignore_crashes=1`. When a round's new crashes cannot be skipped (a harness
   generated before every case was skippable, or a failed rebuild), the round records why and the
   time left goes to fork mode. `keep_going` in the report records the rounds, and duplicates of
   one fingerprint are listed at most 3 times.
2. `guardrail`: the dynamic anti-hallucination oracle used inside `/framac-wp`.
   Replays the module corpus (plus a short mutation burst) against a binary compiled with
   the proposed ACSL contract. Outcomes:
     - passed_dynamic_oracle
     - rejected_overconstrained : an agent-written annotation (requires/ensures/invariant/assert)
                                  failed on a real input
     - code_fault               : an RTE assertion failed; this is a code defect candidate,
                                  not evidence against the contract
     - guardrail_error / compile_error
   Every report has `crash_input`: the run-relative path of the input libFuzzer wrote under the
   scratch -artifact_prefix on a failing replay, or null.
   Past `--max-corpus-inputs`, every promoted seed-* / crash-* file is replayed and the rest is
   a deterministic sample; `corpus_total`, `corpus_replayed`, `corpus_sampled` and
   `corpus_empty` say what was replayed. A pass on an empty corpus is not a pass on real inputs.
3. `selftest`: builds the bundled canary through the production path (never cached).
4. `build`: compiles a module's fuzz binary only (no target code runs). Used by Make.
5. `replay`: replays given inputs once each on a given or built binary. The report's
   `artifacts[{artifact, kind, sha256, size_bytes, reproducible, failure, fingerprint}]`
   is the campaign's shape, which `ledger.py ingest-verifier --replay-report` accepts.
6. `replay-candidates`: replays the reproducers of every unverified candidate on its module's
   binary (built with Make's spec, `pipeline_make.module_build_spec`, so it is the cache entry
   of `make build`) and writes one report per candidate plus index.json.
7. `coverage`: measures which target functions and code regions a module's corpus executes, by
   replaying it on a plain Clang source-coverage build (no E-ACSL, no sanitizers). Outcomes:
   ok | partial | no_inputs | compile_error | coverage_error. Reach only: never proof or a verdict.
   The replay goes on past failing inputs until `--max-time`; inputs whose sha256 matches a file
   under `--known-crashes-dir` (default workspace/crashes/<module>) replay last (`known_crash`).

All fuzzer, replay and guardrail executions run through scripts/sandbox_exec.py. The shared
corpus is never written by the guardrail: new units go to a scratch corpus directory.

Sizing and determinism (scripts/resources.py): campaigns scale the number of LibFuzzer workers
with the job budget (`--workers auto`) and turn a CPU-second budget into wall time
(`--fuzz-budget`), while `-rss_limit_mb` stays fixed at 2048. Guardrail and replay runs use a fixed
per-input `-timeout`, the same `-rss_limit_mb` and a deterministic `-seed` derived from the sha256
of the binary path and module, so rerunning them on the same build mutates and replays
identically. Builds outside agents/*/scratch are cached per run (scripts/cache.py,
namespace `eacsl-build`): an unchanged slice restores its binary instead of recompiling.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import math
import os
import posixpath
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter, deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cache  # noqa: E402
import fuzz_dictionary  # noqa: E402
import prover_candidates  # noqa: E402
import target_env  # noqa: E402
from acsl_ast import tokenize_c_acsl  # noqa: E402
from c_definitions import TYPE_MODIFIERS_AND_PRIMITIVES, extract_functions_from_code  # noqa: E402
from eacsl_toolchain import (  # noqa: E402
    EACSL_FC_EXTRA_FLAGS,
    EACSL_FULL_MTRACKING_DEFINES,
    EACSL_RTE_INITIALIZED_FLAG,
    UnsafePassthroughError,
    build_eacsl_flag_sets,
    build_fallback_object,
    defines_fuzzer_initialize,
    fix_readonly_scalar_globals,
    is_eacsl_instrumented,
    mark_formals_initialized,
    mark_wrapper_results_initialized,
    normalize_passthrough,
    parse_missing_functions,
    parse_undefined_fallbacks,
    preprocess_source,
    reset_verdict_on_input_entry,
    resolve_fuzz_init_source,
    rewrite_sound_verdict_resets,
    rewrite_trailing_alignas,
    select_eacsl_binary,
    slice_has_pthread,
    uses_full_mtracking,
)
from fingerprint import (  # noqa: E402
    detect_alarm_kind,
    detect_predicate_alarm_kind,
    make_fingerprint,
    normalize_file,
)
from framac_common import (  # noqa: E402
    ArtifactError,
    atomic_write_json,
    load_json_optional,
    normalize_flag_args,
    scan_undeclared_functions,
    utc_now,
)
from generate_harness import DISPATCH_SKIP_ALL_MARKER, DISPATCH_SKIP_MACRO, TARGET_EMBEDDED_PREFIX  # noqa: E402
from resources import (  # noqa: E402
    CLASSES,
    FUZZ_RSS_LIMIT_MB,
    FUZZ_WORKER_OVERHEAD_MB,
    enforced_memory_mb,
    fuzz_workers,
)
from sandbox_exec import Limits, SandboxUnavailable, run_sandboxed  # noqa: E402

# Below this, a single LibFuzzer worker cannot have its fixed -rss_limit_mb=2048 alongside
# runtime/fork overhead without risking cgroup OOM kills (sizing model: 512 + int(2048 * 1.25) = 3072).
FUZZ_MIN_MEMORY_MB = FUZZ_WORKER_OVERHEAD_MB + int(FUZZ_RSS_LIMIT_MB * 1.25)

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


def fuzz_required_memory_mb(workers: int = 1) -> int:
    """Minimum memory required for `workers` LibFuzzer workers under the 1.25x headroom sizing model."""
    return FUZZ_WORKER_OVERHEAD_MB + max(1, workers) * int(FUZZ_RSS_LIMIT_MB * 1.25)


# Wall-clock limit of each compile stage (e-acsl-gcc, clang); a hung toolchain must not hold a lease forever.
BUILD_TIMEOUT_S = CLASSES["build"].wall_timeout_s or 3600
# Per-input LibFuzzer -timeout: campaigns and replays (the campaign default), guardrails (contract
# checks add overhead). Fixed values, never derived from the machine.
DEFAULT_PER_INPUT_TIMEOUT_S = 10
GUARDRAIL_PER_INPUT_TIMEOUT_S = 30
DEFAULT_MAX_TIME_S = 60
MIN_FUZZ_WALL_S = 30
# A keep-going round after a crash runs on what is left of the campaign's time, down to this floor.
# Below MIN_FUZZ_WALL_S on purpose: a campaign sized at that minimum must still get a second round
# when its first one crashed within a second. Fixed, never derived from the machine.
MIN_ROUND_WALL_S = 5
# Keep-going campaigns: a fork-mode run saves the same bug over and over, so only this many crash
# inputs are replayed and this many listed per fingerprint. Fixed, never derived from the machine.
MAX_REPLAYED_CRASHES = 64
MAX_ARTIFACTS_PER_FINGERPRINT = 3
# engine_used of a campaign that fuzzed with ASan+UBSan and then E-ACSL (`--engine auto`).
DUAL_ENGINE = "eacsl+sanitizers"
_DISPATCH_SWITCH_RE = re.compile(r"switch \(harness_selector % (\d+)U\)")

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
# Frama-C 33 puts the label on its own line and the predicate one level deeper:
#           The failing predicate is:
#           rte/index_bound:
#               i < 8.
#           With values at failure point:
_FN_RE = re.compile(r"(?P<file>(?:[A-Za-z]:)?[^\s:'\"]+(?:\.[chi]|\.acsl)):\s*In function '(?P<function>[^']+)'")
_ERR_RE = re.compile(
    r"(?P<file>(?:[A-Za-z]:)?[^\s:'\"]+(?:\.[chi]|\.acsl)):(?P<line>\d+):\s*Error:\s*(?P<kind>[A-Za-z][A-Za-z _-]*?)\s+failed:?",
    re.IGNORECASE,
)
# Older style: "Assertion failed at line 42 in file foo.c." / "... in function parse."
_OLD_RE = re.compile(
    r"(?P<kind>[A-Za-z][A-Za-z _-]*?)\s+failed at line (?P<line>\d+)"
    r"(?:\s+in\s+file\s+(?P<file>[^\s]+?(?:\.[chi]|\.acsl)))?(?:\s+in\s+function\s+(?P<function>\w+))?",
    re.IGNORECASE,
)
_PRED_HEAD_RE = re.compile(r"The failing predicate is:[ \t]*", re.IGNORECASE)
# E-ACSL segment memory model runtime messages, e.g.
#   Use of invalid address 0x7f... in unsafe_initialize
_SEGMENT_RE = re.compile(
    r"(?P<msg>Use of invalid address|Invalid (?:read|write|access)|Out of bounds access)[^\n]*?"
    r"(?:\bin\s+(?:function\s+)?'?(?P<function>[A-Za-z_]\w*)'?)?\s*$",
    re.IGNORECASE | re.MULTILINE,
)
# Functions that belong to the E-ACSL runtime or sanitizer runtimes, never to the target.
_RUNTIME_FN_PREFIXES = (
    "__e_acsl",
    "eacsl_",
    "__eacsl",
    "e_acsl_",
    "unsafe_",
    "__asan",
    "__ubsan",
    "__sanitizer",
    "__interceptor",
    "__lsan",
    "fuzzer::",
)
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
# A runtime value in a UBSan message: an integer, a hex address, a float. Not inside a quoted type.
_UBSAN_VALUE_RE = re.compile(r"(?<![\w.])[-+]?(?:0x[0-9a-fA-F]+|\d+(?:\.\d+)?(?:[eE][-+]?\d+)?)(?![\w.])")


def stable_ubsan_message(message: str) -> str:
    """
    A UBSan message with its runtime values replaced by `N`: `left shift of negative value -2806`
    and `... -19345` are one defect, and the predicate feeds the fingerprint. Quoted type names
    (`'char[1024]'`) are static and stay.
    """
    parts = re.split(r"('[^']*')", message)
    return "".join(p if p.startswith("'") else _UBSAN_VALUE_RE.sub("N", p) for p in parts)


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


def derive_seed(binary: Path | str, module: str = "") -> int:
    """
    Deterministic LibFuzzer `-seed` for guardrail and replay runs: the first 32 bits of
    sha256("<resolved binary path>\\0<module>"), in 1..2^31-1 (libFuzzer reads 0 as "pick a
    random seed"). The same build at the same path mutates and replays identically on any machine.
    """
    digest = hashlib.sha256(f"{Path(binary).resolve().as_posix()}\0{module}".encode()).digest()
    return int.from_bytes(digest[:4], "big") % 2147483646 + 1


def _in_agent_scratch(path: Path | str) -> bool:
    """True under agents/<id>/scratch/: agent builds are never cached (they are scoped instead)."""
    parts = Path(os.path.abspath(path)).parts
    return any(parts[i] == "agents" and parts[i + 2] == "scratch" for i in range(len(parts) - 2))


def _decode(data) -> str:
    if data is None:
        return ""
    return data.decode("utf-8", errors="replace") if isinstance(data, bytes) else str(data)


def _resolve_source_candidates(file_path: str) -> list[Path]:
    """Return existing source file paths matching `file_path` in the workspace or current directory."""
    if not file_path:
        return []
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
    return candidates


def _is_acsl_annotation_line(file_path: str, line: int) -> bool:
    """
    True if `file_path:line` resolves to a source line containing only ACSL annotations
    (`/*@ ... */` or `//@ ...`) and no executable C tokens.

    Frama-C `-rte` attaches synthesized runtime assertions in-memory to executable C AST
    statements without modifying the source file on disk, so a true C-code RTE always points
    to a line with executable C tokens, whereas a user/agent-written `/*@ assert ... */` or
    contract clause points to an ACSL annotation line (or an `.acsl` specification file).
    """
    if not file_path or line <= 0:
        return False
    if file_path.lower().endswith(".acsl"):
        return True
    for cpath in _resolve_source_candidates(file_path):
        try:
            raw = cpath.read_text(encoding="utf-8", errors="replace")
            has_acsl = False
            has_c_code = False
            for tok in tokenize_c_acsl(raw):
                tok_start = tok.line
                tok_end = tok.line + tok.text.count("\n")
                if tok_start <= line <= tok_end:
                    if tok.kind in ("acsl_block", "acsl_line"):
                        has_acsl = True
                    elif tok.kind in ("c_token", "string", "char"):
                        has_c_code = True
            return has_acsl and not has_c_code
        except Exception:
            continue
    return False


def _resolve_function_at_line(file_path: str, line: int) -> str:
    """Resolve the enclosing C function at `file_path:line` using token-based span extraction."""
    if not file_path or line <= 0:
        return "unknown_function"
    for cpath in _resolve_source_candidates(file_path):
        try:
            raw = cpath.read_text(encoding="utf-8", errors="replace")
            for fn in extract_functions_from_code(raw, path=str(cpath)):
                name = fn.get("name") or ""
                if name in TYPE_MODIFIERS_AND_PRIMITIVES:
                    continue
                if int(fn.get("line", 0)) <= line <= int(fn.get("end_line", 0)):
                    return name or "unknown_function"
        except Exception:
            continue
    return "unknown_function"


def is_harness_fuzz_function(name: str) -> bool:
    """
    The harness's own fuzz entry, or a target fuzzer's hook it calls (renamed with the
    `__framac_target_embedded_` prefix by generate_harness.py --target-fuzzer): harness code, so never
    selected for RTE/E-ACSL and never a crash location.
    """
    return name == "LLVMFuzzerTestOneInput" or name.startswith(TARGET_EMBEDDED_PREFIX)


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
        if is_runtime_function(fn, fpath) or Path(fpath).name.startswith("harness_") or is_harness_fuzz_function(fn):
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


def _failing_predicate(text: str, start: int) -> tuple[str, str]:
    """
    (label, predicate) of the first "The failing predicate is:" block after `start`. The label is
    the property name or RTE kind (`rte/index_bound`, `range`); the predicate is the expression
    alone, as Eva and WP print it, so the same property fingerprints the same in every tool.
    """
    head = _PRED_HEAD_RE.search(text, start)
    if not head:
        return "", ""
    first, _, rest = text[head.end() :].partition("\n")
    lines = rest.split("\n")
    if not first.strip() and lines and lines[0].strip():
        first, lines = lines[0], lines[1:]  # the line after the header, indented or not (older releases)
    block = [first.strip()] if first.strip() and not first.strip().lower().startswith("with values") else []
    for line in lines if block else []:
        # Continuation lines are indented; the values section or unindented runtime output ends the block.
        if not line[:1].isspace() or not line.strip() or line.strip().lower().startswith("with values"):
            break
        block.append(line.strip())
    if len(block) >= 2 and block[0].endswith(":"):
        return block[0][:-1].strip(), " ".join(block[1:]).rstrip(".").strip()
    joined = " ".join(block).rstrip(".").strip()
    m = re.match(r"^(?P<label>[A-Za-z_][\w/-]*)\s*:\s*(?P<pred>.+)$", joined)
    if m and not m.group("pred").startswith(":"):  # one-line `label: predicate` (older releases)
        return m.group("label"), m.group("pred").strip()
    return "", joined


def parse_eacsl_failure(text: str) -> dict | None:
    """Extract the first E-ACSL failure (file, line, function, kind, label, predicate) from runtime output."""
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
    label, predicate = _failing_predicate(text, hit.end())
    kind = hit.group("kind").strip().lower().replace(" ", "_")
    # A label names the alarm; inside the predicate only a label-like use counts, never an identifier.
    alarm = detect_alarm_kind(label) or detect_predicate_alarm_kind(predicate)
    explicit_rte_prefix = label.lower().startswith("rte") or predicate.lower().startswith("rte")
    has_rte_marker = bool(alarm) or explicit_rte_prefix
    on_acsl_line = _is_acsl_annotation_line(file_, line_)
    annotation_rte = (
        (kind == "rte") or (on_acsl_line and has_rte_marker) or (kind != "assertion" and explicit_rte_prefix)
    )
    is_rte = (kind == "assertion") and has_rte_marker and not on_acsl_line
    res: dict = {
        "file": file_ or "unknown",
        "line": line_,
        "function": function or "unknown_function",
        "kind": kind,
        "alarm_kind": alarm or None,
        "is_rte": is_rte,
        "label": label,
        "predicate": predicate,
    }
    if annotation_rte:
        res["annotation_rte"] = True
    return res


def parse_sanitizer_failure(text: str) -> dict | None:
    """Extract the first UBSan or ASan runtime failure from LibFuzzer/sanitizer output."""
    if not text:
        return None

    frames = list(_STACK_FRAME_RE.finditer(text))
    non_harness_frames = [
        m
        for m in frames
        if not Path(m.group("file")).name.startswith("harness_")
        and not m.group("function").startswith(
            ("__interceptor_", "__asan_", "LLVMFuzzerTestOneInput", TARGET_EMBEDDED_PREFIX)
        )
    ]
    candidates = non_harness_frames or frames
    best_frame: re.Match[str] | None = candidates[0] if candidates else None

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
            # Values out of the predicate (it is fingerprinted); the message as printed stays apart.
            "predicate": f"rte: {alarm}: {stable_ubsan_message(pred)}",
            "message": pred,
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
                # Never pass C type keywords to -rte-select: RTE rejects them at option
                # validation ("no function 'void'"), which aborts the whole instrumentation.
                if (
                    name
                    and name not in ("eva_main", "main")
                    and not is_harness_fuzz_function(name)
                    and name not in TYPE_MODIFIERS_AND_PRIMITIVES
                ):
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


def _run_tool(cmd: list[str], runner=subprocess.run, timeout: float | None = BUILD_TIMEOUT_S) -> tuple[int, str, str]:
    try:
        proc = runner(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        return 124, _decode(exc.stdout), _decode(exc.stderr) + f"\n{cmd[0]} exceeded the {timeout} s build time limit\n"
    except OSError as exc:
        return 127, "", str(exc)


def _note_cache_restore(result: dict, entry: cache.Entry) -> dict:
    """Name the cache entry at the end of the restored compile log."""
    log = result.get("compile_log")
    if log:
        with contextlib.suppress(OSError), open(log, "a", encoding="utf-8") as f:
            f.write(
                f"\n[cache] Restored from {entry.store.scope} build cache entry {entry.ns}/{entry.key}; "
                "the log above is the original build's.\n"
            )
    return result


def _eacsl_cache_material(
    sources: list[str],
    out_bin: Path,
    machdep: str,
    cppflags: str,
    rte_flags: str,
    fuzzer_flag: bool,
    functions: list[str] | None,
    ldflags_extra: str,
    variadic_translation: bool,
    warn_unsigned_downcast: bool,
    rte_initialized: bool,
    concurrency: bool | None = None,
) -> dict | None:
    """Everything an E-ACSL build depends on besides file contents (None: flags the build would refuse)."""
    has_pthread = concurrency if concurrency is not None else slice_has_pthread(sources)
    eacsl_bin, is_modern = _resolve_eacsl_gcc()
    try:
        flags = build_eacsl_flag_sets(
            cppflags, fuzzer=fuzzer_flag, concurrency=has_pthread, full_mtracking=uses_full_mtracking(is_modern)
        )
        ld_parts = []
        if fuzzer_flag:
            ld_parts.append("-fsanitize=fuzzer")
        if has_pthread and "-lpthread" not in ldflags_extra.split():
            ld_parts.append("-lpthread")
        if ldflags_extra:
            ld_parts.append(ldflags_extra)
        ldflags = normalize_passthrough(" ".join(ld_parts))
    except UnsafePassthroughError:
        return None
    return {
        "kind": "eacsl",
        "eacsl_gcc": [eacsl_bin, is_modern],
        "sources": [str(s) for s in sources],
        "out_bin": out_bin.as_posix(),
        "machdep": machdep,
        "cppflags": cppflags,
        "frontend": flags["frontend"],
        "backend": flags["backend"],
        "ldflags": ldflags,
        "rte": rte_flags,
        "fuzzer": fuzzer_flag,
        "functions": sorted({f.strip() for f in functions if f.strip()}) if functions else None,
        "variadic_translation": variadic_translation,
        "warn_unsigned_downcast": warn_unsigned_downcast,
        "rte_initialized": rte_initialized,
        "no_constfold": True,
        "concurrency": has_pthread,
    }


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
    use_cache: bool = True,
    enable_l2: bool | None = None,
    concurrency: bool | None = None,
) -> dict:
    """
    Instrument and compile a slice with E-ACSL (see `_compile_eacsl_binary_uncached`).

    Outside agents/*/scratch, and when caching is enabled (scripts/cache.py), the build is
    cached under its effective flags, output path, cwd and dependency manifest: a hit restores
    the binary, `<out>.instrumented.c`, the variadic fallback object and the compile log (which
    then names the cache entry). The result carries `cache: {"hit": bool, "key": str | None}`.
    """
    out_bin = Path(out_bin)
    cppflags = target_env.with_include_flags(cppflags)
    ldflags_extra = target_env.with_link_flags(ldflags_extra)
    target_fns = _discover_slice_functions(sources, functions, cppflags=cppflags, runner=runner)

    def _build() -> dict:
        return _compile_eacsl_binary_uncached(
            sources,
            out_bin,
            machdep,
            cppflags,
            rte_flags,
            fuzzer_flag,
            functions,
            ldflags_extra,
            variadic_translation,
            warn_unsigned_downcast,
            rte_initialized,
            runner,
            target_fns=target_fns,
            concurrency=concurrency,
        )

    material = None
    if use_cache and not _in_agent_scratch(out_bin):
        material = _eacsl_cache_material(
            sources,
            out_bin,
            machdep,
            cppflags,
            rte_flags,
            fuzzer_flag,
            functions,
            ldflags_extra,
            variadic_translation,
            warn_unsigned_downcast,
            rte_initialized,
            concurrency=concurrency,
        )
    if material is None:
        res = _build()
        res["cache"] = {"hit": False, "key": None}
        return res

    instrumented_c = out_bin.with_suffix(".instrumented.c")
    compile_log = out_bin.with_suffix(".compile.log")
    fallback_dir = out_bin.parent / f"{out_bin.name}_fallbacks"

    def _outputs(res: dict) -> dict[str, Path]:
        files = {"binary": Path(res["binary"]), "instrumented.c": instrumented_c, "compile.log": compile_log}
        if res.get("variadic_fallbacks"):
            files["fallbacks.o"] = fallback_dir / "eacsl_fallbacks.o"
            files["fallbacks.c"] = fallback_dir / "eacsl_fallbacks.c"
        return files

    if enable_l2 is None:
        enable_l2 = bool(target_fns)
    l2_functions = target_fns if target_fns else None
    return cache.memoize(
        "eacsl-build",
        material,
        sources=sources,
        dep_flags=shlex.split(material["frontend"]),
        build=_build,
        outputs=_outputs,
        ok=lambda res: res.get("returncode") == 0,
        runner=runner,
        on_restore=_note_cache_restore,
        enable_l2=enable_l2,
        l2_target_functions=l2_functions,
    )


def _compile_eacsl_binary_uncached(
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
    target_fns: list[str] | None = None,
    concurrency: bool | None = None,
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
    an instrumented main() would. With full tracking the frontend also gets EACSL_FULL_MTRACKING_DEFINES
    (`-Dregister=`, recorded in `full_mtracking_defines`). Between the stages the instrumented file
    is patched for printer and E-ACSL gaps, each counted in the result (`alignas_rewrites`,
    `wrapper_result_inits`, `formal_inits`, ...). Uninitialized reads are checked (`-rte-initialized @all`)
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

    has_pthread = concurrency if concurrency is not None else slice_has_pthread(sources)
    result["concurrency"] = has_pthread
    eacsl_bin, is_modern = _resolve_eacsl_gcc()
    full_mtracking = uses_full_mtracking(is_modern)
    try:
        flags = build_eacsl_flag_sets(
            cppflags, fuzzer=fuzzer_flag, concurrency=has_pthread, full_mtracking=full_mtracking
        )
        ld_parts = []
        if fuzzer_flag:
            ld_parts.append("-fsanitize=fuzzer")
        if has_pthread and "-lpthread" not in ldflags_extra.split():
            ld_parts.append("-lpthread")
        if ldflags_extra:
            ld_parts.append(ldflags_extra)
        ldflags = normalize_passthrough(" ".join(ld_parts))
    except UnsafePassthroughError as exc:
        result["stderr"] = str(exc)
        log_parts.append(f"Refusing to call e-acsl-gcc: {exc}\n")
        return _finish(2, "eacsl_argv_unsafe")
    result["frontend_flags"] = flags["frontend"]
    result["backend_flags"] = flags["backend"]
    if full_mtracking:
        result["full_mtracking_defines"] = list(EACSL_FULL_MTRACKING_DEFINES)
        log_parts.append(
            f"Frontend defines {' '.join(EACSL_FULL_MTRACKING_DEFINES)}: full memory tracking takes the address "
            "of every local, which the kernel refuses for a `register` local.\n"
        )
    if target_fns is None:
        target_fns = _discover_slice_functions(sources, functions, cppflags=cppflags, runner=runner)

    if not is_modern:
        cmd = [
            eacsl_bin,
            "--no-constfold",
            "--compiler=clang",
            f"--machdep={machdep}",
            f"--rte={rte_flags}",
            f"--cflag={flags['backend']} {flags['frontend']}",
            "-o",
            str(out_bin),
            "-O",
            str(instrumented_c),
        ]
        if has_pthread:
            cmd.append("--concurrency")
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
            if has_pthread:
                fc_flags.append("-e-acsl-concurrency")
            if rte_initialized:
                fc_flags.append(EACSL_RTE_INITIALIZED_FLAG)
            if warn_unsigned_downcast:
                fc_flags.append("-warn-unsigned-downcast")
            if not variadic_translation:
                # Kernel option since Frama-C 34; the old Variadic plug-in spelling
                # -variadic-no-translation is rejected as unknown.
                fc_flags.append("-no-variadic-translation")
            if fns:
                fn_csv = ",".join(fns)
                fc_flags.append(f"-rte-select {fn_csv}")
                fc_flags.append(f"-e-acsl-functions {fn_csv}")
            # Pass --no-constfold so Frama-C's CIL constant folder does not zero-fold
            # hoisted block-scope `static const` arrays indexed by variables.
            cmd1 = [
                eacsl_bin,
                "-n",
                "--no-constfold",
                "-G",
                "clang",
                "-F",
                " ".join(fc_flags),
                "-E",
                flags["frontend"],
                "-o",
                str(instrumented_c),
                *sources,
            ]
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
        if instrumented_c.is_file():
            c_text = instrumented_c.read_text(encoding="utf-8", errors="replace")
            c_modified = False

            # Without this, clang rejects a member the kernel printed as `T m _Alignas(N) ;`.
            c_text, n_alignas = rewrite_trailing_alignas(c_text)
            if n_alignas:
                c_modified = True
                result["alignas_rewrites"] = n_alignas
                log_parts.append(
                    f"Rewrote {n_alignas} _Alignas(N) printed after a declarator as __attribute__((__aligned__(N))) "
                    "(the Frama-C printer misplaces member alignment; the alignment is kept).\n"
                )

            if rte_initialized:
                # Without this, any `ensures` reading \result fails \initialized(&__retres) on every input.
                c_text, n_inits = mark_wrapper_results_initialized(c_text)
                if n_inits:
                    c_modified = True
                    result["wrapper_result_inits"] = n_inits
                    log_parts.append(
                        f"Marked __retres initialized after {n_inits} contract-wrapper call(s) "
                        "(E-ACSL omits it; -rte-initialized would reject every ensures on \\result).\n"
                    )

            # Without this, the first read of a by-value struct field fails \initialized on every call.
            c_text, n_formals = mark_formals_initialized(c_text)
            if n_formals:
                c_modified = True
                result["formal_inits"] = n_formals
                log_parts.append(
                    f"Marked {n_formals} formal parameter(s) initialized at function entry "
                    "(E-ACSL registers formals without marking them; uninitialized struct members "
                    "passed by value are not reported).\n"
                )

            c_text, n_readonly = fix_readonly_scalar_globals(c_text)
            if n_readonly:
                c_modified = True
                result["readonly_scalar_global_fixes"] = n_readonly
                log_parts.append(
                    f"Fixed {n_readonly} E-ACSL readonly mark(s) for scalar const globals "
                    "(the printer passed the value instead of its address).\n"
                )

            c_text, n_rewrites = rewrite_sound_verdict_resets(c_text)
            if n_rewrites:
                c_modified = True
                result["sound_verdict_rewrites"] = n_rewrites
                log_parts.append(
                    f"Rewrote {n_rewrites} __e_acsl_sound_verdict = 0 reset(s) after strto*/wcsto* call(s).\n"
                )

            if fuzzer_flag:
                c_text, n_resets = reset_verdict_on_input_entry(c_text)
                if n_resets:
                    c_modified = True
                    result["verdict_resets_injected"] = n_resets
                    log_parts.append(
                        f"Injected {n_resets} __e_acsl_sound_verdict = 1 reset(s) at LLVMFuzzerTestOneInput entry.\n"
                    )

            if c_modified:
                instrumented_c.write_text(c_text, encoding="utf-8", newline="\n")

        init_hook: list[str] = []
        if fuzzer_flag:
            instrumented_text = (
                instrumented_c.read_text(encoding="utf-8", errors="replace") if instrumented_c.is_file() else ""
            )
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
            fb = build_fallback_object(
                instrumented_c,
                out_bin.parent / f"{out_bin.name}_fallbacks",
                runner=runner,
                timeout=BUILD_TIMEOUT_S,
            )
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
        log_parts.append(
            f"Binary {binary} does not contain E-ACSL instrumentation; refusing to label it engine=eacsl.\n"
        )
        return _finish(1, "eacsl_binary_not_instrumented")
    return _finish(0)


def _compile_clang_binary(
    engine: str,
    instrument_flags: list[str],
    log_suffix: str,
    sources: list[str],
    out_bin: Path,
    cppflags: str,
    ldflags_extra: str,
    runner,
    use_cache: bool,
) -> dict:
    """Compile a slice directly with Clang, cached (binary and compile log) outside agents/*/scratch."""
    out_bin = Path(out_bin)
    compile_log = out_bin.with_suffix(log_suffix)
    cppflags = target_env.with_include_flags(cppflags)
    ldflags_extra = target_env.with_link_flags(ldflags_extra)
    cmd = [
        "clang",
        "-g",
        "-O1",
        "-fcommon",
        *instrument_flags,
        *shlex.split(cppflags),
        *sources,
        "-o",
        str(out_bin),
        *shlex.split(ldflags_extra),
    ]

    def _build() -> dict:
        out_bin.parent.mkdir(parents=True, exist_ok=True)
        rc, stdout, stderr = _run_tool(cmd, runner or subprocess.run)
        compile_log.write_text(
            f"Command: {' '.join(cmd)}\nReturncode: {rc}\n--- STDOUT ---\n{stdout}\n--- STDERR ---\n{stderr}\n",
            encoding="utf-8",
        )
        return {
            "engine": engine,
            "returncode": rc,
            "command": " ".join(cmd),
            "binary": str(out_bin),
            "instrumented_source": None,
            "compile_log": str(compile_log),
            "stdout": stdout[-16000:],
            "stderr": stderr[-16000:],
        }

    if not use_cache or _in_agent_scratch(out_bin):
        res = _build()
        res["cache"] = {"hit": False, "key": None}
        return res
    material = {
        "kind": engine,
        "command": cmd,
        "sources": [str(s) for s in sources],
        "out_bin": out_bin.as_posix(),
    }
    return cache.memoize(
        "eacsl-build",
        material,
        sources=sources,
        dep_flags=shlex.split(cppflags),
        build=_build,
        outputs=lambda res: {"binary": out_bin, "compile.log": compile_log},
        ok=lambda res: res.get("returncode") == 0,
        runner=runner,
        on_restore=_note_cache_restore,
    )


def compile_sanitizer_binary(
    sources: list[str],
    out_bin: Path,
    cppflags: str = "-I.",
    fuzzer_flag: bool = True,
    ldflags_extra: str = "",
    runner=None,
    use_cache: bool = True,
) -> dict:
    """
    Compile a slice directly with Clang + LibFuzzer + ASan + UBSan when E-ACSL cannot instrument.
    Cached like `compile_eacsl_binary` (binary and compile log) outside agents/*/scratch.
    """
    san_flags = "-fsanitize=fuzzer,address,undefined" if fuzzer_flag else "-fsanitize=address,undefined"
    return _compile_clang_binary(
        "sanitizers",
        [san_flags, "-fno-sanitize-recover=all"],
        ".sanitizer_compile.log",
        sources,
        out_bin,
        cppflags,
        ldflags_extra,
        runner,
        use_cache,
    )


def compile_coverage_binary(
    sources: list[str],
    out_bin: Path,
    cppflags: str = "-I.",
    ldflags_extra: str = "",
    runner=None,
    use_cache: bool = True,
) -> dict:
    """
    Compile a slice with Clang source coverage + LibFuzzer's driver, without E-ACSL or sanitizers:
    regions then map to the target's own source rather than to generated checks, and a check that
    aborts cannot lose the profile of the inputs replayed before it.
    """
    return _compile_clang_binary(
        "coverage",
        ["-fprofile-instr-generate", "-fcoverage-mapping", "-fsanitize=fuzzer"],
        ".coverage_compile.log",
        sources,
        out_bin,
        cppflags,
        ldflags_extra,
        runner,
        use_cache,
    )


def _artifact_kind(name: str) -> str | None:
    for prefix, kind in ARTIFACT_KINDS:
        if name.startswith(prefix):
            return kind
    return None


def replay_artifact(
    binary: Path,
    artifact: Path,
    scratch: Path,
    timeout_s: int = 60,
    *,
    module: str = "",
    per_input_timeout: int = DEFAULT_PER_INPUT_TIMEOUT_S,
    seed: int | None = None,
) -> dict:
    """
    Replay one input in the sandbox with a fixed per-input `-timeout`, the fixed `-rss_limit_mb`
    and a deterministic `-seed` (derive_seed); report the parsed failure and whether it reproduced.
    """
    binary = Path(binary)
    seed = derive_seed(binary, module) if seed is None else seed
    wall = max(int(timeout_s), 2 * int(per_input_timeout) + 10)
    res = run_sandboxed(
        [
            str(binary.resolve()),
            "-runs=1",
            f"-timeout={per_input_timeout}",
            f"-rss_limit_mb={FUZZ_RSS_LIMIT_MB}",
            f"-seed={seed}",
            str(Path(artifact).resolve()),
        ],
        writable=[scratch],
        timeout_s=wall,
        limits=Limits(cpu_seconds=wall * 2),
        extra_env=SANITIZER_RUNTIME_ENV,
    )
    out = res.stdout + "\n" + res.stderr
    return {
        "reproduced": res.returncode != 0 or res.timed_out,
        "returncode": res.returncode,
        "timed_out": res.timed_out,
        "failure": parse_runtime_failure(out),
        "sandbox": res.sandbox,
        "seed": seed,
        "log_tail": out[-3000:],
    }


def _collapse_duplicate_artifacts(artifacts: list[dict]) -> tuple[list[dict], int]:
    """At most MAX_ARTIFACTS_PER_FINGERPRINT entries per fingerprint, in order; and how many were dropped."""
    kept: list[dict] = []
    per_fp: Counter = Counter()
    dropped = 0
    for a in artifacts:
        fp = a.get("fingerprint")
        if fp:
            per_fp[fp] += 1
            if per_fp[fp] > MAX_ARTIFACTS_PER_FINGERPRINT:
                dropped += 1
                continue
        kept.append(a)
    return kept, dropped


def dispatch_case_count(sources: list[str]) -> int | None:
    """
    The number of cases of a `dispatch` harness among `sources` that a build can skip with
    -D<DISPATCH_SKIP_MACRO> (generate_harness.py), or None: no such harness, or one generated
    before the macro existed.
    """
    for src in sources:
        try:
            text = Path(src).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if DISPATCH_SKIP_MACRO not in text:
            continue
        m = _DISPATCH_SWITCH_RE.search(text)
        if m:
            return int(m.group(1))
    return None


def dispatch_skippable_cases(sources: list[str], n_cases: int) -> int:
    """
    How many of a dispatch harness's `n_cases` (cases 0..result-1) a build can skip: all of them for
    a harness whose guard carries DISPATCH_SKIP_ALL_MARKER, cases 0..63 for one generated before.
    """
    for src in sources:
        try:
            text = Path(src).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if DISPATCH_SKIP_MACRO in text and _DISPATCH_SWITCH_RE.search(text):
            return n_cases if DISPATCH_SKIP_ALL_MARKER in text else min(n_cases, 64)
    return min(n_cases, 64)


def dispatch_skip_cppflags(mask: int) -> str:
    """The -D flags that skip the cases set in `mask`: word 0 always, word k (cases 64k..) when not 0."""
    flags = [f"-D{DISPATCH_SKIP_MACRO}={mask & (2**64 - 1):#x}ULL"]
    k = 1
    while mask >> (64 * k):
        word = (mask >> (64 * k)) & (2**64 - 1)
        if word:
            flags.append(f"-D{DISPATCH_SKIP_MACRO}_{k}={word:#x}ULL")
        k += 1
    return " ".join(flags)


def artifact_dispatch_case(artifact: dict, n_cases: int) -> int | None:
    """The dispatch case an artifact's input selects (its first byte modulo `n_cases`), or None if empty."""
    try:
        with open(artifact["artifact"], "rb") as fh:
            first = fh.read(1)
    except (OSError, KeyError):
        return None
    return first[0] % n_cases if first else None


def run_campaign_rounds(
    binary: Path,
    max_time: int,
    *,
    campaign,
    rebuild,
    n_cases: int | None,
    keep_going: bool = True,
    skippable: int | None = None,
) -> dict:
    """
    A campaign that keeps going after a crash, within `max_time` seconds of fuzzing in all.

    `campaign(binary, max_time, fork)` runs one libFuzzer campaign (run_fuzz_campaign) and
    `rebuild(mask)` returns (binary, build record) for a build skipping the dispatch cases set in
    `mask`, binary None when the build failed.

    - A `dispatch` harness (`n_cases`) runs in rounds: each case an input crashed in is skipped from
      the next round on, so a shallow bug stops ending every run and the other cases get the rest of
      the time. Rounds end when a round finds no new crashing case, every case is skipped, less than
      MIN_ROUND_WALL_S seconds are left, a round's new crashing cases cannot be skipped
      (`unskippable_case`: cases `skippable` and above, for a harness generated before every case
      was skippable), or a rebuild fails. In the last two, the time left runs in fork mode with
      crashes ignored on the last binary built (`fork_fallback`).
    - Any other harness runs once in fork mode with crashes ignored.
    - Without `keep_going`, one campaign that stops at the first crash, as before.
    """
    if not keep_going:
        return campaign(binary, max_time, False)
    if n_cases is None:
        res = campaign(binary, max_time, True)
        res["keep_going"] = {"mode": "fork"}
        return res
    skippable = n_cases if skippable is None else min(skippable, n_cases)

    skipped: set[int] = set()
    rounds: list[dict] = []
    collected: list[dict] = []
    spent = 0.0
    last: dict = {}
    fallback_reason: str | None = None
    while True:
        budget = max(MIN_FUZZ_WALL_S if not rounds else MIN_ROUND_WALL_S, int(max_time - spent))
        started = time.monotonic()
        last = campaign(binary, budget, False)
        spent += time.monotonic() - started
        arts = last.get("artifacts") or []
        collected.extend(arts)
        crashed = sorted(
            {
                c
                for a in arts
                if a.get("kind") in ("crash", "leak", "timeout", "oom") and not a.get("pre_existing")
                for c in [artifact_dispatch_case(a, n_cases)]
                if c is not None
            }
        )
        rnd = {
            "skipped_cases": sorted(skipped),
            "max_time": budget,
            "status": last.get("status"),
            "returncode": last.get("returncode"),
            "artifacts": len(arts),
            "crashed_cases": crashed,
        }
        rounds.append(rnd)
        fresh = [c for c in crashed if c not in skipped]
        new = [c for c in fresh if c < skippable]
        if last.get("status") == "insufficient_memory" or not fresh:
            break
        if max_time - spent < MIN_ROUND_WALL_S:
            rnd["stopped"] = "time_budget_spent"
            break
        if not new:
            rnd["stopped"] = fallback_reason = "unskippable_case"
            rnd["unskippable_cases"] = fresh
            break
        skipped.update(new)
        if len(skipped) >= n_cases:
            rnd["stopped"] = "every_case_skipped"
            break
        mask = sum(1 << c for c in skipped)
        next_binary, build = rebuild(mask)
        if next_binary is None:
            comp = (build or {}).get("compile") or {}
            rnd["stopped"] = fallback_reason = "rebuild_failed"
            rnd["rebuild_log_tail"] = str(comp.get("log_tail") or comp.get("stderr") or "")[-2000:]
            break
        binary = next_binary

    fallback: dict | None = None
    left = int(max_time - spent)
    if fallback_reason and left >= MIN_ROUND_WALL_S:
        # The cases still crashing cannot be skipped: the time left goes to fork mode, which keeps
        # fuzzing past each crash, on the last binary built (its skipped cases stay skipped).
        started = time.monotonic()
        last = campaign(binary, left, True)
        spent += time.monotonic() - started
        arts = last.get("artifacts") or []
        collected.extend(arts)
        fallback = {
            "reason": fallback_reason,
            "max_time": left,
            "status": last.get("status"),
            "returncode": last.get("returncode"),
            "artifacts": len(arts),
        }

    seen: set[str] = set()
    unique = []
    for a in collected:
        key = str(a.get("sha256") or a.get("artifact") or "")
        if key not in seen:
            seen.add(key)
            unique.append(a)
    merged, dropped = _collapse_duplicate_artifacts(unique)
    out = dict(last)
    out["artifacts"] = merged
    if last.get("status") != "insufficient_memory":
        out["status"] = classify_campaign(last.get("returncode") or 0, bool(last.get("timed_out")), merged)
    if dropped:
        omitted = dict(out.get("artifacts_omitted") or {})
        omitted["duplicates"] = omitted.get("duplicates", 0) + dropped
        out["artifacts_omitted"] = omitted
    out["keep_going"] = {
        "mode": "dispatch_rounds",
        "dispatch_cases": n_cases,
        "skippable_cases": skippable,
        "skipped_cases": sorted(skipped),
        "fuzz_seconds": round(spent, 1),
        "rounds": rounds,
    }
    if fallback is not None:
        out["keep_going"]["fork_fallback"] = fallback
    return out


def merge_engine_campaigns(runs: dict[str, dict]) -> dict:
    """
    One report for a module fuzzed with several engines, in the order run: every artifact (each
    carries its `engine`), the most severe status, and each engine's own outcome under `engines`.
    """
    artifacts: list[dict] = []
    engines: dict[str, dict] = {}
    for engine, run in runs.items():
        artifacts.extend(run.get("artifacts") or [])
        engines[engine] = {
            key: run[key]
            for key in ("status", "returncode", "timed_out", "keep_going", "artifacts_omitted", "fork")
            if key in run
        }
        engines[engine]["artifacts"] = len(run.get("artifacts") or [])
    statuses = [r.get("status") for r in runs.values()]
    if "insufficient_memory" in statuses:
        status = "insufficient_memory"
    elif all(st in ("clean", "fuzzer_error") for st in statuses) and "fuzzer_error" in statuses:
        status = "fuzzer_error"  # a run that did not complete is never reported as clean
    else:
        status = classify_campaign(0, False, artifacts)
    last = list(runs.values())[-1]
    return {
        "status": status,
        "returncode": last.get("returncode"),
        "timed_out": any(bool(r.get("timed_out")) for r in runs.values()),
        "sandbox": last.get("sandbox"),
        "artifacts": artifacts,
        "engines": engines,
        "log_tail": "\n".join(f"--- {e}\n{(r.get('log_tail') or '')[-2000:]}" for e, r in runs.items()),
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


_DICT_LINE_RE = re.compile(r'^(?P<prefix>(?:[A-Za-z0-9_]+\s*=\s*)?)"(?P<val>.*)"(?P<suffix>\s*(?:#.*)?)$')


def sanitize_dictionary_token(raw_val: str) -> str:
    """
    Sanitize the string inside a dictionary entry's quotes for LibFuzzer.
    Converts raw backslashes and invalid escapes to valid hex escapes (\\xHH) or \\\\,
    and converts non-printable / control bytes to \\xHH.
    """
    out: list[str] = []
    i = 0
    n = len(raw_val)
    while i < n:
        c = raw_val[i]
        # Check for escape sequences
        if c == "\\":
            if i + 1 >= n:
                # Trailing backslash -> escape it
                out.append("\\\\")
                i += 1
                continue
            nxt = raw_val[i + 1]
            if nxt == "\\" or nxt == '"':
                out.append(c + nxt)
                i += 2
                continue
            if nxt in ("x", "X") and i + 3 < n and all(raw_val[i + k] in "0123456789abcdefABCDEF" for k in (2, 3)):
                out.append(f"\\x{raw_val[i + 2 : i + 4].lower()}")
                i += 4
                continue
            if nxt == "n":
                out.append("\\x0a")
                i += 2
                continue
            if nxt == "r":
                out.append("\\x0d")
                i += 2
                continue
            if nxt == "t":
                out.append("\\x09")
                i += 2
                continue
            if nxt == "0":
                out.append("\\x00")
                i += 2
                continue
            # Unknown escape like \a, \b, \p -> escape the backslash
            out.append("\\\\")
            i += 1
            continue

        # Check for non-printable or non-ASCII characters
        code = ord(c)
        if code < 32 or code >= 127:
            out.append(f"\\x{code & 0xFF:02x}")
        elif c == '"':
            out.append('\\"')
        else:
            out.append(c)
        i += 1

    return "".join(out)


def sanitize_dictionary_line(line: str) -> str:
    """Sanitize a single line in a LibFuzzer dictionary."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return line

    m = _DICT_LINE_RE.match(line)
    if m:
        prefix = m.group("prefix")
        val = m.group("val")
        suffix = m.group("suffix")
        return f'{prefix}"{sanitize_dictionary_token(val)}"{suffix}'

    # Line is not in standard `"..."` format; if it has `name = val` or just `val`
    if "=" in line:
        name, _, rest = line.partition("=")
        rest_val = rest.strip().strip('"')
        return f'{name.strip()} = "{sanitize_dictionary_token(rest_val)}"'
    else:
        rest_val = stripped.strip('"')
        return f'"{sanitize_dictionary_token(rest_val)}"'


def sanitize_dictionary_content(content: str) -> str:
    """Sanitize all entries in LibFuzzer dictionary content."""
    lines = content.splitlines(keepends=True)
    out: list[str] = []
    for line in lines:
        ending = "\n" if line.endswith("\n") else ""
        raw_line = line[:-1] if ending else line
        out.append(sanitize_dictionary_line(raw_line) + ending)
    return "".join(out)


def sanitize_fuzzer_dictionary(dict_path: Path, out_path: Path | None = None) -> Path:
    """Read a LibFuzzer dictionary, sanitize entries by escaping backslashes and non-printables, and write out."""
    dict_path = Path(dict_path)
    if not dict_path.is_file():
        return dict_path
    text = dict_path.read_text(encoding="utf-8", errors="replace")
    sanitized = sanitize_dictionary_content(text)
    if out_path is None:
        out_path = dict_path.with_name(f"{dict_path.stem}.sanitized{dict_path.suffix}")
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(sanitized, encoding="utf-8")
    return out_path


AUTO_DICT_DIR = Path("workspace/dicts")


def _dict_stem(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name).strip("._") or "module"


def auto_dictionary_path(module: str, corpus_dir: Path) -> Path:
    """Where `campaign` writes its auto-dictionary: workspace/dicts/<module>.dict, else next to the corpus."""
    if module:
        return AUTO_DICT_DIR / f"{_dict_stem(module)}.dict"
    corpus_dir = Path(corpus_dir)
    return corpus_dir.parent / f"{_dict_stem(corpus_dir.name)}.auto.dict"


def dictionary_target_sources(sources: list[str] | list[Path]) -> list[Path]:
    """The campaign's target sources for literal extraction: existing files, the harness excluded, sorted."""
    out: set[Path] = set()
    for s in sources or []:
        p = Path(s)
        if p.name.startswith("harness_") or not p.is_file():
            continue
        out.add(p)
    return sorted(out, key=lambda p: p.as_posix())


def build_auto_dictionary(sources: list[str] | list[Path], out_path: Path, cppflags: str | None = None) -> dict:
    """
    Extract a libFuzzer dictionary from the campaign's target sources (scripts/fuzz_dictionary.py, in-process)
    and write it atomically to `out_path`. Never raises: an empty or failed extraction returns
    `path: None` and a `reason`, and the campaign proceeds without a dictionary. The content depends only on
    the target sources' text (files sorted, tokens in a fixed order), so the same slice gives the same file.
    """
    out_path = Path(out_path)
    info: dict = {"path": None, "auto": True, "entries": 0}
    targets = dictionary_target_sources(sources)
    info["source_files"] = len(targets)
    if not targets:
        info["reason"] = "no readable target sources besides the harness"
        return info
    try:
        tokens = fuzz_dictionary.build_dictionary(sources=list(targets), cppflags=cppflags)
    except Exception as exc:  # never fail the campaign over a dictionary
        info["reason"] = f"extraction failed: {type(exc).__name__}: {exc}"
        return info
    if not tokens:
        info["reason"] = "extraction produced no tokens"
        return info
    content = fuzz_dictionary.render_dictionary(tokens)
    tmp: Path | None = None
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=str(out_path.parent), prefix=".tmp_", suffix=".dict")
        tmp = Path(tmp_name)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
        os.replace(tmp, out_path)
        tmp = None
    except OSError as exc:
        info["reason"] = f"could not write {out_path.as_posix()}: {exc}"
        return info
    finally:
        if tmp is not None:
            with contextlib.suppress(OSError):
                tmp.unlink()
    info.update(
        {
            "path": out_path.as_posix(),
            "entries": len(tokens),
            "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
        }
    )
    return info


def resolve_campaign_dictionary(
    explicit: Path | None,
    sources: list[str],
    module: str,
    corpus_dir: Path,
    auto: bool = True,
    cppflags: str | None = None,
) -> tuple[Path | None, dict]:
    """The dictionary a campaign passes to libFuzzer as -dict=, and the report's `dictionary` record."""
    if explicit is not None:
        p = Path(explicit)
        return p, {"path": p.as_posix(), "auto": False, "exists": p.is_file()}
    if not auto:
        return None, {"path": None, "auto": False, "reason": "disabled by --no-auto-dict"}
    info = build_auto_dictionary(sources, auto_dictionary_path(module, corpus_dir), cppflags)
    extra = extra_dictionary_path(module)
    if extra is not None and extra.is_file():
        info = merge_extra_dictionary(info, extra)
    return (Path(info["path"]) if info.get("path") else None), info


def extra_dictionary_path(module: str) -> Path | None:
    """The target's shipped dictionary for `module` (workspace/dicts/<module>.extra.dict, scripts/fuzz_assets.py)."""
    return AUTO_DICT_DIR / f"{_dict_stem(module)}.extra.dict" if module else None


def _dictionary_entry_lines(text: str) -> list[str]:
    return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]


def merge_extra_dictionary(info: dict, extra: Path) -> dict:
    """
    Append the entries of the target's shipped dictionary `extra` to the auto-dictionary `info` describes
    (identical lines once) and record `extra_entries`. Without an auto-dictionary, `extra` is used alone.
    Never raises: an unreadable `extra` leaves `info` as it was, with an `extra_reason`.
    """
    info = dict(info)
    try:
        extra_lines = list(dict.fromkeys(_dictionary_entry_lines(extra.read_text(encoding="utf-8", errors="replace"))))
    except OSError as exc:
        info["extra_reason"] = f"could not read {extra.as_posix()}: {exc}"
        return info
    auto_path = Path(info["path"]) if info.get("path") else None
    if auto_path is None:
        info.update({"path": extra.as_posix(), "entries": len(extra_lines), "extra_entries": len(extra_lines)})
        return info
    try:
        auto_text = auto_path.read_text(encoding="utf-8", errors="replace")
        seen = set(_dictionary_entry_lines(auto_text))
        added = [ln for ln in extra_lines if ln not in seen]
        content = auto_text if auto_text.endswith("\n") or not auto_text else auto_text + "\n"
        content += "".join(f"{ln}\n" for ln in added)
        fd, tmp_name = tempfile.mkstemp(dir=str(auto_path.parent), prefix=".tmp_", suffix=".dict")
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
        os.replace(tmp_name, auto_path)
    except OSError as exc:
        info["extra_reason"] = f"could not merge {extra.as_posix()}: {exc}"
        return info
    info["entries"] = int(info.get("entries") or 0) + len(added)
    info["extra_entries"] = len(added)
    info["sha256"] = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return info


def run_fuzz_campaign(
    binary: Path,
    corpus_dir: Path,
    artifacts_dir: Path,
    max_time: int = 60,
    dict_file: Path | None = None,
    per_input_timeout: int = DEFAULT_PER_INPUT_TIMEOUT_S,
    rss_limit_mb: int = FUZZ_RSS_LIMIT_MB,
    extra_corpus: list[Path] | None = None,
    attribution_builder=None,
    jobs: int = 1,
    workers: int = 1,
    fork: bool = False,
) -> dict:
    """
    `corpus_dir` receives new units (writable); `extra_corpus` directories are read-only
    seed inputs (e.g. the shared module corpus when a breaker works in its own scratch).

    `fork` runs libFuzzer's fork mode with `-ignore_crashes=1` instead of -jobs/-workers: a crash
    is saved and fuzzing goes on until `max_time`. The same bug is then usually saved many times,
    so at most MAX_REPLAYED_CRASHES crash inputs are replayed and the report lists at most
    MAX_ARTIFACTS_PER_FINGERPRINT per fingerprint (`artifacts_omitted` counts the rest).

    `attribution_builder` is an optional zero-argument callable returning the path of a
    Clang ASan+UBSan build of the same slice (or None). It is called at most once, only when
    an E-ACSL crash has no usable location (failure missing, line 0, or a runtime-internal
    function), and the crash input is replayed on that build to attribute file:line.
    """
    req_mem = fuzz_required_memory_mb(workers)
    mem_limit = enforced_memory_mb()
    if mem_limit is not None and mem_limit < req_mem:
        note = (
            f"this job may use {mem_limit} MiB, but LibFuzzer needs at least {req_mem} MiB "
            f"({FUZZ_WORKER_OVERHEAD_MB} MiB overhead plus {workers} worker(s) at "
            f"{int(FUZZ_RSS_LIMIT_MB * 1.25)} MiB each for the fixed {FUZZ_RSS_LIMIT_MB} MiB -rss_limit_mb)"
        )
        return {
            "status": "insufficient_memory",
            "reason": "insufficient_memory",
            "error_summary": [note],
            "memory_limit_mb": mem_limit,
            "min_memory_mb": req_mem,
            "returncode": None,
            "timed_out": False,
            "artifacts": [],
            "new_A2_artifacts": [],
            "log_tail": note,
        }
    corpus_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.gettempdir()) / f"fuzz_scratch_{artifacts_dir.name}_{os.getpid()}"
    scratch.mkdir(parents=True, exist_ok=True)
    try:
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

        extra_env = dict(SANITIZER_RUNTIME_ENV)
        if fork:
            # Fork mode keeps its per-job directories under TMPDIR; keep them in the scratch.
            cmd[1:1] = [f"-fork={eff_workers}", "-ignore_crashes=1"]
            extra_env["TMPDIR"] = str(scratch.resolve())
            waves = 1
        else:
            if eff_workers > 1:
                cmd.insert(1, f"-workers={eff_workers}")
            if eff_jobs > 1:
                cmd.insert(1, f"-jobs={eff_jobs}")
            waves = max(1, (eff_jobs + eff_workers - 1) // eff_workers)
        if dict_file and dict_file.exists():
            sanitized_dict = sanitize_fuzzer_dictionary(dict_file, scratch / f"{dict_file.stem}.sanitized.dict")
            cmd.insert(1, f"-dict={sanitized_dict.resolve()}")

        wall_timeout = max_time * waves + 180
        cpu_mult = max(2, eff_workers + 1)
        res = run_sandboxed(
            cmd,
            writable=[scratch, corpus_dir, artifacts_dir],
            timeout_s=wall_timeout,
            limits=Limits(cpu_seconds=wall_timeout * cpu_mult),
            extra_env=extra_env,
        )
        MAX_WORKER_LOG_BYTES = 1024 * 1024
        worker_logs: list[str] = []
        for log_path in sorted(scratch.glob("fuzz-*.log")):
            if log_path.is_file():
                try:
                    sz = log_path.stat().st_size
                    if sz <= MAX_WORKER_LOG_BYTES:
                        worker_logs.append(log_path.read_text(encoding="utf-8", errors="replace"))
                    else:
                        with log_path.open("rb") as f:
                            f.seek(sz - MAX_WORKER_LOG_BYTES)
                            tail_bytes = f.read(MAX_WORKER_LOG_BYTES)
                        worker_logs.append(
                            "... [truncated earlier worker log] ...\n" + tail_bytes.decode("utf-8", errors="replace")
                        )
                except OSError:
                    pass
        combined_out = "\n".join([res.stdout, res.stderr, *worker_logs])
        written_names = {Path(m.group("path").strip()).name for m in _TEST_UNIT_WRITTEN_RE.finditer(combined_out)}

        all_artifact_files = [
            p for p in sorted(artifacts_dir.iterdir()) if _artifact_kind(p.name) and p.is_file() and not p.is_symlink()
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

        crash_like = sum(1 for p, _ in selected_files if _artifact_kind(p.name) in ("crash", "leak"))
        replayed = 0
        unreplayed = 0
        for p, pre_existing in selected_files:
            kind = _artifact_kind(p.name)
            if not kind:
                continue
            if kind in ("crash", "leak"):
                if replayed >= MAX_REPLAYED_CRASHES:
                    unreplayed += 1
                    continue
                replayed += 1
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
                replay = replay_artifact(binary, p, scratch, per_input_timeout=per_input_timeout)
                # The campaign log names one failure; it can only stand for this input if it is the only one.
                failure = replay["failure"] or (parse_runtime_failure(combined_out) if crash_like == 1 else None)
                entry["reproducible"] = replay["reproduced"]
                entry["replay_log_tail"] = replay["log_tail"]
                entry["failure_source"] = "primary" if failure else None
                if needs_attribution(failure):
                    san_bin = _attribution_binary()
                    if san_bin is not None:
                        san_replay = replay_artifact(Path(san_bin), p, scratch, per_input_timeout=per_input_timeout)
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
                        failure["file"],
                        failure["function"],
                        failure["alarm_kind"] or failure["kind"],
                        failure["predicate"],
                    )
            artifacts.append(entry)

        artifacts, omitted = _collapse_duplicate_artifacts(artifacts)
        status = classify_campaign(res.returncode, res.timed_out, artifacts)
        out = {
            "status": status,
            "returncode": res.returncode,
            "timed_out": res.timed_out,
            "sandbox": res.sandbox,
            "artifacts": artifacts,
            "log_tail": combined_out[-4000:],
        }
        if fork:
            out["fork"] = eff_workers
        if omitted or unreplayed:
            out["artifacts_omitted"] = {"duplicates": omitted, "not_replayed": unreplayed}
        return out
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


_COVERAGE_LINE_RE = re.compile(
    r"^(?:UN)?COVERED_FUNC: hits: (\d+) edges: \d+/\d+ (\S+) .*$|^COVERAGE:\s*$|^stat::number_of_executed_units: (\d+)\s*$",
    re.MULTILINE,
)


def parse_guardrail_reach(output: str, functions: list[str] | None) -> tuple[dict, str]:
    """
    What a guardrail replay executed, from libFuzzer's -print_coverage, and the output without those
    lines (a report can run to hundreds of them, which would push a failure out of any log tail).

    E-ACSL moves a contract into `__gen_e_acsl_<fn>`, so a function counts as reached through either
    name. A function in neither list was inlined or not instrumented: its reach is unknown (None).
    """
    hits: dict[str, int] = {}
    executed: int | None = None
    for m in _COVERAGE_LINE_RE.finditer(output or ""):
        if m.group(3) is not None:
            executed = int(m.group(3))
        elif m.group(2) is not None:
            hits[m.group(2)] = hits.get(m.group(2), 0) + int(m.group(1))
    by_fn: dict[str, int | None] = {}
    for fn in functions or []:
        names = [n for n in (fn, f"__gen_e_acsl_{fn}") if n in hits]
        by_fn[fn] = sum(hits[n] for n in names) if names else None
    reach = {
        "measured": bool(hits),
        "executed_inputs": executed,
        "functions": by_fn,
        "unreached": sorted(fn for fn, n in by_fn.items() if n == 0),
    }
    return reach, _COVERAGE_LINE_RE.sub("", output or "")


def classify_guardrail(returncode: int, timed_out: bool, output: str) -> dict:
    has_unsound = bool(re.search(r"[Ww]arning:\s*(?:no sound verdict for|unsound verdict)", output or ""))
    if has_unsound:
        if returncode == 0 and not timed_out:
            return {
                "status": "guardrail_error",
                "reason": "E-ACSL emitted unsound verdict warning during execution",
                "unsound": True,
            }
        return {
            "status": "guardrail_error",
            "reason": "Assertion failed under unsound E-ACSL verdict",
            "unsound": True,
            "failure": parse_eacsl_failure(output),
        }
    if returncode == 0 and not timed_out:
        return {"status": "passed_dynamic_oracle"}
    failure = parse_eacsl_failure(output)
    if failure is None:
        return {
            "status": "guardrail_error",
            "reason": "Binary failed without a recognizable E-ACSL failure report.",
            "failure": None,
        }
    if failure.get("annotation_rte"):
        return {
            "status": "rejected_overconstrained",
            "reason": (
                "An ACSL annotation evaluated an undefined term at runtime under E-ACSL's 3-valued partial logic "
                "(e.g. unguarded division/modulo by zero or invalid pointer dereference inside a contract/assertion)."
            ),
            "annotation_rte": True,
            "failure": failure,
        }
    if failure["is_rte"]:
        return {
            "status": "code_fault",
            "reason": "An RTE assertion failed on a real input: code defect candidate, not evidence against the proposed contract.",
            "fingerprint": make_fingerprint(
                failure["file"], failure["function"], failure["alarm_kind"] or failure["kind"], failure["predicate"]
            ),
            "failure": failure,
        }
    return {
        "status": "rejected_overconstrained",
        "reason": "A proposed ACSL annotation failed at runtime on a real corpus/test input.",
        "failure": failure,
    }


def derive_eacsl_diagnostic_hints(res: dict) -> list[str]:
    """
    Generate concise, actionable diagnostic hints for E-ACSL guardrail rejections and
    instrumentation compile errors. Returns [] when status == 'passed_dynamic_oracle'.
    """
    status = res.get("status")
    if status == "passed_dynamic_oracle":
        passed_hints: list[str] = []
        if res.get("corpus_empty"):
            passed_hints.append(
                "The module corpus is empty: this pass replayed no real input, only mutations of an empty one. "
                "It is not evidence that the contract holds on real inputs; the merged proof records it as an "
                "open assumption."
            )
        unreached = (res.get("reach") or {}).get("unreached") or []
        if unreached:
            passed_hints.append(
                f"This pass tested nothing for {', '.join(unreached)}: no replayed input reached it, so its contract "
                "was not challenged at runtime. The merged proof records this as an open assumption. Keep every "
                "`requires` as weak as the proof allows, because no runtime check will catch an over-constrained one."
            )
        return passed_hints
    if status in ("built", "no_crash"):
        return []

    hints: list[str] = []

    def _add(msg: str) -> None:
        if msg not in hints:
            hints.append(msg)

    if status == "rejected_overconstrained":
        failure = res.get("failure") or {}
        kind = (failure.get("kind") or "").lower()
        label = (failure.get("label") or "").lower()
        pred = failure.get("predicate") or ""
        loc = f"{failure.get('file', 'unknown')}:{failure.get('line', 0)} in {failure.get('function', 'unknown')}"
        _add(
            f"ACSL annotation failed at runtime on a real corpus input ({loc}, clause={label or kind!r}, "
            f"predicate={pred!r}): your specification is stronger than the actual runtime behavior."
        )
        if res.get("annotation_rte") or failure.get("annotation_rte") or kind == "rte":
            _add(
                "ACSL annotation runtime error (RTE inside specification): unlike WP's 2-valued total logic, "
                "E-ACSL uses 3-valued partial logic and aborts when an annotation evaluates an undefined term "
                "(such as 'x / y' or 'x % y' when 'y == 0', or '*p' / 'buf[i]' on an invalid/out-of-bounds pointer). "
                "Guard partial terms on the left of '==>' or '&&' (e.g. 'y != 0 ==> x % y == 0', "
                "'\\valid_read(p) ==> *p == 0')."
            )
        if "\\valid" in pred:
            _add(
                "Pointer validity clause failed at runtime: if 'len == 0' can occur with a NULL or one-past-end "
                "pointer, guard the clause with 'requires len > 0 ==> \\valid_read(buf + (0 .. len - 1));'."
            )
        if "\\initialized" in pred:
            _add(
                "Initialization predicate failed at runtime: E-ACSL tracks initialization per byte across "
                "'sizeof(*p)' in flat shadow memory, so '\\initialized(p)' fails on structs with uninitialized "
                "padding bytes or unions initialized via a smaller member. Assert field-level initialization "
                "('\\initialized(&p->field)') rather than whole-struct/union '\\initialized(p)'."
            )
        if "precondition" in kind or "requires" in kind or "requires" in label:
            _add(
                "Precondition failed on a real caller/harness input: never constrain attacker-controlled values "
                "or lengths on untrusted entry functions, and relax bounds that exclude valid caller inputs."
            )
        elif "postcondition" in kind or "ensures" in kind or "ensures" in label:
            _add(
                "Postcondition failed at runtime: check whether the property only holds on success "
                "(guard with '\\result == 0 ==> ...') or whether '\\old(...)' was omitted when comparing to pre-state."
            )
        elif "invariant" in kind or "invariant" in label:
            _add(
                "Loop invariant failed at runtime: check the entry and exit bounds (use '0 <= i <= n', NOT "
                "'0 <= i < n') and verify accumulator relationships against negative or boundary inputs."
            )
        return hints

    if status == "code_fault":
        failure = res.get("failure") or {}
        loc = f"{failure.get('file', 'unknown')}:{failure.get('line', 0)} in {failure.get('function', 'unknown')}"
        _add(
            f"RTE assertion failed at runtime on a real input ({loc}, predicate={failure.get('predicate')!r}): "
            "this is a code defect candidate, NOT a contract error. Do NOT weaken your ACSL contracts to hide it; "
            "stop synthesis and return status 'blocked' (or 'failed' for architect) with this guardrail report in 'evidence'."
        )
        return hints

    if status in ("compile_error", "guardrail_error"):
        comp = res.get("compile") or {}
        log_blob = "\n".join(
            [
                str(res.get("reason") or ""),
                str(comp.get("reason") or ""),
                str(comp.get("stdout") or ""),
                str(comp.get("stderr") or ""),
            ]
        )
        if any(
            k in log_blob.lower()
            for k in ("unbounded quantification", "invalid quantification", "quantification", "\\forall", "\\exists")
        ):
            _add(
                "E-ACSL rejected a quantifier: E-ACSL only executes bounded integer quantifications written as "
                "'\\forall integer k; 0 <= k < n ==> ...' (use mathematical type 'integer' and chained 'lo <= k < hi' bounds)."
            )
        if res.get("unsound") or "unsound" in log_blob.lower() or "no sound verdict for" in log_blob.lower():
            _add(
                "E-ACSL emitted an unsound verdict warning: an assertion was evaluated under an untrusted verdict, "
                "often caused by unsupported C standard library functions (e.g. unmodeled libc conversions) or constructs. "
                "Inspect the execution output and replace unsupported calls with verified or modeled equivalents."
            )
        if any(
            k in log_blob.lower()
            for k in ("not yet supported", "unsupported", "axiomatic", "no body", "comparison of", "with")
        ):
            _add(
                "E-ACSL encountered an unsupported ACSL construct (such as an uninterpreted 'axiomatic' logic "
                "function without a definition, or a whole-struct/union comparison 's1 == s2' / functional update "
                "'{ s \\with .x = v }'): rewrite as a concrete 'predicate', bounded '\\forall integer k; 0 <= k < n ==> ...', "
                "or field-by-field scalar comparisons ('s1.x == s2.x')."
            )
        if any(
            k in log_blob.lower() for k in ("annot-error", "syntax error", "unbound logic", "wrong order of clause")
        ):
            _add(
                "ACSL syntax/typing error during E-ACSL build: verify clause order ('requires -> terminates -> exits -> "
                "assigns -> ensures' for functions; 'loop invariant -> loop assigns -> loop variant' for loops), "
                "';' terminators, and intact backslashes (\\valid, \\forall, \\old, \\result)."
            )
        if "not e-acsl-instrumented" in log_blob.lower():
            _add(
                "Guardrail binary lacks E-ACSL instrumentation: ensure '--functions <function_name>' names a "
                "non-inlined C function defined in '--sources'."
            )
        if not hints and status == "compile_error":
            _add(
                "E-ACSL instrumentation/compilation failed: inspect 'compile.stderr' and 'compile.compile_log' "
                "for ACSL annotation or C header errors."
            )
    return hints


def corpus_manifest(corpus_dir: Path) -> list[list[str | int]]:
    """Sorted `[name, sha256, size]` manifest of regular non-hidden files in `corpus_dir`."""
    if not Path(corpus_dir).is_dir():
        return []
    entries: list[list[str | int]] = []
    for p in sorted(Path(corpus_dir).iterdir()):
        if not p.is_file() or p.is_symlink() or p.name.startswith("."):
            continue
        with contextlib.suppress(OSError):
            st = p.stat()
            entries.append([p.name, cache.file_digest(p) or sha256_file(p), st.st_size])
    return entries


# Corpus files a guardrail always replays: promoted seeds (promote_artifact.py names them
# `seed-<sha256[:16]>`) and crash-derived inputs (libFuzzer artifact prefixes, promoted crashes).
# They are the targeted inputs; libFuzzer's own units are named by their SHA-1 hex digest.
TARGETED_CORPUS_PREFIXES = ("seed-", "crash-", "leak-", "timeout-", "oom-", "slow-unit-", "minimized-from-")


def select_replay_inputs(names: list[str], limit: int | None) -> tuple[list[str], bool]:
    """
    The corpus files a guardrail replays, sorted by name, and whether that is a sample.

    Every targeted file (TARGETED_CORPUS_PREFIXES) is kept, even beyond `limit`. The rest of the
    budget goes to the other files ordered by the SHA-256 of their name: a deterministic sample,
    the same on every machine, that does not favour any name prefix. `limit` None or <= 0 keeps all.
    """
    unique = sorted(set(names))
    if limit is None or limit <= 0 or len(unique) <= limit:
        return unique, False
    targeted = [n for n in unique if n.startswith(TARGETED_CORPUS_PREFIXES)]
    others = [n for n in unique if not n.startswith(TARGETED_CORPUS_PREFIXES)]
    room = max(0, limit - len(targeted))
    others.sort(key=lambda n: hashlib.sha256(n.encode("utf-8", errors="surrogateescape")).hexdigest())
    chosen = sorted(targeted + others[:room])
    return chosen, len(chosen) < len(unique)


def corpus_selection_fields(total: int, replayed: int, sampled: bool) -> dict:
    """The report fields that say which part of the corpus a guardrail replayed."""
    return {
        "corpus_total": total,
        "corpus_replayed": replayed,
        "corpus_sampled": sampled,
        "corpus_empty": total == 0,
    }


_CRASH_KIND_ORDER = {"crash": 0, "leak": 1, "timeout": 2, "oom": 3}


def _prefix_artifacts(prefix_dir: Path) -> dict[str, tuple[int, str]]:
    """libFuzzer artifacts (crash-/leak-/timeout-/oom-...) directly under an -artifact_prefix directory."""
    out: dict[str, tuple[int, str]] = {}
    if not prefix_dir.is_dir():
        return out
    for p in prefix_dir.iterdir():
        if p.is_file() and not p.is_symlink() and _artifact_kind(p.name):
            with contextlib.suppress(OSError):
                out[p.name] = (p.stat().st_mtime_ns, sha256_file(p))
    return out


def _run_relative(path: Path) -> str:
    """`path` relative to the run directory (the cwd) in POSIX form, else its absolute POSIX form."""
    resolved = Path(path).resolve()
    try:
        return resolved.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def guardrail_crash_input(prefix_dir: Path, before: dict[str, tuple[int, str]], output: str) -> str | None:
    """
    The crashing input a guardrail replay wrote under its -artifact_prefix directory, run-relative, or None.

    Decided from the directory listing: a file is this run's when it is new or changed since `before`, or when
    libFuzzer's "Test unit written to" line names it at this prefix (a content-addressed rewrite of identical
    bytes can keep the old mtime). Several candidates: crash before leak/timeout/oom, the one libFuzzer named
    first, then by name, so the choice is deterministic.
    """
    prefix_dir = Path(prefix_dir)
    after = _prefix_artifacts(prefix_dir)
    if not after:
        return None
    resolved_prefix = prefix_dir.resolve()
    named: list[str] = []
    for m in _TEST_UNIT_WRITTEN_RE.finditer(output or ""):
        raw = m.group("path").strip()
        try:
            same_dir = Path(raw).parent.resolve() == resolved_prefix
        except (OSError, ValueError):
            same_dir = False
        name = Path(raw).name
        if same_dir and name in after and name not in named:
            named.append(name)
    fresh = {name for name, meta in after.items() if before.get(name) != meta} | set(named)
    if not fresh:
        return None

    def rank(name: str) -> tuple[int, int, str]:
        kind = _artifact_kind(name) or ""
        return (_CRASH_KIND_ORDER.get(kind, 9), named.index(name) if name in named else len(named), name)

    return _run_relative(prefix_dir / min(fresh, key=rank))


def run_guardrail_check(
    binary: Path,
    corpus_dir: Path,
    scratch_dir: Path,
    runs: int = 0,
    timeout_s: int = 600,
    *,
    per_input_timeout: int = GUARDRAIL_PER_INPUT_TIMEOUT_S,
    module: str = "",
    seed: int | None = None,
    use_cache: bool = True,
    use_verdict_cache: bool = True,
    max_corpus_inputs: int = 64,
    functions: list[str] | None = None,
) -> dict:
    """
    Replay the shared corpus (read-only) plus `runs` mutations. New units land in a scratch
    corpus and crash artifacts in scratch, so the guardrail never mutates shared state.
    The per-input `-timeout`, `-rss_limit_mb` and the mutation `-seed` (derive_seed) are fixed,
    so the same contract on the same build gets the same verdict on any machine.

    The binary must be E-ACSL-instrumented: replaying an uninstrumented build would return 0
    for any contract and produce a vacuous `passed_dynamic_oracle`.

    A pass only says that no replayed input broke a check. `reach` records how often each of
    `functions` ran: a contract on a function no input reached was not tested at all.

    When caching is enabled (`scripts/cache.py`), deterministic passing verdicts
    (`passed_dynamic_oracle`) are cached in the run-local `guardrail` namespace
    keyed by `{binary_sha256, corpus, scratch_corpus, extra_runs, per_input_timeout, seed, module}`.
    Transient failures (`rejected_overconstrained`, `code_fault`) are never cached.
    """
    binary = Path(binary)
    corpus_dir = Path(corpus_dir)
    scratch_dir = Path(scratch_dir)
    if not is_eacsl_instrumented(binary):
        err_verdict: dict[str, object] = {
            "status": "guardrail_error",
            "reason": f"{binary} is not E-ACSL-instrumented; refusing to report a vacuous dynamic-oracle pass.",
            "failure": None,
            "corpus_dir": str(corpus_dir),
            "crash_input": None,
        }
        err_verdict["diagnostic_hints"] = derive_eacsl_diagnostic_hints(err_verdict)
        return err_verdict
    scratch_dir.mkdir(parents=True, exist_ok=True)
    scratch_corpus = scratch_dir / "new_units"
    scratch_corpus.mkdir(parents=True, exist_ok=True)
    corpus_dir.mkdir(parents=True, exist_ok=True)
    seed = derive_seed(binary, module) if seed is None else seed

    corpus_entries = corpus_manifest(corpus_dir)
    chosen_names, sampled = select_replay_inputs([str(e[0]) for e in corpus_entries], max_corpus_inputs)
    chosen_set = set(chosen_names)
    replay_manifest = [e for e in corpus_entries if e[0] in chosen_set]
    selection = corpus_selection_fields(len(corpus_entries), len(replay_manifest), sampled)

    g_key: str | None = None
    g_material: dict | None = None
    in_parent_guard = "parent_guard" in binary.as_posix().split("/")
    if use_cache and use_verdict_cache and cache.enabled() and not _in_agent_scratch(binary):
        bin_sha = cache.file_digest(binary)
        if bin_sha is not None:
            g_material = {
                "kind": "guardrail",
                "binary_sha256": bin_sha,
                "corpus": replay_manifest,
                "scratch_corpus": corpus_manifest(scratch_corpus),
                "extra_runs": int(runs),
                "per_input_timeout": int(per_input_timeout),
                "seed": int(seed),
                "module": module,
                "reach_functions": sorted(functions or []),
            }
            g_key = cache.make_key("guardrail", g_material)
            entry = cache.lookup("guardrail", g_key, include_run=not in_parent_guard)
            if entry is not None:
                cached = dict(entry.data.get("verdict") or {})
                if cached.get("status") == "passed_dynamic_oracle":
                    cached.update(selection)
                    cached["corpus_dir"] = str(corpus_dir)
                    cached["crash_input"] = None
                    cached["cache"] = {"hit": True, "key": g_key}
                    cached["diagnostic_hints"] = derive_eacsl_diagnostic_hints(cached)
                    return cached

    replay_dir = corpus_dir
    if sampled:
        replay_corpus = scratch_dir / "replay_corpus"
        if replay_corpus.is_dir():
            shutil.rmtree(replay_corpus, ignore_errors=True)
        replay_corpus.mkdir(parents=True, exist_ok=True)
        for name in chosen_names:
            with contextlib.suppress(OSError):
                shutil.copy2(corpus_dir / name, replay_corpus / name)
        replay_dir = replay_corpus

    cmd = [
        str(binary.resolve()),
        f"-runs={runs}",
        f"-timeout={per_input_timeout}",
        f"-rss_limit_mb={FUZZ_RSS_LIMIT_MB}",
        f"-seed={seed}",
        f"-artifact_prefix={scratch_dir.resolve()}/",
        "-print_coverage=1",
        "-print_final_stats=1",
        str(scratch_corpus.resolve()),
        str(replay_dir.resolve()),
    ]
    artifacts_before = _prefix_artifacts(scratch_dir)
    res = run_sandboxed(cmd, writable=[scratch_dir], timeout_s=timeout_s, limits=Limits(cpu_seconds=timeout_s * 2))
    reach, combined_out = parse_guardrail_reach(res.stdout + "\n" + res.stderr, functions)
    verdict = classify_guardrail(res.returncode, res.timed_out, combined_out)
    crash_input = (
        None
        if verdict["status"] == "passed_dynamic_oracle"
        else guardrail_crash_input(scratch_dir, artifacts_before, combined_out)
    )
    verdict.update(
        {
            "crash_input": crash_input,
            "reach": reach,
            "returncode": res.returncode,
            "timed_out": res.timed_out,
            "sandbox": res.sandbox,
            "corpus_dir": str(corpus_dir),
            "seed": seed,
            "per_input_timeout": per_input_timeout,
            **selection,
        }
    )
    if verdict["status"] != "passed_dynamic_oracle":
        verdict["runtime_trace"] = combined_out[-4000:]
    verdict["diagnostic_hints"] = derive_eacsl_diagnostic_hints(verdict)
    if g_key is not None and g_material is not None:
        if verdict["status"] == "passed_dynamic_oracle":
            with contextlib.suppress(OSError, ValueError):
                if in_parent_guard:
                    s_store = cache.shared_store()
                    if s_store is not None and s_store.writable:
                        s_store.put("guardrail", g_key, {}, {"verdict": dict(verdict)}, key_material=g_material)
                else:
                    cache.publish("guardrail", g_key, {}, {"verdict": dict(verdict)}, key_material=g_material)
        verdict["cache"] = {"hit": False, "key": g_key}
    else:
        verdict["cache"] = {"hit": False, "key": None}
    return verdict


CANARY_INPUT = b"FC33" + b"P" * 12
# Reaches neither the open() branch nor the overflow; must run clean (no false alarm, no runtime crash).
CANARY_BENIGN_INPUT = b"BENIGN" + b"P" * 10
# Reaches canary_pick with data[4] != 'S': an uninitialized read that -rte-initialized must report.
CANARY_UNINIT_INPUT = b"UNINX" + b"P" * 11
# The function holding the canary's uninitialized read. An initialization alarm elsewhere (such as
# E-ACSL's unmarked formals, which every input reaches first) must not satisfy the check.
CANARY_UNINIT_FUNCTION = "canary_pick"
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
    crashes on every input would otherwise pass. The canary is always rebuilt: a selftest checks
    the toolchain itself, so it never reads the build cache.
    """
    replay = replay or replay_artifact
    src = resolve_canary_source()
    expected_line = next(
        (
            i
            for i, line in enumerate(src.read_text(encoding="utf-8").splitlines(), start=1)
            if "/* CANARY_OOB */" in line
        ),
        0,
    )
    work_dir.mkdir(parents=True, exist_ok=True)
    comp = compile_eacsl_binary(
        [str(src)],
        work_dir / "canary",
        machdep,
        cppflags=f"-I{src.parent.as_posix()}",
        variadic_translation=variadic_translation,
        runner=runner,
        use_cache=False,
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
        benign_failure = (
            None if checks["benign_input_clean"] else (benign_rep.get("failure") or benign_rep.get("log_tail"))
        )
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
        checks["detects_uninitialized"] = (
            bool(uninit_rep.get("reproduced"))
            and uninit_failure.get("alarm_kind") == "initialization"
            and uninit_failure.get("function", CANARY_UNINIT_FUNCTION) == CANARY_UNINIT_FUNCTION
        )
    required = (
        "compiled",
        "no_gmp_only",
        "instrumented_binary",
        "benign_input_clean",
        "detects_overflow",
        "detects_uninitialized",
    )
    ok = all(checks[k] for k in required)
    return {
        "mode": "selftest",
        "ok": ok,
        "checks": checks,
        "warnings": []
        if checks["attributes_line"] or not ok
        else [
            "E-ACSL detected the canary overflow but did not attribute the CANARY_OOB line; crashes will rely on sanitizer_replay attribution."
        ],
        "frama_c_version": framac_version(runner),
        "eacsl_gcc": _resolve_eacsl_gcc()[0],
        "variadic_translation": variadic_translation,
        "variadic_fallbacks": comp.get("variadic_fallbacks", []),
        "expected_line": expected_line,
        "failure": failure,
        "benign_failure": benign_failure,
        "uninitialized_failure": uninit_failure or None,
        "compile": {
            k: comp.get(k)
            for k in (
                "returncode",
                "reason",
                "compile_log",
                "binary",
                "frontend_flags",
                "backend_flags",
                "init_hook",
                "reduced_checks",
            )
        },
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


_UNDEFINED_REF_RE = re.compile(r"undefined reference to [`'](?P<sym>[A-Za-z_]\w*)'")


def parse_undefined_references(log: str) -> list[str]:
    """Symbols named in linker `undefined reference to 'X'` diagnostics, in order."""
    found: list[str] = []
    for m in _UNDEFINED_REF_RE.finditer(log or ""):
        sym = m.group("sym")
        if sym not in found:
            found.append(sym)
    return found


def _dag_symbol_files(dag_path: Path) -> dict[str, str]:
    """
    Map function name -> defining source file from callgraph_dag.json: its functions, then the
    functions only the build compiles (`build_only_functions`: code Frama-C's preprocessing hides,
    which the sanitizer build links).
    """
    try:
        dag = json.loads(Path(dag_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    dag = dag if isinstance(dag, dict) else {}
    out: dict[str, str] = {}
    for key, rec in (dag.get("functions") or {}).items():
        if isinstance(rec, dict):
            name = rec.get("name") or str(key).split("#")[-1]
            file = rec.get("file")
            if name and file:
                out.setdefault(str(name), str(file))
    build_only = dag.get("build_only_functions")
    for file, names in (build_only if isinstance(build_only, dict) else {}).items():
        for name in names if isinstance(names, list) else []:
            if isinstance(name, str) and name:
                out.setdefault(name, str(file))
    return out


def _normalize_dag_source(file: str, run_dir: Path) -> str:
    """DAG `file` key as a run-relative overlay path (workspace/work/...), suffix-resolved."""
    src = file.replace("\\", "/").strip()
    if src.startswith("/framac-run/"):
        src = src[len("/framac-run/") :]
    elif src.startswith("/target/"):
        src = f"workspace/work/{src[len('/target/') :]}"
    if src.startswith(("/", "workspace/")):
        return src
    work = run_dir / "workspace/work"
    if (work / src).is_file():
        return f"workspace/work/{src}"
    if work.is_dir():
        matches = sorted(work.glob(f"**/{src}"), key=lambda p: (len(p.parts), p.as_posix()))
        if matches:
            return f"workspace/work/{matches[0].relative_to(work).as_posix()}"
    return f"workspace/work/{src}"


def repair_sources_for_link(
    sources: list[str], log: str, dag_path: Path | str | None, run_dir: Path | str
) -> tuple[list[str], dict]:
    """
    One link-repair round: map `undefined reference to 'X'` symbols to their
    defining sources via the DAG and append the missing files. Returns (sources, info).
    """
    syms = parse_undefined_references(log)
    if not syms or not dag_path:
        return list(sources), {}
    sym_files = _dag_symbol_files(Path(dag_path))
    have = {s.replace("\\", "/") for s in sources}
    added: list[str] = []
    resolved: list[str] = []
    for sym in syms:
        f = sym_files.get(sym)
        if not f:
            continue
        norm = _normalize_dag_source(f, Path(run_dir))
        if norm not in have:
            have.add(norm)
            added.append(norm)
            resolved.append(sym)
    if not added:
        return list(sources), {}
    return [*sources, *added], {"symbols": resolved, "added_sources": added}


def build_module_binary(
    sources: list[str],
    out_bin: Path,
    *,
    engine: str = "auto",
    selftest_json: Path | None = DEFAULT_SELFTEST_JSON,
    machdep: str = "gcc_x86_64",
    cppflags: str = "-I.",
    ldflags: str = "",
    rte: str = "all",
    functions: list[str] | None = None,
    variadic_translation: bool = True,
    warn_unsigned_downcast: bool = False,
    rte_initialized: bool = True,
    use_cache: bool = True,
    dag_path: Path | str | None = None,
) -> dict:
    """
    Compile a module's fuzz binary the way a campaign does, without running it: E-ACSL for
    `eacsl`, and for `auto` unless a failed selftest for this Frama-C version blocks it; Clang
    ASan+UBSan for `sanitizers` and as the `auto` fallback. Both builds go through the cache.
    On a link failure with undefined references, repair rounds append the defining sources (via
    `dag_path`) and relink while a round adds a file: linking takes whole files, so a file added
    for one symbol can need still more files. The rounds are bounded by the number of files the
    DAG names and recorded under `link_repair` (`symbols` and `added_sources` over all rounds,
    `rounds` one entry each).
    Returns {compile, engine_used, engine_fallback_reason, eacsl_compile_attempt, sources}, where
    `sources` is what was compiled last (the input plus any repair).
    """

    def _attempt(srcs: list[str]) -> tuple[dict, dict | None, str | None]:
        eacsl_attempt = None
        fallback_reason = None
        comp = None
        if engine in ("auto", "eacsl"):
            blocked = selftest_blocks_eacsl(selftest_json) if engine == "auto" else None
            if blocked:
                fallback_reason = blocked
            else:
                comp = compile_eacsl_binary(
                    srcs,
                    out_bin,
                    machdep,
                    cppflags,
                    rte,
                    True,
                    functions=functions,
                    ldflags_extra=ldflags,
                    variadic_translation=variadic_translation,
                    warn_unsigned_downcast=warn_unsigned_downcast,
                    rte_initialized=rte_initialized,
                    use_cache=use_cache,
                )
                if comp["returncode"] != 0 and engine == "auto":
                    eacsl_attempt = comp
                    fallback_reason = comp.get("reason") or "eacsl_compile_failed"
                    comp = None
        if comp is None:
            comp = compile_sanitizer_binary(srcs, out_bin, cppflags, True, ldflags_extra=ldflags, use_cache=use_cache)
        return comp, eacsl_attempt, fallback_reason

    current = list(sources)
    comp, eacsl_attempt, fallback_reason = _attempt(current)
    rounds: list[dict] = []
    if comp["returncode"] != 0 and dag_path:
        # Each round adds at least one file the DAG names, so this many rounds always suffice.
        max_rounds = max(1, len(set(_dag_symbol_files(Path(dag_path)).values())))
        while comp["returncode"] != 0 and len(rounds) < max_rounds:
            log = "\n".join(str(comp.get(k) or "") for k in ("stdout", "stderr"))
            current, info = repair_sources_for_link(current, log, dag_path, Path.cwd())
            if not info:
                break
            rounds.append(info)
            comp, eacsl_attempt, fallback_reason = _attempt(current)
    result = {
        "compile": comp,
        "engine_used": comp.get("engine", engine),
        "engine_fallback_reason": fallback_reason,
        "eacsl_compile_attempt": eacsl_attempt,
        "sources": current,
    }
    if rounds:
        result["link_repair"] = {
            "symbols": [sym for r in rounds for sym in r["symbols"]],
            "added_sources": [src for r in rounds for src in r["added_sources"]],
            "rounds": rounds,
        }
    return result


def _sanitizer_attribution_builder(
    sources: list[str], out_bin: Path, cppflags: str, ldflags: str, *, use_cache: bool = True
):
    """Lazily build (at most once) the ASan+UBSan twin used to attribute unlocated E-ACSL crashes."""
    state: dict = {}

    def builder() -> Path | None:
        if "binary" not in state:
            san_out = out_bin.with_name(out_bin.name + ".sanreplay")
            san = compile_sanitizer_binary(sources, san_out, cppflags, True, ldflags_extra=ldflags, use_cache=use_cache)
            state["binary"] = Path(san["binary"]) if san["returncode"] == 0 else None
        return state["binary"]

    return builder


def resolve_workers(value: int | str | None) -> int:
    """`auto` (or None/0): LibFuzzer workers sized from this job's budget at the fixed -rss_limit_mb."""
    if value is None or str(value).strip().lower() == "auto":
        return fuzz_workers()
    count = int(value)
    return count if count > 0 else fuzz_workers()


def campaign_wall_time(max_time: int | None, fuzz_budget: int | None, workers: int) -> int:
    """`--max-time` when given; else max(30, CPU-second budget / workers); else 60 seconds."""
    if max_time is not None:
        return max_time
    if fuzz_budget:
        return max(MIN_FUZZ_WALL_S, math.ceil(fuzz_budget / max(1, workers)))
    return DEFAULT_MAX_TIME_S


def _collect_inputs(inputs: list[Path]) -> tuple[list[Path], list[str]]:
    """Files given directly or found (non-recursively) in given directories; missing paths separately."""
    files: list[Path] = []
    missing: list[str] = []
    seen: set[str] = set()
    for raw in inputs:
        path = Path(raw)
        if path.is_dir():
            found = sorted(c for c in path.iterdir() if c.is_file() and not c.name.startswith("."))
        elif path.is_file():
            found = [path]
        else:
            missing.append(str(raw))
            continue
        for f in found:
            key = os.path.abspath(f)
            if key not in seen:
                seen.add(key)
                files.append(f)
    return files, missing


def replay_inputs(
    binary: Path,
    inputs: list[Path],
    scratch: Path,
    *,
    module: str = "",
    per_input_timeout: int = DEFAULT_PER_INPUT_TIMEOUT_S,
    attribution_builder=None,
) -> list[dict]:
    """Replay every input exactly once; one campaign-shaped artifact record per input."""
    scratch.mkdir(parents=True, exist_ok=True)
    artifacts: list[dict] = []
    for path in inputs:
        rep = replay_artifact(binary, path, scratch, module=module, per_input_timeout=per_input_timeout)
        failure = rep.get("failure")
        entry: dict = {
            "artifact": path.as_posix(),
            "kind": _artifact_kind(path.name) or "crash",
            "sha256": sha256_file(path),
            "size_bytes": path.stat().st_size,
            "reproducible": bool(rep.get("reproduced")),
            "failure": None,
            "fingerprint": None,
            "failure_source": "primary" if failure else None,
            "returncode": rep.get("returncode"),
            "timed_out": rep.get("timed_out"),
            "seed": rep.get("seed"),
            "replay_log_tail": rep.get("log_tail", ""),
        }
        if entry["reproducible"] and needs_attribution(failure) and attribution_builder is not None:
            san_bin = attribution_builder()
            if san_bin is not None:
                san = replay_artifact(Path(san_bin), path, scratch, module=module, per_input_timeout=per_input_timeout)
                entry["attribution"] = {
                    "source": "sanitizer_replay",
                    "binary": str(san_bin),
                    "reproduced": san.get("reproduced"),
                    "failure": san.get("failure"),
                }
                if san.get("failure") and not needs_attribution(san["failure"]):
                    failure = san["failure"]
                    entry["failure_source"] = "sanitizer_replay"
        entry["failure"] = failure
        if failure:
            entry["fingerprint"] = make_fingerprint(
                failure.get("file") or "unknown",
                failure.get("function") or "unknown_function",
                failure.get("alarm_kind") or failure.get("kind") or "crash",
                failure.get("predicate") or "",
            )
        artifacts.append(entry)
    return artifacts


def _slim_compile(comp: dict) -> dict:
    return {k: comp.get(k) for k in ("engine", "returncode", "reason", "binary", "compile_log", "cache")}


def prepare_replay_binary(
    module: str,
    sources: list[str],
    out_bin: Path,
    *,
    attribution: bool = True,
    **build_options,
) -> dict:
    """Build the module binary for replays (normally a cache hit on the Make or campaign build)."""
    build = build_module_binary(sources, Path(out_bin), **build_options)
    comp = build["compile"]
    prepared: dict = {
        "module": module,
        "binary": None,
        "engine_used": build["engine_used"],
        "compile": _slim_compile(comp),
        "cache": comp.get("cache"),
        "attribution_builder": None,
    }
    if build["engine_fallback_reason"]:
        prepared["engine_fallback_reason"] = build["engine_fallback_reason"]
    if comp["returncode"] != 0:
        prepared["reason"] = f"compile_error ({comp.get('reason') or 'returncode ' + str(comp['returncode'])})"
        return prepared
    prepared["binary"] = Path(comp["binary"])
    if attribution and build["engine_used"] == "eacsl":
        prepared["attribution_builder"] = _sanitizer_attribution_builder(
            build.get("sources") or sources,
            Path(out_bin),
            build_options.get("cppflags", "-I."),
            build_options.get("ldflags", ""),
            use_cache=build_options.get("use_cache", True),
        )
    return prepared


def replay_report(
    module: str,
    inputs: list[Path],
    scratch: Path,
    *,
    prepared: dict | None = None,
    binary: Path | None = None,
    per_input_timeout: int = DEFAULT_PER_INPUT_TIMEOUT_S,
) -> dict:
    """
    Replay `inputs` on a prepared (built) or given binary. `status` is `reproduced` when any input
    fails, `not_reproduced` when none does, `error` when nothing could be replayed. The
    `artifacts[]` records are the campaign's, so `ingest-verifier --replay-report` accepts the report.
    """
    files, missing = _collect_inputs(inputs)
    report: dict = {
        "mode": "replay",
        "module": module,
        "status": "error",
        "binary": None,
        "inputs": [str(i) for i in inputs],
        "missing_inputs": missing,
        "per_input_timeout": per_input_timeout,
        "rss_limit_mb": FUZZ_RSS_LIMIT_MB,
        "artifacts": [],
    }
    attribution_builder = None
    if prepared is not None:
        for key in ("engine_used", "engine_fallback_reason", "compile", "cache"):
            if key in prepared:
                report[key] = prepared[key]
        if prepared.get("binary") is None:
            report["reason"] = prepared.get("reason") or "no binary"
            return report
        bin_path = Path(prepared["binary"])
        attribution_builder = prepared.get("attribution_builder")
    elif binary is not None:
        bin_path = Path(binary)
        if not bin_path.is_file():
            report["reason"] = f"binary not found: {bin_path}"
            return report
        report["engine_used"] = "eacsl" if is_eacsl_instrumented(bin_path) else "unknown"
    else:
        report["reason"] = "replay needs --binary, or --sources with --out-bin"
        return report
    report["binary"] = str(bin_path)
    report["seed"] = derive_seed(bin_path, module)
    if not files:
        report["reason"] = "no_inputs"
        return report
    try:
        report["artifacts"] = replay_inputs(
            bin_path,
            files,
            scratch,
            module=module,
            per_input_timeout=per_input_timeout,
            attribution_builder=attribution_builder,
        )
    except SandboxUnavailable as exc:
        report["reason"] = f"sandbox_unavailable: {exc}"
        return report
    report["status"] = "reproduced" if any(a["reproducible"] for a in report["artifacts"]) else "not_reproduced"
    return report


def acsl_include_dir() -> Path | None:
    for base in (Path("/opt/framac-pipeline/templates"), Path(__file__).resolve().parent.parent / "templates"):
        if (base / "acsl").is_dir():
            return base / "acsl"
    return None


def _unit_harness_module(module: str, harness_dir: Path, file: str | None = None, function: str | None = None) -> str:
    """
    The harness module standing for a link unit's name (an Eva candidate may carry its unit, step
    I5b): the module itself when it has a sidecar, else the sub-module whose scope holds
    `file`#`function` (workspace_overlay.harness_module_for_function, as pipeline_make and the
    ledger pick it), else the unit's first sub-module. The DAG is read next to the harness
    directory (workspace/reports/callgraph_dag.json).
    """
    harness_dir = Path(harness_dir)
    if (harness_dir / f"harness_{module}.json").is_file():
        return module
    from module_map import ModuleMap, load_sidecars

    dag = load_json_optional(harness_dir.parent / "reports" / "callgraph_dag.json", None)
    mm = ModuleMap(dag if isinstance(dag, dict) else None, load_sidecars(harness_dir))
    try:
        from workspace_overlay import harness_module_for_function
    except ImportError:
        return mm.harness_module_for(module) or module
    return harness_module_for_function(mm, module, file, function) or module


def _sidecar_build_spec(module: str, harness_dir: Path, file: str | None = None, function: str | None = None) -> dict:
    """
    Fallback build spec when scripts/pipeline_make.py cannot be imported: the harness sidecar's
    sources (the harness alone when it `include_source`s the target) plus the harness, and its
    cppflags plus -I<templates>/acsl (once), as in the documented campaign command. A link unit's
    name resolves to the harness module whose scope holds the candidate's `file`#`function` (else
    its first one), returned in `harness_module`.
    """
    requested, module = module, _unit_harness_module(module, harness_dir, file, function)
    sidecar = Path(harness_dir) / f"harness_{module}.json"
    meta = load_json_optional(sidecar, None)
    if not isinstance(meta, dict):
        raise FileNotFoundError(f"harness sidecar {sidecar} not found")
    harness = (Path(harness_dir) / f"harness_{module}.c").as_posix()
    sources: list[str] = []
    if not meta.get("include_source"):
        for raw in meta.get("sources") or []:
            src = str(raw).replace("\\", "/").strip()
            src = src[len("/framac-run/") :] if src.startswith("/framac-run/") else src
            if src and Path(src).name != f"harness_{module}.c" and src not in sources:
                sources.append(src)
    tokens = shlex.split(meta.get("cppflags") or "-I.")
    acsl_dir = acsl_include_dir()
    if (
        acsl_dir is not None
        and acsl_dir.as_posix() not in (meta.get("cppflags") or "")
        and f"-I{acsl_dir.as_posix()}" not in tokens
    ):
        tokens.append(f"-I{acsl_dir.as_posix()}")
    spec = {"sources": [*sources, harness], "cppflags": shlex.join(tokens), "ldflags": meta.get("ldflags") or ""}
    if module != requested:
        spec["harness_module"] = module
    return spec


def replay_build_spec(
    module: str,
    harness_dir: Path = Path("workspace/harnesses"),
    file: str | None = None,
    function: str | None = None,
) -> dict:
    """
    Sources, cppflags and ldflags of a module's fuzz binary. Inside the pipeline this is
    `pipeline_make.module_build_spec`: exactly what `make build` and the fuzz recipe pass, so a
    replay reuses their cache entry and never rebuilds workspace/harnesses/fuzz_<mod> with other
    flags or sources (ValueError when Make cannot build the module). The harness sidecar decides
    only when pipeline_make cannot be imported. A candidate's module may be a link unit: the spec
    is then its harness module's, the one whose scope holds the crashing `file`#`function` (as the
    ledger picks it), named in `harness_module` (the binary is fuzz_<harness_module>).
    """
    try:
        import pipeline_make  # imported lazily: replays work without the Make layer
    except ImportError:
        return _sidecar_build_spec(module, harness_dir, file, function)
    return pipeline_make.module_build_spec(module, Path("."), file, function)


def _candidate_slug(fingerprint: str) -> str:
    base = re.sub(r"[^A-Za-z0-9_.-]+", "_", fingerprint).strip("._")[:80] or "candidate"
    return f"{base}-{hashlib.sha256(fingerprint.encode()).hexdigest()[:10]}"


def _candidate_engine(cand: dict) -> str:
    """
    The engine that found the candidate: its report's engine_used, or for a campaign that used
    both engines, the `engine` of the report's artifact with the candidate's fingerprint; else auto.
    """
    fingerprint = cand.get("fingerprint")
    for rel in cand.get("tool_outputs") or []:
        try:
            data = json.loads(Path(rel).read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            continue
        engine = data.get("engine_used") if isinstance(data, dict) else None
        if engine in ("eacsl", "sanitizers"):
            return engine
        if engine == DUAL_ENGINE:
            for art in data.get("artifacts") or []:
                if isinstance(art, dict) and art.get("fingerprint") == fingerprint:
                    if art.get("engine") in ("eacsl", "sanitizers"):
                        return art["engine"]
    return "auto"


def _reproducer_paths(cand: dict) -> list[Path]:
    paths: list[Path] = []
    for rep in cand.get("reproducers") or []:
        raw = rep.get("input") if isinstance(rep, dict) else rep
        if isinstance(raw, str) and raw:
            paths.append(Path(raw))
    return paths


def replay_candidates(
    candidates_path: Path,
    harness_dir: Path,
    out_dir: Path,
    *,
    bin_dir: Path | None = None,
    engine: str | None = None,
    selftest_json: Path | None = DEFAULT_SELFTEST_JSON,
    machdep: str = "gcc_x86_64",
    per_input_timeout: int = DEFAULT_PER_INPUT_TIMEOUT_S,
    attribution: bool = True,
) -> dict:
    """
    Replay the reproducers of every unverified candidate on its module's binary, built with
    `replay_build_spec` (Make's sources and flags) into `<bin_dir>/fuzz_<mod>`, the path of
    `make build` and of the campaign, so the build is a cache hit. Candidates whose module Make
    cannot build get an `error` report. Writes `<out_dir>/<fingerprint-slug>.json` per candidate
    and `index.json`, which maps each fingerprint to its report.
    """
    candidates = load_json_optional(Path(candidates_path), [])
    todo = [c for c in candidates if isinstance(c, dict) and c.get("status") == "unverified" and _reproducer_paths(c)]
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    bin_dir = Path(bin_dir) if bin_dir is not None else Path("workspace/harnesses")
    specs: dict[tuple[str, str, str], dict | str] = {}
    prepared_by_key: dict[tuple[str, str], dict] = {}
    index: dict[str, dict] = {}
    by_status: dict[str, int] = {}
    for cand in todo:
        fingerprint = str(cand.get("fingerprint") or "")
        module = str(cand.get("module") or "")
        loc = cand.get("location")
        loc = loc if isinstance(loc, dict) else {}
        file, function = str(loc.get("file") or ""), str(loc.get("function") or "")
        eng = engine or _candidate_engine(cand)
        # A candidate naming a link unit replays on the harness whose scope holds its function.
        skey = (module, file, function)
        if skey not in specs:
            try:
                specs[skey] = replay_build_spec(module, Path(harness_dir), file or None, function or None)
            except (OSError, ValueError, RuntimeError) as exc:
                specs[skey] = f"no build spec for module {module!r}: {exc}"
        spec = specs[skey]
        if isinstance(spec, str):
            key = (f"!{module}", eng)
            prepared_by_key.setdefault(key, {"binary": None, "reason": spec})
        else:
            harness_module = str(spec.get("harness_module") or module)
            key = (harness_module, eng)
            if key not in prepared_by_key:
                prepared_by_key[key] = prepare_replay_binary(
                    harness_module,
                    spec["sources"],
                    bin_dir / f"fuzz_{harness_module}",
                    attribution=attribution,
                    engine=eng,
                    selftest_json=selftest_json,
                    machdep=machdep,
                    cppflags=spec["cppflags"],
                    ldflags=spec["ldflags"],
                    rte_initialized=bool(spec.get("rte_initialized", True)),
                )
        scratch = out_dir / ".scratch" / (re.sub(r"[^A-Za-z0-9_.-]+", "_", module) or "unknown")
        report = replay_report(
            module,
            _reproducer_paths(cand),
            scratch,
            prepared=prepared_by_key[key],
            per_input_timeout=per_input_timeout,
        )
        report["candidate_fingerprint"] = fingerprint
        report["fingerprint_matches"] = any(a.get("fingerprint") == fingerprint for a in report["artifacts"])
        report_path = out_dir / f"{_candidate_slug(fingerprint)}.json"
        atomic_write_json(report_path, report)
        index[fingerprint] = {"report": report_path.as_posix(), "module": module, "status": report["status"]}
        by_status[report["status"]] = by_status.get(report["status"], 0) + 1
    index_path = out_dir / "index.json"
    atomic_write_json(
        index_path,
        {
            "generated_at": utc_now(),
            "candidates_file": Path(candidates_path).as_posix(),
            "by_fingerprint": index,
        },
    )
    return {
        "mode": "replay-candidates",
        "status": "error" if by_status.get("error") else "ok",
        "candidates": len(todo),
        "by_status": by_status,
        "index": index_path.as_posix(),
    }


# ---------------------------------------------------------------------------
# Crash-input minimization with cvise/creduce (upstream share/analysis-scripts/creduce.sh
# pattern, adapted: the interest test replays each variant on the E-ACSL binary and accepts it
# only if it still crashes with the same failure fingerprint).
# ---------------------------------------------------------------------------


def find_creduce() -> str | None:
    """The cvise (Python port of creduce) or creduce binary: $CREDUCE first, then PATH."""
    env = os.environ.get("CREDUCE")
    if env and Path(env).is_file():
        return env
    for name in ("cvise", "creduce"):
        found = shutil.which(name)
        if found:
            return found
    return None


def _failure_fingerprint(failure: dict | None) -> str | None:
    if not failure:
        return None
    return make_fingerprint(
        failure.get("file") or "unknown",
        failure.get("function") or "unknown_function",
        failure.get("alarm_kind") or failure.get("kind") or "crash",
        failure.get("predicate") or "",
    )


def minimize_interest(
    binary: Path,
    variant: Path,
    scratch: Path,
    fingerprint: str | None,
    *,
    module: str = "",
    per_input_timeout: int = DEFAULT_PER_INPUT_TIMEOUT_S,
) -> bool:
    """cvise interest test: the variant still crashes the binary with the same fingerprint."""
    rep = replay_artifact(binary, variant, scratch, module=module, per_input_timeout=per_input_timeout)
    if not rep.get("reproduced"):
        return False
    fp = _failure_fingerprint(rep.get("failure"))
    return fp is not None and (fingerprint is None or fp == fingerprint)


def minimize_input(
    binary: Path,
    input_path: Path,
    scratch: Path,
    *,
    module: str = "",
    fingerprint: str | None = None,
    max_time_s: int = 600,
    jobs: int = 4,
    per_input_timeout: int = DEFAULT_PER_INPUT_TIMEOUT_S,
    tool: str | None = None,
) -> dict:
    """
    Minimize one crash input with cvise/creduce, run under the sandbox with a wall-clock cap. The
    variant file is updated in place as better variants are found, so a timeout still leaves the
    best-so-far. The result is verified by one final replay before it is reported.
    """
    binary = Path(binary)
    input_path = Path(input_path)
    scratch = Path(scratch)
    tool = tool or find_creduce()
    report: dict = {
        "mode": "minimize",
        "input": input_path.as_posix(),
        "binary": binary.as_posix(),
        "tool": tool,
        "fingerprint": fingerprint,
        "status": "error",
        "reason": None,
        "minimized": None,
        "original_size_bytes": None,
        "minimized_size_bytes": None,
        "reduction_pct": None,
        "reproduced": False,
        "passes": None,
        "timed_out": False,
        "log_tail": "",
    }
    if tool is None:
        report["reason"] = "cvise/creduce not found (set CREDUCE or install the cvise package)"
        return report
    if not binary.is_file():
        report["reason"] = f"binary not found: {binary}"
        return report
    if not input_path.is_file():
        report["reason"] = f"input not found: {input_path}"
        return report
    report["original_size_bytes"] = input_path.stat().st_size
    work = scratch / "creduce"
    work.mkdir(parents=True, exist_ok=True)
    variant = work / input_path.name
    shutil.copyfile(input_path, variant)
    script_path = Path(__file__).resolve()
    interest = work / "interest.sh"
    interest.write_text(
        "#!/bin/sh\n"
        f"exec python3 {shlex.quote(str(script_path))} minimize-interest"
        f" --binary {shlex.quote(str(binary.resolve()))}"
        f" --fingerprint {shlex.quote(fingerprint or '')}"
        f" --module {shlex.quote(module)}"
        f" --per-input-timeout {int(per_input_timeout)}"
        f" --scratch-dir {shlex.quote(str(scratch.resolve()))}"
        ' "$1"\n',
        encoding="utf-8",
    )
    interest.chmod(0o755)
    # --not-c: inputs are raw fuzzer bytes, not C sources, so skip the parsability check.
    cmd = [tool, "--not-c", "-n", str(max(1, int(jobs))), str(interest), str(variant)]
    try:
        res = run_sandboxed(
            cmd,
            writable=[work, scratch],
            timeout_s=max(30, int(max_time_s)),
            limits=Limits(cpu_seconds=max(60, int(max_time_s)) * max(1, int(jobs))),
        )
    except SandboxUnavailable as exc:
        report["reason"] = f"sandbox_unavailable: {exc}"
        return report
    out = res.stdout + "\n" + res.stderr
    report["timed_out"] = res.timed_out
    report["log_tail"] = out[-3000:]
    m = re.search(r"===\s*(\d+)\s+interesting", out)
    if m:
        report["passes"] = int(m.group(1))
    if not variant.is_file() or variant.stat().st_size == 0:
        report["reason"] = "cvise produced no variant"
        return report
    # Verify the best-so-far still reproduces with the same fingerprint before reporting it.
    check = replay_artifact(binary, variant, scratch, module=module, per_input_timeout=per_input_timeout)
    report["reproduced"] = bool(check.get("reproduced")) and (
        fingerprint is None or _failure_fingerprint(check.get("failure")) == fingerprint
    )
    minimized = Path(str(input_path) + ".min")
    shutil.copyfile(variant, minimized)
    report["minimized"] = minimized.as_posix()
    report["minimized_size_bytes"] = minimized.stat().st_size
    orig = report["original_size_bytes"] or 0
    if orig > 0:
        report["reduction_pct"] = round(100.0 * (orig - report["minimized_size_bytes"]) / orig, 2)
    report["status"] = "ok" if report["reproduced"] else "not_reproduced"
    return report


def minimize_candidates(
    candidates_path: Path,
    harness_dir: Path,
    out_dir: Path,
    *,
    bin_dir: Path | None = None,
    engine: str | None = None,
    selftest_json: Path | None = DEFAULT_SELFTEST_JSON,
    machdep: str = "gcc_x86_64",
    per_input_timeout: int = DEFAULT_PER_INPUT_TIMEOUT_S,
    max_time_s: int = 600,
    jobs: int = 4,
) -> dict:
    """
    Minimize the reproducer of every unverified candidate (same selection as replay-candidates),
    on the module's replay binary. Each minimized input is written next to its artifact as
    `<artifact>.min`; `index.json` maps each fingerprint to its report.
    """
    candidates = load_json_optional(Path(candidates_path), [])
    todo = [c for c in candidates if isinstance(c, dict) and c.get("status") == "unverified" and _reproducer_paths(c)]
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    bin_dir = Path(bin_dir) if bin_dir is not None else Path("workspace/harnesses")
    prepared_by_key: dict[tuple[str, str], dict] = {}
    specs: dict[tuple[str, str, str], dict | str] = {}
    index: dict[str, dict] = {}
    by_status: dict[str, int] = {}
    tool = find_creduce()
    for cand in todo:
        fingerprint = str(cand.get("fingerprint") or "")
        module = str(cand.get("module") or "")
        eng = engine or _candidate_engine(cand)
        location = cand.get("location")
        location = location if isinstance(location, dict) else {}
        where = (module, str(location.get("file") or ""), str(location.get("function") or ""))
        if where not in specs:
            try:
                specs[where] = replay_build_spec(
                    module, Path(harness_dir), file=where[1] or None, function=where[2] or None
                )
            except (OSError, ValueError, RuntimeError) as exc:
                specs[where] = f"no build spec for module {module!r}: {exc}"
        spec = specs[where]
        # Minimized on the harness holding the crashing function (the unit's own one otherwise).
        key = (str(spec.get("harness_module") or module), eng) if isinstance(spec, dict) else ("!" + module, eng)
        if key not in prepared_by_key:
            if isinstance(spec, str):
                prepared_by_key[key] = {"binary": None, "reason": spec}
            else:
                harness_module = key[0]
                prepared_by_key[key] = prepare_replay_binary(
                    harness_module,
                    spec["sources"],
                    bin_dir / f"fuzz_{harness_module}",
                    engine=eng,
                    selftest_json=selftest_json,
                    machdep=machdep,
                    cppflags=spec["cppflags"],
                    ldflags=spec["ldflags"],
                    rte_initialized=bool(spec.get("rte_initialized", True)),
                )
        prepared = prepared_by_key[key]
        binary = prepared.get("binary") if isinstance(prepared, dict) else None
        scratch = out_dir / ".scratch" / (re.sub(r"[^A-Za-z0-9_.-]+", "_", module) or "unknown")
        if binary is None:
            report = {
                "mode": "minimize",
                "status": "error",
                "reason": (prepared.get("reason") if isinstance(prepared, dict) else None) or "no binary",
                "tool": tool,
            }
        else:
            reproducers = _reproducer_paths(cand)
            reports = [
                minimize_input(
                    Path(binary),
                    rep,
                    scratch,
                    module=module,
                    fingerprint=fingerprint or None,
                    max_time_s=max_time_s,
                    jobs=jobs,
                    per_input_timeout=per_input_timeout,
                    tool=tool,
                )
                for rep in reproducers
            ]
            report = {
                "mode": "minimize",
                "status": "ok" if any(r["status"] == "ok" for r in reports) else "error",
                "tool": tool,
                "fingerprint": fingerprint,
                "runs": reports,
            }
        report["candidate_fingerprint"] = fingerprint
        report_path = out_dir / f"{_candidate_slug(fingerprint)}.json"
        atomic_write_json(report_path, report)
        status = str(report["status"])
        index[fingerprint] = {"report": report_path.as_posix(), "module": module, "status": status}
        by_status[status] = by_status.get(status, 0) + 1
    index_path = out_dir / "index.json"
    atomic_write_json(
        index_path,
        {
            "generated_at": utc_now(),
            "candidates_file": Path(candidates_path).as_posix(),
            "tool": tool,
            "by_fingerprint": index,
        },
    )
    return {
        "mode": "minimize-candidates",
        "status": "error" if by_status.get("error") else "ok",
        "tool": tool,
        "candidates": len(todo),
        "by_status": by_status,
        "index": index_path.as_posix(),
    }


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
        res = run_sandboxed(
            [
                str(Path(binary).resolve()),
                f"-timeout={per_input_timeout}",
                f"-rss_limit_mb={FUZZ_RSS_LIMIT_MB}",
                f"-seed={seed}",
                *[str(Path(f).resolve()) for f in batch],
            ],
            writable=[scratch, batch_dir],
            timeout_s=wall,
            limits=Limits(cpu_seconds=wall * 2),
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
    res = run_sandboxed(
        ["llvm-profdata", "merge", "-sparse", "-o", str(merged), *_written_profiles(profile_dir)],
        writable=[scratch],
        timeout_s=COVERAGE_TOOL_TIMEOUT_S,
        limits=limits,
    )
    if res.returncode != 0 or res.timed_out:
        return None, f"llvm-profdata merge failed ({res.returncode}): {res.stderr[-1000:]}"
    # llvm-cov export only writes to stdout, which the sandbox truncates, so redirect it to a file.
    res = run_sandboxed(
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
    `target`, `harness` (the generated entry point) or `external` (system and pipeline headers, and
    the build capture's snapshot of the build image, wherever the run directory is mounted).
    """
    if path.startswith(COVERAGE_EXTERNAL_PREFIXES) or f"/{COVERAGE_SNAPSHOT_ROOT}" in f"/{path}":
        return "external"
    if "/workspace/harnesses/" in f"/{path}" or posixpath.basename(path).startswith("harness_"):
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
) -> dict:
    """
    Which target functions and regions the corpus executes. `partial` means some inputs failed or
    were not replayed, so reached counts are lower bounds. The report says what the corpus reached;
    it decides no verdict and nothing in the ledger reads it.

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
        comp = compile_coverage_binary(sources, out_bin, flags, ldflags, use_cache=use_cache)
        report["compile"] = comp
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


def _add_build_args(p: argparse.ArgumentParser, sources_required: bool = True) -> None:
    p.add_argument("--sources", nargs="+", required=sources_required)
    p.add_argument("--machdep", default="gcc_x86_64")
    p.add_argument("--cppflags", default="-I.")
    p.add_argument("--ldflags", default="", help="Extra linker flags (e.g. '-lbsd -lm')")
    p.add_argument("--rte", default="all")
    p.add_argument(
        "--engine",
        choices=["auto", "eacsl", "sanitizers"],
        default="auto",
        help=(
            "Instrumentation engine: 'auto' tries E-ACSL first and falls back to Clang ASan+UBSan on compile "
            "error; a campaign with 'auto' and a working E-ACSL build fuzzes with both, half the time each"
        ),
    )
    p.add_argument("--functions", nargs="*", default=None, help="Explicit target functions to instrument in E-ACSL")
    p.add_argument(
        "--no-variadic-translation",
        action="store_true",
        help="Pass -no-variadic-translation to Frama-C (no <fn>_fallback_<N> symbols are emitted)",
    )
    p.add_argument(
        "--warn-unsigned-downcast",
        action="store_true",
        help="Enable -warn-unsigned-downcast in Frama-C E-ACSL instrumentation",
    )
    p.add_argument(
        "--no-rte-initialized",
        action="store_true",
        help="Do not check uninitialized reads (-rte-initialized); recorded in reduced_checks",
    )
    p.add_argument(
        "--selftest-json",
        type=Path,
        default=DEFAULT_SELFTEST_JSON,
        help="Cached selftest result; with --engine auto a failed selftest for this Frama-C version skips E-ACSL",
    )
    p.add_argument(
        "--no-cache",
        action="store_true",
        help="Do not read or write the run/shared cache",
    )
    p.add_argument(
        "--dag",
        type=Path,
        default=None,
        help="callgraph_dag.json used to repair link failures (undefined references -> defining source, one retry)",
    )


def _build_options(args) -> dict:
    dag = getattr(args, "dag", None)
    if dag is None:
        default_dag = Path("workspace/reports/callgraph_dag.json")
        dag = default_dag if default_dag.is_file() else None
    return {
        "engine": args.engine,
        "selftest_json": args.selftest_json,
        "machdep": args.machdep,
        "cppflags": args.cppflags,
        "ldflags": args.ldflags,
        "rte": args.rte,
        "functions": args.functions,
        "variadic_translation": not args.no_variadic_translation,
        "warn_unsigned_downcast": args.warn_unsigned_downcast,
        "rte_initialized": not args.no_rte_initialized,
        "use_cache": not getattr(args, "no_cache", False),
        "dag_path": dag,
    }


_SUMMARY_OMITTED = ("compile", "log_tail", "runtime_trace", "eacsl_compile_attempt", "functions", "failed_inputs")


def _summary(res: dict) -> dict:
    """What is printed: the report without logs and compiler output (the JSON file has everything)."""
    out = {k: v for k, v in res.items() if k not in _SUMMARY_OMITTED}
    if isinstance(out.get("artifacts"), list):
        out["artifacts"] = [
            {k: v for k, v in a.items() if k not in ("replay_log_tail", "attribution")} if isinstance(a, dict) else a
            for a in out["artifacts"]
        ]
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="E-ACSL + LibFuzzer campaigns, guardrails, builds and replays.")
    sub = parser.add_subparsers(dest="mode", required=True)

    p_camp = sub.add_parser("campaign")
    _add_build_args(p_camp)
    p_camp.add_argument("--out-bin", type=Path, required=True)
    p_camp.add_argument("--corpus-dir", type=Path, required=True, help="Writable corpus directory (receives new units)")
    p_camp.add_argument("--extra-corpus", type=Path, nargs="*", default=[], help="Read-only seed corpus directories")
    p_camp.add_argument("--artifacts-dir", type=Path, required=True)
    p_camp.add_argument(
        "--max-time", type=int, default=None, help="Wall-clock seconds per job (default: from --fuzz-budget, else 60)"
    )
    p_camp.add_argument(
        "--fuzz-budget",
        type=int,
        default=None,
        help="CPU-second budget: wall time = max(30, budget / workers) unless --max-time is given",
    )
    p_camp.add_argument("--per-input-timeout", type=int, default=DEFAULT_PER_INPUT_TIMEOUT_S)
    p_camp.add_argument("--dict", type=Path, default=None)
    p_camp.add_argument(
        "--no-auto-dict",
        action="store_true",
        help=(
            "Without --dict, do not extract a dictionary from the target sources "
            "(default: write workspace/dicts/<module>.dict with scripts/fuzz_dictionary.py and fuzz with it)"
        ),
    )
    p_camp.add_argument("--jobs", type=int, default=None, help="LibFuzzer -jobs=<N> (default: the number of workers)")
    p_camp.add_argument(
        "--workers",
        default="auto",
        help="LibFuzzer -workers=<N>: 'auto' (from this job's CPUs and memory at -rss_limit_mb 2048) or N",
    )
    p_camp.add_argument(
        "--no-attribution-replay",
        action="store_true",
        help="Do not replay unattributed E-ACSL crashes on a sanitizer build",
    )
    p_camp.add_argument(
        "--stop-on-first-crash",
        action="store_true",
        help=(
            "End the campaign at the first crash (default: keep going: a dispatch harness reruns "
            f"with the crashed cases skipped via -D{DISPATCH_SKIP_MACRO}, any other in libFuzzer fork mode)"
        ),
    )
    p_camp.add_argument("--module", default="")
    p_camp.add_argument("--out-json", type=Path, required=True)

    p_guard = sub.add_parser("guardrail")
    p_guard.add_argument("--sources", nargs="+", required=True)
    p_guard.add_argument("--out-bin", type=Path, required=True)
    p_guard.add_argument("--corpus-dir", type=Path, required=True)
    p_guard.add_argument(
        "--scratch-dir", type=Path, default=None, help="Agent scratch dir (default: next to --out-bin)"
    )
    p_guard.add_argument("--extra-runs", type=int, default=200)
    p_guard.add_argument(
        "--per-input-timeout",
        type=int,
        default=GUARDRAIL_PER_INPUT_TIMEOUT_S,
        help="LibFuzzer -timeout per input (fixed; never derived from the machine)",
    )
    p_guard.add_argument("--module", default="", help="Module name (part of the deterministic -seed)")
    p_guard.add_argument("--machdep", default="gcc_x86_64")
    p_guard.add_argument("--cppflags", default="-I.")
    p_guard.add_argument("--ldflags", default="", help="Extra linker flags")
    p_guard.add_argument(
        "--functions", nargs="*", default=None, help="Explicit target functions to instrument in E-ACSL"
    )
    p_guard.add_argument("--no-variadic-translation", action="store_true")
    p_guard.add_argument(
        "--warn-unsigned-downcast",
        action="store_true",
        help="Enable -warn-unsigned-downcast in Frama-C E-ACSL instrumentation",
    )
    p_guard.add_argument(
        "--no-rte-initialized",
        action="store_true",
        help="Do not check uninitialized reads (-rte-initialized); recorded in reduced_checks",
    )
    p_guard.add_argument(
        "--no-cache",
        action="store_true",
        help="Do not read or write the run/shared cache",
    )
    p_guard.add_argument(
        "--no-verdict-cache",
        action="store_true",
        help="Do not read or write the guardrail verdict cache",
    )
    p_guard.add_argument(
        "--max-corpus-inputs",
        type=int,
        default=64,
        help=(
            "Corpus inputs to replay (default: 64). Promoted seed-*/crash-* files are always replayed; the rest "
            "is a deterministic sample (report: corpus_total, corpus_replayed, corpus_sampled)"
        ),
    )
    p_guard.add_argument(
        "--reach-functions",
        nargs="*",
        default=None,
        help="Functions whose reach the report measures (default: --functions). Does not narrow instrumentation",
    )
    p_guard.add_argument("--out-json", type=Path, required=True)

    p_self = sub.add_parser("selftest", help="Verify the E-ACSL toolchain contract on the bundled canary")
    p_self.add_argument("--work-dir", type=Path, default=Path("workspace/eacsl_selftest"))
    p_self.add_argument("--machdep", default="gcc_x86_64")
    p_self.add_argument("--no-variadic-translation", action="store_true")
    p_self.add_argument("--out-json", type=Path, default=DEFAULT_SELFTEST_JSON)

    p_build = sub.add_parser("build", help="Compile a module's fuzz binary (cached); nothing is executed")
    _add_build_args(p_build)
    p_build.add_argument("--module", default="")
    p_build.add_argument("--out-bin", type=Path, required=True)
    p_build.add_argument("--out-json", type=Path, required=True)

    p_replay = sub.add_parser("replay", help="Replay inputs once each on a given or (cached) built binary")
    _add_build_args(p_replay, sources_required=False)
    p_replay.add_argument("--module", required=True)
    p_replay.add_argument("--inputs", type=Path, nargs="+", required=True, help="Input files or directories of inputs")
    p_replay.add_argument("--binary", type=Path, default=None, help="Replay on this binary instead of building one")
    p_replay.add_argument("--out-bin", type=Path, default=None)
    p_replay.add_argument("--per-input-timeout", type=int, default=DEFAULT_PER_INPUT_TIMEOUT_S)
    p_replay.add_argument(
        "--scratch-dir", type=Path, default=None, help="Sandbox scratch (default: next to --out-json)"
    )
    p_replay.add_argument(
        "--no-attribution-replay",
        action="store_true",
        help="Do not replay unattributed E-ACSL crashes on a sanitizer build",
    )
    p_replay.add_argument("--out-json", type=Path, required=True)

    p_cov = sub.add_parser("coverage", help="Measure which target functions a module's corpus executes")
    p_cov.add_argument("--module", required=True)
    p_cov.add_argument("--sources", nargs="+", required=True)
    p_cov.add_argument("--out-bin", type=Path, required=True)
    p_cov.add_argument("--corpus-dir", type=Path, required=True)
    p_cov.add_argument("--extra-corpus", type=Path, nargs="*", default=[], help="More corpus directories to replay")
    p_cov.add_argument("--scratch-dir", type=Path, default=None)
    p_cov.add_argument("--cppflags", default="-I.")
    p_cov.add_argument("--ldflags", default="", help="Extra linker flags")
    p_cov.add_argument("--per-input-timeout", type=int, default=DEFAULT_PER_INPUT_TIMEOUT_S)
    p_cov.add_argument(
        "--max-time",
        type=int,
        default=COVERAGE_MAX_TIME_S,
        help="Stop replaying after this many seconds; the report is then `partial`",
    )
    p_cov.add_argument(
        "--known-crashes-dir",
        type=Path,
        nargs="*",
        default=None,
        help="Crash artifacts whose inputs replay last (default: workspace/crashes/<module>; none when empty)",
    )
    p_cov.add_argument("--no-cache", action="store_true", help="Do not read or write the run/shared cache")
    p_cov.add_argument("--out-json", type=Path, required=True)

    p_cands = sub.add_parser("replay-candidates", help="Replay the reproducers of every unverified candidate")
    p_cands.add_argument("--candidates", type=Path, default=Path("candidates.json"))
    p_cands.add_argument("--harness-dir", type=Path, default=Path("workspace/harnesses"))
    p_cands.add_argument("--out-dir", type=Path, default=Path("workspace/reports/replay"))
    p_cands.add_argument(
        "--bin-dir",
        type=Path,
        default=None,
        help="Where module binaries are built (default: workspace/harnesses, as `make build`)",
    )
    p_cands.add_argument(
        "--engine",
        choices=["auto", "eacsl", "sanitizers"],
        default=None,
        help="Default: the engine of the campaign that found each candidate, else auto",
    )
    p_cands.add_argument("--selftest-json", type=Path, default=DEFAULT_SELFTEST_JSON)
    p_cands.add_argument("--machdep", default="gcc_x86_64")
    p_cands.add_argument("--per-input-timeout", type=int, default=DEFAULT_PER_INPUT_TIMEOUT_S)
    p_cands.add_argument("--no-attribution-replay", action="store_true")

    p_min = sub.add_parser("minimize", help="Minimize crash input(s) with cvise/creduce on a given or built binary")
    _add_build_args(p_min, sources_required=False)
    p_min.add_argument("--module", required=True)
    p_min.add_argument("--inputs", type=Path, nargs="+", required=True, help="Crash input files to minimize")
    p_min.add_argument("--binary", type=Path, default=None, help="Minimize on this binary instead of building one")
    p_min.add_argument("--out-bin", type=Path, default=None)
    p_min.add_argument("--fingerprint", default=None, help="Only accept variants crashing with this fingerprint")
    p_min.add_argument("--max-time", type=int, default=600, help="Wall-clock seconds per input (default: 600)")
    p_min.add_argument("--jobs", type=int, default=4, help="cvise/creduce parallel jobs (default: 4)")
    p_min.add_argument("--per-input-timeout", type=int, default=DEFAULT_PER_INPUT_TIMEOUT_S)
    p_min.add_argument("--scratch-dir", type=Path, default=None)
    p_min.add_argument("--out-json", type=Path, required=True)

    p_minc = sub.add_parser("minimize-candidates", help="Minimize the reproducers of every unverified candidate")
    p_minc.add_argument("--candidates", type=Path, default=Path("candidates.json"))
    p_minc.add_argument("--harness-dir", type=Path, default=Path("workspace/harnesses"))
    p_minc.add_argument("--out-dir", type=Path, default=Path("workspace/reports/minimize"))
    p_minc.add_argument("--bin-dir", type=Path, default=None)
    p_minc.add_argument("--engine", choices=["auto", "eacsl", "sanitizers"], default=None)
    p_minc.add_argument("--selftest-json", type=Path, default=DEFAULT_SELFTEST_JSON)
    p_minc.add_argument("--machdep", default="gcc_x86_64")
    p_minc.add_argument("--per-input-timeout", type=int, default=DEFAULT_PER_INPUT_TIMEOUT_S)
    p_minc.add_argument("--max-time", type=int, default=600, help="Wall-clock seconds per reproducer (default: 600)")
    p_minc.add_argument("--jobs", type=int, default=4)

    p_int = sub.add_parser("minimize-interest", help="cvise interest test (called by the generated interest.sh)")
    p_int.add_argument("--binary", type=Path, required=True)
    p_int.add_argument("--fingerprint", default="")
    p_int.add_argument("--module", default="")
    p_int.add_argument("--per-input-timeout", type=int, default=DEFAULT_PER_INPUT_TIMEOUT_S)
    p_int.add_argument("--scratch-dir", type=Path, required=True)
    p_int.add_argument("variant", type=Path)

    raw_argv = normalize_flag_args(list(argv) if argv is not None else sys.argv[1:])
    args = parser.parse_args(raw_argv)
    if args.mode == "campaign" and str(args.workers).strip().lower() != "auto":
        try:
            if int(args.workers) < 1:
                raise ValueError
        except ValueError:
            parser.error(f"--workers must be 'auto' or a positive integer (got {args.workers!r})")
    if args.mode == "replay" and args.binary is None and not (args.sources and args.out_bin):
        parser.error("replay needs --binary, or --sources with --out-bin")

    if args.mode == "campaign":
        gate_reasons = campaign_gate_reasons(Path("."), args.module)
        if gate_reasons:
            for reason in gate_reasons:
                print(f"phase0 gate: {reason}", file=sys.stderr)
            refused = {"mode": "campaign", "module": args.module, "status": "gate_failed", "reasons": gate_reasons}
            print(json.dumps(refused, indent=2))
            return 1

    if args.mode == "replay-candidates":
        summary = replay_candidates(
            args.candidates,
            args.harness_dir,
            args.out_dir,
            bin_dir=args.bin_dir,
            engine=args.engine,
            selftest_json=args.selftest_json,
            machdep=args.machdep,
            per_input_timeout=args.per_input_timeout,
            attribution=not args.no_attribution_replay,
        )
        print(json.dumps(summary, indent=2))
        return 0 if summary["status"] == "ok" else 1

    if args.mode == "minimize-interest":
        # Exit 0 iff the variant is still interesting (crashes with the same fingerprint).
        interesting = minimize_interest(
            args.binary,
            args.variant,
            args.scratch_dir,
            args.fingerprint or None,
            module=args.module,
            per_input_timeout=args.per_input_timeout,
        )
        return 0 if interesting else 1

    if args.mode == "minimize-candidates":
        summary = minimize_candidates(
            args.candidates,
            args.harness_dir,
            args.out_dir,
            bin_dir=args.bin_dir,
            engine=args.engine,
            selftest_json=args.selftest_json,
            machdep=args.machdep,
            per_input_timeout=args.per_input_timeout,
            max_time_s=args.max_time,
            jobs=args.jobs,
        )
        print(json.dumps(summary, indent=2))
        return 0 if summary["status"] == "ok" else 1

    if args.mode == "minimize":
        if args.binary is None and not (args.sources and args.out_bin):
            parser.error("minimize needs --binary, or --sources with --out-bin")
        prepared = None
        if args.binary is None:
            prepared = prepare_replay_binary(
                args.module,
                args.sources,
                args.out_bin,
                engine=args.engine,
                selftest_json=args.selftest_json,
                machdep=args.machdep,
                cppflags=args.cppflags,
                ldflags=args.ldflags,
                rte_initialized=not args.no_rte_initialized,
            )
            binary = prepared.get("binary")
        else:
            binary = args.binary
        scratch = args.scratch_dir or args.out_json.parent / f".scratch_minimize_{args.module}"
        runs = [
            minimize_input(
                Path(binary) if binary else Path(""),
                inp,
                scratch,
                module=args.module,
                fingerprint=args.fingerprint,
                max_time_s=args.max_time,
                jobs=args.jobs,
                per_input_timeout=args.per_input_timeout,
            )
            for inp in args.inputs
        ]
        res = {
            "mode": "minimize",
            "module": args.module,
            "binary": str(binary) if binary else None,
            "status": "ok" if any(r["status"] == "ok" for r in runs) else "error",
            "runs": runs,
        }
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(_summary(res), indent=2))
        return 0 if res["status"] == "ok" else 1

    digest_before = prover_candidates.digest_before_run(args.out_json) if args.mode == "guardrail" else None
    try:
        if args.mode == "selftest":
            res = run_selftest(args.work_dir, args.machdep, variadic_translation=not args.no_variadic_translation)
        elif args.mode == "campaign":
            res = _run_campaign_mode(args)
        elif args.mode == "build":
            res = _run_build_mode(args)
        elif args.mode == "coverage":
            res = coverage_report(
                args.module,
                args.sources,
                args.out_bin,
                [args.corpus_dir, *args.extra_corpus],
                args.scratch_dir or args.out_json.parent / f".scratch_coverage_{args.module}",
                cppflags=args.cppflags,
                ldflags=args.ldflags,
                per_input_timeout=args.per_input_timeout,
                max_time=args.max_time,
                use_cache=not args.no_cache,
                known_crash_dirs=(
                    [Path("workspace/crashes") / args.module]
                    if args.known_crashes_dir is None
                    else args.known_crashes_dir
                ),
            )
        elif args.mode == "replay":
            prepared = None
            if args.binary is None:
                prepared = prepare_replay_binary(
                    args.module,
                    args.sources,
                    args.out_bin,
                    attribution=not args.no_attribution_replay,
                    **_build_options(args),
                )
            scratch = args.scratch_dir or args.out_json.parent / f".scratch_replay_{args.module or 'module'}"
            res = replay_report(
                args.module,
                args.inputs,
                scratch,
                prepared=prepared,
                binary=args.binary,
                per_input_timeout=args.per_input_timeout,
            )
        else:
            use_cache = not getattr(args, "no_cache", False)
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
                use_cache=use_cache,
            )
            if comp["returncode"] != 0:
                res = {
                    "mode": "guardrail",
                    "status": "compile_error",
                    "reason": comp.get("reason"),
                    "compile": comp,
                    "crash_input": None,
                }
                res["diagnostic_hints"] = derive_eacsl_diagnostic_hints(res)
            else:
                scratch = args.scratch_dir or args.out_bin.parent / f"{args.out_bin.name}_guard_scratch"
                use_verdict_cache = use_cache and not getattr(args, "no_verdict_cache", False)
                guard = run_guardrail_check(
                    Path(comp["binary"]),
                    args.corpus_dir,
                    scratch,
                    args.extra_runs,
                    per_input_timeout=args.per_input_timeout,
                    module=args.module,
                    use_cache=use_cache,
                    use_verdict_cache=use_verdict_cache,
                    max_corpus_inputs=args.max_corpus_inputs,
                    functions=args.reach_functions if args.reach_functions else args.functions,
                )
                res = {"mode": "guardrail", "compile": comp, **guard, "reduced_checks": comp.get("reduced_checks", [])}
                if "diagnostic_hints" not in res:
                    res["diagnostic_hints"] = derive_eacsl_diagnostic_hints(res)
    except SandboxUnavailable as exc:
        res = {"mode": args.mode, "status": "sandbox_unavailable", "reason": str(exc)}
        if args.mode == "guardrail":
            res["crash_input"] = None

    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")
    summary = _summary(res)
    if args.mode == "guardrail":
        prover_candidates.add_candidate_block(summary, args.out_json, "guardrail", res, digest_before)
    print(json.dumps(summary, indent=2))
    if args.mode == "selftest":
        return 0 if res.get("ok") else 1
    if args.mode == "build":
        return 0 if res.get("status") == "built" else 1
    if args.mode == "replay":
        if str(res.get("reason") or "").startswith("sandbox_unavailable"):
            return 3
        return 0 if res.get("status") in ("reproduced", "not_reproduced") else 1
    return 3 if res.get("status") == "sandbox_unavailable" else 0


def _run_build_mode(args) -> dict:
    build = build_module_binary(args.sources, args.out_bin, **_build_options(args))
    comp = build["compile"]
    built = comp["returncode"] == 0
    res: dict = {
        "mode": "build",
        "module": args.module,
        "status": "built" if built else "compile_error",
        "engine_used": build["engine_used"],
        "binary": comp.get("binary") if built else None,
        "sources": list(args.sources),
        "cache": comp.get("cache"),
        "compile": comp,
    }
    if built and build["engine_used"] == "eacsl" and comp.get("reduced_checks"):
        res["reduced_checks"] = comp["reduced_checks"]
    if build["engine_fallback_reason"]:
        res["engine_fallback_reason"] = build["engine_fallback_reason"]
    if build["eacsl_compile_attempt"] is not None:
        res["eacsl_compile_attempt"] = build["eacsl_compile_attempt"]
    if build.get("link_repair"):
        res["link_repair"] = build["link_repair"]
    res["diagnostic_hints"] = derive_eacsl_diagnostic_hints(res)
    return res


CAMPAIGN_GATE_NEED = ("reach", "build_check")


def campaign_gate_reasons(run_dir: Path, module: str) -> list[str]:
    """
    Why the Phase 0 gate refuses a campaign on `module` (empty when it may run), checked as
    `phase0_gates.py check --module <mod> --need reach,build_check` checks it before Make's fuzz
    recipe. Only when the run directory has a gate stamp: a campaign outside a pipeline run (no
    workspace/reports/phase0_gates.json) or without --module is not gated. The report is not
    written on a refusal, so nothing ingests a campaign that did not run.
    """
    import phase0_gates  # imported lazily: campaigns outside a run directory do not need it

    if not module or not (Path(run_dir) / phase0_gates.GATES_JSON).is_file():
        return []
    try:
        return phase0_gates.check(Path(run_dir), module, CAMPAIGN_GATE_NEED)
    except (ArtifactError, OSError, ValueError) as exc:
        return [f"cannot read {phase0_gates.GATES_JSON}: {exc}"]


def _run_campaign_mode(args) -> dict:
    workers = resolve_workers(args.workers)
    jobs = args.jobs if args.jobs else workers
    max_time = campaign_wall_time(args.max_time, args.fuzz_budget, workers)
    sizing = {
        "workers": workers,
        "jobs": jobs,
        "max_time": max_time,
        "fuzz_budget_cpu_s": args.fuzz_budget,
        "rss_limit_mb": FUZZ_RSS_LIMIT_MB,
        "per_input_timeout": args.per_input_timeout,
    }
    req_mem = fuzz_required_memory_mb(workers)
    mem_limit = enforced_memory_mb()
    if mem_limit is not None and mem_limit < req_mem:
        note = (
            f"this job may use {mem_limit} MiB, but LibFuzzer needs at least {req_mem} MiB "
            f"({FUZZ_WORKER_OVERHEAD_MB} MiB overhead plus {workers} worker(s) at "
            f"{int(FUZZ_RSS_LIMIT_MB * 1.25)} MiB each for the fixed {FUZZ_RSS_LIMIT_MB} MiB -rss_limit_mb)"
        )
        return {
            "mode": "campaign",
            "module": args.module,
            "sources": args.sources,
            "status": "insufficient_memory",
            "reason": "insufficient_memory",
            "error_summary": [note],
            "memory_limit_mb": mem_limit,
            "min_memory_mb": req_mem,
            "returncode": None,
            "timed_out": False,
            "artifacts": [],
            "new_A2_artifacts": [],
            "log_tail": note,
            "sizing": {**sizing, "memory_limit_mb": mem_limit},
        }
    use_cache = not getattr(args, "no_cache", False)
    build = build_module_binary(args.sources, args.out_bin, **_build_options(args))
    comp = build["compile"]
    engine_used = build["engine_used"]
    res: dict = {"mode": "campaign", "module": args.module}
    if comp["returncode"] != 0:
        res.update({"status": "compile_error", "engine_used": engine_used, "compile": comp})
    else:
        attribution_builder = None
        if engine_used == "eacsl" and not args.no_attribution_replay:
            attribution_builder = _sanitizer_attribution_builder(
                build.get("sources") or args.sources, args.out_bin, args.cppflags, args.ldflags, use_cache=use_cache
            )

        warm_started = cache.warm_start_corpus(args.module, args.corpus_dir) if (args.module and use_cache) else 0
        dict_file, dict_info = resolve_campaign_dictionary(
            args.dict,
            args.sources,
            args.module,
            args.corpus_dir,
            auto=not getattr(args, "no_auto_dict", False),
            cppflags=args.cppflags,
        )

        n_cases = dispatch_case_count(args.sources)
        skippable = dispatch_skippable_cases(args.sources, n_cases) if n_cases is not None else None

        def _engine_campaign(engine: str, binary: Path, seconds: int) -> dict:
            attribution = attribution_builder if engine == "eacsl" else None

            def _campaign(binary: Path, seconds: int, fork: bool) -> dict:
                return run_fuzz_campaign(
                    binary,
                    args.corpus_dir,
                    args.artifacts_dir,
                    seconds,
                    dict_file,
                    args.per_input_timeout,
                    extra_corpus=args.extra_corpus,
                    attribution_builder=attribution,
                    jobs=jobs,
                    workers=workers,
                    fork=fork,
                )

            def _rebuild(mask: int) -> tuple[Path | None, dict]:
                opts = _build_options(args)
                # Same engine as the round before, so every round checks the same properties.
                opts["engine"] = engine
                opts["cppflags"] = f"{opts['cppflags'] or ''} {dispatch_skip_cppflags(mask)}".strip()
                rebuilt = build_module_binary(args.sources, args.out_bin, **opts)
                ok = rebuilt["compile"]["returncode"] == 0 and rebuilt["engine_used"] == engine
                return (Path(rebuilt["compile"]["binary"]) if ok else None), rebuilt

            out = run_campaign_rounds(
                binary,
                seconds,
                campaign=_campaign,
                rebuild=_rebuild,
                n_cases=n_cases,
                keep_going=not args.stop_on_first_crash,
                skippable=skippable,
            )
            for art in out.get("artifacts") or []:
                art["engine"] = engine
            return out

        # `auto` with a working E-ACSL build fuzzes with both engines, half the time each: ASan+UBSan
        # first (faster, and it catches what E-ACSL does not check, such as overlapping memcpy), then
        # E-ACSL on the grown corpus, which replays every corpus input under its contract checks.
        second = None
        if args.engine == "auto" and engine_used == "eacsl":
            san = build_module_binary(args.sources, args.out_bin, **{**_build_options(args), "engine": "sanitizers"})
            if san["compile"]["returncode"] == 0 and san["engine_used"] == "sanitizers":
                second = san
            else:
                res["dual_engine_skipped"] = "sanitizer build failed"
        if second is None:
            fuzz = _engine_campaign(engine_used, Path(comp["binary"]), max_time)
            res.update({"sources": args.sources, "engine_used": engine_used, "compile": comp, **fuzz})
        else:
            share = max(MIN_FUZZ_WALL_S, max_time // 2)
            runs = {
                "sanitizers": _engine_campaign("sanitizers", Path(second["compile"]["binary"]), share),
                "eacsl": _engine_campaign("eacsl", Path(comp["binary"]), share),
            }
            fuzz = merge_engine_campaigns(runs)
            res.update({"sources": args.sources, "engine_used": DUAL_ENGINE, "compile": comp, **fuzz})
            res["sanitizer_compile"] = second["compile"]
        published = (
            cache.publish_corpus(args.module, args.corpus_dir)
            if args.module and use_cache and fuzz.get("status") != "insufficient_memory"
            else 0
        )
        res["dictionary"] = dict_info
        if warm_started or published:
            res["corpus_cache"] = {"warm_started": warm_started, "published": published}
        if engine_used == "eacsl" and comp.get("reduced_checks"):
            res["reduced_checks"] = comp["reduced_checks"]
    res["sizing"] = sizing
    if build["engine_fallback_reason"]:
        res["engine_fallback_reason"] = build["engine_fallback_reason"]
    if build["eacsl_compile_attempt"] is not None:
        res["eacsl_compile_attempt"] = build["eacsl_compile_attempt"]
    if build.get("link_repair"):
        res["link_repair"] = build["link_repair"]
    res["diagnostic_hints"] = derive_eacsl_diagnostic_hints(res)
    return res


if __name__ == "__main__":
    sys.exit(main())
