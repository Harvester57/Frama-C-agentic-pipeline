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
   one fingerprint are listed at most 3 times. A binary that defines the libc functions libFuzzer
   starts its worker processes with (system, exec*, posix_spawn*, ...: an LD_PRELOAD interposer
   such as sudo_noexec.c), or whose multi-process campaign ends before any input ran, is fuzzed in
   one process (`single_process_reason`).
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
   A replayed input that crashes outside the checked functions (a seed that reproduces a known bug
   elsewhere in the module), with no E-ACSL report or with an E-ACSL failure in a function that is
   not checked and was not reached through one, is dropped and the rest replayed again, at most
   GUARDRAIL_MAX_EXCLUDED_INPUTS times; `excluded_inputs` lists each with its crash (and the E-ACSL
   `failure` and `fingerprint`). Such a failure is never a `code_fault` or `rejected_overconstrained`
   of the contract under check. When the input is a mutation of the burst, not a corpus file, the
   corpus is replayed again without mutations and `mutations_skipped` holds the crash (and, for an
   E-ACSL failure, its `failure` and `fingerprint`), whether or not E-ACSL reported it. When the
   input still cannot be dropped, or past the limit, the status is `guardrail_error`; for an E-ACSL
   failure `outside_checked_functions` holds it, a sanitizer crash keeps the classifier's reason.
   A replayed input that hangs (libFuzzer's per-input `-timeout`) says nothing about the contract either: it is
   dropped the same way, its entry has `kind: timeout`, and a hanging mutation skips the burst. `timeout_s` bounds
   all the replays together. When the hang cannot be dropped, every input hung, the limit or the wall budget is
   reached, the status is `guardrail_error` and `replay_hang` holds the hang: never a pass, a `code_fault` or a
   rejected contract. `corpus_replayed` counts the inputs left, and a pass that dropped a hang is not cached.
   E-ACSL does not fail on a clause it cannot translate: it warns `Ignoring annotation` and checks nothing for
   it. The status keeps its meaning (what the executed checks did); `unchecked_clauses` names the clauses of the
   checked functions that were not executed, `dynamic_oracle_incomplete` is true when there is one, and
   `ignored_annotations` is the build's whole list (dynamic_oracle_fields).
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
8. `minimize`: minimizes crash input(s) with cvise/creduce on a given or built binary.
9. `minimize-candidates`: minimizes the reproducers of every unverified candidate.
10. `minimize-interest`: the cvise interest test, called by the generated interest.sh.

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
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter, deque
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cache  # noqa: E402
import crash_replay  # noqa: E402
import fuzz_build  # noqa: E402
import fuzz_coverage  # noqa: E402
import prover_candidates  # noqa: E402
import resources  # noqa: E402
import sandbox_exec  # noqa: E402
from crash_replay import (  # noqa: E402, F401
    _candidate_engine,
    _candidate_slug,
    _reproducer_paths,
    _sidecar_build_spec,
    _slim_compile,
    _unit_harness_module,
    acsl_include_dir,
    find_creduce,
    minimize_candidates,
    minimize_input,
    minimize_interest,
    prepare_replay_binary,
    replay_artifact,
    replay_build_spec,
    replay_candidates,
    replay_inputs,
    replay_report,
)
from eacsl_toolchain import (  # noqa: E402
    is_eacsl_instrumented,
)
from failure_identity import (  # noqa: E402, F401
    _ASAN_ERR_RE,
    _ASAN_OP_RE,
    _EACSL_GEN_PREFIX,
    _ERR_RE,
    _FN_RE,
    _LIBC_FN,
    _LIBC_QUOTED_RE,
    _LIBC_TEMPLATES,
    _OLD_RE,
    _PRED_HEAD_RE,
    _PROCESS_FRAME_FNS,
    _RUNTIME_FILE_MARKERS,
    _RUNTIME_FN_PREFIXES,
    _SEGMENT_RE,
    _SIGNEDNESS_PAIRS,
    _STACK_FRAME_RE,
    _UBSAN_RE,
    _UBSAN_VALUE_RE,
    STACK_FRAMES_MAX,
    _caller_of_eacsl_runtime,
    _failing_predicate,
    _is_acsl_annotation_line,
    _map_sanitizer_alarm_kind,
    _parse_libc_failure,
    _parse_segment_failure,
    _resolve_function_at_line,
    _resolve_source_candidates,
    failure_fingerprint,
    is_harness_fuzz_function,
    is_runtime_function,
    is_startup_failure,
    needs_attribution,
    parse_eacsl_failure,
    parse_eacsl_resource_abort,
    parse_link_stub_abort,
    parse_runtime_failure,
    parse_sanitizer_failure,
    stable_ubsan_message,
    stack_frames,
)
from fingerprint import (  # noqa: E402
    make_fingerprint,
    normalize_file,
)
from framac_common import (  # noqa: E402
    ArtifactError,
    atomic_write_json,
    normalize_flag_args,
    utc_now,
)
from fuzz_build import (  # noqa: E402, F401
    _ENVIRON_KEEP_SOURCE,
    _GETENV_CALL_RE,
    _GLOBAL_ARRAY_RE,
    _GLOBAL_POINTER_SLOT_RE,
    _GLOBAL_TAG_RE,
    _GLOBAL_TYPE_CHARS_RE,
    _PATCHED_STDIO_ERROR_RE,
    _UNDEFINED_REF_RE,
    LINK_GLOBALS_ASSUMPTION,
    LINK_GLOBALS_FILE,
    PrebuiltBinaryError,
    _build_environ_keep_object,
    _check_options,
    _compile_clang_binary,
    _compile_eacsl_binary_uncached,
    _dag_symbol_files,
    _dag_tree_path,
    _declaring_header,
    _decode,
    _discover_slice_functions,
    _eacsl_cache_material,
    _format_runtime_share,
    _link_unit_context,
    _model_global_variables,
    _normalize_dag_source,
    _note_cache_restore,
    _place_global,
    _resolve_eacsl_gcc,
    _run_tool,
    _runtime_patches,
    _sanitizer_attribution_builder,
    build_module_binary,
    compile_coverage_binary,
    compile_eacsl_binary,
    compile_sanitizer_binary,
    framac_version,
    global_definition_text,
    link_globals_source,
    parse_undefined_references,
    repair_sources_for_link,
    resolve_prebuilt_binary,
    selftest_blocks_eacsl,
)
from fuzz_common import (  # noqa: E402, F401
    ARTIFACT_KINDS,
    BUILD_TIMEOUT_S,
    DEFAULT_PER_INPUT_TIMEOUT_S,
    DEFAULT_SELFTEST_JSON,
    DUAL_ENGINE,
    SANITIZER_RUNTIME_ENV,
    _artifact_kind,
    _collect_inputs,
    _in_agent_scratch,
    derive_seed,
    replay_artifact_dir,
    sha256_file,
)
from fuzz_coverage import (  # noqa: E402, F401
    _INCLUDE_RE,
    _RUNNING_RE,
    COVERAGE_BATCH_SIZE,
    COVERAGE_EXTERNAL_PREFIXES,
    COVERAGE_LISTED_FAILED_INPUTS,
    COVERAGE_MAX_TIME_S,
    COVERAGE_MAX_UNCOVERED_RANGES,
    COVERAGE_SNAPSHOT_ROOT,
    COVERAGE_TOOL_TIMEOUT_S,
    COVERAGE_TRUNCATED_MAPPING,
    LLVM_COV_CODE_REGION,
    _coverage_file_role,
    _export_coverage,
    _includes_inside_braces,
    _input_running_at_exit,
    _known_crash_digests,
    _merge_line_ranges,
    _written_profiles,
    coverage_report,
    in_function_includes,
    replay_for_coverage,
    summarize_coverage_export,
)
from fuzz_dictionary import (  # noqa: E402, F401
    _DICT_LINE_RE,
    AUTO_DICT_DIR,
    _dict_stem,
    _dictionary_entry_lines,
    auto_dictionary_path,
    build_auto_dictionary,
    dictionary_target_sources,
    extra_dictionary_path,
    merge_extra_dictionary,
    resolve_campaign_dictionary,
    sanitize_dictionary_content,
    sanitize_dictionary_line,
    sanitize_dictionary_token,
    sanitize_fuzzer_dictionary,
)
from generate_harness import (  # noqa: E402
    DISPATCH_RUNTIME_SKIP_MARKER,
    DISPATCH_RUNTIME_SKIP_MAX_CASES,
    DISPATCH_SELECTOR_MODULO,
    DISPATCH_SKIP_ALL_MARKER,
    DISPATCH_SKIP_FN,
    DISPATCH_SKIP_MACRO,
    DISPATCH_SWITCH_RE,
    dispatch_case_of_bytes,
    dispatch_selector_of,
    dispatch_selector_of_text,
    dispatch_selector_width,
)
from resources import (  # noqa: E402
    FUZZ_RSS_LIMIT_MB,
    FUZZ_WORKER_OVERHEAD_MB,
    enforced_memory_mb,
    fuzz_workers,
)
from sandbox_exec import Limits, SandboxUnavailable  # noqa: E402

# Below this, a single LibFuzzer worker cannot have its fixed -rss_limit_mb=2048 alongside
# runtime/fork overhead without risking cgroup OOM kills (sizing model: 512 + int(2048 * 1.25) = 3072).
FUZZ_MIN_MEMORY_MB = FUZZ_WORKER_OVERHEAD_MB + int(FUZZ_RSS_LIMIT_MB * 1.25)


def fuzz_required_memory_mb(workers: int = 1) -> int:
    """Minimum memory required for `workers` LibFuzzer workers under the 1.25x headroom sizing model."""
    return FUZZ_WORKER_OVERHEAD_MB + max(1, workers) * int(FUZZ_RSS_LIMIT_MB * 1.25)


# Per-input LibFuzzer -timeout of guardrails (contract checks add overhead). The campaign and replay
# value, DEFAULT_PER_INPUT_TIMEOUT_S, is in fuzz_common. Fixed values, never derived from the machine.
GUARDRAIL_PER_INPUT_TIMEOUT_S = 30
DEFAULT_MAX_TIME_S = 60
MIN_FUZZ_WALL_S = 30
# Rounds are bounded by CPU-seconds: wall seconds times LibFuzzer workers, so a campaign runs the same
# rounds whatever its worker count. A new round needs at least this many CPU-seconds left. Fixed, never
# derived from the machine.
MIN_ROUND_CPU_S = 10
# Keep-going campaigns: a fork-mode run saves the same bug over and over, so only this many crash
# inputs are replayed and this many listed per fingerprint. Fixed, never derived from the machine.
MAX_REPLAYED_CRASHES = 64
MAX_ARTIFACTS_PER_FINGERPRINT = 3
# Both selector forms (`% <n>U` and the identity switch): generate_harness.DISPATCH_SWITCH_RE.
_DISPATCH_SWITCH_RE = DISPATCH_SWITCH_RE

_TEST_UNIT_WRITTEN_RE = re.compile(r"Test unit written to\s+(?P<path>\S+)")

# The libc functions libFuzzer starts its -jobs/-workers and -fork processes with (ExecuteCommand: system(),
# popen()). A binary that defines one replaces libc's in the whole process, libFuzzer included: an LD_PRELOAD
# interposer such as sudo_noexec.c returns EACCES, sudo_intercept.c routes it through a port. Such a binary
# is fuzzed in one process (sudo run-1: both engines ended `fuzzer_error` in 0.1 s). exec*/posix_spawn* the
# target replaces do not reach libFuzzer (glibc's system() spawns internally); whatever else keeps the
# workers from starting (a seccomp filter denying execve) is caught by the no-input rerun of run_fuzz_campaign.
PROCESS_LAUNCH_FUNCTIONS = frozenset({"system", "popen"})
# `nm` types of a global function definition: text, weak, indirect (GNU ifunc). A local (`t`) definition
# replaces nothing. A sanitizer runtime defines `popen` as a weak alias of `__interceptor_popen` (LLVM 17+
# also `___interceptor_popen`): that is libc's popen behind the interceptor, not a replacement.
_NM_GLOBAL_FUNCTION_TYPES = frozenset("TWi")
_NM_LINE_RE = re.compile(r"^\s*(?:[0-9a-fA-F]+\s+)?(?P<type>[A-Za-z])\s+(?P<name>\S+)\s*$")
_INTERCEPTOR_PREFIXES = ("___interceptor_", "__interceptor_")
NM_TIMEOUT_S = 120
# libFuzzer output that shows an input ran: a progress line (`#N\tINITED`, `#N\tNEW`, `#N\tpulse`, ...; fork
# mode's `#N: cov: ...`), `Done N runs` or the final stats.
_LIBFUZZER_PROGRESS_RE = re.compile(r"^#\d+(?:\t|:\s)", re.MULTILINE)
_LIBFUZZER_RUNS_RE = re.compile(
    r"^(?:Done (?P<done>\d+) runs|stat::number_of_executed_units:\s*(?P<units>\d+))", re.MULTILINE
)

# P1a/P1b/P2/P5/P6 constants (docs/plans/fuzz-budget-design.md).
DISPATCH_ONLY_CASE_ENV = "FRAMAC_FUZZ_ONLY_CASE"
BLINDING_CASE_THRESHOLD = 16
BLINDING_FORK_JOBS_THRESHOLD = 64
FORK_BLIND_PROBE_S = 5
JUDGE_SCHEMA_VERSION = 1
JUDGE_CORPUS_CAP_BY_PROFILE: dict[str, int] = {
    "quick": 512,
    "standard": 2048,
    "deep": 4096,
}
JUDGE_BATCH_SIZE = 64
JUDGE_DEFAULT_MAX_TIME_S = 1800
FLOOR_PASS_BY_PROFILE: dict[str, tuple[int, int]] = {
    "quick": (5000, 15),
    "standard": (25000, 120),
    "deep": (100000, 600),
}
FLOOR_PASS_MAX_RESTARTS = 4
MAX_TELEMETRY_SERIES_POINTS = 128
CROSS_ENGINE_ADJACENT_LINES = 5
BLINDING_REMEDIES: tuple[str, ...] = (
    "Inspect the blinding fingerprint against docs/references/e-acsl-quickref.md for known E-ACSL runtime issues.",
    "Override this module's engine with `params set --module <mod> --fuzz-engine sanitizers` if E-ACSL is blinded by a toolchain issue.",
    "Or repair the harness/stub setup fault and rerun `judge` (or the blinded campaign) to spend the unspent budget.",
)

# P5a libFuzzer status line regexes (standard worker logs and fork-mode parent logs).
_LF_WORKER_STATUS_RE = re.compile(
    r"^#(?P<unit>\d+)\s+\S+.*?\bcov:\s*(?P<cov>\d+)\s+ft:\s*(?P<ft>\d+)\s+"
    r"corp:\s*(?P<corp>\d+)(?:/\S+)?\b.*?\bexec/s:\s*(?P<exec_s>\d+)"
    r"(?:.*?\brss:\s*(?P<rss_mb>\d+)Mb)?",
    re.MULTILINE,
)
_LF_FORK_STATUS_RE = re.compile(
    r"^#(?P<unit>\d+):\s+cov:\s*(?P<cov>\d+)\s+ft:\s*(?P<ft>\d+)\s+"
    r"corp:\s*(?P<corp>\d+)(?:/\S+)?\b.*?\bexec/s:\s*(?P<exec_s>\d+)"
    r"(?:.*?\boom/timeout/crash:\s*(?P<oom>\d+)/(?P<timeout>\d+)/(?P<crash>\d+))?"
    r"(?:.*?\btime:\s*(?P<time_s>\d+)s)?"
    r"(?:.*?\bjob:\s*(?P<job>\d+))?"
    r"(?:.*?\brss:\s*(?P<rss_mb>\d+)Mb)?",
    re.MULTILINE,
)
_LF_STAT_UNITS_RE = re.compile(r"^stat::number_of_executed_units:\s*(?P<val>\d+)\s*$", re.MULTILINE)
_LF_STAT_EXEC_S_RE = re.compile(r"^stat::average_exec_per_sec:\s*(?P<val>\d+)\s*$", re.MULTILINE)
_LF_STAT_PEAK_RSS_RE = re.compile(r"^stat::peak_rss_mb:\s*(?P<val>\d+)\s*$", re.MULTILINE)
_LF_DONE_RUNS_RE = re.compile(r"^Done\s+(?P<runs>\d+)\s+runs\s+in\s+(?P<secs>\d+)\s+second", re.MULTILINE)


def _downsample_series(series: list[dict[str, Any]], limit: int = MAX_TELEMETRY_SERIES_POINTS) -> list[dict[str, Any]]:
    """Keep up to `limit` points preserving first, last, and evenly spaced interior samples."""
    if limit <= 0 or len(series) <= limit:
        return list(series)
    if limit == 1:
        return [series[-1]]
    step = (len(series) - 1) / (limit - 1)
    indices = sorted({round(i * step) for i in range(limit)})
    return [series[idx] for idx in indices]


def parse_libfuzzer_telemetry(
    outputs: str | Sequence[str],
    *,
    build_s: float = 0.0,
    fuzz_s: float = 0.0,
    replay_s: float = 0.0,
    floor_s: float | None = None,
    shared_s: float | None = None,
    oom_kills_delta: int | None = None,
) -> dict[str, Any]:
    """
    Parse multi-job libFuzzer status lines and final statistics (P5a/P5d) into a compact report
    block with `series`, aggregated executions/exec_s/peak_rss_mb, fork summary (when fork lines
    are present), and wall-time breakdown (`build_s`, `fuzz_s`, `replay_s`).
    """
    streams = [outputs] if isinstance(outputs, str) else [str(s or "") for s in outputs]
    series: list[dict[str, Any]] = []
    total_executions = 0
    total_exec_s = 0.0
    max_cov = 0
    max_ft = 0
    max_corp = 0
    peak_rss_mb: int | None = None
    jobs_observed = 0

    fork_seen = False
    fork_jobs = 0
    fork_crashes = 0
    fork_timeouts = 0
    fork_ooms = 0
    fork_max_corp = 0
    fork_max_unit = 0

    for stream in streams:
        if not stream:
            continue
        stream_points: list[dict[str, Any]] = []
        stream_max_unit = 0
        stream_last_exec_s = 0.0
        stream_peak_rss: int | None = None

        for m in _LF_WORKER_STATUS_RE.finditer(stream):
            unit = int(m.group("unit"))
            cov = int(m.group("cov"))
            ft = int(m.group("ft"))
            corp = int(m.group("corp"))
            exec_s = int(m.group("exec_s"))
            rss = int(m.group("rss_mb")) if m.group("rss_mb") is not None else None
            stream_max_unit = max(stream_max_unit, unit)
            stream_last_exec_s = float(exec_s)
            max_cov = max(max_cov, cov)
            max_ft = max(max_ft, ft)
            max_corp = max(max_corp, corp)
            if rss is not None:
                stream_peak_rss = rss if stream_peak_rss is None else max(stream_peak_rss, rss)
            stream_points.append(
                {
                    "unit": unit,
                    "cov": cov,
                    "ft": ft,
                    "corp": corp,
                    "exec_s": exec_s,
                    "rss_mb": rss,
                }
            )

        for m in _LF_FORK_STATUS_RE.finditer(stream):
            fork_seen = True
            unit = int(m.group("unit"))
            cov = int(m.group("cov"))
            ft = int(m.group("ft"))
            corp = int(m.group("corp"))
            exec_s = int(m.group("exec_s"))
            rss = int(m.group("rss_mb")) if m.group("rss_mb") is not None else None
            oom = int(m.group("oom")) if m.group("oom") is not None else 0
            to = int(m.group("timeout")) if m.group("timeout") is not None else 0
            crash = int(m.group("crash")) if m.group("crash") is not None else 0
            time_s = int(m.group("time_s")) if m.group("time_s") is not None else None
            job = int(m.group("job")) if m.group("job") is not None else None
            stream_max_unit = max(stream_max_unit, unit)
            stream_last_exec_s = float(exec_s)
            max_cov = max(max_cov, cov)
            max_ft = max(max_ft, ft)
            max_corp = max(max_corp, corp)
            fork_max_unit = max(fork_max_unit, unit)
            fork_max_corp = max(fork_max_corp, corp)
            fork_crashes = max(fork_crashes, crash)
            fork_timeouts = max(fork_timeouts, to)
            fork_ooms = max(fork_ooms, oom)
            if job is not None:
                fork_jobs = max(fork_jobs, job)
            if rss is not None:
                stream_peak_rss = rss if stream_peak_rss is None else max(stream_peak_rss, rss)
            point: dict[str, Any] = {
                "unit": unit,
                "cov": cov,
                "ft": ft,
                "corp": corp,
                "exec_s": exec_s,
                "rss_mb": rss,
                "crashes": crash,
            }
            if job is not None:
                point["job"] = job
            if time_s is not None:
                point["time_s"] = time_s
            stream_points.append(point)

        unit_stats = [int(m.group("val")) for m in _LF_STAT_UNITS_RE.finditer(stream)]
        exec_stats = [int(m.group("val")) for m in _LF_STAT_EXEC_S_RE.finditer(stream)]
        rss_stats = [int(m.group("val")) for m in _LF_STAT_PEAK_RSS_RE.finditer(stream)]
        done_runs = [int(m.group("runs")) for m in _LF_DONE_RUNS_RE.finditer(stream)]

        stream_has_activity = bool(stream_points or unit_stats or done_runs or rss_stats)
        if not stream_has_activity:
            continue

        if unit_stats:
            total_executions += sum(unit_stats)
            jobs_observed += len(unit_stats)
        elif done_runs:
            total_executions += sum(done_runs)
            jobs_observed += len(done_runs)
        else:
            total_executions += stream_max_unit
            jobs_observed += 1

        if exec_stats:
            total_exec_s += float(sum(exec_stats))
        elif stream_last_exec_s > 0:
            total_exec_s += stream_last_exec_s

        for rss_val in rss_stats:
            stream_peak_rss = rss_val if stream_peak_rss is None else max(stream_peak_rss, rss_val)
        if stream_peak_rss is not None:
            peak_rss_mb = stream_peak_rss if peak_rss_mb is None else max(peak_rss_mb, stream_peak_rss)

        series.extend(stream_points)

    if total_exec_s <= 0.0 and total_executions > 0 and fuzz_s > 0.0:
        total_exec_s = round(total_executions / fuzz_s, 2)

    out: dict[str, Any] = {
        "build_s": round(max(0.0, float(build_s)), 3),
        "fuzz_s": round(max(0.0, float(fuzz_s)), 3),
        "replay_s": round(max(0.0, float(replay_s)), 3),
        "series": _downsample_series(series),
        "total_executions": int(total_executions),
        "max_cov": int(max_cov),
        "max_ft": int(max_ft),
        "max_corp": int(max_corp),
        "exec_s": round(max(0.0, float(total_exec_s)), 2),
        "peak_rss_mb": peak_rss_mb,
        "jobs_observed": int(jobs_observed),
    }
    if floor_s is not None:
        out["floor_s"] = round(max(0.0, float(floor_s)), 3)
    if shared_s is not None:
        out["shared_s"] = round(max(0.0, float(shared_s)), 3)
    if oom_kills_delta is not None:
        out["oom_kills_delta"] = max(0, int(oom_kills_delta))
    if fork_seen:
        # In libFuzzer fork mode, `#N` counts completed non-crashing executions in the coordinator
        # when `cov > 0` or `corp > 0`, while crashing jobs fail without growing the corpus.
        passing_execs = 0 if (fork_max_corp == 0 and max_cov == 0 and fork_max_unit <= fork_crashes) else fork_max_unit
        out["fork_summary"] = {
            "jobs": max(fork_jobs, fork_crashes + fork_timeouts + fork_ooms),
            "crashes": fork_crashes,
            "timeouts": fork_timeouts,
            "ooms": fork_ooms,
            "max_corp": fork_max_corp,
            "passing_execs": max(0, passing_execs),
        }
    return out


def merge_telemetry(
    items: Sequence[dict[str, Any] | None],
    *,
    build_s: float | None = None,
    floor_s: float | None = None,
    shared_s: float | None = None,
) -> dict[str, Any]:
    """Combine telemetry dicts across rounds, passes, or engines."""
    valid = [t for t in items if isinstance(t, dict)]
    tot_build = sum(float(t.get("build_s") or 0.0) for t in valid) if build_s is None else float(build_s)
    tot_fuzz = sum(float(t.get("fuzz_s") or 0.0) for t in valid)
    tot_replay = sum(float(t.get("replay_s") or 0.0) for t in valid)
    series: list[dict[str, Any]] = []
    total_executions = 0
    max_cov = 0
    max_ft = 0
    max_corp = 0
    peak_rss_mb: float | int | None = None
    jobs_observed = 0
    oom_delta: int | None = None
    fork_summary: dict[str, int] | None = None

    for t in valid:
        series.extend(t.get("series") or [])
        total_executions += int(t.get("total_executions") or 0)
        max_cov = max(max_cov, int(t.get("max_cov") or 0))
        max_ft = max(max_ft, int(t.get("max_ft") or 0))
        max_corp = max(max_corp, int(t.get("max_corp") or 0))
        jobs_observed += int(t.get("jobs_observed") or 0)
        rss = t.get("peak_rss_mb")
        if isinstance(rss, (int, float)) and not isinstance(rss, bool):
            peak_rss_mb = rss if peak_rss_mb is None else max(peak_rss_mb, rss)
        od = t.get("oom_kills_delta")
        if isinstance(od, int) and not isinstance(od, bool):
            oom_delta = (oom_delta or 0) + od
        fs = t.get("fork_summary")
        if isinstance(fs, dict):
            if fork_summary is None:
                fork_summary = {
                    "jobs": int(fs.get("jobs") or 0),
                    "crashes": int(fs.get("crashes") or 0),
                    "timeouts": int(fs.get("timeouts") or 0),
                    "ooms": int(fs.get("ooms") or 0),
                    "max_corp": int(fs.get("max_corp") or 0),
                    "passing_execs": int(fs.get("passing_execs") or 0),
                }
            else:
                fork_summary["jobs"] += int(fs.get("jobs") or 0)
                fork_summary["crashes"] += int(fs.get("crashes") or 0)
                fork_summary["timeouts"] += int(fs.get("timeouts") or 0)
                fork_summary["ooms"] += int(fs.get("ooms") or 0)
                fork_summary["max_corp"] = max(fork_summary["max_corp"], int(fs.get("max_corp") or 0))
                fork_summary["passing_execs"] += int(fs.get("passing_execs") or 0)

    if tot_fuzz > 0.0 and total_executions > 0:
        exec_s = round(total_executions / tot_fuzz, 2)
    else:
        exec_vals = [float(t.get("exec_s") or 0.0) for t in valid if float(t.get("exec_s") or 0.0) > 0.0]
        exec_s = round(sum(exec_vals) / len(exec_vals), 2) if exec_vals else 0.0

    out: dict[str, Any] = {
        "build_s": round(max(0.0, tot_build), 3),
        "fuzz_s": round(max(0.0, tot_fuzz), 3),
        "replay_s": round(max(0.0, tot_replay), 3),
        "series": _downsample_series(series),
        "total_executions": total_executions,
        "max_cov": max_cov,
        "max_ft": max_ft,
        "max_corp": max_corp,
        "exec_s": exec_s,
        "peak_rss_mb": peak_rss_mb,
        "jobs_observed": jobs_observed,
    }
    if floor_s is not None:
        out["floor_s"] = round(max(0.0, float(floor_s)), 3)
    if shared_s is not None:
        out["shared_s"] = round(max(0.0, float(shared_s)), 3)
    if oom_delta is not None:
        out["oom_kills_delta"] = oom_delta
    if fork_summary is not None:
        out["fork_summary"] = fork_summary
    return out


def load_smoke_skipped_cases(smoke_report: Path | None) -> list[int]:
    """
    Read smoke-quarantined dispatch case indices from a `harness_smoke.py` JSON report.
    Returns sorted unique non-negative ints, or `[]` when `smoke_report` is absent/unreadable.
    """
    if smoke_report is None:
        return []
    path = Path(smoke_report)
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    cases: set[int] = set()
    quarantined = data.get("quarantined_cases")
    if isinstance(quarantined, list):
        for item in quarantined:
            if isinstance(item, int) and not isinstance(item, bool) and item >= 0:
                cases.add(item)
    if not cases:
        raw_env = data.get("skip_cases_env")
        if isinstance(raw_env, str) and raw_env.strip():
            for part in raw_env.split(","):
                part = part.strip()
                if part.isdigit():
                    cases.add(int(part))
    return sorted(cases)


def harness_supports_only_case(sources: Sequence[str | Path] | str | Path | None) -> bool:
    """True when at least one harness source supports `FRAMAC_FUZZ_ONLY_CASE` (P6a)."""
    if sources is None:
        return False
    items: Sequence[str | Path] = [sources] if isinstance(sources, (str, Path)) else sources
    for src in items:
        try:
            text = Path(src).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if DISPATCH_ONLY_CASE_ENV in text:
            return True
    return False


def explore_budget_cpu_s(fuzz_budget: int, profile: str = "standard") -> int:
    """CPU-second share for `explore` (P2a): 100% under quick/standard, 4/5 under deep."""
    budget = max(0, int(fuzz_budget))
    if (profile or "").strip().lower() == "deep":
        return (budget * 4) // 5
    return budget


def eacsl_fuzz_budget_cpu_s(fuzz_budget: int, profile: str = "deep") -> int:
    """CPU-second share for `eacsl-fuzz` (P2e): remaining 1/5 under deep, 0 under quick/standard."""
    budget = max(0, int(fuzz_budget))
    if (profile or "").strip().lower() != "deep":
        return 0
    return budget - explore_budget_cpu_s(budget, "deep")


class CaseBlindingTracker:
    """
    Per-case blinding tracker (P1a): a dispatch case (or single-entry module at case=0) that hits
    `threshold` (default K_case = 16) consecutive crashes with 0 passing executions on a single
    fingerprint is marked `blinded`.
    """

    def __init__(self, threshold: int = BLINDING_CASE_THRESHOLD) -> None:
        self.threshold = max(1, int(threshold))
        self._state: dict[int, dict[str, Any]] = {}

    def _entry(self, case: int) -> dict[str, Any]:
        return self._state.setdefault(
            int(case),
            {
                "passes": 0,
                "consecutive_crashes": 0,
                "last_fingerprint": None,
                "blinded": False,
                "blinded_fingerprint": None,
                "blinded_crashes": 0,
            },
        )

    def record_pass(self, case: int) -> None:
        st = self._entry(case)
        st["passes"] += 1
        st["consecutive_crashes"] = 0
        st["last_fingerprint"] = None

    def record_crash(self, case: int, fingerprint: str | None) -> bool:
        """Record one crashing execution on `case`. Returns True if `case` is newly blinded."""
        st = self._entry(case)
        if st["blinded"]:
            st["blinded_crashes"] += 1
            return False
        if st["passes"] > 0:
            return False
        fp_key = str(fingerprint) if fingerprint else "__unparsed__"
        if st["last_fingerprint"] == fp_key:
            st["consecutive_crashes"] += 1
        else:
            st["last_fingerprint"] = fp_key
            st["consecutive_crashes"] = 1
        if st["consecutive_crashes"] >= self.threshold:
            st["blinded"] = True
            st["blinded_fingerprint"] = fingerprint if fingerprint else None
            st["blinded_crashes"] = st["consecutive_crashes"]
            return True
        return False

    def mark_blinded(self, case: int, fingerprint: str | None, crashes: int | None = None) -> None:
        st = self._entry(case)
        st["blinded"] = True
        st["blinded_fingerprint"] = fingerprint
        st["blinded_crashes"] = max(self.threshold, int(crashes or self.threshold))

    def is_blinded(self, case: int) -> bool:
        return bool(self._state.get(int(case), {}).get("blinded"))

    def passes_of(self, case: int) -> int:
        return int(self._state.get(int(case), {}).get("passes") or 0)

    def blinded_case_ids(self) -> list[int]:
        return sorted(c for c, st in self._state.items() if st.get("blinded"))

    def blinded_cases_report(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for c in self.blinded_case_ids():
            st = self._state[c]
            out.append(
                {
                    "case": c,
                    "fingerprint": st.get("blinded_fingerprint"),
                    "crashes": int(st.get("blinded_crashes") or self.threshold),
                    "remedies": list(BLINDING_REMEDIES),
                }
            )
        return out


def detect_fork_blinding(
    telemetry: dict[str, Any] | None,
    artifacts: Sequence[dict[str, Any]],
    *,
    threshold: int = BLINDING_FORK_JOBS_THRESHOLD,
) -> dict[str, Any] | None:
    """
    Detect non-dispatch fork-mode blinding (P1a): `>= threshold` (default 64) crashing jobs with
    `corp == 0` and `0` passing executions. Returns a blinding summary dict or None.
    """
    if not isinstance(telemetry, dict):
        return None
    fs = telemetry.get("fork_summary")
    if not isinstance(fs, dict):
        return None
    crashes = int(fs.get("crashes") or 0)
    max_corp = int(fs.get("max_corp") or 0)
    passing = int(fs.get("passing_execs") or 0)
    if crashes < max(1, int(threshold)) or max_corp > 0 or passing > 0:
        return None
    fps = Counter(str(a.get("fingerprint")) for a in artifacts if isinstance(a, dict) and a.get("fingerprint"))
    dominant_fp = fps.most_common(1)[0][0] if fps else None
    return {
        "blinded": True,
        "crashing_jobs": crashes,
        "fingerprint": dominant_fp,
        "remedies": list(BLINDING_REMEDIES),
    }


def parse_defined_process_launchers(nm_output: str) -> list[str]:
    """
    The PROCESS_LAUNCH_FUNCTIONS that `nm --defined-only` output defines as global functions, sorted. A
    weak definition with a sanitizer interceptor of the same name is the interceptor, not the target's.
    """
    types: dict[str, str] = {}
    intercepted: set[str] = set()
    for line in (nm_output or "").splitlines():
        m = _NM_LINE_RE.match(line)
        if not m or m.group("type") not in _NM_GLOBAL_FUNCTION_TYPES:
            continue
        name = m.group("name").split("@", 1)[0]
        for prefix in _INTERCEPTOR_PREFIXES:
            if name.startswith(prefix):
                intercepted.add(name[len(prefix) :])
                break
        else:
            if name in PROCESS_LAUNCH_FUNCTIONS:
                types[name] = m.group("type")
    return sorted(name for name, typ in types.items() if typ != "W" or name not in intercepted)


def defined_process_launchers(binary: Path, runner=subprocess.run) -> list[str] | None:
    """
    The process-launch functions (PROCESS_LAUNCH_FUNCTIONS) `binary` defines itself, from `nm
    --defined-only`; None when nm cannot read it (no nm, not an ELF file): unknown, not "none".
    """
    try:
        proc = runner(
            ["nm", "--defined-only", str(binary)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=NM_TIMEOUT_S,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return parse_defined_process_launchers(proc.stdout or "")


def libfuzzer_executed_inputs(output: str) -> bool:
    """Whether libFuzzer's output (the campaign's and its workers' logs) shows at least one input ran."""
    text = output or ""
    for m in _LIBFUZZER_RUNS_RE.finditer(text):
        if int(m.group("done") or m.group("units") or 0) > 0:
            return True
    return bool(_LIBFUZZER_PROGRESS_RE.search(text))


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

    Only a source that holds the skip macro is a dispatch harness a build can skip cases of. Its
    sidecar's count is preferred over the source's switch. Every sidecar records
    `dispatch_case_count`, 0 for a harness that is not a dispatch harness: a count of 0 (or an empty
    case list) means "no dispatch", never a harness with no case, which would put the campaign in
    dispatch rounds and divide by zero on its first crash (benchmark run ab-fc35dev, 2026-11-13).
    """
    for src in sources:
        try:
            text = Path(src).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if DISPATCH_SKIP_MACRO not in text:
            continue
        sidecar_path = _dispatch_sidecar_path(src)
        if sidecar_path.is_file():
            try:
                sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
                for cnt in (
                    sidecar.get("dispatch_case_count"),
                    len(sidecar["api_cases"]) if sidecar.get("api_cases") is not None else None,
                    len(sidecar["dispatch_cases"]) if sidecar.get("dispatch_cases") is not None else None,
                ):
                    if cnt is not None:
                        return int(cnt) if int(cnt) > 0 else None
            except (OSError, ValueError, TypeError):
                pass
        found = dispatch_selector_of_text(text)
        if found:
            return found[1]
    return None


def _dispatch_sidecar_path(src: str | Path) -> Path:
    sidecar_path = Path(src).with_suffix(".json")
    if not sidecar_path.is_file():
        sidecar_path = Path(src).parent / f"harness_{Path(src).stem.removeprefix('harness_')}.json"
    return sidecar_path


def dispatch_selector(sources: Sequence[str | Path]) -> str | None:
    """
    How the dispatch harness among `sources` (the source holding the skip macro, as
    `dispatch_case_count` finds it) maps an input's first byte to a case: `identity` or `modulo`
    (generate_harness.dispatch_selector_of: the sidecar's `dispatch_selector`, a sidecar without it is
    modulo; without a readable sidecar, the harness text). None when no source is such a harness.
    """
    for src in sources:
        try:
            text = Path(src).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if DISPATCH_SKIP_MACRO not in text:
            continue
        sidecar: dict | None = None
        sidecar_path = _dispatch_sidecar_path(src)
        if sidecar_path.is_file():
            try:
                loaded = json.loads(sidecar_path.read_text(encoding="utf-8"))
                sidecar = loaded if isinstance(loaded, dict) else None
            except (OSError, ValueError):
                sidecar = None
        return dispatch_selector_of(sidecar, text)
    return None


HARNESS_IDENTITY_FIELDS = ("harness_digest", "dispatch_case_count")


def campaign_harness_identity(module: str, sources: Sequence[str | Path], run_dir: Path = Path(".")) -> dict:
    """
    The identity of the harness a campaign fuzzes, stamped on its report and on every artifact it finds:

    - `harness_digest`: `phase0_gates.harness_digest(run_dir, module, ignore_exempt=True)`, as the
      dynamic reach gate computes it, or None when the run has no harness for `module` or the campaign
      does not fuzz it (none of `sources` is `workspace/harnesses/harness_<module>.c`, e.g. a breaker's
      own copy);
    - `dispatch_case_count`: the case count a dispatch harness selects with (`dispatch_case_count`),
      None for any other harness;
    - `dispatch_selector`: how its first byte selects a case (`dispatch_selector`: `identity`, or
      `modulo` for a harness generated before the identity selector, where the same file selects
      another case under another count), None for any other harness. Not part of
      HARNESS_IDENTITY_FIELDS: an artifact without it was found under the modulo selector.
    """
    digest: str | None = None
    if module:
        import phase0_gates  # imported lazily: campaigns outside a run directory do not need it

        own = (Path(run_dir) / phase0_gates.HARNESS_DIR / f"harness_{module}.c").resolve()
        if any(Path(src).resolve() == own for src in sources):
            try:
                digest = phase0_gates.harness_digest(Path(run_dir), module, ignore_exempt=True)
            except OSError:
                digest = None
    n_cases = dispatch_case_count([str(s) for s in sources])
    return {
        "harness_digest": digest,
        "dispatch_case_count": n_cases,
        "dispatch_selector": dispatch_selector(sources) if n_cases is not None else None,
    }


def stamp_harness_identity(report: dict, identity: dict, prior: dict | None = None) -> dict:
    """
    Stamp `identity` (campaign_harness_identity) on a campaign `report` and on each artifact it lists. An
    artifact this campaign found gets the campaign's values. One carried over from an earlier campaign
    (`pre_existing`) keeps the values the `prior` report recorded for the same sha256, or gets none: its
    harness is unknown, and the reach gate never credits an artifact of a stamped report without them.
    """
    # The selector encoding travels with the identity, but its absence means `modulo` (an artifact
    # stamped before it existed), never "unknown harness".
    fields = (*HARNESS_IDENTITY_FIELDS, "dispatch_selector")
    report.update({k: identity.get(k) for k in fields if k in HARNESS_IDENTITY_FIELDS or identity.get(k)})
    earlier: dict[str, dict] = {}
    prior_arts = prior.get("artifacts") if isinstance(prior, dict) else None
    for art in prior_arts if isinstance(prior_arts, list) else []:
        if isinstance(art, dict) and art.get("sha256") and all(k in art for k in HARNESS_IDENTITY_FIELDS):
            earlier.setdefault(str(art["sha256"]), {k: art[k] for k in fields if k in art})
    for art in report.get("artifacts") or []:
        if not isinstance(art, dict):
            continue
        if not art.get("pre_existing"):
            for k in fields:
                if k in HARNESS_IDENTITY_FIELDS or identity.get(k):
                    art.setdefault(k, identity.get(k))
        elif all(k in art for k in HARNESS_IDENTITY_FIELDS):
            continue
        elif str(art.get("sha256") or "") in earlier:
            art.update(earlier[str(art["sha256"])])
    return report


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


def format_skip_cases_env(cases: Iterable[int]) -> str:
    """Comma-separated sorted non-negative case indices for `FRAMAC_FUZZ_SKIP_CASES`."""
    return ",".join(str(c) for c in sorted({int(c) for c in cases if int(c) >= 0}))


def harness_supports_runtime_skip_cases(sources: Sequence[str | Path] | str | Path | None) -> bool:
    """
    True when at least one harness source in `sources` carries `DISPATCH_RUNTIME_SKIP_MARKER`
    (from `templates/harness_dual.c.template`), calls `DISPATCH_SKIP_FN`, and has a dispatch switch,
    so campaign rounds can skip crashed cases via `FRAMAC_FUZZ_SKIP_CASES` in the environment
    without recompiling.
    """
    if sources is None:
        return False
    items: Sequence[str | Path] = [sources] if isinstance(sources, (str, Path)) else sources
    for src in items:
        try:
            text = Path(src).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if DISPATCH_RUNTIME_SKIP_MARKER in text and DISPATCH_SKIP_FN in text and _DISPATCH_SWITCH_RE.search(text):
            return True
    return False


def artifact_dispatch_case(artifact: dict, n_cases: int, selector: str = DISPATCH_SELECTOR_MODULO) -> int | None:
    """
    The dispatch case an artifact's input selects under `selector` (generate_harness.dispatch_case_of_bytes:
    the first byte for `identity`, the first two bytes little-endian for `identity16`, the first byte
    modulo `n_cases` for `modulo`), or None for an input shorter than the selector or one the harness
    rejects.
    """
    if n_cases <= 0:
        return None
    try:
        with open(artifact["artifact"], "rb") as fh:
            prefix = fh.read(dispatch_selector_width(selector))
    except (OSError, KeyError):
        return None
    return dispatch_case_of_bytes(prefix, n_cases, selector)


def run_campaign_rounds(
    binary: Path,
    max_time: int,
    *,
    campaign,
    rebuild,
    n_cases: int | None,
    keep_going: bool = True,
    skippable: int | None = None,
    runtime_skip: bool = False,
    selector: str = DISPATCH_SELECTOR_MODULO,
    workers: int = 1,
    initial_skipped: Iterable[int] | None = None,
    explore_judge: bool | None = None,
    blinding_threshold: int = BLINDING_CASE_THRESHOLD,
    fork_blinding_threshold: int = BLINDING_FORK_JOBS_THRESHOLD,
    build_s: float = 0.0,
    pre_blinded_cases: Sequence[dict[str, Any]] | None = None,
    smoke_skipped_cases: Sequence[int] | None = None,
) -> dict:
    """
    A campaign that keeps going after a crash, within `max_time` wall seconds of fuzzing in all, which
    is `max_time * workers` CPU-seconds. A crash's
    case is its input's first byte decoded with the harness's `selector` (`dispatch_selector`).

    `campaign(binary, max_time, fork)` runs one libFuzzer campaign (run_fuzz_campaign) and
    `rebuild(mask)` returns (binary, build record) for a build skipping the dispatch cases set in
    `mask`, binary None when the build failed. When `runtime_skip` is True, `campaign` is called with
    `extra_env={FRAMAC_FUZZ_SKIP_CASES: ...}` on the existing `binary` and `rebuild` is never called.

    P1c pure execution timing: when a round's result carries `fuzz_s` (measured strictly around
    the libFuzzer subprocess, excluding post-exit replay and attribution), only `fuzz_s` is charged
    against the round budget `max_time`. `telemetry` records `{build_s, fuzz_s, replay_s, ...}`.

    When `explore_judge` is enabled (via `FRAMAC_FUZZ_EXPLORE_JUDGE` or explicit `explore_judge=True`):
    - Dispatch harnesses track per-case blinding (`K_case = 16` consecutive crashes with 0 passes
      on one fingerprint), adding blinded cases to `FRAMAC_FUZZ_SKIP_CASES` so healthy cases
      continue (`status: "partial_blinded"` or `"blinded"` when all active cases blind).
    - Non-dispatch fork mode stops early as `blinded` at `64` crashing jobs with `corp == 0` and
      `0` passing executions, recording remaining budget as `unspent_budget_s`.
    """
    eff_explore_judge = resources.fuzz_explore_judge_enabled() if explore_judge is None else bool(explore_judge)
    smoke_list = sorted({int(c) for c in (smoke_skipped_cases or []) if int(c) >= 0})

    def _strip_private(doc: dict[str, Any]) -> dict[str, Any]:
        doc.pop("_raw_crashes", None)
        doc.pop("_case_passes", None)
        return doc

    if not keep_going:
        res = _strip_private(dict(campaign(binary, max_time, False)))
        if smoke_list:
            res["smoke_skipped_cases"] = smoke_list
        return res

    if not n_cases:
        if not eff_explore_judge:
            res = _strip_private(dict(campaign(binary, max_time, True)))
            res["keep_going"] = {"mode": "fork"}
            if res.get("single_process_reason"):
                res["keep_going"]["single_process_reason"] = res["single_process_reason"]
                res["keep_going"]["stops_at_first_crash"] = True
            if isinstance(res.get("telemetry"), dict):
                res["telemetry"] = merge_telemetry([res["telemetry"]], build_s=build_s)
            return res

        # P1a non-dispatch fork mode under FRAMAC_FUZZ_EXPLORE_JUDGE: probe briefly on long runs
        # so an immediately blinded binary (64+ crashing jobs, corp == 0, 0 passing execs) stops
        # early instead of burning its entire budget.
        probe_budget = min(max_time, FORK_BLIND_PROBE_S) if max_time > FORK_BLIND_PROBE_S else max_time
        t0 = time.monotonic()
        first = campaign(binary, probe_budget, True)
        wall1 = max(0.0, time.monotonic() - t0)
        spent1 = float(first["fuzz_s"]) if isinstance(first.get("fuzz_s"), (int, float)) else wall1
        eff_w = 1 if first.get("single_process_reason") else max(1, workers)
        blind_info = detect_fork_blinding(
            first.get("telemetry"),
            first.get("artifacts") or [],
            threshold=fork_blinding_threshold,
        )
        if blind_info is not None:
            out = _strip_private(dict(first))
            out["status"] = "blinded"
            out["partial_blinded"] = False
            out["blinded_fingerprint"] = blind_info.get("fingerprint")
            out["blinded_remedies"] = list(blind_info.get("remedies") or BLINDING_REMEDIES)
            out["unspent_budget_s"] = round(max(0.0, max_time - spent1) * eff_w, 3)
            out["keep_going"] = {
                "mode": "fork",
                "stopped": "blinded",
                "fuzz_seconds": round(spent1, 1),
                "workers": eff_w,
                "cpu_seconds_spent": round(spent1 * eff_w, 1),
            }
            if out.get("single_process_reason"):
                out["keep_going"]["single_process_reason"] = out["single_process_reason"]
                out["keep_going"]["stops_at_first_crash"] = True
            if isinstance(out.get("telemetry"), dict):
                out["telemetry"] = merge_telemetry([out["telemetry"]], build_s=build_s)
            return out

        rem_wall = int(max_time - spent1)
        if (
            probe_budget < max_time
            and rem_wall >= 1
            and (max_time - spent1) * eff_w >= MIN_ROUND_CPU_S
            and first.get("status") != "insufficient_memory"
        ):
            t1 = time.monotonic()
            second = campaign(binary, rem_wall, True)
            wall2 = max(0.0, time.monotonic() - t1)
            spent2 = float(second["fuzz_s"]) if isinstance(second.get("fuzz_s"), (int, float)) else wall2
            total_spent = spent1 + spent2
            combined_arts: list[dict] = []
            seen_keys: set[str] = set()
            for a in [*(first.get("artifacts") or []), *(second.get("artifacts") or [])]:
                key = str(a.get("sha256") or a.get("artifact") or "")
                if key not in seen_keys:
                    seen_keys.add(key)
                    combined_arts.append(a)
            merged_arts, dropped_dups = _collapse_duplicate_artifacts(combined_arts)
            merged_tel = merge_telemetry([first.get("telemetry"), second.get("telemetry")], build_s=build_s)
            out = _strip_private(dict(second))
            out["artifacts"] = merged_arts
            out["telemetry"] = merged_tel
            out["fuzz_s"] = round(total_spent, 3)
            out["replay_s"] = round(float(first.get("replay_s") or 0.0) + float(second.get("replay_s") or 0.0), 3)
            if dropped_dups:
                omitted = dict(out.get("artifacts_omitted") or {})
                omitted["duplicates"] = omitted.get("duplicates", 0) + dropped_dups
                out["artifacts_omitted"] = omitted
            blind2 = detect_fork_blinding(merged_tel, merged_arts, threshold=fork_blinding_threshold)
            if blind2 is not None:
                out["status"] = "blinded"
                out["partial_blinded"] = False
                out["blinded_fingerprint"] = blind2.get("fingerprint")
                out["blinded_remedies"] = list(blind2.get("remedies") or BLINDING_REMEDIES)
                out["unspent_budget_s"] = round(max(0.0, max_time - total_spent) * eff_w, 3)
                out["keep_going"] = {"mode": "fork", "stopped": "blinded"}
            else:
                if out.get("status") != "insufficient_memory":
                    out["status"] = classify_campaign(
                        out.get("returncode") or 0, bool(out.get("timed_out")), merged_arts
                    )
                out["keep_going"] = {"mode": "fork"}
            if out.get("single_process_reason"):
                out["keep_going"]["single_process_reason"] = out["single_process_reason"]
                out["keep_going"]["stops_at_first_crash"] = True
            return out

        res = _strip_private(dict(first))
        res["keep_going"] = {"mode": "fork"}
        if res.get("single_process_reason"):
            res["keep_going"]["single_process_reason"] = res["single_process_reason"]
            res["keep_going"]["stops_at_first_crash"] = True
        if isinstance(res.get("telemetry"), dict):
            res["telemetry"] = merge_telemetry([res["telemetry"]], build_s=build_s)
        return res

    skippable = n_cases if skippable is None else min(skippable, n_cases)
    if runtime_skip:
        skippable = min(skippable, DISPATCH_RUNTIME_SKIP_MAX_CASES)

    skipped: set[int] = {int(c) for c in (initial_skipped or []) if 0 <= int(c) < n_cases}
    skipped.update(c for c in smoke_list if 0 <= c < n_cases)
    tracker = CaseBlindingTracker(threshold=blinding_threshold)
    for entry in pre_blinded_cases or []:
        if isinstance(entry, dict) and isinstance(entry.get("case"), int):
            c_idx = int(entry["case"])
            if 0 <= c_idx < n_cases:
                tracker.mark_blinded(c_idx, entry.get("fingerprint"), entry.get("crashes"))
                skipped.add(c_idx)

    rounds: list[dict] = []
    collected: list[dict] = []
    telemetries: list[dict[str, Any]] = []
    spent = 0.0
    total_replay_s = 0.0
    total_rebuild_s = 0.0
    last: dict = {}
    fallback_reason: str | None = None
    skip_error: str | None = None
    single_process_reason: str | None = None

    def _record_round_blinding(result: dict) -> list[int]:
        if not eff_explore_judge:
            return []
        newly_blinded: list[int] = []
        raw_crashes = result.get("_raw_crashes")
        crash_records = raw_crashes if isinstance(raw_crashes, list) else (result.get("artifacts") or [])
        # When a round reports passing executions for cases that didn't crash, or an explicit
        # per-case pass map, keep healthy cases from blinding.
        case_passes = result.get("_case_passes")
        if isinstance(case_passes, dict):
            for c_key, p_cnt in case_passes.items():
                if int(p_cnt or 0) > 0:
                    tracker.record_pass(int(c_key))
        for rec in crash_records:
            if not isinstance(rec, dict) or rec.get("pre_existing"):
                continue
            if rec.get("kind") not in ("crash", "leak", "timeout", "oom"):
                continue
            c = rec.get("case")
            if not isinstance(c, int):
                c = artifact_dispatch_case(rec, n_cases, selector)
            if c is None or not (0 <= c < n_cases):
                continue
            if tracker.record_crash(c, rec.get("fingerprint")):
                newly_blinded.append(c)
        return sorted(set(newly_blinded))

    # If every case is already skipped before round 1 (e.g. smoke + floor pass skipped all cases):
    if len(skipped) >= n_cases:
        out_empty: dict[str, Any] = {
            "status": "clean",
            "returncode": 0,
            "timed_out": False,
            "artifacts": [],
            "keep_going": {
                "mode": "dispatch_rounds",
                "dispatch_cases": n_cases,
                "dispatch_selector": selector,
                "skippable_cases": skippable,
                "skipped_cases": sorted(skipped),
                "fuzz_seconds": 0.0,
                "workers": max(1, workers),
                "cpu_seconds_spent": 0.0,
                "stopped": "every_case_skipped",
                "rounds": [],
            },
            "telemetry": merge_telemetry([], build_s=build_s),
        }
        if runtime_skip:
            out_empty["keep_going"]["runtime_skip"] = True
        if smoke_list:
            out_empty["smoke_skipped_cases"] = smoke_list
        if eff_explore_judge:
            blinded_rep = tracker.blinded_cases_report()
            if blinded_rep:
                active_cases = max(0, n_cases - len(set(smoke_list)))
                all_blind = active_cases > 0 and len(tracker.blinded_case_ids()) >= active_cases
                out_empty["blinded_cases"] = blinded_rep
                out_empty["partial_blinded"] = not all_blind
                out_empty["status"] = "blinded" if all_blind else "partial_blinded"
                out_empty["blinded_remedies"] = list(BLINDING_REMEDIES)
        return out_empty

    while True:
        # A round never runs longer than the wall time the campaign has left. The first round always runs.
        budget = max(1, int(max_time - spent)) if not rounds else int(max_time - spent)
        started = time.monotonic()
        if runtime_skip:
            skip_env = {DISPATCH_SKIP_MACRO: format_skip_cases_env(skipped)} if skipped else None
            last = campaign(binary, budget, False, extra_env=skip_env)
        else:
            last = campaign(binary, budget, False)
        wall_elapsed = max(0.0, time.monotonic() - started)
        # P1c: charge ONLY libFuzzer execution time (`fuzz_s`) when reported, never replay/attribution time.
        round_fuzz_s = float(last["fuzz_s"]) if isinstance(last.get("fuzz_s"), (int, float)) else wall_elapsed
        spent += max(0.0, round_fuzz_s)
        total_replay_s += max(0.0, float(last.get("replay_s") or 0.0))
        if isinstance(last.get("telemetry"), dict):
            telemetries.append(last["telemetry"])
        else:
            telemetries.append(
                parse_libfuzzer_telemetry(
                    str(last.get("log_tail") or ""),
                    fuzz_s=round_fuzz_s,
                    replay_s=float(last.get("replay_s") or 0.0),
                )
            )
        single_process_reason = single_process_reason or last.get("single_process_reason")
        if single_process_reason:
            workers = 1
        newly_blinded = _record_round_blinding(last)
        arts = last.get("artifacts") or []
        collected.extend(arts)
        crashed = sorted(
            {
                c
                for a in arts
                if a.get("kind") in ("crash", "leak", "timeout", "oom") and not a.get("pre_existing")
                for c in [artifact_dispatch_case(a, n_cases, selector)]
                if c is not None
            }
        )
        rnd: dict[str, Any] = {
            "skipped_cases": sorted(skipped),
            "max_time": budget,
            "status": last.get("status"),
            "returncode": last.get("returncode"),
            "artifacts": len(arts),
            "crashed_cases": crashed,
        }
        if newly_blinded:
            rnd["blinded_cases"] = newly_blinded
        rounds.append(rnd)
        if in_skipped := [c for c in crashed if c in skipped]:
            # The round ran with these cases skipped and an input still crashed in one: the skip did
            # not take (runtime skip without a visible environment), or the crash is in harness code
            # every case runs. Another round would find the same crash again.
            rnd["stopped"] = "crash_in_skipped_case"
            rnd["skipped_crashed_cases"] = in_skipped
            skip_error = (
                f"round {len(rounds)} crashed in skipped case{'s' if len(in_skipped) > 1 else ''} "
                f"{', '.join(map(str, in_skipped))}"
                f" ({'FRAMAC_FUZZ_SKIP_CASES in the environment' if runtime_skip else 'skip rebuild'}"
                "): the cases were not skipped, or the crash is in harness code before the dispatch"
            )
            break
        fresh = [c for c in crashed if c not in skipped]
        new = [c for c in fresh if c < skippable]
        if last.get("status") == "insufficient_memory":
            rnd["stopped"] = "insufficient_memory"
            break
        if not fresh:
            rnd["stopped"] = "no_new_case"
            break
        # The next round needs the CPU floor and at least one whole second of wall time left.
        if (max_time - spent) * max(1, workers) < MIN_ROUND_CPU_S or int(max_time - spent) < 1:
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
        if not runtime_skip:
            mask = sum(1 << c for c in skipped)
            rb_t0 = time.perf_counter()
            next_binary, build = rebuild(mask)
            total_rebuild_s += max(0.0, time.perf_counter() - rb_t0)
            if next_binary is None:
                comp = (build or {}).get("compile") or {}
                rnd["stopped"] = fallback_reason = "rebuild_failed"
                rnd["rebuild_log_tail"] = str(comp.get("log_tail") or comp.get("stderr") or "")[-2000:]
                break
            binary = next_binary

    fallback: dict | None = None
    left = int(max_time - spent)
    if fallback_reason and left >= 1 and (max_time - spent) * max(1, workers) >= MIN_ROUND_CPU_S:
        # The cases still crashing cannot be skipped: the time left goes to fork mode, which keeps
        # fuzzing past each crash, on the last binary built (its skipped cases stay skipped).
        started = time.monotonic()
        if runtime_skip:
            skip_env = {DISPATCH_SKIP_MACRO: format_skip_cases_env(skipped)} if skipped else None
            last = campaign(binary, left, True, extra_env=skip_env)
        else:
            last = campaign(binary, left, True)
        wall_elapsed = max(0.0, time.monotonic() - started)
        fb_fuzz_s = float(last["fuzz_s"]) if isinstance(last.get("fuzz_s"), (int, float)) else wall_elapsed
        spent += max(0.0, fb_fuzz_s)
        total_replay_s += max(0.0, float(last.get("replay_s") or 0.0))
        if isinstance(last.get("telemetry"), dict):
            telemetries.append(last["telemetry"])
        single_process_reason = single_process_reason or last.get("single_process_reason")
        if single_process_reason:
            workers = 1
        _record_round_blinding(last)
        arts = last.get("artifacts") or []
        collected.extend(arts)
        fallback = {
            "reason": fallback_reason,
            "max_time": left,
            "status": last.get("status"),
            "returncode": last.get("returncode"),
            "artifacts": len(arts),
        }
        if last.get("single_process_reason"):
            fallback["stops_at_first_crash"] = True

    seen: set[str] = set()
    unique = []
    for a in collected:
        key = str(a.get("sha256") or a.get("artifact") or "")
        if key not in seen:
            seen.add(key)
            unique.append(a)
    merged, dropped = _collapse_duplicate_artifacts(unique)
    out = dict(last)
    out.pop("_raw_crashes", None)
    out.pop("_case_passes", None)
    out["artifacts"] = merged
    if last.get("status") != "insufficient_memory":
        out["status"] = classify_campaign(last.get("returncode") or 0, bool(last.get("timed_out")), merged)
    if dropped:
        omitted = dict(out.get("artifacts_omitted") or {})
        omitted["duplicates"] = omitted.get("duplicates", 0) + dropped
        out["artifacts_omitted"] = omitted
    merged_tel = merge_telemetry(telemetries, build_s=build_s + total_rebuild_s)
    merged_tel["fuzz_s"] = round(spent, 3)
    merged_tel["replay_s"] = round(total_replay_s, 3)
    out["telemetry"] = merged_tel
    out["fuzz_s"] = round(spent, 3)
    out["replay_s"] = round(total_replay_s, 3)
    out["keep_going"] = {
        "mode": "dispatch_rounds",
        "dispatch_cases": n_cases,
        "dispatch_selector": selector,
        "skippable_cases": skippable,
        "skipped_cases": sorted(skipped),
        "fuzz_seconds": round(spent, 1),
        "workers": max(1, workers),
        "cpu_seconds_spent": round(spent * max(1, workers), 1),
        "stopped": rounds[-1].get("stopped"),
        "rounds": rounds,
    }
    if runtime_skip:
        out["keep_going"]["runtime_skip"] = True
    if single_process_reason:
        out["keep_going"]["single_process_reason"] = single_process_reason
    if skip_error:
        # Not ok: the campaign did not fuzz the cases it meant to. The crashes found stay listed (and
        # `status` keeps them for ingest); `error_summary` carries the reason to the reader.
        out["keep_going"].update(status="error", error=skip_error)
        out["error_summary"] = [*(out.get("error_summary") or []), f"keep-going rounds: {skip_error}"]
    if fallback is not None:
        out["keep_going"]["fork_fallback"] = fallback
    if smoke_list:
        out["smoke_skipped_cases"] = smoke_list
    if eff_explore_judge:
        blinded_rep = tracker.blinded_cases_report()
        if blinded_rep and out.get("status") != "insufficient_memory":
            active_cases = max(0, n_cases - len(set(smoke_list)))
            all_blind = active_cases > 0 and len(tracker.blinded_case_ids()) >= active_cases
            out["blinded_cases"] = blinded_rep
            out["partial_blinded"] = not all_blind
            out["status"] = "blinded" if all_blind else "partial_blinded"
            out["blinded_remedies"] = list(BLINDING_REMEDIES)
        else:
            out.setdefault("blinded_cases", [])
            out.setdefault("partial_blinded", False)
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
            for key in (
                "status",
                "returncode",
                "timed_out",
                "keep_going",
                "artifacts_omitted",
                "fork",
                "single_process_reason",
                "multi_process_attempt",
                "telemetry",
            )
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
    merged: dict[str, Any] = {
        "status": status,
        "returncode": last.get("returncode"),
        "timed_out": any(bool(r.get("timed_out")) for r in runs.values()),
        "sandbox": last.get("sandbox"),
        "artifacts": artifacts,
        "engines": engines,
        "log_tail": "\n".join(f"--- {e}\n{(r.get('log_tail') or '')[-2000:]}" for e, r in runs.items()),
    }
    tels = [r.get("telemetry") for r in runs.values() if isinstance(r.get("telemetry"), dict)]
    if tels:
        merged["telemetry"] = merge_telemetry(tels)
    if errors := [f"{engine}: {e}" for engine, run in runs.items() for e in run.get("error_summary") or []]:
        merged["error_summary"] = errors
    # An engine that did not run to completion stays visible even when another engine's crash is the
    # merged status (F9): ledger ingest reads this, not only the status.
    if engine_errors := {
        engine: {
            "status": "fuzzer_error",
            "reason": "; ".join(str(e) for e in run.get("error_summary") or [])
            or f"returncode {run.get('returncode')}",
        }
        for engine, run in runs.items()
        if run.get("status") == "fuzzer_error"
    }:
        merged["engine_errors"] = engine_errors
    return merged


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
    per_input_timeout: int = DEFAULT_PER_INPUT_TIMEOUT_S,
    rss_limit_mb: int = FUZZ_RSS_LIMIT_MB,
    extra_corpus: list[Path] | None = None,
    attribution_builder=None,
    jobs: int = 1,
    workers: int = 1,
    fork: bool = False,
    extra_env: dict[str, str] | None = None,
    single_process_reason: str | None = None,
    runs: int | None = None,
    seed: int | None = None,
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

    A multi-process campaign (`fork`, or more than one job or worker) runs in one process instead,
    with `-print_funcs=0`, when:
      - `single_process_reason` is given (an earlier round of the same engine ran in one process);
      - the binary defines a process-launch function (PROCESS_LAUNCH_FUNCTIONS, `nm`): libFuzzer
        starts its processes through system(), which the target replaced;
      - it ends `fuzzer_error` with no artifact and no input run (the workers never started: a
        replaced launcher nm did not see, or a seccomp filter denying execve as sudo_noexec.c's
        constructor installs). It is then rerun once in one process; `multi_process_attempt` keeps
        the first attempt's returncode and log tail.
    The result then says why (`single_process_reason`) and `workers_used: 1`. NEW_FUNC lines are
    turned off because libFuzzer symbolizes them through a child process, which such a target can
    deny (sudo_noexec_so died of SIGPIPE at its first NEW_FUNC line).
    """
    common = {
        "dict_file": dict_file,
        "per_input_timeout": per_input_timeout,
        "rss_limit_mb": rss_limit_mb,
        "extra_corpus": extra_corpus,
        "attribution_builder": attribution_builder,
        "extra_env": extra_env,
        "runs": runs,
        "seed": seed,
    }
    multi = fork or max(1, int(workers or 1)) > 1 or max(1, int(jobs or 1)) > 1
    reason = single_process_reason if multi else None
    if multi and reason is None:
        launchers = defined_process_launchers(binary)
        if launchers:
            reason = (
                f"the binary defines {', '.join(launchers)}, replacing libc's in the whole process: libFuzzer "
                "starts its -jobs/-workers/-fork processes through system(), so the campaign runs in one process"
            )
    if reason is not None:
        out = _run_fuzz_campaign_once(binary, corpus_dir, artifacts_dir, max_time, **common, print_funcs=False)
        return _single_process_result(out, reason)
    out = _run_fuzz_campaign_once(
        binary, corpus_dir, artifacts_dir, max_time, **common, jobs=jobs, workers=workers, fork=fork
    )
    executed = out.pop("_executed_inputs", True)
    if not multi or out.get("status") != "fuzzer_error" or out.get("artifacts") or out.get("timed_out") or executed:
        return out
    eff_workers = max(1, int(workers or 1), int(jobs or 1))
    mode = f"-fork={eff_workers}" if fork else f"-jobs/-workers={eff_workers}"
    reason = (
        f"the multi-process campaign ({mode}) ended with returncode {out.get('returncode')} before any input ran: "
        "its worker processes did not start (a target that replaces system()/exec*, or a seccomp filter "
        "denying execve), so it was rerun in one process"
    )
    attempt = {"returncode": out.get("returncode"), "log_tail": str(out.get("log_tail") or "")[-1500:]}
    retry = _single_process_result(
        _run_fuzz_campaign_once(binary, corpus_dir, artifacts_dir, max_time, **common, print_funcs=False), reason
    )
    retry["multi_process_attempt"] = attempt
    if retry.get("status") == "fuzzer_error":
        retry["error_summary"] = [
            *(retry.get("error_summary") or []),
            "no input ran in the multi-process campaign nor in its single-process rerun: the binary fails "
            "before fuzzing, not only its worker processes",
        ]
    return retry


def _single_process_result(out: dict, reason: str) -> dict:
    out.pop("_executed_inputs", None)
    out["single_process_reason"] = reason
    out["workers_used"] = 1
    return out


def _run_fuzz_campaign_once(
    binary: Path,
    corpus_dir: Path,
    artifacts_dir: Path,
    max_time: int,
    dict_file: Path | None,
    per_input_timeout: int,
    rss_limit_mb: int,
    extra_corpus: list[Path] | None,
    attribution_builder,
    extra_env: dict[str, str] | None,
    jobs: int = 1,
    workers: int = 1,
    fork: bool = False,
    print_funcs: bool = True,
    runs: int | None = None,
    seed: int | None = None,
) -> dict:
    """One libFuzzer campaign as run_fuzz_campaign describes; `_executed_inputs` says whether any input ran."""
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
        if runs is not None and runs >= 0:
            cmd.insert(-1, f"-runs={int(runs)}")
        if seed is not None:
            cmd.insert(-1, f"-seed={int(seed)}")
        if not print_funcs:
            cmd.insert(-1, "-print_funcs=0")
        cmd += [str(Path(d).resolve()) for d in (extra_corpus or []) if Path(d).is_dir()]
        eff_jobs = max(1, int(jobs or 1))
        eff_workers = max(1, int(workers or 1))
        if eff_workers > 1 and eff_jobs == 1:
            eff_jobs = eff_workers
        elif eff_jobs > 1 and eff_workers == 1:
            eff_workers = eff_jobs

        run_env = dict(SANITIZER_RUNTIME_ENV)
        if extra_env:
            run_env.update(extra_env)
        if fork:
            # Fork mode keeps its per-job directories under TMPDIR; keep them in the scratch.
            cmd[1:1] = [f"-fork={eff_workers}", "-ignore_crashes=1"]
            run_env["TMPDIR"] = str(scratch.resolve())
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
        oom_before = resources.read_cgroup_oom_kills() if resources.fuzz_explore_judge_enabled() else None
        fuzz_started = time.monotonic()
        res = sandbox_exec.run_sandboxed(
            cmd,
            writable=[scratch, corpus_dir, artifacts_dir],
            timeout_s=wall_timeout,
            limits=Limits(cpu_seconds=wall_timeout * cpu_mult, ignore_sigpipe=True),
            extra_env=run_env,
        )
        fuzz_s = max(0.0, time.monotonic() - fuzz_started)
        oom_after = resources.read_cgroup_oom_kills() if oom_before is not None else None
        oom_delta = max(0, oom_after - oom_before) if (oom_before is not None and oom_after is not None) else None
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

        replay_started = time.monotonic()
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
            # An `oom-` input is replayed like a crash (mpack run-4: one never was, and kept no outcome).
            # Past the replay budget it is still listed, unreplayed, as before: only crashes and leaks are dropped.
            replay_it = kind in ("crash", "leak", "oom")
            if replay_it:
                if replayed >= MAX_REPLAYED_CRASHES:
                    replay_it = False
                    if kind != "oom":
                        unreplayed += 1
                        continue
                else:
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
            if replay_it:
                replay = crash_replay.replay_artifact(binary, p, scratch, per_input_timeout=per_input_timeout)
                # The campaign log names one failure; it can only stand for this input if it is the only one.
                # Never for an oom: libFuzzer's out-of-memory is no parsed failure, and an E-ACSL heap-limit
                # abort ends its input as a deadly signal (crash-), so the log's failure or abort is another input's.
                from_log = crash_like == 1 and kind != "oom"
                stub_abort = replay.get("link_stub_abort") or (
                    parse_link_stub_abort(combined_out) if from_log else None
                )
                failure = (
                    None
                    if stub_abort
                    else (replay["failure"] or (parse_runtime_failure(combined_out) if from_log else None))
                )
                entry["reproducible"] = replay["reproduced"]
                entry["replay_log_tail"] = replay["log_tail"]
                entry["frames"] = replay.get("frames") or []
                entry["failure_source"] = "primary" if failure else None
                if not stub_abort and needs_attribution(failure):
                    san_bin = _attribution_binary()
                    if san_bin is not None:
                        san_replay = crash_replay.replay_artifact(
                            Path(san_bin), p, scratch, per_input_timeout=per_input_timeout
                        )
                        entry["attribution"] = {
                            "source": "sanitizer_replay",
                            "binary": str(san_bin),
                            "reproduced": san_replay["reproduced"],
                            "failure": san_replay["failure"],
                            "out_of_memory": bool(san_replay.get("out_of_memory")),
                        }
                        if san_replay.get("link_stub_abort"):
                            stub_abort = san_replay["link_stub_abort"]
                            failure = None
                        elif san_replay["failure"] and not needs_attribution(san_replay["failure"]):
                            failure = san_replay["failure"]
                            entry["failure_source"] = "sanitizer_replay"
                entry["failure"] = failure
                if stub_abort is not None:
                    entry["link_stub_abort"] = stub_abort
                elif not failure:
                    # The E-ACSL runtime stopped on its own limit (its tracked heap zone): no target
                    # check failed. Kept as a crash artifact so keep-going skips its case like any
                    # other, but marked, so ingest makes no candidate of it (ledger.cmd_ingest_fuzz).
                    abort = replay.get("resource_abort") or (
                        parse_eacsl_resource_abort(combined_out) if from_log else None
                    )
                    attribution = entry.get("attribution")
                    record = (
                        crash_replay.resource_abort_record(
                            abort, attribution if isinstance(attribution, dict) else None, kind
                        )
                        if abort
                        else None
                    )
                    if record is not None:
                        entry["eacsl_resource_abort"] = record
                if failure:
                    entry["fingerprint"] = make_fingerprint(
                        failure["file"],
                        failure["function"],
                        failure["alarm_kind"] or failure["kind"],
                        failure["predicate"],
                    )
            artifacts.append(entry)
        replay_s = max(0.0, time.monotonic() - replay_started)

        raw_crashes = [
            {
                "artifact": a.get("artifact"),
                "kind": a.get("kind"),
                "fingerprint": a.get("fingerprint"),
                "pre_existing": bool(a.get("pre_existing")),
            }
            for a in artifacts
        ]
        # P7d: if container OOM kills increased during libFuzzer execution, drop artifacts lacking
        # any parsed failure or libFuzzer OOM/sanitizer report so container kills never become findings.
        container_oom_dropped = 0
        if oom_delta and oom_delta > 0:
            kept_after_oom: list[dict] = []
            for a in artifacts:
                if a.get("failure") is None and a.get("kind") != "oom" and not a.get("link_stub_abort"):
                    container_oom_dropped += 1
                    continue
                kept_after_oom.append(a)
            artifacts = kept_after_oom

        artifacts, omitted = _collapse_duplicate_artifacts(artifacts)
        status = classify_campaign(res.returncode, res.timed_out, artifacts)
        if oom_delta and oom_delta > 0 and container_oom_dropped > 0 and status in ("fuzzer_error", "clean"):
            status = "container_oom"

        telemetry_streams = [f"{res.stdout}\n{res.stderr}", *worker_logs]
        telemetry = parse_libfuzzer_telemetry(
            telemetry_streams,
            build_s=0.0,
            fuzz_s=fuzz_s,
            replay_s=replay_s,
            oom_kills_delta=oom_delta,
        )
        out: dict[str, Any] = {
            "status": status,
            "returncode": res.returncode,
            "timed_out": res.timed_out,
            "sandbox": res.sandbox,
            "artifacts": artifacts,
            "fuzz_s": round(fuzz_s, 3),
            "replay_s": round(replay_s, 3),
            "telemetry": telemetry,
            "log_tail": combined_out[-4000:],
            "_executed_inputs": libfuzzer_executed_inputs(combined_out),
            "_raw_crashes": raw_crashes,
        }
        if fork:
            out["fork"] = eff_workers
        if omitted or unreplayed:
            out["artifacts_omitted"] = {"duplicates": omitted, "not_replayed": unreplayed}
        return out
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


_COVERAGE_LINE_RE = re.compile(
    r"^(?:UN)?COVERED_FUNC: hits: (\d+) edges: \d+/\d+ (\S+) .*$|^COVERAGE:\s*$|^stat::number_of_executed_units: (\d+)\s*$"
    r"|^[ \t]*UNCOVERED_PC: .*$",
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
    return reach, re.sub(r"\n{2,}", "\n", _COVERAGE_LINE_RE.sub("", output or ""))


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
    if (stub_abort := parse_link_stub_abort(output)) is not None:
        return {
            "status": "guardrail_error",
            "reason": (
                f"Guardrail binary hit address-flow link stub {stub_abort['symbol']} "
                f"(caller: {stub_abort.get('caller') or 'unknown'}): pipeline reach defect, not a contract violation."
            ),
            "failure": None,
            "link_stub_abort": stub_abort,
        }
    failure = parse_eacsl_failure(output)
    if failure is None and (abort := parse_eacsl_resource_abort(output)):
        return {
            "status": "guardrail_error",
            "reason": (
                f"The E-ACSL runtime stopped on its own {abort['resource']} limit ({abort['message']}): "
                "no check failed, so this says nothing about the contract."
            ),
            "failure": None,
            "eacsl_resource_abort": abort,
        }
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


# Part of the verdict cache key: raise it when the fields a guardrail verdict carries change, so that a
# verdict stored without them is not returned. (2: the dynamic_oracle_fields.)
GUARDRAIL_VERDICT_FIELDS = 2
MAX_HINTED_UNCHECKED_CLAUSES = 5
_UNCHECKED_HINT_STATUSES = ("passed_dynamic_oracle", "rejected_overconstrained", "compile_error", "guardrail_error")


def dynamic_oracle_fields(ignored: list[dict] | None, checked: list[str] | None) -> dict:
    """
    What a guardrail run could not have executed, from its build's `ignored_annotations`
    (eacsl_toolchain.attribute_ignored_annotations) and the functions it checks:

      ignored_annotations                  the build's list, unchanged
      unchecked_clauses                    the clauses of the checked functions E-ACSL generated no check
                                           for: {function, kind, label, clause, file, line, reason, via}
      dynamic_oracle_incomplete            True when `unchecked_clauses` is not empty
      dynamic_oracle_incomplete_functions  the functions that have one, sorted
      unattributed_ignored_annotations     the ignored annotations no function could be read for

    An ignored annotation counts against a function only when E-ACSL reported it inside a declaration
    of that function (its contract, on the definition or on a prototype, or its body), or when a
    clause of that function uses, directly or through other logic definitions, a `predicate` or
    `logic` E-ACSL reported at its definition; `via` is then the name the clause uses, and `file`,
    `line` and `reason` are those of the definition. Annotations of other functions, and clause kinds
    E-ACSL never executes (`expected_check` false: decreases, terminates, exits), do not count. With
    no checked function named, every function of the build counts. An annotation that cannot be tied
    to a function is listed apart and does not set the flag: nothing is guessed.

    Every value is None when `ignored` is None: the caller has no build report, and the run then does
    not know whether its oracle was complete.
    """
    if ignored is None:
        return {
            "ignored_annotations": None,
            "unchecked_clauses": None,
            "dynamic_oracle_incomplete": None,
            "dynamic_oracle_incomplete_functions": None,
            "unattributed_ignored_annotations": None,
        }
    names = {f.strip() for f in checked or [] if f and f.strip()}
    unchecked: list[dict] = []
    unattributed: list[dict] = []
    seen: set[tuple] = set()

    def _add(function: str, clause: dict, entry: dict, via: str | None) -> None:
        if names and function not in names:
            return
        item = {
            "function": function,
            "kind": clause.get("kind"),
            "label": clause.get("label") or "",
            "clause": clause.get("text"),
            "file": entry.get("file"),
            "line": entry.get("line"),
            "reason": entry.get("reason"),
            "via": via,
        }
        key = tuple(item[k] for k in ("function", "kind", "label", "clause", "file", "line"))
        if key not in seen:
            seen.add(key)
            unchecked.append(item)

    for entry in ignored:
        if not entry.get("expected_check", True):
            continue
        if entry.get("function"):
            _add(str(entry["function"]), entry.get("clause") or {}, entry, None)
        elif entry.get("used_by"):
            for user in entry["used_by"]:
                _add(str(user.get("function")), user.get("clause") or {}, entry, user.get("via"))
        else:
            unattributed.append(entry)
    return {
        "ignored_annotations": ignored,
        "unchecked_clauses": unchecked,
        "dynamic_oracle_incomplete": bool(unchecked),
        "dynamic_oracle_incomplete_functions": sorted({c["function"] for c in unchecked}),
        "unattributed_ignored_annotations": unattributed,
    }


def _clip(text: object, limit: int) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def unchecked_clause_hints(res: dict) -> list[str]:
    """
    Hints for the clauses E-ACSL did not execute (`unchecked_clauses`, `unattributed_ignored_annotations`):
    which clause of which function, why, and the usual remedy. Nothing for a status that tells the
    prover to leave its contract alone (a code fault, a hang, a failure outside the checked functions).
    """
    if res.get("status") not in _UNCHECKED_HINT_STATUSES:
        return []
    if res.get("replay_hang") or res.get("outside_checked_functions"):
        return []
    hints: list[str] = []
    clauses = res.get("unchecked_clauses") or []
    by_function: dict[str, list[dict]] = {}
    for clause in clauses:
        by_function.setdefault(str(clause.get("function")), []).append(clause)
    for function in sorted(by_function):
        items = by_function[function]
        shown = []
        for c in items[:MAX_HINTED_UNCHECKED_CLAUSES]:
            name = " ".join(p for p in (c.get("kind") or "annotation", c.get("label")) if p)
            text = f": {_clip(c['clause'], 120)}" if c.get("clause") else ""
            where = f"{c.get('file')}:{c.get('line')}"
            if c.get("via"):
                shown.append(
                    f"`{name}`{text}, through `{c['via']}`, which rests on a definition E-ACSL could not "
                    f"translate ({where}: {_clip(c.get('reason'), 200)})"
                )
            else:
                shown.append(f"`{name}`{text} ({where}: {_clip(c.get('reason'), 200)})")
        more = len(items) - len(shown)
        hints.append(
            f"E-ACSL did not execute {len(items)} clause(s) of {function}: {'; '.join(shown)}"
            f"{f'; and {more} more in `unchecked_clauses`' if more > 0 else ''}. E-ACSL warned `Ignoring annotation` "
            "and generated no check for them, so this run is no runtime evidence for them, whatever its status "
            "(`dynamic_oracle_incomplete`)."
        )
    reasons = [str(c.get("reason") or "") for c in clauses]
    if any("quantification" in r for r in reasons):
        hints.append(
            "E-ACSL executes a quantifier only when each bound variable has explicit integer bounds on both sides, "
            "written with '<' or '<=': '\\forall integer k; 0 <= k < n ==> ...'. Give the quantifier (in the clause, "
            "or in the predicate it uses) such bounds and run the guardrail again."
        )
    if any("loop variant using GMP" in r for r in reasons):
        hints.append(
            "E-ACSL executes a loop variant only when it can compute it in a C integer type: it does with 'int' "
            "or 'unsigned int' operands, while a difference of 'size_t' values or a 'logic integer' function "
            "needs GMP and is ignored. The termination of that loop was not checked at runtime: it rests "
            "on the WP proof alone."
        )
    if any("quantification" not in r and "loop variant using GMP" not in r for r in reasons):
        hints.append(
            "A clause E-ACSL cannot execute is covered by the WP proof only: rewrite it with constructs E-ACSL "
            "executes, or keep it and report it as not dynamically checked."
        )
    lost = res.get("unattributed_ignored_annotations") or []
    if lost:
        where = "; ".join(
            f"{e.get('file')}:{e.get('line')} ({e.get('attribution')}): {_clip(e.get('reason'), 160)}"
            for e in lost[:MAX_HINTED_UNCHECKED_CLAUSES]
        )
        hints.append(
            f"E-ACSL ignored {len(lost)} annotation(s) that could not be tied to a function ({where}). "
            "`dynamic_oracle_incomplete` does not count them: read `unattributed_ignored_annotations` and check "
            "whether a clause of the checked function depends on one."
        )
    return hints


def derive_eacsl_diagnostic_hints(res: dict) -> list[str]:
    """
    Generate concise, actionable diagnostic hints for E-ACSL guardrail rejections and
    instrumentation compile errors, and for what a pass did not test: an empty corpus, dropped
    inputs, unreached functions, and the clauses E-ACSL did not execute (unchecked_clause_hints).
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
        hangs = [e for e in res.get("excluded_inputs") or [] if e.get("kind") == "timeout"]
        hung = [str(e.get("input")) for e in hangs]
        if hung:
            meaning = (
                "At least one hang was inside a checked function, so the contract was not tested on that input"
                if any(e.get("in_checked_function") for e in hangs)
                else "A hang outside the checked functions says nothing about this contract"
            )
            passed_hints.append(
                f"{len(hung)} replayed input(s) hung until libFuzzer's per-input timeout and were dropped "
                f"({', '.join(hung)}). {meaning}; the verdict comes from the "
                f"{res.get('corpus_replayed')} input(s) that ran to the end."
            )
        dropped = [e for e in res.get("excluded_inputs") or [] if e.get("failure")]
        if dropped:
            passed_hints.append(
                f"{len(dropped)} replayed input(s) were dropped because a check failed outside the checked "
                f"functions (the first: {dropped[0].get('crash')}). That is a defect candidate or an alarm in "
                "other code, not evidence about this contract; `excluded_inputs` lists each one."
            )
        if res.get("mutations_skipped"):
            passed_hints.append(
                "The mutation burst was skipped: a mutated input crashed outside the checked functions "
                f"({res['mutations_skipped'].get('crash')}), which says nothing about this contract. "
                "This pass replayed the corpus only."
            )
        unreached = (res.get("reach") or {}).get("unreached") or []
        if unreached:
            passed_hints.append(
                f"This pass tested nothing for {', '.join(unreached)}: no replayed input reached it, so its contract "
                "was not challenged at runtime. The merged proof records this as an open assumption. Keep every "
                "`requires` as weak as the proof allows, because no runtime check will catch an over-constrained one."
            )
        # E-ACSL only warns about a clause it cannot translate: a pass is the one status that hides it.
        passed_hints.extend(unchecked_clause_hints(res))
        return passed_hints
    if status in ("built", "no_crash"):
        return []

    hints: list[str] = []

    def _add(msg: str) -> None:
        if msg not in hints:
            hints.append(msg)

    # Link repair needed a file that is not there (nginx's generated objs/ngx_modules.c): it was not compiled.
    for missing in (res.get("link_repair") or {}).get("missing_sources") or []:
        _add(
            f"Link repair needs {missing.get('file')} (it defines {', '.join(missing.get('symbols') or [])}) and did "
            f"not add it, because the file does not exist: {missing.get('reason')}."
        )
    # Earlier attempts of a repaired build: their failure differs from the last one's (`build_attempts`).
    for attempt in (res.get("build_attempts") or [])[:-1]:
        parts = (attempt, attempt.get("eacsl") or {})
        logs = ", ".join(attempt.get("logs") or []) or "overwritten"
        if any(part.get("killed") for part in parts):
            what = "was killed (SIGKILL)"
        elif any(part.get("killed_suspected") for part in parts):
            what = "stopped in Frama-C without a Frama-C error message (`aborted by Frama-C` only)"
        else:
            continue
        _add(
            f"Build attempt {attempt.get('attempt')} {what}: most likely out of memory or a hard limit, not a "
            f"compile error; check `docker events` for an `oom` event. The report's `compile` is the last attempt's; "
            f"this attempt's logs: {logs}."
        )

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
        for hint in unchecked_clause_hints(res):
            _add(hint)
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

    if status == "guardrail_error" and res.get("replay_hang"):
        _add(
            f"The dynamic oracle gave no verdict: {res.get('reason')} This says nothing about your contract and it is "
            "NOT a code_fault: do not change your ACSL contracts for it."
        )
        return hints

    if status == "guardrail_error" and res.get("outside_checked_functions"):
        _add(
            f"A check failed outside the checked functions ({res['outside_checked_functions'].get('crash')}): "
            "this says nothing about your contract, and it is NOT a code_fault of the function under proof. "
            "Do not change your ACSL contracts for it; the replay stopped there, so the contract was not tested "
            "on the remaining inputs."
        )
        return hints

    if status in ("compile_error", "guardrail_error"):
        comp = res.get("compile") or {}
        comp_kill = (
            "killed"
            if comp.get("killed")
            else (
                "killed_suspected"
                if comp.get("killed_suspected")
                else fuzz_build._detect_stage_kill(
                    comp.get("returncode"),
                    str(comp.get("stdout") or ""),
                    str(comp.get("stderr") or ""),
                )
            )
        )
        stage_killed = (
            res.get("reason") == "eacsl_stage_killed"
            or comp.get("reason") == "eacsl_stage_killed"
            or comp_kill is not None
        )
        if stage_killed:
            if comp_kill == "killed":
                _add(
                    "E-ACSL build stage was killed (SIGKILL): most likely out of memory (container memory "
                    "limit) or a hard limit, not an ACSL annotation error. Check `docker events` for an "
                    "`oom` event and retry with a larger memory budget; do not rewrite your ACSL contract "
                    "for this failure."
                )
            else:
                _add(
                    "E-ACSL stage 1 stopped in Frama-C without a Frama-C diagnostic message "
                    "(`aborted by Frama-C` only): most likely killed by the container memory limit (OOM), "
                    "not an ACSL annotation or unsupported-construct error. Check `docker events` for an "
                    "`oom` event and retry with a larger memory budget; do not rewrite your ACSL contract "
                    "for this failure."
                )
            for hint in unchecked_clause_hints(res):
                _add(hint)
            return hints
        eacsl_att = res.get("eacsl_compile_attempt") or {}
        if not res.get("build_attempts") and isinstance(eacsl_att, dict) and eacsl_att:
            eacsl_kill = (
                "killed"
                if eacsl_att.get("killed")
                else (
                    "killed_suspected"
                    if eacsl_att.get("killed_suspected")
                    else fuzz_build._detect_stage_kill(
                        eacsl_att.get("returncode"),
                        str(eacsl_att.get("stdout") or ""),
                        str(eacsl_att.get("stderr") or ""),
                    )
                )
            )
            if eacsl_att.get("reason") == "eacsl_stage_killed" or eacsl_kill is not None:
                _add(
                    "The E-ACSL build attempt was killed (most likely container memory limit / OOM; check "
                    "`docker events` for an `oom` event) before falling back to sanitizers."
                )
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
            for k in ("not yet supported", "unsupported", "axiomatic", "no body", "comparison of", "\\with")
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
        for hint in unchecked_clause_hints(res):
            _add(hint)
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


# The crash a replay stopped on: a sanitizer's error headline or libFuzzer's own (deadly signal, ...).
_REPLAY_CRASH_RE = re.compile(r"^(?:==\d+==\s*)?ERROR:\s*(?:\w+Sanitizer|libFuzzer):.*$", re.MULTILINE)
_SANITIZER_SUMMARY_RE = re.compile(r"^SUMMARY:\s*(?P<summary>\S.*)$", re.MULTILINE)
# The function of a stack frame, whatever follows it. `_STACK_FRAME_RE` also wants a `.c`/`.h` file and a
# line, so it skips a frame in `gram.y`, in `tables.inc`, or with no line information; deciding that a crash
# is outside the checked functions must see those frames too.
_STACK_FRAME_FN_RE = re.compile(r"^\s*#\d+\s+0x[0-9a-fA-F]+\s+in\s+(?P<function>[A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)
# How many replayed inputs a guardrail drops for crashing outside the checked functions before it gives up.
GUARDRAIL_MAX_EXCLUDED_INPUTS = 8


def crash_outside_checked_functions(output: str, functions: list[str] | None) -> str | None:
    """
    The crash a guardrail replay stopped on, as one line, when it says nothing about the contract; else None.

    That is the case when E-ACSL reported nothing, a sanitizer or libFuzzer reported a crash (not a timeout or
    an out-of-memory) with a stack, and no frame of that stack is a checked function or its E-ACSL wrapper
    (`__gen_e_acsl_<fn>`). The guardrail build instruments only the checked functions, so such an input
    crashed in other code: a seed or promoted crash that reproduces a known bug elsewhere in the module
    (libmnl `seed-ext-parse-offset-2pow31`: a SEGV in `mnl_attr_ok` stopped every guardrail of module `attr`).
    Without `functions`, or without a stack, nothing is excused.
    """
    if not functions or parse_eacsl_failure(output) is not None:
        return None
    headline = _crash_headline_outside(output, functions)
    if headline is None:
        return None
    summary = _SANITIZER_SUMMARY_RE.search(output, headline.start())
    text = summary.group("summary") if summary else headline.group(0)
    return re.sub(r"\s+", " ", text).strip()[:300]


def _checked_names(functions: list[str]) -> set[str]:
    """The checked functions and their E-ACSL wrappers (`__gen_e_acsl_<fn>`)."""
    return set(functions) | {f"__gen_e_acsl_{fn}" for fn in functions}


def _crash_headline_outside(output: str, functions: list[str]) -> re.Match[str] | None:
    """The crash headline of a replay (not a timeout or an out-of-memory) whose stack has no checked function."""
    headline = _REPLAY_CRASH_RE.search(output or "")
    if headline is None or re.search(r"timeout|out-of-memory", headline.group(0), re.IGNORECASE):
        return None
    frames = [m.group("function") for m in _STACK_FRAME_FN_RE.finditer(output, headline.start())]
    if not frames or any(name in _checked_names(functions) for name in frames):
        return None
    return headline


def failure_outside_checked_functions(failure: dict | None, output: str, functions: list[str] | None) -> str | None:
    """
    The E-ACSL failure a guardrail replay stopped on, as one line, when it says nothing about the contract; else None.

    That is the case when E-ACSL names the function of the failed check, that function is not a checked
    function or its wrapper, and no frame of the stack libFuzzer printed is one either. `-rte-select` and
    `-e-acsl-functions` normally keep other functions uninstrumented, but a checked function Frama-C does not
    know (a header `static inline` nothing in the translation unit calls: `rte_select_dropped`) drops the
    selection and the whole module is instrumented (minmea `minmea_tocoord`: every replay stopped on the
    known signed overflow of `minmea_scan`). A failure below a checked function (a callee it reached) is
    kept: the checked function may have caused it. Without `functions`, a named function or a stack,
    nothing is excused.
    """
    if not functions or not failure:
        return None
    function = str(failure.get("function") or "")
    if function in ("", "unknown", "unknown_function") or function in _checked_names(functions):
        return None
    if _crash_headline_outside(output, functions) is None:
        return None
    what = failure.get("label") or failure.get("alarm_kind") or failure.get("kind") or "check"
    where = f"{failure.get('file')}:{failure.get('line')} in {function}"
    text = f"E-ACSL {what}: {failure.get('predicate') or ''} at {where}"
    return re.sub(r"\s+", " ", text).strip()[:300]


def replay_hang(output: str, crash_input: str | None) -> str | None:
    """
    The hang a guardrail replay stopped on, as one line, or None.

    That is libFuzzer's per-input alarm with its `timeout-` artifact and no E-ACSL report: the input never finished,
    so no check of the contract failed on it. The sandbox's wall limit is not one (no input is named).
    """
    if not crash_input or _artifact_kind(Path(crash_input).name) != "timeout":
        return None
    if parse_eacsl_failure(output) is not None:
        return None
    headline = _REPLAY_CRASH_RE.search(output or "")
    if headline is None or "libFuzzer: timeout" not in headline.group(0):
        return None
    return re.sub(r"^==\d+==\s*", "", headline.group(0)).strip()[:300]


def _hang_entry(input_name: str, why: str, crash_input: str | None, output: str, functions: list[str] | None) -> dict:
    """An `excluded_inputs` entry for a hang; `in_checked_function` tells whether a checked function was on the stack."""
    headline = _REPLAY_CRASH_RE.search(output or "")
    frames = [m.group("function") for m in _STACK_FRAME_FN_RE.finditer(output, headline.start())] if headline else []
    checked = _checked_names(functions or [])
    return {
        "input": input_name,
        "kind": "timeout",
        "crash": why,
        "crash_input": crash_input,
        "in_checked_function": any(name in checked for name in frames),
    }


def _replayed_inputs_of(crash_input: str | None, entries: list[list[str | int]]) -> list[str]:
    """The replayed corpus files whose content is the crash artifact `crash_input` (run-relative), sorted."""
    if not crash_input:
        return []
    path = Path(crash_input)
    digest = cache.file_digest(path) or (sha256_file(path) if path.is_file() else None)
    if not digest:
        return []
    return [str(e[0]) for e in sorted(entries) if e[1] == digest]


def _replayed_input_of(crash_input: str | None, entries: list[list[str | int]]) -> str | None:
    """The first replayed corpus file whose content is the crash artifact `crash_input`, or None."""
    return next(iter(_replayed_inputs_of(crash_input, entries)), None)


def _stage_replay_corpus(scratch_dir: Path, corpus_dir: Path, names: list[str]) -> Path:
    """A scratch copy of the corpus files `names`, so the shared corpus is never changed."""
    replay_corpus = scratch_dir / "replay_corpus"
    if replay_corpus.is_dir():
        shutil.rmtree(replay_corpus, ignore_errors=True)
    replay_corpus.mkdir(parents=True, exist_ok=True)
    for name in names:
        with contextlib.suppress(OSError):
            shutil.copy2(corpus_dir / name, replay_corpus / name)
    return replay_corpus


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
    contract_functions: list[str] | None = None,
    ignored_annotations: list[dict] | None = None,
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

    A failure outside `functions` is not held against the contract (failure_outside_checked_functions),
    nor is a sanitizer crash there (crash_outside_checked_functions). On a corpus input either one drops
    the input; on a mutation of the burst either one skips the burst (`mutations_skipped`).
    `contract_functions` are the functions whose annotations the build is limited to (`--functions`;
    default `functions`): a failed annotation is only excused outside them, so a module-wide build that
    only measures the reach of `functions` (`--reach-functions`, an empty list here) excuses RTE
    failures of other code but never a failed annotation.

    `ignored_annotations` is the build's list of the annotations E-ACSL ignored (the build result's
    `ignored_annotations`). The verdict says which clauses of `functions` and `contract_functions`
    were therefore not executed (dynamic_oracle_fields: `unchecked_clauses`,
    `dynamic_oracle_incomplete`), on every status, and the status itself keeps its meaning. Without
    the list those fields are None: the run cannot tell.

    When caching is enabled (`scripts/cache.py`), deterministic passing verdicts
    (`passed_dynamic_oracle`) are cached in the run-local `guardrail` namespace
    keyed by `{binary_sha256, corpus, scratch_corpus, extra_runs, per_input_timeout, seed, module,
    verdict_fields}`. The dynamic_oracle_fields of a cached verdict are computed again from the list
    this call was given. Transient failures (`rejected_overconstrained`, `code_fault`) are never cached.
    """
    binary = Path(binary)
    corpus_dir = Path(corpus_dir)
    scratch_dir = Path(scratch_dir)
    # The functions whose reach is measured and the ones the build's annotations are limited to: with
    # both named, a clause of either that E-ACSL ignored was not executed.
    oracle_fields = dynamic_oracle_fields(ignored_annotations, [*(functions or []), *(contract_functions or [])])
    if not is_eacsl_instrumented(binary):
        err_verdict: dict[str, object] = {
            "status": "guardrail_error",
            "reason": f"{binary} is not E-ACSL-instrumented; refusing to report a vacuous dynamic-oracle pass.",
            "failure": None,
            "corpus_dir": str(corpus_dir),
            "crash_input": None,
            **oracle_fields,
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
                "verdict_fields": GUARDRAIL_VERDICT_FIELDS,
            }
            g_key = cache.make_key("guardrail", g_material)
            entry = cache.lookup("guardrail", g_key, include_run=not in_parent_guard)
            if entry is not None:
                cached = dict(entry.data.get("verdict") or {})
                if cached.get("status") == "passed_dynamic_oracle":
                    cached.update(selection)
                    cached["corpus_replayed"] = max(0, len(replay_manifest) - len(cached.get("excluded_inputs") or []))
                    cached["corpus_dir"] = str(corpus_dir)
                    cached["crash_input"] = None
                    cached["cache"] = {"hit": True, "key": g_key}
                    cached.update(oracle_fields)  # of the build this call is about, not of the stored one
                    cached["diagnostic_hints"] = derive_eacsl_diagnostic_hints(cached)
                    return cached

    # A replay stops at its first crash. An input that crashes outside the checked functions says nothing about
    # the contract: drop it and replay the rest (crash_outside_checked_functions), at most a few times. So does an
    # input that hangs (replay_hang). Each replay starts over, so that `reach` comes from one complete run of the
    # inputs left, and `timeout_s` is the budget of all of them: a hang costs a whole per-input timeout.
    replay_names = list(chosen_names)
    excluded: list[dict] = []
    mutation_runs = runs
    mutations_skipped: dict | None = None
    hang_stop: str | None = None
    deadline = time.monotonic() + timeout_s
    wall_left = timeout_s
    while True:
        replay_dir = corpus_dir
        if sampled or excluded:
            replay_dir = _stage_replay_corpus(scratch_dir, corpus_dir, replay_names)
        cmd = [
            str(binary.resolve()),
            f"-runs={mutation_runs}",
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
        res = sandbox_exec.run_sandboxed(
            cmd,
            writable=[scratch_dir],
            timeout_s=wall_left,
            limits=Limits(cpu_seconds=wall_left * 2, ignore_sigpipe=True),
        )
        reach, combined_out = parse_guardrail_reach(res.stdout + "\n" + res.stderr, functions)
        verdict = classify_guardrail(res.returncode, res.timed_out, combined_out)
        crash_input = (
            None
            if verdict["status"] == "passed_dynamic_oracle"
            else guardrail_crash_input(scratch_dir, artifacts_before, combined_out)
        )
        if verdict["status"] == "passed_dynamic_oracle" or verdict.get("unsound") or res.timed_out:
            break
        hang = replay_hang(combined_out, crash_input)
        if hang is not None:
            still = set(replay_names)
            hung = _replayed_inputs_of(crash_input, [e for e in replay_manifest if e[0] in still])
            if not hung and mutation_runs > 0:
                # A mutation of the burst: the seed is fixed, so the burst would hang there every time.
                mutations_skipped = {"crash_input": crash_input, "kind": "timeout", "crash": hang}
                mutation_runs = 0
            elif not hung:
                hang_stop = f"An input that is not a replayed corpus file hung ({hang})"
                break
            elif len(excluded) >= GUARDRAIL_MAX_EXCLUDED_INPUTS:
                hang_stop = (
                    f"More than {GUARDRAIL_MAX_EXCLUDED_INPUTS} replayed inputs hang or crash elsewhere ({hang})"
                )
                break
            else:
                excluded.extend(_hang_entry(name, hang, crash_input, combined_out, functions) for name in hung)
                replay_names = [name for name in replay_names if name not in hung]
                if not replay_names:
                    hang_stop = f"every replayed input hung or was dropped ({hang})"
                    break
            wall_left = math.ceil(deadline - time.monotonic())
            if wall_left < 1:
                hang_stop = f"The wall budget of {timeout_s} s ran out on inputs that hang ({hang})"
                break
            continue
        failure = verdict.get("failure")
        if failure is not None:
            scope = functions if verdict["status"] == "code_fault" or contract_functions is None else contract_functions
            why = failure_outside_checked_functions(failure, combined_out, scope)
        elif verdict["status"] == "guardrail_error":
            why = crash_outside_checked_functions(combined_out, functions)
        else:
            why = None
        if why is None:
            break
        outside: dict = {"crash": why}
        if failure is not None:
            # A check that failed in other code is neither a `code_fault` nor a refutation of this contract.
            # Unless the input is dropped below, the replay stopped before testing the contract on the rest.
            outside["failure"] = failure
            if verdict.get("fingerprint"):
                outside["fingerprint"] = verdict["fingerprint"]
            verdict = {
                "status": "guardrail_error",
                "reason": (
                    f"A check failed outside the checked functions ({why}) on an input that cannot be dropped "
                    "(not a replayed corpus file); the contract was not tested on the rest."
                ),
                "outside_checked_functions": outside,
                "failure": None,
            }
        still = set(replay_names)
        name = _replayed_input_of(crash_input, [e for e in replay_manifest if e[0] in still])
        if name is None:
            if crash_input is None or mutation_runs <= 0:
                break
            # Not a corpus file: a mutation of the burst. The seed is fixed, so the burst would stop there
            # every time; replay the corpus alone and say so (`mutations_skipped`). This holds for a sanitizer
            # crash as for an E-ACSL failure: either way no checked function is on the stack (nanopb run-1: a
            # UBSan SEGV of `advance_iterator` on a mutation stopped the header guardrail after 64 inputs).
            mutations_skipped = {"crash_input": crash_input, **outside}
            mutation_runs = 0
            wall_left = math.ceil(deadline - time.monotonic())
            if wall_left < 1:
                break
            continue
        if len(excluded) >= GUARDRAIL_MAX_EXCLUDED_INPUTS:
            verdict["reason"] = (
                f"More than {GUARDRAIL_MAX_EXCLUDED_INPUTS} replayed inputs crash outside the checked functions "
                f"(the last: {why}); the contract was not tested on the rest."
            )
            break
        excluded.append({"input": name, **outside})
        replay_names.remove(name)
        wall_left = math.ceil(deadline - time.monotonic())
        if wall_left < 1:
            break
    dropped_hang = any(e.get("kind") == "timeout" for e in excluded)
    if hang_stop is not None:
        verdict.update(
            status="guardrail_error",
            reason=f"{hang_stop}: the contract was not tested on the rest of the corpus.",
            failure=None,
            replay_hang={"crash": hang_stop, "crash_input": crash_input},
        )
    elif res.timed_out and verdict["status"] == "guardrail_error" and not verdict.get("unsound"):
        verdict.update(
            reason=(
                f"The replay reached its wall limit of {timeout_s} s after {len(excluded)} dropped input(s): "
                "the contract was not tested on the rest of the corpus."
            ),
            replay_hang={"crash": "wall limit", "crash_input": crash_input},
        )
    selection = corpus_selection_fields(len(corpus_entries), len(replay_names), sampled)
    verdict.update(
        {
            "excluded_inputs": excluded,
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
    if mutations_skipped is not None:
        verdict["mutations_skipped"] = mutations_skipped
    if verdict["status"] != "passed_dynamic_oracle":
        verdict["runtime_trace"] = combined_out[-4000:]
    verdict.update(oracle_fields)
    verdict["diagnostic_hints"] = derive_eacsl_diagnostic_hints(verdict)
    if g_key is not None and g_material is not None:
        # Whether an input hangs depends on the machine: such a pass holds for this replay only.
        if verdict["status"] == "passed_dynamic_oracle" and not dropped_hang:
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

# GMP-only mode in a compile log. `e-acsl-gcc -g` passes `-e-acsl-gmp-only` to Frama-C up to 33
# and `-e-acsl-O-gmp-only` from 34 on. The opposite options (`-e-acsl-O-no-gmp-only`) do not match.
_GMP_ONLY_FLAG_RE = re.compile(r"-e-acsl-(?:O-)?gmp-only\b")


def resolve_canary_source() -> Path:
    for base in (Path("/opt/framac-pipeline/templates"), Path(__file__).resolve().parent.parent / "templates"):
        cand = base / "eacsl_canary" / "canary.c"
        if cand.is_file():
            return cand
    raise FileNotFoundError("templates/eacsl_canary/canary.c not found")


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
    replay = replay or crash_replay.replay_artifact
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
    comp = fuzz_build.compile_eacsl_binary(
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
        "no_gmp_only": not _GMP_ONLY_FLAG_RE.search(log_text),
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
        "frama_c_version": fuzz_build.framac_version(runner),
        "eacsl_gcc": fuzz_build._resolve_eacsl_gcc()[0],
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


_failure_fingerprint = failure_fingerprint


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
        "--no-libc-checks",
        action="store_true",
        help="Build E-ACSL without --libc-replacements and --validate-format-strings; recorded in reduced_checks",
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
        help=(
            "callgraph_dag.json used to repair link failures (undefined references -> defining source, "
            "bounded rounds; default: workspace/reports/callgraph_dag.json when it exists)"
        ),
    )
    _add_security_props_arg(p)


def _add_security_props_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--security-props",
        default=None,
        metavar="PATH|none",
        help=(
            "security_props.json whose MetAcsl properties the E-ACSL build checks at run time, when its "
            "meta_engines holds eacsl (default: $FRAMAC_SECURITY_PROPS, else workspace/reports/security_props.json; "
            "'none': no property). The guardrail and the selftest never load them"
        ),
    )


# Why a module's build loaded no property although the run's file turns the engine on: not a warning.
_SECURITY_PROPS_NO_INSTANCE = "no property has an instance in a function of these sources"


def build_security_props(build: dict) -> dict | None:
    """
    The `security_props` record of a module build (fuzz_build.build_module_binary's result): the
    E-ACSL build's, or the one of the E-ACSL attempt the sanitizer build replaced. None when the run's
    MetAcsl properties are off for the E-ACSL build, which is every run without `eacsl` in `meta_engines`.
    """
    for comp in (build.get("compile"), build.get("eacsl_compile_attempt")):
        record = comp.get("security_props") if isinstance(comp, dict) else None
        if isinstance(record, dict):
            return record
    return None


def security_props_warnings(record: dict | None) -> list[str]:
    """
    What the user must see about the MetAcsl properties of an E-ACSL build (its `security_props`): a
    build that lost them all (`dropped`, `error`, a toolchain that cannot take them), then each
    property that is not checked at run time or is checked where the plan did not expect it. Empty
    for a build that checks every property it loaded, and for a module no property has an instance in.
    """
    if not isinstance(record, dict):
        return []
    out: list[str] = []
    status, reason = record.get("status"), str(record.get("reason") or "no reason recorded")
    props = record.get("props") or "the security properties file"
    if status == "dropped":
        names = ", ".join(str(n) for n in record.get("properties") or []) or "every property"
        log = f"; log: {record['log']}" if record.get("log") else ""
        out.append(f"dropped: this binary checks NO MetAcsl property at run time ({reason}); not checked: {names}{log}")
    elif status == "error":
        out.append(f"error: {props} could not be loaded ({reason}); this binary checks no MetAcsl property")
    elif status == "skipped" and reason != _SECURITY_PROPS_NO_INSTANCE:
        out.append(f"skipped: this binary checks no MetAcsl property at run time ({reason})")
    for item in record.get("rejected") or []:
        out.append(
            f"rejected: MetAcsl could not type {item.get('property')} in this module ({item.get('reason')}); "
            "it is not checked at run time"
        )
    for item in record.get("left_out") or []:
        out.append(f"left out: {item.get('property')} is not checked at run time ({item.get('reason')})")
    not_translated = [str(n) for n in record.get("not_translated") or []]
    if not_translated:
        out.append(
            "not translated: no run-time check for "
            + ", ".join(not_translated)
            + " (decided statically, no instance in the instrumented functions, or not translated by E-ACSL)"
        )
    unplanned = record.get("unplanned_instances")
    for name, functions in sorted(unplanned.items()) if isinstance(unplanned, dict) else []:
        out.append(
            f"unplanned instances: {name} is also checked in {', '.join(str(f) for f in functions)}, which "
            "security_props.json does not list as its instances (a violation there links no ledger unit)"
        )
    libc = record.get("libc_contracts")
    if isinstance(libc, dict) and libc.get("status") in ("dropped", "missing") and status == "loaded":
        names = ", ".join(str(n) for n in libc.get("functions") or []) or "the libc writers"
        log = f"; log: {libc['log']}" if libc.get("log") else ""
        out.append(
            f"libc contracts {libc['status']}: the assigns of {names} are not in this build "
            f"({libc.get('reason') or 'no reason recorded'}){log}"
        )
    unchecked = record.get("libc_unchecked")
    calls = sorted(unchecked.items()) if isinstance(unchecked, dict) else []
    if calls and status == "loaded":
        out.append(
            "libc unchecked: "
            + "; ".join(f"{lib} (called in {', '.join(str(f) for f in fns)})" for lib, fns in calls)
            + ": no contract in this build, so no \\writing or \\reading property is checked on what these "
            "calls write or read (WP and Eva, which parse Frama-C's libc, check them)"
        )
    return out


def harness_induced_failures(artifacts: object) -> list[dict]:
    """
    The artifacts whose failure is a MetAcsl precondition the harness itself broke
    (failure_identity: `harness_induced`): {artifact, property, function, caller, fingerprint}.
    `ledger.py ingest-fuzz` makes no candidate of them; the campaign report lists them here.
    """
    out: list[dict] = []
    for art in artifacts if isinstance(artifacts, list) else []:
        failure = art.get("failure") if isinstance(art, dict) else None
        if isinstance(failure, dict) and failure.get("meta_property") and failure.get("harness_induced") is True:
            out.append(
                {
                    "artifact": art.get("artifact"),
                    "property": failure.get("meta_property"),
                    "function": failure.get("function"),
                    "caller": failure.get("caller"),
                    "fingerprint": art.get("fingerprint"),
                }
            )
    return out


def note_security_props(res: dict, record: dict | None) -> None:
    """
    Put a build's `security_props` record and its warnings (`security_props_warnings`) at the top of
    report `res`, and print each warning on stderr. Nothing is added without a record, so the report
    of a run without the engine has the keys it always had.
    """
    if not isinstance(record, dict):
        return
    res["security_props"] = record
    warnings = security_props_warnings(record)
    if warnings:
        res["security_props_warnings"] = warnings
    module = res.get("module") or "module"
    for line in warnings:
        print(f"security props [{module}]: {line}", file=sys.stderr)


def _security_props_kwarg(args) -> dict:
    """`security_props=<--security-props>` for a builder, {} when the option was not given."""
    value = getattr(args, "security_props", None)
    return {"security_props": value} if value is not None else {}


def _build_options(args) -> dict:
    dag = fuzz_build.default_dag_path(getattr(args, "dag", None))
    return {
        # Only when given: the build call of a run without the option is today's.
        **_security_props_kwarg(args),
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
        "libc_checks": not args.no_libc_checks,
        "use_cache": not getattr(args, "no_cache", False),
        "dag_path": dag,
        "link_module": getattr(args, "module", "") or None,
    }


_SUMMARY_OMITTED = (
    "compile",
    "log_tail",
    "runtime_trace",
    "eacsl_compile_attempt",
    "functions",
    "failed_inputs",
    # A module-wide build lists every function's; `unchecked_clauses` (printed) has the checked functions'.
    "ignored_annotations",
)


def _summary(res: dict) -> dict:
    """What is printed: the report without logs and compiler output (the JSON file has everything)."""
    out = {k: v for k, v in res.items() if k not in _SUMMARY_OMITTED}
    if isinstance(out.get("artifacts"), list):
        out["artifacts"] = [
            {k: v for k, v in a.items() if k not in ("replay_log_tail", "attribution", "frames")}
            if isinstance(a, dict)
            else a
            for a in out["artifacts"]
        ]
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="E-ACSL + LibFuzzer campaigns, guardrails, builds and replays.")
    sub = parser.add_subparsers(dest="mode", required=True)

    p_camp = sub.add_parser("campaign")
    _add_build_args(p_camp, sources_required=False)
    p_camp.add_argument("--out-bin", type=Path, default=None)
    p_camp.add_argument(
        "--build-json", type=Path, default=None, help="Pre-built workspace/build/<mod>.build.json (P7f)"
    )
    p_camp.add_argument(
        "--smoke-report", type=Path, default=None, help="Optional workspace/reports/smoke/<mod>.json (P3)"
    )
    p_camp.add_argument(
        "--profile",
        choices=["quick", "standard", "deep"],
        default="standard",
        help="Pipeline profile (used under FRAMAC_FUZZ_EXPLORE_JUDGE for P2a budget share and P6a floor runs)",
    )
    p_camp.add_argument(
        "--no-floor-pass",
        action="store_true",
        help="Skip the P6a per-case floor pass even when FRAMAC_FUZZ_EXPLORE_JUDGE is enabled",
    )
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

    p_judge = sub.add_parser("judge", help="Judge grown corpus, seeds, and explorer crashes on pre-built E-ACSL (P2d)")
    p_judge.add_argument("--module", required=True)
    p_judge.add_argument("--build-json", type=Path, required=True, help="Pre-built workspace/build/<mod>.build.json")
    p_judge.add_argument("--corpus-dir", type=Path, required=True, help="Grown corpus directory")
    p_judge.add_argument(
        "--extra-corpus", type=Path, nargs="*", default=[], help="Seeds and imported corpus directories"
    )
    p_judge.add_argument(
        "--explore-report", type=Path, default=None, help="Explorer fuzz report JSON for crashes and D1b linking"
    )
    p_judge.add_argument("--smoke-report", type=Path, default=None, help="Optional workspace/reports/smoke/<mod>.json")
    p_judge.add_argument("--profile", choices=["quick", "standard", "deep"], default="standard")
    p_judge.add_argument("--max-corpus-inputs", type=int, default=None, help="Override profile cap N (512/2048/4096)")
    p_judge.add_argument(
        "--max-time", type=int, default=JUDGE_DEFAULT_MAX_TIME_S, help="Safety wall-clock stop (seconds)"
    )
    p_judge.add_argument("--per-input-timeout", type=int, default=DEFAULT_PER_INPUT_TIMEOUT_S)
    p_judge.add_argument("--batch-size", type=int, default=JUDGE_BATCH_SIZE)
    p_judge.add_argument("--scratch-dir", type=Path, default=None)
    p_judge.add_argument(
        "--sources", nargs="*", default=None, help="Optional harness/module sources (defaults to build-json)"
    )
    p_judge.add_argument("--out-json", type=Path, required=True)

    p_efuzz = sub.add_parser("eacsl-fuzz", help="Run the deep-profile 1/5 E-ACSL fuzz share after judge (P2e)")
    p_efuzz.add_argument("--module", required=True)
    p_efuzz.add_argument("--build-json", type=Path, required=True, help="Pre-built workspace/build/<mod>.build.json")
    p_efuzz.add_argument("--corpus-dir", type=Path, required=True, help="Writable corpus directory")
    p_efuzz.add_argument("--extra-corpus", type=Path, nargs="*", default=[], help="Read-only seed corpus directories")
    p_efuzz.add_argument("--artifacts-dir", type=Path, required=True)
    p_efuzz.add_argument("--judge-report", type=Path, default=None, help="workspace/reports/judge/<mod>.json")
    p_efuzz.add_argument("--smoke-report", type=Path, default=None, help="workspace/reports/smoke/<mod>.json")
    p_efuzz.add_argument("--profile", choices=["quick", "standard", "deep"], default="deep")
    p_efuzz.add_argument("--fuzz-budget", type=int, default=None, help="Total module CPU-s budget (1/5 share used)")
    p_efuzz.add_argument("--max-time", type=int, default=None, help="Explicit wall-clock seconds override")
    p_efuzz.add_argument("--workers", default="auto")
    p_efuzz.add_argument("--jobs", type=int, default=None)
    p_efuzz.add_argument("--per-input-timeout", type=int, default=DEFAULT_PER_INPUT_TIMEOUT_S)
    p_efuzz.add_argument("--dict", type=Path, default=None)
    p_efuzz.add_argument("--no-auto-dict", action="store_true")
    p_efuzz.add_argument("--cppflags", default="-I.")
    p_efuzz.add_argument("--sources", nargs="*", default=None)
    p_efuzz.add_argument("--stop-on-first-crash", action="store_true")
    p_efuzz.add_argument("--no-cache", action="store_true")
    p_efuzz.add_argument("--out-json", type=Path, required=True)

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
        "--no-libc-checks",
        action="store_true",
        help="Build E-ACSL without --libc-replacements and --validate-format-strings; recorded in reduced_checks",
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
    p_cov.add_argument(
        "--dag",
        type=Path,
        default=None,
        help=(
            "callgraph_dag.json used to repair link failures as the fuzz build does "
            "(default: workspace/reports/callgraph_dag.json when it exists)"
        ),
    )
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
    p_cands.add_argument(
        "--fingerprint",
        default=None,
        help="Replay --inputs on this one candidate's module binary instead (report: --out-json; no index)",
    )
    p_cands.add_argument("--inputs", type=Path, nargs="+", default=None, help="With --fingerprint: the input files")
    p_cands.add_argument("--out-json", type=Path, default=None, help="With --fingerprint: the replay report")
    p_cands.add_argument(
        "--cross-engine",
        action="store_true",
        help="Also replay each candidate's reproducers on the other engine's binary (index.json: cross_engine)",
    )
    _add_security_props_arg(p_cands)

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
    _add_security_props_arg(p_minc)

    p_int = sub.add_parser("minimize-interest", help="cvise interest test (called by the generated interest.sh)")
    p_int.add_argument("--binary", type=Path, required=True)
    p_int.add_argument("--fingerprint", default="")
    p_int.add_argument("--module", default="")
    p_int.add_argument("--per-input-timeout", type=int, default=DEFAULT_PER_INPUT_TIMEOUT_S)
    p_int.add_argument("--scratch-dir", type=Path, required=True)
    p_int.add_argument("variant", type=Path)

    raw_argv = normalize_flag_args(list(argv) if argv is not None else sys.argv[1:])
    args = parser.parse_args(raw_argv)
    if args.mode in ("campaign", "eacsl-fuzz") and str(args.workers).strip().lower() != "auto":
        try:
            if int(args.workers) < 1:
                raise ValueError
        except ValueError:
            parser.error(f"--workers must be 'auto' or a positive integer (got {args.workers!r})")
    if args.mode == "campaign" and not args.sources and args.build_json is None:
        parser.error("campaign needs --sources (or --build-json)")
    if args.mode == "campaign" and args.out_bin is None and args.build_json is None:
        parser.error("campaign needs --out-bin (or --build-json)")
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
        if (args.fingerprint is None) != (args.inputs is None) or (args.fingerprint is None) != (args.out_json is None):
            raise SystemExit("replay-candidates: --fingerprint, --inputs and --out-json go together")
        summary = crash_replay.replay_candidates(
            args.candidates,
            args.harness_dir,
            args.out_dir,
            bin_dir=args.bin_dir,
            engine=args.engine,
            selftest_json=args.selftest_json,
            machdep=args.machdep,
            per_input_timeout=args.per_input_timeout,
            attribution=not args.no_attribution_replay,
            only=args.fingerprint,
            inputs=args.inputs,
            out_json=args.out_json,
            cross_engine=args.cross_engine,
            **_security_props_kwarg(args),
        )
        print(json.dumps(summary, indent=2))
        return 0 if summary["status"] == "ok" else 1

    if args.mode == "minimize-interest":
        # Exit 0 iff the variant is still interesting (crashes with the same fingerprint).
        if args.binary is None:  # required=True on this subcommand; argparse already refuses it
            raise SystemExit("minimize-interest: --binary is required")
        interesting = crash_replay.minimize_interest(
            args.binary,
            args.variant,
            args.scratch_dir,
            args.fingerprint or None,
            module=args.module,
            per_input_timeout=args.per_input_timeout,
        )
        return 0 if interesting else 1

    if args.mode == "minimize-candidates":
        summary = crash_replay.minimize_candidates(
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
            **_security_props_kwarg(args),
        )
        print(json.dumps(summary, indent=2))
        return 0 if summary["status"] == "ok" else 1

    if args.mode == "minimize":
        if args.binary is None and not (args.sources and args.out_bin):
            parser.error("minimize needs --binary, or --sources with --out-bin")
        prepared = None
        if args.binary is None:
            prepared = crash_replay.prepare_replay_binary(
                args.module,
                args.sources,
                args.out_bin,
                engine=args.engine,
                selftest_json=args.selftest_json,
                machdep=args.machdep,
                cppflags=args.cppflags,
                ldflags=args.ldflags,
                rte_initialized=not args.no_rte_initialized,
                libc_checks=not args.no_libc_checks,
                dag_path=fuzz_build.default_dag_path(args.dag),
                link_module=args.module,
                **_security_props_kwarg(args),
            )
            binary = prepared.get("binary")
        else:
            binary = args.binary
        scratch = args.scratch_dir or args.out_json.parent / f".scratch_minimize_{args.module}"
        runs = [
            crash_replay.minimize_input(
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
        note_security_props(res, (prepared or {}).get("security_props"))
        atomic_write_json(args.out_json, res)
        print(json.dumps(_summary(res), indent=2))
        return 0 if res["status"] == "ok" else 1

    digest_before = prover_candidates.digest_before_run(args.out_json) if args.mode == "guardrail" else None
    identity: dict = {}
    prior_report: dict | None = None
    if args.mode in ("campaign", "eacsl-fuzz"):
        # Taken before the build: the values the artifacts are found under. The report this run
        # replaces holds the values of the artifacts libFuzzer only re-reports (`pre_existing`).
        eff_sources = _sources_for_mode(args)
        identity = campaign_harness_identity(args.module, eff_sources)
        try:
            loaded = json.loads(args.out_json.read_text(encoding="utf-8"))
            prior_report = loaded if isinstance(loaded, dict) else None
        except (OSError, ValueError):
            prior_report = None
    guard_build: dict | None = None
    try:
        if args.mode == "selftest":
            res = run_selftest(args.work_dir, args.machdep, variadic_translation=not args.no_variadic_translation)
        elif args.mode == "campaign":
            res = _run_campaign_mode(args)
        elif args.mode == "judge":
            res = _run_judge_mode(args)
        elif args.mode == "eacsl-fuzz":
            res = _run_eacsl_fuzz_mode(args)
        elif args.mode == "build":
            res = _run_build_mode(args)
        elif args.mode == "coverage":
            res = fuzz_coverage.coverage_report(
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
                dag_path=fuzz_build.default_dag_path(args.dag),
                link_module=args.module,
            )
        elif args.mode == "replay":
            prepared = None
            if args.binary is None:
                prepared = crash_replay.prepare_replay_binary(
                    args.module,
                    args.sources,
                    args.out_bin,
                    attribution=not args.no_attribution_replay,
                    **_build_options(args),
                )
            scratch = args.scratch_dir or args.out_json.parent / f".scratch_replay_{args.module or 'module'}"
            res = crash_replay.replay_report(
                args.module,
                args.inputs,
                scratch,
                prepared=prepared,
                binary=args.binary,
                per_input_timeout=args.per_input_timeout,
            )
            # The record is in the report already (crash_replay.replay_report); here its warnings.
            note_security_props(res, res.get("security_props"))
        else:
            # The guardrail checks one function's contract on a prover's copy: its build never loads
            # the run's MetAcsl properties (WP proves them for that function), like the selftest canary.
            use_cache = not getattr(args, "no_cache", False)
            comp = fuzz_build.compile_eacsl_binary(
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
                libc_checks=not args.no_libc_checks,
                use_cache=use_cache,
            )
            guard_build = comp
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
                    contract_functions=args.functions or [],
                    ignored_annotations=comp.get("ignored_annotations"),
                )
                res = {"mode": "guardrail", "compile": comp, **guard, "reduced_checks": comp.get("reduced_checks", [])}
                if "diagnostic_hints" not in res:
                    res["diagnostic_hints"] = derive_eacsl_diagnostic_hints(res)
    except SandboxUnavailable as exc:
        if args.mode == "judge":
            res = _judge_error_report(
                getattr(args, "module", "") or "unknown",
                profile=getattr(args, "profile", "standard") or "standard",
                reason=f"sandbox_unavailable: {exc}",
                corpus_cap=getattr(args, "max_corpus_inputs", None),
            )
        else:
            res = {"mode": args.mode, "status": "sandbox_unavailable", "reason": str(exc)}
            if args.mode == "guardrail":
                res["crash_input"] = None

    if args.mode == "guardrail":
        # What E-ACSL did not execute, on every status: run_guardrail_check set the same fields from the
        # same list; a build that failed and a replay that could not start get them here.
        built = guard_build or {}
        checked = [*(args.reach_functions or []), *(args.functions or [])]
        res.update(dynamic_oracle_fields(built.get("ignored_annotations"), checked))
        res["ignored_frame_clauses"] = built.get("ignored_frame_clauses")
        hints = list(res.get("diagnostic_hints") or [])
        hints += [h for h in unchecked_clause_hints(res) if h not in hints]
        if hints or "diagnostic_hints" in res:
            res["diagnostic_hints"] = hints

    if args.mode in ("campaign", "eacsl-fuzz"):
        import seed_harvest  # lazily: only campaigns read the seed writes' statuses

        res["seeds"] = seed_harvest.seeds_report_field(args.module, bool(args.extra_corpus))
        stamp_harness_identity(res, identity, prior_report)
    atomic_write_json(args.out_json, res)
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
    if args.mode == "judge":
        if str(res.get("reason") or "").startswith("sandbox_unavailable"):
            return 3
        return 0
    return 3 if res.get("status") == "sandbox_unavailable" else 0


def _load_json_dict_optional(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    p = Path(path)
    if not p.is_file():
        return None
    try:
        loaded = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return loaded if isinstance(loaded, dict) else None


def _sources_for_mode(args) -> list[str]:
    srcs = list(getattr(args, "sources", None) or [])
    if srcs:
        return srcs
    bdoc = _load_json_dict_optional(getattr(args, "build_json", None))
    if bdoc and isinstance(bdoc.get("sources"), list):
        return [str(s) for s in bdoc["sources"] if isinstance(s, str)]
    return []


def _run_build_mode(args) -> dict:
    # D8: `build` compiles what --engine asks for and does not apply the selftest; the campaign does.
    build = fuzz_build.build_module_binary(args.sources, args.out_bin, **_build_options(args), apply_selftest=False)
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
    if build.get("binaries") is not None:
        res["binaries"] = build["binaries"]
    if built and build["engine_used"] == "eacsl" and comp.get("reduced_checks"):
        res["reduced_checks"] = comp["reduced_checks"]
    if build["engine_fallback_reason"]:
        res["engine_fallback_reason"] = build["engine_fallback_reason"]
    if build["eacsl_compile_attempt"] is not None:
        res["eacsl_compile_attempt"] = build["eacsl_compile_attempt"]
    if build.get("link_repair"):
        res["link_repair"] = build["link_repair"]
    if build.get("attempts"):
        res["build_attempts"] = build["attempts"]
    note_security_props(res, build_security_props(build))
    if build.get("sanitizer_compile") is not None:
        res["sanitizer_compile"] = build["sanitizer_compile"]
    elif args.engine == "auto" and build["engine_used"] == "eacsl":
        # The campaign falls back to the sanitizers when the selftest fails: build them now, with the
        # campaign's arguments, so that it restores them from the cache.
        san = fuzz_build.build_module_binary(
            args.sources, args.out_bin, **{**_build_options(args), "engine": "sanitizers"}
        )
        res["sanitizer_compile"] = san["compile"]
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


def _encode_dispatch_selector(case_idx: int, selector: str) -> bytes:
    width = dispatch_selector_width(selector)
    return int(case_idx).to_bytes(width, "little")


def _file_dispatch_case(path: Path, n_cases: int | None, selector: str) -> int | None:
    if not n_cases or n_cases <= 0:
        return None
    try:
        with open(path, "rb") as fh:
            prefix = fh.read(dispatch_selector_width(selector))
    except OSError:
        return None
    return dispatch_case_of_bytes(prefix, n_cases, selector)


def run_floor_pass(
    binary: Path,
    corpus_dir: Path,
    artifacts_dir: Path,
    *,
    n_cases: int,
    selector: str,
    supports_only_case: bool,
    profile: str = "standard",
    extra_corpus: Sequence[Path] = (),
    smoke_skipped: Sequence[int] = (),
    dict_file: Path | None = None,
    per_input_timeout: int = DEFAULT_PER_INPUT_TIMEOUT_S,
    rss_limit_mb: int = FUZZ_RSS_LIMIT_MB,
    module: str = "",
    blinding_threshold: int = BLINDING_CASE_THRESHOLD,
    max_restarts: int = FLOOR_PASS_MAX_RESTARTS,
    runs_override: int | None = None,
    safety_time_override: int | None = None,
    campaign_runner=None,
    single_process: dict[str, str] | None = None,
) -> dict[str, Any]:
    """
    P6a per-case floor pass for multi-case dispatch harnesses under FRAMAC_FUZZ_EXPLORE_JUDGE.
    Isolates each non-smoke-skipped case via `FRAMAC_FUZZ_ONLY_CASE=<k>` (falling back to
    `FRAMAC_FUZZ_SKIP_CASES` + a bootstrap selector seed for legacy harnesses), merges grown
    per-case corpora into `corpus_dir` with normalized selector bytes, detects per-case blinding
    (`K_case = 16`), and returns peak per-worker RSS for P7b/P7c sizing.
    """
    runner = campaign_runner or run_fuzz_campaign
    prof = (profile or "standard").strip().lower()
    default_runs, default_safety = FLOOR_PASS_BY_PROFILE.get(prof, FLOOR_PASS_BY_PROFILE["standard"])
    case_runs = max(1, int(runs_override if runs_override is not None else default_runs))
    case_safety_s = max(1, int(safety_time_override if safety_time_override is not None else default_safety))
    smoke_set = {int(c) for c in smoke_skipped if 0 <= int(c) < n_cases}
    width = dispatch_selector_width(selector)

    # Partition existing seeds/imported inputs once by dispatch case.
    seeds_by_case: dict[int, list[Path]] = {k: [] for k in range(n_cases)}
    for root in (corpus_dir, *extra_corpus):
        p = Path(root)
        if not p.is_dir():
            continue
        for f in sorted(p.iterdir()):
            if not f.is_file() or f.is_symlink() or f.name.startswith("."):
                continue
            c = _file_dispatch_case(f, n_cases, selector)
            if c is not None and 0 <= c < n_cases:
                seeds_by_case[c].append(f)

    tracker = CaseBlindingTracker(threshold=blinding_threshold)
    case_results: list[dict[str, Any]] = []
    all_artifacts: list[dict[str, Any]] = []
    telemetries: list[dict[str, Any]] = []
    skip_for_shared: set[int] = set(smoke_set)
    peak_per_worker_mb: float | int | None = None
    floor_started = time.monotonic()

    scratch_root = Path(tempfile.mkdtemp(prefix=f"floor_{module or 'mod'}_"))
    try:
        for k in range(n_cases):
            if k in smoke_set:
                case_results.append(
                    {
                        "case": k,
                        "status": "smoke_skipped",
                        "attempts": 0,
                        "reached_executions": 0,
                        "edges": 0,
                        "corpus_files": 0,
                        "peak_rss_mb": None,
                        "fingerprints": [],
                    }
                )
                continue

            case_corpus = scratch_root / f"case_{k}" / "corpus"
            case_seeds = scratch_root / f"case_{k}" / "seeds"
            case_corpus.mkdir(parents=True, exist_ok=True)
            case_seeds.mkdir(parents=True, exist_ok=True)
            for idx, seed_path in enumerate(seeds_by_case.get(k) or []):
                with contextlib.suppress(OSError):
                    shutil.copy2(seed_path, case_seeds / f"s{idx}_{seed_path.name}")
            if not supports_only_case and not any(case_seeds.iterdir()):
                (case_seeds / f"bootstrap_case_{k}").write_bytes(_encode_dispatch_selector(k, selector))

            if supports_only_case:
                case_env = {DISPATCH_ONLY_CASE_ENV: str(k)}
            else:
                others = [c for c in range(n_cases) if c != k]
                case_env = {DISPATCH_SKIP_MACRO: format_skip_cases_env(others)}

            remaining_runs = case_runs
            restarts = 0
            case_attempts = 0
            case_edges = 0
            case_peak_rss: float | int | None = None
            case_fps: list[str] = []
            case_crashed = False
            case_blinded = False
            case_hit_safety = False
            case_seed_val = derive_seed(binary, f"{module}:floor:{k}")

            while remaining_runs > 0:
                sp_kwargs: dict[str, Any] = (
                    {"single_process_reason": single_process.get("reason")} if single_process is not None else {}
                )
                run = runner(
                    binary,
                    case_corpus,
                    artifacts_dir,
                    case_safety_s,
                    dict_file=dict_file,
                    per_input_timeout=per_input_timeout,
                    rss_limit_mb=rss_limit_mb,
                    extra_corpus=[case_seeds],
                    jobs=1,
                    workers=1,
                    fork=False,
                    extra_env=case_env,
                    runs=remaining_runs,
                    seed=case_seed_val + restarts,
                    **sp_kwargs,
                )
                if single_process is not None and run.get("single_process_reason") and "reason" not in single_process:
                    single_process["reason"] = str(run["single_process_reason"])
                tel = run.get("telemetry")
                if isinstance(tel, dict):
                    telemetries.append(tel)
                    execs = int(tel.get("total_executions") or 0)
                    case_attempts += execs
                    case_edges = max(case_edges, int(tel.get("max_cov") or 0))
                    rss = tel.get("peak_rss_mb")
                    if isinstance(rss, (int, float)) and not isinstance(rss, bool):
                        case_peak_rss = rss if case_peak_rss is None else max(case_peak_rss, rss)
                        peak_per_worker_mb = rss if peak_per_worker_mb is None else max(peak_per_worker_mb, rss)
                else:
                    execs = 0

                arts = [a for a in (run.get("artifacts") or []) if not a.get("pre_existing")]
                raw_crashes = run.get("_raw_crashes")
                crash_list = (
                    [r for r in raw_crashes if isinstance(r, dict) and not r.get("pre_existing")]
                    if isinstance(raw_crashes, list)
                    else arts
                )
                for a in arts:
                    all_artifacts.append(a)
                    if a.get("fingerprint") and str(a["fingerprint"]) not in case_fps:
                        case_fps.append(str(a["fingerprint"]))

                if not crash_list and run.get("status") == "clean":
                    if execs > 0:
                        tracker.record_pass(k)
                    if execs < remaining_runs and float(run.get("fuzz_s") or 0.0) >= case_safety_s:
                        case_hit_safety = True
                    break

                if crash_list:
                    case_crashed = True
                    if execs > len(crash_list):
                        tracker.record_pass(k)
                    for cr in crash_list:
                        if tracker.record_crash(k, cr.get("fingerprint")):
                            case_blinded = True
                    if case_blinded or tracker.is_blinded(k):
                        case_blinded = True
                        break
                    restarts += 1
                    remaining_runs = max(0, remaining_runs - max(1, execs))
                    # Allow up to blinding_threshold probes when 0 passes so blinding is detected cleanly,
                    # otherwise cap restarts at max_restarts (4).
                    allowed_restarts = blinding_threshold if tracker.passes_of(k) == 0 else max_restarts
                    if restarts >= allowed_restarts:
                        break
                    continue

                # Non-crash failure (fuzzer_error / insufficient_memory / timeout)
                if run.get("timed_out"):
                    case_hit_safety = True
                break

            # Merge case_corpus into shared corpus_dir with normalized selector bytes.
            corpus_dir.mkdir(parents=True, exist_ok=True)
            merged_files = 0
            sel_prefix = _encode_dispatch_selector(k, selector)
            for cf in sorted(case_corpus.iterdir()):
                if not cf.is_file() or cf.is_symlink() or cf.name.startswith("."):
                    continue
                with contextlib.suppress(OSError):
                    raw_bytes = cf.read_bytes()
                    if len(raw_bytes) >= width:
                        norm = sel_prefix + raw_bytes[width:]
                    else:
                        norm = sel_prefix + raw_bytes
                    digest = hashlib.sha256(norm).hexdigest()
                    dest = corpus_dir / f"floor_c{k}_{digest[:16]}"
                    if not dest.exists():
                        dest.write_bytes(norm)
                    merged_files += 1

            if case_blinded:
                c_status = "blinded"
                skip_for_shared.add(k)
            elif case_crashed:
                c_status = "crashing"
                skip_for_shared.add(k)
            elif case_hit_safety or (
                case_attempts > 0 and case_edges == 0 and merged_files == 0 and restarts >= max_restarts
            ):
                c_status = "floor_not_reached"
            else:
                c_status = "ok"

            case_results.append(
                {
                    "case": k,
                    "status": c_status,
                    "attempts": case_attempts,
                    "reached_executions": case_attempts,
                    "edges": case_edges,
                    "corpus_files": merged_files,
                    "peak_rss_mb": case_peak_rss,
                    "fingerprints": case_fps,
                }
            )
    finally:
        shutil.rmtree(scratch_root, ignore_errors=True)

    floor_s = max(0.0, time.monotonic() - floor_started)
    merged_tel = merge_telemetry(telemetries, floor_s=floor_s)
    return {
        "cases": case_results,
        "artifacts": all_artifacts,
        "blinded_cases": tracker.blinded_cases_report(),
        "skip_for_shared": sorted(skip_for_shared),
        "peak_per_worker_mb": peak_per_worker_mb,
        "floor_s": round(floor_s, 3),
        "telemetry": merged_tel,
    }


def _judge_input_running_at_exit(output: str, batch: Sequence[Path]) -> int | None:
    """
    Index in `batch` of the input libFuzzer was executing when the process exited (`Running: <p>`
    without a matching `Executed <p>`), resilient to resolved/relative/POSIX path formatting.
    """
    last_running: str | None = None
    for m in _RUNNING_RE.finditer(output or ""):
        if m.group("run") is not None:
            last_running = m.group("run").strip()
        elif m.group("done") is not None and m.group("done").strip() == last_running:
            last_running = None
    if last_running is None:
        return None
    norm_last = last_running.replace("\\", "/")
    for i, path in enumerate(batch):
        p = Path(path)
        if (
            str(p.resolve()) == last_running
            or str(p) == last_running
            or p.resolve().as_posix() == norm_last
            or p.as_posix() == norm_last
        ):
            return i
    base = Path(last_running).name
    matches = [i for i, path in enumerate(batch) if Path(path).name == base]
    return matches[0] if len(matches) == 1 else None


def select_judge_inputs(
    corpus_dir: Path,
    extra_corpus: Sequence[Path] = (),
    explore_report: dict[str, Any] | None = None,
    *,
    cap: int = 2048,
    n_cases: int | None = None,
    selector: str = DISPATCH_SELECTOR_MODULO,
    smoke_skipped: Sequence[int] = (),
) -> dict[str, Any]:
    """
    P2d deterministic case-stratified SHA-256 input selection for E-ACSL judging:
    - Mandatory inputs (always kept): all files from `extra_corpus` (seeds + imported inputs),
      all targeted files in `corpus_dir` (`TARGETED_CORPUS_PREFIXES`), and all explorer crash
      artifacts listed in `explore_report`.
    - Grown corpus inputs (up to `cap`): grouped by dispatch case when `n_cases` is known,
      deterministically ordered by SHA-256 of filename within each case, and selected round-robin
      across cases so no high-volume case starves low-volume cases.
    - Selected inputs are interleaved across dispatch cases for prompt per-case blinding.
    """
    smoke_set = {int(c) for c in smoke_skipped if int(c) >= 0}
    seen_paths: set[str] = set()
    mandatory_raw: list[Path] = []
    grown_raw: list[Path] = []

    def _add_unique(p: Path, dest: list[Path]) -> None:
        if not p.is_file() or p.is_symlink() or p.name.startswith("."):
            return
        key = str(p.resolve())
        if key in seen_paths:
            return
        seen_paths.add(key)
        dest.append(p)

    # 1. Explorer crash artifacts (mandatory)
    if isinstance(explore_report, dict):
        for art in explore_report.get("artifacts") or []:
            if isinstance(art, dict) and art.get("artifact"):
                _add_unique(Path(str(art["artifact"])), mandatory_raw)

    # 2. Extra corpus directories: seeds and imported inputs (mandatory)
    for d in extra_corpus:
        dp = Path(d)
        if dp.is_file():
            _add_unique(dp, mandatory_raw)
        elif dp.is_dir():
            for f in sorted(dp.iterdir()):
                _add_unique(f, mandatory_raw)

    # 3. Corpus directory: targeted files are mandatory, rest are grown corpus
    cdir = Path(corpus_dir)
    if cdir.is_dir():
        for f in sorted(cdir.iterdir()):
            if f.name.startswith(TARGETED_CORPUS_PREFIXES):
                _add_unique(f, mandatory_raw)
            else:
                _add_unique(f, grown_raw)

    # Filter out inputs belonging to smoke-quarantined dispatch cases before cap selection
    smoke_skipped_count = 0
    mandatory: list[tuple[Path, int | None]] = []
    for p in mandatory_raw:
        c = _file_dispatch_case(p, n_cases, selector)
        if c is not None and c in smoke_set:
            smoke_skipped_count += 1
            continue
        mandatory.append((p, c))

    grown: list[tuple[Path, int | None]] = []
    for p in grown_raw:
        c = _file_dispatch_case(p, n_cases, selector)
        if c is not None and c in smoke_set:
            smoke_skipped_count += 1
            continue
        grown.append((p, c))

    def _sha_key(item: tuple[Path, int | None]) -> tuple[str, str]:
        p = item[0]
        digest = hashlib.sha256(p.name.encode("utf-8", errors="surrogateescape")).hexdigest()
        return (digest, p.as_posix())

    eff_cap = max(0, int(cap))
    grown_selected: list[tuple[Path, int | None]] = []
    if len(grown) <= eff_cap:
        grown_selected = sorted(grown, key=_sha_key)
    elif n_cases and n_cases > 0:
        # Case-stratified round-robin SHA-256 selection
        buckets: dict[int, deque[tuple[Path, int | None]]] = {}
        for item in grown:
            bucket_key = item[1] if item[1] is not None else -1
            buckets.setdefault(bucket_key, deque()).append(item)
        for bk in buckets:
            buckets[bk] = deque(sorted(buckets[bk], key=_sha_key))
        active_keys = sorted(buckets.keys())
        while len(grown_selected) < eff_cap and active_keys:
            next_keys: list[int] = []
            for bk in active_keys:
                if len(grown_selected) >= eff_cap:
                    break
                q = buckets[bk]
                if q:
                    grown_selected.append(q.popleft())
                if q:
                    next_keys.append(bk)
            active_keys = next_keys
    else:
        grown_selected = sorted(grown, key=_sha_key)[:eff_cap]

    not_judged_cap = max(0, len(grown) - len(grown_selected))

    # Interleave selected inputs across dispatch cases so broken cases blind early without starving healthy cases.
    combined = [*mandatory, *grown_selected]
    if n_cases and n_cases > 0 and combined:
        inter_buckets: dict[int, deque[Path]] = {}
        for p, c in combined:
            bk = c if c is not None else -1
            inter_buckets.setdefault(bk, deque()).append(p)
        ordered: list[Path] = []
        active = sorted(inter_buckets.keys())
        while active:
            nxt: list[int] = []
            for bk in active:
                iq = inter_buckets[bk]
                if iq:
                    ordered.append(iq.popleft())
                if iq:
                    nxt.append(bk)
            active = nxt
    else:
        ordered = [p for p, _ in combined]

    total_inputs = len(mandatory_raw) + len(grown_raw)
    return {
        "selected": ordered,
        "total": total_inputs,
        "mandatory": len(mandatory),
        "grown_total": len(grown),
        "grown_selected": len(grown_selected),
        "not_judged_cap": not_judged_cap,
        "not_judged_smoke": smoke_skipped_count,
    }


def link_cross_engine_findings(
    artifact_sha256: str,
    judge_failure: dict[str, Any] | None,
    judge_fingerprint: str | None,
    explore_report: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """
    D1b cross-engine linking: link an E-ACSL judge finding to explorer findings when they share
    the same artifact sha256 (`same_artifact`), the same normalized file+function+line (`same_site`),
    or adjacent lines within `CROSS_ENGINE_ADJACENT_LINES` in the same file+function (`adjacent_line`).
    """
    if not isinstance(explore_report, dict):
        return []
    exp_arts = explore_report.get("artifacts")
    if not isinstance(exp_arts, list):
        return []

    links: list[dict[str, Any]] = []
    seen: set[tuple[str | None, str | None, str]] = set()
    j_file = (
        normalize_file(str(judge_failure.get("file") or ""))
        if isinstance(judge_failure, dict) and judge_failure.get("file")
        else ""
    )
    j_fn = str(judge_failure.get("function") or "") if isinstance(judge_failure, dict) else ""
    j_line = int(judge_failure.get("line") or 0) if isinstance(judge_failure, dict) else 0

    for exp in exp_arts:
        if not isinstance(exp, dict):
            continue
        exp_fp = exp.get("fingerprint")
        exp_sha = str(exp.get("sha256") or "")
        exp_engine = str(exp.get("engine") or explore_report.get("engine_used") or "sanitizers")
        exp_art = str(exp.get("artifact") or "") or None
        exp_fail = exp.get("failure") if isinstance(exp.get("failure"), dict) else None

        match_kind: str | None = None
        line_delta: int | None = None
        if artifact_sha256 and exp_sha and exp_sha == artifact_sha256:
            match_kind = "same_artifact"
            if exp_fail and j_line > 0 and int(exp_fail.get("line") or 0) > 0:
                line_delta = abs(j_line - int(exp_fail.get("line") or 0))
        elif j_file and j_fn and exp_fail:
            e_file = normalize_file(str(exp_fail.get("file") or "")) if exp_fail.get("file") else ""
            e_fn = str(exp_fail.get("function") or "")
            e_line = int(exp_fail.get("line") or 0)
            if e_file == j_file and e_fn == j_fn:
                if j_line > 0 and e_line > 0:
                    delta = abs(j_line - e_line)
                    if delta == 0:
                        match_kind = "same_site"
                        line_delta = 0
                    elif delta <= CROSS_ENGINE_ADJACENT_LINES:
                        match_kind = "adjacent_line"
                        line_delta = delta
                else:
                    match_kind = "same_site"

        if match_kind is None:
            continue
        key = (judge_fingerprint, exp_fp, match_kind)
        if key in seen:
            continue
        seen.add(key)
        links.append(
            {
                "judge_fingerprint": judge_fingerprint,
                "explore_fingerprint": exp_fp,
                "explore_engine": exp_engine,
                "match": match_kind,
                "artifact_sha256": artifact_sha256 or None,
                "explore_artifact": exp_art,
                "line_delta": line_delta,
            }
        )
    return links


def _judge_error_report(
    module: str,
    *,
    profile: str = "standard",
    reason: str,
    corpus_cap: int | None = None,
    binary: str | None = None,
) -> dict[str, Any]:
    """Schema-valid `judge_report.schema.json` report for judge-level errors (e.g. `SandboxUnavailable`)."""
    prof = (profile or "standard").strip().lower()
    if prof not in JUDGE_CORPUS_CAP_BY_PROFILE:
        prof = "standard"
    cap = int(corpus_cap) if corpus_cap is not None else JUDGE_CORPUS_CAP_BY_PROFILE[prof]
    mod_name = (module or "").strip() or "unknown"
    return {
        "schema_version": JUDGE_SCHEMA_VERSION,
        "mode": "judge",
        "module": mod_name,
        "generated_at": utc_now(),
        "discovering_step": "judge",
        "engine_used": "eacsl" if binary else None,
        "profile": prof,
        "status": "judge_error",
        "binary": binary,
        "corpus_cap": max(0, cap),
        "inputs": {
            "total": 0,
            "mandatory": 0,
            "grown_total": 0,
            "grown_selected": 0,
            "selected": 0,
            "judged": 0,
            "passed": 0,
            "failed": 0,
            "not_judged": 0,
            "not_judged_breakdown": {
                "cap": 0,
                "timeout": 0,
                "blinded": 0,
                "smoke_skipped": 0,
                "error": 0,
            },
        },
        "not_judged": 0,
        "artifacts": [],
        "batch_state_only": [],
        "cross_engine_links": [],
        "smoke_skipped_cases": [],
        "blinded_cases": [],
        "partial_blinded": False,
        "telemetry": {
            "judge_s": 0.0,
            "batch_s": 0.0,
            "confirm_s": 0.0,
            "inputs_per_s": 0.0,
            "batches_run": 0,
            "fresh_confirmations": 0,
        },
        "harness_digest": None,
        "dispatch_case_count": None,
        "dispatch_selector": None,
        "reason": reason,
    }


def run_judge(
    module: str,
    build_json: dict[str, Any] | Path | str,
    corpus_dir: Path,
    *,
    extra_corpus: Sequence[Path] = (),
    explore_report: dict[str, Any] | Path | None = None,
    smoke_report: Path | None = None,
    profile: str = "standard",
    max_corpus_inputs: int | None = None,
    max_time: int = JUDGE_DEFAULT_MAX_TIME_S,
    per_input_timeout: int = DEFAULT_PER_INPUT_TIMEOUT_S,
    batch_size: int = JUDGE_BATCH_SIZE,
    scratch_dir: Path | None = None,
    sources: Sequence[str] | None = None,
    blinding_threshold: int = BLINDING_CASE_THRESHOLD,
) -> dict[str, Any]:
    """
    P2d standalone E-ACSL judge:
    - Resolves the pre-built `.e-acsl` binary from `build_json` via `resolve_prebuilt_binary`.
    - Selects all mandatory inputs (seeds, imported inputs, explorer crashes) + up to `N`
      case-stratified SHA-256 grown corpus inputs (`512` quick / `2048` standard / `4096` deep).
    - Runs inputs in `O(N)` batches, advancing strictly with `batch[culprit + 1 :]` on failure
      (handling `culprit == last` cleanly with zero infinite loops) and treating `returncode == 0`
      mid-batch exits (`P8a`) as passes before continuing with `batch[idx + 1 :]`.
    - Confirms every new fingerprint in a fresh standalone process (`crash_replay.replay_artifact`),
      separating `batch_state_only` failures from confirmed standalone candidate witnesses.
    - Tracks per-case blinding (`K_case = 16`), D1b cross-engine linking, and `not_judged` accounting.
    """
    prof = (profile or "standard").strip().lower()
    cap = int(max_corpus_inputs) if max_corpus_inputs is not None else JUDGE_CORPUS_CAP_BY_PROFILE.get(prof, 2048)

    build_doc: dict[str, Any] | None = (
        build_json if isinstance(build_json, dict) else _load_json_dict_optional(Path(build_json))
    )
    explore_doc: dict[str, Any] | None = (
        explore_report if isinstance(explore_report, dict) else _load_json_dict_optional(explore_report)
    )
    smoke_skipped = load_smoke_skipped_cases(smoke_report)

    eff_sources = list(sources or [])
    if not eff_sources and isinstance(build_doc, dict) and isinstance(build_doc.get("sources"), list):
        eff_sources = [str(s) for s in build_doc["sources"] if isinstance(s, str)]

    n_cases = dispatch_case_count(eff_sources) if eff_sources else None
    selector = (dispatch_selector(eff_sources) if eff_sources else None) or DISPATCH_SELECTOR_MODULO
    if n_cases is None and isinstance(explore_doc, dict):
        dc = explore_doc.get("dispatch_case_count")
        if isinstance(dc, int) and dc > 0:
            n_cases = dc
            selector = str(explore_doc.get("dispatch_selector") or selector)

    harness_digest = (
        explore_doc.get("harness_digest")
        if isinstance(explore_doc, dict) and explore_doc.get("harness_digest")
        else (campaign_harness_identity(module, eff_sources).get("harness_digest") if eff_sources else None)
    )

    selection = select_judge_inputs(
        corpus_dir,
        extra_corpus,
        explore_doc,
        cap=cap,
        n_cases=n_cases,
        selector=selector,
        smoke_skipped=smoke_skipped,
    )
    selected: list[Path] = list(selection["selected"])

    def _base_report(
        *,
        status: str,
        binary_str: str | None,
        passed: int,
        failed: int,
        not_judged_timeout: int = 0,
        not_judged_blinded: int = 0,
        not_judged_error: int = 0,
        artifacts: list[dict[str, Any]] | None = None,
        batch_state_only: list[dict[str, Any]] | None = None,
        cross_links: list[dict[str, Any]] | None = None,
        blinded_cases: list[dict[str, Any]] | None = None,
        partial_blinded: bool = False,
        blinded_fp: str | None = None,
        judge_s: float = 0.0,
        batch_s: float = 0.0,
        confirm_s: float = 0.0,
        batches_run: int = 0,
        fresh_confirmations: int = 0,
        reason: str | None = None,
        startup_error: str | None = None,
        omitted_dups: int = 0,
    ) -> dict[str, Any]:
        judged = passed + failed
        nj_cap = int(selection["not_judged_cap"])
        nj_smoke = int(selection["not_judged_smoke"])
        nj_total = nj_cap + nj_smoke + not_judged_timeout + not_judged_blinded + not_judged_error
        ips = round(judged / judge_s, 2) if judge_s > 0.0 and judged > 0 else 0.0
        report: dict[str, Any] = {
            "schema_version": JUDGE_SCHEMA_VERSION,
            "mode": "judge",
            "module": module,
            "generated_at": utc_now(),
            "discovering_step": "judge",
            "engine_used": "eacsl" if binary_str else None,
            "profile": prof,
            "status": status,
            "binary": binary_str,
            "corpus_cap": cap,
            "inputs": {
                "total": int(selection["total"]),
                "mandatory": int(selection["mandatory"]),
                "grown_total": int(selection["grown_total"]),
                "grown_selected": int(selection["grown_selected"]),
                "selected": len(selected),
                "judged": judged,
                "passed": passed,
                "failed": failed,
                "not_judged": nj_total,
                "not_judged_breakdown": {
                    "cap": nj_cap,
                    "timeout": not_judged_timeout,
                    "blinded": not_judged_blinded,
                    "smoke_skipped": nj_smoke,
                    "error": not_judged_error,
                },
            },
            "not_judged": nj_total,
            "artifacts": list(artifacts or []),
            "batch_state_only": list(batch_state_only or []),
            "cross_engine_links": list(cross_links or []),
            "smoke_skipped_cases": list(smoke_skipped),
            "blinded_cases": list(blinded_cases or []),
            "partial_blinded": bool(partial_blinded),
            "telemetry": {
                "judge_s": round(max(0.0, judge_s), 3),
                "batch_s": round(max(0.0, batch_s), 3),
                "confirm_s": round(max(0.0, confirm_s), 3),
                "inputs_per_s": ips,
                "batches_run": batches_run,
                "fresh_confirmations": fresh_confirmations,
            },
            "harness_digest": harness_digest,
            "dispatch_case_count": n_cases,
            "dispatch_selector": selector if n_cases is not None else None,
        }
        if blinded_fp is not None:
            report["blinded_fingerprint"] = blinded_fp
        if blinded_cases or status == "blinded":
            report["blinded_remedies"] = list(BLINDING_REMEDIES)
        if omitted_dups > 0:
            report["artifacts_omitted"] = {"duplicates": omitted_dups}
        if reason is not None:
            report["reason"] = reason
        if startup_error is not None:
            report["startup_error"] = startup_error
        return report

    try:
        eacsl_binary = fuzz_build.resolve_prebuilt_binary(build_json, "eacsl")
    except (PrebuiltBinaryError, ValueError, TypeError) as exc:
        return _base_report(
            status="skipped",
            binary_str=None,
            passed=0,
            failed=0,
            not_judged_error=len(selected),
            reason=str(exc),
        )

    seed = derive_seed(eacsl_binary, module)
    eff_batch = max(1, int(batch_size or JUDGE_BATCH_SIZE))
    pending: deque[list[Path]] = deque(selected[i : i + eff_batch] for i in range(0, len(selected), eff_batch))
    skipped_cases: set[int] = set(smoke_skipped)
    tracker = CaseBlindingTracker(threshold=blinding_threshold)
    confirmed_standalone_fps: set[str] = set()
    artifacts: list[dict[str, Any]] = []
    batch_state_only: list[dict[str, Any]] = []
    cross_links: list[dict[str, Any]] = []
    cross_link_keys: set[tuple[str | None, str | None, str, str | None]] = set()

    passed = 0
    failed = 0
    not_judged_timeout = 0
    not_judged_blinded = 0
    not_judged_error = 0
    batches_run = 0
    fresh_confirmations = 0
    batch_s = 0.0
    confirm_s = 0.0
    startup_err: str | None = None
    sandbox_err: str | None = None
    module_blinded_non_dispatch = False
    non_dispatch_blind_fp: str | None = None

    own_scratch = scratch_dir is None
    scratch = Path(scratch_dir) if scratch_dir is not None else Path(tempfile.mkdtemp(prefix=f"judge_{module}_"))
    scratch.mkdir(parents=True, exist_ok=True)
    judge_started = time.monotonic()
    deadline = judge_started + max(1, int(max_time))
    min_wall = 2 * int(per_input_timeout) + 10

    def _case_of(p: Path) -> int | None:
        return _file_dispatch_case(p, n_cases, selector)

    def _record_passes(items: Sequence[Path]) -> None:
        nonlocal passed
        for item in items:
            passed += 1
            if n_cases and n_cases > 0:
                c = _case_of(item)
                if c is not None:
                    tracker.record_pass(c)
            else:
                tracker.record_pass(0)

    def _handle_failure(culprit_path: Path, batch_output: str, batch_rc: int | None, batch_to: bool) -> None:
        nonlocal failed, confirm_s, fresh_confirmations, module_blinded_non_dispatch, non_dispatch_blind_fp
        failed += 1
        c_idx = _case_of(culprit_path)
        sha = sha256_file(culprit_path)
        size = culprit_path.stat().st_size if culprit_path.is_file() else 0
        stub_abort = parse_link_stub_abort(batch_output)
        batch_failure = None if stub_abort else parse_runtime_failure(batch_output, binary=eacsl_binary)
        batch_fp = (
            make_fingerprint(
                batch_failure["file"],
                batch_failure["function"],
                batch_failure["alarm_kind"] or batch_failure["kind"],
                batch_failure["predicate"],
            )
            if batch_failure
            else None
        )

        # Fresh-process standalone confirmation for every new fingerprint (or unparsed crash).
        need_confirm = batch_fp is None or batch_fp not in confirmed_standalone_fps
        standalone_rep: dict[str, Any] | None = None
        if need_confirm:
            fresh_confirmations += 1
            ct0 = time.monotonic()
            standalone_rep = crash_replay.replay_artifact(
                eacsl_binary,
                culprit_path,
                scratch,
                module=module,
                per_input_timeout=per_input_timeout,
            )
            confirm_s += max(0.0, time.monotonic() - ct0)
            if not standalone_rep.get("reproduced"):
                batch_state_only.append(
                    {
                        "input": culprit_path.as_posix(),
                        "sha256": sha,
                        "case": c_idx,
                        "batch_returncode": batch_rc,
                        "batch_timed_out": bool(batch_to),
                        "batch_failure": batch_failure,
                        "batch_fingerprint": batch_fp,
                        "standalone_returncode": standalone_rep.get("returncode"),
                        "standalone_timed_out": bool(standalone_rep.get("timed_out")),
                    }
                )
                return

        eff_stub = (standalone_rep.get("link_stub_abort") if standalone_rep else None) or stub_abort
        eff_failure = (
            None if eff_stub else ((standalone_rep.get("failure") if standalone_rep else None) or batch_failure)
        )
        eff_fp = (
            make_fingerprint(
                eff_failure["file"],
                eff_failure["function"],
                eff_failure["alarm_kind"] or eff_failure["kind"],
                eff_failure["predicate"],
            )
            if eff_failure
            else batch_fp
        )
        if eff_fp:
            confirmed_standalone_fps.add(eff_fp)

        links = link_cross_engine_findings(sha, eff_failure, eff_fp, explore_doc)
        for lk in links:
            lkey = (
                lk.get("judge_fingerprint"),
                lk.get("explore_fingerprint"),
                str(lk.get("match")),
                lk.get("artifact_sha256"),
            )
            if lkey not in cross_link_keys:
                cross_link_keys.add(lkey)
                cross_links.append(lk)

        art_entry: dict[str, Any] = {
            "artifact": culprit_path.as_posix(),
            "kind": _artifact_kind(culprit_path.name) or ("timeout" if batch_to else "crash"),
            "sha256": sha,
            "size_bytes": size,
            "case": c_idx,
            "engine": "eacsl",
            "discovering_step": "judge",
            "reproducible": True,
            "standalone_confirmed": True,
            "returncode": standalone_rep.get("returncode") if standalone_rep else batch_rc,
            "timed_out": bool(standalone_rep.get("timed_out")) if standalone_rep else bool(batch_to),
            "failure": eff_failure,
            "failure_source": "primary" if eff_failure else None,
            "fingerprint": eff_fp,
            "frames": (standalone_rep.get("frames") if standalone_rep else None) or stack_frames(batch_output),
            "replay_log_tail": (standalone_rep.get("log_tail") if standalone_rep else batch_output[-3000:]),
            "cross_engine_links": links,
            "harness_digest": harness_digest,
            "dispatch_case_count": n_cases,
            "dispatch_selector": selector if n_cases is not None else None,
        }
        if eff_stub is not None:
            art_entry["link_stub_abort"] = eff_stub
        elif not eff_failure:
            res_abort = (
                standalone_rep.get("resource_abort") if standalone_rep else None
            ) or parse_eacsl_resource_abort(batch_output)
            if res_abort is not None:
                art_entry["eacsl_resource_abort"] = res_abort
        artifacts.append(art_entry)

        # Update per-case (or single-entry) blinding tracker.
        if n_cases and n_cases > 0:
            if c_idx is not None and tracker.record_crash(c_idx, eff_fp):
                skipped_cases.add(c_idx)
        else:
            if tracker.record_crash(0, eff_fp):
                module_blinded_non_dispatch = True
                non_dispatch_blind_fp = eff_fp

    try:
        while pending:
            if module_blinded_non_dispatch:
                not_judged_blinded += sum(len(b) for b in pending)
                pending.clear()
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                not_judged_timeout += sum(len(b) for b in pending)
                pending.clear()
                break

            raw_batch = pending.popleft()
            if n_cases and n_cases > 0 and skipped_cases:
                batch: list[Path] = []
                for item in raw_batch:
                    c = _case_of(item)
                    if c is not None and c in skipped_cases:
                        not_judged_blinded += 1
                    else:
                        batch.append(item)
                if not batch:
                    continue
            else:
                batch = raw_batch

            batches_run += 1
            wall = min(int(per_input_timeout) * len(batch) + 30, max(int(remaining), min_wall))
            run_env = dict(SANITIZER_RUNTIME_ENV)
            if skipped_cases:
                run_env[DISPATCH_SKIP_MACRO] = format_skip_cases_env(skipped_cases)
            bt0 = time.monotonic()
            res = sandbox_exec.run_sandboxed(
                [
                    str(eacsl_binary.resolve()),
                    f"-timeout={per_input_timeout}",
                    f"-rss_limit_mb={FUZZ_RSS_LIMIT_MB}",
                    f"-seed={seed}",
                    f"-artifact_prefix={replay_artifact_dir(scratch)}/",
                    *[str(Path(f).resolve()) for f in batch],
                ],
                writable=[scratch],
                timeout_s=wall,
                limits=Limits(cpu_seconds=wall * 2, ignore_sigpipe=True),
                extra_env=run_env,
            )
            batch_s += max(0.0, time.monotonic() - bt0)
            out_text = f"{res.stdout}\n{res.stderr}"

            if res.returncode == 0 and not res.timed_out:
                # P8a: handle clean _Exit(0) mid-batch as a pass for batch[:idx+1], then continue with batch[idx+1:].
                exited_idx = _judge_input_running_at_exit(out_text, batch)
                if exited_idx is not None:
                    _record_passes(batch[: exited_idx + 1])
                    rest = batch[exited_idx + 1 :]
                    if rest:
                        pending.appendleft(rest)
                else:
                    _record_passes(batch)
                continue

            # Non-zero exit or timeout: check for startup failure before LLVMFuzzerTestOneInput.
            batch_fail_probe = parse_runtime_failure(out_text, binary=eacsl_binary)
            is_start, start_reason = is_startup_failure(batch_fail_probe, out_text)
            if is_start and _judge_input_running_at_exit(out_text, batch) is None:
                startup_err = start_reason or "startup failure before LLVMFuzzerTestOneInput"
                not_judged_error += len(batch) + sum(len(b) for b in pending)
                pending.clear()
                break

            if len(batch) == 1:
                _handle_failure(batch[0], out_text, res.returncode, res.timed_out)
                continue

            culprit = _judge_input_running_at_exit(out_text, batch)
            if culprit is not None:
                if culprit > 0:
                    _record_passes(batch[:culprit])
                _handle_failure(batch[culprit], out_text, res.returncode, res.timed_out)
                # P2d O(N) continuation: strictly advance past culprit; when culprit == len(batch) - 1,
                # `rest` is empty so we never re-enqueue or loop.
                rest = batch[culprit + 1 :]
                if rest:
                    pending.appendleft(rest)
                continue

            # Output did not identify the running input: bisect deterministically.
            mid = len(batch) // 2
            pending.appendleft(batch[mid:])
            pending.appendleft(batch[:mid])
    except SandboxUnavailable as exc:
        sandbox_err = f"sandbox_unavailable: {exc}"
        accounted = passed + failed + not_judged_timeout + not_judged_blinded + not_judged_error
        not_judged_error += max(0, len(selected) - accounted)
        pending.clear()
    finally:
        if own_scratch:
            shutil.rmtree(scratch, ignore_errors=True)

    judge_s = max(0.0, time.monotonic() - judge_started)
    collapsed_arts, omitted_dups = _collapse_duplicate_artifacts(artifacts)
    blinded_rep = tracker.blinded_cases_report() if (n_cases and n_cases > 0) else []
    partial_blinded = False
    blinded_fp: str | None = non_dispatch_blind_fp

    if sandbox_err is not None:
        status = "judge_error"
    elif startup_err is not None:
        status = "startup_error"
    elif module_blinded_non_dispatch:
        status = "blinded"
    elif blinded_rep:
        active_cases = max(0, (n_cases or 0) - len(set(smoke_skipped)))
        all_blind = active_cases > 0 and len(tracker.blinded_case_ids()) >= active_cases
        status = "blinded" if all_blind else "partial_blinded"
        partial_blinded = not all_blind
    elif collapsed_arts:
        status = "crash_found"
    elif not_judged_timeout > 0:
        status = "partial"
    else:
        status = "clean"

    return _base_report(
        status=status,
        binary_str=str(eacsl_binary),
        passed=passed,
        failed=failed,
        not_judged_timeout=not_judged_timeout,
        not_judged_blinded=not_judged_blinded,
        not_judged_error=not_judged_error,
        artifacts=collapsed_arts,
        batch_state_only=batch_state_only,
        cross_links=cross_links,
        blinded_cases=blinded_rep,
        partial_blinded=partial_blinded,
        blinded_fp=blinded_fp,
        judge_s=judge_s,
        batch_s=batch_s,
        confirm_s=confirm_s,
        batches_run=batches_run,
        fresh_confirmations=fresh_confirmations,
        reason=sandbox_err,
        startup_error=startup_err,
        omitted_dups=omitted_dups,
    )


def _run_judge_mode(args) -> dict:
    return run_judge(
        args.module,
        args.build_json,
        args.corpus_dir,
        extra_corpus=args.extra_corpus,
        explore_report=args.explore_report,
        smoke_report=args.smoke_report,
        profile=args.profile,
        max_corpus_inputs=args.max_corpus_inputs,
        max_time=args.max_time,
        per_input_timeout=args.per_input_timeout,
        batch_size=args.batch_size,
        scratch_dir=args.scratch_dir,
        sources=args.sources,
    )


def _judge_skipped_cases(judge_report: dict[str, Any] | None, n_cases: int | None, selector: str) -> list[int]:
    """Dispatch case indices that crashed or blinded during `judge` (to pre-skip in `eacsl-fuzz`)."""
    if not isinstance(judge_report, dict):
        return []
    cases: set[int] = set()
    for entry in judge_report.get("blinded_cases") or []:
        if isinstance(entry, dict) and isinstance(entry.get("case"), int) and entry["case"] >= 0:
            cases.add(int(entry["case"]))
    for art in judge_report.get("artifacts") or []:
        if not isinstance(art, dict):
            continue
        c = art.get("case")
        if isinstance(c, int) and c >= 0:
            cases.add(c)
        elif n_cases and n_cases > 0:
            dc = artifact_dispatch_case(art, n_cases, selector)
            if dc is not None and dc >= 0:
                cases.add(dc)
    return sorted(cases)


def _run_eacsl_fuzz_mode(args) -> dict:
    """
    P2e `eacsl-fuzz` subcommand (deep profile only): runs the remaining 1/5 CPU budget on the
    pre-built `.e-acsl` binary, skipping cases that crashed or blinded in `judge` and cases
    quarantined by `smoke`.
    """
    prof = (args.profile or "deep").strip().lower()
    smoke_skipped = load_smoke_skipped_cases(args.smoke_report)
    judge_doc = _load_json_dict_optional(args.judge_report)
    eff_sources = _sources_for_mode(args)
    n_cases = dispatch_case_count(eff_sources) if eff_sources else None
    selector = (dispatch_selector(eff_sources) if eff_sources else None) or DISPATCH_SELECTOR_MODULO
    if n_cases is None and isinstance(judge_doc, dict) and isinstance(judge_doc.get("dispatch_case_count"), int):
        dc = int(judge_doc["dispatch_case_count"])
        if dc > 0:
            n_cases = dc
            selector = str(judge_doc.get("dispatch_selector") or selector)
    judge_skipped = _judge_skipped_cases(judge_doc, n_cases, selector)

    share_cpu_s = eacsl_fuzz_budget_cpu_s(args.fuzz_budget, prof) if args.fuzz_budget is not None else None
    if prof != "deep":
        return {
            "mode": "eacsl-fuzz",
            "module": args.module,
            "status": "skipped",
            "engine_used": "eacsl",
            "discovering_step": "eacsl_fuzz",
            "reason": f"eacsl-fuzz runs under 'deep' profile only (got {prof!r})",
            "smoke_skipped_cases": smoke_skipped,
            "judge_skipped_cases": judge_skipped,
            "blinded_cases": [],
            "partial_blinded": False,
            "unspent_budget_s": 0.0,
            "artifacts": [],
            "telemetry": merge_telemetry([], build_s=0.0),
        }

    try:
        eacsl_binary = fuzz_build.resolve_prebuilt_binary(args.build_json, "eacsl")
    except (PrebuiltBinaryError, ValueError, TypeError) as exc:
        return {
            "mode": "eacsl-fuzz",
            "module": args.module,
            "status": "skipped",
            "engine_used": None,
            "discovering_step": "eacsl_fuzz",
            "reason": str(exc),
            "smoke_skipped_cases": smoke_skipped,
            "judge_skipped_cases": judge_skipped,
            "blinded_cases": [],
            "partial_blinded": False,
            "unspent_budget_s": float(share_cpu_s or 0.0),
            "artifacts": [],
            "telemetry": merge_telemetry([], build_s=0.0),
        }

    pre_skipped = sorted(set(smoke_skipped) | set(judge_skipped))
    whole_blinded = (isinstance(judge_doc, dict) and judge_doc.get("status") == "blinded") or (
        n_cases is not None and n_cases > 0 and len(pre_skipped) >= n_cases
    )
    if whole_blinded:
        return {
            "mode": "eacsl-fuzz",
            "module": args.module,
            "status": "unspent_blinded",
            "engine_used": "eacsl",
            "discovering_step": "eacsl_fuzz",
            "reason": "module was fully blinded in judge; eacsl-fuzz 1/5 share recorded as unspent_blinded",
            "smoke_skipped_cases": smoke_skipped,
            "judge_skipped_cases": judge_skipped,
            "blinded_cases": list((judge_doc or {}).get("blinded_cases") or []),
            "partial_blinded": False,
            "blinded_remedies": list(BLINDING_REMEDIES),
            "unspent_budget_s": float(share_cpu_s if share_cpu_s is not None else (args.max_time or 0)),
            "artifacts": [],
            "telemetry": merge_telemetry([], build_s=0.0),
        }

    workers = resolve_workers(args.workers)
    if str(args.workers).strip().lower() == "auto" and share_cpu_s is not None and share_cpu_s > 0:
        workers = max(1, min(workers, max(1, share_cpu_s // MIN_FUZZ_WALL_S)))
    jobs = args.jobs if args.jobs else workers
    max_time = campaign_wall_time(args.max_time, share_cpu_s, workers)
    sizing = {
        "workers": workers,
        "jobs": jobs,
        "max_time": max_time,
        "fuzz_budget_cpu_s": share_cpu_s,
        "rss_limit_mb": FUZZ_RSS_LIMIT_MB,
        "per_input_timeout": args.per_input_timeout,
    }
    dict_file, dict_info = resolve_campaign_dictionary(
        args.dict,
        eff_sources,
        args.module,
        args.corpus_dir,
        auto=not getattr(args, "no_auto_dict", False),
        cppflags=args.cppflags,
    )
    skippable = dispatch_skippable_cases(eff_sources, n_cases) if n_cases is not None else None
    runtime_skip = bool(
        n_cases is not None
        and n_cases <= DISPATCH_RUNTIME_SKIP_MAX_CASES
        and (harness_supports_runtime_skip_cases(eff_sources) if eff_sources else True)
    )
    single_process: dict[str, str] = {}

    def _campaign(binary: Path, seconds: int, fork: bool, *, extra_env: dict[str, str] | None = None) -> dict:
        run = run_fuzz_campaign(
            binary,
            args.corpus_dir,
            args.artifacts_dir,
            seconds,
            dict_file,
            args.per_input_timeout,
            extra_corpus=args.extra_corpus,
            jobs=jobs,
            workers=workers,
            fork=fork,
            extra_env=extra_env,
            single_process_reason=single_process.get("reason"),
        )
        if run.get("single_process_reason") and "reason" not in single_process:
            single_process["reason"] = str(run["single_process_reason"])
        return run

    def _no_rebuild(mask: int) -> tuple[Path | None, dict]:
        return None, {"compile": {"returncode": 1, "log_tail": "P7f: no compilation inside eacsl-fuzz lease"}}

    fuzz = run_campaign_rounds(
        eacsl_binary,
        max_time,
        campaign=_campaign,
        rebuild=_no_rebuild,
        n_cases=n_cases,
        keep_going=not args.stop_on_first_crash,
        skippable=skippable,
        runtime_skip=runtime_skip,
        selector=selector,
        workers=workers,
        initial_skipped=pre_skipped,
        explore_judge=True,
        build_s=0.0,
        smoke_skipped_cases=smoke_skipped,
    )
    for art in fuzz.get("artifacts") or []:
        art["engine"] = "eacsl"
        art["discovering_step"] = "eacsl_fuzz"
    res: dict[str, Any] = {
        "mode": "eacsl-fuzz",
        "module": args.module,
        "sources": eff_sources,
        "engine_used": "eacsl",
        "discovering_step": "eacsl_fuzz",
        "binary": str(eacsl_binary),
        "smoke_skipped_cases": smoke_skipped,
        "judge_skipped_cases": judge_skipped,
        "dictionary": dict_info,
        "sizing": sizing,
        **fuzz,
    }
    res.setdefault("blinded_cases", [])
    res.setdefault("partial_blinded", False)
    return res


def _run_campaign_mode(args) -> dict:
    explore_judge = resources.fuzz_explore_judge_enabled()
    profile = str(getattr(args, "profile", "standard") or "standard").strip().lower()
    smoke_skipped = load_smoke_skipped_cases(getattr(args, "smoke_report", None))
    eff_sources = _sources_for_mode(args)
    build_json_path: Path | None = getattr(args, "build_json", None)

    workers = resolve_workers(args.workers)
    effective_budget = (
        explore_budget_cpu_s(args.fuzz_budget, profile)
        if (explore_judge and args.fuzz_budget is not None)
        else args.fuzz_budget
    )
    if (
        explore_judge
        and str(args.workers).strip().lower() == "auto"
        and effective_budget is not None
        and effective_budget > 0
    ):
        workers = max(1, min(workers, max(1, effective_budget // MIN_FUZZ_WALL_S)))
    jobs = args.jobs if args.jobs else workers
    effective_max_time = args.max_time
    if explore_judge and effective_max_time is not None and args.fuzz_budget is None and profile == "deep":
        effective_max_time = max(1, (effective_max_time * 4) // 5)
    max_time = campaign_wall_time(effective_max_time, effective_budget, workers)
    sizing = {
        "workers": workers,
        "jobs": jobs,
        "max_time": max_time,
        "fuzz_budget_cpu_s": effective_budget,
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
            "sources": eff_sources,
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

    # P2a Explore mode under FRAMAC_FUZZ_EXPLORE_JUDGE + --engine auto (or --engine sanitizers):
    # executes ASan+UBSan using the pre-built .san binary (or compiled sanitizer binary when
    # --build-json is omitted), setting discovering_step = "explore", with 100% budget (quick/standard)
    # or 4/5 budget (deep). E-ACSL judging runs in the standalone `judge` subcommand.
    if explore_judge and args.engine in ("auto", "sanitizers"):
        return _run_explore_campaign_mode(
            args,
            eff_sources=eff_sources,
            build_json_path=build_json_path,
            smoke_skipped=smoke_skipped,
            profile=profile,
            workers=workers,
            jobs=jobs,
            max_time=max_time,
            effective_budget=effective_budget,
            sizing=sizing,
            use_cache=use_cache,
        )

    build_t0 = time.monotonic()
    build = fuzz_build.build_module_binary(eff_sources, args.out_bin, **_build_options(args))
    build_s = max(0.0, time.monotonic() - build_t0)
    comp = build["compile"]
    engine_used = build["engine_used"]
    res: dict = {"mode": "campaign", "module": args.module}
    if comp["returncode"] != 0:
        res.update({"status": "compile_error", "engine_used": engine_used, "compile": comp})
    else:
        attribution_builder = None
        if engine_used == "eacsl" and not args.no_attribution_replay:
            attribution_builder = fuzz_build._sanitizer_attribution_builder(
                build.get("sources") or eff_sources, args.out_bin, args.cppflags, args.ldflags, use_cache=use_cache
            )

        warm_started = cache.warm_start_corpus(args.module, args.corpus_dir) if (args.module and use_cache) else 0
        dict_file, dict_info = resolve_campaign_dictionary(
            args.dict,
            eff_sources,
            args.module,
            args.corpus_dir,
            auto=not getattr(args, "no_auto_dict", False),
            cppflags=args.cppflags,
        )

        n_cases = dispatch_case_count(eff_sources)
        selector = dispatch_selector(eff_sources) or DISPATCH_SELECTOR_MODULO
        skippable = dispatch_skippable_cases(eff_sources, n_cases) if n_cases is not None else None
        harness_runtime_skip = bool(
            n_cases is not None
            and n_cases <= DISPATCH_RUNTIME_SKIP_MAX_CASES
            and harness_supports_runtime_skip_cases(eff_sources)
        )

        def _engine_campaign(engine: str, binary: Path, seconds: int, eng_build_s: float = 0.0) -> dict:
            attribution = attribution_builder if engine == "eacsl" else None
            # The harness reads the skip set with getenv(); in an E-ACSL build the runtime's
            # argv/environ setup leaves `environ` empty unless the `environ_keep` shim is linked
            # (-Wl,--wrap=__e_acsl_memory_init). Without it, skip with rebuilds as for an older harness.
            shim = (comp.get("environ_keep") or {}).get("status") if engine == "eacsl" else None
            runtime_skip = harness_runtime_skip and (engine != "eacsl" or shim == "built")

            # Once a round ran in one process (run_fuzz_campaign), every later round of this engine does too.
            single_process: dict[str, str] = {}

            def _campaign(binary: Path, seconds: int, fork: bool, *, extra_env: dict[str, str] | None = None) -> dict:
                run = run_fuzz_campaign(
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
                    extra_env=extra_env,
                    single_process_reason=single_process.get("reason"),
                )
                if run.get("single_process_reason") and "reason" not in single_process:
                    single_process["reason"] = str(run["single_process_reason"])
                return run

            def _rebuild(mask: int) -> tuple[Path | None, dict]:
                opts = _build_options(args)
                # Same engine as the round before, so every round checks the same properties.
                opts["engine"] = engine
                opts["use_cache"] = False
                opts["cppflags"] = f"{opts['cppflags'] or ''} {dispatch_skip_cppflags(mask)}".strip()
                skip_bin = (
                    args.out_json.parent
                    / f".skip_{args.out_bin.name}"
                    / f"{args.out_bin.stem}_skip{args.out_bin.suffix}"
                )
                rebuilt = fuzz_build.build_module_binary(eff_sources, skip_bin, **opts)
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
                runtime_skip=runtime_skip,
                selector=selector,
                workers=workers,
                initial_skipped=smoke_skipped or None,
                explore_judge=explore_judge,
                build_s=eng_build_s,
                smoke_skipped_cases=smoke_skipped or None,
            )
            if harness_runtime_skip and not runtime_skip and isinstance(out.get("keep_going"), dict):
                out["keep_going"]["runtime_skip_unavailable"] = (
                    f"E-ACSL environ shim {shim or 'not built'}: getenv() would not see FRAMAC_FUZZ_SKIP_CASES, "
                    "so skipped cases are rebuilt out with -DFRAMAC_FUZZ_SKIP_CASES"
                )
            for art in out.get("artifacts") or []:
                art["engine"] = engine
            return out

        # `auto` with a working E-ACSL build fuzzes with both engines, half the time each: ASan+UBSan
        # first (faster, and it catches what E-ACSL does not check, such as heap-use-after-free on a reused block), then
        # E-ACSL on the grown corpus, which replays every corpus input under its contract checks.
        second = None
        san_build_s = 0.0
        if args.engine == "auto" and engine_used == "eacsl":
            st0 = time.monotonic()
            san = fuzz_build.build_module_binary(
                eff_sources, args.out_bin, **{**_build_options(args), "engine": "sanitizers"}
            )
            san_build_s = max(0.0, time.monotonic() - st0)
            if san["compile"]["returncode"] == 0 and san["engine_used"] == "sanitizers":
                second = san
            else:
                res["dual_engine_skipped"] = "sanitizer build failed"
        if second is None:
            fuzz = _engine_campaign(engine_used, Path(comp["binary"]), max_time, eng_build_s=build_s)
            res.update({"sources": eff_sources, "engine_used": engine_used, "compile": comp, **fuzz})
        else:
            share = max(MIN_FUZZ_WALL_S, max_time // 2)
            runs = {
                "sanitizers": _engine_campaign(
                    "sanitizers", Path(second["compile"]["binary"]), share, eng_build_s=san_build_s
                ),
                "eacsl": _engine_campaign("eacsl", Path(comp["binary"]), share, eng_build_s=build_s),
            }
            fuzz = merge_engine_campaigns(runs)
            res.update({"sources": eff_sources, "engine_used": DUAL_ENGINE, "compile": comp, **fuzz})
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
        if smoke_skipped:
            res["smoke_skipped_cases"] = smoke_skipped
    res["sizing"] = sizing
    if build["engine_fallback_reason"]:
        res["engine_fallback_reason"] = build["engine_fallback_reason"]
    if build["eacsl_compile_attempt"] is not None:
        res["eacsl_compile_attempt"] = build["eacsl_compile_attempt"]
    if build.get("link_repair"):
        res["link_repair"] = build["link_repair"]
    if build.get("attempts"):
        res["build_attempts"] = build["attempts"]
    note_security_props(res, build_security_props(build))
    induced = harness_induced_failures(res.get("artifacts"))
    if induced:
        res["security_props_harness_induced"] = induced
        for item in induced:
            print(
                f"security props [{args.module or 'module'}]: harness-induced: {item['property']} failed in "
                f"{item['function']}, called by harness function {item['caller']} ({item['artifact']}): "
                "not a candidate against the target",
                file=sys.stderr,
            )
    res["diagnostic_hints"] = derive_eacsl_diagnostic_hints(res)
    return res


def _run_explore_campaign_mode(
    args,
    *,
    eff_sources: list[str],
    build_json_path: Path | None,
    smoke_skipped: list[int],
    profile: str,
    workers: int,
    jobs: int,
    max_time: int,
    effective_budget: int | None,
    sizing: dict[str, Any],
    use_cache: bool,
) -> dict[str, Any]:
    """
    P2a Explore mode under `FRAMAC_FUZZ_EXPLORE_JUDGE`:
    Resolves the pre-built `.san` binary via `fuzz_build.resolve_prebuilt_binary(build_json, "sanitizers")`
    (falling back to `.e-acsl` if sanitizers failed, or compiling sanitizers when `--build-json` is absent),
    runs optional P6a floor pass + P6b shared pass with per-case blinding and smoke-quarantined skips,
    and stamps `discovering_step = "explore"`.
    """
    build_s = 0.0
    build_doc: dict[str, Any] | None = None
    compile_rec: dict[str, Any] | None = None
    engine_used = "sanitizers"
    binary_path: Path | None = None
    dual_skipped_note: str | None = None

    if build_json_path is not None:
        build_doc = _load_json_dict_optional(build_json_path)
        try:
            binary_path = fuzz_build.resolve_prebuilt_binary(build_json_path, "sanitizers")
            engine_used = "sanitizers"
        except PrebuiltBinaryError as san_exc:
            if args.engine == "auto":
                try:
                    binary_path = fuzz_build.resolve_prebuilt_binary(build_json_path, "eacsl")
                    engine_used = "eacsl"
                    dual_skipped_note = f"sanitizer prebuilt binary unavailable ({san_exc})"
                except PrebuiltBinaryError as eacsl_exc:
                    return {
                        "mode": "campaign",
                        "module": args.module,
                        "sources": eff_sources,
                        "status": "compile_error",
                        "engine_used": "sanitizers",
                        "discovering_step": "explore",
                        "reason": str(eacsl_exc),
                        "smoke_skipped_cases": smoke_skipped,
                        "blinded_cases": [],
                        "partial_blinded": False,
                        "artifacts": [],
                        "sizing": sizing,
                        "telemetry": merge_telemetry([], build_s=0.0),
                    }
            else:
                return {
                    "mode": "campaign",
                    "module": args.module,
                    "sources": eff_sources,
                    "status": "compile_error",
                    "engine_used": "sanitizers",
                    "discovering_step": "explore",
                    "reason": str(san_exc),
                    "smoke_skipped_cases": smoke_skipped,
                    "blinded_cases": [],
                    "partial_blinded": False,
                    "artifacts": [],
                    "sizing": sizing,
                    "telemetry": merge_telemetry([], build_s=0.0),
                }
        if isinstance(build_doc, dict):
            compile_rec = (
                build_doc.get("sanitizer_compile")
                if engine_used == "sanitizers" and isinstance(build_doc.get("sanitizer_compile"), dict)
                else build_doc.get("compile")
            )
    else:
        build_t0 = time.monotonic()
        opts = {**_build_options(args), "engine": "sanitizers"}
        build = fuzz_build.build_module_binary(eff_sources, args.out_bin, **opts)
        build_s = max(0.0, time.monotonic() - build_t0)
        compile_rec = build["compile"]
        engine_used = build["engine_used"]
        if compile_rec["returncode"] != 0 and args.engine == "auto":
            et0 = time.monotonic()
            eb = fuzz_build.build_module_binary(
                eff_sources, args.out_bin, **{**_build_options(args), "engine": "eacsl"}
            )
            build_s += max(0.0, time.monotonic() - et0)
            if eb["compile"]["returncode"] == 0:
                compile_rec = eb["compile"]
                engine_used = "eacsl"
                dual_skipped_note = "sanitizer build failed"
        if compile_rec["returncode"] != 0:
            return {
                "mode": "campaign",
                "module": args.module,
                "sources": eff_sources,
                "status": "compile_error",
                "engine_used": engine_used,
                "discovering_step": "explore",
                "compile": compile_rec,
                "smoke_skipped_cases": smoke_skipped,
                "blinded_cases": [],
                "partial_blinded": False,
                "artifacts": [],
                "sizing": sizing,
                "telemetry": merge_telemetry([], build_s=build_s),
            }
        binary_path = Path(str(compile_rec["binary"]))

    assert binary_path is not None
    warm_started = cache.warm_start_corpus(args.module, args.corpus_dir) if (args.module and use_cache) else 0
    dict_file, dict_info = resolve_campaign_dictionary(
        args.dict,
        eff_sources,
        args.module,
        args.corpus_dir,
        auto=not getattr(args, "no_auto_dict", False),
        cppflags=args.cppflags,
    )

    n_cases = dispatch_case_count(eff_sources) if eff_sources else None
    selector = (dispatch_selector(eff_sources) if eff_sources else None) or DISPATCH_SELECTOR_MODULO
    skippable = dispatch_skippable_cases(eff_sources, n_cases) if (eff_sources and n_cases is not None) else n_cases
    runtime_skip = bool(
        n_cases is not None
        and n_cases <= DISPATCH_RUNTIME_SKIP_MAX_CASES
        and (harness_supports_runtime_skip_cases(eff_sources) if eff_sources else True)
    )
    supports_only = harness_supports_only_case(eff_sources) if eff_sources else True

    floor_result: dict[str, Any] | None = None
    floor_artifacts: list[dict[str, Any]] = []
    pre_blinded: list[dict[str, Any]] = []
    shared_initial_skipped: list[int] = list(smoke_skipped)
    eff_workers = workers
    eff_jobs = jobs
    eff_max_time = max_time

    single_process: dict[str, str] = {}
    attribution_builder = None
    if engine_used == "eacsl" and not args.no_attribution_replay:
        attribution_builder = fuzz_build._sanitizer_attribution_builder(
            eff_sources, args.out_bin, args.cppflags, args.ldflags, use_cache=use_cache
        )

    if (
        n_cases is not None
        and n_cases > 0
        and not args.stop_on_first_crash
        and not getattr(args, "no_floor_pass", False)
    ):
        floor_result = run_floor_pass(
            binary_path,
            args.corpus_dir,
            args.artifacts_dir,
            n_cases=n_cases,
            selector=selector,
            supports_only_case=supports_only,
            profile=profile,
            extra_corpus=args.extra_corpus,
            smoke_skipped=smoke_skipped,
            dict_file=dict_file,
            per_input_timeout=args.per_input_timeout,
            module=args.module,
            single_process=single_process,
        )
        floor_artifacts = list(floor_result.get("artifacts") or [])
        pre_blinded = list(floor_result.get("blinded_cases") or [])
        shared_initial_skipped = sorted(set(shared_initial_skipped) | set(floor_result.get("skip_for_shared") or []))
        peak_mb = floor_result.get("peak_per_worker_mb")
        if peak_mb is not None and str(args.workers).strip().lower() == "auto":
            sized_workers = resources.fuzz_workers_from_rss(peak_rss_mb=float(peak_mb))
            if effective_budget is not None and effective_budget > 0:
                sized_workers = max(1, min(sized_workers, max(1, effective_budget // MIN_FUZZ_WALL_S)))
            eff_workers = sized_workers
            eff_jobs = args.jobs if args.jobs else eff_workers
            eff_max_time = campaign_wall_time(
                args.max_time if (args.max_time is None or profile != "deep") else max(1, (args.max_time * 4) // 5),
                effective_budget,
                eff_workers,
            )
            sizing["workers"] = eff_workers
            sizing["jobs"] = eff_jobs
            sizing["max_time"] = eff_max_time
            sizing["peak_per_worker_mb"] = peak_mb

    def _campaign(binary: Path, seconds: int, fork: bool, *, extra_env: dict[str, str] | None = None) -> dict:
        run = run_fuzz_campaign(
            binary,
            args.corpus_dir,
            args.artifacts_dir,
            seconds,
            dict_file,
            args.per_input_timeout,
            extra_corpus=args.extra_corpus,
            attribution_builder=attribution_builder,
            jobs=eff_jobs,
            workers=eff_workers,
            fork=fork,
            extra_env=extra_env,
            single_process_reason=single_process.get("reason"),
        )
        if run.get("single_process_reason") and "reason" not in single_process:
            single_process["reason"] = str(run["single_process_reason"])
        return run

    def _rebuild(mask: int) -> tuple[Path | None, dict]:
        if build_json_path is not None:
            return None, {"compile": {"returncode": 1, "log_tail": "P7f: no compilation inside explore fuzz lease"}}
        opts = {**_build_options(args), "engine": engine_used, "use_cache": False}
        opts["cppflags"] = f"{opts['cppflags'] or ''} {dispatch_skip_cppflags(mask)}".strip()
        skip_bin = (
            args.out_json.parent / f".skip_{args.out_bin.name}" / f"{args.out_bin.stem}_skip{args.out_bin.suffix}"
        )
        rebuilt = fuzz_build.build_module_binary(eff_sources, skip_bin, **opts)
        ok = rebuilt["compile"]["returncode"] == 0 and rebuilt["engine_used"] == engine_used
        return (Path(rebuilt["compile"]["binary"]) if ok else None), rebuilt

    shared_t0 = time.monotonic()
    fuzz = run_campaign_rounds(
        binary_path,
        eff_max_time,
        campaign=_campaign,
        rebuild=_rebuild,
        n_cases=n_cases,
        keep_going=not args.stop_on_first_crash,
        skippable=skippable,
        runtime_skip=runtime_skip,
        selector=selector,
        workers=eff_workers,
        initial_skipped=shared_initial_skipped,
        explore_judge=True,
        build_s=build_s,
        pre_blinded_cases=pre_blinded,
        smoke_skipped_cases=smoke_skipped,
    )
    shared_s = max(0.0, time.monotonic() - shared_t0)

    # Merge floor pass artifacts + shared pass artifacts cleanly.
    all_arts: list[dict[str, Any]] = []
    seen_art_keys: set[str] = set()
    for a in [*floor_artifacts, *(fuzz.get("artifacts") or [])]:
        key = str(a.get("sha256") or a.get("artifact") or "")
        if key not in seen_art_keys:
            seen_art_keys.add(key)
            all_arts.append(a)
    merged_arts, extra_dups = _collapse_duplicate_artifacts(all_arts)
    for art in merged_arts:
        art["engine"] = engine_used
        art["discovering_step"] = "explore"
    fuzz["artifacts"] = merged_arts
    if extra_dups:
        omitted = dict(fuzz.get("artifacts_omitted") or {})
        omitted["duplicates"] = omitted.get("duplicates", 0) + extra_dups
        fuzz["artifacts_omitted"] = omitted
    if floor_artifacts and fuzz.get("status") == "clean":
        fuzz["status"] = classify_campaign(0, False, merged_arts)

    tels = [floor_result.get("telemetry") if floor_result else None, fuzz.get("telemetry")]
    fuzz["telemetry"] = merge_telemetry(
        tels,
        build_s=build_s,
        floor_s=floor_result.get("floor_s") if floor_result else None,
        shared_s=shared_s,
    )

    published = (
        cache.publish_corpus(args.module, args.corpus_dir)
        if args.module and use_cache and fuzz.get("status") != "insufficient_memory"
        else 0
    )
    res: dict[str, Any] = {
        "mode": "campaign",
        "module": args.module,
        "sources": eff_sources,
        "engine_used": engine_used,
        "discovering_step": "explore",
        "binary": str(binary_path),
        "smoke_skipped_cases": smoke_skipped,
        "dictionary": dict_info,
        "sizing": sizing,
        **fuzz,
    }
    res.setdefault("blinded_cases", [])
    res.setdefault("partial_blinded", False)
    if compile_rec is not None:
        res["compile"] = compile_rec
        if engine_used == "eacsl" and compile_rec.get("reduced_checks"):
            res["reduced_checks"] = compile_rec["reduced_checks"]
    if dual_skipped_note is not None:
        res["dual_engine_skipped"] = dual_skipped_note
    if floor_result is not None:
        res["floor_pass"] = {
            "cases": floor_result["cases"],
            "peak_per_worker_mb": floor_result["peak_per_worker_mb"],
            "floor_s": floor_result["floor_s"],
        }
    if warm_started or published:
        res["corpus_cache"] = {"warm_started": warm_started, "published": published}
    res["diagnostic_hints"] = derive_eacsl_diagnostic_hints(res)
    return res


if __name__ == "__main__":
    sys.exit(main())
