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
   A replayed input that crashes outside the checked functions (a seed that reproduces a known bug
   elsewhere in the module), with no E-ACSL report or with an E-ACSL failure in a function that is
   not checked and was not reached through one, is dropped and the rest replayed again, at most
   GUARDRAIL_MAX_EXCLUDED_INPUTS times; `excluded_inputs` lists each with its crash (and the E-ACSL
   `failure` and `fingerprint`). Such a failure is never a `code_fault` or `rejected_overconstrained`
   of the contract under check. When the input is a mutation of the burst, not a corpus file, the
   corpus is replayed again without mutations and `mutations_skipped` holds the crash. When the
   input still cannot be dropped, or past the limit, the status is `guardrail_error` and
   `outside_checked_functions` holds the failure.
   A replayed input that hangs (libFuzzer's per-input `-timeout`) says nothing about the contract either: it is
   dropped the same way, its entry has `kind: timeout`, and a hanging mutation skips the burst. `timeout_s` bounds
   all the replays together. When the hang cannot be dropped, every input hung, the limit or the wall budget is
   reached, the status is `guardrail_error` and `replay_hang` holds the hang: never a pass, a `code_fault` or a
   rejected contract. `corpus_replayed` counts the inputs left, and a pass that dropped a hang is not cached.
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
from collections import Counter
from collections.abc import Iterable, Sequence
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cache  # noqa: E402
import crash_replay  # noqa: E402
import fuzz_build  # noqa: E402
import fuzz_coverage  # noqa: E402
import prover_candidates  # noqa: E402
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
    needs_attribution,
    parse_eacsl_failure,
    parse_eacsl_resource_abort,
    parse_runtime_failure,
    parse_sanitizer_failure,
    stable_ubsan_message,
    stack_frames,
)
from fingerprint import (  # noqa: E402
    make_fingerprint,
)
from framac_common import (  # noqa: E402
    ArtifactError,
    normalize_flag_args,
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
) -> dict:
    """
    A campaign that keeps going after a crash, within `max_time` wall seconds of fuzzing in all, which
    is `max_time * workers` CPU-seconds. A crash's
    case is its input's first byte decoded with the harness's `selector` (`dispatch_selector`).

    `campaign(binary, max_time, fork)` runs one libFuzzer campaign (run_fuzz_campaign) and
    `rebuild(mask)` returns (binary, build record) for a build skipping the dispatch cases set in
    `mask`, binary None when the build failed. When `runtime_skip` is True, `campaign` is called with
    `extra_env={FRAMAC_FUZZ_SKIP_CASES: ...}` on the existing `binary` and `rebuild` is never called.

    - A `dispatch` harness (`n_cases`) runs in rounds: each case an input crashed in is skipped from
      the next round on, so a shallow bug stops ending every run and the other cases get the rest of
      the time. Rounds end when a round finds no new crashing case, every case is skipped, less than
      MIN_ROUND_CPU_S CPU-seconds (wall seconds times `workers`) or a whole wall second are left. A round's
      wall budget is the wall time left, rounded down (`-max_total_time`), so no round overruns the
      campaign. A round's new crashing cases cannot be skipped
      (`unskippable_case`: cases `skippable` and above, for a harness generated before every case
      was skippable), or a rebuild fails. In the last two, the time left runs in fork mode with
      crashes ignored on the last binary built (`fork_fallback`).
    - Any other harness runs once in fork mode with crashes ignored.
    - Without `keep_going`, one campaign that stops at the first crash, as before.
    """
    if not keep_going:
        return campaign(binary, max_time, False)
    if not n_cases:
        res = campaign(binary, max_time, True)
        res["keep_going"] = {"mode": "fork"}
        return res
    skippable = n_cases if skippable is None else min(skippable, n_cases)
    if runtime_skip:
        skippable = min(skippable, DISPATCH_RUNTIME_SKIP_MAX_CASES)

    skipped: set[int] = set()
    rounds: list[dict] = []
    collected: list[dict] = []
    spent = 0.0
    last: dict = {}
    fallback_reason: str | None = None
    skip_error: str | None = None
    while True:
        # A round never runs longer than the wall time the campaign has left. The first round always runs.
        budget = max(1, int(max_time - spent)) if not rounds else int(max_time - spent)
        started = time.monotonic()
        if runtime_skip:
            skip_env = {DISPATCH_SKIP_MACRO: format_skip_cases_env(skipped)} if skipped else None
            last = campaign(binary, budget, False, extra_env=skip_env)
        else:
            last = campaign(binary, budget, False)
        spent += time.monotonic() - started
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
        rnd = {
            "skipped_cases": sorted(skipped),
            "max_time": budget,
            "status": last.get("status"),
            "returncode": last.get("returncode"),
            "artifacts": len(arts),
            "crashed_cases": crashed,
        }
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
            next_binary, build = rebuild(mask)
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
    if skip_error:
        # Not ok: the campaign did not fuzz the cases it meant to. The crashes found stay listed (and
        # `status` keeps them for ingest); `error_summary` carries the reason to the reader.
        out["keep_going"].update(status="error", error=skip_error)
        out["error_summary"] = [*(out.get("error_summary") or []), f"keep-going rounds: {skip_error}"]
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
    merged = {
        "status": status,
        "returncode": last.get("returncode"),
        "timed_out": any(bool(r.get("timed_out")) for r in runs.values()),
        "sandbox": last.get("sandbox"),
        "artifacts": artifacts,
        "engines": engines,
        "log_tail": "\n".join(f"--- {e}\n{(r.get('log_tail') or '')[-2000:]}" for e, r in runs.items()),
    }
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
        res = sandbox_exec.run_sandboxed(
            cmd,
            writable=[scratch, corpus_dir, artifacts_dir],
            timeout_s=wall_timeout,
            limits=Limits(cpu_seconds=wall_timeout * cpu_mult),
            extra_env=run_env,
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
                failure = replay["failure"] or (parse_runtime_failure(combined_out) if from_log else None)
                entry["reproducible"] = replay["reproduced"]
                entry["replay_log_tail"] = replay["log_tail"]
                entry["frames"] = replay.get("frames") or []
                entry["failure_source"] = "primary" if failure else None
                if needs_attribution(failure):
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
                        if san_replay["failure"] and not needs_attribution(san_replay["failure"]):
                            failure = san_replay["failure"]
                            entry["failure_source"] = "sanitizer_replay"
                entry["failure"] = failure
                if not failure:
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

    A failure outside `functions` is not held against the contract (failure_outside_checked_functions).
    `contract_functions` are the functions whose annotations the build is limited to (`--functions`;
    default `functions`): a failed annotation is only excused outside them, so a module-wide build that
    only measures the reach of `functions` (`--reach-functions`, an empty list here) excuses RTE
    failures of other code but never a failed annotation.

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
                    cached["corpus_replayed"] = max(0, len(replay_manifest) - len(cached.get("excluded_inputs") or []))
                    cached["corpus_dir"] = str(corpus_dir)
                    cached["crash_input"] = None
                    cached["cache"] = {"hit": True, "key": g_key}
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
            cmd, writable=[scratch_dir], timeout_s=wall_left, limits=Limits(cpu_seconds=wall_left * 2)
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
            if failure is None or crash_input is None or mutation_runs <= 0:
                break
            # Not a corpus file: a mutation of the burst. The seed is fixed, so the burst would stop there
            # every time; replay the corpus alone and say so (`mutations_skipped`).
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
        help="callgraph_dag.json used to repair link failures (undefined references -> defining source, one retry)",
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
    dag = getattr(args, "dag", None)
    if dag is None:
        default_dag = Path("workspace/reports/callgraph_dag.json")
        dag = default_dag if default_dag.is_file() else None
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


_SUMMARY_OMITTED = ("compile", "log_tail", "runtime_trace", "eacsl_compile_attempt", "functions", "failed_inputs")


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
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(_summary(res), indent=2))
        return 0 if res["status"] == "ok" else 1

    digest_before = prover_candidates.digest_before_run(args.out_json) if args.mode == "guardrail" else None
    identity: dict = {}
    prior_report: dict | None = None
    if args.mode == "campaign":
        # Taken before the build: the values the artifacts are found under. The report this run
        # replaces holds the values of the artifacts libFuzzer only re-reports (`pre_existing`).
        identity = campaign_harness_identity(args.module, args.sources)
        try:
            loaded = json.loads(args.out_json.read_text(encoding="utf-8"))
            prior_report = loaded if isinstance(loaded, dict) else None
        except (OSError, ValueError):
            prior_report = None
    try:
        if args.mode == "selftest":
            res = run_selftest(args.work_dir, args.machdep, variadic_translation=not args.no_variadic_translation)
        elif args.mode == "campaign":
            res = _run_campaign_mode(args)
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
                )
                res = {"mode": "guardrail", "compile": comp, **guard, "reduced_checks": comp.get("reduced_checks", [])}
                if "diagnostic_hints" not in res:
                    res["diagnostic_hints"] = derive_eacsl_diagnostic_hints(res)
    except SandboxUnavailable as exc:
        res = {"mode": args.mode, "status": "sandbox_unavailable", "reason": str(exc)}
        if args.mode == "guardrail":
            res["crash_input"] = None

    if args.mode == "campaign":
        import seed_harvest  # lazily: only campaigns read the seed writes' statuses

        res["seeds"] = seed_harvest.seeds_report_field(args.module, bool(args.extra_corpus))
        stamp_harness_identity(res, identity, prior_report)
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
    if built and build["engine_used"] == "eacsl" and comp.get("reduced_checks"):
        res["reduced_checks"] = comp["reduced_checks"]
    if build["engine_fallback_reason"]:
        res["engine_fallback_reason"] = build["engine_fallback_reason"]
    if build["eacsl_compile_attempt"] is not None:
        res["eacsl_compile_attempt"] = build["eacsl_compile_attempt"]
    if build.get("link_repair"):
        res["link_repair"] = build["link_repair"]
    note_security_props(res, build_security_props(build))
    if args.engine == "auto" and build["engine_used"] == "eacsl":
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
    build = fuzz_build.build_module_binary(args.sources, args.out_bin, **_build_options(args))
    comp = build["compile"]
    engine_used = build["engine_used"]
    res: dict = {"mode": "campaign", "module": args.module}
    if comp["returncode"] != 0:
        res.update({"status": "compile_error", "engine_used": engine_used, "compile": comp})
    else:
        attribution_builder = None
        if engine_used == "eacsl" and not args.no_attribution_replay:
            attribution_builder = fuzz_build._sanitizer_attribution_builder(
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
        selector = dispatch_selector(args.sources) or DISPATCH_SELECTOR_MODULO
        skippable = dispatch_skippable_cases(args.sources, n_cases) if n_cases is not None else None
        harness_runtime_skip = bool(
            n_cases is not None
            and n_cases <= DISPATCH_RUNTIME_SKIP_MAX_CASES
            and harness_supports_runtime_skip_cases(args.sources)
        )

        def _engine_campaign(engine: str, binary: Path, seconds: int) -> dict:
            attribution = attribution_builder if engine == "eacsl" else None
            # The harness reads the skip set with getenv(); in an E-ACSL build the runtime's
            # argv/environ setup leaves `environ` empty unless the `environ_keep` shim is linked
            # (-Wl,--wrap=__e_acsl_memory_init). Without it, skip with rebuilds as for an older harness.
            shim = (comp.get("environ_keep") or {}).get("status") if engine == "eacsl" else None
            runtime_skip = harness_runtime_skip and (engine != "eacsl" or shim == "built")

            def _campaign(binary: Path, seconds: int, fork: bool, *, extra_env: dict[str, str] | None = None) -> dict:
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
                    extra_env=extra_env,
                )

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
                rebuilt = fuzz_build.build_module_binary(args.sources, skip_bin, **opts)
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
        if args.engine == "auto" and engine_used == "eacsl":
            san = fuzz_build.build_module_binary(
                args.sources, args.out_bin, **{**_build_options(args), "engine": "sanitizers"}
            )
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


if __name__ == "__main__":
    sys.exit(main())
