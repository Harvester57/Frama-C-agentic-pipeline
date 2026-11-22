#!/usr/bin/env python3
"""
Standalone harness smoke gate (P3).

Validates a module's compiled fuzz binary (`.san`, and `.e-acsl` startup if present)
before Phase 1 fuzzing:
  1. Startup check: runs `.san` (and `.e-acsl` if provided and exists) on a benign
     empty / out-of-range selector invocation. Any abort before `LLVMFuzzerTestOneInput`
     ends with `status = "startup_error"` and non-zero exit.
  2. Per-case smoke pass (dispatch harnesses): constructs 0-payload, 64-byte zeroed,
     and up to 2 harvested seed probes per case `k` in `0..dispatch_case_count-1`.
     Executes `.san` in batched mode and isolates any failing case via
     `FRAMAC_FUZZ_ONLY_CASE=k` plus single-probe replay so culprit input and
     `payload_len` are exact. Only unambiguous `harness_setup_fault` failures are
     quarantined; `empty_input_candidate` and `target_crash_candidate` are recorded
     as `candidate_warning` and stay active for Phase 1 fuzzing.
  3. Non-dispatch harnesses (`argv`, `stdin`, `tf_*`, single-entry): startup check +
     1 empty input + up to 4 harvested seeds.

All target binary executions go through `scripts/sandbox_exec.py`.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import re
import sys
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import phase0_gates  # noqa: E402
import sandbox_exec  # noqa: E402
from failure_identity import (  # noqa: E402
    _FUZZ_STARTED_INPUT_RE,
    _LSAN_ERR_RE,
    _STACK_FRAME_RE,
    classify_smoke_failure,
    failure_fingerprint,
    is_startup_failure,
    parse_link_stub_abort,
    parse_runtime_failure,
)
from framac_common import (  # noqa: E402
    ArtifactError,
    atomic_write_json,
    load_json_strict,
    utc_now,
)
from fuzz_common import (  # noqa: E402
    SANITIZER_RUNTIME_ENV,
    derive_seed,
    replay_artifact_dir,
)
from generate_harness import (  # noqa: E402
    DISPATCH_MAX_CASES,
    DISPATCH_SELECTOR_IDENTITY,
    DISPATCH_SELECTOR_IDENTITY16,
    dispatch_case_of_bytes,
    dispatch_selector_of,
    dispatch_selector_width,
)
from resources import FUZZ_RSS_LIMIT_MB  # noqa: E402
from sandbox_exec import Limits, SandboxResult, SandboxUnavailable  # noqa: E402

SCHEMA_VERSION = 1
DEFAULT_SMOKE_TIMEOUT_S = 10
SMOKE_BATCH_CASES = 32
ZERO_PAYLOAD_LEN = 64
MAX_DISPATCH_SEEDS_PER_CASE = 2
MAX_NON_DISPATCH_SEEDS = 4
LOG_TAIL_CHARS = 3000
STACK_TRACE_MAX_CHARS = 4000

_OFF_VALUES = frozenset({"off", "0", "false", "no"})
_RUNNING_RE = re.compile(r"^Running:\s+(?P<path>\S+)\s*$", re.MULTILINE)
_ERROR_LINE_RE = re.compile(
    r"(?:==\d+==ERROR:|SUMMARY:|runtime error:|Error:|Aborted\b|Segmentation fault|"
    r"error while loading shared libraries|undefined symbol|symbol lookup error|ERROR:\s*Failed to mmap)",
    re.IGNORECASE,
)


def harness_smoke_enabled() -> bool:
    """Whether the standalone harness smoke gate is enabled (`FRAMAC_HARNESS_SMOKE`, default on; `=off` disables)."""
    return (os.environ.get("FRAMAC_HARNESS_SMOKE") or "").strip().lower() not in _OFF_VALUES


@dataclass(frozen=True)
class _Probe:
    case: int
    kind: str  # "empty" | "zero64" | "seed"
    payload_len: int
    path: Path


def _extract_stack_trace(output: str) -> str | None:
    text = (output or "").strip()
    if not text:
        return None
    picked: list[str] = []
    for line in text.splitlines():
        if _STACK_FRAME_RE.search(line) or _ERROR_LINE_RE.search(line):
            picked.append(line.rstrip())
    if picked:
        return "\n".join(picked)[:STACK_TRACE_MAX_CHARS]
    return text[-STACK_TRACE_MAX_CHARS:]


def _infer_run_dir_from_sidecar(sidecar_path: Path) -> Path | None:
    resolved = sidecar_path.resolve()
    if resolved.parent.name == "harnesses" and resolved.parent.parent.name == "workspace":
        return resolved.parent.parent.parent
    return None


def compute_harness_digest(sidecar_path: Path, sidecar: dict[str, Any], module: str) -> str | None:
    """
    Compute the harness digest matching `phase0_gates.harness_digest(..., ignore_exempt=True)`.
    Falls back to hashing the given sidecar (without `reach_exempt`/`warnings`) and its sibling `.c`
    file when `--sidecar` is outside a standard `workspace/harnesses/` layout.
    """
    explicit = sidecar.get("harness_digest")
    if isinstance(explicit, str) and re.fullmatch(r"[0-9a-f]{64}", explicit):
        return explicit

    run_dir = _infer_run_dir_from_sidecar(sidecar_path)
    if run_dir is not None:
        digest = phase0_gates.harness_digest(run_dir, module, ignore_exempt=True)
        if digest is not None:
            return digest

    h = hashlib.sha256()
    found = False
    if sidecar_path.is_file():
        found = True
        rest = {k: v for k, v in sidecar.items() if k not in ("reach_exempt", "warnings")}
        h.update(b".json")
        h.update(json.dumps(rest, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    c_path = sidecar_path.with_suffix(".c")
    if c_path.is_file():
        found = True
        h.update(b".c")
        h.update(c_path.read_bytes())
    return h.hexdigest() if found else None


def resolve_binaries(
    san_bin: Path | None,
    eacsl_bin: Path | None,
    build_json: Path | None,
) -> tuple[Path | None, Path | None]:
    """
    Resolve sanitizer and optional E-ACSL binary paths from explicit CLI arguments and/or a
    `run_eacsl_fuzz.py build` report JSON. Explicit CLI arguments take precedence.
    """
    resolved_san = Path(san_bin) if san_bin is not None else None
    resolved_eacsl = Path(eacsl_bin) if eacsl_bin is not None else None
    if build_json is None:
        return resolved_san, resolved_eacsl

    data = load_json_strict(build_json)
    if not isinstance(data, dict):
        raise ArtifactError(f"build JSON is not an object: {build_json}")

    def _pick_path(raw: Any) -> Path | None:
        if not isinstance(raw, str) or not raw.strip():
            return None
        cand = Path(raw)
        if cand.is_file() or cand.is_absolute():
            return cand
        # Relative path stored in build JSON: check relative to run root if inferable.
        rel_root = _infer_run_dir_from_build_json(build_json)
        if rel_root is not None and (rel_root / cand).is_file():
            return rel_root / cand
        return cand

    engine_used = str(data.get("engine_used") or "").strip().lower()
    primary_bin = _pick_path(data.get("binary"))
    if primary_bin is None and isinstance(data.get("compile"), dict):
        primary_bin = _pick_path(data["compile"].get("binary"))

    raw_binaries = data.get("binaries")
    binaries_map: dict[str, Any] = raw_binaries if isinstance(raw_binaries, dict) else {}

    san_from_json = _pick_path(binaries_map.get("sanitizers"))
    if san_from_json is None:
        san_from_json = _pick_path(data.get("san_bin")) or _pick_path(data.get("sanitizer_binary"))
    if san_from_json is None and isinstance(data.get("sanitizer_compile"), dict):
        san_comp = data["sanitizer_compile"]
        if san_comp.get("returncode") in (0, None):
            san_from_json = _pick_path(san_comp.get("binary"))
    if san_from_json is None and engine_used == "sanitizers":
        san_from_json = primary_bin

    eacsl_from_json = _pick_path(binaries_map.get("eacsl"))
    if eacsl_from_json is None:
        eacsl_from_json = _pick_path(data.get("eacsl_bin")) or _pick_path(data.get("eacsl_binary"))
    if eacsl_from_json is None and engine_used == "eacsl":
        eacsl_from_json = primary_bin

    if resolved_san is None:
        resolved_san = san_from_json
    if resolved_eacsl is None:
        resolved_eacsl = eacsl_from_json
    return resolved_san, resolved_eacsl


def _infer_run_dir_from_build_json(build_json: Path) -> Path | None:
    parts = list(build_json.resolve().parts)
    for idx in range(len(parts) - 1, -1, -1):
        if parts[idx] == "workspace" and idx > 0:
            return Path(*parts[:idx])
    return None


def selector_info(sidecar: dict[str, Any], harness_text: str | None = None) -> tuple[str, int, int]:
    """
    Return `(selector_encoding, selector_width, case_count)` for a sidecar.
    Honors explicit `dispatch_selector_bytes` (1 or 2) when present, otherwise derives width from
    `generate_harness.dispatch_selector_of` and `dispatch_case_count`.
    """
    raw_count = sidecar.get("dispatch_case_count")
    if isinstance(raw_count, int) and not isinstance(raw_count, bool) and raw_count >= 0:
        n_cases = raw_count
    else:
        cases = sidecar.get("dispatch_cases")
        n_cases = len(cases) if isinstance(cases, list) else 0

    raw_bytes = sidecar.get("dispatch_selector_bytes")
    if isinstance(raw_bytes, int) and raw_bytes in (1, 2):
        selector = DISPATCH_SELECTOR_IDENTITY16 if raw_bytes == 2 else dispatch_selector_of(sidecar, harness_text)
        return selector, raw_bytes, n_cases

    selector = dispatch_selector_of(sidecar, harness_text)
    width = dispatch_selector_width(selector)
    if width == 1 and n_cases > DISPATCH_MAX_CASES:
        selector = DISPATCH_SELECTOR_IDENTITY16
        width = 2
    return selector, width, n_cases


def encode_selector(case_idx: int, width: int) -> bytes:
    """Encode dispatch case index `case_idx` into `width` (1 or 2) little-endian selector bytes."""
    return int(case_idx).to_bytes(width, "little")


def _startup_probe_bytes(is_dispatch: bool, selector: str, width: int, n_cases: int) -> bytes:
    """
    Benign startup probe input:
      - Dispatch harnesses: out-of-range selector (`0xFF` / `0xFFFF`) when strictly >= `n_cases`
        under an identity selector, else empty `b""` (which also hits `FRAMAC_FUZZ_REJECT()`).
      - Non-dispatch harnesses: empty `b""`.
    """
    if not is_dispatch:
        return b""
    if width == 2 and n_cases < 0xFFFF:
        return b"\xff\xff"
    if width == 1 and selector == DISPATCH_SELECTOR_IDENTITY and n_cases < 256:
        return b"\xff"
    return b""


def _case_entry_map(sidecar: dict[str, Any]) -> dict[int, str]:
    """Map dispatch case index -> human-readable API entry name from `api_cases`, when available."""
    mapping: dict[int, str] = {}
    api_cases = sidecar.get("api_cases")
    if not isinstance(api_cases, list):
        return mapping
    for item in api_cases:
        if not isinstance(item, dict):
            continue
        sel = item.get("selector")
        if not isinstance(sel, int) or isinstance(sel, bool):
            continue
        entry = item.get("entry")
        if isinstance(entry, str) and entry:
            mapping[sel] = entry
            continue
        calls = item.get("calls")
        if isinstance(calls, list) and calls and isinstance(calls[0], str):
            mapping[sel] = calls[0]
    return mapping


def _collect_dispatch_seeds(
    seeds_dir: Path | None,
    n_cases: int,
    selector: str,
    width: int,
) -> dict[int, list[bytes]]:
    by_case: dict[int, list[bytes]] = {}
    if seeds_dir is None or not seeds_dir.is_dir() or n_cases <= 0:
        return by_case
    for path in sorted(p for p in seeds_dir.iterdir() if p.is_file() and not p.name.startswith(".")):
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if len(raw) < width:
            continue
        case_idx = dispatch_case_of_bytes(raw[:width], n_cases, selector)
        if case_idx is None:
            continue
        bucket = by_case.setdefault(case_idx, [])
        if len(bucket) < MAX_DISPATCH_SEEDS_PER_CASE:
            bucket.append(raw)
    return by_case


def _collect_non_dispatch_seeds(seeds_dir: Path | None) -> list[bytes]:
    if seeds_dir is None or not seeds_dir.is_dir():
        return []
    seeds: list[bytes] = []
    for path in sorted(p for p in seeds_dir.iterdir() if p.is_file() and not p.name.startswith(".")):
        try:
            seeds.append(path.read_bytes())
        except OSError:
            continue
        if len(seeds) >= MAX_NON_DISPATCH_SEEDS:
            break
    return seeds


def _run_probe_files(
    binary: Path,
    probe_files: Sequence[Path],
    scratch: Path,
    *,
    timeout_s: int,
    module: str,
    extra_env: dict[str, str] | None = None,
) -> SandboxResult:
    seed = derive_seed(binary, module)
    per_input_timeout = max(1, int(timeout_s))
    wall = max(per_input_timeout * max(1, len(probe_files)) + 5, per_input_timeout + 5)
    env = dict(SANITIZER_RUNTIME_ENV)
    if extra_env:
        env.update(extra_env)
    argv = [
        str(binary.resolve()),
        f"-timeout={per_input_timeout}",
        f"-rss_limit_mb={FUZZ_RSS_LIMIT_MB}",
        f"-seed={seed}",
        f"-artifact_prefix={replay_artifact_dir(scratch)}/",
        *[str(Path(p).resolve()) for p in probe_files],
    ]
    return sandbox_exec.run_sandboxed(
        argv,
        writable=[scratch],
        timeout_s=wall,
        limits=Limits(cpu_seconds=wall * 2, ignore_sigpipe=True),
        extra_env=env,
    )


def _input_running_at_exit(output: str, probes: Sequence[_Probe]) -> int | None:
    """Index in `probes` of the last `Running: <path>` printed by libFuzzer, or None."""
    matches = list(_RUNNING_RE.finditer(output or ""))
    if not matches:
        return None
    running_raw = matches[-1].group("path").strip()
    running_norm = running_raw.replace("\\", "/")
    running_name = Path(running_norm).name
    for idx, probe in enumerate(probes):
        p_res = str(probe.path.resolve()).replace("\\", "/")
        p_raw = str(probe.path).replace("\\", "/")
        if running_norm in (p_res, p_raw) or running_name == probe.path.name:
            return idx
    return None


def _check_startup(
    san_bin: Path | None,
    eacsl_bin: Path | None,
    startup_probe: Path,
    scratch: Path,
    *,
    is_dispatch: bool,
    timeout_s: int,
    module: str,
) -> dict[str, Any]:
    engines: list[tuple[str, Path]] = []
    if san_bin is not None and san_bin.is_file():
        engines.append(("sanitizers", san_bin))
    if eacsl_bin is not None and eacsl_bin.is_file():
        engines.append(("eacsl", eacsl_bin))

    checked: list[str] = []
    results: dict[str, dict[str, Any]] = {}
    failing_engine: str | None = None
    failing_reason: str | None = None
    failing_trace: str | None = None

    for engine_name, binary in engines:
        checked.append(engine_name)
        res = _run_probe_files(binary, [startup_probe], scratch, timeout_s=timeout_s, module=module)
        out = res.stdout + "\n" + res.stderr
        if res.returncode == 0 and not res.timed_out:
            results[engine_name] = {
                "ok": True,
                "binary": binary.as_posix(),
                "returncode": res.returncode,
                "timed_out": False,
                "reason": None,
                "stack_trace": None,
                "failure": None,
            }
            continue

        stub_abort = parse_link_stub_abort(out)
        failure = None if stub_abort else parse_runtime_failure(out, binary=binary)
        is_sf, sf_reason = is_startup_failure(failure, out)
        entered_input = _FUZZ_STARTED_INPUT_RE.search(out) is not None

        # On a dispatch harness, the startup probe is rejected immediately by the selector guard,
        # so any non-zero exit or timeout is a startup error. On a non-dispatch harness, a 0-byte
        # input invokes the target entry point; only pre-entry/init aborts fail startup, while
        # post-entry target faults are classified in the non-dispatch smoke pass.
        startup_failed = is_dispatch or is_sf or (failure is None and not entered_input and not stub_abort)
        if not startup_failed:
            results[engine_name] = {
                "ok": True,
                "binary": binary.as_posix(),
                "returncode": res.returncode,
                "timed_out": res.timed_out,
                "reason": None,
                "stack_trace": None,
                "failure": None,
            }
            continue

        reason = sf_reason
        if not reason:
            if res.timed_out:
                reason = f"startup check timed out after {timeout_s}s"
            elif stub_abort:
                reason = f"startup link-stub abort: {stub_abort['message']}"
            else:
                reason = f"binary aborted during startup (returncode={res.returncode})"
        trace = _extract_stack_trace(out)
        results[engine_name] = {
            "ok": False,
            "binary": binary.as_posix(),
            "returncode": res.returncode,
            "timed_out": res.timed_out,
            "reason": reason,
            "stack_trace": trace,
            "failure": failure,
        }
        failing_engine = engine_name
        failing_reason = reason
        failing_trace = trace
        break

    return {
        "ok": failing_engine is None,
        "engines_checked": checked,
        "failing_engine": failing_engine,
        "reason": failing_reason,
        "stack_trace": failing_trace,
        "results": results,
    }


def _build_failure_case_record(
    case_idx: int,
    entry_name: str | None,
    probes_run: int,
    probe: _Probe,
    res: SandboxResult,
    binary: Path,
    *,
    primary_engine: str = "sanitizers",
) -> tuple[dict[str, Any], bool, dict[str, Any] | None]:
    out = res.stdout + "\n" + res.stderr
    stub_abort = parse_link_stub_abort(out)
    failure = None if stub_abort else parse_runtime_failure(out, binary=binary)
    classification = classify_smoke_failure(failure, probe.payload_len, out)

    if classification == "startup_error":
        _, sf_reason = is_startup_failure(failure, out)
        escalation = {
            "engine": primary_engine,
            "binary": binary.as_posix(),
            "returncode": res.returncode,
            "timed_out": res.timed_out,
            "reason": sf_reason or f"startup error observed while probing case {case_idx}",
            "stack_trace": _extract_stack_trace(out),
            "failure": failure,
        }
        return (
            {
                "case": case_idx,
                "entry": entry_name,
                "status": "candidate_warning",
                "probes_run": probes_run,
                "classification": "startup_error",
                "probe_kind": probe.kind,
                "payload_len": probe.payload_len,
                "kind": (failure.get("kind") if failure else None) or "startup_error",
                "fingerprint": failure_fingerprint(failure),
                "reason": escalation["reason"],
                "returncode": res.returncode,
                "timed_out": res.timed_out,
                "failure": failure,
                "log_tail": out[-LOG_TAIL_CHARS:],
            },
            True,
            escalation,
        )

    case_status = "quarantined" if classification == "harness_setup_fault" else "candidate_warning"
    if failure:
        kind = str(failure.get("kind") or "crash")
        fn = str(failure.get("function") or "unknown_function")
        reason = f"{classification}: {kind} in {fn} (probe={probe.kind}, payload_len={probe.payload_len})"
    elif stub_abort:
        kind = "link_stub_abort"
        reason = f"{classification}: {stub_abort['message']} (probe={probe.kind}, payload_len={probe.payload_len})"
    elif res.timed_out:
        kind = "timeout"
        reason = f"{classification}: probe timed out (probe={probe.kind}, payload_len={probe.payload_len})"
    else:
        kind = "crash"
        reason = (
            f"{classification}: non-zero exit {res.returncode} (probe={probe.kind}, payload_len={probe.payload_len})"
        )

    record: dict[str, Any] = {
        "case": case_idx,
        "entry": entry_name,
        "status": case_status,
        "probes_run": probes_run,
        "classification": classification,
        "probe_kind": probe.kind,
        "payload_len": probe.payload_len,
        "kind": kind,
        "fingerprint": failure_fingerprint(failure),
        "reason": reason,
        "returncode": res.returncode,
        "timed_out": res.timed_out,
        "failure": failure,
        "log_tail": out[-LOG_TAIL_CHARS:],
    }
    return record, False, None


def _isolate_case(
    san_bin: Path,
    case_idx: int,
    entry_name: str | None,
    probes: Sequence[_Probe],
    scratch: Path,
    *,
    timeout_s: int,
    module: str,
    use_only_case_env: bool,
    fallback_batch_res: SandboxResult | None = None,
    primary_engine: str = "sanitizers",
) -> tuple[dict[str, Any], bool, dict[str, Any] | None]:
    extra_env = {"FRAMAC_FUZZ_ONLY_CASE": str(case_idx)} if use_only_case_env else None
    for idx, probe in enumerate(probes, start=1):
        res = _run_probe_files(
            san_bin,
            [probe.path],
            scratch,
            timeout_s=timeout_s,
            module=module,
            extra_env=extra_env,
        )
        if res.returncode != 0 or res.timed_out:
            return _build_failure_case_record(
                case_idx, entry_name, idx, probe, res, san_bin, primary_engine=primary_engine
            )

    if fallback_batch_res is not None and probes:
        out = fallback_batch_res.stdout + "\n" + fallback_batch_res.stderr
        hit = _input_running_at_exit(out, probes)
        culprit = probes[hit] if hit is not None else probes[-1]
        return _build_failure_case_record(
            case_idx, entry_name, len(probes), culprit, fallback_batch_res, san_bin, primary_engine=primary_engine
        )

    return (
        {
            "case": case_idx,
            "entry": entry_name,
            "status": "passed",
            "probes_run": len(probes),
        },
        False,
        None,
    )


def _run_dispatch_smoke(
    san_bin: Path,
    n_cases: int,
    selector: str,
    width: int,
    entry_map: dict[int, str],
    seeds_dir: Path | None,
    scratch: Path,
    *,
    timeout_s: int,
    module: str,
    primary_engine: str = "sanitizers",
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    probes_dir = scratch / "probes"
    probes_dir.mkdir(parents=True, exist_ok=True)
    seeds_by_case = _collect_dispatch_seeds(seeds_dir, n_cases, selector, width)

    probes_by_case: dict[int, list[_Probe]] = {}
    for k in range(n_cases):
        sel_bytes = encode_selector(k, width)
        case_probes: list[_Probe] = []

        p_empty = probes_dir / f"case_{k:04d}_p0_empty.bin"
        p_empty.write_bytes(sel_bytes)
        case_probes.append(_Probe(case=k, kind="empty", payload_len=0, path=p_empty))

        p_zero = probes_dir / f"case_{k:04d}_p1_zero64.bin"
        p_zero.write_bytes(sel_bytes + (b"\x00" * ZERO_PAYLOAD_LEN))
        case_probes.append(_Probe(case=k, kind="zero64", payload_len=ZERO_PAYLOAD_LEN, path=p_zero))

        for s_idx, raw_seed in enumerate(seeds_by_case.get(k, [])):
            p_seed = probes_dir / f"case_{k:04d}_p{2 + s_idx}_seed.bin"
            p_seed.write_bytes(raw_seed)
            case_probes.append(_Probe(case=k, kind="seed", payload_len=max(0, len(raw_seed) - width), path=p_seed))

        probes_by_case[k] = case_probes

    results_by_case: dict[int, dict[str, Any]] = {}
    queue: collections.deque[list[int]] = collections.deque()
    for start in range(0, n_cases, SMOKE_BATCH_CASES):
        queue.append(list(range(start, min(start + SMOKE_BATCH_CASES, n_cases))))

    while queue:
        batch_cases = queue.popleft()
        if not batch_cases:
            continue
        batch_probes = [p for k in batch_cases for p in probes_by_case[k]]
        res = _run_probe_files(
            san_bin,
            [p.path for p in batch_probes],
            scratch,
            timeout_s=timeout_s,
            module=module,
        )
        if res.returncode == 0 and not res.timed_out:
            for k in batch_cases:
                results_by_case[k] = {
                    "case": k,
                    "entry": entry_map.get(k),
                    "status": "passed",
                    "probes_run": len(probes_by_case[k]),
                }
            continue

        out = res.stdout + "\n" + res.stderr
        is_lsan = _LSAN_ERR_RE.search(out) is not None

        if len(batch_cases) == 1:
            k = batch_cases[0]
            rec, escalated, esc_info = _isolate_case(
                san_bin,
                k,
                entry_map.get(k),
                probes_by_case[k],
                scratch,
                timeout_s=timeout_s,
                module=module,
                use_only_case_env=True,
                fallback_batch_res=res,
                primary_engine=primary_engine,
            )
            results_by_case[k] = rec
            if escalated:
                return [results_by_case[i] for i in sorted(results_by_case)], esc_info
            continue

        if not is_lsan:
            hit_idx = _input_running_at_exit(out, batch_probes)
            if hit_idx is not None:
                hit_case = batch_probes[hit_idx].case
                rec, escalated, esc_info = _isolate_case(
                    san_bin,
                    hit_case,
                    entry_map.get(hit_case),
                    probes_by_case[hit_case],
                    scratch,
                    timeout_s=timeout_s,
                    module=module,
                    use_only_case_env=True,
                    primary_engine=primary_engine,
                )
                if escalated:
                    results_by_case[hit_case] = rec
                    return [results_by_case[i] for i in sorted(results_by_case)], esc_info
                if rec["status"] != "passed":
                    results_by_case[hit_case] = rec
                    remaining = [k for k in batch_cases if k != hit_case]
                    if remaining:
                        queue.appendleft(remaining)
                    continue

        mid = len(batch_cases) // 2
        queue.appendleft(batch_cases[mid:])
        queue.appendleft(batch_cases[:mid])

    return [results_by_case[k] for k in range(n_cases)], None


def _run_non_dispatch_smoke(
    san_bin: Path,
    entry_name: str | None,
    seeds_dir: Path | None,
    scratch: Path,
    *,
    timeout_s: int,
    module: str,
    primary_engine: str = "sanitizers",
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    probes_dir = scratch / "probes"
    probes_dir.mkdir(parents=True, exist_ok=True)

    probes: list[_Probe] = []
    p_empty = probes_dir / "entry_p0_empty.bin"
    p_empty.write_bytes(b"")
    probes.append(_Probe(case=0, kind="empty", payload_len=0, path=p_empty))

    for s_idx, raw_seed in enumerate(_collect_non_dispatch_seeds(seeds_dir)):
        p_seed = probes_dir / f"entry_p{1 + s_idx}_seed.bin"
        p_seed.write_bytes(raw_seed)
        probes.append(_Probe(case=0, kind="seed", payload_len=len(raw_seed), path=p_seed))

    res = _run_probe_files(
        san_bin,
        [p.path for p in probes],
        scratch,
        timeout_s=timeout_s,
        module=module,
    )
    if res.returncode == 0 and not res.timed_out:
        return (
            [
                {
                    "case": 0,
                    "entry": entry_name,
                    "status": "passed",
                    "probes_run": len(probes),
                }
            ],
            None,
        )

    rec, escalated, esc_info = _isolate_case(
        san_bin,
        0,
        entry_name,
        probes,
        scratch,
        timeout_s=timeout_s,
        module=module,
        use_only_case_env=False,
        fallback_batch_res=res,
        primary_engine=primary_engine,
    )
    return [rec], esc_info if escalated else None


def _apply_startup_escalation(startup: dict[str, Any], escalation: dict[str, Any]) -> None:
    engine = str(escalation.get("engine") or "sanitizers")
    startup["ok"] = False
    startup["failing_engine"] = engine
    startup["reason"] = escalation.get("reason")
    startup["stack_trace"] = escalation.get("stack_trace")
    startup["results"][engine] = {
        "ok": False,
        "binary": str(escalation.get("binary") or ""),
        "returncode": escalation.get("returncode"),
        "timed_out": bool(escalation.get("timed_out")),
        "reason": escalation.get("reason"),
        "stack_trace": escalation.get("stack_trace"),
        "failure": escalation.get("failure"),
    }


def _counts_for(case_results: Sequence[dict[str, Any]]) -> dict[str, int]:
    return {
        "total": len(case_results),
        "passed": sum(1 for c in case_results if c.get("status") == "passed"),
        "quarantined": sum(1 for c in case_results if c.get("status") == "quarantined"),
        "candidate_warning": sum(1 for c in case_results if c.get("status") == "candidate_warning"),
    }


def run_smoke(
    *,
    module: str,
    sidecar_path: Path,
    out_json: Path,
    san_bin: Path | None = None,
    eacsl_bin: Path | None = None,
    build_json: Path | None = None,
    seeds_dir: Path | None = None,
    timeout_s: int = DEFAULT_SMOKE_TIMEOUT_S,
) -> tuple[dict[str, Any], int]:
    """
    Execute the standalone harness smoke gate for `module`, write the report atomically to
    `out_json`, and return `(report, exit_code)`.
    """
    t0 = time.monotonic()
    sidecar = load_json_strict(sidecar_path)
    if not isinstance(sidecar, dict):
        raise ArtifactError(f"sidecar is not a JSON object: {sidecar_path}")

    harness_c = sidecar_path.with_suffix(".c")
    harness_text = harness_c.read_text(encoding="utf-8", errors="replace") if harness_c.is_file() else None
    digest = compute_harness_digest(sidecar_path, sidecar, module)
    entry_style = str(sidecar.get("entry_style") or "custom")
    selector, width, n_cases = selector_info(sidecar, harness_text)
    is_dispatch = entry_style == "dispatch" and n_cases > 0

    resolved_san, resolved_eacsl = resolve_binaries(san_bin, eacsl_bin, build_json)

    def _finish(
        status: str,
        startup: dict[str, Any],
        case_results: list[dict[str, Any]],
        exit_code: int,
    ) -> tuple[dict[str, Any], int]:
        if is_dispatch:
            quarantined = sorted(c["case"] for c in case_results if c.get("status") == "quarantined")
            warnings = sorted(c["case"] for c in case_results if c.get("status") == "candidate_warning")
            skip_env = ",".join(str(k) for k in quarantined)
        else:
            quarantined = []
            warnings = [c["case"] for c in case_results if c.get("status") == "candidate_warning"]
            skip_env = ""
        report: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "generated_at": utc_now(),
            "module": module,
            "harness_digest": digest,
            "entry_style": entry_style,
            "dispatch_case_count": n_cases if is_dispatch else 0,
            "status": status,
            "startup": startup,
            "quarantined_cases": quarantined,
            "candidate_warning_cases": warnings,
            "skip_cases_env": skip_env,
            "case_results": case_results,
            "counts": _counts_for(case_results),
            "wall_s": round(max(0.0, time.monotonic() - t0), 3),
        }
        atomic_write_json(out_json, report)
        return report, exit_code

    has_san = resolved_san is not None and resolved_san.is_file()
    has_eacsl = resolved_eacsl is not None and resolved_eacsl.is_file()
    if has_san:
        assert resolved_san is not None
        probe_bin = resolved_san
        primary_engine = "sanitizers"
    elif san_bin is None and has_eacsl:
        # `--fuzz-engine eacsl` (or a sanitizer-less build.json / explicit --eacsl-bin):
        # probe the E-ACSL binary directly instead of failing with "sanitizer binary not found".
        assert resolved_eacsl is not None
        probe_bin = resolved_eacsl
        primary_engine = "eacsl"
    else:
        missing_desc = str(resolved_san) if resolved_san is not None else "(unresolved)"
        startup = {
            "ok": False,
            "engines_checked": [],
            "failing_engine": None,
            "reason": f"sanitizer binary not found: {missing_desc}",
            "stack_trace": None,
            "results": {},
        }
        return _finish("failed", startup, [], 1)

    with tempfile.TemporaryDirectory(prefix=f"framac_smoke_{module}_") as tmp_dir:
        scratch = Path(tmp_dir)
        startup_probe = scratch / "startup_probe.bin"
        startup_probe.write_bytes(_startup_probe_bytes(is_dispatch, selector, width, n_cases))

        try:
            startup = _check_startup(
                resolved_san if has_san else None,
                resolved_eacsl if has_eacsl else None,
                startup_probe,
                scratch,
                is_dispatch=is_dispatch,
                timeout_s=timeout_s,
                module=module,
            )
            if not startup["ok"]:
                return _finish("startup_error", startup, [], 1)

            if is_dispatch:
                entry_map = _case_entry_map(sidecar)
                case_results, escalation = _run_dispatch_smoke(
                    probe_bin,
                    n_cases,
                    selector,
                    width,
                    entry_map,
                    seeds_dir,
                    scratch,
                    timeout_s=timeout_s,
                    module=module,
                    primary_engine=primary_engine,
                )
            else:
                entry_fn = sidecar.get("entry_fn")
                entry_name = str(entry_fn) if isinstance(entry_fn, str) and entry_fn else None
                case_results, escalation = _run_non_dispatch_smoke(
                    probe_bin,
                    entry_name,
                    seeds_dir,
                    scratch,
                    timeout_s=timeout_s,
                    module=module,
                    primary_engine=primary_engine,
                )
        except SandboxUnavailable as exc:
            startup = {
                "ok": False,
                "engines_checked": [],
                "failing_engine": None,
                "reason": f"sandbox_unavailable: {exc}",
                "stack_trace": None,
                "results": {},
            }
            return _finish("failed", startup, [], 3)

    if escalation is not None:
        _apply_startup_escalation(startup, escalation)
        return _finish("startup_error", startup, case_results, 1)

    quarantined_count = sum(1 for c in case_results if c.get("status") == "quarantined")
    if is_dispatch:
        if quarantined_count == 0:
            return _finish("ok", startup, case_results, 0)
        if quarantined_count < n_cases:
            return _finish("degraded", startup, case_results, 0)
        return _finish("failed", startup, case_results, 1)

    if quarantined_count > 0:
        return _finish("failed", startup, case_results, 1)
    return _finish("ok", startup, case_results, 0)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Standalone harness smoke gate: verify startup and isolate harness-side setup faults."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_run = sub.add_parser("run", help="Run the smoke gate on a module's harness binary.")
    p_run.add_argument("--module", required=True, help="Harness module name")
    p_run.add_argument("--san-bin", type=Path, default=None, help="Path to sanitizer (.san) fuzz binary")
    p_run.add_argument("--eacsl-bin", type=Path, default=None, help="Optional path to E-ACSL (.e-acsl) fuzz binary")
    p_run.add_argument(
        "--build-json",
        type=Path,
        default=None,
        help="Optional build report JSON from `run_eacsl_fuzz.py build` used to resolve binaries",
    )
    p_run.add_argument("--sidecar", type=Path, required=True, help="Path to harness_<module>.json sidecar")
    p_run.add_argument("--seeds-dir", type=Path, default=None, help="Optional directory of harvested seeds")
    p_run.add_argument("--out-json", type=Path, required=True, help="Output path for smoke report JSON")
    p_run.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_SMOKE_TIMEOUT_S,
        help=f"Per-probe timeout in seconds (default: {DEFAULT_SMOKE_TIMEOUT_S})",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.cmd == "run":
        if args.san_bin is None and args.eacsl_bin is None and args.build_json is None:
            parser.error("one of --san-bin, --eacsl-bin, or --build-json is required")
        _, rc = run_smoke(
            module=args.module,
            sidecar_path=args.sidecar,
            out_json=args.out_json,
            san_bin=args.san_bin,
            eacsl_bin=args.eacsl_bin,
            build_json=args.build_json,
            seeds_dir=args.seeds_dir,
            timeout_s=args.timeout,
        )
        return rc
    return 1


if __name__ == "__main__":
    sys.exit(main())
