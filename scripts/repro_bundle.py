#!/usr/bin/env python3
"""
Standalone C reproducer scaffold, deterministic `try` oracle, and frozen disclosure bundle packager.

Subcommands:
  - scaffold: turn a confirmed finding (or candidate with --allow-candidate) and its crash artifact
    into a standalone plain-C `repro.c`, `expected.json` (Contract 3), and `build_spec.json`.
  - try: compile a C reproducer without libFuzzer, execute it under sandbox_exec.py, and classify
    the outcome against `expected.json` as SAME_CRASH (exit 0), DIFFERENT_CRASH (exit 1),
    NO_CRASH (exit 1), or COMPILE_ERROR (exit 2).
  - package: verify a C reproducer with `try` (unless --skip-verify) and emit a frozen maintainer
    bundle (`repro.c`, `Dockerfile`, `run.sh`, `ISSUE.md`) with LF line endings.
"""

from __future__ import annotations

import argparse
import json
import posixpath
import re
import shlex
import sys
import tempfile
from pathlib import Path
from typing import Any

import failure_identity
import fuzz_build
import sandbox_exec
from fingerprint import normalize_file, normalize_kind
from framac_common import (
    ArtifactError,
    atomic_write_json,
    compile_inputs,
    load_json_optional,
    load_json_strict,
)
from fuzz_common import SANITIZER_RUNTIME_ENV, sha256_file
from generate_harness import (
    dispatch_case_of_bytes,
    dispatch_selector_of,
    dispatch_selector_of_text,
    dispatch_selector_width,
)
from sandbox_exec import Limits, SandboxUnavailable

STATUS_SAME_CRASH = "SAME_CRASH"
STATUS_DIFFERENT_CRASH = "DIFFERENT_CRASH"
STATUS_NO_CRASH = "NO_CRASH"
STATUS_COMPILE_ERROR = "COMPILE_ERROR"

EXIT_SAME_CRASH = 0
EXIT_MISMATCH_OR_NO_CRASH = 1
EXIT_COMPILE_ERROR = 2

DEFAULT_TRY_TIMEOUT_S = 30
DEFAULT_BASE_IMAGE = "framac-analysis:latest"

_GENERIC_KINDS = frozenset(
    {
        "runtime_error",
        "assertion",
        "assert",
        "crash",
        "error",
        "property",
        "libc_error",
        "format_error",
        "eacsl_runtime_error",
    }
)
_HARNESS_NAME_RE = re.compile(r"^harness_(.+)\.[cC]$")
_STD_HEADERS = frozenset({"<stdint.h>", "<stddef.h>", "<stdlib.h>", "<string.h>"})


def _write_lf_text(path: Path, text: str) -> None:
    """Write UTF-8 text with strict LF line endings."""
    path.parent.mkdir(parents=True, exist_ok=True)
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(normalized)


def _infer_module_from_harness_path(harness_path: str | None) -> str | None:
    if not harness_path:
        return None
    m = _HARNESS_NAME_RE.match(Path(harness_path).name)
    return m.group(1) if m else None


def _locate_record(
    run_dir: Path,
    fingerprint: str,
    *,
    allow_candidate: bool = False,
) -> tuple[dict[str, Any], str, dict[str, Any] | None]:
    """
    Locate a verdict in `findings.json` (or `candidates.json` when `allow_candidate` is True).
    Returns `(record, source_kind, matching_candidate_or_None)`.
    """
    findings_path = run_dir / "findings.json"
    candidates_path = run_dir / "candidates.json"

    findings = load_json_optional(findings_path, [])
    candidates = load_json_optional(candidates_path, [])

    cand_match: dict[str, Any] | None = None
    if isinstance(candidates, list):
        for item in candidates:
            if isinstance(item, dict) and item.get("fingerprint") == fingerprint:
                cand_match = item
                break

    if isinstance(findings, list):
        for item in findings:
            if isinstance(item, dict) and item.get("fingerprint") == fingerprint:
                verdict = str(item.get("verdict") or "")
                if verdict == "confirmed":
                    return item, "finding", cand_match
                if not allow_candidate:
                    raise ArtifactError(
                        f"finding {fingerprint!r} has verdict {verdict!r}, not 'confirmed' "
                        "(pass --allow-candidate to scaffold non-confirmed records)"
                    )
                return item, "finding", cand_match

    if allow_candidate and cand_match is not None:
        return cand_match, "candidate", cand_match

    raise ArtifactError(
        f"fingerprint {fingerprint!r} not found in {findings_path}"
        + (f" or {candidates_path}" if allow_candidate else " (pass --allow-candidate to search candidates.json)")
    )


def _resolve_module(
    run_dir: Path,
    record: dict[str, Any],
    candidate: dict[str, Any] | None,
) -> str:
    mod = record.get("module")
    if isinstance(mod, str) and mod.strip():
        return mod.strip()

    harness_info = record.get("harness")
    if isinstance(harness_info, dict):
        inferred = _infer_module_from_harness_path(str(harness_info.get("file") or ""))
        if inferred:
            return inferred

    if isinstance(candidate, dict):
        cmod = candidate.get("module")
        if isinstance(cmod, str) and cmod.strip():
            return cmod.strip()

    loc = record.get("location")
    loc_file = normalize_file(str(loc.get("file") or "")) if isinstance(loc, dict) else ""
    harnesses_dir = run_dir / "workspace" / "harnesses"
    if loc_file and harnesses_dir.is_dir():
        for sidecar_path in sorted(harnesses_dir.glob("harness_*.json")):
            data = load_json_optional(sidecar_path, {})
            if not isinstance(data, dict):
                continue
            sources = data.get("sources") or []
            if any(normalize_file(str(s)) == loc_file for s in sources):
                smod = data.get("module")
                if isinstance(smod, str) and smod.strip():
                    return smod.strip()

    raise ArtifactError(f"unable to determine module for fingerprint {record.get('fingerprint')!r}")


def _resolve_artifact_path(
    run_dir: Path,
    record: dict[str, Any],
    explicit_artifact: Path | None,
) -> Path:
    if explicit_artifact is not None:
        cand = explicit_artifact
        if not cand.is_file() and not cand.is_absolute():
            alt = run_dir / cand
            if alt.is_file():
                cand = alt
        if not cand.is_file():
            raise ArtifactError(f"crash artifact not found: {explicit_artifact}")
    else:
        reproducers = record.get("reproducers")
        if not isinstance(reproducers, list) or not reproducers:
            raise ArtifactError(f"record {record.get('fingerprint')!r} has no recorded reproducers")
        first = reproducers[0]
        raw_path = first.get("input") if isinstance(first, dict) else (first if isinstance(first, str) else "")
        if not raw_path:
            raise ArtifactError(f"record {record.get('fingerprint')!r} has an empty reproducer path")
        cand = Path(str(raw_path))
        if not cand.is_absolute():
            cand = run_dir / cand
        if not cand.is_file():
            raise ArtifactError(f"recorded crash artifact not found: {cand}")

    min_sibling = Path(f"{cand}.min")
    if min_sibling.is_file():
        return min_sibling
    return cand


def _resolve_engine(
    requested: str,
    record: dict[str, Any],
    candidate: dict[str, Any] | None,
) -> str:
    if requested in ("sanitizers", "eacsl"):
        return requested

    raw_prop = record.get("property")
    prop: dict[str, Any] = raw_prop if isinstance(raw_prop, dict) else {}
    kind = str(prop.get("kind") or "").lower()
    if kind.startswith(("asan_", "ubsan_", "lsan_")):
        return "sanitizers"
    if kind.startswith(("eacsl_", "meta_")):
        return "eacsl"

    obs_list = (candidate or record).get("observations")
    if isinstance(obs_list, list) and obs_list:
        engines = {str(o.get("engine") or "").lower() for o in obs_list if isinstance(o, dict)}
        if "sanitizers" in engines:
            return "sanitizers"
        if "eacsl" in engines:
            return "eacsl"

    reproducers = record.get("reproducers")
    if isinstance(reproducers, list) and reproducers and isinstance(reproducers[0], dict):
        cmd = str(reproducers[0].get("command") or "")
        observed = str(reproducers[0].get("observed_result") or "")
        if ("AddressSanitizer" in observed or "UndefinedBehaviorSanitizer" in observed) or ".san" in cmd:
            return "sanitizers"
        if ".e-acsl" in cmd or "The failing predicate is:" in observed:
            return "eacsl"

    return "sanitizers"


def _extract_frames_top(record: dict[str, Any], fallback_fn: str) -> list[str]:
    frames: list[str] = []
    trace = record.get("trace")
    if isinstance(trace, list):
        for step in reversed(trace):
            if isinstance(step, dict):
                fn = str(step.get("function") or "").strip()
                if fn and fn not in frames:
                    frames.append(fn)

    if not frames:
        reproducers = record.get("reproducers")
        if isinstance(reproducers, list) and reproducers and isinstance(reproducers[0], dict):
            obs = str(reproducers[0].get("observed_result") or "")
            for fr in failure_identity.stack_frames(obs, limit=8):
                fn = str(fr.get("function") or "").strip()
                if fn and fn not in frames:
                    frames.append(fn)

    if not frames and fallback_fn and fallback_fn != "unknown_function":
        frames.append(fallback_fn)
    return frames[:8]


def _scan_balanced_braces(text: str, open_idx: int) -> int | None:
    """Return index of matching `}` for `{` at `open_idx`, ignoring C strings, chars, and comments."""
    n = len(text)
    if open_idx >= n or text[open_idx] != "{":
        return None
    depth = 0
    i = open_idx
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            nl = text.find("\n", i + 2)
            i = n if nl == -1 else nl + 1
            continue
        if ch == "/" and nxt == "*":
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
            continue
        if ch in ('"', "'"):
            quote = ch
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def extract_dispatch_case_body(harness_text: str, case_index: int) -> str | None:
    """
    Extract the statement body of `case <case_index>U:` (or `case <case_index>:`) from harness C text.
    Searches inside `LLVMFuzzerTestOneInput` first when present so fuzz-side code is selected.
    """
    if not harness_text:
        return None
    fuzz_pos = harness_text.find("LLVMFuzzerTestOneInput")
    search_text = harness_text[fuzz_pos:] if fuzz_pos != -1 else harness_text
    pattern = re.compile(rf"\bcase\s+{case_index}[uU]?\s*:")
    m = pattern.search(search_text)
    if not m:
        return None
    idx = m.end()
    n = len(search_text)
    while idx < n and search_text[idx].isspace():
        idx += 1
    if idx < n and search_text[idx] == "{":
        close_idx = _scan_balanced_braces(search_text, idx)
        if close_idx is not None:
            return search_text[idx + 1 : close_idx].strip()
    brk = re.search(r"\bbreak\s*;", search_text[idx:])
    if brk:
        return search_text[idx : idx + brk.start()].strip()
    return None


def _extract_harness_prelude(harness_text: str, sidecar: dict[str, Any]) -> str:
    """
    Extract `#include` directives and top-level helper declarations from `harness_<module>.c`
    before the template's runtime-skip / `eva_main` / `LLVMFuzzerTestOneInput` blocks.
    """
    if harness_text:
        cut_markers = (
            "#if !defined(__FRAMAC__) || defined(__FRAMAC_EACSL__)",
            "#if defined(__FRAMAC__) && !defined(__FRAMAC_EACSL__)",
            "int eva_main(",
            "int LLVMFuzzerTestOneInput(",
        )
        cut_pos = len(harness_text)
        for marker in cut_markers:
            pos = harness_text.find(marker)
            if pos != -1 and pos < cut_pos:
                cut_pos = pos
        head = harness_text[:cut_pos]
        # Strip Frama-C-only __GLIBC_INTERNAL_INT_TYPES_DEFINED shim if present.
        head = re.sub(
            r"#if defined\(__FRAMAC__\) && !defined\(__FRAMAC_EACSL__\) && !defined\(__GLIBC_INTERNAL_INT_TYPES_DEFINED\).*?#endif\s*#endif",
            "",
            head,
            flags=re.DOTALL,
        )
        # Drop duplicate standard headers we emit unconditionally at the top.
        out_lines: list[str] = []
        for line in head.splitlines():
            stripped = line.strip()
            if stripped.startswith("#include"):
                inc_target = stripped[len("#include") :].strip()
                if inc_target in _STD_HEADERS or "__fc_builtin.h" in inc_target:
                    continue
            if stripped.startswith("#define FRAMAC_FUZZ_COPY"):
                continue
            out_lines.append(line)
        cleaned = "\n".join(out_lines).strip()
        if cleaned:
            return cleaned

    includes: list[str] = []
    for inc in sidecar.get("extra_includes_first") or []:
        includes.append(f'#include "{inc}"' if not str(inc).startswith(("<", '"')) else f"#include {inc}")
    header = sidecar.get("header")
    if isinstance(header, str) and header and header.lower() != "none":
        includes.append(f'#include "{header}"' if not header.startswith(("<", '"')) else f"#include {header}")
    for inc in sidecar.get("extra_includes") or []:
        includes.append(f'#include "{inc}"' if not str(inc).startswith(("<", '"')) else f"#include {inc}")
    return "\n".join(includes)


def _extract_fuzzer_entry_function(harness_text: str) -> str | None:
    """Extract the full `int LLVMFuzzerTestOneInput(...) { ... }` definition for non-dispatch fallback."""
    m = re.search(r"\bint\s+LLVMFuzzerTestOneInput\s*\([^)]*\)\s*\{", harness_text)
    if not m:
        return None
    brace_idx = harness_text.find("{", m.start())
    close_idx = _scan_balanced_braces(harness_text, brace_idx)
    if close_idx is None:
        return None
    return harness_text[m.start() : close_idx + 1]


def _format_c_byte_array(data: bytes, var_name: str = "repro_input") -> tuple[str, str]:
    """Return `(array_decl, len_expr)` for a C `static const uint8_t` byte array."""
    if not data:
        return f"static const uint8_t {var_name}[1] = {{ 0x00 }};", "0U"
    rows: list[str] = []
    for off in range(0, len(data), 12):
        chunk = data[off : off + 12]
        rows.append("    " + ", ".join(f"0x{b:02x}" for b in chunk))
    body = ",\n".join(rows)
    decl = f"static const uint8_t {var_name}[] = {{\n{body}\n}};"
    return decl, f"sizeof({var_name})"


def _render_repro_c(
    *,
    module: str,
    fingerprint: str,
    prelude: str,
    payload: bytes,
    case_selector: int | None,
    case_body: str | None,
    fuzzer_entry_fn: str | None,
    null_terminate: bool = False,
) -> str:
    array_decl, len_expr = _format_c_byte_array(payload)
    lines: list[str] = [
        "/*",
        f" * Standalone reproducer for module: {module}",
        f" * Fingerprint: {fingerprint}",
    ]
    if case_selector is not None:
        lines.append(f" * Dispatch case: {case_selector}")
    lines += [
        " */",
        "",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "#include <stdlib.h>",
        "#include <string.h>",
        "",
    ]
    if prelude:
        lines += [prelude, ""]

    lines += [
        "#ifndef FRAMAC_FUZZ_COPY",
        "#define FRAMAC_FUZZ_COPY(buf, off) ((buf) + (off))",
        "#endif",
        "#ifndef FRAMAC_FUZZ_REJECT",
        "#define FRAMAC_FUZZ_REJECT() ((void)0)",
        "#endif",
        "#ifndef FRAMAC_PROBE_CASE_START",
        "#define FRAMAC_PROBE_CASE_START(c) ((void)0)",
        "#define FRAMAC_PROBE_INIT_FAIL(c) ((void)0)",
        "#define FRAMAC_PROBE_RET_I64(c, v) ((void)0)",
        "#define FRAMAC_PROBE_RET_PTR(c, p) ((void)0)",
        "#endif",
        "",
    ]

    if case_body is not None:
        lines += [
            array_decl,
            "",
            "int main(void) {",
            f"    const size_t repro_len = {len_expr};",
            "    uint8_t *alloc_ptr = (uint8_t *)malloc(repro_len > 0U ? repro_len : 1U);",
            "    if (alloc_ptr == NULL) {",
            "        return 0;",
            "    }",
            "    uint8_t *fuzz_buf = (repro_len > 0U) ? alloc_ptr : (alloc_ptr + 1);",
            "    if (repro_len > 0U) {",
            "        memcpy(fuzz_buf, repro_input, repro_len);",
            "    }",
            "    size_t fuzz_len = repro_len;",
            "    (void)fuzz_buf;",
            "    (void)fuzz_len;",
        ]
        if null_terminate:
            lines += [
                "    uint8_t *cstr_buf = (uint8_t *)malloc(repro_len + 1U);",
                "    if (cstr_buf != NULL) {",
                "        if (repro_len > 0U) { memcpy(cstr_buf, fuzz_buf, repro_len); }",
                "        cstr_buf[repro_len] = 0;",
                "        fuzz_buf = cstr_buf;",
                "        {",
                f"            {case_body}",
                "        }",
                "        free(cstr_buf);",
                "    }",
            ]
        else:
            lines += [
                "    {",
                f"        {case_body}",
                "    }",
            ]
        lines += [
            "    free(alloc_ptr);",
            "    return 0;",
            "}",
            "",
        ]
        return "\n".join(lines)

    # Fallback for non-dispatch or custom harnesses: embed LLVMFuzzerTestOneInput and call from main(void).
    if fuzzer_entry_fn:
        lines += [fuzzer_entry_fn, ""]
    else:
        lines += [
            "extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);",
            "",
        ]
    lines += [
        array_decl,
        "",
        "int main(void) {",
        f"    const size_t repro_len = {len_expr};",
        "    uint8_t *alloc_ptr = (uint8_t *)malloc(repro_len > 0U ? repro_len : 1U);",
        "    if (alloc_ptr == NULL) {",
        "        return 0;",
        "    }",
        "    uint8_t *fuzz_buf = (repro_len > 0U) ? alloc_ptr : (alloc_ptr + 1);",
        "    if (repro_len > 0U) {",
        "        memcpy(fuzz_buf, repro_input, repro_len);",
        "    }",
        "    (void)LLVMFuzzerTestOneInput(fuzz_buf, repro_len);",
        "    free(alloc_ptr);",
        "    return 0;",
        "}",
        "",
    ]
    return "\n".join(lines)


def scaffold_reproducer(
    *,
    run_dir: Path,
    fingerprint: str,
    out_dir: Path,
    artifact: Path | None = None,
    engine: str = "auto",
    allow_candidate: bool = False,
) -> dict[str, Any]:
    """Generate `expected.json`, `build_spec.json`, and `repro.c` in `out_dir`."""
    run_dir = Path(run_dir)
    out_dir = Path(out_dir)

    record, source_kind, candidate = _locate_record(run_dir, fingerprint, allow_candidate=allow_candidate)
    module = _resolve_module(run_dir, record, candidate)
    sidecar_path = run_dir / "workspace" / "harnesses" / f"harness_{module}.json"
    sidecar = load_json_strict(sidecar_path)
    if not isinstance(sidecar, dict):
        raise ArtifactError(f"harness sidecar is not a JSON object: {sidecar_path}")

    harness_rel = str(sidecar.get("harness_file") or f"workspace/harnesses/harness_{module}.c")
    harness_c_path = Path(harness_rel) if Path(harness_rel).is_absolute() else (run_dir / harness_rel)
    harness_text = harness_c_path.read_text(encoding="utf-8", errors="replace") if harness_c_path.is_file() else ""

    build_capture_path = run_dir / "workspace" / "reports" / "build_capture.json"
    build_capture = load_json_optional(build_capture_path, None)
    if build_capture is not None and not isinstance(build_capture, dict):
        build_capture = None

    artifact_path = _resolve_artifact_path(run_dir, record, artifact)
    artifact_bytes = artifact_path.read_bytes()
    art_sha256 = sha256_file(artifact_path)
    resolved_engine = _resolve_engine(engine, record, candidate)

    # Decode dispatch selector if this is a dispatch harness.
    is_dispatch = sidecar.get("entry_style") == "dispatch" or dispatch_selector_of_text(harness_text) is not None
    case_selector: int | None = None
    case_body: str | None = None
    payload = artifact_bytes

    if is_dispatch:
        selector_enc = dispatch_selector_of(sidecar, harness_text)
        text_info = dispatch_selector_of_text(harness_text)
        n_cases = int(
            sidecar.get("dispatch_case_count")
            or len(sidecar.get("dispatch_cases") or [])
            or (text_info[1] if text_info else 0)
        )
        case_selector = dispatch_case_of_bytes(artifact_bytes, n_cases, selector_enc)
        if case_selector is not None:
            width = dispatch_selector_width(selector_enc)
            case_body = extract_dispatch_case_body(harness_text, case_selector)
            if case_body is None:
                dispatch_cases = sidecar.get("dispatch_cases")
                if isinstance(dispatch_cases, list) and 0 <= case_selector < len(dispatch_cases):
                    case_body = str(dispatch_cases[case_selector]).strip()
            if case_body is not None:
                payload = artifact_bytes[width:]

    prelude = _extract_harness_prelude(harness_text, sidecar)
    fuzzer_entry_fn = None if case_body is not None else _extract_fuzzer_entry_function(harness_text)
    repro_c_text = _render_repro_c(
        module=module,
        fingerprint=fingerprint,
        prelude=prelude,
        payload=payload,
        case_selector=case_selector,
        case_body=case_body,
        fuzzer_entry_fn=fuzzer_entry_fn,
        null_terminate=bool(sidecar.get("null_terminate", False)),
    )

    raw_loc = record.get("location")
    loc: dict[str, Any] = raw_loc if isinstance(raw_loc, dict) else {}
    raw_prop = record.get("property")
    prop: dict[str, Any] = raw_prop if isinstance(raw_prop, dict) else {}
    loc_file = normalize_file(str(loc.get("file") or "unknown"))
    loc_line = int(loc.get("line") or 0)
    loc_fn = str(loc.get("function") or "unknown_function")
    prop_kind = str(prop.get("kind") or "crash")
    prop_pred = str(prop.get("predicate") or "")

    expected: dict[str, Any] = {
        "schema_version": 1,
        "fingerprint": fingerprint,
        "module": module,
        "engine": resolved_engine,
        "kind": prop_kind,
        "file": loc_file,
        "line": loc_line,
        "function": loc_fn,
        "predicate": prop_pred,
        "frames_top": _extract_frames_top(record, loc_fn),
        "case_selector": case_selector,
        "artifact_sha256": art_sha256,
    }

    raw_sources = sidecar.get("flow_build_sources") or sidecar.get("sources") or []
    harness_name = harness_c_path.name
    non_harness_sources = [
        str(s)
        for s in compile_inputs([str(x) for x in raw_sources])
        if Path(str(s)).name != harness_name and normalize_file(str(s)) != normalize_file(harness_rel)
    ]

    build_spec: dict[str, Any] = {
        "schema_version": 1,
        "module": module,
        "run_dir": str(run_dir.resolve()),
        "sources": non_harness_sources,
        "cppflags": str(sidecar.get("cppflags") or "-I."),
        "ldflags": str(sidecar.get("ldflags") or ""),
        "header": sidecar.get("header"),
        "entry_style": sidecar.get("entry_style"),
        "recipe": build_capture.get("recipe") if isinstance(build_capture, dict) else None,
        "target": build_capture.get("target") if isinstance(build_capture, dict) else None,
        "base_image": DEFAULT_BASE_IMAGE,
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    expected_path = out_dir / "expected.json"
    build_spec_path = out_dir / "build_spec.json"
    repro_c_path = out_dir / "repro.c"

    atomic_write_json(expected_path, expected)
    atomic_write_json(build_spec_path, build_spec)
    _write_lf_text(repro_c_path, repro_c_text)

    return {
        "status": "ok",
        "source_kind": source_kind,
        "module": module,
        "engine": resolved_engine,
        "case_selector": case_selector,
        "fallback": case_body is None,
        "artifact": str(artifact_path),
        "expected": str(expected_path),
        "build_spec": str(build_spec_path),
        "repro_c": str(repro_c_path),
    }


def _strip_engine_prefix(kind: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", (kind or "").lower()).strip("_")
    for pref in ("asan_", "ubsan_", "lsan_", "eacsl_"):
        if slug.startswith(pref):
            slug = slug[len(pref) :]
            break
    return slug


def _fingerprint_kind(fp: str | None) -> str:
    if not fp or "::" not in fp:
        return ""
    parts = fp.rsplit("::", 2)
    return parts[1] if len(parts) == 3 else ""


def _kinds_match(expected: dict[str, Any], failure: dict[str, Any]) -> bool:
    exp_raw_kind = str(expected.get("kind") or "")
    exp_pred = str(expected.get("predicate") or "")
    obs_raw_kind = str(failure.get("kind") or "")
    obs_alarm = str(failure.get("alarm_kind") or "")
    obs_pred = str(failure.get("predicate") or "")

    exp_slug = _strip_engine_prefix(exp_raw_kind)
    obs_slug = _strip_engine_prefix(obs_raw_kind)

    # If both carry a specific sanitizer/failure kind (e.g. heap_buffer_overflow vs stack_buffer_overflow),
    # require those specific kinds to agree rather than collapsing both to mem_access.
    exp_specific = exp_slug and exp_slug not in _GENERIC_KINDS
    obs_specific = obs_slug and obs_slug not in _GENERIC_KINDS
    if exp_specific and obs_specific:
        if exp_slug == obs_slug:
            return True
        # Allow matching when one side stored the alarm kind (e.g. "mem_access") and the other the ASan kind.
        exp_norm = normalize_kind(exp_raw_kind, exp_pred)
        obs_norm = normalize_kind(obs_alarm or obs_raw_kind, obs_pred)
        if exp_slug == obs_norm or obs_slug == exp_norm:
            return True
        return False

    exp_keys = {
        k
        for k in (exp_slug, normalize_kind(exp_raw_kind, exp_pred), _fingerprint_kind(expected.get("fingerprint")))
        if k
    }
    obs_keys = {k for k in (obs_slug, obs_alarm, normalize_kind(obs_alarm or obs_raw_kind, obs_pred)) if k}
    return bool(exp_keys & obs_keys)


def match_failure(
    expected: dict[str, Any],
    failure: dict[str, Any],
    observed_fp: str | None,
) -> tuple[bool, str]:
    """
    Compare a parsed runtime failure against `expected.json`.
    Matches on exact fingerprint OR same normalized `(kind, function, basename(file))`.
    """
    exp_fp = str(expected.get("fingerprint") or "")
    if observed_fp and exp_fp and observed_fp == exp_fp:
        return True, "exact_fingerprint"

    exp_fn = str(expected.get("function") or "").strip()
    obs_fn = str(failure.get("function") or "").strip()
    if not exp_fn or not obs_fn or exp_fn == "unknown_function" or obs_fn == "unknown_function":
        return False, "function_mismatch"
    if exp_fn != obs_fn:
        return False, "function_mismatch"

    exp_base = posixpath.basename(normalize_file(str(expected.get("file") or "")))
    obs_base = posixpath.basename(normalize_file(str(failure.get("file") or "")))
    if not exp_base or not obs_base or exp_base == "unknown" or obs_base == "unknown":
        return False, "file_mismatch"
    if exp_base != obs_base:
        return False, "file_mismatch"

    if not _kinds_match(expected, failure):
        return False, "kind_mismatch"

    return True, "normalized_site_match"


def _resolve_build_sources(c_file: Path, build_spec: dict[str, Any]) -> list[str]:
    run_dir_raw = build_spec.get("run_dir")
    run_dir = Path(str(run_dir_raw)) if run_dir_raw else None
    sources: list[str] = [str(c_file)]
    for raw in compile_inputs([str(s) for s in (build_spec.get("sources") or [])]):
        p = Path(raw)
        if not p.is_absolute() and not p.exists() and run_dir is not None:
            candidate = run_dir / p
            if candidate.exists():
                p = candidate
            else:
                ws_candidate = run_dir / "workspace" / "work" / p
                if ws_candidate.exists():
                    p = ws_candidate
        sources.append(str(p))
    return sources


def try_reproducer(
    *,
    c_file: Path,
    expected_path: Path,
    build_spec_path: Path,
    engine: str = "auto",
    timeout_s: int = DEFAULT_TRY_TIMEOUT_S,
) -> dict[str, Any]:
    """Compile `c_file` without libFuzzer, run it under `sandbox_exec`, and classify against `expected.json`."""
    c_file = Path(c_file)
    expected = load_json_strict(Path(expected_path))
    build_spec = load_json_strict(Path(build_spec_path))
    if not isinstance(expected, dict):
        raise ArtifactError(f"expected.json is not a JSON object: {expected_path}")
    if not isinstance(build_spec, dict):
        raise ArtifactError(f"build_spec.json is not a JSON object: {build_spec_path}")

    resolved_engine = engine if engine in ("sanitizers", "eacsl") else str(expected.get("engine") or "sanitizers")
    if resolved_engine not in ("sanitizers", "eacsl"):
        resolved_engine = "sanitizers"

    sources = _resolve_build_sources(c_file, build_spec)
    cppflags = str(build_spec.get("cppflags") or "-I.")
    ldflags = str(build_spec.get("ldflags") or "")
    run_dir_raw = build_spec.get("run_dir")
    run_cwd = Path(str(run_dir_raw)) if run_dir_raw and Path(str(run_dir_raw)).is_dir() else None

    with tempfile.TemporaryDirectory(prefix="framac_repro_try_") as tmp_str:
        tmp_dir = Path(tmp_str)
        out_bin = tmp_dir / "repro_bin"

        if resolved_engine == "eacsl":
            comp = fuzz_build.compile_eacsl_binary(
                sources,
                out_bin,
                cppflags=cppflags,
                fuzzer_flag=False,
                ldflags_extra=ldflags,
                use_cache=False,
            )
        else:
            comp = fuzz_build.compile_sanitizer_binary(
                sources,
                out_bin,
                cppflags=cppflags,
                fuzzer_flag=False,
                ldflags_extra=ldflags,
                use_cache=False,
            )

        if int(comp.get("returncode", 1)) != 0:
            comp_out = "\n".join(p for p in (str(comp.get("stdout") or ""), str(comp.get("stderr") or "")) if p)
            return {
                "status": STATUS_COMPILE_ERROR,
                "exit_code": EXIT_COMPILE_ERROR,
                "engine": resolved_engine,
                "reason": "compilation_failed",
                "compile_returncode": int(comp.get("returncode", 1)),
                "output": comp_out,
                "observed_fingerprint": None,
                "expected_fingerprint": expected.get("fingerprint"),
            }

        binary_path = Path(str(comp.get("binary") or out_bin))
        scratch_dir = tmp_dir / "scratch"
        scratch_dir.mkdir(parents=True, exist_ok=True)
        limits = Limits(cpu_seconds=max(1, int(timeout_s) * 2), ignore_sigpipe=True)

        try:
            res = sandbox_exec.run_sandboxed(
                [str(binary_path)],
                writable=[scratch_dir],
                timeout_s=int(timeout_s),
                cwd=run_cwd or scratch_dir,
                limits=limits,
                extra_env=dict(SANITIZER_RUNTIME_ENV),
            )
        except SandboxUnavailable as exc:
            return {
                "status": STATUS_COMPILE_ERROR,
                "exit_code": EXIT_COMPILE_ERROR,
                "engine": resolved_engine,
                "reason": f"sandbox_unavailable: {exc}",
                "output": str(exc),
                "observed_fingerprint": None,
                "expected_fingerprint": expected.get("fingerprint"),
            }

        combined = "\n".join(p for p in (res.stdout, res.stderr) if p)
        if res.timed_out:
            return {
                "status": STATUS_DIFFERENT_CRASH,
                "exit_code": EXIT_MISMATCH_OR_NO_CRASH,
                "engine": resolved_engine,
                "reason": "timed_out",
                "returncode": res.returncode,
                "timed_out": True,
                "output": combined,
                "observed_fingerprint": None,
                "expected_fingerprint": expected.get("fingerprint"),
            }

        failure = failure_identity.parse_runtime_failure(combined, binary=binary_path)
        if failure is not None:
            observed_fp = failure_identity.failure_fingerprint(failure)
            matched, match_reason = match_failure(expected, failure, observed_fp)
            if matched:
                return {
                    "status": STATUS_SAME_CRASH,
                    "exit_code": EXIT_SAME_CRASH,
                    "engine": resolved_engine,
                    "reason": match_reason,
                    "returncode": res.returncode,
                    "timed_out": False,
                    "output": combined,
                    "observed_fingerprint": observed_fp,
                    "expected_fingerprint": expected.get("fingerprint"),
                    "failure": failure,
                }
            return {
                "status": STATUS_DIFFERENT_CRASH,
                "exit_code": EXIT_MISMATCH_OR_NO_CRASH,
                "engine": resolved_engine,
                "reason": match_reason,
                "returncode": res.returncode,
                "timed_out": False,
                "output": combined,
                "observed_fingerprint": observed_fp,
                "expected_fingerprint": expected.get("fingerprint"),
                "failure": failure,
            }

        if res.returncode == 0:
            return {
                "status": STATUS_NO_CRASH,
                "exit_code": EXIT_MISMATCH_OR_NO_CRASH,
                "engine": resolved_engine,
                "reason": "exited_cleanly",
                "returncode": 0,
                "timed_out": False,
                "output": combined,
                "observed_fingerprint": None,
                "expected_fingerprint": expected.get("fingerprint"),
            }

        return {
            "status": STATUS_DIFFERENT_CRASH,
            "exit_code": EXIT_MISMATCH_OR_NO_CRASH,
            "engine": resolved_engine,
            "reason": f"unparsed_nonzero_exit_{res.returncode}",
            "returncode": res.returncode,
            "timed_out": False,
            "output": combined,
            "observed_fingerprint": None,
            "expected_fingerprint": expected.get("fingerprint"),
        }


def _render_dockerfile(expected: dict[str, Any], build_spec: dict[str, Any]) -> str:
    base_image = str(build_spec.get("base_image") or DEFAULT_BASE_IMAGE)
    engine = str(expected.get("engine") or "sanitizers")
    cppflags = str(build_spec.get("cppflags") or "-I.")
    ldflags = str(build_spec.get("ldflags") or "")
    sources = [str(s) for s in compile_inputs([str(x) for x in (build_spec.get("sources") or [])])]
    recipe = build_spec.get("recipe") if isinstance(build_spec.get("recipe"), dict) else None

    lines: list[str] = [
        f"FROM {base_image}",
        "WORKDIR /repro",
    ]
    if recipe:
        packages = [str(p) for p in (recipe.get("packages") or []) if str(p).strip()]
        if packages:
            pkg_str = " ".join(shlex.quote(p) for p in packages)
            lines += [
                "RUN apt-get update && apt-get install -y --no-install-recommends "
                f"{pkg_str} && rm -rf /var/lib/apt/lists/*",
            ]
        build_cmd = str(recipe.get("command") or "").strip()
        if build_cmd:
            lines.append(f"# Target build recipe: {build_cmd}")

    lines.append("COPY repro.c /repro/repro.c")
    src_args = " ".join(shlex.quote(s) for s in sources)
    if engine == "eacsl":
        compile_cmd = (
            f"e-acsl-gcc.sh -c --rte=all -o /repro/repro /repro/repro.c {src_args} {cppflags} {ldflags}".strip()
        )
    else:
        compile_cmd = (
            "clang -g -O1 -fcommon -fsanitize=address,undefined -fno-sanitize-recover=all "
            f"{cppflags} /repro/repro.c {src_args} -o /repro/repro {ldflags}"
        ).strip()

    lines += [
        f"RUN {compile_cmd}",
        'ENV ASAN_OPTIONS="abort_on_error=1:allocator_may_return_null=1"',
        'ENV UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"',
        'CMD ["/repro/repro"]',
        "",
    ]
    return "\n".join(lines)


def _render_run_sh(module: str) -> str:
    tag = re.sub(r"[^a-z0-9._-]+", "-", f"framac-repro-{module.lower()}").strip("-") or "framac-repro"
    return "\n".join(
        [
            "#!/usr/bin/env bash",
            "set -euo pipefail",
            "",
            'SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"',
            f'IMAGE_TAG="{tag}"',
            "",
            'docker build -t "${IMAGE_TAG}" "${SCRIPT_DIR}"',
            'docker run --rm --network=none "${IMAGE_TAG}"',
            "",
        ]
    )


def _render_issue_md(
    *,
    expected: dict[str, Any],
    repro_c_text: str,
    dockerfile_text: str,
    observed_output: str,
    finding: dict[str, Any] | None,
) -> str:
    title = (
        str(finding.get("title"))
        if isinstance(finding, dict) and finding.get("title")
        else f"{expected['kind']} in `{expected['function']}` (`{expected['file']}:{expected['line']}`)"
    )
    severity = str(finding.get("severity") or "unspecified") if isinstance(finding, dict) else "unspecified"
    lines: list[str] = [
        f"# {title}",
        "",
        "## Summary",
        "",
        f"- **Module:** `{expected['module']}`",
        f"- **Location:** `{expected['file']}:{expected['line']}` in `{expected['function']}`",
        f"- **Kind:** `{expected['kind']}`",
        f"- **Severity:** `{severity}`",
        f"- **Engine:** `{expected['engine']}`",
        f"- **Fingerprint:** `{expected['fingerprint']}`",
    ]
    if expected.get("predicate"):
        lines.append(f"- **Predicate:** `{expected['predicate']}`")
    lines.append("")

    if isinstance(finding, dict) and finding.get("description"):
        lines += ["## Description", "", str(finding["description"]), ""]

    if isinstance(finding, dict) and isinstance(finding.get("trace"), list) and finding["trace"]:
        lines += ["## Trace", ""]
        for step in finding["trace"]:
            if isinstance(step, dict):
                lines.append(
                    f"- **{step.get('kind', 'step')}** `{step.get('file', '')}:{step.get('line', 0)}` "
                    f"(`{step.get('function', '')}`): {step.get('description', '')}"
                )
        lines.append("")

    lines += [
        "## Reproducer (`repro.c`)",
        "",
        "```c",
        repro_c_text.rstrip("\n"),
        "```",
        "",
        "## Observed Crash Output",
        "",
        "```text",
        (observed_output.strip() or "(no crash output captured; packaged with --skip-verify)"),
        "```",
        "",
        "<details>",
        "<summary>Dockerfile</summary>",
        "",
        "```dockerfile",
        dockerfile_text.rstrip("\n"),
        "```",
        "",
        "</details>",
        "",
    ]
    return "\n".join(lines)


def package_bundle(
    *,
    c_file: Path,
    expected_path: Path,
    build_spec_path: Path,
    out_dir: Path,
    finding_json: Path | None = None,
    engine: str = "auto",
    timeout_s: int = DEFAULT_TRY_TIMEOUT_S,
    skip_verify: bool = False,
) -> dict[str, Any]:
    """Verify `c_file` with `try_reproducer` (unless `skip_verify`) and emit the frozen disclosure bundle."""
    c_file = Path(c_file)
    expected = load_json_strict(Path(expected_path))
    build_spec = load_json_strict(Path(build_spec_path))
    if not isinstance(expected, dict):
        raise ArtifactError(f"expected.json is not a JSON object: {expected_path}")
    if not isinstance(build_spec, dict):
        raise ArtifactError(f"build_spec.json is not a JSON object: {build_spec_path}")

    observed_output = ""
    if not skip_verify:
        try_res = try_reproducer(
            c_file=c_file,
            expected_path=expected_path,
            build_spec_path=build_spec_path,
            engine=engine,
            timeout_s=timeout_s,
        )
        if try_res["status"] != STATUS_SAME_CRASH:
            return {
                "status": "refused",
                "exit_code": int(try_res["exit_code"]),
                "try_status": try_res["status"],
                "reason": f"reproducer did not verify as SAME_CRASH (got {try_res['status']}: {try_res.get('reason')})",
                "try_result": try_res,
            }
        observed_output = str(try_res.get("output") or "")

    finding: dict[str, Any] | None = None
    if finding_json is not None:
        loaded = load_json_strict(Path(finding_json))
        fp = expected.get("fingerprint")
        if isinstance(loaded, list):
            for item in loaded:
                if isinstance(item, dict) and item.get("fingerprint") == fp:
                    finding = item
                    break
        elif isinstance(loaded, dict) and loaded.get("fingerprint") == fp:
            finding = loaded

    if not observed_output and isinstance(finding, dict):
        reproducers = finding.get("reproducers")
        if isinstance(reproducers, list) and reproducers and isinstance(reproducers[0], dict):
            observed_output = str(reproducers[0].get("observed_result") or "")

    repro_bytes = c_file.read_bytes()
    repro_text = repro_bytes.decode("utf-8", errors="replace")
    dockerfile_text = _render_dockerfile(expected, build_spec)
    run_sh_text = _render_run_sh(str(expected.get("module") or "target"))
    issue_md_text = _render_issue_md(
        expected=expected,
        repro_c_text=repro_text,
        dockerfile_text=dockerfile_text,
        observed_output=observed_output,
        finding=finding,
    )

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    repro_out = out_dir / "repro.c"
    dockerfile_out = out_dir / "Dockerfile"
    run_sh_out = out_dir / "run.sh"
    issue_out = out_dir / "ISSUE.md"

    repro_out.write_bytes(repro_bytes)
    _write_lf_text(dockerfile_out, dockerfile_text)
    _write_lf_text(run_sh_out, run_sh_text)
    _write_lf_text(issue_out, issue_md_text)

    return {
        "status": "packaged",
        "exit_code": 0,
        "verified": not skip_verify,
        "out_dir": str(out_dir),
        "files": {
            "repro_c": str(repro_out),
            "dockerfile": str(dockerfile_out),
            "run_sh": str(run_sh_out),
            "issue_md": str(issue_out),
        },
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Standalone C reproducer scaffold, deterministic `try` oracle, and disclosure bundle packager."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scaf = sub.add_parser("scaffold", help="Generate expected.json, build_spec.json, and standalone repro.c.")
    p_scaf.add_argument("--run-dir", type=Path, required=True, help="Pipeline run directory.")
    p_scaf.add_argument("--fingerprint", required=True, help="Target finding fingerprint.")
    p_scaf.add_argument("--out", type=Path, required=True, help="Output directory for scaffolded files.")
    p_scaf.add_argument("--artifact", type=Path, default=None, help="Explicit crash artifact path.")
    p_scaf.add_argument("--engine", choices=["auto", "sanitizers", "eacsl"], default="auto")
    p_scaf.add_argument(
        "--allow-candidate",
        action="store_true",
        default=False,
        help="Allow scaffolding from candidates.json or non-confirmed findings.",
    )

    p_try = sub.add_parser("try", help="Compile and run a C reproducer against expected.json.")
    p_try.add_argument("--file", type=Path, required=True, help="Path to standalone C reproducer.")
    p_try.add_argument("--expected", type=Path, required=True, help="Path to expected.json.")
    p_try.add_argument("--build-spec", type=Path, required=True, help="Path to build_spec.json.")
    p_try.add_argument("--engine", choices=["auto", "sanitizers", "eacsl"], default="auto")
    p_try.add_argument("--timeout", type=int, default=DEFAULT_TRY_TIMEOUT_S, help="Execution timeout in seconds.")
    p_try.add_argument("--show", action="store_true", default=False, help="Print full compiler/runtime output.")
    p_try.add_argument("--json", action="store_true", default=False, dest="as_json", help="Emit JSON result.")

    p_pkg = sub.add_parser("package", help="Verify and package a frozen maintainer disclosure bundle.")
    p_pkg.add_argument("--file", type=Path, required=True, help="Path to verified C reproducer.")
    p_pkg.add_argument("--expected", type=Path, required=True, help="Path to expected.json.")
    p_pkg.add_argument("--build-spec", type=Path, required=True, help="Path to build_spec.json.")
    p_pkg.add_argument("--out", type=Path, required=True, help="Output directory for the bundle.")
    p_pkg.add_argument("--finding-json", type=Path, default=None, help="Optional findings.json for rich ISSUE.md.")
    p_pkg.add_argument("--engine", choices=["auto", "sanitizers", "eacsl"], default="auto")
    p_pkg.add_argument("--timeout", type=int, default=DEFAULT_TRY_TIMEOUT_S)
    p_pkg.add_argument(
        "--skip-verify",
        action="store_true",
        default=False,
        help="Skip `try` verification before packaging (not recommended).",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.cmd == "scaffold":
            res = scaffold_reproducer(
                run_dir=args.run_dir,
                fingerprint=args.fingerprint,
                out_dir=args.out,
                artifact=args.artifact,
                engine=args.engine,
                allow_candidate=args.allow_candidate,
            )
            print(json.dumps(res, indent=2))
            return 0

        if args.cmd == "try":
            res = try_reproducer(
                c_file=args.file,
                expected_path=args.expected,
                build_spec_path=args.build_spec,
                engine=args.engine,
                timeout_s=args.timeout,
            )
            if args.as_json:
                print(json.dumps(res, indent=2))
            else:
                print(f"{res['status']} ({res.get('reason', '')})")
                if args.show and res.get("output"):
                    print(res["output"])
            return int(res["exit_code"])

        if args.cmd == "package":
            res = package_bundle(
                c_file=args.file,
                expected_path=args.expected,
                build_spec_path=args.build_spec,
                out_dir=args.out,
                finding_json=args.finding_json,
                engine=args.engine,
                timeout_s=args.timeout,
                skip_verify=args.skip_verify,
            )
            print(json.dumps(res, indent=2))
            return int(res["exit_code"])
    except ArtifactError as exc:
        print(json.dumps({"status": "error", "error": str(exc)}), file=sys.stderr)
        return 2

    return 2


if __name__ == "__main__":
    sys.exit(main())
