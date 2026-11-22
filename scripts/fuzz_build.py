"""
Building the fuzz binaries of one module: the E-ACSL build (with its cache), the sanitizer and coverage
builds, the selftest result that gates E-ACSL, the link repair of the sources, and build_module_binary, which
both the build subcommand and the campaign call (D3, moved out of run_eacsl_fuzz).

Callers reach these functions as `fuzz_build.<name>` (D12), so a test patch on this module applies to every
caller. No module here imports run_eacsl_fuzz.
"""

from __future__ import annotations

import contextlib
import functools
import hashlib
import json
import os
import posixpath
import re
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any

import cache
import fc_cpp_wrapper_eacsl
import include_context
import target_env
from c_definitions import TYPE_MODIFIERS_AND_PRIMITIVES, extract_functions_from_code
from eacsl_toolchain import (
    EACSL_FC_EXTRA_FLAGS,
    EACSL_FORMAT_RUNTIME_PATCH,
    EACSL_FULL_MTRACKING_DEFINES,
    EACSL_GCC_CHECK_OPTIONS,
    EACSL_HEAP_ZONE_MB,
    EACSL_META_LIBC_UNCHECKED,
    EACSL_META_LIBC_WRITERS,
    EACSL_NO_LIBC_CHECKS,
    EACSL_RTE_INITIALIZED_FLAG,
    ERRNO_SHIM_FUNCTIONS,
    INCOMPLETE_ALIGNOF_ASSUMPTION,
    UnsafePassthroughError,
    attribute_ignored_annotations,
    build_eacsl_flag_sets,
    build_errno_shim_object,
    build_fallback_object,
    defines_fuzzer_initialize,
    eacsl_meta_file_text,
    eacsl_meta_guarded_text,
    eacsl_meta_libc_text,
    eacsl_share_dir,
    eacsl_zone_size_options,
    fix_readonly_scalar_globals,
    generate_errno_shim_source,
    is_eacsl_instrumented,
    libc_writer_calls,
    mark_formals_initialized,
    mark_wrapper_results_initialized,
    meta_checks,
    meta_stage_flags,
    normalize_passthrough,
    order_literal_registrations,
    parse_ignored_annotations,
    parse_missing_functions,
    parse_undefined_fallbacks,
    prepare_patched_eacsl_share,
    preprocess_source,
    rejected_meta_property,
    reset_verdict_on_input_entry,
    resolve_fuzz_init_source,
    rewrite_forward_array_sizes,
    rewrite_forward_tag_declarations,
    rewrite_incomplete_alignof,
    rewrite_misplaced_fallthrough,
    rewrite_sound_verdict_resets,
    rewrite_sync_builtins,
    rewrite_trailing_alignas,
    select_eacsl_binary,
    skip_va_list_initialized_checks,
    slice_has_pthread,
    uses_full_mtracking,
)
from failure_identity import SECURITY_META_SUFFIX, is_harness_fuzz_function, meta_sidecar_path
from fingerprint import normalize_file
from framac_common import compile_inputs, load_json_optional, scan_undeclared_functions
from fuzz_common import (
    BUILD_TIMEOUT_S,
    DEFAULT_SELFTEST_JSON,
    _in_agent_scratch,
)

# Part of the build cache key: the shape of `ignored_annotations` in a build result. Raise it when
# the list's fields or the rule that attributes an entry to a function change.
IGNORED_ANNOTATIONS_VERSION = 1


def _decode(data) -> str:
    if data is None:
        return ""
    return data.decode("utf-8", errors="replace") if isinstance(data, bytes) else str(data)


def _harness_header_entries(sources: list[str]) -> list[str]:
    """
    The functions defined in a public header that an `--api` harness among `sources` calls as entry
    points (docs/plans/header-entry-points-plan.md, HD8): the `entry` of its sidecar's `api_cases`
    (`harness_<m>.json` next to it) that the DAG (`workspace/reports/callgraph_dag.json`, two levels
    up from the harness) records as `header` and `is_static`. Nothing when either file is missing.
    """
    out: set[str] = set()
    for src in sources:
        p = Path(src)
        if not (p.name.startswith("harness_") and p.suffix == ".c"):
            continue
        try:
            sidecar = load_json_optional(p.with_suffix(".json"), None)
            dag = load_json_optional(p.parent.parent / "reports" / "callgraph_dag.json", None)
        except Exception:  # noqa: BLE001 - an unreadable sidecar or DAG adds no name, as a missing one
            continue
        if not isinstance(sidecar, dict) or not isinstance(dag, dict):
            continue
        functions = dag.get("functions") or {}
        for lay in sidecar.get("api_cases") or []:
            key = lay.get("entry") if isinstance(lay, dict) else None
            if not isinstance(key, str):
                continue
            rec = functions.get(key)
            if isinstance(rec, dict) and rec.get("header") and rec.get("is_static"):
                out.add(str(rec.get("name") or key.rsplit("#", 1)[-1]))
    return sorted(out)


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
    # The public header functions an `--api` harness calls (`_harness_header_entries`): no source
    # defines them, so the scan below never sees them. A name Frama-C does not know is dropped by the
    # instrumentation's retry (`rte_select_dropped`).
    discovered: set[str] = {
        n
        for n in _harness_header_entries(sources)
        if n not in ("eva_main", "main") and not is_harness_fuzz_function(n) and n not in TYPE_MODIFIERS_AND_PRIMITIVES
    }
    for src in sources:
        p = Path(src)
        if not p.is_file() or p.name.startswith("harness_") or p.name in (LINK_STUBS_FILE, LINK_GLOBALS_FILE):
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
                    and name not in ("eva_main", "main", "__framac_link_stub_called", "__framac_write_all")
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


# What `_run_tool` returns and appends to stderr when a build step outlives its time limit; build-check
# (pipeline_make.KNOWN_EACSL_FAILURES, `eacsl_build_timeout`) reads the line from the compile log.
BUILD_TIMEOUT_RC = 124
BUILD_TIME_LIMIT_TEXT = "s build time limit"


# Where a run keeps its build capture; run-relative, as the Make recipes run in the run directory.
DEFAULT_CAPTURE_PATH = Path("workspace/reports/build_capture.json")


@functools.lru_cache(maxsize=4)
def _capture_context(path: str, mtime_ns: int) -> tuple[dict, str | None]:
    """The build capture at `path` and the DAG's `target_dir` next to it (cached per file version)."""
    capture = load_json_optional(Path(path), None)
    dag = load_json_optional(Path(path).parent / "callgraph_dag.json", None)
    target_dir = dag.get("target_dir") if isinstance(dag, dict) else None
    return (capture if isinstance(capture, dict) else {}), (str(target_dir) if target_dir else None)


def with_capture_include_dirs(
    cppflags: str, sources: list[str], capture_path: Path | str | None = None
) -> tuple[str, list[str]]:
    """
    `cppflags` with the `-I` / `-iquote` directories the build capture's compiles of `sources` search and
    `cppflags` lacks (include_context.source_include_dirs), and the flags added. Unchanged without a capture
    (`capture_path`, default the run's DEFAULT_CAPTURE_PATH).
    """
    path = Path(capture_path) if capture_path is not None else DEFAULT_CAPTURE_PATH
    try:
        mtime = path.stat().st_mtime_ns
    except OSError:
        return cppflags, []
    capture, target_dir = _capture_context(str(path.resolve()), mtime)
    if not capture:
        return cppflags, []
    return include_context.source_include_dirs(cppflags, sources, capture, target_dir)


def _run_tool(cmd: list[str], runner=subprocess.run, timeout: float | None = BUILD_TIMEOUT_S) -> tuple[int, str, str]:
    try:
        proc = runner(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        limit = f"\n{cmd[0]} exceeded the {timeout} {BUILD_TIME_LIMIT_TEXT}\n"
        return BUILD_TIMEOUT_RC, _decode(exc.stdout), _decode(exc.stderr) + limit
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
    libc_checks: bool = True,
    security_meta: dict | None = None,
) -> dict | None:
    """
    Everything an E-ACSL build depends on besides file contents (None: flags the build would refuse).
    `security_meta` is the loaded plan of a build with MetAcsl properties (resolve_security_meta): the
    key `security_meta` (`_security_meta_material`) is there only then, so a build without properties
    keeps the material it always had and is never restored for one with them, nor the reverse.
    """
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
        # The generated libc shim is linked into the binary, and no source or flag says when its text changes.
        "libc_shim": hashlib.sha256(
            generate_errno_shim_source([f[1] for f in ERRNO_SHIM_FUNCTIONS]).encode("utf-8")
        ).hexdigest(),
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
        "check_options": _check_options(is_modern, libc_checks),
        "runtime_patches": _runtime_patches(_check_options(is_modern, libc_checks)),
        "zone_sizes": _zone_size_options(is_modern),
        # A build stored before its result listed the annotations E-ACSL ignored must not be restored.
        "ignored_annotations": IGNORED_ANNOTATIONS_VERSION,
        **({"security_meta": _security_meta_material(security_meta)} if security_meta else {}),
    }


def _security_meta_material(plan: dict) -> dict:
    """
    What the MetAcsl properties add to the key of an E-ACSL build (plan: resolve_security_meta's
    `loaded` result), all of it known before the build:
      text         the digest of the meta file with every selected property (eacsl_security_meta_text's
                   text, libc writers' assigns included; a property MetAcsl rejects during the build,
                   and contracts the build drops, are part of the cached outcome);
      stage        the Frama-C flags of the MetAcsl stage and the e-acsl-gcc options that open the
                   next one (eacsl_toolchain.meta_stage_flags);
      properties, functions, harness_functions, left_out
                   what the sidecar and the result's `security_props` are written from;
      max_rejected SECURITY_META_MAX_REJECTED, which bounds the rejections one build absorbs.
    The path of security_props.json is not in it: Make names the file, a replay or the build check
    may find it by default, and the same properties must give the same entry.
    """
    selected = plan.get("selected") or []
    # The text the build tries first: guarded, with the libc writers' assigns (eacsl_security_meta_text).
    built = eacsl_security_meta_text(plan)
    text = built[0] if built else ""
    first, options = meta_stage_flags(["-rte"])
    return {
        "text": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "stage": [first, options],
        "properties": {
            str(p["name"]): {"obligation_class": p.get("obligation_class"), "instances": list(p.get("instances") or [])}
            for p in selected
        },
        "functions": plan.get("functions") or {},
        "harness_functions": plan.get("harness_functions") or [],
        "left_out": plan.get("left_out") or [],
        "max_rejected": SECURITY_META_MAX_REJECTED,
    }


def _zone_size_options(is_modern: bool) -> list[str]:
    """Stage-2 `--zone-sizes` (eacsl_toolchain.EACSL_HEAP_ZONE_MB); the long-option CLI of Frama-C <= 32 gets none."""
    return eacsl_zone_size_options(EACSL_HEAP_ZONE_MB) if is_modern else []


def _check_options(is_modern: bool, libc_checks: bool) -> list[str]:
    """e-acsl-gcc options for both stages (EACSL_GCC_CHECK_OPTIONS); the long-option CLI of Frama-C <= 32 gets none."""
    return list(EACSL_GCC_CHECK_OPTIONS) if is_modern and libc_checks else []


def _runtime_patches(check_options: list[str]) -> list[str]:
    """Patches of the E-ACSL runtime a build with `check_options` compiles in (EACSL_FORMAT_RUNTIME_PATCH)."""
    return [EACSL_FORMAT_RUNTIME_PATCH] if "--validate-format-strings" in check_options else []


# A compiler error in the patched copy's e_acsl_stdio.c (`<share>/libc_replacements/e_acsl_stdio.c:998:10: error: ...`).
_PATCHED_STDIO_ERROR_RE = re.compile(r"libc_replacements/e_acsl_stdio\.c:\d+:\d+: error:")


def _format_runtime_share(eacsl_bin: str, dest_root: Path) -> dict:
    """The patched E-ACSL share directory for stage 2 (eacsl_toolchain.prepare_patched_eacsl_share)."""
    src = eacsl_share_dir(eacsl_bin)
    if src is None:
        return {
            "patch": EACSL_FORMAT_RUNTIME_PATCH,
            "status": "not_applied",
            "reason": f"no E-ACSL share directory beside {eacsl_bin}",
        }
    try:
        patch = prepare_patched_eacsl_share(src, dest_root)
    except OSError as exc:
        return {"patch": EACSL_FORMAT_RUNTIME_PATCH, "status": "not_applied", "reason": f"copy failed: {exc}"}
    if patch["status"] == "applied" and any(c.isspace() for c in patch["share"]):
        # e-acsl-gcc passes `-I$EACSL_SHARE` unquoted.
        return {
            "patch": EACSL_FORMAT_RUNTIME_PATCH,
            "status": "not_applied",
            "reason": "share path contains whitespace",
        }
    return patch


_GETENV_CALL_RE = re.compile(r"\bgetenv\s*\(")


_ENVIRON_KEEP_SOURCE = """\
/* Generated by run_eacsl_fuzz.py: preserve libc `environ` across __e_acsl_memory_init.
 * Upstream Frama-C E-ACSL's argv_alloca() (e_acsl_segment_observation_model.c /
 * e_acsl_bittree_observation_model.c) registers and marks initialized every string in
 * `environ`, advancing global `extern char **environ` in-place (`environ++`) until NULL.
 * Without restoring `environ`, every subsequent `getenv(...)` call sees an empty environment. */
#include <stddef.h>

extern char **environ;
extern void __real___e_acsl_memory_init(int *argc_ref, char ***argv_ref, size_t ptr_size);

void __wrap___e_acsl_memory_init(int *argc_ref, char ***argv_ref, size_t ptr_size) {
    char **saved_environ = environ;
    __real___e_acsl_memory_init(argc_ref, argv_ref, ptr_size);
    environ = saved_environ;
}
"""


def _build_environ_keep_object(
    instrumented_text: str,
    out_dir: Path,
    runner=subprocess.run,
    compiler: str = "clang",
    timeout: float | None = BUILD_TIMEOUT_S,
) -> dict:
    """
    Build `eacsl_env_keep.o` (`-Wl,--wrap=__e_acsl_memory_init`) when the instrumented slice calls
    `getenv(...)`, so E-ACSL's `argv_alloca()` does not leave global `environ` pointing at its
    terminating NULL entry.
    """
    if not _GETENV_CALL_RE.search(instrumented_text):
        return {"status": "none"}
    out_dir.mkdir(parents=True, exist_ok=True)
    src = out_dir / "eacsl_env_keep.c"
    obj = out_dir / "eacsl_env_keep.o"
    src.write_text(_ENVIRON_KEEP_SOURCE, encoding="utf-8", newline="\n")
    cmd = [compiler, "-c", "-O1", "-Werror", "-std=gnu17", str(src), "-o", str(obj)]
    try:
        proc = runner(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        rc, err = proc.returncode, (proc.stderr or "")[-4000:]
    except subprocess.TimeoutExpired:
        rc, err = 124, f"{compiler} exceeded the {timeout} s build time limit"
    except OSError as exc:
        rc, err = 127, str(exc)
    if rc != 0:
        return {"status": "error", "reason": f"environ keep shim failed to compile: {err}"}
    return {
        "status": "built",
        "object": str(obj),
        "source": str(src),
        "wrap_flags": "-Wl,--wrap=__e_acsl_memory_init",
    }


# ---------------------------------------------------------------------------------------------------
# MetAcsl properties checked at run time (docs/plans/metacsl-exploitation-plan.md, package C)
# ---------------------------------------------------------------------------------------------------

# The run's property file when no path is given (plan section 3.2), as run_wp_function.SECURITY_PROPS_ENV.
SECURITY_PROPS_ENV = "FRAMAC_SECURITY_PROPS"
# Next to the binary: the log of a build the properties made fail (the module is then built without them).
SECURITY_META_LOG_SUFFIX = ".security_meta.log"
# The log of a build the libc writers' assigns made fail (redone without them, _build_with_security_meta).
SECURITY_META_LIBC_LOG_SUFFIX = ".security_meta_libc.log"
# How many properties MetAcsl may reject, one stage-1 run each, before the module is built without any.
SECURITY_META_MAX_REJECTED = 3

_C_COMMENT_RE = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)
_C_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
_META_CONTEXT_RE = re.compile(r"\\context\(\s*\\(?P<context>\w+)\s*\)")


def _meta_targets(acsl: str) -> tuple[bool, set[str]]:
    r"""(`\targets` is a plain list of functions, the names it lists) of one meta-property's text."""
    start = acsl.find("\\targets(")
    if start < 0:
        return False, set()
    depth, end = 0, len(acsl)
    for i in range(start + len("\\targets"), len(acsl)):
        depth += {"(": 1, ")": -1}.get(acsl[i], 0)
        if depth == 0:
            end = i
            break
    arg = acsl[start + len("\\targets(") : end].strip()
    return arg.startswith("{") and "\\" not in arg, set(_C_IDENT_RE.findall(arg.replace("\\", " ")))


def _harness_induced(acsl: str, harness_words: set[str]) -> str | None:
    r"""
    Why a harness could make this meta-property fail on a correct target, or None. Only a `\precond`
    property can: its `requires` is checked in the protected function itself, whoever calls it, and a
    harness that calls the function directly does not go through the gate its callers in the target
    pass. The other contexts are checked in code the harness does not own: the build instruments the
    target's functions only (`-e-acsl-functions`), so a write, read or call the harness makes is not
    checked, and a postcondition speaks of the function's own work.
    """
    m = _META_CONTEXT_RE.search(acsl)
    if not m or m.group("context") != "precond":
        return None
    listed, names = _meta_targets(acsl)
    if not listed:
        return "its targets are not a list of functions: a direct call from the harness cannot be ruled out"
    called = sorted(names & harness_words)
    if called:
        return f"the harness names its target{'s' if len(called) > 1 else ''} {', '.join(called)}"
    return None


def resolve_security_meta(spec: str | None, sources: list[str], out_bin: Path) -> dict | None:
    r"""
    The MetAcsl properties (scripts/security_props.py) the E-ACSL build of `sources` checks at run
    time, or None when it loads none. `spec` is a path, `none`/`off`, or None for
    $FRAMAC_SECURITY_PROPS, else workspace/reports/security_props.json when it exists (as
    run_wp_function.resolve_security_meta). The file acts only when its `meta_engines` holds `eacsl`.

    Returns {status, props, left_out, ...}:
      error    the file is unreadable, or `spec` names a file that does not exist (`reason`);
      skipped  no property applies to this module (`reason`);
      loaded   `properties` (names) are for compile_eacsl_binary, which writes the meta file
               `<out_bin>.security_meta.c` and its sidecar (failure_identity.meta_sidecar_path).
    The properties are the ones with an instance in a function of the non-harness sources (ids
    `file#name` whose file ends a source's path). MetAcsl instantiates each of them in every function
    of the parse. `left_out` lists the `\precond` properties a harness could make fail on a correct
    target (`_harness_induced`), with the reason: they are not compiled as `check` either, because a
    printed check would be parsed before the real failure of the same input, and a campaign never
    sees one. The properties' own `sources` are not added to the build: it compiles the module as it is.
    A property whose `engines` leave E-ACSL out (security_props.for_engine) is not considered; the
    names are listed under `not_for_engine` (absent when there are none).
    """
    import security_props

    if spec is not None and spec.strip().lower() in ("none", "off", ""):
        return None
    path = Path(spec) if spec else Path(os.environ.get(SECURITY_PROPS_ENV) or security_props.DEFAULT_OUT)
    if not path.is_file():
        return {"status": "error", "props": str(path), "reason": "security properties file not found"} if spec else None
    try:
        props = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {"status": "error", "props": str(path), "reason": f"unreadable: {exc}"}
    if not isinstance(props, dict) or "eacsl" not in security_props.meta_engines(props):
        return None

    every = [p for p in props.get("properties") or [] if isinstance(p, dict) and p.get("name")]
    # A property whose `engines` leave E-ACSL out never reaches the build (security_props.for_engine).
    listed = security_props.for_engine({**props, "properties": every}, "eacsl")["properties"]
    not_for_engine = sorted({str(p["name"]) for p in every} - {str(p["name"]) for p in listed})
    all_ids = set(props.get("obligations") or {}) | {str(i) for p in listed for i in p.get("instances") or []}
    ids: set[str] = set()
    functions: dict[str, set[str]] = {}
    harness_words: set[str] = set()
    harness_functions: set[str] = set()
    for src in sources:
        p = Path(src)
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        try:
            defined = {str(fn.get("name") or "") for fn in extract_functions_from_code(text, path=str(p))}
        except Exception:  # noqa: BLE001 - a source the scanner cannot read names no function here
            defined = set()
        defined -= {""} | set(TYPE_MODIFIERS_AND_PRIMITIVES)
        if p.name.startswith("harness_") or "LLVMFuzzerTestOneInput" in text:
            harness_words |= set(_C_IDENT_RE.findall(_C_COMMENT_RE.sub(" ", text)))
            harness_functions |= defined
            continue
        posix = str(src).replace("\\", "/")
        mine = {
            fid for fid in all_ids if posix == fid.rpartition("#")[0] or posix.endswith("/" + fid.rpartition("#")[0])
        }
        ids |= mine
        # The file as the run's ids name it (the ledger's), else the path without its overlay prefix.
        rel = max((fid.rpartition("#")[0] for fid in mine), key=len, default=normalize_file(posix))
        for name in defined:
            functions.setdefault(name, set()).add(rel)

    left_out: list[dict] = []
    kept: list[dict] = []
    for prop in listed:
        reason = _harness_induced(str(prop.get("acsl") or ""), harness_words)
        if reason and ids & set(prop.get("instances") or []) and not prop.get("code"):
            left_out.append({"property": str(prop["name"]), "reason": reason})
        else:
            kept.append(prop)
    base = {
        "props": str(path),
        "left_out": left_out,
        **({"not_for_engine": not_for_engine} if not_for_engine else {}),
    }
    found = security_props.module_meta_file_text({**props, "properties": kept}, ids)
    if found is None:
        return {"status": "skipped", **base, "reason": "no property has an instance in a function of these sources"}
    names = found[1]
    return {
        "status": "loaded",
        **base,
        "properties": names,
        "selected": [p for p in kept if str(p["name"]) in names],
        "preamble": str(props.get("preamble") or ""),
        "functions": {name: sorted(files) for name, files in sorted(functions.items())},
        "harness_functions": sorted(harness_functions),
    }


def eacsl_security_meta_text(
    plan: dict, without: set[str] | frozenset[str] = frozenset(), libc: bool = True
) -> tuple[str, list[str], list[str], dict[str, str]] | None:
    """
    (meta file text, property names, libc writers whose assigns it carries, line -> property name)
    for the E-ACSL build of a loaded plan without the properties named in `without`; None when no
    property is left. The text is security_props.module_meta_file_text's with:
      - the libc include line emptied (eacsl_toolchain.eacsl_meta_file_text);
      - each \\writing and \\reading predicate guarded by the validity of the accessed memory
        (eacsl_toolchain.eacsl_meta_guarded_text), on its own lines;
      - with `libc`, the assigns of the libc writers appended after the last property
        (eacsl_toolchain.eacsl_meta_libc_text), so a call to memcpy gets its \\writing instances.
    Every property keeps its line; the line map is computed before the appended text.
    """
    import security_props

    remaining = [p for p in plan.get("selected") or [] if str(p["name"]) not in without]
    found = security_props.module_meta_file_text(
        {"preamble": plan.get("preamble") or "", "properties": remaining}, None
    )
    if found is None:
        return None
    text = eacsl_meta_guarded_text(eacsl_meta_file_text(found[0], security_props.META_INCLUDE))
    line_names = {str(k): v for k, v in security_props.meta_line_names(text).items()}
    contracts = eacsl_meta_libc_text() if libc else None
    if contracts:
        text = text.rstrip("\n") + "\n" + contracts
    return text, found[1], list(EACSL_META_LIBC_WRITERS) if contracts else [], line_names


def write_security_meta(
    plan: dict, out_bin: Path, without: set[str] | frozenset[str] = frozenset(), libc: bool = True
) -> dict | None:
    """
    Write the meta file of a loaded plan (resolve_security_meta) next to `out_bin`, without the
    properties named in `without`, and its sidecar: {meta_file, properties, line_names,
    libc_contracts}, or None when no property is left. The text is eacsl_security_meta_text's
    (`libc`: with the libc writers' assigns; `libc_contracts` names them).
    """
    built = eacsl_security_meta_text(plan, without, libc)
    if built is None:
        return None
    text, names, libc_contracts, line_names = built
    remaining = [p for p in plan["selected"] if str(p["name"]) not in without]
    meta_file = Path(out_bin).with_suffix(SECURITY_META_SUFFIX)
    meta_file.parent.mkdir(parents=True, exist_ok=True)
    meta_file.write_text(text, encoding="utf-8", newline="\n")
    sidecar = {
        "props": plan["props"],
        "meta_file": meta_file.as_posix(),
        "properties": {
            str(p["name"]): {"obligation_class": p.get("obligation_class"), "instances": list(p.get("instances") or [])}
            for p in remaining
        },
        "functions": plan["functions"],
        "harness_functions": plan["harness_functions"],
        "line_names": line_names,
    }
    meta_sidecar_path(meta_file).write_text(json.dumps(sidecar, indent=2) + "\n", encoding="utf-8", newline="\n")
    return {
        "meta_file": meta_file.as_posix(),
        "properties": names,
        "line_names": line_names,
        "libc_contracts": libc_contracts,
    }


def _build_with_security_meta(plan: dict, out_bin: Path, build) -> tuple[dict | None, dict]:
    """
    Build with the plan's properties: (result, record), the record being the result's `security_props`.
    `build(meta)` is the uncached E-ACSL build with `meta` = write_security_meta's result. A property
    MetAcsl cannot type in this module (eacsl_toolchain.rejected_meta_property) is dropped and stage 1
    run again, SECURITY_META_MAX_REJECTED times at most. (None, record) when the build fails with the
    properties: the caller builds the module without them, so that they never cost it its E-ACSL
    binary, and the record says why (`status` dropped, `log` the failed build's log).
    Record of a build that holds them (`status` loaded): `meta_file`, `properties`, `line_names`,
    `translated` (property -> its checks and the functions holding one), `not_translated` (no run-time
    check: decided statically by MetAcsl, no instance in the instrumented functions, or not translated
    by E-ACSL), `unplanned_instances` (functions holding a check that the property does not list as
    instances; not for a precondition, which is checked in its target), `rejected`, `left_out`,
    `libc_contracts` and `libc_unchecked`.
    The meta file first carries the assigns of the libc writers (eacsl_security_meta_text). A build
    they make fail, for a reason other than a property MetAcsl rejects or the build time limit
    (`eacsl_build_timeout`), is redone once without them:
    `libc_contracts` is then {status: dropped, functions, reason, log} (the failed build's log kept as
    `<out>.security_meta_libc.log`), else {status: loaded, functions}, or {status: missing, reason}
    when the contracts file is not found. `libc_unchecked` maps each libc function that writes or
    reads through a pointer and has no contract in this build (EACSL_META_LIBC_UNCHECKED, plus the
    writers when their contracts are not loaded) to the module's functions that call it: MetAcsl
    checks no \\writing or \\reading property on those calls in this binary.
    """
    record: dict = {"status": "loaded", "props": plan["props"], "left_out": plan["left_out"]}
    if plan.get("not_for_engine"):
        record["not_for_engine"] = plan["not_for_engine"]
    rejected: list[dict] = []
    libc = True
    libc_record: dict | None = None
    while True:
        written = write_security_meta(plan, out_bin, {r["property"] for r in rejected}, libc=libc)
        if rejected:
            record["rejected"] = rejected
        if written is None:
            record.update(status="dropped", reason="MetAcsl rejected every property")
            return None, record
        if libc and not written["libc_contracts"]:
            libc_record = {"status": "missing", "reason": "templates/metacsl/eacsl_libc_writers.h not found"}
        record["libc_contracts"] = libc_record or {"status": "loaded", "functions": written["libc_contracts"]}
        res = build(written)
        applied = res.pop("security_meta", None) or {}
        if not applied.get("applied"):
            # Built, as a plain build: this toolchain or module cannot take the properties.
            record.update(status="skipped", reason=applied.get("reason") or "the build did not take the meta file")
            return res, record
        if res.get("returncode") == 0:
            break
        log = Path(res["compile_log"])
        log_text = log.read_text(encoding="utf-8", errors="replace") if log.is_file() else ""
        hit = rejected_meta_property(log_text)
        if hit and hit[0] in written["properties"] and len(rejected) < SECURITY_META_MAX_REJECTED:
            rejected.append({"property": hit[0], "reason": hit[1]})
            continue
        # A build killed at the time limit was stopped by its size, not by the contracts: redoing it
        # without them would spend the limit again (nginx run-5, S14).
        if written["libc_contracts"] and not hit and res.get("reason") != "eacsl_build_timeout":
            libc_log = Path(out_bin).with_suffix(SECURITY_META_LIBC_LOG_SUFFIX)
            with contextlib.suppress(OSError):
                libc_log.write_text(log_text, encoding="utf-8", newline="\n")
            libc, libc_record = (
                False,
                {
                    "status": "dropped",
                    "functions": written["libc_contracts"],
                    "reason": f"the E-ACSL build failed with them ({res.get('reason') or res.get('returncode')})",
                    "log": libc_log.as_posix(),
                },
            )
            continue
        kept_log = Path(out_bin).with_suffix(SECURITY_META_LOG_SUFFIX)
        with contextlib.suppress(OSError):
            kept_log.write_text(log_text, encoding="utf-8", newline="\n")
        record.update(
            status="dropped",
            reason=f"the E-ACSL build failed with the properties ({res.get('reason') or res.get('returncode')})",
            properties=written["properties"],
            log=kept_log.as_posix(),
        )
        return None, record
    instrumented = Path(res["instrumented_source"])
    text = instrumented.read_text(encoding="utf-8", errors="replace") if instrumented.is_file() else ""
    checks = meta_checks(text, written["properties"])
    by_name = {str(p["name"]): p for p in plan["selected"]}
    unplanned: dict[str, list[str]] = {}
    for name, found in checks.items():
        prop = by_name.get(name) or {}
        context = _META_CONTEXT_RE.search(str(prop.get("acsl") or ""))
        if context and context.group("context") == "precond":
            continue
        planned = {str(i).rpartition("#")[2] for i in prop.get("instances") or []}
        extra = [fn for fn in found["functions"] if fn not in planned]
        if extra:
            unplanned[name] = extra
    record.update(
        meta_file=written["meta_file"],
        properties=written["properties"],
        line_names=written["line_names"],
        translated={name: found for name, found in checks.items() if found["checks"]},
        not_translated=[name for name, found in checks.items() if not found["checks"]],
        unplanned_instances=unplanned,
        libc_unchecked=libc_writer_calls(
            text,
            sorted(set(plan.get("functions") or {}) - set(plan.get("harness_functions") or [])),
            [*EACSL_META_LIBC_UNCHECKED, *(n for n in EACSL_META_LIBC_WRITERS if n not in written["libc_contracts"])],
        ),
    )
    return res, record


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
    libc_checks: bool = True,
    security_meta: dict | None = None,
) -> dict:
    """
    Instrument and compile a slice with E-ACSL (see `_compile_eacsl_binary_uncached`).

    Outside agents/*/scratch, and when caching is enabled (scripts/cache.py), the build is
    cached under its effective flags, output path, cwd and dependency manifest: a hit restores
    the binary, `<out>.instrumented.c`, the variadic fallback object and the compile log (which
    then names the cache entry). The result carries `cache: {"hit": bool, "key": str | None}`.

    The `-I` / `-iquote` directories of the build's own compiles of `sources` that `cppflags` lacks (a file
    another link unit compiles, added by a link repair) are appended (`with_capture_include_dirs`) and listed
    in `source_include_dirs`.

    `security_meta` (resolve_security_meta's result; None: no MetAcsl property, the build of every
    caller but build_module_binary) adds the run's MetAcsl properties to stage 1, so the binary stops
    on an input that violates one (`_build_with_security_meta`). The result then carries
    `security_props`. Such a build is cached under a key of its own (`_security_meta_material`: the
    meta text, the MetAcsl stage flags and what the sidecar is written from), with the meta file
    `<out>.security_meta.c` and its sidecar among the restored files: without the sidecar a restored
    binary would report its violations without their file and class. A build whose toolchain cannot
    take the properties (`status` skipped) is cached the same way. A build the properties make fail
    (`status` dropped) is never published: it is redone without them, through the cache as any plain
    build, and tried again with them the next time.
    """
    out_bin = Path(out_bin)
    # The same build without the properties (the arguments as given: the flags below are completed once).
    plain = functools.partial(
        compile_eacsl_binary,
        sources,
        out_bin,
        machdep=machdep,
        cppflags=cppflags,
        rte_flags=rte_flags,
        fuzzer_flag=fuzzer_flag,
        functions=functions,
        ldflags_extra=ldflags_extra,
        variadic_translation=variadic_translation,
        warn_unsigned_downcast=warn_unsigned_downcast,
        rte_initialized=rte_initialized,
        runner=runner,
        use_cache=use_cache,
        enable_l2=enable_l2,
        concurrency=concurrency,
        libc_checks=libc_checks,
    )
    cppflags, source_dirs = with_capture_include_dirs(cppflags, sources)
    cppflags = target_env.with_include_flags(cppflags)
    ldflags_extra = target_env.with_link_flags(ldflags_extra)
    target_fns = _discover_slice_functions(sources, functions, cppflags=cppflags, runner=runner)

    def _noted(res: dict) -> dict:
        if source_dirs:
            res["source_include_dirs"] = list(source_dirs)
        return res

    def _build(meta: dict | None = None) -> dict:
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
            libc_checks=libc_checks,
            **({"security_meta": meta} if meta else {}),
        )

    plan: dict | None = None
    if security_meta:
        if security_meta.get("status") == "loaded":
            plan = security_meta
        else:
            res = plain()
            res["security_props"] = {
                k: v
                for k, v in security_meta.items()
                if k in ("status", "props", "reason", "left_out", "not_for_engine")
            }
            return res

    # The record of a build the properties made fail: it is not a result to publish.
    dropped: dict = {}

    def _meta_build() -> dict:
        assert plan is not None
        built, record = _build_with_security_meta(plan, out_bin, _build)
        if built is None:
            dropped.update(record)
            return {"returncode": 1, "reason": "security_meta_dropped"}
        built["security_props"] = record
        return built

    def _with_properties(res: dict) -> dict:
        assert plan is not None
        if dropped:
            res = plain()
            if res.get("returncode") != 0:
                dropped["reason"] = f"{dropped.get('reason')}; the build without them fails too"
            res["security_props"] = dict(dropped)
        elif isinstance(res.get("security_props"), dict):
            # The entry may come from a build that named the same properties file another way.
            res["security_props"]["props"] = plan["props"]
        return res

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
            libc_checks=libc_checks,
            security_meta=plan,
        )
    if material is None:
        res = _meta_build() if plan else _build()
        res["cache"] = {"hit": False, "key": None}
        return _noted(_with_properties(res) if plan else res)

    instrumented_c = out_bin.with_suffix(".instrumented.c")
    compile_log = out_bin.with_suffix(".compile.log")
    fallback_dir = out_bin.parent / f"{out_bin.name}_fallbacks"
    errno_shim_dir = out_bin.parent / f"{out_bin.name}_errno_shim"
    env_keep_dir = out_bin.parent / f"{out_bin.name}_env_keep"

    def _outputs(res: dict) -> dict[str, Path]:
        files = {"binary": Path(res["binary"]), "instrumented.c": instrumented_c, "compile.log": compile_log}
        if res.get("variadic_fallbacks"):
            files["fallbacks.o"] = fallback_dir / "eacsl_fallbacks.o"
            files["fallbacks.c"] = fallback_dir / "eacsl_fallbacks.c"
        if (res.get("errno_shim") or {}).get("status") == "built":
            files["errno_shim.o"] = errno_shim_dir / "eacsl_errno_shim.o"
            files["errno_shim.c"] = errno_shim_dir / "eacsl_errno_shim.c"
        if (res.get("environ_keep") or {}).get("status") == "built":
            files["env_keep.o"] = env_keep_dir / "eacsl_env_keep.o"
            files["env_keep.c"] = env_keep_dir / "eacsl_env_keep.c"
        if res.get("security_props"):
            # The meta file is no input of the key (its text is): the rejection loop rewrites it.
            meta_file = out_bin.with_suffix(SECURITY_META_SUFFIX)
            files["security_meta.c"] = meta_file
            files["security_meta.json"] = meta_sidecar_path(meta_file)
        return files

    if enable_l2 is None:
        enable_l2 = bool(target_fns)
    l2_functions = target_fns if target_fns else None
    cached = cache.memoize(
        "eacsl-build",
        material,
        sources=sources,
        dep_flags=shlex.split(material["frontend"]),
        build=_meta_build if plan else _build,
        outputs=_outputs,
        ok=lambda res: res.get("returncode") == 0,
        runner=runner,
        on_restore=_note_cache_restore,
        enable_l2=enable_l2,
        l2_target_functions=l2_functions,
    )
    return _noted(_with_properties(cached) if plan else cached)


def _incomplete_alignof_note(info: dict) -> str:
    """The compile-log paragraph for the checks rewrite_incomplete_alignof made vacuous, one line per check."""
    checks = info["checks"]
    lines = [
        f"Made the pointer-alignment checks of {len(checks)} distinct source assertion(s) vacuous "
        f"({info['rewrites']} `_Alignof` rewritten to "
        f"1): the instrumented translation unit leaves {', '.join(info['types'])} incomplete, so clang rejects "
        f"their `_Alignof` (Frama-C -rte / E-ACSL, pub/frama-c#2805). Assumed, not checked: "
        f"{INCOMPLETE_ALIGNOF_ASSUMPTION}. Listed in the build result's `incomplete_alignof`."
    ]
    for c in checks:
        where = (
            f"{c['file']}:{c['line']} in {c['function']}"
            if c.get("function")
            else f"instrumented line {c.get('instrumented_line')}"
        )
        lines.append(f"  - {where}: {c.get('predicate') or 'alignof(' + str(c['type']) + ')'} ({c['tag']})")
    return "\n".join(lines) + "\n"


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
    libc_checks: bool = True,
    security_meta: dict | None = None,
) -> dict:
    """
    Instrument and compile a slice with E-ACSL.

    Modern CLI (Frama-C 33+) runs in two explicit stages so preprocessor flags never reach the
    compile of the self-contained instrumented file:
      1. instrument: `e-acsl-gcc -n --no-constfold <checks> -G clang -F <frama-c flags> -E <frontend> -o <out>.instrumented.c <sources>`
      2. compile:    `e-acsl-gcc -C <checks> -G clang -e <backend> -l <ldflags> -O <out> [fuzz_init.c] <out>.instrumented.c`
    `<checks>` is EACSL_GCC_CHECK_OPTIONS (libc and format-string checks, `check_options` in the
    result) unless `libc_checks` is False, which is recorded in `reduced_checks`.
    `-n` matters: without it `e-acsl-gcc` also links the original sources, which fails on a
    main-less fuzz harness. Fuzz builds use full memory tracking and link
    templates/eacsl_runtime/fuzz_init.c, whose LLVMFuzzerInitialize initializes the runtime that
    an instrumented main() would. With full tracking the frontend also gets EACSL_FULL_MTRACKING_DEFINES
    (`-Dregister=`, recorded in `full_mtracking_defines`). Between the stages the instrumented file
    is patched for printer and E-ACSL gaps, each counted in the result (`alignas_rewrites`,
    `wrapper_result_inits`, `formal_inits`, `forward_array_sizes`, `misplaced_fallthrough`, ...). A pointer-alignment check on a type the instrumented file
    leaves incomplete (an opaque handle) cannot compile; it is made vacuous and listed, with the assumption it
    leaves, in `incomplete_alignof` (eacsl_toolchain.rewrite_incomplete_alignof). Uninitialized reads are
    checked (`-rte-initialized @all`) unless `rte_initialized` is False, which is recorded in
    `reduced_checks`. Stage 1 is retried once without functions Frama-C reports as unknown; stage 2 is
    retried once with a generated
    link-only object when Variadic `<fn>_fallback_<N>` symbols are undefined.
    When the slice reads errno (the fc_stubs/errno.h global) and calls libc functions that set it,
    stage 2 also links the generated errno shim (`errno_shim`: wrapped functions, or `failed`).
    On success the result's `binary` is the E-ACSL-instrumented executable (`<out>.e-acsl` when
    present) and is guaranteed to contain E-ACSL instrumentation.

    E-ACSL does not fail on an annotation it cannot translate: it warns (`... Ignoring annotation.`)
    and generates no check. The result lists them in `ignored_annotations`, each with the function it
    belongs to when that can be read from the sources (eacsl_toolchain.attribute_ignored_annotations),
    and counts the ignored `assigns` clauses, which E-ACSL never checks, in `ignored_frame_clauses`.

    With `security_meta` ({meta_file, ...}, write_security_meta's result) stage 1 also parses the meta
    file and runs MetAcsl in a stage of its own before RTE and E-ACSL (eacsl_toolchain.EACSL_META_FLAGS):
      `e-acsl-gcc -n --no-constfold <checks> --then-last --e-acsl-extra <rte flags> -G clang
       -F <other frama-c flags> -meta -meta-warn-key unknown-func=inactive -E <frontend> -o ... <sources> <meta file>`
    The result's `security_meta` says whether it did (`applied`), and why not (`reason`): the build is
    then the plain one. The meta file is no source of the module: only stage 1 reads it.
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
        "errno_shim": None,
        "rte_select_dropped": [],
        "reduced_checks": ([] if rte_initialized else ["-no-rte-initialized"])
        + ([] if libc_checks else [EACSL_NO_LIBC_CHECKS]),
    }

    def _record(cmd: list[str], rc: int, out: str, err: str) -> None:
        commands.append(" ".join(cmd))
        log_parts.append(f"Command: {' '.join(cmd)}\nReturncode: {rc}\n--- STDOUT ---\n{out}\n--- STDERR ---\n{err}\n")
        result["stdout"] = out[-16000:]
        result["stderr"] = err[-16000:]

    # The last instrumentation run's output, and whether it left `<out>.instrumented.c` (a failed
    # run can leave an older build's file there).
    frontend: dict = {"output": "", "instrumented": False}

    def _finish(rc: int, reason: str | None = None) -> dict:
        result["returncode"] = rc
        result["command"] = " && ".join(commands)
        result["undeclared_functions"] = scan_undeclared_functions("\n".join(log_parts))
        # E-ACSL warns and goes on when it cannot translate an annotation: the binary then checks
        # nothing for it. Attributed now, while the sources are the ones E-ACSL read, and kept with the
        # result so that a build restored from the cache says the same.
        ignored, frame_clauses = parse_ignored_annotations(frontend["output"])
        result["ignored_annotations"] = attribute_ignored_annotations(
            ignored, instrumented_c if frontend["instrumented"] else None
        )
        result["ignored_frame_clauses"] = frame_clauses
        if reason and rc == BUILD_TIMEOUT_RC and BUILD_TIME_LIMIT_TEXT in str(result["stderr"]):
            # Killed at the build time limit (nginx run-5: a whole-program unit), not stopped by an error:
            # its own reason, so the fallback and build-check do not read it as a Frama-C or clang failure.
            reason = "eacsl_build_timeout"
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
    # The E-ACSL-only `static const union` rewrite (scripts/fc_cpp_wrapper_eacsl.py, O9): on or off for this
    # build, and how many declarations the frontend run rewrote (counted after it below).
    result["const_union_rewrite"] = fc_cpp_wrapper_eacsl.const_union_rewrite_active(flags["frontend"])

    def _note_const_unions(out: str, err: str) -> None:
        n = fc_cpp_wrapper_eacsl.count_const_union_rewrites(out + "\n" + err)
        result.pop("const_union_rewrites", None)
        if n:
            result["const_union_rewrites"] = n
            log_parts.append(
                f"Dropped `const` from {n} `static const union` declaration(s) in the E-ACSL frontend's text only "
                "(E-ACSL bug pub/frama-c#2795: it cannot mark a const union read-only); E-ACSL does not check "
                "them as read-only and this binary holds them as writable data. The sanitizer and coverage "
                "builds, Eva and WP read the original.\n"
            )

    check_options = _check_options(is_modern, libc_checks)
    if is_modern:
        result["check_options"] = check_options
    if full_mtracking:
        result["full_mtracking_defines"] = list(EACSL_FULL_MTRACKING_DEFINES)
        log_parts.append(
            f"Frontend defines {' '.join(EACSL_FULL_MTRACKING_DEFINES)}: full memory tracking takes the address "
            "of every local, which the kernel refuses for a `register` local.\n"
        )
    if target_fns is None:
        target_fns = _discover_slice_functions(sources, functions, cppflags=cppflags, runner=runner)

    meta_file: str | None = None
    if security_meta:
        if not is_modern:
            why_not = "e-acsl-gcc.sh (Frama-C <= 32) has no option to run MetAcsl in a stage of its own"
        elif "fc_compat_types.h" not in flags["frontend"]:
            why_not = (
                "the frontend does not force-include fc_stubs/fc_compat_types.h, which gives the meta file "
                "its vocabulary in an E-ACSL build"
            )
        elif not target_fns:
            why_not = "no target function is listed: without -e-acsl-functions the harness's own code is checked too"
        else:
            why_not = None
            meta_file = str(security_meta["meta_file"])
        result["security_meta"] = {"meta_file": str(security_meta["meta_file"]), "applied": why_not is None}
        if why_not:
            result["security_meta"]["reason"] = why_not
            log_parts.append(f"MetAcsl properties not loaded: {why_not}.\n")

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
        _note_const_unions(out, err)
        frontend.update(output=out + "\n" + err, instrumented=rc == 0 and instrumented_c.is_file())
        if rc != 0:
            kill_kind = _detect_stage_kill(rc, out, err)
            if kill_kind is not None:
                result[kill_kind] = True
                return _finish(rc, "eacsl_stage_killed")
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
            # MetAcsl properties (security_meta): their stage first, the RTE flags behind it. Never
            # without a function list, which is what keeps the harness's own code unchecked.
            stage_options: list[str] = []
            meta_sources: list[str] = []
            if meta_file and fns:
                fc_flags, stage_options = meta_stage_flags(fc_flags)
                meta_sources = [meta_file]
            # Pass --no-constfold so Frama-C's CIL constant folder does not zero-fold
            # hoisted block-scope `static const` arrays indexed by variables.
            cmd1 = [
                eacsl_bin,
                "-n",
                "--no-constfold",
                *check_options,
                *stage_options,
                "-G",
                "clang",
                "-F",
                " ".join(fc_flags),
                "-E",
                flags["frontend"],
                "-o",
                str(instrumented_c),
                *sources,
                *meta_sources,
            ]
            return (cmd1, *_run_tool(cmd1, runner))

        remaining = list(target_fns)
        dropped: list[str] = []
        cmd1, rc, out, err = _stage1(remaining)
        _record(cmd1, rc, out, err)
        for _ in range(8):
            if rc == 0 or not remaining:
                break
            missing = [f for f in parse_missing_functions(out + "\n" + err) if f in remaining]
            if not missing:
                break
            dropped.extend(missing)
            remaining = [f for f in remaining if f not in missing]
            if meta_file and not remaining:
                result["security_meta"].update(
                    applied=False, reason="Frama-C knows none of the listed target functions"
                )
            cmd1, rc, out, err = _stage1(remaining)
            _record(cmd1, rc, out, err)
        if dropped:
            result["rte_select_dropped"] = dropped
        _note_const_unions(out, err)  # the last frontend run only: a retry preprocesses the same files again
        frontend.update(output=out + "\n" + err, instrumented=rc == 0 and instrumented_c.is_file())
        if rc != 0:
            kill_kind = _detect_stage_kill(rc, out, err)
            if kill_kind is not None:
                result[kill_kind] = True
                return _finish(rc, "eacsl_stage_killed")
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

            # Without this, Frama-C's typed `__sync_*_uint64_t` overload names fail at Stage 2 link.
            c_text, n_sync = rewrite_sync_builtins(c_text)
            if n_sync:
                c_modified = True
                result["sync_builtin_rewrites"] = n_sync
                log_parts.append(
                    f"Rewrote {n_sync} typed __sync_*_<intN>_t builtin call(s) back to polymorphic __sync_* "
                    "(Frama-C's gcc_builtins.json overloads are not linker symbols).\n"
                )

            # Without this, clang rejects a struct the kernel names in a parameter list before its definition:
            # the forward declaration the sources had is gone. Before the rewrites that record lines.
            c_text, forward_tags = rewrite_forward_tag_declarations(c_text)
            if forward_tags["count"]:
                c_modified = True
                result["forward_tag_declarations"] = forward_tags
                log_parts.append(
                    f"Declared {forward_tags['count']} struct/union tag(s) at the start of the file "
                    f"({', '.join(forward_tags['tags'][:20])}{', ...' if forward_tags['count'] > 20 else ''}): "
                    "the Frama-C printer drops the forward declaration the sources have and first names the "
                    "tag in a parameter list or a function body, where it declares a type of its own. "
                    "The declaration only joins those mentions to the definition.\n"
                )

            # Without this, clang rejects an array the kernel declares before the object its size reads.
            c_text, forward_arrays = rewrite_forward_array_sizes(c_text)
            if forward_arrays:
                c_modified = True
                result["forward_array_sizes"] = forward_arrays
                names = ", ".join(f"{a['name']} (sized from {', '.join(a['operands'])})" for a in forward_arrays)
                log_parts.append(
                    f"Rewrote {len(forward_arrays)} global array(s) the Frama-C kernel declares before the object "
                    f"their size reads: {names}. The earlier declarations became `extern T x[];` and the sized "
                    "declaration follows that object's definition; the size and the checks are kept.\n"
                )

            # Without this, clang rejects `_Alignof(T)` of an opaque handle T (pub/frama-c#2805): never silent.
            c_text, incomplete = rewrite_incomplete_alignof(c_text)
            if incomplete["rewrites"]:
                c_modified = True
                result["incomplete_alignof"] = {**incomplete, "assumption": INCOMPLETE_ALIGNOF_ASSUMPTION}
                log_parts.append(_incomplete_alignof_note(incomplete))

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
                # Without this, every va_arg fails \initialized(&ap): va_start is not instrumented.
                c_text, n_va = skip_va_list_initialized_checks(c_text)
                if n_va:
                    c_modified = True
                    result["va_list_init_checks_skipped"] = n_va
                    log_parts.append(
                        f"Skipped {n_va} \\initialized check(s) on va_list objects "
                        "(va_start/va_copy are compiler builtins E-ACSL does not instrument).\n"
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

            # Without this, a literal the linker tail-merged into a longer one (`","` in `" ,"`) splits
            # the longer literal's block, and every read past its first byte fails \valid_read.
            c_text, n_literals = order_literal_registrations(c_text)
            if n_literals:
                c_modified = True
                result["literal_registrations_reordered"] = n_literals
                log_parts.append(
                    f"Reordered {n_literals} string literal registration(s) shortest first "
                    "(the linker stores a literal that is a suffix of another inside it; the enclosing "
                    "block must be registered last).\n"
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

            # Without this, clang rejects a fallthrough attribute the kernel printed before `label: default:`.
            # Last, so the lines it records are those of the file stage 2 compiles.
            c_text, fallthrough = rewrite_misplaced_fallthrough(c_text)
            if fallthrough["rewrites"]:
                c_modified = True
                result["misplaced_fallthrough"] = fallthrough
                log_parts.append(
                    f"Removed {fallthrough['rewrites']} __attribute__((__fallthrough__)) not directly followed by "
                    f"a case or default label (instrumented lines {', '.join(map(str, fallthrough['lines'][:20]))}"
                    f"{', ...' if len(fallthrough['lines']) > 20 else ''}): the Frama-C printer puts a goto label "
                    "before `default:`, which clang rejects. Its `;` stays; the attribute only silences "
                    "-Wimplicit-fallthrough, so control flow and checks are unchanged.\n"
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
            env_keep = _build_environ_keep_object(
                instrumented_text,
                out_bin.parent / f"{out_bin.name}_env_keep",
                runner=runner,
                timeout=BUILD_TIMEOUT_S,
            )
            if env_keep["status"] == "built":
                try:
                    ldflags = normalize_passthrough(
                        f"{ldflags} {shlex.quote(Path(env_keep['object']).as_posix())} {env_keep['wrap_flags']}"
                    )
                except UnsafePassthroughError as exc:
                    log_parts.append(f"Refusing to link environ keep shim: {exc}\n")
                    return _finish(2, "eacsl_argv_unsafe")
                result["environ_keep"] = {"status": "built", "object": env_keep["object"]}
            elif env_keep["status"] == "error":
                result["environ_keep"] = {"status": "failed", "reason": env_keep.get("reason")}
                log_parts.append(f"environ keep shim not linked: {env_keep.get('reason')}\n")

        # fc_stubs/errno.h maps errno to a tracked global (libc's TLS errno is outside E-ACSL's
        # shadow segments); the shim copies libc's errno into it after each shimmed call. The same
        # wrappers tell the runtime what libc wrote or returned (eacsl_toolchain.EACSL_LIBC_EFFECTS).
        shim = build_errno_shim_object(
            instrumented_c, out_bin.parent / f"{out_bin.name}_errno_shim", runner=runner, timeout=BUILD_TIMEOUT_S
        )
        if shim["status"] == "built":
            try:
                ldflags = normalize_passthrough(
                    f"{ldflags} {shlex.quote(Path(shim['object']).as_posix())} {shim['wrap_flags']}"
                )
            except UnsafePassthroughError as exc:
                log_parts.append(f"Refusing to link errno shim: {exc}\n")
                return _finish(2, "eacsl_argv_unsafe")
            result["errno_shim"] = {
                "status": "built",
                "wrapped": shim["wrapped"],
                "eacsl_effects": shim["eacsl_effects"],
                "object": shim["object"],
            }
            if shim.get("effects_error"):
                result["errno_shim"]["effects_error"] = shim["effects_error"]
                log_parts.append(f"E-ACSL libc effects not linked: {shim['effects_error']}\n")
        elif shim["status"] == "error":
            # Not fatal: the target still builds, but reads stale errno after these calls and
            # E-ACSL may stop on memory libc wrote.
            result["errno_shim"] = {
                "status": "failed",
                "wrapped": [],
                "unsynced": shim["wrapped"],
                "eacsl_effects_missing": shim.get("eacsl_effects", []),
            }
            log_parts.append(f"errno shim not linked: {shim.get('reason')}\n")

        # The runtime is compiled at stage 2 only, from a patched copy of the share directory when
        # format strings are validated (eacsl_toolchain.EACSL_FORMAT_RUNTIME_PATCH).
        share_args: list[str] = []
        if _runtime_patches(check_options):
            patch = _format_runtime_share(eacsl_bin, out_bin.parent / "eacsl_share")
            result["runtime_patches"] = {"format_runtime": patch}
            if patch["status"] == "applied":
                share_args = ["--e-acsl-share", patch["share"]]
                log_parts.append(
                    f"Runtime patch format_runtime ({patch['patch']}): the runtime is compiled from {patch['share']}; "
                    "a signed/unsigned argument of one rank passes a format directive when its value fits both types, "
                    "and pointer arguments after a floating-point one are read from their own slots.\n"
                )
            else:
                log_parts.append(
                    f"Runtime patch format_runtime not applied ({patch['reason']}): the runtime aborts on every "
                    "promoted unsigned char/short argument of %u/%x/%o and on a %s/%p/%n after a %f/%e/%g.\n"
                )

        # The runtime's tracked heap (eacsl_toolchain.EACSL_HEAP_ZONE_MB): fixed, it decides which
        # input-sized allocations abort the runtime.
        zone_args = _zone_size_options(is_modern)
        result["eacsl_zone_sizes"] = {"heap_mb": int(zone_args[1].split(":", 1)[1])}

        def _stage2(link: str) -> tuple[list[str], int, str, str]:
            cmd2 = [
                eacsl_bin,
                "-C",
                *check_options,
                *zone_args,
                *share_args,
                "-G",
                "clang",
                "-e",
                flags["backend"],
                "-O",
                str(out_bin),
            ]
            if link:
                cmd2.extend(["-l", link])
            cmd2.extend(init_hook)
            cmd2.append(str(instrumented_c))
            return (cmd2, *_run_tool(cmd2, runner))

        link_used = ldflags
        cmd2, rc, out, err = _stage2(link_used)
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
            link_used = link_with_fallbacks
            cmd2, rc, out, err = _stage2(link_used)
            _record(cmd2, rc, out, err)
        if rc != 0 and share_args and _PATCHED_STDIO_ERROR_RE.search(out + "\n" + err):
            # The patched runtime itself does not compile (a Frama-C whose e_acsl_stdio.c still has the
            # anchors but changed around them): build with the image's runtime and say so.
            share_args.clear()
            result["runtime_patches"]["format_runtime"] = {
                "patch": EACSL_FORMAT_RUNTIME_PATCH,
                "status": "not_applied",
                "reason": "the patched e_acsl_stdio.c did not compile",
            }
            log_parts.append("Runtime patch format_runtime dropped: the patched e_acsl_stdio.c did not compile.\n")
            cmd2, rc, out, err = _stage2(link_used)
            _record(cmd2, rc, out, err)
        if rc != 0:
            kill_kind = _detect_stage_kill(rc, out, err)
            if kill_kind is not None:
                result[kill_kind] = True
                return _finish(rc, "eacsl_stage_killed")
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
    """
    Compile a slice directly with Clang, cached (binary and compile log) outside agents/*/scratch.
    Headers among `sources` are left out (`framac_common.compile_inputs`): clang cannot take one.
    The include directories of the build's own compiles of `sources` that `cppflags` lacks are appended
    and listed in `source_include_dirs` (`with_capture_include_dirs`), as for the E-ACSL build.
    """
    sources = compile_inputs(sources)
    out_bin = Path(out_bin)
    compile_log = out_bin.with_suffix(log_suffix)
    cppflags, source_dirs = with_capture_include_dirs(cppflags, sources)
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
    else:
        material = {
            "kind": engine,
            "command": cmd,
            "sources": [str(s) for s in sources],
            "out_bin": out_bin.as_posix(),
        }
        res = cache.memoize(
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
    if source_dirs:
        res["source_include_dirs"] = list(source_dirs)
    return res


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


def framac_version(runner=subprocess.run) -> str:
    rc, out, err = _run_tool(["frama-c", "-version"], runner)
    return (out or err).strip().splitlines()[0] if rc == 0 and (out or err).strip() else "unknown"


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


_UNDEFINED_REF_RE = re.compile(
    r"(?:undefined reference to [`'\"]|undefined symbol:\s*[`'\"]?)(?P<sym>[A-Za-z_]\w*)",
    re.IGNORECASE,
)


def parse_undefined_references(log: str) -> list[str]:
    """Symbols named in linker `undefined reference to 'X'` diagnostics, in order."""
    found: list[str] = []
    for m in _UNDEFINED_REF_RE.finditer(log or ""):
        sym = m.group("sym")
        if sym not in found:
            found.append(sym)
    return found


_HEADER_SUFFIXES = frozenset({".h", ".hh", ".hpp", ".hxx", ".inc"})


def _dag_symbol_tables(dag_path: Path) -> tuple[dict[str, tuple[str, str]], dict[str, str]]:
    """
    Return `(parsed_functions, build_only_functions)` from `callgraph_dag.json`:
    - `parsed_functions`: non-static function name -> `(defining_file, module)` (static functions
      are skipped so they can never shadow an `extern` function or `extern` global, B8). A record
      in a source file wins over one in a header (`header: true`, or a header suffix): the GCC call
      graph also records a function at its header prototype (`include/sudo_debug.h#
      sudo_debug_printf2_v1`, no body), and that header, linked as a source, defines nothing and
      is parsed without the config.h its includer brings (sudo: `sudo_dso_public` at
      sudo_fatal.h:170).
    - `build_only_functions`: build-only function name -> `defining_file` (code hidden from
      Frama-C by compiler macros, e.g. `#ifdef __SSE2__`; never stubbed in `link_stubs.c`).
    """
    try:
        dag = json.loads(Path(dag_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}, {}
    dag = dag if isinstance(dag, dict) else {}
    parsed: dict[str, tuple[str, str]] = {}
    in_header: set[str] = set()
    for key, rec in (dag.get("functions") or {}).items():
        if not isinstance(rec, dict) or rec.get("is_static") is True:
            continue
        name = rec.get("name") or str(key).split("#")[-1]
        file = rec.get("file")
        if not (name and file):
            continue
        header = bool(rec.get("header")) or posixpath.splitext(str(file))[1].lower() in _HEADER_SUFFIXES
        name = str(name)
        if name not in parsed or (name in in_header and not header):
            parsed[name] = (str(file), str(rec.get("module") or ""))
            if header:
                in_header.add(name)
            else:
                in_header.discard(name)
    build_only_out: dict[str, str] = {}
    build_only = dag.get("build_only_functions")
    for file, names in (build_only if isinstance(build_only, dict) else {}).items():
        for name in names if isinstance(names, list) else []:
            if isinstance(name, str) and name and name not in parsed:
                build_only_out.setdefault(name, str(file))
    return parsed, build_only_out


def _dag_function_definers(dag_path: Path) -> dict[str, list[dict]]:
    """
    Non-static function name -> every source file defining it in `callgraph_dag.json`, one record each
    ({file, module, units}, in DAG order; header records left out). A name several programs define for
    themselves (sudo's `open_sudoers`: cvtsudoers.c, sudoers.c, testsudoers.c, visudo.c) has several.
    """
    dag = load_json_optional(Path(dag_path), None)
    out: dict[str, list[dict]] = {}
    for key, rec in ((dag.get("functions") or {}) if isinstance(dag, dict) else {}).items():
        if not isinstance(rec, dict) or rec.get("is_static") is True:
            continue
        name = str(rec.get("name") or str(key).split("#")[-1])
        file = str(rec.get("file") or "")
        if not (name and file) or rec.get("header") or posixpath.splitext(file)[1].lower() in _HEADER_SUFFIXES:
            continue
        recs = out.setdefault(name, [])
        if all(r["file"] != file for r in recs):
            units = rec.get("units")
            recs.append(
                {
                    "file": file,
                    "module": str(rec.get("module") or ""),
                    "units": [str(u) for u in units] if isinstance(units, list) else [],
                }
            )
    return out


def _dag_symbol_files(dag_path: Path) -> dict[str, str]:
    """
    Map non-static function name -> defining source file from callgraph_dag.json: its parsed
    functions (excluding `is_static`), then the functions only the build compiles
    (`build_only_functions`: code Frama-C's preprocessing hides, which the sanitizer build links).
    """
    parsed, build_only = _dag_symbol_tables(dag_path)
    out = {name: file for name, (file, _mod) in parsed.items()}
    for name, file in build_only.items():
        out.setdefault(name, file)
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


LINK_GLOBALS_FILE = "link_globals.c"


LINK_GLOBALS_ASSUMPTION = "starts zero-initialized, as in a fresh process"


_GLOBAL_TYPE_CHARS_RE = re.compile(r"^[\w\s*\[\](),.]+$")


_GLOBAL_TAG_RE = re.compile(r"\b(struct|union)\s+([A-Za-z_]\w*)")


# The declarator slot of a pointer to function or to array, as Frama-C prints it: `(*)`, `(*[4])`.
_GLOBAL_POINTER_SLOT_RE = re.compile(r"\(\s*(\*+)\s*((?:\[\d+\])*)\s*\)")


_GLOBAL_ARRAY_RE = re.compile(r"^(?P<base>[^\[\]]*?)\s*(?P<dims>(?:\[\d+\]\s*)*)$")


def _model_global_variables(dag_path: Path) -> dict[str, list[dict]]:
    """
    Name -> records of the global variables the project defines with external linkage, from the
    Phase 0 model next to the DAG (workspace/reports/phase0_model.json, `global_variables`: name,
    file, type, size, units), falling back to the DAG's `global_variables` when the model is
    absent or omits a record. Empty without either, and for GCC-fallback units.
    """
    model = load_json_optional(Path(dag_path).parent / "phase0_model.json", None)
    records = model.get("global_variables") if isinstance(model, dict) else None
    dag = load_json_optional(Path(dag_path), None)
    dag_records = dag.get("global_variables") if isinstance(dag, dict) else None
    out: dict[str, list[dict]] = {}
    seen_keys: set[str] = set()
    for src_records in (records, dag_records):
        for key, rec in sorted(src_records.items()) if isinstance(src_records, dict) else []:
            if str(key) in seen_keys or not isinstance(rec, dict) or rec.get("static"):
                continue
            seen_keys.add(str(key))
            name = str(rec.get("name") or str(key).split("#")[-1])
            file = rec.get("file") or (str(key).rpartition("#")[0] if "#" in str(key) else "")
            if name and file:
                units = [str(u) for u in rec.get("units") or []] if isinstance(rec.get("units"), list) else []
                size = rec.get("size") if isinstance(rec.get("size"), int) and rec["size"] > 0 else None
                entry: dict[str, Any] = {
                    "name": name,
                    "file": str(file),
                    "type": str(rec.get("type") or ""),
                    "units": units,
                }
                if size is not None:
                    entry["size"] = size
                out.setdefault(name, []).append(entry)
    return out


def global_definition_text(name: str, type_text: str) -> tuple[str | None, str]:
    """
    The C definition of global `name` from the type text the model records (Frama-C's printing,
    typedefs unrolled, qualifiers dropped: `int`, `unsigned char [16]`, `struct conn *`,
    `void (*)(int )`), as (definition, "") or (None, reason). No initializer: an object of static
    storage starts zero-initialized. A type that needs a definition the generated file does not
    have (a struct or union held by value, an enum) is not usable.
    """
    text = " ".join(str(type_text or "").split())
    if not text:
        return None, "the model records no type for it"
    if not _GLOBAL_TYPE_CHARS_RE.match(text):
        return None, f"its type `{text}` is not a plain C type"
    if re.search(r"\benum\b", text):
        return None, f"its type `{text}` needs an enum definition the generated file does not have"
    if any(tag.startswith("__anon") for _kw, tag in _GLOBAL_TAG_RE.findall(text)):
        return None, f"its type `{text}` names an anonymous struct or union"
    slot = _GLOBAL_POINTER_SLOT_RE.search(text)
    if slot:
        return f"{text[: slot.start()]}({slot.group(1)}{name}{slot.group(2)}){text[slot.end() :]};", ""
    m = _GLOBAL_ARRAY_RE.match(text)
    if not m or "(" in text:
        return None, f"its type `{text}` is not one the generated file can declare"
    base, dims = m.group("base").strip(), "".join(m.group("dims").split())
    if not base:
        return None, f"its type `{text}` is not one the generated file can declare"
    if _GLOBAL_TAG_RE.search(base) and "*" not in base:
        return None, f"its type `{text}` is held by value and needs a definition the generated file does not have"
    return f"{base}{'' if base.endswith('*') else ' '}{name}{dims};", ""


def _declaring_headers(name: str, run_dir: Path) -> list[tuple[Path, str]]:
    """
    The project headers (workspace/work) with an `extern` declaration of global `name`, shortest path
    first, each with the definition to write after including it: the declaration itself without
    `extern`, so with its qualifiers and typedef names (`extern volatile int G;` gives `volatile int G;`).
    `__typeof__(G) G;` would not do: Frama-C 35 drops a top-level `volatile` there and then refuses
    the definition (`different qualifiers`). It is used only for a declaration of several variables,
    whose text would define the others too.
    """
    work = Path(run_dir) / "workspace/work"
    if not work.is_dir():
        return []
    decl = re.compile(rf"^[ \t]*extern\b([^;{{}}()]*\b{re.escape(name)}\b\s*(?:\[[^;]*\]\s*)*);", re.MULTILINE)
    out: list[tuple[Path, str]] = []
    for header in sorted(work.rglob("*.h"), key=lambda p: (len(p.parts), p.as_posix())):
        try:
            text = header.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        m = decl.search(text) if name in text else None
        if m:
            own = " ".join(m.group(1).split())
            out.append((header, f"__typeof__({name}) {name};" if "," in own else f"{own};"))
    return out


def _declaring_header(name: str, run_dir: Path) -> tuple[Path, str] | None:
    """The first of `_declaring_headers`: the shortest path that declares global `name`, or None."""
    found = _declaring_headers(name, run_dir)
    return found[0] if found else None


# The words a definition may use and still need no project header: C's own type keywords.
_HEADER_FREE_WORDS = frozenset(
    "void char short int long float double signed unsigned _Bool const volatile restrict __restrict".split()
)


_TAG_POINTER_RE = re.compile(r"\s*(?:(?:const|volatile|restrict|__restrict)\b\s*)*\*")


def _header_free_definition(name: str, definition: str) -> str | None:
    """
    `definition` (a declaring header's own text) when it compiles without any project header: it
    names only C's type keywords and pointers to struct or union tags, which need no definition of
    the struct (`struct client_closure *client_closure;`). None when it names a typedef, a macro, an
    enum, a struct held by value, or other variables (`__typeof__`). sudo's log_client.h, which
    declares client_closure, does not parse without the sudo_queue.h its includers bring first.
    """
    if definition.startswith("__typeof__") or re.search(r"\benum\b", definition):
        return None
    text = definition
    for m in reversed(list(_GLOBAL_TAG_RE.finditer(definition))):
        if not _TAG_POINTER_RE.match(definition, m.end()):
            return None
        text = text[: m.start()] + " " + text[m.end() :]
    words = set(re.findall(r"[A-Za-z_]\w*", text)) - {name}
    return definition if words <= _HEADER_FREE_WORDS else None


_INCLUDE_DIRECTIVE_RE = re.compile(r'^(\s*#\s*include\s*)([<"])([^>"]+)[>"]')
_CONDITIONAL_OPEN_RE = re.compile(r"^\s*#\s*if(?:n?def)?\b")
_CONDITIONAL_CLOSE_RE = re.compile(r"^\s*#\s*endif\b")
_LINE_DIRECTIVE_RE = re.compile(r"^\s*#\s*(?:line\b|\d)")


def _strip_c_comments(text: str) -> str:
    """`text` without its C comments, keeping the line count (block comments keep their newlines)."""
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", text)


def _includer_prelude(header: Path, includer: Path, stub_dir: Path) -> list[str] | None:
    """
    The preprocessor lines of C file `includer` up to its own `#include` of `header`, or None when it
    does not include it directly: its `#include`s (config.h first), `#define`s and conditionals, with
    each conditional still open at the include closed after it. The header's include and the quoted
    includes found next to `includer` are rewritten relative to `stub_dir`, where link_globals.c is;
    `<...>` includes resolve through the module's -I flags, as for the includer itself.
    """
    try:
        text = includer.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    if header.name not in text:
        return None
    target = header.resolve()

    def _rel(p: Path) -> str:
        return Path(os.path.relpath(p.resolve(), stub_dir.resolve())).as_posix()

    lines: list[str] = []
    depth = 0
    for raw in _strip_c_comments(text).replace("\\\n", " ").splitlines():
        line = raw.rstrip()
        if not line.lstrip().startswith("#") or _LINE_DIRECTIVE_RE.match(line):
            continue
        m = _INCLUDE_DIRECTIVE_RE.match(line)
        if m:
            inc = m.group(3).strip()
            local = includer.parent / inc
            if (m.group(2) == '"' and local.is_file() and local.resolve() == target) or (
                header.as_posix().endswith("/" + inc.lstrip("./"))
            ):
                return [*lines, f'{m.group(1)}"{_rel(header)}"', *(["#endif"] * depth)]
            if m.group(2) == '"' and local.is_file():
                line = f'{m.group(1)}"{_rel(local)}"'
        elif _CONDITIONAL_OPEN_RE.match(line):
            depth += 1
        elif _CONDITIONAL_CLOSE_RE.match(line):
            depth = max(0, depth - 1)
        lines.append(line)
    return None


def _includer_candidates(build_sources: list[str], defining_files: list[str], run_dir: Path) -> list[Path]:
    """
    The C files whose includes link_globals.c may copy, best first: the build's own target sources
    (compiled with the same flags), the files defining the global, then every C file of the project.
    """
    out: dict[Path, None] = {}
    for src in build_sources:
        if src.endswith(".c") and not _is_generated_build_source(src):
            p = Path(src) if posixpath.isabs(src) else Path(run_dir) / src
            out.setdefault(p, None)
    for f in defining_files:
        out.setdefault(Path(run_dir) / _normalize_dag_source(f, Path(run_dir)), None)
    work = Path(run_dir) / "workspace/work"
    if work.is_dir():
        for p in sorted(work.rglob("*.c"), key=lambda q: (len(q.parts), q.as_posix())):
            out.setdefault(p, None)
    return [p for p in out if p.is_file()]


def _global_stub_definition(
    sym: str, rec: dict, records: list[dict], build_sources: list[str], run_dir: Path, stub_dir: Path
) -> tuple[dict, str | None, str]:
    """
    How link_globals.c defines global `sym` (model record `rec`, of all `records` for the name), as
    (stub fields, definition or None, reason). A declaring header's own text comes first, as it
    keeps the qualifiers the model's type text drops; it is written without the header when it names
    only C's type keywords and struct pointers (`_header_free_definition`). Otherwise the header is
    included after the preprocessor lines of a C file that includes it (`_includer_prelude`): sudo's
    sudoers.h does not parse without config.h first. Without such a file the header is included
    alone. Without a declaring header, the model's type text (`global_definition_text`).
    """
    fields: dict = {}
    headers = _declaring_headers(sym, run_dir)
    for header, definition in headers:
        free = _header_free_definition(sym, definition)
        if free is not None:
            fields["declared_in"] = header.relative_to(run_dir).as_posix()
            return fields, free, ""
    if not headers:
        from_type, reason = global_definition_text(sym, rec["type"])
        return fields, from_type, reason
    candidates = _includer_candidates(build_sources, [str(r.get("file") or "") for r in records], run_dir)
    for header, definition in headers:
        for includer in candidates:
            prelude = _includer_prelude(header, includer, stub_dir)
            if prelude is not None:
                fields["declared_in"] = header.relative_to(run_dir).as_posix()
                fields["include"] = Path(os.path.relpath(header.resolve(), stub_dir.resolve())).as_posix()
                fields["prelude"] = prelude
                fields["prelude_from"] = Path(os.path.relpath(includer.resolve(), run_dir.resolve())).as_posix()
                return fields, definition, ""
    header, definition = headers[0]
    fields["declared_in"] = header.relative_to(run_dir).as_posix()
    fields["include"] = Path(os.path.relpath(header.resolve(), stub_dir.resolve())).as_posix()
    return fields, definition, ""


def link_globals_source(stubs: list[dict]) -> str:
    """
    The generated definitions file for the globals link repair stands in for (`stubbed_globals`): each
    declaring header after the preprocessor lines of a file that includes it (`prelude`), or alone.
    """
    includes = dict.fromkeys(
        "\n".join(s["prelude"]) if s.get("prelude") else f'#include "{s["include"]}"' for s in stubs if s.get("include")
    )
    tags = dict.fromkeys(
        f"{kw} {tag};"
        for s in stubs
        if not s.get("include")
        for kw, tag in _GLOBAL_TAG_RE.findall(s.get("definition") or s["type"])
    )
    lines = [
        "/* Generated by run_eacsl_fuzz.py (link repair): global variables another link unit defines.",
        " * Linking that unit's file could bring a whole program (its main); each global is defined",
        f" * here instead and {LINK_GLOBALS_ASSUMPTION}. */",
        *includes,
        *tags,
    ]
    for s in stubs:
        lines.append(f"/* {s['name']}: defined in {s['file']} ({', '.join(s['units']) or 'unit not recorded'}) */")
        lines.append(s["definition"])
    return "\n".join(lines) + "\n"


LINK_STUBS_FILE = "link_stubs.c"
LINK_STUB_MARKER = "FRAMAC_LINK_STUB_CALLED"
DEFAULT_BSS_GLOBAL_SIZE = 16


def link_stubs_source(
    stubs: list[dict], global_stubs: list[dict] | tuple[dict, ...] = (), module: str | None = None
) -> str:
    """
    The generated file defining the functions and globals an address-flow cluster's sources name
    and its harness cannot reach (`stubbed_functions`, `.bss` `global_stubs`; scripts/unit_split.py,
    docs/plans/unit-split-address-flow.md), and for any module the functions link repair does not
    link from a file (`reason`: several programs define it, or its file is left out of the link).
    Each function is a symbol in file-scope assembly (no C type, so no project prototype can
    conflict) that jumps to `__framac_link_stub_called(name)`, writing LINK_STUB_MARKER via
    unbuffered `write(2, ...)` (E-ACSL-safe: no `fprintf` / `strlen` on unregistered `.rodata`) and
    calling `abort()`. Each global is a type-free zero-initialized `.bss` symbol sized from the
    Phase 0 model (`size`, defaulting to 16 bytes when unknown), avoiding non-self-contained
    project headers and by-value struct rejection. x86-64 (`gcc_x86_64`).
    """
    lines = [
        "/* Generated by run_eacsl_fuzz.py (link repair): symbols of the unit the address-flow cluster"
        + (f" {module}" if module else "")
        + "'s",
        " * sources name but its harness cannot reach (scripts/unit_split.py). A function stub reports",
        " * itself and aborts (the split's reach missed it); a global stub lives zero-initialized in .bss. */",
        "#include <stddef.h>",
        "#include <stdlib.h>",
        "#include <unistd.h>",
        "static void __framac_write_all(const char *s) {",
        "  size_t n = 0;",
        "  while (s[n] != '\\0') {",
        "    n++;",
        "  }",
        "  ssize_t _r = write(2, s, n);",
        "  (void)_r;",
        "}",
        "void __framac_link_stub_called(const char *name) {",
        f'  __framac_write_all("{LINK_STUB_MARKER}: ");',
        "  __framac_write_all(name);",
        '  __framac_write_all(" (not in the unit split\'s address-flow reach)\\n");',
        "  abort();",
        "}",
        "__asm__(",
    ]
    for i, s in enumerate(stubs):
        name = s["name"]
        # A stub link repair chose over linking a file (several definers, an excluded source) says why.
        why = str(s.get("reason") or "").replace("*/", "* /").replace("\\", "/").replace('"', "'")
        lines += [
            f'  "/* {name}: defined in {s.get("file") or "unknown"}{f"; {why}" if why else ""} */\\n"',
            '  ".text\\n"',
            f'  ".globl {name}\\n"',
            f'  ".type {name}, @function\\n"',
            f'  "{name}:\\n"',
            f'  "  leaq .Lframac_link_stub_{i}(%rip), %rdi\\n"',
            '  "  jmp __framac_link_stub_called@PLT\\n"',
            '  ".section .rodata\\n"',
            f'  ".Lframac_link_stub_{i}: .string \\"{name}\\"\\n"',
        ]
    for g in global_stubs:
        name = g["name"]
        raw_sz = g.get("size")
        size = int(raw_sz) if isinstance(raw_sz, int) and raw_sz > 0 else DEFAULT_BSS_GLOBAL_SIZE
        lines += [
            f'  "/* {name}: global defined in {g.get("file") or "unknown"} */\\n"',
            '  ".bss\\n"',
            '  ".balign 16\\n"',
            f'  ".globl {name}\\n"',
            f'  ".type {name}, @object\\n"',
            f'  ".size {name}, {size}\\n"',
            f'  "{name}: .zero {size}\\n"',
        ]
    lines += ['  ".text\\n");', ""]
    return "\n".join(lines)


def _is_generated_build_source(path: str) -> bool:
    base = posixpath.basename(str(path).replace("\\", "/"))
    return base.startswith("harness_") or base in (LINK_STUBS_FILE, LINK_GLOBALS_FILE) or "_link_globals/" in f"/{path}"


def _flow_cluster_files(dag_path: Path, module: str | None, sources: list[str] | None = None) -> set[str] | None:
    """
    The tree paths an address-flow cluster's builds compile: the union of DAG submodule
    `build_sources`, sidecar `harness_<module>.json` `flow_build_sources` (if widened by harness
    snippets, B7), and the initial non-harness target `sources` passed to the build. None when
    `module` is no such cluster.
    """
    if not module:
        return None
    dag = load_json_optional(Path(dag_path), None)
    sub = ((dag.get("submodules") or {}) if isinstance(dag, dict) else {}).get(module)
    if (
        not isinstance(sub, dict)
        or sub.get("reach") != "address_flow"
        or not isinstance(sub.get("build_sources"), list)
    ):
        return None
    files = {_dag_tree_path(str(f)) for f in sub["build_sources"]}
    sidecar_path = Path(dag_path).parent.parent / "harnesses" / f"harness_{module}.json"
    sidecar = load_json_optional(sidecar_path, None)
    if isinstance(sidecar, dict) and isinstance(sidecar.get("flow_build_sources"), list):
        files |= {_dag_tree_path(str(f)) for f in sidecar["flow_build_sources"] if isinstance(f, str)}
    for src in sources or ():
        if not _is_generated_build_source(src):
            files.add(_dag_tree_path(src))
    return files


def _dag_tree_path(path: str) -> str:
    p = str(path).replace("\\", "/")
    for prefix in ("/framac-run/", "/target/", "./"):
        if p.startswith(prefix):
            p = p[len(prefix) :]
    return p[len("workspace/work/") :] if p.startswith("workspace/work/") else p


def _missing_source(sym: str, file: str, norm: str, dag_path: Path, run_dir: Path) -> dict:
    """
    Why link repair cannot add `norm` (the overlay path of DAG file `file`, defining `sym`): it does not
    exist. A file the build compiles and the target does not have is a source the build generated (nginx's
    objs/ngx_modules.c): the Phase 0 build capture keeps it in the snapshot and installs it in
    workspace/work (target_env.install_generated_sources). The reason names the step to redo.
    """
    rel = _dag_tree_path(file)
    capture = load_json_optional(Path(dag_path).parent / "build_capture.json", None)
    capture = capture if isinstance(capture, dict) else {}
    compiled = any(isinstance(c, dict) and c.get("source") == rel for c in capture.get("compiles") or [])
    gen = ((capture.get("snapshot") or {}).get("generated") or {}) if isinstance(capture.get("snapshot"), dict) else {}
    snap = Path(run_dir) / target_env.SNAPSHOT_REL
    if rel in target_env.generated_source_paths(snap):
        kind = "generated_source_missing"
        reason = (
            f"{rel} is a C source the build generated; the Phase 0 snapshot keeps it "
            f"({target_env.SNAPSHOT_REL}/{target_env.GENERATED_REL}/{rel}) but it is not installed in "
            "workspace/work: run `workspace_overlay.py install-generated --overlay workspace`"
        )
    elif rel in (gen.get("sources_deleted") or []):
        kind = "generated_source_missing"
        reason = (
            f"{rel} is a C source the build generated, compiled and then deleted, so the Phase 0 build capture "
            "(build_capture.py run) could not keep it in the snapshot: change the recipe so the build keeps it, "
            "and run the build capture again"
        )
    elif compiled:
        kind = "generated_source_missing"
        reason = (
            f"{rel} is a source the build compiles (build_capture.json) and the target does not have: the build "
            "generated it, and the Phase 0 build capture (build_capture.py run) did not keep it in the snapshot "
            f"({target_env.SNAPSHOT_REL}/{target_env.GENERATED_REL}) nor install it in workspace/work. A capture "
            "made before generated sources were kept never has it: run the build capture again"
        )
    else:
        kind = "source_missing"
        reason = f"{rel} is not in workspace/work and the build capture does not compile it"
    return {"file": rel, "path": norm, "symbols": [sym], "kind": kind, "reason": reason}


def _link_unit_context(dag_path: Path, module: str | None, sources: list[str] | None = None) -> dict:
    """
    What placing a global needs from the DAG: the link unit record of harness module `module`
    (`unit`: None without link units, without a module, or for a module the DAG and the sidecars
    do not place, as `ModuleMap.unit_of` answers), that unit's sources (`unit_files`: its own and
    those of the project libraries it links), the units of the modules it links (`linked_units`, from
    the record's `linked_modules`, whose files are in `unit_files` too) and the files defining a
    `main` (`main_files`).
    """
    from module_map import ModuleMap, load_sidecars

    dag = load_json_optional(Path(dag_path), None)
    mm = ModuleMap(dag if isinstance(dag, dict) else None, load_sidecars(Path(dag_path).parent.parent / "harnesses"))
    unit: dict | None = None
    if module and mm.units_are_link_units:
        rec = mm.modules.get(mm.unit_of(module))
        unit = rec if isinstance(rec, dict) else None
    files = [*((unit or {}).get("files") or []), *((unit or {}).get("required_sources") or [])]
    linked_units: set[str] = set()
    for name in (unit or {}).get("linked_modules") or []:
        linked = mm.modules.get(str(name)) if isinstance(name, str) else None
        if isinstance(linked, dict):
            linked_units.add(str(linked.get("unit") or name))
            files += [f for f in linked.get("files") or [] if isinstance(f, str)]
    return {
        "flow_files": _flow_cluster_files(Path(dag_path), module, sources=sources),
        "unit": unit,
        "linked_units": linked_units,
        "unit_files": {_dag_tree_path(f) for f in files if isinstance(f, str)},
        "main_files": {
            _dag_tree_path(str(r.get("file") or ""))
            for k, r in mm.functions.items()
            if isinstance(r, dict) and (r.get("name") or str(k).split("#")[-1]) == "main"
        },
    }


def _place_global(records: list[dict], ctx: dict) -> tuple[str, dict, str]:
    """
    Where an undefined global comes from, as (action, record, reason):

    - `add`: link its defining file, as for a function. Its file belongs to the module's link
      unit; or the unit is not known and the file defines no `main`.
    - `stub`: another link unit defines it. Its file is not linked (it may hold that unit's
      `main`); the generated definitions file defines it instead.
    - `unresolved`: the unit is not known and the file defines a `main`.

    For an address-flow cluster (`flow_files`), a global whose file the cluster does not compile is
    a `stub`: no code its harness reaches names it (scripts/unit_split.py), and its file would link
    more files in.
    """
    flow_files = ctx.get("flow_files")
    if flow_files is not None:
        for rec in records:
            if _dag_tree_path(rec["file"]) in flow_files:
                return "add", rec, ""
        return "stub", records[0], ""
    unit = ctx["unit"]
    if unit is None:
        for rec in records:
            if _dag_tree_path(rec["file"]) not in ctx["main_files"]:
                return "add", rec, ""
        return "unresolved", records[0], "its file defines a main and the module's link unit is not known"
    for rec in records:
        if unit.get("unit") in rec["units"] or _dag_tree_path(rec["file"]) in ctx["unit_files"]:
            return "add", rec, ""
    return "stub", records[0], ""


def _excluded_link_sources(dag_path: Path, module: str | None) -> dict[str, list[str]]:
    """
    The files a target fuzz module's link leaves out (tree path -> the symbols its fuzzer defines
    itself), from its sidecar `harness_<module>.json` `target_fuzzer.link.excluded_sources`
    (generate_harness.target_fuzzer_link_sources). Linked back for another symbol they define, they
    bring the conflict back (sudo run-1 tf_fuzz_policy: "global var audit_msg at .../fuzz_policy.c:50
    has different initializer than .../audit.c:43"). Empty for any other module.
    """
    if not module:
        return {}
    sidecar = load_json_optional(Path(dag_path).parent.parent / "harnesses" / f"harness_{module}.json", None)
    tf = sidecar.get("target_fuzzer") if isinstance(sidecar, dict) else None
    link = tf.get("link") if isinstance(tf, dict) else None
    out: dict[str, list[str]] = {}
    for ex in (link.get("excluded_sources") or []) if isinstance(link, dict) else []:
        if isinstance(ex, dict) and isinstance(ex.get("source"), str) and ex["source"].strip():
            out[_dag_tree_path(ex["source"])] = [str(s) for s in ex.get("symbols") or [] if isinstance(s, str)]
    return out


def _file_external_definitions(dag_path: Path) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """
    (functions, globals): source file (tree path) -> the names it defines with external linkage. Functions:
    the DAG's non-static ones (header records left out, `_dag_function_definers`) and those only the build
    compiles (`build_only_functions`); globals: the model's (`_model_global_variables`). What linking that
    file brings into a build besides the symbol it is added for.
    """
    fns: dict[str, set[str]] = {}
    for name, recs in _dag_function_definers(dag_path).items():
        for rec in recs:
            fns.setdefault(_dag_tree_path(rec["file"]), set()).add(name)
    # As `_dag_symbol_tables` reads them: a build-only name the DAG parsed elsewhere is that file's.
    _parsed, build_only = _dag_symbol_tables(dag_path)
    for name, file in build_only.items():
        fns.setdefault(_dag_tree_path(file), set()).add(name)
    globs: dict[str, set[str]] = {}
    for name, recs in _model_global_variables(dag_path).items():
        for rec in recs:
            globs.setdefault(_dag_tree_path(rec["file"]), set()).add(name)
    return fns, globs


def _target_fuzzer_own_definitions(dag_path: Path, module: str | None, run_dir: Path) -> tuple[str, set[str]]:
    """
    (driver tree path, names) the target fuzzer of target fuzz module `module` defines with external linkage:
    the symbols its sidecar `target_fuzzer.link.excluded_sources` records (those another file of the unit
    defines too), and its driver's own definitions (`generate_harness.target_fuzzer_definitions`, the driver
    `target_fuzzer.source` resolved against `run_dir`). The DAG has no record of a driver the build does not
    capture (sudo's plugins/sudoers/regress/fuzz/*.c), so the build's own definitions cannot show them.
    ("", empty) for any other module.
    """
    if not module:
        return "", set()
    sidecar = load_json_optional(Path(dag_path).parent.parent / "harnesses" / f"harness_{module}.json", None)
    tf = sidecar.get("target_fuzzer") if isinstance(sidecar, dict) else None
    if not isinstance(tf, dict) or not isinstance(tf.get("source"), str) or not tf["source"].strip():
        return "", set()
    names = {s for syms in _excluded_link_sources(Path(dag_path), module).values() for s in syms}
    driver = Path(tf["source"])
    for cand in (driver, Path(run_dir) / driver, Path(run_dir) / "workspace" / "work" / driver):
        if cand.is_file():
            import generate_harness  # lazy: generate_harness imports this module

            cppflags = sidecar.get("cppflags") if isinstance(sidecar, dict) else ""
            own, _method = generate_harness.target_fuzzer_definitions(cand.as_posix(), str(cppflags or ""))
            names |= own
            break
    return _dag_tree_path(tf["source"]), names


def _place_function(records: list[dict], ctx: dict, linked: set[str]) -> tuple[str, dict, str]:
    """
    Which of several files defining an undefined function to link, as (action, record, reason). Each
    program of a target may define a function its libraries call (sudo: `open_sudoers` in cvtsudoers.c,
    sudoers.c, testsudoers.c and visudo.c, called from the parser libparsesudoers.a); linking the first
    one the DAG lists pulled the whole cvtsudoers program into libparsesudoers_a (sudo run-1).

    - `add`: a definer the build already links (`linked`, tree paths), else one of the module's link
      unit or of a unit it links (`units`, `unit_files`, `linked_units`); with the unit not known, the
      only definer that defines no `main`.
    - `stub`: none of them; the caller stubs it (`link_stubs.c`) or records it unresolved.
    """
    for rec in records:
        if _dag_tree_path(rec["file"]) in linked:
            return "add", rec, ""
    unit = ctx.get("unit")
    files = ", ".join(_dag_tree_path(r["file"]) for r in records)
    if unit is not None:
        own_units = {str(unit.get("unit") or ""), *ctx.get("linked_units", ())} - {""}
        for rec in records:
            if own_units & set(rec.get("units") or ()) or _dag_tree_path(rec["file"]) in ctx["unit_files"]:
                return "add", rec, ""
        return (
            "stub",
            records[0],
            f"{len(records)} files define it ({files}), none of them in the module's link unit "
            f"{unit.get('unit') or unit.get('module')} or a unit it links",
        )
    candidates = [r for r in records if _dag_tree_path(r["file"]) not in ctx["main_files"]]
    if len(candidates) == 1:
        return "add", candidates[0], ""
    return "stub", records[0], f"{len(records)} files define it ({files}) and the module's link unit is not known"


def _record_in_flow_files(rec: dict | None, flow_files: set[str]) -> bool:
    """Whether a DAG/model function or global record is compiled by any `.c` file in `flow_files`."""
    if not isinstance(rec, dict):
        return False
    file = _dag_tree_path(str(rec.get("file") or ""))
    if file and file in flow_files:
        return True
    compiled_in = rec.get("compiled_in")
    return isinstance(compiled_in, list) and any(_dag_tree_path(str(cf)) in flow_files for cf in compiled_in)


def _flow_sub_stub_info(dag_path: Path, module: str | None, flow_files: set[str] | None = None) -> tuple[str, set[str]]:
    """(sub_unit, explicit_stub_fn_names) for an address-flow cluster, or ('', set())."""
    if not module:
        return "", set()
    dag = load_json_optional(Path(dag_path), None)
    if not isinstance(dag, dict):
        return "", set()
    sub = (dag.get("submodules") or {}).get(module)
    if not isinstance(sub, dict) or sub.get("reach") != "address_flow":
        return "", set()
    fns = dag.get("functions") or {}
    gvars = dag.get("global_variables") or {}
    stub_keys: set[str] = set((sub.get("link_stubs") or {}).get("functions") or [])
    if flow_files is not None:
        base_files = {_dag_tree_path(str(f)) for f in sub.get("build_sources") or []}
        if flow_files != base_files:
            import unit_split

            unit_name = str(sub.get("unit") or "")
            _own_keys, all_keys = unit_split.unit_closure_keys(dag, unit_name)
            if all_keys:
                recomputed = unit_split.link_stubs_for_files(fns, gvars, all_keys, flow_files)
                stub_keys |= set(recomputed["functions"])
    explicit: set[str] = set()
    for fk in stub_keys:
        rec = fns.get(fk) if isinstance(fns, dict) else None
        if flow_files is not None and _record_in_flow_files(rec, flow_files):
            continue
        name = str((rec or {}).get("name") or str(fk).split("#")[-1])
        if name:
            explicit.add(name)
    return str(sub.get("unit") or ""), explicit


def _flow_cluster_functions(
    dag_path: Path | str | None,
    module: str | None,
    sources: list[str],
) -> list[str] | None:
    """
    Reachable target function names for an address-flow cluster's E-ACSL `-rte-select` /
    `-e-acsl-functions` selection.

    An address-flow cluster links whole `.c` files (`build_sources` / `flow_build_sources`) that
    also contain many unreachable functions outside the cluster. Passing every function defined in
    those files to Frama-C RTE + E-ACSL bloats `instrumented.c` and instruments dead code. This
    computes the address-flow reach of the cluster's anchors plus any functions/globals referenced
    by the cluster's harness source(s), keeping E-ACSL instrumentation scoped to reachable code.
    Returns None when `module` is not an address-flow cluster or has no reachable names.
    """
    if not dag_path or not module:
        return None
    dp = Path(dag_path)
    dag = load_json_optional(dp, None)
    if not isinstance(dag, dict):
        return None
    sub = (dag.get("submodules") or {}).get(module)
    if (
        not isinstance(sub, dict)
        or sub.get("reach") != "address_flow"
        or not isinstance(sub.get("build_sources"), list)
    ):
        return None
    import unit_split

    dag_fns: dict[str, dict] = dag.get("functions") or {}
    dag_gvars: dict[str, dict] = dag.get("global_variables") or {}
    unit_name = str(sub.get("unit") or "")
    _own_keys, all_keys = unit_split.unit_closure_keys(dag, unit_name)
    all_set = set(all_keys)
    anchors = [k for k in sub.get("anchors") or [] if k in all_set]

    reached_keys: set[str]
    if all_set and anchors:
        harness_words: set[str] = set()
        for src in sources:
            p = Path(src)
            if not p.is_file():
                continue
            if not p.name.startswith("harness_"):
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            harness_words |= set(_C_IDENT_RE.findall(_C_COMMENT_RE.sub(" ", text)))
        extra_fns: set[str] = set()
        extra_globs: set[str] = set()
        if harness_words:
            for fk in all_keys:
                rec = dag_fns.get(fk)
                if not isinstance(rec, dict):
                    continue
                if rec.get("is_static") and not rec.get("header"):
                    continue
                fname = str(rec.get("name") or fk.rsplit("#", 1)[-1])
                if fname in harness_words:
                    extra_fns.add(fk)
            for gk, grec in dag_gvars.items():
                if not isinstance(grec, dict) or grec.get("static"):
                    continue
                gname = str(grec.get("name") or gk.rsplit("#", 1)[-1])
                if gname in harness_words:
                    extra_globs.add(gk)
        starts = [*anchors, *sorted(extra_fns - set(anchors))]
        reached_keys, _globs = unit_split.flow_reach(
            dag_fns, dag_gvars, starts, all_set, extra_globals=extra_globs or None
        )
    else:
        reached_keys = {str(k) for k in sub.get("functions") or [] if isinstance(k, str)}

    names: set[str] = set(_harness_header_entries(sources))
    for fk in reached_keys:
        rec = dag_fns.get(fk)
        if isinstance(rec, dict) and rec.get("header") and rec.get("is_static"):
            # Static inline header helpers are frequently omitted or inlined out of Frama-C's AST
            # (e.g. nginx ngx_write_fd / ngx_strlchr); public header entry points already come from
            # `_harness_header_entries(sources)` above.
            continue
        name = str((rec or {}).get("name") or str(fk).rsplit("#", 1)[-1])
        if (
            name
            and name not in ("eva_main", "main", "__framac_link_stub_called", "__framac_write_all")
            and not is_harness_fuzz_function(name)
            and name not in TYPE_MODIFIERS_AND_PRIMITIVES
        ):
            names.add(name)
    return sorted(names) if names else None


def _preseed_flow_stubs(
    sources: list[str],
    dag_path: Path | str | None,
    out_bin: Path,
    link_module: str | None,
) -> tuple[list[str], dict | None, list[dict], list[dict]]:
    """
    Pre-generate `<out_bin>_link_globals/link_stubs.c` from `sub["link_stubs"]` (recomputed over
    widened `flow_files` when harness snippets or extra sources extend `sub["build_sources"]`)
    before Attempt 1 for an address-flow cluster (B9: avoids running E-ACSL Stage 1 + Stage 2
    twice). Returns `(sources_with_stubs, preseeded_record_or_None, fn_stubs, bss_global_stubs)`.
    """
    if not dag_path or not link_module:
        return list(sources), None, [], []
    dp = Path(dag_path)
    flow_files = _flow_cluster_files(dp, link_module, sources=sources)
    if flow_files is None:
        return list(sources), None, [], []
    dag = load_json_optional(dp, None)
    if not isinstance(dag, dict):
        return list(sources), None, [], []
    sub = (dag.get("submodules") or {}).get(link_module)
    if not isinstance(sub, dict):
        return list(sources), None, [], []
    link_stubs = sub.get("link_stubs")
    if not isinstance(link_stubs, dict):
        return list(sources), None, [], []
    dag_fns = dag.get("functions") or {}
    dag_gvars = dag.get("global_variables") or {}
    model_gvars = _model_global_variables(dp)

    stub_fn_keys: list[str] = list(link_stubs.get("functions") or [])
    stub_glob_keys: list[str] = list(link_stubs.get("globals") or [])
    base_files = {_dag_tree_path(str(f)) for f in sub.get("build_sources") or []}
    if flow_files != base_files:
        import unit_split

        unit_name = str(sub.get("unit") or "")
        _own_keys, all_keys = unit_split.unit_closure_keys(dag, unit_name)
        if all_keys:
            recomputed = unit_split.link_stubs_for_files(dag_fns, dag_gvars, all_keys, flow_files)
            stub_fn_keys = sorted(set(stub_fn_keys) | set(recomputed["functions"]))
            stub_glob_keys = sorted(set(stub_glob_keys) | set(recomputed["globals"]))

    fn_stubs: list[dict] = []
    seen_fns: set[str] = set()
    for fk in stub_fn_keys:
        rec = dag_fns.get(fk) if isinstance(dag_fns, dict) else None
        if isinstance(rec, dict) and rec.get("is_static") is True:
            continue
        if _record_in_flow_files(rec, flow_files):
            continue
        name = str((rec or {}).get("name") or str(fk).split("#")[-1])
        file = _dag_tree_path(str((rec or {}).get("file") or ""))
        if not name or name in seen_fns or (file and file in flow_files):
            continue
        seen_fns.add(name)
        fn_stubs.append({"name": name, "file": file})

    global_stubs: list[dict] = []
    seen_globs: set[str] = set()
    for gk in stub_glob_keys:
        grec = dag_gvars.get(gk) if isinstance(dag_gvars, dict) else None
        gname = str((grec or {}).get("name") or str(gk).rpartition("#")[2] or gk)
        mrecs = model_gvars.get(gname) or []
        mrec = next((r for r in mrecs if f"{r['file']}#{r['name']}" == gk), mrecs[0] if mrecs else None)
        if isinstance(grec, dict) and grec.get("static"):
            continue
        if _record_in_flow_files(grec, flow_files):
            continue
        file = _dag_tree_path(str((grec or {}).get("file") or (mrec or {}).get("file") or ""))
        if not gname or gname in seen_globs or (file and file in flow_files):
            continue
        raw_sz = (grec or {}).get("size") or (mrec or {}).get("size")
        size = int(raw_sz) if isinstance(raw_sz, int) and raw_sz > 0 else DEFAULT_BSS_GLOBAL_SIZE
        seen_globs.add(gname)
        global_stubs.append(
            {
                "name": gname,
                "file": file,
                "type": str((mrec or {}).get("type") or ""),
                "units": list((mrec or {}).get("units") or []),
                "size": size,
                "assumption": LINK_GLOBALS_ASSUMPTION,
                "bss": True,
            }
        )

    if not fn_stubs and not global_stubs:
        return list(sources), None, [], []
    stub_dir = Path(out_bin).parent / f"{Path(out_bin).name}_link_globals"
    stub_dir.mkdir(parents=True, exist_ok=True)
    fn_file = stub_dir / LINK_STUBS_FILE
    fn_file.write_text(link_stubs_source(fn_stubs, global_stubs, link_module), encoding="utf-8", newline="\n")
    out_sources = list(sources)
    fn_posix = fn_file.as_posix()
    if fn_posix not in {s.replace("\\", "/") for s in out_sources}:
        out_sources.append(fn_posix)
    record = {
        "functions_file": fn_posix,
        "functions": fn_stubs,
        "globals": global_stubs,
    }
    return out_sources, record, fn_stubs, global_stubs


def repair_sources_for_link(
    sources: list[str],
    log: str,
    dag_path: Path | str | None,
    run_dir: Path | str,
    *,
    module: str | None = None,
    stub_dir: Path | None = None,
    stubbed: list[dict] | None = None,
    unresolved: list[dict] | None = None,
    missing: list[dict] | None = None,
    stubbed_functions: list[dict] | None = None,
    unresolved_functions: list[dict] | None = None,
) -> tuple[list[str], dict]:
    """
    One link-repair round: map `undefined reference to 'X'` symbols to their
    defining sources via the DAG and append the missing files. Returns (sources, info).

    A function several files define (each program its own: sudo's `open_sudoers`) is linked from the
    one the build already links, else the one of the module's link unit or of a unit it links
    (`_place_function`). When none is, it is stubbed in `<stub_dir>/link_stubs.c` with its `reason` and
    `definers` (`info["stubbed_functions"]`), or without `stub_dir` listed in `unresolved_functions`:
    linking one program's file into a library pulls that whole program in (sudo run-1 libparsesudoers_a).

    A file a target fuzz module's link leaves out (sidecar `target_fuzzer.link.excluded_sources`,
    `_excluded_link_sources`) is never added back: a function or global it defines is stubbed instead
    (`link_stubs.c` / `link_globals.c`), or recorded unresolved without `stub_dir`. Nor is a file that
    defines, besides the symbol, a name the build already defines (`_file_external_definitions` of the
    linked files, and for a target fuzz module the fuzzer's own, `_target_fuzzer_own_definitions`): linked,
    it fails on "multiple definition" (sudo run-1 tf_fuzz_sudoers_ldif: cvtsudoers.c, the only definer of
    log_warnx and of the global filters, also defines open_sudoers, which the fuzzer defines). The symbol
    is stubbed the same way, its `reason` naming each clash and its current definer. A global another
    linked file defines too is no clash: under the builds' -fcommon two uninitialized ones are one object,
    and the model does not record which are initialized.

    For an address-flow cluster (`module` is a DAG submodule with `build_sources`,
    scripts/unit_split.py), a parsed non-static function defined outside `flow_files` (of the same
    unit, or explicitly listed in `sub["link_stubs"]["functions"]`) is not linked from its file: it
    is defined in `<stub_dir>/link_stubs.c` (`link_stubs_source`, rewritten with earlier rounds'
    stubs), and listed in `info["stubbed_functions"]`. An unreached cluster global outside
    `flow_files` is emitted as a type-free `.bss` symbol in `link_stubs.c` (`bss: True` in
    `info["stubbed_globals"]`), avoiding non-self-contained headers and by-value struct rejection.
    `build_only_functions` are never stubbed in `link_stubs.c` (their `.c` files are linked).

    For non-flow builds, a global defined in another link unit is defined zero-initialized in
    `<stub_dir>/link_globals.c` (`_global_stub_definition`). No global is stubbed whose defining
    file this round links in; an earlier round's stub of one is dropped (`info["unstubbed_globals"]`),
    and link_globals.c leaves the sources when it has nothing left to define.
    """
    syms = parse_undefined_references(log)
    if not syms or not dag_path:
        return list(sources), {}
    dp = Path(dag_path)
    parsed_syms, build_only_syms = _dag_symbol_tables(dp)
    have = {s.replace("\\", "/") for s in sources}
    added: list[str] = []
    resolved: list[str] = []
    new_c_stubs: list[dict] = []
    new_bss_stubs: list[dict] = []
    known_stubs = {s["name"] for s in stubbed or []}
    known_fn_stubs = {s["name"] for s in stubbed_functions or []}
    new_fn_stubs: list[dict] = []
    flow_files = _flow_cluster_files(dp, module, sources=sources) if stub_dir is not None else None
    sub_unit, explicit_fn_stubs = (
        _flow_sub_stub_info(dp, module, flow_files=flow_files) if flow_files is not None else ("", set())
    )
    global_vars: dict[str, list[dict]] | None = None
    definers: dict[str, list[dict]] | None = None
    ctx: dict = {}
    excluded = _excluded_link_sources(dp, module)

    def _excluded_reason(file: str) -> str:
        tree = _dag_tree_path(file)
        return (
            f"the target fuzzer's link leaves {tree} out: the fuzzer defines {', '.join(excluded.get(tree) or [])} "
            "itself (sidecar target_fuzzer.link.excluded_sources)"
        )

    # What the build already defines (name -> the file defining it), read on first need and grown with each
    # file this round adds: a file linked for one symbol brings every other one it defines, and one the
    # build already has fails the link on "multiple definition" (sudo run-1 tf_fuzz_sudoers_ldif:
    # cvtsudoers.c, added for log_warnx, also defines open_sudoers, which the target fuzzer defines).
    file_fns: dict[str, set[str]] = {}
    file_globs: dict[str, set[str]] = {}
    built: dict[str, str] = {}  # the linked files' functions and all the target fuzzer defines
    built_globs: dict[str, str] = {}  # the linked files' globals
    built_read = False

    def _note_linked(tree: str) -> None:
        for name in file_fns.get(tree, ()):
            built.setdefault(name, tree)
        for name in file_globs.get(tree, ()):
            built_globs.setdefault(name, tree)

    def _clashes(file: str, sym: str) -> list[tuple[str, str]]:
        """(name, current definer) of each name `file` would define a second time; none for a linked file."""
        nonlocal built_read
        tree = _dag_tree_path(file)
        if tree in {_dag_tree_path(h) for h in have}:
            return []
        if not built_read:
            built_read = True
            fns, globs = _file_external_definitions(dp)
            file_fns.update(fns)
            file_globs.update(globs)
            for h in sorted({_dag_tree_path(h) for h in have}):
                _note_linked(h)
            driver, own = _target_fuzzer_own_definitions(dp, module, Path(run_dir))
            for name in own:
                built.setdefault(name, f"the target fuzzer {driver}")
        hits = {n: built.get(n) or built_globs[n] for n in file_fns.get(tree, ()) if n in built or n in built_globs}
        # A global two linked files define is no clash under -fcommon (both builds use it) unless both are
        # initialized, which the model does not record: a global only clashes with a function or the fuzzer's own.
        hits.update({n: built[n] for n in file_globs.get(tree, ()) if n in built})
        return sorted((n, d) for n, d in hits.items() if n != sym)

    def _unlinkable_reason(file: str, sym: str) -> str:
        """Why `file` cannot be linked for `sym` (left out of the target fuzzer's link, or a clash), or ""."""
        if _dag_tree_path(file) in excluded:
            return _excluded_reason(file)
        clashes = _clashes(file, sym)
        if not clashes:
            return ""
        named = ", ".join(f"{n} (defined in {d})" for n, d in clashes[:6]) + (", ..." if len(clashes) > 6 else "")
        return f"linking {_dag_tree_path(file)} would define a second time what the build already defines: {named}"

    def _stub_function(sym: str, file: str, reason: str, recs: list[dict]) -> None:
        """Define `sym` in link_stubs.c instead of linking `file`; without `stub_dir`, record it unresolved."""
        stub = {
            "name": sym,
            "file": _dag_tree_path(file),
            "reason": reason,
            "definers": [_dag_tree_path(r["file"]) for r in recs],
        }
        if stub_dir is None:
            if unresolved_functions is not None and all(u["name"] != sym for u in unresolved_functions):
                unresolved_functions.append({**stub, "reason": f"{reason}; no build directory was given"})
        elif sym not in known_fn_stubs:
            known_fn_stubs.add(sym)
            new_fn_stubs.append(stub)
            resolved.append(sym)

    for sym in syms:
        parsed_hit = parsed_syms.get(sym)
        if parsed_hit is not None:
            f, fn_mod = parsed_hit
            outside_flow = flow_files is not None and _dag_tree_path(f) not in flow_files
            # B1 defense in depth: never stub a function from a linked library unit unless it is
            # explicitly outside flow_files AND listed in sub["link_stubs"]["functions"].
            can_stub = outside_flow and (not sub_unit or not fn_mod or fn_mod == sub_unit or sym in explicit_fn_stubs)
            if can_stub:
                if sym not in known_fn_stubs:
                    known_fn_stubs.add(sym)
                    new_fn_stubs.append({"name": sym, "file": _dag_tree_path(f)})
                    resolved.append(sym)
                continue
            if definers is None:
                definers = _dag_function_definers(dp)
            recs = definers.get(sym) or [{"file": f, "module": fn_mod, "units": []}]
            kept = [r for r in recs if not _unlinkable_reason(r["file"], sym)]
            if not kept:
                _stub_function(sym, recs[0]["file"], _unlinkable_reason(recs[0]["file"], sym), recs)
                continue
            if len(recs) > 1:
                # Several programs define it: link the one of this module's unit, never the first listed
                # (nor the one an excluded file leaves: sudo's stubs.c beside an excluded interfaces.c).
                ctx = ctx or _link_unit_context(dp, module, sources=sources)
                action, rec, reason = _place_function(kept, ctx, {_dag_tree_path(h) for h in have})
                if action == "add":
                    f = rec["file"]
                else:
                    _stub_function(sym, rec["file"], reason, recs)
                    continue
            else:
                f = kept[0]["file"]
        elif sym in build_only_syms:
            # B8: build_only_functions (hidden from Frama-C by compiler macros) are never stubbed,
            # unless the target fuzzer's link leaves their file out or it defines what the build has.
            f = build_only_syms[sym]
            why_not = _unlinkable_reason(f, sym)
            if why_not:
                _stub_function(sym, f, why_not, [{"file": f}])
                continue
        else:
            f = ""
        if not f:
            if global_vars is None:
                global_vars = _model_global_variables(dp)
            if sym not in global_vars or sym in known_stubs:
                continue
            ctx = ctx or _link_unit_context(dp, module, sources=sources)
            # A file the target fuzzer's link leaves out is never linked back, nor one defining what the
            # build already defines: its global is stubbed.
            linkable = [r for r in global_vars[sym] if not _unlinkable_reason(r["file"], sym)]
            if linkable:
                action, rec, reason = _place_global(linkable, ctx)
            else:
                action, rec, reason = "stub", global_vars[sym][0], ""
            why = {} if linkable else {"reason": _unlinkable_reason(rec["file"], sym)}
            if action == "stub" and stub_dir is None:
                action, reason = "unresolved", "another link unit defines it and no build directory was given"
                if not linkable:
                    reason = f"{why['reason']}, and no build directory was given"
            elif action == "stub" and stub_dir is not None and flow_files is not None:
                raw_sz = rec.get("size")
                size = int(raw_sz) if isinstance(raw_sz, int) and raw_sz > 0 else DEFAULT_BSS_GLOBAL_SIZE
                known_stubs.add(sym)
                new_bss_stubs.append(
                    {
                        **rec,
                        "file": _dag_tree_path(rec["file"]),
                        "size": size,
                        "assumption": LINK_GLOBALS_ASSUMPTION,
                        "bss": True,
                        **why,
                    }
                )
                resolved.append(sym)
                continue
            elif action == "stub" and stub_dir is not None:
                # The header that declares it comes first: it has the types and the qualifiers the
                # model's type text drops. A plain `int G;` next to another stub's header declaring
                # `extern volatile int G;` does not compile (checked with clang 19 and Frama-C 35).
                fields, definition, reason = _global_stub_definition(
                    sym, rec, global_vars[sym], [*sources, *added], Path(run_dir), stub_dir
                )
                stub = {**rec, "assumption": LINK_GLOBALS_ASSUMPTION, **fields, **why}
                if definition is None:
                    action, reason = "unresolved", f"{reason}, and no header of the project declares it"
                else:
                    known_stubs.add(sym)
                    new_c_stubs.append({**stub, "definition": definition})
                    resolved.append(sym)
                    continue
            if action == "unresolved":
                if unresolved is not None:
                    unresolved.append({"name": sym, "file": rec["file"], "units": rec["units"], "reason": reason})
                continue
            f = rec["file"]
        norm = _normalize_dag_source(f, Path(run_dir))
        if norm not in have and not (Path(norm) if posixpath.isabs(norm) else Path(run_dir) / norm).is_file():
            if missing is not None:
                record = _missing_source(sym, f, norm, dp, Path(run_dir))
                same = next((m for m in missing if m.get("path") == norm), None)
                if same is None:
                    missing.append(record)
                elif sym not in same["symbols"]:
                    same["symbols"].append(sym)
            continue
        if norm not in have:
            have.add(norm)
            added.append(norm)
            resolved.append(sym)
            if built_read:
                _note_linked(_dag_tree_path(norm))
    # A global is defined once: a file this round links in for any symbol defines the globals the
    # model records in it, so neither a stub of this round nor one of an earlier round stays for them
    # (sudo liblogsrv_a: protobuf-c.c added for protobuf_c_message_pack, and protobuf_c_empty_string
    # stubbed too; Frama-C: `global var ... has different initializer`). A global still undefined
    # beside a file the failed build already compiled keeps its stub: that file does not define it
    # under the build's flags. Only link_globals.c's stubs: an address-flow cluster's `.bss` stubs
    # (link_stubs.c, also pre-seeded) are left as they were.
    prior = list(stubbed or [])
    dropped: list[dict] = []
    if added and (new_c_stubs or prior):
        if global_vars is None:
            global_vars = _model_global_variables(dp)
        added_tree = {_dag_tree_path(a) for a in added}

        def _linked(name: str) -> bool:
            return any(_dag_tree_path(r["file"]) in added_tree for r in (global_vars or {}).get(name) or [])

        new_c_stubs = [s for s in new_c_stubs if not _linked(s["name"])]
        dropped = [s for s in prior if not s.get("bss") and _linked(s["name"])]
    prior_c = [s for s in prior if not s.get("bss") and s not in dropped]
    prior_bss = [s for s in prior if s.get("bss")]
    removed: set[str] = set()
    if (new_c_stubs or dropped) and stub_dir is not None:
        stub_file = stub_dir / LINK_GLOBALS_FILE
        if prior_c or new_c_stubs:
            stub_dir.mkdir(parents=True, exist_ok=True)
            stub_file.write_text(link_globals_source([*prior_c, *new_c_stubs]), encoding="utf-8", newline="\n")
            if stub_file.as_posix() not in have:
                have.add(stub_file.as_posix())
                added.append(stub_file.as_posix())
        else:
            # No global left to define: the file leaves the build.
            removed.add(stub_file.as_posix())
            with contextlib.suppress(OSError):
                stub_file.unlink()
    # A function is defined once too: a stub placed because no definer could be linked (`definers`:
    # several programs define it, or its file is excluded) goes when a file this round links in is
    # one of its definers, in either order. An address-flow cluster's stubs (no `definers`) stay.
    prior_fns = list(stubbed_functions or [])
    fn_dropped: list[dict] = []
    if added:
        added_tree = {_dag_tree_path(a) for a in added}

        def _fn_linked(stub: dict) -> bool:
            return any(d in added_tree for d in stub.get("definers") or [])

        new_fn_stubs = [s for s in new_fn_stubs if not _fn_linked(s)]
        fn_dropped = [s for s in prior_fns if _fn_linked(s)]
    kept_fns = [s for s in prior_fns if s not in fn_dropped]
    if (new_fn_stubs or new_bss_stubs or fn_dropped) and stub_dir is not None:
        fn_file = stub_dir / LINK_STUBS_FILE
        if kept_fns or new_fn_stubs or prior_bss or new_bss_stubs:
            stub_dir.mkdir(parents=True, exist_ok=True)
            fn_file.write_text(
                link_stubs_source([*kept_fns, *new_fn_stubs], [*prior_bss, *new_bss_stubs], module),
                encoding="utf-8",
                newline="\n",
            )
            if fn_file.as_posix() not in have:
                have.add(fn_file.as_posix())
                added.append(fn_file.as_posix())
        else:
            # No function or global left to define: the file leaves the build.
            removed.add(fn_file.as_posix())
            with contextlib.suppress(OSError):
                fn_file.unlink()
    new_stubs = [*new_c_stubs, *new_bss_stubs]
    changed = added or new_stubs or new_fn_stubs or dropped or fn_dropped
    info: dict = {"symbols": resolved, "added_sources": added} if changed else {}
    if new_stubs:
        info["stubbed_globals"] = new_stubs
    if new_fn_stubs:
        info["stubbed_functions"] = new_fn_stubs
    if dropped:
        info["unstubbed_globals"] = [s["name"] for s in dropped]
    if fn_dropped:
        info["unstubbed_functions"] = [s["name"] for s in fn_dropped]
    return [s for s in [*sources, *added] if s.replace("\\", "/") not in removed], info


# Where a run keeps its call graph; run-relative, as the Make recipes run in the run directory.
DEFAULT_DAG_PATH = Path("workspace/reports/callgraph_dag.json")


def default_dag_path(dag: Path | str | None = None) -> Path | None:
    """`dag` when given, else the run's DAG (DEFAULT_DAG_PATH) when it exists, else None: no link repair."""
    if dag is not None:
        return Path(dag)
    return DEFAULT_DAG_PATH if DEFAULT_DAG_PATH.is_file() else None


def repair_link_rounds(
    comp: dict,
    sources: list[str],
    rebuild,
    dag_path: Path | str | None,
    out_bin: Path,
    *,
    link_module: str | None = None,
    before_retry=None,
    initial_stubbed_functions: list[dict] | None = None,
    initial_stubbed_globals: list[dict] | None = None,
) -> tuple[dict, list[str], dict | None]:
    """
    The link repair of a module build whose first attempt `comp` (from `sources`) failed: while the
    build fails and a round of `repair_sources_for_link` changes the sources, `rebuild(sources)`
    compiles again (`before_retry(comp)` first, given the failed attempt). Linking takes whole files,
    so a file added for one symbol can need still more files: each round adds at least one file the
    DAG names or defines one global of the model, which bounds the rounds. A global of another link
    unit is defined in the generated `<out_bin>_link_globals/link_globals.c`; for an address-flow
    cluster, functions and globals outside its `flow_files` are stubbed in
    `<out_bin>_link_globals/link_stubs.c` (preserving any pre-seeded stubs).

    Returns (last compile, last sources, `link_repair` or None): `symbols` and `added_sources` over
    all rounds, `rounds` one entry each, and when there are any `stubbed_globals` with `globals_file`,
    `stubbed_functions` with `functions_file`,
    `unresolved_globals` and `missing_sources` (defining files that do not exist, never compiled).
    Nothing is tried without `dag_path` or when `comp` succeeded.
    """
    current = list(sources)
    rounds: list[dict] = []
    stub_dir = Path(out_bin).parent / f"{Path(out_bin).name}_link_globals"
    stubbed: list[dict] = list(initial_stubbed_globals or [])
    stubbed_fns: list[dict] = list(initial_stubbed_functions or [])
    round_stubbed: list[dict] = []
    round_stubbed_fns: list[dict] = []
    left: list[dict] = []
    missing_sources: list[dict] = []
    if comp["returncode"] != 0 and dag_path:
        sym_files = _dag_symbol_files(Path(dag_path))
        # Each round adds a file, or defines a global or (address-flow cluster) stubs a function.
        max_rounds = max(
            1, len(set(sym_files.values())) + len(_model_global_variables(Path(dag_path))) + len(sym_files)
        )
        while comp["returncode"] != 0 and len(rounds) < max_rounds:
            log = "\n".join(str(comp.get(k) or "") for k in ("stdout", "stderr"))
            current, info = repair_sources_for_link(
                current,
                log,
                dag_path,
                Path.cwd(),
                module=link_module,
                stub_dir=stub_dir,
                stubbed=stubbed,
                unresolved=left,
                missing=missing_sources,
                stubbed_functions=stubbed_fns,
            )
            if not info:
                break
            new_g = info.get("stubbed_globals", [])
            new_f = info.get("stubbed_functions", [])
            # A stub whose defining file a later round linked in is gone from the generated file.
            gone = set(info.get("unstubbed_globals") or [])
            stubbed = [s for s in stubbed if s["name"] not in gone]
            round_stubbed = [s for s in round_stubbed if s["name"] not in gone]
            gone_fns = set(info.get("unstubbed_functions") or [])
            stubbed_fns = [s for s in stubbed_fns if s["name"] not in gone_fns]
            round_stubbed_fns = [s for s in round_stubbed_fns if s["name"] not in gone_fns]
            stubbed += new_g
            stubbed_fns += new_f
            round_stubbed += new_g
            round_stubbed_fns += new_f
            rounds.append(info)
            if before_retry is not None:
                before_retry(comp)
            comp = rebuild(current)
    unresolved_globals = list({u["name"]: u for u in left}.values())
    if not (rounds or unresolved_globals or missing_sources):
        return comp, current, None
    record: dict = {
        "symbols": [sym for r in rounds for sym in r["symbols"]],
        # A file a later round took out again (an emptied link_globals.c) is no added source.
        "added_sources": [src for r in rounds for src in r["added_sources"] if src in current],
        "rounds": rounds,
    }
    if round_stubbed:
        record["stubbed_globals"] = round_stubbed
        if any(not g.get("bss") for g in round_stubbed):
            record["globals_file"] = (stub_dir / LINK_GLOBALS_FILE).as_posix()
        if any(g.get("bss") for g in round_stubbed):
            record["functions_file"] = (stub_dir / LINK_STUBS_FILE).as_posix()
    if round_stubbed_fns:
        record["stubbed_functions"] = round_stubbed_fns
        record["functions_file"] = (stub_dir / LINK_STUBS_FILE).as_posix()
    if unresolved_globals:
        record["unresolved_globals"] = unresolved_globals
    if missing_sources:
        record["missing_sources"] = missing_sources
    return comp, current, record


def build_coverage_binary(
    sources: list[str],
    out_bin: Path,
    cppflags: str = "-I.",
    ldflags_extra: str = "",
    *,
    use_cache: bool = True,
    dag_path: Path | str | None = None,
    link_module: str | None = None,
) -> dict:
    """
    The coverage build of a module (`compile_coverage_binary`) with the link repair of the fuzz builds
    (`repair_link_rounds`, driven by `dag_path`, globals placed for harness module `link_module`): the
    module's sources alone may not link (nginx run-5: ngx_core_module, ngx_modules and ngx_module_names
    live in src/core/nginx.c and the generated objs/ngx_modules.c). Returns {compile, sources} with
    `link_repair` after a repair and `preseeded_stubs` when an address-flow cluster pre-seeded
    `link_stubs.c`; `sources` is what was compiled last.
    """

    def _compile(srcs: list[str]) -> dict:
        return compile_coverage_binary(srcs, out_bin, cppflags, ldflags_extra, use_cache=use_cache)

    seeded_sources, preseeded, pre_fns, pre_globs = _preseed_flow_stubs(sources, dag_path, out_bin, link_module)
    comp = _compile(list(seeded_sources))
    comp, current, repair = repair_link_rounds(
        comp,
        seeded_sources,
        _compile,
        dag_path,
        out_bin,
        link_module=link_module,
        initial_stubbed_functions=pre_fns,
        initial_stubbed_globals=pre_globs,
    )
    result: dict = {"compile": comp, "sources": current}
    if preseeded is not None:
        result["preseeded_stubs"] = preseeded
    if repair is not None:
        result["link_repair"] = repair
    return result


def build_module_binary(
    sources: list[str],
    out_bin: Path,
    *,
    engine: str = "auto",
    selftest_json: Path | None = DEFAULT_SELFTEST_JSON,
    apply_selftest: bool = True,
    machdep: str = "gcc_x86_64",
    cppflags: str = "-I.",
    ldflags: str = "",
    rte: str = "all",
    functions: list[str] | None = None,
    variadic_translation: bool = True,
    warn_unsigned_downcast: bool = False,
    rte_initialized: bool = True,
    libc_checks: bool = True,
    use_cache: bool = True,
    dag_path: Path | str | None = None,
    link_module: str | None = None,
    security_props: str | None = None,
) -> dict:
    """
    Compile a module's fuzz binary the way a campaign does, without running it: E-ACSL for
    `eacsl`, and for `auto` unless a failed selftest for this Frama-C version blocks it; Clang
    ASan+UBSan for `sanitizers` and as the `auto` fallback. Both builds go through the cache.
    On a link failure with undefined references, repair rounds (`repair_link_rounds`, which the
    coverage build shares) append the defining sources (via
    `dag_path`) and relink while a round adds a file: linking takes whole files, so a file added
    for one symbol can need still more files. The rounds are bounded by the number of files the
    DAG names plus the globals the model lists, and recorded under `link_repair` (`symbols` and
    `added_sources` over all rounds, `rounds` one entry each).
    An undefined global variable is repaired from the model (`repair_sources_for_link`): its file
    when the link unit of harness module `link_module` defines it, else a zero-initialized
    definition in the generated `<out_bin>_link_globals/link_globals.c`, recorded under
    `link_repair` as `stubbed_globals` (name, type, file, units, definition, assumption) with
    `globals_file`: an assumption of the build, to show in the report. `unresolved_globals`
    (name, file, units, reason) lists the globals no rule could define, `missing_sources` the defining
    files that do not exist (a generated source Phase 0 did not keep), which are never compiled.
    Returns {compile, engine_used, engine_fallback_reason, eacsl_compile_attempt, sources}, where
    `sources` is what was compiled last (the input plus any repair). After a repair, `attempts` lists
    every attempt (engine, return code, reason, `killed`, the end of stderr, the E-ACSL attempt that
    fell back, and the earlier attempts' logs kept as `<log stem>.attempt<N>.log`).
    With `apply_selftest` False, the selftest result is not read: `auto` tries E-ACSL as `eacsl` does
    (D8). The campaign applies the selftest, and it restores these builds from the cache.
    `security_props` (`--security-props PATH|none`; None: $FRAMAC_SECURITY_PROPS, else
    workspace/reports/security_props.json) names the run's MetAcsl properties. When that file turns
    the `eacsl` engine on (`meta_engines`), the E-ACSL build checks them at run time
    (`resolve_security_meta`, per attempt: a link repair changes the sources) and its result carries
    `security_props`. The sanitizer build never does. Without `eacsl` in `meta_engines` nothing changes.
    """

    seeded_sources, preseeded, pre_fns, pre_globs = _preseed_flow_stubs(sources, dag_path, out_bin, link_module)
    effective_functions = (
        functions if functions is not None else _flow_cluster_functions(dag_path, link_module, seeded_sources)
    )
    sticky_fallback: list[tuple[dict | None, str | None]] = []
    # Previous attempt's (non-generated target sources, eacsl_attempt, fallback_reason, eacsl_had_undef):
    # if a link-repair round only writes/updates generated stub files without adding any target source,
    # re-running E-ACSL after a non-link Stage 1/2 failure cannot change the outcome.
    prev_eacsl_state: dict[str, Any] = {}

    def _attempt(srcs: list[str]) -> tuple[dict, dict | None, str | None]:
        eacsl_attempt = None
        fallback_reason = None
        comp = None
        non_gen = {s.replace("\\", "/") for s in srcs if not _is_generated_build_source(s)}
        if (
            not sticky_fallback
            and prev_eacsl_state
            and not prev_eacsl_state["had_undef"]
            and non_gen == prev_eacsl_state["non_gen"]
        ):
            sticky_fallback.append((prev_eacsl_state["attempt"], prev_eacsl_state["reason"]))
        if sticky_fallback:
            eacsl_attempt, fallback_reason = sticky_fallback[0]
        elif engine in ("auto", "eacsl"):
            blocked = selftest_blocks_eacsl(selftest_json) if engine == "auto" and apply_selftest else None
            if blocked:
                fallback_reason = blocked
                sticky_fallback.append((None, fallback_reason))
            else:
                meta = resolve_security_meta(security_props, srcs, Path(out_bin))
                # Only when the run's properties are on: the call of a run without them is today's.
                meta_kwargs: dict[str, Any] = {"security_meta": meta} if meta is not None else {}
                comp = compile_eacsl_binary(
                    srcs,
                    out_bin,
                    machdep,
                    cppflags,
                    rte,
                    True,
                    functions=effective_functions,
                    ldflags_extra=ldflags,
                    variadic_translation=variadic_translation,
                    warn_unsigned_downcast=warn_unsigned_downcast,
                    rte_initialized=rte_initialized,
                    libc_checks=libc_checks,
                    use_cache=use_cache,
                    **meta_kwargs,
                )
                if comp["returncode"] != 0 and engine == "auto":
                    eacsl_attempt = comp
                    fallback_reason = comp.get("reason") or "eacsl_compile_failed"
                    eacsl_log = "\n".join(str(comp.get(k) or "") for k in ("stdout", "stderr"))
                    had_undef = bool(parse_undefined_references(eacsl_log))
                    prev_eacsl_state.update(
                        non_gen=non_gen, attempt=eacsl_attempt, reason=fallback_reason, had_undef=had_undef
                    )
                    if not had_undef and comp.get("reason") in ("eacsl_compile_failed", "eacsl_build_timeout"):
                        # Stage 2 C compile error (no undefined references) or build timeout:
                        # link repair for the sanitizer fallback cannot fix E-ACSL.
                        sticky_fallback.append((eacsl_attempt, fallback_reason))
                    comp = None
        if comp is None:
            comp = compile_sanitizer_binary(srcs, out_bin, cppflags, True, ldflags_extra=ldflags, use_cache=use_cache)
        return comp, eacsl_attempt, fallback_reason

    attempts: list[dict] = []

    def _note(comp: dict, eacsl_attempt: dict | None, fallback_reason: str | None, srcs: list[str]) -> None:
        # What this attempt did, kept when a later one replaces `compile` and `eacsl_compile_attempt`.
        rec: dict[str, Any] = {
            "attempt": len(attempts) + 1,
            "sources": len(srcs),
            "engine_used": comp.get("engine", engine),
            "returncode": comp.get("returncode"),
        }
        if comp.get("returncode") != 0:
            rec.update(_attempt_failure(comp))
        if eacsl_attempt is not None:
            rec["eacsl"] = {"returncode": eacsl_attempt.get("returncode"), **_attempt_failure(eacsl_attempt)}
        if fallback_reason:
            rec["engine_fallback_reason"] = fallback_reason
        attempts.append(rec)

    def _keep_logs(*results: dict | None) -> None:
        # The next attempt rewrites the same logs: the last attempt's are kept under an attempt number.
        rec = attempts[-1]
        kept: list[str] = []
        for res in results:
            log = Path(str((res or {}).get("compile_log") or ""))
            if not log.name or not log.is_file():
                continue
            dest = log.with_name(f"{log.stem}.attempt{rec['attempt']}{log.suffix}")
            with contextlib.suppress(OSError):
                shutil.copyfile(log, dest)
                kept.append(dest.as_posix())
        if kept:
            rec["logs"] = kept

    last: dict[str, Any] = {}

    def _noted_attempt(srcs: list[str]) -> dict:
        comp, eacsl_attempt, fallback_reason = _attempt(srcs)
        _note(comp, eacsl_attempt, fallback_reason, srcs)
        last.update(eacsl_attempt=eacsl_attempt, fallback_reason=fallback_reason)
        return comp

    comp = _noted_attempt(list(seeded_sources))
    comp, current, link_repair = repair_link_rounds(
        comp,
        seeded_sources,
        _noted_attempt,
        dag_path,
        out_bin,
        link_module=link_module,
        before_retry=lambda failed: _keep_logs(failed, last["eacsl_attempt"]),
        initial_stubbed_functions=pre_fns,
        initial_stubbed_globals=pre_globs,
    )
    eacsl_attempt, fallback_reason = last["eacsl_attempt"], last["fallback_reason"]
    result = {
        "compile": comp,
        "engine_used": comp.get("engine", engine),
        "engine_fallback_reason": fallback_reason,
        "eacsl_compile_attempt": eacsl_attempt,
        "sources": current,
    }
    if preseeded is not None:
        result["preseeded_stubs"] = preseeded
    if len(attempts) > 1:
        # `compile` and `eacsl_compile_attempt` are the last attempt's; each earlier failure stays here
        # (nginx run-3: an OOM-killed first E-ACSL attempt was reported as the retry's failure).
        result["attempts"] = attempts
    if link_repair is not None:
        result["link_repair"] = link_repair
    return result


# A diagnostic Frama-C prints when it stops on its own (`[kernel] User Error`, `[e-acsl] Failure`,
# `[kernel:annot-error]`, an uncaught OCaml exception, OCaml's own `Out of memory`).
# Excludes `[kernel] Parsing <path>` progress lines so filenames like `src/error.c` do not mask a kill.
_FRAMAC_DIAGNOSTIC_RE = re.compile(
    r"^\[[\w.:-]*error[\w.:-]*\]"
    r"|^\[[\w.:-]+\](?!\s+Parsing\b)[^\n]*\b(?:Error|Failure|error)\b"
    r"|^Fatal error|Unexpected error|Stack overflow|Out of memory",
    re.MULTILINE,
)


def _detect_stage_kill(rc: int | None, stdout: str, stderr: str) -> str | None:
    """
    Classify whether an E-ACSL build stage was externally killed (typically cgroup OOM):
    - `killed`: SIGKILL seen directly (return code 137 or -9, or a `Killed` line near the end).
    - `killed_suspected`: `e-acsl-gcc` stopped with `aborted by Frama-C` and Frama-C printed no
      diagnostic of its own (`e-acsl-gcc` exits 1 whatever Frama-C's status, and bash prints no
      `Killed` for a process killed inside `$(...)`).
    - None: normal failure (or not a kill).
    """
    text = f"{stdout}\n{stderr}"
    if rc in (-9, 137) or any("Killed" in line for line in text.splitlines()[-8:]):
        return "killed"
    if "aborted by Frama-C" in text and not _FRAMAC_DIAGNOSTIC_RE.search(text):
        return "killed_suspected"
    return None


def _attempt_failure(comp: dict) -> dict:
    """
    The failure of one build attempt as a report keeps it: reason, a killed process, the end of stderr.
    `killed`: SIGKILL seen directly (return code 137 or -9, a `Killed` line). `killed_suspected`: E-ACSL
    stopped with `aborted by Frama-C` and Frama-C printed no diagnostic of its own. e-acsl-gcc exits 1
    whatever Frama-C's status, and bash prints no `Killed` for a process killed inside `$(...)`, so an
    out-of-memory kill (nginx run-3: Frama-C at 8.7 GB, docker `oom` event) shows only that way.
    """
    out: dict[str, Any] = {}
    if comp.get("reason"):
        out["reason"] = comp["reason"]
    rc = comp.get("returncode")
    stderr = str(comp.get("stderr") or "")
    kill_kind = _detect_stage_kill(rc, str(comp.get("stdout") or ""), stderr)
    if comp.get("killed") or kill_kind == "killed":
        out["killed"] = True
    elif comp.get("killed_suspected") or kill_kind == "killed_suspected":
        out["killed_suspected"] = True
    if stderr.strip():
        out["stderr_tail"] = stderr[-1500:]
    if comp.get("compile_log"):
        out["compile_log"] = str(comp["compile_log"])
    return out


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
