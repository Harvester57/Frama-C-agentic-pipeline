"""
Building the fuzz binaries of one module: the E-ACSL build (with its cache), the sanitizer and coverage
builds, the selftest result that gates E-ACSL, the link repair of the sources, and build_module_binary, which
both the build subcommand and the campaign call (D3, moved out of run_eacsl_fuzz).

Callers reach these functions as `fuzz_build.<name>` (D12), so a test patch on this module applies to every
caller. No module here imports run_eacsl_fuzz.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path

import cache
import fc_cpp_wrapper_eacsl
import target_env
from c_definitions import TYPE_MODIFIERS_AND_PRIMITIVES, extract_functions_from_code
from eacsl_toolchain import (
    EACSL_FC_EXTRA_FLAGS,
    EACSL_FORMAT_RUNTIME_PATCH,
    EACSL_FULL_MTRACKING_DEFINES,
    EACSL_GCC_CHECK_OPTIONS,
    EACSL_HEAP_ZONE_MB,
    EACSL_NO_LIBC_CHECKS,
    EACSL_RTE_INITIALIZED_FLAG,
    UnsafePassthroughError,
    attribute_ignored_annotations,
    build_eacsl_flag_sets,
    build_errno_shim_object,
    build_fallback_object,
    defines_fuzzer_initialize,
    eacsl_share_dir,
    eacsl_zone_size_options,
    fix_readonly_scalar_globals,
    generate_errno_shim_source,
    is_eacsl_instrumented,
    mark_formals_initialized,
    mark_wrapper_results_initialized,
    normalize_passthrough,
    order_literal_registrations,
    parse_ignored_annotations,
    parse_missing_functions,
    parse_undefined_fallbacks,
    prepare_patched_eacsl_share,
    preprocess_source,
    reset_verdict_on_input_entry,
    resolve_fuzz_init_source,
    rewrite_sound_verdict_resets,
    rewrite_trailing_alignas,
    select_eacsl_binary,
    skip_va_list_initialized_checks,
    slice_has_pthread,
    uses_full_mtracking,
)
from failure_identity import is_harness_fuzz_function
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
    libc_checks: bool = True,
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
        # The generated libc shim is linked into the binary, and no source or flag says when its text changes.
        "libc_shim": hashlib.sha256(generate_errno_shim_source(["close"]).encode("utf-8")).hexdigest(),
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
            libc_checks=libc_checks,
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
            libc_checks=libc_checks,
        )
    if material is None:
        res = _build()
        res["cache"] = {"hit": False, "key": None}
        return res

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
    libc_checks: bool = True,
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
    `wrapper_result_inits`, `formal_inits`, ...). Uninitialized reads are checked (`-rte-initialized @all`)
    unless `rte_initialized` is False, which is recorded in `reduced_checks`. Stage 1 is retried
    once without functions Frama-C reports as unknown; stage 2 is retried once with a generated
    link-only object when Variadic `<fn>_fallback_<N>` symbols are undefined.
    When the slice reads errno (the fc_stubs/errno.h global) and calls libc functions that set it,
    stage 2 also links the generated errno shim (`errno_shim`: wrapped functions, or `failed`).
    On success the result's `binary` is the E-ACSL-instrumented executable (`<out>.e-acsl` when
    present) and is guaranteed to contain E-ACSL instrumentation.

    E-ACSL does not fail on an annotation it cannot translate: it warns (`... Ignoring annotation.`)
    and generates no check. The result lists them in `ignored_annotations`, each with the function it
    belongs to when that can be read from the sources (eacsl_toolchain.attribute_ignored_annotations),
    and counts the ignored `assigns` clauses, which E-ACSL never checks, in `ignored_frame_clauses`.
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
                *check_options,
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
        _note_const_unions(out, err)  # the last frontend run only: a retry preprocesses the same files again
        frontend.update(output=out + "\n" + err, instrumented=rc == 0 and instrumented_c.is_file())
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
    """
    sources = compile_inputs(sources)
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
    file, type, units). The DAG does not carry them. Empty without a model, and for the units on
    the GCC fallback, whose globals the model does not list.
    """
    model = load_json_optional(Path(dag_path).parent / "phase0_model.json", None)
    records = model.get("global_variables") if isinstance(model, dict) else None
    out: dict[str, list[dict]] = {}
    for key, rec in sorted(records.items()) if isinstance(records, dict) else []:
        if not isinstance(rec, dict) or rec.get("static"):
            continue
        name = str(rec.get("name") or str(key).split("#")[-1])
        file = rec.get("file") or (str(key).rpartition("#")[0] if "#" in str(key) else "")
        if name and file:
            units = [str(u) for u in rec.get("units") or []] if isinstance(rec.get("units"), list) else []
            out.setdefault(name, []).append(
                {"name": name, "file": str(file), "type": str(rec.get("type") or ""), "units": units}
            )
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


def _declaring_header(name: str, run_dir: Path) -> tuple[Path, str] | None:
    """
    The project header (workspace/work) with an `extern` declaration of global `name`, shortest path
    first, and the definition to write after including it: the declaration itself without `extern`,
    so with its qualifiers and typedef names (`extern volatile int G;` gives `volatile int G;`).
    `__typeof__(G) G;` would not do: Frama-C 35 drops a top-level `volatile` there and then refuses
    the definition (`different qualifiers`). It is used only for a declaration of several variables,
    whose text would define the others too.
    """
    work = Path(run_dir) / "workspace/work"
    if not work.is_dir():
        return None
    decl = re.compile(rf"^[ \t]*extern\b([^;{{}}()]*\b{re.escape(name)}\b\s*(?:\[[^;]*\]\s*)*);", re.MULTILINE)
    for header in sorted(work.rglob("*.h"), key=lambda p: (len(p.parts), p.as_posix())):
        try:
            text = header.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        m = decl.search(text) if name in text else None
        if m:
            own = " ".join(m.group(1).split())
            return header, (f"__typeof__({name}) {name};" if "," in own else f"{own};")
    return None


def link_globals_source(stubs: list[dict]) -> str:
    """The generated definitions file for the globals link repair stands in for (`stubbed_globals`)."""
    includes = dict.fromkeys(f'#include "{s["include"]}"' for s in stubs if s.get("include"))
    tags = dict.fromkeys(
        f"{kw} {tag};" for s in stubs if not s.get("include") for kw, tag in _GLOBAL_TAG_RE.findall(s["type"])
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


def _dag_tree_path(path: str) -> str:
    p = str(path).replace("\\", "/")
    for prefix in ("/framac-run/", "/target/", "./"):
        if p.startswith(prefix):
            p = p[len(prefix) :]
    return p[len("workspace/work/") :] if p.startswith("workspace/work/") else p


def _link_unit_context(dag_path: Path, module: str | None) -> dict:
    """
    What placing a global needs from the DAG: the link unit record of harness module `module`
    (`unit`: None without link units, without a module, or for a module the DAG and the sidecars
    do not place, as `ModuleMap.unit_of` answers), that unit's sources (`unit_files`: its own and
    those of the project libraries it links) and the files defining a `main` (`main_files`).
    """
    from module_map import ModuleMap, load_sidecars

    dag = load_json_optional(Path(dag_path), None)
    mm = ModuleMap(dag if isinstance(dag, dict) else None, load_sidecars(Path(dag_path).parent.parent / "harnesses"))
    unit: dict | None = None
    if module and mm.units_are_link_units:
        rec = mm.modules.get(mm.unit_of(module))
        unit = rec if isinstance(rec, dict) else None
    files = [*((unit or {}).get("files") or []), *((unit or {}).get("required_sources") or [])]
    return {
        "unit": unit,
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
    """
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
) -> tuple[list[str], dict]:
    """
    One link-repair round: map `undefined reference to 'X'` symbols to their
    defining sources via the DAG and append the missing files. Returns (sources, info).

    A symbol that is no function of the DAG is looked up among the model's global variables
    (`_model_global_variables`). One defined in the link unit of harness module `module` adds
    its file like a function. One defined in another link unit is defined, zero-initialized, in
    the generated `stub_dir`/link_globals.c (rewritten with those of the earlier rounds,
    `stubbed`), which joins the sources: with the type of its `extern` declaration in a project
    header the file includes (`declared_in`, `include`: the declaration keeps the qualifiers), else,
    when no header declares it, from the model's type text (`global_definition_text`). `info["stubbed_globals"]` lists
    the new ones (name, type, file, units, definition, assumption). The globals left undefined
    are appended to `unresolved` (name, file, units, reason), not to `info`, which stays empty
    for a round that repaired nothing.
    """
    syms = parse_undefined_references(log)
    if not syms or not dag_path:
        return list(sources), {}
    sym_files = _dag_symbol_files(Path(dag_path))
    have = {s.replace("\\", "/") for s in sources}
    added: list[str] = []
    resolved: list[str] = []
    new_stubs: list[dict] = []
    known_stubs = {s["name"] for s in stubbed or []}
    global_vars: dict[str, list[dict]] | None = None
    ctx: dict = {}
    for sym in syms:
        f = sym_files.get(sym)
        if not f:
            if global_vars is None:
                global_vars = _model_global_variables(Path(dag_path))
            if sym not in global_vars or sym in known_stubs:
                continue
            ctx = ctx or _link_unit_context(Path(dag_path), module)
            action, rec, reason = _place_global(global_vars[sym], ctx)
            if action == "stub" and stub_dir is None:
                action, reason = "unresolved", "another link unit defines it and no build directory was given"
            elif action == "stub" and stub_dir is not None:
                stub = {**rec, "assumption": LINK_GLOBALS_ASSUMPTION}
                # The header that declares it comes first: it has the types and the qualifiers the
                # model's type text drops. A plain `int G;` next to another stub's header declaring
                # `extern volatile int G;` does not compile (checked with clang 19 and Frama-C 35).
                declared = _declaring_header(sym, Path(run_dir))
                header = declared[0] if declared else None
                definition, reason = (declared[1], "") if declared else global_definition_text(sym, rec["type"])
                if header is not None:
                    stub["declared_in"] = header.relative_to(Path(run_dir)).as_posix()
                    stub["include"] = Path(os.path.relpath(header.resolve(), stub_dir.resolve())).as_posix()
                if definition is None:
                    action, reason = "unresolved", f"{reason}, and no header of the project declares it"
                else:
                    new_stubs.append({**stub, "definition": definition})
                    resolved.append(sym)
                    continue
            if action == "unresolved":
                if unresolved is not None:
                    unresolved.append({"name": sym, "file": rec["file"], "units": rec["units"], "reason": reason})
                continue
            f = rec["file"]
        norm = _normalize_dag_source(f, Path(run_dir))
        if norm not in have:
            have.add(norm)
            added.append(norm)
            resolved.append(sym)
    if new_stubs and stub_dir is not None:
        stub_dir.mkdir(parents=True, exist_ok=True)
        stub_file = stub_dir / LINK_GLOBALS_FILE
        stub_file.write_text(link_globals_source([*(stubbed or []), *new_stubs]), encoding="utf-8", newline="\n")
        if stub_file.as_posix() not in have:
            added.append(stub_file.as_posix())
    info: dict = {"symbols": resolved, "added_sources": added} if added or new_stubs else {}
    if new_stubs:
        info["stubbed_globals"] = new_stubs
    return [*sources, *added], info


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
) -> dict:
    """
    Compile a module's fuzz binary the way a campaign does, without running it: E-ACSL for
    `eacsl`, and for `auto` unless a failed selftest for this Frama-C version blocks it; Clang
    ASan+UBSan for `sanitizers` and as the `auto` fallback. Both builds go through the cache.
    On a link failure with undefined references, repair rounds append the defining sources (via
    `dag_path`) and relink while a round adds a file: linking takes whole files, so a file added
    for one symbol can need still more files. The rounds are bounded by the number of files the
    DAG names plus the globals the model lists, and recorded under `link_repair` (`symbols` and
    `added_sources` over all rounds, `rounds` one entry each).
    An undefined global variable is repaired from the model (`repair_sources_for_link`): its file
    when the link unit of harness module `link_module` defines it, else a zero-initialized
    definition in the generated `<out_bin>_link_globals/link_globals.c`, recorded under
    `link_repair` as `stubbed_globals` (name, type, file, units, definition, assumption) with
    `globals_file`: an assumption of the build, to show in the report. `unresolved_globals`
    (name, file, units, reason) lists the globals no rule could define.
    Returns {compile, engine_used, engine_fallback_reason, eacsl_compile_attempt, sources}, where
    `sources` is what was compiled last (the input plus any repair).
    With `apply_selftest` False, the selftest result is not read: `auto` tries E-ACSL as `eacsl` does
    (D8). The campaign applies the selftest, and it restores these builds from the cache.
    """

    def _attempt(srcs: list[str]) -> tuple[dict, dict | None, str | None]:
        eacsl_attempt = None
        fallback_reason = None
        comp = None
        if engine in ("auto", "eacsl"):
            blocked = selftest_blocks_eacsl(selftest_json) if engine == "auto" and apply_selftest else None
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
                    libc_checks=libc_checks,
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
    stub_dir = Path(out_bin).parent / f"{Path(out_bin).name}_link_globals"
    stubbed: list[dict] = []
    left: list[dict] = []
    if comp["returncode"] != 0 and dag_path:
        # Each round adds at least one file the DAG names or defines one global of the model, so
        # this many rounds always suffice.
        max_rounds = max(
            1,
            len(set(_dag_symbol_files(Path(dag_path)).values())) + len(_model_global_variables(Path(dag_path))),
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
            )
            if not info:
                break
            stubbed += info.get("stubbed_globals", [])
            rounds.append(info)
            comp, eacsl_attempt, fallback_reason = _attempt(current)
    result = {
        "compile": comp,
        "engine_used": comp.get("engine", engine),
        "engine_fallback_reason": fallback_reason,
        "eacsl_compile_attempt": eacsl_attempt,
        "sources": current,
    }
    unresolved_globals = list({u["name"]: u for u in left}.values())
    if rounds or unresolved_globals:
        result["link_repair"] = {
            "symbols": [sym for r in rounds for sym in r["symbols"]],
            "added_sources": [src for r in rounds for src in r["added_sources"]],
            "rounds": rounds,
        }
        if stubbed:
            result["link_repair"]["stubbed_globals"] = stubbed
            result["link_repair"]["globals_file"] = (stub_dir / LINK_GLOBALS_FILE).as_posix()
        if unresolved_globals:
            result["link_repair"]["unresolved_globals"] = unresolved_globals
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
