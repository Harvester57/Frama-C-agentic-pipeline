#!/usr/bin/env python3
"""
E-ACSL toolchain contract helpers used by run_eacsl_fuzz.py.

`e-acsl-gcc` (Frama-C 33+) splits the values of `-e`, `-E`, `-F` and `-l` on
whitespace and re-parses the resulting tokens, so a standalone `-g` inside
`-e` silently becomes `--gmp` (`-e-acsl-gmp-only`), and paths containing
spaces break. This module enforces the invocation contract:

  - `normalize_passthrough()` joins separated short options (`-I dir` ->
    `-Idir`), rewrites `-g` to `-gline-tables-only`, and rejects any other
    standalone single-letter token or whitespace-containing token;
  - `build_eacsl_flag_sets()` keeps preprocessor flags (`-I`, `-D`, `-include`,
    fc_stubs) on the Frama-C frontend only, and gives the backend compile of
    the self-contained instrumented C file codegen flags only;
  - `select_eacsl_binary()` / `is_eacsl_instrumented()` guarantee that a run
    labelled `engine=eacsl` actually executes an E-ACSL-instrumented binary;
  - `resolve_fuzz_init_source()` / `defines_fuzzer_initialize()` supply the
    `LLVMFuzzerInitialize` hook that initializes the E-ACSL runtime, which a
    main-less libFuzzer target never does on its own;
  - `find_variadic_fallbacks()` / `generate_fallback_source()` define the
    `<fn>_fallback_<N>` symbols the Variadic translation emits for variadic
    calls without a libc specification, in a link-only object that never
    enters the instrumented sources (so the fallback numbering stays stable);
  - `find_errno_shim_calls()` / `build_errno_shim_object()` link `-Wl,--wrap`
    wrappers that copy libc's errno into the global fc_stubs/errno.h maps
    `errno` to, so the target sees the errno a libc call set; the same wrappers
    tell the E-ACSL runtime what the call wrote (`EACSL_LIBC_EFFECTS`).
"""

from __future__ import annotations

import hashlib
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from framac_common import framac_cpp_wrapper, is_pre_c99_std, resolve_fc_stubs_dir, stub_overlay_dir  # noqa: E402
from patterns import FUZZER_INIT_DEF_RE  # noqa: E402

# Frama-C has no 128-bit integer type, and host headers such as <linux/types.h> declare
# `__int128` typedefs only when the compiler predefines __SIZEOF_INT128__.
# glibc's <math.h> expands isnan, isinf, isfinite, isnormal and fpclassify to GCC builtins unless
# __SUPPORT_SNAN__ is defined; Frama-C does not know the builtins and prints K&R prototypes for them,
# which clang refuses ("cannot redeclare builtin function '__builtin_isnan'", QCBOR run-4). With it,
# glibc calls __isnan, __isinf, __finite, __fpclassify. signbit is mapped by EACSL_STUBS_SUBDIR's math.h.
EACSL_DEFINES = ("-D__FRAMAC_EACSL__", "-D_Float128=double", "-U__SIZEOF_INT128__", "-D__SUPPORT_SNAN__")
# Header shims for the E-ACSL frontend only (templates/fc_stubs/eacsl): first on its include path after the run's stub overlay,
# never on the Eva/WP path (which gets templates/fc_stubs itself) nor on the backend compile.
EACSL_STUBS_SUBDIR = "eacsl"
# gcc `-wrapper` of the E-ACSL frontend: fc_cpp_wrapper.py plus the `<==>` rewrite.
EACSL_CPP_WRAPPER = Path(__file__).resolve().parent / "fc_cpp_wrapper_eacsl.py"
EACSL_CODEGEN_FLAGS = ("-gline-tables-only", "-O1", "-fcommon", "-Wno-implicit-function-declaration")
# Fuzz harnesses have no main(), so E-ACSL's memory analysis cannot see the entry point and
# leaves stack blocks untracked (valid accesses through a callee then fail `\valid`). Full
# tracking fixes that; it needs the runtime initialized by templates/eacsl_runtime/fuzz_init.c.
# Failure reports print the values involved by default (-e-acsl-O-print-values, on at O <= 3).
# Never pass the deprecated -e-acsl-assert-print-data: Frama-C 34+ aliases it to -e-acsl-O-valid,
# which re-instruments proven annotations (docs/upstream/frama-c/frama-c-eacsl-assert-print-data-alias.md).
EACSL_FULL_MTRACKING_FLAG = "-e-acsl-full-mtracking"
EACSL_FC_EXTRA_FLAGS = (EACSL_FULL_MTRACKING_FLAG,)
# e-acsl-gcc options passed to both stages of the two-stage CLI (Frama-C 33+):
# --libc-replacements (-e-acsl-replace-libc-functions) checks the buffers of memcpy, memmove, memset,
#   strcpy, strncpy, strcat, strncat, strlen, strcmp, strncmp, strdup and strndup; RTE emits nothing for
#   libc calls, so their overflows, overlaps and unterminated strings were missed.
# --validate-format-strings (-e-acsl-validate-format-strings at stage 1, -DE_ACSL_VALIDATE_FORMAT_STRINGS
#   at stage 2, so both stages need it) checks printf-family directives against their arguments.
# Both abort with a bare `<function>: <message>` line and no location (parse_eacsl_failure reads them).
# 2026-11-14 trial: 2/9 seeded defects caught without them; 8/9 and about +10% run time with them,
# derived from per-flag runs (docs/plans/frama-c-34-option-review.md). Under clang the format runtime needs EACSL_CODEGEN_FLAGS'
# -O1 and -Wno-implicit-function-declaration (docs/upstream/frama-c/frama-c-eacsl-gcc-clang-cflags.md).
# Not --temporal: it aborts on any call that passes a function's address under full tracking
# (docs/upstream/frama-c/frama-c-eacsl-temporal-function-address-argument.md).
EACSL_GCC_CHECK_OPTIONS = ("--libc-replacements", "--validate-format-strings")
# Size in MiB of the program heap E-ACSL's segment model tracks: `e-acsl-gcc --zone-sizes heap:<N>`
# at stage 2, which compiles the runtime with -DE_ACSL_HEAP_SIZE=<N> (share/e-acsl/observation_model/
# segment_model/e_acsl_shadow_layout.h; the upstream default is 128). A larger allocation aborts the
# runtime with "Exceeded heap allocation limit of <N>MB": E-ACSL's limit, not a target defect
# (failure_identity.parse_eacsl_resource_abort). A target that allocates a size read from its input
# (mpack's *_alloc APIs, mpack run-3) hit 128 on legitimate inputs.
# Result-deciding, so fixed, never sized from the machine. Measured in framac-analysis (2026-11-17,
# docs/troubleshooting/eacsl-and-fuzzing.md): the runtime writes the heap shadow of a block when it
# is allocated, so each tracked MiB costs about one MiB of RSS (a one-byte touch of a 64 MiB block:
# 55 -> 126 MB max RSS; of a 1000 MiB block: 1.2 GB), while the zone itself is reserved address
# space only (no RLIMIT_AS, see sandbox_exec.py); startup RSS and throughput did not change from 128.
# 1024 keeps the largest tracked block plus its shadow inside the fixed -rss_limit_mb of 2048
# (resources.FUZZ_RSS_LIMIT_MB; measured: 1.2 GB max RSS for a 1000 MiB block). A calloc'd one (block,
# shadow and init shadow all written) comes to about 2.2 GB by computation, not measured: inside the
# 1.25x per-worker sizing, where libFuzzer's RSS check should report an oom- artifact. The time spent
# writing the shadow of a 500-1000 MiB block against the per-input timeout is not measured yet. A
# larger block aborts in the runtime as before. 2048 itself is not possible (measured: exit 139 at
# startup on every input); the cause is inferred from the source: the runtime computes
# `E_ACSL_HEAP_SIZE * MB` in `int`, which overflows at 2048. 2047 is untested.
EACSL_HEAP_ZONE_MB = 1024
_EACSL_MIN_HEAP_ZONE_MB = 64  # e-acsl-gcc's MIN_HEAP
_EACSL_MAX_HEAP_ZONE_MB = 2047  # E_ACSL_HEAP_SIZE * MB is an int product in the runtime


def eacsl_zone_size_options(heap_mb: int | None = None) -> list[str]:
    """`e-acsl-gcc` stage-2 options that size the runtime's tracked heap (EACSL_HEAP_ZONE_MB)."""
    mb = EACSL_HEAP_ZONE_MB if heap_mb is None else int(heap_mb)
    if not _EACSL_MIN_HEAP_ZONE_MB <= mb <= _EACSL_MAX_HEAP_ZONE_MB:
        raise ValueError(
            f"E-ACSL heap zone {mb} MiB is outside [{_EACSL_MIN_HEAP_ZONE_MB}, {_EACSL_MAX_HEAP_ZONE_MB}] "
            "(e-acsl-gcc's minimum; the runtime's int product E_ACSL_HEAP_SIZE * MB overflows at 2048)"
        )
    return ["--zone-sizes", f"heap:{mb}"]


# The `reduced_checks` entry of a build without them (`--no-libc-checks`). E-ACSL does not track memory
# libc allocates itself (`strerror`'s buffer), so `fprintf(f, "%s", strerror(e))` or `strncpy(d,
# strerror(e), n)` aborts as unallocated: a module whose seeds stop on such a call fuzzes without them.
EACSL_NO_LIBC_CHECKS = "-no-libc-checks"
# --validate-format-strings compares each directive's type with the argument's static type exactly
# (validate_format_type in share/e-acsl/libc_replacements/e_acsl_stdio.c). An `unsigned char` or
# `unsigned short` argument is promoted to `int`, so `snprintf(b, n, "%u", byte)` aborts on every
# input ("directive 1 ('%u') expects argument of type 'unsigned int' but the corresponding argument
# has type 'int'"; c-ares inet_ntop4, run-1 2026-11-16), and so does `"%d"` with a small `unsigned`.
# C11 7.16.1.1p2 (va_arg, how a libc reads these arguments) accepts the signed and unsigned types of
# one rank when the value is representable in both, the rule 6.5.2.2p6 also gives calls without a
# prototype; 7.21.6.1p9 has no such exception, but gcc and clang -Wformat do not warn and glibc agrees. The runtime sees only static types
# (fmtdesc), so the pipeline compiles it from a run-local copy of the share directory whose
# validate_format reads each argument's value and skips the comparison for such a pair: a negative
# `int` for "%u" or an `unsigned` above INT_MAX for "%d" still aborts with the runtime's own message.
# The same copy fixes how validate_format collects the arguments: it read every one with
# `va_arg(ap, void *)`, so after a `double` (passed in an SSE register on x86_64) or a `long double`
# (on the stack) the pointer of a later "%s", "%p" or "%n" came from the wrong slot
# (`snprintf(b, n, "%f %s", 1.5, s)` aborts with "attempt to access unallocated memory via directive 2").
# Stage 2 only (`--e-acsl-share`); upstream draft: docs/upstream/frama-c/frama-c-eacsl-format-promoted-argument-signedness.md.
EACSL_FORMAT_RUNTIME_PATCH = "format-runtime-1"
_EACSL_STDIO_REL = "libc_replacements/e_acsl_stdio.c"
_FMT_PATCH_TAG = f"framac-pipeline patch ({EACSL_FORMAT_RUNTIME_PATCH})"
_FMT_VALUES_BLOCK = f"""\
  /* {_FMT_PATCH_TAG}: read each argument with its own promoted
     type, per fmtdesc, and record whether an integer value is representable in both the signed
     and the unsigned type of its rank. An unknown type leaves that argument and the rest strict. */
  signed char fc_both[arglen > 0 ? arglen : 1];
  {{
    va_list fc_ap;
    int fc_k;
    va_copy(fc_ap, ap);
    for (fc_k = 0; fc_k < arglen; fc_k++) {{
      fc_both[fc_k] = 0;
      switch (fmtdesc[fc_k]) {{
      case 'c':
      case 'h':
      case 'd': {{
        int v = va_arg(fc_ap, int);
        fc_both[fc_k] = v >= 0;
        break;
      }}
      case 'C':
      case 'H':
      case 'D': {{
        unsigned int v = va_arg(fc_ap, unsigned int);
        fc_both[fc_k] = v <= (~0u >> 1);
        break;
      }}
      case 'l': {{
        long v = va_arg(fc_ap, long);
        fc_both[fc_k] = v >= 0;
        break;
      }}
      case 'L': {{
        unsigned long v = va_arg(fc_ap, unsigned long);
        fc_both[fc_k] = v <= (~0ul >> 1);
        break;
      }}
      case 'r': {{
        long long v = va_arg(fc_ap, long long);
        fc_both[fc_k] = v >= 0;
        break;
      }}
      case 'R': {{
        unsigned long long v = va_arg(fc_ap, unsigned long long);
        fc_both[fc_k] = v <= (~0ull >> 1);
        break;
      }}
      case 'f':
      case 'e':
        (void)va_arg(fc_ap, double);
        break;
      case 'E':
        (void)va_arg(fc_ap, long double);
        break;
      case 's':
      case 'S':
      case 'q':
      case 'Q':
      case 'i':
      case 'I':
      case 'z':
      case 'Z':
      case 'w':
      case 'W':
      case 'p':
        (void)va_arg(fc_ap, void *);
        break;
      default:
        goto fc_strict;
      }}
    }}
  fc_strict:
    for (; fc_k < arglen; fc_k++)
      fc_both[fc_k] = 0;
    va_end(fc_ap);
  }}
"""
_FMT_HELPER = f"""\
/* {_FMT_PATCH_TAG}: 1 when the directive's type and the
   argument's type are the signed and unsigned types of one integer rank and the argument's value
   is representable in both (C11 7.16.1.1p2); `both` holds that per argument. */
static int fc_signedness_only(abbrev_t expected_t, abbrev_t actual_t,
                              const signed char *both, int idx) {{
  if (expected_t == actual_t)
    return 0;
  switch (expected_t) {{
  case IInt:
  case IUInt:
    if (actual_t != IInt && actual_t != IUInt)
      return 0;
    break;
  case ILong:
  case IULong:
    if (actual_t != ILong && actual_t != IULong)
      return 0;
    break;
  case ILongLong:
  case IULongLong:
    if (actual_t != ILongLong && actual_t != IULongLong)
      return 0;
    break;
  default:
    return 0;
  }}
  return both[idx] != 0;
}}

"""
# (name, anchor, replacement): each anchor must occur exactly once in e_acsl_stdio.c.
_FMT_HUNKS: tuple[tuple[str, str, str], ...] = (
    (
        "validate_format",
        "static void validate_format(const char *fmtdesc,",
        _FMT_HELPER + "static void validate_format(const char *fmtdesc,",
    ),
    (
        "arglen",
        "  int arglen = strlen(fmtdesc); /* number of variadic arguments */\n",
        "  int arglen = strlen(fmtdesc); /* number of variadic arguments */\n" + _FMT_VALUES_BLOCK,
    ),
    (
        "args",
        "  for (int i = 0; i < arglen; i++)\n    args[i] = va_arg(ap, void *);\n",
        f"  /* {_FMT_PATCH_TAG}: a floating-point argument is read with its\n"
        "     own type, so the pointers after it come from their own slots. */\n"
        "  for (int i = 0; i < arglen; i++) {\n"
        "    if (fmtdesc[i] == 'f' || fmtdesc[i] == 'e') {\n"
        "      (void)va_arg(ap, double);\n"
        "      args[i] = NULL;\n"
        "    } else if (fmtdesc[i] == 'E') {\n"
        "      (void)va_arg(ap, long double);\n"
        "      args[i] = NULL;\n"
        "    } else\n"
        "      args[i] = va_arg(ap, void *);\n"
        "  }\n",
    ),
    (
        "validate_type",
        "#  define validate_type(_t) validate_format_type(_t, fmtdesc, dir, func)",
        f"/* {_FMT_PATCH_TAG}: no abort for a signedness-only mismatch whose value fits both types. */\n"
        "#  define validate_type(_t) (fc_signedness_only((_t), fmtdesc[dir->arg.index], fc_both, dir->arg.index)"
        " ? (void)0 : validate_format_type(_t, fmtdesc, dir, func))",
    ),
)
# Full tracking registers every local with `__e_acsl_store_block(&local, ...)`, and the kernel aborts
# on a `register` local ("Taking the address of a register variable", Cil.mkAddrOf; nettle arcfour.c:
# `register uint8_t i, j;`). Dropping the storage class changes nothing for a local whose address is
# never taken. E-ACSL frontend only: never on the harness cppflags, which Eva and WP read too. A
# global register variable (`register T x asm("reg")`) would change meaning; Frama-C does not parse
# those anyway.
EACSL_FULL_MTRACKING_DEFINES = ("-Dregister=",)
# RTE emits no initialization assertions unless asked, so uninitialized reads would go unchecked.
# Reads of memory written outside instrumented code (libFuzzer's `data`, external libraries) fail
# these checks: harnesses must copy the input into their own buffer, as generated harnesses do.
EACSL_RTE_INITIALIZED_FLAG = "-rte-initialized @all"
# MetAcsl in the E-ACSL build (docs/plans/metacsl-exploitation-plan.md, package C): the module's meta
# file (scripts/security_props.py) is parsed with the sources and translated in a stage of its own,
# before RTE and E-ACSL:
#   frama-c <kernel and E-ACSL options> EACSL_META_FLAGS <sources> <meta file>
#           -then-last <RTE options> -e-acsl ... -then-last -print
# `e-acsl-gcc --then-last` writes the first `-then-last`, and `--e-acsl-extra` puts the RTE options
# behind it (meta_stage_flags). Measured in framac-analysis (Frama-C 34.0~beta, MetAcsl 0.12~beta,
# 2026-11-18, docs/troubleshooting/eacsl-and-fuzzing.md):
# - without the stage switch the printed file holds no check at all, and e-acsl-gcc exits 0;
# - with `-rte` left before the switch, a generated assertion runs before its statement's RTE
#   assertions: an out-of-bounds write is then reported by the E-ACSL guard of `\separated`
#   (`<unknown>:0: Error: E-ACSL RTE failed`) and a known defect changes fingerprint;
# - with the RTE options behind the switch, every assertion of the plain build is kept in its place
#   and the generated ones follow their statement's RTE assertions.
# `unknown-func=inactive`: a property may name a function this module's parse does not hold.
EACSL_META_FLAGS = ("-meta", "-meta-warn-key unknown-func=inactive")
EACSL_META_STAGE_OPTIONS = ("--then-last", "--e-acsl-extra")
# What takes the place of the meta file's `#include "__fc_string_axiomatic.h"` in an E-ACSL build, on
# the same line (the report maps a line of the meta file to its property). e-acsl-gcc parses with
# -no-frama-c-stdlib, so that header of __fc_libc is not on the include path ("fatal error:
# __fc_string_axiomatic.h: No such file or directory"); the frontend's force-included
# fc_compat_types.h gives E-ACSL its own `strlen` and the vocabulary instead.
EACSL_META_INCLUDE_NOTE = (
    "/* __fc_string_axiomatic.h: not on the include path of an E-ACSL build (fc_compat_types.h) */"
)
_FUZZER_INITIALIZE_DEF_RE = FUZZER_INIT_DEF_RE
EACSL_BINARY_MARKERS = (b"__e_acsl_", b"eacsl_assert")

_JOINABLE_SHORT = frozenset({"-I", "-D", "-U", "-L", "-l", "-W"})
_SEPARATE_PREPROCESSOR = frozenset({"-I", "-D", "-U", "-include", "-imacros", "-isystem", "-idirafter", "-iquote"})
_JOINED_PREPROCESSOR = ("-I", "-D", "-U", "-isystem", "-idirafter", "-iquote")
# Force-includes must never reach the backend compile: the instrumented file is
# self-contained and re-including headers redefines its typedefs.
_FORCE_INCLUDE = frozenset({"-include", "-imacros"})


class UnsafePassthroughError(ValueError):
    """A flag value would be misinterpreted by e-acsl-gcc's whitespace re-parsing."""


def normalize_passthrough(value: str) -> str:
    """Make a flag string safe for e-acsl-gcc's whitespace splitting, or raise UnsafePassthroughError."""
    try:
        tokens = shlex.split(value or "", posix=True)
    except ValueError as exc:
        raise UnsafePassthroughError(f"unparseable flag string {value!r}: {exc}") from exc
    out: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if not tok or any(c.isspace() for c in tok):
            raise UnsafePassthroughError(
                f"token {tok!r} contains whitespace; e-acsl-gcc splits flag values on spaces (move the path to one without spaces)"
            )
        if tok in _JOINABLE_SHORT:
            if i + 1 >= len(tokens):
                raise UnsafePassthroughError(f"option {tok!r} is missing its argument")
            arg = tokens[i + 1]
            if not arg or any(c.isspace() for c in arg):
                raise UnsafePassthroughError(
                    f"argument {arg!r} of {tok} contains whitespace; e-acsl-gcc splits flag values on spaces"
                )
            out.append(tok + arg)
            i += 2
            continue
        if tok == "-g":
            out.append("-gline-tables-only")
            i += 1
            continue
        if re.fullmatch(r"-[A-Za-z]", tok):
            raise UnsafePassthroughError(
                f"standalone short option {tok!r} would be re-parsed by e-acsl-gcc as one of its own options"
            )
        out.append(tok)
        i += 1
    return " ".join(out)


def split_preprocessor_flags(flags: str) -> tuple[list[str], list[str], list[str]]:
    """Return (preprocessor_flags, force_include_flags, other_flags) from a flag string."""
    tokens = shlex.split(flags or "", posix=True)
    pre: list[str] = []
    forced: list[str] = []
    other: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in _SEPARATE_PREPROCESSOR and i + 1 < len(tokens):
            (forced if tok in _FORCE_INCLUDE else pre).extend([tok, tokens[i + 1]])
            i += 2
            continue
        if tok.startswith(_JOINED_PREPROCESSOR) or tok == "-nostdinc":
            pre.append(tok)
        else:
            other.append(tok)
        i += 1
    return pre, forced, other


def build_eacsl_flag_sets(
    cppflags: str,
    fuzzer: bool = True,
    fc_stubs: Path | None | str = "auto",
    concurrency: bool = False,
    full_mtracking: bool = False,
) -> dict[str, str]:
    """
    frontend: passed to `-E` (Frama-C preprocessing of the original sources).
    backend:  passed to `-e` (Clang compile of the self-contained instrumented file).
    `full_mtracking` adds EACSL_FULL_MTRACKING_DEFINES to the frontend (see `uses_full_mtracking`).
    """
    stubs = resolve_fc_stubs_dir() if fc_stubs == "auto" else (Path(fc_stubs) if fc_stubs else None)
    pre, forced, other = split_preprocessor_flags(cppflags)
    # A build's pre-C99 -std (an old sidecar; generate_harness.py drops it now): Frama-C prints C99
    # (`restrict` in glibc prototypes) and e-acsl-gcc compiles its own C99 runtime with the `-e` flags.
    other = [t for t in other if not is_pre_c99_std(t)]
    joined_user = " ".join(pre + forced)
    front: list[str] = list(EACSL_DEFINES)
    if full_mtracking:
        front.extend(EACSL_FULL_MTRACKING_DEFINES)
    # The run's stub overlay (workspace/stubs, scripts/stub_gen.py) comes first, as for Frama-C's parses.
    overlay = stub_overlay_dir()
    if overlay is not None and f"-I{overlay.as_posix()}" not in joined_user:
        front.append(f"-I{overlay.as_posix()}")
    if stubs is not None:
        stubs_posix = Path(stubs).as_posix()
        if (Path(stubs) / EACSL_STUBS_SUBDIR).is_dir():
            front.append(f"-I{stubs_posix}/{EACSL_STUBS_SUBDIR}")
        if f"-I{stubs_posix}" not in joined_user:
            front.append(f"-I{stubs_posix}")
        if "fc_compat_types.h" not in joined_user:
            front.extend(["-include", f"{stubs_posix}/fc_compat_types.h"])
    # Frama-C's frontend preprocessing repairs `offsetof` with a non-constant index (scripts/fc_cpp_wrapper.py)
    # and, for E-ACSL only, writes `<==>` in annotations as two implications (scripts/fc_cpp_wrapper_eacsl.py):
    # E-ACSL 35 aborts on `<==>` over `\old`, `\at` or a formal in `ensures`
    # (docs/upstream/frama-c/frama-c-eacsl-iff-labelled-term.md).
    wrapper = framac_cpp_wrapper(EACSL_CPP_WRAPPER)
    if wrapper:
        front.extend(["-wrapper", wrapper])
    front.extend(pre)
    front.extend(forced)
    front.extend(t for t in other if t.startswith("-std="))
    # Codegen flags and warning suppression (-Wno-*) stay isolated on the backend compile
    backend: list[str] = (["-fsanitize=fuzzer"] if fuzzer else []) + list(EACSL_CODEGEN_FLAGS)
    if concurrency and "-DE_ACSL_CONCURRENCY_PTHREAD" not in backend:
        backend.append("-DE_ACSL_CONCURRENCY_PTHREAD")
    for tok in other:
        if tok not in backend:
            backend.append(tok)
    return {
        "frontend": normalize_passthrough(shlex.join(front)),
        "backend": normalize_passthrough(shlex.join(backend)),
    }


def meta_stage_flags(fc_flags: Sequence[str]) -> tuple[list[str], list[str]]:
    """
    Split the stage-1 Frama-C flags of a build that loads MetAcsl properties: (`-F` flags of the
    MetAcsl stage, e-acsl-gcc options that open the next stage with the RTE flags). See EACSL_META_FLAGS.
    """
    rte = [f for f in fc_flags if f.startswith("-rte")]
    first = [f for f in fc_flags if not f.startswith("-rte")] + list(EACSL_META_FLAGS)
    return first, [EACSL_META_STAGE_OPTIONS[0], EACSL_META_STAGE_OPTIONS[1], " ".join(rte)]


def eacsl_meta_file_text(text: str, include_line: str) -> str:
    """
    A meta file (security_props.module_meta_file_text) for the E-ACSL frontend: its `include_line`
    (security_props.META_INCLUDE), when it is the first line, becomes EACSL_META_INCLUDE_NOTE. Every
    other line keeps its number.
    """
    first, sep, rest = text.partition("\n")
    return f"{EACSL_META_INCLUDE_NOTE}{sep}{rest}" if first.strip() == include_line else text


# MetAcsl aborts the whole translation on a property it cannot type in one function (a global this
# module's parse does not declare): `[meta] User Error: Error during the typing of a HILARE!` then
# `What: the HILARE named '<property>' (<meta file>:<line>)`.
_META_REJECTED_RE = re.compile(r"the HILARE named '(?P<name>[A-Za-z_]\w*)'")
_META_WHY_RE = re.compile(r"^\s*Why:\s*(?P<why>.+)$", re.MULTILINE)


def rejected_meta_property(log: str) -> tuple[str, str] | None:
    """(property, reason) of the meta-property MetAcsl stopped on in a stage-1 log, or None."""
    m = _META_REJECTED_RE.search(log or "")
    if not m:
        return None
    why = _META_WHY_RE.search(log, m.end())
    return m.group("name"), (why.group("why").strip() if why else "MetAcsl could not type it")


# The assertion data E-ACSL prints before each check: `<d>.fct = "<function>"; <d>.line = <n>;
# <d>.name = "<property>/meta";` (a check of an annotation MetAcsl generated carries `/meta`).
_META_CHECK_RE = re.compile(
    r'\.fct\s*=\s*"(?P<fct>[^"]*)"\s*;\s*\w+\.line\s*=\s*\d+\s*;\s*\w+\.name\s*=\s*"(?P<name>[A-Za-z_]\w*)/meta"\s*;'
)


def meta_checks(instrumented_text: str, names: Sequence[str]) -> dict[str, dict]:
    """
    The run-time checks of each property in an instrumented file: `{property: {"checks": n,
    "functions": [...]}}`, the functions being the ones whose code holds a check (a `requires` is
    checked in its own function's wrapper). 0 checks: MetAcsl decided every instance statically, the
    property has no instance in the instrumented functions, or E-ACSL did not translate it.
    """
    functions: dict[str, set[str]] = {}
    for m in _META_CHECK_RE.finditer(instrumented_text):
        functions.setdefault(m.group("name"), set()).add(m.group("fct"))
    return {
        name: {"checks": instrumented_text.count(f'"{name}/meta"'), "functions": sorted(functions.get(name, ()))}
        for name in names
    }


def uses_full_mtracking(modern_cli: bool) -> bool:
    """Whether instrumentation runs with full memory tracking: the two-stage CLI (Frama-C 33+) passes EACSL_FC_EXTRA_FLAGS."""
    return modern_cli and EACSL_FULL_MTRACKING_FLAG in EACSL_FC_EXTRA_FLAGS


def is_eacsl_instrumented(path: Path) -> bool:
    """True if the binary contains E-ACSL runtime/instrumentation symbols."""
    try:
        data = Path(path).read_bytes()
    except OSError:
        return False
    return any(marker in data for marker in EACSL_BINARY_MARKERS)


def resolve_fuzz_init_source() -> Path:
    """Locate templates/eacsl_runtime/fuzz_init.c (container or local checkout)."""
    for base in (Path("/opt/framac-pipeline/templates"), Path(__file__).resolve().parent.parent / "templates"):
        cand = base / "eacsl_runtime" / "fuzz_init.c"
        if cand.is_file():
            return cand
    raise FileNotFoundError("templates/eacsl_runtime/fuzz_init.c not found")


def defines_fuzzer_initialize(c_text: str) -> bool:
    """True if the (instrumented) slice already defines LLVMFuzzerInitialize, which the init hook also defines."""
    return bool(_FUZZER_INITIALIZE_DEF_RE.search(c_text))


_PTHREAD_CREATE_RE = re.compile(r"\bpthread_create\b")


def slice_has_pthread(sources: Sequence[str | Path]) -> bool:
    """True if any slice source file references pthread_create."""
    for s in sources:
        try:
            p = Path(s)
            if p.is_file() and _PTHREAD_CREATE_RE.search(p.read_text(encoding="utf-8", errors="replace")):
                return True
        except OSError:
            continue
    return False


_WRAPPER_HEADER_RE = re.compile(r"^[A-Za-z_][^;{}]*\b__gen_e_acsl_\w+\s*\(")
_RETRES_ASSIGN_RE = re.compile(r"^(?P<indent>\s+)__retres = ")
WRAPPER_RESULT_INIT = "__e_acsl_initialize((void *)(& __retres),sizeof(__retres));"
WRAPPER_RESULT_INIT_DECL = "void __e_acsl_initialize(void *ptr, size_t size);"
_INITIALIZE_DECL_RE = re.compile(r"\bvoid\s+__e_acsl_initialize\s*\(\s*void\s*\*")


def mark_wrapper_results_initialized(c_text: str) -> tuple[str, int]:
    """
    Work around an E-ACSL gap (Frama-C 33): a contract wrapper `__gen_e_acsl_<fn>` registers its
    `__retres` with the runtime but never marks it initialized after `__retres = <fn>(...);`.
    Under -rte-initialized every `ensures` that reads \\result then fails `\\initialized(&__retres)`
    on the first input. Insert the missing `__e_acsl_initialize` after each assignment to a
    registered `__retres` inside a wrapper definition. Sound: the callee's own return is checked
    for uninitialized reads. Frama-C prunes the runtime prototype unless E-ACSL emitted a call of its
    own (a `memcpy` or an array-element write does; plain scalars, or `malloc` alone, do not), so
    declare it ahead of the first patched wrapper when it is missing. Returns the new text and the
    number of insertions.
    """
    lines = c_text.split("\n")
    out: list[str] = []
    header = False  # inside a wrapper header, before its `{` (a `;` first means a prototype)
    in_wrapper = tracked = False
    indent: str | None = None  # inside a `__retres = ...` statement, until its `;`
    wrapper_at = first_patched_at = 0  # index in `out` of the current / first patched wrapper's header
    count = 0
    for idx, line in enumerate(lines):
        out.append(line)
        if not in_wrapper:
            if not header and _WRAPPER_HEADER_RE.match(line) and not line.rstrip().endswith(";"):
                header = True
                wrapper_at = len(out) - 1
            elif header and line.rstrip() == "{":
                header, in_wrapper, tracked = False, True, False
            elif header and line.rstrip().endswith(";"):
                header = False
            continue
        if line.startswith("}"):
            in_wrapper, indent = False, None
            continue
        if "__e_acsl_store_block((void *)(& __retres)" in line:
            tracked = True
        if indent is None and tracked:
            m = _RETRES_ASSIGN_RE.match(line)
            if m:
                indent = m.group("indent")
        if indent is not None and line.rstrip().endswith(";"):
            next_nonblank = next((ln for ln in lines[idx + 1 :] if ln.strip()), "")
            already_init = any(
                ("__e_acsl_initialize(" in s or "__e_acsl_full_init(" in s) and "__retres" in s
                for s in (line, next_nonblank)
            )
            if not already_init:
                out.append(indent + WRAPPER_RESULT_INIT)
                if not count:
                    first_patched_at = wrapper_at
                count += 1
            indent = None
    if count and not _INITIALIZE_DECL_RE.search("\n".join(out[:first_patched_at])):
        out[first_patched_at:first_patched_at] = [WRAPPER_RESULT_INIT_DECL, ""]
    return "\n".join(out), count


FORMAL_INIT_DECL = "void __e_acsl_full_init(void *ptr);"
_FULL_INIT_DECL_RE = re.compile(r"\bvoid\s+__e_acsl_full_init\s*\(\s*void\s*\*")
# A definition header starts in column 0 with an identifier and has a parameter list.
_DEF_HEADER_START_RE = re.compile(r"^[A-Za-z_][^;{}]*\(")
_STORE_BLOCK_LINE_RE = re.compile(
    r"^(?P<indent>[ \t]*)__e_acsl_store_block\(\(void \*\)\(& ?(?P<name>[A-Za-z_]\w*)\),\s*\d+[uUlL]*\);$"
)
_CALL_LIKE_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_FN_PTR_DECLARATOR_RE = re.compile(r"\(\s*\*+\s*(?:(?:const|volatile|restrict|__restrict)\s+)*([A-Za-z_]\w*)\s*\)")
_TRAILING_NAME_RE = re.compile(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)*$")
# Words that can precede `(` in a header without being the function name.
_HEADER_NON_NAMES = frozenset(
    {
        "__attribute__",
        "__attribute",
        "__declspec",
        "__extension__",
        "__typeof__",
        "__typeof",
        "typeof",
        "_Alignas",
        "sizeof",
        "void",
        "char",
        "short",
        "int",
        "long",
        "float",
        "double",
        "signed",
        "unsigned",
        "_Bool",
        "const",
        "volatile",
        "restrict",
        "static",
        "extern",
        "inline",
        "__inline",
        "__inline__",
        "struct",
        "union",
        "enum",
    }
)


def _matching_paren(text: str, open_at: int) -> int:
    """Index of the `)` closing the `(` at `open_at`, or -1."""
    depth = 0
    for i in range(open_at, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _split_top_level(params: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    start = 0
    for i, ch in enumerate(params):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(params[start:i])
            start = i + 1
    parts.append(params[start:])
    return parts


def definition_formals(header: str) -> list[str]:
    """
    Parameter names of a function definition header as Frama-C prints it (one or more lines,
    without the `{`). The parameter list is the group after the function name: the first
    `<name>(` whose group ends the header, or is followed by `)` as in a function returning a
    function pointer (`int (*get(int k))(int )`). Function-pointer parameters (`int (*cb)(int )`)
    yield the pointer's name; `void` and `...` yield nothing. Returns [] when no list is found.
    """
    text = " ".join(header.split())
    for m in _CALL_LIKE_RE.finditer(text):
        if m.group(1) in _HEADER_NON_NAMES:
            continue
        open_at = m.end() - 1
        close_at = _matching_paren(text, open_at)
        if close_at < 0:
            return []
        rest = text[close_at + 1 :].strip()
        if rest and not rest.startswith(")"):
            continue
        names: list[str] = []
        for param in _split_top_level(text[open_at + 1 : close_at]):
            param = param.strip()
            if not param or param in ("void", "..."):
                continue
            fn_ptr = _FN_PTR_DECLARATOR_RE.search(param)
            named = fn_ptr or _TRAILING_NAME_RE.search(param)
            if named and named.group(1) not in _HEADER_NON_NAMES:
                names.append(named.group(1))
        return names
    return []


def mark_formals_initialized(c_text: str) -> tuple[str, int]:
    """
    Work around an E-ACSL gap (Frama-C 33-35): a function registers each formal parameter with
    `__e_acsl_store_block((void *)(& p),N)` but never marks it initialized, although the caller
    has just written it. Under -rte-initialized, the first read of a by-value struct field
    (`\\initialized(&s.len)`) or of a scalar formal through its address fails on every call,
    whatever the caller passed; the assertion is blocking, so nothing after it in the function
    is ever checked. Insert `__e_acsl_full_init((void *)(& p));` after the first store_block of
    each formal in each definition. Locals keep their tracking, so uninitialized locals are still
    reported. Cost: uninitialized struct members passed by value are no longer reported by
    E-ACSL (the check that would report them failed on every call). Declares the runtime function
    ahead of the first patched definition when Frama-C pruned its prototype. Returns the new
    text and the number of insertions.
    """
    lines = c_text.split("\n")
    out: list[str] = []
    header_lines: list[str] | None = None  # a definition header being read, before its `{`
    header_at = first_patched_at = 0  # index in `out` of the current / first patched header
    formals: set[str] = set()  # formals of the definition whose body is being read
    patched: set[str] = set()
    in_body = False
    count = 0
    store_lines = [ln for ln in lines if "__e_acsl_store_block(" in ln]
    if store_lines and not any(_STORE_BLOCK_LINE_RE.match(ln) for ln in store_lines):
        import warnings

        warnings.warn(
            "__e_acsl_store_block lines exist in text but none matched _STORE_BLOCK_LINE_RE",
            UserWarning,
            stacklevel=2,
        )
    for idx, line in enumerate(lines):
        out.append(line)
        if in_body:
            if line.startswith("}"):
                in_body = False
                continue
            m = _STORE_BLOCK_LINE_RE.match(line)
            if not m or m.group("name") not in formals or m.group("name") in patched:
                continue
            name = m.group("name")
            patched.add(name)
            next_nonblank = next((ln for ln in lines[idx + 1 :] if ln.strip()), "")
            if re.search(rf"__e_acsl_(?:full_init|initialize)\(\(void \*\)\(& ?{name}\)", next_nonblank):
                continue
            out.append(f"{m.group('indent')}__e_acsl_full_init((void *)(& {name}));")
            if not count:
                first_patched_at = header_at
            count += 1
            continue
        if header_lines is not None:
            if line.rstrip() == "{":
                formals = set(definition_formals(" ".join(header_lines)))
                patched = set()
                in_body = bool(formals)
                header_lines = None
            elif line[:1].isspace() and not line.rstrip().endswith(";"):
                header_lines.append(line)
            else:
                header_lines = None
            if header_lines is not None or in_body:
                continue
        if _DEF_HEADER_START_RE.match(line) and not line.rstrip().endswith(";"):
            header_lines = [line]
            header_at = len(out) - 1
    if count and not _FULL_INIT_DECL_RE.search("\n".join(out[:first_patched_at])):
        out[first_patched_at:first_patched_at] = [FORMAL_INIT_DECL, ""]
    return "\n".join(out), count


# `__e_acsl_initialized((void *)(& ap), sizeof(va_list))`, the check -rte-initialized puts before
# each `__builtin_va_arg(ap, ...)`. Only va_start and va_copy initialize a va_list, and both are
# compiler builtins E-ACSL does not instrument, so the check fails on every va_arg (minmea's
# minmea_scan, S9). Marking `ap` initialized after va_start would not help: the block is registered
# with Frama-C's machdep size (8 on gcc_x86_64) while clang's sizeof(va_list) is 24.
_VA_LIST_INITIALIZED_RE = re.compile(
    r"__e_acsl_initialized\(\s*\(void \*\)\s*\(\s*&\s*(?P<lv>[^,()]+?)\s*\)\s*,\s*"
    r"sizeof\(\s*(?:__builtin_)?va_list\s*\)\s*\)"
)


def skip_va_list_initialized_checks(c_text: str) -> tuple[str, int]:
    """
    Replace E-ACSL's `\\initialized` test on a va_list object by 1. A va_list is initialized only by
    va_start or va_copy, which the runtime never sees, so the test is false on every va_arg; reading
    a va_list before va_start is no longer reported. Returns (new_text, count).
    """
    return _VA_LIST_INITIALIZED_RE.subn(
        lambda m: f"1 /* {m.group('lv')}: va_start/va_copy are not instrumented */", c_text
    )


_READONLY_SCALAR_RE = re.compile(
    r"(?P<store>^[ \t]*__e_acsl_store_block\(\(void \*\)\(& ?(?P<name>[A-Za-z_]\w*)\),\s*\d+[uUlL]*\);\n"
    r"[ \t]*__e_acsl_full_init\(\(void \*\)\(& ?(?P=name)\)\);\n)"
    r"(?P<indent>[ \t]*)__e_acsl_mark_readonly\(\(void \*\)(?P=name)\);",
    re.MULTILINE,
)


def fix_readonly_scalar_globals(c_text: str) -> tuple[str, int]:
    """
    Work around an E-ACSL printer bug on scalar `const` globals: it emits
    `__e_acsl_mark_readonly((void *)<value>)` instead of taking the address.
    The value is then treated as an address by the runtime predicate, which
    aborts before any input is processed (e.g. libcbor's
    `const uint64_t kMaxEmbeddedInt = 23;` -> invalid address 0x17).
    Replace the call with the address of the same global, which is what the
    runtime expects. Arrays and structs already carry `&`/a decayed address and
    do not match this pattern. Returns the new text and the number of fixes.
    """

    def _repl(match: re.Match[str]) -> str:
        return (
            f"{match.group('store')}{match.group('indent')}__e_acsl_mark_readonly((void *)(& {match.group('name')}));"
        )

    return _READONLY_SCALAR_RE.subn(_repl, c_text)


_C_STRING_LITERAL = r'L?"(?:[^"\\\n]|\\.)*"'
_LITERAL_STORE_RE = re.compile(
    rf"__e_acsl_store_block\(\(void \*\)(?P<lit>{_C_STRING_LITERAL}),(?P<size>\d+)[uUlL]*\);"
)
_GLOBALS_INIT_HEAD_RE = re.compile(r"^void __e_acsl_globals_init\(void\)\n\{\n", re.MULTILINE)
_REGISTRATION_CALLS = ("__e_acsl_store_block(", "__e_acsl_full_init(", "__e_acsl_mark_readonly(")


def _globals_init_statements(lines: list[str]) -> list[tuple[list[str], str]]:
    """Group body lines into statements: a registration call the printer wrapped over several lines is one."""
    units: list[tuple[list[str], str]] = []
    i = 0
    while i < len(lines):
        chunk = [lines[i]]
        if lines[i].strip().startswith(_REGISTRATION_CALLS):
            while not chunk[-1].rstrip().endswith(");") and i + len(chunk) < len(lines) and len(chunk) < 8:
                chunk.append(lines[i + len(chunk)])
        units.append((chunk, "".join(part.strip() for part in chunk)))
        i += len(chunk)
    return units


def order_literal_registrations(c_text: str) -> tuple[str, int]:
    """
    Register string literals shortest first in `__e_acsl_globals_init`.

    Under full memory tracking E-ACSL registers every string literal as its own block. clang ignores
    `-fno-merge-constants` and puts literals in a mergeable string section, and GNU ld then stores a
    literal that is a suffix of another one (`","` of `" ,"`) inside it. The two blocks overlap: when
    the shorter one is registered last, the shadow of the shared bytes names it as their block, and
    `\\valid_read(" ," + 1)` fails because that byte no longer belongs to the block of `" ,"` (c-ares:
    `ares_buf_split(buf, " ,", 2, ...)` aborted at init on every input). Registering literals by
    ascending size makes the longer, enclosing block the last writer, so every merged suffix lies inside
    one registered block that ends at the shared terminator.

    Cost: a merged suffix reports the enclosing literal's block, so a read before the start of the
    suffix (but inside the longer literal) and its `\\base_addr`/`\\offset`/`\\block_length` are not
    the suffix's own. Each group (store_block, then the full_init/mark_readonly lines of the same
    literal) moves as a whole; the other globals keep their place. Returns (new_text, number of
    literal groups whose position changed).
    """
    head = _GLOBALS_INIT_HEAD_RE.search(c_text)
    if head is None:
        return c_text, 0
    body_start = head.start()
    end = c_text.find("\n}\n", body_start)
    if end < 0:
        return c_text, 0
    units = _globals_init_statements(c_text[body_start:end].split("\n"))
    groups: list[tuple[int, int, int]] = []  # (first statement, statement count, block size)
    i = 0
    while i < len(units):
        m = _LITERAL_STORE_RE.fullmatch(units[i][1])
        if not m:
            i += 1
            continue
        lit = m.group("lit")
        n = 1
        follow = (f"__e_acsl_full_init((void *)(& {lit}));", f"__e_acsl_mark_readonly((void *){lit});")
        while i + n < len(units) and units[i + n][1] in follow:
            n += 1
        groups.append((i, n, int(m.group("size"))))
        i += n
    ordered = sorted(groups, key=lambda g: g[2])
    moved = sum(1 for a, b in zip(groups, ordered, strict=True) if a != b)
    if not moved:
        return c_text, 0
    out: list[str] = []
    slot = 0
    i = 0
    while i < len(units):
        if slot < len(groups) and i == groups[slot][0]:
            first, count, _size = ordered[slot]
            for chunk, _joined in units[first : first + count]:
                out.extend(chunk)
            i += groups[slot][1]
            slot += 1
        else:
            out.extend(units[i][0])
            i += 1
    return c_text[:body_start] + "\n".join(out) + c_text[end:], moved


_ALIGNAS_RE = re.compile(r"\b_Alignas\s*\(")
_ATTRIBUTE_RE = re.compile(r"\s*__attribute__\s*\(")


def _ends_declarator(line: str, at: int) -> bool:
    """True if `line[at:]` is what may follow a whole declarator: attributes, then `;`, `,` or `=`."""
    while m := _ATTRIBUTE_RE.match(line, at):
        close_at = _matching_paren(line, m.end() - 1)
        if close_at < 0:
            return False
        at = close_at + 1
    rest = line[at:].lstrip()
    return rest[:1] in (";", ",", "=")


def rewrite_trailing_alignas(c_text: str) -> tuple[str, int]:
    """
    Work around a Frama-C kernel printer bug (35.0~~dev): it prints the alignment specifier of a
    struct or union member after the declarator (`alignas(16) uint64_t u64[2];` becomes
    `uint64_t u64[2] _Alignas(16) ;`), which clang rejects with "expected ';' at end of declaration
    list" (nettle's `union nettle_block16`). Rewrite each `_Alignas(N)` that ends a declarator (only
    attributes, then `;`, `,` or `=` follow it) as `__attribute__((__aligned__(N)))`: clang accepts
    that form after the declarator, and it keeps the alignment, so the instrumented build has the
    target's layout. Frama-C prints an `aligned` attribute in that place itself. An `_Alignas` before
    the declarator, as globals and locals print, is valid and stays. Never `-D_Alignas(x)=`: that
    drops the alignment. Returns the new text and the number of rewrites.
    """
    count = 0
    lines = c_text.split("\n")
    for idx, line in enumerate(lines):
        if "_Alignas" not in line:
            continue
        pieces: list[str] = []
        pos = 0
        for m in _ALIGNAS_RE.finditer(line):
            if m.start() < pos:
                continue
            close_at = _matching_paren(line, m.end() - 1)
            if close_at < 0 or not _ends_declarator(line, close_at + 1):
                continue
            alignment = line[m.end() : close_at].strip()
            pieces.extend([line[pos : m.start()], f"__attribute__((__aligned__({alignment})))"])
            pos = close_at + 1
            count += 1
        if pieces:
            lines[idx] = "".join(pieces) + line[pos:]
    return "\n".join(lines), count


_STRTO_CALL_RE = re.compile(r"\b(?:strto\w*|wcsto\w*)\s*\(")
_SOUND_VERDICT_RESET_RE = re.compile(r"\b__e_acsl_sound_verdict\s*=\s*0\s*;")
_FUZZER_TEST_ONE_INPUT_DEF_RE = re.compile(
    r"(?:^|\s)LLVMFuzzerTestOneInput\s*\([^;{]*\)[^{;]*\{",
    re.MULTILINE,
)


def _is_comment_line(line: str, in_block_comment: bool) -> tuple[bool, bool]:
    """
    Check if a line contains only comments and whitespace, and track block comment state.
    Returns (is_comment_only, new_in_block_comment).
    """
    i = 0
    n = len(line)
    has_code = False
    while i < n:
        if in_block_comment:
            end_idx = line.find("*/", i)
            if end_idx != -1:
                in_block_comment = False
                i = end_idx + 2
            else:
                i = n
        else:
            if line[i].isspace():
                i += 1
                continue
            if line[i : i + 2] == "//":
                break
            elif line[i : i + 2] == "/*":
                in_block_comment = True
                i += 2
            else:
                has_code = True
                i += 1
    return (not has_code), in_block_comment


def rewrite_sound_verdict_resets(c_text: str) -> tuple[str, int]:
    """
    Work around E-ACSL automatically emitting `__e_acsl_sound_verdict = 0;` after standard library
    string/wide-string conversion functions (strto*, wcsto*). Without models for these functions,
    E-ACSL poisons the verdict, permanently causing all subsequent assertions to be flagged unsound.
    Comments out `__e_acsl_sound_verdict = 0;` within statements immediately following such calls.
    Returns (new_text, count).
    """
    lines = c_text.split("\n")
    out: list[str] = []
    count = 0
    pending_window = 0
    in_call = False
    call_lines_left = 0
    in_block_comment = False

    for line in lines:
        was_in_block = in_block_comment
        is_comment_only, in_block_comment = _is_comment_line(line, in_block_comment)

        if not is_comment_only and not was_in_block and _STRTO_CALL_RE.search(line):
            if ";" in line:
                in_call = False
                pending_window = 3
            else:
                in_call = True
                call_lines_left = 10
        elif in_call:
            if ";" in line:
                in_call = False
                pending_window = 3
            else:
                call_lines_left -= 1
                if call_lines_left <= 0:
                    in_call = False

        if pending_window > 0 and _SOUND_VERDICT_RESET_RE.search(line):
            stripped = line.strip()
            if not stripped.startswith("/*") and not stripped.startswith("//") and not was_in_block:
                new_line = _SOUND_VERDICT_RESET_RE.sub("/* __e_acsl_sound_verdict = 0; */", line)
                if new_line != line:
                    out.append(new_line)
                    count += 1
                    pending_window = 0
                    continue
            else:
                pending_window = 0
        elif pending_window > 0 and line.strip() and not in_call:
            if not is_comment_only and not _STRTO_CALL_RE.search(line):
                pending_window -= 1

        out.append(line)

    return "\n".join(out), count


def reset_verdict_on_input_entry(c_text: str) -> tuple[str, int]:
    """
    Inject `__e_acsl_sound_verdict = 1;` at entry of LLVMFuzzerTestOneInput if not already present,
    preventing any verdict poisoning from an earlier test iteration from affecting later runs.
    Returns (new_text, count).
    """
    if "LLVMFuzzerTestOneInput" not in c_text:
        return c_text, 0

    m = _FUZZER_TEST_ONE_INPUT_DEF_RE.search(c_text)
    if not m:
        return c_text, 0

    brace_pos = m.end() - 1
    brace_line_idx = c_text[:brace_pos].count("\n")

    lines = c_text.split("\n")
    # Check if already present in the next few statements after the brace line
    already_present = any(
        "__e_acsl_sound_verdict" in lines[j] and "= 1" in lines[j]
        for j in range(brace_line_idx, min(len(lines), brace_line_idx + 10))
    )
    if already_present:
        return c_text, 0

    # Determine indentation from following non-empty lines, or default to 4 spaces
    indent = "    "
    for j in range(brace_line_idx + 1, min(len(lines), brace_line_idx + 5)):
        if lines[j].strip():
            indent = lines[j][: len(lines[j]) - len(lines[j].lstrip())]
            break

    out = list(lines[: brace_line_idx + 1])
    out.append(f"{indent}__e_acsl_sound_verdict = 1;")
    out.extend(lines[brace_line_idx + 1 :])
    return "\n".join(out), 1


def select_eacsl_binary(out_bin: Path) -> Path:
    """e-acsl-gcc writes the instrumented executable to `<out>.e-acsl`; prefer it when present."""
    out_bin = Path(out_bin)
    instrumented = out_bin.with_name(out_bin.name + ".e-acsl")
    return instrumented if instrumented.is_file() else out_bin


# ---------------------------------------------------------------------------
# -rte-select / -e-acsl-functions robustness
# ---------------------------------------------------------------------------

_NO_FUNCTION_RES = (
    re.compile(r"no function '(?P<fn>[A-Za-z_]\w*)'"),
    re.compile(r"function '(?P<fn>[A-Za-z_]\w*)' (?:does not exist|not found|is unknown)"),
    re.compile(r"[Uu]nknown function '(?P<fn>[A-Za-z_]\w*)'"),
)


def parse_missing_functions(log: str) -> list[str]:
    found: list[str] = []
    for rx in _NO_FUNCTION_RES:
        for m in rx.finditer(log or ""):
            if m.group("fn") not in found:
                found.append(m.group("fn"))
    return found


_LINE_MARKER_RE = re.compile(r'^#\s*(?:line\s+)?\d+\s+"(?P<file>[^"]+)"')


def filter_preprocessed_to_file(preprocessed: str, source: Path) -> str:
    """Keep only the lines of `clang -E` output that originate from `source` (blank out the rest, keep line count)."""
    target_name = Path(source).name
    target_resolved = str(Path(source).resolve()).replace("\\", "/")
    keep = False
    out: list[str] = []
    for line in preprocessed.splitlines():
        m = _LINE_MARKER_RE.match(line)
        if m:
            marker = m.group("file").replace("\\", "/")
            keep = marker == target_resolved or marker.endswith("/" + target_name) or marker == target_name
            out.append("")
            continue
        out.append(line if keep else "")
    return "\n".join(out)


def preprocess_source(
    source: Path, cppflags: str, runner: Callable[..., Any] = subprocess.run, clang: str | None = None
) -> str | None:
    exe = clang or shutil.which("clang")
    if not exe:
        return None
    pre, forced, _ = split_preprocessor_flags(cppflags)
    cmd = [exe, "-E", "-x", "c", *EACSL_DEFINES, *pre, *forced, str(source)]
    try:
        proc = runner(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return filter_preprocessed_to_file(proc.stdout or "", source)


# ---------------------------------------------------------------------------
# Variadic `<fn>_fallback_<N>` link-only definitions
# ---------------------------------------------------------------------------

FALLBACK_HEADER_MAP: dict[str, tuple[str, ...]] = {
    "open": ("fcntl.h",),
    "openat": ("fcntl.h",),
    "fcntl": ("fcntl.h",),
    "ioctl": ("sys/ioctl.h",),
    "prctl": ("sys/prctl.h",),
    "execl": ("unistd.h",),
    "execlp": ("unistd.h",),
    "execle": ("unistd.h",),
    "printf": ("stdio.h",),
    "fprintf": ("stdio.h",),
    "dprintf": ("stdio.h",),
    "sprintf": ("stdio.h",),
    "snprintf": ("stdio.h",),
    "scanf": ("stdio.h",),
    "fscanf": ("stdio.h",),
    "sscanf": ("stdio.h",),
    "syslog": ("syslog.h",),
}

_FALLBACK_UNDEFINED_RE = re.compile(
    r"(?:undefined reference to [`'\"]|undefined symbol:\s*[`'\"]?)"
    r"(?P<name>[A-Za-z_]\w*(?:_fallback_|_va_)\d+)['\"]?"
)
_FALLBACK_PROTO_RE = re.compile(
    r"(?P<ret>(?:[A-Za-z_]\w*[\s\*]+)+?)(?P<name>(?P<base>[A-Za-z_]\w*?)(?:_fallback_|_va_)(?P<idx>\d+))\s*\((?P<params>[^;{}()]*)\)\s*(?:/\*[\s\S]*?\*/\s*)?(?P<end>[;{])"
)
_C_TYPE_WORDS = frozenset(
    {
        "const",
        "volatile",
        "restrict",
        "unsigned",
        "signed",
        "char",
        "short",
        "int",
        "long",
        "float",
        "double",
        "void",
        "struct",
        "union",
        "enum",
        "_Bool",
    }
)
_STATEMENT_WORDS = frozenset({"return", "else", "do", "case", "goto", "sizeof"})


def parse_undefined_fallbacks(link_log: str) -> list[str]:
    names: list[str] = []
    for m in _FALLBACK_UNDEFINED_RE.finditer(link_log or ""):
        if m.group("name") not in names:
            names.append(m.group("name"))
    return names


def _split_params(params: str) -> list[str]:
    parts = [p.strip() for p in params.split(",")]
    return [p for p in parts if p]


def _name_params(params: list[str]) -> tuple[list[str], list[str]] | None:
    """Return (declarations_with_names, argument_names), or None if a parameter cannot be handled."""
    if params == ["void"] or not params:
        return [], []
    decls: list[str] = []
    names: list[str] = []
    for i, p in enumerate(params):
        if p == "..." or "(" in p or "[" in p:
            return None
        words = re.findall(r"[A-Za-z_]\w*", p)
        last = words[-1] if words else ""
        named = len(words) >= 2 and last not in _C_TYPE_WORDS and not p.rstrip().endswith("*")
        if named:
            decls.append(p)
            names.append(last)
        else:
            arg = f"a{i}"
            decls.append(f"{p} {arg}")
            names.append(arg)
    return decls, names


def find_variadic_fallbacks(instrumented_source: str) -> list[dict[str, Any]]:
    """Fallback prototypes declared but not defined in the instrumented source."""
    declared: dict[str, dict[str, Any]] = {}
    defined: set[str] = set()
    for m in _FALLBACK_PROTO_RE.finditer(instrumented_source or ""):
        name = m.group("name")
        if m.group("end") == "{":
            defined.add(name)
            continue
        ret = " ".join(m.group("ret").split())
        ret = re.sub(r"^(?:extern|static|inline)\s+", "", ret)
        if set(re.findall(r"[A-Za-z_]\w*", ret)) & _STATEMENT_WORDS:
            continue  # a call statement such as `return open_fallback_1(a, b, c);`
        declared.setdefault(
            name,
            {
                "name": name,
                "base": m.group("base"),
                "index": int(m.group("idx")),
                "ret": ret,
                "params": _split_params(m.group("params")),
            },
        )
    return [d for n, d in sorted(declared.items(), key=lambda kv: (kv[1]["base"], kv[1]["index"])) if n not in defined]


def _enosys_body(fb: dict[str, Any]) -> str:
    ret = fb.get("ret") or "int"
    if ret.strip() == "void":
        return f"void {fb['name']}() {{ errno = ENOSYS; FC_ERRNO_OUT(); }}\n"
    if "*" in ret:
        return f"void *{fb['name']}() {{ errno = ENOSYS; FC_ERRNO_OUT(); return 0; }}\n"
    return f"long {fb['name']}() {{ errno = ENOSYS; FC_ERRNO_OUT(); return -1; }}\n"


def generate_fallback_source(
    fallbacks: list[dict[str, Any]], force_enosys: bool = False
) -> tuple[str, list[dict[str, str]]]:
    """
    Emit C definitions for the fallbacks: forward to the real libc function when the base
    is known and the signature is parseable, otherwise set errno=ENOSYS and fail. Each one also
    syncs errno with the stub's global (`ERRNO_SHIM_GLOBAL`, weak: absent when the slice never
    includes <errno.h>), as the errno shim's wrappers do.
    Returns (source_text, records) where records = [{name, base, mode}].
    """
    headers: list[str] = ["errno.h", "sys/types.h", "stddef.h", "stdint.h"]
    bodies: list[str] = []
    records: list[dict[str, str]] = []
    for fb in fallbacks:
        mode = "enosys"
        named = None if force_enosys else _name_params(fb.get("params") or [])
        base_headers = FALLBACK_HEADER_MAP.get(fb["base"])
        if base_headers and named is not None:
            decls, args = named
            for h in base_headers:
                if h not in headers:
                    headers.append(h)
            ret = fb.get("ret") or "int"
            call = f"{fb['base']}({', '.join(args)})"
            if ret.strip() == "void":
                stmt = f"FC_ERRNO_IN(); {call}; FC_ERRNO_OUT();"
            else:
                stmt = f"FC_ERRNO_IN(); {ret} r = {call}; FC_ERRNO_OUT(); return r;"
            bodies.append(f"{ret} {fb['name']}({', '.join(decls) or 'void'}) {{ {stmt} }}\n")
            mode = "forward"
        else:
            bodies.append(_enosys_body(fb))
        records.append({"name": fb["name"], "base": fb["base"], "mode": mode})
    text = (
        "/* Generated by run_eacsl_fuzz.py: link-only definitions for Variadic fallbacks.\n"
        " * Never add this file to the instrumented sources (it would shift the fallback numbering). */\n"
        "#define _GNU_SOURCE 1\n"
        + "".join(f"#include <{h}>\n" for h in headers)
        + "\n"
        + _FALLBACK_ERRNO_SYNC
        + "".join(bodies)
    )
    return text, records


_FALLBACK_ERRNO_SYNC = (
    "extern int __fc_eacsl_errno __attribute__((weak));\n"
    "#define FC_ERRNO_IN() do { if (&__fc_eacsl_errno) errno = __fc_eacsl_errno; } while (0)\n"
    "#define FC_ERRNO_OUT() do { if (&__fc_eacsl_errno) __fc_eacsl_errno = errno; } while (0)\n\n"
)


def build_fallback_object(
    instrumented_c: Path,
    out_dir: Path,
    runner: Callable[..., Any] = subprocess.run,
    compiler: str = "clang",
    timeout: float | None = None,
) -> dict[str, Any]:
    """
    Generate and compile `eacsl_fallbacks.o` next to the binary. Falls back to ENOSYS-only stubs if
    forwarding fails to compile. `timeout` bounds each compile (the build job class limit).
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        text = Path(instrumented_c).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"status": "error", "reason": f"cannot read instrumented source: {exc}", "fallbacks": []}
    fallbacks = find_variadic_fallbacks(text)
    if not fallbacks:
        return {"status": "none", "fallbacks": []}
    src = out_dir / "eacsl_fallbacks.c"
    obj = out_dir / "eacsl_fallbacks.o"
    last_err = ""
    for force_enosys in (False, True):
        source, records = generate_fallback_source(fallbacks, force_enosys=force_enosys)
        src.write_text(source, encoding="utf-8")
        cmd = [compiler, "-c", "-O1", "-w", "-std=gnu17", str(src), "-o", str(obj)]
        try:
            proc = runner(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
            rc, last_err = proc.returncode, (proc.stderr or "")[-4000:]
        except subprocess.TimeoutExpired:
            rc, last_err = 124, f"{compiler} exceeded the {timeout} s build time limit"
        except OSError as exc:
            rc, last_err = 127, str(exc)
        if rc == 0:
            return {"status": "built", "object": str(obj), "source": str(src), "fallbacks": records}
    return {"status": "error", "reason": f"fallback object failed to compile: {last_err}", "fallbacks": []}


# ---------------------------------------------------------------------------
# errno shim
# ---------------------------------------------------------------------------

# templates/fc_stubs/errno.h maps `errno` to this tracked global in E-ACSL builds: glibc's errno
# lives in libc.so's TLS block, outside the TLS segment the E-ACSL runtime shadows (it covers the
# executable's own block only), so the runtime can neither track nor register it.
ERRNO_SHIM_GLOBAL = "__fc_eacsl_errno"

# Non-variadic libc functions that report failures through errno: (return type, name, parameter
# types, header). Each one the slice calls is linked through `-Wl,--wrap=<name>` to a wrapper that
# copies the global into the real errno before the call and the real errno back after it.
# Variadic ones (open, fcntl, ioctl) reach libc through the Variadic fallbacks, which sync too.
ERRNO_SHIM_FUNCTIONS: tuple[tuple[str, str, tuple[str, ...], str], ...] = (
    ("long", "strtol", ("const char *", "char **", "int"), "stdlib.h"),
    ("long long", "strtoll", ("const char *", "char **", "int"), "stdlib.h"),
    ("unsigned long", "strtoul", ("const char *", "char **", "int"), "stdlib.h"),
    ("unsigned long long", "strtoull", ("const char *", "char **", "int"), "stdlib.h"),
    ("intmax_t", "strtoimax", ("const char *", "char **", "int"), "inttypes.h"),
    ("uintmax_t", "strtoumax", ("const char *", "char **", "int"), "inttypes.h"),
    ("double", "strtod", ("const char *", "char **"), "stdlib.h"),
    ("float", "strtof", ("const char *", "char **"), "stdlib.h"),
    ("long double", "strtold", ("const char *", "char **"), "stdlib.h"),
    ("ssize_t", "read", ("int", "void *", "size_t"), "unistd.h"),
    ("ssize_t", "write", ("int", "const void *", "size_t"), "unistd.h"),
    ("ssize_t", "pread", ("int", "void *", "size_t", "off_t"), "unistd.h"),
    ("ssize_t", "pwrite", ("int", "const void *", "size_t", "off_t"), "unistd.h"),
    ("ssize_t", "readv", ("int", "const struct iovec *", "int"), "sys/uio.h"),
    ("ssize_t", "writev", ("int", "const struct iovec *", "int"), "sys/uio.h"),
    ("int", "close", ("int",), "unistd.h"),
    ("off_t", "lseek", ("int", "off_t", "int"), "unistd.h"),
    ("int", "pipe", ("int *",), "unistd.h"),
    ("int", "dup", ("int",), "unistd.h"),
    ("int", "dup2", ("int", "int"), "unistd.h"),
    ("int", "unlink", ("const char *",), "unistd.h"),
    ("int", "access", ("const char *", "int"), "unistd.h"),
    ("int", "stat", ("const char *", "struct stat *"), "sys/stat.h"),
    ("int", "fstat", ("int", "struct stat *"), "sys/stat.h"),
    ("int", "lstat", ("const char *", "struct stat *"), "sys/stat.h"),
    ("int", "mkdir", ("const char *", "mode_t"), "sys/stat.h"),
    ("int", "socket", ("int", "int", "int"), "sys/socket.h"),
    ("int", "socketpair", ("int", "int", "int", "int *"), "sys/socket.h"),
    ("int", "bind", ("int", "const struct sockaddr *", "socklen_t"), "sys/socket.h"),
    ("int", "connect", ("int", "const struct sockaddr *", "socklen_t"), "sys/socket.h"),
    ("int", "listen", ("int", "int"), "sys/socket.h"),
    ("int", "accept", ("int", "struct sockaddr *", "socklen_t *"), "sys/socket.h"),
    ("int", "shutdown", ("int", "int"), "sys/socket.h"),
    ("ssize_t", "recv", ("int", "void *", "size_t", "int"), "sys/socket.h"),
    ("ssize_t", "recvfrom", ("int", "void *", "size_t", "int", "struct sockaddr *", "socklen_t *"), "sys/socket.h"),
    ("ssize_t", "recvmsg", ("int", "struct msghdr *", "int"), "sys/socket.h"),
    ("ssize_t", "send", ("int", "const void *", "size_t", "int"), "sys/socket.h"),
    (
        "ssize_t",
        "sendto",
        ("int", "const void *", "size_t", "int", "const struct sockaddr *", "socklen_t"),
        "sys/socket.h",
    ),
    ("ssize_t", "sendmsg", ("int", "const struct msghdr *", "int"), "sys/socket.h"),
    ("int", "getsockopt", ("int", "int", "int", "void *", "socklen_t *"), "sys/socket.h"),
    ("int", "setsockopt", ("int", "int", "int", "const void *", "socklen_t"), "sys/socket.h"),
    ("int", "getsockname", ("int", "struct sockaddr *", "socklen_t *"), "sys/socket.h"),
    ("int", "getpeername", ("int", "struct sockaddr *", "socklen_t *"), "sys/socket.h"),
    ("int", "inet_pton", ("int", "const char *", "void *"), "arpa/inet.h"),
    ("int", "poll", ("struct pollfd *", "nfds_t", "int"), "poll.h"),
    ("int", "select", ("int", "fd_set *", "fd_set *", "fd_set *", "struct timeval *"), "sys/select.h"),
    ("FILE *", "fopen", ("const char *", "const char *"), "stdio.h"),
    ("FILE *", "fdopen", ("int", "const char *"), "stdio.h"),
    ("int", "fclose", ("FILE *",), "stdio.h"),
    ("int", "fflush", ("FILE *",), "stdio.h"),
    ("int", "fseek", ("FILE *", "long", "int"), "stdio.h"),
    ("long", "ftell", ("FILE *",), "stdio.h"),
    ("int", "nanosleep", ("const struct timespec *", "struct timespec *"), "time.h"),
    ("int", "clock_gettime", ("clockid_t", "struct timespec *"), "time.h"),
)
_ERRNO_SHIM_NAMES = frozenset(f[1] for f in ERRNO_SHIM_FUNCTIONS)
# A call in CIL output is a statement or the right-hand side of an assignment (CIL hoists calls
# out of expressions); a prototype has its return type before the name, so it never matches.
_CALL_SITE_RE = re.compile(
    r"(?:^|[=;{}:,!?&|()]|\breturn\b|\belse\b)[ \t]*(?:\([^()\n]*\)[ \t]*)?(?!(?:if|while|for|switch|return|sizeof)\b)(?P<name>[A-Za-z_]\w*)[ \t]*\(",
    re.MULTILINE,
)


def find_errno_shim_calls(instrumented_source: str) -> list[str]:
    """Shimmed libc functions the slice calls, when its errno is the stub's global (else [])."""
    text = instrumented_source or ""
    if not re.search(rf"\b{ERRNO_SHIM_GLOBAL}\b", text):
        return []
    called = {m.group("name") for m in _CALL_SITE_RE.finditer(text)} & _ERRNO_SHIM_NAMES
    return [name for _ret, name, _params, _hdr in ERRNO_SHIM_FUNCTIONS if name in called]


# What a libc call writes or returns that the E-ACSL runtime cannot see (F17,
# docs/plans/phase1-review.md). E-ACSL tracks only memory the instrumented code allocates or
# writes: with -rte-initialized, a value libc wrote through an out-parameter fails `\initialized`
# at its first read (`strtol`'s endptr, `getsockname`'s address), and with --libc-replacements and
# --validate-format-strings a buffer libc owns (`strerror`'s string, `gmtime`'s struct) is
# "unallocated". Each listed function the slice calls goes through the same `-Wl,--wrap` wrapper
# as the errno shim (a function can be wrapped once), which after the real call:
#   - `post`: marks the bytes the call wrote initialized, through FC_INIT, which skips memory the
#     runtime does not track (initializing it would write a shadow the runtime never mapped);
#   - `copy`: "string" or "struct", copies the result into a buffer of the shim object, inside
#     the executable's global segment that the runtime shadows, registers that buffer once,
#     marks the copied bytes initialized and returns it. libc's own block cannot be registered:
#     it lies outside every shadowed segment. One buffer per function keeps the libc contract
#     (the result is overwritten by the next call); a string is cut at EACSL_SHIM_STRING_MAX - 1.
# Memory libc allocates with malloc needs nothing: the runtime defines malloc, and libc's strdup
# or getline call it. Their contents still need `post` (libc writes them). `pre` captures inputs
# the call may overwrite (an in/out length). Parameters are a0..aN and the result is r.
# Entries: name -> (return type, parameter types, header, pre, post, copy). The signature of a
# function also in ERRNO_SHIM_FUNCTIONS must match it (tests check this).
EACSL_SHIM_STRING_MAX = 1024
_SOCKLEN_IN = "socklen_t fc_in = {len} ? *{len} : 0;"
_SOCKADDR_OUT = "if ({cond} && {len}) {{ FC_INIT({addr}, FC_MIN(fc_in, *{len})); FC_INIT({len}, sizeof *{len}); }}"
_ENDPTR = "FC_INIT(a1, sizeof *a1);"
EACSL_LIBC_EFFECTS: dict[str, tuple[str, tuple[str, ...], str, str, str, str | None]] = {
    # Out-parameters.
    **{
        name: (ret, ("const char *", "char **", *extra), hdr, "", _ENDPTR, None)
        for name, ret, extra, hdr in (
            ("strtol", "long", ("int",), "stdlib.h"),
            ("strtoll", "long long", ("int",), "stdlib.h"),
            ("strtoul", "unsigned long", ("int",), "stdlib.h"),
            ("strtoull", "unsigned long long", ("int",), "stdlib.h"),
            ("strtoimax", "intmax_t", ("int",), "inttypes.h"),
            ("strtoumax", "uintmax_t", ("int",), "inttypes.h"),
            ("strtod", "double", (), "stdlib.h"),
            ("strtof", "float", (), "stdlib.h"),
            ("strtold", "long double", (), "stdlib.h"),
        )
    },
    "read": ("ssize_t", ("int", "void *", "size_t"), "unistd.h", "", "if (r > 0) FC_INIT(a1, r);", None),
    "pread": ("ssize_t", ("int", "void *", "size_t", "off_t"), "unistd.h", "", "if (r > 0) FC_INIT(a1, r);", None),
    # With MSG_TRUNC, recv and recvfrom return the packet's real length, which can exceed `len`.
    "recv": (
        "ssize_t",
        ("int", "void *", "size_t", "int"),
        "sys/socket.h",
        "",
        "if (r > 0) FC_INIT(a1, FC_MIN((size_t)r, a2));",
        None,
    ),
    "recvfrom": (
        "ssize_t",
        ("int", "void *", "size_t", "int", "struct sockaddr *", "socklen_t *"),
        "sys/socket.h",
        _SOCKLEN_IN.format(len="a5"),
        "if (r > 0) FC_INIT(a1, FC_MIN((size_t)r, a2)); " + _SOCKADDR_OUT.format(cond="r >= 0", addr="a4", len="a5"),
        None,
    ),
    "readv": (
        "ssize_t",
        ("int", "const struct iovec *", "int"),
        "sys/uio.h",
        "",
        "if (r > 0) fc_init_iov(a1, a2, r);",
        None,
    ),
    "recvmsg": (
        "ssize_t",
        ("int", "struct msghdr *", "int"),
        "sys/socket.h",
        "socklen_t fc_name_in = a1 ? a1->msg_namelen : 0; size_t fc_ctl_in = a1 ? a1->msg_controllen : 0;",
        "if (r >= 0 && a1) { fc_init_iov(a1->msg_iov, a1->msg_iovlen, r); "
        "FC_INIT(a1->msg_name, FC_MIN(fc_name_in, a1->msg_namelen)); "
        "FC_INIT(a1->msg_control, FC_MIN(fc_ctl_in, a1->msg_controllen)); "
        "FC_INIT(&a1->msg_namelen, sizeof a1->msg_namelen); "
        "FC_INIT(&a1->msg_controllen, sizeof a1->msg_controllen); "
        "FC_INIT(&a1->msg_flags, sizeof a1->msg_flags); }",
        None,
    ),
    "accept": (
        "int",
        ("int", "struct sockaddr *", "socklen_t *"),
        "sys/socket.h",
        _SOCKLEN_IN.format(len="a2"),
        _SOCKADDR_OUT.format(cond="r >= 0", addr="a1", len="a2"),
        None,
    ),
    **{
        name: (
            "int",
            ("int", "struct sockaddr *", "socklen_t *"),
            "sys/socket.h",
            _SOCKLEN_IN.format(len="a2"),
            _SOCKADDR_OUT.format(cond="r == 0", addr="a1", len="a2"),
            None,
        )
        for name in ("getsockname", "getpeername")
    },
    "getsockopt": (
        "int",
        ("int", "int", "int", "void *", "socklen_t *"),
        "sys/socket.h",
        _SOCKLEN_IN.format(len="a4"),
        _SOCKADDR_OUT.format(cond="r == 0", addr="a3", len="a4"),
        None,
    ),
    "socketpair": (
        "int",
        ("int", "int", "int", "int *"),
        "sys/socket.h",
        "",
        "if (r == 0) FC_INIT(a3, 2 * sizeof *a3);",
        None,
    ),
    "pipe": ("int", ("int *",), "unistd.h", "", "if (r == 0) FC_INIT(a0, 2 * sizeof *a0);", None),
    "inet_pton": (
        "int",
        ("int", "const char *", "void *"),
        "arpa/inet.h",
        "",
        "if (r == 1) FC_INIT(a2, a0 == AF_INET ? 4 : 16);",
        None,
    ),
    **{
        name: ("int", (first, "struct stat *"), "sys/stat.h", "", "if (r == 0) FC_INIT(a1, sizeof *a1);", None)
        for name, first in (("stat", "const char *"), ("fstat", "int"), ("lstat", "const char *"))
    },
    "clock_gettime": (
        "int",
        ("clockid_t", "struct timespec *"),
        "time.h",
        "",
        "if (r == 0) FC_INIT(a1, sizeof *a1);",
        None,
    ),
    "gettimeofday": (
        "int",
        ("struct timeval *", "void *"),
        "sys/time.h",
        "",
        "if (r == 0) FC_INIT(a0, sizeof *a0);",
        None,
    ),
    "time": ("time_t", ("time_t *",), "time.h", "", "FC_INIT(a0, sizeof *a0);", None),
    "nanosleep": (
        "int",
        ("const struct timespec *", "struct timespec *"),
        "time.h",
        "",
        "if (r != 0) FC_INIT(a1, sizeof *a1);",
        None,
    ),
    "poll": (
        "int",
        ("struct pollfd *", "nfds_t", "int"),
        "poll.h",
        "",
        "if (r >= 0) FC_INIT(a0, a1 * sizeof *a0);",
        None,
    ),
    "select": (
        "int",
        ("int", "fd_set *", "fd_set *", "fd_set *", "struct timeval *"),
        "sys/select.h",
        "",
        "if (r >= 0) { FC_INIT(a1, sizeof *a1); FC_INIT(a2, sizeof *a2); FC_INIT(a3, sizeof *a3); }",
        None,
    ),
    **{
        name: ("struct tm *", ("const time_t *", "struct tm *"), "time.h", "", "if (r) FC_INIT(a1, sizeof *a1);", None)
        for name in ("gmtime_r", "localtime_r")
    },
    "fgets": ("char *", ("char *", "int", "FILE *"), "stdio.h", "", "if (r) FC_INIT(a0, strlen(a0) + 1);", None),
    "fread": ("size_t", ("void *", "size_t", "size_t", "FILE *"), "stdio.h", "", "FC_INIT(a0, r * a1);", None),
    # r is strlen(src): strlcpy writes min(r, size - 1) bytes and a NUL, nothing when size is 0.
    "strlcpy": (
        "size_t",
        ("char *", "const char *", "size_t"),
        "string.h",
        "",
        "if (a2) FC_INIT(a0, FC_MIN(r, a2 - 1) + 1);",
        None,
    ),
    # strlcat writes after the old string (it only reads that one), and nothing when dst holds no
    # NUL within size; then r is size + strlen(src), else old length + strlen(src).
    "strlcat": (
        "size_t",
        ("char *", "const char *", "size_t"),
        "string.h",
        "size_t fc_d = a2 ? strnlen(a0, a2) : 0;",
        "if (fc_d < a2) FC_INIT(a0 + fc_d, FC_MIN(r - fc_d, a2 - fc_d - 1) + 1);",
        None,
    ),
    # Blocks libc allocates through the runtime's malloc and fills itself.
    "strdup": ("char *", ("const char *",), "string.h", "", "if (r) FC_INIT(r, strlen(r) + 1);", None),
    "strndup": ("char *", ("const char *", "size_t"), "string.h", "", "if (r) FC_INIT(r, strlen(r) + 1);", None),
    "realpath": ("char *", ("const char *", "char *"), "stdlib.h", "", "if (r) FC_INIT(r, strlen(r) + 1);", None),
    "getline": (
        "ssize_t",
        ("char **", "size_t *", "FILE *"),
        "stdio.h",
        "",
        "FC_INIT(a0, sizeof *a0); FC_INIT(a1, sizeof *a1); if (r >= 0 && *a0) FC_INIT(*a0, (size_t)r + 1);",
        None,
    ),
    # Results in libc's own static storage.
    **{
        name: (ret, params, hdr, "", "", "string")
        for name, ret, params, hdr in (
            ("strerror", "char *", ("int",), "string.h"),
            ("strsignal", "char *", ("int",), "string.h"),
            ("inet_ntoa", "char *", ("struct in_addr",), "arpa/inet.h"),
            ("gai_strerror", "const char *", ("int",), "netdb.h"),
            ("ctime", "char *", ("const time_t *",), "time.h"),
            ("asctime", "char *", ("const struct tm *",), "time.h"),
        )
    },
    **{name: ("struct tm *", ("const time_t *",), "time.h", "", "", "struct") for name in ("gmtime", "localtime")},
}
# Functions a supported libc may not declare (glibc has strlcpy/strlcat from 2.38 only; Debian
# bookworm's 2.36 lacks them). The shim declares them itself, a compatible redeclaration where the
# header has them, so an older libc does not fail the -Werror shim and drop every other effect.
# Their `__real_` is weak: when libc lacks the symbol and the target's fallback is static (its calls
# are then never wrapped), the unused wrapper must not fail the link on an undefined `__real_`.
EACSL_SHIM_OWN_PROTOTYPES = frozenset({"strlcpy", "strlcat"})


def find_eacsl_effect_calls(instrumented_source: str) -> list[str]:
    """Functions of EACSL_LIBC_EFFECTS the slice calls, in table order."""
    called = {m.group("name") for m in _CALL_SITE_RE.finditer(instrumented_source or "")}
    return [name for name in EACSL_LIBC_EFFECTS if name in called]


_SHIM_PRELUDE = (
    "void *__e_acsl_store_block(void *ptr, size_t size);\n"
    "void __e_acsl_initialize(void *ptr, size_t size);\n"
    "int __e_acsl_valid(void *ptr, size_t size, void *ptr_base, void *addrof_base);\n"
    "/* templates/eacsl_runtime/fuzz_init.c sets it once the runtime is initialized. Before that,\n"
    " * libFuzzer and the runtime's own initialization (it read()s /proc/self/maps) make wrapped calls\n"
    " * while the shadow is not mapped. Without the init hook nothing says when the runtime is ready,\n"
    " * so the effects stay off. */\n"
    "extern int __fc_eacsl_runtime_ready __attribute__((weak));\n"
    "#define FC_READY (&__fc_eacsl_runtime_ready && __fc_eacsl_runtime_ready)\n"
    "/* Only memory the runtime tracks: its shadow is mapped. */\n"
    "#define FC_INIT(p, n) do { void *fc_p = (void *)(p); size_t fc_n = (size_t)(n); \\\n"
    "    if (FC_READY && fc_p && fc_n && __e_acsl_valid(fc_p, fc_n, fc_p, (void *)0)) \\\n"
    "        __e_acsl_initialize(fc_p, fc_n); } while (0)\n"
    "#define FC_MIN(a, b) ((a) < (b) ? (a) : (b))\n"
    "#include <sys/uio.h>\n"
    "/* The first `total` bytes a scatter read stored, across the iovec. */\n"
    "static __attribute__((unused)) void fc_init_iov(const struct iovec *iov, size_t n, size_t total)\n"
    "{\n"
    "    for (size_t i = 0; iov && i < n && total > 0; i++) {\n"
    "        size_t k = FC_MIN(iov[i].iov_len, total);\n"
    "        FC_INIT(iov[i].iov_base, k);\n"
    "        total -= k;\n"
    "    }\n"
    "}\n"
)


def _shim_copy_lines(name: str, copy: str) -> tuple[str, list[str]]:
    """(static storage, statements) returning a tracked copy of `r`."""
    buf, reg = f"fc_{name}_buf", f"fc_{name}_registered"
    if copy == "string":
        storage = f"static char {buf}[{EACSL_SHIM_STRING_MAX}];\nstatic int {reg};\n"
        lines = [
            "if (!r || !FC_READY) return r;",
            f"size_t fc_n = strlen(r) + 1; if (fc_n > sizeof {buf}) fc_n = sizeof {buf};",
            f"memcpy({buf}, r, fc_n); {buf}[fc_n - 1] = 0;",
            f"if (!{reg}) {{ __e_acsl_store_block({buf}, sizeof {buf}); {reg} = 1; }}",
            f"__e_acsl_initialize({buf}, fc_n);",
            f"return {buf};",
        ]
    else:
        storage = f"static struct tm {buf};\nstatic int {reg};\n"
        lines = [
            "if (!r || !FC_READY) return r;",
            f"{buf} = *r;",
            f"if (!{reg}) {{ __e_acsl_store_block(&{buf}, sizeof {buf}); {reg} = 1; }}",
            f"__e_acsl_initialize(&{buf}, sizeof {buf});",
            f"return &{buf};",
        ]
    return storage, lines


def generate_errno_shim_source(names: Sequence[str], effects: Sequence[str] = ()) -> str:
    """
    C source of the `__wrap_<name>` wrappers, type-checked against the host prototypes: errno sync
    for `names` (ERRNO_SHIM_FUNCTIONS) and the E-ACSL effects of `effects` (EACSL_LIBC_EFFECTS).
    A function in both gets one wrapper doing both.
    """
    table = {f[1]: (f[0], f[2], f[3]) for f in ERRNO_SHIM_FUNCTIONS}
    effect_names = [n for n in effects if n in EACSL_LIBC_EFFECTS]
    headers = ["errno.h", "stddef.h", "stdint.h", "string.h", "sys/types.h"]
    bodies: list[str] = []
    for name in [*names, *(n for n in effect_names if n not in names)]:
        effect = EACSL_LIBC_EFFECTS.get(name) if name in effect_names else None
        if name in table:
            ret, params, header = table[name]
        else:
            assert effect is not None
            ret, params, header = effect[0], effect[1], effect[2]
        if header not in headers:
            headers.append(header)
        decls = ", ".join(f"{p} a{i}" for i, p in enumerate(params))
        args = ", ".join(f"a{i}" for i in range(len(params)))
        sync = name in names
        storage = ""
        lines: list[str] = []
        if effect and effect[3]:
            lines.append(effect[3])
        if name == "close":
            # The process's stdio belongs to libFuzzer and the E-ACSL runtime. A target handed descriptor 2 as its
            # socket closes it on teardown: every later report is lost and the next failure is a silent exit 77.
            lines.append("if (a0 >= 0 && a0 <= 2) return 0;")
        if sync:
            lines.append(f"errno = {ERRNO_SHIM_GLOBAL};")
        lines.append(f"{ret} r = __real_{name}({args});")
        if sync:
            lines.append(f"{ERRNO_SHIM_GLOBAL} = errno;")
        if effect and effect[4]:
            lines.append(effect[4])
        if effect and effect[5]:
            storage, copy_lines = _shim_copy_lines(name, effect[5])
            lines.extend(copy_lines)
        else:
            lines.append("return r;")
        body = "".join(f"    {line}\n" for line in lines)
        own = name in EACSL_SHIM_OWN_PROTOTYPES
        proto = f"{ret} {name}({', '.join(params)});\n" if own else ""
        bodies.append(
            proto
            + f"extern __typeof__({name}) __real_{name}{' __attribute__((weak))' if own else ''};\n"
            + storage
            + f"{ret} __wrap_{name}({decls})\n{{\n{body}}}\n"
            f"static __typeof__({name}) *const fc_errno_shim_check_{name} __attribute__((unused)) = __wrap_{name};\n"
        )
    return (
        "/* Generated by run_eacsl_fuzz.py: link-only libc shim for E-ACSL builds.\n"
        f" * templates/fc_stubs/errno.h maps the target's errno to {ERRNO_SHIM_GLOBAL}; each errno wrapper hands\n"
        " * that value to libc and copies libc's errno back, so the target sees what the call set. The\n"
        " * E-ACSL effects tell the runtime what the call wrote (eacsl_toolchain.EACSL_LIBC_EFFECTS). */\n"
        "#define _GNU_SOURCE 1\n"
        + "".join(f"#include <{h}>\n" for h in headers)
        + f"\nextern int {ERRNO_SHIM_GLOBAL};\n"
        + (_SHIM_PRELUDE if effect_names else "")
        + "\n"
        + "\n".join(bodies)
    )


def build_errno_shim_object(
    instrumented_c: Path,
    out_dir: Path,
    runner: Callable[..., Any] = subprocess.run,
    compiler: str = "clang",
    timeout: float | None = None,
) -> dict[str, Any]:
    """
    Generate and compile `eacsl_errno_shim.o` when the slice reads errno through the stub's global
    and calls shimmed functions, or calls a function of EACSL_LIBC_EFFECTS. Returns {status:
    none|built|error, wrapped, eacsl_effects, unshimmed, object, source, wrap_flags, reason}; the
    caller links `object` with `wrap_flags`. When the effects do not compile against the host libc,
    the errno wrappers alone are retried and `effects_error` says why.
    """
    try:
        text = Path(instrumented_c).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {
            "status": "error",
            "reason": f"cannot read instrumented source: {exc}",
            "wrapped": [],
            "eacsl_effects": [],
            "unshimmed": [],
        }
    names = find_errno_shim_calls(text)
    effects = find_eacsl_effect_calls(text)
    raw_calls = {m.group("name") for m in _CALL_SITE_RE.finditer(text)}
    unshimmed = sorted((raw_calls & _ERRNO_SHIM_NAMES) - set(names))
    if unshimmed:
        import warnings

        warnings.warn(
            f"libc call(s) without errno shim: {', '.join(unshimmed)}",
            UserWarning,
            stacklevel=2,
        )
    if not names and not effects:
        return {"status": "none", "wrapped": [], "eacsl_effects": [], "unshimmed": unshimmed}
    out_dir.mkdir(parents=True, exist_ok=True)
    src = out_dir / "eacsl_errno_shim.c"
    obj = out_dir / "eacsl_errno_shim.o"

    def _compile(errno_names: list[str], effect_names: list[str]) -> tuple[int, str]:
        src.write_text(generate_errno_shim_source(errno_names, effect_names), encoding="utf-8", newline="\n")
        cmd = [compiler, "-c", "-O1", "-Werror", "-std=gnu17", str(src), "-o", str(obj)]
        try:
            proc = runner(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
            return proc.returncode, (proc.stderr or "")[-4000:]
        except subprocess.TimeoutExpired:
            return 124, f"{compiler} exceeded the {timeout} s build time limit"
        except OSError as exc:
            return 127, str(exc)

    found_effects = effects
    effects_error = ""
    rc, err = _compile(names, effects)
    if rc != 0 and effects and names:
        effects_error = f"E-ACSL libc effects failed to compile: {err}"
        effects = []
        rc, err = _compile(names, [])
    if rc != 0:
        return {
            "status": "error",
            "reason": f"errno shim failed to compile: {err}"
            if names
            else f"E-ACSL libc effects failed to compile: {err}",
            "wrapped": names,
            "eacsl_effects": found_effects,
            "unshimmed": unshimmed,
        }
    wrapped = [*names, *(n for n in effects if n not in names)]
    result: dict[str, Any] = {
        "status": "built",
        "wrapped": wrapped,
        "eacsl_effects": effects,
        "unshimmed": unshimmed,
        "object": str(obj),
        "source": str(src),
        "wrap_flags": "-Wl," + ",".join(f"--wrap={n}" for n in wrapped),
    }
    if effects_error:
        result["effects_error"] = effects_error
    return result


def patch_format_runtime(text: str) -> tuple[str, list[str]]:
    """
    Apply EACSL_FORMAT_RUNTIME_PATCH to the text of e_acsl_stdio.c. Returns (patched text, names
    of the anchors not found exactly once); on any missing anchor the text comes back unchanged.
    """
    missing = [name for name, anchor, _ in _FMT_HUNKS if text.count(anchor) != 1 or _FMT_PATCH_TAG in text]
    if missing:
        return text, missing
    for _, anchor, replacement in _FMT_HUNKS:
        text = text.replace(anchor, replacement, 1)
    return text, []


def eacsl_share_dir(eacsl_bin: str) -> Path | None:
    """E-ACSL's share directory as e-acsl-gcc computes it (`$BASEDIR/../share/frama-c/share/e-acsl`), or None."""
    path = Path(eacsl_bin)
    if len(path.parts) == 1:
        found = shutil.which(eacsl_bin)
        if not found:
            return None
        path = Path(found)
    for base in dict.fromkeys((path.parent, path.resolve().parent)):
        share = base.parent / "share" / "frama-c" / "share" / "e-acsl"
        if (share / "e_acsl_rtl.c").is_file():
            return share
    return None


def _tree_digest(root: Path) -> str:
    # The hunks' text too: an edited patch that keeps its tag must not reuse a copy patched by the old one.
    h = hashlib.sha256(EACSL_FORMAT_RUNTIME_PATCH.encode())
    for hunk in _FMT_HUNKS:
        h.update("\0".join(hunk).encode() + b"\0")
    for p in sorted(q for q in root.rglob("*") if q.is_file()):
        h.update(p.relative_to(root).as_posix().encode() + b"\0" + p.read_bytes() + b"\0")
    return h.hexdigest()[:12]


def prepare_patched_eacsl_share(src: Path, dest_root: Path) -> dict[str, str]:
    """
    A copy of the E-ACSL share directory `src` under `dest_root/<patch>-<digest>/e-acsl` with
    EACSL_FORMAT_RUNTIME_PATCH applied to its e_acsl_stdio.c, for `e-acsl-gcc --e-acsl-share`.
    The image is never written. The digest covers the patch (tag and hunks) and every file of `src`,
    so a new Frama-C or an edited patch gets a new copy; concurrent builds publish one copy with an atomic rename and reuse it.
    `status` is `applied` (with `share`) or `not_applied` (with `reason`: no share, a moved anchor).
    """
    src = Path(src)
    out = {"patch": EACSL_FORMAT_RUNTIME_PATCH}
    stdio = src / _EACSL_STDIO_REL
    if not stdio.is_file():
        return {**out, "status": "not_applied", "reason": f"no {_EACSL_STDIO_REL} under {src.as_posix()}"}
    patched, missing = patch_format_runtime(stdio.read_text(encoding="utf-8", errors="surrogateescape"))
    if missing:
        return {
            **out,
            "status": "not_applied",
            "reason": f"anchor(s) not found exactly once in {_EACSL_STDIO_REL}: {', '.join(missing)}",
        }
    final = Path(dest_root) / f"{EACSL_FORMAT_RUNTIME_PATCH}-{_tree_digest(src)}"
    applied = {**out, "status": "applied", "share": Path(os.path.abspath(final / "e-acsl")).as_posix()}
    if (final / ".complete").is_file():
        return applied
    Path(dest_root).mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix=".tmp-", dir=dest_root))
    try:
        shutil.copytree(src, tmp / "e-acsl")
        target = tmp / "e-acsl" / _EACSL_STDIO_REL
        target.chmod(0o644)
        target.write_text(patched, encoding="utf-8", errors="surrogateescape", newline="\n")
        (tmp / ".complete").write_text(EACSL_FORMAT_RUNTIME_PATCH + "\n", encoding="utf-8")
        try:
            os.rename(tmp, final)
        except OSError:
            if not (final / ".complete").is_file():
                raise
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return applied
