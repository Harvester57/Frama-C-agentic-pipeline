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
    enters the instrumented sources (so the fallback numbering stays stable).
"""

from __future__ import annotations

import re
import shlex
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from framac_common import framac_cpp_wrapper, resolve_fc_stubs_dir  # noqa: E402

# Frama-C has no 128-bit integer type, and host headers such as <linux/types.h> declare
# `__int128` typedefs only when the compiler predefines __SIZEOF_INT128__.
# glibc's <math.h> expands isnan, isinf, isfinite, isnormal and fpclassify to GCC builtins unless
# __SUPPORT_SNAN__ is defined; Frama-C does not know the builtins and prints K&R prototypes for them,
# which clang refuses ("cannot redeclare builtin function '__builtin_isnan'", QCBOR run-4). With it,
# glibc calls __isnan, __isinf, __finite, __fpclassify. signbit is mapped by EACSL_STUBS_SUBDIR's math.h.
EACSL_DEFINES = ("-D__FRAMAC_EACSL__", "-D_Float128=double", "-U__SIZEOF_INT128__", "-D__SUPPORT_SNAN__")
# Header shims for the E-ACSL frontend only (templates/fc_stubs/eacsl): first on its include path,
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
# which re-instruments proven annotations (docs/upstream/frama-c-eacsl-assert-print-data-alias.md).
EACSL_FULL_MTRACKING_FLAG = "-e-acsl-full-mtracking"
EACSL_FC_EXTRA_FLAGS = (EACSL_FULL_MTRACKING_FLAG,)
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
_FUZZER_INITIALIZE_DEF_RE = re.compile(r"\bLLVMFuzzerInitialize\s*\([^;{)]*\)\s*\{")
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
    joined_user = " ".join(pre + forced)
    front: list[str] = list(EACSL_DEFINES)
    if full_mtracking:
        front.extend(EACSL_FULL_MTRACKING_DEFINES)
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
    # (docs/upstream/frama-c-eacsl-iff-labelled-term.md).
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
    r"^(?P<indent>[ \t]*)__e_acsl_store_block\(\(void \*\)\(& ?(?P<name>[A-Za-z_]\w*)\),\s*\d+UL\);$"
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


_READONLY_SCALAR_RE = re.compile(
    r"(?P<store>^[ \t]*__e_acsl_store_block\(\(void \*\)\(& ?(?P<name>[A-Za-z_]\w*)\),\s*\d+UL\);\n"
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

_FALLBACK_UNDEFINED_RE = re.compile(r"undefined reference to [`'\"](?P<name>[A-Za-z_]\w*(?:_fallback_|_va_)\d+)['\"]")
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
        return f"void {fb['name']}() {{ errno = ENOSYS; }}\n"
    if "*" in ret:
        return f"void *{fb['name']}() {{ errno = ENOSYS; return 0; }}\n"
    return f"long {fb['name']}() {{ errno = ENOSYS; return -1; }}\n"


def generate_fallback_source(
    fallbacks: list[dict[str, Any]], force_enosys: bool = False
) -> tuple[str, list[dict[str, str]]]:
    """
    Emit C definitions for the fallbacks: forward to the real libc function when the base
    is known and the signature is parseable, otherwise set errno=ENOSYS and fail.
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
            stmt = f"{call};" if ret.strip() == "void" else f"return {call};"
            bodies.append(f"{ret} {fb['name']}({', '.join(decls) or 'void'}) {{ {stmt} }}\n")
            mode = "forward"
        else:
            bodies.append(_enosys_body(fb))
        records.append({"name": fb["name"], "base": fb["base"], "mode": mode})
    text = (
        "/* Generated by run_eacsl_fuzz.py: link-only definitions for Variadic fallbacks.\n"
        " * Never add this file to the instrumented sources (it would shift the fallback numbering). */\n"
        "#define _GNU_SOURCE 1\n" + "".join(f"#include <{h}>\n" for h in headers) + "\n" + "".join(bodies)
    )
    return text, records


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
