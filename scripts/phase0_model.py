#!/usr/bin/env python3
"""
Phase 0 model (docs/plans/archive/phase0-implementation-plan.md step I3): the inventory and the call graph of the
target, from one Frama-C parse per link unit of the build capture, named as Eva and WP will name them.
Stdlib only.

    phase0_model.py run [--capture workspace/reports/build_capture.json]
                        [--out workspace/reports/phase0_model.json] [--jobs N] [--no-broker]
                        [--alias | --no-alias]
                        [--threat-model PATH] [--metadata run-metadata.json] [--codeql PATH] [--state state]
    phase0_model.py selftest

`run` reads the build capture (scripts/build_capture.py), the scratch tree it names and the run's
snapshot (scripts/target_env.py), so it runs in a container started with the wrapper's -Scratch
(sh: --scratch), in the analysis image:

  1. parse jobs: one per link unit that is not a test unit, over the unit's own sources with each file's
     own flags. Units that compile the same sources with the same flags share one parse. Jobs run in
     parallel, each under a `parse` lease of the container broker (resources.py run --class parse);
  2. each parse loads scripts/phase0_dump.ml: defined functions (kernel name, source name, definition
     line span, storage, signature, loops, cyclomatic complexity), direct calls, indirect call sites
     with the called signature, and the functions whose address is taken;
  3. the target's headers outside the project come from the snapshot (`-idirafter <snapshot>/<dir>`,
     after Frama-C's own libc), the generated headers from the build tree, so no target package is
     needed where the parse runs;
  4. a job Frama-C cannot parse falls back to GCC `-fcallgraph-info` on its compile commands: functions
     and direct edges, with indirect call sites left unresolved, flagged with Frama-C's first error.
     The paths GCC prints resolve against the compile's directory, then the tree (as in step 6);
  5. model-wide resolution, as the linker sees it:
     - a call to a function the unit does not define resolves to a global of the same name in a unit
       it links, else in a unit that links it, else it is an external (kept per caller under
       `external_calls`: the input readers it calls decide its trust);
     - an indirect call site resolves to every address-taken function of the same signature in the
       programs (executables, shared libraries, unconsumed static libraries) that contain the unit;
     - a project function passed to pthread_create/thrd_create is a thread entry, and its unit is
       concurrent; one passed to another external (qsort, signal) is a callback;
  6. macro aliases: `cc -E -dD` per translation unit, keeping each object-like `#define a b` written in
     a project file whose value resolves (through other such aliases) to a defined function;
  7. entry points, link units and the test marking come from the build capture;
  8. trust (step I7, scripts/trust.py): each function's `trust` (untrusted or trusted, the deciding rule,
     whether it is on the trust boundary) from the library API, the input readers' call graph and the
     structured threat model (THREAT_MODEL.md, --threat-model); a missing one records `no_threat_model`.
     When the run's metadata enables CodeQL (--metadata) and its facts exist (--codeql, default
     workspace/reports/codeql_trust.json), they are merged as `trust.py run` merges them, so a model
     rebuilt after the CodeQL run keeps them: `trust.codeql` is `ok` with the facts used, `not_run`
     without the file, or the file's own status when it is not `ok` (no fact used). The summary printed
     at the end shows it under `trust`. `trust.py run` redoes the annotation after a CodeQL run.

With `--alias` (plan step I4; off by default, see docs/plans/archive/phase0-redesign.md §7 "Alias narrowing"), each
parse also loads scripts/phase0_alias.ml, which runs Frama-C's Alias plugin on the same AST and reports,
per indirect call site, the functions the called pointer may point to. A site's type-match candidates
are then intersected with them. A site keeps its full type match, with the reason recorded, when Alias
fails, times out (ALIAS_TIMEOUT_S), crashes, has no state there, finds no function in the pointer's
target, or names only functions outside the type match. Every site records which narrowing applied
(`narrowing`, `narrowing_reason`, `dropped`), and the edges a narrowed site keeps carry the source
`alias` next to `type-match`. Alias is flow-sensitive within a function but starts each function from
the global initializers only, so a function pointer reassigned in another function or another unit is
narrowed to its initializer: that is why it stays off by default.

Functions are identified as `file#name` (paths relative to the target root): same-named statics stay
apart, and a function defined in a project header (static inline) belongs to every unit compiling it.
A definition's file is the file whose text the build compiles. A source with line directives (flex's
`toke.c`, bison's `gram.c`: `#line 1 "gram.y"`) is parsed, and compiled by the GCC fallback and the
macro scan, from a copy with them blanked (blank_line_directives), so its definitions keep their own
file and physical lines; the job records them under `line_directives` with the directives Frama-C
ignored. When a line directive was in play anyway (one in a header), a definition located in a file
that is not a compiled source and does not hold it goes to the compiled source it was parsed from
(attribute_definition, dump schema 7 `root`) with `relocated_from` and a warning.
Every function, edge and alias carries its source. The output is workspace/reports/phase0_model.json
(schemas/phase0_model.schema.json). A failure is a status in the model, never a crash: the command exits
0 when the model was written, 1 when no model could be built (missing capture, dump module error), and
4 when Frama-C parsed none of the units (status `no_unit_parsed`: the model is written for its errors,
and Phase 0 stops there). Like the build capture's `needs_build_recipe`, `no_unit_parsed` is recorded in
the checkpoint (`--state`, scripts/checkpoint.py) with each unit's first error, so a resumed run shows
them and restarts at the model; a model that parses clears it.

Version 2 of the model (`schema_version`) records `external_calls`, `kernel_names`, `formals`, `writes`
and `param_sizes` on its functions; (S2 of docs/plans/templates-and-stubs-improvement-plan.md) each external's
first declaration and C text under `external_decls` (a variadic one with its `...`: declared_record), from
which scripts/stub_gen.py writes the stub skeletons (a model without it gets no skeletons); and, from dump schema 4 on, the parsed functions' `call_sites`
(each direct call with its string-literal arguments); from dump schema 6 on, the address flow the unit split
reads (scripts/unit_split.py): the parsed functions' `address_refs` (functions whose address the body takes)
and `global_refs` (globals it names), and the `init_functions` and `init_globals` each global's initializer
names. Consumers ask `model_features(model)` which of these a model has, so a version 1 model is recognized
the same way everywhere.

`selftest` compiles the dump module and checks it on a two-file program (a static collision, a
callback, an indirect call); the image build runs it, so a kernel upgrade that breaks the dump fails
there.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import re
import shlex
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_capture as bc  # noqa: E402
import target_env  # noqa: E402
from acsl_ast import AcslSyntaxError  # noqa: E402
from c_definitions import extract_functions_from_code  # noqa: E402
from framac_common import (  # noqa: E402
    atomic_write_json,
    augment_framac_cppflags,
    fold_messages,
    is_pre_c99_std,
    load_json_optional,
    restore_variadic_proto,
    utc_now,
)
from kernel_ast import compile_dump_module  # noqa: E402

# 2: every function record carries `external_calls`, `kernel_names` and `param_sizes` when callers pass
# sizes, and the parsed ones `formals` and `writes` (dump schema 3). Version 1 models may lack any of
# them: read them through `model_features`.
SCHEMA_VERSION = 2
DUMP_SOURCE = Path(__file__).resolve().parent / "phase0_dump.ml"
DUMP_OUT_ENV = "FRAMAC_P0_DUMP_OUT"
DEFAULT_CAPTURE = "workspace/reports/build_capture.json"
DEFAULT_OUT = "workspace/reports/phase0_model.json"
LOG_DIR = "workspace/reports/phase0_model"
MACHDEP = "gcc_x86_64"
GCC_TIMEOUT_S = 300
ERROR_CHARS = 400
# Exit code when Frama-C parsed no unit (build_capture.py uses 3 for needs_build_recipe).
NO_UNIT_PARSED_RC = 4
STATUS_NO_UNIT_PARSED = "no_unit_parsed"
# A unit's parse status when Frama-C failed and so did the GCC fallback: no function or edge of it is in the
# model (`gcc_fallback` says they came from GCC). Both are units Frama-C could not parse.
STATUS_UNPARSED = "unparsed"
FRAMAC_FAILED = ("gcc_fallback", STATUS_UNPARSED)
THREAD_SPAWNERS = {"pthread_create": 2, "thrd_create": 1}
SOURCE_FRAMAC = "frama-c-kernel"
SOURCE_GCC = "gcc-callgraph-info"
SOURCE_ALIAS = "alias"
ALIAS_SOURCE = Path(__file__).resolve().parent / "phase0_alias.ml"
ALIAS_PACKAGES = ("frama-c.kernel", "frama-c-alias.core", "unix")
ALIAS_OUT_ENV = "FRAMAC_P0_ALIAS_OUT"
ALIAS_TIMEOUT_ENV = "FRAMAC_P0_ALIAS_TIMEOUT"
# Fixed, not sized from the machine: it decides which sites are narrowed.
ALIAS_TIMEOUT_S = 300
ALIAS_DEFAULT = False  # I4: measured, not adopted (docs/plans/archive/phase0-redesign.md §7)

_LOC_RE = re.compile(r"^(?P<file>.+?):(?P<line>\d+)(?:-\d+)?(?::\d+(?:-\d+)?)?$")
_LINE_MARKER_RE = re.compile(r'^#\s*(?:line\s+)?\d+\s+"(?P<file>[^"]*)"')
_OBJECT_DEFINE_RE = re.compile(r"^#define\s+(?P<name>[A-Za-z_]\w*)\s+(?P<value>[A-Za-z_]\w*)\s*$")
_CI_NODE = re.compile(r'node: \{ title: "([^"]+)" label: "([^"\\]+)(?:\\n([^":]+):(\d+))?')
_CI_EDGE = re.compile(r'edge: \{ sourcename: "([^"]+)" targetname: "([^"]+)"')
_ERROR_RE = re.compile(r"\b(?:User Error|Error|error|Failure|fatal)\b")
# A line directive in a C source: `#line 12 "gram.y"`, or the GNU marker form `# 12 "gram.y"`.
_LINE_DIRECTIVE_RE = re.compile(rb"^[ \t]*#[ \t]*(?:line\b|[0-9])")
# What Frama-C says when it ignores one (the file does not exist relative to its working directory).
_IGNORED_LINE_DIRECTIVE_RE = re.compile(r"ignoring non-existing file '([^']*)', referenced in a line directive")
LINE_DIRECTIVE_DIR = "line-directives"
# Files whose text can hold a C definition the build compiles (a compiled source, a header, an included
# fragment), unlike a `.y`/`.l` grammar a line directive names.
C_TEXT_SUFFIXES = (".c", ".h", ".inc")

_SELFTEST_FILES = {
    "a.c": (
        "static int helper(int x) { return x + 1; }\n"
        "int twice(int x) { return 2 * x; }\n"
        "int apply(int (*f)(int), int x) { return f(x); }\n"
        "int run_a(int x) { return apply(twice, helper(x)); }\n"
        "int counter;\n"
        "void fill(int *p, int n) { for (int i = 0; i < n; i++) p[i] = 0; counter++; }\n"
        "int (*table[1])(int) = { twice };\n"
        "int use_table(int x) { return table[0](x); }\n"
        "struct cb_box { int (*fn)(int); };\n"
        "int use_local_table(int x) { static int (*const sl[1])(int) = { twice }; return sl[0](x); }\n"
        "int use_compound(int x) { const struct cb_box *b = &(struct cb_box){ .fn = twice }; return b->fn(x); }\n"
        "void (*use_cast(void))(void) { return (void (*)(void))twice; }\n"
        "static void __attribute__((constructor)) init_ctor(void) { counter = 1; }\n"
    ),
    "b.c": (
        "static int helper(int x) { return x - 1; }\n"
        "int apply(int (*f)(int), int x);\n"
        "int run_b(int x) { int s = 0; for (int i = 0; i < x; i++) s += helper(i); return s; }\n"
    ),
}


# ---------------------------------------------------------------------------------------------------
# Versions: what a model records
# ---------------------------------------------------------------------------------------------------

# The per-function facts later steps rely on, and what a consumer loses without each.
MODEL_FEATURES: dict[str, str] = {
    "external_calls": "no external calls (made before step I7): no dynamic_allocation blocker, no Tier 2 by "
    "allocation, no format/write detection, no input readers for trust",
    "formals": "no formals (dump before schema 3): pointer constness unknown, no bounded-buffer direction, "
    "so no Tier 1B by output buffer",
    "writes": "no write facts (dump before schema 3): Layer 3 frames fall back to pointer parameters, Layer 4 "
    "state writers are unknown",
    "trust": "no trust annotation (trust.py not run or failed): every function is taken as on an untrusted "
    "path, so only the structure decides tiers",
    "kernel_names": "no kernel names: a kernel-renamed static (f_0) cannot be mapped back to its file#name",
    "param_sizes": "no caller argument sizes (made before 55df295): harnesses and seeds size fixed buffers "
    "from defaults",
    "call_sites": "no call sites with their string-literal arguments (dump before schema 4): no sink argument "
    "is decided from the model (L5 text on a literal, L5 format strings), every one is left to WP",
    "address_flow": "no address-flow facts (dump before schema 6): the unit split follows every type-matched "
    "indirect call (scripts/unit_split.py), which can fold a callback-heavy unit into one cluster, and its "
    "clusters build with the unit's whole source list",
}


def model_features(model: dict | None) -> dict[str, bool]:
    """
    Which of `MODEL_FEATURES` the model records, the same way for every consumer (the DAG, trust,
    security properties). A version 2 model has them all but `trust`, which trust.py adds after the
    build; a version 1 model is read for them: a feature is present when any function (a Frama-C-parsed
    one for `formals` and `writes`, which the GCC fallback never has) carries it. `trust` is present when
    the model has the `trust` block or a function its `trust`. A model with no function has none.
    """
    if not isinstance(model, dict):
        return dict.fromkeys(MODEL_FEATURES, False)
    fns = [f for f in (model.get("functions") or {}).values() if isinstance(f, dict)]
    parsed = [f for f in fns if f.get("source") != SOURCE_GCC]
    try:
        version = int(model.get("schema_version") or 1)
    except (TypeError, ValueError):
        version = 1
    current = version >= 2 and bool(fns)
    return {
        "external_calls": current or any("external_calls" in f for f in fns),
        "formals": current or any("formals" in f for f in parsed),
        "writes": current or any("writes" in f for f in parsed),
        "trust": isinstance(model.get("trust"), dict) or any(isinstance(f.get("trust"), dict) for f in fns),
        "kernel_names": current or any("kernel_names" in f for f in fns),
        "param_sizes": current or any("param_sizes" in f for f in fns),
        # Not implied by the version: dump schema 4 adds it to a version 2 model.
        "call_sites": any("call_sites" in f for f in parsed),
        # Nor this one: dump schema 6.
        "address_flow": any("address_refs" in f for f in parsed),
    }


def missing_features(model: dict | None) -> list[str]:
    """`MODEL_FEATURES` the model lacks, in their order."""
    have = model_features(model)
    return [name for name in MODEL_FEATURES if not have[name]]


def header_declared_functions(model: dict, header: str) -> set[str]:
    """Audit function declarations for a project header directly from the Phase 0 model."""
    norm_h = posixpath.normpath(header.replace("\\", "/")).lstrip("/")
    decls: set[str] = set()
    for fid, fn in (model.get("functions") or {}).items():
        file = posixpath.normpath(str(fn.get("file") or "").replace("\\", "/")).lstrip("/")
        if file == norm_h:
            decls.add(str(fn.get("name") or fid.rsplit("#", 1)[-1]))
    for name, info in (model.get("external_decls") or {}).items():
        decl_loc = str(info.get("decl") or "")
        loc_file = posixpath.normpath(decl_loc.partition(":")[0].replace("\\", "/")).lstrip("/")
        if loc_file == norm_h:
            decls.add(name)
    return decls


def declared_record(d: dict) -> dict:
    """
    One `external_decls` entry from a dump's declared function: its first declaration (`decl`), its C text
    as the source wrote it (`proto`: the Variadic plugin's `__va_params` formal back to `...`, so a stub
    redeclaration matches the real prototype and stub_check never calls it with a fabricated pointer), and
    the kernel's `signature` (translated, as for definitions: `__va_params` still marks the variadic ones).
    """
    return {"decl": d["decl"], "proto": restore_variadic_proto(str(d["proto"])), "signature": d.get("signature") or ""}


# ---------------------------------------------------------------------------------------------------
# Paths and flags
# ---------------------------------------------------------------------------------------------------


def tree_rel(path: str, tree: str, cwd: str | None = None) -> str | None:
    """
    A Frama-C or gcc location path relative to the tree, or None. A relative path is resolved against
    the directory the tool ran in (`cwd`, absolute: GCC prints `-I../include` headers relative to the
    compile's directory), then against the tree (where Frama-C runs); the first that exists inside the
    tree wins, else the first inside it. Frama-C prints its own files under symbolic roots
    (`FRAMAC_SHARE/libc/...`).
    """
    if not path or path.startswith(("FRAMAC_", "<")):
        return None
    if posixpath.isabs(path):
        return bc.tree_rel(posixpath.normpath(path), tree)
    found: list[str] = []
    for base in dict.fromkeys(b for b in (cwd, tree) if b):
        rel = bc.tree_rel(posixpath.normpath(posixpath.join(base, path)), tree)
        if rel is not None and rel not in found:
            found.append(rel)
    for rel in found:
        if os.path.exists(posixpath.join(tree, rel)):
            return rel
    return found[0] if found else None


def _call_sites(fn: dict) -> list[dict] | None:
    """
    The direct calls of a function body with their string-literal arguments (dump schema 4, plan
    steps M2 and M5): [{callee, line, literals: {argument index: text}[, initializer]}], in body
    order. None when the dump predates them, so a consumer can tell "no literal" from "not recorded".
    `initializer` (dump schema 5, package E of docs/plans/metacsl-exploitation-plan.md): the call is
    the initializer of a local (`int n = f(x);`), where MetAcsl generates no \\calling, \\writing or
    \\strong_invariant instance. Absent when the dump does not say.
    """
    calls = [c for c in fn.get("calls") or [] if not c.get("indirect")]
    if any("literal_args" not in c for c in calls) or (not calls and "calls" not in fn):
        return None
    out = []
    for c in calls:
        loc = parse_location(str(c.get("loc") or ""))
        lits = c.get("literal_args") if isinstance(c.get("literal_args"), dict) else {}
        site = {"callee": str(c.get("name") or ""), "line": loc[1] if loc else 0, "literals": dict(lits)}
        if "initializer" in c:
            site["initializer"] = bool(c["initializer"])
        out.append(site)
    return out


def _body_facts(fn: dict, literals: bool = True) -> dict:
    """
    The dump's formals and writes (schema 3, step I9), and its call sites with their literal
    arguments (schema 4, `literals`), when the dump module recorded them.
    """
    out: dict[str, Any] = {}
    if literals:
        sites = _call_sites(fn)
        if sites is not None:
            out["call_sites"] = sites
    if isinstance(fn.get("formals"), list):
        out["formals"] = fn["formals"]
    w = fn.get("writes")
    if isinstance(w, dict):
        out["writes"] = {
            "pointer": int(w.get("pointer") or 0),
            "params": list(w.get("params") or []),
            "globals": list(w.get("globals") or []),
        }
    return out


def parse_location(loc: str) -> tuple[str, int] | None:
    m = _LOC_RE.match((loc or "").strip())
    return (m.group("file"), int(m.group("line"))) if m else None


def snapshot_dirs(snapshot_root: str | None, system_flags: Iterable[str]) -> list[str]:
    """
    `-idirafter` options for the target's system headers, read from the snapshot: the include
    directories the compile named outside the tree, then gcc's default system directories, each only
    when the snapshot has it. Searched after Frama-C's libc, so a libc header never comes from `root/`
    (the libc headers Frama-C lacks come from the snapshot's `libc/`, target_env.libc_include_flags).
    """
    return target_env.include_flags(snapshot_root, system_flags)


def framac_file_flags(flags: list[str], tree: str) -> list[str]:
    """
    Per-file preprocessing flags for Frama-C: project paths absolute, flags Frama-C's libc rejects
    dropped (C89 refuses the `//` comments of its headers), each token quoted for the cpp command line.
    """
    out: list[str] = []
    for tok in bc.absolute_flags(flags, tree):
        if is_pre_c99_std(tok):
            continue
        out.append(shlex.quote(tok))
    return out


def blank_line_directives(data: bytes, original: str) -> bytes | None:
    """
    The text `data` of the source `original` (absolute) with its line directives blanked, or None when
    it has none.

    Generated sources (flex, bison) carry `#line` directives naming their grammar (`toke.l`, `gram.y`)
    and themselves, relative to the directory they were generated in. Frama-C ignores a directive whose
    file does not exist relative to its own working directory, line number included, and with it every
    return marker cpp writes after an `#include` (they name the same file): the definitions that follow
    are then located in the last header entered (`toke.h`, a libc header), at lines that count on from
    there. A directive it does follow moves them into the grammar file. Each directive line (and its
    continuation lines) becomes an empty line, so every other line keeps its number, and a first
    `#line 1 "<original>"` names the original: locations are the physical lines of the compiled source.
    """
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    out: list[bytes] = []
    found = in_directive = continued = False
    for line in data.splitlines(keepends=True):
        body = line.rstrip(b"\r\n")
        # A line continuing the previous one is no directive of its own, but continues one.
        in_directive = in_directive if continued else bool(_LINE_DIRECTIVE_RE.match(body))
        continued = body.endswith(b"\\")
        if in_directive:
            found = True
            out.append(line[len(body) :])
        else:
            out.append(line)
    if not found:
        return None
    name = original.replace("\\", "\\\\").replace('"', '\\"')
    return f'#line 1 "{name}"\n'.encode() + b"".join(out)


def line_directive_copy(source: str, dest: Path) -> str | None:
    """
    `source` (absolute) written under the directory `dest` with its line directives blanked
    (blank_line_directives), under its own name; None when it has none or cannot be read. The copy's
    quoted includes need `-iquote <the source's directory>` first (line_directive_flags).
    """
    try:
        data = Path(source).read_bytes()
    except OSError:
        return None
    blanked = blank_line_directives(data, source)
    if blanked is None:
        return None
    dest.mkdir(parents=True, exist_ok=True)
    copy = dest / posixpath.basename(source)
    copy.write_bytes(blanked)
    return copy.as_posix()


def line_directive_flags(source: str) -> list[str]:
    """
    The flags that make a copy of `source` include what `source` includes: a quoted include is searched
    in the including file's directory first, then in the `-iquote` directories in order.
    """
    return ["-iquote", posixpath.dirname(source)]


def within_file(lines: list[str] | None, first: int, last: int) -> bool:
    """Whether lines first..last (1-based) are lines of the file whose `lines` these are (None: unreadable)."""
    return lines is not None and 1 <= first <= last <= len(lines)


def attribute_definition(
    rel: str | None,
    root: str | None,
    first: int,
    last: int,
    sources: Iterable[str],
    line_directives: bool,
    read_lines: Callable[[str], list[str] | None],
) -> tuple[str | None, bool]:
    """
    The file a definition the dump located in `rel` (tree-relative, None outside the tree) at lines
    first..last belongs to, and whether that is `root` instead: the compiled source the parse read it
    from (dump schema 7).

    The location is used when it is one of the job's compiled `sources`, or when no line directive was
    in play (`line_directives`: the parse ignored one, or a compiled source had one) and it is a C file.
    Otherwise a C file is used when the lines lie within its text. A position a line directive left
    stale cannot: once Frama-C ignores the return marker after an `#include`, it counts on from the end
    of the header it was in, so every later definition lies past that header's last line (sudo's
    `toke.h#sudoersparse` at line 800 of a 40-line header). The text need not name the function: an
    included `.c` defines functions renamed by macros (sudo's `pwutil_impl.c`). A line directive's
    grammar file (`gram.y`), a stale header or a missing file give way to `root` when that is a compiled
    source of the job. A location outside the tree stays dropped: Frama-C's libc defines functions of
    its own in headers the project includes.
    """
    srcs = set(sources)
    if rel is None or rel in srcs:
        return rel, False
    c_text = rel.endswith(C_TEXT_SUFFIXES)
    if not line_directives and c_text:
        return rel, False
    if root is None or root not in srcs:
        return rel, False
    if c_text and within_file(read_lines(rel), first, last):
        return rel, False
    return root, True


def job_key(compiles: list[dict]) -> str:
    """Units that compile the same sources with the same flags share one parse."""
    material = json.dumps(sorted([c["source"], c["flags"], c["system_flags"]] for c in compiles))
    return hashlib.sha256(material.encode()).hexdigest()[:16]


def first_error(log: str) -> str:
    """The first error line and the line after it (Frama-C puts the message there), else the last line."""
    lines = (log or "").splitlines()
    for i, line in enumerate(lines):
        if _ERROR_RE.search(line) and "warning" not in line.lower():
            return " ".join(s.strip() for s in lines[i : i + 2] if s.strip())[:ERROR_CHARS]
    tail = (log or "").strip().splitlines()
    return tail[-1][:ERROR_CHARS] if tail else ""


# ---------------------------------------------------------------------------------------------------
# Parse-loss warning census (Tier 2 Part B)
# ---------------------------------------------------------------------------------------------------

# Benign GCC/Clang optimization, diagnostic and hint attributes that do not alter C layout, ABI,
# linkage, or control flow (normalized by stripping paired leading/trailing `__`).
BENIGN_UNKNOWN_ATTRS: frozenset[str] = frozenset(
    {
        "cold",
        "hot",
        "format",
        "warn_unused_result",
        "nonnull",
        "visibility",
        "deprecated",
        "format_arg",
        "returns_nonnull",
        "unused",
        "used",
        "pure",
        "const",
        "noreturn",
        "noinline",
        "always_inline",
        "flatten",
        "malloc",
        "alloc_size",
        "alloc_align",
        "returns_twice",
        "nothrow",
        "leaf",
        "artificial",
        "fallthrough",
        "access",
        "sentinel",
        "gnu_inline",
        "externally_visible",
        "no_sanitize",
        "no_sanitize_address",
        "no_sanitize_undefined",
        "optimize",
        "target",
        "error",
        "warning",
    }
)

# Semantically impactful attributes affecting layout, ABI, linkage, lifetime, or calling convention.
SEMANTIC_UNKNOWN_ATTRS: frozenset[str] = frozenset(
    {
        "packed",
        "aligned",
        "transparent_union",
        "cleanup",
        "constructor",
        "destructor",
        "weak",
        "alias",
        "section",
        "weakref",
        "ifunc",
        "common",
        "nocommon",
        "mode",
        "vector_size",
        "may_alias",
        "ms_struct",
        "gcc_struct",
        "designated_init",
        "interrupt",
        "naked",
        "regparm",
        "stdcall",
        "cdecl",
        "fastcall",
        "dllexport",
        "dllimport",
        "init_priority",
        "tls_model",
    }
)

# Benign or separately tracked [kernel:...] warning categories that do not indicate C parse loss:
# standard void*-to-typed-pointer C conversions, variadic calls (tracked by variadic_calls.py),
# and global -std= forwarding notices from -cpp-extra-args-per-file.
BENIGN_KERNEL_CATEGORIES: frozenset[str] = frozenset(
    {
        "typing:implicit-conv-void-ptr",
        "typing:variadic",
        "pp:extra-args-std",
    }
)

_ATTR_UNKNOWN_RE = re.compile(r"Ignoring unknown attribute:\s*([A-Za-z_][A-Za-z0-9_]*)")
_ATTR_STMT_RE = re.compile(r"unexpected statement attribute\s+([A-Za-z_][A-Za-z0-9_]*)")
_NO_ANNOT_LIBC_RE = re.compile(r"Unable to locate ACSL predicate\b")
PARSE_WARNING_SAMPLE_CAP = 10
PARSE_WARNING_SAMPLE_CHARS = 200


def normalize_attr_name(name: str) -> str:
    """Strip paired double underscores from a GCC/Clang attribute name (`__packed__` -> `packed`)."""
    if len(name) > 4 and name.startswith("__") and name.endswith("__"):
        return name[2:-2]
    return name


def parse_warnings_has_loss(pw: dict[str, Any]) -> bool:
    """Whether a `parse_warnings` summary reports any actionable C parse loss or silent AST alteration."""
    asm_count = int((pw.get("asm_clobber") or {}).get("count") or 0)
    attrs = pw.get("attrs_unknown") or {}
    uncls = pw.get("unclassified_categories") or {}
    return (
        asm_count > 0
        or bool(attrs.get("semantic"))
        or bool(attrs.get("unclassified"))
        or any(int(v.get("project_count") or 0) > 0 for v in uncls.values() if isinstance(v, dict))
    )


def summarize_parse_warnings(log: str, tree: str) -> dict[str, Any]:
    """
    Count and classify `[kernel:...]` warnings from a Frama-C `-no-annot` Phase 0 parse log.
    Separates `asm:clobber`, semantically impactful vs. benign vs. unclassified `attrs:unknown`
    (and Frama-C 34 benign statement `[kernel:attrs]` warnings), benign/already-tracked kernel
    categories, unclassified `[kernel:...]` categories (project-tree vs. total counts), and
    `-no-annot` `libc:frama-c` noise.
    """
    asm_count = 0
    asm_project_count = 0
    asm_samples: list[str] = []

    attrs_semantic: Counter[str] = Counter()
    attrs_benign: Counter[str] = Counter()
    attrs_unclassified: Counter[str] = Counter()
    attrs_semantic_samples: list[str] = []
    attrs_unclassified_samples: list[str] = []

    benign_categories: Counter[str] = Counter()
    unclassified: dict[str, dict[str, Any]] = {}
    no_annot_libc_skipped = 0

    for m in fold_messages(log):
        if m.plugin != "kernel" or m.kind.lower() != "warning" or not m.category:
            continue
        rel = tree_rel(m.file, tree) if (m.file and tree) else None
        is_project = rel is not None
        loc = f"{rel or m.file}:{m.line}" if m.file else ""

        if m.category == "libc:frama-c" and _NO_ANNOT_LIBC_RE.search(m.text):
            no_annot_libc_skipped += 1
            continue

        if m.category == "asm:clobber":
            asm_count += 1
            if is_project:
                asm_project_count += 1
            if len(asm_samples) < PARSE_WARNING_SAMPLE_CAP:
                asm_samples.append(loc or m.text[:PARSE_WARNING_SAMPLE_CHARS])
            continue

        if m.category == "attrs:unknown":
            match = _ATTR_UNKNOWN_RE.search(m.text)
            raw = match.group(1) if match else ""
            norm = normalize_attr_name(raw) if raw else "<unparsed>"
            if norm in SEMANTIC_UNKNOWN_ATTRS:
                attrs_semantic[norm] += 1
                if len(attrs_semantic_samples) < PARSE_WARNING_SAMPLE_CAP:
                    sample = f"{loc}: {norm}" if loc else norm
                    attrs_semantic_samples.append(sample[:PARSE_WARNING_SAMPLE_CHARS])
            elif norm in BENIGN_UNKNOWN_ATTRS:
                attrs_benign[norm] += 1
            else:
                attrs_unclassified[norm] += 1
                if len(attrs_unclassified_samples) < PARSE_WARNING_SAMPLE_CAP:
                    sample = f"{loc}: {norm}" if loc else norm
                    attrs_unclassified_samples.append(sample[:PARSE_WARNING_SAMPLE_CHARS])
            continue

        if m.category == "attrs":
            match = _ATTR_STMT_RE.search(m.text)
            if match:
                norm = normalize_attr_name(match.group(1))
                if norm in BENIGN_UNKNOWN_ATTRS:
                    attrs_benign[norm] += 1
                    continue

        if m.category in BENIGN_KERNEL_CATEGORIES:
            benign_categories[m.category] += 1
            continue

        entry = unclassified.setdefault(
            m.category,
            {"count": 0, "project_count": 0, "sample": "", "_has_project_sample": False},
        )
        entry["count"] += 1
        sample_text = (f"{loc}: {m.text}" if loc else m.text)[:PARSE_WARNING_SAMPLE_CHARS]
        if is_project:
            entry["project_count"] += 1
            if not entry["_has_project_sample"]:
                entry["sample"] = sample_text
                entry["_has_project_sample"] = True
        elif not entry["sample"]:
            entry["sample"] = sample_text

    cleaned_unclassified = {
        cat: {k: v for k, v in rec.items() if k != "_has_project_sample"} for cat, rec in sorted(unclassified.items())
    }
    summary: dict[str, Any] = {
        "asm_clobber": {
            "count": asm_count,
            "project_count": asm_project_count,
            "samples": asm_samples,
        },
        "attrs_unknown": {
            "semantic": dict(sorted(attrs_semantic.items())),
            "benign": dict(sorted(attrs_benign.items())),
            "unclassified": dict(sorted(attrs_unclassified.items())),
            "semantic_samples": attrs_semantic_samples,
            "unclassified_samples": attrs_unclassified_samples,
        },
        "benign_categories": dict(sorted(benign_categories.items())),
        "unclassified_categories": cleaned_unclassified,
        "no_annot_libc_skipped": no_annot_libc_skipped,
        "has_parse_loss": False,
    }
    summary["has_parse_loss"] = parse_warnings_has_loss(summary)
    return summary


def _format_parse_loss_warning(units: list[str], pw: dict[str, Any]) -> str:
    """Concise model warning summarizing actionable C parse-loss warnings for a parse job."""
    parts: list[str] = []
    asm = pw.get("asm_clobber") or {}
    if asm.get("count"):
        parts.append(f"asm:clobber ({asm['project_count']}/{asm['count']})")
    attrs = pw.get("attrs_unknown") or {}
    if attrs.get("semantic"):
        sem = ", ".join(f"{k}x{v}" for k, v in sorted(attrs["semantic"].items()))
        parts.append(f"semantic attrs:unknown ({sem})")
    if attrs.get("unclassified"):
        uncls = ", ".join(f"{k}x{v}" for k, v in sorted(attrs["unclassified"].items()))
        parts.append(f"unclassified attrs:unknown ({uncls})")
    proj_cats = [
        f"{cat} ({info['project_count']}/{info['count']})"
        for cat, info in sorted((pw.get("unclassified_categories") or {}).items())
        if info.get("project_count")
    ]
    if proj_cats:
        parts.append("kernel warnings: " + ", ".join(proj_cats))
    return f"{', '.join(units)}: Frama-C -no-annot parse warnings ({'; '.join(parts)})"


# ---------------------------------------------------------------------------------------------------
# Running tools
# ---------------------------------------------------------------------------------------------------

Runner = Callable[..., Any]


def run_tool(
    cmd: list[str], cwd: str | None, timeout: int, env: dict[str, str] | None = None, runner: Runner | None = None
) -> tuple[int, str]:
    try:
        proc = (runner or subprocess.run)(
            cmd,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {timeout} s: {shlex.join(cmd)[:300]}"
    except OSError as exc:
        return 127, f"cannot run {cmd[0]}: {exc}"
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def parse_timeout() -> int:
    from resources import CLASSES

    return CLASSES["parse"].wall_timeout_s or 1800


def leased(cmd: list[str], key: str, broker: bool) -> list[str]:
    """`cmd` under a `parse` lease of the container broker, as Make runs its jobs."""
    if not broker:
        return cmd
    script = Path(__file__).resolve().parent / "resources.py"
    return [sys.executable, str(script), "run", "--class", "parse", "--key", key, "--", *cmd]


# ---------------------------------------------------------------------------------------------------
# One parse
# ---------------------------------------------------------------------------------------------------


def framac_parse(
    job: dict,
    tree: str,
    snapshot_root: str | None,
    module: Path,
    log_dir: Path,
    broker: bool,
    runner: Runner | None = None,
    alias_module: Path | None = None,
) -> dict:
    """
    {status: ok, dump, seconds} or {status: parse_failed, error, seconds}. With `alias_module`, the
    same run loads it and `alias` holds its report, or {status: crashed, error} when the run produced
    the dump but no Alias report.
    """
    compiles = job["compiles"]
    with tempfile.TemporaryDirectory(prefix="framac-p0-") as tmp:
        out = Path(tmp) / "dump.json"
        alias_out = Path(tmp) / "alias.json"
        spec = []
        system: list[str] = []
        # Sources with line directives are parsed from a copy with them blanked (blank_line_directives).
        copies: dict[str, str] = {}
        for n, src in enumerate(sorted({c["source"] for c in compiles})):
            copy = line_directive_copy(posixpath.join(tree, src), Path(tmp) / LINE_DIRECTIVE_DIR / str(n))
            if copy is not None:
                copies[src] = copy
        for c in compiles:
            flags = framac_file_flags(c["flags"], tree)
            if c["source"] in copies:
                flags = [shlex.quote(f) for f in line_directive_flags(posixpath.join(tree, c["source"]))] + flags
            if flags:
                path = copies.get(c["source"]) or posixpath.join(tree, c["source"])
                spec.append(f"{path}:{' '.join(f for f in flags if ',' not in f)}")
            system += c["system_flags"]
        extra = augment_framac_cppflags(" ".join(snapshot_dirs(snapshot_root, system)))
        cmd = [
            "frama-c",
            "-no-unicode",
            "-no-annot",  # the code, not its annotations: a bad ACSL comment must not lose the model
            "-keep-unused-functions",
            "all",
            "-machdep",
            MACHDEP,
            f"-cpp-extra-args={extra}",
        ]
        if spec:
            cmd.append("-cpp-extra-args-per-file=" + ",".join(spec))
        cmd += sorted({copies.get(c["source"]) or posixpath.join(tree, c["source"]) for c in compiles})
        env = dict(os.environ, **{DUMP_OUT_ENV: str(out)})
        if alias_module is None:
            cmd += ["-load-module", str(module)]
        else:
            # The dump's extension runs first and writes its file before Alias starts.
            cmd += ["-load-module", f"{module},{alias_module}"]
            env.update({ALIAS_OUT_ENV: str(alias_out), ALIAS_TIMEOUT_ENV: str(ALIAS_TIMEOUT_S)})
        t0 = time.monotonic()
        rc, log = run_tool(leased(cmd, f"p0-{job['key']}", broker), tree, parse_timeout(), env, runner)
        seconds = round(time.monotonic() - t0, 2)
        _write_log(log_dir, job["key"], "framac", cmd, log)
        # A run that crashed in Alias after the dump was written still parsed: the dump is complete
        # (written to a temporary name, then renamed).
        if not out.is_file() or (rc != 0 and alias_module is None):
            return {"status": "parse_failed", "error": first_error(log), "seconds": seconds}
        try:
            dump = json.loads(out.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return {"status": "parse_failed", "error": f"unreadable dump: {exc}", "seconds": seconds}
        # The copies' own path shows only as the root of what they define: name the original there.
        back = {posixpath.normpath(copy): posixpath.join(tree, src) for src, copy in copies.items()}
        for rec in [*(dump.get("functions") or []), *(dump.get("globals") or [])]:
            root = posixpath.normpath(str(rec.get("root") or "")) if rec.get("root") else ""
            if root in back:
                rec["root"] = back[root]
        res: dict[str, Any] = {
            "status": "ok",
            "dump": dump,
            "seconds": seconds,
            "parse_warnings": summarize_parse_warnings(log, tree),
        }
        directives = {
            "blanked": sorted(copies),
            "ignored": sorted(set(_IGNORED_LINE_DIRECTIVE_RE.findall(log))),
        }
        if any(directives.values()):
            res["line_directives"] = directives
        if alias_module is not None:
            res["alias"] = read_alias_report(alias_out, rc, log)
    return res


def read_alias_report(path: Path, rc: int, log: str) -> dict:
    """The Alias module's report, or {status: crashed, error} when the run ended without one."""
    if path.is_file():
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(doc, dict):
                return doc
        except (OSError, ValueError) as exc:
            return {"status": "crashed", "error": f"unreadable Alias report: {exc}"}
    reason = first_error(log) if rc != 0 else "no Alias report"
    return {"status": "crashed", "error": f"exit {rc}: {reason}"[:ERROR_CHARS]}


def gcc_callgraph(job: dict, tree: str, snapshot_root: str | None, log_dir: Path, runner: Runner | None = None) -> dict:
    """
    GCC fallback: per compile, `-fcallgraph-info` nodes and edges. {status, errors, functions, edges,
    indirect}: functions by id, edges as (caller id, callee id or None for an undefined callee, callee
    name), indirect call sites by caller id.
    """
    functions: dict[str, dict] = {}
    edges: list[tuple[str, str | None, str]] = []
    indirect: list[str] = []
    errors: list[str] = []
    logs: list[str] = []
    with tempfile.TemporaryDirectory(prefix="framac-p0-gcc-") as tmp:
        for n, c in enumerate(job["compiles"]):
            base = f"{tmp}/{n}"
            source = posixpath.join(tree, c["source"])
            argv = bc.compile_argv(c["arguments"], source, f"{base}.o")
            # GCC names functions by the file a line directive gives too: compile the blanked copy.
            copy = line_directive_copy(source, Path(tmp) / LINE_DIRECTIVE_DIR / str(n))
            quote = line_directive_flags(source) if copy else []
            if copy:
                argv[-3] = copy
            cmd = ["gcc", *quote, *argv[1:-4], *snapshot_dirs(snapshot_root, c["system_flags"]), *argv[-4:]]
            cmd += ["-fcallgraph-info", "-dumpbase", base]
            cwd = bc.absolute(c["cwd"], tree)
            rc, log = run_tool(cmd, cwd, GCC_TIMEOUT_S, runner=runner)
            logs.append(f"$ {shlex.join(cmd)}\n{log}")
            ci = Path(f"{base}.ci")
            if rc != 0 or not ci.is_file():
                errors.append(first_error(log) or f"gcc exited {rc}")
                continue
            text = ci.read_text(encoding="utf-8", errors="replace")
            labels: dict[str, str] = {}
            ids: dict[str, str] = {}  # node title -> id, for the functions defined in this translation unit
            for title, label, file, line in _CI_NODE.findall(text):
                labels[title] = label
                rel = tree_rel(file, tree, cwd) if file else None
                if rel is not None:
                    ids[title] = f"{rel}#{label}"
                    functions[ids[title]] = {"file": rel, "name": label, "line": int(line), "static": ":" in title}
            for src, dst in _CI_EDGE.findall(text):
                if src not in ids:
                    continue
                if labels.get(dst) == "Indirect Call Placeholder":
                    indirect.append(ids[src])
                else:
                    edges.append((ids[src], ids.get(dst), labels.get(dst, str(dst))))
    _write_log(log_dir, job["key"], "gcc", None, "\n".join(logs))
    status = "ok" if not errors else ("partial" if functions else "failed")
    return {"status": status, "errors": errors, "functions": functions, "edges": edges, "indirect": indirect}


def macro_aliases(compile: dict, tree: str, snapshot_root: str | None, runner: Runner | None = None) -> list[dict]:
    """Object-like `#define a b` (b an identifier) written in a project file, from `gcc -E -dD`."""
    source = posixpath.join(tree, compile["source"])
    argv = bc.compile_argv(compile["arguments"], source, "/dev/null")
    cwd = bc.absolute(compile["cwd"], tree)
    with tempfile.TemporaryDirectory(prefix="framac-p0-defs-") as tmp:
        # A define after a line directive is written in the source, not in the grammar it names.
        copy = line_directive_copy(source, Path(tmp))
        quote = line_directive_flags(source) if copy else []
        snap = snapshot_dirs(snapshot_root, compile["system_flags"])
        cmd = ["gcc", *quote, *argv[1:-4], *snap, "-E", "-dD", copy or argv[-3]]
        rc, out = run_tool(cmd, cwd, GCC_TIMEOUT_S, runner=runner)
    if rc != 0:
        return []
    return parse_defines(out, tree, cwd)


def parse_defines(text: str, tree: str, cwd: str | None = None) -> list[dict]:
    """The defines of `gcc -E -dD` output; line-marker paths resolve against `cwd`, then the tree."""
    found: list[dict] = []
    current: str | None = None
    for line in text.splitlines():
        m = _LINE_MARKER_RE.match(line)
        if m:
            current = tree_rel(m.group("file"), tree, cwd) if not m.group("file").startswith("<") else None
            continue
        if current is None:
            continue
        d = _OBJECT_DEFINE_RE.match(line)
        if d and d.group("name") != d.group("value"):
            found.append({"alias": d.group("name"), "value": d.group("value"), "file": current})
    return found


def _write_log(log_dir: Path, key: str, tool: str, cmd: list[str] | None, log: str) -> None:
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        head = shlex.join(cmd) + "\n\n" if cmd else ""
        (log_dir / f"{key}.{tool}.log").write_text(head + log, encoding="utf-8")
    except OSError:
        pass


# ---------------------------------------------------------------------------------------------------
# The model
# ---------------------------------------------------------------------------------------------------


def plan_jobs(capture: dict) -> tuple[list[dict], dict[str, str]]:
    """Parse jobs over the non-test units, and each unit's job key."""
    by_object = {c["object"]: c for c in capture.get("compiles") or []}
    jobs: dict[str, dict] = {}
    unit_job: dict[str, str] = {}
    for name, u in sorted((capture.get("units") or {}).items()):
        if u.get("test"):
            continue
        own = [by_object[o] for o in u.get("objects") or [] if o in by_object]
        if not own:
            continue
        key = job_key(own)
        unit_job[name] = key
        jobs.setdefault(key, {"key": key, "compiles": own, "units": []})["units"].append(name)
    return list(jobs.values()), unit_job


def alias_site_queues(alias: dict | None) -> dict[str, list[dict]]:
    """An Alias report's sites per caller kernel name, in the dump's order."""
    if not alias or alias.get("status") != "ok":
        return {}
    return {f["kernel_name"]: list(f.get("sites") or []) for f in alias.get("functions") or []}


def match_alias_site(alias: dict, queues: dict[str, list[dict]], caller: str, call: dict, kmap: dict) -> dict:
    """
    Alias's answer for one indirect call of the dump: {status, ids, names}. `status` is the site's
    (`targets`, `no_state`, `no_targets`, `error`), `alias_<status>` when the analysis itself did not
    finish, or `unmatched` when the report has no site at that location. Targets defined in the parse
    are ids; the others are names, resolved like an undefined callee.
    """
    if alias.get("status") != "ok":
        return {"status": f"alias_{alias.get('status') or 'missing'}"}
    queue = queues.get(caller) or []
    for i, s in enumerate(queue):
        if s.get("loc") == call.get("loc") and s.get("expr") == call.get("expr"):
            queue.pop(i)
            break
    else:
        return {"status": "unmatched"}
    out: dict[str, Any] = {"status": s.get("status") or "error"}
    if out["status"] == "targets":
        names = s.get("targets") or []
        out["ids"] = sorted({kmap[n] for n in names if n in kmap})
        out["names"] = sorted({n for n in names if n not in kmap})
    return out


def closures(units: dict) -> dict[str, set[str]]:
    """Each unit with the project libraries it links, transitively."""
    out: dict[str, set[str]] = {}
    for name in units:
        seen = {name}
        stack = list(units[name].get("links") or [])
        while stack:
            lk = stack.pop()
            if lk in seen or lk not in units:
                continue
            seen.add(lk)
            stack += units[lk].get("links") or []
        out[name] = seen
    return out


def reconcile_api_ids(units: dict[str, dict], functions: dict[str, dict]) -> list[str]:
    """
    Map each unit's `entry_points` and `embedded_api` ids to the model's, in place; returns warnings.

    The capture names a function by its compiled source (or the header `nm -l` gives), the model
    by where Frama-C places its definition. They differ for a function defined in a `#include`d
    `.c`, or in a header when the build has no `-g`. Such an id matches no model function, and
    trust, the unit view and the reach gate would then drop that API function without a word. It
    is mapped to the unit's only external function of that name, or kept with a warning.
    """
    by_unit_name: dict[tuple[str, str], list[str]] = defaultdict(list)
    for fid, f in functions.items():
        for unit in f.get("units") or []:
            if not f.get("static"):
                by_unit_name[(unit, str(f.get("name")))].append(fid)
    warnings: list[str] = []
    for name, rec in units.items():
        if rec.get("test") or (rec.get("parse") or {}).get("status") not in ("ok", "gcc_fallback"):
            continue
        for field in ("entry_points", "embedded_api"):
            ids = rec.get(field)
            if not ids:
                continue
            fixed: list[str] = []
            for fid in ids:
                hits = [fid] if fid in functions else sorted(by_unit_name.get((name, fid.rsplit("#", 1)[-1]), []))
                if len(hits) == 1:
                    if hits[0] != fid:
                        warnings.append(f"{name}: {field} {fid} is {hits[0]} in the model")
                    fixed.append(hits[0])
                else:
                    warnings.append(
                        f"{name}: {field} {fid} names no function of the model"
                        + (f" (candidates: {', '.join(hits)})" if hits else "")
                        + "; trust, tiers and the reach gate leave it out"
                    )
                    fixed.append(fid)
            rec[field] = list(dict.fromkeys(fixed))
    return warnings


LIBRARY_UNIT_KINDS = ("static_lib", "shared_lib")


def public_header_files(public: dict | None, headers: Iterable[str]) -> set[str]:
    """
    The public headers of the build capture (`public_headers.files`) as paths relative to the tree.
    They are already, except with the method `install`: the headers the install staged, as absolute
    paths under the scratch directory. Each of those is mapped back to the tree header among
    `headers` (the project's headers) that shares the longest trailing path with it
    (`.../include/qcbor/qcbor_decode.h` -> `inc/qcbor/qcbor_decode.h`); a tie keeps every tied header.
    """
    files = [str(f).replace("\\", "/") for f in (public or {}).get("files") or [] if f]
    tree_headers = sorted({str(h).replace("\\", "/") for h in headers})
    out: set[str] = set()
    for f in files:
        if not (f.startswith("/") or re.match(r"[A-Za-z]:/", f)):
            out.add(f)
            continue
        parts = f.split("/")
        best, hits = 0, []
        for h in tree_headers:
            hp = h.split("/")
            n = 0
            while n < min(len(hp), len(parts)) and hp[-1 - n] == parts[-1 - n]:
                n += 1
            if n and n > best:
                best, hits = n, [h]
            elif n and n == best:
                hits.append(h)
        out.update(hits)
    return out


def header_api(
    units: dict[str, dict], functions: dict[str, dict], public: dict | None, project_headers: Iterable[str] = ()
) -> dict[str, list[str]]:
    """
    Per library unit (static or shared, not a test unit), the functions defined in one of the build
    capture's public headers (`static` and `header` in the model) that the unit compiles: API entry
    points without a global symbol, so the capture's `entry_points` cannot list them. Private
    helpers count too: there is no naming rule (docs/plans/header-entry-points-plan.md, HD1).
    `project_headers` (the headers the capture's compiles include) are the tree headers an installed
    header may stand for, with those defining a function.
    """
    candidates = {*project_headers, *(str(f.get("file")) for f in functions.values() if f.get("header"))}
    pub = public_header_files(public, candidates)
    out: dict[str, list[str]] = {}
    for name, rec in units.items():
        if rec.get("test") or rec.get("kind") not in LIBRARY_UNIT_KINDS:
            continue
        out[name] = sorted(
            fid
            for fid, f in functions.items()
            if f.get("static") and f.get("header") and f.get("file") in pub and name in (f.get("units") or [])
        )
    return out


class ModelBuilder:
    """Merges the parse results of all jobs into one model, resolving across units as the linker does."""

    def __init__(self, capture: dict, tree: str):
        self.tree = tree
        self.units = {n: u for n, u in (capture.get("units") or {}).items() if not u.get("test")}
        self.closure = closures(self.units)
        roots = {n for n in self.units if not any(n in (u.get("links") or []) for u in self.units.values())}
        self.programs = [self.closure[r] for r in sorted(roots)]
        self.functions: dict[str, dict] = {}
        self.edges: dict[tuple[str, str, str], set[str]] = defaultdict(set)
        self.indirect_sites: list[dict] = []
        self.externals: set[str] = set()
        self.external_calls: dict[str, set[str]] = defaultdict(set)  # caller id -> external names it calls
        self.thread_entries: set[str] = set()
        self.concurrent: set[str] = set()
        # Per unit: kernel name -> id, source name -> id of its globals, address-taken ids with signatures.
        self.kmap: dict[str, dict[str, str]] = {}
        self.globals: dict[str, dict[str, str]] = defaultdict(dict)
        self.taken: dict[str, set[str]] = defaultdict(set)
        self.pending_calls: list[tuple[str, str, dict]] = []  # (unit, caller id, call)
        # Step I9: defined global variables (`file#name`) and the formals of declared functions.
        self.global_vars: dict[str, dict] = {}
        self.declared_formals: dict[str, list] = {}
        # Declared (not defined) functions: their first declaration and its C text (scripts/stub_gen.py).
        self.declared_info: dict[str, dict] = {}
        # Callee id -> (caller id, call location, argument index, bytes): what the callers pass.
        self.arg_sites: dict[str, set[tuple[str, str, str, int]]] = defaultdict(set)
        # Units whose Frama-C parse failed (gcc_fallback / unparsed): globals defined there are missing.
        self.failed_units: set[str] = set()
        # Cross-parse `address_taken` names resolved in `resolve_refs`: (units, kernel_names, kmap).
        self.pending_taken: list[tuple[list[str], list[str], dict[str, str]]] = []
        # Address flow (dump schema 6), resolved in `resolve`: (units, target record, kernel names
        # of functions and globals it names, that parse's function and global maps, target keys).
        self.pending_refs: list[
            tuple[list[str], dict, list[str], list[str], dict[str, str], dict[str, str], str, str]
        ] = []
        # Definitions a line directive located outside their compiled source (attribute_definition):
        # {units, loc, id}, and the tree files read to decide it.
        self.relocated: list[dict] = []
        self._lines: dict[str, list[str] | None] = {}
        self._spans: dict[str, dict[str, list[tuple[int, int]]]] = {}

    def file_lines(self, rel: str) -> list[str] | None:
        """The lines of a tree file (cached), None when it cannot be read."""
        if rel not in self._lines:
            try:
                text = Path(posixpath.join(self.tree, rel)).read_text(encoding="utf-8", errors="replace")
                self._lines[rel] = text.splitlines()
            except OSError:
                self._lines[rel] = None
        return self._lines[rel]

    def definition_span(self, rel: str, name: str) -> tuple[int, int] | None:
        """The lines of the one definition of `name` written in the tree file `rel`, if it has exactly one."""
        if rel not in self._spans:
            spans: dict[str, list[tuple[int, int]]] = defaultdict(list)
            lines = self.file_lines(rel)
            try:
                found = extract_functions_from_code("\n".join(lines or []), rel)
            except AcslSyntaxError:
                found = []
            for f in found:
                spans[f["name"]].append((int(f["line"]), int(f["end_line"])))
            self._spans[rel] = spans
        hits = self._spans[rel].get(name) or []
        return hits[0] if len(hits) == 1 else None

    def _attribute(
        self, units: list[str], rec: dict, rel: str | None, first: int, last: int, sources: list[str], directives: bool
    ) -> tuple[str | None, bool]:
        root = tree_rel(str(rec.get("root") or ""), self.tree) if rec.get("root") else None
        file, moved = attribute_definition(rel, root, first, last, sources, directives, self.file_lines)
        if moved:
            self.relocated.append({"units": list(units), "loc": str(rec.get("loc") or ""), "file": file})
        return file, moved

    def _record_arg_sizes(self, caller: str, callee: str, call: dict) -> None:
        sizes = call.get("arg_sizes")
        if not isinstance(sizes, dict):
            return
        for idx, n in sizes.items():
            if isinstance(n, int) and n > 0:
                self.arg_sites[callee].add((caller, str(call.get("loc") or ""), str(idx), n))

    def param_sizes(self, fid: str) -> dict[str, dict]:
        """Per argument index: the smallest and largest object the callers pass, and over how many sites."""
        by_idx: dict[str, list[int]] = defaultdict(list)
        for _caller, _loc, idx, n in self.arg_sites.get(fid, ()):
            by_idx[idx].append(n)
        return {
            i: {"min": min(v), "max": max(v), "sites": len(v)}
            for i, v in sorted(by_idx.items(), key=lambda kv: int(kv[0]))
        }

    def add_function(self, fid: str, unit: str, record: dict) -> None:
        rec = self.functions.get(fid)
        if rec is None:
            rec = self.functions[fid] = {**record, "units": [], "kernel_names": {}}
        elif rec.get("source") == SOURCE_GCC and record.get("source") == SOURCE_FRAMAC:
            # A function compiled by a unit on the GCC fallback and by one Frama-C parsed (a shared
            # source, a header function): the parse knows its signature, formals, loops, writes and
            # last line, which the fallback cannot. Its record wins, whichever job came first.
            keep = {"units": rec["units"], "kernel_names": rec["kernel_names"]}
            address_taken = bool(rec.get("address_taken"))
            rec.clear()
            rec.update(record, **keep)
            rec["address_taken"] = address_taken or bool(record.get("address_taken"))
        elif "constructor" in record:
            rec["constructor"] = bool(rec.get("constructor")) or bool(record["constructor"])
        if unit not in rec["units"]:
            rec["units"].append(unit)
        if record.get("kernel_name"):
            rec["kernel_names"][unit] = record["kernel_name"]
        rec.pop("kernel_name", None)

    def add_dump(
        self,
        units: list[str],
        dump: dict,
        alias: dict | None = None,
        sources: Iterable[str] = (),
        line_directives: bool = False,
    ) -> None:
        """
        One parse's dump. `alias` is that parse's Alias report (scripts/phase0_alias.ml) when the
        model runs with Alias, else None: its sites match the dump's indirect calls in order.
        `sources` are the job's compiled sources (tree-relative) and `line_directives` whether a line
        directive was in play in the parse: they decide where each definition belongs
        (attribute_definition). A definition moved to its compiled source takes the lines of its
        definition there when the text has exactly one of that name, else 0 (unknown), and records the
        location the dump gave (`relocated_from`).
        """
        srcs = [posixpath.normpath(str(s)) for s in sources]
        alias_sites = alias_site_queues(alias)
        kmap: dict[str, str] = {}
        sig: dict[str, str] = {}
        for fn in dump.get("functions") or []:
            loc = parse_location(fn.get("loc", ""))
            if loc is None:
                continue
            first, last = int(fn.get("first_line") or loc[1]), int(fn.get("last_line") or loc[1])
            rel, moved = self._attribute(units, fn, tree_rel(loc[0], self.tree), first, last, srcs, line_directives)
            if rel is None:
                continue  # Frama-C's libc, the stubs, a snapshot header: not the project's code
            relocated: dict[str, Any] = {}
            if moved:
                first, last = self.definition_span(rel, fn["name"]) or (0, 0)
                relocated["relocated_from"] = str(fn.get("loc") or "")
            fid = f"{rel}#{fn['name']}"
            kmap[fn["kernel_name"]] = fid
            sig[fn["kernel_name"]] = fn.get("signature") or ""
            for u in units:
                self.add_function(
                    fid,
                    u,
                    {
                        "file": rel,
                        "name": fn["name"],
                        "kernel_name": fn["kernel_name"],
                        "line": first,
                        "end_line": last,
                        "lines": max(1, last - first + 1) if first else None,
                        "static": bool(fn.get("static")),
                        "inline": bool(fn.get("inline")),
                        **({"constructor": bool(fn["constructor"])} if "constructor" in fn else {}),
                        "header": rel.endswith(".h"),
                        "signature": fn.get("signature") or "",
                        "loops": int(fn.get("loops") or 0),
                        "cyclomatic": int(fn.get("cyclomatic") or 1),
                        "address_taken": False,
                        "source": SOURCE_FRAMAC,
                        **_body_facts(fn, int(dump.get("schema") or 0) >= 4),
                        **relocated,
                    },
                )
                if not fn.get("static"):
                    self.globals[u].setdefault(fn["name"], fid)
        gmap: dict[str, str] = {}  # kernel name -> `file#name` of this parse's defined globals
        flow = int(dump.get("schema") or 0) >= 6
        for g in dump.get("globals") or []:
            gloc = parse_location(g.get("loc", ""))
            grel = None
            if gloc is not None and g.get("name") and not str(g["name"]).startswith("__fc_"):
                grel, _ = self._attribute(
                    units, g, tree_rel(gloc[0], self.tree), gloc[1], gloc[1], srcs, line_directives
                )
            # `__fc_*`: Frama-C's own globals (string literals), not the project's.
            if grel is not None and g.get("name") and not str(g["name"]).startswith("__fc_"):
                gid = f"{grel}#{g['name']}"
                gmap[str(g.get("kernel_name") or g["name"])] = gid
                rec = self.global_vars.setdefault(
                    gid,
                    {
                        "name": g["name"],
                        "file": grel,
                        "static": bool(g.get("static")),
                        "type": str(g.get("type") or ""),
                        "const": bool(g.get("const", False)),
                        "has_init": bool(g.get("has_init", False)),
                        "raw_type": str(g.get("raw_type") or ""),
                        "units": [],
                    },
                )
                rec["units"] = sorted(set(rec["units"]) | set(units))
                if isinstance(g.get("size"), int) and g["size"] > 0 and rec.get("size") is None:
                    rec["size"] = g["size"]
                if g.get("const"):
                    rec["const"] = True
                if g.get("has_init"):
                    rec["has_init"] = True
                if g.get("raw_type") and not rec.get("raw_type"):
                    rec["raw_type"] = str(g["raw_type"])
                if flow:
                    rec.setdefault("init_functions", [])
                    rec.setdefault("init_globals", [])
                    refs = (list(g.get("init_functions") or []), list(g.get("init_globals") or []))
                    self.pending_refs.append((list(units), rec, *refs, kmap, gmap, "init_functions", "init_globals"))
        if flow:
            for fn in dump.get("functions") or []:
                ref_fid = kmap.get(fn["kernel_name"])
                if ref_fid is not None:
                    rec = self.functions[ref_fid]
                    rec.setdefault("address_refs", [])
                    rec.setdefault("global_refs", [])
                    refs = (list(fn.get("address_refs") or []), list(fn.get("global_refs") or []))
                    self.pending_refs.append((list(units), rec, *refs, kmap, gmap, "address_refs", "global_refs"))
        for d in dump.get("declared") or []:
            if d.get("name") and d.get("formals") is not None:
                self.declared_formals.setdefault(d["name"], d["formals"])
            if d.get("name") and d.get("decl") and d.get("proto"):
                self.declared_info.setdefault(d["name"], declared_record(d))
        taken_names = list(dump.get("address_taken") or [])
        for k in taken_names:
            if k in kmap:
                self.functions[kmap[k]]["address_taken"] = True
                for u in units:
                    self.taken[u].add(kmap[k])
        unresolved_taken = [k for k in taken_names if k not in kmap]
        if unresolved_taken:
            self.pending_taken.append((list(units), unresolved_taken, kmap))
        for u in units:
            self.kmap[u] = kmap
        for fn in dump.get("functions") or []:
            caller = kmap.get(fn["kernel_name"])
            if not caller:
                continue
            for call in fn.get("calls") or []:
                if call.get("indirect"):
                    site: dict[str, Any] = {
                        "unit": units[0],
                        "units": list(units),
                        "caller": caller,
                        "expr": call.get("expr"),
                        "signature": call.get("signature"),
                        "loc": call.get("loc"),
                        "candidates": [],
                    }
                    if alias is not None:
                        site["_alias"] = match_alias_site(alias, alias_sites, fn["kernel_name"], call, kmap)
                    self.indirect_sites.append(site)
                    continue
                callee = kmap.get(call.get("kernel_name", ""))
                if callee:
                    # A project function passed to a project function is called through a pointer
                    # there: that indirect site's type match covers it.
                    self.edges[(caller, callee, "direct")].add(SOURCE_FRAMAC)
                    self._record_arg_sizes(caller, callee, call)
                    continue
                args = [kmap.get(a) for a in call.get("function_args") or []]
                for u in units:
                    self.pending_calls.append((u, caller, {**call, "resolved_args": args}))

    def add_gcc(self, units: list[str], g: dict) -> None:
        self.failed_units.update(units)
        for fid, info in g["functions"].items():
            for u in units:
                self.add_function(
                    fid,
                    u,
                    {
                        "file": info["file"],
                        "name": info["name"],
                        "line": info["line"],
                        "end_line": info["line"],
                        "lines": None,
                        "static": info["static"],
                        "inline": False,
                        "header": info["file"].endswith(".h"),
                        "signature": "",
                        "loops": None,
                        "cyclomatic": None,
                        "address_taken": False,
                        "source": SOURCE_GCC,
                    },
                )
                if not info["static"]:
                    self.globals[u].setdefault(info["name"], fid)
        for caller in g["indirect"]:
            # No call-site type in -fcallgraph-info: the site stays unresolved.
            self.indirect_sites.append(
                {"unit": units[0], "units": list(units), "caller": caller, "expr": None, "signature": None,
                 "loc": None, "candidates": []}
            )  # fmt: skip
        for caller, callee, callee_name in g["edges"]:
            if callee:
                self.edges[(caller, callee, "direct")].add(SOURCE_GCC)
                continue
            # Defined in another translation unit: of this unit (GCC sees one file at a time), or linked.
            for u in units:
                self.pending_calls.append(
                    (u, caller, {"name": callee_name, "function_args": [], "resolved_args": [], "gcc": True})
                )

    def _lookup_global(self, unit: str, name: str) -> str | None:
        """A global of that name in a unit this one links, else in a unit that links this one."""
        for other in sorted(self.closure.get(unit, set()) - {unit}):
            if name in self.globals.get(other, {}):
                return self.globals[other][name]
        for other, clos in sorted(self.closure.items()):
            if other != unit and unit in clos and name in self.globals.get(other, {}):
                return self.globals[other][name]
        return None

    def resolve_refs(self) -> None:
        """
        The address-flow facts (dump schema 6) as ids: a function's address its parse defines or
        another linked unit defines (`_lookup_global`, matching `resolve()`), a global its parse
        defines, else the one non-static global of that name another parse defines (an `extern` the
        parse only declares). Libc functions and globals are not the project's. A declared global
        that several parses define (non-static), or an unknown global when a unit in the parse's
        link closure failed Frama-C parsing (`gcc_fallback` / `unparsed`), cannot be resolved: its
        name goes to `unresolved_global_refs`, and the DAG gives no address-flow facts to the code
        that reads it (build_callgraph_dag.model_view), so its unit's split keeps the call graph's
        reach.
        """
        for units, names, _kmap in self.pending_taken:
            for k in names:
                fid: str | None = None
                for u in units:
                    fid = self._lookup_global(u, k)
                    if fid is not None:
                        break
                if fid is not None:
                    self.functions[fid]["address_taken"] = True
                    for u in units:
                        self.taken[u].add(fid)
        self.pending_taken = []
        by_name: dict[str, list[str]] = defaultdict(list)
        for global_id, g in self.global_vars.items():
            if not g.get("static"):
                by_name[str(g["name"])].append(global_id)
        for units, rec, fnames, gnames, kmap, gmap, fkey, gkey in self.pending_refs:
            fids: set[str] = set()
            for k in fnames:
                fid = kmap.get(k)
                if fid is None:
                    for u in units:
                        fid = self._lookup_global(u, k)
                        if fid is not None:
                            break
                if fid is not None:
                    fids.add(fid)
            has_failed_closure = any(other in self.failed_units for u in units for other in self.closure.get(u, ()))
            gids: set[str] = set()
            unresolved: set[str] = set()
            for k in gnames:
                found = gmap.get(k)
                cands = by_name.get(k, [])
                if found is None and len(cands) == 1:
                    found = cands[0]
                if found is not None:
                    gids.add(found)
                elif len(cands) > 1 or (not cands and has_failed_closure):
                    unresolved.add(k)
            rec[fkey] = sorted(set(rec.get(fkey) or []) | fids)
            rec[gkey] = sorted(set(rec.get(gkey) or []) | gids)
            if unresolved:
                rec["unresolved_global_refs"] = sorted(set(rec.get("unresolved_global_refs") or []) | unresolved)
        self.pending_refs = []

    def resolve(self) -> None:
        self.resolve_refs()
        for unit, caller, call in self.pending_calls:
            name = call.get("name") or ""
            own = self.globals.get(unit, {}).get(name) if call.get("gcc") else None
            callee = own or self._lookup_global(unit, name)
            source = SOURCE_GCC if call.get("gcc") else SOURCE_FRAMAC
            if callee:
                self.edges[(caller, callee, "direct")].add(source)
                self._record_arg_sizes(caller, callee, call)
                continue
            self.externals.add(name)
            if name:
                self.external_calls[caller].add(name)
            for fid in call.get("resolved_args") or []:
                if not fid:
                    continue
                if name in THREAD_SPAWNERS:
                    self.thread_entries.add(fid)
                    self.concurrent.add(unit)
                    self.edges[(caller, fid, "indirect")].add("thread-spawn")
                else:
                    self.edges[(caller, fid, "indirect")].add("callback-arg")
        for site in self.indirect_sites:
            alias = site.pop("_alias", None)
            if site.get("signature") is None:
                site.update(narrowing="none", narrowing_reason="gcc_fallback", dropped=[])
                continue
            pool: set[str] = set()
            for prog in self.programs:
                if any(u in prog for u in site["units"]):
                    for u in prog:
                        pool |= self.taken.get(u, set())
            cands = sorted(f for f in pool if self.functions[f]["signature"] == site["signature"])
            kept, reason = self._narrow(site, cands, alias)
            site["candidates"] = kept
            site.update(
                narrowing="alias" if reason == "alias" else "none",
                narrowing_reason=reason,
                dropped=sorted(set(cands) - set(kept)),
            )
            for c in kept:
                sources = self.edges[(site["caller"], c, "indirect")]
                sources.add("type-match")
                if reason == "alias":
                    sources.add(SOURCE_ALIAS)

    def _narrow(self, site: dict, cands: list[str], alias: dict | None) -> tuple[list[str], str]:
        """
        The candidates a site keeps and why: `alias` when Alias's targets narrowed the type match,
        else the reason the full type match stays (`disabled`, `alias_<status>`, `no_targets`, ...).
        """
        if alias is None:
            return cands, "disabled"
        if not cands:
            return cands, "no_candidates"
        if alias["status"] != "targets":
            return cands, alias["status"]
        targets: set[str] = set(alias.get("ids") or [])
        for name in alias.get("names") or []:
            fid = self._lookup_global(site["unit"], name) or self.globals.get(site["unit"], {}).get(name)
            if fid:
                targets.add(fid)
        kept = [c for c in cands if c in targets]
        if not kept:
            # Alias names functions, none of the call's type: a cast. Trust the type match.
            return cands, "disjoint"
        return kept, "alias"

    def aliases(self, defines: Iterable[dict]) -> dict[str, dict]:
        """Macro aliases whose value resolves, through other aliases, to defined functions."""
        raw: dict[str, dict] = {}
        for d in defines:
            raw.setdefault(d["alias"], d)
        by_name: dict[str, list[str]] = defaultdict(list)
        for fid, f in self.functions.items():
            by_name[f["name"]].append(fid)
        out: dict[str, dict] = {}
        for alias, d in sorted(raw.items()):
            chain = [d["value"]]
            while chain[-1] in raw and chain[-1] not in by_name and len(chain) < 16 and chain[-1] != alias:
                chain.append(raw[chain[-1]]["value"])
            target = chain[-1]
            if target in by_name and alias not in by_name:
                out[alias] = {
                    "function": target,
                    "ids": sorted(by_name[target]),
                    "via": chain[:-1],
                    "defined_in": d["file"],
                    "source": "preprocessor",
                }
        return out


def build_model(
    capture_path: Path,
    out_path: Path,
    jobs_n: int | None = None,
    broker: bool = True,
    runner: Runner | None = None,
    alias: bool = ALIAS_DEFAULT,
) -> tuple[dict, int]:
    t0 = time.monotonic()
    model: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "status": "error",
        "capture": str(capture_path),
        "warnings": [],
    }
    capture = load_json_optional(capture_path, None)
    if not isinstance(capture, dict) or capture.get("status") != "ok":
        status = capture.get("status") if isinstance(capture, dict) else "missing"
        model["error"] = f"no usable build capture ({status}): run build_capture.py first"
        return model, 1
    tree = str((capture.get("scratch") or {}).get("tree") or "")
    snapshot_root = (capture.get("snapshot") or {}).get("root")
    if not tree or not os.path.isdir(tree):
        model["error"] = f"the capture's scratch tree {tree or '(none)'} is not mounted: run with -Scratch"
        return model, 1
    model.update(
        tree=tree,
        snapshot={"root": snapshot_root, "digest": (capture.get("snapshot") or {}).get("digest")},
        capture_generated_at=capture.get("generated_at"),
    )
    log_dir = out_path.parent / Path(LOG_DIR).name
    jobs, unit_job = plan_jobs(capture)
    builder = ModelBuilder(capture, tree)
    with tempfile.TemporaryDirectory(prefix="framac-p0-module-") as tmp:
        module, why = compile_dump_module(Path(tmp), runner=runner, dump_source=DUMP_SOURCE)
        if module is None:
            model["error"] = why[-2000:]
            model["dump_module"] = {"status": "compile_failed"}
            return model, 1
        model["dump_module"] = {"status": "ok"}
        alias_module: Path | None = None
        alias_info: dict[str, Any] = {"enabled": alias}
        if alias:
            alias_module, why = compile_dump_module(
                Path(tmp), runner=runner, dump_source=ALIAS_SOURCE, packages=ALIAS_PACKAGES
            )
            alias_info.update(module="ok" if alias_module else "compile_failed", timeout_s=ALIAS_TIMEOUT_S)
            if alias_module is None:
                alias_info["error"] = why[-ERROR_CHARS:]
                model["warnings"].append("Alias module does not compile: indirect sites keep their type match")
        model["alias"] = alias_info
        workers = max(1, jobs_n or _default_jobs())

        def one(job: dict) -> dict:
            res = framac_parse(job, tree, snapshot_root, module, log_dir, broker, runner, alias_module)
            if res["status"] != "ok":
                res["gcc"] = gcc_callgraph(job, tree, snapshot_root, log_dir, runner)
            return res

        unique_compiles = {(c["source"], json.dumps(c["flags"])): c for j in jobs for c in j["compiles"]}
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(one, jobs))
            defines = [
                d
                for found in pool.map(lambda c: macro_aliases(c, tree, snapshot_root, runner), unique_compiles.values())
                for d in found
            ]
    parse_jobs = []
    for job, res in zip(jobs, results, strict=True):
        entry: dict[str, Any] = {
            "key": job["key"],
            "units": job["units"],
            "sources": sorted({c["source"] for c in job["compiles"]}),
            "status": res["status"],
            "seconds": res["seconds"],
        }
        if res["status"] == "ok":
            pw = res.get("parse_warnings")
            if isinstance(pw, dict):
                entry["parse_warnings"] = pw
                if pw.get("has_parse_loss"):
                    model["warnings"].append(_format_parse_loss_warning(job["units"], pw))
            report = res.get("alias") or ({"status": "unavailable"} if alias else None)
            if report is not None:
                entry["alias"] = {
                    k: report[k] for k in ("status", "error", "seconds") if report.get(k) not in (None, "")
                }
                if report.get("status") not in ("ok", "unavailable"):
                    model["warnings"].append(
                        f"{', '.join(job['units'])}: Alias {report.get('status')} ({report.get('error', '')}); "
                        "its indirect sites keep their type match"
                    )
            directives = res.get("line_directives")
            if directives:
                entry["line_directives"] = directives
            before = len(builder.relocated)
            builder.add_dump(
                job["units"],
                res["dump"],
                report,
                sources=[c["source"] for c in job["compiles"]],
                line_directives=bool(directives),
            )
            moved = builder.relocated[before:]
            if moved:
                model["warnings"].append(
                    f"{', '.join(job['units'])}: {len(moved)} definition(s) a line directive located outside "
                    "their compiled source were attributed to it: "
                    + "; ".join(f"{m['loc']} -> {m['file']}" for m in moved[:5])
                )
        else:
            entry["error"] = res["error"]
            g = res["gcc"]
            entry["gcc_fallback"] = {"status": g["status"], "errors": g["errors"][:5]}
            builder.add_gcc(job["units"], g)
            if g["status"] == "failed":
                model["warnings"].append(
                    f"{', '.join(job['units'])}: Frama-C cannot parse ({res['error']}) and the GCC fallback "
                    f"failed too ({(g['errors'] or ['no error recorded'])[0]}): unparsed, its parse contributes no function or edge"
                )
            else:
                model["warnings"].append(
                    f"{', '.join(job['units'])}: Frama-C cannot parse ({res['error']}); GCC fallback"
                )
        parse_jobs.append(entry)
    builder.resolve()
    if alias:
        reasons = Counter(s["narrowing_reason"] for s in builder.indirect_sites)
        model["alias"].update(
            sites=dict(sorted(reasons.items())),
            dropped_candidates=sum(len(s["dropped"]) for s in builder.indirect_sites),
            seconds=round(sum((j.get("alias") or {}).get("seconds") or 0 for j in parse_jobs), 3),
        )
    by_key = {j["key"]: j for j in parse_jobs}
    units_out: dict[str, dict] = {}
    for name, u in sorted((capture.get("units") or {}).items()):
        rec = {k: u.get(k) for k in ("kind", "test", "files", "links", "cppflags", "entry_points", "embedded_api")}
        if u.get("embedded_api_source") is not None:
            rec["embedded_api_source"] = str(u["embedded_api_source"])
        if u.get("unit_visibility") is not None:
            rec["unit_visibility"] = str(u["unit_visibility"])
        if u.get("exported_data_symbols") is not None:
            rec["exported_data_symbols"] = list(u["exported_data_symbols"])
        if u.get("test"):
            rec["parse"] = {"status": "skipped_test"}
        elif name not in unit_job:
            rec["parse"] = {"status": "no_sources"}
        else:
            j = by_key[unit_job[name]]
            fallback = j.get("gcc_fallback") or {}
            rec["parse"] = {
                "status": "ok"
                if j["status"] == "ok"
                else (STATUS_UNPARSED if fallback.get("status") == "failed" else "gcc_fallback"),
                "job": j["key"],
                "seconds": j["seconds"],
            }
            if j["status"] == "ok" and isinstance(j.get("parse_warnings"), dict):
                rec["parse"]["warnings"] = j["parse_warnings"]
            if j["status"] != "ok":
                rec["parse"]["error"] = j["error"]
            if rec["parse"]["status"] == STATUS_UNPARSED:
                rec["parse"]["gcc_error"] = (fallback.get("errors") or ["no error recorded"])[0]
        rec["concurrent"] = name in builder.concurrent
        units_out[name] = rec
    for fid, f in builder.functions.items():
        f["external_calls"] = sorted(builder.external_calls.get(fid, ()))
        f["units"] = sorted(f["units"])
        f["kernel_names"] = dict(sorted(f["kernel_names"].items()))
        sizes = builder.param_sizes(fid)
        if sizes:
            # Fixed-size buffers passed without a length (keys, nonces): the harness and the seed
            # recorder size them from what the project's own callers pass.
            f["param_sizes"] = sizes
    model["warnings"].extend(reconcile_api_ids(units_out, builder.functions))
    included = {str(h) for c in capture.get("compiles") or [] for h in c.get("headers") or [] if str(h).endswith(".h")}
    for name, ids in header_api(units_out, builder.functions, capture.get("public_headers"), included).items():
        units_out[name]["header_api"] = ids
    # Phase 0 stops when Frama-C parses no unit: every later phase but fuzzing needs its AST. The
    # model is still written whole, so the fallback errors can be shown to the user.
    parsed = [n for n, u in units_out.items() if u["parse"]["status"] == "ok"]
    rc, status = 0, "ok"
    if not parsed:
        rc, status = NO_UNIT_PARSED_RC, STATUS_NO_UNIT_PARSED
        failed = sorted(n for n, u in units_out.items() if u["parse"]["status"] in FRAMAC_FAILED)
        model["error"] = (
            f"Frama-C parsed none of the units ({', '.join(failed)}): see each unit's parse.error"
            if failed
            else "the capture has no non-test unit with sources to parse"
        )
    model.update(
        status=status,
        units=units_out,
        functions=dict(sorted(builder.functions.items())),
        edges=[
            {"caller": a, "callee": b, "kind": k, "sources": sorted(s)}
            for (a, b, k), s in sorted(builder.edges.items())
        ],
        indirect_sites=sorted(builder.indirect_sites, key=lambda s: (s["caller"], s.get("loc") or "")),
        externals=sorted(builder.externals),
        external_formals={
            n: builder.declared_formals[n] for n in sorted(builder.externals) if n in builder.declared_formals
        },
        external_decls={n: builder.declared_info[n] for n in sorted(builder.externals) if n in builder.declared_info},
        global_variables=dict(sorted(builder.global_vars.items())),
        macro_aliases=builder.aliases(defines),
        entry_points=sorted({e for u in units_out.values() if not u.get("test") for e in u.get("entry_points") or []}),
        entry_points_source="build_capture",
        thread_entries=sorted(builder.thread_entries),
        parse_jobs=parse_jobs,
        seconds=round(time.monotonic() - t0, 2),
    )
    return model, rc


def annotate_trust(
    model: dict, threat_model: Path | None = None, metadata: Path | None = None, codeql: Path | None = None
) -> None:
    """
    Each function's trust (scripts/trust.py, step I7), with the run's CodeQL facts exactly as
    `trust.py run` merges them (trust.load_codeql: the run's metadata must enable CodeQL; a missing
    facts file is `not_run`, one whose status is not `ok` gives no fact). A model rebuilt after the
    CodeQL run therefore keeps its facts (libmodbus run-1 lost them: this annotation left CodeQL out).
    Metadata or facts that cannot be used (where `trust.py run` stops) cost the facts, not the
    annotation: the model is annotated without CodeQL and a warning says why.
    """
    try:
        import trust

        meta, problem = None, None
        try:
            meta = load_json_optional(metadata or trust.DEFAULT_METADATA, None)
        except Exception as exc:  # noqa: BLE001 - annotated without CodeQL below
            problem = f"{type(exc).__name__}: {exc}"
        if isinstance(meta, dict) and trust.codeql_enabled(meta):
            try:
                trust.annotate_model(model, threat_model, codeql, meta)
                return
            except Exception as exc:  # noqa: BLE001 - annotated without CodeQL below, where any other cause shows again
                problem = f"{type(exc).__name__}: {exc}"
        trust.annotate_model(model, threat_model, codeql)
        if problem:
            model["warnings"].append(
                f"trust: annotated without the CodeQL facts ({problem}): fix the file, then run trust.py run"
            )
    except Exception as exc:  # noqa: BLE001 - the inventory stands without the trust annotation
        model["warnings"].append(f"trust: not annotated ({type(exc).__name__}: {exc})")


def _default_jobs() -> int:
    try:
        from resources import job_budget

        return max(1, int(job_budget().cpus))
    except Exception:  # sizing only: never stop the model for it
        return max(1, os.cpu_count() or 1)


def validate_model(model: dict) -> list[str]:
    from minischema import Validator, load_schema

    here = Path(__file__).resolve().parent
    for cand in (here.parent / "schemas", Path("/opt/framac-pipeline/schemas")):
        path = cand / "phase0_model.schema.json"
        if path.is_file():
            return Validator(load_schema(path)).errors(model)
    return ["schemas/phase0_model.schema.json not found"]


# ---------------------------------------------------------------------------------------------------
# Selftest and CLI
# ---------------------------------------------------------------------------------------------------


def selftest(runner: Runner | None = None) -> dict:
    """Compile the dump module and check it on a known two-file program."""
    with tempfile.TemporaryDirectory(prefix="framac-p0-selftest-") as tmp:
        root = Path(tmp)
        for name, text in _SELFTEST_FILES.items():
            (root / name).write_text(text, encoding="utf-8")
        module, why = compile_dump_module(root, runner=runner, dump_source=DUMP_SOURCE)
        if module is None:
            return {"ok": False, "status": "compile_failed", "reason": why[-2000:]}
        job = {
            "key": "selftest",
            "compiles": [{"source": n, "flags": [], "system_flags": []} for n in sorted(_SELFTEST_FILES)],
        }
        res = framac_parse(job, str(root), None, module, root / "logs", broker=False, runner=runner)
        if res["status"] != "ok":
            return {"ok": False, "status": res["status"], "reason": res.get("error", "")}
        builder = ModelBuilder(
            {"units": {"selftest": {"kind": "static_lib", "files": sorted(_SELFTEST_FILES), "links": []}}}, str(root)
        )
        builder.add_dump(["selftest"], res["dump"])
        builder.resolve()
    want_fns = {
        "a.c#helper",
        "b.c#helper",
        "a.c#twice",
        "a.c#apply",
        "a.c#run_a",
        "b.c#run_b",
        "a.c#fill",
        "a.c#use_table",
        "a.c#use_local_table",
        "a.c#use_compound",
        "a.c#use_cast",
        "a.c#init_ctor",
    }
    edges = {(a, b, k) for (a, b, k) in builder.edges}
    want_edges = {
        ("a.c#run_a", "a.c#helper", "direct"),
        ("b.c#run_b", "b.c#helper", "direct"),
        ("a.c#apply", "a.c#twice", "indirect"),
    }
    loops = builder.functions.get("b.c#run_b", {}).get("loops")
    problems = []
    if set(builder.functions) != want_fns:
        problems.append(f"functions {sorted(builder.functions)}")
    if not want_edges <= edges:
        problems.append(f"edges missing {sorted(want_edges - edges)}")
    if loops != 1:
        problems.append(f"run_b loops {loops}")
    writes = builder.functions.get("a.c#fill", {}).get("writes") or {}
    if writes.get("params") != ["p"] or writes.get("globals") != ["counter"] or not writes.get("pointer"):
        problems.append(f"fill writes {writes}")
    if "a.c#counter" not in builder.global_vars:
        problems.append(f"globals {sorted(builder.global_vars)}")
    # Address flow (dump schema 6): `run_a`, `use_compound`, `use_cast` take `twice`'s address;
    # `table` and static-local `sl` hold it in initializers; `use_table` and `use_local_table` read
    # them; `fill` and `init_ctor` write `counter`; `init_ctor` is a constructor; globals carry size.
    flow = {
        "run_a address_refs": (builder.functions.get("a.c#run_a") or {}).get("address_refs"),
        "use_compound address_refs": (builder.functions.get("a.c#use_compound") or {}).get("address_refs"),
        "use_cast address_refs": (builder.functions.get("a.c#use_cast") or {}).get("address_refs"),
        "use_table global_refs": (builder.functions.get("a.c#use_table") or {}).get("global_refs"),
        "use_local_table global_refs": (builder.functions.get("a.c#use_local_table") or {}).get("global_refs"),
        "fill global_refs": (builder.functions.get("a.c#fill") or {}).get("global_refs"),
        "table init_functions": (builder.global_vars.get("a.c#table") or {}).get("init_functions"),
        "sl init_functions": (builder.global_vars.get("a.c#sl") or {}).get("init_functions"),
        "counter size": (builder.global_vars.get("a.c#counter") or {}).get("size"),
        "table size": (builder.global_vars.get("a.c#table") or {}).get("size"),
        "init_ctor constructor": (builder.functions.get("a.c#init_ctor") or {}).get("constructor"),
        "run_a constructor": (builder.functions.get("a.c#run_a") or {}).get("constructor"),
    }
    want_flow = {
        "run_a address_refs": ["a.c#twice"],
        "use_compound address_refs": ["a.c#twice"],
        "use_cast address_refs": ["a.c#twice"],
        "use_table global_refs": ["a.c#table"],
        "use_local_table global_refs": ["a.c#sl"],
        "fill global_refs": ["a.c#counter"],
        "table init_functions": ["a.c#twice"],
        "sl init_functions": ["a.c#twice"],
        "counter size": 4,
        "table size": 8,
        "init_ctor constructor": True,
        "run_a constructor": False,
    }
    if flow != want_flow:
        problems.append(f"address flow {flow}")
    return {"ok": not problems, "status": "ok" if not problems else "unexpected_dump", "reason": "; ".join(problems)}


def unit_errors(model: dict) -> dict[str, str]:
    """Frama-C's first error per unit it could not parse (on the GCC fallback, or unparsed)."""
    return {
        name: str((u.get("parse") or {}).get("error") or "")
        for name, u in sorted((model.get("units") or {}).items())
        if (u.get("parse") or {}).get("status") in FRAMAC_FAILED
    }


def record_checkpoint(state: Path, model: dict, out: Path) -> None:
    """
    `no_unit_parsed` blocks the run as the build capture's `needs_build_recipe` does: the checkpoint
    records the status with each unit's first error, `phase_done` stays, and a resume restarts at the
    model. A model that parses clears it.
    """
    import checkpoint

    if model.get("status") == STATUS_NO_UNIT_PARSED:
        checkpoint.mark_blocked(
            state,
            STATUS_NO_UNIT_PARSED,
            {"report": str(out), "error": model.get("error"), "units": unit_errors(model)},
        )
    else:
        checkpoint.clear_blocked(state, STATUS_NO_UNIT_PARSED)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Phase 0 model: inventory and call graph from Frama-C parses")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="Build workspace/reports/phase0_model.json from the build capture")
    r.add_argument("--capture", type=Path, default=Path(DEFAULT_CAPTURE))
    r.add_argument("--out", type=Path, default=Path(DEFAULT_OUT))
    r.add_argument("--jobs", type=int, default=None, help="Parallel parses (default: this container's CPUs)")
    r.add_argument("--no-broker", action="store_true", help="Run Frama-C without a parse lease (tests, debugging)")
    r.add_argument(
        "--alias",
        action=argparse.BooleanOptionalAction,
        default=ALIAS_DEFAULT,
        help="Narrow indirect sites' type match with Frama-C's Alias plugin (default: %(default)s)",
    )
    r.add_argument("--threat-model", type=Path, default=None, help="THREAT_MODEL.md (default: trust.py's search order)")
    r.add_argument("--metadata", type=Path, default=None, help="run metadata (default: run-metadata.json, as trust.py)")
    r.add_argument("--codeql", type=Path, default=None, help="CodeQL facts (default: trust.py's, when enabled)")
    r.add_argument("--state", default="state", help="checkpoint directory ('' to leave it alone)")
    sub.add_parser("selftest", help="Check the dump module against this kernel")
    a = p.parse_args(argv)
    if a.cmd == "selftest":
        res = selftest()
        print(json.dumps(res, indent=2))
        return 0 if res["ok"] else 1
    model, rc = build_model(a.capture, a.out, a.jobs, broker=not a.no_broker, alias=a.alias)
    if model.get("status") == "ok":
        annotate_trust(model, a.threat_model, a.metadata, a.codeql)
    problems = validate_model(model)
    if problems:
        model["warnings"].append(f"schema: {problems[:5]}")
    atomic_write_json(a.out, model)
    if a.state and model.get("status") in ("ok", STATUS_NO_UNIT_PARSED):
        record_checkpoint(Path(a.state), model, a.out)
    summary = {
        "status": model["status"],
        "error": model.get("error"),
        "units": {n: u["parse"]["status"] for n, u in (model.get("units") or {}).items()},
        "functions": len(model.get("functions") or {}),
        "edges": len(model.get("edges") or []),
        "macro_aliases": len(model.get("macro_aliases") or {}),
        "alias": {k: v for k, v in (model.get("alias") or {}).items() if k in ("enabled", "module", "sites")},
        "seconds": model.get("seconds"),
        "warnings": model["warnings"][:10],
    }
    trust_block = model.get("trust")
    if isinstance(trust_block, dict):
        # What the annotation used, CodeQL included (the facts merged, or why none was).
        summary["trust"] = {
            "threat_model": (trust_block.get("threat_model") or {}).get("status"),
            "codeql": trust_block.get("codeql"),
            "warnings": (trust_block.get("warnings") or [])[:10],
        }
    print(json.dumps(summary, indent=1))
    return rc


if __name__ == "__main__":
    sys.exit(main())
