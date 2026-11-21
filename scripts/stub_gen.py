#!/usr/bin/env python3
"""
The run's stub overlay, workspace/stubs/ (docs/plans/templates-and-stubs-improvement-plan.md step S2). Stdlib only.

    stub_gen.py run   [--model workspace/reports/phase0_model.json] [--capture workspace/reports/build_capture.json]
                      [--overlay workspace/stubs] [--out workspace/reports/stubs.json]
    stub_gen.py brief --header workspace/stubs/<name> [--report workspace/reports/stubs.json]

A run has no other place for the contract of an external function that only a host header declares:
the pipeline's own templates (templates/fc_stubs) are never edited for one target. The overlay is first
on the include path of every Frama-C parse (framac_common.augment_framac_cppflags) and of the E-ACSL
frontend (eacsl_toolchain.build_eacsl_flag_sets), ahead of templates/fc_stubs.

`run` (Make target `stubs`, after the Phase 0 model and before `reach-gate`) is the deterministic half:

  1. From the model (`externals`, `external_decls`: each external function's first declaration and its C
     text), it sorts the externals the target calls by where they are declared: Frama-C's libc
     (`libc`, specified by Frama-C), templates/fc_stubs (`pipeline_stub`, specified: test_fc_stub_contracts),
     the overlay itself (`overlay`), a header of the project (`project_header`: its contract goes on that
     prototype in the work tree, as any ACSL edit), no prototype at all (`undeclared`: a header is missing
     from the flags), and a host header (`host_header`: a package of the target's build).
  2. Every `host_header` function gets a block in workspace/stubs/<name>, where <name> is how the target
     includes the header that declares it (`json-c/json.h`): the overlay header includes the real one
     (`#include_next`), then redeclares the functions with their contracts. A header that the library
     reaches only through a quoted sibling include (`#include "json_object.h"` inside json.h) is never
     looked up on the include path, so the overlay shadows the sibling that includes it instead. A header
     that refuses to be included on its own (an `#error` naming the header to include "directly":
     glibc 2.41 declares `ptrace` in <bits/ptrace-shared.h>, which demands <sys/ptrace.h>) is never
     shadowed either: the overlay shadows the header its `#error` names.
  3. A new block is a skeleton: the real prototype (a variadic one with its `...`, not the Variadic
     plugin's `void * const *__va_params` that the model's dump printed: framac_common.restore_variadic_proto;
     its clauses name the fixed parameters only) and a conservative frame derived from the signature
     (const pointers are read only; a pointer followed by its length bounds a range: `\\valid_read` or
     `\\valid` and, when written, `assigns p[0 .. n - 1]`; a fixed-size array parameter bounds its own
     range; any other written pointer `assigns *p`; a result `assigns \\result`; one `\\from` listing every
     named parameter, since Eva aborts on a location other than \\result without one), guarded by
     `#ifdef FC_STUB_DRAFT` under a `TODO(stub-author)` line. The guard keeps it out of every analysis
     until a stub author (the judgment half: skills/framac-slice/stub_author_brief.md) fills the contract
     from the library's documentation and removes the guard and the TODO line.
  4. Existing blocks are never rewritten: `run` only appends the blocks of functions it has not written
     yet, so re-running it after the author keeps the author's contracts. Two exceptions, both on drafts
     only: a draft that redeclares the `__va_params` translation is rewritten, and a header of drafts only
     whose functions all moved to another header (an older run's shadow of a header that refuses direct
     inclusion) is deleted (`removed` in the report).
  5. The report, workspace/reports/stubs.json, records each overlay header with its sha256 and each
     function's state: `draft` (still guarded), `incomplete` (guard removed, TODO left, or no `assigns`),
     `filled`, or `manual` (a header someone wrote without the markers). `ledger.py record-stub-contracts`
     records every active contract (incomplete, filled, manual) as a `stub_contract` assumption, with the
     header's digest, on the units of the functions that call it.

`brief` renders the stub-author brief for one overlay header from the report.

Exit status: 0 when the report was written, 1 when the model is missing or unreadable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from acsl_ast import (  # noqa: E402
    AcslError,
    has_function_contract,
    iter_clauses,
    locate_all_definition_spans,
    tokenize_c_acsl,
)
from c_definitions import return_type_tokens, returns_void  # noqa: E402
from framac_common import (  # noqa: E402
    STUB_OVERLAY_REL,
    STUB_REPORT_REL,
    VA_PARAMS,
    atomic_write_json,
    load_json_optional,
    restore_variadic_proto,
    utc_now,
)
from kernel_ast import parse_location  # noqa: E402
from patterns import ASSIGNS_RE  # noqa: E402

SCHEMA_VERSION = 1
DEFAULT_MODEL = "workspace/reports/phase0_model.json"
DEFAULT_CAPTURE = "workspace/reports/build_capture.json"
BRIEF = Path(__file__).resolve().parent.parent / "skills" / "framac-slice" / "stub_author_brief.md"

DRAFT_GUARD = "FC_STUB_DRAFT"
TODO_MARK = "TODO(stub-author)"
BLOCK_MARK_RE = re.compile(r"^/\* fc-stub: ([A-Za-z_]\w*) \*/[ \t]*$", re.MULTILINE)
# System include directories gcc searches by default (scripts/target_env.py), longest first.
DEFAULT_SYSTEM_DIRS = ("/usr/local/include", "/usr/include/x86_64-linux-gnu", "/usr/include")
# A snapshot copy of a system header: the target's packages under `root/`, the build image's copies of the libc
# headers Frama-C's libc lacks under `libc/` (scripts/target_env.py). Both hold absolute paths.
_SNAPSHOT_ROOT_RE = re.compile(r"^(?P<root>.*?/workspace/snapshot/(?:root|libc))(?P<path>/.+)$")
_QUOTED_INCLUDE_RE = re.compile(r'^\s*#\s*include\s*"([^"]+)"', re.MULTILINE)
# A header that refuses to be included on its own names the one to include instead in an `#error`:
# glibc's `# error "Never use <bits/ptrace-shared.h> directly; include <sys/ptrace.h> instead."`, GLib's
# `#error "Only <glib.h> can be included directly."`.
_DIRECT_INCLUDE_ERROR_RE = re.compile(r"^[ \t]*#[ \t]*error\b(?P<msg>[^\n]*\bdirectly\b[^\n]*)$", re.MULTILINE | re.I)
_ANGLE_NAME_RE = re.compile(r"<([^<>\s]+)>")
# A draft block written from a model that kept the Variadic plugin's translation (before restore_variadic_proto).
_TRANSLATED_DECL_RE = re.compile(rf"\bvoid\s*\*\s*const\s*\*\s*{VA_PARAMS}\s*\)")
_INCLUDE_DIR_OPTIONS = ("-isystem", "-idirafter", "-iquote", "-I")
_LENGTH_NAME_RE = re.compile(r"(?:^|_)(?:n|len|length|size|sz|cap|capacity|count|nbytes|bytes|max|maxlen)$|len$|size$")
_ARRAY_PARAM_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\[\s*(\d+)\s*\]")
# The `assigns` keyword of a contract (not `no_assigns`): scripts/libc_gap_report.py imports this one.
_ASSIGNS_RE = ASSIGNS_RE

KINDS = ("host_header", "project_header", "libc", "pipeline_stub", "overlay", "undeclared", "unknown")
ACTIVE_STATES = ("incomplete", "filled", "manual")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="surrogateescape")).hexdigest()


def overlay_digest(overlay: Path) -> str | None:
    """sha256 over every file of the overlay (path and content), or None when it has none."""
    if not overlay.is_dir():
        return None
    h = hashlib.sha256()
    n = 0
    for path in sorted(p for p in overlay.rglob("*") if p.is_file()):
        h.update(path.relative_to(overlay).as_posix().encode() + b"\0")
        h.update(hashlib.sha256(path.read_bytes()).hexdigest().encode() + b"\n")
        n += 1
    return h.hexdigest() if n else None


# ---------------------------------------------------------------------------
# Where an external function is declared
# ---------------------------------------------------------------------------


def decl_file(decl: str) -> str:
    """The file of a declaration's location as Frama-C printed it; the text itself when it is not a location."""
    loc = parse_location(decl)
    return loc["file"] if loc["known"] else (decl or "").strip()


def classify(info: dict | None) -> tuple[str, str]:
    """(kind, declaring file as Frama-C printed it) for one entry of the model's `external_decls`."""
    if not info:
        return "unknown", ""
    path = decl_file(str(info.get("decl") or ""))
    proto = str(info.get("proto") or "")
    if "missing proto" in proto:
        return "undeclared", path
    if path.startswith("FRAMAC_SHARE/"):
        return "libc", path
    if "/fc_stubs/" in f"/{path}":
        return "pipeline_stub", path
    if f"/{STUB_OVERLAY_REL}/" in f"/{path}":
        return "overlay", path
    if not posixpath.isabs(path) or path.startswith(("/target/", "/framac-run/workspace/work/")):
        return "project_header", path
    return "host_header", path


def system_path(path: str) -> tuple[str, str]:
    """(path on the build's system, prefix to read it here): a snapshot copy maps back to its original path."""
    m = _SNAPSHOT_ROOT_RE.match(path)
    return (m.group("path"), m.group("root")) if m else (path, "")


def include_roots(capture: dict) -> list[str]:
    """Include directories outside the project the build names, then gcc's defaults, longest first."""
    roots: set[str] = set(DEFAULT_SYSTEM_DIRS)
    for c in capture.get("compiles") or []:
        toks = list(c.get("system_flags") or [])
        for i, tok in enumerate(toks):
            for opt in _INCLUDE_DIR_OPTIONS:
                if tok == opt and i + 1 < len(toks):
                    d = toks[i + 1]
                elif tok.startswith(opt) and len(tok) > len(opt):
                    d = tok[len(opt) :]
                else:
                    continue
                if posixpath.isabs(d):
                    roots.add(posixpath.normpath(d))
                break
    return sorted(roots, key=lambda r: (-len(r), r))


def include_name(sys_path: str, roots: list[str]) -> str:
    """How a `#include <...>` names the header at `sys_path`: relative to the longest include root."""
    for root in roots:
        if sys_path.startswith(root.rstrip("/") + "/"):
            return sys_path[len(root.rstrip("/")) + 1 :]
    return posixpath.basename(sys_path)


def entry_header(real: Path, limit: int = 8) -> Path:
    """
    The header to shadow for `real`: climbing, while a sibling header includes the current one with
    quotes (found in its own directory first, never through the include path), the sibling that does.
    """
    current = real
    seen = {current.name}
    for _ in range(limit):
        try:
            siblings = sorted(p for p in current.parent.glob("*.h") if p.name not in seen)
        except OSError:
            return current
        parent = None
        for sib in siblings:
            try:
                text = sib.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if current.name in _QUOTED_INCLUDE_RE.findall(text):
                parent = sib
                break
        if parent is None:
            return current
        current = parent
        seen.add(current.name)
    return current


def public_header_name(real: Path, sys_path: str) -> str | None:
    """
    The header to include instead of `real` when it refuses to be included on its own: the first other
    `<name>` of an `#error` that says "directly" (glibc's bits/ headers, GLib's sub-headers). None otherwise.
    """
    try:
        text = real.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for m in _DIRECT_INCLUDE_ERROR_RE.finditer(text):
        for name in _ANGLE_NAME_RE.findall(m.group("msg")):
            if name != posixpath.basename(sys_path) and not sys_path.endswith("/" + name):
                return name
    return None


def resolve_include(name: str, roots: list[str], read_prefix: str = "") -> str | None:
    """The path on the build's system of `#include <name>`: the first include root (longest first) holding it."""
    for root in roots:
        candidate = posixpath.join(root, name)
        if Path(read_prefix + candidate).is_file():
            return candidate
    return None


def shadow_header(
    real: Path, sys_path: str, roots: list[str], read_prefix: str = "", limit: int = 4
) -> tuple[str, str]:
    """
    (path on the build's system, include name) of the header the overlay shadows for a declaration in
    `real`: its quoted-include entry (entry_header), then, while that one refuses to be included on its
    own, the header its `#error` names. A shadow of such a header could never be included by stub_check's
    ABI probe, and the target never includes it either. sudo run-1 (glibc 2.41): `ptrace` is declared in
    <bits/ptrace-shared.h>, whose guard demands <sys/ptrace.h>.
    """
    for _ in range(limit):
        entry_path = entry_header(real) if real.is_file() else real
        entry_sys = posixpath.join(posixpath.dirname(sys_path), entry_path.name)
        public = public_header_name(entry_path, entry_sys) if entry_path.is_file() else None
        if public is None:
            return entry_sys, include_name(entry_sys, roots)
        found = resolve_include(public, roots, read_prefix)
        if found is None:
            # Not under a root here: the name the guard demands is still the one the target includes.
            return public, public
        real, sys_path = Path(read_prefix + found), found
    return sys_path, include_name(sys_path, roots)


def without_va_params(proto: str, formals: list[dict]) -> tuple[str, list[dict]]:
    """The prototype as the source wrote it (`...`) and its named formals, the Variadic plugin's one dropped."""
    return restore_variadic_proto(proto), [f for f in formals if f.get("name") != VA_PARAMS]


# ---------------------------------------------------------------------------
# Skeletons
# ---------------------------------------------------------------------------


def _is_length(name: str) -> bool:
    return bool(_LENGTH_NAME_RE.search(name.lower()))


def skeleton_contract(proto: str, formals: list[dict]) -> list[str]:
    """
    The clauses of a conservative frame derived from the signature (no `ensures`: the author states
    what the documentation justifies). Pointer arguments the library reads or writes without a length
    stay as TODO notes: their extent is a judgment.
    """
    arrays = {m.group(1): int(m.group(2)) for m in _ARRAY_PARAM_RE.finditer(proto)}
    requires: list[str] = []
    assigns: list[str] = []
    notes: list[str] = []
    names = [str(f.get("name") or "") for f in formals]
    for i, f in enumerate(formals):
        name, kind = str(f.get("name") or ""), f.get("kind")
        if kind not in ("pointer", "const_pointer") or not name:
            continue
        nxt = formals[i + 1] if i + 1 < len(formals) else None
        length = (
            str(nxt["name"]) if nxt and nxt.get("kind") == "value" and _is_length(str(nxt.get("name") or "")) else None
        )
        if length:
            rng, guard = f"{name} + (0 .. {length} - 1)", f"{length} > 0 ==> "
        elif name in arrays:
            rng, guard = f"{name} + (0 .. {arrays[name] - 1})", ""
        else:
            rng = guard = ""
        if kind == "const_pointer":
            if rng:
                requires.append(f"requires valid_read_{name}: {guard}\\valid_read({rng});")
            else:
                notes.append(f"{name}: read only; a string (valid_read_string) or an object (\\valid_read({name}))?")
            continue
        if rng:
            requires.append(f"requires valid_{name}: {guard}\\valid({rng});")
            hi = f"{length} - 1" if length else str(arrays[name] - 1)
            assigns.append(f"{name}[0 .. {hi}]")
        else:
            assigns.append(f"*{name}")
            notes.append(f"{name}: written through; one object (*{name}) or a range? may it be NULL?")
    # A prototype c_definitions.returns_void cannot read (None) keeps `\result`: the author sees it.
    if not returns_void(proto):
        assigns.append("\\result")
        if "*" in (return_type_tokens(proto) or proto.split("(", 1)[0]):
            notes.append("result: a pointer; may it be NULL? what does it point to (a ghost pool, an argument)?")
    frame = ", ".join(assigns) if assigns else "\\nothing"
    # Eva aborts on a location other than \result without `\from` ([eva:assigns:missing], a deferred error
    # in stub_check and in Phase 2 Eva). Every named parameter, as a direct dependency, is the conservative
    # default: a written pointer may then point wherever an argument does (an `indirect:` source would not
    # let it), and parameter names type-check where `*p` of an incomplete or void type would not. A frame
    # with a location other than \result always has a named pointer, so it never lacks a `\from`.
    params = [n for n in names if n]
    from_part = f" \\from {', '.join(params)}" if assigns and params else ""
    if from_part and assigns != ["\\result"]:
        notes.append(
            "\\from lists every parameter; add what the function reads through them (src[0 .. n - 1]), mark "
            "`indirect:` a pointer that only says where it writes (Eva writes a garbled mix of a direct "
            "pointer source's addresses), never drop a source the documentation does not rule out"
        )
    if re.search(r"\.\.\.\s*\)", proto):
        # A contract on a `...` prototype names its fixed parameters only, as Frama-C's libc does (prctl,
        # warnx); the Variadic plugin keeps it when it translates the declaration and each call.
        notes.append(
            "variadic (`...`): the clauses can name the fixed parameters only; say in a comment what the "
            "documentation says the function reads or writes through the variable arguments"
        )
    lines = [*requires, f"assigns {frame}{from_part};"]
    return [*(f"// {TODO_MARK}: {n}" for n in notes), *lines]


def draft_block(name: str, proto: str, formals: list[dict]) -> str:
    body = "\n".join(f"  {line}" for line in skeleton_contract(proto, formals))
    decl = proto.strip()
    if not decl.startswith("extern"):
        decl = f"extern {decl}"
    return (
        f"/* fc-stub: {name} */\n"
        f"/* {TODO_MARK}: write {name}'s contract from the library's documentation, then delete this line, "
        f"the #ifdef {DRAFT_GUARD} line and its #endif. */\n"
        f"#ifdef {DRAFT_GUARD}\n"
        f"/*@\n{body}\n*/\n"
        f"{decl};\n"
        f"#endif\n"
    )


def header_preamble(name: str, real: str) -> str:
    return (
        f"/* Stub overlay for <{name}> ({real}): scripts/stub_gen.py, docs/plans/templates-and-stubs-improvement-plan.md S2.\n"
        " *\n"
        " * Found first on the include path of Frama-C (Eva, WP) and of the E-ACSL frontend: it includes the\n"
        " * real header, then redeclares the external functions the target calls, each with its ACSL contract.\n"
        f" * A block still under #ifdef {DRAFT_GUARD} is a skeleton, inactive until a stub author fills it\n"
        " * (skills/framac-slice/stub_author_brief.md). Contracts only: never a function body. Every active\n"
        " * contract is an assumption the ledger records with this file's digest.\n"
        " *\n"
        " * <errno.h> declares errno for the contracts (`assigns errno \\from ...;`): Frama-C's libc maps it to\n"
        " * __fc_errno, templates/fc_stubs/errno.h to __fc_eacsl_errno under E-ACSL, where __fc_errno is unbound.\n"
        " */\n"
        "#pragma once\n"
        f"#include_next <{name}>\n" + ("" if name == "errno.h" else "#include <errno.h>\n")
    )


def split_blocks(text: str) -> dict[str, str]:
    """The `fc-stub` blocks of an overlay header, by function name."""
    marks = list(BLOCK_MARK_RE.finditer(text))
    out: dict[str, str] = {}
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        out.setdefault(m.group(1), text[m.start() : end])
    return out


def block_state(block: str) -> str:
    if re.search(rf"^\s*#\s*if(?:def)?\s+{DRAFT_GUARD}\b", block, re.MULTILINE):
        return "draft"
    if TODO_MARK in block:
        return "incomplete"
    try:
        tokens = tokenize_c_acsl(block)
    except AcslError:
        return "incomplete"
    acsl = "\n".join(t.text for t in tokens if t.kind in ("acsl_block", "acsl_line"))
    if not any(kind == "assigns" and pred for kind, _label, pred, _span in iter_clauses(acsl)):
        return "incomplete"
    return "filled"


def header_problems(text: str, path: str) -> list[str]:
    """Mechanical refusals: a function body (an overlay holds contracts only)."""
    try:
        bodies = sorted(locate_all_definition_spans(text, path=path))
    except AcslError as exc:
        return [f"{path}: cannot tokenize: {exc}"]
    return [f"{path}: function body for {name}: an overlay header holds contracts only" for name in bodies]


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


def _callers(model: dict) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for fid, fn in (model.get("functions") or {}).items():
        for name in fn.get("external_calls") or []:
            out.setdefault(name, []).append(fid)
    return {k: sorted(v) for k, v in out.items()}


def plan_headers(model: dict, capture: dict, read_root: str = "") -> tuple[dict[str, dict], dict[str, list]]:
    """
    ({overlay header name: {real, functions: {name: info}}}, {kind: [entries]}) for the model's externals.
    `read_root` prefixes the declaring paths when they are read here (tests: a fake snapshot).
    """
    decls = model.get("external_decls") or {}
    formals = model.get("external_formals") or {}
    roots = include_roots(capture)
    headers: dict[str, dict] = {}
    others: dict[str, list] = {k: [] for k in KINDS if k != "host_header"}
    for name in sorted(model.get("externals") or []):
        info = decls.get(name)
        kind, path = classify(info)
        if kind != "host_header":
            entry: dict[str, Any] = {"function": name}
            if path:
                entry["declared_in"] = path
            others[kind].append(entry)
            continue
        assert info is not None
        sys_path, prefix = system_path(path)
        real = Path(read_root + path)
        entry_sys, hname = shadow_header(real, sys_path, roots, read_root + prefix)
        rec = headers.setdefault(hname, {"real": entry_sys, "functions": {}})
        proto, named = without_va_params(str(info.get("proto") or ""), formals.get(name) or [])
        rec["functions"][name] = {"declared_in": sys_path, "proto": proto, "formals": named}
    return headers, others


def write_overlay(overlay: Path, headers: dict[str, dict]) -> list[str]:
    """Create or extend the overlay headers; returns the run-relative paths it wrote."""
    written: list[str] = []
    for hname, rec in sorted(headers.items()):
        path = overlay / hname
        old = path.read_text(encoding="utf-8") if path.is_file() else None
        if old is not None and not BLOCK_MARK_RE.search(old) and "#include_next" not in old:
            continue  # a header written by hand without the markers: never touched
        text = old if old is not None else header_preamble(hname, rec["real"])
        have = split_blocks(text)
        for fn, block in list(have.items()):
            # A draft that redeclares the Variadic plugin's translation conflicts with the real prototype
            # (gcc: conflicting types): written before restore_variadic_proto, rewritten from the model.
            info = rec["functions"].get(fn)
            if info and info["proto"] and block_state(block) == "draft" and _TRANSLATED_DECL_RE.search(block):
                text = text.replace(block.rstrip("\n") + "\n", "", 1)
                del have[fn]
        new = [
            draft_block(fn, info["proto"], info["formals"])
            for fn, info in sorted(rec["functions"].items())
            if fn not in have and info["proto"]
        ]
        if not new:
            continue
        text = text.rstrip("\n") + "\n\n" + "\n".join(new)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
        written.append(path.as_posix())
    return written


def retire_superseded(overlay: Path, headers: dict[str, dict]) -> dict[str, dict[str, str]]:
    """
    Delete the overlay headers this script wrote that hold drafts only, every one of them now planned in
    another header (an older run shadowed a header that refuses direct inclusion: sudo run-1's
    bits/ptrace-shared.h). A filled block is never deleted: its header stays, and stub_check keeps
    reporting it until its author moves the contract. Returns {run-relative path: {function: new header}}.
    """
    placed = {fn: hname for hname, rec in headers.items() for fn in rec["functions"]}
    removed: dict[str, dict[str, str]] = {}
    if not overlay.is_dir():
        return removed
    for path in sorted(p for p in overlay.rglob("*.h") if p.is_file()):
        rel = path.relative_to(overlay).as_posix()
        if rel in headers:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        blocks = split_blocks(text)
        if not blocks or "#include_next" not in text:
            continue
        if all(block_state(b) == "draft" and placed.get(fn) not in (None, rel) for fn, b in blocks.items()):
            path.unlink()
            removed[path.as_posix()] = {fn: placed[fn] for fn in sorted(blocks)}
    return removed


def describe_overlay(overlay: Path, headers: dict[str, dict], callers: dict[str, list[str]]) -> dict[str, dict]:
    """Every header of the overlay: digest, functions and their states (with the planned functions' callers)."""
    out: dict[str, dict] = {}
    if not overlay.is_dir():
        return out
    for path in sorted(p for p in overlay.rglob("*.h") if p.is_file()):
        rel = path.relative_to(overlay).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        blocks = split_blocks(text)
        planned = (headers.get(rel) or {}).get("functions") or {}
        functions: dict[str, dict] = {}
        if blocks:
            for fn, block in blocks.items():
                functions[fn] = {"state": block_state(block)}
        else:
            # Written by hand: each called external it declares with a contract counts as active.
            for fn in sorted({*planned, *(n for n in callers if re.search(rf"\b{re.escape(n)}\s*\(", text))}):
                try:
                    has = has_function_contract(text, fn, is_header=True, path=rel)
                except AcslError:
                    has = False
                if has:
                    functions[fn] = {"state": "manual"}
        for fn, rec in functions.items():
            rec["callers"] = callers.get(fn, [])
            if fn in planned:
                rec["declared_in"] = planned[fn]["declared_in"]
        out[f"{STUB_OVERLAY_REL}/{rel}"] = {
            "include_name": rel,
            "real": (headers.get(rel) or {}).get("real"),
            "digest": sha256_text(text),
            "problems": header_problems(text, f"{STUB_OVERLAY_REL}/{rel}"),
            "functions": dict(sorted(functions.items())),
        }
    return out


def cmd_run(model_path: Path, capture_path: Path, overlay: Path, out: Path, read_root: str = "") -> int:
    model = load_json_optional(model_path, None)
    if not isinstance(model, dict):
        print(json.dumps({"ok": False, "error": f"no Phase 0 model at {model_path}: run phase0_model.py first"}))
        return 1
    capture = load_json_optional(capture_path, {})
    if not isinstance(capture, dict):
        capture = {}
    callers = _callers(model)
    report: dict[str, Any] = {"schema_version": SCHEMA_VERSION, "generated_at": utc_now(), "overlay": STUB_OVERLAY_REL}
    if "external_decls" not in model:
        # A model from before S2 records the externals without their declarations.
        report["status"] = "model_without_declarations"
        report["reason"] = "the Phase 0 model has no external_decls: rerun phase0_model.py to get the skeletons"
        headers: dict[str, dict] = {}
        others: dict[str, list] = {"unknown": [{"function": n} for n in sorted(model.get("externals") or [])]}
        written: list[str] = []
        removed: dict[str, dict[str, str]] = {}
    else:
        report["status"] = "ok"
        headers, others = plan_headers(model, capture, read_root)
        overlay.mkdir(parents=True, exist_ok=True)
        written = write_overlay(overlay, headers)
        removed = retire_superseded(overlay, headers)
    for entries in others.values():
        for e in entries:
            e["callers"] = callers.get(e["function"], [])
    described = describe_overlay(overlay, headers, callers)
    counts: dict[str, int] = {}
    for h in described.values():
        for fn in h["functions"].values():
            counts[fn["state"]] = counts.get(fn["state"], 0) + 1
    report.update(
        overlay_digest=overlay_digest(overlay),
        written=written,
        removed=removed,
        headers=described,
        other_externals={k: v for k, v in others.items() if v},
        counts=dict(sorted(counts.items())),
    )
    atomic_write_json(out, report)
    print(
        json.dumps(
            {
                "ok": True,
                "status": report["status"],
                "headers": len(described),
                "written": written,
                "removed": sorted(removed),
                "counts": counts,
            }
        )
    )
    return 0


# ---------------------------------------------------------------------------
# brief
# ---------------------------------------------------------------------------


def default_agent_id(header: str) -> str:
    """The stub author's agent id for an overlay header (`workspace/stubs/json-c/json.h` -> `stub-json-c_json_h`)."""
    name = header[len(STUB_OVERLAY_REL) + 1 :] if header.startswith(STUB_OVERLAY_REL + "/") else header
    return "stub-" + (re.sub(r"[^A-Za-z0-9_-]+", "_", name).strip("_") or "header")


def run_command_values(run_dir: Path, agent_id: str) -> dict[str, str]:
    """
    The host paths of the shared "How to run commands" block, found as `workspace_overlay.prepare_agent` finds
    them: the wrapper's environment (FRAMAC_TARGET_HOST, FRAMAC_RUN_HOST, FRAMAC_REFERENCES_HOST) first, then
    the run's metadata. The brief may be rendered inside the container, where `run_dir` is /framac-run.
    """
    import workspace_overlay  # lazily: it is heavy, and it does not import this module

    run_meta = load_json_optional(run_dir / "run-metadata.json", {})
    if not isinstance(run_meta, dict):
        run_meta = {}
    path = workspace_overlay._brief_path
    references_host = path(
        os.environ.get("FRAMAC_REFERENCES_HOST") or str(Path(__file__).resolve().parent.parent / "docs" / "references")
    )
    return {
        "agent_id": agent_id,
        "target_dir": path(os.environ.get("FRAMAC_TARGET_HOST") or run_meta.get("target") or "/target"),
        "run_dir": path(os.environ.get("FRAMAC_RUN_HOST") or run_meta.get("run_dir_host") or str(run_dir.resolve())),
        "pipeline_dir": workspace_overlay._pipeline_host_dir(references_host),
    }


def render_brief(
    header: str,
    report: dict,
    template: str | None = None,
    *,
    agent_id: str | None = None,
    run_dir: Path | None = None,
) -> str:
    """
    The stub author's brief for `header`, with the shared "How to run commands" block spliced at its sentinel:
    the author runs on the host and reaches the container only through the wrapper.
    """
    rec = (report.get("headers") or {}).get(header)
    if rec is None:
        raise KeyError(f"{header} is not an overlay header of {STUB_REPORT_REL}: run `pipeline_make.py run stubs`")
    import workspace_overlay

    todo = sorted(fn for fn, f in rec["functions"].items() if f["state"] in ("draft", "incomplete"))
    callers = sorted({c for f in rec["functions"].values() for c in f.get("callers") or []})
    text = template if template is not None else BRIEF.read_text(encoding="utf-8")
    text = text.replace(
        workspace_overlay.RUN_COMMANDS_SENTINEL,
        workspace_overlay._resolve_brief_template("run_commands").rstrip("\n"),
    )
    values = {
        "header": header,
        "include_name": rec.get("include_name") or "",
        "real_header": rec.get("real") or "(unknown)",
        "functions": ", ".join(todo) or "(none: every block is filled)",
        "callers": ", ".join(callers) or "(none recorded)",
        **run_command_values(Path(".") if run_dir is None else run_dir, agent_id or default_agent_id(header)),
    }
    for key, value in values.items():
        text = text.replace("{" + key + "}", value)
    return text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="Write the skeletons for unspecified host-header externals and the report")
    r.add_argument("--model", type=Path, default=Path(DEFAULT_MODEL))
    r.add_argument("--capture", type=Path, default=Path(DEFAULT_CAPTURE))
    r.add_argument("--overlay", type=Path, default=Path(STUB_OVERLAY_REL))
    r.add_argument("--out", type=Path, default=Path(STUB_REPORT_REL))
    b = sub.add_parser("brief", help="Print the stub-author brief for one overlay header")
    b.add_argument("--header", required=True, help=f"{STUB_OVERLAY_REL}/<name>, as the report names it")
    b.add_argument("--report", type=Path, default=Path(STUB_REPORT_REL))
    b.add_argument(
        "--agent-id",
        type=_agent_id_arg,
        default=None,
        help="the author's agent id (default: stub-<header name>); its agents/<id>/scratch/ is created",
    )
    args = parser.parse_args(argv)
    if args.cmd == "run":
        return cmd_run(args.model, args.capture, args.overlay, args.out)
    report = load_json_optional(args.report, {})
    agent_id = args.agent_id or default_agent_id(args.header)
    try:
        text = render_brief(args.header, report if isinstance(report, dict) else {}, agent_id=agent_id)
    except KeyError as exc:
        print(json.dumps({"ok": False, "error": str(exc.args[0])}))
        return 1
    # The brief's command scripts go here (`-ScriptFile` / `--script-file`); the working directory is the run's.
    (Path("agents") / agent_id / "scratch").mkdir(parents=True, exist_ok=True)
    print(text)
    return 0


def _agent_id_arg(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise argparse.ArgumentTypeError(f"invalid agent id {value!r}: letters, digits, '_' and '-' only")
    return value


if __name__ == "__main__":
    sys.exit(main())
