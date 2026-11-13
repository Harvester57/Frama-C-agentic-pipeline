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
     looked up on the include path, so the overlay shadows the sibling that includes it instead.
  3. A new block is a skeleton: the real prototype and a conservative frame derived from the signature
     (const pointers are read only; a pointer followed by its length bounds a range: `\\valid_read` or
     `\\valid` and, when written, `assigns p[0 .. n - 1]`; a fixed-size array parameter bounds its own
     range; any other written pointer `assigns *p`; a result `assigns \\result`), guarded by
     `#ifdef FC_STUB_DRAFT` under a `TODO(stub-author)` line. The guard keeps it out of every analysis
     until a stub author (the judgment half: skills/framac-slice/stub_author_brief.md) fills the contract
     from the library's documentation and removes the guard and the TODO line.
  4. Existing blocks are never rewritten: `run` only appends the blocks of functions it has not written
     yet, so re-running it after the author keeps the author's contracts.
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
import posixpath
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from acsl_ast import AcslError, has_function_contract, locate_all_definition_spans  # noqa: E402
from c_definitions import return_type_tokens, returns_void  # noqa: E402
from framac_common import STUB_OVERLAY_REL, STUB_REPORT_REL, atomic_write_json, load_json_optional, utc_now  # noqa: E402
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
_SNAPSHOT_ROOT_RE = re.compile(r"^(?P<root>.*?/workspace/snapshot/root)(?P<path>/.+)$")
_QUOTED_INCLUDE_RE = re.compile(r'^\s*#\s*include\s*"([^"]+)"', re.MULTILINE)
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
    from_part = f" \\from {', '.join(n for n in names if n)}" if assigns == ["\\result"] and any(names) else ""
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
        " */\n"
        "#pragma once\n"
        f"#include_next <{name}>\n"
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
    contracts = re.findall(r"/\*@.*?\*/", block, re.DOTALL)
    if TODO_MARK in block or not any(_ASSIGNS_RE.search(c) for c in contracts):
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
        sys_path, _ = system_path(path)
        real = Path(read_root + path) if read_root else Path(path)
        entry_path = entry_header(real) if real.is_file() else real
        entry_sys = posixpath.join(posixpath.dirname(sys_path), entry_path.name)
        hname = include_name(entry_sys, roots)
        rec = headers.setdefault(hname, {"real": entry_sys, "functions": {}})
        rec["functions"][name] = {
            "declared_in": sys_path,
            "proto": str(info.get("proto") or ""),
            "formals": formals.get(name) or [],
        }
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
    else:
        report["status"] = "ok"
        headers, others = plan_headers(model, capture, read_root)
        overlay.mkdir(parents=True, exist_ok=True)
        written = write_overlay(overlay, headers)
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
        headers=described,
        other_externals={k: v for k, v in others.items() if v},
        counts=dict(sorted(counts.items())),
    )
    atomic_write_json(out, report)
    print(
        json.dumps(
            {"ok": True, "status": report["status"], "headers": len(described), "written": written, "counts": counts}
        )
    )
    return 0


# ---------------------------------------------------------------------------
# brief
# ---------------------------------------------------------------------------


def render_brief(header: str, report: dict, template: str | None = None) -> str:
    rec = (report.get("headers") or {}).get(header)
    if rec is None:
        raise KeyError(f"{header} is not an overlay header of {STUB_REPORT_REL}: run `pipeline_make.py run stubs`")
    todo = sorted(fn for fn, f in rec["functions"].items() if f["state"] in ("draft", "incomplete"))
    callers = sorted({c for f in rec["functions"].values() for c in f.get("callers") or []})
    text = template if template is not None else BRIEF.read_text(encoding="utf-8")
    values = {
        "header": header,
        "include_name": rec.get("include_name") or "",
        "real_header": rec.get("real") or "(unknown)",
        "functions": ", ".join(todo) or "(none: every block is filled)",
        "callers": ", ".join(callers) or "(none recorded)",
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
    args = parser.parse_args(argv)
    if args.cmd == "run":
        return cmd_run(args.model, args.capture, args.overlay, args.out)
    report = load_json_optional(args.report, {})
    try:
        print(render_brief(args.header, report if isinstance(report, dict) else {}))
    except KeyError as exc:
        print(json.dumps({"ok": False, "error": str(exc.args[0])}))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
