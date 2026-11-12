#!/usr/bin/env python3
"""
libc gap report (docs/plans/templates-and-stubs-improvement-plan.md step S7).

Lists the external functions that Phase 0 models call and that neither Frama-C's libc (`__fc_libc`, the
headers Eva and WP parse with `-nostdinc`) nor the pipeline's own stubs (`templates/fc_stubs`) give a
contract with an `assigns` clause. Eva then applies a default frame, WP reports `unsound_proof`, and a
buffer the call fills keeps the caller's value. The report orders what `fc_compat_types.h` gains next and
seeds the per-run stub skeletons (step S2).

Each external name of every model (`externals`, with the callers from each function's `external_calls`)
gets one status:

  stub              a stub header of the pipeline declares it with a contract (covered)
  libc              __fc_libc declares it with a contract (covered)
  variadic          __fc_libc declares it variadic without a contract: the Variadic plugin writes one per
                    call from the format (`printf`, `fprintf`), so it is covered as long as the format is
                    a literal
  no_contract       declared (libc or stubs) without a contract that has `assigns`: a gap
  undeclared_host   neither declares it, a host header does (glibc, Linux, or a library installed in the
                    image such as zlib): a gap, `declared_in` names the host header
  undeclared_other  nobody declares it: a library absent from the image or code outside the model's units
  internal          a Frama-C or compiler builtin (`__FC_*`, `Frama_C_*`, `__va_*`, `__builtin_*`)

The header scan is textual: it reads every `*.h` under each directory, ignoring preprocessor conditions,
and takes the ACSL block written directly in front of a prototype as its contract. A function declared in
a branch the parse never takes still counts as declared.

Usage:
    libc_gap_report.py [--libc DIR] [--stubs DIR] [--host-include DIR ...] [--json OUT] PATH...

PATH is a run directory (`<run>/workspace/reports/phase0_model.json`), a model file, or any directory
searched for models; with several runs of one target, the newest model (`generated_at`) is used. `--libc`
defaults to `$(frama-c -print-share-path)/libc`, `--host-include` to `/usr/include` when present.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from acsl_ast import AcslError, Token, tokenize_c_acsl

MODEL_REL = Path("workspace") / "reports" / "phase0_model.json"
_RUN_DIR_RE = re.compile(r"run-\d+\Z")
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_ASSIGNS_RE = re.compile(r"(?<![A-Za-z0-9_])assigns\b")
_ACSL_STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"')
_ACSL_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
# A statement made only of these is a macro standing alone (`__BEGIN_DECLS`, `__PUSH_FC_STDLIB`), not the
# start of a declaration: a contract written after it still belongs to the next prototype.
_NOISE_MACRO_RE = re.compile(r"__[A-Z][A-Z0-9_]*\Z")
_NOT_A_NAME = frozenset(
    {
        "__attribute__", "__attribute", "__declspec", "__asm__", "__asm", "asm", "_Alignas", "alignas",
        "__typeof__", "typeof", "_Static_assert", "static_assert",
    }
)  # fmt: skip
_INTERNAL_RE = re.compile(r"(?:__FC_|__fc_|Frama_C_|__va_|__builtin_|__e_acsl_)")

COVERED = ("stub", "libc", "variadic")
GAPS = ("no_contract", "undeclared_host")


@dataclass(frozen=True)
class Declaration:
    """Where a function is declared, and whether some declaration carries a contract with `assigns`."""

    files: tuple[str, ...]
    contract: bool
    variadic: bool = False


def has_assigns(contract: str | None) -> bool:
    if contract is None:
        return False
    body = _ACSL_LINE_COMMENT_RE.sub("", _ACSL_STRING_RE.sub('""', contract[3:-2]))
    return _ASSIGNS_RE.search(body) is not None


def _prototype_name(texts: list[str]) -> str | None:
    """The declared function name if this top-level statement is a function prototype."""
    if not texts or texts[0] in ("typedef", "_Static_assert", "static_assert") or "{" in texts or "=" in texts:
        return None
    for i, text in enumerate(texts):
        if text != "(" or i == 0:
            continue
        prev = texts[i - 1]
        if texts[i + 1 : i + 2] == ["*"]:
            # `T (*name)(...)` is a function-pointer object; `T (*name(params))(...)` a function.
            j = i + 2
            while j < len(texts) and texts[j] in ("*", "const", "volatile", "restrict"):
                j += 1
            if j + 1 < len(texts) and _IDENT_RE.match(texts[j]) and texts[j + 1] == "(":
                return texts[j]
            return None
        if prev not in _NOT_A_NAME and _IDENT_RE.match(prev):
            return prev if i >= 2 else None  # `MACRO(args);` has no declaration specifiers
        return None
    return None


@dataclass(frozen=True)
class Prototype:
    name: str
    contract: str | None  # the ACSL block written directly in front of it
    variadic: bool


def _is_variadic(texts: list[str]) -> bool:
    return any(texts[i : i + 3] == [".", ".", "."] for i in range(len(texts) - 2))


def parse_prototypes(source: str, path: str = "<input>") -> list[Prototype]:
    """Every top-level prototype of a header, with the ACSL block written directly in front of it."""
    tokens = tokenize_c_acsl(source, path=path)
    out: list[Prototype] = []
    stmt: list[Token] = []
    pending: str | None = None
    contract: str | None = None
    depth = 0
    linkage: list[bool] = []

    for tok in tokens:
        if tok.kind in ("whitespace", "c_comment"):
            continue
        if depth > 0:
            if tok.kind == "c_token" and tok.text == "{":
                depth += 1
            elif tok.kind == "c_token" and tok.text == "}":
                depth -= 1
            continue
        if not stmt and tok.kind == "c_token" and _NOISE_MACRO_RE.match(tok.text):
            continue  # a macro standing alone: it neither starts a declaration nor detaches a contract
        if tok.kind == "acsl_block":
            pending = tok.text if not stmt else pending
            continue
        if tok.kind in ("pp_directive", "acsl_line"):
            if not stmt:
                pending = None
            continue
        if tok.kind == "c_token" and tok.text == "{":
            if len(stmt) == 2 and stmt[0].text == "extern" and stmt[1].kind == "string":
                stmt, pending = [], None
                linkage.append(True)
                continue
            depth += 1
            stmt.append(tok)
            continue
        if tok.kind == "c_token" and tok.text == "}" and linkage:
            linkage.pop()
            stmt, pending = [], None
            continue
        if not stmt:
            contract, pending = pending, None
        if tok.kind == "c_token" and tok.text == ";":
            texts = [t.text for t in stmt]
            name = _prototype_name(texts)
            if name is not None:
                out.append(Prototype(name, contract, _is_variadic(texts)))
            stmt = []
            continue
        stmt.append(tok)
    return out


def scan_headers(roots: list[Path], label: str) -> tuple[dict[str, Declaration], list[str]]:
    """Every prototype under `roots` (`*.h`, recursively): name -> Declaration; and the files that did not lex."""
    files: dict[str, list[str]] = defaultdict(list)
    contract: dict[str, bool] = defaultdict(bool)
    variadic: dict[str, bool] = defaultdict(bool)
    skipped: list[str] = []
    for root in roots:
        for header in sorted(root.rglob("*.h")):
            rel = f"{label}:{header.relative_to(root).as_posix()}"
            try:
                protos = parse_prototypes(header.read_text(encoding="utf-8", errors="replace"), path=str(header))
            except (AcslError, OSError, IndexError):
                skipped.append(rel)
                continue
            for p in protos:
                if rel not in files[p.name]:
                    files[p.name].append(rel)
                contract[p.name] = contract[p.name] or has_assigns(p.contract)
                variadic[p.name] = variadic[p.name] or p.variadic
    return {n: Declaration(tuple(f), contract[n], variadic[n]) for n, f in files.items()}, skipped


def find_models(paths: list[Path]) -> list[Path]:
    """Model files for the given run directories, model files or search roots."""
    found: list[Path] = []
    for p in paths:
        if p.is_file():
            found.append(p)
        elif (p / MODEL_REL).is_file():
            found.append(p / MODEL_REL)
        elif p.is_dir():
            found.extend(sorted(p.rglob("phase0_model.json")))
    return [m for m in dict.fromkeys(found) if m.parent.name == "reports" or m in paths]


def target_of(model: Path) -> str:
    """`<target>/run-N/workspace/reports/phase0_model.json` -> target; otherwise the run directory's name."""
    parts = model.resolve().parts
    run = Path(*parts[:-3]) if len(parts) > 3 and parts[-3:-1] == ("workspace", "reports") else model.parent
    return run.parent.name if _RUN_DIR_RE.match(run.name) else run.name


def newest_per_target(models: list[Path]) -> dict[str, tuple[Path, dict]]:
    chosen: dict[str, tuple[Path, dict]] = {}
    for m in models:
        try:
            doc = json.loads(m.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(doc, dict) or "externals" not in doc:
            continue
        t = target_of(m)
        if t not in chosen or str(doc.get("generated_at", "")) > str(chosen[t][1].get("generated_at", "")):
            chosen[t] = (m, doc)
    return dict(sorted(chosen.items()))


def classify(
    name: str, libc: dict[str, Declaration], stubs: dict[str, Declaration], host: dict[str, Declaration]
) -> str:
    if _INTERNAL_RE.match(name):
        return "internal"
    s, lc = stubs.get(name), libc.get(name)
    if s is not None and s.contract:
        return "stub"
    if lc is not None and lc.contract:
        return "libc"
    if lc is not None and lc.variadic and s is None:
        return "variadic"
    if s is not None or lc is not None:
        return "no_contract"
    return "undeclared_host" if name in host else "undeclared_other"


def build_report(
    models: dict[str, tuple[Path, dict]],
    libc: dict[str, Declaration],
    stubs: dict[str, Declaration],
    host: dict[str, Declaration],
) -> dict:
    """One entry per external name over all models, gaps first, most-called first."""
    targets: dict[str, set[str]] = defaultdict(set)
    callers: dict[str, set[str]] = defaultdict(set)
    for t, (_, doc) in models.items():
        for name in doc.get("externals") or []:
            if name:
                targets[name].add(t)
        for fid, fn in (doc.get("functions") or {}).items():
            for name in fn.get("external_calls") or []:
                targets[name].add(t)
                callers[name].add(f"{t}:{fid}")
    entries: list[dict[str, Any]] = []
    for name in targets:
        status = classify(name, libc, stubs, host)
        decl = [*(stubs[name].files if name in stubs else ()), *(libc[name].files if name in libc else ())]
        if status == "undeclared_host":
            decl = list(host[name].files)
        entries.append(
            {
                "name": name,
                "status": status,
                "targets": sorted(targets[name]),
                "callers": len(callers[name]),
                "declared_in": decl,
            }
        )
    order = {s: i for i, s in enumerate((*GAPS, "undeclared_other", *COVERED, "internal"))}
    entries.sort(key=lambda e: (order[e["status"]], -len(e["targets"]), -e["callers"], e["name"]))
    counts: dict[str, int] = defaultdict(int)
    for e in entries:
        counts[e["status"]] += 1
    return {
        "targets": {
            t: {"model": m.as_posix(), "generated_at": doc.get("generated_at")} for t, (m, doc) in models.items()
        },
        "counts": {s: counts[s] for s in order},
        "functions": entries,
    }


def render_text(report: dict) -> str:
    lines = [f"libc gap report over {len(report['targets'])} target(s): {', '.join(report['targets']) or '-'}"]
    lines.append("counts: " + ", ".join(f"{s}={n}" for s, n in report["counts"].items()))
    for title, wanted in (
        ("Gaps (no contract, or declared only by a host header)", GAPS),
        (
            "Undeclared, not in the host headers either (a library absent from the image, or outside the units)",
            ("undeclared_other",),
        ),
    ):
        rows = [e for e in report["functions"] if e["status"] in wanted]
        lines += ["", f"{title}: {len(rows)}"]
        for e in rows:
            where = f"  [{', '.join(e['declared_in'])}]" if e["declared_in"] else ""
            lines.append(
                f"  {e['name']:<28} {e['status']:<17} targets={len(e['targets'])} callers={e['callers']:<4}"
                f" {','.join(e['targets'])}{where}"
            )
    return "\n".join(lines) + "\n"


def default_libc_dir() -> Path | None:
    if shutil.which("frama-c") is None:
        return None
    try:
        share = subprocess.run(
            ["frama-c", "-print-share-path"], capture_output=True, text=True, encoding="utf-8", timeout=60, check=True
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    libc = Path(share) / "libc"
    return libc if libc.is_dir() else None


def default_stubs_dir() -> Path | None:
    for cand in (
        Path("/opt/framac-pipeline/templates/fc_stubs"),
        Path(__file__).resolve().parents[1] / "templates/fc_stubs",
    ):
        if cand.is_dir():
            return cand
    return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0] if __doc__ else None)
    ap.add_argument("paths", nargs="+", type=Path, help="run directories, model files or directories to search")
    ap.add_argument("--libc", type=Path, help="Frama-C's libc directory (default: frama-c -print-share-path)/libc")
    ap.add_argument("--stubs", type=Path, help="the pipeline's stub headers (default: templates/fc_stubs)")
    ap.add_argument(
        "--host-include", type=Path, action="append", default=None, help="host system headers (default /usr/include)"
    )
    ap.add_argument("--json", type=Path, help="write the report as JSON here")
    args = ap.parse_args(argv)

    libc_dir = args.libc or default_libc_dir()
    if libc_dir is None or not libc_dir.is_dir():
        print("libc_gap_report: Frama-C's libc not found; pass --libc DIR", file=sys.stderr)
        return 2
    stubs_dir = args.stubs or default_stubs_dir()
    host_dirs = args.host_include if args.host_include is not None else [Path("/usr/include")]
    host_dirs = [d for d in host_dirs if d.is_dir()]

    models = newest_per_target(find_models(args.paths))
    if not models:
        print("libc_gap_report: no Phase 0 model found under the given paths", file=sys.stderr)
        return 1
    libc, skipped = scan_headers([libc_dir], "libc")
    stubs, skipped_stubs = scan_headers([stubs_dir], "fc_stubs") if stubs_dir else ({}, [])
    host_decls, _ = scan_headers(host_dirs, "host") if host_dirs else ({}, [])

    report = build_report(models, libc, stubs, host_decls)
    report["sources"] = {
        "libc": libc_dir.as_posix(),
        "stubs": stubs_dir.as_posix() if stubs_dir else None,
        "host_include": [d.as_posix() for d in host_dirs],
        "unparsed_headers": skipped + skipped_stubs,
    }
    if args.json:
        from framac_common import atomic_write_json

        atomic_write_json(args.json, report)
    sys.stdout.write(render_text(report))
    return 0


if __name__ == "__main__":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    sys.exit(main())
