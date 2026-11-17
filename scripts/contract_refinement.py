#!/usr/bin/env python3
"""
Contract refinement probe (docs/plans/caller-sufficient-contracts-plan.md, step 1).

Compares two ACSL contracts of one C function by meaning, not by text. For a function `f` it writes a
probe translation unit outside the work tree:

- `#include "<f's source file>"`, so every type, macro and logic definition the contracts use is in scope;
- a declaration `f__given` carrying contract A, with no body;
- a definition `f__probe` carrying contract B, whose body is the single call `f__given(<its parameters>)`.

It then runs WP on `f__probe` only, without RTE. If every goal is proved, A refines B: B's `requires`
imply A's, and A's `ensures` and `assigns` give B's under B's `requires`.

Two uses:

1. **Not weaker than before** (`refinement_check`): A is the new contract, B the previous one. A goal left
   unproved names the previous clause the new contract no longer gives (or the new `requires` the old
   precondition does not imply).
2. **Postconditions that say nothing** (`frame_only_ensures`): A is the contract with its `ensures` clauses
   deleted, B the full contract. An `ensures` of B proved here follows from the `requires` and the frame
   alone: it holds for any body, so it tells a caller nothing about this one.

Verdicts: `refines`, `weaker` (with the clauses left unproved: file, line, kind, text) and `undecided`. A
clause counts as not implied only when WP reports a counter-example model for its goal
(`-wp-counter-examples`); a goal left unproved without a model (a timeout on a hard but true implication
looks the same as one on a false one) is undecided. `undecided` is also the verdict when the probe cannot
be built (variadic prototype, unnamed formal, K&R or nested declarator, A without `assigns`, whose frame the
kernel would generate), when Frama-C does not parse it, when the run times out, when an unproved goal is
not one of the probe's clauses, or when no goal at all is proved. `undecided` is never read as `refines`
or `weaker`. A model is the solver's candidate counter-example, which WP does not check: a `weaker` verdict
can still be wrong on a quantified goal, and is recorded, never used to reject a proof.

Limits that decide a verdict are fixed whatever the machine: the per-goal prover timeout
(`PROBE_GOAL_TIMEOUT_S`) and the provers. Only `-wp-par` follows the job budget.

The probe never changes a target file: it is written to a temporary directory (or `--keep-dir`), which
may not lie under `workspace/work/`.

Usage:
  python scripts/contract_refinement.py frame-only --file F.c --function f [--cppflags ...] [--out-json r.json]
  python scripts/contract_refinement.py compare --file NEW.c --previous-file OLD.c --function f [...]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from acsl_ast import (  # noqa: E402
    AcslError,
    DeclSpan,
    contract_declaration_spans,
    declaration_param_names,
    iter_clauses,
    mask_comments_and_literals,
    tokenize_c_acsl,
)

REFINES = "refines"
WEAKER = "weaker"
UNDECIDED = "undecided"
VERDICTS = (REFINES, WEAKER, UNDECIDED)

# Fixed, never derived from the machine: they decide verdicts.
PROBE_GOAL_TIMEOUT_S = 3
PROBE_PROVERS = ("alt-ergo", "z3", "cvc5")
PROBE_WALL_TIMEOUT_S = 180
PROBE_MODEL = "Typed"

GIVEN_SUFFIX = "__given"
PROBE_SUFFIX = "__probe"
LABEL_PREFIX = "fcprobe_"
PROBE_FILE = "contract_probe.c"

_INCLUDE_RE = re.compile(r'^[ \t]*#[ \t]*include[ \t]*["<]([^">\n]+)[">]', re.MULTILINE)
_INCLUDE_DIR_RE = re.compile(r"(?:^|\s)-I\s*(\S+)")
_STORAGE_RE = re.compile(r"(?<![A-Za-z0-9_])(?:static|inline|__inline|__inline__|extern|_Noreturn)(?![A-Za-z0-9_])")
_ATTRIBUTE_RE = re.compile(r"__attribute__\s*\(\(")
_BEHAVIOR_HEAD_RE = re.compile(r"(?<![\\\w])behavior\s+[A-Za-z_][A-Za-z0-9_]*\s*:")
_SECTION_END_RE = re.compile(r"(?<![\\\w])(?:behavior\s+[A-Za-z_]\w*\s*:|complete\s+behaviors|disjoint\s+behaviors)")
_LABEL_RE = re.compile(rf"(?:^|_){LABEL_PREFIX}(\d+)(?:_|$)")
_MODEL_GOAL_RE = re.compile(
    r"^\[wp\] \[(?:Unsuccess|Unknown|Failed|Timeout|Stepout)\] ([A-Za-z_]\w*)(?: \([^)\n]*\))*? \(Model\)",
    re.MULTILINE,
)
_KIND_PROPERTY_RE = {
    "assigns": re.compile(r"(?:^|_)assigns(?:_|$)"),
    "terminates": re.compile(r"(?:^|_)terminates(?:_|$)"),
    "exits": re.compile(r"(?:^|_)exits(?:_|$)"),
}


class ProbeError(RuntimeError):
    """The probe cannot be built for this function: the comparison is `undecided`."""


@dataclass(frozen=True)
class Piece:
    """The ACSL contract in front of one declaration of the function, with that declaration's C head."""

    file: str
    line: int
    acsl: str  # the annotation comment(s) as written, `/*@ ... */` or `//@ ...`
    declarator: str  # the C declaration head (no ACSL, no comments, no `;` or body)
    params: list[str] | None  # named formals, None when one is unnamed
    variadic: bool = False


@dataclass
class FunctionContract:
    """Every contract piece of a function the pipeline reads (source definition, header declarations)."""

    function: str
    pieces: list[Piece] = field(default_factory=list)
    definition: Piece | None = None  # the declaration the probe body is written on
    returns_void: bool | None = None
    source: str = ""

    def text(self) -> str:
        return "\n".join(p.acsl for p in self.pieces)

    def to_dict(self) -> dict[str, Any]:
        return {
            "function": self.function,
            "pieces": [asdict(p) for p in self.pieces],
            "definition": asdict(self.definition) if self.definition else None,
            "returns_void": self.returns_void,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FunctionContract:
        def piece(raw: Any) -> Piece | None:
            if not isinstance(raw, dict):
                return None
            return Piece(
                file=str(raw.get("file") or ""),
                line=int(raw.get("line") or 0),
                acsl=str(raw.get("acsl") or ""),
                declarator=str(raw.get("declarator") or ""),
                params=list(raw["params"]) if isinstance(raw.get("params"), list) else None,
                variadic=bool(raw.get("variadic")),
            )

        pieces = [p for p in (piece(r) for r in data.get("pieces") or []) if p is not None]
        rv = data.get("returns_void")
        return cls(
            function=str(data.get("function") or ""),
            pieces=pieces,
            definition=piece(data.get("definition")),
            returns_void=rv if isinstance(rv, bool) else None,
            source=str(data.get("source") or ""),
        )


# ---------------------------------------------------------------------------
# Reading a function's contract
# ---------------------------------------------------------------------------


def contract_sources(c_file: Path, source: str, cppflags: str = "") -> list[Path]:
    """
    The headers whose declarations of a function in `c_file` carry contract pieces Frama-C merges: the
    sibling `<stem>.h` and the headers `source` includes directly, looked up beside `c_file` and in the
    `-I` directories of `cppflags` (a relative one against the working directory, as the preprocessor
    does, and against `c_file`'s directory). A header found nowhere (a system header, the Frama-C libc)
    is skipped; a contract on a header reached only through another header is not read.
    """
    dirs = [c_file.parent]
    for d in map(Path, _INCLUDE_DIR_RE.findall(cppflags)):
        dirs += [d] if d.is_absolute() else [Path.cwd() / d, c_file.parent / d]
    seen: set[Path] = set()
    out: list[Path] = []
    for name in [c_file.with_suffix(".h").name, *_INCLUDE_RE.findall(source)]:
        header = next((d / name for d in dirs if (d / name).is_file()), None)
        if header is None or header.resolve() in seen or header.resolve() == c_file.resolve():
            continue
        seen.add(header.resolve())
        out.append(header)
    return out


def _decl_head(decl: DeclSpan, path: str) -> str:
    """The C head of a declaration: no ACSL, no comments, no body, no trailing `;`."""
    text = decl.span.text
    masked = mask_comments_and_literals(text, acsl="blank", literals=False, on_error="mask", path=path)
    if decl.kind == "definition":
        brace = masked.find("{")
        masked = masked[:brace] if brace >= 0 else masked
    return " ".join(masked.split()).rstrip(";").strip()


def _param_list(head: str, function: str) -> tuple[str, str] | None:
    """(the text between the parentheses of `function`'s parameter list, the text after them)."""
    m = re.search(rf"(?<![A-Za-z0-9_]){re.escape(function)}\s*\(", head)
    if m is None:
        return None
    depth = 0
    for i in range(m.end() - 1, len(head)):
        if head[i] == "(":
            depth += 1
        elif head[i] == ")":
            depth -= 1
            if depth == 0:
                return head[m.end() : i], head[i + 1 :]
    return None


def _split_params(inner: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    cur: list[str] = []
    for ch in inner:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    parts.append("".join(cur).strip())
    return [p for p in parts if p]


def _strip_attributes(text: str) -> str:
    """`text` without its `__attribute__((...))` groups."""
    out = text
    while (m := _ATTRIBUTE_RE.search(out)) is not None:
        depth = 0
        end = len(out)
        for i in range(m.end() - 2, len(out)):
            if out[i] == "(":
                depth += 1
            elif out[i] == ")":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        out = out[: m.start()] + " " + out[end:]
    return out


def _piece(decl: DeclSpan, function: str, path: str, file_label: str) -> Piece:
    part = decl.span.text
    if decl.kind == "definition":
        masked = mask_comments_and_literals(part, acsl="keep", literals=False, on_error="mask", path=path)
        part = part[: masked.find("{")] if "{" in masked else part
    tokens = [t for t in tokenize_c_acsl(part, path=path) if t.kind in ("acsl_block", "acsl_line")]
    acsl = "\n".join(t.text for t in tokens)
    line = decl.span.start_line + (tokens[0].line - 1 if tokens else 0)
    head = _decl_head(decl, path)
    params_info = _param_list(head, function)
    names = declaration_param_names(decl, path=path)
    params: list[str] | None = names
    variadic = False
    if params_info is not None:
        raw = _split_params(params_info[0])
        variadic = any(p == "..." for p in raw)
        declared = [p for p in raw if p not in ("void", "...")]
        if len(declared) != len(names):
            params = None
    return Piece(file=file_label, line=line, acsl=acsl, declarator=head, params=params, variadic=variadic)


def read_function_contract(c_file: Path, function: str, cppflags: str = "") -> FunctionContract:
    """
    The contract of `function` where Frama-C takes it from: in front of its definition in `c_file`, and on
    its declarations in the headers `c_file` includes directly (`contract_sources`), merged in that order.
    Raises OSError when `c_file` cannot be read and AcslError when it does not tokenize.
    """
    from acsl_ast import function_returns_void

    source = c_file.read_text(encoding="utf-8", errors="replace")
    contract = FunctionContract(function=function, source=str(c_file))
    files: list[tuple[Path, str, bool]] = [(c_file, source, False)]
    for header in contract_sources(c_file, source, cppflags):
        try:
            files.append((header, header.read_text(encoding="utf-8", errors="replace"), True))
        except OSError:
            continue
    for path, text, is_header in files:
        try:
            decls = contract_declaration_spans(text, function, is_header=is_header, path=str(path))
        except AcslError:
            if not is_header:
                raise
            continue
        for decl in decls:
            piece = _piece(decl, function, str(path), str(path))
            if piece.acsl.strip():
                contract.pieces.append(piece)
            if decl.kind == "definition" and contract.definition is None:
                contract.definition = piece
        if contract.returns_void is None:
            try:
                contract.returns_void = function_returns_void(text, function, is_header=is_header, path=str(path))
            except AcslError:
                pass
    if contract.definition is None:
        protos = [p for p in contract.pieces if p.params is not None]
        contract.definition = protos[0] if protos else None
    return contract


# ---------------------------------------------------------------------------
# Building the probe
# ---------------------------------------------------------------------------


def acsl_body(acsl: str) -> str:
    """
    The inside of annotation comment(s), of the same length: `/*@`, `*/`, `//@` and the `@` margins become
    spaces, so offsets and line numbers stay those of `acsl`.
    """
    out = re.sub(r"/\*@", "   ", acsl)
    out = re.sub(r"\*/", "  ", out)
    out = re.sub(r"//@", "   ", out)
    return re.sub(r"(^|\n)([ \t]*)@", lambda m: m.group(1) + m.group(2) + " ", out)


@dataclass
class ClauseRef:
    contract: str  # "given" (A) or "probe" (B)
    kind: str
    file: str
    line: int
    text: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProbeUnit:
    """The probe translation unit and the map from its goals back to the clauses."""

    text: str
    function: str
    labels: dict[int, ClauseRef] = field(default_factory=dict)
    by_kind: dict[str, list[ClauseRef]] = field(default_factory=dict)  # B's unlabelled clauses
    ensures_labels: list[int] = field(default_factory=list)  # B's ensures, in order


def strip_ensures(body: str) -> str:
    """
    `body` (an `acsl_body`) without its `ensures` clauses. A named behavior left empty gets `assumes \\true;`
    (Frama-C rejects an empty named behavior), which is what a behavior without `assumes` means.
    """
    spans = [span for kind, _label, _pred, span in iter_clauses(body) if kind == "ensures"]
    out = body
    for start, end in reversed(spans):
        out = out[:start] + " " * (end - start) + out[end:]
    masked = mask_comments_and_literals(out, acsl="mask", on_error="mask")
    heads = list(_BEHAVIOR_HEAD_RE.finditer(masked))
    for m in reversed(heads):
        nxt = _SECTION_END_RE.search(masked, m.end())
        stop = nxt.start() if nxt else len(masked)
        if not masked[m.end() : stop].strip():
            out = out[: m.end()] + " assumes \\true;" + out[m.end() :]
    return out


def _labelled(body: str, piece: Piece, role: str, unit: ProbeUnit, next_label: list[int]) -> str:
    """`body` with a `fcprobe_<k>:` name on every `requires` / `ensures`, the clauses recorded in `unit`."""
    inserts: list[tuple[int, str]] = []
    for kind, _label, pred, span in iter_clauses(body):
        ref = ClauseRef(
            contract=role,
            kind=kind,
            file=piece.file,
            line=piece.line + body[: span[0]].count("\n"),
            text=" ".join(pred.split()),
        )
        if kind in ("requires", "ensures"):
            k = next_label[0]
            next_label[0] += 1
            unit.labels[k] = ref
            if role == "probe" and kind == "ensures":
                unit.ensures_labels.append(k)
            inserts.append((span[0] + len(kind), f" {LABEL_PREFIX}{k}:"))
        elif role == "probe":
            unit.by_kind.setdefault(kind, []).append(ref)
    out = body
    for pos, text in sorted(inserts, reverse=True):
        out = out[:pos] + text + out[pos:]
    return out


def _check_piece(piece: Piece, function: str, what: str) -> str:
    """The piece's declarator renamed for the probe; ProbeError when the probe cannot carry it."""
    if piece.variadic:
        raise ProbeError(f"{what} of {function} is variadic: the probe cannot forward its arguments")
    split = _param_list(piece.declarator, function)
    if split is None:
        raise ProbeError(f"{what} of {function}: parameter list not found in `{piece.declarator}`")
    if _strip_attributes(split[1]).strip():
        raise ProbeError(
            f"{what} of {function}: text after the parameter list (K&R definition or nested declarator) in "
            f"`{piece.declarator}`"
        )
    return _STORAGE_RE.sub(" ", piece.declarator).strip()


def _rename(declarator: str, function: str, new_name: str) -> str:
    return re.sub(rf"(?<![A-Za-z0-9_]){re.escape(function)}(?=\s*\()", new_name, declarator, count=1)


def build_probe(
    given: list[Piece],
    probe: list[Piece],
    definition: Piece,
    returns_void: bool,
    include: Path,
    function: str,
    *,
    strip_given_ensures: bool = False,
) -> ProbeUnit:
    """
    The probe translation unit: `include` (the function's source, absolute), `f__given` declared once per
    piece of A, `f__probe` declared once per piece of B, then defined on `definition`'s declarator with the
    single call `f__given(<parameters>)`. One declaration per piece, because concatenating pieces would put a
    later top-level clause into an earlier piece's last behavior; Frama-C merges them as it merges the
    contracts of a header prototype and a definition.
    """
    if not given or not probe:
        raise ProbeError(f"{function}: nothing to compare (a contract is empty)")
    if definition.params is None:
        raise ProbeError(f"{function}: a formal parameter of the definition is unnamed")
    def_head = _check_piece(definition, function, "the definition")
    unit = ProbeUnit(text="", function=function)
    label = [1]
    lines = [f'#include "{include.as_posix()}"', ""]
    given_text: list[str] = []
    for p in given:
        head = _check_piece(p, function, f"the declaration at {p.file}:{p.line}")
        body = acsl_body(p.acsl)
        if strip_given_ensures:
            body = strip_ensures(body)
        given_text.append(body)
        lines += [
            "/*@",
            _labelled(body, p, "given", unit, label),
            "*/",
            _rename(head, function, function + GIVEN_SUFFIX) + ";",
            "",
        ]
    if not any(kind == "assigns" for body in given_text for kind, *_ in iter_clauses(body)):
        raise ProbeError(
            f"{function}: the contract compared against has no `assigns` clause, so the kernel would "
            "generate the frame the probe relies on"
        )
    for p in probe:
        head = _check_piece(p, function, f"the declaration at {p.file}:{p.line}")
        body = _labelled(acsl_body(p.acsl), p, "probe", unit, label)
        lines += ["/*@", body, "*/", _rename(head, function, function + PROBE_SUFFIX) + ";", ""]
    args = ", ".join(definition.params)
    call = f"{function}{GIVEN_SUFFIX}({args});"
    lines += [
        _rename(def_head, function, function + PROBE_SUFFIX),
        "{",
        f"  {call}" if returns_void else f"  return {call}",
        "}",
        "",
    ]
    unit.text = "\n".join(lines)
    return unit


# ---------------------------------------------------------------------------
# Running the probe and reading its goals
# ---------------------------------------------------------------------------


def _under_work_tree(path: Path) -> bool:
    """Under `workspace/work/` or an agent's `scratch/work/`: trees a merge diffs against their baseline."""
    parts = path.resolve().as_posix().split("/")
    return any(a in ("workspace", "scratch") and b == "work" for a, b in zip(parts, parts[1:], strict=False))


def probe_command(
    probe_path: Path, function: str, cppflags: str, machdep: str, wp_par: int, json_path: Path, goals_dir: Path
) -> list[str]:
    from framac_common import augment_framac_cppflags
    from resources import WP_MEMLIMIT_MB

    cmd = [
        "frama-c",
        "-pp-annot",
        "-no-unicode",
        "-machdep",
        machdep,
        "-kernel-warn-key",
        "annot-error=abort",
        f"-cpp-extra-args={augment_framac_cppflags(cppflags)}",
        str(probe_path),
        "-wp",
        "-wp-fct",
        function + PROBE_SUFFIX,
        "-wp-model",
        PROBE_MODEL,
    ]
    for prover in PROBE_PROVERS:
        cmd += ["-wp-prover", prover]
    cmd += [
        "-wp-par",
        str(wp_par),
        "-wp-timeout",
        str(PROBE_GOAL_TIMEOUT_S),
        "-wp-memlimit",
        str(WP_MEMLIMIT_MB),
        "-wp-out",
        str(goals_dir),
        "-wp-cache",
        "none",
        # A goal is counted as not implied only with a model: a timeout without one is undecided.
        "-wp-counter-examples",
        "-wp-report-json",
        str(json_path),
    ]
    return cmd


def run_probe(
    unit: ProbeUnit,
    cppflags: str = "",
    machdep: str = "gcc_x86_64",
    *,
    wp_par: int | None = None,
    keep_dir: Path | None = None,
    work_dir: Path | None = None,
) -> dict[str, Any]:
    """
    Run WP on `unit`. Returns {ok, reason, entries, models, elapsed_ms}: `entries` are the `-wp-report-json`
    goals of `f__probe`, `models` the goal names WP printed a model for. The probe is written to `keep_dir`
    when given (it is then kept), else to a temporary directory under `work_dir` (default: the system's).
    """
    if wp_par is None:
        from resources import wp_parallelism

        wp_par = wp_parallelism()
    started = time.monotonic()
    tmp: tempfile.TemporaryDirectory[str] | None = None
    if keep_dir is not None:
        keep_dir.mkdir(parents=True, exist_ok=True)
        directory = keep_dir
    else:
        if work_dir is not None:
            work_dir.mkdir(parents=True, exist_ok=True)
        tmp = tempfile.TemporaryDirectory(prefix="contract_probe_", dir=str(work_dir) if work_dir else None)
        directory = Path(tmp.name)
    try:
        if _under_work_tree(directory):
            return {"ok": False, "reason": f"refusing to write the probe under workspace/work/ ({directory})"}
        probe_path = directory / PROBE_FILE
        json_path = directory / "contract_probe.wp-report-json"
        goals_dir = directory / "goals"
        probe_path.write_text(unit.text, encoding="utf-8", newline="\n")
        if json_path.exists():
            json_path.unlink()
        cmd = probe_command(probe_path, unit.function, cppflags, machdep, wp_par, json_path, goals_dir)
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(directory),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=PROBE_WALL_TIMEOUT_S,
            )
        except subprocess.TimeoutExpired:
            return {"ok": False, "reason": f"the probe run timed out after {PROBE_WALL_TIMEOUT_S}s"}
        except OSError as exc:
            return {"ok": False, "reason": f"frama-c could not be started: {exc}"}
        log = (proc.stdout or "") + "\n" + (proc.stderr or "")
        if keep_dir is not None:
            (directory / "contract_probe.log").write_text(log, encoding="utf-8", newline="\n")
        elapsed_ms = round((time.monotonic() - started) * 1000)
        if proc.returncode != 0 or not json_path.is_file():
            first = next((ln.strip() for ln in log.splitlines() if "rror" in ln or "Failure" in ln), "")
            return {
                "ok": False,
                "reason": f"the probe did not run to the end (rc={proc.returncode}){': ' + first[:300] if first else ''}",
                "elapsed_ms": elapsed_ms,
            }
        try:
            raw = json.loads(json_path.read_text(encoding="utf-8", errors="replace"))
        except ValueError:
            return {"ok": False, "reason": "the probe's WP report is not JSON", "elapsed_ms": elapsed_ms}
        entries = [
            e
            for e in (raw if isinstance(raw, list) else [])
            if isinstance(e, dict) and e.get("function") == unit.function + PROBE_SUFFIX and e.get("smoke") is not True
        ]
        return {
            "ok": True,
            "entries": entries,
            "models": sorted(set(_MODEL_GOAL_RE.findall(log))),
            "elapsed_ms": elapsed_ms,
        }
    finally:
        if tmp is not None:
            tmp.cleanup()


def goal_clauses(unit: ProbeUnit, entry: dict) -> list[ClauseRef]:
    """The clauses a WP goal of the probe checks; empty when it is none of them."""
    prop = str(entry.get("property") or entry.get("goal") or "")
    m = _LABEL_RE.search(prop)
    if m is not None:
        ref = unit.labels.get(int(m.group(1)))
        return [ref] if ref is not None else []
    for kind, pattern in _KIND_PROPERTY_RE.items():
        if pattern.search(prop):
            return list(unit.by_kind.get(kind) or [])
    return []


@dataclass
class GoalOutcome:
    proved: bool
    model: bool
    verdict: str
    clauses: list[ClauseRef]
    label: int | None


def classify_goals(unit: ProbeUnit, run: dict) -> list[GoalOutcome]:
    models = set(run.get("models") or [])
    out: list[GoalOutcome] = []
    for e in run.get("entries") or []:
        prop = str(e.get("property") or e.get("goal") or "")
        m = _LABEL_RE.search(prop)
        out.append(
            GoalOutcome(
                proved=e.get("passed") is True,
                model=str(e.get("goal") or "") in models,
                verdict=str(e.get("verdict") or ""),
                clauses=goal_clauses(unit, e),
                label=int(m.group(1)) if m else None,
            )
        )
    return out


def _clause_rows(outcomes: list[GoalOutcome]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for o in outcomes:
        for ref in o.clauses:
            row = {**ref.to_dict(), "verdict_kind": o.verdict, "model": o.model}
            if row not in rows:
                rows.append(row)
    return rows


def decide(unit: ProbeUnit, run: dict) -> dict[str, Any]:
    """The verdict of a finished probe run (`run_probe`): refines, weaker or undecided."""
    base: dict[str, Any] = {"goal_timeout_s": PROBE_GOAL_TIMEOUT_S, "elapsed_ms": run.get("elapsed_ms")}
    if not run.get("ok"):
        return {**base, "verdict": UNDECIDED, "reason": run.get("reason") or "the probe did not run"}
    outcomes = classify_goals(unit, run)
    base.update(goals=len(outcomes), proved=sum(o.proved for o in outcomes))
    if not outcomes:
        return {**base, "verdict": UNDECIDED, "reason": "WP generated no goal for the probe"}
    unproved = [o for o in outcomes if not o.proved]
    if not unproved:
        return {**base, "verdict": REFINES}
    if len(unproved) == len(outcomes):
        return {**base, "verdict": UNDECIDED, "reason": "no goal of the probe was proved"}
    if any(not o.clauses for o in unproved):
        return {
            **base,
            "verdict": UNDECIDED,
            "reason": "a goal left unproved is none of the compared clauses",
            "undecided_clauses": _clause_rows([o for o in unproved if o.clauses]),
        }
    refuted = [o for o in unproved if o.model]
    open_goals = [o for o in unproved if not o.model]
    if refuted:
        out = {**base, "verdict": WEAKER, "clauses": _clause_rows(refuted)}
        if open_goals:
            out["undecided_clauses"] = _clause_rows(open_goals)
        return out
    return {
        **base,
        "verdict": UNDECIDED,
        "reason": "goals left unproved without a counter-example model (a timeout or a prover giving up)",
        "undecided_clauses": _clause_rows(open_goals),
    }


# ---------------------------------------------------------------------------
# The two uses
# ---------------------------------------------------------------------------


def _undecided(reason: str) -> dict[str, Any]:
    return {"verdict": UNDECIDED, "reason": reason, "goal_timeout_s": PROBE_GOAL_TIMEOUT_S}


def compare(
    given: FunctionContract,
    probe: FunctionContract,
    include: Path,
    cppflags: str = "",
    machdep: str = "gcc_x86_64",
    *,
    strip_given_ensures: bool = False,
    wp_par: int | None = None,
    keep_dir: Path | None = None,
    work_dir: Path | None = None,
) -> tuple[ProbeUnit | None, dict[str, Any], dict[str, Any]]:
    """
    Whether contract `given` (A) refines `probe` (B), by one probe run: (the probe, the run, the verdict).
    The probe body is written on `probe`'s definition. No probe and an empty run when it cannot be built.
    """
    definition = probe.definition or given.definition
    if definition is None:
        reason = f"{probe.function}: no declaration with named parameters to write the probe on"
        return None, {}, _undecided(reason)
    try:
        unit = build_probe(
            given.pieces,
            probe.pieces,
            definition,
            bool(probe.returns_void if probe.returns_void is not None else given.returns_void),
            include.resolve(),
            probe.function,
            strip_given_ensures=strip_given_ensures,
        )
    except (ProbeError, AcslError) as exc:
        return None, {}, _undecided(str(exc))
    run = run_probe(unit, cppflags, machdep, wp_par=wp_par, keep_dir=keep_dir, work_dir=work_dir)
    return unit, run, decide(unit, run)


def _rename_sides(rows: list[dict[str, Any]], names: dict[str, str]) -> list[dict[str, Any]]:
    return [{**r, "contract": names.get(str(r.get("contract")), r.get("contract"))} for r in rows]


def refinement_check(
    new: FunctionContract,
    previous: FunctionContract,
    include: Path,
    cppflags: str = "",
    machdep: str = "gcc_x86_64",
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Use 1: whether the `new` contract gives everything the `previous` one did. `weaker` lists the clauses of
    the previous contract it no longer gives, and the `requires` of the new one the previous precondition
    does not imply (`contract`: `previous` / `new`). An unchanged contract refines without a run; a new
    contract where there was none has nothing to compare.
    """
    if not previous.pieces:
        return {"verdict": REFINES, "reason": "no previous contract", "probe_run": False}
    if " ".join(new.text().split()) == " ".join(previous.text().split()):
        return {"verdict": REFINES, "reason": "contract unchanged", "probe_run": False}
    unit, _run, res = compare(new, previous, include, cppflags, machdep, **kwargs)
    names = {"given": "new", "probe": "previous"}
    for key in ("clauses", "undecided_clauses"):
        if key in res:
            res[key] = _rename_sides(res[key], names)
    res["probe_run"] = unit is not None
    return res


FRAME_DECIDED = "decided"
FRAME_UNDECIDED = "undecided"
FRAME_NOT_APPLICABLE = "not_applicable"


def frame_only_ensures(
    contract: FunctionContract,
    include: Path,
    cppflags: str = "",
    machdep: str = "gcc_x86_64",
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Use 2: which `ensures` clauses of `contract` follow from its `requires` and `assigns` alone. Returns
    {status, ensures, frame_only, not_frame_only, undecided, all_frame_only, ...}. `status` is `decided` when
    the probe either proved every `ensures` or refuted one with a model (then not every `ensures` is
    frame-only, whatever the others are); `not_applicable` when the contract has no `ensures`.
    `all_frame_only` is true only when decided and every `ensures` was proved.
    """
    n_ensures = sum(1 for p in contract.pieces for kind, *_ in iter_clauses(acsl_body(p.acsl)) if kind == "ensures")
    base: dict[str, Any] = {"ensures": n_ensures, "goal_timeout_s": PROBE_GOAL_TIMEOUT_S}
    if n_ensures == 0:
        return {**base, "status": FRAME_NOT_APPLICABLE, "all_frame_only": False}
    unit, run, res = compare(contract, contract, include, cppflags, machdep, strip_given_ensures=True, **kwargs)
    base["elapsed_ms"] = res.get("elapsed_ms")
    if unit is None or not run.get("ok") or not res.get("goals"):
        return {**base, "status": FRAME_UNDECIDED, "reason": res.get("reason"), "all_frame_only": False}
    return {**base, **frame_summary(unit, classify_goals(unit, run))}


def frame_summary(unit: ProbeUnit, outcomes: list[GoalOutcome]) -> dict[str, Any]:
    """The use-2 reading of a probe's goals: each `ensures` of B is frame-only, not, or undecided."""
    by_label: dict[int, list[GoalOutcome]] = {}
    other_unproved = False
    for o in outcomes:
        if o.label is not None and o.label in unit.ensures_labels:
            by_label.setdefault(o.label, []).append(o)
        elif not o.proved:
            other_unproved = True
    frame_only: list[dict[str, Any]] = []
    not_frame: list[dict[str, Any]] = []
    open_rows: list[dict[str, Any]] = []
    for k in unit.ensures_labels:
        ref = unit.labels[k].to_dict()
        ref.pop("contract", None)
        goals = by_label.get(k) or []
        if goals and all(o.proved for o in goals):
            frame_only.append(ref)
        elif any(not o.proved and o.model for o in goals):
            not_frame.append(ref)
        else:
            open_rows.append(ref)
    out: dict[str, Any] = {"frame_only": frame_only, "not_frame_only": not_frame, "undecided": open_rows}
    if other_unproved:
        out.update(status=FRAME_UNDECIDED, reason="a goal other than an ensures was not proved", all_frame_only=False)
    elif not open_rows or not_frame:
        out.update(status=FRAME_DECIDED, all_frame_only=not not_frame and not open_rows)
    else:
        out.update(
            status=FRAME_UNDECIDED,
            reason="ensures left unproved without a counter-example model",
            all_frame_only=False,
        )
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare two ACSL contracts of a C function by a WP probe.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name, help_text in (
        ("frame-only", "which ensures of the function's contract follow from its requires and assigns alone"),
        ("compare", "whether the contract in --file refines the one in --previous-file"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--file", type=Path, required=True, help="C source defining the function")
        p.add_argument("--function", required=True)
        p.add_argument("--cppflags", default="-I.")
        p.add_argument("--machdep", default="gcc_x86_64")
        p.add_argument("--wp-par", type=int, default=None, help="concurrent provers (default: from the job budget)")
        p.add_argument("--keep-dir", type=Path, default=None, help="write and keep the probe and its log here")
        p.add_argument("--out-json", type=Path, default=None, help="write the result here (default: stdout)")
        if name == "compare":
            p.add_argument("--previous-file", type=Path, required=True, help="C source with the previous contract")
    from framac_common import normalize_flag_args

    # `--cppflags -I.`: argparse rejects a separate value that starts with '-'.
    args = parser.parse_args(normalize_flag_args(list(argv) if argv is not None else sys.argv[1:], ("--cppflags",)))
    if args.keep_dir is not None and _under_work_tree(args.keep_dir):
        parser.error("--keep-dir may not lie under workspace/work/")
    try:
        contract = read_function_contract(args.file, args.function, args.cppflags)
        kwargs: dict[str, Any] = {"wp_par": args.wp_par, "keep_dir": args.keep_dir}
        if args.cmd == "frame-only":
            res = frame_only_ensures(contract, args.file, args.cppflags, args.machdep, **kwargs)
        else:
            previous = read_function_contract(args.previous_file, args.function, args.cppflags)
            res = refinement_check(contract, previous, args.file, args.cppflags, args.machdep, **kwargs)
    except (OSError, AcslError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    res = {"function": args.function, "file": args.file.as_posix(), **res}
    text = json.dumps(res, indent=2) + "\n"
    if args.out_json is not None:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(text, encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
