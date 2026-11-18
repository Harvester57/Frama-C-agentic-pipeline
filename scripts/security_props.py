#!/usr/bin/env python3
"""
Security layers L3-L6 (docs/plans/archive/phase0-implementation-plan.md step I9): the obligations the threat model
requires, as MetAcsl meta-properties, and the frame obligation of every function that writes through a
pointer. Stdlib only.

    security_props.py run [--model workspace/reports/phase0_model.json]
                          [--out workspace/reports/security_props.json]
    security_props.py meta-file --function FILE#NAME [--props PATH] --out META.c

`run` reads the Phase 0 model (scripts/phase0_model.py, with the dump's `writes`, `formals` and
`global_variables`) and the structured threat model (THREAT_MODEL.md's `framac-threat-model` block):
the file the model's trust annotation recorded (`trust.threat_model`, path and sha256), so the
properties and the trust come from one threat model (a model without a trust annotation: trust.py's
search order, with a warning). It writes security_props.json
(schemas/security_props.schema.json), with its own schema problems as a `schema:` warning:

  L3  frame: every function that writes through a pointer (the dump's `writes`, or a call to a libc
      memory writer such as memcpy) needs an `assigns` clause WP proves (class l3_frame);
  L4  each auth gate {function, state, protects}:
        L4_auth_state_<gate>     only the gate writes the state (\\writing, every other function);
        L4_auth_required_<gate>  each protected function requires it (\\precond, proved at call sites);
  L5  each output sink: L5_sanitized_<sink>, an assertion at every call of the sink (\\calling, so it
      also holds for a sink the target only declares) that its writers (callers) discharge - no CR/LF
      in text handed to a log or terminal sink, initialized bytes handed to the others - or, for a
      `buffer` sink, initialized out-parameters when it returns (\\postcond). A caller that hands a
      text sink string literals only is decided from the model's call sites instead (plan step M2):
      no goal, the property's `decided` and the obligation's `decided` record the verdict.
      A sink the target defines and calls through a function pointer gets the same obligation as its
      precondition (\\precond), proved at each call: MetAcsl cannot name the arguments of an indirect
      call. A bytes sink that reaches other declared bytes sinks in the model's call graph is a
      forwarding sink: its bytes are checked at the innermost ones, where they leave, and its own
      property has no instance (`forwarded_to`), unless one indirect call site on the way may also
      reach a function that reaches no declared sink (the property stays, with a warning);
  L6  each secret:
        L6_wiped_<secret>    zero when its release function (the secret's `function`) returns;
        L6_no_leak_<secret>  never passed to a sink, never read by a sink the target defines.

Three optional threat-model lists (docs/plans/metacsl-exploitation-plan.md, package D1):
  assets      L3_writers_<asset> (only the writers write the lvalue, \\writing) and, with `readers`,
              L3_readers_<asset> (\\reading); class l3_isolation;
  invariants  L4_invariant_<name>, class l4_invariant: weak, strong or conditional over the functions
              of its `scope`, or monotonic (an lvalue only moves one way, at every write; not for Eva,
              see `engines` and for_engine);
  call_rules  L4_call_<callee>, class l4_call_rule: a predicate at every call of the callee.
Their predicates and lvalues are validated before they reach an annotation (predicate_problem), and
no generated text holds what MetAcsl mishandles (meta_text_problems).

Where MetAcsl 0.12 generates nothing, the property says so instead of passing silently:
  - a \\writing property reads the `assigns` of the declared functions its targets call (at their
    declaration; the model holds no contract). Callers of a callee whose `assigns` holds a set leave
    the targets (MetAcsl stops on it) and are listed under `unchecked`; callees without `assigns`
    are listed under `declared_callees`;
  - a call placed in an initializer gets no \\calling, \\writing or \\strong_invariant instance. With
    the model's `initializer` flag on call sites (phase0_dump.ml, dump schema 5), each such site is
    listed under `init_checks` and `run` writes a `check` named after the property there
    (`code_checks`); a site no check can be written for is `unchecked`.

The templates are templates/metacsl/*.acsl. Each property lists its `instances`: the functions in whose
WP proof its generated annotations land (the target of a \\postcond, the callers of a \\precond or
\\calling target, the writers of a \\writing property). Those are the ledger units (`ledger.py seed`
reads this file): class l4_auth_state, l4_auth_required, l5_sanitized, l6_wiped or l6_no_leak, keyed
to the property names they must discharge.

`meta-file` writes, for one function, the MetAcsl file its WP run parses (the preamble and every
property with an instance there) and prints the extra sources the properties need (the files defining
the globals they name). run_wp_function.py --security-props does the same itself.

Without a threat model only L3 is generated and the status says why. `run` writes nothing and exits:
  1  no model with status ok, or a recorded threat model that changed, went missing or appeared
     since the model was built (re-run the model);
  2  the model recorded an invalid threat model (the errors are printed).
"""

from __future__ import annotations

import argparse
import json
import re
import string
import sys
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from framac_common import atomic_write_json, load_json_optional, utc_now  # noqa: E402
from phase0_model import MODEL_FEATURES, model_features  # noqa: E402

SCHEMA_VERSION = 1
DEFAULT_MODEL = Path("workspace/reports/phase0_model.json")
DEFAULT_OUT = Path("workspace/reports/security_props.json")

# Property kind -> (layer, ledger obligation class).
KINDS: dict[str, tuple[int, str]] = {
    "frame": (3, "l3_frame"),
    "auth_state": (4, "l4_auth_state"),
    "auth_required": (4, "l4_auth_required"),
    "sanitized": (5, "l5_sanitized"),
    "wiped": (6, "l6_wiped"),
    "no_leak": (6, "l6_no_leak"),
    # Package D1 of docs/plans/metacsl-exploitation-plan.md (names: its section 3.3).
    "asset_writers": (3, "l3_isolation"),
    "asset_readers": (3, "l3_isolation"),
    "invariant": (4, "l4_invariant"),
    "call_rule": (4, "l4_call_rule"),
}
CLASSES = tuple(dict.fromkeys(cls for _, cls in KINDS.values()))
# Generated property names start with these; run_wp_function maps goals named so to the class.
NAME_PREFIX = {
    "auth_state": "L4_auth_state_",
    "auth_required": "L4_auth_required_",
    "sanitized": "L5_sanitized_",
    "wiped": "L6_wiped_",
    "no_leak": "L6_no_leak_",
    "asset_writers": "L3_writers_",
    "asset_readers": "L3_readers_",
    "invariant": "L4_invariant_",
    "call_rule": "L4_call_",
}
# Above this many instances a reads or invariant property gets a warning: each instance is a ledger unit.
INSTANCE_WARN = 50
# How the warnings about a threat-model item start, per property kind (`<prefix> <item>: ...`):
# generate_report.py selects the generator's warnings by these prefixes.
WARNING_PREFIX = {
    "auth_state": "auth gate",
    "auth_required": "auth gate",
    "sanitized": "output sink",
    "wiped": "secret",
    "no_leak": "secret",
    "asset_writers": "asset",
    "asset_readers": "asset",
    "invariant": "invariant",
    "call_rule": "call rule",
}

# libc calls that write through a pointer argument: a caller writes through a pointer too.
MEMORY_WRITERS = frozenset(
    {
        "memcpy",
        "memmove",
        "memset",
        "bzero",
        "explicit_bzero",
        "strcpy",
        "strncpy",
        "strcat",
        "strncat",
        "stpcpy",
        "stpncpy",
        "sprintf",
        "snprintf",
        "vsprintf",
        "vsnprintf",
        "fread",
        "fgets",
        "read",
        "pread",
        "recv",
        "recvfrom",
        "getline",
        # The typed syscall rewrites of the libc track (fc_cpp_wrapper.py): read and recvfrom.
        "__fc_syscall_read",
        "__fc_syscall_recvfrom",
    }
)
TEXT_SINKS = frozenset({"log", "terminal"})
_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
_STATE_RE = re.compile(r"^(?P<root>[A-Za-z_]\w*)(?P<path>(?:(?:\.|->)[A-Za-z_]\w*)*)$")


# ---------------------------------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------------------------------


def template_dir() -> Path | None:
    here = Path(__file__).resolve().parent
    for cand in (here.parent / "templates" / "metacsl", Path("/opt/framac-pipeline/templates/metacsl")):
        if cand.is_dir():
            return cand
    return None


def load_template(name: str, directory: Path | None = None) -> dict[str, str]:
    """The `//# <variant>` sections of templates/metacsl/<name>.acsl (the header comment is skipped)."""
    base = directory or template_dir()
    if base is None:
        raise FileNotFoundError("templates/metacsl not found")
    text = (base / f"{name}.acsl").read_text(encoding="utf-8")
    sections: dict[str, str] = {}
    current: str | None = None
    lines: list[str] = []
    for line in text.splitlines():
        if line.startswith("//# "):
            if current is not None:
                sections[current] = "\n".join(lines).strip()
            current, lines = line[4:].strip(), []
        elif current is not None:
            lines.append(line)
    if current is not None:
        sections[current] = "\n".join(lines).strip()
    return sections


class _Templates:
    def __init__(self, directory: Path | None = None) -> None:
        self.directory = directory
        self.cache: dict[str, dict[str, str]] = {}

    def render(self, template: str, variant: str, /, **values: str) -> str:
        if template not in self.cache:
            self.cache[template] = load_template(template, self.directory)
        return string.Template(self.cache[template][variant]).substitute(values)


# ---------------------------------------------------------------------------------------------------
# Model lookups
# ---------------------------------------------------------------------------------------------------


class _Model:
    def __init__(self, model: dict):
        self.functions: dict[str, dict] = model.get("functions") or {}
        test_units = {n for n, u in (model.get("units") or {}).items() if u.get("test")}
        self.live = {
            fid
            for fid, f in self.functions.items()
            if not f.get("units") or any(u not in test_units for u in f.get("units") or [])
        }
        self.by_name: dict[str, list[str]] = defaultdict(list)
        for fid, f in sorted(self.functions.items()):
            self.by_name[str(f.get("name") or fid.split("#")[-1])].append(fid)
        self.callers: dict[str, set[str]] = defaultdict(set)
        self.callees: dict[str, set[str]] = defaultdict(set)
        # Functions with a caller that reaches them through a pointer (an indirect call site's type
        # match, or their address handed to an external as a callback).
        self.pointer_called: set[str] = set()
        for e in model.get("edges") or []:
            a, b = e.get("caller"), e.get("callee")
            if a in self.functions and b in self.functions and a != b:
                self.callers[b].add(a)
                self.callees[a].add(b)
                if e.get("kind") == "indirect":
                    self.pointer_called.add(b)
        # The indirect call sites of each function: one site dispatches to one of its `candidates`.
        self.sites: dict[str, list[dict]] = defaultdict(list)
        for s in model.get("indirect_sites") or []:
            if isinstance(s, dict) and s.get("caller") in self.functions:
                self.sites[str(s["caller"])].append(s)
        self.ext_callers: dict[str, set[str]] = defaultdict(set)
        for fid, f in self.functions.items():
            for name in f.get("external_calls") or []:
                self.ext_callers[name].add(fid)
        self.external_formals: dict[str, list] = model.get("external_formals") or {}
        self.external_decls: dict[str, dict] = model.get("external_decls") or {}
        self.globals_by_name: dict[str, list[dict]] = defaultdict(list)
        for g in (model.get("global_variables") or {}).values():
            self.globals_by_name[str(g.get("name"))].append(g)
        self.features = model_features(model)
        self.has_writes = self.features["writes"]
        # Package E: a call site says whether it is the initializer of a local (`initializer`, dump
        # schema 5). A model whose call sites never carry the key cannot tell.
        sites = [s for f in self.functions.values() for s in (f.get("call_sites") or []) if isinstance(s, dict)]
        self.has_call_sites = bool(sites)
        self.has_init_flags = any("initializer" in s for s in sites)

    def init_sites(self, fid: str, callee: str | None = None) -> list[dict]:
        """The calls of `fid` placed in an initializer (`int n = f(x);`), of `callee` or of anything."""
        sites = self.functions[fid].get("call_sites")
        return [
            s
            for s in (sites if isinstance(sites, list) else [])
            if isinstance(s, dict) and s.get("initializer") is True and callee in (None, s.get("callee"))
        ]

    def external(self, name: str) -> bool:
        """`name` is called by the build and defined by none of its units (declared only)."""
        return name in self.ext_callers and not self.by_name.get(name)

    def call_sites(self, fid: str, callee: str) -> list[dict] | None:
        """The calls of `callee` in `fid` with their literal arguments; None when the model recorded none."""
        sites = self.functions[fid].get("call_sites")
        if not isinstance(sites, list):
            return None
        return [s for s in sites if isinstance(s, dict) and s.get("callee") == callee]

    def resolve(self, ref: str) -> list[str]:
        if "#" in ref:
            return [ref] if ref in self.functions else []
        return list(self.by_name.get(ref, []))

    def name(self, fid: str) -> str:
        return str(self.functions[fid].get("name") or fid.split("#")[-1])

    def formals(self, ref: str) -> list[dict] | None:
        """A function's formals: its definition's, else an external prototype's (None: unknown)."""
        fids = self.resolve(ref)
        for fid in fids:
            f = self.functions[fid].get("formals")
            if isinstance(f, list):
                return f
        name = ref.split("#")[-1]
        f = self.external_formals.get(name)
        return f if isinstance(f, list) else None

    def _signature(self, ref: str) -> str:
        for fid in self.resolve(ref):
            if self.functions[fid].get("signature"):
                return str(self.functions[fid]["signature"])
        return str((self.external_decls.get(ref.split("#")[-1]) or {}).get("signature") or "")

    def arg_refs(self, ref: str) -> dict[str, str] | None:
        """
        Parameter name -> the text that stands for the call's argument in an in-code check written at
        a call of `ref`: `${argN}`, and for a pointer parameter `((T)${argN})` with the parameter's
        type. ACSL has no implicit conversion from a C array to a pointer, so an array argument
        (`char buf[8]; ... f(buf)`) written as it is would not type and would stop the function's WP
        run; the cast is the conversion the call itself makes. A `void *` parameter is cast to
        `char *` (its bytes). None when the parameters are unknown, or the type of a pointer one is.
        """
        formals = self.formals(ref)
        if formals is None:
            return None
        sig = self._signature(ref)
        types: list[str] = []
        if sig.endswith(")") and "(" in sig:
            depth, start = 0, sig.index("(") + 1
            for i in range(start, len(sig)):
                c = sig[i]
                if c in "([":
                    depth += 1
                elif c in ")]" and depth:
                    depth -= 1
                elif (c == "," and not depth) or i == len(sig) - 1:
                    types.append(sig[start:i].strip())
                    start = i + 1
        out: dict[str, str] = {}
        for i, p in enumerate(formals):
            ref_text = f"${{arg{i}}}"
            if p.get("kind") in ("pointer", "const_pointer"):
                kind = _RESTRICT_RE.sub("", types[i]).strip() if i < len(types) else ""
                if not kind.endswith("*") and "(" not in kind:
                    return None
                if "(" not in kind and "[" not in kind:
                    if _VOID_POINTER_RE.fullmatch(kind):
                        kind = "char const *" if "const" in kind else "char *"
                    ref_text = f"(({kind}){ref_text})"
            out[str(p.get("name"))] = ref_text
        return out

    def callers_of(self, ref: str) -> set[str]:
        """Project functions calling `ref` (a project function or an external one)."""
        out: set[str] = set()
        for fid in self.resolve(ref):
            out |= self.callers.get(fid, set())
        out |= self.ext_callers.get(ref.split("#")[-1], set())
        return {f for f in out if f in self.live}

    def global_files(self, name: str) -> list[str]:
        return sorted({str(g["file"]) for g in self.globals_by_name.get(name, []) if g.get("file")})

    def pointer_writers(self) -> dict[str, str]:
        """Functions writing through a pointer, with why (step I9's L3 rule)."""
        out: dict[str, str] = {}
        for fid in sorted(self.live):
            f = self.functions[fid]
            w = f.get("writes")
            why: list[str] = []
            if isinstance(w, dict):
                if w.get("params"):
                    why.append(f"writes through parameter(s) {', '.join(w['params'])}")
                elif w.get("pointer"):
                    why.append(f"{w['pointer']} write(s) through a pointer")
            elif f.get("source") == "gcc-callgraph-info" or not self.has_writes:
                sig = str(f.get("signature") or "")
                if "(" in sig and "*" in sig[sig.find("(") :]:
                    why.append("pointer parameter (no write facts in the model)")
            libc = sorted(set(f.get("external_calls") or []) & MEMORY_WRITERS)
            if libc:
                why.append(f"calls {', '.join(libc)}")
            if why:
                out[fid] = "; ".join(why)
        return out

    def direct_writers(self, global_name: str) -> set[str]:
        return {
            fid for fid in self.live if global_name in ((self.functions[fid].get("writes") or {}).get("globals") or [])
        }


# ---------------------------------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------------------------------


def _ident(text: str) -> str:
    return re.sub(r"\W", "_", text)


def _has_crlf(text: str) -> bool:
    """Whether a C string holds CR or LF before its terminating NUL (what no_crlf_string forbids)."""
    head = text.split("\0", 1)[0]
    return "\r" in head or "\n" in head


def _formalize(expr: str, formals: set[str]) -> str:
    """`n * 2` -> `\\formal(n) * 2` for the function's parameter names (MetAcsl's way to name them)."""
    return _IDENT_RE.sub(lambda m: f"\\formal({m.group(0)})" if m.group(0) in formals else m.group(0), expr)


# What a threat-model predicate may hold (schemas/threat_model.schema.json, `predicate`): it is written
# into a generated annotation like secrets[].size. `;` would close the meta-property and open another
# clause; \result is refused by MetAcsl in a \postcond and becomes a silent \true under \tguard;
# proof:deduce and proof:axiom (in \flags) assume a property instead of checking it (package R).
_PREDICATE_RE = re.compile(r"^[A-Za-z0-9_ ()\[\]*+/.<>=!&|%^~?:,\\-]+$")
_PREDICATE_BANNED = ("/*", "*/", "//", ";", "\\result", "\\flags", "proof:", "\\tguard", "\\inter", "\\in_file")
# Names a predicate may use that are neither globals nor parameters.
_ACSL_WORDS = frozenset(
    "integer real boolean sizeof int char long short unsigned signed float double void struct union enum const "
    "NULL true false".split()
)


_RESTRICT_RE = re.compile(r"\b(?:__restrict__|__restrict|restrict)\b")
_VOID_POINTER_RE = re.compile(r"(?:const\s+)?void(?:\s+const)?\s*\*")


def predicate_problem(text: object) -> str | None:
    """Why a threat-model predicate cannot go into an annotation, or None."""
    if not isinstance(text, str) or not text.strip():
        return "empty"
    if len(text) > 400:
        return "longer than 400 characters"
    for banned in _PREDICATE_BANNED:
        if banned in text:
            return f"holds `{banned}`"
    if not _PREDICATE_RE.match(text):
        return "holds a character a predicate cannot (letters, digits, spaces and ()[]*+/.<>=!&|%^~?:,\\- only)"
    return None


def _balanced(text: str, start: int) -> str:
    """The text between the parenthesis at text[start] and its match (to the end when it never closes)."""
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1 : i]
    return text[start + 1 :]


def meta_text_problems(acsl: str) -> list[str]:
    """
    What no generated property may hold, whatever a template or a threat model says (constraints of
    package R, docs/plans/metacsl-exploitation-plan.md): \\inter or \\in_file in \\targets (the set is
    computed here and listed), the proof:deduce and proof:axiom flags, \\result under \\tguard.
    """
    out: list[str] = []
    for flag in ("proof:deduce", "proof:axiom"):
        if re.search(re.escape(flag).replace(":", r"\s*:\s*"), acsl):
            out.append(f"the flag {flag} (it assumes the property instead of checking it)")
    for m in re.finditer(r"\\targets\s*\(", acsl):
        inner = _balanced(acsl, m.end() - 1)
        for op in ("\\inter", "\\in_file"):
            if op in inner:
                out.append(f"{op} in \\targets (MetAcsl 0.12 mishandles it: list the functions)")
    for m in re.finditer(r"\\tguard\s*\(", acsl):
        if "\\result" in _balanced(acsl, m.end() - 1):
            out.append("\\result under \\tguard (it does not type there, so the property is a silent \\true)")
    return out


def _names_in(expr: str) -> list[tuple[int, int, str]]:
    """(start, end, name) of the C identifiers of an expression: no ACSL builtin (`\\valid`), no field name."""
    out = []
    for m in _IDENT_RE.finditer(expr):
        before = expr[: m.start()]
        if before.endswith("\\") or before.rstrip().endswith((".", "->")) or (before[-1:].isdigit()):
            continue
        out.append((m.start(), m.end(), m.group(0)))
    return out


def _rename(expr: str, mapping: dict[str, str]) -> str:
    """`expr` with each identifier of `mapping` replaced (not a field name, not an ACSL builtin)."""
    out, last = [], 0
    for start, end, name in _names_in(expr):
        if name in mapping:
            out += [expr[last:start], mapping[name]]
            last = end
    return "".join(out) + expr[last:]


# ---------------------------------------------------------------------------------------------------
# What a declared callee assigns (the \writing context takes a call's writes from the callee's assigns)
# ---------------------------------------------------------------------------------------------------

_SHARE: list[str | None] = []


def _share_path() -> str | None:
    """Frama-C's share directory (FRAMAC_SHARE, else `frama-c -print-share-path`), where its libc is."""
    if not _SHARE:
        import os  # noqa: PLC0415
        import shutil  # noqa: PLC0415
        import subprocess  # noqa: PLC0415

        found = os.environ.get("FRAMAC_SHARE") or None
        if not found and shutil.which("frama-c"):
            try:
                res = subprocess.run(
                    ["frama-c", "-print-share-path"], capture_output=True, text=True, timeout=30, check=False
                )
                found = res.stdout.strip() or None
            except (OSError, subprocess.SubprocessError):
                found = None
        _SHARE.append(found)
    return _SHARE[0]


def contract_assigns(text: str, line: int, name: str) -> dict:
    """
    The `assigns` of the ACSL contract written before the declaration of `name` at `line` of `text`:
    {status, terms}. status `listed` (terms: what it assigns, without \\result and \\nothing), `set`
    (a term is \\union(...), \\inter(...) or {a, b}: MetAcsl 0.12 stops on it, meta_annotate.ml line
    675), or `none` (no contract there, or one without `assigns`). Read from the text, not from
    Frama-C: the Phase 0 parse runs with -no-annot, so the model holds no contract.
    """
    lines = text.splitlines(keepends=True)
    start = sum(len(x) for x in lines[: max(0, line - 1)])
    m = re.compile(rf"\b{re.escape(name)}\s*\(").search(text, start)
    head = text[: m.start()] if m and text.count("\n", start, m.start()) <= 3 else text[:start]
    found = re.search(r"/\*@((?:(?!\*/).)*)\*/[\s\w*]*$", head, re.DOTALL)
    if not found:
        return {"status": "none", "terms": []}
    clauses = re.findall(r"\bassigns\b([^;]*);", found.group(1))
    if not clauses:
        return {"status": "none", "terms": []}
    terms: list[str] = []
    is_set = False
    for clause in clauses:
        lhs = clause.split("\\from")[0].strip()
        if "\\union" in lhs or "\\inter" in lhs or "{" in lhs:
            is_set = True
        depth, cur = 0, ""
        for ch in lhs + ",":
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            if ch == "," and depth == 0:
                if cur.strip() and cur.strip() not in ("\\nothing", "\\result"):
                    terms.append(" ".join(cur.split()))
                cur = ""
            else:
                cur += ch
    return {"status": "set" if is_set else "listed", "terms": terms}


class _Contracts:
    """What each declared (external) function assigns, read at its first declaration (`external_decls`)."""

    def __init__(self, model: dict, roots: Iterable[Path] | None):
        self.decls: dict[str, dict] = model.get("external_decls") or {}
        self.tree = str(model.get("tree") or "").rstrip("/")
        self.roots = [Path(r) for r in roots or []]
        self.files: dict[str, str | None] = {}
        self.cache: dict[str, dict] = {}

    def _read(self, file: str) -> str | None:
        if file not in self.files:
            cands: list[Path] = []
            if file.startswith("FRAMAC_SHARE/"):
                share = _share_path()
                cands = [Path(share) / file[len("FRAMAC_SHARE/") :]] if share else []
            else:
                rel = file[len(self.tree) + 1 :] if self.tree and file.startswith(self.tree + "/") else file
                if not rel.startswith("/"):
                    cands = [root / rel for root in self.roots]
                cands.append(Path(file))
            text = None
            for cand in cands:
                try:
                    if cand.is_file():
                        text = cand.read_text(encoding="utf-8", errors="replace")
                        break
                except OSError:
                    continue
            self.files[file] = text
        return self.files[file]

    def of(self, name: str) -> dict:
        """{status: listed | set | none | unknown, terms, decl} for the declared function `name`."""
        if name not in self.cache:
            decl = str((self.decls.get(name) or {}).get("decl") or "")
            file, _, line = decl.rpartition(":")
            text = self._read(file) if file and line.isdigit() else None
            res = contract_assigns(text, int(line), name) if text is not None else {"status": "unknown", "terms": []}
            self.cache[name] = {**res, "decl": decl}
        return self.cache[name]


class _Gen:
    def __init__(self, model: dict, block: dict | None, templates: _Templates, roots: Iterable[Path] | None = None):
        self.contracts = _Contracts(model, roots)
        self.m = _Model(model)
        self.block = block or {}
        self.t = templates
        self.properties: list[dict] = []
        self.warnings: list[str] = []
        self.names: set[str] = set()
        if model.get("functions"):
            # The facts this generator reads (phase0_model.MODEL_FEATURES says what each one's absence loses).
            for feature in ("external_calls", "formals", "writes"):
                if not self.m.features[feature]:
                    self.warnings.append(f"the model has {MODEL_FEATURES[feature]}")
            if block and self.m.has_call_sites and not self.m.has_init_flags:
                self.warnings.append(
                    "the model's call sites do not say which calls are initializers (`initializer`, dump schema 5): "
                    "MetAcsl generates no \\calling, \\writing or \\strong_invariant instance at `int n = f(x);`, "
                    "no in-code check is written there, and a unit whose only call of a sink is an initializer "
                    "can be credited with nothing checked"
                )

    # -- helpers ------------------------------------------------------------------------------------

    def _unique(self, name: str) -> str:
        base, n = name, 2
        while name in self.names:
            name, n = f"{base}_{n}", n + 1
        self.names.add(name)
        return name

    def _one(self, ref: str, what: str) -> str | None:
        """The C name of a threat-model function reference, warning when it is ambiguous or absent."""
        fids = self.m.resolve(ref)
        name = ref.split("#")[-1]
        if not fids and name not in self.m.ext_callers:
            self.warnings.append(f"{what}: {ref} is neither a function of the build nor called by one")
            return None
        if len({self.m.name(f) for f in fids}) > 1 or len(fids) > 1:
            self.warnings.append(f"{what}: {ref} names {len(fids)} functions; MetAcsl targets them all by name")
        return name

    def _add(self, kind: str, name: str, acsl: str, instances: set[str], **extra: Any) -> dict:
        layer, cls = KINDS[kind]
        problems = meta_text_problems(acsl)
        if problems:
            self.warnings.append(
                f"{WARNING_PREFIX.get(kind, kind)} property {name}: not generated, its text holds {'; '.join(problems)}"
            )
            return {}
        decided = {f: d for f, d in (extra.pop("decided", None) or {}).items() if f in self.m.live}
        # An in-code check that does not type stops the whole WP run of its function. The meta file
        # is parsed with the files that define the globals a property names (`sources`); a check
        # written into another file is not, so it is placed only where its globals are defined.
        kept: list[dict] = []
        hidden: list[dict] = []
        for c in extra.get("init_checks") or []:
            file = str(c["function"]).rpartition("#")[0]
            body = re.sub(r"\$\{arg\d+\}", " ", str(c["check"]).split(":", 1)[-1])
            foreign = sorted(
                {n for _, _, n in _names_in(body) if (files := self.m.global_files(n)) and file not in files}
            )
            if foreign:
                where = {k: c[k] for k in ("function", "callee", "line") if k in c}
                hidden.append(
                    {
                        **where,
                        "reason": f"an initializer call of {c.get('callee')}: its check names {', '.join(foreign)}, "
                        f"which {file} does not define (the check might not type there)",
                    }
                )
            else:
                kept.append(c)
        if hidden:
            extra["init_checks"] = kept
            extra["unchecked"] = [*(extra.get("unchecked") or []), *hidden]
            notes = [n for n in extra.get("notes") or [] if "placed in an initializer" not in n]
            extra["notes"] = notes + self._init_note(kept)
        for key in ("init_checks", "unchecked", "declared_callees"):
            if key in extra and not extra[key]:
                del extra[key]
        prop = {
            "name": name,
            "layer": layer,
            "kind": kind,
            "obligation_class": cls,
            "acsl": acsl,
            "instances": sorted(f for f in instances if f in self.m.live and f not in decided),
            "sources": sorted(set(extra.pop("sources", []))),
            "notes": list(extra.pop("notes", [])),
        }
        if decided:
            prop["decided"] = [{"function": f, **decided[f]} for f in sorted(decided)]
        prop.update(extra)
        self.properties.append(prop)
        return prop

    def _state(self, state: str, formals_of: list[str]) -> tuple[str, str, list[str]] | None:
        """(variant, ACSL lvalue, defining files) of an auth state, or None when it cannot be named."""
        m = _STATE_RE.match(state)
        if not m:
            return None
        root, path = m.group("root"), m.group("path")
        files = self.m.global_files(root)
        if files:
            return "global", state, files
        params = {str(p.get("name")) for ref in formals_of for p in (self.m.formals(ref) or [])}
        if root in params:
            return "formal", f"\\formal({root}){path}", []
        return None

    # -- \writing properties and declared callees ------------------------------------------------------

    def _writing_facts(self, allowed: set[str], scope: set[str] | None, what: str) -> dict:
        """
        What a \\writing property over `scope` (None: every function) but `allowed` meets in the
        declared functions its targets call. MetAcsl takes the writes of such a call from the
        callee's `assigns`:
          excluded  the callers of a callee whose `assigns` holds a set (\\union(...), {a, b}):
                    MetAcsl 0.12 stops on it (meta_annotate.ml line 675), so they leave the targets
                    and are listed as `unchecked`;
          writers   the callers of a callee that assigns something: instances of the property;
          lists     `declared_callees`: set_assigns, no_assigns (nothing is generated for what such
                    a callee writes, with no warning from MetAcsl) and unknown (declaration not read).
        """
        targets = (self.m.live if scope is None else scope & self.m.live) - allowed
        lists: dict[str, dict[str, list[str]]] = {"set_assigns": {}, "no_assigns": {}, "unknown": {}}
        key = {"set": "set_assigns", "none": "no_assigns", "unknown": "unknown"}
        writers: set[str] = set()
        unchecked: list[dict] = []
        for fid in sorted(targets):
            for callee in sorted(set(self.m.functions[fid].get("external_calls") or [])):
                if not self.m.external(callee):
                    continue
                contract = self.contracts.of(callee)
                status = contract["status"]
                if status in key:
                    lists[key[status]].setdefault(callee, []).append(fid)
                if status == "set":
                    unchecked.append(
                        {
                            "function": fid,
                            "callee": callee,
                            "reason": f"calls {callee}, whose `assigns` holds a set (\\union(...) or braces): MetAcsl "
                            "stops on it, so the function is left out of the property's targets",
                        }
                    )
                elif status == "listed" and contract["terms"]:
                    writers.add(fid)
        declared = {
            k: [
                {"callee": c, "callers": callers, **({"decl": d} if (d := self.contracts.of(c)["decl"]) else {})}
                | ({"assigns": self.contracts.of(c)["terms"]} if k == "set_assigns" else {})
                for c, callers in sorted(v.items())
            ]
            for k, v in lists.items()
            if v
        }

        def some(names: Iterable[str]) -> str:
            names = sorted(names)
            return ", ".join(names[:8]) + (f" and {len(names) - 8} more" if len(names) > 8 else "")

        if lists["set_assigns"]:
            self.warnings.append(
                f"{what}: {some(lists['set_assigns'])} assign(s) a set (`assigns \\union(...)` or `{{a, b}}`), which "
                f"stops MetAcsl: the caller(s) {some({self.m.name(u['function']) for u in unchecked})} are left "
                "out of the property and not checked. Write one `assigns` term per location in that contract"
            )
        if lists["no_assigns"]:
            self.warnings.append(
                f"{what}: the declared function(s) {some(lists['no_assigns'])} have no `assigns` at their "
                "declaration: MetAcsl generates nothing for what they write, so the property says nothing about it"
            )
        return {
            "excluded": {u["function"] for u in unchecked},
            "writers": writers,
            "unchecked": unchecked,
            "declared_callees": declared,
        }

    def _but(self, allowed: Iterable[str], excluded: Iterable[str]) -> str:
        """`a, b`: the C names a \\diff(\\ALL, {...}) leaves out (the allowed functions, then the excluded ids)."""
        names = list(dict.fromkeys([*allowed, *sorted({self.m.name(f) for f in excluded})]))
        return ", ".join(names)

    def _targets(self, scope_names: list[str] | None, but: str) -> str:
        """The \\targets text: the scope listed by name (never \\inter or \\in_file), else every function."""
        left = {n.strip() for n in but.split(",") if n.strip()}
        if scope_names is None:
            return f"\\diff(\\ALL, {{{but}}})" if left else "\\ALL"
        return "{" + ", ".join(n for n in scope_names if n not in left) + "}"

    def _separated(self, variant: str, fid: str, names: list[str], path: str, state: str):
        """
        The in-code form of `\\separated(\\written, &state)` for function `fid`: region -> predicate,
        or None when the property is \\true there (a state reached from a parameter `fid` lacks).
        """
        if variant == "global":
            lvalues = [state]
        else:
            own = {str(p.get("name")) for p in self.m.functions[fid].get("formals") or []}
            lvalues = [f"{n}{path}" for n in names if n in own]
        if not lvalues:
            return None
        return lambda region: " && ".join(
            self.t.render("l3_asset", "init_write", region=region, lvalue=lv) for lv in lvalues
        )

    def _init_write_checks(
        self, name: str, pool: set[str], variant: str, names: list[str], path: str, state: str, transition: bool = False
    ) -> tuple[list[dict], list[dict]]:
        """
        Package E, \\writing: MetAcsl gives a call placed in an initializer no instance from the
        callee's `assigns`. For each such call of a declared function in `pool`, an in-code check that
        what the callee assigns, with the call's arguments in place of its parameters, is separated
        from the state. Returns (init_checks, unchecked): a site whose check cannot be written (the
        callee's contract or parameters unknown, a transition property) is `unchecked`.
        """
        checks: list[dict] = []
        unchecked: list[dict] = []
        for fid in sorted(pool):
            clause = self._separated(variant, fid, names, path, state)
            if clause is None:
                continue
            for site in self.m.init_sites(fid):
                callee = str(site.get("callee") or "")
                if not self.m.external(callee):
                    continue  # a function of the build: its own writes are checked in its own proof
                where = {"function": fid, "callee": callee, "line": int(site.get("line") or 0)}
                contract = self.contracts.of(callee)
                if contract["status"] in ("none", "set") or (contract["status"] == "listed" and not contract["terms"]):
                    continue  # nothing MetAcsl would check at a statement call either (see declared_callees)
                mapping = self.m.arg_refs(callee)
                if contract["status"] == "unknown" or mapping is None:
                    unchecked.append(
                        {
                            **where,
                            "reason": f"an initializer call of {callee}, whose `assigns` or parameter types are unknown",
                        }
                    )
                    continue
                if transition:
                    unchecked.append(
                        {**where, "reason": f"an initializer call of {callee}: a transition needs the state before it"}
                    )
                    continue
                regions = []
                for term in contract["terms"]:
                    text = _rename(term, mapping)
                    regions.append(text[1:].strip() if text.startswith("*") else f"&({text})")
                predicate = " && ".join(clause(r) for r in regions)
                check = self.t.render("l4_call_rule", "init_call", name=name, predicate=predicate)
                checks.append({**where, "at": "before", "check": check})
        return checks, unchecked

    def _init_call_checks(
        self, name: str, pool: Iterable[str], callee: str, predicate: str | None, why: str = ""
    ) -> tuple[list[dict], list[dict]]:
        """
        Package E, \\calling: MetAcsl gives a call placed in an initializer no instance. For each such
        call of `callee` in `pool`, the property's predicate as an in-code check before the
        declaration (`predicate`: `${argN}` for the call's N-th argument); with no predicate the site
        is `unchecked`, for the reason `why`.
        """
        checks: list[dict] = []
        unchecked: list[dict] = []
        for fid in sorted(pool):
            for site in self.m.init_sites(fid, callee):
                where = {"function": fid, "callee": callee, "line": int(site.get("line") or 0)}
                if predicate is None:
                    unchecked.append({**where, "reason": f"an initializer call of {callee}: {why}"})
                else:
                    check = self.t.render("l4_call_rule", "init_call", name=name, predicate=predicate)
                    checks.append({**where, "at": "before", "check": check})
        return checks, unchecked

    def _init_note(self, checks: list[dict]) -> list[str]:
        if not checks:
            return []
        return [
            f"{len(checks)} call(s) placed in an initializer, where MetAcsl generates no instance: a `check` named "
            "after the property is written into the work tree there (`init_checks`)"
        ]

    # -- L3 -----------------------------------------------------------------------------------------

    def frame(self) -> dict[str, str]:
        return self.m.pointer_writers()

    def _lvalue(self, lvalue: str, params: Iterable[str], what: str) -> dict | None:
        """
        {variant, root, path, names, acsl, files} of an asset or state lvalue: a global (`config`,
        `session.mode`), or a field reached from a parameter (`c->mode`), with one ACSL lvalue per
        parameter name the object is passed as. None (with a warning) when it names neither.
        """
        m = _STATE_RE.match(lvalue)
        if not m:
            self.warnings.append(f"{what}: `{lvalue}` is not an lvalue a property can name")
            return None
        root, path = m.group("root"), m.group("path")
        files = self.m.global_files(root)
        if files:
            return {"variant": "global", "root": root, "path": path, "names": [], "acsl": [lvalue], "files": files}
        known = {str(p.get("name")) for fid in self.m.live for p in self.m.functions[fid].get("formals") or []}
        names = [n for n in dict.fromkeys([root, *params]) if n in known]
        # A misspelt parameter name would make its clause \true in every function, silently.
        for n in dict.fromkeys([root, *params]):
            if n not in known:
                self.warnings.append(
                    f"{what}: {n} is neither a global of the build nor a parameter of one of its functions"
                    + ("" if n == root else ": that name is left out")
                )
        if root not in known or not path:
            if root in known:
                self.warnings.append(
                    f"{what}: `{lvalue}` is a parameter itself: name what it reaches (`{root}->field`)"
                )
            return None
        return {
            "variant": "formal",
            "root": root,
            "path": path,
            "names": names,
            "acsl": [f"\\formal({n}){path}" for n in names],
            "files": [],
        }

    def assets(self) -> None:
        """
        Threat model `assets` (package D1): L3_writers_<name>, only the declared writers write the
        lvalue (\\writing over every other function), and with `readers`, L3_readers_<name>, only
        they read it (\\reading). Class l3_isolation.
        """
        pointer_writers = set(self.m.pointer_writers())
        for item in self.block.get("assets") or []:
            asset = str(item.get("name") or "")
            what = f"asset {asset}"
            lv = self._lvalue(str(item.get("lvalue") or ""), [str(p) for p in item.get("params") or []], what)
            if lv is None:
                continue
            variant, root = lv["variant"], lv["root"]
            note = (
                []
                if variant == "global"
                else [
                    f"{item['lvalue']} hangs off a parameter: checked only in functions with a parameter named "
                    f"{' or '.join(lv['names'])}; a function that takes the object under another name is not checked"
                ]
            )
            meta = {"asset": asset, "lvalue": item.get("lvalue")}
            writers = [w for w in (self._one(str(r), f"{what} writers") for r in item.get("writers") or []) if w]
            writer_fids = {f for w in writers for f in self.m.resolve(w)}
            name = self._unique(f"{NAME_PREFIX['asset_writers']}{_ident(asset)}")
            facts = self._writing_facts(writer_fids, None, f"{what} ({name})")
            instances = (pointer_writers | self.m.direct_writers(root) | facts["writers"]) - writer_fids
            instances -= facts["excluded"]
            predicate = " &&\n      ".join(
                self.t.render("l3_asset", f"writers_{variant}", lvalue=a) for a in lv["acsl"]
            )
            targets = self._targets(None, self._but(writers, facts["excluded"]))
            checks, unchecked = self._init_write_checks(
                name, instances, variant, lv["names"], lv["path"], str(item["lvalue"])
            )
            self._add(
                "asset_writers",
                name,
                self.t.render("l3_asset", "writers", name=name, targets=targets, predicate=predicate),
                instances,
                sources=lv["files"],
                notes=note + self._init_note(checks),
                threat_model={**meta, "writers": writers},
                targets=f"every function but {', '.join(writers)}" if writers else "every function",
                variant=variant,
                direct_writers=sorted(self.m.direct_writers(root) - writer_fids),
                init_checks=checks,
                unchecked=facts["unchecked"] + unchecked,
                declared_callees=facts["declared_callees"],
            )
            if item.get("readers") is None:
                continue
            readers = [r for r in (self._one(str(r), f"{what} readers") for r in item.get("readers") or []) if r]
            reader_fids = {f for r in readers for f in self.m.resolve(r)}
            name = self._unique(f"{NAME_PREFIX['asset_readers']}{_ident(asset)}")
            # Any function may read it through a pointer: every function but the readers is an instance
            # (for a parameter-held asset, those with a parameter of one of the names).
            pool = set(self.m.live)
            if variant == "formal":
                pool = {
                    f
                    for f in pool
                    if {str(p.get("name")) for p in self.m.functions[f].get("formals") or []} & set(lv["names"])
                }
            instances = pool - reader_fids
            if len(instances) > INSTANCE_WARN:
                self.warnings.append(
                    f"{what} ({name}): {len(instances)} functions carry a unit of this property (every function but the "
                    "readers may read the asset through a pointer)"
                )
            predicate = " &&\n      ".join(
                self.t.render("l3_asset", f"readers_{variant}", lvalue=a) for a in lv["acsl"]
            )
            self._add(
                "asset_readers",
                name,
                self.t.render(
                    "l3_asset",
                    "readers",
                    name=name,
                    targets=self._targets(None, self._but(readers, [])),
                    predicate=predicate,
                ),
                instances,
                sources=lv["files"],
                notes=list(note),
                threat_model={**meta, "readers": readers},
                targets=f"every function but {', '.join(readers)}" if readers else "every function",
                variant=variant,
            )

    # -- L4 -----------------------------------------------------------------------------------------

    def auth_gates(self) -> None:
        writers = self.m.pointer_writers()
        for item in self.block.get("auth_gates") or []:
            gate = self._one(str(item.get("function") or ""), "auth gate")
            protects = [p for p in (self._one(str(r), "auth gate protects") for r in item.get("protects") or []) if p]
            if gate is None:
                continue
            state = item.get("state")
            if not state:
                self.warnings.append(
                    f"auth gate {gate}: no `state` (the variable the gate sets): L4 properties not generated"
                )
                continue
            resolved = self._state(str(state), [gate, *protects])
            if resolved is None:
                self.warnings.append(
                    f"auth gate {gate}: state {state} is neither a global of the build nor reached from a parameter of the gate or the functions it protects"
                )
                continue
            variant, lv, files = resolved
            root = str(state).split("-")[0].split(".")[0]
            if item.get("success") is not None:
                self._gate_on_failure(item, gate, variant, lv, root)
            note = (
                []
                if variant == "global"
                else [f"{state} hangs off a parameter: checked only in functions with a parameter named {root}"]
            )
            gate_fids = set(self.m.resolve(gate))
            name = self._unique(f"{NAME_PREFIX['auth_state']}{_ident(gate)}")
            # What declared callees assign counts as a write of their caller (MetAcsl reads their `assigns`).
            facts = self._writing_facts(gate_fids, None, f"auth gate {gate} ({name})")
            writes = (set(writers) | self.m.direct_writers(root) | facts["writers"]) - gate_fids - facts["excluded"]
            acsl = self.t.render(
                "l4_auth_state", variant, name=name, gate=self._but([gate], facts["excluded"]), state=lv
            )
            path = str(state)[len(root) :]
            checks, unchecked = self._init_write_checks(name, writes, variant, [root], path, str(state))
            self._add(
                "auth_state",
                name,
                acsl,
                writes,
                sources=files,
                notes=note + self._init_note(checks),
                threat_model={"auth_gate": gate, "state": state},
                targets=f"every function but {gate}",
                direct_writers=sorted(self.m.direct_writers(root) - gate_fids),
                init_checks=checks,
                unchecked=facts["unchecked"] + unchecked,
                declared_callees=facts["declared_callees"],
            )
            if not protects:
                continue
            name = self._unique(f"{NAME_PREFIX['auth_required']}{_ident(gate)}")
            acsl = self.t.render("l4_auth_required", variant, name=name, protects=", ".join(protects), state=lv)
            callers: set[str] = set()
            entry: list[str] = []
            for p in protects:
                c = self.m.callers_of(p)
                callers |= c
                if not c:
                    entry += [f for f in self.m.resolve(p) if f in self.m.live]
            notes = list(note)
            if entry:
                notes.append(
                    f"no project code calls {', '.join(sorted({self.m.name(f) for f in entry}))}: its external callers must pass {gate}"
                )
            self._add(
                "auth_required",
                name,
                acsl,
                callers | set(entry),
                sources=files,
                notes=notes,
                threat_model={"auth_gate": gate, "state": state, "protects": protects},
                targets=", ".join(protects),
                entry_points=sorted(entry),
            )

    def _gate_on_failure(self, item: dict, gate: str, variant: str, lv: str, root: str) -> None:
        """
        Plan step M7: when the gate's result is not its `success` value, the auth state is unchanged.
        MetAcsl's \\postcond cannot name \\result, so this is a `check` apply_code writes before each
        `return` of the gate, with the returned expression in place of the result.
        """
        fids = [f for f in self.m.resolve(gate) if f in self.m.live]
        if not fids:
            self.warnings.append(f"auth gate {gate}: not defined in the build: its `success` is not checked")
            return
        if variant == "formal" and root not in {str(p.get("name")) for p in self.m.formals(gate) or []}:
            self.warnings.append(
                f"auth gate {gate}: state {item.get('state')} is not reached from a parameter of the gate: "
                "its `success` is not checked"
            )
            return
        name = self._unique(f"{NAME_PREFIX['auth_state']}{_ident(gate)}_on_failure")
        state = lv.replace("\\formal(", "(")
        check = self.t.render(
            "l4_auth_state", "on_failure", name=name, result="${result}", success=str(item["success"]), state=state
        )
        self._add(
            "auth_state",
            name,
            check,
            set(fids),
            notes=[
                "written into the work tree before each return of the gate, the returned expression in place of "
                "the result; a return whose expression the check cannot repeat (a call, an assignment) is skipped"
            ],
            threat_model={"auth_gate": gate, "state": item.get("state"), "success": item["success"]},
            targets=gate,
            code={"returns": True, "check": check},
        )

    def _unknown_names(self, predicate: str, params: set[str]) -> list[str]:
        """Identifiers of a predicate that are neither globals of the build, `params`, nor ACSL words."""
        seen = dict.fromkeys(n for _, _, n in _names_in(predicate))
        return [n for n in seen if n not in params and n not in _ACSL_WORDS and not self.m.global_files(n)]

    def invariants(self) -> None:
        """
        Threat model `invariants` (package D1): L4_invariant_<name>, class l4_invariant. Variants
        weak, strong and conditional state a predicate over globals on the functions in scope;
        monotonic states that an lvalue only moves one way, at every write.
        """
        pointer_writers = set(self.m.pointer_writers())
        for item in self.block.get("invariants") or []:
            inv = str(item.get("name") or "")
            variant = str(item.get("variant") or "")
            what = f"invariant {inv}"
            scope_names: list[str] | None = None
            scope: set[str] | None = None
            if item.get("scope"):
                scope_names = [s for s in (self._one(str(r), f"{what} scope") for r in item["scope"]) if s]
                scope = {f for s in scope_names for f in self.m.resolve(s) if f in self.m.live}
                if not scope:
                    self.warnings.append(f"{what}: no function of its scope is defined in the build: not generated")
                    continue
            name = self._unique(f"{NAME_PREFIX['invariant']}{_ident(inv)}")
            meta = {"invariant": inv, "variant": variant, **({"scope": scope_names} if scope_names else {})}
            if variant == "monotonic":
                if item.get("predicate") is not None or not item.get("lvalue"):
                    self.warnings.append(f"{what}: a monotonic invariant takes an `lvalue` and no `predicate`")
                    continue
                lv = self._lvalue(str(item["lvalue"]), [], what)
                if lv is None:
                    continue
                order = ">=" if item.get("direction") == "down" else "<="
                facts = self._writing_facts(set(), scope, f"{what} ({name})")
                instances = pointer_writers | self.m.direct_writers(lv["root"]) | facts["writers"]
                instances = (instances & (scope if scope is not None else self.m.live)) - facts["excluded"]
                template = "monotonic" if lv["variant"] == "global" else "monotonic_formal"
                targets = self._targets(scope_names, self._but([], facts["excluded"]))
                # A transition cannot be written as one in-code check: initializer calls are unchecked.
                _, unchecked = self._init_write_checks(
                    name, instances, lv["variant"], lv["names"], lv["path"], str(item["lvalue"]), transition=True
                )
                prop = self._add(
                    "invariant",
                    name,
                    self.t.render(
                        "l4_invariant", template, name=name, targets=targets, lvalue=lv["acsl"][0], order=order
                    ),
                    instances,
                    sources=lv["files"],
                    notes=[
                        f"{item['lvalue']} only moves {'down' if order == '>=' else 'up'}, at every write; "
                        "\\at(x, Before) is not evaluated by Eva: `engines` leaves it out"
                    ],
                    threat_model={**meta, "lvalue": item["lvalue"], "direction": item.get("direction") or "up"},
                    targets=", ".join(scope_names) if scope_names else "every function",
                    variant=template,
                    engines=[e for e in META_ENGINES if e != "eva"],
                    unchecked=facts["unchecked"] + unchecked,
                    declared_callees=facts["declared_callees"],
                )
            else:
                problem = (
                    predicate_problem(item.get("predicate"))
                    if variant in ("weak", "strong", "conditional")
                    else f"unknown variant `{variant}`"
                )
                if problem is None and item.get("lvalue"):
                    problem = "`lvalue` goes with the monotonic variant"
                if problem is None and variant == "conditional" and scope is None:
                    problem = "a conditional invariant needs a `scope` (the entry points that keep it)"
                if problem:
                    self.warnings.append(f"{what}: {problem}: not generated")
                    continue
                predicate = str(item["predicate"])
                unknown = self._unknown_names(predicate, set())
                if unknown:
                    self.warnings.append(
                        f"{what}: the predicate names {', '.join(unknown)}, which no unit of the build defines as a "
                        "global: the property does not type where they are not in scope"
                    )
                targets = self._targets(scope_names, "")
                inside = set(scope) if scope is not None else set(self.m.live)
                notes: list[str] = []
                instances = set(inside)
                files = sorted({f for _, _, n in _names_in(predicate) for f in self.m.global_files(n)})
                checks: list[dict] = []
                if variant != "conditional":
                    # The generated `requires` is proved at each call: the callers carry it too.
                    callers = {c for f in inside for c in self.m.callers.get(f, ())} & self.m.live
                    instances |= callers
                    entry = sorted(self.m.name(f) for f in inside if not self.m.callers.get(f))
                    if entry:
                        notes.append(
                            f"no project code calls {', '.join(entry[:8])}{' ...' if len(entry) > 8 else ''}: "
                            "their external callers must establish the invariant"
                        )
                if variant == "strong":
                    # Package E: after an initializer call MetAcsl's default simplification drops the
                    # assertion, whatever the callee writes.
                    for fid in sorted(inside):
                        for site in self.m.init_sites(fid):
                            checks.append(
                                {
                                    "function": fid,
                                    "callee": str(site.get("callee") or ""),
                                    "line": int(site.get("line") or 0),
                                    "at": "after",
                                    "check": self.t.render(
                                        "l4_invariant", "init_strong", name=name, predicate=predicate
                                    ),
                                }
                            )
                prop = self._add(
                    "invariant",
                    name,
                    self.t.render("l4_invariant", variant, name=name, targets=targets, predicate=predicate),
                    instances,
                    sources=files,
                    notes=notes + self._init_note(checks),
                    threat_model={**meta, "predicate": predicate},
                    targets=", ".join(scope_names) if scope_names else "every function",
                    variant=variant,
                    init_checks=checks,
                )
            count = len(prop.get("instances") or [])
            if count > INSTANCE_WARN:
                self.warnings.append(
                    f"{what} ({name}): {count} functions carry a unit of this invariant"
                    + (" (no `scope`: every function of the build)" if scope is None else "")
                    + f": give a `scope` to bound it (warning above {INSTANCE_WARN})"
                )

    def call_rules(self) -> None:
        """
        Threat model `call_rules` (package D1): L4_call_<callee>, class l4_call_rule: a predicate
        that holds at every call of the callee. A parameter of the callee named in the predicate is
        the argument of the call (\\called_arg). A callee the target defines and calls through a
        function pointer gets the rule as its precondition instead, as a Layer 5 sink does.
        """
        for item in self.block.get("call_rules") or []:
            ref = str(item.get("function") or "")
            callee = self._one(ref, f"call rule {ref.split('#')[-1]}")
            if callee is None:
                continue
            what = f"call rule {callee}"
            problem = predicate_problem(item.get("predicate"))
            if problem:
                self.warnings.append(f"{what}: the predicate {problem}: not generated")
                continue
            predicate = str(item["predicate"])
            formals = self.m.formals(ref)
            params = [str(p.get("name")) for p in formals or []]
            used = [p for p in params if p in {n for _, _, n in _names_in(predicate)}]
            unknown = self._unknown_names(predicate, set(params))
            if unknown:
                self.warnings.append(
                    f"{what}: the predicate names {', '.join(unknown)}, which is neither a parameter of {callee} "
                    "nor a global of the build"
                    + ("" if formals is not None else " (the model has no parameters for it)")
                    + ": the property is \\false (unproven) where the name does not type"
                )
            entry = any(f in self.m.pointer_called for f in self.m.resolve(ref) if f in self.m.live)
            name = self._unique(f"{NAME_PREFIX['call_rule']}{_ident(callee)}")
            instances = self.m.callers_of(ref)
            notes = []
            if not instances:
                notes.append(f"no project code calls {callee}: nothing to discharge in the target")
            checks: list[dict] = []
            unchecked: list[dict] = []
            if entry:
                acsl = self.t.render(
                    "l4_call_rule",
                    "entry",
                    name=name,
                    callee=callee,
                    predicate=_rename(predicate, {p: f"\\formal({p})" for p in params}),
                )
                notes.append(
                    f"{callee} is called through a function pointer: the rule is its precondition, proved at each "
                    f"call; a call through a pointer needs a `calls` annotation naming {callee}"
                )
            else:
                acsl = self.t.render(
                    "l4_call_rule",
                    "calling",
                    name=name,
                    targets="\\ALL",
                    callee=callee,
                    predicate=_rename(predicate, {p: f"\\called_arg({p})" for p in params}),
                )
                refs = self.m.arg_refs(ref)
                code = _rename(predicate, refs) if refs is not None else None
                checks, unchecked = self._init_call_checks(
                    name, instances, callee, code, "the callee's parameters or their types are unknown"
                )
            self._add(
                "call_rule",
                name,
                acsl,
                instances,
                sources=sorted({f for _, _, n in _names_in(predicate) for f in self.m.global_files(n)}),
                notes=notes + self._init_note(checks),
                threat_model={"call_rule": callee, "predicate": predicate},
                targets=callee,
                variant="entry" if entry else "formal" if used else "global",
                init_checks=checks,
                unchecked=unchecked,
            )

    # -- L5 -----------------------------------------------------------------------------------------

    def _sink_params(self, item: dict, sink: str, kinds: tuple[str, ...]) -> tuple[list[str], list[dict] | None]:
        formals = self.m.formals(sink)
        if item.get("params"):
            return [str(p) for p in item["params"]], formals
        if formals is None:
            return [], None
        return [str(p["name"]) for p in formals if p.get("kind") in kinds], formals

    def _bytes_sinks(self) -> dict[str, set[str]]:
        """
        The sinks of the threat model that get an initialization property (every kind but `log`,
        `terminal` and `buffer`, with a pointer parameter to state it on): C name -> the live
        functions defining it (none: a sink the target only declares). No warning here: output_sinks
        gives them, item by item.
        """
        out: dict[str, set[str]] = {}
        for item in self.block.get("output_sinks") or []:
            ref = str(item.get("function") or "")
            name = ref.split("#")[-1]
            kind = str(item.get("kind") or "other")
            if not name or kind in TEXT_SINKS or kind == "buffer":
                continue
            fids = self.m.resolve(ref)
            if not fids and name not in self.m.ext_callers:
                continue
            if not self._sink_params(item, name, ("pointer", "const_pointer"))[0]:
                continue
            out.setdefault(name, set()).update(f for f in fids if f in self.m.live)
        return out

    def _sinks_from(self, start: Iterable[str], sinks: dict[str, set[str]], own: str) -> tuple[set[str], set[str]]:
        """
        The bytes sinks other than `own` that the functions `start` reach in the model's call graph
        (direct and indirect edges), and the functions walked. The walk stops at a declared sink, so
        these are the nearest ones on each path.
        """
        by_fid = {f: n for n, fids in sinks.items() if n != own for f in fids}
        external = {n for n, fids in sinks.items() if n != own and not fids}
        found: set[str] = set()
        walked: set[str] = set()
        todo = list(start)
        while todo:
            fid = todo.pop()
            if fid in walked or fid not in self.m.live:
                continue
            if fid in by_fid:
                found.add(by_fid[fid])
                continue
            walked.add(fid)
            found |= external & set(self.m.functions[fid].get("external_calls") or [])
            todo += sorted(self.m.callees.get(fid, ()))
        return found, walked

    def _shape(self, fid: str) -> tuple[str, ...] | None:
        """The kinds of a function's parameters (value, pointer, const_pointer), or None when unknown."""
        formals = self.m.functions[fid].get("formals")
        return tuple(str(p.get("kind")) for p in formals) if isinstance(formals, list) else None

    def _forwarding(self, sinks: dict[str, set[str]]) -> tuple[dict[str, list[str]], dict[str, str]]:
        """
        The forwarding sinks (plan A of docs/plans/metacsl-exploitation-plan.md): a bytes sink the
        target defines that reaches other declared bytes sinks. What it is handed may be completed on
        the way (libmodbus's send_msg has the backend fill the MBAP length before the backend's send),
        so its bytes are checked where they leave, at the innermost declared sinks, and not at its own
        calls. Returns (sink -> the innermost sinks its obligation moves to, sink -> why a sink that
        reaches declared sinks keeps its own property).

        A sink keeps its property when one indirect call site on the way has a candidate that reaches
        a declared sink and another, callable through the same pointer type, that reaches none (a
        backend table with one declared `send` and one undeclared): forwarding would then stop
        checking what the undeclared one transmits. Two sinks that only reach each other keep one
        property between them.
        """
        nearest: dict[str, set[str]] = {}
        kept: dict[str, str] = {}
        for name in sorted(sinks):
            if not sinks[name]:
                continue  # declared only: nothing of it is in the call graph
            found, walked = self._sinks_from(sinks[name], sinks, name)
            if not found:
                continue
            reach: dict[str, set[str]] = {}
            partial: list[str] = []
            undeclared: set[str] = set()
            for fid in sorted(walked):
                for site in self.m.sites.get(fid, []):
                    cands = sorted(c for c in site.get("candidates") or [] if c in self.m.live)
                    for c in cands:
                        if c not in reach:
                            reach[c] = self._sinks_from([c], sinks, name)[0]
                    # The model's type match ignores `const`, so a site typed like the backend's send
                    # (`const unsigned char *`) also lists its recv (`unsigned char *`). One pointer
                    # type cannot call both without a cast: a candidate that reaches no sink counts
                    # only when its parameters have the kinds of one that does (or are unknown).
                    shapes = {self._shape(c) for c in cands if reach[c]}
                    dead = [
                        c
                        for c in cands
                        if not reach[c] and (self._shape(c) is None or None in shapes or self._shape(c) in shapes)
                    ]
                    if not dead or not shapes:
                        continue
                    declared = sorted({s for c in cands for s in reach[c]})
                    undeclared |= {self.m.name(c) for c in dead}
                    partial.append(
                        f"the call through `{site.get('expr') or '?'}` in {self.m.name(fid)}"
                        f" ({site.get('loc') or 'no location'}) reaches the declared sink(s) {', '.join(declared)}"
                        f" and also {', '.join(sorted(self.m.name(c) for c in dead))}, which reach(es) none"
                    )
            if partial:
                kept[name] = (
                    f"output sink {name}: it forwards to {', '.join(sorted(found))}, but {'; '.join(partial)}. "
                    f"Its property stays at its own calls (which is before the buffer is complete when a callee "
                    f"of {name} completes it). Declare {', '.join(sorted(undeclared))} (or what they transmit "
                    "through) as output sinks to have the bytes checked where they leave"
                )
                continue
            nearest[name] = found

        def innermost(name: str, seen: frozenset[str]) -> set[str]:
            out: set[str] = set()
            for s in nearest[name]:
                if s not in nearest:
                    out.add(s)
                elif s not in seen:
                    out |= innermost(s, seen | {s})
            return out

        while True:
            cyclic = next((n for n in sorted(nearest) if not innermost(n, frozenset({n}))), None)
            if cyclic is None:
                break
            del nearest[cyclic]
        return {n: sorted(innermost(n, frozenset({n}))) for n in nearest}, kept

    def output_sinks(self) -> None:
        forwards, kept = self._forwarding(self._bytes_sinks())
        for item in self.block.get("output_sinks") or []:
            sink = self._one(str(item.get("function") or ""), "output sink")
            if sink is None:
                continue
            if item.get("format"):
                self._format_literal(item, sink)
            kind = str(item.get("kind") or "other")
            buffer = kind == "buffer"
            params, formals = self._sink_params(item, sink, ("pointer",) if buffer else ("pointer", "const_pointer"))
            if formals is not None:
                known = {str(p.get("name")) for p in formals}
                for p in params:
                    if p not in known:
                        self.warnings.append(f"output sink {sink}: {p} is not one of its parameters")
            if not params:
                self.warnings.append(
                    f"output sink {sink}: no pointer parameter to state a property on (give `params`): L5 not generated"
                )
                continue
            length = item.get("length")
            bytes_sink = not buffer and kind not in TEXT_SINKS
            meta = {"output_sink": sink, "kind": kind, "params": params}
            if bytes_sink and sink in forwards:
                # A forwarding sink: no goal at its calls, the innermost declared sinks check the bytes.
                name = self._unique(f"{NAME_PREFIX['sanitized']}{_ident(sink)}")
                to = forwards[sink]
                self._add(
                    "sanitized",
                    name,
                    f"/* {name}: {sink} forwards its buffer to the declared sink(s) {', '.join(to)}; the bytes are "
                    "checked there, where they leave. No MetAcsl goal. */",
                    set(),
                    notes=[
                        f"{sink} forwards to the declared sink(s) {', '.join(to)}: the bytes are checked at their "
                        f"calls, after anything {sink} or its callees complete, and the callers of {sink} have no "
                        "goal"
                    ],
                    threat_model=meta,
                    targets=sink,
                    forwarded_to=to,
                )
                continue
            if bytes_sink and sink in kept:
                self.warnings.append(kept[sink])
            # A sink the target defines and calls through a pointer: a precondition of the sink, which
            # WP proves at each call. A \calling instance cannot name the arguments of such a call.
            entry = not buffer and any(f in self.m.pointer_called for f in self.m.resolve(sink) if f in self.m.live)
            suffix = "_formal" if entry else ""
            clauses = []
            for p in params:
                if buffer:
                    clauses.append(self.t.render("l5_sanitized", "out_object", param=p))
                elif kind in TEXT_SINKS:
                    clauses.append(self.t.render("l5_sanitized", "text" + suffix, param=p))
                elif length:
                    clauses.append(self.t.render("l5_sanitized", "bytes" + suffix, param=p, length=str(length)))
                else:
                    clauses.append(self.t.render("l5_sanitized", "object" + suffix, param=p))
            name = self._unique(f"{NAME_PREFIX['sanitized']}{_ident(sink)}")
            predicate = " &&\n      ".join(clauses)
            variant = "buffer" if buffer else "entry" if entry else "emit"
            acsl = self.t.render("l5_sanitized", variant, name=name, sink=sink, predicate=predicate)
            notes = []
            if entry:
                notes.append(
                    f"{sink} is called through a function pointer: the property is its precondition, proved at "
                    f"each call; a call through a pointer needs a `calls` annotation naming {sink}"
                )
            if bytes_sink and not length:
                notes.append("no `length`: only the first object each parameter points to is checked")
            if buffer:
                instances = {f for f in self.m.resolve(sink) if f in self.m.live}
                if not instances:
                    self.warnings.append(
                        f"output sink {sink}: a buffer sink must be defined in the target: L5 not generated"
                    )
                    continue
            else:
                instances = self.m.callers_of(sink)
                if not instances:
                    notes.append(f"no project code calls {sink}: nothing to discharge in the target")
            decided: dict[str, dict] = {}
            if kind in TEXT_SINKS and not buffer:
                decided = self._decide_text_literals(sink, params, formals, instances, notes)
            checks: list[dict] = []
            unchecked: list[dict] = []
            if variant == "emit":
                # Package E: the \calling instance MetAcsl does not generate at an initializer call.
                index = {str(p.get("name")): i for i, p in enumerate(formals or [])}
                wanted = [*params, *([str(length)] if bytes_sink and length else [])]
                code = None
                why = "the sink's parameters or their types are unknown"
                args = self.m.arg_refs(sink)
                if kind in TEXT_SINKS:
                    # `no_crlf_string` is declared in the meta file's preamble; whether the caller's
                    # file declares it is not known here, and a check that does not type stops its
                    # function's WP run.
                    why = "a text sink: `no_crlf_string` is not known to be declared in the caller's file"
                elif args is not None and all(p in index for p in wanted):
                    code = " && ".join(
                        f"\\initialized({args[p]} + (0 .. {args[str(length)]} - 1))"
                        if length
                        else f"\\initialized({args[p]})"
                        for p in params
                    )
                checks, unchecked = self._init_call_checks(name, instances - set(decided), sink, code, why)
            self._add(
                "sanitized",
                name,
                acsl,
                instances,
                decided=decided,
                notes=notes + self._init_note(checks),
                threat_model=meta,
                targets=sink,
                init_checks=checks,
                unchecked=unchecked,
            )

    def _format_literal(self, item: dict, sink: str) -> None:
        """
        Plan step M5 (CWE-134): the `format` argument of the sink is a string literal at every call.
        Decided from the model (call_sites) like the literals of M2, with no MetAcsl goal: a caller
        whose every call passes a literal there is satisfied, one with any other format is violated.
        A caller that is itself a format sink of the threat model forwards its own format: its callers
        are checked instead.
        """
        fmt = str(item["format"])
        formals = self.m.formals(sink)
        index = {str(p.get("name")): i for i, p in enumerate(formals or [])}
        if fmt not in index:
            unnamed = bool(index) and all(re.fullmatch(r"param\d+", n) for n in index)
            self.warnings.append(
                f"output sink {sink}: format {fmt} is not one of its parameters"
                + ("" if formals else " (the model has no parameters for it)")
                + (f" (its prototype names none: write its 0-based position, {', '.join(index)})" if unnamed else "")
                + ": L5 format property not generated"
            )
            return
        callers = self.m.callers_of(str(item["function"]))
        if callers and not self.m.features["call_sites"]:
            self.warnings.append(
                f"output sink {sink}: the model has {MODEL_FEATURES['call_sites']}: format not decided"
            )
            return
        forwarders = {
            f
            for s in self.block.get("output_sinks") or []
            if s.get("format") and s.get("function")
            for f in self.m.resolve(str(s["function"]))
        }
        decided: dict[str, dict] = {}
        notes: list[str] = []
        for fid in sorted(callers):
            if fid in forwarders:
                notes.append(f"{self.m.name(fid)} is a format sink itself: its callers are checked")
                continue
            sites = self.m.call_sites(fid, sink) or []
            if not sites:
                notes.append(f"{self.m.name(fid)}: no call of {sink} recorded (an indirect call?): not decided")
                continue
            other = [
                int(s.get("line") or 0)
                for s in sites
                if not isinstance((s.get("literals") or {}).get(str(index[fmt])), str)
            ]
            lines = ", ".join(str(int(s.get("line") or 0)) for s in sites)
            if other:
                decided[fid] = {
                    "verdict": "violated",
                    "how": "syntactic",
                    "reason": f"{sink} is passed a format `{fmt}` that is not a string literal (line {other[0]}; CWE-134)",
                }
            else:
                decided[fid] = {
                    "verdict": "satisfied",
                    "how": "syntactic",
                    "reason": f"every call of {sink} passes a string-literal format `{fmt}` (line(s) {lines})",
                }
        if not callers:
            notes.append(f"no project code calls {sink}: nothing to decide in the target")
        name = self._unique(f"{NAME_PREFIX['sanitized']}format_{_ident(sink)}")
        # No MetAcsl text: the property is decided from the model and never reaches a meta file.
        acsl = (
            f"/* {name}: at every call of {sink}, the format argument `{fmt}` is a string literal (CWE-134). "
            "Decided from the model's call sites; no MetAcsl goal. */"
        )
        self._add(
            "sanitized",
            name,
            acsl,
            set(),
            decided=decided,
            notes=notes,
            threat_model={"output_sink": sink, "format": fmt},
            targets=sink,
        )

    def _literal_sites(self, fid: str, sink: str, indexes: list[int]) -> tuple[list[tuple[int, list[str]]], int] | None:
        """
        The calls of `sink` in `fid` whose arguments at `indexes` are all string literals, as (line,
        texts), and how many calls pass something else there. None when the model recorded no call
        sites (dump before schema 4) or none of this sink.
        """
        sites = self.m.call_sites(fid, sink)
        if not sites:
            return None
        literal: list[tuple[int, list[str]]] = []
        other = 0
        for site in sites:
            lits = site.get("literals") or {}
            texts = [lits.get(str(i)) for i in indexes]
            if all(isinstance(t, str) for t in texts):
                literal.append((int(site.get("line") or 0), [str(t) for t in texts]))
            else:
                other += 1
        return literal, other

    def _decide_text_literals(
        self, sink: str, params: list[str], formals: list[dict] | None, instances: set[str], notes: list[str]
    ) -> dict[str, dict]:
        """
        Plan step M2: no_crlf_string on a string literal does not prove (an unbounded quantifier over the
        literal's bytes), but the model knows the literal. A caller whose every call of the sink passes
        literals to the text parameters is decided here, syntactically: satisfied when no literal holds
        CR or LF before its first NUL, else violated. It gets no MetAcsl goal (the ledger records the
        verdict); a caller that also passes something else keeps its goal.
        """
        if not instances:
            return {}
        if not self.m.features["call_sites"]:
            self.warnings.append(f"output sink {sink}: the model has {MODEL_FEATURES['call_sites']}")
            return {}
        index = {str(p.get("name")): i for i, p in enumerate(formals or [])}
        if not formals or any(p not in index for p in params):
            return {}
        indexes = [index[p] for p in params]
        out: dict[str, dict] = {}
        mixed: list[str] = []
        for fid in sorted(instances):
            found = self._literal_sites(fid, sink, indexes)
            if found is None or not found[0]:
                continue
            literal, other = found
            if other:
                mixed.append(self.m.name(fid))
                continue
            bad = [(line, t) for line, texts in literal for t in texts if _has_crlf(t)]
            if bad:
                line, text = bad[0]
                out[fid] = {
                    "verdict": "violated",
                    "how": "syntactic",
                    "reason": f"{sink} is passed the string literal {json.dumps(text)}, which holds a CR or LF (line {line})",
                }
            else:
                lines = ", ".join(str(line) for line, _ in literal)
                out[fid] = {
                    "verdict": "satisfied",
                    "how": "syntactic",
                    "reason": f"every call of {sink} passes string literals without CR or LF (line(s) {lines})",
                }
        if mixed:
            notes.append(
                f"{', '.join(mixed)}: call(s) {sink} with string literals and with other text; the literal calls keep "
                "a goal that does not prove (no_crlf_string on a literal)"
            )
        return out

    # -- L6 -----------------------------------------------------------------------------------------

    def _secret_region(self, item: dict) -> dict | None:
        """{lv, region, scope, formals, files, shape} for a secret, or None (with a warning)."""
        name, kind = str(item.get("name")), str(item.get("kind"))
        fn = item.get("function")
        fn_name = str(fn).split("#")[-1] if fn else None
        size = item.get("size")
        obj = item.get("object")
        if kind == "global":
            files = self.m.global_files(name)
            if not files:
                self.warnings.append(f"secret {name}: no global of that name is defined in the build")
                return None
            shape = self._global_shape(name)
            return {
                "lv": name,
                "region": f"&{name}",
                "scope": "global",
                "formals": set(),
                "files": files,
                "shape": shape,
            }
        if not fn_name:
            self.warnings.append(f"secret {name} ({kind}): give the `function` that holds it")
            return None
        formals = {str(p.get("name")) for p in (self.m.formals(str(fn)) or [])}
        if kind == "parameter":
            if formals and name not in formals:
                self.warnings.append(f"secret {name}: not a parameter of {fn_name}")
                return None
            lv = f"\\formal({name})"
            region = f"{lv} + (0 .. {_formalize(str(size), formals)} - 1)" if size else lv
            return {
                "lv": lv,
                "region": region,
                "scope": "function",
                "formals": formals,
                "files": [],
                "shape": "pointer",
            }
        if kind == "field":
            if not obj:
                self.warnings.append(f"secret {name} (field): give the `object` (parameter or global) holding it")
                return None
            if obj in formals:
                ptr = next((p.get("kind") for p in self.m.formals(str(fn)) or [] if p.get("name") == obj), "pointer")
                lv = f"\\formal({obj}){'->' if ptr != 'value' else '.'}{name}"
                return {
                    "lv": lv,
                    "region": f"&{lv}",
                    "scope": "function",
                    "formals": formals,
                    "files": [],
                    "shape": "field",
                }
            files = self.m.global_files(str(obj))
            if files:
                lv = f"{obj}.{name}"
                return {
                    "lv": lv,
                    "region": f"&{lv}",
                    "scope": "global",
                    "formals": formals,
                    "files": files,
                    "shape": "field",
                }
            self.warnings.append(f"secret {name}: object {obj} is neither a parameter of {fn_name} nor a global")
            return None
        if kind == "local":
            if name in formals:
                self.warnings.append(f"secret {name}: a parameter of {fn_name}, not a local (kind `parameter`)")
                return None
            return {"lv": name, "region": "", "scope": "local", "formals": formals, "files": [], "shape": "local"}
        self.warnings.append(
            f"secret {name}: kind `{kind}` (a returned secret) has no lvalue a property can name, so no property is "
            "generated; declare where the caller keeps it (a global, a field, or a local of the caller)"
        )
        return None

    def _global_shape(self, name: str) -> str:
        for g in self.m.globals_by_name.get(name, []):
            t = str(g.get("type") or "")
            if t.endswith("]"):
                return "array"
            if t.endswith("*"):
                return "pointer"
            if t.startswith(("struct ", "union ")):
                return "struct"
            if t:
                return "scalar"
        return "unknown"

    def secrets(self) -> None:
        sinks = [s for s in (self.block.get("output_sinks") or []) if s.get("function")]
        for item in self.block.get("secrets") or []:
            sec = self._secret_region(item)
            if sec is None:
                continue
            name = str(item["name"])
            fn = item.get("function")
            fn_name = str(fn).split("#")[-1] if fn else None
            size = item.get("size")
            if sec["scope"] == "local":
                self._local_wipe(item, sec)
                if sinks:
                    self.warnings.append(
                        f"secret {name}: a local: no no-leak property (MetAcsl cannot name a local, and the taint "
                        "annotations follow globals and parameters only)"
                    )
                continue
            # Wiped before release.
            if fn_name and self._one(str(fn), f"secret {name}") is not None:
                shape = sec["shape"]
                if size or shape in ("array", "pointer", "field", "unknown"):
                    if size:
                        count = _formalize(str(size), sec["formals"])
                    elif shape == "pointer":
                        count = "1"
                        self.warnings.append(f"secret {name}: no `size`: only its first element is checked")
                    else:
                        count = f"sizeof({sec['lv']}) / sizeof({sec['lv']}[0])"
                    pred = self.t.render("l6_wiped", "array", count=count, lv=sec["lv"])
                elif shape == "scalar":
                    pred = self.t.render("l6_wiped", "scalar", lv=sec["lv"])
                else:
                    self.warnings.append(
                        f"secret {name}: a whole {shape}: name its fields (kind `field`) or give `size`"
                    )
                    pred = ""
                if pred:
                    pname = self._unique(f"{NAME_PREFIX['wiped']}{_ident(name)}")
                    acsl = self.t.render("l6_wiped", "property", name=pname, function=fn_name, predicate=pred)
                    self._add(
                        "wiped",
                        pname,
                        acsl,
                        set(self.m.resolve(str(fn))),
                        sources=sec["files"],
                        threat_model={"secret": name, "kind": item.get("kind"), "release": fn_name},
                        targets=fn_name,
                    )
            elif not fn_name:
                self.warnings.append(f"secret {name}: no release `function`: the wipe property is not generated")
            # Never flows to an output sink.
            if not sinks:
                continue
            clauses, defined, instances = [], [], set()
            # Package E: per sink, the same clause over the arguments of a call (`${argN}`), for the
            # in-code check at an initializer call; None when the sink's parameters are unknown.
            region_code = re.sub(r"\\formal\((\w+)\)", r"\1", sec["region"])
            init_code: dict[str, str | None] = {}
            for s in sinks:
                sname = str(s["function"]).split("#")[-1]
                params, sink_formals = self._sink_params(s, sname, ("pointer", "const_pointer"))
                refs = self.m.arg_refs(sname)
                if params:
                    init_code[sname] = (
                        " && ".join(f"\\separated({refs[p]}, {region_code})" for p in params)
                        if refs is not None and all(p in refs for p in params)
                        else None
                    )
                for p in params:
                    clauses.append(
                        self.t.render("l6_no_leak", "call_clause", sink=sname, param=p, region=sec["region"])
                    )
                instances |= self.m.callers_of(str(s["function"]))
                defined += [f for f in self.m.resolve(str(s["function"])) if f in self.m.live]
            if not clauses:
                continue
            pname = self._unique(f"{NAME_PREFIX['no_leak']}{_ident(name)}")
            if sec["scope"] == "global":
                targets = "\\ALL"
            else:
                targets = "{" + str(fn_name) + "}"
                instances &= set(self.m.resolve(str(fn)))
            acsl = self.t.render(
                "l6_no_leak", "calling", name=pname, targets=targets, predicate=" &&\n      ".join(clauses)
            )
            notes = ["direct flows only: a copy of the secret that reaches a sink is not seen (see `taint`)"]
            if sec["scope"] != "global":
                notes.append(f"a parameter secret is checked in {fn_name} only")
            taint = self._taint_plan(item, sec, sinks, set(instances))
            checks: list[dict] = []
            unchecked: list[dict] = []
            for sname, code in sorted(init_code.items()):
                found = self._init_call_checks(pname, instances, sname, code, "the sink's parameters are unknown")
                checks += found[0]
                unchecked += found[1]
            notes += self._init_note(checks)
            if defined and sec["scope"] == "global":
                rname = self._unique(f"{NAME_PREFIX['no_leak']}read_{_ident(name)}")
                sink_names = sorted({self.m.name(f) for f in defined})
                acsl += "\n" + self.t.render(
                    "l6_no_leak", "reading", name=rname, sinks=", ".join(sink_names), region=sec["region"]
                )
                instances |= set(defined)
            self._add(
                "no_leak",
                pname,
                acsl,
                instances,
                sources=sec["files"],
                notes=notes,
                threat_model={"secret": name, "kind": item.get("kind"), "sinks": [str(s["function"]) for s in sinks]},
                targets=targets,
                taint=taint,
                init_checks=checks,
                unchecked=unchecked,
            )

    def _local_wipe(self, item: dict, sec: dict) -> None:
        """
        Plan step M6: a secret held in a local array. A postcondition cannot name a local, so the
        property is a named `check` that apply_code writes into the work tree before each `return` in
        the local's scope and before the closing brace of its block; WP proves it with the function.
        """
        name = str(item["name"])
        if self._one(str(item["function"]), f"secret {name}") is None:
            return
        fids = [f for f in self.m.resolve(str(item["function"])) if f in self.m.live]
        size = item.get("size")
        count = f"({size})" if size else f"sizeof({name}) / sizeof({name}[0])"
        pred = self.t.render("l6_wiped", "local_array", count=count, lv=name)
        pname = self._unique(f"{NAME_PREFIX['wiped']}{_ident(name)}")
        check = self.t.render("l6_wiped", "local", name=pname, predicate=pred)
        notes = ["a local array: the check is written into the work tree, not the meta file"]
        if not size:
            notes.append("no `size`: sizeof of the local (an array; a pointer local needs `size`)")
        self._add(
            "wiped",
            pname,
            check,
            set(fids),
            notes=notes,
            threat_model={"secret": name, "kind": "local", "release": str(item["function"]).split("#")[-1]},
            targets=str(item["function"]).split("#")[-1],
            code={"local": name, "check": check},
        )

    # -- L6, indirect flows (plan step M3) ----------------------------------------------------------

    def _taint_lvalues(self, item: dict, sec: dict) -> str:
        """The secret as a C-scope ACSL tset for `//@ taint` (no \\formal: the annotation is in the code)."""
        name, kind, size = str(item.get("name")), str(item.get("kind")), item.get("size")
        if kind == "parameter":
            return f"{name}[0 .. ({size}) - 1]" if size else f"*{name}"
        if kind == "field":
            return sec["lv"].replace("\\formal(", "(")
        shape = sec["shape"]
        if size:
            return f"{name}[0 .. ({size}) - 1]"
        if shape == "array":
            return f"{name}[0 .. sizeof({name}) / sizeof({name}[0]) - 1]"
        if shape == "pointer":
            return f"*{name}"
        return name

    def _taint_plan(self, item: dict, sec: dict, sinks: list[dict], callers: set[str]) -> dict:
        """
        Where the work tree gets Eva taint annotations for this secret (plan step M3), applied by
        `apply_taint`: `//@ taint <secret>;` at its sources, and `//@ assert <property>: eva_taint:
        !\\tainted(...);` before each call of a sink in the property's calling instances. A secret held
        by a function (a parameter, a field of one) is tainted when that function starts; a global one
        where it may be written: before each return of its direct writers and of the functions that
        call a libc memory writer (tainting the secret more often only marks it more precisely).
        """
        lvalues = self._taint_lvalues(item, sec)
        sources: list[dict] = []
        if sec["scope"] == "function":
            for fid in self.m.resolve(str(item.get("function"))):
                if fid in self.m.live:
                    sources.append({"function": fid, "at": "entry", "lvalues": lvalues})
        else:
            root = str(item.get("object") if str(item.get("kind")) == "field" else item.get("name"))
            writers = self.m.direct_writers(root) | {
                fid for fid in self.m.live if set(self.m.functions[fid].get("external_calls") or []) & MEMORY_WRITERS
            }
            sources += [{"function": fid, "at": "return", "lvalues": lvalues} for fid in sorted(writers)]
        checks: list[dict] = []
        notes: list[str] = []
        for s in sinks:
            sname = str(s["function"]).split("#")[-1]
            params, formals = self._sink_params(s, sname, ("pointer", "const_pointer"))
            index = {str(p.get("name")): i for i, p in enumerate(formals or [])}
            length = s.get("length")
            if not formals or any(p not in index for p in params) or (length and str(length) not in index):
                notes.append(f"{sname}: its parameters are unknown, no taint check at its calls")
                continue
            args = [[index[p], index[str(length)] if length else None] for p in params]
            for fid in sorted(callers & self.m.callers_of(str(s["function"]))):
                checks.append({"function": fid, "sink": sname, "args": args})
        if not sources:
            notes.append("no function the secret's taint can start in: the checks cannot fail")
        return {"sources": sources, "checks": checks, "notes": notes}


def generate(
    model: dict, threat: dict | None, templates: _Templates | None = None, roots: Iterable[Path] | None = None
) -> dict:
    """
    The security properties of a model under a threat model (trust.load_threat_model's result).
    `roots`: where the target's files are (the work tree, the model's tree), to read what the declared
    functions assign at their declarations; without them those contracts are `unknown`.
    """
    threat = threat or {"status": "no_threat_model"}
    block = threat.get("block") if threat.get("status") == "ok" else None
    gen = _Gen(model, block, templates or _Templates(), roots)
    frame = gen.frame()
    if block:
        gen.assets()
        gen.auth_gates()
        gen.invariants()
        gen.call_rules()
        gen.output_sinks()
        gen.secrets()
    elif threat.get("status") == "invalid_threat_model":
        gen.warnings.append("invalid threat model: only L3 is generated")
    obligations: dict[str, list[dict]] = defaultdict(list)
    for fid, why in sorted(frame.items()):
        obligations[fid].append({"class": "l3_frame", "property": "L3_frame", "reason": why})
    for prop in gen.properties:
        reason = f"{prop['name']} ({prop['kind'].replace('_', ' ')}, layer {prop['layer']})"
        for fid in prop["instances"]:
            obligations[fid].append({"class": prop["obligation_class"], "property": prop["name"], "reason": reason})
        # Decided from the model (plan step M2): the ledger seed records the verdict; no WP goal exists.
        for d in prop.get("decided") or []:
            obligations[d["function"]].append(
                {
                    "class": prop["obligation_class"],
                    "property": prop["name"],
                    "reason": reason,
                    "decided": d["verdict"],
                    "decided_reason": d["reason"],
                }
            )
        # A function left out of the property's targets (a callee whose `assigns` stops MetAcsl): the
        # obligation stays, marked, so its unit exists and no run without a goal can credit it.
        for u in prop.get("unchecked") or []:
            if u["function"] not in prop["instances"] and u["function"] in gen.m.live:
                obligations[u["function"]].append(
                    {
                        "class": prop["obligation_class"],
                        "property": prop["name"],
                        "reason": reason,
                        "unchecked": u["reason"],
                    }
                )
    by_class: dict[str, int] = defaultdict(int)
    for items in obligations.values():
        for cls in {i["class"] for i in items}:
            by_class[cls] += 1
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "threat_model": {k: threat.get(k) for k in ("status", "path", "sha256", "reason")},
        "preamble": (templates or _Templates()).render("preamble", "preamble"),
        "properties": gen.properties,
        "frame": [{"function": fid, "reason": why} for fid, why in sorted(frame.items())],
        "obligations": dict(sorted(obligations.items())),
        "summary": {
            "properties": len(gen.properties),
            "by_kind": dict(sorted(_count(p["kind"] for p in gen.properties).items())),
            "functions_by_class": dict(sorted(by_class.items())),
        },
        "warnings": gen.warnings,
    }


def _count(items: Any) -> dict[str, int]:
    out: dict[str, int] = defaultdict(int)
    for x in items:
        out[x] += 1
    return dict(out)


# ---------------------------------------------------------------------------------------------------
# Consumers
# ---------------------------------------------------------------------------------------------------


META_INCLUDE = '#include "__fc_string_axiomatic.h"'
# The include guard of templates/acsl/acsl_vocabulary.h. Every Frama-C run of the pipeline force-includes
# that header through fc_compat_types.h, so the meta file's own unit already declares no_crlf_string,
# and a second declaration in one unit is a fatal annot-error ("already declared with the same
# profile"). The preamble applies only when the vocabulary is absent (a run without fc_stubs).
META_PREAMBLE_GUARD = ("#ifndef ACSL_VOCABULARY_H", "#endif /* ACSL_VOCABULARY_H */")


def properties_for(props: dict, function: str) -> list[dict]:
    """The MetAcsl properties with an instance in `function` (`file#name`, or a bare name)."""
    out = []
    for p in props.get("properties") or []:
        inst = p.get("instances") or []
        if function in inst or ("#" not in function and any(i.split("#")[-1] == function for i in inst)):
            out.append(p)
    return out


def meta_file_text(props: dict, function: str) -> tuple[str, list[str], list[str]] | None:
    """(meta C file, property names, extra sources) for one function's WP run; None without properties."""
    # A property written into the work tree (`code`, plan step M6) is not MetAcsl: the source holds it.
    return _meta_text(props, [p for p in properties_for(props, function) if not p.get("code")])


def module_meta_file_text(
    props: dict, functions: Iterable[str] | None = None
) -> tuple[str, list[str], list[str]] | None:
    """
    (meta C file, property names, extra sources) for a whole-module run (Eva, E-ACSL), where MetAcsl
    instantiates each property in every function of the parse: the properties with an instance among
    `functions` (`file#name` ids), or every property with an instance when `functions` is None. A
    property without instances (decided from the model, or naming no live function) has no MetAcsl
    goal and is left out, like one written into the work tree (`code`). None without properties.
    The text has the same layout as meta_file_text's, so meta_line_names maps its lines to names.
    """
    wanted = None if functions is None else set(functions)
    selected = []
    for p in props.get("properties") or []:
        instances = set(p.get("instances") or [])
        if p.get("code") or not instances or (wanted is not None and not wanted & instances):
            continue
        selected.append(p)
    return _meta_text(props, selected)


# The engines that can check the MetAcsl properties besides WP: Eva on each harness module (Phase 2)
# and E-ACSL in the fuzz build (Phase 1). WP always loads them (run_wp_function.py --security-props).
META_ENGINES = ("eva", "eacsl")


def meta_engines(props: dict | None) -> frozenset[str]:
    """The engines `security_props.json` turns on (`meta_engines`); none for a report without the key."""
    chosen = (props or {}).get("meta_engines")
    return frozenset(e for e in chosen if e in META_ENGINES) if isinstance(chosen, list) else frozenset()


def for_engine(props: dict, engine: str) -> dict:
    """
    `props` with the properties `engine` (`eva`, `eacsl`) may load: a property that lists `engines`
    is kept only when the engine is among them (a monotonic invariant uses \\at(x, Before), which Eva
    does not evaluate). Pass the result to module_meta_file_text; WP loads every property.
    """
    kept = [p for p in props.get("properties") or [] if "engines" not in p or engine in p["engines"]]
    return {**props, "properties": kept}


def _engine_list(text: str) -> list[str]:
    """`eva,eacsl` -> ["eva", "eacsl"]; `none` -> []."""
    names = [t.strip().lower() for t in text.split(",") if t.strip()]
    if names == ["none"]:
        return []
    unknown = [n for n in names if n not in META_ENGINES]
    if unknown or not names:
        raise argparse.ArgumentTypeError(f"expected `none` or a list of {', '.join(META_ENGINES)}: {text!r}")
    return names


def _meta_text(props: dict, selected: list[dict]) -> tuple[str, list[str], list[str]] | None:
    if not selected:
        return None
    # libc's `strlen` for the vocabulary's no_crlf_string the preamble repeats (plan step S8), and the
    # preamble only where the vocabulary was not force-included (META_PREAMBLE_GUARD).
    parts = [META_INCLUDE, META_PREAMBLE_GUARD[0], str(props.get("preamble") or ""), META_PREAMBLE_GUARD[1]]
    parts += [str(p["acsl"]) for p in selected]
    sources = sorted({s for p in selected for s in p.get("sources") or []})
    return "\n".join(parts) + "\n", [str(p["name"]) for p in selected], sources


def match_function(props: dict, c_file: str, fn_name: str) -> tuple[str, str] | None:
    """
    (`file#name`, work root) of the function a WP run proves: the id whose file is the longest suffix
    of the run's source path (`agents/a1/scratch/work/src/x.c` -> `src/x.c#f`, root `agents/a1/scratch/work/`).
    """
    path = c_file.replace("\\", "/")
    ids = set(props.get("obligations") or {})
    ids |= {i for p in props.get("properties") or [] for i in p.get("instances") or []}
    best: tuple[str, str] | None = None
    for fid in sorted(ids):
        file, _, name = fid.rpartition("#")
        if name != fn_name or not (path == file or path.endswith("/" + file)):
            continue
        if best is None or len(file) > len(best[0].rpartition("#")[0]):
            best = (fid, path[: len(path) - len(file)])
    return best


def meta_line_names(text: str) -> dict[int, str]:
    """
    Line -> property name of a meta file. Frama-C's report locates a generated assertion at its
    meta-property's line in the meta file, without the name (postconditions and preconditions keep it).
    """
    out: dict[int, str] = {}
    current: str | None = None
    for i, line in enumerate(text.splitlines(), start=1):
        m = re.search(r"\\name\(([A-Za-z_]\w*)\)", line)
        if m:
            current = m.group(1)
        elif line.lstrip().startswith("/*@") and "meta" not in line:
            current = None
        if current:
            out[i] = current
    return out


# ---------------------------------------------------------------------------------------------------
# Eva taint annotations in the work tree (plan step M3)
# ---------------------------------------------------------------------------------------------------

# The name every generated taint check carries next to its property's: WP leaves it out
# (`-wp-prop=-eva_taint`), and ledger.py ingest-eva files its status under the property's l6 unit.
TAINT_TAG = "eva_taint"
DEFAULT_WORK = Path("workspace/work")
# What apply_taint inserts, and nothing else: re-running it first removes these.
# The checks carry a generated property name: a local's wipe, a gate's failure, and (package E) any
# property with a call placed in an initializer.
_GENERATED_TAINT_RE = re.compile(
    r"/\*@ (?:taint [^\n]*?; |assert L6_no_leak_[A-Za-z0-9_]+: " + TAINT_TAG + r": [^\n]*?; "
    r"|check (?:" + "|".join(sorted(NAME_PREFIX.values())) + r")[A-Za-z0-9_]+: [^\n]*?; )\*/ "
)
# Argument text an assertion may repeat: no call, assignment or increment.
_ARG_UNSAFE_RE = re.compile(r"[A-Za-z_]\w*\s*\(|(?<![=!<>])=(?!=)|\+\+|--")
_STATEMENT_STOP = frozenset({";", "{", "}"})
# Code-check operations (written whatever --eva-taint says): a local's wipe (M6), a gate's failure
# (M7), a property's check at a call placed in an initializer (package E).
CODE_OPS = frozenset({"local", "returns", "init"})


def taint_annotation(lvalues: str) -> str:
    return f"/*@ taint {lvalues}; */ "


def taint_check(prop: str, regions: list[str]) -> str:
    pred = " && ".join(f"!\\tainted({r})" for r in regions)
    return f"/*@ assert {prop}: {TAINT_TAG}: {pred}; */ "


def strip_taint(text: str) -> tuple[str, int]:
    """`text` without the annotations apply_taint generated, and how many there were."""
    return _GENERATED_TAINT_RE.subn("", text)


def _call_args(tokens: list, open_idx: int, close_idx: int, source: str) -> list[str]:
    """The source text of each argument of a call whose parentheses are tokens[open_idx], tokens[close_idx]."""
    out, depth, start = [], 0, tokens[open_idx].end
    for tok in tokens[open_idx + 1 : close_idx]:
        if tok.kind != "c_token":
            continue
        if tok.text in "([{":
            depth += 1
        elif tok.text in ")]}":
            depth -= 1
        elif tok.text == "," and depth == 0:
            out.append(source[start : tok.start].strip())
            start = tok.end
    last = source[start : tokens[close_idx].start].strip()
    if last or out:
        out.append(last)
    return out


def _statement_start(tokens: list, idx: int) -> int | None:
    """
    The token starting the statement that holds the call at tokens[idx], or None when the call is
    inside a condition, an argument list or a conditional expression (no place for an assertion).
    """
    code = [k for k in range(idx) if tokens[k].kind == "c_token"]
    start = idx
    pos = len(code) - 1
    while pos >= 0:
        k = code[pos]
        text = tokens[k].text
        if text in (")", "]"):
            # Skip the group back to its opener: a cast, an index, or the head of a control statement.
            opener_text = "(" if text == ")" else "["
            depth = 0
            while pos >= 0:
                t = tokens[code[pos]].text
                if t == text:
                    depth += 1
                elif t == opener_text:
                    depth -= 1
                    if depth == 0:
                        break
                pos -= 1
            if pos < 0:
                return None
            before = tokens[code[pos - 1]].text if pos > 0 else ""
            if text == ")" and before in ("if", "while", "for", "switch"):
                return start  # `if (c) f(x);`: the call is the body
            start = code[pos]
        elif text in ("(", "["):
            return None  # inside a condition or an argument list
        elif text in _STATEMENT_STOP or text in ("else", "do"):
            return start
        elif text == ":":
            # A label or a case ends the walk; the `:` of a conditional expression does not.
            for back in range(pos - 1, -1, -1):
                t = tokens[code[back]].text
                if t == "?":
                    return None
                if t in _STATEMENT_STOP:
                    break
            return start
        elif text in ("?", ","):
            return None  # a conditional or comma expression, or a declarator list
        else:
            start = k
        pos -= 1
    return start


def _unplaced(op: dict, where: str, name: str, reason: str) -> dict:
    return {
        "property": op["property"],
        "function": f"{where}#{name}",
        "callee": op["callee"],
        "line": op["line"],
        "reason": reason,
    }


def _init_check_inserts(
    source: str,
    tokens: list,
    ops: list[dict],
    skipped: list[str],
    where: str,
    name: str,
    placed: list[dict] | None,
    unplaced: list[dict] | None,
) -> list[tuple[int, str]]:
    """
    Package E: the checks at the calls placed in initializers (`int n = f(x);`). Each op names a
    callee and the line the model gives the call; the call is found in the function's tokens as a
    call of that callee inside a declaration that starts or sits on that line. `at` before: the check
    goes before the declaration, with `${argN}` replaced by the text of the call's N-th argument;
    `at` after: after the `;` that ends it. A site that is not found, shares its declaration with
    another declarator, or has an argument the check cannot repeat (a call, an assignment) goes to
    `skipped` and `unplaced`.
    """
    out: list[tuple[int, str]] = []
    # (callee, line of the declaration or of the call) -> the call's place and arguments.
    found: dict[tuple[str, int], dict] = {}
    callees = {op["callee"] for op in ops}
    for i, tok in enumerate(tokens):
        if tok.kind != "c_token" or tok.text not in callees:
            continue
        nxt = next((k for k in range(i + 1, len(tokens)) if tokens[k].kind == "c_token"), None)
        prev = next((k for k in range(i - 1, -1, -1) if tokens[k].kind == "c_token"), None)
        if nxt is None or tokens[nxt].text != "(" or (prev is not None and tokens[prev].text in (".", "->")):
            continue
        depth, close = 0, None
        for k in range(nxt, len(tokens)):
            if tokens[k].kind == "c_token" and tokens[k].text == "(":
                depth += 1
            elif tokens[k].kind == "c_token" and tokens[k].text == ")":
                depth -= 1
                if depth == 0:
                    close = k
                    break
        if close is None:
            continue
        start = _statement_start(tokens, i)
        end = next((k for k in range(close + 1, len(tokens)) if tokens[k].kind == "c_token"), None)
        site: dict[str, Any] = {"line": tok.line, "problem": None}
        if start is None or end is None or tokens[end].text != ";":
            site["problem"] = "the call is not the whole initializer of one declaration"
        else:
            head = [t.text for t in tokens[start:i] if t.kind == "c_token"]
            # A declaration: `T n = f(...)`, at least a type and a name before the `=`, no lvalue operator.
            lhs = head[: head.index("=")] if "=" in head else []
            if len(lhs) < 2 or not _IDENT_RE.fullmatch(lhs[0]) or {".", "->", "[", "("} & set(lhs):
                continue  # a statement call (`n = f(x);`, `f(x);`): MetAcsl handles it
            site.update(start=tokens[start].start, end=tokens[end].end, args=_call_args(tokens, nxt, close, source))
            site.update(start_line=tokens[start].line, end_line=tokens[end].line)
            found.setdefault((tok.text, tokens[start].line), site)
        found.setdefault((tok.text, tok.line), site)
    # A fixed order on a line (the checks before a declaration, then the ones after it, by property):
    # a report names a check by its file and line only, so `index` tells the checks of one line apart.
    on_line: dict[int, int] = defaultdict(int)
    for op in sorted(ops, key=lambda o: (o["line"], o["at"] != "before", o["property"])):
        hit = found.get((op["callee"], op["line"]))
        problem = "no initializer call found on that line (a macro?)" if hit is None else hit["problem"]
        text = ""
        if hit is not None and problem is None:
            text = op["check"]
            for n in sorted({int(x) for x in re.findall(r"\$\{arg(\d+)\}", text)}):
                if n >= len(hit["args"]) or _ARG_UNSAFE_RE.search(hit["args"][n]):
                    problem = "an argument the check cannot repeat"
                    break
                text = text.replace(f"${{arg{n}}}", f"({hit['args'][n]})")
        if hit is None or problem is not None:
            skipped.append(f"{where}:{op['line']}: {name}, initializer call of {op['callee']}: {problem}")
            if unplaced is not None:
                unplaced.append(_unplaced(op, where, name, f"an initializer call of {op['callee']}: {problem}"))
            continue
        out.append((hit["start"] if op["at"] == "before" else hit["end"], text + " "))
        # Where a report locates the check: the line it is written on, not the line of the call.
        line = int(hit["start_line"] if op["at"] == "before" else hit["end_line"])
        if placed is not None:
            placed.append(
                {
                    "file": where,
                    "line": line,
                    "function": f"{where}#{name}",
                    "property": op["property"],
                    "index": on_line[line],
                }
            )
        on_line[line] += 1
    return out


def _insert_taint_in_function(
    source: str,
    name: str,
    ops: list[dict],
    skipped: list[str],
    where: str,
    placed: list[dict] | None = None,
    unplaced: list[dict] | None = None,
) -> list:
    """
    (offset, text) insertions for one function's sources and checks; problems go to `skipped`, and each
    check placed (file, line, function, property: where Eva reports its status) to `placed`. An
    initializer check that could not be placed also goes to `unplaced`.
    """
    from acsl_ast import _find_body_brace_offset, locate_all_definition_spans, tokenize_c_acsl  # noqa: PLC0415

    init_ops = [op for op in ops if op["kind"] == "init"]
    ops = [op for op in ops if op["kind"] != "init"]
    spans = locate_all_definition_spans(source, where)
    span = spans.get(name)
    brace = _find_body_brace_offset(span.text, where) if span is not None else None
    if span is None or brace is None:
        skipped.append(f"{where}#{name}: no {'definition' if span is None else 'body'} found")
        if unplaced is not None:
            unplaced += [_unplaced(op, where, name, "the function was not found in the work tree") for op in init_ops]
        return []
    body_start = span.start_byte + brace
    tokens = [t for t in tokenize_c_acsl(source, where) if body_start <= t.start < span.end_byte]
    out: list[tuple[int, str]] = []
    if init_ops:
        out += _init_check_inserts(source, tokens, init_ops, skipped, where, name, placed, unplaced)
    for op in ops:
        if op["kind"] == "local":
            out += _local_check_inserts(source, tokens, op, skipped, where, name, placed)
            continue
        if op["kind"] == "returns":
            out += _return_check_inserts(source, tokens, op, skipped, where, name, placed)
            continue
        if op["kind"] == "entry":
            out.append((body_start + 1, taint_annotation(op["lvalues"])))
        elif op["kind"] == "return":
            text = taint_annotation(op["lvalues"])
            out += [(t.start, text) for t in tokens if t.kind == "c_token" and t.text == "return"]
            out.append((span.end_byte - 1, text))
        else:
            for i, tok in enumerate(tokens):
                if tok.kind != "c_token" or tok.text != op["sink"]:
                    continue
                nxt = next((k for k in range(i + 1, len(tokens)) if tokens[k].kind == "c_token"), None)
                prev = next((k for k in range(i - 1, -1, -1) if tokens[k].kind == "c_token"), None)
                if nxt is None or tokens[nxt].text != "(" or (prev is not None and tokens[prev].text in (".", "->")):
                    continue
                close = nxt
                depth = 0
                for k in range(nxt, len(tokens)):
                    if tokens[k].kind == "c_token" and tokens[k].text == "(":
                        depth += 1
                    elif tokens[k].kind == "c_token" and tokens[k].text == ")":
                        depth -= 1
                        if depth == 0:
                            close = k
                            break
                args = _call_args(tokens, nxt, close, source)
                regions: list[str] = []
                for p, length in op["args"]:
                    if p >= len(args) or (length is not None and length >= len(args)):
                        regions = []
                        break
                    ptr = args[p]
                    if _ARG_UNSAFE_RE.search(ptr) or (length is not None and _ARG_UNSAFE_RE.search(args[length])):
                        regions = []
                        break
                    if length is None:
                        regions.append(f"*((unsigned char const *)({ptr}))")
                    else:
                        regions.append(f"((unsigned char const *)({ptr}))[0 .. ({args[length]}) - 1]")
                start = _statement_start(tokens, i)
                if not regions or start is None:
                    skipped.append(
                        f"{where}:{tok.line}: {op['sink']} call: "
                        + ("an argument the assertion cannot repeat" if not regions else "not a statement of its own")
                    )
                    continue
                out.append((tokens[start].start, taint_check(op["property"], regions)))
                if placed is not None:
                    placed.append(
                        {
                            "file": where,
                            "line": tokens[start].line,
                            "function": f"{where}#{name}",
                            "property": op["property"],
                        }
                    )
    return out


def _local_check_inserts(
    source: str, tokens: list, op: dict, skipped: list[str], where: str, name: str, placed: list[dict] | None
) -> list[tuple[int, str]]:
    """
    Plan step M6: before each `return` in the scope of local `op["local"]` (from its declaration, the
    first use of the name in the body, to the end of its block) and before that block's closing brace.
    """
    code = [t for t in tokens if t.kind == "c_token"]
    stack: list[int] = []
    decl = None
    for i, tok in enumerate(code):
        if tok.text == "{":
            stack.append(i)
        elif tok.text == "}":
            if stack:
                stack.pop()
        elif tok.text == op["local"] and stack:
            decl = i
            break
    if decl is None:
        skipped.append(f"{where}#{name}: local {op['local']} not found")
        return []
    depth, close = 0, None
    for k in range(stack[-1], len(code)):
        if code[k].text == "{":
            depth += 1
        elif code[k].text == "}":
            depth -= 1
            if depth == 0:
                close = k
                break
    if close is None:
        skipped.append(f"{where}#{name}: the block of local {op['local']} does not close")
        return []
    text = op["check"] + " "
    out = [(code[k].start, text) for k in range(decl, close) if code[k].text == "return"]
    out.append((code[close].start, text))
    if placed is not None:
        lines = [code[k].line for k in range(decl, close) if code[k].text == "return"] + [code[close].line]
        placed += [
            {"file": where, "line": line, "function": f"{where}#{name}", "property": op["property"]} for line in lines
        ]
    return out


def _return_check_inserts(
    source: str, tokens: list, op: dict, skipped: list[str], where: str, name: str, placed: list[dict] | None
) -> list[tuple[int, str]]:
    """Plan step M7: before each `return <expr>;`, the check with `<expr>` in place of the result."""
    code = [t for t in tokens if t.kind != "whitespace" and t.kind not in ("c_comment", "acsl_block", "acsl_line")]
    out: list[tuple[int, str]] = []
    for i, tok in enumerate(code):
        if tok.kind != "c_token" or tok.text != "return":
            continue
        depth, end = 0, None
        for k in range(i + 1, len(code)):
            t = code[k]
            if t.kind == "c_token" and t.text in "([{":
                depth += 1
            elif t.kind == "c_token" and t.text in ")]}":
                depth -= 1
            elif t.kind == "c_token" and t.text == ";" and depth == 0:
                end = k
                break
        expr = source[tok.end : code[end].start].strip() if end is not None else ""
        if not expr or _ARG_UNSAFE_RE.search(expr):
            skipped.append(
                f"{where}:{tok.line}: {name} return: "
                + ("no returned value" if not expr else "a returned expression the check cannot repeat")
            )
            continue
        out.append((tok.start, op["check"].replace("${result}", expr) + " "))
        if placed is not None:
            placed.append({"file": where, "line": tok.line, "function": f"{where}#{name}", "property": op["property"]})
    return out


def apply_taint(props: dict, work: Path, taint: bool = True) -> dict:
    """
    Write the taint annotations of every property's `taint` plan into the work tree (`work`, the
    target's copy): same-line insertions, so no line number moves. Annotations a previous run
    generated are removed first, so a re-run (or a run with taint off and an empty plan) leaves
    exactly the current plan. Returns the files changed, the annotated functions and what was skipped.
    """
    by_file: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    code_placed: list[dict] = []
    init_unplaced: list[dict] = []
    for p in props.get("properties") or []:
        # Package E: the property's checks at calls placed in initializers. Unlike `code`, the
        # property keeps its MetAcsl text: these only stand in where MetAcsl generates no instance.
        for c in p.get("init_checks") or []:
            file, _, name = str(c["function"]).rpartition("#")
            by_file[file][name].append(
                {
                    "kind": "init",
                    "callee": c["callee"],
                    "line": c["line"],
                    "at": c.get("at") or "before",
                    "check": c["check"],
                    "property": p["name"],
                }
            )
        code = p.get("code")
        for fid in p.get("instances") or [] if code else []:
            file, _, name = str(fid).rpartition("#")
            if code.get("returns"):
                by_file[file][name].append({"kind": "returns", "check": code["check"], "property": p["name"]})
            else:
                by_file[file][name].append(
                    {"kind": "local", "local": code["local"], "check": code["check"], "property": p["name"]}
                )
        if not taint:
            continue
        plan = p.get("taint") or {}
        for s in plan.get("sources") or []:
            file, _, name = str(s["function"]).rpartition("#")
            by_file[file][name].append({"kind": s["at"], "lvalues": s["lvalues"]})
        for c in plan.get("checks") or []:
            file, _, name = str(c["function"]).rpartition("#")
            by_file[file][name].append({"kind": "check", "sink": c["sink"], "args": c["args"], "property": p["name"]})
    changed: list[str] = []
    annotated: list[str] = []
    annotated_files: list[str] = []
    placed: list[dict] = []
    skipped: list[str] = []
    candidates = set(by_file)
    if work.is_dir():
        for path in sorted(work.rglob("*")):
            if path.suffix in (".c", ".h") and path.is_file():
                rel = path.relative_to(work).as_posix()
                try:
                    if _GENERATED_TAINT_RE.search(path.read_text(encoding="utf-8", errors="replace")):
                        candidates.add(rel)
                except OSError:
                    continue
    for file in sorted(candidates):
        path = work / file
        if not path.is_file():
            skipped.append(f"{file}: not in the work tree")
            init_unplaced += [
                _unplaced(op, file, name, "its file is not in the work tree")
                for name, ops in sorted(by_file.get(file, {}).items())
                for op in ops
                if op["kind"] == "init"
            ]
            continue
        original = path.read_text(encoding="utf-8", errors="surrogateescape")
        text, _ = strip_taint(original)
        inserts: list[tuple[int, str]] = []
        tainted = False
        for name, ops in sorted(by_file.get(file, {}).items()):
            local_ops = [op for op in ops if op["kind"] in CODE_OPS]
            taint_ops = [op for op in ops if op["kind"] not in CODE_OPS]
            inserts += _insert_taint_in_function(text, name, local_ops, skipped, file, code_placed, init_unplaced)
            found = _insert_taint_in_function(text, name, taint_ops, skipped, file, placed)
            if found:
                annotated.append(f"{file}#{name}")
                tainted = True
            inserts += found
        for offset, snippet in sorted(set(inserts), reverse=True):
            text = text[:offset] + snippet + text[offset:]
        if tainted:
            annotated_files.append(file)
        if text != original:
            path.write_text(text, encoding="utf-8", errors="surrogateescape", newline="")
            changed.append(file)
    return {
        "work": work.as_posix(),
        "changed": changed,
        "files": annotated_files,
        "functions": sorted(set(annotated)),
        "checks": sorted(placed, key=lambda c: (c["file"], c["line"], c["property"])),
        "code_checks": sorted(code_placed, key=lambda c: (c["file"], c["line"], c["property"])),
        "init_unplaced": init_unplaced,
        "skipped": skipped,
    }


def settle_init_checks(props: dict, unplaced: list[dict]) -> int:
    """
    Package E: move each initializer check apply_taint could not write (`init_unplaced`) from its
    property's `init_checks` to its `unchecked`, with the reason, so that what `init_checks` lists
    is what the work tree holds. Returns how many moved.
    """
    by_name = {p.get("name"): p for p in props.get("properties") or []}
    moved = 0
    for u in unplaced:
        prop = by_name.get(u["property"])
        if prop is None:
            continue
        key = (u["function"], u["callee"], u["line"])
        left = [c for c in prop.get("init_checks") or [] if (c["function"], c["callee"], c["line"]) != key]
        if len(left) == len(prop.get("init_checks") or []):
            continue
        moved += 1
        if left:
            prop["init_checks"] = left
        else:
            prop.pop("init_checks", None)
        prop.setdefault("unchecked", []).append({k: u[k] for k in ("function", "callee", "line", "reason")})
    return moved


def set_taint_params(files: list[str], previous: list[str], work: Path, run_dir: Path = Path(".")) -> dict:
    """
    Turn Eva's taint domain on (params.json `eva_taint`, EVA_TAINT_<mod> in the Makefile) for every
    harness module whose sources include an annotated file, and off again for the modules a previous
    run turned it on for that no longer need it. Without harness modules yet (Phase 0 Step 3 runs
    before Step 4), nothing is set: the Makefile's `seed` runs `security-props` again after them.
    """
    import pipeline_make  # noqa: PLC0415 (lazy: the generation itself needs no Make layer)

    wanted = {(work / f).as_posix() for f in files}
    try:
        plan = pipeline_make.build_plan(run_dir)
    except Exception as exc:  # noqa: BLE001 (no plan yet: nothing to set, said in the result)
        return {"modules": [], "pending": f"no module plan yet ({str(exc)[:160]})"}
    if not plan.modules:
        return {"modules": [], "pending": "no harness module yet: run security_props.py again after Step 4"}
    modules = []
    for name, mod in sorted(plan.modules.items()):
        # An include_source harness #includes the module's files: its DAG record names them.
        dag_sources = (plan.records.get(name) or {}).get("required_sources") or []
        srcs = {Path(s).as_posix() for s in mod.sources} | {(work / str(s)).as_posix() for s in dag_sources}
        if wanted & srcs:
            modules.append(name)
    for name in modules:
        pipeline_make.params_set(run_dir, name, eva_taint=True)
    for name in sorted(set(previous) - set(modules)):
        if name in plan.modules:
            pipeline_make.params_set(run_dir, name, eva_taint=False)
    return {"modules": modules}


def obligations_for(props: dict, file: str, name: str) -> list[dict]:
    """The obligations of a function, keyed `file#name`."""
    return list((props.get("obligations") or {}).get(f"{file}#{name}") or [])


DISCHARGE = {
    "frame": "an `assigns` clause naming every location the function writes; WP proves it (l3_frame)",
    "auth_state": (
        "the generated `assert {name}: meta:` before each write: the written location is separated from the auth "
        "state. Give pointer parameters `requires \\separated(p, &state)`; only the gate may write the state"
    ),
    "auth_required": (
        "the precondition `{name}` of each protected function, at its call sites here: call it only where the "
        "auth state holds (after the gate, or under a test of the state)"
    ),
    "sanitized": (
        "the generated `assert {name}: meta:` before each call of the sink here (or, for a buffer sink, its "
        "`ensures {name}`): what reaches the sink is sanitized"
    ),
    "sanitized_entry": (
        "the precondition `{name}` of the sink (generated `requires {name}: meta:`), at each call of the sink "
        "here: what reaches the sink is sanitized. A call through a function pointer needs a `calls` annotation "
        "naming the sink, or WP has no precondition to prove there"
    ),
    "wiped": "the generated `ensures {name}`: the secret is zero on every return path",
    "gate_failure": (
        "the generated `check {name}` already in the code before each return of the gate (do not edit or move "
        "it): a result other than the success value leaves the auth state as it was on entry. Set the state on "
        "the success path only"
    ),
    "wiped_local": (
        "the generated `check {name}` already in the code before each return in the local's scope (do not edit or "
        "move it): the local is zero there. Wipe it with a loop whose invariants state the zeroed prefix"
    ),
    "no_leak": (
        "the generated `assert {name}: meta:` before each sink call: no argument points into the secret "
        "(for a pointer parameter, `requires \\separated(...)` with the secret)"
    ),
    "asset_writers": (
        "the generated `assert {name}: meta:` before each write: the written location is separated from the "
        "asset. Give pointer parameters `requires \\separated(p, &asset)`; only the declared writers may write it"
    ),
    "asset_readers": (
        "the generated `assert {name}: meta:` before each read: the location read is separated from the asset. "
        "Give pointer parameters `requires \\separated(p, &asset)`; only the declared readers may read it"
    ),
    "invariant": (
        "the generated `requires {name}: meta:` and `ensures {name}: meta:` of the functions in scope (the "
        "`requires` is proved here at each call of one), and for a strong invariant the `assert {name}: meta:` "
        "after each statement that may change it: keep the predicate true at every such point"
    ),
    "invariant_conditional": (
        "the generated behavior `{name}` (`assumes` the predicate, `ensures` it): when the predicate holds on "
        "entry it holds on return"
    ),
    "invariant_monotonic": (
        "the generated `assert {name}: meta:` after each write: either the written location is separated from "
        "the state, or the state did not move back"
    ),
    "call_rule": (
        "the generated `assert {name}: meta:` before each call of the callee here: establish the rule first "
        "(a test of the state, or a `requires` of this function)"
    ),
    "call_rule_entry": (
        "the precondition `{name}` of the callee (generated `requires {name}: meta:`), at each call of it here. "
        "A call through a function pointer needs a `calls` annotation naming the callee"
    ),
}
# Added to the entry of a property with a call placed in an initializer in the function (package E).
DISCHARGE_INIT = (
    " At a call placed in an initializer (`int n = f(x);`) MetAcsl generates nothing: the generated "
    "`check {name}` already in the code there (do not edit or move it) is the same obligation"
)


def _discharge(p: dict, fid: str) -> str:
    kind = str(p.get("kind"))
    variant = str(p.get("variant") or "")
    code = p.get("code") or {}
    if code.get("returns"):
        key = "gate_failure"
    elif code:
        key = "wiped_local"
    elif kind == "sanitized" and "\\context(\\precond)" in str(p.get("acsl")):
        key = "sanitized_entry"
    elif kind == "invariant" and variant in ("conditional", "monotonic", "monotonic_formal"):
        key = "invariant_conditional" if variant == "conditional" else "invariant_monotonic"
    elif kind == "call_rule" and variant == "entry":
        key = "call_rule_entry"
    else:
        key = kind
    text = DISCHARGE.get(key, "")
    if any(c.get("function") == fid for c in p.get("init_checks") or []):
        text += DISCHARGE_INIT
    return text.format(name=p.get("name"))


def brief_entries(props: dict, file: str, name: str) -> list[dict]:
    """
    The security obligations of `file#name` for a Phase 3 brief: each MetAcsl property whose generated
    annotations land in the function, with its ACSL, and the L3 frame obligation.
    """
    fid = f"{file}#{name}"
    out: list[dict] = []
    for ob in obligations_for(props, file, name):
        if ob.get("class") == "l3_frame":
            out.append(
                {
                    "layer": 3,
                    "obligation_class": "l3_frame",
                    "property": "L3_frame",
                    "reason": ob.get("reason"),
                    "discharge": DISCHARGE["frame"],
                }
            )
    for p in props.get("properties") or []:
        if fid not in (p.get("instances") or []):
            continue
        out.append(
            {
                "layer": p.get("layer"),
                "obligation_class": p.get("obligation_class"),
                "property": p.get("name"),
                "kind": p.get("kind"),
                "metacsl": p.get("acsl"),
                "notes": p.get("notes") or [],
                "discharge": _discharge(p, fid),
            }
        )
    return out


def validate(doc: dict) -> list[str]:
    from minischema import Validator, load_schema

    here = Path(__file__).resolve().parent
    for cand in (here.parent / "schemas", Path("/opt/framac-pipeline/schemas")):
        path = cand / "security_props.schema.json"
        if path.is_file():
            return list(Validator(load_schema(path)).errors(doc))
    return ["schemas/security_props.schema.json not found"]


# ---------------------------------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------------------------------


def cmd_run(args: argparse.Namespace) -> int:
    import trust

    model = load_json_optional(args.model, None)
    if not isinstance(model, dict) or model.get("status") != "ok":
        print(json.dumps({"ok": False, "error": f"{args.model}: no model with status ok (run phase0_model.py)"}))
        return 1
    # The threat model the model's trust used (its recorded path and sha256), never a new search. A model
    # without the trust feature (trust.py failed, or an old model) has no record: look it up as trust.py
    # would, and say so.
    note = None
    if model_features(model)["trust"]:
        threat, why = trust.recorded_threat_model(model)
    else:
        threat, why = trust.load_threat_model(trust.find_threat_model(None, model)), None
        note = f"the model has {MODEL_FEATURES['trust']}; threat model looked up as trust.py does: {threat['path']}"
    if threat is None:
        print(json.dumps({"ok": False, "error": f"{args.model}: {why}"}))
        return 1
    if threat["status"] == trust.STATUS_INVALID:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": f"invalid threat model {threat['path']}: fix it (trust.py check-threat-model), then "
                    f"{trust.RERUN_MODEL}",
                    "threat_model": trust.STATUS_INVALID,
                    "errors": threat["errors"],
                },
                indent=1,
            )
        )
        return 2
    # The declarations of the functions the target only declares are read from the work tree, else
    # from the tree the model was built on (their `assigns` decides what a \writing property sees).
    roots = [args.work] + ([Path(str(model["tree"]))] if model.get("tree") else [])
    doc = generate(model, threat, roots=roots)
    if note:
        doc["warnings"].insert(0, note)
    # Plan step M3, opt in: Eva taint annotations in the work tree. The choice is sticky (the Makefile's
    # `security-props` runs without options), and turning it off removes the annotations again.
    previous = load_json_optional(args.out, None)
    previous_taint = previous.get("eva_taint") if isinstance(previous, dict) else None
    previous_taint = previous_taint if isinstance(previous_taint, dict) else {}
    enabled = args.eva_taint if args.eva_taint is not None else bool(previous_taint.get("enabled"))
    applied = apply_taint(doc, args.work, taint=enabled)
    doc["code_checks"] = applied["code_checks"]
    settle_init_checks(doc, applied["init_unplaced"])
    record: dict[str, Any] = {
        "enabled": enabled,
        **{k: applied[k] for k in ("files", "functions", "checks", "skipped")},
    }
    if enabled or previous_taint.get("modules"):
        record.update(
            set_taint_params(applied["files"], list(previous_taint.get("modules") or []), args.work, args.run_dir)
        )
    doc["eva_taint"] = record
    if enabled and record.get("pending"):
        doc["warnings"].append(f"eva_taint: {record['pending']}")
    if applied["skipped"]:
        doc["warnings"].append(
            f"work tree: {len(applied['skipped'])} annotation(s) not placed: {applied['skipped'][:3]}"
        )
    # The engines that check the MetAcsl properties besides WP (docs/plans/metacsl-exploitation-plan.md):
    # opt in and sticky like --eva-taint, so the Makefile's plain `security-props` run keeps the choice.
    previous_engines = previous.get("meta_engines") if isinstance(previous, dict) else None
    chosen = args.meta_engines if args.meta_engines is not None else previous_engines
    doc["meta_engines"] = sorted(meta_engines({"meta_engines": chosen}))
    # Own schema problems are warnings in the artifact (validate_artifacts.py run-dir fails on them).
    problems = validate(doc)
    if problems:
        doc["warnings"].append(f"schema: {problems[:5]}")
    atomic_write_json(args.out, doc)
    out = {
        "ok": True,
        "out": str(args.out),
        "threat_model": doc["threat_model"]["status"],
        "summary": doc["summary"],
        "eva_taint": {k: v for k, v in doc["eva_taint"].items() if k not in ("functions", "checks")},
        "meta_engines": doc["meta_engines"],
        "warnings": doc["warnings"][:10],
    }
    if problems:
        out["schema"] = problems[:5]
    print(json.dumps(out, indent=1))
    return 0


def cmd_meta_file(args: argparse.Namespace) -> int:
    props = load_json_optional(args.props, None)
    if not isinstance(props, dict):
        print(json.dumps({"ok": False, "error": f"{args.props}: not found"}))
        return 1
    res = meta_file_text(props, args.function)
    if res is None:
        print(json.dumps({"ok": True, "properties": [], "sources": []}))
        return 0
    text, names, sources = res
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(text, encoding="utf-8", newline="\n")
    print(json.dumps({"ok": True, "out": str(args.out), "properties": names, "sources": sources}))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Security layers L3-L6: MetAcsl properties from the threat model")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="Write workspace/reports/security_props.json")
    r.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    r.add_argument("--out", type=Path, default=DEFAULT_OUT)
    taint = r.add_mutually_exclusive_group()
    taint.add_argument(
        "--eva-taint",
        dest="eva_taint",
        action="store_true",
        help="Write Eva taint annotations for the L6 secrets into the work tree (sticky; plan step M3)",
    )
    taint.add_argument("--no-eva-taint", dest="eva_taint", action="store_false", help="Remove them again")
    r.set_defaults(eva_taint=None)
    r.add_argument(
        "--meta-engines",
        type=_engine_list,
        default=None,
        help=f"Engines that check the MetAcsl properties besides WP: a comma-separated list of "
        f"{', '.join(META_ENGINES)}, or `none` (sticky; default: the previous run's choice, else none)",
    )
    r.add_argument("--work", type=Path, default=DEFAULT_WORK, help=f"The work tree (default {DEFAULT_WORK})")
    r.add_argument("--run-dir", type=Path, default=Path("."), help="The run directory (params.json)")
    m = sub.add_parser("meta-file", help="The MetAcsl file of one function's WP run")
    m.add_argument("--function", required=True, help="file#name (or a bare name)")
    m.add_argument("--props", type=Path, default=DEFAULT_OUT)
    m.add_argument("--out", type=Path, required=True)
    a = p.parse_args(argv)
    return cmd_run(a) if a.cmd == "run" else cmd_meta_file(a)


if __name__ == "__main__":
    sys.exit(main())
