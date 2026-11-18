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
      no goal, the property's `decided` and the obligation's `decided` record the verdict;
  L6  each secret:
        L6_wiped_<secret>    zero when its release function (the secret's `function`) returns;
        L6_no_leak_<secret>  never passed to a sink, never read by a sink the target defines.

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
}
CLASSES = tuple(cls for _, cls in KINDS.values())
# Generated property names start with these; run_wp_function maps goals named so to the class.
NAME_PREFIX = {
    "auth_state": "L4_auth_state_",
    "auth_required": "L4_auth_required_",
    "sanitized": "L5_sanitized_",
    "wiped": "L6_wiped_",
    "no_leak": "L6_no_leak_",
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
        for e in model.get("edges") or []:
            a, b = e.get("caller"), e.get("callee")
            if a in self.functions and b in self.functions and a != b:
                self.callers[b].add(a)
        self.ext_callers: dict[str, set[str]] = defaultdict(set)
        for fid, f in self.functions.items():
            for name in f.get("external_calls") or []:
                self.ext_callers[name].add(fid)
        self.external_formals: dict[str, list] = model.get("external_formals") or {}
        self.globals_by_name: dict[str, list[dict]] = defaultdict(list)
        for g in (model.get("global_variables") or {}).values():
            self.globals_by_name[str(g.get("name"))].append(g)
        self.features = model_features(model)
        self.has_writes = self.features["writes"]

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


class _Gen:
    def __init__(self, model: dict, block: dict | None, templates: _Templates):
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
        decided = {f: d for f, d in (extra.pop("decided", None) or {}).items() if f in self.m.live}
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

    # -- L3 -----------------------------------------------------------------------------------------

    def frame(self) -> dict[str, str]:
        return self.m.pointer_writers()

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
            writes = (set(writers) | self.m.direct_writers(root)) - gate_fids
            name = self._unique(f"{NAME_PREFIX['auth_state']}{_ident(gate)}")
            acsl = self.t.render("l4_auth_state", variant, name=name, gate=gate, state=lv)
            self._add(
                "auth_state",
                name,
                acsl,
                writes,
                sources=files,
                notes=note,
                threat_model={"auth_gate": gate, "state": state},
                targets=f"every function but {gate}",
                direct_writers=sorted(self.m.direct_writers(root) - gate_fids),
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

    # -- L5 -----------------------------------------------------------------------------------------

    def _sink_params(self, item: dict, sink: str, kinds: tuple[str, ...]) -> tuple[list[str], list[dict] | None]:
        formals = self.m.formals(sink)
        if item.get("params"):
            return [str(p) for p in item["params"]], formals
        if formals is None:
            return [], None
        return [str(p["name"]) for p in formals if p.get("kind") in kinds], formals

    def output_sinks(self) -> None:
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
            clauses = []
            for p in params:
                if buffer:
                    clauses.append(self.t.render("l5_sanitized", "out_object", param=p))
                elif kind in TEXT_SINKS:
                    clauses.append(self.t.render("l5_sanitized", "text", param=p))
                elif length:
                    clauses.append(self.t.render("l5_sanitized", "bytes", param=p, length=str(length)))
                else:
                    clauses.append(self.t.render("l5_sanitized", "object", param=p))
            name = self._unique(f"{NAME_PREFIX['sanitized']}{_ident(sink)}")
            predicate = " &&\n      ".join(clauses)
            acsl = self.t.render(
                "l5_sanitized", "buffer" if buffer else "emit", name=name, sink=sink, predicate=predicate
            )
            notes = []
            if not buffer and kind not in TEXT_SINKS and not length:
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
            self._add(
                "sanitized",
                name,
                acsl,
                instances,
                decided=decided,
                notes=notes,
                threat_model={"output_sink": sink, "kind": kind, "params": params},
                targets=sink,
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
            for s in sinks:
                sname = str(s["function"]).split("#")[-1]
                params, _ = self._sink_params(s, sname, ("pointer", "const_pointer"))
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


def generate(model: dict, threat: dict | None, templates: _Templates | None = None) -> dict:
    """The security properties of a model under a threat model (trust.load_threat_model's result)."""
    threat = threat or {"status": "no_threat_model"}
    block = threat.get("block") if threat.get("status") == "ok" else None
    gen = _Gen(model, block, templates or _Templates())
    frame = gen.frame()
    if block:
        gen.auth_gates()
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
_GENERATED_TAINT_RE = re.compile(
    r"/\*@ (?:taint [^\n]*?; |assert L6_no_leak_[A-Za-z0-9_]+: " + TAINT_TAG + r": [^\n]*?; "
    r"|check (?:L6_wiped_|L4_auth_state_)[A-Za-z0-9_]+: [^\n]*?; )\*/ "
)
# Argument text an assertion may repeat: no call, assignment or increment.
_ARG_UNSAFE_RE = re.compile(r"[A-Za-z_]\w*\s*\(|(?<![=!<>])=(?!=)|\+\+|--")
_STATEMENT_STOP = frozenset({";", "{", "}"})
# Code-check operations (written whatever --eva-taint says): a local's wipe (M6), a gate's failure (M7).
CODE_OPS = frozenset({"local", "returns"})


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


def _insert_taint_in_function(
    source: str, name: str, ops: list[dict], skipped: list[str], where: str, placed: list[dict] | None = None
) -> list:
    """
    (offset, text) insertions for one function's sources and checks; problems go to `skipped`, and each
    check placed (file, line, function, property: where Eva reports its status) to `placed`.
    """
    from acsl_ast import _find_body_brace_offset, locate_all_definition_spans, tokenize_c_acsl  # noqa: PLC0415

    spans = locate_all_definition_spans(source, where)
    span = spans.get(name)
    if span is None:
        skipped.append(f"{where}#{name}: no definition found")
        return []
    brace = _find_body_brace_offset(span.text, where)
    if brace is None:
        skipped.append(f"{where}#{name}: no body found")
        return []
    body_start = span.start_byte + brace
    tokens = [t for t in tokenize_c_acsl(source, where) if body_start <= t.start < span.end_byte]
    out: list[tuple[int, str]] = []
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
    for p in props.get("properties") or []:
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
            continue
        original = path.read_text(encoding="utf-8", errors="surrogateescape")
        text, _ = strip_taint(original)
        inserts: list[tuple[int, str]] = []
        tainted = False
        for name, ops in sorted(by_file.get(file, {}).items()):
            local_ops = [op for op in ops if op["kind"] in CODE_OPS]
            taint_ops = [op for op in ops if op["kind"] not in CODE_OPS]
            inserts += _insert_taint_in_function(text, name, local_ops, skipped, file, code_placed)
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
        "skipped": skipped,
    }


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
}


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
                "discharge": (
                    DISCHARGE["gate_failure"]
                    if (p.get("code") or {}).get("returns")
                    else DISCHARGE["wiped_local"]
                    if p.get("code")
                    else DISCHARGE.get(str(p.get("kind")), "")
                ).format(name=p.get("name")),
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
    doc = generate(model, threat)
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
