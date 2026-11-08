#!/usr/bin/env python3
"""
Security layers L3-L6 (docs/phase0-implementation-plan.md step I9): the obligations the threat model
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
      `buffer` sink, initialized out-parameters when it returns (\\postcond);
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
        prop = {
            "name": name,
            "layer": layer,
            "kind": kind,
            "obligation_class": cls,
            "acsl": acsl,
            "instances": sorted(f for f in instances if f in self.m.live),
            "sources": sorted(set(extra.pop("sources", []))),
            "notes": list(extra.pop("notes", [])),
        }
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
            self._add(
                "sanitized",
                name,
                acsl,
                instances,
                notes=notes,
                threat_model={"output_sink": sink, "kind": kind, "params": params},
                targets=sink,
            )

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
        self.warnings.append(
            f"secret {name}: kind `{kind}` (a returned secret) has no lvalue a property can name; declare where the caller keeps it"
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
            notes = ["direct flows only: a copy of the secret that reaches a sink is not seen"]
            if sec["scope"] != "global":
                notes.append(f"a parameter secret is checked in {fn_name} only")
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
            )


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
        for fid in prop["instances"]:
            reason = f"{prop['name']} ({prop['kind'].replace('_', ' ')}, layer {prop['layer']})"
            obligations[fid].append({"class": prop["obligation_class"], "property": prop["name"], "reason": reason})
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
    selected = properties_for(props, function)
    if not selected:
        return None
    parts = [str(props.get("preamble") or "")]
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
                "discharge": DISCHARGE.get(str(p.get("kind")), "").format(name=p.get("name")),
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
    m = sub.add_parser("meta-file", help="The MetAcsl file of one function's WP run")
    m.add_argument("--function", required=True, help="file#name (or a bare name)")
    m.add_argument("--props", type=Path, default=DEFAULT_OUT)
    m.add_argument("--out", type=Path, required=True)
    a = p.parse_args(argv)
    return cmd_run(a) if a.cmd == "run" else cmd_meta_file(a)


if __name__ == "__main__":
    sys.exit(main())
