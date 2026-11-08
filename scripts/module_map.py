#!/usr/bin/env python3
"""
Harness modules and the build's link units (docs/phase0-implementation-plan.md step I5b).

With the Phase 0 model, the DAG's modules are link units (`libqcbor_a`, `libcryptolib_so`): the ledger
groups functions by unit, and tiers, sources and flags come from the unit. Harnesses stay smaller: a
*harness module* (the name of `harness_<name>.{c,json}`, of its Make targets, reports, corpus and
candidates) is either a unit itself or a sub-module of one, such as QCBOR's 8 harnesses inside
`libqcbor_a`. Its sidecar names its unit in `unit`.

Every place that matches a harness module against a DAG module or a ledger unit's `module` goes
through `ModuleMap`, so a sub-module's report credits its unit's functions. Without the model the DAG
modules are the lexer's, every harness module is its own unit, and the mapping is the identity.

Sub-modules come from two places: the lexer modules of a unit (the benchmark's harnesses are written
per lexer module), and the clusters of a unit too large for one Eva run (step I8, scripts/unit_split.py:
the DAG's `submodules`, each with its `unit`, `functions` and entry points).

A harness module's *scope* is the code it answers for at the reachability gate: the whole unit for a
unit-named harness; for a sub-module, the functions of the lexer module of the same name, else of the
split cluster of that name, else `scope_files` from its sidecar, else the functions of the sources its
sidecar lists. Its tier and run flags come from the same record (the lexer module's or the cluster's,
both set from its functions' tiers by scripts/tiers.py), else from its unit.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

DAG_PATH = Path("workspace/reports/callgraph_dag.json")
HARNESS_DIR = Path("workspace/harnesses")


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def load_sidecars(harness_dir: Path = HARNESS_DIR) -> dict[str, dict]:
    """Harness module -> sidecar (keyed by file stem, as pipeline_make does)."""
    out: dict[str, dict] = {}
    if not harness_dir.is_dir():
        return out
    for path in sorted(harness_dir.glob("harness_*.json")):
        data = _load(path)
        if isinstance(data, dict):
            out[path.stem[len("harness_") :]] = data
    return out


def _norm(path: str) -> str:
    p = str(path).replace("\\", "/").lstrip("./")
    return p[len("workspace/work/") :] if p.startswith("workspace/work/") else p


class ModuleMap:
    def __init__(self, dag: dict | None, sidecars: dict[str, dict] | None = None) -> None:
        self.dag = dag if isinstance(dag, dict) else {}
        self.sidecars = sidecars or {}
        self.modules: dict[str, dict] = self.dag.get("modules") or {}
        self.lexer_modules: dict[str, dict] = self.dag.get("lexer_modules") or {}
        self.functions: dict[str, dict] = self.dag.get("functions") or {}
        self._unit_of_lexer: dict[str, str] = self.dag.get("unit_of_lexer_module") or {}
        # Step I8: clusters of split units (scripts/unit_split.py).
        self.split_submodules: dict[str, dict] = {
            n: r
            for n, r in (self.dag.get("submodules") or {}).items()
            if isinstance(r, dict) and r.get("unit") in self.modules
        }

    @classmethod
    def load(cls, run_dir: Path | str = ".") -> ModuleMap:
        root = Path(run_dir)
        return cls(_load(root / DAG_PATH), load_sidecars(root / HARNESS_DIR))

    @property
    def units_are_link_units(self) -> bool:
        return self.dag.get("module_kind") == "link_unit"

    def unit_of(self, module: str) -> str:
        """The DAG module (link unit) a harness module belongs to; the module itself when unknown."""
        declared = (self.sidecars.get(module) or {}).get("unit")
        if isinstance(declared, str) and declared in self.modules:
            return declared
        if module in self.modules:
            return module
        if module in self._unit_of_lexer:
            return self._unit_of_lexer[module]
        split = self.split_submodules.get(module)
        return str(split["unit"]) if split else module

    def same_unit(self, a: str, b: str) -> bool:
        return self.unit_of(a) == self.unit_of(b)

    def submodules(self, unit: str) -> list[str]:
        """Harness modules (with a sidecar) of a unit, the unit's own harness included."""
        return sorted(m for m in self.sidecars if self.unit_of(m) == unit)

    def harness_module_for(self, unit: str) -> str | None:
        """The harness to build or replay on behalf of a unit: its own, else its first sub-module."""
        if unit in self.sidecars:
            return unit
        subs = self.submodules(unit)
        return subs[0] if subs else None

    def is_submodule(self, module: str) -> bool:
        return module not in self.modules and self.unit_of(module) in self.modules

    def scope_functions(self, module: str) -> list[str]:
        """DAG keys of the functions a harness module answers for (see the module docstring)."""
        if module in self.modules and not self.is_submodule(module):
            return list(self.modules[module].get("functions") or [])
        unit = self.unit_of(module)
        in_unit = set((self.modules.get(unit) or {}).get("functions") or []) or set(self.functions)
        if module in self.lexer_modules:
            return sorted(k for k in in_unit if (self.functions.get(k) or {}).get("lexer_module") == module)
        if module in self.split_submodules:
            return sorted(k for k in self.split_submodules[module].get("functions") or [] if k in in_unit)
        sidecar = self.sidecars.get(module) or {}
        files = {_norm(f) for f in sidecar.get("scope_files") or sidecar.get("sources") or [] if isinstance(f, str)}
        return sorted(k for k in in_unit if _norm((self.functions.get(k) or {}).get("file") or "") in files)

    def scope_entry_points(self, module: str) -> list[str]:
        """The unit's API entry points within a harness module's scope."""
        unit = self.unit_of(module)
        entries = [e for e in (self.modules.get(unit) or {}).get("candidate_entry_points") or [] if isinstance(e, str)]
        if unit == module:
            return entries
        scope = set(self.scope_functions(module))
        return [e for e in entries if e in scope]

    def unit_record(self, module: str) -> dict:
        """The DAG module record (tier, run flags, sources, flags) a harness module runs under."""
        return self.modules.get(self.unit_of(module)) or self.modules.get(module) or {}

    def submodule_record(self, module: str) -> dict | None:
        """The record a sub-module takes its tier and run flags from: its lexer module's, else its cluster's."""
        if not self.is_submodule(module):
            return None
        for rec in (self.lexer_modules.get(module), self.split_submodules.get(module)):
            if isinstance(rec, dict) and rec.get("tier"):
                return rec
        return None

    def splits(self, unit: str) -> list[str]:
        """The clusters a split unit was cut into (scripts/unit_split.py), in DAG order."""
        return [n for n, r in self.split_submodules.items() if r.get("unit") == unit]

    def tier_of(self, module: str) -> str | None:
        """A sub-module's tier is its lexer module's or its cluster's (scripts/tiers.py); else the unit's."""
        sub = self.submodule_record(module)
        if sub is not None:
            return str(sub["tier"])
        tier = self.unit_record(module).get("tier")
        return str(tier) if tier else None

    def run_flags(self, module: str) -> dict[str, bool]:
        """`run_eva`, `run_eacsl_fuzz`, `run_wp_full` for a harness module, from the same record as its tier."""
        rec = self.submodule_record(module) or self.unit_record(module)
        return {
            k: bool(rec.get(k, True if k == "run_eva" else False)) for k in ("run_eva", "run_eacsl_fuzz", "run_wp_full")
        }


def infer_unit(dag: dict | None, module: str, referenced_functions: list[str] | None = None) -> str | None:
    """
    The unit a new harness module belongs to (generate_harness.py writes it into the sidecar): the
    module itself when it is a DAG module, else the unit holding its lexer module's functions, else the
    unit holding most of the functions the harness calls. None without link units.
    """
    mm = ModuleMap(dag)
    if not mm.units_are_link_units:
        return None
    if module in mm.modules:
        return module
    if module in mm._unit_of_lexer:
        return mm._unit_of_lexer[module]
    if module in mm.split_submodules:
        return str(mm.split_submodules[module]["unit"])
    votes: dict[str, int] = {}
    for fn in referenced_functions or []:
        mod = (mm.functions.get(fn) or {}).get("module")
        if isinstance(mod, str) and mod in mm.modules:
            votes[mod] = votes.get(mod, 0) + 1
    return sorted(votes.items(), key=lambda kv: (-kv[1], kv[0]))[0][0] if votes else None
