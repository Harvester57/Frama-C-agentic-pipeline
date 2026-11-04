#!/usr/bin/env python3
"""
Make-driven deterministic phases: writes the run's Makefile, runs its targets, and implements
the recipes that need Python (stdlib only).

Per-module work that needs no judgment runs from workspace/build/Makefile instead of LLM
subagents: builds, the E-ACSL selftest, fuzz campaigns, Eva runs, report ingestion, candidate
replays, the WP queue, the end-of-run WP sweep and the reports. Make runs inside the container
from the run directory (/framac-run), the working directory every script assumes.

Subcommands (run from the run directory):
  gen                          write workspace/build/{Makefile,modules.mk}; print the module plan
  params set --module M [...]  record per-module tuning in workspace/build/params.json
  params show [--module M]     effective tuning of every module
  run <targets...>             make -f workspace/build/Makefile -j<this container's CPUs> -k --output-sync=target
  ingest [--module M]          ingest new fuzz then Eva reports, stubbing missing ones; validate
  sweep-list                   the ledger's WP-covered proof units, as (file, function)
  sweep [--jobs N]             re-prove them without the per-run WP cache, one leased WP job each

modules.mk is derived from workspace/reports/callgraph_dag.json, the harness sidecars
(workspace/harnesses/harness_<mod>.json), params.json and run-metadata.json. Every value is a
shell word escaped for make, and every flag must pass an allowlist, so a sidecar can neither
inject shell commands nor load compiler plug-ins into the trusted builds. `run` regenerates it
before each make invocation, so tuning and harness repairs apply without a separate `gen`.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from collections import deque
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cache  # noqa: E402
from framac_common import (  # noqa: E402
    ArtifactError,
    RunLockTimeout,
    atomic_write_json,
    is_safe_relative_path,
    load_json_optional,
    load_json_strict,
    run_lock,
    utc_now,
)
from workspace_overlay import infer_prover_wp_flags  # noqa: E402

SCRIPTS_DIR = Path(__file__).resolve().parent
CONTAINER_TEMPLATES_DIR = Path("/opt/framac-pipeline/templates")

# Run-relative paths (forward slashes: they are written into the Makefile and the reports).
BUILD_DIR = "workspace/build"
MAKEFILE = f"{BUILD_DIR}/Makefile"
MODULES_MK = f"{BUILD_DIR}/modules.mk"
PARAMS_JSON = f"{BUILD_DIR}/params.json"
LOG_DIR = f"{BUILD_DIR}/logs"
DAG_JSON = "workspace/reports/callgraph_dag.json"
HARNESS_DIR = "workspace/harnesses"
WORK_DIR = "workspace/work"
REPORT_DIRS = {"fuzz": "workspace/reports/fuzz", "eva": "workspace/reports/eva"}
SELFTEST_JSON = "workspace/reports/eacsl_selftest.json"
INGESTED_JSON = "state/ingested.json"
LEDGER_JSON = "coverage-ledger.json"
SWEEP_DIR = "workspace/reports/wp-sweep"

DEFAULT_PROFILE = "standard"
FUZZ_BUDGET_BY_PROFILE = {"quick": 60, "standard": 120, "deep": 900}  # CPU-seconds per campaign
DEFAULT_EVA_SLEVEL = 100
MODULE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.+-]{0,127}$")
FUNCTION_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class PipelineMakeError(RuntimeError):
    pass


class _Excluded(Exception):
    """A module cannot run from Make; the message is the reason shown to the orchestrator."""


# ---------------------------------------------------------------------------
# Flag allowlist
# ---------------------------------------------------------------------------
#
# Flags a module may carry into the Make builds (cppflags and ldflags, after shlex.split).
# None of them can load code into a compiler, swap a tool or write outside the build outputs.
# Everything else (-fplugin, -B, -fuse-ld, -specs, -Xclang, -Wl,, -load, ...) is rejected and the
# module is left out of the Make phases: `build`, `eva` and `wp-sweep` are trusted steps that may
# write the shared cross-run cache.

_VALUE_FLAGS = ("-I", "-D", "-U", "-l", "-L", "-include", "-imacros", "-isystem", "-iquote", "-idirafter")
_PATH_FLAG_PREFIXES = ("-include", "-imacros", "-isystem", "-iquote", "-idirafter")
_JOINED_FLAG_PREFIXES = ("-I", "-D", "-U", "-l", "-L")
_EXACT_FLAGS = frozenset({"-fcommon", "-fno-common"})
_PREFIX_FLAGS = ("-std=", "-O", "-g", "-W")
# Look allowed but are not: passthroughs to the linker, assembler and preprocessor, clang's
# file-writing -gen-* options, and Frama-C's module loader (-load*, which -l* would match).
_DENIED_PREFIXES = ("-Wl,", "-Wa,", "-Wp,", "-gen-", "-load")
_SPACE_RE = re.compile(r"\s")


def check_flags(tokens: list[str]) -> list[str]:
    """Reasons why `tokens` fail the build flag allowlist (empty when every token is allowed)."""
    problems: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        i += 1
        if _SPACE_RE.search(tok):
            # e-acsl-gcc re-splits flag values on spaces, so `-DX -fplugin=p.so` would become two flags.
            problems.append(f"{tok!r} contains whitespace")
        elif tok.startswith(_DENIED_PREFIXES):
            problems.append(f"{tok!r} is not allowed")
        elif tok in _VALUE_FLAGS:
            value = tokens[i] if i < len(tokens) else None
            i += 1
            if value is None:
                problems.append(f"{tok} has no value")
            elif value.startswith("-") or _SPACE_RE.search(value):
                problems.append(f"{tok} {value!r}: value looks like an option or contains whitespace")
        elif tok.startswith(_PATH_FLAG_PREFIXES) or (tok.startswith(_JOINED_FLAG_PREFIXES) and len(tok) > 2):
            continue
        elif tok in _EXACT_FLAGS or tok.startswith(_PREFIX_FLAGS):
            continue
        else:
            problems.append(f"{tok!r} is not allowed")
    return problems


def split_flags(value: Any, default: str = "") -> list[str]:
    """Flag tokens from a sidecar string (shlex) or a DAG list; ValueError on anything else."""
    if value is None:
        value = default
    if isinstance(value, str):
        return shlex.split(value)
    if isinstance(value, list) and all(isinstance(t, str) for t in value):
        return list(value)
    raise ValueError(f"expected a string or a list of strings, got {type(value).__name__}")


def _joined_forms(tokens: list[str]) -> set[str]:
    """`-I dir` and `-Idir` compare equal (DAG flags are always joined)."""
    out: set[str] = set()
    i = 0
    while i < len(tokens):
        if tokens[i] in _JOINED_FLAG_PREFIXES and i + 1 < len(tokens):
            out.add(tokens[i] + tokens[i + 1])
            i += 2
        else:
            out.add(tokens[i])
            i += 1
    return out


def with_acsl(tokens: list[str], acsl_dir: str) -> list[str]:
    """Build flags: the module's flags plus the ACSL template headers, as in every campaign and Eva run."""
    acsl = f"-I{acsl_dir}"
    return list(tokens) if acsl in _joined_forms(tokens) else [*tokens, acsl]


# ---------------------------------------------------------------------------
# Make quoting
# ---------------------------------------------------------------------------


def mk_quote(value: str) -> str:
    """
    One shell word, written so that make passes it through unchanged: shlex.quote, then `$` as
    `$$` and `#` (a make comment) behind an odd number of backslashes. Line breaks cannot be
    written into a makefile at all.
    """
    if any(c in value for c in "\n\r\0"):
        raise ValueError(f"{value!r} contains a line break or NUL and cannot be written to a makefile")
    quoted = shlex.quote(value).replace("$", "$$")
    # make halves a run of backslashes before `#`; an odd count leaves a literal `#`.
    return re.sub(r"(\\*)#", lambda m: "\\" * (2 * len(m.group(1)) + 1) + "#", quoted)


def _assign(name: str, value: str) -> str:
    return f"{name} := {value}" if value else f"{name} :="


def _opt(value: Any) -> str:
    return "" if value is None else mk_quote(str(value))


# ---------------------------------------------------------------------------
# Per-module tuning (workspace/build/params.json)
# ---------------------------------------------------------------------------

PARAM_TYPES: dict[str, type] = {
    "eva_slevel": int,
    "eva_taint": bool,
    "eva_timeout": int,
    "fuzz_budget": int,
    "fuzz_max_time": int,
    "fuzz_dict": str,
}


def default_params(profile: str) -> dict:
    return {
        "eva_slevel": DEFAULT_EVA_SLEVEL,
        "eva_taint": False,
        "eva_timeout": None,
        "fuzz_budget": FUZZ_BUDGET_BY_PROFILE.get(profile, FUZZ_BUDGET_BY_PROFILE[DEFAULT_PROFILE]),
        "fuzz_max_time": None,
        "fuzz_dict": None,
    }


def _param_problem(key: str, value: Any) -> str | None:
    kind = PARAM_TYPES.get(key)
    if kind is None:
        return "unknown parameter"
    if kind is bool:
        return None if isinstance(value, bool) else "must be true or false"
    if kind is int:
        if isinstance(value, bool) or not isinstance(value, int):
            return "must be an integer"
        if key == "eva_slevel":
            return None if 0 <= value <= 1_000_000 else "must be between 0 and 1000000"
        return None if value > 0 else "must be positive"
    if not isinstance(value, str) or not value or value.startswith("-") or any(c in value for c in "\n\r\0"):
        return "must be a file path (not empty, not starting with '-', no line breaks)"
    return None


def load_params(run_dir: Path | str = ".") -> dict:
    """The validated params document; ArtifactError when it is malformed."""
    doc = load_json_optional(Path(run_dir) / PARAMS_JSON, None)
    if doc is None:
        return {"version": 1, "modules": {}}
    if not isinstance(doc, dict) or not isinstance(doc.get("modules", {}), dict):
        raise ArtifactError(f"{PARAMS_JSON}: expected an object with a 'modules' object")
    modules: dict[str, dict] = {}
    for name, entry in doc.get("modules", {}).items():
        if not isinstance(entry, dict):
            raise ArtifactError(f"{PARAMS_JSON}: modules.{name} must be an object")
        for key, value in entry.items():
            problem = _param_problem(key, value)
            if problem:
                raise ArtifactError(f"{PARAMS_JSON}: modules.{name}.{key} {problem}")
        modules[str(name)] = dict(entry)
    return {"version": 1, "modules": modules}


def effective_params(params_doc: dict, module: str, profile: str) -> dict:
    params = default_params(profile)
    params.update(params_doc.get("modules", {}).get(module, {}))
    return params


# ---------------------------------------------------------------------------
# Module plan
# ---------------------------------------------------------------------------


@dataclass
class ModulePlan:
    name: str
    tier: str
    fuzz: bool
    eva: bool
    entry_fn: str | None
    sources: list[str]
    source_origin: str  # sidecar | include_source | dag
    base_cppflags: list[str]  # the sidecar's, as every other consumer uses them (WP, guardrails)
    cppflags: list[str]  # build, campaign and Eva: base_cppflags plus the ACSL template headers
    ldflags: list[str]
    params: dict
    dag_cppflags_missing: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_json(self) -> dict:
        return {
            "tier": self.tier,
            "fuzz": self.fuzz,
            "eva": self.eva,
            "entry_fn": self.entry_fn,
            "sources": self.sources,
            "source_origin": self.source_origin,
            "cppflags": shlex.join(self.cppflags),
            "ldflags": shlex.join(self.ldflags),
            "dag_cppflags_missing": self.dag_cppflags_missing,
            "params": self.params,
            "warnings": self.warnings,
        }


@dataclass
class Plan:
    run_dir: Path
    profile: str
    acsl_dir: str
    dag_present: bool
    dag_modules: dict[str, dict]
    sidecars: set[str]
    params_doc: dict
    seed_scope_args: str | None  # None: a scope path cannot be written to the makefile
    modules: dict[str, ModulePlan] = field(default_factory=dict)
    excluded: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def fuzz_modules(self) -> list[str]:
        return [name for name, mod in self.modules.items() if mod.fuzz]

    @property
    def eva_modules(self) -> list[str]:
        return [name for name, mod in self.modules.items() if mod.eva]

    def expected(self, kind: str) -> dict[str, str]:
        """
        Modules that should have a `kind` ("fuzz" or "eva") report, mapped to the reason a
        missing one gets in its stub: every module the DAG schedules for that phase, except Tier 3
        modules without a harness (they are deferred by design).
        """
        flag = "run_eacsl_fuzz" if kind == "fuzz" else "run_eva"
        out: dict[str, str] = {}
        for name, dag_mod in sorted(self.dag_modules.items()):
            if not dag_mod.get(flag) or not MODULE_RE.match(name):
                continue
            if name in self.modules:
                out[name] = f"{kind}-{name} produced no report"
            elif str(dag_mod.get("tier") or "").startswith("Tier 3") and name not in self.sidecars:
                continue
            else:
                out[name] = f"excluded from the Make phases: {self.excluded.get(name, 'not runnable')}"
        return out

    def wp_cppflags_for(self, module: str | None) -> tuple[list[str] | None, str]:
        """
        cppflags of any ledger module for the WP sweep: the sidecar's, exactly as the parent
        re-check proved the merged function with (`-I.` without a sidecar), or (None, reason).
        """
        if module in self.modules:
            return self.modules[module].base_cppflags, ""
        try:
            return _module_base_cppflags(self.run_dir, module or ""), ""
        except _Excluded as exc:
            return None, str(exc)

    def summary(self) -> dict:
        return {
            "profile": self.profile,
            "dag": "present" if self.dag_present else "missing",
            "fuzz_modules": self.fuzz_modules,
            "eva_modules": self.eva_modules,
            "modules": {name: mod.to_json() for name, mod in self.modules.items()},
            "excluded": dict(self.excluded),
            "warnings": list(self.warnings),
            "errors": list(self.errors),
        }


def resolve_templates_dir() -> Path:
    if CONTAINER_TEMPLATES_DIR.is_dir():
        return CONTAINER_TEMPLATES_DIR
    return SCRIPTS_DIR.parent / "templates"


def normalize_source(raw: str, run_dir: Path) -> str:
    """Path of a slice source as the tools see it from the run directory (sidecar or DAG form)."""
    src = raw.replace("\\", "/").strip()
    if src.startswith("/framac-run/"):
        src = src[len("/framac-run/") :]
    elif src.startswith("/target/"):
        src = f"{WORK_DIR}/{src[len('/target/') :]}"
    while src.startswith("./"):
        src = src[2:]
    if src.startswith(("/", "workspace/")):
        return src
    # Target-relative (DAG required_sources, most sidecars): the overlay copy in workspace/work.
    if (run_dir / WORK_DIR / src).is_file() or not (run_dir / src).is_file():
        return f"{WORK_DIR}/{src}"
    return src


def _module_sources(run_dir: Path, name: str, sidecar: dict, dag_mod: dict) -> tuple[list[str], str]:
    harness_c = f"{HARNESS_DIR}/harness_{name}.c"
    if sidecar.get("include_source"):
        return [harness_c], "include_source"  # the harness #includes the module's .c files
    raw, origin = sidecar.get("sources"), "sidecar"
    if not raw:
        raw, origin = dag_mod.get("required_sources") or [], "dag"
    if isinstance(raw, str):
        raw = [raw]
    sources: list[str] = []
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, str) or not item.strip():
            continue
        src = normalize_source(item, run_dir)
        if PurePosixPath(src).name != f"harness_{name}.c" and src not in sources:
            sources.append(src)
    return [*sources, harness_c], origin


def _load_sidecar(run_dir: Path, name: str) -> dict | None:
    path = run_dir / HARNESS_DIR / f"harness_{name}.json"
    if not path.is_file():
        return None
    try:
        sidecar = load_json_strict(path)
    except ArtifactError as exc:
        raise _Excluded(f"harness sidecar unreadable: {exc}") from None
    if not isinstance(sidecar, dict):
        raise _Excluded("harness sidecar is not a JSON object")
    return sidecar


def _module_base_cppflags(run_dir: Path, name: str, sidecar: dict | None = None) -> list[str]:
    """
    The sidecar's cppflags (`-I.` when it has none), allowlist-checked. The sidecar is the single
    source of truth: prover briefs, the parent re-check and replay-candidates use the same flags,
    so Make builds hit their cache entries and the WP sweep re-proves what was merged.
    """
    if sidecar is None and MODULE_RE.match(name or ""):
        sidecar = _load_sidecar(run_dir, name)
    try:
        tokens = split_flags((sidecar or {}).get("cppflags") or None, "-I.")
    except ValueError as exc:
        raise _Excluded(f"cppflags cannot be parsed: {exc}") from None
    problems = check_flags(tokens)
    if problems:
        raise _Excluded("flags outside the build allowlist: " + "; ".join(f"sidecar cppflags: {p}" for p in problems))
    return tokens


def _plan_module(plan: Plan, name: str, dag_mod: dict) -> ModulePlan:
    fuzz, eva = bool(dag_mod.get("run_eacsl_fuzz")), bool(dag_mod.get("run_eva"))
    if not MODULE_RE.match(name):
        raise _Excluded("module name cannot be used in make targets and report paths")
    if not (fuzz or eva):
        raise _Excluded("the DAG schedules neither fuzzing nor Eva (run_eacsl_fuzz and run_eva are false)")
    sidecar = _load_sidecar(plan.run_dir, name)
    if sidecar is None:
        raise _Excluded(f"no harness sidecar ({HARNESS_DIR}/harness_{name}.json)")
    if not (plan.run_dir / HARNESS_DIR / f"harness_{name}.c").is_file():
        raise _Excluded(f"harness source {HARNESS_DIR}/harness_{name}.c is missing")

    sources, origin = _module_sources(plan.run_dir, name, sidecar, dag_mod)
    for src in sources:
        if src.startswith("-"):
            raise _Excluded(f"source {src!r} looks like an option")
    base = _module_base_cppflags(plan.run_dir, name, sidecar)
    try:
        ldflags = split_flags(sidecar.get("ldflags"), "")
    except ValueError as exc:
        raise _Excluded(f"ldflags cannot be parsed: {exc}") from None
    problems = check_flags(ldflags)
    if problems:
        raise _Excluded("flags outside the build allowlist: " + "; ".join(f"ldflags: {p}" for p in problems))
    try:
        dag_flags = split_flags(dag_mod.get("cppflags"), "")
    except ValueError:
        dag_flags = []

    mod = ModulePlan(
        name=name,
        tier=str(dag_mod.get("tier") or "unclassified"),
        fuzz=fuzz,
        eva=eva,
        entry_fn=sidecar.get("entry_fn") if isinstance(sidecar.get("entry_fn"), str) else None,
        sources=sources,
        source_origin=origin,
        base_cppflags=base,
        cppflags=with_acsl(base, plan.acsl_dir),
        ldflags=ldflags,
        params=effective_params(plan.params_doc, name, plan.profile),
        # Discovered by build_callgraph_dag.py but not in the sidecar: what to pass to
        # generate_harness.py --cppflags if the module does not build.
        dag_cppflags_missing=[t for t in dag_flags if t not in _joined_forms(base)],
    )
    missing = [s for s in sources if not (plan.run_dir / s if not s.startswith("/") else Path(s)).is_file()]
    if missing:
        mod.warnings.append("source file(s) not found: " + ", ".join(missing))
    if origin == "dag" and len(sources) == 1:
        mod.warnings.append("no module sources: neither the sidecar nor the DAG lists any")
    try:
        _module_block(mod)
    except ValueError as exc:
        raise _Excluded(str(exc)) from None
    return mod


def build_plan(run_dir: Path | str = ".", templates_dir: Path | str | None = None) -> Plan:
    """Read the DAG, the sidecars, params.json and run-metadata.json (never fails on a missing input)."""
    run_dir = Path(run_dir)
    warnings: list[str] = []
    errors: list[str] = []

    meta: Any = {}
    try:
        meta = load_json_optional(run_dir / "run-metadata.json", {})
    except ArtifactError as exc:
        errors.append(str(exc))
    meta = meta if isinstance(meta, dict) else {}
    if not meta:
        warnings.append(f"run-metadata.json missing: profile defaults to {DEFAULT_PROFILE}")
    profile = meta.get("profile") or DEFAULT_PROFILE
    if profile not in FUZZ_BUDGET_BY_PROFILE:
        warnings.append(f"unknown profile {profile!r}: using {DEFAULT_PROFILE}")
        profile = DEFAULT_PROFILE
    scope_paths = meta.get("scope_paths")
    scope = [s for s in scope_paths if isinstance(s, str)] if isinstance(scope_paths, list) else []
    try:
        seed_scope_args: str | None = " ".join(mk_quote(f"--scope={s}") for s in scope)
    except ValueError as exc:
        seed_scope_args = None
        errors.append(f"run-metadata.json scope_paths: {exc}")

    try:
        params_doc = load_params(run_dir)
    except ArtifactError as exc:
        errors.append(str(exc))
        params_doc = {"version": 1, "modules": {}}

    dag_modules: dict[str, dict] = {}
    dag_path = run_dir / DAG_JSON
    if dag_path.is_file():
        try:
            dag = load_json_strict(dag_path)
            mods = dag.get("modules") if isinstance(dag, dict) else None
            if not isinstance(mods, dict):
                raise ArtifactError(f"{DAG_JSON} has no 'modules' object")
            dag_modules = {str(k): v for k, v in mods.items() if isinstance(v, dict)}
        except ArtifactError as exc:
            errors.append(f"callgraph DAG unusable: {exc}")
    else:
        warnings.append(f"{DAG_JSON} missing: no module targets until slice-init has run")

    harness_dir = run_dir / HARNESS_DIR
    sidecars = (
        {p.name[len("harness_") : -len(".json")] for p in harness_dir.glob("harness_*.json")}
        if harness_dir.is_dir()
        else set()
    )
    for name in sorted(sidecars - set(dag_modules)):
        if dag_modules:
            warnings.append(f"harness sidecar for {name!r} ignored: no such module in the DAG")

    templates = str(templates_dir) if templates_dir is not None else resolve_templates_dir().as_posix()
    plan = Plan(
        run_dir=run_dir,
        profile=profile,
        acsl_dir=templates.replace("\\", "/").rstrip("/") + "/acsl",
        dag_present=bool(dag_modules) or dag_path.is_file(),
        dag_modules=dag_modules,
        sidecars=sidecars,
        params_doc=params_doc,
        seed_scope_args=seed_scope_args,
        warnings=warnings,
        errors=errors,
    )
    for name in sorted(dag_modules):
        try:
            plan.modules[name] = _plan_module(plan, name, dag_modules[name])
        except _Excluded as exc:
            plan.excluded[name] = str(exc)
    for name in sorted(set(params_doc["modules"]) - set(dag_modules)):
        if dag_modules:
            warnings.append(f"params.json tunes {name!r}, which is not a DAG module")
    return plan


def module_build_spec(module: str, run_dir: Path | str = ".") -> dict:
    """
    Sources, cppflags and ldflags of a runnable module's fuzz build, exactly as the Makefile's
    build and fuzz recipes pass them (other builders of the same binary should use this, so their
    builds share the cache entry). ValueError when the module cannot run from Make.
    """
    plan = build_plan(run_dir)
    mod = plan.modules.get(module)
    if mod is None:
        raise ValueError(f"module {module!r} is not runnable: {plan.excluded.get(module, 'not in the DAG')}")
    return {"sources": list(mod.sources), "cppflags": shlex.join(mod.cppflags), "ldflags": shlex.join(mod.ldflags)}


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

MAKEFILE_TEXT = """\
# Generated by pipeline_make.py gen; do not edit (`pipeline_make.py run` regenerates it).
# From the run directory: python3 /opt/framac-pipeline/scripts/pipeline_make.py run <targets...>
S ?= /opt/framac-pipeline/scripts
PIPELINE_BUILD_DIR := $(patsubst %/,%,$(dir $(lastword $(MAKEFILE_LIST))))
include $(PIPELINE_BUILD_DIR)/modules.mk
include $(S)/../templates/pipeline.mk
"""


def _module_block(mod: ModulePlan) -> list[str]:
    n, p = mod.name, mod.params
    return [
        f"# {n}",
        _assign(f"SOURCES_{n}", " ".join(mk_quote(s) for s in mod.sources)),
        _assign(f"CPPFLAGS_{n}", mk_quote(shlex.join(mod.cppflags))),
        _assign(f"LDFLAGS_{n}", mk_quote(shlex.join(mod.ldflags))),
        _assign(f"EVA_SLEVEL_{n}", mk_quote(str(p["eva_slevel"]))),
        _assign(f"EVA_TAINT_{n}", "1" if p["eva_taint"] else ""),
        _assign(f"EVA_TIMEOUT_{n}", _opt(p["eva_timeout"])),
        _assign(f"FUZZ_BUDGET_{n}", mk_quote(str(p["fuzz_budget"]))),
        _assign(f"FUZZ_MAX_TIME_{n}", _opt(p["fuzz_max_time"])),
        _assign(f"FUZZ_DICT_{n}", _opt(p["fuzz_dict"])),
    ]


def render_modules_mk(plan: Plan) -> str:
    if plan.seed_scope_args is None:
        # Fails the `seed` recipe only, when it expands the variable.
        scope_line = "SEED_SCOPE_ARGS = $(error scope_paths in run-metadata.json cannot be passed through make)"
    else:
        scope_line = _assign("SEED_SCOPE_ARGS", plan.seed_scope_args)
    lines = [
        "# Generated by pipeline_make.py gen from the callgraph DAG, the harness sidecars, params.json",
        "# and run-metadata.json; do not edit (`pipeline_make.py run` regenerates it). Every value is",
        "# a shell word (shlex.quote) with $ and # escaped for make.",
        _assign("PROFILE", plan.profile),
        _assign("MODULES", " ".join(plan.modules)),
        _assign("FUZZ_MODULES", " ".join(plan.fuzz_modules)),
        _assign("EVA_MODULES", " ".join(plan.eva_modules)),
        scope_line,
    ]
    for mod in plan.modules.values():
        lines += ["", *_module_block(mod)]
    return "\n".join(lines) + "\n"


def _write_if_changed(path: Path, text: str) -> bool:
    data = text.encode()
    try:
        if path.read_bytes() == data:
            return False
    except OSError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp_")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return True


def _generate(
    run_dir: Path,
    templates_dir: Path | str | None = None,
    private_dir: Path | None = None,
) -> tuple[Plan, bool]:
    plan = build_plan(run_dir, templates_dir)
    modules_text = render_modules_mk(plan)
    changed = _write_if_changed(run_dir / MODULES_MK, modules_text)
    changed = _write_if_changed(run_dir / MAKEFILE, MAKEFILE_TEXT) or changed
    if private_dir is not None:
        # Write the stage's private copy directly from memory so a concurrent `gen` or `params set`
        # on workspace/build/ cannot mutate `modules.mk` between generation and `make` reading it.
        _write_if_changed(private_dir / "modules.mk", modules_text)
        _write_if_changed(private_dir / "Makefile", MAKEFILE_TEXT)
    return plan, changed


def generate(run_dir: Path | str = ".", templates_dir: Path | str | None = None) -> dict:
    """Write workspace/build/{Makefile,modules.mk} and return the module plan."""
    plan, changed = _generate(Path(run_dir), templates_dir)
    return {"ok": not plan.errors, "makefile": MAKEFILE, "modules_mk": MODULES_MK, "changed": changed, **plan.summary()}


# ---------------------------------------------------------------------------
# params set / show
# ---------------------------------------------------------------------------

_CLEARED_BY_ZERO = ("eva_timeout", "fuzz_budget", "fuzz_max_time")


def params_set(run_dir: Path | str = ".", module: str = "", reset: bool = False, **updates: Any) -> dict:
    """
    Update one module's overrides. 0 clears eva_timeout, fuzz_budget (back to the profile
    default) and fuzz_max_time; an empty fuzz_dict clears the dictionary; `reset` drops every
    earlier override first. ValueError on an invalid value.
    """
    run_dir = Path(run_dir)
    if not MODULE_RE.match(module or ""):
        raise ValueError(f"invalid module name {module!r}")
    unknown = sorted(set(updates) - set(PARAM_TYPES))
    if unknown:
        raise ValueError(f"unknown parameter(s): {', '.join(unknown)}")
    with run_lock("params", run_dir=run_dir):
        doc = load_params(run_dir)
        entry = {} if reset else dict(doc["modules"].get(module, {}))
        for key, value in updates.items():
            if value is None:
                continue
            if (key in _CLEARED_BY_ZERO and value == 0) or (key == "fuzz_dict" and value == ""):
                entry.pop(key, None)
                continue
            problem = _param_problem(key, value)
            if problem:
                raise ValueError(f"{key} {problem}")
            entry[key] = value
        if entry:
            doc["modules"][module] = entry
        else:
            doc["modules"].pop(module, None)
        atomic_write_json(run_dir / PARAMS_JSON, doc)
    plan = build_plan(run_dir)
    warnings = []
    if plan.dag_modules and module not in plan.dag_modules:
        warnings.append(f"{module!r} is not a module of the callgraph DAG")
    if (
        entry.get("fuzz_dict")
        and not (run_dir / entry["fuzz_dict"]).is_file()
        and not Path(entry["fuzz_dict"]).is_file()
    ):
        warnings.append(f"fuzz dictionary {entry['fuzz_dict']!r} does not exist (yet)")
    return {
        "ok": True,
        "module": module,
        "overrides": entry,
        "effective": effective_params(doc, module, plan.profile),
        "applies": "on the next `pipeline_make.py run` (or `gen`)",
        "warnings": warnings,
    }


def params_show(run_dir: Path | str = ".", module: str | None = None) -> dict:
    plan = build_plan(run_dir)
    names = sorted(set(plan.dag_modules) | set(plan.params_doc["modules"]))
    if module is not None:
        names = [module]
    return {
        "ok": not plan.errors,
        "profile": plan.profile,
        "defaults": default_params(plan.profile),
        "modules": {
            name: {
                "effective": effective_params(plan.params_doc, name, plan.profile),
                "overrides": plan.params_doc["modules"].get(name, {}),
                "runnable": name in plan.modules,
                "in_dag": name in plan.dag_modules,
            }
            for name in names
        },
        "errors": plan.errors,
    }


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------

# Targets run in pipeline order: each stage is one make invocation (parallel inside), so that,
# for example, `run fuzz eva ingest` ingests only after every campaign and Eva run has finished.
STAGE_OF_TARGET = {
    "slice-init": 0,
    "seed": 1,
    "build": 2,
    "selftest": 2,
    "fuzz": 2,
    "eva": 2,
    "ingest": 3,
    "replay": 3,
    "wp-queue": 3,
    "wp-sweep": 4,
    "report": 5,
}
MODULE_TARGET_PREFIXES = ("build-", "fuzz-", "eva-", "module-")
_TARGET_OUTPUTS = {
    "slice-init": DAG_JSON,
    "seed": LEDGER_JSON,
    "selftest": SELFTEST_JSON,
    "ingest": INGESTED_JSON,
    "replay": "workspace/reports/replay/index.json",
    "wp-queue": "workspace/reports/wp_queue.json",
    "wp-sweep": f"{SWEEP_DIR}/summary.json",
    "report": "REPORT.md",
}
_MAKE_FAILED_RE = re.compile(r"^\S*make(?:\[\d+\])?: \*\*\* \[(?:[^\]]*?:\d+: )?(?P<target>[^\]]+)\] ")
_MAKE_NOT_REMADE_RE = re.compile(r"Target '(?P<target>[^']+)' not remade because of errors")

# (cmd, cwd, line_sink) -> returncode
MakeRunner = Callable[[list[str], Path, Callable[[str], None]], int]


def _stage(target: str) -> int | None:
    if target in STAGE_OF_TARGET:
        return STAGE_OF_TARGET[target]
    if target.startswith(MODULE_TARGET_PREFIXES) and target.partition("-")[2]:
        return 2
    return None


def _target_problem(target: str, plan: Plan) -> str | None:
    if plan.errors and target != "slice-init":
        return "; ".join(plan.errors)
    if target in STAGE_OF_TARGET:
        return None
    kind, _, mod = target.partition("-")
    allowed = {
        "build": plan.fuzz_modules,
        "fuzz": plan.fuzz_modules,
        "eva": plan.eva_modules,
        "module": list(plan.modules),
    }[kind]
    if mod in allowed:
        return None
    if mod in plan.excluded:
        return f"module {mod} is excluded: {plan.excluded[mod]}"
    if mod in plan.modules:
        return f"module {mod} has no {kind} target: the DAG does not schedule it"
    return f"unknown module {mod!r}"


def _target_nodes(target: str, plan: Plan) -> list[str]:
    if target == "build":
        return [f"build-{m}" for m in plan.fuzz_modules]
    if target == "fuzz":
        return [f"fuzz-{m}" for m in plan.fuzz_modules]
    if target == "eva":
        return [f"eva-{m}" for m in plan.eva_modules]
    return [target]


def _node_deps(node: str, plan: Plan) -> list[str]:
    """Prerequisites as declared in templates/pipeline.mk (to tell skipped from failed)."""
    kind, _, mod = node.partition("-")
    if kind == "fuzz" and mod:
        return ["selftest", f"build-{mod}"]
    if kind == "module":
        deps = [f"fuzz-{mod}"] if mod in plan.fuzz_modules else []
        return deps + ([f"eva-{mod}"] if mod in plan.eva_modules else [])
    if node in ("replay", "wp-queue"):
        return ["ingest"]
    return []


def _node_output(node: str) -> str | None:
    if node in _TARGET_OUTPUTS:
        return _TARGET_OUTPUTS[node]
    kind, _, mod = node.partition("-")
    return {
        "build": f"{BUILD_DIR}/{mod}.build.json",
        "fuzz": f"{REPORT_DIRS['fuzz']}/{mod}.json",
        "eva": f"{REPORT_DIRS['eva']}/{mod}.json",
        "module": INGESTED_JSON,
    }.get(kind)


def _output_state(run_dir: Path, rel: str) -> str | None:
    """Content digest of an expected output (None when absent): `updated` means new content."""
    try:
        return hashlib.sha256((run_dir / rel).read_bytes()).hexdigest()
    except OSError:
        return None


def _report_brief(path: Path) -> dict:
    """`status` of a JSON report (or `ok` for the selftest), for the run summary."""
    if path.suffix != ".json" or not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {"report_status": "unreadable"}
    if not isinstance(data, dict):
        return {}
    out: dict = {}
    if "status" in data:
        out["report_status"] = data["status"]
    elif isinstance(data.get("ok"), bool):
        out["report_status"] = "ok" if data["ok"] else "failed"
    if data.get("stub"):
        out["stub"] = True
    return out


def _subprocess_make_runner(cmd: list[str], cwd: Path, sink: Callable[[str], None]) -> int:
    with subprocess.Popen(
        cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace"
    ) as proc:
        assert proc.stdout is not None
        for line in proc.stdout:
            sink(line.rstrip("\n"))
        return proc.wait()


_default_make_runner = _subprocess_make_runner


def _private_make_runner(
    priv_makefile_or_text: Path | str,
    modules_text_or_runner: str | MakeRunner | None = None,
    base_runner: MakeRunner | None = None,
) -> MakeRunner:
    """Redirect `make -f workspace/build/Makefile` to a stage-private Makefile copy outside the run dir."""
    if isinstance(priv_makefile_or_text, str) and isinstance(modules_text_or_runner, str):
        makefile_text = priv_makefile_or_text
        modules_text = modules_text_or_runner

        def run_ephemeral(cmd: list[str], cwd: Path, sink: Callable[[str], None]) -> int:
            eff_runner = base_runner or _default_make_runner
            with tempfile.TemporaryDirectory(prefix="framac-make-") as tmp:
                priv_dir = Path(tmp)
                priv_mk = priv_dir / "Makefile"
                _write_if_changed(priv_dir / "modules.mk", modules_text)
                _write_if_changed(priv_mk, makefile_text)
                actual = list(cmd)
                if "-f" in actual:
                    idx = actual.index("-f")
                    if idx + 1 < len(actual):
                        actual[idx + 1] = str(priv_mk)
                return eff_runner(actual, cwd, sink)

        return run_ephemeral

    priv_makefile = Path(priv_makefile_or_text)
    runner_arg = modules_text_or_runner if callable(modules_text_or_runner) else base_runner

    def run(cmd: list[str], cwd: Path, sink: Callable[[str], None]) -> int:
        eff_runner = runner_arg or _default_make_runner
        actual = list(cmd)
        if "-f" in actual:
            idx = actual.index("-f")
            if idx + 1 < len(actual):
                actual[idx + 1] = str(priv_makefile)
        return eff_runner(actual, cwd, sink)

    return run


def _make_jobs() -> int:
    """make -j: this container's own CPUs (its lease, re-read from the cgroup), not the node's pool."""
    from resources import job_budget

    return max(1, int(job_budget().cpus))


def _run_stage(make_runner: MakeRunner, cmd: list[str], run_dir: Path, log) -> tuple[int, set[str], list[str]]:
    failed: set[str] = set()
    tail: deque[str] = deque(maxlen=40)

    def sink(line: str) -> None:
        print(line, file=sys.stderr, flush=True)
        log.write(line + "\n")
        tail.append(line)
        m = _MAKE_FAILED_RE.match(line) or _MAKE_NOT_REMADE_RE.search(line)
        if m:
            failed.add(m.group("target"))

    log.write("$ " + shlex.join(cmd) + "\n")
    rc = make_runner(cmd, run_dir, sink)
    log.flush()
    return rc, failed, list(tail)


def _node_status(node: str, plan: Plan, run_dir: Path, failed: set[str], cache: dict[str, str]) -> str:
    if node not in cache:
        if node in failed:
            status = "failed"
        elif any(
            _node_status(d, plan, run_dir, failed, cache) in ("failed", "skipped") for d in _node_deps(node, plan)
        ):
            status = "skipped"  # a prerequisite failed, so make never ran this recipe
        else:
            out = _node_output(node)
            status = "ok" if out is None or (run_dir / out).exists() else "no_output"
        cache[node] = status
    return cache[node]


def run_targets(
    targets: list[str],
    run_dir: Path | str = ".",
    jobs: int | None = None,
    make_runner: MakeRunner | None = None,
    templates_dir: Path | str | None = None,
) -> tuple[int, dict]:
    """
    Run make targets from the run directory, stage by stage (STAGE_OF_TARGET), regenerating
    modules.mk before each stage. Returns (exit code, summary): per target the status of each
    module recipe (ok, failed, skipped after a failed prerequisite, no_output), its expected
    output, whether this run changed it, and the report's own status.
    """
    run_dir = Path(run_dir)
    if not (run_dir / MAKEFILE).is_file():
        return 2, {
            "ok": False,
            "error": f"{MAKEFILE} not found: run `pipeline_make.py gen` first, from the run directory",
        }
    targets = list(dict.fromkeys(targets))
    unknown = [t for t in targets if _stage(t) is None]
    if not targets or unknown:
        known = ", ".join([*STAGE_OF_TARGET, *(p + "<mod>" for p in MODULE_TARGET_PREFIXES)])
        return 2, {"ok": False, "error": f"unknown target(s) {unknown or '(none given)'}; targets: {known}"}
    make_bin = "make"
    use_private_makefile = make_runner is None
    if make_runner is None:
        found = shutil.which("make")
        if found is None:
            return 2, {
                "ok": False,
                "error": "make not found: `pipeline_make.py run` runs inside the framac-pipeline container",
            }
        make_bin, make_runner = found, _subprocess_make_runner
    jobs = max(1, int(jobs or _make_jobs()))

    stamp = f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{os.getpid()}"
    log_rel = f"{LOG_DIR}/run-{stamp}.log"
    (run_dir / LOG_DIR).mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    summary: dict = {"ok": True, "targets": {}, "stages": [], "jobs": jobs, "log": log_rel}
    with contextlib.ExitStack() as stack:
        priv_dir: Path | None = None
        priv_makefile: Path | None = None
        if use_private_makefile:
            priv_dir = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="framac-make-")))
            priv_makefile = priv_dir / "Makefile"
            make_runner = _private_make_runner(priv_makefile, make_runner)
        log = stack.enter_context(open(run_dir / log_rel, "w", encoding="utf-8", newline="\n"))
        stages = sorted({s for t in targets if (s := _stage(t)) is not None})
        for stage in stages:
            stage_targets = [t for t in targets if _stage(t) == stage]
            plan, _ = _generate(run_dir, templates_dir, private_dir=priv_dir)
            summary.update(excluded=plan.excluded, warnings=plan.warnings)
            runnable = []
            for target in stage_targets:
                problem = _target_problem(target, plan)
                if problem:
                    summary["targets"][target] = {"status": "refused", "error": problem}
                    summary["ok"] = False
                else:
                    runnable.append(target)
            if not runnable:
                continue
            nodes = {n for t in runnable for n in _target_nodes(t, plan)}
            outputs = {n: _node_output(n) for n in nodes}
            before = {out: _output_state(run_dir, out) for out in outputs.values() if out}
            eff_makefile = str(priv_makefile) if priv_makefile is not None else MAKEFILE
            cmd = [
                make_bin,
                "-f",
                eff_makefile,
                f"-j{jobs}",
                "-k",
                "--output-sync=target",
                f"S={SCRIPTS_DIR.as_posix()}",
                *runnable,
            ]
            rc, failed, tail = _run_stage(make_runner, cmd, run_dir, log)
            if rc != 0 and not failed:
                failed = set(runnable) | nodes  # make stopped without naming a target (see the log)
            stage_info: dict = {"targets": runnable, "command": cmd, "rc": rc}
            if rc != 0:
                stage_info["log_tail"] = tail
                summary["ok"] = False
            summary["stages"].append(stage_info)
            cache: dict[str, str] = {}
            for target in runnable:
                entries = {}
                for node in _target_nodes(target, plan):
                    info: dict = {"status": _node_status(node, plan, run_dir, failed, cache)}
                    out = outputs.get(node) or _node_output(node)
                    if out:
                        after = _output_state(run_dir, out)
                        info.update(
                            output=out, exists=after is not None, updated=after is not None and after != before.get(out)
                        )
                        info.update(_report_brief(run_dir / out))
                    entries[node] = info
                bad = sorted(n for n, e in entries.items() if e["status"] in ("failed", "skipped"))
                result: dict = {"status": "failed" if bad or target in failed else "ok", "nodes": entries}
                if not entries:
                    result["note"] = "no runnable module"
                summary["targets"][target] = result
    summary["elapsed_s"] = round(time.monotonic() - started, 1)
    summary["ok"] = summary["ok"] and all(t.get("status") == "ok" for t in summary["targets"].values())
    try:
        atomic_write_json(run_dir / f"{LOG_DIR}/run-{stamp}.json", summary)
    except OSError:
        pass
    return (0 if summary["ok"] else 1), summary


# ---------------------------------------------------------------------------
# ingest
# ---------------------------------------------------------------------------

# (script name, args) -> (returncode, combined output); runs from the run directory.
ScriptRunner = Callable[[str, list[str]], tuple[int, str]]


def _script_runner(run_dir: Path) -> ScriptRunner:
    def run(script: str, args: list[str]) -> tuple[int, str]:
        proc = subprocess.run(
            [sys.executable, str(SCRIPTS_DIR / script), *args],
            cwd=run_dir,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")

    return run


def _json_or_tail(text: str) -> Any:
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return {"output_tail": (text or "")[-2000:]}


def _object_problem(data: bytes) -> str | None:
    try:
        obj = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return f"malformed JSON: {exc}"
    return None if isinstance(obj, dict) else "not a JSON object"


def _stub(kind: str, module: str, reason: str) -> dict:
    meta = {"stub": True, "generated_by": "pipeline_make.py ingest", "generated_at": utc_now()}
    if kind == "fuzz":
        return {"mode": "campaign", "module": module, "status": "not_run", "reason": reason, **meta}
    return {"status": "analysis_error", "module": module, "reason": "not_run", "detail": reason, **meta}


def _load_ingested(run_dir: Path) -> dict:
    state = load_json_optional(run_dir / INGESTED_JSON, {"version": 1, "fuzz": {}, "eva": {}})
    if not isinstance(state, dict) or not all(isinstance(state.get(k, {}), dict) for k in REPORT_DIRS):
        # Re-ingesting everything would re-open candidates a verifier already closed.
        raise ArtifactError(f"{INGESTED_JSON} is malformed; repair or remove it deliberately")
    for kind in REPORT_DIRS:
        state.setdefault(kind, {})
    return state


def _pending_reports(
    run_dir: Path, kind: str, module: str | None, seen: dict
) -> tuple[list[tuple[str, str]], int, list[dict]]:
    report_dir = run_dir / REPORT_DIRS[kind]
    if module is not None:
        paths = [report_dir / f"{module}.json"]
    else:
        paths = sorted(report_dir.glob("*.json")) if report_dir.is_dir() else []
    pending: list[tuple[str, str]] = []
    known = 0
    bad: list[dict] = []
    for path in paths:
        if not path.is_file():
            continue
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        rel = f"{REPORT_DIRS[kind]}/{path.name}"
        if digest in seen:
            known += 1
            continue
        problem = _object_problem(data)
        if problem:
            bad.append({"report": rel, "error": problem})
        else:
            pending.append((rel, digest))
    return pending, known, bad


def ingest(
    run_dir: Path | str = ".",
    module: str | None = None,
    runner: ScriptRunner | None = None,
    plan: Plan | None = None,
) -> dict:
    """
    Ingest every fuzz and Eva report whose digest is not in state/ingested.json, fuzz first (crash
    candidates must exist before Eva may mark a unit covered), then validate the run directory.
    An expected module without a report first gets a stub: fuzz `not_run`, Eva `analysis_error`
    with reason `not_run`. A malformed expected report is moved aside and stubbed the same way.
    """
    run_dir = Path(run_dir)
    if module is not None and not MODULE_RE.match(module):
        raise PipelineMakeError(f"invalid module name {module!r}")
    runner = runner or _script_runner(run_dir)
    plan = plan or build_plan(run_dir)
    result: dict = {
        "ok": True,
        "module": module,
        "stubs": [],
        "quarantined": [],
        "malformed": [],
        "ingested": {"fuzz": [], "eva": []},
        "already_ingested": {"fuzz": 0, "eva": 0},
        "ledger": {},
        "errors": [],
    }
    with run_lock("ingest", run_dir=run_dir):
        state = _load_ingested(run_dir)
        for kind in ("fuzz", "eva"):
            for mod, reason in plan.expected(kind).items():
                if module is not None and mod != module:
                    continue
                path = run_dir / REPORT_DIRS[kind] / f"{mod}.json"
                if path.is_file():
                    problem = _object_problem(path.read_bytes())
                    if problem is None:
                        continue
                    aside = path.with_name(path.name + ".malformed")
                    os.replace(path, aside)
                    reason = f"report was unusable ({problem}); kept as {REPORT_DIRS[kind]}/{aside.name}"
                    result["quarantined"].append(f"{REPORT_DIRS[kind]}/{aside.name}")
                atomic_write_json(path, _stub(kind, mod, reason))
                result["stubs"].append(f"{REPORT_DIRS[kind]}/{mod}.json")

        for kind in ("fuzz", "eva"):
            pending, known, bad = _pending_reports(run_dir, kind, module, state[kind])
            result["already_ingested"][kind] = known
            result["malformed"] += bad
            if not pending:
                continue
            rc, out = runner("ledger.py", [f"ingest-{kind}", *(rel for rel, _ in pending)])
            result["ledger"][kind] = _json_or_tail(out)
            if rc != 0:
                result["ok"] = False
                result["errors"].append(f"ledger.py ingest-{kind} failed (rc={rc}); nothing recorded for these reports")
                break  # never ingest Eva after a failed fuzz ingestion
            stamp = utc_now()
            for rel, digest in pending:
                state[kind][digest] = {"report": rel, "ingested_at": stamp}
            atomic_write_json(run_dir / INGESTED_JSON, state)
            result["ingested"][kind] = [rel for rel, _ in pending]

        if cache.shared_mode() == "rw":
            published_corpora: dict[str, int] = {}
            target_modules = (
                [module]
                if module is not None
                else sorted(set(plan.fuzz_modules) | {Path(rel).stem for rel in result["ingested"].get("fuzz", [])})
            )
            for mod_name in target_modules:
                c_dirs = [
                    run_dir / "workspace" / "corpus" / mod_name,
                    run_dir / "workspace" / "corpora" / mod_name,
                    run_dir / "workspace" / "scratch" / "fuzz" / mod_name / "corpus",
                    run_dir / "scratch" / "fuzz" / mod_name / "corpus",
                ]
                pub_count = 0
                for cd in c_dirs:
                    if cd.is_dir():
                        pub_count += cache.publish_corpus(mod_name, cd)
                if pub_count > 0:
                    published_corpora[mod_name] = pub_count
            if published_corpora:
                result["published_corpora"] = published_corpora

        rc, out = runner("validate_artifacts.py", ["run-dir", "."])
        result["validate"] = _json_or_tail(out)
        if rc != 0:
            result["ok"] = False
            result["errors"].append("validate_artifacts.py run-dir . failed")
    return result


# ---------------------------------------------------------------------------
# WP sweep
# ---------------------------------------------------------------------------


def sweep_list(run_dir: Path | str = ".") -> tuple[list[dict], list[dict]]:
    """
    The ledger's covered proof units, one entry per (file, function): units whose status is
    `covered` with discharging WP evidence, plus any Eva-covered callee in `callgraph_dag.json`
    called by a WP-covered caller that carries a `valid_under_hyp` assumption. Returns (entries, skipped).
    """
    run_path = Path(run_dir)
    ledger = load_json_optional(run_path / LEDGER_JSON, [])
    if not isinstance(ledger, list):
        raise ArtifactError(f"{LEDGER_JSON} is not a list")
    entries: dict[tuple[str, str], dict] = {}
    eva_covered_by_fn: dict[str, list[dict]] = {}
    vuh_callers: list[tuple[str, str]] = []
    skipped: list[dict] = []
    for unit in ledger:
        if not isinstance(unit, dict) or unit.get("status") != "covered":
            continue
        evidence = unit.get("evidence") or []
        has_wp = any(isinstance(e, dict) and e.get("phase") == "wp" and e.get("discharging") for e in evidence)
        file, function = unit.get("file"), unit.get("function")
        if not has_wp:
            if isinstance(file, str) and isinstance(function, str):
                eva_covered_by_fn.setdefault(function, []).append(unit)
            continue
        if not (
            isinstance(file, str)
            and is_safe_relative_path(file)
            and isinstance(function, str)
            and FUNCTION_RE.match(function)
        ):
            skipped.append({"file": file, "function": function, "reason": "unsafe file path or function name"})
            continue
        entry = entries.setdefault(
            (file, function), {"file": file, "function": function, "module": unit.get("module"), "coverage_ids": []}
        )
        entry["coverage_ids"].append(unit.get("coverage_id"))
        if any(
            isinstance(a, dict) and a.get("kind") in ("valid_under_hyp", "callee_contract_hypothesis")
            for a in (unit.get("assumptions") or [])
        ):
            if (file, function) not in vuh_callers:
                vuh_callers.append((file, function))

    if vuh_callers and eva_covered_by_fn:
        dag = load_json_optional(run_path / DAG_JSON, {})
        dag_fns = dag.get("functions", {}) if isinstance(dag, dict) else {}
        if isinstance(dag_fns, dict) and dag_fns:
            callees_map: dict[tuple[str, str], list[str]] = {}
            callees_by_name: dict[str, list[str]] = {}
            for k, fmeta in dag_fns.items():
                if not isinstance(fmeta, dict):
                    continue
                fn_n = str(fmeta.get("name") or (k.split("#", 1)[-1] if "#" in str(k) else k))
                fn_f = str(fmeta.get("file") or (k.split("#", 1)[0] if "#" in str(k) else ""))
                raw_c = fmeta.get("internal_callees") or fmeta.get("direct_callees") or fmeta.get("callees") or []
                clean_c = [str(c) for c in raw_c if isinstance(c, str) and c]
                if fn_f and fn_n:
                    callees_map[(fn_f, fn_n)] = clean_c
                if fn_n and fn_n not in callees_by_name:
                    callees_by_name[fn_n] = clean_c

            for c_file, c_fn in vuh_callers:
                c_names = callees_map.get((c_file, c_fn)) or callees_by_name.get(c_fn, [])
                for callee_name in c_names:
                    cand_units = eva_covered_by_fn.get(callee_name, [])
                    same_file = [u for u in cand_units if u.get("file") == c_file]
                    for u in same_file or cand_units:
                        uf, ufn = u.get("file"), u.get("function")
                        if not (
                            isinstance(uf, str)
                            and is_safe_relative_path(uf)
                            and isinstance(ufn, str)
                            and FUNCTION_RE.match(ufn)
                        ):
                            continue
                        ent = entries.setdefault(
                            (uf, ufn),
                            {
                                "file": uf,
                                "function": ufn,
                                "module": u.get("module"),
                                "coverage_ids": [],
                                "eva_only": True,
                            },
                        )
                        if u.get("coverage_id") not in ent["coverage_ids"]:
                            ent["coverage_ids"].append(u.get("coverage_id"))

    return [entries[k] for k in sorted(entries)], skipped


def _file_slugs(files: set[str]) -> dict[str, str]:
    by_slug: dict[str, list[str]] = {}
    for f in sorted(files):
        by_slug.setdefault(re.sub(r"[^A-Za-z0-9_.-]+", "_", f), []).append(f)
    slugs = {}
    for slug, group in by_slug.items():
        for f in group:
            # Disambiguate the rare collision (src/a_b.c vs src/a/b.c) with a digest of the path.
            slugs[f] = slug if len(group) == 1 else f"{slug}-{hashlib.sha256(f.encode()).hexdigest()[:8]}"
    return slugs


# (cmd, log path relative to the run dir) -> returncode
SweepRunner = Callable[[list[str], str], int]


def _sweep_runner(run_dir: Path) -> SweepRunner:
    def run(cmd: list[str], log_rel: str) -> int:
        log_path = run_dir / log_rel
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "w", encoding="utf-8") as log:
            return subprocess.run(cmd, cwd=run_dir, stdout=log, stderr=subprocess.STDOUT, check=False).returncode

    return run


def sweep(
    run_dir: Path | str = ".",
    jobs: int | None = None,
    runner: SweepRunner | None = None,
    plan: Plan | None = None,
    script_runner: ScriptRunner | None = None,
) -> dict:
    """
    Re-prove every entry of `sweep_list` on the final work tree with the flags of the parent
    re-check, without the per-run WP cache (--cache-dir off), each as a leased `wp` job of the
    container broker; the pool size comes from resources.recommend(). Writes
    workspace/reports/wp-sweep/. Regressions are ingested into the ledger, so a function whose
    proof no longer holds on the final tree stops counting as covered.
    """
    run_dir = Path(run_dir)
    plan = plan or build_plan(run_dir)
    runner = runner or _sweep_runner(run_dir)
    py, scripts = sys.executable or "python3", SCRIPTS_DIR.as_posix()
    with run_lock("wp-sweep", run_dir=run_dir):
        entries, skipped = sweep_list(run_dir)
        slugs = _file_slugs({e["file"] for e in entries})
        tasks: list[tuple[dict, str, list[str]]] = []
        for e in entries:
            flags, reason = plan.wp_cppflags_for(e["module"])
            if flags is None:
                skipped.append({"file": e["file"], "function": e["function"], "reason": reason})
                continue
            key = f"{slugs[e['file']]}__{e['function']}"
            out_json = f"{SWEEP_DIR}/{key}.json"
            wp_extra_flags = infer_prover_wp_flags(
                run_dir,
                c_file=e["file"],
                function=e["function"],
            )
            cmd = [
                py,
                f"{scripts}/resources.py",
                "run",
                "--class",
                "wp",
                "--key",
                key,
                "--output",
                out_json,
                "--",
                py,
                f"{scripts}/run_wp_function.py",
                "--file",
                f"{WORK_DIR}/{e['file']}",
                "--function",
                e["function"],
                f"--cppflags={shlex.join(flags)}",
                "--cache-dir",
                "off",
                *wp_extra_flags,
                "--sarif",
                # One out-dir per file: run_wp_function names its artifacts after the function only.
                "--out-dir",
                f"{SWEEP_DIR}/work/{slugs[e['file']]}",
                "--out-json",
                out_json,
            ]
            # A report left by an earlier sweep must never be read as this sweep's result.
            (run_dir / out_json).unlink(missing_ok=True)
            tasks.append((e, out_json, cmd))

        rcs: list[int] = []
        if tasks:
            workers = max(1, min(int(jobs or _make_jobs()), len(tasks)))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                rcs = list(pool.map(lambda t: runner(t[2], f"{SWEEP_DIR}/logs/{PurePosixPath(t[1]).stem}.log"), tasks))

        results, regressions, missing, newly_wp_proven = [], [], [], []
        for (e, out_json, _), rc in zip(tasks, rcs, strict=True):
            status = _report_brief(run_dir / out_json).get("report_status") if (run_dir / out_json).is_file() else None
            row = {
                "file": e["file"],
                "function": e["function"],
                "module": e["module"],
                "rc": rc,
                "status": status,
                "report": out_json,
            }
            results.append(row)
            if status is None:
                missing.append(row)
            elif status != "all_proven":
                regressions.append(row)
            elif e.get("eva_only"):
                newly_wp_proven.append(row)
        summary = {
            "ok": not missing,
            "status": "incomplete" if missing else ("regressions" if regressions else "ok"),
            "total": len(tasks),
            "proven": sum(1 for r in results if r["status"] == "all_proven"),
            "regressions": regressions,
            "missing": missing,
            "skipped": skipped,
            "results": results,
            "generated_at": utc_now(),
        }
        s_runner = script_runner or _script_runner(run_dir)
        to_ingest = [*(r["report"] for r in regressions), *(r["report"] for r in newly_wp_proven)]
        if to_ingest:
            # The sweep is the trusted backstop: regressions and newly WP-verified Eva callees reach the ledger.
            rc, out = s_runner("ledger.py", ["ingest-wp", *to_ingest])
            summary["ledger"] = _json_or_tail(out)
            if rc != 0:
                summary["ok"] = False
                summary["ledger_error"] = f"ledger.py ingest-wp failed (rc={rc}); regressions not recorded"
        raw_ledger = load_json_optional(run_dir / LEDGER_JSON, [])
        has_vuh = any(
            isinstance(u, dict)
            and any(
                isinstance(a, dict) and a.get("kind") in ("valid_under_hyp", "callee_contract_hypothesis")
                for a in (u.get("assumptions") or [])
            )
            for u in (raw_ledger if isinstance(raw_ledger, list) else [])
        )
        if has_vuh and summary["ok"]:
            rc_a, out_a = s_runner("ledger.py", ["audit-hypotheses"])
            if rc_a == 0:
                summary["hypothesis_audit"] = _json_or_tail(out_a)
        atomic_write_json(run_dir / SWEEP_DIR / "summary.json", summary)
    return summary


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _normalize_flag_args(argv: list[str]) -> list[str]:
    """`--fuzz-dict -x` would be read as an option by argparse: bind such values with `=`."""
    from framac_common import normalize_flag_args

    return normalize_flag_args(argv, ("--fuzz-dict",))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate and run the Make-driven pipeline phases.")
    parser.add_argument("--run-dir", type=Path, default=Path("."), help="Run directory (default: the cwd)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("gen", help="Write workspace/build/{Makefile,modules.mk} and print the module plan")

    p_params = sub.add_parser("params", help="Per-module tuning in workspace/build/params.json")
    psub = p_params.add_subparsers(dest="params_cmd", required=True)
    p_set = psub.add_parser("set")
    p_set.add_argument("--module", required=True)
    p_set.add_argument("--reset", action="store_true", help="Drop the module's earlier overrides first")
    p_set.add_argument("--eva-slevel", type=int, default=None)
    taint = p_set.add_mutually_exclusive_group()
    taint.add_argument("--eva-taint", dest="eva_taint", action="store_true", help="Add the taint domain")
    taint.add_argument("--no-eva-taint", dest="eva_taint", action="store_false")
    p_set.set_defaults(eva_taint=None)
    p_set.add_argument("--eva-timeout", type=int, default=None, help="Eva wall-clock seconds (0 clears)")
    p_set.add_argument("--fuzz-dict", default=None, help="libFuzzer dictionary, run-relative ('' clears)")
    p_set.add_argument("--fuzz-budget", type=int, default=None, help="Campaign CPU-seconds (0: profile default)")
    p_set.add_argument(
        "--fuzz-max-time", type=int, default=None, help="Campaign wall-clock override in seconds (0 clears)"
    )
    p_show = psub.add_parser("show")
    p_show.add_argument("--module", default=None)

    p_run = sub.add_parser("run", help="Run make targets from the run directory")
    p_run.add_argument("targets", nargs="+")
    p_run.add_argument("--jobs", type=int, default=None, help="Override make -j (default: this container's CPUs)")
    p_ing = sub.add_parser("ingest", help="Ingest new fuzz/Eva reports (fuzz first), then validate")
    p_ing.add_argument("--module", default=None)
    sub.add_parser("sweep-list", help="WP-covered proof units of the ledger, as (file, function)")
    p_sweep = sub.add_parser("sweep", help="Trusted re-proof of the sweep list without the per-run WP cache")
    p_sweep.add_argument("--jobs", type=int, default=None)

    raw = list(argv) if argv is not None else sys.argv[1:]
    args = parser.parse_args(_normalize_flag_args(raw))
    run_dir = args.run_dir
    rc = 0
    try:
        if args.cmd == "gen":
            out: Any = generate(run_dir)
            rc = 0 if out["ok"] else 1
        elif args.cmd == "params" and args.params_cmd == "set":
            out = params_set(
                run_dir,
                args.module,
                reset=args.reset,
                eva_slevel=args.eva_slevel,
                eva_taint=args.eva_taint,
                eva_timeout=args.eva_timeout,
                fuzz_dict=args.fuzz_dict,
                fuzz_budget=args.fuzz_budget,
                fuzz_max_time=args.fuzz_max_time,
            )
        elif args.cmd == "params":
            out = params_show(run_dir, args.module)
            rc = 0 if out["ok"] else 1
        elif args.cmd == "run":
            rc, out = run_targets(args.targets, run_dir, jobs=args.jobs)
        elif args.cmd == "ingest":
            out = ingest(run_dir, args.module)
            rc = 0 if out["ok"] else 1
        elif args.cmd == "sweep-list":
            entries, skipped = sweep_list(run_dir)
            out = {"count": len(entries), "units": entries, "skipped": skipped}
        else:
            out = sweep(run_dir, jobs=args.jobs)
            rc = 0 if out["ok"] else 1
    except (ValueError, ArtifactError, PipelineMakeError, RunLockTimeout) as exc:
        out, rc = {"ok": False, "error": str(exc)}, 1
    print(json.dumps(out, indent=2))
    return rc


if __name__ == "__main__":
    sys.exit(main())
