#!/usr/bin/env python3
"""
Make-driven deterministic phases: writes the run's Makefile, runs its targets, and implements
the recipes that need Python (stdlib only).

Per-module work that needs no judgment runs from workspace/build/Makefile instead of LLM
subagents: builds, the E-ACSL selftest, fuzz campaigns, corpus coverage, Eva runs, the provers' function
facts, report ingestion, candidate replays, the WP queue, the end-of-run WP sweep and the reports. Make runs inside the container
from the run directory (/framac-run), the working directory every script assumes.

Subcommands (run from the run directory):
  gen                          write workspace/build/{Makefile,modules.mk}; print the module plan
  params set --module M [...]  record per-module tuning in workspace/build/params.json
  params show [--module M]     effective tuning of every module
  run <targets...>             make -f workspace/build/Makefile -j<this container's CPUs> -k --output-sync=target
                               (`eva-tune` is the Eva ladder: docs/resources-and-caching.md, Section 6)
  ingest [--module M]          ingest new fuzz then Eva reports, stubbing missing ones; validate
  build-check [--target D]     Phase 0's last gate: every fuzzed module builds with E-ACSL; once
                               every Phase 0 gate passed, records the Phase 0 checkpoint (state/)
  sweep-list                   the ledger's WP-covered proof units, as (file, function)
  sweep [--jobs N]             re-prove them without the per-run WP cache, one leased WP job each

modules.mk is derived from workspace/reports/callgraph_dag.json, the harness sidecars
(workspace/harnesses/harness_<mod>.json), params.json and run-metadata.json. Make targets, reports
and params are per *harness module*: a DAG module, or a sub-module of a link unit (its sidecar's
`unit`, scripts/module_map.py), which runs under its unit's sources and flags with its own tier. Every value is a
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
import phase0_gates  # noqa: E402
from eva_loops import loop_ref_from_json, mirror_id  # noqa: E402
from eva_options import (  # noqa: E402
    EVA_OPTIONS,
    LADDER,
    PERFN_MAX_FUNCTIONS,
    PERFN_SLEVEL,
    TRIAL_TIMEOUT_CEILING_S,
    TUNING_SKIP_MARGIN,
    format_option,
    loop_unroll_level,
    merge_options,
    options_problem,
    parse_option,
    record_is_current,
    recorded_rungs,
    settings_digest,
    trial_timeout,
    tuned_record_problem,
    tuning_skip_reason,
)
from eva_shards import MAX_SHARDS, SHARD_DIR, harness_shardable, make_plan, plan_problem, shard_cppflags  # noqa: E402
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
from module_map import ModuleMap, load_sidecars  # noqa: E402
from tiers import is_deferred  # noqa: E402
from workspace_overlay import harness_module_for_function, infer_prover_wp_flags  # noqa: E402

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
COVERAGE_REPORT_DIR = "workspace/reports/coverage"  # not in REPORT_DIRS: nothing ingests these reports
FACTS_DIR = "workspace/reports/facts"
SELFTEST_JSON = "workspace/reports/eacsl_selftest.json"
INGESTED_JSON = "state/ingested.json"
LEDGER_JSON = "coverage-ledger.json"
SWEEP_DIR = "workspace/reports/wp-sweep"
TUNE_REPORT_DIR = "workspace/reports/eva-tuning"
# Their eva-<name> targets would collide with the ladder's own aggregate targets.
_RESERVED_MODULES = frozenset({"tune", "tune-base"})

DEFAULT_PROFILE = "standard"
# CPU-seconds of fuzzing per harness case (a campaign gets one share per dispatch case; a harness without
# cases counts as one), and the most one link unit's campaigns may get together: a unit with more cases
# than the cap allows has its campaigns scaled down in proportion, never below MIN_FUZZ_BUDGET_S each.
# params.json's fuzz_budget for a module replaces all of this for that module.
FUZZ_BUDGET_BY_PROFILE = {"quick": 60, "standard": 120, "deep": 900}
FUZZ_UNIT_CAP_BY_PROFILE = {"quick": 480, "standard": 1200, "deep": 7200}
MIN_FUZZ_BUDGET_S = 30
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


_C_IDENT_JUNK = re.compile(r"\W")  # a module name in a C identifier


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


def _flag_groups(tokens: list[str]) -> list[tuple[str, ...]]:
    """Tokens as flags with their separate value (`-include x` is one group)."""
    groups: list[tuple[str, ...]] = []
    i = 0
    while i < len(tokens):
        if tokens[i] in _VALUE_FLAGS and i + 1 < len(tokens):
            groups.append((tokens[i], tokens[i + 1]))
            i += 2
        else:
            groups.append((tokens[i],))
            i += 1
    return groups


def union_flags(flag_lists: list[list[str]]) -> list[str]:
    """Flags of several harness modules in order, each once; only the first `-Dmain=` rename is kept."""
    seen: set[tuple[str, ...]] = set()
    has_main = False
    out: list[str] = []
    for tokens in flag_lists:
        for group in _flag_groups(tokens):
            if "".join(group).startswith("-Dmain="):
                if has_main:
                    continue
                has_main = True
            if group in seen:
                continue
            seen.add(group)
            out.extend(group)
    return out


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
    "eva_mlevel": int,
    "eva_taint": bool,
    "eva_timeout": int,
    "eva_recursion_fallback": bool,
    "eva_options": dict,
    "eva_tuned": dict,
    "eva_shards": int,
    "fuzz_budget": int,
    "fuzz_max_time": int,
    "fuzz_dict": str,
    "fuzz_rte_initialized": bool,
    "fuzz_engine": str,
    "wp_exclude_files": list,
    "wp_extra_sources": list,
}


def default_params(profile: str) -> dict:
    return {
        "eva_slevel": DEFAULT_EVA_SLEVEL,
        "eva_mlevel": 0,
        "eva_taint": False,
        "eva_timeout": None,
        "eva_recursion_fallback": False,
        "eva_options": {},
        "eva_tuned": None,
        # None: shard when the last single run was too slow to tune (eva_shards.py); 1: never; k: k shards.
        "eva_shards": None,
        "fuzz_budget": FUZZ_BUDGET_BY_PROFILE.get(profile, FUZZ_BUDGET_BY_PROFILE[DEFAULT_PROFILE]),
        "fuzz_max_time": None,
        "fuzz_dict": None,
        "fuzz_rte_initialized": True,
        "fuzz_engine": "auto",
        "wp_exclude_files": [],
        "wp_extra_sources": [],
    }


def _param_problem(key: str, value: Any) -> str | None:
    kind = PARAM_TYPES.get(key)
    if kind is None:
        return "unknown parameter"
    if kind is bool:
        return None if isinstance(value, bool) else "must be true or false"
    if kind is dict:
        return options_problem(value) if key == "eva_options" else tuned_record_problem(value)
    if kind is int:
        if isinstance(value, bool) or not isinstance(value, int):
            return "must be an integer"
        if key == "eva_slevel":
            return None if 0 <= value <= 1_000_000 else "must be between 0 and 1000000"
        if key == "eva_mlevel":
            return None if 0 <= value <= 1_000 else "must be between 0 and 1000"
        if key == "eva_shards":
            return None if 1 <= value <= MAX_SHARDS else f"must be between 1 (never shard) and {MAX_SHARDS}"
        return None if value > 0 else "must be positive"
    if key == "fuzz_engine":
        return (
            None
            if isinstance(value, str) and value in ("auto", "eacsl", "sanitizers")
            else "must be one of: 'auto', 'eacsl', 'sanitizers'"
        )
    if key in ("wp_exclude_files", "wp_extra_sources"):
        if not isinstance(value, list) or any(
            not isinstance(v, str) or not v or v.startswith("-") or any(c in v for c in "\n\r\0") for v in value
        ):
            return "must be a list of file paths (not empty, not starting with '-', no line breaks)"
        return None
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
    # Why `params["fuzz_engine"]` came from the DAG (build_callgraph_dag: the GCC fallback, setjmp/longjmp).
    engine_reason: str | None = None
    dag_cppflags_missing: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    # Rungs of the Eva ladder this module runs next, with their options; empty until its base run left Unknowns.
    tune_rungs: dict[str, dict] = field(default_factory=dict)
    tune_timeout: int | None = None
    # Why the ladder is not searched although the base run left Unknowns (eva_options.tuning_skip_reason).
    tune_skip: str | None = None
    loop_unroll: int = field(default_factory=lambda: loop_unroll_level(None))
    # A recorded decision current for these settings and the last base run's inputs: `eva-<mod>` then
    # replays the tuning (base run, recorded rungs, combination) instead of one run of the selected options.
    eva_replay: bool = False
    # Why the module never runs Eva although its DAG record schedules it (a target fuzz module), or None.
    eva_off: str | None = None
    # The dispatch cases each Eva shard keeps (eva_shards.py), from SHARD_DIR/<mod>/plan.json; empty
    # when the module runs as one Eva run.
    shards: list[list[int]] = field(default_factory=list)

    def to_json(self) -> dict:
        return {
            **({"eva_off": self.eva_off} if self.eva_off else {}),
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
            **({"engine_reason": self.engine_reason} if self.engine_reason else {}),
            "tune_rungs": list(self.tune_rungs),
            **({"tune_skip": self.tune_skip} if self.tune_skip else {}),
            "eva_replay": self.eva_replay,
            **({"eva_shards": [list(s) for s in self.shards]} if self.shards else {}),
            "warnings": self.warnings,
        }

    @property
    def base_options(self) -> dict:
        """The module's own Eva options, without any recorded tuning decision."""
        return dict(self.params.get("eva_options") or {})

    @property
    def settings_digest(self) -> str:
        """Everything but tuning that decides what Eva analyses for this module."""
        p = self.params
        return settings_digest(
            {
                "sources": sorted(self.sources),
                "cppflags": self.cppflags,
                "slevel": p["eva_slevel"],
                "mlevel": p["eva_mlevel"],
                "taint": p["eva_taint"],
                "recursion_fallback": p["eva_recursion_fallback"],
                # Raising the limit is how to give a rung that timed out another chance.
                "timeout": p["eva_timeout"],
                "options": self.base_options,
            }
        )

    @property
    def tuned(self) -> dict | None:
        """The recorded decision, when it was made under these settings."""
        record = self.params.get("eva_tuned")
        return record if record and record.get("settings_digest") == self.settings_digest else None

    def rung_options(self, overlay: dict) -> dict:
        """A ladder rung's complete options: it refines the module's own settings, never lowers them."""
        return merge_options({"slevel": self.params["eva_slevel"], **self.base_options}, overlay)


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
    # Every module the plan considers, with the DAG record it runs under: each harness module whose
    # unit is a DAG module (a sub-module's record carries its own tier and run flags), plus each DAG
    # module without any harness. Under a DAG without link units (an old run directory or a test fixture:
    # build_callgraph_dag.py always writes link units) these are exactly the DAG modules.
    records: dict[str, dict] = field(default_factory=dict)
    mm: ModuleMap = field(default_factory=lambda: ModuleMap(None))
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
        modules without a harness (they are deferred by design) and modules whose tier the profile
        defers (Tier 3 under quick, step I8). A link unit whose harnesses are sub-modules expects
        nothing under its own name: its sub-modules do.
        """
        flag = "run_eacsl_fuzz" if kind == "fuzz" else "run_eva"
        out: dict[str, str] = {}
        for name, dag_mod in sorted(self.records.items()):
            if not dag_mod.get(flag) or not MODULE_RE.match(name):
                continue
            if is_deferred(str(dag_mod.get("tier") or ""), self.profile):
                continue
            if name in self.modules:
                out[name] = f"{kind}-{name} produced no report"
            elif str(dag_mod.get("tier") or "").startswith("Tier 3") and name not in self.sidecars:
                continue
            else:
                out[name] = f"excluded from the Make phases: {self.excluded.get(name, 'not runnable')}"
        return out

    def unit_harness_modules(self, module: str | None) -> list[str]:
        """
        The harness modules standing for a ledger unit's `module`: none when it has a harness of its
        own (or is no DAG module), else the sub-modules of the link unit. A target fuzz module never
        stands for its unit (it is additive).
        """
        if not module or module in self.mm.sidecars or module not in self.dag_modules:
            return []
        return [s for s in self.mm.submodules(module) if s != module and not is_target_fuzzer(self.mm.sidecars.get(s))]

    def wp_cppflags_for(self, module: str | None) -> tuple[list[str] | None, str]:
        """
        cppflags of any ledger module for the WP sweep: the sidecar's, exactly as the parent
        re-check proved the merged function with (`-I.` without a sidecar), or (None, reason).
        A link unit whose harnesses are sub-modules takes the union of theirs (a function of the
        unit compiles under any of them; the first `-Dmain=` rename wins).
        """
        if module in self.modules:
            return self.modules[module].base_cppflags, ""
        subs = self.unit_harness_modules(module)
        if subs:
            groups: list[list[str]] = []
            problems: list[str] = []
            for sub in subs:
                try:
                    if sub in self.modules:
                        groups.append(self.modules[sub].base_cppflags)
                    else:
                        groups.append(_module_base_cppflags(self.run_dir, sub))
                except _Excluded as exc:
                    problems.append(f"{sub}: {exc}")
            if not groups:
                return None, "no sub-module of the unit has usable cppflags: " + "; ".join(problems)
            return union_flags(groups), ""
        try:
            return _module_base_cppflags(self.run_dir, module or ""), ""
        except _Excluded as exc:
            return None, str(exc)

    def wp_extra_sources_for(self, module: str | None) -> list[str]:
        """`wp_extra_sources` of a ledger unit's module: its own params plus its sub-modules'."""
        out: list[str] = []
        for name in [module or "", *self.unit_harness_modules(module)]:
            for src in self.params_doc.get("modules", {}).get(name, {}).get("wp_extra_sources", []) or []:
                if src not in out:
                    out.append(src)
        return out

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
    work = run_dir / WORK_DIR
    if (work / src).is_file():
        return f"{WORK_DIR}/{src}"
    # The DAG may store bare names (or a stale directory) while the overlay keeps the
    # sources in a subdirectory (e.g. workspace/work/src/misc.c): resolve by suffix.
    if work.is_dir():
        matches = sorted(work.glob(f"**/{src}"), key=lambda p: (len(p.parts), p.as_posix()))
        if matches:
            return f"{WORK_DIR}/{matches[0].relative_to(work).as_posix()}"
    if not (run_dir / src).is_file():
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


_MAIN_DEF_RE = re.compile(r"\bmain\s*\([^;{}]*\)\s*\{")


def _source_defines_main(path: Path) -> bool:
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    cleaned = re.sub(r"/\*.*?\*/", " ", content, flags=re.DOTALL)
    cleaned = re.sub(r"//[^\n]*", " ", cleaned)
    return bool(_MAIN_DEF_RE.search(cleaned))


TARGET_FUZZER_EVA_OFF = (
    "target fuzz module (sidecar target_fuzzer): it wraps the target's own fuzz function, so it is "
    "fuzzed and measured for coverage only; Eva runs from its unit's own harness"
)


def is_target_fuzzer(sidecar: dict | None) -> bool:
    """Whether a harness sidecar is a target fuzz module's (`tf_<id>`, generate_harness.py --target-fuzzer)."""
    return isinstance((sidecar or {}).get("target_fuzzer"), dict)


def _plan_module(plan: Plan, name: str, dag_mod: dict) -> ModulePlan:
    fuzz, eva = bool(dag_mod.get("run_eacsl_fuzz")), bool(dag_mod.get("run_eva"))
    if not MODULE_RE.match(name) or name in _RESERVED_MODULES:
        raise _Excluded("module name cannot be used in make targets and report paths")
    target_fuzzer = is_target_fuzzer(plan.mm.sidecars.get(name))
    if target_fuzzer:
        eva = False
        if not fuzz:
            raise _Excluded(
                "the DAG does not schedule its unit for fuzzing (run_eacsl_fuzz is false): " + TARGET_FUZZER_EVA_OFF
            )
    if not (fuzz or eva):
        raise _Excluded("the DAG schedules neither fuzzing nor Eva (run_eacsl_fuzz and run_eva are false)")
    sidecar = _load_sidecar(plan.run_dir, name)
    if sidecar is None:
        raise _Excluded(f"no harness sidecar ({HARNESS_DIR}/harness_{name}.json)")
    if not (plan.run_dir / HARNESS_DIR / f"harness_{name}.c").is_file():
        raise _Excluded(f"harness source {HARNESS_DIR}/harness_{name}.c is missing")
    tier = str(dag_mod.get("tier") or "")
    if is_deferred(tier, plan.profile):
        raise _Excluded(f"{tier.split(' (')[0]} is deferred under the {plan.profile} profile (scripts/tiers.py)")

    sources, origin = _module_sources(plan.run_dir, name, sidecar, dag_mod)
    for src in sources:
        if src.startswith("-"):
            raise _Excluded(f"source {src!r} looks like an option")
    base = _module_base_cppflags(plan.run_dir, name, sidecar)

    # Detect whether slice sources define main( to prevent linker collision with LibFuzzer's main()
    all_slice_sources = list(sources)
    for raw_s in (sidecar.get("sources") or []) + (dag_mod.get("required_sources") or []):
        if isinstance(raw_s, str) and raw_s not in all_slice_sources:
            all_slice_sources.append(raw_s)
    has_main_def = False
    for src in all_slice_sources:
        if PurePosixPath(src).name == f"harness_{name}.c":
            continue
        cand_paths = [
            plan.run_dir / src if not src.startswith("/") else Path(src),
            plan.run_dir / WORK_DIR / src,
        ]
        for cp in cand_paths:
            if cp.is_file():
                if _source_defines_main(cp):
                    has_main_def = True
                break
        if has_main_def:
            break

    if has_main_def:
        main_flag = f"-Dmain=__framac_module_main_{_C_IDENT_JUNK.sub('_', name)}"
        if not any(tok.startswith("-Dmain=") for tok in base):
            base.append(main_flag)

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

    params = effective_params(plan.params_doc, name, plan.profile)
    dag_engine = dag_mod.get("fuzz_engine")
    engine_reason: str | None = None
    if dag_engine and "fuzz_engine" not in (plan.params_doc.get("modules", {}).get(name) or {}):
        # A unit on the GCC fallback (E-ACSL needs the Frama-C parse) or calling setjmp/longjmp: the
        # DAG asks for the sanitizers, unless a recorded param says otherwise.
        if _param_problem("fuzz_engine", dag_engine) is None:
            params["fuzz_engine"] = dag_engine
            reason = dag_mod.get("fuzz_engine_reason")
            engine_reason = str(reason) if reason else "the call-graph DAG chose it"

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
        params=params,
        engine_reason=engine_reason,
        # Discovered by build_callgraph_dag.py but not in the sidecar: what to pass to
        # generate_harness.py --cppflags if the module does not build.
        dag_cppflags_missing=[t for t in dag_flags if t not in _joined_forms(base)],
        loop_unroll=loop_unroll_level(sidecar.get("max_input_size")),
        eva_off=TARGET_FUZZER_EVA_OFF if target_fuzzer else None,
    )
    missing = [s for s in sources if not (plan.run_dir / s if not s.startswith("/") else Path(s)).is_file()]
    if missing:
        mod.warnings.append("source file(s) not found: " + ", ".join(missing))
    if origin == "dag" and len(sources) == 1:
        mod.warnings.append("no module sources: neither the sidecar nor the DAG lists any")
    if mod.eva:
        _plan_shards(plan, mod, sidecar)
        if not mod.shards:
            _plan_tuning(plan, mod)
            _tuning_warning(mod)
    try:
        _module_block(mod)
    except ValueError as exc:
        raise _Excluded(str(exc)) from None
    return mod


def _has_target_unknowns(report: dict) -> bool:
    """Whether any Unknown is in target code: a libc function's own row never becomes prover work."""
    by_function = report.get("unknown_obligations_by_function")
    if not isinstance(by_function, dict):
        return False
    return any(
        "FRAMAC_SHARE" not in str(row.get("directory") or "")
        for rows in by_function.values()
        for row in rows
        if isinstance(row, dict)
    )


def _plan_tuning(plan: Plan, mod: ModulePlan) -> None:
    """
    The rungs `eva-tune` runs for this module, read from its base run: none when that left no
    Unknowns, those of a recorded decision still valid for these settings and sources, else the
    whole ladder. A rung that changes nothing here is the base run again and is left out.
    """
    try:
        base = load_json_optional(plan.run_dir / TUNE_REPORT_DIR / mod.name / "base.json", None)
    except ArtifactError as exc:
        mod.warnings.append(f"Eva tuning: {exc}")
        return
    if not isinstance(base, dict) or base.get("status") != "ok" or not _has_target_unknowns(base):
        return
    mod.tune_timeout = trial_timeout(base.get("elapsed_s"), mod.params.get("eva_timeout"))
    record = mod.params.get("eva_tuned")
    if record is not None and record_is_current(record, mod.settings_digest, base.get("input_digest")):
        # Recorded rungs finished here before: they replay (from the cache) whatever the base run took.
        wanted = set(recorded_rungs(record))
        mod.eva_replay = True
    else:
        skip = tuning_skip_reason(base.get("elapsed_s"), mod.tune_timeout, mod.params.get("eva_timeout"))
        if skip:
            mod.tune_skip = skip
            mod.warnings.append(TUNING_WARNING_PREFIX + skip)
            return
        wanted = {rung.name for rung in LADDER}
    plain = mod.rung_options({})
    for rung in LADDER:
        overlay = dict(rung.options)
        if rung.name == "perfn":
            # Per-function slevel for the functions with the most surviving Unknowns (upstream
            # -eva-slevel-function f:n, repeatable). Deterministic: the base run is re-run first.
            by_fn = base.get("unknown_obligations_by_function")
            if isinstance(by_fn, dict) and by_fn:
                ranked = sorted(by_fn.items(), key=lambda kv: (-len(kv[1]), kv[0]))
                overlay["slevel-function"] = [f"{fn}:{PERFN_SLEVEL}" for fn, _ in ranked[:PERFN_MAX_FUNCTIONS]]
        options = mod.rung_options(overlay)
        if rung.name in wanted and options != plain:
            mod.tune_rungs[rung.name] = options


TUNING_WARNING_PREFIX = "Eva tuning: "


def _tuning_warning(mod: ModulePlan) -> None:
    """
    Say when a recorded decision is not what `eva-<mod>` will reproduce, so a less precise report
    never replaces the tuned one silently (it also reaches `gen` and `run` output as a plan warning).
    """
    record = mod.params.get("eva_tuned")
    if not record or mod.eva_replay:
        return
    if mod.tuned is None:
        mod.warnings.append(
            TUNING_WARNING_PREFIX + f"the recorded decision is stale (the module's Eva settings changed since): "
            f"eva-{mod.name} falls back to the base options; run eva-tune to tune again"
        )
    else:
        mod.warnings.append(
            TUNING_WARNING_PREFIX + "the recorded decision cannot be replayed (no base run with Unknowns on "
            f"these sources yet, or the sources changed since): eva-{mod.name} runs the selected options "
            "without the per-obligation combination; run eva-tune to replay or tune again"
        )


SHARD_WARNING_PREFIX = "Eva sharding: "


def _shard_basis(plan: Plan, name: str) -> tuple[str, dict, Path | None] | None:
    """
    The module's last single run, that the shard plan is predicted from: (report path, report, its
    flamegraph.txt). The tuning base run first, then the module's report. A merged sharded report
    counts with the sum of its shards' times and their concatenated flamegraph.
    """
    for rel in (f"{TUNE_REPORT_DIR}/{name}/base.json", f"{REPORT_DIRS['eva']}/{name}.json"):
        path = plan.run_dir / rel
        if not path.is_file():
            continue
        try:
            report = load_json_strict(path, max_bytes=1 << 31)
        except ArtifactError:
            continue
        if not isinstance(report, dict):
            continue
        sharded = report.get("eva_shards")
        if isinstance(sharded, dict) and isinstance(sharded.get("total_s"), (int, float)):
            report = {**report, "elapsed_s": sharded["total_s"]}
        if report.get("status") not in ("ok", "analysis_timeout"):
            continue
        if not isinstance(report.get("elapsed_s"), (int, float)) or report["elapsed_s"] <= 0:
            continue
        fg = report.get("flamegraph_file")
        flamegraph = plan.run_dir / fg if isinstance(fg, str) and fg else None
        return rel, report, flamegraph if flamegraph is not None and flamegraph.is_file() else None
    return None


def _plan_shards(plan: Plan, mod: ModulePlan, sidecar: dict | None) -> None:
    """
    Whether `eva-<mod>` runs as shards (eva_shards.py), and which cases each keeps: the recorded plan
    while it fits these settings and cases, else a new one when the last single run was too slow for
    the ladder to finish (or params.json sets eva_shards). The plan is recorded so it never moves.
    """
    forced = mod.params.get("eva_shards")
    if forced == 1:
        return
    raw = (sidecar or {}).get("dispatch_cases")
    cases = [c for c in raw if isinstance(c, str) and c.strip()] if isinstance(raw, list) else []
    if len(cases) < 2:
        if forced:
            mod.warnings.append(SHARD_WARNING_PREFIX + "eva_shards is set, but the harness has fewer than 2 cases")
        return
    try:
        harness = (plan.run_dir / HARNESS_DIR / f"harness_{mod.name}.c").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    if not harness_shardable(harness):
        if forced:
            mod.warnings.append(
                SHARD_WARNING_PREFIX + "eva_shards is set, but the harness predates sharding (no per-case "
                "guards): generate it again"
            )
        return
    plan_path = plan.run_dir / SHARD_DIR / mod.name / "plan.json"
    try:
        record = load_json_optional(plan_path, None)
    except ArtifactError:
        record = None
    problem = plan_problem(record, len(cases), mod.settings_digest, forced)
    if problem is not None:
        basis = _shard_basis(plan, mod.name)
        module_timeout = mod.params.get("eva_timeout")
        limit_s = (module_timeout or TRIAL_TIMEOUT_CEILING_S) / TUNING_SKIP_MARGIN
        if basis is None:
            if not forced:
                return
            rel, total_s, flamegraph = None, limit_s, None
        else:
            rel, report, flamegraph = basis
            total_s = float(report["elapsed_s"])
            timed_out = report.get("status") == "analysis_timeout" or bool(report.get("timeout_fallback"))
            slow = timed_out or tuning_skip_reason(total_s, trial_timeout(total_s, module_timeout), module_timeout)
            if not forced and not slow:
                return
            if timed_out:
                total_s = max(total_s, limit_s * TUNING_SKIP_MARGIN)
        record = make_plan(cases, flamegraph, total_s, limit_s, mod.settings_digest, forced, rel)
        if record["k"] < 2:
            return
        atomic_write_json(plan_path, record)
    assert isinstance(record, dict)
    mod.shards = [list(s) for s in record["shards"]]
    predicted = record.get("predicted_makespan_s")
    mod.warnings.append(
        SHARD_WARNING_PREFIX + f"eva-{mod.name} runs as {len(mod.shards)} shards "
        f"({SHARD_DIR}/{mod.name}/plan.json, predicted {predicted} s for the slowest); the ladder does "
        "not run per shard yet"
    )


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
    dag_doc: dict | None = None
    dag_path = run_dir / DAG_JSON
    if dag_path.is_file():
        try:
            dag = load_json_strict(dag_path)
            mods = dag.get("modules") if isinstance(dag, dict) else None
            if not isinstance(mods, dict):
                raise ArtifactError(f"{DAG_JSON} has no 'modules' object")
            dag_modules = {str(k): v for k, v in mods.items() if isinstance(v, dict)}
            dag_doc = dag
        except ArtifactError as exc:
            errors.append(f"callgraph DAG unusable: {exc}")
    else:
        warnings.append(f"{DAG_JSON} missing: no module targets until the dag target has run")

    harness_dir = run_dir / HARNESS_DIR
    sidecars = (
        {p.name[len("harness_") : -len(".json")] for p in harness_dir.glob("harness_*.json")}
        if harness_dir.is_dir()
        else set()
    )
    mm = ModuleMap(dag_doc, load_sidecars(harness_dir))
    records: dict[str, dict] = {}
    for name in sorted(sidecars):
        if mm.unit_of(name) in dag_modules:
            records[name] = _harness_record(mm, name, dag_modules)
        elif dag_modules:
            warnings.append(f"harness sidecar for {name!r} ignored: no such module in the DAG")
    harnessed_units = {mm.unit_of(name) for name in records}
    for name, dag_mod in dag_modules.items():
        if name not in harnessed_units and name not in records:
            records[name] = dag_mod  # no harness: excluded below, then stubbed or deferred by `expected`

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
        records=dict(sorted(records.items())),
        mm=mm,
        warnings=warnings,
        errors=errors,
    )
    for name in plan.records:
        try:
            plan.modules[name] = _plan_module(plan, name, plan.records[name])
        except _Excluded as exc:
            plan.excluded[name] = str(exc)
            continue
        # Tuning and sharding warnings change what a report means, so they are surfaced at the top of
        # `gen` and `run`.
        warnings.extend(
            f"{name}: {w}"
            for w in plan.modules[name].warnings
            if w.startswith((TUNING_WARNING_PREFIX, SHARD_WARNING_PREFIX))
        )
    allocate_fuzz_budgets(plan)
    for name in sorted(set(params_doc["modules"]) - set(plan.records)):
        if name in dag_modules:
            warnings.append(f"params.json tunes {name!r}, {_unit_note(plan, name)}")
        elif dag_modules:
            warnings.append(f"params.json tunes {name!r}, which is not a DAG module")
    return plan


def harness_case_count(sidecar: dict | None) -> int:
    """Cases of a harness: its dispatch cases, else 1 (always 1 for a target fuzz module: one fuzz function)."""
    if is_target_fuzzer(sidecar):
        return 1
    cases = (sidecar or {}).get("dispatch_cases")
    n = len([c for c in cases if isinstance(c, str) and c.strip()]) if isinstance(cases, list) else 0
    return max(1, n)


def allocate_fuzz_budgets(plan: Plan) -> None:
    """
    The fuzz budget of each fuzzed module without a params.json override: FUZZ_BUDGET_BY_PROFILE per
    harness case, with the campaigns of one link unit together capped at FUZZ_UNIT_CAP_BY_PROFILE
    (scaled down in proportion, at least MIN_FUZZ_BUDGET_S each). The plan records how each budget was
    set in the module's params (`fuzz_budget_source`: params, cases or unit_cap; `fuzz_cases`).
    A params.json budget above the unit cap is kept, with a tuning warning; so is a unit that the
    MIN_FUZZ_BUDGET_S floor keeps above its cap. Both warnings reach `gen` and `run` output.
    """
    per_case = FUZZ_BUDGET_BY_PROFILE.get(plan.profile, FUZZ_BUDGET_BY_PROFILE[DEFAULT_PROFILE])
    cap = FUZZ_UNIT_CAP_BY_PROFILE.get(plan.profile, FUZZ_UNIT_CAP_BY_PROFILE[DEFAULT_PROFILE])
    by_unit: dict[str, list[ModulePlan]] = {}
    for name, mod in plan.modules.items():
        if not mod.fuzz:
            continue
        if "fuzz_budget" in (plan.params_doc.get("modules", {}).get(name) or {}):
            mod.params["fuzz_budget_source"] = "params"
            budget = mod.params.get("fuzz_budget")
            if isinstance(budget, int) and budget > cap:
                warning = (
                    f"fuzz budget: params.json sets {budget} CPU-seconds, above the {cap} the {plan.profile} "
                    f"profile allows one link unit; kept as recorded (`params set --module {name} "
                    "--fuzz-budget 0` returns to the profile default)"
                )
                mod.warnings.append(warning)
                plan.warnings.append(f"{name}: {warning}")
            continue
        mod.params["fuzz_cases"] = harness_case_count(plan.mm.sidecars.get(name))
        mod.params["fuzz_budget"] = per_case * mod.params["fuzz_cases"]
        mod.params["fuzz_budget_source"] = "cases"
        by_unit.setdefault(plan.mm.unit_of(name), []).append(mod)
    for unit, mods in by_unit.items():
        total = sum(m.params["fuzz_budget"] for m in mods)
        if total <= cap:
            continue
        for m in mods:
            m.params["fuzz_budget"] = max(MIN_FUZZ_BUDGET_S, m.params["fuzz_budget"] * cap // total)
            m.params["fuzz_budget_source"] = "unit_cap"
        scaled = sum(m.params["fuzz_budget"] for m in mods)
        if scaled > cap:
            plan.warnings.append(
                f"fuzz budget: link unit {unit} gets {scaled} CPU-seconds over {len(mods)} campaigns, above its "
                f"{cap} cap under the {plan.profile} profile, because each campaign keeps at least "
                f"{MIN_FUZZ_BUDGET_S}; set `fuzz_budget` per module with `params set` to stay within the cap"
            )


def _unit_note(plan: Plan, unit: str) -> str:
    subs = ", ".join(plan.unit_harness_modules(unit))
    return f"a link unit whose harness modules are its sub-modules ({subs}): only its WP settings apply"


def _harness_record(mm: ModuleMap, name: str, dag_modules: dict[str, dict]) -> dict:
    """
    The DAG record a harness module runs under: its own DAG module's, or for a sub-module of a link
    unit, its path module's record (the DAG's `lexer_modules`) when it has one (the sources and flags its harness was
    generated against), else the unit's, with the sub-module's own tier and run flags.
    """
    unit = mm.unit_of(name)
    if unit == name:
        return dag_modules[name]
    lexer = mm.lexer_modules.get(name)
    base = lexer if isinstance(lexer, dict) else dag_modules[unit]
    rec = {**base, "tier": mm.tier_of(name) or base.get("tier"), **mm.run_flags(name)}
    unit_rec = dag_modules.get(unit) or {}
    fallback = unit_rec.get("callgraph_fallback")
    if fallback:
        # The unit is on the GCC fallback (build_callgraph_dag.block_fallback_units): so is the harness.
        rec.update(run_eva=False, run_wp_full=False, fuzz_engine="sanitizers", callgraph_fallback=fallback)
    if unit_rec.get("fuzz_engine"):
        # The unit's engine (the fallback, or setjmp/longjmp: route_nonlocal_jumps) is its harnesses'.
        rec.update(fuzz_engine=unit_rec["fuzz_engine"], fuzz_engine_reason=unit_rec.get("fuzz_engine_reason"))
    if is_target_fuzzer(mm.sidecars.get(name)):
        # Fuzz and coverage only: no Eva report is expected of it (Plan.expected).
        rec["run_eva"] = False
    return rec


def module_build_spec(
    module: str, run_dir: Path | str = ".", file: str | None = None, function: str | None = None
) -> dict:
    """
    Sources, cppflags and ldflags of a runnable module's fuzz build, exactly as the Makefile's
    build and fuzz recipes pass them (other builders of the same binary should use this, so their
    builds share the cache entry). ValueError when the module cannot run from Make. A link unit
    without a harness of its own resolves to the sub-module whose scope holds `file`#`function`
    (the harness the ledger verifies a candidate through), else its first one, named in
    `harness_module`.
    """
    plan = build_plan(run_dir)
    requested = module
    if module not in plan.records:
        # A link unit's name (an Eva candidate may carry one): the harness module that stands for it.
        module = harness_module_for_function(plan.mm, module, file, function) or module
    mod = plan.modules.get(module)
    if mod is None:
        raise ValueError(f"module {module!r} is not runnable: {plan.excluded.get(module, 'not in the DAG')}")
    return {
        # Only for a unit resolved to one of its harness modules: the binary is fuzz_<harness_module>.
        **({"harness_module": module} if module != requested else {}),
        "sources": list(mod.sources),
        "cppflags": shlex.join(mod.cppflags),
        "ldflags": shlex.join(mod.ldflags),
        "rte_initialized": bool(mod.params.get("fuzz_rte_initialized", True)),
    }


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


def _option_words(options: dict) -> str:
    return " ".join(mk_quote(f"--eva-option={format_option(k, options[k])}") for k in sorted(options))


def _eva_tuning_lines(mod: ModulePlan) -> list[str]:
    n = mod.name
    tuned = mod.tuned
    effective = merge_options(mod.base_options, tuned.get("options") or {}) if tuned else mod.base_options
    loops = [loop_ref_from_json(item) for item in (tuned.get("loops") or [])] if tuned else []
    loop_words = [mk_quote(f"--loop-unroll={ref.to_arg()}") for ref in sorted(loops)]
    if loops:
        loop_words.append(mk_quote(f"--mirror-root=workspace/eva/{n}/tune/mirrors/{mirror_id(loops)}"))
    lines = [
        _assign(f"ENTRY_FN_{n}", mk_quote(mod.entry_fn) if mod.entry_fn else ""),
        _assign(f"EVA_OPTIONS_{n}", _option_words(effective)),
        _assign(f"EVA_LOOPS_{n}", " ".join(loop_words)),
        _assign(f"EVA_BASE_OPTIONS_{n}", _option_words(mod.base_options)),
        _assign(f"EVA_TUNE_DIGEST_{n}", mk_quote(mod.settings_digest)),
        _assign(f"EVA_TUNE_TIMEOUT_{n}", _opt(mod.tune_timeout)),
        _assign(f"EVA_LOOP_UNROLL_{n}", mk_quote(str(mod.loop_unroll))),
        _assign(f"EVA_TUNE_RUNGS_{n}", " ".join(mod.tune_rungs)),
        _assign(f"EVA_TUNE_SKIP_{n}", mk_quote(mod.tune_skip) if mod.tune_skip else ""),
        _assign(f"EVA_REPLAY_{n}", "1" if mod.eva_replay else ""),
    ]
    for rung, options in mod.tune_rungs.items():
        lines.append(_assign(f"EVA_RUNG_OPTIONS_{n}__{rung}", _option_words(options)))
    lines.append(_assign(f"EVA_SHARDS_{n}", " ".join(str(i) for i in range(len(mod.shards)))))
    for i, cases in enumerate(mod.shards):
        flags = mk_quote(shlex.join([*mod.cppflags, *shard_cppflags(cases)]))
        lines.append(_assign(f"EVA_SHARD_CPPFLAGS_{n}__{i}", flags))
    return lines


def _module_block(mod: ModulePlan) -> list[str]:
    n, p = mod.name, mod.params
    return [
        f"# {n}",
        _assign(f"SOURCES_{n}", " ".join(mk_quote(s) for s in mod.sources)),
        _assign(f"CPPFLAGS_{n}", mk_quote(shlex.join(mod.cppflags))),
        _assign(f"LDFLAGS_{n}", mk_quote(shlex.join(mod.ldflags))),
        _assign(f"EVA_SLEVEL_{n}", mk_quote(str(p["eva_slevel"]))),
        _assign(f"EVA_MLEVEL_{n}", mk_quote(str(p["eva_mlevel"])) if p["eva_mlevel"] else ""),
        _assign(f"EVA_TAINT_{n}", "1" if p["eva_taint"] else ""),
        _assign(f"EVA_TIMEOUT_{n}", _opt(p["eva_timeout"])),
        _assign(f"EVA_RECURSION_FALLBACK_{n}", "1" if p["eva_recursion_fallback"] else ""),
        *_eva_tuning_lines(mod),
        _assign(f"FUZZ_BUDGET_{n}", mk_quote(str(p["fuzz_budget"]))),
        _assign(f"FUZZ_MAX_TIME_{n}", _opt(p["fuzz_max_time"])),
        _assign(f"FUZZ_DICT_{n}", _opt(p["fuzz_dict"])),
        _assign(f"FUZZ_NO_RTE_INIT_{n}", "" if p["fuzz_rte_initialized"] else "1"),
        _assign(f"FUZZ_ENGINE_{n}", mk_quote(str(p.get("fuzz_engine") or "auto"))),
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
        # PROFILE is for the reader of modules.mk: recipes take the profile through the values it set
        # (FUZZ_BUDGET_<mod>, ...), never directly.
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

_CLEARED_BY_ZERO = ("eva_mlevel", "eva_timeout", "eva_shards", "fuzz_budget", "fuzz_max_time")


def parse_eva_option_updates(texts: list[str]) -> dict[str, Any]:
    """`name=value` and `name=` (clear) from `params set --eva-option` into a params_set update."""
    updates: dict[str, Any] = {}
    for text in texts:
        name, sep, value = text.partition("=")
        if sep and not value.strip():
            if name.strip() not in EVA_OPTIONS:
                raise ValueError(f"{name.strip()!r} is not an allowed Eva option")
            updates[name.strip()] = None
        else:
            key, parsed = parse_option(text)
            updates[key] = parsed
    return updates


def params_set(
    run_dir: Path | str = ".", module: str = "", reset: bool = False, eva_retune: bool = False, **updates: Any
) -> dict:
    """
    Update one module's overrides. 0 clears eva_mlevel, eva_timeout, eva_shards (back to sharding only a
    module too slow to tune), fuzz_budget (back to the profile default) and fuzz_max_time; an empty fuzz_dict clears the dictionary; `reset` drops every
    earlier override first. `eva_options` updates individual options (None clears one). `eva_retune`
    forgets the recorded tuning decision, so `eva-tune` searches the ladder again; a change to any
    other setting Eva analyses under makes that decision stale by itself. ValueError on an invalid value.
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
        if eva_retune:
            entry.pop("eva_tuned", None)
        for key, value in updates.items():
            if value is None:
                continue
            if key == "eva_options":
                options = dict(entry.get("eva_options") or {})
                for name, option in value.items():
                    if option is None:
                        options.pop(name, None)
                    else:
                        options[name] = option
                value = options
                if not value:
                    entry.pop(key, None)
                    continue
            if (
                (key in _CLEARED_BY_ZERO and value == 0)
                or (key == "fuzz_dict" and value == "")
                or (key == "fuzz_engine" and value == "")
                or (key in ("wp_exclude_files", "wp_extra_sources") and value == [])
            ):
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
    if module in plan.dag_modules and module not in plan.records:
        warnings.append(f"{module!r} is {_unit_note(plan, module)}; tune the sub-modules")
    elif plan.dag_modules and module not in plan.records:
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


def record_eva_tuning(run_dir: Path | str, module: str, record: dict) -> None:
    """Store a module's tuning decision, so `eva` and another machine's `eva-tune` replay it."""
    problem = tuned_record_problem(record)
    if problem:
        raise ValueError(f"eva_tuned {problem}")
    with run_lock("params", run_dir=Path(run_dir)):
        doc = load_params(run_dir)
        doc["modules"].setdefault(module, {})["eva_tuned"] = record
        atomic_write_json(Path(run_dir) / PARAMS_JSON, doc)


def params_show(run_dir: Path | str = ".", module: str | None = None) -> dict:
    plan = build_plan(run_dir)
    names = sorted(set(plan.records) | set(plan.params_doc["modules"]))
    if module is not None:
        names = [module]
    units = plan.mm.units_are_link_units
    return {
        "ok": not plan.errors,
        "profile": plan.profile,
        "defaults": default_params(plan.profile),
        "modules": {
            name: {
                # A runnable module's fuzz engine is its plan's (the DAG asks for the sanitizers on a
                # unit on the GCC fallback).
                "effective": {
                    **effective_params(plan.params_doc, name, plan.profile),
                    **(
                        {"fuzz_engine": plan.modules[name].params["fuzz_engine"]}
                        if name in plan.modules and "fuzz_engine" in plan.modules[name].params
                        else {}
                    ),
                },
                "overrides": plan.params_doc["modules"].get(name, {}),
                "runnable": name in plan.modules,
                "in_dag": name in plan.dag_modules or name in plan.records,
                **({"unit": plan.mm.unit_of(name)} if units else {}),
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
    # The overlay; the build capture and the Phase 0 model run outside Make between it and the DAG.
    "slice-init": 0,
    "dag": 1,
    "security-props": 2,
    "reach-gate": 2,
    "seed": 2,
    "build": 3,
    "selftest": 3,
    "fuzz": 3,
    "eva": 3,
    "eva-tune-base": 3,
    # Its own stage: modules.mk is regenerated first, so the rungs come from the base runs' results.
    "eva-tune": 4,
    # Renders the flamegraph.txt an earlier Eva run left (it never runs Eva), so after eva and eva-tune.
    "flamegraph": 5,
    "coverage": 4,  # after fuzz, so that it measures the campaign's corpus
    "seeds": 3,
    # Reads the coverage reports, so after coverage (its per-module targets depend on coverage-<mod>).
    "reach-dynamic": 5,
    # After eva-tune, which rewrites the Eva report the facts read.
    "facts": 5,
    "ingest": 5,
    "replay": 5,
    "minimize": 5,
    "wp-queue": 5,
    "wp-baseline": 5,
    "wp-sweep": 6,
    "report": 7,
}
# Phase 0 targets that write what the plan reads: they run even when the current DAG is unusable.
PHASE0_INPUT_TARGETS = frozenset({"slice-init", "dag", "security-props"})
MODULE_TARGET_PREFIXES = ("build-", "fuzz-", "coverage-", "eva-", "flamegraph-", "module-", "facts-")
REACH_DYNAMIC_PREFIX = "reach-dynamic-"
_TARGET_OUTPUTS = {
    "slice-init": "workspace/overlay_meta.json",
    "dag": DAG_JSON,
    "security-props": "workspace/reports/security_props.json",
    "seed": LEDGER_JSON,
    "selftest": SELFTEST_JSON,
    "ingest": INGESTED_JSON,
    "replay": "workspace/reports/replay/index.json",
    "minimize": "workspace/reports/minimize/index.json",
    "wp-queue": "workspace/reports/wp_queue.json",
    "wp-baseline": "workspace/reports/wp_baseline.json",
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
    if target.startswith("facts-") and target.partition("-")[2]:
        return STAGE_OF_TARGET["facts"]  # it reads the Eva report, so it follows the Eva stages of the invocation
    if target.startswith("flamegraph-") and target.partition("-")[2]:
        return STAGE_OF_TARGET["flamegraph"]
    if target.startswith(REACH_DYNAMIC_PREFIX) and target[len(REACH_DYNAMIC_PREFIX) :]:
        return STAGE_OF_TARGET["reach-dynamic"]
    if target.startswith(MODULE_TARGET_PREFIXES) and target.partition("-")[2]:
        return STAGE_OF_TARGET["coverage"] if target.startswith("coverage-") else STAGE_OF_TARGET["build"]
    return None


def _target_problem(target: str, plan: Plan) -> str | None:
    if plan.errors and target not in PHASE0_INPUT_TARGETS:
        return "; ".join(plan.errors)
    if target in STAGE_OF_TARGET:
        return None
    kind, _, mod = target.partition("-")
    if target.startswith(REACH_DYNAMIC_PREFIX):
        kind, mod = "coverage", target[len(REACH_DYNAMIC_PREFIX) :]
    allowed = {
        "build": plan.fuzz_modules,
        "fuzz": plan.fuzz_modules,
        "coverage": plan.fuzz_modules,
        "eva": plan.eva_modules,
        "flamegraph": plan.eva_modules,
        "module": list(plan.modules),
        "facts": list(plan.modules),
    }[kind]
    if mod in allowed:
        return None
    if mod in plan.excluded:
        return f"module {mod} is excluded: {plan.excluded[mod]}"
    if mod in plan.modules:
        return f"module {mod} has no {kind} target: the DAG does not schedule it"
    if plan.unit_harness_modules(mod):
        return f"{mod} is a link unit: use the targets of its harness modules ({', '.join(plan.unit_harness_modules(mod))})"
    return f"unknown module {mod!r}"


def _target_nodes(target: str, plan: Plan) -> list[str]:
    if target == "build":
        return [f"build-{m}" for m in plan.fuzz_modules]
    if target == "fuzz":
        return [f"fuzz-{m}" for m in plan.fuzz_modules]
    if target == "coverage":
        return [f"coverage-{m}" for m in plan.fuzz_modules]
    if target == "reach-dynamic":
        return [f"{REACH_DYNAMIC_PREFIX}{m}" for m in plan.fuzz_modules]
    if target == "eva":
        return [f"eva-{m}" for m in plan.eva_modules]
    if target == "flamegraph":
        return [f"flamegraph-{m}" for m in plan.eva_modules]
    if target == "eva-tune-base":
        return [f"evabase-{m}" for m in plan.eva_modules]
    if target == "eva-tune":
        return [f"evatune-{m}" for m in plan.eva_modules]
    if target == "facts":
        return [f"facts-{m}" for m in plan.modules]
    return [target]


def _node_deps(node: str, plan: Plan) -> list[str]:
    """Prerequisites as declared in templates/pipeline.mk (to tell skipped from failed)."""
    if node.startswith(REACH_DYNAMIC_PREFIX):
        return [f"coverage-{node[len(REACH_DYNAMIC_PREFIX) :]}"]
    kind, _, mod = node.partition("-")
    if kind == "fuzz" and mod:
        return ["selftest", f"build-{mod}"]
    if kind == "module":
        deps = [f"fuzz-{mod}"] if mod in plan.fuzz_modules else []
        return deps + ([f"eva-{mod}"] if mod in plan.eva_modules else [])
    if kind == "eva" and mod in plan.modules and plan.modules[mod].eva_replay:
        return [f"evabase-{mod}"]  # the recorded rungs are optional, as in eva-tune
    if node == "seed":
        return ["reach-gate", "security-props"]
    if node in ("replay", "wp-queue"):
        # wp-queue also depends on facts in pipeline.mk, but facts recipes never fail the build (`-`),
        # so they can never be the reason wp-queue was skipped.
        return ["ingest"]
    if node == "minimize":
        return ["replay"]
    if node == "wp-baseline":
        return ["wp-queue"]
    return []


def _node_output(node: str, plan: Plan | None = None) -> str | None:
    if node in _TARGET_OUTPUTS:
        return _TARGET_OUTPUTS[node]
    if node.startswith(REACH_DYNAMIC_PREFIX):
        return "workspace/reports/harness_reach_dynamic.json"
    kind, _, mod = node.partition("-")
    if kind == "evabase" and plan is not None and mod in plan.modules and plan.modules[mod].shards:
        return f"{REPORT_DIRS['eva']}/{mod}.json"  # a sharded module's base run is its merged shards
    return {
        "build": f"{BUILD_DIR}/{mod}.build.json",
        "fuzz": f"{REPORT_DIRS['fuzz']}/{mod}.json",
        "coverage": f"{COVERAGE_REPORT_DIR}/{mod}.json",
        "eva": f"{REPORT_DIRS['eva']}/{mod}.json",
        "flamegraph": f"workspace/eva/{mod}/flamegraph.svg",
        "evabase": f"{TUNE_REPORT_DIR}/{mod}/base.json",
        "evatune": f"{REPORT_DIRS['eva']}/{mod}.json",
        "facts": f"{FACTS_DIR}/{mod}.json",
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
            out = _node_output(node, plan)
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
    if "eva-tune" in targets and "eva-tune-base" not in targets:
        targets.insert(targets.index("eva-tune"), "eva-tune-base")
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
                "error": "make not found: `pipeline_make.py run` runs inside the analysis container",
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
            outputs = {n: _node_output(n, plan) for n in nodes}
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
                    out = outputs.get(node) or _node_output(node, plan)
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


def sweep_list(run_dir: Path | str = ".", warnings: list[str] | None = None) -> tuple[list[dict], list[dict]]:
    """
    The ledger's covered proof units, one entry per (file, function): units whose status is
    `covered` with discharging WP evidence, plus any Eva-covered callee in `callgraph_dag.json`
    called by a WP-covered caller that carries a `valid_under_hyp` assumption. Returns (entries, skipped).
    A callee matched by name only (a stale DAG without the callee's record) is appended to `warnings`.
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

            def _ref(key: str) -> tuple[str, str]:
                # A callee is a DAG key: the plain name, or `file#name` when the name collides.
                meta = dag_fns.get(key)
                if isinstance(meta, dict) and meta.get("name"):
                    return str(meta.get("file") or ""), str(meta["name"])
                return (key.split("#", 1)[0], key.split("#", 1)[1]) if "#" in key else ("", key)

            for c_file, c_fn in vuh_callers:
                c_names = callees_map.get((c_file, c_fn)) or callees_by_name.get(c_fn, [])
                for callee_key in c_names:
                    callee_file, callee_name = _ref(callee_key)
                    cand_units = eva_covered_by_fn.get(callee_name, [])
                    if callee_file:
                        chosen = [u for u in cand_units if u.get("file") == callee_file]
                    else:  # an old DAG without the callee's record: prefer the caller's file
                        chosen = [u for u in cand_units if u.get("file") == c_file] or cand_units
                        if chosen and warnings is not None:
                            files = sorted({str(u.get("file")) for u in chosen})
                            warnings.append(
                                f"{c_file}#{c_fn}: the DAG has no record of callee {callee_key!r}; matched the "
                                f"Eva-covered unit(s) of the same name in {', '.join(files)} (rebuild the DAG)"
                            )
                    for u in chosen:
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
        list_warnings: list[str] = []
        entries, skipped = sweep_list(run_dir, list_warnings)
        slugs = _file_slugs({e["file"] for e in entries})
        tasks: list[tuple[dict, str, list[str]]] = []
        for e in entries:
            flags, reason = plan.wp_cppflags_for(e["module"])
            if flags is None:
                skipped.append({"file": e["file"], "function": e["function"], "reason": reason})
                continue
            key = f"{e['module']}:{e['file']}#{e['function']}"
            out_json = f"{SWEEP_DIR}/{slugs[e['file']]}__{e['function']}.json"
            wp_extra_flags = infer_prover_wp_flags(
                run_dir,
                c_file=e["file"],
                function=e["function"],
            )
            extra_sources = plan.wp_extra_sources_for(e["module"])
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
            if extra_sources:
                cmd.extend(["--extra-sources", *extra_sources])
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
            if e.get("eva_only"):
                row["eva_only"] = True
            results.append(row)
            if status is None:
                missing.append(row)
            elif status != "all_proven":
                regressions.append(row)
            elif e.get("eva_only"):
                newly_wp_proven.append(row)
        summary: dict[str, Any] = {
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
        if list_warnings:
            summary["warnings"] = list_warnings
        # A WP-covered function whose re-proof left no report was not re-established either: record
        # that as its own report, so the ledger stops counting it as covered.
        missing_reports = []
        for r in missing:
            if r.get("eva_only"):
                continue
            stub = f"{SWEEP_DIR}/missing/{PurePosixPath(r['report']).name}"
            atomic_write_json(
                run_dir / stub,
                {
                    "mode": "sweep_missing",
                    "file": f"{WORK_DIR}/{r['file']}",
                    "function": r["function"],
                    "status": "analysis_error",
                    "reason": f"wp-sweep re-proof wrote no report (rc={r['rc']})",
                },
            )
            missing_reports.append(stub)
        s_runner = script_runner or _script_runner(run_dir)
        to_ingest = [*(r["report"] for r in regressions), *missing_reports, *(r["report"] for r in newly_wp_proven)]
        if to_ingest:
            # The sweep is the trusted backstop: regressions, functions it could not re-prove and newly
            # WP-verified Eva callees reach the ledger.
            rc, out = s_runner("ledger.py", ["ingest-wp", "--sweep", *to_ingest])
            summary["ledger"] = _json_or_tail(out)
            if rc != 0:
                summary["ok"] = False
                summary["ledger_error"] = f"ledger.py ingest-wp failed (rc={rc}); regressions not recorded"
        # Always resolve callee hypotheses on the final ledger: a regression can turn a callee's proof
        # conditional, and that must reach every caller above it.
        rc_a, out_a = s_runner("ledger.py", ["audit-hypotheses"])
        summary["hypothesis_audit"] = _json_or_tail(out_a)
        if rc_a != 0:
            summary["ok"] = False
            summary["audit_error"] = f"ledger.py audit-hypotheses failed (rc={rc_a})"
        atomic_write_json(run_dir / SWEEP_DIR / "summary.json", summary)
    return summary


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


BUILD_CHECK_JSON = "workspace/reports/build_check.json"
_BUILD_ERROR_RE = re.compile(r"User Error|\berror:|Fatal error", re.IGNORECASE)


_SILENT_ABORT_RE = re.compile(r"aborted by Frama-C", re.IGNORECASE)


def _first_build_error(log_path: Path) -> str | None:
    """
    The first error line of the compile log's last failed command and the two lines after it, or None.

    The log holds one `Command:` section per attempt. An earlier attempt's error can be one the
    build already recovered from (the retry that drops unknown -rte-select names), so only the
    attempt that failed last explains the fallback. When Frama-C stopped there without a message of
    its own, it was most likely killed (out of memory), and the excerpt says so.
    """
    try:
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    starts = [i for i, line in enumerate(lines) if line.startswith("Command: ")] or [0]
    sections = [lines[a:b] for a, b in zip(starts, [*starts[1:], len(lines)], strict=True)]
    failed = [s for s in sections if not any(line.strip() == "Returncode: 0" for line in s[:3])]
    section = (failed or sections)[-1]
    for i, line in enumerate(section):
        if _BUILD_ERROR_RE.search(line):
            excerpt = " ".join(s.strip() for s in section[i : i + 3] if s.strip())[:400]
            if _SILENT_ABORT_RE.search(line):
                excerpt += " (Frama-C stopped without an error message: most likely killed for lack of memory)"
            return excerpt
    return None


PHASE0_STATE_DIR = "state"
DEFAULT_TARGET_DIR = "/target"


def record_phase0_checkpoint(
    run_dir: Path,
    plan: Plan,
    script_runner: ScriptRunner | None = None,
    target_dir: str = DEFAULT_TARGET_DIR,
) -> dict:
    """
    Record `phase_done = 0` once Phase 0's last gate passed: build-check, and the reach gate of every
    module of the plan with its harness and the DAG unchanged since. `checkpoint.py init` runs first
    when the run has no progress file yet (it never rewinds an existing one).
    """
    reasons = phase0_gates.check(run_dir, None, phase0_gates.SECTIONS, list(plan.modules), list(plan.fuzz_modules))
    if reasons:
        return {"saved": False, "reasons": reasons}
    s_runner = script_runner or _script_runner(run_dir)
    if not (run_dir / PHASE0_STATE_DIR / "progress.json").is_file():
        rc, out = s_runner("checkpoint.py", ["init", PHASE0_STATE_DIR, "--target", target_dir])
        if rc != 0:
            return {"saved": False, "error": f"checkpoint.py init failed (rc={rc})", "output": _json_or_tail(out)}
    rc, out = s_runner("checkpoint.py", ["save-phase", PHASE0_STATE_DIR, "--phase", "0", "--from-file", DAG_JSON])
    if rc != 0:
        return {"saved": False, "error": f"checkpoint.py save-phase failed (rc={rc})", "output": _json_or_tail(out)}
    return {"saved": True, "phase_done": 0}


def build_check(
    run_dir: Path | str = ".",
    runner: Callable[..., tuple[int, Any]] | None = None,
    templates_dir: Path | str | None = None,
    script_runner: ScriptRunner | None = None,
    target_dir: str = DEFAULT_TARGET_DIR,
) -> dict:
    """
    Phase 0 gate: build every fuzzed module (`run build`) and require the E-ACSL engine.

    A module whose build fell back to ASan/UBSan, or failed, fails the check with the first
    compiler error of its E-ACSL attempt. Fuzzing it would lose the E-ACSL checks without anyone
    deciding so. A module whose `fuzz_engine` param is `sanitizers` passes: that is a recorded choice
    (`params set --module M --fuzz-engine sanitizers`), or the DAG's for its unit (the GCC fallback,
    setjmp/longjmp), whose reason the row gives. A module the reach gate stops (its `build-<mod>`
    recipe refuses it) is `not_built` with the gate's reason, whatever build report an earlier run left.
    Writes workspace/reports/build_check.json. Build-check is Phase 0's last gate: when it passes and
    the reach gate holds for the whole plan, it records the Phase 0 checkpoint (`phase0_checkpoint`).
    """
    run_dir = Path(run_dir)
    plan = build_plan(run_dir, templates_dir)
    modules = [plan.modules[name] for name in plan.fuzz_modules]
    if not modules:
        # Nothing to fuzz (an Eva-only plan, or every module deferred under quick) passes the gate;
        # a plan with no module at all means `gen` has not run, or the DAG has no runnable module.
        out: dict[str, Any] = {
            "ok": bool(plan.modules),
            "build_returncode": None,
            "modules": {},
            "generated_at": utc_now(),
        }
        if plan.modules:
            out["note"] = "no module of the plan is fuzzed: nothing to build"
        else:
            out["error"] = "no module in the plan: run `pipeline_make.py gen` first"
        return _finish_build_check(run_dir, plan, out, script_runner, target_dir)
    build_rc, _ = (runner or run_targets)(["build"], run_dir)
    # The reach gate as `build-<mod>` saw it. Without a reach stamp at all (a run that never seeded)
    # the recipes stopped too, but there is no gate reason to give beyond the missing report.
    reach_ran = isinstance(phase0_gates.load_gates(run_dir).get("reach"), dict)
    results: dict[str, dict] = {}
    for mod in sorted(modules, key=lambda m: m.name):
        chosen = str(mod.params.get("fuzz_engine") or "auto")
        entry: dict[str, Any] = {"fuzz_engine": chosen}
        gate = phase0_gates.check(run_dir, mod.name, ("reach",)) if reach_ran else []
        if gate:
            entry.update({"status": "not_built", "ok": False, "reason": "reach gate: " + "; ".join(gate)})
            results[mod.name] = entry
            continue
        report_path = run_dir / BUILD_DIR / f"{mod.name}.build.json"
        try:
            report = load_json_optional(report_path, None)
        except ArtifactError as exc:
            report = None
            entry["error"] = str(exc)
        if not isinstance(report, dict):
            entry.update({"status": "not_built", "ok": False})
            entry.setdefault("reason", f"no build report ({BUILD_DIR}/{mod.name}.build.json)")
            results[mod.name] = entry
            continue
        engine = report.get("engine_used")
        entry["engine_used"] = engine
        compiled = (report.get("compile") or {}).get("returncode") == 0
        if not compiled:
            entry["status"] = "build_failed"
        elif engine == "eacsl":
            entry["status"] = "eacsl"
        elif chosen == "sanitizers":
            entry["status"] = "sanitizers_chosen"
            if mod.engine_reason:
                entry["reason"] = mod.engine_reason
        else:
            entry["status"] = "eacsl_fallback"
            entry["fallback_reason"] = report.get("engine_fallback_reason")
        entry["ok"] = entry["status"] in ("eacsl", "sanitizers_chosen")
        if not entry["ok"]:
            attempt = report.get("eacsl_compile_attempt") or report.get("compile") or {}
            log = attempt.get("compile_log")
            if log:
                entry["compile_log"] = log
                entry["first_error"] = _first_build_error(run_dir / log)
        results[mod.name] = entry
    out = {
        "ok": all(r["ok"] for r in results.values()),
        "build_returncode": build_rc,
        "modules": results,
        "generated_at": utc_now(),
    }
    return _finish_build_check(run_dir, plan, out, script_runner, target_dir)


def _finish_build_check(
    run_dir: Path, plan: Plan, out: dict, script_runner: ScriptRunner | None, target_dir: str
) -> dict:
    """Write build_check.json and the gate stamp, then the Phase 0 checkpoint when Phase 0 passed."""
    phase0_gates.record_build_check(run_dir, out)  # the stamp fuzz-<mod> and wp-queue check
    if out["ok"]:
        out["phase0_checkpoint"] = record_phase0_checkpoint(run_dir, plan, script_runner, target_dir)
    from validate_artifacts import SCHEMA_WARNING_PREFIX, schema_warning

    # R5's policy: schema problems are recorded as warnings, and `validate_artifacts run-dir` fails on them.
    warnings = [w for w in out.get("warnings") or [] if not str(w).startswith(SCHEMA_WARNING_PREFIX)]
    problem = schema_warning("build_check", {**out, "warnings": warnings})
    out["warnings"] = [*warnings, problem] if problem else warnings
    atomic_write_json(run_dir / BUILD_CHECK_JSON, out)
    return out


def _normalize_flag_args(argv: list[str]) -> list[str]:
    """`--fuzz-dict -x` would be read as an option by argparse: bind such values with `=`."""
    from framac_common import normalize_flag_args

    return normalize_flag_args(argv, ("--fuzz-dict", "--fuzz-engine"))


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
    p_set.add_argument(
        "--eva-mlevel",
        type=int,
        default=None,
        help="Eva dynamic allocation unrolling level per callstack (-eva-mlevel; 0 clears)",
    )
    taint = p_set.add_mutually_exclusive_group()
    taint.add_argument("--eva-taint", dest="eva_taint", action="store_true", help="Add the taint domain")
    taint.add_argument("--no-eva-taint", dest="eva_taint", action="store_false")
    p_set.set_defaults(eva_taint=None)
    p_set.add_argument("--eva-timeout", type=int, default=None, help="Eva wall-clock seconds (0 clears)")
    p_set.add_argument(
        "--eva-shards",
        type=int,
        default=None,
        help="Run Eva as this many shards by dispatch case (1: never; 0 clears: shard when too slow to tune)",
    )
    eva_rec = p_set.add_mutually_exclusive_group()
    eva_rec.add_argument(
        "--eva-recursion-fallback",
        dest="eva_recursion_fallback",
        action="store_true",
        help=(
            "Continue Eva when a recursive call has no assigns clause by downgrading the "
            "assigns:missing error to a warning (recorded in reduced_checks)."
        ),
    )
    eva_rec.add_argument(
        "--no-eva-recursion-fallback",
        dest="eva_recursion_fallback",
        action="store_false",
        help="Keep the default: a recursive call without assigns aborts Eva",
    )
    p_set.set_defaults(eva_recursion_fallback=None)
    p_set.add_argument(
        "--eva-option",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="Allowlisted Eva option (see eva_options.py), for example min-loop-unroll=8; NAME= clears it. Repeatable.",
    )
    p_set.add_argument(
        "--eva-retune",
        action="store_true",
        help="Forget the recorded tuning decision, so the next `run eva-tune` searches the ladder again",
    )
    p_set.add_argument("--fuzz-dict", default=None, help="libFuzzer dictionary, run-relative ('' clears)")
    p_set.add_argument("--fuzz-budget", type=int, default=None, help="Campaign CPU-seconds (0: profile default)")
    p_set.add_argument(
        "--fuzz-max-time", type=int, default=None, help="Campaign wall-clock override in seconds (0 clears)"
    )
    rte_init = p_set.add_mutually_exclusive_group()
    rte_init.add_argument(
        "--fuzz-rte-initialized",
        dest="fuzz_rte_initialized",
        action="store_true",
        help="Check uninitialized reads in the fuzz build (default)",
    )
    rte_init.add_argument(
        "--no-fuzz-rte-initialized",
        dest="fuzz_rte_initialized",
        action="store_false",
        help=(
            "Drop -rte-initialized from the fuzz build for this module; recorded in "
            "reduced_checks. Useful when uninstrumented code fills memory the target reads "
            "(Eva still checks statically). Not needed for alarms on formal parameters: the "
            "build marks formals initialized (compile.formal_inits)."
        ),
    )
    p_set.set_defaults(fuzz_rte_initialized=None)
    p_set.add_argument(
        "--fuzz-engine",
        choices=["auto", "eacsl", "sanitizers", ""],
        default=None,
        help="Instrumentation engine (auto, eacsl, sanitizers; '' clears)",
    )
    p_set.add_argument(
        "--wp-exclude-files",
        nargs="*",
        default=None,
        help="C files to exclude from WP analysis (empty list clears)",
    )
    p_set.add_argument(
        "--wp-extra-sources",
        nargs="*",
        default=None,
        help="Extra C files needed for WP analysis (empty list clears)",
    )
    p_show = psub.add_parser("show")
    p_show.add_argument("--module", default=None)

    p_run = sub.add_parser("run", help="Run make targets from the run directory")
    p_run.add_argument("targets", nargs="+")
    p_run.add_argument("--jobs", type=int, default=None, help="Override make -j (default: this container's CPUs)")
    p_ing = sub.add_parser("ingest", help="Ingest new fuzz/Eva reports (fuzz first), then validate")
    p_ing.add_argument("--module", default=None)
    p_bc = sub.add_parser(
        "build-check",
        help="Phase 0: build every fuzzed module and fail unless E-ACSL instrumented it (or sanitizers were "
        "chosen); records the Phase 0 checkpoint once every Phase 0 gate passed",
    )
    p_bc.add_argument(
        "--target",
        default=DEFAULT_TARGET_DIR,
        help=f"Target directory recorded when the checkpoint is new (default: {DEFAULT_TARGET_DIR})",
    )
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
                eva_mlevel=args.eva_mlevel,
                eva_taint=args.eva_taint,
                eva_timeout=args.eva_timeout,
                eva_shards=args.eva_shards,
                eva_recursion_fallback=args.eva_recursion_fallback,
                eva_options=parse_eva_option_updates(args.eva_option) if args.eva_option else None,
                eva_retune=args.eva_retune,
                fuzz_dict=args.fuzz_dict,
                fuzz_budget=args.fuzz_budget,
                fuzz_max_time=args.fuzz_max_time,
                fuzz_rte_initialized=args.fuzz_rte_initialized,
                fuzz_engine=args.fuzz_engine,
                wp_exclude_files=args.wp_exclude_files,
                wp_extra_sources=args.wp_extra_sources,
            )
        elif args.cmd == "params":
            out = params_show(run_dir, args.module)
            rc = 0 if out["ok"] else 1
        elif args.cmd == "run":
            rc, out = run_targets(args.targets, run_dir, jobs=args.jobs)
        elif args.cmd == "ingest":
            out = ingest(run_dir, args.module)
            rc = 0 if out["ok"] else 1
        elif args.cmd == "build-check":
            out = build_check(run_dir, target_dir=args.target)
            rc = 0 if out["ok"] and "error" not in out.get("phase0_checkpoint", {}) else 1
        elif args.cmd == "sweep-list":
            list_warnings: list[str] = []
            entries, skipped = sweep_list(run_dir, list_warnings)
            out = {"count": len(entries), "units": entries, "skipped": skipped, "warnings": list_warnings}
        else:
            out = sweep(run_dir, jobs=args.jobs)
            rc = 0 if out["ok"] else 1
    except (ValueError, ArtifactError, PipelineMakeError, RunLockTimeout) as exc:
        out, rc = {"ok": False, "error": str(exc)}, 1
    print(json.dumps(out, indent=2))
    return rc


if __name__ == "__main__":
    sys.exit(main())
