#!/usr/bin/env python3
"""
The Eva options a module may carry, as typed values rather than raw tokens (stdlib only).

Every option here passes through one table, so params.json can neither smuggle a flag into the
Makefile nor turn a check off. Frama-C classifies each Eva parameter itself
(plugins/eva/src/parameters.ml, add_precision_dep / add_correctness_dep), and its kernel states
the difference (Emitter.create in emitter.mli): a tuning parameter "may improve a generated
element ... a valid status cannot become invalid", while a correctness parameter "may fully
change" it. So:

- `tuning` options only change precision and cost. Runs that differ only in those check the same
  program under the same assumptions, which is what lets eva_tuning.py compare and combine them.
- `-eva-context-depth` is a correctness parameter: it changes the initial state. It is allowed
  for a whole module, never below its default of 2 (a shallower context analyses fewer states),
  and runs with different values are never combined.

`multidim` is the only domain that can be added here; the base domains stay enabled.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from eva_loops import loop_ref_problem

MAX_INT_OPTION = 1_000_000
EXTRA_DOMAINS = ("multidim",)
SPLIT_RETURN_WORDS = ("auto", "full")
EQUALITY_THROUGH_CALLS = ("none", "formals", "all")
ALLOC_BUILTIN_MODES = ("imprecise", "by_stack", "fresh", "fresh_weak")
STD_ALLOC_FUNCTIONS = ("malloc", "calloc", "realloc")
_SIMPLE_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
_C_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@dataclass(frozen=True)
class EvaOption:
    kind: str  # int | bool | enum | split_return | domains | func_list
    minimum: int = 0
    maximum: int = MAX_INT_OPTION
    choices: tuple[str, ...] = ()
    correctness: bool = False


EVA_OPTIONS: dict[str, EvaOption] = {
    "min-loop-unroll": EvaOption("int"),
    "auto-loop-unroll": EvaOption("int"),
    "widening-delay": EvaOption("int", minimum=1),
    "widening-period": EvaOption("int", minimum=1),
    "partition-history": EvaOption("int"),
    "slevel": EvaOption("int"),
    "ilevel": EvaOption("int", minimum=2),
    "plevel": EvaOption("int"),
    "subdivide-non-linear": EvaOption("int"),
    "unroll-recursive-calls": EvaOption("int"),
    "split-return": EvaOption("split_return"),
    "alloc-builtin": EvaOption("enum", choices=ALLOC_BUILTIN_MODES),
    "alloc-functions": EvaOption("func_list"),
    "remove-redundant-alarms": EvaOption("bool"),
    "octagon-through-calls": EvaOption("bool"),
    "equality-through-calls": EvaOption("enum", choices=EQUALITY_THROUGH_CALLS),
    "context-depth": EvaOption("int", minimum=2, correctness=True),
    "precision": EvaOption("int", maximum=11),
    "domains": EvaOption("domains"),
}


def option_problem(name: str, value: Any) -> str | None:
    """Why (`name`, `value`) is not allowed, or None."""
    spec = EVA_OPTIONS.get(name)
    if spec is None:
        return f"{name!r} is not an allowed Eva option (allowed: {', '.join(sorted(EVA_OPTIONS))})"
    if spec.kind == "bool":
        return None if isinstance(value, bool) else f"{name} must be true or false"
    if spec.kind == "int":
        if isinstance(value, bool) or not isinstance(value, int):
            return f"{name} must be an integer"
        if not spec.minimum <= value <= spec.maximum:
            return f"{name} must be between {spec.minimum} and {spec.maximum}"
        return None
    if spec.kind == "enum":
        return None if value in spec.choices else f"{name} must be one of {', '.join(spec.choices)}"
    if spec.kind == "split_return":
        if isinstance(value, bool):
            return f"{name} must be auto, full or an integer return code"
        if isinstance(value, int) or value in SPLIT_RETURN_WORDS:
            return None
        return f"{name} must be auto, full or an integer return code"
    if spec.kind == "func_list":
        if not isinstance(value, list) or not value or not all(isinstance(fn, str) for fn in value):
            return f"{name} must be a non-empty list of C function names"
        bad = [fn for fn in value if not _C_IDENT_RE.fullmatch(fn)]
        if bad or len(set(value)) != len(value):
            return f"{name} must contain unique valid C identifiers (got {value})"
        return None
    if not isinstance(value, list) or not value or not all(isinstance(d, str) for d in value):
        return f"{name} must be a non-empty list of domain names"
    unknown = sorted(set(value) - set(EXTRA_DOMAINS))
    if unknown or len(set(value)) != len(value):
        return f"{name} may only add {', '.join(EXTRA_DOMAINS)}, each once (got {value})"
    return None


def options_problem(options: Any) -> str | None:
    """Why a whole options mapping is not allowed, or None."""
    if not isinstance(options, Mapping):
        return "must be an object mapping Eva option names to values"
    for name, value in options.items():
        problem = option_problem(str(name), value)
        if problem:
            return problem
    return None


def parse_option(text: str) -> tuple[str, Any]:
    """`name=value` from a command line into its typed form. ValueError on anything not allowed."""
    name, sep, raw = text.partition("=")
    name = name.strip()
    if not sep:
        raise ValueError(f"{text!r} is not of the form name=value")
    spec = EVA_OPTIONS.get(name)
    value: Any = raw.strip()
    if spec is not None:
        if spec.kind == "int":
            value = _parse_int(name, raw)
        elif spec.kind == "bool":
            lowered = raw.strip().lower()
            if lowered not in ("true", "false"):
                raise ValueError(f"{name} must be true or false")
            value = lowered == "true"
        elif spec.kind == "split_return" and raw.strip() not in SPLIT_RETURN_WORDS:
            value = _parse_int(name, raw)
        elif spec.kind in ("domains", "func_list"):
            value = [d.strip() for d in raw.split(",") if d.strip()]
    problem = option_problem(name, value)
    if problem:
        raise ValueError(problem)
    return name, value


def _parse_int(name: str, raw: str) -> int:
    try:
        return int(raw.strip())
    except ValueError:
        raise ValueError(f"{name} must be an integer") from None


def format_option(name: str, value: Any) -> str:
    """The `name=value` form `parse_option` reads back."""
    if isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, list):
        text = ",".join(value)
    else:
        text = str(value)
    return f"{name}={text}"


def extra_domains(options: Mapping[str, Any]) -> list[str]:
    return list(options.get("domains") or [])


def framac_args(options: Mapping[str, Any]) -> list[str]:
    """Frama-C tokens for `options`, in a fixed order. `domains` goes through -eva-domains instead."""
    args: list[str] = []
    for name in sorted(options):
        spec = EVA_OPTIONS[name]
        value = options[name]
        if spec.kind == "domains":
            continue
        if spec.kind == "bool":
            args.append(f"-eva-{name}" if value else f"-eva-no-{name}")
        elif spec.kind == "func_list":
            funcs = list(dict.fromkeys([*STD_ALLOC_FUNCTIONS, *value]))
            args.extend([f"-eva-{name}", ",".join(funcs)])
        else:
            args.extend([f"-eva-{name}", str(value)])
    return args


def assumption_options(options: Mapping[str, Any]) -> dict[str, Any]:
    """The options that change what is analysed; runs must agree on them to be combined."""
    return {name: value for name, value in options.items() if EVA_OPTIONS[name].correctness}


def merge_options(base: Mapping[str, Any], overlay: Mapping[str, Any]) -> dict[str, Any]:
    """
    `base` refined by `overlay`: a numeric knob keeps the larger value, so a rung never lowers what
    the module already asks for; the other kinds take the overlay's value, and domains add up.
    """
    merged = dict(base)
    for name, value in overlay.items():
        kind = EVA_OPTIONS[name].kind
        if kind == "int" and name in merged:
            merged[name] = max(merged[name], value)
        elif kind in ("domains", "func_list") and name in merged:
            merged[name] = sorted(set(merged[name]) | set(value))
        else:
            merged[name] = value
    return merged


# ---------------------------------------------------------------------------
# The ladder
# ---------------------------------------------------------------------------
#
# Fixed configurations tried on a module that still has Unknowns. They are deliberately not nested:
# PARF (JCST 2025, Table A2) found no knob dominant on every program. slevel leads on average (0.490),
# then domains (0.258, already on in the base configuration), while partition-history helps some
# programs (x509-parser 0.407, khash 0.292) and hurts others (qlz-ex3 -0.167, and `tutorials`, where
# only a high slevel with no history removes the alarm). The rungs therefore change one concern each,
# and history stays out of the rung that raises slevel the most. Changing a rung changes results, so
# bump LADDER_VERSION with it: recorded decisions then no longer apply.

LADDER_VERSION = 1
# A trial may take this many times the base run, so a slower machine gets proportionally more time
# and finishes the same trials. The floor keeps very fast modules from cutting a rung off early.
TRIAL_TIMEOUT_FACTOR = 8
LOOP_TRIAL_TIMEOUT_FACTOR = 2
TRIAL_TIMEOUT_FLOOR_S = 600
TRIAL_TIMEOUT_CEILING_S = 7200
DEFAULT_LOOP_UNROLL = 256


@dataclass(frozen=True)
class Rung:
    name: str
    options: Mapping[str, Any]


LADDER: tuple[Rung, ...] = (
    Rung("slevel", {"slevel": 1000}),
    Rung("unroll", {"auto-loop-unroll": 1024, "min-loop-unroll": 256}),
    # History needs states to keep apart: Eva manual 6.5.1, and PARF 5 on its exponential appetite for slevel.
    Rung("history", {"partition-history": 2, "slevel": 500}),
    Rung("values", {"ilevel": 64, "plevel": 1000, "subdivide-non-linear": 100}),
    # Not multidim: Frama-C calls it experimental, and a Valid here can end a function's verification.
    # It stays available as a module option, where someone chooses it.
    Rung("relational", {"octagon-through-calls": True, "equality-through-calls": "formals"}),
    Rung("returns", {"split-return": "auto", "slevel": 500}),
    # Eva's own recipe for every knob at once. The pipeline always passes these two explicitly, and
    # -eva-precision never overrides an option set by hand, so they carry its values for level 8.
    Rung("precision", {"precision": 8, "slevel": 500, "auto-loop-unroll": 384}),
)
RUNG_NAMES = tuple(rung.name for rung in LADDER)


def loop_unroll_level(max_input_size: Any) -> int:
    """
    N for a per-loop trial. Loupe: an over-large N is harmless, since Eva stops at the loop's real bound
    (Eva manual 6.4.1), so it only has to cover the longest input the harness can feed a parsing loop.
    """
    size = max_input_size if isinstance(max_input_size, int) and not isinstance(max_input_size, bool) else 0
    return min(MAX_INT_OPTION, max(DEFAULT_LOOP_UNROLL, size + 1))


def trial_timeout(base_elapsed_s: float | None, module_timeout: int | None = None) -> int:
    """Seconds one rung or loop trial may take. An explicit per-module timeout always wins."""
    if module_timeout:
        return int(module_timeout)
    scaled = TRIAL_TIMEOUT_FACTOR * float(base_elapsed_s or 0)
    return int(min(TRIAL_TIMEOUT_CEILING_S, max(TRIAL_TIMEOUT_FLOOR_S, scaled)))


def loop_trial_timeout(rung_elapsed_s: float | None) -> int:
    """
    Seconds for one loop trial: they run one after another on one CPU, so they get a tighter limit than
    the rungs, relative to the rung they build on. This bounds the search at about 16 rung runs.
    """
    scaled = LOOP_TRIAL_TIMEOUT_FACTOR * float(rung_elapsed_s or 0)
    return int(min(TRIAL_TIMEOUT_CEILING_S, max(TRIAL_TIMEOUT_FLOOR_S, scaled)))


def settings_digest(settings: Mapping[str, Any]) -> str:
    """Digest of the module settings a decision was made under; other settings mean another search."""
    blob = json.dumps(settings, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def tuned_record_problem(record: Any) -> str | None:
    """Why a recorded tuning decision cannot be used, or None. It reaches Make, so it is checked like any flag."""
    if not isinstance(record, Mapping):
        return "must be an object"
    problem = options_problem(record.get("options", {}))
    if problem:
        return f"options: {problem}"
    if not _simple_name(record.get("rung")) or not _simple_name(record.get("selected")):
        return "rung and selected must be simple names"
    entries = record.get("contributors", [])
    if not isinstance(entries, list):
        return "contributors must be a list"
    groups = [record.get("loops", [])]
    for entry in entries:
        if not isinstance(entry, Mapping) or not _simple_name(entry.get("name")):
            return "each contributor must name a run"
        problem = options_problem(entry.get("options", {}))
        if problem:
            return f"contributor {entry.get('name')}: {problem}"
        groups.append(entry.get("loops", []))
    for group in groups:
        if not isinstance(group, list):
            return "loops must be a list"
        for item in group:
            if not isinstance(item, Mapping):
                return "each loop must be an object"
            problem = loop_ref_problem(item.get("file"), item.get("function"), item.get("ordinal"), item.get("unroll"))
            if problem:
                return f"loop: {problem}"
    return None


def _simple_name(value: Any) -> bool:
    return isinstance(value, str) and bool(_SIMPLE_NAME_RE.fullmatch(value))


def record_is_current(record: Any, digest: str, input_digest: str | None) -> bool:
    """A decision applies to the settings and sources it was made for, under this ladder."""
    return (
        isinstance(record, Mapping)
        and tuned_record_problem(record) is None
        and record.get("ladder") == LADDER_VERSION
        and record.get("settings_digest") == digest
        and bool(input_digest)
        and record.get("input_digest") == input_digest
    )


def recorded_rungs(record: Mapping[str, Any]) -> list[str]:
    """The ladder rungs a replay has to run, in ladder order."""
    wanted = {record.get("rung")} | {
        entry.get("name") for entry in record.get("contributors", []) if not entry.get("loops")
    }
    return [name for name in RUNG_NAMES if name in wanted]
