"""
Replay and minimization of fuzz failures: replay of artifacts and candidates' reproducers on
their module's binary, the build specs they replay on, and cvise/creduce minimization.

Moved out of run_eacsl_fuzz.py (D3). Callers reach these names as `crash_replay.<name>` so that a
test patch on this module applies to every caller (D12).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
from pathlib import Path
from typing import Any

import fuzz_build
import sandbox_exec
from eacsl_toolchain import (
    is_eacsl_instrumented,
)
from failure_identity import failure_fingerprint as _failure_fingerprint
from failure_identity import (
    is_libfuzzer_out_of_memory,
    is_sanitizer_allocation_cap,
    needs_attribution,
    parse_eacsl_resource_abort,
    parse_runtime_failure,
    stack_frames,
)
from fingerprint import (
    make_fingerprint,
)
from framac_common import (
    atomic_write_json,
    load_json_optional,
    utc_now,
)
from fuzz_common import (
    DEFAULT_PER_INPUT_TIMEOUT_S,
    DEFAULT_SELFTEST_JSON,
    DUAL_ENGINE,
    SANITIZER_RUNTIME_ENV,
    _artifact_kind,
    _collect_inputs,
    derive_seed,
    replay_artifact_dir,
    sha256_file,
)
from resources import (
    FUZZ_RSS_LIMIT_MB,
)
from sandbox_exec import Limits, SandboxUnavailable


def replay_artifact(
    binary: Path,
    artifact: Path,
    scratch: Path,
    timeout_s: int = 60,
    *,
    module: str = "",
    per_input_timeout: int = DEFAULT_PER_INPUT_TIMEOUT_S,
    seed: int | None = None,
) -> dict:
    """
    Replay one input in the sandbox with a fixed per-input `-timeout`, the fixed `-rss_limit_mb`
    and a deterministic `-seed` (derive_seed); report the parsed failure and whether it reproduced.
    """
    binary = Path(binary)
    seed = derive_seed(binary, module) if seed is None else seed
    wall = max(int(timeout_s), 2 * int(per_input_timeout) + 10)
    res = sandbox_exec.run_sandboxed(
        [
            str(binary.resolve()),
            "-runs=1",
            f"-timeout={per_input_timeout}",
            f"-rss_limit_mb={FUZZ_RSS_LIMIT_MB}",
            f"-seed={seed}",
            f"-artifact_prefix={replay_artifact_dir(scratch)}/",
            str(Path(artifact).resolve()),
        ],
        writable=[scratch],
        timeout_s=wall,
        limits=Limits(cpu_seconds=wall * 2),
        extra_env=SANITIZER_RUNTIME_ENV,
    )
    out = res.stdout + "\n" + res.stderr
    failure = parse_runtime_failure(out)
    return {
        "reproduced": res.returncode != 0 or res.timed_out,
        "returncode": res.returncode,
        "timed_out": res.timed_out,
        "failure": failure,
        # Read from the whole output: the runtime prints its message before the stack, out of the tail.
        "resource_abort": None if failure else parse_eacsl_resource_abort(out),
        "out_of_memory": is_libfuzzer_out_of_memory(out),
        "sandbox": res.sandbox,
        "seed": seed,
        "log_tail": out[-3000:],
        "frames": stack_frames(out),
    }


def resource_abort_record(abort: dict, attribution: dict | None, kind: str = "crash") -> dict | None:
    """
    An artifact's `eacsl_resource_abort`: the E-ACSL runtime stopped on its own limit (no target check
    failed), and what the sanitizer replay of the same input said: `unavailable` (no sanitizer build),
    `not_reproduced`, `no_failure`, or `allocation_size_too_big` (ASan refused the same request past its own
    allocator maximum: the same tool limit). None when the sanitizer replay reported any other failure,
    located or not: the artifact then stays an ordinary (unparsed) crash for a verifier.

    An `oom-` artifact is libFuzzer's own out-of-memory report: when the sanitizer build of the same input
    runs out of memory too, the E-ACSL limit does not explain it, and it stays for a verifier (None).
    """
    san_failure = attribution.get("failure") if attribution else None
    if is_sanitizer_allocation_cap(san_failure):
        return {**abort, "sanitizer_replay": "allocation_size_too_big"}
    if san_failure:
        return None
    if kind == "oom" and attribution and attribution.get("out_of_memory"):
        return None
    if not attribution:
        san = "unavailable"
    elif not attribution.get("reproduced"):
        san = "not_reproduced"
    else:
        san = "no_failure"
    return {**abort, "sanitizer_replay": san}


def replay_inputs(
    binary: Path,
    inputs: list[Path],
    scratch: Path,
    *,
    module: str = "",
    per_input_timeout: int = DEFAULT_PER_INPUT_TIMEOUT_S,
    attribution_builder=None,
) -> list[dict]:
    """Replay every input exactly once; one campaign-shaped artifact record per input."""
    scratch.mkdir(parents=True, exist_ok=True)
    artifacts: list[dict] = []
    for path in inputs:
        rep = replay_artifact(binary, path, scratch, module=module, per_input_timeout=per_input_timeout)
        failure = rep.get("failure")
        entry: dict = {
            "artifact": path.as_posix(),
            "kind": _artifact_kind(path.name) or "crash",
            "sha256": sha256_file(path),
            "size_bytes": path.stat().st_size,
            "reproducible": bool(rep.get("reproduced")),
            "failure": None,
            "fingerprint": None,
            "failure_source": "primary" if failure else None,
            "returncode": rep.get("returncode"),
            "timed_out": rep.get("timed_out"),
            "seed": rep.get("seed"),
            "replay_log_tail": rep.get("log_tail", ""),
        }
        if entry["reproducible"] and needs_attribution(failure) and attribution_builder is not None:
            san_bin = attribution_builder()
            if san_bin is not None:
                san = replay_artifact(Path(san_bin), path, scratch, module=module, per_input_timeout=per_input_timeout)
                entry["attribution"] = {
                    "source": "sanitizer_replay",
                    "binary": str(san_bin),
                    "reproduced": san.get("reproduced"),
                    "failure": san.get("failure"),
                    "out_of_memory": bool(san.get("out_of_memory")),
                }
                if san.get("failure") and not needs_attribution(san["failure"]):
                    failure = san["failure"]
                    entry["failure_source"] = "sanitizer_replay"
        entry["failure"] = failure
        if not failure and rep.get("resource_abort"):
            record = resource_abort_record(rep["resource_abort"], entry.get("attribution"), entry["kind"])
            if record is not None:
                entry["eacsl_resource_abort"] = record
        if failure:
            entry["fingerprint"] = make_fingerprint(
                failure.get("file") or "unknown",
                failure.get("function") or "unknown_function",
                failure.get("alarm_kind") or failure.get("kind") or "crash",
                failure.get("predicate") or "",
            )
        artifacts.append(entry)
    return artifacts


def _slim_compile(comp: dict) -> dict:
    return {k: comp.get(k) for k in ("engine", "returncode", "reason", "binary", "compile_log", "cache")}


def prepare_replay_binary(
    module: str,
    sources: list[str],
    out_bin: Path,
    *,
    attribution: bool = True,
    **build_options,
) -> dict:
    """
    Build the module binary for replays (normally a cache hit on the Make or campaign build).
    `security_props` among `build_options` (`--security-props PATH|none`) names the run's MetAcsl
    properties as for the campaign's build: the cache key holds their text, not the file's path, so
    a replay that names the file another way restores the same entry. A replay that builds in another
    directory is another entry (the key holds the directory, as for any build) with the same
    fingerprints: the identity of a violation does not hold the path of its meta file
    (failure_identity._meta_failure).
    """
    build = fuzz_build.build_module_binary(sources, Path(out_bin), **build_options)
    comp = build["compile"]
    prepared: dict = {
        "module": module,
        "binary": None,
        "engine_used": build["engine_used"],
        "compile": _slim_compile(comp),
        "cache": comp.get("cache"),
        "attribution_builder": None,
    }
    # The MetAcsl properties of the E-ACSL build (or of the attempt the sanitizers replaced): only
    # with the engine on, so a replay report without it has the keys it always had.
    for built in (comp, build.get("eacsl_compile_attempt")):
        if isinstance(built, dict) and isinstance(built.get("security_props"), dict):
            prepared["security_props"] = built["security_props"]
            break
    if build["engine_fallback_reason"]:
        prepared["engine_fallback_reason"] = build["engine_fallback_reason"]
    if comp["returncode"] != 0:
        prepared["reason"] = f"compile_error ({comp.get('reason') or 'returncode ' + str(comp['returncode'])})"
        return prepared
    prepared["binary"] = Path(comp["binary"])
    if attribution and build["engine_used"] == "eacsl":
        prepared["attribution_builder"] = fuzz_build._sanitizer_attribution_builder(
            build.get("sources") or sources,
            Path(out_bin),
            build_options.get("cppflags", "-I."),
            build_options.get("ldflags", ""),
            use_cache=build_options.get("use_cache", True),
        )
    return prepared


def replay_report(
    module: str,
    inputs: list[Path],
    scratch: Path,
    *,
    prepared: dict | None = None,
    binary: Path | None = None,
    per_input_timeout: int = DEFAULT_PER_INPUT_TIMEOUT_S,
) -> dict:
    """
    Replay `inputs` on a prepared (built) or given binary. `status` is `reproduced` when any input
    fails, `not_reproduced` when none does, `error` when nothing could be replayed. The
    `artifacts[]` records are the campaign's, so `ingest-verifier --replay-report` accepts the report.
    """
    files, missing = _collect_inputs(inputs)
    report: dict = {
        "mode": "replay",
        "module": module,
        "status": "error",
        "binary": None,
        "inputs": [str(i) for i in inputs],
        "missing_inputs": missing,
        "per_input_timeout": per_input_timeout,
        "rss_limit_mb": FUZZ_RSS_LIMIT_MB,
        "artifacts": [],
    }
    attribution_builder = None
    if prepared is not None:
        for key in ("engine_used", "engine_fallback_reason", "compile", "cache", "security_props"):
            if key in prepared:
                report[key] = prepared[key]
        if prepared.get("binary") is None:
            report["reason"] = prepared.get("reason") or "no binary"
            return report
        bin_path = Path(prepared["binary"])
        attribution_builder = prepared.get("attribution_builder")
    elif binary is not None:
        bin_path = Path(binary)
        if not bin_path.is_file():
            report["reason"] = f"binary not found: {bin_path}"
            return report
        report["engine_used"] = "eacsl" if is_eacsl_instrumented(bin_path) else "unknown"
    else:
        report["reason"] = "replay needs --binary, or --sources with --out-bin"
        return report
    report["binary"] = str(bin_path)
    report["seed"] = derive_seed(bin_path, module)
    if not files:
        report["reason"] = "no_inputs"
        return report
    try:
        report["artifacts"] = replay_inputs(
            bin_path,
            files,
            scratch,
            module=module,
            per_input_timeout=per_input_timeout,
            attribution_builder=attribution_builder,
        )
    except SandboxUnavailable as exc:
        report["reason"] = f"sandbox_unavailable: {exc}"
        return report
    report["status"] = "reproduced" if any(a["reproducible"] for a in report["artifacts"]) else "not_reproduced"
    return report


def acsl_include_dir() -> Path | None:
    for base in (Path("/opt/framac-pipeline/templates"), Path(__file__).resolve().parent.parent / "templates"):
        if (base / "acsl").is_dir():
            return base / "acsl"
    return None


def _unit_harness_module(module: str, harness_dir: Path, file: str | None = None, function: str | None = None) -> str:
    """
    The harness module standing for a link unit's name (an Eva candidate may carry its unit, step
    I5b): the module itself when it has a sidecar, else the sub-module whose scope holds
    `file`#`function` (workspace_overlay.harness_module_for_function, as pipeline_make and the
    ledger pick it), else the unit's first sub-module. The DAG is read next to the harness
    directory (workspace/reports/callgraph_dag.json).
    """
    harness_dir = Path(harness_dir)
    if (harness_dir / f"harness_{module}.json").is_file():
        return module
    from module_map import ModuleMap, load_sidecars

    dag = load_json_optional(harness_dir.parent / "reports" / "callgraph_dag.json", None)
    mm = ModuleMap(dag if isinstance(dag, dict) else None, load_sidecars(harness_dir))
    try:
        from workspace_overlay import harness_module_for_function
    except ImportError:
        return mm.harness_module_for(module) or module
    return harness_module_for_function(mm, module, file, function) or module


def _sidecar_build_spec(module: str, harness_dir: Path, file: str | None = None, function: str | None = None) -> dict:
    """
    Fallback build spec when scripts/pipeline_make.py cannot be imported: the harness sidecar's
    sources (the harness alone when it `include_source`s the target) plus the harness, and its
    cppflags plus -I<templates>/acsl (once), as in the documented campaign command. A link unit's
    name resolves to the harness module whose scope holds the candidate's `file`#`function` (else
    its first one), returned in `harness_module`.
    """
    requested, module = module, _unit_harness_module(module, harness_dir, file, function)
    sidecar = Path(harness_dir) / f"harness_{module}.json"
    meta = load_json_optional(sidecar, None)
    if not isinstance(meta, dict):
        raise FileNotFoundError(f"harness sidecar {sidecar} not found")
    harness = (Path(harness_dir) / f"harness_{module}.c").as_posix()
    sources: list[str] = []
    if not meta.get("include_source"):
        for raw in meta.get("sources") or []:
            src = str(raw).replace("\\", "/").strip()
            src = src[len("/framac-run/") :] if src.startswith("/framac-run/") else src
            if src and Path(src).name != f"harness_{module}.c" and src not in sources:
                sources.append(src)
    tokens = shlex.split(meta.get("cppflags") or "-I.")
    acsl_dir = acsl_include_dir()
    if (
        acsl_dir is not None
        and acsl_dir.as_posix() not in (meta.get("cppflags") or "")
        and f"-I{acsl_dir.as_posix()}" not in tokens
    ):
        tokens.append(f"-I{acsl_dir.as_posix()}")
    spec = {"sources": [*sources, harness], "cppflags": shlex.join(tokens), "ldflags": meta.get("ldflags") or ""}
    if module != requested:
        spec["harness_module"] = module
    return spec


def replay_build_spec(
    module: str,
    harness_dir: Path = Path("workspace/harnesses"),
    file: str | None = None,
    function: str | None = None,
) -> dict:
    """
    Sources, cppflags and ldflags of a module's fuzz binary. Inside the pipeline this is
    `pipeline_make.module_build_spec`: exactly what `make build` and the fuzz recipe pass, so a
    replay reuses their cache entry and never rebuilds workspace/harnesses/fuzz_<mod> with other
    flags or sources (ValueError when Make cannot build the module). The harness sidecar decides
    only when pipeline_make cannot be imported. A candidate's module may be a link unit: the spec
    is then its harness module's, the one whose scope holds the crashing `file`#`function` (as the
    ledger picks it), named in `harness_module` (the binary is fuzz_<harness_module>).
    """
    try:
        import pipeline_make  # imported lazily: replays work without the Make layer
    except ImportError:
        return _sidecar_build_spec(module, harness_dir, file, function)
    return pipeline_make.module_build_spec(module, Path("."), file, function)


def _candidate_slug(fingerprint: str) -> str:
    base = re.sub(r"[^A-Za-z0-9_.-]+", "_", fingerprint).strip("._")[:80] or "candidate"
    return f"{base}-{hashlib.sha256(fingerprint.encode()).hexdigest()[:10]}"


def _candidate_engine(cand: dict) -> str:
    """
    The engine that found the candidate: its report's engine_used, or for a campaign that used
    both engines, the `engine` of the report's artifact with the candidate's fingerprint; else auto.
    """
    fingerprint = cand.get("fingerprint")
    for rel in cand.get("tool_outputs") or []:
        try:
            data = json.loads(Path(rel).read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            continue
        engine = data.get("engine_used") if isinstance(data, dict) else None
        if engine in ("eacsl", "sanitizers"):
            return engine
        if engine == DUAL_ENGINE:
            for art in data.get("artifacts") or []:
                if isinstance(art, dict) and art.get("fingerprint") == fingerprint:
                    if art.get("engine") in ("eacsl", "sanitizers"):
                        return art["engine"]
    return "auto"


def _reproducer_paths(cand: dict) -> list[Path]:
    paths: list[Path] = []
    for rep in cand.get("reproducers") or []:
        raw = rep.get("input") if isinstance(rep, dict) else rep
        if isinstance(raw, str) and raw:
            paths.append(Path(raw))
    return paths


_ENGINES = ("eacsl", "sanitizers")


def _security_props_option(spec: dict, override: str | None) -> dict:
    """
    The `security_props` keyword of a candidate's replay build, {} when nothing names a file: the
    caller's `--security-props`, else the file Make passes to the module's build and campaign
    (`security_props` of pipeline_make.module_build_spec, there only with the engine on). Without
    either, fuzz_build resolves the run's default as the campaign did.
    """
    value = override if override is not None else spec.get("security_props")
    return {"security_props": str(value)} if value else {}


def _accepted_fingerprints(cand: dict) -> list[str]:
    """The candidate's key, then the fingerprint of each observation: every failure that is this candidate."""
    out = [str(cand.get("fingerprint") or "")]
    for obs in cand.get("observations") or []:
        fp = str(obs.get("fingerprint") or "") if isinstance(obs, dict) else ""
        if fp and fp not in out:
            out.append(fp)
    return out


def _reproducers_by_engine(cand: dict, default: str, *, use_observations: bool) -> dict[str, list[Path]]:
    """
    The candidate's reproducers grouped by the engine to replay them on. A reproducer named by an
    observation (`observations[].reproducer`) replays on that observation's engine; the others on `default`.
    Candidates without observations, and a caller that forces an engine, give one group: as before.
    """
    named: dict[str, str] = {}
    if use_observations:
        for obs in cand.get("observations") or []:
            if isinstance(obs, dict) and obs.get("reproducer") and obs.get("engine") in _ENGINES:
                named.setdefault(str(Path(str(obs["reproducer"]))), str(obs["engine"]))
    groups: dict[str, list[Path]] = {}
    for path in _reproducer_paths(cand):
        groups.setdefault(named.get(str(path), default), []).append(path)
    ordered = {default: groups[default]} if default in groups else {}
    for name in (*_ENGINES, *sorted(groups)):
        if name in groups and name not in ordered:
            ordered[name] = groups[name]
    return ordered


def _prepared_replay(
    module: str,
    spec: dict | str,
    engine_name: str,
    *,
    own_engine: str,
    bin_dir: Path,
    prepared_by_key: dict[tuple[str, str], dict],
    attribution: bool,
    selftest_json: Path | None,
    machdep: str,
    security_props: str | None = None,
) -> dict:
    """
    The replay binary for one engine of a module's harness. The candidate's own engine keeps the path of
    `make build`; another engine (an observation's, D1) builds as cross_<engine>_<harness> so the two never share a file.
    """
    if isinstance(spec, str):
        return prepared_by_key.setdefault((f"!{module}", engine_name), {"binary": None, "reason": spec})
    harness_module = str(spec.get("harness_module") or module)
    key = (harness_module, engine_name)
    if key not in prepared_by_key:
        name = f"fuzz_{harness_module}" if engine_name == own_engine else f"cross_{engine_name}_{harness_module}"
        prepared_by_key[key] = prepare_replay_binary(
            harness_module,
            spec["sources"],
            bin_dir / name,
            attribution=attribution,
            engine=engine_name,
            selftest_json=selftest_json,
            machdep=machdep,
            cppflags=spec["cppflags"],
            ldflags=spec["ldflags"],
            rte_initialized=bool(spec.get("rte_initialized", True)),
            libc_checks=bool(spec.get("libc_checks", True)),
            **_security_props_option(spec, security_props),
        )
    return prepared_by_key[key]


def _merged_replay_report(reports: list[tuple[str, dict]]) -> dict:
    """
    One report from the replays of each engine group. A single group is returned as it is. With several,
    the first group's report is kept and its artifacts are joined by every group's; `engines` names each group's status.
    """
    first = reports[0][1]
    if len(reports) == 1:
        return first
    merged = dict(first)
    merged["artifacts"] = [a for _, rep in reports for a in rep.get("artifacts") or []]
    merged["engines"] = {name: rep.get("status") for name, rep in reports}
    return merged


def _cross_engine_replay(
    *,
    module: str,
    harness_module: str,
    spec: dict,
    reproducers: list[Path],
    other: str,
    bin_dir: Path | None,
    scratch: Path,
    per_input_timeout: int,
    prepared_cache: dict[tuple[str, str], dict],
    attribution: bool,
    selftest_json: Path | None,
    machdep: str,
    security_props: str | None = None,
) -> dict:
    """
    Replay a candidate's reproducers on the other engine's binary of its module (D1b). A build that fails
    is recorded (`build_failed`) and skipped. `failures` lists each distinct failure once, by its fingerprint.
    """
    key = (harness_module, other)
    if key not in prepared_cache:
        out_bin = (bin_dir if bin_dir is not None else Path("workspace/harnesses")) / f"cross_{other}_{harness_module}"
        prepared_cache[key] = prepare_replay_binary(
            harness_module,
            spec["sources"],
            out_bin,
            attribution=attribution,
            engine=other,
            selftest_json=selftest_json,
            machdep=machdep,
            cppflags=spec["cppflags"],
            ldflags=spec["ldflags"],
            rte_initialized=bool(spec.get("rte_initialized", True)),
            libc_checks=bool(spec.get("libc_checks", True)),
            **_security_props_option(spec, security_props),
        )
    prepared = prepared_cache[key]
    if prepared.get("binary") is None:
        return {"engine": other, "status": "build_failed", "reason": prepared.get("reason"), "failures": []}
    report = replay_report(module, reproducers, scratch, prepared=prepared, per_input_timeout=per_input_timeout)
    failures: list[dict] = []
    seen: set[str] = set()
    for art in report.get("artifacts") or []:
        fp = art.get("fingerprint")
        if not fp or fp in seen:
            continue
        seen.add(fp)
        failure = art.get("failure") or {}
        failures.append(
            {
                "fingerprint": fp,
                "file": failure.get("file"),
                "line": failure.get("line"),
                "function": failure.get("function"),
                "kind": failure.get("alarm_kind") or failure.get("kind"),
            }
        )
    return {"engine": other, "status": report.get("status"), "failures": failures}


def replay_candidates(
    candidates_path: Path,
    harness_dir: Path,
    out_dir: Path,
    *,
    bin_dir: Path | None = None,
    engine: str | None = None,
    selftest_json: Path | None = DEFAULT_SELFTEST_JSON,
    machdep: str = "gcc_x86_64",
    per_input_timeout: int = DEFAULT_PER_INPUT_TIMEOUT_S,
    attribution: bool = True,
    only: str | None = None,
    inputs: list[Path] | None = None,
    out_json: Path | None = None,
    cross_engine: bool = False,
    security_props: str | None = None,
) -> dict:
    """
    Replay the reproducers of every unverified candidate on its module's binary, built with
    `replay_build_spec` (Make's sources and flags) into `<bin_dir>/fuzz_<mod>`, the path of
    `make build` and of the campaign, so the build is a cache hit. Candidates whose module Make
    cannot build get an `error` report. Writes `<out_dir>/<fingerprint-slug>.json` per candidate
    and `index.json`, which maps each fingerprint to its report.

    With `only` (a candidate fingerprint), replay the given `inputs` instead of the candidate's own
    reproducers, on that candidate's binary, whatever its status. This is how the parent checks the
    reproducers a Crash Verifier lists from its own scratch before `ingest-verifier`. Only `out_json`
    is written: the candidate's own report and `index.json` stay as they are.

    `security_props` (`--security-props PATH|none`) names the MetAcsl properties the E-ACSL replay
    builds check; by default they are the ones Make gives the module's build (`_security_props_option`).
    """
    candidates = load_json_optional(Path(candidates_path), [])
    todo = [c for c in candidates if isinstance(c, dict) and c.get("status") == "unverified" and _reproducer_paths(c)]
    if only is not None:
        if not inputs or out_json is None:
            raise ValueError("replay_candidates(only=...) needs inputs and out_json")
        todo = [c for c in candidates if isinstance(c, dict) and c.get("fingerprint") == only][:1]
        out_dir = Path(out_json).parent
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    bin_dir = Path(bin_dir) if bin_dir is not None else Path("workspace/harnesses")
    specs: dict[tuple[str, str, str], dict | str] = {}
    prepared_by_key: dict[tuple[str, str], dict] = {}
    cross_prepared: dict[tuple[str, str], dict] = {}
    index: dict[str, dict] = {}
    by_status: dict[str, int] = {}
    for cand in todo:
        fingerprint = str(cand.get("fingerprint") or "")
        module = str(cand.get("module") or "")
        loc = cand.get("location")
        loc = loc if isinstance(loc, dict) else {}
        file, function = str(loc.get("file") or ""), str(loc.get("function") or "")
        eng = engine or _candidate_engine(cand)
        # A candidate naming a link unit replays on the harness whose scope holds its function.
        skey = (module, file, function)
        if skey not in specs:
            try:
                specs[skey] = replay_build_spec(module, Path(harness_dir), file or None, function or None)
            except (OSError, ValueError, RuntimeError) as exc:
                specs[skey] = f"no build spec for module {module!r}: {exc}"
        spec = specs[skey]
        scratch = out_dir / ".scratch" / (re.sub(r"[^A-Za-z0-9_.-]+", "_", module) or "unknown")
        # Each reproducer replays on its own engine (its observation's, D1); the candidate's engine otherwise.
        groups = (
            {eng: list(inputs or [])}
            if only is not None
            else _reproducers_by_engine(cand, eng, use_observations=engine is None)
        ) or {eng: []}
        replays: list[tuple[str, dict]] = []
        for group_eng, paths in groups.items():
            prepared = _prepared_replay(
                module,
                spec,
                group_eng,
                own_engine=eng,
                bin_dir=bin_dir,
                prepared_by_key=prepared_by_key,
                attribution=attribution,
                selftest_json=selftest_json,
                machdep=machdep,
                security_props=security_props,
            )
            group_scratch = scratch if group_eng == eng else scratch.parent / f"{scratch.name}-{group_eng}"
            replays.append(
                (
                    group_eng,
                    replay_report(
                        module,
                        paths,
                        group_scratch,
                        prepared=prepared,
                        per_input_timeout=per_input_timeout,
                    ),
                )
            )
        report = _merged_replay_report(replays)
        report["candidate_fingerprint"] = fingerprint
        # Any failure that is this candidate: its key or one of its observations' fingerprints (D1).
        accepted = _accepted_fingerprints(cand)
        report["fingerprint_matches"] = any(a.get("fingerprint") in accepted for a in report["artifacts"])
        report_path = Path(out_json) if out_json is not None else out_dir / f"{_candidate_slug(fingerprint)}.json"
        atomic_write_json(report_path, report)
        entry: dict[str, Any] = {"report": report_path.as_posix(), "module": module, "status": report["status"]}
        harness_module = module if isinstance(spec, str) else str(spec.get("harness_module") or module)
        if cross_engine and only is None and eng in ("eacsl", "sanitizers") and not isinstance(spec, str):
            # D1b: the same reproducers on the other engine's binary, so one bug seen by both links (link-related).
            other = "sanitizers" if eng == "eacsl" else "eacsl"
            entry["cross_engine"] = _cross_engine_replay(
                module=module,
                harness_module=harness_module,
                spec=spec,
                reproducers=_reproducer_paths(cand),
                other=other,
                bin_dir=bin_dir,
                scratch=out_dir / ".scratch" / f"{_candidate_slug(fingerprint)}-cross-{other}",
                per_input_timeout=per_input_timeout,
                prepared_cache=cross_prepared,
                attribution=attribution,
                selftest_json=selftest_json,
                machdep=machdep,
                security_props=security_props,
            )
        index[fingerprint] = entry
        by_status[report["status"]] = by_status.get(report["status"], 0) + 1
    if only is not None and out_json is not None:
        if not todo:
            by_status["error"] = 1
            atomic_write_json(
                Path(out_json),
                {
                    "mode": "replay",
                    "status": "error",
                    "reason": f"unknown candidate fingerprint: {only}",
                    "candidate_fingerprint": only,
                    "inputs": [str(i) for i in inputs or []],
                    "artifacts": [],
                },
            )
        return {
            "mode": "replay-candidates",
            "status": "error" if by_status.get("error") else "ok",
            "candidates": len(todo),
            "by_status": by_status,
            "report": Path(out_json).as_posix(),
        }
    index_path = out_dir / "index.json"
    atomic_write_json(
        index_path,
        {
            "generated_at": utc_now(),
            "candidates_file": Path(candidates_path).as_posix(),
            "by_fingerprint": index,
        },
    )
    return {
        "mode": "replay-candidates",
        "status": "error" if by_status.get("error") else "ok",
        "candidates": len(todo),
        "by_status": by_status,
        "index": index_path.as_posix(),
    }


# ---------------------------------------------------------------------------
# Crash-input minimization with cvise/creduce (upstream share/analysis-scripts/creduce.sh
# pattern, adapted: the interest test replays each variant on the E-ACSL binary and accepts it
# only if it still crashes with the same failure fingerprint).
# ---------------------------------------------------------------------------


def find_creduce() -> str | None:
    """The cvise (Python port of creduce) or creduce binary: $CREDUCE first, then PATH."""
    env = os.environ.get("CREDUCE")
    if env and Path(env).is_file():
        return env
    for name in ("cvise", "creduce"):
        found = shutil.which(name)
        if found:
            return found
    return None


def minimize_interest(
    binary: Path,
    variant: Path,
    scratch: Path,
    fingerprint: str | None,
    *,
    module: str = "",
    per_input_timeout: int = DEFAULT_PER_INPUT_TIMEOUT_S,
) -> bool:
    """
    cvise interest test: the variant still crashes the binary with one of the fingerprints. `fingerprint` may
    name several, comma-separated (a candidate's key and its observations', D1).
    """
    rep = replay_artifact(binary, variant, scratch, module=module, per_input_timeout=per_input_timeout)
    if not rep.get("reproduced"):
        return False
    fp = _failure_fingerprint(rep.get("failure"))
    return fp is not None and (fingerprint is None or fp in fingerprint.split(","))


def minimize_input(
    binary: Path,
    input_path: Path,
    scratch: Path,
    *,
    module: str = "",
    fingerprint: str | None = None,
    max_time_s: int = 600,
    jobs: int = 4,
    per_input_timeout: int = DEFAULT_PER_INPUT_TIMEOUT_S,
    tool: str | None = None,
) -> dict:
    """
    Minimize one crash input with cvise/creduce, run under the sandbox with a wall-clock cap. The
    variant file is updated in place as better variants are found, so a timeout still leaves the
    best-so-far. The result is verified by one final replay before it is reported.
    """
    binary = Path(binary)
    input_path = Path(input_path)
    scratch = Path(scratch)
    tool = tool or find_creduce()
    report: dict = {
        "mode": "minimize",
        "input": input_path.as_posix(),
        "binary": binary.as_posix(),
        "tool": tool,
        "fingerprint": fingerprint,
        "status": "error",
        "reason": None,
        "minimized": None,
        "original_size_bytes": None,
        "minimized_size_bytes": None,
        "reduction_pct": None,
        "reproduced": False,
        "passes": None,
        "timed_out": False,
        "log_tail": "",
    }
    if tool is None:
        report["reason"] = "cvise/creduce not found (set CREDUCE or install the cvise package)"
        return report
    if not binary.is_file():
        report["reason"] = f"binary not found: {binary}"
        return report
    if not input_path.is_file():
        report["reason"] = f"input not found: {input_path}"
        return report
    report["original_size_bytes"] = input_path.stat().st_size
    work = scratch / "creduce"
    work.mkdir(parents=True, exist_ok=True)
    variant = work / input_path.name
    shutil.copyfile(input_path, variant)
    script_path = Path(__file__).resolve()
    interest = work / "interest.sh"
    interest.write_text(
        "#!/bin/sh\n"
        f"exec python3 {shlex.quote(str(script_path))} minimize-interest"
        f" --binary {shlex.quote(str(binary.resolve()))}"
        f" --fingerprint {shlex.quote(fingerprint or '')}"
        f" --module {shlex.quote(module)}"
        f" --per-input-timeout {int(per_input_timeout)}"
        f" --scratch-dir {shlex.quote(str(scratch.resolve()))}"
        ' "$1"\n',
        encoding="utf-8",
    )
    interest.chmod(0o755)
    # --not-c: inputs are raw fuzzer bytes, not C sources, so skip the parsability check.
    cmd = [tool, "--not-c", "-n", str(max(1, int(jobs))), str(interest), str(variant)]
    try:
        res = sandbox_exec.run_sandboxed(
            cmd,
            writable=[work, scratch],
            timeout_s=max(30, int(max_time_s)),
            limits=Limits(cpu_seconds=max(60, int(max_time_s)) * max(1, int(jobs))),
        )
    except SandboxUnavailable as exc:
        report["reason"] = f"sandbox_unavailable: {exc}"
        return report
    out = res.stdout + "\n" + res.stderr
    report["timed_out"] = res.timed_out
    report["log_tail"] = out[-3000:]
    m = re.search(r"===\s*(\d+)\s+interesting", out)
    if m:
        report["passes"] = int(m.group(1))
    if not variant.is_file() or variant.stat().st_size == 0:
        report["reason"] = "cvise produced no variant"
        return report
    # Verify the best-so-far still reproduces with the same fingerprint before reporting it.
    check = replay_artifact(binary, variant, scratch, module=module, per_input_timeout=per_input_timeout)
    report["reproduced"] = bool(check.get("reproduced")) and (
        fingerprint is None or _failure_fingerprint(check.get("failure")) in fingerprint.split(",")
    )
    minimized = Path(str(input_path) + ".min")
    shutil.copyfile(variant, minimized)
    report["minimized"] = minimized.as_posix()
    report["minimized_size_bytes"] = minimized.stat().st_size
    orig = report["original_size_bytes"] or 0
    if orig > 0:
        report["reduction_pct"] = round(100.0 * (orig - report["minimized_size_bytes"]) / orig, 2)
    report["status"] = "ok" if report["reproduced"] else "not_reproduced"
    return report


def minimize_candidates(
    candidates_path: Path,
    harness_dir: Path,
    out_dir: Path,
    *,
    bin_dir: Path | None = None,
    engine: str | None = None,
    selftest_json: Path | None = DEFAULT_SELFTEST_JSON,
    machdep: str = "gcc_x86_64",
    per_input_timeout: int = DEFAULT_PER_INPUT_TIMEOUT_S,
    max_time_s: int = 600,
    jobs: int = 4,
    security_props: str | None = None,
) -> dict:
    """
    Minimize the reproducer of every unverified candidate (same selection as replay-candidates),
    on the module's replay binary. Each minimized input is written next to its artifact as
    `<artifact>.min`; `index.json` maps each fingerprint to its report.
    """
    candidates = load_json_optional(Path(candidates_path), [])
    todo = [c for c in candidates if isinstance(c, dict) and c.get("status") == "unverified" and _reproducer_paths(c)]
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    bin_dir = Path(bin_dir) if bin_dir is not None else Path("workspace/harnesses")
    prepared_by_key: dict[tuple[str, str], dict] = {}
    specs: dict[tuple[str, str, str], dict | str] = {}
    index: dict[str, dict] = {}
    by_status: dict[str, int] = {}
    tool = find_creduce()
    for cand in todo:
        fingerprint = str(cand.get("fingerprint") or "")
        module = str(cand.get("module") or "")
        eng = engine or _candidate_engine(cand)
        location = cand.get("location")
        location = location if isinstance(location, dict) else {}
        where = (module, str(location.get("file") or ""), str(location.get("function") or ""))
        if where not in specs:
            try:
                specs[where] = replay_build_spec(
                    module, Path(harness_dir), file=where[1] or None, function=where[2] or None
                )
            except (OSError, ValueError, RuntimeError) as exc:
                specs[where] = f"no build spec for module {module!r}: {exc}"
        spec = specs[where]
        # Minimized on the harness holding the crashing function (the unit's own one otherwise), each
        # reproducer on its own engine (D1). The interest test accepts the candidate's key or any observation's.
        scratch = out_dir / ".scratch" / (re.sub(r"[^A-Za-z0-9_.-]+", "_", module) or "unknown")
        accepted = ",".join(_accepted_fingerprints(cand))
        reports: list[dict] = []
        reason: str | None = None
        for group_eng, paths in _reproducers_by_engine(cand, eng, use_observations=engine is None).items():
            prepared = _prepared_replay(
                module,
                spec,
                group_eng,
                own_engine=eng,
                bin_dir=bin_dir,
                prepared_by_key=prepared_by_key,
                attribution=True,
                selftest_json=selftest_json,
                machdep=machdep,
                security_props=security_props,
            )
            binary = prepared.get("binary")
            if binary is None:
                reason = reason or prepared.get("reason") or "no binary"
                continue
            reports.extend(
                minimize_input(
                    Path(binary),
                    rep,
                    scratch,
                    module=module,
                    fingerprint=accepted or None,
                    max_time_s=max_time_s,
                    jobs=jobs,
                    per_input_timeout=per_input_timeout,
                    tool=tool,
                )
                for rep in paths
            )
        report: dict[str, Any]
        if not reports:
            report = {
                "mode": "minimize",
                "status": "error",
                "reason": reason or "no binary",
                "tool": tool,
            }
        else:
            report = {
                "mode": "minimize",
                "status": "ok" if any(r["status"] == "ok" for r in reports) else "error",
                "tool": tool,
                "fingerprint": fingerprint,
                "runs": reports,
            }
        report["candidate_fingerprint"] = fingerprint
        report_path = out_dir / f"{_candidate_slug(fingerprint)}.json"
        atomic_write_json(report_path, report)
        status = str(report["status"])
        index[fingerprint] = {"report": report_path.as_posix(), "module": module, "status": status}
        by_status[status] = by_status.get(status, 0) + 1
    index_path = out_dir / "index.json"
    atomic_write_json(
        index_path,
        {
            "generated_at": utc_now(),
            "candidates_file": Path(candidates_path).as_posix(),
            "tool": tool,
            "by_fingerprint": index,
        },
    )
    return {
        "mode": "minimize-candidates",
        "status": "error" if by_status.get("error") else "ok",
        "tool": tool,
        "candidates": len(todo),
        "by_status": by_status,
        "index": index_path.as_posix(),
    }
