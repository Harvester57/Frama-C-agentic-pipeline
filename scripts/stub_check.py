#!/usr/bin/env python3
"""
Checks of stub contracts (docs/plans/templates-and-stubs-improvement-plan.md step S3). Stdlib only.

    stub_check.py run    [--report workspace/reports/stubs.json] [--model workspace/reports/phase0_model.json]
                         [--dag workspace/reports/callgraph_dag.json] [--out workspace/reports/stub_check.json]
                         [--header workspace/stubs/<name> ...] [--checks abi,eva,dynamic] [--trials N]
                         [--ldflags=FLAGS]
    stub_check.py shipped [--stubs-dir templates/fc_stubs] [--header <rel> ...] [--out FILE]

`run` (Make target `stub-check`, after `stubs`) checks every header of the run's stub overlay
(workspace/stubs, scripts/stub_gen.py) three ways:

  abi      One translation unit that includes the header the way the target does: the overlay header
           pulls in the real one (`#include_next`), then redeclares its functions, drafts included
           (-DFC_STUB_DRAFT). A prototype that does not match the library's is a compile error.
  eva      Per active function (filled, incomplete, manual), a generated caller (`fc_stub_smoke.c`) with
           one valid call, which must raise no precondition alarm, and, when the function takes a buffer
           and its length (or a fixed-size array), one call whose buffer is one element short, which must
           raise one. A contract that accepts both is too weak (`too_weak`); a valid call that alarms says
           the contract or the generated arguments demand more than the documentation (`valid_call_alarm`).
  dynamic  The contract against the real library: the same valid calls, with lengths and contents varied
           over `--trials` runs, built with E-ACSL (which checks a declared function's contract around
           each call) and linked with the libraries the modules calling it link (the DAG's `ldflags`, the
           snapshot's library directories, plus --ldflags). Each function runs in its own process, under
           sandbox_exec.py. A failed `ensures` is a wrong contract (`violated`); a failed `requires` means
           the generated arguments do not meet it (`driver_rejected`), a crash or a link failure leaves
           the check `inconclusive`.

A header fails when its ABI check fails, Frama-C cannot parse it or Eva aborts on it (a deferred error such
as `assigns:missing`, a location other than \\result without `\\from`, which Phase 2 Eva aborts on too), the
E-ACSL build fails on an annotation of the header itself (`annot-error`, which every fuzz build including
it would hit), or a contract is `violated`. A failed
header blocks every module whose DAG `external_callees` name one of its functions (with the module's
lexer modules and sub-modules): workspace/reports/stub_check.json lists them under `blocked_modules`, and
phase0_gates.py refuses those modules until a stub-check of the unchanged header passes. Eva warnings
(`too_weak`, `valid_call_alarm`) and inconclusive dynamic checks are reported, never blocking.

Each checked header leaves its generated programs and tool logs (each starting with its command line) in
workspace/reports/stub_check/<include with / as __>/ (abi.log, fc_stub_smoke.c, eva.log, fc_stub_driver.c,
eacsl_instrument.log, eacsl_build.log, run<N>.log): the header's `artifacts` and each check's `log` name
them, and a failure's reason is the tool's most fatal message followed by `(see <log>)`.

`shipped` runs the ABI check on the pipeline's own templates/fc_stubs (whole-header replacements): one
translation unit per stub that includes the real system header, then the stub's prototypes; and, per
struct the stub defines, a layout probe built once against the real header and once against the stub,
which must print the same offset, size and type class (GCC's __builtin_classify_type: a struct and an
array differ) for every member and member macro (`icmp_ip`). A real header the image does not have is
`skipped`; SHIPPED_EXEMPT names the stubs that replace no real header. `--isystem DIR` adds a system
include directory.

Exit status: 0 when the report was written and no header failed, 1 when a header failed or an input is
missing.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import stub_gen  # noqa: E402
import target_env  # noqa: E402
from acsl_ast import AcslError, AcslSyntaxError, Token, locate_all_prototype_spans, tokenize_c_acsl  # noqa: E402
from c_definitions import (  # noqa: E402
    TYPE_MODIFIERS_AND_PRIMITIVES,
    _find_matching_backward,
    _is_ident,
    _resolve_declarator,
    _without_attributes,
    return_type_tokens,
    returns_void,
)
from framac_common import (  # noqa: E402
    STATUS_DEAD,
    STATUS_VALID,
    STATUS_VALID_UNDER_HYP,
    STUB_OVERLAY_REL,
    STUB_REPORT_REL,
    atomic_write_json,
    augment_framac_cppflags,
    load_json_optional,
    normalize_status,
    read_report_csv,
    resolve_fc_stubs_dir,
    stub_overlay_dir,
    utc_now,
)

STUB_CHECK_REL = "workspace/reports/stub_check.json"
DEFAULT_DAG = "workspace/reports/callgraph_dag.json"
CHECKS = ("abi", "eva", "dynamic")
BUF = 64
DEFAULT_TRIALS = 64
TOOL_TIMEOUT_S = 600
RUN_TIMEOUT_S = 60
SMOKE = "fc_stub_smoke.c"
DRIVER = "fc_stub_driver.c"
ABI_SRC = "fc_stub_abi.c"
ABI_LOG = "abi.log"
EVA_LOG = "eva.log"
EVA_CSV = "fc_stub_smoke_report.csv"
INSTRUMENT_LOG = "eacsl_instrument.log"
BUILD_LOG = "eacsl_build.log"
# What each header's check leaves for the agent to read (`stub_check.py run`, under ARTIFACTS_DIR/<slug>/):
# the generated programs, every tool's log (its command line first) and one log per dynamic run.
ARTIFACT_NAMES = (ABI_SRC, ABI_LOG, SMOKE, EVA_LOG, EVA_CSV, DRIVER, INSTRUMENT_LOG, BUILD_LOG)
ARTIFACT_GLOBS = ("run*.log",)
ARTIFACTS_DIR = "stub_check"  # next to stub_check.json: workspace/reports/stub_check/<slug>/

_WARNING_RE = re.compile(
    # The column and the `, behavior <name>` part are optional: without them here, a location printed as
    # `file:line:col` would read as file `line`, and the alarm would be dropped as "not the smoke file".
    r"(?P<file>[^\s:]+):(?P<line>\d+)(?::\d+)?: Warning:\s*\n?\s*function (?P<fn>[A-Za-z_]\w*)"
    r"(?:, behavior [^:\n]+)?: precondition(?P<name>[^\n]*?) got status (?P<status>[a-z_]+)"
)
_PARAM_NAME_RE = re.compile(r"([A-Za-z_]\w*)\s*(\[\s*\d*\s*\])?\s*$")
_TYPE_WORDS = frozenset(
    "void char short int long float double signed unsigned _Bool const volatile size_t ssize_t".split()
)
_EACSL_FAIL_RE = re.compile(r"(Precondition|Postcondition) failed", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Prototypes as callable signatures
# ---------------------------------------------------------------------------


def _split_params(text: str) -> list[str]:
    out: list[str] = []
    depth = 0
    cur: list[str] = []
    for ch in text:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    if "".join(cur).strip():
        out.append("".join(cur).strip())
    return out


def parse_proto(proto: str) -> dict | None:
    """
    {name, returns_void, params: [{name, type, array}]} for a prototype as the model prints it, or None
    when it cannot be called generically (variadic, function-pointer return, no parameter list).
    """
    is_void = returns_void(proto)
    if is_void is None:
        return None
    ret_tokens = return_type_tokens(proto)
    if ret_tokens is None or ("(" in ret_tokens and "*" in ret_tokens):
        return None
    try:
        raw_tokens = [t for t in tokenize_c_acsl(proto) if t.kind in ("c_token", "string", "char")]
    except AcslSyntaxError:
        return None
    tokens = _without_attributes(raw_tokens)
    while tokens and tokens[-1].text == ";":
        tokens.pop()
    if not tokens or tokens[-1].text != ")":
        return None
    close_params = len(tokens) - 1
    open_params = _find_matching_backward(tokens, close_params, "(", ")")
    if open_params <= 0:
        return None
    name, _, _ = _resolve_declarator(tokens, -1, open_params, close_params)
    if not name:
        return None
    params_tokens = tokens[open_params + 1 : close_params]
    if not params_tokens or [t.text for t in params_tokens] == ["void"]:
        return {"name": name, "returns_void": is_void, "params": []}
    params_text = " ".join(t.text for t in params_tokens)
    params: list[dict] = []
    for i, p in enumerate(_split_params(params_text)):
        if p == "...":
            return None
        if "(" in p:
            return None
        pm = _PARAM_NAME_RE.search(p)
        if pm is None:
            if not p.endswith("*"):
                return None
            params.append({"name": f"a{i}", "type": p, "array": None})
            continue
        pname, arr = pm.group(1), pm.group(2)
        ptype = p[: pm.start()].strip()
        if not ptype or pname in _TYPE_WORDS or ptype.split()[-1] in ("struct", "union", "enum"):
            ptype, pname = p, f"a{i}"
        size = int(arr.strip("[] ")) if arr and arr.strip("[] ") else None
        if arr:
            ptype = f"{ptype} *"
        params.append({"name": pname, "type": ptype, "array": size})
    return {"name": name, "returns_void": is_void, "params": params}


def _pairs(sig: dict) -> dict[int, int | str]:
    """Pointer parameter index -> its bound: the index of the length that follows it, or a fixed size."""
    out: dict[int, int | str] = {}
    params = sig["params"]
    for i, p in enumerate(params):
        if "*" not in p["type"]:
            continue
        if p["array"]:
            out[i] = p["array"]
        elif i + 1 < len(params) and "*" not in params[i + 1]["type"] and stub_gen._is_length(params[i + 1]["name"]):
            out[i] = f"len{i + 1}"
    return out


def call_lines(sig: dict, tag: str, short: bool, length: str = str(BUF)) -> list[str]:
    """
    The statements of one generic call: an aligned, initialized buffer of BUF bytes (or the fixed size)
    per pointer parameter, a zeroed local per value parameter, `length` for a length parameter. With
    `short`, every bounded buffer is one element shorter than its bound says.
    """
    pairs = _pairs(sig)
    lengths = {int(str(b)[3:]) for b in pairs.values() if isinstance(b, str)}
    lines: list[str] = []
    args: list[str] = []
    for i, p in enumerate(sig["params"]):
        v = f"{tag}_{i}"
        if "*" in p["type"]:
            fixed = p["array"]
            size = (fixed - 1 if short else fixed) if fixed else BUF
            lines.append(f"  _Alignas(16) unsigned char {v}[{max(size, 1)}];")
            lines.append(f"  for (unsigned i_ = 0; i_ < sizeof {v}; i_++) {v}[i_] = (unsigned char)(i_ * 31u + seed);")
            args.append(f"({p['type']}){v}")
        elif i in lengths:
            args.append(f"({p['type']})({length}{' + 1' if short else ''})")
        else:
            lines.append(f"  {p['type']} {v};")
            lines.append(f"  memset(&{v}, 0, sizeof {v});")
            args.append(v)
    call = f"{sig['name']}({', '.join(args)});"
    lines.append(f"  {'(void)' if not sig['returns_void'] else ''}{call}")
    return lines


# ---------------------------------------------------------------------------
# Generated programs
# ---------------------------------------------------------------------------


def smoke_source(include: str, sigs: list[dict]) -> tuple[str, dict[int, tuple[str, str]]]:
    """(the Eva smoke program, line -> (function, `ok` | `short`) of each call)."""
    out = [
        f"#include <{include}>",
        "#include <string.h>",
        "volatile int fc_stub_pick;",
        "static const unsigned seed = 0;",
    ]
    lines_of: dict[int, tuple[str, str]] = {}
    for sig in sigs:
        for kind in ("ok", "short"):
            if kind == "short" and not _pairs(sig):
                continue
            out.append(f"static void fc_smoke_{kind}_{sig['name']}(void) {{")
            body = call_lines(sig, "v", kind == "short")
            out.extend(body[:-1])
            out.append(body[-1])
            lines_of[len(out)] = (sig["name"], kind)
            out.append("}")
    out.append("int fc_stub_smoke_main(void) {")
    out.append("  switch (fc_stub_pick) {")
    case = 0
    for sig in sigs:
        for kind in ("ok", "short"):
            if kind == "short" and not _pairs(sig):
                continue
            out.append(f"  case {case}: fc_smoke_{kind}_{sig['name']}(); break;")
            case += 1
    out += ["  default: break;", "  }", "  return 0;", "}", ""]
    return "\n".join(out), lines_of


def driver_source(include: str, sigs: list[dict], trials: int) -> str:
    """One process per function (argv[1] = its index): `trials` valid calls with varied lengths and contents."""
    out = [f"#include <{include}>", "#include <stdlib.h>", "#include <string.h>"]
    for idx, sig in enumerate(sigs):
        out.append(f"static void fc_drive_{idx}(unsigned seed, unsigned long n) {{")
        out.extend(call_lines(sig, "v", False, length="n"))
        out.append("}")
    out.append("int main(int argc, char **argv) {")
    out.append("  int which = argc > 1 ? atoi(argv[1]) : -1;")
    out.append(f"  for (unsigned t = 0; t < {trials}u; t++) {{")
    out.append(f"    unsigned long n = (t * 7u) % {BUF + 1}u;")
    out.append("    switch (which) {")
    for idx in range(len(sigs)):
        out.append(f"    case {idx}: fc_drive_{idx}(t, n); break;")
    out += ["    default: return 2;", "    }", "  }", "  return 0;", "}", ""]
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Runners
# ---------------------------------------------------------------------------


def _run(cmd: list[str], cwd: Path, timeout: int = TOOL_TIMEOUT_S, env: dict | None = None) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {timeout} s"
    except OSError as exc:
        return 127, str(exc)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


# How fatal a tool's message is, most fatal first. Frama-C prints `[plugin:key] file:line: User Error:` and the
# text on the indented lines after it; a warning promoted to an error is repeated at the end as `Deferred
# error`. `\berror\b` leaves out cpp's `warning: "__errordecl" redefined`, which merely contains "error".
_FATAL_TIERS = (
    re.compile(r"User Error|\bFailure\b|[Ff]atal error|Deferred error|^\[kernel[^\]]*\].*\bError\b"),
    re.compile(r"\berror:"),
    re.compile(r"\baborted\b"),
    re.compile(r"\berror\b", re.IGNORECASE),
)
_MESSAGE_MAX = 500


def _messages(log: str) -> list[str]:
    """A log's messages: each line, with the indented lines after a Frama-C `[...]` line joined to it."""
    out: list[str] = []
    framac = False
    for line in log.splitlines():
        if framac and out and line[:1] in (" ", "\t") and line.strip():
            out[-1] = f"{out[-1]} {line.strip()}"
            continue
        framac = line.startswith("[")
        if line.strip():
            out.append(line.strip())
    return out


def _first_error(log: str) -> str:
    """The most fatal message of a tool's log (with its continuation lines), else its last line."""
    msgs = _messages(log)
    for tier in _FATAL_TIERS:
        for msg in msgs:
            if tier.search(msg):
                return msg[:_MESSAGE_MAX]
    return msgs[-1][:_MESSAGE_MAX] if msgs else ""


def _with_log(reason: str, log: Path | str | None) -> str:
    return f"{reason} (see {Path(log).as_posix()})" if log else reason


def system_include_flags(capture: dict) -> list[str]:
    """The snapshot's include directories for the target's system headers (target_env), as gcc options."""
    snap = target_env.snapshot_dir()
    system = [tok for c in capture.get("compiles") or [] for tok in c.get("system_flags") or []]
    root = (snap / "root").as_posix() if snap else None
    return target_env.include_flags(root, system) + target_env.generated_include_flags()


def check_abi(include: str, overlay: Path, sys_flags: list[str], work: Path) -> dict:
    src = work / ABI_SRC
    src.write_text(f"#include <{include}>\n", encoding="utf-8")
    cmd = ["gcc", "-fsyntax-only", "-DFC_STUB_DRAFT", f"-I{overlay.as_posix()}", *sys_flags, src.name]
    rc, log = _run(cmd, work)
    (work / ABI_LOG).write_text(f"$ {shlex.join(cmd)}\n{log}", encoding="utf-8")
    if rc == 0:
        return {"status": "passed", "log": ABI_LOG}
    if "No such file or directory" in log and include in log and "include_next" in log:
        reason = f"the real <{include}> is not on the include path: {_first_error(log)}"
        return {"status": "error", "reason": reason, "log": ABI_LOG}
    return {"status": "failed", "reason": _first_error(log), "command": shlex.join(cmd), "log": ABI_LOG}


def check_eva(include: str, sigs: list[dict], work: Path) -> dict:
    """{status, functions: {name: {status, alarms}}}: `error` when Frama-C cannot parse the program."""
    text, lines_of = smoke_source(include, sigs)
    (work / SMOKE).write_text(text, encoding="utf-8")
    csv_path = work / EVA_CSV
    cmd = [
        "frama-c",
        "-no-unicode",
        "-machdep",
        "gcc_x86_64",
        f"-cpp-extra-args={augment_framac_cppflags('-I.')}",
        SMOKE,
        "-eva",
        "-main",
        "fc_stub_smoke_main",
        "-eva-no-alloc-returns-null",
        "-then",
        "-report",
        "-report-csv",
        str(csv_path),
    ]
    rc, log = _run(cmd, work)
    (work / EVA_LOG).write_text(f"$ {shlex.join(cmd)}\n{log}", encoding="utf-8")
    # Eva prints its results before it aborts on a deferred error (a warning key set to error, e.g.
    # `assigns:missing`): a non-zero exit is an error even with VALUES COMPUTED in the log.
    if rc != 0 or ("[eva] done" not in log and "====== VALUES COMPUTED ======" not in log):
        return {"status": "error", "reason": _first_error(log) or f"frama-c exited {rc}", "log": EVA_LOG}
    if not csv_path.is_file():
        return {"status": "error", "reason": "no Eva report CSV produced", "log": EVA_LOG}

    alarms: dict[tuple[str, str], list[str]] = {}
    for row in read_report_csv(csv_path):
        if Path(row["file"]).name != SMOKE:
            continue
        where = lines_of.get(int(row["line"]))
        if where is None:
            continue
        if " of " in row["kind"]:
            callee = row["kind"].split(" of ", 1)[1].strip()
            if where[0] != callee:
                continue
        norm_status = row["status"]
        status_raw = str(row["status_raw"] or "").strip().lower()
        prop = str(row["property"] or "").strip()
        alarm_text = f"{prop}: {status_raw}"

        if where[1] == "ok":
            if norm_status not in (STATUS_VALID, STATUS_VALID_UNDER_HYP):
                alarms.setdefault(where, []).append(alarm_text)
        elif where[1] == "short":
            if norm_status not in (STATUS_VALID, STATUS_VALID_UNDER_HYP, STATUS_DEAD):
                alarms.setdefault(where, []).append(alarm_text)

    for m in _WARNING_RE.finditer(log):
        if Path(m.group("file")).name != SMOKE:
            continue
        where = lines_of.get(int(m.group("line")))
        if where is None or where[0] != m.group("fn"):
            continue
        pred_name = m.group("name").strip() or "precondition"
        st = m.group("status").strip()
        norm_st = normalize_status(st)
        if where[1] == "ok" and norm_st in (STATUS_VALID, STATUS_VALID_UNDER_HYP):
            continue
        if where[1] == "short" and norm_st in (STATUS_VALID, STATUS_VALID_UNDER_HYP, STATUS_DEAD):
            continue
        existing = alarms.get(where, [])
        if not any(pred_name in a for a in existing):
            alarms.setdefault(where, []).append(f"{pred_name}: {st} (Eva log only)")

    functions: dict[str, dict] = {}
    for sig in sigs:
        fn = sig["name"]
        ok_alarms = alarms.get((fn, "ok"), [])
        rec: dict[str, Any] = {"valid_call_alarms": ok_alarms}
        if (fn, "short") not in lines_of.values():
            rec["status"] = "valid_call_alarm" if ok_alarms else "passed"
            rec["short_call"] = "not_applicable"
        else:
            short_alarms = alarms.get((fn, "short"), [])
            rec["short_call_alarms"] = short_alarms
            rec["status"] = "valid_call_alarm" if ok_alarms else ("passed" if short_alarms else "too_weak")
        functions[fn] = rec
    return {"status": "ok", "functions": functions, "log": EVA_LOG}


def build_driver(work: Path, ldflags: str) -> dict:
    """
    E-ACSL build of the driver, in the two stages of run_eacsl_fuzz.py, without `-e-acsl-functions`:
    E-ACSL checks a declared function's contract around each call only when no selection leaves it out,
    and the option refuses a function without a body (so does `-rte-select`, which
    run_eacsl_fuzz.compile_eacsl_binary passes the same list). The instrumented file gets the same text
    repairs as a fuzz build.
    """
    from eacsl_toolchain import (
        UnsafePassthroughError,
        build_eacsl_flag_sets,
        mark_formals_initialized,
        mark_wrapper_results_initialized,
        normalize_passthrough,
        rewrite_trailing_alignas,
        select_eacsl_binary,
    )

    flags = build_eacsl_flag_sets(target_env.with_include_flags("-I."), fuzzer=False)
    instrumented = work / "fc_stub_driver.instrumented.c"
    out_bin = work / "fc_stub_driver"
    fc_flags = "-machdep gcc_x86_64"
    cmd1 = ["e-acsl-gcc", "-n", "--no-constfold", "-G", "clang", "-F", fc_flags, "-E", flags["frontend"]]
    cmd1 += ["-o", str(instrumented), DRIVER]
    rc, log = _run(cmd1, work)
    (work / INSTRUMENT_LOG).write_text(f"$ {shlex.join(cmd1)}\n{log}", encoding="utf-8")
    if rc != 0 or not instrumented.is_file():
        return {"status": "build_failed", "reason": _first_error(log) or f"e-acsl-gcc exited {rc}", "log": INSTRUMENT_LOG}
    text = instrumented.read_text(encoding="utf-8", errors="replace")
    for repair in (rewrite_trailing_alignas, mark_wrapper_results_initialized, mark_formals_initialized):
        text, _ = repair(text)
    instrumented.write_text(text, encoding="utf-8")
    # e-acsl-gcc re-splits flag values on spaces and matches each word against its own options, so a
    # separate `-L /dir` would eat the input file: join the pairs the way run_eacsl_fuzz.py does.
    try:
        link = normalize_passthrough(" ".join(x for x in (ldflags, target_env.with_link_flags("")) if x.strip()))
    except UnsafePassthroughError as exc:
        return {"status": "build_failed", "reason": str(exc), "log": INSTRUMENT_LOG}
    cmd2 = ["e-acsl-gcc", "-C", "-G", "clang", "-O", str(out_bin)]
    if flags["backend"]:
        cmd2 += ["-e", flags["backend"]]
    if link.strip():
        cmd2 += ["-l", link.strip()]
    cmd2.append(str(instrumented))
    rc, log = _run(cmd2, work)
    (work / BUILD_LOG).write_text(f"$ {shlex.join(cmd2)}\n{log}", encoding="utf-8")
    if rc != 0:
        status = "no_library" if "undefined reference" in log else "build_failed"
        return {"status": status, "reason": _first_error(log) or f"e-acsl-gcc exited {rc}", "log": BUILD_LOG}
    return {"status": "built", "binary": str(select_eacsl_binary(out_bin)), "log": BUILD_LOG}


def check_dynamic(include: str, sigs: list[dict], ldflags: str, trials: int, work: Path) -> dict:
    """E-ACSL build of the driver against the real library, then one sandboxed process per function."""
    from sandbox_exec import Limits, SandboxUnavailable, run_sandboxed

    (work / DRIVER).write_text(driver_source(include, sigs, trials), encoding="utf-8")
    build = build_driver(work, ldflags)
    if build["status"] != "built":
        return {**build, "ldflags": ldflags}
    binary = Path(build["binary"])
    functions: dict[str, dict] = {}
    for idx, sig in enumerate(sigs):
        try:
            res = run_sandboxed(
                [str(binary.resolve()), str(idx)],
                writable=[work / f"run{idx}"],
                timeout_s=RUN_TIMEOUT_S,
                limits=Limits(cpu_seconds=RUN_TIMEOUT_S * 2),
            )
        except SandboxUnavailable as exc:
            return {"status": "sandbox_unavailable", "reason": str(exc), "log": BUILD_LOG}
        out = res.stdout + "\n" + res.stderr
        (work / f"run{idx}.log").write_text(
            f"$ {binary.name} {idx}  # {sig['name']}, exit {res.returncode}\n{out}", encoding="utf-8"
        )
        fail = _EACSL_FAIL_RE.search(out)
        if res.returncode == 0 and not fail:
            functions[sig["name"]] = {"status": "passed", "trials": trials}
        elif fail and fail.group(1).lower() == "postcondition":
            functions[sig["name"]] = {"status": "violated", "report": out[fail.start() : fail.start() + 800].strip()}
        elif fail:
            functions[sig["name"]] = {
                "status": "driver_rejected",
                "report": out[fail.start() : fail.start() + 800].strip(),
            }
        else:
            functions[sig["name"]] = {
                "status": "inconclusive",
                "reason": "timeout" if res.timed_out else f"exit {res.returncode}",
                "output_tail": out[-800:],
            }
    for idx, sig in enumerate(sigs):
        if sig["name"] in functions:
            functions[sig["name"]]["log"] = f"run{idx}.log"
    return {"status": "ok", "functions": functions, "ldflags": ldflags, "log": BUILD_LOG}


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


def _signatures(rec: dict, model: dict) -> tuple[list[dict], list[str]]:
    """Callable signatures of the header's active functions, and the names that have none."""
    decls = model.get("external_decls") or {}
    sigs: list[dict] = []
    skipped: list[str] = []
    for fn, f in sorted((rec.get("functions") or {}).items()):
        if f.get("state") not in ("incomplete", "filled", "manual"):
            continue
        sig = parse_proto(str((decls.get(fn) or {}).get("proto") or ""))
        if sig is None or sig["name"] != fn:
            skipped.append(fn)
        else:
            sigs.append(sig)
    return sigs, skipped


def blocked_modules(dag: dict, failed: dict[str, list[str]]) -> dict[str, list[str]]:
    """Module -> the failed headers it depends on (DAG `external_callees`), with lexer and sub-modules."""
    out: dict[str, set[str]] = {}
    for name, mod in (dag.get("modules") or {}).items():
        if not isinstance(mod, dict):
            continue
        callees = set(mod.get("external_callees") or [])
        hit = sorted(h for h, fns in failed.items() if callees & set(fns))
        if not hit:
            continue
        related = [name, *(mod.get("lexer_modules") or []), *((mod.get("split") or {}).get("submodules") or [])]
        for m in related:
            out.setdefault(str(m), set()).update(hit)
    return {m: sorted(h) for m, h in sorted(out.items())}


def module_ldflags(dag: dict, functions: list[str]) -> list[str]:
    opts: list[str] = []
    for mod in (dag.get("modules") or {}).values():
        if isinstance(mod, dict) and set(mod.get("external_callees") or []) & set(functions):
            opts += [str(o) for o in mod.get("ldflags") or []]
    return list(dict.fromkeys(opts))


def artifact_slug(include: str) -> str:
    """The directory name of a header's artifacts: `sys/epoll.h` -> `sys__epoll.h`."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", include.strip("/").replace("/", "__")) or "header"


def persist_artifacts(work: Path, dest: Path) -> dict:
    """
    Copy the check's programs and logs from the scratch directory `work` to `dest` (emptied first: what
    it held was a previous check of the same header). {dir, files}, paths as the report names them.
    """
    if dest.is_dir():
        shutil.rmtree(dest, ignore_errors=True)
    names = [n for n in ARTIFACT_NAMES if (work / n).is_file()]
    names += sorted({p.name for g in ARTIFACT_GLOBS for p in work.glob(g) if p.is_file()})
    copied: list[str] = []
    for name in names:
        try:
            dest.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(work / name, dest / name)
        except OSError:
            continue
        copied.append(name)
    return {"dir": dest.as_posix(), "files": copied}


def header_annot_error(dynamic: dict, header: str) -> bool:
    """
    Whether the E-ACSL build failed on an annotation of `header` itself (`[kernel:annot-error] <header>:N:
    Failure: unbound logic variable __fc_errno`): every fuzz build including the header aborts the same way.
    """
    reason = str(dynamic.get("reason") or "")
    return dynamic.get("status") == "build_failed" and "annot-error" in reason and Path(header).as_posix() in reason


def _point_logs_at(res: dict, dest: Path) -> None:
    """Rewrite each check's `log` (a file name in the scratch directory) to its persisted path."""
    for key in ("abi", "eva", "dynamic"):
        check = res.get(key)
        if not isinstance(check, dict):
            continue
        records = [check, *((check.get("functions") or {}).values())]
        for r in records:
            if isinstance(r, dict) and r.get("log"):
                r["log"] = (dest / str(r["log"])).as_posix()


def cmd_run(args: argparse.Namespace) -> int:
    report = load_json_optional(args.report, None)
    if not isinstance(report, dict):
        print(json.dumps({"ok": False, "error": f"no stub report at {args.report}: run `stubs` first"}))
        return 1
    model = load_json_optional(args.model, {}) or {}
    dag = load_json_optional(args.dag, {}) or {}
    capture = load_json_optional(Path(stub_gen.DEFAULT_CAPTURE), {}) or {}
    overlay = stub_overlay_dir() or Path(STUB_OVERLAY_REL).resolve()
    checks = [c for c in args.checks.split(",") if c]
    sys_flags = system_include_flags(capture if isinstance(capture, dict) else {})
    headers = report.get("headers") or {}
    wanted = args.header or sorted(headers)
    artifacts_root = Path(args.out).parent / ARTIFACTS_DIR
    results: dict[str, dict] = {}
    failed: dict[str, list[str]] = {}
    for header in wanted:
        rec = headers.get(header)
        if not isinstance(rec, dict):
            results[header] = {"status": "error", "reason": "not in the stub report"}
            continue
        include = rec.get("include_name") or header[len(STUB_OVERLAY_REL) + 1 :]
        path = Path(header)
        digest = stub_gen.sha256_text(path.read_text(encoding="utf-8")) if path.is_file() else None
        sigs, skipped = _signatures(rec, model if isinstance(model, dict) else {})
        res: dict[str, Any] = {"digest": digest, "include_name": include, "not_callable": skipped}
        reasons: list[str] = list(rec.get("problems") or [])
        dest = artifacts_root / artifact_slug(include)
        with tempfile.TemporaryDirectory(prefix="stub-check-") as tmp:
            work = Path(tmp)
            try:
                if "abi" in checks:
                    res["abi"] = check_abi(include, overlay, sys_flags, work)
                if "eva" in checks and sigs:
                    res["eva"] = check_eva(include, sigs, work)
                if "dynamic" in checks and sigs:
                    ld = " ".join([*module_ldflags(dag, [s["name"] for s in sigs]), args.ldflags or ""]).strip()
                    res["dynamic"] = check_dynamic(include, sigs, ld, args.trials, work)
            finally:
                # Kept even when a check raised: the logs are what the agent reads to fix the header.
                res["artifacts"] = persist_artifacts(work, dest)
        _point_logs_at(res, dest)
        if res.get("abi", {}).get("status") == "failed":
            reasons.append(_with_log(f"ABI: {res['abi']['reason']}", res["abi"].get("log")))
        if res.get("eva", {}).get("status") == "error":
            reasons.append(_with_log(f"Frama-C: {res['eva']['reason']}", res["eva"].get("log")))
        if header_annot_error(res.get("dynamic") or {}, header):
            reasons.append(_with_log(f"E-ACSL: {res['dynamic']['reason']}", res["dynamic"].get("log")))
        for fn, f in (res.get("dynamic", {}).get("functions") or {}).items():
            if f["status"] == "violated":
                reasons.append(_with_log(f"{fn}: postcondition failed against the real library", f.get("log")))
        res["status"] = "failed" if reasons else "passed"
        res["reasons"] = reasons
        results[header] = res
        if reasons:
            failed[header] = sorted(rec.get("functions") or {})
    # Headers not re-checked keep their previous result unless their content changed.
    previous = load_json_optional(args.out, {}) or {}
    for header, old in ((previous.get("headers") or {}) if isinstance(previous, dict) else {}).items():
        if header in results or header not in headers or not isinstance(old, dict):
            continue
        if old.get("digest") != (headers[header] or {}).get("digest"):
            continue  # edited since: its old result no longer says anything, the next full run checks it
        results[header] = old
        if old.get("status") == "failed":
            failed[header] = sorted((headers[header] or {}).get("functions") or {})
    blocked = blocked_modules(dag if isinstance(dag, dict) else {}, failed)
    out = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "checks": checks,
        "headers": dict(sorted(results.items())),
        "blocked_modules": blocked,
    }
    atomic_write_json(args.out, out)
    print(json.dumps({"ok": not failed, "failed": sorted(failed), "blocked_modules": sorted(blocked)}))
    return 1 if failed else 0


# ---------------------------------------------------------------------------
# Gate (phase0_gates.py)
# ---------------------------------------------------------------------------


def gate_reasons(run_dir: Path, module: str | None) -> list[str]:
    """Why stub-check blocks `module` (every blocked module when None): a failed header, still unchanged or not re-checked."""
    data = load_json_optional(run_dir / STUB_CHECK_REL, {})
    if not isinstance(data, dict):
        return []
    blocked = data.get("blocked_modules") or {}
    reasons: list[str] = []
    for mod, hdrs in sorted(blocked.items()):
        if module is not None and mod != module:
            continue
        for h in hdrs:
            rec = (data.get("headers") or {}).get(h) or {}
            why = "; ".join(rec.get("reasons") or [])[:400]
            # The logs' directory survives the cut above, which can drop a reason's own "(see ...)".
            art = rec.get("artifacts")
            art = art if isinstance(art, dict) else {}
            where = f"; logs and generated programs in {art['dir']}/" if art.get("dir") and art.get("files") else ""
            reasons.append(
                f"stub-check failed for {h} ({why}{where}), which module {mod} depends on: fix the header, then run "
                "`pipeline_make.py run stubs stub-check`"
            )
    return reasons


# ---------------------------------------------------------------------------
# shipped
# ---------------------------------------------------------------------------


def shipped_prototypes(text: str, path: str) -> list[str]:
    """The text of each top-level function prototype of a stub header, ACSL and comments dropped."""
    try:
        spans = locate_all_prototype_spans(text, path=path)
    except AcslError:
        return []
    out: list[str] = []
    for span in spans:
        body = re.sub(r"/\*.*?\*/|//[^\n]*", " ", span.text, flags=re.DOTALL).strip()
        if body:
            out.append(" ".join(body.split()))
    return out


# Stubs that are not replacements of one real header: the E-ACSL variants, the type shim the pipeline
# force-includes, and errno.h, which maps errno to a global on purpose (README of fc_stubs).
SHIPPED_EXEMPT = ("eacsl/", "fc_compat_types.h", "errno.h")
_MEMBER_MACRO_RE = re.compile(r"^\s*#\s*define\s+([A-Za-z_]\w*)\s+[A-Za-z_]\w*\s*(?:\.\s*[A-Za-z_]\w*\s*)+$", re.M)
_STRUCT_QUALIFIERS = frozenset({"const", "volatile", "restrict", "__restrict", "__restrict__"})


def _extract_member_name_from_decl(tokens: list[Token]) -> str | None:
    p_depth = 0
    b_depth = 0
    for t in tokens:
        if t.text == "(":
            p_depth += 1
        elif t.text == ")":
            p_depth -= 1
        elif t.text == "[":
            b_depth += 1
        elif t.text == "]":
            b_depth -= 1
        elif t.text == ":" and p_depth == 0 and b_depth == 0:
            return None  # Bit-field: omitted

    idx = 0
    while idx < len(tokens) and tokens[idx].text == "*":
        idx += 1
    if idx < len(tokens) and tokens[idx].text == "(":
        p_depth = 0
        close_idx = -1
        for j in range(idx, len(tokens)):
            if tokens[j].text == "(":
                p_depth += 1
            elif tokens[j].text == ")":
                p_depth -= 1
                if p_depth == 0:
                    close_idx = j
                    break
        if close_idx != -1:
            inner = tokens[idx + 1 : close_idx]
            for t in inner:
                if t.text == "[":
                    break
                if _is_ident(t.text) and t.text not in _STRUCT_QUALIFIERS and t.text not in TYPE_MODIFIERS_AND_PRIMITIVES:
                    return t.text

    candidates: list[str] = []
    for t in tokens:
        if t.text in ("[", "("):
            break
        if _is_ident(t.text) and t.text not in _STRUCT_QUALIFIERS and t.text not in TYPE_MODIFIERS_AND_PRIMITIVES:
            candidates.append(t.text)
    return candidates[-1] if candidates else None


def _split_decl_tokens(tokens: list[Token]) -> list[list[Token]]:
    decls: list[list[Token]] = []
    cur: list[Token] = []
    p_depth = 0
    b_depth = 0
    for t in tokens:
        if t.text == "(":
            p_depth += 1
        elif t.text == ")":
            p_depth -= 1
        elif t.text == "[":
            b_depth += 1
        elif t.text == "]":
            b_depth -= 1
        elif t.text == "," and p_depth == 0 and b_depth == 0:
            if cur:
                decls.append(cur)
                cur = []
            continue
        cur.append(t)
    if cur:
        decls.append(cur)
    return decls


def _parse_stmt_members(stmt: list[Token]) -> list[str]:
    last_close = -1
    for idx, t in enumerate(stmt):
        if t.text == "}":
            last_close = idx
    if last_close != -1:
        decl_tokens = _without_attributes(stmt[last_close + 1 :])
    else:
        clean = _without_attributes(stmt)
        if not clean:
            return []
        start_idx = 0
        if clean[0].text in ("struct", "union", "enum"):
            if len(clean) > 1 and _is_ident(clean[1].text):
                start_idx = 2
            else:
                start_idx = 1
        else:
            while start_idx < len(clean) and (
                clean[start_idx].text in TYPE_MODIFIERS_AND_PRIMITIVES
                or clean[start_idx].text in _STRUCT_QUALIFIERS
            ):
                start_idx += 1
            if start_idx == 0:
                start_idx = 1
        decl_tokens = clean[start_idx:]

    members: list[str] = []
    for piece in _split_decl_tokens(decl_tokens):
        name = _extract_member_name_from_decl(piece)
        if name:
            members.append(name)
    return members


def struct_members(text: str) -> dict[str, list[str]]:
    """
    Struct tag -> its member designators: the members declared at the struct's own level, and the member
    macros defined inside its body (`#define icmp_ip icmp_dun.id_ip.idi_ip`), which is how code names
    them. Bit-fields are left out (offsetof refuses them).
    """
    raw_tokens = tokenize_c_acsl(text)
    all_tokens = _without_attributes(
        [t for t in raw_tokens if t.kind in ("c_token", "string", "pp_directive")]
    )
    out: dict[str, list[str]] = {}
    stack: list[dict[str, Any]] = []

    i = 0
    n = len(all_tokens)
    while i < n:
        tok = all_tokens[i]

        if tok.kind == "pp_directive" and stack:
            m = _MEMBER_MACRO_RE.match(tok.text)
            if m:
                macro_name = m.group(1)
                for frame in stack:
                    if frame["tag"]:
                        frame["members"].append(macro_name)
            i += 1
            continue

        if tok.kind not in ("c_token", "string"):
            i += 1
            continue

        if tok.text in ("struct", "union") and i + 1 < n:
            tag = None
            brace_idx = -1
            if all_tokens[i + 1].text == "{":
                brace_idx = i + 1
            elif _is_ident(all_tokens[i + 1].text) and i + 2 < n and all_tokens[i + 2].text == "{":
                if tok.text == "struct":
                    tag = all_tokens[i + 1].text
                brace_idx = i + 2
            if brace_idx != -1:
                if stack:
                    stack[-1]["cur_stmt"].append(tok)
                    if tag:
                        stack[-1]["cur_stmt"].append(all_tokens[i + 1])
                    stack[-1]["cur_stmt"].append(all_tokens[brace_idx])
                stack.append({"tag": tag, "members": [], "cur_stmt": []})
                i = brace_idx + 1
                continue

        if tok.text == "}":
            if stack:
                frame = stack.pop()
                if frame["tag"]:
                    out.setdefault(frame["tag"], list(dict.fromkeys(frame["members"])))
                if stack:
                    stack[-1]["cur_stmt"].append(tok)
            i += 1
            continue

        if tok.text == ";":
            if stack:
                mems = _parse_stmt_members(stack[-1]["cur_stmt"])
                stack[-1]["members"].extend(mems)
                stack[-1]["cur_stmt"] = []
            i += 1
            continue

        if stack:
            stack[-1]["cur_stmt"].append(tok)

        i += 1

    return out


def layout_probe_source(include: str, structs: dict[str, list[str]]) -> str:
    """A program printing, per struct member, its offset, size and GCC type class (a struct, an array...)."""
    lines = [f"#include <{include}>", "#include <stddef.h>", "#include <stdio.h>", "int main(void) {"]
    for tag, members in sorted(structs.items()):
        lines.append(f'  printf("{tag} size %zu\\n", sizeof(struct {tag}));')
        for mem in members:
            # A member the header does not have is a compile error, reported as a divergence.
            lines.append(
                f'  printf("{tag}.{mem} %zu %zu %d\\n", offsetof(struct {tag}, {mem}), '
                f"sizeof(((struct {tag} *)0)->{mem}), __builtin_classify_type((&((struct {tag} *)0)->{mem})[0]));"
            )
    lines += ["  return 0;", "}", ""]
    return "\n".join(lines)


def _layout(include: str, structs: dict[str, list[str]], flags: list[str], work: Path) -> tuple[dict[str, str], str]:
    """Member -> `offset size class` under `flags`, or the compile error."""
    (work / "layout.c").write_text(layout_probe_source(include, structs), encoding="utf-8")
    rc, log = _run(["gcc", *flags, "-o", "layout", "layout.c"], work)
    if rc != 0:
        return {}, _first_error(log)
    rc, log = _run([str(work / "layout")], work, timeout=30)
    if rc != 0:
        return {}, f"layout probe exited {rc}"
    rows = dict(line.split(" ", 1) for line in log.splitlines() if " " in line)
    return rows, ""


def check_shipped_layout(rel: str, text: str, stubs: Path, isystem: list[str], work: Path) -> dict:
    """The stub's structs against the real header's: same members, offsets, sizes and type classes."""
    try:
        structs = struct_members(text)
    except AcslSyntaxError as exc:
        return {"status": "error", "reason": f"header does not tokenize: {exc}"}
    if not structs:
        return {"status": "passed", "structs": 0}
    sys_flags = [f for d in isystem for f in ("-isystem", d)]
    real, real_err = _layout(rel, structs, sys_flags, work)
    if real_err:
        if re.search(rf"{re.escape(rel)}: No such file", real_err):
            return {"status": "skipped"}
        return {"status": "failed", "reason": f"with the real header: {real_err}"}
    stub, stub_err = _layout(rel, structs, [f"-I{stubs.as_posix()}", *sys_flags], work)
    if stub_err:
        return {"status": "error", "reason": f"with the stub: {stub_err}"}
    diverging = [
        f"{key}: real {real[key]!r}, stub {stub.get(key)!r}" for key in sorted(real) if real[key] != stub.get(key)
    ]
    if diverging:
        return {"status": "failed", "reason": "layout differs (offset size type-class): " + "; ".join(diverging)}
    return {"status": "passed", "structs": len(structs)}


def cmd_shipped(args: argparse.Namespace) -> int:
    stubs = Path(args.stubs_dir) if args.stubs_dir else resolve_fc_stubs_dir()
    if stubs is None or not stubs.is_dir():
        print(json.dumps({"ok": False, "error": "templates/fc_stubs not found"}))
        return 1
    names = args.header or sorted(
        p.relative_to(stubs).as_posix()
        for p in stubs.rglob("*.h")
        if not p.relative_to(stubs).as_posix().startswith(SHIPPED_EXEMPT)
    )
    sys_flags = [f for d in args.isystem for f in ("-isystem", d)]
    results: dict[str, dict] = {}
    with tempfile.TemporaryDirectory(prefix="stub-abi-") as tmp:
        work = Path(tmp)
        for rel in names:
            text = (stubs / rel).read_text(encoding="utf-8")
            protos = shipped_prototypes(text, rel)
            src = work / "abi.c"
            src.write_text(f"#include <{rel}>\n" + "\n".join(f"{p}" for p in protos) + "\n", encoding="utf-8")
            rc, log = _run(["gcc", "-fsyntax-only", *sys_flags, src.name], work)
            if re.search(rf"{re.escape(rel)}: No such file", log):
                results[rel] = {"status": "skipped", "reason": f"<{rel}> is not installed here"}
                continue
            res: dict[str, Any] = {"prototypes": len(protos)}
            reasons = [] if rc == 0 else [f"prototypes: {_first_error(log)}"]
            layout = check_shipped_layout(rel, text, stubs, args.isystem, work)
            res["structs"] = len(struct_members(text))
            if layout["status"] in ("failed", "error"):
                reasons.append(f"structs: {layout['reason']}")
            res["status"] = "failed" if reasons else "passed"
            if reasons:
                res["reason"] = "; ".join(reasons)
            results[rel] = res
    out = {"schema_version": 1, "generated_at": utc_now(), "headers": results}
    if args.out:
        atomic_write_json(Path(args.out), out)
    print(json.dumps(out, indent=2))
    return 1 if any(r["status"] == "failed" for r in results.values()) else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="Check the run's stub overlay (Make target stub-check)")
    r.add_argument("--report", type=Path, default=Path(STUB_REPORT_REL))
    r.add_argument("--model", type=Path, default=Path(stub_gen.DEFAULT_MODEL))
    r.add_argument("--dag", type=Path, default=Path(DEFAULT_DAG))
    r.add_argument("--out", type=Path, default=Path(STUB_CHECK_REL))
    r.add_argument("--header", action="append", default=[], help="Only this overlay header (repeatable)")
    r.add_argument("--checks", default=",".join(CHECKS), help="Comma-separated: abi, eva, dynamic")
    r.add_argument("--trials", type=int, default=DEFAULT_TRIALS)
    r.add_argument("--ldflags", default="", help="Extra link options for the dynamic check")
    s = sub.add_parser("shipped", help="ABI check of templates/fc_stubs against the real headers")
    s.add_argument("--stubs-dir", default=None)
    s.add_argument("--header", action="append", default=[], help="Header path relative to fc_stubs (repeatable)")
    s.add_argument("--out", default=None)
    s.add_argument("--isystem", action="append", default=[], help="Extra system include directory (repeatable)")
    args = parser.parse_args(argv)
    if args.cmd == "run":
        unknown = [c for c in args.checks.split(",") if c and c not in CHECKS]
        if unknown:
            parser.error(f"unknown check(s): {', '.join(unknown)}")
        return cmd_run(args)
    if shutil.which("gcc") is None:
        print(json.dumps({"ok": False, "error": "gcc not found"}))
        return 1
    return cmd_shipped(args)


if __name__ == "__main__":
    sys.exit(main())
