#!/usr/bin/env python3
"""
Phase 0 PoC: inventory, call graph, link units and entry points from the target's own build and the
Frama-C kernel (docs/phase0-redesign.md). Stdlib only; runs inside the framac-pipeline image.

    phase0b.py extract --target DIR --out DIR [--build "make"] [--timeout 900]

Steps:
  1. copy the target to <out>/work and run its build under `bear intercept`;
  2. read compile, link and archive steps from the intercepted executions: per-file flags, link
     units (executables, shared and static libraries) and the sources of each;
  3. per unit, one Frama-C run over its sources (plus the sources of the project libraries it links)
     with each file's own flags and the p0_dump.ml module: functions, direct calls, indirect call
     sites, address-taken functions; `-cg` for Frama-C's own function-pointer over-approximation;
  4. a unit Frama-C cannot parse falls back to GCC `-fcallgraph-info` on its compile commands;
  5. entry points: exported dynamic symbols (shared libraries), globals declared in public headers
     (static libraries), `main` (executables); thread entries from `pthread_create`/`thrd_create`.

Writes <out>/model.json (schema in poc/phase0/README.md). Everything is a status, never a crash:
a failed step leaves its reason in the model.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
DUMP_SOURCE = HERE / "p0_dump.ml"

_COMPILER_RE = re.compile(r"^(?:[\w.+-]+-)?(?:cc|gcc|clang|c89|c99)(?:-\d+(?:\.\d+)*)?$")
_AR_RE = re.compile(r"^(?:[\w.+-]+-)?(?:gcc-)?(?:llvm-)?ar$")
# Options whose value is the next argument.
_ARG_OPTS = {
    "-o",
    "-I",
    "-D",
    "-U",
    "-include",
    "-imacros",
    "-iquote",
    "-isystem",
    "-idirafter",
    "-iprefix",
    "-MF",
    "-MT",
    "-MQ",
    "-x",
    "-L",
    "-l",
    "-Xlinker",
    "-Xpreprocessor",
    "-Xassembler",
    "-T",
    "-arch",
    "-target",
    "-isysroot",
    "--sysroot",
    "-aux-info",
    "-dumpbase",
    "-dumpdir",
}
# Preprocessing options kept for Frama-C, with a value (joined or separate).
_PP_VALUE_OPTS = ("-I", "-D", "-U", "-include", "-imacros", "-iquote", "-isystem", "-idirafter")
_SOURCE_SUFFIXES = (".c",)
_OBJECT_SUFFIXES = (".o", ".lo", ".obj")
_SHARED_RE = re.compile(r"\.so(?:\.\d+)*$")
THREAD_SPAWNERS = {"pthread_create": 2, "thrd_create": 1}
# Build-system probes (CMake compiler identification) are compiled but are not project code.
_PROBE_RE = re.compile(r"(^|/)CMakeFiles/|(^|/)CMakeScratch/|conftest\.c$")
_GENERATED_PREFIXES = ("build/CMakeFiles/",)
FRAMAC_TIMEOUT_S = 900


def run(cmd: list[str], cwd: Path | None = None, timeout: int = 600, env: dict | None = None) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {timeout} s: {shlex.join(cmd)[:300]}"
    except OSError as exc:
        return 127, f"cannot run {cmd[0]}: {exc}"
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def rel(path: Path, root: Path) -> str | None:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return None


# --- 1. Build capture -------------------------------------------------------------------------


def capture_build(target: Path, work: Path, out: Path, build: str, timeout: int) -> dict:
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(target, work, symlinks=True, ignore=shutil.ignore_patterns(".git"))
    events = out / "events.json"
    t0 = time.monotonic()
    rc, log = run(["bear", "intercept", "--output", str(events), "--", "sh", "-c", build], cwd=work, timeout=timeout)
    (out / "build.log").write_text(log, encoding="utf-8")
    return {
        "command": build,
        "status": "ok" if rc == 0 else "failed",
        "returncode": rc,
        "seconds": round(time.monotonic() - t0, 2),
        "log_tail": log[-1500:] if rc else "",
        "events": str(events),
    }


def read_executions(events: Path) -> list[dict]:
    execs: list[dict] = []
    seen: set = set()
    if not events.is_file():
        return execs
    for line in events.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        ex = (ev.get("started") or {}).get("execution")
        if not ex:
            continue
        key = (ex.get("working_dir"), tuple(ex.get("arguments") or []))
        if key in seen:
            continue
        seen.add(key)
        execs.append(
            {"exe": ex.get("executable") or "", "args": ex.get("arguments") or [], "cwd": ex.get("working_dir") or ""}
        )
    return execs


# --- 2. Compile, link and archive steps ----------------------------------------------------------


def parse_driver(args: list[str]) -> dict:
    """Split a compiler driver command line into its parts."""
    res: dict[str, Any] = {
        "mode": "link",
        "output": None,
        "sources": [],
        "inputs": [],
        "libs": [],
        "libdirs": [],
        "pp": [],
        "shared": False,
    }
    i = 1
    while i < len(args):
        a = args[i]
        val = None
        if a in _ARG_OPTS and i + 1 < len(args):
            val = args[i + 1]
            i += 1
        if a in ("-c",):
            res["mode"] = "compile"
        elif a in ("-E", "-S", "-M", "-MM", "-fsyntax-only"):
            res["mode"] = "other" if res["mode"] != "compile" or a in ("-E", "-S") else res["mode"]
        elif a == "-shared":
            res["shared"] = True
        elif a == "-o":
            res["output"] = val
        elif a == "-L" or (a.startswith("-L") and len(a) > 2):
            res["libdirs"].append(val if val is not None else a[2:])
        elif a == "-l" or (a.startswith("-l") and len(a) > 2):
            res["libs"].append(val if val is not None else a[2:])
        elif a.startswith(_PP_VALUE_OPTS) or a.startswith("-std="):
            opt = next((o for o in _PP_VALUE_OPTS if a.startswith(o)), None)
            if a.startswith("-std="):
                res["pp"].append([a])
            elif val is not None:
                res["pp"].append([a, val])
            elif opt and a != opt:
                res["pp"].append([opt, a[len(opt) :]])
        elif val is None and not a.startswith("-"):
            if a.endswith(_SOURCE_SUFFIXES):
                res["sources"].append(a)
            elif a.endswith(_OBJECT_SUFFIXES) or a.endswith(".a") or _SHARED_RE.search(a):
                res["inputs"].append(a)
        i += 1
    if args and any(x in args for x in ("-M", "-MM")) and "-c" not in args:
        res["mode"] = "other"
    return res


def build_inventory(execs: list[dict], work: Path) -> dict:
    """Compile entries, artifacts (units) and the objects/sources of each."""
    compiles: list[dict] = []  # {source, object, flags, cwd}
    artifacts: dict[str, dict] = {}  # rel path -> {kind, objects, sources, lib_refs, libdirs}
    archives: dict[str, list[str]] = defaultdict(list)

    def norm(p: str, cwd: str) -> str:
        q = Path(p) if os.path.isabs(p) else Path(cwd) / p
        r = rel(Path(os.path.normpath(q)), work)
        return r if r is not None else os.path.normpath(str(q))

    def pp_flags(pp: list[list[str]], cwd: str) -> list[str]:
        flags: list[str] = []
        for item in pp:
            if len(item) == 1:
                # C89 rejects the `//` comments of Frama-C's own libc headers.
                if item[0] not in ("-std=c89", "-std=c90", "-std=gnu89", "-std=gnu90", "-std=iso9899:1990"):
                    flags.append(item[0])
                continue
            opt, val = item
            if opt in ("-I", "-iquote", "-isystem", "-idirafter", "-include", "-imacros"):
                q = Path(val) if os.path.isabs(val) else Path(cwd) / val
                r = rel(Path(os.path.normpath(q)), work)
                if r is None:
                    continue  # host system paths: Frama-C uses its own libc
                flags += [opt, str(work / r)]
            else:
                flags.append(opt + val)
        return flags

    for ex in execs:
        name = os.path.basename(ex["exe"] or (ex["args"][0] if ex["args"] else ""))
        cwd = ex["cwd"]
        if _AR_RE.match(name) and len(ex["args"]) >= 3:
            ops = ex["args"][1].lstrip("-")
            if any(c in ops for c in "rq"):
                archive = norm(ex["args"][2], cwd)
                members = [norm(m, cwd) for m in ex["args"][3:] if m.endswith(_OBJECT_SUFFIXES)]
                archives[archive] += [m for m in members if m not in archives[archive]]
            continue
        if not _COMPILER_RE.match(name):
            continue
        d = parse_driver(ex["args"])
        if d["mode"] == "other" or any(_PROBE_RE.search(norm(s, cwd)) for s in d["sources"]):
            continue
        flags = pp_flags(d["pp"], cwd)
        if d["mode"] == "compile":
            for src in d["sources"]:
                obj = d["output"] if d["output"] and len(d["sources"]) == 1 else Path(src).with_suffix(".o").name
                compiles.append({"source": norm(src, cwd), "object": norm(obj, cwd), "flags": flags, "cwd": cwd})
            continue
        output = norm(d["output"] or "a.out", cwd)
        implicit = []
        for src in d["sources"]:
            entry = {"source": norm(src, cwd), "object": f"{output}::{src}", "flags": flags, "cwd": cwd}
            compiles.append(entry)
            implicit.append(entry["object"])
        artifacts[output] = {
            "kind": "shared_lib" if d["shared"] else "executable",
            "objects": implicit + [norm(x, cwd) for x in d["inputs"]],
            "lib_refs": d["libs"],
            "libdirs": [norm(x, cwd) for x in d["libdirs"]] + [norm(".", cwd)],
        }
    for archive, members in archives.items():
        artifacts[archive] = {"kind": "static_lib", "objects": members, "lib_refs": [], "libdirs": []}

    obj_to_compile = {c["object"]: c for c in compiles}
    units: dict[str, dict] = {}
    for path, art in sorted(artifacts.items()):
        own, links = [], []
        for o in art["objects"]:
            if o in obj_to_compile:
                own.append(obj_to_compile[o])
            elif o in artifacts:
                links.append(o)
        for lib in art["lib_refs"]:
            for d in art["libdirs"]:
                hit = next(
                    (
                        f"{d}/lib{lib}{suf}".lstrip("./")
                        for suf in (".so", ".a")
                        if f"{d}/lib{lib}{suf}".lstrip("./") in artifacts
                    ),
                    None,
                )
                if hit is None:
                    hit = next(
                        (
                            p
                            for suf in (".so", ".a")
                            for p in artifacts
                            if p == f"lib{lib}{suf}" or p.endswith(f"/lib{lib}{suf}")
                        ),
                        None,
                    )
                if hit:
                    links.append(hit)
                    break
        if not own and not links:
            continue  # a build-system probe (CMake try-compile, configure test): no project source
        units[path] = {
            "kind": art["kind"],
            "files": sorted({c["source"] for c in own}),
            "compiles": own,
            "links": sorted(set(links)),
        }
    linked_objects = {o for a in artifacts.values() for o in a["objects"]}
    loose = [c for c in compiles if c["object"] not in linked_objects]
    by_dir: dict[str, list[dict]] = defaultdict(list)
    for c in loose:
        by_dir[str(Path(c["source"]).parent.as_posix())].append(c)
    for dirname, cs in sorted(by_dir.items()):
        units[f"unlinked:{dirname}"] = {
            "kind": "unlinked",
            "files": sorted({c["source"] for c in cs}),
            "compiles": cs,
            "links": [],
        }
    return {"compiles": compiles, "units": units}


# --- 3. Symbols and entry points -----------------------------------------------------------------


def nm_symbols(path: Path, dynamic: bool = False) -> dict[str, str]:
    cmd = ["nm", "--defined-only"] + (["-D"] if dynamic else []) + [str(path)]
    rc, out = run(cmd, timeout=60)
    syms: dict[str, str] = {}
    if rc != 0:
        return syms
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            syms[parts[2]] = parts[1]
    return syms


def public_headers(work: Path, unit_files: list[str], consumer_files: list[str]) -> list[Path]:
    headers = [p for p in work.rglob("*.h") if ".git" not in p.parts]
    inc = [h for h in headers if any(part in ("include", "inc") for part in h.relative_to(work).parts[:-1])]
    if inc:
        return inc
    # Headers included by sources outside the library are its public interface.
    names: set[str] = set()
    for f in consumer_files:
        try:
            text = (work / f).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        names |= {Path(m).name for m in re.findall(r'#\s*include\s*["<]([^">]+)[">]', text)}
    used = [h for h in headers if h.name in names]
    return used or headers


def declared_in(headers: list[Path], names: set[str], flags: list[str] | None = None) -> set[str]:
    """Names declared in the headers, read after preprocessing (macro-generated prototypes count)."""
    found: set[str] = set()
    for h in headers:
        rc, text = run(["gcc", "-E", "-P", *(flags or []), "-x", "c", str(h)], cwd=h.parent, timeout=60)
        if rc != 0:
            try:
                text = h.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
        for n in names - found:
            if re.search(rf"\b{re.escape(n)}\s*\(", text):
                found.add(n)
    return found


# --- 4. Frama-C ------------------------------------------------------------------------------


def compile_dump(tmp: Path) -> tuple[Path | None, str]:
    src = tmp / DUMP_SOURCE.name
    shutil.copyfile(DUMP_SOURCE, src)
    rc, log = run(
        [
            "ocamlfind",
            "ocamlopt",
            "-shared",
            "-alert",
            "-deprecated",
            "-w",
            "-a",
            "-package",
            "frama-c.kernel",
            src.name,
            "-o",
            "p0_dump.cmxs",
        ],
        cwd=tmp,
        timeout=300,
    )
    target = tmp / "p0_dump.cmxs"
    return (target, "") if rc == 0 and target.is_file() else (None, log[-2000:])


def first_error(log: str) -> str:
    for line in log.splitlines():
        if re.search(r"(error|Error|User Error|failure|Failure)", line) and "warning" not in line.lower():
            return line.strip()[:400]
    return log.strip().splitlines()[-1][:400] if log.strip() else ""


def frama_c_unit(work: Path, out: Path, name: str, compiles: list[dict], module: Path) -> dict[str, Any]:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
    dump = out / "framac" / f"{safe}.json"
    dot = out / "framac" / f"{safe}.cg.dot"
    dump.parent.mkdir(parents=True, exist_ok=True)
    per_file: dict[str, list[str]] = {}
    for c in compiles:
        per_file.setdefault(c["source"], c["flags"])
    files = sorted(per_file)
    spec = []
    for f in files:
        fl = [x for x in per_file[f] if "," not in x]
        if fl:
            spec.append(f"{work / f}:{' '.join(fl)}")
    cmd = ["frama-c", "-no-unicode", "-machdep", "gcc_x86_64", "-keep-unused-functions", "all"]
    if spec:
        cmd.append("-cpp-extra-args-per-file=" + ",".join(spec))
    cmd += [str(work / f) for f in files]
    cmd += ["-load-module", str(module), "-cg", str(dot)]
    env = dict(os.environ, P0_DUMP_OUT=str(dump))
    t0 = time.monotonic()
    rc, log = run(cmd, cwd=work, timeout=FRAMAC_TIMEOUT_S, env=env)
    (out / "framac" / f"{safe}.log").write_text(shlex.join(cmd) + "\n\n" + log, encoding="utf-8")
    res: dict[str, Any] = {"status": "ok", "seconds": round(time.monotonic() - t0, 2), "files": files}
    if rc != 0 or not dump.is_file():
        res.update(status="parse_failed", error=first_error(log))
        return res
    res["dump"] = json.loads(dump.read_text(encoding="utf-8"))
    res["cg_edges"] = parse_cg_dot(dot)
    return res


def parse_cg_dot(dot: Path) -> list[tuple[str, str]]:
    if not dot.is_file():
        return []
    text = dot.read_text(encoding="utf-8", errors="replace")
    node = r'"UV ([^"]+?) \(\d+\)"'
    return re.findall(node + r"\s*->\s*" + node, text)


# --- 5. GCC fallback -----------------------------------------------------------------------------

_CI_NODE = re.compile(r'node: \{ title: "([^"]+)" label: "([^"\\]+)(?:\\n([^":]+):(\d+))?')
_CI_EDGE = re.compile(r'edge: \{ sourcename: "([^"]+)" targetname: "([^"]+)"')


def gcc_unit(work: Path, out: Path, name: str, compiles: list[dict]) -> dict[str, Any]:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
    ci_dir = out / "gcc-ci" / safe
    ci_dir.mkdir(parents=True, exist_ok=True)
    functions: dict[tuple[str, str], dict[str, Any]] = {}
    edges: list[tuple[str, str, str, str]] = []
    errors: list[str] = []
    for n, c in enumerate(compiles):
        base = ci_dir / f"{n}"
        cmd = [
            "gcc",
            *c["flags"],
            "-fcallgraph-info",
            "-c",
            str(work / c["source"]),
            "-o",
            f"{base}.o",
            "-dumpbase",
            f"{base}",
        ]
        rc, log = run(cmd, cwd=work, timeout=300)
        ci = Path(f"{base}.ci")
        if rc != 0 or not ci.is_file():
            errors.append(first_error(log))
            continue
        text = ci.read_text(encoding="utf-8", errors="replace")
        titles = {}
        for title, label, file, line in _CI_NODE.findall(text):
            titles[title] = label
            if file:
                fid = f"{c['source']}#{label}"
                functions[(c["source"], label)] = {"id": fid, "line": int(line), "static": ":" in title}
        for src, dst in _CI_EDGE.findall(text):
            edges.append((c["source"], titles.get(src, src), dst, titles.get(dst, dst)))
    return {"status": "ok" if not errors else "partial", "errors": errors, "functions": functions, "edges": edges}


# --- 6. Model -------------------------------------------------------------------------------------


def extract(target: Path, out: Path, build: str, timeout: int, keep_work: bool = False) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    # The build and Frama-C run in container-local scratch: on a host bind mount (Windows, OneDrive)
    # file I/O dominated the measured time. keep_work keeps the tree under <out>/work instead.
    work = out / "work" if keep_work else Path(tempfile.mkdtemp(prefix="p0-work-")) / "work"
    t0 = time.monotonic()
    model: dict = {"schema": 1, "extractor": "phase0b", "target": str(target)}
    model["build"] = capture_build(target, work, out, build, timeout)
    inv = build_inventory(read_executions(Path(model["build"]["events"])), work)
    units = inv["units"]
    model["compile_commands"] = len(inv["compiles"])

    functions: dict[str, dict] = {}
    edges: dict[tuple[str, str, str], set[str]] = defaultdict(set)  # (caller, callee, kind) -> sources
    externals: set[str] = set()
    thread_entries: set[str] = set()
    indirect_sites: list[dict] = []
    cg_extra: set[tuple[str, str]] = set()

    def add_fn(
        fid: str, file: str, name: str, line: int, static: bool, unit: str, source: str, signature: str = ""
    ) -> None:
        rec = functions.setdefault(
            fid,
            {
                "file": file,
                "name": name,
                "line": line,
                "static": static,
                "signature": signature,
                "units": [],
                "source": source,
            },
        )
        if unit not in rec["units"]:
            rec["units"].append(unit)

    with tempfile.TemporaryDirectory(prefix="p0-dump-") as tmp:
        module, why = compile_dump(Path(tmp))
        model["dump_module"] = "ok" if module else f"compile_failed: {why[-400:]}"
        for uname, u in units.items():
            # Whole program of the artifact: its own sources plus the project libraries it links.
            comp = list(u["compiles"])
            seen = {uname}
            stack = list(u["links"])
            while stack:
                lk = stack.pop()
                if lk in seen or lk not in units:
                    continue
                seen.add(lk)
                comp += [c for c in units[lk]["compiles"] if c["source"] not in {x["source"] for x in comp}]
                stack += units[lk]["links"]
            own_files = set(u["files"])
            res: dict[str, Any] = (
                frama_c_unit(work, out, uname, comp, module)
                if module
                else {"status": "parse_failed", "error": "no dump module"}
            )
            u["frama_c"] = {k: v for k, v in res.items() if k not in ("dump", "cg_edges", "files")}
            if res["status"] == "ok":
                dump = res["dump"]
                kmap: dict[str, str] = {}
                defined_k = set()
                for fn in dump["functions"]:
                    loc = fn["loc"]
                    m = re.match(r"^(.+?):(\d+)", loc)
                    file = (
                        rel(Path(m.group(1)) if os.path.isabs(m.group(1)) else work / m.group(1), work) if m else None
                    )
                    if not m or not file:
                        continue
                    fid = f"{file}#{fn['name']}"
                    kmap[fn["kernel_name"]] = fid
                    defined_k.add(fn["kernel_name"])
                    # Functions defined in project headers (header-only code, static inline) belong to
                    # every unit that compiles them.
                    if file in own_files or (file.endswith(".h") and not file.startswith(_GENERATED_PREFIXES)):
                        add_fn(
                            fid,
                            file,
                            fn["name"],
                            int(m.group(2)),
                            fn["static"],
                            uname,
                            "frama-c-kernel",
                            fn["signature"],
                        )
                taken = {k for k in dump.get("address_taken", []) if k in defined_k}
                sig_of = {fn["kernel_name"]: fn["signature"] for fn in dump["functions"]}
                for fn in dump["functions"]:
                    caller = kmap.get(fn["kernel_name"])
                    if not caller:
                        continue
                    for call in fn["calls"]:
                        if call.get("indirect"):
                            cands = sorted(kmap[k] for k in taken if sig_of.get(k) == call.get("signature"))
                            indirect_sites.append(
                                {
                                    "caller": caller,
                                    "expr": call.get("expr"),
                                    "signature": call.get("signature"),
                                    "candidates": cands,
                                }
                            )
                            for c in cands:
                                edges[(caller, c, "indirect")].add("type-match")
                            continue
                        kn = call["kernel_name"]
                        if kn in kmap:
                            edges[(caller, kmap[kn], "direct")].add("frama-c-kernel")
                        else:
                            externals.add(call["name"])
                            if call["name"] in THREAD_SPAWNERS:
                                for fk in call.get("function_args", []):
                                    if fk in kmap:
                                        thread_entries.add(kmap[fk])
                                        edges[(caller, kmap[fk], "indirect")].add("thread-spawn")
                        for fk in call.get("function_args", []):
                            if fk in kmap and call["name"] not in THREAD_SPAWNERS and kn not in kmap:
                                # A project function handed to an external (qsort, signal): called back.
                                edges[(caller, kmap[fk], "indirect")].add("callback-arg")
                direct_pairs = {(a, b) for (a, b, k) in edges if k == "direct"}
                for a, b in res.get("cg_edges", []):
                    if a in kmap and b in kmap and (kmap[a], kmap[b]) not in direct_pairs:
                        cg_extra.add((kmap[a], kmap[b]))
            else:
                g = gcc_unit(work, out, uname, comp)
                u["gcc_fallback"] = {"status": g["status"], "errors": g["errors"][:5]}
                by_name: dict[tuple[str, str], str] = {}
                for (file, name), info in g["functions"].items():
                    by_name[(file, name)] = info["id"]
                    if file in own_files:
                        add_fn(info["id"], file, name, info["line"], info["static"], uname, "gcc-callgraph-info")
                globals_by_name = {name: fid for (file, name), fid in by_name.items()}
                for file, src_name, _dst_title, dst_name in g["edges"]:
                    caller = by_name.get((file, src_name))
                    if not caller:
                        continue
                    if dst_name == "Indirect Call Placeholder":
                        indirect_sites.append({"caller": caller, "expr": None, "signature": None, "candidates": []})
                        continue
                    callee = by_name.get((file, dst_name)) or globals_by_name.get(dst_name)
                    if callee:
                        edges[(caller, callee, "direct")].add("gcc-callgraph-info")
                    else:
                        externals.add(dst_name)

        # Entry points.
        for uname, u in units.items():
            entries: set[str] = set()
            own = set(u["files"])
            if u["kind"] == "executable":
                entries |= {fid for fid, f in functions.items() if f["name"] == "main" and f["file"] in own}
            elif u["kind"] == "shared_lib":
                exported = {s for s, t in nm_symbols(work / uname, dynamic=True).items() if t in ("T", "W", "i")}
                entries |= {
                    fid
                    for fid, f in functions.items()
                    if f["file"] in own and not f["static"] and f["name"] in exported
                }
            elif u["kind"] == "static_lib":
                consumers = [f for n, v in units.items() if uname in v["links"] for f in v["files"]]
                globals_ = {f["name"]: fid for fid, f in functions.items() if f["file"] in own and not f["static"]}
                headers = public_headers(work, u["files"], consumers)
                # No header at all: every global is linkable, so every global is API.
                flags = u["compiles"][0]["flags"] if u["compiles"] else []
                entries |= (
                    {globals_[n] for n in declared_in(headers, set(globals_), flags)}
                    if headers
                    else set(globals_.values())
                )
            u["entry_points"] = sorted(entries)
            u.pop("compiles", None)

    model["units"] = units
    model["functions"] = dict(sorted(functions.items()))
    model["edges"] = [
        {"caller": a, "callee": b, "kind": k, "sources": sorted(s)} for (a, b, k), s in sorted(edges.items())
    ]
    model["externals"] = sorted(externals)
    model["entry_points"] = sorted({e for u in units.values() for e in u.get("entry_points", [])})
    model["thread_entries"] = sorted(thread_entries)
    model["indirect_sites"] = indirect_sites
    model["cg_overapprox_extra_edges"] = len(cg_extra)
    model["seconds"] = round(time.monotonic() - t0, 2)
    (out / "model.json").write_text(json.dumps(model, indent=1) + "\n", encoding="utf-8")
    if not keep_work:
        shutil.rmtree(work.parent, ignore_errors=True)
    return model


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("extract")
    e.add_argument("--target", type=Path, required=True)
    e.add_argument("--out", type=Path, required=True)
    e.add_argument("--build", default="make")
    e.add_argument("--timeout", type=int, default=900)
    e.add_argument("--keep-work", action="store_true", help="keep the built tree under <out>/work")
    a = p.parse_args(argv)
    m = extract(a.target.resolve(), a.out.resolve(), a.build, a.timeout, a.keep_work)
    summary = {
        "build": m["build"]["status"],
        "units": {n: (u["kind"], u.get("frama_c", {}).get("status")) for n, u in m["units"].items()},
        "functions": len(m["functions"]),
        "edges": len(m["edges"]),
        "seconds": m["seconds"],
    }
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
