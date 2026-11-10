#!/usr/bin/env python3
"""
Seed inputs from the target's own tests (docs/phase0-implementation-plan.md, step I6).

The tests of a C library call its API with realistic, well-formed inputs, written inline as literals
(minmea's sentences, QCBOR's encoded arrays). This script records those calls and turns them into
seed inputs for each harness module, in the byte layout that harness reads.

    seed_harvest.py record [--scratch /framac-scratch] [--timeout 600]     (build image, scratch volume)
    seed_harvest.py write [--module M]...                                   (any image)

`record`, in the build image on the run's scratch volume, after build_capture.py built the tree there:

  1. the API to record: the model's entry points (workspace/reports/phase0_model.json) that a test
     executable defines, with a signature the recorder can spell (scalars, enums, pointers, and structs
     by value whose definition is in a project header); variadic functions and anonymous structs are
     skipped with a reason;
  2. a recorder, generated from those signatures: `__wrap_<fn>` saves the arguments of each outermost
     API call (string and buffer contents, scalars, the `(ptr, len)` pairs inside a struct passed by
     value, the pointee of a pointer to a scalar) and calls `__real_<fn>`. Memory is copied through a
     pipe, so a bad pointer is recorded as missing, never a crash;
  3. each executable (every one, not only those named as tests: the test command decides which run)
     is linked again from the build's own link command (bear's events) with the
     recorder and `-Wl,--wrap=<fn>` for each API function it defines. Calls between object files are
     recorded: the tests call the API from their own objects. Calls inside one object file, and API
     functions that are header `static inline`, are not;
  4. the recipe's test command runs under strace (`openat`), through sandbox_exec.py: no network (the
     container has none), capped time, CPU, processes and file sizes. A failing test suite is not an
     error: seeds are an improvement, not a requirement;
  5. the calls go to workspace/seed_records/calls.jsonl (deduplicated, capped per function), the data
     files the tests opened for reading inside the target tree to workspace/seed_records/files/
     (capped by size and count), and the report to workspace/reports/seed_harvest.json.

`write`, from the records and the harness sidecars and sources (workspace/harnesses/harness_<m>.{json,c}):
each harness's fuzz entry point is read for the way it turns the fuzz input into API arguments, case
by case for a dispatch harness:

  - the selector byte of a dispatch harness (case i of n is byte i);
  - leading scalar slots: `memcpy(&v, fuzz_buf [+ fuzz_off], sizeof v)` in order, filled from the
    recorded argument passed as `v` (or `&v`);
  - the rest of the input: an argument that is `fuzz_buf` itself (through casts or `+ fuzz_off`), a
    variable assigned or copied from it, or a struct whose field is set to it (`in.ptr = fuzz_buf`),
    filled from the recorded string, buffer, or struct's `(ptr, len)` buffer.

Each recorded call of an API function a case passes the input to becomes one seed for that case; the
data files become seeds for every case that passes the whole input as one buffer. Seeds larger than
the harness's `max_input_size` are dropped. They go to workspace/seeds/<module>/ (replaced on each
write), which the fuzz and coverage recipes pass to the campaign with --extra-corpus; the summary of a
module is workspace/reports/seeds/<module>.json.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from framac_common import atomic_write_json, load_json_optional, utc_now  # noqa: E402

SCHEMA_VERSION = 1
MODEL_JSON = Path("workspace/reports/phase0_model.json")
CAPTURE_JSON = Path("workspace/reports/build_capture.json")
EVENTS_JSONL = Path("workspace/reports/build_capture/events.jsonl")
REPORT_JSON = Path("workspace/reports/seed_harvest.json")
RECORDS_DIR = Path("workspace/seed_records")
SEEDS_DIR = Path("workspace/seeds")
SEED_REPORTS_DIR = Path("workspace/reports/seeds")
HARNESS_DIR = Path("workspace/harnesses")
RUN_METADATA = Path("run-metadata.json")

DEFAULT_TIMEOUT_S = 600
MAX_CALLS_PER_FUNCTION = 2000  # recorded by the recorder per process and function
MAX_UNIQUE_CALLS_PER_FUNCTION = 1000  # kept after deduplication
MAX_VALUE_BYTES = 65536  # one recorded buffer or string
MAX_RECORD_BYTES = 64 * 1024 * 1024  # all records of one process
MAX_FILES = 64  # secondary seeds: data files the tests open
MAX_FILE_BYTES = 1024 * 1024
MAX_SEEDS_PER_MODULE = 2000
WRAP_LIMIT = 4000  # functions one recorder can wrap
MAX_TRACE_CALLS = 256  # calls kept, in order, of one process's trace
MAX_TRACES = 512  # distinct traces kept (one per process)
EXECUTABLE_TIMEOUT_S = 60  # one run of a non-test executable, when the recipe has no test command
SEED_PREFIX = "seed-"

_SCALARS = {
    "_Bool": "int",
    "char": "int",
    "signed char": "int",
    "unsigned char": "int",
    "short": "int",
    "unsigned short": "int",
    "int": "int",
    "unsigned int": "int",
    "long": "int",
    "unsigned long": "int",
    "long long": "int",
    "unsigned long long": "int",
    "float": "float",
    "double": "float",
    "long double": "float",
}
_TYPEDEF_SCALARS = {
    "size_t": "unsigned long",
    "ssize_t": "long",
    "int8_t": "signed char",
    "uint8_t": "unsigned char",
    "int16_t": "short",
    "uint16_t": "unsigned short",
    "int32_t": "int",
    "uint32_t": "unsigned int",
    "int64_t": "long",
    "uint64_t": "unsigned long",
    "intptr_t": "long",
    "uintptr_t": "unsigned long",
    "bool": "_Bool",
}
_LEN_SCALARS = {
    "short",
    "unsigned short",
    "int",
    "unsigned int",
    "long",
    "unsigned long",
    "long long",
    "unsigned long long",
}
_UNSIGNED_LEN_SCALARS = {"unsigned short", "unsigned int", "unsigned long", "unsigned long long"}
# A signed integer is a length only when its formal says so: `len`, `size`, `count`, `nBytes`, `n`.
_LEN_NAME_RE = re.compile(r"[Ll]en|[Ss]ize|[Cc]ount|[Cc]nt|[Bb]ytes|^n(?:[A-Z_0-9]|$)|^num|^N$")
_CHAR_POINTEES = {"char", "signed char", "unsigned char", "void"}
_QUALIFIERS_RE = re.compile(r"\b(?:const|volatile|restrict|__restrict|__restrict__)\b")
_ATTR_RE = re.compile(r"\b__attribute__\s*\(\(.*?\)\)")
_TAG_RE = re.compile(r"^(struct|union|enum)\s+([A-Za-z_]\w*)$")
_IDENT_RE = re.compile(r"^[A-Za-z_]\w*$")


class SeedError(RuntimeError):
    pass


# ---------------------------------------------------------------------------------------------------
# 1. Signatures (the model's Frama-C type strings) and the recorder
# ---------------------------------------------------------------------------------------------------


def _norm_type(t: str) -> str:
    cleaned = _ATTR_RE.sub(" ", _QUALIFIERS_RE.sub(" ", t))
    return " ".join(cleaned.split()).replace(" *", "*").replace("*", " *").strip()


def split_signature(sig: str) -> tuple[str, list[str], bool] | None:
    """(return type, parameter types, variadic) of a model signature such as `int(char *,_Bool)`."""
    sig = _ATTR_RE.sub("", (sig or "").strip()).strip()
    i = sig.find("(")
    if i <= 0 or not sig.endswith(")") or sig[i:].startswith("(*"):
        return None
    ret, body = sig[:i].strip(), sig[i + 1 : -1]
    depth = 0
    for ch in body:
        depth += ch == "("
        depth -= ch == ")"
        if depth < 0:
            return None
    if depth:
        return None
    params: list[str] = []
    cur, depth = "", 0
    for ch in body:
        if ch == "," and depth == 0:
            params.append(cur.strip())
            cur = ""
            continue
        depth += ch == "("
        depth -= ch == ")"
        cur += ch
    if cur.strip():
        params.append(cur.strip())
    variadic = bool(params) and params[-1] == "..."
    if variadic:
        params = params[:-1]
    if params == ["void"]:
        params = []
    return ret, params, variadic


def classify_type(t: str) -> dict[str, Any]:
    """How the recorder declares and records one type: {kind, ctype, ...} or {kind: unsupported, why}."""
    n = _norm_type(t)
    if "(" in n:
        return {"kind": "fnptr", "ctype": "void *"}
    if n.endswith("*"):
        pointee = n[:-1].strip()
        pointee = _TYPEDEF_SCALARS.get(pointee, pointee)
        return {"kind": "ptr", "ctype": "void *", "pointee": pointee}
    if "[" in n:
        return {"kind": "ptr", "ctype": "void *", "pointee": ""}
    n = _TYPEDEF_SCALARS.get(n, n)
    if n == "void":
        return {"kind": "void", "ctype": "void"}
    if n in _SCALARS:
        return {"kind": _SCALARS[n], "ctype": n}
    m = _TAG_RE.match(n)
    if m:
        what, tag = m.groups()
        if what == "enum":
            return {"kind": "int", "ctype": "int", "enum": True}
        if tag.startswith("__anon"):
            return {"kind": "unsupported", "why": f"anonymous {what} by value"}
        return {"kind": "struct", "ctype": f"{what} {tag}", "tag": tag, "what": what}
    return {"kind": "unsupported", "why": f"type {n!r}"}


def is_length(p: dict[str, Any], name: str | None = None) -> bool:
    """
    Whether a classified parameter can be the length of the byte pointer before it: an unsigned
    integer (size_t), or a signed one whose formal name says length (or is unknown). Never an enum
    (QCBOR's `const char *szLabel, enum QCBORDecodeTagReq uTagReq` is a C string and a tag rule).
    """
    if p.get("kind") != "int" or p.get("enum"):
        return False
    ctype = p.get("ctype")
    if ctype in _UNSIGNED_LEN_SCALARS:
        return True
    return ctype in _LEN_SCALARS and (name is None or bool(_LEN_NAME_RE.search(name)))


def plan_function(
    name: str, signature: str, sizes: dict | None = None, names: list[str | None] | None = None
) -> dict[str, Any]:
    """
    The recorder plan of one API function: return and parameter types and what to record of each.
    `sizes` is the model's `param_sizes`: a pointer with no length next to it whose callers pass a
    known-size object (a key, a nonce, an array of scalars) is recorded with that many bytes ('a').
    `names` are the formals' names (the model's `formals`), which decide whether a signed integer
    after a byte pointer is its length.
    """
    parts = split_signature(signature)
    if parts is None:
        return {"name": name, "supported": False, "why": f"signature {signature!r} not understood"}
    ret_s, params_s, variadic = parts
    if variadic:
        return {"name": name, "supported": False, "why": "variadic"}
    ret = classify_type(ret_s)
    if ret["kind"] == "unsupported":
        return {"name": name, "supported": False, "why": f"return {ret['why']}"}
    params = [classify_type(p) for p in params_s]
    for p in params:
        if p["kind"] in ("unsupported", "void"):
            return {"name": name, "supported": False, "why": p.get("why") or "void parameter"}
    for i, p in enumerate(params):
        if p["kind"] != "ptr":
            p["record"] = {"int": "i", "float": "f", "struct": "t"}.get(p["kind"])
            continue
        pointee = p["pointee"]
        nxt = params[i + 1] if i + 1 < len(params) else None
        nxt_name = names[i + 1] if names is not None and i + 1 < len(names) else None
        if pointee in _CHAR_POINTEES and nxt is not None and is_length(nxt, nxt_name):
            p["record"] = "b"  # (buffer, length) pair: the next argument is its length
        elif pointee in ("char", "signed char"):
            p["record"] = "s"
        elif pointee in _SCALARS and pointee != "_Bool":
            p["record"] = "p"
        else:
            p["record"] = None
        known = (sizes or {}).get(str(i))
        if p["record"] in (None, "p") and isinstance(known, dict) and int(known.get("max") or 0) > 0:
            p["record"] = "a"
            p["size"] = min(int(known["max"]), MAX_VALUE_BYTES)
    structs = sorted({p["ctype"] for p in [ret, *params] if p["kind"] == "struct"})
    return {"name": name, "supported": True, "ret": ret, "params": params, "structs": structs}


RECORDER_RUNTIME = r"""
/* Seed recorder runtime (scripts/seed_harvest.py). Compiled without the target's flags. */
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FC_CAP %(cap)d
#define FC_TOTAL %(total)d
#define FC_MAX_CALLS %(max_calls)d
#define FC_FUNCS %(funcs)d

static __thread int fc_depth;
static int fc_fd = -1;
static long fc_fd_pid = -1;
static int fc_pipe[2] = {-1, -1};
static long fc_pipe_pid = -1;
static size_t fc_total;
static unsigned fc_calls[FC_FUNCS];
static char *fc_buf;
static size_t fc_len, fc_capacity;

static void fc_put(const char *s, size_t n) {
    if (fc_len + n + 1 > fc_capacity) {
        size_t want = fc_capacity ? fc_capacity * 2 : 4096;
        while (want < fc_len + n + 1) want *= 2;
        char *grown = (char *)realloc(fc_buf, want);
        if (grown == NULL) return;
        fc_buf = grown;
        fc_capacity = want;
    }
    memcpy(fc_buf + fc_len, s, n);
    fc_len += n;
}

static void fc_hex(const unsigned char *p, size_t n) {
    static const char digits[] = "0123456789abcdef";
    char chunk[512];
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        chunk[k++] = digits[p[i] >> 4];
        chunk[k++] = digits[p[i] & 15];
        if (k == sizeof chunk) { fc_put(chunk, k); k = 0; }
    }
    if (k) fc_put(chunk, k);
}

/* Copies up to n bytes from p through a pipe, a page at a time: a bad address ends the copy (EFAULT)
   instead of crashing the test. Returns the number of bytes copied. */
static size_t fc_copy(unsigned char *dst, const void *p, size_t n) {
    long pid = (long)getpid();
    if (fc_pipe_pid != pid) {
        if (fc_pipe[0] >= 0) { close(fc_pipe[0]); close(fc_pipe[1]); }
        fc_pipe[0] = fc_pipe[1] = -1;
        if (pipe(fc_pipe) != 0) return 0;
        fcntl(fc_pipe[0], F_SETFD, FD_CLOEXEC);
        fcntl(fc_pipe[1], F_SETFD, FD_CLOEXEC);
        fcntl(fc_pipe[0], F_SETFL, O_NONBLOCK);
        fcntl(fc_pipe[1], F_SETFL, O_NONBLOCK);
        fc_pipe_pid = pid;
    }
    size_t done = 0;
    while (done < n) {
        uintptr_t a = (uintptr_t)p + done;
        size_t chunk = 4096 - (size_t)(a & 4095U);
        if (chunk > n - done) chunk = n - done;
        ssize_t w = write(fc_pipe[1], (const char *)p + done, chunk);
        if (w <= 0) break;
        ssize_t r = read(fc_pipe[0], dst + done, (size_t)w);
        if (r != w) break;
        done += (size_t)w;
    }
    return done;
}

int fc_enter(int fn) {
    fc_depth++;
    if (fc_depth != 1 || fn < 0 || fn >= FC_FUNCS || fc_total >= FC_TOTAL) return 0;
    if (fc_calls[fn] >= FC_MAX_CALLS) return 0;
    fc_calls[fn]++;
    return 1;
}

void fc_leave(void) { fc_depth--; }

void fc_begin(const char *name) {
    fc_len = 0;
    fc_put(name, strlen(name));
}

static void fc_head(int idx, char kind, size_t off, int with_off) {
    char head[48];
    int k = with_off ? snprintf(head, sizeof head, " %%d%%c%%lu=", idx, kind, (unsigned long)off)
                     : snprintf(head, sizeof head, " %%d%%c=", idx, kind);
    if (k > 0) fc_put(head, (size_t)k);
}

/* A value held by the wrapper itself (a scalar or struct argument): read directly. */
void fc_raw(int idx, char kind, const void *p, size_t n) {
    fc_head(idx, kind, 0, 0);
    fc_hex((const unsigned char *)p, n);
}

/* Memory an argument points to: copied safely; `-` when nothing could be read. */
void fc_mem(int idx, char kind, const void *p, size_t n) {
    fc_head(idx, kind, 0, 0);
    if (p == NULL) { fc_put("-", 1); return; }
    if (n > FC_CAP) n = FC_CAP;
    unsigned char *tmp = (unsigned char *)malloc(n ? n : 1);
    if (tmp == NULL) { fc_put("-", 1); return; }
    size_t got = fc_copy(tmp, p, n);
    if (got < n) fc_put("-", 1); else fc_hex(tmp, n);
    free(tmp);
}

/* A pointer argument's address: calls passing the same address share that buffer (call traces). */
void fc_addr(int idx, const void *p) {
    char tok[48];
    if (p == NULL) return;
    int k = snprintf(tok, sizeof tok, " %%dx=%%lx", idx, (unsigned long)(uintptr_t)p);
    if (k > 0) fc_put(tok, (size_t)k);
}

/* A NUL-terminated string: copied safely up to FC_CAP bytes, without the NUL. */
void fc_str(int idx, const void *p) {
    fc_head(idx, 's', 0, 0);
    if (p == NULL) { fc_put("-", 1); return; }
    unsigned char *tmp = (unsigned char *)malloc(FC_CAP);
    if (tmp == NULL) { fc_put("-", 1); return; }
    size_t n = 0;
    while (n < FC_CAP) {
        uintptr_t a = (uintptr_t)p + n;
        size_t chunk = 4096 - (size_t)(a & 4095U);
        if (chunk > FC_CAP - n) chunk = FC_CAP - n;
        size_t got = fc_copy(tmp + n, (const char *)p + n, chunk);
        void *nul = memchr(tmp + n, 0, got);
        if (nul != NULL) { n = (size_t)((unsigned char *)nul - tmp); break; }
        n += got;
        if (got < chunk) break;
    }
    fc_hex(tmp, n);
    free(tmp);
}

/* A struct passed by value: its bytes when small, and every (pointer, length) pair in it whose
   memory can be read (a UsefulBufC, a slice), with the pair's offset. */
void fc_struct(int idx, const void *p, size_t n) {
    if (n <= 64) fc_raw(idx, 't', p, n);
    for (size_t off = 0; off + 2 * sizeof(void *) <= n; off += sizeof(void *)) {
        const void *ptr;
        size_t len;
        memcpy(&ptr, (const char *)p + off, sizeof ptr);
        memcpy(&len, (const char *)p + off + sizeof ptr, sizeof len);
        if (ptr == NULL || len == 0 || len > FC_CAP) continue;
        unsigned char *tmp = (unsigned char *)malloc(len);
        if (tmp == NULL) continue;
        if (fc_copy(tmp, ptr, len) == len) {
            fc_head(idx, 'n', off, 1);
            fc_hex(tmp, len);
        }
        free(tmp);
    }
}

void fc_end(void) {
    long pid = (long)getpid();
    fc_put("\n", 1);
    if (fc_fd_pid != pid) {
        char path[1024];
        snprintf(path, sizeof path, "%%s/calls-%%ld.txt", FC_OUT_DIR, pid);
        fc_fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fc_fd >= 0) fcntl(fc_fd, F_SETFD, FD_CLOEXEC);
        fc_fd_pid = pid;
    }
    if (fc_fd >= 0 && fc_len) {
        int saved = errno;
        ssize_t w = write(fc_fd, fc_buf, fc_len);
        if (w > 0) fc_total += (size_t)w;
        errno = saved;
    }
    fc_len = 0;
}
"""


def _record_stmt(i: int, p: dict[str, Any], params: list[dict[str, Any]]) -> str | None:
    kind = p.get("record")
    a = f"a{i}"
    if kind == "i" or kind == "f":
        return f"fc_raw({i}, '{kind}', &{a}, sizeof {a});"
    if kind == "t":
        return f"fc_struct({i}, &{a}, sizeof {a});"
    if kind == "s":
        return f"fc_str({i}, {a});"
    if kind == "b":
        return f"fc_mem({i}, 'b', {a}, (size_t)a{i + 1});"
    if kind == "p":
        return f"fc_mem({i}, 'p', {a}, sizeof({p['pointee']}));"
    if kind == "a":
        return f"fc_mem({i}, 'a', {a}, (size_t){int(p['size'])});"
    return None


def wrapper_source(plans: list[dict[str, Any]], headers: list[str]) -> str:
    """The `__wrap_<fn>` definitions of the supported plans (index i is the plan's position)."""
    lines = [
        "/* Seed recorder wrappers (scripts/seed_harvest.py). Compiled with the test's own flags. */",
        "#include <stddef.h>",
        *[f'#include "{h}"' for h in headers],
        "int fc_enter(int fn);",
        "void fc_leave(void);",
        "void fc_begin(const char *name);",
        "void fc_raw(int idx, char kind, const void *p, size_t n);",
        "void fc_mem(int idx, char kind, const void *p, size_t n);",
        "void fc_str(int idx, const void *p);",
        "void fc_addr(int idx, const void *p);",
        "void fc_struct(int idx, const void *p, size_t n);",
        "void fc_end(void);",
        "",
    ]
    for k, plan in enumerate(plans):
        name, ret, params = plan["name"], plan["ret"], plan["params"]
        decl = ", ".join(f"{p['ctype']} a{i}" for i, p in enumerate(params)) or "void"
        call = ", ".join(f"a{i}" for i in range(len(params)))
        rec = [s for i, p in enumerate(params) if (s := _record_stmt(i, p, params))]
        rec += [f"fc_addr({i}, a{i});" for i, p in enumerate(params) if p["kind"] == "ptr"]
        lines.append(f"extern {ret['ctype']} __real_{name}({decl});")
        lines.append(f"{ret['ctype']} __wrap_{name}({decl}) {{")
        lines.append(f'    if (fc_enter({k})) {{ fc_begin("{name}"); {" ".join(rec)} fc_end(); }}')
        if ret["kind"] == "void":
            lines.append(f"    __real_{name}({call});")
            lines.append("    fc_leave();")
        else:
            lines.append(f"    {ret['ctype']} r = __real_{name}({call});")
            lines.append("    fc_leave();")
            lines.append("    return r;")
        lines.append("}")
    return "\n".join(lines) + "\n"


def runtime_source(n_funcs: int) -> str:
    return RECORDER_RUNTIME % {
        "cap": MAX_VALUE_BYTES,
        "total": MAX_RECORD_BYTES,
        "max_calls": MAX_CALLS_PER_FUNCTION,
        "funcs": max(1, n_funcs),
    }


_TOKEN_RE = re.compile(r"(\d+)([a-z])(\d*)=([0-9a-f]*|-)")


def parse_record_line(line: str) -> dict[str, Any] | None:
    """
    One recorder line: `name 0s=68656c6c6f 1i=0a000000 2n0=... 0x=7ffd10` -> {fn, args: {idx: [[kind,
    off, hex]]}, addrs: {idx: hex address}}. Addresses (`x`) only link calls within one process.
    """
    parts = line.strip().split(" ")
    if not parts or not _IDENT_RE.match(parts[0]):
        return None
    args: dict[str, list[list[Any]]] = {}
    addrs: dict[str, str] = {}
    for tok in parts[1:]:
        m = _TOKEN_RE.fullmatch(tok)
        if not m:
            return None
        idx, kind, off, hexv = m.groups()
        if hexv == "-":
            continue
        if kind == "x":
            addrs[idx] = hexv
            continue
        args.setdefault(idx, []).append([kind, int(off) if off else 0, hexv])
    return {"fn": parts[0], "args": args, "addrs": addrs}


def trace_call(rec: dict[str, Any]) -> dict[str, Any]:
    """A trace entry: the call with its pointer addresses and the bytes recorded per argument."""
    sizes: dict[str, int] = {}
    for idx, vals in rec["args"].items():
        # Buffers only: a 'p' record is one pointee and an 's' record a string's length, not the object.
        lens = [len(hexv) // 2 for kind, _off, hexv in vals if kind in ("a", "b")]
        if lens:
            sizes[idx] = max(lens)
    return {"fn": rec["fn"], "args": rec["args"], "addrs": rec.get("addrs") or {}, "sizes": sizes}


# ---------------------------------------------------------------------------------------------------
# 2. record (build image)
# ---------------------------------------------------------------------------------------------------


def _header_index(tree: Path) -> list[Path]:
    skip = {".git", "CMakeFiles"}
    out: list[Path] = []
    for root, dirs, files in os.walk(tree):
        dirs[:] = sorted(d for d in dirs if d not in skip)
        out += [Path(root) / f for f in sorted(files) if f.endswith(".h")]
    return out


def struct_headers(tags: set[str], headers: list[Path]) -> dict[str, Path]:
    """`struct tag` / `union tag` -> the first project header defining it."""
    found: dict[str, Path] = {}
    wanted = {t: re.compile(rf"\b{t.split()[0]}\s+{re.escape(t.split()[1])}\s*\{{") for t in tags}
    for h in headers:
        if len(found) == len(wanted):
            break
        try:
            text = h.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for t, rx in wanted.items():
            if t not in found and rx.search(text):
                found[t] = h
    return found


def _run(argv: list[str], cwd: Path, timeout: int) -> tuple[int, str]:
    import subprocess

    try:
        p = subprocess.run(argv, cwd=str(cwd), capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, str(exc)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def defined_functions(binary: Path) -> set[str]:
    rc, out = _run(["nm", "--defined-only", str(binary)], binary.parent, 120)
    if rc != 0:
        return set()
    names: set[str] = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] in ("T", "W"):
            names.add(parts[2])
    return names


def link_commands(events: Path, tree: Path) -> dict[str, dict]:
    """Output (tree-relative) -> the last link execution producing it, from bear's events."""
    import build_capture as bc

    out: dict[str, dict] = {}
    for ex in bc.read_executions(events):
        args = ex["args"]
        if not args or not bc._COMPILER_RE.match(Path(args[0]).name):
            continue
        cwd = ex["cwd"] or str(tree)
        d = bc.parse_driver(bc.expand_response_files(args, cwd))
        if d["mode"] != "link":
            continue
        output = bc.norm_in_tree(d["output"] or "a.out", cwd, str(tree))
        out[output] = {"args": args, "cwd": cwd}
    return out


def compile_flags_for(unit: dict, capture: dict, tree: Path) -> list[str]:
    """Preprocessing flags of the test unit's first compile, with absolute paths."""
    import build_capture as bc

    objs = set(unit.get("objects") or [])
    for c in capture.get("compiles") or []:
        if c.get("object") in objs:
            return bc.absolute_flags(list(c.get("flags") or []), str(tree)) + list(c.get("system_flags") or [])
    return []


def plan_recorder(model: dict) -> tuple[list[dict], dict[str, str]]:
    """Plans of the model's API entry points (`main` excluded), and why the others are skipped."""
    plans: list[dict] = []
    skipped: dict[str, str] = {}
    functions = model.get("functions") or {}
    seen: set[str] = set()
    # An executable's embedded API (a library compiled into it) is API too, as for trust and the DAG.
    embedded = {
        e
        for u in (model.get("units") or {}).values()
        if isinstance(u, dict) and not u.get("test")
        for e in u.get("embedded_api") or []
    }
    for fid in sorted({*(model.get("entry_points") or []), *embedded}):
        rec = functions.get(fid) or {}
        name = str(rec.get("name") or fid.split("#")[-1])
        if name == "main" or name in seen:
            continue
        seen.add(name)
        if rec.get("static") or (rec.get("inline") and rec.get("header")):
            skipped[name] = "static or header inline: not a linked symbol"
            continue
        formals = rec.get("formals") if isinstance(rec.get("formals"), list) else None
        names = [f.get("name") if isinstance(f, dict) else None for f in formals] if formals is not None else None
        plan = plan_function(name, str(rec.get("signature") or ""), rec.get("param_sizes"), names)
        if plan["supported"]:
            plans.append(plan)
        else:
            skipped[name] = plan["why"]
    return plans, skipped


def strace_opened(text: str, tree: Path) -> list[str]:
    """Files (absolute) opened for reading only under `tree`, in first-open order, from `strace -y` output."""
    out: list[str] = []
    prefix = str(tree).rstrip("/") + "/"
    rx = re.compile(r'openat\([^"]*"[^"]*",\s*([A-Z_|]+)[^)]*\)\s*=\s*\d+<([^>]+)>')
    for line in text.splitlines():
        m = rx.search(line)
        if not m:
            continue
        flags, path = m.groups()
        if any(f in flags for f in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_DIRECTORY", "O_PATH", "O_TRUNC")):
            continue
        if path.startswith(prefix) and path not in out:
            out.append(path)
    return out


_NOT_DATA_SUFFIXES = (
    ".c",
    ".h",
    ".o",
    ".a",
    ".so",
    ".d",
    ".cmake",
    ".make",
    ".mk",
    ".in",
    ".py",
    ".sh",
    ".log",
)
_NOT_DATA_NAMES = {"Makefile", "CMakeCache.txt", "CTestTestfile.cmake", "CMakeLists.txt", "DartConfiguration.tcl"}


def is_data_file(path: Path, tree: Path) -> bool:
    rel = path.relative_to(tree).as_posix() if path.is_relative_to(tree) else ""
    parts = rel.split("/")
    if not rel or ".git" in parts or "CMakeFiles" in parts or "Testing" in parts[:2]:
        return False
    if path.name in _NOT_DATA_NAMES or path.name.endswith(_NOT_DATA_SUFFIXES) or ".so." in path.name:
        return False
    try:
        if not path.is_file() or path.stat().st_size == 0 or path.stat().st_size > MAX_FILE_BYTES:
            return False
        with path.open("rb") as fh:
            return fh.read(4) != b"\x7fELF"
    except OSError:
        return False


def _load_recipe() -> dict | None:
    meta = load_json_optional(RUN_METADATA, {}) or {}
    recipe = meta.get("build") if isinstance(meta, dict) else None
    return recipe if isinstance(recipe, dict) else None


def record(args: argparse.Namespace) -> tuple[dict, int]:
    started = time.monotonic()
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "status": "error",
        "test_command": None,
        "test_units": [],
        "warnings": [],
    }
    recipe = None
    if args.recipe_file:
        data = load_json_optional(Path(args.recipe_file), {}) or {}
        recipe = data.get("build") if isinstance(data, dict) else None
    recipe = recipe or _load_recipe()
    command = (recipe or {}).get("test_command")
    report["test_command"] = command
    report["source"] = "test_command" if command else "executables"
    model = load_json_optional(MODEL_JSON, None)
    capture = load_json_optional(CAPTURE_JSON, None)
    if not isinstance(model, dict) or model.get("status") != "ok":
        report["status"] = "no_model"
        return report, 0
    if not isinstance(capture, dict) or capture.get("status") != "ok":
        report["status"] = "no_capture"
        return report, 0
    scratch = Path(args.scratch)
    tree = Path((capture.get("scratch") or {}).get("tree") or scratch / "tree")
    if not tree.is_dir():
        report["status"] = "no_build_tree"
        report["warnings"].append(f"{tree} not found: run build_capture.py on this scratch volume first")
        return report, 0
    units = capture.get("units") or {}
    if command:
        # Every executable is relinked, not only the units the name rule calls tests: the test command
        # decides which ones run (libpng's ctest runs `pngtest`, `pngvalid`, ... none named as a test).
        # One it does not run records nothing.
        report["test_units"] = sorted(n for n, u in units.items() if u.get("test") and u.get("kind") == "executable")
        tests = {n: u for n, u in units.items() if u.get("kind") == "executable"}
        report["executables"] = sorted(tests)
        if not tests:
            report["status"] = "no_test_units"
            return report, 0
    else:
        # No test command: the project's own programs (demos, tools) are the only callers of its API
        # that ship with it. Each one that defines API functions is relinked and run once, with no
        # arguments and empty stdin; whatever it passes to the API becomes a seed.
        tests = {n: u for n, u in units.items() if not u.get("test") and u.get("kind") == "executable"}
        report["executables"] = sorted(tests)
        if not tests:
            report["status"] = "no_test_command"
            return report, 0

    plans, skipped = plan_recorder(model)
    links = link_commands(EVENTS_JSONL, tree)
    work = scratch / "seed_harvest"
    shutil.rmtree(work, ignore_errors=True)
    out_dir = work / "calls"
    out_dir.mkdir(parents=True)
    os.chmod(out_dir, 0o1777)
    headers = _header_index(tree)
    report["functions"] = {"planned": len(plans), "skipped": skipped}
    relinked: dict[str, Any] = {}
    for unit_name, unit in sorted(tests.items()):
        info: dict[str, Any] = {}
        relinked[unit_name] = info
        exe = tree / unit_name
        link = links.get(unit_name)
        if not exe.is_file() or link is None:
            info["status"] = "not_built" if not exe.is_file() else "no_link_command"
            continue
        defined = defined_functions(exe)
        mine = [p for p in plans if p["name"] in defined][:WRAP_LIMIT]
        if not mine:
            info["status"] = "no_api_function"
            continue
        tags = {t for p in mine for t in p["structs"]}
        where = struct_headers(tags, headers)
        dropped = [p["name"] for p in mine if any(t not in where for t in p["structs"])]
        for name in dropped:
            skipped[name] = "struct by value without a project header defining it"
        mine = [p for p in mine if p["name"] not in dropped]
        info["wrapped"] = [p["name"] for p in mine]
        cc = link["args"][0]
        flags = compile_flags_for(unit, capture, tree)
        rt_c, rt_o = work / f"rt-{len(relinked)}.c", work / f"rt-{len(relinked)}.o"
        wr_c, wr_o = work / f"wrap-{len(relinked)}.c", work / f"wrap-{len(relinked)}.o"
        rt_c.write_bytes(runtime_source(len(mine)).encode())
        rc, log = _run(
            [cc, "-c", "-O1", "-fPIC", "-w", f'-DFC_OUT_DIR="{out_dir}"', str(rt_c), "-o", str(rt_o)], work, 300
        )
        if rc != 0:
            info.update(status="recorder_compile_failed", log=log[-2000:])
            continue
        compiled, mine, log = _compile_wrappers(cc, flags, mine, where, wr_c, wr_o, work)
        for name in sorted(set(info["wrapped"]) - {p["name"] for p in mine}):
            skipped[name] = "wrapper does not compile with the test's flags"
        info["wrapped"] = [p["name"] for p in mine]
        if not compiled:
            info.update(status="recorder_compile_failed", log=log[-2000:])
            continue
        argv = [link["args"][0], str(rt_o), str(wr_o), *link["args"][1:]] + [f"-Wl,--wrap={p['name']}" for p in mine]
        res = _sandboxed(argv, Path(link["cwd"]), scratch, 600, {})
        if res.returncode != 0:
            info.update(status="relink_failed", log=((res.stdout or "") + (res.stderr or ""))[-2000:])
            continue
        info["status"] = "relinked"
    report["relink"] = relinked
    if not any(i.get("status") == "relinked" for i in relinked.values()):
        report["status"] = "not_relinked"
        _collect(report, out_dir, [], tree, started)
        return report, 0

    cwd = tree / str((recipe or {}).get("workdir") or ".")
    if not command:
        _run_executables(report, relinked, tree, cwd, scratch, args.timeout, dict((recipe or {}).get("env") or {}))
        _collect(report, out_dir, [], tree, started)
        return report, 0
    strace_log = work / "strace.txt"
    test_argv = ["sh", "-c", command]
    if shutil.which("strace"):
        test_argv = ["strace", "-f", "-qq", "-y", "-e", "trace=openat", "-o", str(strace_log), *test_argv]
    else:
        report["warnings"].append("strace not found: no secondary seeds from files the tests open")
    t0 = time.monotonic()
    res = _sandboxed(test_argv, cwd, scratch, args.timeout, dict((recipe or {}).get("env") or {}))
    report["test"] = {
        "returncode": res.returncode,
        "timed_out": res.timed_out,
        "seconds": round(time.monotonic() - t0, 2),
        "log_tail": ((res.stdout or "") + (res.stderr or ""))[-3000:],
    }
    if res.returncode != 0:
        report["warnings"].append(
            f"the test command exited {res.returncode}{' (timed out)' if res.timed_out else ''}: "
            "calls recorded before that are kept"
        )
    opened: list[str] = []
    if strace_log.is_file():
        opened = strace_opened(strace_log.read_text(encoding="utf-8", errors="replace"), tree)
    _collect(report, out_dir, opened, tree, started)
    return report, 0


def _run_executables(
    report: dict, relinked: dict, tree: Path, cwd: Path, scratch: Path, timeout: int, env: dict[str, str]
) -> None:
    """Run each relinked non-test executable once, no arguments, empty stdin, a short time cap."""
    cap = max(1, min(timeout, EXECUTABLE_TIMEOUT_S))
    runs: dict[str, Any] = {}
    for name, info in sorted(relinked.items()):
        if info.get("status") != "relinked":
            continue
        t0 = time.monotonic()
        res = _sandboxed([str(tree / name)], cwd, scratch, cap, env)
        runs[name] = {
            "returncode": res.returncode,
            "timed_out": res.timed_out,
            "seconds": round(time.monotonic() - t0, 2),
            "log_tail": ((res.stdout or "") + (res.stderr or ""))[-1000:],
        }
    report["runs"] = runs
    failed = sorted(n for n, r in runs.items() if r["returncode"] != 0)
    if failed:
        report["warnings"].append(
            f"{', '.join(failed)} exited non-zero without arguments: calls recorded before that are kept"
        )


def _compile_wrappers(
    cc: str, flags: list[str], plans: list[dict], where: dict[str, Path], src: Path, obj: Path, work: Path
) -> tuple[bool, list[dict], str]:
    """Compile the wrappers; on failure, keep the functions whose wrapper compiles alone."""

    def attempt(ps: list[dict], c: Path, o: Path) -> tuple[int, str]:
        hdrs = sorted({where[t].as_posix() for p in ps for t in p["structs"]})
        c.write_bytes(wrapper_source(ps, hdrs).encode())
        incs = sorted({f"-I{Path(h).parent.as_posix()}" for h in hdrs})
        return _run([cc, "-c", "-O0", "-fPIC", "-w", *flags, *incs, str(c), "-o", str(o)], work, 300)

    rc, log = attempt(plans, src, obj)
    if rc == 0:
        return True, plans, log
    good = [p for i, p in enumerate(plans) if attempt([p], work / f"one-{i}.c", work / f"one-{i}.o")[0] == 0]
    if not good:
        return False, [], log
    rc, log2 = attempt(good, src, obj)
    return rc == 0, good if rc == 0 else [], log2


def _sandboxed(argv: list[str], cwd: Path, scratch: Path, timeout: int, env: dict[str, str]) -> Any:
    from sandbox_exec import Limits, run_sandboxed

    limits = Limits(cpu_seconds=timeout, processes=2048, file_size_mb=2048, open_files=4096)
    return run_sandboxed(argv, [scratch], timeout, cwd=cwd, limits=limits, extra_env=env)


def _collect(report: dict, out_dir: Path, opened: list[str], tree: Path, started: float) -> None:
    """Deduplicate the recorded calls into workspace/seed_records, copy the data files, finish the report."""
    if RECORDS_DIR.exists():
        shutil.rmtree(RECORDS_DIR)
    (RECORDS_DIR / "files").mkdir(parents=True)
    seen: set[str] = set()
    seen_traces: set[str] = set()
    per_fn: dict[str, int] = {}
    total = unique = bad = 0
    with (
        (RECORDS_DIR / "calls.jsonl").open("w", encoding="utf-8", newline="\n") as out,
        (RECORDS_DIR / "traces.jsonl").open("w", encoding="utf-8", newline="\n") as tr_out,
    ):
        # One file per process, its calls in order: the trace of that process.
        for path in sorted(out_dir.glob("calls-*.txt")) if out_dir.is_dir() else []:
            trace: list[dict] = []
            for line in path.read_text(encoding="ascii", errors="replace").splitlines():
                rec = parse_record_line(line)
                if rec is None:
                    bad += 1
                    continue
                total += 1
                if len(trace) < MAX_TRACE_CALLS:
                    trace.append(trace_call(rec))
                # Addresses differ between runs: the same arguments are the same call.
                call = {"fn": rec["fn"], "args": rec["args"]}
                text = json.dumps(call, separators=(",", ":"), sort_keys=True)
                key = hashlib.sha256(text.encode()).hexdigest()
                if key in seen or per_fn.get(rec["fn"], 0) >= MAX_UNIQUE_CALLS_PER_FUNCTION:
                    continue
                seen.add(key)
                per_fn[rec["fn"]] = per_fn.get(rec["fn"], 0) + 1
                unique += 1
                out.write(json.dumps(call, separators=(",", ":")) + "\n")
            if len(trace) > 1 and len(seen_traces) < MAX_TRACES:
                shape = json.dumps([[c["fn"], c["args"]] for c in trace], separators=(",", ":"), sort_keys=True)
                digest = hashlib.sha256(shape.encode()).hexdigest()
                if digest not in seen_traces:
                    seen_traces.add(digest)
                    tr_out.write(
                        json.dumps({"pid": path.stem.split("-", 1)[-1], "calls": trace}, separators=(",", ":")) + "\n"
                    )
    files: list[dict] = []
    for p in opened:
        path = Path(p)
        if len(files) >= MAX_FILES or not is_data_file(path, tree):
            continue
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        (RECORDS_DIR / "files" / digest[:32]).write_bytes(data)
        files.append({"path": path.relative_to(tree).as_posix(), "bytes": len(data), "sha256": digest})
    report["traces"] = len(seen_traces)
    report["calls"] = {
        "recorded": total,
        "unique": unique,
        "unparsed_lines": bad,
        "by_function": dict(sorted(per_fn.items())),
    }
    report["files"] = {"opened_in_tree": len(opened), "kept": files}
    report["records"] = RECORDS_DIR.as_posix()
    if report["status"] == "error":
        report["status"] = "ok" if unique or files else "no_calls_recorded"
    report["seconds"] = round(time.monotonic() - started, 2)


# ---------------------------------------------------------------------------------------------------
# 3. write: recorded calls -> each harness's case format
# ---------------------------------------------------------------------------------------------------

_INVOKE_MARK = "/* Invoke target module entry point */"


def strip_comments(text: str) -> str:
    return re.sub(r"/\*.*?\*/|//[^\n]*", " ", text, flags=re.S)


def _match_brace(text: str, start: int, open_ch: str = "{", close_ch: str = "}") -> int:
    depth = 0
    i = start
    while i < len(text):
        ch = text[i]
        if ch in "\"'":
            j = i + 1
            while j < len(text) and text[j] != ch:
                j += 2 if text[j] == "\\" else 1
            i = j + 1
            continue
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def fuzz_invocation(harness_c: str) -> str:
    """The fuzz-side invocation block of a generated harness (LLVMFuzzerTestOneInput, after the input copy)."""
    k = harness_c.find("LLVMFuzzerTestOneInput")
    body = harness_c[k:] if k >= 0 else harness_c
    m = body.find(_INVOKE_MARK)
    if m >= 0:
        body = body[m + len(_INVOKE_MARK) :]
    end = body.rfind("free(alloc_ptr)")
    return strip_comments(body[:end] if end >= 0 else body)


def harness_cases(harness_c: str) -> list[tuple[int | None, str]]:
    """(selector byte or None, statement) per case of a harness's fuzz entry point."""
    block = fuzz_invocation(harness_c)
    m = re.search(r"switch\s*\(\s*harness_selector\s*%\s*(\d+)U?\s*\)\s*\{", block)
    if not m:
        return [(None, block)]
    end = _match_brace(block, m.end() - 1)
    body = block[m.end() : end if end > 0 else len(block)]
    cases: list[tuple[int | None, str]] = []
    for c in re.finditer(r"\bcase\s+(\d+)U?\s*:\s*\{", body):
        close = _match_brace(body, c.end() - 1)
        if close > 0:
            cases.append((int(c.group(1)), body[c.end() : close]))
    return cases


def _split_args(text: str) -> list[str]:
    out: list[str] = []
    cur, depth = "", 0
    for ch in text:
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


_CAST_RE = re.compile(r"^\(\s*(?:const\s+|volatile\s+|unsigned\s+|signed\s+|struct\s+|enum\s+)*[A-Za-z_]\w*[\s*]*\)\s*")


def _bare(arg: str) -> str:
    a = arg.strip()
    while True:
        b = _CAST_RE.sub("", a, count=1).strip()
        if b.startswith("(") and _match_brace(b, 0, "(", ")") == len(b) - 1:
            b = b[1:-1].strip()
        if b == a:
            return a
        a = b


# The harness's own copies name their source through a macro (api_harness.FUZZ_COPY).
_FUZZ_COPY_RE = re.compile(r"FRAMAC_FUZZ_COPY\(\s*fuzz_buf\s*,\s*fuzz_off\s*\)")


def case_bindings(stmt: str, functions: set[str]) -> dict[str, Any]:
    """
    How one case turns its input into API arguments: the scalar slots it reads first (in order), and per
    call of a recorded function, which parameter receives a slot ('slot'/'pslot' with the variable) or
    the rest of the input ('data' for a pointer or string, 'struct' for a struct around it).
    """
    s = _FUZZ_COPY_RE.sub("fuzz_buf + fuzz_off", strip_comments(stmt))
    slots: list[str] = []
    data: set[str] = set()
    structs: set[str] = set()
    for m in re.finditer(r"memcpy\s*\(\s*(&?)\s*([A-Za-z_]\w*)\s*,\s*([^,]+),", s):
        amp, var, src = m.groups()
        src_b = _bare(src)
        if amp and re.fullmatch(r"fuzz_buf(\s*\+\s*fuzz_off)?", src_b):
            slots.append(var)
        elif not amp and src_b == "fuzz_buf":
            data.add(var)
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*=\s*([^;=][^;]*);", s):
        var, rhs = m.groups()
        rhs_b = _bare(rhs)
        if var in ("fuzz_buf", "fuzz_len", "fuzz_off"):
            continue
        if re.fullmatch(r"fuzz_buf(\s*\+\s*fuzz_off)?", rhs_b):
            data.add(var)
        elif rhs_b.startswith("{") and re.match(r"\{\s*(?:\([^()]*\)\s*)?fuzz_buf\b", rhs_b):
            structs.add(var)
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\.\s*[A-Za-z_]\w*\s*=\s*([^;]+);", s):
        if _bare(m.group(2)) == "fuzz_buf":
            structs.add(m.group(1))
    calls: list[dict[str, Any]] = []
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", s):
        fn = m.group(1)
        if fn not in functions:
            continue
        close = _match_brace(s, m.end() - 1, "(", ")")
        if close < 0:
            continue
        binds: dict[int, tuple[str, str]] = {}
        for i, arg in enumerate(_split_args(s[m.end() : close])):
            b = _bare(arg)
            if b.startswith("&") and _bare(b[1:]) in slots:
                binds[i] = ("pslot", _bare(b[1:]))
            elif b in slots:
                binds[i] = ("slot", b)
            elif b in structs or (b.startswith("{") and "fuzz_buf" in b):
                binds[i] = ("struct", b)
            elif b in data or re.fullmatch(r"fuzz_buf(\s*\+\s*fuzz_off)?", b):
                binds[i] = ("data", b)
        if binds:
            calls.append({"fn": fn, "binds": binds})
    return {"slots": slots, "calls": calls}


def _value(rec_args: dict[str, list], idx: int, want: str) -> bytes | None:
    """The recorded bytes of parameter idx for a binding kind ('data', 'struct', 'slot', 'pslot')."""
    vals = rec_args.get(str(idx)) or []
    kinds = {"data": ("s", "b"), "struct": ("n",), "slot": ("i", "f"), "pslot": ("p",)}[want]
    hits = sorted((off, hexv) for kind, off, hexv in vals if kind in kinds)
    return bytes.fromhex(hits[0][1]) if hits else None


def seeds_for_case(selector: int | None, binding: dict[str, Any], calls: list[dict]) -> list[bytes]:
    """Seed inputs of one case from the recorded calls of the functions it passes its input to."""
    prefix = bytes([selector]) if selector is not None else b""
    out: list[bytes] = []
    by_fn: dict[str, list[dict]] = {}
    for c in binding["calls"]:
        by_fn.setdefault(c["fn"], []).append(c)
    for rec in calls:
        for c in by_fn.get(rec["fn"], []):
            slot_vals: dict[str, bytes] = {}
            data: bytes | None = None
            ok = True
            for idx, (kind, var) in sorted(c["binds"].items()):
                v = _value(rec["args"], idx, kind)
                if kind in ("slot", "pslot"):
                    if v is None:
                        ok = False
                        break
                    slot_vals[var] = v
                elif data is None and v is not None:
                    data = v
            if not ok or any(s not in slot_vals for s in binding["slots"]):
                continue
            if data is None and not binding["slots"]:
                continue
            out.append(prefix + b"".join(slot_vals[s] for s in binding["slots"]) + (data or b""))
    return out


def whole_input_cases(bindings: list[tuple[int | None, dict]]) -> list[int | None]:
    """Cases that pass their whole input (no scalar slot) to an API function: where data files fit."""
    return [
        sel
        for sel, b in bindings
        if not b["slots"] and any(k in ("data", "struct") for c in b["calls"] for k, _ in c["binds"].values())
    ]


def load_calls(records: Path = RECORDS_DIR) -> list[dict]:
    path = records / "calls.jsonl"
    out: list[dict] = []
    if not path.is_file():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict) and isinstance(rec.get("fn"), str) and isinstance(rec.get("args"), dict):
            out.append(rec)
    return out


# The recorded value kinds each layout slot of an API harness (scripts/api_harness.py) reads.
_LAYOUT_KINDS = {"int": ("i", "f"), "struct": ("t",), "bytes": ("a", "b", "p", "s"), "pointee": ("p", "a")}


def _fit(value: bytes, size: int | None) -> bytes:
    if size is None:
        return value
    return value[:size].ljust(size, b"\0")


def _recorded(args: dict, param: int, kinds: tuple[str, ...]) -> bytes | None:
    hits = sorted((off, hexv) for kind, off, hexv in args.get(str(param)) or [] if kind in kinds)
    return bytes.fromhex(hits[0][1]) if hits else None


def _pair_recorded(args: dict, param: int, off: int) -> bytes | None:
    """The memory of the (pointer, length) pair at byte `off` of a struct argument (the recorder's 'n')."""
    for kind, o, hexv in args.get(str(param)) or []:
        if kind == "n" and int(o) == off:
            return bytes.fromhex(hexv)
    return None


def _slot_value(slot: dict, args: dict) -> bytes | None:
    """
    A slot's recorded value. A struct field slot (api_harness.py `_fill_fields`) never takes a recorded
    pointer: `field` takes the struct's raw bytes at a scalar field, `field_bytes` the memory a pair
    pointed to, `field_len` that memory's length (clamped to the slot's `max`).
    """
    kind, param = slot["kind"], int(slot["param"])
    if kind == "field":
        raw = _recorded(args, param, ("t",))
        off, size = int(slot.get("off") or 0), int(slot.get("size") or 0)
        return raw[off : off + size] if raw is not None and len(raw) >= off + size else None
    if kind == "field_bytes":
        return _pair_recorded(args, param, int(slot.get("off") or 0))
    if kind == "field_len":
        data = _pair_recorded(args, param, int(slot.get("off") or 0))
        if data is None:
            return None
        n = min(len(data), int(slot.get("max") or len(data)))
        return n.to_bytes(int(slot.get("size") or 8), "little")
    return _recorded(args, param, _LAYOUT_KINDS.get(kind, ()))


def layout_seed(layout: dict, call_args: list[dict]) -> bytes | None:
    """
    One seed for an API harness case from the recorded arguments of its calls (one dict per call of
    the case, in order, then one per initializer call of `inits`): the selector byte, each slot's
    value (fitted to its size; zeros when the call did not record it), then the rest of the input.
    None when nothing recorded feeds the case, or a slot of unknown size has no recorded value.
    """
    out = bytearray([int(layout["selector"])])
    fed = False
    for slot in layout.get("slots") or []:
        args = call_args[slot["call"]] if slot["call"] < len(call_args) else {}
        v = _slot_value(slot, args)
        if v is None:
            if slot.get("size") is None:
                return None
            v = b""
        else:
            fed = True
        out += _fit(v, slot.get("size"))
    rest = layout.get("rest")
    if rest:
        args = call_args[rest["call"]] if rest["call"] < len(call_args) else {}
        if "off" in rest:
            v = _pair_recorded(args, int(rest["param"]), int(rest["off"]))
        else:
            v = _recorded(args, int(rest["param"]), ("b", "s", "a"))
        if v is not None:
            out += v
            fed = True
    return bytes(out) if fed else None


def _init_args(lay: dict, call_args: list[dict], trace: list[dict] | None, at: list[int]) -> list[dict]:
    """
    `call_args` followed by the recorded arguments of each initializer call of the case (`inits`):
    in a trace, the last call of that initializer before the call it serves, on the same object
    (its first argument's address); else nothing ({}).
    """
    out = list(call_args)
    for init in lay.get("inits") or []:
        k = int(init.get("call") or 0)
        while len(out) <= k:
            out.append({})
        target = init.get("for") or {}
        c = int(target.get("call") or 0)
        if trace is None or c >= len(at):
            continue
        j = at[c]
        addr = (trace[j].get("addrs") or {}).get(str(target.get("param")))
        for t in range(j - 1, -1, -1):
            prev = trace[t]
            if prev.get("fn") == init.get("fn") and addr and (prev.get("addrs") or {}).get("0") == addr:
                out[k] = prev.get("args") or {}
                break
    return out


def layout_seeds(layouts: list[dict], calls: list[dict], traces: list[list[dict]]) -> dict[int, list[bytes]]:
    """
    Seeds per selector of an API harness: single cases from recorded calls, sequences from traces. A
    case that initializes an object first takes that initializer's arguments from the trace call that
    initialized the same object; a recorded call no trace holds pairs with the initializer's recorded
    calls in turn (their inputs, a CBOR document for a decoder, are what the case decodes).
    """
    by_fn: dict[str, list[dict]] = {}
    for rec in calls:
        by_fn.setdefault(rec["fn"], []).append(rec)
    out: dict[int, list[bytes]] = {}
    for lay in layouts:
        made: list[bytes] = []
        if lay.get("kind") == "sequence":
            want = list(lay.get("calls") or [])
            for trace in traces:
                fns = [c.get("fn") for c in trace]
                for start in range(len(fns)):
                    picked: list[dict] = []
                    at: list[int] = []
                    k = start
                    for fn in want:
                        while k < len(fns) and fns[k] != fn:
                            k += 1
                        if k == len(fns):
                            break
                        picked.append(trace[k].get("args") or {})
                        at.append(k)
                        k += 1
                    if len(picked) == len(want):
                        seed = layout_seed(lay, _init_args(lay, picked, trace, at))
                        if seed is not None:
                            made.append(seed)
                        break
        else:
            fn = (lay.get("calls") or [""])[0]
            inits = list(lay.get("inits") or [])
            traced: set[str] = set()
            if inits:
                for trace in traces:
                    for j, c in enumerate(trace):
                        if c.get("fn") != fn:
                            continue
                        args = c.get("args") or {}
                        traced.add(json.dumps(args, sort_keys=True))
                        seed = layout_seed(lay, _init_args(lay, [args], trace, [j]))
                        if seed is not None:
                            made.append(seed)
            for n, rec in enumerate(by_fn.get(fn, [])):
                args = rec.get("args") or {}
                if json.dumps(args, sort_keys=True) in traced:
                    continue
                call_args = _init_args(lay, [args], None, [])
                for init in inits:
                    pool = by_fn.get(str(init.get("fn")), [])
                    if pool:
                        call_args[int(init["call"])] = pool[n % len(pool)].get("args") or {}
                seed = layout_seed(lay, call_args)
                if seed is not None:
                    made.append(seed)
        out[int(lay["selector"])] = made
    return out


def load_traces(records: Path = RECORDS_DIR) -> list[list[dict]]:
    path = records / "traces.jsonl"
    out: list[list[dict]] = []
    if not path.is_file():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict) and isinstance(rec.get("calls"), list):
            out.append([c for c in rec["calls"] if isinstance(c, dict)])
    return out


def write_layout_module(module: str, sidecar: dict, calls: list[dict], traces: list[list[dict]]) -> dict:
    """Seeds of an API harness from its sidecar's case layouts (`api_cases`)."""
    layouts = [lay for lay in sidecar.get("api_cases") or [] if isinstance(lay, dict) and "selector" in lay]
    max_size = int(sidecar.get("max_input_size") or 0) or 1 << 20
    seeds: dict[str, bytes] = {}
    too_large = 0
    per_case: dict[str, dict[str, Any]] = {}
    for sel, made in sorted(layout_seeds(layouts, calls, traces).items()):
        lay = next(lay for lay in layouts if int(lay["selector"]) == sel)
        per_case[str(sel)] = {"functions": list(lay.get("calls") or []), "kind": lay.get("kind"), "from_calls": 0}
        for s in made:
            if len(s) > max_size:
                too_large += 1
                continue
            if hashlib.sha256(s).hexdigest() not in seeds:
                per_case[str(sel)]["from_calls"] += 1
            seeds.setdefault(hashlib.sha256(s).hexdigest(), s)
    return _store_seeds(module, seeds, too_large, max_size, True, per_case)


def _store_seeds(
    module: str, seeds: dict[str, bytes], too_large: int, max_size: int, dispatch: bool, per_case: dict
) -> dict:
    out_dir = SEEDS_DIR / module
    if out_dir.is_dir():
        for old in out_dir.glob(f"{SEED_PREFIX}*"):
            old.unlink()
    kept = list(seeds.items())[:MAX_SEEDS_PER_MODULE]
    if kept:
        out_dir.mkdir(parents=True, exist_ok=True)
        for digest, data in kept:
            (out_dir / f"{SEED_PREFIX}{digest[:16]}").write_bytes(data)
    summary = {
        "module": module,
        "generated_at": utc_now(),
        "seeds": len(kept),
        "dropped_over_cap": max(0, len(seeds) - MAX_SEEDS_PER_MODULE),
        "dropped_too_large": too_large,
        "max_input_size": max_size,
        "dispatch": dispatch,
        "cases": per_case,
        "dir": out_dir.as_posix(),
    }
    SEED_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    atomic_write_json(SEED_REPORTS_DIR / f"{module}.json", summary)
    return summary


def write_module(module: str, sidecar: dict, harness_c: str, calls: list[dict], files: list[bytes]) -> dict:
    """Write workspace/seeds/<module>/ from the records; the module's summary."""
    functions = {c["fn"] for c in calls}
    cases = harness_cases(harness_c)
    bindings = [(sel, case_bindings(stmt, functions)) for sel, stmt in cases]
    max_size = int(sidecar.get("max_input_size") or 0) or 1 << 20
    seeds: dict[str, bytes] = {}
    too_large = 0
    per_case: dict[str, dict[str, Any]] = {}
    for sel, b in bindings:
        made = seeds_for_case(sel, b, calls)
        label = "all" if sel is None else str(sel)
        fns = sorted({c["fn"] for c in b["calls"]})
        per_case[label] = {"functions": fns, "slots": b["slots"], "from_calls": 0, "from_files": 0}
        for s in made:
            if len(s) > max_size:
                too_large += 1
                continue
            if s not in seeds.values():
                per_case[label]["from_calls"] += 1
            seeds.setdefault(hashlib.sha256(s).hexdigest(), s)
    for sel in whole_input_cases(bindings):
        prefix = bytes([sel]) if sel is not None else b""
        for data in files:
            s = prefix + data
            if len(s) > max_size:
                too_large += 1
                continue
            per_case["all" if sel is None else str(sel)]["from_files"] += 1
            seeds.setdefault(hashlib.sha256(s).hexdigest(), s)
    dispatch = cases[0][0] is not None if cases else False
    return _store_seeds(module, seeds, too_large, max_size, dispatch, per_case)


def write(modules: list[str]) -> dict:
    calls = load_calls()
    traces = load_traces()
    files = (
        [p.read_bytes() for p in sorted((RECORDS_DIR / "files").glob("*"))] if (RECORDS_DIR / "files").is_dir() else []
    )
    out: dict[str, Any] = {"calls": len(calls), "files": len(files), "modules": {}}
    for sidecar_path in sorted(HARNESS_DIR.glob("harness_*.json")):
        module = sidecar_path.stem[len("harness_") :]
        if modules and module not in modules:
            continue
        sidecar = load_json_optional(sidecar_path, {}) or {}
        c_path = sidecar_path.with_suffix(".c")
        if not isinstance(sidecar, dict) or not c_path.is_file():
            continue
        if not calls and not files:
            out_dir = SEEDS_DIR / module
            if out_dir.is_dir():
                for old in out_dir.glob(f"{SEED_PREFIX}*"):
                    old.unlink()
            out["modules"][module] = {"seeds": 0, "reason": "no records (seed_harvest.py record has not run)"}
            continue
        if sidecar.get("api_cases"):
            summary = write_layout_module(module, sidecar, calls, traces)
        else:
            summary = write_module(module, sidecar, c_path.read_text(encoding="utf-8", errors="replace"), calls, files)
        out["modules"][module] = {k: summary[k] for k in ("seeds", "dropped_too_large")}
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Seed inputs recorded from the target's tests (step I6).")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("record", help="Relink the test executables with recorders and run the test command")
    r.add_argument("--scratch", default="/framac-scratch", help="the run's scratch volume (holds the build tree)")
    r.add_argument("--recipe-file", default=None, help="JSON file with a `build` block (default: run-metadata.json)")
    r.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_S, help="test command wall-time cap, seconds")
    r.add_argument("--out", type=Path, default=REPORT_JSON)
    w = sub.add_parser("write", help="Write each harness module's seeds from the records")
    w.add_argument("--module", action="append", default=[])
    a = p.parse_args(argv)
    if a.cmd == "write":
        print(json.dumps(write(a.module), indent=1))
        return 0
    try:
        report, code = record(a)
    except Exception as exc:  # noqa: BLE001 - recorded as a status: seeds never stop the pipeline
        report = {
            "schema_version": SCHEMA_VERSION,
            "generated_at": utc_now(),
            "status": "error",
            "error": f"{type(exc).__name__}: {exc}",
            "warnings": [],
        }
        code = 1
    a.out.parent.mkdir(parents=True, exist_ok=True)
    from validate_artifacts import schema_warning

    problem = schema_warning("seed_harvest", report)  # R5: recorded, `validate_artifacts run-dir` fails on it
    if problem:
        report["warnings"] = [*(report.get("warnings") or []), problem]
    atomic_write_json(a.out, report)
    summary = {k: report.get(k) for k in ("status", "test_units", "calls", "error")}
    summary["files"] = len((report.get("files") or {}).get("kept") or [])
    print(json.dumps(summary, indent=1))
    return code


if __name__ == "__main__":
    sys.exit(main())
