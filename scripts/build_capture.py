#!/usr/bin/env python3
"""
Build capture (Phase 0, docs/phase0-implementation-plan.md step I2): run the target's own build under
`bear intercept` in a scratch copy and record what it compiles, links, archives and exports. Stdlib only.

    build_capture.py run [--recipe-file run-metadata.json] [--command CMD] [--workdir DIR]
                         [--env KEY=VALUE]... [--package PKG]... [--test-command CMD]
                         [--target /target] [--scratch /framac-scratch]
                         [--out workspace/reports/build_capture.json] [--state state] [--timeout 1800]
    build_capture.py propose [--target /target]

`run` runs in the build image (framac-build, or framac-build:<repo> when the recipe names packages),
started by the wrapper with -BuildImage -Scratch (sh: --build-image --scratch), so the scratch tree is on
the run's named Docker volume at /framac-scratch:

  1. copy the read-only target to <scratch>/tree (without .git and pipeline output) and run the recipe's
     command there, under `bear intercept`, through sandbox_exec.py (rlimits, env allowlist, timeout);
  2. read compile, link and archive steps from the intercepted executions, drop build-system probes
     (CMake try-compiles and compiler identification, autoconf conftest, meson-private);
  3. link units: every executable, shared and static library; its files are the sources of its own
     objects, `links` the project libraries it links (`.a` members followed through `ar`, `-l` resolved
     against the produced artifacts). Objects linked into nothing form one `unlinked:<dir>` unit per dir.
     Test units are marked (rule in TEST_RULE below);
  4. per-file preprocessing flags (-I -D -U -include -imacros -iquote -isystem -idirafter -std), project
     paths relative to the target root; include paths outside the tree are kept apart (`system_flags`);
  5. entry points: `main` (executables); `nm -D` exports, which already reflect version scripts and
     visibility (shared libraries); global functions declared in the public headers (static libraries).
     Public headers come from `make install DESTDIR=` (or `cmake --install`) when that works, else the
     headers outside the source directories, else the project headers the library's consumers include;
  6. a snapshot for the analysis image under <run>/workspace/snapshot/root/ (absolute paths kept), with a
     digest, read by scripts/target_env.py:
     the headers the compiler's dependency lists (`cc -M` per TU) name outside the project and outside libc
     and the toolchain (told apart with `dpkg -S`: libc6-dev, linux-libc-dev, gcc's own headers), the
     libraries the link steps name (`-l` through `cc -print-file-name`, absolute inputs) and their shared
     dependencies (DT_NEEDED read with readelf and resolved through `ldconfig -p`, recursively: what ldd
     reports, without running the dynamic loader on target binaries). The headers the build generated in
     the tree (`config.h`: named in a dependency list, absent from the target) are copied to
     <run>/workspace/snapshot/generated/<tree-relative path>, with the include directories that find them.

The report is workspace/reports/build_capture.json (schemas/build_capture.schema.json). A build that fails
(or compiles no C file, or has no recipe) stops Phase 0: status `needs_build_recipe` with the first error,
the missing headers and candidate -dev packages (CANDIDATE_RULE), the checkpoint records the status, and
the exit code is 3. After the recipe is fixed (`run_metadata.py set-build ...`), running the capture again
clears the status and Phase 0 resumes.

`propose` prints a recipe guessed from the build files, for the agent to confirm with the user.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import re
import shlex
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import target_env  # noqa: E402
from framac_common import atomic_write_json, is_pipeline_output_dir, load_json_optional, utc_now  # noqa: E402

SCHEMA_VERSION = 1
STATUS_OK = "ok"
STATUS_NEEDS_RECIPE = "needs_build_recipe"
EXIT_NEEDS_RECIPE = 3
DEFAULT_TIMEOUT_S = 1800
INSTALL_TIMEOUT_S = 300
TOOL_TIMEOUT_S = 120
LOG_TAIL_CHARS = 4000

TEST_RULE = (
    "a unit is `test` when its artifact name, split on _ - . into words, has a word test/tests/check/checks/"
    "unittest/unittests/testsuite; or a directory of its path is test/tests/testing/check/unittest(s); or all "
    "its own sources are test sources (in such a directory, or named with such a word); or its name ends in "
    "`test`/`tests` and one of its own sources is a test source. The test command is not run here (step I6)."
)
CANDIDATE_RULE = (
    "best effort, no apt-file: a table of common headers, pkg-config modules, CMake packages and commands; "
    "otherwise lib<name>-dev from the header's first path component, the pkg-config module, the CMake "
    "package or the missing -l library. Candidates are proposals to confirm with the user."
)

_COMPILER_RE = re.compile(r"^(?:[\w.+-]+-)?(?:cc|gcc|clang|c89|c99)(?:-\d+(?:\.\d+)*)?$")
_AR_RE = re.compile(r"^(?:[\w.+-]+-)?(?:gcc-|llvm-)?ar(?:-\d+(?:\.\d+)*)?$")
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
    "-iwithprefix",
    "-iwithprefixbefore",
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
    "-dumpbase-ext",
    "-dumpdir",
    "-z",
    "-u",
    "-e",
}
_PATH_OPTS = ("-I", "-iquote", "-isystem", "-idirafter", "-include", "-imacros")
_PP_VALUE_OPTS = ("-include", "-imacros", "-iquote", "-isystem", "-idirafter", "-I", "-D", "-U")
_SOURCE_SUFFIXES = (".c",)
_OBJECT_SUFFIXES = (".o", ".lo", ".obj")
# A shared library by name: `.so`, then any version suffix, numeric or not (`libpng18.so.18.0.git`).
_SHARED_RE = re.compile(r"\.so(?:\.[0-9A-Za-z_+-]+)*$")
_DEP_FLAGS_NOARG = {"-MD", "-MMD", "-MP", "-M", "-MM", "-MG"}
_DEP_FLAGS_ARG = {"-MF", "-MT", "-MQ"}
_LINK_ONLY_NOARG = {"-shared", "-static", "-rdynamic", "-pie", "-no-pie", "-static-pie", "-s", "-nostartfiles"}

TEST_WORDS = frozenset({"test", "tests", "check", "checks", "unittest", "unittests", "testsuite"})
TEST_DIRS = frozenset({"test", "tests", "testing", "check", "checks", "unittest", "unittests"})

LIBC_PACKAGES = frozenset({"libc6", "libc6-dev", "linux-libc-dev", "libc-dev-bin", "libc6-dbg", "libc-bin"})
TOOLCHAIN_PREFIXES = (
    "gcc",
    "cpp",
    "g++",
    "libgcc",
    "libstdc++",
    "libasan",
    "libubsan",
    "libtsan",
    "liblsan",
    "libhwasan",
    "libatomic",
    "libgomp",
    "libitm",
    "libquadmath",
    "libcc1",
    "libobjc",
    "clang",
    "libclang",
    "llvm",
)

# Header (or header directory) -> Debian package, for the stop-and-ask diagnostic.
HEADER_PACKAGES = {
    "openssl": "libssl-dev",
    "zlib.h": "zlib1g-dev",
    "gcrypt.h": "libgcrypt20-dev",
    "gpg-error.h": "libgpg-error-dev",
    "curl": "libcurl4-openssl-dev",
    "mysql.h": "libmariadb-dev",
    "mysql": "libmariadb-dev",
    "mariadb": "libmariadb-dev",
    "check.h": "check",
    "json-c": "libjson-c-dev",
    "libxml": "libxml2-dev",
    "libxml2": "libxml2-dev",
    "sqlite3.h": "libsqlite3-dev",
    "pcap.h": "libpcap-dev",
    "pcap": "libpcap-dev",
    "event2": "libevent-dev",
    "event.h": "libevent-dev",
    "bsd": "libbsd-dev",
    "net-snmp": "libsnmp-dev",
    "yaml.h": "libyaml-dev",
    "uuid": "uuid-dev",
    "ffi.h": "libffi-dev",
    "ncurses.h": "libncurses-dev",
    "curses.h": "libncurses-dev",
    "readline": "libreadline-dev",
    "png.h": "libpng-dev",
    "jpeglib.h": "libjpeg-dev",
    "gmp.h": "libgmp-dev",
    "mbedtls": "libmbedtls-dev",
    "psa": "libmbedtls-dev",
    "sodium.h": "libsodium-dev",
    "systemd": "libsystemd-dev",
    "libmnl": "libmnl-dev",
    "netlink": "libnl-3-dev",
    "lzma.h": "liblzma-dev",
    "bzlib.h": "libbz2-dev",
    "zstd.h": "libzstd-dev",
    "lz4.h": "liblz4-dev",
    "expat.h": "libexpat1-dev",
    "pcre.h": "libpcre3-dev",
    "pcre2.h": "libpcre2-dev",
    "cmocka.h": "libcmocka-dev",
    "CUnit": "libcunit1-dev",
    "glib.h": "libglib2.0-dev",
    "dbus": "libdbus-1-dev",
    "libusb-1.0": "libusb-1.0-0-dev",
    "sys/capability.h": "libcap-dev",
    "seccomp.h": "libseccomp-dev",
    "selinux": "libselinux1-dev",
    "attr": "libattr1-dev",
    "acl": "libacl1-dev",
    "krb5.h": "libkrb5-dev",
    "ldap.h": "libldap-dev",
    "security": "libpam0g-dev",
    "magic.h": "libmagic-dev",
    "archive.h": "libarchive-dev",
    "gnutls": "libgnutls28-dev",
    "nettle": "nettle-dev",
    "gpgme.h": "libgpgme-dev",
    "idn2.h": "libidn2-dev",
    "maxminddb.h": "libmaxminddb-dev",
    "microhttpd.h": "libmicrohttpd-dev",
    "jansson.h": "libjansson-dev",
    "cjson": "libcjson-dev",
    "mosquitto.h": "libmosquitto-dev",
    "protobuf-c": "libprotobuf-c-dev",
    "hiredis": "libhiredis-dev",
    "sasl": "libsasl2-dev",
    "wolfssl": "libwolfssl-dev",
    "editline": "libedit-dev",
    "numa.h": "libnuma-dev",
    "rpc": "libtirpc-dev",
    "tirpc": "libtirpc-dev",
    "crypt.h": "libcrypt-dev",
    "linux": "linux-libc-dev",
    "asm": "linux-libc-dev",
}
PKGCONFIG_PACKAGES = {
    "check": "check",
    "openssl": "libssl-dev",
    "libssl": "libssl-dev",
    "libcrypto": "libssl-dev",
    "zlib": "zlib1g-dev",
    "libcurl": "libcurl4-openssl-dev",
    "libxml-2.0": "libxml2-dev",
    "sqlite3": "libsqlite3-dev",
    "libgcrypt": "libgcrypt20-dev",
    "glib-2.0": "libglib2.0-dev",
    "json-c": "libjson-c-dev",
    "libsystemd": "libsystemd-dev",
    "libmariadb": "libmariadb-dev",
    "mariadb": "libmariadb-dev",
    "libpcap": "libpcap-dev",
    "libevent": "libevent-dev",
    "libbsd": "libbsd-dev",
    "cmocka": "libcmocka-dev",
    "libsodium": "libsodium-dev",
    "libmnl": "libmnl-dev",
    "uuid": "uuid-dev",
    "yaml-0.1": "libyaml-dev",
}
CMAKE_PACKAGES = {
    "openssl": "libssl-dev",
    "zlib": "zlib1g-dev",
    "curl": "libcurl4-openssl-dev",
    "libxml2": "libxml2-dev",
    "sqlite3": "libsqlite3-dev",
    "threads": "libc6-dev",
    "pkgconfig": "pkg-config",
    "check": "check",
    "gcrypt": "libgcrypt20-dev",
    "libgcrypt": "libgcrypt20-dev",
    "mysql": "libmariadb-dev",
    "mariadb": "libmariadb-dev",
    "cmocka": "libcmocka-dev",
    "gtest": "libgtest-dev",
    "pcap": "libpcap-dev",
    "bzip2": "libbz2-dev",
    "liblzma": "liblzma-dev",
    "expat": "libexpat1-dev",
    "png": "libpng-dev",
    "jpeg": "libjpeg-dev",
    "doxygen": "doxygen",
    "python3": "python3",
    "pythoninterp": "python3",
    "perl": "perl",
    "bison": "bison",
    "flex": "flex",
}
LIB_PACKAGES = {
    "ssl": "libssl-dev",
    "crypto": "libssl-dev",
    "z": "zlib1g-dev",
    "curl": "libcurl4-openssl-dev",
    "gcrypt": "libgcrypt20-dev",
    "mariadb": "libmariadb-dev",
    "mysqlclient": "libmariadb-dev-compat",
    "check": "check",
    "subunit": "libsubunit-dev",
    "xml2": "libxml2-dev",
    "sqlite3": "libsqlite3-dev",
    "pcap": "libpcap-dev",
    "event": "libevent-dev",
    "bsd": "libbsd-dev",
    "ncurses": "libncurses-dev",
    "readline": "libreadline-dev",
    "uuid": "uuid-dev",
    "cap": "libcap-dev",
}
COMMAND_PACKAGES = {
    "autoreconf": "autoconf",
    "autoconf": "autoconf",
    "aclocal": "automake",
    "automake": "automake",
    "libtoolize": "libtool",
    "pkg-config": "pkg-config",
    "yacc": "bison",
    "bison": "bison",
    "lex": "flex",
    "flex": "flex",
    "python": "python3",
    "perl": "perl",
    "gperf": "gperf",
    "xxd": "xxd",
    "doxygen": "doxygen",
    "scons": "scons",
    "gettext": "gettext",
    "msgfmt": "gettext",
    "makeinfo": "texinfo",
}

_FIRST_ERROR_RES = [
    re.compile(p)
    for p in (
        r"fatal error:",
        r"\berror:",
        r"undefined reference to",
        r"cannot find -l",
        r"CMake Error",
        r"Could NOT find",
        r"No package '[^']+' found",
        r"Package '[^']+'.*not found",
        r"No rule to make target",
        r"command not found",
        r": not found$",
        r"No such file or directory",
        r"^ERROR:",
        r"\*\*\* .*Error \d+",
    )
]
_MISSING_HEADER_RE = re.compile(r"fatal error: ([^\s:]+): No such file or directory")
_PKGCONFIG_RE = re.compile(r"(?:No package '([^']+)' found|Package '([^']+)',? (?:required by '[^']*', )?not found)")
_CMAKE_MISSING_RE = re.compile(r"Could NOT find (\w+)")
_CMAKE_CONFIG_RE = re.compile(r'By not providing "Find(\w+)\.cmake"')
_LIB_MISSING_RE = re.compile(r"cannot find -l([\w.+-]+)")
_COMMAND_MISSING_RE = re.compile(
    r"(?:(?:sh|bash|/bin/sh)(?:: line \d+|: \d+)?: ([\w.+-]+): (?:command )?not found|([\w.+-]+): command not found)"
)


class CaptureError(RuntimeError):
    pass


# ---------------------------------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------------------------------


def run_tool(cmd: list[str], cwd: Path | str | None = None, timeout: int = TOOL_TIMEOUT_S) -> tuple[int, str, str]:
    """A trusted tool (compiler driver in -M/-E/-c mode, nm, readelf, dpkg): rc, stdout, stderr. Never raises."""
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout} s: {shlex.join(cmd)[:300]}"
    except OSError as exc:
        return 127, "", f"cannot run {cmd[0]}: {exc}"
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def tree_rel(path: str, tree: str) -> str | None:
    """`path` (absolute, normalised) relative to the tree, '.' for the root, None when outside."""
    p = posixpath.normpath(path)
    t = posixpath.normpath(tree)
    if p == t:
        return "."
    if p.startswith(t.rstrip("/") + "/"):
        return p[len(t.rstrip("/")) + 1 :]
    return None


def absolute(path: str, cwd: str) -> str:
    return posixpath.normpath(path if posixpath.isabs(path) else posixpath.join(cwd, path))


def norm_in_tree(path: str, cwd: str, tree: str) -> str:
    """Tree-relative path when inside the tree, else the normalised absolute path."""
    a = absolute(path, cwd)
    r = tree_rel(a, tree)
    return r if r is not None else a


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def job_count() -> int:
    raw = (os.environ.get("FRAMAC_JOB_CPUS") or "").strip()
    if raw.isdigit() and int(raw) > 0:
        return int(raw)
    try:
        return max(1, len(os.sched_getaffinity(0)))  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return max(1, os.cpu_count() or 1)


def expand_response_files(args: list[str], cwd: str) -> list[str]:
    """Inline `@file` arguments (CMake and Meson use response files for long command lines)."""
    out: list[str] = []
    for a in args:
        if a.startswith("@") and len(a) > 1:
            p = Path(absolute(a[1:], cwd))
            try:
                out += shlex.split(p.read_text(encoding="utf-8", errors="replace"))
                continue
            except (OSError, ValueError):
                pass
        out.append(a)
    return out


# ---------------------------------------------------------------------------------------------------
# 1. Intercepted executions
# ---------------------------------------------------------------------------------------------------


def read_executions(events: Path) -> list[dict]:
    """The `started` executions of a `bear intercept` event file (JSON lines), deduplicated."""
    execs: list[dict] = []
    seen: set = set()
    if not events.is_file():
        return execs
    for line in events.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        ex = (ev.get("started") or {}).get("execution") if isinstance(ev, dict) else None
        if not ex:
            continue
        key = (ex.get("working_dir"), tuple(ex.get("arguments") or []))
        if key in seen:
            continue
        seen.add(key)
        execs.append(
            {"exe": ex.get("executable") or "", "args": list(ex.get("arguments") or []), "cwd": ex.get("working_dir")}
        )
    return execs


def is_probe_path(path: str) -> bool:
    """A build-system probe: CMake try-compile / compiler identification, autoconf conftest, meson-private."""
    parts = [p for p in path.replace("\\", "/").split("/") if p]
    for i, part in enumerate(parts):
        # A target's own objects live in CMakeFiles/<target>.dir/...; anything else under CMakeFiles is CMake's.
        if part == "CMakeFiles" and (i + 2 >= len(parts) or not parts[i + 1].endswith(".dir")):
            return True
        if part == "meson-private":
            return True
    return bool(parts) and parts[-1].startswith("conftest")


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
    preprocess_only = False
    while i < len(args):
        a = args[i]
        val = None
        if a in _ARG_OPTS and i + 1 < len(args):
            val = args[i + 1]
            i += 1
        if a == "-c":
            res["mode"] = "compile"
        elif a in ("-E", "-S", "-fsyntax-only", "-cc1", "-cc1as") or a.startswith("-print-") or a.startswith("-dump"):
            preprocess_only = True
        elif a in ("-M", "-MM"):
            preprocess_only = True
        elif a in ("--version", "-v", "-###", "--help"):
            preprocess_only = True
        elif a == "-shared":
            res["shared"] = True
        elif a == "-o":
            res["output"] = val
        elif a.startswith("-o") and len(a) > 2:
            res["output"] = a[2:]
        elif a == "-L" or (a.startswith("-L") and len(a) > 2):
            res["libdirs"].append(val if val is not None else a[2:])
        elif a == "-l" or (a.startswith("-l") and len(a) > 2):
            res["libs"].append(val if val is not None else a[2:])
        elif a.startswith("-std="):
            res["pp"].append([a])
        elif a in _PP_VALUE_OPTS and val is not None:
            res["pp"].append([a, val])
        elif a.startswith(_PP_VALUE_OPTS) and val is None:
            opt = next(o for o in _PP_VALUE_OPTS if a.startswith(o))
            if len(a) > len(opt):
                res["pp"].append([opt, a[len(opt) :]])
        elif val is None and not a.startswith("-"):
            if a.endswith(_SOURCE_SUFFIXES):
                res["sources"].append(a)
            elif a.endswith(_OBJECT_SUFFIXES) or a.endswith(".a") or _SHARED_RE.search(a):
                res["inputs"].append(a)
        i += 1
    if preprocess_only:
        res["mode"] = "other"
    return res


def parse_ar(args: list[str]) -> tuple[str, list[str]] | None:
    """(archive, members) of an `ar` call that adds members (r or q), else None."""
    i = 1
    while i < len(args) and args[i].startswith("--"):
        i += 2 if args[i] in ("--plugin", "--target", "--output") else 1
    if i + 1 >= len(args):
        return None
    ops = args[i].lstrip("-")
    if not any(c in ops for c in "rq"):
        return None
    rest = args[i + 1 :]
    # Positional modifiers (a, b, i) and count (N) take an extra operand before the archive.
    skip = sum(1 for c in ops if c in "abiN")
    rest = rest[skip:]
    if not rest:
        return None
    return rest[0], [m for m in rest[1:] if not m.startswith("-")]


def split_flags(pp: list[list[str]], cwd: str, tree: str) -> tuple[list[str], list[str]]:
    """
    Preprocessing flags of one compile: (project flags, system flags). Project path options are made
    relative to the target root; include paths outside the tree go to the system flags (absolute); a
    bare `-include name` that is not a file next to the working directory is kept as written.
    """
    flags: list[str] = []
    system: list[str] = []
    for item in pp:
        if len(item) == 1:
            flags.append(item[0])
            continue
        opt, val = item
        if opt not in _PATH_OPTS:
            flags.append(opt + val)
            continue
        a = absolute(val, cwd)
        r = tree_rel(a, tree)
        if r is not None:
            if opt in ("-include", "-imacros") and not posixpath.isabs(val) and not os.path.exists(a):
                flags += [opt, val]  # found through the include path at compile time
            else:
                flags += [opt, r]
        elif opt in ("-include", "-imacros") and not posixpath.isabs(val) and not os.path.exists(a):
            flags += [opt, val]
        else:
            system += [opt, a]
    return flags, system


def _without_link_and_output(args: list[str], keep_source: str) -> list[str]:
    """The driver arguments minus outputs, dependency-file options, link-only options and other inputs."""
    out = [args[0]]
    i = 1
    while i < len(args):
        a = args[i]
        if a in ("-o", "-L", "-l", "-Xlinker", "-T", "-z", "-u", "-e") or a in _DEP_FLAGS_ARG:
            i += 2
            continue
        if (
            a == "-c"
            or a in _DEP_FLAGS_NOARG
            or a in _LINK_ONLY_NOARG
            or a.startswith(("-Wl,", "-L", "-o"))
            or (a.startswith("-l") and len(a) > 2)
            or a.startswith(("-MF", "-MT", "-MQ"))
        ):
            i += 1
            continue
        if a in _ARG_OPTS and i + 1 < len(args):
            out += [a, args[i + 1]]
            i += 2
            continue
        if not a.startswith("-") and (
            a.endswith(_SOURCE_SUFFIXES) or a.endswith(_OBJECT_SUFFIXES) or a.endswith(".a") or _SHARED_RE.search(a)
        ):
            i += 1
            continue
        out.append(a)
        i += 1
    return out + [keep_source]


def deps_argv(args: list[str], source: str) -> list[str]:
    """`cc ... -M source`: the compiler's dependency list for one translation unit, with its own flags."""
    base = _without_link_and_output(args, source)
    return base[:-1] + ["-M", base[-1]]


def compile_argv(args: list[str], source: str, output: str) -> list[str]:
    """Compile one source of a compile-and-link command to an object (for its symbols)."""
    base = _without_link_and_output(args, source)
    return base[:-1] + ["-c", base[-1], "-o", output]


def classify_executions(execs: list[dict], tree: str) -> dict:
    """Compile entries and raw artifacts (outputs of link and archive steps)."""
    compiles: dict[str, dict] = {}  # object -> entry (the last compile of an object wins)
    artifacts: dict[str, dict] = {}
    archives: dict[str, list[str]] = defaultdict(list)
    probes = 0
    for ex in execs:
        name = posixpath.basename(ex["exe"] or (ex["args"][0] if ex["args"] else ""))
        cwd = ex["cwd"] or tree
        if _AR_RE.match(name):
            parsed = parse_ar(ex["args"])
            if parsed is None:
                continue
            archive = norm_in_tree(parsed[0], cwd, tree)
            if is_probe_path(archive) or is_probe_path(norm_in_tree(".", cwd, tree)):
                probes += 1
                continue
            for m in parsed[1]:
                if m.endswith(_OBJECT_SUFFIXES):
                    member = norm_in_tree(m, cwd, tree)
                    if member not in archives[archive]:
                        archives[archive].append(member)
            continue
        if not _COMPILER_RE.match(name) and not (ex["args"] and _COMPILER_RE.match(posixpath.basename(ex["args"][0]))):
            continue
        args = expand_response_files(ex["args"], cwd)
        d = parse_driver(args)
        if d["mode"] == "other":
            continue
        rel_cwd = norm_in_tree(".", cwd, tree)
        srcs = [norm_in_tree(s, cwd, tree) for s in d["sources"]]
        out_rel = norm_in_tree(d["output"], cwd, tree) if d["output"] else None
        if is_probe_path(rel_cwd) or any(is_probe_path(s) for s in srcs) or (out_rel and is_probe_path(out_rel)):
            probes += 1
            continue
        flags, system = split_flags(d["pp"], cwd, tree)
        base = {"cwd": rel_cwd, "compiler": args[0], "arguments": args, "flags": flags, "system_flags": system}
        if d["mode"] == "compile":
            for src, raw in zip(srcs, d["sources"], strict=True):
                obj = d["output"] if d["output"] and len(d["sources"]) == 1 else Path(raw).with_suffix(".o").name
                key = norm_in_tree(obj, cwd, tree)
                compiles[key] = {"source": src, "object": key, "implicit": False, **base}
            continue
        if not srcs and not d["inputs"] and not d["libs"]:
            continue  # a driver call that links nothing (version or search-path query)
        output = out_rel or norm_in_tree("a.out", cwd, tree)
        implicit = []
        for src in srcs:
            key = f"{output}::{src}"
            compiles[key] = {"source": src, "object": key, "implicit": True, **base}
            implicit.append(key)
        external_dirs = [absolute(x, cwd) for x in d["libdirs"] if tree_rel(absolute(x, cwd), tree) is None]
        artifacts[output] = {
            "kind": "shared_lib" if d["shared"] else "executable",
            "objects": implicit + [norm_in_tree(x, cwd, tree) for x in d["inputs"]],
            "lib_refs": list(dict.fromkeys(d["libs"])),
            "libdirs": [norm_in_tree(x, cwd, tree) for x in d["libdirs"]],
            "external_libdirs": external_dirs,
            "compiler": args[0],
        }
    for archive, members in archives.items():
        artifacts[archive] = {
            "kind": "static_lib",
            "objects": members,
            "lib_refs": [],
            "libdirs": [],
            "external_libdirs": [],
            "compiler": None,
        }
    return {"compiles": compiles, "artifacts": artifacts, "probes_dropped": probes}


# ---------------------------------------------------------------------------------------------------
# 2. Link units
# ---------------------------------------------------------------------------------------------------


def resolve_project_lib(
    ref: str, libdirs: list[str], artifacts: dict[str, dict], real_of: Callable[[str], str | None]
) -> str | None:
    """The produced artifact a `-l<ref>` names: -L directories first (.so before .a, as ld does), then by name."""
    names = [ref[1:]] if ref.startswith(":") else [f"lib{ref}.so", f"lib{ref}.a"]
    for d in libdirs:
        for n in names:
            cand = posixpath.normpath(posixpath.join(d, n)) if d != "." else n
            if cand in artifacts:
                return cand
            real = real_of(cand)
            if real in artifacts:
                return real
    for n in names:
        hits = sorted(p for p in artifacts if p == n or p.endswith("/" + n))
        if hits:
            return hits[0]
    return None


def _words(name: str) -> list[str]:
    return [w for w in re.split(r"[_.\-]+", name.lower()) if w]


def is_test_source(path: str) -> bool:
    parts = path.lower().split("/")
    if any(p in TEST_DIRS for p in parts[:-1]):
        return True
    stem = parts[-1].rsplit(".", 1)[0]
    return bool(set(_words(stem)) & TEST_WORDS)


def test_reason(name: str, files: list[str]) -> str | None:
    """Why a unit is a test unit (TEST_RULE), or None."""
    base = name.rsplit("/", 1)[-1]
    stem = re.sub(r"\.(a|so(\.\d+)*|exe)$", "", base)
    if set(_words(stem)) & TEST_WORDS:
        return "name"
    if any(p.lower() in TEST_DIRS for p in name.split("/")[:-1]):
        return "directory"
    if files and all(is_test_source(f) for f in files):
        return "test_sources"
    if re.search(r"tests?$", stem.lower()) and any(is_test_source(f) for f in files):
        return "name_and_sources"
    return None


def derive_units(capture: dict, tree: str) -> dict[str, dict]:
    """Link units from compile entries and artifacts; `unlinked:<dir>` for objects linked into nothing."""
    compiles: dict[str, dict] = capture["compiles"]
    artifacts: dict[str, dict] = capture["artifacts"]
    # Symlinked artifacts (libfoo.so -> libfoo.so.1.2) resolve through the tree on the scratch volume.
    posix = os.name == "posix"
    real_index: dict[str, str] = {}
    for key in artifacts:
        if posix and not posixpath.isabs(key):
            real = tree_rel(os.path.realpath(posixpath.join(tree, key)), os.path.realpath(tree))
            if real:
                real_index[real] = key

    def real_of(rel: str) -> str | None:
        if not posix or posixpath.isabs(rel):
            return None
        real = tree_rel(os.path.realpath(posixpath.join(tree, rel)), os.path.realpath(tree))
        return real_index.get(real or "", real)

    units: dict[str, dict] = {}
    for path, art in sorted(artifacts.items()):
        own: list[dict] = []
        links: list[str] = []
        external: list[dict] = []
        for o in art["objects"]:
            if o in compiles:
                own.append(compiles[o])
            elif o in artifacts and o != path:
                links.append(o)
            elif (r := real_of(o)) in artifacts and r != path:
                links.append(str(r))
            elif posixpath.isabs(o) and (o.endswith(".a") or _SHARED_RE.search(o)):
                external.append({"ref": o, "libdirs": []})
        for ref in art["lib_refs"]:
            hit = resolve_project_lib(ref, art["libdirs"], artifacts, real_of)
            if hit and hit != path:
                links.append(hit)
            else:
                external.append({"ref": f"-l{ref}", "libdirs": art["external_libdirs"]})
        if not own and not links:
            continue  # nothing of the project in it (a probe the filter missed, or a copy)
        files = sorted({c["source"] for c in own})
        units[path] = {
            "kind": art["kind"],
            "files": files,
            "objects": sorted({c["object"] for c in own}),
            "links": sorted(set(links)),
            "external_libs": external,
            "compiler": art.get("compiler"),
        }
    linked = {o for a in artifacts.values() for o in a["objects"]}
    by_dir: dict[str, list[dict]] = defaultdict(list)
    for c in compiles.values():
        if c["object"] not in linked:
            by_dir[str(Path(c["source"]).parent.as_posix())].append(c)
    for dirname, cs in sorted(by_dir.items()):
        units[f"unlinked:{dirname}"] = {
            "kind": "unlinked",
            "files": sorted({c["source"] for c in cs}),
            "objects": sorted({c["object"] for c in cs}),
            "links": [],
            "external_libs": [],
            "compiler": None,
        }
    for name, u in units.items():
        reason = test_reason(name, u["files"]) if u["kind"] != "unlinked" else None
        u["test"] = reason is not None
        u["test_reason"] = reason
    return units


def unit_cppflags(compiles: Iterable[dict]) -> list[str]:
    """The unit's preprocessing flags merged over its files, first occurrence first."""
    seen: list[tuple[str, ...]] = []
    for c in compiles:
        toks = c["flags"]
        i = 0
        while i < len(toks):
            tok = toks[i]
            if tok in _PATH_OPTS and i + 1 < len(toks):
                item: tuple[str, ...] = (tok, toks[i + 1])
                i += 1
            else:
                item = (tok,)
            if item not in seen:
                seen.append(item)
            i += 1
    return [t for item in seen for t in item]


# ---------------------------------------------------------------------------------------------------
# 3. Symbols, dependency lists, public headers and entry points
# ---------------------------------------------------------------------------------------------------


def parse_nm(text: str) -> dict[str, tuple[str, str | None]]:
    """`nm --defined-only [-l]` output: symbol -> (type letter, defining file from debug info or None)."""
    syms: dict[str, tuple[str, str | None]] = {}
    for line in text.splitlines():
        head, _, loc = line.partition("\t")
        parts = head.split()
        if len(parts) >= 3:
            name = parts[2].split("@", 1)[0]
            file = re.sub(r":\d+$", "", loc.strip()) or None
            syms.setdefault(name, (parts[1], file))
        elif len(parts) == 2 and parts[0] in ("T", "t", "W", "w", "i"):
            syms.setdefault(parts[1], (parts[0], None))
    return syms


FUNCTION_TYPES = {"T", "W", "i"}


def parse_make_deps(text: str, cwd: str) -> list[str]:
    """The prerequisites of a `cc -M` rule, as absolute normalised paths (the first is the source)."""
    joined = text.replace("\\\n", " ")
    _, _, rhs = joined.partition(":")
    deps: list[str] = []
    for tok in re.split(r"(?<!\\)\s+", rhs.strip()):
        if tok:
            deps.append(absolute(tok.replace("\\ ", " "), cwd))
    return deps


def declared_names(text: str, names: set[str]) -> set[str]:
    return {n for n in names if re.search(rf"\b{re.escape(n)}\s*\(", text)}


def declared_in(headers: list[Path], names: set[str], flags: list[str]) -> set[str]:
    """Names declared in the headers, read after preprocessing (macro-generated prototypes count)."""
    found: set[str] = set()
    for h in headers:
        if not names - found:
            break
        rc, text, _ = run_tool(["cc", "-E", "-P", *flags, "-x", "c", str(h)], cwd=h.parent, timeout=60)
        if rc != 0:
            try:
                text = h.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
        found |= declared_names(text, names - found)
    return found


def absolute_flags(flags: list[str], tree: str) -> list[str]:
    """Project flags with paths made absolute again (for running the preprocessor in the tree)."""
    out: list[str] = []
    i = 0
    while i < len(flags):
        tok = flags[i]
        if tok in _PATH_OPTS and i + 1 < len(flags):
            val = flags[i + 1]
            path = posixpath.normpath(posixpath.join(tree, val))
            out += [tok, path if (tok not in ("-include", "-imacros") or os.path.exists(path)) else val]
            i += 2
            continue
        out.append(tok)
        i += 1
    return out


def source_dirs(compiles: Iterable[dict]) -> set[str]:
    return {str(Path(c["source"]).parent.as_posix()) for c in compiles if not posixpath.isabs(c["source"])}


def outside_source_dirs(headers: list[str], src_dirs: set[str]) -> list[str]:
    """Project headers in no source directory and in no subdirectory of one."""

    def under(path: str) -> bool:
        parent = str(Path(path).parent.as_posix())
        return any(parent == d or (d == "." or parent.startswith(d + "/")) for d in src_dirs)

    return sorted(h for h in headers if not under(h))


# ---------------------------------------------------------------------------------------------------
# 4. System files: dpkg ownership and the snapshot
# ---------------------------------------------------------------------------------------------------


def parse_dpkg_s(text: str) -> dict[str, str]:
    """`dpkg -S path...` output: path -> first owning package (architecture qualifier dropped)."""
    owners: dict[str, str] = {}
    for line in text.splitlines():
        if line.startswith(("diversion by", "local diversion")) or ": " not in line:
            continue
        pkgs, _, path = line.partition(": ")
        pkg = pkgs.split(",")[0].strip().split(":")[0]
        owners.setdefault(path.strip(), pkg)
    return owners


def owner_class(package: str | None) -> str:
    """libc | toolchain | package | unowned (only the last two are exported to the snapshot)."""
    if package is None:
        return "unowned"
    if package in LIBC_PACKAGES:
        return "libc"
    if package.startswith(TOOLCHAIN_PREFIXES):
        return "toolchain"
    return "package"


def _path_variants(path: str) -> list[str]:
    variants = [path]
    real = os.path.realpath(path)
    if real != path:
        variants.append(real)
    for p in list(variants):
        if p.startswith(("/lib/", "/lib64/", "/bin/", "/sbin/")):
            variants.append("/usr" + p)
    return list(dict.fromkeys(variants))


def dpkg_owners(paths: Iterable[str]) -> dict[str, str]:
    """Owning package of each path (merged-/usr and symlink variants tried), batched `dpkg -S` calls."""
    wanted = {p: _path_variants(p) for p in paths}
    queries = sorted({v for vs in wanted.values() for v in vs})
    found: dict[str, str] = {}
    for i in range(0, len(queries), 200):
        _, out, _ = run_tool(["dpkg", "-S", *queries[i : i + 200]], timeout=TOOL_TIMEOUT_S)
        found.update(parse_dpkg_s(out))
    result: dict[str, str] = {}
    for p, vs in wanted.items():
        for v in vs:
            if v in found:
                result[p] = found[v]
                break
    return result


def classify_system_paths(
    paths: Iterable[str], lookup: Callable[[Iterable[str]], dict[str, str]] = dpkg_owners
) -> dict[str, dict]:
    """path -> {"package", "class"}; `lookup` is dpkg_owners (replaced in tests)."""
    paths = sorted(set(paths))
    owners = lookup(paths)
    return {p: {"package": owners.get(p), "class": owner_class(owners.get(p))} for p in paths}


def parse_ldconfig(text: str) -> dict[str, str]:
    """`ldconfig -p`: soname -> path (x86-64 entries first)."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        m = re.match(r"\s*(\S+) \(([^)]*)\) => (\S+)", line)
        if m and ("x86-64" in m.group(2) or m.group(1) not in out):
            out.setdefault(m.group(1), m.group(3))
    return out


def parse_needed(text: str) -> list[str]:
    return re.findall(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]", text)


def resolve_link_lib(ref: str, libdirs: list[str], compiler: str | None) -> str | None:
    """The file a link step's external `-lfoo` (or absolute input) resolved to."""
    if not ref.startswith("-l"):
        return ref if os.path.exists(ref) else None
    name = ref[2:]
    names = [name[1:]] if name.startswith(":") else [f"lib{name}.so", f"lib{name}.a"]
    for d in libdirs:
        for n in names:
            p = posixpath.join(d, n)
            if os.path.exists(p):
                return posixpath.normpath(p)
    cc = compiler or "cc"
    for n in names:
        rc, out, _ = run_tool([cc, f"-print-file-name={n}"])
        p = out.strip()
        if rc == 0 and posixpath.isabs(p) and os.path.exists(p):
            return posixpath.normpath(p)
    return None


def shared_closure(start: Iterable[Path], ldconfig: dict[str, str]) -> dict[str, list[str]]:
    """soname -> path for every DT_NEEDED library reachable from the start files (recursively)."""
    resolved: dict[str, str] = {}
    pending = list(start)
    seen: set[str] = set()
    while pending:
        f = pending.pop()
        key = str(f)
        if key in seen:
            continue
        seen.add(key)
        rc, out, _ = run_tool(["readelf", "-d", key])
        if rc != 0:
            continue
        for soname in parse_needed(out):
            path = ldconfig.get(soname)
            if path and soname not in resolved:
                resolved[soname] = path
                pending.append(Path(path))
    return {k: [v] for k, v in sorted(resolved.items())}


def generated_headers(compiles: Iterable[dict], target: Path) -> list[str]:
    """
    Project headers the build generated (`config.h` from configure or CMake): named in a compile's
    dependency list, inside the tree, and absent from the read-only target.
    """
    named = {h for c in compiles for h in c.get("headers") or [] if h.endswith(".h") and not posixpath.isabs(h)}
    return sorted(h for h in named if not (target / h).is_file())


def generated_include_dirs(headers: list[str], compiles: Iterable[dict]) -> list[str]:
    """
    Tree-relative directories the analyses search for the generated headers: each header's own directory
    (`#include "config.h"`), then the compiles' project include directories that hold one below them
    (`-Ibuild` for `#include <gen/version.h>`). '.' is the tree root.
    """
    out: list[str] = []
    for h in headers:
        d = posixpath.dirname(h) or "."
        if d not in out:
            out.append(d)
    for c in compiles:
        toks = c.get("flags") or []
        for i, tok in enumerate(toks):
            if tok not in ("-I", "-iquote", "-isystem", "-idirafter") or i + 1 >= len(toks):
                continue
            d = posixpath.normpath(toks[i + 1])
            if posixpath.isabs(d) or d.startswith(".."):
                continue
            if d not in out and any(d == "." or h.startswith(d + "/") for h in headers):
                out.append(d)
    return out


def export_snapshot(
    snapshot: Path,
    files: dict[str, dict],
    generated: dict[str, Path] | None = None,
    generated_dirs: list[str] | None = None,
) -> dict:
    """
    Copy the exported files under <snapshot>/root/<absolute path> and the build's generated headers under
    <snapshot>/generated/<tree-relative path>; digest over (path, sha256), the generated headers keyed
    `generated/<path>` (a snapshot without one keeps the digest it always had).
    """
    root = snapshot / "root"
    if snapshot.exists():
        shutil.rmtree(snapshot)
    root.mkdir(parents=True)
    manifest: dict[str, str] = {}
    for path in sorted(files):
        src = Path(path)
        if not src.is_file():
            continue
        dest = root / src.relative_to(src.anchor)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest)
        manifest[path] = sha256_file(dest)
    gen: dict[str, str] = {}
    for rel in sorted(generated or {}):
        src = (generated or {})[rel]
        if not src.is_file():
            continue
        dest = snapshot / target_env.GENERATED_REL / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest)
        gen[rel] = sha256_file(dest)
    material = sorted([*manifest.items(), *((f"{target_env.GENERATED_REL}/{r}", h) for r, h in gen.items())])
    digest = hashlib.sha256("".join(f"{p}\0{h}\n" for p, h in material).encode()).hexdigest()
    data: dict[str, Any] = {"digest": digest, "files": manifest}
    if gen:
        data["generated"] = gen
        data["generated_dirs"] = list(generated_dirs or [])
    atomic_write_json(snapshot / "manifest.json", data)
    return {"digest": digest, "files": len(manifest) + len(gen), "generated": len(gen)}


# ---------------------------------------------------------------------------------------------------
# 5. Stop and ask: diagnostics of a failed build
# ---------------------------------------------------------------------------------------------------


def first_error(log: str) -> tuple[str, list[str]]:
    lines = log.splitlines()
    for i, line in enumerate(lines):
        if "warning" in line.lower() and "error" not in line.lower():
            continue
        if any(r.search(line) for r in _FIRST_ERROR_RES):
            return line.strip()[:500], [x.rstrip()[:300] for x in lines[i + 1 : i + 6]]
    tail = [x for x in lines if x.strip()]
    return (tail[-1].strip()[:500] if tail else ""), []


def _header_package(header: str) -> str:
    h = header.strip("<>\"'")
    if h in HEADER_PACKAGES:
        return HEADER_PACKAGES[h]
    first = h.split("/", 1)[0]
    if "/" in h and first in HEADER_PACKAGES:
        return HEADER_PACKAGES[first]
    stem = re.sub(r"\.h$", "", first)
    stem = re.sub(r"^lib", "", stem)
    return f"lib{stem.lower()}-dev"


def diagnose(log: str, packages_not_installed: list[str] | None = None) -> dict:
    """The stop-and-ask diagnostic of a failed build (CANDIDATE_RULE)."""
    err, context = first_error(log)
    headers = list(dict.fromkeys(_MISSING_HEADER_RE.findall(log)))
    candidates: list[str] = [_header_package(h) for h in headers]
    for a, b in _PKGCONFIG_RE.findall(log):
        mod = (a or b).strip()
        candidates.append(PKGCONFIG_PACKAGES.get(mod, f"lib{re.sub(r'^lib', '', mod)}-dev"))
    for name in _CMAKE_MISSING_RE.findall(log) + _CMAKE_CONFIG_RE.findall(log):
        low = name.lower()
        candidates.append(CMAKE_PACKAGES.get(low, f"lib{re.sub(r'^lib', '', low)}-dev"))
    for lib in _LIB_MISSING_RE.findall(log):
        candidates.append(LIB_PACKAGES.get(lib, f"lib{lib}-dev"))
    commands = list(dict.fromkeys(a or b for a, b in _COMMAND_MISSING_RE.findall(log)))
    for cmd in commands:
        candidates.append(COMMAND_PACKAGES.get(cmd, cmd))
    return {
        "first_error": err,
        "context": context,
        "missing_headers": headers,
        "missing_commands": commands,
        "candidate_packages": [c for c in dict.fromkeys(candidates) if c != "libc6-dev"],
        "packages_not_installed": list(packages_not_installed or []),
        "heuristic": CANDIDATE_RULE,
        "log_tail": log[-LOG_TAIL_CHARS:],
    }


# ---------------------------------------------------------------------------------------------------
# 6. Recipe
# ---------------------------------------------------------------------------------------------------


def propose_recipe(tree: Path) -> dict | None:
    """A recipe guessed from the build files at the target root (to confirm with the user)."""
    if (tree / "CMakeLists.txt").is_file():
        command = "cmake -S . -B build && cmake --build build"
    elif (tree / "meson.build").is_file():
        command = "meson setup build && meson compile -C build"
    elif (tree / "configure").is_file():
        command = "./configure && make"
    elif (tree / "configure.ac").is_file() or (tree / "autogen.sh").is_file():
        command = "autoreconf -fi && ./configure && make"
    elif any((tree / n).is_file() for n in ("GNUmakefile", "Makefile", "makefile")):
        command = "make"
    else:
        return None
    return {"command": command, "workdir": ".", "packages": [], "env": {}, "test_command": None}


def load_recipe(args: argparse.Namespace) -> dict | None:
    """The recipe: the recipe file's `build` block, overridden by command-line options."""
    from run_metadata import normalize_build_recipe  # build-recipe validation lives with the metadata

    raw: dict[str, Any] = {}
    if args.recipe_file:
        data = load_json_optional(Path(args.recipe_file), None)
        if isinstance(data, dict) and isinstance(data.get("build"), dict):
            raw = dict(data["build"])
    if args.command:
        raw = {"command": args.command, "origin": "user"}
    if not raw.get("command"):
        return None
    if args.workdir:
        raw["workdir"] = args.workdir
    if args.package:
        raw["packages"] = list(args.package)
    if args.env:
        raw["env"] = dict(item.split("=", 1) for item in args.env)
    if args.test_command:
        raw["test_command"] = args.test_command
    return normalize_build_recipe(raw)


def packages_missing(packages: list[str]) -> list[str]:
    missing = []
    for pkg in packages:
        rc, out, _ = run_tool(["dpkg-query", "-W", "-f=${Status}", pkg])
        if rc != 0 or "install ok installed" not in out:
            missing.append(pkg)
    return missing


# ---------------------------------------------------------------------------------------------------
# 7. The run
# ---------------------------------------------------------------------------------------------------


def copy_target(target: Path, tree: Path) -> int:
    """Copy the read-only target into the scratch tree (no .git, no pipeline output); file count."""
    if tree.exists():
        shutil.rmtree(tree)

    def ignore(directory: str, names: list[str]) -> set[str]:
        skip = {".git"} & set(names)
        for n in names:
            p = Path(directory) / n
            if p.is_dir() and not p.is_symlink() and is_pipeline_output_dir(p):
                skip.add(n)
        return skip

    shutil.copytree(target, tree, symlinks=True, ignore=ignore)
    return sum(len(fs) for _, _, fs in os.walk(tree))


def run_sandboxed_shell(
    command: str, cwd: Path, scratch: Path, timeout: int, env: dict[str, str], wrap: list[str]
) -> Any:
    """`sh -c command` (optionally under `wrap`, e.g. bear) through sandbox_exec.py: a SandboxResult."""
    from sandbox_exec import Limits, run_sandboxed

    limits = Limits(cpu_seconds=timeout, processes=2048, file_size_mb=2048, open_files=4096)
    return run_sandboxed([*wrap, "sh", "-c", command], [scratch], timeout, cwd=cwd, limits=limits, extra_env=env)


def build_env(recipe: dict, jobs: int) -> dict[str, str]:
    env = {"MAKEFLAGS": f"-j{jobs}", "CMAKE_BUILD_PARALLEL_LEVEL": str(jobs)}
    env.update(recipe.get("env") or {})
    return env


def compile_symbols(entry: dict, tree: str, tmp: Path, index: int) -> dict[str, tuple[str, str | None]]:
    """Defined symbols of one compile's object (recompiled into tmp for a compile-and-link command)."""
    cwd = absolute(entry["cwd"], tree)
    if entry["implicit"]:
        obj = tmp / f"implicit-{index}.o"
        src = absolute(entry["source"], tree)
        rc, _, _ = run_tool(compile_argv(entry["arguments"], src, str(obj)), cwd=cwd, timeout=300)
        if rc != 0:
            return {}
    else:
        obj = Path(absolute(entry["object"], tree))
    if not obj.is_file():
        return {}
    rc, out, _ = run_tool(["nm", "--defined-only", "-l", str(obj)], timeout=TOOL_TIMEOUT_S)
    if rc != 0:
        rc, out, _ = run_tool(["nm", "--defined-only", str(obj)], timeout=TOOL_TIMEOUT_S)
    return parse_nm(out) if rc == 0 else {}


def compile_deps(entry: dict, tree: str) -> list[str]:
    cwd = absolute(entry["cwd"], tree)
    src = absolute(entry["source"], tree)
    rc, out, _ = run_tool(deps_argv(entry["arguments"], src), cwd=cwd, timeout=300)
    return parse_make_deps(out, cwd) if rc == 0 else []


def function_ids(entry: dict, syms: dict[str, tuple[str, str | None]], tree: str) -> dict[str, dict]:
    """name -> {"id", "global"} for the functions an object defines (`file#name`)."""
    out: dict[str, dict] = {}
    for name, (typ, file) in syms.items():
        if typ not in FUNCTION_TYPES and typ != "t":
            continue
        where = entry["source"]
        if file and file.endswith(".h"):
            rel = tree_rel(absolute(file, absolute(entry["cwd"], tree)), tree)
            if rel:
                where = rel
        out[name] = {"id": f"{where}#{name}", "global": typ in FUNCTION_TYPES}
    return out


def try_install(tree: Path, scratch: Path, recipe: dict, timeout: int) -> tuple[list[Path], str]:
    """Headers a `make install DESTDIR=` (or `cmake --install`) stages, or ([], why not)."""
    staging = scratch / "install"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    command = recipe.get("install_command")
    cwd = tree / recipe["workdir"]
    if command:
        command = command.replace("{destdir}", shlex.quote(str(staging)))
    else:
        caches = sorted(tree.rglob("CMakeCache.txt"))
        makefile = next((cwd / n for n in ("GNUmakefile", "Makefile", "makefile") if (cwd / n).is_file()), None)
        if caches:
            command = f"cmake --install {shlex.quote(str(caches[0].parent))} --prefix {shlex.quote(str(staging))}"
        elif makefile and re.search(r"^install\s*:", makefile.read_text(encoding="utf-8", errors="replace"), re.M):
            command = f"make install DESTDIR={shlex.quote(str(staging))}"
        else:
            return [], "no install target"
    try:
        res = run_sandboxed_shell(command, cwd, scratch, timeout, dict(recipe.get("env") or {}), [])
    except Exception as exc:  # noqa: BLE001 - the fallback must never fail the capture
        return [], f"install failed: {exc}"
    if res.returncode != 0:
        return [], f"install failed (rc={res.returncode})"
    headers = sorted(p for p in staging.rglob("*.h") if p.is_file())
    return headers, "install" if headers else "install staged no header"


def capture(args: argparse.Namespace) -> tuple[dict, int]:
    run_dir = Path.cwd()
    target = Path(args.target)
    scratch = Path(args.scratch)
    tree = scratch / "tree"
    logs = run_dir / "workspace" / "reports" / "build_capture"
    logs.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "status": STATUS_NEEDS_RECIPE,
        "target": str(target),
        "scratch": {"root": str(scratch), "tree": str(tree)},
        "recipe": None,
        "build": None,
        "diagnostics": None,
        "compiles": [],
        "units": {},
        "entry_points": [],
        "public_headers": None,
        "snapshot": None,
        "test_rule": TEST_RULE,
        "warnings": [],
        "seconds": 0.0,
    }
    recipe = load_recipe(args)
    if recipe is None:
        proposed = propose_recipe(target)
        report["diagnostics"] = {
            **diagnose(""),
            "first_error": "no build recipe recorded (run_metadata.py set-build)",
            "proposed_recipe": proposed,
        }
        return report, EXIT_NEEDS_RECIPE
    report["recipe"] = recipe
    tree_files = copy_target(target, tree)
    build_dir = tree / recipe["workdir"]
    if not build_dir.is_dir():
        report["diagnostics"] = {**diagnose(""), "first_error": f"working directory {recipe['workdir']} not found"}
        return report, EXIT_NEEDS_RECIPE
    missing_pkgs = packages_missing(recipe["packages"])
    events = scratch / "events.jsonl"
    jobs = job_count()
    # A Makefile that is not parallel-safe fails under -j, or stalls (CryptoLib under `bear` without the
    # broker's lease): after a non-zero exit or a timeout, retry once with one job, on a fresh copy, unless
    # the recipe sets the parallelism itself.
    plan = [jobs]
    if jobs > 1 and not {"MAKEFLAGS", "CMAKE_BUILD_PARALLEL_LEVEL"} & set(recipe["env"]):
        plan.append(1)
    attempts: list[dict] = []
    log = ""
    for n, j in enumerate(plan):
        if n:
            (logs / "build-parallel.log").write_text(log, encoding="utf-8")
            tree_files = copy_target(target, tree)
        events.unlink(missing_ok=True)
        t0 = time.monotonic()
        res = run_sandboxed_shell(
            recipe["command"],
            build_dir,
            scratch,
            args.timeout,
            build_env(recipe, j),
            ["bear", "intercept", "--output", str(events), "--"],
        )
        build_seconds = round(time.monotonic() - t0, 2)
        log = (res.stdout or "") + (res.stderr or "")
        attempts.append(
            {"jobs": j, "returncode": res.returncode, "timed_out": bool(res.timed_out), "seconds": build_seconds}
        )
        if res.returncode == 0 and not res.timed_out:
            break
    if len(attempts) > 1 and res.returncode == 0 and not res.timed_out:
        how = "timed out" if attempts[0]["timed_out"] else "failed"
        report["warnings"].append(
            f"the build {how} with {jobs} jobs and succeeded with one (not parallel-safe); "
            "see workspace/reports/build_capture/build-parallel.log"
        )
    (logs / "build.log").write_text(log, encoding="utf-8")
    if events.is_file():
        shutil.copyfile(events, logs / "events.jsonl")
    execs = read_executions(events)
    report["build"] = {
        "returncode": res.returncode,
        "timed_out": res.timed_out,
        "seconds": build_seconds,
        "jobs": attempts[-1]["jobs"],
        "attempts": attempts,
        "tree_files": tree_files,
        "executions": len(execs),
        "log": "workspace/reports/build_capture/build.log",
        "events": "workspace/reports/build_capture/events.jsonl",
    }
    if res.returncode != 0 or res.timed_out:
        report["diagnostics"] = diagnose(log, missing_pkgs)
        if res.timed_out:
            report["diagnostics"]["first_error"] = f"build timed out after {args.timeout} s"
        return report, EXIT_NEEDS_RECIPE
    cap = classify_executions(execs, str(tree))
    if not cap["compiles"]:
        report["diagnostics"] = {
            **diagnose(log, missing_pkgs),
            "first_error": "the build compiled no C file (a prebuilt tree, or a recipe that does not build: "
            "add a clean step or name the build target)",
        }
        return report, EXIT_NEEDS_RECIPE
    analyse(report, cap, tree, scratch, recipe, args.timeout, jobs)
    report["status"] = STATUS_OK
    report["seconds"] = round(time.monotonic() - started, 2)
    return report, 0


def analyse(report: dict, cap: dict, tree: Path, scratch: Path, recipe: dict, timeout: int, jobs: int) -> None:
    """Units, flags, symbols, entry points and the snapshot of a successful build."""
    t = str(tree)
    compiles: dict[str, dict] = cap["compiles"]
    units = derive_units(cap, t)
    tmp = scratch / "tmp"
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)
    entries = sorted(compiles.values(), key=lambda c: c["object"])
    with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        deps = dict(zip([c["object"] for c in entries], pool.map(lambda c: compile_deps(c, t), entries), strict=True))
        syms = dict(
            zip(
                [c["object"] for c in entries],
                pool.map(lambda ic: compile_symbols(ic[1], t, tmp, ic[0]), enumerate(entries)),
                strict=True,
            )
        )
    system_headers: set[str] = set()
    for c in entries:
        project: list[str] = []
        system: list[str] = []
        for d in deps[c["object"]][1:]:
            r = tree_rel(d, t)
            (project if r is not None else system).append(r if r is not None else d)
        c["headers"] = sorted(set(project))
        # E-ACSL builds against glibc, whose setjmp.h Frama-C rejects (build_callgraph_dag.route_nonlocal_jumps).
        c["includes_setjmp_h"] = any(posixpath.basename(d) == "setjmp.h" for d in system)
        system_headers |= set(system)
    fn_of = {c["object"]: function_ids(c, syms[c["object"]], t) for c in entries}
    for c in entries:
        # What the compiler emitted, for the DAG to compare with what Frama-C parsed: code behind a
        # macro the compiler defines and Frama-C does not (`__SSE2__`) is in the build only.
        c["defined_functions"] = sorted({info["id"] for info in fn_of[c["object"]].values()})
    project_headers = sorted({h for c in entries for h in c["headers"] if h.endswith(".h")})
    project_headers = sorted(set(project_headers) | {p.relative_to(tree).as_posix() for p in tree.rglob("*.h")})

    # Public headers (static libraries).
    public: dict[str, Any] = {"method": None, "files": []}
    public_paths: list[Path] = []
    static_units = [n for n, u in units.items() if u["kind"] == "static_lib" and not u["test"]]
    if static_units:
        installed, why = try_install(tree, scratch, recipe, INSTALL_TIMEOUT_S)
        if installed:
            public = {"method": "install", "files": [str(p) for p in installed]}
            public_paths = installed
        else:
            src_dirs = source_dirs(compiles.values())
            outside = outside_source_dirs([h for h in project_headers if not posixpath.isabs(h)], src_dirs)
            if outside:
                public = {"method": "outside_source_dirs", "files": outside, "install": why}
            else:
                public = {"method": "consumers", "files": [], "install": why}
            public_paths = [tree / h for h in outside]
    report["public_headers"] = public

    # Entry points.
    for name, u in units.items():
        own = [compiles[o] for o in u["objects"]]
        u["cppflags"] = unit_cppflags(own)
        entries_: set[str] = set()
        embedded: set[str] = set()
        globals_: dict[str, str] = {}
        for c in own:
            for fname, info in fn_of[c["object"]].items():
                if info["global"]:
                    globals_.setdefault(fname, info["id"])
        if u["kind"] == "executable":
            if "main" in globals_:
                entries_.add(globals_["main"])
            if "main" in globals_ and not u["test"]:
                # A library compiled straight into the executable: its globals declared in project headers.
                main_file = globals_["main"].split("#", 1)[0]
                api = {n: i for n, i in globals_.items() if n != "main" and i.split("#", 1)[0] != main_file}
                headers = sorted({h for c in own for h in c["headers"] if h.endswith(".h")})
                flags = absolute_flags(own[0]["flags"], t) + own[0]["system_flags"] if own else []
                if api and headers:
                    embedded = {api[n] for n in declared_in([tree / h for h in headers], set(api), flags)}
        elif u["kind"] == "shared_lib":
            rc, out, _ = run_tool(["nm", "-D", "--defined-only", str(tree / name)])
            exported = {s for s, (typ, _) in parse_nm(out).items() if typ in FUNCTION_TYPES} if rc == 0 else set()
            entries_ = {i for n, i in globals_.items() if n in exported}
        elif u["kind"] == "static_lib":
            headers_ = list(public_paths)
            if public["method"] == "consumers":
                consumers = [
                    compiles[o] for v in units.values() if name in v["links"] for o in v["objects"] if o in compiles
                ]
                used = sorted({h for c in consumers for h in c["headers"] if h.endswith(".h")})
                # No consumer in the build: every project header is a candidate.
                chosen = used or [h for h in project_headers if not posixpath.isabs(h)]
                headers_ = [tree / h for h in chosen]
                public["files"] = sorted(set(public["files"]) | set(chosen))
            flags = absolute_flags(own[0]["flags"], t) + own[0]["system_flags"] if own else []
            if headers_:
                entries_ = {globals_[n] for n in declared_in(headers_, set(globals_), flags)}
            else:
                entries_ = set(globals_.values())
        u["entry_points"] = sorted(entries_)
        u["embedded_api"] = sorted(embedded)
    report["units"] = {n: units[n] for n in sorted(units)}
    report["entry_points"] = sorted({e for u in units.values() if not u["test"] for e in u["entry_points"]})
    report["compiles"] = [
        {
            k: c[k]
            for k in (
                "source",
                "object",
                "cwd",
                "compiler",
                "arguments",
                "flags",
                "system_flags",
                "headers",
                "includes_setjmp_h",
                "defined_functions",
            )
        }
        for c in entries
    ]
    report["build"]["probes_dropped"] = cap["probes_dropped"]
    snapshot = Path.cwd() / target_env.SNAPSHOT_REL
    generated = generated_headers(entries, Path(report["target"]))
    report["snapshot"] = build_snapshot(
        snapshot,
        tree,
        units,
        system_headers,
        recipe,
        report["warnings"],
        generated=generated,
        generated_dirs=generated_include_dirs(generated, entries),
    )


def build_snapshot(
    snapshot: Path,
    tree: Path,
    units: dict,
    system_headers: set[str],
    recipe: dict,
    warnings: list[str],
    generated: list[str] | None = None,
    generated_dirs: list[str] | None = None,
) -> dict:
    """
    Headers, libraries and their shared dependencies outside the project and libc, copied with a digest
    to the run's snapshot (<run>/workspace/snapshot): every container of the run mounts the run
    directory, so the analysis image finds them there (scripts/target_env.py). The headers the build
    generated in the tree (`generated`, tree-relative) go with them: the analyses read the target, not
    the scratch tree, and would miss `config.h`.
    """
    t = str(tree)
    libs: dict[str, str] = {}  # path -> how it was found
    for name, u in units.items():
        for ext in u["external_libs"]:
            path = resolve_link_lib(ext["ref"], ext["libdirs"], u.get("compiler"))
            if path:
                libs.setdefault(path, "link")
                real = os.path.realpath(path)
                if real != path:
                    libs.setdefault(real, "link")
            else:
                warnings.append(f"{name}: {ext['ref']} not resolved")
    rc, out, _ = run_tool(["ldconfig", "-p"])
    ldconfig = parse_ldconfig(out) if rc == 0 else {}
    starts = [tree / n for n, u in units.items() if u["kind"] in ("executable", "shared_lib") and (tree / n).is_file()]
    starts += [Path(p) for p in libs if _SHARED_RE.search(p)]
    for _, paths in shared_closure(starts, ldconfig).items():
        for p in paths:
            if tree_rel(p, t) is None:
                libs.setdefault(p, "needed")
    extra = [p for p in recipe.get("snapshot_extra") or []]
    extra_files: list[str] = []
    for p in extra:
        if os.path.isdir(p):
            extra_files += [str(f) for f in Path(p).rglob("*") if f.is_file()]
        elif os.path.isfile(p):
            extra_files.append(p)
        else:
            warnings.append(f"snapshot_extra: {p} not found")
    classes = classify_system_paths(set(system_headers) | set(libs))
    headers = [
        {"path": p, "package": classes[p]["package"], "class": classes[p]["class"]} for p in sorted(system_headers)
    ]
    libraries = [
        {"path": p, "package": classes[p]["package"], "class": classes[p]["class"], "via": how}
        for p, how in sorted(libs.items())
    ]
    exported = {e["path"]: e for e in headers + libraries if e["class"] in ("package", "unowned")}
    exported.update({p: {"path": p} for p in extra_files})
    summary = export_snapshot(snapshot, exported, {h: tree / h for h in generated or []}, generated_dirs)
    result: dict[str, Any] = {
        "root": (snapshot / "root").as_posix(),
        "digest": summary["digest"],
        "files": summary["files"],
        "headers": [h for h in headers if h["class"] in ("package", "unowned")],
        "libraries": [lib for lib in libraries if lib["class"] in ("package", "unowned")],
        "excluded": {
            "libc_headers": sum(1 for h in headers if h["class"] == "libc"),
            "toolchain_headers": sum(1 for h in headers if h["class"] == "toolchain"),
            "libc_or_toolchain_libraries": sum(1 for lib in libraries if lib["class"] in ("libc", "toolchain")),
        },
        "packages": sorted({e["package"] for e in exported.values() if e.get("package")}),
        "extra": extra,
    }
    if summary["generated"]:
        result["generated"] = {"headers": sorted(generated or []), "include_dirs": list(generated_dirs or [])}
    return result


# ---------------------------------------------------------------------------------------------------
# 8. Report, checkpoint, CLI
# ---------------------------------------------------------------------------------------------------


def validate_report(report: dict) -> list[str]:
    from minischema import Validator, load_schema

    here = Path(__file__).resolve().parent
    for cand in (here.parent / "schemas", Path("/opt/framac-pipeline/schemas")):
        path = cand / "build_capture.schema.json"
        if path.is_file():
            return Validator(load_schema(path)).errors(report)
    return ["schemas/build_capture.schema.json not found"]


def record_checkpoint(state: Path, report: dict) -> None:
    import checkpoint

    if report["status"] == STATUS_NEEDS_RECIPE:
        diag = report.get("diagnostics") or {}
        checkpoint.mark_blocked(
            state,
            STATUS_NEEDS_RECIPE,
            {"report": "workspace/reports/build_capture.json", "first_error": diag.get("first_error")},
        )
    else:
        checkpoint.clear_blocked(state, STATUS_NEEDS_RECIPE)


def cmd_run(args: argparse.Namespace) -> int:
    try:
        report, code = capture(args)
    except Exception as exc:  # noqa: BLE001 - recorded as a status, never a traceback without a report
        report = {
            "schema_version": SCHEMA_VERSION,
            "generated_at": utc_now(),
            "status": "error",
            "target": str(args.target),
            "error": f"{type(exc).__name__}: {exc}",
            "warnings": [],
        }
        code = 1
    errors = validate_report(report)
    if errors:
        report.setdefault("warnings", []).append("report does not match its schema: " + "; ".join(errors[:5]))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(out, report)
    if args.state and report.get("status") in (STATUS_OK, STATUS_NEEDS_RECIPE):
        record_checkpoint(Path(args.state), report)
    summary: dict[str, Any] = {"status": report["status"], "report": str(out)}
    if report.get("status") == STATUS_OK:
        summary["units"] = {n: [u["kind"], len(u["files"]), u["test"]] for n, u in report["units"].items()}
        summary["snapshot_digest"] = (report.get("snapshot") or {}).get("digest")
        summary["seconds"] = report.get("seconds")
    elif report.get("diagnostics"):
        d = report["diagnostics"]
        summary.update(
            {k: d.get(k) for k in ("first_error", "missing_headers", "candidate_packages", "packages_not_installed")}
        )
        if d.get("proposed_recipe"):
            summary["proposed_recipe"] = d["proposed_recipe"]
    else:
        summary["error"] = report.get("error")
    print(json.dumps(summary, indent=1))
    return code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Capture the target's build (Phase 0 build capture).")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("run", help="Run the build recipe under bear and write the capture report")
    p.add_argument("--target", default="/target")
    p.add_argument("--scratch", default="/framac-scratch", help="the run's scratch volume")
    p.add_argument("--out", default="workspace/reports/build_capture.json")
    p.add_argument("--state", default="state", help="checkpoint directory ('' to leave it alone)")
    p.add_argument("--recipe-file", default="run-metadata.json", help="JSON file with a `build` block")
    p.add_argument("--command", default=None, help="build command (overrides the recipe file)")
    p.add_argument("--workdir", default=None)
    p.add_argument("--env", action="append", default=[], metavar="KEY=VALUE")
    p.add_argument("--package", action="append", default=[])
    p.add_argument("--test-command", default=None)
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_S)
    q = sub.add_parser("propose", help="Print a recipe guessed from the build files")
    q.add_argument("--target", default="/target")
    args = parser.parse_args(argv)
    if args.cmd == "propose":
        print(json.dumps({"proposed_recipe": propose_recipe(Path(args.target))}, indent=1))
        return 0
    return cmd_run(args)


if __name__ == "__main__":
    sys.exit(main())
