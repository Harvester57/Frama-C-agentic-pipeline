"""
glibc names, layouts and pragmas that stopped Frama-C's parse of sudo 1.9.18 (run-1, 2026-11-21): 8 of its
25 link units went to the GCC fallback, with no harness, Eva or WP. Each repair is generic: the glibc
internal types (`__pid_t`, glibc's <sys/procfs.h>), the Linux RLIMIT_* names, RTLD_NEXT / RTLD_DEFAULT,
the GNU FNM_* flags, the lockf commands and mkdirat in templates/fc_stubs/fc_compat_types.h (__fc_libc
branch only); templates/fc_stubs/link.h (glibc's <link.h> uses GCC vector types and hides dl_phdr_info
behind __USE_GNU); `struct group`'s gr_passwd and `struct utmpx`'s ut_exit in templates/fc_stubs/fc_libc,
__fc_libc's headers with glibc's structures, which scripts/fc_cpp_wrapper.py puts before __fc_libc's on the
include path; and the wrapper again, which drops pragmas Frama-C's parser rejects
(`#pragma pvs(disable: 575, 618)`).
Docker-backed tests: FRAMAC_DOCKER_TESTS=1.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

import fc_cpp_wrapper as W
from conftest import ANALYSIS_IMAGE, ROOT, require_docker_images

STUBS = ROOT / "templates" / "fc_stubs"
COMPAT_TEXT = (STUBS / "fc_compat_types.h").read_text(encoding="utf-8")
FC_LIBC_BRANCH = COMPAT_TEXT.split("#else /* Frama-C __fc_libc */", 1)[1].split("#endif /* __FRAMAC_EACSL__ */", 1)[0]
EACSL_BRANCH = COMPAT_TEXT.split("#if defined(__FRAMAC_EACSL__)\n\n/* GCC's `__restrict__`", 1)[1].split(
    "#else /* Frama-C __fc_libc */", 1
)[0]

_PY = 'import sys; sys.path.insert(0, "/opt/framac-pipeline/scripts"); '
_FRAMAC_A = f"A=$(python3 -c '{_PY}import framac_common; print(framac_common.augment_framac_cppflags(\"-I.\"))'); "
_EACSL_F = (
    f"F=$(python3 -c '{_PY}import eacsl_toolchain as T; "
    'print(T.build_eacsl_flag_sets("-I.", fuzzer=False)["frontend"])\'); '
)

# glibc 2.41's x86_64 <bits/types.h>, as `gcc -E` prints it.
GLIBC_INTERNAL_TYPES = {
    "__u_char": "unsigned char", "__u_short": "unsigned short int", "__u_int": "unsigned int",
    "__u_long": "unsigned long int", "__quad_t": "long int", "__u_quad_t": "unsigned long int",
    "__intmax_t": "long int", "__uintmax_t": "unsigned long int", "__dev_t": "unsigned long int",
    "__uid_t": "unsigned int", "__gid_t": "unsigned int", "__ino_t": "unsigned long int",
    "__ino64_t": "unsigned long int", "__mode_t": "unsigned int", "__nlink_t": "unsigned long int",
    "__off_t": "long int", "__off64_t": "long int", "__pid_t": "int", "__clock_t": "long int",
    "__rlim_t": "unsigned long int", "__rlim64_t": "unsigned long int", "__id_t": "unsigned int",
    "__time_t": "long int", "__useconds_t": "unsigned int", "__suseconds_t": "long int",
    "__suseconds64_t": "long int", "__daddr_t": "int", "__key_t": "int", "__clockid_t": "int",
    "__timer_t": "void *", "__blksize_t": "long int", "__blkcnt_t": "long int", "__blkcnt64_t": "long int",
    "__fsblkcnt_t": "unsigned long int", "__fsblkcnt64_t": "unsigned long int",
    "__fsfilcnt_t": "unsigned long int", "__fsfilcnt64_t": "unsigned long int", "__fsword_t": "long int",
    "__ssize_t": "long int", "__syscall_slong_t": "long int", "__syscall_ulong_t": "unsigned long int",
    "__loff_t": "long int", "__caddr_t": "char *", "__intptr_t": "long int", "__socklen_t": "unsigned int",
    "__sig_atomic_t": "int",
}  # fmt: skip
_TYPEDEF_RE = re.compile(r"^typedef ([^;]*?)\s*(\*?)(__\w+);$", re.MULTILINE)

# __fc_libc's seven POSIX limits (34.0~beta <sys/resource.h>) and the names fc_compat_types.h adds.
FC_LIBC_RLIMITS = {"RLIMIT_CORE": 0, "RLIMIT_CPU": 1, "RLIMIT_DATA": 2, "RLIMIT_FSIZE": 3, "RLIMIT_NOFILE": 4,
                   "RLIMIT_STACK": 5, "RLIMIT_AS": 6}  # fmt: skip
ADDED_RLIMITS = ("RLIMIT_RSS", "RLIMIT_NPROC", "RLIMIT_MEMLOCK", "RLIMIT_LOCKS", "RLIMIT_SIGPENDING",
                 "RLIMIT_MSGQUEUE", "RLIMIT_NICE", "RLIMIT_RTPRIO", "RLIMIT_RTTIME")  # fmt: skip
_DEFINE_RE = re.compile(r"^#define\s+(\w+)\s+(.+?)\s*$", re.MULTILINE)


def _defines(text: str) -> dict[str, str]:
    return dict(_DEFINE_RE.findall(text))


def _run_in_image(tmp_path: Path, files: dict[str, str], script: str, timeout: int = 900) -> str:
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8", newline="\n")
    proc = subprocess.run(
        [
            "docker", "run", "--rm", "--network", "none", "--label", "framac.test=test_fc_glibc_gaps",
            "-v", f"{tmp_path}:/w",
            "-v", f"{ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
            "-v", f"{ROOT / 'templates'}:/opt/framac-pipeline/templates:ro",
            "--entrypoint", "bash", ANALYSIS_IMAGE, "-c", "cd /w; " + script,
        ],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, check=False,
    )  # fmt: skip
    log = proc.stdout + proc.stderr
    assert proc.returncode == 0, log
    return log


def _section(log: str, tag: str) -> str:
    """The output between the `==tag==` line and the next `==name==` line (printed code has `==` too)."""
    after = ("\n" + log).split(f"\n=={tag}==\n", 1)[1]
    return re.split(r"^==\w+==$", after, maxsplit=1, flags=re.MULTILINE)[0]


# ---------------------------------------------------------------------------------------------------
# fc_compat_types.h, read as text
# ---------------------------------------------------------------------------------------------------


@pytest.mark.unit
def test_glibc_internal_types_are_glibc_s_and_only_for_frama_c_libc():
    block = FC_LIBC_BRANCH.split("#define __FC_COMPAT_GLIBC_TYPES_DEFINED 1", 1)[1].split("#endif", 1)[0]
    found = {name: f"{base} {star}".strip() for base, star, name in _TYPEDEF_RE.findall(block)}
    assert found == GLIBC_INTERNAL_TYPES
    # E-ACSL builds take them from glibc itself.
    assert "__pid_t" not in EACSL_BRANCH


@pytest.mark.unit
def test_rlimit_names_continue_after_frama_c_libc_s_and_never_collide():
    defs = _defines(FC_LIBC_BRANCH)
    values = [int(defs[name]) for name in ADDED_RLIMITS]
    assert len(set(values)) == len(values)
    assert not set(values) & set(FC_LIBC_RLIMITS.values())
    assert int(defs["RLIMIT_NLIMITS"]) == max(values) + 1
    assert defs["RLIM_NLIMITS"] == "RLIMIT_NLIMITS" and defs["RLIMIT_OFILE"] == "RLIMIT_NOFILE"
    for name in (*ADDED_RLIMITS, "RLIMIT_NLIMITS", "RLIM_NLIMITS", "RLIMIT_OFILE"):
        assert f"#ifndef {name}\n#define {name} " in FC_LIBC_BRANCH, name
    # After <sys/resource.h>, so each steps aside when the libc defines it.
    assert FC_LIBC_BRANCH.index("#include <sys/resource.h>") < FC_LIBC_BRANCH.index("#define RLIMIT_RSS ")


@pytest.mark.unit
def test_rtld_pseudo_handles_fnmatch_flags_and_lockf_commands_are_glibc_s():
    defs = _defines(FC_LIBC_BRANCH)
    expected = {
        "RTLD_NEXT": "((void *) -1l)", "RTLD_DEFAULT": "((void *) 0)",
        "FNM_FILE_NAME": "FNM_PATHNAME", "FNM_LEADING_DIR": "(1 << 3)", "FNM_CASEFOLD": "(1 << 4)",
        "FNM_EXTMATCH": "(1 << 5)", "FNM_NOSYS": "(-1)",
        "F_ULOCK": "0", "F_LOCK": "1", "F_TLOCK": "2", "F_TEST": "3",
    }  # fmt: skip
    for name, value in expected.items():
        assert defs.get(name) == value, name
        assert f"#ifndef {name}\n#define {name} {value}\n#endif" in FC_LIBC_BRANCH, name
        assert COMPAT_TEXT.count(f"#define {name} ") == 1, name


FC_LIBC_OVERRIDES = STUBS / W.LIBC_OVERRIDE_SUBDIR


@pytest.mark.unit
def test_fc_libc_holds_frama_c_s_grp_and_utmpx_with_glibc_s_structures():
    assert sorted(p.name for p in FC_LIBC_OVERRIDES.iterdir()) == ["grp.h", "utmpx.h"]
    grp = (FC_LIBC_OVERRIDES / "grp.h").read_text(encoding="utf-8")
    utmpx = (FC_LIBC_OVERRIDES / "utmpx.h").read_text(encoding="utf-8")
    # __fc_libc's guards (a later `#include <grp.h>` reads nothing more), marked as __fc_libc's headers.
    for text, guard, name in ((grp, "__FC_GRP_H", "grp.h"), (utmpx, "__FC_UTMPX_H", "utmpx.h")):
        assert f"\n#ifndef {guard}\n#define {guard}\n" in text, name
        assert f'__PRAGMA_PUSH("{name}")' in text and text.rstrip().endswith("__POP_FC_STDLIB\n#endif"), name
    members = re.search(r"struct group \{(.*?)\};", grp, re.DOTALL)
    assert members is not None
    assert re.findall(r"(\w+);", members.group(1)) == ["gr_name", "gr_passwd", "gr_gid", "gr_mem"]
    for fn in ("getgrgid", "getgrnam", "getgrgid_r", "getgrnam_r", "getgrent", "endgrent", "setgrent",
               "getgrouplist", "initgroups"):  # fmt: skip
        assert re.search(rf"\*/\nextern [^;]*\b{fn}\(", grp), fn
    assert "struct __exit_status ut_exit;" in utmpx and "int32_t ut_session;" in utmpx
    for fn in ("getutxent", "setutxent", "endutxent", "getutxid", "getutxline", "pututxline"):
        assert re.search(rf"\*/\nextern [^;]*\b{fn} \(", utmpx), fn
    # Never in the force-included header: its names would be in every unit (`EMPTY`, `ut_time`, `struct group`).
    for name in ("struct group", "struct utmpx", "__fc_utmp_constants.h", "__FC_GRP_H", "__FC_UTMPX_H"):
        assert name not in COMPAT_TEXT, name


def _fake_dirs(tmp_path: Path, overrides: bool = True) -> tuple[str, str]:
    libc = tmp_path / "share" / "libc"
    libc.mkdir(parents=True)
    (libc / "__fc_libc.h").write_text("", encoding="utf-8")
    stubs = tmp_path / "fc_stubs"
    stubs.mkdir()
    (stubs / "fc_compat_types.h").write_text("", encoding="utf-8")
    if overrides:
        (stubs / "fc_libc").mkdir()
    return str(libc), str(stubs)


@pytest.mark.unit
def test_the_wrapper_puts_fc_libc_right_before_frama_c_s_libc(tmp_path):
    libc, stubs = _fake_dirs(tmp_path)
    over = str(Path(stubs) / "fc_libc")
    cc1 = "/usr/libexec/gcc/x86_64-linux-gnu/14/cc1"
    out = tmp_path / "p.i"
    out.write_text("int x;\n", encoding="utf-8")
    tail = ["-D", "__FRAMAC__", "-include", f"{stubs}/fc_compat_types.h", "/tmp/p.c", "-o", str(out)]
    cmd = [cc1, "-E", "-quiet", "-nostdinc", "-I", ".", "-I", "/tmp/md.dir", "-I", libc, "-I", stubs, *tail]
    assert W.with_libc_overrides(cmd) == [cc1, "-E", "-quiet", "-nostdinc", "-I", ".", "-I", "/tmp/md.dir",
                                          "-I", over, "-I", libc, "-I", stubs, *tail]  # fmt: skip
    joined = [cc1, "-E", f"-I{libc}", f"-I{stubs}", "/tmp/p.c"]
    assert W.with_libc_overrides(joined) == [cc1, "-E", "-I", over, f"-I{libc}", f"-I{stubs}", "/tmp/p.c"]
    # The E-ACSL frontend (-no-frama-c-stdlib: no __fc_libc), an argument list that has it already, a
    # compile (no -E) and another subcommand stay as they are.
    for same in (
        [cc1, "-E", "-I", stubs, "-idirafter", "/usr/include", "/tmp/p.c"],
        [cc1, "-E", "-I", over, "-I", libc, "-I", stubs, "/tmp/p.c"],
        [cc1, "-I", libc, "-I", stubs, "/tmp/p.c"],
        ["/usr/bin/as", "-I", libc, "-I", stubs, "-E"],
    ):
        assert W.with_libc_overrides(same) == same
    # Run with the override, unless FRAMAC_CPP_REWRITE=off.
    seen: list[list[str]] = []

    def call(c: list[str]) -> int:
        seen.append(c)
        return 0

    assert W.run(cmd, call=call) == 0
    at = seen[-1].index(libc)
    assert seen[-1][at - 3 : at] == ["-I", over, "-I"]


@pytest.mark.unit
def test_the_wrapper_adds_nothing_without_an_fc_libc_next_to_the_compat_header(tmp_path):
    libc, stubs = _fake_dirs(tmp_path, overrides=False)
    cmd = ["cc1", "-E", "-I", libc, "-I", stubs, "/tmp/p.c"]
    assert W.with_libc_overrides(cmd) == cmd


@pytest.mark.unit
def test_link_h_serves_its_declarations_to_every_frama_c_parse_and_glibc_s_to_compilers():
    text = (STUBS / "link.h").read_text(encoding="utf-8")
    framac, other = text.split("#if defined(__FRAMAC__)", 1)[1].split("#else", 1)
    assert framac.strip() == '#include "fc_link.h"'
    assert "#include_next <link.h>" in other
    # No structure in link.h itself: stub_check.py's shipped check cannot compile glibc's under __USE_GNU.
    assert "struct" not in text.split("*/", 1)[1]
    framac = (STUBS / "fc_link.h").read_text(encoding="utf-8").split("*/", 1)[1]
    assert "__FRAMAC_EACSL__" not in framac
    info = re.search(r"struct dl_phdr_info \{(.*?)\};", framac, re.DOTALL)
    assert info is not None
    assert re.findall(r"(\w+);", info.group(1)) == [
        "dlpi_addr", "dlpi_name", "dlpi_phdr", "dlpi_phnum", "dlpi_adds", "dlpi_subs", "dlpi_tls_modid",
        "dlpi_tls_data",
    ]  # fmt: skip
    assert "extern int dl_iterate_phdr(" in framac and "__vector_size__" not in framac


# ---------------------------------------------------------------------------------------------------
# fc_cpp_wrapper.py: pragmas Frama-C does not interpret
# ---------------------------------------------------------------------------------------------------

PRAGMA_TEXT = (
    '# 1 "<built-in>"\n'
    '# 1210 "gram.y"\n'
    "void sudoerserror(const char *s)\n"
    "{\n"
    "#pragma pvs(push)\n"
    "#pragma pvs(disable: 575, 618)\n"
    "  /* a comment that mentions\n"
    "#pragma pvs(disable: 1)\n"
    "  */\n"
    '  f("#pragma pvs(x: 1)");\n'
    "#pragma GCC diagnostic push\n"
    "#pragma pack(push, 1)\n"
    "#pragma STDC FP_CONTRACT ON\n"
    "#pragma fc_stdlib(pop)\n"
    "  #  pragma clang loop vectorize(enable)\n"
    "#pragma\n"
    "#pragma pvs(pop)\n"
    "}\n"
)


@pytest.mark.unit
def test_unknown_pragmas_are_blanked_and_located_and_known_ones_kept():
    new, notes = W.drop_unknown_pragmas(PRAGMA_TEXT)
    assert new.count("\n") == PRAGMA_TEXT.count("\n")
    lines = new.split("\n")
    assert lines[4] == lines[5] == lines[14] == lines[16] == ""
    for kept in ("#pragma pvs(disable: 1)", '"#pragma pvs(x: 1)"', "#pragma GCC diagnostic push",
                 "#pragma pack(push, 1)", "#pragma STDC FP_CONTRACT ON", "#pragma fc_stdlib(pop)"):  # fmt: skip
        assert kept in new, kept
    assert lines[15] == "#pragma"
    assert [(n["file"], n["line"], n["original"]) for n in notes] == [
        ("gram.y", 1212, "#pragma pvs(push)"),
        ("gram.y", 1213, "#pragma pvs(disable: 575, 618)"),
        ("gram.y", 1222, "# pragma clang loop vectorize(enable)"),
        ("gram.y", 1224, "#pragma pvs(pop)"),
    ]
    assert {n["kind"] for n in notes} == {"unknown pragma"}
    assert W.drop_unknown_pragmas("int x;\n") == ("int x;\n", [])


@pytest.mark.unit
def test_rewrite_file_drops_the_pvs_pragma_and_logs_it(tmp_path, capsys):
    path = tmp_path / "gram.i"
    path.write_bytes(PRAGMA_TEXT.encode("latin-1"))
    notes = W.rewrite_file(str(path))
    assert len(notes) == 4
    text = path.read_bytes().decode("latin-1")
    assert "pvs(disable: 575" not in text and "#pragma pack(push, 1)" in text
    err = capsys.readouterr().err
    assert "[fc-cpp] gram.y:1213: unknown pragma rewritten: #pragma pvs(disable: 575, 618) -> (blank line)" in err


@pytest.mark.unit
def test_frama_c_s_line_pragmas_and_interpreted_pragmas_are_kept():
    for name in ("warning", "GCC", "omp", "weak", "redefine_extname", "pack", "align", "noalign", "fc_stdlib"):
        assert name in W.PRAGMA_KEEP, name
    assert "pvs" not in W.PRAGMA_KEEP and "clang" not in W.PRAGMA_KEEP


# ---------------------------------------------------------------------------------------------------
# Docker: Frama-C's own libc (Eva, WP, the model) and the E-ACSL frontend
# ---------------------------------------------------------------------------------------------------

# Every gap of sudo's first round, as sudo meets it, with gcc's offsets as `_Static_assert`s (layout.h).
GAPS_C = r"""#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/procfs.h>
#include <bits/types.h>
#include <grp.h>
#include <utmpx.h>
#include <dlfcn.h>
#include <link.h>
#include <fnmatch.h>
#include <unistd.h>
#include <sys/resource.h>
#include <stddef.h>
#include "layout.h"

int status_pid(const struct elf_prstatus *st) { return st->pr_pid; }

char *group_password(struct group *gr) { return gr->gr_passwd; }

int exit_status(struct utmpx *ut) { return ut->ut_exit.e_termination + ut->ut_exit.__e_exit; }

int limit_kind(int resource) {
  switch (resource) {
  case RLIMIT_CORE: case RLIMIT_CPU: case RLIMIT_DATA: case RLIMIT_FSIZE: case RLIMIT_NOFILE:
  case RLIMIT_STACK: case RLIMIT_AS:
    return 0;
  case RLIMIT_RSS: case RLIMIT_NPROC: case RLIMIT_MEMLOCK: case RLIMIT_LOCKS: case RLIMIT_SIGPENDING:
  case RLIMIT_MSGQUEUE: case RLIMIT_NICE: case RLIMIT_RTPRIO: case RLIMIT_RTTIME:
    return 1;
  default:
    return 2;
  }
}
_Static_assert(RLIM_NLIMITS > RLIMIT_RTTIME && RLIMIT_OFILE == RLIMIT_NOFILE, "rlimit names");

int nproc_limit(struct rlimit *rl) { return getrlimit(RLIMIT_NPROC, rl); }

void *next_execve(void) { return RTLD_DEFAULT == 0 ? dlsym(RTLD_NEXT, "execve") : 0; }

int casefold_match(const char *p, const char *s) { return fnmatch(p, s, FNM_CASEFOLD | FNM_LEADING_DIR); }

int lock_all(int fd) { return lockf(fd, F_LOCK, 0) + lockf(fd, F_ULOCK, 0); }

/* Two calls whose mode argument has two types: with an implicit `int mkdirat()` the second stopped the unit. */
int make_dirs(int dfd, int mode) { return mkdirat(dfd, "a", mode) + mkdirat(dfd, "b", (mode_t)0700); }

static int phdr_cb(struct dl_phdr_info *info, size_t size, void *data) {
  unsigned long *sum = data;
  (void)size;
  *sum += info->dlpi_addr + info->dlpi_phnum;
  return 0;
}

unsigned long objects(void) {
  unsigned long sum = 0;
  dl_iterate_phdr(phdr_cb, &sum);
  return sum;
}

int quiet(int x) {
#pragma pvs(push)
#pragma pvs(disable: 575, 618)
  x += 1;
#pragma pvs(pop)
  return x;
}

#pragma pack(push, 1)
struct packed { char c; int i; };
#pragma pack(pop)
_Static_assert(sizeof(struct packed) == 5, "#pragma pack is still honoured");
"""

# gcc with glibc: the offsets and sizes Frama-C must agree with, written as `_Static_assert`s.
LAYOUT_GCC_C = r"""#define _GNU_SOURCE
#include <grp.h>
#include <utmpx.h>
#include <link.h>
#include <stddef.h>
#include <stdio.h>
#define SZ(T) printf("_Static_assert(sizeof(" #T ") == %zu, \"sizeof " #T "\");\n", sizeof(T))
#define OFF(T, m) printf("_Static_assert(offsetof(" #T ", " #m ") == %zu, \"" #T " " #m "\");\n", offsetof(T, m))
int main(void) {
  SZ(struct group); OFF(struct group, gr_name); OFF(struct group, gr_passwd); OFF(struct group, gr_gid);
  OFF(struct group, gr_mem);
  SZ(struct utmpx); OFF(struct utmpx, ut_type); OFF(struct utmpx, ut_pid); OFF(struct utmpx, ut_line);
  OFF(struct utmpx, ut_id); OFF(struct utmpx, ut_user); OFF(struct utmpx, ut_host); OFF(struct utmpx, ut_exit);
  OFF(struct utmpx, ut_session); OFF(struct utmpx, ut_tv); OFF(struct utmpx, ut_tv.tv_usec);
  OFF(struct utmpx, ut_addr_v6); OFF(struct utmpx, __glibc_reserved);
  SZ(struct dl_phdr_info); OFF(struct dl_phdr_info, dlpi_addr); OFF(struct dl_phdr_info, dlpi_name);
  OFF(struct dl_phdr_info, dlpi_phdr); OFF(struct dl_phdr_info, dlpi_phnum); OFF(struct dl_phdr_info, dlpi_adds);
  OFF(struct dl_phdr_info, dlpi_subs); OFF(struct dl_phdr_info, dlpi_tls_modid);
  OFF(struct dl_phdr_info, dlpi_tls_data);
  SZ(struct link_map); OFF(struct link_map, l_addr); OFF(struct link_map, l_name); OFF(struct link_map, l_ld);
  OFF(struct link_map, l_next); OFF(struct link_map, l_prev);
  SZ(struct r_debug); OFF(struct r_debug, r_map); OFF(struct r_debug, r_brk); OFF(struct r_debug, r_state);
  OFF(struct r_debug, r_ldbase);
  printf("_Static_assert(RTLD_LAZY > 0, \"layout.h read\");\n");
  return 0;
}
"""

# A unit that includes neither <grp.h> nor <utmpx.h> keeps its own names: the force-included compat header
# brings no `struct group` and no utmp constants (`EMPTY`, `ut_time`). (No <errno.h> with every opt-out:
# tests/test_fc_compat_contracts.py.)
OWN_NAMES_C = r"""enum fill { EMPTY, FULL };
struct group { int n; };
struct log { long ut_time; const char *ut_name; };
int count(const struct group *g, const struct log *l) { return g->n + FULL + EMPTY + (int)l->ut_time; }
"""

# __fc_libc's own <grp.h> (the wrapper's changes off): the gap the fc_libc directory repairs.
GRP_ONLY_C = r"""#include <grp.h>
char *group_password(struct group *gr) { return gr->gr_passwd; }
"""

# gcc with glibc: the compat header's typedefs must be the ones glibc's <bits/types.h> makes.
TYPES_GCC_C = r"""#include <sys/types.h>
#include <bits/types.h>
#include "ours.h"
int main(void) { return 0; }
"""

# The E-ACSL frontend: glibc's headers (gr_passwd and the RLIMIT_* names are glibc's), this directory's
# link.h (dl_iterate_phdr although glibc's __USE_GNU is off there: fc_compat_types.h includes glibc headers
# before the source's `#define _GNU_SOURCE`, an open pipeline bug, kernel-and-stubs.md), and the pvs pragma
# dropped by the E-ACSL wrapper. Run for real.
EACSL_C = r"""#define _GNU_SOURCE
#include <grp.h>
#include <utmpx.h>
#include <link.h>
#include <sys/resource.h>
#include <stdio.h>

static int count(struct dl_phdr_info *info, size_t size, void *data) {
  int *n = data;
  (void)size;
  if (info->dlpi_phnum > 0)
    *n += 1;
  return 0;
}

int main(void) {
  int n = 0;
  char pw[] = "x";
  struct group g = {0};
  struct utmpx ut = {0};
  struct rlimit rl;
#pragma pvs(disable: 575, 618)
  g.gr_passwd = pw;
  ut.ut_pid = 3;
  dl_iterate_phdr(count, &n);
  printf("objects=%d passwd=%s pid=%d nproc=%d\n", n > 0, g.gr_passwd, (int)ut.ut_pid,
         getrlimit(RLIMIT_NPROC, &rl));
  return 0;
}
"""


def _types_header() -> str:
    block = FC_LIBC_BRANCH.split("#define __FC_COMPAT_GLIBC_TYPES_DEFINED 1", 1)[1].split("#endif", 1)[0]
    return block.strip() + "\n"


@pytest.mark.integration
@pytest.mark.slow
def test_sudo_s_glibc_gaps_parse_with_frama_c_libc_with_glibc_s_layouts(tmp_path):
    require_docker_images(ANALYSIS_IMAGE)
    script = (
        _FRAMAC_A + 'echo "==guards=="; S=$(frama-c -print-share-path)/libc; '
        'grep -c "^#define __FC_GRP_H$" $S/grp.h; grep -c "^#define __FC_UTMPX_H$" $S/utmpx.h; '
        'echo "==types=="; gcc -fsyntax-only types.c 2>&1; echo "types=$?"; '
        'echo "==layout=="; gcc layout.c -o layout && ./layout > layout.h; echo "layout=$?"; '
        'echo "==parse=="; frama-c -no-unicode gaps.c -cpp-extra-args="$A" -print 2>&1; echo "rc=$?"; '
        'echo "==own=="; frama-c -no-unicode own.c -cpp-extra-args="$A" -print 2>&1; echo "rc=$?"; '
        'echo "==off=="; FRAMAC_CPP_REWRITE=off frama-c -no-unicode grp_only.c -cpp-extra-args="$A" 2>&1; '
        'echo "rc=$?"; echo "==end=="'
    )
    files = {
        "gaps.c": GAPS_C, "layout.c": LAYOUT_GCC_C, "types.c": TYPES_GCC_C, "ours.h": _types_header(),
        "own.c": OWN_NAMES_C, "grp_only.c": GRP_ONLY_C,
    }  # fmt: skip
    log = _run_in_image(tmp_path, files, script, timeout=600)
    # fc_libc keeps the libc's guards: a renamed guard would read the libc header a second time.
    assert _section(log, "guards").split() == ["1", "1"], log
    assert "types=0" in _section(log, "types"), log
    assert "layout=0" in _section(log, "layout"), log
    parse = _section(log, "parse")
    assert "rc=0" in parse, parse
    for stop in ("Cannot", "syntax error", "Unsupported attribute", "static assertion failed", "undeclared"):
        assert stop not in parse, parse
    line = GAPS_C.splitlines().index("#pragma pvs(disable: 575, 618)") + 1
    assert f"[fc-cpp] /w/gaps.c:{line}: unknown pragma rewritten: #pragma pvs(disable: 575, 618)" in parse, parse
    assert "pvs" not in parse.split("/* Generated by Frama-C */", 1)[1], parse
    own = _section(log, "own")
    assert "rc=0" in own, own
    assert "__fc_grp" not in own and "__fc_getx" not in own and "__fc_utmp" not in own, own
    # Without the wrapper's include directory, __fc_libc's <grp.h> is read: the gap comes back.
    off = _section(log, "off")
    assert "Cannot find field gr_passwd in type struct group" in off, off


@pytest.mark.integration
@pytest.mark.slow
def test_the_eacsl_frontend_builds_and_runs_with_link_h_and_glibc_s_names(tmp_path):
    require_docker_images(ANALYSIS_IMAGE)
    script = (
        _EACSL_F + 'echo "==eacsl=="; '
        'e-acsl-gcc -c -F -e-acsl-full-mtracking -E "$F" -o e.frama.c -O bin e.c > build.log 2>&1; '
        'echo "build=$?"; ./bin.e-acsl 2>&1; echo "run=$?"; echo "==end=="'
    )
    log = _run_in_image(tmp_path, {"e.c": EACSL_C}, script, timeout=900)
    eacsl = _section(log, "eacsl")
    assert "build=0" in eacsl, (tmp_path / "build.log").read_text(encoding="utf-8", errors="replace")
    assert "objects=1 passwd=x pid=3 nproc=0" in eacsl and "run=0" in eacsl, eacsl
