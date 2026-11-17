"""
E-ACSL --validate-format-strings and promoted arguments (c-ares run-1, 2026-11-16).

c-ares `inet_ntop4` formats `const unsigned char` bytes with "%u". Each byte is promoted to `int`, and
the E-ACSL runtime (share/e-acsl/libc_replacements/e_acsl_stdio.c, validate_format_type) compares the
directive's type with the argument's static type exactly, so every IPv4 address aborted the campaign:

    snprintf: directive 1 ('%u') expects argument of type 'unsigned int' but the corresponding argument has type 'int'

C11 7.16.1.1p2 (va_arg) accepts the signed and unsigned types of one rank when the value is
representable in both. The pipeline builds the runtime from a patched copy of the share directory
that applies this rule with the argument's value; a negative `int` for "%u" still aborts. The same
copy reads a floating-point argument with its own type when it collects the arguments, so a "%s" after
a "%f" no longer gets the wrong slot ("attempt to access unallocated memory via directive 2").
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

import eacsl_toolchain as T
import fuzz_build
import ledger
import run_eacsl_fuzz as R

WT_ROOT = Path(__file__).resolve().parent.parent

# Verbatim lines of Frama-C 34.0~beta's e_acsl_stdio.c around the three patch anchors.
STDIO_EXCERPT = """\
static void validate_format_type(abbrev_t expected_t, const char *fmtdesc,
                                 format_directive *dir, const char *func) {
  abbrev_t actual_t = fmtdesc[dir->arg.index];
  if (actual_t != expected_t) {
  }
}

/** \\brief Main format validation function that parses the format string and
   validates each format directive against the provided format description.
   If any of the requirements are violated the the program is aborted. */
static void validate_format(const char *fmtdesc, const char *fmt, va_list ap,
                            const char *func, char *buffer, size_t buf_size) {
  /* Track addresses of variadic arguments */
  int arglen = strlen(fmtdesc); /* number of variadic arguments */
  void *args[arglen];
  int i;
  for (int i = 0; i < arglen; i++)
    args[i] = va_arg(ap, void *);
  va_end(ap);

/* Shortcut for `validate_format_type` function */
#  define validate_type(_t) validate_format_type(_t, fmtdesc, dir, func)
}
"""


def _fake_share(root: Path, stdio: str = STDIO_EXCERPT) -> Path:
    share = root / "share" / "frama-c" / "share" / "e-acsl"
    (share / "libc_replacements").mkdir(parents=True)
    (share / "libc_replacements" / "e_acsl_stdio.c").write_text(stdio, encoding="utf-8", newline="\n")
    (share / "e_acsl_rtl.c").write_text('#include "libc_replacements/e_acsl_stdio.c"\n', encoding="utf-8")
    (share / "e_acsl.h").write_text("/* header */\n", encoding="utf-8")
    return share


def test_patch_applies_the_value_rule_at_every_anchor():
    patched, missing = T.patch_format_runtime(STDIO_EXCERPT)
    assert missing == []
    assert patched != STDIO_EXCERPT
    # The values are read per fmtdesc with their own promoted types (a double travels apart).
    assert "va_copy(" in patched and "va_arg(fc_ap, double)" in patched
    assert "static int fc_signedness_only(" in patched
    assert patched.index("static int fc_signedness_only(") < patched.index("static void validate_format(")
    assert "fc_signedness_only((_t), fmtdesc[dir->arg.index], fc_both, dir->arg.index)" in patched
    # The pointer arguments are collected past a double with the double's own type.
    assert patched.count("args[i] = va_arg(ap, void *);") == 1
    assert "    } else\n      args[i] = va_arg(ap, void *);" in patched
    assert "(void)va_arg(ap, double);" in patched and "(void)va_arg(ap, long double);" in patched
    # The exact comparison stays for every other pair; the abort text is unchanged.
    assert "if (actual_t != expected_t) {" in patched
    assert T.patch_format_runtime(patched)[1] != []  # anchors consumed: never applied twice


def test_patched_share_is_a_run_local_copy_and_the_image_is_untouched(tmp_path):
    src = _fake_share(tmp_path / "image")
    before = (src / "libc_replacements" / "e_acsl_stdio.c").read_bytes()
    res = T.prepare_patched_eacsl_share(src, tmp_path / "harnesses" / "eacsl_share")
    assert res["status"] == "applied", res
    assert res["patch"] == T.EACSL_FORMAT_RUNTIME_PATCH
    share = Path(res["share"])
    # Stack frames in the copy still read as E-ACSL runtime frames.
    assert share.name == "e-acsl" and R.is_runtime_function("validate_format_type", f"{share}/x.c")
    assert (share / "e_acsl_rtl.c").is_file() and (share / "e_acsl.h").is_file()
    assert "fc_signedness_only" in (share / "libc_replacements" / "e_acsl_stdio.c").read_text(encoding="utf-8")
    assert (src / "libc_replacements" / "e_acsl_stdio.c").read_bytes() == before
    # Parallel module builds share one copy: a second call reuses it.
    again = T.prepare_patched_eacsl_share(src, tmp_path / "harnesses" / "eacsl_share")
    assert again == res
    assert [p.name for p in (tmp_path / "harnesses" / "eacsl_share").iterdir()] == [share.parent.name]


def test_missing_anchor_builds_with_the_unpatched_runtime_and_says_so(tmp_path):
    src = _fake_share(tmp_path / "image", STDIO_EXCERPT.replace("#  define validate_type", "#define validate_type"))
    res = T.prepare_patched_eacsl_share(src, tmp_path / "eacsl_share")
    assert res["status"] == "not_applied" and "validate_type" in res["reason"]
    assert not (tmp_path / "eacsl_share").exists() or not any((tmp_path / "eacsl_share").iterdir())
    assert T.prepare_patched_eacsl_share(tmp_path / "nowhere", tmp_path / "eacsl_share")["status"] == "not_applied"


def test_share_dir_is_found_beside_e_acsl_gcc(tmp_path):
    share = _fake_share(tmp_path / "opam")
    gcc = tmp_path / "opam" / "bin" / "e-acsl-gcc"
    gcc.parent.mkdir(parents=True)
    gcc.write_text("#!/bin/sh\n", encoding="utf-8")
    assert T.eacsl_share_dir(str(gcc)) == share
    assert T.eacsl_share_dir(str(tmp_path / "elsewhere" / "e-acsl-gcc")) is None


class _StageRecorder:
    """Records e-acsl-gcc calls; stage 1 writes the instrumented file, stage 2 the binaries."""

    def __init__(self):
        self.calls: list[list[str]] = []

    def __call__(self, cmd, **kwargs):
        self.calls.append(list(cmd))
        if cmd[0] == "clang" and "-c" in cmd:
            Path(cmd[cmd.index("-o") + 1]).write_bytes(b"obj")
        elif "-C" in cmd:
            out = Path(cmd[cmd.index("-O") + 1])
            out.write_bytes(b"plain")
            out.with_name(out.name + ".e-acsl").write_bytes(b"\x7fELF __e_acsl_assert")
        else:
            Path(cmd[cmd.index("-o") + 1]).write_text("int f(void) { return 0; }\n", encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")


@pytest.fixture
def modern_gcc_with_share(tmp_path, monkeypatch):
    share = _fake_share(tmp_path / "image")
    monkeypatch.setattr(fuzz_build, "_resolve_eacsl_gcc", lambda: ("e-acsl-gcc", True))
    monkeypatch.setattr(T.shutil, "which", lambda name: None)
    monkeypatch.setattr(fuzz_build, "eacsl_share_dir", lambda eacsl_bin: share)
    src = tmp_path / "mod.c"
    src.write_text("int entry(int x) { return x; }\n", encoding="utf-8")
    return src


def test_stage2_builds_the_runtime_from_the_patched_share(tmp_path, modern_gcc_with_share):
    fake = _StageRecorder()
    res = R.compile_eacsl_binary([str(modern_gcc_with_share)], tmp_path / "out" / "fuzz_mod", runner=fake)
    assert res["returncode"] == 0, res
    stage1, stage2 = [c for c in fake.calls if c[0] == "e-acsl-gcc"]
    patch = res["runtime_patches"]["format_runtime"]
    assert patch["status"] == "applied" and Path(patch["share"]).parent.parent == tmp_path / "out" / "eacsl_share"
    # Stage 2 compiles e_acsl_rtl.c from the copy; stage 1 never reads the runtime's C sources.
    assert stage2[stage2.index("--e-acsl-share") + 1] == patch["share"]
    assert stage2.index("--e-acsl-share") < stage2.index("-G")
    assert "--e-acsl-share" not in stage1
    assert "format_runtime" in Path(res["compile_log"]).read_text(encoding="utf-8")


def test_patched_runtime_that_does_not_compile_falls_back_to_the_image_runtime(tmp_path, modern_gcc_with_share):
    class PatchedRuntimeBreaks(_StageRecorder):
        def __call__(self, cmd, **kwargs):
            if "-C" in cmd and "--e-acsl-share" in cmd:
                self.calls.append(list(cmd))
                share = cmd[cmd.index("--e-acsl-share") + 1]
                err = f"{share}/libc_replacements/e_acsl_stdio.c:812:5: error: use of undeclared identifier 'fc_both'\n"
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr=err)
            return super().__call__(cmd, **kwargs)

    fake = PatchedRuntimeBreaks()
    res = R.compile_eacsl_binary([str(modern_gcc_with_share)], tmp_path / "out" / "fuzz_mod", runner=fake)
    assert res["returncode"] == 0, res
    stage2 = [c for c in fake.calls if c[0] == "e-acsl-gcc" and "-C" in c]
    assert len(stage2) == 2 and "--e-acsl-share" in stage2[0] and "--e-acsl-share" not in stage2[1]
    patch = res["runtime_patches"]["format_runtime"]
    assert patch["status"] == "not_applied" and "did not compile" in patch["reason"]


def test_no_format_checks_means_no_patched_share(tmp_path, modern_gcc_with_share):
    fake = _StageRecorder()
    res = R.compile_eacsl_binary(
        [str(modern_gcc_with_share)], tmp_path / "out" / "fuzz_mod", runner=fake, libc_checks=False
    )
    assert res["returncode"] == 0, res
    assert all("--e-acsl-share" not in c for c in fake.calls)
    assert "runtime_patches" not in res


def test_runtime_patch_is_part_of_the_build_cache_key(tmp_path, modern_gcc_with_share):
    def material(libc_checks: bool):
        return R._eacsl_cache_material(
            [str(modern_gcc_with_share)],
            tmp_path / "fuzz_mod",
            "gcc_x86_64",
            "-I.",
            "all",
            True,
            None,
            "",
            True,
            False,
            True,
            libc_checks=libc_checks,
        )

    with_checks = material(True)
    assert with_checks is not None and with_checks["runtime_patches"] == [T.EACSL_FORMAT_RUNTIME_PATCH]
    without = material(False)
    assert without is not None and without["runtime_patches"] == []


@pytest.mark.parametrize(
    ("expected", "actual", "signedness_only"),
    [
        ("unsigned int", "int", True),
        ("int", "unsigned int", True),
        ("unsigned long", "long", True),
        ("long long", "unsigned long long", True),
        ("long", "int", False),
        ("char*", "long", False),
        ("double", "int", False),
    ],
)
def test_signedness_only_mismatch_is_marked_but_stays_a_candidate(expected, actual, signedness_only):
    line = (
        f"snprintf: directive 1 ('%u') expects argument of type '{expected}' "
        f"but the corresponding argument has type '{actual}'"
    )
    f = R.parse_eacsl_failure(f"{line}\nAborted\n")
    assert f is not None and f["kind"] == "eacsl_format_error"
    assert (f.get("format_mismatch") == "signedness") is signedness_only
    # Same predicate and fingerprint as before: the flag informs the verifier, it dismisses nothing.
    assert f["predicate"] == (
        f"snprintf: directive expects argument of type '{expected}' but the corresponding argument has type '{actual}'"
    )
    assert ledger.make_fingerprint(f["file"], f["function"], f["alarm_kind"] or f["kind"], f["predicate"])


FORMAT_PROBE_C = r"""
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

static const char fmt4[] = "%u.%u.%u.%u";

static int probe(int c)
{
    char t[128];
    unsigned char uc = 200;
    const unsigned char src[4] = {192, 168, 1, 200};
    unsigned int big = 3000000000u;
    int neg = -1;
    switch (c) {
    /* Accepted by C11 6.5.2.2p6 / 7.16.1.1p2: a value representable in both types. */
    case 0: return snprintf(t, sizeof t, "%u", uc);
    case 1: return snprintf(t, sizeof t, "%x", uc);
    case 2: return snprintf(t, sizeof t, "%u", 7);
    case 3: return snprintf(t, sizeof t, "%d", 5u);
    case 4: return snprintf(t, sizeof t, fmt4, src[0], src[1], src[2], src[3]);
    case 5: return snprintf(t, sizeof t, "%f %u", 1.5, uc);
    case 6: return snprintf(t, sizeof t, "%u %u %u %u %u %u %u %u", uc, uc, uc, uc, uc, uc, uc, uc);
    case 7: return snprintf(t, sizeof t, "%lu", 9L);
    case 13: return snprintf(t, sizeof t, "%f %s", 1.5, "abc");
    case 14: return snprintf(t, sizeof t, "%Lf %s %p", 2.5L, "abc", (void *)&uc);
    /* Not representable in the directive's type, or not the same rank: still aborts. */
    case 8: return snprintf(t, sizeof t, "%u", neg);
    case 9: return snprintf(t, sizeof t, "%f %u", 1.5, neg);
    case 10: return snprintf(t, sizeof t, "%d", big);
    case 11: return snprintf(t, sizeof t, "%ld", 7);
    case 12: return snprintf(t, sizeof t, "%u %u %u %u %u %u %u %u", uc, uc, uc, uc, uc, uc, uc, neg);
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1)
        return 0;
    return probe(data[0] % 15) == 12345;
}
"""

FORMAT_PROBE_SCRIPT = r"""set -e
cp -r /fixture /tmp/w && cd /tmp/w
python3 - <<'EOF'
import json, sys
from pathlib import Path
sys.path.insert(0, "/repo/scripts")
import fuzz_build
import run_eacsl_fuzz as R
keys = ("returncode", "reason", "binary", "check_options", "runtime_patches")
res = R.compile_eacsl_binary(["mod.c"], Path("out/fuzz_mod"), cppflags="-I.", use_cache=False)
print("RESULT " + json.dumps({k: res.get(k) for k in keys}))
# The same build with the image's runtime: the cases the patch lets through must abort there.
fuzz_build.eacsl_share_dir = lambda eacsl_bin: None
res = R.compile_eacsl_binary(["mod.c"], Path("plain/fuzz_mod"), cppflags="-I.", use_cache=False)
print("UNPATCHED " + json.dumps({k: res.get(k) for k in keys}))
EOF
set +e
for i in 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14; do
  printf "$(printf '\\%03o' "$i")" > "in$i"
  for b in out plain; do
    timeout 60 ./$b/fuzz_mod.e-acsl -runs=1 "in$i" > "$b$i.log" 2>&1
    echo "CASE $b $i rc=$? fmt=$(grep -c 'expects argument of type\|via directive' "$b$i.log")"
  done
done
for i in 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14; do echo "PLAIN $i $(grep -m1 '^[a-z]*printf: ' "plain$i.log")"; done
"""


@pytest.mark.integration
def test_promoted_arguments_pass_and_out_of_range_values_abort_in_the_analysis_image(tmp_path):
    from conftest import ANALYSIS_IMAGE, require_docker_images

    require_docker_images(ANALYSIS_IMAGE)
    (tmp_path / "mod.c").write_text(FORMAT_PROBE_C, encoding="utf-8")
    argv = ["docker", "run", "--rm", "--network", "none", "-v", f"{tmp_path}:/fixture:ro"]
    argv += ["-v", f"{WT_ROOT}:/repo:ro", ANALYSIS_IMAGE, FORMAT_PROBE_SCRIPT]
    proc = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900)
    out = proc.stdout + proc.stderr
    line = next((ln for ln in proc.stdout.splitlines() if ln.startswith("RESULT ")), None)
    assert line, out[-4000:]
    res = json.loads(line[len("RESULT ") :])
    assert res["returncode"] == 0, out[-4000:]
    assert "--validate-format-strings" in res["check_options"]
    assert res["runtime_patches"]["format_runtime"]["status"] == "applied", out[-4000:]
    plain = next((ln for ln in proc.stdout.splitlines() if ln.startswith("UNPATCHED ")), None)
    assert plain and json.loads(plain[len("UNPATCHED ") :])["runtime_patches"]["format_runtime"]["status"] == (
        "not_applied"
    ), out[-4000:]
    cases = {(b, i): v for b, i, v in re.findall(r"^CASE (\w+) (\d+) (rc=\d+ fmt=\d+)$", proc.stdout, re.MULTILINE)}
    for i in map(str, [*range(8), 13, 14]):
        assert cases["out", i] == "rc=0 fmt=0", (i, out[-4000:])
        # The image's runtime stops on each of them: the false positives this patch removes.
        assert not cases["plain", i].startswith("rc=0 "), (i, out[-4000:])
    for i in map(str, range(8, 13)):
        for b in ("out", "plain"):
            assert not cases[b, i].startswith("rc=0 ") and cases[b, i].endswith("fmt=1"), (b, i, out[-4000:])
