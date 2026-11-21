"""
Build gaps sudo run-1 showed in Phase 0 build-check #4 (2026-11-21).

A. The Frama-C printer puts a goto label before `default:` (fmtsudoers.c: `FALLTHROUGH; default:
   print_word:` printed `__attribute__((__fallthrough__)); print_word: default:`): clang stops on
   "fallthrough annotation does not directly precede switch label" (eacsl_toolchain.rewrite_misplaced_fallthrough).
B. Link repair resolved `open_sudoers`, which four programs define and the archive libparsesudoers.a does
   not, by linking cvtsudoers.c: nine more rounds pulled in the whole program (fuzz_build.repair_sources_for_link).
C. Link repair added back a file the target fuzzer generator left out (sidecar
   `target_fuzzer.link.excluded_sources`): "global var audit_msg ... has different initializer".
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

import eacsl_toolchain as T
import run_eacsl_fuzz as R
from test_eacsl_toolchain import FakeEacslGcc, _src, modern_cli  # noqa: F401 - modern_cli is a fixture

SLP_REPO = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# A. A fallthrough attribute the printer leaves before `label: default:`
# ---------------------------------------------------------------------------

# As the E-ACSL frontend printed sudo's fmtsudoers.c (fuzz_libparsesudoers_a.instrumented.c:2911023; shortened).
SLP_PRINTED = """int sudoers_format_member_int(int type, int negated)
{
  switch (type) {
    case 1:
    {
      alias_put(a);
      break;
    }
     __attribute__((__fallthrough__));
    print_word: default:
    __e_acsl_store_block_duplicate((void *)(& tmp_0),8UL);
    ;
  }
  return 0;
}
"""


def test_a_fallthrough_before_a_goto_label_is_removed_and_its_semicolon_kept():
    new, info = T.rewrite_misplaced_fallthrough(SLP_PRINTED)
    assert info == {"rewrites": 1, "lines": [9]}
    lines = new.split("\n")
    assert lines[8] == "     ;"
    assert lines[9] == "    print_word: default:"
    assert new.count("\n") == SLP_PRINTED.count("\n")
    assert "fallthrough" not in new


@pytest.mark.parametrize(
    "text",
    [
        # Directly before a switch label (comments and annotations aside): what clang accepts.
        "switch (k) {\n  case 1: r = 1;\n  __attribute__((__fallthrough__));\n  case 2: r++;\n}\n",
        "switch (k) {\n  case 1: r = 1;\n  __attribute__((fallthrough));\n  default: r++;\n}\n",
        "switch (k) {\n  case 1: r = 1;\n  __attribute__((__fallthrough__));\n  /*@ assert r == 1; */\n  case 2: ;\n}\n",
        # No attribute at all, or in a string.
        "int f(void) { return 0; }\n",
        'char const *s = "x"; char const *t = "__attribute__((__fallthrough__));";\n',
    ],
)
def test_other_fallthrough_attributes_are_left_alone(text):
    assert T.rewrite_misplaced_fallthrough(text) == (text, {"rewrites": 0, "lines": []})


def test_a_labelled_fallthrough_at_the_end_of_a_block_keeps_its_statement():
    text = "switch (k) {\n  case 1:\n  {\n    if (v) goto out;\n    out: __attribute__((__fallthrough__));\n  }\n  default: ;\n}\n"
    new, info = T.rewrite_misplaced_fallthrough(text)
    assert info["rewrites"] == 1
    assert "    out: ;\n" in new


@pytest.mark.usefixtures("modern_cli")
def test_the_build_removes_the_misplaced_fallthrough_and_records_it(tmp_path):
    fake = FakeEacslGcc(instrumented_text=SLP_PRINTED)
    res = R.compile_eacsl_binary([str(_src(tmp_path))], tmp_path / "fuzz_mod", runner=fake, use_cache=False)
    assert res["returncode"] == 0, res
    assert res["misplaced_fallthrough"] == {"rewrites": 1, "lines": [9]}
    instrumented = Path(res["instrumented_source"]).read_text(encoding="utf-8")
    assert "fallthrough" not in instrumented
    log = Path(res["compile_log"]).read_text(encoding="utf-8")
    assert "Removed 1 __attribute__((__fallthrough__))" in log
    plain = R.compile_eacsl_binary([str(_src(tmp_path))], tmp_path / "plain", runner=FakeEacslGcc(), use_cache=False)
    assert "misplaced_fallthrough" not in plain


# End to end in the analysis image (FRAMAC_DOCKER_TESTS=1): fmtsudoers.c's shape.
SLP_FT_C = """#include <stddef.h>
#include <stdint.h>
#define FALLTHROUGH __attribute__((__fallthrough__))

static int pick(int k, int v)
{
    int r = 0;
    switch (k) {
    case 1:
        if (v > 3)
            goto print_word;
        r = 1;
        FALLTHROUGH;
    default:
    print_word:
        r += v;
        break;
    }
    return r;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2)
        return 0;
    return pick(data[0] % 3, data[1]) == 1000;
}
"""

SLP_FT_DRIVE_PY = """import json, shutil, sys
from pathlib import Path
sys.path.insert(0, "/repo/scripts")
import run_eacsl_fuzz as R
work = Path("/tmp/w")
shutil.copytree("/fixture", work)
res = R.compile_eacsl_binary([str(work / "ft.c")], work / "out" / "fuzz_mod", cppflags=f"-I{work}", use_cache=False)
keys = ("returncode", "reason", "binary", "misplaced_fallthrough")
print("SLP_RESULT " + json.dumps({k: res.get(k) for k in keys}))
"""


@pytest.mark.integration
def test_the_printed_fallthrough_builds_under_eacsl(tmp_path):
    from conftest import ANALYSIS_IMAGE, require_docker_images

    require_docker_images(ANALYSIS_IMAGE)
    for name, text in (("ft.c", SLP_FT_C), ("drive.py", SLP_FT_DRIVE_PY)):
        (tmp_path / name).write_text(text, encoding="utf-8", newline="\n")
    tag = os.environ.get("FRAMAC_RUN_TAG", "pytest-sudo-link-pick")
    name = f"framac-test-slp-{tmp_path.name}".lower()
    argv = ["docker", "run", "--rm", "--name", name, "--label", f"framac.run={tag}", "--network", "none"]
    argv += ["-v", f"{tmp_path}:/fixture:ro", "-v", f"{SLP_REPO}:/repo:ro", ANALYSIS_IMAGE]
    argv += ["timeout 900 python3 /fixture/drive.py"]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1200)
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
        raise
    out = proc.stdout + proc.stderr
    lines = [ln for ln in proc.stdout.splitlines() if ln.startswith("SLP_RESULT ")]
    assert lines, out[-4000:]
    res = json.loads(lines[-1].split(" ", 1)[1])
    assert res["returncode"] == 0, out[-4000:]
    assert res["binary"].endswith(".e-acsl")
    assert res["misplaced_fallthrough"]["rewrites"] == 1
