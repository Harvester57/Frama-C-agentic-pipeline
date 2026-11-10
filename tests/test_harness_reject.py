"""
H3 of docs/templates-and-stubs-improvement-plan.md: an input that reaches no target code makes
LLVMFuzzerTestOneInput return -1, so libFuzzer keeps the corpus to inputs that reach the target.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import generate_harness as gh

REPO = Path(__file__).resolve().parents[1]
TEMPLATE = REPO / "templates" / "harness_dual.c.template"


def _render(invocation: str, max_size: int = 16) -> str:
    text = TEMPLATE.read_text(encoding="utf-8")
    for key, value in {
        "MODULE_NAME": "rej",
        "MODULE_HEADER": "rej.h",
        "MAX_INPUT_SIZE": str(max_size),
        "TARGET_INVOCATION_EVA": invocation,
        "TARGET_INVOCATION_FUZZ": invocation,
    }.items():
        text = text.replace("{{" + key + "}}", value)
    return text


@pytest.mark.unit
def test_dispatch_rejects_an_input_without_selector_and_a_skipped_case():
    inv = gh._build_dispatch_invocation(["(void)f0(fuzz_len);", "(void)f1(fuzz_len);"])
    lines = [ln.strip() for ln in inv.splitlines()]
    assert lines[-1] == "} else { FRAMAC_FUZZ_REJECT(); }"
    # The skipped-case `else` belongs to the mask test, so it sits under the same #ifdef.
    i = lines.index("else { FRAMAC_FUZZ_REJECT(); }")
    assert lines[i - 2] == "}" and lines[i - 1] == f"#ifdef {gh.DISPATCH_SKIP_MACRO}" and lines[i + 1] == "#endif"


@pytest.mark.unit
def test_template_returns_minus_one_for_oversized_and_rejected_inputs():
    text = _render("FRAMAC_FUZZ_REJECT();")
    fuzz = text[text.index("int LLVMFuzzerTestOneInput") :]
    assert "if (size > MAX_INPUT_SIZE) {\n        return -1;" in fuzz
    assert "return harness_reject ? -1 : 0;" in fuzz
    assert "#define FRAMAC_FUZZ_REJECT() ((void)(harness_reject = 1))" in fuzz
    # eva_main has its own, empty, definition, dropped after it.
    eva = text[text.index("int eva_main") : text.index("int LLVMFuzzerTestOneInput")]
    assert "#undef FRAMAC_FUZZ_REJECT" in eva
    assert "#define FRAMAC_FUZZ_REJECT() ((void)0)" in text[: text.index("int eva_main")]
    # seed_harvest.fuzz_invocation still finds the invocation block's end.
    assert fuzz.index("free(alloc_ptr);") < fuzz.index("return harness_reject")


REJECT_SCRIPT = r"""set -e
cp -r /fixture /tmp/w && cd /tmp/w
clang -fsanitize=fuzzer -g -DFRAMAC_FUZZ_SKIP_CASES=1ULL -I. harness.c rej.c -o fz
mkdir corpus
./fz -runs=30000 -seed=7 -max_len=64 corpus > fz.log 2>&1 || { tail -20 fz.log; exit 1; }
echo FUZZ_OK
for f in corpus/*; do od -An -tu1 -N1 "$f" | tr -d ' \n'; echo " $(wc -c < "$f")"; done > kept.txt
echo "KEPT $(wc -l < kept.txt)"
awk '$1 % 2 != 1 || $2 < 1 || $2 > 16 { bad++ } END { print "BAD " bad+0 }' kept.txt
frama-c -eva -main eva_main -cpp-extra-args=-I. harness.c rej.c > eva.log 2>&1 && echo EVA_OK || tail -20 eva.log
"""


@pytest.mark.integration
def test_libfuzzer_keeps_only_inputs_that_reach_a_case(tmp_path):
    from conftest import ANALYSIS_IMAGE, require_docker_images

    require_docker_images(ANALYSIS_IMAGE)
    inv = gh._build_dispatch_invocation(["f0(fuzz_buf, fuzz_len);", "f1(fuzz_buf, fuzz_len);"])
    (tmp_path / "harness.c").write_text(_render(inv), encoding="utf-8")
    (tmp_path / "rej.h").write_text(
        "#include <stddef.h>\n#include <stdint.h>\n"
        "int f0(const uint8_t *p, size_t n);\nint f1(const uint8_t *p, size_t n);\n",
        encoding="utf-8",
    )
    (tmp_path / "rej.c").write_text(
        '#include "rej.h"\n'
        "int f0(const uint8_t *p, size_t n) { return n > 0 ? p[0] : 0; }\n"
        "int f1(const uint8_t *p, size_t n) { int s = 0; for (size_t i = 0; i < n; i++) { s += p[i] == 'x'; }"
        " return s; }\n",
        encoding="utf-8",
    )
    argv = ["docker", "run", "--rm", "--network", "none", "-v", f"{tmp_path}:/fixture:ro", ANALYSIS_IMAGE]
    proc = subprocess.run(
        [*argv, REJECT_SCRIPT], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600
    )
    out = proc.stdout + proc.stderr
    assert "FUZZ_OK" in proc.stdout, out[-4000:]
    kept = next(ln for ln in proc.stdout.splitlines() if ln.startswith("KEPT "))
    assert int(kept.split()[1]) > 0, out[-4000:]
    # Case 0 is skipped: no kept input selects it, none is empty, none is longer than MAX_INPUT_SIZE.
    assert "BAD 0" in proc.stdout, out[-4000:]
    assert "EVA_OK" in proc.stdout, out[-4000:]
