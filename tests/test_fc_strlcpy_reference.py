"""
What backs the Eva / WP postconditions of templates/fc_stubs/fc_strlcpy.h.

Every caller's proof assumes those postconditions, and nothing else checks them: the E-ACSL branch of
the header has no `ensures`, and `stub_check.py shipped` compares prototypes and layouts only. Two legs:

- WP proves both contracts for the reference bodies of tests/fixtures/fc_strlcpy_reference/reference.c;
- differential.c runs those bodies against the C library's functions on every small length and size.

The proof admits three facts the contracts do not state; `STRL_ADMITTED` pins them, so a contract that
starts to claim more than it says shows up as a new admit or as an unproved goal.
"""

from __future__ import annotations

import re
import shutil

import pytest

from conftest import ANALYSIS_IMAGE, ROOT, require_docker_images, wp_proved_goals
from test_fc_stub_repairs import _branches, _contract_of, _docker, _per_main, _read

STRL_REFERENCE_DIR = ROOT / "tests" / "fixtures" / "fc_strlcpy_reference"

# function -> the facts its proof admits, in the order of reference.c.
STRL_ADMITTED = {
    "strlcpy": ["src_initialized"],
    "strlcat": ["src_initialized", "dst_initialized", "no_wrap"],
}

_STRL_GCC = "gcc -O1 -Wall -Wextra -Werror -U_FORTIFY_SOURCE"


def _postcondition_names(function: str) -> list[str]:
    _, eva = _branches(_read("fc_strlcpy.h"))
    return re.findall(r"\bensures\s+(\w+)\s*:", _contract_of(eva, function))


def test_reference_bodies_admit_only_the_recorded_facts():
    text = (STRL_REFERENCE_DIR / "reference.c").read_text(encoding="utf-8")
    cpy, cat = text.split("size_t strlcat(", 1)
    admitted = {name: re.findall(r"\badmit\s+(\w+)\s*:", body) for name, body in (("strlcpy", cpy), ("strlcat", cat))}
    assert admitted == STRL_ADMITTED
    # No other way to assume a fact, and no contract of its own: the declarations' contracts are proved.
    code = re.sub(r"/\*(?!@).*?\*/", "", text, flags=re.S)
    for word in ("axiom", "lemma", "requires", "ensures", "assumes"):
        assert not re.search(rf"\b{word}\b", code), word


def test_both_contracts_state_result_copied_bytes_initialization_and_nul():
    assert _postcondition_names("strlcpy") == ["result_is_src_length", "copied", "initialized", "nul_terminated"]
    assert _postcondition_names("strlcat") == ["result_is_total_length", "copied", "initialized", "nul_terminated"]


@pytest.mark.integration
@pytest.mark.slow
def test_reference_bodies_satisfy_the_contracts_and_match_the_c_library(tmp_path):
    require_docker_images(ANALYSIS_IMAGE)
    for name in ("reference.c", "differential.c"):
        shutil.copyfile(STRL_REFERENCE_DIR / name, tmp_path / name)
    script = (
        # The pipeline's WP checks (run_wp_function.py), every prover, no cache.
        'echo "@@MAIN wp"; timeout 900 frama-c -no-unicode reference.c -cpp-extra-args="$A" -wp -wp-rte '
        "-warn-unsigned-overflow -warn-unsigned-downcast -warn-invalid-pointer -wp-cache none "
        "-wp-prover alt-ergo,z3,cvc5 -wp-timeout 30 -wp-print 2>&1; "
        f'echo "@@MAIN diff"; {_STRL_GCC} -Dstrlcpy=ref_strlcpy -Dstrlcat=ref_strlcat -c reference.c -o ref.o 2>&1 '
        f"&& {_STRL_GCC} differential.c ref.o -o diff 2>&1 && ./diff; "
        # Control: strlcat compared with the reference strlcpy must be reported.
        f'echo "@@MAIN control"; {_STRL_GCC} -Dref_strlcat=ref_strlcpy differential.c ref.o -o control 2>&1 '
        "&& ./control | tail -1"
    )
    per = _per_main(_docker(ANALYSIS_IMAGE, tmp_path, script))
    wp = per["wp"]
    summary = "\n".join(line for line in wp.splitlines() if line.startswith(("[wp]", "[kernel]", "  ")))
    # The stub's contract alone: fc_compat_types.h renames the libc declarations.
    assert "found two contracts" not in wp, summary
    assert all(proved == total for proved, total in wp_proved_goals(wp)), summary
    for function in STRL_ADMITTED:
        for name in _postcondition_names(function):
            assert f"Goal Post-condition '{name}' in '{function}':" in wp, (function, name, summary)
    diff = re.search(r"DIFF_OK (\d+) cases, 0 mismatches", per["diff"])
    assert diff and int(diff.group(1)) >= 1000, per["diff"]
    assert "DIFF_BAD" in per["control"], per["control"]
