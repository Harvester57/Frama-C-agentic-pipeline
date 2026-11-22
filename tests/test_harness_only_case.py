"""Runtime single-case filtering via FRAMAC_FUZZ_ONLY_CASE in templates/harness_dual.c.template."""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

import generate_harness as G
import run_eacsl_fuzz as R

pytestmark = pytest.mark.unit

_REPO = Path(__file__).resolve().parents[1]
_TEMPLATE = _REPO / "templates" / "harness_dual.c.template"
_NUM_CASES = 8


def _generate_dispatch_harness(tmp_path: Path, n_cases: int = _NUM_CASES) -> Path:
    src = tmp_path / "mod.c"
    src.write_text("int hit_case(unsigned int c) { return (int)c; }\n", encoding="utf-8")
    (tmp_path / "mod.h").write_text("int hit_case(unsigned int c);\n", encoding="utf-8")
    res = G.generate_module_harness(
        module_name="mod",
        sources=[str(src)],
        header_include="mod.h",
        entry_fn="hit_case",
        max_input_size=64,
        cppflags=f"-I{tmp_path.as_posix()}",
        out_dir=tmp_path / "harnesses",
        entry_style="dispatch",
        dispatch_cases=[f"(void)hit_case({i}U);" for i in range(n_cases)],
        auto_prelude=False,
    )
    return Path(res["harness_file"])


def test_template_preserves_runtime_skip_markers_and_eva_guard() -> None:
    text = _TEMPLATE.read_text(encoding="utf-8")

    # Preserve existing runtime skip markers and macros expected by existing callers/tests.
    assert "/* runtime dispatch case skip */" in text
    assert "#define FRAMAC_FUZZ_RUNTIME_SKIP_CASES 1" in text
    assert "#define framac_fuzz_skip_case framac_fuzz_skip_case" in text

    # The runtime skip/only-case helper must stay inside the non-Eva guard
    # (`!defined(__FRAMAC__) || defined(__FRAMAC_EACSL__)`), leaving Eva completely unaffected.
    skip_block_match = re.search(
        r"#if !defined\(__FRAMAC__\) \|\| defined\(__FRAMAC_EACSL__\)\n(.*?)\n#endif",
        text,
        re.DOTALL,
    )
    assert skip_block_match is not None
    skip_block = skip_block_match.group(1)

    assert 'getenv("FRAMAC_FUZZ_SKIP_CASES")' in skip_block
    assert 'getenv("FRAMAC_FUZZ_ONLY_CASE")' in skip_block
    assert "strtol(" in skip_block
    assert "framac_fuzz_rt_only_case" in skip_block
    assert "4096L" in skip_block

    # Ensure FRAMAC_FUZZ_ONLY_CASE does not appear in the Eva section.
    eva_section = text[text.index("int eva_main") : text.index("int LLVMFuzzerTestOneInput")]
    assert "FRAMAC_FUZZ_ONLY_CASE" not in eva_section
    assert "framac_fuzz_skip_case" not in eva_section


def test_generated_dispatch_harness_carries_only_case_filter(tmp_path: Path) -> None:
    harness_c = _generate_dispatch_harness(tmp_path)
    text = harness_c.read_text(encoding="utf-8")

    assert "#define FRAMAC_FUZZ_RUNTIME_SKIP_CASES 1" in text
    assert 'getenv("FRAMAC_FUZZ_ONLY_CASE")' in text
    assert "framac_fuzz_skip_case(" in text
    assert R.harness_supports_runtime_skip_cases(harness_c) is True


def _write_only_case_driver(tmp_path: Path) -> Path:
    driver = tmp_path / "driver.c"
    driver.write_text(
        '#include "harnesses/harness_mod.c"\n'
        "#include <stdio.h>\n"
        "static int last_hit = -1;\n"
        "int hit_case(unsigned int c) { last_hit = (int)c; return (int)c; }\n"
        "int main(void) {\n"
        '    printf("direct:%d,%d,%d,%d,%d\\n",\n'
        "           framac_fuzz_skip_case(0U),\n"
        "           framac_fuzz_skip_case(3U),\n"
        "           framac_fuzz_skip_case(4095U),\n"
        "           framac_fuzz_skip_case(4096U),\n"
        "           framac_fuzz_skip_case(5000U));\n"
        f"    for (unsigned int c = 0U; c < {_NUM_CASES + 2}U; c++) {{\n"
        "        uint8_t in[2] = {(uint8_t)c, 0x42U};\n"
        "        last_hit = -1;\n"
        "        int rc = LLVMFuzzerTestOneInput(in, 2U);\n"
        '        printf("case:%u:%d:%d\\n", c, rc, last_hit);\n'
        "    }\n"
        "    return 0;\n"
        "}\n",
        encoding="utf-8",
    )
    return driver


def _run_driver_scenarios(
    tmp_path: Path,
    driver: Path,
    scenarios: list[tuple[str, dict[str, str]]],
) -> dict[str, list[str]]:
    """Compile and run `driver` for every env scenario using host clang/gcc or Docker ANALYSIS_IMAGE."""
    cc = shutil.which("clang") or shutil.which("gcc")
    outputs: dict[str, list[str]] = {}

    if cc:
        exe = tmp_path / "only_case_driver.exe"
        proc = subprocess.run(
            [cc, "-Wall", "-Wextra", "-Werror", f"-I{tmp_path.as_posix()}", str(driver), "-o", str(exe)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        assert proc.returncode == 0, proc.stderr

        # Verify Eva preprocessor guard: under -D__FRAMAC__ (without __FRAMAC_EACSL__), the helper is absent.
        pp = subprocess.run(
            [cc, "-E", "-D__FRAMAC__", f"-I{tmp_path.as_posix()}", str(tmp_path / "harnesses" / "harness_mod.c")],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        assert "FRAMAC_FUZZ_ONLY_CASE" not in pp.stdout

        for label, extra_env in scenarios:
            env = dict(os.environ)
            env.pop("FRAMAC_FUZZ_ONLY_CASE", None)
            env.pop("FRAMAC_FUZZ_SKIP_CASES", None)
            env.update(extra_env)
            run_proc = subprocess.run(
                [str(exe)],
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=True,
            )
            outputs[label] = [
                ln.strip() for ln in run_proc.stdout.splitlines() if ln.strip().startswith(("direct:", "case:"))
            ]
        return outputs

    from conftest import ANALYSIS_IMAGE, require_docker_images

    require_docker_images(ANALYSIS_IMAGE)  # skips without FRAMAC_DOCKER_TESTS=1
    commands = [
        "set -e",
        "cd /tmp",
        "clang -Wall -Wextra -Werror -I/fixture /fixture/driver.c -o drv",
        "if clang -E -D__FRAMAC__ -I/fixture /fixture/harnesses/harness_mod.c 2>/dev/null"
        " | grep -q FRAMAC_FUZZ_ONLY_CASE; then echo EVA_LEAK; exit 1; fi",
    ]
    for label, extra_env in scenarios:
        env_prefix = " ".join(f"{k}={shlex.quote(v)}" for k, v in extra_env.items())
        prefix = f"env -u FRAMAC_FUZZ_ONLY_CASE -u FRAMAC_FUZZ_SKIP_CASES {env_prefix}".strip()
        commands.append(f"echo SCENARIO:{shlex.quote(label)}")
        commands.append(f"{prefix} timeout 60 ./drv")

    script = "\n".join(commands)
    argv = ["docker", "run", "--rm", "--network", "none", "-v", f"{tmp_path}:/fixture:ro", ANALYSIS_IMAGE, script]
    proc = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
    assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-2000:]

    current: str | None = None
    for raw in proc.stdout.splitlines():
        ln = raw.strip()
        if ln.startswith("SCENARIO:"):
            current = ln.split(":", 1)[1]
            outputs[current] = []
        elif current is not None and ln.startswith(("direct:", "case:")):
            outputs[current].append(ln)
    return outputs


def _parse_case_lines(lines: list[str]) -> tuple[str, dict[int, tuple[int, int]]]:
    assert len(lines) == _NUM_CASES + 3, lines
    direct = lines[0]
    cases: dict[int, tuple[int, int]] = {}
    for ln in lines[1:]:
        _, c_s, rc_s, hit_s = ln.split(":")
        cases[int(c_s)] = (int(rc_s), int(hit_s))
    return direct, cases


def test_only_case_c_execution(tmp_path: Path) -> None:
    """
    Compiled and run (host clang/gcc, else ANALYSIS_IMAGE under FRAMAC_DOCKER_TESTS=1):
    - FRAMAC_FUZZ_ONLY_CASE=3 runs only case 3 and rejects every other selector (-1).
    - Unset FRAMAC_FUZZ_ONLY_CASE runs all valid cases normally.
    - Empty/invalid/out-of-range values leave all valid cases active.
    - Combining FRAMAC_FUZZ_ONLY_CASE=3 with FRAMAC_FUZZ_SKIP_CASES=3 skips case 3 too.
    """
    _generate_dispatch_harness(tmp_path, _NUM_CASES)
    driver = _write_only_case_driver(tmp_path)

    scenarios: list[tuple[str, dict[str, str]]] = [
        ("unset", {}),
        ("only_3", {"FRAMAC_FUZZ_ONLY_CASE": "3"}),
        ("only_0", {"FRAMAC_FUZZ_ONLY_CASE": "0"}),
        ("only_4095", {"FRAMAC_FUZZ_ONLY_CASE": "4095"}),
        ("invalid_empty", {"FRAMAC_FUZZ_ONLY_CASE": ""}),
        ("invalid_alpha", {"FRAMAC_FUZZ_ONLY_CASE": "abc"}),
        ("invalid_trailing", {"FRAMAC_FUZZ_ONLY_CASE": "3abc"}),
        ("invalid_neg", {"FRAMAC_FUZZ_ONLY_CASE": "-1"}),
        ("invalid_neg_zero", {"FRAMAC_FUZZ_ONLY_CASE": "-0"}),
        ("invalid_4096", {"FRAMAC_FUZZ_ONLY_CASE": "4096"}),
        ("invalid_9999", {"FRAMAC_FUZZ_ONLY_CASE": "9999"}),
        ("invalid_overflow", {"FRAMAC_FUZZ_ONLY_CASE": "99999999999999999999999999"}),
        ("only_3_skip_3", {"FRAMAC_FUZZ_ONLY_CASE": "3", "FRAMAC_FUZZ_SKIP_CASES": "3"}),
        ("only_3_skip_other", {"FRAMAC_FUZZ_ONLY_CASE": "3", "FRAMAC_FUZZ_SKIP_CASES": "1,2"}),
    ]
    results = _run_driver_scenarios(tmp_path, driver, scenarios)

    # 1. Unset and all invalid values leave filtering inactive: cases 0..7 run, 8..9 reject.
    for label in (
        "unset",
        "invalid_empty",
        "invalid_alpha",
        "invalid_trailing",
        "invalid_neg",
        "invalid_neg_zero",
        "invalid_4096",
        "invalid_9999",
        "invalid_overflow",
    ):
        direct, cases = _parse_case_lines(results[label])
        assert direct == "direct:0,0,0,0,0", label
        for c in range(_NUM_CASES):
            assert cases[c] == (0, c), (label, c, cases[c])
        for c in range(_NUM_CASES, _NUM_CASES + 2):
            assert cases[c] == (-1, -1), (label, c, cases[c])

    # 2. FRAMAC_FUZZ_ONLY_CASE=3 runs ONLY case 3 and skips everything else (including >= 4096).
    direct, cases = _parse_case_lines(results["only_3"])
    assert direct == "direct:1,0,1,1,1"
    for c in range(_NUM_CASES + 2):
        expected = (0, 3) if c == 3 else (-1, -1)
        assert cases[c] == expected, (c, cases[c])

    # 3. FRAMAC_FUZZ_ONLY_CASE=0 boundary runs ONLY case 0.
    direct, cases = _parse_case_lines(results["only_0"])
    assert direct == "direct:0,1,1,1,1"
    for c in range(_NUM_CASES + 2):
        expected = (0, 0) if c == 0 else (-1, -1)
        assert cases[c] == expected, (c, cases[c])

    # 4. FRAMAC_FUZZ_ONLY_CASE=4095 upper boundary allows only 4095.
    direct, cases = _parse_case_lines(results["only_4095"])
    assert direct == "direct:1,1,0,1,1"
    for c in range(_NUM_CASES + 2):
        assert cases[c] == (-1, -1), (c, cases[c])

    # 5. FRAMAC_FUZZ_ONLY_CASE=3 + FRAMAC_FUZZ_SKIP_CASES=3 skips case 3 as well.
    direct, cases = _parse_case_lines(results["only_3_skip_3"])
    assert direct == "direct:1,1,1,1,1"
    for c in range(_NUM_CASES + 2):
        assert cases[c] == (-1, -1), (c, cases[c])

    # 6. FRAMAC_FUZZ_ONLY_CASE=3 + FRAMAC_FUZZ_SKIP_CASES=1,2 still runs case 3 only.
    direct, cases = _parse_case_lines(results["only_3_skip_other"])
    assert direct == "direct:1,0,1,1,1"
    for c in range(_NUM_CASES + 2):
        expected = (0, 3) if c == 3 else (-1, -1)
        assert cases[c] == expected, (c, cases[c])
