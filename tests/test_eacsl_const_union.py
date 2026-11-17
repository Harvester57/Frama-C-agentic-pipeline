"""O9: the E-ACSL-only rewrite of `static const union` declarations (scripts/fc_cpp_wrapper_eacsl.py)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

import fc_cpp_wrapper_eacsl as W
import generate_report
import phase0_gates
import pipeline_make as pm
import run_eacsl_fuzz as R
import validate_artifacts
from test_eacsl_toolchain import FakeEacslGcc, _src, modern_cli  # noqa: F401 - modern_cli is a fixture
from test_pipeline_make import ACSL, UNION_LOG, _failed_build, _make_run

CONST_UNION_REPO = Path(__file__).resolve().parent.parent

# Preprocessed text as gcc -E writes it: line markers, the union type, then the declarations.
CONST_UNION_PP = """# 1 "mod.c"
union u { unsigned char b[16]; unsigned long w[2]; };
struct s { unsigned char b[16]; };
static const union u file_zero;
static const union u file_init = { { 0 } };
const static union u reordered;
static const struct s const_struct;
static union u plain_union;
const union u not_static = { { 1 } };
static const union u *ptr_to_const;
static const union u returns_union(void);
/* static const union u in_a_comment; */
const char *text = "static const union u in_a_string;";
static const union { int a; } anonymous;
int f(void)
{
    static const union u local_zero;
    static const union u local_init = { { 0 } };
    return local_zero.b[0] + local_init.b[1];
}
"""


def _lines(text: str) -> list[str]:
    return text.split("\n")


def test_rewrite_drops_const_from_static_const_union_objects_only():
    new, notes = W.rewrite_const_union_text(CONST_UNION_PP)
    old_lines, new_lines = _lines(CONST_UNION_PP), _lines(new)
    assert len(new_lines) == len(old_lines)
    assert [len(a) for a in old_lines] == [len(b) for b in new_lines]  # blanks: lines and columns kept
    changed = {i + 1 for i, (a, b) in enumerate(zip(old_lines, new_lines, strict=True)) if a != b}
    # file scope (with and without initializer), `const static`, anonymous, local (with and without initializer)
    assert changed == {4, 5, 6, 14, 17, 18}
    for line in changed:
        assert "const" not in new_lines[line - 1].split("=")[0] and "union" in new_lines[line - 1]
    assert new_lines[3] == "static       union u file_zero;"
    assert new_lines[16] == "    static       union u local_zero;"
    assert len(notes) == 6 and {n["kind"] for n in notes} == {W.CONST_UNION_KIND}
    assert [n["line"] for n in notes] == [3, 4, 5, 13, 16, 17]  # from the `# 1 "mod.c"` marker
    assert {n["file"] for n in notes} == {"mod.c"}
    assert notes[0]["original"] == "static const union u file_zero"
    assert notes[0]["rewritten"] == "static union u file_zero"


def test_rewrite_leaves_structs_plain_unions_pointers_comments_and_strings_alone():
    new, _ = W.rewrite_const_union_text(CONST_UNION_PP)
    for kept in (
        "static const struct s const_struct;",
        "static union u plain_union;",
        "const union u not_static = { { 1 } };",
        "static const union u *ptr_to_const;",
        "static const union u returns_union(void);",
        "/* static const union u in_a_comment; */",
        'const char *text = "static const union u in_a_string;";',
    ):
        assert kept in new
    text = "static const struct s a;\nstatic union u b;\nunion u c;\n"
    assert W.rewrite_const_union_text(text) == (text, [])


def test_rewritten_file_is_reported_and_counted_once_per_declaration(tmp_path, capsys):
    pp = tmp_path / "mod.i"
    pp.write_text(CONST_UNION_PP, encoding="utf-8", newline="\n")
    assert len(W.rewrite_const_union_file(str(pp))) == 6
    assert "static const union u file_zero" not in pp.read_text(encoding="utf-8")
    err = capsys.readouterr().err
    assert err.count("[fc-cpp] mod.c:") == 6
    # A header two sources include is preprocessed twice: the same location counts once.
    assert W.count_const_union_rewrites(err + "\n" + err) == 6
    assert W.count_const_union_rewrites("[fc-cpp] a.c:3: offsetof with a non-constant index rewritten: x -> y") == 0


def _preprocess(tmp_path: Path, monkeypatch, const_unions: bool | None) -> tuple[int, str]:
    out = tmp_path / "out.i"

    def fake_cc1(cmd: list[str]) -> int:
        out.write_text(CONST_UNION_PP, encoding="utf-8", newline="\n")
        return 0

    monkeypatch.delenv(W.DISABLE_ENV, raising=False)
    rc = W.run_eacsl(["/usr/lib/gcc/cc1", "-E", "mod.c", "-o", str(out)], call=fake_cc1, const_unions=const_unions)
    return rc, out.read_text(encoding="utf-8")


def test_wrapper_rewrites_by_default_and_not_with_the_switch_off(tmp_path, monkeypatch):
    assert W.REWRITE_STATIC_CONST_UNIONS is True
    rc, text = _preprocess(tmp_path, monkeypatch, None)
    assert rc == 0 and "static const union u file_zero" not in text
    rc, text = _preprocess(tmp_path, monkeypatch, False)
    assert rc == 0 and text == CONST_UNION_PP
    monkeypatch.setattr(W, "REWRITE_STATIC_CONST_UNIONS", False)
    rc, text = _preprocess(tmp_path, monkeypatch, None)
    assert rc == 0 and text == CONST_UNION_PP
    assert not W.const_union_rewrite_active(f"-wrapper /s/{Path(W.__file__).name}")


def test_rewrite_is_active_only_through_the_eacsl_wrapper(monkeypatch):
    monkeypatch.delenv(W.DISABLE_ENV, raising=False)
    flags = f"-DE_ACSL -wrapper /opt/scripts/{Path(W.__file__).name} -I."
    assert W.const_union_rewrite_active(flags)
    assert not W.const_union_rewrite_active("-DE_ACSL -I.")  # no wrapper (a host without POSIX gcc)
    monkeypatch.setenv(W.DISABLE_ENV, "off")
    assert not W.const_union_rewrite_active(flags)


# ---------------------------------------------------------------------------
# build-check and the run report
# ---------------------------------------------------------------------------


def _mark_rewrite(run: Path, mod: str, on: bool) -> None:
    path = run / pm.BUILD_DIR / f"{mod}.build.json"
    report = json.loads(path.read_text(encoding="utf-8"))
    report["compile"]["const_union_rewrite"] = on
    path.write_text(json.dumps(report), encoding="utf-8")


def test_build_check_sends_a_missed_const_union_to_the_rewrite_not_to_the_sanitizers(tmp_path):
    run = _make_run(tmp_path)
    _failed_build(run, "log", UNION_LOG, fallback=False)
    _mark_rewrite(run, "log", True)
    out = pm.build_check(run, runner=lambda targets, run_dir: (0, {}), templates_dir=ACSL)
    row = out["modules"]["log"]
    assert (row["status"], row["reason_code"], row["ok"]) == ("build_failed", "eacsl_static_const_union", False)
    assert "next_step" not in row
    assert "fc_cpp_wrapper_eacsl.py" in row["reason"] and "extend the rewrite" in row["reason"]
    assert "sanitizers" not in row["reason"]
    assert not validate_artifacts.validate_build_check(out)
    # The gate stamp keeps the row; a refused fuzz-<mod> shows the first error, and no sanitizers command.
    gates = json.loads((run / "workspace/reports/phase0_gates.json").read_text(encoding="utf-8"))["build_check"]
    assert gates["modules"]["log"]["reason_code"] == "eacsl_static_const_union"
    assert "next_step" not in gates["modules"]["log"]
    assert not validate_artifacts.validate_phase0_gates(gates)
    (reason,) = phase0_gates.check(run, "log", ("build_check",))
    assert reason.startswith("build-check failed for log: build_failed (") and "implicit cast" in reason
    assert "sanitizers" not in reason

    # With the switch off, the module gets the sanitizers command as before.
    _mark_rewrite(run, "log", False)
    row = pm.build_check(run, runner=lambda targets, run_dir: (0, {}), templates_dir=ACSL)["modules"]["log"]
    assert row["next_step"] == pm.sanitizers_command("log") and "recorded choice" in row["reason"]


def _build_report(run: Path, mod: str, comp: dict) -> None:
    path = run / "workspace/build" / f"{mod}.build.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"mode": "build", "module": mod, "engine_used": comp["engine"], "compile": comp}))


CONST_UNION_NOTE = (
    "[fc-cpp] mod.c:{line}: static const union rewritten: static const union u z{line} -> static union u z{line}"
    " (E-ACSL only: E-ACSL no longer checks the object as read-only)\n"
)


class _ConstUnionEacslGcc(FakeEacslGcc):
    """Stage 1 reports `[fc-cpp]` rewrites on stderr, as the E-ACSL frontend's wrapper does."""

    def __init__(self, stage1_errs: list[str], **kwargs):
        super().__init__(**kwargs)
        self.stage1_errs = list(stage1_errs)

    def __call__(self, cmd, **kwargs):
        res = super().__call__(cmd, **kwargs)
        if cmd[0] != "clang" and "-n" in cmd:
            res.stderr = self.stage1_errs.pop(0) + (res.stderr or "")
        return res


@pytest.mark.usefixtures("modern_cli")
def test_the_build_counts_the_rewrites_of_its_last_frontend_run(tmp_path):
    # Two sources include the same header (`z3` twice): one declaration. The rte-select retry preprocesses
    # again: only the last run counts.
    first = CONST_UNION_NOTE.format(line=3) * 2 + CONST_UNION_NOTE.format(line=9)
    retry = CONST_UNION_NOTE.format(line=3) * 2 + CONST_UNION_NOTE.format(line=9) + CONST_UNION_NOTE.format(line=12)
    fake = _ConstUnionEacslGcc([first, retry], stage1_failures=["[kernel] User Error: no function 'ghost'\n"])
    res = R.compile_eacsl_binary(
        [str(_src(tmp_path))], tmp_path / "fuzz_mod", functions=["entry", "ghost"], runner=fake, use_cache=False
    )
    assert res["returncode"] == 0 and res["rte_select_dropped"] == ["ghost"]
    assert res["const_union_rewrites"] == 3
    assert isinstance(res["const_union_rewrite"], bool)  # False here: no POSIX gcc wrapper in unit tests
    log = Path(res["compile_log"]).read_text(encoding="utf-8")
    assert log.count("Dropped `const` from 3 `static const union` declaration(s)") == 1
    plain = R.compile_eacsl_binary([str(_src(tmp_path))], tmp_path / "plain", runner=FakeEacslGcc(), use_cache=False)
    assert "const_union_rewrites" not in plain


def test_run_report_names_the_modules_built_with_the_rewrite(tmp_path):
    assert generate_report.const_union_rewrite_lines(tmp_path) == []
    _build_report(tmp_path, "sm4", {"engine": "eacsl", "returncode": 0, "const_union_rewrites": 1})
    _build_report(tmp_path, "ccm", {"engine": "eacsl", "returncode": 0, "const_union_rewrites": 2})
    _build_report(tmp_path, "md5", {"engine": "eacsl", "returncode": 0, "const_union_rewrite": True})
    _build_report(tmp_path, "gcm", {"engine": "eacsl", "returncode": 1, "const_union_rewrites": 1})
    _build_report(tmp_path, "asan", {"engine": "sanitizers", "returncode": 0, "const_union_rewrites": 1})
    lines = generate_report.const_union_rewrite_lines(tmp_path)
    assert len([ln for ln in lines if ln]) == 1
    assert "2 module(s)" in lines[0] and lines[0].endswith("`ccm` (2), `sm4` (1).")
    meta: dict[str, Any] = {
        "run_id": "r1",
        "repo": "x",
        "target": "/target",
        "run_status": "complete",
        "incomplete_reason": None,
        "source_ref": {"vcs": "git", "commit": None},
        "profile": "standard",
        "scope_paths": [],
        "budget": None,
        "sandbox": {"outer": "docker", "inner": "none"},
        "prior_runs": [],
    }
    data = {"meta": meta, "ledger": [], "findings": [], "candidates": [], "run_dir": tmp_path}
    report = generate_report.render_report(data)
    assert lines[0] in report.splitlines()
    assert report.index(lines[0]) < report.index("## 6. Coverage gaps")


# ---------------------------------------------------------------------------
# End to end in the analysis image (FRAMAC_DOCKER_TESTS=1)
# ---------------------------------------------------------------------------

CONST_UNION_FUZZ_C = r"""#include <stddef.h>
#include <stdint.h>

union blk { uint8_t b[16]; uint64_t w[2]; };
struct pair { uint8_t b[16]; };

static const union blk file_zero;
static const struct pair const_pair;
static union blk scratch;

static uint8_t first_byte(void)
{
    static const union blk local_zero = { { 0 } };
    return local_zero.b[0];
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0)
        return 0;
    scratch.b[data[0] % 16] = data[0];
    return file_zero.b[data[0] % 16] + const_pair.b[0] + first_byte() + scratch.b[0] == 1000;
}
"""

# Two script trees: the repository's (rewrite on) and a copy with the switch turned off.
CONST_UNION_DOCKER_SCRIPT = r"""set -e
cp -r /fixture /tmp/w && cd /tmp/w
cp -r /repo/scripts /tmp/scripts_off
python3 - <<'EOF'
from pathlib import Path
p = Path("/tmp/scripts_off/fc_cpp_wrapper_eacsl.py")
text = p.read_text()
assert "REWRITE_STATIC_CONST_UNIONS = True" in text
p.write_text(text.replace("REWRITE_STATIC_CONST_UNIONS = True", "REWRITE_STATIC_CONST_UNIONS = False"))
EOF
for side in on off; do
  if [ "$side" = on ]; then scripts=/repo/scripts; else scripts=/tmp/scripts_off; fi
  SCRIPTS="$scripts" SIDE="$side" python3 - <<'EOF'
import json, os, sys
from pathlib import Path
sys.path.insert(0, os.environ["SCRIPTS"])
import run_eacsl_fuzz as R
side = os.environ["SIDE"]
res = R.compile_eacsl_binary(["mod.c"], Path(f"out_{side}/fuzz_mod"), cppflags="-I.", use_cache=False)
log = Path(res["compile_log"]).read_text(errors="replace")
keys = ("returncode", "reason", "binary", "const_union_rewrite", "const_union_rewrites")
out = {k: res.get(k) for k in keys}
out["implicit_cast"] = "implicit cast: cast from union blk to void *" in log
print(f"RESULT_{side} " + json.dumps(out))
EOF
done
./out_on/fuzz_mod.e-acsl -runs=200 > run.log 2>&1 && echo RUN_OK || tail -20 run.log
"""


@pytest.mark.integration
def test_static_const_union_builds_and_runs_under_eacsl_only_with_the_rewrite(tmp_path):
    from conftest import ANALYSIS_IMAGE, require_docker_images

    require_docker_images(ANALYSIS_IMAGE)
    (tmp_path / "mod.c").write_text(CONST_UNION_FUZZ_C, encoding="utf-8", newline="\n")
    name = f"framac-test-o9-{tmp_path.name}".lower()
    argv = ["docker", "run", "--rm", "--name", name, "--network", "none", "-v", f"{tmp_path}:/fixture:ro"]
    argv += ["-v", f"{CONST_UNION_REPO}:/repo:ro", ANALYSIS_IMAGE, CONST_UNION_DOCKER_SCRIPT]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1200)
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
        raise
    out = proc.stdout + proc.stderr
    results = {
        side: json.loads(line.split(" ", 1)[1])
        for line in proc.stdout.splitlines()
        for side in ("on", "off")
        if line.startswith(f"RESULT_{side} ")
    }
    assert set(results) == {"on", "off"}, out[-4000:]
    on, off = results["on"], results["off"]
    # With the rewrite: both declarations (file scope, local initialized) rewritten, E-ACSL binary, runs.
    assert on["returncode"] == 0, out[-4000:]
    assert on["const_union_rewrite"] is True and on["const_union_rewrites"] == 2
    assert on["binary"].endswith(".e-acsl") and not on["implicit_cast"]
    assert "RUN_OK" in proc.stdout, out[-4000:]
    # Without it, the same file hits the E-ACSL bug: the test tests something.
    assert off["returncode"] != 0 and off["const_union_rewrite"] is False
    assert off["const_union_rewrites"] is None and off["implicit_cast"] is True, out[-4000:]
