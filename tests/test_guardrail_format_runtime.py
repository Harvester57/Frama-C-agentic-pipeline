"""
The WP Dual-Oracle guardrail builds its E-ACSL binary with the patched format runtime (c-ares run-1, 2026-11-16).

Every prover of an `adig` function stopped with `guardrail_error`: the guardrail binary aborted in
`print_header` (src/tools/adig.c), whose `printf("... id: %u\n", ..., ares_dns_record_get_id(dnsrec))`
passes an `unsigned short` promoted to `int`, on libFuzzer's empty input, before any corpus file. The
check is outside the checked function and the input cannot be dropped, so the contract was never tested.

The guardrail (`run_eacsl_fuzz.py guardrail`) builds through `compile_eacsl_binary`, the same stage 2 as
the Phase 1 fuzz build, so the patched share directory (eacsl_toolchain.EACSL_FORMAT_RUNTIME_PATCH)
applies to it. These tests hold that: the guardrail CLI path, an agent-scratch output (never cached),
and an image test that builds and replays a print_header-shaped fixture with and without the patch.
"""

from __future__ import annotations

import functools
import json
import os
import re
import subprocess
import uuid
from pathlib import Path

import pytest

import eacsl_toolchain as T
import fuzz_build
import run_eacsl_fuzz as R
from test_eacsl_format_signedness import _fake_share, _StageRecorder

GUARD_WT_ROOT = Path(__file__).resolve().parent.parent
GUARD_SCRATCH = Path("agents") / "prove-checked" / "scratch"


@pytest.fixture
def guard_run_dir(tmp_path, monkeypatch):
    """A run directory with one source, an agent scratch, a corpus file, and a modern e-acsl-gcc with a share."""
    share = _fake_share(tmp_path / "image")
    monkeypatch.setattr(fuzz_build, "_resolve_eacsl_gcc", lambda: ("e-acsl-gcc", True))
    monkeypatch.setattr(T.shutil, "which", lambda name: None)
    monkeypatch.setattr(fuzz_build, "eacsl_share_dir", lambda eacsl_bin: share)
    run = tmp_path / "run"
    (run / GUARD_SCRATCH).mkdir(parents=True)
    (run / "corpus").mkdir()
    (run / "corpus" / "seed-a").write_bytes(b"A")
    (run / "mod.c").write_text("int checked(int x) { return x; }\n", encoding="utf-8")
    monkeypatch.chdir(run)
    return run


def _guard_argv(tag: str) -> list[str]:
    out = GUARD_SCRATCH / f"guard_{tag}"
    return [
        "guardrail",
        "--sources", "mod.c",
        "--out-bin", out.as_posix(),
        "--corpus-dir", "corpus",
        "--functions", "checked",
        "--extra-runs", "0",
        "--out-json", f"{out.as_posix()}.json",
    ]  # fmt: skip


def test_guardrail_cli_builds_the_runtime_from_the_patched_share(guard_run_dir, monkeypatch):
    fake = _StageRecorder()
    monkeypatch.setattr(fuzz_build, "compile_eacsl_binary", functools.partial(R.compile_eacsl_binary, runner=fake))
    replayed: list[Path] = []

    def fake_guardrail(binary, *args, **kwargs):
        replayed.append(Path(binary))
        return {"status": "passed_dynamic_oracle", "crash_input": None, "failure": None}

    monkeypatch.setattr(R, "run_guardrail_check", fake_guardrail)
    assert R.main(_guard_argv("checked")) == 0
    report = json.loads((GUARD_SCRATCH / "guard_checked.json").read_text(encoding="utf-8"))
    patch = report["compile"]["runtime_patches"]["format_runtime"]
    assert patch["status"] == "applied", report["compile"]
    # The copy lives in the agent's scratch, beside the guardrail binary, and stage 2 compiles the runtime from it.
    share = Path(patch["share"])
    assert share.parent.parent == (guard_run_dir / GUARD_SCRATCH / "eacsl_share").resolve()
    stage1, stage2 = [c for c in fake.calls if c[0] == "e-acsl-gcc"]
    assert stage2[stage2.index("--e-acsl-share") + 1] == patch["share"]
    assert "--validate-format-strings" in stage2 and "--e-acsl-share" not in stage1
    assert replayed and replayed[0].name.startswith("guard_checked")


def test_guardrail_build_in_agent_scratch_is_uncached_and_patched(guard_run_dir):
    fake = _StageRecorder()
    res = R.compile_eacsl_binary(["mod.c"], GUARD_SCRATCH / "guard_checked", functions=["checked"], runner=fake)
    assert res["returncode"] == 0, res
    # Agent builds are never cached, so no stale unpatched binary can come back from the build cache.
    assert res["cache"] == {"hit": False, "key": None}
    assert res["runtime_patches"]["format_runtime"]["status"] == "applied"


def test_guardrail_falls_back_to_the_image_runtime_when_the_patch_does_not_compile(guard_run_dir):
    class PatchedRuntimeBreaks(_StageRecorder):
        def __call__(self, cmd, **kwargs):
            if "-C" in cmd and "--e-acsl-share" in cmd:
                self.calls.append(list(cmd))
                share = cmd[cmd.index("--e-acsl-share") + 1]
                err = f"{share}/libc_replacements/e_acsl_stdio.c:812:5: error: use of undeclared identifier 'fc_both'\n"
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr=err)
            return super().__call__(cmd, **kwargs)

    fake = PatchedRuntimeBreaks()
    res = R.compile_eacsl_binary(["mod.c"], GUARD_SCRATCH / "guard_checked", functions=["checked"], runner=fake)
    assert res["returncode"] == 0, res
    stage2 = [c for c in fake.calls if c[0] == "e-acsl-gcc" and "-C" in c]
    assert len(stage2) == 2 and "--e-acsl-share" in stage2[0] and "--e-acsl-share" not in stage2[1]
    assert res["runtime_patches"]["format_runtime"]["status"] == "not_applied"


def test_patched_share_copy_follows_the_patch_text(tmp_path, monkeypatch):
    src = _fake_share(tmp_path / "image")
    first = T.prepare_patched_eacsl_share(src, tmp_path / "eacsl_share")
    name, anchor, replacement = T._FMT_HUNKS[0]
    monkeypatch.setattr(T, "_FMT_HUNKS", ((name, anchor, "/* edited */\n" + replacement), *T._FMT_HUNKS[1:]))
    second = T.prepare_patched_eacsl_share(src, tmp_path / "eacsl_share")
    # Same tag, different hunks: a new copy, never the one patched by the old text.
    assert first["status"] == second["status"] == "applied"
    assert first["share"] != second["share"]
    patched = Path(second["share"]) / "libc_replacements" / "e_acsl_stdio.c"
    assert "/* edited */" in patched.read_text(encoding="utf-8")


# print_header of c-ares src/tools/adig.c, reduced: a `%u` given a promoted `unsigned short` after two
# `%s`, then four `%u` given `(unsigned int)` casts of a size_t. The harness calls it on every input,
# libFuzzer's empty one included, as adig's harness did; only `checked` is instrumented for RTE.
GUARD_PROBE_C = r"""
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

static unsigned short record_id(size_t size) { return (unsigned short)(4660 + size); }
static size_t record_cnt(size_t size, int section) { return size + (size_t)section; }

static void print_header(size_t size)
{
  printf(";; ->>HEADER<<- opcode: %s, status: %s, id: %u\n", "QUERY", "NOERROR", record_id(size));
  printf("; QUERY: %u, ANSWER: %u, AUTHORITY: %u, ADDITIONAL: %u\n",
         (unsigned int)record_cnt(size, 0), (unsigned int)record_cnt(size, 1),
         (unsigned int)record_cnt(size, 2), (unsigned int)record_cnt(size, 3));
}

/*@ requires size <= 4096;
    assigns \nothing;
    ensures \result == (int)size; */
int checked(size_t size) { return (int)size; }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  (void)data;
  if (size > 4096)
    return 0;
  print_header(size);
  return checked(size) < 0;
}
"""

# Runs the guardrail CLI twice in the analysis image: with the patched share, then with the image's runtime.
GUARD_PROBE_SCRIPT = r"""set -e
cp -r /fixture /tmp/w && cd /tmp/w
mkdir -p corpus agents/prove-checked/scratch
printf 'AB' > corpus/seed-ab
python3 - <<'EOF'
import json, sys
sys.path.insert(0, "/repo/scripts")
import run_eacsl_fuzz as R

def run(tag):
    out = f"agents/prove-checked/scratch/guard_{tag}"
    rc = R.main(["guardrail", "--sources", "mod.c", "--out-bin", out, "--corpus-dir", "corpus",
                 "--functions", "checked", "--extra-runs", "0", "--no-cache", "--out-json", out + ".json"])
    rep = json.load(open(out + ".json"))
    keep = {k: rep.get(k) for k in ("status", "reason", "crash_input", "excluded_inputs", "mutations_skipped")}
    keep["runtime_patches"] = (rep.get("compile") or {}).get("runtime_patches")
    keep["compile_reason"] = (rep.get("compile") or {}).get("reason")
    keep["trace"] = (rep.get("runtime_trace") or "")[-1500:]
    print(f"GUARD {tag} rc={rc} " + json.dumps(keep))

run("patched")
R.eacsl_share_dir = lambda eacsl_bin: None
run("stock")
EOF
for tag in patched stock; do
  echo "SHARE $tag $(grep -c -- '--e-acsl-share' agents/prove-checked/scratch/guard_$tag.compile.log)"
done
"""


def _guard_reports(stdout: str) -> dict[str, dict]:
    reports = {}
    for tag, rc, body in re.findall(r"^GUARD (\w+) rc=(-?\d+) (\{.*\})$", stdout, re.MULTILINE):
        reports[tag] = {"rc": int(rc), **json.loads(body)}
    return reports


@pytest.mark.integration
def test_guardrail_passes_a_promoted_unsigned_short_printf_in_the_analysis_image(tmp_path):
    from conftest import ANALYSIS_IMAGE, require_docker_images

    require_docker_images(ANALYSIS_IMAGE)
    (tmp_path / "mod.c").write_text(GUARD_PROBE_C, encoding="utf-8", newline="\n")
    tag = os.environ.get("FRAMAC_RUN_TAG") or f"test-guardfmt-{uuid.uuid4().hex[:8]}"
    name = f"framac-test-guardfmt-{uuid.uuid4().hex[:8]}"
    argv = ["docker", "run", "--rm", "--name", name, "--label", f"framac.run={tag}", "--network", "none"]
    argv += ["-v", f"{tmp_path}:/fixture:ro", "-v", f"{GUARD_WT_ROOT}:/repo:ro", ANALYSIS_IMAGE, GUARD_PROBE_SCRIPT]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1200)
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
    out = proc.stdout + proc.stderr
    reports = _guard_reports(proc.stdout)
    assert set(reports) == {"patched", "stock"}, out[-6000:]
    patched, stock = reports["patched"], reports["stock"]
    assert patched["runtime_patches"]["format_runtime"]["status"] == "applied", out[-6000:]
    assert re.search(r"^SHARE patched [1-9]", proc.stdout, re.MULTILINE), out[-6000:]
    # The image's runtime stops on the promoted `unsigned short` of print_header, outside the checked
    # function, on the empty input libFuzzer runs first: the guardrail cannot test the contract.
    assert stock["runtime_patches"]["format_runtime"]["status"] == "not_applied", out[-6000:]
    assert stock["status"] == "guardrail_error", out[-6000:]
    assert "print_header" in json.dumps(stock), out[-6000:]
    # The patched runtime lets it through and the contract is tested on every input.
    assert patched["status"] == "passed_dynamic_oracle", out[-6000:]
    assert patched["rc"] == 0 and not patched["excluded_inputs"], out[-6000:]
