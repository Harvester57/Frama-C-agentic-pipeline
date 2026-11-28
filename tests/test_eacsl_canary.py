"""
C1 of docs/plans/templates-and-stubs-improvement-plan.md: the E-ACSL selftest canary exercises, on every
input, the build steps it did not cover: the wrapper result-init pass (an `ensures` reading
\\result), the <math.h> classification shim (`isnan`) and the errno stub and shim. Taking any one of
them out of the build fails the selftest.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
CANARY = REPO / "templates" / "eacsl_canary" / "canary.c"


@pytest.mark.unit
def test_canary_exercises_result_init_isnan_and_errno_on_every_input():
    text = CANARY.read_text(encoding="utf-8")
    # A field of a struct result: Frama-C 35 checks no scalar \result for initialization.
    assert "/*@ ensures \\result.len <= span.len; */\nstatic struct canary_span canary_clamp(" in text
    assert "return isnan(ratio) ? 1 : 0;" in text
    assert "errno = 0;" in text and "/*@ assert canary_errno_synced: synced != 0; */" in text
    body = text[text.index("static int canary_process") :]
    # Before the input-dependent branches: every input runs them.
    every = body.index("canary_clamp(span).len + canary_classify(len) + canary_errno()")
    assert every < body.index("if (len > 0 && data[0] == 'O')")


# Each variant takes one step out of the production build, through the module attribute it reads.
VARIANTS = {
    "production": "",
    "no_result_init": "FB.mark_wrapper_results_initialized = lambda t: (t, 0)",
    "no_errno_shim": "FB.build_errno_shim_object = lambda *a, **k: {'status': 'none', 'wrapped': []}",
    "no_snan": "T.EACSL_DEFINES = tuple(d for d in T.EACSL_DEFINES if d != '-D__SUPPORT_SNAN__')",
}

SELFTEST_SCRIPT = r"""mkdir -p /tmp/w && cd /tmp/w
cat > st.py <<'EOF'
import json, sys
from pathlib import Path
sys.path.insert(0, "/opt/framac-pipeline/scripts")
import eacsl_toolchain as T
import fuzz_build as FB
import run_eacsl_fuzz as R
variants = json.loads(Path("/fixture/variants.json").read_text())
for name, patch in variants.items():
    import importlib
    T = importlib.reload(T)
    FB = importlib.reload(FB)
    R = importlib.reload(R)
    exec(patch)
    res = R.run_selftest(Path(name))
    keys = ("ok", "checks", "benign_failure")
    print("RESULT " + json.dumps({"variant": name, **{k: res.get(k) for k in keys}}))
EOF
python3 st.py
"""


@pytest.mark.integration
def test_selftest_fails_when_a_covered_build_step_is_taken_out(tmp_path):
    from conftest import ANALYSIS_IMAGE, require_docker_images

    require_docker_images(ANALYSIS_IMAGE)
    (tmp_path / "variants.json").write_text(json.dumps(VARIANTS), encoding="utf-8")
    argv = ["docker", "run", "--rm", "--network", "none", "-v", f"{tmp_path}:/fixture:ro"]
    argv += ["-v", f"{REPO / 'scripts'}:/opt/framac-pipeline/scripts:ro"]
    argv += ["-v", f"{REPO / 'templates'}:/opt/framac-pipeline/templates:ro", ANALYSIS_IMAGE]
    argv += [SELFTEST_SCRIPT]
    proc = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1800)
    out = proc.stdout + proc.stderr
    results = {
        r["variant"]: r
        for r in (json.loads(ln[len("RESULT ") :]) for ln in proc.stdout.splitlines() if ln.startswith("RESULT "))
    }
    assert set(results) == set(VARIANTS), out[-4000:]
    assert results["production"]["ok"], results["production"]
    # Patch 08 fixes struct \result initialization in E-ACSL itself, so no_result_init passes on patched images
    # and fails with \result.len on stock 34.0~beta.
    no_res = results["no_result_init"]
    assert no_res["checks"]["compiled"], no_res
    if not no_res["ok"]:
        assert not no_res["checks"]["benign_input_clean"], no_res
        assert "\\\\result.len" in json.dumps(no_res["benign_failure"])
    no_errno = results["no_errno_shim"]
    assert no_errno["checks"]["compiled"] and not no_errno["checks"]["benign_input_clean"] and not no_errno["ok"], (
        no_errno
    )
    assert "canary_errno_synced" in json.dumps(no_errno["benign_failure"])
    # Without the classification define the build itself fails (clang refuses Frama-C's builtin prototypes).
    assert not results["no_snan"]["ok"], results["no_snan"]
