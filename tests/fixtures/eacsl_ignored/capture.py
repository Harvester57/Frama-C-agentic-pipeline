"""
Capture run of scenario.sh (analysis image): real E-ACSL builds and guardrail replays of probe.c,
violation.c and extras.c, through the pipeline's own build path. Writes into /out:

  <tag>.stage1.log        the stage 1 record of the build's compile log (command, return code, E-ACSL's
                          stdout and stderr), unedited; stage 2 (clang compiling the runtime) is left out
  <tag>.json              the guardrail report (`unb_requires`, `violation`)
  <tag>.instrumented.c    the instrumented file, as the build left it (the three `via_*` builds)
  frama-c-version.txt

The reports in this directory were captured before the guardrail read `Ignoring annotation`: they
pass and name no ignored clause.
"""

import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, "/repo/scripts" if Path("/repo/scripts").is_dir() else "/opt/framac-pipeline/scripts")
import fuzz_build  # noqa: E402
import run_eacsl_fuzz as R  # noqa: E402

OUT = Path("/out")
SRC_DIR = "workspace/work/src"
CPP = f"-I{SRC_DIR}"
KEEP_REPORT = {"unb_requires", "violation"}
KEEP_INSTRUMENTED = {"via_pred", "via_wrapped", "via_hdr_pred"}


def save_stage1(compile_log: Path, tag: str) -> None:
    if not compile_log.is_file():
        return
    records = compile_log.read_text(encoding="utf-8").split("\nCommand: ")
    if len(records) > 1:
        (OUT / f"{tag}.stage1.log").write_text("Command: " + records[1] + "\n", encoding="utf-8", newline="\n")


def guard(tag: str, extra: list[str], source: str = "probe.c") -> None:
    out = f"state/guard/{tag}/guard_{tag}"
    t0 = time.time()
    argv = [
        "guardrail", "--sources", f"{SRC_DIR}/{source}", "--out-bin", out,
        "--corpus-dir", "workspace/corpus/probe", "--module", "probe", f"--cppflags={CPP}",
        "--extra-runs", "0", "--no-cache", "--out-json", out + ".json", *extra,
    ]  # fmt: skip
    rc = R.main(argv)
    print(f"GUARD {tag} rc={rc} {time.time() - t0:.0f}s", flush=True)
    save_stage1(Path(out + ".compile.log"), tag)
    if tag in KEEP_REPORT:
        shutil.copy(out + ".json", OUT / f"{tag}.json")
    if tag in KEEP_INSTRUMENTED:
        shutil.copy(out + ".instrumented.c", OUT / f"{tag}.instrumented.c")


def extra(name: str) -> None:
    out = Path(f"state/extra/{name}/x_{name}")
    t0 = time.time()
    comp = fuzz_build.compile_eacsl_binary(
        [f"{SRC_DIR}/extras.c"], out, cppflags=f"{CPP} -DX_{name.upper()}", functions=["probe_fn"], use_cache=False
    )
    print(f"EXTRA {name} rc={comp['returncode']} reason={comp.get('reason')} {time.time() - t0:.0f}s", flush=True)
    save_stage1(Path(comp["compile_log"]), f"extra_{name}")


def main() -> None:
    version = subprocess.run(["frama-c", "-version"], capture_output=True, text=True).stdout.strip()
    (OUT / "frama-c-version.txt").write_text(version + "\n", encoding="utf-8", newline="\n")
    for fn in ("unb_requires", "unb_ensures", "plain", "walk", "hdr_fn", "via_pred", "via_wrapped", "via_hdr_pred"):
        guard(fn, ["--functions", fn])
    guard("body_assert", ["--functions", "body_assert"])
    guard("multi_line", ["--functions", "multi_line"])
    guard("module", ["--reach-functions", "unb_requires", "plain"])
    guard("violation", ["--functions", "wrong_post"], source="violation.c")
    for name in (
        "at", "struct", "decreases", "terminates", "exists", "fresh", "axiomatic", "with", "behavior", "exits",
        "allocates",
    ):  # fmt: skip
        try:
            extra(name)
        except Exception as exc:  # each construct is independent
            print(f"EXTRA {name} raised {exc!r}", flush=True)
    print("CAPTURE done", flush=True)


if __name__ == "__main__":
    main()
