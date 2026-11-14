# Toolchain & Frama-C Upgrade Notes

Behavior changes across Frama-C releases and deprecated wrapper flags. See [`./README.md`](./README.md) for the master troubleshooting index.

---

## Frama-C 34.0~beta (Selenium), built from source (2026-11-13)

The analysis image no longer starts from `framac/frama-c:dev`. A `framac-opam` stage on `ocaml/opam:debian-13-ocaml-5.5` (pinned digest) installs Frama-C 34.0~beta and MetAcsl 0.12~beta from the local opam repository in `opam/`, plus `why3.1.8.2`, `alt-ergo-free.2.4.3` and `ocamlfind`. `framac-analysis` starts from the build image's own `DEBIAN_BASE` and copies only the switch. The image went from 6.79 GB to 3.55 GB. Image tag while it was being validated: `framac-analysis:fc34`.

### Symptom: the pinned `framac/frama-c:dev` image had none of the Frama-C 34 Eva changes
- **Seen on:** `framac-analysis:latest` built on the `framac/frama-c:dev` digest `sha256:2296220f…` (2026-11-04, the newest `dev` push), checked against the Frama-C 34.0~beta release notes on 2026-11-13.
- **Cause:** the image reports `35.0~~dev (Bromine)` and its `/frama-c/Changelog` already holds the kernel's 34.0 section, but its Eva predates the 34 work. `frama-c -eva-help-options` listed `-eva-partition-history` and had no `-eva-partition-path` or `-eva-auto-partition-path`. The Eva soundness fixes of 34.0 were therefore missing too: octagon on `x = *p + 1` when `p` points to `x`, casts from or to floating-point values, right shifts of negative values by an imprecise amount, and `memmove` with overlapping locations and an imprecise size. Docker Hub has no 34.0 tag of `framac/frama-c`; its newest numbered tag is `33.0`. This is not a pipeline defect: the base image was older than its version string suggested.
- **Fix (uncommitted):** the analysis image is built from the 34.0~beta source tarball as above. Eva Valid statuses from the earlier image may be wrong on code that hits one of the four fixed cases.
- **Benchmark A/B (2026-11-13):** `benchmark.py run` with the same scripts on both images, runs `ab-fc35dev` and `ab-fc34`, all 10 targets. Every module's Eva `alarms.csv` is byte-identical (25 modules), so are the Valid, Unknown, Invalid and Dead counts and the functions with an Unknown; recall is 7/7 on both, and `benchmark.py compare` finds nothing but the toolchain change. None of the four soundness fixes changes a status on these targets. Wall time 4,720 s against 4,992 s, CPU 7,669 s against 7,684 s. Both runs carry the fuzz `ZeroDivisionError` of [`./eacsl-and-fuzzing.md`](./eacsl-and-fuzzing.md), so their fuzz results compare like for like but are not campaign results.

### Symptom: `-eva-partition-history` renamed `-eva-partition-path`
- **Seen on:** Frama-C 34.0~beta. The old name still works and prints `[kernel] Warning: -eva-partition-history is a deprecated alias for option -eva-partition-path.`
- **Fix (uncommitted):** [`../../scripts/eva_options.py`](../../scripts/eva_options.py) allows `partition-path` and `partition-path-function` and refuses the old names, with a message naming the new one, so a module configuration shows what Eva actually runs. The `history` ladder step uses `partition-path` with the same values, so `LADDER_VERSION` stays 2. `auto-partition-path` and `auto-partition-path-function` are allowlisted but not in the ladder until a benchmark compares them with `history`. Tests: `tests/test_eva_tuning.py`.

### Note: E-ACSL RTE options of 34.0
The release notes list `-e-acsl-O-rte-initialized` and `-e-acsl-O-implicit-downcast`. In the 34.0~beta build these are `-e-acsl-rte-initialized` and `-e-acsl-rte-implicit-downcast`, part of the new `-e-acsl-rte <n>` group (see `frama-c -e-acsl-help`, section "RTE analysis for annotations"). The pipeline passes none of them yet.

### Note: workarounds labelled "Frama-C 35"
The repairs and tests written against the `35.0~~dev` image (`<==>` with labelled terms, the `_Alignas` printer repair, the `volatile` link repair, the `strlcpy`/`strlcat` stubs) were observed on a kernel whose `<next-release>` Changelog section was empty, so they describe 34 behaviour. On 34.0~beta the image's own Phase 0 selftest, CI's sandbox probe, E-ACSL canary and kernel AST selftests, `image_toolchain.py compare` against the build image, and the whole test suite with `FRAMAC_DOCKER_TESTS=1` pass (4965 passed, 49 skipped). The first run of that suite failed 32 MetAcsl acceptance tests; the cause was a template change the old image predated, not Frama-C 34 (see [`./security-properties.md`](./security-properties.md), "already declared with the same profile").

## Frama-C 34 (Selenium) & 35.0~~dev (Bromine) Upgrade Notes

Behavior changes since Frama-C 33 that the pipeline already accounts for:

- **Empty named behaviors are forbidden.** `behavior b: ;` in a function or statement contract is now a fatal `[kernel:annot-error] ... unexpected token ';'` (verified on the dev image). `acsl_ast.py` (`verify_acsl_only` / `find_empty_named_behaviors`) rejects them mechanically before splicing, and `run_wp_function.py` maps the kernel error to a repair hint.
- **ACSL clause order relaxed.** ACSL extensions may now precede `requires`, and `terminates`/`decreases` may sit anywhere between `requires` and `behavior` (verified: `assigns \nothing; terminates x > 0;` parses). The `exits`/`assigns`/`ensures` order is still enforced. The prover brief's recommended order remains valid.
- **Array-to-pointer decay removed in comparisons.** The kernel no longer implicitly converts an array to a pointer in `==`/`!=`/`<`/... comparisons, so array operands keep their array type. `kernel_ast_dump.ml` now matches both pointer and array operands when setting the `pointer_compare` feature.
- **New unsequenced-effect warnings (UB CC.35, upstream #@1219 fixed).** Local definitions with unsequenced side effects (e.g. `int x = i++ + i;`) now produce a `[kernel]` warning. Warnings do not change `-report-csv` statuses; no parser change needed.
- **Fine-grained `-rte-initialized` configuration fixed.** The option-hook bug that blocked per-function exclusion for `static` functions is fixed: `-rte-initialized=@all,-s` now emits zero initialization assertions for a `static` function `s` (verified with `-print` on the dev image). Prefer per-function exclusion over a global `--no-rte-initialized` (which is recorded in `reduced_checks`).
- **GCC machine modes partially supported.** `__attribute__((mode(<MODE>)))` is now converted to integer types (partial support), so targets using machine modes parse instead of failing with a syntax error.
- **`FRAMAC_TESTING` env var.** Frama-C 34+ exposes `FRAMAC_TESTING` (`Cmdline.inside_tests`) to mark test executions and guard extra verifications. Set it only for the repo's own test invocations of `frama-c`, never for production pipeline runs.
- **Base image is now 35.0~~dev (Bromine).** The pinned `framac/frama-c:dev` digest in the `Dockerfile` reports `35.0~~dev (Bromine)`. As of the master archive used for the upstream mining (2026-11-06), the Changelog's `<next-release>` section is still empty, so no 34->35 behavior changes need porting yet — but re-check `Changelog`/`Changelog_detailed.md` in the master archive on every base-image bump and port any `-`/`!` entries here. Upstream reference snippets mined from that archive live in [`../upstream/sources/`](../upstream/sources/README.md).
- **E-ACSL `<==>` regression (35.0~~dev, and 34.0~beta too):** E-ACSL in 35 and in the 34.0~beta image (rechecked 2026-11-14) aborts with `labels pre-analysis was not performed on construct \old(...)` when `p1 <==> p2` contains labelled terms; see [`./wp-and-guardrail.md`](./wp-and-guardrail.md) for the automatic preprocessor rewrite.
