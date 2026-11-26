# Toolchain & Frama-C Upgrade Notes

Behavior changes across Frama-C releases and deprecated wrapper flags. See [`./README.md`](./README.md) for the master troubleshooting index.

---

## Curated local opam patch queue on Frama-C 34.0~beta & MetAcsl 0.12~beta (2026-11-23)

The local opam repository under [`../../opam/`](../../opam/patches-manifest.json) now applies a curated, source-only patch queue managed by [`../../tools/sync_opam_patches.py`](../../tools/sync_opam_patches.py): 52 validated patches on `frama-c.34.0~beta` and 4 validated patches on `frama-c-metacsl.0.12~beta` (excluding deprecated alias `09`, open-design `22`, bittree `37`/`38`, and manual-only `40`).

- **Provenance and cache keys:** `Dockerfile` installs `opam/patches-manifest.json` as `$FRAMAC_SHARE/pipeline-patches.json`. [`../../scripts/run_metadata.py`](../../scripts/run_metadata.py) records it under `toolchain["frama-c-patches"]`, and [`../../scripts/cache.py`](../../scripts/cache.py) mixes its digest into the fallback toolchain identity when `FRAMAC_IMAGE_ID` is unset.
- **Retired workaround:** `REWRITE_STATIC_CONST_UNIONS` in [`../../scripts/fc_cpp_wrapper_eacsl.py`](../../scripts/fc_cpp_wrapper_eacsl.py) is now `False` because patch `27` (`pub/frama-c#2795` / `!26`) is baked into `framac-analysis:latest`.
- **Format-runtime interaction:** With upstream patches `30`, `31`, and `32` baked into `e_acsl_stdio.c`, [`../../scripts/eacsl_toolchain.py`](../../scripts/eacsl_toolchain.py) `patch_format_runtime` reports `status: "not_applied"` (missing stock `args`/`validate_type` anchors) and falls back cleanly to the image's patched runtime. Promoted `unsigned char`/`unsigned short`/`_Bool`, floating-point slots, and `*` width/precision now work natively; plain `int` vs `unsigned int` stays strict unless `patch_format_runtime` is updated for the post-patch-32 anchors.
- **Upstream reproduction:** Keep an unpatched tag (e.g. `framac-analysis:34.0-beta-stock`) and the stock [`../../tools/upstream_audit/Dockerfile`](../../tools/upstream_audit/Dockerfile) image for verifying upstream bug reports; never reproduce upstream bugs against the patched `framac-analysis:latest`.

---

## Frama-C 34.0~beta (Selenium), built from source (2026-11-13)

The analysis image no longer starts from `framac/frama-c:dev`. A `framac-opam` stage on `ocaml/opam:debian-13-ocaml-5.5` (pinned digest) installs Frama-C 34.0~beta and MetAcsl 0.12~beta from the local opam repository in `opam/`, plus `why3.1.8.2`, `alt-ergo-free.2.4.3` and `ocamlfind`. `framac-analysis` starts from the build image's own `DEBIAN_BASE` and copies only the switch. The image went from 6.79 GB to 3.55 GB. Image tag while it was being validated: `framac-analysis:fc34`.

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
- **Base image was 35.0~~dev (Bromine) until 2026-11-13.** The pinned `framac/frama-c:dev` digest in the `Dockerfile` reported `35.0~~dev (Bromine)`; the image is now built from the 34.0~beta source (see above). As of the master archive used for the upstream mining (2026-11-06), the Changelog's `<next-release>` section is still empty, so no 34->35 behavior changes need porting yet — but re-check `Changelog`/`Changelog_detailed.md` in the master archive on every base-image bump and port any `-`/`!` entries here. Upstream reference snippets mined from that archive live in [`../upstream/sources/`](../upstream/sources/README.md).
- **E-ACSL `<==>` regression (35.0~~dev, and 34.0~beta too):** E-ACSL in 35 and in the 34.0~beta image (rechecked 2026-11-14) aborts with `labels pre-analysis was not performed on construct \old(...)` when `p1 <==> p2` contains labelled terms; see [`./wp-and-guardrail.md`](./wp-and-guardrail.md) for the automatic preprocessor rewrite.
