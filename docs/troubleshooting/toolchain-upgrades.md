# Toolchain & Frama-C Upgrade Notes

Behavior changes across Frama-C releases and deprecated wrapper flags. See [`./README.md`](./README.md) for the master troubleshooting index.

---

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
- **Frama-C 35.0~~dev E-ACSL `<==>` regression:** E-ACSL in 35 aborts with `labels pre-analysis was not performed on construct \old(...)` when `p1 <==> p2` contains labelled terms; see [`./wp-and-guardrail.md`](./wp-and-guardrail.md) for the automatic preprocessor rewrite.
