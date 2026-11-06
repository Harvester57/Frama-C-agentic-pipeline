# Vendored upstream reference snippets

Provenance: all files in this directory are copied verbatim from the Frama-C **master** archive
(`https://git.frama-c.com/pub/frama-c/-/archive/master/frama-c-master.zip?ref_type=heads`,
VERSION `35~dev`, codename Bromine, downloaded 2026-11-06) unless noted. They are reference
material for pipeline scripts, skills and briefs — not build inputs. When Frama-C is upgraded,
re-extract and diff these against the new master.

| File | Upstream path | Used for |
|---|---|---|
| `eva_stubs.c` | `share/libc/eva_stubs.c` | Model for the `argv` harness entry style (`generate_harness.py`): generic `eva_main` emulating `argc`/`argv` via `Frama_C_interval` + `Frama_C_make_unknown` + `//@ loop unroll 5;` |
| `taint.c`, `multi_taint.c` | `plugins/eva/tests/value/` | `//@ taint x;` / `\eva::taint` annotation idioms and `-eva-domains taint -eva-taint-auto` flags for Layer 6 |
| `annot11.c`, `security_macro.h` | `plugins/eva/tests/secure_flow/` | `__fc_private` / `__attribute__((private))` marking + `assert security_status(x) == public;` under `-eva-secure-flow` — alternative to `!\tainted(...)` in `templates/acsl/layer6_zeroization_and_taint.acsl` |
| `loopinv.c` | `plugins/eva/tests/value/` | `-eva-slevel-function main2:20`, loop invariants reducing widening |
| `partitioning-annots.c` | `plugins/eva/tests/value/` | `//@ loop unroll N;`, `-eva-partition-value` / `-eva-partition-history` |
| `use_spec.i` | `plugins/eva/tests/value/` | `-eva-use-spec f,h` — override a function with a spec inside Eva (complements `templates/acsl/external_stubs.h`) |
| `euclid.c`, `bsearch.c`, `find.i` | `plugins/wp/tests/wp_gallery/` | Textbook WP contract patterns (axiomatic gcd + `\at(...,Pre)`, named behaviors, `∀` invariants) for `skills/framac-wp/prover_brief.md` |
| `eacsl_manual_link.sh` | `plugins/e-acsl/examples/demo/compile.sh` | Manual E-ACSL runtime link recipe (`e_acsl.c` + `e_acsl_bittree.c` + `e_acsl_mmodel.c`) as fallback when `eacsl_toolchain.py`'s `e-acsl-gcc` flow fails |
| `make_wrapper_tips.md` | `share/analysis-scripts/make_wrapper.py` (rewritten as notes) | Log-pattern → repair-hint mapping ported into `run_eva_slice.py` report `repair_hints` |

Related upstream locations (not vendored, consult in the extracted tree or online):
`share/analysis-scripts/` (Make pipeline `analysis.mk`, `estimate_difficulty.py`, `creduce.sh`,
`normalize_jcdb.py`, `summary.py`), `plugins/eva/src/parameters.ml` (full `-eva-*` option list),
`plugins/wp/tests/` (prover flag usage), `share/libc/` (ACSL libc specs, `no_eva:` invariant
label idiom, `__fc_builtin.h`).
