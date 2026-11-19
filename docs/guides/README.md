# Core Pipeline Architecture & Operational Guides

- **Documentation Hub:** [`../README.md`](../README.md)
- **Repository Root:** [`../../README.md`](../../README.md)

These eight living guides describe how the Frama-C Agentic Verification Pipeline works today. When pipeline behavior, schemas, Make targets, or environment knobs change, update the matching guide here in the same change.

---

## Guides in Recommended Reading Order

| # | Guide | Scope |
| :---: | :--- | :--- |
| 1 | [`./architecture.md`](./architecture.md) | Macro-level and micro-level dataflow across Phase 0 (`/framac-slice`), Phase 1 (`/framac-fuzz`), Phase 2 (`/framac-eva`), and Phase 3 (`/framac-wp`), and how RTE, E-ACSL, Eva, and WP collaborate on a shared AST. |
| 2 | [`./v2-design.md`](./v2-design.md) | Run directory layout, parent-vs-subagent write ownership, container/sandbox isolation, coverage ledger (`function x obligation class`), independent crash verification verdicts, and `quick`/`standard`/`deep` profiles. |
| 3 | [`./slicing-and-onboarding.md`](./slicing-and-onboarding.md) | Partitioning large codebases into link-unit modules and sub-modules, trust-derived risk tiers (Tiers 1A, 1B, 2, 3), stub overlays (`workspace/stubs/`), and dual-use harnesses. |
| 4 | [`./security-properties.md`](./security-properties.md) | Proving security properties beyond memory safety (Layers 1 to 6) via structured `THREAT_MODEL.md` declarations and generated MetAcsl meta-properties (`l3_frame` through `l6_no_leak`). |
| 5 | [`./agentic-swarm.md`](./agentic-swarm.md) | Multi-level parallelism, speculative header architects, dependency-driven `wp_scheduler.py`, the Dual-Oracle Guardrail (WP + E-ACSL), adversarial breakers, contract negotiation, KBSpec, and loop invariant seeds. |
| 6 | [`./resources-and-caching.md`](./resources-and-caching.md) | Dynamic cgroup/Slurm/Docker resource probing, container job classes and leases, deterministic `pipeline_make.py` execution, L1/L2 build caches, Eva/guardrail/proof caches, and host `FRAMAC_*` knobs. |
| 7 | [`./eva-sharding.md`](./eva-sharding.md) | Splitting slow single-threaded Eva module runs across *k* dispatch-case shards via `eva_shards.py` using flamegraph cost profiles and sound obligation-status merging. |
| 8 | [`./benchmark.md`](./benchmark.md) | Running deterministic A/B regression benchmarks (`benchmark.py`), comparing against stored baselines, running the seeded recall/decoy corpus (`benchmark_seeded.py`), and evaluating prover briefs (`benchmark_briefs.py`). |

---

## Related Reference Material

- **Third-Party Header Stubs (`templates/fc_stubs/`):** [`../../templates/fc_stubs/README.md`](../../templates/fc_stubs/README.md)
- **E-ACSL Quick Reference:** [`../references/e-acsl-quickref.md`](../references/e-acsl-quickref.md)
- **Frama-C Reference Manuals (`INDEX.md`):** [`../references/README.md`](../references/README.md)
- **Thematic Troubleshooting Guides:** [`../troubleshooting/README.md`](../troubleshooting/README.md)
