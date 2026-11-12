# Frama-C Verification Pipeline Documentation

- **Repository Root:** [`../README.md`](../README.md)
- **Documentation Maintenance Rules:** [`./AGENTS.md`](./AGENTS.md)

This directory holds all architecture documentation, operational guides, troubleshooting catalogs, verified target advisories, upstream issue drafts, active/archived engineering plans, and greppable Frama-C reference manuals.

---

## Navigation by Goal

| Goal | Entry Point | Contents |
| :--- | :--- | :--- |
| **Understand how the pipeline works** | [`./guides/README.md`](./guides/README.md) | Macro/micro architecture, v2 evidence discipline, 90k+ LoC slicing, Layers 1-6 security properties, multi-agent swarm & guardrail, resource broker & caching, Eva sharding, and benchmark harness |
| **Diagnose a build, tool, or gate failure** | [`./troubleshooting/README.md`](./troubleshooting/README.md) | 10 thematic symptom/cause/fix catalogs covering Phase 0 through Phase 3, MetAcsl, the coverage ledger, and host/container infrastructure |
| **Review verified target vulnerabilities** | [`./bugs-found/README.md`](./bugs-found/README.md) | Master vulnerability index, per-target advisories, standalone reproducers, and proof summaries |
| **Inspect staged upstream bug reports & reference snippets** | [`./upstream/README.md`](./upstream/README.md) | Frama-C / E-ACSL / `e-acsl-gcc` bug drafts (`./upstream/frama-c/`), staged target disclosures (`./upstream/qcbor/`), and vendored Frama-C master C/ACSL examples (`./upstream/sources/`) |
| **Check open roadmap items or historical designs** | [`./plans/README.md`](./plans/README.md) | Living [`backlog.md`](./plans/backlog.md), active remediation/improvement plans, and archived Phase 0 / coherency plans (`./plans/archive/`) |
| **Read chronological run assessments & postmortems** | [`./runs/README.md`](./runs/README.md) | Dated target verification assessments, validation runs, and pipeline-blocker postmortems (`YYYY-MM-DD-*.md`) |
| **Look up Frama-C / ACSL / E-ACSL manual syntax** | [`./references/README.md`](./references/README.md) | Greppable Markdown conversions of the upstream WP, Eva, RTE, ACSL, and E-ACSL manuals, [`INDEX.md`](./references/INDEX.md), and [`e-acsl-quickref.md`](./references/e-acsl-quickref.md) |

---

## Recommended Reading Order for New Contributors

1. **Macro & Micro Dataflow:** [`./guides/architecture.md`](./guides/architecture.md)
2. **Evidence Discipline, Write Ownership & Isolation:** [`./guides/v2-design.md`](./guides/v2-design.md)
3. **Phase 0 Slicing, Risk Tiers & Stub Overlays:** [`./guides/slicing-and-onboarding.md`](./guides/slicing-and-onboarding.md) (plus [`../templates/fc_stubs/README.md`](../templates/fc_stubs/README.md))
4. **Layers 1-6 Security Properties (MetAcsl):** [`./guides/security-properties.md`](./guides/security-properties.md)
5. **Phase 3 Multi-Agent Swarm & Dual-Oracle Guardrail:** [`./guides/agentic-swarm.md`](./guides/agentic-swarm.md)
6. **Self-Sizing Resource Broker, Make Runner & Caches:** [`./guides/resources-and-caching.md`](./guides/resources-and-caching.md) and [`./guides/eva-sharding.md`](./guides/eva-sharding.md)
7. **Measuring Changes Without Regressions:** [`./guides/benchmark.md`](./guides/benchmark.md)
