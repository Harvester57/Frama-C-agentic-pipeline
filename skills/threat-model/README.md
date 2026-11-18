# Threat Model

This skill guides an AI assistant through building a source-backed threat model of a C codebase. Its one deliverable is `ThreatModel.md`, which ends with the machine-readable block the Frama-C verification pipeline reads.

> [!NOTE]
> This skill is derived from the ENISA Code Auditor skill (1.0-beta, EUPL-1.2). The audit phases of the original (tool analysis, candidate discovery, triage, remediation, reporting, exploitation) were removed; the scope, ledger and threat-model phases were kept and extended. AI tools were used to support the development of both.

---

| Property       | Value        |
| -------------- | ------------ |
| **Skill Name** | Threat Model |
| **Version**    | 2.0          |
| **License**    | EUPL-1.2     |

---

## Overview

A threat model states what the target is, who can reach it, where attacker-controlled data enters, what must stay secret or intact, where data leaves, and what must never happen. It does not say whether the code is correct: the verification that takes the model as its input finds that out.

The skill follows these phases and writes its artifacts under `.security-reviews/`:

1. **Control:** check the review state and decide which phase to start or resume.
2. **Scope:** confirm the paths to model and inventory the files.
3. **Context:** understand the target from its documentation, build files and layout (purpose, deployment, directory roles, documented build and test commands, build options that change the attack surface). Nothing is executed.
4. **Inventory:** read every file in three passes (inputs and entry points; state, secrets and authorization; outputs and platform), with a coverage receipt per file and per pass, then cross-check with search probes.
5. **Model:** class every exported function, fill the typed tables, trace the data flows, state what can go wrong and who will check each property.
6. **Block:** restate the tables as the `framac-threat-model` JSON block and validate it.
7. **Review:** an independent reviewer checks that every item holds, that nothing is missing, and that every restriction is earned.

---

## Usage Notes

Start a threat model by naming the skill and the target:

```text
/threat-model Build the threat model of the library under ./targets/libfoo.
```

You can give context the source cannot show:

```text
/threat-model Build the threat model of ./src. The library is linked into a network daemon that runs as root and receives unauthenticated packets. Only the default configure options ship.
```

Things to consider:

- The model is only as good as its deployment facts. Answer the open questions the skill asks after the context phase, or review the assumptions it used instead.
- Functions classed as not attacker-reachable (`trusted-only`) remove code from the verification's untrusted set. Review them first.
- The threats marked `not checked by the verification` are the residual risk: the pipeline will not look at them.
- The skill never runs the target's build, tests or scripts, and never edits the target.
- You may ask for a specific number of workers or inventory passes.

---

## Repository contents

```text
threat-model/
├── README.md     # (This file) information for repository users
├── SKILL.md      # The operating instructions for compatible AI systems
└── references/   # Per-phase instructions
    ├── control.md               # ledger, artifact layout, closure
    ├── scope.md                 # scope and file inventory
    ├── context.md               # Context.md: purpose, deployment, build, options
    ├── surface-inventory.md     # full-file inventory passes, row kinds, probes
    ├── threat-model.md          # ThreatModel.md contract and section rules
    ├── framac-threat-model.md   # the machine-readable block
    └── review.md                # independent challenge of the model
```

---

## Default Output

```text
.security-reviews/
├── <review-id>/
    ├── Scope.md
    ├── Ledger.md
    ├── Context.md        # what the target is; proposals for the pipeline's build recipe
    ├── ThreatModel.md    # the deliverable, ending with a `framac-threat-model` JSON block
    ├── files.txt
    └── evidence/         # inventory receipts, review challenges, validator output
```

Your agentic tool may not store the `.security-reviews` folder under your current working directory.

The Frama-C verification pipeline takes `ThreatModel.md` directly as its threat model:

- **How to pass it:** use `phase0_model.py run --threat-model PATH` or `trust.py run --threat-model PATH`. The pipeline reads only the fenced `framac-threat-model` block (see `references/framac-threat-model.md`).
- **How to check it:** `python scripts/trust.py check-threat-model PATH` validates it.
- **What else helps Phase 0:** `Context.md` lists the documented build and test commands, the role of each directory and the build options that change the attack surface. They are proposals: Phase 0 records only a build recipe the user confirmed.

---

## Installation

Copy the `threat-model` directory into the skill location used by your compatible AI client/platform.

```text
.agents/
└── skills/ <-- the skills folder used by your AI client/platform
    └── threat-model/ <-- this folder
```

Refer to the documentation of your AI client/platform for installation and discovery instructions.

---

## License

This skill is distributed under the EUPL-1.2, the licence of the ENISA skill it derives from.

---

## Disclaimer

A threat model produced by an AI agent with this skill should be reviewed by someone who knows how the target is deployed, before the verification relies on it.

AI tools were used to support the development of this skill.
