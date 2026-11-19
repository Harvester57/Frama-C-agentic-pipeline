# Ledger, Artifacts, and Closure

Use durable filesystem state rather than chat history to coordinate, resume, and validate a threat-modeling review.

## Contents

- [Artifact layout](#artifact-layout)
- [Phase ledger](#phase-ledger)
- [State invariants](#state-invariants)
- [Hard errors and completeness gaps](#hard-errors-and-completeness-gaps)
- [Closure check](#closure-check)

## Artifact layout

Use this portable layout:

```text
.security-reviews/<review-id>/
├── Scope.md
├── Ledger.md
├── Context.md
├── ThreatModel.md
├── files.txt
├── non-reviewable.txt
└── evidence/
    ├── inventory/
    │   ├── pass-N/worker-NN.md
    │   └── probes.md
    ├── review/
    │   └── challenge-NN.md
    └── validation/
        └── check-threat-model.txt
```

Keep every path contained below the review directory. `ThreatModel.md` is the only deliverable; everything else is the evidence that it is complete.

## Phase ledger

Create `Ledger.md` with:

```markdown
# Review Ledger — REVIEW_ID

## Metadata

- Created at: UTC timestamp
- Project root: path
- Confirmed scope: path or paths
- Source-control mode: filesystem | git-aware
- Revision: revision | nogit
- Model: visible identifier | unavailable
- Inventory passes: count
- Worker mode: delegated | sequential
- Baseline threat model: path and sha256 | none

## Phase State

| Phase | Status | Updated UTC | Evidence | Note |
| --- | --- | --- | --- | --- |
| scope | complete | ... | `Scope.md`, `files.txt` | ... |
| context | pending | | | |
| inventory | pending | | | |
| model | pending | | | |
| block | pending | | | |
| review | pending | | | |

## Coverage

| Pass | Assignment | Expected paths | Receipt | Deferred paths |
| --- | --- | --- | --- | --- |

## Inventory Counts

| Kind | Rows found | Rows in `ThreatModel.md` | Items in the block | Rows dropped, with reason |
| --- | --- | --- | --- | --- |

## Open Questions

| ID | Question | Asked UTC | Answer or assumption used | Sections affected |
| --- | --- | --- | --- | --- |

## Review Challenges

| ID | Item or omission challenged | Verdict | Repair | Evidence |
| --- | --- | --- | --- | --- |

## Partial Decision

- Decision: undecided | accepted
- Reason:
- Accepted gaps:
- Decided at:

## History

- UTC timestamp — state transition and reason.
```

Allowed phase states are `pending`, `in_progress`, `complete`, `partial`, `skipped`, and `blocked`.
A complete phase needs existing evidence. No phase of this workflow may be skipped: a phase that cannot run is `blocked`, with the reason.
Partial or blocked phases are gaps even when later work can responsibly proceed.

Review verdicts are `confirmed`, `corrected`, `removed`, and `added`. Give every verdict other than `confirmed` its repair and the source reference that justifies it.

## State invariants

- Start a phase only after every earlier phase has a closed, explained state.
- Preserve complete worker results and challenge records; do not replace them with ledger summaries.
- Allocate inventory row IDs monotonically per kind (`EP-NNN`, `RD-NNN`, `SK-NNN`, `SE-NNN`, `AG-NNN`, `ST-NNN`, `TC-NNN`) and never reuse an ID.
- Keep the counts consistent: every inventory row is either in `ThreatModel.md` or dropped with a reason, and every block item points back to a `ThreatModel.md` row.
- Record changes in history. Any change to the scope, the inventory or the block invalidates a previous partial acceptance until the current gaps are accepted again.
- On resume, verify artifact existence and consistency before trusting a status.

## Hard errors and completeness gaps

Repair hard errors before closure.

Examples include:

- a missing or renamed `ThreatModel.md` section;
- unresolved placeholders or generation comments;
- broken or escaping paths;
- missing, duplicate, or unowned coverage rows;
- a complete phase with absent evidence;
- a block that fails validation, or more than one block in the file;
- a block item with no matching prose row, or with a function or parameter name the source does not have;
- an empty block list without the prose statement that the target has none of that kind;
- an inventory row that is neither in the model nor dropped with a reason;
- a claim taken from a pipeline run result, a benchmark manifest or a known-bug list instead of the source;
- any change to the product source.

Treat these as completeness gaps:

- partial or blocked phases;
- deferred files;
- fewer requested passes or workers;
- sequential rather than independent workers;
- a review challenge done by the agent that wrote the model;
- unanswered open questions, with the assumption used in their place;
- unavailable deployment facts;
- a block checked by hand because the validator was not available;
- names the validator's model check could not resolve.

## Closure check

Call a threat model complete only when:

- every eligible file has an accepted receipt in every inventory pass;
- every section of the `ThreatModel.md` contract is filled;
- every exported function has a row in the API classification table, and the class counts add up to the number of exported functions;
- every search probe family has its line in `evidence/inventory/probes.md`;
- the inventory counts in the ledger agree with the model and the block;
- the block validates;
- every review challenge has a verdict and its repair is applied;
- every phase is complete;
- no hard error or completeness gap remains.

If only gaps remain, present the exact list and the consequence of each for the verification that will use the model (an entry point that may be missing, a list that may be incomplete). Resume work where practical. Record partial acceptance only after the user explicitly accepts those current gaps and supplies or confirms a reason. Preserve the reason and gaps in `Ledger.md` and under "Unknowns And Evidence Limits" of `ThreatModel.md`. Label the result `valid but partial`.

Never convert a hard error into an accepted limitation.
