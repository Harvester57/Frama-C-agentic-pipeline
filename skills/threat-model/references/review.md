# Independent Review

Before the model is handed off, someone who did not write it tries to break it. A threat model fails in two ways: it states something the source does not support, or it leaves out something the source has. The review looks for both, and the second is the one that matters most for the verification: an entry point the model omits is code the verification may treat as trusted.

## Who reviews

- **With delegation:** one fresh worker per challenge set below. Give it the confirmed scope, `files.txt`, `ThreatModel.md` and the challenge set. Do not give it the inventory results, the ledger's counts, or the author's reasoning: it must rebuild each answer from the source.
- **Without delegation:** run the same challenges yourself after the block is written, and record in the ledger that the review was not independent.

Prohibit source edits, command execution in the target, external requests, and nested delegation.

## Challenge sets

### 1. Every stated item holds

For each row of the typed tables and each block item:

- the function exists at the cited place, with the cited prototype;
- every parameter named in the row or the item is a parameter of that prototype, spelled the same;
- the role is what the code does (an `entry` receives outside data, a `reader` fills or returns it, a sink emits it, a gate's protected functions are really behind it);
- the description says nothing the cited lines do not show.

### 2. Nothing is missing

Without looking at the model's tables first, list from the source:

- every function the public headers declare and the build files export;
- every hit of the reader, sink, secret, authorization and state probes of [Surface inventory](surface-inventory.md).

Then compare with the model. Each function or hit must be covered by a classification row, a typed row, or a negative result. Report every one that is not.

### 3. Every restriction is earned

For each `trusted-only`, `no-attacker-data` and `unreachable-in-configuration` row, and each `trusted_callers` item, try to show the opposite: find an external caller, a documented public use, a parameter that can carry attacker data, or a configuration that exports the function. These rows remove code from the attacker's reach, so each needs positive evidence that survives the attempt.

Do the same for every `None:` sentence: try to find one instance of what it says does not exist.

### 4. The block equals the tables

- every block item has its table row, and every table row is in the block or counted as dropped with its reason;
- names, parameters, kinds and sizes agree between the two;
- no block item adds a claim the prose lacks.

## Result contract

Require one Markdown result per challenge set, saved below `evidence/review/`:

```markdown
# Challenge NN — <set name>

## Checked

| Item | Verdict | Evidence | Repair needed |
| --- | --- | --- | --- |
| row ID, block item, or omitted function | confirmed, corrected, removed, added | `path:line-line` | what to change, or none |

## Not Checked

- Item, and the exact reason it could not be checked.
```

## Apply the verdicts

- **`confirmed`:** nothing to do.
- **`corrected`, `removed`, `added`:** change `ThreatModel.md` and the block, record the repair in "Review Challenges" of the ledger, update the inventory counts, and validate the block again.
- **Disagreement:** when the author's evidence and the reviewer's conflict and the source does not settle it, keep the more cautious reading (the function stays `entry`, the sink stays listed) and record the question under "Unknowns And Evidence Limits".

A second review is needed only when a repair added or removed five or more rows.

## Exit gate

Close the phase when every challenge set has a saved result, every verdict other than `confirmed` is applied, the block validates after the last repair, and "Not Checked" items are recorded as gaps.
