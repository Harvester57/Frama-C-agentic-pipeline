# minmea: Upstream Issue and Pull Request Drafts

- **Upstream Hub:** [`../README.md`](../README.md)
- **Findings:** [`../../bugs-found/minmea/README.md`](../../bugs-found/minmea/README.md)
- **Upstream Repository:** [https://github.com/kosma/minmea](https://github.com/kosma/minmea), `master` at `c43c9e7` on 2026-11-14

| Finding | Draft | Status |
| :--- | :--- | :--- |
| `MINMEA-01`, unvalidated month and day in `minmea_getdatetime` | Issue text: [`./01-getdatetime-issue.md`](./01-getdatetime-issue.md). Pull request text: [`./01-getdatetime-pr.md`](./01-getdatetime-pr.md). | Posted 2026-11-14: issue [kosma/minmea#107](https://github.com/kosma/minmea/issues/107), pull request [kosma/minmea#108](https://github.com/kosma/minmea/pull/108) (commit `9ebca16`, branch `fix-getdatetime-calendar-range` of the fork `Harvester57/minmea`). Local clone: `C:\Users\Florian\framac-pipeline\minmea-upstream`. |

The fix differs from the one proposed in the findings document: it validates in `minmea_getdatetime` only, with month `1..12` and day `1..31`, and leaves `minmea_parse_zda` unchanged so that sentences with empty date fields still parse. The year arithmetic does not overflow for any `int` year, so it is not checked.

`MINMEA-02` and `MINMEA-03` are already reported upstream; `MINMEA-04` is partly covered by an open pull request. See the upstream status section of the findings document.
