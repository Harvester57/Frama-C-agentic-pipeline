# WP `strategy` timeout with suffix or overflow aborts with internal error

- **Parent index:** [`./README.md`](./README.md)
- **Package:** `69` (`H16` from [`./frama-c-hunt-2026-11-18-candidates.md`](./frama-c-hunt-2026-11-18-candidates.md))
- **Issue text:** [`./filing/69-wp-strategy-timeout-exception-issue.md`](./filing/69-wp-strategy-timeout-exception-issue.md)
- **Merge request text:** [`./filing/69-wp-strategy-timeout-exception-mr.md`](./filing/69-wp-strategy-timeout-exception-mr.md)
- **Reproducer:** [`./repro/69-wp-strategy-timeout-exception.sh`](./repro/69-wp-strategy-timeout-exception.sh) + [`./repro/69-wp-strategy-timeout-exception.c`](./repro/69-wp-strategy-timeout-exception.c)
- **Patch:** [`./patches/69-wp-strategy-timeout-exception.patch`](./patches/69-wp-strategy-timeout-exception.patch)
- **Local `opam/` patch queue recommendation:** **NO (minor crash on invalid user annotation)** — cleanly fixable upstream.

## Summary

`ProofStrategy.parse_provers` (`plugins/wp/src/ProofStrategy.ml:158-169`) wraps `int_of_string` and `float_of_string` with `with Invalid_argument _` to report `"Invalid timeout"`. Because OCaml's `int_of_string` and `float_of_string` raise `Failure _`, any `strategy` timeout with a suffix (`2u`, `2.5f`) or integer overflow (`99999999999999999999`) escapes as an internal error (exit 4) instead of an `"Invalid timeout"` annotation error (exit 1).

## Duplicate search

Live read-only `glab api` search across `pub/frama-c` (project `780`, issues and MRs, all states) for `ProofStrategy`, `Invalid timeout`, `parse_provers`, `strategy timeout`, plus [`./pub-frama-c_work_items_2026-11-09.csv`](./pub-frama-c_work_items_2026-11-09.csv) and packages `01`-`50`: **0 duplicates** (`#2832` overview only).

## Fix and validation

- **Source change (`plugins/wp/src/ProofStrategy.ml:159, 165, 167`):** catch `Failure _` in both branches and reject non-finite floats (`not (Float.is_finite time) || time < 0.0`).
- **Full WP suite:** `./dev/test.sh -p plugins/wp` passes with zero existing oracle changes.
- **Lint/headers and reproducer:** validated in container on `master` `189053d4a2` and `34.0~beta`.
