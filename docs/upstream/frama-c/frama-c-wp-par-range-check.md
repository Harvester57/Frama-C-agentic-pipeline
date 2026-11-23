# WP `-wp-par 0` (and negative values) crash `Prove_client.set_max_running_provers`

- **Parent index:** [`./README.md`](./README.md)
- **Package:** `71` (`N16` from [`./frama-c-hunt-2026-11-18-candidates.md`](./frama-c-hunt-2026-11-18-candidates.md))
- **Issue text:** [`./filing/71-wp-par-range-check-issue.md`](./filing/71-wp-par-range-check-issue.md)
- **Merge request text:** [`./filing/71-wp-par-range-check-mr.md`](./filing/71-wp-par-range-check-mr.md)
- **Reproducer:** [`./repro/71-wp-par-range-check.sh`](./repro/71-wp-par-range-check.sh) + [`./repro/71-wp-par-range-check.c`](./repro/71-wp-par-range-check.c)
- **Patch:** [`./patches/71-wp-par-range-check.patch`](./patches/71-wp-par-range-check.patch)
- **Local `opam/` patch queue recommendation:** **NO (minor CLI option crash)** — cleanly fixable upstream.

## Summary

`Wp_parameters.Procs` (`-wp-par`, `plugins/wp/src/wp_parameters.ml:862-870`) is an unbounded `Int` option with no `set_range`. Passing `-wp-par 0` or `-wp-par -1` passes CLI validation and crashes inside Why3's `Prove_client.set_max_running_provers` with `Unexpected error (Invalid_argument("Prove_client.set_max_running_provers"))` (exit 125).

## Duplicate search

Live read-only `glab api` search across `pub/frama-c` (project `780`, issues and MRs, all states) for `wp-par`, `set_max_running_provers`, `Prove_client`, plus [`./pub-frama-c_work_items_2026-11-09.csv`](./pub-frama-c_work_items_2026-11-09.csv) and packages `01`-`50`: **0 duplicates** (`#2832` overview only).

## Fix and validation

- **Source change (`plugins/wp/src/wp_parameters.ml`):** add `let () = Procs.set_range ~min:1 ~max:max_int`. Zero `.mli` or help-message oracle impact.
- **Full WP suite:** `./dev/test.sh -p plugins/wp` passes with zero existing oracle changes.
- **Stacking:** stacks cleanly with [`./patches/70-wp-time-margin-validation.patch`](./patches/70-wp-time-margin-validation.patch) on `wp_parameters.ml` in either order.
