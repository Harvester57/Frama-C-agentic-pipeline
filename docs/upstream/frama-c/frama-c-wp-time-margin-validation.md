# WP `-wp-time-margin` unchecked (`float_of_string` crash) and manual default mismatch

- **Parent index:** [`./README.md`](./README.md)
- **Package:** `70` (`H17` from [`./frama-c-hunt-2026-11-18-candidates.md`](./frama-c-hunt-2026-11-18-candidates.md))
- **Issue text:** [`./filing/70-wp-time-margin-validation-issue.md`](./filing/70-wp-time-margin-validation-issue.md)
- **Merge request text:** [`./filing/70-wp-time-margin-validation-mr.md`](./filing/70-wp-time-margin-validation-mr.md)
- **Reproducer:** [`./repro/70-wp-time-margin-validation.sh`](./repro/70-wp-time-margin-validation.sh) + [`./repro/70-wp-time-margin-validation.c`](./repro/70-wp-time-margin-validation.c)
- **Patch:** [`./patches/70-wp-time-margin-validation.patch`](./patches/70-wp-time-margin-validation.patch)
- **Local `opam/` patch queue recommendation:** **NO (minor CLI option crash + doc mismatch)** — cleanly fixable upstream.

## Summary

`Wp_parameters.TimeMargin` (`-wp-time-margin`) is a `String` option (`plugins/wp/src/wp_parameters.ml:846-857`, `.mli:116`) parsed lazily with unguarded `float_of_string` in `VCS.ml:132` and `ProofEngine.ml:598`. Passing `-wp-time-margin 1s` (invited by `plugins/wp/doc/manual/wp_plugin.tex:1441`, which says `Default is 5s.` while the code defaults to `"0.5"`) crashes after running provers with `Unexpected error (Failure("float_of_string"))` (exit 125). `nan`, `inf`, and `-1` are accepted silently.

## Duplicate search

Live read-only `glab api` search across `pub/frama-c` (project `780`, issues and MRs, all states) for `wp-time-margin`, `TimeMargin`, `time-margin`, `float_of_string`, plus [`./pub-frama-c_work_items_2026-11-09.csv`](./pub-frama-c_work_items_2026-11-09.csv) and packages `01`-`50`: **0 duplicates** (`#2832` overview only).

## Fix and validation

- **Source changes:** change `TimeMargin` to `Float` (`default = 0.5`), set `TimeMargin.set_range ~min:0.0 ~max:infinity` with an `add_set_hook` rejecting non-finite values (`not (Stdlib.Float.is_finite f)`), remove `float_of_string` from `VCS.ml:132` and `ProofEngine.ml:598`, update `wp_plugin.tex:1441` (`0.5` seconds), and update `tests/misc/oracle/help-messages.32.res.oracle`.
- **Stacking:** stacks cleanly with [`./patches/71-wp-par-range-check.patch`](./patches/71-wp-par-range-check.patch) on `wp_parameters.ml` in either order.
