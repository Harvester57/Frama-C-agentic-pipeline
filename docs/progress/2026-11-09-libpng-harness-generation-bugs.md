# Bug report: Phase 0 Step 4 harness generation still fails on libpng (round 2)

Date: 2026-11-09 · Pipeline: `86fa400` (phase1-remediation, includes `a07ada5`, `a4939e1`, `29b9aa7`, `05b74c7`)
Target: libpng `a70313dbb`, **LF** checkout (`core.autocrlf=false`), CMake build · Profile: standard
Run dir: `C:\Users\Florian\framac-pipeline\libpng\run-3` (host) = `/framac-run` (container)
Audience: a fresh engineer/model with no memory of the session. Everything needed to reproduce is below.

Round 1 (`docs/progress/2026-11-08-libpng-harness-sources-bug.md`) is **fixed**: `pngfix`'s harness now has
`pngfix.c` + 16 library files, all programs link `-lz -lm`, `pnglibconf.h` is found by the prelude. This report
covers what is left. There are **four independent defects** (A–D), ordered by impact. A blocks the run.

## How to reproduce

```
# host, from the repo (any worktree at >= 86fa400); PowerShell
$T = "C:\Users\Florian\OneDrive\Documents\Dev\targets\libpng"
& .\wrappers\framac-docker.ps1 -TargetDir $T -NewRun "python3 /opt/framac-pipeline/scripts/run_metadata.py init --repo libpng --profile standard"
# then (RunDir = printed run dir): workspace_overlay.py init --target /target --overlay workspace
#   run_metadata.py set-build --command 'cmake -S . -B build && cmake --build build' --workdir . --package zlib1g-dev --test-command 'ctest --test-dir build' --origin user
#   build_capture.py run   (-BuildImage -Scratch -TargetPackages zlib1g-dev)
#   phase0_model.py run    (-Scratch -Class phase-static)
#   build_callgraph_dag.py --target workspace/work --out workspace/reports/callgraph_dag.json
#   security_props.py run
# then the harness step, which is what fails. The exact driver used (run-3/gen_all.py):
```

```python
import json, subprocess, sys
d = json.load(open('workspace/reports/callgraph_dag.json'))
G = '/opt/framac-pipeline/scripts/generate_harness.py'
for n in d.get('submodules', {}):               # 9 clusters of unit libpng18_a
    run(['--module', n, '--api', '--header', 'workspace/work/png.h', '--max-size', '1500', '--out-dir', 'workspace/harnesses'])
for n, m in d['modules'].items():               # 9 executables (libpng18_a is NOT in d['modules'] keys here;
    run(['--module', n, '--sources'] + m['required_sources'] + ['--entry-fn', 'main', '--max-size', '1500',
         '--cppflags=' + ' '.join(m['cppflags']), '--out-dir', 'workspace/harnesses'])
```

Note: without `--header workspace/work/png.h` the `--api` clusters `pngwutil` and `pngset` fail with
`unresolved identifiers after automatic prelude resolution: jmp_buf, FILE` (commit `a4939e1` was meant to fix
the headerless case; it does not for these two). With the header they pass the prelude. So the header must be
given by hand today — the generator does not infer the unit's public header (`png.h`) although the capture
knows it (`public_headers`). Treat as defect E (minor), see below.

DAG facts: 9 clusters `libpng18_a__{png,pngwrite,pngset,pngwutil,pngget,pngget_2..5}`; 9 executable modules
(`png_fix_itxt pngfix pnggetset pngimage pngreadend pngstest pngtest pngunknown pngvalid`), all Tier 1A; every
module is `fuzz_engine: sanitizers` except `png_fix_itxt` (libpng calls `setjmp`, so E-ACSL is off — expected).

## Defect A (blocking) — `--api` emits opaque libpng handles as by-value stack structs

**Symptom.** `generate_harness.py --module libpng18_a__pngget{,_2,_3,_4,_5} --api …` exits 1:
`module 'libpng18_a__pngget_4': no API case compiles: [('png_get_next_frame_width', "the case does not compile with
the target's headers"), …]`. Five of the nine clusters are dead this way; the cases of `png`, `pngwrite`,
`pngset` are mostly dropped by the same rule (`cases 3/2/3`, with 9/8/10 `api_skipped` "does not compile").
`pngwutil` ends with `prelude error` and 221 cases (see below).

**Root cause (confirmed by compiling).** For `png_get_next_frame_width(png_const_structrp, png_const_inforp)` the
generator writes, per case (harness line 140 of `harness_libpng18_a__pngget_4.c`):

```c
case 0U: { size_t fuzz_off = 0; struct png_struct_def c0a0; memset(&c0a0, 0, sizeof(c0a0));
           struct png_info_def c0a1; memset(&c0a1, 0, sizeof(c0a1));
           (void)png_get_next_frame_width(&c0a0, &c0a1); (void)fuzz_off; } break;
```

`png.h` only forward-declares `struct png_struct_def` and `struct png_info_def` (`typedef struct png_struct_def
png_struct; /* [Opaque] */`, `png.h:361`). Declaring a variable of that type is a hard error (`variable has
incomplete type`), so **every** case that takes a `png_structp`/`png_infop` fails. That is nearly all of libpng's
API. `scripts/api_harness.py:498 failing_cases()` then drops every case, and `generate()` raises
(`api_harness.py:606`).

To see the errors yourself (script used: `run-3/probe_dbg.py`): call
`api_harness.generate(mod, 'workspace/work/png.h', 1500, '-Iworkspace/work -Iworkspace/work/build', Path('workspace/harnesses_dbg'), probe=False)`
then `clang -fsyntax-only -w -x c <cppflags + with_include_flags> harness.c` → 21 errors, all
`variable has incomplete type 'struct png_struct_def' / 'struct png_info_def'`.

**Why this is a design gap, not a one-line bug.** A pointer to an incomplete (opaque) struct cannot be
fabricated from fuzz bytes; the library must create it (`png_create_read_struct`, `png_create_info_struct`, …).
The "pointer to an anonymous struct" skip already exists for `png_image*` (they land in `api_skipped`); the
incomplete-but-named case needs a decision:

1. *Opaque handle from the library's own constructor* (best, matches how the API is used). Needs a per-type
   "factory" table, possibly inferred: a function returning `T*` whose name/return type matches and takes only
   scalars/NULLs (`png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL)`; `png_create_info_struct(png)`),
   plus the teardown. The harness runs the factory once per input (or once at init), and the case passes it.
   Recorded call sequences (Step 1e `traces.jsonl`) would give this for free, but `seed_harvest` found no test
   units here (defect D), so there are none.
2. *Include the private header* (`pngpriv.h` defines `struct png_struct_def`) so the struct is complete and a
   zeroed one can be passed. Cheap, but a zeroed `png_struct` with `longjmp` state and null function pointers makes
   most functions crash trivially → harness-induced crashes the verifier must reject. Likely poor.
3. *Pass NULL*. Most libpng functions check `png_ptr == NULL` and return; useless coverage, but sound and
   compiles. As a fallback it beats dropping the function, but it should be recorded as a coverage gap, not a pass
   of the reach gate.

Recommended: implement (1) generically (opaque `T*` args are produced by a unique constructor returning `T*` from
the same unit, found via the model's signatures), fall back to NULL with an explicit `api_skipped`-style note, and
**never** fall back to by-value fabrication of a type that is not complete in the harness TU. Regardless of the
chosen design, `generate()` must not raise when only some cases are dropped; and the reach gate must see the
functions that were reduced to NULL as "reached only with NULL" (today a dropped function is a plain gap, which
is the honest outcome).

**Acceptance.** `generate_harness.py --api` succeeds for all 9 clusters; `harness_reach.py check` either passes or
lists only exempted/skipped entry points with reasons; a smoke fuzz of `libpng18_a__pngget` runs ≥ 1 s without a
harness-induced crash on the first input.

Also worth a look while there: `libpng18_a__pngwutil` returns rc 0 with `prelude_status: error`
(`harness_libpng18_a__pngwutil.c:358:63: error: variable has incomplete type 'struct png_struct_def'`) and
`cases 221`. The sidecar was written with cases that do not compile; the probe loop's `MAX_PROBE_ROUNDS` apparently
ran out, or the error line is outside a `case N:` line so it is not attributed (`failing_cases` only maps errors on
lines matching `^\s*case (\d+)U: \{`; a single-line case does match, but errors in a *different* line of the file
are ignored and `bad` stays empty → `return None`). **Treat a harness with `prelude_status: error` as a failed
generation (non-zero exit), not a success.** Today `generate_module_harness` returns normally.

## Defect B — `png_fix_itxt` harness: `break int main(void);` is emitted

`harness_png_fix_itxt.c:36`:

```c
/* Include module header and external boundary stubs */
break int main(void);
```

→ `clang: error: expected identifier or '('`. The auto-prototype synthesizer for `main` read the *line above*
`main(void)` in `contrib/tools/png-fix-itxt.c`. That file formats `main` K&R-style as

```c
int
main(void)
```

but preceded by the macro `#define GETBREAK inchar=getchar(); \ … break; …` (line 36) — the synthesizer's
"return type" regexp picked up the token `break` (from the macro body / previous line) instead of `int`. Find the
declaration synthesizer in `scripts/generate_harness.py` (search `external_decl`, `synth`, or the code that writes
"Include module header and external boundary stubs") and make it (a) strip preprocessor lines and macro
continuations before extracting the type, (b) prefer the model's signature for `main` (the Phase 0 model has
`formals`/return type for every function) over regexing source text. **Acceptance:** the harness parses.

## Defect C — argv-style `main` is wrongly assumed for stdin/no-argument programs

`pnggetset` and `png-fix-itxt` define `int main(void)`. For `--entry-fn main` the default `argv` style emits
`main(2, argv)` → `harness_pnggetset.c:119:10: error: too many arguments to function call, expected 0, have 2`.
Neither program reads `argv`; `png-fix-itxt` reads **stdin** (`getchar()`), and `pnggetset` reads a file named by
argument? (it is `main(void)`, so no — it opens a hard-coded/`PNG_FILE`-style input; unverified).

Needed: choose the entry style from the model's signature for `main`: `main(void)` → `void_call` (with stdin fed
from the fuzz input where the program reads stdin: the sandbox runner already controls stdin, but the *harness*
(LibFuzzer in-process) must redirect: e.g. `freopen`/`fmemopen`/`dup2` of a pipe, or compile with a `getchar`
shim). Today there is no stdin-fed style; programs that read stdin are common (Unix tools), so a generic
`stdin` entry style would pay off beyond libpng. If out of scope, record these two modules as exempt with a reason
(`harness_reach.py exempt --module pnggetset --reason …`) rather than emitting an uncompilable harness.

**Acceptance:** `png_fix_itxt` and `pnggetset` either produce a harness that compiles and consumes the fuzz bytes,
or are exempted with a recorded reason.

## Defect D — no seeds are recorded for libpng

`seed_harvest.py record` → `{"status": "no_test_units", "test_units": [], "calls": null}` although
`test_command = ctest --test-dir build` is set and the build has `pngtest`, `pngvalid`, `pngstest`, `pngimage`,
`pngunknown`, `pngreadend` executables. Per the skill the test-unit rule splits artifact names on `_ - .` and looks
for the words test/tests/check/…; `pngtest` is one word and does not match, so no unit is a "test" unit.
Consequence: no recorded API calls/traces, so (i) no seeds, (ii) no `sequence` cases in `--api` harnesses — and
sequences are what would solve defect A for free. Two reasonable fixes: let the recorded `test_command` define test
units (relink every executable the `ctest` run starts, discovered via `strace`/`ctest -N`, regardless of name), or
extend the name rule with the `png…test`/`…valid` suffix heuristic (weaker). Check `docs/slicing-and-onboarding.md`
for the intended behaviour before changing the rule.

Related: the libpng repo ships **no libFuzzer targets** in this checkout (`fuzz_assets.py discover` found none),
so Step 1f is a no-op here — not a bug.

## Defect E (minor) — `--api` does not infer the unit's public header

Without `--header workspace/work/png.h` the prelude fails for `pngwutil` / `pngset` (`jmp_buf, FILE`) even after
`a4939e1`. The build capture records `public_headers` for the shared library; `--api` should default `--header`
to it. Also `png_access_version_number` was picked as the nominal `entry_fn` of every `--api` harness (cosmetic).

## Other observations (not defects of this step)

- `pngsimd.c`: the build defines 15 functions Frama-C's parse lacks (`abs_i16`, `if_then_else`, `load3`, …) behind
  `__SSE2__`; Eva/WP/E-ACSL won't see them (the DAG warns, correctly).
- No `THREAT_MODEL.md` → trust from default rules only, Layer 3 properties only. Fine, but affects coverage of the
  report; the user was told.
- Target working-tree CRLF broke the build once (`options.awk: bad line (10): com\r`). `build_capture` could
  detect `\r` in the build's scripts and say "CRLF checkout" in `diagnostics`; right now the message is
  `Failed to generate pnglibconf.tf5`.
- A harness whose generation fails leaves **partial files** (`harness_libpng18_a__pngget*.{c,json}` exist in
  `workspace/harnesses/` although the command exited 1). Stale artifacts like that can be picked up by `gen`/the
  reach gate. Generation should write to a temp name and move into place on success only.
- I (the reporting session) briefly generated `harness_libpng18_a` for the *library unit* by looping over
  `d['modules']` with `--entry-fn main`; the unit has no `main`, so it failed. Self-inflicted, deleted; but note
  that the DAG exposes the library only through `submodules`, which my driver script initially did not expect.

## Suggested order of work for the fixer

1. A (design decision first; the rest of the run depends on it), plus "non-zero exit on `prelude_status: error`" and
   atomic harness writes.
2. B (small, mechanical), then C (decide: stdin style vs exemption).
3. D and E.
4. Re-run Phase 0 on a **new** run dir (`-NewRun`) with the commands above, then `harness_reach.py check`,
   `ledger.py seed`, `pipeline_make.py gen`, `pipeline_make.py build-check`.

Tests to add: unit tests for the opaque-handle case in `tests/test_api_harness*.py` (a header with
`typedef struct s s_t; s_t *s_new(void); int s_get(const s_t *)`), for the `main(void)` declaration synthesis with a
preceding macro continuation containing `break`, and for non-zero exit on prelude error.
