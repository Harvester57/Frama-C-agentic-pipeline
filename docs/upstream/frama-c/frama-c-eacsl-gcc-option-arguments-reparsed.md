# e-acsl-gcc: option arguments are re-parsed as options (`-e "-g"` enables GMP and drops an input file, `-E "-I dir"` loses every input)

**Filed upstream on 2026-11-15:** issue [#2807](https://git.frama-c.com/pub/frama-c/-/work_items/2807), merge request [!38](https://git.frama-c.com/pub/frama-c/-/merge_requests/38).

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).

**Filing package:** [issue](./filing/01-eacsl-gcc-option-arguments-reparsed-issue.md), [MR](./filing/01-eacsl-gcc-option-arguments-reparsed-mr.md), [reproducer](./repro/01-eacsl-gcc-option-arguments-reparsed.sh), [patch](./patches/01-eacsl-gcc-option-arguments-reparsed.patch)

## Summary

After `getopt` and `eval set -- "$ARGS"`, `e-acsl-gcc` walks its options with an unquoted
`for i in $@` (line 442), while each `case` branch `shift`s the real positional parameters. The
word list of the `for` loop is split on whitespace once, when the loop starts. Every word inside an
option **argument** is therefore matched against the option patterns again. When a word equals an
`e-acsl-gcc` option, that option's branch runs: it changes a setting and shifts the real argument
list out of step. The final `shift` at line 814, meant to drop `--`, then removes an input file
instead.

Arguments that contain a word equal to a short option are common:

| Invocation | What happens |
|---|---|
| `-e "-g -O1"` (debug info for the compiler) | `-g` runs the `-g\|--gmp` branch, so Frama-C gets **`-e-acsl-O-gmp-only`**. The extra shift then makes the run abort with `no input files`, or silently drop the first input file |
| `-E "-I inc"` (separated include path) | `-I` runs the `-I\|--frama-c` branch: `fatal error: no input files` |
| `-l "-L /usr/lib -lm"` | `-L` runs the `-L\|--frama-c-stdlib` branch: `fatal error: no input files` |

The joined forms (`-Iinc`, `-L/usr/lib`) work, which is why the examples in `-h` do not show the
problem. Arguments containing spaces (include paths with spaces) cannot be passed at all.

## Versions

- Reproduced on 2026-11-15 with Frama-C `35.0~~dev (Bromine)`, `master` at `3dff90fc70`
  (2026-11-13), and with `34.0~beta (Selenium)`: same output on both, Debian 13 (bash 5.2,
  util-linux `getopt`) ([reproducer](./repro/01-eacsl-gcc-option-arguments-reparsed.sh)).
- First seen with 33.0, then on `master` `ad24dca` (2026-11-02).

## Reproduction

```sh
cat > t1.c <<'EOF'
int helper(int x) { return x + 1; }
EOF
cat > t2.c <<'EOF'
int main(void) { return 0; }
EOF
mkdir -p inc && echo '#define FOO 1' > inc/foo.h
printf '#include "foo.h"\nint main(void) { return FOO - 1; }\n' > inc_use.c
```

```text
$ e-acsl-gcc -G clang -F "-rte" -e "-g -O1" -o t.instrumented.c -O t t2.c
e-acsl-gcc: fatal error: no input files

$ e-acsl-gcc -n -o t.instrumented.c -e "-g -O1" t1.c t2.c        # exit 0
++ frama-c ... -no-frama-c-stdlib t2.c -e-acsl -e-acsl-O-gmp-only ...
$ grep -c helper t.instrumented.c                                 # t1.c was dropped
0

$ e-acsl-gcc -n -E "-I inc" -o i.inst.c inc_use.c
e-acsl-gcc: fatal error: no input files

$ e-acsl-gcc -l "-L /usr/lib -lm" -o t.inst.c -O tl t2.c
e-acsl-gcc: fatal error: no input files
```

Trace of the second command. After `getopt`, the positional parameters are
`-n -o 't.instrumented.c' -e '-g -O1' -- 't1.c' 't2.c'`. The loop visits `-n`, `-o`,
`t.instrumented.c` and `-e` normally, then visits `-g` (taken from inside the `-e` argument). That
sets `OPTION_GMP` and shifts `--` away. The line 814 `shift` then drops `t1.c`.

## Fix (patch)

[`patches/01-eacsl-gcc-option-arguments-reparsed.patch`](./patches/01-eacsl-gcc-option-arguments-reparsed.patch),
one commit on `fix/eacsl-gcc-option-arguments` from `3dff90fc70`, "[e-acsl] e-acsl-gcc: do not read
the words of option arguments as options". It contains the script change below, a regression test
`plugins/e-acsl/tests/special/e-acsl-gcc-option-arguments.c` whose `dev` run passes `-e -g` to
`e-acsl-gcc` (on `master` it fails with `no input files`), the test's default-configuration
oracles, and a Changelog entry. The 56 option branches all shift their option (checked against
`SHORTOPTIONS` and `LONGOPTIONS`).

Loop on the positional parameters themselves. Each branch already shifts its own option and
argument, so nothing else changes. `--` ends the loop, and the trailing `shift` goes away.

```diff
--- a/plugins/e-acsl/scripts/e-acsl-gcc
+++ b/plugins/e-acsl/scripts/e-acsl-gcc
@@ -438,10 +438,12 @@ fi
 # Set all options in $@ before -- and other after
 eval set -- "$ARGS"
 
-# Switch statements for other options
-for i in $@
+# Switch statements for other options. Loop on the positional parameters
+# themselves: each branch shifts its option (and its argument), so the words
+# of an option argument are never read again as options.
+while [ $# -gt 0 ]
 do
-  case "$i" in
+  case "$1" in
     # Do compile instrumented code
     --help|-h)
       shift;
@@ -809,9 +811,16 @@ $zone_help_msg"
       OPTION_MBITS="$1"
       shift;
     ;;
+    # End of the options normalized by getopt: the input files follow
+    --)
+      shift;
+      break;
+    ;;
+    *)
+      error "unexpected argument '$1'";
+    ;;
   esac
 done
-shift;
 
 # Bail if no files to translate are given and we're not trying to only compile
 # dlmalloc
```

The `*)` branch should never be reached, because `getopt` puts every non-option after `--`. It
protects the `while` loop from spinning forever if a future branch forgets to shift.

## Validation

Validated on 2026-11-15: patch built over `framac-master-audit:3dff90f` (master `3dff90fc70`) and
installed. `main.c` needs `inc/value.h`, `helper.c` defines `helper`:

| Invocation | `master` `3dff90fc70` | Patched |
|---|---|---|
| `-n -E -Iinc -e "-g -O1" -o a.c main.c helper.c` | Frama-C gets `helper.c … -e-acsl-O-gmp-only … -ocode --`, aborts | Frama-C gets `main.c helper.c`, no GMP, `-ocode a.c` |
| `-n -o a.c -e "-g -O1" helper.c main.c` (here `main.c` has no include) | exit 0, Frama-C gets `main.c` only, with `-e-acsl-O-gmp-only` | exit 0, `helper.c main.c`, no GMP; `helper` in `a.c` |
| `-n -E "-I inc" -o b.c main.c` | `no input files` | builds |
| `-E -Iinc -e -Iinc -l "-L /usr/lib -lm" -o c.c -O c main.c` | `no input files` | builds and links; `c.e-acsl` exits 0 |
| New test `special/e-acsl-gcc-option-arguments.c`, `dev` run (`-e -g`) | `no input files` | pass |
| ptests `plugins/e-acsl/tests`, `dev` configuration (196 tests, each through `e-acsl-gcc`) | — | all pass |
| ptests `special`, default configuration | — | pass; only the new oracles added |
| `34.0~beta (Selenium)` | same as `master` | — |

`git diff --check` is clean except for the final empty line of the generated `gen_*.0.c` oracle.
`clang-format-19 --dry-run` passes on the test file. `make check-lint` / `make check-headers` were
not run (no `ocp-indent` or `headache` in the image).

Earlier validation of the same script change on `ad24dca`:

| Invocation | `master` | Patched |
|---|---|---|
| `-G clang -F "-rte" -e "-g -O1" -o … -O t t2.c` | `no input files` | builds; no `-e-acsl-O-gmp-only` |
| `-n -e "-g -O1" … t1.c t2.c` | Frama-C sees only `t2.c`, with `-e-acsl-O-gmp-only` | Frama-C sees `t1.c t2.c`, no GMP; `helper` present |
| `-n -E "-I inc" … inc_use.c` | `no input files` | builds |
| `-l "-L /usr/lib -lm" … t2.c` | `no input files` | builds and links |
| `-X --oexec-e-acsl=t_inst --zone-sizes=heap:128 -D … t2.c` | — | builds; `t_inst` runs, exit 0 |
| `--frama-c-extra=… --ocode=t4.c --oexec=t4 t1.c t2.c` | — | builds `t4` and `t4.e-acsl` from both files |
| `-n -o t5.c` (no input file) | `no input files` | `no input files` (unchanged) |

## Workaround

Pass joined forms only (`-Idir`, `-Ldir`). Replace `-g` with `-gline-tables-only` or `-g2`, and
keep spaces out of paths.
