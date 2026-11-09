# e-acsl-gcc: option arguments are re-parsed as options (`-e "-g"` enables GMP and drops an input file, `-E "-I dir"` loses every input)

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).

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

- Reproduced with Frama-C `35.0~~dev (Bromine)`, built from `master` at `ad24dca` (2026-11-02), on
  Debian 13 (bash 5.2, util-linux `getopt`).
- `plugins/e-acsl/scripts/e-acsl-gcc` is byte-identical in `34.0~~dev (Selenium)`. The bug was
  first seen with 33.0.

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

## Proposed fix

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
+# themselves: each branch shifts its option (and argument), so option
+# arguments are never re-read as options.
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

## Validation of the proposed fix

Patched script on `ad24dca`, same container:

| Invocation | `master` | Patched |
|---|---|---|
| `-G clang -F "-rte" -e "-g -O1" -o … -O t t2.c` | `no input files` | builds; no `-e-acsl-O-gmp-only` |
| `-n -e "-g -O1" … t1.c t2.c` | Frama-C sees only `t2.c`, with `-e-acsl-O-gmp-only` | Frama-C sees `t1.c t2.c`, no GMP; `helper` present |
| `-n -E "-I inc" … inc_use.c` | `no input files` | builds |
| `-l "-L /usr/lib -lm" … t2.c` | `no input files` | builds and links |
| `-X --oexec-e-acsl=t_inst --zone-sizes=heap:128 -D … t2.c` | — | builds; `t_inst` runs, exit 0 |
| `--frama-c-extra=… --ocode=t4.c --oexec=t4 t1.c t2.c` | — | builds `t4` and `t4.e-acsl` from both files |
| `-n -o t5.c` (no input file) | `no input files` | `no input files` (unchanged) |

The E-ACSL test suite in its `dev` configuration, which runs `e-acsl-gcc` on every test, is
covered in the [validation summary](frama-c-e-acsl-issues.md#validation-of-the-proposed-fixes).

## Workaround

Pass joined forms only (`-Idir`, `-Ldir`). Replace `-g` with `-gline-tables-only` or `-g2`, and
keep spaces out of paths.
