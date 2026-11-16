# [e-acsl-gcc] Option arguments are read again as options: `-e "-g -O1"` enables GMP and drops an input file, `-E "-I inc"` fails with "no input files"

<!-- Everything below this line is the issue description. -->

### Summary

`e-acsl-gcc` splits the value of `-e`, `-E`, `-l` and `-F` on whitespace and parses the words again as its own options. So `-e "-g -O1"` turns on GMP mode and drops the first input file, and `-E "-I inc"` or `-l "-L dir -lm"` fail with "no input files".

### Steps to reproduce the issue

```sh
mkdir inc
echo '#define VALUE 1' > inc/value.h
printf '#include "value.h"\nint main(void) { return VALUE - 1; }\n' > main.c
echo 'int helper(int x) { return x + 1; }' > helper.c

e-acsl-gcc -n -E -Iinc -e "-g -O1" -o a.c main.c helper.c
e-acsl-gcc -n -E "-I inc" -o b.c main.c
e-acsl-gcc -E -Iinc -e -Iinc -l "-L /usr/lib -lm" -o c.c -O c main.c
```

Each command passes an ordinary compiler, preprocessor or linker flag in the argument of `-e`,
`-E` or `-l`: debug info, a separated include path, a separated library path.

### Expected behaviour

The three commands succeed. In the first one, Frama-C gets `main.c helper.c` and `-ocode a.c`, and
`-g -O1` is passed to the compiler.

### Actual behaviour

```text
$ e-acsl-gcc -n -E -Iinc -e "-g -O1" -o a.c main.c helper.c
++ ... -no-frama-c-stdlib helper.c -e-acsl -e-acsl-O-gmp-only -then-last -print -ocode --
[kernel] User Error: option `-ocode' requires a string as argument.
e-acsl-gcc: fatal error: aborted by Frama-C

$ e-acsl-gcc -n -E "-I inc" -o b.c main.c
e-acsl-gcc: fatal error: no input files

$ e-acsl-gcc -E -Iinc -e -Iinc -l "-L /usr/lib -lm" -o c.c -O c main.c
e-acsl-gcc: fatal error: no input files
```

(the `++` line is the Frama-C command echoed by e-acsl-gcc, shortened.) In the first command, the
`-g` of `-g -O1` turned on `-e-acsl-O-gmp-only`, `main.c` was dropped and `-ocode` lost its
argument. In the other two, `-I` (`--frama-c`) and `-L` (`--frama-c-stdlib`) shifted the
arguments.

With another option order, the run succeeds silently without the first input file (here `main.c`
is `int main(void) { return 0; }`):

```text
$ e-acsl-gcc -n -o a.c -e "-g -O1" helper.c main.c; echo "exit=$?"
++ ... -no-frama-c-stdlib main.c -e-acsl -e-acsl-O-gmp-only -then-last -print -ocode a.c
exit=0
$ grep -c 'int helper' a.c
0
```

**Cause.** In `plugins/e-acsl/scripts/e-acsl-gcc` (master `3dff90fc70`), after
`eval set -- "$ARGS"` (line 439), the options are walked with an unquoted loop (lines 442-444):

```sh
for i in $@
do
  case "$i" in
```

while each `case` branch `shift`s the real positional parameters, and a final `shift` (line 814)
drops the `--` that getopt put before the input files. The word list of the `for` loop is split on
whitespace once, when the loop starts, so each word inside an option argument is matched against
the option patterns again. When a word equals an e-acsl-gcc option, its branch runs: it changes a
setting and shifts the positional parameters out of step, and the final `shift` then drops an
input file. Trace of the first command: after getopt the parameters are
`-n -E '-Iinc' -e '-g -O1' -o 'a.c' -- 'main.c' 'helper.c'`; the loop visits `-g` (from inside
the `-e` argument), which sets the GMP option and shifts `-o` away; when the loop reaches the word
`-o`, its branch shifts `a.c` away and takes `--` as the output name; the final `shift` then drops
`main.c`.

Joined forms (`-Iinc`, `-L/usr/lib`) work, which is why the examples of `e-acsl-gcc -h` do not
show the problem; arguments that contain spaces cannot be passed reliably at all.

**Fix.** Loop on the positional parameters themselves (`while [ $# -gt 0 ]` and `case "$1"`). Each
branch already shifts its option and its argument; a `--)` branch ends the loop and replaces the
trailing `shift`. A merge request with a fix follows.

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 3dff90fc70; also 34.0~beta (Selenium)
- Plug-in used: E-ACSL (`e-acsl-gcc`)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

Same behaviour on 34.0~beta (Selenium) and on master `3dff90fc70` (bash 5.2, util-linux
`getopt`).

Workaround: only pass joined forms (`-Idir`, `-Ldir`), and no argument word that equals a short
e-acsl-gcc option (for instance `-g2` instead of `-g`).

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
