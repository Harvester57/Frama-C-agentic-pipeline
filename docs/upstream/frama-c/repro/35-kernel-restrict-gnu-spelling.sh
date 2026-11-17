#!/bin/sh
# Issue 35: [Kernel] the GNU spelling __restrict__ of the restrict qualifier is
# not a keyword of the C lexer, so it is a syntax error everywhere unless a
# Frama-C libc header such as <stddef.h> was included (they include features.h,
# which defines it as __restrict). "after a libc #include" force-includes
# Frama-C's <stddef.h>; "host headers" force-includes the system <stddef.h>.
#
# Images: framac-master-audit:9540804 (master 95408044f7, before),
#         framac-analysis:latest (34.0~beta, same output), and the master image
#         with ../patches/35-kernel-restrict-gnu-spelling.patch built and
#         installed (after).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     35-kernel-restrict-gnu-spelling.sh
#
# Output before (master 95408044f7; 34.0~beta prints the same):
#   --- positions 1-6: file scope, member, prototype, definition, block, cast
#   gcc   restrict:     ok ok ok ok ok ok
#   gcc   __restrict:   ok ok ok ok ok ok
#   gcc   __restrict__: ok ok ok ok ok ok
#   clang __restrict__: ok ok ok ok ok ok
#   frama-c restrict:     ok ok ok ok ok ok
#   frama-c __restrict:   ok ok ok ok ok ok
#   frama-c __restrict__: ERR ERR ERR ERR ERR ERR
#   frama-c __restrict__ after a libc #include: ok ok ok ok ok ok
#   frama-c __restrict__ host headers (gcc_x86_64 -no-frama-c-stdlib): ERR ERR ERR ERR ERR ERR
#   [kernel] 35-kernel-restrict-gnu-spelling.c:5: User Error:
#     syntax error:
#     Location: "35-kernel-restrict-gnu-spelling.c", line 5, before or at token: gp
#   --- unnamed __restrict__ parameter used as a name in the body
#   gcc: rejected
#   frama-c: accepted, printed as:
#   int get(int *__restrict__)
#   {
#     int __retres;
#     __retres = *__restrict__;
#   RESULT: bug present
#
# Output after:
#   --- positions 1-6: file scope, member, prototype, definition, block, cast
#   gcc   restrict:     ok ok ok ok ok ok
#   gcc   __restrict:   ok ok ok ok ok ok
#   gcc   __restrict__: ok ok ok ok ok ok
#   clang __restrict__: ok ok ok ok ok ok
#   frama-c restrict:     ok ok ok ok ok ok
#   frama-c __restrict:   ok ok ok ok ok ok
#   frama-c __restrict__: ok ok ok ok ok ok
#   frama-c __restrict__ after a libc #include: ok ok ok ok ok ok
#   frama-c __restrict__ host headers (gcc_x86_64 -no-frama-c-stdlib): ok ok ok ok ok ok
#   --- unnamed __restrict__ parameter used as a name in the body
#   gcc: rejected
#   frama-c: rejected
#   RESULT: fixed
set -u
src=35-kernel-restrict-gnu-spelling.c
uns=35-kernel-restrict-gnu-spelling-unnamed.c
tmp=${TMPDIR:-/tmp}/repro35.$$
mkdir -p "$tmp"
bad=0

row() { # $1: label, then a command taking -DR=... -DPOS=... as "$@"
  label=$1; shift
  line="$label"
  for pos in 1 2 3 4 5 6; do
    if "$@" "-DPOS=$pos" > "$tmp/log.$pos" 2>&1
    then line="$line ok"; else line="$line ERR"; fi
  done
  echo "$line"
}
fc() { # frama-c on the file with the -D options given
  frama-c -no-unicode "$@" "$src" -print -ocode "$tmp/out.c"
}
fcd() { fc -cpp-extra-args="$*"; }
fcn() { fc -machdep gcc_x86_64 -no-frama-c-stdlib -cpp-extra-args="$*"; }

echo "--- positions 1-6: file scope, member, prototype, definition, block, cast"
for r in "restrict:    " "__restrict:  " "__restrict__:"; do
  row "gcc   $r" \
    gcc -std=c99 -pedantic -Werror -fsyntax-only "-DR=${r%%:*}" "$src"
done
if command -v clang > /dev/null 2>&1; then
  row "clang __restrict__:" clang -std=c99 -fsyntax-only -DR=__restrict__ "$src"
fi
for r in "restrict:    " "__restrict:  " "__restrict__:"; do
  out=$(row "frama-c $r" fcd "-DR=${r%%:*}")
  echo "$out"
done
case $out in *ERR*) bad=1; cp "$tmp/log.1" "$tmp/first-error";; esac
row "frama-c __restrict__ after a libc #include:" \
  fcd "-DR=__restrict__ -include stddef.h"
row "frama-c __restrict__ host headers (gcc_x86_64 -no-frama-c-stdlib):" \
  fcn "-DR=__restrict__ -include stddef.h"
if [ -f "$tmp/first-error" ]; then
  grep -A2 'User Error' "$tmp/first-error"
fi

echo "--- unnamed __restrict__ parameter used as a name in the body"
if gcc -fsyntax-only "$uns" > /dev/null 2>&1
then echo "gcc: accepted"; else echo "gcc: rejected"; fi
if frama-c -no-unicode "$uns" -print -ocode "$tmp/uns.c" > /dev/null 2>&1
then
  echo "frama-c: accepted, printed as:"
  grep -v '^/\*' "$tmp/uns.c" | grep -v '^$' | head -4
  bad=1
else echo "frama-c: rejected"
fi
rm -rf "$tmp"
if [ $bad = 1 ]; then echo "RESULT: bug present"; exit 1; fi
echo "RESULT: fixed"
