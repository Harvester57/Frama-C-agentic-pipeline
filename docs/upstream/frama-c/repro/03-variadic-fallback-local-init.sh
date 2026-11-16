#!/bin/sh
# Variadic: a call to a variadic function in a local initializer is printed
# with the generated fixed-arity name, so the printed program does not link.
#
# Images: framac-master-audit:3dff90f (master 3dff90fc70, before),
#         the same image with the patch (after), framac-analysis:fc34 (34.0~beta).
# Command, from the repro directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> 03-variadic-fallback-local-init.sh
#
# Output before the fix (master 3dff90fc70; 34.0~beta prints the same):
#   35.0~~dev (Bromine)
#   --- frama-c -no-frama-c-stdlib -print: calls in main
#     int fd = open_fallback_1((char const *)*(argv + 0),00);
#     int fl = fcntl_fallback_1(fd,3);
#   --- gcc on the printed program
#   undefined reference to `fcntl_fallback_1'
#   undefined reference to `open_fallback_1'
#   link: FAILED
#
# Output after the fix:
#   35.0~~dev (Bromine)
#   --- frama-c -no-frama-c-stdlib -print: calls in main
#     int fd = open((char const *)*(argv + 0),00); /* open_fallback_1 */
#     int fl = fcntl(fd,3); /* fcntl_fallback_1 */
#   --- gcc on the printed program
#   link: OK
set -u
src=03-variadic-fallback-local-init.c
tmp=$(mktemp -d)
frama-c -version
echo '--- frama-c -no-frama-c-stdlib -print: calls in main'
frama-c -no-frama-c-stdlib "$src" -print -ocode "$tmp/printed.c" > "$tmp/fc.log" 2>&1 \
  || { cat "$tmp/fc.log"; exit 2; }
sed -n '/^int main/,/^}/p' "$tmp/printed.c" | grep -E 'open|fcntl'
echo '--- gcc on the printed program'
if gcc -w "$tmp/printed.c" -o "$tmp/printed" > "$tmp/gcc.log" 2>&1; then
  echo 'link: OK'
else
  grep -o "undefined reference to [^ ]*" "$tmp/gcc.log" | sort -u
  echo 'link: FAILED'
fi
rm -rf "$tmp"
