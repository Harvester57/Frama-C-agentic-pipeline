#!/bin/sh
# Frama-C libc: the getsockopt precondition `\valid(((char*)optval)+(0..))`
# is unsatisfiable (Eva: Invalid on a correct call; WP: aborts).
#
# Images: framac-master-audit:3dff90f (master 3dff90fc70, before),
#         the same image with the patch (after), framac-analysis:fc34 (34.0~beta).
# Command, from the repro directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> 04b-libc-getsockopt-unbounded-range.sh
#
# Output before the fix (master 3dff90fc70; 34.0~beta prints the same):
#   35.0~~dev (Bromine)
#   --- Eva, correct call (optval: 4-byte int, *optlen == 4)
#   [  Alarm  ]
#   NON TERMINATING FUNCTION
#   --- Eva, *optlen (8) larger than optval (4 bytes)
#   [  Alarm  ]
#   NON TERMINATING FUNCTION
#   --- WP (-wp-model Bytes), function get_rcvbuf
#   Invalid infinite range (global L_opt_402)+(0..)
#   [kernel] Plug-in wp aborted: invalid user input.
#
# Output after the fix:
#   35.0~~dev (Bromine)
#   --- Eva, correct call (optval: 4-byte int, *optlen == 4)
#   [  Valid  ]
#   r ∈ {-1; 0}
#   --- Eva, *optlen (8) larger than optval (4 bytes)
#   [  Alarm  ]
#   NON TERMINATING FUNCTION
#   --- WP (-wp-model Bytes), function get_rcvbuf
#   [wp] Proved goals:    8 / 8
set -u
src=04b-libc-getsockopt-unbounded-range.c
tmp=$(mktemp -d)
frama-c -version
eva() { # eva <log> [frama-c options]: status of optval_null_or_valid, end state
  log=$1; shift
  frama-c "$src" "$@" -eva -eva-msg-key=-summary -then -report > "$log" 2>&1
  grep "optval_null_or_valid'' at" "$log" | sed 's/ Instance of.*//'
  grep -E 'NON TERMINATING' "$log" | sed 's/^ *//' | sort -u
  grep -A3 'Values at end of function get_rcvbuf' "$log" | grep -E '^  r ' | sed 's/^ *//'
}
echo '--- Eva, correct call (optval: 4-byte int, *optlen == 4)'
eva "$tmp/eva.log"
echo '--- Eva, *optlen (8) larger than optval (4 bytes)'
eva "$tmp/eva8.log" -cpp-extra-args=-DOPTLEN=8
echo '--- WP (-wp-model Bytes), function get_rcvbuf'
frama-c "$src" -wp -wp-fct get_rcvbuf -wp-model Bytes -wp-timeout 10 > "$tmp/wp.log" 2>&1
grep -E 'infinite range|aborted|Proved goals' "$tmp/wp.log" | sed 's/^ *//'
rm -rf "$tmp"
