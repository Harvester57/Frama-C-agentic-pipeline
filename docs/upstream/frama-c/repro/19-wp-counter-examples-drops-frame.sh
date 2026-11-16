#!/bin/sh
# Issue 19: [WP] a probe (-wp-counter-examples, or a 'probe' annotation)
# drops the hypothesis relating unchanged memory states, so a valid
# postcondition becomes unprovable.
#
# Images: framac-master-audit:3dff90f (master 3dff90fc70, before),
#         framac-analysis:fc34 (34.0~beta, same output), and the master image
#         with ../patches/19-wp-counter-examples-drops-frame.patch built and
#         installed (after). Needs Alt-Ergo (both images have it).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     19-wp-counter-examples-drops-frame.sh
#
# Output before (master 3dff90fc70; 34.0~beta prints the same):
#   ##### 19-wp-counter-examples-drops-frame.c (no option)
#   Prove: true.
#   ##### 19-wp-counter-examples-drops-frame.c -wp-counter-examples
#   Prove: Mptr_0[a] = Mptr_1[a].
#   [wp] [Timeout] typed_buf_reset_ensures_keep_ptr (Qed 2ms) (Alt-Ergo)
#   ##### 19-wp-counter-examples-drops-frame-probe.c (no option)
#   Prove: Mptr_0[a] = Mptr_1[a].
#   [wp] [Timeout] typed_buf_reset_ensures_keep_ptr (Qed 2ms) (Alt-Ergo)
#   RESULT: bug present
#
# Output after:
#   ##### 19-wp-counter-examples-drops-frame.c (no option)
#   Prove: true.
#   ##### 19-wp-counter-examples-drops-frame.c -wp-counter-examples
#   Prove: true.
#   [wp] Proved goals:    1 / 1
#   ##### 19-wp-counter-examples-drops-frame-probe.c (no option)
#   Prove: true.
#   [wp] Proved goals:    1 / 1
#   RESULT: fixed
#
# (The Qed times in the [Timeout] lines vary from run to run.)
set -u
B="-no-unicode -wp -wp-fct buf_reset -wp-prop keep_ptr -wp-cache none"
fail=0
run() { # $1: file, $2: extra option (may be empty)
  echo "##### $1 ${2:-(no option)}"
  # shellcheck disable=SC2086
  frama-c $1 $B ${2:-} -wp-prover none -wp-print 2>&1 | grep '^Prove:'
  if [ -n "${3:-}" ]; then
    # shellcheck disable=SC2086
    r=$(frama-c $1 $B ${2:-} -wp-prover alt-ergo -wp-timeout 5 2>&1 \
          | grep -e 'keep_ptr' -e 'Proved goals' | grep -e Timeout -e Unknown \
              -e 'Proved goals:    1 / 1' | head -1)
    echo "$r"
    case "$r" in *"1 / 1"*) ;; *) fail=1 ;; esac
  fi
}
run 19-wp-counter-examples-drops-frame.c ""
run 19-wp-counter-examples-drops-frame.c -wp-counter-examples prove
run 19-wp-counter-examples-drops-frame-probe.c "" prove
if [ "$fail" = 0 ]; then echo "RESULT: fixed"; exit 0
else echo "RESULT: bug present"; exit 1
fi
