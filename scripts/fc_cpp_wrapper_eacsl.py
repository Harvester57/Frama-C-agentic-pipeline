#!/usr/bin/env python3
"""
gcc `-wrapper` for the E-ACSL frontend only: fc_cpp_wrapper.py plus the `<==>` rewrite.

E-ACSL in Frama-C 35 aborts on `p1 <==> p2` when an operand holds a labelled term (`\\old`, `\\at`, or a
formal in an `ensures`): "labels pre-analysis was not performed on construct \\old(b)"
(docs/upstream/frama-c-eacsl-iff-labelled-term.md). This wrapper writes every `<==>` in an annotation as
`((p1) ==> (p2)) && ((p2) ==> (p1))` in the preprocessed text, so contracts already proved with `<==>`
(merged, carried forward, or in the target's headers) still build. WP and Eva use fc_cpp_wrapper.py and read
the contract as written. A separate script rather than a `-wrapper prog,arg` argument: e-acsl-gcc splits
flag values on commas.
"""

from __future__ import annotations

import sys

from fc_cpp_wrapper import run

if __name__ == "__main__":
    sys.exit(run(sys.argv[1:], iff=True))
