I ran into the same overflow independently and tested this change. The rounding fix is correct, but `minmea_rescale()` still overflows in its other branch, on values the parser produces.

## The scale-down fix holds

With this PR's `minmea.h` on top of `master` (`c43c9e7`), built with `clang -fsanitize=undefined`:

- `{2147483647, 100}` rescaled to `10` returns `214748365`, with no UBSan report (`master` reports `2147483647 + 5` and returns `-214748364`).
- Against the `master` formula evaluated in 64 bits, the new code returns the same result for 9.6 million `{value, scale, new_scale}` triples with `scale > new_scale > 0`, including both `int_least32_t` limits and odd divisors (3, 7, 15).

That value is not artificial: `21474836.47` in any float field parses to `{2147483647, 100}`.

## The scale-up branch still overflows

`return f->value * (new_scale/f->scale);` is unchanged, and it overflows as soon as the product does not fit. A field without a decimal point parses to `{value, 1}`, so rescaling to `1000`, as `example.c` does for latitude, longitude and speed, overflows for any value above `2147483`:

```c
#include <stdio.h>
#include "minmea.h"

int main(void)
{
    struct minmea_sentence_rmc r;
    if (!minmea_parse_rmc(&r, "$GPRMC,081836,A,3751.65,S,14507.36,E,2147484,360.0,130998,011.3,E"))
        return 2;
    printf("speed = {%d, %d}\n", (int) r.speed.value, (int) r.speed.scale);
    printf("rescale(speed, 1000) = %d\n", (int) minmea_rescale(&r.speed, 1000));
    return 0;
}
```

```
$ clang -g -O1 -fsanitize=undefined minmea.c repro.c -o repro && ./repro
minmea.h:285:25: runtime error: signed integer overflow: 2147484 * 1000 cannot be represented in type 'int_least32_t' (aka 'int')
speed = {2147484, 1}
rescale(speed, 1000) = -2147483296
```

(Line 285 with this PR applied; line 276 on `master`. The checksum is omitted; `minmea_parse_rmc()` does not look at it.)

Not a memory-safety problem, but a caller gets a negative number for a positive field, with no way to tell.

## Suggestion

Here the result itself does not fit, so the function has to pick an answer. Saturating keeps the sign and needs no wider arithmetic, in line with the approach of this PR:

```diff
-    } else
-        return f->value * (new_scale/f->scale);
+    } else {
+        int_least32_t factor = new_scale / f->scale;
+        /* The product may not fit: saturate instead of overflowing. */
+        if (factor > 0 && f->value > INT_LEAST32_MAX / factor)
+            return INT_LEAST32_MAX;
+        if (factor > 0 && f->value < INT_LEAST32_MIN / factor)
+            return INT_LEAST32_MIN;
+        return f->value * factor;
+    }
```

Tested on top of this PR's header: the program above prints `2147483647` with no UBSan report; the result equals the 64-bit product clamped to `int_least32_t` for 9.6 million triples with `0 < scale < new_scale` (identical to `master` wherever the product fits); `master`'s `tests.c` passes under UBSan (38 checks). Two regression assertions that would fit next to yours:

```c
ck_assert_int_eq(minmea_rescale(&(struct minmea_float) { 2147484, 1 }, 1000), INT_LEAST32_MAX);
ck_assert_int_eq(minmea_rescale(&(struct minmea_float) { -2147484, 1 }, 1000), INT_LEAST32_MIN);
```

Whether to saturate or do something else is the maintainers' call. If you would rather keep this PR to the rounding fix, I can open a separate one for the scale-up branch.

Found with Frama-C and a UBSan driver in an LLM-assisted analysis pipeline; I ran the reproducer and the comparisons above by hand.
