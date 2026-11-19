# Bugs Found in `minmea` (`kosma/minmea`)

- **Master Index:** [`../README.md`](../README.md)
- **Upstream Repository:** [https://github.com/kosma/minmea](https://github.com/kosma/minmea)
- **Evaluated Revision:** [`c43c9e7c5ed788122a9d8a5445679e1594f8a030`](https://github.com/kosma/minmea/tree/c43c9e7c5ed788122a9d8a5445679e1594f8a030)
- **Pipeline Profile:** `standard` (whole target)
- **Campaign Summary:**
  - **Confirmed Findings:** 4 (2 Medium, 2 Low); `MINMEA-04` was confirmed by hand after minmea run-1 (2026-11-14), not by the campaign summarized below
  - **Rejected Candidates:** 1
  - **Assurance Summary:** 73.93% of RTE obligations discharged by Frama-C Eva with 0 `Invalid` alarms; `minmea_gettime` fully proven by WP (`1` unconditional proof, `6` proven under boundary assumptions).

---

## Summary of Findings

| ID | Title | Location | Property / CWE | Severity | Upstream Ticket | Status |
| :--- | :--- | :--- | :--- | :---: | :--- | :--- |
| [`MINMEA-01`](#minmea-01-unvalidated-zda-calendar-fields-cause-signed-integer-overflow-in-minmea_getdatetime) | Unvalidated ZDA calendar fields reach `minmea_getdatetime`, where `date->month - 1` overflows | [`minmea.c:656`](https://github.com/kosma/minmea/blob/c43c9e7c5ed788122a9d8a5445679e1594f8a030/minmea.c#L656) (`minmea_getdatetime`) | `signed_overflow` (CWE-190) | **Medium** | Filed by us on 2026-11-14: [kosma/minmea#107](https://github.com/kosma/minmea/issues/107), fix in [kosma/minmea#108](https://github.com/kosma/minmea/pull/108) (open) | Reported |
| [`MINMEA-02`](#minmea-02-absint_min-signed-overflow-in-minmea_parse_zda-bypasses-utc-offset-validation) | `abs(INT_MIN)` signed overflow in `minmea_parse_zda` defeats the timezone-offset range check | [`minmea.c:635`](https://github.com/kosma/minmea/blob/c43c9e7c5ed788122a9d8a5445679e1594f8a030/minmea.c#L635) (`minmea_parse_zda`) | `signed_overflow` (CWE-190 / CWE-20) | **Medium** | Reported by a third party: [kosma/minmea#106](https://github.com/kosma/minmea/issues/106) (2026-11-01; closed on 2026-11-17 with no fix on `master`) | Reported (third party) |
| [`MINMEA-03`](#minmea-03-unbounded-scale--10-signed-overflow-in-minmea_scan-fractional-field-parser) | Unbounded `scale *= 10` signed overflow in `minmea_scan` fractional (`'f'`) field parser | [`minmea.c:186`](https://github.com/kosma/minmea/blob/c43c9e7c5ed788122a9d8a5445679e1594f8a030/minmea.c#L186) (`minmea_scan`) | `signed_overflow` (CWE-190) | **Low** | Reported by third parties: [kosma/minmea#56](https://github.com/kosma/minmea/issues/56) (open, 2020), [kosma/minmea#106](https://github.com/kosma/minmea/issues/106) (closed 2026-11-17); fix proposed in [kosma/minmea#75](https://github.com/kosma/minmea/pull/75) (open) | Reported (third party) |
| [`MINMEA-04`](#minmea-04-signed-integer-overflow-in-minmea_rescale-on-parser-produced-values) | Unchecked 32-bit arithmetic in `minmea_rescale` overflows on values the parser accepts | [`minmea.h:274`](https://github.com/kosma/minmea/blob/c43c9e7c5ed788122a9d8a5445679e1594f8a030/minmea.h#L274), [`minmea.h:276`](https://github.com/kosma/minmea/blob/c43c9e7c5ed788122a9d8a5445679e1594f8a030/minmea.h#L276) (`minmea_rescale`) | `signed_overflow` (CWE-190) | **Low** | Partly reported: [kosma/minmea#105](https://github.com/kosma/minmea/pull/105) (open PR) fixes the rounding site (line 274) only; the multiplication (line 276) was reported by us on 2026-11-14 in a [comment on that pull request](https://github.com/kosma/minmea/pull/105#issuecomment-6882277543) | Reported (confirmed by hand) |

### Upstream status (checked 2026-11-14, updated 2026-11-19)

**Update, 2026-11-19:** `master` is still at `c43c9e7`, so none of the four is fixed. [kosma/minmea#107](https://github.com/kosma/minmea/issues/107), [kosma/minmea#108](https://github.com/kosma/minmea/pull/108), [kosma/minmea#105](https://github.com/kosma/minmea/pull/105), [kosma/minmea#56](https://github.com/kosma/minmea/issues/56) and [kosma/minmea#75](https://github.com/kosma/minmea/pull/75) are open. [kosma/minmea#106](https://github.com/kosma/minmea/issues/106) was closed as completed on 2026-11-17 without a commit.

All issues and pull requests of `kosma/minmea` (numbers 1 to 106) were listed and the relevant ones read. Upstream `master` is still at the evaluated revision `c43c9e7`, so none of the four is fixed.

- **`MINMEA-01`:** no issue or pull request mentions `minmea_getdatetime`, the month arithmetic or unvalidated ZDA calendar fields. Filed by us the same day as [kosma/minmea#107](https://github.com/kosma/minmea/issues/107), with the fix in [kosma/minmea#108](https://github.com/kosma/minmea/pull/108).
- **`MINMEA-02`:** reported on 2026-11-01 in [kosma/minmea#106](https://github.com/kosma/minmea/issues/106) (item 2), with the same trigger sentence and the same fix.
- **`MINMEA-03`:** reported in 2020 in [kosma/minmea#56](https://github.com/kosma/minmea/issues/56), again in [kosma/minmea#106](https://github.com/kosma/minmea/issues/106) (item 1); [kosma/minmea#75](https://github.com/kosma/minmea/pull/75) proposes a fix and has been open since 2023. [kosma/minmea#104](https://github.com/kosma/minmea/issues/104) reports a related wrong value in the same parser.
- **`MINMEA-04`:** [kosma/minmea#105](https://github.com/kosma/minmea/pull/105) (open) fixes the rounding addition at line 274 by rounding on the remainder. It leaves the multiplication at line 276 unchanged, and nothing else reports that site.

**Not found by the pipeline:** [kosma/minmea#102](https://github.com/kosma/minmea/issues/102) and #106 refer to CVE-2026-29974, an unbounded copy by the `'s'` format specifier of `minmea_scan` into the caller's buffer, said to be unfixed on `master` ([kosma/minmea#98](https://github.com/kosma/minmea/pull/98) proposes a fix). No pipeline run on minmea raised it. The code is present at `c43c9e7` (`minmea.c`, `case 's'`: `*buf++ = *field++` with no length). No built-in `minmea_parse_*` function uses the `'s'` specifier (only `tests.c` does), so it is reachable only from an application that calls the public `minmea_scan` with `'s'`; the pipeline's harness never did. Not reproduced here.

---

## Detailed Findings

### `MINMEA-01`: Unvalidated ZDA calendar fields cause signed integer overflow in `minmea_getdatetime`

| Field | Value |
| :--- | :--- |
| **Fingerprint** | `minmea.c#minmea_getdatetime::signed_overflow::b7030b5601` |
| **Status** | Reported |
| **Upstream Ticket** | Filed by us on 2026-11-14: [kosma/minmea#107](https://github.com/kosma/minmea/issues/107), fix in [kosma/minmea#108](https://github.com/kosma/minmea/pull/108) (open) |
| **Severity** | **Medium** (C11 signed integer overflow reachable from untrusted NMEA 0183 sentence input; corrupts `struct tm` handed to `timegm()`) |
| **Reachability** | `untrusted_surface` |
| **Location** | [`minmea.c:656`](https://github.com/kosma/minmea/blob/c43c9e7c5ed788122a9d8a5445679e1594f8a030/minmea.c#L656) (`minmea_getdatetime`) and [`minmea.c:619-641`](https://github.com/kosma/minmea/blob/c43c9e7c5ed788122a9d8a5445679e1594f8a030/minmea.c#L619-L641) (`minmea_parse_zda`) |
| **Failing Property** | `signed_overflow`: `-2147483648 - 1` cannot be represented in type `int` (C11 6.5p5 / CWE-190) |

#### Description & Root Cause

`minmea_parse_zda` parses five integer (`'i'`) fields into `struct minmea_sentence_zda` via `minmea_scan(sentence, "tTiiiii", ...)`. Inside `minmea_scan` (`minmea.c:223`), the `'i'` specifier converts the field with `strtol(field, &endptr, 10)` and narrows the result into an `int`. While `minmea_parse_zda` checks `hour_offset` and `minute_offset`, it performs **no range validation** on `frame->date.day`, `frame->date.month`, or `frame->date.year`.

When the parsed `frame->date` is passed to the documented consumer `minmea_getdatetime(&tm, &frame.date, &frame.time)` (or `minmea_gettime`), `minmea_getdatetime` only checks `date->year == -1` before executing calendar arithmetic:

```c
// minmea.c:643-663
int minmea_getdatetime(struct tm *tm, const struct minmea_date *date, const struct minmea_time *time_)
{
    if (date->year == -1 || time_->hours == -1)
        return -1;

    memset(tm, 0, sizeof(*tm));
    if (date->year < 80) {
        tm->tm_year = 2000 + date->year - 1900; // 2000-2079 (also overflows near INT_MIN)
    } else if (date->year >= 1900) {
        tm->tm_year = date->year - 1900;        // 4 digit year, use directly
    } else {
        tm->tm_year = date->year;               // 1980-1999
    }
    tm->tm_mon = date->month - 1;               // <-- UB when date->month == INT_MIN
    tm->tm_mday = date->day;
```

An NMEA `$GPZDA` sentence with `month` set to `-2147483648` (`INT_MIN`) is accepted as valid by `minmea_parse_zda` (`returns true`) and triggers signed integer overflow at `date->month - 1` (`minmea.c:656`).

**Correction (2026-11-14):** the year arithmetic does not overflow. `2000 + date->year - 1900` with `date->year == INT_MIN` evaluates to `INT_MIN + 100`, and the other two branches need `date->year >= 80`. The comment on line 650 in the excerpt above and the year checks in the proposed fix below are not needed for the overflow. The fix prepared for upstream ([`../../upstream/minmea/README.md`](../../upstream/minmea/README.md)) validates the month and day in `minmea_getdatetime` only.

#### Minimal Standalone Reproducer

- **Triggering NMEA sentence (36 bytes):**
  ```text
  $GPZDA,000000.00,0,-2147483648,0,0,0
  ```
- **Standalone C reproducer (`repro_minmea_01.c`):**
  ```c
  #include <time.h>
  #include "minmea.h"

  int main(void) {
      const char *sentence = "$GPZDA,000000.00,0,-2147483648,0,0,0";
      struct minmea_sentence_zda zda;
      struct tm tm;
      if (minmea_parse_zda(&zda, sentence)) {
          minmea_getdatetime(&tm, &zda.date, &zda.time);
      }
      return 0;
  }
  ```
- **Compile & Run:**
  ```sh
  clang -g -O1 -fsanitize=undefined minmea.c repro_minmea_01.c -o repro_minmea_01
  ./repro_minmea_01
  # Output:
  # minmea.c:656:29: runtime error: signed integer overflow: -2147483648 - 1 cannot be represented in type 'int'
  ```

#### Proposed Fix

Validate the calendar fields both when produced in `minmea_parse_zda` and when consumed in `minmea_getdatetime`:

```diff
--- a/minmea.c
+++ b/minmea.c
@@ -636,6 +636,11 @@ bool minmea_parse_zda(struct minmea_sentence_zda *frame, const char *sentence)
       frame->minute_offset > 59 ||
       frame->minute_offset < 0)
       return false;
+  // check calendar fields (NMEA 0183 valid ranges)
+  if (frame->date.year < 0 || frame->date.year > 9999 ||
+      frame->date.month < 0 || frame->date.month > 12 ||
+      frame->date.day < 0 || frame->date.day > 31)
+      return false;
 
   return true;
 }
@@ -644,6 +649,10 @@ int minmea_getdatetime(struct tm *tm, const struct minmea_date *date, const struct minmea_time *time_)
 {
     if (date->year == -1 || time_->hours == -1)
         return -1;
+    if (date->year < -1 || date->year > 9999 ||
+        date->month < -1 || date->month > 12 ||
+        date->day < -1 || date->day > 31)
+        return -1;
 
     memset(tm, 0, sizeof(*tm));
     if (date->year < 80) {
```

---

### `MINMEA-02`: `abs(INT_MIN)` signed overflow in `minmea_parse_zda` bypasses UTC offset validation

| Field | Value |
| :--- | :--- |
| **Fingerprint** | `minmea.c#minmea_parse_zda::signed_overflow::7c3a91d0f2` |
| **Status** | Reported (third party) |
| **Upstream Ticket** | Reported by a third party: [kosma/minmea#106](https://github.com/kosma/minmea/issues/106) (2026-11-01; closed on 2026-11-17 with no fix on `master`) |
| **Severity** | **Medium** (C11 signed integer overflow reachable from untrusted NMEA input; also bypasses the `\|hour_offset\| <= 13` validation check on two's-complement targets) |
| **Reachability** | `untrusted_surface` |
| **Location** | [`minmea.c:635`](https://github.com/kosma/minmea/blob/c43c9e7c5ed788122a9d8a5445679e1594f8a030/minmea.c#L635) (`minmea_parse_zda`) |
| **Failing Property** | `signed_overflow`: negation of `-2147483648` cannot be represented in type `int` (C11 7.22.6.1p2 / CWE-190 / CWE-20) |

#### Description & Root Cause

`minmea_parse_zda` validates the local-zone hours field (`frame->hour_offset`) using `abs(frame->hour_offset) > 13`:

```c
// minmea.c:634-639
  // check offsets
  if (abs(frame->hour_offset) > 13 ||
      frame->minute_offset > 59 ||
      frame->minute_offset < 0)
      return false;
```

Because `minmea_scan`'s `'i'` specifier narrows `strtol(field, &endptr, 10)` into an `int` without range checking, a ZDA sentence with an hour offset of `-2147483648` (`INT_MIN`) sets `frame->hour_offset = INT_MIN`. Calling `abs(INT_MIN)` invokes undefined behavior in C11 because `-INT_MIN` is not representable in signed 32-bit `int`. Furthermore, on standard two's-complement hardware where `abs(INT_MIN)` wraps to `INT_MIN` (`-2147483648`), `abs(frame->hour_offset) > 13` evaluates to `false`, **bypassing the range check** and causing `minmea_parse_zda` to return `true` with `frame->hour_offset == -2147483648`.

#### Minimal Standalone Reproducer

- **Triggering NMEA sentence (43 bytes):**
  ```text
  $GPZDA,201530.00,04,07,2002,-2147483648,0\r\n
  ```
- **Standalone C reproducer (`repro_minmea_02.c`):**
  ```c
  #include <assert.h>
  #include "minmea.h"

  int main(void) {
      const char *sentence = "$GPZDA,201530.00,04,07,2002,-2147483648,0\r\n";
      struct minmea_sentence_zda zda;
      bool ok = minmea_parse_zda(&zda, sentence);
      assert(!ok); // Fails without sanitizer when abs(INT_MIN) wraps to negative
      return 0;
  }
  ```
- **Compile & Run:**
  ```sh
  clang -g -O1 -fsanitize=undefined minmea.c repro_minmea_02.c -o repro_minmea_02
  ./repro_minmea_02
  # Output:
  # minmea.c:635:7: runtime error: negation of -2147483648 cannot be represented in type 'int'; cast to an unsigned type to negate this value to itself
  ```

#### Proposed Fix

Replace `abs(frame->hour_offset) > 13` with explicit signed range comparisons:

```diff
--- a/minmea.c
+++ b/minmea.c
@@ -633,7 +633,8 @@ bool minmea_parse_zda(struct minmea_sentence_zda *frame, const char *sentence)
 
   // check offsets
-  if (abs(frame->hour_offset) > 13 ||
+  if (frame->hour_offset < -13 ||
+      frame->hour_offset > 13 ||
       frame->minute_offset > 59 ||
       frame->minute_offset < 0)
       return false;
```

---

### `MINMEA-03`: Unbounded `scale *= 10` signed overflow in `minmea_scan` fractional field parser

| Field | Value |
| :--- | :--- |
| **Fingerprint** | `minmea.c#minmea_scan::signed_overflow::d8e58750af` |
| **Status** | Reported (third party) |
| **Upstream Ticket** | Reported by third parties: [kosma/minmea#56](https://github.com/kosma/minmea/issues/56) (open, 2020), [kosma/minmea#106](https://github.com/kosma/minmea/issues/106) (closed 2026-11-17); fix proposed in [kosma/minmea#75](https://github.com/kosma/minmea/pull/75) (open) |
| **Severity** | **Low** (C11 signed integer overflow reachable from any NMEA sentence parser that scans a floating-point `'f'` field; corrupts the fixed-point scale of the parsed field) |
| **Reachability** | `untrusted_surface` |
| **Location** | [`minmea.c:186`](https://github.com/kosma/minmea/blob/c43c9e7c5ed788122a9d8a5445679e1594f8a030/minmea.c#L186) (`minmea_scan`) |
| **Failing Property** | `signed_overflow`: `1000000000 * 10` cannot be represented in type `int` / `int_least32_t` (C11 6.5p5 / CWE-190) |

#### Description & Root Cause

In `minmea_scan`'s floating-point (`'f'`) field handler (`minmea.c:160-216`), digits are accumulated into `int_least32_t value` while `int_least32_t scale` tracks the power-of-10 denominator after the decimal point `'.'`. Line 174 checks whether `value` would overflow before multiplying by 10, and truncates extra fractional precision (`break`) if so:

```c
// minmea.c:171-187
int digit = *field - '0';
if (value == -1)
    value = 0;
if (value > (INT_LEAST32_MAX-digit) / 10) {
    /* we ran out of bits, what do we do? */
    if (scale) {
        /* truncate extra precision */
        break;
    } else {
        /* integer overflow. bail out. */
        goto parse_error;
    }
}
value = (10 * value) + digit;
if (scale)
    scale *= 10; // <-- Unbounded when leading fractional digits are 0
```

When a fractional field has leading zeros after the decimal point (for example `.0012345678` or `.2123456789`), `value` stays below `(INT_LEAST32_MAX - digit) / 10` on the 10th fractional digit (`value == 212345678 <= 214748363`), while `scale` has already reached $10^9$ (`1000000000`). Multiplying `scale *= 10` on the 10th fractional digit evaluates `1000000000 * 10 = 10000000000`, overflowing 32-bit signed `int_least32_t` (`INT_LEAST32_MAX == 2147483647`). Because every NMEA sentence parser with floating-point fields (`GGA`, `RMC`, `GBS`, `GLL`, `GST`, `GSV`, `VTG`, `ZDA`) delegates to `minmea_scan`, any sentence with 10 fractional digits and a small numerator triggers this overflow.

#### Minimal Standalone Reproducer

- **Triggering NMEA sentence (29 bytes):**
  ```text
  $GPGBS,,6,,0,,,,.2123456789,,
  ```
- **Standalone C reproducer (`repro_minmea_03.c`):**
  ```c
  #include "minmea.h"

  int main(void) {
      const char *sentence = "$GPGBS,,6,,0,,,,.2123456789,,";
      struct minmea_sentence_gbs gbs;
      minmea_parse_gbs(&gbs, sentence);
      return 0;
  }
  ```
- **Compile & Run:**
  ```sh
  clang -g -O1 -fsanitize=undefined minmea.c repro_minmea_03.c -o repro_minmea_03
  ./repro_minmea_03
  # Output:
  # minmea.c:186:39: runtime error: signed integer overflow: 1000000000 * 10 cannot be represented in type 'int'
  ```

#### Proposed Fix

Bound `scale` alongside `value` before multiplying by 10 so extra fractional digits are truncated cleanly:

```diff
--- a/minmea.c
+++ b/minmea.c
@@ -171,7 +171,8 @@ bool minmea_scan(const char *sentence, const char *format, ...)
                             int digit = *field - '0';
                             if (value == -1)
                                 value = 0;
-                            if (value > (INT_LEAST32_MAX-digit) / 10) {
+                            if (value > (INT_LEAST32_MAX-digit) / 10 ||
+                                (scale && scale > INT_LEAST32_MAX / 10)) {
                                 /* we ran out of bits, what do we do? */
                                 if (scale) {
                                     /* truncate extra precision */
```

---

### `MINMEA-04`: Signed integer overflow in `minmea_rescale` on parser-produced values

| Field | Value |
| :--- | :--- |
| **Fingerprint** | `minmea.h#minmea_rescale::signed_overflow::e02d0e78e8` |
| **Status** | Confirmed by hand on 2026-11-14; reported in a comment on the open pull request. The pipeline run that raised it (minmea run-1) left it `needs_validation`, because the module harness never calls this header inline. Not in `benchmark/manifest.json`. |
| **Upstream Ticket** | Partly reported: [kosma/minmea#105](https://github.com/kosma/minmea/pull/105) (open PR) fixes the rounding site (line 274) only; the multiplication (line 276) was reported by us on 2026-11-14 in a [comment on that pull request](https://github.com/kosma/minmea/pull/105#issuecomment-6882277543) |
| **Severity** | **Low** (C11 signed integer overflow on a value the parser accepts; the caller gets a wrong, sign-flipped number. No memory effect inside minmea.) |
| **Reachability** | `untrusted_surface` for the value; the overflow needs the application to call `minmea_rescale` on it, as the target's own `example.c` does |
| **Location** | [`minmea.h:274`](https://github.com/kosma/minmea/blob/c43c9e7c5ed788122a9d8a5445679e1594f8a030/minmea.h#L274) and [`minmea.h:276`](https://github.com/kosma/minmea/blob/c43c9e7c5ed788122a9d8a5445679e1594f8a030/minmea.h#L276) (`minmea_rescale`) |
| **Failing Property** | `signed_overflow`: `2147484 * 1000` and `2147483647 + 5` cannot be represented in type `int_least32_t` (C11 6.5p5 / CWE-190) |

#### Description & Root Cause

`minmea_rescale` converts a fixed-point `{value, scale}` to another scale in 32-bit arithmetic, with no check that the result fits:

```c
// minmea.h:267-277
static inline int_least32_t minmea_rescale(const struct minmea_float *f, int_least32_t new_scale)
{
    if (f->scale == 0)
        return 0;
    if (f->scale == new_scale)
        return f->value;
    if (f->scale > new_scale)
        return (f->value + ((f->value > 0) - (f->value < 0)) * f->scale/new_scale/2) / (f->scale/new_scale); // <-- rounding term added to value
    else
        return f->value * (new_scale/f->scale); // <-- unchecked multiplication
}
```

`minmea_scan` accepts any `'f'` field whose digits fit `int_least32_t` (`minmea.c:174`), so the parser hands out values up to `2147483647` at any scale:

- **Line 276 (scale up):** a field without a decimal point parses to `{value, 1}`. Rescaling to `1000` overflows for every `value > 2147483`. `example.c:30-32` rescales latitude, longitude and speed to `1000`.
- **Line 274 (scale down):** the rounding term is added before the division. `21474836.47` parses to `{2147483647, 100}`; rescaling to `10` computes `2147483647 + 5`.

Both calls respect the documented contract (`new_scale` cannot be zero). With wrapping arithmetic the function returns a negative number for a positive input.

A separate, misuse-only defect was seen while testing: a negative `new_scale` larger in magnitude than `scale` makes the divisor `f->scale/new_scale` zero (`{1, 1}` rescaled to `-10`), an integer division by zero. The contract does not exclude negative scales, but no parser output leads there with a positive `new_scale`. The proposed fix does not address it.

#### Minimal Standalone Reproducer

- **Triggering NMEA sentences:**
  ```text
  $GPRMC,081836,A,3751.65,S,14507.36,E,2147484,360.0,130998,011.3,E
  $GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,21474836.47,M,46.9,M,,
  ```
- **Standalone C reproducer (`repro_minmea_04.c`):**
  ```c
  #include <stdio.h>
  #include "minmea.h"

  int main(void) {
      struct minmea_sentence_rmc r;
      if (!minmea_parse_rmc(&r, "$GPRMC,081836,A,3751.65,S,14507.36,E,2147484,360.0,130998,011.3,E"))
          return 2;
      printf("rescale(speed, 1000) = %d\n", (int) minmea_rescale(&r.speed, 1000));

      struct minmea_sentence_gga g;
      if (!minmea_parse_gga(&g, "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,21474836.47,M,46.9,M,,"))
          return 3;
      printf("rescale(altitude, 10) = %d\n", (int) minmea_rescale(&g.altitude, 10));
      return 0;
  }
  ```
- **Compile & Run** (clang 19.1.7, image `framac-analysis:latest`, 2026-11-14):
  ```sh
  clang -g -O1 -fsanitize=undefined minmea.c repro_minmea_04.c -o repro_minmea_04
  ./repro_minmea_04
  # Output:
  # minmea.h:276:25: runtime error: signed integer overflow: 2147484 * 1000 cannot be represented in type 'int_least32_t' (aka 'int')
  # minmea.h:274:26: runtime error: signed integer overflow: 2147483647 + 5 cannot be represented in type 'int'
  # rescale(speed, 1000) = -2147483296
  # rescale(altitude, 10) = -214748364
  ```
  Without a sanitizer (`clang -O2`) the program prints the same two negative results and exits 0. Built with `gcc -ftrapv` it aborts (exit 134).

#### Proposed Fix

Compute in 64 bits and saturate. Saturation is a policy choice for upstream; the function has no error return.

```diff
--- a/minmea.h
+++ b/minmea.h
@@ -266,14 +266,21 @@ int minmea_gettime(struct timespec *ts, const struct minmea_date *date, const st
  */
 static inline int_least32_t minmea_rescale(const struct minmea_float *f, int_least32_t new_scale)
 {
+    int_least64_t result;
     if (f->scale == 0)
         return 0;
     if (f->scale == new_scale)
         return f->value;
     if (f->scale > new_scale)
-        return (f->value + ((f->value > 0) - (f->value < 0)) * f->scale/new_scale/2) / (f->scale/new_scale);
+        result = ((int_least64_t) f->value + ((f->value > 0) - (f->value < 0)) * f->scale/new_scale/2) / (f->scale/new_scale);
     else
-        return f->value * (new_scale/f->scale);
+        result = (int_least64_t) f->value * (new_scale/f->scale);
+    /* The result may not fit the return type: saturate instead of overflowing. */
+    if (result > INT_LEAST32_MAX)
+        return INT_LEAST32_MAX;
+    if (result < INT_LEAST32_MIN)
+        return INT_LEAST32_MIN;
+    return (int_least32_t) result;
 }
```

Tested on 2026-11-14 with the patched header:

- The reproducer runs clean under UBSan and prints `2147483647` and `214748365`.
- The target's own `tests.c` passes under UBSan (`Checks: 38, Failures: 0, Errors: 0`).
- A differential test against the original formula evaluated in 64 bits, over 18.6 million `{value, scale, new_scale}` triples, shows no mismatch: equal results wherever the original does not overflow, the clamped result elsewhere. Triples with a zero divisor (see above) were skipped.
