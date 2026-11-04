# Bugs Found in `minmea` (`kosma/minmea`)

- **Master Index:** [`../README.md`](../README.md)
- **Upstream Repository:** [https://github.com/kosma/minmea](https://github.com/kosma/minmea)
- **Evaluated Revision:** [`c43c9e7c5ed788122a9d8a5445679e1594f8a030`](https://github.com/kosma/minmea/tree/c43c9e7c5ed788122a9d8a5445679e1594f8a030)
- **Pipeline Profile:** `standard` (whole target)
- **Campaign Summary:**
  - **Confirmed Findings:** 3 (2 Medium, 1 Low)
  - **Rejected Candidates:** 1
  - **Assurance Summary:** 73.93% of RTE obligations discharged by Frama-C Eva with 0 `Invalid` alarms; `minmea_gettime` fully proven by WP (`1` unconditional proof, `6` proven under boundary assumptions).

---

## Summary of Findings

| ID | Title | Location | Property / CWE | Severity | Upstream Ticket | Status |
| :--- | :--- | :--- | :--- | :---: | :--- | :--- |
| [`MINMEA-01`](#minmea-01-unvalidated-zda-calendar-fields-cause-signed-integer-overflow-in-minmea_getdatetime) | Unvalidated ZDA calendar fields reach `minmea_getdatetime`, where `date->month - 1` overflows | [`minmea.c:656`](https://github.com/kosma/minmea/blob/c43c9e7c5ed788122a9d8a5445679e1594f8a030/minmea.c#L656) (`minmea_getdatetime`) | `signed_overflow` (CWE-190) | **Medium** | Pending / Not yet filed | Confirmed (Unreported) |
| [`MINMEA-02`](#minmea-02-absint_min-signed-overflow-in-minmea_parse_zda-bypasses-utc-offset-validation) | `abs(INT_MIN)` signed overflow in `minmea_parse_zda` defeats the timezone-offset range check | [`minmea.c:635`](https://github.com/kosma/minmea/blob/c43c9e7c5ed788122a9d8a5445679e1594f8a030/minmea.c#L635) (`minmea_parse_zda`) | `signed_overflow` (CWE-190 / CWE-20) | **Medium** | Pending / Not yet filed | Confirmed (Unreported) |
| [`MINMEA-03`](#minmea-03-unbounded-scale--10-signed-overflow-in-minmea_scan-fractional-field-parser) | Unbounded `scale *= 10` signed overflow in `minmea_scan` fractional (`'f'`) field parser | [`minmea.c:186`](https://github.com/kosma/minmea/blob/c43c9e7c5ed788122a9d8a5445679e1594f8a030/minmea.c#L186) (`minmea_scan`) | `signed_overflow` (CWE-190) | **Low** | Pending / Not yet filed | Confirmed (Unreported) |

---

## Detailed Findings

### `MINMEA-01`: Unvalidated ZDA calendar fields cause signed integer overflow in `minmea_getdatetime`

| Field | Value |
| :--- | :--- |
| **Fingerprint** | `minmea.c#minmea_getdatetime::signed_overflow::95a4d01721` |
| **Status** | Confirmed (Unreported) |
| **Upstream Ticket** | Pending / Not yet filed |
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

An NMEA `$GPZDA` sentence with `month` (or `year`) set to `-2147483648` (`INT_MIN`) is accepted as valid by `minmea_parse_zda` (`returns true`) and triggers signed integer overflow at `date->month - 1` (`minmea.c:656`) and `2000 + date->year - 1900` (`minmea.c:650`).

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
| **Status** | Confirmed (Unreported) |
| **Upstream Ticket** | Pending / Not yet filed |
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
| **Fingerprint** | `minmea.c#minmea_scan::signed_overflow::e0fa2b9da1` |
| **Status** | Confirmed (Unreported) |
| **Upstream Ticket** | Pending / Not yet filed |
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
