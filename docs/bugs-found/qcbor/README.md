# Bugs Found in `QCBOR` (`laurencelundblade/QCBOR`)

- **Master Index:** [`../README.md`](../README.md)
- **Upstream Repository:** [https://github.com/laurencelundblade/QCBOR](https://github.com/laurencelundblade/QCBOR)
- **Evaluated Revisions:**
  - `master` branch: [`572a567d02bcfde42f5863f6a515131cc270798d`](https://github.com/laurencelundblade/QCBOR/tree/572a567d02bcfde42f5863f6a515131cc270798d) (`run-2`, `standard` profile)
  - `dev` (v2) branch: [`9bd08456d46ac5fbaa7822420fd3e25e0e9c486f`](https://github.com/laurencelundblade/QCBOR/tree/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f) (`run-3`, `deep` profile)
- **Scope:** `src/`, `inc/` (8 module slices)
- **Campaign Summary:**
  - **Confirmed Findings:** 3 (1 Medium, 2 Low)
  - **Rejected Candidates:** 5 on `master`, 1 on `dev`
  - **Assurance Summary:** 2,130 `Valid` properties discharged by Frama-C Eva across 8 modules (`31` ledger units discharged by Eva, `3` functions proven by WP on `master` and `2` on `dev`).

---

## Summary of Findings

| ID | Title | Location (`dev` v2 / `master`) | Property / CWE | Severity | Upstream Ticket | Status |
| :--- | :--- | :--- | :--- | :---: | :--- | :--- |
| [`QCBOR-01`](#qcbor-01-c11-signed-integer-overflow-negating-int64_min-in-qcbordecode_processbignumber) | C11 signed integer overflow negating `INT64_MIN` in `QCBORDecode_ProcessBigNumber` | [`src/qcbor_number_decode.c:1964`](https://github.com/laurencelundblade/QCBOR/blob/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f/src/qcbor_number_decode.c#L1964), [`:2008`](https://github.com/laurencelundblade/QCBOR/blob/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f/src/qcbor_number_decode.c#L2008) (`dev`) | `signed_overflow` (CWE-190) | **Medium** | Pending / Not yet filed | Confirmed (Unreported) |
| [`QCBOR-02`](#qcbor-02-c11-undefined-shift-by-negative-exponent-in-ieee754_doubletosingle) | C11 undefined right-shift by negative shift count in `IEEE754_DoubleToSingle` | [`src/ieee754.c:625`](https://github.com/laurencelundblade/QCBOR/blob/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f/src/ieee754.c#L625) (`dev`) / [`src/ieee754.c:666`](https://github.com/laurencelundblade/QCBOR/blob/572a567d02bcfde42f5863f6a515131cc270798d/src/ieee754.c#L666) (`master`) | `shift` (C11 6.5.7p3 / CWE-758) | **Low** | Pending / Not yet filed | Confirmed (Unreported) |
| [`QCBOR-03`](#qcbor-03-c11-undefined-shift-by-negative-exponent-in-ieee754_singletohalf) | C11 undefined right-shift by negative shift count in `IEEE754_SingleToHalf` | [`src/ieee754.c:466`](https://github.com/laurencelundblade/QCBOR/blob/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f/src/ieee754.c#L466) (`dev`) / [`src/ieee754.c:510`](https://github.com/laurencelundblade/QCBOR/blob/572a567d02bcfde42f5863f6a515131cc270798d/src/ieee754.c#L510) (`master`) | `shift` (C11 6.5.7p3 / CWE-758) | **Low** | Pending / Not yet filed | Confirmed (Unreported) |

---

## Detailed Findings

### `QCBOR-01`: C11 signed integer overflow negating `INT64_MIN` in `QCBORDecode_ProcessBigNumber`

| Field | Value |
| :--- | :--- |
| **Fingerprint** | `src/qcbor_number_decode.c#QCBORDecode_ProcessBigNumber::signed_overflow::e3d0c960fc` |
| **Status** | Confirmed (Unreported) |
| **Upstream Ticket** | Pending / Not yet filed |
| **Severity** | **Medium** (Arithmetic undefined behavior directly reachable from untrusted CBOR input when decoding decimal fractions or bigfloats with an `INT64_MIN` mantissa) |
| **Reachability** | `untrusted_surface` (`QCBORDecode_GetDecimalFractionBig` / `QCBORDecode_GetBigFloatBig` / `QCBORDecode_GetTDecimalFractionBigMantissa`) |
| **Location** | [`src/qcbor_number_decode.c:1964`](https://github.com/laurencelundblade/QCBOR/blob/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f/src/qcbor_number_decode.c#L1964) and [`src/qcbor_number_decode.c:2008`](https://github.com/laurencelundblade/QCBOR/blob/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f/src/qcbor_number_decode.c#L2008) (`QCBORDecode_ProcessBigNumber`) |
| **Failing Property** | `rte:signed_overflow`: `-9223372036854775807 <= Item.val.int64` (C11 6.5.3.3p3 / CWE-190) |

#### Description & Root Cause

When decoding a CBOR Decimal Fraction (Tag 4) or Bigfloat (Tag 5) through the big-mantissa decode APIs, a negative integer mantissa in the range $[-2^{63}, -1]$ is decoded as `QCBOR_TYPE_INT64` with `Item.val.int64` holding the signed 64-bit value, and passed to `QCBORDecode_ProcessBigNumber`.

For a CBOR negative integer encoding $-2^{63}$ (major type 1, argument `0x7fffffffffffffff`, which has value $-1 - \text{arg} = -9223372036854775808 = \text{INT64\_MIN}$), `Item.val.int64` is `INT64_MIN`. `QCBORDecode_ProcessBigNumber` then computes its magnitude via signed unary negation in two places:

```c
// src/qcbor_private.h:496
#define ABSOLUTE_VALUE(x) ((x) < 0 ? -(x) : (x))

// src/qcbor_number_decode.c:1963-1965
      case QCBOR_TYPE_INT64:
         uLen = QCBORDecode_Private_CountNonZeroBytes((uint64_t)ABSOLUTE_VALUE(Item.val.int64));
         break;

// src/qcbor_number_decode.c:2006-2010
      case QCBOR_TYPE_INT64:
         /* Offset of 1 for negative numbers already performed */
         uIntTmp = (uint64_t)(bIsNegative ? -Item.val.int64 : Item.val.int64);
         *pBigNumber = QCBORDecode_Private_UIntToBigNumber(uIntTmp, BigNumberBuf);
         break;
```

In both places, `-Item.val.int64` is evaluated in `int64_t` **before** casting to `uint64_t`. When `Item.val.int64 == INT64_MIN`, `-Item.val.int64` overflows `int64_t` (C11 6.5p5).

#### Minimal Standalone Reproducer

- **Triggering CBOR input (12 bytes, hex):**
  ```text
  c4 82 00 3b 7f ff ff ff ff ff ff ff
  ```
  - `c4`: Tag 4 (Decimal Fraction)
  - `82`: 2-element array `[exponent, mantissa]`
  - `00`: Exponent `0`
  - `3b 7f ff ff ff ff ff ff ff`: Negative integer $-1 - \text{0x7fffffffffffffff} = -2^{63}$ (`INT64_MIN`)

- **Pipeline E-ACSL replay result:**
  ```text
  E-ACSL: src/qcbor_number_decode.c:1964 assertion rte:signed_overflow '-9223372036854775807 <= Item.val.int64' failed.
  ```

- **Standalone C reproducer (`repro_qcbor_01.c`):**
  ```c
  #include <stdint.h>
  #include "qcbor/qcbor_decode.h"
  #include "qcbor/qcbor_spiffy_decode.h"

  int main(void) {
      static const uint8_t cbor[] = {
          0xc4, 0x82, 0x00, 0x3b,
          0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
      };
      uint8_t mantissa_buf[64];
      UsefulBufC mantissa;
      bool is_negative = false;
      int64_t exp = 0;

      QCBORDecodeContext ctx;
      QCBORDecode_Init(&ctx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(cbor), QCBOR_DECODE_MODE_NORMAL);
      QCBORDecode_GetDecimalFractionBig(&ctx, (UsefulBuf){mantissa_buf, sizeof(mantissa_buf)}, &mantissa, &is_negative, &exp);
      return 0;
  }
  ```

#### Proposed Fix

Perform the negation in `uint64_t` (`0ULL - (uint64_t)Item.val.int64`) so `INT64_MIN` produces `0x8000000000000000ULL` without signed overflow:

```diff
--- a/src/qcbor_number_decode.c
+++ b/src/qcbor_number_decode.c
@@ -1961,7 +1961,8 @@ QCBORDecode_ProcessBigNumber(QCBORDecodeContext *pMe,
          break;
 
       case QCBOR_TYPE_INT64:
-         uLen = QCBORDecode_Private_CountNonZeroBytes((uint64_t)ABSOLUTE_VALUE(Item.val.int64));
+         uLen = QCBORDecode_Private_CountNonZeroBytes(
+            bIsNegative ? (0ULL - (uint64_t)Item.val.int64) : (uint64_t)Item.val.int64);
          break;
 
       case QCBOR_TYPE_UINT64:
@@ -2005,7 +2006,7 @@ QCBORDecode_ProcessBigNumber(QCBORDecodeContext *pMe,
 
       case QCBOR_TYPE_INT64:
          /* Offset of 1 for negative numbers already performed */
-         uIntTmp = (uint64_t)(bIsNegative ? -Item.val.int64 : Item.val.int64);
+         uIntTmp = bIsNegative ? (0ULL - (uint64_t)Item.val.int64) : (uint64_t)Item.val.int64;
          *pBigNumber = QCBORDecode_Private_UIntToBigNumber(uIntTmp, BigNumberBuf);
          break;
```

---

### `QCBOR-02`: C11 undefined shift by negative exponent in `IEEE754_DoubleToSingle`

| Field | Value |
| :--- | :--- |
| **Fingerprint** | `src/ieee754.c#IEEE754_DoubleToSingle::shift::d355106f76` |
| **Status** | Confirmed (Unreported) |
| **Upstream Ticket** | Pending / Not yet filed |
| **Severity** | **Low** (C11 6.5.7p3 undefined behavior when converting any `double` that cannot be losslessly narrowed to a normal `float`, such as `1.1`) |
| **Reachability** | `internal_api` (called by `IEEE754_DoubleToSmaller` during preferred float serialization and on `dev` v2 by `QCBORDecode_Private_DoubleConformance` under `QCBOR_DECODE_MODE_ONLY_SHORTEST_FLOAT`) |
| **Location** | [`src/ieee754.c:625`](https://github.com/laurencelundblade/QCBOR/blob/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f/src/ieee754.c#L625) (`dev`) / [`src/ieee754.c:666`](https://github.com/laurencelundblade/QCBOR/blob/572a567d02bcfde42f5863f6a515131cc270798d/src/ieee754.c#L666) (`master`) (`IEEE754_DoubleToSingle`) |
| **Failing Property** | `rte:shift`: `0 <= nShiftAmount < 64` (C11 6.5.7p3 / CWE-758) |

#### Description & Root Cause

In `IEEE754_DoubleToSingle`, when a normal `double` cannot be losslessly represented as a normal single-precision `float` (either because its exponent is outside `[-126, 127]` or because `uDroppedBits != 0`, as with `1.1`), execution enters the `else` branch to check whether the number can be represented as a single-precision **subnormal**:

```c
// src/ieee754.c:623-629 (dev) / lines 664-670 (master)
nExponentDifference = -(nDoubleUnbiasedExponent - SINGLE_EXPONENT_MIN);
nShiftAmount        = nExponentDifference + (DOUBLE_NUM_SIGNIFICAND_BITS - SINGLE_NUM_SIGNIFICAND_BITS);
uSingleSignificand  = (uDoubleSignificand + (1ULL << DOUBLE_NUM_SIGNIFICAND_BITS)) >> nShiftAmount;

if(nDoubleUnbiasedExponent < SINGLE_EXPONENT_MIN &&
   nDoubleUnbiasedExponent >= SINGLE_EXPONENT_MIN - SINGLE_NUM_SIGNIFICAND_BITS &&
   uSingleSignificand << nShiftAmount == uDoubleSignificand + (1ULL << DOUBLE_NUM_SIGNIFICAND_BITS)) {
```

Because `uSingleSignificand = ... >> nShiftAmount` is evaluated **before** checking whether `nDoubleUnbiasedExponent` lies in the subnormal exponent window `[-149, -127]`, any non-convertible `double` with `nDoubleUnbiasedExponent > -97` (for example `1.1`, which has `nDoubleUnbiasedExponent == 0`) produces a negative `nShiftAmount` (`-97 - 0 = -97`), and any `double` with `nDoubleUnbiasedExponent < -160` produces `nShiftAmount >= 64`. Right-shifting by a negative count or by $\ge 64$ is undefined behavior under C11 6.5.7p3, even though the subsequent `if` condition discards `uSingleSignificand`.

#### Minimal Standalone Reproducer

- **Triggering 8-byte `double` input (`1.1`, IEEE 754 little-endian hex):**
  ```text
  9a 99 99 99 99 99 f1 3f
  ```
- **Pipeline E-ACSL & UBSan result:**
  ```text
  E-ACSL: src/ieee754.c:625 assertion rte/shift 0 <= nShiftAmount < 64 failed (nShiftAmount == -97).
  UBSan:  src/ieee754.c:625:85: runtime error: shift exponent -97 is negative
  ```
- **Standalone C reproducer (`repro_qcbor_02.c`):**
  ```c
  #include "ieee754.h"

  int main(void) {
      /* 1.1 has unbiased exponent 0 and non-zero dropped significand bits */
      IEEE754_DoubleToSmaller(1.1);
      return 0;
  }
  ```
- **Compile & Run:**
  ```sh
  clang -g -O1 -fsanitize=undefined -Iinc -Isrc src/ieee754.c repro_qcbor_02.c -o repro_qcbor_02
  ./repro_qcbor_02
  # Output:
  # src/ieee754.c:625:85: runtime error: shift exponent -97 is negative
  ```

#### Proposed Fix

Check that `nDoubleUnbiasedExponent` is within the single-subnormal exponent range before computing and executing the shift:

```diff
--- a/src/ieee754.c
+++ b/src/ieee754.c
@@ -620,16 +620,17 @@ IEEE754_DoubleToSingle(const double d)
           * to the exponent and 1 must be added in. See
           * https://en.wikipedia.org/wiki/Single-precision_floating-point_format#Exponent_encoding
           */
-         nExponentDifference = -(nDoubleUnbiasedExponent - SINGLE_EXPONENT_MIN);
-         nShiftAmount        = nExponentDifference + (DOUBLE_NUM_SIGNIFICAND_BITS - SINGLE_NUM_SIGNIFICAND_BITS);
-         uSingleSignificand  = (uDoubleSignificand + (1ULL << DOUBLE_NUM_SIGNIFICAND_BITS)) >> nShiftAmount;
-
          if(nDoubleUnbiasedExponent < SINGLE_EXPONENT_MIN &&
-            nDoubleUnbiasedExponent >= SINGLE_EXPONENT_MIN - SINGLE_NUM_SIGNIFICAND_BITS &&
-            uSingleSignificand << nShiftAmount == uDoubleSignificand + (1ULL << DOUBLE_NUM_SIGNIFICAND_BITS)) {
-            /* --- IS CONVERTABLE TO SINGLE SUBNORMAL --- */
-            Result.uSize  = IEEE754_UNION_IS_SINGLE;
-            Result.uValue = IEEE754_AssembleSingle(nIsNegative,
-                                                   uSingleSignificand,
-                                                   SINGLE_EXPONENT_ZERO);
-         } else {
+            nDoubleUnbiasedExponent >= SINGLE_EXPONENT_MIN - SINGLE_NUM_SIGNIFICAND_BITS) {
+            nExponentDifference = -(nDoubleUnbiasedExponent - SINGLE_EXPONENT_MIN);
+            nShiftAmount        = nExponentDifference + (DOUBLE_NUM_SIGNIFICAND_BITS - SINGLE_NUM_SIGNIFICAND_BITS);
+            uSingleSignificand  = (uDoubleSignificand + (1ULL << DOUBLE_NUM_SIGNIFICAND_BITS)) >> nShiftAmount;
+         }
+
+         if(nDoubleUnbiasedExponent < SINGLE_EXPONENT_MIN &&
+            nDoubleUnbiasedExponent >= SINGLE_EXPONENT_MIN - SINGLE_NUM_SIGNIFICAND_BITS &&
+            uSingleSignificand << nShiftAmount == uDoubleSignificand + (1ULL << DOUBLE_NUM_SIGNIFICAND_BITS)) {
+            /* --- IS CONVERTABLE TO SINGLE SUBNORMAL --- */
```

---

### `QCBOR-03`: C11 undefined shift by negative exponent in `IEEE754_SingleToHalf`

| Field | Value |
| :--- | :--- |
| **Fingerprint** | `src/ieee754.c#IEEE754_SingleToHalf::shift::ceaaa12428` |
| **Status** | Confirmed (Unreported) |
| **Upstream Ticket** | Pending / Not yet filed |
| **Severity** | **Low** (C11 6.5.7p3 undefined behavior when converting any `float` that cannot be losslessly narrowed to a normal half-precision float, such as `1.1f` or `1.0e30f`) |
| **Reachability** | `internal_api` (called by `IEEE754_FloatToSmallest` / `IEEE754_DoubleToSmaller` during preferred float serialization and on `dev` v2 by `QCBORDecode_Private_SingleConformance` under `QCBOR_DECODE_MODE_ONLY_SHORTEST_FLOAT`) |
| **Location** | [`src/ieee754.c:466`](https://github.com/laurencelundblade/QCBOR/blob/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f/src/ieee754.c#L466) (`dev`) / [`src/ieee754.c:510`](https://github.com/laurencelundblade/QCBOR/blob/572a567d02bcfde42f5863f6a515131cc270798d/src/ieee754.c#L510) (`master`) (`IEEE754_SingleToHalf`) |
| **Failing Property** | `rte:shift`: `0 <= nShiftAmount < 32` (C11 6.5.7p3 / CWE-758) |

#### Description & Root Cause

Identical in structure to [`QCBOR-02`](#qcbor-02-c11-undefined-shift-by-negative-exponent-in-ieee754_doubletosingle): in `IEEE754_SingleToHalf`, when a normal single-precision `float` cannot be converted to a normal half-precision float (`HALF_EXPONENT_MIN == -14`, `HALF_EXPONENT_MAX == 15`, or non-zero dropped significand bits), the `else` branch computes `nShiftAmount = -1 - nSingleUnbiasedExponent` and shifts a `uint32_t` right by `nShiftAmount` **before** checking whether `nSingleUnbiasedExponent` lies in the half-subnormal exponent range `[-24, -15]`:

```c
// src/ieee754.c:454-472 (dev) / lines 498-516 (master)
nExponentDifference = -(nSingleUnbiasedExponent - HALF_EXPONENT_MIN);
nShiftAmount = nExponentDifference + (SINGLE_NUM_SIGNIFICAND_BITS - HALF_NUM_SIGNIFICAND_BITS);

uHalfSignificand = (uSingleSignificand + (1 << SINGLE_NUM_SIGNIFICAND_BITS)) >> nShiftAmount;

if(nSingleUnbiasedExponent < HALF_EXPONENT_MIN &&
   nSingleUnbiasedExponent >= HALF_EXPONENT_MIN - HALF_NUM_SIGNIFICAND_BITS &&
   uHalfSignificand << nShiftAmount == uSingleSignificand + (1 << SINGLE_NUM_SIGNIFICAND_BITS)) {
```

For any non-convertible single-precision float with `nSingleUnbiasedExponent >= 0` (such as `1.1f`, where `nSingleUnbiasedExponent == 0` and `nShiftAmount == -1`, or `1.0e30f`, where `nShiftAmount == -100`), `nShiftAmount` is negative, triggering C11 6.5.7p3 undefined behavior on line 466 (`dev`) / line 510 (`master`).

#### Minimal Standalone Reproducer

- **Triggering 4-byte `float` input (`0x7a00007a`, or `1.1f` = `0x3f8ccccd`):**
  ```text
  7a 00 00 7a
  ```
- **Pipeline E-ACSL & UBSan result:**
  ```text
  E-ACSL: src/ieee754.c:466 assertion rte/shift 0 <= nShiftAmount < 32 failed, nShiftAmount: -100.
  UBSan:  src/ieee754.c:466:78: runtime error: shift exponent -100 is negative
  ```
- **Standalone C reproducer (`repro_qcbor_03.c`):**
  ```c
  #include "ieee754.h"

  int main(void) {
      /* 1.0e30f has unbiased exponent 99 -> nShiftAmount = -100 */
      IEEE754_FloatToSmallest(1.0e30f);
      return 0;
  }
  ```
- **Compile & Run:**
  ```sh
  clang -g -O1 -fsanitize=undefined -Iinc -Isrc src/ieee754.c repro_qcbor_03.c -o repro_qcbor_03
  ./repro_qcbor_03
  # Output:
  # src/ieee754.c:466:78: runtime error: shift exponent -100 is negative
  ```

#### Proposed Fix

Guard the subnormal shift calculation with the half-subnormal exponent range check (`[-24, -15]`):

```diff
--- a/src/ieee754.c
+++ b/src/ieee754.c
@@ -451,18 +451,19 @@ IEEE754_SingleToHalf(const uint32_t uSingle)
           * than this are normal and handled above. We're going to
           * shift the significand right by at least this amount.
           */
-         nExponentDifference = -(nSingleUnbiasedExponent - HALF_EXPONENT_MIN);
-
-         /* In addition to the shift based on the exponent's value,
-          * the single significand has to be shifted right to fit into
-          * a half-precision significand */
-         nShiftAmount = nExponentDifference + (SINGLE_NUM_SIGNIFICAND_BITS - HALF_NUM_SIGNIFICAND_BITS);
-
-         /* Must add 1 in to the possible significand because there is
-          * an implied 1 for normal values and not for subnormal
-          * values. See equations here:
-          * https://en.wikipedia.org/wiki/Single-precision_floating-point_format#Exponent_encoding
-          */
-         uHalfSignificand = (uSingleSignificand + (1 << SINGLE_NUM_SIGNIFICAND_BITS)) >> nShiftAmount;
+         if(nSingleUnbiasedExponent < HALF_EXPONENT_MIN &&
+            nSingleUnbiasedExponent >= HALF_EXPONENT_MIN - HALF_NUM_SIGNIFICAND_BITS) {
+            nExponentDifference = -(nSingleUnbiasedExponent - HALF_EXPONENT_MIN);
+            nShiftAmount = nExponentDifference + (SINGLE_NUM_SIGNIFICAND_BITS - HALF_NUM_SIGNIFICAND_BITS);
+            uHalfSignificand = (uSingleSignificand + (1 << SINGLE_NUM_SIGNIFICAND_BITS)) >> nShiftAmount;
+         }
 
          /* If only zero bits get shifted out, this can be converted
           * to subnormal */
```
