# Bugs Found in `QCBOR` (`laurencelundblade/QCBOR`)

- **Master Index:** [`../README.md`](../README.md)
- **Upstream Repository:** [https://github.com/laurencelundblade/QCBOR](https://github.com/laurencelundblade/QCBOR)
- **Evaluated Revisions:**
  - `master` branch: [`572a567d02bcfde42f5863f6a515131cc270798d`](https://github.com/laurencelundblade/QCBOR/tree/572a567d02bcfde42f5863f6a515131cc270798d) (`run-2`, `standard` profile)
  - `dev` (v2) branch: [`9bd08456d46ac5fbaa7822420fd3e25e0e9c486f`](https://github.com/laurencelundblade/QCBOR/tree/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f) (`run-3`, `deep` profile; then `run-5` and `run-6`, whose verdicts were re-judged by hand in [`../../runs/2026-11-09-qcbor-run5-assessment.md`](../../runs/2026-11-09-qcbor-run5-assessment.md) and [`../../runs/2026-11-15-qcbor-run6-findings-assessment.md`](../../runs/2026-11-15-qcbor-run6-findings-assessment.md))
- **Scope:** `src/`, `inc/` (8 module slices)
- **Campaign Summary:**
  - **Confirmed Findings:** 9 (2 Medium, 7 Low): `QCBOR-01` to `QCBOR-03` from runs 2 and 3, `QCBOR-04` to `QCBOR-09` from the run-5 and run-6 re-assessments. Upstream status checked on 2026-11-19.
  - **Rejected Candidates:** 5 on `master`, 1 on `dev`
  - **Assurance Summary:** 2,130 `Valid` properties discharged by Frama-C Eva across 8 modules (`31` ledger units discharged by Eva, `3` functions proven by WP on `master` and `2` on `dev`).

---

## Summary of Findings

| ID | Title | Location (`dev` v2 / `master`) | Property / CWE | Severity | Upstream Ticket | Status |
| :--- | :--- | :--- | :--- | :---: | :--- | :--- |
| [`QCBOR-01`](#qcbor-01-c11-signed-integer-overflow-negating-int64_min-in-qcbordecode_processbignumber) | C11 signed integer overflow negating `INT64_MIN` in `QCBORDecode_ProcessBigNumber` | [`src/qcbor_number_decode.c:1964`](https://github.com/laurencelundblade/QCBOR/blob/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f/src/qcbor_number_decode.c#L1964), [`:2008`](https://github.com/laurencelundblade/QCBOR/blob/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f/src/qcbor_number_decode.c#L2008) (`dev`) | `signed_overflow` (CWE-190) | **Medium** | Reported privately by email on 2026-11-04 (with patch); still open on `dev` `19c3367` | Reported |
| [`QCBOR-02`](#qcbor-02-c11-undefined-shift-by-negative-exponent-in-ieee754_doubletosingle) | C11 undefined right-shift by negative shift count in `IEEE754_DoubleToSingle` | [`src/ieee754.c:625`](https://github.com/laurencelundblade/QCBOR/blob/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f/src/ieee754.c#L625) (`dev`) / [`src/ieee754.c:666`](https://github.com/laurencelundblade/QCBOR/blob/572a567d02bcfde42f5863f6a515131cc270798d/src/ieee754.c#L666) (`master`) | `shift` (C11 6.5.7p3 / CWE-758) | **Low** | Reported privately by email on 2026-11-04; public as [laurencelundblade/QCBOR#434](https://github.com/laurencelundblade/QCBOR/issues/434) (third party), fixed on `dev` by [laurencelundblade/QCBOR#438](https://github.com/laurencelundblade/QCBOR/pull/438) (merged 2026-11-15); 1.x `master` unfixed | Fixed on `dev` |
| [`QCBOR-03`](#qcbor-03-c11-undefined-shift-by-negative-exponent-in-ieee754_singletohalf) | C11 undefined right-shift by negative shift count in `IEEE754_SingleToHalf` | [`src/ieee754.c:466`](https://github.com/laurencelundblade/QCBOR/blob/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f/src/ieee754.c#L466) (`dev`) / [`src/ieee754.c:510`](https://github.com/laurencelundblade/QCBOR/blob/572a567d02bcfde42f5863f6a515131cc270798d/src/ieee754.c#L510) (`master`) | `shift` (C11 6.5.7p3 / CWE-758) | **Low** | Reported privately by email on 2026-11-04; public as [laurencelundblade/QCBOR#434](https://github.com/laurencelundblade/QCBOR/issues/434) (third party), fixed on `dev` by [laurencelundblade/QCBOR#438](https://github.com/laurencelundblade/QCBOR/pull/438) (merged 2026-11-15); 1.x `master` unfixed | Fixed on `dev` |
| [`QCBOR-04`](#qcbor-04-positive-big-numbers-encoded-with-qcbor_encode_as_borrowed-come-out-negative) | Positive big numbers encoded with `QCBOR_ENCODE_AS_BORROWED` come out negative | `src/qcbor_number_encode.c:404` | Wrong output (CWE-682) | **Medium** | [#439](https://github.com/laurencelundblade/QCBOR/issues/439), fix [#445](https://github.com/laurencelundblade/QCBOR/pull/445) merged 2026-11-18 | Fixed on `dev` |
| [`QCBOR-05`](#qcbor-05-a-negative-zero-big-number-is-encoded-as-1-or-264) | A negative zero big number is encoded as −1 or −2^64 | `src/qcbor_number_encode.c:384-407` | Wrong output (CWE-682) | **Low** | [#440](https://github.com/laurencelundblade/QCBOR/issues/440), fix [#446](https://github.com/laurencelundblade/QCBOR/pull/446) merged 2026-11-18 | Fixed on `dev` |
| [`QCBOR-06`](#qcbor-06-usefuloutbuf_compare-reads-outside-the-buffer-for-out-of-range-offsets-and-lengths) | `UsefulOutBuf_Compare` reads outside the buffer for out-of-range offsets and lengths | `src/UsefulBuf.c:742-757` | `mem_access` (CWE-125 / CWE-823) | **Low** | [#441](https://github.com/laurencelundblade/QCBOR/issues/441), fix [#447](https://github.com/laurencelundblade/QCBOR/pull/447) merged 2026-11-18 | Fixed on `dev` |
| [`QCBOR-07`](#qcbor-07-epoch-date-and-days-getters-overwrite-the-callers-output-with-an-indeterminate-value-on-error) | Epoch date and days getters overwrite the caller's output with an indeterminate value on error | `src/qcbor_tag_decode.c:893`, `:919`, `:945`, `:966`, `:992`, `:1018` | `initialization` (CWE-908) | **Low** | [#442](https://github.com/laurencelundblade/QCBOR/issues/442), fix [#448](https://github.com/laurencelundblade/QCBOR/pull/448) merged 2026-11-18 | Fixed on `dev` |
| [`QCBOR-08`](#qcbor-08-qcborencode_encodehead-with-uminlen-above-8-writes-before-the-callers-buffer) | `QCBOREncode_EncodeHead` with `uMinLen` above 8 writes before the caller's buffer | `src/qcbor_main_encode.c:470` (`dev`) / `src/qcbor_encode.c:468` (1.x) | `index_bound` (CWE-129 / CWE-787) | **Low** | [#443](https://github.com/laurencelundblade/QCBOR/issues/443), fix [#449](https://github.com/laurencelundblade/QCBOR/pull/449) merged 2026-11-18; 1.x [#451](https://github.com/laurencelundblade/QCBOR/pull/451) open | Fixed on `dev`; 1.x open |
| [`QCBOR-09`](#qcbor-09-consuming-a-truncated-array-or-map-overwrites-unextnestlevel-with-an-uninitialized-byte) | Consuming a truncated array or map overwrites `uNextNestLevel` with an uninitialized byte | `src/qcbor_main_decode.c:2116` (`dev`) / `src/qcbor_decode.c:3175` (1.x) | `initialization` (CWE-908) | **Low** | [#444](https://github.com/laurencelundblade/QCBOR/issues/444), fix [#450](https://github.com/laurencelundblade/QCBOR/pull/450) merged 2026-11-18; 1.x [#452](https://github.com/laurencelundblade/QCBOR/pull/452) open | Fixed on `dev`; 1.x open |

---

## Detailed Findings

### `QCBOR-01`: C11 signed integer overflow negating `INT64_MIN` in `QCBORDecode_ProcessBigNumber`

| Field | Value |
| :--- | :--- |
| **Fingerprint** | `src/qcbor_number_decode.c#QCBORDecode_ProcessBigNumber::signed_overflow::e3d0c960fc` |
| **Status** | Reported |
| **Upstream Ticket** | Reported privately to the maintainer by email on 2026-11-04, with a patch, following QCBOR's `SECURITY.md`. Still present on `dev` `19c3367` (2026-11-15). Rebased patch and follow-up: [`../../upstream/qcbor/09-processbignumber-int64-min.md`](../../upstream/qcbor/09-processbignumber-int64-min.md) |
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
| **Status** | Fixed on `dev` |
| **Upstream Ticket** | Reported privately to the maintainer by email on 2026-11-04, with a patch. Filed publicly by a third party as [laurencelundblade/QCBOR#434](https://github.com/laurencelundblade/QCBOR/issues/434); the maintainer's fix for `dev` is [laurencelundblade/QCBOR#438](https://github.com/laurencelundblade/QCBOR/pull/438) (merged on 2026-11-15; checked clean against our reproducer on 2026-11-15). `master` (1.x) is not covered by #438. |
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
| **Status** | Fixed on `dev` |
| **Upstream Ticket** | Reported privately to the maintainer by email on 2026-11-04, with a patch. Filed publicly by a third party as [laurencelundblade/QCBOR#434](https://github.com/laurencelundblade/QCBOR/issues/434); the maintainer's fix for `dev` is [laurencelundblade/QCBOR#438](https://github.com/laurencelundblade/QCBOR/pull/438) (merged on 2026-11-15; checked clean against our reproducer on 2026-11-15). `master` (1.x) is not covered by #438. |
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

---

### `QCBOR-04`: Positive big numbers encoded with `QCBOR_ENCODE_AS_BORROWED` come out negative

| Field | Value |
| :--- | :--- |
| **Fingerprint** | None. The pipeline missed it; found by hand while re-assessing `run-5` ([`../../runs/2026-11-09-qcbor-run5-assessment.md`](../../runs/2026-11-09-qcbor-run5-assessment.md)). |
| **Status** | Fixed on `dev` |
| **Upstream Ticket** | Filed by us on 2026-11-15: [laurencelundblade/QCBOR#439](https://github.com/laurencelundblade/QCBOR/issues/439); fix [laurencelundblade/QCBOR#445](https://github.com/laurencelundblade/QCBOR/pull/445) merged on 2026-11-18. Not in 1.x. Draft: [`../../upstream/qcbor/02-bignum-positive-borrowed-sign.md`](../../upstream/qcbor/02-bignum-positive-borrowed-sign.md) |
| **Severity** | **Medium** (silent data corruption: the receiver decodes a different number, with the opposite sign) |
| **Reachability** | `public_api` (any application that encodes big numbers with `QCBOR_ENCODE_AS_BORROWED`, or builds with `QCBOR_ENCODE_CONFIG_ONLY_PREFERRED_BIG_NUMBERS`) |
| **Location** | [`src/qcbor_number_encode.c:404`](https://github.com/laurencelundblade/QCBOR/blob/19c3367c0bf7db3ffcc8bc5626d7740dc5b8a76e/src/qcbor_number_encode.c#L404) (`QCBOREncode_Private_AddTBigNumberMain`, `dev` `19c3367`) |
| **Failing Property** | Functional: wrong CBOR output, no error set (CWE-682) |

#### Description & Root Cause

`QCBOREncode_Private_AddTBigNumberMain()` calls `QCBOREncode_AddTBigNumberRaw(pMe, false, uTagRequirement, BigNumberNLZ)`, but the prototype is `(pCtx, uTagRequirement, bNegative, BigNumber)`. `false` (0, `QCBOR_ENCODE_AS_TAG`) becomes the tag requirement and `uTagRequirement` becomes `bNegative`. With `QCBOR_ENCODE_AS_BORROWED` (1) the number gets a tag 3 (negative big number) it should not have. Calling the public `AddTBigNumberRaw()` also runs its guard for the preferred-only configuration, which then refuses a big number that is in fact the preferred form.

| Call | Expected | Actual |
| :--- | :--- | :--- |
| `AddTBigNumberNoPreferred(BORROWED, +258)` | `42 01 02` | `c3 42 01 02` (−259) |
| `AddTBigNumber(BORROWED, +2^64)` | `49 01 00 00 00 00 00 00 00 00` | `c3 49 01 00 …` (−2^64−1) |
| `ONLY_PREFERRED_BIG_NUMBERS`: `AddTBigNumber(TAG, +2^64)` | `c2 49 01 00 …` | `QCBOR_ERR_NOT_PREFERRED` |

#### Minimal Standalone Reproducer

```c
#include <stdio.h>
#include "qcbor/qcbor_encode.h"

int main(void)
{
   static const uint8_t a258[]   = {0x01, 0x02};       /* +258 */
   static const uint8_t expect[] = {0x42, 0x01, 0x02}; /* h'0102', no tag */
   UsefulBuf_MAKE_STACK_UB(Out, 16);
   QCBOREncodeContext E;
   UsefulBufC Enc;

   QCBOREncode_Init(&E, Out);
   QCBOREncode_AddTBigNumberNoPreferred(&E, QCBOR_ENCODE_AS_BORROWED, false,
                                        UsefulBuf_FROM_BYTE_ARRAY_LITERAL(a258));
   if(QCBOREncode_Finish(&E, &Enc) != QCBOR_SUCCESS) {
      return 2;
   }
   if(UsefulBuf_Compare(Enc, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(expect))) {
      printf("BUG: +258 encoded with a negative tag\n");
      return 1;
   }
   printf("OK\n");
   return 0;
}
```

#### Fix

Merged upstream in [laurencelundblade/QCBOR#445](https://github.com/laurencelundblade/QCBOR/pull/445): the arguments are passed in the prototype's order, and the internal call no longer goes through the public function's usage guard. Our patch: [`../../upstream/qcbor/patches/public/0001-Fix-encoding-of-positive-big-numbers-that-are-not-ty.patch`](../../upstream/qcbor/patches/public/0001-Fix-encoding-of-positive-big-numbers-that-are-not-ty.patch).

---

### `QCBOR-05`: A negative zero big number is encoded as −1 or −2^64

| Field | Value |
| :--- | :--- |
| **Fingerprint** | None. Noticed by hand from a crash verifier's side note while re-assessing `run-5`. |
| **Status** | Fixed on `dev` |
| **Upstream Ticket** | Filed by us on 2026-11-15: [laurencelundblade/QCBOR#440](https://github.com/laurencelundblade/QCBOR/issues/440); fix [laurencelundblade/QCBOR#446](https://github.com/laurencelundblade/QCBOR/pull/446) merged on 2026-11-18. Not in 1.x. Draft: [`../../upstream/qcbor/03-bignum-negative-zero.md`](../../upstream/qcbor/03-bignum-negative-zero.md) |
| **Severity** | **Low** (degenerate input that still occurs naturally, such as a sign-and-magnitude −0; the output is a large wrong number and nothing reports it) |
| **Reachability** | `public_api` (encode API, with data the application chooses) |
| **Location** | [`src/qcbor_number_encode.c:384-407`](https://github.com/laurencelundblade/QCBOR/blob/19c3367c0bf7db3ffcc8bc5626d7740dc5b8a76e/src/qcbor_number_encode.c#L384-L407) (`QCBOREncode_Private_AddTBigNumberMain`, `dev` `19c3367`) |
| **Failing Property** | Functional: wrong CBOR output, no error set (CWE-682) |

#### Description & Root Cause

`QCBOREncode_AddTBigNumber()` and `QCBOREncode_AddTBigNumberNoPreferred()` accept `bNegative = true` with a magnitude of zero and apply CBOR's offset of one for negative numbers to it. On the preferred path `uInt--` turns 0 into `UINT64_MAX`, encoded as a type 1 integer (−2^64); on the non-preferred path an empty magnitude goes out as a tag 3 big number with no bytes (−1). The test rows named "0 and error for no negative 0" have no negative expectation, so this was never checked.

| Call | Expected | Actual |
| :--- | :--- | :--- |
| `AddTBigNumber(TAG, negative, empty)` | `00` | `3b ff ff ff ff ff ff ff ff` (−2^64) |
| `AddTBigNumberNoPreferred(TAG, negative, empty)` | `c2 40` | `c3 40` (−1) |

#### Minimal Standalone Reproducer

```c
#include <stdio.h>
#include "qcbor/qcbor_encode.h"

int main(void)
{
   static const uint8_t aPreferredZero[] = {0x00};   /* 0 */
   const UsefulBufC Empty = {"", 0};                 /* the big number zero */
   UsefulBuf_MAKE_STACK_UB(Out, 16);
   QCBOREncodeContext E;
   UsefulBufC Enc;

   QCBOREncode_Init(&E, Out);
   QCBOREncode_AddTBigNumber(&E, QCBOR_ENCODE_AS_TAG, true, Empty);
   if(QCBOREncode_Finish(&E, &Enc) != QCBOR_SUCCESS) {
      return 2;
   }
   if(UsefulBuf_Compare(Enc, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(aPreferredZero))) {
      printf("BUG: negative zero not encoded as 0\n");
      return 1;
   }
   printf("OK\n");
   return 0;
}
```

#### Fix

Merged upstream in [laurencelundblade/QCBOR#446](https://github.com/laurencelundblade/QCBOR/pull/446): a zero magnitude ignores `bNegative` and encodes as zero. Our patch: [`../../upstream/qcbor/patches/public/0002-Encode-a-negative-zero-big-number-as-zero.patch`](../../upstream/qcbor/patches/public/0002-Encode-a-negative-zero-big-number-as-zero.patch).

---

### `QCBOR-06`: `UsefulOutBuf_Compare` reads outside the buffer for out-of-range offsets and lengths

| Field | Value |
| :--- | :--- |
| **Fingerprint** | `src/UsefulBuf.c#UsefulOutBuf_Compare::mem_access::b939358da2` (`run-5`); `0e34c586b3`, `22aa038aa3` (`run-6`, the same missing bounds check) |
| **Status** | Fixed on `dev` |
| **Upstream Ticket** | Filed by us on 2026-11-15: [laurencelundblade/QCBOR#441](https://github.com/laurencelundblade/QCBOR/issues/441); fix [laurencelundblade/QCBOR#447](https://github.com/laurencelundblade/QCBOR/pull/447) merged on 2026-11-18 after one review round. 1.x has no `UsefulOutBuf_Compare()`. Draft: [`../../upstream/qcbor/05-usefuloutbuf-compare-offsets.md`](../../upstream/qcbor/05-usefuloutbuf-compare-offsets.md) |
| **Severity** | **Low** (API hardening and a documentation fix; the pipeline's `medium` was corrected in the run-6 assessment) |
| **Reachability** | `public_api` (`UsefulBuf` API only; QCBOR's own caller, map sorting, passes offsets from its own output) |
| **Location** | [`src/UsefulBuf.c:742-757`](https://github.com/laurencelundblade/QCBOR/blob/19c3367c0bf7db3ffcc8bc5626d7740dc5b8a76e/src/UsefulBuf.c#L742-L757) (`dev` `19c3367`) |
| **Failing Property** | `mem_access`: out-of-bounds read and pointer overflow (CWE-125, CWE-823; C11 6.5.6p8) |

#### Description & Root Cause

`UsefulBuf.h` promises that `UsefulOutBuf_Compare()` never reads beyond the buffer, "regardless of the provided offsets". The implementation adds the offsets and lengths to the base pointer before checking them:

```c
p1Start = pBase + uStart1;
p2Start = pBase + uStart2;
p1End   = p1Start + uLen1;
p2End   = p2Start + uLen2;
...
for(p1 = p1Start, p2 = p2Start;
    p1 < pEnd && p2 < pEnd && p1 < p1End && p2 < p2End;
    p1++, p2++) {
```

An offset near `SIZE_MAX` wraps to just before the buffer and the loop reads there; a length near `SIZE_MAX` wraps the end pointer so the loop never runs and equal strings compare unequal. The `@return` documentation also has the sign backwards.

#### Minimal Standalone Reproducer

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "qcbor/UsefulBuf.h"

int main(void)
{
   UsefulOutBuf OB;
   uint8_t *pStorage = malloc(16);

   UsefulOutBuf_Init(&OB, (UsefulBuf){pStorage, 16});
   UsefulOutBuf_AppendData(&OB, "abcd", 4);
   /* ASan: heap-buffer-overflow, READ of size 1, one byte before the allocation */
   printf("%d\n", UsefulOutBuf_Compare(&OB, SIZE_MAX, 2, 0, 2));
   free(pStorage);
   return 0;
}
```

#### Fix

Merged upstream in [laurencelundblade/QCBOR#447](https://github.com/laurencelundblade/QCBOR/pull/447): the comparison works on offsets clamped to the data length instead of on pointers, and the documentation is corrected. Our patch: [`../../upstream/qcbor/patches/public/0004-Make-UsefulOutBuf_Compare-safe-for-any-offset-and-le.patch`](../../upstream/qcbor/patches/public/0004-Make-UsefulOutBuf_Compare-safe-for-any-offset-and-le.patch).

---

### `QCBOR-07`: Epoch date and days getters overwrite the caller's output with an indeterminate value on error

| Field | Value |
| :--- | :--- |
| **Fingerprint** | `src/qcbor_tag_decode.c#QCBORDecode_GetTEpochDate::initialization::745871f887`, `src/qcbor_tag_decode.c#QCBORDecode_GetTEpochDays::initialization::f982f8f015` (`run-5` and `run-6`; the in-map variants were the four `needs_validation` records of `run-6`) |
| **Status** | Fixed on `dev` |
| **Upstream Ticket** | Filed by us on 2026-11-15: [laurencelundblade/QCBOR#442](https://github.com/laurencelundblade/QCBOR/issues/442); fix [laurencelundblade/QCBOR#448](https://github.com/laurencelundblade/QCBOR/pull/448) merged on 2026-11-18. Not in 1.x. Draft: [`../../upstream/qcbor/06-epoch-date-output-on-error.md`](../../upstream/qcbor/06-epoch-date-output-on-error.md) |
| **Severity** | **Low** (not undefined behavior, since `Item`'s address is taken; a caller that keeps a default when a label is missing loses it) |
| **Reachability** | `untrusted_surface` (any malformed or unexpected input reaches the error path) |
| **Location** | [`src/qcbor_tag_decode.c:893`](https://github.com/laurencelundblade/QCBOR/blob/19c3367c0bf7db3ffcc8bc5626d7740dc5b8a76e/src/qcbor_tag_decode.c#L893), `:919`, `:945`, `:966`, `:992`, `:1018` (`dev` `19c3367`) |
| **Failing Property** | `initialization`: indeterminate value stored to the caller's output (CWE-908) |

#### Description & Root Cause

Six getters, `QCBORDecode_GetTEpochDate()`, `GetTEpochDays()` and their `InMapN` and `InMapSZ` variants, end with an unconditional `*pnTime = Item.val.epochDate.nSeconds;` (or `*pnDays = ...`). When an error is already latched, `Item` is a local nothing wrote; when the label is not found, it is a copy of the map-search template whose `val` was never set. 1.x, and the other getters of `qcbor_tag_decode.c`, assign the output only on success.

#### Minimal Standalone Reproducer

```c
#include <stdio.h>
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include "qcbor/qcbor_tag_decode.h"

int main(void)
{
   static const uint8_t aMap[] = {0xa1, 0x01, 0x02};   /* {1: 2} */
   QCBORDecodeContext D;
   int64_t nTime = 42;                                /* caller's default */

   QCBORDecode_Init(&D, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(aMap), QCBOR_DECODE_MODE_NORMAL);
   QCBORDecode_EnterMap(&D, NULL);
   QCBORDecode_GetTEpochDateInMapN(&D, 5, QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG, &nTime);
   if(nTime != 42) {   /* MSan: use-of-uninitialized-value */
      printf("BUG: output overwritten on error\n");
      return 1;
   }
   printf("OK\n");
   return 0;
}
```

#### Fix

Merged upstream in [laurencelundblade/QCBOR#448](https://github.com/laurencelundblade/QCBOR/pull/448): the output is assigned only when decoding succeeded. Our patch: [`../../upstream/qcbor/patches/public/0005-Don-t-write-an-indeterminate-epoch-date-or-days-on-d.patch`](../../upstream/qcbor/patches/public/0005-Don-t-write-an-indeterminate-epoch-date-or-days-on-d.patch).

---

### `QCBOR-08`: `QCBOREncode_EncodeHead` with `uMinLen` above 8 writes before the caller's buffer

| Field | Value |
| :--- | :--- |
| **Fingerprint** | `src/qcbor_main_encode.c#QCBOREncode_EncodeHead::index_bound::02209a353f` (`run-5`, rejected `harness_induced` by the run and re-judged confirmed), `ce76fb1dc0` (`run-6`) |
| **Status** | Fixed on `dev`; 1.x fix open |
| **Upstream Ticket** | Filed by us on 2026-11-15: [laurencelundblade/QCBOR#443](https://github.com/laurencelundblade/QCBOR/issues/443); `dev` fix [laurencelundblade/QCBOR#449](https://github.com/laurencelundblade/QCBOR/pull/449) merged on 2026-11-18, 1.x fix [laurencelundblade/QCBOR#451](https://github.com/laurencelundblade/QCBOR/pull/451) open. Draft: [`../../upstream/qcbor/07-encodehead-uminlen.md`](../../upstream/qcbor/07-encodehead-uminlen.md) |
| **Severity** | **Low** (API hardening: the trigger is an out-of-range constant from the application, not data) |
| **Reachability** | `public_api` (encode API only; no caller inside QCBOR passes more than 8) |
| **Location** | [`src/qcbor_main_encode.c:462-472`](https://github.com/laurencelundblade/QCBOR/blob/19c3367c0bf7db3ffcc8bc5626d7740dc5b8a76e/src/qcbor_main_encode.c#L462-L472) (`dev` `19c3367`); `src/qcbor_encode.c:468` (1.x `master` `1d06057`, v1.6.1) |
| **Failing Property** | `index_bound` on `aIterate[]`, then out-of-bounds writes (CWE-129, CWE-787) |

#### Description & Root Cause

`QCBOREncode_EncodeHead()` is public, for applications that hash a byte string in chunks, and documents `uMinLen` only as "the minimum number of bytes to encode uNumber". A CBOR head argument is at most 8 bytes, but nothing checks `uMinLen`. With 9 or more, the encoding loop indexes the 4-entry `aIterate[]` past its end and keeps pre-decrementing `pByte` before the start of the caller's buffer. On 1.x the UBSan build then crashed with a SEGV, the writes having corrupted the stack frame.

#### Minimal Standalone Reproducer

```c
#include <stdio.h>
#include "qcbor/qcbor_encode.h"

int main(void)
{
   UsefulBuf_MAKE_STACK_UB(Head, QCBOR_HEAD_BUFFER_SIZE);

   /* UBSan: index 4 out of bounds for type 'const uint8_t[4]' */
   UsefulBufC Out = QCBOREncode_EncodeHead(Head, CBOR_MAJOR_TYPE_POSITIVE_INT, 9, 0);
   if(!UsefulBuf_IsNULLC(Out)) {
      printf("BUG: uMinLen 9 accepted, len %zu\n", Out.len);
      return 1;
   }
   printf("OK\n");
   return 0;
}
```

#### Fix

Merged on `dev` in [laurencelundblade/QCBOR#449](https://github.com/laurencelundblade/QCBOR/pull/449): `uMinLen` above 8 returns `NULLUsefulBufC`, as a too-small buffer already does. Our patches: [`../../upstream/qcbor/patches/public/0006-Reject-uMinLen-8-in-QCBOREncode_EncodeHead.patch`](../../upstream/qcbor/patches/public/0006-Reject-uMinLen-8-in-QCBOREncode_EncodeHead.patch) (`dev`), [`../../upstream/qcbor/patches/v1/0002-Reject-uMinLen-8-in-QCBOREncode_EncodeHead.patch`](../../upstream/qcbor/patches/v1/0002-Reject-uMinLen-8-in-QCBOREncode_EncodeHead.patch) (1.x).

---

### `QCBOR-09`: Consuming a truncated array or map overwrites `uNextNestLevel` with an uninitialized byte

| Field | Value |
| :--- | :--- |
| **Fingerprint** | `QCBORDecode_Private_ConsumeItem` `b5ec324eae` (`run-6`, the one new bug of that run) |
| **Status** | Fixed on `dev`; 1.x fix open |
| **Upstream Ticket** | Filed by us on 2026-11-15: [laurencelundblade/QCBOR#444](https://github.com/laurencelundblade/QCBOR/issues/444); `dev` fix [laurencelundblade/QCBOR#450](https://github.com/laurencelundblade/QCBOR/pull/450) merged on 2026-11-18, 1.x fix [laurencelundblade/QCBOR#452](https://github.com/laurencelundblade/QCBOR/pull/452) open. Draft: [`../../upstream/qcbor/10-consumeitem-nest-level-issue.md`](../../upstream/qcbor/10-consumeitem-nest-level-issue.md) |
| **Severity** | **Low** (the error is set, so a caller that checks it is not affected; an application that reads the returned item gets an uninitialized value) |
| **Reachability** | `untrusted_surface` (one input byte, `81` or `b7`, through `QCBORDecode_VGetNextConsume`) |
| **Location** | [`src/qcbor_main_decode.c:2099-2116`](https://github.com/laurencelundblade/QCBOR/blob/19c3367c0bf7db3ffcc8bc5626d7740dc5b8a76e/src/qcbor_main_decode.c#L2099-L2116) (`dev` `19c3367`); `src/qcbor_decode.c:3175` (1.x `master` `1d06057`, v1.6.1, v1.5.3) |
| **Failing Property** | `initialization`: indeterminate value stored to the caller's item (CWE-908) |

#### Description & Root Cause

`QCBORDecode_Private_ConsumeItem()` walks the members with a local `QCBORItem Item`. When `QCBORDecode_Private_GetNextMapOrArray()` stops on an error it does not write `Item`; the loop breaks, and the line after it copies the unwritten field out:

```c
   do {
      uReturn = QCBORDecode_Private_GetNextMapOrArray(pMe, pEnd, &Item, NULL);
      if(QCBORDecode_IsHaltingError(uReturn)) {
         break;
      }
      if(uReturn == QCBOR_ERR_NO_MORE_ITEMS) {
         /* Should never occur. ... */
         break;
      }
   } while(Item.uNextNestLevel >= pItemToConsume->uNextNestLevel);

   *puNextNestLevel = Item.uNextNestLevel;
```

The function's own documentation says the output is "Not set when traversal stops early", and a truncated array reaches the "Should never occur" branch. `QCBORDecode_VGetNextConsume()` passes `&pDecodedItem->uNextNestLevel`, so the 1 just stored for the array head is replaced with stack contents. v2.0-alpha-6 is not affected.

#### Minimal Standalone Reproducer

```c
#include <stdio.h>
#include "qcbor/qcbor_decode.h"

int main(void)
{
   static const uint8_t aIn[] = {0x81};   /* array of one item, item missing */
   QCBORDecodeContext D;
   QCBORItem Item;

   QCBORDecode_Init(&D, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(aIn), QCBOR_DECODE_MODE_NORMAL);
   QCBORDecode_VGetNextConsume(&D, &Item);
   if(Item.uNextNestLevel != 1) {   /* MSan: use-of-uninitialized-value */
      printf("BUG: uNextNestLevel overwritten\n");
      return 1;
   }
   printf("OK\n");
   return 0;
}
```

#### Fix

Merged on `dev` in [laurencelundblade/QCBOR#450](https://github.com/laurencelundblade/QCBOR/pull/450): the nest level is written only when the traversal completed. Our patches: [`../../upstream/qcbor/patches/public/0008-Don-t-set-uNextNestLevel-when-consuming-an-array-or-.patch`](../../upstream/qcbor/patches/public/0008-Don-t-set-uNextNestLevel-when-consuming-an-array-or-.patch) (`dev`), [`../../upstream/qcbor/patches/v1/0003-Don-t-set-uNextNestLevel-when-consuming-an-array-or-.patch`](../../upstream/qcbor/patches/v1/0003-Don-t-set-uNextNestLevel-when-consuming-an-array-or-.patch) (1.x).
