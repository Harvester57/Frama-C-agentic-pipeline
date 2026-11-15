# Private follow-up email to the QCBOR maintainer

Draft, not sent. It follows up the private report of 2026-11-04 (the `ieee754.c` shifts and the `INT64_MIN` negation, reports 04 and 09 here). It also carries the two private bugs, 01 and 08. Send it before filing any of the public issues, so the maintainer hears about everything from you first.

Before sending, fill in the point marked **[check]**. Attach:
- [`patches/public/0007-Don-t-negate-INT64_MIN-in-QCBORDecode_ProcessBigNumb.patch`](./patches/public/0007-Don-t-negate-INT64_MIN-in-QCBORDecode_ProcessBigNumb.patch) (09, rebased on `dev` `19c3367`);
- [`patches/v1/0001-Don-t-shift-by-an-out-of-range-amount-in-float-conve.patch`](./patches/v1/0001-Don-t-shift-by-an-out-of-range-amount-in-float-conve.patch) (04 for 1.x), only if you want to offer it;
- for 01 and 08, the two report files, the two patches in `patches/private/`, and the two reproducers `repro/bignum_zero.c` and `repro/getarray_empty.c`.

Both private patches are rebased on `dev` `19c3367` and validated there (2026-11-15; see the README).

---

> **To:** the address in QCBOR's `SECURITY.md`
> **Subject:** QCBOR SECURITY: follow-up on the Nov 4 report, and two more out-of-bounds reads
>
> Good morning M. Lundblade,
>
> A follow-up to my email of November 4.
>
> **1. A correction first.** I wrote then that I had not published these details. That is no
> longer true: notes on these findings, including the two new bugs below, are in a public GitHub
> repository of mine (my Frama-C pipeline's documentation). **[check]** *Say here what you have done
> about it, for example removed them, or that they stay.* I apologize for this, and I am telling
> you so that you can judge the timing yourself.
>
> **2. The float shifts (ieee754.c).** I saw #434 and your fix in #438. I checked #438 against my
> reproducers on `dev` `19c3367`: the four cases (encode and preferred decode, double and single)
> are clean under UBSan, the UBSan test-suite run no longer reports `ieee754.c`, and `make warn`
> is clean with gcc and clang. 1.x `master` still has the same two shifts (`ieee754.c:510`,
> `:666`); a 1.x patch is attached in case it is useful.
>
> **3. INT64_MIN in QCBORDecode_ProcessBigNumber().** Still present on `dev` `19c3367`
> (`qcbor_number_decode.c:1964`, `:2008`). The attached patch is rebased on `19c3367`. It negates
> as unsigned at both sites (`0 - (uint64_t)x`) and leaves `ABSOLUTE_VALUE()` alone. All 12 CI
> configurations build with gcc and clang with no new warning, the tests pass, and UBSan no longer
> reports either site. Would you like it as a pull request, or would you rather fix it yourself?
>
> **4. Two new out-of-bounds reads.** Each comes with a report, a patch with tests, and a
> reproducer, attached. Both patches apply to `dev` `19c3367` and pass the same checks as above,
> plus ASan and MSan on the reproducers.
>
> - `QCBORDecode_GetArray()` / `GetMap()` on an empty definite-length array or map (`80`, `a0`)
>   return `pEncodedCBOR` with a valid pointer and a length taken from uninitialized stack memory.
>   One byte of input does it, and a caller that hashes or copies the result reads far past the
>   input. On `dev` only.
> - `QCBOREncode_AddTBigNumber()` / `AddTBigNumberNoPreferred()` read and encode the byte after an
>   all-zero big number. On `dev` and v2.0-alpha-6.
>
> **5. Lower-severity bugs I plan to file publicly** with patches, unless you would rather see any
> of them privately first:
> - a positive big number with `QCBOR_ENCODE_AS_BORROWED` is encoded as tag 3 (negative);
> - a negative big number of value zero is encoded as −1 or −2^64;
> - `UsefulOutBuf_Compare()` reads outside the buffer for offsets or lengths near `SIZE_MAX`;
> - the epoch date and days getters overwrite the caller's output with an uninitialized value on
>   error;
> - `QCBOREncode_EncodeHead()` with `uMinLen` > 8 writes before its buffer (also 1.x);
> - `QCBORDecode_VGetNextConsume()` on a truncated array or map leaves an uninitialized
>   `uNextNestLevel` in the item (also 1.x).
>
> The patches and texts were prepared with LLM assistance (Claude Code); I reviewed them and ran
> the tests myself.
>
> Best regards,
> Florian
