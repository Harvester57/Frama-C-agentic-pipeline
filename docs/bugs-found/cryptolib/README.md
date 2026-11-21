# Bugs Found in `CryptoLib` (`nasa/CryptoLib`)

- **Master Index:** [`../README.md`](../README.md)
- **Upstream Repository:** [https://github.com/nasa/CryptoLib](https://github.com/nasa/CryptoLib)
- **Evaluated Revision:** [`5b98c8b2561b22822a9d4e26c959677ed93c815a`](https://github.com/nasa/CryptoLib/tree/5b98c8b2561b22822a9d4e26c959677ed93c815a)
- **Scope:** Core Telecommand (TC), Telemetry (TM), Advanced Orbiting Systems (AOS), Security Association (SA) in-memory backend, Key Management, and Monitoring & Control (MC) slices (`core`, `crypto`, `sa`, `key`, `mc`).
- **Campaign Summary:**
  - **Confirmed Findings:** 2 (2 Medium; `CRYPTOLIB-01` from the pipeline campaign, `CRYPTOLIB-02` not in the campaign record)
  - **Upstream status (checked 2026-11-21):** both reported as private GitHub security advisories on 2026-11-05 (still in `triage`). `CRYPTOLIB-01` is fixed on `dev` by [`d65a49a`](https://github.com/nasa/CryptoLib/commit/d65a49ab55e31ab68b38ad233fe0563f9a82b704) (2026-11-18), not yet on `main`; `CRYPTOLIB-02` is still present on `dev`.
  - **Needs Validation / C11 Hygiene:** 1 (`update_sa_from_ptr` self-overlapping `memcpy`; still present on `dev` on 2026-11-21)
  - **Rejected Candidates:** 7 (`5` unconfigured-harness artifacts, `1` dead `unsigned_downcast` sentinel initializer, `1` E-ACSL by-value struct parameter false alarm)

---

## Summary of Findings

| ID | Title | Location | Property / CWE | Severity | Upstream Ticket | Status |
| :--- | :--- | :--- | :--- | :---: | :--- | :--- |
| [`CRYPTOLIB-01`](#cryptolib-01-one-byte-out-of-bounds-read-in-crypto_tc_set_segment_header-on-5-byte-tc-frame) | One-byte out-of-bounds read of received TC frame buffer when a minimal 5-byte frame is processed with segmentation headers enabled | [`src/core/crypto_tc.c:1949`](https://github.com/nasa/CryptoLib/blob/5b98c8b2561b22822a9d4e26c959677ed93c815a/src/core/crypto_tc.c#L1949), [`:2025`](https://github.com/nasa/CryptoLib/blob/5b98c8b2561b22822a9d4e26c959677ed93c815a/src/core/crypto_tc.c#L2025) (`Crypto_TC_Set_Segment_Header`) | `mem_access` (CWE-125) | **Medium** | [GHSA-7f4g-c4pm-cvw8](https://github.com/nasa/CryptoLib/security/advisories/GHSA-7f4g-c4pm-cvw8) (private, filed 2026-11-05); fixed by [`d65a49a`](https://github.com/nasa/CryptoLib/commit/d65a49ab55e31ab68b38ad233fe0563f9a82b704) | Fixed on `dev` |
| [`CRYPTOLIB-02`](#cryptolib-02-one-byte-out-of-bounds-read-in-crypto_tm_process_setup-on-6-byte-tm-frame-with-secondary-header-flag) | One-byte out-of-bounds read of received TM frame buffer when a 6-byte frame has the Secondary Header flag set | [`src/core/crypto_tm.c:1372`](https://github.com/nasa/CryptoLib/blob/0e4ef191943b3c1700519f49f61aaf65849594ef/src/core/crypto_tm.c#L1372) at v1.5.2 (`Crypto_TM_Process_Setup`); `:1384` on `dev` | `mem_access` (CWE-125) | **Medium** | [GHSA-mfqc-272c-5gwx](https://github.com/nasa/CryptoLib/security/advisories/GHSA-mfqc-272c-5gwx) (private, filed 2026-11-05) | Reported |

---

## Detailed Findings

### `CRYPTOLIB-01`: One-byte out-of-bounds read in `Crypto_TC_Set_Segment_Header` on 5-byte TC frame

| Field | Value |
| :--- | :--- |
| **Fingerprint** | `src/core/crypto_tc.c#Crypto_TC_Set_Segment_Header::mem_access::74b4df8a1f` |
| **Status** | Fixed on `dev` ([`d65a49a`](https://github.com/nasa/CryptoLib/commit/d65a49ab55e31ab68b38ad233fe0563f9a82b704), 2026-11-18); `main` (last merge `c216ede`, 2026-11-04) and every release up to v1.5.2 still affected |
| **Upstream Ticket** | [GHSA-7f4g-c4pm-cvw8](https://github.com/nasa/CryptoLib/security/advisories/GHSA-7f4g-c4pm-cvw8) (private security advisory, filed 2026-11-05, state `triage`) |
| **Severity** | **Medium** (1-byte heap/buffer out-of-bounds read past the end of an attacker-controlled TC frame; reproduced under both Frama-C E-ACSL and Clang AddressSanitizer) |
| **Reachability** | `untrusted_surface` (`Crypto_TC_ProcessSecurity` / `Crypto_TC_ProcessSecurity_Cam`) |
| **Location** | [`src/core/crypto_tc.c:1949`](https://github.com/nasa/CryptoLib/blob/5b98c8b2561b22822a9d4e26c959677ed93c815a/src/core/crypto_tc.c#L1949) (`Crypto_TC_Set_Segment_Header`) called from [`src/core/crypto_tc.c:2025`](https://github.com/nasa/CryptoLib/blob/5b98c8b2561b22822a9d4e26c959677ed93c815a/src/core/crypto_tc.c#L2025) (`Crypto_TC_ProcessSecurity_Cam`) |
| **Failing Property** | `rte:mem_access`: `\valid_read(ingest + *byte_idx)` (CWE-125: Out-of-bounds Read) |

#### Description & Root Cause

`Crypto_TC_ProcessSecurity` (forwarding to `Crypto_TC_ProcessSecurity_Cam`) parses an incoming Telecommand (TC) transfer frame buffer `ingest` of length `*len_ingest`:

1. `Crypto_TC_Process_Sanity_Check(len_ingest)` (`src/core/crypto_tc.c:1671`) only verifies that `*len_ingest >= TC_FRAME_HEADER_SIZE` (`5` bytes).
2. `Crypto_TC_ProcessSecurity_Cam` (`src/core/crypto_tc.c:1989-2003`) reads the 5-byte primary header (`byte_idx` advances from `0` to `5`) and checks `tc_header.fl + 1 != *len_ingest` at line 2005. For a 5-byte input with `fl == 4` (`4 + 1 == 5`), this check passes.
3. At line 2013, `Crypto_Get_TC_Managed_Parameters_For_Gvcid` looks up the managed parameters for `(tfvn, scid, vcid)`. When the virtual channel is configured with `has_segmentation_hdr == TC_HAS_SEGMENT_HDRS` (the standard configuration used in `Crypto_Init_TC_Unit_Test` and `ut_tc_process.c`), line 2025 calls `Crypto_TC_Set_Segment_Header` **before** checking whether any bytes remain in `ingest` after the 5-byte primary header:

```c
// src/core/crypto_tc.c:1944-1953
void Crypto_TC_Set_Segment_Header(TC_t *tc_sdls_processed_frame, uint8_t *ingest, int *byte_idx)
{
    int byte_idx_tmp = *byte_idx;
    if (tc_current_managed_parameters_struct.has_segmentation_hdr == TC_HAS_SEGMENT_HDRS)
    {
        tc_sdls_processed_frame->tc_sec_header.sh = (uint8_t)ingest[*byte_idx]; // <-- OOB read: *byte_idx == 5
        byte_idx_tmp++;
    }
    *byte_idx = byte_idx_tmp;
}

// src/core/crypto_tc.c:2024-2038
    // Segment Header
    Crypto_TC_Set_Segment_Header(tc_sdls_processed_frame, ingest, &byte_idx);

    if (*len_ingest >= byte_idx + SPI_LEN)
    {
        // Security Header
        tc_sdls_processed_frame->tc_sec_header.spi = ((uint8_t)ingest[byte_idx] << 8) | (uint8_t)ingest[byte_idx + 1];
        byte_idx += 2;
    }
    else
    {
        status = CRYPTO_LIB_ERR_TC_FRAME_TOO_SHORT;
        mc_if->mc_log(status);
        return status;
    }
```

With `*len_ingest == 5` and `*byte_idx == 5`, `ingest[*byte_idx]` reads `ingest[5]`, one byte past the end of the 5-byte buffer, right before the `if (*len_ingest >= byte_idx + SPI_LEN)` check at line 2027 would have rejected the frame with `CRYPTO_LIB_ERR_TC_FRAME_TOO_SHORT`.

#### Minimal Standalone Reproducer

- **Triggering 5-byte TC transfer frame (hex):**
  ```text
  00 03 00 04 24
  ```
  - `tfvn = 0`, `scid = 0x0003`, `vcid = 0`, `fl = 4` (`fl + 1 == 5 == *len_ingest`), `fsn = 0x24`.

- **Pipeline E-ACSL & ASan results:**
  ```text
  E-ACSL: src/core/crypto_tc.c:1949 assertion rte:mem_access \valid_read(ingest + *byte_idx) failed (*byte_idx == 5).
  ASan:   ERROR: AddressSanitizer: heap-buffer-overflow on address ... READ of size 1 at 0 bytes after 5-byte region
          #0 Crypto_TC_Set_Segment_Header src/core/crypto_tc.c:1949
          #1 Crypto_TC_ProcessSecurity_Cam src/core/crypto_tc.c:2025
  ```

- **Standalone C reproducer (`repro_cryptolib_01.c`):**
  ```c
  #include <stdlib.h>
  #include <string.h>
  #include "crypto.h"

  int main(void) {
      static const uint8_t frame[5] = { 0x00, 0x03, 0x00, 0x04, 0x24 };
      Crypto_Init_TC_Unit_Test();

      uint8_t *buf = (uint8_t *)malloc(sizeof(frame));
      memcpy(buf, frame, sizeof(frame));
      int len = (int)sizeof(frame);
      TC_t tc;
      memset(&tc, 0, sizeof(tc));

      Crypto_TC_ProcessSecurity(buf, &len, &tc);
      free(buf);
      return 0;
  }
  ```

#### Upstream Fix

[`d65a49a`](https://github.com/nasa/CryptoLib/commit/d65a49ab55e31ab68b38ad233fe0563f9a82b704) ("resolve reported vulnerabilities", on `dev`) only calls `Crypto_TC_Set_Segment_Header` when `*len_ingest >= 6` and otherwise returns `CRYPTO_LIB_ERR_TC_FRAME_TOO_SHORT` (-200). `byte_idx` is always 5 at that point, so the bound is exact and the reproducer frame is rejected before `ingest[5]` is read. The same commit adds a full minimum-length check after `Crypto_TC_Calc_Lengths` (primary header, segment header, SPI, IV, sequence number, pad length, MAC and FECF). Checked by reading the diff; the reproducer was not rerun against `dev`.

#### Proposed Fix (as filed)

Check that `*len_ingest` has room for the optional segment header (plus the mandatory 2-byte SPI) before calling `Crypto_TC_Set_Segment_Header`:

```diff
--- a/src/core/crypto_tc.c
+++ b/src/core/crypto_tc.c
@@ -2022,6 +2022,14 @@ int32_t Crypto_TC_ProcessSecurity_Cam(uint8_t *ingest, int *len_ingest, TC_t *tc
     } // Unable to get necessary Managed Parameters for TC TF -- return with error.
 
     // Segment Header
+    uint8_t segment_hdr_present =
+        (tc_current_managed_parameters_struct.has_segmentation_hdr == TC_HAS_SEGMENT_HDRS) ? TC_SEGMENT_HDR_SIZE : 0;
+    if (*len_ingest < byte_idx + segment_hdr_present + SPI_LEN)
+    {
+        status = CRYPTO_LIB_ERR_TC_FRAME_TOO_SHORT;
+        mc_if->mc_log(status);
+        return status;
+    }
     Crypto_TC_Set_Segment_Header(tc_sdls_processed_frame, ingest, &byte_idx);
 
     if (*len_ingest >= byte_idx + SPI_LEN)
```

---

### `CRYPTOLIB-02`: One-byte out-of-bounds read in `Crypto_TM_Process_Setup` on 6-byte TM frame with Secondary Header flag

| Field | Value |
| :--- | :--- |
| **Status** | Reported; still present on `dev` (`329f895`, checked 2026-11-21) |
| **Upstream Ticket** | [GHSA-mfqc-272c-5gwx](https://github.com/nasa/CryptoLib/security/advisories/GHSA-mfqc-272c-5gwx) (private security advisory, filed 2026-11-05, state `triage`) |
| **Severity** | **Medium** (CVSS v3.1 5.3, `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`; 1-byte heap out-of-bounds read before any MAC check) |
| **Reachability** | `untrusted_surface` (`Crypto_TM_ProcessSecurity`) |
| **Detection** | Not in the pipeline campaign record for revision `5b98c8b`; found and verified with `ASan + UBSan` against v1.5.2 (`0e4ef19`) for the advisory |
| **Location** | [`src/core/crypto_tm.c:1372`](https://github.com/nasa/CryptoLib/blob/0e4ef191943b3c1700519f49f61aaf65849594ef/src/core/crypto_tm.c#L1372) at v1.5.2 (`Crypto_TM_Process_Setup`), called from `:2029` (`Crypto_TM_ProcessSecurity`); lines 1381-1397 on `dev` |
| **Failing Property** | `mem_access`: read of `p_ingest[6]` when `len_ingest == 6` (CWE-125) |

#### Description & Root Cause

`Crypto_TM_ProcessSecurity` and `Crypto_TM_Process_Setup` only reject frames shorter than `TM_FRAME_PRIMARYHEADER_SIZE` (6 bytes). When byte 4 has the Secondary Header flag (`0x80`) set, `Crypto_TM_Process_Setup` sets `*byte_idx = 6` and reads `p_ingest[6]` to decode the secondary-header version number (`shvn`) and length. The only check that the secondary header fits (`len_ingest < TM_FRAME_PRIMARYHEADER_SIZE + *secondary_hdr_len + 1`) runs after those reads, so a 6-byte frame reads one byte past the caller's buffer. Introduced by `29cd1b4` (2024-04-02); affects v1.3.1 to v1.5.2.

[`d65a49a`](https://github.com/nasa/CryptoLib/commit/d65a49ab55e31ab68b38ad233fe0563f9a82b704) does not touch `Crypto_TM_Process_Setup`: its `crypto_tm.c` changes only add unsupported-mode checks and free a leaked buffer in `Crypto_TM_Do_Decrypt`. On `dev` the read is at line 1384 (`shvn`) and 1397 (length), and the fit check is still at line 1419.

#### Minimal Standalone Reproducer

- **Triggering 6-byte TM frame (hex):** `00 3a 00 00 f7 00` (byte 4 `0xf7` has the Secondary Header flag set).
- **Expected unpatched result (`clang -fsanitize=address,undefined`):** `heap-buffer-overflow ... READ of size 1` in `Crypto_TM_Process_Setup` (`crypto_tm.c:1372`), `0 bytes after 6-byte region`.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto.h"

int main(void) {
    Crypto_SC_Init();
    const uint8_t frame[6] = {0x00, 0x3a, 0x00, 0x00, 0xf7, 0x00};
    uint8_t *buf = malloc(6);
    memcpy(buf, frame, 6);
    TM_t tm;
    memset(&tm, 0, sizeof tm);
    uint16_t declen = 0;
    int32_t st = Crypto_TM_ProcessSecurity(buf, 6, &tm, &declen);
    printf("Crypto_TM_ProcessSecurity status=%d\n", st);
    free(buf);
    return 0;
}
```

#### Proposed Fix (as filed)

```diff
--- a/src/core/crypto_tm.c
+++ b/src/core/crypto_tm.c
@@ -1368,6 +1368,14 @@
             // Secondary header is present
             *byte_idx = 6;
 
+            // A secondary header requires at least one byte at *byte_idx.
+            if (len_ingest <= *byte_idx)
+            {
+                status = CRYPTO_LIB_ERR_TM_SECONDARY_HDR_SIZE;
+                mc_if->mc_log(status);
+                return status;
+            }
+
             // Determine Secondary Header Version Number, should always be 0b00
             uint8_t shvn = (p_ingest[*byte_idx] & 0xC0) >> 6;
```

With the patch the reproducer returns `CRYPTO_LIB_ERR_TM_SECONDARY_HDR_SIZE` (-80).

---

## Additional C11 Hygiene Note (`needs_validation`)

### Self-overlapping `memcpy` (`dest == src`) in `update_sa_from_ptr` during `sa_populate`

- **Location:** [`src/sa/internal/sa_interface_inmemory.template.c:143`](https://github.com/nasa/CryptoLib/blob/5b98c8b2561b22822a9d4e26c959677ed93c815a/src/sa/internal/sa_interface_inmemory.template.c#L143) (`update_sa_from_ptr`)
- **Detection Engine:** Phase 2 (`Frama-C Eva` `Invalid` status on `memcpy` ACSL `separation` precondition)
- **Summary:** During `Crypto_Init()`, when `sa_save_file.bin` is absent, `sa_init()` falls back to `sa_populate()`, which initializes `sa[0].spi = 0` and calls `sa_perform_save(&sa[0])` (`line 570`) -> `update_sa_from_ptr(&sa[0])` (`line 189`). Inside `update_sa_from_ptr`, `location = sa_ptr->spi` evaluates to `0`, and lines 143-144 execute `memcpy(sa[0].ek_ref, sa_ptr->ek_ref, REF_SIZE)` and `memcpy(sa[0].ak_ref, sa_ptr->ak_ref, REF_SIZE)` with `dest == src`. Calling `memcpy` on identical non-empty source and destination buffers violates C11 7.24.2.1p2 (`\separated`), though it is a benign self-copy at initialization time. Guarding the copies with `if (&sa[location] != sa_ptr)` (or using `memmove`) eliminates the undefined behavior.
