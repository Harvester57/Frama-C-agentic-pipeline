# Bugs Found in `CryptoLib` (`nasa/CryptoLib`)

- **Master Index:** [`../README.md`](../README.md)
- **Upstream Repository:** [https://github.com/nasa/CryptoLib](https://github.com/nasa/CryptoLib)
- **Evaluated Revision:** [`5b98c8b2561b22822a9d4e26c959677ed93c815a`](https://github.com/nasa/CryptoLib/tree/5b98c8b2561b22822a9d4e26c959677ed93c815a)
- **Scope:** Core Telecommand (TC), Telemetry (TM), Advanced Orbiting Systems (AOS), Security Association (SA) in-memory backend, Key Management, and Monitoring & Control (MC) slices (`core`, `crypto`, `sa`, `key`, `mc`).
- **Campaign Summary:**
  - **Confirmed Findings:** 1 (1 Medium)
  - **Needs Validation / C11 Hygiene:** 1 (`update_sa_from_ptr` self-overlapping `memcpy`)
  - **Rejected Candidates:** 7 (`5` unconfigured-harness artifacts, `1` dead `unsigned_downcast` sentinel initializer, `1` E-ACSL by-value struct parameter false alarm)

---

## Summary of Findings

| ID | Title | Location | Property / CWE | Severity | Upstream Ticket | Status |
| :--- | :--- | :--- | :--- | :---: | :--- | :--- |
| [`CRYPTOLIB-01`](#cryptolib-01-one-byte-out-of-bounds-read-in-crypto_tc_set_segment_header-on-5-byte-tc-frame) | One-byte out-of-bounds read of received TC frame buffer when a minimal 5-byte frame is processed with segmentation headers enabled | [`src/core/crypto_tc.c:1949`](https://github.com/nasa/CryptoLib/blob/5b98c8b2561b22822a9d4e26c959677ed93c815a/src/core/crypto_tc.c#L1949), [`:2025`](https://github.com/nasa/CryptoLib/blob/5b98c8b2561b22822a9d4e26c959677ed93c815a/src/core/crypto_tc.c#L2025) (`Crypto_TC_Set_Segment_Header`) | `mem_access` (CWE-125) | **Medium** | Pending / Not yet filed | Confirmed (Unreported) |

---

## Detailed Findings

### `CRYPTOLIB-01`: One-byte out-of-bounds read in `Crypto_TC_Set_Segment_Header` on 5-byte TC frame

| Field | Value |
| :--- | :--- |
| **Fingerprint** | `src/core/crypto_tc.c#Crypto_TC_Set_Segment_Header::mem_access::74b4df8a1f` |
| **Status** | Confirmed (Unreported) |
| **Upstream Ticket** | Pending / Not yet filed |
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

#### Proposed Fix

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

## Additional C11 Hygiene Note (`needs_validation`)

### Self-overlapping `memcpy` (`dest == src`) in `update_sa_from_ptr` during `sa_populate`

- **Location:** [`src/sa/internal/sa_interface_inmemory.template.c:143`](https://github.com/nasa/CryptoLib/blob/5b98c8b2561b22822a9d4e26c959677ed93c815a/src/sa/internal/sa_interface_inmemory.template.c#L143) (`update_sa_from_ptr`)
- **Detection Engine:** Phase 2 (`Frama-C Eva` `Invalid` status on `memcpy` ACSL `separation` precondition)
- **Summary:** During `Crypto_Init()`, when `sa_save_file.bin` is absent, `sa_init()` falls back to `sa_populate()`, which initializes `sa[0].spi = 0` and calls `sa_perform_save(&sa[0])` (`line 570`) -> `update_sa_from_ptr(&sa[0])` (`line 189`). Inside `update_sa_from_ptr`, `location = sa_ptr->spi` evaluates to `0`, and lines 143-144 execute `memcpy(sa[0].ek_ref, sa_ptr->ek_ref, REF_SIZE)` and `memcpy(sa[0].ak_ref, sa_ptr->ak_ref, REF_SIZE)` with `dest == src`. Calling `memcpy` on identical non-empty source and destination buffers violates C11 7.24.2.1p2 (`\separated`), though it is a benign self-copy at initialization time. Guarding the copies with `if (&sa[location] != sa_ptr)` (or using `memmove`) eliminates the undefined behavior.
