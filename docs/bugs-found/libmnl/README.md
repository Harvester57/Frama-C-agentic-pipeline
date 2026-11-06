# Bugs Found in `libmnl` (netfilter)

- **Master Index:** [`../README.md`](../README.md)
- **Upstream Repository:** [https://git.netfilter.org/libmnl](https://git.netfilter.org/libmnl)
- **Evaluated Revision:** [`d24c88693be13ae77843e18e3388ca9142efdc31`](https://git.netfilter.org/libmnl/commit/?id=d24c88693be13ae77843e18e3388ca9142efdc31) (`master`, still upstream HEAD on 2026-11-06)
- **Pipeline Profile:** `deep` (whole target)
- **Campaign Summary:**
  - **Confirmed Findings:** 5 (1 Medium, 4 Low)
  - **Pipeline Verdicts:** The pipeline confirmed 5 findings and left 6 as `needs_validation`. Manual triage merged these 11 into the 5 distinct bugs below and dismissed 1. The pipeline also kept 12 rejected candidates.
  - **Assurance Summary:** 32 of 182 units proven under open assumptions (29 by WP, 3 discharged by Eva), 0 unconditionally. 35 units are blocked, mostly by WP Typed-model limits on `void *` / `struct` pointer casts.
- **Upstream Report:** [`[PATCH libmnl 0/5]` series on netfilter-devel](https://lore.kernel.org/netfilter-devel/20261106191841.1645-1-florian.stosse@harvester.fr/T/#t), sent 2026-11-06 to netfilter-devel@vger.kernel.org, Cc Pablo Neira Ayuso.
- **Security Assessment:** None of the bugs is reachable from kernel netlink data through the normal parse path (`mnl_cb_run`, `mnl_attr_parse`). Each needs a caller that uses the API in an uncommon way. None warrants private disclosure. They were sent upstream as ordinary fixes.

---

## Summary of Findings

| ID | Title | Location | Property / CWE | Severity | Upstream Ticket | Status |
| :--- | :--- | :--- | :--- | :---: | :--- | :--- |
| [`LIBMNL-01`](#libmnl-01-overlapping-memcpy-in-mnl_nlmsg_batch_reset-corrupts-the-batch-length) | Overlapping `memcpy` in `mnl_nlmsg_batch_reset` corrupts the batch length | [`src/nlmsg.c:534`](https://git.netfilter.org/libmnl/tree/src/nlmsg.c?id=d24c88693be13ae77843e18e3388ca9142efdc31#n534) (`mnl_nlmsg_batch_reset`) | `memcpy` separation precondition (CWE-475 / CWE-787) | **Medium** | [Patch 1/5 on netfilter-devel](https://lore.kernel.org/netfilter-devel/20261106191841.1645-2-florian.stosse@harvester.fr/) (2026-11-06) | Reported |
| [`LIBMNL-02`](#libmnl-02-_check-builders-ignore-alignment-padding-and-write-past-the-buffer) | `*_check` builders ignore alignment padding and write up to 3 bytes past the buffer | [`src/attr.c:603`](https://git.netfilter.org/libmnl/tree/src/attr.c?id=d24c88693be13ae77843e18e3388ca9142efdc31#n603), [`:748`](https://git.netfilter.org/libmnl/tree/src/attr.c?id=d24c88693be13ae77843e18e3388ca9142efdc31#n748) (`mnl_attr_put_check`, `mnl_attr_nest_start_check`) | `mem_access` (CWE-787) | **Low** | [Patch 2/5 on netfilter-devel](https://lore.kernel.org/netfilter-devel/20261106191841.1645-3-florian.stosse@harvester.fr/) (2026-11-06) | Reported |
| [`LIBMNL-03`](#libmnl-03-mnl_attr_get_payload_len-wraps-for-short-attributes-so-nested-parsing-reads-past-the-nest) | `mnl_attr_get_payload_len` wraps for `nla_len < 4`, so nested parsing reads past the nest | [`src/attr.c:66`](https://git.netfilter.org/libmnl/tree/src/attr.c?id=d24c88693be13ae77843e18e3388ca9142efdc31#n66) (`mnl_attr_get_payload_len`) → `src/attr.c:101` (`mnl_attr_ok`) | `mem_access` (CWE-191 / CWE-125) | **Low** | [Patch 3/5 on netfilter-devel](https://lore.kernel.org/netfilter-devel/20261106191841.1645-4-florian.stosse@harvester.fr/) (2026-11-06) | Reported |
| [`LIBMNL-04`](#libmnl-04-mnl_nlmsg_fprintf-over-reads-up-to-3-bytes-on-unaligned-messages) | `mnl_nlmsg_fprintf` over-reads up to 3 bytes on unaligned messages | [`src/nlmsg.c:305`](https://git.netfilter.org/libmnl/tree/src/nlmsg.c?id=d24c88693be13ae77843e18e3388ca9142efdc31#n305) (`mnl_nlmsg_fprintf_payload`) | `mem_access` (CWE-125) | **Low** | [Patch 4/5 on netfilter-devel](https://lore.kernel.org/netfilter-devel/20261106191841.1645-5-florian.stosse@harvester.fr/) (2026-11-06) | Reported |
| [`LIBMNL-05`](#libmnl-05-signed-overflow-negating-int_min-in-mnl_cb_error) | Signed overflow negating `INT_MIN` in `mnl_cb_error` | [`src/callback.c:29`](https://git.netfilter.org/libmnl/tree/src/callback.c?id=d24c88693be13ae77843e18e3388ca9142efdc31#n29) (`mnl_cb_error`) | `signed_overflow` (CWE-190) | **Low** | [Patch 5/5 on netfilter-devel](https://lore.kernel.org/netfilter-devel/20261106191841.1645-6-florian.stosse@harvester.fr/) (2026-11-06) | Reported |

**Dismissed:** the `needs_validation` candidate on `mnl_attr_parse` (`src/attr.c#mnl_attr_parse::rte::5173b92389`, signed truncation in `mnl_attr_for_each`). It needs a caller-supplied `offset >= 2^31`, which violates the caller's contract. A netlink message cannot supply it.

All reproducers below build against the evaluated revision with:

```sh
touch config.h
clang -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=undefined \
      -Iinclude -I. src/*.c repro.c -o repro && ./repro
```

---

## Detailed Findings

### `LIBMNL-01`: Overlapping `memcpy` in `mnl_nlmsg_batch_reset` corrupts the batch length

| Field | Value |
| :--- | :--- |
| **Fingerprint** | `src/nlmsg.c#mnl_nlmsg_batch_reset::rte::44501ef319` |
| **Pipeline Verdict** | `needs_validation`. The crash verifier reproduced it with a standalone ASan driver, but no module harness calls the batch API. Validated manually. |
| **Status** | Reported |
| **Upstream Ticket** | [Patch 1/5 on netfilter-devel](https://lore.kernel.org/netfilter-devel/20261106191841.1645-2-florian.stosse@harvester.fr/) (2026-11-06) |
| **Severity** | **Medium**. The trigger is documented, valid API use. Without sanitizers, the batch length and cursor become payload bytes, and the next batch call dereferences a wild pointer. |
| **Reachability** | `internal_api` (message sizes come from the application; any program that batches messages larger than half the batch limit is affected) |
| **Location** | [`src/nlmsg.c:530-542`](https://git.netfilter.org/libmnl/tree/src/nlmsg.c?id=d24c88693be13ae77843e18e3388ca9142efdc31#n530) (`mnl_nlmsg_batch_reset`) |
| **Failing Property** | `memcpy` precondition `separated(dest[0..n-1], src[0..n-1])` (C11 7.24.2.1p2) |

#### Description & Root Cause

When `mnl_nlmsg_batch_next()` finds that the current message does not fit, it sets `b->overflow`. `mnl_nlmsg_batch_reset()` then moves that pending message to the head of the buffer:

```c
// src/nlmsg.c:530-542
EXPORT_SYMBOL void mnl_nlmsg_batch_reset(struct mnl_nlmsg_batch *b)
{
	if (b->overflow) {
		struct nlmsghdr *nlh = b->cur;
		memcpy(b->buf, b->cur, nlh->nlmsg_len);   // <-- src = buf + buflen, overlaps when nlmsg_len > buflen
		b->buflen = nlh->nlmsg_len;               // <-- re-reads a header the copy has just overwritten
		b->cur = b->buf + b->buflen;
		b->overflow = false;
	} ...
```

The source is `b->buf + b->buflen` and the destination is `b->buf`. They overlap whenever the pending message is longer than the data already batched, which is undefined behaviour for `memcpy`. On glibc x86-64 the copy runs forward, so `nlh->nlmsg_len` (at the old `b->cur`) has already been overwritten with message payload bytes when line 535 reads it. `b->buflen` and `b->cur` then come from attacker- or application-controlled data. The trigger respects the documented preconditions: the buffer is `2 * limit` and one message was batched before `batch_next`.

#### Minimal Standalone Reproducer

```c
#include <libmnl/libmnl.h>
#include <stdio.h>
#include <stdlib.h>

#define LIMIT 100

static void put(void *at, unsigned int len, unsigned char fill)
{
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(at);
	for (unsigned int i = sizeof(*nlh); i < len; i++)
		((unsigned char *)nlh)[i] = fill + i;
	nlh->nlmsg_len = len;
}

int main(void)
{
	char *buf = malloc(2 * LIMIT);			/* documented: buffer is 2 * limit */
	struct mnl_nlmsg_batch *b = mnl_nlmsg_batch_start(buf, LIMIT);

	put(mnl_nlmsg_batch_current(b), 20, 0x80);	/* small message */
	mnl_nlmsg_batch_next(b);
	put(mnl_nlmsg_batch_current(b), 92, 0x80);	/* does not fit: 20 + 92 > 100 */
	if (mnl_nlmsg_batch_next(b))
		return 2;

	mnl_nlmsg_batch_reset(b);			/* memcpy(buf, buf + 20, 92) */
	size_t size = mnl_nlmsg_batch_size(b);
	printf("batch_size after reset = %#zx (expected 0x5c)\n", size);
	mnl_nlmsg_batch_stop(b);
	free(buf);
	return size == 92 ? 0 : 1;
}
```

```text
# with -fsanitize=address,undefined:
ERROR: AddressSanitizer: memcpy-param-overlap: memory ranges [0x511000000040,0x51100000009c) and [0x511000000054, 0x5110000000b0) overlap
# without sanitizers, clang -O2, glibc x86-64:
batch_size after reset = 0x97969594 (expected 0x5c)
```

#### Proposed Fix

```diff
--- a/src/nlmsg.c
+++ b/src/nlmsg.c
@@ -531,8 +531,10 @@ EXPORT_SYMBOL void mnl_nlmsg_batch_reset(struct mnl_nlmsg_batch *b)
 {
 	if (b->overflow) {
 		struct nlmsghdr *nlh = b->cur;
-		memcpy(b->buf, b->cur, nlh->nlmsg_len);
-		b->buflen = nlh->nlmsg_len;
+		size_t len = nlh->nlmsg_len;
+
+		memmove(b->buf, b->cur, len);
+		b->buflen = len;
 		b->cur = b->buf + b->buflen;
 		b->overflow = false;
 	} else {
```

---

### `LIBMNL-02`: `*_check` builders ignore alignment padding and write past the buffer

| Field | Value |
| :--- | :--- |
| **Fingerprint** | `src/attr.c#mnl_attr_nest_start::mem_access::81da41c0a5` (confirmed). Also covers `needs_validation` `src/attr.c#mnl_attr_nest_start_check::...::bef77b5964` and `src/attr.c#mnl_attr_put_str_check::...::2b443e207f`. |
| **Pipeline Verdict** | `confirmed` (E-ACSL witness `workspace/crashes/attr/crash-428ae95cf02dbc3ddfb860face3aad06ff3dd571`) |
| **Status** | Reported |
| **Upstream Ticket** | [Patch 2/5 on netfilter-devel](https://lore.kernel.org/netfilter-devel/20261106191841.1645-3-florian.stosse@harvester.fr/) (2026-11-06) |
| **Severity** | **Low**. A heap out-of-bounds write of up to 3 bytes. It needs a caller that leaves `nlmsg_len` unaligned (for example after appending raw bytes); libmnl's own builders and the kernel always keep it aligned. |
| **Reachability** | `internal_api` |
| **Location** | [`src/attr.c:603`](https://git.netfilter.org/libmnl/tree/src/attr.c?id=d24c88693be13ae77843e18e3388ca9142efdc31#n603) (`mnl_attr_put_check`), [`src/attr.c:748`](https://git.netfilter.org/libmnl/tree/src/attr.c?id=d24c88693be13ae77843e18e3388ca9142efdc31#n748) (`mnl_attr_nest_start_check`); write at [`src/attr.c:578`](https://git.netfilter.org/libmnl/tree/src/attr.c?id=d24c88693be13ae77843e18e3388ca9142efdc31#n578) |
| **Failing Property** | `mem_access`: `\valid(&start->nla_type)` |

#### Description & Root Cause

The builders write the new attribute at `mnl_nlmsg_get_payload_tail(nlh)`, which is `MNL_ALIGN(nlh->nlmsg_len)`. The size checks compare the *unaligned* length against `buflen`:

```c
// src/attr.c:603 (mnl_attr_put_check)
	if (nlh->nlmsg_len + MNL_ATTR_HDRLEN + MNL_ALIGN(len) > buflen)
// src/attr.c:748 (mnl_attr_nest_start_check)
	if (nlh->nlmsg_len + MNL_ATTR_HDRLEN > buflen)
```

With an unaligned `nlmsg_len`, the check is short by the 1–3 bytes of padding. All other `mnl_attr_put_*_check` helpers delegate to `mnl_attr_put_check`, so the whole family is affected.

#### Minimal Standalone Reproducer

```c
#include <libmnl/libmnl.h>
#include <stdlib.h>

int main(void)
{
	char *buf = calloc(1, 21);
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);

	nlh->nlmsg_len = 17;	/* caller appended one raw byte */
	/* check: 17 + 4 <= 21 passes; header is written at bytes 20..23 */
	struct nlattr *nest = mnl_attr_nest_start_check(nlh, 21, 1);

	free(buf);
	return nest == NULL ? 0 : 1;	/* NULL: correctly refused */
}
```

```text
ERROR: AddressSanitizer: heap-buffer-overflow ... WRITE of size 2
SUMMARY: AddressSanitizer: heap-buffer-overflow src/attr.c:578:18 in mnl_attr_nest_start
```

#### Proposed Fix

```diff
--- a/src/attr.c
+++ b/src/attr.c
@@ -600,7 +600,7 @@ EXPORT_SYMBOL bool mnl_attr_put_check(struct nlmsghdr *nlh, size_t buflen,
 				      uint16_t type, size_t len,
 				      const void *data)
 {
-	if (nlh->nlmsg_len + MNL_ATTR_HDRLEN + MNL_ALIGN(len) > buflen)
+	if (MNL_ALIGN(nlh->nlmsg_len) + MNL_ATTR_HDRLEN + MNL_ALIGN(len) > buflen)
 		return false;
 	mnl_attr_put(nlh, type, len, data);
 	return true;
@@ -745,7 +745,7 @@ EXPORT_SYMBOL struct nlattr *mnl_attr_nest_start_check(struct nlmsghdr *nlh,
 						       size_t buflen,
 						       uint16_t type)
 {
-	if (nlh->nlmsg_len + MNL_ATTR_HDRLEN > buflen)
+	if (MNL_ALIGN(nlh->nlmsg_len) + MNL_ATTR_HDRLEN > buflen)
 		return NULL;
 	return mnl_attr_nest_start(nlh, type);
 }
```

---

### `LIBMNL-03`: `mnl_attr_get_payload_len` wraps for short attributes, so nested parsing reads past the nest

| Field | Value |
| :--- | :--- |
| **Fingerprint** | `src/attr.c#mnl_attr_ok::precondition::33f068e63f` (confirmed). Also covers `needs_validation` `src/attr.c#mnl_attr_parse_nested::...::b1b67d4213`. |
| **Pipeline Verdict** | `confirmed` (E-ACSL witness `workspace/crashes/attr/crash-87df2657f75a0144561673b76e53a29c2dfe19b2`) |
| **Status** | Reported |
| **Upstream Ticket** | [Patch 3/5 on netfilter-devel](https://lore.kernel.org/netfilter-devel/20261106191841.1645-4-florian.stosse@harvester.fr/) (2026-11-06) |
| **Severity** | **Low**. An out-of-bounds read of an attribute header just past the nest. An attribute reached through `mnl_attr_parse` already has `nla_len >= 4` (checked by `mnl_attr_ok`), so only hand-built or unvalidated attributes reach it. |
| **Reachability** | `internal_api` |
| **Location** | [`src/attr.c:66`](https://git.netfilter.org/libmnl/tree/src/attr.c?id=d24c88693be13ae77843e18e3388ca9142efdc31#n66) (`mnl_attr_get_payload_len`), used by [`mnl_attr_for_each_nested`](https://git.netfilter.org/libmnl/tree/include/libmnl/libmnl.h?id=d24c88693be13ae77843e18e3388ca9142efdc31#n153); read at [`src/attr.c:101`](https://git.netfilter.org/libmnl/tree/src/attr.c?id=d24c88693be13ae77843e18e3388ca9142efdc31#n101) (`mnl_attr_ok`) |
| **Failing Property** | `mnl_attr_ok` precondition `len >= 4 ==> \valid_read(attr)` |

#### Description & Root Cause

```c
// src/attr.c:64-67
EXPORT_SYMBOL uint16_t mnl_attr_get_payload_len(const struct nlattr *attr)
{
	return attr->nla_len - MNL_ATTR_HDRLEN;   // <-- wraps to 65532..65535 for nla_len < 4
}
```

`mnl_attr_for_each_nested` (and so `mnl_attr_parse_nested`) uses this value as the length of the nest. For `nla_len < 4`, `mnl_attr_ok` is told there are about 64 KiB of attributes left and reads the next header just past the nest.

#### Minimal Standalone Reproducer

```c
#include <libmnl/libmnl.h>
#include <stdlib.h>

static int cb(const struct nlattr *attr, void *data) { return MNL_CB_OK; }

int main(void)
{
	struct nlattr *nest = calloc(1, sizeof(*nest));	/* 4 bytes */

	nest->nla_len = 0;
	int ret = mnl_attr_parse_nested(nest, cb, NULL);

	free(nest);
	return ret == MNL_CB_OK ? 0 : 1;
}
```

```text
SUMMARY: AddressSanitizer: heap-buffer-overflow src/attr.c:101:15 in mnl_attr_ok
```

#### Proposed Fix

The patch clamps the value in `mnl_attr_get_payload_len()` itself. That way it also covers applications that use the `mnl_attr_for_each_nested()` macro directly:

```diff
--- a/src/attr.c
+++ b/src/attr.c
@@ -63,6 +63,9 @@ EXPORT_SYMBOL uint16_t mnl_attr_get_len(const struct nlattr *attr)
  */
 EXPORT_SYMBOL uint16_t mnl_attr_get_payload_len(const struct nlattr *attr)
 {
+	if (attr->nla_len < MNL_ATTR_HDRLEN)
+		return 0;
+
 	return attr->nla_len - MNL_ATTR_HDRLEN;
 }
```

---

### `LIBMNL-04`: `mnl_nlmsg_fprintf` over-reads up to 3 bytes on unaligned messages

| Field | Value |
| :--- | :--- |
| **Fingerprint** | `src/nlmsg.c#mnl_nlmsg_fprintf_payload::mem_access::7b6a313aec` and `::a092230d5a` (both confirmed, same root cause). Also covers `needs_validation` `::2940a57682`. |
| **Pipeline Verdict** | `confirmed` (E-ACSL witnesses `workspace/crashes/nlmsg/crash-d821a213368c953bc6a6bd4e11f12b9d8e280f22`, `crash-aa5f1a4c5a9e0031f0333e258d29001984724a72`) |
| **Status** | Reported |
| **Upstream Ticket** | [Patch 4/5 on netfilter-devel](https://lore.kernel.org/netfilter-devel/20261106191841.1645-5-florian.stosse@harvester.fr/) (2026-11-06) |
| **Severity** | **Low**. A read-only over-read of at most 3 bytes in a debug printer. Receive buffers are normally larger than the message, so it needs an exact-size heap buffer. |
| **Reachability** | `internal_api` |
| **Location** | [`src/nlmsg.c:305`](https://git.netfilter.org/libmnl/tree/src/nlmsg.c?id=d24c88693be13ae77843e18e3388ca9142efdc31#n305) (`mnl_nlmsg_fprintf_payload`) |
| **Failing Property** | `mem_access`: `\valid_read(b + (i + 3))` |

#### Description & Root Cause

```c
// src/nlmsg.c:305
	for (i=sizeof(struct nlmsghdr); i<nlh->nlmsg_len; i+=4) {
		...  b[i], b[i+1], b[i+2], b[i+3] ...   // <-- whole 4-byte word read even if i + 4 > nlmsg_len
```

`mnl_nlmsg_ok()` does not require `nlmsg_len` to be a multiple of 4. For an unaligned length, the last iteration reads 1–3 bytes past the message.

#### Minimal Standalone Reproducer

```c
#include <libmnl/libmnl.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
	unsigned char *buf = calloc(1, 17);
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;

	nlh->nlmsg_len = 17;
	nlh->nlmsg_type = NLMSG_MIN_TYPE;
	buf[16] = 0x41;
	mnl_nlmsg_fprintf(stdout, buf, 17, 0);
	free(buf);
	return 0;
}
```

```text
SUMMARY: AddressSanitizer: heap-buffer-overflow src/nlmsg.c:323:33 in mnl_nlmsg_fprintf_payload
```

#### Proposed Fix

```diff
--- a/src/nlmsg.c
+++ b/src/nlmsg.c
@@ -302,7 +302,7 @@ static void mnl_nlmsg_fprintf_payload(FILE *fd, const struct nlmsghdr *nlh,
 	if (fdnum != -1)
 		colorize = isatty(fdnum);
 
-	for (i=sizeof(struct nlmsghdr); i<nlh->nlmsg_len; i+=4) {
+	for (i=sizeof(struct nlmsghdr); i + 4 <= nlh->nlmsg_len; i+=4) {
 		char *b = (char *) nlh;
 		struct nlattr *attr = (struct nlattr *) (b+i);
```

---

### `LIBMNL-05`: Signed overflow negating `INT_MIN` in `mnl_cb_error`

| Field | Value |
| :--- | :--- |
| **Fingerprint** | `src/callback.c#mnl_cb_error::signed_overflow::afc427fc0e` |
| **Pipeline Verdict** | `confirmed` (witness `workspace/crashes/callback/crash-132a653a854c8db92af538dda40209b882c53ca8`) |
| **Status** | Reported |
| **Upstream Ticket** | [Patch 5/5 on netfilter-devel](https://lore.kernel.org/netfilter-devel/20261106191841.1645-6-florian.stosse@harvester.fr/) (2026-11-06) |
| **Severity** | **Low**. C11 undefined behaviour on a field of a received `NLMSG_ERROR` message. In practice it wraps, `errno` gets a meaningless negative value, and `MNL_CB_ERROR` is still returned. |
| **Reachability** | `untrusted_surface` (the value comes from the received message, but needs a forged `NLMSG_ERROR` or a buggy kernel subsystem) |
| **Location** | [`src/callback.c:29`](https://git.netfilter.org/libmnl/tree/src/callback.c?id=d24c88693be13ae77843e18e3388ca9142efdc31#n29) (`mnl_cb_error`) |
| **Failing Property** | `signed_overflow`: negation of `-2147483648` cannot be represented in type `int` (C11 6.5p5 / CWE-190) |

#### Description & Root Cause

```c
// src/callback.c:27-31
	/* Netlink subsystems returns the errno value with different signess */
	if (err->error < 0)
		errno = -err->error;   // <-- UB for err->error == INT_MIN
	else
		errno = err->error;
```

Only the payload length of the `nlmsgerr` is validated, not its value.

#### Minimal Standalone Reproducer

```c
#include <libmnl/libmnl.h>
#include <linux/netlink.h>
#include <limits.h>
#include <stdio.h>

int main(void)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	struct nlmsgerr *err;

	nlh->nlmsg_type = NLMSG_ERROR;
	err = mnl_nlmsg_put_extra_header(nlh, sizeof(*err));
	err->error = INT_MIN;

	printf("ret=%d\n", mnl_cb_run(buf, nlh->nlmsg_len, 0, 0, NULL, NULL));
	return 0;
}
```

```text
src/callback.c:29:11: runtime error: negation of -2147483648 cannot be represented in type 'int'; cast to an unsigned type to negate this value to itself
```

#### Proposed Fix

No errno has the value `INT_MIN`, so the patch reports the message as malformed. It uses `EBADMSG`, the same code `mnl_cb_error` already uses for a short `nlmsgerr`:

```diff
--- a/src/callback.c
+++ b/src/callback.c
@@ -8,6 +8,7 @@
  */
 
 #include <errno.h>
+#include <limits.h>
 #include <libmnl/libmnl.h>
 #include "internal.h"
 
@@ -25,7 +26,9 @@ static int mnl_cb_error(const struct nlmsghdr *nlh, void *data)
 		return MNL_CB_ERROR;
 	}
 	/* Netlink subsystems returns the errno value with different signess */
-	if (err->error < 0)
+	if (err->error == INT_MIN)
+		errno = EBADMSG;
+	else if (err->error < 0)
 		errno = -err->error;
 	else
 		errno = err->error;
```

---

## Patch Validation

The five patches were checked against a clean clone of the evaluated revision:

- They apply with `git am --whitespace=error` and pass `git diff --check`.
- The library builds with gcc and clang (`-Wall -Wextra`) with no new warnings. The 73 exported symbols are unchanged, and all 21 examples compile.
- All five reproducers above fail on the evaluated revision and run clean with the patches applied.
- A separate well-formed-use test gives byte-identical output on the patched and unpatched trees. It covers exact-fit `_check` calls, nested parsing, `mnl_nlmsg_fprintf` output, `NLMSG_ERROR` with either errno sign and the ACK case, and batch overflow followed by reset.
