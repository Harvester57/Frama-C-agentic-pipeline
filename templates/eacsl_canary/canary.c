/*
 * E-ACSL toolchain canary (run_eacsl_fuzz.py selftest).
 *
 * Built through the exact production E-ACSL path to verify, on every Frama-C /
 * image version, that:
 *   - host glibc typedefs resolve in host-header mode (__int32_t, u_short);
 *   - a variadic libc call (open) links (Variadic <fn>_fallback_<N> symbols);
 *   - an ACSL precondition is accepted;
 *   - the heap overflow reached by the input "FC33" + padding is detected and
 *     attributed to the line marked CANARY_OOB;
 *   - the uninitialized read reached by the input "UNIN" + padding is detected
 *     (-rte-initialized);
 *   - a benign input runs clean. Every input writes a caller's stack buffer
 *     through canary_fill: without full memory tracking E-ACSL reports these
 *     valid writes as invalid, and without the runtime init hook
 *     (templates/eacsl_runtime/fuzz_init.c) every input crashes. Every input
 *     also reads a by-value struct parameter (canary_span_len) and a scalar
 *     parameter through its address (canary_odd): E-ACSL registers formals
 *     without marking them initialized, so without the build's formal-init
 *     pass every input fails \initialized on them.
 * Like generated harnesses, LLVMFuzzerTestOneInput copies the input into its
 * own buffer: libFuzzer writes `data` outside instrumented code, so with
 * -rte-initialized every direct read of it would be reported as uninitialized.
 * Keep the CANARY_OOB marker on the overflowing statement.
 */

#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define CANARY_MAX_INPUT 64

static void canary_fill(char *dst, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        dst[i] = (char)i;
    }
}

struct canary_span {
    const uint8_t *ptr;
    size_t len;
};

static size_t canary_span_len(struct canary_span span)
{
    return span.len;
}

static int canary_odd(size_t n)
{
    const size_t *pn = &n;
    return (int)(*pn & 1U);
}

static int canary_pick(const uint8_t *data, size_t len)
{
    int picked;

    if (len > 4 && data[4] == 'S') {
        picked = 1;
    }
    return picked; /* CANARY_UNINIT unless data[4] == 'S' */
}

/*@ requires len <= 64; */
static int canary_process(const uint8_t *data, size_t len)
{
    u_short short_len = (u_short)len;
    __int32_t widened = (__int32_t)short_len;
    char local[4] = {0};
    struct canary_span span = {data, len};

    canary_fill(local, len < sizeof local ? len : sizeof local);
    widened += canary_odd(canary_span_len(span));
    if (len > 0 && data[0] == 'O') {
        int fd = open("/nonexistent/framac-canary", O_RDONLY, 0);
        if (fd >= 0) {
            close(fd);
        }
    }
    if (len >= 5 && data[0] == 'U' && data[1] == 'N' && data[2] == 'I' && data[3] == 'N') {
        widened += canary_pick(data, len);
    }
    if (len >= 8 && data[0] == 'F' && data[1] == 'C' && data[2] == '3' && data[3] == '3') {
        char *heap = (char *)malloc(4);
        if (heap != NULL) {
            heap[len] = 0; /* CANARY_OOB */
            free(heap);
        }
    }
    return (int)widened + local[0];
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == NULL || size > CANARY_MAX_INPUT) {
        return 0;
    }
    uint8_t *copy = (uint8_t *)malloc(size > 0 ? size : 1U);
    if (copy == NULL) {
        return 0;
    }
    if (size > 0) {
        memcpy(copy, data, size);
    }
    (void)canary_process(copy, size);
    free(copy);
    return 0;
}
