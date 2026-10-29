/*
 * E-ACSL toolchain canary (run_eacsl_fuzz.py selftest).
 *
 * Built through the exact production E-ACSL path to verify, on every Frama-C /
 * image version, that:
 *   - host glibc typedefs resolve in host-header mode (__int32_t, u_short);
 *   - a variadic libc call (open) links (Variadic <fn>_fallback_<N> symbols);
 *   - an ACSL precondition is accepted;
 *   - the heap overflow reached by the input "FC33" + padding is detected and
 *     attributed to the line marked CANARY_OOB.
 * Keep the CANARY_OOB marker on the overflowing statement.
 */

#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#define CANARY_MAX_INPUT 64

/*@ requires len <= 64; */
static int canary_process(const uint8_t *data, size_t len)
{
    u_short short_len = (u_short)len;
    __int32_t widened = (__int32_t)short_len;

    if (len > 0 && data[0] == 'O') {
        int fd = open("/nonexistent/framac-canary", O_RDONLY, 0);
        if (fd >= 0) {
            close(fd);
        }
    }
    if (len >= 8 && data[0] == 'F' && data[1] == 'C' && data[2] == '3' && data[3] == '3') {
        char *heap = (char *)malloc(4);
        if (heap != NULL) {
            heap[len] = 0; /* CANARY_OOB */
            free(heap);
        }
    }
    return (int)widened;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == NULL || size > CANARY_MAX_INPUT) {
        return 0;
    }
    (void)canary_process(data, size);
    return 0;
}
