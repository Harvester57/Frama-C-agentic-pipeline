/* Harness in the shape of templates/harness_dual.c.template (LibFuzzer entry only): it calls process(). */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "prog.h"

#ifndef MAX_INPUT_SIZE
#define MAX_INPUT_SIZE 256
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
#ifdef __FRAMAC_EACSL__
    extern int __e_acsl_sound_verdict;
    __e_acsl_sound_verdict = 1;
#endif
    if (data == NULL) {
        return 0;
    }
    if (size > MAX_INPUT_SIZE) {
        return -1;
    }
    uint8_t *alloc_ptr = (uint8_t *)malloc(size > 0 ? size : 1U);
    if (alloc_ptr == NULL) {
        return 0;
    }
    uint8_t *bounded_buf = (size > 0) ? alloc_ptr : (alloc_ptr + 1);
    if (size > 0) {
        memcpy(bounded_buf, data, size);
    }

    /* A fresh session per input: the harness's own write of the authentication state. */
    auth_ok = 0;
    (void)process(bounded_buf, size);

    free(alloc_ptr);
    return 0;
}
