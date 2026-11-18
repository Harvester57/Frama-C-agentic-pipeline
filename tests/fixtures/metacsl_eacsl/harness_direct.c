/*
 * The harness of harness_prog.c, which also calls the protected function itself on input 'H':
 * no gate was passed, so its `requires` fails there on a correct target.
 */
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

    auth_ok = 0;
    if (size > 0 && bounded_buf[0] == 'H') {
        (void)admin();
    }
    (void)process(bounded_buf, size);

    free(alloc_ptr);
    return 0;
}
