/* libFuzzer target for rcf_parse (OSS-Fuzz style; not built by make). Its seed corpus is
 * fuzz_parse_seed_corpus.zip, next to it. */
#include <stddef.h>
#include <stdint.h>

#include "rcf.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    (void)rcf_parse(data, size);
    return 0;
}
