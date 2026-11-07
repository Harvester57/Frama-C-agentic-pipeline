#include "api.h"

int crypto_hash_sha512_tweet(unsigned char *out, const unsigned char *in, unsigned long n)
{
    unsigned long i;
    for (i = 0; i < n; i++)
        out[i % 64] ^= in[i];
    return clamp((int)n);
}
