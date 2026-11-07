#ifndef API_H
#define API_H

/* A macro alias chain, as tweetnacl's: crypto_hash -> crypto_hash_sha512 -> crypto_hash_sha512_tweet. */
#define crypto_hash crypto_hash_sha512
#define crypto_hash_sha512 crypto_hash_sha512_tweet

int crypto_hash_sha512_tweet(unsigned char *out, const unsigned char *in, unsigned long n);
int nest_sum(int n);

/* Compiled by both units: one function, two units. */
static inline int clamp(int v) { return v < 0 ? 0 : v; }

#endif
