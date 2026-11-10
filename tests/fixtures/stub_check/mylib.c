#include <stddef.h>
struct ml_ctx { int x; };
int ml_hash(struct ml_ctx *ctx, const unsigned char *data, size_t len, unsigned char out[32]) {
  (void)ctx;
  for (int i = 0; i < 32; i++) out[i] = (unsigned char)(len ? data[i % len] ^ i : i);
  return 0;
}
const char *ml_name(const struct ml_ctx *ctx) { (void)ctx; return "mylib"; }
