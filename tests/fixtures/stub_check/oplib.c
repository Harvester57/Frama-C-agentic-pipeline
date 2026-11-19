/* tests/test_stub_check.py (nginx run-4, S10): the real library behind workspace/stubs/op/oplib.h. */
struct op_ctx { int flags; };
/* OpenSSL's EVP_CIPHER_CTX_is_encrypting in miniature: reads a field of an object the caller allocated. */
int op_is_on(const struct op_ctx *ctx) { return ctx->flags; }
/* OpenSSL_version in miniature: a string in the library's own read-only data. */
const char *op_version(int t) { (void)t; return "oplib 1.0"; }
/* A function with genuine arguments only, whose documented ensures (`\result == 0`) is wrong. */
int op_answer(const int x) { (void)x; return 42; }
