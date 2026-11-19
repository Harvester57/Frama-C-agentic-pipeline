#ifndef OPLIB_H
#define OPLIB_H
typedef struct op_ctx op_ctx;
int op_is_on(const op_ctx *ctx);
const char *op_version(int t);
const char *op_name(int t);
int op_answer(const int x);
#endif
