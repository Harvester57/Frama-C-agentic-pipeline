/* L6_wiped, field secret of a parameter object: ctx->secret is zero when ctx_free returns. */
struct ctx {
    unsigned char secret[8];
    int n;
};

/*@ requires \valid(ctx); */
void ctx_free(struct ctx *ctx)
{
#ifndef VIOLATE
    /*@ loop invariant 0 <= i <= 8;
        loop invariant \forall integer j; 0 <= j < i ==> ctx->secret[j] == 0;
        loop assigns i, ctx->secret[0 .. 7];
        loop variant 8 - i;
    */
    for (int i = 0; i < 8; i++)
        ctx->secret[i] = 0;
#endif
    ctx->n = 0;
}
