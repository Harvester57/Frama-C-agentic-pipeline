/* L5_sanitized, buffer: the sink's out-parameter is initialized when it returns. */
void finish(int *out, int v)
{
#ifndef VIOLATE
    *out = v; /* VIOLATE returns without writing it */
#else
    (void)out;
    (void)v;
#endif
}
