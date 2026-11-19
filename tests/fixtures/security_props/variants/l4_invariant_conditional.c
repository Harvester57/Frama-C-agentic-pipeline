/*
 * L4_invariant, conditional: an entry point keeps depth <= 8 when it holds on entry. Nothing is
 * required of its callers (a weak invariant would require it at every call).
 */
int depth;

void handle(int more)
{
#ifdef VIOLATE
    if (more)
        depth = 9;
#else
    if (more && depth < 8)
        depth++;
#endif
}
