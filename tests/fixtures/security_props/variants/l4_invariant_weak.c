/* L4_invariant, weak: count <= limit holds when add starts and when it returns. */
int count;
int limit;

void add(int k)
{
#ifdef VIOLATE
    count = k; /* may pass the limit */
#else
    if (k > 0 && count < limit)
        count++;
#endif
}
