/* L4_invariant, monotonic, a state reached from a parameter (c->phase): it only moves up. */
struct conn {
    int phase;
    int n;
};

/*@ requires \valid(c); */
void advance(struct conn *c)
{
#ifdef VIOLATE
    c->phase = 0; /* moves back */
#else
    if (c->phase < 3)
        c->phase = c->phase + 1;
#endif
}
