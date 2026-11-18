/* L4_invariant, strong: 0 <= level <= 3 holds at the boundaries of step and after each of its writes. */
int level;

void step(void)
{
#ifdef VIOLATE
    level = 4; /* out of range between the two writes */
    level = 3;
#else
    if (level < 3)
        level = level + 1;
#endif
}
