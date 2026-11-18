/* L4_invariant, monotonic: phase only moves up, at every write. */
int phase;

void advance(void)
{
#ifdef VIOLATE
    phase = 0; /* moves back */
#else
    if (phase < 3)
        phase = phase + 1;
#endif
}
