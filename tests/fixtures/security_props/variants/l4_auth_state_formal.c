/* L4_auth_state, state reached from a parameter (s->ok): only check writes it. */
struct sess {
    int ok;
    int count;
};

int check(struct sess *s, int pw)
{
    s->ok = (pw == 42);
    return s->ok ? 0 : -1;
}

void act(struct sess *s)
{
    (void)s;
}

void bump(struct sess *s)
{
#ifdef VIOLATE
    s->ok = 1; /* not the gate */
#else
    s->count = 0;
#endif
}
