/* L4_auth_required, state reached from a parameter (s->ok): act requires it at its call sites. */
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

void serve(struct sess *s, int cmd)
{
#ifdef VIOLATE
    if (cmd == 1) /* no auth check */
#else
    if (cmd == 1 && s->ok)
#endif
        act(s);
}
