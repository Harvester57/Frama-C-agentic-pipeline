/*
 * L3_writers, an asset reached from a parameter (c->mode): only set_mode writes it. The object is
 * passed as `c` to set_mode and as `s` to bump: the threat model lists both names (`params`), and the
 * property has one clause per name.
 */
struct conf {
    int mode;
    int count;
};

void set_mode(struct conf *c, int m)
{
    c->mode = m;
}

/*@ requires \valid(s); */
void bump(struct conf *s)
{
#ifdef VIOLATE
    s->mode = 1; /* not a declared writer */
#else
    s->count = 0;
#endif
}
