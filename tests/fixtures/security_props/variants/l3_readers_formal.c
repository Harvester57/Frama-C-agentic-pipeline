/* L3_readers, an asset reached from a parameter (c->token, passed as `s` to peek): only use_token reads it. */
struct conf {
    int token;
    int count;
};

void set_token(struct conf *c, int t)
{
    c->token = t;
}

int use_token(const struct conf *c, int t)
{
    return c->token == t;
}

/*@ requires \valid_read(s); */
int peek(const struct conf *s)
{
#ifdef VIOLATE
    return s->token; /* not a declared reader */
#else
    return s->count;
#endif
}
