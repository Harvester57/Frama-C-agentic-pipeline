/* L6_wiped, scalar global secret: token is zero when drop returns. */
static unsigned long token;

void set_token(unsigned long t)
{
    token = t;
}

void drop(void)
{
#ifndef VIOLATE
    token = 0; /* VIOLATE never wipes it */
#endif
}
