/*
 * L6_no_leak, calling, global secret, decided statically: the satisfied version passes another global,
 * so the instance is obviously true and MetAcsl (-meta-simpl, its default) drops it: no goal is left.
 */
void log_line(const char *msg);

static char key[16];
static char banner[16];

void set_key(const char *k)
{
    key[0] = k[0];
}

void show(void)
{
#ifdef VIOLATE
    log_line(key); /* leak */
#else
    log_line(banner);
#endif
}
