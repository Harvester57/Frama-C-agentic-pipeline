/* L6_no_leak, calling, global secret: no sink argument points into key. */
void log_line(const char *msg);

static char key[16];

void set_key(const char *k)
{
    key[0] = k[0];
}

/*@ requires \separated(msg, &key); */
void show(const char *msg)
{
#ifdef VIOLATE
    (void)msg;
    log_line(key); /* leak */
#else
    log_line(msg);
#endif
}
