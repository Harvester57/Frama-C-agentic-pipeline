/* L6_no_leak, reading: the sink the target defines never reads key. */
static unsigned char key[16];
static unsigned char last;

void set_key(const unsigned char *k)
{
    key[0] = k[0];
}

/*@ requires \valid_read(msg) && \separated(msg, &key); */
void log_line(const unsigned char *msg)
{
    last = msg[0];
#ifdef VIOLATE
    last = key[0]; /* the sink reads the secret */
#endif
}
