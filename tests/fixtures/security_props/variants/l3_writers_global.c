/* L3_writers, global asset: only set_config writes config; store writes through a pointer. */
int config;

void set_config(int v)
{
    config = v;
}

/*@ requires \valid(out) && \separated(out, &config); */
void store(int *out, int v)
{
    *out = v;
#ifdef VIOLATE
    config = 0; /* not a declared writer */
#endif
}
