/* L3_readers, global asset: only check_pin reads pin. */
static int pin;

void set_pin(int v)
{
    pin = v;
}

int check_pin(int v)
{
    return v == pin;
}

/*@ requires \valid_read(p) && \separated(p, &pin); */
int peek(const int *p)
{
#ifdef VIOLATE
    return pin; /* not a declared reader */
#else
    return *p;
#endif
}
