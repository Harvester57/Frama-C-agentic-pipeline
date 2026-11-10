/* L4_auth_state, global state: only login writes auth_ok; store writes through a pointer. */
int auth_ok;

int login(int pw)
{
    auth_ok = (pw == 42);
    return auth_ok ? 0 : -1;
}

void admin(void)
{
}

/*@ requires \valid(out) && \separated(out, &auth_ok); */
void store(int *out, int v)
{
    *out = v;
#ifdef VIOLATE
    auth_ok = 0; /* not the gate */
#endif
}
