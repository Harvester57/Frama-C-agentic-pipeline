/* L4_auth_required, global state: admin requires auth_ok; dispatch calls it only after the gate. */
int auth_ok;

int login(int pw)
{
    auth_ok = (pw == 42);
    return auth_ok ? 0 : -1;
}

void admin(void)
{
}

void dispatch(int cmd)
{
#ifdef VIOLATE
    if (cmd == 1) /* no auth check */
#else
    if (cmd == 1 && auth_ok)
#endif
        admin();
}
