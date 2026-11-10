/* L4, the gate sets the state only on success (plan step M7): login returns 0 when the password matches. */
int auth_ok;

int login(int pw)
{
#ifdef VIOLATE
    auth_ok = 1; /* set before the check: a failed login leaves it set */
    if (pw != 42)
        return -1;
#else
    if (pw != 42)
        return -1;
    auth_ok = 1;
#endif
    return 0;
}

void admin(void);

void dispatch(int pw)
{
    if (login(pw) == 0 && auth_ok)
        admin();
}
