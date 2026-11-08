#include <stddef.h>
#include "session.h"

static unsigned char session_key[16];
static int session_open;
int auth_ok;

/* The auth gate: the only function meant to write auth_ok. */
int session_login(const unsigned char *pw, size_t n)
{
    auth_ok = (n == 4 && pw[0] == 'o' && pw[1] == 'p' && pw[2] == 'e' && pw[3] == 'n');
    return auth_ok ? 0 : -1;
}

void session_set_key(const unsigned char *k)
{
    for (size_t i = 0; i < sizeof session_key; i++)
        session_key[i] = k[i];
    session_open = 1;
}

/* Privileged: requires a passed gate. */
void session_admin(void)
{
    log_line("admin command");
}

void session_dispatch(int cmd)
{
    if (cmd == 1 && auth_ok)
        session_admin();
}

void session_status(void)
{
    log_line(session_open ? "open" : "closed");
}

/* Writes the auth state without being the gate (an L4 violation, on purpose). */
void session_reset(void)
{
    auth_ok = 0;
    session_open = 0;
}

/* Writes through a pointer (an L3 frame obligation). */
size_t session_copy_state(unsigned char *out)
{
    out[0] = (unsigned char)session_open;
    return 1;
}

/* Releases the session: the key is never wiped. */
void session_close(void)
{
    session_open = 0;
}
