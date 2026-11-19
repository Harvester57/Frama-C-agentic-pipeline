/* MetAcsl under Eva (plan package B): an auth gate, a protected command and a network sink.
 * -DVIOLATE plants a write of the auth state outside the gate and leaves a sink byte unset. */
#include <stddef.h>
#include "prog.h"

int auth_ok;
static unsigned char level;

/* The auth gate: the only function meant to write auth_ok. */
int login(int pw)
{
    if (pw == 42) {
        auth_ok = 1;
        return 0;
    }
    return -1;
}

/* Privileged: requires a passed gate. */
int admin(int cmd)
{
    level = (unsigned char)(cmd & 0x7f);
    return level + 1;
}

/* Calls the privileged function only where the gate has set the auth state. */
int handle(int pw, int cmd)
{
    login(pw);
    if (!auth_ok)
        return -1;
    return admin(cmd);
}

#ifdef VIOLATE
/* Writes the auth state without being the gate (an L4 violation, on purpose). */
void backdoor(void)
{
    auth_ok = 1;
}
#endif

/* Writes through a pointer: checked against the auth state (and an L3 frame obligation). */
void get_level(unsigned char *out)
{
    *out = level;
}

/* Hands two bytes to the network sink. */
void emit(unsigned char v)
{
    unsigned char b[2];
    unsigned char lvl;
    get_level(&lvl);
    b[0] = (unsigned char)(v ^ lvl);
#ifndef VIOLATE
    b[1] = lvl; /* VIOLATE leaves b[1] uninitialized */
#endif
    send_bytes(b, 2);
}
