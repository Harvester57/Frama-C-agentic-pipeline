/*
 * Target of tests/test_metacsl_eacsl.py: a session with an authentication state, a protected
 * function, two output sinks and a secret. Correct as it is; each VIOLATE_* macro plants one
 * violation of a MetAcsl property of the test's security_props.json, and RTE_BUG an ordinary
 * out-of-bounds write. process() dispatches on the first input byte.
 * VIOLATE_MEMCPY writes the authentication state through memcpy, which the E-ACSL build checks only
 * with the libc writers' assigns (templates/metacsl/eacsl_libc_writers.h); RTE_MEMCPY is an ordinary
 * overflow through memcpy, whose identity must not change once those assigns give the call a check.
 */
#include <string.h>

#include "prog.h"

int auth_ok;
static unsigned long emitted;
static unsigned char session_key[16];

int emit(const char *buf, size_t n)
{
    (void)buf;
    emitted += n;
    return 0;
}

int logmsg(const char *s)
{
    (void)s;
    return 0;
}

int login(const unsigned char *pw, size_t n)
{
    if (n >= 2 && pw[0] == 'o' && pw[1] == 'k') {
        auth_ok = 1;
        return 0;
    }
    return -1;
}

int admin(void)
{
    return 7;
}

void session_close(void)
{
    size_t keep = 0;
#ifdef VIOLATE_WIPE
    keep = 1;
#endif
    for (size_t i = 0; i + keep < sizeof session_key; i++) {
        session_key[i] = 0;
    }
}

static void mix(unsigned char *dst, const unsigned char *src, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        dst[i] = (unsigned char)(src[i] ^ 0x5a);
    }
}

#ifdef VIOLATE_WRITE
static void backdoor(int *state)
{
    *state = 1;
}
#endif

int process(const unsigned char *data, size_t n)
{
    unsigned char work[64];
    char out[8];
    char line[16];
    int rc = 0;
    size_t m;

    if (n < 1) {
        return 0;
    }
#ifdef RTE_BUG
    m = n - 1;
#else
    m = n - 1 < sizeof work ? n - 1 : sizeof work;
#endif
    mix(work, data + 1, m);
    switch (data[0]) {
    case 'L':
        rc = login(data + 1, n - 1);
        break;
    case 'A':
#ifdef VIOLATE_PRECOND
        rc = admin();
#else
        if (auth_ok) {
            rc = admin();
        }
#endif
        break;
#ifdef VIOLATE_WRITE
    case 'B':
        backdoor(&auth_ok);
        break;
#endif
    case 'E':
        for (size_t i = 0; i < sizeof out; i++) {
#ifdef VIOLATE_INIT
            if (i == 5) {
                continue;
            }
#endif
            out[i] = (char)(i < m ? work[i] : 0);
        }
        rc = emit(out, sizeof out);
        break;
    case 'K':
        for (size_t i = 0; i < sizeof session_key && i < m; i++) {
            session_key[i] = work[i];
        }
        break;
    case 'C':
        for (size_t i = 0; i < sizeof session_key; i++) {
            session_key[i] = (unsigned char)(i < m ? work[i] : 1);
        }
        session_close();
        break;
#ifdef VIOLATE_LEAK
    case 'S':
        rc = emit((const char *)session_key, sizeof session_key);
        break;
#endif
    case 'T': {
        size_t k = m < sizeof line - 1 ? m : sizeof line - 1;
        for (size_t i = 0; i < k; i++) {
            char c = (char)data[1 + i];
#ifndef VIOLATE_TEXT
            if (c == '\r' || c == '\n') {
                c = ' ';
            }
#endif
            line[i] = c;
        }
        line[k] = '\0';
        rc = logmsg(line);
        break;
    }
    case 'W':
        /* a libc write into a local: correct. */
        memcpy(line, work, 8);
        break;
#ifdef VIOLATE_MEMCPY
    case 'X':
        memcpy(&auth_ok, work, sizeof auth_ok);
        break;
#endif
#ifdef RTE_MEMCPY
    case 'O':
        memcpy(out, work, m);
        break;
#endif
    default:
        break;
    }
    return rc;
}
