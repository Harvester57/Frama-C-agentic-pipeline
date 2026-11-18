/* Calls placed in initializers (package E of docs/plans/metacsl-exploitation-plan.md).
 *
 * MetAcsl 0.12 gives a call written as an initializer (`int n = net_send(fd, buf, 8);`, a
 * `Local_init (_, ConsInit ...)` instruction) no \calling instance, no \writing instance from the
 * callee's assigns and no \strong_invariant instance. Each function below exists twice: `_assign`
 * calls in a statement, `_init` in an initializer.
 *
 * The default build satisfies every property; -DVIOLATE plants one violation per pair:
 *   f_*  seven uninitialized bytes handed to the sink `net_send`            (L5_sanitized_net_send)
 *   g_*  the secret `key` handed to the sink                            (L6_no_leak_key)
 *   h_*  the declared `fill` writes the auth state through its assigns  (L4_auth_state_login,
 *        and the invariant 0 <= auth_ok <= 1 is no longer known to hold after it)
 *   r_*  reads the secret (the \reading context does handle an initializer)
 */
/*@ assigns \result \from fd, buf[0 .. n - 1]; */
extern int net_send(int fd, const char *buf, unsigned long n);
/*@ assigns *out \from \nothing; */
extern int fill(int *out);

int auth_ok;
int counter;
char key[16];
char pub[16];

#ifdef VIOLATE
#define SENT key
#define FILLED auth_ok
/*@ requires \valid(buf + (0 .. 7)); assigns buf[0]; ensures \initialized(buf + (0 .. 0)); */ static void prepare(char *buf);
#else
#define SENT pub
#define FILLED counter
/*@ requires \valid(buf + (0 .. 7)); assigns buf[0 .. 7]; ensures \initialized(buf + (0 .. 7)); */ static void prepare(char *buf);
#endif

static void prepare(char *buf)
{
    int i;
    buf[0] = 'a';
#ifndef VIOLATE
    /*@ loop invariant 1 <= i <= 8;
        loop invariant \initialized(buf + (0 .. i - 1));
        loop assigns i, buf[1 .. 7];
        loop variant 8 - i; */
    for (i = 1; i < 8; i++)
        buf[i] = 'b';
#else
    (void)i;
#endif
}

void f_assign(int fd)
{
    char buf[8];
    int n;
    prepare(buf);
    n = net_send(fd, buf, 8);
    (void)n;
}

void f_init(int fd)
{
    char buf[8];
    prepare(buf);
    int n = net_send(fd, buf, 8);
    (void)n;
}

void g_assign(int fd)
{
    int n;
    n = net_send(fd, SENT, 16);
    (void)n;
}

void g_init(int fd)
{
    int n = net_send(fd, SENT, 16);
    (void)n;
}

void h_assign(void)
{
    int r;
    r = fill(&FILLED);
    (void)r;
}

void h_init(void)
{
    int r = fill(&FILLED);
    (void)r;
}

int r_assign(void)
{
    int x;
    x = SENT[0];
    return x;
}

int r_init(void)
{
    int x = SENT[0];
    return x;
}

void login(void)
{
    auth_ok = 1;
}
