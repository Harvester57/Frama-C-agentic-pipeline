/* L6_no_leak, indirect flow (plan step M3): a copy of the key reaches the sink under VIOLATE. */
#include <string.h>

void log_line(const char *msg);

static char key[16];
static char line[16];

int set_key(const char *k)
{
    if (!k)
        return -1;
    memcpy(key, k, sizeof key);
    return 0;
}

void show(void)
{
#ifdef VIOLATE
    memcpy(line, key, sizeof line); /* the copy MetAcsl's direct-flow property does not see */
#else
    memset(line, 'a', sizeof line);
#endif
    line[15] = 0;
    log_line(line);
}

void eva_main(void)
{
    char k[16] = "0123456789abcde";
    set_key(k);
    show();
}
