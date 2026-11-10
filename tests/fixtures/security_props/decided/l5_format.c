/* L5 format strings (plan step M5, CWE-134): syslog's format is a string literal at every call. */
#include <syslog.h>

void report(const char *user)
{
    syslog(LOG_INFO, "login: %s", user);
#ifdef VIOLATE
    syslog(LOG_INFO, user); /* the user's text is the format */
#endif
}
