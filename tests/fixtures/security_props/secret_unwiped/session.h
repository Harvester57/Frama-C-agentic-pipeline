#ifndef SESSION_H
#define SESSION_H
#include <stddef.h>

/* Provided by the application: writes one line to the system log. */
void log_line(const char *msg);

int session_login(const unsigned char *pw, size_t n);
void session_set_key(const unsigned char *k);
void session_admin(void);
void session_dispatch(int cmd);
void session_status(void);
void session_reset(void);
size_t session_copy_state(unsigned char *out);
void session_close(void);

#endif
