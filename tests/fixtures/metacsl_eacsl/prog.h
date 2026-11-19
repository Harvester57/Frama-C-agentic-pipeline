#ifndef PROG_H
#define PROG_H

#include <stddef.h>

extern int auth_ok;

int login(const unsigned char *pw, size_t n);
int admin(void);
int emit(const char *buf, size_t n);
int logmsg(const char *s);
void session_close(void);
int process(const unsigned char *data, size_t n);

#endif
