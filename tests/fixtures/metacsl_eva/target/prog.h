#ifndef PROG_H
#define PROG_H
#include <stddef.h>

/* Provided by the application: sends n bytes to the peer. */
void send_bytes(const unsigned char *buf, size_t n);

int login(int pw);
int admin(int cmd);
int handle(int pw, int cmd);
void get_level(unsigned char *out);
void emit(unsigned char v);
#ifdef VIOLATE
void backdoor(void);
#endif

#endif
