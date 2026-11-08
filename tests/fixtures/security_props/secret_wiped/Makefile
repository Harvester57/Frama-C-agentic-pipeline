CC ?= cc
CFLAGS = -O0 -g -Wall -Wextra -std=c99

all: libsession.a

session.o: session.c session.h
	$(CC) $(CFLAGS) -c -o $@ session.c

libsession.a: session.o
	ar rcs $@ session.o
