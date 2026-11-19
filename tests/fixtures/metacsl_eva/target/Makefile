CC ?= cc
CFLAGS = -O0 -g -Wall -Wextra -std=c99 $(DEFS)

all: libprog.a

prog.o: prog.c prog.h
	$(CC) $(CFLAGS) -c -o $@ prog.c

libprog.a: prog.o
	ar rcs $@ prog.o
