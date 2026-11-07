CC ?= cc
AR ?= ar
CFLAGS = -O0 -g -Wall -Wextra -std=c99 -Iinclude

all: libproto.a msgtool

libproto.a: src/handlers.o src/dispatch.o
	$(AR) rcs $@ $^

msgtool: tools/msgtool.o libproto.a
	$(CC) $(CFLAGS) -o $@ tools/msgtool.o libproto.a

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f src/*.o tools/*.o libproto.a msgtool

.PHONY: all clean
