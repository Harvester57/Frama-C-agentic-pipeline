CC ?= cc
AR ?= ar
CFLAGS = -O0 -g -Wall -Wextra -std=c99 -Iinclude

all: libkv.a kvfmt

libkv.a: src/lexer.o src/emit.o
	$(AR) rcs $@ $^

kvfmt: tools/main.o libkv.a
	$(CC) $(CFLAGS) -o $@ tools/main.o libkv.a

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f src/*.o tools/*.o libkv.a kvfmt

.PHONY: all clean
