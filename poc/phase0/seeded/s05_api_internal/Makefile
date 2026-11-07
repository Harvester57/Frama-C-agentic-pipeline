CC ?= cc
AR ?= ar
CFLAGS = -O0 -g -Wall -Wextra -std=c99 -Iinclude

all: libkv.a

libkv.a: src/kv.o
	$(AR) rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f src/*.o libkv.a

.PHONY: all clean
