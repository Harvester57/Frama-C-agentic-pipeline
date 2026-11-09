CC ?= cc
AR ?= ar
CFLAGS = -O0 -g -Wall -Wextra -std=c99 -Iinclude

all: librcf.a

librcf.a: src/rcf.o
	$(AR) rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f src/*.o librcf.a

.PHONY: all clean
