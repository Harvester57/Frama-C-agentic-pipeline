CC ?= cc
AR ?= ar
CFLAGS = -O0 -g -Wall -Wextra -std=c99 -pthread -Iinclude
LDLIBS = -pthread

all: libpool.a pooltool

libpool.a: src/queue.o src/pool.o
	$(AR) rcs $@ $^

pooltool: tools/pooltool.o libpool.a
	$(CC) $(CFLAGS) -o $@ tools/pooltool.o libpool.a $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f src/*.o tools/*.o libpool.a pooltool

.PHONY: all clean
