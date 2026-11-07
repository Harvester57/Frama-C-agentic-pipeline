CC ?= cc
CFLAGS = -O0 -g -Wall -Wextra -std=c99
LIB_CFLAGS = $(CFLAGS) -fPIC -fvisibility=hidden -Iinclude

LIBOBJS = lib/core/ringbuf.o lib/core/line.o lib/util/wrap.o

all: libringbuf.so rbcat

lib/%.o: lib/%.c
	$(CC) $(LIB_CFLAGS) -c -o $@ $<

libringbuf.so: $(LIBOBJS)
	$(CC) -shared -fPIC -o $@ $(LIBOBJS)

tools/rbcat.o: tools/rbcat.c
	$(CC) $(CFLAGS) -Iinclude -c -o $@ $<

rbcat: tools/rbcat.o libringbuf.so
	$(CC) $(CFLAGS) -o $@ tools/rbcat.o -L. -lringbuf -Wl,-rpath,'$$ORIGIN'

clean:
	rm -f lib/core/*.o lib/util/*.o tools/*.o libringbuf.so rbcat

.PHONY: all clean
