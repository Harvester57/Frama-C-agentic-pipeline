CC ?= cc
AR ?= ar
CPPFLAGS = -DHTTPP_ENABLE_CHUNKED -Iinclude -Isrc
CFLAGS = -O0 -g -Wall -Wextra -std=c99

LIBOBJS = src/chars.o src/headers.o src/parser.o src/chunked.o compat/strcasecmp.o

all: libhttpp.a httpdump

libhttpp.a: $(LIBOBJS)
	$(AR) rcs $@ $(LIBOBJS)

httpdump: tools/httpdump.o libhttpp.a
	$(CC) $(CFLAGS) -o $@ tools/httpdump.o libhttpp.a

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

clean:
	rm -f src/*.o compat/*.o tools/*.o libhttpp.a httpdump

.PHONY: all clean
