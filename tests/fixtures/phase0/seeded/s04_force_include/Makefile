CC ?= cc
AR ?= ar
CPPFLAGS = -include config.h -Iinclude -Ilib
CFLAGS = -O0 -g -Wall -Wextra -std=c99

all: libtlv.a

libtlv.a: src/tlv.o lib/bytes.o
	$(AR) rcs $@ $^

%.o: %.c config.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

clean:
	rm -f src/*.o lib/*.o libtlv.a

.PHONY: all clean
