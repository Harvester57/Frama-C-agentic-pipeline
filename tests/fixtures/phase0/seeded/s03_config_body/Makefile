CC ?= cc
AR ?= ar

# Optional features, passed to the compiler as -D<feature>.
FEATURES ?= FAST_UNESCAPE
CPPFLAGS = -Iinclude $(addprefix -D,$(FEATURES)) $(EXTRA_CPPFLAGS)
CFLAGS = -O0 -g -Wall -Wextra -std=c99

all: libpkt.a

libpkt.a: src/packet.o src/unescape.o
	$(AR) rcs $@ $^

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

# Rebuild for firmware < 2.0 (old unescaper).
legacy: clean
	$(MAKE) FEATURES= EXTRA_CPPFLAGS=-DLEGACY_UNESCAPE all

clean:
	rm -f src/*.o libpkt.a

.PHONY: all clean legacy
