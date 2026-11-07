CC ?= cc
AR ?= ar

# Build configuration: CRC32 checksums, wire protocol v2, no compression.
FEATURES = -DWITH_CRC32 -DPROTO_VERSION=2
CPPFLAGS = $(FEATURES) -Iinclude -Isrc
CFLAGS = -O0 -g -Wall -Wextra -std=c99

all: libframe.a framecat

libframe.a: src/decode.o src/checksum.o
	$(AR) rcs $@ $^

framecat: tools/framecat.o src/platform.o libframe.a
	$(CC) $(CFLAGS) -o $@ tools/framecat.o src/platform.o libframe.a

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

clean:
	rm -f src/*.o tools/*.o libframe.a framecat

.PHONY: all clean
