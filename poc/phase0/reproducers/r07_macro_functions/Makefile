CC ?= cc
AR ?= ar
CFLAGS = -O0 -g -Wall -Wextra -std=c99 -Iinclude

all: librecord.a recdump

librecord.a: src/getters.o src/decode.o src/log.o
	$(AR) rcs $@ $^

recdump: tools/recdump.o librecord.a
	$(CC) $(CFLAGS) -o $@ tools/recdump.o librecord.a

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f src/*.o tools/*.o librecord.a recdump

.PHONY: all clean
