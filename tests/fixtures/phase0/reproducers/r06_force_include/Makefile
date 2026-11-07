CC ?= cc
AR ?= ar
CPPFLAGS = -include config.h -Iinclude -iquote src/internal -isystem vendor/include
CFLAGS = -O0 -g -Wall -Wextra -std=c99

all: libtlv.a tlvdump

libtlv.a: src/tlv.o src/version.o
	$(AR) rcs $@ $^

tlvdump: tools/tlvdump.o libtlv.a
	$(CC) $(CFLAGS) -o $@ tools/tlvdump.o libtlv.a

%.o: %.c config.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

clean:
	rm -f src/*.o tools/*.o libtlv.a tlvdump

.PHONY: all clean
