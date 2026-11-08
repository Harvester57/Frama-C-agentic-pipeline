CC ?= cc
AR ?= ar
CFLAGS = -O0 -g -Wall -Wextra -std=c99 -Iinclude

all: libsdf.a sdf_test

libsdf.a: src/sdf.o
	$(AR) rcs $@ $^

sdf_test: tests/test_sdf.o libsdf.a
	$(CC) $(CFLAGS) -o $@ tests/test_sdf.o libsdf.a

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f src/*.o tests/*.o libsdf.a sdf_test

.PHONY: all clean
