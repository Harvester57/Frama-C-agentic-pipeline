# The default target also builds a unit test that needs the `check` framework, which the base build
# image does not have: `make` stops on a missing <check.h>. `make lib` builds only the library.
CC ?= cc
AR ?= ar
CFLAGS = -O0 -g -std=c99 -Iinclude

all: lib test_demo

lib: libdemo.a

libdemo.a: src/demo.o
	$(AR) rcs $@ $^

test_demo: tests/test_demo.o libdemo.a
	$(CC) -o $@ tests/test_demo.o libdemo.a -lcheck

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f src/*.o tests/*.o libdemo.a test_demo

.PHONY: all lib clean
