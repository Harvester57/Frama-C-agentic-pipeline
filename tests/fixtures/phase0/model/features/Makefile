CFLAGS = -O0 -Iinclude

all: libhash.a libnest.a

libhash.a: src/hash.o
	ar rcs $@ $^

libnest.a: src/nest.o
	ar rcs $@ $^

clean:
	rm -f src/*.o *.a
