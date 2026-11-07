CC ?= cc
AR ?= ar
CFLAGS = -O0 -g -Wall -Wextra -std=c99 -Isrc

# src/ holds both the library and two programs; the library also pulls
# its quoting helpers from extra/.
LIBOBJS = src/csv.o src/field.o extra/quote.o

all: libcsv.a csvstat csvcut

libcsv.a: $(LIBOBJS)
	$(AR) rcs $@ $(LIBOBJS)

csvstat: src/csvstat.o libcsv.a
	$(CC) $(CFLAGS) -o $@ src/csvstat.o libcsv.a

csvcut: src/csvcut.o libcsv.a
	$(CC) $(CFLAGS) -o $@ src/csvcut.o libcsv.a

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f src/*.o extra/*.o libcsv.a csvstat csvcut

.PHONY: all clean
