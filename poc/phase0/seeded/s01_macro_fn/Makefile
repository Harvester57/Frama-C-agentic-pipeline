CC ?= cc
AR ?= ar
CFLAGS = -O0 -g -Wall -Wextra -std=c99 -Iinclude

LIB_OBJS = src/record.o src/readers.o

all: librec.a

librec.a: $(LIB_OBJS)
	$(AR) rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f src/*.o librec.a

.PHONY: all clean
