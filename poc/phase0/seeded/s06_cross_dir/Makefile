CC ?= cc
AR ?= ar
CFLAGS = -O0 -g -Wall -Wextra -std=c99 -Iinclude -Icompat

all: libmsg.a

libmsg.a: src/msg.o compat/b64.o
	$(AR) rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f src/*.o compat/*.o libmsg.a

.PHONY: all clean
