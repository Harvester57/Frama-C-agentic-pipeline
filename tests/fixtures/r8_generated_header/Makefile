# The build generates build/config.h (as configure or CMake would): the target never has it.
# demo links zlib, a package the analysis image does not have: its header and library reach the
# analysis image through the run's snapshot (remediation plan step R8).
CFLAGS ?= -O0 -g

all: demo

build/config.h:
	mkdir -p build
	printf '#define GREETING "hello"\n' > build/config.h

demo.o: demo.c build/config.h
	$(CC) $(CFLAGS) -Ibuild -c demo.c -o demo.o

demo: demo.o
	$(CC) demo.o -lz -o demo
