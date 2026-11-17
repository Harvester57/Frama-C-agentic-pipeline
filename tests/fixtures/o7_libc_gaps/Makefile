# demo includes two libc headers Frama-C's libc lacks, glibc's <elf.h> and linux-libc-dev's
# <linux/audit.h>: the capture exports the build image's copies to the run's snapshot, and Frama-C
# parses read them before the analysis image's own (open topic O7).
CFLAGS ?= -O0 -g

all: demo

demo: demo.c
	$(CC) $(CFLAGS) demo.c -o demo
