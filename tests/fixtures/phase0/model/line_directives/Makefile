# Generated-source shapes (flex, bison): relative line directives that name a grammar file and the
# source itself, resolved by the compiler against src/ (where it runs), not against the tree root.
# The grammar files are shipped next to their outputs, as sudo ships toke.l and gram.y: no lex or yacc
# rule may regenerate the sources.
MAKEFLAGS += --no-builtin-rules
.SUFFIXES:
CFLAGS = -O0
OBJS = src/scan.o src/gram.o src/hdrline.o

all: libld.a

libld.a: $(OBJS)
	ar rcs $@ $^

src/%.o: src/%.c
	cd src && $(CC) $(CFLAGS) -c $*.c -o $*.o

clean:
	rm -f src/*.o *.a
