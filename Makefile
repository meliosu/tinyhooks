AR=ar rcs
CC=gcc
CFLAGS=-Wall -Wextra -Wno-unused-parameter -O2

LIBS=-lZydis

INSTALL=./devkit

EXAMPLES=examples/malloc examples/simple examples/overhead examples/recursion examples/bench examples/backtrace

.PHONY: all install clean

all: libtinyhooks.a $(EXAMPLES)

install: $(INSTALL)/libtinyhooks.a $(INSTALL)/tinyhooks.h

$(EXAMPLES): %: %.c libtinyhooks.a
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

$(INSTALL)/libtinyhooks.a: libtinyhooks.a $(INSTALL)
	cp $< $@

$(INSTALL)/tinyhooks.h: tinyhooks.h $(INSTALL)
	cp $< $@

$(INSTALL):
	mkdir -p $@

libtinyhooks.a: tinyhooks.o tinyhooks-asm.o
	$(AR) $@ $^

tinyhooks-asm.o: tinyhooks-asm.S
	$(CC) $(CFLAGS) -o $@ -c $<

tinyhooks.o: tinyhooks.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f *.o *.a $(EXAMPLES)
