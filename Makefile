AR=ar rcs
CC=gcc
CFLAGS=-Wall -Wextra -O2

LIBS=-lZydis

INSTALL=./devkit

.PHONY: all install clean

all: libtinyhooks.a

install: $(INSTALL)/libtinyhooks.a $(INSTALL)/tinyhooks.h

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
	rm -f *.o *.a
