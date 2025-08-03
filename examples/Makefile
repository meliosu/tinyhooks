CC=gcc
CFLAGS=-Wall -Wextra -Wno-unused-parameter -O2

EXAMPLES_SOURCES=$(wildcard *.c)
EXAMPLES=$(EXAMPLES_SOURCES:%.c=%)

DEVKIT_PATH=../devkit
INCLUDE=-I$(DEVKIT_PATH)/

LIBS=-lZydis

all: $(EXAMPLES)

$(EXAMPLES): %: %.c $(DEVKIT_PATH)/libtinyhooks.a
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ $^ $(LIBS)

clean:
	rm -f $(EXAMPLES)
