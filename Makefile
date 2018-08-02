CC ?= clang
CFLAGS ?= -Wall -Wextra -pedantic -std=c99 -O2

.PHONY: all
all:
	$(CC) $(CFLAGS) sandy.c -o sandy

.PHONY: clean
clean:
	$(RM) sandy
