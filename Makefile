CFLAGS = -Wall -Wextra -O0 -g -std=c2x -pedantic 
ENABLE_SANITIZERS ?= 1
ifeq ($(ENABLE_SANITIZERS), 1)
	CFLAGS += -fsanitize=address \
		-fsanitize=undefined -fsanitize=leak \
		-fsanitize=bounds-strict -fsanitize=bounds \
		-fsanitize=alignment -fsanitize=float-divide-by-zero \
		-fsanitize=float-cast-overflow -fsanitize=nonnull-attribute \
		-fsanitize=null -fsanitize=return \
		-fsanitize=signed-integer-overflow -fsanitize=undefined \
		-fsanitize=unreachable -fsanitize=vla-bound -fsanitize=vptr \
		-fsanitize=pointer-compare -fsanitize=pointer-subtract \
		-fsanitize=pointer-overflow -fsanitize=return -fsanitize=shift \
		-fsanitize=shift-base -fsanitize=shift-exponent \
		-fsanitize=integer-divide-by-zero -fsanitize=pointer-overflow
endif

build: charm
all: charm
.PHONY: all build clean test

charm: charm.c
	$(CC) $(CFLAGS) charm.c -o charm

test: charm
	./run-tests.sh

clean:
	$(RM) -f charm.c.o
	$(RM) -f charm
	$(RM) -f tests/*.elf
	$(RM) -f tests/*.actual
	$(RM) -f tests/*.expected
