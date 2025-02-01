CFLAGS = -Wall -Wextra -O0 -g -std=c11 -pedantic 
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

all: charm test

charm: charm.c
	$(CC) $(CFLAGS) charm.c -o charm

quick-test: charm
	./charm sample.S sample.elf

gdb-quick-test: charm
	gdb -tui charm -- sample.S sample.elf

test: charm
	@echo "Running tests..."
	@for test in $(wildcard tests/*.S); do \
		expected=$${test%.S}.expected; \
		echo "Testing $${test}..."; \
		./charm < $$test > test_output.txt; \
		diff test_output.txt $$expected && echo "✓ Passed" || echo "✗ Failed"; \
	done

clean:
	$(RM) -f charm.c.o
	$(RM) -f charm

.PHONY: clean
