# compat16 - build and run the 16-bit compatibility mode experiments.
#
# -O0 is deliberate: several tests depend on exact register contents across an
# inline-asm mode transition, and optimisation is free to keep those values
# somewhere the test cannot see.

CC       ?= gcc
CFLAGS   ?= -std=gnu11 -O0 -g -Wall -Wextra -Werror
CPPFLAGS := -Iinclude -Itest
BUILD    := build
BIN      := $(BUILD)/test_compat16

SRCS := src/compat16.c test/harness.c test/test_compat16.c

.PHONY: all test clean

all: $(BIN)

$(BIN): $(SRCS) include/compat16.h test/harness.h | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(SRCS)

$(BUILD):
	mkdir -p $(BUILD)

test: $(BIN)
	./$(BIN)

clean:
	rm -rf $(BUILD)
