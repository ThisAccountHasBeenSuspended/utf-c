CC ?= gcc
CFLAGS ?= -std=c99 -O2 -Wall -Wextra -I include

SRCS := $(wildcard tests/*.c)
BINS := $(patsubst tests/%.c,build/%,$(SRCS))

all: $(BINS)

build/%: tests/%.c | build
	$(CC) $(CFLAGS) $< -o $@

build:
	mkdir -p $@

run: all
	@for t in $(BINS); do echo "-> $$t"; $$t; echo; done

clean:
	rm -rf build
