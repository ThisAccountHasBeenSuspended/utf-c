# Default flags
CFLAGS = -std=c99 -O2 -Wall -Wextra -I include

ifeq ($(arm),1)
	CC = arm-linux-gnueabihf-gcc
	CFLAGS += -static -mfpu=neon -mcpu=cortex-a9
	QEMU = qemu-arm -cpu cortex-a9
else
	CC = gcc
	CFLAGS += -mavx2 -mavx512bw
	QEMU =
endif

# Sources and targets
SRCS := $(wildcard tests/*.c)
BINS := $(patsubst tests/%.c,build/%,$(SRCS))

all: $(BINS)

build/%: tests/%.c | build
	$(CC) $(CFLAGS) $< -o $@

build:
	mkdir -p $@

run: all
	@for t in $(BINS); do echo "-> $$t"; $(QEMU) $$t; echo; done

clean:
	rm -rf build
