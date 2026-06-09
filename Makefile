CFLAGS = -std=c99 -O2 -Wall -Wextra -I include -static

# Validation: Was ARCH passed?
ifndef ARCH
$(error Error: You must specify ARCH! Usage: make ARCH=[x86_64|arm|aarch64|riscv] [Optional SIMD flags])
endif

# --- ARCHITECTURE: x86_64
ifeq ($(ARCH),x86_64)
    CC = x86_64-linux-gnu-gcc
    QEMU = qemu-x86_64 -cpu max
    
    # Optional Extensions
    ifeq ($(sse2),1)
        CFLAGS += -msse2
    endif
    ifeq ($(avx2),1)
        CFLAGS += -mavx2
    endif
    ifeq ($(avx512),1)
        CFLAGS += -mavx512f -mavx512bw
    endif

# --- ARCHITECTURE: arm (32-Bit)
else ifeq ($(ARCH),arm)
    CC = arm-linux-gnueabihf-gcc
    CFLAGS += -mcpu=cortex-a9
    QEMU = qemu-arm -cpu cortex-a9
    
    ifeq ($(neon),1)
        CFLAGS += -mfpu=neon
    endif

# --- ARCHITECTURE: aarch64 (64-Bit ARM)
else ifeq ($(ARCH),aarch64)
    CC = aarch64-linux-gnu-gcc
    CFLAGS += -mcpu=cortex-a53
    QEMU = qemu-aarch64 -cpu cortex-a53
    # Note: On AArch64, NEON/ASIMD is always enabled by default.

# --- ARCHITECTURE: riscv (64-Bit)
else ifeq ($(ARCH),riscv)
    CC = riscv64-linux-gnu-gcc
    QEMU = qemu-riscv64 -cpu max
    
    ifeq ($(rvv),1)
        CFLAGS += -march=rv64gcv -mabi=lp64d
    else
        CFLAGS += -march=rv64gc -mabi=lp64d
    endif

# --- Fallback for typos
else
$(error Invalid ARCH '$(ARCH)'. Valid values are: x86_64, arm, aarch64, riscv)
endif

# --- Build logic
SRCS := $(wildcard tests/*.c)
BINS := $(patsubst tests/%.c,build/$(ARCH)/%,$(SRCS))

all: $(BINS)

build/$(ARCH)/%: tests/%.c | build/$(ARCH)
	$(CC) $(CFLAGS) $< -o $@

build/$(ARCH):
	mkdir -p $@

run: all
	@for t in $(BINS); do echo "-> Executing $$t"; $(QEMU) $$t; echo; done

clean:
	rm -rf build