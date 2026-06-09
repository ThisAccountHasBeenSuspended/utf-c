FROM debian:trixie-slim

# Kombiniert Updates und Installs, um die Image-Größe minimal zu halten
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc-x86-64-linux-gnu g++-x86-64-linux-gnu \
    gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf \
    gcc-aarch64-linux-gnu g++-aarch64-linux-gnu \
    gcc-riscv64-linux-gnu g++-riscv64-linux-gnu \
    qemu-user \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace