FROM debian:trixie-slim

RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y build-essential gcc-multilib libc6-dev-i386
RUN apt-get install -y qemu-user qemu-user-static binfmt-support gcc-arm-linux-gnueabihf gcc-riscv64-linux-gnu

VOLUME /workspace
WORKDIR /workspace