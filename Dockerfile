FROM debian:trixie-slim

RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y build-essential binfmt-support qemu-user qemu-user-static
RUN apt-get install -y gcc-x86-64-linux-gnu libc6-dev-amd64-cross gcc-i686-linux-gnu libc6-dev-i386-cross
RUN apt-get install -y gcc-arm-linux-gnueabihf gcc-riscv64-linux-gnu

VOLUME /workspace
WORKDIR /workspace