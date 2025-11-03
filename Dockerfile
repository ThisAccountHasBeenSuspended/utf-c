FROM debian:13.1-slim

RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y build-essential
RUN apt-get install -y qemu-user qemu-user-static binfmt-support gcc-arm-linux-gnueabihf

VOLUME /workspace
WORKDIR /workspace