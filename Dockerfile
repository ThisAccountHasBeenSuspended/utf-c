FROM debian:13.1-slim

RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y build-essential gcc-multilib libc6-dev-i386

VOLUME /workspace
WORKDIR /workspace