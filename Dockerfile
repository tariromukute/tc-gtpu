FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y clang llvm libbpf-dev iproute2 iputils-ping tcpdump && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /home

COPY gtpu.bpf.c ./

RUN clang -O2 -emit-llvm -c gtpu.bpf.c -o - | llc -march=bpf -mcpu=probe -filetype=obj -o gtpu.bpf.o

# RUN tc qdisc add dev eth0 clsact
# RUN tc filter add dev eth0 ingress bpf direct-action obj gtpu.bpf.o sec .text
# RUN tc filter show dev eth0
# RUN tc filter show dev eth0 ingress
