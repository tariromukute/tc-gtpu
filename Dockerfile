FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y clang llvm iproute2 iputils-ping tcpdump make git \
    libelf1 libelf-dev zlib1g-dev gcc pkg-config 
    # && \
    # rm -rf /var/lib/apt/lists/*

WORKDIR /home

COPY . ./

RUN make build

# ENTRYPOINT ./entrypoint.sh
