ARG BASE_IMAGE=ubuntu:jammy
FROM $BASE_IMAGE as builder

WORKDIR /app

RUN apt-get update && \
    apt-get install -y clang llvm make git \
    libelf1 libelf-dev zlib1g-dev gcc pkg-config libpcap-dev

RUN if [ "$TARGETPLATFORM" = "linux/amd64" ]; then \
    apt-get install libc6-dev-i386; \
fi

RUN rm -rf /var/lib/apt/lists/*

COPY . ./

RUN make build

FROM $BASE_IMAGE AS runtime

RUN apt-get update && \
    apt-get install -y iproute2 iputils-ping tcpdump \
    libelf1 libelf-dev zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*

RUN apt-get autoremove -y && \
    apt-get clean -y && \
    rm -rf /var/cache/apt/* && \
    rm -rf /usr/share/locale/* && \
    rm -rf /usr/share/doc/* && \
    rm -rf /usr/share/man/* && \
    rm -rf /usr/share/info/*

WORKDIR /app

COPY --from=builder /app/src /app/
COPY ./entrypoint.sh /app/bin/entrypoint.sh

# ENTRYPOINT ./entrypoint.sh
