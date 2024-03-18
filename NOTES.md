
## Running on docker

```bash
# --cap-add=NET_ADMIN to allow tc to add dev (avoids error: RTNETLINK answers: Operation not permitted)
# --cap-add=SYS_ADMIN to allow ebpf to mount to bpf fs (avoids error: mount --make-private /sys/fs/bpf failed: Operation not permitted)

docker run \
    --cap-add=NET_ADMIN \
    --cap-add=SYS_ADMIN \
    -it \
    -v /sys/kernel/debug/:/sys/kernel/debug/ \
    -v `pwd`/:/home ubuntu:latest

apt update

apt install clang llvm libbpf-dev iproute2 iputils-ping

# -g for BTF
clang -O2 -emit-llvm -g -c gtpu.bpf.c -o - | \
	llc -march=bpf -mcpu=probe -filetype=obj -o gtpu.bpf.o

clang -o gtpu_loader gtpu_loader.c -lbpf

# On seperate terminal, print logs
cat /sys/kernel/debug/tracing/trace_pipe
```

Build with Dockerfile

Either:
1. create container and the mount the debugfs inside the container.

```bash
docker run \
    -it \
    # --privileged \
    --cap-add=NET_ADMIN \
    --cap-add=SYS_ADMIN \
    --device /dev/net/tun \
    -v /sys/:/sys/ \
    # -v /lib/modules/:/lib/modules/:ro \
    # -v /usr/src:/usr/src:ro \
    -v `pwd`/:/home \
    tariromukute/tc-gtpu:latest

mount -t debugfs debugfs /sys/kernel/debug
```

Or
2. Create a debugfs volume and then add it to the container

```bash
docker volume create --driver local --opt type=debugfs --opt device=debugfs debugfs

docker run \
    -it \
    --cap-add=NET_ADMIN \
    --cap-add=SYS_ADMIN \
    --device /dev/net/tun \
    -v debugfs:/sys/kernel/debug:rw \
    tariromukute/tc-gtpu:latest
```

Or
3. Docker compose file

## Create dummy interface to act as UE interface

```bash
ip link add uegtp0 type dummy
ip addr add 12.1.1.2/24 dev uegtp0
ip link set uegtp0 up

ip link show
```
## Attach eBPF programs

```bash
tc qdisc add dev eth0 clsact
tc filter add dev eth0 ingress bpf direct-action obj gtpu.bpf.o sec gtpu_ingress
tc filter add dev eth0 egress bpf direct-action obj gtpu.bpf.o sec gtpu_egress
tc filter show dev eth0
tc filter show dev eth0 ingress
tc filter show dev eth0 egress

tc qdisc add dev uegtp0 clsact
tc filter add dev uegtp0 ingress bpf direct-action obj gtpu.bpf.o sec tnl_if_ingress
tc filter add dev uegtp0 egress bpf direct-action obj gtpu.bpf.o sec tnl_if_egress
tc filter show dev uegtp0
tc filter show dev uegtp0 ingress
tc filter show dev uegtp0 egress
```

```bash
# Testing
ping -I uegtp0 8.8.8.8 -c 5
# Analyse packet
tcpdump -i eth0 -w tmp.pcap
```

Or

```bash
./gtpu_loader -g eth0 -i uegtp -s 172.0.0.1 -d 172.0.0.2 -u 12.1.1.2 -t 1234 -q 9 -n 2
```

```bash
docker run -it --rm --privileged --pid=host ubuntu:latest nsenter -t 1 -m -u -n -i sh -c 'cat /proc/config.gz | gunzip | grep CONFIG_DEBUG_INFO_BTF'
```
## Useful Resources

- [Understanding tc “direct action” mode for BPF](https://qmonnet.github.io/whirl-offload/2020/04/11/tc-bpf-direct-action/)
- [Run eBPF Programs in Docker using docker-bpf](https://hemslo.io/run-ebpf-programs-in-docker-using-docker-bpf/)
- https://github.com/edgecomllc/eupf/issues/509
- http://arthurchiao.art/blog/differentiate-bpf-redirects/

