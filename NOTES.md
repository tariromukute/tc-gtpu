
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

```bash
docker buildx build --platform=linux/amd64 -t tariromukute/tc-gtpu:latest -f Dockerfile .
```

Either:
1. create container and the mount the debugfs inside the container.

```bash
# For dev: -v `pwd`/:/home \
docker run \
    -it \
    --cap-add=NET_ADMIN \
    --cap-add=SYS_ADMIN \
    -v /sys/:/sys/ \
    --device /dev/net/tun \
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
./tc-gtpu -g eth0 -i uegtp -s 192.168.70.130 -d 192.168.70.134 -u 12.1.1.2 -b 12.1.1.1 --ul-teid 1234 --dl-teid 1234 -q 9 -n 2 -f /home/tu-gtpu.pcap -vvv
```

```bash
docker run -it --rm --privileged --pid=host ubuntu:latest nsenter -t 1 -m -u -n -i sh -c 'cat /proc/config.gz | gunzip | grep CONFIG_DEBUG_INFO_BTF'
```

Disable redirects on UPF to avoid duplicate packets
```bash
sysctl -a | grep redirects

sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.conf.eth0.accept_redirects=0

sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.conf.eth0.send_redirects=0

sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.conf.eth0.secure_redirects=0
```

```bash
ip link add br-gtp type bridge
ip netns add uegtp0
ip netns exec uegtp0 ip link
ip link add uegtp0_i type veth peer name uegtp0
ip netns exec uegtp0 ip link
ip link set uegtp0_i netns uegtp0
ip netns exec uegtp0 ip link
ip netns exec uegtp0 ip r
ip link set br-gtp up
ip netns add uegtp1
ip netns exec uegtp1 ip link
ip link add uegtp1_i type veth peer name uegtp1
ip netns exec uegtp1 ip link
ip link set uegtp1_i netns uegtp1
ip netns exec uegtp1 ip link
ip netns exec uegtp1 ip r
ip link set uegtp0 master br-gtp
ip link set uegtp1 master br-gtp
ip link set uegtp0 up
ip link set uegtp1 up
ip netns exec uegtp0 ip link set dev uegtp0_i up
ip netns exec uegtp0 ip link
ip netns exec uegtp0 ip r
ip netns exec uegtp1 ip link set dev uegtp1_i up
ip netns exec uegtp1 ip r
ip netns exec uegtp1 ip link
ip netns exec uegtp0 ip address add 12.1.1.2/24 dev uegtp0_i
ip netns exec uegtp0 ip link
ip netns exec uegtp0 ip a
ip netns exec uegtp0 ip r
ip netns exec uegtp1 ip address add 12.1.1.3/24 dev uegtp1_i
ip netns exec uegtp1 ip r
ip netns exec uegtp1 ip a
ping -c 4 -i 0.2 12.1.1.2
ping -c 4 -i 0.2 12.1.1.3
ip a add 12.1.1.1/24 brd + dev br-gtp
ip a | grep br-gtp
ip r
ping -c 4 -i 0.2 12.1.1.2
ip netns exec uegtp1 ip r
ping -c 4 -i 0.2 12.1.1.3
ip netns exec uegtp1 ip route add default via 12.1.1.1
ip netns exec uegtp1 ip r
ip netns exec uegtp0 ip route add default via 12.1.1.1
ip netns exec uegtp0 ip r
ping -c 4 -i 0.2 12.1.1.3
sysctl -w net.ipv4.ip_forward=1
ping -c 4 -i 0.2 12.1.1.3
ping -c 4 -i 0.2 12.1.1.2
ip netns exec uegtp1 ping -c 4 -i 0.2 12.1.1.2
ip netns exec uegtp0 ping -c 4 -i 0.2 12.1.1.3
```

# Enable TCP packets in NAT'ed env

```bash
ethtool --offload  <iface_name> rx off tx off

# Check for TCP related errors
netstat -s
```

```bash
sysctl net.ipv4.tcp_timestamps

sysctl -w net.ipv4.tcp_timestamps=0

```
## Useful Resources

- [Understanding tc “direct action” mode for BPF](https://qmonnet.github.io/whirl-offload/2020/04/11/tc-bpf-direct-action/)
- [Run eBPF Programs in Docker using docker-bpf](https://hemslo.io/run-ebpf-programs-in-docker-using-docker-bpf/)
- https://github.com/edgecomllc/eupf/issues/509
- http://arthurchiao.art/blog/differentiate-bpf-redirects/
- https://patchwork.kernel.org/project/netdevbpf/patch/20210512103451.989420-3-memxor@gmail.com/
- https://lore.kernel.org/bpf/d5995641-9ce9-9cad-7a58-999614550963@fb.com/
- https://lore.kernel.org/bpf/1567892444-16344-2-git-send-email-alan.maguire@oracle.com/
- https://github.com/siemens/edgeshark?tab=readme-ov-file#siemens-industrial-edge
- https://www.dasblinkenlichten.com/working-with-tc-on-linux-systems/
- https://www.alibabacloud.com/blog/why-are-linux-kernel-protocol-stacks-dropping-syn-packets_595251
- https://arstechnica.com/civis/threads/a-possibly-simple-sniffer-trace-question-psh-ack.343792/
- https://blogs.oracle.com/linux/post/notes-on-bpf-7-bpf-tc-and-generic-segmentation-offload