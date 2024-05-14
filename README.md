# GTP-U library based on eBPF TC

The project implements GTP-U encapusalation on traffic from network namespace. It can be used to emualte UE devices sending traffic to the UPF.

**Why the implementation**

The current support through libraries like [libgtpnl](http://git.osmocom.org/libgtpnl/) and [libgtp5gnl](https://github.com/free5gc/libgtp5gnl) require kernel modules, which in some environments, like Docker without control on the underlying host, can be difficult to get running. The docker environments make development and sharing of work easier. With eBPF, the GTP-U functionality can be supported without the need for kernel modules.

## Get started

This setup utilises Docker and Docker Compose for deployment. Ensure you have them installed before proceeding.

### Usage

| Option              | Short Option | Description                                                                                | Required |
|---------------------|--------------|--------------------------------------------------------------------------------------------|----------|
| --help              | -h           | Displays help message and available options                                                | No       |
| --gtpu-interface    | -g           | Name of the interface used for GTP-U tunnel encapsulation                                  | Yes      |
| --tnl-interface     | -i           | Prefix of the UE interfaces and UE/namespaces                                              | Yes      |
| --src-ip            | -s           | Source IP address of the GTP-U tunnel                                                      | Yes      |
| --dest-ip           | -d           | Destination IP address of the GTP-U tunnel                                                 | Yes      |
| --ue-ip             | -u           | IP address to be assigned to first User Equipment (UE). Incremented for subsequent UEs     | Yes      |
| --bridge-address    | -b           | Bridge interface address (Optional)                                                        | Yes      |
| --ul-teid           | -p           | Uplink TEID (Tunnel Endpoint Identifier)                                                   | Yes      |
| --dl-teid           | -l           | Downlink TEID (Tunnel Endpoint Identifier)                                                 | Yes      |
| --qfi               | -q           | Quality of Flow Identifier (QFI)                                                           | Yes      |
| --num-ues           | -n           | Number of simulated UEs (for testing purposes) (Optional)                                  |          |
| --pcap-file         | -f           | Path to a pcap file for recorded or captured traffic (only when verbose is vvv)            |          |
| --verbose           | -v           | Enable verbose output (Optional)                                                           |          |

### Test with docker compose (eUPF, pfcp-kitchen-sink, OpenN6LAN)

You can test the project with eUPF, using docker compose to intialise the setup. For more details on the setup see the [OpenN6LAN](https://github.com/tariromukute/OpenN6LAN) project.

```bash
# Set up
docker-compose -f docker-compose/docker-compose-pfcp-eupf.yaml up -d

# Run ping on one of the namespace (UE), eugtp0
docker exec -it ue-sim \
    ip netns exec uegtp0 ping -c 4 8.8.8.8

# Display traffic sent by UEs and on the GTP-U interface
docker exec -it ue-sim \
    tcpdump -ttttnnr /home/tu-gtpu.pcap
```

### On Docker

On Terminal 1:
```bash
docker run -d --name tc-gtpu \
    --cap-add=NET_ADMIN \
    --cap-add=SYS_ADMIN \
    --cap-add=CAP_SYS_ADMIN \
    --security-opt apparmor=unconfined \
    -v /sys/:/sys/ \
    --device /dev/net/tun \
    tariromukute/tc-gtpu:latest \
    tail -f /dev/null

docker exec -it tc-gtpu \
    ./tc-gtpu -g eth0 -i uegtp -s 192.168.71.130 -d 192.168.71.134 \
    -u 12.1.1.2 -b 12.1.1.1 --ul-teid 1234 --dl-teid 1234 --qfi 9 \
    -n 2 -f /home/tu-gtpu.pcap -vvv
```

On Terminal 2: Generate traffic
```bash
# Run ping on one of the namespace (UE), eugtp0
docker exec -it tc-gtpu \
    ip netns exec uegtp0 ping -c 4 8.8.8.8

# Get the pcap
docker exec -it tc-gtpu \
    tcpdump -ttttnnr /home/tu-gtpu.pcap
```

### Build docker image

Get project

```bash
# Clone repo
git clone --recurse-submodules https://github.com/tariromukute/tc-gtpu.git
# Navigate to project directory
cd tc-gtpu
```

Run project

```bash
docker buildx build --platform=linux/amd64 -t local/tc-gtpu:latest -f Dockerfile .
```

## Contribution

Please create an issue to report a bug or share an idea.