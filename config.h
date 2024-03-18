#ifndef __CONFIG_HELPERS_H
#define __CONFIG_HELPERS_H

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>

struct ingress_state {
    __u32 ifindex;
    __u32 qfi;
};

struct egress_state {
    __u32 teid;
    __u32 qfi;
};

struct ip_addr {
	int af;
	union {
		struct in_addr addr4;
		struct in6_addr addr6;
	} addr;
};

struct gtpu_config {
    struct ip_addr saddr;
    struct ip_addr daddr;
};

#endif /* __CONFIG_HELPERS_H */