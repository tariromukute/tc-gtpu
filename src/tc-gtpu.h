#ifndef __CONFIG_HELPERS_H
#define __CONFIG_HELPERS_H

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include "gtpu.h"

struct ipv4_gtpu_encap {
    struct iphdr ipv4h;
    struct udphdr udp;
    struct gtpuhdr gtpu;
    struct gtpu_hdr_ext gtpu_hdr_ext;
    struct gtp_pdu_session_container pdu;
} __attribute__((__packed__));

struct ipv6_gtpu_encap {
    struct ipv6hdr ipv6h;
    struct udphdr udp;
    struct gtpuhdr gtpu;
    struct gtpu_hdr_ext gtpu_hdr_ext;
    struct gtp_pdu_session_container pdu;
} __attribute__((__packed__));

struct ingress_state {
    __u32 ifindex;
    __u32 qfi;
    unsigned char	if_mac[ETH_ALEN];
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
    int verbose_level;
    int gtpu_ifindex;
    struct ip_addr saddr;
    struct ip_addr daddr;
};

#endif /* __CONFIG_HELPERS_H */