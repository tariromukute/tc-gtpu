#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/swab.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include "gtpu.h"
#include "config.h"
#include "parsing_helpers.h"

#define TC_ACT_UNSPEC         (-1)
#define TC_ACT_OK               0
#define TC_ACT_SHOT             2
#define TC_ACT_STOLEN           4
#define TC_ACT_REDIRECT         7

#define ETH_P_IP 0x0800 /* Internet Protocol packet */
#define __section(x) __attribute__((section(x), used))

#define DEFAULT_QFI 9
#define UDP_CSUM_OFF offsetof(struct udphdr, check)
#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))

const int gtpu_interface  = 22;
const __be32 gtpu_dest_ip = bpf_htonl(0xac110003); // 172.17.0.3
const __be32 gtpu_src_ip = bpf_htonl(0xac110002); // 172.17.0.2

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

static struct ipv4_gtpu_encap ipv4_gtpu_encap = {
	.ipv4h.version = 4,
    .ipv4h.ihl = 5,
    .ipv4h.ttl = 64,
    .ipv4h.protocol = IPPROTO_UDP,
    .ipv4h.saddr = bpf_htonl(0x0a000304), // 10.0.3.4
    .ipv4h.daddr = bpf_htonl(0x0a000305), // 10.0.3.5
    .ipv4h.check = 0, // bpf_htons(0x609b),

    .udp.source = bpf_htons(GTP_UDP_PORT),
	.udp.dest = bpf_htons(GTP_UDP_PORT),
    .udp.check = 0,
	
    .gtpu.flags = 0x34,
	.gtpu.message_type = GTPU_G_PDU,
    .gtpu.message_length = 0,
    
	.gtpu_hdr_ext.sqn = 0,
	.gtpu_hdr_ext.npdu = 0,
	.gtpu_hdr_ext.next_ext = GTPU_EXT_TYPE_PDU_SESSION_CONTAINER,
	.pdu.length = 1,
	.pdu.pdu_type = PDU_SESSION_CONTAINER_PDU_TYPE_UL_PSU,
	.pdu.next_ext = 0,
};

static struct ipv6_gtpu_encap ipv6_gtpu_encap = {
	.udp.source = bpf_htons(GTP_UDP_PORT),
	.udp.dest = bpf_htons(GTP_UDP_PORT),
	
    .gtpu.flags = 0x34,
	.gtpu.message_type = GTPU_G_PDU,
    .gtpu.message_length = 0,

	.gtpu_hdr_ext.sqn = 0,
	.gtpu_hdr_ext.npdu = 0,
	.gtpu_hdr_ext.next_ext = GTPU_EXT_TYPE_PDU_SESSION_CONTAINER,
	.pdu.length = 1,
	.pdu.pdu_type = PDU_SESSION_CONTAINER_PDU_TYPE_UL_PSU,
	.pdu.next_ext = 0,
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32); // teid
	__type(value, struct ingress_state);
	__uint(max_entries, 32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ingress_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32); // ifindex
	__type(value, struct egress_state);
	__uint(max_entries, 32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} egress_map SEC(".maps");

/* Logic for checksum, thanks to https://github.com/facebookincubator/katran/blob/main/katran/lib/bpf/csum_helpers.h */
__attribute__((__always_inline__))
static inline __u16 csum_fold_helper(__u64 csum) {
    int i;
#pragma unroll
    for (i = 0; i < 4; i++) {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

__attribute__((__always_inline__))
static inline void ipv4_csum(void* data_start, int data_size, __u64* csum) {
    *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
    *csum = csum_fold_helper(*csum);
}

__attribute__((__always_inline__))
static inline void ipv4_csum_inline(
    void* iph,
    __u64* csum) {
  __u16* next_iph_u16 = (__u16*)iph;
#pragma clang loop unroll(full)
    for (int i = 0; i < sizeof(struct iphdr) >> 1; i++) {
        *csum += *next_iph_u16++;
    }
    *csum = csum_fold_helper(*csum);
}


SEC("tnl_if_ingress")
int tnl_if_ingress_fn(struct __sk_buff *skb)
{
    /**
     * The function is attached to the ingress of the tunnel interface associated with a UE.
     * The receives the data after it have been decapsulated at teh interface that receives
     * the GTPU packets (gtpu ingress). This functions does nothing to the data except for other
     * util functions like recording the number of received packets etc. It returns TC_ACT_OK
    */
    bpf_printk("Received packet on tnl_if_ingress\n");
	void *data_end = (void *)(unsigned long long)skb->data_end;
	void *data = (void *)(unsigned long long)skb->data;
	struct ethhdr *eth = data;

	if (data + sizeof(struct ethhdr) > data_end)
		return TC_ACT_SHOT;

	if (eth->h_proto == ___constant_swab16(ETH_P_IP)) {
        bpf_printk("Got IP packet");
		return TC_ACT_OK;
    } else {
		return TC_ACT_OK;
    }
};

SEC("tnl_if_egress")
int tnl_if_egress_fn(struct __sk_buff *skb)
{
    /**
     * This function is attached to the egress of the tunnel interface associated with a UE.
     * The function encapsulates the IP data with a GTPU header. If the tnl_interfaces_map
     * contains data for the index of the interface, it will encapsulate the IP data based on
     * the values from the map i.e., qfi, tied etc. If the map doesn't have values, the qfi 
     * will equal the default qfi defined (DEFAULT_QFI) and tied will equal the interface 
     * index. The function then redirects the output to the egress of the gtpu_interface 
     * interface (the global const volatile variable gtpu_interface). It sets the destination
     * ip to the gtpu_dest_ip (global const volatile variable gtpu_dest_ip).
    */
    bpf_printk("Received packet on tnl_if_egress\n");
    void *data_end = (void *)(unsigned long long)skb->data_end;
    void *data = (void *)(unsigned long long)skb->data;
    struct ethhdr *eth = data;
    __u64 csum = 0;
    __u32 qfi, teid;
    __u32 key = skb->ifindex;
    struct egress_state *state;

    int payload_len = (data_end - data) - sizeof(struct ethhdr);

    if (data + sizeof(struct ethhdr) > data_end) {
        bpf_printk("error data less than eth header\n");
        return TC_ACT_SHOT;
    }

    if (eth->h_proto == ___constant_swab16(ETH_P_IP)) {
        // Logic to fetch QFI and TEID from maps or use defaults
        state = bpf_map_lookup_elem(&egress_map, &key);
        if (state && state->teid && state->qfi) {
            qfi = state->qfi;
            teid = state->teid;
        } else {
            qfi = DEFAULT_QFI;
            teid = skb->ifindex;  // Use interface index as default TEID
        }
            
        int roomlen = sizeof(struct ipv4_gtpu_encap);
        int ret = bpf_skb_adjust_room(skb, roomlen, BPF_ADJ_ROOM_MAC, 0);
        if (ret) {
            bpf_printk("error calling skb adjust room.\n");
            return TC_ACT_SHOT;
        }

        // Adjust pointers to new packet location after possible linearization
        data_end = (void *)(unsigned long long)skb->data_end;
        data = (void *)(unsigned long long)skb->data;
        eth = data;

        ipv4_gtpu_encap.ipv4h.daddr = gtpu_dest_ip;
        ipv4_gtpu_encap.ipv4h.saddr = gtpu_src_ip;
        ipv4_gtpu_encap.ipv4h.tot_len = bpf_htons(sizeof(struct ipv4_gtpu_encap) + payload_len);
        
        ipv4_gtpu_encap.udp.len = bpf_htons(sizeof(struct ipv4_gtpu_encap) + payload_len - sizeof(struct iphdr));

        ipv4_gtpu_encap.gtpu.teid = bpf_htonl(teid);
        ipv4_gtpu_encap.gtpu.message_length = bpf_htons(payload_len + sizeof(struct gtpu_hdr_ext) + sizeof(struct gtp_pdu_session_container));

        int offset = sizeof(struct ethhdr);
        ret = bpf_skb_store_bytes(skb, offset, &ipv4_gtpu_encap, roomlen, 0);
        if (ret) {
            bpf_printk("error storing ip header\n");
            return TC_ACT_SHOT;
        }
        
        bpf_printk("Redirecting to gtpu interface\n");
        return bpf_redirect_neigh(gtpu_interface, NULL, 0, 0);

    } else {
        bpf_printk("error: protocol not ETH_P_IP, it is: %d\n", eth->h_proto);
        return TC_ACT_OK;
    }
}


SEC("gtpu_ingress")
int gtpu_ingress_fn(struct __sk_buff *skb)
{
    /**
     * The function is attched to the ingress of the interface attached to the external
     * network, the gtpu_interface. The function decapsulates the GTPU header of the 
     * incoming packets and sends it to the ingress of the tunnel interface (tnl_interface).
     * The function gets the tunnel interface by checking the tied_map to get interface to
     * send to based on the tied of the incoming GTPU packet. If the tied_map does not contain
     * a valid value, it will treat the tied as the interface index to send to.
    */
    bpf_printk("Received packet on gtpu_ingress\n");
	void *data_end = (void *)(unsigned long long)skb->data_end;
	void *data = (void *)(unsigned long long)skb->data;
    int eth_type, ip_type, err;
	struct hdr_cursor nh = { .pos = data };
	struct ethhdr *eth;
	struct iphdr *iphdr;
    struct udphdr *udphdr;
    struct gtpuhdr *gtpuhdr;
	struct gtp_pdu_session_container *pdu;
    int tnl_interface;
    __u32 key, qfi;
    struct ingress_state *state;

    // Check if the incoming packet is GTPU
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type != bpf_htons(ETH_P_IP))
		goto out;

	ip_type = parse_iphdr(&nh, data_end, &iphdr);
	if (ip_type != IPPROTO_UDP)
		goto out;

	if (parse_udphdr(&nh, data_end, &udphdr) < 0)
		goto out;

    if (udphdr->dest != bpf_htons(GTP_UDP_PORT))
        goto out;

    if (parse_gtpuhdr(&nh, data_end, &gtpuhdr) < 0)
		goto out;
    
    key = bpf_ntohl(gtpuhdr->teid);
    state = bpf_map_lookup_elem(&ingress_map, &key);
    if (state && state->qfi && state->ifindex) {
        qfi = state->qfi;
        tnl_interface = state->ifindex;
    } else {
        qfi = DEFAULT_QFI;
        tnl_interface = gtpuhdr->teid; // default ifindex = teid
    }

    // bpf_redirect_peer might be a better call
    return bpf_redirect(tnl_interface, BPF_F_INGRESS);

out:
    return TC_ACT_OK;
};

SEC("gtpu_egress")
int gtpu_egress_fn(struct __sk_buff *skb)
{
    /**
     * The function is attched to the egress of the interface attached to the external
     * network. It receives GTPU encapuslated packets from the tunnel interfaces. This 
     * functions does nothing to the packet data except for other util functions like 
     * recording the number of received packets etc. It the sends the packet out.
    */
    bpf_printk("Received packet on gtpu_egress\n");
	void *data_end = (void *)(unsigned long long)skb->data_end;
	void *data = (void *)(unsigned long long)skb->data;
    int eth_type, ip_type, err;
    struct hdr_cursor nh = { .pos = data };
	struct ethhdr *eth; // = data;
    struct gtpuhdr *ghdr;
	struct gtp_pdu_session_container *pdu;
	struct iphdr *iphdr;
    struct udphdr *udphdr;
    __u64 csum = 0;

    eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type != bpf_htons(ETH_P_IP))
		goto out;

	ip_type = parse_iphdr(&nh, data_end, &iphdr);
	if (ip_type != IPPROTO_UDP)
		goto out;

	if (parse_udphdr(&nh, data_end, &udphdr) < 0)
		goto out;

    if (udphdr->dest != bpf_htons(GTP_UDP_PORT))
        goto out;

    ipv4_csum_inline(iphdr, &csum);
    iphdr->check = csum;

	bpf_printk("Got GTPU packet on egress");
out:
    return TC_ACT_OK;
};

char __license[] __section("license") = "GPL";