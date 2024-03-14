#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/swab.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <linux/ip.h>
#include "gtpu.h"

#define TC_ACT_UNSPEC         (-1)
#define TC_ACT_OK               0
#define TC_ACT_SHOT             2
#define TC_ACT_STOLEN           4
#define TC_ACT_REDIRECT         7

#define ETH_P_IP 0x0800 /* Internet Protocol packet */
#define __section(x) __attribute__((section(x), used))

#define DEFAULT_QFI 9
const int gtpu_interface  = 2;
const __u32 gtpu_dest_ip = 0xac120002; // 172.18.0.2

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

    if (data + sizeof(struct ethhdr) > data_end)
        return TC_ACT_SHOT;

    if (eth->h_proto == ___constant_swab16(ETH_P_IP)) {
        // TODO: Logic to fetch QFI and TEID from maps or use defaults
        __u32 qfi = DEFAULT_QFI;
        __u32 teid = skb->ifindex;  // Use interface index as default TEID

        
        int roomlen = sizeof(struct iphdr) + sizeof(struct gtpuhdr);
        // Check if there is enough headroom in the skb
        int ret = bpf_skb_adjust_room(skb, roomlen, BPF_ADJ_ROOM_MAC, 0);
        if (ret) {
            bpf_printk("error calling skb adjust room.\n");
            return TC_ACT_SHOT;
        }

        

        // Adjust pointers to new packet location after possible linearization
        data_end = (void *)(unsigned long long)skb->data_end;
        data = (void *)(unsigned long long)skb->data;
        eth = data;

        // TODO: Build GTPU header
        struct gtpuhdr gtpu_hdr = {
            .teid = bpf_htonl(teid),
        };

        // TODO: Build the IP header to deliver the GTPU packet to
        struct iphdr *ip = (struct iphdr*)(eth + 1);
        __be32 saddr = ip->saddr;
        __be32 daddr = bpf_htonl(gtpu_dest_ip);
        ip->saddr = daddr;
        ip->daddr = saddr;
        ip->ttl -= 1;
        ip->check = 0;
        // ip->check = ip_fast_csum(ip, ip->ihl);

        int offset = sizeof(struct ethhdr);
        ret = bpf_skb_store_bytes(skb, offset, ip, sizeof(struct iphdr),
                            BPF_F_RECOMPUTE_CSUM);
        if (ret) {
            bpf_printk("error storing ip header\n");
            return TC_ACT_SHOT;
        }

        offset += sizeof(struct iphdr);
        ret = bpf_skb_store_bytes(skb, offset, &gtpu_hdr, sizeof(struct gtpuhdr),
                            BPF_F_RECOMPUTE_CSUM);
        if (ret) {
            bpf_printk("error storing gtpu header\n");
            return TC_ACT_SHOT;
        }

        // TODO: Redirect to egress of gtpu_interface
        skb->protocol = bpf_htons(0x86dd);  // Change protocol to IPv6
        // skb->priority = TC_PRIO_CONTROL;
        // skb->mark = 0;
        // skb->vlan_present = 0;
        // skb->vlan_tci = 0;
        // skb->tc_index = 0;
        // skb->tc_classid = 0;
        // skb->cb = 0;
        // skb->dev = gtpu_interface;
        // skb->offload_fwd_mark = 0;
        return bpf_redirect(gtpu_interface, 0); // 0 for egress
        // bpf_redirect_neigh might be a better call

    } else {
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
	struct ethhdr *eth = data;

	if (data + sizeof(struct ethhdr) > data_end)
		return TC_ACT_SHOT;

	if (eth->h_proto == ___constant_swab16(ETH_P_IP)) {
        // TODO: Check if it's a GTPU packet

        // TODO: Logic to get the tunnel interface from tied_map or use default

        // TODO: Parse and remove GTPU header

        // TODO: Send packet to tunnel interface using bpf_redirect(tnl_interface, BPF_F_INGRESS)
		return TC_ACT_OK;
        // bpf_redirect_peer might be a better call
    } else {
		return TC_ACT_OK;
    }
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

char __license[] __section("license") = "GPL";