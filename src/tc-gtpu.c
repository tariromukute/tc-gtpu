// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

static const char *__doc__=
 " TC GTPU Tunnel\n\n"
 " The user program attaches tc bpf programs using TC cmdline tool\n"
;

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <locale.h>
#include <linux/types.h>

#include <getopt.h>
#include <net/if.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>    

#include <linux/bpf.h>
#include <errno.h>
#include <assert.h>
#include <sys/sysinfo.h>
#include <sys/resource.h>
#include <libgen.h>
#include <linux/if_link.h>
#include <poll.h>
#include <sys/mman.h>
#define PCAP_DONT_INCLUDE_PCAP_BPF_H
#include <pcap/pcap.h>
#include <pcap/dlt.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <linux/limits.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "logging.h"
#include "tc-gtpu.h"
#include "tc-gtpu.skel.h"

#define LO_IFINDEX 1

#define CMD_MAX     2048
#define CMD_MAX_TC  256

static pcap_t* pd;
static pcap_dumper_t* pdumper;
static unsigned int pcap_pkts;

struct perf_buffer *pb;

static const char *default_filename = "tu-gtpu.pcap";
static char pcap_filename[PATH_MAX];
#define SAMPLE_SIZE 1024
#define NANOSECS_PER_USEC 1000

static volatile sig_atomic_t exiting = 0;

static int verbose_level = 0;
struct config {
	/* Define config */
	char *gtpu_ifname;
	char *tnl_ifname;
	struct ip_addr src_ip;
	struct ip_addr dest_ip;
	struct ip_addr ue_ip;
	struct ip_addr bridge_address;
	__u32 ul_teid;
	__u32 dl_teid;
	__u32 qfi;
	__u32 num_ues;
};

bool validate_ifname(const char* input_ifname)
{
	size_t len;
	int i;

	len = strlen(input_ifname);
	if (len >= IF_NAMESIZE) {
		return false;
	}
	for (i = 0; i < len; i++) {
		char c = input_ifname[i];

		if (!(isalpha(c) || isdigit(c)))
			return false;
	}
	return true;
}

static int validate_ip_address(const char *addr_str, struct ip_addr *ipaddr)
{
    struct in_addr addr4;
    struct in6_addr addr6;

    if (inet_pton(AF_INET, addr_str, &addr4) == 1) {
        ipaddr->af = AF_INET;
        ipaddr->addr.addr4 = addr4;
        return 0;
    }
    else if (inet_pton(AF_INET6, addr_str, &addr6) == 1) {
        ipaddr->af = AF_INET6;
        ipaddr->addr.addr6 = addr6;
        return 0;
    }

    return -1;
}

static const struct option long_options[] = {
	{"help",    no_argument,        NULL, 'h' },
	{"gtpu-interface",  required_argument,    NULL, 'g' },
	{"tnl-interface",   required_argument,    NULL, 'i' },
	{"src-ip", required_argument,    NULL, 's' },
	{"dest-ip",    required_argument,    NULL, 'd' },
	{"ue-ip",    required_argument,    NULL, 'u' },
	{"bridge-address", required_argument,    NULL, 'b' },
	{"ul-teid",    required_argument,    NULL, 'p' },
	{"dl-teid",    required_argument,    NULL, 'l' },
	{"qfi", required_argument,    NULL, 'q' },
	{"num-ues", optional_argument,    NULL, 'n' },
	{"pcap-file", optional_argument,    NULL, '-f' },
	{"verbose", optional_argument,    NULL, 'v' },
	/* HINT assign: optional_arguments with '=' */
	{0, 0, NULL,  0 }
};

static void usage(char *argv[])
{
	int i;
	printf("\nDOCUMENTATION:\n%s\n", __doc__);
	printf("\n");
	printf(" Usage: %s (options-see-below)\n",
		   argv[0]);
	printf(" Listing options:\n");
	for (i = 0; long_options[i].name != 0; i++) {
		printf(" --%-15s", long_options[i].name);
		if (long_options[i].flag != NULL)
			printf(" flag (internal value:%d)",
				   *long_options[i].flag);
		else
			printf("(internal short-option: -%c)",
				   long_options[i].val);
		printf("\n");
	}
	printf("\n");
}

void parse_cmdline_args(int argc, char **argv,
						const struct option *options,
						struct config *cfg, const char *doc)
{
	int opt;
	unsigned int gtpu_ifindex;

	while ((opt = getopt_long(argc, argv, "hg:i:s:d:u:b:t:p:l:q:n:f:v", options, NULL)) != -1) {
		switch(opt) {
			case 'h':
				usage(argv);
				exit(EXIT_SUCCESS);
				break;
			case 'g':
                if (!validate_ifname(optarg)) {
                    pr_warn("Invalid gtpu_ifname name\n");
                    usage(argv);
                    exit(EXIT_FAILURE);
                }
                cfg->gtpu_ifname = optarg;
                gtpu_ifindex = if_nametoindex(cfg->gtpu_ifname);
                if (gtpu_ifindex == 0) {
                    pr_warn("Interface %s does not exist\n", cfg->gtpu_ifname);
                    usage(argv);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'i':
                if (!validate_ifname(optarg)) {
                    pr_warn("Invalid tnl_ifname name\n");
                    usage(argv);
                    exit(EXIT_FAILURE);
                }
                cfg->tnl_ifname = optarg;
                break;
			case 's':
                if (validate_ip_address(optarg, &cfg->src_ip) != 0) {
					pr_warn("Invalid source IP address\n");
					usage(argv);
					exit(EXIT_FAILURE);
				}
                break;
            case 'd':
                if (validate_ip_address(optarg, &cfg->dest_ip) != 0) {
					pr_warn("Invalid destination IP address\n");
					usage(argv);
					exit(EXIT_FAILURE);
				}
                break;
			case 'u':
                if (inet_pton(AF_INET, optarg, &(cfg->ue_ip.addr.addr4)) <= 0) {
                    pr_warn("Invalid UE IP address '%s'\n", optarg);
                    exit(EXIT_FAILURE);
                }
                cfg->ue_ip.af = AF_INET;
				break;
			case 'b':
				if (inet_pton(AF_INET, optarg, &(cfg->bridge_address.addr.addr4)) <= 0) {
                    pr_warn("Invalid bridge IP address '%s'\n", optarg);
                    exit(EXIT_FAILURE);
                }
                cfg->bridge_address.af = AF_INET;
				break;
			case 'p':
                cfg->ul_teid = (__u32) strtoul(optarg, NULL, 0);
                break;
			case 'l':
                cfg->dl_teid = (__u32) strtoul(optarg, NULL, 0);
                break;
            case 'q':
                cfg->qfi = (__u32) strtoul(optarg, NULL, 0);
                break;
            case 'n':
                cfg->num_ues = (__u32) strtoul(optarg, NULL, 0);
                break;
			case 'f':
				strcpy(pcap_filename, optarg);
                break;
			case 'v':
				verbose_level++;
				if (verbose_level > 3) {
					verbose_level = 3;
				}
            	break;
			default:
				usage(argv);
				exit(EXIT_FAILURE);
				break;
		}
	}

	// Check if all required arguments were provided
	if (cfg->gtpu_ifname == NULL ||
		cfg->tnl_ifname == NULL ||
		cfg->src_ip.af == AF_UNSPEC ||
		cfg->dest_ip.af == AF_UNSPEC ||
		cfg->ue_ip.af == AF_UNSPEC ||
		cfg->ul_teid == 0 ||
		cfg->dl_teid == 0 ||
		cfg->qfi == 0 ||
		cfg->num_ues == 0)
	{
		usage(argv);
		exit(EXIT_FAILURE);
	}

	if (cfg->num_ues == 0) {
		cfg->num_ues = 1; // Default value
	}

	if (strlen(pcap_filename) == 0) {
		strcpy(pcap_filename, default_filename);
	}
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int set_if_mac(const char *ifname, __u8 m_addr[ETH_ALEN]) {
	struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, ifname);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {        
		memcpy(m_addr, s.ifr_addr.sa_data, ETH_ALEN);
        return 0;
    }

    return -1;
}
static int create_dummy_interface(const char* ifname, const char* ip_address) {
	char cmd[CMD_MAX];
	int ret = 0;

	// Step 1: Create dummy interface */
	memset(&cmd, 0, CMD_MAX);
	snprintf(cmd, CMD_MAX,
		 "ip link add %s type dummy 2> /dev/null",
		 ifname);
	pr_debug(" - Run: %s\n", cmd);
	ret = system(cmd);
	if (!WIFEXITED(ret)) {
		pr_debug(
			"ERR(%d): Cannot exec ip cmd\n Cmdline:%s\n",
			WEXITSTATUS(ret), cmd);
		exit(EXIT_FAILURE);
	}

	// Step 2: Assign ip address */
	memset(&cmd, 0, CMD_MAX);
	snprintf(cmd, CMD_MAX,
		 "ip addr add %s/24 dev %s 2> /dev/null",
		 ip_address, ifname);
	pr_debug(" - Run: %s\n", cmd);
	ret = system(cmd);
	if (!WIFEXITED(ret)) {
		pr_debug(
			"ERR(%d): Cannot exec ip cmd\n Cmdline:%s\n",
			WEXITSTATUS(ret), cmd);
		exit(EXIT_FAILURE);
	}

	// Step 3: Set interface up
	memset(&cmd, 0, CMD_MAX);
	snprintf(cmd, CMD_MAX,
		 "ip link set %s up 2> /dev/null",
		 ifname);
	pr_debug(" - Run: %s\n", cmd);
	ret = system(cmd);
	if (!WIFEXITED(ret)) {
		pr_debug(
			"ERR(%d): Cannot exec ip cmd\n Cmdline:%s\n",
			WEXITSTATUS(ret), cmd);
		exit(EXIT_FAILURE);
	}

	return ret;
}

static int delete_dummy_interface(const char* ifname) {
	char cmd[CMD_MAX];
	int ret = 0;

	// Step 1: Create dummy interface */
	memset(&cmd, 0, CMD_MAX);
	snprintf(cmd, CMD_MAX,
		 "ip link delete %s 2> /dev/null",
		 ifname);
	pr_debug(" - Run: %s\n", cmd);
	ret = system(cmd);
	if (!WIFEXITED(ret)) {
		pr_debug(
			"ERR(%d): Cannot exec ip cmd\n Cmdline:%s\n",
			WEXITSTATUS(ret), cmd);
		exit(EXIT_FAILURE);
	}

	return ret;
}

static int create_ns_bridge(const char* name, const char* address) {
	char cmd[CMD_MAX];
	int ret = 0;

	// Step 1: Create bridge
	memset(&cmd, 0, CMD_MAX);
	snprintf(cmd, CMD_MAX,
		 "ip link add %s type bridge 2> /dev/null",
		 name);
	pr_debug(" - Run: %s\n", cmd);
	ret = system(cmd);
	if (!WIFEXITED(ret)) {
		pr_debug(
			"ERR(%d): Cannot exec ip cmd\n Cmdline:%s\n",
			WEXITSTATUS(ret), cmd);
		exit(EXIT_FAILURE);
	}

	// Step 2: Set the bridge up
	memset(&cmd, 0, CMD_MAX);
	snprintf(cmd, CMD_MAX,
		 "ip link set %s up 2> /dev/null",
		 name);
	pr_debug(" - Run: %s\n", cmd);
	ret = system(cmd);
	if (!WIFEXITED(ret)) {
		pr_debug(
			"ERR(%d): Cannot exec ip cmd\n Cmdline:%s\n",
			WEXITSTATUS(ret), cmd);
		exit(EXIT_FAILURE);
	}

	// Step 3: assign address to bridge
	memset(&cmd, 0, CMD_MAX);
	snprintf(cmd, CMD_MAX,
		 "ip a add %s/24 brd + dev %s 2> /dev/null",
		 address, name);
	pr_debug(" - Run: %s\n", cmd);
	ret = system(cmd);
	if (!WIFEXITED(ret)) {
		pr_debug(
			"ERR(%d): Cannot exec ip cmd\n Cmdline:%s\n",
			WEXITSTATUS(ret), cmd);
		exit(EXIT_FAILURE);
	}
	
	return ret;
}

static int create_ue_ns(const char* br_postfix, const char* bridge_address, const char* ifname, const char* ip_address) {
	char cmd[CMD_MAX];
	int ret = 0;
	const char* name = ifname;

	// Step 1: Create namespance */
	printf("======= Name is %s", name);
	memset(&cmd, 0, CMD_MAX);
	snprintf(cmd, CMD_MAX,
		 "ip netns add %s 2> /dev/null",
		 name);
	pr_debug(" - Run: %s\n", cmd);
	ret = system(cmd);
	if (!WIFEXITED(ret)) {
		pr_debug(
			"ERR(%d): Cannot exec ip cmd\n Cmdline:%s\n",
			WEXITSTATUS(ret), cmd);
		exit(EXIT_FAILURE);
	}

	// Step 2: Create veth pair
	memset(&cmd, 0, CMD_MAX);
	snprintf(cmd, CMD_MAX,
		 "ip link add %s_i type veth peer name %s 2> /dev/null",
		 ifname, ifname);
	pr_debug(" - Run: %s\n", cmd);
	ret = system(cmd);
	if (!WIFEXITED(ret)) {
		pr_debug(
			"ERR(%d): Cannot exec ip cmd\n Cmdline:%s\n",
			WEXITSTATUS(ret), cmd);
		exit(EXIT_FAILURE);
	}

	// Step 3: Create set the namespace to the veth
	memset(&cmd, 0, CMD_MAX);
	snprintf(cmd, CMD_MAX,
		 "ip link set %s_i netns %s 2> /dev/null",
		 ifname, name);
	pr_debug(" - Run: %s\n", cmd);
	ret = system(cmd);
	if (!WIFEXITED(ret)) {
		pr_debug(
			"ERR(%d): Cannot exec ip cmd\n Cmdline:%s\n",
			WEXITSTATUS(ret), cmd);
		exit(EXIT_FAILURE);
	}

	// Step x: Set to bridge
	memset(&cmd, 0, CMD_MAX);
	snprintf(cmd, CMD_MAX,
		 "ip link set %s master br-%s 2> /dev/null",
		 ifname, br_postfix);
	pr_debug(" - Run: %s\n", cmd);
	ret = system(cmd);
	if (!WIFEXITED(ret)) {
		pr_debug(
			"ERR(%d): Cannot exec ip cmd\n Cmdline:%s\n",
			WEXITSTATUS(ret), cmd);
		exit(EXIT_FAILURE);
	}
	// Step 4: Set the floating veth up
	memset(&cmd, 0, CMD_MAX);
	snprintf(cmd, CMD_MAX,
		 "ip link set dev %s up 2> /dev/null",
		 ifname);
	pr_debug(" - Run: %s\n", cmd);
	ret = system(cmd);
	if (!WIFEXITED(ret)) {
		pr_debug(
			"ERR(%d): Cannot exec ip cmd\n Cmdline:%s\n",
			WEXITSTATUS(ret), cmd);
		exit(EXIT_FAILURE);
	}

	// Step 5: Set address for the inner veth pair
	memset(&cmd, 0, CMD_MAX);
	snprintf(cmd, CMD_MAX,
		 "ip netns exec %s ip addr add %s/24 dev %s_i 2> /dev/null",
		 name, ip_address, ifname);
	pr_debug(" - Run: %s\n", cmd);
	ret = system(cmd);
	if (!WIFEXITED(ret)) {
		pr_debug(
			"ERR(%d): Cannot exec ip cmd\n Cmdline:%s\n",
			WEXITSTATUS(ret), cmd);
		exit(EXIT_FAILURE);
	}

	// Step 7: Set the inner veth pair up
	memset(&cmd, 0, CMD_MAX);
	snprintf(cmd, CMD_MAX,
		 "ip netns exec %s ip link set %s_i up 2> /dev/null",
		 name, ifname);
	pr_debug(" - Run: %s\n", cmd);
	ret = system(cmd);
	if (!WIFEXITED(ret)) {
		pr_debug(
			"ERR(%d): Cannot exec ip cmd\n Cmdline:%s\n",
			WEXITSTATUS(ret), cmd);
		exit(EXIT_FAILURE);
	}

	// Step 8: Set the inner lo interface up
	memset(&cmd, 0, CMD_MAX);
	snprintf(cmd, CMD_MAX,
		 "ip netns exec %s ip link set lo up 2> /dev/null",
		 name);
	pr_debug(" - Run: %s\n", cmd);
	ret = system(cmd);
	if (!WIFEXITED(ret)) {
		pr_debug(
			"ERR(%d): Cannot exec ip cmd\n Cmdline:%s\n",
			WEXITSTATUS(ret), cmd);
		exit(EXIT_FAILURE);
	}

	// Step 9: Add default namespace
	
	memset(&cmd, 0, CMD_MAX);
	snprintf(cmd, CMD_MAX,
		 "ip netns exec %s ip route add default via %s 2> /dev/null",
		 name, bridge_address);
	pr_debug(" - Run: %s\n", cmd);
	ret = system(cmd);
	if (!WIFEXITED(ret)) {
		pr_debug(
			"ERR(%d): Cannot exec ip cmd\n Cmdline:%s\n",
			WEXITSTATUS(ret), cmd);
		exit(EXIT_FAILURE);
	}

	return ret;
}

static int delete_ue_ns(const char* name) {
	char cmd[CMD_MAX];
	int ret = 0;

	// Step 1: Create dummy interface */
	memset(&cmd, 0, CMD_MAX);
	snprintf(cmd, CMD_MAX,
		 "ip netns delete %s 2> /dev/null",
		 name);
	pr_debug(" - Run: %s\n", cmd);
	ret = system(cmd);
	if (!WIFEXITED(ret)) {
		pr_debug(
			"ERR(%d): Cannot exec ip cmd\n Cmdline:%s\n",
			WEXITSTATUS(ret), cmd);
		exit(EXIT_FAILURE);
	}

	return ret;
}

static int delete_ns_bridge(const char* name) {
	char cmd[CMD_MAX];
	int ret = 0;

	// Step 1: Create dummy interface */
	memset(&cmd, 0, CMD_MAX);
	snprintf(cmd, CMD_MAX,
		 "ip link del %s 2> /dev/null",
		 name);
	pr_debug(" - Run: %s\n", cmd);
	ret = system(cmd);
	if (!WIFEXITED(ret)) {
		pr_debug(
			"ERR(%d): Cannot exec ip cmd\n Cmdline:%s\n",
			WEXITSTATUS(ret), cmd);
		exit(EXIT_FAILURE);
	}

	return ret;
}

static int tc_dettach_program(struct tc_gtpu_bpf *skel, const char* prog_name, int ifindex, int attach_point) {
	int err = 0;
	struct bpf_program *bpf_prog;

	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = ifindex,
                        .attach_point = attach_point);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1);

	bpf_prog = bpf_object__find_program_by_name(skel->obj, prog_name);
	tc_opts.prog_fd = bpf_program__fd(bpf_prog);

	err = bpf_tc_detach(&tc_hook, &tc_opts);
	if (err)
		goto out;

out:
	bpf_tc_hook_destroy(&tc_hook);
	return err;
}

static int tc_attach_program(struct tc_gtpu_bpf *skel, const char* prog_name, int ifindex, int attach_point) {
	int err = 0;
	struct bpf_program *bpf_prog;

	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = ifindex,
                        .attach_point = attach_point);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1);

	bpf_prog = bpf_object__find_program_by_name(skel->obj, prog_name);
	tc_opts.prog_fd = bpf_program__fd(bpf_prog);

    err = bpf_tc_hook_create(&tc_hook);
    if (err && err != -EEXIST) {
        pr_warn("Failed to create TC hook (type: %d) ifindex: %d", attach_point, ifindex);
		goto cleanup;
	}

    err = bpf_tc_attach(&tc_hook, &tc_opts);
    if (err) {
        pr_warn("Failed to attach TC (type: %d) program: %s, on ifindex: %d", attach_point, prog_name, ifindex);
		goto cleanup;
	}

	return err;

cleanup:
	bpf_tc_hook_destroy(&tc_hook);
	return err;
}

static int attach_hooks(int ifindex, struct tc_gtpu_bpf *skel) {
	int err = 0;

	fprintf(stderr, "Creating for index %d\n", ifindex);
	err = tc_attach_program(skel, "tnl_if_ingress_fn", ifindex, BPF_TC_INGRESS);
	if (err) {
		goto out;
	}

	err = tc_attach_program(skel, "tnl_if_egress_fn", ifindex, BPF_TC_EGRESS);
	if (err) {
		goto out;
	}

out:
	return err;
}

static int create_ue_interface(char *br_postfix, char *bridge_address, char *ifname, char *ue_address, int ul_teid, int dl_teid, struct config *cfg,
                                 struct tc_gtpu_bpf *skel) {
    int err = 0;

    // create_dummy_interface(ifname, ue_address);
	create_ue_ns(br_postfix, bridge_address, ifname, ue_address);
	int ifindex = if_nametoindex(ifname);
	if (ifindex == 0) {
		pr_warn("Interface %s does not exist\n", ifname);
		goto out;
	}

    err = attach_hooks(ifindex, skel);
	if (err)
		goto out;

    struct ingress_state istate = {
        .ifindex = ifindex,
        .qfi = cfg->qfi,
    };
	err = set_if_mac(ifname, istate.if_mac);
	if (err) {
		pr_warn("Failed to set if mac address");
	}
	
	err = bpf_map_update_elem(bpf_map__fd(skel->maps.ingress_map), &dl_teid, &istate, 0);
	if (err) {
		pr_warn("ERROR: bpf_map_update_elem");
		goto out;
	}

    struct egress_state estate = {
        .teid = ul_teid,
        .qfi = cfg->qfi,
    };
	err = bpf_map_update_elem(bpf_map__fd(skel->maps.egress_map), &ifindex, &estate, 0);
	if (err) {
		pr_warn("ERROR: bpf_map_update_elem");
		goto out;
	}

out:
	return err;
}

static inline int
sys_perf_event_open(struct perf_event_attr *attr,
                  pid_t pid, int cpu, int group_fd,
                   unsigned long flags)
{
       return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static void print_bpf_output(void *ctx, int cpu, void *data, __u32 size)
{
	struct {
		__u16 cookie;
		__u16 pkt_len;
		__u8  pkt_data[SAMPLE_SIZE];
	} __attribute__((packed)) *e = data;
	struct pcap_pkthdr h = {
		.caplen	= e->pkt_len,
		.len	= e->pkt_len,
	};
	struct timespec ts;
	int err;

	if (e->cookie != 0xdead)
		printf("BUG cookie %x sized %d\n",
		       e->cookie, size);

	err = clock_gettime(CLOCK_MONOTONIC, &ts);
	if (err < 0)
		printf("Error with clock_gettime! (%i)\n", err);

	h.ts.tv_sec  = ts.tv_sec;
	h.ts.tv_usec = ts.tv_nsec / NANOSECS_PER_USEC;

	pcap_dump((u_char *) pdumper, &h, e->pkt_data);
	pcap_pkts++;
}

static void clean_perf_pcap () {
	perf_buffer__free(pb);
	pcap_dump_close(pdumper);
	pcap_close(pd);
	printf("\n%u packet samples stored in %s\n", pcap_pkts, pcap_filename);
}

static int set_perf_pcap(struct tc_gtpu_bpf *skel) {
	int pcap_map_fd = bpf_map__fd(skel->maps.pcap_map);
	pb = perf_buffer__new(pcap_map_fd, 8, print_bpf_output, NULL, NULL, NULL);
	int err = libbpf_get_error(pb);
	if (err) {
		fprintf(stderr, "perf_buffer setup failed");
		goto cleanup;
	}

	pd = pcap_open_dead(DLT_EN10MB, 65535);
	if (!pd) {
		perf_buffer__free(pb);
		goto cleanup;
	}

	pdumper = pcap_dump_open(pd, pcap_filename);
	if (!pdumper) {
		perf_buffer__free(pb);
		pcap_close(pd);
		goto cleanup;
	}

	printf("Capturing packets into %s\n", pcap_filename);
	return 0;

cleanup:
	printf("Failed to set up perf pcap");
	clean_perf_pcap();
	return -1;
}

static void sig_handler(int signo)
{
	if (verbose_level == LOG_VERBOSE)
		clean_perf_pcap();
	exiting = 1;
}

static void tc_gtpu(struct config *cfg) {
    struct tc_gtpu_bpf *skel;
    int err;

    libbpf_set_print(libbpf_print_fn);

    skel = tc_gtpu_bpf__open();
    if (!skel) {
        pr_warn("Failed to open BPF skeleton");
		return;
	}
	int gtpu_ifindex = if_nametoindex(cfg->gtpu_ifname);
	skel->rodata->config.gtpu_ifindex = gtpu_ifindex;
    skel->rodata->config.daddr.af = cfg->dest_ip.af;
    memcpy(&skel->rodata->config.daddr.addr, & cfg->dest_ip.addr, sizeof(struct ip_addr));
    skel->rodata->config.saddr.af = cfg->src_ip.af;
    memcpy(&skel->rodata->config.saddr.addr, &cfg->src_ip.addr, sizeof(struct ip_addr));
	skel->rodata->config.verbose_level = verbose_level;

	err = tc_gtpu_bpf__load(skel);
	if (err) {
		pr_warn("Failed to load TC hook");
		tc_gtpu_bpf__destroy(skel);
		return;
	}

	err = tc_attach_program(skel, "gtpu_ingress_fn", gtpu_ifindex, BPF_TC_INGRESS);
	if (err) {
		goto cleanup;
	}

	err = tc_attach_program(skel, "gtpu_egress_fn", gtpu_ifindex, BPF_TC_EGRESS);
	if (err) {
		goto cleanup;
	}

	char ifname[IF_NAMESIZE];
	// Create bridge to add the interfaces to
	char bridge_address[INET6_ADDRSTRLEN];
	if (cfg->bridge_address.af == AF_INET) {
		inet_ntop(AF_INET, &cfg->bridge_address.addr.addr4, bridge_address, INET_ADDRSTRLEN);
	} else if (cfg->bridge_address.af == AF_INET6) {
		memcpy(bridge_address, &cfg->bridge_address.addr.addr6, sizeof(struct in6_addr));
	}
	snprintf(ifname, sizeof(ifname), "br-%s", cfg->tnl_ifname);
	create_ns_bridge(ifname, bridge_address);
    // Create dummy interface for each UE
    __u32 num_ues = cfg->num_ues;
    char ue_address[INET6_ADDRSTRLEN];
    int ul_teid, dl_teid;
    for (int i = 0; i < num_ues; ++i) {
        ul_teid = cfg->ul_teid + i;
		dl_teid = cfg->dl_teid + i;
        snprintf(ifname, sizeof(ifname), "%s%d", cfg->tnl_ifname, i);

        // Increment the last byte of IP address
        if (cfg->ue_ip.af == AF_INET) {
            struct in_addr addr = cfg->ue_ip.addr.addr4;
            addr.s_addr = htonl(ntohl(addr.s_addr) + i);
            inet_ntop(AF_INET, &addr, ue_address, INET_ADDRSTRLEN);
        } else if (cfg->ue_ip.af == AF_INET6) {
            memcpy(ue_address, &cfg->ue_ip.addr.addr6, sizeof(struct in6_addr));
            __u8* last_byte = (__u8*) &ue_address[15];
            *last_byte += (__u8)i;
        }

        create_ue_interface(cfg->tnl_ifname, bridge_address, ifname, ue_address, ul_teid, dl_teid, cfg, skel);
    }

	if (verbose_level == LOG_VERBOSE)
		set_perf_pcap(skel);
	if (signal(SIGINT, sig_handler) ||
	    signal(SIGHUP, sig_handler) ||
	    signal(SIGTERM, sig_handler)) {
		fprintf(stderr, "Can't set signal handler");
		goto cleanup;
	}

    printf("Successfully started! To test: \n" 
		"\t 1. RUN: `cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF program.\n"
		"\t 2. RUN: `ping -I %s0 8.8.8.8 -c 5` to send packet via the gtpu tunnel\n", cfg->tnl_ifname);

	while (true) {
		if (verbose_level == LOG_VERBOSE && ((err = perf_buffer__poll(pb, 1000)) < 0 && exiting))
			break;
		else if (exiting)
			break;
	}

	for (int i = 0; i < num_ues; ++i) {
        char ifname[IF_NAMESIZE];
        snprintf(ifname, sizeof(ifname), "%s%d", cfg->tnl_ifname, i);
        // delete_dummy_interface(ifname);
		delete_ue_ns(ifname);
    }

	snprintf(ifname, sizeof(ifname), "br-%s", cfg->tnl_ifname);
	delete_ns_bridge(ifname);

cleanup:
	tc_dettach_program(skel, "gtpu_ingress_fn", gtpu_ifindex, BPF_TC_INGRESS);
	tc_dettach_program(skel, "gtpu_egress_fn", gtpu_ifindex, BPF_TC_EGRESS);
    tc_gtpu_bpf__destroy(skel);
}

static char gtpu_ifname[IF_NAMESIZE];
static char tnl_ifname[IF_NAMESIZE];

int main(int argc, char **argv)
{
	
	// Parse the command line arguments
	struct config cfg = {0};
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	pr_info("gtpu_ifname: %s\n", cfg.gtpu_ifname);
    pr_info("tnl_ifname: %s\n", cfg.tnl_ifname);

    if (cfg.src_ip.af == AF_INET) {
        char addr_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cfg.src_ip.addr.addr4, addr_str, INET_ADDRSTRLEN);
        pr_info("src_ip: %s (IPv4)\n", addr_str);
    }
    else if (cfg.src_ip.af == AF_INET6) {
        char addr_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &cfg.src_ip.addr.addr6, addr_str, INET6_ADDRSTRLEN);
        pr_info("src_ip: %s (IPv6)\n", addr_str);
    }
    if (cfg.dest_ip.af == AF_INET) {
        char addr_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cfg.dest_ip.addr.addr4, addr_str, INET_ADDRSTRLEN);
        pr_info("dest_ip: %s (IPv4)\n", addr_str);
    }
    else if (cfg.dest_ip.af == AF_INET6) {
        char addr_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &cfg.dest_ip.addr.addr6, addr_str, INET6_ADDRSTRLEN);
        printf("dest_ip: %s (IPv6)\n", addr_str);
    }
	if (cfg.ue_ip.af == AF_INET) {
        char addr_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cfg.ue_ip.addr.addr4, addr_str, INET_ADDRSTRLEN);
        printf("ue_ip: %s (IPv4)\n", addr_str);
    }
    else if (cfg.ue_ip.af == AF_INET6) {
        char addr_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &cfg.ue_ip.addr.addr6, addr_str, INET6_ADDRSTRLEN);
        pr_info("ue_ip: %s (IPv6)\n", addr_str);
    }
	if (cfg.bridge_address.af == AF_INET) {
        char addr_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cfg.bridge_address.addr.addr4, addr_str, INET_ADDRSTRLEN);
        printf("bridge_address: %s (IPv4)\n", addr_str);
    }
    else if (cfg.bridge_address.af == AF_INET6) {
        char addr_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &cfg.bridge_address.addr.addr6, addr_str, INET6_ADDRSTRLEN);
        pr_info("bridge_address: %s (IPv6)\n", addr_str);
    }

    pr_info("teid: %u\n", cfg.ul_teid);
    pr_info("qfi: %u\n", cfg.qfi);
    pr_info("num_ues: %u\n", cfg.num_ues);
	

	memset(gtpu_ifname, 0, IF_NAMESIZE); /* Can be used uninitialized */
	memset(tnl_ifname, 0, IF_NAMESIZE); /* Can be used uninitialized */

	// Setup gtpu interface
	snprintf(gtpu_ifname, sizeof(gtpu_ifname), "%s", cfg.gtpu_ifname);

	tc_gtpu(&cfg);
	return 0;
}