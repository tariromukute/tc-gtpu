
/**
 * This is a BPF user program.
 * The program receive arguments for creating tunnel interfaces. It gets the source and dest
 * IP addresses, the first UE Ip address, the start teid, the qfi, the number of UEs to create.
 * The program will then put these into bpf maps.
*/

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

#include <bpf/bpf.h>

#include "config.h"

static int verbose = 1;
static const char *ingress_mapfile = "/sys/fs/bpf/tc/globals/ingress_map";
static const char *egress_mapfile = "/sys/fs/bpf/tc/globals/egress_map";

#define CMD_MAX     2048
#define CMD_MAX_TC  256
static char tc_cmd[CMD_MAX_TC] = "tc";

struct config {
	/* Define config */
	char *gtpu_interface;
	char *tnl_interface;
	struct ip_addr src_ip;
	struct ip_addr dest_ip;
	struct ip_addr ue_ip;
	__u32 teid;
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
	{"teid",    required_argument,    NULL, 't' },
	{"qfi", required_argument,    NULL, 'q' },
	{"num-ues", required_argument,    NULL, 'n' },
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

	while ((opt = getopt_long(argc, argv, "hg:i:s:d:u:t:q:n:", options, NULL)) != -1) {
		switch(opt) {
			case 'h':
				usage(argv);
				exit(EXIT_SUCCESS);
				break;
			case 'g':
                if (!validate_ifname(optarg)) {
                    printf("Invalid gtpu_interface name\n");
                    usage(argv);
                    exit(EXIT_FAILURE);
                }
                cfg->gtpu_interface = optarg;
                gtpu_ifindex = if_nametoindex(cfg->gtpu_interface);
                if (gtpu_ifindex == 0) {
                    printf("Interface %s does not exist\n", cfg->gtpu_interface);
                    usage(argv);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'i':
                if (!validate_ifname(optarg)) {
                    printf("Invalid tnl_interface name\n");
                    usage(argv);
                    exit(EXIT_FAILURE);
                }
                cfg->tnl_interface = optarg;
                break;
			case 's':
                if (validate_ip_address(optarg, &cfg->src_ip) != 0) {
					printf("Invalid source IP address\n");
					usage(argv);
					exit(EXIT_FAILURE);
				}
                break;
            case 'd':
                if (validate_ip_address(optarg, &cfg->dest_ip) != 0) {
					printf("Invalid destination IP address\n");
					usage(argv);
					exit(EXIT_FAILURE);
				}
                break;
			case 'u':
                if (inet_pton(AF_INET, optarg, &(cfg->ue_ip.addr.addr4)) <= 0) {
                    fprintf(stderr, "Invalid UE IP address '%s'\n", optarg);
                    exit(EXIT_FAILURE);
                }
                cfg->ue_ip.af = AF_INET;
				break;
			case 't':
                cfg->teid = (__u32) strtoul(optarg, NULL, 0);
                break;
            case 'q':
                cfg->qfi = (__u32) strtoul(optarg, NULL, 0);
                break;
            case 'n':
                cfg->num_ues = (__u32) strtoul(optarg, NULL, 0);
                break;
			default:
				usage(argv);
				exit(EXIT_FAILURE);
				break;
		}
	}

	// Check if all required arguments were provided
	if (cfg->gtpu_interface == NULL ||
		cfg->tnl_interface == NULL ||
		cfg->src_ip.af == AF_UNSPEC ||
		cfg->dest_ip.af == AF_UNSPEC ||
		cfg->ue_ip.af == AF_UNSPEC ||
		cfg->teid == 0 ||
		cfg->qfi == 0 ||
		cfg->num_ues == 0)
	{
		usage(argv);
		exit(EXIT_FAILURE);
	}
}


static int tc_remove_clsact(const char* dev)
{
	char cmd[CMD_MAX];
	int ret = 0;

	/* Step-1: Delete clsact, which also remove filters */
	memset(&cmd, 0, CMD_MAX);
	snprintf(cmd, CMD_MAX,
		 "%s qdisc del dev %s clsact 2> /dev/null",
		 tc_cmd, dev);
	if (verbose) printf(" - Run: %s\n", cmd);
	ret = system(cmd);
	if (!WIFEXITED(ret)) {
		fprintf(stderr,
			"ERR(%d): Cannot exec tc cmd\n Cmdline:%s\n",
			WEXITSTATUS(ret), cmd);
		exit(EXIT_FAILURE);
	} else if (WEXITSTATUS(ret) == 2) {
		/* Unfortunately TC use same return code for many errors */
		if (verbose) printf(" - (First time loading clsact?)\n");
	}

	return ret;
}

static int tc_attach_clsact(const char* dev)
{
	char cmd[CMD_MAX];
	int ret = 0;

	memset(&cmd, 0, CMD_MAX);
	snprintf(cmd, CMD_MAX,
		 "%s qdisc add dev %s clsact",
		 tc_cmd, dev);
	if (verbose) printf(" - Run: %s\n", cmd);
	ret = system(cmd);
	if (ret) {
		fprintf(stderr,
			"ERR(%d): tc cannot attach qdisc hook\n Cmdline:%s\n",
			WEXITSTATUS(ret), cmd);
		exit(EXIT_FAILURE);
	}

	return ret;
}

static int tc_remove_filter(const char* dev, const char* type)
{
	char cmd[CMD_MAX];
	int ret = 0;

	memset(&cmd, 0, CMD_MAX);
	snprintf(cmd, CMD_MAX,
		 /* Remove all ingress filters on dev */
		 "%s filter del dev %s %s",
		 /* Alternatively could remove specific filter handle:
		 "%s filter delete dev %s ingress prio 1 handle 1 bpf",
		 */
		 tc_cmd, dev, type);
	if (verbose) printf(" - Run: %s\n", cmd);
	ret = system(cmd);
	if (ret) {
		fprintf(stderr,
			"ERR(%d): tc cannot remove filters\n Cmdline:%s\n",
			ret, cmd);
		exit(EXIT_FAILURE);
	}
	return ret;

}

static int tc_attach_bpf(const char* dev, const char* type, const char* bpf_obj, const char* prog_name)
{
	char cmd[CMD_MAX];
	int ret = 0;

	/* Step-1: Delete clsact, which also remove filters */
	tc_remove_clsact(dev);

	/* Step-2: Attach a new clsact qdisc */
	tc_attach_clsact(dev);

	/* Step-3: Attach BPF program/object as ingress filter */
	memset(&cmd, 0, CMD_MAX);
	snprintf(cmd, CMD_MAX,
		 "%s filter add dev %s "
		 "%s bpf direct-action obj %s sec %s",
		 tc_cmd, dev, type, bpf_obj, prog_name);
	if (verbose) printf(" - Run: %s\n", cmd);
	ret = system(cmd);
	if (ret) {
		fprintf(stderr,
			"ERR(%d): tc cannot attach filter\n Cmdline:%s\n",
			WEXITSTATUS(ret), cmd);
		exit(EXIT_FAILURE);
	}

	return ret;
}


static char gtpu_ifname[IF_NAMESIZE];
static char tnl_ifname[IF_NAMESIZE];
static char buf_ifname[IF_NAMESIZE] = "(unknown-dev)";

static int create_dummy_interface(const char* ifname, const char* ip_address) {
	char cmd[CMD_MAX];
	int ret = 0;

	// Step 1: Create dummy interface */
	memset(&cmd, 0, CMD_MAX);
	snprintf(cmd, CMD_MAX,
		 "ip link add %s type dummy 2> /dev/null",
		 ifname);
	if (verbose) printf(" - Run: %s\n", cmd);
	ret = system(cmd);
	if (!WIFEXITED(ret)) {
		fprintf(stderr,
			"ERR(%d): Cannot exec ip cmd\n Cmdline:%s\n",
			WEXITSTATUS(ret), cmd);
		exit(EXIT_FAILURE);
	}

	// Step 2: Assign ip address */
	memset(&cmd, 0, CMD_MAX);
	snprintf(cmd, CMD_MAX,
		 "ip addr add %s/24 dev %s 2> /dev/null",
		 ip_address, ifname);
	if (verbose) printf(" - Run: %s\n", cmd);
	ret = system(cmd);
	if (!WIFEXITED(ret)) {
		fprintf(stderr,
			"ERR(%d): Cannot exec ip cmd\n Cmdline:%s\n",
			WEXITSTATUS(ret), cmd);
		exit(EXIT_FAILURE);
	}

	// Step 3: Set interface up
	memset(&cmd, 0, CMD_MAX);
	snprintf(cmd, CMD_MAX,
		 "ip link set %s up 2> /dev/null",
		 ifname);
	if (verbose) printf(" - Run: %s\n", cmd);
	ret = system(cmd);
	if (!WIFEXITED(ret)) {
		fprintf(stderr,
			"ERR(%d): Cannot exec ip cmd\n Cmdline:%s\n",
			WEXITSTATUS(ret), cmd);
		exit(EXIT_FAILURE);
	}

	return ret;
}

static int get_map_fd_by_path(const char* path)
{
	int fd = bpf_obj_get(path);
	if (fd < 0) {
		fprintf(stderr, "ERROR: cannot open bpf_obj_get(%s): %s(%d)\n",
			path, strerror(errno), errno);
		return -EXIT_FAILURE;
	}

	return fd;
}

static int init_egress_map(int fd, __u32 ifindex, struct egress_state* state)
{
	int ret = 0;
	ret = bpf_map_update_elem(fd, &ifindex, state, 0);
	if (ret) {
		perror("ERROR: bpf_map_update_elem");
		ret = -EXIT_FAILURE;
	}
	return ret;
}

static int init_ingress_map(int fd, __u32 teid, struct ingress_state* state)
{
	int ret = 0;
	ret = bpf_map_update_elem(fd, &teid, state, 0);
	if (ret) {
		perror("ERROR: bpf_map_update_elem");
		ret = -EXIT_FAILURE;
	}
	return ret;
}

int main(int argc, char **argv)
{

	int longindex = 0, opt, fd = -1;
	int gtpu_ifindex = -1;
	int tnl_ifindex = 0;
	int key = 0;
	size_t len;

	char bpf_obj[256];
	snprintf(bpf_obj, sizeof(bpf_obj), "gtpu.bpf.o");

	// Parse the command line arguments
	struct config cfg = {0};
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	printf("gtpu_interface: %s\n", cfg.gtpu_interface);
    printf("tnl_interface: %s\n", cfg.tnl_interface);

    if (cfg.src_ip.af == AF_INET) {
        char addr_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cfg.src_ip.addr.addr4, addr_str, INET_ADDRSTRLEN);
        printf("src_ip: %s (IPv4)\n", addr_str);
    }
    else if (cfg.src_ip.af == AF_INET6) {
        char addr_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &cfg.src_ip.addr.addr6, addr_str, INET6_ADDRSTRLEN);
        printf("src_ip: %s (IPv6)\n", addr_str);
    }
    if (cfg.dest_ip.af == AF_INET) {
        char addr_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cfg.dest_ip.addr.addr4, addr_str, INET_ADDRSTRLEN);
        printf("dest_ip: %s (IPv4)\n", addr_str);
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
        printf("ue_ip: %s (IPv6)\n", addr_str);
    }

    printf("teid: %u\n", cfg.teid);
    printf("qfi: %u\n", cfg.qfi);
    printf("num_ues: %u\n", cfg.num_ues);
	

	memset(gtpu_ifname, 0, IF_NAMESIZE); /* Can be used uninitialized */
	memset(tnl_ifname, 0, IF_NAMESIZE); /* Can be used uninitialized */

	// Setup gtpu interface
	snprintf(gtpu_ifname, sizeof(gtpu_ifname), "%s", cfg.gtpu_interface);
	tc_attach_bpf(gtpu_ifname, "ingress", bpf_obj, "gtpu_ingress");
	tc_attach_bpf(gtpu_ifname, "egress", bpf_obj, "gtpu_egress");

	// Get map
	int ingress_map_fd = bpf_obj_get(ingress_mapfile);
	if (ingress_map_fd < 0)
		goto err;

	int egress_map_fd = bpf_obj_get(egress_mapfile);
	if (egress_map_fd < 0)
		goto err;
	

	// create dummy interfaces for ues
    __u32 num_ues = cfg.num_ues;
    char ifname[IF_NAMESIZE];
	char ue_address[INET6_ADDRSTRLEN];
	int ifindex, teid;
    for (int i = 0; i < num_ues; ++i) {
		teid = cfg.teid + i;
        snprintf(ifname, sizeof(ifname), "%s%d", cfg.tnl_interface, i);
        ifindex = if_nametoindex(ifname);
		// Increment the ue_ip by i and call create_dummy_interface
		if (cfg.ue_ip.af == AF_INET) {
			struct in_addr addr = cfg.ue_ip.addr.addr4;
			addr.s_addr = htonl(ntohl(addr.s_addr) + i); // increment the last byte of IP address
			inet_ntop(AF_INET, &addr, ue_address, INET_ADDRSTRLEN);
		} else if (cfg.ue_ip.af == AF_INET6) {
			// Increment the last byte of IPv6 address
			memcpy(ue_address, &cfg.ue_ip.addr.addr6, sizeof(struct in6_addr));
			__u8* last_byte = (__u8*) &ue_address[15];
			*last_byte += (__u8)i;
		}

    	create_dummy_interface(ifname, ue_address);
		tc_attach_bpf(ifname, "ingress", bpf_obj, "tnl_if_ingress");
		tc_attach_bpf(ifname, "egress", bpf_obj, "tnl_if_egress");

		struct ingress_state istate = {
			.ifindex = ifindex,
			.qfi = cfg.qfi,
		};
		init_ingress_map(ingress_map_fd, teid, &istate);

		struct egress_state estate = {
			.teid = teid,
			.qfi = cfg.qfi,
		};
		init_egress_map(egress_map_fd, ifindex, &estate);
    }

out:
	return EXIT_SUCCESS;
err:
	return EXIT_FAILURE;
}