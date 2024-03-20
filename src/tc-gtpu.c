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

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "tc-gtpu.h"
#include "tc-gtpu.skel.h"

#define LO_IFINDEX 1

#define CMD_MAX     2048
#define CMD_MAX_TC  256

static int verbose = 1;

struct config {
	/* Define config */
	char *gtpu_ifname;
	char *tnl_ifname;
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
                    printf("Invalid gtpu_ifname name\n");
                    usage(argv);
                    exit(EXIT_FAILURE);
                }
                cfg->gtpu_ifname = optarg;
                gtpu_ifindex = if_nametoindex(cfg->gtpu_ifname);
                if (gtpu_ifindex == 0) {
                    printf("Interface %s does not exist\n", cfg->gtpu_ifname);
                    usage(argv);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'i':
                if (!validate_ifname(optarg)) {
                    printf("Invalid tnl_ifname name\n");
                    usage(argv);
                    exit(EXIT_FAILURE);
                }
                cfg->tnl_ifname = optarg;
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
	if (cfg->gtpu_ifname == NULL ||
		cfg->tnl_ifname == NULL ||
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

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

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

static int delete_dummy_interface(const char* ifname) {
	char cmd[CMD_MAX];
	int ret = 0;

	// Step 1: Create dummy interface */
	memset(&cmd, 0, CMD_MAX);
	snprintf(cmd, CMD_MAX,
		 "ip link delete %s 2> /dev/null",
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
        printf("Failed to create TC hook (type: %d) ifindex: %d", attach_point, ifindex);
		goto cleanup;
	}

    err = bpf_tc_attach(&tc_hook, &tc_opts);
    if (err) {
        printf("Failed to attach TC (type: %d) program: %s, on ifindex: %d", attach_point, prog_name, ifindex);
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

static int create_ue_interface(char *ifname, char *ue_address, int teid, struct config *cfg,
                                 struct tc_gtpu_bpf *skel) {
    int err = 0;

    create_dummy_interface(ifname, ue_address);
	int ifindex = if_nametoindex(ifname);
	if (ifindex == 0) {
		printf("Interface %s does not exist\n", ifname);
		goto out;
	}

    err = attach_hooks(ifindex, skel);
	if (err)
		goto out;

    struct ingress_state istate = {
        .ifindex = ifindex,
        .qfi = cfg->qfi,
    };
	err = bpf_map_update_elem(bpf_map__fd(skel->maps.ingress_map), &teid, &istate, 0);
	if (err) {
		perror("ERROR: bpf_map_update_elem");
		goto out;
	}

    struct egress_state estate = {
        .teid = teid,
        .qfi = cfg->qfi,
    };
	err = bpf_map_update_elem(bpf_map__fd(skel->maps.egress_map), &ifindex, &estate, 0);
	if (err) {
		perror("ERROR: bpf_map_update_elem");
		goto out;
	}

out:
	return err;
}

static void tc_gtpu(struct config *cfg) {
    struct tc_gtpu_bpf *skel;
    int err;

    libbpf_set_print(libbpf_print_fn);

    skel = tc_gtpu_bpf__open();
    if (!skel) {
        perror("Failed to open BPF skeleton");
		return;
	}
	int gtpu_ifindex = if_nametoindex(cfg->gtpu_ifname);
	skel->rodata->config.gtpu_ifindex = gtpu_ifindex;
    skel->rodata->config.daddr.af = cfg->dest_ip.af;
    memcpy(&skel->rodata->config.daddr.addr, & cfg->dest_ip.addr, sizeof(struct ip_addr));
    skel->rodata->config.saddr.af = cfg->src_ip.af;
    memcpy(&skel->rodata->config.saddr.addr, &cfg->src_ip.addr, sizeof(struct ip_addr));

	err = tc_gtpu_bpf__load(skel);
	if (err) {
		perror("Failed to load TC hook");
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

    // Create dummy interface for each UE
    __u32 num_ues = cfg->num_ues;
    char ue_address[INET6_ADDRSTRLEN];
    int teid;
    for (int i = 0; i < num_ues; ++i) {
        teid = cfg->teid + i;
        char ifname[IF_NAMESIZE];
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

        create_ue_interface(ifname, ue_address, teid, cfg, skel);
    }

    if (signal(SIGINT, sig_int) == SIG_ERR)
        perror("Can't set signal handler");

    printf("Successfully started! To test: \n" 
		"\t 1. RUN: `cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF program.\n"
		"\t 2. RUN: `ping -I %s0 8.8.8.8 -c 5` to send packet via the gtpu tunnel\n", cfg->tnl_ifname);

    while (!exiting) {
        fprintf(stderr, ".");
        sleep(1);
    }

	for (int i = 0; i < num_ues; ++i) {
        char ifname[IF_NAMESIZE];
        snprintf(ifname, sizeof(ifname), "%s%d", cfg->tnl_ifname, i);
        delete_dummy_interface(ifname);
    }

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

	printf("gtpu_ifname: %s\n", cfg.gtpu_ifname);
    printf("tnl_ifname: %s\n", cfg.tnl_ifname);

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
	snprintf(gtpu_ifname, sizeof(gtpu_ifname), "%s", cfg.gtpu_ifname);

	tc_gtpu(&cfg);
	return 0;
}