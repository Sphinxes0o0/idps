// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// IDPS - User Space Loader
// Loads eBPF programs and manages IDPS configuration

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>

/* IDPS map names and constants - shared with BPF program */
#define MAX_RULES 1024
#define MAX_TRACKED_IPS 65536
#define MAX_ALERTS 4096

struct idps_context {
    int xdp_fd;
    int ifindex;
    char *ifname;
    struct bpf_object *obj;
};

/* Load eBPF program from object file */
static int load_bpf_object(struct idps_context *ctx, const char *filename)
{
    struct bpf_program *prog;
    int err;

    // Open BPF object
    ctx->obj = bpf_object__open(filename);
    if (!ctx->obj) {
        fprintf(stderr, "ERROR: Failed to open BPF object: %s\n",
                strerror(errno));
        return -1;
    }

    // Load BPF programs into kernel
    err = bpf_object__load(ctx->obj);
    if (err) {
        fprintf(stderr, "ERROR: Failed to load BPF object: %s\n",
                strerror(errno));
        return -1;
    }

    // Find XDP program
    prog = bpf_object__find_program_by_name(ctx->obj, "idps_xdp");
    if (!prog) {
        fprintf(stderr, "ERROR: Failed to find XDP program\n");
        return -1;
    }

    ctx->xdp_fd = bpf_program__fd(prog);
    printf("Loaded XDP program (fd=%d)\n", ctx->xdp_fd);

    return 0;
}

/* Attach XDP program to interface */
static int attach_xdp(struct idps_context *ctx)
{
    int err;

    // Get interface index
    ctx->ifindex = if_nametoindex(ctx->ifname);
    if (ctx->ifindex == 0) {
        fprintf(stderr, "ERROR: Failed to get interface index for %s\n",
                ctx->ifname);
        return -1;
    }

    // Attach XDP program
    err = bpf_xdp_attach(ctx->ifindex, ctx->xdp_fd,
                          XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
    if (err) {
        fprintf(stderr, "ERROR: Failed to attach XDP: %s\n",
                strerror(errno));
        return -1;
    }

    printf("Attached XDP program to %s (ifindex=%d)\n",
           ctx->ifname, ctx->ifindex);

    return 0;
}

/* Detach XDP program */
static int detach_xdp(struct idps_context *ctx)
{
    int err;

    err = bpf_xdp_detach(ctx->ifindex, XDP_FLAGS_SKB_MODE, NULL);
    if (err) {
        fprintf(stderr, "ERROR: Failed to detach XDP: %s\n",
                strerror(errno));
        return err;
    }

    printf("Detached XDP program from %s\n", ctx->ifname);
    return 0;
}

/* Add IP to whitelist */
static int add_to_whitelist(struct idps_context *ctx, const char *ip_str)
{
    struct bpf_map *map;
    __u32 ip;
    __u32 value = 0;
    int map_fd;
    int err;
    int a, b, c, d;

    // Parse IP address
    if (sscanf(ip_str, "%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
        fprintf(stderr, "ERROR: Invalid IP address: %s\n", ip_str);
        return -1;
    }
    ip = (__u32)((a & 0xFF) | ((b & 0xFF) << 8) | ((c & 0xFF) << 16) | ((d & 0xFF) << 24));

    // Find whitelist map
    map = bpf_object__find_map_by_name(ctx->obj, "whitelist");
    if (!map) {
        fprintf(stderr, "ERROR: Failed to find whitelist map\n");
        return -1;
    }

    map_fd = bpf_map__fd(map);
    err = bpf_map_update_elem(map_fd, &ip, &value, BPF_ANY);
    if (err) {
        fprintf(stderr, "ERROR: Failed to add to whitelist: %s\n",
                strerror(errno));
        return err;
    }

    printf("Added %s to whitelist\n", ip_str);
    return 0;
}

/* Print statistics */
static void print_stats(struct idps_context *ctx)
{
    struct bpf_map *map;
    int map_fd;
    __u32 key;
    __u64 value;

    map = bpf_object__find_map_by_name(ctx->obj, "idps_stats");
    if (!map) {
        fprintf(stderr, "ERROR: Failed to find stats map\n");
        return;
    }

    map_fd = bpf_map__fd(map);

    printf("\n=== IDPS Statistics ===\n");
    printf("%-20s: %llu\n", "Total Packets",
           bpf_map_lookup_elem(map_fd, &(__u32){0}, &value) ? 0 : value);

    key = 1;
    bpf_map_lookup_elem(map_fd, &key, &value);
    printf("%-20s: %llu\n", "IPv4 Packets", value);

    key = 2;
    bpf_map_lookup_elem(map_fd, &key, &value);
    printf("%-20s: %llu\n", "Rate Limited", value);

    key = 3;
    bpf_map_lookup_elem(map_fd, &key, &value);
    printf("%-20s: %llu\n", "TCP Packets", value);

    key = 7;
    bpf_map_lookup_elem(map_fd, &key, &value);
    printf("%-20s: %llu\n", "UDP Packets", value);
}

/* Print usage */
static void print_usage(const char *prog)
{
    printf("Usage: %s [OPTIONS]\n", prog);
    printf("\nOptions:\n");
    printf("  -i <interface>   Interface to attach (required)\n");
    printf("  -f <bpf_file>    BPF object file (default: bpf/idps.bpf.o)\n");
    printf("  -w <ip>         Add IP to whitelist\n");
    printf("  -s              Show statistics\n");
    printf("  -d              Detach XDP program\n");
    printf("  -h              Show this help\n");
    printf("\nExamples:\n");
    printf("  %s -i eth0 -f bpf/idps.bpf.o\n", prog);
    printf("  %s -i eth0 -w 192.168.1.100\n", prog);
    printf("  %s -i eth0 -s\n", prog);
}

int main(int argc, char **argv)
{
    struct idps_context ctx = {0};
    const char *bpf_file = "bpf/idps.bpf.o";
    const char *ifname = NULL;
    int opt;
    int err;

    // Parse command line options
    while ((opt = getopt(argc, argv, "i:f:w:sdh")) != -1) {
        switch (opt) {
        case 'i':
            ifname = optarg;
            break;
        case 'f':
            bpf_file = optarg;
            break;
        case 'w':
            if (!ctx.obj) {
                fprintf(stderr, "ERROR: Load BPF first (-i option)\n");
                return 1;
            }
            add_to_whitelist(&ctx, optarg);
            break;
        case 's':
            if (!ctx.obj) {
                fprintf(stderr, "ERROR: Load BPF first (-i option)\n");
                return 1;
            }
            print_stats(&ctx);
            break;
        case 'd':
            if (!ctx.obj) {
                fprintf(stderr, "ERROR: Load BPF first (-i option)\n");
                return 1;
            }
            detach_xdp(&ctx);
            return 0;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!ifname) {
        fprintf(stderr, "ERROR: Interface (-i) is required\n");
        print_usage(argv[0]);
        return 1;
    }

    ctx.ifname = (char *)ifname;

    // Set rlimit for BPF operations
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    setrlimit(RLIMIT_MEMLOCK, &rlim);

    // Load BPF object
    printf("Loading BPF object from %s...\n", bpf_file);
    err = load_bpf_object(&ctx, bpf_file);
    if (err) {
        return 1;
    }

    // Attach to interface
    err = attach_xdp(&ctx);
    if (err) {
        return 1;
    }

    printf("\nIDPS is running. Press Ctrl+C to stop.\n");

    // Main loop
    while (1) {
        sleep(10);
        print_stats(&ctx);
    }

    // Cleanup
    detach_xdp(&ctx);
    bpf_object__close(ctx.obj);

    return 0;
}
