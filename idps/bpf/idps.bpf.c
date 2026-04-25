// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// IDPS - Intrusion Detection and Prevention System
// eBPF Data Plane

#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include "idps.h"

/* Forward declarations for static inline functions */
static __always_inline int process_tcp(struct xdp_md *ctx,
                                      struct iphdr *ip,
                                      __u32 src_ip, __u32 dst_ip);
static __always_inline int process_udp(struct xdp_md *ctx,
                                      struct iphdr *ip,
                                      __u32 src_ip, __u32 dst_ip);
static __always_inline int process_icmp(struct iphdr *ip,
                                      __u32 src_ip, __u32 dst_ip);

/*
 * XDP Program - Main entry point for packet processing
 * Attaches to network interface and processes packets at wire speed
 */
SEC("xdp")
int idps_xdp(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    update_stats(0, 1);  // total packets

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        update_stats(9, 1);  // invalid
        return XDP_PASS;
    }

    // Only handle IPv4 for now
    // h_proto is in network byte order (big-endian)
    // On little-endian ARM64, reading 2 bytes gives 0x0008 (not 0x0800)
    // so we need to byte-swap to get host byte order
    unsigned int ether_type = *(unsigned short *)((char *)data + 12);
    ether_type = ((ether_type & 0x00FF) << 8) | ((ether_type & 0xFF00) >> 8);
    if (ether_type != 0x0800) {
        return XDP_PASS;
    }

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        update_stats(9, 1);
        return XDP_PASS;
    }

    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    __u8 protocol = ip->protocol;

    update_stats(1, 1);  // IPv4 packets
    update_stats(10, ip->ihl * 4 + ip->tot_len);  // bytes

    // 1. Whitelist check
    if (is_whitelisted(src_ip)) {
        update_stats(8, 1);  // whitelisted
        return XDP_PASS;
    }

    // 2. Rate limit check (DDoS protection)
    if (check_rate_limit(src_ip, 10000, 20000) < 0) {
        // Syn flood or DDoS
        send_alert(src_ip, dst_ip, 0, 0, protocol,
                   SEVERITY_CRITICAL, 1001);
        update_stats(2, 1);  // rate limited
        return XDP_DROP;
    }

    // 3. Protocol-specific processing
    if (protocol == PROTO_TCP) {
        return process_tcp(ctx, ip, src_ip, dst_ip);
    } else if (protocol == PROTO_UDP) {
        return process_udp(ctx, ip, src_ip, dst_ip);
    } else if (protocol == PROTO_ICMP) {
        return process_icmp(ip, src_ip, dst_ip);
    }

    return XDP_PASS;
}

/*
 * TCP processing
 */
static __always_inline int process_tcp(struct xdp_md *ctx,
                                      struct iphdr *ip,
                                      __u32 src_ip, __u32 dst_ip)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct tcphdr *tcp = (void *)((char *)ip + ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end) {
        return XDP_PASS;
    }

    __u16 src_port = tcp->source;
    __u16 dst_port = tcp->dest;

    update_stats(3, 1);  // TCP packets

    // Track connection
    struct ip_state *state = bpf_map_lookup_elem(&ip_tracker, &src_ip);
    if (!state) {
        struct ip_state new_state = {};
        new_state.last_seen = bpf_ktime_get_ns();
        bpf_map_update_elem(&ip_tracker, &src_ip, &new_state, BPF_ANY);
        state = &new_state;
    }
    state->last_seen = bpf_ktime_get_ns();

    // SYN Flood detection
    if (tcp->syn && !tcp->ack) {
        state->syn_count++;

        if (state->syn_count > 1000) {
            send_alert(src_ip, dst_ip, src_port, dst_port,
                       PROTO_TCP, SEVERITY_HIGH, 1001);
            update_stats(4, 1);  // syn flood
            return XDP_DROP;
        }
    }

    // Connection count tracking
    if (tcp->syn && tcp->ack) {
        state->conn_count++;

        if (state->conn_count > 5000) {
            send_alert(src_ip, dst_ip, src_port, dst_port,
                       PROTO_TCP, SEVERITY_MEDIUM, 1002);
            update_stats(5, 1);  // connection flood
        }
    }

    // Check for malicious ports
    if (dst_port == 22 || dst_port == 23 || dst_port == 3389) {
        // SSH/Telnet/RDP - potential brute force
        if (tcp->syn && !tcp->ack) {
            // Track connection attempts
            __u32 key = src_ip ^ (dst_port << 16);
            __u32 *count = bpf_map_lookup_elem(&ip_tracker, &key);
            if (!count) {
                __u32 init = 1;
                bpf_map_update_elem(&ip_tracker, &key, &init, BPF_ANY);
            } else {
                (*count)++;
                if (*count > 10) {
                    send_alert(src_ip, dst_ip, src_port, dst_port,
                               PROTO_TCP, SEVERITY_HIGH, 2001);
                    update_stats(6, 1);  // brute force
                }
            }
        }
    }

    return XDP_PASS;
}

/*
 * UDP processing
 */
static __always_inline int process_udp(struct xdp_md *ctx,
                                      struct iphdr *ip,
                                      __u32 src_ip, __u32 dst_ip)
{
    void *data_end = (void *)(long)ctx->data_end;

    struct udphdr *udp = (void *)((char *)ip + ip->ihl * 4);
    if ((void *)(udp + 1) > data_end) {
        return XDP_PASS;
    }

    __u16 dst_port = udp->dest;

    update_stats(7, 1);  // UDP packets

    // DNS Tunneling detection (simplified)
    if (dst_port == 53) {
        // In real implementation, parse DNS query
        // Look for unusually long queries or high frequency
    }

    return XDP_PASS;
}

/*
 * ICMP processing
 */
static __always_inline int process_icmp(struct iphdr *ip,
                                      __u32 src_ip, __u32 dst_ip)
{
    update_stats(11, 1);  // ICMP packets

    // Track ICMP source
    struct ip_state *state = bpf_map_lookup_elem(&ip_tracker, &src_ip);
    if (!state) {
        struct ip_state new_state = {};
        new_state.last_seen = bpf_ktime_get_ns();
        new_state.icmp_count = 1;
        bpf_map_update_elem(&ip_tracker, &src_ip, &new_state, BPF_ANY);
        return XDP_PASS;
    }

    state->last_seen = bpf_ktime_get_ns();
    state->icmp_count++;

    // ICMP Flood detection - more than 100 ICMP in 1 second
    if (state->icmp_count > 100) {
        send_alert(src_ip, dst_ip, 0, 0, PROTO_ICMP,
                   SEVERITY_MEDIUM, 3001);
        update_stats(12, 1);  // ICMP flood
    }

    return XDP_PASS;
}

/*
 * License - required by eBPF
 */
char LICENSE[] SEC("license") = "GPL";
