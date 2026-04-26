/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* IDPS - Intrusion Detection and Prevention System
 * Common header file
 */

#ifndef _IDPS_H
#define _IDPS_H

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>

/* Map definitions */
#define MAX_RULES 1024
#define MAX_TRACKED_IPS 65536
#define MAX_ALERTS 4096

/* Severity levels */
#define SEVERITY_LOW      1
#define SEVERITY_MEDIUM   2
#define SEVERITY_HIGH     3
#define SEVERITY_CRITICAL 4

/* Protocol numbers */
#define PROTO_TCP 6
#define PROTO_UDP 17
#define PROTO_ICMP 1

/* Action types */
#define ACTION_ALERT  0
#define ACTION_DROP   1
#define ACTION_LOG     2

/* Alert structure */
struct idps_alert {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  severity;
    __u32 rule_id;
    __u64 timestamp;
};

/* Rule structure */
struct idps_rule {
    __u32 id;
    __u8  severity;
    __u8  action;
    __u8  protocol;
    __u16 dst_port;
    __u32 src_ip;
    __u32 src_ip_mask;
    __u32 dst_ip;
    __u32 dst_ip_mask;
    char  name[64];
};

/* IP tracking state */
struct ip_state {
    __u64 last_seen;
    __u32 syn_count;
    __u32 conn_count;
    __u32 icmp_count;
    __u64 bytes_total;
    __u8  flags;
};

/* Rate limit info */
struct rate_info {
    __u64 tokens;
    __u64 last_update;
    __u64 rate;
    __u64 capacity;
};

/* BPF Maps */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);           // rule_id
    __type(value, struct idps_rule);
    __uint(max_entries, MAX_RULES);
} idps_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);           // src_ip
    __type(value, struct ip_state);
    __uint(max_entries, MAX_TRACKED_IPS);
} ip_tracker SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);           // src_ip
    __type(value, struct rate_info);
    __uint(max_entries, MAX_TRACKED_IPS);
} rate_limiters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);           // src_ip
    __type(value, __u32);        // 0 = whitelisted
    __uint(max_entries, 1024);
} whitelist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, MAX_ALERTS);
} idps_alerts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 16);
} idps_stats SEC(".maps");

/* Helper functions */
static __always_inline int is_whitelisted(__u32 ip)
{
    return bpf_map_lookup_elem(&whitelist, &ip) != NULL;
}

static __always_inline int check_rate_limit(__u32 ip, __u64 rate, __u64 capacity)
{
    struct rate_info *rl = bpf_map_lookup_elem(&rate_limiters, &ip);
    if (!rl) {
        struct rate_info new_rl = {
            .tokens = capacity,
            .last_update = bpf_ktime_get_ns(),
            .rate = rate,
            .capacity = capacity,
        };
        bpf_map_update_elem(&rate_limiters, &ip, &new_rl, BPF_ANY);
        return 0;
    }

    __u64 now = bpf_ktime_get_ns();
    __u64 elapsed = now - rl->last_update;
    __u64 tokens_to_add = (elapsed * rl->rate) / 1000000000;

    rl->tokens = rl->tokens + tokens_to_add;
    if (rl->tokens > rl->capacity)
        rl->tokens = rl->capacity;
    rl->last_update = now;

    if (rl->tokens < 1)
        return -1;  // Rate limited

    rl->tokens--;
    return 0;
}

static __always_inline void send_alert(__u32 src_ip, __u32 dst_ip,
                                      __u16 src_port, __u16 dst_port,
                                      __u8 protocol, __u8 severity,
                                      __u32 rule_id)
{
    struct idps_alert *alert = bpf_ringbuf_reserve(&idps_alerts,
                                                    sizeof(*alert), 0);
    if (!alert)
        return;

    alert->src_ip = src_ip;
    alert->dst_ip = dst_ip;
    alert->src_port = src_port;
    alert->dst_port = dst_port;
    alert->protocol = protocol;
    alert->severity = severity;
    alert->rule_id = rule_id;
    alert->timestamp = bpf_ktime_get_ns();

    bpf_ringbuf_submit(alert, 0);
}

static __always_inline void update_stats(__u32 idx, __u64 count)
{
    __u64 *val = bpf_map_lookup_elem(&idps_stats, &idx);
    if (val)
        __sync_fetch_and_add(val, count);
}

#endif /* _IDPS_H */
