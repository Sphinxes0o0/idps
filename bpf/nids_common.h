/* SPDX-License-Identifier: MIT */
/*
 * nids_common.h - eBPF/NIDS 共享头文件
 *
 * 定义内核态和用户态共享的数据结构、Map 定义、常量等
 */

#ifndef NIDS_COMMON_H
#define NIDS_COMMON_H

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* 常量定义 */
#define MAX_RULES 50000
#define MAX_FLOWS 100000
#define DDoS_THRESHOLD_DEFAULT 10000
#define WINDOW_SIZE_NS 1000000000ULL  /* 1 second in nanoseconds */

/* 事件类型 */
enum event_type {
    EVENT_RULE_MATCH = 0,
    EVENT_DDoS_ALERT = 1,
    EVENT_FLOW_THRESHOLD = 2,
    EVENT_NEW_FLOW = 3,
    EVENT_DPI_REQUEST = 4,  /* 需要用户态 DPI 检查的请求 */
    EVENT_SYN_FLOOD = 5,    /* SYN flood detected */
    EVENT_ICMP_FLOOD = 6,   /* ICMP flood detected */
    EVENT_DNS_AMP = 7,      /* DNS amplification detected */
};

/* 告警严重级别 */
enum severity {
    SEVERITY_INFO = 0,
    SEVERITY_LOW = 1,
    SEVERITY_MEDIUM = 2,
    SEVERITY_HIGH = 3,
    SEVERITY_CRITICAL = 4,
};

/*
 * flow_key - 5-tuple 流标识符
 * 用于 conn_track Map 的 key
 */
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  padding[3];  /* 填充到 16 字节对齐 */
};

/*
 * flow_stats - 流统计数据
 * 存储在 conn_track Map 的 value 中
 */
struct flow_stats {
    __u64 packet_count;
    __u64 byte_count;
    __u64 last_seen;
    __u64 window_start;      /* 当前窗口起始时间 */
    __u32 window_packets;    /* 当前窗口内的包数 */
    __u8  flags;
    __u8  padding[7];
};

/*
 * src_track - 基于源 IP 的 DDoS 跟踪结构
 * 用于 SYN flood 和 ICMP flood 检测
 */
struct src_track {
    __u64 packet_count;     /* 窗口内的包计数 */
    __u64 last_seen;        /* 最后包时间 */
    __u64 window_start;     /* 窗口起始时间 */
    __u8  flags;           /* 标志位 */
    __u8  padding[7];
};

/*
 * syn_flood_key - SYN flood 跟踪的 key
 * 使用源 IP + 目标 IP + 目标端口追踪特定端口的 SYN flood
 */
struct syn_flood_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 dst_port;
    __u8  padding[2];
};

/*
 * icmp_flood_key - ICMP flood 跟踪的 key
 * 只使用源 IP
 */
struct icmp_flood_key {
    __u32 src_ip;
};

/*
 * alert_event - 告警事件结构
 * 通过 Ringbuf 传递到用户态
 */
struct alert_event {
    __u64 timestamp;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  severity;
    __u32 rule_id;
    __u8  event_type;
    __u8  padding[3];
};

/*
 * rule_entry - 规则条目
 * 存储在 rules Map 中
 */
struct rule_entry {
    __u32 rule_id;
    __u8  action;        /* 0=log, 1=drop, 2=alert */
    __u8  severity;
    __u8  protocol;      /* 6=TCP, 17=UDP, 0=any */
    __u16 dst_port;
    __u8  dpi_needed;    /* 0=不需要, 1=需要用户态 DPI */
    __u8  padding[3];
};

/*
 * config_entry - 配置参数
 * 存储在 config Map 中
 */
struct config_entry {
    __u32 ddos_threshold;
    __u32 window_size_ns;
    __u32 enabled;
    __u32 drop_enabled;  /* 运行时可配置 */
};

/* 统计计数器索引 */
enum stats_index {
    STATS_PACKETS_TOTAL = 0,
    STATS_PACKETS_DROPPED = 1,
    STATS_PACKETS_PASSED = 2,
    STATS_DDoS_ALERTS = 3,
    STATS_RULE_MATCHES = 4,
    STATS_NEW_FLOWS = 5,
    STATS_SYN_FLOOD_ALERTS = 6,
    STATS_ICMP_FLOOD_ALERTS = 7,
    STATS_DNS_AMP_ALERTS = 8,
    STATS_MAX = 256,
};

/*
 * 辅助函数: 从 IP 头获取协议
 */
static __always_inline __u8 get_ip_protocol(const struct iphdr *iph) {
    return iph->protocol;
}

/*
 * 辅助函数: 计算 5-tuple 哈希
 * 使用 FNV-1a 算法（与用户态保持一致）
 */
static __always_inline __u32 calc_flow_hash(const struct flow_key *key) {
    __u32 hash = 2166136261U;
    const __u8 *data = (const __u8 *)key;
    __u32 len = sizeof(struct flow_key);

    for (__u32 i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 16777619U;
    }
    return hash;
}

/*
 * 辅助函数: 检测是否为 DDoS 攻击
 * 返回: 0=正常, 1=DDoS 告警
 */
static __always_inline int check_ddos(struct flow_stats *stats, __u32 threshold) {
    return stats->window_packets >= threshold;
}

/*
 * 辅助宏: 安全地访问以太网头后的 IP 头
 */
static __always_inline int parse_eth_ip(const void *data, void *data_end,
                                        struct ethhdr **eth, struct iphdr **ip) {
    *eth = (struct ethhdr *)data;
    if ((void *)(*eth + 1) > data_end)
        return -1;

    if (bpf_ntohs((*eth)->h_proto) != ETH_P_IP)
        return -2;  /* 非 IPv4 */

    *ip = (struct iphdr *)((*eth) + 1);
    if ((void *)(*ip + 1) > data_end)
        return -1;

    return 0;
}

/*
 * 辅助宏: 解析 TCP/UDP 传输层头
 */
static __always_inline int parse_transport(const void *data, void *data_end,
                                           struct iphdr *ip,
                                           void **l4, __u8 *proto) {
    *proto = ip->protocol;
    *l4 = (void *)(ip + 1);

    if ((void *)(*l4) > data_end)
        return -1;

    return 0;
}

/*
 * BPF Map 定义
 * 使用 SEC(".maps") 让 libbpf 自动识别
 */

/* 连接跟踪表 - LRU Hash */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow_key);
    __type(value, struct flow_stats);
} conn_track SEC(".maps");

/* 规则表 - Hash */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_RULES);
    __type(key, __u32);           /* rule_id */
    __type(value, struct rule_entry);
} rules SEC(".maps");

/* 统计计数器 - Per-CPU Array */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STATS_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

/* 配置表 - Array */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config_entry);
} config SEC(".maps");

/* 告警事件 Ringbuf */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  /* 256KB ring buffer */
} events SEC(".maps");

/* XDP 跳转表 (用于多程序链) */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
} xdp_jmp_table SEC(".maps");

/* SYN flood 跟踪表 - LRU Hash (key = syn_flood_key) */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct syn_flood_key);
    __type(value, struct src_track);
} syn_flood_track SEC(".maps");

/* ICMP flood 跟踪表 - LRU Hash (key = source IP) */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct icmp_flood_key);
    __type(value, struct src_track);
} icmp_flood_track SEC(".maps");

/* DNS query tracking - key: (src_ip, dst_ip) */
struct dns_query_key {
    __u32 src_ip;
    __u32 dst_ip;
};

/* DNS query stats */
struct dns_query_stats {
    __u64 query_count;
    __u64 query_bytes;
    __u64 last_seen;
};

/* DNS amplification tracking - key: victim dst_ip */
struct dns_amp_key {
    __u32 victim_ip;
};

/* DNS amplification stats */
struct dns_amp_stats {
    __u64 response_bytes;
    __u64 query_bytes;
    __u64 last_seen;
    __u8 alert_sent;
    __u8 padding[7];
};

/* DNS query 跟踪表 - LRU Hash */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct dns_query_key);
    __type(value, struct dns_query_stats);
} dns_query_track SEC(".maps");

/* DNS amplification 跟踪表 - LRU Hash */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct dns_amp_key);
    __type(value, struct dns_amp_stats);
} dns_amp_track SEC(".maps");

#endif /* NIDS_COMMON_H */
