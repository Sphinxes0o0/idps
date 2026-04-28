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
#include <linux/ipv6.h>
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
#define PORT_SCAN_THRESHOLD_DEFAULT 20
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
    EVENT_HTTP_DETECTED = 8,
    EVENT_SSH_BANNER = 9,
    EVENT_FTP_CMD = 10,
    EVENT_TELNET_OPT = 11,
    EVENT_PORT_SCAN = 12,
    EVENT_FRAG_REASSEMBLE = 13,  /* Fragment reassembly complete, user-space should reassemble */
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
 *
 * Port range support:
 *   dst_port:     起始端口 (单端口或范围起始)
 *   dst_port_max: 范围结束端口 (0 表示单端口)
 *   当 dst_port_max > dst_port 时，表示范围匹配
 */
struct rule_entry {
    __u32 rule_id;
    __u8  action;        /* 0=log, 1=drop, 2=alert */
    __u8  severity;
    __u8  protocol;      /* 6=TCP, 17=UDP, 0=any */
    __u16 dst_port;     /* 起始端口 (单端口或范围起始) */
    __u16 dst_port_max; /* 范围结束端口 (0 = 单端口) */
    __u8  dpi_needed;   /* 0=不需要, 1=需要用户态 DPI */
    __u8  padding[2];
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
    __u32 port_scan_threshold;
    __u32 dns_amp_threshold;  /* DNS amplification 检测阈值 (默认 10x) */
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
    STATS_HTTP_DETECTED = 9,
    STATS_SSH_BANNER = 10,
    STATS_FTP_CMD = 11,
    STATS_TELNET_OPT = 12,
    STATS_PORT_SCAN_ALERTS = 13,
    STATS_MAX = 256,
};

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

/* DNS amplification tracking - key: victim IP */
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

/* DNS amplification 跟踪表 - LRU Hash (单表统一跟踪 query 和 response 都以 victim_ip 为 key) */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct dns_amp_key);
    __type(value, struct dns_amp_stats);
} dns_amp_track SEC(".maps");

/* Port scan detection - scan type flags */
#define SCAN_TYPE_SYN 0x01
#define SCAN_TYPE_FIN_NULL 0x02
#define SCAN_TYPE_XMAS 0x04

/* port_scan_key - Port scan tracking key (src_ip, dst_ip) */
struct port_scan_key {
    __u32 src_ip;
    __u32 dst_ip;
};

/* port_scan_stats - Port scan tracking statistics */
struct port_scan_stats {
    __u64 window_start;
    __u64 last_seen;
    __u32 packet_count;
    __u8 scan_type_mask;
    __u8 alert_sent;
    __u8 padding[2];
};

/* Port scan tracking table - LRU Hash */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct port_scan_key);
    __type(value, struct port_scan_stats);
} port_scan_track SEC(".maps");

/* 规则索引 key: (protocol << 16) | dst_port */
struct rule_index_key {
    __u32 proto_port;  /* (protocol << 16) | port */
};

/* 规则索引: 加速 (protocol, port) -> rule_id 查找 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct rule_index_key);
    __type(value, __u32);  /* rule_id */
} rule_index SEC(".maps");

/*
 * IP Defragmentation
 *
 * Fragment key: (src_ip, dst_ip, ip_id, protocol, ip_version)
 * - IPv4: uses identification field (16-bit) from IP header
 * - IPv6: uses identification field (32-bit) from Fragment header
 */

/*
 * IPv6 Fragment Header (RFC 8200)
 * Next Header: Protocol of the fragment
 * Reserved: Reserved byte
 * Fragment Offset: 13-bit offset in 8-byte units
 * Res: Reserved 2 bits
 * M Flag: 1 = more fragments, 0 = last fragment
 * Identification: 32-bit identification value
 */
struct frag_hdr {
    __u8    nexthdr;
    __u8    reserved;
    __u16    frag_off;       /* bits 0-12: offset, bits 13-14: reserved, bit 15: M flag */
    __u32   identification;
};

/* Fragment tracking key */
struct frag_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u32 ip_id;       /* IPv4: 16-bit identification extended to 32 */
    __u8  protocol;    /* Next header protocol */
    __u8  ip_version; /* 4 or 6 */
    __u8  padding[2];
};

/* Fragment tracking value - stores metadata for up to 8 fragments */
#define MAX_FRAGMENTS 8

/* Per-fragment metadata stored in frag_entry */
struct frag_frag_meta {
    __u32 buf_id;        /* Buffer ID in frag_buffers map */
    __u16 offset;       /* Fragment offset in bytes */
    __u16 size;         /* Fragment size in bytes */
};

/* Fragment tracking value - stores metadata for reassembly */
struct frag_entry {
    __u64 first_seen;       /* Timestamp of first fragment */
    __u64 last_seen;        /* Timestamp of last fragment */
    __u32 total_length;     /* Total reassembled length (from first frag) */
    __u32 ip_id;            /* IP identification for lookup */
    __u8  frag_count;       /* Number of fragments received */
    __u8  complete;         /* Reassembly complete flag */
    __u8  more_fragments;   /* MF flag from first fragment */
    __u8  ip_version;       /* IP version (4 or 6) */
    /* 5-tuple for user-space lookup */
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  padding;
    struct frag_frag_meta frags[MAX_FRAGMENTS];  /* Fragment metadata array */
};

/* Fragment data buffer - stores actual fragment data */
struct frag_data {
    __u32 session_id;      /* Index into frag_track */
    __u16 offset;          /* Fragment offset in bytes */
    __u16 size;            /* Fragment size in bytes */
    __u8  padding[4];
    /* Actual fragment data stored inline */
    /* Data size is limited by FRAG_BUFFER_SIZE */
};

/* Fragment tracking map - LRU hash to auto-evict old fragments */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);  /* Max concurrent reassemblies */
    __type(key, struct frag_key);
    __type(value, struct frag_entry);
} frag_track SEC(".maps");

/* Fragment data buffer map - stores actual fragment data */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);  /* Max 16K fragment buffers, LRU auto-evicts */
    __type(key, __u32);         /* Buffer ID */
    __type(value, struct frag_data);
} frag_buffers SEC(".maps");

/* Defragmentation constants */
#define FRAG_TIMEOUT_NS 30000000000ULL    /* 30 seconds timeout */
#define FRAG_MAX_SIZE 65535               /* Max reassembled packet size */
#define FRAG_MIN_SIZE 8                   /* Minimum fragment size (8-byte aligned) */
#define FRAG_BUFFER_SIZE 128              /* Size of each fragment buffer entry */

#endif /* NIDS_COMMON_H */
