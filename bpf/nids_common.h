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
    EVENT_ACK_FLOOD = 14,        /* TCP ACK flood detected */
    EVENT_FIN_FLOOD = 15,       /* TCP FIN flood detected */
    EVENT_RST_FLOOD = 16,       /* TCP RST flood detected */
    EVENT_PROCESS_CONNECT = 17,  /* Process connect() syscall */
    EVENT_PROCESS_CLOSE = 18,    /* Process close() syscall */
    EVENT_PROCESS_SOCKET = 19,    /* Process socket() syscall */
    EVENT_PROCESS_SEND = 20,     /* Process send() syscall */
    EVENT_PROCESS_RECV = 21,     /* Process recv() syscall */
    EVENT_SLOWLORIS = 22,       /* Slowloris/Slow POST attack detected */
    EVENT_TLS_WRITE = 23,       /* TLS/SSL write activity */
    EVENT_TLS_READ = 24,        /* TLS/SSL read activity */
    EVENT_SMTP_CMD = 25,        /* SMTP command detected */
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
    __u8  padding[3];
    __u32 pid;              /* 关联的进程 ID (当进程调用 connect() 时记录) */
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
    STATS_ACK_FLOOD_ALERTS = 14,
    STATS_FIN_FLOOD_ALERTS = 15,
    STATS_RST_FLOOD_ALERTS = 16,
    STATS_SLOWLORIS_ALERTS = 17,
    STATS_SMTP_CMD = 18,
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

/*
 * fast_alert_event - 快速告警事件结构 (精简版，用于 DDoS 快速路径)
 * 比 alert_event 更小，专用 ringbuf 无锁竞争
 */
struct fast_alert_event {
    __u64 timestamp;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  severity;
    __u32 rule_id;
    __u8  event_type;
};

/* 快速告警事件 Ringbuf (独立于 events 的专用 ringbuf) */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128 * 1024);  /* 128KB ring buffer for fast path */
} fast_alerts SEC(".maps");

/* Alert rate limiting - tracks last alert time per source IP for DDoS alerts */
struct alert_rate_key {
    __u32 src_ip;
    __u8 event_type;  /* Which alert type */
    __u8 padding[3];
};

struct alert_rate_value {
    __u64 last_alert_time;
    __u32 alert_count;  /* Count in current window */
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct alert_rate_key);
    __type(value, struct alert_rate_value);
} alert_rate_limit SEC(".maps");

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

/* TCP ACK flood tracking table - LRU Hash (key = flow_key) */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, struct src_track);
} tcp_ack_flood_track SEC(".maps");

/* TCP FIN flood tracking table - LRU Hash (key = flow_key) */
/* Tracks FIN packets per source IP to detect single-source FIN flood */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, struct src_track);
} tcp_fin_flood_track SEC(".maps");

/* TCP RST flood tracking table - LRU Hash (key = flow_key) */
/* Tracks RST packets per source IP to detect single-source RST flood */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, struct src_track);
} tcp_rst_flood_track SEC(".maps");

/*
 * Slowloris/Slow POST attack detection
 * Tracks HTTP connections and detects slow data transmission
 */

/* Slow HTTP tracking stats */
struct slow_http_stats {
    __u64 last_packet_time;  /* Timestamp of last packet */
    __u64 connection_start; /* Timestamp when connection was established */
    __u8  alert_sent;       /* Alert has been sent for this connection */
    __u8  padding[7];
};

/* Slow HTTP tracking table - LRU Hash (key = flow_key) */
/* Tracks packet intervals on HTTP connections to detect Slowloris/Slow POST attacks */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, struct slow_http_stats);
} slow_http_track SEC(".maps");

/* Slowloris detection threshold - 10 seconds in nanoseconds */
#define SLOWLORIS_THRESHOLD_NS 10000000000ULL

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
 * 规则匹配计数表 - 用于无锁 RCU 风格规则匹配
 * 使用 atomic fetch-add 操作实现无锁计数
 * key: rule_id
 * value: match count (atomic increment via __sync_fetch_and_add)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_RULES);
    __type(key, __u32);   /* rule_id */
    __type(value, __u64); /* match count */
} rule_match_count SEC(".maps");

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

/*
 * process_event - Process lifecycle event (connect/close/socket/send/recv)
 * Sent via ringbuf for tracking process network activity
 */
struct process_event {
    __u64 timestamp;
    __u32 pid;            /* Process ID */
    __u32 tid;            /* Thread ID */
    __u32 uid;            /* User ID */
    __u32 fd;             /* File descriptor (socket fd, closed fd, or send/recv fd) */
    __u8  event_type;     /* EVENT_PROCESS_CONNECT, EVENT_PROCESS_CLOSE, EVENT_PROCESS_SOCKET, etc. */
    __u8  addr_family;    /* AF_INET or AF_INET6 */
    __u8  protocol;       /* IPPROTO_TCP, IPPROTO_UDP, etc. */
    __u8  socket_type;   /* SOCK_STREAM, SOCK_DGRAM, etc. (for socket events) */
    __u32 src_ip;         /* Source IP (network byte order for IPv4, first 32 bits for IPv6) */
    __u32 dst_ip;         /* Destination IP */
    __u16 src_port;       /* Source port */
    __u16 dst_port;       /* Destination port */
    __u64 bytes;          /* Bytes sent/recv'd (for send/recv events) */
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

/* FD tracking */
#define FD_TYPE_UNKNOWN 0
#define FD_TYPE_FILE    1
#define FD_TYPE_SOCKET  2
#define FD_TYPE_PIPE    3

struct fd_track {
    __u32 total_fds;
    __u32 socket_count;
    __u32 file_count;
    __u32 pipe_count;
    __u64 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, struct fd_track);
} fd_monitor SEC(".maps");

struct fd_type_key {
    __u32 pid;
    __u32 fd;
};

struct fd_type_val {
    __u8 type;
    __u8 padding[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, struct fd_type_key);
    __type(value, struct fd_type_val);
} fd_type_track SEC(".maps");

/*
 * P-05: DNS Query Process Tracking
 *
 * Tracks getaddrinfo/gethostbyname calls to correlate DNS queries with processes.
 * Key: pid (process ID)
 * Value: hostname being resolved
 */

/* DNS process tracking - key: PID */
struct dns_query_key {
    __u32 pid;
};

/* DNS query info - hostname being resolved */
struct dns_query_info {
    __u64 timestamp;
    char hostname[128];  /* Maximum hostname length */
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);  /* Track up to 16K concurrent DNS queries */
    __type(key, struct dns_query_key);
    __type(value, struct dns_query_info);
} dns_query_track SEC(".maps");

/*
 * syn_flood_src_pid - SYN flood 源进程追踪
 * 记录每个源 IP 最近发起连接的进程 ID
 * 用于在检测到 SYN flood 时关联攻击源进程
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);  /* src_ip */
    __type(value, __u32);  /* pid */
} syn_flood_src_pid SEC(".maps");

/*
 * P-04: TLS Connection Process Attribution
 *
 * Tracks SSL_write/SSL_read calls to correlate TLS connections with processes.
 * Key: SSL pointer address (userspace pointer)
 * Value: PID, FD, and connection info
 */

/* TLS connection tracking key - SSL pointer */
struct tls_conn_key {
    __u64 ssl_ptr;  /* SSL* pointer from tracepoint */
};

/* TLS connection info */
struct tls_conn_info {
    __u32 pid;           /* Process ID */
    __u32 tid;           /* Thread ID */
    __u32 fd;            /* Socket file descriptor (if available) */
    __u64 timestamp;     /* Last activity timestamp */
    __u32 src_ip;        /* Source IP */
    __u32 dst_ip;        /* Destination IP */
    __u16 src_port;      /* Source port */
    __u16 dst_port;      /* Destination port */
};

/* TLS connection tracking map - LRU Hash */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);  /* Max concurrent TLS connections */
    __type(key, struct tls_conn_key);
    __type(value, struct tls_conn_info);
} tls_conn_track SEC(".maps");


/*
 * P-01: 进程感知流量监控
 *
 * process_info - 存储进程 connect() 系统调用信息
 * 用于在 XDP 处理时关联 packet 与进程
 *
 * Key: flow_key (src_ip, dst_ip, src_port, dst_port, protocol)
 * Value: process information (pid, uid, fd, timestamp)
 */
struct process_info {
    __u32 pid;           /* Process ID */
    __u32 uid;           /* User ID */
    __u32 fd;            /* Socket file descriptor */
    __u64 timestamp;     /* Last update timestamp */
    __u8  addr_family;   /* AF_INET or AF_INET6 */
    __u8  protocol;      /* IPPROTO_TCP or IPPROTO_UDP */
    __u8  padding[2];
};

/* Process tracking map - keyed by 5-tuple for XDP lookup */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);  /* Max concurrent tracked connections */
    __type(key, struct flow_key);
    __type(value, struct process_info);
} process_map SEC(".maps");

/*
 * R-04: SMTP Session State Tracking
 *
 * Tracks SMTP session state per flow to detect command sequences:
 *   CONNECT -> EHLO/HELO -> AUTH -> USER -> PASS -> DATA
 *
 * SMTP ports: 25 (SMTP), 587 (Submission), 465 (SMTPS)
 */

/* SMTP state machine states */
enum smtp_state {
    SMTP_CONNECT = 0,    /* 220 banner received - connection established */
    SMTP_EHLO = 1,       /* EHLO/HELO received - session started */
    SMTP_AUTH = 2,        /* AUTH command received - authentication started */
    SMTP_USER = 3,       /* AUTH LOGIN - username submitted */
    SMTP_PASS = 4,       /* AUTH LOGIN - password submitted */
    SMTP_DATA = 5,       /* DATA command - mail body follows */
    SMTP_UNKNOWN = 6,    /* Unknown/invalid state */
};

/* SMTP tracking key - based on flow 5-tuple */
struct smtp_track_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

/* SMTP tracking value - stores session state and metadata */
struct smtp_track_value {
    __u8 state;           /* Current SMTP state (enum smtp_state) */
    __u8 padding[3];
    __u64 last_seen;      /* Last packet timestamp */
    __u32 command_count;  /* Number of commands in session */
};

/* SMTP session tracking table - LRU Hash */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);  /* Max concurrent SMTP sessions */
    __type(key, struct smtp_track_key);
    __type(value, struct smtp_track_value);
} smtp_track SEC(".maps");

/*
 * P-03: Process Socket Mapping Table
 *
 * Tracks which process (pid) has which socket (fd) with its address info.
 * Used for correlating network activity with processes.
 * Key: file descriptor (fd)
 * Value: process information (pid, fd, address info)
 */

/* Process to socket mapping entry */
struct proc_sock_entry {
    __u32 pid;           /* Process ID */
    __u32 fd;            /* Socket file descriptor */
    __u32 family;        /* AF_INET or AF_INET6 */
    __u32 ip;            /* IP address (network byte order) */
    __u16 port;          /* Port (network byte order) */
    __u8  protocol;      /* IPPROTO_TCP, IPPROTO_UDP, etc. */
    __u8  padding[3];
};

/* Process to socket mapping table - keyed by fd */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);  /* fd */
    __type(value, struct proc_sock_entry);
} proc_sock_map SEC(".maps");

/*
 * P-02: System Call Network Monitoring
 *
 * Extended process_event structure for socket/send/recv syscalls.
 * Uses existing process_events ringbuf for transport.
 */

#endif /* NIDS_COMMON_H */
