/* SPDX-License-Identifier: MIT */
/*
 * nids_bpf.c - XDP eBPF 网络入侵检测程序
 *
 * 设计理念:
 * 1. 在内核网络栈之前（XDP 层）进行快速处理
 * 2. 利用 per-CPU 计数器实现无锁 DDoS 检测
 * 3. 使用 LRU Hash 做连接跟踪，自动淘汰旧条目
 * 4. 通过 Ringbuf 零拷贝传递告警事件到用户态
 * 5. 简单规则匹配在内核态完成，复杂 DPI 保留在用户态
 */

#include "nids_common.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/ptrace.h>

/*
 * 全局配置 (从用户态更新)
 */
const volatile __u32 ddos_threshold = DDoS_THRESHOLD_DEFAULT;
const volatile __u32 enabled = 1;

/* 全局规则匹配标志 */
const volatile __u32 match_rules_enabled = 1;

/*
 * 静态内联函数
 */

/*
 * 递增统计计数器
 * 使用 per-CPU array，无需锁
 */
static __always_inline void increment_stat(__u32 index, __u64 value) {
    __u32 key = index;
    __u64 *count = bpf_map_lookup_elem(&stats, &key);
    if (count)
        __sync_fetch_and_add(count, value);
}

/*
 * 发送告警事件到 Ringbuf
 * 零拷贝路径
 */
static __always_inline int send_alert(__u32 src_ip, __u32 dst_ip,
                                       __u16 src_port, __u16 dst_port,
                                       __u8 proto, __u8 severity,
                                       __u32 rule_id, __u8 event_type) {
    struct alert_event *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        /* Ringbuf 已满，计数并丢弃 */
        increment_stat(STATS_PACKETS_DROPPED, 1);
        return -1;
    }

    event->timestamp = bpf_ktime_get_ns();
    event->src_ip = src_ip;
    event->dst_ip = dst_ip;
    event->src_port = src_port;
    event->dst_port = dst_port;
    event->protocol = proto;
    event->severity = severity;
    event->rule_id = rule_id;
    event->event_type = event_type;

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/*
 * 检查并更新流统计
 * 返回: 0=正常, 1=DDoS 告警已发送
 */
static __always_inline int update_flow_stats(struct flow_key *key,
                                              __u32 pkt_len,
                                              __u64 now) {
    struct flow_stats *stats;
    int alert_sent = 0;

    stats = bpf_map_lookup_elem(&conn_track, key);
    if (!stats) {
        /* 新流 */
        struct flow_stats new_stats = {
            .packet_count = 1,
            .byte_count = pkt_len,
            .last_seen = now,
            .window_start = now,
            .window_packets = 1,
            .flags = 0,
        };

        int ret = bpf_map_update_elem(&conn_track, key, &new_stats, BPF_ANY);
        if (ret != 0)
            return 0;

        increment_stat(STATS_NEW_FLOWS, 1);
    } else {
        /* 更新现有流 */
        stats->packet_count++;
        stats->byte_count += pkt_len;
        stats->last_seen = now;

        /* 检查是否需要重置窗口 */
        if (now - stats->window_start >= WINDOW_SIZE_NS) {
            stats->window_start = now;
            stats->window_packets = 1;
        } else {
            stats->window_packets++;
        }

        /* DDoS 检测 */
        if (stats->window_packets >= ddos_threshold) {
            /* 发送 DDoS 告警 */
            send_alert(key->src_ip, key->dst_ip,
                      key->src_port, key->dst_port,
                      key->protocol, SEVERITY_CRITICAL,
                      0, EVENT_DDoS_ALERT);
            increment_stat(STATS_DDoS_ALERTS, 1);
            alert_sent = 1;
        }
    }

    return alert_sent;
}

/*
 * 简单规则匹配 (仅支持协议+端口快速过滤)
 * 复杂内容匹配保留在用户态 BMH
 *
 * 遍历规则表（最多检查 MAX_RULES_TO_CHECK 条），返回第一个匹配的 rule_id
 * 注意：这是 O(n) 扫描，生产环境建议用 proto+port 做 hash 索引
 *
 * @return rule_id | (dpi_needed << 31) 组合值
 */
static __always_inline __u32 match_simple_rules(__u8 proto, __u16 dst_port) {
    /* 最多检查的规则数（避免 BPF verifier 抱怨无界循环）*/
    #define MAX_RULES_TO_CHECK 256

    for (__u32 i = 0; i < MAX_RULES_TO_CHECK; i++) {
        __u32 key = i;
        struct rule_entry *rule = bpf_map_lookup_elem(&rules, &key);
        if (!rule)
            break;  /* 规则不存在，终止扫描 */

        /* 检查协议匹配 (0=any) */
        if (rule->protocol != 0 && rule->protocol != proto)
            continue;

        /* 检查端口匹配 (0=any port) */
        if (rule->dst_port != 0 && rule->dst_port != dst_port)
            continue;

        /* 找到匹配！返回 rule_id，如果有 dpi 标志则设置最高位 */
        if (rule->dpi_needed)
            return (1U << 31) | rule->rule_id;  /* DPI needed */
        return rule->rule_id;
    }

    return 0;  /* 无匹配 */
}

/*
 * 解析以太网 + IPv4 + TCP/UDP 头
 * 直接从 XDP 帧访问，不依赖 skb
 *
 * 返回值:
 *   0: 成功解析
 *  -1: 数据越界
 *  -2: 非 IPv4
 *  -3: 非 TCP/UDP
 */
static __always_inline int parse_packet(void *data, void *data_end,
                                         struct flow_key *key,
                                         __u32 *pkt_len) {
    struct ethhdr *eth;
    struct iphdr *ip;
    void *l4;

    /* 解析 Ethernet */
    eth = (struct ethhdr *)data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return -2;

    /* 解析 IPv4 */
    ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;

    /* 提取 5-tuple */
    key->src_ip = bpf_ntohl(ip->saddr);
    key->dst_ip = bpf_ntohl(ip->daddr);
    key->protocol = ip->protocol;
    *pkt_len = bpf_ntohs(ip->tot_len);

    /* 解析传输层 */
    l4 = (void *)(ip + 1);
    if (l4 > data_end)
        return -1;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)l4;
        if ((void *)(tcp + 1) > data_end)
            return -1;
        key->src_port = bpf_ntohs(tcp->source);
        key->dst_port = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)l4;
        if ((void *)(udp + 1) > data_end)
            return -1;
        key->src_port = bpf_ntohs(udp->source);
        key->dst_port = bpf_ntohs(udp->dest);
    } else {
        /* ICMP 等协议 */
        key->src_port = 0;
        key->dst_port = 0;
    }

    return 0;
}

/*
 * XDP 主程序
 */
static __always_inline int handle_xdp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct flow_key key = {};
    __u32 pkt_len = 0;
    int ret;

    /* 检查是否启用 */
    if (!enabled)
        return XDP_PASS;

    /* 解析数据包 */
    ret = parse_packet(data, data_end, &key, &pkt_len);
    if (ret != 0) {
        /* 非支持协议，直接通过 */
        increment_stat(STATS_PACKETS_PASSED, 1);
        return XDP_PASS;
    }

    /* 更新流统计并检查 DDoS */
    int alert_sent = update_flow_stats(&key, pkt_len, bpf_ktime_get_ns());
    if (alert_sent) {
        /* DDoS 告警已发送，但仍然放行让用户态记录 */
        /* 或者可以在这里 XDP_DROP 丢弃 */
    }

    /* 简单规则匹配 (内核态) */
    if (match_rules_enabled) {
        __u32 matched = match_simple_rules(key.protocol, key.dst_port);
        if (matched > 0) {
            int dpi_needed = (matched >> 31) & 1;
            __u32 rule_id = matched & 0x7FFFFFFF;

            if (dpi_needed) {
                /* 需要用户态 DPI 检查，发送 DPI_REQUEST 事件 */
                send_alert(key.src_ip, key.dst_ip,
                          key.src_port, key.dst_port,
                          key.protocol, SEVERITY_MEDIUM,
                          rule_id, EVENT_DPI_REQUEST);
            } else {
                /* 内核直接匹配，发送 RULE_MATCH 事件 */
                send_alert(key.src_ip, key.dst_ip,
                          key.src_port, key.dst_port,
                          key.protocol, SEVERITY_HIGH,
                          rule_id, EVENT_RULE_MATCH);
                increment_stat(STATS_RULE_MATCHES, 1);
            }
        }
    }

    increment_stat(STATS_PACKETS_TOTAL, 1);
    return XDP_PASS;
}

/*
 * SEC("xdp") - XDP 入口点
 */
SEC("xdp")
int nids_xdp(struct xdp_md *ctx) {
    return handle_xdp(ctx);
}

/*
 * license - 必需的 license 声明
 * GPL 是使用某些 BPF helper 的前提
 */
char LICENSE[] SEC("license") = "MIT";
