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
#include <linux/ipv6.h>

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
 * 获取配置值 (从 config map)
 */
static __always_inline __u32 get_config_enabled(void) {
    __u32 key = 0;
    struct config_entry *cfg = bpf_map_lookup_elem(&config, &key);
    if (cfg)
        return cfg->enabled;
    return 1;  /* 默认启用 */
}

static __always_inline __u32 get_config_drop_enabled(void) {
    __u32 key = 0;
    struct config_entry *cfg = bpf_map_lookup_elem(&config, &key);
    if (cfg)
        return cfg->drop_enabled;
    return 0;  /* 默认关闭 drop */
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
 * @return rule_id | (dpi_needed << 31) | (action << 30)
 *   dpi_needed: bit 31 = 1 表示需要用户态 DPI
 *   action: bit 30 = 1 表示 drop, bit 30 = 0 表示 alert
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

        /* 找到匹配！
         * 返回 rule_id + dpi_needed (bit 31) + action (bit 30)
         * action: 0=alert, 1=drop
         */
        return rule->rule_id | ((__u32)rule->dpi_needed << 31) | ((__u32)rule->action << 30);
    }

    return 0;  /* 无匹配 */
}

/*
 * 解析以太网 + IPv4 + TCP/UDP/ICMP 头
 * 直接从 XDP 帧访问，不依赖 skb
 *
 * 返回值:
 *   0: 成功解析
 *  -1: 数据越界
 *  -2: 非 IPv4
 */
static __always_inline int parse_packet(void *data, void *data_end,
                                         struct flow_key *key,
                                         __u32 *pkt_len,
                                         __u8 *tcp_flags) {
    struct ethhdr *eth;
    struct iphdr *ip;
    void *l4;

    /* 解析 Ethernet */
    eth = (struct ethhdr *)data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    __u16 eth_proto = bpf_ntohs(eth->h_proto);

    if (eth_proto == ETH_P_IP) {
        /* IPv4 */
        ip = (struct iphdr *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return -1;

        /* 提取 5-tuple */
        key->src_ip = bpf_ntohl(ip->saddr);
        key->dst_ip = bpf_ntohl(ip->daddr);
        key->protocol = ip->protocol;
        *pkt_len = bpf_ntohs(ip->tot_len);

        /* 初始化 tcp_flags */
        *tcp_flags = 0;

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
            *tcp_flags = *( (__u8 *)tcp + 13);
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)l4;
            if ((void *)(udp + 1) > data_end)
                return -1;
            key->src_port = bpf_ntohs(udp->source);
            key->dst_port = bpf_ntohs(udp->dest);
        } else {
            key->src_port = 0;
            key->dst_port = 0;
        }

        return 0;
    } else if (eth_proto == ETH_P_IPV6) {
        /* IPv6 — 暂不支持深度检测，记录统计后放行 */
        struct ipv6hdr *ipv6 = (struct ipv6hdr *)(eth + 1);
        if ((void *)(ipv6 + 1) > data_end)
            return -1;

        key->src_ip = 0;  /* IPv6 不兼容 IPv4 */
        key->dst_ip = 0;
        key->protocol = ipv6->nexthdr;
        *pkt_len = bpf_ntohs(ipv6->payload_len);

        /* 初始化 tcp_flags */
        *tcp_flags = 0;

        /* 解析传输层 (简化版，不处理扩展头) */
        l4 = (void *)(ipv6 + 1);
        if (l4 > data_end)
            return -1;

        if (ipv6->nexthdr == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)l4;
            if ((void *)(tcp + 1) > data_end)
                return -1;
            key->src_port = bpf_ntohs(tcp->source);
            key->dst_port = bpf_ntohs(tcp->dest);
            *tcp_flags = *( (__u8 *)tcp + 13);
        } else if (ipv6->nexthdr == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)l4;
            if ((void *)(udp + 1) > data_end)
                return -1;
            key->src_port = bpf_ntohs(udp->source);
            key->dst_port = bpf_ntohs(udp->dest);
        } else {
            key->src_port = 0;
            key->dst_port = 0;
        }

        return 0;
    }

    return -2;  /* 非 IPv4/IPv6 */
}

/*
 * 归一化流 key，确保 (A→B) 和 (B→A) 使用相同的 key
 * 规则：src_ip <= dst_ip，如果相等则 src_port <= dst_port
 */
static __always_inline void normalize_flow_key(struct flow_key *key) {
    /* 交换 IP 如果 src > dst */
    if (key->src_ip > key->dst_ip) {
        __u32 tmp_ip = key->src_ip;
        key->src_ip = key->dst_ip;
        key->dst_ip = tmp_ip;
    }

    /* 如果 IP 相等，交换端口 */
    if (key->src_ip == key->dst_ip && key->src_port > key->dst_port) {
        __u16 tmp_port = key->src_port;
        key->src_port = key->dst_port;
        key->dst_port = tmp_port;
    }
}

/*
 * SYN flood 检测
 * 检查 TCP SYN 包，如果源 IP 发送大量 SYN 但无响应则判定为 flood
 * 返回: 0=正常, 1=flood detected
 */
static __always_inline int check_syn_flood(__u32 src_ip, __u32 dst_ip,
                                          __u16 dst_port, __u8 tcp_flags) {
    /* 只检测 SYN flood (SYN=2, ACK=16) */
    if (!(tcp_flags & 0x02) || (tcp_flags & 0x17)) {
        /* 不是纯 SYN 包，忽略 */
        return 0;
    }

    struct syn_flood_key s_key = {
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .dst_port = dst_port,
    };
    struct src_track *track = bpf_map_lookup_elem(&syn_flood_track, &s_key);
    __u64 now = bpf_ktime_get_ns();

    if (!track) {
        /* 新条目 */
        struct src_track new_track = {
            .packet_count = 1,
            .last_seen = now,
            .window_start = now,
            .flags = 0,
        };
        bpf_map_update_elem(&syn_flood_track, &s_key, &new_track, BPF_ANY);
        return 0;
    }

    /* 更新统计 */
    if (now - track->window_start >= WINDOW_SIZE_NS) {
        /* 重置窗口 */
        track->window_start = now;
        track->packet_count = 1;
    } else {
        track->packet_count++;
    }
    track->last_seen = now;

    /* 检测阈值 */
    if (track->packet_count >= ddos_threshold) {
        /* 发送 SYN flood 告警 */
        send_alert(src_ip, dst_ip, 0, dst_port,
                   IPPROTO_TCP, SEVERITY_HIGH,
                   0, EVENT_SYN_FLOOD);
        increment_stat(STATS_SYN_FLOOD_ALERTS, 1);
        return 1;
    }

    return 0;
}

/*
 * ICMP flood 检测
 * 检查 ICMP 包，如果源 IP 发送大量 ICMP 则判定为 flood
 * 返回: 0=正常, 1=flood detected
 */
static __always_inline int check_icmp_flood(__u32 src_ip) {
    struct icmp_flood_key i_key = {
        .src_ip = src_ip,
    };
    struct src_track *track = bpf_map_lookup_elem(&icmp_flood_track, &i_key);
    __u64 now = bpf_ktime_get_ns();

    if (!track) {
        /* 新条目 */
        struct src_track new_track = {
            .packet_count = 1,
            .last_seen = now,
            .window_start = now,
            .flags = 0,
        };
        bpf_map_update_elem(&icmp_flood_track, &i_key, &new_track, BPF_ANY);
        return 0;
    }

    /* 更新统计 */
    if (now - track->window_start >= WINDOW_SIZE_NS) {
        /* 重置窗口 */
        track->window_start = now;
        track->packet_count = 1;
    } else {
        track->packet_count++;
    }
    track->last_seen = now;

    /* 检测阈值 (ICMP flood 阈值可以低一些) */
    if (track->packet_count >= ddos_threshold / 10) {
        /* 发送 ICMP flood 告警 (阈值是 DDoS 的 1/10) */
        send_alert(src_ip, 0, 0, 0,
                   IPPROTO_ICMP, SEVERITY_MEDIUM,
                   0, EVENT_ICMP_FLOOD);
        increment_stat(STATS_ICMP_FLOOD_ALERTS, 1);
        return 1;
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
    __u8 tcp_flags = 0;
    int ret;

    /* 检查是否启用 */
    if (!enabled)
        return XDP_PASS;

    /* 解析数据包 */
    ret = parse_packet(data, data_end, &key, &pkt_len, &tcp_flags);
    if (ret != 0) {
        /* 非支持协议，直接通过 */
        increment_stat(STATS_PACKETS_PASSED, 1);
        return XDP_PASS;
    }

    /* SYN flood 检测 (TCP with only SYN flag) */
    if (key.protocol == IPPROTO_TCP) {
        check_syn_flood(key.src_ip, key.dst_ip, key.dst_port, tcp_flags);
    }

    /* ICMP flood 检测 */
    if (key.protocol == IPPROTO_ICMP) {
        check_icmp_flood(key.src_ip);
    }

    /* 归一化流 key，确保 (A→B) 和 (B→A) 使用同一 entry */
    normalize_flow_key(&key);

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
            __u32 dpi_needed = (matched >> 31) & 1;
            __u32 action = (matched >> 30) & 1;
            __u32 rule_id = matched & 0x3FFFFFFF;  /* bits 0-29 */

            if (dpi_needed) {
                /* 需要用户态 DPI 检查，发送 DPI_REQUEST 事件 */
                send_alert(key.src_ip, key.dst_ip,
                          key.src_port, key.dst_port,
                          key.protocol, SEVERITY_MEDIUM,
                          rule_id, EVENT_DPI_REQUEST);
            } else if (action == 1 && get_config_drop_enabled()) {
                /* Drop 动作：丢弃数据包并发送告警 */
                send_alert(key.src_ip, key.dst_ip,
                          key.src_port, key.dst_port,
                          key.protocol, SEVERITY_HIGH,
                          rule_id, EVENT_RULE_MATCH);
                increment_stat(STATS_RULE_MATCHES, 1);
                increment_stat(STATS_PACKETS_DROPPED, 1);
                return XDP_DROP;
            } else {
                /* Alert 动作：发送告警但放行包 */
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
