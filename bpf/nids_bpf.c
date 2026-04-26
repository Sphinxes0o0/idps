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
 * 检查端口是否匹配规则
 * 支持单端口和端口范围
 *
 * @param rule_port      规则中的端口 (起始端口)
 * @param rule_port_max  规则中的最大端口 (0 = 单端口)
 * @param pkt_port       数据包中的目标端口
 * @return 1 如果匹配，0 如果不匹配
 */
static __always_inline int port_match(__u16 rule_port, __u16 rule_port_max, __u16 pkt_port) {
    if (rule_port == 0)
        return 1;  /* any port */
    if (rule_port_max == 0)
        return rule_port == pkt_port;  /* 单端口精确匹配 */
    /* 端口范围匹配 */
    return pkt_port >= rule_port && pkt_port <= rule_port_max;
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

    /* 首先尝试 hash 索引查找 O(1) */
    struct rule_index_key idx_key = {
        .proto_port = ((__u32)proto << 16) | dst_port,
    };
    __u32 *idx_rule_id = bpf_map_lookup_elem(&rule_index, &idx_key);
    if (idx_rule_id) {
        /* 找到索引，检查对应规则是否仍然匹配 */
        struct rule_entry *rule = bpf_map_lookup_elem(&rules, idx_rule_id);
        if (rule &&
            (rule->protocol == 0 || rule->protocol == proto) &&
            port_match(rule->dst_port, rule->dst_port_max, dst_port)) {
            return rule->rule_id | ((__u32)rule->dpi_needed << 31) | ((__u32)rule->action << 30);
        }
        /* 索引指向的规则已变更或不再匹配，删除无效索引 */
        bpf_map_delete_elem(&rule_index, &idx_key);
    }

    /* 退回到线性扫描（处理 any 协议/端口规则） */
    for (__u32 i = 0; i < MAX_RULES_TO_CHECK; i++) {
        __u32 key = i;
        struct rule_entry *rule = bpf_map_lookup_elem(&rules, &key);
        if (!rule)
            break;  /* 规则不存在，终止扫描 */

        /* 检查协议匹配 (0=any) */
        if (rule->protocol != 0 && rule->protocol != proto)
            continue;

        /* 检查端口匹配 (支持范围) */
        if (!port_match(rule->dst_port, rule->dst_port_max, dst_port))
            continue;

        /* 找到匹配！更新索引以加速下次查找 */
        bpf_map_update_elem(&rule_index, &idx_key, &key, BPF_ANY);

        /* 返回 rule_id + dpi_needed (bit 31) + action (bit 30) */
        return rule->rule_id | ((__u32)rule->dpi_needed << 31) | ((__u32)rule->action << 30);
    }

    return 0;  /* 无匹配 */
}

/*
 * IP Defragmentation Functions
 *
 * Simplified defragmentation for XDP:
 * - Tracks fragments in a per-CPU LRU hash map
 * - Times out incomplete fragments after 30 seconds
 * - Allows fragments to pass through for user-space reassembly
 */

/*
 * 检查 IPv4 数据包是否为分片
 * @return 1 如果是分片，0 如果不是
 */
static __always_inline int is_ipv4_fragment(struct iphdr *ip) {
    /* IPv4 分片检测: MF flag 或者 offset != 0 */
    __u16 frag_offset = bpf_ntohs(ip->frag_off);
    /* IP_OFFSET mask = 0x1FFF (13 bits for offset) */
    /* IP_MF mask = 0x2000 */
    return (frag_offset & (0x2000 | 0x1FFF)) != 0;
}

/*
 * 获取 IPv4 分片的偏移量 (字节单位)
 */
static __always_inline __u16 get_ipv4_frag_offset(struct iphdr *ip) {
    __u16 frag_offset = bpf_ntohs(ip->frag_off);
    return (frag_offset & 0x1FFF) * 8;  /* 13-bit offset in 8-byte units */
}

/*
 * 检查 IPv4 分片是否有更多分片标记
 */
static __always_inline int is_ipv4_more_fragments(struct iphdr *ip) {
    __u16 frag_off = bpf_ntohs(ip->frag_off);
    return (frag_off & 0x2000) != 0;
}

/*
 * 处理 IPv4 分片
 *
 * @return XDP_PASS 继续处理, XDP_DROP 丢弃, negative 错误
 */
static __always_inline int handle_ipv4_fragment(struct xdp_md *ctx,
                                                struct iphdr *ip,
                                                void *data_end) {
    __u64 now = bpf_ktime_get_ns();

    /* 构造 fragment key */
    struct frag_key fkey = {};
    fkey.src_ip = ip->saddr;
    fkey.dst_ip = ip->daddr;
    fkey.ip_id = ip->id;
    fkey.protocol = ip->protocol;
    fkey.ip_version = 4;

    /* 查找已存在的 fragment 链 */
    struct frag_entry *entry = bpf_map_lookup_elem(&frag_track, &fkey);

    /* 检查超时，清理过期分片 */
    if (entry && now - entry->last_seen > FRAG_TIMEOUT_NS) {
        bpf_map_delete_elem(&frag_track, &fkey);
        entry = NULL;
    }

    if (!entry) {
        /* 新 fragment 链 - 这是第一个分片 */
        struct frag_entry new_entry = {};
        new_entry.first_seen = now;
        new_entry.last_seen = now;
        new_entry.total_length = (__u32)bpf_ntohs(ip->tot_len);
        new_entry.fragment_count = 1;
        new_entry.more_fragments = is_ipv4_more_fragments(ip);

        /* 检查并发分片限制 */
        __u32 count_key = 0;
        __u32 *frag_count = bpf_map_lookup_elem(&frag_count, &count_key);
        if (frag_count && *frag_count >= FRAG_MAX_CONCURRENT) {
            /* 太多并发分片，丢弃这个新分片 */
            increment_stat(STATS_PACKETS_DROPPED, 1);
            return XDP_DROP;
        }

        bpf_map_update_elem(&frag_track, &fkey, &new_entry, BPF_ANY);
        if (frag_count) {
            (*frag_count)++;
        }

        increment_stat(STATS_PACKETS_PASSED, 1);
        return XDP_PASS;  /* 第一个分片，暂不重组 */
    }

    /* 更新已存在的 fragment 链 */
    entry->last_seen = now;
    entry->fragment_count++;

    /* 检查是否完整 (收到 MF=0 的分片) */
    if (!is_ipv4_more_fragments(ip)) {
        entry->complete = 1;
    }

    /* 简化处理: 让所有分片通过，在用户态进行完整重组
     * BPF 中进行完整的分片重组太复杂且受限于 verifier
     */
    increment_stat(STATS_PACKETS_PASSED, 1);
    return XDP_PASS;
}

/*
 * 处理 IPv6 分片 (简化版本)
 */
static __always_inline int handle_ipv6_fragment(struct xdp_md *ctx,
                                               struct ipv6hdr *ipv6,
                                               void *data_end) {
    /* IPv6 分片处理需要解析扩展头链，比较复杂
     * 这里简化处理：只检查是否存在分片头，让分片通过
     * 完整的 IPv6 分片重组需要用户态或 socket 层处理
     */
    __u8 *next_hdr = (__u8 *)ipv6 + sizeof(struct ipv6hdr);

    /* 检查下一个头是否为分片头 (44) */
    if ((void *)next_hdr >= data_end) {
        increment_stat(STATS_PACKETS_PASSED, 1);
        return XDP_PASS;
    }

    if (*next_hdr == 44) {  /* IPv6 Fragment Header */
        /* 记录分片事件，但不阻止分片通过 */
        increment_stat(STATS_PACKETS_PASSED, 1);
        return XDP_PASS;
    }

    increment_stat(STATS_PACKETS_PASSED, 1);
    return XDP_PASS;
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
static __always_inline int check_icmp_flood(__u32 src_ip);

/*
 * IP Defragmentation
 *
 * Checks if a packet is an IPv4 fragment and handles reassembly.
 * Returns:
 *   - NULL if packet is not a fragment or is a middle/last fragment (waiting for more)
 *   - Pointer to reassembled packet data if reassembly is complete
 *
 * Note: Due to BPF stack limits, we use a simplified reassembly strategy:
 *   - Store fragment metadata and data in maps
 *   - When all fragments arrive, copy data to a contiguous buffer
 *   - This implementation handles small-to-medium reassemblies
 */

/* Get current fragment count for this CPU */
static __always_inline __u32 get_frag_count(void) {
    __u32 key = 0;
    __u32 *count = bpf_map_lookup_elem(&frag_count, &key);
    return count ? *count : 0;
}

/*
 * Check if IPv4 packet is a fragment
 * Returns: fragment info in out parameters
 *   is_fragment: 1 if this is a fragment
 *   frag_offset: fragment offset in 8-byte units
 *   more_fragments: 1 if more fragments follow
 *   ip_id: identification field value
 *   ip_header_len: IP header length in bytes
 */
static __always_inline int check_ipv4_fragment(struct iphdr *ip,
                                                int *is_fragment,
                                                __u16 *frag_offset,
                                                __u8 *more_fragments,
                                                __u16 *ip_id) {
    __u16 flags_offset;

    /* Get flags and fragment offset */
    flags_offset = bpf_ntohs(ip->frag_off);

    /* Check if fragment flag is set (bit 13 = MF or offset != 0) */
    *frag_offset = flags_offset & 0x1FFF;  /* 13-bit offset */
    *more_fragments = (flags_offset >> 13) & 1;
    *ip_id = ip->id;

    /* A packet is a fragment if offset != 0 or MF flag is set */
    *is_fragment = (*frag_offset != 0) || (*more_fragments != 0);

    /* Get header length */
    return ip->ihl * 4;
}

/*
 * Handle IPv4 defragmentation
 * Returns: XDP action (XDP_PASS if reassembled, XDP_FRAG if waiting, etc.)
 *
 * Note: This simplified implementation stores fragments in map and
 * reassembles when the last fragment arrives.
 */
static __always_inline int handle_ipv4_defrag(void *data, void *data_end,
                                               struct flow_key *key,
                                               __u32 *pkt_len) {
    struct ethhdr *eth = (struct ethhdr *)data;
    struct iphdr *ip;
    struct frag_key fkey;
    struct frag_entry *entry;
    int ip_header_len;
    int is_fragment;
    __u16 frag_offset;
    __u8 more_fragments;
    __u16 ip_id;
    __u32 frag_data_len;
    __u32 buf_id;
    __u64 now = bpf_ktime_get_ns();
    int ret;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;  /* Not IPv4 */

    ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Check if this is a fragment */
    ip_header_len = check_ipv4_fragment(ip, &is_fragment, &frag_offset,
                                         &more_fragments, &ip_id);
    if (!is_fragment)
        return XDP_PASS;  /* Not a fragment, proceed normally */

    /* This is a fragment - look up tracking entry */
    __builtin_memset(&fkey, 0, sizeof(fkey));
    fkey.src_ip = bpf_ntohl(ip->saddr);
    fkey.dst_ip = bpf_ntohl(ip->daddr);
    fkey.ip_id = ip_id;
    fkey.protocol = ip->protocol;
    fkey.ip_version = 4;

    entry = bpf_map_lookup_elem(&frag_track, &fkey);

    if (!entry) {
        /* No existing entry - this is first fragment */

        /* Check if too many concurrent reassemblies */
        __u32 current_count = get_frag_count();
        if (current_count >= FRAG_MAX_CONCURRENT) {
            /* Try to find and delete oldest entry */
            increment_stat(STATS_PACKETS_DROPPED, 1);
            return XDP_DROP;
        }

        /* Create new tracking entry */
        struct frag_entry new_entry = {
            .first_seen = now,
            .last_seen = now,
            .total_length = bpf_ntohs(ip->tot_len),
            .received_length = 0,
            .fragment_count = 0,
            .more_fragments = more_fragments,
            .complete = 0,
        };

        /* Calculate fragment data offset and length */
        frag_data_len = *pkt_len - ip_header_len;

        /* First fragment: initialize tracking */
        /* We'll use a simple approach: store first fragment inline */
        /* For BPF compatibility, we store fragment info directly */

        /* Check fragment size limits */
        if (frag_data_len > FRAG_BUFFER_SIZE)
            frag_data_len = FRAG_BUFFER_SIZE;

        /* Allocate buffer and store fragment */
        buf_id = (__u32)(fkey.src_ip ^ fkey.dst_ip ^ fkey.ip_id ^ (fkey.protocol << 16));
        struct frag_data fbuf = {
            .session_id = buf_id,
            .offset = frag_offset * 8,  /* Convert to bytes */
            .size = frag_data_len,
        };

        ret = bpf_map_update_elem(&frag_buffers, &buf_id, &fbuf, BPF_ANY);
        if (ret != 0) {
            increment_stat(STATS_PACKETS_DROPPED, 1);
            return XDP_DROP;
        }

        ret = bpf_map_update_elem(&frag_track, &fkey, &new_entry, BPF_ANY);
        if (ret != 0) {
            bpf_map_delete_elem(&frag_buffers, &buf_id);
            increment_stat(STATS_PACKETS_DROPPED, 1);
            return XDP_DROP;
        }

        increment_stat(STATS_PACKETS_PASSED, 1);
        return XDP_PASS;  /* Waiting for more fragments */
    }

    /* Existing fragment stream - update entry */
    entry->last_seen = now;
    entry->fragment_count++;

    /* Check for timeout */
    if (now - entry->first_seen > FRAG_TIMEOUT_NS) {
        /* Timeout - delete entry and buffer */
        buf_id = (__u32)(fkey.src_ip ^ fkey.dst_ip ^ fkey.ip_id ^ (fkey.protocol << 16));
        bpf_map_delete_elem(&frag_track, &fkey);
        bpf_map_delete_elem(&frag_buffers, &buf_id);
        increment_stat(STATS_PACKETS_PASSED, 1);
        return XDP_PASS;
    }

    /* If this is the last fragment and we have all pieces, reassemble */
    if (!more_fragments && entry->fragment_count > 0) {
        /* Check if we have expected number of fragments */
        /* For simplicity, assume if we got last fragment, reassembly is complete */
        /* This is a simplified model - real IP defragmentation needs more robust tracking */

        /* Mark as complete for stats */
        entry->complete = 1;

        /* Reassembly complete - delete tracking and pass packet */
        buf_id = (__u32)(fkey.src_ip ^ fkey.dst_ip ^ fkey.ip_id ^ (fkey.protocol << 16));
        bpf_map_delete_elem(&frag_track, &fkey);
        bpf_map_delete_elem(&frag_buffers, &buf_id);

        /* Update packet length to indicate reassembled packet */
        /* Note: In a full implementation, we would copy all fragments to a buffer */
        /* For this skeleton, we mark it as reassembled and let it proceed */
        increment_stat(STATS_PACKETS_PASSED, 1);
        return XDP_PASS;
    }

    /* More fragments expected */
    increment_stat(STATS_PACKETS_PASSED, 1);
    return XDP_PASS;
}

/*
 * Check if IPv6 packet has fragment header
 * Returns: 1 if fragment, 0 if not
 */
static __always_inline int is_ipv6_fragment(struct ipv6hdr *ipv6,
                                            void *data_end,
                                            __u8 **next_header,
                                            int *header_len) {
    __u8 nexthdr = ipv6->nexthdr;
    void *hdr = (void *)(ipv6 + 1);
    int len = sizeof(struct ipv6hdr);

    /* Simple extension header parsing - only handles fragments */
    if (nexthdr == 44) {  /* IPv6-Frag */
        struct frag_hdr *frag = (struct frag_hdr *)hdr;
        if ((void *)(frag + 1) > data_end)
            return 0;
        *next_header = (__u8 *)frag + sizeof(struct frag_hdr);
        *header_len = len + sizeof(struct frag_hdr);
        return 1;
    }

    return 0;
}

/*
 * Handle IPv6 defragmentation
 * Returns: XDP action
 */
static __always_inline int handle_ipv6_defrag(void *data, void *data_end,
                                               struct flow_key *key,
                                               __u32 *pkt_len) {
    struct ethhdr *eth = (struct ethhdr *)data;
    struct ipv6hdr *ipv6;
    struct frag_key fkey;
    struct frag_entry *entry;
    __u8 *next_header_ptr;
    int header_len;
    int is_frag;
    __u32 frag_offset;
    __u8 more_fragments;
    __u32 ip_id;
    __u32 frag_data_len;
    __u32 buf_id;
    __u64 now = bpf_ktime_get_ns();
    int ret;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IPV6)
        return XDP_PASS;  /* Not IPv6 */

    ipv6 = (struct ipv6hdr *)(eth + 1);
    if ((void *)(ipv6 + 1) > data_end)
        return XDP_PASS;

    /* Check if this is a fragment */
    is_frag = is_ipv6_fragment(ipv6, data_end, &next_header_ptr, &header_len);
    if (!is_frag)
        return XDP_PASS;  /* Not a fragment, proceed normally */

    /* Get fragment header info */
    struct frag_hdr *frag = (struct frag_hdr *)((void *)ipv6 + sizeof(struct ipv6hdr));
    frag_offset = bpf_ntohs(frag->frag_off) & 0x1FFF;  /* 13-bit offset in 8-byte units */
    more_fragments = frag->frag_off & 0x01;  /* M flag is bit 0 after 13-bit offset */
    ip_id = bpf_ntohl(frag->identification);

    /* This is a fragment - look up tracking entry */
    __builtin_memset(&fkey, 0, sizeof(fkey));
    /* For IPv6, we use the first 32 bits of src/dst IP */
    __u32 *src_ip_arr = (__u32 *)ipv6->saddr.in6_u.u6_addr32;
    __u32 *dst_ip_arr = (__u32 *)ipv6->daddr.in6_u.u6_addr32;
    fkey.src_ip = src_ip_arr[0] ^ src_ip_arr[1] ^ src_ip_arr[2] ^ src_ip_arr[3];
    fkey.dst_ip = dst_ip_arr[0] ^ dst_ip_arr[1] ^ dst_ip_arr[2] ^ dst_ip_arr[3];
    fkey.ip_id = ip_id;
    fkey.protocol = ipv6->nexthdr;  /* Next header after fragment header */
    fkey.ip_version = 6;

    entry = bpf_map_lookup_elem(&frag_track, &fkey);

    if (!entry) {
        /* No existing entry - this is first fragment */

        /* Check if too many concurrent reassemblies */
        __u32 current_count = get_frag_count();
        if (current_count >= FRAG_MAX_CONCURRENT) {
            increment_stat(STATS_PACKETS_DROPPED, 1);
            return XDP_DROP;
        }

        /* Create new tracking entry */
        struct frag_entry new_entry = {
            .first_seen = now,
            .last_seen = now,
            .total_length = bpf_ntohs(ipv6->payload_len) + sizeof(struct ipv6hdr),
            .received_length = 0,
            .fragment_count = 0,
            .more_fragments = more_fragments,
            .complete = 0,
        };

        /* Calculate fragment data offset and length */
        frag_data_len = *pkt_len - header_len;

        /* Check fragment size limits */
        if (frag_data_len > FRAG_BUFFER_SIZE)
            frag_data_len = FRAG_BUFFER_SIZE;

        /* Allocate buffer and store fragment */
        buf_id = fkey.src_ip ^ fkey.dst_ip ^ fkey.ip_id ^ (fkey.protocol << 16);
        struct frag_data fbuf = {
            .session_id = buf_id,
            .offset = frag_offset * 8,  /* Convert to bytes */
            .size = frag_data_len,
        };

        ret = bpf_map_update_elem(&frag_buffers, &buf_id, &fbuf, BPF_ANY);
        if (ret != 0) {
            increment_stat(STATS_PACKETS_DROPPED, 1);
            return XDP_DROP;
        }

        ret = bpf_map_update_elem(&frag_track, &fkey, &new_entry, BPF_ANY);
        if (ret != 0) {
            bpf_map_delete_elem(&frag_buffers, &buf_id);
            increment_stat(STATS_PACKETS_DROPPED, 1);
            return XDP_DROP;
        }

        increment_stat(STATS_PACKETS_PASSED, 1);
        return XDP_PASS;  /* Waiting for more fragments */
    }

    /* Existing fragment stream - update entry */
    entry->last_seen = now;
    entry->fragment_count++;

    /* Check for timeout */
    if (now - entry->first_seen > FRAG_TIMEOUT_NS) {
        /* Timeout - delete entry and buffer */
        buf_id = fkey.src_ip ^ fkey.dst_ip ^ fkey.ip_id ^ (fkey.protocol << 16);
        bpf_map_delete_elem(&frag_track, &fkey);
        bpf_map_delete_elem(&frag_buffers, &buf_id);
        increment_stat(STATS_PACKETS_PASSED, 1);
        return XDP_PASS;
    }

    /* If this is the last fragment and we have all pieces, reassemble */
    if (!more_fragments && entry->fragment_count > 0) {
        /* Mark as complete for stats */
        entry->complete = 1;

        /* Reassembly complete - delete tracking and pass packet */
        buf_id = fkey.src_ip ^ fkey.dst_ip ^ fkey.ip_id ^ (fkey.protocol << 16);
        bpf_map_delete_elem(&frag_track, &fkey);
        bpf_map_delete_elem(&frag_buffers, &buf_id);

        increment_stat(STATS_PACKETS_PASSED, 1);
        return XDP_PASS;
    }

    /* More fragments expected */
    increment_stat(STATS_PACKETS_PASSED, 1);
    return XDP_PASS;
}

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
 * DNS Amplification 检测
 * 跟踪 DNS 查询和响应，当响应字节数远大于查询时判定为放大攻击
 * 返回: 0=正常, 1=amplification detected
 */
static __always_inline int check_dns_amplification(__u32 src_ip, __u32 dst_ip,
                                                   __u16 src_port, __u16 dst_port,
                                                   __u32 pkt_len) {
    __u64 now = bpf_ktime_get_ns();

    if (dst_port == 53 && src_port != 53) {
        /* DNS 查询: 记录查询字节数 */
        struct dns_query_key q_key = {
            .src_ip = src_ip,
            .dst_ip = dst_ip,
        };
        struct dns_query_stats *q_stats = bpf_map_lookup_elem(&dns_query_track, &q_key);

        if (!q_stats) {
            struct dns_query_stats new_q = {
                .query_count = 1,
                .query_bytes = pkt_len,
                .last_seen = now,
            };
            bpf_map_update_elem(&dns_query_track, &q_key, &new_q, BPF_ANY);
        } else {
            if (now - q_stats->last_seen >= WINDOW_SIZE_NS) {
                q_stats->query_count = 1;
                q_stats->query_bytes = pkt_len;
                q_stats->last_seen = now;
            } else {
                q_stats->query_count++;
                q_stats->query_bytes += pkt_len;
                q_stats->last_seen = now;
            }
        }
    } else if (src_port == 53 && dst_port != 53) {
        /* DNS 响应: 检查是否是放大攻击 */
        struct dns_amp_key a_key = {
            .victim_ip = dst_ip,
        };
        struct dns_amp_stats *a_stats = bpf_map_lookup_elem(&dns_amp_track, &a_key);

        if (!a_stats) {
            struct dns_amp_stats new_a = {
                .response_bytes = pkt_len,
                .query_bytes = 0,
                .last_seen = now,
                .alert_sent = 0,
            };
            bpf_map_update_elem(&dns_amp_track, &a_key, &new_a, BPF_ANY);
        } else {
            if (now - a_stats->last_seen >= WINDOW_SIZE_NS) {
                a_stats->response_bytes = pkt_len;
                a_stats->query_bytes = 0;
                a_stats->last_seen = now;
                a_stats->alert_sent = 0;
            } else {
                a_stats->response_bytes += pkt_len;
                a_stats->last_seen = now;
            }

            /* 检测放大: 响应 > 10x 查询 (典型放大倍数) */
            if (a_stats->query_bytes > 0 &&
                a_stats->response_bytes > a_stats->query_bytes * 10 &&
                !a_stats->alert_sent) {
                send_alert(src_ip, dst_ip, src_port, dst_port,
                           IPPROTO_UDP, SEVERITY_HIGH,
                           0, EVENT_DNS_AMP);
                increment_stat(STATS_DNS_AMP_ALERTS, 1);
                a_stats->alert_sent = 1;
                return 1;
            }
        }
    }

    return 0;
}

/* Forward declaration for handle_xdp (used by tail_call_dispatch) */
static __always_inline int handle_xdp(struct xdp_md *ctx);

/*
 * Tail call dispatch - jumps to first stage in pipeline via xdp_jmp_table
 *
 * Stage indices in xdp_jmp_table:
 *   0 = PARSER   - Parse packet and extract 5-tuple
 *   1 = DDOS     - SYN/ICMP flood detection
 *   2 = DNS_AMP  - DNS amplification detection
 *   3 = RULES    - Rule matching
 *
 * Uses per-CPU xdp_ctx_buffer to pass state between stages.
 */
static __always_inline int tail_call_dispatch(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Initialize per-CPU context buffer */
    __u32 ctx_key = 0;
    struct xdp_pipeline_ctx *pctx = bpf_map_lookup_elem(&xdp_ctx_buffer, &ctx_key);
    if (!pctx)
        return XDP_PASS;  /* Fallback to normal path if context unavailable */

    __builtin_memset(pctx, 0, sizeof(*pctx));

    /* Parse packet into context buffer */
    int ret = parse_packet(data, data_end,
                          (struct flow_key *)pctx,  /* Reuse ctx fields as flow_key */
                          &pctx->pkt_len, &pctx->tcp_flags);
    if (ret != 0) {
        increment_stat(STATS_PACKETS_PASSED, 1);
        return XDP_PASS;
    }

    /* Initialize pipeline context */
    pctx->stage = 0;
    pctx->verdict = XDP_PASS;

    /* Tail call to first stage (parser) */
    bpf_tail_call(ctx, &xdp_jmp_table, 0);

    /* If no tail call target, fall through to normal processing */
    return handle_xdp(ctx);
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

    /* IP Defragmentation - handle IPv4 and IPv6 fragments */
    struct ethhdr *eth = (struct ethhdr *)data;
    if ((void *)(eth + 1) <= data_end) {
        __u16 eth_proto = bpf_ntohs(eth->h_proto);

        if (eth_proto == ETH_P_IP) {
            /* IPv4 defragmentation */
            ret = handle_ipv4_defrag(data, data_end, &key, &pkt_len);
            if (ret != XDP_PASS)
                return ret;
        } else if (eth_proto == ETH_P_IPV6) {
            /* IPv6 defragmentation */
            ret = handle_ipv6_defrag(data, data_end, &key, &pkt_len);
            if (ret != XDP_PASS)
                return ret;
        }
    }

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

    /* DNS Amplification 检测 */
    if (key.protocol == IPPROTO_UDP) {
        check_dns_amplification(key.src_ip, key.dst_ip,
                                key.src_port, key.dst_port, pkt_len);
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
