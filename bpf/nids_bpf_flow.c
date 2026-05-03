// SPDX-License-Identifier: GPL-2.0
/*
 * nids_bpf_flow.c - Flow tracking module
 *
 * This file was split from nids_bpf.c
 * Functions: normalize_flow_key, update_flow_stats, match_simple_rules, port_match
 */

#include "nids_common.h"
#include "nids_bpf_internal.h"

/*
 * Flow tracking functions
 */

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

        /* 找到匹配！仅对单端口规则更新索引（范围规则无法索引） */
        if (rule->dst_port_max == 0) {
            bpf_map_update_elem(&rule_index, &idx_key, &key, BPF_ANY);
        }

        /* 返回 rule_id + dpi_needed (bit 31) + action (bit 30) */
        return rule->rule_id | ((__u32)rule->dpi_needed << 31) | ((__u32)rule->action << 30);
    }

    return 0;  /* 无匹配 */
}
