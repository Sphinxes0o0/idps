// SPDX-License-Identifier: GPL-2.0
/*
 * nids_bpf_events.c - Event sending functions for NIDS eBPF
 *
 * This file contains functions for sending alerts and events via BPF ringbuf.
 */

#include "nids_common.h"

/*
 * Rate limiting check for alerts
 * Returns: 0 = send alert allowed, 1 = rate limited
 */
static __always_inline int check_alert_rate_limit(__u32 src_ip, __u8 event_type) {
    struct alert_rate_key r_key = {
        .src_ip = src_ip,
        .event_type = event_type,
    };
    struct alert_rate_value *r_val = bpf_map_lookup_elem(&alert_rate_limit, &r_key);
    __u64 now = bpf_ktime_get_ns();
    __u64 min_interval = 1000000000ULL;  /* 1 second minimum between alerts */
    __u64 window_reset = 10000000000ULL;  /* 10 seconds - reset count after this */

    if (!r_val) {
        /* First alert from this source/type */
        struct alert_rate_value new_val = {
            .last_alert_time = now,
            .alert_count = 1,
        };
        bpf_map_update_elem(&alert_rate_limit, &r_key, &new_val, BPF_ANY);
        return 0;
    }

    /* Check if window expired - reset count */
    if (now - r_val->last_alert_time > window_reset) {
        r_val->last_alert_time = now;
        r_val->alert_count = 1;
        return 0;
    }

    /* Check if enough time has passed since last alert */
    if (now - r_val->last_alert_time < min_interval) {
        return 1;  /* Rate limited */
    }

    /* Update rate limit entry */
    r_val->last_alert_time = now;
    r_val->alert_count++;
    return 0;
}

/*
 * 发送告警事件到 Ringbuf
 * 零拷贝路径
 */
static __always_inline int send_alert(__u32 src_ip, __u32 dst_ip,
                                       __u16 src_port, __u16 dst_port,
                                       __u8 proto, __u8 severity,
                                       __u32 rule_id, __u8 event_type) {
    /* Rate limiting for DDoS-type alerts */
    if (event_type >= EVENT_SYN_FLOOD && event_type <= EVENT_RST_FLOOD) {
        if (check_alert_rate_limit(src_ip, event_type)) {
            return -1;  /* Rate limited, drop */
        }
    }

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
 * N-01: 发送快速告警事件到专用 Ringbuf
 * 用于 XDP 层高优先级告警的低延迟传递
 * 与 send_alert 分离，使用独立的 fast_alerts ringbuf
 *
 * @param event_type  事件类型
 * @param key         流 key (5-tuple)
 * @param severity    严重级别
 * @param rule_id     规则 ID (可为 0)
 */
static __always_inline void send_fast_alert(__u32 event_type, struct flow_key *key,
                                           __u8 severity, __u32 rule_id) {
    struct fast_alert_event *event = bpf_ringbuf_reserve(&fast_alerts,
                                                         sizeof(*event), 0);
    if (!event) {
        /* Ringbuf 已满，仅计数不阻塞主路径 */
        increment_stat(STATS_PACKETS_DROPPED, 1);
        return;
    }

    event->event_type = event_type;
    event->rule_id = rule_id;
    event->src_ip = key->src_ip;
    event->dst_ip = key->dst_ip;
    event->src_port = key->src_port;
    event->dst_port = key->dst_port;
    event->protocol = key->protocol;
    event->severity = severity;
    event->timestamp = bpf_ktime_get_ns();

    bpf_ringbuf_submit(event, 0);
}
