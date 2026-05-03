// SPDX-License-Identifier: GPL-2.0
/*
 * nids_bpf_helpers.c - Helper functions for XDP eBPF program
 *
 * 代码拆分说明:
 * 此文件包含从 nids_bpf.c 提取的通用 helper 函数,实现代码组织上的分离。
 * 由于 BPF verifier 要求所有代码在单一对象文件中,实际编译仍通过 nids_bpf.c
 * 编译,此文件仅作为占位符用于代码文档和未来重构参考。
 *
 * 拆分计划:
 * - increment_stat:     统计计数器递增 (nids_bpf.c lines 40-45)
 * - get_config_drop_enabled: 获取配置 (nids_bpf.c lines 50-56)
 * - check_alert_rate_limit: 告警 rate limiting (nids_bpf.c lines 62-98)
 */

#include "nids_common.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
 * 递增统计计数器
 * 使用 per-CPU array,无需锁
 * Note: 此函数在 nids_bpf.c 中定义为 static __always_inline
 */
static __always_inline void increment_stat(__u32 index, __u64 value) {
    __u32 key = index;
    __u64 *count = bpf_map_lookup_elem(&stats, &key);
    if (count)
        __sync_fetch_and_add(count, value);
}

/*
 * 获取配置值 (从 config map)
 * 返回: drop_enabled 配置值,默认为 0 (关闭)
 * Note: 此函数在 nids_bpf.c 中定义为 static __always_inline
 */
static __always_inline __u32 get_config_drop_enabled(void) {
    __u32 key = 0;
    struct config_entry *cfg = bpf_map_lookup_elem(&config, &key);
    if (cfg)
        return cfg->drop_enabled;
    return 0;  /* 默认关闭 drop */
}

/*
 * Rate limiting check for alerts
 * @src_ip: 源 IP 地址
 * @event_type: 事件类型
 * Returns: 0 = send alert allowed, 1 = rate limited
 *
 * 算法:
 * - 使用 alert_rate_limit map 跟踪每个 (src_ip, event_type) 的告警
 * - min_interval: 同一来源同一类型告警的最小间隔 (1 second)
 * - window_reset: 窗口重置时间 (10 seconds),超过此时间计数器重置
 *
 * Note: 此函数在 nids_bpf.c 中定义为 static __always_inline
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
