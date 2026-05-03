// Internal header for BPF modules
#ifndef NIDS_BPF_INTERNAL_H
#define NIDS_BPF_INTERNAL_H

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
 * SPLIT: Attack detection functions moved to nids_bpf_attack.c
 * The following helpers are still needed by attack module:
 */

/* Forward declarations for helper functions used by attack detection */
static __always_inline void increment_stat(__u32 index, __u64 value);
static __always_inline int send_alert(__u32 src_ip, __u32 dst_ip,
                                      __u16 src_port, __u16 dst_port,
                                      __u8 proto, __u8 severity,
                                      __u32 rule_id, __u8 event_type);
static __always_inline void normalize_flow_key(struct flow_key *key);

#endif /* NIDS_BPF_INTERNAL_H */
