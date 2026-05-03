// SPDX-License-Identifier: GPL-2.0
/*
 * nids_bpf_defrag.c - IP Defragmentation Module
 *
 * This module handles IPv4 and IPv6 packet defragmentation for XDP/eBPF.
 *
 * Functions:
 *   - compute_frag_buf_id(): Generate buffer ID for fragment tracking
 *   - check_ipv4_fragment(): Check if IPv4 packet is a fragment
 *   - handle_ipv4_defrag(): Handle IPv4 defragmentation
 *   - is_ipv6_fragment(): Check if IPv6 packet has fragment header
 *   - handle_ipv6_defrag(): Handle IPv6 defragmentation
 *
 * Dependencies:
 *   - nids_common.h: Shared structs, maps, constants
 *   - nids_bpf_internal.h: Internal BPF definitions
 *
 * Usage:
 *   Include this file in nids_bpf.c or compile separately with clang -target bpf
 */

#include "nids_common.h"
#include "nids_bpf_internal.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/ipv6.h>

/*
 * TODO: Split this module into separate files:
 *   - nids_bpf_defrag_ipv4.c: IPv4 defragmentation only
 *   - nids_bpf_defrag_ipv6.c: IPv6 defragmentation only
 *   - nids_bpf_defrag_common.c: Shared compute_frag_buf_id() and helpers
 */

/*
 * compute_frag_buf_id - Generate a unique buffer ID for fragment tracking
 *
 * Uses ror32 hash for better distribution to reduce collisions
 */
static __always_inline __u32 compute_frag_buf_id(struct frag_key *fkey) {
    /* Use ror32 hash for better distribution to reduce collisions */
    __u32 src = (__u32)((fkey->src_ip << 15) | (fkey->src_ip >> 17));
    __u32 dst = (__u32)((fkey->dst_ip << 7) | (fkey->dst_ip >> 25));
    __u32 id = (__u32)(fkey->ip_id * 0x45d9f3b);
    __u32 proto = (__u32)((fkey->protocol << 16) | (fkey->protocol >> 16));
    return src ^ dst ^ id ^ proto;
}

/*
 * check_ipv4_fragment - Check if IPv4 packet is a fragment
 *
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
 * handle_ipv4_defrag - Handle IPv4 defragmentation
 *
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
        /* LRU hash will handle eviction when capacity is reached */

        /* Calculate fragment data offset and length */
        frag_data_len = *pkt_len - ip_header_len;
        if (frag_data_len > FRAG_BUFFER_SIZE)
            frag_data_len = FRAG_BUFFER_SIZE;

        /* Allocate buffer ID */
        buf_id = compute_frag_buf_id(&fkey);
        /* Add fragment index to make unique buf_id for each fragment */
        buf_id ^= (frag_offset << 16);

        /* Store fragment data in frag_buffers */
        struct frag_data fbuf = {
            .session_id = buf_id,
            .offset = (__u16)(frag_offset * 8),
            .size = (__u16)frag_data_len,
        };

        ret = bpf_map_update_elem(&frag_buffers, &buf_id, &fbuf, BPF_ANY);
        if (ret != 0) {
            increment_stat(STATS_PACKETS_DROPPED, 1);
            return XDP_DROP;
        }

        /* Create new tracking entry */
        struct frag_entry new_entry = {
            .first_seen = now,
            .last_seen = now,
            .total_length = bpf_ntohs(ip->tot_len),
            .ip_id = ip_id,
            .frag_count = 1,
            .complete = 0,
            .more_fragments = more_fragments,
            .ip_version = 4,
            .src_ip = bpf_ntohl(ip->saddr),
            .dst_ip = bpf_ntohl(ip->daddr),
            .src_port = 0,
            .dst_port = 0,
            .protocol = ip->protocol,
        };
        new_entry.frags[0].buf_id = buf_id;
        new_entry.frags[0].offset = (__u16)(frag_offset * 8);
        new_entry.frags[0].size = (__u16)frag_data_len;

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

    /* Check for timeout */
    if (now - entry->first_seen > FRAG_TIMEOUT_NS) {
        /* Timeout - delete all fragment buffers */
        for (__u8 i = 0; i < entry->frag_count; i++) {
            bpf_map_delete_elem(&frag_buffers, &entry->frags[i].buf_id);
        }
        bpf_map_delete_elem(&frag_track, &fkey);
        increment_stat(STATS_PACKETS_PASSED, 1);
        return XDP_PASS;
    }

    /* Store this fragment */
    if (entry->frag_count < MAX_FRAGMENTS) {
        /* Calculate fragment data */
        frag_data_len = *pkt_len - ip_header_len;
        if (frag_data_len > FRAG_BUFFER_SIZE)
            frag_data_len = FRAG_BUFFER_SIZE;

        /* Allocate unique buffer ID */
        buf_id = compute_frag_buf_id(&fkey);
        buf_id ^= ((frag_offset << 16) | (entry->frag_count << 8));

        /* Store fragment data */
        struct frag_data fbuf = {
            .session_id = buf_id,
            .offset = (__u16)(frag_offset * 8),
            .size = (__u16)frag_data_len,
        };
        bpf_map_update_elem(&frag_buffers, &buf_id, &fbuf, BPF_ANY);

        /* Add to fragment array */
        entry->frags[entry->frag_count].buf_id = buf_id;
        entry->frags[entry->frag_count].offset = (__u16)(frag_offset * 8);
        entry->frags[entry->frag_count].size = (__u16)frag_data_len;
        entry->frag_count++;
    }

    /* If this is the last fragment, notify user-space for reassembly */
    if (!more_fragments) {
        entry->complete = 1;
        entry->total_length = (__u32)(frag_offset * 8 + *pkt_len - ip_header_len);

        /* Send reassembly notification via ringbuf */
        send_alert(entry->src_ip, entry->dst_ip,
                   entry->src_port, entry->dst_port,
                   entry->protocol, SEVERITY_INFO,
                   entry->frag_count, EVENT_FRAG_REASSEMBLE);

        /* Clean up - in production, user-space would do the reassembly */
        for (__u8 i = 0; i < entry->frag_count; i++) {
            bpf_map_delete_elem(&frag_buffers, &entry->frags[i].buf_id);
        }
        bpf_map_delete_elem(&frag_track, &fkey);
    }

    increment_stat(STATS_PACKETS_PASSED, 1);
    return XDP_PASS;
}

/*
 * is_ipv6_fragment - Check if IPv6 packet has fragment header
 *
 * Returns: 1 if fragment, 0 if not
 * Sets *next_header to the protocol after fragment header
 * Sets *header_len to total length of all extension headers before fragment
 */
static __always_inline int is_ipv6_fragment(struct ipv6hdr *ipv6,
                                            void *data_end,
                                            __u8 **next_header,
                                            int *header_len) {
    __u8 nexthdr = ipv6->nexthdr;
    void *hdr = (void *)(ipv6 + 1);
    int total_len = sizeof(struct ipv6hdr);

    /* Traverse extension header chain */
    while (nexthdr == 0 ||   /* Hop-by-Hop Options */
           nexthdr == 43 ||  /* Routing Header */
           nexthdr == 44 ||  /* Fragment Header */
           nexthdr == 51 ||  /* AH Header */
           nexthdr == 60) {  /* Destination Options */

        if (nexthdr == 44) {  /* Fragment */
            struct frag_hdr *frag = (struct frag_hdr *)hdr;
            if ((void *)(frag + 1) > data_end)
                return 0;
            *next_header = (__u8 *)frag + sizeof(struct frag_hdr);
            *header_len = total_len + sizeof(struct frag_hdr);
            return 1;
        }

        /* Skip other extension headers */
        struct ipv6_opt_hdr *opt = (struct ipv6_opt_hdr *)hdr;
        if ((void *)(opt + 1) > data_end)
            return 0;

        nexthdr = opt->nexthdr;
        __u8 ext_len = (opt->hdrlen + 1) * 8;
        hdr = (__u8 *)hdr + ext_len;
        total_len += ext_len;

        if ((void *)hdr >= data_end)
            return 0;
    }

    return 0;
}

/*
 * handle_ipv6_defrag - Handle IPv6 defragmentation
 *
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
    more_fragments = (bpf_ntohs(frag->frag_off) >> 15) & 1;  /* M flag is bit 15 */
    ip_id = bpf_ntohl(frag->identification);

    /* This is a fragment - look up tracking entry */
    __builtin_memset(&fkey, 0, sizeof(fkey));
    /* For IPv6, fold 128-bit address into 32-bit using ror32-based hash */
    __u32 *src_ip_arr = (__u32 *)ipv6->saddr.in6_u.u6_addr32;
    __u32 *dst_ip_arr = (__u32 *)ipv6->daddr.in6_u.u6_addr32;
    fkey.src_ip = src_ip_arr[0] ^ (src_ip_arr[1] << 12) ^ (src_ip_arr[2] >> 12) ^ (src_ip_arr[3] << 6);
    fkey.dst_ip = dst_ip_arr[0] ^ (dst_ip_arr[1] << 12) ^ (dst_ip_arr[2] >> 12) ^ (dst_ip_arr[3] << 6);
    fkey.ip_id = ip_id;
    fkey.protocol = frag->nexthdr;  /* Actual transport protocol from fragment header */
    fkey.ip_version = 6;

    entry = bpf_map_lookup_elem(&frag_track, &fkey);

    if (!entry) {
        /* No existing entry - this is first fragment */
        /* LRU hash will handle eviction when capacity is reached */

        /* Calculate fragment data offset and length */
        frag_data_len = *pkt_len - header_len;
        if (frag_data_len > FRAG_BUFFER_SIZE)
            frag_data_len = FRAG_BUFFER_SIZE;

        /* Allocate unique buffer ID */
        buf_id = compute_frag_buf_id(&fkey);
        buf_id ^= (frag_offset << 16);

        /* Store fragment data in frag_buffers */
        struct frag_data fbuf = {
            .session_id = buf_id,
            .offset = (__u16)(frag_offset * 8),
            .size = (__u16)frag_data_len,
        };

        ret = bpf_map_update_elem(&frag_buffers, &buf_id, &fbuf, BPF_ANY);
        if (ret != 0) {
            increment_stat(STATS_PACKETS_DROPPED, 1);
            return XDP_DROP;
        }

        /* Create new tracking entry */
        struct frag_entry new_entry = {
            .first_seen = now,
            .last_seen = now,
            .total_length = bpf_ntohs(ipv6->payload_len) + sizeof(struct ipv6hdr),
            .ip_id = ip_id,
            .frag_count = 1,
            .complete = 0,
            .more_fragments = more_fragments,
            .ip_version = 6,
            .src_ip = src_ip_arr[0],
            .dst_ip = dst_ip_arr[0],
            .src_port = 0,
            .dst_port = 0,
            .protocol = frag->nexthdr,  /* Actual transport protocol from fragment header */
        };
        new_entry.frags[0].buf_id = buf_id;
        new_entry.frags[0].offset = (__u16)(frag_offset * 8);
        new_entry.frags[0].size = (__u16)frag_data_len;

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

    /* Check for timeout */
    if (now - entry->first_seen > FRAG_TIMEOUT_NS) {
        /* Timeout - delete all fragment buffers */
        for (__u8 i = 0; i < entry->frag_count; i++) {
            bpf_map_delete_elem(&frag_buffers, &entry->frags[i].buf_id);
        }
        bpf_map_delete_elem(&frag_track, &fkey);
        increment_stat(STATS_PACKETS_PASSED, 1);
        return XDP_PASS;
    }

    /* Store this fragment */
    if (entry->frag_count < MAX_FRAGMENTS) {
        /* Calculate fragment data */
        frag_data_len = *pkt_len - header_len;
        if (frag_data_len > FRAG_BUFFER_SIZE)
            frag_data_len = FRAG_BUFFER_SIZE;

        /* Allocate unique buffer ID */
        buf_id = compute_frag_buf_id(&fkey);
        buf_id ^= ((frag_offset << 16) | (entry->frag_count << 8));

        /* Store fragment data */
        struct frag_data fbuf = {
            .session_id = buf_id,
            .offset = (__u16)(frag_offset * 8),
            .size = (__u16)frag_data_len,
        };
        bpf_map_update_elem(&frag_buffers, &buf_id, &fbuf, BPF_ANY);

        /* Add to fragment array */
        entry->frags[entry->frag_count].buf_id = buf_id;
        entry->frags[entry->frag_count].offset = (__u16)(frag_offset * 8);
        entry->frags[entry->frag_count].size = (__u16)frag_data_len;
        entry->frag_count++;
    }

    /* If this is the last fragment, notify user-space for reassembly */
    if (!more_fragments) {
        entry->complete = 1;
        entry->total_length = (__u32)(frag_offset * 8 + *pkt_len - header_len);

        /* Send reassembly notification via ringbuf */
        send_alert(entry->src_ip, entry->dst_ip,
                   entry->src_port, entry->dst_port,
                   entry->protocol, SEVERITY_INFO,
                   entry->frag_count, EVENT_FRAG_REASSEMBLE);

        /* Clean up - in production, user-space would do the reassembly */
        for (__u8 i = 0; i < entry->frag_count; i++) {
            bpf_map_delete_elem(&frag_buffers, &entry->frags[i].buf_id);
        }
        bpf_map_delete_elem(&frag_track, &fkey);
    }

    increment_stat(STATS_PACKETS_PASSED, 1);
    return XDP_PASS;
}

/*
 * Forward declarations for external dependencies
 * These functions are defined in nids_bpf.c or other modules
 */
extern struct stats {
    __u64 packets_total;
    __u64 packets_dropped;
    __u64 packets_passed;
    __u64 new_flows;
    __u64 ddos_alerts;
} *stats;

/* Maps defined in nids_common.h */
extern struct bpf_map_def frag_track;
extern struct bpf_map_def frag_buffers;

/* Constants */
#define FRAG_BUFFER_SIZE 65535
#define FRAG_TIMEOUT_NS 30000000000ULL
#define MAX_FRAGMENTS 16
