// SPDX-License-Identifier: MIT
/*
 * nids_bpf_attack.c - Attack detection functions
 *
 * Extracted attack detection modules:
 *   - TCP flood detection (SYN, ACK, FIN, RST)
 *   - ICMP flood detection
 *   - DNS amplification detection
 *   - Port scan detection
 */

#include "nids_bpf_internal.h"
#include "nids_common.h"

/*
 * TCP RST flood detection
 * Checks TCP RST-only packets (flags == 0x04, no SYN/FIN/ACK/PSH)
 * Tracks RST packet rate per flow
 * Returns: 0=normal, 1=flood detected
 */
static __always_inline int check_rst_flood(__u32 src_ip, __u32 dst_ip,
                                          __u16 src_port, __u16 dst_port,
                                          __u8 tcp_flags) {
    /* Only detect pure RST packets - flags == 0x04 (RST only, no SYN/FIN/ACK/PSH/URG) */
    if (tcp_flags != 0x04) {
        return 0;
    }

    struct flow_key r_key = {
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
        .protocol = IPPROTO_TCP,
    };
    normalize_flow_key(&r_key);

    struct src_track *track = bpf_map_lookup_elem(&tcp_rst_flood_track, &r_key);
    __u64 now = bpf_ktime_get_ns();

    if (!track) {
        /* New entry */
        struct src_track new_track = {
            .packet_count = 1,
            .last_seen = now,
            .window_start = now,
            .flags = 0,
        };
        bpf_map_update_elem(&tcp_rst_flood_track, &r_key, &new_track, BPF_ANY);
        return 0;
    }

    /* Check for timeout - delete stale entry */
    if (now - track->last_seen > WINDOW_SIZE_NS * 2) {
        bpf_map_delete_elem(&tcp_rst_flood_track, &r_key);
        struct src_track new_track = {
            .packet_count = 1,
            .last_seen = now,
            .window_start = now,
            .flags = 0,
        };
        bpf_map_update_elem(&tcp_rst_flood_track, &r_key, &new_track, BPF_ANY);
        return 0;
    }

    /* Update statistics */
    if (now - track->window_start >= WINDOW_SIZE_NS) {
        /* Reset window */
        track->window_start = now;
        track->packet_count = 1;
    } else {
        track->packet_count++;
    }
    track->last_seen = now;

    /* Check threshold */
    if (track->packet_count >= ddos_threshold) {
        /* Send RST flood alert */
        send_alert(src_ip, dst_ip, src_port, dst_port,
                   IPPROTO_TCP, SEVERITY_HIGH,
                   0, EVENT_RST_FLOOD);
        increment_stat(STATS_RST_FLOOD_ALERTS, 1);
        return 1;
    }

    return 0;
}

/*
 * SYN flood detection
 * Checks TCP SYN packets, detects flood when source sends many SYNs without response
 * Returns: 0=normal, 1=flood detected
 */
static __always_inline int check_syn_flood(__u32 src_ip, __u32 dst_ip,
                                          __u16 dst_port, __u8 tcp_flags) {
    /* Only detect pure SYN flood - SYN flag must be set, no other flags (except ECN) */
    if (!(tcp_flags & 0x02)) {
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
        /* New entry */
        struct src_track new_track = {
            .packet_count = 1,
            .last_seen = now,
            .window_start = now,
            .flags = 0,
        };
        bpf_map_update_elem(&syn_flood_track, &s_key, &new_track, BPF_ANY);
        return 0;
    }

    /* Check for timeout - delete stale entry */
    if (now - track->last_seen > WINDOW_SIZE_NS * 2) {
        bpf_map_delete_elem(&syn_flood_track, &s_key);
        struct src_track new_track = {
            .packet_count = 1,
            .last_seen = now,
            .window_start = now,
            .flags = 0,
        };
        bpf_map_update_elem(&syn_flood_track, &s_key, &new_track, BPF_ANY);
        return 0;
    }

    /* Update statistics */
    if (now - track->window_start >= WINDOW_SIZE_NS) {
        /* Reset window */
        track->window_start = now;
        track->packet_count = 1;
    } else {
        track->packet_count++;
    }
    track->last_seen = now;

    /* Check threshold */
    if (track->packet_count >= ddos_threshold) {
        /* Send SYN flood alert */
        send_alert(src_ip, dst_ip, 0, dst_port,
                   IPPROTO_TCP, SEVERITY_HIGH,
                   0, EVENT_SYN_FLOOD);
        increment_stat(STATS_SYN_FLOOD_ALERTS, 1);
        return 1;
    }

    return 0;
}

/*
 * TCP ACK Flood detection
 * Checks TCP ACK-only packets (flags == 0x10, no SYN/FIN/RST/PSH)
 * Tracks ACK packet rate per flow
 * Returns: 0=normal, 1=flood detected
 */
static __always_inline int check_ack_flood(__u32 src_ip, __u32 dst_ip,
                                          __u16 src_port, __u16 dst_port,
                                          __u8 tcp_flags) {
    /* Only detect pure ACK packets - flags == 0x10 (ACK only, no SYN/FIN/RST/PSH/URG) */
    if (tcp_flags != 0x10) {
        return 0;
    }

    struct flow_key a_key = {
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
        .protocol = IPPROTO_TCP,
    };
    normalize_flow_key(&a_key);

    struct src_track *track = bpf_map_lookup_elem(&tcp_ack_flood_track, &a_key);
    __u64 now = bpf_ktime_get_ns();

    if (!track) {
        /* New entry */
        struct src_track new_track = {
            .packet_count = 1,
            .last_seen = now,
            .window_start = now,
            .flags = 0,
        };
        bpf_map_update_elem(&tcp_ack_flood_track, &a_key, &new_track, BPF_ANY);
        return 0;
    }

    /* Check for timeout - delete stale entry */
    if (now - track->last_seen > WINDOW_SIZE_NS * 2) {
        bpf_map_delete_elem(&tcp_ack_flood_track, &a_key);
        struct src_track new_track = {
            .packet_count = 1,
            .last_seen = now,
            .window_start = now,
            .flags = 0,
        };
        bpf_map_update_elem(&tcp_ack_flood_track, &a_key, &new_track, BPF_ANY);
        return 0;
    }

    /* Update statistics */
    if (now - track->window_start >= WINDOW_SIZE_NS) {
        /* Reset window */
        track->window_start = now;
        track->packet_count = 1;
    } else {
        track->packet_count++;
    }
    track->last_seen = now;

    /* Check threshold */
    if (track->packet_count >= ddos_threshold) {
        /* Send ACK flood alert */
        send_alert(src_ip, dst_ip, src_port, dst_port,
                   IPPROTO_TCP, SEVERITY_HIGH,
                   0, EVENT_ACK_FLOOD);
        increment_stat(STATS_ACK_FLOOD_ALERTS, 1);
        return 1;
    }

    return 0;
}

/*
 * TCP FIN flood detection
 * Checks TCP FIN-only packets (flags == 0x01, no SYN/ACK/RST/PSH)
 * Tracks FIN packet rate per flow
 * Returns: 0=normal, 1=flood detected
 */
static __always_inline int check_fin_flood(__u32 src_ip, __u32 dst_ip,
                                          __u16 src_port, __u16 dst_port,
                                          __u8 tcp_flags) {
    /* Only detect pure FIN packets - flags == 0x01 (FIN only, no SYN/ACK/RST/PSH/URG) */
    if (tcp_flags != 0x01) {
        return 0;
    }

    struct flow_key f_key = {
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
        .protocol = IPPROTO_TCP,
    };
    normalize_flow_key(&f_key);

    struct src_track *track = bpf_map_lookup_elem(&tcp_fin_flood_track, &f_key);
    __u64 now = bpf_ktime_get_ns();

    if (!track) {
        /* New entry */
        struct src_track new_track = {
            .packet_count = 1,
            .last_seen = now,
            .window_start = now,
            .flags = 0,
        };
        bpf_map_update_elem(&tcp_fin_flood_track, &f_key, &new_track, BPF_ANY);
        return 0;
    }

    /* Check for timeout - delete stale entry */
    if (now - track->last_seen > WINDOW_SIZE_NS * 2) {
        bpf_map_delete_elem(&tcp_fin_flood_track, &f_key);
        struct src_track new_track = {
            .packet_count = 1,
            .last_seen = now,
            .window_start = now,
            .flags = 0,
        };
        bpf_map_update_elem(&tcp_fin_flood_track, &f_key, &new_track, BPF_ANY);
        return 0;
    }

    /* Update statistics */
    if (now - track->window_start >= WINDOW_SIZE_NS) {
        /* Reset window */
        track->window_start = now;
        track->packet_count = 1;
    } else {
        track->packet_count++;
    }
    track->last_seen = now;

    /* Check threshold */
    if (track->packet_count >= ddos_threshold) {
        /* Send FIN flood alert */
        send_alert(src_ip, dst_ip, src_port, dst_port,
                   IPPROTO_TCP, SEVERITY_HIGH,
                   0, EVENT_FIN_FLOOD);
        increment_stat(STATS_FIN_FLOOD_ALERTS, 1);
        return 1;
    }

    return 0;
}

/*
 * ICMP flood detection
 * Tracks ICMP packet rate per source IP
 * Returns: 0=normal, 1=flood detected
 */
static __always_inline int check_icmp_flood(__u32 src_ip) {
    struct icmp_flood_key i_key = {
        .src_ip = src_ip,
    };
    struct src_track *track = bpf_map_lookup_elem(&icmp_flood_track, &i_key);
    __u64 now = bpf_ktime_get_ns();

    if (!track) {
        /* New entry */
        struct src_track new_track = {
            .packet_count = 1,
            .last_seen = now,
            .window_start = now,
            .flags = 0,
        };
        bpf_map_update_elem(&icmp_flood_track, &i_key, &new_track, BPF_ANY);
        return 0;
    }

    /* Check for timeout - delete stale entry */
    if (now - track->last_seen > WINDOW_SIZE_NS * 2) {
        bpf_map_delete_elem(&icmp_flood_track, &i_key);
        struct src_track new_track = {
            .packet_count = 1,
            .last_seen = now,
            .window_start = now,
            .flags = 0,
        };
        bpf_map_update_elem(&icmp_flood_track, &i_key, &new_track, BPF_ANY);
        return 0;
    }

    /* Update statistics */
    if (now - track->window_start >= WINDOW_SIZE_NS) {
        /* Reset window */
        track->window_start = now;
        track->packet_count = 1;
    } else {
        track->packet_count++;
    }
    track->last_seen = now;

    /* Check threshold (ICMP flood threshold can be lower) */
    if (track->packet_count >= ddos_threshold / 10) {
        /* Send ICMP flood alert (threshold is 1/10 of DDoS) */
        send_alert(src_ip, 0, 0, 0,
                   IPPROTO_ICMP, SEVERITY_MEDIUM,
                   0, EVENT_ICMP_FLOOD);
        increment_stat(STATS_ICMP_FLOOD_ALERTS, 1);
        return 1;
    }

    return 0;
}

/*
 * DNS Amplification detection
 * Tracks DNS queries and responses, detects amplification when response bytes >> query bytes
 * Returns: 0=normal, 1=amplification detected
 */
static __always_inline int check_dns_amplification(__u32 src_ip, __u32 dst_ip,
                                                   __u16 src_port, __u16 dst_port,
                                                   __u32 pkt_len) {
    __u64 now = bpf_ktime_get_ns();
    __u32 key = 0;
    struct config_entry *cfg = bpf_map_lookup_elem(&config, &key);

    if (dst_port == 53 && src_port != 53) {
        /* DNS query: attacker->DNS server (victim IP is spoofed as src_ip)
         * Use victim_ip (src_ip) as key for tracking, since response also goes to src_ip */
        struct dns_amp_key q_key = {
            .victim_ip = src_ip,  /* victim = spoofed source = attack target */
        };
        struct dns_amp_stats *q_stats = bpf_map_lookup_elem(&dns_amp_track, &q_key);

        if (!q_stats) {
            struct dns_amp_stats new_q = {
                .response_bytes = 0,
                .query_bytes = pkt_len,
                .last_seen = now,
                .alert_sent = 0,
            };
            bpf_map_update_elem(&dns_amp_track, &q_key, &new_q, BPF_ANY);
        } else {
            if (now - q_stats->last_seen >= WINDOW_SIZE_NS) {
                q_stats->query_bytes = pkt_len;
                q_stats->response_bytes = 0;
                q_stats->last_seen = now;
                q_stats->alert_sent = 0;
            } else {
                q_stats->query_bytes += pkt_len;
                q_stats->last_seen = now;
            }
        }
    } else if (src_port == 53 && dst_port != 53) {
        /* DNS response: DNS server->victim (dst_ip = victim)
         * victim IP is at dst_ip position */
        struct dns_amp_key a_key = {
            .victim_ip = dst_ip,  /* victim is the destination of the response */
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

            /* Detect amplification: response > dns_amp_threshold x query (configurable threshold) */
            __u32 dns_thresh = cfg ? cfg->dns_amp_threshold : 10;
            if (a_stats->query_bytes > 0 &&
                a_stats->response_bytes > a_stats->query_bytes * dns_thresh &&
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

/*
 * Port Scan Detection
 * Detects various port scan types:
 *   - SYN scan (0x02): TCP SYN to multiple ports
 *   - FIN/NULL scan (0x00 or 0x01): TCP with no flags or just FIN
 *   - XMAS scan (0x29): TCP with FIN+URG+PUSH flags
 * Returns: 0=normal, 1=port scan detected
 */
static __always_inline int check_port_scan(__u32 src_ip, __u32 dst_ip,
                                           __u16 dst_port, __u8 tcp_flags) {
    struct port_scan_key ps_key = {
        .src_ip = src_ip,
        .dst_ip = dst_ip,
    };
    struct port_scan_stats *ps_stats = bpf_map_lookup_elem(&port_scan_track, &ps_key);
    __u64 now = bpf_ktime_get_ns();
    __u8 scan_type = 0;

    /* Determine scan type based on TCP flags */
    if (tcp_flags & 0x02) {
        /* SYN flag set - could be SYN scan */
        if ((tcp_flags & 0x17) == 0x02) {
            /* Only SYN flag (no ACK, RST, etc.) - SYN scan */
            scan_type = SCAN_TYPE_SYN;
        }
    } else if ((tcp_flags & 0x29) == 0x29) {
        /* XMAS scan: FIN+URG+PUSH flags set */
        scan_type = SCAN_TYPE_XMAS;
    } else if (tcp_flags == 0x01) {
        /* FIN scan: only FIN flag set */
        scan_type = SCAN_TYPE_FIN_NULL;
    } else if (tcp_flags == 0) {
        /* NULL scan: no TCP flags set */
        scan_type = SCAN_TYPE_FIN_NULL;
    }

    /* If not a scan packet, ignore */
    if (scan_type == 0)
        return 0;

    if (!ps_stats) {
        /* New entry */
        struct port_scan_stats new_ps = {
            .window_start = now,
            .last_seen = now,
            .packet_count = 1,
            .scan_type_mask = scan_type,
            .alert_sent = 0,
        };
        bpf_map_update_elem(&port_scan_track, &ps_key, &new_ps, BPF_ANY);
        return 0;
    }

    /* Check for timeout - delete stale entry */
    if (now - ps_stats->last_seen > WINDOW_SIZE_NS * 2) {
        bpf_map_delete_elem(&port_scan_track, &ps_key);
        struct port_scan_stats new_ps = {
            .window_start = now,
            .last_seen = now,
            .packet_count = 1,
            .scan_type_mask = scan_type,
            .alert_sent = 0,
        };
        bpf_map_update_elem(&port_scan_track, &ps_key, &new_ps, BPF_ANY);
        return 0;
    }

    /* Update existing entry */
    if (now - ps_stats->window_start >= WINDOW_SIZE_NS) {
        /* Reset window */
        ps_stats->window_start = now;
        ps_stats->packet_count = 1;
        ps_stats->scan_type_mask = scan_type;
    } else {
        ps_stats->packet_count++;
        ps_stats->scan_type_mask |= scan_type;
    }
    ps_stats->last_seen = now;

    /* Check threshold */
    if (ps_stats->packet_count >= port_scan_threshold && !ps_stats->alert_sent) {
        /* Send port scan alert */
        send_alert(src_ip, dst_ip, 0, dst_port,
                   IPPROTO_TCP, SEVERITY_HIGH,
                   0, EVENT_PORT_SCAN);
        increment_stat(STATS_PORT_SCAN_ALERTS, 1);
        ps_stats->alert_sent = 1;
        return 1;
    }

    return 0;
}
