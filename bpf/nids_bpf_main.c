// SPDX-License-Identifier: GPL-2.0
#include "nids_common.h"
#include "nids_bpf_internal.h"

/*
 * Main XDP handler - extracted from nids_bpf.c
 *
 * Split structure:
 *   - nids_bpf_main.c: handle_xdp(), nids_xdp() [THIS FILE]
 *   - nids_bpf_defrag.c: IPv4/IPv6 defragmentation
 *   - nids_bpf_detect.c: DDoS/flood/port scan detection
 *   - nids_bpf_rules.c: Rule matching
 *   - nids_bpf_proto.c: Protocol detection (HTTP/SSH/FTP/Telnet/SMTP/POP3/IMAP)
 *   - nids_bpf_flow.c: Flow tracking
 *   - nids_trace.c: Tracepoint handlers (already separate)
 */

/*
 * XDP 主程序 - 直接处理，不使用 tail call
 */
static __always_inline int handle_xdp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /*
     * O-01: Batch processing optimization - cache common values
     */
    struct flow_key key = {};
    __u32 pkt_len = 0;
    __u8 tcp_flags = 0;
    __u64 now = bpf_ktime_get_ns();  /* O-01: Cache time once */
    int ret;

    /* O-01: Cache config lookup at function start */
    __u32 drop_enabled = get_config_drop_enabled();

    /* O-06: Use unlikely() for disabled check - most common path is enabled */
    if (unlikely(!enabled))
        return XDP_PASS;

    /* O-01: Parse ethernet header ONCE and cache eth_proto */
    struct ethhdr *eth = (struct ethhdr *)data;
    if (unlikely((void *)(eth + 1) > data_end)) {
        /* Invalid packet, count and pass */
        increment_stat(STATS_PACKETS_PASSED, 1);
        return XDP_PASS;
    }
    __u16 eth_proto = bpf_ntohs(eth->h_proto);  /* O-01: Cache eth_proto */

    /* IP Defragmentation - handle IPv4 and IPv6 fragments */
    /* O-01: Use likely() for IPv4 (most common) */
    if (likely(eth_proto == ETH_P_IP)) {
        /* IPv4 defragmentation */
        ret = handle_ipv4_defrag(data, data_end, &key, &pkt_len);
        if (unlikely(ret != XDP_PASS))
            return ret;
    } else if (unlikely(eth_proto == ETH_P_IPV6)) {
        /* IPv6 defragmentation */
        ret = handle_ipv6_defrag(data, data_end, &key, &pkt_len);
        if (unlikely(ret != XDP_PASS))
            return ret;
    }

    /* IPv6 Deep Detection - parse and detect before IPv4 path */
    __u32 ipv6_src_ip = 0, ipv6_dst_ip = 0;
    __u16 ipv6_src_port = 0, ipv6_dst_port = 0;
    __u8 ipv6_protocol = 0, ipv6_tcp_flags = 0;
    __u32 ipv6_pkt_len = 0;
    void *ipv6_transport_hdr = NULL;

    /* O-01: Use cached eth_proto instead of re-parsing */
    if (unlikely(eth_proto == ETH_P_IPV6)) {
            /* IPv6: Parse with extension header support */
            ret = parse_ipv6(data, data_end,
                           &ipv6_src_ip, &ipv6_dst_ip,
                           &ipv6_src_port, &ipv6_dst_port,
                           &ipv6_protocol, &ipv6_pkt_len,
                           &ipv6_tcp_flags, &ipv6_transport_hdr);

            if (ret == 0) {
                /* O-06: Consolidate TCP flood detections into single branch - reduces 5 branches to 1 */
                if (ipv6_protocol == IPPROTO_TCP) {
                    check_syn_flood(ipv6_src_ip, ipv6_dst_ip, ipv6_dst_port, ipv6_tcp_flags);
                    check_ack_flood(ipv6_src_ip, ipv6_dst_ip, ipv6_src_port, ipv6_dst_port, ipv6_tcp_flags);
                    check_fin_flood(ipv6_src_ip, ipv6_dst_ip, ipv6_src_port, ipv6_dst_port, ipv6_tcp_flags);
                    check_rst_flood(ipv6_src_ip, ipv6_dst_ip, ipv6_src_port, ipv6_dst_port, ipv6_tcp_flags);
                    check_port_scan(ipv6_src_ip, ipv6_dst_ip, ipv6_dst_port, ipv6_tcp_flags);
                }

                /* ICMPv6 flood detection (protocol 58 = IPPROTO_ICMPV6) */
                /* Only type 128 (Echo Request) and 129 (Echo Reply) should trigger flood detection */
                if (ipv6_protocol == IPPROTO_ICMPV6 && ipv6_transport_hdr != NULL) {
                    __u8 *icmp6_hdr = (__u8 *)ipv6_transport_hdr;
                    if ((void *)(icmp6_hdr + 1) <= data_end) {
                        __u8 icmp6_type = icmp6_hdr[0];
                        if (icmp6_type == 128 || icmp6_type == 129) {
                            check_icmp_flood(ipv6_src_ip);
                        }
                    }
                }

                /* DNS Amplification detection */
                if (ipv6_protocol == IPPROTO_UDP) {
                    check_dns_amplification(ipv6_src_ip, ipv6_dst_ip,
                                           ipv6_src_port, ipv6_dst_port, ipv6_pkt_len);
                }

                /* Protocol detection for TCP with payload */
                if (ipv6_protocol == IPPROTO_TCP && ipv6_transport_hdr != NULL) {
                    struct tcphdr *tcp = (struct tcphdr *)ipv6_transport_hdr;
                    if ((void *)(tcp + 1) <= data_end) {
                        __u32 tcp_header_len = tcp->doff * 4;
                        __u8 *payload = (__u8 *)tcp + tcp_header_len;
                        /* IPv6 header is 40 bytes, no extension headers should be here if we parsed correctly */
                        __u32 payload_len = ipv6_pkt_len - sizeof(struct ipv6hdr) - tcp_header_len;

                        if (payload_len > 0) {
                            /* HTTP detection on ports 80, 8080 */
                            if (ipv6_dst_port == 80 || ipv6_dst_port == 8080) {
                                if (check_http(payload, payload_len)) {
                                    send_alert(ipv6_src_ip, ipv6_dst_ip, ipv6_src_port, ipv6_dst_port,
                                               IPPROTO_TCP, SEVERITY_LOW, 0, EVENT_HTTP_DETECTED);
                                    increment_stat(STATS_HTTP_DETECTED, 1);
                                }
                            }
                            /* SSH detection on port 22 */
                            if (ipv6_dst_port == 22) {
                                if (check_ssh(payload, payload_len)) {
                                    send_alert(ipv6_src_ip, ipv6_dst_ip, ipv6_src_port, ipv6_dst_port,
                                               IPPROTO_TCP, SEVERITY_LOW, 0, EVENT_SSH_BANNER);
                                    increment_stat(STATS_SSH_BANNER, 1);
                                }
                            }
                            /* FTP detection on port 21 */
                            if (ipv6_dst_port == 21) {
                                if (check_ftp(payload, payload_len)) {
                                    send_alert(ipv6_src_ip, ipv6_dst_ip, ipv6_src_port, ipv6_dst_port,
                                               IPPROTO_TCP, SEVERITY_MEDIUM, 0, EVENT_FTP_CMD);
                                    increment_stat(STATS_FTP_CMD, 1);
                                }
                            }
                            /* Telnet detection on port 23 */
                            if (ipv6_dst_port == 23) {
                                if (check_telnet(payload, payload_len)) {
                                    send_alert(ipv6_src_ip, ipv6_dst_ip, ipv6_src_port, ipv6_dst_port,
                                               IPPROTO_TCP, SEVERITY_MEDIUM, 0, EVENT_TELNET_OPT);
                                    increment_stat(STATS_TELNET_OPT, 1);
                                }
                            }
                        }
                    }
                }

                /* Rule matching for IPv6 (uses truncated IPs for indexing) */
                if (match_rules_enabled) {
                    __u32 matched = match_simple_rules(ipv6_protocol, ipv6_dst_port);
                    if (matched > 0) {
                        __u32 dpi_needed = (matched >> 31) & 1;
                        __u32 action = (matched >> 30) & 1;
                        __u32 rule_id = matched & 0x3FFFFFFF;

                        if (dpi_needed) {
                            send_alert(ipv6_src_ip, ipv6_dst_ip,
                                      ipv6_src_port, ipv6_dst_port,
                                      ipv6_protocol, SEVERITY_MEDIUM,
                                      rule_id, EVENT_DPI_REQUEST);
                        } else if (action == 1 && drop_enabled) {  /* O-01: Use cached drop_enabled */
                            send_alert(ipv6_src_ip, ipv6_dst_ip,
                                      ipv6_src_port, ipv6_dst_port,
                                      ipv6_protocol, SEVERITY_HIGH,
                                      rule_id, EVENT_RULE_MATCH);
                            increment_stat(STATS_RULE_MATCHES, 1);
                            increment_stat(STATS_PACKETS_DROPPED, 1);
                            return XDP_DROP;
                        } else {
                            send_alert(ipv6_src_ip, ipv6_dst_ip,
                                      ipv6_src_port, ipv6_dst_port,
                                      ipv6_protocol, SEVERITY_HIGH,
                                      rule_id, EVENT_RULE_MATCH);
                            increment_stat(STATS_RULE_MATCHES, 1);
                        }
                    }
                }
            }

            /* IPv6: Call flow tracking and then pass */
            /* Populate key struct for flow tracking */
            key.src_ip = ipv6_src_ip;
            key.dst_ip = ipv6_dst_ip;
            key.src_port = ipv6_src_port;
            key.dst_port = ipv6_dst_port;
            key.protocol = ipv6_protocol;
            normalize_flow_key(&key);

            /* C-01: Associate flow with container */
            __u32 flow_hash = compute_flow_hash(&key);
            associate_flow_with_container(&key, flow_hash);

            update_flow_stats(&key, ipv6_pkt_len, now);

            increment_stat(STATS_PACKETS_TOTAL, 1);
            return XDP_PASS;
        }

    /* IPv4 and other: Parse and detect normally */
    /* 解析数据包 */
    ret = parse_packet(data, data_end, &key, &pkt_len, &tcp_flags);
    if (ret != 0) {
        /* 非支持协议，直接通过 */
        increment_stat(STATS_PACKETS_PASSED, 1);
        return XDP_PASS;
    }

    /* O-06: Consolidate TCP flood detections into single branch for IPv4 */
    if (key.protocol == IPPROTO_TCP) {
        check_syn_flood(key.src_ip, key.dst_ip, key.dst_port, tcp_flags);
        check_ack_flood(key.src_ip, key.dst_ip, key.src_port, key.dst_port, tcp_flags);
        check_fin_flood(key.src_ip, key.dst_ip, key.src_port, key.dst_port, tcp_flags);
        check_rst_flood(key.src_ip, key.dst_ip, key.src_port, key.dst_port, tcp_flags);
        check_port_scan(key.src_ip, key.dst_ip, key.dst_port, tcp_flags);
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

    /*
     * C-05: Cloud Metadata API Access Detection
     *
     * Detect access to cloud metadata service (169.254.0.0/16)
     * This is commonly used for:
     * - AWS: 169.254.169.254 (EC2 metadata, IMDS)
     * - GCP: 169.254.169.254 (GCE metadata server)
     * - Azure: 169.254.169.254 (Azure IMDS)
     *
     * Access to metadata from non-node sources may indicate:
     * - Container breakout attempt
     * - Misconfigured pod trying to access cloud credentials
     * - Potential credential theft attack
     *
     * Detection: Check if dst_ip is in 169.254.0.0/16 (link-local)
     * In network byte order: 0xFEA90000 - 0xFEA9FFFF
     */
    if ((key.dst_ip & 0xFFFF0000) == 0xFEA90000) {
        /* Accessing cloud metadata service */
        send_alert(key.src_ip, key.dst_ip, key.src_port, key.dst_port,
                   key.protocol, SEVERITY_HIGH, 0, EVENT_RULE_MATCH);
        increment_stat(STATS_DDoS_ALERTS, 1);
    }

    /* Protocol detection for TCP with payload */
    /* O-01: IPv4 path - eth pointer already cached at function start */
    if (key.protocol == IPPROTO_TCP) {
        /* Extract TCP payload pointer and length */
        struct iphdr *ip = (struct iphdr *)(eth + 1);  /* O-01: Use cached eth */
        __u32 ip_header_len = ip->ihl * 4;
        struct tcphdr *tcp = (struct tcphdr *)((__u8 *)ip + ip_header_len);
        if ((void *)(tcp + 1) <= data_end) {
            __u32 tcp_header_len = tcp->doff * 4;
            __u8 *payload = (__u8 *)tcp + tcp_header_len;
            __u32 payload_len = pkt_len - sizeof(struct ethhdr) - ip_header_len - tcp_header_len;

            /* Only check if we have payload */
            if (payload_len > 0 && payload_len <= pkt_len) {
                /* HTTP detection on ports 80, 8080 */
                if (key.dst_port == 80 || key.dst_port == 8080) {
                    if (check_http(payload, payload_len)) {
                        send_alert(key.src_ip, key.dst_ip, key.src_port, key.dst_port,
                                   IPPROTO_TCP, SEVERITY_LOW, 0, EVENT_HTTP_DETECTED);
                        increment_stat(STATS_HTTP_DETECTED, 1);
                    }
                }
                /* SSH detection on port 22 */
                if (key.dst_port == 22) {
                    if (check_ssh(payload, payload_len)) {
                        send_alert(key.src_ip, key.dst_ip, key.src_port, key.dst_port,
                                   IPPROTO_TCP, SEVERITY_LOW, 0, EVENT_SSH_BANNER);
                        increment_stat(STATS_SSH_BANNER, 1);
                    }
                }
                /* FTP detection on port 21 */
                if (key.dst_port == 21) {
                    if (check_ftp(payload, payload_len)) {
                        send_alert(key.src_ip, key.dst_ip, key.src_port, key.dst_port,
                                   IPPROTO_TCP, SEVERITY_MEDIUM, 0, EVENT_FTP_CMD);
                        increment_stat(STATS_FTP_CMD, 1);
                    }
                }
                /* Telnet detection on port 23 */
                if (key.dst_port == 23) {
                    if (check_telnet(payload, payload_len)) {
                        send_alert(key.src_ip, key.dst_ip, key.src_port, key.dst_port,
                                   IPPROTO_TCP, SEVERITY_MEDIUM, 0, EVENT_TELNET_OPT);
                        increment_stat(STATS_TELNET_OPT, 1);
                    }
                }
                /* SMTP detection on ports 25, 587, 465 */
                if (key.dst_port == 25 || key.dst_port == 587 || key.dst_port == 465) {
                    if (check_smtp(payload, payload_len)) {
                        send_alert(key.src_ip, key.dst_ip, key.src_port, key.dst_port,
                                   IPPROTO_TCP, SEVERITY_LOW, 0, EVENT_SMTP_RESPONSE);
                        increment_stat(STATS_SMTP_RESPONSE, 1);
                    }
                }
                /* POP3 detection on ports 110, 995 */
                if (key.dst_port == 110 || key.dst_port == 995) {
                    if (check_pop3(payload, payload_len)) {
                        send_alert(key.src_ip, key.dst_ip, key.src_port, key.dst_port,
                                   IPPROTO_TCP, SEVERITY_LOW, 0, EVENT_POP3_RESPONSE);
                        increment_stat(STATS_POP3_RESPONSE, 1);
                    }
                }
                /* IMAP detection on ports 143, 993 */
                if (key.dst_port == 143 || key.dst_port == 993) {
                    if (check_imap(payload, payload_len)) {
                        send_alert(key.src_ip, key.dst_ip, key.src_port, key.dst_port,
                                   IPPROTO_TCP, SEVERITY_LOW, 0, EVENT_IMAP_RESPONSE);
                        increment_stat(STATS_IMAP_RESPONSE, 1);
                    }
                }
            }
        }
    }

    /* 归一化流 key，确保 (A→B) 和 (B→A) 使用同一 entry */
    normalize_flow_key(&key);

    /* C-01: Associate flow with container */
    __u32 flow_hash = compute_flow_hash(&key);
    associate_flow_with_container(&key, flow_hash);

    /* 更新流统计并检查 DDoS */
    int alert_sent = update_flow_stats(&key, pkt_len, now);  /* O-01: Use cached now */
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
            } else if (action == 1 && drop_enabled) {  /* O-01: Use cached drop_enabled */
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

char LICENSE[] SEC("license") = "GPL";
