// SPDX-License-Identifier: GPL-2.0
#include "nids_common.h"

/*
 * Protocol parsing functions
 */

/* TODO: Extract parse_packet from nids_bpf.c */
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
        /* IPv6 — 使用第一个 32 位块作为 IPv4 兼容的流标识 */
        struct ipv6hdr *ipv6 = (struct ipv6hdr *)(eth + 1);
        if ((void *)(ipv6 + 1) > data_end)
            return -1;

        /* 使用第一个 32 位块用于流跟踪（截断可接受用于检测） */
        key->src_ip = ipv6->saddr.in6_u.u6_addr32[0];
        key->dst_ip = ipv6->daddr.in6_u.u6_addr32[0];
        key->protocol = ipv6->nexthdr;
        *pkt_len = bpf_ntohs(ipv6->payload_len) + sizeof(struct ipv6hdr);

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

/* TODO: Extract parse_ipv6 from nids_bpf.c */
static __always_inline int parse_ipv6(void *data, void *data_end,
                                      __u32 *src_ip, __u32 *dst_ip,
                                      __u16 *src_port, __u16 *dst_port,
                                      __u8 *protocol, __u32 *pkt_len,
                                      __u8 *tcp_flags, void **transport_hdr) {
    struct ethhdr *eth = (struct ethhdr *)data;
    struct ipv6hdr *ipv6 = (struct ipv6hdr *)(eth + 1);

    if ((void *)(ipv6 + 1) > data_end)
        return -1;

    /* Extract first 32 bits of IPv6 addresses for tracking (truncation is acceptable for detection) */
    *src_ip = ipv6->saddr.in6_u.u6_addr32[0];
    *dst_ip = ipv6->daddr.in6_u.u6_addr32[0];
    *protocol = ipv6->nexthdr;
    *pkt_len = bpf_ntohs(ipv6->payload_len) + sizeof(struct ipv6hdr);

    /* Initialize tcp_flags */
    *tcp_flags = 0;
    *src_port = 0;
    *dst_port = 0;

    /* Skip extension headers to find transport header */
    __u8 nexthdr = ipv6->nexthdr;
    void *hdr = (void *)(ipv6 + 1);

    /* Extension header types to skip */
    /* 0: Hop-by-Hop Options, 43: Routing, 44: Fragment, 50: ESP, 51: AH, 60: Destination Options */
    while (nexthdr == 0 || nexthdr == 43 || nexthdr == 44 ||
           nexthdr == 50 || nexthdr == 51 || nexthdr == 60) {
        struct ipv6_opt_hdr *opt_hdr = (struct ipv6_opt_hdr *)hdr;

        if ((void *)(opt_hdr + 1) > data_end)
            return -1;

        nexthdr = opt_hdr->nexthdr;
        /* Extension header length is in 8-byte units, plus the 8-byte header itself */
        __u8 ext_len = (nexthdr == 44) ? 8 : (opt_hdr->hdrlen + 1) * 8;
        hdr = (__u8 *)hdr + ext_len;

        if ((void *)hdr >= data_end)
            return -1;
    }

    *transport_hdr = hdr;
    *protocol = nexthdr;

    /* Parse transport layer */
    if (nexthdr == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)hdr;
        if ((void *)(tcp + 1) > data_end)
            return -1;
        *src_port = bpf_ntohs(tcp->source);
        *dst_port = bpf_ntohs(tcp->dest);
        *tcp_flags = *((__u8 *)tcp + 13);
    } else if (nexthdr == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)hdr;
        if ((void *)(udp + 1) > data_end)
            return -1;
        *src_port = bpf_ntohs(udp->source);
        *dst_port = bpf_ntohs(udp->dest);
    } else if (nexthdr == IPPROTO_ICMPV6) {
        /* ICMPv6 - no ports */
        *src_port = 0;
        *dst_port = 0;
    }

    return 0;
}
