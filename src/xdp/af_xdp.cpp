/* SPDX-License-Identifier: MIT */
/*
 * af_xdp.cpp - AF_XDP 用户态数据包处理实现
 */

#include "af_xdp.h"
#include "../utils/bmh_search.h"
#include "../core/logger.h"
#include <linux/if_xdp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <unistd.h>
#include <cstring>
#include <errno.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>

namespace nids {

XdpProcessor::XdpProcessor()
    : sock_fd_(-1)
    , opened_(false)
    , running_(false)
    , rx_count_(0)
    , drop_count_(0)
    , dpi_match_count_(0) {
}

XdpProcessor::~XdpProcessor() {
    close();
}

bool XdpProcessor::open(const XdpConfig& config) {
    if (opened_) {
        LOG_WARN("xdp", "already opened");
        return true;
    }

    // 创建 AF_XDP socket
    sock_fd_ = socket(AF_XDP, SOCK_RAW, 0);
    if (sock_fd_ < 0) {
        LOG_ERR("xdp", "failed to create socket: %s", strerror(errno));
        return false;
    }

    // 获取接口索引
    int ifindex = if_nametoindex(config.iface.c_str());
    if (ifindex == 0) {
        LOG_ERR("xdp", "failed to get ifindex for %s", config.iface.c_str());
        close();
        return false;
    }

    // 设置 XDP 地址
    struct sockaddr_xdp addr = {};
    addr.sxdp_family = AF_XDP;
    addr.sxdp_ifindex = ifindex;
    addr.sxdp_queue_id = config.queue_id;
    addr.sxdp_flags = XDP_SHARED_UMEM;

    if (bind(sock_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LOG_ERR("xdp", "failed to bind socket: %s", strerror(errno));
        close();
        return false;
    }

    opened_ = true;
    LOG_INFO("xdp", "opened AF_XDP on %s queue %u", config.iface.c_str(), config.queue_id);
    return true;
}

void XdpProcessor::close() {
    if (running_) {
        stop();
    }

    if (sock_fd_ >= 0) {
        ::close(sock_fd_);
        sock_fd_ = -1;
    }

    opened_ = false;
    LOG_INFO("xdp", "closed AF_XDP");
}

void XdpProcessor::set_rules(const std::vector<std::pair<std::string, int>>& rules) {
    rules_ = rules;
}

void XdpProcessor::run() {
    if (!opened_ || running_) {
        return;
    }

    running_ = true;
    LOG_INFO("xdp", "started processing");

    while (running_.load()) {
        process_packets();
    }

    LOG_INFO("xdp", "stopped processing");
}

void XdpProcessor::stop() {
    running_ = false;
}

void XdpProcessor::process_packets() {
    // Note: This is a simplified implementation
    // Full AF_XDP requires:
    // 1. UMEM setup with mmap
    // 2. Fill ring management
    // 3. Completion ring handling
    // 4. Receiving packets via recvmsg

    // For now, this is a placeholder that demonstrates
    // the architecture for DPI in user space

    // The actual implementation would use:
    // - recvmsg() to receive packets from AF_XDP socket
    // - Access packet data via umem frames
    // - Parse headers and payload
    // - Perform BMH matching

    // Simplified: just record statistics
    rx_count_++;
}

bool XdpProcessor::parse_packet(uint8_t* data, uint32_t len, XdpPacket& pkt) {
    if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
        return false;
    }

    struct ethhdr* eth = reinterpret_cast<struct ethhdr*>(data);
    if (ntohs(eth->h_proto) != ETH_P_IP) {
        return false;
    }

    struct iphdr* ip = reinterpret_cast<struct iphdr*>(data + sizeof(struct ethhdr));
    if (ip->version != 4 || ip->ihl < 5) {
        return false;
    }

    pkt.src_ip = ntohl(ip->saddr);
    pkt.dst_ip = ntohl(ip->daddr);
    pkt.protocol = ip->protocol;

    uint8_t* l4 = data + sizeof(struct ethhdr) + ip->ihl * 4;
    uint32_t l4_len = len - sizeof(struct ethhdr) - ip->ihl * 4;

    if (pkt.protocol == IPPROTO_TCP && l4_len >= sizeof(struct tcphdr)) {
        struct tcphdr* tcp = reinterpret_cast<struct tcphdr*>(l4);
        pkt.src_port = ntohs(tcp->source);
        pkt.dst_port = ntohs(tcp->dest);
        pkt.data = l4 + tcp->doff * 4;
        pkt.len = l4_len - tcp->doff * 4;
    } else if (pkt.protocol == IPPROTO_UDP && l4_len >= sizeof(struct udphdr)) {
        struct udphdr* udp = reinterpret_cast<struct udphdr*>(l4);
        pkt.src_port = ntohs(udp->source);
        pkt.dst_port = ntohs(udp->dest);
        pkt.data = l4 + sizeof(struct udphdr);
        pkt.len = l4_len - sizeof(struct udphdr);
    } else {
        pkt.data = l4;
        pkt.len = l4_len;
    }

    return true;
}

void XdpProcessor::perform_dpi(const XdpPacket& pkt) {
    if (rules_.empty()) {
        return;
    }

    for (const auto& [pattern, rule_id] : rules_) {
        if (search_payload(pkt.data, pkt.len, pattern)) {
            dpi_match_count_++;

            DpiResult result;
            result.matched = true;
            result.rule_id = rule_id;
            result.message = "Content match: " + pattern;

            if (dpi_callback_) {
                dpi_callback_(pkt, result);
            }
            break;  // 一旦匹配就停止
        }
    }
}

} // namespace nids
