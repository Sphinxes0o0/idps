/* SPDX-License-Identifier: MIT */
/*
 * af_xdp.cpp - AF_XDP 用户态数据包处理实现
 */

#include "af_xdp.h"
#include "../utils/bmh_search.h"
#include "../core/logger.h"
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <cstring>
#include <errno.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>

namespace nids {

/* TLS constants */
static constexpr uint8_t TLS_CONTENT_TYPE_HANDSHAKE = 22;
static constexpr uint8_t TLS_HANDSHAKE_CLIENT_HELLO = 1;
static constexpr uint8_t TLS_HANDSHAKE_SERVER_HELLO = 2;
static constexpr uint16_t TLS_VERSION_SSL3 = 0x0300;
static constexpr uint16_t TLS_VERSION_TLS1_0 = 0x0301;
static constexpr uint16_t TLS_VERSION_TLS1_1 = 0x0302;
static constexpr uint16_t TLS_VERSION_TLS1_2 = 0x0303;
static constexpr uint16_t TLS_VERSION_TLS1_3 = 0x0304;
/* TLS extension types */
static constexpr uint8_t TLS_EXT_SNI = 0;
/* TLS cipher suites that are considered weak */
static constexpr uint16_t WEAK_CIPHERS[] = {
    0x0005, /* TLS_RSA_WITH_RC4_128_SHA */
    0x0027, /* TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA */
    0x0003, /* TLS_RSA_EXPORT_WITH_RC4_40_MD5 */
    0x0006, /* TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 */
    0x0011, /* TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA */
};

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

bool XdpProcessor::is_available() {
    int sock = socket(AF_XDP, SOCK_RAW, 0);
    if (sock < 0) {
        return false;
    }
    ::close(sock);
    return true;
}

std::string XdpProcessor::get_unavailable_reason() {
    int sock = socket(AF_XDP, SOCK_RAW, 0);
    if (sock >= 0) {
        ::close(sock);
        return "AF_XDP is available";
    }
    
    if (errno == EAFNOSUPPORT) {
        return "AF_XDP not supported: kernel or CONFIG_XDP_SOCKETS not enabled";
    } else if (errno == ENOMEM) {
        return "AF_XDP not available: insufficient memory";
    } else {
        return "AF_XDP not available: " + std::string(strerror(errno));
    }
}

bool XdpProcessor::open(const XdpConfig& config) {
    if (opened_) {
        LOG_WARN("xdp", "already opened");
        return true;
    }

    num_frames_ = config.num_frames;
    frame_size_ = config.frame_size;
    umem_size_ = num_frames_ * frame_size_;

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

    // 注册 UMEM
    struct xdp_umem_reg mr = {};
    mr.addr = 0;  // 让内核分配
    mr.len = umem_size_;
    mr.chunk_size = frame_size_;
    mr.headroom = 0;
    mr.flags = XDP_UMEM_UNALIGNED_CHUNK_FLAG;

    if (setsockopt(sock_fd_, SOL_XDP, XDP_UMEM_REG, &mr, sizeof(mr)) < 0) {
        LOG_ERR("xdp", "failed to register UMEM: %s", strerror(errno));
        close();
        return false;
    }

    // mmap UMEM area
    umem_area_ = static_cast<uint8_t*>(mmap(nullptr, umem_size_,
                                              PROT_READ | PROT_WRITE,
                                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (umem_area_ == MAP_FAILED) {
        LOG_ERR("xdp", "failed to mmap UMEM: %s", strerror(errno));
        close();
        return false;
    }

    // 设置 XDP 地址 (bind 前需要先设好 UMEM)
    struct sockaddr_xdp addr = {};
    addr.sxdp_family = AF_XDP;
    addr.sxdp_ifindex = ifindex;
    addr.sxdp_queue_id = config.queue_id;
    addr.sxdp_flags = 0;  // 不共享 UMEM

    if (bind(sock_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LOG_ERR("xdp", "failed to bind socket: %s", strerror(errno));
        close();
        return false;
    }

    // 获取 mmap offsets
    struct xdp_mmap_offsets off = {};
    socklen_t optlen = sizeof(off);
    if (getsockopt(sock_fd_, SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen) < 0) {
        LOG_ERR("xdp", "failed to get mmap offsets: %s", strerror(errno));
        close();
        return false;
    }
    ring_offsets_.fill.producer = off.fr.producer;
    ring_offsets_.fill.consumer = off.fr.consumer;
    ring_offsets_.fill.desc = off.fr.desc;
    ring_offsets_.fill.flags = off.fr.flags;
    ring_offsets_.completion.producer = off.cr.producer;
    ring_offsets_.completion.consumer = off.cr.consumer;
    ring_offsets_.completion.desc = off.cr.desc;
    ring_offsets_.completion.flags = off.cr.flags;

    // mmap fill ring
    fill_ring_ = static_cast<struct xdp_desc*>(
        mmap(nullptr, num_frames_ * sizeof(struct xdp_desc),
             PROT_READ | PROT_WRITE, MAP_SHARED, sock_fd_,
             XDP_UMEM_PGOFF_FILL_RING));
    if (fill_ring_ == MAP_FAILED) {
        LOG_ERR("xdp", "failed to mmap fill ring: %s", strerror(errno));
        close();
        return false;
    }

    // mmap completion ring
    completion_ring_ = static_cast<struct xdp_desc*>(
        mmap(nullptr, num_frames_ * sizeof(struct xdp_desc),
             PROT_READ | PROT_WRITE, MAP_SHARED, sock_fd_,
             XDP_UMEM_PGOFF_COMPLETION_RING));
    if (completion_ring_ == MAP_FAILED) {
        LOG_ERR("xdp", "failed to mmap completion ring: %s", strerror(errno));
        close();
        return false;
    }

    // 预填充 fill ring: 将所有帧地址放入 fill ring
    for (uint32_t i = 0; i < num_frames_; i++) {
        fill_ring_[i].addr = reinterpret_cast<uint64_t>(umem_area_ + i * frame_size_);
        fill_ring_[i].len = frame_size_;
        fill_ring_[i].options = 0;
    }

    // 设置 socket 为非阻塞
    int sock_flags = fcntl(sock_fd_, F_GETFL, 0);
    fcntl(sock_fd_, F_SETFL, sock_flags | O_NONBLOCK);

    opened_ = true;
    LOG_INFO("xdp", "opened AF_XDP on %s queue %u (%u frames @ %u bytes)",
             config.iface.c_str(), config.queue_id, num_frames_, frame_size_);
    return true;
}

void XdpProcessor::close() {
    if (running_) {
        stop();
    }

    if (fill_ring_ != nullptr && fill_ring_ != MAP_FAILED) {
        munmap(fill_ring_, num_frames_ * sizeof(struct xdp_desc));
        fill_ring_ = nullptr;
    }
    if (completion_ring_ != nullptr && completion_ring_ != MAP_FAILED) {
        munmap(completion_ring_, num_frames_ * sizeof(struct xdp_desc));
        completion_ring_ = nullptr;
    }
    if (umem_area_ != nullptr && umem_area_ != MAP_FAILED) {
        munmap(umem_area_, umem_size_);
        umem_area_ = nullptr;
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

void XdpProcessor::clear_all_rules() {
    rules_.clear();
    tls_version_rules_.clear();
    sni_rules_.clear();
    cipher_rules_.clear();
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
    // Use poll to wait for packets with timeout
    struct pollfd pfd = {};
    pfd.fd = sock_fd_;
    pfd.events = POLLIN;

    int ret = poll(&pfd, 1, 100);  // 100ms timeout
    if (ret <= 0) {
        return;  // timeout or error
    }

    // Access producer/consumer counters via UMEM base + offset
    volatile uint64_t* fprod = reinterpret_cast<volatile uint64_t*>(
        umem_area_ + ring_offsets_.fill.producer);
    volatile uint64_t* fcons = reinterpret_cast<volatile uint64_t*>(
        umem_area_ + ring_offsets_.fill.consumer);
    volatile uint64_t* cprod = reinterpret_cast<volatile uint64_t*>(
        umem_area_ + ring_offsets_.completion.producer);
    volatile uint64_t* ccons = reinterpret_cast<volatile uint64_t*>(
        umem_area_ + ring_offsets_.completion.consumer);

    // Process completion ring: recycle frames back to fill ring
    while (*ccons != *cprod) {
        uint32_t idx = (*ccons) & (num_frames_ - 1);
        uint64_t frame_addr = completion_ring_[idx].addr;
        uint32_t frame_len = completion_ring_[idx].len;

        // Add back to fill ring if there's space
        if ((*fprod - *fcons) < num_frames_) {
            uint32_t fill_idx = (*fprod) & (num_frames_ - 1);
            fill_ring_[fill_idx].addr = frame_addr;
            fill_ring_[fill_idx].len = frame_len;
            fill_ring_[fill_idx].options = 0;
            (*fprod)++;
        }
        (*ccons)++;
    }

    // Receive packets - build iovecs from fill ring descriptors
    static constexpr int BATCH_SIZE = 64;
    struct iovec iov[BATCH_SIZE];
    struct mmsghdr msg[BATCH_SIZE];
    char* frames[BATCH_SIZE];
    int frame_count = 0;

    memset(msg, 0, sizeof(msg));
    while (frame_count < BATCH_SIZE) {
        if (*fprod == *fcons) {
            break;  // fill ring empty
        }

        uint32_t idx = (*fcons) & (num_frames_ - 1);
        frames[frame_count] = reinterpret_cast<char*>(fill_ring_[idx].addr);
        uint32_t frm_len = fill_ring_[idx].len;

        iov[frame_count].iov_base = frames[frame_count];
        iov[frame_count].iov_len = frm_len;

        msg[frame_count].msg_hdr.msg_iov = &iov[frame_count];
        msg[frame_count].msg_hdr.msg_iovlen = 1;

        (*fcons)++;
        frame_count++;
    }

    if (frame_count == 0) {
        return;
    }

    int n = recvmmsg(sock_fd_, msg, frame_count, MSG_DONTWAIT, nullptr);
    if (n <= 0) {
        // Return frames to completion ring on error
        for (int i = 0; i < frame_count; i++) {
            uint32_t idx = (*cprod) & (num_frames_ - 1);
            completion_ring_[idx].addr = reinterpret_cast<uint64_t>(frames[i]);
            completion_ring_[idx].len = frame_size_;
            completion_ring_[idx].options = 0;
            (*cprod)++;
        }
        return;
    }

    for (int i = 0; i < n; i++) {
        uint32_t len = msg[i].msg_len;
        if (len == 0 || len > frame_size_) {
            // Return empty/invalid frame to completion
            uint32_t idx = (*cprod) & (num_frames_ - 1);
            completion_ring_[idx].addr = reinterpret_cast<uint64_t>(frames[i]);
            completion_ring_[idx].len = frame_size_;
            completion_ring_[idx].options = 0;
            (*cprod)++;
            rx_count_++;
            continue;
        }

        XdpPacket pkt = {};
        pkt.data = reinterpret_cast<uint8_t*>(frames[i]);
        pkt.len = len;
        pkt.timestamp = 0;

        if (!parse_packet(pkt.data, pkt.len, pkt)) {
            uint32_t idx = (*cprod) & (num_frames_ - 1);
            completion_ring_[idx].addr = reinterpret_cast<uint64_t>(frames[i]);
            completion_ring_[idx].len = len;
            completion_ring_[idx].options = 0;
            (*cprod)++;
            rx_count_++;
            continue;
        }

        // Perform BMH content matching
        perform_dpi(pkt);

        // Perform TLS detection if we have TLS rules
        if (pkt.protocol == IPPROTO_TCP && pkt.len > 0) {
            detect_tls(pkt, pkt.data, pkt.len);
        }

        rx_count_++;

        // Return frame to completion ring
        uint32_t idx = (*cprod) & (num_frames_ - 1);
        completion_ring_[idx].addr = reinterpret_cast<uint64_t>(frames[i]);
        completion_ring_[idx].len = len;
        completion_ring_[idx].options = 0;
        (*cprod)++;
    }

    // Return any remaining frames that weren't processed (partial recvmmsg)
    for (int i = n; i < frame_count; i++) {
        uint32_t idx = (*cprod) & (num_frames_ - 1);
        completion_ring_[idx].addr = reinterpret_cast<uint64_t>(frames[i]);
        completion_ring_[idx].len = frame_size_;
        completion_ring_[idx].options = 0;
        (*cprod)++;
    }
}

bool XdpProcessor::parse_packet(uint8_t* data, uint32_t len, XdpPacket& pkt) {
    if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
        return false;
    }

    struct ethhdr* eth = reinterpret_cast<struct ethhdr*>(data);
    uint16_t eth_proto = ntohs(eth->h_proto);

    if (eth_proto == ETH_P_IP) {
        /* IPv4 */
        struct iphdr* ip = reinterpret_cast<struct iphdr*>(data + sizeof(struct ethhdr));
        uint32_t ip_hdr_len = ip->ihl * 4;
        if (ip->version != 4 || ip_hdr_len < sizeof(struct iphdr) ||
            ip_hdr_len > len - sizeof(struct ethhdr)) {
            return false;
        }

        pkt.src_ip = ntohl(ip->saddr);
        pkt.dst_ip = ntohl(ip->daddr);
        pkt.protocol = ip->protocol;

        uint8_t* l4 = data + sizeof(struct ethhdr) + ip_hdr_len;
        uint32_t l4_len = len - sizeof(struct ethhdr) - ip_hdr_len;

        if (pkt.protocol == IPPROTO_TCP && l4_len >= sizeof(struct tcphdr)) {
            struct tcphdr* tcp = reinterpret_cast<struct tcphdr*>(l4);
            if (tcp->doff < 5 || tcp->doff > 15) {
                return false;
            }
            pkt.src_port = ntohs(tcp->source);
            pkt.dst_port = ntohs(tcp->dest);
            pkt.data = l4 + tcp->doff * 4;
            pkt.len = l4_len - tcp->doff * 4;
            if (pkt.len > l4_len || pkt.data > l4 + l4_len) {
                return false;
            }
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
    } else if (eth_proto == ETH_P_IPV6) {
        /* IPv6 */
        struct ipv6hdr* ipv6 = reinterpret_cast<struct ipv6hdr*>(data + sizeof(struct ethhdr));
        if (len < sizeof(struct ethhdr) + sizeof(struct ipv6hdr)) {
            return false;
        }

        /* Use first 32 bits of IPv6 addresses for compatibility */
        pkt.src_ip = ipv6->saddr.in6_u.u6_addr32[0];
        pkt.dst_ip = ipv6->daddr.in6_u.u6_addr32[0];
        pkt.protocol = ipv6->nexthdr;

        uint8_t* l4 = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
        uint32_t l4_len = len - sizeof(struct ethhdr) - sizeof(struct ipv6hdr);

        if (pkt.protocol == IPPROTO_TCP && l4_len >= sizeof(struct tcphdr)) {
            struct tcphdr* tcp = reinterpret_cast<struct tcphdr*>(l4);
            if (tcp->doff < 5 || tcp->doff > 15) {
                return false;
            }
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
    } else {
        return false;
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

bool XdpProcessor::parse_tls_record(const uint8_t* data, size_t len, TlsInfo& info) {
    info = TlsInfo{};

    /* TLS record header: content_type(1) + version(2) + length(2) = 5 bytes */
    if (len < 5) {
        return false;
    }

    uint8_t content_type = data[0];
    uint16_t version = (static_cast<uint16_t>(data[1]) << 8) | data[2];

    if (content_type != TLS_CONTENT_TYPE_HANDSHAKE) {
        return false;
    }

    info.is_tls = true;
    info.version = version;

    /* Weak TLS version check */
    if (version == TLS_VERSION_SSL3 || version == TLS_VERSION_TLS1_0 ||
        version == TLS_VERSION_TLS1_1) {
        info.weak_version = true;
    }

    /* Need at least handshake header (5 bytes) + handshake type (1 byte) */
    if (len < 6) {
        return true;  /* TLS record valid but no handshake body */
    }

    const uint8_t* handshake = data + 5;
    size_t handshake_len = len - 5;

    if (handshake_len < 4) {
        return true;
    }

    info.handshake_type = handshake[0];

    if (info.handshake_type == TLS_HANDSHAKE_CLIENT_HELLO) {
        /* ClientHello parsing:
         *   uint24 length;    (3 bytes, handshake[1..3])
         *   uint16 client_version; (2 bytes, handshake[4..5])
         *   uint32 random; (32 bytes)
         *   uint8 session_id_len; (1 byte)
         *   ... then variable-length fields including cipher_suites and extensions
         *
         * For SNI extraction, we look for extension type=0 (SNI) after cipher_suites.
         */

        size_t offset = 4; /* client_version + random (4 + 32 = 36, but we start at 4) */

        /* Session ID length (1 byte) */
        if (handshake_len <= offset + 1) {
            return true;
        }
        uint8_t session_id_len = handshake[++offset];

        /* Cipher suites length (2 bytes) */
        offset += 1 + session_id_len;
        if (handshake_len <= offset + 2) {
            return true;
        }
        uint16_t cipher_suites_len = (static_cast<uint16_t>(handshake[offset]) << 8) |
                                      handshake[offset + 1];
        offset += 2 + cipher_suites_len; /* skip cipher suites */

        /* Compression methods length (1 byte) */
        if (handshake_len <= offset + 1) {
            return true;
        }
        uint8_t comp_len = handshake[++offset];
        offset += 1 + comp_len;

        /* Extensions (if any) */
        if (handshake_len <= offset + 2) {
            return true;
        }
        uint16_t ext_len = (static_cast<uint16_t>(handshake[offset]) << 8) |
                            handshake[offset + 1];
        offset += 2;

        size_t ext_end = offset + ext_len;
        if (ext_end > handshake_len) {
            ext_end = handshake_len;
        }

        /* Search for SNI extension (type=0) */
        while (offset + 4 < ext_end) {
            uint16_t ext_type = (static_cast<uint16_t>(handshake[offset]) << 8) |
                                 handshake[offset + 1];
            uint16_t ext_len_inner = (static_cast<uint16_t>(handshake[offset + 2]) << 8) |
                                      handshake[offset + 3];
            offset += 4;

            if (ext_type == TLS_EXT_SNI && offset + ext_len_inner <= ext_end) {
                /* SNI extension found - skip server_name_list length (2 bytes) */
                if (offset + 2 <= ext_end) {
                    uint16_t sni_list_len = (static_cast<uint16_t>(handshake[offset]) << 8) |
                                            handshake[offset + 1];
                    (void)sni_list_len;
                    offset += 2;

                    if (offset + 3 <= ext_end) {
                        uint8_t sni_type = handshake[offset];
                        (void)sni_type;
                        offset += 1;

                        uint16_t sni_len = (static_cast<uint16_t>(handshake[offset]) << 8) |
                                            handshake[offset + 1];
                        offset += 2;

                        if (offset + sni_len <= ext_end && sni_len > 0) {
                            info.sni = std::string(reinterpret_cast<const char*>(&handshake[offset]),
                                                   sni_len);
                        }
                    }
                }
                break;
            }

            offset += ext_len_inner;
        }
    } else if (info.handshake_type == TLS_HANDSHAKE_SERVER_HELLO) {
        /* ServerHello: version(2) + random(32) + session_id_len(1) + cipher_suite(2) +
         *              compression(1) = 38 bytes minimum */
        if (handshake_len >= 38) {
            info.cipher_suite = (static_cast<uint16_t>(handshake[33]) << 8) |
                                handshake[34];
        }
    }

    return true;
}

void XdpProcessor::detect_tls(const XdpPacket& pkt, const uint8_t* payload, size_t payload_len) {
    if (tls_version_rules_.empty() && sni_rules_.empty() && cipher_rules_.empty()) {
        return;
    }

    TlsInfo tls;
    if (!parse_tls_record(payload, payload_len, tls)) {
        return;  /* Not a TLS record */
    }

    /* Check weak TLS version */
    if (tls.weak_version) {
        for (const auto& rule : tls_version_rules_) {
            if (rule.version == tls.version) {
                DpiResult result;
                result.matched = true;
                result.rule_id = rule.rule_id;
                result.message = rule.message + " (TLS " +
                    std::to_string((tls.version >> 8) & 0xFF) + "." +
                    std::to_string(tls.version & 0xFF) + ")";
                dpi_match_count_++;
                if (dpi_callback_) {
                    dpi_callback_(pkt, result);
                }
                break;
            }
        }
    }

    /* Check SNI against blocklist rules */
    if (!tls.sni.empty()) {
        for (const auto& rule : sni_rules_) {
            /* Simple substring match for SNI pattern */
            if (tls.sni.find(rule.pattern) != std::string::npos) {
                DpiResult result;
                result.matched = true;
                result.rule_id = rule.rule_id;
                result.message = rule.message + " (SNI: " + tls.sni + ")";
                dpi_match_count_++;
                if (dpi_callback_) {
                    dpi_callback_(pkt, result);
                }
                break;
            }
        }
    }

    /* Check cipher suite against blocklist */
    if (tls.cipher_suite != 0) {
        for (const auto& rule : cipher_rules_) {
            if (rule.cipher == tls.cipher_suite) {
                DpiResult result;
                result.matched = true;
                result.rule_id = rule.rule_id;
                result.message = rule.message + " (cipher: 0x" +
                    std::to_string(tls.cipher_suite) + ")";
                dpi_match_count_++;
                if (dpi_callback_) {
                    dpi_callback_(pkt, result);
                }
                break;
            }
        }
    }
}

} // namespace nids
