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
    // Note: This is a placeholder implementation.
    // Full AF_XDP requires:
    // 1. UMEM setup with mmap (frames, fill ring, completion ring)
    // 2. recvmsg() to receive packets
    // 3. Frame recycling
    //
    // For now, record statistics to indicate the thread is alive.
    // TLS detection is still performed when parse_packet() is called externally
    // (e.g., for testing or integration with other packet sources).
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
         * This is complex to parse precisely, so we use a simple search approach.
         */

        /* Extract cipher suite if possible (at offset after session_id) */
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
                    (void)sni_list_len; /* suppress unused warning */
                    offset += 2;

                    if (offset + 3 <= ext_end) {
                        uint8_t sni_type = handshake[offset]; /* should be 0 = host_name */
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
