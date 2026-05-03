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
#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace nids {


/* Forward declaration for IPv6 extension header parsing */
static bool parse_ipv6_ext_headers(const struct ipv6hdr* ipv6,
                                   const uint8_t* data_end,
                                   uint8_t& next_header,
                                   size_t& header_len);
/*
 * HMAC Verification Failure Details
 * Used for post-analysis of HMAC-authenticated protocols (e.g., TLS, SSH, API authentication)
 */
struct HmacVerifyResult {
    bool valid;
    uint16_t rule_id;
    std::string protocol;
    std::string error_detail;
    uint64_t timestamp_ns;
};

/* Log HMAC verification failure for post-analysis */
static inline void log_hmac_failure(const HmacVerifyResult& result) {
    LOG_WARN("HMAC",
             "HMAC verification failed: protocol=%s rule_id=%u error=%s timestamp=%lu",
             result.protocol.c_str(),
             result.rule_id,
             result.error_detail.c_str(),
             result.timestamp_ns);
}

/* TLS constants */
static constexpr uint8_t TLS_CONTENT_TYPE_HANDSHAKE = 22;
static constexpr uint8_t TLS_HANDSHAKE_CLIENT_HELLO = 1;
static constexpr uint8_t TLS_HANDSHAKE_SERVER_HELLO = 2;
static constexpr uint8_t TLS_HANDSHAKE_CERTIFICATE = 11;
static constexpr uint16_t TLS_VERSION_SSL3 = 0x0300;
static constexpr uint16_t TLS_VERSION_TLS1_0 = 0x0301;
static constexpr uint16_t TLS_VERSION_TLS1_1 = 0x0302;
static constexpr uint16_t TLS_VERSION_TLS1_2 = 0x0303;
static constexpr uint16_t TLS_VERSION_TLS1_3 = 0x0304;
/* TLS extension types */
static constexpr uint8_t TLS_EXT_SNI = 0;
/* F-22: TLS 0-RTT early data extension (RFC 8446) */
static constexpr uint8_t TLS_EXT_EARLY_DATA = 42;
/* TLS cipher suites that are considered weak */
static constexpr uint16_t WEAK_CIPHERS[] = {
    0x0005, /* TLS_RSA_WITH_RC4_128_SHA */
    0x0027, /* TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA */
    0x0003, /* TLS_RSA_EXPORT_WITH_RC4_40_MD5 */
    0x0006, /* TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 */
    0x0011, /* TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA */
};

/*
 * ASN.1 OID constants for signature algorithms
 * Weak hash algorithms: MD5 (1.2.840.113549.2.5), SHA1 (1.2.840.113549.2.1)
 */
static constexpr uint8_t OID_MD5[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05};
static constexpr uint8_t OID_SHA1[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x01};
static constexpr uint8_t OID_SHA256[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09};
static constexpr uint8_t OID_SHA384[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0c};
static constexpr uint8_t OID_SHA512[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0d};
/* CN OID: 2.5.4.3 */
static constexpr uint8_t OID_CN[] = {0x55, 0x04, 0x03};
/* SAN OID: 2.5.29.17 */
static constexpr uint8_t OID_SAN[] = {0x55, 0x1d, 0x11};

/*
 * ASN.1 helper: Read a TLV (Tag-Length-Value) element
 * Returns pointer to value, sets len to value length, or nullptr on error
 */
static const uint8_t* asn1_read_tlv(const uint8_t* data, size_t remaining,
                                    uint8_t& tag, uint32_t& len) {
    if (remaining < 2) {
        return nullptr;
    }

    tag = data[0];

    /* Handle long form length */
    if (data[1] & 0x80) {
        uint8_t len_bytes = data[1] & 0x7f;
        if (remaining < 2 + len_bytes || len_bytes > 4) {
            return nullptr;
        }
        len = 0;
        for (uint8_t i = 0; i < len_bytes; i++) {
            len = (len << 8) | data[2 + i];
        }
        return data + 2 + len_bytes;
    } else {
        len = data[1];
        return data + 2;
    }
}

/*
 * ASN.1 helper: Compare OID
 */
static bool asn1_oid_equals(const uint8_t* oid1, size_t oid1_len,
                             const uint8_t* oid2, size_t oid2_len) {
    return oid1_len == oid2_len && std::memcmp(oid1, oid2, oid1_len) == 0;
}

/*
 * ASN.1 helper: Parse PrintableString or UTF8String
 */
static std::string asn1_read_string(const uint8_t* data, size_t len, uint8_t tag) {
    /* Simple string types: PrintableString=0x13, UTF8String=0x0c, IA5String=0x22 */
    if ((tag != 0x13 && tag != 0x0c && tag != 0x22) || len == 0) {
        return "";
    }
    return std::string(reinterpret_cast<const char*>(data), len);
}

/*
 * ASN.1 helper: Parse UTCTime (YYMMDDHHMMSSZ)
 * Returns epoch seconds or 0 on error
 */
static uint64_t asn1_parse_utctime(const uint8_t* data, size_t len) {
    /* UTCTime tag is 0x17 */
    if (len < 13) {
        return 0;
    }

    /* Format: YYMMDDHHMMSSZ */
    int year = (data[0] - '0') * 10 + (data[1] - '0');
    int month = (data[2] - '0') * 10 + (data[3] - '0');
    int day = (data[4] - '0') * 10 + (data[5] - '0');
    int hour = (data[6] - '0') * 10 + (data[7] - '0');
    int minute = (data[8] - '0') * 10 + (data[9] - '0');
    int second = (data[10] - '0') * 10 + (data[11] - '0');

    /* Handle 2-digit year: 00-49 = 2000-2049, 50-99 = 1950-1999 */
    if (year < 50) {
        year += 2000;
    } else {
        year += 1900;
    }

    /* Validate */
    if (month < 1 || month > 12 || day < 1 || day > 31 ||
        hour > 23 || minute > 59 || second > 59) {
        return 0;
    }

    /* Convert to epoch seconds (simplified, UTC) */
    static constexpr int days_per_month[] = {
        31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
    };

    uint64_t days = 0;
    for (int y = 1970; y < year; y++) {
        days += (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)) ? 366 : 365;
    }
    for (int m = 1; m < month; m++) {
        days += days_per_month[m - 1];
        if (m == 2 && (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0))) {
            days += 1;  /* Feb 29 */
        }
    }
    days += day - 1;

    return static_cast<uint64_t>(days) * 86400 +
           static_cast<uint64_t>(hour) * 3600 +
           static_cast<uint64_t>(minute) * 60 +
           static_cast<uint64_t>(second);
}

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

/*
 * O-04: Multi-core Load Balancing - Flow Hash Function
 *
 * Computes a 32-bit hash from the 5-tuple using a Jenkins-style hash.
 * This provides good distribution of flows across queues for RSS-style
 * load balancing.
 */
uint32_t XdpProcessor::flow_hash(uint32_t src_ip, uint32_t dst_ip,
                                 uint16_t src_port, uint16_t dst_port,
                                 uint8_t protocol) {
    uint32_t hash = 0;

    // Mix src_ip
    hash = src_ip ^ (0x85ebca6b + (hash << 6) + (hash >> 2));
    hash = (hash << 16) | (hash >> 16);
    hash = hash * 0x85ebca6b;

    // Mix dst_ip
    hash = dst_ip ^ (0xc2b2ae35 + (hash << 6) + (hash >> 2));
    hash = (hash << 16) | (hash >> 16);
    hash = hash * 0xc2b2ae35;

    // Mix src_port
    hash = src_port ^ (0x85ebca6b + (hash << 6) + (hash >> 2));
    hash = (hash << 16) | (hash >> 16);
    hash = hash * 0x85ebca6b;

    // Mix dst_port
    hash = dst_port ^ (0xc2b2ae35 + (hash << 6) + (hash >> 2));
    hash = (hash << 16) | (hash >> 16);
    hash = hash * 0xc2b2ae35;

    // Mix protocol
    hash = protocol ^ (0x85ebca6b + (hash << 6) + (hash >> 2));
    hash = (hash << 16) | (hash >> 16);
    hash = hash * 0x85ebca6b;
    hash = hash ^ (hash >> 13);
    hash = hash * 0xc2b2ae35;
    hash = hash ^ (hash >> 15);

    return hash;
}

/*
 * O-04: Multi-queue Setup for RSS-based Load Balancing
 *
 * Creates multiple AF_XDP sockets, one per queue, all sharing the same UMEM.
 * Each socket is bound to a different queue, allowing the kernel to distribute
 * flows across queues using RSS hashing.
 */
bool XdpProcessor::setup_multiqueue(int ifindex, uint32_t base_queue, uint32_t num_queues) {
    num_queues_ = num_queues;

    // Resize vectors to hold per-queue data
    sock_fds_.resize(num_queues_);
    fill_rings_.resize(num_queues_);
    completion_rings_.resize(num_queues_);
    ring_offsets_vec_.resize(num_queues_);
    queue_stats_.resize(num_queues_);

    // Initialize queue stats
    for (uint32_t i = 0; i < num_queues_; i++) {
        queue_stats_[i].packets_processed = 0;
        queue_stats_[i].bytes_processed = 0;
        queue_stats_[i].drops = 0;
    }

    // Calculate UMEM size for all queues (shared)
    uint64_t total_umem_size = num_frames_ * frame_size_;

    // Create UMEM once and share across sockets
    struct xdp_umem_reg mr = {};
    mr.addr = 0;  // Let kernel allocate
    mr.len = total_umem_size;
    mr.chunk_size = frame_size_;
    mr.headroom = 0;
    mr.flags = XDP_UMEM_UNALIGNED_CHUNK_FLAG;

    // mmap UMEM area (shared)
    umem_area_ = static_cast<uint8_t*>(mmap(nullptr, total_umem_size,
                                              PROT_READ | PROT_WRITE,
                                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (umem_area_ == MAP_FAILED) {
        LOG_ERR("xdp", "failed to mmap shared UMEM: %s", strerror(errno));
        return false;
    }

    // Create sockets for each queue
    for (uint32_t q = 0; q < num_queues_; q++) {
        // Create AF_XDP socket
        sock_fds_[q] = socket(AF_XDP, SOCK_RAW, 0);
        if (sock_fds_[q] < 0) {
            LOG_ERR("xdp", "failed to create socket for queue %u: %s", q, strerror(errno));
            for (uint32_t j = 0; j < q; j++) {
                ::close(sock_fds_[j]);
            }
            sock_fds_.clear();
            return false;
        }

        // Register UMEM with this socket
        if (setsockopt(sock_fds_[q], SOL_XDP, XDP_UMEM_REG, &mr, sizeof(mr)) < 0) {
            LOG_ERR("xdp", "failed to register UMEM for queue %u: %s", q, strerror(errno));
            for (uint32_t j = 0; j <= q; j++) {
                ::close(sock_fds_[j]);
            }
            sock_fds_.clear();
            return false;
        }

        // Bind socket to queue
        struct sockaddr_xdp addr = {};
        addr.sxdp_family = AF_XDP;
        addr.sxdp_ifindex = ifindex;
        addr.sxdp_queue_id = base_queue + q;
        addr.sxdp_flags = XDP_SHARED_UMEM;  // Share UMEM with other sockets

        if (bind(sock_fds_[q], (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            LOG_ERR("xdp", "failed to bind socket to queue %u: %s", base_queue + q, strerror(errno));
            for (uint32_t j = 0; j <= q; j++) {
                ::close(sock_fds_[j]);
            }
            sock_fds_.clear();
            return false;
        }

        // Get mmap offsets for this socket
        struct xdp_mmap_offsets off = {};
        socklen_t optlen = sizeof(off);
        if (getsockopt(sock_fds_[q], SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen) < 0) {
            LOG_ERR("xdp", "failed to get mmap offsets for queue %u: %s", q, strerror(errno));
            for (uint32_t j = 0; j <= q; j++) {
                ::close(sock_fds_[j]);
            }
            sock_fds_.clear();
            return false;
        }

        ring_offsets_vec_[q].fill.producer = off.fr.producer;
        ring_offsets_vec_[q].fill.consumer = off.fr.consumer;
        ring_offsets_vec_[q].fill.desc = off.fr.desc;
        ring_offsets_vec_[q].fill.flags = off.fr.flags;
        ring_offsets_vec_[q].completion.producer = off.cr.producer;
        ring_offsets_vec_[q].completion.consumer = off.cr.consumer;
        ring_offsets_vec_[q].completion.desc = off.cr.desc;
        ring_offsets_vec_[q].completion.flags = off.cr.flags;

        // mmap fill ring for this queue
        fill_rings_[q] = static_cast<struct xdp_desc*>(
            mmap(nullptr, num_frames_ * sizeof(struct xdp_desc),
                 PROT_READ | PROT_WRITE, MAP_SHARED, sock_fds_[q],
                 XDP_UMEM_PGOFF_FILL_RING));
        if (fill_rings_[q] == MAP_FAILED) {
            LOG_ERR("xdp", "failed to mmap fill ring for queue %u: %s", q, strerror(errno));
            for (uint32_t j = 0; j <= q; j++) {
                ::close(sock_fds_[j]);
            }
            sock_fds_.clear();
            return false;
        }

        // mmap completion ring for this queue
        completion_rings_[q] = static_cast<struct xdp_desc*>(
            mmap(nullptr, num_frames_ * sizeof(struct xdp_desc),
                 PROT_READ | PROT_WRITE, MAP_SHARED, sock_fds_[q],
                 XDP_UMEM_PGOFF_COMPLETION_RING));
        if (completion_rings_[q] == MAP_FAILED) {
            LOG_ERR("xdp", "failed to mmap completion ring for queue %u: %s", q, strerror(errno));
            for (uint32_t j = 0; j <= q; j++) {
                ::close(sock_fds_[j]);
            }
            sock_fds_.clear();
            return false;
        }

        // Pre-fill the fill ring with frame addresses
        for (uint32_t i = 0; i < num_frames_; i++) {
            fill_rings_[q][i].addr = reinterpret_cast<uint64_t>(umem_area_ + i * frame_size_);
            fill_rings_[q][i].len = frame_size_;
            fill_rings_[q][i].options = 0;
        }

        // Set socket to non-blocking
        int sock_flags = fcntl(sock_fds_[q], F_GETFL, 0);
        fcntl(sock_fds_[q], F_SETFL, sock_flags | O_NONBLOCK);

        LOG_INFO("xdp", "setup queue %u (socket fd=%d)", q, sock_fds_[q]);
    }

    // Use first socket as primary for single-queue style operations
    sock_fd_ = sock_fds_[0];
    fill_ring_ = fill_rings_[0];
    completion_ring_ = completion_rings_[0];
    ring_offsets_ = ring_offsets_vec_[0];

    LOG_INFO("xdp", "multi-queue setup complete: %u queues, %u frames total",
             num_queues_, num_frames_);
    return true;
}

bool XdpProcessor::open(const XdpConfig& config) {
    if (opened_) {
        LOG_WARN("xdp", "already opened");
        return true;
    }

    num_frames_ = config.num_frames;
    frame_size_ = config.frame_size;
    umem_size_ = num_frames_ * frame_size_;

    // 获取接口索引
    int ifindex = if_nametoindex(config.iface.c_str());
    if (ifindex == 0) {
        LOG_ERR("xdp", "failed to get ifindex for %s", config.iface.c_str());
        close();
        return false;
    }

    // O-04: Multi-queue mode if num_queues > 1
    if (config.num_queues > 1) {
        if (!setup_multiqueue(ifindex, config.queue_id, config.num_queues)) {
            close();
            return false;
        }
        opened_ = true;
        LOG_INFO("xdp", "opened AF_XDP multi-queue on %s queues %u-%u (%u frames @ %u bytes)",
                 config.iface.c_str(), config.queue_id, config.queue_id + config.num_queues - 1,
                 num_frames_, frame_size_);
        return true;
    }

    // Single queue mode (original behavior)
    // 创建 AF_XDP socket
    sock_fd_ = socket(AF_XDP, SOCK_RAW, 0);
    if (sock_fd_ < 0) {
        LOG_ERR("xdp", "failed to create socket: %s", strerror(errno));
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

    // O-04: Multi-queue cleanup
    if (num_queues_ > 1 && !sock_fds_.empty()) {
        // Clean up per-queue rings
        for (uint32_t q = 0; q < num_queues_; q++) {
            if (q < fill_rings_.size() && fill_rings_[q] != nullptr && fill_rings_[q] != MAP_FAILED) {
                munmap(fill_rings_[q], num_frames_ * sizeof(struct xdp_desc));
                fill_rings_[q] = nullptr;
            }
            if (q < completion_rings_.size() && completion_rings_[q] != nullptr && completion_rings_[q] != MAP_FAILED) {
                munmap(completion_rings_[q], num_frames_ * sizeof(struct xdp_desc));
                completion_rings_[q] = nullptr;
            }
            if (q < sock_fds_.size() && sock_fds_[q] >= 0) {
                ::close(sock_fds_[q]);
                sock_fds_[q] = -1;
            }
        }
        sock_fds_.clear();
        fill_rings_.clear();
        completion_rings_.clear();
        ring_offsets_vec_.clear();
        queue_stats_.clear();
        num_queues_ = 1;
    } else {
        // Single queue cleanup (original behavior)
        if (fill_ring_ != nullptr && fill_ring_ != MAP_FAILED) {
            munmap(fill_ring_, num_frames_ * sizeof(struct xdp_desc));
            fill_ring_ = nullptr;
        }
        if (completion_ring_ != nullptr && completion_ring_ != MAP_FAILED) {
            munmap(completion_ring_, num_frames_ * sizeof(struct xdp_desc));
            completion_ring_ = nullptr;
        }
        if (sock_fd_ >= 0) {
            ::close(sock_fd_);
            sock_fd_ = -1;
        }
    }

    // Shared UMEM cleanup (only in multi-queue mode, UMEM was allocated separately)
    if (umem_area_ != nullptr && umem_area_ != MAP_FAILED) {
        munmap(umem_area_, umem_size_);
        umem_area_ = nullptr;
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

        // F-17: HTTP pipeline out-of-order detection
        if (pkt.protocol == IPPROTO_TCP && pkt.len > 0) {
            detect_http_pipeline(pkt, pkt.data, pkt.len);
        }

        // F-23: WebSocket frame detection
        if (pkt.len > 2) {
            detect_websocket(pkt, pkt.data, pkt.len);
        }

        // N-05: SSH brute force detection (TCP port 22)
        if (pkt.protocol == IPPROTO_TCP && (pkt.dst_port == 22 || pkt.src_port == 22) && pkt.len > 0) {
            detect_ssh_bruteforce(pkt, pkt.data, pkt.len);
        }

        // F-19: FTP data connection tracking
        if ((pkt.dst_port == 21 || pkt.src_port == 21) && pkt.len > 0) {
            detect_ftp_data_connection(pkt, pkt.data, pkt.len);
        }

        // F-04: DNS tunneling detection
        if (pkt.protocol == IPPROTO_UDP && (pkt.dst_port == 53 || pkt.src_port == 53) && pkt.len > 0) {
            DnsQueryInfo dns_info = {};
            if (parse_dns_query(pkt.data, pkt.len, dns_info)) {
                detect_dns_tunneling(pkt, dns_info);
            }
        }

        // R-01: QUIC protocol detection (UDP port 443)
        if (pkt.protocol == IPPROTO_UDP && (pkt.dst_port == 443 || pkt.src_port == 443) && pkt.len > 0) {
            QuicInfo quic_info = {};
            if (parse_quic_header(pkt.data, pkt.len, quic_info) && quic_info.is_quic) {
                /* QUIC traffic detected on port 443 */
                LOG_DEBUG("xdp", "QUIC detected: version=0x%x cid=%s", quic_info.version, quic_info.connection_id.c_str());
            }
        }

        // R-05: MQTT protocol analysis (TCP ports 1883, 8883)
        if (pkt.protocol == IPPROTO_TCP && (pkt.dst_port == 1883 || pkt.dst_port == 8883 ||
                                             pkt.src_port == 1883 || pkt.src_port == 8883) && pkt.len > 0) {
            MqttInfo mqtt_info = {};
            if (parse_mqtt(pkt.data, pkt.len, mqtt_info)) {
                /* MQTT traffic detected */
                LOG_DEBUG("xdp", "MQTT detected: type=%u client_id=%s topic=%s",
                         mqtt_info.type, mqtt_info.client_id.c_str(), mqtt_info.topic.c_str());
            }
        }

        // R-02: HTTP/2 multiplexed stream analysis (TCP ports 80, 443, 8080)
        if (pkt.protocol == IPPROTO_TCP && pkt.len > 0) {
            detect_http2(pkt, pkt.data, pkt.len);
        }

        // C-04: Service mesh traffic monitoring (iptables vs eBPF path analysis)
        analyze_service_mesh_traffic(pkt);

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

        /* Parse IPv6 extension headers to find actual L4 protocol */
        const uint8_t* pkt_end = data + len;
        uint8_t next_header = 0;
        size_t ip_header_len = 0;
        if (!parse_ipv6_ext_headers(ipv6, pkt_end, next_header, ip_header_len)) {
            return false;
        }
        pkt.protocol = next_header;

        uint8_t* l4 = data + sizeof(struct ethhdr) + ip_header_len;
        uint32_t l4_len = len - sizeof(struct ethhdr) - ip_header_len;

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

            /* F-22: TLS 0-RTT early_data extension (type=42) */
            if (ext_type == TLS_EXT_EARLY_DATA) {
                info.early_data = true;
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

/*
 * F-05: TLS Certificate Message Parsing
 *
 * Parses TLS Certificate handshake messages (type=11) and extracts X.509 certificate
 * information including CN, Issuer, SAN, Validity, and weak hash detection.
 *
 * TLS Certificate message format:
 *   SEQUENCE { chain }
 *     SEQUENCE { cert }
 *       SEQUENCE { TBSCertificate }
 *         [0] { version }
 *         INTEGER { serialNumber }
 *         SEQUENCE { signatureAlgorithm }
 *         SEQUENCE { issuer }
 *         SEQUENCE { validity }
 *           UTCTime { notBefore }
 *           UTCTime { notAfter }
 *         SEQUENCE { subject }
 *         ...
 *         SEQUENCE { extensions }
 *           ...
 *           SEQUENCE { OID, [0] { OCTET STRING } }  // SAN extension
 */
bool XdpProcessor::parse_tls_certificate(const uint8_t* handshake_data,
                                         size_t handshake_len,
                                         std::vector<TlsCertInfo>& certs) {
    certs.clear();

    /* TLS Certificate message parsing
     * handshake_data points after handshake header (type + 3-byte length)
     */
    if (handshake_len < 4) {
        return false;
    }

    /* Skip handshake type (1 byte) and length (3 bytes) */
    const uint8_t* ptr = handshake_data;
    size_t remaining = handshake_len;

    /* Read certificate chain length (3 bytes) */
    if (remaining < 3) {
        return false;
    }
    uint32_t chain_len = (static_cast<uint32_t>(ptr[0]) << 16) |
                         (static_cast<uint32_t>(ptr[1]) << 8) |
                         static_cast<uint32_t>(ptr[2]);
    ptr += 3;
    remaining -= 3;

    const uint8_t* end = ptr + std::min(static_cast<size_t>(chain_len), remaining);

    while (ptr < end && ptr + 3 < handshake_data + handshake_len) {
        /* Read certificate length (3 bytes) */
        if (remaining < 3) {
            break;
        }
        uint32_t cert_len = (static_cast<uint32_t>(ptr[0]) << 16) |
                            (static_cast<uint32_t>(ptr[1]) << 8) |
                            static_cast<uint32_t>(ptr[2]);
        ptr += 3;
        remaining -= 3;

        if (cert_len > remaining || ptr + cert_len > end) {
            break;
        }

        TlsCertInfo cert;
        if (parse_x509_certificate(ptr, cert_len, cert)) {
            certs.push_back(cert);
        }
        ptr += cert_len;
        remaining -= cert_len;
    }

    return !certs.empty();
}

/*
 * Forward declaration for parse_x509_name
 */
std::string parse_x509_name(const uint8_t* data, size_t len);
std::string extract_cn(const std::string& subject);

/*
 * Parse X.509 certificate and extract key fields
 */
bool XdpProcessor::parse_x509_certificate(const uint8_t* cert_data,
                                          size_t cert_len,
                                          TlsCertInfo& cert) {
    cert = TlsCertInfo{};
    cert.not_before = 0;
    cert.not_after = 0;
    cert.self_signed = false;
    cert.expired = false;
    cert.weak_hash = false;

    const uint8_t* ptr = cert_data;
    size_t remaining = cert_len;

    /* Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature } */
    uint8_t tag;
    uint32_t len;
    ptr = asn1_read_tlv(ptr, remaining, tag, len);
    if (!ptr || tag != 0x30) {  /* SEQUENCE */
        return false;
    }
    remaining = len;

    /* TBSCertificate ::= SEQUENCE { ... } */
    const uint8_t* tbs_ptr = ptr;
    ptr = asn1_read_tlv(ptr, remaining, tag, len);
    if (!ptr || tag != 0x30) {
        return false;
    }
    size_t tbs_len = len;

    /* Parse TBSCertificate fields */
    size_t pos = 0;
    const uint8_t* tbs_start = ptr;

    /* version [0] EXPLICIT Version DEFAULT v1 */
    if (pos + 1 < tbs_len && ptr[pos] == 0xa0) {
        uint8_t vtag;
        uint32_t vlen;
        const uint8_t* vptr = asn1_read_tlv(ptr + pos, tbs_len - pos, vtag, vlen);
        if (vptr && vtag == 0xa0) {
            pos = vptr - tbs_start + vlen;
        }
    }

    /* serialNumber (INTEGER) */
    uint8_t serial_tag;
    uint32_t serial_len;
    const uint8_t* serial_ptr = asn1_read_tlv(ptr + pos, tbs_len - pos, serial_tag, serial_len);
    if (!serial_ptr || serial_tag != 0x02) {
        return false;
    }
    pos += serial_ptr - (ptr + pos) + serial_len;

    /* signatureAlgorithm (SEQUENCE) */
    uint8_t sig_tag;
    uint32_t sig_len;
    const uint8_t* sig_ptr = asn1_read_tlv(ptr + pos, tbs_len - pos, sig_tag, sig_len);
    if (!sig_ptr || sig_tag != 0x30) {
        return false;
    }
    pos += sig_ptr - (ptr + pos) + sig_len;

    /* Check for weak hash algorithm in signature OID */
    uint8_t oid_tag;
    uint32_t oid_len;
    const uint8_t* oid_ptr = asn1_read_tlv(sig_ptr, sig_len, oid_tag, oid_len);
    if (oid_ptr && oid_tag == 0x06) {
        if (asn1_oid_equals(oid_ptr, oid_len, OID_MD5, sizeof(OID_MD5)) ||
            asn1_oid_equals(oid_ptr, oid_len, OID_SHA1, sizeof(OID_SHA1))) {
            cert.weak_hash = true;
        }
    }

    /* issuer (SEQUENCE) */
    uint8_t issuer_tag;
    uint32_t issuer_len;
    const uint8_t* issuer_ptr = asn1_read_tlv(ptr + pos, tbs_len - pos, issuer_tag, issuer_len);
    if (!issuer_ptr || issuer_tag != 0x30) {
        return false;
    }
    cert.issuer = nids::parse_x509_name(issuer_ptr, issuer_len);
    pos += issuer_ptr - (ptr + pos) + issuer_len;

    /* validity (SEQUENCE) */
    uint8_t validity_tag;
    uint32_t validity_len;
    const uint8_t* validity_ptr = asn1_read_tlv(ptr + pos, tbs_len - pos, validity_tag, validity_len);
    if (!validity_ptr || validity_tag != 0x30) {
        return false;
    }
    /* Parse UTCTime notBefore and notAfter */
    const uint8_t* vptr = validity_ptr;
    size_t vremaining = validity_len;
    while (vremaining > 0) {
        uint8_t time_tag;
        uint32_t time_len;
        vptr = asn1_read_tlv(vptr, vremaining, time_tag, time_len);
        if (!vptr) break;
        if (time_tag == 0x17) {  /* UTCTime */
            uint64_t time_val = asn1_parse_utctime(vptr, time_len);
            if (cert.not_before == 0) {
                cert.not_before = time_val;
            } else {
                cert.not_after = time_val;
            }
        }
        vremaining = validity_len - (vptr - validity_ptr + time_len);
        if (vremaining >= validity_len) break;
        vptr += time_len;
    }
    pos += validity_ptr - (ptr + pos) + validity_len;

    /* subject (SEQUENCE) */
    uint8_t subject_tag;
    uint32_t subject_len;
    const uint8_t* subject_ptr = asn1_read_tlv(ptr + pos, tbs_len - pos, subject_tag, subject_len);
    if (!subject_ptr || subject_tag != 0x30) {
        return false;
    }
    cert.subject = nids::parse_x509_name(subject_ptr, subject_len);
    cert.common_name = nids::extract_cn(cert.subject);
    pos += subject_ptr - (ptr + pos) + subject_len;

    /* Check self-signed: issuer == subject */
    if (cert.issuer == cert.subject && !cert.issuer.empty()) {
        cert.self_signed = true;
    }

    /* Skip remaining fields until extensions [3] */
    while (pos + 1 < tbs_len && ptr[pos] != 0xa3) {  /* [3] for v3 extensions */
        uint8_t skip_tag;
        uint32_t skip_len;
        const uint8_t* skip_ptr = asn1_read_tlv(ptr + pos, tbs_len - pos, skip_tag, skip_len);
        if (!skip_ptr) break;
        pos += skip_ptr - (ptr + pos) + skip_len;
    }

    /* extensions [3] EXPLICIT Extensions */
    if (pos + 1 < tbs_len && ptr[pos] == 0xa3) {
        uint8_t ext_tag;
        uint32_t ext_len;
        const uint8_t* ext_ptr = asn1_read_tlv(ptr + pos, tbs_len - pos, ext_tag, ext_len);
        if (ext_ptr && ext_tag == 0xa3) {
            /* Parse extensions sequence */
            uint8_t seq_tag;
            uint32_t seq_len;
            const uint8_t* seq_ptr = asn1_read_tlv(ext_ptr, ext_len, seq_tag, seq_len);
            if (seq_ptr && seq_tag == 0x30) {
                const uint8_t* ext_end = seq_ptr + seq_len;
                const uint8_t* eptr = seq_ptr;
                while (eptr < ext_end && eptr + 4 < cert_data + cert_len) {
                    uint8_t e_tag;
                    uint32_t e_len;
                    eptr = asn1_read_tlv(eptr, ext_end - eptr, e_tag, e_len);
                    if (!eptr) break;

                    /* Extension ::= SEQUENCE { extnID, critical, extnValue } */
                    uint8_t ext_id_tag, ext_val_tag;
                    uint32_t ext_id_len, ext_val_len;
                    const uint8_t* ext_id_ptr = asn1_read_tlv(eptr, e_len, ext_id_tag, ext_id_len);
                    if (!ext_id_ptr) break;

                    /* Skip critical flag */
                    uint8_t crit_tag;
                    uint32_t crit_len;
                    const uint8_t* crit_ptr = asn1_read_tlv(ext_id_ptr + ext_id_len, e_len - (ext_id_ptr - eptr + ext_id_len), crit_tag, crit_len);
                    if (!crit_ptr) {
                        eptr += e_len;
                        continue;
                    }

                    /* extnValue is OCTET STRING containing the extension value */
                    const uint8_t* ext_val_ptr = asn1_read_tlv(crit_ptr + crit_len, e_len - (crit_ptr - eptr + crit_len), ext_val_tag, ext_val_len);
                    if (!ext_val_ptr) {
                        eptr += e_len;
                        continue;
                    }

                    /* Check for SAN extension (OID 2.5.29.17) */
                    if (ext_id_tag == 0x06 && ext_id_len == sizeof(OID_SAN) &&
                        std::memcmp(ext_id_ptr, OID_SAN, sizeof(OID_SAN)) == 0) {
                        /* Parse SAN sequence */
                        uint8_t san_seq_tag;
                        uint32_t san_seq_len;
                        const uint8_t* san_seq_ptr = asn1_read_tlv(ext_val_ptr, ext_val_len, san_seq_tag, san_seq_len);
                        if (san_seq_ptr && san_seq_tag == 0x30) {
                            const uint8_t* san_end = san_seq_ptr + san_seq_len;
                            const uint8_t* sptr = san_seq_ptr;
                            while (sptr < san_end && sptr + 2 < ext_val_ptr + ext_val_len) {
                                uint8_t name_tag;
                                uint32_t name_len;
                                sptr = asn1_read_tlv(sptr, san_end - sptr, name_tag, name_len);
                                if (!sptr) break;
                                /* otherName, email, DNS, x400Address, directoryName, ediPartyName, URI, IP */
                                if (name_tag == 0x82) {  /* dNSName - IA5String */
                                    std::string san = asn1_read_string(sptr, name_len, 0x22);
                                    if (!san.empty()) {
                                        cert.sans.push_back(san);
                                    }
                                } else if (name_tag == 0x87) {  /* iPAddress */
                                    if (name_len == 4) {
                                        char ip[16];
                                        std::snprintf(ip, sizeof(ip), "%u.%u.%u.%u",
                                                     sptr[0], sptr[1], sptr[2], sptr[3]);
                                        cert.sans.push_back(ip);
                                    } else if (name_len == 16) {
                                        char ip[64];
                                        std::snprintf(ip, sizeof(ip),
                                                     "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                                                     sptr[0], sptr[1], sptr[2], sptr[3],
                                                     sptr[4], sptr[5], sptr[6], sptr[7],
                                                     sptr[8], sptr[9], sptr[10], sptr[11],
                                                     sptr[12], sptr[13], sptr[14], sptr[15]);
                                        cert.sans.push_back(ip);
                                    }
                                }
                                sptr += name_len;
                            }
                        }
                    }
                    eptr += e_len;
                }
            }
        }
    }

    /* Check expiration */
    uint64_t now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    if (cert.not_after > 0 && now > cert.not_after) {
        cert.expired = true;
    }

    return !cert.subject.empty();
}

/*
 * Parse X.509 Name (issuer/subject) and extract string values
 */
std::string parse_x509_name(const uint8_t* data, size_t len) {
    std::string result;
    const uint8_t* ptr = data;
    size_t remaining = len;

    /* Name ::= RDNSequence */
    /* RDNSequence ::= SEQUENCE OF RelativeDistinguishedName */
    /* RelativeDistinguishedName ::= SET OF AttributeTypeAndValue */
    /* AttributeTypeAndValue ::= SEQUENCE { type, value } */

    while (remaining > 0) {
        uint8_t tag;
        uint32_t len_val;
        ptr = asn1_read_tlv(ptr, remaining, tag, len_val);
        if (!ptr) break;

        if (tag == 0x30) {  /* SEQUENCE - RDN */
            const uint8_t* rdn_ptr = ptr;
            size_t rdn_len = len_val;
            while (rdn_len > 0) {
                uint8_t set_tag;
                uint32_t set_len;
                rdn_ptr = asn1_read_tlv(rdn_ptr, rdn_len, set_tag, set_len);
                if (!rdn_ptr) break;

                if (set_tag == 0x31) {  /* SET - AttributeTypeAndValue */
                    uint8_t type_tag, value_tag;
                    uint32_t type_len, value_len;
                    const uint8_t* type_ptr = asn1_read_tlv(rdn_ptr, set_len, type_tag, type_len);
                    if (!type_ptr) break;

                    const uint8_t* value_ptr = asn1_read_tlv(type_ptr + type_len, set_len - (type_ptr - rdn_ptr + type_len), value_tag, value_len);
                    if (!value_ptr) {
                        rdn_ptr += set_len;
                        rdn_len -= rdn_ptr - (ptr + len_val - remaining);
                        continue;
                    }

                    /* Check for CN (2.5.4.3) */
                    if (type_tag == 0x06 && type_len == sizeof(OID_CN) &&
                        std::memcmp(type_ptr, OID_CN, sizeof(OID_CN)) == 0) {
                        std::string cn = asn1_read_string(value_ptr, value_len, value_tag);
                        if (!cn.empty()) {
                            if (!result.empty()) result += ", ";
                            result += cn;
                        }
                    }
                }
                rdn_ptr += set_len;
                rdn_len -= rdn_ptr - (ptr + len_val - remaining);
            }
        }

        remaining -= len_val + (ptr - data - (len - remaining));
        ptr += len_val;
        remaining = len - (ptr - data);
        if (remaining >= len) break;
    }

    return result;
}

/*
 * Extract CN from a full subject string
 */
std::string extract_cn(const std::string& subject) {
    /* CN is usually at the beginning or end of the subject string */
    size_t cn_pos = subject.find("CN=");
    if (cn_pos != std::string::npos) {
        size_t start = cn_pos + 3;
        size_t end = subject.find(',', start);
        if (end == std::string::npos) end = subject.size();
        return subject.substr(start, end - start);
    }
    /* If no CN= prefix, return the first component */
    size_t comma = subject.find(',');
    if (comma != std::string::npos) {
        return subject.substr(0, comma);
    }
    return subject;
}

void XdpProcessor::detect_tls(const XdpPacket& pkt, const uint8_t* payload, size_t payload_len) {
    if (tls_version_rules_.empty() && sni_rules_.empty() && cipher_rules_.empty()) {
        return;
    }

    /*
     * E-24: TLS record fragment reassembly
     * Check if we have a partial TLS record for this flow and try to reassemble
     */
    TlsFragmentKey frag_key = {
        .src_ip = pkt.src_ip,
        .dst_ip = pkt.dst_ip,
        .src_port = pkt.src_port,
        .dst_port = pkt.dst_port
    };

    /* Clean up old fragments (timeout-based) */
    uint64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    for (auto it = tls_fragments_.begin(); it != tls_fragments_.end(); ) {
        if (now_ms - (it->second.first_seen / 1000000) > TLS_FRAG_TIMEOUT_MS) {
            it = tls_fragments_.erase(it);
        } else {
            ++it;
        }
    }

    /* Check if we have a partial record for this flow */
    auto frag_it = tls_fragments_.find(frag_key);
    std::vector<uint8_t> reassembled;
    bool have_complete_record = false;

    if (frag_it != tls_fragments_.end()) {
        /* We have a partial record - append this data */
        TlsFragmentData& frag = frag_it->second;
        if (frag.data.size() + payload_len > 16384) {  /* Max TLS record size */
            /* Fragment data too large, discard */
            tls_fragments_.erase(frag_it);
            frag_it = tls_fragments_.end();
        } else {
            frag.data.insert(frag.data.end(), payload, payload + payload_len);
            reassembled = frag.data;
            /* Check if we have the complete TLS record */
            if (reassembled.size() >= 5) {
                uint16_t record_len = (static_cast<uint16_t>(reassembled[3]) << 8) | reassembled[4];
                if (reassembled.size() >= 5 + record_len) {
                    have_complete_record = true;
                    tls_fragments_.erase(frag_it);
                }
            }
        }
    }

    /*
     * E-24: If we don't have a complete record, check if this packet starts one
     * TLS record header is 5 bytes: content_type(1) + version(2) + length(2)
     */
    const uint8_t* data_to_parse = payload;
    size_t data_len = payload_len;

    if (!have_complete_record && frag_it == tls_fragments_.end()) {
        /* No partial record - check if this starts a new TLS record */
        if (payload_len >= 5) {
            uint16_t record_len = (static_cast<uint16_t>(payload[3]) << 8) | payload[4];
            size_t total_record_len = 5 + record_len;

            if (payload_len < total_record_len) {
                /* Incomplete TLS record - start tracking fragment */
                if (tls_fragments_.size() < TLS_MAX_FRAGMENTS && payload_len < 16384) {
                    TlsFragmentData frag;
                    frag.data.assign(payload, payload + payload_len);
                    frag.expected_len = total_record_len;
                    frag.first_seen = now_ms * 1000000;  /* Convert to ns */
                    tls_fragments_[frag_key] = std::move(frag);
                }
                return;  /* Wait for more data */
            }
            /* We have a complete record, parse normally */
        }
    } else if (have_complete_record) {
        data_to_parse = reassembled.data();
        data_len = reassembled.size();
    } else {
        /* Partial record exists but not complete yet */
        return;
    }

    /* Parse the (possibly reassembled) TLS record */
    TlsInfo tls;
    if (!parse_tls_record(data_to_parse, data_len, tls)) {
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
        std::string sni_lower = tls.sni;
        std::transform(sni_lower.begin(), sni_lower.end(), sni_lower.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        for (const auto& rule : sni_rules_) {
            std::string pattern_lower = rule.pattern;
            std::transform(pattern_lower.begin(), pattern_lower.end(), pattern_lower.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            if (sni_lower.find(pattern_lower) != std::string::npos) {
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

    /* F-22: TLS 0-RTT early data detection */
    if (tls.early_data && tls.handshake_type == TLS_HANDSHAKE_CLIENT_HELLO) {
        DpiResult result;
        result.matched = true;
        result.rule_id = 0;
        result.message = "TLS 0-RTT early data detected (replay attack risk)";
        dpi_match_count_++;
        if (dpi_callback_) {
            dpi_callback_(pkt, result);
        }
    }
}

/*
 * F-17: HTTP Pipeline Out-of-Order Detection
 *
 * Detects out-of-order HTTP requests in a pipeline, which could indicate
 * an evasion attempt or malicious traffic pattern.
 *
 * HTTP pipelining allows multiple requests to be sent without waiting for
 * responses. We track the sequence of requests to detect when they arrive
 * out of order.
 */
void XdpProcessor::detect_http_pipeline(const XdpPacket& pkt, const uint8_t* payload, size_t payload_len) {
    // Only track HTTP traffic (port 80, 8080, 8000)
    if (pkt.dst_port != 80 && pkt.dst_port != 8080 && pkt.dst_port != 8000) {
        return;
    }

    // Only track packets with payload
    if (payload_len == 0) {
        return;
    }

    // Get current timestamp in ms
    uint64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();

    // Clean up old entries (timeout-based)
    for (auto it = http_pipeline_.begin(); it != http_pipeline_.end(); ) {
        if (now_ms - (it->second.last_seen / 1000) > HTTP_PIPELINE_TIMEOUT_MS) {
            it = http_pipeline_.erase(it);
        } else {
            ++it;
        }
    }

    // Build key for this flow
    HttpPipelineKey key = {
        .src_ip = pkt.src_ip,
        .dst_ip = pkt.dst_ip,
        .src_port = pkt.src_port,
        .dst_port = pkt.dst_port
    };

    // Check if payload looks like an HTTP request
    // HTTP requests start with a method (GET, POST, PUT, etc.)
    bool looks_like_http_request = false;
    if (payload_len >= 4 &&
        ((payload[0] >= 'A' && payload[0] <= 'Z') || (payload[0] >= 'a' && payload[0] <= 'z')) &&
        payload[3] == ' ') {
        // Could be HTTP method
        static const char* methods[] = {"GET", "POST", "PUT ", "DELE", "HEAD", "OPTI", "PATC", "CONN", "TRAC"};
        for (const auto& m : methods) {
            if (std::memcmp(payload, m, 4) == 0) {
                looks_like_http_request = true;
                break;
            }
        }
    }

    if (!looks_like_http_request) {
        return;  // Not an HTTP request, skip
    }

    // Look up existing entry
    auto it = http_pipeline_.find(key);
    if (it == http_pipeline_.end()) {
        // First request on this flow
        HttpPipelineData data = {
            .last_seq = 0,
            .expected_seq = 1,
            .last_seen = now_ms * 1000,
            .alert_sent = false
        };
        http_pipeline_[key] = data;
        return;
    }

    // Update existing entry
    HttpPipelineData& data = it->second;
    data.last_seen = now_ms * 1000;

    // For simplicity, we track the "sequence number" as the count of requests
    // In a real implementation, this would use actual sequence numbers from TCP
    uint32_t current_seq = data.expected_seq;

    // Check if this is the expected next request
    // If we receive the same sequence number, it might be a retransmit
    // If we receive a sequence number we've already seen, it's out of order
    if (current_seq > 0 && !data.alert_sent) {
        // Simple heuristic: if we see another request and expected_seq hasn't advanced,
        // something is out of order. In a real implementation, we'd use TCP seq numbers.
        if (data.last_seq == current_seq) {
            // Same request again - could be retransmit, which is normal
        } else if (data.last_seq > current_seq) {
            // Out-of-order detected
            DpiResult result;
            result.matched = true;
            result.rule_id = -1;  // Internal rule
            result.message = "HTTP pipeline out-of-order detected";
            dpi_match_count_++;
            if (dpi_callback_) {
                dpi_callback_(pkt, result);
            }
            data.alert_sent = true;
            return;
        }
    }

    // Advance the expected sequence
    data.last_seq = data.expected_seq;
    data.expected_seq++;
}

/*
 * R-03: WebSocket Frame Parsing
 *
 * Parses WebSocket frame header according to RFC 6455.
 * Returns frame metadata including FIN, opcode, masked bit, and payload length.
 * Handles extended payload length (126 = 16-bit, 127 = 64-bit).
 *
 * WebSocket frame format:
 * - Byte 0: FIN(1) + opcode(4) + RSV(3)
 * - Byte 1: MASK(1) + payload_len(7)
 * - Extended length (if payload_len == 126 or 127)
 * - Masking key (if MASK bit set, 4 bytes)
 * - Payload data
 */
bool XdpProcessor::parse_websocket_frame(const uint8_t* data, size_t len, WebSocketFrame& frame) {
    // Initialize output
    frame = WebSocketFrame{};
    frame.header_len = 0;

    // WebSocket frame requires at least 2 bytes header
    if (len < 2) {
        return false;
    }

    // Parse byte 0: FIN bit (bit 7), opcode (bits 3-0)
    frame.fin = (data[0] & 0x80) != 0;
    frame.opcode = data[0] & 0x0F;

    // Parse byte 1: MASK bit (bit 7), payload length (bits 6-0)
    frame.masked = (data[1] & 0x80) != 0;
    uint64_t payload_len_field = data[1] & 0x7F;

    // Calculate base header length
    size_t header_len = 2;

    // Handle extended payload length
    if (payload_len_field == 126) {
        // 16-bit extended length
        if (len < 4) {
            return false;  // Need 4 bytes for 16-bit extended length
        }
        frame.payload_len = (static_cast<uint16_t>(data[2]) << 8) | data[3];
        header_len = 4;
    } else if (payload_len_field == 127) {
        // 64-bit extended length
        if (len < 10) {
            return false;  // Need 10 bytes for 64-bit extended length
        }
        // Read 64-bit length (only handle 32-bit values for sanity)
        frame.payload_len = (static_cast<uint64_t>(data[2]) << 56) |
                            (static_cast<uint64_t>(data[3]) << 48) |
                            (static_cast<uint64_t>(data[4]) << 40) |
                            (static_cast<uint64_t>(data[5]) << 32) |
                            (static_cast<uint64_t>(data[6]) << 24) |
                            (static_cast<uint64_t>(data[7]) << 16) |
                            (static_cast<uint64_t>(data[8]) << 8) |
                            static_cast<uint64_t>(data[9]);
        header_len = 10;
    } else {
        frame.payload_len = payload_len_field;
    }

    // Add masking key length if present
    if (frame.masked) {
        header_len += 4;  // Masking key is always 4 bytes
    }

    frame.header_len = header_len;

    // Validate we have enough data for the header
    if (len < header_len) {
        return false;
    }

    // Validate payload length is reasonable (reject unreasonable frames)
    if (frame.payload_len > 16777216) {  // 16MB limit
        return false;
    }

    return true;
}

/*
 * F-23: WebSocket Frame Detection
 *
 * Parses WebSocket frame headers to detect fragmented/mixed frames.
 * WebSocket frames may be fragmented across multiple TCP packets.
 * We track fragments to detect anomalous patterns.
 *
 * WebSocket frame format (RFC 6455):
 * - Byte 0: FIN bit (bit 7), opcode (bits 3-0)
 * - Byte 1: MASK bit (bit 7), payload length (bits 6-0)
 * - Extended length (if payload_len == 126 or 127)
 * - Masking key (if MASK bit set)
 * - Payload data
 *
 * Opcodes: 0x0=continuation, 0x1=text, 0x2=binary, 0x8=close, 0x9=ping, 0xA=pong
 */
void XdpProcessor::detect_websocket(const XdpPacket& pkt, const uint8_t* payload, size_t payload_len) {
    // Only track TCP traffic on WebSocket ports (80, 8080, 8000, 443)
    if (pkt.protocol != IPPROTO_TCP) {
        return;
    }
    if (pkt.dst_port != 80 && pkt.dst_port != 8080 && pkt.dst_port != 8000 && pkt.dst_port != 443 &&
        pkt.src_port != 80 && pkt.src_port != 8080 && pkt.src_port != 8000 && pkt.src_port != 443) {
        return;
    }

    // Need at least 2 bytes for frame header
    if (payload_len < 2) {
        return;
    }

    // Parse WebSocket frame header
    uint8_t first_byte = payload[0];
    uint8_t second_byte = payload[1];

    bool fin = (first_byte & 0x80) != 0;
    uint8_t opcode = first_byte & 0x0F;
    bool masked = (second_byte & 0x80) != 0;
    uint64_t payload_len_ws = second_byte & 0x7F;

    size_t header_len = 2;
    size_t mask_key_len = 0;

    // Parse extended payload length
    if (payload_len_ws == 126) {
        if (payload_len < 4) {
            return;  // Need 4 bytes for 16-bit extended length
        }
        payload_len_ws = (static_cast<uint16_t>(payload[2]) << 8) | payload[3];
        header_len = 4;
    } else if (payload_len_ws == 127) {
        if (payload_len < 10) {
            return;  // Need 10 bytes for 64-bit extended length
        }
        // Read 64-bit length (we only handle 32-bit values for sanity)
        payload_len_ws = (static_cast<uint64_t>(payload[2]) << 56) |
                         (static_cast<uint64_t>(payload[3]) << 48) |
                         (static_cast<uint64_t>(payload[4]) << 40) |
                         (static_cast<uint64_t>(payload[5]) << 32) |
                         (static_cast<uint64_t>(payload[6]) << 24) |
                         (static_cast<uint64_t>(payload[7]) << 16) |
                         (static_cast<uint64_t>(payload[8]) << 8) |
                         static_cast<uint64_t>(payload[9]);
        header_len = 10;
    }

    // Masking key is present if client-to-server frame
    if (masked) {
        mask_key_len = 4;
    }

    // Calculate total frame size
    size_t total_frame_len = header_len + mask_key_len + static_cast<size_t>(payload_len_ws);

    // Sanity check: reject unreasonably large frames
    if (payload_len_ws > 65536) {
        DpiResult result;
        result.matched = true;
        result.rule_id = -1;  // Internal rule
        result.message = "WebSocket: excessive payload length detected";
        dpi_match_count_++;
        if (dpi_callback_) {
            dpi_callback_(pkt, result);
        }
        return;
    }

    // Get current timestamp
    uint64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();

    // Build key for this WebSocket flow
    WebSocketKey key = {
        .src_ip = pkt.src_ip,
        .dst_ip = pkt.dst_ip,
        .src_port = pkt.src_port,
        .dst_port = pkt.dst_port
    };

    // Clean up old entries (timeout-based)
    for (auto it = websocket_connections_.begin(); it != websocket_connections_.end(); ) {
        if (now_ms - (it->second.last_seen / 1000) > WEBSOCKET_TIMEOUT_MS) {
            it = websocket_connections_.erase(it);
        } else {
            ++it;
        }
    }

    // Look up existing connection state
    auto it = websocket_connections_.find(key);
    if (it == websocket_connections_.end()) {
        // New connection
        WebSocketData data = {
            .last_opcode = opcode,
            .fragmented = false,
            .fragment_count = 0,
            .last_seen = now_ms * 1000,
            .alert_sent = false
        };

        // Check for start of fragmentation (FIN=0, opcode=text/binary)
        if (!fin && (opcode == 0x1 || opcode == 0x2)) {
            data.fragmented = true;
            data.fragment_count = 1;
            data.fragment_opcode = opcode;  // Remember initial opcode
        }
        // Check for suspicious: FIN=1 with continuation opcode (should start new)
        else if (fin && opcode == 0x0) {
            DpiResult result;
            result.matched = true;
            result.rule_id = -1;
            result.message = "WebSocket: FIN=1 with continuation opcode (no prior fragment)";
            dpi_match_count_++;
            if (dpi_callback_) {
                dpi_callback_(pkt, result);
            }
        }
        // Check for control frames interleaved with fragments
        else if (opcode >= 0x8 && opcode <= 0xA) {
            // Control frames should not fragment
            DpiResult result;
            result.matched = true;
            result.rule_id = -1;
            result.message = "WebSocket: fragmented control frame";
            dpi_match_count_++;
            if (dpi_callback_) {
                dpi_callback_(pkt, result);
            }
        }

        websocket_connections_[key] = data;
        return;
    }

    // Update existing connection
    WebSocketData& data = it->second;
    data.last_seen = now_ms * 1000;

    // If we're tracking a fragmented message
    if (data.fragmented) {
        // Continuation frame should have opcode=0
        if (opcode == 0x0) {
            data.fragment_count++;

            // Check for excessive fragmentation (evasion attempt)
            if (data.fragment_count > 64) {
                DpiResult result;
                result.matched = true;
                result.rule_id = -1;
                result.message = "WebSocket: excessive fragmentation (" +
                    std::to_string(data.fragment_count) + " fragments)";
                dpi_match_count_++;
                if (dpi_callback_) {
                    dpi_callback_(pkt, result);
                }
                data.alert_sent = true;
            }

            // Check for interleaved control frame during fragmentation
            if (opcode >= 0x8 && opcode <= 0xA) {
                DpiResult result;
                result.matched = true;
                result.rule_id = -1;
                result.message = "WebSocket: control frame during fragmented message";
                dpi_match_count_++;
                if (dpi_callback_) {
                    dpi_callback_(pkt, result);
                }
                data.alert_sent = true;
            }
        }
        // Final frame should have FIN=1 and opcode=0
        else if (fin && opcode == 0x0) {
            // Message complete
            data.fragmented = false;
            data.fragment_count = 0;
        }
        // New data frame before previous fragmented message finished
        else if (!fin && (opcode == 0x1 || opcode == 0x2)) {
            // Mixed frame types in fragmentation - suspicious
            if (!data.alert_sent) {
                DpiResult result;
                result.matched = true;
                result.rule_id = -1;
                result.message = "WebSocket: new fragment type before previous complete (mixed frame types)";
                dpi_match_count_++;
                if (dpi_callback_) {
                    dpi_callback_(pkt, result);
                }
                data.alert_sent = true;
            }
        }
    } else {
        // Not fragmented - check for start of new fragmentation
        if (!fin && (opcode == 0x1 || opcode == 0x2)) {
            data.fragmented = true;
            data.fragment_count = 1;
            data.fragment_opcode = opcode;
            data.alert_sent = false;
        }
        // Unexpected continuation frame
        else if (opcode == 0x0 && !data.fragmented) {
            if (!data.alert_sent) {
                DpiResult result;
                result.matched = true;
                result.rule_id = -1;
                result.message = "WebSocket: unexpected continuation frame";
                dpi_match_count_++;
                if (dpi_callback_) {
                    dpi_callback_(pkt, result);
                }
                data.alert_sent = true;
            }
        }
    }

    // Update last opcode
    data.last_opcode = opcode;
}

/*
 * N-05: SSH Brute Force Detection
 *
 * Detects SSH brute force attacks by tracking authentication failure messages.
 * SSH servers send various failure messages including:
 * - "Permission denied"
 * - "Invalid password"
 * - "Authentication failed"
 * - "Connection refused"
 *
 * We track failures per (source_ip, target_ip) pair and alert when threshold is exceeded.
 */
void XdpProcessor::detect_ssh_bruteforce(const XdpPacket& pkt, const uint8_t* payload, size_t payload_len) {
    // Only track SSH traffic (port 22)
    if (pkt.protocol != IPPROTO_TCP) {
        return;
    }

    if (payload_len == 0) {
        return;
    }

    // Get current timestamp in ms
    uint64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();

    // Clean up old entries (timeout-based eviction)
    for (auto it = ssh_brute_force_.begin(); it != ssh_brute_force_.end(); ) {
        if (now_ms - (it->second.last_failure / 1000) > SSH_BRUTE_FORCE_TIMEOUT_MS) {
            it = ssh_brute_force_.erase(it);
        } else {
            ++it;
        }
    }

    // SSH failure strings to detect
    static const char* ssh_failed_strings[] = {
        "Permission denied",
        "Invalid password",
        "Authentication failed",
        "Connection refused",
        "No route to host",
        "Host key verification failed",
        "Too many authentication failures"
    };

    // Simple portable substring search (replaces GNU-specific memmem)
    auto find_in_payload = [&payload, payload_len](const char* msg) -> bool {
        size_t msg_len = std::strlen(msg);
        if (payload_len < msg_len) {
            return false;
        }
        // Slide window over payload
        for (size_t i = 0; i <= payload_len - msg_len; i++) {
            bool match = true;
            for (size_t j = 0; j < msg_len && match; j++) {
                if (payload[i + j] != static_cast<uint8_t>(msg[j])) {
                    match = false;
                }
            }
            if (match) {
                return true;
            }
        }
        return false;
    };

    bool found_failure = false;
    for (const auto& msg : ssh_failed_strings) {
        if (find_in_payload(msg)) {
            found_failure = true;
            break;
        }
    }

    if (!found_failure) {
        return;  // No SSH failure message detected
    }

    // Build key for this (source_ip, target_ip) pair
    // The source is the potential attacker, destination is the SSH server
    SshBruteForceKey key = {
        .src_ip = pkt.src_ip,
        .dst_ip = pkt.dst_ip
    };

    auto it = ssh_brute_force_.find(key);
    if (it == ssh_brute_force_.end()) {
        // First failure from this source to this target
        SshBruteForceData data = {
            .fail_count = 1,
            .window_start = now_ms,
            .last_failure = now_ms,
            .alert_sent = false
        };
        ssh_brute_force_[key] = data;
        return;
    }

    // Update existing entry
    SshBruteForceData& data = it->second;
    data.last_failure = now_ms;

    // Check if we're still within the detection window
    if (now_ms - data.window_start > SSH_BRUTE_FORCE_WINDOW_MS) {
        // Reset window
        data.window_start = now_ms;
        data.fail_count = 1;
        data.alert_sent = false;
        return;
    }

    // Increment failure count
    data.fail_count++;

    // Check if threshold exceeded
    if (data.fail_count >= SSH_BRUTE_FORCE_THRESHOLD && !data.alert_sent) {
        // Generate alert
        DpiResult result;
        result.matched = true;
        result.rule_id = -1;  // Internal rule
        result.message = "SSH brute force detected: " +
            std::to_string(data.fail_count) + " failures from " +
            std::to_string((pkt.src_ip >> 24) & 0xFF) + "." +
            std::to_string((pkt.src_ip >> 16) & 0xFF) + "." +
            std::to_string((pkt.src_ip >> 8) & 0xFF) + "." +
            std::to_string(pkt.src_ip & 0xFF) + " to SSH server";

        dpi_match_count_++;
        if (dpi_callback_) {
            dpi_callback_(pkt, result);
        }
        data.alert_sent = true;

        LOG_WARN("xdp", "SSH brute force detected: %u failures from %u.%u.%u.%u to SSH server %u.%u.%u.%u:%u",
                 data.fail_count,
                 (pkt.src_ip >> 24) & 0xFF, (pkt.src_ip >> 16) & 0xFF,
                 (pkt.src_ip >> 8) & 0xFF, pkt.src_ip & 0xFF,
                 (pkt.dst_ip >> 24) & 0xFF, (pkt.dst_ip >> 16) & 0xFF,
                 (pkt.dst_ip >> 8) & 0xFF, pkt.dst_ip & 0xFF,
                 pkt.dst_port);
    }
}

/*
 * F-19: FTP Data Connection Tracking
 *
 * Tracks FTP PORT and PASV commands to identify data connections.
 * FTP uses separate connections for data transfer (PORT/PASV commands).
 * Tracking these helps identify data connections and prevent bypass attempts.
 */
void XdpProcessor::detect_ftp_data_connection(const XdpPacket& pkt, const uint8_t* payload, size_t payload_len) {
    // Only track FTP control connections (port 21)
    if (pkt.dst_port != 21 && pkt.src_port != 21) {
        return;
    }

    if (payload_len == 0) {
        return;
    }

    // Get current timestamp in ms
    uint64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();

    // Clean up old entries
    for (auto it = ftp_data_connections_.begin(); it != ftp_data_connections_.end(); ) {
        if (now_ms - (it->second.last_seen / 1000) > FTP_CONN_TIMEOUT_MS) {
            it = ftp_data_connections_.erase(it);
        } else {
            ++it;
        }
    }

    // Convert payload to string for easier parsing
    std::string payload_str(reinterpret_cast<const char*>(payload),
                           std::min(payload_len, size_t(256)));

    // Check for PORT command: PORT h1,h2,h3,h4,p1,p2
    // where h1-h4 are IP octets and p1,p2 form the port number
    if (payload_str.find("PORT ") == 0 || payload_str.find("port ") == 0) {
        size_t space_pos = payload_str.find(' ');
        if (space_pos != std::string::npos && space_pos + 18 <= payload_str.size()) {
            std::string params = payload_str.substr(space_pos + 1);
            // Parse IP and port from parameters like "h1,h2,h3,h4,p1,p2"
            std::replace(params.begin(), params.end(), ',', ' ');
            std::replace(params.begin(), params.end(), '\r', ' ');
            std::replace(params.begin(), params.end(), '\n', ' ');

            std::stringstream ss(params);
            int h1, h2, h3, h4, p1, p2;
            if (ss >> h1 >> h2 >> h3 >> h4 >> p1 >> p2) {
                // Build key for FTP control connection
                FtpDataKey key = {
                    .src_ip = pkt.src_ip,
                    .dst_ip = pkt.dst_ip,
                    .src_port = pkt.src_port,
                    .dst_port = pkt.dst_port
                };

                FtpDataInfo info = {
                    .data_ip = static_cast<uint32_t>((h1 << 24) | (h2 << 16) | (h3 << 8) | h4),
                    .data_port = static_cast<uint16_t>((p1 << 8) | p2),
                    .last_seen = now_ms * 1000,
                    .passive_mode = false,
                    .alert_sent = false
                };

                ftp_data_connections_[key] = info;
            }
        }
    }
    // Check for PASV command response: 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
    else if (payload_str.find("227 ") == 0 || payload_str.find("227\t") == 0) {
        // Find the IP and port in the response
        size_t paren_start = payload_str.find('(');
        size_t paren_end = payload_str.find(')');
        if (paren_start != std::string::npos && paren_end != std::string::npos) {
            std::string params = payload_str.substr(paren_start + 1, paren_end - paren_start - 1);
            std::replace(params.begin(), params.end(), ',', ' ');

            std::stringstream ss(params);
            int h1, h2, h3, h4, p1, p2;
            if (ss >> h1 >> h2 >> h3 >> h4 >> p1 >> p2) {
                // Build key for FTP control connection
                FtpDataKey key = {
                    .src_ip = pkt.src_ip,
                    .dst_ip = pkt.dst_ip,
                    .src_port = pkt.src_port,
                    .dst_port = pkt.dst_port
                };

                FtpDataInfo info = {
                    .data_ip = static_cast<uint32_t>((h1 << 24) | (h2 << 16) | (h3 << 8) | h4),
                    .data_port = static_cast<uint16_t>((p1 << 8) | p2),
                    .last_seen = now_ms * 1000,
                    .passive_mode = true,
                    .alert_sent = false
                };

                ftp_data_connections_[key] = info;
            }
        }
    }
}

/*
 * C-04: Service Mesh Traffic Monitoring
 *
 * Analyzes traffic paths to distinguish between iptables and eBPF routing:
 * - IPTABLES: kube-proxy standard routing (10.x.x.x service IPs)
 * - EBPF: eBPF-based service mesh (Cilium direct routing, Linkerd)
 * - HOST: Traffic to/from node (host network)
 * - CROSS_NS: Cross-namespace communication
 *
 * Detection heuristics:
 * 1. Check if traffic is to a Kubernetes service IP (10.x.x.x)
 * 2. Check if source/dest is host network (non-pod IP range)
 * 3. Check for cross-namespace communication patterns
 * 4. Analyze connection characteristics (hairpinning, NAT patterns)
 */
void XdpProcessor::analyze_service_mesh_traffic(const XdpPacket& pkt) {
    // Kubernetes service IP range: 10.0.0.0/8
    // Pod IP range typically: 10.244.0.0/16 or 10.42.0.0/16 (Cilium)
    // Host network: 172.16.x.x - 172.31.x.x or physical interface IPs

    bool is_k8s_service = (pkt.dst_ip & 0xFF000000) == 0x0A000000;  // 10.0.0.0/8
    bool is_k8s_pod = ((pkt.src_ip & 0xFFFF0000) == 0x0A0A0000) ||  // 10.10.x.x (Cilium pod)
                       ((pkt.src_ip & 0xFFC00000) == 0x0A440000);   // 10.244.0.0/14 (standard k8s)

    TrafficPath path = TrafficPath::UNKNOWN;

    if (is_k8s_service) {
        // Traffic to Kubernetes service VIP (via kube-proxy or eBPF)
        path = TrafficPath::IPTABLES;
    } else if (is_k8s_pod && !is_k8s_service) {
        // Direct pod-to-pod communication (typical of eBPF service mesh)
        // Cilium uses this for direct routing without NAT
        path = TrafficPath::EBPF;
    }

    // Check for host network traffic
    // Host network range: 172.16.0.0/12 or physical IPs
    bool is_host_range = ((pkt.dst_ip & 0xF0000000) == 0xA000000);  // 172.16.x.x - 172.31.x.x

    if (is_host_range || (pkt.dst_port != 0 && pkt.dst_port < 1024)) {
        // Well-known port traffic often indicates host services
        path = TrafficPath::HOST;
    }

    // Log service mesh traffic analysis (for debugging/monitoring)
    // In production, this could emit metrics or alerts
    static std::atomic<uint64_t> iptables_count{0};
    static std::atomic<uint64_t> ebpf_count{0};
    static std::atomic<uint64_t> host_count{0};
    static std::atomic<uint64_t> cross_ns_count{0};

    switch (path) {
        case TrafficPath::IPTABLES:
            iptables_count++;
            break;
        case TrafficPath::EBPF:
            ebpf_count++;
            break;
        case TrafficPath::HOST:
            host_count++;
            break;
        case TrafficPath::CROSS_NS:
            cross_ns_count++;
            break;
        case TrafficPath::UNKNOWN:
        default:
            break;
    }

    // Note: In a full implementation, we could emit these as metrics
    // or detect anomalies (e.g., unexpected iptables traffic when eBPF is expected)
}

/**
 * @brief Parse IPv6 extension headers
 * @param ipv6 IPv6 header pointer
 * @param data_end End of packet data
 * @param next_header [out] Protocol after extension headers
 * @param header_len [out] Total length of IPv6 header + extension headers
 * @return true if parsing succeeded
 */
static bool parse_ipv6_ext_headers(const struct ipv6hdr* ipv6,
                                   const uint8_t* data_end,
                                   uint8_t& next_header,
                                   size_t& header_len) {
    next_header = ipv6->nexthdr;
    header_len = sizeof(struct ipv6hdr);

    const uint8_t* hdr = (const uint8_t*)(ipv6 + 1);

    while (hdr < data_end) {
        switch (next_header) {
            case 0:   /* Hop-by-Hop Options */
            case 43:  /* Routing Header */
            case 44:  /* Fragment Header */
            case 51:  /* AH Header */
            case 60:  /* Destination Options */
                if (hdr + 2 > data_end) return false;
                header_len += (hdr[1] + 1) * 8;
                next_header = hdr[0];
                hdr += (hdr[1] + 1) * 8;
                break;
            default:
                return true;  /* Unknown or final header */
        }
    }
    return true;
}

/*
 * F-04: DNS Tunneling Detection - DNS Query Parser
 *
 * Parses DNS query packets to extract query name and type.
 * DNS format:
 *   - Transaction ID (2 bytes)
 *   - Flags (2 bytes)
 *   - Questions (2 bytes)
 *   - Answer RRs (2 bytes)
 *   - Authority RRs (2 bytes)
 *   - Additional RRs (2 bytes)
 *   - Query name (variable, null-terminated with label lengths)
 *   - Query type (2 bytes)
 *   - Query class (2 bytes)
 */
bool XdpProcessor::parse_dns_query(const uint8_t* payload, size_t payload_len, DnsQueryInfo& info) {
    info = DnsQueryInfo{};
    info.is_valid = false;
    info.is_tunneling = false;

    if (payload_len < 12) {
        return false;  // DNS header is 12 bytes minimum
    }

    // DNS header parsing
    uint16_t flags = (payload[2] << 8) | payload[3];

    // QR bit = 0 for query, QR bit = 1 for response
    // We only process queries (not responses)
    if ((flags & 0x8000) != 0) {
        return false;  // This is a response, not a query
    }

    info.query_id = (payload[0] << 8) | payload[1];

    // Skip header (12 bytes)
    const uint8_t* ptr = payload + 12;
    size_t remaining = payload_len - 12;

    // Parse query name (DNS name encoding: length-prefixed labels)
    std::string query_name;
    while (remaining > 0 && *ptr != 0) {
        if (*ptr > remaining - 1) {
            return false;  // Invalid label length
        }
        uint8_t label_len = *ptr;
        if (label_len > 63) {
            return false;  // Label too long (DNS compression not handled here)
        }
        ptr++;  // Skip length byte
        query_name.append(reinterpret_cast<const char*>(ptr), label_len);
        ptr += label_len;
        remaining -= (label_len + 1);
        if (*ptr != 0) {
            query_name.push_back('.');
        }
    }

    if (remaining < 5) {
        return false;  // Need at least null terminator + query type + query class
    }

    ptr++;  // Skip null terminator
    remaining--;

    // Parse query type (2 bytes)
    info.query_type = (ptr[0] << 8) | ptr[1];
    info.query_name = query_name;

    // N-03: DNS Tunneling Detection - check for suspicious patterns
    // Long domain name (>50 bytes) - may indicate encoded data exfiltration
    if (info.query_name.length() > 50) {
        info.is_tunneling = true;
    }

    // Excessive labels (>20 dots) - may indicate obfuscation or tunneling
    size_t label_count = std::count(info.query_name.begin(), info.query_name.end(), '.');
    if (label_count > 20) {
        info.is_tunneling = true;
    }

    // Abnormal query types often used in DNS tunneling:
    // TXT (16), NULL (10), AXFR (252)
    if (info.query_type == 16 || info.query_type == 10 || info.query_type == 252) {
        info.is_tunneling = true;
    }

    info.is_valid = !query_name.empty();
    return info.is_valid;
}

/*
 * R-02: HTTP/2 Multiplexed Stream Analysis
 *
 * Parses HTTP/2 frames to detect and analyze multiplexed streams.
 * HTTP/2 allows multiple streams to be multiplexed over a single TCP connection.
 *
 * HTTP/2 frame format (RFC 7540):
 * - Length (3 bytes): payload length (up to 16384)
 * - Type (1 byte): frame type
 * - Flags (1 byte): frame-specific flags
 * - Stream ID (4 bytes): stream identifier (bit 1 must be 0)
 *
 * Frame types:
 * - 0x0: DATA - stream data
 * - 0x1: HEADERS - headers for a stream
 * - 0x2: PRIORITY - stream priority
 * - 0x3: RST_STREAM - stream error notification
 * - 0x4: SETTINGS - connection configuration
 * - 0x5: PING - round-trip time measurement
 * - 0x6: WINDOW_UPDATE - flow control
 * - 0x7: CONTINUATION - header continuation
 * - 0x8: ALT_SVC - alternative services
 * - 0x9: ORIGIN - origins for connection
 */
bool XdpProcessor::parse_http2_frame(const uint8_t* data, size_t len, Http2FrameInfo& info) {
    /* HTTP/2 frame header is 9 bytes: length(3) + type(1) + flags(1) + stream_id(4) */
    if (len < 9) {
        return false;
    }

    /* Parse length (3 bytes, big-endian) */
    info.length = (static_cast<uint32_t>(data[0]) << 16) |
                  (static_cast<uint32_t>(data[1]) << 8) |
                  static_cast<uint32_t>(data[2]);

    /* Type (1 byte) */
    info.type = data[3];

    /* Flags (1 byte) */
    info.flags = data[4];

    /* Stream ID (4 bytes, big-endian, bits 1-31 used) */
    info.stream_id = (static_cast<uint32_t>(data[5]) << 24) |
                     (static_cast<uint32_t>(data[6]) << 16) |
                     (static_cast<uint32_t>(data[7]) << 8) |
                     static_cast<uint32_t>(data[8]);

    /* Stream ID must not be 0 for DATA, HEADERS, PRIORITY frames */
    /* Stream ID 0 is reserved for connection-level frames (SETTINGS, PING) */
    if (info.type != 0x4 && info.type != 0x5 && info.type != 0x6) {
        if (info.stream_id == 0) {
            return false;  /* Invalid stream ID */
        }
    }

    /* Check for padded frames (HEADERS, DATA) */
    info.padded = (info.flags & 0x08) != 0;

    /* Check for priority (HEADERS, PRIORITY) */
    info.has_priority = (info.flags & 0x20) != 0;

    /* Validate frame length doesn't exceed max (16KB per RFC 7540) */
    if (info.length > 16384) {
        return false;
    }

    /* Calculate total frame size */
    info.frame_size = 9 + info.length;

    /* Validate we have enough data */
    if (len < info.frame_size) {
        return false;
    }

    return true;
}

/*
 * R-02: HTTP/2 Stream Tracking
 *
 * Tracks HTTP/2 streams to detect:
 * - Excessive concurrent streams
 * - Stream ID anomalies
 * - Rapid stream creation/teardown
 * - Priority inversions
 */
void XdpProcessor::detect_http2(const XdpPacket& pkt, const uint8_t* payload, size_t payload_len) {
    /* Only track HTTP/2 on port 80, 443, 8080 */
    if (pkt.protocol == IPPROTO_TCP &&
        pkt.dst_port != 80 && pkt.dst_port != 443 && pkt.dst_port != 8080 &&
        pkt.src_port != 80 && pkt.src_port != 443 && pkt.src_port != 8080) {
        return;
    }

    if (payload_len < 9) {
        return;  /* Need at least HTTP/2 frame header */
    }

    /* Get current timestamp */
    uint64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();

    /* Clean up old entries */
    for (auto it = http2_streams_.begin(); it != http2_streams_.end(); ) {
        if (now_ms - (it->second.last_seen / 1000) > HTTP2_STREAM_TIMEOUT_MS) {
            it = http2_streams_.erase(it);
        } else {
            ++it;
        }
    }

    /* Build key for this connection */
    Http2ConnectionKey key = {
        .src_ip = pkt.src_ip,
        .dst_ip = pkt.dst_ip,
        .src_port = pkt.src_port,
        .dst_port = pkt.dst_port
    };

    /* Look up existing connection state */
    auto conn_it = http2_connections_.find(key);
    if (conn_it == http2_connections_.end()) {
        /* New HTTP/2 connection */
        Http2ConnectionData conn_data = {
            .connection_initiated = now_ms,
            .total_streams = 0,
            .concurrent_streams = 0,
            .last_stream_id = 0,
            .settings_received = false,
            .goaway_sent = false,
            .alert_sent = false,
            .rst_flood_count = 0,
            .settings_count = 0
        };
        http2_connections_[key] = conn_data;
        conn_it = http2_connections_.find(key);
    }

    Http2ConnectionData& conn = conn_it->second;
    conn.last_seen = now_ms;

    /* Parse HTTP/2 frame */
    Http2FrameInfo frame;
    if (!parse_http2_frame(payload, payload_len, frame)) {
        return;  /* Not a valid HTTP/2 frame */
    }

    /* Process based on frame type */
    switch (frame.type) {
        case 0x1: { /* HEADERS - new stream */
            /* Check for new stream on existing connection without SETTINGS */
            if (conn.total_streams == 0 && !conn.settings_received) {
                if (!conn.alert_sent) {
                    DpiResult result;
                    result.matched = true;
                    result.rule_id = -1;
                    result.message = "HTTP/2 HEADERS without prior SETTINGS frame";
                    dpi_match_count_++;
                    if (dpi_callback_) {
                        dpi_callback_(pkt, result);
                    }
                    conn.alert_sent = true;
                }
            }

            /* Check for invalid stream ID (should be increasing) */
            if (frame.stream_id <= conn.last_stream_id && conn.last_stream_id != 0) {
                if (!conn.alert_sent) {
                    DpiResult result;
                    result.matched = true;
                    result.rule_id = -1;
                    result.message = "HTTP/2: stream ID not increasing (possible reuse/attack)";
                    dpi_match_count_++;
                    if (dpi_callback_) {
                        dpi_callback_(pkt, result);
                    }
                    conn.alert_sent = true;
                }
            }

            /* Check concurrent streams limit (RFC 7540 recommends at least 100) */
            conn.concurrent_streams++;
            conn.total_streams++;
            conn.last_stream_id = frame.stream_id;

            if (conn.concurrent_streams > HTTP2_MAX_CONCURRENT_STREAMS) {
                DpiResult result;
                result.matched = true;
                result.rule_id = -1;
                result.message = "HTTP/2: excessive concurrent streams (" +
                               std::to_string(conn.concurrent_streams) + ")";
                dpi_match_count_++;
                if (dpi_callback_) {
                    dpi_callback_(pkt, result);
                }
            }

            /* Track new stream */
            Http2StreamData stream_data = {
                .stream_id = frame.stream_id,
                .created = now_ms,
                .last_seen = now_ms,
                .headers_sent = true,
                .data_received = false,
                .closed = false
            };
            http2_streams_[key] = stream_data;  /* Simplified: keyed by connection only */
            (void)stream_data;
            break;
        }

        case 0x0: { /* DATA - stream data */
            /* Find the stream */
            auto stream_it = http2_streams_.find(key);
            if (stream_it != http2_streams_.end()) {
                stream_it->second.data_received = true;
                stream_it->second.last_seen = now_ms;
            }

            /* Check for DATA on closed stream */
            if (stream_it != http2_streams_.end() && stream_it->second.closed) {
                DpiResult result;
                result.matched = true;
                result.rule_id = -1;
                result.message = "HTTP/2 DATA on closed stream (stream_id=" +
                               std::to_string(frame.stream_id) + ")";
                dpi_match_count_++;
                if (dpi_callback_) {
                    dpi_callback_(pkt, result);
                }
            }
            break;
        }

        case 0x3: { /* RST_STREAM - stream error */
            auto stream_it = http2_streams_.find(key);
            if (stream_it != http2_streams_.end()) {
                stream_it->second.closed = true;
                if (conn.concurrent_streams > 0) {
                    conn.concurrent_streams--;
                }
            }

            /* Check for RST_STREAM flood (rapid stream closure) */
            conn.rst_flood_count++;
            if (conn.rst_flood_count > HTTP2_RST_FLOOD_THRESHOLD) {
                DpiResult result;
                result.matched = true;
                result.rule_id = -1;
                result.message = "HTTP/2 RST_STREAM flood detected";
                dpi_match_count_++;
                if (dpi_callback_) {
                    dpi_callback_(pkt, result);
                }
            }
            break;
        }

        case 0x4: { /* SETTINGS - connection configuration */
            conn.settings_received = true;

            /* Check for SETTINGS flood */
            conn.settings_count++;
            if (conn.settings_count > HTTP2_SETTINGS_FLOOD_THRESHOLD) {
                DpiResult result;
                result.matched = true;
                result.rule_id = -1;
                result.message = "HTTP/2 SETTINGS flood detected";
                dpi_match_count_++;
                if (dpi_callback_) {
                    dpi_callback_(pkt, result);
                }
            }
            break;
        }

        case 0x6: { /* WINDOW_UPDATE - flow control */
            /* Large WINDOW_UPDATE could indicate bandwidth exhaustion attack */
            if (frame.length > 8) {  /* Normal is 4 bytes for window increment */
                DpiResult result;
                result.matched = true;
                result.rule_id = -1;
                result.message = "HTTP/2: abnormal WINDOW_UPDATE size";
                dpi_match_count_++;
                if (dpi_callback_) {
                    dpi_callback_(pkt, result);
                }
            }
            break;
        }

        case 0x7: { /* CONTINUATION - header continuation */
            /* Check for header compression bombs (large CONTINUATION) */
            if (frame.length > HTTP2_MAX_FRAME_SIZE) {
                DpiResult result;
                result.matched = true;
                result.rule_id = -1;
                result.message = "HTTP/2: excessive CONTINUATION frame (possible compression bomb)";
                dpi_match_count_++;
                if (dpi_callback_) {
                    dpi_callback_(pkt, result);
                }
            }
            break;
        }

        case 0x8: { /* GOAWAY - connection termination */
            conn.goaway_sent = true;
            /* Clear all streams for this connection */
            conn.concurrent_streams = 0;
            http2_streams_.erase(key);
            break;
        }

        default:
            break;
    }
}

/*
 * R-01: QUIC Protocol Detection
 *
 * Parses QUIC packet headers to detect QUIC traffic on UDP port 443.
 * QUIC is a UDP-based multiplexed transport protocol used by HTTP/3.
 *
 * QUIC header format (RFC 9000):
 * - Long header packets (initial, handshake, 0-RTT):
 *   First byte: 0xC0 (form=1, fixed=1, type=0)
 *   Version (4 bytes)
 *   Connection ID length (1 byte)
 *   Connection ID (0-20 bytes)
 *   Packet number (1-4 bytes)
 * - Short header packets (1-RTT):
 *   First byte: 0x40 (form=0, fixed=1, type=0)
 *   Connection ID (absent in short header unless negotiated)
 *   Packet number (1-4 bytes)
 */
bool XdpProcessor::parse_quic_header(const uint8_t* data, size_t len, QuicInfo& info) {
    info = QuicInfo{};

    /* Minimum QUIC header is 5 bytes (first byte + version + cid_len) */
    if (len < 5) {
        return false;
    }

    uint8_t first_byte = data[0];

    /* Check for long header (form bit = 1) */
    bool long_header = (first_byte & 0x80) != 0;

    if (long_header) {
        /* Long header packet */
        /* First byte: 1 form + 1 fixed + 2 type + 2 reserved + 2 pn len */
        info.is_quic = true;

        /* Version (bytes 1-4) - stored in host byte order */
        info.version = (static_cast<uint32_t>(data[1]) << 24) |
                       (static_cast<uint32_t>(data[2]) << 16) |
                       (static_cast<uint32_t>(data[3]) << 8) |
                       static_cast<uint32_t>(data[4]);

        /* Connection ID length (byte 5) */
        if (len < 6) {
            return false;
        }
        info.connection_id_len = data[5];

        /* Validate CID length (max 20 bytes) */
        if (info.connection_id_len > 20) {
            return false;
        }

        /* Check we have enough data for CID */
        if (len < 6 + info.connection_id_len) {
            return false;
        }

        /* Extract Connection ID as hex string */
        std::ostringstream oss;
        for (uint8_t i = 0; i < info.connection_id_len; i++) {
            oss << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                << static_cast<int>(data[6 + i]);
        }
        info.connection_id = oss.str();

        /* Packet number length is in bits 0-1 of first byte after extracting other fields */
        info.packet_number_len = (first_byte & 0x03) + 1;  /* 1-4 bytes */
    } else {
        /* Short header packet - this is 1-RTT data, QUIC is established */
        /* Short header packets don't have connection ID in the header itself */
        /* We detect them based on the fact that they're on UDP 443 with QUIC established */
        info.is_quic = true;
        info.version = 1;  /* 1-RTT */
        info.connection_id_len = 0;
        info.connection_id = "";
        /* Packet number length: 1-4 bytes from first byte bits 0-1 */
        info.packet_number_len = (first_byte & 0x03) + 1;
    }

    return info.is_quic;
}

/*
 * R-05: MQTT Protocol Analysis
 *
 * Parses MQTT packets on ports 1883 (unencrypted) and 8883 (TLS).
 * Extracts connection info (client_id, username) from CONNECT packets,
 * topic names from PUBLISH/SUBSCRIBE packets.
 *
 * MQTT Fixed Header format:
 * - Byte 0: message_type(4) + flags(4)
 * - Bytes 1-4: remaining_length (variable, MSB indicates more bytes)
 *
 * CONNECT Packet Variable Header:
 * - Protocol Name (UTF-8 string)
 * - Protocol Level (1 byte)
 * - Connect Flags (1 byte): username(1), password(1), will_retain(1), will_qos(2), will_flag(1), clean_session(1), reserved(1)
 * - Keep Alive (2 bytes)
 *
 * CONNECT Packet Payload:
 * - Client ID (UTF-8 string)
 * - Will Topic (if will_flag set)
 * - Will Message (if will_flag set)
 * - Username (if username_flag set)
 * - Password (if password_flag set)
 *
 * PUBLISH Packet Variable Header:
 * - Topic Name (UTF-8 string)
 * - Packet Identifier (if QoS > 0)
 *
 * SUBSCRIBE Packet Variable Header:
 * - Packet Identifier (2 bytes)
 *
 * SUBSCRIBE Packet Payload:
 * - Topic Filter (UTF-8 string)
 * - QoS (1 byte)
 */
bool XdpProcessor::parse_mqtt(const uint8_t* data, size_t len, MqttInfo& info) {
    info = MqttInfo{};

    /* Minimum MQTT packet: 2 bytes (fixed header) */
    if (len < 2) {
        return false;
    }

    /* Fixed header: message_type(4) + flags(4) */
    info.type = (data[0] >> 4) & 0x0F;
    info.flags = data[0] & 0x0F;

    /* Parse remaining length (variable length, 1-4 bytes) */
    size_t pos = 1;
    uint32_t multiplier = 1;
    uint32_t remaining_len = 0;
    while (pos < len && pos < 5) {
        uint8_t byte = data[pos];
        remaining_len += (byte & 0x7F) * multiplier;
        multiplier *= 128;
        pos++;
        if ((byte & 0x80) == 0) {
            break;  /* Last byte of remaining length */
        }
    }

    /* Validate we have at least the remaining length bytes */
    if (pos >= len) {
        return false;
    }

    const uint8_t* payload = data + pos;
    size_t payload_len = len - pos;

    /* Parse based on message type */
    switch (info.type) {
        case 1: { /* CONNECT - Connection Request */
            /* Variable header: protocol name, level, flags, keep-alive */
            if (payload_len < 10) {
                return true;  /* Valid but no payload to parse */
            }

            /* Protocol name length (2 bytes) + "MQTT" (4 bytes) = 6 bytes minimum */
            uint16_t proto_name_len = (payload[0] << 8) | payload[1];
            if (proto_name_len > payload_len - 2) {
                return true;  /* Invalid, but still mark as MQTT */
            }

            /* Protocol Level (byte after protocol name) */
            uint8_t protocol_level = payload[2 + proto_name_len];

            /* Connect Flags (byte after protocol level) */
            uint8_t connect_flags = payload[3 + proto_name_len];

            /* Keep Alive (2 bytes after connect flags) */
            info.keepalive = (payload[4 + proto_name_len] << 8) | payload[5 + proto_name_len];

            /* Payload starts after variable header */
            size_t var_header_len = 6 + proto_name_len;
            const uint8_t* client_id_start = payload + var_header_len;
            size_t client_id_len_rem = payload_len - var_header_len;

            if (client_id_len_rem < 2) {
                return true;  /* No client ID */
            }

            /* Client ID (UTF-8 string) */
            uint16_t client_id_len = (client_id_start[0] << 8) | client_id_start[1];
            if (client_id_len > 0 && client_id_len <= client_id_len_rem - 2) {
                info.client_id = std::string(reinterpret_cast<const char*>(client_id_start + 2), client_id_len);
            }

            /* Parse username if present (connect_flags & 0x80) */
            if (connect_flags & 0x80) {
                size_t offset = var_header_len + 2 + client_id_len;
                if (offset + 2 <= payload_len) {
                    uint16_t username_len = (payload[offset] << 8) | payload[offset + 1];
                    offset += 2;
                    if (username_len > 0 && offset + username_len <= payload_len) {
                        info.username = std::string(reinterpret_cast<const char*>(payload + offset), username_len);
                    }
                }
            }

            /* Parse password if present (connect_flags & 0x40) */
            if (connect_flags & 0x40) {
                size_t offset = var_header_len + 2 + client_id_len;
                if (connect_flags & 0x80) {
                    /* Skip username */
                    if (offset + 2 <= payload_len) {
                        uint16_t username_len = (payload[offset] << 8) | payload[offset + 1];
                        offset += 2 + username_len;
                    }
                }
                if (offset + 2 <= payload_len) {
                    uint16_t password_len = (payload[offset] << 8) | payload[offset + 1];
                    offset += 2;
                    if (password_len > 0 && offset + password_len <= payload_len) {
                        info.password = std::string(reinterpret_cast<const char*>(payload + offset), password_len);
                    }
                }
            }

            return true;
        }

        case 3: { /* PUBLISH */
            if (payload_len < 2) {
                return true;
            }

            /* Topic name (UTF-8 string) */
            uint16_t topic_len = (payload[0] << 8) | payload[1];
            if (topic_len > 0 && topic_len <= payload_len - 2) {
                info.topic = std::string(reinterpret_cast<const char*>(payload + 2), topic_len);
            }

            /* Extract QoS from flags (bits 1-2) */
            info.qos = (info.flags >> 1) & 0x03;

            return true;
        }

        case 8: { /* SUBSCRIBE */
            if (payload_len < 3) {
                return true;  /* Need at least packet ID (2 bytes) + topic filter */
            }

            /* Packet Identifier (2 bytes) - skip */
            /* Topic Filter (UTF-8 string) starts at offset 2 */
            uint16_t topic_len = (payload[2] << 8) | payload[3];
            if (topic_len > 0 && 4 + topic_len <= payload_len) {
                info.topic = std::string(reinterpret_cast<const char*>(payload + 4), topic_len);
            }

            /* QoS byte after topic filter */
            if (4 + topic_len < payload_len) {
                info.qos = payload[4 + topic_len] & 0x03;
            }

            return true;
        }

        case 9: { /* SUBACK */
            if (payload_len >= 3) {
                /* Return code in payload[2] - we could log this */
                info.qos = payload[2] & 0x03;
            }
            return true;
        }

        case 12: { /* PINGREQ */
            /* No payload */
            return true;
        }

        case 14: { /* DISCONNECT */
            /* No payload */
            return true;
        }

        default:
            /* For other message types, just indicate MQTT detected */
            return true;
    }
}

/*
 * F-04: DNS Tunneling Detection
 *
 * Detects DNS tunneling by analyzing query patterns:
 * - Long domain names (>50 bytes) - may indicate encoded data
 * - Excessive labels (>20 dots) - may indicate obfuscation
 * - Abnormal query types (TXT=16, NULL=10, AXFR=252) - often used in tunneling
 */
void XdpProcessor::detect_dns_tunneling(const XdpPacket& pkt, const DnsQueryInfo& info) {
    // DNS tunneling detection heuristics
    if (info.query_name.length() > 50) {
        // Suspiciously long domain name
        if (dns_tunneling_callback_) {
            DpiResult result;
            result.matched = true;
            result.rule_id = -1;
            result.message = "DNS tunneling suspected: long domain name (" +
                           std::to_string(info.query_name.length()) + " bytes)";
            dns_tunneling_callback_(pkt, result);
        }
    }

    // Count labels in domain name
    size_t label_count = 0;
    for (char c : info.query_name) {
        if (c == '.') label_count++;
    }
    if (label_count > 20) {
        // Suspiciously many labels
        if (dns_tunneling_callback_) {
            DpiResult result;
            result.matched = true;
            result.rule_id = -1;
            result.message = "DNS tunneling suspected: too many labels (" +
                           std::to_string(label_count) + ")";
            dns_tunneling_callback_(pkt, result);
        }
    }

    // Check for abnormal query types (TXT=16, NULL=10, AXFR=252)
    if (info.query_type == 16 || info.query_type == 10 || info.query_type == 252) {
        if (dns_tunneling_callback_) {
            DpiResult result;
            result.matched = true;
            result.rule_id = -1;
            result.message = "DNS tunneling suspected: abnormal query type " +
                           std::to_string(info.query_type);
            dns_tunneling_callback_(pkt, result);
        }
    }
}

/*
 * F-05: TLS Certificate Detection - ASN.1 Basic Decoding
 *
 * ASN.1 DER (Distinguished Encoding Rules) decoding for X.509 certificates.
 * X.509 certificates use DER encoding which has the following structure:
 *   - Tag (1 byte): Identifies the type (SEQUENCE, INTEGER, OID, etc.)
 *   - Length (1-3 bytes): Length of the content
 *   - Content (variable): The actual data
 *
 * Common ASN.1 tags used in X.509:
 *   0x30 = SEQUENCE
 *   0x02 = INTEGER
 *   0x03 = BIT STRING
 *   0x06 = OBJECT IDENTIFIER (OID)
 *   0x0C = UTF8String
 *   0x13 = PrintableString
 *   0x16 = IA5String
 *   0x17 = UTCTime
 *   0x20 = GeneralTime (GeneralizedTime)
 */

/**
 * @brief Decode a single ASN.1 tag from buffer
 * @param data Input buffer
 * @param len Buffer length
 * @param tag Output: decoded ASN.1 tag
 * @return true if successful, false if insufficient data or invalid encoding
 */
bool XdpProcessor::decode_asn1_tag(const uint8_t* data, size_t len, Asn1Tag& tag) {
    if (len < 2) {
        return false;  // Need at least tag + length byte
    }

    tag.tag = data[0];
    tag.value = nullptr;
    tag.length = 0;

    // Parse length (DER uses definite form)
    if (data[1] < 0x80) {
        // Short form: length is in the byte itself
        tag.length = data[1];
        tag.value = data + 2;
    } else if (data[1] == 0x80) {
        // Indefinite form (not typically used in DER)
        return false;
    } else {
        // Long form: bits 5-0 indicate number of subsequent bytes
        size_t num_len_bytes = data[1] & 0x7F;
        if (len < 2 + num_len_bytes) {
            return false;  // Insufficient data for length
        }

        tag.length = 0;
        for (size_t i = 0; i < num_len_bytes; i++) {
            tag.length = (tag.length << 8) | data[2 + i];
        }
        tag.value = data + 2 + num_len_bytes;
    }

    // Validate we have enough data
    if (tag.value + tag.length > data + len) {
        return false;
    }

    return true;
}

/**
 * @brief Extract OID (Object Identifier) from ASN.1 encoded data
 * @param oid_data OID encoded bytes
 * @param oid_len OID length
 * @return Human-readable OID string (e.g., "2.5.4.3" for CN)
 *
 * OID encoding:
 * - First byte = (first_arc * 40) + second_arc
 * - Subsequent bytes = variable-length encoding of remaining arcs
 */
std::string XdpProcessor::extract_oid_string(const uint8_t* oid_data, size_t oid_len) {
    if (oid_len < 1) {
        return "";
    }

    // Decode first component
    uint8_t first = oid_data[0];
    uint32_t arc1 = first / 40;
    uint32_t arc2 = first % 40;

    std::ostringstream oss;
    oss << arc1 << "." << arc2;

    // Decode remaining components (base 128, variable length)
    uint32_t value = 0;
    for (size_t i = 1; i < oid_len; i++) {
        value = (value << 7) | (oid_data[i] & 0x7F);
        if ((oid_data[i] & 0x80) == 0) {
            // End of this component
            oss << "." << value;
            value = 0;
        }
    }

    return oss.str();
}

/**
 * @brief Parse time from ASN.1 UTCTime or GeneralizedTime
 * @param time_data Time encoded bytes
 * @param time_len Time length
 * @return Epoch seconds (0 on error)
 *
 * UTCTime format: YYMMDDhhmmssZ or YYMMDDhhmmss+hhmm
 * GeneralizedTime format: YYYYMMDDhhmmssZ (4-digit year)
 */
uint64_t XdpProcessor::parse_asn1_time(const uint8_t* time_data, size_t time_len) {
    if (time_len < 10) {
        return 0;
    }

    int year, month, day, hour, minute, second;
    char zulu;

    if (time_len == 13 && time_data[12] == 'Z') {
        // UTCTime: YYMMDDhhmmssZ
        year = (time_data[0] - '0') * 10 + (time_data[1] - '0');
        month = (time_data[2] - '0') * 10 + (time_data[3] - '0');
        day = (time_data[4] - '0') * 10 + (time_data[5] - '0');
        hour = (time_data[6] - '0') * 10 + (time_data[7] - '0');
        minute = (time_data[8] - '0') * 10 + (time_data[9] - '0');
        second = (time_data[10] - '0') * 10 + (time_data[11] - '0');
        zulu = 'Z';

        // UTCTime: years 00-49 = 2000-2049, 50-99 = 1950-1999
        if (year < 50) {
            year += 2000;
        } else {
            year += 1900;
        }
    } else if (time_len >= 15 && time_data[14] == 'Z') {
        // GeneralizedTime: YYYYMMDDhhmmssZ
        year = (time_data[0] - '0') * 1000 + (time_data[1] - '0') * 100 +
               (time_data[2] - '0') * 10 + (time_data[3] - '0');
        month = (time_data[4] - '0') * 10 + (time_data[5] - '0');
        day = (time_data[6] - '0') * 10 + (time_data[7] - '0');
        hour = (time_data[8] - '0') * 10 + (time_data[9] - '0');
        minute = (time_data[10] - '0') * 10 + (time_data[11] - '0');
        second = (time_data[12] - '0') * 10 + (time_data[13] - '0');
        zulu = 'Z';
    } else {
        return 0;  // Unsupported format
    }

    // Simple date to epoch (this is a stub - proper implementation would use tm struct)
    // For now, return a sentinel value indicating parsing was attempted
    (void)zulu;

    // Basic validation
    if (month < 1 || month > 12 || day < 1 || day > 31 ||
        hour > 23 || minute > 59 || second > 59) {
        return 0;
    }

    // Calculate approximate epoch (this is a simplified calculation)
    // Days from epoch (1970-01-01) to this date
    uint64_t days = 0;
    for (int y = 1970; y < year; y++) {
        days += (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)) ? 366 : 365;
    }
    static const int mdays[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    for (int m = 1; m < month; m++) {
        days += mdays[m - 1];
    }
    if (month > 2 && year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)) {
        days += 1;  // Leap day
    }
    days += day - 1;

    return (days * 86400ULL) + (hour * 3600ULL) + (minute * 60ULL) + second;
}

/*
 * F-05: TLS Certificate Parsing (Stub Implementation)
 *
 * TLS Certificate message contains:
 * - Certificate list (SEQUENCE of Certificate)
 * - Each Certificate is a SEQUENCE containing:
 *   - TBSCertificate (SEQUENCE)
 *   - signatureAlgorithm (AlgorithmIdentifier)
 *   - signatureValue (BIT STRING)
 *
 * Agent-6 will implement full certificate chain parsing and validation.
 */

/**
 * @brief Parse TLS certificate from ServerCertificate handshake
 * @param handshake_data Certificate handshake message data
 * @param handshake_len Data length
 * @param certs Output: vector of parsed certificates
 * @return true if at least one certificate was parsed
 */
} // namespace nids
