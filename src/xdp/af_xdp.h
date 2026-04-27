/* SPDX-License-Identifier: MIT */
/*
 * af_xdp.h - AF_XDP 用户态数据包处理接口
 *
 * AF_XDP 提供零拷贝方式访问网络数据包，
 * 使得用户态可以进行完整的深度包检测 (DPI)
 */

#pragma once
#include <memory>
#include <functional>
#include <cstdint>
#include <string>
#include <vector>
#include <atomic>
#include <cstddef>

/* AF_XDP constants (from linux/if_xdp.h) */
#ifndef AF_XDP
#define AF_XDP 44
#endif
#ifndef SOL_XDP
#define SOL_XDP 283
#endif
#ifndef XDP_SHARED_UMEM
#define XDP_SHARED_UMEM (1 << 0)
#endif
#ifndef XDP_UMEM_UNALIGNED_CHUNK_FLAG
#define XDP_UMEM_UNALIGNED_CHUNK_FLAG (1 << 0)
#endif
#ifndef XDP_UMEM_REG
#define XDP_UMEM_REG 4
#endif
#ifndef XDP_UMEM_FILL_RING
#define XDP_UMEM_FILL_RING 5
#endif
#ifndef XDP_UMEM_COMPLETION_RING
#define XDP_UMEM_COMPLETION_RING 6
#endif
#ifndef XDP_MMAP_OFFSETS
#define XDP_MMAP_OFFSETS 1
#endif
#ifndef XDP_UMEM_PGOFF_FILL_RING
#define XDP_UMEM_PGOFF_FILL_RING 0x100000000ULL
#endif
#ifndef XDP_UMEM_PGOFF_COMPLETION_RING
#define XDP_UMEM_PGOFF_COMPLETION_RING 0x180000000ULL
#endif

/* From linux/if_xdp.h (for UMEM setup) */
struct xdp_umem_reg {
    uint64_t addr;
    uint64_t len;
    uint32_t chunk_size;
    uint32_t headroom;
    uint32_t flags;
    uint32_t tx_metadata_len;
};

struct sockaddr_xdp {
    uint16_t sxdp_family;
    uint16_t sxdp_flags;
    uint32_t sxdp_ifindex;
    uint32_t sxdp_queue_id;
    uint32_t sxdp_shared_umem_fd;
};

struct xdp_ring_offset {
    uint64_t producer;
    uint64_t consumer;
    uint64_t desc;
    uint64_t flags;
};

struct xdp_mmap_offsets {
    struct xdp_ring_offset rx;
    struct xdp_ring_offset tx;
    struct xdp_ring_offset fr;
    struct xdp_ring_offset cr;
};

struct xdp_socket;

namespace nids {

/**
 * @brief 数据包描述符
 */
struct XdpPacket {
    uint8_t* data;           ///< 数据包起始指针
    uint32_t len;            ///< 数据包长度
    uint64_t timestamp;      ///< 时间戳

    // 5-tuple 信息
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
};

/**
 * @brief DPI 匹配结果
 */
struct DpiResult {
    bool matched;            ///< 是否匹配
    int rule_id;             ///< 匹配的规则 ID (-1 = 无)
    std::string message;    ///< 告警消息
};

/**
 * @brief DPI 回调函数
 */
using DpiCallback = std::function<void(const XdpPacket& pkt, const DpiResult& result)>;

/**
 * @brief AF_XDP 配置
 */
struct XdpConfig {
    std::string iface;       ///< 网络接口名
    uint32_t queue_id = 0;  ///< 队列 ID
    uint32_t num_frames = 4096;  ///< UMEM 帧数量
    uint32_t frame_size = 2048;   ///< 每个帧的大小
    bool use_fill_ring = true;    ///< 是否使用 fill ring
};

/**
 * @brief AF_XDP 处理器
 *
 * 使用 AF_XDP 接收数据包并在用户态进行 DPI
 */
class XdpProcessor {
public:
    XdpProcessor();
    ~XdpProcessor();

    // 禁用拷贝
    XdpProcessor(const XdpProcessor&) = delete;
    XdpProcessor& operator=(const XdpProcessor&) = delete;

    /**
     * @brief 打开 AF_XDP socket
     * @param config 配置
     * @return true 成功
     */
    bool open(const XdpConfig& config);

    /**
     * @brief 关闭 socket
     */
    void close();

    /**
     * @brief 检查是否已打开
     */
    bool is_open() const { return opened_; }

    /**
     * @brief 设置 DPI 回调函数
     */
    void set_dpi_callback(DpiCallback callback) { dpi_callback_ = std::move(callback); }

    /**
     * @brief 设置规则
     */
    void set_rules(const std::vector<std::pair<std::string, int>>& rules);

    /**
     * @brief 清除所有规则 (用于热重载)
     */
    void clear_all_rules();

    /**
     * @brief 开始处理数据包
     * @note 此函数会阻塞，直到 close() 被调用
     */
    void run();

    /**
     * @brief 停止处理
     */
    void stop();

    /**
     * @brief 获取统计信息
     */
    uint64_t get_rx_count() const { return rx_count_; }
    uint64_t get_drop_count() const { return drop_count_; }
    uint64_t get_dpi_match_count() const { return dpi_match_count_; }

    /**
     * @brief 添加 TLS 版本规则 (weak TLS detection)
     */
    void add_tls_version_rule(uint16_t version, int rule_id, const std::string& message) {
        tls_version_rules_.push_back({version, rule_id, message});
    }

    /**
     * @brief 添加 SNI hostname 规则 (TLS SNI blocklist)
     */
    void add_sni_rule(const std::string& sni_pattern, int rule_id, const std::string& message) {
        sni_rules_.push_back({sni_pattern, rule_id, message});
    }

    /**
     * @brief 添加 cipher suite 规则
     */
    void add_cipher_rule(uint16_t cipher, int rule_id, const std::string& message) {
        cipher_rules_.push_back({cipher, rule_id, message});
    }

private:
    void process_packets();
    bool parse_packet(uint8_t* data, uint32_t len, XdpPacket& pkt);
    void perform_dpi(const XdpPacket& pkt);

    /* TLS detection types */
    struct TlsInfo {
        bool is_tls = false;
        uint16_t version = 0;
        uint8_t handshake_type = 0;
        std::string sni;
        uint16_t cipher_suite = 0;
        bool weak_version = false;
    };

    bool parse_tls_record(const uint8_t* data, size_t len, TlsInfo& info);
    void detect_tls(const XdpPacket& pkt, const uint8_t* payload, size_t payload_len);

    struct TlsVersionRule { uint16_t version; int rule_id; std::string message; };
    struct SniRule { std::string pattern; int rule_id; std::string message; };
    struct CipherRule { uint16_t cipher; int rule_id; std::string message; };

    int sock_fd_;
    bool opened_;
    std::atomic<bool> running_;

    DpiCallback dpi_callback_;
    std::vector<std::pair<std::string, int>> rules_;  ///< (pattern, rule_id)

    uint64_t rx_count_;
    uint64_t drop_count_;
    uint64_t dpi_match_count_;

    std::vector<TlsVersionRule> tls_version_rules_;
    std::vector<SniRule> sni_rules_;
    std::vector<CipherRule> cipher_rules_;

    /* AF_XDP UMEM */
    uint8_t* umem_area_ = nullptr;  ///< mmap'd UMEM region
    uint32_t num_frames_ = 4096;
    uint32_t frame_size_ = 2048;
    struct xdp_ring_offset {
        uint64_t producer;
        uint64_t consumer;
        uint64_t desc;
        uint64_t flags;
    };
    struct xdp_ring_offsets {
        struct xdp_ring_offset fill;
        struct xdp_ring_offset completion;
    } ring_offsets_;
    struct xdp_desc {
        uint64_t addr;
        uint32_t len;
        uint32_t options;
    };
    struct xdp_desc* fill_ring_ = nullptr;  ///< mmap'd fill ring
    struct xdp_desc* completion_ring_ = nullptr;  ///< mmap'd completion ring
    uint64_t umem_size_;
};

} // namespace nids
