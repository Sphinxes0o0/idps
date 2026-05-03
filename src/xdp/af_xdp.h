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
#include <map>

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
 * @brief DNS 隧道检测回调函数
 */
using DnsCallback = std::function<void(const XdpPacket& pkt, const DpiResult& result)>;

/**
 * @brief DNS 查询信息
 */
struct DnsQueryInfo {
    std::string query_name;   ///< 查询的域名
    uint16_t query_type;     ///< 查询类型 (A=1, AAAA=28, MX=15, etc.)
    uint16_t query_id;       ///< DNS Transaction ID
    bool is_valid;           ///< 解析是否成功
    bool is_tunneling;      ///< 可疑的 DNS 隧道特征
};

/**
 * @brief QUIC 连接信息
 *
 * QUIC header format (draft-ietf-quic-transport-34):
 * - First byte: header form (1) + fixed bit (1) + packet type (2) + reserved (2) + packet number len (2)
 * - Version (4 bytes) for long header packets
 * - Connection ID length (1 byte) for long header
 * - Connection ID (0-20 bytes)
 * - Packet number (1-4 bytes based on len)
 */
struct QuicInfo {
    bool is_quic = false;           ///< 是否为 QUIC 流量
    uint32_t version = 0;          ///< QUIC 版本
    uint8_t connection_id_len = 0; ///< Connection ID 长度
    std::string connection_id;      ///< Connection ID (hex)
    uint8_t packet_number_len = 0; ///< 包号长度 (1-4 bytes)
};

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
     * @brief 检查 AF_XDP 是否可用
     * @return true AF_XDP 可用
     */
    static bool is_available();

    /**
     * @brief 获取 AF_XDP 不可用时的错误信息
     */
    static std::string get_unavailable_reason();

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
     * @brief 设置 DNS 隧道检测回调函数
     */
    void set_dns_tunneling_callback(DnsCallback callback) { dns_tunneling_callback_ = std::move(callback); }

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

    /*
     * C-04: Service Mesh Traffic Monitoring
     *
     * Analyzes traffic paths to distinguish between:
     * - iptables-routed traffic (kube-proxy)
     * - eBPF-routed traffic (Cilium, Linkerd)
     * - host network traffic
     * - cross-namespace traffic
     */
    enum class TrafficPath {
        UNKNOWN = 0,
        IPTABLES = 1,   // kube-proxy or standard iptables routing
        EBPF = 2,      // eBPF-based service mesh (Cilium, Linkerd)
        HOST = 3,      // Traffic to/from host network
        CROSS_NS = 4   // Cross-namespace communication
    };

    void analyze_service_mesh_traffic(const XdpPacket& pkt);

    /**
     * @brief TLS 证书信息 (public for testing)
     */
    struct TlsCertInfo {
        std::string issuer;        // 颁发者 (CN)
        std::string subject;       // 主题 (CN)
        std::string common_name;   // CN
        std::vector<std::string> sans;  // Subject Alternative Names
        uint64_t not_before;      // 有效期开始 (epoch seconds)
        uint64_t not_after;       // 有效期结束 (epoch seconds)
        bool self_signed;         // 是否自签名
        bool expired;            // 是否已过期
        bool weak_hash;           // 使用弱哈希算法 (MD5, SHA1)
    };

    /* TLS certificate parsing - made public for testing */
    bool parse_tls_certificate(const uint8_t* handshake_data, size_t handshake_len,
                               std::vector<TlsCertInfo>& certs);
    bool parse_x509_certificate(const uint8_t* cert_data, size_t cert_len, TlsCertInfo& cert);

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
        bool early_data = false;  /* F-22: TLS 0-RTT early data indicator */
    };

    bool parse_tls_record(const uint8_t* data, size_t len, TlsInfo& info);
    void detect_tls(const XdpPacket& pkt, const uint8_t* payload, size_t payload_len);

    /*
     * F-05: TLS Certificate Detection - ASN.1 Basic Decoding
     * ASN.1 DER encoding structures used in X.509 certificates:
     * - Universal tags (0x02=INTEGER, 0x03=BIT STRING, 0x06=OBJECT IDENTIFIER, 0x0C=UTF8String,
     *                   0x13=PrintableString, 0x16=IA5String, 0x17=UTCTime, 0x30=SEQUENCE)
     */
    struct Asn1Tag {
        uint8_t tag;        // ASN.1 tag byte
        size_t length;      // Length of the value
        const uint8_t* value;  // Pointer to the value bytes
    };

    /**
     * @brief Decode a single ASN.1 tag from buffer
     * @param data Input buffer
     * @param len Buffer length
     * @param tag Output: decoded ASN.1 tag
     * @return true if successful, false if insufficient data or invalid encoding
     */
    bool decode_asn1_tag(const uint8_t* data, size_t len, Asn1Tag& tag);

    /**
     * @brief Extract OID (Object Identifier) from ASN.1 encoded data
     * @param oid_data OID encoded bytes
     * @param oid_len OID length
     * @return Human-readable OID string (e.g., "2.5.4.3" for CN)
     */
    std::string extract_oid_string(const uint8_t* oid_data, size_t oid_len);

    /**
     * @brief Parse time from ASN.1 UTCTime or GeneralizedTime
     * @param time_data Time encoded bytes
     * @param time_len Time length
     * @return Epoch seconds (0 on error)
     */
    uint64_t parse_asn1_time(const uint8_t* time_data, size_t time_len);

    /*
     * F-17: HTTP pipeline out-of-order detection
     * Detects when HTTP requests arrive out of order in a pipeline
     */
    void detect_http_pipeline(const XdpPacket& pkt, const uint8_t* payload, size_t payload_len);

    /*
     * F-19: FTP data connection tracking
     * Tracks FTP PORT/PASV commands to identify data connections
     */
    void detect_ftp_data_connection(const XdpPacket& pkt, const uint8_t* payload, size_t payload_len);

    /*
     * F-23: WebSocket frame detection
     * Parses WebSocket frame headers to detect fragmented/mixed frames
     */
    void detect_websocket(const XdpPacket& pkt, const uint8_t* payload, size_t payload_len);

    /*
     * F-04: DNS Tunneling Detection
     * Detects DNS tunneling by analyzing query patterns:
     * - Long domain names (>50 bytes)
     * - Excessive labels (>20 dots)
     * - Abnormal query types (TXT=16, NULL=10, AXFR=252)
     */
    void detect_dns_tunneling(const XdpPacket& pkt, const DnsQueryInfo& info);
    bool parse_dns_query(const uint8_t* payload, size_t payload_len, DnsQueryInfo& info);

    /**
     * @brief Parse QUIC header
     * @param data UDP payload data
     * @param len UDP payload length
     * @param info [out] Parsed QUIC info
     * @return true if QUIC header detected
     */
    bool parse_quic_header(const uint8_t* data, size_t len, QuicInfo& info);

    struct TlsVersionRule { uint16_t version; int rule_id; std::string message; };
    struct SniRule { std::string pattern; int rule_id; std::string message; };
    struct CipherRule { uint16_t cipher; int rule_id; std::string message; };

    /*
     * E-24: TLS record fragment tracking for reassembly
     * TLS records may be fragmented across multiple TCP packets.
     * We track partial records until we have the complete record.
     */
    struct TlsFragmentKey {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint16_t src_port;
        uint16_t dst_port;

        bool operator<(const TlsFragmentKey& other) const {
            if (src_ip != other.src_ip) return src_ip < other.src_ip;
            if (dst_ip != other.dst_ip) return dst_ip < other.dst_ip;
            if (src_port != other.src_port) return src_port < other.src_port;
            return dst_port < other.dst_port;
        }
    };
    struct TlsFragmentData {
        std::vector<uint8_t> data;  // Accumulated TLS record data
        uint32_t expected_len;       // Expected total TLS record length
        uint64_t first_seen;         // Timestamp for timeout
    };
    // Map to track partial TLS records (keyed by 5-tuple)
    std::map<TlsFragmentKey, TlsFragmentData, std::less<>> tls_fragments_;
    static constexpr uint32_t TLS_FRAG_TIMEOUT_MS = 5000;  // 5 second timeout
    static constexpr size_t TLS_MAX_FRAGMENTS = 16;  // Max fragments per record

    /*
     * F-17: HTTP pipeline tracking for out-of-order detection
     * HTTP pipelining allows multiple requests to be sent without waiting for responses.
     * We track the sequence number of each request to detect out-of-order packets
     * which could indicate an evasion attempt.
     */
    struct HttpPipelineKey {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint16_t src_port;
        uint16_t dst_port;

        bool operator<(const HttpPipelineKey& other) const {
            if (src_ip != other.src_ip) return src_ip < other.src_ip;
            if (dst_ip != other.dst_ip) return dst_ip < other.dst_ip;
            if (src_port != other.src_port) return src_port < other.src_port;
            return dst_port < other.dst_port;
        }
    };
    struct HttpPipelineData {
        uint32_t last_seq;         // Last seen HTTP request sequence number
        uint32_t expected_seq;      // Expected next sequence number
        uint64_t last_seen;        // Timestamp for timeout
        bool alert_sent;           // Alert sent for out-of-order
    };
    // Map to track HTTP pipeline sequences (keyed by 5-tuple)
    std::map<HttpPipelineKey, HttpPipelineData, std::less<>> http_pipeline_;
    static constexpr uint32_t HTTP_PIPELINE_TIMEOUT_MS = 60000;  // 60 second timeout

    /*
     * F-19: FTP data connection tracking
     * FTP uses PORT (active) and PASV (passive) commands to establish data connections.
     * We track these to identify data connections and prevent bypass attempts.
     */
    struct FtpDataKey {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint16_t src_port;  // FTP control connection source port
        uint16_t dst_port;  // FTP control connection destination port (21)

        bool operator<(const FtpDataKey& other) const {
            if (src_ip != other.src_ip) return src_ip < other.src_ip;
            if (dst_ip != other.dst_ip) return dst_ip < other.dst_ip;
            if (src_port != other.src_port) return src_port < other.src_port;
            return dst_port < other.dst_port;
        }
    };
    struct FtpDataInfo {
        uint32_t data_ip;        // IP for data connection
        uint16_t data_port;      // Port for data connection
        uint64_t last_seen;      // Timestamp
        bool passive_mode;       // true = PASV, false = PORT
        bool alert_sent;         // Alert sent
    };
    // Map to track FTP data connections
    std::map<FtpDataKey, FtpDataInfo, std::less<>> ftp_data_connections_;
    static constexpr uint32_t FTP_CONN_TIMEOUT_MS = 300000;  // 5 minute timeout

    /*
     * F-23: WebSocket frame tracking
     * Tracks fragmented WebSocket frames to detect anomalous patterns
     */
    struct WebSocketKey {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint16_t src_port;
        uint16_t dst_port;

        bool operator<(const WebSocketKey& other) const {
            if (src_ip != other.src_ip) return src_ip < other.src_ip;
            if (dst_ip != other.dst_ip) return dst_ip < other.dst_ip;
            if (src_port != other.src_port) return src_port < other.src_port;
            return dst_port < other.dst_port;
        }
    };
    struct WebSocketData {
        uint8_t last_opcode;        // Last seen WebSocket opcode
        uint8_t fragment_opcode;    // Opcode of fragmented message start
        bool fragmented;            // Currently tracking fragmented message
        uint32_t fragment_count;    // Number of fragments seen
        uint64_t last_seen;         // Timestamp for timeout
        bool alert_sent;           // Alert sent for this message
    };
    // Map to track WebSocket connections
    std::map<WebSocketKey, WebSocketData, std::less<>> websocket_connections_;
    static constexpr uint32_t WEBSOCKET_TIMEOUT_MS = 120000;  // 2 minute timeout

    int sock_fd_;
    bool opened_;
    std::atomic<bool> running_;

    DpiCallback dpi_callback_;
    DnsCallback dns_tunneling_callback_;
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
