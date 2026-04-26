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

private:
    void process_packets();
    bool parse_packet(uint8_t* data, uint32_t len, XdpPacket& pkt);
    void perform_dpi(const XdpPacket& pkt);

    int sock_fd_;
    bool opened_;
    bool running_;

    DpiCallback dpi_callback_;
    std::vector<std::pair<std::string, int>> rules_;  ///< (pattern, rule_id)

    uint64_t rx_count_;
    uint64_t drop_count_;
    uint64_t dpi_match_count_;
};

} // namespace nids
