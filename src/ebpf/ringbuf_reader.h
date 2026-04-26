/* SPDX-License-Identifier: MIT */
/*
 * ringbuf_reader.h - Ringbuf 事件读取器
 *
 * 从 eBPF Ringbuf 高效读取告警事件
 * 使用底層 bpf API 实现，不依赖 ringbuf.h
 */

#pragma once
#include <functional>
#include <memory>
#include <atomic>
#include <cstdint>
#include <sys/resource.h>
#include <unistd.h>

struct bpf_map;

namespace nids {

/*
 * 告警事件结构 (与 nids_common.h 中的定义保持一致)
 */
struct AlertEvent {
    uint64_t timestamp;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    uint8_t  severity;
    uint32_t rule_id;
    uint8_t  event_type;
};

/*
 * 事件类型枚举
 */
enum EventType {
    EVENT_RULE_MATCH = 0,
    EVENT_DDoS_ALERT = 1,
    EVENT_FLOW_THRESHOLD = 2,
    EVENT_NEW_FLOW = 3,
};

/*
 * 告警回调函数类型
 */
using AlertCallback = std::function<void(const AlertEvent& event)>;

/*
 * RingbufReader - 读取 eBPF Ringbuf 中的告警事件
 *
 * 使用 epoll 轮询 ringbuf 文件描述符
 */
class RingbufReader {
public:
    /*
     * 构造函数
     * @param map_fd Ringbuf Map 的文件描述符
     * @param callback 告警回调函数
     */
    explicit RingbufReader(int map_fd, AlertCallback callback);
    ~RingbufReader();

    // 禁用拷贝
    RingbufReader(const RingbufReader&) = delete;
    RingbufReader& operator=(const RingbufReader&) = delete;

    /*
     * 开始轮询事件
     * @param timeout_ms 每次 poll 的超时时间 (毫秒)
     * @note 此函数会阻塞，在 stop() 被调用前不会返回
     */
    void start(int timeout_ms = -1);

    /*
     * 停止轮询
     */
    void stop();

    /*
     * 检查是否正在运行
     */
    bool is_running() const { return running_.load(); }

    /*
     * 获取已处理事件计数
     */
    uint64_t get_processed_count() const { return processed_count_; }

private:
    int epoll_fd_;
    int map_fd_;
    int ringbuf_fd_;
    AlertCallback callback_;
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> processed_count_{0};
};

/*
 * 工具函数: 将 AlertEvent 转换为可读字符串
 */
std::string alert_to_string(const AlertEvent& event);

/*
 * 工具函数: 将 IP 地址转换为字符串
 */
std::string ip_to_string(uint32_t ip);

} // namespace nids
