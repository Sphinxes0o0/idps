/* SPDX-License-Identifier: MIT */
/*
 * ringbuf_reader.cpp - Ringbuf 事件读取器实现
 *
 * 使用 epoll + read() 轮询 ringbuf
 */

#include "ringbuf_reader.h"
#include "core/logger.h"
#include <unistd.h>
#include <cstring>
#include <arpa/inet.h>
#include <cstdio>
#include <sys/epoll.h>
#include <errno.h>

namespace nids {

RingbufReader::RingbufReader(int map_fd, AlertCallback callback)
    : epoll_fd_(-1)
    , map_fd_(map_fd)
    , ringbuf_fd_(-1)
    , callback_(std::move(callback)) {
}

RingbufReader::~RingbufReader() {
    stop();
    if (epoll_fd_ >= 0) {
        close(epoll_fd_);
    }
}

void RingbufReader::start(int timeout_ms) {
    if (running_.load()) {
        LOG_WARN("ringbuf", "already running");
        return;
    }

    if (map_fd_ < 0) {
        LOG_ERR("ringbuf", "invalid map fd");
        return;
    }

    // Ringbuf 的 fd 通过 map 获取
    // 在 libbpf 中，ringbuf 是一个特殊的 map，其 fd 可以通过 bpf_map_get_ringbuf_fd 获取
    // 但由于我们没有 ringbuf.h，我们使用 epoll 轮询的方式
    // 实际上 ringbuf 是一个 ring buffer，可以通过普通的文件描述符操作读取

    ringbuf_fd_ = map_fd_;  // 假设 map_fd 是 ringbuf 的 fd

    // 创建 epoll 实例
    epoll_fd_ = epoll_create1(0);
    if (epoll_fd_ < 0) {
        LOG_ERR("ringbuf", "failed to create epoll: %s", strerror(errno));
        return;
    }

    struct epoll_event ev = {};
    ev.events = EPOLLIN;
    ev.data.fd = ringbuf_fd_;

    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, ringbuf_fd_, &ev) < 0) {
        LOG_ERR("ringbuf", "failed to add fd to epoll: %s", strerror(errno));
        close(epoll_fd_);
        epoll_fd_ = -1;
        return;
    }

    running_ = true;
    LOG_INFO("ringbuf", "started polling on fd %d", ringbuf_fd_);

    // 分配大页内存用于读取事件
    // Ringbuf 事件最大为 page_size * 2 (通常 4096 * 2 = 8192)
    static constexpr size_t BUF_SIZE = 8192;
    uint8_t buf[BUF_SIZE];

    // 轮询循环
    while (running_.load()) {
        struct epoll_event events[16];
        int nfds = epoll_wait(epoll_fd_, events, 16, timeout_ms);

        if (nfds < 0) {
            if (errno == EINTR) {
                continue;
            }
            LOG_ERR("ringbuf", "epoll_wait error: %s", strerror(errno));
            break;
        }

        if (nfds == 0) {
            // 超时，继续等待
            continue;
        }

        for (int i = 0; i < nfds; i++) {
            if (events[i].events & EPOLLIN) {
                // 读取数据
                ssize_t n = read(ringbuf_fd_, buf, BUF_SIZE);
                if (n < 0) {
                    if (errno == EINTR || errno == EAGAIN) {
                        continue;
                    }
                    LOG_ERR("ringbuf", "read error: %s", strerror(errno));
                    continue;
                }

                // 解析事件
                size_t offset = 0;
                while (offset + sizeof(AlertEvent) <= static_cast<size_t>(n)) {
                    auto* event = reinterpret_cast<AlertEvent*>(&buf[offset]);
                    processed_count_++;

                    try {
                        callback_(*event);
                    } catch (const std::exception& e) {
                        LOG_ERR("ringbuf", "callback exception: %s", e.what());
                    }

                    offset += sizeof(AlertEvent);
                }
            }
        }
    }

    running_ = false;
    LOG_INFO("ringbuf", "stopped");
}

void RingbufReader::stop() {
    if (!running_.load()) {
        return;
    }

    running_ = false;

    // 如果在 epoll_wait 中阻塞，关闭 ringbuf fd 会使其返回
    if (ringbuf_fd_ >= 0) {
        close(ringbuf_fd_);
        ringbuf_fd_ = -1;
    }
}

std::string alert_to_string(const AlertEvent& event) {
    char buf[512];
    std::string event_type_str;

    switch (event.event_type) {
        case EVENT_RULE_MATCH: event_type_str = "RULE_MATCH"; break;
        case EVENT_DDoS_ALERT: event_type_str = "DDoS_ALERT"; break;
        case EVENT_FLOW_THRESHOLD: event_type_str = "FLOW_THRESHOLD"; break;
        case EVENT_NEW_FLOW: event_type_str = "NEW_FLOW"; break;
        default: event_type_str = "UNKNOWN"; break;
    }

    snprintf(buf, sizeof(buf),
             "[%s] rule_id=%u severity=%u %s:%u -> %s:%u proto=%u",
             event_type_str.c_str(),
             event.rule_id,
             event.severity,
             ip_to_string(event.src_ip).c_str(),
             event.src_port,
             ip_to_string(event.dst_ip).c_str(),
             event.dst_port,
             event.protocol);

    return buf;
}

std::string ip_to_string(uint32_t ip) {
    char buf[INET_ADDRSTRLEN];
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    if (inet_ntop(AF_INET, &addr, buf, sizeof(buf))) {
        return buf;
    }
    return "invalid";
}

} // namespace nids
