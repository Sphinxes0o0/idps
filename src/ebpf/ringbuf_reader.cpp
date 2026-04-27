/* SPDX-License-Identifier: MIT */
/*
 * ringbuf_reader.cpp - Ringbuf 事件读取器实现
 *
 * 使用 libbpf ring_buffer API 实现正确的 ringbuf 消费
 */

#include "ringbuf_reader.h"
#include "core/logger.h"
#include <unistd.h>
#include <cstring>
#include <arpa/inet.h>
#include <cstdio>
#include <errno.h>

namespace nids {

RingbufReader::RingbufReader(int map_fd, AlertCallback callback)
    : map_fd_(map_fd)
    , callback_(std::move(callback)) {
}

RingbufReader::~RingbufReader() {
    stop();
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

    // 创建 ring_buffer 并注册回调
    rb_ = ring_buffer__new(map_fd_, ringbuf_callback, this, nullptr);
    if (!rb_) {
        LOG_ERR("ringbuf", "failed to create ring buffer: %s", strerror(errno));
        return;
    }

    running_ = true;
    LOG_INFO("ringbuf", "started polling on map fd %d", map_fd_);

    // 轮询循环
    while (running_.load()) {
        int err = ring_buffer__poll(rb_, timeout_ms);
        if (err < 0 && err != -EINTR) {
            if (running_.load()) {
                LOG_ERR("ringbuf", "ring_buffer__poll error: %s", strerror(-err));
            }
            break;
        }
        // ring_buffer__poll 会调用注册的回调处理所有可用事件
    }

    running_ = false;
    LOG_INFO("ringbuf", "stopped");
}

void RingbufReader::stop() {
    if (!running_.load()) {
        return;
    }

    running_ = false;

    // ring_buffer__poll 会因为 running_=false 而在下一次调用时返回
    if (rb_) {
        ring_buffer__free(rb_);
        rb_ = nullptr;
    }
}

int RingbufReader::ringbuf_callback(void* ctx, void* data, size_t len) {
    auto* reader = static_cast<RingbufReader*>(ctx);

    if (len != sizeof(AlertEvent)) {
        LOG_WARN("ringbuf", "unexpected event size: %zu (expected %zu)", len, sizeof(AlertEvent));
        return 1;  // 继续处理
    }

    auto* event = static_cast<AlertEvent*>(data);
    reader->processed_count_++;

    try {
        reader->callback_(*event);
    } catch (const std::exception& e) {
        LOG_ERR("ringbuf", "callback exception: %s", e.what());
    }

    return 0;  // 成功
}

std::string alert_to_string(const AlertEvent& event) {
    char buf[512];
    std::string event_type_str;

    switch (event.event_type) {
        case EVENT_RULE_MATCH: event_type_str = "RULE_MATCH"; break;
        case EVENT_DDoS_ALERT: event_type_str = "DDoS_ALERT"; break;
        case EVENT_FLOW_THRESHOLD: event_type_str = "FLOW_THRESHOLD"; break;
        case EVENT_NEW_FLOW: event_type_str = "NEW_FLOW"; break;
        case EVENT_DPI_REQUEST: event_type_str = "DPI_REQUEST"; break;
        case EVENT_SYN_FLOOD: event_type_str = "SYN_FLOOD"; break;
        case EVENT_ICMP_FLOOD: event_type_str = "ICMP_FLOOD"; break;
        case EVENT_DNS_AMP: event_type_str = "DNS_AMP"; break;
        case EVENT_HTTP_DETECTED: event_type_str = "HTTP_DETECTED"; break;
        case EVENT_SSH_BANNER: event_type_str = "SSH_BANNER"; break;
        case EVENT_FTP_CMD: event_type_str = "FTP_CMD"; break;
        case EVENT_TELNET_OPT: event_type_str = "TELNET_OPT"; break;
        case EVENT_PORT_SCAN: event_type_str = "PORT_SCAN"; break;
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
