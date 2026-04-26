/* SPDX-License-Identifier: MIT */
/*
 * ebpf_nic.cpp - eBPF 网络接口实现
 */

#include "ebpf_nic.h"
#include "core/logger.h"
#include <bpf/bpf.h>
#include <chrono>
#include <unistd.h>

namespace nids {

static uint64_t get_current_time_ns() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();
}

EbpfNic::EbpfNic()
    : loader_(nullptr)
    , ringbuf_reader_(nullptr) {
}

EbpfNic::~EbpfNic() {
    close();
}

bool EbpfNic::open(const std::string& iface) {
    if (loader_ && loader_->is_loaded()) {
        LOG_WARN("ebpf_nic", "already opened");
        return true;
    }

    iface_ = iface;

    // 创建 eBPF 加载器
    loader_ = std::make_unique<EbpfLoader>();

    // 获取 BPF 对象文件路径
    // 默认在 $(PROJECT_BINARY_DIR)/bpf/nids_bpf.o
    // 或者从环境变量 / 配置获取
    std::string bpf_obj_path = "./build/bin/nids_bpf.o";

    // 加载并 attach
    if (!loader_->load_and_attach(iface, bpf_obj_path)) {
        LOG_ERR("ebpf_nic", "failed to load eBPF program");
        loader_.reset();
        return false;
    }

    LOG_INFO("ebpf_nic", "opened on %s", iface.c_str());
    return true;
}

void EbpfNic::close() {
    stop_event_loop();

    if (loader_) {
        loader_->detach();
        loader_.reset();
    }

    ringbuf_reader_.reset();
    iface_.clear();
}

bool EbpfNic::receive(PacketSlot* slot, int /*timeout_ms*/) {
    // XDP 模式下，数据包由内核处理
    // 此函数仅用于兼容性
    // 实际告警通过 Ringbuf 传递

    // 更新 slot 的基本信息（如果需要）
    if (slot) {
        slot->timestamp = get_current_time_ns();
    }

    return true;  // XDP 运行中
}

uint64_t EbpfNic::get_total_packets() const {
    if (!loader_) return 0;
    return loader_->get_stat(0);  // STATS_PACKETS_TOTAL
}

uint64_t EbpfNic::get_dropped_packets() const {
    if (!loader_) return 0;
    return loader_->get_stat(1);  // STATS_PACKETS_DROPPED
}

uint64_t EbpfNic::get_ddos_alerts() const {
    if (!loader_) return 0;
    return loader_->get_stat(3);  // STATS_DDoS_ALERTS
}

uint64_t EbpfNic::get_rule_matches() const {
    if (!loader_) return 0;
    return loader_->get_stat(4);  // STATS_RULE_MATCHES
}

void EbpfNic::set_alert_callback(AlertCallback callback) {
    alert_callback_ = std::move(callback);

    if (loader_ && loader_->is_loaded()) {
        int events_fd = loader_->get_map_fd("events");
        if (events_fd >= 0) {
            ringbuf_reader_ = std::make_unique<RingbufReader>(events_fd, alert_callback_);
        }
    }
}

void EbpfNic::start_event_loop() {
    if (running_.load()) {
        LOG_WARN("ebpf_nic", "event loop already running");
        return;
    }

    if (!ringbuf_reader_) {
        LOG_ERR("ebpf_nic", "ringbuf_reader not initialized");
        return;
    }

    running_ = true;
    event_thread_ = std::thread(&EbpfNic::event_loop_thread_func, this);
    LOG_INFO("ebpf_nic", "event loop started");
}

void EbpfNic::stop_event_loop() {
    if (!running_.load()) {
        return;
    }

    running_ = false;

    if (ringbuf_reader_) {
        ringbuf_reader_->stop();
    }

    if (event_thread_.joinable()) {
        event_thread_.join();
    }

    LOG_INFO("ebpf_nic", "event loop stopped");
}

void EbpfNic::event_loop_thread_func() {
    if (ringbuf_reader_) {
        ringbuf_reader_->start(100);  // 100ms timeout
    }
}

} // namespace nids
