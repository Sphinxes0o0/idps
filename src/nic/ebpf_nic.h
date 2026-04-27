/* SPDX-License-Identifier: MIT */
/*
 * ebpf_nic.h - eBPF 网络接口封装
 *
 * 实现 INic 接口，利用 XDP 进行数据包捕获
 * 与 AfPacketNic API 兼容
 */

#pragma once
#include "nic_interface.h"
#include "../ebpf/ebpf_loader.h"
#include "../ebpf/ringbuf_reader.h"
#include <string>
#include <memory>
#include <thread>
#include <atomic>

namespace nids {

/*
 * EbpfNic - 基于 XDP eBPF 的网络接口
 *
 * 提供与 AfPacketNic 相同的接口，但底层使用 XDP
 * 数据包通过 XDP 处理后，可以通过两种方式获取:
 * 1. 直接从 Ringbuf 接收处理后的事件
 * 2. 通过 AF_XDP 零拷贝接收原始数据包
 *
 * 当前实现使用方式1: XDP 处理 + Ringbuf 事件
 */
class EbpfNic : public INic {
public:
    EbpfNic();
    ~EbpfNic() override;

    /*
     * 打开网络接口并加载 eBPF 程序
     * @param iface 接口名 (如 "eth0")
     * @return true 成功
     */
    bool open(const std::string& iface) override;

    /*
     * 关闭接口并卸载 eBPF 程序
     */
    void close() override;

    /*
     * 接收数据包 (兼容 AfPacketNic 接口)
     *
     * 注意: 由于 XDP 处理发生在内核态，
     * 原始数据包直接进入处理流程，不会返回到这里
     * 此函数主要用于兼容性和统计
     *
     * @param slot PacketSlot (未使用)
     * @param timeout_ms 超时 (未使用)
     * @return true (始终返回 true 表示 XDP 运行中)
     */
    bool receive(PacketSlot* slot, int timeout_ms = 10) override;

    /*
     * 获取接口名
     */
    const std::string& iface() const override { return iface_; }

    /*
     * 获取 eBPF 加载器
     */
    EbpfLoader* get_loader() { return loader_.get(); }

    /*
     * 设置 eBPF 配置参数
     */
    void set_config(const NidsConfig& config) {
        if (loader_) loader_->update_config(config);
    }

    /*
     * 获取统计信息
     */
    uint64_t get_total_packets() const;
    uint64_t get_dropped_packets() const;
    uint64_t get_ddos_alerts() const;
    uint64_t get_rule_matches() const;

    /*
     * 注册告警回调
     */
    void set_alert_callback(AlertCallback callback);

    /*
     * 启动 Ringbuf 事件处理线程
     */
    void start_event_loop();

    /*
     * 停止事件处理
     */
    void stop_event_loop();

private:
    void event_loop_thread_func();

    std::string iface_;
    std::unique_ptr<EbpfLoader> loader_;
    std::unique_ptr<RingbufReader> ringbuf_reader_;
    std::thread event_thread_;
    std::atomic<bool> running_{false};
    AlertCallback alert_callback_;
};

} // namespace nids
