/* SPDX-License-Identifier: MIT */
/*
 * ebpf_loader.h - eBPF 程序加载器接口
 *
 * 负责:
 * 1. 加载 BPF 对象文件
 * 2. Attach XDP 程序到网络接口
 * 3. 管理 eBPF Maps (读取统计、更新规则)
 */

#pragma once
#include <string>
#include <memory>
#include <unordered_map>
#include <vector>
#include <cstdint>

// Forward declarations instead of including libbpf headers
struct bpf_object;
struct bpf_program;
struct bpf_map;
struct bpf_link;
struct bpf_tracer_opts;

namespace nids {

/*
 * 配置参数结构
 */
struct NidsConfig {
    uint32_t ddos_threshold = 10000;
    uint32_t window_size_ns = 1000000000;
    uint32_t enabled = 1;
    uint32_t drop_enabled = 0;
    uint32_t port_scan_threshold = 20;
};

/*
 * 规则条目
 * 支持单端口和端口范围
 */
struct RuleEntry {
    uint32_t rule_id;
    uint8_t action;      // 0=log, 1=drop, 2=alert
    uint8_t severity;
    uint8_t protocol;    // 6=TCP, 17=UDP, 0=any
    uint16_t dst_port;   // 起始端口 (单端口或范围起始)
    uint16_t dst_port_max; // 范围结束端口 (0 = 单端口)
    uint8_t dpi_needed; // 0=不需要, 1=需要用户态 DPI
    uint8_t padding[2];  /* Match kernel layout: 12 bytes total */
} __attribute__((packed));

/*
 * 告警事件回调接口
 */
class IAlertCallback {
public:
    virtual ~IAlertCallback() = default;
    virtual void on_alert(const void* data, size_t size) = 0;
};

/*
 * EbpfLoader - eBPF 程序加载器
 *
 * 使用 libbpf 进行 CO-RE (Compile Once - Run Everywhere) 加载
 */
class EbpfLoader {
public:
    EbpfLoader();
    ~EbpfLoader();

    // 禁用拷贝
    EbpfLoader(const EbpfLoader&) = delete;
    EbpfLoader& operator=(const EbpfLoader&) = delete;

    /*
     * 加载 BPF 对象文件并 attach 到指定接口
     * @param iface 网络接口名 (如 "eth0")
     * @param bpf_obj_path BPF 对象文件路径
     * @return true 成功
     */
    bool load_and_attach(const std::string& iface, const std::string& bpf_obj_path);

    /*
     * 分离并清理
     */
    void detach();

    /*
     * 检查是否已加载
     */
    bool is_loaded() const { return loaded_; }

    /*
     * 获取 Map 文件描述符
     * @param name Map 名称
     * @return fd 或 -1
     */
    int get_map_fd(const std::string& name);

    /*
     * 更新规则
     * @param rule 规则条目
     * @return true 成功
     */
    bool update_rule(const RuleEntry& rule);

    /*
     * 删除规则
     * @param rule_id 规则 ID
     * @return true 成功
     */
    bool delete_rule(uint32_t rule_id);

    /*
     * 获取配置
     */
    const NidsConfig& get_config() const { return config_; }

    /*
     * 更新配置
     */
    bool update_config(const NidsConfig& config);

    /*
     * 获取统计信息
     * @param index 统计索引
     * @return 统计值
     */
    uint64_t get_stat(uint32_t index);

    /*
     * 获取接口索引
     */
    int get_ifindex() const { return ifindex_; }

    /*
     * 获取接口名
     */
    const std::string& get_iface() const { return iface_; }

    /*
     * @brief 检查 BPF 是否可用
     * @return true BPF 可用
     */
    static bool is_bpf_available();

    /*
     * @brief 获取 BPF 不可用时的错误信息
     */
    static std::string get_bpf_unavailable_reason();

private:
    bool load_bpf_object(const std::string& path);
    bool attach_xdp();
    bool attach_tracepoints();
    void close_maps();
    void close_tracepoints();

    bpf_object* obj_;
    bpf_program* prog_;
    int ifindex_;
    std::string iface_;
    bool loaded_;
    bool attached_;
    NidsConfig config_;

    // Map 缓存
    std::unordered_map<std::string, int> map_fds_;

    // Tracepoint 程序链接 (P-01: 进程感知流量监控)
    std::vector<bpf_link*> tracepoint_links_;
};

} // namespace nids
