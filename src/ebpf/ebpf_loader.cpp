/* SPDX-License-Identifier: MIT */
/*
 * ebpf_loader.cpp - eBPF 程序加载器实现
 */

#include "ebpf_loader.h"
#include "core/logger.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <cstring>

namespace nids {

namespace {
    // 从 ifreq 获取接口索引
    int get_iface_index(const std::string& iface) {
        return if_nametoindex(iface.c_str());
    }

    // 加载 BPF 对象
    int load_bpf_object_file(const char* path, struct bpf_object** obj) {
        struct bpf_object_open_opts opts = {};
        opts.sz = sizeof(opts);
        opts.object_name = "nids_bpf";

        *obj = bpf_object__open_file(path, &opts);
        if (libbpf_get_error(*obj)) {
            char err_buf[256];
            libbpf_strerror(libbpf_get_error(*obj), err_buf, sizeof(err_buf));
            LOG_ERR("ebpf", "failed to open BPF object: %s", err_buf);
            return -1;
        }
        return 0;
    }

    // 加载并验证 BPF 程序
    int load_programs(struct bpf_object* obj) {
        int err = bpf_object__load(obj);
        if (err) {
            char err_buf[256];
            libbpf_strerror(err, err_buf, sizeof(err_buf));
            LOG_ERR("ebpf", "failed to load BPF object: %s", err_buf);
            return err;
        }
        return 0;
    }
}

EbpfLoader::EbpfLoader()
    : obj_(nullptr)
    , prog_(nullptr)
    , ifindex_(0)
    , loaded_(false)
    , attached_(false) {
    tracepoint_links_.reserve(4);  // Reserve for trace_connect and trace_connect_ret
}

EbpfLoader::~EbpfLoader() {
    detach();
}

bool EbpfLoader::is_bpf_available() {
    int sock = socket(AF_INET, SOCK_RAW, 0);
    if (sock >= 0) {
        close(sock);
        return true;
    }
    return false;
}

std::string EbpfLoader::get_bpf_unavailable_reason() {
    int sock = socket(AF_INET, SOCK_RAW, 0);
    if (sock >= 0) {
        close(sock);
        return "BPF is available";
    }
    
    if (errno == EAFNOSUPPORT) {
        return "BPF not supported: CONFIG_BPF not enabled in kernel";
    } else if (errno == EPERM) {
        return "BPF not available: permission denied (need root or CAP_BPF)";
    } else {
        return "BPF not available: " + std::string(strerror(errno));
    }
}

bool EbpfLoader::load_and_attach(const std::string& iface, const std::string& bpf_obj_path) {
    if (loaded_) {
        LOG_WARN("ebpf", "already loaded, call detach first");
        return false;
    }

    iface_ = iface;
    ifindex_ = get_iface_index(iface);
    if (ifindex_ == 0) {
        LOG_ERR("ebpf", "failed to get ifindex for %s", iface.c_str());
        return false;
    }

    // 加载 BPF 对象
    if (!load_bpf_object(bpf_obj_path)) {
        return false;
    }

    // 加载程序
    if (load_programs(obj_) < 0) {
        bpf_object__close(obj_);
        obj_ = nullptr;
        return false;
    }

    // 获取程序
    prog_ = bpf_object__find_program_by_name(obj_, "nids_xdp");
    if (!prog_) {
        LOG_ERR("ebpf", "failed to find nids_xdp program");
        bpf_object__close(obj_);
        obj_ = nullptr;
        return false;
    }

    // Attach XDP
    if (!attach_xdp()) {
        bpf_object__close(obj_);
        obj_ = nullptr;
        return false;
    }

    // Attach tracepoint programs (P-01: 进程感知流量监控)
    if (!attach_tracepoints()) {
        LOG_WARN("ebpf", "failed to attach tracepoints, continuing without process tracking");
        // Don't fail the whole load, tracepoints are optional
    }

    loaded_ = true;
    LOG_INFO("ebpf", "loaded and attached to %s", iface.c_str());
    return true;
}

void EbpfLoader::detach() {
    if (attached_ && ifindex_ > 0) {
        bpf_xdp_attach(ifindex_, -1, XDP_FLAGS_DRV_MODE, nullptr);
        attached_ = false;
    }

    // Close tracepoint links (P-01)
    close_tracepoints();

    if (obj_) {
        bpf_object__close(obj_);
        obj_ = nullptr;
        prog_ = nullptr;
    }

    loaded_ = false;
    iface_.clear();
    ifindex_ = 0;
}

int EbpfLoader::get_map_fd(const std::string& name) {
    if (!loaded_ || !obj_) {
        return -1;
    }

    auto it = map_fds_.find(name);
    if (it != map_fds_.end()) {
        return it->second;
    }

    // 查找 Map
    struct bpf_map* map = bpf_object__find_map_by_name(obj_, name.c_str());
    if (!map) {
        LOG_WARN("ebpf", "map '%s' not found", name.c_str());
        return -1;
    }

    int fd = bpf_map__fd(map);
    if (fd < 0) {
        LOG_ERR("ebpf", "failed to get fd for map '%s'", name.c_str());
        return fd;
    }

    map_fds_[name] = fd;
    return fd;
}

bool EbpfLoader::update_rule(const RuleEntry& rule) {
    // Validate rule values to prevent BPF verifier issues and malicious injection
    if (rule.action > 2) {
        LOG_ERR("ebpf", "invalid rule action: %u (must be 0-2)", rule.action);
        return false;
    }
    if (rule.severity > 4) {
        LOG_ERR("ebpf", "invalid rule severity: %u (must be 0-4)", rule.severity);
        return false;
    }
    if (rule.protocol != 0 && rule.protocol != 6 && rule.protocol != 17) {
        LOG_ERR("ebpf", "invalid rule protocol: %u (must be 0, 6, or 17)", rule.protocol);
        return false;
    }
    if (rule.dpi_needed > 1) {
        LOG_ERR("ebpf", "invalid rule dpi_needed: %u (must be 0 or 1)", rule.dpi_needed);
        return false;
    }

    int rules_fd = get_map_fd("rules");
    if (rules_fd < 0) {
        LOG_ERR("ebpf", "rules map not available");
        return false;
    }

    uint32_t key = rule.rule_id;
    int err = bpf_map_update_elem(rules_fd, &key, &rule, BPF_ANY);
    if (err < 0) {
        LOG_ERR("ebpf", "failed to update rule %u: %s", rule.rule_id, strerror(errno));
        return false;
    }

    /* 更新规则索引 (rule_index) 以加速内核查找 */
    int idx_fd = get_map_fd("rule_index");
    if (idx_fd >= 0) {
        uint32_t idx_key = ((uint32_t)rule.protocol << 16) | rule.dst_port;
        err = bpf_map_update_elem(idx_fd, &idx_key, &rule.rule_id, BPF_ANY);
        if (err < 0) {
            LOG_WARN("ebpf", "failed to update rule_index for rule %u", rule.rule_id);
            /* 不影响主流程，继续 */
        }
    }

    LOG_DEBUG("ebpf", "updated rule %u", rule.rule_id);
    return true;
}

bool EbpfLoader::delete_rule(uint32_t rule_id) {
    int rules_fd = get_map_fd("rules");
    if (rules_fd < 0) {
        return false;
    }

    uint32_t key = rule_id;

    RuleEntry rule;
    if (bpf_map_lookup_elem(rules_fd, &key, &rule) == 0) {
        int idx_fd = get_map_fd("rule_index");
        if (idx_fd >= 0) {
            uint32_t idx_key = ((uint32_t)rule.protocol << 16) | rule.dst_port;
            bpf_map_delete_elem(idx_fd, &idx_key);
        }
    }

    int err = bpf_map_delete_elem(rules_fd, &key);
    if (err < 0 && errno != ENOENT) {
        LOG_ERR("ebpf", "failed to delete rule %u: %s", rule_id, strerror(errno));
        return false;
    }

    LOG_DEBUG("ebpf", "deleted rule %u", rule_id);
    return true;
}

bool EbpfLoader::update_config(const NidsConfig& config) {
    int config_fd = get_map_fd("config");
    if (config_fd < 0) {
        LOG_ERR("ebpf", "config map not available");
        return false;
    }

    uint32_t key = 0;
    int err = bpf_map_update_elem(config_fd, &key, &config, BPF_ANY);
    if (err < 0) {
        LOG_ERR("ebpf", "failed to update config: %s", strerror(errno));
        return false;
    }

    config_ = config;
    return true;
}

uint64_t EbpfLoader::get_stat(uint32_t index) {
    int stats_fd = get_map_fd("stats");
    if (stats_fd < 0) {
        return 0;
    }

    uint32_t key = index;

    /* PERCPU_ARRAY stores a separate value per CPU. We need to sum all of them.
     * Allocate buffer for max 256 CPUs and sum values returned by kernel. */
    const int MAX_CPUS = 256;
    uint64_t per_cpu_buf[MAX_CPUS];
    memset(per_cpu_buf, 0, sizeof(per_cpu_buf));

    int err = bpf_map_lookup_elem(stats_fd, &key, per_cpu_buf);
    if (err < 0) {
        return 0;
    }

    /* Sum values from all CPUs. Kernel returns values for all CPUs in one call. */
    uint64_t total = 0;
    for (int i = 0; i < MAX_CPUS; i++) {
        total += per_cpu_buf[i];
    }

    return total;
}

bool EbpfLoader::load_bpf_object(const std::string& path) {
    if (load_bpf_object_file(path.c_str(), &obj_) < 0) {
        return false;
    }
    return true;
}

/*
 * P-01: attach_tracepoints - Attach tracepoint programs for process tracking
 *
 * Attaches tracepoint programs for monitoring connect() syscalls
 * to correlate network traffic with processes.
 */
bool EbpfLoader::attach_tracepoints() {
    struct bpf_program *prog;

    // Attach sys_enter_connect tracepoint
    prog = bpf_object__find_program_by_name(obj_, "trace_connect");
    if (prog) {
        struct bpf_link *link = bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_connect");
        if (libbpf_get_error(link)) {
            char err_buf[256];
            libbpf_strerror(libbpf_get_error(link), err_buf, sizeof(err_buf));
            LOG_ERR("ebpf", "failed to attach trace_connect: %s", err_buf);
        } else {
            tracepoint_links_.push_back(link);
            LOG_INFO("ebpf", "attached trace_connect tracepoint");
        }
    } else {
        LOG_WARN("ebpf", "trace_connect program not found in BPF object");
    }

    // Attach sys_exit_connect tracepoint
    prog = bpf_object__find_program_by_name(obj_, "trace_connect_ret");
    if (prog) {
        struct bpf_link *link = bpf_program__attach_tracepoint(prog, "syscalls", "sys_exit_connect");
        if (libbpf_get_error(link)) {
            char err_buf[256];
            libbpf_strerror(libbpf_get_error(link), err_buf, sizeof(err_buf));
            LOG_ERR("ebpf", "failed to attach trace_connect_ret: %s", err_buf);
        } else {
            tracepoint_links_.push_back(link);
            LOG_INFO("ebpf", "attached trace_connect_ret tracepoint");
        }
    } else {
        LOG_WARN("ebpf", "trace_connect_ret program not found in BPF object");
    }

    return !tracepoint_links_.empty();
}

/*
 * P-01: close_tracepoints - Close tracepoint program links
 */
void EbpfLoader::close_tracepoints() {
    for (auto link : tracepoint_links_) {
        if (link) {
            bpf_link__destroy(link);
        }
    }
    tracepoint_links_.clear();
}

bool EbpfLoader::attach_xdp() {
    int prog_fd = bpf_program__fd(prog_);
    if (prog_fd < 0) {
        LOG_ERR("ebpf", "failed to get program fd");
        return false;
    }

    int err = bpf_xdp_attach(ifindex_, prog_fd, XDP_FLAGS_DRV_MODE, nullptr);
    if (err < 0) {
        LOG_ERR("ebpf", "bpf_xdp_attach failed, trying SKB mode");
        err = bpf_xdp_attach(ifindex_, prog_fd, XDP_FLAGS_SKB_MODE, nullptr);
        if (err < 0) {
            LOG_ERR("ebpf", "failed to attach XDP: %s (try running as root)", strerror(errno));
            return false;
        }
        LOG_WARN("ebpf", "attached in SKB mode (less efficient)");
    }

    attached_ = true;
    return true;
}

void EbpfLoader::close_maps() {
    for (auto& pair : map_fds_) {
        if (pair.second >= 0) {
            ::close(pair.second);
        }
    }
    map_fds_.clear();
}

} // namespace nids
