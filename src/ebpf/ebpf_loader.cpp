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
}

EbpfLoader::~EbpfLoader() {
    detach();
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

    loaded_ = true;
    LOG_INFO("ebpf", "loaded and attached to %s", iface.c_str());
    return true;
}

void EbpfLoader::detach() {
    if (attached_ && ifindex_ > 0) {
        struct bpf_xdp_attach_opts opts = {};
        opts.sz = sizeof(opts);
        bpf_xdp_detach(ifindex_, 0, &opts);
        attached_ = false;
    }

    close_maps();

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

    LOG_DEBUG("ebpf", "updated rule %u", rule.rule_id);
    return true;
}

bool EbpfLoader::delete_rule(uint32_t rule_id) {
    int rules_fd = get_map_fd("rules");
    if (rules_fd < 0) {
        return false;
    }

    uint32_t key = rule_id;
    int err = bpf_map_delete_elem(rules_fd, &key);
    if (err < 0 && errno != ENOENT) {
        LOG_ERR("ebpf", "failed to delete rule %u: %s", rule_id, strerror(errno));
        return false;
    }

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
    uint64_t value = 0;

    // 简单起见，读取第一个 CPU 的值
    // 实际应遍历所有 CPU 并求和
    int err = bpf_map_lookup_elem(stats_fd, &key, &value);
    if (err < 0) {
        return 0;
    }

    return value;
}

bool EbpfLoader::load_bpf_object(const std::string& path) {
    if (load_bpf_object_file(path.c_str(), &obj_) < 0) {
        return false;
    }
    return true;
}

bool EbpfLoader::attach_xdp() {
    int prog_fd = bpf_program__fd(prog_);
    if (prog_fd < 0) {
        LOG_ERR("ebpf", "failed to get program fd");
        return false;
    }

    struct bpf_xdp_attach_opts opts = {};
    opts.sz = sizeof(opts);
    opts.old_prog_fd = -1;

    int err = bpf_xdp_attach(ifindex_, prog_fd, XDP_FLAGS_DRV_MODE, &opts);
    if (err < 0) {
        LOG_ERR("ebpf", "bpf_xdp_attach failed, trying SKB mode");
        err = bpf_xdp_attach(ifindex_, prog_fd, XDP_FLAGS_SKB_MODE, &opts);
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
