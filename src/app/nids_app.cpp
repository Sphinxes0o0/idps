#include "nids_app.h"
#include "../nic/ebpf_nic.h"
#include "../ebpf/ebpf_loader.h"
#include "../ebpf/ringbuf_reader.h"
#include "../utils/bmh_search.h"
#include "../core/logger.h"
#include <iostream>
#include <stdexcept>
#include <thread>

namespace nids {

std::unique_ptr<INic> NidsApp::make_nic(const std::string& /*iface*/) {
    return std::make_unique<EbpfNic>();
}

bool NidsApp::load_rules(const std::string& path, INic* nic,
                         std::vector<MatchRule>& content_rules) {
    if (path.empty())
        return true;

    RuleParser parser;
    RuleSet rs = parser.parse_file(path);

    if (!parser.error().empty()) {
        LOG_WARN("app", "rule parse warning: %s", parser.error().c_str());
    }

    LOG_INFO("app", "loaded %zu simple rules, %zu content rules",
             rs.simple_rules.size(), rs.content_rules.size());

    // Push simple rules to kernel via EbpfLoader
    auto* ebpf_nic = dynamic_cast<EbpfNic*>(nic);
    if (ebpf_nic) {
        auto* loader = ebpf_nic->get_loader();
        if (loader) {
            // Push content rules with dpi_needed=1
            for (const auto& rule : rs.content_rules) {
                RuleEntry entry;
                entry.rule_id = static_cast<uint32_t>(rule.id);
                entry.action = 2;  // alert
                entry.severity = 1;  // low
                entry.protocol = rule.proto;
                entry.dst_port = rule.dst_port;
                entry.dpi_needed = 1;  // 需要用户态 DPI

                if (!loader->update_rule(entry)) {
                    LOG_WARN("app", "failed to push content rule %d to kernel", rule.id);
                }
            }

            // Push simple rules with dpi_needed=0
            for (const auto& rule : rs.simple_rules) {
                RuleEntry entry;
                entry.rule_id = static_cast<uint32_t>(rule.id);
                entry.action = 2;  // alert
                entry.severity = 1;  // low
                entry.protocol = rule.proto;
                entry.dst_port = rule.dst_port;
                entry.dpi_needed = 0;  // 内核直接匹配

                if (!loader->update_rule(entry)) {
                    LOG_WARN("app", "failed to push simple rule %d to kernel", rule.id);
                }
            }
        }
    }

    // Store content rules for user-space BMH matching
    // Note: Currently DPI requires AF_XDP or separate packet capture
    // This infrastructure is ready for future implementation
    content_rules = std::move(rs.content_rules);

    return true;
}

bool NidsApp::reload_rules() {
    LOG_INFO("app", "reloading rules...");

    int reloaded = 0;
    for (auto& inst : instances_) {
        // Get pipeline config (stored in cfg_ at same index)
        size_t idx = &inst - &instances_[0];
        if (idx >= cfg_.pipelines.size())
            continue;

        const auto& pcfg = cfg_.pipelines[idx];
        if (pcfg.rules_file.empty())
            continue;

        // Re-parse rules
        RuleParser parser;
        RuleSet rs = parser.parse_file(pcfg.rules_file);
        if (!parser.error().empty()) {
            LOG_WARN("app", "rule reload parse warning: %s", parser.error().c_str());
        }

        // Push to kernel
        auto* ebpf_nic = dynamic_cast<EbpfNic*>(inst.nic.get());
        if (!ebpf_nic)
            continue;

        auto* loader = ebpf_nic->get_loader();
        if (!loader)
            continue;

        // Push content rules
        for (const auto& rule : rs.content_rules) {
            RuleEntry entry;
            entry.rule_id = static_cast<uint32_t>(rule.id);
            entry.action = 2;
            entry.severity = 1;
            entry.protocol = rule.proto;
            entry.dst_port = rule.dst_port;
            entry.dpi_needed = 1;

            if (loader->update_rule(entry)) {
                reloaded++;
            }
        }

        // Push simple rules
        for (const auto& rule : rs.simple_rules) {
            RuleEntry entry;
            entry.rule_id = static_cast<uint32_t>(rule.id);
            entry.action = 2;
            entry.severity = 1;
            entry.protocol = rule.proto;
            entry.dst_port = rule.dst_port;
            entry.dpi_needed = 0;

            if (loader->update_rule(entry)) {
                reloaded++;
            }
        }

        // Update content rules for user-space BMH
        inst.content_rules = std::move(rs.content_rules);

        // Update AF_XDP rules if running
        if (inst.xdp) {
            std::vector<std::pair<std::string, int>> dpi_rules;
            for (const auto& rule : inst.content_rules) {
                dpi_rules.emplace_back(rule.content, static_cast<int>(rule.id));
            }
            inst.xdp->set_rules(dpi_rules);
        }
    }

    LOG_INFO("app", "rules reloaded: %d rules updated", reloaded);
    return true;
}

bool NidsApp::start() {
    // Shared event queue for all pipelines
    event_queue_ = std::make_shared<EventQueue>(65536);

    // Build one pipeline instance per configured NIC
    for (const auto& pcfg : cfg_.pipelines) {
        PipelineInstance inst;

        // NIC (eBPF/XDP)
        inst.nic = make_nic(pcfg.iface);
        if (!inst.nic->open(pcfg.iface)) {
            LOG_ERR("app", "failed to open NIC '%s'", pcfg.iface.c_str());
            return false;
        }

        // Load rules
        if (!load_rules(pcfg.rules_file, inst.nic.get(), inst.content_rules)) {
            LOG_WARN("app", "failed to load rules from '%s'", pcfg.rules_file.c_str());
        }

        // Set up alert callback to convert eBPF events to SecEvent
        auto* ebpf_nic = dynamic_cast<EbpfNic*>(inst.nic.get());
        if (ebpf_nic) {
            ebpf_nic->set_alert_callback([this](const AlertEvent& event) {
                SecEvent sev;
                sev.timestamp = event.timestamp;
                sev.src_ip = event.src_ip;
                sev.dst_ip = event.dst_ip;
                sev.src_port = event.src_port;
                sev.dst_port = event.dst_port;
                sev.ip_proto = event.protocol;
                sev.rule_id = event.rule_id;

                if (event.event_type == EVENT_DDoS_ALERT) {
                    sev.type = SecEvent::Type::DDOS;
                    std::snprintf(sev.message, sizeof(sev.message),
                                  "DDoS alert: flow %08x packets exceeded threshold", event.src_ip);
                } else if (event.event_type == EVENT_RULE_MATCH) {
                    // 内核已匹配简单规则 (proto/port)
                    sev.type = SecEvent::Type::RULE_MATCH;
                    std::snprintf(sev.message, sizeof(sev.message),
                                  "Rule %u matched (kernel)", event.rule_id);
                } else if (event.event_type == EVENT_DPI_REQUEST) {
                    // 需要用户态 DPI 检查
                    // Note: 当前架构下无法获取 packet payload 进行 BMH 匹配
                    // 需要 AF_XDP 或额外的数据包捕获机制
                    sev.type = SecEvent::Type::RULE_MATCH;
                    std::snprintf(sev.message, sizeof(sev.message),
                                  "DPI requested for rule %u (payload unavailable)", event.rule_id);
                    LOG_DEBUG("app", "DPI_REQUEST for rule %u src=%u:%u dst=%u:%u proto=%u",
                              event.rule_id, event.src_ip, event.src_port,
                              event.dst_ip, event.dst_port, event.protocol);
                } else {
                    sev.type = SecEvent::Type::UNKNOWN;
                }

                event_queue_->push(sev);
            });

            // Start event loop to poll Ringbuf
            ebpf_nic->start_event_loop();
        }

        // Set up AF_XDP for user-space DPI with BMH content matching
        if (!inst.content_rules.empty()) {
            inst.xdp = std::make_unique<XdpProcessor>();
            XdpConfig xdp_cfg;
            xdp_cfg.iface = pcfg.iface;
            xdp_cfg.queue_id = pcfg.capture_cpu >= 0 ? static_cast<uint32_t>(pcfg.capture_cpu) : 0;

            if (inst.xdp->open(xdp_cfg)) {
                // Convert MatchRule to (pattern, rule_id) pairs for XdpProcessor
                std::vector<std::pair<std::string, int>> dpi_rules;
                for (const auto& rule : inst.content_rules) {
                    dpi_rules.emplace_back(rule.content, static_cast<int>(rule.id));
                }
                inst.xdp->set_rules(dpi_rules);

                // Set DPI callback to feed results into event queue
                inst.xdp->set_dpi_callback([this](const XdpPacket& pkt, const DpiResult& result) {
                    SecEvent sev;
                    sev.timestamp = pkt.timestamp;
                    sev.src_ip = pkt.src_ip;
                    sev.dst_ip = pkt.dst_ip;
                    sev.src_port = pkt.src_port;
                    sev.dst_port = pkt.dst_port;
                    sev.ip_proto = pkt.protocol;
                    sev.rule_id = static_cast<uint32_t>(result.rule_id);
                    sev.type = SecEvent::Type::RULE_MATCH;
                    std::snprintf(sev.message, sizeof(sev.message),
                                  "Rule %d matched (BMH): %s", result.rule_id, result.message.c_str());
                    event_queue_->push(sev);
                    LOG_DEBUG("app", "BMH match: rule %d src=%u:%u dst=%u:%u",
                              result.rule_id, pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port);
                });

                // Start AF_XDP processing in background thread
                std::thread xdp_thread([&inst]() {
                    inst.xdp->run();
                });
                xdp_thread.detach();
                LOG_INFO("app", "AF_XDP DPI started on iface='%s' with %zu content rules",
                         pcfg.iface.c_str(), inst.content_rules.size());
            } else {
                LOG_WARN("app", "failed to open AF_XDP on iface='%s'", pcfg.iface.c_str());
            }
        }

        instances_.push_back(std::move(inst));
        LOG_INFO("app", "pipeline started on iface='%s' rules='%s'",
                 pcfg.iface.c_str(),
                 pcfg.rules_file.empty() ? "(none)" : pcfg.rules_file.c_str());
    }

    // Communication thread - writes events to log
    comm_thread_ = std::make_unique<CommThread>(event_queue_, cfg_.event_log);
    comm_thread_->start();

    return true;
}

void NidsApp::stop() {
    // Stop event loops first
    for (auto& inst : instances_) {
        // Stop AF_XDP processor
        if (inst.xdp) {
            inst.xdp->stop();
        }

        auto* ebpf_nic = dynamic_cast<EbpfNic*>(inst.nic.get());
        if (ebpf_nic) {
            ebpf_nic->stop_event_loop();
        }
        if (inst.nic) {
            inst.nic->close();
        }
    }

    // Signal shutdown to event queue
    if (event_queue_) {
        event_queue_->signal_shutdown();
    }

    // Stop comm thread
    if (comm_thread_) {
        comm_thread_->stop();
    }

    instances_.clear();
}

void NidsApp::wait() {
    while (true) {
        struct timespec ts{1, 0};
        nanosleep(&ts, nullptr);
    }
}

} // namespace nids
