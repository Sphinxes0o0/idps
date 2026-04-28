#include "nids_app.h"
#include "../nic/ebpf_nic.h"
#include "../ebpf/ebpf_loader.h"
#include "../ebpf/ringbuf_reader.h"
#include "../ebpf/trace_reader.h"
#include "../utils/bmh_search.h"
#include "../core/logger.h"
#include "../metrics/metrics_registry.h"
#include <iostream>
#include <stdexcept>
#include <thread>
#include <fstream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace nids {

AppConfig load_config(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) {
        throw std::runtime_error("failed to open config file: " + path);
    }
    json j;
    f >> j;

    AppConfig cfg;
    cfg.event_log = j.value("event_log", "-");
    cfg.use_syslog = j.value("use_syslog", false);
    cfg.metrics_port = j.value("metrics_port", 0);
    cfg.trace_bpf_obj = j.value("trace_bpf_obj", "");

    if (j.contains("pipelines")) {
        for (const auto& p : j["pipelines"]) {
            PipelineConfig pcfg;
            pcfg.iface = p.value("iface", "");
            pcfg.rules_file = p.value("rules_file", "");
            pcfg.ddos_threshold = p.value("ddos_threshold", 10000);
            pcfg.window_size_ns = p.value("window_size_ns", 1000000000);
            pcfg.enabled = p.value("enabled", 1);
            pcfg.drop_enabled = p.value("drop_enabled", 0);
            pcfg.port_scan_threshold = p.value("port_scan_threshold", 20);
            pcfg.capture_cpu = p.value("capture_cpu", -1);
            cfg.pipelines.push_back(pcfg);
        }
    } else {
        PipelineConfig pcfg;
        pcfg.iface = j.value("interface", j.value("iface", ""));
        pcfg.rules_file = j.value("rules_file", "");
        pcfg.ddos_threshold = j.value("ddos_threshold", 10000);
        pcfg.window_size_ns = j.value("window_size_ns", 1000000000);
        pcfg.enabled = j.value("enabled", 1);
        pcfg.drop_enabled = j.value("drop_enabled", 0);
        pcfg.port_scan_threshold = j.value("port_scan_threshold", 20);
        cfg.pipelines.push_back(pcfg);
    }

    return cfg;
}

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

    auto* ebpf_nic = dynamic_cast<EbpfNic*>(nic);
    if (ebpf_nic) {
        auto* loader = ebpf_nic->get_loader();
        if (loader) {
            for (const auto& rule : rs.content_rules) {
                RuleEntry entry;
                entry.rule_id = static_cast<uint32_t>(rule.id);
                entry.action = 2;
                entry.severity = 1;
                entry.protocol = rule.proto;
                entry.dst_port = rule.dst_port;
                entry.dst_port_max = rule.dst_port_max;
                entry.dpi_needed = 1;

                if (!loader->update_rule(entry)) {
                    LOG_WARN("app", "failed to push content rule %d to kernel", rule.id);
                }
            }

            for (const auto& rule : rs.simple_rules) {
                RuleEntry entry;
                entry.rule_id = static_cast<uint32_t>(rule.id);
                entry.action = 2;
                entry.severity = 1;
                entry.protocol = rule.proto;
                entry.dst_port = rule.dst_port;
                entry.dst_port_max = rule.dst_port_max;
                entry.dpi_needed = 0;

                if (!loader->update_rule(entry)) {
                    LOG_WARN("app", "failed to push simple rule %d to kernel", rule.id);
                }
            }
        }
    }

    content_rules = std::move(rs.content_rules);
    return true;
}

bool NidsApp::reload_rules() {
    LOG_INFO("app", "reloading rules...");

    int reloaded = 0;
    for (auto& inst : instances_) {
        size_t idx = &inst - &instances_[0];
        if (idx >= cfg_.pipelines.size())
            continue;

        const auto& pcfg = cfg_.pipelines[idx];
        if (pcfg.rules_file.empty())
            continue;

        RuleParser parser;
        RuleSet rs = parser.parse_file(pcfg.rules_file);
        if (!parser.error().empty()) {
            LOG_WARN("app", "rule reload parse warning: %s", parser.error().c_str());
        }

        auto* ebpf_nic = dynamic_cast<EbpfNic*>(inst.nic.get());
        if (!ebpf_nic)
            continue;

        auto* loader = ebpf_nic->get_loader();
        if (!loader)
            continue;

        std::set<uint32_t> new_rule_ids;
        for (const auto& rule : rs.content_rules) {
            new_rule_ids.insert(rule.id);
        }
        for (const auto& rule : rs.simple_rules) {
            new_rule_ids.insert(rule.id);
        }

        for (uint32_t old_id : inst.active_rule_ids) {
            if (new_rule_ids.find(old_id) == new_rule_ids.end()) {
                loader->delete_rule(old_id);
            }
        }

        for (const auto& rule : rs.content_rules) {
            RuleEntry entry;
            entry.rule_id = static_cast<uint32_t>(rule.id);
            entry.action = 2;
            entry.severity = 1;
            entry.protocol = rule.proto;
            entry.dst_port = rule.dst_port;
            entry.dst_port_max = rule.dst_port_max;
            entry.dpi_needed = 1;

            if (loader->update_rule(entry)) {
                reloaded++;
            }
        }

        for (const auto& rule : rs.simple_rules) {
            RuleEntry entry;
            entry.rule_id = static_cast<uint32_t>(rule.id);
            entry.action = 2;
            entry.severity = 1;
            entry.protocol = rule.proto;
            entry.dst_port = rule.dst_port;
            entry.dst_port_max = rule.dst_port_max;
            entry.dpi_needed = 0;

            if (loader->update_rule(entry)) {
                reloaded++;
            }
        }

        inst.content_rules = std::move(rs.content_rules);
        inst.active_rule_ids = std::move(new_rule_ids);

        if (inst.xdp) {
            inst.xdp->clear_all_rules();

            std::vector<std::pair<std::string, int>> dpi_rules;
            for (const auto& rule : inst.content_rules) {
                dpi_rules.emplace_back(rule.content, static_cast<int>(rule.id));
            }
            inst.xdp->set_rules(dpi_rules);

            for (const auto& rule : inst.content_rules) {
                if (rule.tls_version != 0) {
                    inst.xdp->add_tls_version_rule(rule.tls_version, rule.id, rule.message);
                }
                if (!rule.tls_sni.empty()) {
                    inst.xdp->add_sni_rule(rule.tls_sni, rule.id, rule.message);
                }
                if (rule.tls_cipher != 0) {
                    inst.xdp->add_cipher_rule(rule.tls_cipher, rule.id, rule.message);
                }
            }
        }
    }

    LOG_INFO("app", "rules reloaded: %d rules updated", reloaded);
    return true;
}

bool NidsApp::start() {
    event_queue_ = std::make_shared<EventQueue>(65536);

    for (const auto& pcfg : cfg_.pipelines) {
        PipelineInstance inst;

        inst.nic = make_nic(pcfg.iface);
        if (!inst.nic->open(pcfg.iface)) {
            LOG_ERR("app", "failed to open NIC '%s'", pcfg.iface.c_str());
            return false;
        }

        if (!load_rules(pcfg.rules_file, inst.nic.get(), inst.content_rules)) {
            LOG_WARN("app", "failed to load rules from '%s'", pcfg.rules_file.c_str());
        }

        auto* ebpf_nic = dynamic_cast<EbpfNic*>(inst.nic.get());
        if (ebpf_nic) {
            NidsConfig cfg;
            cfg.ddos_threshold = pcfg.ddos_threshold;
            cfg.window_size_ns = pcfg.window_size_ns;
            cfg.enabled = pcfg.enabled;
            cfg.drop_enabled = pcfg.drop_enabled;
            cfg.port_scan_threshold = pcfg.port_scan_threshold;
            ebpf_nic->set_config(cfg);

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
                    sev.type = SecEvent::Type::RULE_MATCH;
                    std::snprintf(sev.message, sizeof(sev.message),
                                  "Rule %u matched (kernel)", event.rule_id);
                } else if (event.event_type == EVENT_DPI_REQUEST) {
                    sev.type = SecEvent::Type::RULE_MATCH;
                    std::snprintf(sev.message, sizeof(sev.message),
                                  "DPI requested for rule %u (payload unavailable)", event.rule_id);
                    LOG_DEBUG("app", "DPI_REQUEST for rule %u src=%u:%u dst=%u:%u proto=%u",
                              event.rule_id, event.src_ip, event.src_port,
                              event.dst_ip, event.dst_port, event.protocol);
                } else if (event.event_type == EVENT_FRAG_REASSEMBLE) {
                    sev.type = SecEvent::Type::UNKNOWN;
                    std::snprintf(sev.message, sizeof(sev.message),
                                  "Fragment reassembly complete: %u fragments from %08x:%u to %08x:%u",
                                  event.rule_id, event.src_ip, event.src_port,
                                  event.dst_ip, event.dst_port);
                    LOG_DEBUG("app", "FRAG_REASSEMBLE: %u fragments src=%u:%u dst=%u:%u proto=%u",
                              event.rule_id, event.src_ip, event.src_port,
                              event.dst_ip, event.dst_port, event.protocol);
                } else if (event.event_type == EVENT_ACK_FLOOD) {
                    sev.type = SecEvent::Type::DDOS;
                    std::snprintf(sev.message, sizeof(sev.message),
                                  "TCP ACK flood detected from %08x:%u to %08x:%u",
                                  event.src_ip, event.src_port, event.dst_ip, event.dst_port);
                    LOG_DEBUG("app", "ACK_FLOOD: src=%u:%u dst=%u:%u proto=%u",
                              event.src_ip, event.src_port, event.dst_ip, event.dst_port, event.protocol);
                } else if (event.event_type == EVENT_FIN_FLOOD) {
                    sev.type = SecEvent::Type::DDOS;
                    std::snprintf(sev.message, sizeof(sev.message),
                                  "TCP FIN flood detected from %08x:%u to %08x:%u",
                                  event.src_ip, event.src_port, event.dst_ip, event.dst_port);
                    LOG_DEBUG("app", "FIN_FLOOD: src=%u:%u dst=%u:%u proto=%u",
                              event.src_ip, event.src_port, event.dst_ip, event.dst_port, event.protocol);
                } else if (event.event_type == EVENT_RST_FLOOD) {
                    sev.type = SecEvent::Type::DDOS;
                    std::snprintf(sev.message, sizeof(sev.message),
                                  "TCP RST flood detected from %08x:%u to %08x:%u",
                                  event.src_ip, event.src_port, event.dst_ip, event.dst_port);
                    LOG_DEBUG("app", "RST_FLOOD: src=%u:%u dst=%u:%u proto=%u",
                              event.src_ip, event.src_port, event.dst_ip, event.dst_port, event.protocol);
                } else {
                    sev.type = SecEvent::Type::UNKNOWN;
                }

                event_queue_->push(sev);
            });

            ebpf_nic->start_event_loop();
        }

        if (!inst.content_rules.empty()) {
            inst.xdp = std::make_unique<XdpProcessor>();
            XdpConfig xdp_cfg;
            xdp_cfg.iface = pcfg.iface;
            xdp_cfg.queue_id = pcfg.capture_cpu >= 0 ? static_cast<uint32_t>(pcfg.capture_cpu) : 0;

            if (inst.xdp->open(xdp_cfg)) {
                std::vector<std::pair<std::string, int>> dpi_rules;
                for (const auto& rule : inst.content_rules) {
                    dpi_rules.emplace_back(rule.content, static_cast<int>(rule.id));
                }
                inst.xdp->set_rules(dpi_rules);

                for (const auto& rule : inst.content_rules) {
                    if (rule.tls_version != 0) {
                        inst.xdp->add_tls_version_rule(rule.tls_version, rule.id, rule.message);
                    }
                    if (!rule.tls_sni.empty()) {
                        inst.xdp->add_sni_rule(rule.tls_sni, rule.id, rule.message);
                    }
                    if (rule.tls_cipher != 0) {
                        inst.xdp->add_cipher_rule(rule.tls_cipher, rule.id, rule.message);
                    }
                }

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

    if (!cfg_.trace_bpf_obj.empty()) {
        trace_reader_ = std::make_unique<TraceReader>();
        if (trace_reader_->init(cfg_.trace_bpf_obj.c_str())) {
            trace_reader_->set_process_callback([this](const ProcessEvent& event) {
                SecEvent sev;
                sev.timestamp = event.timestamp;
                sev.src_ip = event.saddr;
                sev.dst_ip = event.daddr;
                sev.src_port = event.sport;
                sev.dst_port = event.dport;
                sev.ip_proto = event.protocol;
                sev.rule_id = 0;
                sev.type = SecEvent::Type::UNKNOWN;

                switch (event.type) {
                    case ProcessEventType::CONNECT:
                        std::snprintf(sev.message, sizeof(sev.message),
                                      "Process connect: pid=%d tid=%d comm=%s %08x:%u -> %08x:%u",
                                      event.pid, event.tid, event.comm,
                                      event.saddr, event.sport, event.daddr, event.dport);
                        break;
                    case ProcessEventType::ACCEPT:
                        std::snprintf(sev.message, sizeof(sev.message),
                                      "Process accept: pid=%d tid=%d comm=%s fd=%d",
                                      event.pid, event.tid, event.comm, event.fd);
                        break;
                    case ProcessEventType::CLOSE:
                        std::snprintf(sev.message, sizeof(sev.message),
                                      "Process close: pid=%d tid=%d comm=%s fd=%d",
                                      event.pid, event.tid, event.comm, event.fd);
                        break;
                    case ProcessEventType::EXIT:
                        std::snprintf(sev.message, sizeof(sev.message),
                                      "Process exit: pid=%d tid=%d comm=%s",
                                      event.pid, event.tid, event.comm);
                        break;
                }
                event_queue_->push(sev);
                LOG_DEBUG("app", "process event: %s", sev.message);
            });

            std::thread trace_thread([this]() {
                trace_reader_->start_poll();
            });
            trace_thread.detach();
            LOG_INFO("app", "trace reader started with BPF obj='%s'", cfg_.trace_bpf_obj.c_str());
        } else {
            LOG_WARN("app", "failed to initialize trace reader with BPF obj='%s'", cfg_.trace_bpf_obj.c_str());
            trace_reader_.reset();
        }
    }

    comm_thread_ = std::make_unique<CommThread>(event_queue_, cfg_.event_log, cfg_.use_syslog);
    comm_thread_->start();

    if (cfg_.metrics_port > 0) {
        prom_server_ = std::make_unique<PrometheusServer>(cfg_.metrics_port);
        prom_server_->set_collector([this]() {
            auto& metrics = MetricsRegistry::instance();
            if (comm_thread_) {
                metrics.set_events_written(comm_thread_->events_written());
            }
            return metrics.collect();
        });
        prom_server_->start();
        LOG_INFO("app", "Prometheus metrics server listening on port %u", cfg_.metrics_port);
    }

    return true;
}

void NidsApp::stop() {
    for (auto& inst : instances_) {
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

    if (event_queue_) {
        event_queue_->signal_shutdown();
    }

    if (trace_reader_) {
        trace_reader_->stop();
        trace_reader_.reset();
    }

    if (comm_thread_) {
        comm_thread_->stop();
    }

    if (prom_server_) {
        prom_server_->stop();
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
