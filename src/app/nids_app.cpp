#include "nids_app.h"
#include "../nic/ebpf_nic.h"
#include "../ebpf/ringbuf_reader.h"
#include "../core/logger.h"
#include <iostream>
#include <stdexcept>

namespace nids {

std::unique_ptr<INic> NidsApp::make_nic(const std::string& /*iface*/) {
    return std::make_unique<EbpfNic>();
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
                    sev.type = SecEvent::Type::RULE_MATCH;
                    std::snprintf(sev.message, sizeof(sev.message),
                                  "Rule %u matched", event.rule_id);
                } else {
                    sev.type = SecEvent::Type::UNKNOWN;
                }

                event_queue_->push(sev);
            });

            // Start event loop to poll Ringbuf
            ebpf_nic->start_event_loop();
        }

        instances_.push_back(std::move(inst));
        LOG_INFO("app", "pipeline started on iface='%s' (eBPF/XDP)",
                 pcfg.iface.c_str());
    }

    // Communication thread - writes events to log
    comm_thread_ = std::make_unique<CommThread>(event_queue_, cfg_.event_log);
    comm_thread_->start();

    return true;
}

void NidsApp::stop() {
    // Stop event loops first
    for (auto& inst : instances_) {
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
