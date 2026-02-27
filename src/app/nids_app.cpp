#include "nids_app.h"
#include "../nic/af_packet_nic.h"
#include "../core/logger.h"
#include <iostream>
#include <stdexcept>

namespace nids {

std::unique_ptr<INic> NidsApp::make_nic() {
    return std::make_unique<AfPacketNic>();
}

bool NidsApp::start() {
    // Shared event queue for all pipelines
    event_queue_ = std::make_shared<EventQueue>(65536);

    // Build one pipeline instance per configured NIC
    for (const auto& pcfg : cfg_.pipelines) {
        PipelineInstance inst;

        // Memory
        inst.pool  = std::make_unique<PacketPool>(pcfg.pool_slots, pcfg.slot_size);
        inst.queue = std::make_unique<SPSCQueue<PacketSlot*>>(pcfg.queue_depth);

        // NIC
        inst.nic = make_nic();
        if (!inst.nic->open(pcfg.iface)) {
            LOG_ERR("app", "failed to open NIC '%s'", pcfg.iface.c_str());
            return false;
        }

        // Pipeline
        inst.pipeline = std::make_unique<Pipeline>();
        inst.pipeline->add_stage(std::make_unique<PreprocessStage>());
        inst.pipeline->add_stage(std::make_unique<DecodeStage>());
        inst.pipeline->add_stage(
            std::make_unique<DetectionStage>(pcfg.ddos_pkt_threshold, pcfg.ddos_window_ms));

        auto* matcher = new MatchingStage();
        if (!pcfg.rules_file.empty()) {
            if (!matcher->load_rules(pcfg.rules_file)) {
                LOG_WARN("app", "failed to load rules from '%s'", pcfg.rules_file.c_str());
            }
        }
        inst.pipeline->add_stage(std::unique_ptr<IStage>(matcher));
        inst.pipeline->add_stage(std::make_unique<EventStage>(event_queue_));

        // Threads
        inst.capture    = std::make_unique<CaptureThread>(
            *inst.pool, *inst.queue, *inst.nic, pcfg.capture_cpu);
        inst.processing = std::make_unique<ProcessingThread>(
            *inst.pool, *inst.queue, *inst.pipeline, pcfg.process_cpu);

        inst.processing->start();
        inst.capture->start();

        instances_.push_back(std::move(inst));
        LOG_INFO("app", "pipeline started on iface='%s' ddos_threshold=%u rules='%s'",
                 pcfg.iface.c_str(), pcfg.ddos_pkt_threshold,
                 pcfg.rules_file.empty() ? "(none)" : pcfg.rules_file.c_str());
    }

    // Communication thread
    comm_thread_ = std::make_unique<CommThread>(event_queue_, cfg_.event_log);
    comm_thread_->start();

    return true;
}

void NidsApp::stop() {
    // Stop capture first (source of data)
    for (auto& inst : instances_) {
        if (inst.capture) inst.capture->stop();
    }
    // Then processing (drain remaining packets)
    for (auto& inst : instances_) {
        if (inst.processing) inst.processing->stop();
    }
    // Finally comm thread
    if (comm_thread_) comm_thread_->stop();

    instances_.clear();
}

void NidsApp::wait() {
    // Simple busy-wait; real impl would use sigwait / condition variable
    while (true) {
        struct timespec ts{1, 0};
        nanosleep(&ts, nullptr);
    }
}

} // namespace nids
