#pragma once
#include "../core/pool.hpp"
#include "../core/spsc_queue.hpp"
#include "../core/pipeline.h"
#include "../ipc/event_queue.hpp"
#include "../nic/nic_interface.h"
#include "../threads/capture_thread.h"
#include "../threads/processing_thread.h"
#include "../threads/comm_thread.h"
#include "../stages/preprocess_stage.h"
#include "../stages/decode_stage.h"
#include "../stages/detection_stage.h"
#include "../stages/matching_stage.h"
#include "../stages/event_stage.h"
#include <memory>
#include <string>
#include <vector>

namespace nids {

/**
 * @brief Configuration for one NIC → pipeline instance.
 */
struct PipelineConfig {
    std::string iface;             ///< Network interface name, e.g., "eth0"
    size_t      pool_slots  = 16384;
    size_t      slot_size   = 2048;
    size_t      queue_depth = 4096;
    uint32_t    ddos_pkt_threshold = 10000;
    uint32_t    ddos_window_ms     = 1000;
    std::string rules_file;        ///< Optional path to rules file
    int         capture_cpu = -1;
    int         process_cpu = -1;
};

/**
 * @brief Configuration for the whole NIDS application.
 */
struct AppConfig {
    std::vector<PipelineConfig> pipelines;
    std::string event_log = "-";  ///< "-" = stdout
};

/**
 * @brief Owns all resources for one NIC pipeline.
 */
struct PipelineInstance {
    std::unique_ptr<PacketPool>              pool;
    std::unique_ptr<SPSCQueue<PacketSlot*>>  queue;
    std::unique_ptr<Pipeline>                pipeline;
    std::unique_ptr<INic>                    nic;
    std::unique_ptr<CaptureThread>           capture;
    std::unique_ptr<ProcessingThread>        processing;
};

/**
 * @brief Top-level NIDS application.
 *
 * Wires together all subsystems per NIC and provides a blocking run() method.
 */
class NidsApp {
public:
    explicit NidsApp(AppConfig cfg) : cfg_(std::move(cfg)) {}

    /**
     * @brief Build and start all pipelines and the comm thread.
     * @return false if any pipeline fails to initialise.
     */
    bool start();

    /**
     * @brief Orderly shutdown of all threads.
     */
    void stop();

    /**
     * @brief Block until stop() is called from another thread or a signal.
     */
    void wait();

    const std::shared_ptr<EventQueue>& event_queue() const { return event_queue_; }

protected:
    /**
     * @brief Factory to create the NIC instance.
     * Overridden in tests to inject MockNic.
     */
    virtual std::unique_ptr<INic> make_nic();

private:
    AppConfig cfg_;
    std::shared_ptr<EventQueue>      event_queue_;
    std::unique_ptr<CommThread>      comm_thread_;
    std::vector<PipelineInstance>    instances_;
};

} // namespace nids
