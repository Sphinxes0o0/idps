#pragma once
#include "../ipc/event_queue.hpp"
#include "../nic/nic_interface.h"
#include "../threads/comm_thread.h"
#include "../rules/rule_parser.h"
#include "../xdp/af_xdp.h"
#include <memory>
#include <string>
#include <vector>

namespace nids {

/**
 * @brief Configuration for one NIC → pipeline instance.
 */
struct PipelineConfig {
    std::string iface;             ///< Network interface name, e.g., "eth0"
    uint32_t    ddos_threshold = 10000;
    int         capture_cpu = -1;
    std::string rules_file;        ///< Path to rules file (optional)
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
    std::unique_ptr<INic>    nic;
    std::unique_ptr<XdpProcessor> xdp;  ///< AF_XDP processor for user-space DPI
    std::vector<MatchRule>   content_rules;  ///< Rules needing BMH content matching
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
     * Overridden in tests to inject mock.
     */
    virtual std::unique_ptr<INic> make_nic(const std::string& iface);

private:
    /**
     * @brief Load rules from file and push to kernel/user-space
     */
    bool load_rules(const std::string& path, INic* nic, std::vector<MatchRule>& content_rules);

    AppConfig cfg_;
    std::shared_ptr<EventQueue>      event_queue_;
    std::unique_ptr<CommThread>     comm_thread_;
    std::vector<PipelineInstance>    instances_;
};

} // namespace nids
