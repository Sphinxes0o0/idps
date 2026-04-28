#pragma once
#include <atomic>
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <sys/types.h>

namespace nids {

enum class FloodType { ACK, FIN, RST };

struct ProcessMetrics {
    uint64_t cpu_ns;
    uint64_t mem_bytes;
    uint32_t fd_count;
};

/**
 * @brief Simple metrics registry for Prometheus.
 *
 * Thread-safe counter and gauge metrics that can be exposed
 * in Prometheus text format.
 */
class MetricsRegistry {
public:
    struct MetricInfo {
        std::string name;
        std::string help;
    };

    static MetricsRegistry& instance();

    void add_counter(const std::string& name, const std::string& help);
    void add_gauge(const std::string& name, const std::string& help);

    void inc_counter(const std::string& name, uint64_t delta = 1);
    void set_gauge(const std::string& name, int64_t value);

    std::string collect() const;

    // Pre-defined metrics
    void set_events_written(uint64_t v);
    void inc_events_processed();
    void inc_packets_total();
    void inc_ddos_alerts();
    void inc_rule_matches();
    void inc_dpi_requests();

    // TCP flood metrics
    void recordFloodAlert(FloodType type);
    void updateProcessMetrics(pid_t pid, const ProcessMetrics& m);

private:
    MetricsRegistry() = default;

    std::vector<MetricInfo> counter_infos_;
    std::vector<MetricInfo> gauge_infos_;
    std::unordered_map<std::string, std::atomic<uint64_t>> counter_values_;
    std::unordered_map<std::string, std::atomic<int64_t>> gauge_values_;

    std::atomic<uint64_t> events_written_{0};
    std::atomic<uint64_t> events_processed_{0};
    std::atomic<uint64_t> packets_total_{0};
    std::atomic<uint64_t> ddos_alerts_{0};
    std::atomic<uint64_t> rule_matches_{0};
    std::atomic<uint64_t> dpi_requests_{0};

    std::atomic<int64_t> tcp_ack_flood_active_{0};
    std::atomic<int64_t> tcp_fin_flood_active_{0};
    std::atomic<int64_t> tcp_rst_flood_active_{0};
    std::atomic<uint64_t> tcp_ack_flood_total_{0};
    std::atomic<uint64_t> tcp_fin_flood_total_{0};
    std::atomic<uint64_t> tcp_rst_flood_total_{0};

    std::atomic<int64_t> process_count_{0};
    std::atomic<uint64_t> process_cpu_ns_{0};
    std::atomic<uint64_t> process_mem_bytes_{0};
    std::atomic<int64_t> process_fd_count_{0};
};

} // namespace nids