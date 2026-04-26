#pragma once
#include <atomic>
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

namespace nids {

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
};

} // namespace nids