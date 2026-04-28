#include "metrics_registry.h"
#include <sstream>

namespace nids {

MetricsRegistry& MetricsRegistry::instance() {
    static MetricsRegistry inst;
    return inst;
}

void MetricsRegistry::add_counter(const std::string& name, const std::string& help) {
    counter_infos_.push_back({name, help});
    counter_values_.emplace(name, 0);
}

void MetricsRegistry::add_gauge(const std::string& name, const std::string& help) {
    gauge_infos_.push_back({name, help});
    gauge_values_.emplace(name, 0);
}

void MetricsRegistry::inc_counter(const std::string& name, uint64_t delta) {
    auto it = counter_values_.find(name);
    if (it != counter_values_.end()) {
        it->second.fetch_add(delta, std::memory_order_relaxed);
    }
}

void MetricsRegistry::set_gauge(const std::string& name, int64_t value) {
    auto it = gauge_values_.find(name);
    if (it != gauge_values_.end()) {
        it->second.store(value, std::memory_order_relaxed);
    }
}

std::string MetricsRegistry::collect() const {
    std::ostringstream oss;

    // Built-in metrics
    oss << "# HELP idps_events_written Total events written to log\n";
    oss << "# TYPE idps_events_written counter\n";
    oss << "idps_events_written " << events_written_.load(std::memory_order_relaxed) << "\n";

    oss << "# HELP idps_events_processed Total events processed\n";
    oss << "# TYPE idps_events_processed counter\n";
    oss << "idps_events_processed " << events_processed_.load(std::memory_order_relaxed) << "\n";

    oss << "# HELP idps_packets_total Total packets processed\n";
    oss << "# TYPE idps_packets_total counter\n";
    oss << "idps_packets_total " << packets_total_.load(std::memory_order_relaxed) << "\n";

    oss << "# HELP idps_ddos_alerts_total Total DDoS alerts\n";
    oss << "# TYPE idps_ddos_alerts_total counter\n";
    oss << "idps_ddos_alerts_total " << ddos_alerts_.load(std::memory_order_relaxed) << "\n";

    oss << "# HELP idps_rule_matches_total Total rule matches\n";
    oss << "# TYPE idps_rule_matches_total counter\n";
    oss << "idps_rule_matches_total " << rule_matches_.load(std::memory_order_relaxed) << "\n";

    oss << "# HELP idps_dpi_requests_total Total DPI requests\n";
    oss << "# TYPE idps_dpi_requests_total counter\n";
    oss << "idps_dpi_requests_total " << dpi_requests_.load(std::memory_order_relaxed) << "\n";

    oss << "# HELP idps_tcp_ack_flood_total Total ACK flood alerts\n";
    oss << "# TYPE idps_tcp_ack_flood_total counter\n";
    oss << "idps_tcp_ack_flood_total " << tcp_ack_flood_total_.load(std::memory_order_relaxed) << "\n";

    oss << "# HELP idps_tcp_fin_flood_total Total FIN flood alerts\n";
    oss << "# TYPE idps_tcp_fin_flood_total counter\n";
    oss << "idps_tcp_fin_flood_total " << tcp_fin_flood_total_.load(std::memory_order_relaxed) << "\n";

    oss << "# HELP idps_tcp_rst_flood_total Total RST flood alerts\n";
    oss << "# TYPE idps_tcp_rst_flood_total counter\n";
    oss << "idps_tcp_rst_flood_total " << tcp_rst_flood_total_.load(std::memory_order_relaxed) << "\n";

    oss << "# HELP idps_tcp_ack_flood_active ACK flood detection active flows\n";
    oss << "# TYPE idps_tcp_ack_flood_active gauge\n";
    oss << "idps_tcp_ack_flood_active " << tcp_ack_flood_active_.load(std::memory_order_relaxed) << "\n";

    oss << "# HELP idps_tcp_fin_flood_active FIN flood detection active flows\n";
    oss << "# TYPE idps_tcp_fin_flood_active gauge\n";
    oss << "idps_tcp_fin_flood_active " << tcp_fin_flood_active_.load(std::memory_order_relaxed) << "\n";

    oss << "# HELP idps_tcp_rst_flood_active RST flood detection active flows\n";
    oss << "# TYPE idps_tcp_rst_flood_active gauge\n";
    oss << "idps_tcp_rst_flood_active " << tcp_rst_flood_active_.load(std::memory_order_relaxed) << "\n";

    oss << "# HELP idps_process_count Number of tracked processes\n";
    oss << "# TYPE idps_process_count gauge\n";
    oss << "idps_process_count " << process_count_.load(std::memory_order_relaxed) << "\n";

    oss << "# HELP idps_process_cpu_ns Process CPU time in nanoseconds\n";
    oss << "# TYPE idps_process_cpu_ns gauge\n";
    oss << "idps_process_cpu_ns " << process_cpu_ns_.load(std::memory_order_relaxed) << "\n";

    oss << "# HELP idps_process_mem_bytes Process memory usage bytes\n";
    oss << "# TYPE idps_process_mem_bytes gauge\n";
    oss << "idps_process_mem_bytes " << process_mem_bytes_.load(std::memory_order_relaxed) << "\n";

    oss << "# HELP idps_process_fd_count Process FD count\n";
    oss << "# TYPE idps_process_fd_count gauge\n";
    oss << "idps_process_fd_count " << process_fd_count_.load(std::memory_order_relaxed) << "\n";

    // Custom counters
    for (const auto& info : counter_infos_) {
        auto it = counter_values_.find(info.name);
        uint64_t val = (it != counter_values_.end()) ? it->second.load(std::memory_order_relaxed) : 0;
        oss << "# HELP " << info.name << " " << info.help << "\n";
        oss << "# TYPE " << info.name << " counter\n";
        oss << info.name << " " << val << "\n";
    }

    // Custom gauges
    for (const auto& info : gauge_infos_) {
        auto it = gauge_values_.find(info.name);
        int64_t val = (it != gauge_values_.end()) ? it->second.load(std::memory_order_relaxed) : 0;
        oss << "# HELP " << info.name << " " << info.help << "\n";
        oss << "# TYPE " << info.name << " gauge\n";
        oss << info.name << " " << val << "\n";
    }

    return oss.str();
}

void MetricsRegistry::set_events_written(uint64_t v) {
    events_written_.store(v, std::memory_order_relaxed);
}

void MetricsRegistry::inc_events_processed() {
    events_processed_.fetch_add(1, std::memory_order_relaxed);
}

void MetricsRegistry::inc_packets_total() {
    packets_total_.fetch_add(1, std::memory_order_relaxed);
}

void MetricsRegistry::inc_ddos_alerts() {
    ddos_alerts_.fetch_add(1, std::memory_order_relaxed);
}

void MetricsRegistry::inc_rule_matches() {
    rule_matches_.fetch_add(1, std::memory_order_relaxed);
}

void MetricsRegistry::inc_dpi_requests() {
    dpi_requests_.fetch_add(1, std::memory_order_relaxed);
}

void MetricsRegistry::recordFloodAlert(FloodType type) {
    switch (type) {
        case FloodType::ACK:
            tcp_ack_flood_total_.fetch_add(1, std::memory_order_relaxed);
            tcp_ack_flood_active_.store(1, std::memory_order_relaxed);
            break;
        case FloodType::FIN:
            tcp_fin_flood_total_.fetch_add(1, std::memory_order_relaxed);
            tcp_fin_flood_active_.store(1, std::memory_order_relaxed);
            break;
        case FloodType::RST:
            tcp_rst_flood_total_.fetch_add(1, std::memory_order_relaxed);
            tcp_rst_flood_active_.store(1, std::memory_order_relaxed);
            break;
    }
}

void MetricsRegistry::updateProcessMetrics(pid_t pid, const ProcessMetrics& m) {
    (void)pid;
    process_count_.store(1, std::memory_order_relaxed);
    process_cpu_ns_.store(static_cast<int64_t>(m.cpu_ns), std::memory_order_relaxed);
    process_mem_bytes_.store(static_cast<int64_t>(m.mem_bytes), std::memory_order_relaxed);
    process_fd_count_.store(static_cast<int64_t>(m.fd_count), std::memory_order_relaxed);
}

} // namespace nids