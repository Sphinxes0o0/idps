#pragma once
#include <string>
#include <thread>
#include <atomic>
#include <functional>
#include <cstdint>

namespace nids {

/**
 * @brief Simple Prometheus metrics HTTP server.
 *
 * Serves /metrics endpoint in Prometheus text format using only POSIX sockets.
 * No external HTTP library dependencies.
 */
class PrometheusServer {
public:
    using StatsCollector = std::function<std::string()>;

    PrometheusServer(uint16_t port = 8080);
    ~PrometheusServer();

    PrometheusServer(const PrometheusServer&) = delete;
    PrometheusServer& operator=(const PrometheusServer&) = delete;

    /**
     * @brief Start the HTTP server in a background thread.
     */
    void start();

    /**
     * @brief Stop the HTTP server.
     */
    void stop();

    bool running() const { return running_.load(std::memory_order_relaxed); }

    /**
     * @brief Register a stats collector callback.
     * The callback returns metrics in Prometheus text format.
     */
    void set_collector(StatsCollector collector) { collector_ = std::move(collector); }

    uint16_t port() const { return port_; }

private:
    void thread_func();
    int create_socket();
    void handle_client(int client_fd);
    std::string build_http_response(const std::string& body);

    uint16_t port_;
    std::atomic<bool> running_{false};
    std::thread thread_;
    StatsCollector collector_;
};

} // namespace nids