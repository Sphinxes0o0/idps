#include "prometheus_server.h"
#include "../core/logger.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <errno.h>

namespace nids {

namespace {
    const char* HTTP_200 = "HTTP/1.1 200 OK\r\n";
    const char* CONTENT_TYPE = "Content-Type: text/plain; version=0.0.4\r\n";
    const char* CONNECTION_CLOSE = "Connection: close\r\n";
    const char* CRLF = "\r\n";
}

PrometheusServer::PrometheusServer(uint16_t port)
    : port_(port) {
}

PrometheusServer::~PrometheusServer() {
    stop();
}

int PrometheusServer::create_socket() {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        LOG_ERR("prom", "failed to create socket: %s", strerror(errno));
        return -1;
    }

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LOG_ERR("prom", "failed to bind to port %u: %s", port_, strerror(errno));
        close(fd);
        return -1;
    }

    if (listen(fd, 5) < 0) {
        LOG_ERR("prom", "failed to listen: %s", strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

std::string PrometheusServer::build_http_response(const std::string& body) {
    std::string response;
    response.reserve(256 + body.size());
    response = HTTP_200;
    response += CONTENT_TYPE;
    response += "Content-Length: ";
    response += std::to_string(body.size());
    response += CRLF;
    response += CONNECTION_CLOSE;
    response += CRLF;
    response += body;
    return response;
}

void PrometheusServer::handle_client(int client_fd) {
    char buffer[1024];
    ssize_t n = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (n <= 0) {
        close(client_fd);
        return;
    }
    buffer[n] = '\0';

    // Simple request parsing - look for GET /metrics
    std::string request(buffer, n);
    std::string response;

    if (request.find("GET /metrics") == 0) {
        if (collector_) {
            std::string metrics = collector_();
            response = build_http_response(metrics);
        } else {
            response = build_http_response("# No collector registered\n");
        }
    } else if (request.find("GET /") == 0) {
        response = build_http_response("IDPS Prometheus Exporter\n");
    } else {
        response = build_http_response("Not Found\n");
    }

    send(client_fd, response.c_str(), response.size(), 0);
    close(client_fd);
}

void PrometheusServer::thread_func() {
    int listen_fd = create_socket();
    if (listen_fd < 0) {
        LOG_ERR("prom", "failed to start server on port %u", port_);
        return;
    }

    LOG_INFO("prom", "Prometheus server listening on port %u", port_);

    while (running_.load(std::memory_order_acquire)) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            if (running_.load(std::memory_order_acquire)) {
                LOG_WARN("prom", "accept failed: %s", strerror(errno));
            }
            continue;
        }

        handle_client(client_fd);
    }

    close(listen_fd);
}

void PrometheusServer::start() {
    if (running_.load()) return;
    running_.store(true, std::memory_order_release);
    thread_ = std::thread(&PrometheusServer::thread_func, this);
}

void PrometheusServer::stop() {
    running_.store(false, std::memory_order_release);
    if (thread_.joinable()) {
        thread_.join();
    }
}

} // namespace nids