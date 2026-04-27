#include "app/nids_app.h"
#include "core/logger.h"
#include <iostream>
#include <csignal>
#include <cstring>
#include <string>
#include <cstdlib>

static nids::NidsApp* g_app = nullptr;

static void on_signal(int sig) {
    std::cerr << "\n[NIDS] Received signal " << sig << " — shutting down...\n";
    if (g_app) g_app->stop();
    std::exit(0);
}

static void on_sigusr1(int sig) {
    (void)sig;
    std::cerr << "\n[NIDS] Received SIGUSR1 — reloading rules...\n";
    if (g_app) g_app->reload_rules();
}

static void print_usage(const char* prog) {
    std::cerr << "Usage: " << prog
              << " [--config <file>] | <iface> [rules_file] [event_log] [log_level]]\n"
              << "  --config     - Path to JSON configuration file\n"
              << "  iface       - Network interface for XDP/eBPF (e.g., eth0)\n"
              << "  rules_file  - Path to rules file [default: none]\n"
              << "  event_log   - Path to event log file, '-' for stdout [default: -]\n"
              << "  log_level   - trace/debug/info/warn/error/off [default: info]\n\n"
              << "Config file format (JSON):\n"
              << "  {\"interface\": \"eth0\", \"rules_file\": \"/etc/nids/rules.txt\",\n"
              << "   \"event_log\": \"/var/log/nids/events.json\", \"use_syslog\": true,\n"
              << "   \"metrics_port\": 8080}\n\n"
              << "Example: " << prog << " eth0 rules.txt /var/log/nids.json debug\n"
              << "Example: " << prog << " --config /etc/nids/nids.conf\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    nids::AppConfig cfg;

    // Check for --config option
    if (std::string(argv[1]) == "--config" && argc >= 3) {
        try {
            cfg = nids::load_config(argv[2]);
        } catch (const std::exception& e) {
            std::cerr << "Error loading config: " << e.what() << "\n";
            return 1;
        }
    } else {
        // Legacy positional arguments mode
        nids::PipelineConfig pcfg;
        pcfg.iface = argv[1];
        if (argc >= 3) pcfg.rules_file = argv[2];
        cfg.pipelines.push_back(std::move(pcfg));
        if (argc >= 4) cfg.event_log = argv[3];
        if (argc >= 5) nids::log_set_level(argv[4]);
    }

    std::signal(SIGINT,  on_signal);
    std::signal(SIGTERM, on_signal);
    std::signal(SIGUSR1, on_sigusr1);

    nids::NidsApp app(std::move(cfg));
    g_app = &app;

    LOG_INFO("main", "Starting NIDS on interface '%s' (eBPF/XDP)", argv[1]);

    if (!app.start()) {
        LOG_ERR("main", "Startup failed.");
        return 1;
    }

    LOG_INFO("main", "Running — press Ctrl+C to stop.");
    app.wait();

    return 0;
}
