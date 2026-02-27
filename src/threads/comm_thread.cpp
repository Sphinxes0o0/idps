#include "comm_thread.h"
#include <iostream>
#include <fstream>
#include <memory>

namespace nids {

void CommThread::start() {
    if (running_.load()) return;
    running_.store(true, std::memory_order_release);
    thread_ = std::thread(&CommThread::thread_func, this);
}

void CommThread::stop() {
    running_.store(false, std::memory_order_release);
    if (event_queue_) event_queue_->signal_shutdown();
    if (thread_.joinable()) thread_.join();
}

void CommThread::thread_func() {
    // Open output stream
    std::ofstream fout;
    std::ostream* out = &std::cout;
    if (log_path_ != "-" && !log_path_.empty()) {
        fout.open(log_path_, std::ios::app);
        if (fout.is_open()) out = &fout;
    }

    while (running_.load(std::memory_order_acquire)) {
        auto maybe_ev = event_queue_->pop(200 /*ms*/);
        if (!maybe_ev) continue;

        *out << maybe_ev->to_json() << '\n';
        out->flush();
        ++events_written_;
    }

    // Drain remaining events
    std::vector<SecEvent> rem;
    event_queue_->drain(rem);
    for (const auto& ev : rem) {
        *out << ev.to_json() << '\n';
        ++events_written_;
    }
    out->flush();
}

} // namespace nids
