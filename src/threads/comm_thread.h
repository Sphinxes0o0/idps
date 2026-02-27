#pragma once
#include "../ipc/event_queue.hpp"
#include <thread>
#include <atomic>
#include <string>
#include <memory>
#include <functional>

namespace nids {

/**
 * @brief CommThread — communication / slow-path thread.
 *
 * Responsibilities:
 *   - Drain the EventQueue and write SecEvents to disk / stdout.
 *   - Receive external IPC control commands (future extension).
 *   - Report periodic stats to operators.
 *
 * Design: pure "slow path" — never touches the PacketPool or SPSCQueue.
 */
class CommThread {
public:
    /**
     * @param event_queue  Shared queue fed by EventStage.
     * @param log_path     File path for event JSON log. "-" = stdout.
     */
    CommThread(std::shared_ptr<EventQueue> event_queue,
               std::string                 log_path = "-")
        : event_queue_(std::move(event_queue)),
          log_path_(std::move(log_path)) {}

    ~CommThread() { stop(); }

    CommThread(const CommThread&)            = delete;
    CommThread& operator=(const CommThread&) = delete;

    void start();
    void stop();
    bool running() const { return running_.load(std::memory_order_relaxed); }

    uint64_t events_written() const { return events_written_; }

private:
    void thread_func();

    std::shared_ptr<EventQueue> event_queue_;
    std::string                 log_path_;

    std::atomic<bool> running_{false};
    std::thread       thread_;
    uint64_t          events_written_ = 0;
};

} // namespace nids
