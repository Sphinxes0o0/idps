#pragma once
#include "sec_event.h"
#include <mutex>
#include <vector>
#include <deque>
#include <condition_variable>
#include <optional>
#include <chrono>

namespace nids {

/**
 * @brief Thread-safe bounded queue for SecEvent objects.
 *
 * Used to pass events from the Processing Thread to the Communication Thread.
 * MPSC (multiple processing threads may push; one comm thread pops).
 * Uses a mutex since events are "slow path" — not in the packet hot path.
 */
class EventQueue {
public:
    explicit EventQueue(size_t max_size = 4096) : max_size_(max_size) {}

    /** @brief Push an event.  Drops if queue is full (non-blocking). */
    bool push(SecEvent evt) {
        std::lock_guard<std::mutex> lk(mu_);
        if (q_.size() >= max_size_) {
            ++dropped_;
            return false;
        }
        q_.push_back(std::move(evt));
        cv_.notify_one();
        return true;
    }

    /** @brief Pop one event, blocking up to timeout_ms. Returns nullopt on timeout. */
    std::optional<SecEvent> pop(int timeout_ms = 100) {
        std::unique_lock<std::mutex> lk(mu_);
        cv_.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                     [this]{ return !q_.empty() || shutdown_; });
        if (q_.empty()) return std::nullopt;
        SecEvent ev = std::move(q_.front());
        q_.pop_front();
        return ev;
    }

    /** @brief Drain all pending events into `out_vec`. Non-blocking. */
    size_t drain(std::vector<SecEvent>& out_vec) {
        std::lock_guard<std::mutex> lk(mu_);
        size_t n = q_.size();
        for (auto& e : q_) out_vec.push_back(std::move(e));
        q_.clear();
        return n;
    }

    void signal_shutdown() {
        std::lock_guard<std::mutex> lk(mu_);
        shutdown_ = true;
        cv_.notify_all();
    }

    size_t size() const {
        std::lock_guard<std::mutex> lk(mu_);
        return q_.size();
    }

    uint64_t dropped_total() const { return dropped_; }

private:
    size_t   max_size_;
    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::deque<SecEvent> q_;
    bool     shutdown_ = false;
    uint64_t dropped_  = 0;
};

} // namespace nids
