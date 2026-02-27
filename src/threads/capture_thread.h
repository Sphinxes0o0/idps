#pragma once
#include "../core/pool.hpp"
#include "../core/spsc_queue.hpp"
#include "../nic/nic_interface.h"
#include <thread>
#include <atomic>
#include <string>
#include <cstdint>
#include <functional>

namespace nids {

/**
 * @brief CaptureThread — producer side of the packet processing pipeline.
 *
 * Responsibilities:
 *   1. Allocate a PacketSlot from the PacketPool.
 *   2. Call INic::receive() to fill the slot.
 *   3. Push the slot pointer onto the SPSCQueue for the processing thread.
 *   4. If queue is full, drop the slot (return to pool).
 *
 * Thread affinity: should be set to the CPU core nearest the NIC PCIe slot.
 */
class CaptureThread {
public:
    struct Stats {
        std::atomic<uint64_t> captured{0};
        std::atomic<uint64_t> dropped_queue{0};  ///< Queue full drops
        std::atomic<uint64_t> dropped_pool{0};   ///< Pool exhausted drops
        std::atomic<uint64_t> nic_errors{0};
    };

    CaptureThread(PacketPool&                pool,
                  SPSCQueue<PacketSlot*>&    queue,
                  INic&                      nic,
                  int                        cpu_affinity = -1)
        : pool_(pool), queue_(queue), nic_(nic), cpu_affinity_(cpu_affinity) {}

    ~CaptureThread() { stop(); }

    CaptureThread(const CaptureThread&)            = delete;
    CaptureThread& operator=(const CaptureThread&) = delete;

    void start();
    void stop();
    bool running() const { return running_.load(std::memory_order_relaxed); }

    const Stats& stats() const { return stats_; }

private:
    void thread_func();

    PacketPool&             pool_;
    SPSCQueue<PacketSlot*>& queue_;
    INic&                   nic_;
    int                     cpu_affinity_;

    std::atomic<bool> running_{false};
    std::thread       thread_;
    Stats             stats_;
};

} // namespace nids
