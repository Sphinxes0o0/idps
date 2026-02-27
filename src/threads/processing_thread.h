#pragma once
#include "../core/pool.hpp"
#include "../core/spsc_queue.hpp"
#include "../core/pipeline.h"
#include <thread>
#include <atomic>

namespace nids {

/**
 * @brief ProcessingThread — consumer side of the packet processing pipeline.
 *
 * Responsibilities:
 *   1. Batch-pop PacketSlot* from the SPSCQueue.
 *   2. Drive the Pipeline for each slot.
 *   3. Return the slot to the PacketPool after processing.
 *
 * Drain-on-stop: when stop() is called the thread completes all queued
 * packets before exiting, preventing slot leaks.
 */
class ProcessingThread {
public:
    static constexpr size_t BATCH_SIZE = 32;  ///< Max packets per batch

    struct Stats {
        std::atomic<uint64_t> processed{0};
        std::atomic<uint64_t> idle_spins{0};
    };

    ProcessingThread(PacketPool&             pool,
                     SPSCQueue<PacketSlot*>& queue,
                     Pipeline&               pipeline,
                     int                     cpu_affinity = -1)
        : pool_(pool), queue_(queue), pipeline_(pipeline),
          cpu_affinity_(cpu_affinity) {}

    ~ProcessingThread() { stop(); }

    ProcessingThread(const ProcessingThread&)            = delete;
    ProcessingThread& operator=(const ProcessingThread&) = delete;

    void start();
    void stop();
    bool running() const { return running_.load(std::memory_order_relaxed); }

    const Stats& stats() const { return stats_; }

private:
    void thread_func();

    PacketPool&             pool_;
    SPSCQueue<PacketSlot*>& queue_;
    Pipeline&               pipeline_;
    int                     cpu_affinity_;

    std::atomic<bool> running_{false};
    std::atomic<bool> stop_requested_{false};
    std::thread       thread_;
    Stats             stats_;
};

} // namespace nids
