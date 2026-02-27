#include "capture_thread.h"
#include "../core/logger.h"
#include <pthread.h>
#include <sched.h>

namespace nids {

static void pin_thread(int cpu) {
    if (cpu < 0) return;
#ifdef __linux__
    cpu_set_t cs;
    CPU_ZERO(&cs);
    CPU_SET(cpu, &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);
#endif
}

void CaptureThread::start() {
    if (running_.load()) return;
    running_.store(true, std::memory_order_release);
    thread_ = std::thread(&CaptureThread::thread_func, this);
}

void CaptureThread::stop() {
    running_.store(false, std::memory_order_release);
    if (thread_.joinable()) thread_.join();
}

void CaptureThread::thread_func() {
    pin_thread(cpu_affinity_);
    LOG_INFO("capture", "thread started on iface='%s' cpu=%d",
             nic_.iface().c_str(), cpu_affinity_);

    uint64_t log_interval = 10000;  // print stats every N captured packets

    while (running_.load(std::memory_order_acquire)) {
        // 1. Allocate a slot
        PacketSlot* slot = pool_.allocate();
        if (!slot) {
            uint64_t n = stats_.dropped_pool.fetch_add(1, std::memory_order_relaxed);
            if (n % 1000 == 0)
                LOG_WARN("capture", "pool exhausted — dropped_pool=%lu", n + 1);
            struct timespec ts{0, 1000};  // 1 µs
            nanosleep(&ts, nullptr);
            continue;
        }

        // 2. Receive from NIC (10 ms timeout)
        if (!nic_.receive(slot, 10)) {
            pool_.free(slot);
            stats_.nic_errors.fetch_add(1, std::memory_order_relaxed);
            continue;
        }

        // 3. Push to processing queue
        if (!queue_.push(slot)) {
            pool_.free(slot);
            uint64_t n = stats_.dropped_queue.fetch_add(1, std::memory_order_relaxed);
            if (n % 1000 == 0)
                LOG_WARN("capture", "queue full — dropped_queue=%lu", n + 1);
        } else {
            uint64_t cap = stats_.captured.fetch_add(1, std::memory_order_relaxed) + 1;
            LOG_TRACE("capture", "pkt #%lu captured len=%u", cap, slot->length);
            if (cap % log_interval == 0)
                LOG_INFO("capture", "stats: captured=%lu dropped_pool=%lu dropped_queue=%lu",
                         cap,
                         stats_.dropped_pool.load(std::memory_order_relaxed),
                         stats_.dropped_queue.load(std::memory_order_relaxed));
        }
    }
    LOG_INFO("capture", "thread stopped — total captured=%lu dropped_pool=%lu dropped_queue=%lu",
             stats_.captured.load(),
             stats_.dropped_pool.load(),
             stats_.dropped_queue.load());
}

} // namespace nids
