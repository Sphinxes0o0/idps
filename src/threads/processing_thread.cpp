#include "processing_thread.h"
#include "../core/logger.h"
#include <pthread.h>
#include <sched.h>
#ifdef __x86_64__
#include <immintrin.h>  // _mm_pause (x86) — graceful busy-wait
#endif

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

void ProcessingThread::start() {
    if (running_.load()) return;
    running_.store(true, std::memory_order_release);
    stop_requested_.store(false, std::memory_order_release);
    thread_ = std::thread(&ProcessingThread::thread_func, this);
}

void ProcessingThread::stop() {
    stop_requested_.store(true, std::memory_order_release);
    running_.store(false, std::memory_order_release);
    if (thread_.joinable()) thread_.join();
    pipeline_.shutdown();
}

void ProcessingThread::thread_func() {
    pin_thread(cpu_affinity_);
    pipeline_.init();
    LOG_INFO("process", "thread started cpu=%d", cpu_affinity_);

    PacketSlot* batch[BATCH_SIZE];
    uint64_t log_interval = 10000;

    while (running_.load(std::memory_order_acquire)) {
        size_t n = queue_.pop_bulk(batch, BATCH_SIZE);

        if (n == 0) {
            stats_.idle_spins.fetch_add(1, std::memory_order_relaxed);
#if defined(__x86_64__) || defined(__i386__)
            _mm_pause();
#else
            struct timespec ts{0, 100};
            nanosleep(&ts, nullptr);
#endif
            continue;
        }

        LOG_TRACE("process", "dequeued batch of %zu packets", n);
        for (size_t i = 0; i < n; ++i) {
            pipeline_.execute(batch[i]);
            pool_.free(batch[i]);
            uint64_t total = stats_.processed.fetch_add(1, std::memory_order_relaxed) + 1;
            if (total % log_interval == 0)
                LOG_INFO("process", "stats: processed=%lu idle_spins=%lu",
                         total, stats_.idle_spins.load(std::memory_order_relaxed));
        }
    }

    // Drain remaining items before exit
    size_t n;
    while ((n = queue_.pop_bulk(batch, BATCH_SIZE)) > 0) {
        for (size_t i = 0; i < n; ++i) {
            pipeline_.execute(batch[i]);
            pool_.free(batch[i]);
            stats_.processed.fetch_add(1, std::memory_order_relaxed);
        }
    }
    LOG_INFO("process", "thread stopped — total processed=%lu",
             stats_.processed.load());
}

} // namespace nids
