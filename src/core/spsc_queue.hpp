#pragma once
#include <atomic>
#include <memory>
#include <cassert>
#include <stdexcept>

namespace nids {

/**
 * @brief Lock-free, bounded Single-Producer Single-Consumer ring queue.
 *
 * Critical design points:
 *   - Producer and consumer run on different CPU cores.
 *   - head_ and tail_ are cache-line-separated to avoid false sharing.
 *   - Uses acquire/release memory ordering — no seq_cst barrier overhead.
 *   - Capacity is always rounded up to the next power of two.
 *
 * @tparam T  Must be trivially copyable (e.g., PacketSlot*).
 */
template <typename T>
class SPSCQueue {
public:
    static_assert(std::is_trivially_copyable<T>::value,
                  "SPSCQueue<T>: T must be trivially copyable");

    explicit SPSCQueue(size_t capacity)
        : cap_(next_pow2(capacity)), mask_(cap_ - 1)
    {
        if (capacity == 0)
            throw std::invalid_argument("SPSCQueue: capacity must be > 0");
        buf_ = std::make_unique<T[]>(cap_);
    }

    /**
     * @brief Push one item (producer side).
     * @return false if queue is full — caller must handle drop.
     */
    bool push(T item) noexcept {
        size_t t = tail_.load(std::memory_order_relaxed);
        size_t next_t = (t + 1) & mask_;
        // Check if full: next tail would meet head
        if (next_t == head_.load(std::memory_order_acquire))
            return false;  // full
        buf_[t] = item;
        tail_.store(next_t, std::memory_order_release);
        return true;
    }

    /**
     * @brief Pop one item (consumer side).
     * @return false if queue is empty.
     */
    bool pop(T& out) noexcept {
        size_t h = head_.load(std::memory_order_relaxed);
        if (h == tail_.load(std::memory_order_acquire))
            return false;  // empty
        out = buf_[h];
        head_.store((h + 1) & mask_, std::memory_order_release);
        return true;
    }

    /**
     * @brief Bulk pop up to `max_items`.
     * @return Number of items actually popped.
     */
    size_t pop_bulk(T* out, size_t max_items) noexcept {
        size_t h = head_.load(std::memory_order_relaxed);
        size_t t = tail_.load(std::memory_order_acquire);
        size_t avail = (t - h + cap_) & mask_;
        if (avail == 0) return 0;

        size_t n = (avail < max_items) ? avail : max_items;
        for (size_t i = 0; i < n; ++i)
            out[i] = buf_[(h + i) & mask_];
        head_.store((h + n) & mask_, std::memory_order_release);
        return n;
    }

    bool   empty()    const noexcept {
        return head_.load(std::memory_order_acquire)
            == tail_.load(std::memory_order_acquire);
    }
    size_t capacity() const noexcept { return cap_ - 1; }

    size_t size() const noexcept {
        size_t t = tail_.load(std::memory_order_acquire);
        size_t h = head_.load(std::memory_order_acquire);
        return (t - h + cap_) & mask_;
    }

private:
    static size_t next_pow2(size_t n) noexcept {
        size_t p = 1;
        while (p <= n) p <<= 1;  // strictly bigger than n so cap-1 >= n
        return p;
    }

    size_t cap_;
    size_t mask_;
    std::unique_ptr<T[]> buf_;

    alignas(64) std::atomic<size_t> head_{0};
    alignas(64) std::atomic<size_t> tail_{0};
};

} // namespace nids
