#pragma once
#include "packet.h"
#include <memory>
#include <atomic>
#include <cassert>
#include <stdexcept>
#include <cstdlib>

namespace nids {

/**
 * @brief Lock-free PacketPool using a Treiber stack as the free-list.
 *
 * Thread safety model:
 *   - Capture thread calls allocate() repeatedly.
 *   - Processing thread calls free() after finishing each packet.
 *   - Both operations are wait-free on average (CAS loop, no mutex).
 *
 * Memory layout:
 *   - One contiguous slab of (num_slots × slot_size) bytes, cache-line aligned.
 *   - PacketSlot[] descriptor array alongside the slab.
 *   - A parallel free_next_[] array for the Treiber stack links (keeps PacketSlot POD-clean).
 *
 * ABA mitigation:
 *   - Tagged pointer: upper 32 bits = monotonic tag, lower 32 bits = slot index.
 */
class PacketPool {
public:
    static constexpr size_t NO_SLOT = UINT32_MAX;

    PacketPool(size_t num_slots, size_t slot_size)
        : num_slots_(num_slots), slot_size_(slot_size)
    {
        if (num_slots == 0 || slot_size == 0)
            throw std::invalid_argument("PacketPool: args must be > 0");
        if (num_slots > UINT32_MAX - 1)
            throw std::invalid_argument("PacketPool: too many slots");

        // Allocate slab (64-byte alignment for NUMA/cache)
        size_t slab_bytes = num_slots * slot_size;
        slab_bytes = (slab_bytes + 63) & ~size_t(63);
        slab_ = static_cast<uint8_t*>(aligned_alloc(64, slab_bytes));
        if (!slab_) throw std::bad_alloc();

        slots_     = std::make_unique<PacketSlot[]>(num_slots);
        free_next_ = std::make_unique<uint32_t[]>(num_slots);

        // Initialise descriptors and build initial stack (0 -> 1 -> 2 -> ... -> NO_SLOT)
        for (size_t i = 0; i < num_slots; ++i) {
            slots_[i].data     = slab_ + i * slot_size;
            slots_[i].capacity = static_cast<uint32_t>(slot_size);
            slots_[i].pool_ref = this;
            free_next_[i]      = (i + 1 < num_slots)
                                   ? static_cast<uint32_t>(i + 1)
                                   : static_cast<uint32_t>(NO_SLOT);
        }
        // Head points at slot 0
        stack_head_.store(make_tagged(0, 0), std::memory_order_relaxed);
        available_.store(static_cast<int32_t>(num_slots), std::memory_order_relaxed);
    }

    ~PacketPool() { ::free(slab_); }

    PacketPool(const PacketPool&)            = delete;
    PacketPool& operator=(const PacketPool&) = delete;

    /**
     * @brief O(1) amortised, lock-free allocation.
     * @return Valid slot pointer or nullptr when pool is exhausted.
     */
    [[nodiscard]] PacketSlot* allocate() noexcept {
        uint64_t old_head = stack_head_.load(std::memory_order_acquire);
        while (true) {
            uint32_t idx = low32(old_head);
            if (idx == static_cast<uint32_t>(NO_SLOT)) return nullptr;

            uint32_t next_idx = free_next_[idx];
            uint64_t new_head = make_tagged(next_idx, high32(old_head) + 1);

            if (stack_head_.compare_exchange_weak(
                    old_head, new_head,
                    std::memory_order_acq_rel, std::memory_order_acquire)) {
                available_.fetch_sub(1, std::memory_order_relaxed);
                slots_[idx].reset();
                return &slots_[idx];
            }
            // old_head updated by CAS failure — retry
        }
    }

    /**
     * @brief Return slot to pool.  Must have been acquired from this pool.
     */
    void free(PacketSlot* slot) noexcept {
        assert(slot);
        assert(slot->pool_ref == this);
        size_t idx = static_cast<size_t>(slot - slots_.get());
        assert(idx < num_slots_);

        slot->reset();

        uint64_t old_head = stack_head_.load(std::memory_order_acquire);
        while (true) {
            free_next_[idx] = low32(old_head);
            uint64_t new_head = make_tagged(static_cast<uint32_t>(idx), high32(old_head) + 1);

            if (stack_head_.compare_exchange_weak(
                    old_head, new_head,
                    std::memory_order_acq_rel, std::memory_order_acquire)) {
                available_.fetch_add(1, std::memory_order_relaxed);
                return;
            }
        }
    }

    size_t  total()     const noexcept { return num_slots_; }
    size_t  slot_size() const noexcept { return slot_size_; }
    int32_t available() const noexcept {
        return available_.load(std::memory_order_relaxed);
    }

private:
    static uint64_t make_tagged(uint32_t idx, uint32_t tag) noexcept {
        return (static_cast<uint64_t>(tag) << 32) | idx;
    }
    static uint32_t low32(uint64_t v)  noexcept { return static_cast<uint32_t>(v); }
    static uint32_t high32(uint64_t v) noexcept { return static_cast<uint32_t>(v >> 32); }

    size_t   num_slots_;
    size_t   slot_size_;
    uint8_t* slab_ = nullptr;

    std::unique_ptr<PacketSlot[]> slots_;
    std::unique_ptr<uint32_t[]>   free_next_;  ///< Treiber-stack next links

    alignas(64) std::atomic<uint64_t> stack_head_{0};
    alignas(64) std::atomic<int32_t>  available_{0};
};

} // namespace nids
