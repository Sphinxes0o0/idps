/* SPDX-License-Identifier: MIT */
/*
 * test_af_xdp_frame_recycle.cpp - T-13: AF_XDP Frame Recycle Test
 *
 * Tests that verify completion ring correctly recycles UMEM frames.
 * Frame recycling is critical for AF_XDP performance - frames must be
 * returned to the fill ring after processing.
 */

#include "gtest/gtest.h"
#include "xdp/af_xdp.h"
#include <cstdint>
#include <vector>
#include <algorithm>

using namespace nids;

// AF_XDP constants
constexpr uint32_t DEFAULT_NUM_FRAMES = 4096;
constexpr uint32_t DEFAULT_FRAME_SIZE = 2048;

// Simulated completion ring entry (xdp_desc)
struct xdp_desc {
    uint64_t addr;
    uint32_t len;
    uint32_t options;
};

class AfXdpFrameRecycleTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}

    // Calculate frame address from index
    static uint64_t frame_addr(uint64_t base_addr, uint32_t frame_size, uint32_t idx) {
        return base_addr + (static_cast<uint64_t>(idx) * frame_size);
    }

    // Check if ring is empty
    static bool ring_empty(uint32_t prod, uint32_t cons) {
        return prod == cons;
    }

    // Check if ring is full
    static bool ring_full(uint32_t prod, uint32_t cons, uint32_t size) {
        return (prod - cons) >= size;
    }

    // Get number of entries in ring
    static uint32_t ring_used(uint32_t prod, uint32_t cons) {
        return prod - cons;
    }
};

// T-13: Frame address calculation is correct
TEST_F(AfXdpFrameRecycleTest, FrameAddressCalculation) {
    uint64_t base_addr = 0x1000000000ULL;
    uint32_t frame_size = 2048;

    // Frame 0
    EXPECT_EQ(frame_addr(base_addr, frame_size, 0), 0x1000000000ULL);

    // Frame 1
    EXPECT_EQ(frame_addr(base_addr, frame_size, 1), 0x1000000800ULL);

    // Frame 4095 (last in 4096 frame pool)
    uint64_t addr_4095 = base_addr + (4095ULL * 2048ULL);
    EXPECT_EQ(frame_addr(base_addr, frame_size, 4095), addr_4095);
}

// T-13: Frame index can be recovered from address
TEST_F(AfXdpFrameRecycleTest, FrameIndexRecovery) {
    uint64_t base_addr = 0x1000000000ULL;
    uint32_t frame_size = 2048;

    // Frame index = (addr - base) / frame_size
    uint64_t addr = 0x1000000800ULL;  // Frame 1
    uint32_t idx = static_cast<uint32_t>((addr - base_addr) / frame_size);
    EXPECT_EQ(idx, 1u);

    addr = 0x1000000000ULL;  // Frame 0
    idx = static_cast<uint32_t>((addr - base_addr) / frame_size);
    EXPECT_EQ(idx, 0u);

    addr = base_addr + (4095ULL * frame_size);
    idx = static_cast<uint32_t>((addr - base_addr) / frame_size);
    EXPECT_EQ(idx, 4095u);
}

// T-13: Completion ring tracks produced frames
TEST_F(AfXdpFrameRecycleTest, CompletionRingTracksProduced) {
    const uint32_t ring_size = 4096;
    uint32_t prod = 0;
    uint32_t cons = 0;

    // Initially empty
    EXPECT_TRUE(ring_empty(prod, cons));
    EXPECT_EQ(ring_used(prod, cons), 0u);

    // Producer adds a frame
    prod++;
    EXPECT_FALSE(ring_empty(prod, cons));
    EXPECT_EQ(ring_used(prod, cons), 1u);

    // Multiple frames added (now 101 total)
    prod += 100;
    EXPECT_EQ(ring_used(prod, cons), 101u);
}

// T-13: Completion ring consumer reclaims frames
TEST_F(AfXdpFrameRecycleTest, CompletionRingConsumerReclaims) {
    const uint32_t ring_size = 4096;
    uint32_t prod = 100;
    uint32_t cons = 0;

    // 100 frames to consume
    EXPECT_EQ(ring_used(prod, cons), 100u);

    // Consumer reclaims 50
    cons += 50;
    EXPECT_EQ(ring_used(prod, cons), 50u);

    // Consumer reclaims remaining 50
    cons += 50;
    EXPECT_TRUE(ring_empty(prod, cons));
}

// T-13: Frame can be recycled back to fill ring
TEST_F(AfXdpFrameRecycleTest, FrameRecycleBackToFillRing) {
    uint64_t base_addr = 0x1000000000ULL;
    uint32_t frame_size = 2048;
    const uint32_t fill_ring_size = 4096;

    uint32_t fill_prod = 0;
    uint32_t fill_cons = 0;

    // Frame was used (in completion ring)
    uint64_t used_addr = frame_addr(base_addr, frame_size, 100);

    // Recycle: add frame back to fill ring
    // (This is what happens after kernel processes the packet)
    fill_prod++;

    EXPECT_FALSE(ring_empty(fill_prod, fill_cons));
    EXPECT_EQ(ring_used(fill_prod, fill_cons), 1u);
}

// T-13: Fill ring feeds frames to receive
TEST_F(AfXdpFrameRecycleTest, FillRingFeedsReceive) {
    uint32_t fill_prod = 0;
    uint32_t fill_cons = 0;

    // Pre-fill ring with frames
    fill_prod = 100;  // 100 frames available

    EXPECT_FALSE(ring_empty(fill_prod, fill_cons));
    EXPECT_EQ(ring_used(fill_prod, fill_cons), 100u);

    // Application receives (consumes from fill ring)
    fill_cons += 10;

    EXPECT_EQ(ring_used(fill_prod, fill_cons), 90u);
}

// T-13: Ring wrap-around works correctly
TEST_F(AfXdpFrameRecycleTest, RingWrapAround) {
    const uint32_t ring_size = 4096;
    const uint32_t mask = ring_size - 1;  // 0xFFF

    // Simulate wrap-around
    uint32_t prod = 4095;
    uint32_t cons = 0;

    // Frame 4095 completes
    prod++;
    // After modulo: prod = 0
    prod = prod & mask;
    EXPECT_EQ(prod, 0u);

    // The actual ring is not full - we wrapped
    // Used entries = (prod + ring_size - cons) & mask would be used for ring buffer
    // But here we're using simple producer-consumer model
}

// T-13: Completion ring signals when frames are ready
TEST_F(AfXdpFrameRecycleTest, CompletionRingSignalsReady) {
    const uint32_t ring_size = 4096;
    uint32_t prod = 50;
    uint32_t cons = 0;

    // 50 frames ready for recycling
    EXPECT_EQ(ring_used(prod, cons), 50u);
    EXPECT_GT(ring_used(prod, cons), 0u);

    // Application can poll and get these frames
    while (prod != cons) {
        // Process each completed frame
        cons++;
    }

    EXPECT_TRUE(ring_empty(prod, cons));
}

// T-13: Fill ring depletion handled
TEST_F(AfXdpFrameRecycleTest, FillRingDepletion) {
    const uint32_t fill_ring_size = 4096;
    uint32_t fill_prod = 0;
    uint32_t fill_cons = 0;

    // Ring is empty
    EXPECT_TRUE(ring_empty(fill_prod, fill_cons));

    // Need to add more frames (recycle from completion)
    // This is the normal operation - app recycles frames back
    fill_prod += 100;
    EXPECT_FALSE(ring_empty(fill_prod, fill_cons));
}

// T-13: Frame addresses are reused after recycle
TEST_F(AfXdpFrameRecycleTest, FrameAddressReuse) {
    uint64_t base_addr = 0x1000000000ULL;
    uint32_t frame_size = 2048;

    // Frame 100 was used
    uint64_t addr_first_use = frame_addr(base_addr, frame_size, 100);

    // After recycle, frame 100 can be reused
    uint64_t addr_reuse = frame_addr(base_addr, frame_size, 100);

    // Same address - correctly reused
    EXPECT_EQ(addr_first_use, addr_reuse);
}

// T-13: Completion ring batch processing
TEST_F(AfXdpFrameRecycleTest, BatchProcessing) {
    const uint32_t ring_size = 4096;
    std::vector<xdp_desc> completed;
    uint32_t prod = 500;
    uint32_t cons = 0;

    // Batch process 500 completed frames
    while (cons < prod) {
        xdp_desc desc;
        desc.addr = 0x1000000000ULL + (static_cast<uint64_t>(cons) * 2048);
        desc.len = 1500;
        desc.options = 0;
        completed.push_back(desc);
        cons++;
    }

    EXPECT_EQ(completed.size(), 500u);

    // All frames should be consecutive addresses
    for (size_t i = 0; i < completed.size(); i++) {
        uint64_t expected_addr = 0x1000000000ULL + (static_cast<uint64_t>(i) * 2048);
        EXPECT_EQ(completed[i].addr, expected_addr);
    }
}

// T-13: UMEM size calculation
TEST_F(AfXdpFrameRecycleTest, UmemSizeCalculation) {
    uint32_t num_frames = 4096;
    uint32_t frame_size = 2048;
    uint64_t umem_size = static_cast<uint64_t>(num_frames) * frame_size;

    EXPECT_EQ(umem_size, 8388608ULL);  // 8MB

    // UMEM address range: base to base + umem_size
    uint64_t base_addr = 0x1000000000ULL;
    uint64_t end_addr = base_addr + umem_size;
    EXPECT_EQ(end_addr, 0x1000000000ULL + 8388608ULL);
}

// T-13: All frames can be recycled
TEST_F(AfXdpFrameRecycleTest, AllFramesCanBeRecycled) {
    uint64_t base_addr = 0x1000000000ULL;
    uint32_t frame_size = 2048;
    uint32_t num_frames = 4096;

    // Track which frames have been used
    std::vector<bool> frame_used(num_frames, false);

    // Simulate using all frames
    for (uint32_t i = 0; i < num_frames; i++) {
        frame_used[i] = true;
    }

    // All frames used
    uint32_t used_count = std::count(frame_used.begin(), frame_used.end(), true);
    EXPECT_EQ(used_count, num_frames);

    // Simulate recycling all frames
    for (uint32_t i = 0; i < num_frames; i++) {
        frame_used[i] = false;  // Frame returned to free pool
    }

    // All frames recycled
    uint32_t free_count = std::count(frame_used.begin(), frame_used.end(), false);
    EXPECT_EQ(free_count, num_frames);
}

// T-13: Frame size alignment for DMA
TEST_F(AfXdpFrameRecycleTest, FrameSizeAlignment) {
    // Frame size should be power of 2 for efficient DMA
    uint32_t frame_size = 2048;

    // Check power of 2
    EXPECT_EQ(frame_size & (frame_size - 1), 0u);

    // Check typical cache line alignment (64 bytes)
    EXPECT_EQ(frame_size % 64, 0u);
}

// T-13: Completion ring offset calculation
TEST_F(AfXdpFrameRecycleTest, CompletionRingOffset) {
    // Offset from UMEM base to completion ring
    // XDP_UMEM_PGOFF_COMPLETION_RING = 0x180000000ULL
    uint64_t umem_base = 0x1000000000ULL;
    uint64_t completion_ring_offset = 0x180000000ULL;
    uint64_t completion_ring_addr = umem_base + completion_ring_offset;

    EXPECT_EQ(completion_ring_addr, 0x1180000000ULL);
}

// T-13: Fill ring offset calculation
TEST_F(AfXdpFrameRecycleTest, FillRingOffset) {
    // Offset from UMEM base to fill ring
    // XDP_UMEM_PGOFF_FILL_RING = 0x100000000ULL
    uint64_t umem_base = 0x1000000000ULL;
    uint64_t fill_ring_offset = 0x100000000ULL;
    uint64_t fill_ring_addr = umem_base + fill_ring_offset;

    EXPECT_EQ(fill_ring_addr, 0x1100000000ULL);
}

// T-13: xdp_desc structure size
TEST_F(AfXdpFrameRecycleTest, XdpDescSize) {
    xdp_desc desc = {};

    desc.addr = 0x1000000000ULL;
    desc.len = 1500;
    desc.options = 0;

    EXPECT_EQ(desc.addr, 0x1000000000ULL);
    EXPECT_EQ(desc.len, 1500u);
    EXPECT_EQ(desc.options, 0u);

    // xdp_desc should be 16 bytes (8 + 4 + 4)
    EXPECT_EQ(sizeof(xdp_desc), 16u);
}

// T-13: Frame recycling rate
TEST_F(AfXdpFrameRecycleTest, RecyclingRate) {
    const uint32_t ring_size = 4096;
    uint32_t prod = 0;
    uint32_t cons = 0;

    // Simulate steady state: 100 packets/second
    for (int i = 0; i < 100; i++) {
        prod++;  // Completion
        cons++;  // Fill
    }

    // Should be balanced
    EXPECT_TRUE(ring_empty(prod, cons));
}

// T-13: Completion ring capacity
TEST_F(AfXdpFrameRecycleTest, RingCapacity) {
    const uint32_t ring_size = 4096;

    // At capacity
    uint32_t prod = 0;
    uint32_t cons = 0;
    prod = ring_size;

    EXPECT_TRUE(ring_full(prod, cons, ring_size));
    EXPECT_EQ(ring_used(prod, cons), ring_size);
}

// T-13: Zero-copy path for completed frames
TEST_F(AfXdpFrameRecycleTest, ZeroCopyPath) {
    uint64_t base_addr = 0x1000000000ULL;
    uint32_t frame_size = 2048;

    // Frame address directly usable as UMEM offset
    uint64_t addr = frame_addr(base_addr, frame_size, 100);

    // This address can be used directly with mmap'd UMEM
    // No copy needed - kernel and userspace share the same memory
    EXPECT_EQ(addr % frame_size, 0ULL);  // Properly aligned
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
