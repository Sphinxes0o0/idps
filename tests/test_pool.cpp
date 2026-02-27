#include <gtest/gtest.h>
#include "core/pool.hpp"
#include <thread>
#include <vector>
#include <set>

using namespace nids;

// ---- Basic allocation / free ------------------------------------------------

TEST(PacketPool, AllocAndFree) {
    PacketPool pool(8, 512);
    EXPECT_EQ(pool.total(), 8u);

    PacketSlot* s = pool.allocate();
    ASSERT_NE(s, nullptr);
    EXPECT_NE(s->data, nullptr);
    EXPECT_EQ(s->capacity, 512u);
    EXPECT_EQ(s->pool_ref, &pool);

    pool.free(s);
    EXPECT_GE(pool.available(), 7);  // at least 7 back
}

TEST(PacketPool, ExhaustPool) {
    PacketPool pool(4, 256);
    std::vector<PacketSlot*> held;

    for (int i = 0; i < 4; ++i) {
        auto* s = pool.allocate();
        ASSERT_NE(s, nullptr);
        held.push_back(s);
    }

    // Pool exhausted
    EXPECT_EQ(pool.allocate(), nullptr);

    // Return one
    pool.free(held.back());
    held.pop_back();

    auto* s2 = pool.allocate();
    EXPECT_NE(s2, nullptr);
    held.push_back(s2);

    for (auto* s : held) pool.free(s);
}

TEST(PacketPool, AllSlotsUniqueData) {
    PacketPool pool(16, 1024);
    std::set<uint8_t*> ptrs;
    std::vector<PacketSlot*> held;

    for (int i = 0; i < 16; ++i) {
        auto* s = pool.allocate();
        ASSERT_NE(s, nullptr);
        EXPECT_EQ(ptrs.count(s->data), 0u) << "Duplicate data pointer!";
        ptrs.insert(s->data);
        held.push_back(s);
    }
    for (auto* s : held) pool.free(s);
}

TEST(PacketPool, ResetOnAllocate) {
    PacketPool pool(2, 256);

    auto* s = pool.allocate();
    ASSERT_NE(s, nullptr);
    s->length    = 100;
    s->timestamp = 9999;
    pool.free(s);

    auto* s2 = pool.allocate();
    ASSERT_NE(s2, nullptr);
    EXPECT_EQ(s2->length, 0u);
    EXPECT_EQ(s2->timestamp, 0u);
    pool.free(s2);
}

// ---- Concurrent alloc / free ------------------------------------------------

TEST(PacketPool, ConcurrentAllocFree) {
    constexpr int SLOTS = 128;
    constexpr int ITERS = 10000;
    PacketPool pool(SLOTS, 256);

    std::atomic<int> errors{0};

    // Producer allocates, consumer frees
    std::vector<PacketSlot*> ring(SLOTS * 2, nullptr);
    std::atomic<size_t> prod_idx{0}, cons_idx{0};

    auto producer = [&]() {
        for (int i = 0; i < ITERS; ++i) {
            PacketSlot* s = nullptr;
            while (!(s = pool.allocate()))
                std::this_thread::yield();
            size_t pos = prod_idx.fetch_add(1) % ring.size();
            ring[pos] = s;
        }
    };

    auto consumer = [&]() {
        for (int i = 0; i < ITERS; ++i) {
            while (cons_idx.load() >= prod_idx.load())
                std::this_thread::yield();
            size_t pos = cons_idx.fetch_add(1) % ring.size();
            PacketSlot* s = ring[pos];
            if (!s || s->pool_ref != &pool) errors++;
            else pool.free(s);
        }
    };

    std::thread t1(producer), t2(consumer);
    t1.join(); t2.join();
    EXPECT_EQ(errors.load(), 0);
}
