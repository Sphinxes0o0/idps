#include <gtest/gtest.h>
#include "core/spsc_queue.hpp"
#include <thread>
#include <vector>

using namespace nids;

// ---- Basic push / pop -------------------------------------------------------

TEST(SPSCQueue, PushPop) {
    SPSCQueue<int> q(8);
    EXPECT_TRUE(q.empty());

    EXPECT_TRUE(q.push(42));
    EXPECT_FALSE(q.empty());
    EXPECT_EQ(q.size(), 1u);

    int v = 0;
    EXPECT_TRUE(q.pop(v));
    EXPECT_EQ(v, 42);
    EXPECT_TRUE(q.empty());
}

TEST(SPSCQueue, FIFOOrder) {
    SPSCQueue<int> q(16);
    for (int i = 0; i < 10; ++i) q.push(i);
    for (int i = 0; i < 10; ++i) {
        int v;
        ASSERT_TRUE(q.pop(v));
        EXPECT_EQ(v, i);
    }
}

TEST(SPSCQueue, FullReturnsFalse) {
    SPSCQueue<int> q(4);  // Capacity = next pow2 above 4 - 1 = 7

    // Fill up (capacity is 2^3 - 1 = 7 with pow2=8)
    int cap = static_cast<int>(q.capacity());
    for (int i = 0; i < cap; ++i)
        EXPECT_TRUE(q.push(i));

    // One more should fail
    EXPECT_FALSE(q.push(999));
}

TEST(SPSCQueue, PopEmptyReturnsFalse) {
    SPSCQueue<int> q(8);
    int v;
    EXPECT_FALSE(q.pop(v));
}

TEST(SPSCQueue, BulkPop) {
    SPSCQueue<int> q(64);
    for (int i = 0; i < 10; ++i) q.push(i * 2);

    int out[20];
    size_t n = q.pop_bulk(out, 20);
    EXPECT_EQ(n, 10u);
    for (size_t i = 0; i < n; ++i)
        EXPECT_EQ(out[i], static_cast<int>(i) * 2);
}

// ---- SPSC concurrent correctness --------------------------------------------

TEST(SPSCQueue, ConcurrentSPSC) {
    constexpr int ITEMS = 100000;
    SPSCQueue<int> q(1024);

    std::vector<int> received;
    received.reserve(ITEMS);
    std::atomic<bool> done{false};

    std::thread prod([&]() {
        for (int i = 0; i < ITEMS; ++i) {
            while (!q.push(i)) std::this_thread::yield();
        }
        done.store(true, std::memory_order_release);
    });

    std::thread cons([&]() {
        int v;
        while (received.size() < ITEMS) {
            if (q.pop(v))
                received.push_back(v);
            else
                std::this_thread::yield();
        }
    });

    prod.join();
    cons.join();

    ASSERT_EQ(received.size(), static_cast<size_t>(ITEMS));
    for (int i = 0; i < ITEMS; ++i)
        EXPECT_EQ(received[i], i) << "FIFO violation at index " << i;
}
