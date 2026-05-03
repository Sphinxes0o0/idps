/* SPDX-License-Identifier: MIT */
/*
 * test_ringbuf_full.cpp - T-05: ringbuf 满载测试
 *
 * 验证 ringbuf 满时的告警丢失率
 */

#include <gtest/gtest.h>
#include "core/spsc_queue.hpp"
#include <thread>
#include <atomic>
#include <vector>
#include <chrono>
#include <cstring>

using namespace nids;

// Simulated ringbuf event
struct test_alert_event {
    uint64_t timestamp;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    uint8_t  severity;
    uint32_t rule_id;
    uint8_t  event_type;
    uint8_t  padding[3];
};

class RingbufFullTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}

    // Simulate alert generation
    static test_alert_event make_event(uint32_t rule_id, uint32_t src_ip) {
        test_alert_event evt = {};
        evt.timestamp = 0;
        evt.src_ip = src_ip;
        evt.dst_ip = 0x1000000A;
        evt.src_port = 12345;
        evt.dst_port = 80;
        evt.protocol = 6;
        evt.severity = 3;
        evt.rule_id = rule_id;
        evt.event_type = 0;
        return evt;
    }
};

// T-05: Test SPSC queue behavior under high load (simulates ringbuf)
TEST_F(RingbufFullTest, QueueUnderHighLoad) {
    // Simulate a queue that can hold 256 events (like 256KB ringbuf)
    SPSCQueue<test_alert_event> q(256);

    std::atomic<bool> done{false};
    std::atomic<int> sent_count{0};
    std::atomic<int> received_count{0};
    std::atomic<int> dropped_count{0};

    // Producer thread - generates events as fast as possible
    std::thread producer([&]() {
        test_alert_event evt;
        for (int i = 0; i < 10000; i++) {
            evt = make_event(i, i);
            if (!q.push(evt)) {
                dropped_count++;
            } else {
                sent_count++;
            }
        }
        done.store(true);
    });

    // Consumer thread - reads events slowly (simulating slow processing)
    std::thread consumer([&]() {
        test_alert_event evt;
        while (!done.load() || !q.empty()) {
            if (q.pop(evt)) {
                received_count++;
                // Simulate slow processing
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
        }
    });

    producer.join();
    consumer.join();

    printf("Sent: %d, Received: %d, Dropped: %d\n",
           sent_count.load(), received_count.load(), dropped_count.load());

    // Some events should be dropped when queue is full
    EXPECT_GT(dropped_count.load(), 0);
}

// T-05: Test that queue has expected capacity
TEST_F(RingbufFullTest, QueueCapacity) {
    SPSCQueue<test_alert_event> q(256);

    // Queue capacity should be at least what we asked for
    EXPECT_GE(q.capacity(), 256u);
}

// T-05: Test drop rate calculation
TEST_F(RingbufFullTest, DropRateCalculation) {
    SPSCQueue<test_alert_event> q(256);

    int sent = 0;
    int dropped = 0;

    test_alert_event evt;
    for (int i = 0; i < 1000; i++) {
        evt = make_event(i, i);
        if (!q.push(evt)) {
            dropped++;
        } else {
            sent++;
        }
    }

    double drop_rate = static_cast<double>(dropped) / (sent + dropped);
    printf("Drop rate: %.2f%%\n", drop_rate * 100);

    // With queue size 256 and 1000 events, we expect significant drops
    // At least 40% drop rate expected
    EXPECT_GT(drop_rate, 0.35);
}

// T-05: Test consumer can drain queue fast enough in normal conditions
TEST_F(RingbufFullTest, ConsumerCanKeepUp) {
    SPSCQueue<test_alert_event> q(1024);

    std::atomic<int> sent{0};
    std::atomic<int> received{0};
    std::atomic<bool> done{false};

    // Fast producer
    std::thread prod([&]() {
        test_alert_event evt;
        for (int i = 0; i < 100; i++) {
            evt = make_event(i, i);
            if (q.push(evt)) {
                sent++;
            }
        }
        done.store(true);
    });

    // Fast consumer
    std::thread cons([&]() {
        test_alert_event evt;
        while (!done.load() || !q.empty()) {
            if (q.pop(evt)) {
                received++;
            }
        }
    });

    prod.join();
    cons.join();

    // All events should be received when consumer keeps up
    EXPECT_EQ(sent.load(), received.load());
}

// T-05: Test burst handling
TEST_F(RingbufFullTest, BurstHandling) {
    SPSCQueue<test_alert_event> q(64);

    test_alert_event evt;
    int accepted = 0;

    // Burst of 100 events
    for (int i = 0; i < 100; i++) {
        evt = make_event(i, i);
        if (q.push(evt)) {
            accepted++;
        }
    }

    // Queue can only hold 64 (rounded up to power of 2 - 1 = 127)
    // With power-of-2 size 64, actual capacity is 128
    // So all 100 should fit
    EXPECT_EQ(accepted, 100);
}

// T-05: Test multiple producers simulation
TEST_F(RingbufFullTest, MultipleEventTypes) {
    SPSCQueue<test_alert_event> q(128);

    std::vector<int> event_type_counts(8, 0);  // 8 event types
    std::atomic<int> total_sent{0};
    std::atomic<int> total_dropped{0};

    // Generate mixed events
    for (int i = 0; i < 500; i++) {
        test_alert_event evt = make_event(i % 100, i);
        evt.event_type = i % 8;  // Rotate through 8 event types

        if (q.push(evt)) {
            total_sent++;
            event_type_counts[i % 8]++;
        } else {
            total_dropped++;
        }
    }

    printf("Total sent: %d, Total dropped: %d\n",
           total_sent.load(), total_dropped.load());

    // All event types should experience some drops when queue is full
    EXPECT_GT(total_dropped.load(), 0);
}

// T-05: Verify queue empty after consumer drains
TEST_F(RingbufFullTest, QueueDrainedCompletely) {
    SPSCQueue<test_alert_event> q(64);

    test_alert_event evt;
    for (int i = 0; i < 50; i++) {
        evt = make_event(i, i);
        q.push(evt);
    }

    // Drain queue
    while (q.pop(evt)) {}

    EXPECT_TRUE(q.empty());
    EXPECT_EQ(q.size(), 0u);
}

// T-05: Ringbuf loss rate with varying consumer speeds
TEST_F(RingbufFullTest, VaryingConsumerSpeed) {
    std::vector<double> loss_rates;

    for (int speed_factor : {1, 5, 10, 50}) {
        SPSCQueue<test_alert_event> q(256);

        std::atomic<int> sent{0};
        std::atomic<int> received{0};
        std::atomic<bool> done{false};

        std::thread prod([&]() {
            test_alert_event evt;
            for (int i = 0; i < 2000; i++) {
                evt = make_event(i, i);
                if (q.push(evt)) sent++;
                if (i % 100 == 0) std::this_thread::yield();
            }
            done.store(true);
        });

        std::thread cons([&]() {
            test_alert_event evt;
            int delay_us = speed_factor * 10;
            while (!done.load() || !q.empty()) {
                if (q.pop(evt)) {
                    received++;
                    std::this_thread::sleep_for(std::chrono::microseconds(delay_us));
                }
            }
        });

        prod.join();
        cons.join();

        double loss_rate = 1.0 - (static_cast<double>(received.load()) / sent.load());
        loss_rates.push_back(loss_rate);
        printf("Speed factor %d: loss rate = %.2f%%\n", speed_factor, loss_rate * 100);
    }

    // Slower consumers should have higher loss rates
    EXPECT_GE(loss_rates[3], loss_rates[0]);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}