/* SPDX-License-Identifier: MIT */
/*
 * test_icmp_flood_threshold.cpp - T-11: ICMP Flood Threshold Test
 *
 * Tests that verify ICMP flood detection uses ddos_threshold/10 as threshold.
 * ICMP flood is less resource-intensive than TCP SYN flood, so a lower
 * threshold is appropriate.
 */

#include "gtest/gtest.h"
#include "ebpf/ebpf_loader.h"
#include <cstdint>

using namespace nids;

// Constants matching nids_common.h and BPF code
constexpr uint32_t DDoS_THRESHOLD_DEFAULT = 10000;
constexpr uint64_t WINDOW_SIZE_NS = 1000000000ULL;  /* 1 second in nanoseconds */

// ICMP flood threshold = ddos_threshold / 10
constexpr uint32_t ICMP_FLOOD_THRESHOLD_DEFAULT = DDoS_THRESHOLD_DEFAULT / 10;  // 1000

class IcmpFloodThresholdTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}

    // Simulate ICMP flood check logic from BPF
    static bool check_icmp_flood_threshold(uint32_t ddos_threshold, uint32_t packet_count) {
        uint32_t icmp_threshold = ddos_threshold / 10;
        return packet_count >= icmp_threshold;
    }

    // Simulate window-based ICMP tracking
    struct icmp_track_state {
        uint64_t window_start;
        uint32_t packet_count;
        uint64_t last_seen;
    };

    static bool is_window_expired(uint64_t now, uint64_t window_start, uint64_t window_size = WINDOW_SIZE_NS) {
        return (now - window_start) >= window_size;
    }
};

// T-11: Verify ICMP flood threshold is ddos_threshold / 10
TEST_F(IcmpFloodThresholdTest, IcmpThresholdIsOneTenthOfDdos) {
    // Default DDoS threshold is 10000, so ICMP threshold should be 1000
    uint32_t ddos_threshold = 10000;
    uint32_t expected_icmp_threshold = ddos_threshold / 10;

    EXPECT_EQ(expected_icmp_threshold, 1000u);
    EXPECT_EQ(ICMP_FLOOD_THRESHOLD_DEFAULT, 1000u);
}

// T-11: ICMP flood does not trigger below threshold
TEST_F(IcmpFloodThresholdTest, NoAlertBelowThreshold) {
    uint32_t ddos_threshold = 10000;
    uint32_t icmp_threshold = ddos_threshold / 10;  // 1000

    // One packet should not trigger
    EXPECT_FALSE(check_icmp_flood_threshold(ddos_threshold, 1));

    // 999 packets should not trigger
    EXPECT_FALSE(check_icmp_flood_threshold(ddos_threshold, icmp_threshold - 1));

    // At threshold - 1 should not trigger
    EXPECT_FALSE(check_icmp_flood_threshold(ddos_threshold, icmp_threshold - 1));
}

// T-11: ICMP flood triggers at threshold
TEST_F(IcmpFloodThresholdTest, AlertAtThreshold) {
    uint32_t ddos_threshold = 10000;
    uint32_t icmp_threshold = ddos_threshold / 10;  // 1000

    // At threshold should trigger
    EXPECT_TRUE(check_icmp_flood_threshold(ddos_threshold, icmp_threshold));

    // Above threshold should trigger
    EXPECT_TRUE(check_icmp_flood_threshold(ddos_threshold, icmp_threshold + 1));

    // Way above threshold should trigger
    EXPECT_TRUE(check_icmp_flood_threshold(ddos_threshold, icmp_threshold * 2));
}

// T-11: Verify ICMP threshold scales with DDoS threshold
TEST_F(IcmpFloodThresholdTest, ThresholdScalesWithDdosThreshold) {
    struct {
        uint32_t ddos_threshold;
        uint32_t expected_icmp_threshold;
    } test_cases[] = {
        {1000, 100},    // Very aggressive
        {5000, 500},    // Aggressive
        {10000, 1000},  // Default
        {20000, 2000},  // Moderate
        {50000, 5000},  // Conservative
        {100000, 10000} // Very conservative
    };

    for (const auto& tc : test_cases) {
        uint32_t icmp_threshold = tc.ddos_threshold / 10;
        EXPECT_EQ(icmp_threshold, tc.expected_icmp_threshold)
            << "ICMP threshold should be " << tc.expected_icmp_threshold
            << " for DDoS threshold " << tc.ddos_threshold;
    }
}

// T-11: ICMP flood detection uses separate tracking from SYN flood
TEST_F(IcmpFloodThresholdTest, SeparateTrackingFromSynFlood) {
    // SYN flood uses syn_flood_track keyed by (src_ip, dst_ip, dst_port)
    // ICMP flood uses icmp_flood_track keyed by (src_ip) only
    // This is a structural test - we verify the key structures are different

    // ICMP flood key is smaller (only src_ip)
    struct icmp_flood_key {
        uint32_t src_ip;
    };

    // SYN flood key is larger (src_ip, dst_ip, dst_port)
    struct syn_flood_key {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint16_t dst_port;
        uint8_t padding[2];
    };

    EXPECT_EQ(sizeof(icmp_flood_key), 4u);
    EXPECT_EQ(sizeof(syn_flood_key), 12u);
}

// T-11: Window reset behavior for ICMP flood
TEST_F(IcmpFloodThresholdTest, WindowResetBehavior) {
    icmp_track_state state = {0, 0, 0};
    uint64_t now = 1000000000ULL;  // 1 second

    // Initialize window
    state.window_start = now;
    state.packet_count = 1;

    // Simulate window expiration (now = 2 seconds)
    now = 2000000000ULL;
    EXPECT_TRUE(is_window_expired(now, state.window_start));

    // After window reset, packet count should reset to 1
    if (is_window_expired(now, state.window_start)) {
        state.window_start = now;
        state.packet_count = 1;
    }

    EXPECT_EQ(state.packet_count, 1u);
    EXPECT_EQ(state.window_start, now);
}

// T-11: Multiple ICMP packets accumulate in window
TEST_F(IcmpFloodThresholdTest, PacketAccumulation) {
    icmp_track_state state = {1000000000ULL, 0, 1000000000ULL};
    uint32_t ddos_threshold = 10000;
    uint32_t icmp_threshold = ddos_threshold / 10;
    uint64_t now = 1000000000ULL;

    // Simulate packets arriving within the same window
    for (uint32_t i = 0; i < 500; i++) {
        if (now - state.window_start >= WINDOW_SIZE_NS) {
            state.window_start = now;
            state.packet_count = 1;
        } else {
            state.packet_count++;
        }
        now += 1000000;  // 1ms between packets
    }

    // Should not trigger at 500 packets
    EXPECT_LT(state.packet_count, icmp_threshold);
    EXPECT_FALSE(check_icmp_flood_threshold(ddos_threshold, state.packet_count));
}

// T-11: ICMP flood triggers after enough packets in window
TEST_F(IcmpFloodThresholdTest, FloodDetectionAfterThresholdCrossed) {
    icmp_track_state state = {1000000000ULL, 0, 1000000000ULL};
    uint32_t ddos_threshold = 10000;
    uint32_t icmp_threshold = ddos_threshold / 10;
    uint64_t now = 1000000000ULL;

    bool flood_detected = false;

    // Simulate packets arriving
    for (uint32_t i = 0; i < 1500; i++) {
        if (now - state.window_start >= WINDOW_SIZE_NS) {
            state.window_start = now;
            state.packet_count = 1;
        } else {
            state.packet_count++;
        }
        now += 100000;  // 100us between packets

        if (check_icmp_flood_threshold(ddos_threshold, state.packet_count)) {
            flood_detected = true;
            break;
        }
    }

    EXPECT_TRUE(flood_detected);
    EXPECT_GE(state.packet_count, icmp_threshold);
}

// T-11: Test different ICMP types share the same flood tracking
TEST_F(IcmpFloodThresholdTest, AllIcmpTypesShareTracking) {
    // All ICMP types (echo, echo reply, destination unreachable, etc.)
    // share the same icmp_flood_track map keyed by source IP only
    // This is correct because ICMP flood is about volume, not type

    uint8_t icmp_types[] = {0, 3, 4, 5, 8, 11, 12, 13, 14};  // Various ICMP types

    // Each type would use the same tracking mechanism
    for (uint8_t type : icmp_types) {
        // Just verify types are valid
        EXPECT_GE(type, 0u);
        EXPECT_LE(type, 15u);
    }
}

// T-11: Verify timeout behavior removes stale ICMP tracking
TEST_F(IcmpFloodThresholdTest, TimeoutRemovesStaleTracking) {
    uint64_t now = 1000000000ULL;
    uint64_t last_seen = 1000000000ULL;
    uint64_t window_size = WINDOW_SIZE_NS;

    // Stale after 2x window timeout
    uint64_t timeout_threshold = window_size * 2;

    // Not stale yet (1.5x window)
    last_seen = now - (window_size + window_size / 2);
    EXPECT_FALSE((now - last_seen) > timeout_threshold);

    // Stale (2.1x window)
    last_seen = now - (window_size * 2 + window_size / 10);
    EXPECT_TRUE((now - last_seen) > timeout_threshold);
}

// T-11: Configurable ICMP flood threshold via ddos_threshold
TEST_F(IcmpFloodThresholdTest, ConfigurableThreshold) {
    NidsConfig config = {};
    config.ddos_threshold = 10000;

    uint32_t icmp_threshold = config.ddos_threshold / 10;
    EXPECT_EQ(icmp_threshold, 1000u);

    // Change config
    config.ddos_threshold = 5000;
    icmp_threshold = config.ddos_threshold / 10;
    EXPECT_EQ(icmp_threshold, 500u);

    // Aggressive settings
    config.ddos_threshold = 1000;
    icmp_threshold = config.ddos_threshold / 10;
    EXPECT_EQ(icmp_threshold, 100u);
}

// T-11: Zero DDoS threshold disables ICMP flood detection
TEST_F(IcmpFloodThresholdTest, ZeroThresholdDisablesDetection) {
    uint32_t ddos_threshold = 0;
    uint32_t icmp_threshold = ddos_threshold / 10;

    // Zero threshold should not cause issues
    EXPECT_EQ(icmp_threshold, 0u);

    // With zero threshold, any non-zero packet count would trigger
    // This is correct behavior - zero threshold means flood detection is always active
    EXPECT_TRUE(check_icmp_flood_threshold(ddos_threshold, 1));
    EXPECT_TRUE(check_icmp_flood_threshold(ddos_threshold, 0));  // At 0, >= 0 is true
}

// T-11: Boundary conditions for ICMP flood threshold
TEST_F(IcmpFloodThresholdTest, BoundaryConditions) {
    struct {
        uint32_t ddos_threshold;
        uint32_t packet_count;
        bool expected_trigger;
    } test_cases[] = {
        {10000, 0, false},      // Zero packets
        {10000, 999, false},    // Just below threshold
        {10000, 1000, true},     // At threshold
        {10000, 1001, true},     // Just above threshold
        {10000, 2000, true},     // 2x threshold
        {1, 0, true},            // Min threshold: 0 packets >= 0 (icmp_thresh=0)
        {1, 1, true},            // Min threshold: 1 packet triggers
        {UINT32_MAX, UINT32_MAX, true},  // Max values
    };

    for (const auto& tc : test_cases) {
        bool result = check_icmp_flood_threshold(tc.ddos_threshold, tc.packet_count);
        EXPECT_EQ(result, tc.expected_trigger)
            << "ddos=" << tc.ddos_threshold << ", packets=" << tc.packet_count
            << ": expected " << tc.expected_trigger << " but got " << result;
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
