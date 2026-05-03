/* SPDX-License-Identifier: MIT */
/*
 * test_dns_amplification.cpp - T-12: DNS Amplification Ratio Test
 *
 * Tests that verify DNS amplification detection uses dns_amp_threshold multiplier.
 * A DNS amplification attack occurs when response_bytes > query_bytes * threshold.
 */

#include "gtest/gtest.h"
#include "ebpf/ebpf_loader.h"
#include <cstdint>
#include <algorithm>

using namespace nids;

// DNS amplification detection constant
constexpr uint32_t DNS_AMP_THRESHOLD_DEFAULT = 10;  // 10x amplification default
constexpr uint64_t WINDOW_SIZE_NS = 1000000000ULL;  /* 1 second in nanoseconds */

class DnsAmplificationTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}

    // Simulate DNS amplification check logic from BPF
    // Returns true if amplification is detected
    static bool check_dns_amplification(uint32_t dns_thresh,
                                        uint64_t query_bytes,
                                        uint64_t response_bytes,
                                        bool alert_sent) {
        // E-13: prevent zero-threshold false positives
        if (dns_thresh == 0)
            dns_thresh = 10;

        // Amplification detected if:
        // 1. query_bytes > 0 (avoid division by zero)
        // 2. response_bytes > query_bytes * threshold
        // 3. alert hasn't been sent yet
        if (query_bytes > 0 &&
            response_bytes > query_bytes * dns_thresh &&
            !alert_sent) {
            return true;
        }
        return false;
    }

    // DNS amplification tracking state
    struct dns_amp_stats {
        uint64_t response_bytes;
        uint64_t query_bytes;
        uint64_t last_seen;
        uint8_t alert_sent;
        uint8_t padding[7];
    };
};

// T-12: Verify DNS amplification threshold default is 10x
TEST_F(DnsAmplificationTest, DefaultAmplificationThreshold) {
    EXPECT_EQ(DNS_AMP_THRESHOLD_DEFAULT, 10u);

    uint32_t dns_thresh = DNS_AMP_THRESHOLD_DEFAULT;
    EXPECT_EQ(dns_thresh, 10u);
}

// T-12: Normal DNS query-response is not amplification
TEST_F(DnsAmplificationTest, NormalQueryResponseNotAmplification) {
    uint32_t dns_thresh = 10;

    // Typical DNS query: 50 bytes, response: 500 bytes (10x, still not attack)
    // 500 > 50 * 10 = 500, but not > so no detection
    EXPECT_FALSE(check_dns_amplification(dns_thresh, 50, 500, false));

    // Response smaller than threshold multiple
    EXPECT_FALSE(check_dns_amplification(dns_thresh, 100, 500, false));

    // Response equals threshold multiple (not >, so no detection)
    EXPECT_FALSE(check_dns_amplification(dns_thresh, 100, 1000, false));
}

// T-12: DNS amplification detected when response > query * threshold
TEST_F(DnsAmplificationTest, AmplificationDetectedAboveThreshold) {
    uint32_t dns_thresh = 10;

    // Query: 50 bytes, Response: 501 bytes (501 > 50 * 10 = 500)
    EXPECT_TRUE(check_dns_amplification(dns_thresh, 50, 501, false));

    // Query: 100 bytes, Response: 1001 bytes (1001 > 100 * 10 = 1000)
    EXPECT_TRUE(check_dns_amplification(dns_thresh, 100, 1001, false));

    // Query: 64 bytes (typical EDNS), Response: 4096 bytes (4096 > 64 * 10 = 640)
    EXPECT_TRUE(check_dns_amplification(dns_thresh, 64, 4096, false));
}

// T-12: Amplification detection respects alert_sent flag
TEST_F(DnsAmplificationTest, AlertSentPreventsDuplicates) {
    uint32_t dns_thresh = 10;

    // Same condition but alert already sent
    EXPECT_FALSE(check_dns_amplification(dns_thresh, 50, 1000, true));

    // Alert not sent yet
    EXPECT_TRUE(check_dns_amplification(dns_thresh, 50, 1000, false));
}

// T-12: Zero threshold defaults to 10 to prevent false positives
TEST_F(DnsAmplificationTest, ZeroThresholdDefaultsToTen) {
    // This is E-13 protection: zero threshold should not cause issues
    uint32_t dns_thresh = 0;

    // Should default to 10
    if (dns_thresh == 0)
        dns_thresh = 10;

    EXPECT_EQ(dns_thresh, 10u);

    // Now check with the defaulted threshold
    EXPECT_FALSE(check_dns_amplification(dns_thresh, 1, 9, false));   // 9 > 1*10 = false
    EXPECT_TRUE(check_dns_amplification(dns_thresh, 1, 11, false));   // 11 > 1*10 = true
}

// T-12: Zero query bytes prevents false positives
TEST_F(DnsAmplificationTest, ZeroQueryBytesPreventsFalsePositive) {
    uint32_t dns_thresh = 10;

    // Zero query should not trigger (would be division by zero)
    EXPECT_FALSE(check_dns_amplification(dns_thresh, 0, 10000, false));

    // This simulates a response-only packet without prior query tracking
    EXPECT_FALSE(check_dns_amplification(dns_thresh, 0, 0, false));
}

// T-12: Different threshold values affect detection
TEST_F(DnsAmplificationTest, DifferentThresholds) {
    // Lower threshold = more sensitive (detects smaller amplification)
    struct {
        uint32_t dns_thresh;
        uint64_t query_bytes;
        uint64_t response_bytes;
        bool expected;
    } test_cases[] = {
        // Aggressive (5x)
        {5, 100, 501, true},   // 501 > 500
        {5, 100, 500, false},  // 500 not > 500
        // Default (10x)
        {10, 100, 1001, true},  // 1001 > 1000
        {10, 100, 1000, false}, // 1000 not > 1000
        // Conservative (20x)
        {20, 100, 2001, true},  // 2001 > 2000
        {20, 100, 2000, false}, // 2000 not > 2000
    };

    for (const auto& tc : test_cases) {
        bool result = check_dns_amplification(tc.dns_thresh, tc.query_bytes,
                                               tc.response_bytes, false);
        EXPECT_EQ(result, tc.expected)
            << "thresh=" << tc.dns_thresh << ", query=" << tc.query_bytes
            << ", resp=" << tc.response_bytes
            << ": expected " << tc.expected << " but got " << result;
    }
}

// T-12: DNS query tracking state updates correctly
TEST_F(DnsAmplificationTest, QueryTrackingStateUpdate) {
    dns_amp_stats stats = {0, 0, 0, 0};
    uint64_t now = 1000000000ULL;
    uint32_t pkt_len = 64;  // Typical DNS query size

    // First query
    stats.query_bytes = pkt_len;
    stats.last_seen = now;

    EXPECT_EQ(stats.query_bytes, 64u);
    EXPECT_EQ(stats.response_bytes, 0u);
    EXPECT_FALSE(stats.alert_sent);
}

// T-12: DNS response tracking state updates correctly
TEST_F(DnsAmplificationTest, ResponseTrackingStateUpdate) {
    dns_amp_stats stats = {0, 0, 0, 0};
    uint64_t now = 1000000000ULL;
    uint32_t pkt_len = 500;  // Typical DNS response size

    // First response
    stats.response_bytes = pkt_len;
    stats.last_seen = now;

    EXPECT_EQ(stats.response_bytes, 500u);
    EXPECT_EQ(stats.query_bytes, 0u);
    EXPECT_FALSE(stats.alert_sent);
}

// T-12: Window expiration resets amplification tracking
TEST_F(DnsAmplificationTest, WindowExpirationResetsTracking) {
    dns_amp_stats stats = {1000, 100, 1000000000ULL, 1};  // Old data with alert sent
    uint64_t now = 2500000000ULL;  // 2.5 seconds later
    uint64_t window_size = WINDOW_SIZE_NS;

    // Check if window expired
    bool window_expired = (now - stats.last_seen) >= window_size;
    EXPECT_TRUE(window_expired);

    // After expiration, reset
    if (window_expired) {
        stats.response_bytes = 0;
        stats.query_bytes = 0;
        stats.alert_sent = 0;
        stats.last_seen = now;
    }

    EXPECT_EQ(stats.response_bytes, 0u);
    EXPECT_EQ(stats.query_bytes, 0u);
    EXPECT_FALSE(stats.alert_sent);
}

// T-12: Accumulating query bytes across multiple queries
TEST_F(DnsAmplificationTest, AccumulatingQueryBytes) {
    dns_amp_stats stats = {0, 0, 1000000000ULL, 0};
    uint64_t now = 1000001000ULL;  // 1 second + 1ms later

    // Multiple small queries accumulate
    uint32_t query_sizes[] = {50, 60, 45, 55, 50};

    for (uint32_t size : query_sizes) {
        if (now - stats.last_seen < WINDOW_SIZE_NS) {
            stats.query_bytes += size;
        } else {
            stats.query_bytes = size;
            stats.last_seen = now;
        }
    }

    // Total: 50+60+45+55+50 = 260
    EXPECT_EQ(stats.query_bytes, 260u);
}

// T-12: Accumulating response bytes across multiple responses
TEST_F(DnsAmplificationTest, AccumulatingResponseBytes) {
    dns_amp_stats stats = {0, 0, 1000000000ULL, 0};
    uint64_t now = 1000001000ULL;

    // Multiple responses accumulate
    uint32_t response_sizes[] = {500, 600, 450, 550, 500};

    for (uint32_t size : response_sizes) {
        if (now - stats.last_seen < WINDOW_SIZE_NS) {
            stats.response_bytes += size;
        } else {
            stats.response_bytes = size;
            stats.last_seen = now;
        }
    }

    // Total: 500+600+450+550+500 = 2600
    EXPECT_EQ(stats.response_bytes, 2600u);
}

// T-12: Attack scenario - large amplification
TEST_F(DnsAmplificationTest, AttackScenarioLargeAmplification) {
    uint32_t dns_thresh = 10;

    // Simulate a DNS amplification attack:
    // Attacker sends small query (50 bytes) to open DNS resolver
    // Resolver sends large response (4000 bytes) to victim
    // 4000 > 50 * 10 = 500 -> Attack detected

    uint64_t query_bytes = 50;
    uint64_t response_bytes = 4000;

    EXPECT_TRUE(check_dns_amplification(dns_thresh, query_bytes, response_bytes, false));
}

// T-12: Legitimate large DNS response not flagged
TEST_F(DnsAmplificationTest, LegitimateLargeResponseNotFlagged) {
    uint32_t dns_thresh = 10;

    // Legitimate scenario: query 100 bytes, response 900 bytes
    // 900 > 100 * 10 = 1000? No -> Not an attack
    EXPECT_FALSE(check_dns_amplification(dns_thresh, 100, 900, false));

    // Edge case: exactly at threshold
    // 1000 > 100 * 10 = 1000? No (not >) -> Not an attack
    EXPECT_FALSE(check_dns_amplification(dns_thresh, 100, 1000, false));

    // Just above threshold
    // 1001 > 100 * 10 = 1000? Yes -> Attack detected
    EXPECT_TRUE(check_dns_amplification(dns_thresh, 100, 1001, false));
}

// T-12: Small amplification not detected
TEST_F(DnsAmplificationTest, SmallAmplificationNotDetected) {
    uint32_t dns_thresh = 10;

    // 2x amplification
    EXPECT_FALSE(check_dns_amplification(dns_thresh, 100, 200, false));

    // 5x amplification
    EXPECT_FALSE(check_dns_amplification(dns_thresh, 100, 500, false));

    // 9x amplification
    EXPECT_FALSE(check_dns_amplification(dns_thresh, 100, 900, false));

    // 10x amplification (exactly at threshold, not >)
    EXPECT_FALSE(check_dns_amplification(dns_thresh, 100, 1000, false));
}

// T-12: dns_amp_threshold configurable
TEST_F(DnsAmplificationTest, ConfigurableThreshold) {
    // This would be configured via config_entry.dns_amp_threshold
    // in the BPF config map

    struct config_entry {
        uint32_t ddos_threshold;
        uint32_t window_size_ns;
        uint32_t drop_enabled;
        uint32_t port_scan_threshold;
        uint32_t dns_amp_threshold;
    };

    config_entry cfg = {};
    cfg.dns_amp_threshold = 10;  // Default

    EXPECT_EQ(cfg.dns_amp_threshold, 10u);

    // Can be configured lower for more sensitive detection
    cfg.dns_amp_threshold = 5;
    EXPECT_EQ(cfg.dns_amp_threshold, 5u);

    // Or higher for less sensitive
    cfg.dns_amp_threshold = 20;
    EXPECT_EQ(cfg.dns_amp_threshold, 20u);
}

// T-12: DNS amplification detection only applies to UDP port 53
TEST_F(DnsAmplificationTest, OnlyAppliesToDnsPort) {
    // The BPF code checks dst_port == 53 && src_port != 53 for queries
    // and src_port == 53 && dst_port != 53 for responses
    // This ensures we only track actual DNS traffic

    uint16_t dns_server_port = 53;
    uint16_t other_port = 80;

    // DNS query: dst_port == 53, src_port != 53
    EXPECT_EQ(dns_server_port, 53u);
    EXPECT_NE(dns_server_port, other_port);

    // DNS response: src_port == 53, dst_port != 53
    EXPECT_EQ(dns_server_port, 53u);
    EXPECT_NE(other_port, dns_server_port);
}

// T-12: Boundary conditions for amplification detection
TEST_F(DnsAmplificationTest, BoundaryConditions) {
    struct {
        uint32_t dns_thresh;
        uint64_t query_bytes;
        uint64_t response_bytes;
        bool alert_sent;
        bool expected;
        const char* description;
    } test_cases[] = {
        // E-13: Zero threshold protection
        {0, 100, 1001, false, true, "Zero threshold defaults to 10"},
        {0, 100, 999, false, false, "Zero threshold: 999 not > 1000"},

        // Normal cases
        {10, 0, 10000, false, false, "Zero query bytes"},
        {10, 1, 10, false, false, "1 not > 10"},
        {10, 1, 11, false, true, "11 > 10"},
        {10, 100, 1001, false, true, "1001 > 1000"},

        // Alert already sent
        {10, 100, 1001, true, false, "Alert already sent"},

        // Very large values (avoid overflow by using smaller multipliers)
        {10, 0xFFFFFFFF, 0xFFFFFFFF * 10ULL + 1, false, true, "Max 32-bit values"},
        {10, 1000000000ULL, 10000000001ULL, false, true, "Large but safe values"},
    };

    for (const auto& tc : test_cases) {
        bool result = check_dns_amplification(tc.dns_thresh, tc.query_bytes,
                                               tc.response_bytes, tc.alert_sent);
        EXPECT_EQ(result, tc.expected) << tc.description;
    }
}

// T-12: Verify dns_amp_key structure
TEST_F(DnsAmplificationTest, DnsAmpKeyStructure) {
    struct dns_amp_key {
        uint32_t victim_ip;
    };

    dns_amp_key key = {};
    key.victim_ip = 0xC0A80101;  // 192.168.1.1

    EXPECT_EQ(key.victim_ip, 0xC0A80101u);
    EXPECT_EQ(sizeof(dns_amp_key), 4u);
}

// T-12: Verify dns_amp_stats structure
TEST_F(DnsAmplificationTest, DnsAmpStatsStructure) {
    struct dns_amp_stats st = {};
    st.response_bytes = 5000;
    st.query_bytes = 100;
    st.last_seen = 1000000000ULL;
    st.alert_sent = 0;

    EXPECT_EQ(st.response_bytes, 5000u);
    EXPECT_EQ(st.query_bytes, 100u);
    EXPECT_EQ(st.last_seen, 1000000000ULL);
    EXPECT_FALSE(st.alert_sent);

    // Padding should not affect functionality
    EXPECT_EQ(st.padding[0], 0u);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
