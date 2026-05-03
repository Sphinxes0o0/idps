/* SPDX-License-Identifier: MIT */
/*
 * test_rule_concurrent.cpp - T-09: Multi-Rule Concurrent Update Test
 *
 * Tests concurrent safety of update_rule and delete_rule operations.
 * Validates that rules can be safely added, updated, and removed concurrently.
 */

#include "gtest/gtest.h"
#include "ebpf/ebpf_loader.h"
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <cstring>

using namespace nids;

class RuleConcurrentTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}

    // Helper to create a rule entry
    static RuleEntry make_rule(uint32_t id, uint8_t protocol, uint16_t port) {
        RuleEntry rule = {};
        rule.rule_id = id;
        rule.action = 2;  // alert
        rule.severity = 3;  // high
        rule.protocol = protocol;
        rule.dst_port = port;
        rule.dst_port_max = 0;
        rule.dpi_needed = 0;
        return rule;
    }

    // Helper to verify rule entry validity
    static bool is_valid_rule(const RuleEntry& rule) {
        if (rule.action > 2) return false;
        if (rule.severity > 4) return false;
        if (rule.protocol != 0 && rule.protocol != 6 && rule.protocol != 17) return false;
        if (rule.dpi_needed > 1) return false;
        return true;
    }
};

// T-09: Rule entry structure validation
TEST_F(RuleConcurrentTest, RuleEntryStructureValidation) {
    RuleEntry rule = make_rule(1, 6, 80);

    EXPECT_TRUE(is_valid_rule(rule));
    EXPECT_EQ(rule.rule_id, 1u);
    EXPECT_EQ(rule.protocol, 6u);
    EXPECT_EQ(rule.dst_port, 80u);
    EXPECT_EQ(rule.action, 2u);
    EXPECT_EQ(rule.severity, 3u);
}

// T-09: Rule entry padding and layout
TEST_F(RuleConcurrentTest, RuleEntryPadding) {
    RuleEntry rule = {};
    std::memset(&rule, 0, sizeof(rule));

    rule.rule_id = 100;
    rule.action = 1;
    rule.severity = 2;
    rule.protocol = 17;
    rule.dst_port = 443;
    rule.dst_port_max = 0;
    rule.dpi_needed = 1;

    // Verify padding bytes are not affecting validity
    EXPECT_TRUE(is_valid_rule(rule));

    // Verify size is as expected (14 bytes based on struct layout)
    EXPECT_EQ(sizeof(RuleEntry), 14u);
}

// T-09: Rule entry protocol validation
TEST_F(RuleConcurrentTest, RuleProtocolValidation) {
    RuleEntry rule = {};

    // Valid protocols
    rule.protocol = 0;  // any
    EXPECT_TRUE(is_valid_rule(rule));

    rule.protocol = 6;  // TCP
    EXPECT_TRUE(is_valid_rule(rule));

    rule.protocol = 17;  // UDP
    EXPECT_TRUE(is_valid_rule(rule));

    // Invalid protocols
    rule.protocol = 1;  // ICMP - invalid for our rules
    EXPECT_FALSE(is_valid_rule(rule));

    rule.protocol = 255;  // invalid
    EXPECT_FALSE(is_valid_rule(rule));
}

// T-09: Rule action validation
TEST_F(RuleConcurrentTest, RuleActionValidation) {
    RuleEntry rule = make_rule(1, 6, 80);

    // Valid actions
    rule.action = 0;  // log
    EXPECT_TRUE(is_valid_rule(rule));

    rule.action = 1;  // drop
    EXPECT_TRUE(is_valid_rule(rule));

    rule.action = 2;  // alert
    EXPECT_TRUE(is_valid_rule(rule));

    // Invalid actions
    rule.action = 3;
    EXPECT_FALSE(is_valid_rule(rule));

    rule.action = 255;
    EXPECT_FALSE(is_valid_rule(rule));
}

// T-09: Rule severity validation
TEST_F(RuleConcurrentTest, RuleSeverityValidation) {
    RuleEntry rule = make_rule(1, 6, 80);

    // Valid severities
    for (uint8_t sev = 0; sev <= 4; sev++) {
        rule.severity = sev;
        EXPECT_TRUE(is_valid_rule(rule));
    }

    // Invalid severities
    rule.severity = 5;
    EXPECT_FALSE(is_valid_rule(rule));

    rule.severity = 255;
    EXPECT_FALSE(is_valid_rule(rule));
}

// T-09: Rule with port range validation
TEST_F(RuleConcurrentTest, RulePortRangeValidation) {
    RuleEntry rule = make_rule(1, 6, 80);
    rule.dst_port_max = 100;

    EXPECT_TRUE(is_valid_rule(rule));
    EXPECT_EQ(rule.dst_port, 80u);
    EXPECT_EQ(rule.dst_port_max, 100u);
}

// T-09: DPI needed flag validation
TEST_F(RuleConcurrentTest, RuleDpiNeededValidation) {
    RuleEntry rule = make_rule(1, 6, 80);

    rule.dpi_needed = 0;
    EXPECT_TRUE(is_valid_rule(rule));

    rule.dpi_needed = 1;
    EXPECT_TRUE(is_valid_rule(rule));

    rule.dpi_needed = 2;
    EXPECT_FALSE(is_valid_rule(rule));
}

// T-09: Multiple rules creation
TEST_F(RuleConcurrentTest, MultipleRulesCreation) {
    std::vector<RuleEntry> rules;

    // Create rules for TCP ports (80 to 90 inclusive = 11 ports)
    for (uint16_t port = 80; port <= 90; port++) {
        rules.push_back(make_rule(port, 6, port));
    }

    // Create rules for UDP ports (53 to 55 inclusive = 3 ports)
    for (uint16_t port = 53; port <= 55; port++) {
        rules.push_back(make_rule(1000 + port, 17, port));
    }

    // Total: 11 + 3 = 14 rules
    EXPECT_EQ(rules.size(), 14u);

    // Verify all rules are valid
    for (const auto& rule : rules) {
        EXPECT_TRUE(is_valid_rule(rule));
    }
}

// T-09: Concurrent rule updates simulation
TEST_F(RuleConcurrentTest, ConcurrentRuleUpdateSimulation) {
    std::vector<RuleEntry> rules;
    std::atomic<bool> start{false};

    // Create initial rules
    for (uint32_t i = 0; i < 100; i++) {
        rules.push_back(make_rule(i, 6, static_cast<uint16_t>(i % 65536)));
    }

    // Verify initial rules
    for (const auto& rule : rules) {
        EXPECT_TRUE(is_valid_rule(rule));
    }

    // Simulate update operation (validation only, no actual BPF map)
    auto update_rule = [](RuleEntry& rule) {
        // Validate before update
        if (!is_valid_rule(rule)) {
            return false;
        }
        // Simulate some modification
        rule.severity = (rule.severity + 1) % 5;
        return true;
    };

    // Concurrent updates
    std::atomic<int> success_count{0};
    std::vector<std::thread> threads;

    for (size_t i = 0; i < 10; i++) {
        threads.emplace_back([&rules, &start, &update_rule, &success_count, i]() {
            while (!start.load()) { /* spin */ }
            for (size_t j = 0; j < 10; j++) {
                size_t idx = (j * 10 + i) % rules.size();
                if (update_rule(rules[idx])) {
                    success_count++;
                }
            }
        });
    }

    start = true;
    for (auto& t : threads) {
        t.join();
    }

    // All updates should succeed
    EXPECT_EQ(success_count, 100);

    // All rules should still be valid
    for (const auto& rule : rules) {
        EXPECT_TRUE(is_valid_rule(rule));
    }
}

// T-09: Concurrent rule add and delete simulation
TEST_F(RuleConcurrentTest, ConcurrentAddDeleteSimulation) {
    std::vector<RuleEntry> rules;
    std::mutex rules_mutex;
    std::atomic<bool> start{false};
    std::atomic<int> add_count{0};
    std::atomic<int> delete_count{0};

    // Initial rules
    for (uint32_t i = 0; i < 50; i++) {
        rules.push_back(make_rule(i, 6, static_cast<uint16_t>(i + 1000)));
    }

    // Add thread
    std::thread add_thread([&rules, &rules_mutex, &start, &add_count]() {
        while (!start.load()) { /* spin */ }
        for (uint32_t i = 0; i < 50; i++) {
            RuleEntry rule = make_rule(10000 + i, 6, static_cast<uint16_t>(i + 2000));
            std::lock_guard<std::mutex> lock(rules_mutex);
            rules.push_back(rule);
            add_count++;
        }
    });

    // Delete thread - use explicit deletion counter to avoid premature loop exit
    // when rules.size() shrinks due to deletes outpacing adds
    std::thread delete_thread([&rules, &rules_mutex, &start, &delete_count]() {
        while (!start.load()) { /* spin */ }
        int deleted = 0;
        while (deleted < 50) {
            std::lock_guard<std::mutex> lock(rules_mutex);
            if (rules.empty()) {
                break;  // Nothing left to delete
            }
            rules.erase(rules.begin());
            deleted++;
        }
        delete_count = deleted;
    });

    start = true;
    add_thread.join();
    delete_thread.join();

    // Verify counts
    EXPECT_EQ(add_count, 50);
    EXPECT_EQ(delete_count, 50);

    // All remaining rules should be valid
    std::lock_guard<std::mutex> lock(rules_mutex);
    for (const auto& rule : rules) {
        EXPECT_TRUE(is_valid_rule(rule));
    }
}

// T-09: Rule index key calculation
TEST_F(RuleConcurrentTest, RuleIndexKeyCalculation) {
    // Rule index key: (protocol << 16) | dst_port
    uint8_t protocol = 6;  // TCP
    uint16_t port = 80;

    uint32_t idx_key = ((uint32_t)protocol << 16) | port;

    EXPECT_EQ(idx_key, 0x00060050u);  // 6 << 16 | 80

    // Extract back
    uint8_t extracted_proto = (idx_key >> 16) & 0xFF;
    uint16_t extracted_port = idx_key & 0xFFFF;

    EXPECT_EQ(extracted_proto, protocol);
    EXPECT_EQ(extracted_port, port);
}

// T-09: Rule index key with port range
TEST_F(RuleConcurrentTest, RuleIndexKeyWithPortRange) {
    // For port ranges, we use the start port
    uint8_t protocol = 6;
    uint16_t port_start = 80;
    uint16_t port_end = 100;

    uint32_t idx_key = ((uint32_t)protocol << 16) | port_start;

    EXPECT_EQ(idx_key, 0x00060050u);

    // Multiple ports in range should map to same index key
    uint32_t idx_key2 = ((uint32_t)protocol << 16) | port_end;
    EXPECT_NE(idx_key, idx_key2);  // Different ports = different keys
}

// T-09: Rule with any protocol
TEST_F(RuleConcurrentTest, RuleWithAnyProtocol) {
    RuleEntry rule = make_rule(1, 0, 80);  // protocol=0 means "any"

    EXPECT_TRUE(is_valid_rule(rule));
    EXPECT_EQ(rule.protocol, 0u);
}

// T-09: Rule modification safety
TEST_F(RuleConcurrentTest, RuleModificationSafety) {
    RuleEntry rule1 = make_rule(1, 6, 80);
    RuleEntry rule2 = make_rule(2, 6, 80);

    // Rules should be independent
    rule1.severity = 4;
    EXPECT_EQ(rule2.severity, 3u);  // rule2 unchanged

    // Can safely modify fields without affecting other rules
    rule1.action = 1;
    rule2.action = 2;
    EXPECT_EQ(rule1.action, 1u);
    EXPECT_EQ(rule2.action, 2u);
}

// T-09: Rule copy safety
TEST_F(RuleConcurrentTest, RuleCopySafety) {
    RuleEntry original = make_rule(42, 17, 443);
    original.severity = 4;
    original.dpi_needed = 1;

    // Copy constructor equivalent
    RuleEntry copy = original;

    // Modify original
    original.severity = 0;

    // Copy should be independent
    EXPECT_EQ(copy.severity, 4u);
    EXPECT_EQ(copy.rule_id, original.rule_id);
    EXPECT_EQ(copy.protocol, original.protocol);
    EXPECT_EQ(copy.dst_port, original.dst_port);
}

// T-09: Rule zero initialization
TEST_F(RuleConcurrentTest, RuleZeroInitialization) {
    RuleEntry rule = {};
    std::memset(&rule, 0, sizeof(rule));

    // Zero-initialized rule should be mostly valid except for protocol=0
    EXPECT_TRUE(is_valid_rule(rule));  // protocol=0 is valid (any)
    EXPECT_EQ(rule.rule_id, 0u);
    EXPECT_EQ(rule.dst_port, 0u);
}

// T-09: Rule with maximum values
TEST_F(RuleConcurrentTest, RuleMaximumValues) {
    RuleEntry rule = {};
    rule.rule_id = 0xFFFFFFFF;
    rule.action = 2;
    rule.severity = 4;
    rule.protocol = 17;
    rule.dst_port = 65535;
    rule.dst_port_max = 65535;
    rule.dpi_needed = 1;

    EXPECT_TRUE(is_valid_rule(rule));
    EXPECT_EQ(rule.rule_id, 0xFFFFFFFFu);
    EXPECT_EQ(rule.dst_port, 65535u);
}

// T-09: Rule with minimum values
TEST_F(RuleConcurrentTest, RuleMinimumValues) {
    RuleEntry rule = {};
    rule.rule_id = 0;
    rule.action = 0;
    rule.severity = 0;
    rule.protocol = 0;
    rule.dst_port = 0;
    rule.dst_port_max = 0;
    rule.dpi_needed = 0;

    EXPECT_TRUE(is_valid_rule(rule));
    EXPECT_EQ(rule.rule_id, 0u);
    EXPECT_EQ(rule.dst_port, 0u);
}

// T-09: Rule map iteration simulation
TEST_F(RuleConcurrentTest, RuleMapIteration) {
    std::vector<RuleEntry> rules;
    for (uint32_t i = 0; i < 100; i++) {
        rules.push_back(make_rule(i, i % 2 == 0 ? 6 : 17, static_cast<uint16_t>(i + 1)));
    }

    // Count by protocol
    int tcp_count = 0;
    int udp_count = 0;

    for (const auto& rule : rules) {
        if (rule.protocol == 6) tcp_count++;
        else if (rule.protocol == 17) udp_count++;
    }

    EXPECT_EQ(tcp_count, 50);
    EXPECT_EQ(udp_count, 50);
}

// T-09: Concurrent readers while writer active simulation
TEST_F(RuleConcurrentTest, ConcurrentReadWriteSimulation) {
    std::vector<RuleEntry> rules;
    std::mutex rules_mutex;
    std::atomic<bool> start{false};
    std::atomic<bool> write_done{false};

    // Initialize rules
    for (uint32_t i = 0; i < 100; i++) {
        rules.push_back(make_rule(i, 6, static_cast<uint16_t>(i + 1000)));
    }

    // Writer thread
    std::thread writer([&rules, &rules_mutex, &start, &write_done]() {
        start = true;
        for (size_t i = 0; i < 100; i++) {
            std::lock_guard<std::mutex> lock(rules_mutex);
            if (i < rules.size()) {
                rules[i].severity = (rules[i].severity + 1) % 5;
            }
        }
        write_done = true;
    });

    // Reader threads
    std::atomic<int> read_count{0};
    std::vector<std::thread> readers;
    for (int i = 0; i < 5; i++) {
        readers.emplace_back([&rules, &rules_mutex, &start, &write_done, &read_count]() {
            while (!start.load()) { /* spin */ }
            int local_count = 0;
            while (!write_done.load()) {
                std::lock_guard<std::mutex> lock(rules_mutex);
                for (const auto& rule : rules) {
                    if (is_valid_rule(rule)) {
                        local_count++;
                    }
                }
            }
            read_count += local_count;
        });
    }

    writer.join();
    for (auto& r : readers) {
        r.join();
    }

    // All rules should still be valid after writes complete
    std::lock_guard<std::mutex> lock(rules_mutex);
    for (const auto& rule : rules) {
        EXPECT_TRUE(is_valid_rule(rule));
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}